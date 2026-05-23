#!/usr/bin/env python3
"""
SSH MCP Server - Remote server management via SSH over MCP protocol.

Provides tools for executing commands, reading/writing files, and managing
SSH credentials on remote Linux servers and ONTAP storage systems.

Supports three transports:
  - stdio           : default on Windows (for local Claude Desktop)
  - sse             : default on Linux  (served over HTTP for remote clients)
  - streamable-http : alternative HTTP transport

Single-file code base is kept identical between:
  - Windows 11 laptop (stdio)  -> C:\\Users\\zhaoyang.li\\.lizy_dataops\\ssh-mcp\\
  - Rocky Linux 9 (sse:9876)   -> /opt/ssh-mcp/
"""

import asyncio
import json
import logging
import os
import platform
import re
import sys
try:
    import fcntl
except ImportError:
    fcntl = None  # Windows: fcntl not available, file locking skipped
import time
import uuid
from pathlib import Path
from typing import Optional

import paramiko
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

# ---------------------------------------------------------------------------
# Version info
# ---------------------------------------------------------------------------

__version__ = "2.4.0"

# ---------------------------------------------------------------------------
# Platform-aware configuration
# ---------------------------------------------------------------------------


def _default_credentials_path() -> Path:
    """Determine the default credentials file path based on platform.

    Priority order:
      1. $SSH_MCP_CREDENTIALS environment variable (highest)
      2. Platform default:
         - Windows: %APPDATA%\\ssh-mcp\\credentials.json
         - Linux  : /opt/ssh-mcp/credentials.json
      3. Fallback: <script_dir>/credentials.json
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "ssh-mcp" / "credentials.json"
    elif sys.platform.startswith("linux"):
        linux_default = Path("/opt/ssh-mcp/credentials.json")
        # Use /opt only if the directory exists or is writable by current user
        try:
            linux_default.parent.mkdir(parents=True, exist_ok=True)
            return linux_default
        except (OSError, PermissionError):
            pass
    # Fallback: script directory
    return Path(__file__).parent / "credentials.json"


def _default_transport() -> str:
    """Pick a reasonable default transport based on platform.

    Windows -> stdio (local Claude Desktop spawns subprocess)
    Linux   -> sse   (served via systemd for remote Claude Desktop clients)
    """
    return "stdio" if sys.platform == "win32" else "sse"


SERVER_PORT = int(os.environ.get("SSH_MCP_PORT", "9876"))
SERVER_HOST = os.environ.get("SSH_MCP_HOST", "0.0.0.0")
CREDENTIALS_FILE = os.environ.get(
    "SSH_MCP_CREDENTIALS",
    str(_default_credentials_path()),
)

# Safety: commands that are blocked by default
BLOCKED_COMMANDS = [
    r"\brm\s+-rf\s+/\s*$",
    r"\bmkfs\b",
    r"\bdd\s+.*of=/dev/",
    r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;",  # fork bomb
    r"\bshutdown\b",
    r"\breboot\b",
    r"\binit\s+0\b",
    r"\bhalt\b",
]

# Output truncation limits
MAX_OUTPUT_CHARS = 50000
MAX_OUTPUT_LINES = 2000

# Logging (stderr only -- stdout is reserved for MCP JSON-RPC under stdio)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("ssh_mcp")

# Runtime info populated by main() -- exposed via ssh_mcp_version tool
_RUNTIME_INFO = {
    "transport": None,
    "host": None,
    "port": None,
}

_ENABLE_TIMING = os.environ.get("SSH_MCP_TIMING", "1") != "0"
_ENABLE_TIMING_DETAIL = os.environ.get("SSH_MCP_TIMING_DETAIL", "1") != "0"


class _Timing:
    __slots__ = ("_enabled", "_t0", "_last", "_steps")

    def __init__(self, enabled: bool = _ENABLE_TIMING):
        self._enabled = enabled
        self._t0 = time.monotonic()
        self._last = self._t0
        self._steps = {}

    def mark(self, step: str) -> None:
        if not self._enabled:
            return
        now = time.monotonic()
        self._steps[step] = round((now - self._last) * 1000, 3)
        self._last = now

    def as_dict(self) -> Optional[dict]:
        if not self._enabled:
            return None
        now = time.monotonic()
        return {
            "total_ms": round((now - self._t0) * 1000, 3),
            "steps": self._steps,
        }


def _attach_timing(result: dict, timing: _Timing) -> dict:
    timing_data = timing.as_dict()
    if timing_data is not None:
        result["_timing"] = timing_data
    return result


# ---------------------------------------------------------------------------
# Credential store helpers
# ---------------------------------------------------------------------------


def _load_credentials() -> dict:
    """Load credentials from JSON file."""
    path = Path(CREDENTIALS_FILE)
    if not path.exists():
        return {"hosts": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "hosts" not in data:
            data = {"hosts": data}
        return data
    except (json.JSONDecodeError, IOError) as exc:
        logger.error("Failed to load credentials: %s", exc)
        return {"hosts": {}}


def _save_credentials(data: dict) -> None:
    """Save credentials with exclusive file lock (prevents concurrent write corruption)."""
    path = Path(CREDENTIALS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(".lock")
    payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    with open(lock_path, "w") as lf:
        if fcntl is not None:
            fcntl.flock(lf, fcntl.LOCK_EX)  # exclusive lock
        try:
            with open(path, "wb") as f:
                f.write(payload)
            if sys.platform != "win32":
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
        finally:
            if fcntl is not None:
                fcntl.flock(lf, fcntl.LOCK_UN)


def _build_host_list(creds: dict) -> list:
    """Build a list of all hosts with masked passwords and numeric IDs."""
    return [
        {
            "id": idx + 1,
            "name": name,
            "host": info.get("host", ""),
            "port": info.get("port", 22),
            "username": info.get("username", ""),
            "password": info.get("password", ""),
            "private_key_path": info.get("private_key_path"),
            "description": info.get("description", ""),
            "device_type": info.get("device_type", "linux"),
        }
        for idx, (name, info) in enumerate(creds.get("hosts", {}).items())
    ]


def _resolve_host(name_or_ip: str) -> Optional[dict]:
    """
    Resolve a host reference to connection parameters.
    Accepts either a credential name, numeric ID, or an IP/hostname.
    Returns dict with host, port, username, password, private_key_path keys; None if not found.
    """
    creds = _load_credentials()
    hosts = creds.get("hosts", {})

    # Try direct name match first
    if name_or_ip in hosts:
        entry = hosts[name_or_ip]
        return {
            "host": entry["host"],
            "port": entry.get("port", 22),
            "username": entry.get("username", "root"),
            "password": entry.get("password"),
            "private_key_path": entry.get("private_key_path"),
        }

    # Try numeric ID (e.g., "1", "2", etc.)
    if name_or_ip.isdigit():
        host_id = int(name_or_ip)
        host_list = list(hosts.keys())
        if 1 <= host_id <= len(host_list):
            name = host_list[host_id - 1]
            entry = hosts[name]
            return {
                "host": entry["host"],
                "port": entry.get("port", 22),
                "username": entry.get("username", "root"),
                "password": entry.get("password"),
                "private_key_path": entry.get("private_key_path"),
            }
        return None

    return None


# ---------------------------------------------------------------------------
# SSH execution helpers
# ---------------------------------------------------------------------------


def _check_blocked(command: str) -> Optional[str]:
    """Check if a command matches any blocked patterns."""
    for pattern in BLOCKED_COMMANDS:
        if re.search(pattern, command):
            return f"BLOCKED: Command matches dangerous pattern: {pattern}"
    return None


def _truncate_output(text: str, label: str = "output") -> str:
    """Truncate output if too long."""
    lines = text.split("\n")
    if len(lines) > MAX_OUTPUT_LINES:
        head = "\n".join(lines[:MAX_OUTPUT_LINES // 2])
        tail = "\n".join(lines[-MAX_OUTPUT_LINES // 2:])
        text = (
            f"{head}\n\n... [{len(lines) - MAX_OUTPUT_LINES} lines truncated from {label}] ...\n\n{tail}"
        )
    if len(text) > MAX_OUTPUT_CHARS:
        half = MAX_OUTPUT_CHARS // 2
        text = (
            f"{text[:half]}\n\n... [{len(text) - MAX_OUTPUT_CHARS} chars truncated from {label}] ...\n\n{text[-half:]}"
        )
    return text


def _ssh_connect(host, port, username, password=None, private_key_path=None):
    """Create and return a connected SSH client.

    Supports both password and key-based authentication.
    If private_key_path is provided, it will be used for authentication.
    Otherwise, falls back to password authentication.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 15,
        "look_for_keys": False,
        "allow_agent": False,
    }

    if private_key_path:
        # Key-based authentication
        key_path = os.path.expanduser(private_key_path)
        try:
            # Try to load the private key
            pkey = paramiko.Ed25519Key.from_private_key_file(key_path)
        except (paramiko.SSHException, FileNotFoundError, IOError):
            try:
                # Fallback to RSA key
                pkey = paramiko.RSAKey.from_private_key_file(key_path)
            except (paramiko.SSHException, FileNotFoundError, IOError) as e:
                raise paramiko.SSHException(f"Failed to load private key from {key_path}: {e}")
        connect_kwargs["pkey"] = pkey
    elif password:
        # Password authentication
        connect_kwargs["password"] = password

    client.connect(**connect_kwargs)
    return client


def _ssh_sftp_write(
    host: str,
    port: int,
    username: str,
    password: str = None,
    remote_path: str = None,
    content: str = None,
    mode: int = 0o644,
    private_key_path: str = None,
) -> dict:
    """Write content to a remote file via SFTP. No shell escaping needed."""
    client = None
    try:
        client = _ssh_connect(host, port, username, password, private_key_path)
        sftp = client.open_sftp()
        with sftp.file(remote_path, "w") as f:
            f.write(content)
        if mode:
            sftp.chmod(remote_path, mode)
        sftp.close()
        return {"success": True, "message": f"File written: {remote_path}"}
    except paramiko.AuthenticationException:
        return {"success": False, "exit_code": -1, "stdout": "",
                "stderr": f"Authentication failed for {username}@{host}:{port}."}
    except Exception as e:
        return {"success": False, "exit_code": -1, "stdout": "",
                "stderr": f"{type(e).__name__}: {e}"}
    finally:
        if client:
            client.close()


def _ssh_sftp_upload_and_run(
    host: str,
    port: int,
    username: str,
    password: str = None,
    script_content: str = None,
    interpreter: str = "/bin/bash",
    timeout: int = 120,
    use_sudo: bool = False,
    private_key_path: str = None,
) -> dict:
    """Upload a script via SFTP and execute it. No heredoc issues."""
    tmp_script = f"/tmp/.ssh_mcp_{uuid.uuid4().hex[:16]}.sh"
    client = None
    try:
        client = _ssh_connect(host, port, username, password, private_key_path)

        # Upload via SFTP - binary transfer, no shell parsing
        sftp = client.open_sftp()
        with sftp.file(tmp_script, "w") as f:
            f.write(script_content)
        sftp.chmod(tmp_script, 0o755)
        sftp.close()

        # Execute
        if use_sudo and username != "root":
            exec_cmd = f"sudo {interpreter} {tmp_script}"
        else:
            exec_cmd = f"{interpreter} {tmp_script}"

        stdin, stdout, stderr = client.exec_command(exec_cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode("utf-8", errors="replace")
        stderr_text = stderr.read().decode("utf-8", errors="replace")

        # Cleanup
        try:
            client.exec_command(f"rm -f {tmp_script}")
        except Exception:
            pass

        return {
            "success": exit_code == 0,
            "exit_code": exit_code,
            "stdout": _truncate_output(stdout_text, "stdout"),
            "stderr": _truncate_output(stderr_text, "stderr"),
        }
    except paramiko.AuthenticationException:
        return {
            "success": False, "exit_code": -1, "stdout": "",
            "stderr": f"Authentication failed for {username}@{host}:{port}.",
        }
    except Exception as e:
        return {
            "success": False, "exit_code": -1, "stdout": "",
            "stderr": f"{type(e).__name__}: {e}",
        }
    finally:
        if client:
            client.close()


def _ssh_exec_command(
    host: str,
    port: int,
    username: str,
    password: str = None,
    command: str = None,
    timeout: int = 30,
    use_sudo: bool = False,
    private_key_path: str = None,
) -> dict:
    """Execute a command over SSH and return structured result."""
    client = None
    try:
        client = _ssh_connect(host, port, username, password, private_key_path)

        if use_sudo and username != "root" and password:
            command = f"echo '{password}' | sudo -S bash -c '{command}'"

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode("utf-8", errors="replace")
        stderr_text = stderr.read().decode("utf-8", errors="replace")

        return {
            "success": exit_code == 0,
            "exit_code": exit_code,
            "stdout": _truncate_output(stdout_text, "stdout"),
            "stderr": _truncate_output(stderr_text, "stderr"),
        }
    except paramiko.AuthenticationException:
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Authentication failed for {username}@{host}:{port}. Check username/password.",
        }
    except paramiko.SSHException as e:
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"SSH error connecting to {host}:{port}: {e}",
        }
    except Exception as e:
        return {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Connection error to {host}:{port}: {type(e).__name__}: {e}",
        }
    finally:
        if client:
            client.close()


def _ssh_interactive_session(
    host: str,
    port: int,
    username: str,
    password: str = None,
    commands: list[str] = None,
    prompt_pattern: str = r"[#\$>]\s*$",
    timeout: int = 30,
    command_interval: float = 0.5,
    private_key_path: str = None,
) -> dict:
    """
    Interactive SSH session for devices like ONTAP that need shell mode.
    Sends commands one by one and waits for the prompt between them.
    """
    client = _ssh_connect(host, port, username, password, private_key_path)
    full_output = ""
    try:
        shell = client.invoke_shell(width=200, height=50)
        shell.settimeout(timeout)

        # Wait for initial prompt
        time.sleep(1)
        if shell.recv_ready():
            initial = shell.recv(65535).decode("utf-8", errors="replace")
            full_output += initial

        for cmd in commands:
            shell.send(cmd + "\n")
            time.sleep(command_interval)

            # Collect output until prompt appears
            cmd_output = ""
            deadline = time.time() + timeout
            while time.time() < deadline:
                if shell.recv_ready():
                    chunk = shell.recv(65535).decode("utf-8", errors="replace")
                    cmd_output += chunk
                    if re.search(prompt_pattern, chunk):
                        break
                else:
                    time.sleep(0.2)
            full_output += cmd_output

        return {
            "success": True,
            "exit_code": 0,
            "stdout": _truncate_output(full_output, "interactive output"),
            "stderr": "",
        }
    except Exception as e:
        return {
            "success": False,
            "exit_code": -1,
            "stdout": full_output,
            "stderr": f"Interactive session error: {type(e).__name__}: {e}",
        }
    finally:
        client.close()




def _parse_tool_params(params, model_cls):
    """Accept Codex/mcp-remote params as JSON string or dict, then validate."""
    if isinstance(params, model_cls):
        return params
    if isinstance(params, str):
        try:
            params = json.loads(params)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON params for {model_cls.__name__}: {exc}") from exc
    return model_cls.model_validate(params)

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP("ssh_mcp", host=SERVER_HOST, port=SERVER_PORT)


# ---------------------------------------------------------------------------
# Tool input models
# ---------------------------------------------------------------------------


class SSHTarget(BaseModel):
    """Base model for SSH connection target - either by name or by explicit params."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: Optional[str] = Field(
        default=None,
        description="Credential name from the saved hosts (e.g. 'harvest-monitor'). "
        "If provided, host/username/password are loaded from credentials.",
    )
    host: Optional[str] = Field(
        default=None,
        description="Target hostname or IP address (e.g. '10.128.58.104'). "
        "Required if 'name' is not provided.",
    )
    port: int = Field(default=22, description="SSH port", ge=1, le=65535)
    username: Optional[str] = Field(
        default=None, description="SSH username. Required if 'name' is not provided."
    )
    password: Optional[str] = Field(
        default=None, description="SSH password. Required if 'name' is not provided."
    )

    def resolve(self) -> dict:
        """Resolve to concrete connection parameters."""
        if self.name:
            # Try to resolve by name or numeric ID
            resolved = _resolve_host(self.name)
            if resolved is None:
                # Check if it's a numeric ID that's out of range
                if self.name.isdigit():
                    creds = _load_credentials()
                    host_count = len(creds.get("hosts", {}))
                    raise ValueError(
                        f"Host ID '{self.name}' not found. "
                        f"Valid IDs are 1-{host_count}. Use ssh_credential_list to see available hosts."
                    )
                raise ValueError(
                    f"Credential '{self.name}' not found. "
                    f"Use ssh_credential_list to see available hosts."
                )
            return resolved
        if not self.host or not self.username:
            raise ValueError(
                "Either 'name' (credential name or ID) or 'host' + 'username' + 'password' must be provided."
            )
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password or "",
        }


class SSHExecuteInput(SSHTarget):
    """Input for ssh_execute tool."""

    command: str = Field(
        ...,
        description="Shell command to execute on the remote host.",
        min_length=1,
    )
    timeout: int = Field(
        default=30,
        description="Command timeout in seconds. Use larger values (120-600) for "
        "package installation or long-running operations.",
        ge=5,
        le=3600,
    )
    use_sudo: bool = Field(
        default=False,
        description="Run command with sudo. Automatically wraps command in sudo.",
    )
    cwd: Optional[str] = Field(
        default=None,
        description="Working directory. Command will cd to this path first.",
    )


class SSHInteractiveInput(SSHTarget):
    """Input for ssh_interactive tool (ONTAP / network devices)."""

    commands: list[str] = Field(
        ...,
        description="List of commands to send sequentially in interactive shell. "
        "E.g. ['system health show', 'storage disk show -broken']",
        min_length=1,
    )
    prompt_pattern: str = Field(
        default=r"[#\$>:]\s*$",
        description="Regex pattern matching the device prompt. "
        "Default matches common shells and ONTAP '::>' prompts.",
    )
    timeout: int = Field(
        default=30,
        description="Timeout per command in seconds.",
        ge=5,
        le=600,
    )
    command_interval: float = Field(
        default=0.5,
        description="Seconds to wait after sending each command before reading output.",
        ge=0.1,
        le=10.0,
    )


class SSHFileReadInput(SSHTarget):
    """Input for ssh_file_read tool."""

    file_path: str = Field(
        ..., description="Absolute path of the file to read on the remote host."
    )
    use_sudo: bool = Field(
        default=False, description="Use sudo to read the file (for protected files)."
    )
    max_lines: int = Field(
        default=1000,
        description="Maximum number of lines to return. Use -1 for unlimited.",
        ge=-1,
    )
    tail: bool = Field(
        default=False,
        description="If True, return the last max_lines instead of first.",
    )


class SSHFileWriteInput(SSHTarget):
    """Input for ssh_file_write tool."""

    file_path: str = Field(
        ..., description="Absolute path of the file to write on the remote host."
    )
    content: str = Field(..., description="File content to write.")
    use_sudo: bool = Field(
        default=False, description="Use sudo to write the file."
    )
    backup: bool = Field(
        default=True,
        description="Create a .bak backup before overwriting.",
    )


class SSHScriptInput(SSHTarget):
    """Input for ssh_script tool."""

    script_content: str = Field(
        ..., description="Script content to upload and execute."
    )
    interpreter: str = Field(
        default="/bin/bash",
        description="Script interpreter path (e.g. /bin/bash, /usr/bin/python3).",
    )
    timeout: int = Field(
        default=120,
        description="Script execution timeout in seconds.",
        ge=5,
        le=3600,
    )
    use_sudo: bool = Field(
        default=False, description="Run script with sudo."
    )


class CredentialSaveInput(BaseModel):
    """Input for ssh_credential_save tool."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(
        ...,
        description="Short name for this host (e.g. 'harvest-monitor', 'fas9500').",
        min_length=1,
        max_length=64,
    )
    host: str = Field(..., description="Hostname or IP address.")
    port: int = Field(default=22, description="SSH port.", ge=1, le=65535)
    username: str = Field(default="root", description="SSH username.")
    password: Optional[str] = Field(default=None, description="SSH password. Not required if private_key_path is provided.")
    private_key_path: Optional[str] = Field(
        default=None,
        description="Path to SSH private key file (e.g. '~/.ssh/id_ed25519'). If provided, key-based authentication will be used instead of password.",
    )
    description: str = Field(
        default="", description="Optional description of this host."
    )
    device_type: str = Field(
        default="linux",
        description="Device type: 'linux' for standard servers, 'ontap' for NetApp storage.",
    )


class CredentialDeleteInput(BaseModel):
    """Input for ssh_credential_delete tool."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(..., description="Name of the credential to delete.")


class CredentialUpdateInput(BaseModel):
    """Input for ssh_credential_update tool."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(..., description="Name of the credential to update.")
    host: Optional[str] = Field(default=None, description="New hostname or IP address.")
    port: Optional[int] = Field(default=None, description="New SSH port.", ge=1, le=65535)
    username: Optional[str] = Field(default=None, description="New SSH username.")
    password: Optional[str] = Field(default=None, description="New SSH password.")
    private_key_path: Optional[str] = Field(default=None, description="New SSH private key path.")
    description: Optional[str] = Field(default=None, description="New description.")
    device_type: Optional[str] = Field(default=None, description="Device type: linux or ontap.")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="ssh_execute",
    annotations={
        "title": "Execute SSH Command",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def ssh_execute(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, SSHExecuteInput)
    timing.mark("parse_params")
    """Execute a shell command on a remote Linux server via SSH.

    Use this tool for running diagnostics (systemctl, journalctl, df, top, etc.),
    installing packages (yum, apt), managing services, and general troubleshooting.
    Supports sudo and custom working directory.

    Returns structured result with stdout, stderr, and exit_code.
    """
    conn = params.resolve()
    command = params.command
    timing.mark("resolve_params")

    # Safety check
    block_reason = _check_blocked(command)
    timing.mark("safety_check")
    if block_reason:
        timing.mark("attach_timing")
        return json.dumps(
            _attach_timing({"success": False, "error": block_reason}, timing),
            indent=2,
            ensure_ascii=False,
        )

    # Prepend cd if cwd specified
    if params.cwd:
        command = f"cd {params.cwd} && {command}"

    logger.info(
        "ssh_execute: %s@%s:%d -> %s",
        conn["username"],
        conn["host"],
        conn["port"],
        command[:100],
    )

    result = await asyncio.to_thread(
        _ssh_exec_command,
        host=conn["host"],
        port=conn["port"],
        username=conn["username"],
        password=conn.get("password"),
        command=command,
        timeout=params.timeout,
        use_sudo=params.use_sudo,
        private_key_path=conn.get("private_key_path"),
    )
    timing.mark("ssh_exec")
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)


@mcp.tool(
    name="ssh_interactive",
    annotations={
        "title": "Interactive SSH Session",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def ssh_interactive(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, SSHInteractiveInput)
    timing.mark("parse_params")
    """Open an interactive SSH shell session and send commands sequentially.

    Use this tool for devices that require interactive shell mode, such as:
    - NetApp ONTAP storage systems (clustershell with ::> prompts)
    - Network switches/routers
    - Any device that doesn't support exec_command properly

    Commands are sent one at a time, waiting for the prompt between them.
    """
    conn = params.resolve()
    timing.mark("resolve_params")

    logger.info(
        "ssh_interactive: %s@%s:%d -> %d commands",
        conn["username"],
        conn["host"],
        conn["port"],
        len(params.commands),
    )

    result = await asyncio.to_thread(
        _ssh_interactive_session,
        host=conn["host"],
        port=conn["port"],
        username=conn["username"],
        password=conn.get("password"),
        commands=params.commands,
        prompt_pattern=params.prompt_pattern,
        timeout=params.timeout,
        command_interval=params.command_interval,
        private_key_path=conn.get("private_key_path"),
    )
    timing.mark("interactive_session")
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)


@mcp.tool(
    name="ssh_file_read",
    annotations={
        "title": "Read Remote File",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def ssh_file_read(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, SSHFileReadInput)
    timing.mark("parse_params")
    """Read the contents of a file on a remote server via SSH.

    Useful for inspecting configuration files, logs, and other text files.
    Supports head/tail mode and line limits to avoid huge outputs.
    """
    conn = params.resolve()
    timing.mark("resolve_params")

    if params.tail:
        cmd = f"tail -n {params.max_lines} {params.file_path}"
    elif params.max_lines > 0:
        cmd = f"head -n {params.max_lines} {params.file_path}"
    else:
        cmd = f"cat {params.file_path}"
    timing.mark("build_command")

    result = await asyncio.to_thread(
        _ssh_exec_command,
        host=conn["host"],
        port=conn["port"],
        username=conn["username"],
        password=conn.get("password"),
        command=cmd,
        timeout=15,
        use_sudo=params.use_sudo,
        private_key_path=conn.get("private_key_path"),
    )
    timing.mark("ssh_exec")
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)


@mcp.tool(
    name="ssh_file_write",
    annotations={
        "title": "Write Remote File",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def ssh_file_write(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, SSHFileWriteInput)
    timing.mark("parse_params")
    """Write content to a file on a remote server via SSH.

    Uses SFTP for file transfer - no shell escaping or heredoc issues.
    Creates a .bak backup by default before overwriting.
    """
    conn = params.resolve()
    timing.mark("resolve_params")

    # Backup existing file if requested
    if params.backup:
        await asyncio.to_thread(
            _ssh_exec_command,
            host=conn["host"],
            port=conn["port"],
            username=conn["username"],
            password=conn.get("password"),
            command=f"[ -f {params.file_path} ] && cp {params.file_path} {params.file_path}.bak",
            timeout=10,
            private_key_path=conn.get("private_key_path"),
        )
        timing.mark("backup_existing")

    if params.use_sudo and conn["username"] != "root":
        # SFTP write to temp, then sudo move
        tmp_path = f"/tmp/.ssh_mcp_fw_{int(time.time())}_{os.getpid()}"
        write_result = await asyncio.to_thread(
            _ssh_sftp_write,
            host=conn["host"],
            port=conn["port"],
            username=conn["username"],
            password=conn.get("password"),
            remote_path=tmp_path,
            content=params.content,
            private_key_path=conn.get("private_key_path"),
        )
        timing.mark("sftp_write_temp")
        if not write_result.get("success"):
            timing.mark("attach_timing")
            return json.dumps(_attach_timing(write_result, timing), indent=2, ensure_ascii=False)

        # sudo move temp file to target
        move_result = await asyncio.to_thread(
            _ssh_exec_command,
            host=conn["host"],
            port=conn["port"],
            username=conn["username"],
            password=conn.get("password"),
            command=f"sudo mv {tmp_path} {params.file_path}",
            timeout=10,
            private_key_path=conn.get("private_key_path"),
        )
        timing.mark("sudo_move")
        if move_result["success"]:
            move_result["message"] = f"File written successfully: {params.file_path}"
        timing.mark("attach_timing")
        return json.dumps(_attach_timing(move_result, timing), indent=2, ensure_ascii=False)
    else:
        # Direct SFTP write
        result = await asyncio.to_thread(
            _ssh_sftp_write,
            host=conn["host"],
            port=conn["port"],
            username=conn["username"],
            password=conn.get("password"),
            remote_path=params.file_path,
            content=params.content,
            private_key_path=conn.get("private_key_path"),
        )
        timing.mark("sftp_write")
        if result.get("success"):
            result["exit_code"] = 0
            result["stdout"] = ""
            result["stderr"] = ""
            result["message"] = f"File written successfully: {params.file_path}"
        timing.mark("attach_timing")
        return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)


@mcp.tool(
    name="ssh_script",
    annotations={
        "title": "Execute Script on Remote Host",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def ssh_script(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, SSHScriptInput)
    timing.mark("parse_params")
    """Upload and execute a script on a remote server.

    Uses SFTP for script upload - no heredoc or shell escaping issues.
    The script can contain any characters including quotes, heredocs,
    special characters, etc.

    The script is uploaded to /tmp, executed, and then cleaned up.
    """
    conn = params.resolve()
    timing.mark("resolve_params")

    logger.info(
        "ssh_script: %s@%s:%d -> upload and run script (%d bytes)",
        conn["username"],
        conn["host"],
        conn["port"],
        len(params.script_content),
    )

    result = await asyncio.to_thread(
        _ssh_sftp_upload_and_run,
        host=conn["host"],
        port=conn["port"],
        username=conn["username"],
        password=conn.get("password"),
        script_content=params.script_content,
        interpreter=params.interpreter,
        timeout=params.timeout,
        use_sudo=params.use_sudo,
        private_key_path=conn.get("private_key_path"),
    )
    timing.mark("script_upload_exec_total")
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)



# ---------------------------------------------------------------------------
# Batch execution models & tools  (parallel: ssh_execute_batch / ssh_script_batch)
# ---------------------------------------------------------------------------

class SSHBatchHostEntry(BaseModel):
    """Single host entry for batch tools."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: Optional[str] = Field(default=None,
        description="Saved credential name or ID (e.g. 'client105'). Use instead of host/username/password.")
    host: Optional[str] = Field(default=None, description="Target IP or hostname.")
    port: int = Field(default=22, ge=1, le=65535)
    username: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    private_key_path: Optional[str] = Field(default=None, description="SSH private key path.")
    command: Optional[str] = Field(default=None,
        description="Per-host command override (ssh_execute_batch only).")
    script_content: Optional[str] = Field(default=None,
        description="Per-host script override (ssh_script_batch only).")

    def resolve(self) -> dict:
        if self.name:
            resolved = _resolve_host(self.name)
            if resolved is None:
                raise ValueError(f"Credential \'{self.name}\' not found.")
            return resolved
        if not self.host or not self.username:
            raise ValueError("Either name or host+username+password required.")
        return {"host": self.host, "port": self.port,
                "username": self.username, "password": self.password or "",
                "private_key_path": self.private_key_path}


class SSHBatchExecuteInput(BaseModel):
    """Input for ssh_execute_batch."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hosts: list[SSHBatchHostEntry] = Field(..., min_length=1,
        description="Target host list. Each entry may override the top-level command.")
    command: Optional[str] = Field(default=None,
        description="Default command for all hosts; per-host entry overrides.")
    timeout: int = Field(default=60, ge=5, le=3600)
    use_sudo: bool = Field(default=False)
    cwd: Optional[str] = Field(default=None)
    max_concurrency: int = Field(default=20, ge=1, le=50,
        description="Max simultaneous SSH connections. Prevents gateway resource exhaustion.")


class SSHBatchScriptInput(BaseModel):
    """Input for ssh_script_batch."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hosts: list[SSHBatchHostEntry] = Field(..., min_length=1,
        description="Target host list. Each entry may override top-level script_content.")
    script_content: Optional[str] = Field(default=None,
        description="Default script to run on all hosts.")
    interpreter: str = Field(default="/bin/bash")
    timeout: int = Field(default=600, ge=5, le=3600)
    use_sudo: bool = Field(default=False)
    max_concurrency: int = Field(default=20, ge=1, le=50)


@mcp.tool(
    name="ssh_execute_batch",
    annotations={
        "title": "Batch Execute SSH Command (Parallel)",
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": False, "openWorldHint": True,
    },
)
async def ssh_execute_batch(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, SSHBatchExecuteInput)
    timing.mark("parse_params")
    """Execute a command on multiple hosts in TRUE PARALLEL using asyncio.gather.

    Total elapsed time = slowest single host (not sum of all).
    Use this instead of calling ssh_execute N times when initializing N hosts.
    max_concurrency caps simultaneous SSH connections to protect gateway resources.
    """
    sem = asyncio.Semaphore(params.max_concurrency)

    async def _run_one(entry: SSHBatchHostEntry) -> dict:
        host_timing = _Timing(_ENABLE_TIMING and _ENABLE_TIMING_DETAIL)
        cmd   = entry.command or params.command
        label = entry.name or entry.host or "unknown"
        if not cmd:
            return _attach_timing(
                {"host": label, "name": entry.name,
                 "success": False, "error": "No command specified."},
                host_timing,
            )
        try:
            conn = entry.resolve()
            host_timing.mark("resolve")
        except ValueError as e:
            host_timing.mark("resolve")
            return _attach_timing(
                {"host": label, "name": entry.name, "success": False, "error": str(e)},
                host_timing,
            )
        if params.cwd:
            cmd = f"cd {params.cwd} && {cmd}"
        block = _check_blocked(cmd)
        if block:
            return _attach_timing(
                {"host": conn["host"], "name": entry.name, "success": False, "error": block},
                host_timing,
            )
        async with sem:
            result = await asyncio.to_thread(
                _ssh_exec_command,
                host=conn["host"], port=conn["port"],
                username=conn["username"], password=conn.get("password"),
                command=cmd, timeout=params.timeout, use_sudo=params.use_sudo,
                private_key_path=conn.get("private_key_path"),
            )
        host_timing.mark("ssh_exec")
        result["host"] = conn["host"]
        result["name"] = entry.name
        return _attach_timing(result, host_timing)

    start_ts = time.time()
    results  = await asyncio.gather(*[_run_one(h) for h in params.hosts])
    timing.mark("batch_gather")
    elapsed  = round(time.time() - start_ts, 2)
    total    = len(results)
    success  = sum(1 for r in results if r.get("success"))
    logger.info("ssh_execute_batch: %d hosts, %d ok, %d failed, %.1fs",
                total, success, total - success, elapsed)
    response = {
        "summary": {"total": total, "success": success,
                    "failed": total - success, "elapsed_seconds": elapsed},
        "results": list(results),
    }
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(response, timing), indent=2, ensure_ascii=False)


@mcp.tool(
    name="ssh_script_batch",
    annotations={
        "title": "Batch Execute Script (Parallel)",
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": False, "openWorldHint": True,
    },
)
async def ssh_script_batch(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, SSHBatchScriptInput)
    timing.mark("parse_params")
    """Upload and execute a script on multiple hosts in TRUE PARALLEL.

    Total elapsed time = slowest single host (not sum of all).
    Scripts are uploaded via SFTP (no heredoc issues) and cleaned up after execution.
    """
    sem = asyncio.Semaphore(params.max_concurrency)

    async def _run_one(entry: SSHBatchHostEntry) -> dict:
        host_timing = _Timing(_ENABLE_TIMING and _ENABLE_TIMING_DETAIL)
        script = entry.script_content or params.script_content
        label  = entry.name or entry.host or "unknown"
        if not script:
            return _attach_timing(
                {"host": label, "name": entry.name,
                 "success": False, "error": "No script_content specified."},
                host_timing,
            )
        try:
            conn = entry.resolve()
            host_timing.mark("resolve")
        except ValueError as e:
            host_timing.mark("resolve")
            return _attach_timing(
                {"host": label, "name": entry.name, "success": False, "error": str(e)},
                host_timing,
            )
        async with sem:
            result = await asyncio.to_thread(
                _ssh_sftp_upload_and_run,
                host=conn["host"], port=conn["port"],
                username=conn["username"], password=conn.get("password"),
                script_content=script, interpreter=params.interpreter,
                timeout=params.timeout, use_sudo=params.use_sudo,
                private_key_path=conn.get("private_key_path"),
            )
        host_timing.mark("script_upload_exec_total")
        result["host"] = conn["host"]
        result["name"] = entry.name
        return _attach_timing(result, host_timing)

    start_ts = time.time()
    results  = await asyncio.gather(*[_run_one(h) for h in params.hosts])
    timing.mark("batch_gather")
    elapsed  = round(time.time() - start_ts, 2)
    total    = len(results)
    success  = sum(1 for r in results if r.get("success"))
    logger.info("ssh_script_batch: %d hosts, %d ok, %d failed, %.1fs",
                total, success, total - success, elapsed)
    response = {
        "summary": {"total": total, "success": success,
                    "failed": total - success, "elapsed_seconds": elapsed},
        "results": list(results),
    }
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(response, timing), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Linux client preparation tools
# ---------------------------------------------------------------------------

class LinuxPrepareClientInput(SSHTarget):
    """Input for preparing one Linux client for faster initialization."""

    force_dnf_cleanup: bool = Field(
        default=True,
        description="Kill stale dnf processes and remove stale yum/dnf lock files.",
    )
    dnf_parallel_downloads: int = Field(
        default=10,
        ge=1,
        le=20,
        description="Value for /etc/dnf/dnf.conf max_parallel_downloads.",
    )
    configure_chrony: bool = Field(
        default=True,
        description="Ensure chrony uses makestep 1.0 -1 for large clock offsets.",
    )
    run_chrony_makestep: bool = Field(
        default=True,
        description="Run chronyc makestep immediately after chrony configuration.",
    )
    dry_run: bool = Field(
        default=False,
        description="Print planned actions without changing the target host.",
    )
    timeout: int = Field(default=180, ge=5, le=1800)


class LinuxPrepareClientBatchInput(BaseModel):
    """Input for preparing multiple Linux clients in parallel."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    hosts: list[SSHBatchHostEntry] = Field(..., min_length=1)
    force_dnf_cleanup: bool = Field(default=True)
    dnf_parallel_downloads: int = Field(default=10, ge=1, le=20)
    configure_chrony: bool = Field(default=True)
    run_chrony_makestep: bool = Field(default=True)
    dry_run: bool = Field(default=False)
    timeout: int = Field(default=180, ge=5, le=1800)
    max_concurrency: int = Field(default=20, ge=1, le=50)


def _build_linux_prepare_script(
    *,
    force_dnf_cleanup: bool = True,
    dnf_parallel_downloads: int = 10,
    configure_chrony: bool = True,
    run_chrony_makestep: bool = True,
    dry_run: bool = False,
) -> str:
    """Build an idempotent script that runs on a target Linux client."""
    return f"""#!/bin/bash
set -u

DRY_RUN={str(dry_run).lower()}
FORCE_DNF_CLEANUP={str(force_dnf_cleanup).lower()}
DNF_PARALLEL_DOWNLOADS={int(dnf_parallel_downloads)}
CONFIGURE_CHRONY={str(configure_chrony).lower()}
RUN_CHRONY_MAKESTEP={str(run_chrony_makestep).lower()}

log() {{ printf '[linux_prepare] %s\\n' "$*"; }}

run() {{
  if [ "$DRY_RUN" = "true" ]; then
    printf '[dry-run] %s\\n' "$*"
  else
    eval "$@"
  fi
}}

ensure_root() {{
  if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: this preparation requires root privileges"
    exit 1
  fi
}}

set_key_value() {{
  local file="$1" key="$2" value="$3"
  if [ "$DRY_RUN" = "true" ]; then
    log "Would ensure $file has $key=$value"
    return 0
  fi
  touch "$file"
  if grep -qE "^${{key}}=" "$file"; then
    sed -i "s/^${{key}}=.*/${{key}}=${{value}}/" "$file"
  else
    printf '\\n%s=%s\\n' "$key" "$value" >> "$file"
  fi
}}

ensure_line() {{
  local file="$1" line="$2"
  if [ "$DRY_RUN" = "true" ]; then
    log "Would ensure $file contains: $line"
    return 0
  fi
  touch "$file"
  grep -qxF "$line" "$file" || printf '\\n%s\\n' "$line" >> "$file"
}}

ensure_root
log "host=$(hostname) dry_run=$DRY_RUN"

if [ "$FORCE_DNF_CLEANUP" = "true" ]; then
  log "Cleaning stale DNF/YUM locks before repo/package operations"
  if [ "$DRY_RUN" = "true" ]; then
    log "Would kill dnf processes and remove yum/dnf lock files"
  else
    pkill -9 dnf 2>/dev/null || true
    sleep 1
    rm -f /var/run/yum.pid /var/cache/dnf/download_lock.pid 2>/dev/null || true
  fi
fi

if command -v dnf >/dev/null 2>&1; then
  log "Setting DNF max_parallel_downloads=$DNF_PARALLEL_DOWNLOADS"
  set_key_value /etc/dnf/dnf.conf max_parallel_downloads "$DNF_PARALLEL_DOWNLOADS"
else
  log "DNF not found; skipping max_parallel_downloads"
fi

if [ "$CONFIGURE_CHRONY" = "true" ]; then
  if [ -f /etc/chrony.conf ] || command -v chronyd >/dev/null 2>&1 || command -v chronyc >/dev/null 2>&1; then
    log "Ensuring chrony makestep for large clock offsets"
    ensure_line /etc/chrony.conf "makestep 1.0 -1"
    if [ "$DRY_RUN" != "true" ]; then
      systemctl restart chronyd 2>/dev/null || systemctl restart chrony 2>/dev/null || true
    fi
  else
    log "chrony not found; skipping chrony configuration"
  fi
fi

if [ "$RUN_CHRONY_MAKESTEP" = "true" ]; then
  if command -v chronyc >/dev/null 2>&1; then
    log "Running chronyc makestep"
    run "chronyc makestep || true"
  else
    log "chronyc not found; skipping immediate makestep"
  fi
fi

log "Final DNF setting:"
grep -n '^max_parallel_downloads=' /etc/dnf/dnf.conf 2>/dev/null || true
log "Final chrony makestep setting:"
grep -n '^makestep 1.0 -1$' /etc/chrony.conf 2>/dev/null || true
log "Remaining DNF lock files/processes:"
ls -l /var/run/yum.pid /var/cache/dnf/download_lock.pid 2>/dev/null || true
pgrep -a dnf 2>/dev/null || true
log "complete"
"""


def _linux_prepare_options_from_input(params) -> dict:
    return {
        "force_dnf_cleanup": params.force_dnf_cleanup,
        "dnf_parallel_downloads": params.dnf_parallel_downloads,
        "configure_chrony": params.configure_chrony,
        "run_chrony_makestep": params.run_chrony_makestep,
        "dry_run": params.dry_run,
    }


@mcp.tool(
    name="ssh_linux_prepare_client",
    annotations={
        "title": "Prepare Linux Client",
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": True, "openWorldHint": True,
    },
)
async def ssh_linux_prepare_client(params: str) -> str:
    """Prepare one Linux client for faster, more reliable initialization."""
    timing = _Timing()
    params = _parse_tool_params(params, LinuxPrepareClientInput)
    timing.mark("parse_params")
    conn = params.resolve()
    timing.mark("resolve_params")
    script = _build_linux_prepare_script(**_linux_prepare_options_from_input(params))
    timing.mark("build_script")
    logger.info("ssh_linux_prepare_client: %s@%s:%d dry_run=%s",
                conn["username"], conn["host"], conn["port"], params.dry_run)
    result = await asyncio.to_thread(
        _ssh_sftp_upload_and_run,
        host=conn["host"], port=conn["port"],
        username=conn["username"], password=conn.get("password"),
        script_content=script, interpreter="/bin/bash",
        timeout=params.timeout, use_sudo=False,
        private_key_path=conn.get("private_key_path"),
    )
    timing.mark("script_upload_exec_total")
    result["host"] = conn["host"]
    result["name"] = params.name
    result["dry_run"] = params.dry_run
    result["optimizations"] = {
        "dnf_lock_cleanup": params.force_dnf_cleanup,
        "dnf_parallel_downloads": params.dnf_parallel_downloads,
        "chrony_makestep_config": params.configure_chrony,
        "chronyc_makestep_now": params.run_chrony_makestep,
    }
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)


@mcp.tool(
    name="ssh_linux_prepare_client_batch",
    annotations={
        "title": "Prepare Linux Clients (Parallel)",
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": True, "openWorldHint": True,
    },
)
async def ssh_linux_prepare_client_batch(params: str) -> str:
    """Prepare multiple Linux clients in parallel. Use dry_run=true first."""
    timing = _Timing()
    params = _parse_tool_params(params, LinuxPrepareClientBatchInput)
    timing.mark("parse_params")
    script = _build_linux_prepare_script(**_linux_prepare_options_from_input(params))
    timing.mark("build_script")
    sem = asyncio.Semaphore(params.max_concurrency)

    async def _run_one(entry: SSHBatchHostEntry) -> dict:
        host_timing = _Timing(_ENABLE_TIMING and _ENABLE_TIMING_DETAIL)
        label = entry.name or entry.host or "unknown"
        try:
            conn = entry.resolve()
            host_timing.mark("resolve")
        except ValueError as e:
            host_timing.mark("resolve")
            return _attach_timing(
                {"host": label, "name": entry.name, "success": False, "error": str(e)},
                host_timing,
            )
        async with sem:
            result = await asyncio.to_thread(
                _ssh_sftp_upload_and_run,
                host=conn["host"], port=conn["port"],
                username=conn["username"], password=conn.get("password"),
                script_content=script, interpreter="/bin/bash",
                timeout=params.timeout, use_sudo=False,
                private_key_path=conn.get("private_key_path"),
            )
        host_timing.mark("script_upload_exec_total")
        result["host"] = conn["host"]
        result["name"] = entry.name
        result["dry_run"] = params.dry_run
        return _attach_timing(result, host_timing)

    start_ts = time.time()
    results = await asyncio.gather(*[_run_one(h) for h in params.hosts])
    timing.mark("batch_gather")
    elapsed = round(time.time() - start_ts, 2)
    total = len(results)
    success = sum(1 for r in results if r.get("success"))
    logger.info("ssh_linux_prepare_client_batch: %d hosts, %d ok, %d failed, %.1fs",
                total, success, total - success, elapsed)
    response = {
        "summary": {
            "total": total, "success": success,
            "failed": total - success, "elapsed_seconds": elapsed,
            "dry_run": params.dry_run,
            "optimizations": {
                "dnf_lock_cleanup": params.force_dnf_cleanup,
                "dnf_parallel_downloads": params.dnf_parallel_downloads,
                "chrony_makestep_config": params.configure_chrony,
                "chronyc_makestep_now": params.run_chrony_makestep,
            },
        },
        "results": list(results),
    }
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(response, timing), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Credential management tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="ssh_credential_save",
    annotations={
        "title": "Save SSH Credential",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def ssh_credential_save(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, CredentialSaveInput)
    timing.mark("parse_params")
    """Save SSH connection credentials to the local credential store.

    Saved credentials can be used by other ssh_* tools via the 'name' parameter,
    avoiding the need to pass host/username/password every time.
    """
    creds = _load_credentials()
    timing.mark("load_credentials")
    creds["hosts"][params.name] = {
        "host": params.host,
        "port": params.port,
        "username": params.username,
        "password": params.password,
        "private_key_path": params.private_key_path,
        "description": params.description,
        "device_type": params.device_type,
    }
    _save_credentials(creds)
    timing.mark("save_credentials")
    logger.info("Credential saved: %s -> %s@%s", params.name, params.username, params.host)

    host_list = _build_host_list(creds)
    timing.mark("build_host_list")

    result = {
        "success": True,
        "message": f"Credential '{params.name}' saved successfully.",
        "changed_entry": {
            "name": params.name,
            "host": params.host,
            "port": params.port,
            "username": params.username,
            "private_key_path": params.private_key_path,
            "description": params.description,
            "device_type": params.device_type,
        },
        "all_hosts": host_list,
    }
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)


@mcp.tool(
    name="ssh_credential_list",
    annotations={
        "title": "List Saved SSH Credentials",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def ssh_credential_list() -> str:
    """List all saved SSH credentials from the local credential store.

    Shows host IDs, names, IPs, usernames, passwords, and descriptions.
    Use the numeric ID (e.g., "1", "2") or name to connect to a host.
    """
    timing = _Timing()
    creds = _load_credentials()
    hosts = creds.get("hosts", {})
    timing.mark("load_credentials")

    if not hosts:
        timing.mark("attach_timing")
        return json.dumps(
            _attach_timing(
                {"success": True, "message": "No saved credentials.", "hosts": []},
                timing,
            ),
            indent=2,
            ensure_ascii=False,
        )

    # 构建结构化的主机列表，包含所有字段（密码和类型也显示）
    host_list = []
    for idx, (name, info) in enumerate(hosts.items(), start=1):
        host_list.append({
            "id": idx,
            "name": name,
            "host": info.get("host", ""),
            "port": info.get("port", 22),
            "username": info.get("username", ""),
            "password": info.get("password", ""),  # 密码明文显示
            "private_key_path": info.get("private_key_path"),
            "description": info.get("description", ""),
            "device_type": info.get("device_type", "linux"),
        })

    # 构建 Markdown 表格，美观且所有字段都显示
    lines = []
    lines.append("| ID | 名称 | IP 地址 | 端口 | 用户名 | 密码 | 密钥路径 | 类型 | 描述 |")
    lines.append("|----|------|---------|------|--------|------|----------|------|------|")
    for h in host_list:
        row = "| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            h["id"], h["name"], h["host"], h["port"],
            h["username"], h["password"], h.get("private_key_path") or "-",
            h["device_type"], h["description"]
        )
        lines.append(row)
    markdown_table = "\n".join(lines)
    timing.mark("build_host_list")

    result = {
        "success": True,
        "message": f"Found {len(host_list)} saved credential(s).",
        "table": markdown_table,
        "all_hosts": host_list,
    }
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)

    # 返回 JSON，包含 Markdown 表格和原始数据，确保所有字段完整显示


@mcp.tool(
    name="ssh_credential_delete",
    annotations={
        "title": "Delete SSH Credential",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def ssh_credential_delete(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, CredentialDeleteInput)
    timing.mark("parse_params")
    """Delete a saved SSH credential from the local credential store."""
    creds = _load_credentials()
    timing.mark("load_credentials")
    if params.name not in creds.get("hosts", {}):
        timing.mark("attach_timing")
        return json.dumps(
            _attach_timing({
                "success": False,
                "error": f"Credential '{params.name}' not found.",
            }, timing),
            indent=2,
            ensure_ascii=False,
        )

    # Get info before deletion
    deleted_info = creds["hosts"][params.name]
    del creds["hosts"][params.name]
    _save_credentials(creds)
    timing.mark("save_credentials")
    logger.info("Credential deleted: %s", params.name)

    host_list = _build_host_list(creds)
    timing.mark("build_host_list")

    result = {
        "success": True,
        "message": f"Credential '{params.name}' deleted.",
        "changed_entry": {
            "action": "deleted",
            "name": params.name,
            "host": deleted_info.get("host", ""),
            "username": deleted_info.get("username", ""),
        },
        "all_hosts": host_list,
    }
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)


@mcp.tool(
    name="ssh_credential_update",
    annotations={
        "title": "Update SSH Credential",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def ssh_credential_update(params: str) -> str:
    timing = _Timing()
    params = _parse_tool_params(params, CredentialUpdateInput)
    timing.mark("parse_params")
    """Update an existing SSH credential. Only provided fields will be updated.

    Use this tool to modify specific attributes of a saved credential without
    re-specifying all fields. Unspecified fields retain their current values.
    """
    creds = _load_credentials()
    timing.mark("load_credentials")
    if params.name not in creds.get("hosts", {}):
        timing.mark("attach_timing")
        return json.dumps(
            _attach_timing(
                {"success": False, "error": f"Credential '{params.name}' not found."},
                timing,
            ),
            indent=2,
            ensure_ascii=False,
        )

    host_info = creds["hosts"][params.name]
    changes = []

    if params.host is not None:
        old = host_info.get("host", "")
        host_info["host"] = params.host
        changes.append(f"host: {old} -> {params.host}")
    if params.port is not None:
        old = host_info.get("port", 22)
        host_info["port"] = params.port
        changes.append(f"port: {old} -> {params.port}")
    if params.username is not None:
        old = host_info.get("username", "")
        host_info["username"] = params.username
        changes.append(f"username: {old} -> {params.username}")
    if params.password is not None:
        host_info["password"] = params.password
        changes.append("password: ***")
    if params.private_key_path is not None:
        old = host_info.get("private_key_path")
        host_info["private_key_path"] = params.private_key_path
        changes.append(f"private_key_path: {old} -> {params.private_key_path}")
    if params.description is not None:
        old = host_info.get("description", "")
        host_info["description"] = params.description
        changes.append(f"description: {old} -> {params.description}")
    if params.device_type is not None:
        old = host_info.get("device_type", "linux")
        host_info["device_type"] = params.device_type
        changes.append(f"device_type: {old} -> {params.device_type}")
    timing.mark("apply_changes")

    _save_credentials(creds)
    timing.mark("save_credentials")
    logger.info("Credential updated: %s, changes: %s", params.name, changes)

    host_list = _build_host_list(creds)
    timing.mark("build_host_list")

    result = {
        "success": True,
        "message": f"Credential '{params.name}' updated.",
        "changes": changes,
        "changed_entry": {
            "action": "updated",
            "name": params.name,
            "host": host_info["host"],
            "port": host_info["port"],
            "username": host_info["username"],
            "password": host_info.get("password"),
            "private_key_path": host_info.get("private_key_path"),
            "description": host_info.get("description", ""),
            "device_type": host_info.get("device_type", "linux"),
        },
        "all_hosts": host_list,
    }
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(result, timing), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Diagnostic tool (for verifying local vs remote version parity)
# ---------------------------------------------------------------------------


@mcp.tool(
    name="ssh_mcp_version",
    annotations={
        "title": "SSH MCP Server Version Info",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def ssh_mcp_version() -> str:
    """Return version and runtime information about this SSH MCP server instance.

    Use this tool to verify that the local (laptop) and remote (10.128.58.70)
    deployments are running the same code version.
    """
    timing = _Timing()
    info = {
        "success": True,
        "version": __version__,
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python_version": platform.python_version(),
        "transport": _RUNTIME_INFO.get("transport"),
        "host": _RUNTIME_INFO.get("host"),
        "port": _RUNTIME_INFO.get("port"),
        "credentials_file": CREDENTIALS_FILE,
        "credentials_exists": Path(CREDENTIALS_FILE).exists(),
        "hostname": platform.node(),
        "features": [
            "ssh_execute",
            "ssh_script",
            "ssh_execute_batch",
            "ssh_script_batch",
            "ssh_linux_prepare_client",
            "ssh_linux_prepare_client_batch",
            "timing",
            "timing_all_tools",
            "key_auth",
        ],
    }
    timing.mark("gather_info")
    timing.mark("attach_timing")
    return json.dumps(_attach_timing(info, timing), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main():
    """Start SSH MCP server."""
    import argparse

    default_transport = _default_transport()

    parser = argparse.ArgumentParser(description=f"SSH MCP Server v{__version__}")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default=default_transport,
        help=f"MCP transport type (default: {default_transport} on this platform)",
    )
    parser.add_argument(
        "--host", default=SERVER_HOST, help=f"Bind address (default: {SERVER_HOST}). Ignored for stdio."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=SERVER_PORT,
        help=f"Listen port (default: {SERVER_PORT}). Ignored for stdio.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ssh-mcp {__version__}",
    )
    args = parser.parse_args()

    # Populate runtime info for ssh_mcp_version tool
    _RUNTIME_INFO["transport"] = args.transport
    _RUNTIME_INFO["host"] = args.host if args.transport != "stdio" else None
    _RUNTIME_INFO["port"] = args.port if args.transport != "stdio" else None

    if args.transport == "stdio":
        logger.info(
            "Starting SSH MCP Server v%s (transport: stdio, platform: %s)",
            __version__,
            platform.system(),
        )
    else:
        logger.info(
            "Starting SSH MCP Server v%s on %s:%d (transport: %s, platform: %s)",
            __version__,
            args.host,
            args.port,
            args.transport,
            platform.system(),
        )
    logger.info("Credentials file: %s", CREDENTIALS_FILE)

    # For HTTP-based transports, update FastMCP's bind address
    if args.transport != "stdio":
        mcp._host = args.host
        mcp._port = args.port

    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
