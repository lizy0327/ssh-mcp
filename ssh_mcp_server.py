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
import time
from pathlib import Path
from typing import Optional

import paramiko
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

# ---------------------------------------------------------------------------
# Version info
# ---------------------------------------------------------------------------

__version__ = "2.0.0"

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
    """Save credentials to JSON file with restricted permissions (POSIX only)."""
    path = Path(CREDENTIALS_FILE)
    # Ensure parent directory exists (important for Windows %APPDATA%\ssh-mcp\)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    # chmod only works on POSIX; silently skip on Windows
    if sys.platform != "win32":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _build_host_list(creds: dict) -> list:
    """Build a list of all hosts with masked passwords and numeric IDs."""
    return [
        {
            "id": idx + 1,
            "name": name,
            "host": info.get("host", ""),
            "port": info.get("port", 22),
            "username": info.get("username", ""),
            "description": info.get("description", ""),
            "device_type": info.get("device_type", "linux"),
        }
        for idx, (name, info) in enumerate(creds.get("hosts", {}).items())
    ]


def _resolve_host(name_or_ip: str) -> Optional[dict]:
    """
    Resolve a host reference to connection parameters.
    Accepts either a credential name, numeric ID, or an IP/hostname.
    Returns dict with host, port, username, password keys; None if not found.
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
            "password": entry.get("password", ""),
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
                "password": entry.get("password", ""),
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


def _ssh_connect(host, port, username, password):
    """Create and return a connected SSH client."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _ssh_sftp_write(
    host: str,
    port: int,
    username: str,
    password: str,
    remote_path: str,
    content: str,
    mode: int = 0o644,
) -> dict:
    """Write content to a remote file via SFTP. No shell escaping needed."""
    client = None
    try:
        client = _ssh_connect(host, port, username, password)
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
    password: str,
    script_content: str,
    interpreter: str = "/bin/bash",
    timeout: int = 120,
    use_sudo: bool = False,
) -> dict:
    """Upload a script via SFTP and execute it. No heredoc issues."""
    tmp_script = f"/tmp/.ssh_mcp_script_{int(time.time())}_{os.getpid()}.sh"
    client = None
    try:
        client = _ssh_connect(host, port, username, password)

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
    password: str,
    command: str,
    timeout: int = 30,
    use_sudo: bool = False,
) -> dict:
    """Execute a command over SSH and return structured result."""
    client = None
    try:
        client = _ssh_connect(host, port, username, password)

        if use_sudo and username != "root":
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
    password: str,
    commands: list[str],
    prompt_pattern: str = r"[#\$>]\s*$",
    timeout: int = 30,
    command_interval: float = 0.5,
) -> dict:
    """
    Interactive SSH session for devices like ONTAP that need shell mode.
    Sends commands one by one and waits for the prompt between them.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    full_output = ""
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
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
    password: str = Field(..., description="SSH password.")
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
async def ssh_execute(params: SSHExecuteInput) -> str:
    """Execute a shell command on a remote Linux server via SSH.

    Use this tool for running diagnostics (systemctl, journalctl, df, top, etc.),
    installing packages (yum, apt), managing services, and general troubleshooting.
    Supports sudo and custom working directory.

    Returns structured result with stdout, stderr, and exit_code.
    """
    conn = params.resolve()
    command = params.command

    # Safety check
    block_reason = _check_blocked(command)
    if block_reason:
        return json.dumps({"success": False, "error": block_reason}, indent=2)

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
        password=conn["password"],
        command=command,
        timeout=params.timeout,
        use_sudo=params.use_sudo,
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


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
async def ssh_interactive(params: SSHInteractiveInput) -> str:
    """Open an interactive SSH shell session and send commands sequentially.

    Use this tool for devices that require interactive shell mode, such as:
    - NetApp ONTAP storage systems (clustershell with ::> prompts)
    - Network switches/routers
    - Any device that doesn't support exec_command properly

    Commands are sent one at a time, waiting for the prompt between them.
    """
    conn = params.resolve()

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
        password=conn["password"],
        commands=params.commands,
        prompt_pattern=params.prompt_pattern,
        timeout=params.timeout,
        command_interval=params.command_interval,
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


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
async def ssh_file_read(params: SSHFileReadInput) -> str:
    """Read the contents of a file on a remote server via SSH.

    Useful for inspecting configuration files, logs, and other text files.
    Supports head/tail mode and line limits to avoid huge outputs.
    """
    conn = params.resolve()

    if params.tail:
        cmd = f"tail -n {params.max_lines} {params.file_path}"
    elif params.max_lines > 0:
        cmd = f"head -n {params.max_lines} {params.file_path}"
    else:
        cmd = f"cat {params.file_path}"

    result = await asyncio.to_thread(
        _ssh_exec_command,
        host=conn["host"],
        port=conn["port"],
        username=conn["username"],
        password=conn["password"],
        command=cmd,
        timeout=15,
        use_sudo=params.use_sudo,
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


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
async def ssh_file_write(params: SSHFileWriteInput) -> str:
    """Write content to a file on a remote server via SSH.

    Uses SFTP for file transfer - no shell escaping or heredoc issues.
    Creates a .bak backup by default before overwriting.
    """
    conn = params.resolve()

    # Backup existing file if requested
    if params.backup:
        await asyncio.to_thread(
            _ssh_exec_command,
            host=conn["host"],
            port=conn["port"],
            username=conn["username"],
            password=conn["password"],
            command=f"[ -f {params.file_path} ] && cp {params.file_path} {params.file_path}.bak",
            timeout=10,
        )

    if params.use_sudo and conn["username"] != "root":
        # SFTP write to temp, then sudo move
        tmp_path = f"/tmp/.ssh_mcp_fw_{int(time.time())}_{os.getpid()}"
        write_result = await asyncio.to_thread(
            _ssh_sftp_write,
            host=conn["host"],
            port=conn["port"],
            username=conn["username"],
            password=conn["password"],
            remote_path=tmp_path,
            content=params.content,
        )
        if not write_result.get("success"):
            return json.dumps(write_result, indent=2, ensure_ascii=False)

        # sudo move temp file to target
        move_result = await asyncio.to_thread(
            _ssh_exec_command,
            host=conn["host"],
            port=conn["port"],
            username=conn["username"],
            password=conn["password"],
            command=f"sudo mv {tmp_path} {params.file_path}",
            timeout=10,
        )
        if move_result["success"]:
            move_result["message"] = f"File written successfully: {params.file_path}"
        return json.dumps(move_result, indent=2, ensure_ascii=False)
    else:
        # Direct SFTP write
        result = await asyncio.to_thread(
            _ssh_sftp_write,
            host=conn["host"],
            port=conn["port"],
            username=conn["username"],
            password=conn["password"],
            remote_path=params.file_path,
            content=params.content,
        )
        if result.get("success"):
            result["exit_code"] = 0
            result["stdout"] = ""
            result["stderr"] = ""
            result["message"] = f"File written successfully: {params.file_path}"
        return json.dumps(result, indent=2, ensure_ascii=False)


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
async def ssh_script(params: SSHScriptInput) -> str:
    """Upload and execute a script on a remote server.

    Uses SFTP for script upload - no heredoc or shell escaping issues.
    The script can contain any characters including quotes, heredocs,
    special characters, etc.

    The script is uploaded to /tmp, executed, and then cleaned up.
    """
    conn = params.resolve()

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
        password=conn["password"],
        script_content=params.script_content,
        interpreter=params.interpreter,
        timeout=params.timeout,
        use_sudo=params.use_sudo,
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


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
async def ssh_credential_save(params: CredentialSaveInput) -> str:
    """Save SSH connection credentials to the local credential store.

    Saved credentials can be used by other ssh_* tools via the 'name' parameter,
    avoiding the need to pass host/username/password every time.
    """
    creds = _load_credentials()
    creds["hosts"][params.name] = {
        "host": params.host,
        "port": params.port,
        "username": params.username,
        "password": params.password,
        "description": params.description,
        "device_type": params.device_type,
    }
    _save_credentials(creds)
    logger.info("Credential saved: %s -> %s@%s", params.name, params.username, params.host)

    host_list = _build_host_list(creds)

    return json.dumps(
        {
            "success": True,
            "message": f"Credential '{params.name}' saved successfully.",
            "changed_entry": {
                "name": params.name,
                "host": params.host,
                "port": params.port,
                "username": params.username,
                "description": params.description,
                "device_type": params.device_type,
            },
            "all_hosts": host_list,
        },
        indent=2,
        ensure_ascii=False,
    )


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
    creds = _load_credentials()
    hosts = creds.get("hosts", {})

    if not hosts:
        return json.dumps(
            {"success": True, "message": "No saved credentials.", "hosts": []},
            indent=2,
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
            "description": info.get("description", ""),
            "device_type": info.get("device_type", "linux"),
        })

    # 构建 Markdown 表格，美观且所有字段都显示
    lines = []
    lines.append("| ID | 名称 | IP 地址 | 端口 | 用户名 | 密码 | 类型 | 描述 |")
    lines.append("|----|------|---------|------|--------|------|------|------|")
    for h in host_list:
        row = "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
            h["id"], h["name"], h["host"], h["port"],
            h["username"], h["password"], h["device_type"], h["description"]
        )
        lines.append(row)
    markdown_table = "\n".join(lines)

    # 返回 JSON，包含 Markdown 表格和原始数据，确保所有字段完整显示
    return json.dumps(
        {
            "success": True,
            "message": f"Found {len(host_list)} saved credential(s).",
            "table": markdown_table,
            "all_hosts": host_list,
        },
        indent=2,
        ensure_ascii=False,
    )


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
async def ssh_credential_delete(params: CredentialDeleteInput) -> str:
    """Delete a saved SSH credential from the local credential store."""
    creds = _load_credentials()
    if params.name not in creds.get("hosts", {}):
        return json.dumps(
            {
                "success": False,
                "error": f"Credential '{params.name}' not found.",
            },
            indent=2,
        )

    # Get info before deletion
    deleted_info = creds["hosts"][params.name]
    del creds["hosts"][params.name]
    _save_credentials(creds)
    logger.info("Credential deleted: %s", params.name)

    host_list = _build_host_list(creds)

    return json.dumps(
        {
            "success": True,
            "message": f"Credential '{params.name}' deleted.",
            "changed_entry": {
                "action": "deleted",
                "name": params.name,
                "host": deleted_info.get("host", ""),
                "username": deleted_info.get("username", ""),
            },
            "all_hosts": host_list,
        },
        indent=2,
        ensure_ascii=False,
    )


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
async def ssh_credential_update(params: CredentialUpdateInput) -> str:
    """Update an existing SSH credential. Only provided fields will be updated.

    Use this tool to modify specific attributes of a saved credential without
    re-specifying all fields. Unspecified fields retain their current values.
    """
    creds = _load_credentials()
    if params.name not in creds.get("hosts", {}):
        return json.dumps(
            {"success": False, "error": f"Credential '{params.name}' not found."},
            indent=2,
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
    if params.description is not None:
        old = host_info.get("description", "")
        host_info["description"] = params.description
        changes.append(f"description: {old} -> {params.description}")
    if params.device_type is not None:
        old = host_info.get("device_type", "linux")
        host_info["device_type"] = params.device_type
        changes.append(f"device_type: {old} -> {params.device_type}")

    _save_credentials(creds)
    logger.info("Credential updated: %s, changes: %s", params.name, changes)

    host_list = _build_host_list(creds)

    return json.dumps(
        {
            "success": True,
            "message": f"Credential '{params.name}' updated.",
            "changes": changes,
            "changed_entry": {
                "action": "updated",
                "name": params.name,
                "host": host_info["host"],
                "port": host_info["port"],
                "username": host_info["username"],
                "description": host_info.get("description", ""),
                "device_type": host_info.get("device_type", "linux"),
            },
            "all_hosts": host_list,
        },
        indent=2,
        ensure_ascii=False,
    )


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
    }
    return json.dumps(info, indent=2, ensure_ascii=False)


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
