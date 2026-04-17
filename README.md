# ssh-mcp

SSH MCP server for remote server management via the Model Context Protocol.
One codebase, two deployments:

| Role              | Host                 | Transport | Path                              |
|-------------------|----------------------|-----------|-----------------------------------|
| Local development | Windows 11 laptop    | `stdio`   | `C:\Users\zhaoyang.li\.lizy_dataops\ssh-mcp\` |
| Remote gateway    | Rocky Linux 9 (10.128.58.70) | `sse` (port 9876) | `/opt/ssh-mcp/` |

The laptop is the Git source of truth; 58.70 is a deployment target (no Git
access). Syncing is handled by the `deploy-ssh-mcp` skill (see below).

## Tools exposed

| Tool                    | Purpose                                       |
|-------------------------|-----------------------------------------------|
| `ssh_execute`           | Run a shell command on a remote Linux host.  |
| `ssh_interactive`       | Interactive shell (for ONTAP, switches).     |
| `ssh_file_read`         | Read a remote file.                           |
| `ssh_file_write`        | Write a remote file via SFTP.                 |
| `ssh_script`            | Upload and execute a script on the remote.   |
| `ssh_credential_save`   | Save SSH connection info.                     |
| `ssh_credential_list`   | List saved credentials (passwords masked).   |
| `ssh_credential_delete` | Remove a saved credential.                    |
| `ssh_credential_update` | Partial-update a saved credential.            |
| `ssh_mcp_version`       | Report version/platform/transport - use to verify the two deployments match. |

## Local install (Windows 11)

```powershell
cd C:\Users\zhaoyang.li\.lizy_dataops
git clone git@github.com:<your-github-username>/ssh-mcp.git
cd ssh-mcp
powershell -ExecutionPolicy Bypass -File .\scripts\install_local.ps1
```

The script creates `.venv\`, installs dependencies, runs a sanity check, and
prints the Claude Desktop config snippet. Add the snippet to
`%APPDATA%\Claude\claude_desktop_config.json`, then fully quit & restart Claude
Desktop.

Credentials live in `%APPDATA%\ssh-mcp\credentials.json` on Windows. They are
**independent** from the 58.70 credential store.

## Remote deploy (58.70)

You never touch 58.70 by hand. Ask Claude to deploy via the `deploy-ssh-mcp`
skill:

> "Deploy ssh-mcp to 58.70"

The skill runs `scripts/deploy_to_58_70.ps1`, which:

1. Verifies `git status` is clean and `HEAD` is pushed to `origin`.
2. `py_compile`s the server to catch syntax errors locally.
3. Creates a timestamped backup on 58.70 (`ssh_mcp_server.py.bak.<ts>`).
4. Uploads the new file via `scp` (OpenSSH client, Windows built-in).
5. Restarts `ssh-mcp.service` via `systemctl`.
6. Verifies the service is active and calls `ssh_mcp_version` to confirm the
   new version is running.
7. On failure, restores the backup and restarts.

### Prerequisites for deployment

- SSH public-key auth configured from laptop to `root@10.128.58.70` (no
  password prompt needed). Generate with `ssh-keygen`, deploy with
  `ssh-copy-id` or manually to `/root/.ssh/authorized_keys`.
- Windows built-in OpenSSH client (`ssh.exe`, `scp.exe`) available on `PATH`.
  On Windows 10/11 this is enabled by default.

## Verifying version parity

Call `ssh_mcp_version` against both the local stdio server and the 58.70 SSE
server. The `version` field must match. The `platform` field will differ
(Windows vs Linux) - that's expected.

## Development workflow

1. Edit `ssh_mcp_server.py` on the laptop.
2. If bumping version, update both `__version__` at the top of
   `ssh_mcp_server.py` **and** `version` in `pyproject.toml`. Also append to
   `CHANGELOG.md`.
3. Restart Claude Desktop to reload the stdio server and test locally.
4. Commit and push to `origin/main`.
5. Ask Claude to run the `deploy-ssh-mcp` skill to push to 58.70.

## Security notes

- `credentials.json` is in `.gitignore`; never commit it.
- On Linux the file is chmod 600; on Windows rely on NTFS ACLs under
  `%APPDATA%`.
- The two credential stores are independent. Add credentials on whichever
  deployment needs them.
