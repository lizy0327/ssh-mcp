# Changelog

All notable changes to ssh-mcp are recorded here. Bump `__version__` in
`ssh_mcp_server.py` and `pyproject.toml` together when releasing.

## [2.0.0] - 2026-04-17

First version with a proper Git repo, dual-host deployment (Windows laptop +
Rocky Linux on 10.128.58.70), and version tracking.

### Added
- `stdio` transport support alongside existing `sse` / `streamable-http`.
- Platform-aware default transport: Windows defaults to `stdio`, Linux to `sse`.
- Cross-platform credentials file location:
  - Windows: `%APPDATA%\ssh-mcp\credentials.json`
  - Linux:   `/opt/ssh-mcp/credentials.json`
  - Overridable via `SSH_MCP_CREDENTIALS` env var.
- New diagnostic tool `ssh_mcp_version` returning version, platform, transport,
  and credentials path -- use it to confirm both deployments are in sync.
- `__version__` constant and `--version` CLI flag.

### Changed
- Refactor startup logging to include version and platform.
- Drop chmod(0o600) attempt on Windows (no-op anyway, but silences log noise).
- Credentials parent directory is auto-created on save (important for Windows).

### Removed
- Unused imports (`asynccontextmanager`, `io`).
- Redundant `host_list_table` / `host_list_display` debug blocks inside
  credential save/delete/update tools -- they were dead code.

### Known issues (unchanged from previous behaviour, not fixed in 2.0.0)
- `_ssh_exec_command` with `use_sudo=True` uses single-quoted wrapping; a
  password containing a literal `'` will break the command.

## [1.x] - pre-git

Single file `ssh_mcp_server.py` on `/opt/ssh-mcp/` (formerly 10.128.59.119,
migrated to 10.128.58.70). SSE transport only, Linux only. Not in version
control.
