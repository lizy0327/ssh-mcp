# SSH-MCP project status

Updated: 2026-09-13

## Scope completed in this workspace

This working copy implements the structured transport improvements requested
for Hermes and other MCP clients. The source was cloned from
`https://github.com/lizy0327/ssh-mcp` at commit
`13dd761c0279b3dffc323b632fe3e62ed76dcc1c` (`main`). The optimization was
committed and pushed as `8d15da808ff196276e31d484c29b267b99ffd8b1` on `main`,
with capability-reporting follow-up `02efa7e` and HTTP diagnostics release
`a894e34ad61b0fd8f2f460eb8cc9daf1dc806099`.

Release version: **2.5.1** (source validated and deployed)

## Implemented changes

- Added `ssh_execute_v2` with native MCP fields such as `command`, `name`,
  `timeout`, `cwd`, and `stdin_text`. It removes the double-encoded `params`
  JSON boundary for new callers.
- Added `ssh_script_v2` with a native `script` field. It uses the existing
  SFTP upload path, making it the default route for multi-line shell logic,
  redirects, embedded JSON, and heredocs.
- Extended command execution to write `stdin_text`, flush it, and close stdin.
  This prevents a remote command from waiting indefinitely for further input.
- Reworked `sudo` password delivery to use stdin rather than interpolating a
  password into a shell command.
- Added structured errors: `validation`, `policy`, `stdin_required`,
  `tty_required`, `remote_exit`, `auth`, and `connection`. Policy denials
  include `policy_id`.
- Added key-path support to the explicit target model and constrained the MCP
  dependency to `>=1.27.0,<2.0.0`; MCP 2.x removed the FastMCP import used by
  this project.
- Retained the legacy `ssh_execute(params)` and `ssh_script(params)` tools for
  existing clients.
- Added a cache-free `GET /healthz` endpoint that remains available even when
  no MCP session can be established. It exposes only liveness/version/transport
  data, never request content, credentials, or client identifiers.
- Added safe `transport_event` journal records for malformed SSE messages and
  HTTP errors. The service records no request body or query string in these
  summaries; `ssh_mcp_version` exposes the restart-scoped parse-error counter.

## Validation completed

Executed successfully in the local virtual environment:

```text
python -m unittest discover -s tests -v
8 tests passed
python -m py_compile ssh_mcp_server.py
python ssh_mcp_server.py --version
ssh-mcp 2.5.1
```

The tests assert that the live MCP schema exposes native v2 fields (and no
`params` wrapper), stdin is written and closed, sudo does not inject a password
into a shell command, policy identifiers are stable, and invalid legacy JSON
returns a structured validation failure. The new tests also confirm that health
checks work without an MCP session and malformed-message telemetry holds no
payload.

## Deployment state

Deployment to `root@10.128.58.70:2345` completed successfully using the
dedicated `id_ed25519_vm70` key. Before each source replacement, the target
file was backed up and the uploaded candidate passed
`/opt/ssh-mcp/venv/bin/python3.11 -m py_compile`. The service was then restarted
and verified active.

Current live state after the 2.5.1 deployment (2026-09-13):

- Service: `ssh-mcp.service` is `active (running)` with `NRestarts=0`.
- The process listens on `0.0.0.0:9876`; the host firewall allows `9876/tcp`.
- `GET /healthz` passed both locally on vm70 and from the release workstation
  (with the workstation HTTP proxy bypassed): status `ok`, version `2.5.1`,
  transport `sse`.
- The server journal confirms the existing client at `10.66.0.3` reconnected
  to `GET /sse` after the restart.
- Feature list from the previous 2.5.0 verification includes `ssh_execute_v2`
  and `ssh_script_v2`; the new 2.5.1 code retains both.
- Deployed source SHA-256:
  `8705de31b5f4a79f0549213e8f312e864177a869693b6f4a68d3dabf207c53f6`.
- Latest rollback backup:
  `/opt/ssh-mcp/ssh_mcp_server.py.bak.20260913_133800`.

## Recommended release sequence

1. Refresh Hermes's MCP tool discovery and route new calls to the `*_v2`
   tools. Keep legacy tools enabled during migration.
2. Capture and redact the first real Hermes failures, if any, and add them as
   regression cases before altering the calling rules again.
3. Periodically prune only explicitly approved old backup files after confirming
   the new version is stable.
4. On the next Hermes incident, extract only `transport_event` entries plus
   the MCP client's structured error; then run a normal SDK MCP
   initialize/tools-list exchange. Do not use raw JSON or `curl` as an MCP
   client test. (`curl` is acceptable for the separate `/healthz` endpoint.)
