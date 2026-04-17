# install_local.ps1
# One-time setup for ssh-mcp on the local Windows 11 laptop.
#
# Run from the repo root:
#   cd C:\Users\zhaoyang.li\.lizy_dataops\ssh-mcp
#   powershell -ExecutionPolicy Bypass -File .\scripts\install_local.ps1
#
# What it does:
#   1. Creates .venv/ with uv (or python -m venv as fallback).
#   2. Installs deps from requirements.txt.
#   3. Runs a sanity check (--version).
#   4. Prints the Claude Desktop config snippet to add to claude_desktop_config.json.

$ErrorActionPreference = "Stop"

# Determine repo root (parent of this script's directory)
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

Write-Host "=== ssh-mcp local install ===" -ForegroundColor Cyan
Write-Host "Repo root: $RepoRoot"

# Check for uv, fall back to python venv
$UseUv = $false
if (Get-Command uv -ErrorAction SilentlyContinue) {
    Write-Host "Found uv, using it for venv management." -ForegroundColor Green
    $UseUv = $true
} else {
    Write-Host "uv not found, falling back to python -m venv." -ForegroundColor Yellow
}

# Create venv
if (-not (Test-Path ".venv")) {
    Write-Host "Creating .venv ..."
    if ($UseUv) {
        uv venv .venv
    } else {
        python -m venv .venv
    }
} else {
    Write-Host ".venv already exists, skipping creation."
}

# Install deps
Write-Host "Installing dependencies from requirements.txt ..."
if ($UseUv) {
    uv pip install --python .venv\Scripts\python.exe -r requirements.txt
} else {
    & .\.venv\Scripts\python.exe -m pip install --upgrade pip
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
}

# Sanity check
Write-Host "Sanity check: --version" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe ssh_mcp_server.py --version

# Print Claude Desktop config snippet
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$ServerPy  = Join-Path $RepoRoot "ssh_mcp_server.py"
# Escape backslashes for JSON
$PythonExeJson = $PythonExe -replace '\\', '\\'
$ServerPyJson  = $ServerPy  -replace '\\', '\\'

Write-Host ""
Write-Host "=== Add this to claude_desktop_config.json under 'mcpServers' ===" -ForegroundColor Cyan
Write-Host ""
$snippet = @"
    "ssh-mcp-local": {
      "command": "$PythonExeJson",
      "args": ["$ServerPyJson", "--transport", "stdio"]
    }
"@
Write-Host $snippet -ForegroundColor White
Write-Host ""
Write-Host "Config file is typically at: %APPDATA%\Claude\claude_desktop_config.json" -ForegroundColor Gray
Write-Host "After editing, fully quit and restart Claude Desktop." -ForegroundColor Gray
Write-Host ""
Write-Host "=== Install complete ===" -ForegroundColor Green
