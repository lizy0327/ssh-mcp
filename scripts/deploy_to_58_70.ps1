# deploy_to_58_70.ps1
# Deploy ssh_mcp_server.py from the local laptop repo to /opt/ssh-mcp/ on
# 10.128.58.70. Called by the `deploy-ssh-mcp` skill.
#
# Usage (from the repo root):
#   powershell -ExecutionPolicy Bypass -File .\scripts\deploy_to_58_70.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\deploy_to_58_70.ps1 -DryRun
#   powershell -ExecutionPolicy Bypass -File .\scripts\deploy_to_58_70.ps1 -SkipGitCheck
#
# Requires:
#   - Windows built-in OpenSSH client (ssh.exe, scp.exe) on PATH.
#   - Public-key auth configured for root@10.128.58.70 (no password).
#   - Python (any recent 3.x) on PATH for the syntax check.

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SkipGitCheck,
    [string]$RemoteHost = "10.128.58.70",
    [string]$RemoteUser = "root",
    [string]$RemotePath = "/opt/ssh-mcp/ssh_mcp_server.py",
    [string]$ServiceName = "ssh-mcp"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}
function Write-Ok($msg)   { Write-Host "    [OK]    $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "    [WARN]  $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "    [FAIL]  $msg" -ForegroundColor Red }

# -- Resolve repo root (parent of this script's directory) ------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot
$LocalFile = Join-Path $RepoRoot "ssh_mcp_server.py"

Write-Host "=== ssh-mcp deploy to $RemoteHost ===" -ForegroundColor Cyan
Write-Host "Repo root:  $RepoRoot"
Write-Host "Local file: $LocalFile"
Write-Host "Remote:     $RemoteUser@${RemoteHost}:$RemotePath"
if ($DryRun) { Write-Host "Mode:       DRY RUN (no changes will be made)" -ForegroundColor Yellow }

# -- 1. Preflight: file exists ----------------------------------------------
Write-Step "1. Preflight checks"

if (-not (Test-Path $LocalFile)) {
    Write-Fail "$LocalFile not found."
    exit 1
}
Write-Ok "Local ssh_mcp_server.py found."

# -- 1a. Tools on PATH ------------------------------------------------------
foreach ($tool in @("ssh", "scp", "python", "git")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Fail "Required tool '$tool' not found on PATH."
        exit 1
    }
}
Write-Ok "ssh.exe, scp.exe, python, git all on PATH."

# -- 1b. Git state ----------------------------------------------------------
if (-not $SkipGitCheck) {
    $gitStatus = git status --porcelain 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "git status failed. Is this a git repo?"
        exit 1
    }
    if ($gitStatus) {
        Write-Warn2 "Working tree is not clean:"
        Write-Host $gitStatus
        $confirm = Read-Host "Continue deploying anyway? (y/N)"
        if ($confirm -ne "y") {
            Write-Host "Aborted by user." -ForegroundColor Yellow
            exit 2
        }
    } else {
        Write-Ok "Git working tree clean."
    }

    # Check unpushed commits
    git fetch origin 2>&1 | Out-Null
    $unpushed = git log origin/main..HEAD --oneline 2>&1
    if ($LASTEXITCODE -eq 0 -and $unpushed) {
        Write-Warn2 "Unpushed commits on local main:"
        Write-Host $unpushed
        $confirm = Read-Host "Deploy unpushed code to 58.70? (y/N)"
        if ($confirm -ne "y") {
            Write-Host "Aborted by user. Push first: git push origin main" -ForegroundColor Yellow
            exit 2
        }
    } else {
        Write-Ok "Local main is in sync with origin/main (or no upstream configured)."
    }
} else {
    Write-Warn2 "Skipping git checks (-SkipGitCheck)."
}

# -- 1c. Syntax check -------------------------------------------------------
python -m py_compile $LocalFile
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Local syntax check failed."
    exit 1
}
Write-Ok "Python syntax check passed."

# -- 1d. Read local version -------------------------------------------------
$versionLine = Select-String -Path $LocalFile -Pattern '^__version__\s*=' | Select-Object -First 1
if (-not $versionLine) {
    Write-Fail "Could not find __version__ in $LocalFile"
    exit 1
}
if ($versionLine.Line -match '"([^"]+)"') {
    $LocalVersion = $Matches[1]
} else {
    Write-Fail "Could not parse __version__ line: $($versionLine.Line)"
    exit 1
}
Write-Ok "Local version: $LocalVersion"

# -- 2. Remote reachability -------------------------------------------------
Write-Step "2. Verify SSH connectivity to $RemoteHost"

$sshOpts = @(
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10"
)

$remoteUname = & ssh @sshOpts "$RemoteUser@$RemoteHost" "uname -a" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Cannot SSH to $RemoteUser@$RemoteHost without password."
    Write-Host "       Output: $remoteUname"
    Write-Host "       Run 'ssh-copy-id $RemoteUser@$RemoteHost' first, or set up key auth manually." -ForegroundColor Yellow
    exit 3
}
Write-Ok "SSH works: $remoteUname"

# -- 3. Backup on remote ----------------------------------------------------
Write-Step "3. Backup current /opt/ssh-mcp/ssh_mcp_server.py on $RemoteHost"

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = "$RemotePath.bak.$timestamp"

if ($DryRun) {
    Write-Warn2 "DRY RUN: would back up to $backupPath"
} else {
    $backupCmd = "cp $RemotePath $backupPath && ls -la $backupPath"
    $backupOut = & ssh @sshOpts "$RemoteUser@$RemoteHost" $backupCmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Backup failed: $backupOut"
        exit 4
    }
    Write-Ok "Backup created: $backupPath"
    Write-Host "    $backupOut"
}

# -- 4. Upload --------------------------------------------------------------
Write-Step "4. Upload $LocalFile -> $RemoteUser@${RemoteHost}:$RemotePath"

if ($DryRun) {
    Write-Warn2 "DRY RUN: would scp file."
} else {
    # Note: scp uses a slightly different option set but -o works.
    & scp @sshOpts $LocalFile "${RemoteUser}@${RemoteHost}:$RemotePath"
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "scp upload failed."
        # Attempt rollback
        Write-Warn2 "Restoring from $backupPath ..."
        & ssh @sshOpts "$RemoteUser@$RemoteHost" "cp $backupPath $RemotePath"
        exit 5
    }
    Write-Ok "Upload complete."
}

# -- 5. Restart service -----------------------------------------------------
Write-Step "5. Restart $ServiceName service"

if ($DryRun) {
    Write-Warn2 "DRY RUN: would restart $ServiceName."
} else {
    $restartCmd = "systemctl restart $ServiceName && sleep 3 && systemctl is-active $ServiceName"
    $restartOut = & ssh @sshOpts "$RemoteUser@$RemoteHost" $restartCmd 2>&1
    if ($LASTEXITCODE -ne 0 -or $restartOut -notmatch "active") {
        Write-Fail "Service failed to become active. Output: $restartOut"
        Write-Warn2 "Rolling back..."
        $rollbackCmd = "cp $backupPath $RemotePath && systemctl restart $ServiceName && sleep 2 && systemctl is-active $ServiceName"
        $rollbackOut = & ssh @sshOpts "$RemoteUser@$RemoteHost" $rollbackCmd 2>&1
        Write-Host "       Rollback output: $rollbackOut"

        Write-Host "`n    Recent journalctl:" -ForegroundColor Yellow
        & ssh @sshOpts "$RemoteUser@$RemoteHost" "journalctl -u $ServiceName -n 30 --no-pager"
        exit 6
    }
    Write-Ok "Service is active."
}

# -- 6. Version parity check via journalctl ---------------------------------
Write-Step "6. Verify deployed version"

if ($DryRun) {
    Write-Warn2 "DRY RUN: skipping version check."
} else {
    Start-Sleep -Seconds 1
    $verifyCmd = "journalctl -u $ServiceName -n 30 --no-pager | grep -E 'Starting SSH MCP Server' | tail -1"
    $verifyOut = & ssh @sshOpts "$RemoteUser@$RemoteHost" $verifyCmd 2>&1
    Write-Host "    journalctl says: $verifyOut"

    if ($verifyOut -match "v$([regex]::Escape($LocalVersion))") {
        Write-Ok "Remote is running v$LocalVersion (matches local)."
    } else {
        Write-Warn2 "Could not confirm v$LocalVersion in journal -- check manually."
        Write-Host "       Try calling the ssh_mcp_version tool via ssh-mcp-remote." -ForegroundColor Yellow
    }
}

# -- 7. Done ---------------------------------------------------------------
Write-Step "Deploy complete"
Write-Host ""
if ($DryRun) {
    Write-Host "This was a dry run. No changes were made." -ForegroundColor Yellow
} else {
    Write-Host "Summary:" -ForegroundColor Green
    Write-Host "  Version deployed: $LocalVersion"
    Write-Host "  Backup file:      $backupPath"
    Write-Host "  Service:          $ServiceName (active)"
    Write-Host ""
    Write-Host "Next: optionally call ssh_mcp_version via ssh-mcp-remote to confirm the version field." -ForegroundColor Gray
    Write-Host "Also: prune old backups periodically -> ssh $RemoteUser@$RemoteHost 'ls /opt/ssh-mcp/*.bak.*'" -ForegroundColor Gray
}
