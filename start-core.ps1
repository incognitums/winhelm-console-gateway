#Requires -Version 5.1
param(
    [int]$Port = 18790
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pidFile = Join-Path $root 'core.pid'
$coreLog = Join-Path $root 'core.stdout.log'
$coreErr = Join-Path $root 'core.stderr.log'

# Check if port is already active
$conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    $existingPid = ($conn | Select-Object -First 1).OwningProcess
    Write-Host "[WinHelm Core] Already listening on port $Port (PID: $existingPid)" -ForegroundColor Green
    Set-Content -LiteralPath $pidFile -Value $existingPid -Encoding ascii
    exit 0
}

# Resolve execution method:
# 1. Local build in D:\mcp\winhelm-mcp\dist\index.js (fastest)
# 2. Global npm binary 'winhelm'
# 3. npx -y -p winhelm-mcp winhelm
$localEntry = 'D:\mcp\winhelm-mcp\dist\index.js'
$localDir = 'D:\mcp\winhelm-mcp'

$exe = 'node'
$arguments = @()
$workDir = $root

if (Test-Path -LiteralPath $localEntry -PathType Leaf) {
    Write-Host "[WinHelm Core] Launching local build from $localDir..." -ForegroundColor Cyan
    $exe = 'node'
    $arguments = @($localEntry, '--port', "$Port")
    $workDir = $localDir
} elseif (Get-Command 'winhelm' -ErrorAction SilentlyContinue) {
    Write-Host "[WinHelm Core] Launching global npm package 'winhelm'..." -ForegroundColor Cyan
    $exe = 'cmd.exe'
    $arguments = @('/c', 'winhelm', '--port', "$Port")
} else {
    Write-Host "[WinHelm Core] Launching via npx (winhelm-mcp)..." -ForegroundColor Cyan
    $exe = 'cmd.exe'
    $arguments = @('/c', 'npx', '-y', '-p', 'winhelm-mcp', 'winhelm', '--port', "$Port")
}

$proc = Start-Process -FilePath $exe `
    -ArgumentList $arguments `
    -WorkingDirectory $workDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $coreLog `
    -RedirectStandardError $coreErr `
    -PassThru

Set-Content -LiteralPath $pidFile -Value $proc.Id -Encoding ascii
Write-Host "[WinHelm Core] Started background process (PID: $($proc.Id)), waiting for port $Port..." -ForegroundColor Yellow

$started = $false
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Milliseconds 400
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        $started = $true
        break
    }
}

if ($started) {
    Write-Host "[WinHelm Core] Successfully listening on port $Port! (PID: $($proc.Id))" -ForegroundColor Green
    exit 0
} else {
    Write-Warning "[WinHelm Core] Process started (PID: $($proc.Id)) but port $Port is not responding yet."
    if (Test-Path -LiteralPath $coreErr) {
        Get-Content -LiteralPath $coreErr -Tail 5 | ForEach-Object { Write-Warning "  $_" }
    }
    exit 1
}
