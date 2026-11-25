#Requires -Version 5.1
param(
    [switch]$Foreground
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$server = Join-Path $root 'server.js'
$pidFile = Join-Path $root 'gateway.pid'
$log = Join-Path $root 'gateway.stdout.log'
$err = Join-Path $root 'gateway.stdout.log.err'

# Check if gateway is already listening on 18788
$conn = Get-NetTCPConnection -LocalPort 18788 -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    $existingPid = ($conn | Select-Object -First 1).OwningProcess
    Write-Host "[WinHelm Gateway] Already listening on port 18788 (PID: $existingPid)" -ForegroundColor Green
    Set-Content -LiteralPath $pidFile -Value $existingPid -Encoding ascii
    exit 0
}

if ($Foreground) {
    Write-Host "[WinHelm Gateway] Starting Gateway on port 18788 (foreground)..." -ForegroundColor Cyan
    & node $server
} else {
    $p = Start-Process -FilePath 'node' `
        -ArgumentList @($server) `
        -WorkingDirectory $root -WindowStyle Hidden `
        -RedirectStandardOutput $log `
        -RedirectStandardError $err -PassThru
    Set-Content -LiteralPath $pidFile -Value $p.Id -NoNewline -Encoding ascii
    Write-Host "[WinHelm Gateway] Started background Gateway (PID: $($p.Id)) on port 18788" -ForegroundColor Green
    Start-Sleep -Milliseconds 600
}
