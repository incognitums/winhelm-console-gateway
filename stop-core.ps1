#Requires -Version 5.1
param(
    [int]$Port = 18790
)

$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$pidFile = Join-Path $root 'core.pid'

$stopped = $false

if (Test-Path -LiteralPath $pidFile) {
    $raw = (Get-Content -LiteralPath $pidFile -Raw).Trim()
    if ($raw -match '^\d+$') {
        $pidNum = [int]$raw
        Stop-Process -Id $pidNum -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        Write-Host "[WinHelm Core] Stopped process PID $pidNum" -ForegroundColor Yellow
        $stopped = $true
    }
}

# Also verify port owning process
$conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    $portPid = ($conn | Select-Object -First 1).OwningProcess
    if ($portPid) {
        Stop-Process -Id $portPid -Force -ErrorAction SilentlyContinue
        Write-Host "[WinHelm Core] Stopped port $Port listener PID $portPid" -ForegroundColor Yellow
        $stopped = $true
    }
}

if (-not $stopped) {
    Write-Host "[WinHelm Core] Not running." -ForegroundColor Gray
}
