[CmdletBinding()]
param()

$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $root) { $root = (Get-Location).Path }
$script = "$root\tray\winhelm-tray.ps1"

if (-not (Test-Path -LiteralPath $script)) {
    Write-Error "Cannot find tray script at: $script"
    exit 1
}

# Clean up any existing tray process
Get-CimInstance Win32_Process -Filter "Name='powershell.exe' or Name='pwsh.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'winhelm-tray\.ps1' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 300

$psExe = 'powershell.exe'
$psArgs = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $script)

Start-Process -FilePath $psExe -ArgumentList $psArgs
Write-Host "[WinHelm Tray] Launched in background system tray (NotifyIcon)." -ForegroundColor Green
Write-Host "[WinHelm Tray] Look for the 'W' icon in the Windows taskbar tray (bottom right corner)." -ForegroundColor Cyan
