[CmdletBinding()]
param(
    [switch] $Browser
)

$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $root) { $root = (Get-Location).Path }
$script = "$root\tray\open-console.ps1"

if (-not (Test-Path -LiteralPath $script)) {
    Write-Error "Cannot find open-console script at: $script"
    exit 1
}

$psExe = if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { 'pwsh.exe' } else { 'powershell.exe' }
$psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script)
if ($Browser) { $psArgs += '-Browser' }

& $psExe @psArgs
