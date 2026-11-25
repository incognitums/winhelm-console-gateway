#Requires -Version 5.1
<#
    Open the tool console as an app window (Edge --app), no install required.

    Why this shape:
      - Electron/WebView2 host = a runtime to install and update. Edge is already here.
      - The long-lived admin token must not appear in a browser command line, which any local
        process can read. So this script starts the admin server with the token in its
        environment, then hands the browser a single-use launch ticket instead. The ticket is
        exchanged for a Strict cookie and dies after one use.

    Called by the tray, or by hand:
        pwsh -File tray\open-console.ps1
        pwsh -File tray\open-console.ps1 -Browser     # force the default browser instead
#>
[CmdletBinding()]
param(
    [switch] $Browser,          # use the default browser instead of an Edge app window
    [int]    $Port = 18789,
    [int]    $Width = 1280,
    [int]    $Height = 900
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$adminDir = Join-Path $root 'admin'
$serverScript = Join-Path $adminDir 'admin-server.mjs'
$log = Join-Path $adminDir 'admin.log'
$pidFile = Join-Path $root 'admin.pid'

function Get-AdminProcess {
    if (-not (Test-Path $pidFile)) { return $null }
    $raw = (Get-Content $pidFile -Raw -ErrorAction SilentlyContinue)
    if ($raw -notmatch '^\s*(\d+)\s*$') { return $null }
    $procId = [int]$Matches[1]
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
    if (-not $cim) { return $null }
    if ($cim.Name -notmatch '^node(\.exe)?$') { return $null }
    if ($cim.CommandLine -notmatch 'admin[\\/]admin-server\.mjs') { return $null }   # pid reuse guard
    [pscustomobject]@{ Id = $procId }
}

# The pid file can be stale (killed by hand, crashed, or written by an older launcher), which
# leaves a previous admin server holding the port and answering with a token we no longer have.
# So also look at whoever is listening on the port, and only kill it when it is our own script.
function Get-AdminListeners([int] $p) {
    $owners = @(Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique)
    foreach ($owner in $owners) {
        if (-not $owner) { continue }
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$owner" -ErrorAction SilentlyContinue
        if (-not $cim) { continue }
        if ($cim.Name -notmatch '^node(\.exe)?$') { continue }
        if ($cim.CommandLine -notmatch 'admin[\\/]admin-server\.mjs') { continue }
        [pscustomobject]@{ Id = [int]$owner }
    }
}

function Stop-AdminProcess([int] $p) {
    $targets = @()
    $pidFileProc = Get-AdminProcess
    if ($pidFileProc) { $targets += $pidFileProc }
    $targets += @(Get-AdminListeners $p)
    $seen = @{}
    foreach ($t in $targets) {
        if ($seen.ContainsKey($t.Id)) { continue }
        $seen[$t.Id] = $true
        Stop-Process -Id $t.Id -Force -ErrorAction SilentlyContinue
    }
    if ($seen.Count -gt 0) { Start-Sleep -Milliseconds 600 }
    if (Test-Path $pidFile) { Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue }
}

function Test-Port([int] $p) {
    $c = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue
    [bool]$c
}

function Find-Edge {
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe' -ErrorAction SilentlyContinue
    if ($reg -and (Test-Path -LiteralPath $reg.'(default)')) { return $reg.'(default)' }
    $null
}

# --- 1. replace any previous admin server so the ticket and token are current
Stop-AdminProcess $Port

# --- 2. start it with the token and the launch ticket in the environment (never on the command line)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$rng.GetBytes($bytes)
$token = [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')

$ticketBytes = New-Object byte[] 24
$rng.GetBytes($ticketBytes)
$ticket = [Convert]::ToBase64String($ticketBytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')

$envWasSet = Test-Path Env:ADMIN_TOKEN
$previous = $env:ADMIN_TOKEN
$ticketWasSet = Test-Path Env:ADMIN_LAUNCH_TICKET
$previousTicket = $env:ADMIN_LAUNCH_TICKET
try {
    $env:ADMIN_TOKEN = $token
    $env:ADMIN_LAUNCH_TICKET = $ticket
    $proc = Start-Process -FilePath 'node' -ArgumentList @($serverScript) `
        -WorkingDirectory $root -WindowStyle Hidden `
        -RedirectStandardOutput $log -RedirectStandardError (Join-Path $adminDir 'admin.log.err') -PassThru
    Set-Content -LiteralPath $pidFile -Value $proc.Id -NoNewline -Encoding ascii
} finally {
    if ($envWasSet) { $env:ADMIN_TOKEN = $previous } else { Remove-Item Env:ADMIN_TOKEN -ErrorAction SilentlyContinue }
    if ($ticketWasSet) { $env:ADMIN_LAUNCH_TICKET = $previousTicket } else { Remove-Item Env:ADMIN_LAUNCH_TICKET -ErrorAction SilentlyContinue }
}

# --- 3. wait for the listener; the launcher already knows the ticket, so nothing is read back
$deadline = (Get-Date).AddSeconds(10)
while ((Get-Date) -lt $deadline -and -not (Test-Port $Port)) { Start-Sleep -Milliseconds 250 }

if (-not (Test-Port $Port)) {
    throw "admin server did not start listening on $Port; check $log"
}

$launch = "http://127.0.0.1:$Port/__launch?t=$ticket"

# --- 4. open it
if ($Browser) {
    Start-Process $launch | Out-Null
    "opened in default browser"
} else {
    $edge = Find-Edge
    if (-not $edge) {
        Start-Process $launch | Out-Null
        "Edge not found — opened in default browser instead"
    } else {
        $appProfile = Join-Path $env:LOCALAPPDATA 'WinHelm\ConsoleAppProfile'
        if (-not (Test-Path -LiteralPath $appProfile)) { New-Item -ItemType Directory -Path $appProfile -Force | Out-Null }
        Start-Process -FilePath $edge -ArgumentList @(
            "--app=$launch",
            "--user-data-dir=$appProfile",
            "--window-size=$Width,$Height",
            '--no-first-run'
        ) | Out-Null
        "opened as Edge app window ($Width x $Height)"
    }
}

[pscustomobject]@{
    admin_pid = $proc.Id
    port = $Port
    window = if ($Browser) { 'browser' } else { 'edge-app' }
    token_in_argv = $false
} | ConvertTo-Json -Compress
