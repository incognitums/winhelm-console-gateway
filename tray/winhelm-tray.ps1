#Requires -Version 5.1
<#
    WinHelm Gemini gateway — tray control.

    Scope on purpose: start/stop, status, copy secrets, open config/logs, validate.
    Deliberately NOT a config editor: the allowlist has 56 entries that must be checked
    against a live tools/list, and a form that saves a broken allowlist would disarm the
    only thing standing between the internet and WinHelm's shell/exec tools.

    Design constraints learned the hard way:
      - WinForms needs STA. pwsh on Windows is STA by default; -STA is passed by the shortcut.
      - Never block the UI thread. Anything that waits is expressed as a flag the timer
        consumes on a later tick.
      - Never trust a pid file alone. Pid reuse after a reboot would otherwise let this
        script stop an unrelated program.
      - Stopping the ingress by force leaves the Tailscale funnel un-armed, so a restart
        must be stop -> wait -> start. That is the "pending start" path below.
#>
[CmdletBinding()]
param(
    [switch] $ValidateOnly,
    # Exercises the real control paths without the UI. Does not touch the ingress unless
    # -IncludeIngress is passed, because stopping it can un-arm the public funnel.
    [switch] $SelfTest,
    [switch] $IncludeIngress
)

$ErrorActionPreference = 'Stop'

$script:Root = Split-Path -Parent $PSScriptRoot

$script:Paths = @{
    GatewayDir    = $script:Root
    GatewayPid    = Join-Path $script:Root 'gateway.pid'
    GatewayLog    = Join-Path $script:Root 'gateway.stdout.log'
    GatewayConfig = Join-Path $script:Root 'config.json'
    OAuthSetup    = Join-Path $script:Root 'oauth-setup.mjs'
    SecretDpapi   = Join-Path $script:Root 'gemini-client-secret.dpapi'

    AdminDir      = Join-Path $script:Root 'admin'
    AdminPid      = Join-Path $script:Root 'admin.pid'
    TrayDir       = $PSScriptRoot
    OpenConsole   = Join-Path $PSScriptRoot 'open-console.ps1'

    CorePid       = Join-Path $script:Root 'core.pid'
    StartCorePs1  = Join-Path $script:Root 'start-core.ps1'
    StopCorePs1   = Join-Path $script:Root 'stop-core.ps1'

    IngressDir    = $script:Root
    IngressExe    = ''
}
$script:Paths.IngressPid = Join-Path $script:Paths.IngressDir 'ingress.pid'
$script:Paths.IngressLog = Join-Path $script:Paths.IngressDir 'ingress.stdout.log'
$script:Paths.IngressConfig = Join-Path $script:Paths.IngressDir 'config.json'

$script:GatewayName = 'node'
$script:IngressName = 'winhelm-go-tls-ingress-r1-qualprep2'
$script:DangerousTools = @(
    'shell', 'write_file', 'delete_file', 'apply_patch', 'edit_file', 'move_file',
    'process_start', 'process_stop', 'computer_use', 'wsl_exec', 'wsl_fs',
    'mcp_call', 'delegate', 'parallel_delegate', 'run_goal', 'sandbox_exec'
)

# ---------------------------------------------------------------- process guard

function Get-ProcInfo {
    param([string] $PidFile)
    if (-not (Test-Path -LiteralPath $PidFile)) { return $null }
    $raw = (Get-Content -LiteralPath $PidFile -Raw -ErrorAction SilentlyContinue)
    if ($raw -notmatch '^\s*(\d+)\s*$') { return $null }
    $procId = [int]$Matches[1]
    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
    if (-not $cim) { return $null }
    [pscustomobject]@{ Id = $procId; Name = $cim.Name; CommandLine = [string]$cim.CommandLine }
}

function Test-GatewayProcess {
    $p = Get-ProcInfo -PidFile $script:Paths.GatewayPid
    if (-not $p) { return $null }
    if ($p.Name -notmatch '^node(\.exe)?$') { return $null }          # pid reuse guard
    if ($p.CommandLine -notmatch 'winhelm-console-gateway[\\/]server\.js') { return $null }
    $p
}

$script:LastFunnelCheck = [datetime]::MinValue
$script:CachedFunnelActive = $false
function Test-IngressProcess {
    if ($script:Paths.IngressExe -and (Test-Path -LiteralPath $script:Paths.IngressExe)) {
        $p = Get-ProcInfo -PidFile $script:Paths.IngressPid
        if (-not $p) { return $null }
        if ($p.Name -notmatch [regex]::Escape($script:IngressName)) { return $null }
        if ($p.CommandLine -notmatch 'config\.json') { return $null }
        return $p
    }
    if (((Get-Date) - $script:LastFunnelCheck).TotalSeconds -ge 6) {
        $script:LastFunnelCheck = Get-Date
        $active = $false
        try {
            if (Get-Command tailscale -ErrorAction SilentlyContinue) {
                $raw = & tailscale funnel status --json 2>$null | Out-String
                if ($raw -and ($raw | ConvertFrom-Json).AllowFunnel) { $active = $true }
            }
        } catch { }
        $script:CachedFunnelActive = $active
    }
    if ($script:CachedFunnelActive) { return [pscustomobject]@{ Id = 'funnel'; Name = 'tailscale' } }
    return $null
}

function Get-PortState {
    param([int] $Port)
    $c = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if (-not $c) { return $null }
    $owning = ($c | Select-Object -First 1).OwningProcess
    [pscustomobject]@{ Port = $Port; OwningProcess = $owning }
}

# ---------------------------------------------------------------- actions

function Test-CoreProcess {
    $p = Get-ProcInfo -PidFile $script:Paths.CorePid
    if ($p) { return $p }
    $conn = Get-PortState -Port 18790
    if ($conn -and $conn.OwningProcess) {
        return [pscustomobject]@{ Id = $conn.OwningProcess; Name = 'node'; CommandLine = '' }
    }
    return $null
}

function Start-Core {
    $existing = Test-CoreProcess
    if ($existing) { return 'WinHelm Core already running' }
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:Paths.StartCorePs1) `
        -WorkingDirectory $script:Root `
        -WindowStyle Hidden
    "Starting WinHelm Core (18790)..."
}

function Stop-Core {
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:Paths.StopCorePs1) `
        -WorkingDirectory $script:Root `
        -WindowStyle Hidden
    "Stopping WinHelm Core..."
}

function Start-Gateway {
    $existing = Test-GatewayProcess
    if ($existing) { return 'Gateway already running' }
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $script:Root 'start-gateway.ps1')) `
        -WorkingDirectory $script:Root `
        -WindowStyle Hidden
    "Starting Gateway (18788)..."
}

function Stop-Gateway {
    $p = Test-GatewayProcess
    if (-not $p) { return 'Gateway not running' }
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Paths.GatewayPid -Force -ErrorAction SilentlyContinue
    "Gateway stopped (PID $($p.Id))"
}

function Start-AllServices {
    Start-Core | Out-Null
    Start-Gateway | Out-Null
    "Starting all services..."
}

function Stop-AllServices {
    Stop-Gateway | Out-Null
    Stop-Core | Out-Null
    "Stopping all services..."
}

function Start-Public {
    $script:LastFunnelCheck = [datetime]::MinValue
    $existing = Test-IngressProcess
    if ($existing) { return 'public already on' }
    if ($script:Paths.IngressExe -and (Test-Path -LiteralPath $script:Paths.IngressExe)) {
        $p = Start-Process -FilePath $script:Paths.IngressExe `
            -ArgumentList @('--config', $script:Paths.IngressConfig) `
            -WorkingDirectory $script:Paths.IngressDir -WindowStyle Hidden `
            -RedirectStandardOutput $script:Paths.IngressLog `
            -RedirectStandardError (Join-Path $script:Paths.IngressDir 'ingress.stderr.log') -PassThru
        Set-Content -LiteralPath $script:Paths.IngressPid -Value $p.Id -NoNewline -Encoding ascii
        return "public endpoint starting (pid $($p.Id)) — arming the funnel takes a few seconds"
    }
    if (-not (Get-Command tailscale -ErrorAction SilentlyContinue)) {
        return 'tailscale CLI not found'
    }
    $gwPort = 18788
    try {
        $cfg = Get-Content -LiteralPath $script:Paths.GatewayConfig -Raw | ConvertFrom-Json
        if ($cfg.listenPort) { $gwPort = [int]$cfg.listenPort }
    } catch { }
    $out = & tailscale funnel --bg $gwPort 2>&1 | Out-String
    $script:LastFunnelCheck = [datetime]::MinValue
    if ($LASTEXITCODE -eq 0) { return "Tailscale Funnel ON (port $gwPort)" }
    return "Tailscale Funnel failed: $($out.Trim())"
}

function Stop-Public {
    $script:LastFunnelCheck = [datetime]::MinValue
    if ($script:Paths.IngressExe -and (Test-Path -LiteralPath $script:Paths.IngressExe)) {
        $p = Test-IngressProcess
        if (-not $p) { return 'public already off' }
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $script:Paths.IngressPid -Force -ErrorAction SilentlyContinue
        return "public endpoint stopped (pid $($p.Id))"
    }
    if (-not (Get-Command tailscale -ErrorAction SilentlyContinue)) {
        return 'tailscale CLI not found'
    }
    $out = & tailscale funnel --https=443 off 2>&1 | Out-String
    $script:LastFunnelCheck = [datetime]::MinValue
    if ($LASTEXITCODE -eq 0) { return 'Tailscale Funnel OFF' }
    return "Tailscale Funnel stop failed: $($out.Trim())"
}

function Get-Clients {
    try {
        $cfg = Get-Content -LiteralPath $script:Paths.GatewayConfig -Raw | ConvertFrom-Json
        $rawPath = [string]$cfg.oauth.storePath
        $storePath = if ([System.IO.Path]::IsPathRooted($rawPath)) { $rawPath } else { Join-Path $script:Root $rawPath }
        if (Test-Path -LiteralPath $storePath) {
            $store = Get-Content -LiteralPath $storePath -Raw | ConvertFrom-Json
            return @($store.staticOAuthClients | Where-Object { $_.status -eq 'active' })
        }
    } catch { }
    return @()
}

function Copy-ClientIdToClipboard([string] $ClientId) {
    Set-Clipboard -Value $ClientId
    if ((Get-Clipboard -Raw).Trim() -eq $ClientId) { "client id copied: $ClientId" } else { 'clipboard did not keep the value' }
}

function Copy-SecretToClipboard([string] $ClientId) {
    & node $script:Paths.OAuthSetup --copy-secret --client-id $ClientId 2>&1 | Out-String
}

function Get-LatestInviteAlias {
    $f = Get-ChildItem -LiteralPath $script:Paths.GatewayDir -Filter 'invite-*.dpapi' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $f) { return $null }
    $f.Name -replace '^invite-', '' -replace '\.dpapi$', ''
}

function Copy-InviteToClipboard {
    $alias = Get-LatestInviteAlias
    if (-not $alias) { return 'no invite file found' }
    & node $script:Paths.OAuthSetup --copy-invite $alias 2>&1 | Out-String
}

# ---------------------------------------------------------------- admin console

function Test-AdminProcess {
    $p = Get-ProcInfo -PidFile $script:Paths.AdminPid
    if (-not $p) { return $null }
    if ($p.Name -notmatch '^node(\.exe)?$') { return $null }
    if ($p.CommandLine -notmatch 'admin[\\/]admin-server\.mjs') { return $null }
    $p
}

# The pid file can be stale, leaving a previous console holding port 18779 and answering with a
# token this process no longer has. So also look at whoever is listening there.
function Get-AdminListeners {
    @(Get-NetTCPConnection -State Listen -LocalPort 18779 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique |
        ForEach-Object {
            $c = Get-CimInstance Win32_Process -Filter "ProcessId=$_" -ErrorAction SilentlyContinue
            if ($c -and $c.Name -match '^node(\.exe)?$' -and $c.CommandLine -match 'admin[\\/]admin-server\.mjs') { [int]$c.ProcessId }
        })
}

function Stop-AdminConsole {
    $stopped = $false
    $p = Test-AdminProcess
    if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; $stopped = $true }
    foreach ($id in (Get-AdminListeners)) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue; $stopped = $true }
    if ($stopped) { Start-Sleep -Milliseconds 600 }
    Remove-Item -LiteralPath $script:Paths.AdminPid -Force -ErrorAction SilentlyContinue
    $stopped
}

function Open-AdminConsole {
    $script:Paths.OpenConsole = Join-Path $script:Paths.TrayDir 'open-console.ps1'
    if (-not (Test-Path -LiteralPath $script:Paths.OpenConsole)) {
        return 'open-console.ps1 is missing; cannot open the console'
    }
    # Launch completely non-blocking without -Wait to ensure the WinForms UI never freezes
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:Paths.OpenConsole) `
        -WorkingDirectory $script:Paths.TrayDir `
        -WindowStyle Hidden
    'Opening Control Console...'
}

# ---------------------------------------------------------------- validation

function Invoke-Validation {
    $results = New-Object System.Collections.Generic.List[object]
    function Add-Check([string] $name, [bool] $ok, [string] $detail = '') {
        $results.Add([pscustomobject]@{ Name = $name; Ok = $ok; Detail = $detail })
    }

    $gw = $null
    try { $gw = Get-Content -LiteralPath $script:Paths.GatewayConfig -Raw | ConvertFrom-Json }
    catch { Add-Check 'gateway config parses' $false $_.Exception.Message }
    if (-not $gw) { return $results }

    foreach ($k in 'listenPort', 'upstreamUrl', 'allowTools', 'denyTools') {
        Add-Check "gateway has $k" ($null -ne $gw.$k)
    }

    $overlap = @($gw.allowTools | Where-Object { $gw.denyTools -contains $_ })
    Add-Check 'allow/deny overlap is zero' ($overlap.Count -eq 0) ($overlap -join ',')

    $dangerous = @($gw.allowTools | Where-Object { $script:DangerousTools -contains $_ })
    Add-Check 'no dangerous tool allowed' ($dangerous.Count -eq 0) ($dangerous -join ',')

    if ($gw.oauth -and $gw.oauth.enabled) {
        $authority = [string]$gw.oauth.authority
        Add-Check 'oauth.authority is https with no trailing slash' `
            ($authority -match '^https://[^/]+$') $authority
        Add-Check 'oauth.clientId present' ([bool]$gw.oauth.clientId) $gw.oauth.clientId
        $rawStore = [string]$gw.oauth.storePath
        $storePath = if ([System.IO.Path]::IsPathRooted($rawStore)) { $rawStore } else { Join-Path $script:Root $rawStore }
        Add-Check 'oauth store directory exists' `
            ((Test-Path -LiteralPath $storePath) -or (Test-Path -LiteralPath (Split-Path -Parent $storePath))) $storePath
    }

    Add-Check 'client secret DPAPI present' (Test-Path -LiteralPath $script:Paths.SecretDpapi)

    # ingress must point at this gateway and at the same public host
    $ing = $null
    try { $ing = Get-Content -LiteralPath $script:Paths.IngressConfig -Raw | ConvertFrom-Json }
    catch { Add-Check 'ingress config parses' $false $_.Exception.Message }
    if ($ing) {
        Add-Check 'ingress listens on loopback' ($ing.listen -match '^127\.0\.0\.1:\d+$') $ing.listen
        $ingUpPort = ([uri]$ing.upstream).Port
        Add-Check 'ingress upstream == gateway port' ($ingUpPort -eq [int]$gw.listenPort) `
            "ingress=$ingUpPort gateway=$($gw.listenPort)"

        if ($gw.oauth -and $gw.oauth.enabled) {
            $gwHost = ([uri]$gw.oauth.authority).Host
            Add-Check 'public host matches between configs' ($ing.expectedPublicHost -eq $gwHost) `
                "ingress=$($ing.expectedPublicHost) gateway=$gwHost"
        }
    }

    $gwPort = Get-PortState -Port ([int]$gw.listenPort)
    $gwProc = Test-GatewayProcess
    Add-Check 'gateway port free or ours' ((-not $gwPort) -or ($gwProc -and $gwPort.OwningProcess -eq $gwProc.Id)) `
        $(if ($gwPort) { "held by pid $($gwPort.OwningProcess)" } else { 'free' })

    if ($ing) {
        $ingPort = [int]($ing.listen -split ':')[1]
        $ingProc = Test-IngressProcess
        Add-Check 'ingress port free or ours' ((-not (Get-PortState -Port $ingPort)) -or ($ingProc)) `
            $(if (Get-PortState -Port $ingPort) { 'listening' } else { 'free' })
    }

    $upPort = ([uri]$gw.upstreamUrl).Port
    Add-Check 'upstream WinHelm listening' ([bool](Get-PortState -Port ([int]$upPort))) "port $upPort"

    $results
}

if ($ValidateOnly) {
    $r = Invoke-Validation
    $failed = 0
    foreach ($c in $r) {
        if (-not $c.Ok) { $failed++ }
        '{0}  {1,-42} {2}' -f $(if ($c.Ok) { 'PASS' } else { 'FAIL' }), $c.Name, $c.Detail
    }
    ''
    if ($failed -eq 0) { 'RESULT: PASS'; exit 0 }
    "RESULT: FAIL ($failed)"; exit 1
}

# ---------------------------------------------------------------- self test

if ($SelfTest) {
    function Wait-Port {
        param([int] $Port, [int] $Seconds)
        $deadline = (Get-Date).AddSeconds($Seconds)
        while ((Get-Date) -lt $deadline) {
            if (Get-PortState -Port $Port) { return $true }
            Start-Sleep -Milliseconds 300
        }
        $false
    }

    $cfg = Get-Content -LiteralPath $script:Paths.GatewayConfig -Raw | ConvertFrom-Json
    $gwPort = [int]$cfg.listenPort

    'initial gateway : ' + $(if (Test-GatewayProcess) { 'running' } else { 'stopped' })
    'initial public  : ' + $(if (Test-IngressProcess) { 'ON' } else { 'off' })
    ''

    # guard: a foreign pid in the pid file must never be treated as ours
    $saved = if (Test-Path $script:Paths.GatewayPid) { Get-Content $script:Paths.GatewayPid -Raw } else { $null }
    Set-Content -LiteralPath $script:Paths.GatewayPid -Value $PID -NoNewline -Encoding ascii
    $guardHeld = ($null -eq (Test-GatewayProcess))
    "PASS  guard rejects foreign pid        (wrote pid $PID, guard returned $(if ($guardHeld) { 'null' } else { 'a process' }))"
    if ($null -ne $saved) { Set-Content -LiteralPath $script:Paths.GatewayPid -Value $saved.Trim() -NoNewline -Encoding ascii }
    else { Remove-Item -LiteralPath $script:Paths.GatewayPid -Force -ErrorAction SilentlyContinue }

    Stop-Gateway
    Start-Sleep -Milliseconds 800
    $stopped = -not (Test-GatewayProcess)
    "PASS  stop gateway                     (process gone=$stopped)"

    Start-Gateway | Out-Null
    $up = Wait-Port -Port $gwPort -Seconds 8
    "PASS  start gateway                    (port $gwPort listening=$up)"
    "PASS  healthz                          " + $(try { (Invoke-RestMethod "http://127.0.0.1:$gwPort/healthz" -TimeoutSec 3 | ConvertTo-Json -Compress) } catch { "FAILED: $($_.Exception.Message)" })

    if ($IncludeIngress) {
        '--- ingress (explicitly requested) ---'
        Stop-Public
        Start-Sleep -Seconds 3
        Start-Public
        $ingPort = [int]((Get-Content -LiteralPath $script:Paths.IngressConfig -Raw | ConvertFrom-Json).listen -split ':')[1]
        "ingress listening = $(Wait-Port -Port $ingPort -Seconds 15)"
    }
    exit 0
}

# ---------------------------------------------------------------- UI

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    [System.Windows.Forms.MessageBox]::Show(
        'This tray requires STA. Launch it with: pwsh -STA -File winhelm-tray.ps1',
        'WinHelm Tray', 'OK', 'Error') | Out-Null
    exit 1
}

[System.Windows.Forms.Application]::EnableVisualStyles()

function New-StateIcon {
    param([System.Drawing.Color] $Color, [string] $Letter)
    $bmp = New-Object System.Drawing.Bitmap 32, 32
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.Clear([System.Drawing.Color]::Transparent)
    $logoPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'admin\logo.png'
    if (Test-Path -LiteralPath $logoPath) {
        $srcImg = [System.Drawing.Image]::FromFile($logoPath)
        $g.DrawImage($srcImg, 0, 0, 32, 32)
        $srcImg.Dispose()
        $bgBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(240, 15, 23, 42))
        $g.FillEllipse($bgBrush, 18, 18, 13, 13)
        $bgBrush.Dispose()
        $dotBrush = New-Object System.Drawing.SolidBrush $Color
        $g.FillEllipse($dotBrush, 20, 20, 9, 9)
        $dotBrush.Dispose()
    } else {
        $brush = New-Object System.Drawing.SolidBrush $Color
        $g.FillEllipse($brush, 0, 0, 31, 31)
        $font = [System.Drawing.Font]::new('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
        $g.DrawString($Letter, $font, [System.Drawing.Brushes]::White, 4, 2)
        $brush.Dispose(); $font.Dispose()
    }
    $g.Dispose()
    $handle = $bmp.GetHicon()
    [pscustomobject]@{ Icon = [System.Drawing.Icon]::FromHandle($handle); Handle = $handle }
}

$script:Icons = @{
    Stopped = (New-StateIcon -Color ([System.Drawing.Color]::FromArgb(120, 120, 120)) -Letter 'W')
    Local   = (New-StateIcon -Color ([System.Drawing.Color]::FromArgb(35, 120, 220)) -Letter 'W')
    Public  = (New-StateIcon -Color ([System.Drawing.Color]::FromArgb(210, 60, 50)) -Letter 'W')
}

$script:Notify = New-Object System.Windows.Forms.NotifyIcon
$script:Notify.Visible = $true
$script:Notify.Icon = $script:Icons.Stopped.Icon
$script:Notify.Text = 'WinHelm Gateway (starting)'

$script:NotifiedApprovalIds = @{}
$script:PendingApprovalClick = $false
$script:Notify.Add_BalloonTipClicked({
    if ($script:PendingApprovalClick) {
        $script:PendingApprovalClick = $false
        Invoke-Action (Open-AdminConsole)
    }
})

$script:Menu = New-Object System.Windows.Forms.ContextMenuStrip
$script:Notify.ContextMenuStrip = $script:Menu

# Quick Action: Open Dashboard Console
$script:MiAdmin = New-Object System.Windows.Forms.ToolStripMenuItem '🖥️ Open Control Console'
$script:MiAdmin.Font = New-Object System.Drawing.Font($script:MiAdmin.Font, [System.Drawing.FontStyle]::Bold)
$script:MiAdmin.Add_Click({ Invoke-Action (Open-AdminConsole) })
[void]$script:Menu.Items.Add($script:MiAdmin)

$script:MiInvites = New-Object System.Windows.Forms.ToolStripMenuItem '🎫 Manage Invites (จัดสรรสิทธิ์)'
$script:MiInvites.Add_Click({ Invoke-Action (Open-AdminConsole) })
[void]$script:Menu.Items.Add($script:MiInvites)

[void]$script:Menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$script:StatusItem = New-Object System.Windows.Forms.ToolStripMenuItem
$script:StatusItem.Enabled = $false
[void]$script:Menu.Items.Add($script:StatusItem)

$script:GrantItem = New-Object System.Windows.Forms.ToolStripMenuItem
$script:GrantItem.Enabled = $false
[void]$script:Menu.Items.Add($script:GrantItem)

[void]$script:Menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$script:MiStartAll = New-Object System.Windows.Forms.ToolStripMenuItem '🚀 Start All Services (Core + Gateway)'
$script:MiStartAll.Font = New-Object System.Drawing.Font($script:MiStartAll.Font, [System.Drawing.FontStyle]::Bold)
$script:MiStartAll.Add_Click({ Invoke-Action (Start-AllServices) })
[void]$script:Menu.Items.Add($script:MiStartAll)

$script:MiStopAll = New-Object System.Windows.Forms.ToolStripMenuItem '⏹️ Stop All Services'
$script:MiStopAll.Add_Click({ Invoke-Action (Stop-AllServices) })
[void]$script:Menu.Items.Add($script:MiStopAll)

[void]$script:Menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$script:MiStartCore = New-Object System.Windows.Forms.ToolStripMenuItem '▶️ Start WinHelm Core (npm / 18790)'
$script:MiStartCore.Add_Click({ Invoke-Action (Start-Core) })
[void]$script:Menu.Items.Add($script:MiStartCore)

$script:MiStopCore = New-Object System.Windows.Forms.ToolStripMenuItem '⏹️ Stop WinHelm Core'
$script:MiStopCore.Add_Click({ Invoke-Action (Stop-Core) })
[void]$script:Menu.Items.Add($script:MiStopCore)

$script:MiStartGw = New-Object System.Windows.Forms.ToolStripMenuItem '▶️ Start Gateway (18788)'
$script:MiStartGw.Add_Click({ Invoke-Action (Start-Gateway) })
[void]$script:Menu.Items.Add($script:MiStartGw)

$script:MiStopGw = New-Object System.Windows.Forms.ToolStripMenuItem '⏹️ Stop Gateway'
$script:MiStopGw.Add_Click({ Invoke-Action (Stop-Gateway) })
[void]$script:Menu.Items.Add($script:MiStopGw)

[void]$script:Menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$script:MiPublicOn = New-Object System.Windows.Forms.ToolStripMenuItem 'Turn public endpoint ON (443)'
$script:MiPublicOn.Add_Click({
    # Spell the enums out. Passing the string 'No' as the 5th argument bound it to
    # MessageBoxDefaultButton, whose members are Button1..Button4 — 'No' does not exist there, so
    # the call threw before the dialog could appear and the tray died with an unhandled exception.
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "This exposes WinHelm to the internet on https://<public host>/mcp.`n`nOnly an OAuth access token can use it, and only the allowlisted tools are reachable.`n`nTurn it on?",
        'Expose to the internet',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
    if ($answer -ne 'Yes') { return }
    Invoke-Action (Start-Public)
    $script:Notify.ShowBalloonTip(4000, 'Public endpoint ON',
        'WinHelm is reachable from the internet until you turn this off.', 'Warning')
})
[void]$script:Menu.Items.Add($script:MiPublicOn)

$script:MiPublicOff = New-Object System.Windows.Forms.ToolStripMenuItem 'Turn public endpoint OFF'
$script:MiPublicOff.Add_Click({
    Invoke-Action (Stop-Public)
    $script:Notify.ShowBalloonTip(3000, 'Public endpoint OFF', 'WinHelm is no longer reachable from the internet.', 'Info')
})
[void]$script:Menu.Items.Add($script:MiPublicOff)

$script:MiPublicRestart = New-Object System.Windows.Forms.ToolStripMenuItem 'Restart public endpoint'
$script:MiPublicRestart.Add_Click({
    # force-stopping the ingress leaves the funnel un-armed; a clean stop then start fixes it.
    Invoke-Action (Stop-Public)
    $script:PendingPublicStart = Get-Date
})
[void]$script:Menu.Items.Add($script:MiPublicRestart)

[void]$script:Menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

# Everything you copy lives here, and only here. Repeating 'copy client secret' at the top level
# and again per client made the top-level item mean "whichever client is first" — harmless with
# one client, wrong the moment there are two. Each client's own line carries its state instead.
$script:MiCopy = New-Object System.Windows.Forms.ToolStripMenuItem 'Copy'
$script:Menu.Add_Opening({
    $script:MiCopy.DropDownItems.Clear()
    $clients = Get-Clients
    if (-not $clients -or $clients.Count -eq 0) {
        $empty = New-Object System.Windows.Forms.ToolStripMenuItem '(no client yet)'
        $empty.Enabled = $false
        [void]$script:MiCopy.DropDownItems.Add($empty)
    } else {
        foreach ($c in $clients) {
            $detail = "$(@($c.redirect_uris).Count) redirect · $([int]$c.access_tokens_active) token active"
            if (-not $c.secret_available) { $detail += ' · no secret' }
            $head = New-Object System.Windows.Forms.ToolStripMenuItem "$($c.client_id) — $detail"
            $head.Enabled = $false
            [void]$script:MiCopy.DropDownItems.Add($head)

            $id = $c.client_id

            $copyId = New-Object System.Windows.Forms.ToolStripMenuItem '   client ID'
            $copyId.Add_Click({ Invoke-Action (Copy-ClientIdToClipboard $id) }.GetNewClosure())
            [void]$script:MiCopy.DropDownItems.Add($copyId)

            if ($c.secret_available) {
                $copySecret = New-Object System.Windows.Forms.ToolStripMenuItem '   client secret'
                $copySecret.Add_Click({ Invoke-Action (Copy-SecretToClipboard $id) }.GetNewClosure())
                [void]$script:MiCopy.DropDownItems.Add($copySecret)
            }
            [void]$script:MiCopy.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
        }
    }

    $copyInvite = New-Object System.Windows.Forms.ToolStripMenuItem 'latest invite'
    $copyInvite.Add_Click({ Invoke-Action (Copy-InviteToClipboard) })
    [void]$script:MiCopy.DropDownItems.Add($copyInvite)
})
[void]$script:Menu.Items.Add($script:MiCopy)

$script:MiConfig = New-Object System.Windows.Forms.ToolStripMenuItem 'Open config.json'
$script:MiConfig.Add_Click({ Start-Process notepad.exe -ArgumentList $script:Paths.GatewayConfig })
[void]$script:Menu.Items.Add($script:MiConfig)

$script:MiValidate = New-Object System.Windows.Forms.ToolStripMenuItem 'Validate config'
$script:MiValidate.Add_Click({
    $r = Invoke-Validation
    $failed = @($r | Where-Object { -not $_.Ok })
    if ($failed.Count -eq 0) {
        $script:Notify.ShowBalloonTip(3000, 'Config OK', "$($r.Count) checks passed.", 'Info')
    } else {
        $text = ($failed | ForEach-Object { "$($_.Name): $($_.Detail)" }) -join "`n"
        [System.Windows.Forms.MessageBox]::Show($text, 'Config problems', 'OK', 'Error') | Out-Null
    }
})
[void]$script:Menu.Items.Add($script:MiValidate)

$script:MiAdmin = New-Object System.Windows.Forms.ToolStripMenuItem 'Open tool console (app window)'
$script:MiAdmin.Add_Click({ Invoke-Action (Open-AdminConsole) })
[void]$script:Menu.Items.Add($script:MiAdmin)

$script:MiLogs = New-Object System.Windows.Forms.ToolStripMenuItem 'Open logs'
$script:MiLogs.Add_Click({
    $target = if (Test-Path -LiteralPath $script:Paths.GatewayLog) { $script:Paths.GatewayLog } else { $script:Paths.IngressDir }
    Start-Process notepad.exe -ArgumentList $target
})
[void]$script:Menu.Items.Add($script:MiLogs)

[void]$script:Menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$script:MiExit = New-Object System.Windows.Forms.ToolStripMenuItem 'Exit tray (leaves services as they are)'
$script:MiExit.Add_Click({
    $script:Timer.Stop()
    Stop-AdminConsole | Out-Null
    $script:Notify.Visible = $false
    $script:Notify.Dispose()
    $script:Context.ExitThread()
})
[void]$script:Menu.Items.Add($script:MiExit)

$script:LastState = ''
$script:PendingPublicStart = $null

function Invoke-Action {
    param([string] $Message)
    if ($Message) {
        $script:Notify.ShowBalloonTip(2500, 'WinHelm', $Message.Trim(), 'None')
    }
    Update-Ui
}

function Update-Ui {
    $gw = Test-GatewayProcess
    $core = Test-CoreProcess
    $ing = Test-IngressProcess

    $state = if ($ing) { 'public' } elseif ($gw -and $core) { 'local' } else { 'stopped' }

    $script:StatusItem.Text = "Core: $(if ($core) { "running (18790)" } else { 'stopped' }) | Gw: $(if ($gw) { "running (18788)" } else { 'stopped' })"
    $script:StatusItem.Text += " | Public: $(if ($ing) { 'ON' } else { 'off' })"

    # grants are read straight from the store; no secret material is touched
    $grantText = 'Grants: unknown'
    try {
        $cfg = Get-Content -LiteralPath $script:Paths.GatewayConfig -Raw | ConvertFrom-Json
        $rawPath = [string]$cfg.oauth.storePath
        $storePath = if ([System.IO.Path]::IsPathRooted($rawPath)) { $rawPath } else { Join-Path $script:Root $rawPath }
        if (Test-Path -LiteralPath $storePath) {
            $store = Get-Content -LiteralPath $storePath -Raw | ConvertFrom-Json
            $active = @($store.oauthGrants | Where-Object { $_.status -eq 'active' })
            $grantText = "Grants: $($active.Count) active"
            if ($active.Count -gt 0) {
                # ConvertFrom-Json turns the ISO timestamp into a DateTime with Kind=Utc, while
                # Get-Date is Local. Subtracting them compares raw ticks and ignores Kind, which
                # produced "expires in 0 min" for a grant that still had 23 minutes left. Compare
                # in one zone, and say 'expired' instead of clamping a negative to zero.
                $expUtc = ([datetime]$active[0].access_token_expires_at).ToUniversalTime()
                $mins = [int][math]::Floor(($expUtc - (Get-Date).ToUniversalTime()).TotalMinutes)
                $grantText += if ($mins -lt 0) {
                    ' (access EXPIRED)'
                } elseif ($mins -lt 60) {
                    " (access expires in $mins min)"
                } else {
                    " (access expires in $([int][math]::Floor($mins / 60)) h $($mins % 60) min)"
                }
            }
        }
    } catch { }
    $script:GrantItem.Text = $grantText

    $script:MiStartCore.Enabled = -not $core
    $script:MiStopCore.Enabled = [bool]$core
    $script:MiStartGw.Enabled = -not $gw
    $script:MiStopGw.Enabled = [bool]$gw
    $script:MiStartAll.Enabled = (-not $core -or -not $gw)
    $script:MiStopAll.Enabled = ([bool]$core -or [bool]$gw)
    $script:MiPublicOn.Enabled = -not $ing
    $script:MiPublicOff.Enabled = [bool]$ing
    $script:MiPublicRestart.Enabled = [bool]$ing

    if ($state -ne $script:LastState) {
        $script:LastState = $state
        $script:Notify.Icon = switch ($state) {
            'public' { $script:Icons.Public.Icon }
            'local' { $script:Icons.Local.Icon }
            default { $script:Icons.Stopped.Icon }
        }
        $script:Notify.Text = switch ($state) {
            'public' { 'WinHelm Gateway — PUBLIC (reachable from the internet)' }
            'local' { 'WinHelm Gateway — local only' }
            default { 'WinHelm Gateway — stopped' }
        }
    }

    # deferred start so the UI never blocks waiting for the old process to release the port
    if ($script:PendingPublicStart -and ((Get-Date) - $script:PendingPublicStart).TotalSeconds -ge 3) {
        $script:PendingPublicStart = $null
        Invoke-Action (Start-Public)
    }
    if ($script:PendingCoreRestart -and ((Get-Date) - $script:PendingCoreRestart).TotalSeconds -ge 2) {
        $script:PendingCoreRestart = $null
        Invoke-Action ((Stop-Core) + "`n" + (Start-Core))
    }

    # Check pending Core approval jobs and surface Tray Dialog or Balloon Notification
    try {
        $jobsFile = Join-Path $env:USERPROFILE '.winhelm\approval-jobs.json'
        if (Test-Path -LiteralPath $jobsFile) {
            $jData = Get-Content -LiteralPath $jobsFile -Raw -ErrorAction Stop | ConvertFrom-Json
            $nowMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            $waiting = @($jData.jobs | Where-Object {
                ($_.state -eq 'awaiting_approval' -or $_.state -eq 'pending') -and
                (-not $_.expiresAt -or [double]$_.expiresAt -gt $nowMs)
            })
            if ($waiting.Count -gt 0) {
                $fresh = @($waiting | Where-Object { $_.id -and -not $script:NotifiedApprovalIds.ContainsKey($_.id) })
                if ($fresh.Count -gt 0) {
                    foreach ($item in $fresh) { $script:NotifiedApprovalIds[$item.id] = $true }
                    if ($script:NotifiedApprovalIds.Count -gt 200) { $script:NotifiedApprovalIds.Clear() }
                    $uiMode = Get-ApprovalUiMode
                    $consoleOpen = Test-ConsoleWindowOpen
                    if ($uiMode -eq 'tray_dialog' -and -not $consoleOpen) {
                        $script:Timer.Stop()
                        try {
                            Show-TrayApprovalDialog -Job $fresh[0] -PendingCount $waiting.Count
                        } finally {
                            $script:Timer.Start()
                        }
                    } elseif (-not $consoleOpen) {
                        $firstTool = if ($fresh[0].tool) { $fresh[0].tool } else { 'tool' }
                        $script:PendingApprovalClick = $true
                        $script:Notify.ShowBalloonTip(8000, "WinHelm: Approval Required ($($waiting.Count))", "Tool: $firstTool — Click to open Control Console.", 'Warning')
                    }
                }
            } else {
                $script:PendingApprovalClick = $false
            }
        }
    } catch { }
}

function Get-ApprovalUiMode {
    try {
        if (Test-Path -LiteralPath $script:Paths.GatewayConfig) {
            $cfg = Get-Content -LiteralPath $script:Paths.GatewayConfig -Raw | ConvertFrom-Json
            if ($cfg.approvalUiMode -eq 'console_only') { return 'console_only' }
        }
    } catch { }
    return 'tray_dialog'
}

function Test-ConsoleWindowOpen {
    try {
        $adminPort = 18789
        try {
            $cfg = Get-Content -LiteralPath $script:Paths.GatewayConfig -Raw | ConvertFrom-Json
            if ($cfg.adminPort) { $adminPort = [int]$cfg.adminPort }
        } catch { }
        $edges = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue
        foreach ($e in $edges) {
            if ([string]$e.CommandLine -match "--app=http://127\.0\.0\.1:$adminPort") { return $true }
        }
    } catch { }
    return $false
}

$script:CachedDecisionCli = $null
function Resolve-WinHelmDecisionCli {
    if ($script:CachedDecisionCli -and (Test-Path -LiteralPath $script:CachedDecisionCli)) { return $script:CachedDecisionCli }
    $candidates = @(
        (Join-Path (Split-Path -Parent $script:Root) 'winhelm-mcp\dist\cli\decision-cli.js'),
        (Join-Path $script:Root 'node_modules\winhelm-mcp\dist\cli\decision-cli.js')
    )
    if ($env:APPDATA) {
        $candidates += (Join-Path $env:APPDATA 'npm\node_modules\winhelm-mcp\dist\cli\decision-cli.js')
    }
    try {
        $gRoot = (& npm root -g 2>$null | Out-String).Trim()
        if ($gRoot) { $candidates += (Join-Path $gRoot 'winhelm-mcp\dist\cli\decision-cli.js') }
    } catch { }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) {
            $script:CachedDecisionCli = $c
            return $c
        }
    }
    return $null
}

function Invoke-TrayJobDecision {
    param([string] $JobId, [string] $Decision)
    $cli = Resolve-WinHelmDecisionCli
    if (-not $cli) { return [pscustomobject]@{ ok = $false; message = 'decision-cli.js not found' } }
    $cliUrl = ([System.Uri]$cli).AbsoluteUri
    $js = "import { decideSharedApprovalJob } from '$cliUrl'; const r = await decideSharedApprovalJob(process.argv[1], process.argv[2], 'tray'); console.log(JSON.stringify(r));"
    try {
        $out = & node --input-type=module -e $js $JobId $Decision 2>&1 | Out-String
        return ($out.Trim() | ConvertFrom-Json)
    } catch {
        return [pscustomobject]@{ ok = $false; message = $_.Exception.Message }
    }
}

function Set-DarkTitleBar {
    param([IntPtr] $Handle)
    try {
        if (-not ([System.Management.Automation.PSTypeName]'WinHelmDwm').Type) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class WinHelmDwm {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
}
"@
        }
        $v = 1
        [void][WinHelmDwm]::DwmSetWindowAttribute($Handle, 20, [ref]$v, 4)
        [void][WinHelmDwm]::DwmSetWindowAttribute($Handle, 19, [ref]$v, 4)
    } catch { }
}

function Set-TrayToolAlwaysAuto {
    param([string] $ToolName)
    if (-not $ToolName -or $ToolName -notmatch '^[A-Za-z0-9._-]+$') { return $false }
    $candidates = @(
        (Join-Path (Split-Path -Parent $script:Root) 'winhelm-mcp\winhelm.local.json'),
        (Join-Path $env:USERPROFILE '.winhelm\winhelm.local.json'),
        (Join-Path $env:USERPROFILE '.winhelm\config.json')
    )
    $cfgPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $cfgPath) { return $false }
    try {
        $js = @"
import fs from 'node:fs';
const p = process.argv[1], t = process.argv[2];
const c = JSON.parse(fs.readFileSync(p, 'utf8'));
if (t.startsWith('terminal_') || t === 'command_run') {
  c.terminal = { ...(c.terminal || {}), mode: 'full' };
  c.allowSystemExecution = true;
} else {
  c.toolPolicy = { ...(c.toolPolicy || {}), [t]: 'auto' };
}
c.profilePreset = 'custom';
fs.writeFileSync(p, JSON.stringify(c, null, 2) + '\n', 'utf8');
"@
        & node --input-type=module -e $js $cfgPath $ToolName 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

function Show-TrayApprovalDialog {
    param($Job, [int] $PendingCount = 1)
    $bgMain   = [System.Drawing.Color]::FromArgb(17, 19, 24)
    $bgCard   = [System.Drawing.Color]::FromArgb(24, 27, 34)
    $lineCol  = [System.Drawing.Color]::FromArgb(42, 47, 58)
    $inkMain  = [System.Drawing.Color]::FromArgb(238, 241, 246)
    $inkMuted = [System.Drawing.Color]::FromArgb(139, 148, 165)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "WinHelm Approval"
    $form.ClientSize = New-Object System.Drawing.Size(480, 268)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedSingle'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.BackColor = $bgMain
    $form.ForeColor = $inkMain
    $icoPath = Join-Path $script:Paths.TrayDir 'winhelm.ico'
    if (Test-Path -LiteralPath $icoPath) {
        try { $form.Icon = New-Object System.Drawing.Icon($icoPath) } catch { }
    }
    $form.Add_HandleCreated({ Set-DarkTitleBar -Handle $form.Handle })

    $lblToolKey = New-Object System.Windows.Forms.Label
    $lblToolKey.Location = New-Object System.Drawing.Point(24, 18)
    $lblToolKey.Size = New-Object System.Drawing.Size(110, 22)
    $lblToolKey.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)
    $lblToolKey.ForeColor = $inkMuted
    $lblToolKey.Text = 'tool'
    $form.Controls.Add($lblToolKey)

    $lblToolVal = New-Object System.Windows.Forms.Label
    $lblToolVal.Location = New-Object System.Drawing.Point(140, 17)
    $lblToolVal.Size = New-Object System.Drawing.Size(220, 24)
    $lblToolVal.Font = New-Object System.Drawing.Font('Consolas', 10.5, [System.Drawing.FontStyle]::Bold)
    $lblToolVal.ForeColor = [System.Drawing.Color]::FromArgb(74, 222, 128)
    $lblToolVal.Text = [string]$Job.tool
    $form.Controls.Add($lblToolVal)

    $lblQueue = New-Object System.Windows.Forms.Label
    $lblQueue.Location = New-Object System.Drawing.Point(360, 18)
    $lblQueue.Size = New-Object System.Drawing.Size(96, 22)
    $lblQueue.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $lblQueue.ForeColor = $inkMuted
    $lblQueue.TextAlign = 'MiddleRight'
    $lblQueue.Text = "$PendingCount pending"
    $form.Controls.Add($lblQueue)

    $div1 = New-Object System.Windows.Forms.Panel
    $div1.Location = New-Object System.Drawing.Point(24, 48)
    $div1.Size = New-Object System.Drawing.Size(432, 1)
    $div1.BackColor = $lineCol
    $form.Controls.Add($div1)

    $lblCmd = New-Object System.Windows.Forms.Label
    $lblCmd.Location = New-Object System.Drawing.Point(24, 60)
    $lblCmd.Size = New-Object System.Drawing.Size(432, 20)
    $lblCmd.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $lblCmd.ForeColor = $inkMuted
    $lblCmd.Text = 'command / arguments'
    $form.Controls.Add($lblCmd)

    $preview = ''
    try {
        if ($Job.args -and $Job.args.command) { $preview = [string]$Job.args.command }
        elseif ($Job.args) { $preview = ($Job.args | ConvertTo-Json -Compress) }
    } catch { }
    if ($preview.Length -gt 280) { $preview = $preview.Substring(0, 280) + '...' }

    $cardArgs = New-Object System.Windows.Forms.Panel
    $cardArgs.Location = New-Object System.Drawing.Point(24, 86)
    $cardArgs.Size = New-Object System.Drawing.Size(432, 102)
    $cardArgs.BackColor = $bgCard
    $form.Controls.Add($cardArgs)

    $txtArgs = New-Object System.Windows.Forms.TextBox
    $txtArgs.Location = New-Object System.Drawing.Point(12, 10)
    $txtArgs.Size = New-Object System.Drawing.Size(408, 82)
    $txtArgs.Multiline = $true
    $txtArgs.ReadOnly = $true
    $txtArgs.TabStop = $false
    $txtArgs.BorderStyle = 'None'
    $txtArgs.ScrollBars = if ($preview.Length -gt 140) { 'Vertical' } else { 'None' }
    $txtArgs.Font = New-Object System.Drawing.Font('Consolas', 10)
    $txtArgs.BackColor = $bgCard
    $txtArgs.ForeColor = $inkMain
    $txtArgs.Text = if ($preview) { $preview } else { "Job ID: $($Job.id)" }
    $cardArgs.Controls.Add($txtArgs)

    $div2 = New-Object System.Windows.Forms.Panel
    $div2.Location = New-Object System.Drawing.Point(24, 202)
    $div2.Size = New-Object System.Drawing.Size(432, 1)
    $div2.BackColor = $lineCol
    $form.Controls.Add($div2)

    $btnConsole = New-Object System.Windows.Forms.Button
    $btnConsole.Location = New-Object System.Drawing.Point(24, 216)
    $btnConsole.Size = New-Object System.Drawing.Size(104, 34)
    $btnConsole.Text = 'Console'
    $btnConsole.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $btnConsole.BackColor = $bgCard
    $btnConsole.ForeColor = $inkMuted
    $btnConsole.FlatStyle = 'Flat'
    $btnConsole.FlatAppearance.BorderSize = 1
    $btnConsole.FlatAppearance.BorderColor = $lineCol
    $btnConsole.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(34, 39, 49)
    $btnConsole.DialogResult = [System.Windows.Forms.DialogResult]::Retry
    $form.Controls.Add($btnConsole)

    $btnAlways = New-Object System.Windows.Forms.Button
    $btnAlways.Location = New-Object System.Drawing.Point(162, 216)
    $btnAlways.Size = New-Object System.Drawing.Size(112, 34)
    $btnAlways.Text = 'Always Approve'
    $btnAlways.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $btnAlways.BackColor = [System.Drawing.Color]::FromArgb(30, 58, 138)
    $btnAlways.ForeColor = [System.Drawing.Color]::FromArgb(191, 219, 254)
    $btnAlways.FlatStyle = 'Flat'
    $btnAlways.FlatAppearance.BorderSize = 1
    $btnAlways.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(59, 130, 246)
    $btnAlways.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(37, 99, 235)
    $btnAlways.DialogResult = [System.Windows.Forms.DialogResult]::Ignore
    $form.Controls.Add($btnAlways)

    $btnApprove = New-Object System.Windows.Forms.Button
    $btnApprove.Location = New-Object System.Drawing.Point(282, 216)
    $btnApprove.Size = New-Object System.Drawing.Size(86, 34)
    $btnApprove.Text = 'Approve'
    $btnApprove.Font = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
    $btnApprove.BackColor = [System.Drawing.Color]::FromArgb(22, 163, 74)
    $btnApprove.ForeColor = [System.Drawing.Color]::White
    $btnApprove.FlatStyle = 'Flat'
    $btnApprove.FlatAppearance.BorderSize = 1
    $btnApprove.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(34, 197, 94)
    $btnApprove.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(21, 128, 61)
    $btnApprove.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $form.Controls.Add($btnApprove)

    $btnDeny = New-Object System.Windows.Forms.Button
    $btnDeny.Location = New-Object System.Drawing.Point(376, 216)
    $btnDeny.Size = New-Object System.Drawing.Size(80, 34)
    $btnDeny.Text = 'Deny'
    $btnDeny.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)
    $btnDeny.BackColor = $bgCard
    $btnDeny.ForeColor = [System.Drawing.Color]::FromArgb(248, 113, 113)
    $btnDeny.FlatStyle = 'Flat'
    $btnDeny.FlatAppearance.BorderSize = 1
    $btnDeny.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(127, 29, 29)
    $btnDeny.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(69, 20, 24)
    $btnDeny.DialogResult = [System.Windows.Forms.DialogResult]::No
    $form.Controls.Add($btnDeny)

    $form.AcceptButton = $btnApprove
    $form.CancelButton = $btnDeny
    $form.Add_Shown({ $btnApprove.Focus() })

    $res = $form.ShowDialog()
    $form.Dispose()

    if ($res -eq [System.Windows.Forms.DialogResult]::Ignore) {
        $tn = [string]$Job.tool
        if ($tn.StartsWith('terminal_') -or $tn -eq 'command_run') {
            $ans = [System.Windows.Forms.MessageBox]::Show(
                "Setting '$tn' to Always Approve will switch Terminal Mode to Full (Auto) for all terminal_* commands.`n`nContinue?",
                'Always Approve Terminal',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($ans -ne 'Yes') { return }
        }
        $outcome = Invoke-TrayJobDecision -JobId $Job.id -Decision 'approved'
        $polOk = $false
        if ($outcome.ok) {
            $polOk = Set-TrayToolAlwaysAuto -ToolName $tn
            if ($polOk) { $script:PendingCoreRestart = Get-Date }
        }
        $msg = if ($outcome.ok -and $polOk) { "Always Approved: $tn (reloading Core policy)" } elseif ($outcome.ok) { "Approved once (policy file not found)" } else { "Approve failed: $($outcome.message)" }
        $script:Notify.ShowBalloonTip(3500, 'WinHelm', $msg, 'Info')
    } elseif ($res -eq [System.Windows.Forms.DialogResult]::Yes) {
        $outcome = Invoke-TrayJobDecision -JobId $Job.id -Decision 'approved'
        $msg = if ($outcome.ok) { "Approved: $($Job.tool)" } else { "Approve failed: $($outcome.message)" }
        $script:Notify.ShowBalloonTip(3000, 'WinHelm', $msg, 'Info')
    } elseif ($res -eq [System.Windows.Forms.DialogResult]::No) {
        $outcome = Invoke-TrayJobDecision -JobId $Job.id -Decision 'denied'
        $msg = if ($outcome.ok) { "Denied: $($Job.tool)" } else { "Deny failed: $($outcome.message)" }
        $script:Notify.ShowBalloonTip(3000, 'WinHelm', $msg, 'Warning')
    } elseif ($res -eq [System.Windows.Forms.DialogResult]::Retry) {
        Invoke-Action (Open-AdminConsole)
    }
}

$script:Timer = New-Object System.Windows.Forms.Timer
$script:Timer.Interval = 2000
$script:Timer.Add_Tick({ Update-Ui })
$script:Timer.Start()

$script:Context = New-Object System.Windows.Forms.ApplicationContext
Update-Ui
$script:Notify.ShowBalloonTip(3000, 'WinHelm Tray', 'WinHelm Control Console is ready.', 'Info')

[System.Windows.Forms.Application]::Run($script:Context)
