#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  WinHelm Console & Gateway - First-Run Setup & Doctor" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "Directory: $root`n"

$okAll = $true

# 1. Check Node.js
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if ($nodeCmd) {
    $nodeVer = (& node -v).Trim()
    Write-Host "[OK] Node.js: $nodeVer" -ForegroundColor Green
} else {
    Write-Host "[MISSING] Node.js v20+ is required (https://nodejs.org)" -ForegroundColor Red
    $okAll = $false
}

# 2. Check Microsoft Edge
$edgePaths = @(
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
)
$edgeFound = $edgePaths | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if ($edgeFound) {
    Write-Host "[OK] Microsoft Edge: found" -ForegroundColor Green
} else {
    Write-Host "[WARN] Microsoft Edge not found in standard paths (will fallback to default browser)" -ForegroundColor Yellow
}

# 3. Check Tailscale
$tsDomain = $null
$tsCmd = Get-Command tailscale -ErrorAction SilentlyContinue
if ($tsCmd) {
    try {
        $tsRaw = & tailscale status --json 2>$null | ConvertFrom-Json
        if ($tsRaw.Self.DNSName) {
            $tsDomain = $tsRaw.Self.DNSName.TrimEnd('.')
            Write-Host "[OK] Tailscale: connected ($tsDomain)" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Tailscale installed, but not logged in or DNSName missing" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[WARN] Tailscale installed, unable to read status" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] Tailscale CLI not found (required for public HTTPS Funnel)" -ForegroundColor Yellow
}

# 4. Check WinHelm Core availability
$localCore = Join-Path (Split-Path -Parent $root) "winhelm-mcp\dist\index.js"
$globalCore = Get-Command winhelm -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $localCore) {
    Write-Host "[OK] WinHelm Core: local build ($localCore)" -ForegroundColor Green
} elseif ($globalCore) {
    Write-Host "[OK] WinHelm Core: global command ($($globalCore.Source))" -ForegroundColor Green
} elseif (Get-Command npx -ErrorAction SilentlyContinue) {
    Write-Host "[OK] WinHelm Core: will run via npx winhelm-mcp" -ForegroundColor Green
} else {
    Write-Host "[MISSING] Neither local winhelm-mcp, global winhelm, nor npx was found" -ForegroundColor Red
    $okAll = $false
}

# 5. Initialize config.json if missing
$cfgPath = Join-Path $root "config.json"
$examplePath = Join-Path $root "config.example.json"
if (-not (Test-Path -LiteralPath $cfgPath)) {
    if (Test-Path -LiteralPath $examplePath) {
        $cfg = Get-Content -LiteralPath $examplePath -Raw | ConvertFrom-Json
        $winhelmDir = Join-Path $env:USERPROFILE ".winhelm"
        if (-not (Test-Path -LiteralPath $winhelmDir)) { New-Item -ItemType Directory -Path $winhelmDir -Force | Out-Null }
        $cfg.oauth.storePath = (Join-Path $winhelmDir "registered-ingress-r7.json") -replace '\\', '/'
        if ($tsDomain) {
            $cfg.baseUrl = "https://$tsDomain/mcp"
            $cfg.oauth.authority = "https://$tsDomain"
        }
        $cfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $cfgPath -Encoding utf8
        Write-Host "[CREATED] config.json initialized from config.example.json" -ForegroundColor Green
    } else {
        Write-Host "[WARN] config.example.json not found; skipping config.json creation" -ForegroundColor Yellow
    }
} else {
    Write-Host "[OK] config.json already exists (preserved)" -ForegroundColor Green
}

# 6. Build portable shortcuts pointing to this directory
$vbsPath = Join-Path $root "tray\launch-tray.vbs"
$icoPath = Join-Path $root "tray\winhelm.ico"
$ws = New-Object -ComObject WScript.Shell
foreach ($lnk in @((Join-Path $root "WinHelm Tray.lnk"), (Join-Path $root "tray\winhelm tray.lnk"))) {
    $s = $ws.CreateShortcut($lnk)
    $s.TargetPath = "$env:SystemRoot\System32\wscript.exe"
    $s.Arguments = "`"$vbsPath`""
    $s.WorkingDirectory = $root
    $s.WindowStyle = 7
    if (Test-Path -LiteralPath $icoPath) { $s.IconLocation = "$icoPath,0" }
    $s.Description = "Launch WinHelm System Tray silently"
    $s.Save()
}
Write-Host "[OK] Shortcuts updated for current directory ($root)" -ForegroundColor Green

Write-Host ""
if ($okAll) {
    Write-Host "Setup complete! Double-click 'WinHelm Tray.lnk' to start." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Setup finished with missing prerequisites. Please install missing items above." -ForegroundColor Red
    exit 1
}
