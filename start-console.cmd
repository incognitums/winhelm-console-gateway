@echo off
setlocal
cd /d "%~dp0"
echo [WinHelm Console] Launching Modern Desktop Console Window...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tray\open-console.ps1" %*
