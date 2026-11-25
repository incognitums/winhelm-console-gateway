@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-machine.ps1"
if errorlevel 1 (
    echo.
    echo [Setup] Found issues. Please review messages above.
    pause
    exit /b 1
)
echo.
pause
