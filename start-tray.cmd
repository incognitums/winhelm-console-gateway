@echo off
setlocal
cd /d "%~dp0"
wscript.exe "%~dp0tray\launch-tray.vbs"
