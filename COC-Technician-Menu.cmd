@echo off
setlocal
color 0B
title COC - Cybersecurity Operations Center
powershell.exe -NoProfile -File "%~dp0COC\launchers\windows\Start-COC-Control.ps1"
echo.
echo If Windows blocks this launcher, keep the security policy and contact the system owner.
pause
