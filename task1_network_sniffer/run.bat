@echo off
title NetSniff
cd /d "%~dp0"

:: Check for admin rights (needed for packet capture)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %~dp0 && python app.py' -Verb RunAs"
    exit /b
)

python app.py
if %errorlevel% neq 0 (
    echo.
    echo Something went wrong. Make sure you ran: pip install PyQt5 scapy
    pause
)
