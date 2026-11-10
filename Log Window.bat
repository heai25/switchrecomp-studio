@echo off
start "Kirikae log" powershell -NoExit -ExecutionPolicy Bypass -File "%~dp0log-window.ps1" -Quiet %*
