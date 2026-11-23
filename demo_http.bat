@echo off
setlocal
chcp 65001 >nul
"%~dp0.venv\Scripts\python.exe" -X utf8 "%~dp0demo_http.py"
if errorlevel 1 pause
