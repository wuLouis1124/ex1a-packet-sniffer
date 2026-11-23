@echo off
chcp 65001 >nul
"%~dp0.venv\Scripts\python.exe" -X utf8 "%~dp0check_environment.py"
echo.
pause
