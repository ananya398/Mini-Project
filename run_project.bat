@echo off
setlocal
cd /d "%~dp0"
title CVE Severity Predictor

if not exist ".venv\Scripts\python.exe" (
    echo Virtual environment not found. Running setup first...
    call setup_windows.bat
    if errorlevel 1 exit /b 1
)

echo Checking application syntax...
".venv\Scripts\python.exe" -m py_compile app.py
if errorlevel 1 (
    echo ERROR: app.py has a syntax error.
    pause
    exit /b 1
)

echo.
echo Starting CVE Severity Predictor...
echo Your browser should open automatically.
echo Keep this window open while using the application.
echo Press Ctrl+C here to stop the app.
echo.

".venv\Scripts\python.exe" -m streamlit run app.py --server.port 8501
pause
