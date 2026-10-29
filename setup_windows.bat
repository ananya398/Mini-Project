@echo off
setlocal
cd /d "%~dp0"
title CVE Project Setup

echo ============================================
echo   CVE Severity Predictor - Windows Setup
echo ============================================
echo.

if exist ".venv\Scripts\python.exe" goto install_packages

echo Creating Python virtual environment...
where py >nul 2>&1
if not errorlevel 1 goto try_py311

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed.
    echo Install Python 3.11 from https://www.python.org/downloads/windows/
    echo Enable "Add Python to PATH" during installation.
    pause
    exit /b 1
)
python -m venv .venv
if errorlevel 1 goto setup_error
goto install_packages

:try_py311
py -3.11 -m venv .venv
if not errorlevel 1 goto install_packages
py -3.10 -m venv .venv
if not errorlevel 1 goto install_packages
py -3 -m venv .venv
if errorlevel 1 goto setup_error

:install_packages
echo.
echo Installing required packages. This may take several minutes...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto setup_error

".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto setup_error

echo.
echo Setup completed successfully.
echo Double-click run_project.bat to launch the app.
pause
exit /b 0

:setup_error
echo.
echo SETUP FAILED. Read the error messages above.
echo Check your internet connection and Python installation.
pause
exit /b 1
