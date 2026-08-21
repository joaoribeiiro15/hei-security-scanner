@echo off
cd /d "%~dp0"

set VENV_DIR=.venv
set VENV_PYTHON=%VENV_DIR%\Scripts\python.exe
set VENV_ACTIVATE=%VENV_DIR%\Scripts\activate.bat

:: Create venv if it doesn't exist
if not exist "%VENV_PYTHON%" (
    echo [GUI] Creating virtual environment...
    python -m venv %VENV_DIR%
    if errorlevel 1 (
        echo.
        echo ERROR: Could not create virtual environment.
        echo Make sure Python 3.10+ is installed and available in PATH.
        pause
        exit /b 1
    )
)

:: Activate
call "%VENV_ACTIVATE%"

:: Install / update dependencies
echo [GUI] Checking dependencies...
pip install -r requirements.txt -q
if errorlevel 1 (
    echo WARNING: Some packages may not have installed correctly.
)

:: Launch GUI
echo [GUI] Launching...
python gui.py
if errorlevel 1 pause
