
@echo off
title CyberThreat Shield Hardware Agent Setup

echo ==========================================
echo CyberThreat Shield Hardware Agent Setup
echo ==========================================

echo.
echo [1/3] Checking Python installation...
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not available in PATH.
    echo Install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.
echo [2/3] Installing Python dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install Python dependencies.
    pause
    exit /b 1
)

echo.
echo [3/3] Installing Chromium for Playwright...
python -m playwright install chromium
if errorlevel 1 (
    echo ERROR: Failed to install Chromium.
    pause
    exit /b 1
)

echo.
echo Setup completed successfully.
echo You can now start the hardware agent using start_agent.bat.
pause
