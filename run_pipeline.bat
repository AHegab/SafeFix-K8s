@echo off
REM SafeFixK8s Pipeline - Windows Batch Launcher
REM Run the full SafeFixK8s pipeline

echo ====================================
echo SafeFixK8s Pipeline
echo ====================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found!
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

REM Run the pipeline
python pipeline.py --input tests/ --output results/

echo.
echo ====================================
echo Pipeline completed!
echo Check results/ folder for outputs
echo ====================================
pause
