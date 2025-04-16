@echo off
echo PII Authenticator Backend Load Testing

REM Check if Python is installed
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Python is not installed or not in PATH. Please install Python and try again.
    exit /b 1
)

REM Install required packages if not already installed
echo Installing required packages...
pip install requests colorama argparse matplotlib numpy

REM Run the load test script
echo Running load tests...
python load_test.py %*

echo.
echo Load testing completed.
pause