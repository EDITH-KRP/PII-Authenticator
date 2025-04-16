@echo off
echo PII Authenticator Log Viewer

if not exist logs (
    echo No logs directory found. Please run the application first.
    pause
    exit /b 1
)

:menu
cls
echo PII Authenticator Log Viewer
echo ===========================
echo.
echo 1. View main logs
echo 2. View error logs
echo 3. View access logs
echo 4. View all logs (combined)
echo 5. Clear logs
echo 6. Exit
echo.
set /p choice=Enter your choice (1-6): 

if "%choice%"=="1" (
    cls
    echo Main Logs:
    echo ==========
    echo.
    if exist logs\pii_authenticator.log (
        type logs\pii_authenticator.log | more
    ) else (
        echo No main logs found.
    )
    pause
    goto menu
)

if "%choice%"=="2" (
    cls
    echo Error Logs:
    echo ===========
    echo.
    if exist logs\errors.log (
        type logs\errors.log | more
    ) else (
        echo No error logs found.
    )
    pause
    goto menu
)

if "%choice%"=="3" (
    cls
    echo Access Logs:
    echo ============
    echo.
    if exist logs\access.log (
        type logs\access.log | more
    ) else (
        echo No access logs found.
    )
    pause
    goto menu
)

if "%choice%"=="4" (
    cls
    echo All Logs (Combined):
    echo ===================
    echo.
    echo --- MAIN LOGS ---
    echo.
    if exist logs\pii_authenticator.log (
        type logs\pii_authenticator.log
    ) else (
        echo No main logs found.
    )
    echo.
    echo --- ERROR LOGS ---
    echo.
    if exist logs\errors.log (
        type logs\errors.log
    ) else (
        echo No error logs found.
    )
    echo.
    echo --- ACCESS LOGS ---
    echo.
    if exist logs\access.log (
        type logs\access.log
    ) else (
        echo No access logs found.
    )
    pause
    goto menu
)

if "%choice%"=="5" (
    cls
    echo Are you sure you want to clear all logs? (Y/N)
    set /p confirm=
    if /i "%confirm%"=="Y" (
        del /q logs\*.log 2>nul
        echo Logs cleared.
    ) else (
        echo Operation cancelled.
    )
    pause
    goto menu
)

if "%choice%"=="6" (
    exit /b 0
)

echo Invalid choice. Please try again.
pause
goto menu