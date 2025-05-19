@echo off
:start
echo Blockchain Operations Menu
echo ========================
echo.
echo 1. Check existing contract status
echo 2. Deploy new contract (only if needed)
echo 3. Exit
echo.

set /p choice=Enter your choice (1-3): 

if "%choice%"=="1" (
    echo.
    echo Checking existing contract status...
    echo.
    npx hardhat run scripts/check_contract.js --network sepolia
    echo.
    pause
    goto :menu
)

if "%choice%"=="2" (
    echo.
    echo WARNING: This will deploy a new contract and may take several minutes.
    echo Only proceed if the existing contract is not working.
    echo.
    set /p confirm=Are you sure you want to deploy a new contract? (y/n): 
    if /i "%confirm%"=="y" (
        echo.
        echo Deploying new contract...
        echo This may take several minutes. Please be patient.
        echo.
        npx hardhat run scripts/deploy.js --network sepolia
        echo.
        pause
    ) else (
        echo Deployment cancelled.
        echo.
        pause
    )
    goto :menu
)

if "%choice%"=="3" (
    exit /b 0
)

echo Invalid choice. Please try again.
echo.
pause
goto :menu

:menu
cls
goto :start