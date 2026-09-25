@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%tools\Start-User-Test.ps1"

if not exist "%PS_SCRIPT%" (
    echo [ERROR] PowerShell launcher not found: %PS_SCRIPT%
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo [INFO] User test launcher finished with code %EXIT_CODE%. Review the messages above.
    if /I not "%~1"=="-CheckOnly" if /I not "%~1"=="-PrepareOnly" pause
)

exit /b %EXIT_CODE%
