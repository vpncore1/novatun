@echo off
setlocal enabledelayedexpansion
title novatun Windows Client Launcher

echo ==========================================================
echo           novatun Windows Client Launcher
echo ==========================================================

:: 1. Check for Administrative Privileges (Required for Wintun virtual adapter)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Administrative privileges are REQUIRED to create virtual TUN adapters.
    echo Please right-click this script and select 'Run as administrator'.
    echo.
    pause
    exit /b 1
)

:: 2. Resolve script directory and locate binary
set "SCRIPT_DIR=%~dp0"
set "BIN_PATH=%SCRIPT_DIR%novatun-client.exe"
set "PROJECT_ROOT=%SCRIPT_DIR%.."

if not exist "%BIN_PATH%" (
    if exist "%PROJECT_ROOT%\novatun-client.exe" (
        set "BIN_PATH=%PROJECT_ROOT%\novatun-client.exe"
    ) else if exist "%PROJECT_ROOT%\cmd\client" (
        echo [INFO] novatun-client.exe not found. Building from source...
        pushd "%PROJECT_ROOT%"
        go build -o novatun-client.exe ./cmd/client
        popd
        set "BIN_PATH=%PROJECT_ROOT%\novatun-client.exe"
    )
)

if not exist "%BIN_PATH%" (
    echo [FATAL] Cannot locate novatun-client.exe!
    echo Please compile the client binary or place novatun-client.exe in this folder.
    pause
    exit /b 1
)

:: 3. Determine config file path
set "CONFIG_PATH=%SCRIPT_DIR%client.json"
if not exist "%CONFIG_PATH%" (
    if exist "%PROJECT_ROOT%\client.json" (
        set "CONFIG_PATH=%PROJECT_ROOT%\client.json"
    )
)

if exist "%CONFIG_PATH%" (
    echo [INFO] Launching novatun client using config: %CONFIG_PATH%
    "%BIN_PATH%" -config "%CONFIG_PATH%" %*
) else (
    echo [WARN] client.json not found. Launching with command-line arguments: %*
    "%BIN_PATH%" %*
)

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] novatun client terminated with exit code %errorlevel%.
    pause
)
