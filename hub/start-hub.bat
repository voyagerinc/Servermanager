@echo off
rem ===========================================================================
rem  Server Monitor HUB - one page for all servers
rem  Run this on the ONE machine that all servers can reach (a cloud server,
rem  or an office PC published with Cloudflare Tunnel - see README).
rem  The servers themselves need no open port: they connect out to the hub.
rem    1. Administrator rights   2. Python 3.10+   3. venv + packages
rem    4. Hub login password     5. Firewall port  6. Start the hub
rem ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
title Server Monitor Hub
cd /d "%~dp0"
set "VENV_PY=%~dp0venv\Scripts\python.exe"

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
echo [1/6] Administrator rights ............ OK

set "PYTHON="
for %%c in ("%ProgramFiles%\Python312\python.exe" "py" "python") do (
    if not defined PYTHON (
        %%c -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
        if not errorlevel 1 set "PYTHON=%%~c"
    )
)
if not defined PYTHON (
    echo ERROR: Python 3.10+ is needed. Run ..\start.bat once - it installs Python - or
    echo install it from https://www.python.org/downloads/ and run this file again.
    goto :fail
)
echo [2/6] Python .......................... OK - !PYTHON!

if exist "%VENV_PY%" (
    "%VENV_PY%" -c "import sys" >nul 2>&1
    if errorlevel 1 rmdir /s /q "%~dp0venv"
)
if not exist "%VENV_PY%" (
    "!PYTHON!" -m venv "%~dp0venv"
    if errorlevel 1 goto :fail
)
"%VENV_PY%" -c "import flask, waitress" >nul 2>&1
if errorlevel 1 (
    echo [3/6] Installing packages...
    "%VENV_PY%" -m pip install -q --disable-pip-version-check flask waitress
    "%VENV_PY%" -c "import flask, waitress" >nul 2>&1
    if errorlevel 1 goto :fail
)
echo [3/6] venv and packages ............... OK

"%VENV_PY%" -c "import json,sys;sys.exit(0 if json.load(open('hub_config.json')).get('password_hash') else 1)" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [4/6] Set the username/password for the hub page:
    "%VENV_PY%" hub.py --set-password
    if errorlevel 1 goto :fail
)
echo [4/6] Hub login ....................... OK

set "PORT=30090"
for /f "delims=" %%p in ('call "%VENV_PY%" -c "import json;print(json.load(open('hub_config.json')).get('port',30090))"') do set "PORT=%%p"
powershell -NoProfile -Command "$r = Get-NetFirewallRule -DisplayName 'Server Monitor Hub' -ErrorAction SilentlyContinue; if ($r -and (($r | Get-NetFirewallPortFilter).LocalPort -contains '%PORT%')) {exit 0} else {exit 1}" >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Get-NetFirewallRule -DisplayName 'Server Monitor Hub' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; New-NetFirewallRule -DisplayName 'Server Monitor Hub' -Direction Inbound -Protocol TCP -LocalPort %PORT% -Action Allow | Out-Null"
)
echo [5/6] Firewall port %PORT% ............... OK

echo [6/6] Starting the hub...
echo.
echo   Open:  http://localhost:%PORT%
echo   Keep this window open. Press Ctrl+C to stop.
echo.
start "" /min powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep 3; Start-Process 'http://localhost:%PORT%'"
rem keep the hub running: restart it if it ever stops (Ctrl+C twice to quit)
:loop
"%VENV_PY%" hub.py --port %PORT%
echo Hub stopped - restarting in 5 seconds. Press Ctrl+C to quit.
timeout /t 5 >nul
goto :loop

:fail
echo.
echo Setup did not finish. See the message above.
pause
endlocal
