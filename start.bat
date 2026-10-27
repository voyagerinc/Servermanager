@echo off
rem ===========================================================================
rem  Server Monitor - one-click setup and start
rem  Checks every requirement, installs whatever is missing, then runs the app.
rem    1. Administrator rights   (needed to control services / open firewall)
rem    2. Python 3.10+           (downloaded and installed silently if missing)
rem    3. Virtual environment    (venv folder)
rem    4. Python packages        (flask, psutil, waitress)
rem    5. Git + latest version   (Git installed if missing, then pull from GitHub)
rem    6. Web login password     (asked once, saved in config.json)
rem    7. Firewall port          (inbound rule "Server Monitor")
rem    8. Start the program and open the browser
rem ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
title Server Monitor
cd /d "%~dp0"

set "PY_VERSION=3.12.10"
set "PY_URL=https://www.python.org/ftp/python/%PY_VERSION%/python-%PY_VERSION%-amd64.exe"
set "PY_DIR=%ProgramFiles%\Python312"
set "VENV_PY=%~dp0venv\Scripts\python.exe"
set "GIT_VERSION=2.47.1"
set "GIT_URL=https://github.com/git-for-windows/git/releases/download/v%GIT_VERSION%.windows.1/Git-%GIT_VERSION%-64-bit.exe"

rem --------------------------------------------------------------- 1. admin
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
echo [1/8] Administrator rights ............ OK

rem --------------------------------------------------------------- 2. python
set "PYTHON="
call :find_python
if not defined PYTHON (
    echo [2/8] Python 3.10+ not found - installing Python %PY_VERSION% ...
    call :install_python
    call :find_python
)
if not defined PYTHON (
    echo.
    echo ERROR: Python could not be installed automatically.
    echo Install it manually from https://www.python.org/downloads/
    echo  - tick "Add python.exe to PATH" and "Install for all users"
    echo then run this file again.
    goto :fail
)
for /f "delims=" %%v in ('call "!PYTHON!" -c "import platform;print(platform.python_version())"') do set "PYV=%%v"
echo [2/8] Python !PYV! ..................... OK - !PYTHON!

rem --------------------------------------------------------------- 3. venv
rem a venv only works with the Python that created it - rebuild it if that
rem Python is gone (e.g. the folder was copied from another PC)
if exist "%VENV_PY%" (
    "%VENV_PY%" -c "import sys" >nul 2>&1
    if errorlevel 1 (
        echo [3/8] Virtual environment is broken or from another PC - rebuilding...
        rmdir /s /q "%~dp0venv"
    )
)
if not exist "%VENV_PY%" (
    echo [3/8] Creating virtual environment...
    "!PYTHON!" -m venv "%~dp0venv"
    if errorlevel 1 goto :fail
)
echo [3/8] Virtual environment ............. OK

rem --------------------------------------------------------------- 4. packages
"%VENV_PY%" -c "import flask, psutil, waitress" >nul 2>&1
if errorlevel 1 (
    echo [4/8] Installing packages from requirements.txt...
    "%VENV_PY%" -m pip install -q --disable-pip-version-check --upgrade pip
    "%VENV_PY%" -m pip install -q --disable-pip-version-check -r "%~dp0requirements.txt"
    "%VENV_PY%" -c "import flask, psutil, waitress" >nul 2>&1
    if errorlevel 1 (
        echo ERROR: package installation failed - see the messages above.
        echo Check the internet connection, or delete the venv folder and run this file again.
        goto :fail
    )
)
echo [4/8] Packages flask/psutil/waitress .. OK

rem --------------------------------------------------------------- 5. git + update
set "GIT="
call :find_git
if not defined GIT (
    echo [5/8] Git not found - installing Git %GIT_VERSION% ...
    call :install_git
    call :find_git
)
if not defined GIT (
    echo [5/8] WARNING: Git could not be installed - starting without checking for updates.
    goto :after_update
)
echo [5/8] Checking GitHub for a newer version...
rem The update may replace this very file, so the rest of this step is one
rem bracketed block - cmd reads a block completely before running it.
(
    "%VENV_PY%" app.py --update
    if errorlevel 10 (
        echo [5/8] Updated to the latest version - restarting setup...
        start "" "%~f0"
        exit
    )
    if errorlevel 1 (
        echo [5/8] WARNING: could not update - starting the current version.
    ) else (
        echo [5/8] Latest version .................. OK
    )
    goto :after_update
)
:after_update

rem --------------------------------------------------------------- 6. password
"%VENV_PY%" -c "import json,sys;sys.exit(0 if json.load(open('config.json')).get('password_hash') else 1)" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [6/8] Set the username/password for the web page:
    "%VENV_PY%" app.py --set-password
    if errorlevel 1 goto :fail
)
echo [6/8] Web login ....................... OK

rem read the port from config.json (default 30081)
set "PORT=30081"
for /f "delims=" %%p in ('call "%VENV_PY%" -c "import json;print(json.load(open('config.json')).get('port',30081))"') do set "PORT=%%p"

rem --------------------------------------------------------------- 7. firewall
powershell -NoProfile -Command "$r = Get-NetFirewallRule -DisplayName 'Server Monitor' -ErrorAction SilentlyContinue; if ($r -and (($r | Get-NetFirewallPortFilter).LocalPort -contains '%PORT%')) {exit 0} else {exit 1}" >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Get-NetFirewallRule -DisplayName 'Server Monitor' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; New-NetFirewallRule -DisplayName 'Server Monitor' -Direction Inbound -Protocol TCP -LocalPort %PORT% -Action Allow | Out-Null"
)
echo [7/8] Firewall port %PORT% ............... OK

rem --------------------------------------------------------------- 8. run
set "IP=localhost"
for /f "delims=" %%i in ('powershell -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress"') do set "IP=%%i"

netstat -ano | findstr /r /c:":%PORT% .*LISTENING" >nul
if errorlevel 1 goto :start_app
rem the port is busy - is it Server Monitor or some other program?
powershell -NoProfile -Command "try { if ((Invoke-WebRequest 'http://127.0.0.1:%PORT%/' -UseBasicParsing -TimeoutSec 5).Content -match 'Server Monitor') {exit 0} } catch {}; exit 1" >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: port %PORT% is already used by another program.
    echo Change "port" in config.json to a free port, e.g. 8090, and run this file again.
    goto :fail
)
echo [8/8] Server Monitor is already running on port %PORT%.
echo.
echo   This PC:        http://localhost:%PORT%
echo   Other PCs:      http://!IP!:%PORT%
start "" "http://localhost:%PORT%"
goto :end

:start_app
echo [8/8] Starting Server Monitor...
echo.
echo   This PC:        http://localhost:%PORT%
echo   Other PCs:      http://!IP!:%PORT%
echo   Keep this window open. Press Ctrl+C to stop.
echo   To update: web page - Update tab - "Pull update and restart".
echo.
start "" /min powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep 3; Start-Process 'http://localhost:%PORT%'"
rem one block again: an update from the web page may replace this file while it runs
(
    "%VENV_PY%" app.py --supervise --port %PORT%
    echo.
    echo Server Monitor stopped.
    pause
    exit /b
)


rem ===========================================================================
:find_python
rem Looks for a working Python 3.10+ (skips the Microsoft Store stub).
for %%c in ("%PY_DIR%\python.exe" "py" "python") do (
    if not defined PYTHON (
        %%c -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
        if not errorlevel 1 set "PYTHON=%%~c"
    )
)
exit /b

:install_python
set "PY_SETUP=%TEMP%\python-%PY_VERSION%-amd64.exe"
echo       Downloading %PY_URL%
curl.exe -L --fail -o "%PY_SETUP%" "%PY_URL%"
if errorlevel 1 (
    powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest '%PY_URL%' -OutFile '%PY_SETUP%'"
)
if exist "%PY_SETUP%" (
    echo       Installing silently - this takes a minute...
    "%PY_SETUP%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1 TargetDir="%PY_DIR%"
    del "%PY_SETUP%" >nul 2>&1
) else (
    echo       Download failed - trying winget...
    winget install -e --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements
)
exit /b

:find_git
for /f "delims=" %%g in ('where git 2^>nul') do if not defined GIT set "GIT=%%g"
if not defined GIT if exist "%ProgramFiles%\Git\cmd\git.exe" set "GIT=%ProgramFiles%\Git\cmd\git.exe"
exit /b

:install_git
set "GIT_SETUP=%TEMP%\Git-%GIT_VERSION%-64-bit.exe"
echo       Downloading %GIT_URL%
curl.exe -L --fail -o "%GIT_SETUP%" "%GIT_URL%"
if exist "%GIT_SETUP%" (
    echo       Installing silently - this takes a minute...
    "%GIT_SETUP%" /VERYSILENT /NORESTART /NOCANCEL /SP- /SUPPRESSMSGBOXES
    del "%GIT_SETUP%" >nul 2>&1
) else (
    echo       Download failed - trying winget...
    winget install -e --id Git.Git --scope machine --silent --accept-package-agreements --accept-source-agreements
)
exit /b

:fail
echo.
echo Setup did not finish. See the message above.
:end
echo.
pause
endlocal
