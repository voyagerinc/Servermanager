# Server Monitor - Windows installer
# Run ONCE on the server in an *Administrator* PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
param([int]$Port = 30081)

$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")) {
    Write-Host "Please run this in an Administrator PowerShell." -ForegroundColor Red; exit 1
}

$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { Write-Host "Python 3.10+ is required: https://www.python.org/downloads/ (tick 'Add to PATH', install for all users)" -ForegroundColor Red; exit 1 }

Write-Host "1/4 Creating virtual environment and installing packages..."
python -m venv "$dir\venv"
& "$dir\venv\Scripts\python.exe" -m pip install -q --upgrade pip
& "$dir\venv\Scripts\python.exe" -m pip install -q -r "$dir\requirements.txt"

Write-Host "2/4 Set the login for the web page:"
& "$dir\venv\Scripts\python.exe" "$dir\app.py" --set-password

Write-Host "3/4 Opening firewall port $Port..."
Get-NetFirewallRule -DisplayName "Server Monitor" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "Server Monitor" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null

Write-Host "4/4 Registering to start automatically with Windows (runs as SYSTEM)..."
$action   = New-ScheduledTaskAction -Execute "$dir\venv\Scripts\python.exe" -Argument "`"$dir\app.py`" --supervise --port $Port" -WorkingDirectory $dir
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName "ServerMonitor" -Action $action -Trigger $trigger -Settings $settings `
    -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName "ServerMonitor"

$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress
Write-Host ""
Write-Host "Done! Open from any computer:  http://${ip}:$Port" -ForegroundColor Green
