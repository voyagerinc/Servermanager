# Run in an Administrator PowerShell to remove the auto-start task and firewall rule.
Stop-ScheduledTask -TaskName "ServerMonitor" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "ServerMonitor" -Confirm:$false -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName "Server Monitor" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "Server Monitor removed. You can now delete this folder."
