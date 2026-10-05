# Registers a scheduled task that starts SSH Monitor (hidden) every time you log on to Windows,
# then starts it right away. Run once:  powershell -ExecutionPolicy Bypass -File scripts\windows\install-autostart.ps1
# Remove it again with:                 Unregister-ScheduledTask -TaskName "SSH Monitor" -Confirm:$false
$runner = Join-Path $PSScriptRoot "run-server.ps1"
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runner`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "SSH Monitor" -Action $action -Trigger $trigger -Settings $settings `
    -Description "Runs the SSH Monitor web app (scripts\windows\run-server.ps1)" -Force | Out-Null
Start-ScheduledTask -TaskName "SSH Monitor"
Write-Output "Scheduled task 'SSH Monitor' registered and started. Log: data\server.log"
