# Registers a daily backup of the database (03:00, or at the next chance if the PC was off) and runs one now.
# Run once:  powershell -ExecutionPolicy Bypass -File scripts\windows\install-backup.ps1
# Remove:    Unregister-ScheduledTask -TaskName "SSH Monitor Backup" -Confirm:$false
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$node = (Get-Command node -ErrorAction Stop).Source
$log = Join-Path $root "data\backup.log"
$action = New-ScheduledTaskAction -Execute "cmd.exe" -WorkingDirectory $root `
    -Argument "/c `"`"$node`" scripts\backup.js >> `"$log`" 2>&1`""
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName "SSH Monitor Backup" -Action $action -Trigger $trigger -Settings $settings `
    -Description "Daily copy of the SSH Monitor database (scripts\backup.js)" -Force | Out-Null
Start-ScheduledTask -TaskName "SSH Monitor Backup"
Write-Output "Scheduled task 'SSH Monitor Backup' registered (daily 03:00) and started. Log: data\backup.log"
