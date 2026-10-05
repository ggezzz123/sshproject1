# Starts SSH Monitor if it is not already running, then exits. The scheduled task from
# install-autostart.ps1 runs this at log-on and every minute, so a crashed server is back within ~1 minute.
# Node runs hidden in its own console with SSH_MONITOR_SERVICE=1, which makes it ignore Ctrl+C events
# (a stray Ctrl+C on this PC used to stop the server).
# Output: data\server.log (current run) and data\server.prev.log (previous run); errors in *.err.log.
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
New-Item -ItemType Directory -Force -Path data | Out-Null

$port = 5000
$portLine = Get-Content (Join-Path $root ".env") -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*PORT\s*=\s*(\d+)' } | Select-Object -First 1
if ($portLine -match '(\d+)') { $port = [int]$Matches[1] }
if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { exit 0 }

$out = Join-Path $root "data\server.log"
$err = Join-Path $root "data\server.err.log"
foreach ($f in @($out, $err)) {
    if (Test-Path $f) { Move-Item -Force $f ($f -replace "\.log$", ".prev.log") }
}
Add-Content (Join-Path $root "data\restarts.log") "[$(Get-Date -Format s)] server was not running, starting it"
$env:SSH_MONITOR_SERVICE = "1"
$node = (Get-Command node -ErrorAction Stop).Source
Start-Process -FilePath $node -ArgumentList "server.js" -WorkingDirectory $root -WindowStyle Hidden `
    -RedirectStandardOutput $out -RedirectStandardError $err | Out-Null
