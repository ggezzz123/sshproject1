# Keeps SSH Monitor running on this PC: starts `node server.js` and restarts it if it stops.
# Node runs in its own hidden console, so a Ctrl+C / console close elsewhere does not take it down.
# If the server is already listening (e.g. this runner was restarted while node kept running),
# it just watches the port instead of starting a second copy.
# Output: data\server.log (current run) and data\server.prev.log (previous run); errors in *.err.log.
# Started by the scheduled task from install-autostart.ps1.
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
New-Item -ItemType Directory -Force -Path data | Out-Null
$out = Join-Path $root "data\server.log"
$err = Join-Path $root "data\server.err.log"
$restarts = Join-Path $root "data\restarts.log"
$node = (Get-Command node -ErrorAction Stop).Source

$port = 5000
$portLine = Get-Content (Join-Path $root ".env") -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*PORT\s*=\s*(\d+)' } | Select-Object -First 1
if ($portLine -match '(\d+)') { $port = [int]$Matches[1] }

function Test-Listening { [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) }

while ($true) {
    if (Test-Listening) { Start-Sleep -Seconds 15; continue }
    foreach ($f in @($out, $err)) {
        if (Test-Path $f) { Move-Item -Force $f ($f -replace "\.log$", ".prev.log") }
    }
    Add-Content $restarts "[$(Get-Date -Format s)] starting server"
    $p = Start-Process -FilePath $node -ArgumentList "server.js" -WorkingDirectory $root -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $p.WaitForExit()
    Add-Content $restarts "[$(Get-Date -Format s)] server exited (code $($p.ExitCode)), restarting in 5s"
    Start-Sleep -Seconds 5
}
