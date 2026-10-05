# Keeps SSH Monitor running on this PC: starts `node server.js` and restarts it if it stops.
# Node runs in its own hidden console, so a Ctrl+C / console close elsewhere does not take it down.
# Output: data\server.log (current run) and data\server.prev.log (previous run); errors in *.err.log.
# Started at log-on by the scheduled task from install-autostart.ps1.
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
New-Item -ItemType Directory -Force -Path data | Out-Null
$out = Join-Path $root "data\server.log"
$err = Join-Path $root "data\server.err.log"
$node = (Get-Command node -ErrorAction Stop).Source

while ($true) {
    foreach ($f in @($out, $err)) {
        if (Test-Path $f) { Move-Item -Force $f ($f -replace "\.log$", ".prev.log") }
    }
    $p = Start-Process -FilePath $node -ArgumentList "server.js" -WorkingDirectory $root -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $p.WaitForExit()
    Add-Content (Join-Path $root "data\restarts.log") "[$(Get-Date -Format s)] server exited (code $($p.ExitCode)), restarting in 5s"
    Start-Sleep -Seconds 5
}
