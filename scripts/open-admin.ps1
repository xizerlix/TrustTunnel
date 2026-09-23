param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Server,
    [int] $LocalPort = 8443
)

$ErrorActionPreference = "Stop"

$firefox = @(
    "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
    "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $firefox) {
    throw "Firefox not found. Install it or edit this script."
}

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    throw "OpenSSH client not found (ssh). Enable Optional Feature OpenSSH Client."
}

$url = "http://127.0.0.1:${LocalPort}/"
Write-Host "Tunnel: localhost:${LocalPort} -> ${Server}:127.0.0.1:8443"
Write-Host "Firefox: $url"
Write-Host "Close this window or Ctrl+C to drop the tunnel."

$ssh = Start-Process -FilePath ssh -ArgumentList @(
    "-N",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-L", "${LocalPort}:127.0.0.1:8443",
    "root@${Server}"
) -PassThru -WindowStyle Minimized

Start-Sleep -Seconds 1
if ($ssh.HasExited) {
    throw "ssh exited immediately (key login failed, or port $LocalPort is busy)."
}

Start-Process -FilePath $firefox -ArgumentList $url
Wait-Process -Id $ssh.Id
