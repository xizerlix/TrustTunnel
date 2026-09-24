param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Server,
    [int] $LocalPort = 0
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

function Test-LocalPortFree([int] $Port) {
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new(
            [System.Net.IPAddress]::Loopback,
            $Port
        )
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($listener) {
            $listener.Stop()
        }
    }
}

function Select-LocalPort([int] $Wanted) {
    if ($Wanted -gt 0) {
        if (Test-LocalPortFree $Wanted) {
            return $Wanted
        }
        throw "Local port $Wanted is already in use (old ssh -L, or another app). Close that process or pick another port: -LocalPort 18443"
    }
    foreach ($p in 8443, 18443, 28443, 38443, 48443) {
        if (Test-LocalPortFree $p) {
            if ($p -ne 8443) {
                Write-Host "Port 8443 is busy (usually a leftover ssh -L). Using $p instead."
            }
            return $p
        }
    }
    throw "No free local port in 8443/18443/.... Stop leftover ssh: Get-Process ssh"
}

$port = Select-LocalPort $LocalPort
$url = "http://127.0.0.1:${port}/"
Write-Host "Tunnel: localhost:${port} -> ${Server}:127.0.0.1:8443"
Write-Host "Open exactly: $url  (http, not https)"
Write-Host "Ctrl+C or close this window to drop the tunnel."

$ssh = Start-Process -FilePath ssh -ArgumentList @(
    "-N",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-L", "${port}:127.0.0.1:8443",
    "root@${Server}"
) -PassThru -WindowStyle Minimized

function Stop-Tunnel {
    if ($ssh -and -not $ssh.HasExited) {
        Stop-Process -Id $ssh.Id -Force -ErrorAction SilentlyContinue
    }
}

try {
    Start-Sleep -Seconds 1
    if ($ssh.HasExited) {
        throw "ssh exited immediately (key login failed)."
    }
    Start-Process -FilePath $firefox -ArgumentList $url
    while (-not $ssh.HasExited) {
        Start-Sleep -Milliseconds 400
    }
} finally {
    Stop-Tunnel
}
