#!/bin/sh
# SSH local forward to admin (127.0.0.1:8443) and open Firefox.
# Usage: ./open-admin.sh YOUR_SERVER_IP [local_port]
# If local 8443 is already taken (leftover ssh -L), a free port is chosen.

set -eu
server="${1:?usage: $0 HOST [local_port]}"
wanted="${2:-}"

port_free() {
  python3 - "$1" <<'PY'
import socket, sys
p = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", p))
except OSError:
    sys.exit(1)
s.close()
sys.exit(0)
PY
}

pick_port() {
  if [ -n "$wanted" ]; then
    if port_free "$wanted"; then
      printf '%s' "$wanted"
      return 0
    fi
    echo "Local port $wanted is already in use (old ssh -L?). Close it or pass another port." >&2
    exit 1
  fi
  for p in 8443 18443 28443 38443 48443; do
    if port_free "$p"; then
      if [ "$p" != 8443 ]; then
        echo "Port 8443 is busy (usually a leftover ssh -L). Using $p instead." >&2
      fi
      printf '%s' "$p"
      return 0
    fi
  done
  echo "No free local port. Stop leftover ssh and retry." >&2
  exit 1
}

port="$(pick_port)"
url="http://127.0.0.1:${port}/"

firefox_bin=""
for c in firefox firefox-esr /usr/bin/firefox \
  "/Applications/Firefox.app/Contents/MacOS/firefox"; do
  if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then
    firefox_bin="$c"
    break
  fi
done
[ -n "$firefox_bin" ] || {
  echo "Firefox not found" >&2
  exit 1
}

echo "Tunnel: localhost:${port} -> ${server}:127.0.0.1:8443"
echo "Open exactly: ${url}  (http, not https)"

cleanup() {
  if [ -n "${ssh_pid:-}" ]; then
    kill "$ssh_pid" 2>/dev/null || true
    wait "$ssh_pid" 2>/dev/null || true
  fi
}
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -L "${port}:127.0.0.1:8443" "root@${server}" &
ssh_pid=$!
trap cleanup EXIT INT TERM HUP
sleep 1
kill -0 "$ssh_pid" 2>/dev/null || {
  echo "ssh failed (keys?)" >&2
  exit 1
}
"$firefox_bin" "$url" >/dev/null 2>&1 &
wait "$ssh_pid"
