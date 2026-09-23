#!/bin/sh
# SSH local forward to admin (127.0.0.1:8443) and open Firefox.
# Usage: ./open-admin.sh YOUR_SERVER_IP

set -eu
server="${1:?usage: $0 HOST [local_port]}"
port="${2:-8443}"
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

cleanup() { kill "$ssh_pid" 2>/dev/null || true; }
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -L "${port}:127.0.0.1:8443" "root@${server}" &
ssh_pid=$!
trap cleanup EXIT INT TERM
sleep 1
kill -0 "$ssh_pid" 2>/dev/null || {
  echo "ssh failed (keys? port ${port} busy?)" >&2
  exit 1
}
"$firefox_bin" "$url" >/dev/null 2>&1 &
wait "$ssh_pid"
