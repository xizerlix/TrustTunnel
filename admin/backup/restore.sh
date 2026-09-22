#!/bin/sh
# Interactive restore of an MDM/VPN panel backup onto a new host.
# Run as root from the unpacked archive directory:  sudo ./restore.sh

set -eu

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "run as root: sudo ./restore.sh"
  fi
}

here="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$here"

need_root
[ -f restore.sh ] || die "run this from the unpacked backup directory"
[ -d data ] || die "missing data/ — is the archive complete?"

say ""
say "=== New hostname (TLS certificate) ==="
say "The old domain/IP is blocked. You need a NEW name."
say "1. Open https://www.duckdns.org  (free dynamic DNS)"
say "2. Sign in (GitHub/Google), create a subdomain, e.g. mypanel"
say "3. Copy the full name: mypanel.duckdns.org"
say "4. Copy your DuckDNS token from that page"
say "5. Point the A record at THIS server public IPv4 (the script can push it)"
say ""
printf "New hostname (e.g. mypanel.duckdns.org): "
read -r NEW_HOST
NEW_HOST="$(printf '%s' "$NEW_HOST" | tr -d '[:space:]')"
[ -n "$NEW_HOST" ] || die "hostname is required"
printf "DuckDNS token (empty = skip auto IP update): "
read -r DUCK_TOKEN
printf "Email for Let's Encrypt (required for certbot): "
read -r LE_EMAIL
LE_EMAIL="$(printf '%s' "$LE_EMAIL" | tr -d '[:space:]')"
[ -n "$LE_EMAIL" ] || die "email is required"

say ""
say "Installing packages (curl, certbot)..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl certbot ca-certificates python3 >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y curl certbot python3
elif command -v yum >/dev/null 2>&1; then
  yum install -y curl certbot python3
else
  say "WARNING: install curl and certbot yourself, then press Enter"
  read -r _
fi

PUB_IP="$(curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)"
if [ -n "$DUCK_TOKEN" ]; then
  DUCK_NAME="${NEW_HOST%.duckdns.org}"
  say "Updating DuckDNS $DUCK_NAME -> ${PUB_IP:-auto} ..."
  curl -fsS "https://www.duckdns.org/update?domains=${DUCK_NAME}&token=${DUCK_TOKEN}&ip=" || true
  say "Wait ~30s for DNS, then continue."
  sleep 5
fi

say "Public IPv4 of this host (check DuckDNS A record): ${PUB_IP:-unknown}"
printf "Press Enter when DNS for %s points here... " "$NEW_HOST"
read -r _

copy_tree() {
  src="$1"
  dst="$2"
  if [ -e "$src" ]; then
    mkdir -p "$(dirname "$dst")"
    if [ -d "$src" ]; then
      mkdir -p "$dst"
      cp -a "$src"/. "$dst"/
    else
      mkdir -p "$(dirname "$dst")"
      cp -a "$src" "$dst"
    fi
  fi
}

say "Copying backup files..."
if [ -d data/opt/trusttunnel ]; then
  mkdir -p /opt/trusttunnel
  cp -a data/opt/trusttunnel/. /opt/trusttunnel/
fi
if [ -d data/etc/trusttunnel ]; then
  mkdir -p /etc/trusttunnel
  cp -a data/etc/trusttunnel/. /etc/trusttunnel/
fi
if [ -d data/root ]; then
  cp -a data/root/. /root/ 2>/dev/null || true
  chmod 700 /root/*.sh 2>/dev/null || true
fi
if [ -d data/tmp ]; then
  mkdir -p /tmp
  cp -a data/tmp/. /tmp/ 2>/dev/null || true
fi
if [ -d data/etc/systemd/system ]; then
  mkdir -p /etc/systemd/system
  cp -a data/etc/systemd/system/. /etc/systemd/system/
fi
if [ -d data/etc/caddy ]; then
  mkdir -p /etc/caddy
  cp -a data/etc/caddy/. /etc/caddy/ 2>/dev/null || true
fi

chmod +x /opt/trusttunnel/trusttunnel_endpoint 2>/dev/null || true
chmod +x /opt/trusttunnel/trusttunnel_admin 2>/dev/null || true
chmod +x /opt/trusttunnel/setup_wizard 2>/dev/null || true

say "Stopping old listeners on 80/443 if any..."
systemctl stop trusttunnel 2>/dev/null || true
systemctl stop trusttunnel-admin 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true
systemctl stop caddy 2>/dev/null || true
systemctl stop apache2 2>/dev/null || true

say "Requesting Let's Encrypt certificate for $NEW_HOST (HTTP-01 on port 80)..."
if certbot certonly --standalone --non-interactive --agree-tos -m "$LE_EMAIL" -d "$NEW_HOST"; then
  CHAIN="/etc/letsencrypt/live/${NEW_HOST}/fullchain.pem"
  KEY="/etc/letsencrypt/live/${NEW_HOST}/privkey.pem"
else
  say "certbot failed. You can retry later:"
  say "  certbot certonly --standalone --agree-tos -m $LE_EMAIL -d $NEW_HOST"
  CHAIN="/etc/letsencrypt/live/${NEW_HOST}/fullchain.pem"
  KEY="/etc/letsencrypt/live/${NEW_HOST}/privkey.pem"
fi

HOSTS="/opt/trusttunnel/hosts.toml"
if [ -f "$HOSTS" ]; then
  say "Updating hosts.toml hostname and certificate paths..."
  python3 - "$HOSTS" "$NEW_HOST" "$CHAIN" "$KEY" <<'PY' || true
import re, sys
path, host, chain, key = sys.argv[1:5]
text = open(path, encoding="utf-8").read()
text = re.sub(r'(?m)^(hostname\s*=\s*)".*"', r'\1"' + host + '"', text, count=1)
text = re.sub(r'(?m)^(cert_chain_path\s*=\s*)".*"', r'\1"' + chain + '"', text)
text = re.sub(r'(?m)^(private_key_path\s*=\s*)".*"', r'\1"' + key + '"', text)
open(path, "w", encoding="utf-8").write(text)
PY
fi

if [ -f data/cron/root.crontab ]; then
  say "Restoring crontab..."
  crontab data/cron/root.crontab || true
fi
if [ -n "${DUCK_TOKEN:-}" ]; then
  DUCK_NAME="${NEW_HOST%.duckdns.org}"
  say "Installing /root/duckdns-update.sh ..."
  cat > /root/duckdns-update.sh <<EOF
#!/bin/sh
curl -fsS "https://www.duckdns.org/update?domains=${DUCK_NAME}&token=${DUCK_TOKEN}&ip=" >/dev/null
EOF
  chmod 700 /root/duckdns-update.sh
  (crontab -l 2>/dev/null | grep -v duckdns-update.sh; echo "*/5 * * * * /root/duckdns-update.sh") | crontab - || true
fi

systemctl daemon-reload 2>/dev/null || true
if [ -f /etc/systemd/system/trusttunnel.service ]; then
  systemctl enable --now trusttunnel || systemctl restart trusttunnel || true
fi
if [ -f /etc/systemd/system/trusttunnel-admin.service ]; then
  systemctl enable --now trusttunnel-admin || systemctl restart trusttunnel-admin || true
fi
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files caddy.service >/dev/null 2>&1; then
  systemctl restart caddy || true
fi

say ""
say "Done."
say "Endpoint + admin should be up. Admin is usually reverse-proxied on :443"
say "or bound on 127.0.0.1:8443 (see trusttunnel-admin.service)."
say "Point clients at the new hostname: $NEW_HOST"
say "If certbot failed, fix DNS/port 80 and run certbot, then restart trusttunnel."
say ""
