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

bin_ok() {
  f="$1"
  [ -x "$f" ] || return 1
  sz=$(stat -c%s "$f" 2>/dev/null || wc -c <"$f")
  [ "$sz" -gt 1000000 ]
}

install_release_binaries() {
  repo="${TT_GITHUB_REPO:-xizerlix/TrustTunnel}"
  default_tag=""
  default_tag=$(curl -fsS --max-time 8 "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null || true)
  [ -n "$default_tag" ] || default_tag="custom-1.1.41"
  say ""
  say "VPN/admin binaries: download from GitHub if missing or truncated."
  printf "Release tag [%s]: " "$default_tag"
  read -r TAG
  TAG="$(printf '%s' "${TAG:-$default_tag}" | tr -d '[:space:]')"
  [ -n "$TAG" ] || die "release tag is required"
  name="trusttunnel-${TAG}-linux-x86_64"
  url="https://github.com/${repo}/releases/download/${TAG}/${name}.tar.gz"
  say "Downloading $url ..."
  tmp=$(mktemp -d)
  if ! curl -fL --retry 3 --connect-timeout 15 --max-time 180 -o "$tmp/tt.tgz" "$url"; then
    rm -rf "$tmp"
    die "could not download $url — check the tag and disk space (df -h)"
  fi
  if ! tar -xzf "$tmp/tt.tgz" -C "$tmp"; then
    rm -rf "$tmp"
    die "tar extract failed (disk full? df -h / /tmp)"
  fi
  ep=$(find "$tmp" -name trusttunnel_endpoint -type f | head -n 1)
  ad=$(find "$tmp" -name trusttunnel_admin -type f | head -n 1)
  if [ -z "$ep" ]; then
    rm -rf "$tmp"
    die "archive has no trusttunnel_endpoint"
  fi
  mkdir -p /opt/trusttunnel
  install -m 0755 "$ep" /opt/trusttunnel/trusttunnel_endpoint
  if [ -n "$ad" ]; then
    install -m 0755 "$ad" /opt/trusttunnel/trusttunnel_admin
  fi
  rm -rf "$tmp"
  say "Installed binaries to /opt/trusttunnel"
}

start_root_daemons() {
  need_jq=0
  for s in /root/bot_listener.sh /root/telegram_vpn_bot.sh /root/monitor.sh; do
    [ -f "$s" ] && need_jq=1
  done
  if [ "$need_jq" -eq 1 ] && command -v apt-get >/dev/null 2>&1; then
    apt-get install -y -qq jq >/dev/null 2>&1 || true
  fi
  for s in /root/bot_listener.sh /root/telegram_vpn_bot.sh; do
    if [ -x "$s" ]; then
      if pgrep -f "$s" >/dev/null 2>&1; then
        say "$s already running"
      else
        say "Starting $s ..."
        nohup "$s" >/dev/null 2>&1 &
      fi
    fi
  done
}

fix_ssh_perms() {
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  [ -f /root/.ssh/authorized_keys ] && chmod 600 /root/.ssh/authorized_keys
  [ -f /root/.ssh/config ] && chmod 600 /root/.ssh/config
  for f in /root/.ssh/id_* /root/.ssh/*.pem; do
    [ -e "$f" ] || continue
    case "$f" in
      *.pub) chmod 644 "$f" ;;
      *) chmod 600 "$f" ;;
    esac
  done
}

harden_sshd() {
  mkdir -p /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/99-tt-pubkey-only.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
EOF
  if command -v sshd >/dev/null 2>&1 && sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    say "sshd: password login disabled (pubkey only)"
  else
    say "WARNING: sshd -t failed; password login was not reloaded. Check /root/.ssh/authorized_keys before closing this session."
  fi
}

ensure_vpn_metrics() {
  vpn="/opt/trusttunnel/vpn.toml"
  [ -f "$vpn" ] || return 0
  python3 - "$vpn" <<'PY' || true
from pathlib import Path
import sys
p = Path(sys.argv[1])
text = p.read_text(encoding="utf-8")
if "[metrics]" in text:
    sys.exit(0)
block = """
[metrics]
address = "127.0.0.1:1987"
per_client_metrics = true
"""
if not text.endswith("\n"):
    text += "\n"
p.write_text(text + block, encoding="utf-8")
print("appended [metrics] per_client_metrics = true to vpn.toml")
PY
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
say "Installing packages (curl, certbot, python3, jq)..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl certbot ca-certificates python3 jq openssh-server >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y curl certbot python3 jq
elif command -v yum >/dev/null 2>&1; then
  yum install -y curl certbot python3 jq
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
if [ -d data/etc/ssh ]; then
  mkdir -p /etc/ssh/sshd_config.d
  if [ -f data/etc/ssh/sshd_config ]; then
    cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.ttrestore 2>/dev/null || true
    cp -a data/etc/ssh/sshd_config /etc/ssh/sshd_config
  fi
  if [ -d data/etc/ssh/sshd_config.d ]; then
    cp -a data/etc/ssh/sshd_config.d/. /etc/ssh/sshd_config.d/ 2>/dev/null || true
  fi
fi
fix_ssh_perms
harden_sshd

chmod +x /opt/trusttunnel/trusttunnel_endpoint 2>/dev/null || true
chmod +x /opt/trusttunnel/trusttunnel_admin 2>/dev/null || true
chmod +x /opt/trusttunnel/setup_wizard 2>/dev/null || true

if ! bin_ok /opt/trusttunnel/trusttunnel_endpoint || ! bin_ok /opt/trusttunnel/trusttunnel_admin; then
  say "Binaries missing or too small (backup skips large files). Installing from GitHub..."
  install_release_binaries
fi

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

ensure_vpn_metrics

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

mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/trusttunnel.sh <<'EOF'
#!/bin/sh
systemctl kill -s HUP trusttunnel 2>/dev/null || true
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/trusttunnel.sh
systemctl enable --now certbot.timer 2>/dev/null || systemctl enable --now certbot-renew.timer 2>/dev/null || true

if grep -q '127.0.0.1:8443' /etc/systemd/system/trusttunnel-admin.service 2>/dev/null; then
  mkdir -p /etc/systemd/system/trusttunnel-admin.service.d
  printf '%s\n' '[Service]' 'Environment=TT_SECURE_COOKIES=false' \
    > /etc/systemd/system/trusttunnel-admin.service.d/localhost.conf
fi

systemctl daemon-reload 2>/dev/null || true
if [ -f /etc/systemd/system/trusttunnel.service ]; then
  systemctl enable trusttunnel || true
  systemctl restart trusttunnel || true
fi
if [ -f /etc/systemd/system/trusttunnel-admin.service ]; then
  systemctl enable trusttunnel-admin || true
  systemctl restart trusttunnel-admin || true
fi

start_root_daemons

say ""
say "Done."
say "Endpoint should listen on :443. Admin default is 127.0.0.1:8443 (SSH tunnel):"
say "  ssh -L 8443:127.0.0.1:8443 root@THIS_HOST"
say "  then open http://127.0.0.1:8443/"
say "Point clients at the new hostname: $NEW_HOST"
say "certbot.timer only *checks* about every 12 hours; it renews when <~30 days remain."
say "A deploy hook sends SIGHUP so the endpoint loads the new cert without waiting for reboot."
say "Password SSH is off; keep an SSH session until you confirm key login."
say ""
