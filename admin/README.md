# TrustTunnel Admin Console

Single-binary web UI for editing TrustTunnel configs (`vpn.toml`, `hosts.toml`,
`credentials.toml`, `rules.toml`) and restarting/reloading the endpoint without
SSH.

## What it does

- Edits every documented flag in `vpn.toml` and `hosts.toml` with inline help.
- Manages users in `credentials.toml`: add, edit, delete, set per-user
  `max_http2_conns`, `max_http3_conns`, `max_traffic_bytes`.
- Edits rules in `rules.toml` (CIDR + client-random-prefix + allow/deny).
- Shows a live dashboard with TrustTunnel status, active sessions, traffic.
- Shows the last N lines of `journalctl -u trusttunnel`.
- On login success, bad password, or too many attempts, sends a Telegram
  message through the same bot as `bot_listener.sh` (`TOKEN` / `MY_CHAT_ID`
  at `/root/bot_listener.sh`, or `TT_TELEGRAM_BOT_TOKEN` +
  `TT_TELEGRAM_CHAT_ID`).
- Save → atomic write → `systemctl restart trusttunnel` for vpn/creds/rules,
  and `kill -HUP` for `hosts.toml` (no full restart).
- Single admin user with bcrypt-hashed password stored in
  `/etc/trusttunnel/admin.toml` (mode 0600).

## Requirements

- TrustTunnel installed and running (`/opt/trusttunnel/vpn.toml` must exist).
- Same Linux machine (the admin process reads TrustTunnel's on-disk files).
- For TLS termination on a public port: a reverse proxy (Caddy shown below).
- For `kill -HUP` and `systemctl restart` to work without a password prompt:
  NOPASSWD sudoers entries (template provided).

## Install on the server

```bash
# 1. Drop the binary
sudo install -m 0755 trusttunnel_admin /opt/trusttunnel/trusttunnel_admin

# 2. Initialize the admin password
sudo /opt/trusttunnel/trusttunnel_admin init-admin
# Enter a strong password (min 10 chars) at the prompt.
# This creates /etc/trusttunnel/admin.toml with a bcrypt hash.

# 3. sudoers so the admin can restart TrustTunnel without a password
sudo tee /etc/sudoers.d/trusttunnel-admin <<'EOF'
root ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart trusttunnel
root ALL=(ALL) NOPASSWD: /usr/bin/systemctl status trusttunnel
root ALL=(ALL) NOPASSWD: /bin/kill -HUP */trusttunnel_endpoint
root ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u trusttunnel -n * --no-pager
EOF
sudo chmod 0440 /etc/sudoers.d/trusttunnel-admin

# 4. Install the systemd unit
sudo cp service/trusttunnel-admin.service.template /etc/systemd/system/trusttunnel-admin.service
sudo systemctl daemon-reload
sudo systemctl enable --now trusttunnel-admin

# 5. Expose via reverse proxy (recommended)
sudo apt install -y caddy   # or download from https://caddyserver.com
sudo cp service/Caddyfile.template /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo ufw allow 8443/tcp   # open the public port if needed

# 6. Visit `https://<your-domain>:8443/` and log in.
```

To change the admin password later: log in → Settings → update form.
To rotate the password from the shell:

```bash
sudo /opt/trusttunnel/trusttunnel_admin init-admin --password "new-strong-password"
```

## How config edits are applied

| File edited | Action | Downtime |
|---|---|---|
| `vpn.toml` | atomic write + `systemctl restart trusttunnel` | ~1–3 s (new TCP connections refused; existing ones drop) |
| `hosts.toml` | atomic write + `kill -HUP $(pidof trusttunnel_endpoint)` | none (TrustTunnel re-reads hosts without restart) |
| `credentials.toml` | atomic write + `systemctl restart trusttunnel` | ~1–3 s (same as vpn) |
| `rules.toml` | atomic write + `systemctl restart trusttunnel` | ~1–3 s |

Atomic write: write to `*.toml.tmp`, `fsync`, `rename` over the real file.
This avoids partial writes if the process is killed mid-save.

## Security notes

- Admin binds to `127.0.0.1:8443` by default. Do **not** expose it directly to
  the internet; use Caddy/nginx for TLS + rate-limiting.
- Sessions are `HttpOnly`, `Secure` (when behind HTTPS), `SameSite=Strict`
  cookies. Idle timeout: 30 min by default. Login is rate-limited to
  5 attempts/minute per IP.
- `admin.toml` contains a bcrypt hash of your password — keep its
  permissions at 0600. The admin process reads it at startup.
- All admin actions are logged by systemd to `journalctl -u trusttunnel-admin`.
- The admin binary does not modify TrustTunnel binary code or restart
  itself. It only edits TOML files and sends signals to TrustTunnel.

## Build

The crate is part of the workspace. CI builds it via
`cargo build --bins --release`. To build locally:

```bash
cd admin
cargo build --release
```

Output: `target/release/trusttunnel_admin`.

## Layout

```
admin/
├── Cargo.toml
├── README.md
├── service/
│   ├── trusttunnel-admin.service.template
│   └── Caddyfile.template
├── src/
│   ├── main.rs           # binary entrypoint
│   ├── paths.rs          # /opt/trusttunnel/ discovery
│   ├── config.rs         # admin.toml load/save, bcrypt
│   ├── auth.rs           # session cookies, login rate limit
│   ├── state.rs          # AppState
│   ├── apply.rs          # atomic write, systemctl, kill -HUP
│   ├── live.rs
│   ├── telegram.rs       # login alerts via bot_listener TOKEN/chat
│   ├── models.rs         # DTOs that mirror vpn.toml etc.
│   ├── error.rs          # AdminError + IntoResponse
│   └── handlers/
│       ├── login.rs
│       ├── dashboard.rs
│       ├── vpn.rs
│       ├── hosts.rs
│       ├── users.rs
│       ├── rules.rs
│       ├── logs.rs
│       └── settings.rs
└── templates/
    ├── base.html
    ├── login.html
    ├── dashboard.html
    ├── vpn.html
    ├── hosts.html
    ├── users.html
    ├── rules.html
    ├── logs.html
    └── settings.html
```