# Custom build: install and update

This fork adds per-client traffic metrics (`/clients`), Prometheus labels by username,
and optional traffic quotas.

Repository: https://github.com/xizerlix/TrustTunnel  
Branch: `feature/per-client-metrics-and-traffic-quotas`

## For server owners

### Configuration (required for `/clients`)

In `vpn.toml`:

```toml
[metrics]
address = "127.0.0.1:1987"
request_timeout_secs = 3
```

Optional traffic quotas:

```toml
default_max_traffic_bytes_per_client = 10737418240
traffic_usage_file = "traffic_usage.toml"
```

In `credentials.toml`:

```toml
[[client]]
username = "alice"
password = "secret"
max_traffic_bytes = 5368709120
```

### Install binary from GitHub Release

Replace `custom-1.0.0` with the latest tag from
https://github.com/xizerlix/TrustTunnel/releases

```bash
TAG=custom-1.0.0
ARCH=linux-x86_64
cd /tmp
curl -L -o tt.tar.gz \
  "https://github.com/xizerlix/TrustTunnel/releases/download/${TAG}/trusttunnel-${TAG}-${ARCH}.tar.gz"
tar -xzf tt.tar.gz
sudo systemctl stop trusttunnel
sudo install -m 755 "trusttunnel-${TAG}-${ARCH}/trusttunnel_endpoint" \
  /opt/trusttunnel/trusttunnel_endpoint
sudo systemctl start trusttunnel
curl -s http://127.0.0.1:1987/clients | head
```

**Do not use the official `/update` Telegram command** — it downloads upstream releases
without these features.

### Verify

```bash
/opt/trusttunnel/trusttunnel_endpoint --version
curl -s http://127.0.0.1:1987/health-check
curl -s http://127.0.0.1:1987/clients | jq .
```

## For the maintainer (xizerlix)

### Create a release on GitHub (no local build)

1. Push branch to your fork (if not already):
   ```bash
   git push myfork feature/per-client-metrics-and-traffic-quotas
   ```
2. Open https://github.com/xizerlix/TrustTunnel/actions
3. Select **Build custom release (fork)** → **Run workflow**
4. Branch: `feature/per-client-metrics-and-traffic-quotas`
5. Tag: e.g. `custom-1.0.0` → **Run workflow**
6. Wait ~20–40 minutes. Release appears at https://github.com/xizerlix/TrustTunnel/releases

Alternative: push a tag from git:

```bash
git tag custom-1.0.0
git push myfork custom-1.0.0
```

### Build on WSL (local)

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libssl-dev perl golang-go
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
cd /mnt/d/Projects/TrustTunnel   # your path
git checkout feature/per-client-metrics-and-traffic-quotas
cargo build --bins --release
# binary: target/release/trusttunnel_endpoint
scp target/release/trusttunnel_endpoint user@server:/opt/trusttunnel/
```

### Clean up a failed server-side build (free disk space)

Run on the VPS as root:

```bash
systemctl stop trusttunnel 2>/dev/null || true

# Remove source tree and Rust artifacts (~5–15 GB)
rm -rf /opt/trusttunnel-src
rm -rf /root/.cargo /root/.rustup

# Optional: remove build packages if you installed them only for compile
apt-get remove -y golang-go cmake 2>/dev/null || true
apt-get autoremove -y
apt-get clean

df -h /
```

Keep `/opt/trusttunnel/` — that is your live install (configs, certs, binary).
