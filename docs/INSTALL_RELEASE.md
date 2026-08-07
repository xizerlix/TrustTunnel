# Installing from a GitHub Release

Use this when you receive a `trusttunnel-*-linux-x86_64.tar.gz` build with per-client
metrics (`/clients` endpoint). Replace placeholders with values from your release page.

## Requirements

- Linux x86_64
- Existing TrustTunnel configs in `/opt/trusttunnel/` (`vpn.toml`, `hosts.toml`, etc.)

## Install or update

```bash
# Release tag and download URL — from the GitHub Releases page you were given
TAG=custom-1.0.0
BASE_URL="https://github.com/OWNER/REPO/releases/download/${TAG}"
ARCH=linux-x86_64

cd /tmp
curl -fL -o tt.tar.gz "${BASE_URL}/trusttunnel-${TAG}-${ARCH}.tar.gz"
tar -xzf tt.tar.gz

sudo systemctl stop trusttunnel
sudo install -m 755 "trusttunnel-${TAG}-${ARCH}/trusttunnel_endpoint" \
  /opt/trusttunnel/trusttunnel_endpoint
sudo systemctl start trusttunnel
```

## Enable per-user traffic stats

Add to `vpn.toml` if not present:

```toml
[metrics]
address = "127.0.0.1:1987"
request_timeout_secs = 3
```

Restart and verify:

```bash
sudo systemctl restart trusttunnel
curl -s http://127.0.0.1:1987/clients | jq .
```

Optional traffic quotas: see [CONFIGURATION.md](../CONFIGURATION.md) (`max_traffic_bytes`,
`traffic_usage_file`).

## Metrics endpoint reference

See [METRICS.md](../METRICS.md) for `/clients` JSON fields and Prometheus metrics.
