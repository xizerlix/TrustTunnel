# Agent Guide for Trusttunnel Repository

This document provides context and instructions for AI agents working on the `Trusttunnel` codebase.

## Project Overview

TrustTunnel is an open-source VPN protocol endpoint originally developed by
AdGuard. It provides fast, secure, and reliable VPN connections whose
traffic is indistinguishable from regular HTTPS. The endpoint supports
HTTP/1.1, HTTP/2, and QUIC transports, and can tunnel TCP, UDP, and ICMP
traffic.

## Technical Context

- **Language/Version**: Rust 1.95 (edition 2021), pinned via
  `rust-toolchain.toml`
- **Primary Dependencies**: tokio, rustls, quiche (QUIC/HTTP3), h2, boring
  (BoringSSL), hyper, clap, sentry, prometheus, rcgen, instant-acme
- **Storage**: TOML configuration files on disk (`vpn.toml`, `hosts.toml`,
  `credentials.toml`, `rules.toml`); no database
- **Testing**: `cargo test` with built-in test harness; hyper and tempfile for
  integration tests; proptest for property-based tests in `deeplink`
- **Target Platform**: Linux (production), macOS (development)
- **Project Type**: Cargo workspace with 6 crates (`lib`, `endpoint`,
  `admin`, `deeplink`, `macros`, `tools`)

## Project Structure

```text
vpn-libs-endpoint/
├── lib/                       # Core library crate (`trusttunnel`)
│   ├── src/                   # Protocol logic, codecs, forwarders, settings
│   │   └── authentication/    # Authentication module
│   │   └── traffic_limiter.rs # Optional per-user traffic quotas
│   └── tests/                 # Integration tests (tunnel, auth, ping, speedtest, reverse proxy)
│       └── common/            # Shared test helpers and fixtures
├── endpoint/                  # Binary crate (`trusttunnel_endpoint`)
│   └── src/main.rs            # CLI entrypoint for the VPN endpoint
├── admin/                     # Binary crate (`trusttunnel_admin`) web console
│   ├── src/                   # Auth, TOML editors, dashboard
│   ├── backup/                # restore.sh baked into Settings Backup zip
│   ├── static/                # Bundled CSS (`admin.css`, no third-party CDNs)
│   └── templates/             # Askama HTML templates
├── tools/                     # Binary crate (`setup_wizard`)
│   └── setup_wizard/          # Interactive config generator with ACME support
├── deeplink/                  # Library crate (`trusttunnel-deeplink`)
│   └── src/                   # Deep-link URI encoding/decoding for client configs
├── macros/                    # Proc-macro crate (derive helpers)
│   └── src/                   # rt_doc, getter macros
├── bench/                     # Benchmarking scripts and Docker setup
├── scripts/                   # Automation scripts
│   ├── hooks/pre-commit       # Git pre-commit hook (lint + test)
│   ├── install.sh             # Release installation script
│   ├── open-admin.ps1         # Windows: SSH -L 8443 + Firefox to admin
│   ├── open-admin.sh          # POSIX: same tunnel + Firefox
│   └── trusttunnel.service.template  # systemd service template
├── bamboo-specs/              # Bamboo CI pipeline definitions
├── .github/workflows/         # GitHub Actions (test, md-lint, security-audit, bench)
├── Dockerfile                 # Multi-stage Docker build
├── docker-entrypoint.sh       # Container entrypoint script
├── Makefile                   # Development task runner
├── Cargo.toml                 # Workspace manifest
├── rust-toolchain.toml        # Pinned Rust toolchain version
├── .markdownlint.json         # Markdownlint configuration
├── vpn.toml                   # Main endpoint settings (generated, gitignored)
├── hosts.toml                 # TLS host settings (generated, gitignored)
├── credentials.toml           # User credentials (generated, gitignored)
├── rules.toml                 # Connection filtering rules (generated, gitignored)
└── certs/                     # TLS certificates for tests (generated, gitignored)
```

## Build And Test Commands

- `make init` - set up git pre-commit hooks and development environment
- `cargo build --bins` - build all binaries (debug)
- `cargo build --bins --release` - build all binaries (release)
- `make endpoint/setup ENDPOINT_HOSTNAME=<host>` - run setup wizard and
  generate `vpn.toml`/`hosts.toml` with defaults
- `make endpoint/run LOG_LEVEL=info` - build and run the endpoint with
  existing configs
- `make endpoint/gen_client_config CLIENT_NAME=<name> ENDPOINT_ADDRESS=<ip:port>` -
  generate client configuration for distribution
- `make test` - run the full test suite (`cargo test --workspace`)
- `make lint` - run all linters (`lint-rust` + `lint-md`)
- `make lint-rust` - check Rust formatting and run clippy
  (`cargo fmt --all -- --check` and `cargo clippy -- -D warnings`)
- `make lint-md` - lint Markdown files (`markdownlint .`)
- `make lint-fix` - auto-fix all linter issues
- `make lint-fix-rust` - auto-fix Rust formatting and clippy issues
- `make lint-fix-md` - auto-fix Markdown issues
- `make endpoint/clean` - clean cargo build artifacts
- `docker build -t trusttunnel-endpoint .` - build Docker image
- `docker run -it trusttunnel-endpoint` - run endpoint in Docker container

## Contribution Workflow

You MUST follow the following rules for EVERY task that you perform:

- You MUST verify your changes pass all static analysis checks before
  completing a task:
    - `make lint-rust` to check Rust formatting and run clippy
    - `make lint-md` to lint Markdown files

- You MUST update or add unit tests for any changed code.

- You MUST run the test suite to verify your changes do not break existing
  functionality:
    - `make test` (runs `cargo test --workspace`)

- When making changes to the project structure, ensure the Project Structure
  section in `AGENTS.md` is updated and remains valid.

- Limit the amount of comments you put in the code to a strict minimum. You should almost never add comments, except
sometimes on non-trivial code, function definitions if the arguments aren't self-explanatory, and class definitions and
their members.

- Do not use emoji.

- If the prompt essentially asks you to refactor or improve existing code, check
  if you can phrase it as a code guideline. If it's possible, add it to
  the relevant Code Guidelines section in `AGENTS.md`.

- After completing the task you MUST verify that the code you've written
  follows the Code Guidelines in this file.

- Use concise, imperative commit subjects; keep body brief. CI recognizes
  `skipci:` prefix when intentionally skipping pipelines.

- Reference tickets or PR numbers in the commit body when available; describe
  behavior changes, not just refactors.

- Pull requests should include: purpose summary, key changes, testing performed
  (`make test`, linters), and config/CLI impacts.

- Always check that changes in `lib/` or `deeplink/` are synchronized with
  `setup_wizard` behavior and flags.

## Changelog

We maintain a changelog in CHANGELOG.md. Changes should be noted in the changelog if they are user-visible
(changes to documented public APIs, significant bug fixes, or new functionality).
Changelog descriptions should be concise.
If you are not sure whether something should be in the CHANGELOG or you are not sure how to describe the change,
ask the user for guidance.
When adding new entries, write them at the very top of the file, immediately after the latest released version.
Do not add a new version heading (no #, ##, etc.) for unreleased changes.
Formatting rules:

- Each entry MUST start with a dash (- ).
- Prefer a short category tag in square brackets at the beginning of the line, matching existing style:
    - [Feature] for new functionality
    - [Fix] for bug fixes
    - [Security] for security-impacting changes
- The first line should describe the user-visible impact and mention the affected surface (CLI flag, config key,
protocol/deep-link format, library API) when relevant.

## Code Guidelines

### I. Architecture

1. The project is a Cargo workspace with six crates, each with a distinct
   responsibility:
    - **`lib`** (`trusttunnel`): core library containing protocol logic, HTTP
      codecs (HTTP/1.1, HTTP/2, HTTP/3), TLS demultiplexing, traffic
      forwarding (TCP, UDP, ICMP), settings parsing, authentication, and
      metrics. All shared types live here.
    - **`endpoint`** (`trusttunnel_endpoint`): binary crate with the CLI
      entrypoint for the VPN endpoint. Thin wrapper around `lib`.
    - **`admin`** (`trusttunnel_admin`): optional web console for editing
      TOML configs, viewing live sessions/traffic, and restarting the
      endpoint.
    - **`tools`** (`setup_wizard`): binary crate providing an interactive
      configuration wizard with ACME/Let's Encrypt support for certificate
      provisioning.
    - **`deeplink`** (`trusttunnel-deeplink`): library crate for encoding and
      decoding `tt://` deep-link URIs used in client configuration
      distribution.
    - **`macros`**: proc-macro crate providing derive helpers (`rt_doc`,
      `getter`).

   **Rationale**: separating concerns into crates enforces clear dependency
   boundaries and keeps compile times manageable.

2. New protocol or networking logic MUST go into `lib/`. The `endpoint` crate
   SHOULD remain a thin CLI wrapper.

   **Rationale**: keeps the core library reusable and testable independently
   of the binary.

### II. Code Quality Standards

1. Follow `rustfmt` defaults. Validate with `make lint-rust`.

   **Rationale**: consistent formatting across the workspace.

2. Clippy MUST pass with `-D warnings` (all warnings are errors).

   **Rationale**: catches common mistakes and enforces idiomatic Rust.

3. Keep binary names and CLI flags descriptive. New TOML config keys MUST use
   `snake_case` to match existing configuration style. Inbound TCP accept and
   TLS handshake rate limits MUST be gated by `limit_inbound_handshakes`, with
   the concurrent cap in `max_concurrent_inbound_handshakes` (default 32), so
   operators behind shared NAT can turn them off or raise them without a rebuild.
   In `trusttunnel_admin`, repeated HTML table fields (`username`, `cidr`, …)
   MUST be parsed with `form::form_lists`, not `serde_urlencoded` into `Vec<_>`:
   interleaved duplicate keys (`username=a&password=x&username=b`) error as
   `duplicate field`. `form::one_or_many` is only for a single key that is
   either one string or a consecutive sequence.
   Admin GETs to the endpoint metrics listener (`/clients`, `/metrics`) MUST
   finish once `Content-Length` or a complete chunked body is present. The
   metrics HTTP/1 codec does not close keep-alive GET sockets, so
   `read_to_end` times out and the dashboard shows zero sessions.
   Login attempts MUST be rate-limited per source IP and globally (bcrypt is
   expensive on a 1-CPU host). Trust `X-Forwarded-For` only from loopback.
   Admin password changes MUST write `bcrypt_hash` to the CLI `--admin-toml`
   path (not a hardcoded `/etc/trusttunnel/admin.toml`) and update the
   in-memory hash; login MUST re-read that file. Unique client-IP caps are
   not in the protocol — only `max_http2_conns` / `max_http3_conns`.
   The admin dashboard SHOULD keep rows for usernames that still have
   `traffic_usage_file` (or live) counters after they were deleted from
   `credentials.toml`, and MUST label those rows as removed.
   Admin Logs → top MUST sample `top -b` twice and display the second
   frame: the first batch iteration reports 0% CPU and lists tasks by PID.
   Admin login success, failed password, and rate-limit events SHOULD notify
   Telegram using the same `TOKEN` / `MY_CHAT_ID` as `/root/bot_listener.sh`
   (or `TT_TELEGRAM_BOT_TOKEN` / `TT_TELEGRAM_CHAT_ID` / `TT_TELEGRAM_SCRIPT`).
   Do not put bot tokens in the git repository.
   Admin Settings Backup MUST POST `/settings/backup` with CSRF and return
   a zip (configs under `/opt/trusttunnel`, `admin.toml`, systemd units,
   `crontab -l`, `/root` scripts referenced from cron, `/root/.ssh`
   (`authorized_keys` and identity keys), `/etc/ssh/sshd_config` and
   `sshd_config.d`, plus `restore.sh`). Do not copy SSH host keys into the
   zip. Restore MUST issue a new Let's Encrypt cert for a new hostname
   (DuckDNS instructions); do not reuse the old domain. If endpoint/admin
   binaries are missing from the zip, restore MUST download the GitHub
   release tarball. Restore MUST start `/root/bot_listener.sh` (and
   telegram bot if present) instead of waiting for `@reboot`. Restore MUST
   write `/etc/ssh/sshd_config.d/99-tt-pubkey-only.conf` (`PasswordAuthentication
   no`) and `sshd -t` before reload. Restore MUST ensure `vpn.toml` has
   `[metrics]` with `per_client_metrics = true` (otherwise the endpoint does
   not bind `127.0.0.1:1987` and `/clients` is empty). Enable
   `certbot.timer` (it *checks* about every 12 hours; Let's Encrypt renews
   only when fewer than ~30 days remain) and a renew deploy hook that HUP's
   the endpoint so a monthly reboot is not required to pick up the new
   files. Saving VPN settings MUST keep or insert that `[metrics]` block.
   Do not put backup zip contents in git.
   Admin 2FA is TOTP (`totp_enabled` / `totp_secret` in `admin.toml`). The
   shared secret MUST stay on the server; do not commit it. The setup card
   MUST show an SVG QR of the otpauth URI (no CDN). Disable 2FA MUST use a
   visible `bg-indigo-600` button (classes that exist in `admin.css`;
   `bg-slate-700` is not shipped) plus a hint that a current app code and
   that button turn 2FA off. Login history
   lives next to `admin.toml` as `login_history.json` (time + IP) and is
   shown from Logs → Sign-in history.
   Dashboard IP modal MUST refetch geo when `/tmp/vpn_times/geo` has city/ISP
   but no lat/lon (monitor.sh / bot cache omit coordinates). Click MUST not
   share the 3s kind-lookup throttle. Prefer `curl` to ip-api.com (same host
   as the bot) then ipwho.is for coordinates; do not label a public IP as
   private just because the map URL is empty.
   Admin HTML MUST NOT load scripts or stylesheets from third-party CDNs
   (`cdn.tailwindcss.com`, unpkg, jsDelivr, …). Ship CSS with the binary
   (`admin/static/admin.css` at `/static/admin.css`). Do not add htmx unless
   templates actually use it; interactive pages already use `fetch()`.
   Admin CSS MUST be served with `Cache-Control: no-cache` (the file is
   baked into the binary; a 24h cache hid dashboard UI after binary-only
   upgrades). Dashboard lock icons MUST set SVG `width`/`height` (and
   inline display), not rely on utility classes, so they stay 22px when
   CSS is stale.
   Destination visit stats MUST increment once per tunneled TCP CONNECT
   hostname, TLS ClientHello SNI on IP CONNECTs, or DNS question on UDP/53
   (not per packet or byte), persist at most every 30s, cap domains
   per user, and load on username click or the traffic-card Top domains
   control (which sums every user) rather than the dashboard poll. Periods
   are last hour (current clock hour), today, week, month, and all time.
   Last hour MUST match stored hour ids exactly (unix hour or local
   day*24+hour), never via saturating subtraction (day ids looked like
   "this hour" and cloned Today).
   Admin traffic chart bars are inbound+outbound byte deltas per bucket
   (10s last hour, 5min last day, 15min last week). Sample host gauges
   about every 10s in memory; persist `traffic_series.json` about every
   50s and coarsen samples older than 2h to 60s so disk I/O stays low.
   CPU milli-percent MUST come from `/proc/stat` busy delta (not 1-min
   loadavg) and buckets MUST keep the peak in the interval. RAM/I/O use
   the same timestamps. Charts MUST stack vertically, each with its own
   X axis at window quarters (hour: 0 15 30 45 60). Hover and touch MUST
   show local clock time and the series unit (bytes 1024, or percent),
   with a readout under the plot on tap. Do not label Y.
   Top domains control lives on the service card, above restart.
   Chart hairline MUST be an SVG rect with the same x/width as the bar.
   The readout under each chart MUST always show the latest bucket
   (fixed height, no layout jump).
   Dashboard poll MUST keep existing chart SVGs (`#cpu-chart`,
   `#ram-chart`, `#io-chart`, `#traf-chart`); do not wipe then refetch.
   Dest modal period/user switches MUST keep the previous list until the
   new rows arrive — no loading placeholder that collapses the card.
   Admin dashboard SHOULD sample total traffic, CPU, RAM, and disk I/O
   about every 10s (flush to `traffic_series.json` about once a minute).
   User notes/tags live on `[[client]]` (`note`, `tags`); the users page
   edits them and the dashboard shows them. Endpoint ignores unknown keys.
   Dashboard per-user lock MUST write `disabled = true` on the matching
   `[[client]]` in `credentials.toml` (absent/false = unlocked), then
   restart the endpoint so live sessions drop.    User-page saves MUST keep
   the existing `disabled` flag.
   The unauthenticated login HTML `<title>` MUST be a generic MDM/UEM label
   (`MDM Panel`), not TrustTunnel or VPN.
   Reverse proxy MUST copy the request body (Content-Length bytes, or until
   EOF for POST/PUT/PATCH without a length) to the origin before reading
   the origin response so form POST cannot deadlock.
   Reverse proxy MUST set `X-Forwarded-For` / `X-Real-IP` from the TLS peer
   and `X-Forwarded-Proto: https`. Admin login MUST use those headers when
   the peer is loopback (the origin TCP client is 127.0.0.1).
   `/clients` MUST keep User-Agent strings from CONNECT on each session and
   merge distinct agents under the same username+IP (NAT). The dashboard IP
   modal MUST list those agents under the geo block, collapsing protocol
   channel tokens (`_udp2`, `_icmp`, `_check`, `unknown`) so one device is
   one OS+app line. The IP row MUST show OS icons for distinct platforms
   on that address.
   Saving vpn/users/rules/hosts or dashboard restart MUST defer
   `systemctl restart` / `kill -HUP` (~2.5s) so the HTTP response can flush
   through reverse proxy on :443; do not restart the endpoint on the
   request task before returning the page.
   Below 768px the dashboard user table MUST stack as a card grid (name /
   sessions / lock, then IPs, then traffic / quota) with nowrap on IP age
   and traffic so values do not split while columns sit empty.

   **Rationale**: consistency with the existing config surface. Several
   TrustTunnel clients behind one public IP share a source address and each
   opens multiple HTTP/2 sessions, so a global per-IP handshake cap can stall
   legitimate household reconnects.

4. Markdown files MUST pass `markdownlint` (configured in
   `.markdownlint.json`). Run `make lint-md` before submitting docs.
   **Markdown table formatting (MD060)**: When the Markdownlint MD060 rule
   triggers, switch to tight table formatting with spaces. Example:

   ```markdown
   | Column1 | Column2 |
   | --- | --- |
   | Value 1 | Value 2 |
   ```

   **Rationale**: consistent documentation formatting.

### III. Testing Discipline

1. Unit tests MUST live next to their source module in `#[cfg(test)]` blocks.

   **Rationale**: keeps tests close to the code they verify.

2. Integration tests MUST be placed in `lib/tests/`. Shared test helpers live
   in `lib/tests/common/mod.rs`.

   **Rationale**: centralized integration test infrastructure with reusable
   endpoint setup, TLS connection helpers, and HTTP/3 session management.

3. Tests MUST be hermetic: do not rely on developer-specific credentials or
   real certificates. Use fixtures or generated temp files (see
   `make_cert_key_file()` in test helpers).

   **Rationale**: ensures tests pass in any environment (local, CI).

4. Add edge cases for protocol parsing, config validation, and network
   boundary handling when touching related code.

   **Rationale**: the VPN protocol has strict binary parsing requirements
   where off-by-one errors can cause connection failures.

5. The primary test command is `make test` (`cargo test --workspace`). Run it
   locally before pushing.

   **Rationale**: the pre-commit hook runs it automatically, but explicit
   runs catch issues earlier.

### IV. Other

1. NEVER commit secrets or real credential files. The `.gitignore` excludes
   generated configs (`vpn.toml`, `hosts.toml`, `credentials.toml`,
   `rules.toml`) and `certs/`. Example configs in the repo are for reference
   only.

   **Rationale**: prevents accidental credential exposure.

2. Generated certificates and configs SHOULD stay local or be encrypted before
   transmission.

   **Rationale**: TLS private keys and user credentials are security-critical.

3. When exposing endpoints, confirm hostnames and ports match the generated
   client configs to avoid TLS handshake failures.

   **Rationale**: hostname/port mismatches are the most common deployment
   issue.
