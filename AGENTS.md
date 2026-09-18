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
   Admin HTML MUST NOT load scripts or stylesheets from third-party CDNs
   (`cdn.tailwindcss.com`, unpkg, jsDelivr, …). Ship CSS with the binary
   (`admin/static/admin.css` at `/static/admin.css`). Do not add htmx unless
   templates actually use it; interactive pages already use `fetch()`.

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
