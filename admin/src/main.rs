mod apply;
mod auth;
mod config;
mod error;
mod form;
mod handlers;
mod i18n;
mod live;
mod models;
mod paths;
mod state;

use crate::auth::{LoginLimiter, SessionStore};
use crate::config::AdminConfig;
use crate::paths::TrustTunnelPaths;
use crate::state::AppState;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

#[derive(Parser)]
#[command(name = "trusttunnel_admin", version, about = "TrustTunnel admin console")]
struct Cli {
    #[arg(long, env = "TT_ADMIN_BIND", default_value = "127.0.0.1:8443")]
    bind: SocketAddr,
    #[arg(long, env = "TT_PATHS_ROOT", default_value = "/opt/trusttunnel")]
    paths_root: PathBuf,
    #[arg(long, env = "TT_ADMIN_TOML", default_value = "/etc/trusttunnel/admin.toml")]
    admin_toml: PathBuf,
    #[arg(long, env = "TT_SECURE_COOKIES", default_value_t = true)]
    secure_cookies: bool,
    /// Initialize or rotate the admin password (creates admin.toml) and exit.
    #[arg(long)]
    init_admin: bool,
    /// Password for --init-admin. If absent, prompts on stdin.
    #[arg(long, requires = "init_admin")]
    password: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.init_admin {
        return init_admin(cli.admin_toml, cli.bind, cli.password);
    }
    serve(cli.bind, cli.paths_root, cli.admin_toml, cli.secure_cookies).await
}

async fn serve(
    bind: SocketAddr,
    paths_root: PathBuf,
    admin_toml: PathBuf,
    secure_cookies: bool,
) -> anyhow::Result<()> {
    let paths = TrustTunnelPaths::detect_with_root(paths_root)?;
    if !paths.exists() {
        anyhow::bail!(
            "TrustTunnel configs not found at {}; run setup_wizard first",
            paths.root.display()
        );
    }
    let mut paths = paths;
    paths.admin_toml = admin_toml.clone();
    let mut config = AdminConfig::load_or_default(&admin_toml);
    config.bind = bind;
    if !config.is_initialized() {
        anyhow::bail!(
            "admin not initialized; run `trusttunnel_admin init-admin` first"
        );
    }
    let bcrypt_hash = Arc::new(tokio::sync::RwLock::new(config.bcrypt_hash.clone()));
    let config = Arc::new(config);

    let state = AppState {
        config,
        bcrypt_hash,
        paths: Arc::new(paths),
        sessions: SessionStore::new(),
        login_limiter: LoginLimiter::new(),
        secure_cookies,
        live: Arc::new(crate::live::LiveCache::new()),
        slow: crate::state::SlowInfo::new(),
    };

    spawn_cleanup(state.clone());

    let app = build_router(state.clone());

    log::info!("trusttunnel_admin listening on {}", state.config.bind);
    let listener = tokio::net::TcpListener::bind(state.config.bind).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn spawn_cleanup(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let ttl = Duration::from_secs(state.config.session_ttl_secs);
            state.sessions.cleanup_expired(ttl).await;
            state.login_limiter.cleanup_expired().await;
        }
    });
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handlers::login::index))
        .route(
            "/login",
            get(handlers::login::login_form).post(handlers::login::login_submit),
        )
        .route("/logout", post(handlers::login::logout))
        .route("/health-check", get(health_check))
        .route("/lang", get(handlers::login::set_lang))
        .route("/dashboard", get(handlers::dashboard::dashboard))
        .route("/dashboard/data", get(handlers::dashboard::dashboard_data))
        .route("/dashboard/ip", get(handlers::dashboard::ip_lookup))
        .route(
            "/dashboard/service",
            post(handlers::dashboard::service_restart),
        )
        .route("/dashboard/reboot", post(handlers::dashboard::host_reboot))
        .route(
            "/vpn",
            get(handlers::vpn::vpn_form).post(handlers::vpn::vpn_save),
        )
        .route(
            "/hosts",
            get(handlers::hosts::hosts_form).post(handlers::hosts::hosts_save),
        )
        .route(
            "/users",
            get(handlers::users::users_form).post(handlers::users::users_save),
        )
        .route("/users/delete", post(handlers::users::users_delete))
        .route(
            "/users/:username/deeplink",
            post(handlers::users::users_deeplink),
        )
        .route(
            "/rules",
            get(handlers::rules::rules_form).post(handlers::rules::rules_save),
        )
        .route("/logs", get(handlers::logs::logs_view))
        .route("/logs/data", get(handlers::logs::logs_data))
        .route("/logs/htop", get(handlers::logs::htop_view))
        .route("/logs/htop/data", get(handlers::logs::htop_data))
        .route(
            "/settings",
            get(handlers::settings::settings_form).post(handlers::settings::settings_password),
        )
        .route("/csrf", get(handlers::login::csrf_token))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::HeaderName::from_static("x-content-type-options"),
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::HeaderName::from_static("referrer-policy"),
            axum::http::HeaderValue::from_static("no-referrer"),
        ))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health_check() -> &'static str {
    "ok\n"
}

fn init_admin(admin_toml: PathBuf, bind: SocketAddr, password: Option<String>) -> anyhow::Result<()> {
    let plain = match password {
        Some(p) => p,
        None => {
            eprint!("Enter admin password: ");
            let mut s = String::new();
            std::io::stdin().read_line(&mut s)?;
            s.trim().to_string()
        }
    };
    if plain.len() < 10 {
        anyhow::bail!("password must be at least 10 characters");
    }
    let hash = config::hash_password(&plain)?;
    let cfg = AdminConfig {
        bind,
        bcrypt_hash: hash,
        session_ttl_secs: 1800,
        login_rate_per_min: 5,
    };
    if let Some(parent) = admin_toml.parent() {
        std::fs::create_dir_all(parent)?;
    }
    cfg.save(&admin_toml)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&admin_toml, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("admin.toml written to {} (mode 0600)", admin_toml.display());
    Ok(())
}