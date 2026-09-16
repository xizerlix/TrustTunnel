use crate::auth::{LoginLimiter, SessionStore};
use crate::config::AdminConfig;
use crate::paths::TrustTunnelPaths;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AdminConfig>,
    pub paths: Arc<TrustTunnelPaths>,
    pub sessions: Arc<SessionStore>,
    pub login_limiter: Arc<LoginLimiter>,
    pub secure_cookies: bool,
}

impl axum::extract::FromRef<AppState> for Arc<AdminConfig> {
    fn from_ref(s: &AppState) -> Self { s.config.clone() }
}

impl axum::extract::FromRef<AppState> for Arc<TrustTunnelPaths> {
    fn from_ref(s: &AppState) -> Self { s.paths.clone() }
}