use crate::auth::{LoginLimiter, SessionStore};
use crate::config::AdminConfig;
use crate::live::{HostSnapshot, LiveCache};
use crate::paths::TrustTunnelPaths;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AdminConfig>,
    pub paths: Arc<TrustTunnelPaths>,
    pub sessions: Arc<SessionStore>,
    pub login_limiter: Arc<LoginLimiter>,
    pub secure_cookies: bool,
    pub live: Arc<LiveCache>,
    pub slow: Arc<SlowInfo>,
}

pub struct SlowInfo {
    inner: Mutex<SlowSlot>,
}

struct SlowSlot {
    host: HostSnapshot,
    host_at: Instant,
    cert: Option<(String, String)>,
    cert_at: Instant,
}

impl SlowInfo {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(SlowSlot {
                host: HostSnapshot::default(),
                host_at: Instant::now() - Duration::from_secs(120),
                cert: None,
                cert_at: Instant::now() - Duration::from_secs(3600),
            }),
        })
    }

    pub fn host_and_cert(&self, cert_path: Option<&str>) -> (HostSnapshot, Option<(String, String)>) {
        let mut g = self.inner.lock().unwrap();
        if g.host_at.elapsed() > Duration::from_secs(30) {
            g.host = crate::live::parse_host_snapshot();
            g.host_at = Instant::now();
        }
        if g.cert_at.elapsed() > Duration::from_secs(600) {
            g.cert = cert_path.and_then(crate::live::read_cert_summary);
            g.cert_at = Instant::now();
        }
        (g.host.clone(), g.cert.clone())
    }
}

impl axum::extract::FromRef<AppState> for Arc<AdminConfig> {
    fn from_ref(s: &AppState) -> Self {
        s.config.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<TrustTunnelPaths> {
    fn from_ref(s: &AppState) -> Self {
        s.paths.clone()
    }
}
