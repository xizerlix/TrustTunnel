use axum::extract::{FromRef, FromRequestParts, Request, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use crate::config::AdminConfig;
use crate::error::AdminError;
use crate::state::AppState;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub const SESSION_COOKIE: &str = "tt_admin_session";
pub const CSRF_COOKIE: &str = "tt_admin_csrf";
pub const TOTP_COOKIE: &str = "tt_admin_totp";

#[derive(Clone)]
pub struct Session {
    pub token: String,
    pub csrf: String,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub username: String,
}

#[derive(Default)]
pub struct SessionStore {
    inner: RwLock<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn create(&self, username: &str, _ttl: Duration) -> Session {
        let token = random_token();
        let csrf = random_token();
        let now = Instant::now();
        let session = Session {
            token: token.clone(),
            csrf,
            created_at: now,
            last_seen: now,
            username: username.to_string(),
        };
        self.inner.write().await.insert(token, session.clone());
        session
    }

    pub async fn touch(&self, token: &str, ttl: Duration) -> Option<Session> {
        let mut guard = self.inner.write().await;
        let session = guard.get_mut(token)?;
        if session.created_at.elapsed() > ttl {
            guard.remove(token);
            return None;
        }
        session.last_seen = Instant::now();
        Some(session.clone())
    }

    pub async fn destroy(&self, token: &str) {
        self.inner.write().await.remove(token);
    }

    pub async fn cleanup_expired(&self, ttl: Duration) {
        let mut guard = self.inner.write().await;
        guard.retain(|_, s| s.created_at.elapsed() <= ttl);
    }
}

#[derive(Default)]
pub struct LoginLimiter {
    inner: RwLock<HashMap<IpAddr, LoginBucket>>,
    global: RwLock<LoginBucket>,
}

struct LoginBucket {
    count: u32,
    limited_notified: bool,
    window_start: Instant,
}

impl Default for LoginBucket {
    fn default() -> Self {
        Self {
            count: 0,
            limited_notified: false,
            window_start: Instant::now(),
        }
    }
}

impl LoginLimiter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Returns `(allowed, notify_rate_limit)` — Telegram only on the first
    /// rejection in the current window, not on every extra POST.
    pub async fn check(&self, ip: IpAddr, per_ip: u32, global_per_min: u32) -> (bool, bool) {
        let mut global = self.global.write().await;
        let mut ips = self.inner.write().await;
        reset_bucket(&mut global);
        let bucket = ips.entry(ip).or_default();
        reset_bucket(bucket);
        if global.count >= global_per_min || bucket.count >= per_ip {
            let notify = if bucket.count >= per_ip {
                let n = !bucket.limited_notified;
                bucket.limited_notified = true;
                n
            } else {
                let n = !global.limited_notified;
                global.limited_notified = true;
                n
            };
            return (false, notify);
        }
        global.count = global.count.saturating_add(1);
        bucket.count = bucket.count.saturating_add(1);
        (true, false)
    }

    pub async fn cleanup_expired(&self) {
        let mut guard = self.inner.write().await;
        guard.retain(|_, b| b.window_start.elapsed() <= Duration::from_secs(120));
    }
}

fn reset_bucket(bucket: &mut LoginBucket) {
    if bucket.window_start.elapsed() > Duration::from_secs(60) {
        bucket.count = 0;
        bucket.limited_notified = false;
        bucket.window_start = Instant::now();
    }
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn build_session_cookies(token: &str, ttl_secs: u64, secure: bool) -> Vec<(String, String)> {
    let secure_flag = if secure { "; Secure" } else { "" };
    let samesite = "; SameSite=Strict; Path=/; HttpOnly";
    let max_age = format!("; Max-Age={ttl_secs}");
    let value = format!("{token}{samesite}{max_age}{secure_flag}");
    vec![(SESSION_COOKIE.to_string(), value)]
}

pub fn build_csrf_cookie(csrf: &str, ttl_secs: u64, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{csrf}; SameSite=Strict; Path=/; Max-Age={ttl_secs}{secure_flag}",
        csrf = csrf,
        ttl_secs = ttl_secs,
        secure_flag = secure_flag,
    )
}

pub fn build_clear_cookies() -> Vec<(String, String)> {
    vec![
        (
            SESSION_COOKIE.to_string(),
            "; Path=/; Max-Age=0; HttpOnly".to_string(),
        ),
        (CSRF_COOKIE.to_string(), "; Path=/; Max-Age=0".to_string()),
        (
            TOTP_COOKIE.to_string(),
            "; Path=/; Max-Age=0; HttpOnly".to_string(),
        ),
    ]
}

pub fn set_cookies(headers: &mut HeaderMap, cookies: Vec<(String, String)>) {
    for (name, value) in cookies {
        let cookie = format!("{name}={value}");
        if let Ok(v) = cookie.parse() {
            headers.append(SET_COOKIE, v);
        }
    }
}

pub fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find_map(|c| {
            c.strip_prefix(&format!("{SESSION_COOKIE}="))
                .map(String::from)
        })
}

pub fn extract_csrf_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, CSRF_COOKIE)
}

pub fn extract_totp_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, TOTP_COOKIE)
}

pub async fn inject_open_session(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    if AdminConfig::load_or_default(&state.paths.admin_toml).password_login {
        return next.run(request).await;
    }
    let ttl = Duration::from_secs(state.config.session_ttl_secs);
    if let Some(token) = extract_session_cookie(request.headers()) {
        if state.sessions.touch(&token, ttl).await.is_some() {
            return next.run(request).await;
        }
    }
    let session = state.sessions.create("admin", ttl).await;
    merge_request_cookie(request.headers_mut(), SESSION_COOKIE, &session.token);
    merge_request_cookie(request.headers_mut(), CSRF_COOKIE, &session.csrf);
    let mut resp = next.run(request).await;
    set_cookies(
        resp.headers_mut(),
        build_session_cookies(
            &session.token,
            state.config.session_ttl_secs,
            state.secure_cookies,
        ),
    );
    let csrf_header = format!(
        "{}={}",
        CSRF_COOKIE,
        build_csrf_cookie(
            &session.csrf,
            state.config.session_ttl_secs,
            state.secure_cookies,
        )
    );
    if let Ok(v) = csrf_header.parse::<HeaderValue>() {
        resp.headers_mut().append(SET_COOKIE, v);
    }
    resp
}

fn merge_request_cookie(headers: &mut HeaderMap, name: &str, value: &str) {
    let extra = format!("{name}={value}");
    let merged = match headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        Some(c) if !c.is_empty() => format!("{c}; {extra}"),
        _ => extra,
    };
    if let Ok(v) = HeaderValue::from_str(&merged) {
        headers.insert(COOKIE, v);
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find_map(|c| c.strip_prefix(&format!("{name}=")).map(String::from))
}

pub struct Authenticated(pub Session);

#[axum::async_trait]
impl<S> FromRequestParts<S> for Authenticated
where
    S: Send + Sync,
    crate::state::AppState: axum::extract::FromRef<S>,
{
    type Rejection = AdminError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = crate::state::AppState::from_ref(state);
        let token = extract_session_cookie(&parts.headers)
            .ok_or_else(|| AdminError::Auth("no session".into()))?;
        let ttl = Duration::from_secs(app_state.config.session_ttl_secs);
        let session = app_state
            .sessions
            .touch(&token, ttl)
            .await
            .ok_or_else(|| AdminError::Auth("no session".into()))?;
        Ok(Authenticated(session))
    }
}

pub async fn verify_csrf(
    headers: &HeaderMap,
    session: &crate::auth::Session,
) -> Result<(), AdminError> {
    let header_csrf = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
    let cookie_csrf = extract_csrf_cookie(headers);
    let csrf: Option<&str> = header_csrf.or(cookie_csrf.as_deref());
    match csrf {
        Some(t) if t == session.csrf => Ok(()),
        _ => Err(AdminError::Auth("CSRF token mismatch".into())),
    }
}

pub async fn verify_csrf_from_form(
    headers: &HeaderMap,
    body: &str,
    session: &crate::auth::Session,
) -> Result<(), AdminError> {
    verify_csrf(headers, session).await.or_else(|_| {
        if let Some(token) = csrf_from_form(body) {
            if token == session.csrf {
                return Ok(());
            }
        }
        Err(AdminError::Auth("CSRF token mismatch".into()))
    })
}

pub fn csrf_from_form(body: &str) -> Option<String> {
    for (k, v) in body.split('&').filter_map(|kv| {
        let mut parts = kv.splitn(2, '=');
        let k = parts.next()?;
        let v = parts.next().unwrap_or("");
        Some((k, v))
    }) {
        if k == "csrf" {
            return url_decode(v);
        }
    }
    None
}

fn url_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_digit(bytes[i + 1])?;
                let lo = hex_digit(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn per_ip_cap_blocks_further_attempts() {
        let limiter = LoginLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        for _ in 0..3 {
            assert!(limiter.check(ip, 3, 10).await.0);
        }
        let (ok, notify) = limiter.check(ip, 3, 10).await;
        assert!(!ok);
        assert!(notify);
        let (ok, notify) = limiter.check(ip, 3, 10).await;
        assert!(!ok);
        assert!(!notify);
    }

    #[tokio::test]
    async fn global_cap_blocks_other_ips() {
        let limiter = LoginLimiter::new();
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        assert!(limiter.check(a, 5, 1).await.0);
        assert!(!limiter.check(b, 5, 1).await.0);
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}
