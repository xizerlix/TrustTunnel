use crate::error::AdminError;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::SET_COOKIE;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub const SESSION_COOKIE: &str = "tt_admin_session";
pub const CSRF_COOKIE: &str = "tt_admin_csrf";

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
}

struct LoginBucket {
    count: u32,
    window_start: Instant,
}

impl LoginLimiter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn check(&self, ip: IpAddr, per_min: u32) -> bool {
        let mut guard = self.inner.write().await;
        let bucket = guard.entry(ip).or_insert(LoginBucket {
            count: 0,
            window_start: Instant::now(),
        });
        if bucket.window_start.elapsed() > Duration::from_secs(60) {
            bucket.count = 0;
            bucket.window_start = Instant::now();
        }
        bucket.count += 1;
        bucket.count <= per_min
    }

    pub async fn cleanup_expired(&self) {
        let mut guard = self.inner.write().await;
        guard.retain(|_, b| b.window_start.elapsed() <= Duration::from_secs(120));
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
        (
            CSRF_COOKIE.to_string(),
            "; Path=/; Max-Age=0".to_string(),
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
        .find_map(|c| c.strip_prefix(&format!("{SESSION_COOKIE}=")).map(String::from))
}

pub fn extract_csrf_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find_map(|c| c.strip_prefix(&format!("{CSRF_COOKIE}=")).map(String::from))
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
            .ok_or_else(|| AdminError::Auth("session expired".into()))?;
        Ok(Authenticated(session))
    }
}

pub async fn verify_csrf(
    headers: &HeaderMap,
    session: &crate::auth::Session,
) -> Result<(), AdminError> {
    let header_csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok());
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