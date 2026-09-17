use crate::auth::{
    self, build_csrf_cookie, build_session_cookies, extract_session_cookie, Authenticated,
    LoginForm,
};
use crate::config::verify_password;
use crate::error::AdminResult;
use crate::i18n::{self, I18n};
use crate::state::AppState;
use askama::Template;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
    pub username: String,
    pub t: I18n,
    pub lang: &'static str,
    pub csrf: String,
    pub title: String,
}

fn login_page(headers: &HeaderMap, error: Option<String>, username: String) -> LoginTemplate {
    let lang = i18n::from_headers(headers);
    let t = i18n::t(lang);
    LoginTemplate {
        title: t.sign_in.into(),
        error,
        username,
        t,
        lang: lang.as_str(),
        csrf: String::new(),
    }
}

pub async fn login_form(headers: HeaderMap) -> Response {
    login_page(&headers, None, String::new()).into_response()
}

pub async fn login_submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = login_ip(&headers, Some(addr.ip()));
    let global = state.config.login_rate_per_min.saturating_mul(3).max(8);
    if !state
        .login_limiter
        .check(ip, state.config.login_rate_per_min, global)
        .await
    {
        let t = i18n::t(i18n::from_headers(&headers));
        let mut resp = login_page(&headers, Some(t.too_many_logins.into()), form.username)
            .into_response();
        *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        return resp;
    }

    let config = state.config.clone();
    let username = form.username.clone();
    let password = form.password.clone();
    let verified = tokio::task::spawn_blocking(move || {
        if username != "admin" {
            return false;
        }
        verify_password(&password, &config.bcrypt_hash)
    })
    .await
    .unwrap_or(false);

    if !verified {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let t = i18n::t(i18n::from_headers(&headers));
        let mut resp =
            login_page(&headers, Some(t.invalid_login.into()), form.username).into_response();
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
        return resp;
    }

    let session = state
        .sessions
        .create("admin", Duration::from_secs(state.config.session_ttl_secs))
        .await;

    let mut resp_headers = HeaderMap::new();
    let cookies = build_session_cookies(
        &session.token,
        state.config.session_ttl_secs,
        state.secure_cookies,
    );
    auth::set_cookies(&mut resp_headers, cookies);
    let csrf_header = format!(
        "{}={}",
        auth::CSRF_COOKIE,
        build_csrf_cookie(
            &session.csrf,
            state.config.session_ttl_secs,
            state.secure_cookies,
        )
    );
    if let Ok(v) = csrf_header.parse::<HeaderValue>() {
        resp_headers.append(axum::http::header::SET_COOKIE, v);
    }
    (resp_headers, Redirect::to("/dashboard")).into_response()
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> AdminResult<Response> {
    if let Some(token) = extract_session_cookie(&headers) {
        state.sessions.destroy(&token).await;
    }
    let mut h = HeaderMap::new();
    for (name, value) in auth::build_clear_cookies() {
        let cookie = format!("{name}={value}");
        if let Ok(v) = cookie.parse::<HeaderValue>() {
            h.append(axum::http::header::SET_COOKIE, v);
        }
    }
    Ok((h, Redirect::to("/login")).into_response())
}

pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = extract_session_cookie(&headers) {
        let ttl = Duration::from_secs(state.config.session_ttl_secs);
        if state.sessions.touch(&token, ttl).await.is_some() {
            return Redirect::to("/dashboard").into_response();
        }
    }
    Redirect::to("/login").into_response()
}

#[derive(Deserialize)]
pub struct LangQuery {
    pub set: Option<String>,
    pub next: Option<String>,
}

pub async fn set_lang(Query(q): Query<LangQuery>, headers: HeaderMap) -> Response {
    let lang = q
        .set
        .as_deref()
        .and_then(i18n::parse_set)
        .unwrap_or_else(|| i18n::from_headers(&headers));
    let next = q
        .next
        .as_deref()
        .and_then(safe_path)
        .or_else(|| {
            headers
                .get(axum::http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .and_then(safe_path)
        })
        .unwrap_or_else(|| "/dashboard".into());
    let mut h = HeaderMap::new();
    let cookie = format!(
        "{}={}; Path=/; Max-Age=31536000; SameSite=Lax",
        i18n::LANG_COOKIE,
        lang.as_str()
    );
    if let Ok(v) = cookie.parse::<HeaderValue>() {
        h.insert(axum::http::header::SET_COOKIE, v);
    }
    (h, Redirect::to(&next)).into_response()
}

fn safe_path(s: &str) -> Option<String> {
    if let Ok(uri) = s.parse::<axum::http::Uri>() {
        let p = uri.path();
        if p.starts_with('/') && !p.starts_with("//") && p != "/lang" {
            return Some(p.to_string());
        }
    }
    if s.starts_with('/') && !s.starts_with("//") && s != "/lang" {
        return Some(s.to_string());
    }
    None
}

#[derive(Serialize)]
pub struct CsrfJson {
    pub csrf: String,
}

pub async fn csrf_token(Authenticated(session): Authenticated) -> Json<CsrfJson> {
    Json(CsrfJson {
        csrf: session.csrf,
    })
}

pub fn login_ip(headers: &HeaderMap, peer: Option<IpAddr>) -> IpAddr {
    let peer = peer.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let trusted_proxy = match peer {
        IpAddr::V4(v) => v.is_loopback(),
        IpAddr::V6(v) => v.is_loopback(),
    };
    if trusted_proxy {
        if let Some(xff) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse().ok())
        {
            return xff;
        }
        if let Some(real) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
        {
            return real;
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn xff_ignored_unless_peer_is_loopback() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.9"));
        let peer: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(login_ip(&headers, Some(peer)), peer);
    }

    #[test]
    fn xff_trusted_from_loopback() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.9"));
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            login_ip(&headers, Some(peer)),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
    }
}
