use crate::auth::{
    self, build_csrf_cookie, build_session_cookies, extract_session_cookie,
    Authenticated, LoginForm,
};
use crate::config::verify_password;
use crate::error::AdminResult;
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum::Json;
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
    pub username: String,
}

pub async fn login_form() -> Response {
    LoginTemplate {
        error: None,
        username: String::new(),
    }
    .into_response()
}

pub async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = client_ip(&headers).unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    if !state
        .login_limiter
        .check(ip, state.config.login_rate_per_min)
        .await
    {
        let mut resp = LoginTemplate {
            error: Some("Too many login attempts. Try again in a minute.".into()),
            username: form.username,
        }
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
        let mut resp = LoginTemplate {
            error: Some("Invalid credentials".into()),
            username: form.username,
        }
        .into_response();
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
        return resp;
    }

    let session = state
        .sessions
        .create("admin", Duration::from_secs(state.config.session_ttl_secs))
        .await;

    let mut resp_headers = headers;
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

#[derive(Serialize)]
pub struct CsrfJson {
    pub csrf: String,
}

pub async fn csrf_token(Authenticated(session): Authenticated) -> Json<CsrfJson> {
    Json(CsrfJson {
        csrf: session.csrf,
    })
}

fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
        })
}