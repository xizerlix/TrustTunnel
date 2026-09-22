use crate::auth::{verify_csrf_from_form, Authenticated};
use crate::config::{hash_password, AdminConfig};
use crate::error::{AdminError, AdminResult, WithStatusExt};
use crate::i18n::{self, I18n};
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub t: I18n,
    pub lang: &'static str,
    pub status: Option<String>,
    pub error: Option<String>,
    pub totp_on: bool,
    pub totp_secret: Option<String>,
    pub totp_otpauth: Option<String>,
    pub totp_qr: Option<String>,
}

fn page(
    session: &crate::auth::Session,
    headers: &HeaderMap,
    status: Option<String>,
    error: Option<String>,
    totp_on: bool,
    totp_secret: Option<String>,
) -> SettingsTemplate {
    let lang = i18n::from_headers(headers);
    let t = i18n::t(lang);
    let totp_otpauth = totp_secret.as_ref().map(|s| crate::totp::otpauth_url(s));
    let totp_qr = totp_secret
        .as_ref()
        .and_then(|s| crate::totp::otpauth_qr_data_uri(s));
    SettingsTemplate {
        title: t.settings.into(),
        username: session.username.clone(),
        csrf: session.csrf.clone(),
        t,
        lang: lang.as_str(),
        status,
        error,
        totp_on,
        totp_secret,
        totp_otpauth,
        totp_qr,
    }
}

fn totp_on_file(state: &AppState) -> bool {
    AdminConfig::load_or_default(&state.paths.admin_toml).totp_on()
}

pub async fn settings_form(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> Response {
    let pending = state.totp_setup.read().await.clone();
    page(
        &session,
        &headers,
        None,
        None,
        totp_on_file(&state),
        pending,
    )
    .into_response()
}

pub async fn settings_password(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let form: PasswordForm = serde_urlencoded::from_str(&body)
        .map_err(|e| AdminError::Validation(format!("invalid form: {e}")))?;
    if form.current_password.is_empty() || form.new_password.is_empty() {
        return Err(AdminError::Validation("both passwords required".into()));
    }
    if form.new_password != form.confirm_password {
        return Err(AdminError::Validation("passwords do not match".into()));
    }
    if form.new_password.len() < 10 {
        return Err(AdminError::Validation(
            "password must be at least 10 characters".into(),
        ));
    }
    let mut cfg = AdminConfig::load_or_default(&state.paths.admin_toml);
    let current_hash = if cfg.bcrypt_hash.is_empty() {
        state.bcrypt_hash.read().await.clone()
    } else {
        cfg.bcrypt_hash.clone()
    };
    let current = form.current_password.clone();
    let ok = tokio::task::spawn_blocking(move || {
        crate::config::verify_password(&current, &current_hash)
    })
    .await
    .unwrap_or(false);
    if !ok {
        return Err(AdminError::Validation("current password incorrect".into()));
    }
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&form.new_password))
        .await
        .map_err(|e| AdminError::Apply(format!("hashing task: {e}")))?
        .map_err(|e| AdminError::Apply(format!("hash: {e}")))?;
    cfg.bcrypt_hash = new_hash.clone();
    cfg.save(&state.paths.admin_toml)?;
    *state.bcrypt_hash.write().await = new_hash;
    let t = i18n::t(i18n::from_headers(&headers));
    Ok(page(
        &session,
        &headers,
        Some(t.password_updated.to_string()),
        None,
        cfg.totp_on(),
        None,
    )
    .into_response()
    .with_status(StatusCode::OK))
}

pub async fn totp_start(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    if totp_on_file(&state) {
        let t = i18n::t(i18n::from_headers(&headers));
        return Ok(page(
            &session,
            &headers,
            None,
            Some(t.totp_already.to_string()),
            true,
            None,
        )
        .into_response());
    }
    let secret = crate::totp::generate_secret();
    *state.totp_setup.write().await = Some(secret.clone());
    Ok(page(&session, &headers, None, None, false, Some(secret)).into_response())
}

pub async fn totp_confirm(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let form: TotpCodeForm = serde_urlencoded::from_str(&body)
        .map_err(|e| AdminError::Validation(format!("invalid form: {e}")))?;
    let t = i18n::t(i18n::from_headers(&headers));
    let Some(secret) = state.totp_setup.read().await.clone() else {
        return Ok(page(
            &session,
            &headers,
            None,
            Some(t.totp_start_first.to_string()),
            totp_on_file(&state),
            None,
        )
        .into_response());
    };
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    if !crate::totp::verify(&secret, &form.totp_code, now) {
        return Ok(page(
            &session,
            &headers,
            None,
            Some(t.totp_bad_code.to_string()),
            false,
            Some(secret),
        )
        .into_response());
    }
    let mut cfg = AdminConfig::load_or_default(&state.paths.admin_toml);
    cfg.totp_enabled = true;
    cfg.totp_secret = secret;
    cfg.save(&state.paths.admin_toml)?;
    *state.totp_setup.write().await = None;
    Ok(page(
        &session,
        &headers,
        Some(t.totp_enabled_ok.to_string()),
        None,
        true,
        None,
    )
    .into_response())
}

pub async fn totp_disable(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let form: TotpCodeForm = serde_urlencoded::from_str(&body)
        .map_err(|e| AdminError::Validation(format!("invalid form: {e}")))?;
    let t = i18n::t(i18n::from_headers(&headers));
    let cfg = AdminConfig::load_or_default(&state.paths.admin_toml);
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    if !cfg.totp_on() || !crate::totp::verify(&cfg.totp_secret, &form.totp_code, now) {
        return Ok(page(
            &session,
            &headers,
            None,
            Some(t.totp_bad_code.to_string()),
            cfg.totp_on(),
            None,
        )
        .into_response());
    }
    let mut cfg = cfg;
    cfg.totp_enabled = false;
    cfg.totp_secret.clear();
    cfg.save(&state.paths.admin_toml)?;
    *state.totp_setup.write().await = None;
    Ok(page(
        &session,
        &headers,
        Some(t.totp_disabled_ok.to_string()),
        None,
        false,
        None,
    )
    .into_response())
}

pub async fn settings_backup(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let root = state.paths.root.clone();
    let admin_toml = state.paths.admin_toml.clone();
    let bytes = tokio::task::spawn_blocking(move || {
        let input = crate::backup::collect_live(root, admin_toml);
        crate::backup::build_zip(&input)
    })
    .await
    .map_err(|e| AdminError::Apply(format!("backup task: {e}")))?
    .map_err(|e| AdminError::Apply(format!("backup zip: {e}")))?;
    let name = format!(
        "mdm-backup-{}.zip",
        chrono::Local::now().format("%Y%m%d-%H%M")
    );
    let disp = format!("attachment; filename=\"{name}\"");
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disp).unwrap_or_else(|_| {
                    HeaderValue::from_static("attachment; filename=\"mdm-backup.zip\"")
                }),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        bytes,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct PasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Deserialize)]
pub struct TotpCodeForm {
    pub totp_code: String,
}
