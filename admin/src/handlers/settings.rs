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
}

pub async fn settings_form(Authenticated(session): Authenticated, headers: HeaderMap) -> Response {
    let lang = i18n::from_headers(&headers);
    let t = i18n::t(lang);
    SettingsTemplate {
        title: t.settings.into(),
        username: session.username,
        csrf: session.csrf,
        t,
        lang: lang.as_str(),
        status: None,
        error: None,
    }
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
    let current_hash = {
        let file_hash =
            crate::config::AdminConfig::load_or_default(&state.paths.admin_toml).bcrypt_hash;
        if file_hash.is_empty() {
            state.bcrypt_hash.read().await.clone()
        } else {
            file_hash
        }
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
    let mut cfg: AdminConfig = (*state.config).clone();
    cfg.bcrypt_hash = new_hash.clone();
    cfg.save(&state.paths.admin_toml)?;
    *state.bcrypt_hash.write().await = new_hash;
    let lang = i18n::from_headers(&headers);
    let t = i18n::t(lang);
    let status = Some(t.password_updated.to_string());
    Ok(SettingsTemplate {
        title: t.settings.into(),
        username: session.username,
        csrf: session.csrf,
        t,
        lang: lang.as_str(),
        status,
        error: None,
    }
    .into_response()
    .with_status(StatusCode::OK))
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
