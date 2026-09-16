use crate::auth::{verify_csrf_from_form, Authenticated};
use crate::config::{hash_password, AdminConfig};
use crate::error::{AdminError, AdminResult};
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub status: Option<String>,
    pub error: Option<String>,
}

pub async fn settings_form(
    Authenticated(session): Authenticated,
) -> Response {
    SettingsTemplate {
        title: "Settings".into(),
        username: session.username,
        csrf: session.csrf,
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
        return Err(AdminError::Validation("password must be at least 10 characters".into()));
    }
    let current_hash = state.config.bcrypt_hash.clone();
    let current = form.current_password.clone();
    let ok = tokio::task::spawn_blocking(move || {
        crate::config::verify_password(&current, &current_hash)
    })
    .await
    .unwrap_or(false);
    if !ok {
        return Err(AdminError::Auth("current password incorrect".into()));
    }
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&form.new_password))
        .await
        .map_err(|e| AdminError::Apply(format!("hashing task: {e}")))?
        .map_err(|e| AdminError::Apply(format!("hash: {e}")))?;
    let mut cfg: AdminConfig = (*state.config).clone();
    cfg.bcrypt_hash = new_hash;
    cfg.save(&state.paths.admin_toml)?;
    Ok(SettingsTemplate {
        title: "Settings".into(),
        username: session.username,
        csrf: session.csrf,
        status: Some("Password updated".into()),
        error: None,
    }
    .into_response()
        .with_status(StatusCode::OK))
}

use crate::error::WithStatusExt;

#[derive(Deserialize)]
pub struct PasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}