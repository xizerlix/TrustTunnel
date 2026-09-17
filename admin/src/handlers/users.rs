use crate::apply::{apply, ApplyKind};
use crate::auth::{verify_csrf_from_form, Authenticated};
use crate::error::{AdminError, AdminResult};
use crate::models::{ClientEntry, CredentialsToml};
use crate::state::AppState;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub creds: CredentialsToml,
    pub save_status: Option<String>,
    pub error: Option<String>,
}

pub async fn users_form(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> AdminResult<Response> {
    let creds = load_or_default(&state.paths.credentials_toml)?;
    Ok(UsersTemplate {
        title: "Users".into(),
        username: session.username,
        csrf: session.csrf,
        creds,
        save_status: None,
        error: None,
    }
    .into_response())
}

pub async fn users_save(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let mut creds = load_or_default(&state.paths.credentials_toml)?;
    let existing_clients = creds.clients.clone();
    let form: UsersForm = serde_urlencoded::from_str(&body)
        .map_err(|e| AdminError::Validation(format!("invalid form: {e}")))?;

    creds.clients.clear();
    for (i, name) in form.username.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        let password = form.password.get(i).cloned().unwrap_or_default();
        let existing = existing_clients.iter().find(|c| c.username == *name);
        let password = if password.is_empty() {
            match existing {
                Some(c) => c.password.clone(),
                None => {
                    return Err(AdminError::Validation(format!(
                        "password is required for user {name}"
                    )));
                }
            }
        } else {
            password
        };
        creds.clients.push(ClientEntry {
            username: name.clone(),
            password,
            max_http2_conns: parse_u32(form.max_http2_conns.get(i).cloned().unwrap_or_default()),
            max_http3_conns: parse_u32(form.max_http3_conns.get(i).cloned().unwrap_or_default()),
            max_traffic_bytes: parse_u64(form.max_traffic_bytes.get(i).cloned().unwrap_or_default()),
        });
    }
    let serialized = toml::to_string_pretty(&creds).map_err(AdminError::TomlSe)?;
    crate::apply::atomic_write(&state.paths.credentials_toml, &serialized)?;
    let apply_result = apply(&state.paths, ApplyKind::FullRestart);
    let msg = match &apply_result {
        Ok(m) => m.clone(),
        Err(e) => format!("save OK but apply failed: {e}"),
    };
    let err = if apply_result.is_err() { Some(msg.clone()) } else { None };
    let resp = UsersTemplate {
        title: "Users".into(),
        username: session.username,
        csrf: session.csrf,
        creds,
        save_status: Some(msg),
        error: err,
    }
    .into_response();
    let s = if apply_result.is_err() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    };
    Ok((s, resp).into_response())
}

pub async fn users_delete(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> AdminResult<Response> {
    crate::auth::verify_csrf(&headers, &session).await?;
    let mut creds = load_or_default(&state.paths.credentials_toml)?;
    let before = creds.clients.len();
    creds.clients.retain(|c| c.username != username);
    if creds.clients.len() == before {
        return Err(AdminError::NotFound(format!("user {username}")));
    }
    let serialized = toml::to_string_pretty(&creds).map_err(AdminError::TomlSe)?;
    crate::apply::atomic_write(&state.paths.credentials_toml, &serialized)?;
    apply(&state.paths, ApplyKind::FullRestart)?;
    Ok(Redirect::to("/users").into_response())
}

fn load_or_default(path: &std::path::Path) -> AdminResult<CredentialsToml> {
    match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).map_err(AdminError::TomlDe),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CredentialsToml::default()),
        Err(e) => Err(AdminError::Io(e)),
    }
}


#[derive(Deserialize, Default)]
pub struct UsersForm {
    #[serde(default, deserialize_with = "crate::form::one_or_many")]
    pub username: Vec<String>,
    #[serde(default, deserialize_with = "crate::form::one_or_many")]
    pub password: Vec<String>,
    #[serde(default, deserialize_with = "crate::form::one_or_many")]
    pub max_http2_conns: Vec<String>,
    #[serde(default, deserialize_with = "crate::form::one_or_many")]
    pub max_http3_conns: Vec<String>,
    #[serde(default, deserialize_with = "crate::form::one_or_many")]
    pub max_traffic_bytes: Vec<String>,
}

fn parse_u32(s: String) -> u32 { s.parse().unwrap_or(0) }
fn parse_u64(s: String) -> u64 { s.parse().unwrap_or(0) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_user_form_deserializes() {
        let form: UsersForm =
            serde_urlencoded::from_str("username=alice&password=secret&max_http2_conns=8&max_http3_conns=0&max_traffic_bytes=0")
                .unwrap();
        assert_eq!(form.username, vec!["alice"]);
        assert_eq!(form.password, vec!["secret"]);
    }
}