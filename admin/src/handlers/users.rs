use crate::apply::{apply, ApplyKind};
use crate::auth::{verify_csrf_from_form, Authenticated};
use crate::error::{AdminError, AdminResult};
use crate::form::{bytes_to_gib_field, form_col, form_lists, gib_field_to_bytes};
use crate::i18n::{self, I18n};
use crate::models::{ClientEntry, CredentialsToml, HostsToml, VpnToml};
use crate::state::AppState;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Serialize;

#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub t: I18n,
    pub lang: &'static str,
    pub rows: Vec<UserEditRow>,
    pub save_status: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct UserEditRow {
    pub username: String,
    pub max_http2_conns: String,
    pub max_http3_conns: String,
    pub max_traffic_gb: String,
}

fn rows_from(creds: &CredentialsToml) -> Vec<UserEditRow> {
    creds
        .clients
        .iter()
        .map(|c| UserEditRow {
            username: c.username.clone(),
            max_http2_conns: if c.max_http2_conns > 0 {
                c.max_http2_conns.to_string()
            } else {
                String::new()
            },
            max_http3_conns: if c.max_http3_conns > 0 {
                c.max_http3_conns.to_string()
            } else {
                String::new()
            },
            max_traffic_gb: bytes_to_gib_field(c.max_traffic_bytes),
        })
        .collect()
}

fn page(
    session: &crate::auth::Session,
    headers: &HeaderMap,
    creds: &CredentialsToml,
    save_status: Option<String>,
    error: Option<String>,
) -> UsersTemplate {
    let lang = i18n::from_headers(headers);
    let t = i18n::t(lang);
    UsersTemplate {
        title: t.users.into(),
        username: session.username.clone(),
        csrf: session.csrf.clone(),
        t,
        lang: lang.as_str(),
        rows: rows_from(creds),
        save_status,
        error,
    }
}

pub async fn users_form(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> AdminResult<Response> {
    let creds = load_or_default(&state.paths.credentials_toml)?;
    Ok(page(&session, &headers, &creds, None, None).into_response())
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
    let map = form_lists(&body);
    let names = form_col(&map, "username");
    let passwords = form_col(&map, "password");
    let h2 = form_col(&map, "max_http2_conns");
    let h3 = form_col(&map, "max_http3_conns");
    let gb = form_col(&map, "max_traffic_gb");

    creds.clients.clear();
    for (i, name) in names.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        let password = passwords.get(i).cloned().unwrap_or_default();
        let existing = existing_clients.iter().find(|c| c.username == *name);
        let password = if password.is_empty() {
            match existing {
                Some(c) => c.password.clone(),
                None => {
                    return Ok(page(
                        &session,
                        &headers,
                        &CredentialsToml {
                            clients: existing_clients,
                        },
                        None,
                        Some(format!("password is required for user {name}")),
                    )
                    .into_response());
                }
            }
        } else {
            password
        };
        creds.clients.push(ClientEntry {
            username: name.clone(),
            password,
            max_http2_conns: h2.get(i).cloned().unwrap_or_default().parse().unwrap_or(0),
            max_http3_conns: h3.get(i).cloned().unwrap_or_default().parse().unwrap_or(0),
            max_traffic_bytes: gib_field_to_bytes(gb.get(i).map(|s| s.as_str()).unwrap_or("")),
        });
    }
    let serialized = toml::to_string_pretty(&creds).map_err(AdminError::TomlSe)?;
    crate::apply::atomic_write(&state.paths.credentials_toml, &serialized)?;
    let t = i18n::t(i18n::from_headers(&headers));
    let apply_result = apply(&state.paths, ApplyKind::FullRestart);
    let msg = crate::apply::format_apply(&t, &apply_result);
    let err = if apply_result.is_err() {
        Some(msg.clone())
    } else {
        None
    };
    let resp = page(&session, &headers, &creds, Some(msg), err).into_response();
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
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let map = form_lists(&body);
    let username = form_col(&map, "username")
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    if username.is_empty() {
        return Err(AdminError::Validation("username required".into()));
    }
    let mut creds = load_or_default(&state.paths.credentials_toml)?;
    let before = creds.clients.len();
    creds.clients.retain(|c| c.username != username);
    if creds.clients.len() == before {
        return Err(AdminError::NotFound(format!("user {username}")));
    }
    let serialized = toml::to_string_pretty(&creds).map_err(AdminError::TomlSe)?;
    crate::apply::atomic_write(&state.paths.credentials_toml, &serialized)?;
    let t = i18n::t(i18n::from_headers(&headers));
    let apply_result = apply(&state.paths, ApplyKind::FullRestart);
    if apply_result.is_err() {
        let msg = crate::apply::format_apply(&t, &apply_result);
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            page(&session, &headers, &creds, Some(msg.clone()), Some(msg)),
        )
            .into_response());
    }
    Ok(Redirect::to("/users").into_response())
}

#[derive(Serialize)]
pub struct DeeplinkJson {
    pub url: String,
}

pub async fn users_deeplink(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> AdminResult<Response> {
    crate::auth::verify_csrf(&headers, &session).await?;
    let creds = load_or_default(&state.paths.credentials_toml)?;
    let user = creds
        .clients
        .iter()
        .find(|c| c.username == username)
        .ok_or_else(|| AdminError::NotFound(format!("user {username}")))?;
    let hosts: HostsToml = toml::from_str(&std::fs::read_to_string(&state.paths.hosts_toml)?)?;
    let host = hosts
        .main_hosts
        .first()
        .ok_or_else(|| AdminError::Apply("no main host".into()))?;
    let vpn = VpnToml::from_str(&std::fs::read_to_string(&state.paths.vpn_toml)?)
        .map_err(|e| AdminError::Apply(e.to_string()))?;
    let addr = format!("{}:{}", host.hostname, vpn.listen_address.port());
    let cfg = trusttunnel_deeplink::DeepLinkConfig {
        hostname: host.hostname.clone(),
        addresses: vec![addr],
        username: user.username.clone(),
        password: user.password.clone(),
        client_random_prefix: None,
        custom_sni: None,
        has_ipv6: vpn.ipv6_available,
        skip_verification: false,
        certificate: None,
        upstream_protocol: trusttunnel_deeplink::Protocol::Http2,
        anti_dpi: false,
        name: Some(host.hostname.clone()),
        dns_upstreams: Vec::new(),
    };
    let url = trusttunnel_deeplink::encode(&cfg)
        .map_err(|e| AdminError::Apply(e.to_string()))?;
    Ok(Json(DeeplinkJson { url }).into_response())
}

fn load_or_default(path: &std::path::Path) -> AdminResult<CredentialsToml> {
    match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).map_err(AdminError::TomlDe),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CredentialsToml::default()),
        Err(e) => Err(AdminError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_users_parse() {
        let map = form_lists(
            "username=alice&password=secret&max_http2_conns=8&max_http3_conns=0&max_traffic_gb=1&username=test&password=pw&max_http2_conns=0&max_http3_conns=0&max_traffic_gb=",
        );
        assert_eq!(form_col(&map, "username"), vec!["alice", "test"]);
        assert_eq!(gib_field_to_bytes(&form_col(&map, "max_traffic_gb")[0]), 1_073_741_824);
        assert_eq!(gib_field_to_bytes(&form_col(&map, "max_traffic_gb")[1]), 0);
    }
}
