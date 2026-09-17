use crate::apply::{apply, ApplyKind};
use crate::auth::{verify_csrf_from_form, Authenticated};
use crate::error::{AdminError, AdminResult};
use crate::models::HostsToml;
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "hosts.html")]
pub struct HostsTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub hosts: HostsToml,
    pub save_status: Option<String>,
    pub error: Option<String>,
}

pub async fn hosts_form(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> AdminResult<Response> {
    let content = std::fs::read_to_string(&state.paths.hosts_toml)
        .map_err(AdminError::Io)?;
    let hosts: HostsToml = toml::from_str(&content).map_err(AdminError::TomlDe)?;
    Ok(HostsTemplate {
        title: "TLS hosts".into(),
        username: session.username,
        csrf: session.csrf,
        hosts,
        save_status: None,
        error: None,
    }
    .into_response())
}

pub async fn hosts_save(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let content = std::fs::read_to_string(&state.paths.hosts_toml)?;
    let mut hosts: HostsToml = toml::from_str(&content).map_err(AdminError::TomlDe)?;
    let form: HostsForm = serde_urlencoded::from_str(&body)
        .map_err(|e| AdminError::Validation(format!("invalid form: {e}")))?;
    hosts.main_hosts = form.into_main_hosts();
    let serialized = toml::to_string_pretty(&hosts).map_err(AdminError::TomlSe)?;
    crate::apply::atomic_write(&state.paths.hosts_toml, &serialized)?;
    let apply_result = apply(&state.paths, ApplyKind::Hosts);
    let status = match &apply_result {
        Ok(msg) => msg.clone(),
        Err(e) => format!("save OK but apply failed: {e}"),
    };
    let error = if apply_result.is_err() { Some(status.clone()) } else { None };
    let resp = HostsTemplate {
        title: "TLS hosts".into(),
        username: session.username,
        csrf: session.csrf,
        hosts,
        save_status: Some(status),
        error,
    }
    .into_response();
    let status_code = if apply_result.is_err() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    };
    Ok((status_code, resp).into_response())
}

#[derive(Deserialize, Default)]
pub struct HostsForm {
    #[serde(default, deserialize_with = "crate::form::one_or_many")]
    pub main_hostname: Vec<String>,
    #[serde(default, deserialize_with = "crate::form::one_or_many")]
    pub main_cert: Vec<String>,
    #[serde(default, deserialize_with = "crate::form::one_or_many")]
    pub main_key: Vec<String>,
    #[serde(default, deserialize_with = "crate::form::one_or_many")]
    pub main_allowed_sni: Vec<String>,
}

impl HostsForm {
    pub fn into_main_hosts(self) -> Vec<crate::models::HostEntry> {
        let hostnames = self.main_hostname;
        let certs = self.main_cert;
        let keys = self.main_key;
        let snis = self.main_allowed_sni;
        let len = hostnames.len().max(certs.len()).max(keys.len());
        (0..len)
            .filter_map(|idx| {
                let hostname = hostnames.get(idx).cloned().unwrap_or_default();
                if hostname.is_empty() {
                    return None;
                }
                let cert_chain_path = certs.get(idx).cloned().unwrap_or_default();
                let private_key_path = keys.get(idx).cloned().unwrap_or_default();
                let allowed_sni = snis
                    .get(idx)
                    .map(|s| {
                        s.split(',')
                            .map(|x| x.trim().to_string())
                            .filter(|x| !x.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                Some(crate::models::HostEntry {
                    hostname,
                    cert_chain_path,
                    private_key_path,
                    allowed_sni,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_hostname_saves_as_one_host() {
        let form: HostsForm = serde_urlencoded::from_str(
            "main_hostname=watafa.duckdns.org&main_cert=/certs/fullchain.pem&main_key=/certs/privkey.pem&main_allowed_sni=watafa.duckdns.org",
        )
        .unwrap();
        let hosts = form.into_main_hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "watafa.duckdns.org");
        assert_eq!(hosts[0].allowed_sni, vec!["watafa.duckdns.org"]);
    }

    #[test]
    fn two_hostnames_stay_two_rows() {
        let form: HostsForm = serde_urlencoded::from_str(
            "main_hostname=a.example&main_cert=/a.pem&main_key=/a.key&main_allowed_sni=a.example&main_hostname=b.example&main_cert=/b.pem&main_key=/b.key&main_allowed_sni=b.example",
        )
        .unwrap();
        let hosts = form.into_main_hosts();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[1].hostname, "b.example");
    }
}