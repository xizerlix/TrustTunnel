use crate::apply::{apply, ApplyKind};
use crate::auth::{verify_csrf_from_form, Authenticated};
use crate::error::{AdminError, AdminResult};
use crate::form::{form_col, form_lists};
use crate::i18n::{self, I18n};
use crate::models::HostsToml;
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

#[derive(Template)]
#[template(path = "hosts.html")]
pub struct HostsTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub t: I18n,
    pub lang: &'static str,
    pub hosts: HostsToml,
    pub save_status: Option<String>,
    pub error: Option<String>,
}

fn page(
    session: &crate::auth::Session,
    headers: &HeaderMap,
    hosts: HostsToml,
    save_status: Option<String>,
    error: Option<String>,
) -> HostsTemplate {
    let lang = i18n::from_headers(headers);
    let t = i18n::t(lang);
    HostsTemplate {
        title: t.tls_hosts.into(),
        username: session.username.clone(),
        csrf: session.csrf.clone(),
        t,
        lang: lang.as_str(),
        hosts,
        save_status,
        error,
    }
}

pub async fn hosts_form(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> AdminResult<Response> {
    let content = std::fs::read_to_string(&state.paths.hosts_toml).map_err(AdminError::Io)?;
    let hosts: HostsToml = toml::from_str(&content).map_err(AdminError::TomlDe)?;
    Ok(page(&session, &headers, hosts, None, None).into_response())
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
    let map = form_lists(&body);
    let form = HostsForm {
        main_hostname: form_col(&map, "main_hostname"),
        main_cert: form_col(&map, "main_cert"),
        main_key: form_col(&map, "main_key"),
        main_allowed_sni: form_col(&map, "main_allowed_sni"),
    };
    hosts.main_hosts = form.into_main_hosts();
    let serialized = toml::to_string_pretty(&hosts).map_err(AdminError::TomlSe)?;
    crate::apply::atomic_write(&state.paths.hosts_toml, &serialized)?;
    let apply_result = apply(&state.paths, ApplyKind::Hosts);
    let status = match &apply_result {
        Ok(msg) => msg.clone(),
        Err(e) => format!("save OK but apply failed: {e}"),
    };
    let error = if apply_result.is_err() {
        Some(status.clone())
    } else {
        None
    };
    let resp = page(&session, &headers, hosts, Some(status), error).into_response();
    let status_code = if apply_result.is_err() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    };
    Ok((status_code, resp).into_response())
}

#[derive(Default)]
pub struct HostsForm {
    pub main_hostname: Vec<String>,
    pub main_cert: Vec<String>,
    pub main_key: Vec<String>,
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
                        s.split(|c: char| c == ',' || c == '\n' || c == '\r')
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
        let form = HostsForm {
            main_hostname: vec!["watafa.duckdns.org".into()],
            main_cert: vec!["/certs/fullchain.pem".into()],
            main_key: vec!["/certs/privkey.pem".into()],
            main_allowed_sni: vec!["watafa.duckdns.org\nalias.example".into()],
        };
        let hosts = form.into_main_hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "watafa.duckdns.org");
        assert_eq!(
            hosts[0].allowed_sni,
            vec!["watafa.duckdns.org", "alias.example"]
        );
    }

    #[test]
    fn two_hostnames_stay_two_rows() {
        let form = HostsForm {
            main_hostname: vec!["a.example".into(), "b.example".into()],
            main_cert: vec!["/a.pem".into(), "/b.pem".into()],
            main_key: vec!["/a.key".into(), "/b.key".into()],
            main_allowed_sni: vec!["a.example".into(), "b.example".into()],
        };
        let hosts = form.into_main_hosts();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[1].hostname, "b.example");
    }
}