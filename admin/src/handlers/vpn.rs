use crate::apply::{apply, ApplyKind};
use crate::auth::{verify_csrf_from_form, Authenticated};
use crate::error::{AdminError, AdminResult};
use crate::models::VpnToml;
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "vpn.html")]
pub struct VpnTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub vpn: VpnToml,
    pub save_status: Option<String>,
    pub error: Option<String>,
}

pub async fn vpn_form(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> AdminResult<Response> {
    let content = std::fs::read_to_string(&state.paths.vpn_toml)
        .map_err(|e| AdminError::Io(e))?;
    let vpn: VpnToml =
        toml::from_str(&content).map_err(AdminError::TomlDe)?;
    Ok(VpnTemplate {
        title: "VPN settings".into(),
        username: session.username,
        csrf: session.csrf,
        vpn,
        save_status: None,
        error: None,
    }
    .into_response())
}

pub async fn vpn_save(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let form: VpnForm = serde_urlencoded::from_str(&body)
        .map_err(|e| AdminError::Validation(format!("invalid form: {e}")))?;

    let mut vpn = VpnToml::from_str(&std::fs::read_to_string(&state.paths.vpn_toml)?)?;

    apply_form(&mut vpn, &form)?;

    let serialized = vpn.to_string_pretty()?;
    crate::apply::atomic_write(&state.paths.vpn_toml, &serialized)?;
    let result = apply(&state.paths, ApplyKind::FullRestart);

    let status = match &result {
        Ok(msg) => msg.clone(),
        Err(e) => format!("save OK but apply failed: {e}"),
    };
    let error = if result.is_err() {
        Some(status.clone())
    } else {
        None
    };

    Ok(VpnTemplate {
        title: "VPN settings".into(),
        username: session.username,
        csrf: session.csrf,
        vpn,
        save_status: Some(status),
        error,
    }
    .into_response()
        .with_status(if result.is_err() {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::OK
        }))
}

use crate::error::WithStatusExt;

#[derive(Deserialize, Default)]
pub struct VpnForm {
    pub listen_address: Option<String>,
    pub ipv6_available: Option<String>,
    pub allow_private_network_connections: Option<String>,
    pub tls_handshake_timeout_secs: Option<String>,
    pub limit_inbound_handshakes: Option<String>,
    pub max_concurrent_inbound_handshakes: Option<String>,
    pub client_listener_timeout_secs: Option<String>,
    pub connection_establishment_timeout_secs: Option<String>,
    pub tcp_connections_timeout_secs: Option<String>,
    pub udp_connections_timeout_secs: Option<String>,
    pub credentials_file: Option<String>,
    pub rules_file: Option<String>,
    pub speedtest_enable: Option<String>,
    pub ping_enable: Option<String>,
    pub ping_path: Option<String>,
    pub speedtest_path: Option<String>,
    pub auth_failure_status_code: Option<String>,
    pub non_connect_auth_failure_status_code: Option<String>,
    pub default_max_http2_conns_per_client: Option<String>,
    pub default_max_http3_conns_per_client: Option<String>,
    pub default_max_traffic_bytes_per_client: Option<String>,
    pub traffic_usage_file: Option<String>,
}

fn parse_u64(s: Option<String>) -> u64 {
    s.as_deref().and_then(|v| v.parse().ok()).unwrap_or(0)
}
fn parse_u32(s: Option<String>) -> u32 {
    s.as_deref().and_then(|v| v.parse().ok()).unwrap_or(0)
}
fn parse_u16(s: Option<String>) -> u16 {
    s.as_deref().and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn parse_bool(s: Option<&str>) -> Option<bool> {
    s.map(|v| v == "on" || v == "true" || v == "1")
}

fn parse_optional_string(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

pub fn apply_form(vpn: &mut VpnToml, form: &VpnForm) -> AdminResult<()> {
    if let Some(s) = &form.listen_address {
        if !s.is_empty() {
            vpn.listen_address = s.parse().map_err(|e: std::net::AddrParseError| {
                AdminError::Validation(format!("listen_address: {e}"))
            })?;
        }
    }
    if let Some(b) = parse_bool(form.ipv6_available.as_deref()) {
        vpn.ipv6_available = b;
    }
    if let Some(b) = parse_bool(form.allow_private_network_connections.as_deref()) {
        vpn.allow_private_network_connections = b;
    }
    let v = parse_u64(form.tls_handshake_timeout_secs.clone());
    if v != 0 { vpn.tls_handshake_timeout_secs = v; }
    if let Some(b) = parse_bool(form.limit_inbound_handshakes.as_deref()) {
        vpn.limit_inbound_handshakes = b;
    }
    let h = parse_u32(form.max_concurrent_inbound_handshakes.clone()).max(1);
    vpn.max_concurrent_inbound_handshakes = h;
    vpn.client_listener_timeout_secs = parse_u64(form.client_listener_timeout_secs.clone()).max(60);
    vpn.connection_establishment_timeout_secs = parse_u64(form.connection_establishment_timeout_secs.clone()).max(1);
    vpn.tcp_connections_timeout_secs = parse_u64(form.tcp_connections_timeout_secs.clone()).max(60);
    vpn.udp_connections_timeout_secs = parse_u64(form.udp_connections_timeout_secs.clone()).max(60);
    vpn.credentials_file = parse_optional_string(form.credentials_file.clone());
    vpn.rules_file = parse_optional_string(form.rules_file.clone());
    if let Some(b) = parse_bool(form.speedtest_enable.as_deref()) {
        vpn.speedtest_enable = b;
    }
    if let Some(b) = parse_bool(form.ping_enable.as_deref()) {
        vpn.ping_enable = b;
    }
    vpn.ping_path = parse_optional_string(form.ping_path.clone());
    vpn.speedtest_path = parse_optional_string(form.speedtest_path.clone());
    let code = parse_u16(form.auth_failure_status_code.clone());
    if code != 0 { vpn.auth_failure_status_code = code; }
    vpn.non_connect_auth_failure_status_code = form
        .non_connect_auth_failure_status_code
        .as_deref()
        .and_then(|v| v.parse().ok());
    vpn.default_max_http2_conns_per_client = parse_u32(form.default_max_http2_conns_per_client.clone());
    vpn.default_max_http3_conns_per_client = parse_u32(form.default_max_http3_conns_per_client.clone());
    vpn.default_max_traffic_bytes_per_client = parse_u64(form.default_max_traffic_bytes_per_client.clone());
    vpn.traffic_usage_file = parse_optional_string(form.traffic_usage_file.clone());
    Ok(())
}