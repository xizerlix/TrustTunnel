use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnToml {
    #[serde(default = "default_listen_address")]
    pub listen_address: SocketAddr,
    #[serde(default = "default_true")]
    pub ipv6_available: bool,
    #[serde(default)]
    pub allow_private_network_connections: bool,
    #[serde(default = "default_tls_handshake_timeout")]
    pub tls_handshake_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub limit_inbound_handshakes: bool,
    #[serde(default = "default_max_concurrent_handshakes")]
    pub max_concurrent_inbound_handshakes: u32,
    #[serde(default = "default_client_listener_timeout")]
    pub client_listener_timeout_secs: u64,
    #[serde(default = "default_connection_establishment_timeout")]
    pub connection_establishment_timeout_secs: u64,
    #[serde(default = "default_tcp_connections_timeout")]
    pub tcp_connections_timeout_secs: u64,
    #[serde(default = "default_udp_connections_timeout")]
    pub udp_connections_timeout_secs: u64,
    #[serde(default, skip_serializing_if = "is_empty_option_str")]
    pub credentials_file: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_option_str")]
    pub rules_file: Option<String>,
    #[serde(default)]
    pub speedtest_enable: bool,
    #[serde(default)]
    pub ping_enable: bool,
    #[serde(default = "default_ping_path", skip_serializing_if = "is_empty_option_str")]
    pub ping_path: Option<String>,
    #[serde(default = "default_speedtest_path", skip_serializing_if = "is_empty_option_str")]
    pub speedtest_path: Option<String>,
    #[serde(default = "default_auth_failure_status_code")]
    pub auth_failure_status_code: u16,
    #[serde(default)]
    pub non_connect_auth_failure_status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub default_max_http2_conns_per_client: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub default_max_http3_conns_per_client: u32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub default_max_traffic_bytes_per_client: u64,
    #[serde(default, skip_serializing_if = "is_empty_option_str")]
    pub traffic_usage_file: Option<String>,
    #[serde(default)]
    pub forward_protocol: Option<ForwardProtocolToml>,
    #[serde(default)]
    pub listen_protocols: Option<ListenProtocolsToml>,
    #[serde(default)]
    pub reverse_proxy: Option<ReverseProxyToml>,
    #[serde(default)]
    pub icmp: Option<IcmpToml>,
    #[serde(default)]
    pub metrics: Option<MetricsToml>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectForwarderSettingsToml {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5ForwarderSettingsToml {
    pub address: SocketAddr,
    #[serde(default)]
    pub extended_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardProtocolToml {
    Direct(DirectForwarderSettingsToml),
    Socks5(Socks5ForwarderSettingsToml),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListenProtocolsToml {
    #[serde(default)]
    pub http1: Option<Http1Toml>,
    #[serde(default)]
    pub http2: Option<Http2Toml>,
    #[serde(default)]
    pub quic: Option<QuicToml>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Http1Toml {
    #[serde(default = "default_http1_upload_buffer")]
    pub upload_buffer_size: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Http2Toml {
    #[serde(default = "default_http2_conn_window")]
    pub initial_connection_window_size: u32,
    #[serde(default = "default_http2_stream_window")]
    pub initial_stream_window_size: u32,
    #[serde(default = "default_http2_max_streams")]
    pub max_concurrent_streams: u32,
    #[serde(default = "default_http2_max_frame")]
    pub max_frame_size: u32,
    #[serde(default = "default_http2_header_table")]
    pub header_table_size: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuicToml {
    #[serde(default = "default_udp_payload")]
    pub recv_udp_payload_size: usize,
    #[serde(default = "default_udp_payload")]
    pub send_udp_payload_size: usize,
    #[serde(default = "default_quic_initial_data")]
    pub initial_max_data: u64,
    #[serde(default = "default_quic_initial_stream")]
    pub initial_max_stream_data_bidi_local: u64,
    #[serde(default = "default_quic_initial_stream")]
    pub initial_max_stream_data_bidi_remote: u64,
    #[serde(default = "default_quic_initial_stream")]
    pub initial_max_stream_data_uni: u64,
    #[serde(default = "default_quic_max_streams")]
    pub initial_max_streams_bidi: u64,
    #[serde(default = "default_quic_max_streams")]
    pub initial_max_streams_uni: u64,
    #[serde(default = "default_quic_conn_window")]
    pub max_connection_window: u64,
    #[serde(default = "default_quic_stream_window")]
    pub max_stream_window: u64,
    #[serde(default = "default_true")]
    pub disable_active_migration: bool,
    #[serde(default = "default_true")]
    pub enable_early_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseProxyToml {
    pub server_address: SocketAddr,
    #[serde(default = "default_reverse_proxy_path")]
    pub path_mask: String,
    #[serde(default)]
    pub h3_backward_compatibility: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpToml {
    #[serde(default = "default_iface")]
    pub interface_name: String,
    #[serde(default = "default_icmp_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_queue_capacity")]
    pub recv_message_queue_capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsToml {
    #[serde(default = "default_metrics_addr")]
    pub address: SocketAddr,
    #[serde(default = "default_metrics_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub per_client_metrics: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostsToml {
    #[serde(default, rename = "main_hosts")]
    pub main_hosts: Vec<HostEntry>,
    #[serde(default, rename = "ping_hosts")]
    pub ping_hosts: Vec<HostEntry>,
    #[serde(default, rename = "speedtest_hosts")]
    pub speedtest_hosts: Vec<HostEntry>,
    #[serde(default, rename = "reverse_proxy_hosts")]
    pub reverse_proxy_hosts: Vec<HostEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub hostname: String,
    pub cert_chain_path: String,
    pub private_key_path: String,
    #[serde(default, skip_serializing_if = "is_empty_vec")]
    pub allowed_sni: Vec<String>,
}

impl HostEntry {
    pub fn sni_text(&self) -> String {
        self.allowed_sni.join("\n")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEntry {
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_http2_conns: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_http3_conns: u32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub max_traffic_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialsToml {
    #[serde(default, rename = "client")]
    pub clients: Vec<ClientEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub client_random_prefix: Option<String>,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesToml {
    #[serde(default, rename = "rule")]
    pub rules: Vec<RuleEntry>,
}

fn default_listen_address() -> SocketAddr {
    "0.0.0.0:443".parse().unwrap()
}
fn default_true() -> bool { true }
fn default_tls_handshake_timeout() -> u64 { 10 }
fn default_max_concurrent_handshakes() -> u32 { 32 }
fn default_client_listener_timeout() -> u64 { 600 }
fn default_connection_establishment_timeout() -> u64 { 30 }
fn default_tcp_connections_timeout() -> u64 { 7200 }
fn default_udp_connections_timeout() -> u64 { 300 }
fn default_ping_path() -> Option<String> { Some("/ping".into()) }
fn default_speedtest_path() -> Option<String> { Some("/speedtest".into()) }
fn default_auth_failure_status_code() -> u16 { 407 }
fn default_http1_upload_buffer() -> usize { 64 * 1024 }
fn default_http2_conn_window() -> u32 { 8 * 1024 * 1024 }
fn default_http2_stream_window() -> u32 { 128 * 1024 }
fn default_http2_max_streams() -> u32 { 1000 }
fn default_http2_max_frame() -> u32 { 1 << 14 }
fn default_http2_header_table() -> u32 { 65536 }
fn default_udp_payload() -> usize { 1350 }
fn default_quic_initial_data() -> u64 { 100 * 1024 * 1024 }
fn default_quic_initial_stream() -> u64 { 1024 * 1024 }
fn default_quic_max_streams() -> u64 { 4 * 1024 }
fn default_quic_conn_window() -> u64 { 24 * 1024 * 1024 }
fn default_quic_stream_window() -> u64 { 16 * 1024 * 1024 }
fn default_reverse_proxy_path() -> String { "/".into() }
fn default_iface() -> String {
    if cfg!(target_os = "linux") { "eth0".into() } else { "en0".into() }
}
fn default_icmp_timeout() -> u64 { 3 }
fn default_queue_capacity() -> usize { 256 }
fn default_metrics_addr() -> SocketAddr {
    "127.0.0.1:1987".parse().unwrap()
}
fn default_metrics_timeout() -> u64 { 3 }

fn is_zero_u32(v: &u32) -> bool { *v == 0 }
fn is_zero_u64(v: &u64) -> bool { *v == 0 }
fn is_empty_option_str(v: &Option<String>) -> bool {
    v.as_ref().map(|s| s.is_empty()).unwrap_or(true)
}
fn is_empty_vec<T>(v: &Vec<T>) -> bool { v.is_empty() }

impl VpnToml {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(s)?)
    }
    pub fn to_string_pretty(&self) -> anyhow::Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_text_joins_lines() {
        let h = HostEntry {
            hostname: "a.example".into(),
            cert_chain_path: "/c".into(),
            private_key_path: "/k".into(),
            allowed_sni: vec!["a.example".into(), "front.example".into()],
        };
        assert_eq!(h.sni_text(), "a.example\nfront.example");
    }
}

#[allow(dead_code)]
fn _unused() -> IpAddr { "127.0.0.1".parse().unwrap() }