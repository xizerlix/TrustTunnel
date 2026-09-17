use crate::apply::{read_clients_json, read_prometheus_metrics, systemctl_show};
use crate::auth::Authenticated;
use crate::models::{CredentialsToml, VpnToml};
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub service_active: bool,
    pub service_label: String,
    pub since_label: Option<String>,
    pub clients_count: usize,
    pub session_total: u64,
    pub unique_ips: usize,
    pub traffic_inbound_h: String,
    pub traffic_outbound_h: String,
    pub traffic_total_h: String,
    pub users: Vec<UserRow>,
}

#[derive(Template)]
#[template(path = "dashboard_data.html")]
pub struct DashboardDataTemplate {
    pub service_active: bool,
    pub service_label: String,
    pub since_label: Option<String>,
    pub clients_count: usize,
    pub session_total: u64,
    pub unique_ips: usize,
    pub traffic_inbound_h: String,
    pub traffic_outbound_h: String,
    pub traffic_total_h: String,
    pub users: Vec<UserRow>,
}

#[derive(Clone)]
pub struct UserRow {
    pub username: String,
    pub active: bool,
    pub sessions: u64,
    pub ips_label: String,
    pub total_h: String,
    pub quota_limit_h: String,
    pub quota_used_pct: u8,
    pub quota_exceeded: bool,
}

#[derive(Deserialize, Default, Clone)]
struct UsageUser {
    #[serde(default)]
    inbound: u64,
    #[serde(default)]
    outbound: u64,
}

#[derive(Clone, Default)]
struct LiveClient {
    username: String,
    sessions: u64,
    inbound: u64,
    outbound: u64,
    ips: Vec<String>,
    quota_exceeded: bool,
    limit: Option<u64>,
}

pub fn humanize(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{:.2} {}", v, UNITS[i])
    }
}

pub fn humanize_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m")
    } else {
        format!("{secs}s")
    }
}

pub struct ServiceStatus {
    pub active: bool,
    pub label: String,
    pub since_label: Option<String>,
}

pub fn parse_systemctl_show(show: &str, now: SystemTime) -> ServiceStatus {
    let mut active_state = String::new();
    let mut active_enter_us: u64 = 0;
    let mut inactive_enter_us: u64 = 0;
    for line in show.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "ActiveState" => active_state = v.trim().to_string(),
                "ActiveEnterTimestampUSec" => {
                    active_enter_us = v.trim().parse().unwrap_or(0);
                }
                "InactiveEnterTimestampUSec" => {
                    inactive_enter_us = v.trim().parse().unwrap_or(0);
                }
                _ => {}
            }
        }
    }
    let active = active_state == "active";
    let label = if active_state.is_empty() {
        "unknown".into()
    } else {
        active_state.clone()
    };
    let since_label = if active {
        duration_since_usec(now, active_enter_us).map(|d| format!("up {}", humanize_duration(d)))
    } else {
        duration_since_usec(now, inactive_enter_us).map(|d| format!("down {}", humanize_duration(d)))
    };
    ServiceStatus {
        active,
        label,
        since_label,
    }
}

fn duration_since_usec(now: SystemTime, usec: u64) -> Option<Duration> {
    if usec == 0 {
        return None;
    }
    let then = UNIX_EPOCH.checked_add(Duration::from_micros(usec))?;
    now.duration_since(then).ok()
}

pub fn parse_live_clients(live_json: &Value) -> Vec<LiveClient> {
    let empty = Vec::new();
    let arr = match live_json {
        Value::Array(arr) => arr,
        Value::Object(obj) => obj
            .get("clients")
            .or_else(|| obj.get("users"))
            .and_then(Value::as_array)
            .unwrap_or(&empty),
        _ => &empty,
    };
    arr.iter().filter_map(parse_one_client).collect()
}

fn parse_one_client(v: &Value) -> Option<LiveClient> {
    let obj = v.as_object()?;
    let username = obj.get("username")?.as_str()?.to_string();
    let sessions = json_u64(obj.get("sessions"));
    let mut inbound = json_u64(obj.get("inbound"));
    let mut outbound = json_u64(obj.get("outbound"));
    let total = json_u64(obj.get("total"));
    if inbound == 0 && outbound == 0 && total > 0 {
        inbound = total;
    }
    let quota_exceeded = obj
        .get("quota_exceeded")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let limit = obj.get("limit").and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
    });
    let mut ips: Vec<String> = Vec::new();
    if let Some(arr) = obj.get("ips").and_then(Value::as_array) {
        for item in arr {
            if let Some(s) = item.as_str() {
                if !s.is_empty() {
                    ips.push(s.to_string());
                }
            } else if let Some(address) = item.get("address").and_then(Value::as_str) {
                if !address.is_empty() {
                    ips.push(address.to_string());
                }
            }
        }
    }
    if ips.is_empty() {
        if let Some(ip) = obj.get("ip").and_then(Value::as_str) {
            if !ip.is_empty() {
                ips.push(ip.to_string());
            }
        }
    }
    Some(LiveClient {
        username,
        sessions,
        inbound,
        outbound,
        ips,
        quota_exceeded,
        limit,
    })
}

fn json_u64(v: Option<&Value>) -> u64 {
    let Some(v) = v else {
        return 0;
    };
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

pub fn parse_user_traffic_from_prometheus(text: &str) -> HashMap<String, (u64, u64)> {
    let mut inbound: HashMap<String, u64> = HashMap::new();
    let mut outbound: HashMap<String, u64> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let is_in = line.starts_with("inbound_traffic_bytes_per_user{");
        let is_out = line.starts_with("outbound_traffic_bytes_per_user{");
        if !is_in && !is_out {
            continue;
        }
        let Some(brace) = line.find('}') else {
            continue;
        };
        let labels = &line[line.find('{').unwrap_or(0) + 1..brace];
        let Some(rest) = line.get(brace + 1..) else {
            continue;
        };
        let value: u64 = rest.trim().parse().unwrap_or(0);
        let mut username = None;
        for part in labels.split(',') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("username=\"") {
                username = Some(v.trim_end_matches('"').to_string());
            }
        }
        if let Some(u) = username.filter(|s| !s.is_empty()) {
            if is_in {
                *inbound.entry(u).or_insert(0) += value;
            } else {
                *outbound.entry(u).or_insert(0) += value;
            }
        }
    }
    let mut out = HashMap::new();
    let mut names: BTreeSet<String> = inbound.keys().cloned().collect();
    names.extend(outbound.keys().cloned());
    for name in names {
        out.insert(
            name.clone(),
            (
                inbound.get(&name).copied().unwrap_or(0),
                outbound.get(&name).copied().unwrap_or(0),
            ),
        );
    }
    out
}

pub fn parse_session_total_from_prometheus(text: &str) -> u64 {
    let mut total = 0u64;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.starts_with("client_sessions{") {
            continue;
        }
        let Some(value) = line.rsplit(' ').next() else {
            continue;
        };
        total = total.saturating_add(value.parse().unwrap_or(0));
    }
    total
}

pub fn parse_sessions_from_prometheus(text: &str) -> HashMap<String, u64> {
    let mut out: HashMap<String, u64> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.starts_with("client_sessions_per_user{") {
            continue;
        }
        let Some(brace) = line.find('}') else {
            continue;
        };
        let labels = &line[line.find('{').unwrap_or(0) + 1..brace];
        let Some(rest) = line.get(brace + 1..) else {
            continue;
        };
        let value: u64 = rest.trim().parse().unwrap_or(0);
        let mut username = None;
        for part in labels.split(',') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("username=\"") {
                username = Some(v.trim_end_matches('"').to_string());
            }
        }
        if let Some(u) = username.filter(|s| !s.is_empty()) {
            *out.entry(u).or_insert(0) += value;
        }
    }
    out
}

fn load_usage_map(path: &Path) -> HashMap<String, UsageUser> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| parse_usage_toml(&s))
        .unwrap_or_default()
}

fn parse_usage_toml(s: &str) -> HashMap<String, UsageUser> {
    let Ok(value) = s.parse::<toml::Value>() else {
        return HashMap::new();
    };
    let Some(table) = value.as_table() else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (name, v) in table {
        if name == "clients" {
            if let Some(inner) = v.as_table() {
                for (user, rec) in inner {
                    out.insert(user.clone(), usage_from_value(rec));
                }
            }
            continue;
        }
        out.insert(name.clone(), usage_from_value(v));
    }
    out
}

fn usage_from_value(v: &toml::Value) -> UsageUser {
    UsageUser {
        inbound: toml_u64(v.get("inbound")),
        outbound: toml_u64(v.get("outbound")),
    }
}

fn toml_u64(v: Option<&toml::Value>) -> u64 {
    let Some(v) = v else {
        return 0;
    };
    v.as_integer()
        .and_then(|n| u64::try_from(n).ok())
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

fn join_usage_path(root: &Path, p: &str) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn traffic_usage_path(root: &Path, vpn: &VpnToml) -> PathBuf {
    match vpn.traffic_usage_file.as_deref() {
        Some(p) if !p.is_empty() => join_usage_path(root, p),
        _ => root.join("traffic_usage.toml"),
    }
}

fn resolve_usage_path(root: &Path, vpn_text: Option<&str>) -> PathBuf {
    let Some(text) = vpn_text else {
        return root.join("traffic_usage.toml");
    };
    if let Some(p) = crate::paths::parse_traffic_usage_file(text) {
        return join_usage_path(root, &p);
    }
    match VpnToml::from_str(text) {
        Ok(v) => traffic_usage_path(root, &v),
        Err(_) => root.join("traffic_usage.toml"),
    }
}

struct Stats {
    service_active: bool,
    service_label: String,
    since_label: Option<String>,
    clients_count: usize,
    session_total: u64,
    unique_ips: usize,
    traffic_inbound_h: String,
    traffic_outbound_h: String,
    traffic_total_h: String,
    users: Vec<UserRow>,
}

async fn collect(state: &AppState) -> Stats {
    let show = systemctl_show(&state.paths.service_name).unwrap_or_default();
    let svc = parse_systemctl_show(&show, SystemTime::now());

    let live_json = read_clients_json(&state.paths.metrics_address).ok();
    let mut live_list = live_json
        .as_ref()
        .map(parse_live_clients)
        .unwrap_or_default();

    let prom = read_prometheus_metrics(&state.paths.metrics_address).ok();
    if live_list.iter().all(|c| c.sessions == 0) {
        if let Some(prom) = prom.as_deref() {
            let by_user = parse_sessions_from_prometheus(prom);
            if !by_user.is_empty() {
                for (username, sessions) in by_user {
                    if let Some(c) = live_list.iter_mut().find(|c| c.username == username) {
                        c.sessions = sessions;
                    } else {
                        live_list.push(LiveClient {
                            username,
                            sessions,
                            ..LiveClient::default()
                        });
                    }
                }
            }
        }
    }
    if let Some(prom) = prom.as_deref() {
        for (username, (inbound, outbound)) in parse_user_traffic_from_prometheus(prom) {
            if let Some(c) = live_list.iter_mut().find(|c| c.username == username) {
                c.inbound = c.inbound.max(inbound);
                c.outbound = c.outbound.max(outbound);
            } else {
                live_list.push(LiveClient {
                    username,
                    inbound,
                    outbound,
                    ..LiveClient::default()
                });
            }
        }
    }

    let vpn_text = std::fs::read_to_string(&state.paths.vpn_toml).ok();
    let vpn = vpn_text.as_deref().and_then(|s| VpnToml::from_str(s).ok());
    let usage_path = resolve_usage_path(&state.paths.root, vpn_text.as_deref());
    let usage = load_usage_map(&usage_path);

    let mut by_user: HashMap<String, LiveClient> = HashMap::new();
    let mut all_ips: BTreeSet<String> = BTreeSet::new();
    let mut session_total: u64 = 0;
    for c in live_list {
        session_total = session_total.saturating_add(c.sessions);
        for ip in &c.ips {
            all_ips.insert(ip.clone());
        }
        by_user.insert(c.username.clone(), c);
    }

    let creds = std::fs::read_to_string(&state.paths.credentials_toml)
        .ok()
        .and_then(|s| toml::from_str::<CredentialsToml>(&s).ok())
        .unwrap_or_default();

    let mut all_user_names: Vec<String> = Vec::new();
    for c in &creds.clients {
        if !all_user_names.contains(&c.username) {
            all_user_names.push(c.username.clone());
        }
    }
    for u in by_user.keys() {
        if !all_user_names.contains(u) {
            all_user_names.push(u.clone());
        }
    }
    for u in usage.keys() {
        if !all_user_names.contains(u) {
            all_user_names.push(u.clone());
        }
    }

    let default_limit = vpn
        .as_ref()
        .map(|v| v.default_max_traffic_bytes_per_client)
        .unwrap_or(0);

    let mut users: Vec<UserRow> = Vec::new();
    for username in all_user_names {
        let live = by_user.get(&username);
        let sessions = live.map(|c| c.sessions).unwrap_or(0);
        let ips_label = live
            .map(|c| {
                if c.ips.is_empty() {
                    "—".into()
                } else {
                    c.ips.join(", ")
                }
            })
            .unwrap_or_else(|| "—".into());
        let active = sessions > 0
            || live
                .map(|c| !c.ips.is_empty())
                .unwrap_or(false);
        let u_usage = usage.get(&username).cloned().unwrap_or_default();
        let mut total_bytes = u_usage.inbound.saturating_add(u_usage.outbound);
        if let Some(c) = live {
            total_bytes = total_bytes.max(c.inbound.saturating_add(c.outbound));
        }

        let mut quota_limit = 0u64;
        if let Some(c) = creds.clients.iter().find(|c| c.username == username) {
            quota_limit = c.max_traffic_bytes;
        }
        if quota_limit == 0 {
            quota_limit = default_limit;
        }
        if let Some(c) = live {
            if let Some(limit) = c.limit {
                if limit > 0 {
                    quota_limit = limit;
                }
            }
        }

        let mut quota_limit_h = "∞".to_string();
        let mut quota_used_pct: u8 = 0;
        let mut quota_exceeded = live.map(|c| c.quota_exceeded).unwrap_or(false);
        if quota_limit > 0 {
            quota_limit_h = humanize(quota_limit);
            quota_used_pct =
                ((total_bytes as f64 / quota_limit as f64) * 100.0).clamp(0.0, 100.0) as u8;
            quota_exceeded = quota_exceeded || total_bytes > quota_limit;
        }

        users.push(UserRow {
            username,
            active,
            sessions,
            ips_label,
            total_h: humanize(total_bytes),
            quota_limit_h,
            quota_used_pct,
            quota_exceeded,
        });
    }
    users.sort_by(|a, b| {
        if a.active == b.active {
            a.username.cmp(&b.username)
        } else if a.active {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });

    if session_total == 0 {
        if let Ok(prom) = read_prometheus_metrics(&state.paths.metrics_address) {
            session_total = parse_session_total_from_prometheus(&prom);
        }
    }

    let clients_count = users.iter().filter(|u| u.active).count();
    let total_in = usage.values().map(|u| u.inbound).sum::<u64>();
    let total_out = usage.values().map(|u| u.outbound).sum::<u64>();
    let live_in: u64 = by_user.values().map(|c| c.inbound).sum();
    let live_out: u64 = by_user.values().map(|c| c.outbound).sum();
    let total_in = total_in.max(live_in);
    let total_out = total_out.max(live_out);
    let total_combined = total_in.saturating_add(total_out);

    Stats {
        service_active: svc.active,
        service_label: svc.label,
        since_label: svc.since_label,
        clients_count,
        session_total,
        unique_ips: all_ips.len(),
        traffic_inbound_h: humanize(total_in),
        traffic_outbound_h: humanize(total_out),
        traffic_total_h: humanize(total_combined),
        users,
    }
}

fn fill_data(stats: Stats) -> DashboardDataTemplate {
    DashboardDataTemplate {
        service_active: stats.service_active,
        service_label: stats.service_label,
        since_label: stats.since_label,
        clients_count: stats.clients_count,
        session_total: stats.session_total,
        unique_ips: stats.unique_ips,
        traffic_inbound_h: stats.traffic_inbound_h,
        traffic_outbound_h: stats.traffic_outbound_h,
        traffic_total_h: stats.traffic_total_h,
        users: stats.users,
    }
}

pub async fn dashboard(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> Response {
    let stats = collect(&state).await;
    let data = fill_data(stats);
    DashboardTemplate {
        title: "Dashboard".into(),
        username: session.username,
        csrf: session.csrf,
        service_active: data.service_active,
        service_label: data.service_label,
        since_label: data.since_label,
        clients_count: data.clients_count,
        session_total: data.session_total,
        unique_ips: data.unique_ips,
        traffic_inbound_h: data.traffic_inbound_h,
        traffic_outbound_h: data.traffic_outbound_h,
        traffic_total_h: data.traffic_total_h,
        users: data.users,
    }
    .into_response()
}

pub async fn dashboard_data(
    State(state): State<AppState>,
    Authenticated(_session): Authenticated,
) -> Response {
    let stats = collect(&state).await;
    fill_data(stats).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn live_clients_accept_ip_objects() {
        let v = json!([{
            "username": "alice",
            "sessions": 3,
            "inbound": 10,
            "outbound": 20,
            "ips": [{"address": "1.2.3.4", "tag": "#ip_1_2_3_4"}],
            "quota_exceeded": false
        }]);
        let parsed = parse_live_clients(&v);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].username, "alice");
        assert_eq!(parsed[0].sessions, 3);
        assert_eq!(parsed[0].ips, vec!["1.2.3.4"]);
    }

    #[test]
    fn live_clients_accept_string_ips() {
        let v = json!([{
            "username": "bob",
            "sessions": 1,
            "ips": ["10.0.0.2"],
            "ip": "10.0.0.2"
        }]);
        let parsed = parse_live_clients(&v);
        assert_eq!(parsed[0].ips, vec!["10.0.0.2"]);
    }

    #[test]
    fn live_clients_accept_wrapped_array() {
        let v = json!({"clients": [{
            "username": "carol",
            "sessions": 2,
            "ips": [{"address": "8.8.8.8"}]
        }]});
        let parsed = parse_live_clients(&v);
        assert_eq!(parsed[0].username, "carol");
        assert_eq!(parsed[0].sessions, 2);
        assert_eq!(parsed[0].ips, vec!["8.8.8.8"]);
    }

    #[test]
    fn prometheus_sessions_are_summed() {
        let text = r#"
# HELP client_sessions_per_user Number of active client sessions per user
client_sessions_per_user{username="alice",protocol_type="HTTP2"} 2
client_sessions_per_user{username="alice",protocol_type="HTTP3"} 1
client_sessions_per_user{username="bob",protocol_type="HTTP2"} 4
"#;
        let map = parse_sessions_from_prometheus(text);
        assert_eq!(map.get("alice"), Some(&3));
        assert_eq!(map.get("bob"), Some(&4));
    }

    #[test]
    fn systemd_active_shows_uptime() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let show = "ActiveState=active\nActiveEnterTimestampUSec=994000000000000\nInactiveEnterTimestampUSec=0\n";
        let st = parse_systemctl_show(show, now);
        assert!(st.active);
        assert_eq!(st.label, "active");
        assert!(st.since_label.as_deref().unwrap().starts_with("up "));
    }

    #[test]
    fn systemd_inactive_shows_downtime() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let show = "ActiveState=failed\nActiveEnterTimestampUSec=0\nInactiveEnterTimestampUSec=994000000000000\n";
        let st = parse_systemctl_show(show, now);
        assert!(!st.active);
        assert_eq!(st.label, "failed");
        assert!(st.since_label.as_deref().unwrap().starts_with("down "));
    }

    #[test]
    fn humanize_bytes_and_duration() {
        assert_eq!(humanize(512), "512 B");
        assert_eq!(humanize(2048), "2.00 KB");
        assert_eq!(humanize_duration(Duration::from_secs(90)), "1m");
        assert_eq!(humanize_duration(Duration::from_secs(3700)), "1h 1m");
    }

    #[test]
    fn usage_file_path_uses_vpn_setting() {
        let vpn = VpnToml::from_str("listen_address = \"0.0.0.0:443\"\ntraffic_usage_file = \"usage.toml\"\n")
            .unwrap();
        let root = PathBuf::from("/opt/trusttunnel");
        assert_eq!(
            traffic_usage_path(&root, &vpn),
            PathBuf::from("/opt/trusttunnel/usage.toml")
        );
        let mut vpn = vpn;
        vpn.traffic_usage_file = Some("/var/lib/tt/usage.toml".into());
        assert_eq!(
            traffic_usage_path(&root, &vpn),
            PathBuf::from("/var/lib/tt/usage.toml")
        );
    }

    #[test]
    fn usage_toml_tables_are_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic_usage.toml");
        std::fs::write(&path, "[alice]\ninbound = 100\noutbound = 200\n").unwrap();
        let map = load_usage_map(&path);
        assert_eq!(map.get("alice").map(|u| u.inbound), Some(100));
        assert_eq!(map.get("alice").map(|u| u.outbound), Some(200));
    }

    #[test]
    fn usage_toml_inline_tables_are_parsed() {
        let map = parse_usage_toml("alice = { inbound = 10, outbound = 20 }\n");
        assert_eq!(map.get("alice").map(|u| u.inbound), Some(10));
        assert_eq!(map.get("alice").map(|u| u.outbound), Some(20));
    }

    #[test]
    fn live_clients_use_total_when_split_counters_missing() {
        let v = json!([{
            "username": "alice",
            "sessions": 1,
            "total": 4096,
            "ips": [{"address": "1.2.3.4", "tag": "#ip_1_2_3_4"}]
        }]);
        let parsed = parse_live_clients(&v);
        assert_eq!(parsed[0].inbound, 4096);
        assert_eq!(parsed[0].sessions, 1);
    }

    #[test]
    fn resolve_usage_path_reads_vpn_key_without_full_parse() {
        let root = PathBuf::from("/opt/trusttunnel");
        let path = resolve_usage_path(
            &root,
            Some("traffic_usage_file = \"/var/lib/tt/usage.toml\"\n"),
        );
        assert_eq!(path, PathBuf::from("/var/lib/tt/usage.toml"));
    }

    #[test]
    fn prometheus_per_user_traffic_is_summed() {
        let text = r#"
inbound_traffic_bytes_per_user{username="alice"} 100
outbound_traffic_bytes_per_user{username="alice"} 40
inbound_traffic_bytes_per_user{username="bob"} 7
"#;
        let map = parse_user_traffic_from_prometheus(text);
        assert_eq!(map.get("alice"), Some(&(100, 40)));
        assert_eq!(map.get("bob"), Some(&(7, 0)));
    }

    #[test]
    fn json_sessions_accept_string_values() {
        let v = json!([{
            "username": "alice",
            "sessions": "4",
            "inbound": -1,
            "ips": [{"address": "1.2.3.4"}]
        }]);
        let parsed = parse_live_clients(&v);
        assert_eq!(parsed[0].sessions, 4);
        assert_eq!(parsed[0].inbound, 0);
    }

    #[test]
    fn prometheus_session_total_ignores_per_user() {
        let text = r#"
client_sessions{protocol_type="HTTP2"} 5
client_sessions{protocol_type="HTTP3"} 2
client_sessions_per_user{username="alice",protocol_type="HTTP2"} 99
"#;
        assert_eq!(parse_session_total_from_prometheus(text), 7);
    }
}
