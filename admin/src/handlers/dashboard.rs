use crate::apply::{read_clients_json, systemctl_status};
use crate::auth::Authenticated;
use crate::models::CredentialsToml;
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub service_active: String,
    pub uptime: Option<String>,
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
    pub service_active: String,
    pub uptime: Option<String>,
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

#[derive(Deserialize)]
struct LiveClient {
    username: String,
    sessions: u64,
    #[serde(default)]
    inbound: u64,
    #[serde(default)]
    outbound: u64,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    quota_exceeded: bool,
    #[serde(default)]
    limit: Option<u64>,
}

#[derive(Deserialize, Default)]
#[derive(Clone)]
struct UsageUser {
    #[serde(default)]
    inbound: u64,
    #[serde(default)]
    outbound: u64,
}

fn humanize(n: u64) -> String {
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

struct Stats {
    active: String,
    uptime: Option<String>,
    clients_count: usize,
    session_total: u64,
    unique_ips: usize,
    traffic_inbound_h: String,
    traffic_outbound_h: String,
    traffic_total_h: String,
    users: Vec<UserRow>,
}

async fn collect(state: &AppState) -> Stats {
    let status = systemctl_status(&state.paths.service_name)
        .unwrap_or_else(|e| format!("failed to read status: {e}"));
    let active = if status.contains("active (running)") {
        "active".into()
    } else if status.contains("inactive") {
        "inactive".into()
    } else {
        "unknown".into()
    };
    let uptime = parse_uptime(&status);

    let live_json =
        read_clients_json(&state.paths.metrics_address).unwrap_or_else(|_| serde_json::json!([]));

    let mut usage: std::collections::HashMap<String, UsageUser> =
        std::collections::HashMap::new();
    if let Ok(s) = std::fs::read_to_string(&state.paths.root.join("traffic_usage.toml")) {
        if let Ok(parsed) = toml::from_str::<std::collections::HashMap<String, UsageUser>>(&s) {
            usage = parsed;
        }
    }

    let mut by_user: std::collections::HashMap<String, LiveClient> =
        std::collections::HashMap::new();
    let mut all_ips: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut session_total: u64 = 0;
    if let Value::Array(arr) = &live_json {
        for v in arr {
            if let Ok(mut c) = serde_json::from_value::<LiveClient>(v.clone()) {
                if c.ips.is_empty() {
                    if let Some(obj) = v.as_object() {
                        if let Some(ip) = obj.get("ip").and_then(|x| x.as_str()) {
                            c.ips.push(ip.to_string());
                        }
                    }
                }
                session_total = session_total.saturating_add(c.sessions);
                for ip in &c.ips {
                    all_ips.insert(ip.clone());
                }
                by_user.insert(c.username.clone(), c);
            }
        }
    }

    let creds = std::fs::read_to_string(&state.paths.credentials_toml)
        .ok()
        .and_then(|s| toml::from_str::<CredentialsToml>(&s).ok())
        .unwrap_or_default();

    let mut users: Vec<UserRow> = Vec::new();
    let mut all_user_names: Vec<String> = Vec::new();
    for c in &creds.clients {
        if !all_user_names.contains(&c.username) {
            all_user_names.push(c.username.clone());
        }
    }
    for (u, _) in &by_user {
        if !all_user_names.contains(u) {
            all_user_names.push(u.clone());
        }
    }
    for username in all_user_names {
        let live = by_user.get(&username);
        let sessions = live.map(|c| c.sessions).unwrap_or(0);
        let ips_label = live
            .map(|c| if c.ips.is_empty() { "—".into() } else { c.ips.join(", ") })
            .unwrap_or_else(|| "—".into());
        let active = sessions > 0;
        let u_usage = usage.get(&username).cloned().unwrap_or_default();
        let mut total_bytes = u_usage.inbound.saturating_add(u_usage.outbound);
        let mut quota_limit_h = "∞".to_string();
        let mut quota_used_pct: u8 = 0;
        let mut quota_exceeded = false;
        if let Some(c) = creds.clients.iter().find(|c| c.username == username) {
            let limit = c.max_traffic_bytes;
            if limit > 0 {
                quota_limit_h = humanize(limit);
                quota_used_pct =
                    ((total_bytes as f64 / limit as f64) * 100.0).clamp(0.0, 100.0) as u8;
                quota_exceeded = total_bytes > limit;
            }
        }
        if let Some(c) = live {
            if let Some(limit) = c.limit {
                if limit > 0 {
                    quota_limit_h = humanize(limit);
                    quota_used_pct =
                        ((total_bytes as f64 / limit as f64) * 100.0).clamp(0.0, 100.0) as u8;
                    quota_exceeded = total_bytes > limit;
                }
            }
        }
        if !active {
            total_bytes = 0;
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

    let clients_count = users.iter().filter(|u| u.active).count();
    let total_in = usage.values().map(|u| u.inbound).sum::<u64>();
    let total_out = usage.values().map(|u| u.outbound).sum::<u64>();
    let total_combined = total_in.saturating_add(total_out);

    Stats {
        active,
        uptime,
        clients_count,
        session_total,
        unique_ips: all_ips.len(),
        traffic_inbound_h: humanize(total_in),
        traffic_outbound_h: humanize(total_out),
        traffic_total_h: humanize(total_combined),
        users,
    }
}

pub async fn dashboard(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> Response {
    let stats = collect(&state).await;
    DashboardTemplate {
        title: "Dashboard".into(),
        username: session.username,
        csrf: session.csrf,
        service_active: stats.active,
        uptime: stats.uptime,
        clients_count: stats.clients_count,
        session_total: stats.session_total,
        unique_ips: stats.unique_ips,
        traffic_inbound_h: stats.traffic_inbound_h,
        traffic_outbound_h: stats.traffic_outbound_h,
        traffic_total_h: stats.traffic_total_h,
        users: stats.users,
    }
    .into_response()
}

pub async fn dashboard_data(
    State(state): State<AppState>,
    Authenticated(_session): Authenticated,
) -> Response {
    let stats = collect(&state).await;
    DashboardDataTemplate {
        service_active: stats.active,
        uptime: stats.uptime,
        clients_count: stats.clients_count,
        session_total: stats.session_total,
        unique_ips: stats.unique_ips,
        traffic_inbound_h: stats.traffic_inbound_h,
        traffic_outbound_h: stats.traffic_outbound_h,
        traffic_total_h: stats.traffic_total_h,
        users: stats.users,
    }
    .into_response()
}

fn parse_uptime(status: &str) -> Option<String> {
    for line in status.lines() {
        if line.trim_start().starts_with("Active:") {
            let since_idx = line.find("since")?;
            let rest = &line[since_idx + 5..].trim_start();
            let end = rest.find('.')?;
            return Some(rest[..end].trim().to_string());
        }
    }
    None
}
