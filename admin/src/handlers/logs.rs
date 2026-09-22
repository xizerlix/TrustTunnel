use crate::apply::journalctl_logs;
use crate::auth::Authenticated;
use crate::i18n::{self, I18n};
use crate::live::htop_snapshot;
use crate::state::AppState;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "logs.html")]
pub struct LogsTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub t: I18n,
    pub lang: &'static str,
    pub lines: usize,
    pub content: String,
    pub error: Option<String>,
    pub refresh: String,
    pub system: bool,
    pub tab: &'static str,
    pub login_rows: Vec<LoginRow>,
}

pub struct LoginRow {
    pub time: String,
    pub ip: String,
    pub event: String,
}

#[derive(Deserialize)]
pub struct LogsQuery {
    pub lines: Option<usize>,
    pub refresh: Option<String>,
    pub system: Option<String>,
}

fn refresh_val(s: Option<&str>) -> String {
    match s {
        Some("3") => "3".into(),
        Some("10") => "10".into(),
        Some("30") => "30".into(),
        _ => "off".into(),
    }
}

fn system_on(s: Option<&str>) -> bool {
    matches!(s, Some("on" | "1" | "true"))
}

fn read_journal(state: &AppState, lines: usize, system: bool) -> (String, Option<String>) {
    let unit = if system {
        None
    } else {
        Some(state.paths.service_name.as_str())
    };
    match journalctl_logs(unit, lines) {
        Ok(mut content) => {
            if !content.is_empty() {
                let mut reversed: Vec<&str> = content.lines().collect();
                reversed.reverse();
                content = reversed.join("\n");
                content.push('\n');
            }
            (content, None)
        }
        Err(e) => (String::new(), Some(e.to_string())),
    }
}

fn plain_text(body: String) -> Response {
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

pub async fn logs_view(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    Query(q): Query<LogsQuery>,
) -> Response {
    let lang = i18n::from_headers(&headers);
    let t = i18n::t(lang);
    let lines = q.lines.unwrap_or(200).clamp(50, 5000);
    let refresh = refresh_val(q.refresh.as_deref());
    let system = system_on(q.system.as_deref());
    let (content, error) = read_journal(&state, lines, system);
    LogsTemplate {
        title: t.logs.into(),
        username: session.username,
        csrf: session.csrf,
        t,
        lang: lang.as_str(),
        lines,
        content,
        error,
        refresh,
        system,
        tab: "logs",
        login_rows: Vec::new(),
    }
    .into_response()
}

pub async fn logs_data(
    State(state): State<AppState>,
    Authenticated(_session): Authenticated,
    Query(q): Query<LogsQuery>,
) -> Response {
    let lines = q.lines.unwrap_or(200).clamp(50, 5000);
    let system = system_on(q.system.as_deref());
    let (content, error) = read_journal(&state, lines, system);
    if let Some(e) = error {
        return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    plain_text(content)
}

pub async fn htop_view(Authenticated(session): Authenticated, headers: HeaderMap) -> Response {
    let lang = i18n::from_headers(&headers);
    let t = i18n::t(lang);
    let content = tokio::task::spawn_blocking(htop_snapshot)
        .await
        .unwrap_or_else(|_| "htop unavailable".into());
    LogsTemplate {
        title: t.tab_htop.into(),
        username: session.username,
        csrf: session.csrf,
        t,
        lang: lang.as_str(),
        lines: 0,
        content,
        error: None,
        refresh: "10".into(),
        system: false,
        tab: "htop",
        login_rows: Vec::new(),
    }
    .into_response()
}

pub async fn htop_data(Authenticated(_session): Authenticated) -> Response {
    let content = tokio::task::spawn_blocking(htop_snapshot)
        .await
        .unwrap_or_else(|_| "htop unavailable".into());
    plain_text(content)
}

fn event_label(t: &I18n, event: &str) -> String {
    match event {
        "ok" => t.login_ev_ok.to_string(),
        "fail" => t.login_ev_fail.to_string(),
        "limited" => t.login_ev_limited.to_string(),
        "totp_fail" => t.login_ev_totp_fail.to_string(),
        other => other.to_string(),
    }
}

pub async fn logins_view(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> Response {
    let lang = i18n::from_headers(&headers);
    let t = i18n::t(lang);
    let login_rows: Vec<LoginRow> = state
        .login_log
        .list()
        .into_iter()
        .map(|ev| {
            let time = chrono::DateTime::from_timestamp(ev.t, 0)
                .map(|dt| {
                    dt.with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M:%S")
                        .to_string()
                })
                .unwrap_or_else(|| ev.t.to_string());
            LoginRow {
                time,
                ip: ev.ip,
                event: event_label(&t, &ev.event),
            }
        })
        .collect();
    LogsTemplate {
        title: t.tab_logins.into(),
        username: session.username,
        csrf: session.csrf,
        t,
        lang: lang.as_str(),
        lines: 0,
        content: String::new(),
        error: None,
        refresh: "off".into(),
        system: false,
        tab: "logins",
        login_rows,
    }
    .into_response()
}
