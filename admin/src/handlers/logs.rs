use crate::apply::journalctl_logs;
use crate::auth::Authenticated;
use crate::i18n::{self, I18n};
use crate::live::htop_snapshot;
use crate::state::AppState;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
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
    let system = matches!(q.system.as_deref(), Some("on" | "1" | "true"));
    let unit = if system {
        None
    } else {
        Some(state.paths.service_name.as_str())
    };
    let result = journalctl_logs(unit, lines);
    let (mut content, error) = match result {
        Ok(s) => (s, None),
        Err(e) => (String::new(), Some(e.to_string())),
    };
    if !content.is_empty() {
        let mut reversed: Vec<&str> = content.lines().collect();
        reversed.reverse();
        content = reversed.join("\n");
        content.push('\n');
    }
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
    }
    .into_response()
}

pub async fn htop_view(
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> Response {
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
    }
    .into_response()
}
