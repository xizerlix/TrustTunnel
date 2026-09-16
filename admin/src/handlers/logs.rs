use crate::apply::journalctl_logs;
use crate::auth::Authenticated;
use crate::state::AppState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "logs.html")]
pub struct LogsTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub lines: usize,
    pub content: String,
    pub error: Option<String>,
    pub refresh: String,
}

#[derive(Deserialize)]
pub struct LogsQuery {
    pub lines: Option<usize>,
    pub refresh: Option<String>,
}

pub async fn logs_view(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Query(q): Query<LogsQuery>,
) -> Response {
    let lines = q.lines.unwrap_or(200).clamp(50, 5000);
    let refresh = match q.refresh.as_deref() {
        Some("3") => "3".into(),
        Some("10") => "10".into(),
        Some("30") => "30".into(),
        _ => "off".into(),
    };
    let result = journalctl_logs(&state.paths.service_name, lines);
    let (mut content, error) = match result {
        Ok(s) => (s, None),
        Err(e) => (String::new(), Some(e.to_string())),
    };
    if !content.is_empty() {
        let lines_vec: Vec<&str> = content.lines().collect();
        let mut reversed = lines_vec.clone();
        reversed.reverse();
        content = reversed.join("\n");
        content.push('\n');
    }
    LogsTemplate {
        title: "Logs".into(),
        username: session.username,
        csrf: session.csrf,
        lines,
        content,
        error,
        refresh,
    }
    .into_response()
}
