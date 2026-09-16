use crate::apply::{apply, ApplyKind};
use crate::auth::{verify_csrf_from_form, Authenticated};
use crate::error::{AdminError, AdminResult};
use crate::models::{RuleAction, RuleEntry, RulesToml};
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "rules.html")]
pub struct RulesTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub rules: RulesToml,
    pub save_status: Option<String>,
    pub error: Option<String>,
    pub action_strs: Vec<String>,
}

pub async fn rules_form(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> AdminResult<Response> {
    let rules = load_or_default(&state.paths.rules_toml)?;
    let action_strs: Vec<String> = rules
        .rules
        .iter()
        .map(|r| action_to_str(&r.action))
        .collect();
    Ok(RulesTemplate {
        title: "Rules".into(),
        username: session.username,
        csrf: session.csrf,
        rules,
        save_status: None,
        error: None,
        action_strs,
    }
    .into_response())
}

pub async fn rules_save(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let form: RulesForm = serde_urlencoded::from_str(&body)
        .map_err(|e| AdminError::Validation(format!("invalid form: {e}")))?;
    let mut new_rules = RulesToml::default();
    for (i, cidr) in form.cidr.iter().enumerate() {
        if cidr.is_empty() && form.client_random_prefix.get(i).map(|s| s.is_empty()).unwrap_or(true) {
            continue;
        }
        let action = match form.action.get(i).map(|s| s.as_str()).unwrap_or("allow") {
            "deny" => RuleAction::Deny,
            _ => RuleAction::Allow,
        };
        new_rules.rules.push(RuleEntry {
            cidr: if cidr.is_empty() { None } else { Some(cidr.clone()) },
            client_random_prefix: form
                .client_random_prefix
                .get(i)
                .filter(|s| !s.is_empty())
                .cloned(),
            action,
        });
    }
    let serialized = toml::to_string_pretty(&new_rules).map_err(AdminError::TomlSe)?;
    crate::apply::atomic_write(&state.paths.rules_toml, &serialized)?;
    let apply_result = apply(&state.paths, ApplyKind::FullRestart);
    let msg = match &apply_result {
        Ok(m) => m.clone(),
        Err(e) => format!("save OK but apply failed: {e}"),
    };
    let err = if apply_result.is_err() { Some(msg.clone()) } else { None };
    let resp = RulesTemplate {
        title: "Rules".into(),
        username: session.username,
        csrf: session.csrf,
        rules: new_rules.clone(),
        save_status: Some(msg),
        error: err,
        action_strs: new_rules
            .rules
            .iter()
            .map(|r| action_to_str(&r.action))
            .collect(),
    }
    .into_response();
    let s = if apply_result.is_err() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    };
    Ok((s, resp).into_response())
}

fn load_or_default(path: &std::path::Path) -> AdminResult<RulesToml> {
    match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).map_err(AdminError::TomlDe),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RulesToml::default()),
        Err(e) => Err(AdminError::Io(e)),
    }
}

fn action_to_str(a: &RuleAction) -> String {
    match a {
        RuleAction::Allow => "allow".to_string(),
        RuleAction::Deny => "deny".to_string(),
    }
}

#[derive(Deserialize)]
pub struct RulesForm {
    pub cidr: Vec<String>,
    pub client_random_prefix: Vec<String>,
    pub action: Vec<String>,
}