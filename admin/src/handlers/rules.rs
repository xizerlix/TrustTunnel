use crate::apply::{apply, ApplyKind};
use crate::auth::{verify_csrf_from_form, Authenticated};
use crate::error::{AdminError, AdminResult};
use crate::form::{form_col, form_lists};
use crate::i18n::{self, I18n};
use crate::models::{RuleAction, RuleEntry, RulesToml};
use crate::state::AppState;
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

#[derive(Template)]
#[template(path = "rules.html")]
pub struct RulesTemplate {
    pub title: String,
    pub username: String,
    pub csrf: String,
    pub t: I18n,
    pub lang: &'static str,
    pub rules: RulesToml,
    pub save_status: Option<String>,
    pub error: Option<String>,
    pub action_strs: Vec<String>,
}

fn page(
    session: &crate::auth::Session,
    headers: &HeaderMap,
    rules: RulesToml,
    save_status: Option<String>,
    error: Option<String>,
) -> RulesTemplate {
    let lang = i18n::from_headers(headers);
    let t = i18n::t(lang);
    let action_strs: Vec<String> = rules.rules.iter().map(|r| action_to_str(&r.action)).collect();
    RulesTemplate {
        title: t.rules.into(),
        username: session.username.clone(),
        csrf: session.csrf.clone(),
        t,
        lang: lang.as_str(),
        rules,
        save_status,
        error,
        action_strs,
    }
}

pub async fn rules_form(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
) -> AdminResult<Response> {
    let rules = load_or_default(&state.paths.rules_toml)?;
    Ok(page(&session, &headers, rules, None, None).into_response())
}

pub async fn rules_save(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    headers: HeaderMap,
    body: String,
) -> AdminResult<Response> {
    verify_csrf_from_form(&headers, &body, &session).await?;
    let map = form_lists(&body);
    let cidrs = form_col(&map, "cidr");
    let prefixes = form_col(&map, "client_random_prefix");
    let actions = form_col(&map, "action");
    let mut new_rules = RulesToml::default();
    let len = cidrs.len().max(prefixes.len()).max(actions.len());
    for i in 0..len {
        let cidr = cidrs.get(i).cloned().unwrap_or_default();
        let prefix = prefixes.get(i).cloned().unwrap_or_default();
        if cidr.trim().is_empty() && prefix.trim().is_empty() {
            continue;
        }
        let action = match actions.get(i).map(|s| s.as_str()).unwrap_or("allow") {
            "deny" => RuleAction::Deny,
            _ => RuleAction::Allow,
        };
        new_rules.rules.push(RuleEntry {
            cidr: if cidr.trim().is_empty() {
                None
            } else {
                Some(cidr)
            },
            client_random_prefix: if prefix.trim().is_empty() {
                None
            } else {
                Some(prefix)
            },
            action,
        });
    }
    let serialized = toml::to_string_pretty(&new_rules).map_err(AdminError::TomlSe)?;
    crate::apply::atomic_write(&state.paths.rules_toml, &serialized)?;
    let t = i18n::t(i18n::from_headers(&headers));
    let apply_result = apply(&state.paths, ApplyKind::FullRestart);
    let msg = crate::apply::format_apply(&t, &apply_result);
    let err = if apply_result.is_err() {
        Some(msg.clone())
    } else {
        None
    };
    let resp = page(&session, &headers, new_rules, Some(msg), err).into_response();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaved_cidr_parses() {
        let map = form_lists("cidr=1.1.1.0/24&action=deny&cidr=&client_random_prefix=&action=allow");
        assert_eq!(form_col(&map, "cidr").len(), 2);
    }

    #[test]
    fn empty_cidr_and_prefix_are_skipped() {
        let map = form_lists("cidr=&client_random_prefix=&action=allow&cidr=10.0.0.0/8&action=deny");
        let cidrs = form_col(&map, "cidr");
        let prefixes = form_col(&map, "client_random_prefix");
        let actions = form_col(&map, "action");
        let mut kept = 0;
        let len = cidrs.len().max(prefixes.len()).max(actions.len());
        for i in 0..len {
            let cidr = cidrs.get(i).cloned().unwrap_or_default();
            let prefix = prefixes.get(i).cloned().unwrap_or_default();
            if cidr.trim().is_empty() && prefix.trim().is_empty() {
                continue;
            }
            kept += 1;
        }
        assert_eq!(kept, 1);
    }
}
