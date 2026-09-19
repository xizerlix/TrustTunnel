use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};

#[derive(Debug)]
pub enum AdminError {
    Io(std::io::Error),
    TomlDe(toml::de::Error),
    TomlSe(toml::ser::Error),
    TomlEdit(String),
    Apply(String),
    Auth(String),
    Validation(String),
    NotFound(String),
    Internal(anyhow::Error),
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminError::Io(e) => write!(f, "io: {e}"),
            AdminError::TomlDe(e) => write!(f, "toml parse: {e}"),
            AdminError::TomlSe(e) => write!(f, "toml serialize: {e}"),
            AdminError::TomlEdit(e) => write!(f, "toml_edit: {e}"),
            AdminError::Apply(e) => write!(f, "apply: {e}"),
            AdminError::Auth(e) => write!(f, "auth: {e}"),
            AdminError::Validation(e) => write!(f, "validation: {e}"),
            AdminError::NotFound(e) => write!(f, "not found: {e}"),
            AdminError::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

impl std::error::Error for AdminError {}

impl From<std::io::Error> for AdminError {
    fn from(e: std::io::Error) -> Self {
        AdminError::Io(e)
    }
}
impl From<toml::de::Error> for AdminError {
    fn from(e: toml::de::Error) -> Self {
        AdminError::TomlDe(e)
    }
}
impl From<toml::ser::Error> for AdminError {
    fn from(e: toml::ser::Error) -> Self {
        AdminError::TomlSe(e)
    }
}
impl From<serde_json::Error> for AdminError {
    fn from(e: serde_json::Error) -> Self {
        AdminError::Internal(anyhow::anyhow!(e.to_string()))
    }
}
impl From<toml_edit::TomlError> for AdminError {
    fn from(e: toml_edit::TomlError) -> Self {
        AdminError::TomlEdit(e.to_string())
    }
}
impl From<anyhow::Error> for AdminError {
    fn from(e: anyhow::Error) -> Self {
        AdminError::Internal(e)
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn html_page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title></head><body style=\"font-family:system-ui,sans-serif;\
         max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5\">\
         <h1>{title}</h1><p>{body}</p>\
         <p><a href=\"javascript:history.back()\">Go back</a> · <a href=\"/login\">Sign in</a></p>\
         </body></html>"
    )
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        match self {
            AdminError::Auth(_) => Redirect::to("/login").into_response(),
            other => {
                let (status, msg) = match &other {
                    AdminError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
                    AdminError::TomlDe(_) => (StatusCode::BAD_REQUEST, other.to_string()),
                    AdminError::TomlSe(_) => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
                    AdminError::TomlEdit(_) => (StatusCode::BAD_REQUEST, other.to_string()),
                    AdminError::Apply(_) => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
                    AdminError::Validation(_) => (StatusCode::BAD_REQUEST, other.to_string()),
                    AdminError::NotFound(_) => (StatusCode::NOT_FOUND, other.to_string()),
                    AdminError::Internal(_) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, other.to_string())
                    }
                    AdminError::Auth(_) => unreachable!(),
                };
                (
                    status,
                    Html(html_page("Something went wrong", &html_escape(&msg))),
                )
                    .into_response()
            }
        }
    }
}

pub type AdminResult<T> = Result<T, AdminError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, StatusCode};

    #[test]
    fn unauthenticated_browser_is_sent_to_login() {
        let resp = AdminError::Auth("no session".into()).into_response();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/login"
        );
    }

    #[test]
    fn validation_is_html_not_json() {
        let resp = AdminError::Validation("invalid form: expected a sequence".into()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_ne!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            "application/json"
        );
    }
}

pub trait WithStatusExt {
    fn with_status(self, s: axum::http::StatusCode) -> axum::response::Response;
}
impl<T: IntoResponse> WithStatusExt for T {
    fn with_status(self, s: axum::http::StatusCode) -> axum::response::Response {
        let mut r = self.into_response();
        *r.status_mut() = s;
        r
    }
}
