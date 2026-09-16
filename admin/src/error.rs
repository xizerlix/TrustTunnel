use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

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
    fn from(e: std::io::Error) -> Self { AdminError::Io(e) }
}
impl From<toml::de::Error> for AdminError {
    fn from(e: toml::de::Error) -> Self { AdminError::TomlDe(e) }
}
impl From<toml::ser::Error> for AdminError {
    fn from(e: toml::ser::Error) -> Self { AdminError::TomlSe(e) }
}
impl From<serde_json::Error> for AdminError {
    fn from(e: serde_json::Error) -> Self { AdminError::Internal(anyhow::anyhow!(e.to_string())) }
}
impl From<toml_edit::TomlError> for AdminError {
    fn from(e: toml_edit::TomlError) -> Self { AdminError::TomlEdit(e.to_string()) }
}
impl From<anyhow::Error> for AdminError {
    fn from(e: anyhow::Error) -> Self { AdminError::Internal(e) }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AdminError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AdminError::TomlDe(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AdminError::TomlSe(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AdminError::TomlEdit(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AdminError::Apply(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AdminError::Auth(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AdminError::Validation(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AdminError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AdminError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, Json(json!({"error": msg}))).into_response()
    }
}

pub type AdminResult<T> = Result<T, AdminError>;

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