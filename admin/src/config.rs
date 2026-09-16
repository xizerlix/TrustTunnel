use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub bind: SocketAddr,
    pub bcrypt_hash: String,
    pub session_ttl_secs: u64,
    pub login_rate_per_min: u32,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8443".parse().unwrap(),
            bcrypt_hash: String::new(),
            session_ttl_secs: 1800,
            login_rate_per_min: 5,
        }
    }
}

impl AdminConfig {
    pub fn load_or_default(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        !self.bcrypt_hash.is_empty()
    }
}

pub fn hash_password(plain: &str) -> anyhow::Result<String> {
    Ok(bcrypt::hash(plain, bcrypt::DEFAULT_COST)?)
}

pub fn verify_password(plain: &str, hash: &str) -> bool {
    bcrypt::verify(plain, hash).unwrap_or(false)
}