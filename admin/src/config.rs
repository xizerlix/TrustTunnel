use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub bind: SocketAddr,
    pub bcrypt_hash: String,
    pub session_ttl_secs: u64,
    pub login_rate_per_min: u32,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default = "default_password_login")]
    pub password_login: bool,
}

fn default_password_login() -> bool {
    true
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8443".parse().unwrap(),
            bcrypt_hash: String::new(),
            session_ttl_secs: 1800,
            login_rate_per_min: 5,
            totp_enabled: false,
            totp_secret: String::new(),
            password_login: true,
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        !self.bcrypt_hash.is_empty()
    }

    pub fn totp_on(&self) -> bool {
        self.totp_enabled && !self.totp_secret.is_empty()
    }
}

pub fn hash_password(plain: &str) -> anyhow::Result<String> {
    Ok(bcrypt::hash(plain, bcrypt::DEFAULT_COST)?)
}

pub fn verify_password(plain: &str, hash: &str) -> bool {
    bcrypt::verify(plain, hash).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_hash_from_same_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.toml");
        let mut cfg = AdminConfig::default();
        cfg.bcrypt_hash = "stored-hash".into();
        cfg.save(&path).unwrap();
        let loaded = AdminConfig::load_or_default(&path);
        assert_eq!(loaded.bcrypt_hash, "stored-hash");
        assert!(!loaded.totp_on());
    }

    #[test]
    fn load_keeps_totp_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.toml");
        std::fs::write(
            &path,
            "bind = \"127.0.0.1:8443\"\nbcrypt_hash = \"h\"\nsession_ttl_secs = 1800\nlogin_rate_per_min = 5\ntotp_enabled = true\ntotp_secret = \"MFRGGZDFMZTWQ2LK\"\n",
        )
        .unwrap();
        let loaded = AdminConfig::load_or_default(&path);
        assert!(loaded.totp_on());
        assert_eq!(loaded.totp_secret, "MFRGGZDFMZTWQ2LK");
        assert!(loaded.password_login);
    }

    #[test]
    fn missing_password_login_defaults_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.toml");
        std::fs::write(
            &path,
            "bind = \"127.0.0.1:8443\"\nbcrypt_hash = \"h\"\nsession_ttl_secs = 1800\nlogin_rate_per_min = 5\n",
        )
        .unwrap();
        assert!(AdminConfig::load_or_default(&path).password_login);
    }

    #[test]
    fn password_login_false_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.toml");
        let mut cfg = AdminConfig::default();
        cfg.password_login = false;
        cfg.save(&path).unwrap();
        assert!(!AdminConfig::load_or_default(&path).password_login);
    }
}
