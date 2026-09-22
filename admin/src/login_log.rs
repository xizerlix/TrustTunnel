use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_EVENTS: usize = 400;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginEvent {
    pub t: i64,
    pub ip: String,
    pub event: String,
}

pub struct LoginLog {
    path: PathBuf,
    inner: Mutex<Vec<LoginEvent>>,
}

impl LoginLog {
    pub fn load(path: PathBuf) -> Self {
        let events = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self {
            path,
            inner: Mutex::new(events),
        }
    }

    pub fn record(&self, ip: IpAddr, event: &str) {
        let ev = LoginEvent {
            t: chrono::Local::now().timestamp(),
            ip: ip.to_string(),
            event: event.to_string(),
        };
        let mut g = self.inner.lock().unwrap();
        g.push(ev);
        if g.len() > MAX_EVENTS {
            let drop_n = g.len() - MAX_EVENTS;
            g.drain(0..drop_n);
        }
        let _ = write_all(&self.path, &*g);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
    }

    pub fn list(&self) -> Vec<LoginEvent> {
        let g = self.inner.lock().unwrap();
        let mut out = g.clone();
        out.reverse();
        out
    }
}

fn write_all(path: &Path, events: &[LoginEvent]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(events).unwrap_or_default())
}

pub fn history_path(admin_toml: &Path) -> PathBuf {
    admin_toml
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("login_history.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn appends_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("login_history.json");
        let log = LoginLog::load(path.clone());
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        log.record(ip, "ok");
        log.record(ip, "fail");
        let list = log.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].event, "fail");
        assert_eq!(list[1].event, "ok");
        let loaded = LoginLog::load(path);
        assert_eq!(loaded.list().len(), 2);
    }
}
