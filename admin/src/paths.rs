use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct TrustTunnelPaths {
    pub root: PathBuf,
    pub vpn_toml: PathBuf,
    pub hosts_toml: PathBuf,
    pub credentials_toml: PathBuf,
    pub rules_toml: PathBuf,
    pub admin_toml: PathBuf,
    pub service_name: String,
    pub metrics_address: String,
}

impl TrustTunnelPaths {
    pub fn detect() -> anyhow::Result<Self> {
        let candidates_root = [
            "/opt/trusttunnel",
            "/etc/trusttunnel",
        ];
        let root = candidates_root
            .iter()
            .map(Path::new)
            .find(|p| p.join("vpn.toml").exists())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/opt/trusttunnel"));

        let vpn_toml = root.join("vpn.toml");
        let hosts_toml = root.join("hosts.toml");
        let credentials_toml = root.join("credentials.toml");
        let rules_toml = root.join("rules.toml");
        let admin_dir = PathBuf::from("/etc/trusttunnel");
        let admin_toml = admin_dir.join("admin.toml");

        let metrics_address = std::fs::read_to_string(&vpn_toml)
            .ok()
            .and_then(|s| {
                let doc: toml_edit::DocumentMut = s.parse().ok()?;
                doc.get("metrics")
                    .and_then(|m| m.get("address"))
                    .and_then(|a| a.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "127.0.0.1:1987".into());

        Ok(Self {
            root,
            vpn_toml,
            hosts_toml,
            credentials_toml,
            rules_toml,
            admin_toml,
            service_name: "trusttunnel".into(),
            metrics_address,
        })
    }

    pub fn exists(&self) -> bool {
        self.vpn_toml.exists() && self.hosts_toml.exists()
    }

    pub fn detect_with_root(root: std::path::PathBuf) -> anyhow::Result<Self> {
        let candidates = [
            root.clone(),
            std::path::PathBuf::from("/opt/trusttunnel"),
            std::path::PathBuf::from("/etc/trusttunnel"),
        ];
        let chosen = candidates
            .iter()
            .find(|p| p.join("vpn.toml").exists())
            .cloned()
            .unwrap_or(root);
        let mut paths = Self::detect()?;
        paths.root = chosen.clone();
        paths.vpn_toml = chosen.join("vpn.toml");
        paths.hosts_toml = chosen.join("hosts.toml");
        paths.credentials_toml = chosen.join("credentials.toml");
        paths.rules_toml = chosen.join("rules.toml");
        Ok(paths)
    }
}