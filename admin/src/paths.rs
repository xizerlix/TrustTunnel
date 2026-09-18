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
    pub fn from_root(root: PathBuf) -> Self {
        let vpn_toml = root.join("vpn.toml");
        let hosts_toml = root.join("hosts.toml");
        let credentials_toml = root.join("credentials.toml");
        let rules_toml = root.join("rules.toml");
        let admin_toml = PathBuf::from("/etc/trusttunnel/admin.toml");
        let metrics_address = std::fs::read_to_string(&vpn_toml)
            .ok()
            .and_then(|s| parse_metrics_address(&s))
            .unwrap_or_else(|| "127.0.0.1:1987".into());

        Self {
            root,
            vpn_toml,
            hosts_toml,
            credentials_toml,
            rules_toml,
            admin_toml,
            service_name: "trusttunnel".into(),
            metrics_address,
        }
    }

    pub fn detect() -> anyhow::Result<Self> {
        let candidates_root = ["/opt/trusttunnel", "/etc/trusttunnel"];
        let root = candidates_root
            .iter()
            .map(Path::new)
            .find(|p| p.join("vpn.toml").exists())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/opt/trusttunnel"));
        Ok(Self::from_root(root))
    }

    pub fn exists(&self) -> bool {
        self.vpn_toml.exists() && self.hosts_toml.exists()
    }

    pub fn detect_with_root(root: PathBuf) -> anyhow::Result<Self> {
        let candidates = [
            root.clone(),
            PathBuf::from("/opt/trusttunnel"),
            PathBuf::from("/etc/trusttunnel"),
        ];
        let chosen = candidates
            .iter()
            .find(|p| p.join("vpn.toml").exists())
            .cloned()
            .unwrap_or(root);
        Ok(Self::from_root(chosen))
    }
}

pub fn parse_metrics_address(vpn_toml: &str) -> Option<String> {
    let doc: toml_edit::DocumentMut = vpn_toml.parse().ok()?;
    doc.get("metrics")
        .and_then(|m| m.get("address"))
        .and_then(|a| a.as_str())
        .map(String::from)
}

pub fn parse_traffic_usage_file(vpn_toml: &str) -> Option<String> {
    let doc: toml_edit::DocumentMut = vpn_toml.parse().ok()?;
    doc.get("traffic_usage_file")
        .and_then(|a| a.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

pub fn parse_destination_stats_file(vpn_toml: &str) -> Option<String> {
    let doc: toml_edit::DocumentMut = vpn_toml.parse().ok()?;
    doc.get("destination_stats_file")
        .and_then(|a| a.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_metrics_address() {
        let toml = "[metrics]\naddress = \"127.0.0.1:1987\"\n";
        assert_eq!(parse_metrics_address(toml).as_deref(), Some("127.0.0.1:1987"));
    }

    #[test]
    fn parses_traffic_usage_file() {
        let toml = "listen_address = \"0.0.0.0:443\"\ntraffic_usage_file = \"traffic_usage.toml\"\n";
        assert_eq!(
            parse_traffic_usage_file(toml).as_deref(),
            Some("traffic_usage.toml")
        );
    }

    #[test]
    fn parses_destination_stats_file() {
        let toml =
            "listen_address = \"0.0.0.0:443\"\ndestination_stats_file = \"dest_stats.json\"\n";
        assert_eq!(
            parse_destination_stats_file(toml).as_deref(),
            Some("dest_stats.json")
        );
    }
}
