use std::collections::BTreeMap;

const CHANNELS: &[&str] = &["_udp2", "_icmp", "_check", "unknown"];

pub fn display_lines(raw: &[String]) -> Vec<String> {
    let mut by_platform: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for ua in raw {
        let Some((platform, token)) = split_ua(ua) else {
            continue;
        };
        let key = platform.to_ascii_lowercase();
        let entry = by_platform
            .entry(key)
            .or_insert_with(|| (platform, Vec::new()));
        if let Some(app) = token.filter(|t| !is_channel(t)) {
            if !entry.1.iter().any(|x| x.eq_ignore_ascii_case(&app)) {
                entry.1.push(app);
            }
        }
    }
    let mut lines = Vec::new();
    for (_, (platform, mut apps)) in by_platform {
        apps.sort_by(|a, b| a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()));
        if apps.is_empty() {
            lines.push(platform);
        } else {
            for app in apps {
                lines.push(format!("{platform} · {app}"));
            }
        }
    }
    lines
}

pub fn os_keys(raw: &[String]) -> Vec<String> {
    let mut keys = Vec::new();
    for ua in raw {
        let Some((platform, _)) = split_ua(ua) else {
            continue;
        };
        let key = icon_key(&platform).to_string();
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys.sort();
    keys
}

fn split_ua(s: &str) -> Option<(String, Option<String>)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    match s.split_once(char::is_whitespace) {
        Some((platform, rest)) => {
            let platform = platform.trim();
            if platform.is_empty() {
                return None;
            }
            let rest = rest.trim();
            let token = if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            Some((platform.to_string(), token))
        }
        None => Some((s.to_string(), None)),
    }
}

fn is_channel(token: &str) -> bool {
    let t = token.trim();
    if t.starts_with('_') {
        return true;
    }
    CHANNELS.iter().any(|c| t.eq_ignore_ascii_case(c))
}

fn icon_key(platform: &str) -> &'static str {
    match platform.to_ascii_lowercase().as_str() {
        "android" => "android",
        "ios" | "ipados" | "iphone" | "ipad" => "ios",
        "macos" | "osx" | "darwin" | "mac" => "macos",
        "windows" | "win32" | "win64" => "windows",
        "linux" => "linux",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn collapses_protocol_channels_per_os() {
        let raw = s(&[
            "Android _udp2",
            "Android trusttunnel_client",
            "Android unknown",
            "Windows _udp2",
            "Windows trusttunnel_client",
            "Windows unknown",
        ]);
        assert_eq!(
            display_lines(&raw),
            vec![
                "Android · trusttunnel_client".to_string(),
                "Windows · trusttunnel_client".to_string(),
            ]
        );
        assert_eq!(
            os_keys(&raw),
            vec!["android".to_string(), "windows".to_string()]
        );
    }

    #[test]
    fn official_phone_is_one_line() {
        let raw = s(&["iOS trusttunnel_client", "iOS unknown"]);
        assert_eq!(
            display_lines(&raw),
            vec!["iOS · trusttunnel_client".to_string()]
        );
        assert_eq!(os_keys(&raw), vec!["ios".to_string()]);
    }

    #[test]
    fn health_check_only_shows_platform() {
        assert_eq!(display_lines(&s(&["Android"])), vec!["Android".to_string()]);
    }
}
