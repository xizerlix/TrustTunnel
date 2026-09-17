use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

const SCRIPT_CANDIDATES: &[&str] = &[
    "/root/bot_listener.sh",
    "/root/telegram_vpn_bot.sh",
    "/opt/trusttunnel/bot_listener.sh",
    "/opt/trusttunnel/scripts/telegram_vpn_bot.sh",
];

#[derive(Clone)]
pub struct Telegram {
    token: String,
    chat_id: String,
}

impl Telegram {
    pub fn load() -> Option<Self> {
        let mut token = env_nonempty("TT_TELEGRAM_BOT_TOKEN");
        let mut chat_id = env_nonempty("TT_TELEGRAM_CHAT_ID").or_else(|| env_nonempty("TT_TELEGRAM_CHAT"));
        if token.is_none() || chat_id.is_none() {
            if let Some(script) = script_path() {
                if let Ok(src) = std::fs::read_to_string(&script) {
                    if token.is_none() {
                        token = parse_assign(&src, "TOKEN");
                    }
                    if chat_id.is_none() {
                        chat_id = parse_assign(&src, "MY_CHAT_ID")
                            .or_else(|| parse_assign(&src, "CHAT_ID"));
                    }
                }
            }
        }
        Some(Self {
            token: token.filter(|s| !s.is_empty())?,
            chat_id: chat_id.filter(|s| !s.is_empty())?,
        })
    }

    pub fn notify_login_ok(&self, ip: IpAddr) {
        self.send(&format!(
            "✅ *Админка*: успешный вход\n🌐 IP: `{}`",
            md_code(&ip.to_string())
        ));
    }

    pub fn notify_login_fail(&self, ip: IpAddr, username: &str) {
        self.send(&format!(
            "❌ *Админка*: неверный пароль\n👤 логин: `{}`\n🌐 IP: `{}`",
            md_code(&sanitize_user(username)),
            md_code(&ip.to_string())
        ));
    }

    pub fn notify_login_limited(&self, ip: IpAddr) {
        self.send(&format!(
            "🚫 *Админка*: слишком много попыток входа\n🌐 IP: `{}`",
            md_code(&ip.to_string())
        ));
    }

    fn send(&self, text: &str) {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        let _ = Command::new("curl")
            .args([
                "-s",
                "--connect-timeout",
                "5",
                "--max-time",
                "8",
                "-X",
                "POST",
                &url,
                "--data-urlencode",
                &format!("chat_id={}", self.chat_id),
                "--data-urlencode",
                &format!("text={text}"),
                "--data-urlencode",
                "parse_mode=Markdown",
            ])
            .output();
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn script_path() -> Option<PathBuf> {
    if let Some(p) = env_nonempty("TT_TELEGRAM_SCRIPT") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    SCRIPT_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

pub fn parse_assign(src: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for line in src.lines() {
        let mut line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim();
        }
        let Some(rest) = line.strip_prefix(&prefix) else {
            continue;
        };
        let rest = rest.trim();
        let val = if rest.len() >= 2
            && ((rest.starts_with('"') && rest.ends_with('"'))
                || (rest.starts_with('\'') && rest.ends_with('\'')))
        {
            rest[1..rest.len() - 1].to_string()
        } else {
            rest.split_whitespace().next().unwrap_or("").to_string()
        };
        if !val.is_empty() {
            return Some(val);
        }
    }
    None
}

fn sanitize_user(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(32).collect()
}

fn md_code(s: &str) -> String {
    s.replace('`', "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_and_chat_from_bot_listener() {
        let src = r#"
# TOKEN="skip"
TOKEN="123:ABC"
MY_CHAT_ID="999"
IP_SERVER="1.2.3.4"
"#;
        assert_eq!(parse_assign(src, "TOKEN").as_deref(), Some("123:ABC"));
        assert_eq!(parse_assign(src, "MY_CHAT_ID").as_deref(), Some("999"));
    }

    #[test]
    fn parse_export_and_single_quotes() {
        let src = "export TOKEN='aa:bb'\nCHAT_ID=42\n";
        assert_eq!(parse_assign(src, "TOKEN").as_deref(), Some("aa:bb"));
        assert_eq!(parse_assign(src, "CHAT_ID").as_deref(), Some("42"));
    }

    #[test]
    fn parse_ignores_empty() {
        assert_eq!(parse_assign("TOKEN=\"\"\n", "TOKEN"), None);
    }

    #[test]
    fn md_code_strips_backticks() {
        assert_eq!(md_code("a`b"), "a'b");
    }
}
