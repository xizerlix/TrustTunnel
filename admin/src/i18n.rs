use axum::http::HeaderMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Ru,
}

impl Lang {
    pub fn as_str(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ru => "ru",
        }
    }
}

#[derive(Clone, Copy)]
pub struct I18n {
    pub nav_dashboard: &'static str,
    pub nav_vpn: &'static str,
    pub nav_hosts: &'static str,
    pub nav_users: &'static str,
    pub nav_rules: &'static str,
    pub nav_logs: &'static str,
    pub nav_settings: &'static str,
    pub logout: &'static str,
    pub sign_in: &'static str,
    pub username: &'static str,
    pub password: &'static str,
    pub invalid_login: &'static str,
    pub too_many_logins: &'static str,
    pub dashboard: &'static str,
    pub service: &'static str,
    pub active_users_ips: &'static str,
    pub active_sessions: &'static str,
    pub traffic_period: &'static str,
    pub per_user: &'static str,
    pub no_users: &'static str,
    pub offline: &'static str,
    pub sessions: &'static str,
    pub ips: &'static str,
    pub traffic_used: &'static str,
    pub quota: &'static str,
    pub host: &'static str,
    pub version: &'static str,
    pub cpu: &'static str,
    pub ram: &'static str,
    pub disk: &'static str,
    pub host_uptime: &'static str,
    pub certificates: &'static str,
    pub cert_missing: &'static str,
    pub expires: &'static str,
    pub vpn_settings: &'static str,
    pub save_restart: &'static str,
    pub save_reload: &'static str,
    pub saving: &'static str,
    pub tls_hosts: &'static str,
    pub hostname: &'static str,
    pub cert_path: &'static str,
    pub key_path: &'static str,
    pub allowed_sni: &'static str,
    pub sni_help: &'static str,
    pub users: &'static str,
    pub new_user: &'static str,
    pub traffic_gb: &'static str,
    pub traffic_gb_help: &'static str,
    pub deeplink: &'static str,
    pub deeplink_copied: &'static str,
    pub deeplink_failed: &'static str,
    pub delete: &'static str,
    pub delete_confirm: &'static str,
    pub rules: &'static str,
    pub rules_help: &'static str,
    pub cidr: &'static str,
    pub prefix: &'static str,
    pub action: &'static str,
    pub logs: &'static str,
    pub lines: &'static str,
    pub auto_refresh: &'static str,
    pub refresh: &'static str,
    pub system_logs: &'static str,
    pub tab_service: &'static str,
    pub tab_htop: &'static str,
    pub settings: &'static str,
    pub change_password: &'static str,
    pub current_password: &'static str,
    pub new_password: &'static str,
    pub confirm_password: &'static str,
    pub update_password: &'static str,
    pub password_updated: &'static str,
    pub mobile: &'static str,
    pub home: &'static str,
    pub proxy: &'static str,
    pub hosting: &'static str,
    pub up: &'static str,
    pub down: &'static str,
    pub unlimited: &'static str,
}

pub const EN: I18n = I18n {
    nav_dashboard: "Dashboard",
    nav_vpn: "VPN settings",
    nav_hosts: "TLS hosts",
    nav_users: "Users",
    nav_rules: "Rules",
    nav_logs: "Logs",
    nav_settings: "Settings",
    logout: "Logout",
    sign_in: "Sign in",
    username: "Username",
    password: "Password",
    invalid_login: "Invalid credentials",
    too_many_logins: "Too many login attempts. Try again in a minute.",
    dashboard: "Dashboard",
    service: "Service",
    active_users_ips: "Active users / Unique IPs",
    active_sessions: "Active sessions",
    traffic_period: "Traffic this period",
    per_user: "Per-user summary",
    no_users: "No users configured.",
    offline: "offline",
    sessions: "Sessions",
    ips: "IPs",
    traffic_used: "Traffic used",
    quota: "Quota",
    host: "Host",
    version: "Version",
    cpu: "CPU load",
    ram: "RAM",
    disk: "Disk",
    host_uptime: "Host uptime",
    certificates: "Certificate",
    cert_missing: "Certificate details unavailable",
    expires: "expires",
    vpn_settings: "VPN settings",
    save_restart: "Save & restart",
    save_reload: "Save & reload",
    saving: "Saving… this restarts the VPN and may take a while.",
    tls_hosts: "TLS hosts",
    hostname: "Hostname",
    cert_path: "Cert chain path",
    key_path: "Private key path",
    allowed_sni: "Alternate SNI names",
    sni_help: "SNI is the hostname the client sends in the TLS handshake. Leave empty to accept only the hostname above. Add extra names (one per line) if clients use a custom SNI / domain front so DPI sees a different site while the cert still matches.",
    users: "Users",
    new_user: "new username",
    traffic_gb: "Quota (GiB)",
    traffic_gb_help: "Monthly traffic cap in gibibytes (in+out). Empty or 0 = unlimited. Stored as bytes in credentials.toml.",
    deeplink: "Copy deeplink",
    deeplink_copied: "Deeplink copied to clipboard",
    deeplink_failed: "Could not copy deeplink",
    delete: "delete",
    delete_confirm: "Delete this row?",
    rules: "Rules",
    rules_help: "First matching rule wins. Empty rows are ignored. Each rule needs a CIDR and/or a client-random prefix.",
    cidr: "CIDR",
    prefix: "Client random prefix",
    action: "Action",
    logs: "Logs",
    lines: "Lines",
    auto_refresh: "Auto-refresh",
    refresh: "Refresh",
    system_logs: "Show system journal (all units)",
    tab_service: "Service logs",
    tab_htop: "htop",
    settings: "Settings",
    change_password: "Change admin password",
    current_password: "Current password",
    new_password: "New password (min 10 chars)",
    confirm_password: "Confirm new password",
    update_password: "Update password",
    password_updated: "Password updated",
    mobile: "mobile",
    home: "home",
    proxy: "proxy",
    hosting: "hosting",
    up: "up",
    down: "down",
    unlimited: "unlimited",
};

pub const RU: I18n = I18n {
    nav_dashboard: "Дашборд",
    nav_vpn: "Настройки VPN",
    nav_hosts: "TLS-хосты",
    nav_users: "Пользователи",
    nav_rules: "Правила",
    nav_logs: "Логи",
    nav_settings: "Настройки",
    logout: "Выйти",
    sign_in: "Войти",
    username: "Имя",
    password: "Пароль",
    invalid_login: "Неверный логин или пароль",
    too_many_logins: "Слишком много попыток. Подождите минуту.",
    dashboard: "Дашборд",
    service: "Сервис",
    active_users_ips: "Активные / уникальные IP",
    active_sessions: "Активные сессии",
    traffic_period: "Трафик за период",
    per_user: "По пользователям",
    no_users: "Нет пользователей.",
    offline: "офлайн",
    sessions: "Сессии",
    ips: "IP",
    traffic_used: "Трафик",
    quota: "Квота",
    host: "Сервер",
    version: "Версия",
    cpu: "Нагрузка CPU",
    ram: "RAM",
    disk: "Диск",
    host_uptime: "Аптайм хоста",
    certificates: "Сертификат",
    cert_missing: "Нет данных о сертификате",
    expires: "до",
    vpn_settings: "Настройки VPN",
    save_restart: "Сохранить и перезапустить",
    save_reload: "Сохранить и перечитать",
    saving: "Сохранение… VPN перезапускается, это может занять время.",
    tls_hosts: "TLS-хосты",
    hostname: "Имя хоста",
    cert_path: "Цепочка сертификата",
    key_path: "Приватный ключ",
    allowed_sni: "Доп. SNI-имена",
    sni_help: "SNI — имя, которое клиент шлёт в TLS ClientHello. Пустое поле: принимается только hostname слева. Дополнительные имена (по одному в строке) нужны, если клиент ставит custom SNI / domain fronting: снаружи виден чужой сайт, а сертификат всё равно подходит.",
    users: "Пользователи",
    new_user: "новый логин",
    traffic_gb: "Квота (ГиБ)",
    traffic_gb_help: "Лимит трафика за месяц в гибибайтах (вход+выход). Пусто или 0 — без лимита. В credentials.toml пишется в байтах.",
    deeplink: "Скопировать диплинк",
    deeplink_copied: "Диплинк скопирован",
    deeplink_failed: "Не удалось скопировать диплинк",
    delete: "удалить",
    delete_confirm: "Удалить эту строку?",
    rules: "Правила",
    rules_help: "Срабатывает первое совпадение. Пустые строки игнорируются. У правила должен быть CIDR и/или префикс client random.",
    cidr: "CIDR",
    prefix: "Префикс client random",
    action: "Действие",
    logs: "Логи",
    lines: "Строк",
    auto_refresh: "Автообновление",
    refresh: "Обновить",
    system_logs: "Системный журнал (все юниты)",
    tab_service: "Логи сервиса",
    tab_htop: "htop",
    settings: "Настройки",
    change_password: "Сменить пароль админа",
    current_password: "Текущий пароль",
    new_password: "Новый пароль (от 10 символов)",
    confirm_password: "Повтор нового пароля",
    update_password: "Обновить пароль",
    password_updated: "Пароль обновлён",
    mobile: "мобильный",
    home: "домашний",
    proxy: "прокси",
    hosting: "хостинг",
    up: "аптайм",
    down: "лежит",
    unlimited: "без лимита",
};

pub const LANG_COOKIE: &str = "tt_admin_lang";

pub fn from_headers(headers: &HeaderMap) -> Lang {
    if let Some(c) = cookie_lang(headers) {
        return c;
    }
    let accept = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if accept.to_ascii_lowercase().contains("ru") {
        Lang::Ru
    } else {
        Lang::En
    }
}

fn cookie_lang(headers: &HeaderMap) -> Option<Lang> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .find_map(|c| c.strip_prefix(&format!("{LANG_COOKIE}=")).map(str::trim))
        .and_then(|v| match v {
            "ru" => Some(Lang::Ru),
            "en" => Some(Lang::En),
            _ => None,
        })
}

pub fn parse_set(v: &str) -> Option<Lang> {
    match v {
        "ru" => Some(Lang::Ru),
        "en" => Some(Lang::En),
        _ => None,
    }
}

pub fn t(lang: Lang) -> I18n {
    match lang {
        Lang::En => EN,
        Lang::Ru => RU,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn cookie_wins_over_accept() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("tt_admin_lang=en"),
        );
        h.insert(
            axum::http::header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("ru,en;q=0.8"),
        );
        assert_eq!(from_headers(&h), Lang::En);
    }
}
