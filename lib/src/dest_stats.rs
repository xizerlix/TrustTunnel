use crate::net_utils::TcpDestination;
use chrono::Datelike;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

const DAY_SLOTS: usize = 32;
const HOUR_SLOTS: usize = 48;
const MAX_DOMAINS_PER_USER: usize = 48;
pub(crate) const TOP_N: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DestPeriod {
    Hour,
    Today,
    Week,
    Month,
    All,
}

impl DestPeriod {
    fn window_days(self) -> Option<u32> {
        match self {
            Self::Hour => None,
            Self::Today => Some(1),
            Self::Week => Some(7),
            Self::Month => Some(31),
            Self::All => None,
        }
    }
}

#[derive(Clone)]
struct DomainEntry {
    total: u64,
    slots: [u32; DAY_SLOTS],
    days: [u32; DAY_SLOTS],
    hour_slots: [u32; HOUR_SLOTS],
    hours: [u32; HOUR_SLOTS],
}

impl Default for DomainEntry {
    fn default() -> Self {
        Self {
            total: 0,
            slots: [0; DAY_SLOTS],
            days: [0; DAY_SLOTS],
            hour_slots: [0; HOUR_SLOTS],
            hours: [0; HOUR_SLOTS],
        }
    }
}

impl DomainEntry {
    fn add(&mut self, day: u32, hour: u32, n: u32) {
        let i = (day as usize) % DAY_SLOTS;
        if self.days[i] != day {
            self.slots[i] = 0;
            self.days[i] = day;
        }
        self.slots[i] = self.slots[i].saturating_add(n);
        let hi = (hour as usize) % HOUR_SLOTS;
        if self.hours[hi] != hour {
            self.hour_slots[hi] = 0;
            self.hours[hi] = hour;
        }
        self.hour_slots[hi] = self.hour_slots[hi].saturating_add(n);
        self.total = self.total.saturating_add(u64::from(n));
    }

    fn in_window(&self, today: u32, hour: u32, period: DestPeriod) -> u64 {
        match period {
            DestPeriod::All => self.total,
            DestPeriod::Hour => {
                let mut sum = 0u64;
                for i in 0..HOUR_SLOTS {
                    if self.hours[i] != 0 && hour.saturating_sub(self.hours[i]) < 1 {
                        sum += u64::from(self.hour_slots[i]);
                    }
                }
                sum
            }
            _ => {
                let days = period.window_days().unwrap_or(0);
                let mut sum = 0u64;
                for i in 0..DAY_SLOTS {
                    if self.days[i] != 0 && today.saturating_sub(self.days[i]) < days {
                        sum += u64::from(self.slots[i]);
                    }
                }
                sum
            }
        }
    }
}

type UserMap = HashMap<String, HashMap<String, DomainEntry>>;

pub(crate) struct DestinationStats {
    users: Arc<Mutex<UserMap>>,
    path: Option<PathBuf>,
    stop_persist: Arc<AtomicBool>,
    dirty: Arc<AtomicBool>,
    persist_thread: Mutex<Option<JoinHandle<()>>>,
}

impl DestinationStats {
    pub fn new(path: Option<PathBuf>) -> Arc<Self> {
        let users = Arc::new(Mutex::new(load_file(path.as_deref())));
        let stop_persist = Arc::new(AtomicBool::new(false));
        let dirty = Arc::new(AtomicBool::new(false));
        let persist_thread = Mutex::new(None);
        let stats = Arc::new(Self {
            users: users.clone(),
            path: path.clone(),
            stop_persist: stop_persist.clone(),
            dirty: dirty.clone(),
            persist_thread,
        });
        if let Some(path) = path {
            log::info!("Destination visit stats file: {}", path.display());
            let handle = std::thread::Builder::new()
                .name("tt-dest-stats".into())
                .spawn(move || {
                    while !stop_persist.load(Ordering::Relaxed) {
                        for _ in 0..30 {
                            if stop_persist.load(Ordering::Relaxed) {
                                return;
                            }
                            std::thread::sleep(Duration::from_secs(1));
                        }
                        persist_map(&users, &path, &dirty, false);
                    }
                })
                .ok();
            *stats.persist_thread.lock().unwrap() = handle;
        }
        stats
    }

    pub fn record_destination(&self, username: &str, destination: &TcpDestination) -> bool {
        let host = match destination {
            TcpDestination::HostName((host, _)) => host.as_str(),
            TcpDestination::Address(_) => return false,
        };
        self.record(username, host, local_day_id(), local_hour_id());
        true
    }

    pub fn record_host(&self, username: &str, host: &str) {
        self.record(username, host, local_day_id(), local_hour_id());
    }

    fn record(&self, username: &str, host: &str, day: u32, hour: u32) {
        let Some(host) = normalize_host(host) else {
            return;
        };
        if username.is_empty() {
            return;
        }
        let mut users = self.users.lock().unwrap();
        let map = users.entry(username.to_string()).or_default();
        if !map.contains_key(&host) && map.len() >= MAX_DOMAINS_PER_USER {
            let victim = map
                .iter()
                .min_by_key(|(_, e)| e.total)
                .map(|(k, _)| k.clone());
            if let Some(victim) = victim {
                map.remove(&victim);
            }
        }
        map.entry(host).or_default().add(day, hour, 1);
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub(crate) fn top(
        &self,
        username: &str,
        period: DestPeriod,
        day: u32,
        hour: u32,
    ) -> Vec<(String, u64)> {
        let users = self.users.lock().unwrap();
        let Some(map) = users.get(username) else {
            return Vec::new();
        };
        rank_domains(map, period, day, hour)
    }

    pub(crate) fn persist_now(&self) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        persist_map(&self.users, path, &self.dirty, true);
    }
}

impl Drop for DestinationStats {
    fn drop(&mut self) {
        self.stop_persist.store(true, Ordering::Relaxed);
        if let Some(handle) = self.persist_thread.lock().unwrap().take() {
            let _ = handle.join();
        }
        self.persist_now();
    }
}

fn rank_domains(
    map: &HashMap<String, DomainEntry>,
    period: DestPeriod,
    day: u32,
    hour: u32,
) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = map
        .iter()
        .filter_map(|(host, entry)| {
            let n = entry.in_window(day, hour, period);
            (n > 0).then(|| (host.clone(), n))
        })
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(TOP_N);
    rows
}

pub(crate) fn local_day_id() -> u32 {
    chrono::Local::now()
        .date_naive()
        .num_days_from_ce()
        .max(0) as u32
}

fn local_hour_id() -> u32 {
    (chrono::Local::now().timestamp().max(0) as u64 / 3600) as u32
}

pub(crate) fn normalize_host(raw: &str) -> Option<String> {
    let mut host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(stripped) = host.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            host = stripped[..end].to_string();
        }
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if let Some(rest) = host.strip_prefix("www.") {
        host = rest.to_string();
    }
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    if host.ends_with(".arpa") || host.ends_with(".local") {
        return None;
    }
    if host.len() > 253 {
        return None;
    }
    Some(registrable(&host))
}

pub(crate) const TLS_SNI_MAX: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsSniScan {
    Found,
    NeedMore,
    GiveUp,
}

pub(crate) fn scan_tls_sni(buf: &[u8]) -> (TlsSniScan, Option<String>) {
    if buf.is_empty() {
        return (TlsSniScan::NeedMore, None);
    }
    if buf[0] != 0x16 {
        return (TlsSniScan::GiveUp, None);
    }
    if buf.len() < 5 {
        return (TlsSniScan::NeedMore, None);
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if rec_len == 0 || rec_len > TLS_SNI_MAX {
        return (TlsSniScan::GiveUp, None);
    }
    if buf.len() < 5 + rec_len {
        return (TlsSniScan::NeedMore, None);
    }
    match sni_from_handshake(&buf[5..5 + rec_len]) {
        Some(host) => (TlsSniScan::Found, Some(host)),
        None => (TlsSniScan::GiveUp, None),
    }
}

fn sni_from_handshake(hs: &[u8]) -> Option<String> {
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    if hs.len() < 4 + hs_len {
        return None;
    }
    let mut p = &hs[4..4 + hs_len];
    if p.len() < 34 {
        return None;
    }
    p = &p[34..];
    let sid_len = *p.first()? as usize;
    p = p.get(1 + sid_len..)?;
    if p.len() < 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([p[0], p[1]]) as usize;
    p = p.get(2 + cs_len..)?;
    let comp_len = *p.first()? as usize;
    p = p.get(1 + comp_len..)?;
    if p.len() < 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([p[0], p[1]]) as usize;
    p = p.get(2..2 + ext_len.min(p.len().saturating_sub(2)))?;
    let mut rest = p;
    while rest.len() >= 4 {
        let ext_type = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        rest = rest.get(4..)?;
        if rest.len() < len {
            break;
        }
        let body = &rest[..len];
        rest = &rest[len..];
        if ext_type == 0 {
            return sni_from_extension(body);
        }
    }
    None
}

fn sni_from_extension(body: &[u8]) -> Option<String> {
    if body.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut rest = body.get(2..2 + list_len.min(body.len().saturating_sub(2)))?;
    while rest.len() >= 3 {
        let name_type = rest[0];
        let name_len = u16::from_be_bytes([rest[1], rest[2]]) as usize;
        rest = rest.get(3..)?;
        if rest.len() < name_len {
            break;
        }
        if name_type == 0 {
            return String::from_utf8(rest[..name_len].to_vec()).ok();
        }
        rest = &rest[name_len..];
    }
    None
}

pub(crate) fn dns_question_names(payload: &[u8]) -> Vec<String> {
    if payload.len() < 12 {
        return Vec::new();
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return Vec::new();
    }
    let qd = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let mut pos = 12;
    let mut names = Vec::new();
    for _ in 0..qd.min(4) {
        let Some((name, next)) = read_dns_name(payload, pos) else {
            break;
        };
        pos = next.saturating_add(4);
        if pos > payload.len() {
            break;
        }
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

fn read_dns_name(packet: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end = pos;
    for _ in 0..16 {
        let len = *packet.get(pos)? as usize;
        if len == 0 {
            if !jumped {
                end = pos + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let b2 = *packet.get(pos + 1)?;
            let ptr = (((len & 0x3f) as usize) << 8) | b2 as usize;
            if !jumped {
                end = pos + 2;
                jumped = true;
            }
            pos = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let start = pos + 1;
        let label = packet.get(start..start + len)?;
        labels.push(std::str::from_utf8(label).ok()?.to_string());
        pos = start + len;
        if !jumped {
            end = pos;
        }
    }
    Some((labels.join("."), end))
}

fn registrable(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 {
        return host.to_string();
    }
    let last = labels[labels.len() - 1];
    let second = labels[labels.len() - 2];
    const MULTI: &[&str] = &["co", "com", "net", "org", "gov", "ac", "edu"];
    if last.len() == 2 && MULTI.contains(&second) && labels.len() >= 3 {
        return labels[labels.len() - 3..].join(".");
    }
    labels[labels.len() - 2..].join(".")
}

#[derive(Serialize, Deserialize, Default)]
struct FileDomain {
    total: u64,
    #[serde(default)]
    days: HashMap<String, u32>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    hours: HashMap<String, u32>,
}

fn load_file(path: Option<&Path>) -> UserMap {
    let Some(path) = path else {
        return HashMap::new();
    };
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };
    let stored: HashMap<String, HashMap<String, FileDomain>> = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Couldn't parse destination stats {}: {}", path.display(), e);
            return HashMap::new();
        }
    };
    stored
        .into_iter()
        .map(|(user, domains)| {
            let mapped = domains
                .into_iter()
                .map(|(host, rec)| {
                    let mut entry = DomainEntry {
                        total: rec.total,
                        ..DomainEntry::default()
                    };
                    for (k, n) in rec.days {
                        if let Ok(day) = k.parse::<u32>() {
                            let i = (day as usize) % DAY_SLOTS;
                            entry.days[i] = day;
                            entry.slots[i] = n;
                        }
                    }
                    for (k, n) in rec.hours {
                        if let Ok(hour) = k.parse::<u32>() {
                            let i = (hour as usize) % HOUR_SLOTS;
                            entry.hours[i] = hour;
                            entry.hour_slots[i] = n;
                        }
                    }
                    (host, entry)
                })
                .collect();
            (user, mapped)
        })
        .collect()
}

fn persist_map(users: &Mutex<UserMap>, path: &Path, dirty: &AtomicBool, force: bool) {
    if !force && !dirty.swap(false, Ordering::AcqRel) {
        return;
    }
    if force {
        dirty.store(false, Ordering::Relaxed);
    }
    let snapshot = users.lock().unwrap();
    let stored: HashMap<String, HashMap<String, FileDomain>> = snapshot
        .iter()
        .map(|(user, domains)| {
            let recs = domains
                .iter()
                .map(|(host, entry)| {
                    let mut days = HashMap::new();
                    for i in 0..DAY_SLOTS {
                        if entry.days[i] != 0 && entry.slots[i] > 0 {
                            days.insert(entry.days[i].to_string(), entry.slots[i]);
                        }
                    }
                    let mut hours = HashMap::new();
                    for i in 0..HOUR_SLOTS {
                        if entry.hours[i] != 0 && entry.hour_slots[i] > 0 {
                            hours.insert(entry.hours[i].to_string(), entry.hour_slots[i]);
                        }
                    }
                    (
                        host.clone(),
                        FileDomain {
                            total: entry.total,
                            days,
                            hours,
                        },
                    )
                })
                .collect();
            (user.clone(), recs)
        })
        .collect();
    drop(snapshot);
    let content = match serde_json::to_string(&stored) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Couldn't serialize destination stats: {}", e);
            return;
        }
    };
    if let Err(e) = std::fs::write(path, content) {
        log::warn!(
            "Couldn't write destination stats {}: {}",
            path.display(),
            e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_utils::TcpDestination;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tempfile::NamedTempFile;

    #[test]
    fn normalize_collapses_subdomains() {
        assert_eq!(
            normalize_host("www.Instagram.com."),
            Some("instagram.com".into())
        );
        assert_eq!(
            normalize_host("i.instagram.com"),
            Some("instagram.com".into())
        );
        assert_eq!(normalize_host("bbc.co.uk"), Some("bbc.co.uk".into()));
        assert_eq!(normalize_host("1.2.3.4"), None);
        assert_eq!(normalize_host("localhost"), None);
        assert_eq!(normalize_host("1.0.0.127.in-addr.arpa"), None);
    }

    #[test]
    fn ranks_today_and_all_time() {
        let stats = DestinationStats::new(None);
        stats.record("alice", "instagram.com", 100, 10);
        stats.record("alice", "instagram.com", 100, 10);
        stats.record("alice", "youtube.com", 100, 10);
        stats.record("alice", "old.example", 90, 10);
        let today = stats.top("alice", DestPeriod::Today, 100, 10);
        assert_eq!(
            today,
            vec![
                ("instagram.com".into(), 2),
                ("youtube.com".into(), 1),
            ]
        );
        let all = stats.top("alice", DestPeriod::All, 100, 10);
        assert_eq!(all[0], ("instagram.com".into(), 2));
        assert!(all.iter().any(|(h, n)| h == "old.example" && *n == 1));
    }

    #[test]
    fn ranks_current_hour() {
        let stats = DestinationStats::new(None);
        stats.record("alice", "instagram.com", 100, 50);
        stats.record("alice", "instagram.com", 100, 50);
        stats.record("alice", "youtube.com", 100, 49);
        let hour = stats.top("alice", DestPeriod::Hour, 100, 50);
        assert_eq!(hour, vec![("instagram.com".into(), 2)]);
    }

    #[test]
    fn ignores_ip_destinations() {
        let stats = DestinationStats::new(None);
        assert!(!stats.record_destination(
            "alice",
            &TcpDestination::Address(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443)),
        ));
        stats.record_destination(
            "alice",
            &TcpDestination::HostName(("cdn.tiktok.com".into(), 443)),
        );
        let top = stats.top("alice", DestPeriod::All, local_day_id(), 0);
        assert_eq!(top, vec![("tiktok.com".into(), 1)]);
    }

    fn client_hello_with_sni(sni: &str) -> Vec<u8> {
        let mut hello_body = Vec::new();
        hello_body.extend([0x03, 0x03]);
        hello_body.extend([0u8; 32]);
        hello_body.push(0);
        hello_body.extend([0x00, 0x02, 0x00, 0x2f]);
        hello_body.push(1);
        hello_body.push(0);
        let mut sni_list = Vec::new();
        sni_list.push(0);
        sni_list.extend((sni.len() as u16).to_be_bytes());
        sni_list.extend(sni.as_bytes());
        let mut sni_data = Vec::new();
        sni_data.extend((sni_list.len() as u16).to_be_bytes());
        sni_data.extend(sni_list);
        let mut extensions = Vec::new();
        extensions.extend([0x00, 0x00]);
        extensions.extend((sni_data.len() as u16).to_be_bytes());
        extensions.extend(sni_data);
        hello_body.extend((extensions.len() as u16).to_be_bytes());
        hello_body.extend(extensions);
        let mut handshake = vec![0x01];
        let hs_len = hello_body.len() as u32;
        handshake.push(((hs_len >> 16) & 0xff) as u8);
        handshake.push(((hs_len >> 8) & 0xff) as u8);
        handshake.push((hs_len & 0xff) as u8);
        handshake.extend(hello_body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }

    #[test]
    fn parses_sni_from_client_hello() {
        let pkt = client_hello_with_sni("www.youtube.com");
        let (scan, host) = scan_tls_sni(&pkt);
        assert_eq!(scan, TlsSniScan::Found);
        assert_eq!(host.as_deref(), Some("www.youtube.com"));
        assert_eq!(scan_tls_sni(&pkt[..8]).0, TlsSniScan::NeedMore);
        assert_eq!(scan_tls_sni(b"GET /").0, TlsSniScan::GiveUp);
    }

    #[test]
    fn parses_dns_question() {
        let mut q = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["i", "instagram", "com"] {
            q.push(label.len() as u8);
            q.extend(label.as_bytes());
        }
        q.push(0);
        q.extend([0, 1, 0, 1]);
        assert_eq!(
            dns_question_names(&q),
            vec!["i.instagram.com".to_string()]
        );
        let mut resp = q.clone();
        resp[2] = 0x81;
        assert!(dns_question_names(&resp).is_empty());
    }

    #[test]
    fn persists_and_reloads() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        {
            let stats = DestinationStats::new(Some(path.clone()));
            stats.record("bob", "example.com", 50, 3);
            stats.persist_now();
        }
        let reloaded = DestinationStats::new(Some(path));
        assert_eq!(
            reloaded.top("bob", DestPeriod::All, 50, 3),
            vec![("example.com".into(), 1)]
        );
    }

    #[test]
    fn evicts_least_used_at_cap() {
        let stats = DestinationStats::new(None);
        for i in 0..MAX_DOMAINS_PER_USER {
            stats.record("u", &format!("site{i}.com"), 1, 1);
        }
        stats.record("u", "later.com", 1, 1);
        let map = stats.users.lock().unwrap();
        let user = map.get("u").unwrap();
        assert_eq!(user.len(), MAX_DOMAINS_PER_USER);
        assert!(user.contains_key("later.com"));
    }
}
