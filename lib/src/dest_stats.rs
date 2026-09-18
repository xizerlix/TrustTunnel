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
const MAX_DOMAINS_PER_USER: usize = 48;
pub(crate) const TOP_N: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DestPeriod {
    Today,
    Week,
    Month,
    All,
}

impl DestPeriod {
    fn window_days(self) -> Option<u32> {
        match self {
            Self::Today => Some(1),
            Self::Week => Some(7),
            Self::Month => Some(31),
            Self::All => None,
        }
    }
}

#[derive(Clone, Default)]
struct DomainEntry {
    total: u64,
    slots: [u32; DAY_SLOTS],
    days: [u32; DAY_SLOTS],
}

impl DomainEntry {
    fn add(&mut self, day: u32, n: u32) {
        let i = (day as usize) % DAY_SLOTS;
        if self.days[i] != day {
            self.slots[i] = 0;
            self.days[i] = day;
        }
        self.slots[i] = self.slots[i].saturating_add(n);
        self.total = self.total.saturating_add(u64::from(n));
    }

    fn in_window(&self, today: u32, window: Option<u32>) -> u64 {
        match window {
            None => self.total,
            Some(days) => {
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

    pub fn record_destination(&self, username: &str, destination: &TcpDestination) {
        let host = match destination {
            TcpDestination::HostName((host, _)) => host.as_str(),
            TcpDestination::Address(_) => return,
        };
        self.record(username, host, local_day_id());
    }

    fn record(&self, username: &str, host: &str, day: u32) {
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
        map.entry(host).or_default().add(day, 1);
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub(crate) fn top(&self, username: &str, period: DestPeriod, day: u32) -> Vec<(String, u64)> {
        let users = self.users.lock().unwrap();
        let Some(map) = users.get(username) else {
            return Vec::new();
        };
        rank_domains(map, period, day)
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
) -> Vec<(String, u64)> {
    let window = period.window_days();
    let mut rows: Vec<(String, u64)> = map
        .iter()
        .filter_map(|(host, entry)| {
            let n = entry.in_window(day, window);
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
    if host.len() > 253 {
        return None;
    }
    Some(registrable(&host))
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
                    (
                        host.clone(),
                        FileDomain {
                            total: entry.total,
                            days,
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
    }

    #[test]
    fn ranks_today_and_all_time() {
        let stats = DestinationStats::new(None);
        stats.record("alice", "instagram.com", 100);
        stats.record("alice", "instagram.com", 100);
        stats.record("alice", "youtube.com", 100);
        stats.record("alice", "old.example", 90);
        let today = stats.top("alice", DestPeriod::Today, 100);
        assert_eq!(
            today,
            vec![
                ("instagram.com".into(), 2),
                ("youtube.com".into(), 1),
            ]
        );
        let all = stats.top("alice", DestPeriod::All, 100);
        assert_eq!(all[0], ("instagram.com".into(), 2));
        assert!(all.iter().any(|(h, n)| h == "old.example" && *n == 1));
    }

    #[test]
    fn ignores_ip_destinations() {
        let stats = DestinationStats::new(None);
        stats.record_destination(
            "alice",
            &TcpDestination::Address(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443)),
        );
        stats.record_destination(
            "alice",
            &TcpDestination::HostName(("cdn.tiktok.com".into(), 443)),
        );
        let top = stats.top("alice", DestPeriod::All, local_day_id());
        assert_eq!(top, vec![("tiktok.com".into(), 1)]);
    }

    #[test]
    fn persists_and_reloads() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        {
            let stats = DestinationStats::new(Some(path.clone()));
            stats.record("bob", "example.com", 50);
            stats.persist_now();
        }
        let reloaded = DestinationStats::new(Some(path));
        assert_eq!(
            reloaded.top("bob", DestPeriod::All, 50),
            vec![("example.com".into(), 1)]
        );
    }

    #[test]
    fn evicts_least_used_at_cap() {
        let stats = DestinationStats::new(None);
        for i in 0..MAX_DOMAINS_PER_USER {
            stats.record("u", &format!("site{i}.com"), 1);
        }
        stats.record("u", "later.com", 1);
        let map = stats.users.lock().unwrap();
        let user = map.get("u").unwrap();
        assert_eq!(user.len(), MAX_DOMAINS_PER_USER);
        assert!(user.contains_key("later.com"));
    }
}
