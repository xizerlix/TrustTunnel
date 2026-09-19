use chrono::Datelike;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const TOP_N: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestPeriod {
    Today,
    Week,
    Month,
    All,
}

impl DestPeriod {
    pub fn parse(s: &str) -> Self {
        match s {
            "week" => Self::Week,
            "month" => Self::Month,
            "all" => Self::All,
            _ => Self::Today,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Today => "today",
            Self::Week => "week",
            Self::Month => "month",
            Self::All => "all",
        }
    }

    fn window_days(self) -> Option<u32> {
        match self {
            Self::Today => Some(1),
            Self::Week => Some(7),
            Self::Month => Some(31),
            Self::All => None,
        }
    }
}

#[derive(Deserialize, Default)]
struct FileDomain {
    #[serde(default)]
    total: u64,
    #[serde(default)]
    days: HashMap<String, u32>,
}

pub fn local_day_id() -> u32 {
    chrono::Local::now()
        .date_naive()
        .num_days_from_ce()
        .max(0) as u32
}

pub fn top_for_user(
    path: &Path,
    username: &str,
    period: DestPeriod,
    today: u32,
) -> Vec<(String, u64)> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    rank_user_json(&content, username, period, today)
}

pub fn rank_user_json(
    json: &str,
    username: &str,
    period: DestPeriod,
    today: u32,
) -> Vec<(String, u64)> {
    let stored: HashMap<String, HashMap<String, FileDomain>> =
        match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
    let Some(map) = stored.get(username) else {
        return Vec::new();
    };
    let window = period.window_days();
    rank_counts(map.iter().map(|(h, rec)| (h.clone(), count_record(rec, window, today))))
}

pub fn top_all(
    path: &Path,
    period: DestPeriod,
    today: u32,
) -> Vec<(String, u64)> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    rank_all_json(&content, period, today)
}

pub fn rank_all_json(json: &str, period: DestPeriod, today: u32) -> Vec<(String, u64)> {
    let stored: HashMap<String, HashMap<String, FileDomain>> =
        match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
    let window = period.window_days();
    let mut counts: HashMap<String, u64> = HashMap::new();
    for map in stored.values() {
        for (host, rec) in map {
            let n = count_record(rec, window, today);
            if n > 0 {
                *counts.entry(host.clone()).or_default() += n;
            }
        }
    }
    rank_counts(counts.into_iter())
}

fn count_record(rec: &FileDomain, window: Option<u32>, today: u32) -> u64 {
    match window {
        None => rec.total,
        Some(days) => rec
            .days
            .iter()
            .filter_map(|(k, n)| {
                k.parse::<u32>()
                    .ok()
                    .filter(|d| today.saturating_sub(*d) < days)
                    .map(|_| u64::from(*n))
            })
            .sum(),
    }
}

fn rank_counts<I>(counts: I) -> Vec<(String, u64)>
where
    I: IntoIterator<Item = (String, u64)>,
{
    let mut rows: Vec<(String, u64)> = counts.into_iter().filter(|(_, n)| *n > 0).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(TOP_N);
    rows
}

pub fn resolve_dest_stats_path(root: &Path, vpn_text: Option<&str>) -> PathBuf {
    if let Some(text) = vpn_text {
        if let Some(p) = crate::paths::parse_destination_stats_file(text) {
            return join_path(root, &p);
        }
    }
    root.join("dest_stats.json")
}

fn join_path(root: &Path, p: &str) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_today_from_json() {
        let json = r#"{
            "alice": {
                "instagram.com": {"total": 10, "days": {"100": 4, "90": 6}},
                "youtube.com": {"total": 2, "days": {"100": 2}}
            }
        }"#;
        let today = rank_user_json(json, "alice", DestPeriod::Today, 100);
        assert_eq!(
            today,
            vec![
                ("instagram.com".into(), 4),
                ("youtube.com".into(), 2),
            ]
        );
        let all = rank_user_json(json, "alice", DestPeriod::All, 100);
        assert_eq!(all[0], ("instagram.com".into(), 10));
        let week = rank_user_json(json, "alice", DestPeriod::Week, 100);
        assert_eq!(week[0], ("instagram.com".into(), 4));
    }

    #[test]
    fn missing_user_is_empty() {
        assert!(rank_user_json("{}", "alice", DestPeriod::Today, 1).is_empty());
    }

    #[test]
    fn ranks_all_users_summed() {
        let json = r#"{
            "alice": {
                "instagram.com": {"total": 10, "days": {"100": 4}},
                "youtube.com": {"total": 8, "days": {"100": 8}}
            },
            "bob": {
                "instagram.com": {"total": 3, "days": {"100": 3}},
                "tiktok.com": {"total": 1, "days": {"100": 1}}
            }
        }"#;
        let today = rank_all_json(json, DestPeriod::Today, 100);
        assert_eq!(
            today,
            vec![
                ("youtube.com".into(), 8),
                ("instagram.com".into(), 7),
                ("tiktok.com".into(), 1),
            ]
        );
        let all = rank_all_json(json, DestPeriod::All, 100);
        assert_eq!(all[0], ("instagram.com".into(), 13));
    }

    #[test]
    fn period_parse_round_trips() {
        assert_eq!(DestPeriod::parse("week").as_str(), "week");
        assert_eq!(DestPeriod::parse("month").as_str(), "month");
        assert_eq!(DestPeriod::parse("all").as_str(), "all");
        assert_eq!(DestPeriod::parse("").as_str(), "today");
    }

    #[test]
    fn resolve_relative_and_absolute() {
        let root = PathBuf::from("/opt/trusttunnel");
        assert_eq!(
            resolve_dest_stats_path(&root, Some("destination_stats_file = \"stats.json\"\n")),
            PathBuf::from("/opt/trusttunnel/stats.json")
        );
        assert_eq!(
            resolve_dest_stats_path(
                &root,
                Some("destination_stats_file = \"/var/lib/tt/dest.json\"\n")
            ),
            PathBuf::from("/var/lib/tt/dest.json")
        );
        assert_eq!(
            resolve_dest_stats_path(&root, None),
            PathBuf::from("/opt/trusttunnel/dest_stats.json")
        );
    }
}
