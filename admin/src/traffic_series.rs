use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_SAMPLES: usize = 8 * 24 * 60;
const MIN_GAP_SECS: i64 = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafPeriod {
    Hour,
    Day,
    Week,
}

impl TrafPeriod {
    pub fn parse(s: &str) -> Self {
        match s {
            "day" => Self::Day,
            "week" => Self::Week,
            _ => Self::Hour,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Week => "week",
        }
    }

    fn window_secs(self) -> i64 {
        match self {
            Self::Hour => 3600,
            Self::Day => 86400,
            Self::Week => 7 * 86400,
        }
    }

    fn bucket_secs(self) -> i64 {
        match self {
            Self::Hour => 60,
            Self::Day => 15 * 60,
            Self::Week => 3600,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sample {
    pub ts: i64,
    pub inbound: u64,
    pub outbound: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    samples: Vec<Sample>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChartPoint {
    pub t: i64,
    pub bytes: u64,
}

pub fn series_path(root: &Path) -> PathBuf {
    root.join("traffic_series.json")
}

pub fn record(path: &Path, now: i64, inbound: u64, outbound: u64) {
    let mut file = load(path);
    if let Some(last) = file.samples.last() {
        if now.saturating_sub(last.ts) < MIN_GAP_SECS {
            return;
        }
    }
    file.samples.push(Sample {
        ts: now,
        inbound,
        outbound,
    });
    if file.samples.len() > MAX_SAMPLES {
        let drop = file.samples.len() - MAX_SAMPLES;
        file.samples.drain(0..drop);
    }
    if let Ok(text) = serde_json::to_string(&file) {
        let _ = crate::apply::atomic_write(path, &text);
    }
}

pub fn chart(path: &Path, period: TrafPeriod, now: i64) -> Vec<ChartPoint> {
    chart_from_samples(&load(path).samples, period, now)
}

fn load(path: &Path) -> File {
    let Ok(text) = std::fs::read_to_string(path) else {
        return File::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

fn chart_from_samples(samples: &[Sample], period: TrafPeriod, now: i64) -> Vec<ChartPoint> {
    let window = period.window_secs();
    let bucket = period.bucket_secs();
    let start = ((now.saturating_sub(window)) / bucket) * bucket;
    let n = ((window / bucket) as usize).max(1);
    let mut out: Vec<ChartPoint> = (0..n)
        .map(|i| ChartPoint {
            t: start.saturating_add((i as i64).saturating_mul(bucket)),
            bytes: 0,
        })
        .collect();
    let mut prev: Option<&Sample> = None;
    for s in samples {
        if s.ts < start {
            prev = Some(s);
            continue;
        }
        let delta = match prev {
            Some(p)
                if s.inbound.saturating_add(s.outbound) >= p.inbound.saturating_add(p.outbound) =>
            {
                s.inbound
                    .saturating_add(s.outbound)
                    .saturating_sub(p.inbound.saturating_add(p.outbound))
            }
            _ => 0,
        };
        let slot = (s.ts / bucket) * bucket;
        if let Some(pt) = out.iter_mut().find(|p| p.t == slot) {
            pt.bytes = pt.bytes.saturating_add(delta);
        }
        prev = Some(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs_and_buckets_hour() {
        let samples = vec![
            Sample { ts: 1000, inbound: 10, outbound: 0 },
            Sample { ts: 1060, inbound: 40, outbound: 10 },
            Sample { ts: 1120, inbound: 40, outbound: 20 },
        ];
        let pts = chart_from_samples(&samples, TrafPeriod::Hour, 1120);
        assert!(pts.len() >= 2);
        let used: u64 = pts.iter().map(|p| p.bytes).sum();
        assert_eq!(used, 50);
    }

    #[test]
    fn period_parse() {
        assert_eq!(TrafPeriod::parse("day").as_str(), "day");
        assert_eq!(TrafPeriod::parse("").as_str(), "hour");
    }
}
