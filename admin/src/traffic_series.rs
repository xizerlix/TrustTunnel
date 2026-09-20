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
    #[serde(default)]
    pub cpu_milli: u32,
    #[serde(default)]
    pub ram_milli: u32,
    #[serde(default)]
    pub io_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    samples: Vec<Sample>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChartPoint {
    pub t: i64,
    pub v: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ChartSet {
    pub traffic: Vec<ChartPoint>,
    pub cpu: Vec<ChartPoint>,
    pub ram: Vec<ChartPoint>,
    pub io: Vec<ChartPoint>,
}

pub fn series_path(root: &Path) -> PathBuf {
    root.join("traffic_series.json")
}

pub fn record(
    path: &Path,
    now: i64,
    inbound: u64,
    outbound: u64,
    cpu_milli: u32,
    ram_milli: u32,
    io_bytes: u64,
) {
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
        cpu_milli,
        ram_milli,
        io_bytes,
    });
    if file.samples.len() > MAX_SAMPLES {
        let drop = file.samples.len() - MAX_SAMPLES;
        file.samples.drain(0..drop);
    }
    if let Ok(text) = serde_json::to_string(&file) {
        let _ = crate::apply::atomic_write(path, &text);
    }
}

pub fn chart(path: &Path, period: TrafPeriod, now: i64) -> ChartSet {
    chart_from_samples(&load(path).samples, period, now)
}

fn load(path: &Path) -> File {
    let Ok(text) = std::fs::read_to_string(path) else {
        return File::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

fn layout(period: TrafPeriod, now: i64) -> (i64, i64, usize) {
    let window = period.window_secs();
    let bucket = period.bucket_secs();
    let start = ((now.saturating_sub(window)) / bucket) * bucket;
    let n = ((window / bucket) as usize).max(1);
    (start, bucket, n)
}

fn empty_points(start: i64, bucket: i64, n: usize) -> Vec<ChartPoint> {
    (0..n)
        .map(|i| ChartPoint {
            t: start.saturating_add((i as i64).saturating_mul(bucket)),
            v: 0,
        })
        .collect()
}

fn slot_index(ts: i64, start: i64, bucket: i64, n: usize) -> Option<usize> {
    if ts < start || bucket <= 0 {
        return None;
    }
    let i = ((ts - start) / bucket) as usize;
    (i < n).then_some(i)
}

fn chart_from_samples(samples: &[Sample], period: TrafPeriod, now: i64) -> ChartSet {
    let (start, bucket, n) = layout(period, now);
    let mut traffic = empty_points(start, bucket, n);
    let mut io = empty_points(start, bucket, n);
    let mut cpu_sum = vec![0u64; n];
    let mut ram_sum = vec![0u64; n];
    let mut gauge_n = vec![0u64; n];
    let mut prev: Option<&Sample> = None;
    for s in samples {
        if s.ts < start {
            prev = Some(s);
            continue;
        }
        let Some(i) = slot_index(s.ts, start, bucket, n) else {
            prev = Some(s);
            continue;
        };
        let traf_delta = match prev {
            Some(p)
                if s.inbound.saturating_add(s.outbound) >= p.inbound.saturating_add(p.outbound) =>
            {
                s.inbound
                    .saturating_add(s.outbound)
                    .saturating_sub(p.inbound.saturating_add(p.outbound))
            }
            _ => 0,
        };
        let io_delta = match prev {
            Some(p) if s.io_bytes >= p.io_bytes => s.io_bytes.saturating_sub(p.io_bytes),
            _ => 0,
        };
        traffic[i].v = traffic[i].v.saturating_add(traf_delta);
        io[i].v = io[i].v.saturating_add(io_delta);
        cpu_sum[i] = cpu_sum[i].saturating_add(u64::from(s.cpu_milli));
        ram_sum[i] = ram_sum[i].saturating_add(u64::from(s.ram_milli));
        gauge_n[i] = gauge_n[i].saturating_add(1);
        prev = Some(s);
    }
    let mut cpu = empty_points(start, bucket, n);
    let mut ram = empty_points(start, bucket, n);
    for i in 0..n {
        cpu[i].v = cpu_sum[i].checked_div(gauge_n[i]).unwrap_or(0);
        ram[i].v = ram_sum[i].checked_div(gauge_n[i]).unwrap_or(0);
    }
    ChartSet {
        traffic,
        cpu,
        ram,
        io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs_and_buckets_hour() {
        let samples = vec![
            Sample {
                ts: 1000,
                inbound: 10,
                outbound: 0,
                cpu_milli: 0,
                ram_milli: 0,
                io_bytes: 0,
            },
            Sample {
                ts: 1060,
                inbound: 40,
                outbound: 10,
                cpu_milli: 0,
                ram_milli: 0,
                io_bytes: 0,
            },
            Sample {
                ts: 1120,
                inbound: 40,
                outbound: 20,
                cpu_milli: 0,
                ram_milli: 0,
                io_bytes: 0,
            },
        ];
        let pts = chart_from_samples(&samples, TrafPeriod::Hour, 1120);
        assert!(pts.traffic.len() >= 2);
        let used: u64 = pts.traffic.iter().map(|p| p.v).sum();
        assert_eq!(used, 50);
    }

    #[test]
    fn cpu_average_and_io_delta() {
        let samples = vec![
            Sample {
                ts: 1000,
                inbound: 0,
                outbound: 0,
                cpu_milli: 10_000,
                ram_milli: 40_000,
                io_bytes: 100,
            },
            Sample {
                ts: 1060,
                inbound: 0,
                outbound: 0,
                cpu_milli: 30_000,
                ram_milli: 50_000,
                io_bytes: 250,
            },
        ];
        let pts = chart_from_samples(&samples, TrafPeriod::Hour, 1060);
        let cpu: u64 = pts.cpu.iter().map(|p| p.v).sum();
        let ram: u64 = pts.ram.iter().map(|p| p.v).sum();
        let io: u64 = pts.io.iter().map(|p| p.v).sum();
        assert_eq!(cpu, 40_000);
        assert_eq!(ram, 90_000);
        assert_eq!(io, 150);
    }

    #[test]
    fn old_json_missing_host_fields() {
        let file: File = serde_json::from_str(
            r#"{"samples":[{"ts":1,"inbound":2,"outbound":3}]}"#,
        )
        .unwrap();
        assert_eq!(file.samples[0].cpu_milli, 0);
        assert_eq!(file.samples[0].io_bytes, 0);
    }

    #[test]
    fn period_parse() {
        assert_eq!(TrafPeriod::parse("day").as_str(), "day");
        assert_eq!(TrafPeriod::parse("").as_str(), "hour");
    }
}
