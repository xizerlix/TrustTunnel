use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_SAMPLES: usize = 8 * 24 * 60 + 720;
const MIN_GAP_SECS: i64 = 8;
const FLUSH_SECS: i64 = 50;
const FINE_KEEP_SECS: i64 = 2 * 3600;
const COARSE_SECS: i64 = 60;

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
            Self::Hour => 10,
            Self::Day => 5 * 60,
            Self::Week => 15 * 60,
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

pub struct SeriesStore {
    path: PathBuf,
    inner: Mutex<StoreInner>,
}

struct StoreInner {
    samples: Vec<Sample>,
    last_flush: i64,
}

impl SeriesStore {
    pub fn new(path: PathBuf) -> Self {
        let samples = load(&path).samples;
        Self {
            path,
            inner: Mutex::new(StoreInner {
                samples,
                last_flush: 0,
            }),
        }
    }

    pub fn record(
        &self,
        now: i64,
        inbound: u64,
        outbound: u64,
        cpu_milli: u32,
        ram_milli: u32,
        io_bytes: u64,
    ) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(last) = g.samples.last() {
            if now.saturating_sub(last.ts) < MIN_GAP_SECS {
                return;
            }
        }
        g.samples.push(Sample {
            ts: now,
            inbound,
            outbound,
            cpu_milli,
            ram_milli,
            io_bytes,
        });
        compact_samples(&mut g.samples, now);
        if g.last_flush == 0 || now.saturating_sub(g.last_flush) >= FLUSH_SECS {
            persist(&self.path, &g.samples);
            g.last_flush = now;
        }
    }

    pub fn chart(&self, period: TrafPeriod, now: i64) -> ChartSet {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        chart_from_samples(&g.samples, period, now)
    }
}

fn persist(path: &Path, samples: &[Sample]) {
    let file = File {
        samples: samples.to_vec(),
    };
    if let Ok(text) = serde_json::to_string(&file) {
        let _ = crate::apply::atomic_write(path, &text);
    }
}

fn compact_samples(samples: &mut Vec<Sample>, now: i64) {
    let fine = now.saturating_sub(FINE_KEEP_SECS);
    let mut out: Vec<Sample> = Vec::with_capacity(samples.len());
    let mut coarse: Option<Sample> = None;
    for s in samples.drain(..) {
        if s.ts >= fine {
            if let Some(c) = coarse.take() {
                out.push(c);
            }
            out.push(s);
            continue;
        }
        let slot = if COARSE_SECS > 0 { s.ts / COARSE_SECS } else { s.ts };
        match coarse {
            None => coarse = Some(s),
            Some(ref mut c) if c.ts / COARSE_SECS == slot => {
                c.cpu_milli = c.cpu_milli.max(s.cpu_milli);
                c.ram_milli = c.ram_milli.max(s.ram_milli);
                c.inbound = s.inbound;
                c.outbound = s.outbound;
                c.io_bytes = s.io_bytes;
                c.ts = s.ts;
            }
            Some(prev) => {
                out.push(prev);
                coarse = Some(s);
            }
        }
    }
    if let Some(c) = coarse {
        out.push(c);
    }
    if out.len() > MAX_SAMPLES {
        let drop = out.len() - MAX_SAMPLES;
        out.drain(0..drop);
    }
    *samples = out;
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
    if ts < start || bucket <= 0 || n == 0 {
        return None;
    }
    let i = ((ts - start) / bucket) as usize;
    if i < n {
        Some(i)
    } else if ts <= start.saturating_add(bucket.saturating_mul(n as i64)) {
        Some(n - 1)
    } else {
        None
    }
}

fn chart_from_samples(samples: &[Sample], period: TrafPeriod, now: i64) -> ChartSet {
    let (start, bucket, n) = layout(period, now);
    let mut traffic = empty_points(start, bucket, n);
    let mut io = empty_points(start, bucket, n);
        let mut cpu_max = vec![0u32; n];
        let mut ram_max = vec![0u32; n];
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
        cpu_max[i] = cpu_max[i].max(s.cpu_milli);
        ram_max[i] = ram_max[i].max(s.ram_milli);
        gauge_n[i] = gauge_n[i].saturating_add(1);
        prev = Some(s);
    }
    let mut cpu = empty_points(start, bucket, n);
    let mut ram = empty_points(start, bucket, n);
    for i in 0..n {
        if gauge_n[i] > 0 {
            cpu[i].v = u64::from(cpu_max[i]);
            ram[i].v = u64::from(ram_max[i]);
        }
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
    fn cpu_keeps_peak_in_bucket() {
        let samples = vec![
            Sample {
                ts: 1000,
                inbound: 0,
                outbound: 0,
                cpu_milli: 10_000,
                ram_milli: 10_000,
                io_bytes: 0,
            },
            Sample {
                ts: 1005,
                inbound: 0,
                outbound: 0,
                cpu_milli: 80_000,
                ram_milli: 12_000,
                io_bytes: 0,
            },
        ];
        let pts = chart_from_samples(&samples, TrafPeriod::Hour, 1010);
        let peak = pts.cpu.iter().map(|p| p.v).max().unwrap_or(0);
        assert_eq!(peak, 80_000);
    }

    #[test]
    fn compact_keeps_recent_fine() {
        let mut samples = vec![
            Sample {
                ts: 100,
                inbound: 1,
                outbound: 0,
                cpu_milli: 5,
                ram_milli: 1,
                io_bytes: 0,
            },
            Sample {
                ts: 110,
                inbound: 2,
                outbound: 0,
                cpu_milli: 9,
                ram_milli: 2,
                io_bytes: 0,
            },
        ];
        compact_samples(&mut samples, 10_000);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].cpu_milli, 9);
        assert_eq!(samples[0].inbound, 2);
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
