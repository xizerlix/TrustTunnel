use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BOT_SEEN: &str = "/tmp/vpn_times/active_vpn.json";
const OUR_SEEN: &str = "/tmp/trusttunnel_admin_seen.json";
const GEO_DIR: &str = "/tmp/vpn_times/geo";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpKind {
    Home,
    Mobile,
    Proxy,
    Hosting,
}

impl IpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IpKind::Home => "home",
            IpKind::Mobile => "mobile",
            IpKind::Proxy => "proxy",
            IpKind::Hosting => "hosting",
        }
    }
}

#[derive(Clone, Debug)]
pub struct IpView {
    pub address: String,
    pub connected_h: String,
    pub kind: &'static str,
    pub user_agents: Vec<String>,
}

impl IpView {
    pub fn agents_json(&self) -> String {
        serde_json::to_string(&crate::client_ua::display_lines(&self.user_agents))
            .unwrap_or_else(|_| "[]".into())
    }

    pub fn os_keys(&self) -> Vec<String> {
        crate::client_ua::os_keys(&self.user_agents)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct GeoDetail {
    pub query: String,
    pub kind: &'static str,
    pub country: String,
    pub region: String,
    pub city: String,
    pub zip: String,
    pub isp: String,
    pub org: String,
    pub asn: String,
    pub timezone: String,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub mobile: bool,
    pub proxy: bool,
    pub hosting: bool,
    pub map_url: String,
}

pub struct LiveCache {
    seen: Mutex<HashMap<String, u64>>,
    geo: Mutex<HashMap<String, CachedGeo>>,
    last_lookup: Mutex<Instant>,
}

#[derive(Clone, Copy)]
struct CachedGeo {
    kind: IpKind,
    expire: Instant,
}

impl LiveCache {
    pub fn new() -> Self {
        let seen = load_json_map(OUR_SEEN)
            .into_iter()
            .chain(load_json_map(BOT_SEEN))
            .collect();
        Self {
            seen: Mutex::new(seen),
            geo: Mutex::new(HashMap::new()),
            last_lookup: Mutex::new(Instant::now() - Duration::from_secs(60)),
        }
    }

    pub fn sync_ips(&self, pairs: &[(String, String)]) -> Vec<IpView> {
        let now = unix_now();
        let live_keys: Vec<String> = pairs.iter().map(|(u, ip)| format!("{u}|{ip}")).collect();
        {
            let mut seen = self.seen.lock().unwrap();
            for (k, v) in load_json_map(BOT_SEEN) {
                seen.entry(k).or_insert(v);
            }
            for key in &live_keys {
                seen.entry(key.clone()).or_insert(now);
            }
            seen.retain(|k, _| live_keys.iter().any(|l| l == k));
            let _ = std::fs::write(
                OUR_SEEN,
                serde_json::to_string(&*seen).unwrap_or_else(|_| "{}".into()),
            );
        }
        let mut out = Vec::new();
        for (user, ip) in pairs {
            let key = format!("{user}|{ip}");
            let start = self.seen.lock().unwrap().get(&key).copied().unwrap_or(now);
            let age = now.saturating_sub(start);
            out.push(IpView {
                address: ip.clone(),
                connected_h: humanize_nosec(age),
                kind: self.lookup_kind(ip).as_str(),
                user_agents: Vec::new(),
            });
        }
        out
    }

    fn lookup_kind(&self, ip: &str) -> IpKind {
        if is_private_ip(ip) {
            return IpKind::Home;
        }
        if let Some(c) = self.geo.lock().unwrap().get(ip).copied() {
            if c.expire > Instant::now() {
                return c.kind;
            }
        }
        let disk = disk_geo(ip);
        if let Some(kind) = disk {
            self.geo.lock().unwrap().insert(
                ip.to_string(),
                CachedGeo {
                    kind,
                    expire: Instant::now() + Duration::from_secs(86_400),
                },
            );
            return kind;
        }
        let mut last = self.last_lookup.lock().unwrap();
        if last.elapsed() < Duration::from_secs(3) {
            return IpKind::Home;
        }
        *last = Instant::now();
        drop(last);
        if let Some(d) = fetch_geo_detail(ip) {
            save_disk_geo_detail(ip, &d);
            let kind = kind_from_flags(d.mobile, d.proxy, d.hosting);
            self.geo.lock().unwrap().insert(
                ip.to_string(),
                CachedGeo {
                    kind,
                    expire: Instant::now() + Duration::from_secs(86_400),
                },
            );
            return kind;
        }
        IpKind::Home
    }

    pub fn ip_detail(&self, ip: &str) -> GeoDetail {
        if is_private_ip(ip) {
            return GeoDetail {
                query: ip.to_string(),
                kind: IpKind::Home.as_str(),
                ..GeoDetail::default()
            };
        }
        if let Some(d) = disk_geo_detail(ip) {
            if !(d.city.is_empty() && d.country.is_empty() && d.lat.is_none()) {
                return d;
            }
        }
        let mut last = self.last_lookup.lock().unwrap();
        if last.elapsed() < Duration::from_secs(3) {
            drop(last);
            return disk_geo_detail(ip).unwrap_or(GeoDetail {
                query: ip.to_string(),
                kind: IpKind::Home.as_str(),
                ..GeoDetail::default()
            });
        }
        *last = Instant::now();
        drop(last);
        if let Some(d) = fetch_geo_detail(ip) {
            save_disk_geo_detail(ip, &d);
            self.geo.lock().unwrap().insert(
                ip.to_string(),
                CachedGeo {
                    kind: kind_from_flags(d.mobile, d.proxy, d.hosting),
                    expire: Instant::now() + Duration::from_secs(86_400),
                },
            );
            return d;
        }
        GeoDetail {
            query: ip.to_string(),
            kind: self.lookup_kind(ip).as_str(),
            ..GeoDetail::default()
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_json_map(path: &str) -> HashMap<String, u64> {
    let Ok(s) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    serde_json::from_str(&s).unwrap_or_default()
}

pub fn humanize_nosec(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m")
    } else {
        "<1m".into()
    }
}

pub fn is_private_ip(s: &str) -> bool {
    let Ok(ip) = s.parse::<IpAddr>() else {
        return true;
    };
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        IpAddr::V6(v) => ipv6_is_local(v),
    }
}

fn ipv6_is_local(v: std::net::Ipv6Addr) -> bool {
    if v.is_loopback() {
        return true;
    }
    let o = v.octets();
    (o[0] & 0xfe) == 0xfc || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80)
}

fn disk_geo(ip: &str) -> Option<IpKind> {
    let path = geo_path(ip);
    let meta = std::fs::metadata(&path).ok()?;
    let mtime = meta.modified().ok()?;
    if SystemTime::now().duration_since(mtime).ok()? > Duration::from_secs(86_400) {
        return None;
    }
    let s = std::fs::read_to_string(&path).ok()?;
    parse_geo_json(&s)
}

fn geo_path(ip: &str) -> PathBuf {
    let slug: String = ip
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == ':' {
                c
            } else {
                '_'
            }
        })
        .collect();
    PathBuf::from(GEO_DIR).join(format!("{slug}.json"))
}

fn parse_geo_json(s: &str) -> Option<IpKind> {
    let g = parse_geo_fields(s)?;
    Some(kind_from_flags(g.mobile, g.proxy, g.hosting))
}

fn kind_from_flags(mobile: bool, proxy: bool, hosting: bool) -> IpKind {
    if mobile {
        IpKind::Mobile
    } else if proxy {
        IpKind::Proxy
    } else if hosting {
        IpKind::Hosting
    } else {
        IpKind::Home
    }
}

#[derive(Deserialize, Default)]
struct GeoFields {
    #[serde(default)]
    status: String,
    #[serde(default)]
    country: String,
    #[serde(default, rename = "regionName")]
    region_name: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    zip: String,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    timezone: String,
    #[serde(default)]
    isp: String,
    #[serde(default)]
    org: String,
    #[serde(default, rename = "as")]
    asn: String,
    #[serde(default)]
    mobile: bool,
    #[serde(default)]
    proxy: bool,
    #[serde(default)]
    hosting: bool,
    #[serde(default)]
    query: String,
}

fn parse_geo_fields(s: &str) -> Option<GeoFields> {
    let g: GeoFields = serde_json::from_str(s).ok()?;
    if !g.status.is_empty() && g.status != "success" {
        return None;
    }
    Some(g)
}

fn detail_from_fields(ip: &str, g: GeoFields) -> GeoDetail {
    let kind = kind_from_flags(g.mobile, g.proxy, g.hosting);
    let mut map_url = String::new();
    if let (Some(lat), Some(lon)) = (g.lat, g.lon) {
        if lat != 0.0 || lon != 0.0 {
            let pad = 0.35;
            map_url = format!(
                "https://www.openstreetmap.org/export/embed.html?bbox={left}%2C{bottom}%2C{right}%2C{top}&layer=mapnik&marker={lat}%2C{lon}",
                left = lon - pad,
                bottom = lat - pad,
                right = lon + pad,
                top = lat + pad,
                lat = lat,
                lon = lon
            );
        }
    }
    GeoDetail {
        query: if g.query.is_empty() {
            ip.to_string()
        } else {
            g.query
        },
        kind: kind.as_str(),
        country: g.country,
        region: g.region_name,
        city: g.city,
        zip: g.zip,
        isp: g.isp,
        org: g.org,
        asn: g.asn,
        timezone: g.timezone,
        lat: g.lat,
        lon: g.lon,
        mobile: g.mobile,
        proxy: g.proxy,
        hosting: g.hosting,
        map_url,
    }
}

fn disk_geo_detail(ip: &str) -> Option<GeoDetail> {
    let path = geo_path(ip);
    let meta = std::fs::metadata(&path).ok()?;
    let mtime = meta.modified().ok()?;
    if SystemTime::now().duration_since(mtime).ok()? > Duration::from_secs(86_400) {
        return None;
    }
    let s = std::fs::read_to_string(&path).ok()?;
    let g = parse_geo_fields(&s)?;
    Some(detail_from_fields(ip, g))
}

fn save_disk_geo_detail(ip: &str, d: &GeoDetail) {
    let _ = std::fs::create_dir_all(GEO_DIR);
    let body = serde_json::json!({
        "status": "success",
        "country": d.country,
        "regionName": d.region,
        "city": d.city,
        "zip": d.zip,
        "lat": d.lat,
        "lon": d.lon,
        "timezone": d.timezone,
        "isp": d.isp,
        "org": d.org,
        "as": d.asn,
        "mobile": d.mobile,
        "proxy": d.proxy,
        "hosting": d.hosting,
        "query": d.query,
    });
    let _ = std::fs::write(geo_path(ip), body.to_string());
}

fn fetch_geo_detail(ip: &str) -> Option<GeoDetail> {
    let body = http_get_ip_api(ip)?;
    let g = parse_geo_fields(&body)?;
    Some(detail_from_fields(ip, g))
}

fn http_get_ip_api(ip: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::net::ToSocketAddrs;
    let addr = "ip-api.com:80".to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(800)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(1200)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .ok()?;
    let path = format!(
        "/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query"
    );
    let req = format!("GET {path} HTTP/1.0\r\nHost: ip-api.com\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 8192 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    Some(text.split("\r\n\r\n").nth(1)?.to_string())
}

pub fn parse_host_snapshot() -> HostSnapshot {
    let load = read_load();
    let ram = read_ram();
    let disk = read_disk();
    let load_n: f64 = load.parse().unwrap_or(0.0);
    let cpus = cpu_count();
    let load_pct = if cpus > 0.0 {
        (load_n / cpus * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let ram_pct = ram_used_pct();
    let disk_pct = parse_pct(&disk);
    HostSnapshot {
        load,
        ram,
        disk,
        uptime: read_host_uptime(),
        version: read_tt_version(),
        load_color: heat_color(load_pct),
        ram_color: heat_color(ram_pct),
        disk_color: heat_color(disk_pct),
        cpu_milli: cpu_busy_milli(),
        ram_milli: (ram_pct.clamp(0.0, 100.0) * 1000.0).round() as u32,
        io_bytes: disk_io_bytes(),
        hostname: read_hostname(),
        cores: cpu_count().max(1.0) as u32,
        ram_total: ram_total_label(),
        disk_size: df_field(1),
    }
}

pub fn series_gauges() -> (u32, u32, u64) {
    let ram_pct = ram_used_pct();
    (
        cpu_busy_milli(),
        (ram_pct.clamp(0.0, 100.0) * 1000.0).round() as u32,
        disk_io_bytes(),
    )
}

#[derive(Clone, Default)]
pub struct HostSnapshot {
    pub load: String,
    pub ram: String,
    pub disk: String,
    pub uptime: String,
    pub version: String,
    pub load_color: String,
    pub ram_color: String,
    pub disk_color: String,
    pub cpu_milli: u32,
    pub ram_milli: u32,
    pub io_bytes: u64,
    pub hostname: String,
    pub cores: u32,
    pub ram_total: String,
    pub disk_size: String,
}

pub fn parse_pct(s: &str) -> f64 {
    let digits: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    digits.parse().unwrap_or(0.0)
}

pub fn heat_color(pct: f64) -> String {
    let p = pct.clamp(0.0, 100.0) / 100.0;
    let (r, g, b) = if p <= 0.5 {
        lerp_rgb((22, 163, 74), (202, 138, 4), p * 2.0)
    } else {
        lerp_rgb((202, 138, 4), (220, 38, 38), (p - 0.5) * 2.0)
    };
    format!("#{r:02x}{g:02x}{b:02x}")
}

fn lerp_rgb(a: (u8, u8, u8), b: (u8, u8, u8), t: f64) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0);
    (
        (a.0 as f64 + (b.0 as f64 - a.0 as f64) * t).round() as u8,
        (a.1 as f64 + (b.1 as f64 - a.1 as f64) * t).round() as u8,
        (a.2 as f64 + (b.2 as f64 - a.2 as f64) * t).round() as u8,
    )
}

fn cpu_count() -> f64 {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|s| {
            s.lines()
                .filter(|l| l.starts_with("processor"))
                .count()
                .max(1) as f64
        })
        .unwrap_or(1.0)
}

static CPU_PREV: Mutex<Option<(u64, u64)>> = Mutex::new(None);

pub fn parse_proc_stat_cpu(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().next().unwrap_or(stat);
    let mut it = line.split_whitespace();
    if it.next() != Some("cpu") {
        return None;
    }
    let nums: Vec<u64> = it.filter_map(|x| x.parse().ok()).collect();
    if nums.len() < 4 {
        return None;
    }
    let idle = nums[3].saturating_add(nums.get(4).copied().unwrap_or(0));
    let total: u64 = nums.iter().sum();
    Some((total.saturating_sub(idle), total))
}

fn cpu_busy_milli() -> u32 {
    let Ok(text) = std::fs::read_to_string("/proc/stat") else {
        return 0;
    };
    let Some((busy, total)) = parse_proc_stat_cpu(&text) else {
        return 0;
    };
    let mut prev = CPU_PREV.lock().unwrap_or_else(|p| p.into_inner());
    let milli = match *prev {
        Some((pb, pt)) if total > pt => {
            let db = busy.saturating_sub(pb) as f64;
            let dt = total.saturating_sub(pt) as f64;
            if dt <= 0.0 {
                0
            } else {
                ((db / dt) * 100_000.0).round().clamp(0.0, 100_000.0) as u32
            }
        }
        _ => 0,
    };
    *prev = Some((busy, total));
    milli
}

fn read_load() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .unwrap_or_else(|| "—".into())
}

fn meminfo_kb() -> (u64, u64) {
    let Ok(s) = std::fs::read_to_string("/proc/meminfo") else {
        return (0, 0);
    };
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in s.lines() {
        let mut p = line.split_whitespace();
        match p.next() {
            Some("MemTotal:") => total = p.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            Some("MemAvailable:") => avail = p.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }
    (total, avail)
}

fn ram_used_pct() -> f64 {
    let (total, avail) = meminfo_kb();
    if total == 0 {
        return 0.0;
    }
    (total.saturating_sub(avail) as f64 / total as f64) * 100.0
}

fn read_ram() -> String {
    let (total, avail) = meminfo_kb();
    if total == 0 {
        return "—".into();
    }
    let used = total.saturating_sub(avail);
    let pct = used as f64 / total as f64 * 100.0;
    format!(
        "{:.0}% ({:.0}/{:.0} MB)",
        pct,
        used as f64 / 1024.0,
        total as f64 / 1024.0
    )
}

pub fn parse_block_stat(stat: &str) -> u64 {
    let fields: Vec<&str> = stat.split_whitespace().collect();
    if fields.len() < 7 {
        return 0;
    }
    let r: u64 = fields[2].parse().unwrap_or(0);
    let w: u64 = fields[6].parse().unwrap_or(0);
    r.saturating_add(w).saturating_mul(512)
}

fn skip_block_name(name: &str) -> bool {
    name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("sr")
        || name.starts_with("fd")
        || name.starts_with("dm-")
        || name.starts_with("zram")
}

fn disk_io_bytes() -> u64 {
    let Ok(dir) = std::fs::read_dir("/sys/block") else {
        return 0;
    };
    let mut total = 0u64;
    for ent in dir.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if skip_block_name(&name) {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(ent.path().join("stat")) else {
            continue;
        };
        total = total.saturating_add(parse_block_stat(&stat));
    }
    total
}

fn ram_total_label() -> String {
    let (total, _) = meminfo_kb();
    if total == 0 {
        return "—".into();
    }
    let mb = total as f64 / 1024.0;
    if mb >= 1024.0 {
        format!("{:.1} GB", mb / 1024.0)
    } else {
        format!("{:.0} MB", mb)
    }
}

fn read_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "—".into())
}

fn df_field(idx: usize) -> String {
    let out = std::process::Command::new("df")
        .args(["-h", "/"])
        .output()
        .ok();
    let Some(out) = out else {
        return "—".into();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .nth(1)
        .and_then(|l| l.split_whitespace().nth(idx))
        .unwrap_or("—")
        .to_string()
}

fn read_disk() -> String {
    df_field(4)
}

fn read_host_uptime() -> String {
    let Ok(s) = std::fs::read_to_string("/proc/uptime") else {
        return "—".into();
    };
    let secs = s
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0) as u64;
    humanize_nosec(secs)
}

fn read_tt_version() -> String {
    let bin = std::path::Path::new("/opt/trusttunnel/trusttunnel_endpoint");
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .ok();
    let Some(out) = out else {
        return "—".into();
    };
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn read_cert_summary(cert_path: &str) -> Option<(String, String)> {
    let out = std::process::Command::new("openssl")
        .args(["x509", "-in", cert_path, "-noout", "-subject", "-enddate"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut subject = String::new();
    let mut end = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("subject=") {
            subject = rest
                .rsplit("CN = ")
                .next()
                .or_else(|| rest.rsplit("CN=").next())
                .unwrap_or(rest)
                .trim()
                .to_string();
        }
        if let Some(rest) = line.strip_prefix("notAfter=") {
            end = rest.trim().to_string();
            let parts: Vec<&str> = end.split_whitespace().collect();
            if parts.len() >= 5 {
                let hm: String = parts[2].split(':').take(2).collect::<Vec<_>>().join(":");
                end = format!("{} {} {} {} {}", parts[0], parts[1], hm, parts[3], parts[4]);
            }
        }
    }
    if subject.is_empty() && end.is_empty() {
        None
    } else {
        Some((subject, end))
    }
}

fn second_top_frame(raw: &str) -> Option<String> {
    let lines: Vec<&str> = raw.lines().collect();
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with("top -") || l.starts_with("top "))
        .map(|(i, _)| i)
        .collect();
    let start = *starts.get(1).or_else(|| starts.first())?;
    Some(
        lines[start..]
            .iter()
            .copied()
            .take(50)
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn run_top(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("top")
        .args(args)
        .env("LC_ALL", "C")
        .env("COLUMNS", "180")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    second_top_frame(&s)
}

pub fn htop_snapshot() -> String {
    if let Some(s) = run_top(&["-b", "-n", "2", "-d", "0.5", "-w", "180", "-o", "%CPU"]) {
        return s;
    }
    if let Some(s) = run_top(&["-b", "-n", "2", "-d", "0.5", "-w", "180"]) {
        return s;
    }
    let ps = std::process::Command::new("ps")
        .args(["-eo", "pid,user,pcpu,pmem,comm", "--sort=-pcpu"])
        .output();
    match ps {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .lines()
            .take(30)
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("ps/top unavailable: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ips_are_home() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("fc00::1"));
        assert!(is_private_ip("fe80::1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("2001:4860:4860::8888"));
    }

    #[test]
    fn block_stat_read_write_sectors() {
        assert_eq!(parse_block_stat("10 0 2 0 4 0 6 0"), 8 * 512);
        assert_eq!(parse_block_stat("1 2"), 0);
    }

    #[test]
    fn proc_stat_busy_excludes_idle() {
        let (busy, total) = parse_proc_stat_cpu("cpu  10 0 10 80 0 0 0 0").unwrap();
        assert_eq!(total, 100);
        assert_eq!(busy, 20);
    }

    #[test]
    fn duration_hides_seconds() {
        assert_eq!(humanize_nosec(40), "<1m");
        assert_eq!(humanize_nosec(90), "1m");
        assert_eq!(humanize_nosec(3700), "1h 1m");
    }

    #[test]
    fn geo_json_mobile() {
        assert_eq!(
            parse_geo_json("{\"mobile\":true,\"proxy\":false,\"hosting\":false}"),
            Some(IpKind::Mobile)
        );
        assert_eq!(
            parse_geo_json("{\"mobile\":false,\"proxy\":false,\"hosting\":false}"),
            Some(IpKind::Home)
        );
    }

    #[test]
    fn second_top_frame_keeps_later_sample() {
        let raw = "\
top - 00:00:00 up 1 min,  0 users,  load average: 0.00, 0.00, 0.00
%Cpu(s):  0.0 us,  0.0 sy,  0.0 ni,100.0 id
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
      1 root      20   0       0      0      0 S   0.0   0.0   0:00.00 systemd
top - 00:00:01 up 1 min,  0 users,  load average: 0.00, 0.00, 0.00
%Cpu(s):  1.2 us,  0.4 sy,  0.0 ni, 98.4 id
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    100 vpn       20   0    9999   1111   2222 S   4.0   1.0   0:01.00 trusttunnel_endpoint
";
        let frame = second_top_frame(raw).unwrap();
        assert!(frame.contains("trusttunnel_endpoint"));
        assert!(frame.contains("1.2 us"));
        assert!(!frame.contains("100.0 id"));
    }

    #[test]
    fn heat_color_transitions() {
        assert_eq!(heat_color(0.0), "#16a34a");
        assert_eq!(heat_color(50.0), "#ca8a04");
        assert_eq!(heat_color(100.0), "#dc2626");
        assert_eq!(parse_pct("84%"), 84.0);
        assert_eq!(parse_pct("33% (321/961 MB)"), 33.0);
    }
}
