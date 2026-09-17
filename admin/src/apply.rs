use crate::error::{AdminError, AdminResult};
use crate::paths::TrustTunnelPaths;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

pub fn atomic_write(path: &Path, content: &str) -> AdminResult<()> {
    let parent = path.parent().ok_or_else(|| AdminError::Apply("no parent dir".into()))?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("toml.tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn systemctl_restart(service: &str) -> AdminResult<()> {
    let status = Command::new("systemctl")
        .args(["restart", service])
        .status()?;
    if !status.success() {
        return Err(AdminError::Apply(format!(
            "systemctl restart {service} failed: {status}"
        )));
    }
    Ok(())
}

pub fn systemctl_status(service: &str) -> AdminResult<String> {
    let out = Command::new("systemctl")
        .args(["status", "--no-pager", service])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn wait_active(service: &str, timeout: Duration) -> AdminResult<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let out = Command::new("systemctl")
            .args(["is-active", "--quiet", service])
            .status();
        if let Ok(status) = out {
            if status.success() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(AdminError::Apply(format!(
        "{service} did not become active within {timeout:?}"
    )))
}

pub fn kill_hup(process_name: &str) -> AdminResult<()> {
    let out = Command::new("pidof").arg(process_name).output()?;
    if !out.status.success() {
        return Err(AdminError::Apply(format!(
            "pidof {process_name} failed: not running?"
        )));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pids: Vec<&str> = stdout.split_whitespace().collect();
    for pid in pids {
        let status = Command::new("kill")
            .args(["-HUP", pid])
            .status()?;
        if !status.success() {
            return Err(AdminError::Apply(format!(
                "kill -HUP {pid} failed: {status}"
            )));
        }
    }
    Ok(())
}

pub fn apply(paths: &TrustTunnelPaths, kind: ApplyKind) -> AdminResult<String> {
    match kind {
        ApplyKind::Hosts => {
            kill_hup("trusttunnel_endpoint")?;
            Ok("SIGHUP sent; TrustTunnel reloaded hosts.toml without restart".into())
        }
        ApplyKind::FullRestart => {
            systemctl_restart(&paths.service_name)?;
            wait_active(&paths.service_name, Duration::from_secs(15))?;
            Ok(format!(
                "systemctl restart {} completed; service is active",
                paths.service_name
            ))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ApplyKind {
    Hosts,
    FullRestart,
}

pub fn connect_metrics_address(addr: &str) -> String {
    let Ok(sa) = addr.parse::<SocketAddr>() else {
        return addr.to_string();
    };
    match sa.ip() {
        IpAddr::V4(v) if v.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), sa.port()).to_string()
        }
        IpAddr::V6(v) if v.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), sa.port()).to_string()
        }
        _ => sa.to_string(),
    }
}

pub fn metrics_http_get(metrics_address: &str, path: &str) -> AdminResult<(u16, String)> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let connect_to = connect_metrics_address(metrics_address);
    let mut stream = TcpStream::connect(&connect_to)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    parse_http_response(&buf)
}

pub fn parse_http_response(buf: &[u8]) -> AdminResult<(u16, String)> {
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| AdminError::Apply("no http body".into()))?;
    let headers = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut body = String::from_utf8_lossy(&buf[header_end..]).into_owned();
    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        if let Some(decoded) = decode_chunked_body(&body) {
            body = decoded;
        }
    }
    Ok((status, body))
}

fn decode_chunked_body(body: &str) -> Option<String> {
    let mut rest = body;
    let mut out = String::new();
    loop {
        let (size_line, after) = rest.split_once("\r\n")?;
        let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        let chunk = after.get(..size)?;
        out.push_str(chunk);
        rest = after.get(size..)?;
        rest = rest.strip_prefix("\r\n").unwrap_or(rest);
    }
}

pub fn parse_json_body(body: &str) -> AdminResult<serde_json::Value> {
    let trimmed = body.trim();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return Ok(v);
    }
    let start = trimmed
        .find('[')
        .into_iter()
        .chain(trimmed.find('{'))
        .min()
        .ok_or_else(|| AdminError::Apply("no json in http body".into()))?;
    let slice = &trimmed[start..];
    let end = if slice.starts_with('[') {
        slice.rfind(']')
    } else {
        slice.rfind('}')
    }
    .ok_or_else(|| AdminError::Apply("truncated json".into()))?;
    Ok(serde_json::from_str(&slice[..=end])?)
}

pub fn read_clients_json(metrics_address: &str) -> AdminResult<serde_json::Value> {
    let (status, body) = metrics_http_get(metrics_address, "/clients")?;
    if status == 404 {
        return Ok(serde_json::Value::Array(Vec::new()));
    }
    if status != 200 {
        return Err(AdminError::Apply(format!("GET /clients -> {status}")));
    }
    parse_json_body(&body)
}

pub fn read_prometheus_metrics(metrics_address: &str) -> AdminResult<String> {
    let (status, body) = metrics_http_get(metrics_address, "/metrics")?;
    if status != 200 {
        return Err(AdminError::Apply(format!("GET /metrics -> {status}")));
    }
    Ok(body)
}

pub fn systemctl_show(service: &str) -> AdminResult<String> {
    let out = Command::new("systemctl")
        .args([
            "show",
            service,
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "ActiveEnterTimestampUSec",
            "-p",
            "InactiveEnterTimestampUSec",
            "--no-pager",
        ])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn journalctl_logs(service: &str, lines: usize) -> AdminResult<String> {
    let out = Command::new("journalctl")
        .args(["-u", service, "-n", &lines.to_string(), "--no-pager"])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod apply_http_tests {
    use super::*;

    #[test]
    fn parse_http_response_splits_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{\"ok\":true}]";
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "[{\"ok\":true}]");
    }

    #[test]
    fn parse_http_response_decodes_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n[{\"a\"\r\n8\r\n:true}]\r\n0\r\n\r\n";
        let (status, body) = parse_http_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "[{\"a\":true}]");
        let v = parse_json_body(&body).unwrap();
        assert!(v.is_array());
    }

    #[test]
    fn unspecified_metrics_bind_connects_to_localhost() {
        assert_eq!(connect_metrics_address("0.0.0.0:1987"), "127.0.0.1:1987");
        assert_eq!(connect_metrics_address("[::]:1987"), "[::1]:1987");
        assert_eq!(connect_metrics_address("127.0.0.1:1987"), "127.0.0.1:1987");
    }
}