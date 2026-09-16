use crate::error::{AdminError, AdminResult};
use crate::paths::TrustTunnelPaths;
use std::fs;
use std::io::Write;
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

pub fn read_clients_json(metrics_address: &str) -> AdminResult<serde_json::Value> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut stream = TcpStream::connect(metrics_address)?;
    let req = format!(
        "GET /clients HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let body = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| AdminError::Apply("no http body".into()))?;
    let body = String::from_utf8_lossy(&buf[body..]).into_owned();
    Ok(serde_json::from_str(&body)?)
}

pub fn journalctl_logs(service: &str, lines: usize) -> AdminResult<String> {
    let out = Command::new("journalctl")
        .args(["-u", service, "-n", &lines.to_string(), "--no-pager"])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}