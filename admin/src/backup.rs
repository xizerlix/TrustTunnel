use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;
use zip::ZipWriter;

const MAX_FILE: u64 = 80 * 1024 * 1024;
const RESTORE_SH: &str = include_str!("../backup/restore.sh");

const KNOWN_SCRIPTS: &[&str] = &[
    "/root/monitor.sh",
    "/root/monthly_reboot.sh",
    "/root/bot_listener.sh",
    "/root/telegram_vpn_bot.sh",
    "/root/duckdns-update.sh",
];

const EXTRA_PATHS: &[&str] = &[
    "/etc/trusttunnel/admin.toml",
    "/etc/systemd/system/trusttunnel.service",
    "/etc/systemd/system/trusttunnel-admin.service",
    "/etc/caddy/Caddyfile",
    "/tmp/trusttunnel_admin_seen.json",
];

pub struct BackupInput {
    pub root: PathBuf,
    pub admin_toml: PathBuf,
    pub extra: Vec<PathBuf>,
    pub crontab_text: String,
}

pub fn collect_live(root: PathBuf, admin_toml: PathBuf) -> BackupInput {
    let crontab_text = Command::new("crontab")
        .arg("-l")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let mut extra: Vec<PathBuf> = EXTRA_PATHS.iter().map(PathBuf::from).collect();
    extra.push(admin_toml.clone());
    extra.push(crate::login_log::history_path(&admin_toml));
    for p in KNOWN_SCRIPTS {
        extra.push(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("TT_TELEGRAM_SCRIPT") {
        if !p.trim().is_empty() {
            extra.push(PathBuf::from(p.trim()));
        }
    }
    extra.extend(paths_from_crontab(&crontab_text));
    extra.push(PathBuf::from("/tmp/vpn_times"));
    BackupInput {
        root,
        admin_toml,
        extra,
        crontab_text,
    }
}

pub fn build_zip(input: &BackupInput) -> Result<Vec<u8>, String> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let file_opts = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o600);
        let exec_opts = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o755);
        zip.start_file("restore.sh", exec_opts)
            .map_err(|e| e.to_string())?;
        zip.write_all(RESTORE_SH.as_bytes())
            .map_err(|e| e.to_string())?;
        zip.start_file("README.txt", file_opts)
            .map_err(|e| e.to_string())?;
        zip.write_all(readme_text().as_bytes())
            .map_err(|e| e.to_string())?;
        if !input.crontab_text.trim().is_empty() {
            zip.start_file("data/cron/root.crontab", file_opts)
                .map_err(|e| e.to_string())?;
            zip.write_all(input.crontab_text.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        let mut seen = std::collections::BTreeSet::new();
        add_tree(
            &mut zip,
            &input.root,
            "data/opt/trusttunnel",
            &mut seen,
            file_opts,
            exec_opts,
        )?;
        if let Some(name) =
            entry_name(&input.admin_toml).or_else(|| Some("data/etc/trusttunnel/admin.toml".into()))
        {
            add_named(
                &mut zip,
                &input.admin_toml,
                &name,
                &mut seen,
                file_opts,
                exec_opts,
            )?;
        }
        for p in &input.extra {
            if let Some(name) = entry_name(p) {
                add_named(&mut zip, p, &name, &mut seen, file_opts, exec_opts)?;
            }
        }
        zip.finish().map_err(|e| e.to_string())?;
    }
    Ok(cursor.into_inner())
}

fn readme_text() -> String {
    let mut s = String::new();
    s.push_str("Backup of panel data + restore.sh\n\n");
    s.push_str("On the NEW server (Debian/Ubuntu):\n");
    s.push_str("  1. apt-get update && apt-get install -y unzip\n");
    s.push_str("  2. unzip mdm-backup-*.zip -d /root/mdm-restore && cd /root/mdm-restore\n");
    s.push_str("  3. sudo ./restore.sh\n\n");
    s.push_str("The script asks for a new hostname. Register it at https://www.duckdns.org\n");
    s.push_str("then Let's Encrypt issues a new certificate (old domain is not reused).\n");
    s.push_str("Users, quotas, rules, admin password, cron and bot scripts are restored.\n");
    s
}

fn add_tree(
    zip: &mut ZipWriter<&mut Cursor<Vec<u8>>>,
    dir: &Path,
    zip_prefix: &str,
    seen: &mut std::collections::BTreeSet<String>,
    file_opts: SimpleFileOptions,
    exec_opts: SimpleFileOptions,
) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    if dir.is_file() {
        let name = format!("{zip_prefix}/{}", file_name(dir));
        return add_named(zip, dir, &name, seen, file_opts, exec_opts);
    }
    for p in walkdir(dir) {
        let Ok(rel) = p.strip_prefix(dir) else {
            continue;
        };
        let rel_s = rel_unix(rel);
        if rel_s.is_empty() {
            continue;
        }
        let name = format!("{zip_prefix}/{rel_s}");
        add_named(zip, &p, &name, seen, file_opts, exec_opts)?;
    }
    Ok(())
}

fn add_named(
    zip: &mut ZipWriter<&mut Cursor<Vec<u8>>>,
    path: &Path,
    name: &str,
    seen: &mut std::collections::BTreeSet<String>,
    file_opts: SimpleFileOptions,
    exec_opts: SimpleFileOptions,
) -> Result<(), String> {
    if !path.is_file() {
        return Ok(());
    }
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_FILE {
        return Ok(());
    }
    if !seen.insert(name.to_string()) {
        return Ok(());
    }
    let opts = if is_exec(path) { exec_opts } else { file_opts };
    zip.start_file(name, opts).map_err(|e| e.to_string())?;
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    zip.write_all(&buf).map_err(|e| e.to_string())?;
    Ok(())
}

fn is_exec(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("sh") | Some("py")
    ) || path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.contains("trusttunnel") || n == "setup_wizard")
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn rel_unix(rel: &Path) -> String {
    rel.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn entry_name(path: &Path) -> Option<String> {
    let n = path.to_string_lossy().replace('\\', "/");
    const MARKERS: &[&str] = &[
        "/opt/trusttunnel/",
        "/etc/trusttunnel/",
        "/etc/systemd/system/",
        "/etc/caddy/",
        "/root/",
        "/tmp/",
    ];
    for m in MARKERS {
        if let Some(i) = n.find(m) {
            return Some(format!("data{}", &n[i..]));
        }
    }
    let name = path.file_name()?.to_string_lossy();
    let parent = path.parent()?.file_name()?.to_string_lossy();
    match parent.as_ref() {
        "root" => Some(format!("data/root/{name}")),
        "tmp" => Some(format!("data/tmp/{name}")),
        "caddy" => Some(format!("data/etc/caddy/{name}")),
        "system" => Some(format!("data/etc/systemd/system/{name}")),
        "trusttunnel" => {
            let gp = path.parent()?.parent()?.file_name()?.to_string_lossy();
            match gp.as_ref() {
                "opt" => Some(format!("data/opt/trusttunnel/{name}")),
                "etc" => Some(format!("data/etc/trusttunnel/{name}")),
                _ => None,
            }
        }
        _ => None,
    }
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        let skip = p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == ".git" || n == "target" || n == "lost+found");
        if skip {
            continue;
        }
        if p.is_dir() {
            out.extend(walkdir(&p));
        } else {
            out.push(p);
        }
    }
    out
}

pub fn paths_from_crontab(text: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for tok in line.split_whitespace() {
            if tok.starts_with('/') && !tok.contains("://") {
                let clean = tok.trim_matches(|c: char| c == ';' || c == '&' || c == '|');
                if clean.len() > 1 {
                    out.push(PathBuf::from(clean));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use zip::ZipArchive;

    fn zip_has_entry(bytes: &[u8], name: &str) -> bool {
        let Ok(z) = ZipArchive::new(Cursor::new(bytes)) else {
            return false;
        };
        let found = z.file_names().any(|n| n == name);
        found
    }

    #[test]
    fn crontab_extracts_script_paths() {
        let text = "* * * * * /root/monitor.sh\n\
0 0 1 * * rm -f /opt/trusttunnel/traffic_usage.toml && systemctl restart trusttunnel\n\
@reboot /root/bot_listener.sh > /dev/null 2>&1 &\n";
        let paths = paths_from_crontab(text);
        assert!(paths.iter().any(|p| p.ends_with("monitor.sh")));
        assert!(paths.iter().any(|p| p.ends_with("bot_listener.sh")));
        assert!(paths.iter().any(|p| p.ends_with("traffic_usage.toml")));
    }

    #[test]
    fn zip_contains_restore_readme_and_data() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("opt").join("trusttunnel");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("credentials.toml"),
            "[[client]]\nusername=\"a\"\n",
        )
        .unwrap();
        std::fs::write(root.join("vpn.toml"), "listen_address=\"0.0.0.0:443\"\n").unwrap();
        let admin = dir.path().join("etc").join("trusttunnel");
        std::fs::create_dir_all(&admin).unwrap();
        let admin_toml = admin.join("admin.toml");
        std::fs::write(&admin_toml, "bcrypt_hash=\"x\"\n").unwrap();
        let script = dir.path().join("root");
        std::fs::create_dir_all(&script).unwrap();
        let mon = script.join("monitor.sh");
        std::fs::write(&mon, "#!/bin/sh\necho ok\n").unwrap();
        let zip = build_zip(&BackupInput {
            root,
            admin_toml,
            extra: vec![mon],
            crontab_text: "* * * * * /root/monitor.sh\n".into(),
        })
        .unwrap();
        assert!(zip_has_entry(&zip, "restore.sh"));
        assert!(zip_has_entry(&zip, "README.txt"));
        assert!(zip_has_entry(&zip, "data/cron/root.crontab"));
        assert!(zip_has_entry(&zip, "data/opt/trusttunnel/credentials.toml"));
        assert!(zip_has_entry(&zip, "data/etc/trusttunnel/admin.toml"));
        assert!(zip_has_entry(&zip, "data/root/monitor.sh"));
        let mut z = ZipArchive::new(Cursor::new(zip)).unwrap();
        let mut sh = String::new();
        z.by_name("restore.sh")
            .unwrap()
            .read_to_string(&mut sh)
            .unwrap();
        assert!(sh.contains("duckdns.org"));
        assert!(sh.contains("certbot"));
        assert!(sh.contains("trusttunnel-admin"));
        assert!(sh.contains("hosts.toml"));
        assert!(sh.contains("duckdns-update.sh"));
    }
}
