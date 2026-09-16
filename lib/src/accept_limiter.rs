use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Caps new TCP accepts so TLS handshake storms cannot pin a single CPU.
pub(crate) struct AcceptLimiter {
    window: Duration,
    max_per_ip: u32,
    max_global: u32,
    global: Mutex<(Instant, u32)>,
    per_ip: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl AcceptLimiter {
    pub fn new(max_per_ip: u32, max_global: u32) -> Self {
        Self {
            window: Duration::from_secs(1),
            max_per_ip,
            max_global,
            global: Mutex::new((Instant::now(), 0)),
            per_ip: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let mut per_ip = self.per_ip.lock().unwrap();
        if per_ip.len() > 4096 {
            let window = self.window;
            per_ip.retain(|_, (started, _)| started.elapsed() < window);
        }
        let ip_entry = per_ip.entry(ip).or_insert((Instant::now(), 0));
        if ip_entry.0.elapsed() >= self.window {
            *ip_entry = (Instant::now(), 0);
        }
        if ip_entry.1 >= self.max_per_ip {
            return false;
        }

        let mut global = self.global.lock().unwrap();
        if global.0.elapsed() >= self.window {
            *global = (Instant::now(), 0);
        }
        if global.1 >= self.max_global {
            return false;
        }

        ip_entry.1 = ip_entry.1.saturating_add(1);
        global.1 = global.1.saturating_add(1);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rejects_when_per_ip_budget_exceeded() {
        let limiter = AcceptLimiter::new(2, 100);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn other_ip_is_independent() {
        let limiter = AcceptLimiter::new(1, 100);
        let a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        assert!(limiter.allow(a));
        assert!(!limiter.allow(a));
        assert!(limiter.allow(b));
    }

    #[test]
    fn rejects_when_global_budget_exceeded() {
        let limiter = AcceptLimiter::new(100, 2);
        let a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        assert!(limiter.allow(a));
        assert!(limiter.allow(b));
        assert!(!limiter.allow(IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))));
    }
}
