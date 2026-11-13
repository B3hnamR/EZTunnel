//! Figures about this machine, read from /proc and the file system.
use serde::Serialize;
use std::time::Instant;

#[derive(Serialize, Clone, Default, Debug)]
pub struct Host {
    pub hostname: String,
    pub address: Option<String>,
    pub os: Option<String>,
    pub kernel: Option<String>,
    pub cores: usize,
    pub uptime_sec: Option<u64>,
    pub congestion: Option<String>,
    pub cpu_pct: Option<f64>,
    pub mem_pct: Option<f64>,
    pub mem_total: Option<u64>,
    pub disk_pct: Option<f64>,
    pub disk_total: Option<u64>,
    /// Bytes per second over all network interfaces except loopback.
    pub rx_bps: Option<f64>,
    pub tx_bps: Option<f64>,
}

#[derive(Default)]
pub struct HostSampler {
    cpu: Option<(u64, u64)>,
    net: Option<(u64, u64, Instant)>,
    facts: Option<Facts>,
}

/// What does not change while the dashboard runs.
#[derive(Clone)]
struct Facts {
    os: Option<String>,
    kernel: Option<String>,
    address: Option<String>,
    cores: usize,
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

impl HostSampler {
    pub fn sample(&mut self) -> Host {
        let facts = self
            .facts
            .get_or_insert_with(|| Facts {
                os: os_name(),
                kernel: read("/proc/sys/kernel/osrelease")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                address: crate::manager::local_ip(),
                cores: std::thread::available_parallelism().map_or(1, |n| n.get()),
            })
            .clone();
        let (mem_pct, mem_total) = memory().unzip();
        let (disk_pct, disk_total) = disk().unzip();
        let (rx_bps, tx_bps) = self.network().unzip();
        Host {
            hostname: hostname(),
            address: facts.address,
            os: facts.os,
            kernel: facts.kernel,
            cores: facts.cores,
            uptime_sec: read("/proc/uptime")
                .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
                .map(|s| s as u64),
            congestion: read("/proc/sys/net/ipv4/tcp_congestion_control").map(|s| s.trim().to_string()),
            cpu_pct: self.cpu(),
            mem_pct,
            mem_total,
            disk_pct,
            disk_total,
            rx_bps,
            tx_bps,
        }
    }

    fn cpu(&mut self) -> Option<f64> {
        let (busy, total) = cpu_counters(&read("/proc/stat")?)?;
        let previous = self.cpu.replace((busy, total));
        let (busy0, total0) = previous?;
        let total = total.checked_sub(total0).filter(|t| *t > 0)?;
        Some((busy.saturating_sub(busy0) as f64 * 100.0 / total as f64).clamp(0.0, 100.0))
    }

    fn network(&mut self) -> Option<(f64, f64)> {
        let (rx, tx) = network_counters(&read("/proc/net/dev")?);
        let now = Instant::now();
        let (rx0, tx0, at) = self.net.replace((rx, tx, now))?;
        let seconds = now.duration_since(at).as_secs_f64().max(0.001);
        Some((
            rx.saturating_sub(rx0) as f64 / seconds,
            tx.saturating_sub(tx0) as f64 / seconds,
        ))
    }
}

fn hostname() -> String {
    read("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this server".to_string())
}

fn os_name() -> Option<String> {
    read("/etc/os-release")?.lines().find_map(|line| {
        line.strip_prefix("PRETTY_NAME=")
            .map(|v| v.trim_matches('"').to_string())
    })
}

/// (busy, total) jiffies from the first line of /proc/stat.
fn cpu_counters(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().next()?.strip_prefix("cpu ")?;
    let values: Vec<u64> = line
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    if values.len() < 4 {
        return None;
    }
    // user nice system idle iowait irq softirq steal; guest time is already inside user.
    let total: u64 = values.iter().take(8).sum();
    let idle = values[3] + values.get(4).copied().unwrap_or(0);
    Some((total - idle, total))
}

/// (percent used, total bytes)
fn memory() -> Option<(f64, u64)> {
    memory_from(&read("/proc/meminfo")?)
}

fn memory_from(meminfo: &str) -> Option<(f64, u64)> {
    let field = |name: &str| {
        meminfo.lines().find_map(|line| {
            line.strip_prefix(name)?
                .trim_start_matches(':')
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
    };
    let total = field("MemTotal")?;
    let available = field("MemAvailable")?;
    (total > 0).then(|| {
        (
            total.saturating_sub(available) as f64 * 100.0 / total as f64,
            total * 1024,
        )
    })
}

/// Received and sent bytes summed over every interface except loopback.
fn network_counters(dev: &str) -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in dev.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else { continue };
        if name.trim() == "lo" {
            continue;
        }
        let values: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        if values.len() >= 9 {
            rx = rx.saturating_add(values[0]);
            tx = tx.saturating_add(values[8]);
        }
    }
    (rx, tx)
}

/// (percent used, total bytes) of the root file system.
#[cfg(target_os = "linux")]
fn disk() -> Option<(f64, u64)> {
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let path = c"/";
    // SAFETY: `path` is a valid NUL-terminated string and `stat` is a writable statvfs.
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let block = stat.f_frsize as u64;
    let total = stat.f_blocks as u64 * block;
    let free = stat.f_bavail as u64 * block;
    let used = total.saturating_sub(stat.f_bfree as u64 * block);
    let usable = used + free;
    (usable > 0).then(|| (used as f64 * 100.0 / usable as f64, total))
}

#[cfg(not(target_os = "linux"))]
fn disk() -> Option<(f64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_counters_leave_out_idle_and_iowait() {
        let stat = "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n";
        assert_eq!(cpu_counters(stat), Some((150, 1000)));
        assert_eq!(cpu_counters("intr 1 2"), None);
    }

    #[test]
    fn memory_in_use_is_total_minus_available() {
        let meminfo = "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    250 kB\n";
        let (percent, total) = memory_from(meminfo).unwrap();
        assert!((percent - 75.0).abs() < 1e-9);
        assert_eq!(total, 1_024_000);
    }

    #[test]
    fn loopback_traffic_is_not_counted() {
        let dev = "Inter-|   Receive\n face |bytes\n    lo: 500 1 0 0 0 0 0 0 500 1 0 0 0 0 0 0\n  eth0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0\n  eth1: 10 1 0 0 0 0 0 0 20 1 0 0 0 0 0 0\n";
        assert_eq!(network_counters(dev), (1010, 2020));
    }
}
