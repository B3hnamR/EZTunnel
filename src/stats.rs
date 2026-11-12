//! Running totals for operators: how many sessions and user connections are open, how many were
//! refused, and how much data has moved. A summary line is logged at a configurable interval.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

/// Round-trip samples kept for the live status (newest last).
const RTT_SAMPLES: usize = 64;

/// Flow-control frames are 16 KiB, so a mebibyte holds 64 of them.
pub const FRAMES_PER_MIB: usize = 64;

/// A cap on the memory the flow-control windows of all user connections may use.
///
/// Every connection starts with a small window. The receiving side then opens it wider so that
/// one connection can fill a long link, and a slow user can leave that whole window queued in
/// memory. Without a cap, hundreds of slow users on a small server would use gigabytes. The
/// budget counts only the extra frames beyond the initial window: a connection that finds the
/// budget used up simply keeps its small window and so a lower speed on long links, and gets the
/// frames back for the next connection when it ends. Nothing changes on the wire, because the
/// receiver alone decides how many credits it hands out.
pub struct WindowBudget {
    limit: AtomicUsize,
    used: AtomicUsize,
}

impl Default for WindowBudget {
    /// Unlimited until `set_limit` is called, so code that never configures a budget (tests,
    /// tools) behaves as before.
    fn default() -> Self {
        Self {
            limit: AtomicUsize::new(usize::MAX),
            used: AtomicUsize::new(0),
        }
    }
}

impl WindowBudget {
    pub fn set_limit(&self, frames: usize) {
        self.limit.store(frames, Relaxed);
    }

    /// Reserves up to `wanted` frames and returns how many were granted (possibly none).
    pub fn reserve(&self, wanted: usize) -> usize {
        let limit = self.limit.load(Relaxed);
        let mut used = self.used.load(Relaxed);
        loop {
            let granted = wanted.min(limit.saturating_sub(used));
            if granted == 0 {
                return 0;
            }
            match self
                .used
                .compare_exchange_weak(used, used + granted, Relaxed, Relaxed)
            {
                Ok(_) => return granted,
                Err(now) => used = now,
            }
        }
    }

    /// Gives frames back.
    pub fn release(&self, frames: usize) {
        let mut used = self.used.load(Relaxed);
        loop {
            let after = used.saturating_sub(frames);
            match self
                .used
                .compare_exchange_weak(used, after, Relaxed, Relaxed)
            {
                Ok(_) => return,
                Err(now) => used = now,
            }
        }
    }

    pub fn used(&self) -> usize {
        self.used.load(Relaxed)
    }

    /// `None` while no budget is set.
    pub fn limit(&self) -> Option<usize> {
        Some(self.limit.load(Relaxed)).filter(|limit| *limit != usize::MAX)
    }
}

/// The budget chosen automatically: a quarter of the machine's memory, between 64 MiB and 1 GiB
/// (256 MiB when the memory size cannot be read).
pub fn automatic_budget_mb(total_memory_mb: Option<u64>) -> u64 {
    total_memory_mb.map_or(256, |total| (total / 4).clamp(64, 1024))
}

/// The memory this process can really use, in MiB: the machine's, or the smaller limit of the
/// container or service it runs in (cgroup), which is what decides when it gets killed.
fn total_memory_mb() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(smaller_of(kib / 1024, cgroup_memory_limit()))
}

/// The smaller of the machine's memory and a cgroup limit in bytes (if there is one).
fn smaller_of(machine_mb: u64, cgroup_bytes: Option<u64>) -> u64 {
    cgroup_bytes.map_or(machine_mb, |bytes| machine_mb.min(bytes / (1024 * 1024)))
}

/// A cgroup limit file's content: a number of bytes, or `max` (cgroup v2) for no limit.
fn parse_cgroup_limit(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// The smallest memory limit of the cgroup the process is in, or of any parent of it (cgroup v2
/// `memory.max`, or v1 `memory.limit_in_bytes`). A container usually sees its own cgroup as the
/// root; a service on a normal host sits below `system.slice`.
#[cfg(target_os = "linux")]
fn cgroup_memory_limit() -> Option<u64> {
    use std::path::{Path, PathBuf};
    let membership = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let mut limit: Option<u64> = None;
    for line in membership.lines() {
        let mut parts = line.splitn(3, ':');
        let (Some(hierarchy), Some(controllers), Some(path)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let (base, file) = if hierarchy == "0" && controllers.is_empty() {
            ("/sys/fs/cgroup", "memory.max")
        } else if controllers.split(',').any(|name| name == "memory") {
            ("/sys/fs/cgroup/memory", "memory.limit_in_bytes")
        } else {
            continue;
        };
        let mut current = PathBuf::from(path);
        loop {
            let relative = current.strip_prefix("/").unwrap_or(&current).to_path_buf();
            let candidate = Path::new(base).join(relative).join(file);
            if let Some(bytes) = std::fs::read_to_string(&candidate)
                .ok()
                .and_then(|text| parse_cgroup_limit(&text))
            {
                limit = Some(limit.map_or(bytes, |smallest| smallest.min(bytes)));
            }
            if !current.pop() || current.as_os_str().is_empty() {
                break;
            }
        }
    }
    limit
}

#[cfg(not(target_os = "linux"))]
fn cgroup_memory_limit() -> Option<u64> {
    None
}

/// The budget in frames for a `memory_budget_mb` setting (0 = automatic) and whether it was
/// chosen automatically.
pub fn budget_frames(setting_mb: u64) -> (usize, bool) {
    let automatic = setting_mb == 0;
    let mb = if automatic {
        automatic_budget_mb(total_memory_mb())
    } else {
        setting_mb
    };
    ((mb as usize).saturating_mul(FRAMES_PER_MIB), automatic)
}

#[derive(Default)]
pub struct Stats {
    /// Latest authenticated raw size-probe lower bound; zero is inconclusive/not run.
    pub raw_payload_echoed: AtomicUsize,
    pub raw_inner_mtu_advisory: AtomicUsize,
    /// Authenticated tunnel sessions open right now.
    pub sessions: AtomicUsize,
    /// User connections (streams) open right now.
    pub streams: AtomicUsize,
    /// Tunnel sessions opened since start. Growing fast while `sessions` stays the same means
    /// the link keeps dropping and reconnecting.
    pub sessions_total: AtomicU64,
    pub streams_total: AtomicU64,
    /// User connections turned away because no session or stream capacity was available.
    pub streams_refused: AtomicU64,
    /// Incoming tunnel connections dropped: too many waiting, failed handshake, or no free slot.
    pub connections_rejected: AtomicU64,
    /// Requests from the other server for a target that `allowed_targets` does not list.
    pub targets_denied: AtomicU64,
    /// Bytes sent into the tunnel by this machine.
    pub bytes_to_peer: AtomicU64,
    /// Bytes received from the tunnel by this machine.
    pub bytes_from_peer: AtomicU64,
    /// Heartbeats sent and answered; their difference shows lost or very late answers.
    pub pings: AtomicU64,
    pub pongs: AtomicU64,
    /// Heartbeats still unanswered one full heartbeat interval after they were sent. A ping
    /// that is merely in flight is not counted; a late answer takes it back out.
    pub pings_lost: AtomicU64,
    /// Memory the flow-control windows of all user connections may use (see `WindowBudget`).
    pub window_budget: WindowBudget,
    /// UDP datagrams dropped before entering the tunnel because the memory budget was used up or
    /// the conversation's queue was full.
    pub udp_dropped: AtomicU64,
    /// The live sessions, to tell the other server before this one stops.
    pub farewell: crate::farewell::Farewell,
    /// Heartbeat round trips in microseconds.
    rtt: Mutex<VecDeque<u32>>,
    started: OnceLock<Instant>,
}

impl Stats {
    pub fn refuse_stream(&self) {
        self.streams_refused.fetch_add(1, Relaxed);
    }

    pub fn reject_connection(&self) {
        self.connections_rejected.fetch_add(1, Relaxed);
    }

    /// Marks the moment the tunnel started (the first call wins).
    pub fn start(&self) {
        let _ = self.started.set(Instant::now());
    }

    pub fn uptime(&self) -> Duration {
        self.started.get().map_or(Duration::ZERO, Instant::elapsed)
    }

    pub fn record_rtt(&self, rtt: Duration) {
        let mut samples = self.rtt.lock().unwrap_or_else(|p| p.into_inner());
        if samples.len() == RTT_SAMPLES {
            samples.pop_front();
        }
        samples.push_back(rtt.as_micros().min(u32::MAX as u128) as u32);
    }

    pub fn rtt_samples(&self) -> Vec<u32> {
        self.rtt
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .collect()
    }

    pub fn summary(&self) -> String {
        format!(
            "sessions={} connects={} streams={} streams_total={} refused={} rejected={} udp_dropped={} sent={} received={}",
            self.sessions.load(Relaxed),
            self.sessions_total.load(Relaxed),
            self.streams.load(Relaxed),
            self.streams_total.load(Relaxed),
            self.streams_refused.load(Relaxed),
            self.connections_rejected.load(Relaxed),
            self.udp_dropped.load(Relaxed),
            human_bytes(self.bytes_to_peer.load(Relaxed)),
            human_bytes(self.bytes_from_peer.load(Relaxed)),
        )
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Logs one summary line every `every`. Runs until the task is dropped.
pub async fn report(stats: Arc<Stats>, every: Duration) {
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        tracing::info!("status: {}", stats.summary());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_container_limit_below_the_machines_memory_decides_the_budget() {
        // A 16 GiB machine, a container limited to 512 MiB: the budget follows the container.
        assert_eq!(smaller_of(16 * 1024, Some(512 * 1024 * 1024)), 512);
        assert_eq!(
            automatic_budget_mb(Some(smaller_of(16 * 1024, Some(512 * 1024 * 1024)))),
            128
        );
        // No limit, or a limit above the machine (cgroup v1 reports an enormous number): the machine.
        assert_eq!(smaller_of(2048, None), 2048);
        assert_eq!(smaller_of(2048, Some(9_223_372_036_854_771_712)), 2048);
        assert_eq!(parse_cgroup_limit("max\n"), None);
        assert_eq!(parse_cgroup_limit("268435456\n"), Some(268_435_456));
    }

    #[test]
    fn human_bytes_picks_a_readable_unit() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
        assert!(human_bytes(u64::MAX).ends_with("TiB"));
    }

    #[test]
    fn the_window_budget_grants_what_is_left_and_takes_frames_back() {
        let budget = WindowBudget::default();
        assert_eq!(budget.limit(), None, "unlimited until configured");
        assert_eq!(budget.reserve(1_000_000), 1_000_000);
        budget.release(1_000_000);
        budget.set_limit(100);
        assert_eq!(budget.limit(), Some(100));
        assert_eq!(budget.reserve(60), 60);
        assert_eq!(budget.reserve(60), 40, "only what is left");
        assert_eq!(budget.reserve(1), 0, "used up");
        assert_eq!(budget.used(), 100);
        budget.release(60);
        assert_eq!(budget.reserve(30), 30);
        assert_eq!(budget.used(), 70);
        // Releasing more than is held never underflows.
        budget.release(1_000);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn the_automatic_budget_is_a_quarter_of_memory_within_bounds() {
        assert_eq!(automatic_budget_mb(Some(512)), 128);
        assert_eq!(automatic_budget_mb(Some(8192)), 1024);
        assert_eq!(automatic_budget_mb(Some(64 * 1024)), 1024, "capped");
        assert_eq!(automatic_budget_mb(Some(100)), 64, "never below 64 MiB");
        assert_eq!(automatic_budget_mb(None), 256);
        assert_eq!(budget_frames(8), (8 * FRAMES_PER_MIB, false));
        let (frames, automatic) = budget_frames(0);
        assert!(automatic && frames >= 64 * FRAMES_PER_MIB);
    }

    #[test]
    fn summary_reports_every_counter() {
        let stats = Stats::default();
        stats.sessions.fetch_add(2, Relaxed);
        stats.sessions_total.fetch_add(7, Relaxed);
        stats.refuse_stream();
        stats.reject_connection();
        stats.reject_connection();
        let line = stats.summary();
        assert!(line.contains("sessions=2"));
        assert!(line.contains("connects=7"));
        assert!(line.contains("refused=1"));
        assert!(line.contains("rejected=2"));
    }
}
