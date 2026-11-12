//! Planned restarts and the traffic quota of one tunnel process.
//!
//! Both end the process cleanly and leave starting it again to the service manager, so a
//! restart needs no special code in the engine. The quota keeps its count in a small file, so
//! the data already carried survives restarts, and a tunnel whose quota is used up stays idle
//! (holding no ports) until the period ends.
use crate::{
    config::{Quota, Schedule},
    stats::Stats,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering::Relaxed},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// How often the carried data is added up and saved.
const SAMPLE_EVERY: Duration = Duration::from_secs(10);

/// Message the manager looks for in the journal.
pub const EXHAUSTED_MESSAGE: &str = "traffic quota used up";

/// What has been carried in the current period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaState {
    /// Start of the current period, seconds since 1970.
    pub period_start: u64,
    /// Bytes carried in both directions since then.
    pub used_bytes: u64,
}

/// A clock that is set back by this much or less (a time sync) does not start a new period.
const CLOCK_STEP_TOLERANCE: u64 = 3600;

impl QuotaState {
    pub fn fresh(now: u64) -> Self {
        Self {
            period_start: now,
            used_bytes: 0,
        }
    }

    /// Starts a new period when the old one is over; returns whether it did. A tunnel that was
    /// off for several periods lands in the one that contains `now`, keeping the original grid.
    pub fn roll(&mut self, now: u64, period_seconds: u64) -> bool {
        if period_seconds == 0 {
            return false;
        }
        // The period starts after "now": the clock was wrong when the state was written (before
        // the time was synced). Left alone, the count would never roll over.
        if self.period_start > now.saturating_add(CLOCK_STEP_TOLERANCE) {
            tracing::warn!(
                period_start = self.period_start,
                now,
                used_bytes = self.used_bytes,
                "the clock moved back more than an hour; the quota period and its count were reset"
            );
            *self = Self::fresh(now);
            return true;
        }
        if now < self.period_start.saturating_add(period_seconds) {
            return false;
        }
        let periods = (now - self.period_start) / period_seconds;
        self.period_start += periods * period_seconds;
        self.used_bytes = 0;
        true
    }

    pub fn period_end(&self, period_seconds: u64) -> u64 {
        self.period_start.saturating_add(period_seconds)
    }

    pub fn exhausted(&self, limit_bytes: u64) -> bool {
        limit_bytes > 0 && self.used_bytes >= limit_bytes
    }

    /// `None` both when the file is missing (a tunnel's first run) and when it is damaged; the
    /// latter is logged, since it silently restarts the count at zero.
    pub fn load(path: &Path) -> Option<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "could not read the quota count; starting over at zero");
                return None;
            }
        };
        match serde_json::from_slice(&bytes) {
            Ok(state) => Some(state),
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "the quota count is damaged; starting over at zero");
                None
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let temporary = path.with_extension("tmp");
        let file = std::fs::File::create(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        serde_json::to_writer(&file, self)
            .with_context(|| format!("write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("flush {}", temporary.display()))?;
        std::fs::rename(&temporary, path).context("replace the quota file")
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Where a tunnel run by the manager keeps its count (a systemd state directory).
pub fn service_state_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/var/lib/eztunnel-{name}/quota.json"))
}

/// Where this process keeps its count: the service's state directory when systemd gave one,
/// otherwise next to the configuration file.
pub fn state_path(config_path: &Path) -> PathBuf {
    state_path_with(
        config_path,
        std::env::var_os("EZTUNNEL_QUOTA_FILE").as_deref(),
        std::env::var_os("STATE_DIRECTORY").as_deref(),
    )
}

fn state_path_with(
    config_path: &Path,
    explicit: Option<&std::ffi::OsStr>,
    directories: Option<&std::ffi::OsStr>,
) -> PathBuf {
    // New manager units supply the exact path, independently of the config name.
    if let Some(path) = explicit.filter(|path| !path.is_empty()) {
        return PathBuf::from(path);
    }
    // Units made by older versions also list the shared /var/lib/eztunnel directory. Select
    // the tunnel's own directory so each tunnel keeps its own counter.
    if let Some(directories) = directories {
        let text = directories.to_string_lossy();
        let entries: Vec<_> = text
            .split(':')
            .filter(|part| !part.is_empty())
            .map(PathBuf::from)
            .collect();
        if let Some(name) = config_path.file_stem().and_then(|name| name.to_str()) {
            let wanted = format!("eztunnel-{name}");
            if let Some(path) = entries
                .iter()
                .find(|path| path.file_name().is_some_and(|name| name == wanted.as_str()))
            {
                return path.join("quota.json");
            }
        }
        let mut tunnels = entries.iter().filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("eztunnel-"))
        });
        if let Some(path) = tunnels.next() {
            if tunnels.next().is_none() {
                return path.join("quota.json");
            }
        }
        // Retain a custom single-directory service's previous behavior, but never
        // choose the shared /var/lib/eztunnel directory as quota storage.
        if entries.len() == 1 && entries[0].file_name().is_none_or(|name| name != "eztunnel") {
            return entries[0].join("quota.json");
        }
    }
    let mut name = config_path.as_os_str().to_owned();
    name.push(".quota");
    PathBuf::from(name)
}

/// Human text for a duration, for log lines and the manager.
pub fn describe_seconds(seconds: u64) -> String {
    match (seconds / 86_400, seconds / 3600 % 24, seconds / 60 % 60) {
        (0, 0, m) => format!("{m} minute(s)"),
        (0, h, m) => format!("{h} h {m} min"),
        (d, h, _) => format!("{d} day(s) {h} h"),
    }
}

/// Returns once the tunnel may run: at once without a quota or with room left, otherwise after
/// idling until the period that used it up ends. The idle process holds no ports.
pub async fn wait_until_available(quota: &Quota, state_file: &Path) {
    if !quota.enabled() {
        return;
    }
    let mut announced = false;
    loop {
        let now = now();
        let mut state = QuotaState::load(state_file).unwrap_or_else(|| QuotaState::fresh(now));
        if state.roll(now, quota.period_seconds())
            && let Err(error) = state.save(state_file)
        {
            tracing::warn!(%error, "could not save the quota count");
        }
        if !state.exhausted(quota.limit_bytes()) {
            if announced {
                tracing::info!("a new quota period has started; the tunnel runs again");
            }
            return;
        }
        let remaining = state.period_end(quota.period_seconds()).saturating_sub(now);
        if !announced {
            tracing::warn!(
                used_gb = state.used_bytes / 1_000_000_000,
                limit_gb = quota.limit_gb,
                resumes_in = %describe_seconds(remaining),
                "{EXHAUSTED_MESSAGE}: the tunnel stays off until the period ends"
            );
            announced = true;
        }
        tokio::time::sleep(Duration::from_secs(remaining.clamp(1, 60))).await;
    }
}

/// Adds up the data the engine carries and keeps the file current.
pub struct Tracker {
    quota: Quota,
    file: PathBuf,
    stats: Arc<Stats>,
    state: QuotaState,
    counted: u64,
}

impl Tracker {
    pub fn new(quota: Quota, file: PathBuf, stats: Arc<Stats>) -> Self {
        let now = now();
        let mut state = QuotaState::load(&file).unwrap_or_else(|| QuotaState::fresh(now));
        state.roll(now, quota.period_seconds());
        Self {
            quota,
            file,
            stats,
            state,
            counted: 0,
        }
    }

    fn carried(&self) -> u64 {
        self.stats
            .bytes_to_peer
            .load(Relaxed)
            .saturating_add(self.stats.bytes_from_peer.load(Relaxed))
    }

    /// A cheap, unsaved check against the live counters: whether the limit is already reached
    /// right now, without waiting for the next `sample()`. Lets `watch()` poll often (catching a
    /// fast tunnel close to the limit sooner) while still only writing the state file every
    /// `SAMPLE_EVERY`.
    fn would_be_exhausted(&self) -> bool {
        if !self.quota.enabled() {
            return false;
        }
        let added = self.carried().saturating_sub(self.counted);
        let projected = self.state.used_bytes.saturating_add(added);
        self.quota.limit_bytes() > 0 && projected >= self.quota.limit_bytes()
    }

    /// Adds what was carried since the last call, saves it, and says whether the limit is reached.
    pub fn sample(&mut self) -> bool {
        // Without a quota nothing is counted, and there may be no writable place for the file.
        if !self.quota.enabled() {
            return false;
        }
        // An explicit manager reset/period change can occur while the process
        // is active. Adopt a fresh external baseline instead of overwriting it
        // from our stale in-memory count at the next timer tick.
        if let Ok(bytes)=std::fs::read(&self.file)&&let Ok(external)=serde_json::from_slice::<QuotaState>(&bytes){
            if external.period_start!=self.state.period_start||external.used_bytes<self.state.used_bytes{
                self.state=external;
                self.counted=self.carried();
            }
        }
        let carried = self.carried();
        let added = carried.saturating_sub(self.counted);
        self.counted = carried;
        let rolled = self.state.roll(now(), self.quota.period_seconds());
        self.state.used_bytes = self.state.used_bytes.saturating_add(added);
        if (added > 0 || rolled)
            && let Err(error) = self.state.save(&self.file)
        {
            tracing::warn!(%error, "could not save the quota count");
        }
        self.state.exhausted(self.quota.limit_bytes())
    }

    pub fn state(&self) -> QuotaState {
        self.state
    }
}

/// Shared handle so the caller can take a last sample after the tunnel stopped.
pub type SharedTracker = Arc<std::sync::Mutex<Tracker>>;

/// How often the live counters are checked against the limit between full samples: a fast
/// tunnel is stopped within this long of crossing the limit instead of up to `SAMPLE_EVERY`.
const POLL_EVERY: Duration = Duration::from_millis(500);

/// Completes when the quota is used up. Never completes without a quota.
pub async fn watch(tracker: SharedTracker) {
    let enabled = tracker
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .quota
        .enabled();
    if !enabled {
        std::future::pending::<()>().await;
    }
    let mut since_sample = Duration::ZERO;
    loop {
        tokio::time::sleep(POLL_EVERY).await;
        since_sample += POLL_EVERY;
        let mut guard = tracker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let exhausted = if since_sample >= SAMPLE_EVERY {
            since_sample = Duration::ZERO;
            guard.sample()
        } else {
            guard.would_be_exhausted()
        };
        drop(guard);
        if exhausted {
            return;
        }
    }
}

/// How long the tunnel runs before a planned restart; `None` when none is planned.
pub fn restart_delay(schedule: &Schedule) -> Option<Duration> {
    (schedule.restart_every_hours > 0)
        .then(|| Duration::from_secs(schedule.restart_every_hours.saturating_mul(3600)))
}

/// Completes when the tunnel has run as long as `schedule` asks. Never completes without one.
pub async fn restart_due(schedule: &Schedule) {
    match restart_delay(schedule) {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    #[test]
    fn a_period_rolls_over_on_its_original_grid() {
        let mut state = QuotaState {
            period_start: 1000,
            used_bytes: 5,
        };
        assert!(!state.roll(1000 + DAY - 1, DAY), "still inside the period");
        assert_eq!(state.used_bytes, 5);
        assert!(state.roll(1000 + DAY, DAY));
        assert_eq!(state, QuotaState::fresh(1000 + DAY));
        // Off for three and a half periods: the new period still starts on the grid.
        let mut state = QuotaState {
            period_start: 1000,
            used_bytes: 9,
        };
        assert!(state.roll(1000 + 3 * DAY + DAY / 2, DAY));
        assert_eq!(state.period_start, 1000 + 3 * DAY);
        assert_eq!(state.used_bytes, 0);
    }

    #[test]
    fn a_period_that_starts_far_in_the_future_is_replaced_but_a_small_clock_step_is_not() {
        let mut stepped = QuotaState {
            period_start: 1_000_000_000,
            used_bytes: 5,
        };
        assert!(!stepped.roll(1_000_000_000 - 2, 3600));
        assert_eq!(stepped.used_bytes, 5);
        // Saved while the clock said 2033; the real time is 2001.
        let mut future = QuotaState {
            period_start: 2_000_000_000,
            used_bytes: 9,
        };
        assert!(future.roll(1_000_000_000, 3600));
        assert_eq!((future.period_start, future.used_bytes), (1_000_000_000, 0));
    }

    #[test]
    fn the_limit_is_reached_at_exactly_the_limit_and_zero_means_none() {
        let state = QuotaState {
            period_start: 0,
            used_bytes: 100,
        };
        assert!(state.exhausted(100));
        assert!(!state.exhausted(101));
        assert!(!state.exhausted(0));
    }

    #[test]
    fn the_count_survives_a_restart_through_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("quota.json");
        assert_eq!(QuotaState::load(&file), None);
        let state = QuotaState {
            period_start: 42,
            used_bytes: 7,
        };
        state.save(&file).unwrap();
        assert_eq!(QuotaState::load(&file), Some(state));
        std::fs::write(&file, "not json").unwrap();
        assert_eq!(QuotaState::load(&file), None, "a damaged file starts over");
    }

    #[test]
    fn the_tracker_adds_what_the_engine_carried_and_stops_at_the_limit() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("quota.json");
        let stats = Arc::new(Stats::default());
        let quota = Quota {
            limit_gb: 1,
            period_days: 30,
        };
        let mut tracker = Tracker::new(quota.clone(), file.clone(), stats.clone());
        assert!(!tracker.sample());
        stats.bytes_to_peer.fetch_add(400_000_000, Relaxed);
        stats.bytes_from_peer.fetch_add(500_000_000, Relaxed);
        assert!(!tracker.sample());
        assert_eq!(tracker.state().used_bytes, 900_000_000);
        // Sampling twice without traffic adds nothing.
        assert!(!tracker.sample());
        assert_eq!(tracker.state().used_bytes, 900_000_000);
        stats.bytes_from_peer.fetch_add(100_000_000, Relaxed);
        assert!(tracker.sample());
        // A restarted process (fresh counters) continues from the saved count.
        let mut again = Tracker::new(quota, file, Arc::new(Stats::default()));
        assert_eq!(again.state().used_bytes, 1_000_000_000);
        assert!(again.sample(), "still used up after the restart");
    }
    #[test]
    fn externally_reset_period_is_not_overwritten_by_an_active_tracker(){
        let directory=tempfile::tempdir().unwrap();let file=directory.path().join("quota.json");let stats=Arc::new(Stats::default());
        let mut tracker=Tracker::new(Quota{limit_gb:1,period_days:30},file.clone(),stats.clone());
        stats.bytes_to_peer.store(100,Relaxed);tracker.sample();assert_eq!(tracker.state.used_bytes,100);
        let reset=QuotaState{period_start:now(),used_bytes:0};reset.save(&file).unwrap();
        tracker.sample();assert_eq!(tracker.state.used_bytes,0);
        stats.bytes_to_peer.fetch_add(7,Relaxed);tracker.sample();assert_eq!(tracker.state.used_bytes,7);
    }

    #[test]
    fn would_be_exhausted_sees_the_limit_between_samples_without_saving() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("quota.json");
        let stats = Arc::new(Stats::default());
        let quota = Quota {
            limit_gb: 1,
            period_days: 30,
        };
        let mut tracker = Tracker::new(quota, file.clone(), stats.clone());
        assert!(!tracker.would_be_exhausted());
        // Traffic that would cross the limit is seen at once, before the next sample() call.
        stats.bytes_to_peer.fetch_add(1_000_000_000, Relaxed);
        assert!(tracker.would_be_exhausted());
        // Checking it does not itself count or save anything.
        assert_eq!(tracker.state().used_bytes, 0);
        assert_eq!(QuotaState::load(&file), None);
        assert!(
            tracker.sample(),
            "sample() independently reaches the same limit"
        );
    }

    #[tokio::test]
    async fn an_unused_quota_lets_the_tunnel_run_and_a_used_one_waits_for_the_period() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("quota.json");
        let quota = Quota {
            limit_gb: 1,
            period_days: 1,
        };
        // No file yet: room left.
        tokio::time::timeout(Duration::from_secs(2), wait_until_available(&quota, &file))
            .await
            .expect("room left");
        // Used up inside the current period: it keeps waiting.
        QuotaState {
            period_start: now(),
            used_bytes: 2_000_000_000,
        }
        .save(&file)
        .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(300),
                wait_until_available(&quota, &file)
            )
            .await
            .is_err()
        );
        // The same count in a period that ended long ago: a new period begins.
        QuotaState {
            period_start: now() - 3 * DAY,
            used_bytes: 2_000_000_000,
        }
        .save(&file)
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), wait_until_available(&quota, &file))
            .await
            .expect("new period");
        assert_eq!(QuotaState::load(&file).unwrap().used_bytes, 0);
    }

    #[tokio::test]
    async fn without_a_schedule_or_quota_nothing_ever_triggers() {
        let tracker: SharedTracker = Arc::new(std::sync::Mutex::new(Tracker::new(
            Quota::default(),
            PathBuf::from("/nonexistent/quota.json"),
            Arc::new(Stats::default()),
        )));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), watch(tracker))
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                restart_due(&Schedule::default())
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn a_schedule_means_that_many_hours_and_zero_means_none() {
        assert_eq!(restart_delay(&Schedule::default()), None);
        assert_eq!(
            restart_delay(&Schedule {
                restart_every_hours: 2
            }),
            Some(Duration::from_secs(7200))
        );
    }

    #[test]
    fn the_state_file_sits_in_the_service_directory_or_next_to_the_config() {
        assert_eq!(
            state_path_with(Path::new("/etc/eztunnel/tunnels/a.json"), None, None),
            PathBuf::from("/etc/eztunnel/tunnels/a.json.quota")
        );
        assert_eq!(
            service_state_path("a"),
            PathBuf::from("/var/lib/eztunnel-a/quota.json")
        );
    }

    #[test]
    fn shared_state_directory_is_never_selected_for_quota_storage() {
        use std::ffi::OsStr;
        for name in ["alpha", "beta"] {
            let config = PathBuf::from(format!("/etc/eztunnel/tunnels/{name}.json"));
            for directories in [
                format!("/var/lib/eztunnel:/var/lib/eztunnel-{name}"),
                format!("/var/lib/eztunnel-{name}:/var/lib/eztunnel"),
            ] {
                assert_eq!(
                    state_path_with(&config, None, Some(OsStr::new(&directories))),
                    service_state_path(name)
                );
            }
        }
        let config = Path::new("/etc/custom.json");
        assert_eq!(
            state_path_with(
                config,
                None,
                Some(OsStr::new("/var/lib/eztunnel:/var/lib/eztunnel-alpha"))
            ),
            service_state_path("alpha")
        );
        assert_eq!(
            state_path_with(
                config,
                Some(OsStr::new("/var/lib/eztunnel-beta/quota.json")),
                Some(OsStr::new("/var/lib/eztunnel"))
            ),
            service_state_path("beta")
        );
        assert_eq!(
            state_path_with(config, None, Some(OsStr::new("/var/lib/eztunnel"))),
            PathBuf::from("/etc/custom.json.quota")
        );
        assert_eq!(
            state_path_with(config, None, Some(OsStr::new("/var/lib/custom-state"))),
            PathBuf::from("/var/lib/custom-state/quota.json")
        );
    }

    #[test]
    fn two_tunnels_with_a_shared_directory_keep_independent_quota_counts() {
        let directory = tempfile::tempdir().unwrap();
        let shared = directory.path().join("eztunnel");
        std::fs::create_dir(&shared).unwrap();
        let mut paths = Vec::new();
        for name in ["alpha", "beta"] {
            let own = directory.path().join(format!("eztunnel-{name}"));
            std::fs::create_dir(&own).unwrap();
            let entries = format!("{}:{}", shared.display(), own.display());
            paths.push(state_path_with(
                Path::new(&format!("{name}.json")),
                None,
                Some(std::ffi::OsStr::new(&entries)),
            ));
        }
        assert_ne!(paths[0], paths[1]);
        std::thread::scope(|scope| {
            for (i, path) in paths.iter().enumerate() {
                scope.spawn(move || {
                    for used in 0..50 {
                        QuotaState {
                            period_start: 100 + i as u64,
                            used_bytes: (i as u64 + 1) * 1000 + used,
                        }
                        .save(path)
                        .unwrap();
                    }
                });
            }
        });
        assert_eq!(
            QuotaState::load(&paths[0]),
            Some(QuotaState {
                period_start: 100,
                used_bytes: 1049
            })
        );
        assert_eq!(
            QuotaState::load(&paths[1]),
            Some(QuotaState {
                period_start: 101,
                used_bytes: 2049
            })
        );
        assert!(!shared.join("quota.json").exists());
    }
}
