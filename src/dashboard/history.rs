//! Metrics history: one row per minute for this server and for every tunnel, kept for 30 days.
//!
//! Snapshots (every two seconds) are summed into the row of the current minute; when the minute
//! changes the row is written. Each series keeps one file per day (UTC) of 1440 fixed-size rows,
//! so a minute is found by its offset and nothing needs a database. Files older than the
//! retention are deleted.
use super::data::{INTERVAL, Snapshot};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Days of history kept.
pub const RETENTION_DAYS: u64 = 30;
const MINUTES_PER_DAY: u64 = 1440;
const MAGIC: &[u8; 8] = b"EZHIST01";
const ROW: usize = 56;

/// What one minute looked like. `samples == 0` means no data for that minute.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Row {
    /// Bytes users received (download) and sent (upload) during the minute.
    pub down: u64,
    pub up: u64,
    /// Highest rate seen, bytes per second.
    pub peak_down: f32,
    pub peak_up: f32,
    /// Average and highest round trip in ms (NaN when unknown).
    pub rtt: f32,
    pub rtt_max: f32,
    /// Average heartbeat loss in percent (NaN when unknown).
    pub loss: f32,
    pub sessions: f32,
    /// Host only: average CPU, memory and disk use in percent (NaN otherwise).
    pub cpu: f32,
    pub mem: f32,
    pub disk: f32,
    /// Snapshots that went into the row, and how many of them found the tunnel running.
    pub samples: u16,
    pub running: u16,
}

impl Row {
    fn encode(&self, out: &mut [u8]) {
        out[0..8].copy_from_slice(&self.down.to_le_bytes());
        out[8..16].copy_from_slice(&self.up.to_le_bytes());
        let floats = [
            self.peak_down, self.peak_up, self.rtt, self.rtt_max, self.loss, self.sessions,
            self.cpu, self.mem, self.disk,
        ];
        for (i, value) in floats.iter().enumerate() {
            out[16 + i * 4..20 + i * 4].copy_from_slice(&value.to_le_bytes());
        }
        out[52..54].copy_from_slice(&self.samples.to_le_bytes());
        out[54..56].copy_from_slice(&self.running.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Self {
        let u64_at = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        let f32_at = |i: usize| f32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let u16_at = |i: usize| u16::from_le_bytes(bytes[i..i + 2].try_into().unwrap());
        Self {
            down: u64_at(0),
            up: u64_at(8),
            peak_down: f32_at(16),
            peak_up: f32_at(20),
            rtt: f32_at(24),
            rtt_max: f32_at(28),
            loss: f32_at(32),
            sessions: f32_at(36),
            cpu: f32_at(40),
            mem: f32_at(44),
            disk: f32_at(48),
            samples: u16_at(52),
            running: u16_at(54),
        }
    }
}

/// Where rows are kept.
pub trait Store: Send + Sync {
    fn put(&self, series: &str, minute: u64, row: &Row) -> Result<()>;
    /// Rows with data in `[from, to)` minutes.
    fn rows(&self, series: &str, from: u64, to: u64) -> Vec<(u64, Row)>;
    fn series(&self) -> Vec<String>;
    /// The first minute that has any data, in any series.
    fn first_minute(&self) -> Option<u64>;
    /// Removes data older than the retention; `today` is the current UTC day number.
    fn prune(&self, _today: u64) {}
}

/// Rows on disk: `<dir>/<series>/<unix day>.bin`.
pub struct FileStore {
    dir: PathBuf,
    /// The day being written for each series, kept in memory so a minute costs one write.
    open: Mutex<HashMap<String, (u64, Vec<u8>)>>,
}

/// Series names become directory names: `host`, or `t-` and a tunnel name (tunnel names are
/// already limited to letters, digits and hyphens).
fn directory_of(series: &str) -> Option<String> {
    if series == "host" {
        return Some("host".into());
    }
    let name = series.strip_prefix("t:")?;
    (!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        .then(|| format!("t-{name}"))
}

fn series_of(directory: &str) -> Option<String> {
    if directory == "host" {
        return Some("host".into());
    }
    directory.strip_prefix("t-").map(|name| format!("t:{name}"))
}

fn empty_day() -> Vec<u8> {
    let mut bytes = vec![0u8; MAGIC.len() + MINUTES_PER_DAY as usize * ROW];
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    bytes
}

fn row_in(day: &[u8], minute_of_day: u64) -> Row {
    let start = MAGIC.len() + minute_of_day as usize * ROW;
    Row::decode(&day[start..start + ROW])
}

impl FileStore {
    pub fn open(dir: &Path) -> Result<Self> {
        super::create_private_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            open: Mutex::new(HashMap::new()),
        })
    }

    fn day_path(&self, directory: &str, day: u64) -> PathBuf {
        self.dir.join(directory).join(format!("{day}.bin"))
    }

    fn read_day(&self, directory: &str, day: u64) -> Option<Vec<u8>> {
        let bytes = std::fs::read(self.day_path(directory, day)).ok()?;
        (bytes.len() == MAGIC.len() + MINUTES_PER_DAY as usize * ROW && bytes.starts_with(MAGIC))
            .then_some(bytes)
    }

    fn days(&self, directory: &str) -> Vec<u64> {
        let mut days: Vec<u64> = std::fs::read_dir(self.dir.join(directory))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.strip_suffix(".bin")?.parse().ok())
            .collect();
        days.sort_unstable();
        days
    }
}

impl Store for FileStore {
    fn put(&self, series: &str, minute: u64, row: &Row) -> Result<()> {
        let directory = directory_of(series).context("bad series name")?;
        let (day, minute_of_day) = (minute / MINUTES_PER_DAY, minute % MINUTES_PER_DAY);
        let mut open = self.open.lock().unwrap();
        let entry = open.entry(series.to_string()).or_insert_with(|| (u64::MAX, Vec::new()));
        if entry.0 != day {
            *entry = (day, self.read_day(&directory, day).unwrap_or_else(empty_day));
        }
        let start = MAGIC.len() + minute_of_day as usize * ROW;
        row.encode(&mut entry.1[start..start + ROW]);
        super::create_private_dir(&self.dir.join(&directory))?;
        super::write_private(&self.day_path(&directory, day), &entry.1)
    }

    fn rows(&self, series: &str, from: u64, to: u64) -> Vec<(u64, Row)> {
        let Some(directory) = directory_of(series) else { return Vec::new() };
        let open = self.open.lock().unwrap();
        let mut rows = Vec::new();
        // Only days that exist (on disk or being written) inside the range.
        let (first_day, last_day) = (from / MINUTES_PER_DAY, to.saturating_sub(1) / MINUTES_PER_DAY);
        let mut days: Vec<u64> = self.days(&directory);
        if let Some((day, _)) = open.get(series) {
            days.push(*day);
        }
        days.sort_unstable();
        days.dedup();
        for day in days.into_iter().filter(|d| (first_day..=last_day).contains(d)) {
            let cached = open.get(series).filter(|(d, _)| *d == day).map(|(_, b)| b.clone());
            let Some(bytes) = cached.or_else(|| self.read_day(&directory, day)) else { continue };
            for minute_of_day in 0..MINUTES_PER_DAY {
                let minute = day * MINUTES_PER_DAY + minute_of_day;
                if minute < from || minute >= to {
                    continue;
                }
                let row = row_in(&bytes, minute_of_day);
                if row.samples > 0 {
                    rows.push((minute, row));
                }
            }
        }
        rows
    }

    fn series(&self) -> Vec<String> {
        let mut list: Vec<String> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| series_of(entry.file_name().to_str()?))
            .collect();
        list.sort();
        list
    }

    fn first_minute(&self) -> Option<u64> {
        self.series()
            .iter()
            .filter_map(|series| {
                let directory = directory_of(series)?;
                let day = *self.days(&directory).first()?;
                let bytes = self.read_day(&directory, day)?;
                (0..MINUTES_PER_DAY)
                    .find(|m| row_in(&bytes, *m).samples > 0)
                    .map(|m| day * MINUTES_PER_DAY + m)
            })
            .min()
    }

    fn prune(&self, today: u64) {
        let oldest = today.saturating_sub(RETENTION_DAYS);
        for series in self.series() {
            let Some(directory) = directory_of(&series) else { continue };
            for day in self.days(&directory) {
                if day < oldest {
                    let _ = std::fs::remove_file(self.day_path(&directory, day));
                }
            }
            // A tunnel deleted long ago leaves an empty directory behind.
            let _ = std::fs::remove_dir(self.dir.join(&directory));
        }
    }
}

/// Sums snapshots into the row of the current minute.
#[derive(Default)]
struct Sum {
    down: f64,
    up: f64,
    peak_down: f64,
    peak_up: f64,
    rtt: (f64, u32),
    rtt_max: f64,
    loss: (f64, u32),
    sessions: (f64, u32),
    cpu: (f64, u32),
    mem: (f64, u32),
    disk: (f64, u32),
    samples: u16,
    running: u16,
}

fn add(pair: &mut (f64, u32), value: Option<f64>) {
    if let Some(value) = value.filter(|v| v.is_finite()) {
        pair.0 += value;
        pair.1 += 1;
    }
}

fn mean(pair: (f64, u32)) -> f32 {
    if pair.1 == 0 { f32::NAN } else { (pair.0 / pair.1 as f64) as f32 }
}

impl Sum {
    fn row(&self) -> Row {
        Row {
            down: self.down.round() as u64,
            up: self.up.round() as u64,
            peak_down: self.peak_down as f32,
            peak_up: self.peak_up as f32,
            rtt: mean(self.rtt),
            rtt_max: if self.rtt.1 == 0 { f32::NAN } else { self.rtt_max as f32 },
            loss: mean(self.loss),
            sessions: mean(self.sessions),
            cpu: mean(self.cpu),
            mem: mean(self.mem),
            disk: mean(self.disk),
            samples: self.samples,
            running: self.running,
        }
    }

    fn traffic(&mut self, down_bps: Option<f64>, up_bps: Option<f64>) {
        let seconds = INTERVAL.as_secs_f64();
        let (down, up) = (down_bps.unwrap_or(0.0).max(0.0), up_bps.unwrap_or(0.0).max(0.0));
        self.down += down * seconds;
        self.up += up * seconds;
        self.peak_down = self.peak_down.max(down);
        self.peak_up = self.peak_up.max(up);
    }
}

pub struct History {
    store: Box<dyn Store>,
    current: Mutex<(u64, BTreeMap<String, Sum>)>,
    pruned_day: Mutex<u64>,
}

impl History {
    pub fn new(store: Box<dyn Store>) -> Self {
        Self {
            store,
            current: Mutex::new((0, BTreeMap::new())),
            pruned_day: Mutex::new(0),
        }
    }

    /// Adds one snapshot; writes the previous minute's rows when the minute changed.
    pub fn record(&self, snapshot: &Snapshot) {
        let minute = snapshot.at / 60_000;
        let finished = {
            let mut current = self.current.lock().unwrap();
            let finished = (current.0 != minute && current.0 != 0)
                .then(|| (current.0, std::mem::take(&mut current.1)));
            current.0 = minute;
            let sums = &mut current.1;
            let host = sums.entry("host".into()).or_default();
            host.samples = host.samples.saturating_add(1);
            host.running = host.running.saturating_add(1);
            host.traffic(snapshot.host.rx_bps, snapshot.host.tx_bps);
            add(&mut host.cpu, snapshot.host.cpu_pct);
            add(&mut host.mem, snapshot.host.mem_pct);
            add(&mut host.disk, snapshot.host.disk_pct);
            for tunnel in &snapshot.tunnels {
                let sum = sums.entry(format!("t:{}", tunnel.name)).or_default();
                sum.samples = sum.samples.saturating_add(1);
                if tunnel.state == "running" {
                    sum.running = sum.running.saturating_add(1);
                }
                sum.traffic(tunnel.down_bps, tunnel.up_bps);
                add(&mut sum.rtt, tunnel.rtt_ms);
                if let Some(rtt) = tunnel.rtt_ms {
                    sum.rtt_max = sum.rtt_max.max(rtt);
                }
                add(&mut sum.loss, tunnel.loss_pct);
                add(&mut sum.sessions, tunnel.sessions.map(|s| s as f64));
            }
            finished
        };
        if let Some((minute, sums)) = finished {
            for (series, sum) in sums {
                // A full disk loses this minute; the dashboard keeps running.
                let _ = self.store.put(&series, minute, &sum.row());
            }
            let today = minute / MINUTES_PER_DAY;
            let mut pruned = self.pruned_day.lock().unwrap();
            if *pruned != today {
                *pruned = today;
                self.store.prune(today);
            }
        }
    }

    /// Points for a chart. `range`: "24h", "7d" or "30d". `which`: "all" (every tunnel summed),
    /// "host", or "tunnels" (each tunnel apart). `tz_minutes` aligns daily buckets to the
    /// viewer's midnight.
    pub fn query(&self, range: &str, which: &str, now_ms: u64, tz_minutes: i64) -> Option<Value> {
        let (span, bucket): (u64, u64) = match range {
            "24h" => (24 * 60, 5),
            "7d" => (7 * 24 * 60, 60),
            "30d" => (30 * 24 * 60, 24 * 60),
            _ => return None,
        };
        // Daily buckets start at the viewer's midnight; the others at whole multiples of UTC.
        let offset = if bucket == 24 * 60 { tz_minutes } else { 0 };
        let start_of = |minute: u64| -> u64 {
            let b = bucket as i64;
            ((minute as i64 + offset).div_euclid(b) * b - offset).max(0) as u64
        };
        let to = start_of(now_ms / 60_000) + bucket;
        let from = to.saturating_sub(span / bucket * bucket);
        let points = |rows: &[(u64, Row)]| -> Vec<Value> {
            let count = ((to - from) / bucket) as usize;
            let mut buckets: Vec<Option<Row>> = vec![None; count];
            for (minute, row) in rows {
                let index = ((minute - from) / bucket) as usize;
                if index < count {
                    let b = buckets[index].get_or_insert_with(Row::default);
                    b.down += row.down;
                    b.up += row.up;
                    b.peak_down = b.peak_down.max(row.peak_down);
                    b.peak_up = b.peak_up.max(row.peak_up);
                    b.samples = b.samples.saturating_add(row.samples);
                    b.running = b.running.saturating_add(row.running);
                }
            }
            buckets
                .into_iter()
                .enumerate()
                .map(|(i, b)| {
                    let at = (from + i as u64 * bucket) * 60_000;
                    match b {
                        Some(b) => json!({"at": at, "down": b.down, "up": b.up, "peak": b.peak_down.max(b.peak_up)}),
                        None => json!({"at": at, "down": null, "up": null}),
                    }
                })
                .collect()
        };
        let uptime = |rows: &[(u64, Row)]| {
            let samples: u64 = rows.iter().map(|(_, r)| r.samples as u64).sum();
            let running: u64 = rows.iter().map(|(_, r)| r.running as u64).sum();
            (samples > 0).then(|| (running as f64 * 1000.0 / samples as f64).round() / 10.0)
        };
        let tunnels: Vec<String> = self
            .store
            .series()
            .into_iter()
            .filter(|s| s.starts_with("t:"))
            .collect();
        let mut out = json!({
            "range": range,
            "bucket_sec": bucket * 60,
            "from": from * 60_000,
            "to": to * 60_000,
            "first_at": self.store.first_minute().map(|m| m * 60_000),
        });
        match which {
            "host" => out["points"] = json!(points(&self.store.rows("host", from, to))),
            "all" => {
                let mut merged: BTreeMap<u64, Row> = BTreeMap::new();
                for series in &tunnels {
                    for (minute, row) in self.store.rows(series, from, to) {
                        let m = merged.entry(minute).or_default();
                        m.down += row.down;
                        m.up += row.up;
                        m.peak_down += row.peak_down;
                        m.peak_up += row.peak_up;
                        m.samples = m.samples.max(row.samples);
                    }
                }
                let rows: Vec<(u64, Row)> = merged.into_iter().collect();
                out["points"] = json!(points(&rows));
            }
            "tunnels" => {
                let mut map = serde_json::Map::new();
                for series in &tunnels {
                    let rows = self.store.rows(series, from, to);
                    let day = to.saturating_sub(24 * 60);
                    let last_day: Vec<(u64, Row)> = rows.iter().filter(|(m, _)| *m >= day).copied().collect();
                    map.insert(
                        series.trim_start_matches("t:").to_string(),
                        json!({"points": points(&rows), "uptime_pct": uptime(&rows), "uptime_24h_pct": uptime(&last_day)}),
                    );
                }
                out["tunnels"] = Value::Object(map);
            }
            _ => return None,
        }
        Some(out)
    }
}

/// Thirty days of made-up history for the demo, worked out from the minute itself, so nothing
/// is stored and every range has data.
pub struct DemoStore {
    pub tunnels: Vec<(&'static str, f64, bool)>,
    pub started_minute: u64,
}

impl Store for DemoStore {
    fn put(&self, _: &str, _: u64, _: &Row) -> Result<()> {
        Ok(())
    }

    fn rows(&self, series: &str, from: u64, to: u64) -> Vec<(u64, Row)> {
        let first = self.started_minute.saturating_sub(RETENTION_DAYS * MINUTES_PER_DAY - 1);
        let (rate, running) = if series == "host" {
            (16.0e6, true)
        } else {
            match self.tunnels.iter().find(|(name, _, _)| series == format!("t:{name}")) {
                Some((_, rate, running)) => (*rate, *running),
                None => return Vec::new(),
            }
        };
        let seed = series.bytes().fold(7u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64));
        (from.max(first)..to.min(self.started_minute + 1))
            .map(|minute| {
                // Busy evenings (Tehran time), quieter nights, a little noise per minute.
                let hour = ((minute + 210) % MINUTES_PER_DAY) as f64 / 60.0;
                let daily = 0.55 + 0.45 * ((hour - 21.0) / 24.0 * std::f64::consts::TAU).cos();
                let noise = ((minute.wrapping_mul(2_654_435_761) ^ seed) % 1000) as f64 / 1000.0;
                let weekly = 1.0 + 0.15 * (((minute / MINUTES_PER_DAY) % 7) as f64 / 6.0);
                let down_rate = if running { rate * daily * weekly * (0.8 + 0.4 * noise) } else { 0.0 };
                let up_rate = down_rate * 0.1;
                // The stopped demo tunnel ran until two days ago.
                let up = running || minute + 2 * MINUTES_PER_DAY < self.started_minute;
                let down_rate = if up && !running { rate.max(2.0e6) * daily * 0.5 } else { down_rate };
                (minute, Row {
                    down: (down_rate * 60.0) as u64,
                    up: (up_rate.max(down_rate * 0.1) * 60.0) as u64,
                    peak_down: (down_rate * 1.4) as f32,
                    peak_up: (down_rate * 0.14) as f32,
                    rtt: f32::NAN,
                    rtt_max: f32::NAN,
                    loss: f32::NAN,
                    sessions: 4.0,
                    cpu: (20.0 + 15.0 * daily) as f32,
                    mem: 41.0,
                    disk: 38.0,
                    samples: 30,
                    running: if up { 30 } else { 0 },
                })
            })
            .collect()
    }

    fn series(&self) -> Vec<String> {
        let mut list = vec!["host".to_string()];
        list.extend(self.tunnels.iter().map(|(name, _, _)| format!("t:{name}")));
        list
    }

    fn first_minute(&self) -> Option<u64> {
        Some(self.started_minute.saturating_sub(RETENTION_DAYS * MINUTES_PER_DAY - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::{data::Tunnel, host::Host};

    fn row(down: u64) -> Row {
        Row { down, up: down / 10, samples: 30, running: 30, rtt: 80.0, ..Row::default() }
    }

    fn snapshot(at_ms: u64, down_bps: f64, state: &'static str) -> Snapshot {
        Snapshot {
            at: at_ms,
            version: "test",
            demo: false,
            host: Host { rx_bps: Some(1000.0), tx_bps: Some(500.0), cpu_pct: Some(10.0), ..Host::default() },
            tunnels: vec![Tunnel {
                name: "game".into(),
                state,
                down_bps: Some(down_bps),
                up_bps: Some(down_bps / 10.0),
                rtt_ms: Some(80.0),
                ..Tunnel::default()
            }],
            issues: Vec::new(),
        }
    }

    #[test]
    fn rows_survive_encoding() {
        let original = Row { down: u64::MAX - 3, up: 7, peak_down: 1.5, rtt: f32::NAN, samples: 30, running: 12, ..Row::default() };
        let mut bytes = [0u8; ROW];
        original.encode(&mut bytes);
        let back = Row::decode(&bytes);
        assert_eq!(back.down, original.down);
        assert_eq!(back.running, 12);
        assert!(back.rtt.is_nan());
    }

    #[test]
    fn minutes_are_written_to_day_files_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::open(dir.path()).unwrap();
        let day = 20_000;
        store.put("t:game", day * MINUTES_PER_DAY + 5, &row(100)).unwrap();
        store.put("t:game", day * MINUTES_PER_DAY + 1439, &row(200)).unwrap();
        store.put("t:game", (day + 1) * MINUTES_PER_DAY, &row(300)).unwrap();
        let rows = store.rows("t:game", day * MINUTES_PER_DAY, (day + 2) * MINUTES_PER_DAY);
        assert_eq!(rows.iter().map(|(_, r)| r.down).collect::<Vec<_>>(), [100, 200, 300]);
        // A fresh store (a restart) reads the same from disk.
        let again = FileStore::open(dir.path()).unwrap();
        assert_eq!(again.rows("t:game", 0, u64::MAX / 2).len(), 3);
        assert_eq!(again.first_minute(), Some(day * MINUTES_PER_DAY + 5));
        assert_eq!(again.series(), ["t:game"]);
    }

    #[test]
    fn series_names_cannot_leave_the_history_directory() {
        assert_eq!(directory_of("t:../../etc"), None);
        assert_eq!(directory_of("t:"), None);
        assert_eq!(directory_of("other"), None);
        assert_eq!(directory_of("t:web-wss").as_deref(), Some("t-web-wss"));
    }

    #[test]
    fn days_past_the_retention_are_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::open(dir.path()).unwrap();
        for day in [100, 129, 131] {
            store.put("host", day * MINUTES_PER_DAY, &row(1)).unwrap();
        }
        store.prune(160);
        assert_eq!(store.days("host"), [131]);
    }

    #[test]
    fn snapshots_become_one_row_per_minute() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::new(Box::new(FileStore::open(dir.path()).unwrap()));
        let minute = 30_000_000u64;
        for i in 0..30 {
            history.record(&snapshot(minute * 60_000 + i * 2000, 1000.0, if i < 15 { "running" } else { "stopped" }));
        }
        // Nothing is written until the next minute begins.
        history.record(&snapshot((minute + 1) * 60_000, 0.0, "running"));
        let store = FileStore::open(dir.path()).unwrap();
        let rows = store.rows("t:game", minute, minute + 1);
        assert_eq!(rows.len(), 1);
        let r = rows[0].1;
        assert_eq!((r.samples, r.running), (30, 15));
        assert_eq!(r.down, 60_000); // 1000 B/s for 30 snapshots of 2 s
        assert_eq!(r.rtt, 80.0);
        let host = store.rows("host", minute, minute + 1)[0].1;
        assert_eq!(host.down, 60_000);
        assert_eq!(host.cpu, 10.0);
    }

    #[test]
    fn a_clock_set_back_only_rewrites_the_minute_it_lands_on() {
        let dir = tempfile::tempdir().unwrap();
        let history = History::new(Box::new(FileStore::open(dir.path()).unwrap()));
        let minute = 30_000_000u64;
        history.record(&snapshot(minute * 60_000, 1000.0, "running"));
        history.record(&snapshot((minute - 90) * 60_000, 1000.0, "running"));
        history.record(&snapshot((minute - 89) * 60_000, 1000.0, "running"));
        let store = FileStore::open(dir.path()).unwrap();
        assert_eq!(store.rows("t:game", minute - 100, minute + 10).len(), 2);
    }

    #[test]
    fn queries_bucket_rows_and_report_uptime() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::open(dir.path()).unwrap();
        let now = 30_000_000u64; // minute
        for m in 0..60 {
            let mut r = row(1000);
            if m >= 30 {
                r.running = 0;
            }
            store.put("t:game", now - 59 + m, &r).unwrap();
            store.put("t:web", now - 59 + m, &row(10)).unwrap();
        }
        let history = History::new(Box::new(store));
        let now_ms = now * 60_000 + 30_000;
        let all = history.query("24h", "all", now_ms, 0).unwrap();
        let points = all["points"].as_array().unwrap();
        assert_eq!(points.len(), 288);
        let total: u64 = points.iter().filter_map(|p| p["down"].as_u64()).sum();
        assert_eq!(total, 60 * 1010);
        assert!(points[0]["down"].is_null(), "no data yet at the start of the range");
        let tunnels = history.query("24h", "tunnels", now_ms, 0).unwrap();
        assert_eq!(tunnels["tunnels"]["game"]["uptime_pct"], 50.0);
        assert_eq!(tunnels["tunnels"]["web"]["uptime_pct"], 100.0);
        assert!(history.query("1y", "all", now_ms, 0).is_none());
    }

    #[test]
    fn daily_buckets_start_at_the_viewers_midnight() {
        let history = History::new(Box::new(DemoStore { tunnels: vec![("game", 1e6, true)], started_minute: 30_000_000 }));
        let tehran = history.query("30d", "all", 30_000_000 * 60_000, 210).unwrap();
        let first = tehran["points"][0]["at"].as_u64().unwrap() / 60_000;
        assert_eq!((first + 210) % MINUTES_PER_DAY, 0);
        assert_eq!(tehran["points"].as_array().unwrap().len(), 30);
    }
}
