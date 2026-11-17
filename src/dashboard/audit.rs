//! The audit log: one JSON line per sign-in attempt and action, appended to a private file. The
//! dashboard shows it as "Dashboard activity", newest first.
use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Events a request may ask for.
pub const MAX_EVENTS: usize = 1000;
/// How much of the end of the file is read for the newest events (lines are about 120 bytes).
const TAIL_BYTES: u64 = 512 * 1024;
/// Events the in-memory log (demo, tests) keeps.
const MEMORY_EVENTS: usize = 500;
/// The file is moved to `<name>.1` (replacing the one before) when it grows past this, so the log
/// on disk stays under twice this size whatever is sent to the dashboard.
const MAX_FILE: u64 = 8 * 1024 * 1024;
/// A repeated event (the same kind from the same address) is written at most once per this many
/// seconds; the ones in between are counted into the next line.
const REPEAT_SEC: u64 = 60;
/// Repeated-event keys remembered at once.
const MAX_REPEAT_KEYS: usize = 1024;

pub struct Audit {
    file: Option<(Mutex<File>, PathBuf)>,
    /// Without a file: the events of this run, oldest first.
    memory: Mutex<VecDeque<Value>>,
    /// `record_repeated`: (address, event) -> (last written, left out since).
    repeats: Mutex<HashMap<(Option<IpAddr>, String), (u64, u64)>>,
}

impl Audit {
    pub fn open(path: &Path) -> Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        Ok(Self {
            file: Some((Mutex::new(file), path.to_path_buf())),
            memory: Mutex::default(),
            repeats: Mutex::default(),
        })
    }

    /// No file: the demo and tests keep the events of this run in memory only.
    pub fn disabled() -> Self {
        Self {
            file: None,
            memory: Mutex::default(),
            repeats: Mutex::default(),
        }
    }

    pub fn record(&self, ip: Option<IpAddr>, event: &str, detail: &str) {
        self.record_at(super::now(), ip, event, detail);
    }

    /// For events that can arrive without end (sign-ins refused during a lockout): one line per
    /// address and event per `REPEAT_SEC`, saying how many were left out since the last one.
    pub fn record_repeated(&self, ip: Option<IpAddr>, event: &str, detail: &str) {
        self.record_repeated_at(super::now(), ip, event, detail);
    }

    fn record_repeated_at(&self, now: u64, ip: Option<IpAddr>, event: &str, detail: &str) {
        let left_out = {
            let mut repeats = self.repeats.lock().unwrap_or_else(|p| p.into_inner());
            if repeats.len() >= MAX_REPEAT_KEYS {
                repeats.retain(|_, (last, _)| now.saturating_sub(*last) < REPEAT_SEC);
            }
            let key = (ip, event.to_string());
            let full = repeats.len() >= MAX_REPEAT_KEYS;
            match repeats.get_mut(&key) {
                Some((last, skipped)) if now.saturating_sub(*last) < REPEAT_SEC => {
                    *skipped += 1;
                    return;
                }
                Some(entry) => std::mem::replace(entry, (now, 0)).1,
                None if full => return,
                None => {
                    repeats.insert(key, (now, 0));
                    0
                }
            }
        };
        if left_out == 0 {
            self.record_at(now, ip, event, detail);
        } else {
            self.record_at(now, ip, event, &format!("{detail} ({left_out} more like it before this)"));
        }
    }

    fn record_at(&self, time: u64, ip: Option<IpAddr>, event: &str, detail: &str) {
        let line = serde_json::json!({
            "time": time,
            "ip": ip.map(|ip| ip.to_string()),
            "event": event,
            "detail": detail,
        });
        match &self.file {
            Some((file, path)) => {
                if let Ok(mut file) = file.lock() {
                    // A full disk must not stop the dashboard; the event is then only lost.
                    let _ = writeln!(file, "{line}");
                    if file.metadata().is_ok_and(|m| m.len() > MAX_FILE) {
                        let _ = std::fs::rename(path, previous(path));
                        if let Ok(fresh) = Self::open(path) {
                            if let Some((fresh, _)) = fresh.file {
                                *file = fresh.into_inner().unwrap_or_else(|p| p.into_inner());
                            }
                        }
                    }
                }
            }
            None => {
                let mut memory = self.memory.lock().unwrap_or_else(|p| p.into_inner());
                if memory.len() == MEMORY_EVENTS {
                    memory.pop_front();
                }
                memory.push_back(line);
            }
        }
    }

    /// Sample events for the demo, as if the dashboard had been in use for a while.
    pub fn with_samples(self) -> Self {
        let now = super::now();
        let samples: [(u64, Option<&str>, &str, &str); 7] = [
            (5 * 86_400, None, "start", "listening on 203.0.113.10:38471"),
            (5 * 86_400 - 60, Some("198.51.100.23"), "login", "signed in"),
            (2 * 86_400, Some("198.51.100.23"), "action", "restart cdn-xhttps"),
            (86_400 + 7200, Some("192.0.2.77"), "login_failed", "wrong password"),
            (86_400 + 7100, Some("192.0.2.77"), "login_failed", "wrong password"),
            (86_400, None, "certificate", "Let's Encrypt certificate in use; next renewal (sample)"),
            (3600, Some("198.51.100.23"), "login", "signed in"),
        ];
        for (ago, ip, event, detail) in samples {
            self.record_at(now - ago, ip.and_then(|ip| ip.parse().ok()), event, detail);
        }
        self
    }

    /// The newest `limit` events, newest first. Lines that are not JSON are skipped.
    pub fn recent(&self, limit: usize) -> Vec<Value> {
        let limit = limit.clamp(1, MAX_EVENTS);
        match &self.file {
            Some((_, path)) => [read_tail(&previous(path)), read_tail(path)]
                .concat()
                .lines()
                .rev()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .take(limit)
                .collect(),
            None => self
                .memory
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .rev()
                .take(limit)
                .cloned()
                .collect(),
        }
    }
}

/// Where the file goes when it is full.
fn previous(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

/// The last part of the file, starting at a whole line.
fn read_tail(path: &Path) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let length = file.metadata().map_or(0, |m| m.len());
    let start = length.saturating_sub(TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    let _ = file.take(TAIL_BYTES).read_to_end(&mut bytes);
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if start > 0 {
        // The first line was probably cut in the middle.
        text = text.split_once('\n').map_or(String::new(), |(_, rest)| rest.to_string());
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_appended_as_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let audit = Audit::open(&path).unwrap();
        audit.record(Some("198.51.100.7".parse().unwrap()), "login_failed", "wrong password");
        audit.record(None, "start", "x");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> =
            text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["ip"], "198.51.100.7");
        assert_eq!(lines[0]["event"], "login_failed");
        assert!(lines[1]["ip"].is_null());
    }

    #[test]
    fn recent_events_come_newest_first_and_skip_broken_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let audit = Audit::open(&path).unwrap();
        for n in 0..5 {
            audit.record(None, "action", &format!("stop t{n}"));
        }
        // A line cut by a crash, then more events.
        std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"{\"time\":1,\"ev\n").unwrap();
        audit.record(None, "action", "stop last");
        let events = audit.recent(3);
        let details: Vec<&str> = events.iter().map(|e| e["detail"].as_str().unwrap()).collect();
        assert_eq!(details, ["stop last", "stop t4", "stop t3"]);
        assert_eq!(audit.recent(0).len(), 1, "at least one");
        assert_eq!(audit.recent(50_000).len(), 6);
    }

    #[test]
    fn a_large_log_is_read_from_its_end_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let audit = Audit::open(&path).unwrap();
        let filler = "x".repeat(200);
        for n in 0..4000 {
            audit.record(None, "action", &format!("{n} {filler}"));
        }
        assert!(std::fs::metadata(&path).unwrap().len() > TAIL_BYTES);
        let events = audit.recent(MAX_EVENTS);
        assert!(!events.is_empty() && events.len() <= MAX_EVENTS);
        assert!(events[0]["detail"].as_str().unwrap().starts_with("3999 "));
        // Every event read is whole: the cut first line was dropped.
        assert!(events.iter().all(|e| e["event"] == "action"));
    }

    #[test]
    fn repeated_refusals_are_coalesced_and_the_file_is_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let audit = Audit::open(&path).unwrap();
        let ip = Some("198.51.100.9".parse().unwrap());
        for second in 0..1000 {
            audit.record_repeated_at(10_000 + second / 10, ip, "login_refused", "locked");
        }
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        // 100 seconds of refusals: one line per minute, not a thousand.
        assert_eq!(lines, 2);
        assert!(audit.recent(5)[0]["detail"].as_str().unwrap().contains("more like it"));
        // However much is written, the log stays bounded: it moves aside past MAX_FILE.
        let filler = "x".repeat(4000);
        for n in 0..((2 * MAX_FILE) / 4000 + 10) {
            audit.record(None, "action", &format!("{n} {filler}"));
        }
        let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
        assert!(size(&path) <= MAX_FILE + 8192);
        assert!(size(&previous(&path)) <= MAX_FILE + 8192);
        assert!(!audit.recent(10).is_empty());
    }

    #[test]
    fn the_memory_log_keeps_the_newest_events() {
        let audit = Audit::disabled().with_samples();
        let first = audit.recent(1);
        assert_eq!(first[0]["event"], "login");
        for n in 0..MEMORY_EVENTS {
            audit.record(None, "action", &n.to_string());
        }
        let all = audit.recent(MAX_EVENTS);
        assert_eq!(all.len(), MEMORY_EVENTS);
        assert_eq!(all[0]["detail"], (MEMORY_EVENTS - 1).to_string());
    }
}
