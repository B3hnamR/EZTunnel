//! The audit log: one JSON line per sign-in attempt and action, appended to a private file.
use anyhow::{Context, Result};
use std::{fs::File, io::Write, net::IpAddr, path::Path, sync::Mutex};

pub struct Audit {
    file: Option<Mutex<File>>,
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
            file: Some(Mutex::new(file)),
        })
    }

    /// The demo keeps no log.
    pub fn disabled() -> Self {
        Self { file: None }
    }

    pub fn record(&self, ip: Option<IpAddr>, event: &str, detail: &str) {
        let Some(file) = &self.file else { return };
        let line = serde_json::json!({
            "time": super::now(),
            "ip": ip.map(|ip| ip.to_string()),
            "event": event,
            "detail": detail,
        });
        if let Ok(mut file) = file.lock() {
            // A full disk must not stop the dashboard; the event is then only lost.
            let _ = writeln!(file, "{line}");
        }
    }
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
}
