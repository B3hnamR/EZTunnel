//! Keeps the last log lines of the test tunnels in memory, so the live view can show them. The
//! manager has no log output of its own; this installs one that writes here (once per process).
use std::{
    collections::VecDeque,
    io::Write,
    sync::{Mutex, OnceLock},
};

const KEEP: usize = 400;

fn lines() -> &'static Mutex<VecDeque<String>> {
    static LINES: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(VecDeque::with_capacity(KEEP)))
}

/// Adds one line (also used for the checker's own events).
pub fn push(line: impl Into<String>) {
    let mut lines = lines().lock().unwrap_or_else(|e| e.into_inner());
    if lines.len() == KEEP {
        lines.pop_front();
    }
    lines.push_back(line.into());
}

/// The newest `count` lines, oldest first.
pub fn tail(count: usize) -> Vec<String> {
    let lines = lines().lock().unwrap_or_else(|e| e.into_inner());
    lines
        .iter()
        .skip(lines.len().saturating_sub(count))
        .cloned()
        .collect()
}

struct Writer;

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for line in String::from_utf8_lossy(buf).lines() {
            let line = line.trim_end();
            if !line.is_empty() {
                push(line.to_string());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Sends the tunnels' log lines (info and above) here. Does nothing if the process already has a
/// log output, for example when `eztunnel check` runs with its own.
pub fn capture() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(|| Writer)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_the_newest_lines() {
        for index in 0..(KEEP + 10) {
            push(format!("logbuf-test {index}"));
        }
        let newest = tail(2);
        assert_eq!(newest.len(), 2);
        assert!(newest[1].ends_with(&format!("{}", KEEP + 9)));
    }
}
