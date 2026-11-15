//! Mirage source tests from the dashboard: which permitted spoof source addresses get through,
//! with which packet types, in each direction. The hub makes the invitation (a short-lived secret
//! that never reaches the browser); the Iran server hosts the test and the foreign server joins.
//! The rows each side sees are kept for the screen.
use crate::{
    raw_packet::RawProfile,
    spoof_session::{self, Depth, Invitation, Report},
    spoof_test::Row,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    net::Ipv4Addr,
    path::Path,
    sync::{Arc, Mutex},
};

/// Where a server keeps its test reports.
const DIR: &str = "/var/lib/eztunnel-mirage-tests";

struct Job {
    /// (toward the foreign server, row) as they arrive.
    rows: Arc<Mutex<Vec<(bool, Row)>>>,
    end: Arc<Mutex<Option<Result<Report, String>>>>,
    /// Ends the test early.
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

static JOB: Mutex<Option<Job>> = Mutex::new(None);

/// The invitation for two servers, from the dashboard's form.
pub fn invitation(form: &Value) -> Result<Invitation> {
    let ip = |key: &str| -> Result<Ipv4Addr> {
        form[key].as_str().unwrap_or("").trim().parse().with_context(|| format!("{key} must be an IPv4 address"))
    };
    let (iran, foreign) = (ip("iran_ip")?, ip("foreign_ip")?);
    ensure!(iran != foreign, "the two servers need different addresses");
    let foreign_sources = spoof_session::parse_sources(form["foreign_sources"].as_str().unwrap_or(""))?;
    // Iran → foreign is optional; "real" sends from the Iran server's own address.
    let iran_sources = match form["iran_sources"].as_str().map(str::trim).unwrap_or("") {
        "" => Vec::new(),
        "real" => vec![iran],
        text => spoof_session::parse_sources(text)?,
    };
    let profiles: Vec<RawProfile> = form["profiles"]
        .as_array()
        .context("choose at least one packet type")?
        .iter()
        .map(|p| serde_json::from_value(p.clone()).context("unknown packet type"))
        .collect::<Result<_>>()?;
    ensure!(!profiles.is_empty() && profiles.len() <= 10, "choose 1 to 10 packet types");
    let depth = match form["depth"].as_str().unwrap_or("quick") {
        "quick" => Depth::Quick,
        "extended" => Depth::Extended,
        other => bail!("unknown depth {other}"),
    };
    let port = |key: &str, default: u16| -> Result<u16> {
        match form[key].as_u64() {
            None => Ok(default),
            Some(p) => u16::try_from(p).ok().filter(|p| *p >= 1024).with_context(|| format!("{key} must be 1024 to 65535")),
        }
    };
    Invitation::new(iran, foreign, foreign_sources, iran_sources, profiles, depth, port("control_port", 47110)?, port("raw_port", 47111)?)
}

/// `{"action": "host"|"join", "invitation"}`, `{"action": "status"}`, `{"action": "stop"}`.
pub fn answer(request: &Value) -> Result<Value> {
    match request["action"].as_str() {
        Some(action @ ("host" | "join")) => {
            let invite = Invitation::decode(request["invitation"].as_str().unwrap_or(""), spoof_session::now()?)?;
            start(invite, action == "host")?;
            Ok(json!({"started": true}))
        }
        Some("status") => Ok(status()),
        Some("stop") => {
            if let Some(job) = JOB.lock().unwrap().as_mut()
                && let Some(cancel) = job.cancel.take()
            {
                let _ = cancel.send(());
            }
            Ok(json!({"stopping": true}))
        }
        _ => bail!("unknown Mirage test request"),
    }
}

fn start(invite: Invitation, host: bool) -> Result<()> {
    let mut slot = JOB.lock().unwrap();
    if let Some(job) = slot.as_ref() {
        ensure!(job.end.lock().unwrap().is_some(), "a Mirage source test is already running on this server");
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(DIR)?;
    let state = spoof_session::report_path(Path::new(DIR), &invite.session)?;
    let rows: Arc<Mutex<Vec<(bool, Row)>>> = Arc::default();
    let end: Arc<Mutex<Option<Result<Report, String>>>> = Arc::default();
    let (seen, done) = (rows.clone(), end.clone());
    let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
    // The test library reports progress through a callback that is not thread-safe, so the test
    // runs on its own thread with its own small runtime.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().context("a runtime for the test")?;
    std::thread::spawn(move || runtime.block_on(async move {
        let mut progress = |reverse: bool, row: &Row| {
            let mut list = seen.lock().unwrap();
            // A row is reported again as it completes; keep the newest per (direction, source, type).
            list.retain(|(r, old)| !(*r == reverse && old.source == row.source && old.profile == row.profile));
            list.push((reverse, row.clone()));
        };
        let work = async {
            if host {
                match tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, invite.control_port)).await {
                    Ok(listener) => spoof_session::host(listener, invite, &state, &mut progress).await,
                    Err(error) => Err(anyhow::anyhow!("listen on the control port: {error}")),
                }
            } else {
                spoof_session::join(invite, &state, &mut progress).await
            }
        };
        let result = tokio::select! {
            result = work => result.map_err(|e| format!("{e:#}")),
            _ = cancelled => Err("stopped".to_string()),
        };
        *done.lock().unwrap() = Some(result);
    }));
    *slot = Some(Job { rows, end, cancel: Some(cancel) });
    Ok(())
}

fn row_json(reverse: bool, row: &Row) -> Value {
    json!({
        "toward": if reverse { "foreign" } else { "iran" },
        "source": row.source, "profile": row.profile, "sent": row.sent, "received": row.received,
        "loss": row.loss_percent, "reply_received": row.raw_reply_received, "rtt_ms": row.rtt_median_ms,
        "rtt_p95_ms": row.rtt_p95_ms, "stage": row.stage, "error": row.error,
    })
}

fn status() -> Value {
    let slot = JOB.lock().unwrap();
    let Some(job) = slot.as_ref() else {
        return json!({"state": "idle"});
    };
    let rows: Vec<Value> = job.rows.lock().unwrap().iter().map(|(r, row)| row_json(*r, row)).collect();
    match job.end.lock().unwrap().as_ref() {
        None => json!({"state": "running", "rows": rows}),
        Some(Ok(report)) => {
            let all: Vec<Value> = report.iran_bound.iter().map(|r| row_json(false, r)).chain(report.foreign_bound.iter().map(|r| row_json(true, r))).collect();
            json!({"state": "finished", "rows": all})
        }
        Some(Err(error)) => json!({"state": "failed", "error": error, "rows": rows}),
    }
}

/// Sample progress for the demo.
pub fn demo_status(started: u64, now: u64) -> Value {
    let sources = ["198.51.100.10", "198.51.100.11", "203.0.113.50"];
    let profiles = ["udp", "icmp", "tcp"];
    let total = sources.len() * profiles.len();
    let done = (((now.saturating_sub(started)) / 3) as usize).min(total);
    let rows: Vec<Value> = (0..done)
        .map(|i| {
            let (source, profile) = (sources[i / profiles.len()], profiles[i % profiles.len()]);
            let received = if profile == "tcp" { 0 } else if source.starts_with("203") { 3 } else { 5 };
            json!({"toward": "iran", "source": source, "profile": profile, "sent": 5, "received": received,
                   "loss": (5 - received) as f64 * 20.0, "reply_received": received, "rtt_ms": (received > 0).then_some(84.0 + i as f64),
                   "rtt_p95_ms": (received > 0).then_some(91.0 + i as f64), "stage": "complete", "error": null})
        })
        .collect();
    json!({"state": if done >= total { "finished" } else { "running" }, "rows": rows})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_makes_an_invitation_the_other_server_can_read() {
        let form = json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "foreign_sources": "198.51.100.1, 198.51.100.2",
                          "iran_sources": "real", "profiles": ["udp", "icmp"], "depth": "quick"});
        let invite = invitation(&form).unwrap();
        assert_eq!(invite.foreign_sources.len(), 2);
        assert_eq!(invite.iran_sources, vec!["203.0.113.10".parse::<Ipv4Addr>().unwrap()]);
        let text = invite.encode().unwrap();
        let back = Invitation::decode(&text, spoof_session::now().unwrap()).unwrap();
        assert_eq!(back.session, invite.session);
        for bad in [
            json!({"iran_ip": "x", "foreign_ip": "198.51.100.20", "foreign_sources": "198.51.100.1", "profiles": ["udp"]}),
            json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "foreign_sources": "", "profiles": ["udp"]}),
            json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "foreign_sources": "10.0.0.0/8", "profiles": ["udp"]}),
            json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "foreign_sources": "198.51.100.1", "profiles": []}),
            json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "foreign_sources": "198.51.100.1", "profiles": ["udp"], "control_port": 80}),
        ] {
            assert!(invitation(&bad).is_err(), "{bad}");
        }
        assert_eq!(answer(&json!({"action": "status"})).unwrap()["state"], "idle");
        assert!(answer(&json!({"action": "host", "invitation": "nonsense"})).is_err());
        assert_eq!(demo_status(0, 1000)["state"], "finished");
    }
}
