//! The transport check (`eztunnel check`) run from the dashboard: the hub makes the check code,
//! one server starts its part and the other joins, each in the background of its own process.
//! Both answer `status` with the live view, and the finished report once it is done.
use crate::checker::{
    self, Options, Preset, Priority, Report, Side, Verdict,
    code::{self, CheckCode},
    control::Command,
    run::{self, View},
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};

/// This server's part of a check, while it runs and after it ends.
struct Job {
    view: watch::Receiver<View>,
    commands: mpsc::UnboundedSender<Command>,
    priority: Priority,
    /// Set when the check ended: the report, or why it failed.
    end: Arc<Mutex<Option<Result<Report, String>>>>,
}

static JOB: Mutex<Option<Job>> = Mutex::new(None);

/// The check code for two servers, from the dashboard's form.
pub fn make_code(form: &Value) -> Result<CheckCode> {
    let ip = |key: &str| -> Result<IpAddr> {
        form[key].as_str().unwrap_or("").trim().parse().with_context(|| format!("{key} must be an IP address"))
    };
    let preset = match form["preset"].as_str().unwrap_or("quick") {
        "quick" => Preset::Quick,
        "standard" => Preset::Standard,
        "thorough" => Preset::Thorough,
        other => bail!("unknown preset {other}"),
    };
    let mut options = Options::preset(preset);
    if let Some(custom) = form.get("custom").filter(|v| !v.is_null()) {
        options = customized(&options, custom)?;
    }
    options.dialers = match form["directions"].as_str().unwrap_or("both") {
        "both" => vec![Side::Foreign, Side::Iran],
        "foreign" => vec![Side::Foreign],
        "iran" => vec![Side::Iran],
        other => bail!("unknown directions {other}"),
    };
    options.priority = match form["priority"].as_str().unwrap_or("stability") {
        "stability" => Priority::Stability,
        "speed" => Priority::Speed,
        "hiding" => Priority::Hiding,
        "lossy" => Priority::Lossy,
        other => bail!("unknown priority {other}"),
    };
    if let Some(port) = form["control_port"].as_u64() {
        options.control_port = u16::try_from(port).ok().filter(|p| *p > 0).context("the control port must be 1 to 65535")?;
    }
    options.validate()?;
    let (iran, foreign) = (ip("iran_ip")?, ip("foreign_ip")?);
    ensure!(iran != foreign, "the two servers need different addresses");
    CheckCode::new(Side::Iran, iran, foreign, options)
}

/// The options the Customize panel may change, as the terminal checker offers them: transports,
/// raw TUN packet types, measurements, extra variants, ports and the slow threshold. Directions,
/// the ranking and the control port stay with the rest of the form.
const CUSTOM_KEYS: [&str; 19] = [
    "transports", "tun_profiles", "pings", "download", "upload", "parallel", "speed_sec", "hold_sec", "udp", "mtu",
    "repeat_failed", "browser_tls", "tls_fragment", "also_congestion", "also_pacer", "also_fragment", "tls_port",
    "port", "slow_mbps",
];

/// The preset's options with the Customize panel's choices laid over them.
fn customized(base: &Options, custom: &Value) -> Result<Options> {
    let fields = custom.as_object().context("custom options are an object")?;
    let mut merged = serde_json::to_value(base)?;
    for (key, value) in fields {
        ensure!(CUSTOM_KEYS.contains(&key.as_str()), "{key} cannot be changed here");
        merged[key] = value.clone();
    }
    serde_json::from_value(merged).context("an option has a value it cannot take")
}

/// Answers `{"action": "start"|"join", "code"}`, `{"action": "status"}` and `{"action": "stop"}`.
/// Must run where a Tokio runtime is reachable (the dashboard's blocking threads are).
pub fn answer(request: &Value) -> Result<Value> {
    match request["action"].as_str() {
        Some("start") | Some("join") => {
            let code = code::decode(request["code"].as_str().unwrap_or("")).context("a bad check code")?;
            let me = if request["action"] == "start" { code.starter } else { code.starter.other() };
            start(code, me)?;
            Ok(json!({"started": true}))
        }
        Some("status") => Ok(status()),
        Some("stop") => {
            if let Some(job) = JOB.lock().unwrap().as_ref() {
                let _ = job.commands.send(Command::Stop);
            }
            Ok(json!({"stopping": true}))
        }
        _ => bail!("unknown check request"),
    }
}

fn start(code: CheckCode, me: Side) -> Result<()> {
    let mut slot = JOB.lock().unwrap();
    if let Some(job) = slot.as_ref() {
        ensure!(job.end.lock().unwrap().is_some(), "a transport check is already running on this server");
    }
    let priority = code.options.priority;
    let runtime = tokio::runtime::Handle::try_current().context("no runtime for the check")?;
    let _entered = runtime.enter();
    let handle = run::spawn(code, me);
    let end = Arc::new(Mutex::new(None));
    let done = end.clone();
    runtime.spawn(async move {
        let result = match handle.task.await {
            Ok(Ok(report)) => Ok(report),
            Ok(Err(error)) => Err(format!("{error:#}")),
            Err(error) => Err(format!("the check stopped: {error}")),
        };
        *done.lock().unwrap() = Some(result);
    });
    *slot = Some(Job { view: handle.view, commands: handle.commands, priority, end });
    Ok(())
}

/// The ids of the usable cases, best first.
pub fn ranked(rows: &[checker::CaseResult], priority: Priority) -> Vec<u32> {
    checker::rank(rows, priority).iter().map(|r| r.spec.id).collect()
}

fn status() -> Value {
    let slot = JOB.lock().unwrap();
    let Some(job) = slot.as_ref() else {
        return json!({"state": "idle"});
    };
    let end = job.end.lock().unwrap();
    match end.as_ref() {
        None => {
            let view = job.view.borrow().clone();
            json!({"state": "running", "view": view, "best": ranked(&view.rows, job.priority)})
        }
        Some(Ok(report)) => json!({"state": "finished", "report": report, "best": ranked(&report.cases, job.priority)}),
        Some(Err(error)) => json!({"state": "failed", "error": error, "view": job.view.borrow().clone()}),
    }
}

/// Sample progress for the demo: the cases of a Quick check, finishing over about a minute.
pub fn demo_status(started: u64, now: u64) -> Value {
    let mut options = Options::preset(Preset::Quick);
    options.dialers = vec![Side::Foreign, Side::Iran];
    let mut rows: Vec<checker::CaseResult> = options.cases().into_iter().map(checker::CaseResult::new).collect();
    let elapsed = now.saturating_sub(started);
    let done = (elapsed / 4) as usize;
    let verdicts = [Verdict::Works, Verdict::Reachable, Verdict::NoHandshake, Verdict::Works, Verdict::BlockedAfterHandshake];
    for (index, row) in rows.iter_mut().enumerate().take(done) {
        row.runs = 1;
        let verdict = verdicts[index % verdicts.len()];
        row.verdict = Some(verdict);
        if verdict.usable() {
            row.handshake_ms = Some(180 + 23 * index as u64);
            row.rtt_ms = Some(84.0 + index as f64);
        } else {
            row.failed_runs = 1;
            row.note = Some("no answer within 15 s".into());
        }
    }
    let finished = done >= rows.len();
    let view = View {
        iran_ip: "203.0.113.10".into(),
        foreign_ip: "198.51.100.20".into(),
        current: (!finished).then(|| rows[done.min(rows.len() - 1)].spec.id),
        step: if finished { "finished".into() } else { format!("checking case {} of {}", done + 1, rows.len()) },
        connected: true,
        elapsed_sec: elapsed,
        remaining_sec: (rows.len().saturating_sub(done) * 4) as u64,
        finished,
        rows,
        ..View::default()
    };
    let best = ranked(&view.rows, Priority::Stability);
    if finished {
        json!({"state": "finished", "report": {"version": env!("CARGO_PKG_VERSION"), "started": started, "seconds": elapsed,
               "iran_ip": view.iran_ip, "foreign_ip": view.foreign_ip, "cases": view.rows, "stopped": null}, "best": best})
    } else {
        json!({"state": "running", "view": view, "best": best})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_makes_a_code_the_other_server_can_read() {
        let form = json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "preset": "standard", "directions": "foreign", "priority": "speed"});
        let made = make_code(&form).unwrap();
        assert_eq!(made.starter, Side::Iran);
        assert_eq!(made.options.dialers, vec![Side::Foreign]);
        assert_eq!(made.options.priority, Priority::Speed);
        let text = code::encode(&made).unwrap();
        assert_eq!(code::decode(&text).unwrap(), made);
        for bad in [
            json!({"iran_ip": "nope", "foreign_ip": "198.51.100.20"}),
            json!({"iran_ip": "203.0.113.10", "foreign_ip": "203.0.113.10"}),
            json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "preset": "forever"}),
            json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "control_port": 0}),
        ] {
            assert!(make_code(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn customize_lays_its_choices_over_the_preset_and_nothing_else() {
        use crate::config::Transport;
        let base = json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "preset": "quick"});
        let mut form = base.clone();
        form["custom"] = json!({"transports": ["fec-raw-gaming", "fec-udp", "tun"], "tun_profiles": ["icmp", "dns"],
            "also_pacer": true, "download": true, "speed_sec": 7, "tls_port": 8443, "slow_mbps": 20});
        let options = make_code(&form).unwrap().options;
        assert_eq!(options.transports, vec![Transport::FecRawGaming, Transport::FecUdp, Transport::Tun]);
        assert_eq!(options.tun_profiles, vec![crate::raw_packet::RawProfile::Icmp, crate::raw_packet::RawProfile::Dns]);
        assert!(options.also_pacer && options.download && !options.upload);
        assert_eq!((options.speed_sec, options.tls_port, options.slow_mbps), (7, 8443, 20));
        // The rest of the Quick preset stays: five pings, no hold.
        assert_eq!((options.pings, options.hold_sec), (5, 0));
        // Pacer cases for both FEC transports; one TUN case per packet type.
        let cases = options.cases();
        assert!(cases.iter().any(|c| c.transport == Transport::FecRawGaming && c.variant == crate::checker::Variant::Pacer));
        assert_eq!(cases.iter().filter(|c| c.transport == Transport::Tun).count(), 2);
        for bad in [
            json!({"control_port": 9}),
            json!({"dialers": ["iran"]}),
            json!({"transports": ["carrier-pigeon"]}),
            json!({"transports": []}),
            json!({"speed_sec": 0}),
            json!("everything"),
        ] {
            let mut form = base.clone();
            form["custom"] = bad.clone();
            assert!(make_code(&form).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_demo_progresses_to_a_ranked_report() {
        let running = demo_status(1000, 1004);
        assert_eq!(running["state"], "running");
        let done = demo_status(1000, 1000 + 3600);
        assert_eq!(done["state"], "finished");
        assert!(!done["best"].as_array().unwrap().is_empty());
        assert!(answer(&json!({"action": "status"})).unwrap()["state"].is_string());
        assert!(answer(&json!({"action": "explode"})).is_err());
    }
}
