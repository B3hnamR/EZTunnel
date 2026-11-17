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
    mode: checker::Mode,
    /// Set when the check ended: the report, or why it failed.
    end: Arc<Mutex<Option<Result<Report, String>>>>,
    /// Which check this is (`job_id` of its code): a stop for another check leaves it running.
    id: String,
}

/// A check's id: from its code, so the hub that made the code can name the check it means.
pub fn job_id(code: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(code.trim().as_bytes())[..8].iter().map(|b| format!("{b:02x}")).collect()
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
    // Find: every transport with its defaults. Tune: the chosen transports with every option.
    let mut options = match form["mode"].as_str().unwrap_or("find") {
        "find" => Options::preset(preset),
        "tune" => {
            let transports: Vec<crate::config::Transport> =
                serde_json::from_value(form["tune_transports"].clone()).context("tune_transports must list transports")?;
            ensure!(!transports.is_empty(), "choose at least one transport to tune");
            Options::tune(preset, transports)
        }
        other => bail!("unknown check mode {other}"),
    };
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
    let ipv6_only = match form["family"].as_str() {
        Some("ipv6") => true,
        Some("ipv4" | "both") | None => false,
        Some(other) => bail!("unknown address family {other}"),
    };
    if ipv6_only {
        let (iran, foreign) = (ip("iran_ip6")?, ip("foreign_ip6")?);
        options.ipv6 = true;
        options.ipv6_only = true;
        options.validate()?;
        return CheckCode::new(Side::Iran, iran, foreign, options)?.with_ipv6(iran, foreign);
    }
    options.validate()?;
    let (iran, foreign) = (ip("iran_ip")?, ip("foreign_ip")?);
    ensure!(iran != foreign, "the two servers need different addresses");
    if matches!(form["family"].as_str(), Some("ipv4" | "both")) {
        ensure!(iran.is_ipv4() && foreign.is_ipv4(), "give the IPv4 addresses of both servers");
    }
    let code = CheckCode::new(Side::Iran, iran, foreign, options)?;
    if form["family"] == "ipv4" {
        return Ok(code);
    }
    // Both IPv6 addresses given: every case also runs over IPv6.
    let text = |key: &str| form[key].as_str().map(str::trim).filter(|t| !t.is_empty());
    match (text("iran_ip6"), text("foreign_ip6")) {
        (Some(_), Some(_)) => code.with_ipv6(ip("iran_ip6")?, ip("foreign_ip6")?),
        (None, None) if form["family"] != "both" => Ok(code),
        _ if form["family"] == "both" => bail!("give the IPv6 addresses of both servers"),
        _ => bail!("give the IPv6 addresses of both servers, or of neither"),
    }
}

/// The options the Customize panel may change, as the terminal checker offers them: transports,
/// raw TUN packet types, measurements, extra variants, ports and the slow threshold. Directions,
/// the ranking and the control port stay with the rest of the form.
const CUSTOM_KEYS: [&str; 22] = [
    "transports", "tun_profiles", "pings", "download", "upload", "parallel", "speed_sec", "hold_sec", "udp", "mtu",
    "repeat_failed", "browser_tls", "tls_fragment", "also_congestion", "also_pacer", "also_fragment",
    "parallax_packet", "also_game", "rounds", "tls_port", "port", "slow_mbps",
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
            let text = request["code"].as_str().unwrap_or("");
            let code = code::decode(text).context("a bad check code")?;
            let me = if request["action"] == "start" { code.starter } else { code.starter.other() };
            start(code, me, job_id(text))?;
            Ok(json!({"started": true}))
        }
        Some("status") => Ok(status()),
        Some("stop") => {
            if let Some(job) = JOB.lock().unwrap().as_ref() {
                // A stop that names a check stops only that one.
                if request["id"].as_str().is_some_and(|id| id != job.id) {
                    return Ok(json!({"stopping": false, "reason": "another check is running here"}));
                }
                let _ = job.commands.send(Command::Stop);
            }
            Ok(json!({"stopping": true}))
        }
        _ => bail!("unknown check request"),
    }
}

fn start(code: CheckCode, me: Side, id: String) -> Result<()> {
    let mut slot = JOB.lock().unwrap();
    if let Some(job) = slot.as_ref() {
        ensure!(job.end.lock().unwrap().is_some(), "a transport check is already running on this server");
    }
    let priority = code.options.priority;
    let mode = code.options.mode;
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
    *slot = Some(Job { view: handle.view, commands: handle.commands, priority, mode, end, id });
    Ok(())
}

/// The ids of the usable cases, best first.
pub fn ranked(rows: &[checker::CaseResult], priority: Priority) -> Vec<u32> {
    checker::rank(rows, priority).iter().map(|r| r.spec.id).collect()
}

/// What the results show besides the rows: the best cases, and for a tune check the options of
/// each transport best first; for a find check the transports "Tune the best" would take.
pub fn summary(rows: &[checker::CaseResult], priority: Priority, mode: checker::Mode) -> Value {
    json!({
        "mode": mode,
        "best": ranked(rows, priority),
        "paths": checker::path_summary(rows),
        "tune": (mode == checker::Mode::Tune).then(|| checker::tune_summary(rows, priority)),
        "tune_best": (mode == checker::Mode::Find)
            .then(|| checker::best_transports(rows, priority, checker::TUNE_BEST)),
    })
}

fn status() -> Value {
    let slot = JOB.lock().unwrap();
    let Some(job) = slot.as_ref() else {
        return json!({"state": "idle"});
    };
    let end = job.end.lock().unwrap();
    let mut answer = match end.as_ref() {
        None => {
            let view = job.view.borrow().clone();
            let mut answer = summary(&view.rows, job.priority, job.mode);
            answer["state"] = json!("running");
            answer["view"] = json!(view);
            answer
        }
        Some(Ok(report)) => {
            let mut answer = summary(&report.cases, job.priority, job.mode);
            answer["state"] = json!("finished");
            answer["report"] = json!(report);
            answer
        }
        Some(Err(error)) => json!({"state": "failed", "error": error, "view": job.view.borrow().clone()}),
    };
    if answer["state"] == "failed" {
        answer["mode"] = json!(job.mode);
    }
    answer
}

/// Sample progress for the demo: the cases of the check that was started (a Quick find check
/// when none was), each case taking 2 seconds, with made-up but steady measurements.
pub fn demo_status(chosen: Option<&Options>, started: u64, now: u64) -> Value {
    let options = chosen.cloned().unwrap_or_else(|| {
        let mut options = Options::preset(Preset::Quick);
        options.dialers = vec![Side::Foreign, Side::Iran];
        options
    });
    let mut rows: Vec<checker::CaseResult> = options.cases().into_iter().map(checker::CaseResult::new).collect();
    let elapsed = now.saturating_sub(started);
    let done = (elapsed / 2) as usize;
    let verdicts = [Verdict::Works, Verdict::Reachable, Verdict::NoHandshake, Verdict::Works, Verdict::BlockedAfterHandshake];
    for (index, row) in rows.iter_mut().enumerate().take(done) {
        row.runs = 1;
        // A tune check shows which options work; a find check mixes in blocked transports.
        let verdict = if options.mode == checker::Mode::Tune {
            if row.spec.variant == checker::Variant::TlsFragment { Verdict::NoHandshake } else { Verdict::Works }
        } else {
            verdicts[index % verdicts.len()]
        };
        row.verdict = Some(verdict);
        if verdict.usable() {
            let base = 30.0 + f64::from((row.spec.transport as u32 * 7 + row.spec.variant as u32 * 11) % 40);
            let wobble = f64::from(row.spec.round) * 3.0 - 1.5;
            row.handshake_ms = Some(180 + 23 * (index % 9) as u64);
            row.rtt_ms = Some(84.0 + (index % 7) as f64);
            if options.download {
                row.download = Some(checker::Transfer { mbps: base + wobble, bytes: 1 << 20, error: None });
            }
            if options.upload {
                row.upload = Some(checker::Transfer { mbps: base * 0.8 - wobble, bytes: 1 << 20, error: None });
            }
            if options.udp {
                row.udp = Some(checker::UdpStats { sent: 300, answered: 300, median_ms: Some(86.0), p95_ms: Some(120.0), ..Default::default() });
            }
            if verdict == Verdict::Works && options.mode == checker::Mode::Find && options.pings > 0 && !options.download {
                row.verdict = Some(Verdict::Reachable);
            }
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
        remaining_sec: (rows.len().saturating_sub(done) * 2) as u64,
        finished,
        rows,
        ..View::default()
    };
    let mut answer = summary(&view.rows, options.priority, options.mode);
    if finished {
        answer["state"] = json!("finished");
        answer["report"] = json!({"version": env!("CARGO_PKG_VERSION"), "started": started, "seconds": elapsed,
            "iran_ip": view.iran_ip, "foreign_ip": view.foreign_ip, "options": options, "cases": view.rows, "stopped": null});
    } else {
        answer["state"] = json!("running");
        answer["view"] = json!(view);
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With the IPv6 addresses of both servers, every case (raw ones aside) also runs over IPv6,
    /// and the summary says which family and direction works.
    #[test]
    fn ipv6_addresses_add_ipv6_cases_and_a_path_summary() {
        use crate::config::Transport;
        let mut form = json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "preset": "quick",
            "iran_ip6": "2001:db8::10", "foreign_ip6": "2001:db8::20"});
        let code = make_code(&form).unwrap();
        assert!(code.options.ipv6);
        let cases = code.options.cases();
        let wss: Vec<_> = cases.iter().filter(|c| c.transport == Transport::Wss).collect();
        assert_eq!(wss.iter().filter(|c| c.ipv6).count(), wss.len() / 2, "each case once per family");
        assert!(!cases.iter().any(|c| c.ipv6 && crate::manager::plan::is_raw(c.transport)), "raw stays IPv4");
        let spec = **wss.iter().find(|c| c.ipv6).unwrap();
        assert_eq!(code.pair_for(&spec), Some(("2001:db8::10".parse().unwrap(), "2001:db8::20".parse().unwrap())));
        assert!(spec.transport_name().ends_with("over IPv6"));
        // The code keeps them on the way to the other server.
        let back = checker::code::decode(&checker::code::encode(&code).unwrap()).unwrap();
        assert_eq!((back.iran_ip6, back.foreign_ip6), (code.iran_ip6, code.foreign_ip6));
        // One of the two is not enough.
        form["foreign_ip6"] = json!("");
        assert!(make_code(&form).is_err());
        // The path summary: IPv4 direct blocked, IPv6 direct and IPv4 reverse working.
        let result = |dialer, ipv6, verdict| checker::CaseResult {
            verdict: Some(verdict),
            ..checker::CaseResult::new(checker::CaseSpec { dialer: Some(dialer), ipv6, ..spec })
        };
        let rows = vec![
            result(Side::Iran, false, Verdict::NoHandshake),
            result(Side::Iran, true, Verdict::Works),
            result(Side::Foreign, false, Verdict::Works),
        ];
        let lines: Vec<String> = checker::path_summary(&rows).iter().map(checker::path_line).collect();
        assert_eq!(lines, ["IPv4 direct: blocked", "IPv4 reverse: works", "IPv6 direct: works"]);
    }

    #[test]
    fn explicit_ipv4_and_comparison_modes_share_the_ipv4_control_pair() {
        let mut form = json!({"family": "both", "iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20",
            "iran_ip6": "2001:db8::10", "foreign_ip6": "2001:db8::20", "custom": {"transports": ["tcp", "fec-raw"]}});
        let both = make_code(&form).unwrap();
        assert!(both.iran_ip.is_ipv4() && both.foreign_ip.is_ipv4());
        assert_eq!(both.options.cases().iter().filter(|c| c.ipv6).count(), 2);
        assert_eq!(both.options.cases().iter().filter(|c| !c.ipv6).count(), 3);
        form["family"] = json!("ipv4");
        let ipv4 = make_code(&form).unwrap();
        assert_eq!((ipv4.iran_ip, ipv4.foreign_ip), (both.iran_ip, both.foreign_ip));
        assert!(ipv4.iran_ip6.is_none() && ipv4.options.cases().iter().all(|c| !c.ipv6));
        form["family"] = json!("both");
        form["iran_ip6"] = Value::Null;
        form["foreign_ip6"] = Value::Null;
        assert!(make_code(&form).is_err());
    }

    #[test]
    fn ipv6_only_find_and_tune_use_ipv6_for_control_and_cases() {
        let mut form = json!({"family": "ipv6", "iran_ip6": "2001:db8::10", "foreign_ip6": "2001:db8::20"});
        for mode in ["find", "tune"] {
            form["mode"] = json!(mode);
            form["tune_transports"] = json!(["wss"]);
            let code = make_code(&form).unwrap();
            let round_trip = code::decode(&code::encode(&code).unwrap()).unwrap();
            assert_eq!(round_trip, code);
            assert_eq!(Some(code.iran_ip), code.iran_ip6);
            assert_eq!(Some(code.foreign_ip), code.foreign_ip6);
            let cases = code.options.cases();
            assert!(!cases.is_empty());
            assert!(cases.iter().all(|c| c.ipv6 && code.pair_for(c) == Some((code.iran_ip, code.foreign_ip))));
        }
        form["tune_transports"] = json!(["fec-raw", "wss"]);
        assert!(make_code(&form).is_err());
        form["mode"] = json!("find");
        form["custom"] = json!({"transports": ["tun"]});
        assert!(make_code(&form).is_err());
        form["custom"] = Value::Null;
        form["foreign_ip6"] = json!("2001:db8::10");
        assert!(make_code(&form).is_err());
        form["foreign_ip6"] = Value::Null;
        assert!(make_code(&form).is_err());
    }

    #[test]
    fn tune_mode_checks_every_option_of_the_chosen_transports() {
        use crate::config::Transport;
        let form = json!({"iran_ip": "203.0.113.10", "foreign_ip": "198.51.100.20", "preset": "standard",
            "mode": "tune", "tune_transports": ["wss", "parallax", "fec-udp"]});
        let options = make_code(&form).unwrap().options;
        assert_eq!(options.mode, checker::Mode::Tune);
        assert_eq!(options.rounds, checker::TUNE_ROUNDS);
        assert_eq!(options.transports, vec![Transport::Wss, Transport::Parallax, Transport::FecUdp]);
        assert!(options.download && options.hold_sec > 0, "the standard depth is kept");
        let cases = options.cases();
        // wss: default, browser TLS, TLS fragment, congestion, Game mode; parallax: default,
        // congestion, packet, Game mode; fec-udp: default, pacer, Game mode. Two directions, two
        // rounds.
        assert_eq!(cases.len(), (5 + 4 + 3) * 2 * 2);
        for round in 0..2 {
            assert!(cases.iter().any(|c| c.round == round && c.variant == checker::Variant::BrowserTls));
        }
        // The custom panel can change the rounds; an empty or unknown list is refused.
        let mut one = form.clone();
        one["custom"] = json!({"rounds": 1});
        assert_eq!(make_code(&one).unwrap().options.cases().len(), (5 + 4 + 3) * 2);
        for bad in [json!([]), json!(["warp"]), json!("wss")] {
            let mut f = form.clone();
            f["tune_transports"] = bad;
            assert!(make_code(&f).is_err());
        }
        let mut f = form.clone();
        f["mode"] = json!("everything");
        assert!(make_code(&f).is_err());
        let mut f = form;
        f["custom"] = json!({"rounds": 4});
        assert!(make_code(&f).is_err(), "rounds are 1 to 3");
    }

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
        form["custom"] = json!({"transports": ["fec-raw", "fec-udp", "tun"], "tun_profiles": ["icmp", "dns"],
            "also_pacer": true, "download": true, "speed_sec": 7, "tls_port": 8443, "slow_mbps": 20});
        let options = make_code(&form).unwrap().options;
        assert_eq!(options.transports, vec![Transport::FecRaw, Transport::FecUdp, Transport::Tun]);
        assert_eq!(options.tun_profiles, vec![crate::raw_packet::RawProfile::Icmp, crate::raw_packet::RawProfile::Dns]);
        assert!(options.also_pacer && options.download && !options.upload);
        assert_eq!((options.speed_sec, options.tls_port, options.slow_mbps), (7, 8443, 20));
        let mut stream = base.clone();
        stream["custom"] = json!({"transports": ["parallax"], "parallax_packet": false});
        let cases = make_code(&stream).unwrap().options.cases();
        assert_eq!(cases.len(), 2, "stream mode in both directions only");
        // The rest of the Quick preset stays: five pings, no hold.
        assert_eq!((options.pings, options.hold_sec), (5, 0));
        // Pacer cases for both FEC transports; one TUN case per packet type.
        let cases = options.cases();
        assert!(cases.iter().any(|c| c.transport == Transport::FecRaw && c.variant == crate::checker::Variant::Pacer));
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
        let running = demo_status(None, 1000, 1004);
        assert_eq!(running["state"], "running");
        let done = demo_status(None, 1000, 1000 + 3600);
        assert_eq!(done["state"], "finished");
        assert!(!done["best"].as_array().unwrap().is_empty());
        assert_eq!(done["mode"], "find");
        // A started tune check plays out as one, with its per-transport summary.
        let tune = Options::tune(Preset::Standard, vec![crate::config::Transport::Wss, crate::config::Transport::Parallax]);
        let done = demo_status(Some(&tune), 1000, 1000 + 3600);
        assert_eq!(done["mode"], "tune");
        let groups = done["tune"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|g| g["rows"][0]["usable"] == 2), "{groups:?}");
        assert_eq!(done["report"]["options"]["mode"], "tune");
        assert!(answer(&json!({"action": "status"})).unwrap()["state"].is_string());
        assert!(answer(&json!({"action": "explode"})).is_err());
    }
}
