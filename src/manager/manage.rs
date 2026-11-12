//! "Manage tunnels": the list of tunnels and what can be done with one.
use super::plan::{PortRule, Protocol, Side, format_ports, parse_ports, summarize};
use super::service::{self, State};
use super::store::Store;
use super::{bulk, rawfw, tune, ui};
use anyhow::{Context, Result};
use serde_json::{Value, json};

pub fn state_label(state: State) -> String {
    match state {
        State::Running => ui::green("● running"),
        State::Starting => ui::yellow("◌ starting"),
        State::Stopped => ui::dim("○ stopped"),
        State::Failed => ui::red("✘ failed"),
        State::NoService => ui::dim("· no service"),
    }
}

/// One line per tunnel for the list.
fn row(store: &Store, name: &str) -> String {
    let state = state_label(service::state(store, name));
    let description = match store.read(name).and_then(|config| summarize(&config)) {
        Ok(summary) => format!(
            "{:<8} {:<8} {:<9} {:<24} {}",
            match summary.side {
                Side::Iran => "Iran",
                Side::Foreign => "Foreign",
            },
            summary.direction.label(),
            summary.transport,
            summary.link,
            summary.carry
        ),
        Err(error) => ui::red(&format!("unreadable: {error:#}")),
    };
    format!(
        "{:<20} {:<width$} {description}",
        name,
        state,
        width = 12 + state.len() - console::measure_text_width(&state)
    )
}

fn rate(bytes_per_second: f64) -> String {
    let megabits = bytes_per_second * 8.0 / 1_000_000.0;
    if megabits >= 10.0 {
        format!("{megabits:.0} Mbit/s")
    } else {
        format!("{megabits:.1} Mbit/s")
    }
}

fn amount(bytes: u64) -> String {
    let mut value = bytes as f64;
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if value < 1000.0 || unit == "TB" {
            return format!("{value:.1} {unit}");
        }
        value /= 1000.0;
    }
    unreachable!()
}

fn duration(seconds: u64) -> String {
    let (d, h, m, s) = (
        seconds / 86400,
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60,
    );
    match (d, h) {
        (0, 0) => format!("{m}m {s}s"),
        (0, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h"),
    }
}

/// Waits up to `millis` for the Enter key; true when it was pressed.
fn enter_pressed(millis: i32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let mut fd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the duration of the call.
        let ready = unsafe { libc::poll(&mut fd, 1, millis) };
        if ready > 0 {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            return true;
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = millis;
        true
    }
}

/// Whether the running tunnel opens a control socket (live status, speed test). A pure TUN
/// tunnel, with no `forwarding_port`, only forwards IP packets and has none.
fn has_status_channel(config: &Value) -> bool {
    match config.get("tun") {
        Some(tun) if !tun.is_null() => tun
            .get("forwarding_port")
            .is_some_and(|port| !port.is_null()),
        _ => true,
    }
}

/// Heartbeat loss in percent from the heartbeats that were settled: answered, or unanswered for
/// a whole interval. A heartbeat still in flight is neither, so it cannot make the figure jump.
/// `None` until five have settled.
fn loss_percent(lost: u64, answered: u64) -> Option<f64> {
    let settled = lost + answered;
    (settled >= 5).then(|| lost as f64 * 100.0 / settled as f64)
}

/// Round-trip statistics from heartbeat samples: (average, lowest, highest, jitter) in ms.
fn rtt_figures(samples: &[f64]) -> Option<(f64, f64, f64, f64)> {
    if samples.is_empty() {
        return None;
    }
    let recent = &samples[samples.len().saturating_sub(20)..];
    let avg = recent.iter().sum::<f64>() / recent.len() as f64;
    let min = recent.iter().copied().fold(f64::MAX, f64::min);
    let max = recent.iter().copied().fold(0.0, f64::max);
    let jitter = if recent.len() > 1 {
        recent.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (recent.len() - 1) as f64
    } else {
        0.0
    };
    Some((avg, min, max, jitter))
}

fn live_status(store: &Store, name: &str, config: &Value) -> Result<()> {
    if !matches!(
        service::state(store, name),
        State::Running | State::Starting
    ) {
        anyhow::bail!("the tunnel is not running");
    }
    let server = config["mode"] == "server";
    let mut previous: Option<(Value, std::time::Instant)> = None;
    let mut first: Option<Value> = None;
    let (mut peak_down, mut peak_up) = (0.0f64, 0.0f64);
    loop {
        let status = service::control(
            name,
            &json!({"cmd": "status"}),
            std::time::Duration::from_secs(3),
        )?;
        let now = std::time::Instant::now();
        let first_status = first.get_or_insert_with(|| status.clone()).clone();
        let counter = |value: &Value, key: &str| value[key].as_u64().unwrap_or(0);
        // Users download what the foreign server sends towards Iran.
        let (down_key, up_key) = if server {
            ("bytes_from_peer", "bytes_to_peer")
        } else {
            ("bytes_to_peer", "bytes_from_peer")
        };
        let (down, up) = match &previous {
            Some((before, at)) => {
                let seconds = now.duration_since(*at).as_secs_f64().max(0.001);
                (
                    counter(&status, down_key).saturating_sub(counter(before, down_key)) as f64
                        / seconds,
                    counter(&status, up_key).saturating_sub(counter(before, up_key)) as f64
                        / seconds,
                )
            }
            None => (0.0, 0.0),
        };
        peak_down = peak_down.max(down);
        peak_up = peak_up.max(up);
        let samples: Vec<f64> = status["rtt_ms"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_f64)
            .collect();
        let pongs = counter(&status, "pongs").saturating_sub(counter(&first_status, "pongs"));
        let lost =
            counter(&status, "pings_lost").saturating_sub(counter(&first_status, "pings_lost"));
        let loss = match loss_percent(lost, pongs) {
            Some(percent) => format!("{percent:.1}%"),
            None => ui::dim("measuring…"),
        };
        let ping = match rtt_figures(&samples) {
            Some((avg, min, max, jitter)) => {
                let ms = |v: f64| {
                    if v < 10.0 {
                        format!("{v:.1}")
                    } else {
                        format!("{v:.0}")
                    }
                };
                format!(
                    "{} ms  {}",
                    ms(avg),
                    ui::dim(&format!(
                        "(lowest {}, highest {}, jitter {jitter:.1} ms)",
                        ms(min),
                        ms(max)
                    ))
                )
            }
            None => ui::dim("waiting for the first heartbeat…"),
        };
        let reconnects =
            counter(&status, "connects").saturating_sub(counter(&first_status, "connects"));
        let memory = match status["window_frames_limit"].as_u64() {
            Some(limit) => format!(
                "{} of {} MiB in use",
                counter(&status, "window_frames_used") / 64,
                limit / 64
            ),
            None => ui::dim("no limit"),
        };
        ui::banner(&format!("Live status · {name}"));
        ui::boxed(
            name,
            &[
                format!(
                    "{}  {} connection(s) to the other server",
                    ui::dim("Link       "),
                    counter(&status, "sessions")
                ),
                format!(
                    "{}  {} since start, {} while watching",
                    ui::dim("Reconnects "),
                    counter(&status, "connects").saturating_sub(counter(&status, "sessions")),
                    reconnects
                ),
                format!("{}  {}", ui::dim("Ping       "), ping),
                format!("{}  {}", ui::dim("Loss       "), loss),
                format!("{}  {}", ui::dim("Window mem "), memory),
                format!(
                    "{}  {}  {}",
                    ui::dim("Download   "),
                    ui::accent(&rate(down)),
                    ui::dim(&format!("peak {}", rate(peak_down)))
                ),
                format!(
                    "{}  {}  {}",
                    ui::dim("Upload     "),
                    ui::accent(&rate(up)),
                    ui::dim(&format!("peak {}", rate(peak_up)))
                ),
                format!(
                    "{}  {} now, {} since start",
                    ui::dim("Users      "),
                    counter(&status, "streams"),
                    counter(&status, "streams_total")
                ),
                format!(
                    "{}  {} down, {} up",
                    ui::dim("Total      "),
                    amount(counter(&status, down_key)),
                    amount(counter(&status, up_key))
                ),
                format!(
                    "{}  {}   {}",
                    ui::dim("Uptime     "),
                    duration(counter(&status, "uptime_sec")),
                    ui::dim(&format!("v{}", status["version"].as_str().unwrap_or("?")))
                ),
            ],
        );
        ui::note(
            "Download and upload are what users receive and send. Ping comes from the\nheartbeats between the servers. Press Enter to return.",
        );
        previous = Some((status, now));
        if enter_pressed(1000) {
            return Ok(());
        }
    }
}

fn speed_test(name: &str) -> Result<()> {
    ui::heading("Speed test", "through the tunnel, between the two servers");
    ui::note(
        "Data goes between the two EZTunnel servers only; users are not affected much,\nbut the test uses the link while it runs.",
    );
    let sizes = [
        ("Quick (10 MB each way)", 10u64 << 20),
        ("Full  (50 MB each way)", 50 << 20),
    ];
    let labels: Vec<String> = sizes.iter().map(|(l, _)| l.to_string()).collect();
    let Some(choice) = ui::choose("Test size", &labels, 0)? else {
        return Ok(());
    };
    let bytes = sizes[choice].1;
    let mut lines = Vec::new();
    for (label, direction, streams) in [
        ("Download, one connection ", "down", 1),
        ("Upload, one connection   ", "up", 1),
        ("Download, 4 connections  ", "down", 4),
        ("Upload, 4 connections    ", "up", 4),
    ] {
        ui::info(&format!("{}…", label.trim()));
        let request =
            json!({"cmd": "speedtest", "direction": direction, "bytes": bytes, "streams": streams});
        let line = match service::control(name, &request, std::time::Duration::from_secs(300)) {
            Ok(answer) => {
                let per_second = answer["bytes_per_second"].as_f64().unwrap_or(0.0);
                format!(
                    "{}  {}  {}",
                    ui::dim(label),
                    ui::accent(&rate(per_second)),
                    ui::dim(&format!("({:.1} MB/s)", per_second / 1_000_000.0))
                )
            }
            Err(error) => format!("{}  {}", ui::dim(label), ui::red(&format!("{error:#}"))),
        };
        lines.push(line);
    }
    eprintln!();
    ui::boxed("Speed test", &lines);
    ui::note(
        "Download = from the foreign server to this one (what users download).\nOne connection shows a single user's speed; 4 connections show the link's capacity.",
    );
    ui::pause();
    Ok(())
}

/// How much of the traffic quota is used, for the tunnel's box. `None` without a quota.
fn quota_line(name: &str, config: &Value) -> Option<String> {
    let limit = config["quota"]["limit_gb"].as_u64().filter(|l| *l > 0)?;
    let days = config["quota"]["period_days"].as_u64().unwrap_or(30);
    let period = days * 86_400;
    let now = crate::quota::now();
    Some(
        match crate::quota::QuotaState::load(&crate::quota::service_state_path(name)) {
            Some(mut state) => {
                state.roll(now, period);
                format!(
                    "{} of {limit} GB used · new period in {}",
                    amount(state.used_bytes),
                    crate::quota::describe_seconds(state.period_end(period).saturating_sub(now))
                )
            }
            None => format!("0 of {limit} GB used (counting starts when the tunnel runs)"),
        },
    )
}

/// Whether the two servers are actually connected, from the tunnel's own log.
pub fn link_label(store: &Store, name: &str, state: State) -> String {
    if !store.system {
        return ui::dim("unknown in test mode");
    }
    if !matches!(state, State::Running | State::Starting) {
        return ui::dim("down (the service is not running)");
    }
    let health = service::health(name);
    if health.quota_exhausted {
        return ui::yellow("⏸ traffic quota used up; the tunnel is off until the period ends");
    }
    let drop = health
        .last_drop
        .as_deref()
        .map(|reason| format!("; last drop: {reason}"))
        .unwrap_or_default();
    if health.silent {
        return ui::yellow(&format!(
            "◐ connected, but no traffic comes back (a filter may be blocking this carrier){drop}"
        ));
    }
    match (health.sessions, health.recent_connects) {
        (Some(0), _) => ui::red(&format!("✘ not connected{drop}")),
        (Some(n), Some(0)) => ui::green(&format!("● {n} connection(s), stable")),
        (Some(n), Some(r)) => ui::yellow(&format!(
            "◐ {n} connection(s), {r} reconnect(s) in the last minute{drop}"
        )),
        (Some(n), None) => ui::green(&format!("● {n} connection(s)")),
        (None, _) if health.authenticated > 0 => ui::green("● connected (details after a minute)"),
        (None, _) => ui::yellow("◌ waiting for the other server"),
    }
}

pub fn manage(store: &Store) -> Result<()> {
    loop {
        ui::banner("Manage tunnels");
        let names = store.names()?;
        if names.is_empty() {
            ui::info("There are no tunnels yet. Choose New tunnel in the main menu.");
            ui::pause();
            return Ok(());
        }
        ui::note(&format!(
            "  {:<20} {:<12} {:<8} {:<8} {:<9} {:<24} {}",
            "NAME", "STATE", "SERVER", "TYPE", "TRANSPORT", "CONNECTION", "CARRIES"
        ));
        let mut labels: Vec<String> = names.iter().map(|name| row(store, name)).collect();
        labels.push(format!(
            "{}  {}",
            ui::bold("All tunnels"),
            ui::dim("start, stop, restart or delete them all; change one setting everywhere")
        ));
        labels.push(ui::dim("← Back"));
        let Some(choice) = ui::choose("Tunnel", &labels, 0)? else {
            return Ok(());
        };
        if choice == names.len() {
            bulk::menu(store)?;
            continue;
        }
        if choice == names.len() + 1 {
            return Ok(());
        }
        tunnel(store, &names[choice])?;
    }
}

enum Action {
    Live,
    SpeedTest,
    Logs,
    Status,
    Start,
    Stop,
    Restart,
    Ports,
    Proxy,
    RawFirewall,
    Wire,
    Settings,
    LogLevel,
    QuotaReset,
    Edit,
    Key,
    Delete,
    Back,
}

fn tunnel(store: &Store, name: &str) -> Result<()> {
    loop {
        ui::banner(&format!("Tunnel {name}"));
        let config = store.read(name)?;
        let state = service::state(store, name);
        if let Ok(summary) = summarize(&config) {
            let mut lines = vec![
                format!("{}  {}", ui::dim("State     "), state_label(state)),
                format!("{}  {}", ui::dim("Server    "), summary.side.label()),
                format!(
                    "{}  {} tunnel over {}",
                    ui::dim("Type      "),
                    summary.direction.label(),
                    summary.transport
                ),
                format!("{}  {}", ui::dim("Connection"), summary.link),
                format!("{}  {}", ui::dim("Carries   "), summary.carry),
                format!(
                    "{}  {}",
                    ui::dim("Link      "),
                    link_label(store, name, state)
                ),
            ];
            if let Some(quota) = quota_line(name, &config) {
                lines.push(format!("{}  {}", ui::dim("Quota     "), quota));
            }
            ui::boxed(name, &lines);
        }
        let mut actions = Vec::new();
        let mut labels = Vec::new();
        let mut add = |action: Action, label: &str| {
            actions.push(action);
            labels.push(label.to_string());
        };
        if store.system && !has_status_channel(&config) {
            ui::note(
                "This is a TUN-only tunnel: it just forwards IP packets, so it has no live status\nor speed test. Live logs show its state.",
            );
        }
        if store.system {
            if has_status_channel(&config) {
                add(
                    Action::Live,
                    "Live status          (speed, ping, reconnects)",
                );
            }
            if config["mode"] == "server" && config.get("tun").is_none_or(|t| t.is_null()) {
                add(
                    Action::SpeedTest,
                    "Speed test           (through the tunnel)",
                );
            }
            add(Action::Logs, "Live logs            (Ctrl+C to return)");
            add(Action::Status, "Status details");
            match state {
                State::Running | State::Starting => {
                    add(Action::Restart, "Restart");
                    add(Action::Stop, "Stop");
                }
                _ => add(Action::Start, "Start"),
            }
        }
        let is_server = config["mode"] == "server";
        let has_maps = config["listeners"][0]["maps"]
            .as_array()
            .is_some_and(|maps| !maps.is_empty());
        if is_server && has_maps {
            add(Action::Ports, "Change forwarded ports");
        }
        if is_server && has_tcp_maps(&config) {
            add(Action::Proxy, &proxy_label(&config));
        }
        if store.system
            && let Ok(parsed) = super::store::check_file(&store.path(name))
            && let Some(raw) = rawfw::endpoints(&parsed)
        {
            add(Action::RawFirewall, &raw_firewall_label(name, &raw));
        }
        if !raw_only(&config) {
            add(Action::Wire, &wire_label(&config));
        }
        add(Action::Settings, "Change settings");
        if store.system {
            add(
                Action::LogLevel,
                if service::debug_logging(name) {
                    "Log detail: debug   (switch back to normal)"
                } else {
                    "Log detail: normal  (switch to debug for troubleshooting)"
                },
            );
        }
        if store.system && config["quota"]["limit_gb"].as_u64().unwrap_or(0) > 0 {
            add(
                Action::QuotaReset,
                "Reset the quota counter  (start a new period now)",
            );
        }
        add(Action::Edit, "Edit the config file");
        add(Action::Key, "Show the pairing code and key");
        add(Action::Delete, "Delete this tunnel");
        add(Action::Back, "← Back");
        let Some(choice) = ui::choose("Action", &labels, 0)? else {
            return Ok(());
        };
        if matches!(actions[choice], Action::Back) {
            return Ok(());
        }
        let mut deleted = false;
        let result = (|| -> Result<()> {
            match actions[choice] {
                Action::Back => return Ok(()),
                Action::Live => live_status(store, name, &config),
                Action::SpeedTest => speed_test(name),
                Action::Logs => {
                    ui::note("Showing live logs. Press Ctrl+C to return.");
                    service::follow_logs(name)
                }
                Action::Status => {
                    eprintln!("{}", service::status_text(name));
                    ui::pause();
                    Ok(())
                }
                Action::Start => {
                    service::start_saved(store, name)?;
                    if started_well(store, name) {
                        ui::ok("Service is running. Live status shows whether the peer is connected.");
                        Ok(())
                    } else {
                        anyhow::bail!("The service did not stay running. Open Live logs for the startup error; the saved configuration is unchanged.")
                    }
                }
                Action::Stop => service::stop(name).map(|()| ui::ok("Stopped")),
                // Restarting rewrites the service file, so a tunnel created by an older version
                // gets the current settings (for example its status channel).
                Action::Restart => service::install(store, name).map(|()| ui::ok("Restarted")),
                Action::Ports => change_ports(store, name, &config),
                Action::Proxy => change_proxy_protocol(store, name, &config),
                Action::RawFirewall => toggle_raw_firewall(store, name),
                Action::Wire => toggle_wire_version(store, name, &config),
                Action::Settings => match tune::tune_config(&config)? {
                    Some(edited) => save_and_restart(store, name, &edited),
                    None => Ok(()),
                },
                Action::LogLevel => {
                    let debug = !service::debug_logging(name);
                    service::set_debug_logging(name, debug).map(|()| {
                        ui::ok(if debug {
                            "Debug logging is on; the tunnel restarted"
                        } else {
                            "Normal logging; the tunnel restarted"
                        })
                    })
                }
                Action::QuotaReset => reset_quota(name),
                Action::Edit => edit_file(store, name),
                Action::Key => {
                    show_key(&config);
                    eprintln!();
                    if config["tunnel_key"].is_string()
                        && let Err(error) = super::wizard::show_pairing_code(&config)
                    {
                        if ui::is_back(&error) {
                            return Ok(());
                        }
                        ui::warn(&format!("No pairing code: {error:#}"));
                    }
                    ui::pause();
                    Ok(())
                }
                Action::Delete => {
                    if delete(store, name)? {
                        deleted = true;
                    }
                    Ok(())
                }
            }
        })();
        if deleted {
            return Ok(());
        }
        if let Err(error) = result {
            if !ui::is_back(&error) {
                ui::fail(&format!("{error:#}"));
                ui::pause();
            }
        } else if matches!(
            actions[choice],
            Action::Start | Action::Stop | Action::Restart | Action::LogLevel | Action::QuotaReset
        ) {
            std::thread::sleep(std::time::Duration::from_millis(800));
        }
    }
}

/// Forgets the traffic counted so far and restarts the tunnel, which starts a new period.
fn reset_quota(name: &str) -> Result<()> {
    if !ui::confirm(
        "Forget the traffic counted so far and start a new period now?",
        false,
    )? {
        return Ok(());
    }
    reset_quota_with(
        || service::stop(name),
        || std::fs::remove_file(crate::quota::service_state_path(name)),
        || service::start(name),
    )?;
    ui::ok("New period started; the tunnel restarted");
    Ok(())
}

/// C21: the running tracker would write its in-memory count back, so the tunnel stops
/// before the count is removed and starts afterwards; a failed removal still restarts it.
fn reset_quota_with(
    stop: impl FnOnce() -> Result<()>,
    remove: impl FnOnce() -> std::io::Result<()>,
    mut start: impl FnMut() -> Result<()>,
) -> Result<()> {
    stop()?;
    match remove() {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            let _ = start();
            return Err(error).context("remove the quota count; restarting the unchanged tunnel was attempted");
        }
    }
    start()
}

/// Raw carriers expose their wire-format setting separately from this stream toggle.
fn raw_only(config: &Value) -> bool {
    ["listeners", "paths"]
        .iter()
        .filter_map(|key| config[key].get(0))
        .any(|entry| entry["transport"] == "tun")
}

fn wire_label(config: &Value) -> String {
    if config["wire_version"] == 3 {
        return "Session rotation (wire version 3): on  (switch to legacy)".to_string();
    }
    if config["wire_version"].as_u64().unwrap_or(1) >= 2 {
        "Probe resistance (wire version 2): on  (turn off)".to_string()
    } else {
        "Probe resistance (wire version 2): off (turn on)".to_string()
    }
}

/// Switches shaping/rotation settings; both endpoints need the same setting.
fn toggle_wire_version(store: &Store, name: &str, config: &Value) -> Result<()> {
    let on = config["wire_version"].as_u64().unwrap_or(1) >= 2;
    ui::note(if on {
        "Wire version 1 disables shaping and rotation. Both endpoints must use the same setting."
    } else {
        "Version 3 rotates frame formats for each authenticated session. Both servers must use version 3."
    });
    if !ui::confirm(
        if on {
            "Switch this tunnel to wire version 1?"
        } else {
            "Switch this tunnel to wire version 3?"
        },
        false,
    )? {
        return Ok(());
    }
    let mut edited = config.clone();
    if on {
        edited
            .as_object_mut()
            .map(|root| root.remove("wire_version"));
    } else {
        edited["wire_version"] = crate::stealth::new_version().into();
    }
    save_and_restart(store, name, &edited)?;
    ui::warn("Change the same setting on the other server too, or the tunnel will not connect.");
    ui::pause();
    Ok(())
}

/// The menu line for the raw TCP firewall rules of a tunnel.
fn raw_firewall_label(name: &str, raw: &rawfw::RawTcp) -> String {
    match (rawfw::enabled(name), rawfw::rules_present(name, raw)) {
        (true, Some(true)) => "Raw TCP firewall rules: on (turn off)".to_string(),
        (true, _) => "Raw TCP firewall rules: switched on but NOT in place (re-apply)".to_string(),
        (false, _) => "Raw TCP firewall rules: off (turn on, recommended)".to_string(),
    }
}

/// Switches the raw TCP firewall rules on or off, or re-applies them when they went missing.
fn toggle_raw_firewall(store: &Store, name: &str) -> Result<()> {
    let config = super::store::check_file(&store.path(name))?;
    let Some(raw) = rawfw::endpoints(&config) else {
        ui::note("This tunnel does not send raw TCP packets, so it needs no rules.");
        ui::pause();
        return Ok(());
    };
    let missing = rawfw::enabled(name) && rawfw::rules_present(name, &raw) != Some(true);
    if rawfw::enabled(name) && !missing {
        if ui::confirm("Remove the firewall rules of this tunnel?", false)? {
            rawfw::disable(name)?;
            ui::ok("Firewall rules removed");
        }
        return Ok(());
    }
    ui::note(
        "These rules keep the kernel's TCP resets and connection tracking away from the raw\npackets. They only touch the other server's address and the raw ports:",
    );
    for rule in rawfw::rules(&raw, name) {
        ui::note(&format!("  {}", rule.command("-I")));
    }
    if ui::confirm("Add these rules now?", true)? {
        rawfw::enable(name, &config)?;
        ui::ok("Firewall rules added (they start with the tunnel)");
    }
    Ok(())
}

/// Saves new settings and restarts the tunnel with them. A configuration that passes every check
/// can still fail to start (a port another program holds), so the tunnel is watched for a few
/// seconds afterwards; if it does not stay up, the previous settings can be put back.
fn save_and_restart(store: &Store, name: &str, config: &Value) -> Result<()> {
    store.save(name, config)?;
    ui::ok("Saved");
    let mut outcome = None;
    if store.system {
        let result = recover_after_save(
            || service::install(store, name),
            || started_well(store, name),
            store.has_previous(name),
            |question| ui::confirm(question, true),
            || store.restore_previous(name),
        )?;
        report_recovery(&result);
        outcome = Some(result);
    }
    std::thread::sleep(std::time::Duration::from_millis(800));
    match outcome {
        Some(Recovery::KeptNew { install_error: Some(error) }) => {
            anyhow::bail!("the new settings are saved but their service could not be installed: {error}")
        }
        Some(Recovery::RestoreFailed(error)) => anyhow::bail!("going back to the previous settings failed: {error}"),
        _ => Ok(()),
    }
}

/// What happened after new settings were saved over existing ones.
#[derive(Debug, PartialEq, Eq)]
enum Recovery {
    Running,
    /// The previous settings are back and their service is running (or not).
    Restored { running: bool },
    /// The new settings stay saved; `install_error` when their service could not even be
    /// installed (the old process may still be running the old settings).
    KeptNew { install_error: Option<String> },
    /// Putting the previous settings back, or installing them, failed.
    RestoreFailed(String),
}

/// C20: an installation error goes through the same recovery choice as a failed start,
/// is reported as what it is, and a failure of the recovery itself is reported apart.
fn recover_after_save(
    mut install: impl FnMut() -> Result<()>,
    mut started: impl FnMut() -> bool,
    has_previous: bool,
    mut confirm: impl FnMut(&str) -> Result<bool>,
    mut restore: impl FnMut() -> Result<()>,
) -> Result<Recovery> {
    let install_error = match install() {
        Ok(()) if started() => return Ok(Recovery::Running),
        Ok(()) => None,
        Err(error) => Some(format!("{error:#}")),
    };
    match &install_error {
        Some(error) => ui::fail(&format!("Configuration saved but service installation failed: {error}")),
        None => ui::fail("The tunnel did not stay up with the new settings (see Logs for the reason)."),
    }
    if !has_previous || !confirm("Go back to the previous settings?")? {
        return Ok(Recovery::KeptNew { install_error });
    }
    if let Err(error) = restore() {
        return Ok(Recovery::RestoreFailed(format!("restore the previous settings: {error:#}")));
    }
    if let Err(error) = install() {
        return Ok(Recovery::RestoreFailed(format!(
            "the previous settings are saved again but their service could not be installed: {error:#}"
        )));
    }
    Ok(Recovery::Restored { running: started() })
}

fn report_recovery(outcome: &Recovery) {
    match outcome {
        Recovery::Running => ui::ok("Restarted with the new settings"),
        Recovery::Restored { running: true } => ui::ok("Back on the previous settings; the tunnel is running"),
        Recovery::Restored { running: false } => ui::fail("It does not stay up with the previous settings either (see Logs)."),
        Recovery::KeptNew { .. } => ui::note("The new settings stay saved."),
        Recovery::RestoreFailed(error) => ui::fail(error),
    }
}

/// Waits a few seconds and says whether the tunnel's service is running and stays running.
fn started_well(store: &Store, name: &str) -> bool {
    ui::info("Checking that it starts…");
    service::watch_started(
        || service::state(store, name) == service::State::Running,
        std::thread::sleep,
    )
}

fn has_tcp_maps(config: &Value) -> bool {
    config["listeners"][0]["maps"]
        .as_array()
        .is_some_and(|maps| maps.iter().any(|map| map["type"] != "udp"))
}

/// The PROXY protocol version the TCP maps use (the first one that sets it), if any.
fn current_proxy(config: &Value) -> Option<u8> {
    config["listeners"][0]["maps"]
        .as_array()?
        .iter()
        .filter(|map| map["type"] != "udp")
        .find_map(|map| map["proxy_protocol"].as_u64())
        .and_then(|version| u8::try_from(version).ok())
}

fn proxy_label(config: &Value) -> String {
    match current_proxy(config) {
        Some(1) => "PROXY protocol to the destination: version 1 (text)".to_string(),
        Some(_) => "PROXY protocol to the destination: version 2 (binary)".to_string(),
        None => "PROXY protocol to the destination: off".to_string(),
    }
}

/// Sets (or with `None` removes) `proxy_protocol` on every TCP map.
fn set_proxy(config: &mut Value, version: Option<u8>) {
    let Some(maps) = config["listeners"][0]["maps"].as_array_mut() else {
        return;
    };
    for map in maps.iter_mut().filter(|map| map["type"] != "udp") {
        match version {
            Some(version) => map["proxy_protocol"] = version.into(),
            None => {
                if let Some(object) = map.as_object_mut() {
                    object.remove("proxy_protocol");
                }
            }
        }
    }
}

/// Chooses whether the destination service is told the real address of each user.
fn change_proxy_protocol(store: &Store, name: &str, config: &Value) -> Result<()> {
    ui::heading(
        "PROXY protocol",
        "the real user address for the destination",
    );
    ui::note(
        "Without this, the service behind the tunnel (for example nginx) sees every user\nas the tunnel itself. With it, this server sends each user's address through the tunnel and\nthe far end writes a PROXY protocol header to the destination before the user's data.\nThe destination MUST be set to expect it (for example nginx `proxy_protocol`),\notherwise it reads the header as garbage and every connection fails. Only TCP ports use it.\nBoth servers need EZTunnel 0.7.1 or later.",
    );
    let choices = vec![
        "Off".to_string(),
        "Version 1  (text, understood by almost everything)".to_string(),
        "Version 2  (binary, smaller)".to_string(),
    ];
    let current = current_proxy(config).map_or(0, usize::from);
    let picked = ui::choose_required("PROXY protocol", &choices, current.min(2))?;
    let version = match picked {
        0 => None,
        1 => Some(1),
        _ => Some(2),
    };
    if version == current_proxy(config) {
        return Ok(());
    }
    let mut edited = config.clone();
    set_proxy(&mut edited, version);
    save_and_restart(store, name, &edited)
}

/// Reads the forwarded ports back from a server configuration, and whether every map shares one
/// bind address: this screen can only show and write back one, so a config with more than one
/// (only reachable by hand-editing - the wizard itself never writes more than one) would
/// otherwise be silently collapsed onto whichever map happened to be read last.
fn current_ports(config: &Value) -> (Vec<PortRule>, Protocol, String, bool) {
    let mut rules: Vec<PortRule> = Vec::new();
    let (mut tcp, mut udp) = (false, false);
    let mut public_ip = "0.0.0.0".to_string();
    let mut bind_ips: Vec<String> = Vec::new();
    for map in config["listeners"][0]["maps"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let bind = map["bind"].as_str().unwrap_or_default();
        let target = map["target"].as_str().unwrap_or_default().to_string();
        match map["type"].as_str() {
            Some("udp") => udp = true,
            _ => tcp = true,
        }
        if let Some((ip, port)) = bind.rsplit_once(':') {
            let ip = ip.trim_start_matches('[').trim_end_matches(']').to_string();
            if !bind_ips.contains(&ip) {
                bind_ips.push(ip.clone());
            }
            public_ip = ip;
            if let Ok(listen) = port.parse()
                && !rules.iter().any(|r| r.listen == listen)
            {
                rules.push(PortRule { listen, target });
            }
        }
    }
    let protocol = match (tcp, udp) {
        (true, true) => Protocol::Both,
        (false, true) => Protocol::Udp,
        _ => Protocol::Tcp,
    };
    (rules, protocol, public_ip, bind_ips.len() > 1)
}

fn change_ports(store: &Store, name: &str, config: &Value) -> Result<()> {
    let (rules, protocol, public_ip, differs) = current_ports(config);
    let proxy = current_proxy(config);
    ui::heading("Forwarded ports", "");
    if differs {
        ui::warn(&format!(
            "This tunnel's ports are bound to more than one address; this screen only shows and \
             writes back one ({public_ip}). Continuing moves every port onto that one address."
        ));
        if !ui::confirm("Continue anyway?", false)? {
            return Ok(());
        }
    }
    ui::note("Examples:  443   443, 8443   2083=443   9000-9010   5000=10.0.0.5:5000");
    let text = ui::ask(
        "Ports to forward",
        Some(&format_ports(&rules)),
        |t: &String| parse_ports(t).map(|_| ()).map_err(|e| e.to_string()),
    )?;
    let rules = parse_ports(&text)?;
    let protocols = [Protocol::Tcp, Protocol::Udp, Protocol::Both];
    let labels: Vec<String> = protocols.iter().map(|p| p.label().to_string()).collect();
    let current = protocols.iter().position(|p| *p == protocol).unwrap_or(0);
    let protocol = protocols[ui::choose_required("Protocol", &labels, current)?];
    let(original_rules,original_protocol,_,_)=current_ports(config);
    if rules==original_rules&&protocol==original_protocol{return Ok(());}
    let host = if public_ip.contains(':') {
        format!("[{public_ip}]")
    } else {
        public_ip
    };
    let mut maps = Vec::new();
    for rule in &rules {
        let bind = format!("{host}:{}", rule.listen);
        if protocol != Protocol::Udp {
            maps.push(json!({"type":"tcp","bind":bind,"target":rule.target}));
        }
        if protocol != Protocol::Tcp {
            maps.push(json!({"type":"udp","bind":bind,"target":rule.target}));
        }
    }
    let mut edited = config.clone();
    for map in &mut maps{if map["type"]!="udp"&&let Some(proxy)=proxy{map["proxy_protocol"]=proxy.into();}}
    edited["listeners"][0]["maps"] = Value::Array(preserve_unedited_maps(config,&original_rules,&rules,protocol==original_protocol,maps));
    save_and_restart(store, name, &edited)
}

fn preserve_unedited_maps(config:&Value,old:&[PortRule],new:&[PortRule],same_protocol:bool,generated:Vec<Value>)->Vec<Value>{
    if !same_protocol{return generated;}
    let original=config["listeners"][0]["maps"].as_array().cloned().unwrap_or_default();
    let port=|map:&Value|map["bind"].as_str().and_then(|bind|bind.rsplit_once(':')).and_then(|(_,port)|port.parse::<u16>().ok());
    let mut out=Vec::new();
    for rule in new{
        let list=if old.iter().any(|old|old==rule){&original}else{&generated};
        out.extend(list.iter().filter(|map|port(map)==Some(rule.listen)).cloned());
    }out
}

fn edit_file(store: &Store, name: &str) -> Result<()> {
    let draft = store.draft(name)?;
    let editor = std::env::var("EDITOR")
        .ok()
        .filter(|e| !e.trim().is_empty())
        .or_else(|| {
            ["nano", "vim", "vi"]
                .iter()
                .find(|e| {
                    std::process::Command::new("sh")
                        .args(["-c", &format!("command -v {e}")])
                        .stdout(std::process::Stdio::null())
                        .status()
                        .is_ok_and(|s| s.success())
                })
                .map(|e| e.to_string())
        })
        .context("no text editor found; install nano or set EDITOR")?;
    // Split on whitespace instead of handing the raw string to a shell: EDITOR commonly carries
    // its own arguments ("code --wait"), but it is the operator's own environment, not something
    // to let run arbitrary shell syntax (a stray `;` would otherwise execute, not just annoy).
    let mut words = editor.split_whitespace();
    let program = words.next().context("EDITOR is set but empty")?.to_string();
    let arguments: Vec<String> = words.map(str::to_string).collect();
    loop {
        let status = std::process::Command::new(&program)
            .args(&arguments)
            .arg(&draft)
            .status()
            .context("open the editor")?;
        if !status.success() {
            ui::warn("The editor reported an error.");
        }
        let unchanged = std::fs::read(&draft)? == std::fs::read(store.path(name))?;
        if unchanged {
            let _ = std::fs::remove_file(&draft);
            ui::info("No changes.");
            return Ok(());
        }
        match super::store::check_file(&draft) {
            Ok(_) => {
                store.adopt(name, &draft)?;
                ui::ok("Saved");
                if store.system && ui::confirm("Restart the tunnel to use it?", true)? {
                    service::install(store, name)?;
                    ui::ok("Restarted");
                }
                return Ok(());
            }
            Err(error) => {
                ui::fail(&format!("The file has a problem: {error:#}"));
                let choices = vec!["Edit again".to_string(), "Discard my changes".to_string()];
                if ui::choose_required("What now?", &choices, 0)? == 1 {
                    let _ = std::fs::remove_file(&draft);
                    return Ok(());
                }
            }
        }
    }
}

pub fn show_key(config: &Value) {
    let key = config["tunnel_key"]
        .as_str()
        .unwrap_or("(this tunnel uses key files)");
    let mut lines = vec![ui::accent(key).to_string()];
    if let Ok(summary) = summarize(config) {
        lines.push(String::new());
        lines.push(format!(
            "On the {}: New tunnel → {} → {} tunnel →",
            summary.side.other().label(),
            summary.side.other().label(),
            summary.direction.label()
        ));
        lines.push(format!(
            "transport {} → same port → paste this key.",
            summary.transport
        ));
    }
    ui::boxed("Tunnel key", &lines);
    ui::note("Keep it secret: whoever has it can join this tunnel.");
}

/// Returns true when the tunnel was deleted.
fn delete(store: &Store, name: &str) -> Result<bool> {
    if !ui::confirm(
        &format!("Delete tunnel {name}? Its service stops and its config is removed."),
        false,
    )? {
        return Ok(false);
    }
    if store.system {
        service::remove(name)?;
    }
    store.remove(name)?;
    ui::ok(&format!("Deleted {name}"));
    std::thread::sleep(std::time::Duration::from_millis(800));
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C20: injected service callbacks, no systemd. `installs` scripts each install call.
    fn recovery(installs: Vec<bool>, starts: Vec<bool>, has_previous: bool, consent: bool, restore_ok: bool) -> (Recovery, usize, usize) {
        let (mut installs, mut starts) = (installs.into_iter(), starts.into_iter());
        let (mut install_calls, mut restores) = (0, 0);
        let outcome = recover_after_save(
            || { install_calls += 1; if installs.next().unwrap_or(true) { Ok(()) } else { Err(anyhow::anyhow!("unit write failed")) } },
            || starts.next().unwrap_or(false),
            has_previous,
            |_| Ok(consent),
            || { restores += 1; if restore_ok { Ok(()) } else { Err(anyhow::anyhow!("backup unreadable")) } },
        ).unwrap();
        (outcome, install_calls, restores)
    }

    #[test]
    fn quota_reset_stops_before_removing_the_count_and_always_restarts() {
        use std::cell::RefCell;
        let run = |remove: std::io::Result<()>, stop_ok: bool| {
            let log = RefCell::new(Vec::new());
            let result = reset_quota_with(
                || { log.borrow_mut().push("stop"); if stop_ok { Ok(()) } else { Err(anyhow::anyhow!("stop failed")) } },
                || { log.borrow_mut().push("remove"); remove },
                || { log.borrow_mut().push("start"); Ok(()) },
            );
            (result.is_ok(), log.into_inner())
        };
        assert_eq!(run(Ok(()), true), (true, vec!["stop", "remove", "start"]));
        assert_eq!(run(Err(std::io::ErrorKind::NotFound.into()), true), (true, vec!["stop", "remove", "start"]));
        assert_eq!(run(Err(std::io::ErrorKind::PermissionDenied.into()), true), (false, vec!["stop", "remove", "start"]));
        assert_eq!(run(Ok(()), false), (false, vec!["stop"]), "a running tracker must not survive a removed count");
    }

    #[test]
    fn an_install_error_reaches_the_previous_settings_recovery() {
        // Success and health-failure controls.
        assert_eq!(recovery(vec![true], vec![true], true, true, true).0, Recovery::Running);
        assert_eq!(recovery(vec![true, true], vec![false, true], true, true, true), (Recovery::Restored { running: true }, 2, 1));
        // Install error: recovery is offered; consent restores and reinstalls the previous settings.
        assert_eq!(recovery(vec![false, true], vec![true], true, true, true), (Recovery::Restored { running: true }, 2, 1));
        // Refusal keeps the new bytes with the install error visible.
        let (outcome, _, restores) = recovery(vec![false], vec![], true, false, true);
        assert_eq!(restores, 0);
        assert!(matches!(outcome, Recovery::KeptNew { install_error: Some(ref e) } if e.contains("unit write failed")), "{outcome:?}");
        // No previous settings: nothing to offer, error still visible.
        assert!(matches!(recovery(vec![false], vec![], false, true, true).0, Recovery::KeptNew { install_error: Some(_) }));
        // Failures of the recovery itself are reported separately.
        assert!(matches!(recovery(vec![false], vec![], true, true, false).0, Recovery::RestoreFailed(ref e) if e.contains("backup unreadable")));
        assert!(matches!(recovery(vec![false, false], vec![], true, true, true).0, Recovery::RestoreFailed(ref e) if e.contains("could not be installed")));
    }

    #[test]
    fn editing_another_port_preserves_mixed_protocol_targets_and_per_map_proxy(){
        let config=json!({"listeners":[{"maps":[
            {"type":"tcp","bind":"0.0.0.0:443","target":"127.0.0.1:8443","proxy_protocol":1},
            {"type":"udp","bind":"0.0.0.0:443","target":"127.0.0.1:9443"},
            {"type":"tcp","bind":"0.0.0.0:444","target":"127.0.0.1:444","proxy_protocol":2}]}]});
        let(old,_,_,_)=current_ports(&config);let mut new=old.clone();new.push(PortRule{listen:445,target:"127.0.0.1:445".into()});
        let added=json!({"type":"tcp","bind":"0.0.0.0:445","target":"127.0.0.1:445"});
        let maps=preserve_unedited_maps(&config,&old,&new,true,vec![added.clone()]);
        assert_eq!(&maps[..3],config["listeners"][0]["maps"].as_array().unwrap());assert_eq!(maps[3],added);
    }

    #[test]
    fn only_a_tun_tunnel_without_port_forwarding_lacks_a_status_channel() {
        use serde_json::json;
        assert!(has_status_channel(&json!({"mode": "server"})));
        assert!(has_status_channel(&json!({"mode": "server", "tun": null})));
        assert!(has_status_channel(
            &json!({"mode": "server", "tun": {"name": "ez0", "forwarding_port": 47475}})
        ));
        assert!(!has_status_channel(
            &json!({"mode": "server", "tun": {"name": "ez0"}})
        ));
        assert!(!has_status_channel(
            &json!({"mode": "client", "tun": {"name": "ez0", "forwarding_port": null}})
        ));
    }

    #[test]
    fn loss_ignores_heartbeats_that_are_still_in_flight() {
        // Too few settled heartbeats: no figure yet (one in-flight ping used to read as 20 %).
        assert_eq!(loss_percent(0, 0), None);
        assert_eq!(loss_percent(1, 3), None);
        assert_eq!(loss_percent(0, 5), Some(0.0));
        assert_eq!(loss_percent(1, 9), Some(10.0));
        assert_eq!(loss_percent(5, 5), Some(50.0));
    }

    #[test]
    fn the_proxy_protocol_choice_applies_to_tcp_maps_only_and_survives_a_port_change() {
        let mut config = json!({"mode":"server","listeners":[{"addr":"0.0.0.0:7000","maps":[
            {"type":"tcp","bind":"0.0.0.0:443","target":"127.0.0.1:443"},
            {"type":"udp","bind":"0.0.0.0:443","target":"127.0.0.1:443"}
        ]}]});
        assert!(has_tcp_maps(&config));
        assert_eq!(current_proxy(&config), None);
        set_proxy(&mut config, Some(2));
        assert_eq!(current_proxy(&config), Some(2));
        let maps = config["listeners"][0]["maps"].as_array().unwrap();
        assert_eq!(maps[0]["proxy_protocol"], 2);
        assert!(maps[1].get("proxy_protocol").is_none(), "UDP has none");
        assert!(proxy_label(&config).contains("version 2"));
        set_proxy(&mut config, Some(1));
        assert!(proxy_label(&config).contains("version 1"));
        set_proxy(&mut config, None);
        assert_eq!(current_proxy(&config), None);
        assert!(
            config["listeners"][0]["maps"][0]
                .get("proxy_protocol")
                .is_none()
        );
        let udp_only = json!({"listeners":[{"maps":[{"type":"udp","bind":"0.0.0.0:53","target":"127.0.0.1:53"}]}]});
        assert!(!has_tcp_maps(&udp_only));
    }

    #[test]
    fn forwarded_ports_are_read_back() {
        let config = json!({"mode":"server","listeners":[{"addr":"0.0.0.0:7000","maps":[
            {"type":"tcp","bind":"0.0.0.0:443","target":"127.0.0.1:443"},
            {"type":"udp","bind":"0.0.0.0:443","target":"127.0.0.1:443"},
            {"type":"tcp","bind":"0.0.0.0:2083","target":"127.0.0.1:8443"}
        ]}]});
        let (rules, protocol, ip, differs) = current_ports(&config);
        assert_eq!(format_ports(&rules), "443, 2083=8443");
        assert_eq!(protocol, Protocol::Both);
        assert_eq!(ip, "0.0.0.0");
        assert!(!differs, "every map here shares the same bind address");
    }

    #[test]
    fn maps_with_different_bind_addresses_are_flagged_as_differing() {
        // Only reachable by hand-editing: the wizard itself never writes more than one bind
        // address, since this screen (and the Plan it is built from) can only hold one.
        let config = json!({"mode":"server","listeners":[{"addr":"0.0.0.0:7000","maps":[
            {"type":"tcp","bind":"127.0.0.1:443","target":"127.0.0.1:443"},
            {"type":"tcp","bind":"10.0.0.5:8080","target":"10.0.0.5:8080"}
        ]}]});
        let (_rules, _protocol, ip, differs) = current_ports(&config);
        assert!(differs);
        assert_eq!(
            ip, "10.0.0.5",
            "the last map's address, same as before this fix"
        );
    }
}
