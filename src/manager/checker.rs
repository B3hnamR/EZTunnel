//! Tools → Transport checker: start a check on one server, join it on the other with the code,
//! watch it live (pause, skip, stop, log, details), then see the ranked results, keep the report
//! and create a tunnel with the transport that worked best.
use super::plan::{Direction, Side as PlanSide};
use super::store::Store;
use super::{ui, wizard};
use crate::checker::{
    self, CHECKABLE, CaseResult, Options, Preset, Priority, Report, Side, Verdict,
    code::{self, CheckCode},
    control::Command,
    logbuf,
    run::{self, View},
};
use crate::config::Transport;
use anyhow::{Context, Result};
use console::{Key, Term, style};
use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

pub fn menu(store: &Store) -> Result<()> {
    loop {
        ui::banner("Transport checker");
        ui::note(
            "Finds which transports work between your two servers, in which direction and how\nfast. Start a check on one server, then join it on the other with the code.",
        );
        let items = vec![
            format!(
                "{}  {}",
                ui::bold("Start a check"),
                ui::dim("choose what to check and get a code")
            ),
            format!(
                "{}  {}",
                ui::bold("Join a check "),
                ui::dim("paste the code from the other server")
            ),
            format!(
                "{}  {}",
                ui::bold("Past checks  "),
                ui::dim("reports kept on this server")
            ),
            ui::dim("← Back"),
        ];
        let result = match ui::choose("Transport checker", &items, 0)? {
            Some(0) => start(store),
            Some(1) => join(store),
            Some(2) => past(store),
            _ => return Ok(()),
        };
        if let Err(error) = result {
            if !ui::is_back(&error) {
                ui::fail(&format!("{error:#}"));
                ui::pause();
            }
        }
    }
}

/// A list with a "← Back" row at the end; `None` for that row or Esc.
fn choose_or_back(prompt: &str, items: &[String], default: usize) -> Result<Option<usize>> {
    let mut rows = items.to_vec();
    rows.push(ui::dim("← Back"));
    Ok(ui::choose(prompt, &rows, default)?.filter(|i| *i < items.len()))
}

fn side_label(side: Side) -> &'static str {
    match side {
        Side::Iran => "Iran server",
        Side::Foreign => "Foreign server",
    }
}

/// An IP address; `None` when the answer is left empty (back).
fn ask_ip(prompt: &str, default: Option<String>) -> Result<Option<IpAddr>> {
    let answer = ui::ask_or_back(prompt, default.as_deref(), |text: &String| {
        text.trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| "enter an IP address, for example 1.2.3.4".to_string())
    })?;
    answer
        .map(|text| Ok(text.trim_start_matches('[').trim_end_matches(']').parse()?))
        .transpose()
}

/// The local address the system would use to reach `other` (a hint; behind NAT it is not the
/// public one).
fn route_source(other: IpAddr) -> Option<String> {
    let bind = if other.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect((other, 9)).ok()?;
    let local = socket.local_addr().ok()?.ip();
    (!local.is_unspecified()).then(|| local.to_string())
}

fn fmt_duration(seconds: u64) -> String {
    if seconds >= 3600 {
        format!(
            "{}:{:02}:{:02}",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        )
    } else {
        format!("{:02}:{:02}", seconds / 60, seconds % 60)
    }
}

fn about(seconds: u64) -> String {
    if seconds < 90 {
        format!("~{seconds} s")
    } else {
        format!("~{} min", seconds.div_ceil(60))
    }
}

fn start(store: &Store) -> Result<()> {
    let (me, iran_ip, foreign_ip, options) = ui::form(|| {
        ui::banner("Transport checker · start");
        let sides = vec![
            format!(
                "{}  {}",
                ui::bold("Iran server   "),
                ui::dim("entry: users connect to this server")
            ),
            format!(
                "{}  {}",
                ui::bold("Foreign server"),
                ui::dim("exit: traffic leaves to the internet from here")
            ),
        ];
        let Some(choice) = choose_or_back("Which server is this?", &sides, 0)? else {
            return Err(ui::Back.into());
        };
        let me = if choice == 0 {
            Side::Iran
        } else {
            Side::Foreign
        };
        let Some(other) = ask_ip(
            &format!(
                "IP address of the {}",
                side_label(me.other()).to_lowercase()
            ),
            None,
        )?
        else {
            return Err(ui::Back.into());
        };
        let Some(own) = ask_ip("This server's public IP address", route_source(other))? else {
            return Err(ui::Back.into());
        };
        anyhow::ensure!(own != other, "the two servers need different addresses");
        let (iran_ip, foreign_ip) = match me {
            Side::Iran => (own, other),
            Side::Foreign => (other, own),
        };
        let options = choose_options(store, iran_ip, foreign_ip)?.ok_or(ui::Back)?;
        Ok((me, iran_ip, foreign_ip, options))
    })?;
    let mut code = CheckCode::new(me, iran_ip, foreign_ip, options)?;
    // This server has IPv6: the check can also run every case over IPv6 (a route that drops one
    // family may carry the other).
    if let Some(own6) = super::local_ip6() {
        ui::note(&format!("This server also has the IPv6 address {own6}."));
        let other6 = ui::ask(
            &format!("IPv6 address of the {} (empty: check IPv4 only)", side_label(me.other()).to_lowercase()),
            Some(""),
            |text: &String| {
                if text.trim().is_empty() || text.trim().trim_matches(['[', ']']).parse::<std::net::Ipv6Addr>().is_ok() {
                    Ok(())
                } else {
                    Err("enter an IPv6 address, or nothing".into())
                }
            },
        )?;
        if let Ok(other6) = other6.trim().trim_matches(['[', ']']).parse::<std::net::Ipv6Addr>() {
            let (iran6, foreign6) = match me {
                Side::Iran => (IpAddr::V6(own6), IpAddr::V6(other6)),
                Side::Foreign => (IpAddr::V6(other6), IpAddr::V6(own6)),
            };
            code = code.with_ipv6(iran6, foreign6)?;
        }
    }
    if !bridge(code.ip(me), code.ip(me.other()), code.options.control_port)? {
        return Ok(());
    }
    let text = code::encode(&code)?;
    ui::boxed(
        "On the other server",
        &[
            "1. Run  sudo eztunnel  there".to_string(),
            "2. Tools → Transport checker → Join a check".to_string(),
            "3. Paste the code below".to_string(),
        ],
    );
    eprintln!();
    eprintln!("{}", ui::accent(&text));
    eprintln!();
    ui::note("The code holds a key for this check only. This server waits for the other one now.");
    watch(store, code, me)
}

fn join(store: &Store) -> Result<()> {
    let (code, me) = ui::form(|| {
        ui::banner("Transport checker · join");
        let Some(text) = ui::ask_or_back("Paste the check code", None, |text: &String| {
            code::decode(text).map(|_| ()).map_err(|e| e.to_string())
        })?
        else {
            return Err(ui::Back.into());
        };
        let code = code::decode(&text)?;
        let me = code.starter.other();
        ui::ok(&format!(
            "This server is the {} ({}); the other one started the check.",
            side_label(me).to_lowercase(),
            code.ip(me)
        ));
        summary(&code.options);
        let actions = vec![ui::bold("Join and start the check").to_string()];
        if choose_or_back("Ready", &actions, 0)?.is_none() {
            return Err(ui::Back.into());
        }
        Ok((code, me))
    })?;
    if !bridge(code.ip(me), code.ip(me.other()), code.options.control_port)? {
        return Ok(());
    }
    watch(store, code, me)
}

/// How the two servers coordinate the check. Normally directly; when they cannot reach each
/// other, through the operator's computer: an SSH reverse forward makes a local port on this
/// server lead to the other server's control port. Only the check's control messages take that
/// way; every test tunnel still connects directly, so each transport still gets a real verdict.
/// Returns false when the operator went back.
fn bridge(own: IpAddr, other: IpAddr, control: u16) -> Result<bool> {
    let ways = vec![
        format!("{}  {}", ui::bold("Directly"), ui::dim("the two servers can reach each other (normal)")),
        format!("{}  {}", ui::bold("Through my computer over SSH"), ui::dim("the servers cannot reach each other, but my computer reaches both")),
    ];
    let Some(way) = choose_or_back("How do the two servers coordinate the check?", &ways, 0)? else {
        return Ok(false);
    };
    if way == 0 {
        crate::checker::control::set_control_via(None);
        return Ok(true);
    }
    const LOCAL: u16 = 47101;
    let host = |ip: IpAddr| if ip.is_ipv6() { format!("[{ip}]") } else { ip.to_string() };
    ui::boxed(
        "On your computer (keep it open while the check runs)",
        &[
            format!("ssh -N -R {LOCAL}:{}:{control} root@{}", host(other), host(own)),
            String::new(),
            "Use your SSH user instead of root if it differs; add -p PORT when SSH is not on port 22.".into(),
            "Only this server uses it: on the other server choose Directly.".into(),
            "If the other server can still reach this one directly, the check starts without it.".into(),
            format!("If your computer cannot reach {}:{control} directly, use two windows instead:", host(other)),
            format!("  ssh -N -L 47102:127.0.0.1:{control} root@{}", host(other)),
            format!("  ssh -N -R {LOCAL}:127.0.0.1:47102 root@{}", host(own)),
        ],
    );
    ui::note("Only the check's control messages go through your computer; every test tunnel still connects the servers directly, so each transport gets its real result.");
    crate::checker::control::set_control_via(Some(std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, LOCAL))));
    Ok(true)
}

/// Find or tune; then preset, priority and (for Custom) every option; then a summary to confirm.
fn choose_options(store: &Store, iran_ip: IpAddr, foreign_ip: IpAddr) -> Result<Option<Options>> {
    let modes = [checker::Mode::Find, checker::Mode::Tune];
    let items: Vec<String> = modes
        .iter()
        .map(|mode| format!("{}  {}", ui::bold(&format!("{:<16}", mode.label())), ui::dim(mode.description())))
        .collect();
    let Some(mode) = choose_or_back("What do you want to do?", &items, 0)? else {
        return Ok(None);
    };
    if modes[mode] == checker::Mode::Tune {
        let suggested = last_best(store, iran_ip, foreign_ip);
        return choose_tune(iran_ip, foreign_ip, suggested);
    }
    choose_find(iran_ip, foreign_ip)
}

/// The best transports of the newest find check between these two servers, if there is one.
fn last_best(store: &Store, iran_ip: IpAddr, foreign_ip: IpAddr) -> Vec<Transport> {
    for path in list_reports(&reports_dir(store)) {
        let Some(report) = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Report>(&bytes).ok())
        else {
            continue;
        };
        if report.options.mode == checker::Mode::Find
            && report.iran_ip == iran_ip.to_string()
            && report.foreign_ip == foreign_ip.to_string()
        {
            return checker::best_transports(&report.cases, report.options.priority, checker::TUNE_BEST);
        }
    }
    Vec::new()
}

/// What tuning a transport tries, for the picker: "browser TLS, TLS fragment, congestion".
fn tune_options_text(transport: Transport) -> String {
    let probe = Options { mode: checker::Mode::Tune, ..Options::default() };
    let labels: Vec<&str> = probe
        .variants(transport)
        .into_iter()
        .filter(|v| *v != checker::Variant::Plain)
        .map(checker::Variant::label)
        .collect();
    if labels.is_empty() {
        "directions only".into()
    } else {
        format!("default, {}", labels.join(", "))
    }
}

/// A tune check: which transports (the best ones of the last find check preselected), how deep and
/// what matters most; then the summary.
fn choose_tune(iran_ip: IpAddr, foreign_ip: IpAddr, suggested: Vec<Transport>) -> Result<Option<Options>> {
    if suggested.is_empty() {
        ui::note("Pick the transports that worked in a find check. Each one is checked with every option it has.");
    } else {
        ui::note("Preselected: the best transports of the last find check between these two servers.");
    }
    let listed: Vec<Transport> = CHECKABLE.to_vec();
    let items: Vec<String> = listed
        .iter()
        .map(|t| {
            let name = super::plan::transport_name(*t);
            match unavailable(*t, iran_ip, foreign_ip) {
                Some(reason) => format!("{name:<16}{}", ui::dim(&format!("not available: {reason}"))),
                None => format!("{name:<16}{}", ui::dim(&tune_options_text(*t))),
            }
        })
        .collect();
    let defaults: Vec<bool> = listed.iter().map(|t| suggested.contains(t)).collect();
    let transports = loop {
        let Some(chosen) = multi("Transports to tune", &items, &defaults)? else {
            return Ok(None);
        };
        let transports: Vec<Transport> = chosen
            .into_iter()
            .map(|i| listed[i])
            .filter(|t| unavailable(*t, iran_ip, foreign_ip).is_none())
            .collect();
        if transports.is_empty() {
            ui::warn("Choose at least one transport that can run here.");
            continue;
        }
        break transports;
    };
    let presets = [Preset::Quick, Preset::Standard, Preset::Thorough];
    let items: Vec<String> = presets
        .iter()
        .map(|preset| {
            let options = Options::tune(*preset, transports.clone());
            format!(
                "{}  {}  {}",
                ui::bold(&format!("{:<9}", preset.label())),
                ui::dim(&format!("{:<52}", preset.description())),
                ui::dim(&format!("{} cases · {}", options.cases().len(), about(options.estimate_seconds())))
            )
        })
        .collect();
    let Some(depth) = choose_or_back("How deep", &items, 1)? else {
        return Ok(None);
    };
    let mut options = Options::tune(presets[depth], transports);
    let Some(priority) = choose_priority()? else {
        return Ok(None);
    };
    options.priority = priority;
    confirm_options(options, iran_ip, foreign_ip)
}

/// A find check: preset, priority and (for Custom) every option; then the summary.
fn choose_find(iran_ip: IpAddr, foreign_ip: IpAddr) -> Result<Option<Options>> {
    let presets = [Preset::Quick, Preset::Standard, Preset::Thorough];
    let mut items: Vec<String> = presets
        .iter()
        .map(|preset| {
            let options = with_raw(Options::preset(*preset), iran_ip, foreign_ip);
            format!(
                "{}  {}  {}",
                ui::bold(&format!("{:<9}", preset.label())),
                ui::dim(&format!("{:<52}", preset.description())),
                ui::dim(&about(options.estimate_seconds()))
            )
        })
        .collect();
    items.push(format!(
        "{}  {}",
        ui::bold(&format!("{:<9}", "Custom")),
        ui::dim("choose transports, directions and every measurement")
    ));
    // This is a pure form: the caller can replay answers to reopen the previous
    // page without restarting listeners or losing draft answers.
    let options = {
        let Some(choice) = choose_or_back("What to check", &items, 1)? else {
            return Ok(None);
        };
        let mut options = with_raw(
            Options::preset(*presets.get(choice).unwrap_or(&Preset::Standard)),
            iran_ip,
            foreign_ip,
        );
        let Some(priority) = choose_priority()? else {
            return Ok(None);
        };
        options.priority = priority;
        if choice == 3 && !custom(&mut options, iran_ip, foreign_ip)? {
            return Ok(None);
        }
        options
    };
    confirm_options(options, iran_ip, foreign_ip)
}

/// The summary, with a way into every option, until the check starts or the operator goes back.
fn confirm_options(mut options: Options, iran_ip: IpAddr, foreign_ip: IpAddr) -> Result<Option<Options>> {
    loop {
        if let Err(error) = options.validate() {
            ui::fail(&format!("{error:#}"));
            if !custom(&mut options, iran_ip, foreign_ip)? {
                return Ok(None);
            }
            continue;
        }
        summary(&options);
        let actions = vec![
            ui::bold("Start the check").to_string(),
            "Change the options".to_string(),
        ];
        match choose_or_back("Ready", &actions, 0)? {
            Some(0) => return Ok(Some(options)),
            Some(1) => {
                // Esc keeps the options as they were.
                custom(&mut options, iran_ip, foreign_ip)?;
            }
            _ => return Ok(None),
        }
    }
}

fn choose_priority() -> Result<Option<Priority>> {
    let items: Vec<String> = Priority::ALL
        .iter()
        .map(|p| {
            format!(
                "{}  {}",
                ui::bold(&format!("{:<10}", p.label())),
                ui::dim(p.description())
            )
        })
        .collect();
    Ok(choose_or_back("What matters most in the results?", &items, 0)?.map(|i| Priority::ALL[i]))
}

/// The raw transports (fec-raw, raw TUN) are checked too when they can run here
/// (root and IPv4 addresses).
fn with_raw(mut options: Options, iran_ip: IpAddr, foreign_ip: IpAddr) -> Options {
    for transport in [Transport::FecRaw, Transport::Tun] {
        if unavailable(transport, iran_ip, foreign_ip).is_none()
            && !options.transports.contains(&transport)
        {
            options.transports.push(transport);
        }
    }
    options
}

/// Why a transport cannot be checked from here, for the list.
fn unavailable(transport: Transport, iran_ip: IpAddr, foreign_ip: IpAddr) -> Option<&'static str> {
    match transport {
        Transport::FecRaw | Transport::FecRawGaming | Transport::Tun
            if !super::store::is_root() =>
        {
            Some("needs root on both servers")
        }
        Transport::FecRaw | Transport::FecRawGaming | Transport::Tun
            if !(iran_ip.is_ipv4() && foreign_ip.is_ipv4()) =>
        {
            Some("needs IPv4 addresses")
        }
        Transport::Tcp6 if !(iran_ip.is_ipv6() && foreign_ip.is_ipv6()) => {
            Some("needs IPv6 addresses for both servers")
        }
        _ => None,
    }
}

/// A checklist: Enter turns the row under the cursor on or off; the last rows choose all or
/// none, finish, or go back. Returns the chosen rows, or `None` for "← Back" (or Esc).
fn multi(prompt: &str, items: &[String], defaults: &[bool]) -> Result<Option<Vec<usize>>> {
    if let Some(values) = ui::remembered_multi(prompt) {
        return Ok(Some(values));
    }
    let mut chosen = defaults.to_vec();
    chosen.resize(items.len(), false);
    let mut cursor = 0;
    let summary = |chosen: &[bool]| {
        items
            .iter()
            .zip(chosen)
            .filter(|(_, on)| **on)
            .map(|(item, _)| {
                let plain = console::strip_ansi_codes(item).into_owned();
                plain.split_whitespace().next().unwrap_or("").to_string()
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    loop {
        let mut rows: Vec<String> = items
            .iter()
            .zip(&chosen)
            .map(|(item, on)| {
                let mark = if *on {
                    style("[x]").green().to_string()
                } else {
                    ui::dim("[ ]")
                };
                format!("{mark} {item}")
            })
            .collect();
        rows.push(ui::dim("    all / none"));
        rows.push(ui::bold("    ✔ Done").to_string());
        rows.push(ui::dim("    ← Back"));
        let picked = dialoguer::Select::with_theme(&ui::theme())
            .with_prompt(format!(
                "{prompt}  {}",
                ui::dim("(Enter turns a row on or off)")
            ))
            .items(&rows)
            .default(cursor)
            .max_length(
                (ui::term().size().0 as usize)
                    .saturating_sub(10)
                    .clamp(8, 40),
            )
            .report(false)
            .interact_opt()?;
        match picked {
            Some(i) if i < items.len() => {
                chosen[i] = !chosen[i];
                cursor = i;
            }
            Some(i) if i == items.len() => {
                let all = chosen.iter().all(|on| *on);
                chosen.iter_mut().for_each(|on| *on = !all);
                cursor = i;
            }
            Some(i) if i == items.len() + 1 => {
                eprintln!(
                    "{} {} {} {}",
                    style("✔").for_stderr().green().bold(),
                    style(prompt).for_stderr().bold(),
                    style("·").for_stderr().dim(),
                    style(summary(&chosen)).for_stderr().cyan()
                );
                let values = chosen
                    .iter()
                    .enumerate()
                    .filter(|(_, on)| **on)
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>();
                ui::remember_multi(prompt, &values);
                return Ok(Some(values));
            }
            _ => return Ok(None),
        }
    }
}

fn ask_number(prompt: &str, default: u64, range: std::ops::RangeInclusive<u64>) -> Result<u64> {
    let text = ui::ask(
        prompt,
        Some(&default.to_string()),
        |text: &String| match text.trim().parse::<u64>() {
            Ok(value) if range.contains(&value) => Ok(()),
            _ => Err(format!(
                "enter a number from {} to {}",
                range.start(),
                range.end()
            )),
        },
    )?;
    Ok(text.trim().parse()?)
}

/// Every option by hand. Returns false, leaving `options` as it was, when Esc goes back.
fn custom(options: &mut Options, iran_ip: IpAddr, foreign_ip: IpAddr) -> Result<bool> {
    let mut edited = options.clone();
    if !custom_into(&mut edited, iran_ip, foreign_ip)? {
        return Ok(false);
    }
    *options = edited;
    Ok(true)
}

fn custom_into(options: &mut Options, iran_ip: IpAddr, foreign_ip: IpAddr) -> Result<bool> {
    ui::heading(
        "Transport checker · options",
        "every choice can be changed later",
    );
    // Transports
    let listed: Vec<Transport> = CHECKABLE.to_vec();
    let items: Vec<String> = listed
        .iter()
        .map(|t| {
            let name = super::plan::transport_name(*t);
            match unavailable(*t, iran_ip, foreign_ip) {
                Some(reason) => {
                    format!("{name:<16}{}", ui::dim(&format!("not available: {reason}")))
                }
                None => name,
            }
        })
        .collect();
    let defaults: Vec<bool> = listed
        .iter()
        .map(|t| options.transports.contains(t) && unavailable(*t, iran_ip, foreign_ip).is_none())
        .collect();
    let Some(chosen) = multi("Transports to check", &items, &defaults)? else {
        return Ok(false);
    };
    let mut transports = Vec::new();
    for index in chosen {
        let transport = listed[index];
        match unavailable(transport, iran_ip, foreign_ip) {
            Some(reason) => ui::warn(&format!(
                "{} left out: {reason}",
                super::plan::transport_name(transport)
            )),
            None => transports.push(transport),
        }
    }
    options.transports = transports;
    if options.transports.contains(&Transport::Tun) {
        let items: Vec<String> = checker::TUN_PROFILES
            .iter()
            .map(|p| checker::profile_name(*p).to_string())
            .collect();
        let defaults: Vec<bool> = checker::TUN_PROFILES
            .iter()
            .map(|p| options.tun_profiles.contains(p))
            .collect();
        let Some(chosen) = multi("Raw TUN packet types (one case each)", &items, &defaults)? else {
            return Ok(false);
        };
        options.tun_profiles = chosen
            .into_iter()
            .map(|i| checker::TUN_PROFILES[i])
            .collect();
    }
    // Directions
    let items = vec![
        format!(
            "Foreign dials  {}",
            ui::dim("the foreign server connects to the Iran server (reverse tunnel)")
        ),
        format!(
            "Iran dials     {}",
            ui::dim("the Iran server connects to the foreign server (direct tunnel)")
        ),
    ];
    let defaults = [
        options.dialers.contains(&Side::Foreign),
        options.dialers.contains(&Side::Iran),
    ];
    let Some(chosen) = multi("Directions", &items, &defaults)? else {
        return Ok(false);
    };
    options.dialers = chosen
        .into_iter()
        .map(|i| if i == 0 { Side::Foreign } else { Side::Iran })
        .collect();
    // Measurements, then the extra variants that apply to the chosen transports only.
    let chosen_has = |pick: fn(Transport) -> bool| options.transports.iter().any(|t| pick(*t));
    let any_tls = chosen_has(|t| t.uses_tls());
    let any_tcp = chosen_has(|t| {
        !crate::manager::plan::is_raw(t) && !crate::manager::plan::uses_udp(t)
    });
    let any_fec = chosen_has(|t| {
        matches!(t, Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming)
    });
    let any_tun = options.transports.contains(&Transport::Tun);
    let any_parallax = options.transports.contains(&Transport::Parallax);
    #[derive(Clone, Copy, PartialEq)]
    enum Pick {
        Ping,
        Download,
        Upload,
        Parallel,
        Hold,
        Mtu,
        Repeat,
        Udp,
        BrowserTls,
        TlsFragment,
        Congestion,
        Pacer,
        TunFragment,
        ParallaxPacket,
        Game,
    }
    let mut rows: Vec<(Pick, String, bool)> = vec![
        (Pick::Ping, format!("Ping              {}", ui::dim("short requests through the tunnel")), options.pings > 0),
        (Pick::Download, format!("Download speed    {}", ui::dim("foreign → Iran")), options.download),
        (Pick::Upload, format!("Upload speed      {}", ui::dim("Iran → foreign")), options.upload),
        (Pick::Parallel, format!("4 downloads       {}", ui::dim("four streams at once")), options.parallel),
        (Pick::Hold, format!("Stability hold    {}", ui::dim("a ping every 2 s for a while")), options.hold_sec > 0),
        (Pick::Mtu, format!("Baseline and MTU  {}", ui::dim("plain TCP/UDP and the largest packet, once")), options.mtu),
        (Pick::Repeat, format!("Repeat failures   {}", ui::dim("a failed case runs once more")), options.repeat_failed),
        (Pick::Udp, format!("UDP loss and delay {}", ui::dim("small UDP packets through the tunnel, idle and during the download")), options.udp),
    ];
    let find = options.mode == checker::Mode::Find;
    if find && any_tls {
        rows.push((Pick::BrowserTls, format!("Browser TLS       {}", ui::dim("also check TLS transports with a browser-like fingerprint")), options.browser_tls));
        rows.push((Pick::TlsFragment, format!("TLS fragment      {}", ui::dim("also check TLS transports with a split ClientHello")), options.tls_fragment));
    }
    if find && any_tcp {
        rows.push((Pick::Congestion, format!("TCP congestion A/B {}", ui::dim("also check TCP-based transports with tcp_congestion set to cubic")), options.also_congestion));
    }
    if find && any_fec {
        rows.push((Pick::Pacer, format!("Adaptive pacer     {}", ui::dim("also check fec-udp/fec-raw(-gaming) with the delay-based pacer on")), options.also_pacer));
    }
    if find && any_tun {
        rows.push((Pick::TunFragment, format!("TUN fragmentation  {}", ui::dim("also check raw TUN with packet splitting on and a too-big MTU")), options.also_fragment));
    }
    let any_game = chosen_has(|t| !crate::manager::plan::is_raw(t));
    if find && any_game {
        rows.push((Pick::Game, format!("Game mode          {}", ui::dim("also check with Game mode: game UDP as datagram copies")), options.also_game));
    }
    if find && any_parallax {
        rows.push((Pick::ParallaxPacket, format!("Parallax packet mode {}", ui::dim("also check Parallax with lanes and error correction")), options.parallax_packet));
    }
    let items: Vec<String> = rows.iter().map(|(_, label, _)| label.clone()).collect();
    let defaults: Vec<bool> = rows.iter().map(|(_, _, on)| *on).collect();
    let Some(chosen) = multi("Measurements", &items, &defaults)? else {
        return Ok(false);
    };
    let has = |pick: Pick| {
        rows.iter()
            .position(|(p, _, _)| *p == pick)
            .is_some_and(|i| chosen.contains(&i))
    };
    options.pings = if has(Pick::Ping) {
        ask_number("Pings per case", u64::from(options.pings.max(1)), 1..=100)? as u32
    } else {
        0
    };
    options.download = has(Pick::Download);
    options.upload = has(Pick::Upload);
    options.parallel = has(Pick::Parallel);
    if options.download || options.upload || options.parallel {
        options.speed_sec = ask_number(
            "Seconds per speed test",
            u64::from(options.speed_sec),
            1..=60,
        )? as u32;
    }
    options.hold_sec = if has(Pick::Hold) {
        ask_number(
            "Seconds of stability hold per case",
            u64::from(if options.hold_sec == 0 {
                30
            } else {
                options.hold_sec
            }),
            1..=600,
        )? as u32
    } else {
        0
    };
    options.mtu = has(Pick::Mtu);
    options.repeat_failed = has(Pick::Repeat);
    options.udp = has(Pick::Udp);
    if find {
        // A variant whose transports are not chosen is off, not silently kept.
        options.browser_tls = has(Pick::BrowserTls);
        options.tls_fragment = has(Pick::TlsFragment);
        options.also_congestion = has(Pick::Congestion);
        options.also_pacer = has(Pick::Pacer);
        options.also_fragment = has(Pick::TunFragment);
        options.parallax_packet = !any_parallax || has(Pick::ParallaxPacket);
        options.also_game = has(Pick::Game);
    } else {
        ui::note("A tune check runs every option each transport has; rounds repeat every case so one noisy run does not decide.");
        options.rounds = ask_number("Rounds of every case", u64::from(options.rounds), 1..=3)? as u8;
    }
    // Ports and thresholds
    ui::note("Some filters block by port: enter the port you plan to use, or 0 for the default.");
    options.tls_port = ask_number(
        "Port for TLS transports (0 = the first free of 443, 8443, 2053, 2083, 2087, 2096)",
        u64::from(options.tls_port),
        0..=65535,
    )? as u16;
    options.port = ask_number(
        "Port for the other transports (0 = ws/http/xhttp: the first free of 80, 8080, 8880, 2052, 2082, 2086, 2095; the rest: a free random port)",
        u64::from(options.port),
        0..=65535,
    )? as u16;
    options.control_port = ask_number(
        "Port for the checker's own connection (TCP, must be open between the servers)",
        u64::from(options.control_port),
        1..=65535,
    )? as u16;
    options.slow_mbps = ask_number(
        "Call a working transport slow below (Mbit/s)",
        u64::from(options.slow_mbps),
        0..=10_000,
    )? as u32;
    Ok(true)
}

fn summary(options: &Options) {
    let names: Vec<String> = options
        .transports
        .iter()
        .map(|t| {
            let name = super::plan::transport_name(*t);
            if *t == Transport::Tun {
                let profiles: Vec<&str> = options
                    .tun_profiles
                    .iter()
                    .map(|p| checker::profile_name(*p))
                    .collect();
                format!("{name} ({})", profiles.join("/"))
            } else {
                name
            }
        })
        .collect();
    let mut measures = Vec::new();
    if options.pings > 0 {
        measures.push(format!("{} pings", options.pings));
    }
    if options.download {
        measures.push(format!("download {} s", options.speed_sec));
    }
    if options.upload {
        measures.push(format!("upload {} s", options.speed_sec));
    }
    if options.parallel {
        measures.push(format!("4 downloads {} s", options.speed_sec));
    }
    if options.hold_sec > 0 {
        measures.push(format!("hold {} s", options.hold_sec));
    }
    if options.udp {
        measures.push("UDP loss and delay".into());
    }
    if options.mtu {
        measures.push("baseline + MTU".into());
    }
    let directions: Vec<&str> = options
        .dialers
        .iter()
        .map(|side| match side {
            Side::Foreign => "foreign dials",
            Side::Iran => "Iran dials",
        })
        .collect();
    let port = |port: u16, auto: &str| {
        if port == 0 {
            auto.to_string()
        } else {
            port.to_string()
        }
    };
    let cases = options.cases().len();
    ui::boxed(
        "Transport check",
        &[
            format!(
                "Check         {}{}",
                options.mode.label(),
                if options.rounds > 1 { format!(" · {} rounds of every case", options.rounds) } else { String::new() }
            ),
            format!("Transports    {}", names.join(", ")),
            format!("Directions    {}", directions.join(", ")),
            format!("Measurements  {}", measures.join(", ")),
            format!(
                "Ports         TLS {} · others {} · control {}",
                port(options.tls_port, "first free web port (443, 8443, 2053…)"),
                port(
                    options.port,
                    "HTTP: first free web port (80, 8080, 8880…), rest random"
                ),
                options.control_port
            ),
            format!("Ranking       {}", options.priority.label().to_lowercase()),
            format!(
                "Cases         {cases} · about {} if everything works",
                about(options.estimate_seconds())
            ),
        ],
    );
}

// ---------------------------------------------------------------------------------------------
// Live view

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// While a check runs, Ctrl+C stops the check (with cleanup) instead of leaving the program.
fn catch_interrupt() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    #[cfg(target_os = "linux")]
    {
        extern "C" fn flag(_: libc::c_int) {
            INTERRUPTED.store(true, Ordering::SeqCst);
        }
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
        unsafe {
            libc::signal(libc::SIGINT, flag as *const () as libc::sighandler_t);
        }
    }
}

struct Screen {
    term: Term,
    drawn: usize,
    selected: Option<usize>,
    show_log: bool,
    show_details: bool,
    confirm_stop: Option<Instant>,
    message: Option<(String, Instant)>,
}

impl Screen {
    fn draw(&mut self, view: &View, me: Side, started: Instant) {
        let (rows, cols) = self.term.size();
        let width = (cols as usize).saturating_sub(1).max(40);
        let mut lines = Vec::new();
        let status = if view.finished {
            style("✔ finished").green().to_string()
        } else if !view.connected {
            style("◌ waiting for the other server").yellow().to_string()
        } else if view.paused {
            style("⏸ paused").yellow().to_string()
        } else if view.pause_requested {
            style("⏸ pausing after this step").yellow().to_string()
        } else {
            style("● running").green().to_string()
        };
        let elapsed = if view.elapsed_sec > 0 {
            view.elapsed_sec
        } else {
            started.elapsed().as_secs()
        };
        lines.push(format!(
            "  {}   Iran {} ⇄ foreign {}   {}  {} / ~{} left   {}",
            style("Transport checker").bold(),
            view.iran_ip,
            view.foreign_ip,
            status,
            fmt_duration(elapsed),
            fmt_duration(view.remaining_sec),
            style(format!("· you: {}", me.label())).dim()
        ));
        lines.push(format!(
            "  {}",
            style("─".repeat(width.saturating_sub(2))).dim()
        ));
        lines.push(
            style(format!("   {}  Result", checker::table_header()))
                .bold()
                .to_string(),
        );
        // Rows that fit, around the selected (or running) one. The fixed lines around the table
        // (title, two dividers, step, keys) are 6; up to two more are conditional (the "… N
        // cases" scroll indicator, the baseline line) and not always shown, so budget for both to
        // stay clear of them. Capped well under the terminal's height too: this printed region
        // sits below whatever was already printed above it (the check code and instructions), which
        // `rows` knows nothing about, so claiming the terminal's full height here can still overflow
        // the real remaining space and make the terminal scroll - and a scroll strands whatever
        // this function clears-and-redraws every frame as permanent, growing scrollback, since a
        // relative cursor-up can't reach content that has already scrolled out of the viewport.
        let log_lines = if self.show_log { 8 } else { 0 };
        let detail_lines = if self.show_details { 6 } else { 0 };
        let room = (rows as usize)
            .saturating_sub(9 + log_lines + detail_lines)
            .clamp(3, 15);
        let focus = self
            .selected
            .or_else(|| {
                view.current
                    .and_then(|id| view.rows.iter().position(|r| r.spec.id == id))
            })
            .unwrap_or(0);
        let first = focus
            .saturating_sub(room / 2)
            .min(view.rows.len().saturating_sub(room));
        for (index, row) in view.rows.iter().enumerate().skip(first).take(room) {
            let running = view.current == Some(row.spec.id);
            let marker = if self.selected == Some(index) {
                style("›").cyan().bold().to_string()
            } else if running {
                style("▸").cyan().to_string()
            } else {
                " ".into()
            };
            lines.push(format!(" {marker} {}", row_line(row, running, view)));
        }
        if view.rows.len() > room {
            lines.push(
                style(format!("   … {} cases; ↑/↓ to scroll", view.rows.len()))
                    .dim()
                    .to_string(),
            );
        }
        if let Some(baseline) = &view.baseline {
            lines.push(
                style(format!(
                    "   baseline: plain TCP {}, UDP loss {}, path MTU {}",
                    if baseline.tcp { "ok" } else { "failed" },
                    baseline
                        .udp_loss_percent
                        .map_or("-".into(), |l| format!("{l:.0} %")),
                    baseline.path_mtu.map_or("-".into(), |m| m.to_string()),
                ))
                .dim()
                .to_string(),
            );
        }
        lines.push(format!(
            "  {}",
            style("─".repeat(width.saturating_sub(2))).dim()
        ));
        if self.show_details
            && let Some(row) = self.selected.and_then(|i| view.rows.get(i)).or_else(|| {
                view.current
                    .and_then(|id| view.rows.iter().find(|r| r.spec.id == id))
            })
        {
            lines.extend(details(row));
        }
        if self.show_log {
            for line in logbuf::tail(log_lines) {
                lines.push(format!("  {}", style(line).dim()));
            }
        }
        let step = match &self.message {
            Some((text, at)) if at.elapsed() < Duration::from_secs(3) => {
                style(text.clone()).yellow().to_string()
            }
            _ => view.step.clone(),
        };
        lines.push(format!("  {} {step}", style("▸").cyan()));
        if let Some(hint) = view.path_hint.as_ref().filter(|_| !view.connected) {
            lines.push(format!("  {}", style(hint).yellow()));
        }
        let keys = if view.finished {
            "press any key for the results".to_string()
        } else if self.confirm_stop.is_some() {
            "press q again to stop the check (any other key continues)".to_string()
        } else {
            format!(
                "[{}] {}  [s] skip case  [l] log  [d] details  [↑↓] select  [q] stop",
                if view.paused || view.pause_requested {
                    "r"
                } else {
                    "p"
                },
                if view.paused || view.pause_requested {
                    "resume"
                } else {
                    "pause"
                }
            )
        };
        lines.push(format!("  {}", style(keys).dim()));
        let _ = self.term.clear_last_lines(self.drawn);
        for line in &lines {
            let _ = self
                .term
                .write_line(&console::truncate_str(line, width, "…"));
        }
        self.drawn = lines.len();
    }
}

fn verdict_style(verdict: Verdict) -> String {
    let label = verdict.label();
    match verdict {
        Verdict::Works => style(format!("✔ {label}")).green().to_string(),
        Verdict::Reachable => style(format!("✔ {label}")).cyan().to_string(),
        Verdict::Unstable | Verdict::Slow => style(format!("✔ {label}")).yellow().to_string(),
        Verdict::NotPossible | Verdict::Skipped | Verdict::Stopped => {
            style(format!("– {label}")).dim().to_string()
        }
        _ => style(format!("✘ {label}")).red().to_string(),
    }
}

fn row_line(row: &CaseResult, running: bool, view: &View) -> String {
    let result = match row.verdict {
        Some(verdict) => {
            let mut text = verdict_style(verdict);
            if let Some(note) = &row.note {
                text.push_str(&style(format!(" ({note})")).dim().to_string());
            }
            text
        }
        None if running => {
            let step = view.step.rsplit(" · ").next().unwrap_or("").to_string();
            style(format!("… {step}")).cyan().to_string()
        }
        None => style("waiting").dim().to_string(),
    };
    format!("{}  {result}", checker::table_cells(row))
}

fn details(row: &CaseResult) -> Vec<String> {
    let mut lines = vec![format!(
        "  {} · {} dials · port {} · runs {} ({} failed) · tunnel heartbeats {}/{}",
        style(row.spec.transport_name()).bold(),
        row.spec.dialer_label(),
        row.port.map_or("-".into(), |p| p.to_string()),
        row.runs,
        row.failed_runs,
        row.heartbeats.1,
        row.heartbeats.0
    )];
    let transfer = |name: &str, t: &Option<checker::Transfer>| {
        t.as_ref().map(|t| {
            format!(
                "  {name}: {:.1} Mbit/s, {} bytes{}",
                t.mbps,
                t.bytes,
                t.error
                    .as_ref()
                    .map_or(String::new(), |e| format!(" · {e}"))
            )
        })
    };
    lines.extend(transfer("download", &row.download));
    lines.extend(transfer("upload", &row.upload));
    lines.extend(transfer("4 downloads", &row.parallel));
    if let Some(hold) = &row.hold {
        lines.push(format!(
            "  hold: {} pings, {} failed, {} reconnects",
            hold.pings, hold.failures, hold.reconnects
        ));
    }
    if let Some(note) = &row.note {
        lines.push(format!("  note: {note}"));
    }
    lines.truncate(6);
    lines
}

/// Runs this server's part and shows the live view until the check ends.
fn watch(store: &Store, code: CheckCode, me: Side) -> Result<()> {
    let handle = run::spawn(code.clone(), me);
    let term = Term::stderr();
    let _ = term.hide_cursor();
    catch_interrupt();
    let (keys_tx, keys) = mpsc::channel::<Key>();
    let done = Arc::new(AtomicBool::new(false));
    {
        let done = done.clone();
        let term = term.clone();
        std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let Ok(key) = term.read_key() else { break };
                if keys_tx.send(key).is_err() || done.load(Ordering::SeqCst) {
                    break;
                }
            }
        });
    }
    let started = Instant::now();
    let mut screen = Screen {
        term: term.clone(),
        drawn: 0,
        selected: None,
        show_log: false,
        show_details: false,
        confirm_stop: None,
        message: None,
    };
    let send = |command: Command| {
        let _ = handle.commands.send(command);
    };
    let mut asked_stop = false;
    loop {
        let view = handle.view.borrow().clone();
        screen.draw(&view, me, started);
        if handle.task.is_finished() {
            break;
        }
        if INTERRUPTED.swap(false, Ordering::SeqCst) && !asked_stop {
            asked_stop = true;
            send(Command::Stop);
            screen.message = Some((
                "stopping: removing the test tunnels…".into(),
                Instant::now(),
            ));
        }
        match keys.recv_timeout(Duration::from_millis(250)) {
            Ok(Key::CtrlC) => {
                asked_stop = true;
                send(Command::Stop);
                screen.message = Some((
                    "stopping: removing the test tunnels…".into(),
                    Instant::now(),
                ));
            }
            Ok(Key::Char('q') | Key::Escape) => {
                if screen
                    .confirm_stop
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(5))
                {
                    screen.confirm_stop = None;
                    asked_stop = true;
                    send(Command::Stop);
                    screen.message = Some((
                        "stopping: removing the test tunnels…".into(),
                        Instant::now(),
                    ));
                } else {
                    screen.confirm_stop = Some(Instant::now());
                }
            }
            Ok(key) => {
                screen.confirm_stop = None;
                match key {
                    Key::Char('p') => {
                        send(Command::Pause);
                        screen.message =
                            Some(("pausing after the current step".into(), Instant::now()));
                    }
                    Key::Char('r') => send(Command::Resume),
                    Key::Char('s') => {
                        send(Command::Skip);
                        screen.message = Some(("skipping this case".into(), Instant::now()));
                    }
                    Key::Char('l') => screen.show_log = !screen.show_log,
                    Key::Char('d') => screen.show_details = !screen.show_details,
                    Key::ArrowUp => {
                        let last = view.rows.len().saturating_sub(1);
                        screen.selected =
                            Some(screen.selected.map_or(last, |i| i.saturating_sub(1)));
                    }
                    Key::ArrowDown => {
                        screen.selected = Some(
                            screen
                                .selected
                                .map_or(0, |i| (i + 1).min(view.rows.len().saturating_sub(1))),
                        );
                    }
                    Key::Enter if screen.selected.is_some() => {
                        screen.show_details = !screen.show_details
                    }
                    _ => {}
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {}
        }
    }
    // The task has ended; take its result.
    let outcome = futures_util::FutureExt::now_or_never(handle.task)
        .context("the check did not end")?
        .context("the check failed")?;
    let mut final_view = handle.view.borrow().clone();
    final_view.finished = true;
    screen.draw(&final_view, me, started);
    super::ui::exit_on_interrupt();
    // The key reader takes one more key, then ends.
    done.store(true, Ordering::SeqCst);
    let _ = keys.recv_timeout(Duration::from_secs(600));
    let _ = term.show_cursor();
    match outcome {
        Ok(report) => {
            let saved = save(store, &report);
            results(store, &report, me, saved.as_ref().ok())?;
            if let Err(error) = saved {
                ui::warn(&format!("The report could not be saved: {error:#}"));
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

// ---------------------------------------------------------------------------------------------
// Results and reports

fn results(store: &Store, report: &Report, me: Side, saved: Option<&PathBuf>) -> Result<()> {
    {
        ui::banner("Transport check result");
        let counted = |f: fn(Verdict) -> bool| {
            report
                .cases
                .iter()
                .filter(|c| c.verdict.is_some_and(f))
                .count()
        };
        eprintln!(
            "  {} cases · {} · {} · {}",
            report.cases.len(),
            style(format!("{} work", counted(Verdict::usable))).green(),
            style(format!("{} blocked", counted(Verdict::failed))).red(),
            style(format!(
                "{} not run",
                report.cases.len() - counted(Verdict::usable) - counted(Verdict::failed)
            ))
            .dim()
        );
        if let Some(reason) = &report.stopped {
            ui::warn(&format!("The check stopped early: {reason}"));
        }
        eprintln!();
        eprintln!(
            "{}",
            style(format!("   {}  Result", checker::table_header())).bold()
        );
        let idle = View::default();
        for row in &report.cases {
            eprintln!("   {}", row_line(row, false, &idle));
        }
        if report
            .cases
            .iter()
            .any(|c| c.verdict == Some(Verdict::Reachable))
        {
            eprintln!();
            ui::note(checker::REACHABLE_NOTE);
        }
        if report.options.mode == checker::Mode::Tune {
            return tune_results(store, report, me, saved);
        }
        let ranked = checker::rank(&report.cases, report.options.priority);
        eprintln!();
        if ranked.is_empty() {
            ui::warn("No transport carried data between these servers.");
        } else {
            eprintln!(
                "  {}",
                style(format!(
                    "Best for this pair ({})",
                    report.options.priority.label().to_lowercase()
                ))
                .bold()
            );
            for (index, case) in ranked.iter().take(3).enumerate() {
                eprintln!(
                    "   {}. {} · {} dials   {}   ping {} ms   {}",
                    index + 1,
                    style(case.spec.transport_name()).cyan().bold(),
                    case.spec.dialer_label(),
                    match (&case.download, &case.upload) {
                        (Some(d), Some(u)) if d.ok() && u.ok() =>
                            format!("{:.0} / {:.0} Mbit/s", d.mbps, u.mbps),
                        _ => String::new(),
                    },
                    case.ping
                        .as_ref()
                        .map_or("-".into(), |p| checker::fmt_ms(p.median_ms)),
                    case.verdict.map_or("", Verdict::label)
                );
            }
        }
        let blocked: Vec<String> = report
            .cases
            .iter()
            .filter(|c| c.verdict.is_some_and(Verdict::failed))
            .map(|c| {
                format!(
                    "{} ({} dials): {}",
                    c.spec.transport_name(),
                    c.spec.dialer_label(),
                    c.verdict.map_or("", Verdict::label)
                )
            })
            .collect();
        if !blocked.is_empty() {
            eprintln!();
            eprintln!("  {}", style("Blocked on this path").bold());
            for line in blocked {
                eprintln!("   {}", style(line).red());
            }
        }
        if let Some(path) = saved {
            eprintln!();
            ui::note(&format!(
                "Saved: {} (and .txt). Tools → Transport checker → Past checks.",
                path.display()
            ));
        }
        let mut actions: Vec<String> = ranked
            .iter()
            .take(3)
            .map(|c| {
                format!(
                    "Create a tunnel with {} · {} dials",
                    c.spec.transport_name(),
                    c.spec.dialer_label()
                )
            })
            .collect();
        let failed: Vec<Transport> = report
            .cases
            .iter()
            .filter(|c| {
                c.verdict
                    .is_some_and(|v| v.failed() || v == Verdict::Stopped)
            })
            .map(|c| c.spec.transport)
            .collect();
        let rerun = !failed.is_empty();
        if rerun {
            actions.push("Check the failed transports again (new code)".into());
        }
        let best = checker::best_transports(&report.cases, report.options.priority, checker::TUNE_BEST);
        let tune_row = (!best.is_empty()).then(|| {
            let names: Vec<String> = best.iter().map(|t| super::plan::transport_name(*t)).collect();
            actions.push(format!(
                "Tune the best {}: {} with every option (new code)",
                best.len(),
                names.join(", ")
            ));
            actions.len() - 1
        });
        actions.push(ui::dim("← Back"));
        let Some(choice) = ui::choose("Next", &actions, 0)? else {
            return Ok(());
        };
        let tunnels = ranked.len().min(3);
        if choice < tunnels {
            create_from(store, report, me, ranked[choice])?;
            return Ok(());
        }
        if Some(choice) == tune_row {
            let mut options = report.options.clone();
            options.mode = checker::Mode::Tune;
            options.rounds = checker::TUNE_ROUNDS;
            options.transports = best;
            options.repeat_failed = false;
            return new_check(store, report, me, options);
        }
        if rerun && choice == tunnels {
            let mut options = report.options.clone();
            options.transports.retain(|t| failed.contains(t));
            options.repeat_failed = true;
            return new_check(store, report, me, options);
        }
    }
    Ok(())
}

/// Starts a follow-up check between the same two servers and shows its code for the other one.
fn new_check(store: &Store, report: &Report, me: Side, options: Options) -> Result<()> {
    let iran_ip = report.iran_ip.parse()?;
    let foreign_ip = report.foreign_ip.parse()?;
    let code = CheckCode::new(me, iran_ip, foreign_ip, options)?;
    summary(&code.options);
    eprintln!();
    eprintln!("{}", ui::accent(&code::encode(&code)?));
    eprintln!();
    ui::note("Join this new check on the other server.");
    watch(store, code, me)
}

/// The end of a tune check: every transport with its options best first, averaged over the
/// rounds, and a tunnel one step away for the best option of each.
fn tune_results(store: &Store, report: &Report, me: Side, saved: Option<&PathBuf>) -> Result<()> {
    let groups = checker::tune_summary(&report.cases, report.options.priority);
    eprintln!();
    if groups.iter().all(|g| g.rows[0].usable == 0) {
        ui::warn("No option of these transports carried data between these servers.");
    } else {
        eprintln!(
            "  {}",
            style(format!(
                "Best option per transport ({}, {} rounds each)",
                report.options.priority.label().to_lowercase(),
                report.options.rounds
            ))
            .bold()
        );
        eprintln!(
            "   {}",
            style(format!(
                "  {:<16} {:<9} {:>7} {:>16} {:>9} {:>9}",
                "option", "dials", "works", "↓ / ↑ Mbit/s", "ping ms", "UDP loss"
            ))
            .dim()
        );
        for group in &groups {
            eprintln!("   {}", style(group.name()).cyan().bold());
            for (index, row) in group.rows.iter().enumerate() {
                let speed = row.speed_text();
                let line = format!(
                    "{} {:<16} {:<9} {:>7} {:>16} {:>9} {:>9}",
                    if index == 0 && row.usable > 0 { "★" } else { " " },
                    row.option_label(),
                    row.dialer.map_or("both", Side::label),
                    format!("{}/{}", row.usable, row.rounds),
                    speed,
                    checker::fmt_ms(row.ping_ms),
                    row.udp_loss.map_or("-".into(), |v| format!("{v:.0} %"))
                );
                let styled = if row.usable == 0 {
                    style(line).red().to_string()
                } else if index == 0 {
                    style(line).green().to_string()
                } else {
                    line
                };
                eprintln!("     {styled}");
            }
        }
    }
    if let Some(path) = saved {
        eprintln!();
        ui::note(&format!(
            "Saved: {} (and .txt). Tools → Transport checker → Past checks.",
            path.display()
        ));
    }
    let winners: Vec<&CaseResult> = groups
        .iter()
        .filter_map(|g| g.rows.first())
        .filter_map(|row| row.case_id)
        .filter_map(|id| report.cases.iter().find(|c| c.spec.id == id))
        .take(3)
        .collect();
    let mut actions: Vec<String> = winners
        .iter()
        .map(|c| {
            let option = match c.spec.variant {
                checker::Variant::Plain => "default settings".to_string(),
                variant => variant.label().to_string(),
            };
            let mut name = c.spec;
            name.variant = checker::Variant::Plain;
            name.round = 0;
            format!(
                "Create a tunnel with {} · {option} · {} dials",
                name.transport_name(),
                c.spec.dialer_label()
            )
        })
        .collect();
    actions.push(ui::dim("← Back"));
    let Some(choice) = ui::choose("Next", &actions, 0)? else {
        return Ok(());
    };
    if let Some(case) = winners.get(choice) {
        create_from(store, report, me, case)?;
    }
    Ok(())
}

fn create_from(store: &Store, report: &Report, me: Side, case: &CaseResult) -> Result<()> {
    let side = match me {
        Side::Iran => PlanSide::Iran,
        Side::Foreign => PlanSide::Foreign,
    };
    let direction = match case.spec.dialer {
        Some(Side::Iran) => Direction::Direct,
        _ => Direction::Reverse,
    };
    // An IPv6 case makes an IPv6 tunnel, on the other server's IPv6 address.
    let other = match (me, case.spec.ipv6) {
        (Side::Iran, false) => &report.foreign_ip,
        (Side::Foreign, false) => &report.iran_ip,
        (Side::Iran, true) => report.foreign_ip6.as_ref().unwrap_or(&report.foreign_ip),
        (Side::Foreign, true) => report.iran_ip6.as_ref().unwrap_or(&report.iran_ip),
    };
    ui::note("Create the tunnel here; the pairing code at the end sets up the other server.");
    wizard::new_tunnel_with(
        store,
        Some(wizard::Prefill {
            side,
            direction,
            transport: case.spec.transport,
            port: case.port,
            peer_host: Some(other.clone()),
            ipv6: case.spec.ipv6,
            tested:Some(case.spec),
        }),
    )?;
    Ok(())
}

fn reports_dir(store: &Store) -> PathBuf {
    if store.system {
        PathBuf::from("/var/lib/eztunnel/checks")
    } else {
        store.root().join("checks")
    }
}

/// Year, month, day, hour, minute of a Unix time (UTC), for file names and lists.
pub(super) fn civil(seconds: u64) -> (i64, u32, u32, u32, u32) {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // Howard Hinnant's days-to-civil algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, (rest / 3600) as u32, (rest / 60 % 60) as u32)
}

const KEEP_REPORTS: usize = 20;

fn save(store: &Store, report: &Report) -> Result<PathBuf> {
    let dir = reports_dir(store);
    // A report holds exactly what the checker exists to keep hidden: both servers' addresses
    // and which transports are blocked between them. Private like the tunnel configs, not world
    // readable like a plain `create_dir_all`/`fs::write` would leave it.
    super::store::create_private_dir(&dir)?;
    let (y, mo, d, h, mi) = civil(report.started);
    let stem = format!(
        "check-{y:04}{mo:02}{d:02}-{h:02}{mi:02}{:02}",
        report.started % 60
    );
    let json = dir.join(format!("{stem}.json"));
    super::store::write_private(&json, &serde_json::to_vec_pretty(report)?)?;
    super::store::write_private(&dir.join(format!("{stem}.txt")), report.text().as_bytes())?;
    // Keep the newest reports only.
    let mut all = list_reports(&dir);
    if all.len() > KEEP_REPORTS {
        for old in all.drain(KEEP_REPORTS..) {
            let _ = std::fs::remove_file(&old);
            let _ = std::fs::remove_file(old.with_extension("txt"));
        }
    }
    Ok(json)
}

/// Saved reports, newest first.
fn list_reports(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|e| e == "json")
                        && p.file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with("check-"))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files.reverse();
    files
}

fn past(store: &Store) -> Result<()> {
    loop {
        ui::banner("Transport checker · past checks");
        let files = list_reports(&reports_dir(store));
        let reports: Vec<(PathBuf, Report)> = files
            .into_iter()
            .filter_map(|path| {
                let report = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
                Some((path, report))
            })
            .collect();
        if reports.is_empty() {
            ui::info("No checks saved on this server yet.");
            ui::pause();
            return Ok(());
        }
        let mut items: Vec<String> = reports
            .iter()
            .map(|(_, report)| {
                let (y, mo, d, h, mi) = civil(report.started);
                let works = report
                    .cases
                    .iter()
                    .filter(|c| c.verdict.is_some_and(Verdict::usable))
                    .count();
                format!(
                    "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02} UTC  Iran {} ⇄ foreign {}  {}",
                    report.iran_ip,
                    report.foreign_ip,
                    ui::dim(&format!("{works} of {} work", report.cases.len()))
                )
            })
            .collect();
        items.push(ui::dim("← Back"));
        let Some(choice) = ui::choose("Report", &items, 0)? else {
            return Ok(());
        };
        let Some((path, report)) = reports.get(choice) else {
            return Ok(());
        };
        let me = if let Ok(ip) = report.iran_ip.parse::<IpAddr>()
            && std::net::UdpSocket::bind((ip, 0)).is_ok()
        {
            Side::Iran
        } else {
            Side::Foreign
        };
        results(store, report, me, Some(path))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1, 0, 0));
        // 2026-10-12 15:03 UTC
        assert_eq!(civil(1_791_817_380), (2026, 10, 12, 15, 3));
        assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0));
    }

    #[test]
    fn unavailable_transports_say_why() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        if super::super::store::is_root() {
            assert!(unavailable(Transport::Tun, v4, other).is_none());
        } else {
            assert_eq!(unavailable(Transport::Tun, v4, other), Some("needs root on both servers"));
        }
        assert_eq!(unavailable(Transport::Tun, "::1".parse().unwrap(), other), Some(if super::super::store::is_root() { "needs IPv4 addresses" } else { "needs root on both servers" }));
        assert!(unavailable(Transport::Tcp6, v4, other).is_some());
        assert!(unavailable(Transport::Tcp, v4, other).is_none());
        assert!(fmt_duration(3725).starts_with("1:02"));
        assert_eq!(about(30), "~30 s");
        assert_eq!(about(600), "~10 min");
    }
}
