//! "Customize" screens: transport options and every numeric limit, each with its default.
use super::plan::{IpMode, Plan, apply_setting, check, is_raw, is_xhttp, read_setting};
use super::scope::{self, Scope, Section};
use super::speed::{self, SpeedMode};
use super::ui;
use crate::config::{Mode, Transport, XhttpMode};
use crate::settings::Setting;
use anyhow::Result;
use serde_json::Value;

enum Item {
    Pool,
    HttpPath,
    Sni,
    XhttpMode,
    TlsFragment,
    TlsProfile,
    LocalAddress,
    ListenIp,
    PublicIp,
    IpMode,
    Interface,
    LocalIp,
    Mirage,
    TunMtu,
    TunName,
    Speed,
    Game,
    Group(Section),
    Done,
}

fn value_text(current: Option<u64>, setting: &Setting) -> String {
    match (current, setting.default.as_u64()) {
        (Some(value), _) => ui::yellow(&format!("{value} {}", setting.unit)),
        (None, Some(default)) => format!("{default} {}", setting.unit),
        (None, None) => "off".into(),
    }
}

/// The settings of each group that has any, in screen order.
fn groups(settings: &[Setting]) -> Vec<(Section, Vec<Setting>)> {
    Section::ALL
        .iter()
        .filter_map(|section| {
            let list: Vec<Setting> = settings
                .iter()
                .filter(|s| scope::section(s) == *section)
                .cloned()
                .collect();
            (!list.is_empty()).then_some((*section, list))
        })
        .collect()
}

/// The row that opens one group: its title, how many settings it has and how many are changed.
fn group_label(section: Section, scope: &Scope, count: usize, changed: usize) -> String {
    let detail = if changed > 0 {
        format!(
            "{count} {} · {}",
            if count == 1 { "setting" } else { "settings" },
            ui::yellow(&format!("{changed} changed"))
        )
    } else {
        format!("{count} {}", if count == 1 { "setting" } else { "settings" })
    };
    format!("{:<38} {detail}", format!("▸ {}", section.title(scope)))
}

/// One group's settings: choose one to change, until Back. `read` and `write` reach the value
/// wherever this screen keeps it (the wizard's answers or a saved file).
fn edit_group<T>(
    section: Section,
    scope: &Scope,
    settings: &[Setting],
    state: &mut T,
    read: fn(&T, &Setting) -> Option<u64>,
    write: fn(&mut T, &Setting, Option<u64>) -> Result<()>,
) -> Result<()> {
    let mut cursor = 0;
    loop {
        ui::heading(&section.title(scope), section.detail());
        let changed = settings.iter().filter(|s| read(state, s).is_some()).count();
        let mut labels: Vec<String> = settings
            .iter()
            .map(|s| format!("{:<38} {}", s.name, value_text(read(state, s), s)))
            .collect();
        let reset = (changed > 0).then(|| {
            labels.push(ui::red(&format!("↺ Put the {changed} changed back to the defaults")));
            labels.len() - 1
        });
        let Some(choice) = ui::choose("Change", &labels, cursor)? else {
            return Ok(());
        };
        if Some(choice) == reset {
            for setting in settings {
                if read(state, setting).is_some() {
                    write(state, setting, None)?;
                }
            }
            cursor = 0;
            continue;
        }
        cursor = choice;
        let setting = &settings[choice];
        match ask_number(setting, read(state, setting)) {
            Ok(Some(value)) => write(state, setting, value)?,
            Ok(None) => {}
            Err(error) if ui::is_back(&error) => {}
            Err(error) => return Err(error),
        }
    }
}

fn plan_value(plan: &Plan, setting: &Setting) -> Option<u64> {
    plan.tuned
        .iter()
        .find(|(s, _)| s.name == setting.name && s.place == setting.place)
        .map(|(_, v)| *v)
}

fn set_plan_value(plan: &mut Plan, setting: &Setting, value: Option<u64>) -> Result<()> {
    plan.tuned
        .retain(|(s, _)| !(s.name == setting.name && s.place == setting.place));
    if let Some(value) = value {
        plan.tuned.push((setting.clone(), value));
    }
    Ok(())
}

fn file_value(config: &Value, setting: &Setting) -> Option<u64> {
    read_setting(config, setting)
}

fn set_file_value(config: &mut Value, setting: &Setting, value: Option<u64>) -> Result<()> {
    apply_setting(config, setting, value)
}

/// Asks what the TLS client of the dialing side looks like. `None` keeps the current choice.
fn ask_tls_profile(
    current: crate::config::TlsProfile,
) -> Result<Option<crate::config::TlsProfile>> {
    use crate::config::TlsProfile;
    ui::note(
        "How this side's TLS handshake looks to a network that watches it.\n  classic  this program's own TLS client (the same as in earlier versions)\n  chrome   the handshake of a current Chrome: its cipher suites, extensions, groups and\n           signature algorithms, GREASE values, a different extension order each time\nBoth servers need this release or a later one. Check what is sent with:  eztunnel tlscheck",
    );
    if !cfg!(feature = "browser-tls") {
        ui::warn("This build was made without the browser-tls feature: only classic is available.");
        return Ok(None);
    }
    let labels = vec![
        "classic  this program's own TLS client".to_string(),
        "chrome   looks like Chrome".to_string(),
    ];
    let current_index = usize::from(current == TlsProfile::Chrome);
    let picked = ui::choose_required("TLS look", &labels, current_index)?;
    let profile = if picked == 1 {
        TlsProfile::Chrome
    } else {
        TlsProfile::Classic
    };
    Ok((profile != current).then_some(profile))
}

/// Asks which of this server's own addresses the dialing side connects from. `None` means the
/// system's choice.
fn ask_local_address(current: Option<&str>) -> Result<Option<String>> {
    ui::note(
        "Only for a server with more than one IP address: the tunnel connects out from this
address instead of the one the system picks. It must be an address of this server.",
    );
    let text = ui::ask(
        "Connect from address ('auto' = the system's choice)",
        Some(current.unwrap_or("auto")),
        |t: &String| {
            if t == "auto" {
                return Ok(());
            }
            crate::config::parse_local_address(t)
                .map(|_| ())
                .map_err(|e| e.to_string())
        },
    )?;
    Ok((text != "auto").then_some(text))
}

/// C46: only a non-fragmenting raw TUN tunnel must fit each inner packet into one outer
/// packet; with authenticated fragmentation the configuration bound applies.
fn single_packet_cap(transport: Transport, fragment: bool) -> bool {
    transport == Transport::Tun && !fragment
}

/// The largest TUN MTU the editor accepts: the configuration maximum, narrowed by the
/// single-packet room when that applies.
fn mtu_limit(max: Option<&(usize, String, u32)>) -> usize {
    max.map_or(9000, |(room, _, _)| (*room).min(9000))
}

/// Asks for the TUN MTU of a saved tunnel. `max` is the largest value that fits through the
/// interface of a raw tunnel (it would not start with more).
fn ask_tun_mtu(current: u64, max: Option<(usize, String, u32)>) -> Result<Option<u16>> {
    let limit = mtu_limit(max.as_ref());
    if limit < 576 {
        // 576..=limit would be empty: every answer would be rejected, with no way out of the
        // prompt. The interface cannot carry a valid TUN MTU at all, so there is only one
        // sensible value to offer - the most this interface can fit, not a range to choose from.
        let (_, interface, mtu) = max
            .as_ref()
            .expect("limit is only below the 576 floor when max narrowed it there");
        ui::warn(&format!(
            "Interface {interface} has MTU {mtu}, so only {limit} fits through it - too small for \
             a valid TUN MTU (576 or more). The TUN MTU is set to {limit}; a larger interface MTU \
             is needed to raise it."
        ));
        let value = limit as u16;
        return Ok((u64::from(value) != current).then_some(value));
    }
    ui::note(
        "The size of the largest IP packet the virtual network carries. Smaller is safer on a path with a small MTU; larger moves more data per packet.",
    );
    match &max {
        Some((room, interface, mtu)) => ui::note(&format!(
            "Interface {interface} has MTU {mtu}, so up to {room} fits through it. The usual value is 1400."
        )),
        None => ui::note("Allowed 576 to 9000. The usual value is 1400."),
    }
    let text = ui::ask(
        "TUN MTU",
        Some(&current.to_string()),
        move |t: &String| match t.parse::<usize>() {
            Ok(value) if (576..=limit).contains(&value) => Ok(()),
            _ => Err(format!("enter a number from 576 to {limit}")),
        },
    )?;
    let value: u16 = text.parse()?;
    Ok((u64::from(value) != current).then_some(value))
}

/// Whether a tunnel of this carrier connects from a chosen address (not the raw carriers).
fn can_choose_local_address(dials: bool, transport: Transport) -> bool {
    dials && crate::config::server_can_dial(transport)
}

/// Asks for a new value of one numeric setting. `Ok(None)` keeps the current value,
/// `Ok(Some(None))` goes back to the default.
pub(super) fn ask_number(setting: &Setting, current: Option<u64>) -> Result<Option<Option<u64>>> {
    ask_number_mode(setting,current,false)
}
pub(super) fn ask_number_batch(setting:&Setting)->Result<Option<Option<u64>>>{ask_number_mode(setting,None,true)}
fn ask_number_mode(setting:&Setting,current:Option<u64>,batch:bool)->Result<Option<Option<u64>>>{
    ui::heading(setting.name, "");
    ui::note(setting.description);
    let default = setting
        .default
        .as_u64()
        .map_or("off".to_string(), |d| d.to_string());
    ui::note(&format!(
        "Allowed {}..{} {}, default {default}. Type 'default' to reset.",
        setting.min, setting.max, setting.unit
    ));
    let shown = current.map_or(default.clone(), |c| c.to_string());
    let (min, max) = (setting.min, setting.max);
    let text = ui::ask("New value", Some(&shown), move |text: &String| {
        if text == "default" {
            return Ok(());
        }
        match text.parse::<u64>() {
            Ok(value) if (min..=max).contains(&value) => Ok(()),
            _ => Err(format!("enter a number from {min} to {max}, or 'default'")),
        }
    })?;
    number_outcome(&text,current,setting.default.as_u64(),batch)
}

/// C17: what an accepted answer means. One tunnel: typing its current (or default, when
/// unset) value is no change. A batch has no shared current value, so every submitted
/// number is applied to every selected tunnel, including the built-in default.
fn number_outcome(text:&str,current:Option<u64>,default:Option<u64>,batch:bool)->Result<Option<Option<u64>>>{
    if text == "default" {
        return Ok(Some(None));
    }
    let value: u64 = text.parse()?;
    if !batch&&(Some(value) == current || current.is_none() && default == Some(value)) {
        return Ok(None);
    }
    Ok(Some(Some(value)))
}

fn explain_game() {
    ui::note(
        "Game mode sends the users' game UDP straight between the servers as encrypted datagrams,\n\
         each in several copies over different ports, and uses whichever copy arrives first. It\n\
         skips the tunnel's ordered stream, so a resent packet never holds the game back. Both\n\
         servers need it: the pairing code carries it, or turn it on at the other server too.\n\
         The Iran server listens on the Game mode port, TCP and UDP; open it in its firewall.",
    );
}

/// Port and copies of Game mode.
fn ask_game(port: &mut u16, copies: &mut u8) -> Result<()> {
    let text = ui::ask("Game mode port (TCP and UDP, the same on both servers)", Some(&port.to_string()), |t: &String| {
        match t.parse::<u16>() {
            Ok(1..=65535) => Ok(()),
            _ => Err("enter a port from 1 to 65535".into()),
        }
    })?;
    *port = text.parse()?;
    let text = ui::ask("Copies of each game packet (1 to 4; 3 recommended)", Some(&copies.to_string()), |t: &String| {
        match t.parse::<u8>() {
            Ok(1..=4) => Ok(()),
            _ => Err("enter 1 to 4".into()),
        }
    })?;
    *copies = text.parse()?;
    Ok(())
}

/// The Iran server's address, for a foreign server that does not dial it (a direct tunnel).
pub(crate) fn ask_iran_host(current: Option<&str>) -> Result<String> {
    ui::ask("IP address of the Iran server (for Game mode)", current, |t: &String| {
        if t.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() {
            Ok(())
        } else {
            Err("enter the Iran server's IP address (Game mode cannot use a host name)".into())
        }
    })
    .map(|t| t.trim_matches(['[', ']']).to_string())
}

/// The host of a saved tunnel's carrier address (`host:port`), without brackets.
fn carrier_host(config: &Value) -> Option<String> {
    let server = config["mode"] == "server";
    let entry = if server { &config["listeners"][0] } else { &config["paths"][0] };
    let addr = entry["addr"].as_str()?;
    Some(addr.rsplit_once(':')?.0.trim_matches(['[', ']']).to_string())
}

/// Whether turning Game mode on in this saved configuration needs the Iran server's IP: the
/// foreign end of a direct tunnel, or one whose carrier address is not an IP (a host name, a CDN).
pub(crate) fn game_asks_iran_ip(config: &Value) -> bool {
    let client = config["mode"] == "client";
    let server_dials = config["server_dials"].as_bool().or(config["reverse"].as_bool()).unwrap_or(false);
    client && (server_dials || !carrier_host(config).is_some_and(|h| h.parse::<std::net::IpAddr>().is_ok()))
}

/// Turns Game mode on or off in a saved configuration (see `plan::GamePlan`).
pub(crate) fn set_game_config(config: &mut Value, on: Option<(u16, u8, Option<String>)>) -> Result<()> {
    use anyhow::Context;
    let carrier_address = carrier_host(config);
    let Some(object) = config.as_object_mut() else { anyhow::bail!("not a configuration") };
    let Some((port, copies, iran_host)) = on else {
        object.remove("gaming");
        return Ok(());
    };
    let server = object.get("mode").and_then(Value::as_str) == Some("server");
    let server_dials = object.get("server_dials").or_else(|| object.get("reverse")).and_then(Value::as_bool).unwrap_or(false);
    let entry = if server { &object["listeners"][0] } else { &object["paths"][0] };
    let (control, wildcard) = if server {
        let ipv6 = entry["addr"].as_str().is_some_and(|a| a.starts_with('['));
        let wildcard = if ipv6 { "[::]" } else { "0.0.0.0" };
        (format!("{wildcard}:{port}"), wildcard)
    } else {
        // The Iran server's IP: the one given, else the carrier's address when it is an IP.
        let carrier = (!server_dials).then_some(carrier_address).flatten();
        let host = [iran_host.map(|h| h.trim_matches(['[', ']']).to_string()), carrier]
            .into_iter()
            .flatten()
            .find(|host| host.parse::<std::net::IpAddr>().is_ok())
            .context("Game mode needs the Iran server's IP address (a host name or a CDN domain cannot carry its datagrams)")?;
        // The game socket sends to the Iran server: the same address family.
        let wildcard = if host.contains(':') { "[::]" } else { "0.0.0.0" };
        let control = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        (control, wildcard)
    };
    object.insert(
        "gaming".into(),
        serde_json::json!({"control_address": control, "udp_bind": format!("{wildcard}:{port}"), "copies": copies}),
    );
    Ok(())
}

/// Customizes a tunnel that is still being created.
pub fn tune_plan(plan: &mut Plan) -> Result<()> {
    loop {
        ui::heading(
            "Customize",
            "Enter changes a value · choose Done when finished",
        );
        let mut items = Vec::new();
        let mut labels = Vec::new();
        let mut add = |item: Item, label: &str, value: String| {
            labels.push(format!("{:<38} {value}", label));
            items.push(item);
        };
        add(Item::Done, &ui::green("✔ Done"), String::new());
        let single = is_raw(plan.transport) || plan.carry.uses_tun();
        if plan.dials() && !single {
            add(
                Item::Pool,
                "Parallel connections (pool)",
                plan.pool.to_string(),
            );
        }
        if plan.transport.uses_http() {
            add(Item::HttpPath, "HTTP path", plan.http_path.clone());
        }
        if plan.transport.uses_tls() && plan.dials() && plan.cdn.is_none() {
            add(
                Item::Sni,
                "TLS name sent (SNI)",
                plan.sni.clone().unwrap_or_else(|| "none".into()),
            );
        }
        if can_choose_local_address(plan.dials(), plan.transport) {
            add(
                Item::LocalAddress,
                "Connect from address (local IP)",
                plan.local_address
                    .clone()
                    .unwrap_or_else(|| "automatic".into()),
            );
        }
        if plan.transport.uses_tls() && plan.dials() {
            add(
                Item::TlsProfile,
                "TLS look (dialing side)",
                match plan.tls_profile {
                    crate::config::TlsProfile::Classic => "classic".to_string(),
                    crate::config::TlsProfile::Chrome => ui::yellow("chrome"),
                },
            );
        }
        if plan.transport.uses_tls() {
            add(
                Item::TlsFragment,
                "TLS fragmentation (dialing side)",
                if plan.tls_fragment {
                    ui::yellow("on")
                } else {
                    "off".into()
                },
            );
        }
        if is_xhttp(plan.transport) {
            add(
                Item::XhttpMode,
                "XHTTP upload mode",
                serde_json::to_value(plan.xhttp_mode)?
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            );
        }
        if !plan.dials() && !is_raw(plan.transport) {
            add(Item::ListenIp, "Listen on address", plan.listen_ip.clone());
        }
        if plan.side == super::plan::Side::Iran && !plan.ports.is_empty() {
            add(
                Item::PublicIp,
                "Users connect on address",
                format!(
                    "{}{}",
                    plan.public_ip,
                    if plan.public_ip == "0.0.0.0" {
                        " (everyone)"
                    } else {
                        ""
                    }
                ),
            );
        }
        if let Some(raw) = &plan.raw {
            if plan.transport == Transport::Mirage {
                add(
                    Item::Mirage,
                    "Mirage spoofing and routing",
                    raw.mirage
                        .as_ref()
                        .map_or("not configured".into(), |m| m.spoof_src_ip.to_string()),
                );
            } else {
                add(
                    Item::IpMode,
                    "IP header mode",
                    match raw.ip_mode {
                        IpMode::Normal => "normal".into(),
                        IpMode::Proto58 => "proto58".into(),
                    },
                );
            }
            add(
                Item::Interface,
                "Network interface",
                raw.interface.clone().unwrap_or_else(|| "automatic".into()),
            );
            add(
                Item::LocalIp,
                "This server's IPv4",
                raw.local_ip.map_or("automatic".into(), |ip| ip.to_string()),
            );
        }
        if let Some(tun) = &plan.tun {
            add(Item::TunName, "TUN interface name", tun.name.clone());
            add(Item::TunMtu, "TUN MTU", tun.mtu.to_string());
        }
        let scope = Scope::of_plan(plan);
        if plan.carries_udp() && plan.tun.is_none() {
            add(
                Item::Game,
                "Game mode (fast path for game UDP)",
                match &plan.game {
                    Some(game) => ui::yellow(&format!("on · {} copies · port {}", game.copies, game.port)),
                    None => "off".into(),
                },
            );
        }
        if speed::applies(plan.transport, scope.parallax_packet) {
            add(
                Item::Speed,
                "Speed mode (CPU against latency)",
                plan.speed.label().to_string(),
            );
        }
        // A value kept from before a change of carrier or mode would only be a warning.
        let offered = scope::relevant(&scope);
        plan.tuned
            .retain(|(s, _)| offered.iter().any(|o| o.name == s.name && o.place == s.place));
        for (section, list) in groups(&offered) {
            let changed = list.iter().filter(|s| plan_value(plan, s).is_some()).count();
            let label = group_label(section, &scope, list.len(), changed);
            labels.push(label);
            items.push(Item::Group(section));
        }
        let Some(choice) = ui::choose("Option", &labels, 0)? else {
            return Err(ui::Back.into());
        };
        if matches!(&items[choice], Item::Done) {
            if let Err(error) = plan.to_json().and_then(|json| check(&json).map(|_| ())) {
                ui::fail(&format!("{error:#}"));
                ui::pause();
                continue;
            }
            return Ok(());
        }
        let before = plan.clone();
        let result = (|| -> Result<()> {
            match &items[choice] {
                Item::Mirage => {
                    if super::mirage::consent()?
                        && let Some(raw) = &mut plan.raw
                    {
                        raw.mirage = Some(super::mirage::settings(raw.mirage.as_ref())?);
                    }
                }
                Item::Done => unreachable!(),
                Item::Pool => {
                    let text = ui::ask(
                        "Parallel connections between the servers",
                        Some(&plan.pool.to_string()),
                        |t: &String| match t.parse::<usize>() {
                            Ok(1..=16) => Ok(()),
                            _ => Err("enter 1 to 16".into()),
                        },
                    )?;
                    plan.pool = text.parse()?;
                }
                Item::HttpPath => {
                    ui::note("Both servers must use the same path.");
                    plan.http_path = ui::ask("HTTP path", Some(&plan.http_path), |t: &String| {
                        let ok = t.starts_with('/')
                            && t.len() <= 200
                            && t.bytes()
                                .all(|b| b.is_ascii_graphic() && !b"?#\\".contains(&b));
                        if ok {
                            Ok(())
                        } else {
                            Err("start with / and use no spaces, ? or #".into())
                        }
                    })?;
                }
                Item::Sni => {
                    ui::note(
                        "The name this server sends when it opens TLS. The certificate is checked\nby the tunnel key, so any name works. Type 'none' to send no name.",
                    );
                    let text = ui::ask(
                        "TLS name (SNI)",
                        Some(plan.sni.as_deref().unwrap_or("none")),
                        |t: &String| {
                            if t == "none"
                                || !t.is_empty()
                                    && t.len() <= 253
                                    && t.bytes()
                                        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                            {
                                Ok(())
                            } else {
                                Err("enter a domain name or 'none'".into())
                            }
                        },
                    )?;
                    plan.sni = (text != "none").then_some(text);
                }
                Item::TlsFragment => {
                    ui::note(
                        "Splits the first TLS packet into small pieces so a filter cannot read the\nserver name (SNI) from it. Only the side that opens the connection does this;\nthe other side needs nothing. Turn it on when TLS carriers get blocked by name.\nTest it before relying on it: some filters drop split packets, and then the tunnel\nnever connects. If it does not come up, turn this off again.",
                    );
                    let labels = vec!["Off".to_string(), "On".to_string()];
                    plan.tls_fragment = ui::choose_required(
                        "TLS fragmentation",
                        &labels,
                        usize::from(plan.tls_fragment),
                    )? == 1;
                }
                Item::TlsProfile => {
                    if let Some(profile) = ask_tls_profile(plan.tls_profile)? {
                        plan.tls_profile = profile;
                    }
                }
                Item::LocalAddress => {
                    plan.local_address = ask_local_address(plan.local_address.as_deref())?;
                }
                Item::XhttpMode => {
                    let modes = [XhttpMode::StreamUp, XhttpMode::PacketUp, XhttpMode::Auto];
                    let labels: Vec<String> = [
                        "stream-up   one long upload request (fastest, direct links)",
                        "packet-up   many small upload requests (works through most CDNs)",
                        "auto        try stream-up, fall back to packet-up",
                    ]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                    let current = modes
                        .iter()
                        .position(|m| *m == plan.xhttp_mode)
                        .unwrap_or(0);
                    plan.xhttp_mode = modes[ui::choose_required("Upload mode", &labels, current)?];
                }
                Item::ListenIp => {
                    plan.listen_ip = ui::ask(
                        "Listen on address (0.0.0.0 = all IPv4, :: = all IPv6)",
                        Some(&plan.listen_ip),
                        |t: &String| {
                            t.parse::<std::net::IpAddr>()
                                .map(|_| ())
                                .map_err(|_| "enter an IP address".to_string())
                        },
                    )?;
                }
                Item::PublicIp => {
                    plan.public_ip = ui::ask(
                        "Address users connect on (0.0.0.0 = everyone, 127.0.0.1 = this server only)",
                        Some(&plan.public_ip),
                        |t: &String| {
                            t.parse::<std::net::IpAddr>()
                                .map(|_| ())
                                .map_err(|_| "enter an IP address".to_string())
                        },
                    )?;
                }
                Item::IpMode => {
                    let labels = vec![
                        "normal    ordinary IPv4 headers".to_string(),
                        "proto58   IPv4 protocol 58 with a fixed marker (both servers)".to_string(),
                    ];
                    if let Some(raw) = &mut plan.raw {
                        raw.ip_mode = if ui::choose_required("IP header mode", &labels, 0)? == 0 {
                            IpMode::Normal
                        } else {
                            IpMode::Proto58
                        };
                    }
                }
                Item::Interface => {
                    let text = ui::ask(
                        "Network interface ('auto' to detect)",
                        Some("auto"),
                        |t: &String| {
                            if t == "auto"
                                || (1..=15).contains(&t.len())
                                    && t.bytes()
                                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                            {
                                Ok(())
                            } else {
                                Err("enter an interface name such as eth0".into())
                            }
                        },
                    )?;
                    if let Some(raw) = &mut plan.raw {
                        raw.interface = (text != "auto").then_some(text);
                    }
                }
                Item::LocalIp => {
                    let text = ui::ask(
                        "This server's IPv4 ('auto' to detect)",
                        Some("auto"),
                        |t: &String| {
                            if t == "auto" {
                                return Ok(());
                            }
                            super::plan::unicast_ipv4(t)
                                .map(|_| ())
                                .map_err(|e| e.to_string())
                        },
                    )?;
                    if let Some(raw) = &mut plan.raw {
                        raw.local_ip = if text == "auto" {
                            None
                        } else {
                            Some(super::plan::unicast_ipv4(&text)?)
                        };
                    }
                }
                Item::TunName => {
                    if let Some(tun) = &mut plan.tun {
                        tun.name = ui::ask("TUN interface name", Some(&tun.name), |t: &String| {
                            if (1..=15).contains(&t.len())
                                && t.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                            {
                                Ok(())
                            } else {
                                Err("1 to 15 letters, digits, _ or -".into())
                            }
                        })?;
                    }
                }
                Item::TunMtu => {
                    if let Some(tun) = &mut plan.tun {
                        // A raw tunnel must fit inside one packet of the interface it leaves from.
                        let max = single_packet_cap(plan.transport, tun.fragment)
                            .then(|| {
                                plan.raw.as_ref().and_then(|raw| {
                                    super::iface::max_tun_mtu(&serde_json::json!({
                                        "profile": raw.profile,
                                        "peer_ip": raw.peer_ip.to_string(),
                                        "interface": raw.interface,
                                    }))
                                })
                            })
                            .flatten();
                        if let Some(value) = ask_tun_mtu(u64::from(tun.mtu), max)? {
                            tun.mtu = value;
                        }
                    }
                }
                Item::Game => {
                    explain_game();
                    let on = ui::choose_required(
                        "Game mode",
                        &["Off".to_string(), "On (recommended for games)".to_string()],
                        usize::from(plan.game.is_some()),
                    )? == 1;
                    plan.set_game(on);
                    let needs_ip = plan.game_needs_iran_ip();
                    if let Some(game) = &mut plan.game {
                        ask_game(&mut game.port, &mut game.copies)?;
                        if needs_ip {
                            game.iran_host = Some(ask_iran_host(game.iran_host.as_deref())?);
                        }
                    }
                }
                Item::Speed => {
                    if let Some(mode) = ask_speed_mode(plan.speed)? {
                        plan.speed = mode;
                    }
                }
                Item::Group(section) => {
                    let section = *section;
                    let scope = Scope::of_plan(plan);
                    let list: Vec<Setting> = scope::relevant(&scope)
                        .into_iter()
                        .filter(|s| scope::section(s) == section)
                        .collect();
                    edit_group(section, &scope, &list, plan, plan_value, set_plan_value)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            *plan = before;
            if !ui::is_back(&error) {
                return Err(error);
            }
        }
    }
}

/// Asks for a KCP/FEC timing mode. `None` keeps the current one.
fn ask_speed_mode(current: SpeedMode) -> Result<Option<SpeedMode>> {
    ui::heading("Speed mode", "");
    ui::note(
        "How often KCP resends and acknowledges. A shorter timer is faster and uses more CPU.\nEach server may use its own mode; nothing has to match.",
    );
    let labels: Vec<String> = SpeedMode::ALL
        .iter()
        .map(|mode| format!("{:<8} {}", mode.label(), mode.description()))
        .collect();
    let start = SpeedMode::ALL
        .iter()
        .position(|m| *m == current)
        .unwrap_or(0);
    Ok(ui::choose("Mode", &labels, start)?.map(|index| SpeedMode::ALL[index]))
}

/// The optional capabilities a tunnel can use, by number: 0 adaptive controller (FEC
/// carriers), 1 TCP packet fallback and 2 adaptive raw ports (raw FEC carriers), 3 direct gaming
/// datagrams (anything but TUN).
fn extensions(config: &Value, transport: Transport) -> Vec<usize> {
    let raw = is_raw(transport) && transport != Transport::Tun;
    let fec = matches!(
        transport,
        Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage
    );
    let mut list = Vec::new();
    if fec {
        list.push(0);
    }
    if raw {
        list.extend([1, 2]);
    }
    if !config["tun"].is_object() && transport != Transport::Tun {
        list.push(3);
    }
    list
}

fn transport_extensions(config:&mut Value,entry_key:&str,transport:Transport)->Result<()> {
    ui::heading("Adaptive paths and gaming", "Optional; existing peers and settings are unchanged while disabled");
    let names=["Adaptive controller and shared bandwidth", "Authenticated TCP packet fallback", "Authenticated adaptive raw ports", "Direct gaming datagrams and UDP migration"];
    let offered=extensions(config,transport);
    let items:Vec<String>=offered.iter().map(|i|names[*i].to_string()).collect();
    let Some(picked)=ui::choose("Capability",&items,0)? else{return Ok(());};
    let Some(&choice)=offered.get(picked) else{return Ok(());};
    let raw=is_raw(transport)&&transport!=Transport::Tun;
    match choice {
        0=>{
            if !matches!(transport,Transport::FecUdp|Transport::FecRaw|Transport::FecRawGaming|Transport::Mirage){ui::warn("The adaptive controller is for FEC carriers.");return Ok(());}
            let enabled=ui::confirm("Enable adaptive controller?",config[entry_key][0]["fec"]["adaptive"]["enabled"].as_bool().unwrap_or(false))?;
            let shared=enabled&&ui::confirm("Share bandwidth across loaded sessions on this path?",config[entry_key][0]["fec"]["adaptive"]["shared_bandwidth"].as_bool().unwrap_or(true))?;
            let entry=&mut config[entry_key][0];merge_fields(&mut entry["fec"]["adaptive"],serde_json::json!({"enabled":enabled,"shared_bandwidth":shared}));
            if enabled{entry["fec"]["pacer"]=false.into();entry["fec"]["tuner"]["mode"]="off".into();entry["fec"]["congestion_control"]=false.into();}
        }
        1=>{
            if !raw{ui::warn("TCP packet fallback requires a raw FEC carrier.");return Ok(());}
            ui::note("Configure both peers. Iran binds a separate unused TCP port; Foreign connects to that IP:port. No firewall rules are added automatically.");
            let text=ui::ask("TCP fallback IP:port ('off' disables)",Some(config[entry_key][0]["fec"]["tcp_fallback"]["address"].as_str().unwrap_or("off")),|value:&String|if value=="off"||value.parse::<std::net::SocketAddr>().is_ok(){Ok(())}else{Err("enter IP:port or off".into())})?;
            set_fallback(&mut config[entry_key][0]["fec"]["tcp_fallback"],&text);
        }
        2=>{
            if !raw{ui::warn("Adaptive ports require raw FEC with TCP or UDP profile.");return Ok(());}
            ui::note("Both peers need the same bounded port range and tunnel key. Existing firewall rules are never modified automatically. Preserve reachability for all chosen ports.");
            let enabled=ui::confirm("Enable authenticated raw port hopping?",config[entry_key][0]["raw"]["hopping"]["enabled"].as_bool().unwrap_or(false))?;
            let current=config[entry_key][0]["raw"]["hopping"].clone();
            let first=if enabled{ui::ask("First permitted hop port",Some(&current["first_port"].as_u64().unwrap_or(40000).to_string()),|value:&String|if value.parse::<u16>().is_ok_and(|v|v>=1024){Ok(())}else{Err("enter 1024..65535".into())})?.parse::<u16>()?}else{40000};
            let last=if enabled{ui::ask("Last permitted hop port (at most 256 ports)",Some(&current["last_port"].as_u64().unwrap_or(u64::from(first.saturating_add(31))).to_string()),move|value:&String|if value.parse::<u16>().is_ok_and(|v|v>=first&&u32::from(v)-u32::from(first)<256){Ok(())}else{Err("the range must contain 1..256 ports".into())})?.parse::<u16>()?}else{40063};
            set_hopping(&mut config[entry_key][0]["raw"]["hopping"],enabled.then_some((first,last)));
        }
        3=>{
            if config["tun"].is_object(){ui::warn("Direct gaming is for UDP maps and SOCKS UDP; TUN keeps its existing authenticated datagram mode.");return Ok(());}
            ui::note("Configure both endpoints explicitly. Control uses separate authenticated Noise, with an unused TCP port. UDP bind and advertised address are local to this host. The advertised IP must match the remote TCP-observed IP; NAT rebinding needs a newly authenticated control handshake. Packets are unreliable UDP, not delivery-guaranteed records.");
            if !ui::confirm("Enable direct gaming UDP?",config["gaming"]["control_address"].is_string())?{disable_gaming(&mut config["gaming"]);return Ok(());}
            let ask=|label:&str,field:&str|ui::ask(label,Some(config["gaming"][field].as_str().unwrap_or("127.0.0.1:45000")),|value:&String|if value.parse::<std::net::SocketAddr>().is_ok(){Ok(())}else{Err("enter explicit IP:port".into())});
            let control=ask("Control TCP IP:port (Iran bind / Foreign destination)","control_address")?;
            let bind=ask("This host's UDP bind IP:port","udp_bind")?;
            let advertise=ask("This host's publicly reachable UDP IP:port","advertise")?;
            let migrate=ui::confirm("Allow authenticated UDP flow migration on renewal?",config["gaming"]["migrate"].as_bool().unwrap_or(true))?;
            merge_fields(&mut config["gaming"],serde_json::json!({"control_address":control,"udp_bind":bind,"advertise":advertise,"migrate":migrate}));
        }
        _=>{}
    }
    Ok(())
}

/// C27: turning an extension off or on changes only the fields the editor shows; hidden
/// limits (min_rate, max_window, retry_ms, mtu, max_flows, ...) are kept as saved.
fn set_fallback(object:&mut Value,text:&str){
    if text=="off"{if let Some(object)=object.as_object_mut(){object.remove("address");}}else{merge_fields(object,serde_json::json!({"address":text}));}
}
fn set_hopping(object:&mut Value,range:Option<(u16,u16)>){
    merge_fields(object,match range{Some((first,last))=>serde_json::json!({"enabled":true,"first_port":first,"last_port":last}),None=>serde_json::json!({"enabled":false})});
}
fn disable_gaming(gaming:&mut Value){
    if let Some(object)=gaming.as_object_mut(){object.remove("control_address");}
}
fn merge_fields(target:&mut Value,changes:Value){
    if !target.is_object(){*target=serde_json::json!({});}
    target.as_object_mut().unwrap().extend(changes.as_object().expect("field updates are objects").clone());
}
#[cfg(test)]mod extension_edit_tests{
    use super::*;
    #[test]fn disabling_and_reenabling_extensions_keeps_hidden_settings(){
        let mut fallback=serde_json::json!({"address":"192.0.2.1:4567","handshake_sec":12,"idle_ms":700});
        set_fallback(&mut fallback,"off");
        assert_eq!(fallback,serde_json::json!({"handshake_sec":12,"idle_ms":700}));
        set_fallback(&mut fallback,"192.0.2.9:4000");
        assert_eq!(fallback,serde_json::json!({"address":"192.0.2.9:4000","handshake_sec":12,"idle_ms":700}));
        let mut hopping=serde_json::json!({"enabled":true,"first_port":41000,"last_port":41010,"interval_ms":900});
        set_hopping(&mut hopping,None);
        assert_eq!(hopping,serde_json::json!({"enabled":false,"first_port":41000,"last_port":41010,"interval_ms":900}),"disabling keeps the saved range");
        set_hopping(&mut hopping,Some((42000,42031)));
        assert_eq!(hopping["interval_ms"],900);assert_eq!(hopping["first_port"],42000);
        let mut gaming=serde_json::json!({"control_address":"127.0.0.1:45000","udp_bind":"0.0.0.0:45001","max_flows":37,"renewal_sec":60,"mtu":900});
        disable_gaming(&mut gaming);
        assert_eq!(gaming,serde_json::json!({"udp_bind":"0.0.0.0:45001","max_flows":37,"renewal_sec":60,"mtu":900}));
        let mut absent=Value::Null;disable_gaming(&mut absent);set_fallback(&mut absent,"off");assert!(absent.is_null());
    }
    #[test]fn displayed_changes_preserve_unedited_nested_limits(){
        let mut value=serde_json::json!({"enabled":true,"min_rate":123456,"max_window":777,"retry_ms":777,"handshake_sec":12,"mtu":700,"max_flows":37});
        let original=value.clone();merge_fields(&mut value,serde_json::json!({"enabled":false,"address":"192.0.2.1:4567"}));
        for field in ["min_rate","max_window","retry_ms","handshake_sec","mtu","max_flows"]{assert_eq!(value[field],original[field],"{field}");}
        assert_eq!(value["enabled"],false);assert_eq!(value["address"],"192.0.2.1:4567");
    }

    /// C46: 1500-byte interface, TCP profile: single-packet room 1413. Without fragmentation
    /// 2000 is above the editor limit; with fragmentation no single-packet cap is computed
    /// and 2000/2100 fit the configuration bound.
    #[test]fn batch_numeric_default_is_applied_but_single_no_op_is_kept()->Result<()>{
        // heartbeat_sec default 10; selected tunnels customized to 20.
        assert_eq!(number_outcome("10",None,Some(10),true)?,Some(Some(10)),"batch must apply the default number");
        assert_eq!(number_outcome("20",None,Some(10),true)?,Some(Some(20)));
        assert_eq!(number_outcome("default",None,Some(10),true)?,Some(None));
        assert_eq!(number_outcome("10",None,Some(10),false)?,None,"single unset tunnel already uses the default");
        assert_eq!(number_outcome("20",Some(20),Some(10),false)?,None);
        assert_eq!(number_outcome("10",Some(20),Some(10),false)?,Some(Some(10)));
        Ok(())
    }

    /// C28: v2 (no spoof_src_ip) -> legacy v1 asks for a unicast source, drops `mirage`,
    /// sets the acknowledgement; cancellation and non-TCP profiles change nothing.
    #[test]fn legacy_mirage_conversion_is_transactional_and_needs_a_unicast_source()->Result<()>{
        use super::super::plan::MiragePlan;
        let v2=serde_json::json!({"profile":"tcp","peer_ip":"192.0.2.2","l4_port":4443,"mirage":{"source_pool":["198.51.100.0/30"]}});
        let source:std::net::Ipv4Addr="198.51.100.7".parse()?;
        let plan=|current:Option<&MiragePlan>|{assert!(current.is_none(),"no legacy source existed");Ok(MiragePlan{spoof_src_ip:source,advanced:None,spoof_dst_ip:None,gateway_ip:None,peer_mac:None})};
        let draft=legacy_mirage_draft(&v2,plan,|_,_|Ok((None,None)))?;
        assert!(draft.get("mirage").is_none());
        assert_eq!(draft["spoof_src_ip"],"198.51.100.7");
        assert_eq!(draft["mirage_acknowledgement"],serde_json::json!(crate::mirage::ACK));
        let _:crate::raw_packet::RawOptions=serde_json::from_value(draft)?;
        // Cancelled prompt: error, and the caller's v2 entry is untouched (it is never mutated).
        assert!(legacy_mirage_draft(&v2,|_|Err(anyhow::anyhow!("back")),|_,_|Ok((None,None))).is_err());
        assert!(v2["mirage"].is_object());
        // The v2 placeholder source is never written as legacy configuration.
        let placeholder=|_:Option<&MiragePlan>|Ok(MiragePlan{spoof_src_ip:std::net::Ipv4Addr::UNSPECIFIED,advanced:None,spoof_dst_ip:None,gateway_ip:None,peer_mac:None});
        assert!(legacy_mirage_draft(&v2,placeholder,|_,_|Ok((None,None))).is_err());
        let udp=serde_json::json!({"profile":"udp","peer_ip":"192.0.2.2","l4_port":4443});
        assert!(format!("{:#}",legacy_mirage_draft(&udp,plan,|_,_|Ok((None,None))).unwrap_err()).contains("tcp packet type"));
        Ok(())
    }

    #[test]fn fragmented_tun_mtu_is_not_capped_to_one_outer_packet(){
        assert!(single_packet_cap(Transport::Tun,false));
        assert!(!single_packet_cap(Transport::Tun,true));
        for other in [Transport::Mirage,Transport::FecRaw,Transport::Tcp]{assert!(!single_packet_cap(other,false),"{other:?}");}
        let room=(1413usize,"eth0".to_string(),1500u32);
        let capped=mtu_limit(Some(&room));
        assert_eq!(capped,1413);assert!(2000>capped);
        let fragmented=mtu_limit(None);
        assert_eq!(fragmented,9000);assert!((576..=fragmented).contains(&2000)&&(576..=fragmented).contains(&2100));
        assert_eq!(mtu_limit(Some(&(20000,"jumbo".into(),20000))),9000,"never above the configuration maximum");
    }
}

/// C28: converts a raw entry to legacy Mirage v1 (TCP only). The v2 `mirage` object is
/// dropped, a unicast spoofed source is asked for even when none existed, and the result is
/// returned for the caller to commit; on any error or cancellation nothing is changed.
fn legacy_mirage_draft(
    raw_entry: &Value,
    ask: impl FnOnce(Option<&super::plan::MiragePlan>) -> Result<super::plan::MiragePlan>,
    local: impl FnOnce(Option<&str>, Option<std::net::Ipv4Addr>) -> Result<(Option<String>, Option<std::net::Ipv4Addr>)>,
) -> Result<Value> {
    let mut draft = raw_entry.clone();
    let profile = draft["profile"].as_str().unwrap_or("tcp");
    anyhow::ensure!(profile == "tcp", "legacy Mirage v1 needs the tcp packet type; this tunnel uses {profile}. Use Mirage setup (v2) instead");
    draft.as_object_mut().ok_or_else(|| anyhow::anyhow!("raw settings missing"))?.remove("mirage");
    let raw: crate::raw_packet::RawOptions = serde_json::from_value(draft.clone())?;
    let current = raw.spoof_src_ip.map(|source| super::plan::MiragePlan {
        spoof_src_ip: source,
        advanced: None,
        spoof_dst_ip: raw.spoof_dst_ip,
        gateway_ip: raw.gateway_ip,
        peer_mac: raw.peer_mac.clone(),
    });
    let value = ask(current.as_ref())?;
    anyhow::ensure!(value.advanced.is_none() && !value.spoof_src_ip.is_unspecified(), "legacy Mirage v1 needs a unicast spoofed source");
    let (interface, local_ip) = local(raw.interface.as_deref(), raw.local_ip)?;
    let entry = draft.as_object_mut().ok_or_else(|| anyhow::anyhow!("raw settings missing"))?;
    entry.insert("spoof_src_ip".into(), serde_json::json!(value.spoof_src_ip));
    entry.insert("mirage_acknowledgement".into(), serde_json::json!(crate::mirage::ACK));
    for (name, value) in [
        ("spoof_dst_ip", serde_json::to_value(value.spoof_dst_ip)?),
        ("gateway_ip", serde_json::to_value(value.gateway_ip)?),
        ("peer_mac", serde_json::to_value(value.peer_mac)?),
        ("interface", serde_json::to_value(interface)?),
        ("local_ip", serde_json::to_value(local_ip)?),
    ] {
        if value.is_null() {
            entry.remove(name);
        } else {
            entry.insert(name.into(), value);
        }
    }
    Ok(draft)
}

/// The numeric settings offered for a saved tunnel.
pub(crate) fn settings_of(config: &Value) -> Result<Vec<Setting>> {
    Ok(scope::relevant(&Scope::of_config(config)?))
}

/// Changes the settings of a saved tunnel. Returns the new configuration when the operator
/// saved changes that pass the program's checks. Only what this tunnel's carrier, mode and side
/// use is offered; the numeric settings are grouped, the carrier's own group first.
pub fn tune_config(config: &Value) -> Result<Option<Value>> {
    let original = Scope::of_config(config)?;
    let (mode, transport) = (original.mode, original.transport);
    let mut edited = config.clone();
    let mut cursor = 0;
    loop {
        let scope = Scope::of_config(&edited)?;
        let settings = scope::relevant(&scope);
        ui::heading(
            "Change settings",
            &format!(
                "{} · {} · values in yellow differ from the default",
                scope.carrier_title(),
                if mode == Mode::Server { "Iran server" } else { "foreign server" }
            ),
        );
        let entry_key = match mode {
            Mode::Server => "listeners",
            Mode::Client => "paths",
        };
        let dials = scope.dials();
        let mut labels = vec![
            ui::green("✔ Save and restart"),
            ui::red("✘ Discard changes"),
        ];
        let row = |labels: &mut Vec<String>, name: &str, value: String| {
            labels.push(format!("{name:<38} {value}"));
            labels.len() - 1
        };
        let parallax_row = (transport == Transport::Parallax).then(|| {
            let value = if scope.parallax_packet { ui::yellow("packet") } else { "stream".to_string() };
            row(&mut labels, "Parallax mode (same on both servers)", value)
        });
        let single = is_raw(transport) || edited["tun"].is_object();
        let pool_row = (dials && !single).then(|| {
            let pool = super::plan::pool_now(&edited[entry_key][0], transport);
            let value = if pool == transport.auto_pool() as u64 { format!("{pool} (automatic)") } else { ui::yellow(&pool.to_string()) };
            row(&mut labels, "Parallel connections (pool)", value)
        });
        let speed_row = speed::applies(transport, scope.parallax_packet).then(|| {
            let value = speed::detect(&edited, transport)
                .map_or_else(|| ui::yellow("custom"), |m| m.label().to_string());
            row(&mut labels, "Speed mode (CPU against latency)", value)
        });
        let fragment_row = (transport.uses_tls() && dials).then(|| {
            let value = if scope.tls_fragment { ui::yellow("on") } else { "off".into() };
            row(&mut labels, "TLS fragmentation (dialing side)", value)
        });
        let profile_row = (dials && transport.uses_tls()).then(|| {
            let value = match edited[entry_key][0]["tls_profile"].as_str() {
                Some("chrome") => ui::yellow("chrome"),
                _ => "classic".to_string(),
            };
            row(&mut labels, "TLS look (dialing side)", value)
        });
        let local_row = can_choose_local_address(dials, transport).then(|| {
            let value = edited[entry_key][0]["local_address"]
                .as_str()
                .map_or("automatic".to_string(), |ip| ui::yellow(ip).to_string());
            row(&mut labels, "Connect from address (local IP)", value)
        });
        let tun_row = edited["tun"].is_object().then(|| {
            let value = edited["tun"]["mtu"]
                .as_u64()
                .map_or("1400".to_string(), |mtu| mtu.to_string());
            row(&mut labels, "TUN MTU", value)
        });
        let mirage_row = (transport == Transport::Mirage).then(|| {
            let value = edited[entry_key][0]["raw"]["spoof_src_ip"]
                .as_str()
                .unwrap_or("not configured")
                .to_string();
            row(&mut labels, "Mirage spoofing and routing", value)
        });
        let game_now = super::pairing::game_of(&edited);
        let custom_gaming = edited["gaming"]["control_address"].is_string() && game_now.is_none();
        let carries_udp = mode == Mode::Client
            || edited["socks5"].is_string()
            || edited["listeners"][0]["maps"].as_array().is_some_and(|maps| maps.iter().any(|m| m["type"] == "udp"));
        let game_row = (carries_udp && !edited["tun"].is_object() && !custom_gaming).then(|| {
            let value = match game_now {
                Some((port, copies)) => ui::yellow(&format!("on · {copies} copies · port {port}")),
                None => "off".to_string(),
            };
            row(&mut labels, "Game mode (fast path for game UDP)", value)
        });
        let extension_row = (!extensions(&edited, transport).is_empty())
            .then(|| row(&mut labels, "Adaptive paths and gaming", ui::dim("optional")));
        let mut group_rows = Vec::new();
        for (section, list) in groups(&settings) {
            let changed = list.iter().filter(|s| read_setting(&edited, s).is_some()).count();
            labels.push(group_label(section, &scope, list.len(), changed));
            group_rows.push((labels.len() - 1, section, list));
        }
        let Some(choice) = ui::choose("Setting", &labels, cursor)? else {
            return Ok(None);
        };
        cursor = choice;
        if choice == 1 {
            return Ok(None);
        }
        if choice == 0 {
            // Values of the old Parallax mode or TLS fragmentation would only be warnings now.
            let gone = scope::stale(&original, &scope, &edited);
            let mut saved = edited.clone();
            for setting in &gone {
                apply_setting(&mut saved, setting, None)?;
            }
            match check(&saved) {
                Ok(_) => {
                    if !gone.is_empty() {
                        let names: Vec<&str> = gone.iter().map(|s| s.name).collect();
                        ui::note(&format!(
                            "Removed values that no longer apply: {}",
                            names.join(", ")
                        ));
                    }
                    return Ok((saved != *config).then_some(saved));
                }
                Err(error) => {
                    ui::fail(&format!("{error:#}"));
                    ui::pause();
                    continue;
                }
            }
        }
        let previous = edited.clone();
        let result = (|| -> Result<()> {
            if Some(choice) == game_row {
                explain_game();
                let current = super::pairing::game_of(&edited);
                let on = ui::choose_required(
                    "Game mode",
                    &["Off".to_string(), "On (recommended for games)".to_string()],
                    usize::from(current.is_some()),
                )? == 1;
                if !on {
                    return set_game_config(&mut edited, None);
                }
                let tunnel_port = edited[entry_key][0]["addr"].as_str()
                    .and_then(|a| a.rsplit_once(':')).and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(7000);
                let (mut port, mut copies) = current.unwrap_or((super::plan::game_port(tunnel_port), super::plan::GAME_COPIES));
                ask_game(&mut port, &mut copies)?;
                // The Iran IP Game mode uses now: kept unless it is changed here (a reverse tunnel's
                // Game address may differ from its carrier's).
                let known = (mode == Mode::Client && current.is_some())
                    .then(|| edited["gaming"]["control_address"].as_str()
                        .and_then(|a| a.rsplit_once(':')).map(|(h, _)| h.trim_matches(['[', ']']).to_string()))
                    .flatten();
                let iran_host = if mode == Mode::Client && game_asks_iran_ip(&edited) {
                    Some(ask_iran_host(known.as_deref())?)
                } else {
                    known
                };
                set_game_config(&mut edited, Some((port, copies, iran_host)))?;
                // The carrier's own resends never hold game packets back now, but its timer
                // still paces the control and game TCP: use the fastest where it has one.
                if speed::applies(transport, scope.parallax_packet) && speed::detect(&edited, transport) == Some(SpeedMode::Default) {
                    speed::apply_config(&mut edited, transport, SpeedMode::Fast3);
                }
                ui::note("Turn Game mode on at the other server too, with the same port and copies.");
                return Ok(());
            }
            if Some(choice) == extension_row {
                return transport_extensions(&mut edited, entry_key, transport);
            }
            if let Some((_, section, list)) = group_rows.iter().find(|(row, _, _)| *row == choice) {
                return edit_group(*section, &scope, list, &mut edited, file_value, set_file_value);
            }
            if Some(choice) == fragment_row {
                let entry = &mut edited[entry_key][0];
                if scope.tls_fragment {
                    if let Some(object) = entry.as_object_mut() {
                        object.remove("tls_fragment");
                    }
                } else {
                    entry["tls_fragment"] = serde_json::json!({"enabled": true});
                }
                return Ok(());
            }
            if Some(choice) == pool_row {
                let current = super::plan::pool_now(&edited[entry_key][0], transport);
                ui::note("Parallel tunnel connections this side opens. More spread users and limit the effect of one dropping.");
                let text = ui::ask(
                    "Parallel connections between the servers",
                    Some(&current.to_string()),
                    |t: &String| match t.parse::<u64>() {
                        Ok(1..=16) => Ok(()),
                        _ => Err("enter 1 to 16".into()),
                    },
                )?;
                let pool: u64 = text.parse()?;
                super::plan::set_pool(&mut edited[entry_key][0], transport, pool);
                return Ok(());
            }
            if Some(choice) == local_row {
                let current = edited[entry_key][0]["local_address"]
                    .as_str()
                    .map(str::to_string);
                let entry = &mut edited[entry_key][0];
                match ask_local_address(current.as_deref())? {
                    Some(address) => entry["local_address"] = address.into(),
                    None => {
                        if let Some(object) = entry.as_object_mut() {
                            object.remove("local_address");
                        }
                    }
                }
                return Ok(());
            }
            if Some(choice) == tun_row {
                let current = edited["tun"]["mtu"].as_u64().unwrap_or(1400);
                let max = single_packet_cap(transport, edited["tun"]["fragment"].as_bool().unwrap_or(false))
                    .then(|| super::iface::max_tun_mtu(&edited[entry_key][0]["raw"]))
                    .flatten();
                if let Some(mtu) = ask_tun_mtu(current, max)? {
                    edited["tun"]["mtu"] = mtu.into();
                }
                return Ok(());
            }
            if Some(choice) == parallax_row {
                use crate::parallax_carrier::Mode as ParallaxMode;
                let current = match edited[entry_key][0]["parallax"]["mode"].as_str() {
                    Some("packet") => ParallaxMode::Packet,
                    _ => ParallaxMode::Stream,
                };
                let chosen = super::wizard::ask_parallax_mode(current)?;
                if current == ParallaxMode::Packet && chosen == ParallaxMode::Stream {
                    // Stream mode has no packet timer: drop the speed mode's fields first.
                    speed::apply_config(&mut edited, transport, SpeedMode::Default);
                }
                let entry = &mut edited[entry_key][0];
                if chosen == ParallaxMode::Packet {
                    crate::settings::set_dotted(entry, "parallax.mode", serde_json::json!("packet"));
                } else if let Some(parallax) = entry["parallax"].as_object_mut() {
                    parallax.remove("mode");
                    if parallax.is_empty()
                        && let Some(object) = entry.as_object_mut()
                    {
                        object.remove("parallax");
                    }
                }
                return Ok(());
            }
            if Some(choice) == profile_row {
                let current: crate::config::TlsProfile =
                    serde_json::from_value(edited[entry_key][0]["tls_profile"].clone())
                        .unwrap_or_default();
                if let Some(profile) = ask_tls_profile(current)? {
                    let entry = &mut edited[entry_key][0];
                    if profile.is_classic() {
                        if let Some(object) = entry.as_object_mut() {
                            object.remove("tls_profile");
                        }
                    } else {
                        entry["tls_profile"] = serde_json::json!(profile);
                    }
                }
                return Ok(());
            }
            if Some(choice) == speed_row {
                let current = speed::detect(&edited, transport).unwrap_or_default();
                if let Some(mode) = ask_speed_mode(current)? {
                    speed::apply_config(&mut edited, transport, mode);
                }
                return Ok(());
            }
            if Some(choice) == mirage_row {
                if super::mirage::consent()? {
                    let variants=["Mirage setup  source IPs and packet types", "Compatibility / legacy TCP v1", "Back"].map(str::to_string);
                    match ui::choose_required("Mirage configuration",&variants,0)? {
                        0=>{super::mirage::advanced(&mut edited[entry_key][0]["raw"])?;return Ok(());}
                        1=>{
                            if edited[entry_key][0]["raw"]["mirage"].is_object(){
                                ui::warn("Legacy v1 uses a different packet format. Both endpoints must change together; no automatic downgrade is performed.");
                                if !ui::confirm("Configure legacy v1 on this endpoint?",false)?{return Ok(());}
                            }
                        }
                        _=>return Ok(()),
                    }
                    // C28: build the legacy draft on a copy and commit it only once every prompt
                    // succeeded, so cancelling leaves the previous (v2) draft untouched.
                    let draft=legacy_mirage_draft(&edited[entry_key][0]["raw"],super::mirage::legacy_settings,super::mirage::local_settings)?;
                    edited[entry_key][0]["raw"]=draft;                }
                return Ok(());
            }
            Ok(())
        })();
        if let Err(error) = result {
            edited = previous;
            if !ui::is_back(&error) {
                return Err(error);
            }
        }
    }
}
