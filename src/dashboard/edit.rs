//! Editing a saved tunnel from the dashboard: its forwarded ports (Iran end), its traffic limit and
//! the numeric settings the terminal manager offers for it. Changes are applied to the
//! configuration the same way the manager applies them; saving checks the result like any save.
use crate::{
    manager::{
        manage::{current_ports, current_proxy, with_ports},
        plan::{self, Protocol, apply_setting, format_ports, parse_ports, read_setting},
        scope::{Scope, Section, section},
        tune::settings_of,
    },
    settings::{Place, Setting},
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

fn place_word(place: Place) -> &'static str {
    match place {
        Place::Top => "top",
        Place::Listener => "listener",
        Place::Path => "path",
    }
}

fn protocol_word(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Both => "both",
    }
}

fn protocol_of(word: &str) -> Result<Protocol> {
    Ok(match word {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "both" => Protocol::Both,
        _ => bail!("protocol must be tcp, udp or both"),
    })
}

/// Whether the tunnel forwards ports itself (the Iran end of a port-forwarding tunnel).
fn has_ports(config: &Value) -> bool {
    config["mode"] == "server" && config["listeners"][0]["maps"].as_array().is_some_and(|m| !m.is_empty())
}

/// What the edit screen shows for a tunnel, with the current values.
pub fn editable(config: &Value) -> Result<Value> {
    let ports = if has_ports(config) {
        let (rules, protocol, _, several) = current_ports(config);
        json!({"text": format_ports(&rules), "protocol": protocol_word(protocol), "several_addresses": several,
               "proxy_protocol": current_proxy(config).unwrap_or(0)})
    } else {
        Value::Null
    };
    // The traffic limit and the scheduled restart have their own parts of the screen. The rest
    // is listed by group, the carrier's own settings first, as in the terminal manager.
    let scope = Scope::of_config(config)?;
    let mut listed: Vec<Setting> = settings_of(config)?
        .into_iter()
        .filter(|s| !s.name.starts_with("quota.") && !s.name.starts_with("schedule."))
        .collect();
    listed.sort_by_key(|s| Section::ALL.iter().position(|g| *g == section(s)));
    let settings: Vec<Value> = listed
        .iter()
        .map(|s| {
            let group = section(s);
            json!({
                "name": s.name, "place": place_word(s.place), "unit": s.unit, "min": s.min, "max": s.max,
                "default": s.default, "value": read_setting(config, s), "description": s.description,
                "group": group.id(), "group_title": group.title(&scope), "carrier": scope.carrier_title(),
            })
        })
        .collect();
    Ok(json!({
        "ports": ports,
        "carrier": carrier_of(config, &scope),
        "quota": {
            "limit_gb": config["quota"]["limit_gb"].as_u64().unwrap_or(0),
            "period_days": config["quota"]["period_days"].as_u64().unwrap_or(30),
        },
        "settings": settings,
        "restart_hours": config["schedule"]["restart_every_hours"].as_u64().unwrap_or(0),
        // Sized on the server that runs the tunnel (an agent answers for its own server).
        "presets": crate::manager::presets::listed(config, crate::manager::presets::Capacity::here()),
    }))
}

/// The listener or path the tunnel's carrier settings live in.
fn entry_key(scope: &Scope) -> &'static str {
    match scope.mode {
        crate::config::Mode::Server => "listeners",
        crate::config::Mode::Client => "paths",
    }
}

/// The carrier choices the terminal's Change settings has, each only where it applies to this
/// tunnel (`null` otherwise): Parallax mode, parallel connections and the TLS look and
/// fragmentation of the side that dials, and the speed mode.
fn carrier_of(config: &Value, scope: &Scope) -> Value {
    use crate::config::Transport;
    let entry = &config[entry_key(scope)][0];
    let single = crate::manager::plan::is_raw(scope.transport) || config["tun"].is_object();
    let tls = scope.transport.uses_tls() && scope.dials();
    let speed = crate::manager::speed::applies(scope.transport, scope.parallax_packet).then(|| {
        crate::manager::speed::detect(config, scope.transport).map_or("custom", |mode| mode.label())
    });
    json!({
        "transport": scope.transport,
        "parallax_mode": (scope.transport == Transport::Parallax)
            .then(|| if scope.parallax_packet { "packet" } else { "stream" }),
        "pool": (scope.dials() && !single).then(|| crate::manager::plan::pool_now(entry, scope.transport)),
        "speed": speed,
        "tls_profile": tls.then(|| entry["tls_profile"].as_str().unwrap_or("classic")),
        "tls_fragment": tls.then(|| entry["tls_fragment"]["enabled"].as_bool().unwrap_or(false)),
        // Game mode where users' UDP goes through (UDP maps or SOCKS5 on the Iran end) and no
        // hand-made gaming setup would be overwritten.
        "game": game_offered(config, scope).then(|| match crate::manager::pairing::game_of(config) {
            Some((port, copies)) => json!({"on": true, "port": port, "copies": copies,
                "iran_address": iran_address(config)}),
            None => json!({"on": false, "port": crate::manager::plan::game_port(tunnel_port(config, scope)),
                "copies": crate::manager::plan::GAME_COPIES, "iran_address": null}),
        }),
        "game_needs_iran_address": crate::manager::tune::game_asks_iran_ip(config),
    })
}

fn game_offered(config: &Value, scope: &Scope) -> bool {
    let custom = config["gaming"]["control_address"].is_string() && crate::manager::pairing::game_of(config).is_none();
    let udp = scope.mode == crate::config::Mode::Client
        || config["socks5"].is_string()
        || config["listeners"][0]["maps"].as_array().is_some_and(|maps| maps.iter().any(|m| m["type"] == "udp"));
    udp && !custom && !config["tun"].is_object() && !crate::manager::plan::is_raw(scope.transport)
}

fn tunnel_port(config: &Value, scope: &Scope) -> u16 {
    config[entry_key(scope)][0]["addr"].as_str().and_then(|a| a.rsplit_once(':'))
        .and_then(|(_, p)| p.parse().ok()).unwrap_or(7000)
}

/// The Iran address a foreign end's Game mode connects to, when it is set.
fn iran_address(config: &Value) -> Option<String> {
    (config["mode"] == "client").then_some(())?;
    let address = config["gaming"]["control_address"].as_str()?;
    Some(address.rsplit_once(':')?.0.trim_matches(['[', ']']).to_string())
}

/// Applies `{"parallax_mode", "pool", "speed", "tls_profile", "tls_fragment"}` (each optional).
/// A choice this tunnel does not have is refused. Values of the old Parallax mode or of TLS
/// fragmentation that no longer apply are removed, as the terminal manager does when it saves.
fn apply_carrier(config: &mut Value, carrier: &Value) -> Result<()> {
    use crate::manager::speed::{self, SpeedMode};
    let before = Scope::of_config(config)?;
    let offered = carrier_of(config, &before);
    let key = entry_key(&before);
    let has = |name: &str| !offered[name].is_null();
    if let Some(mode) = carrier.get("parallax_mode").filter(|v| !v.is_null()) {
        ensure!(has("parallax_mode"), "Parallax mode applies to Parallax tunnels only");
        match mode.as_str() {
            Some("packet") => crate::settings::set_dotted(&mut config[key][0], "parallax.mode", json!("packet")),
            Some("stream") => {
                if before.parallax_packet {
                    // Stream mode has no packet timer: the speed mode's fields go first.
                    speed::apply_config(config, before.transport, SpeedMode::Default);
                }
                if let Some(parallax) = config[key][0]["parallax"].as_object_mut() {
                    parallax.remove("mode");
                    if parallax.is_empty()
                        && let Some(entry) = config[key][0].as_object_mut()
                    {
                        entry.remove("parallax");
                    }
                }
            }
            _ => bail!("Parallax mode must be stream or packet"),
        }
    }
    if let Some(word) = carrier.get("speed").filter(|v| !v.is_null()) {
        let now = Scope::of_config(config)?;
        ensure!(speed::applies(now.transport, now.parallax_packet), "this carrier has no speed mode");
        let mode = word.as_str().and_then(SpeedMode::from_label).context("unknown speed mode")?;
        speed::apply_config(config, now.transport, mode);
    }
    if let Some(pool) = carrier.get("pool").filter(|v| !v.is_null()) {
        ensure!(has("pool"), "only the side that connects has parallel connections");
        let pool = pool.as_u64().filter(|p| (1..=16).contains(p)).context("parallel connections must be 1 to 16")?;
        let transport = Scope::of_config(config)?.transport;
        crate::manager::plan::set_pool(&mut config[key][0], transport, pool);
    }
    if let Some(profile) = carrier.get("tls_profile").filter(|v| !v.is_null()) {
        ensure!(has("tls_profile"), "the TLS look applies to the connecting side of a TLS carrier only");
        let entry = &mut config[key][0];
        match profile.as_str() {
            Some("classic") => {
                if let Some(object) = entry.as_object_mut() {
                    object.remove("tls_profile");
                }
            }
            Some("chrome") => entry["tls_profile"] = json!("chrome"),
            _ => bail!("the TLS look must be classic or chrome"),
        }
    }
    if let Some(on) = carrier.get("tls_fragment").filter(|v| !v.is_null()) {
        ensure!(has("tls_fragment"), "TLS fragmentation applies to the connecting side of a TLS carrier only");
        let entry = &mut config[key][0];
        if on.as_bool().context("tls_fragment must be true or false")? {
            entry["tls_fragment"] = json!({"enabled": true});
        } else if let Some(object) = entry.as_object_mut() {
            object.remove("tls_fragment");
        }
    }
    if let Some(game) = carrier.get("game").filter(|v| !v.is_null()) {
        ensure!(has("game"), "Game mode is not offered for this tunnel");
        if game["on"].as_bool().unwrap_or(false) {
            let port = game["port"].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0)
                .context("the Game mode port must be 1 to 65535")?;
            let copies = game["copies"].as_u64().filter(|c| (1..=4).contains(c)).context("Game mode copies must be 1 to 4")? as u8;
            let iran_host = game["iran_address"].as_str().map(str::trim).filter(|h| !h.is_empty()).map(str::to_string);
            crate::manager::tune::set_game_config(config, Some((port, copies, iran_host)))?;
            let now = Scope::of_config(config)?;
            if speed::applies(now.transport, now.parallax_packet)
                && speed::detect(config, now.transport) == Some(SpeedMode::Default)
            {
                speed::apply_config(config, now.transport, SpeedMode::Fast3);
            }
        } else {
            crate::manager::tune::set_game_config(config, None)?;
        }
    }
    let after = Scope::of_config(config)?;
    for setting in crate::manager::scope::stale(&before, &after, config) {
        apply_setting(config, &setting, None)?;
    }
    // A carrier object left empty by the removals is not written either.
    if let Some(entry) = config[key][0].as_object_mut() {
        entry.retain(|name, value| {
            !(matches!(name.as_str(), "parallax" | "fec" | "tls_fragment")
                && value.as_object().is_some_and(|o| o.is_empty()))
        });
    }
    Ok(())
}

/// The configuration with `changes` applied: `{"ports": {"text", "protocol"}, "quota": {"limit_gb",
/// "period_days"}, "settings": [{"name", "place", "value"}]}`; each part is optional, a setting
/// value of `null` goes back to its default. Every value is checked against its allowed range.
pub fn apply(config: &Value, changes: &Value) -> Result<Value> {
    let mut edited = config.clone();
    if let Some(ports) = changes.get("ports").filter(|p| !p.is_null()) {
        ensure!(has_ports(config), "this tunnel does not forward ports here");
        let text = ports["text"].as_str().context("ports.text is missing")?;
        let rules = parse_ports(text)?;
        ensure!(!rules.is_empty(), "give at least one port");
        let protocol = protocol_of(ports["protocol"].as_str().unwrap_or("tcp"))?;
        edited = with_ports(&edited, &rules, protocol);
    }
    if let Some(quota) = changes.get("quota").filter(|q| !q.is_null()) {
        let limit = quota["limit_gb"].as_u64().context("quota.limit_gb must be a whole number")?;
        let days = quota["period_days"].as_u64().unwrap_or(30);
        ensure!(limit <= 1_000_000, "the traffic limit must be 0 (none) to 1000000 GB");
        ensure!((1..=3650).contains(&days), "the period must be 1 to 3650 days");
        if limit == 0 {
            if let Some(object) = edited.as_object_mut() {
                object.remove("quota");
            }
        } else {
            edited["quota"] = json!({"limit_gb": limit, "period_days": days});
        }
    }
    if let Some(version) = changes.get("proxy_protocol").filter(|p| !p.is_null()) {
        ensure!(has_ports(config), "this tunnel does not forward ports here");
        let version = version.as_u64().filter(|v| *v <= 2).context("PROXY protocol must be 0 (off), 1 or 2")?;
        for map in edited["listeners"][0]["maps"].as_array_mut().into_iter().flatten() {
            if map["type"] == "udp" {
                continue;
            }
            if version == 0 {
                if let Some(object) = map.as_object_mut() {
                    object.remove("proxy_protocol");
                }
            } else {
                map["proxy_protocol"] = json!(version);
            }
        }
    }
    if let Some(hours) = changes.get("restart_hours").filter(|h| !h.is_null()) {
        let hours = hours.as_u64().filter(|h| *h <= 8760).context("the restart interval must be 0 (never) to 8760 hours")?;
        let setting = settings_of(config)?
            .into_iter()
            .find(|s| s.name == "schedule.restart_every_hours")
            .context("this tunnel has no scheduled restart setting")?;
        apply_setting(&mut edited, &setting, (hours > 0).then_some(hours))?;
    }
    if let Some(list) = changes.get("settings").and_then(Value::as_array) {
        let known: Vec<Setting> = settings_of(config)?;
        for change in list {
            let name = change["name"].as_str().context("a setting without a name")?;
            let place = change["place"].as_str().unwrap_or("top");
            let setting = known
                .iter()
                .find(|s| s.name == name && place_word(s.place) == place)
                .with_context(|| format!("{name} is not a setting of this tunnel"))?;
            let value = match &change["value"] {
                Value::Null => None,
                value => {
                    let value = value.as_u64().with_context(|| format!("{name} must be a whole number"))?;
                    ensure!(
                        (setting.min..=setting.max).contains(&value),
                        "{name} must be {} to {}",
                        setting.min,
                        setting.max
                    );
                    Some(value)
                }
            };
            apply_setting(&mut edited, setting, value)?;
        }
    }
    if let Some(carrier) = changes.get("carrier").filter(|c| !c.is_null()) {
        apply_carrier(&mut edited, carrier)?;
    }
    plan::check(&edited).context("the changed settings are not valid")?;
    Ok(edited)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iran() -> Value {
        json!({
            "mode": "server", "tunnel_key": crate::tunnel_key::TunnelKey::generate().unwrap().display(),
            "listeners": [{"addr": "0.0.0.0:7000", "transport": "tcp",
                "maps": [{"type": "tcp", "bind": "0.0.0.0:443", "target": "127.0.0.1:443"},
                         {"type": "udp", "bind": "0.0.0.0:9392", "target": "127.0.0.1:9392"}]}]
        })
    }

    #[test]
    fn the_edit_screen_lists_ports_limit_and_settings() {
        let screen = editable(&iran()).unwrap();
        assert_eq!(screen["ports"]["text"], "443, 9392");
        assert_eq!(screen["ports"]["protocol"], "both");
        assert_eq!(screen["quota"]["limit_gb"], 0);
        let names: Vec<&str> = screen["settings"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"stream_window"), "{names:?}");
        assert!(!names.iter().any(|n| n.starts_with("quota.")), "{names:?}");
        // A foreign end has no ports to edit.
        let foreign = json!({"mode": "client", "tunnel_key": iran()["tunnel_key"], "allowed_targets": ["127.0.0.1:443"],
            "paths": [{"addr": "203.0.113.10:7000", "transport": "tcp"}]});
        assert!(editable(&foreign).unwrap()["ports"].is_null());
    }

    #[test]
    fn carrier_choices_follow_the_tunnel_and_mode_switches_clean_up() {
        let key = iran()["tunnel_key"].clone();
        // The foreign end of a reverse Parallax tunnel dials: mode, pool and (packet) speed.
        let foreign = json!({"mode": "client", "tunnel_key": key, "allowed_targets": ["127.0.0.1:*"],
            "paths": [{"addr": "203.0.113.10:7003", "transport": "parallax", "connection_pool": 4,
                       "parallax": {"buffer_bytes": 131072}}]});
        let carrier = &editable(&foreign).unwrap()["carrier"];
        assert_eq!(carrier["parallax_mode"], "stream");
        assert_eq!(carrier["pool"], 4);
        assert!(carrier["speed"].is_null(), "stream mode has no speed mode");
        assert!(carrier["tls_profile"].is_null());
        // To packet mode with a speed mode: the stream-only value goes, the FEC timer is written.
        let packet = apply(&foreign, &json!({"carrier": {"parallax_mode": "packet", "speed": "fast2"}})).unwrap();
        let path = &packet["paths"][0];
        assert_eq!(path["parallax"]["mode"], "packet");
        assert!(path["parallax"].get("buffer_bytes").is_none(), "{path}");
        assert_eq!(path["fec"]["interval_ms"], 20);
        let screen = editable(&packet).unwrap();
        assert_eq!(screen["carrier"]["speed"], "fast2");
        let names: Vec<&str> = screen["settings"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"parallax.lanes") && names.contains(&"fec.sndwnd"), "{names:?}");
        assert!(!names.contains(&"parallax.buffer_bytes"), "{names:?}");
        // And back: the packet timer and packet-only values go again.
        let mut tuned = packet.clone();
        tuned["paths"][0]["parallax"]["lanes"] = json!(4);
        let stream = apply(&tuned, &json!({"carrier": {"parallax_mode": "stream"}})).unwrap();
        assert!(stream["paths"][0].get("fec").is_none(), "{}", stream["paths"][0]);
        assert!(stream["paths"][0].get("parallax").is_none(), "{}", stream["paths"][0]);
        // Pool 1 is no longer the default: it is written. The automatic size is not.
        let one = apply(&foreign, &json!({"carrier": {"pool": 1}})).unwrap();
        assert_eq!(one["paths"][0]["connection_pool"], 1);
        let auto = crate::config::Transport::Parallax.auto_pool() as u64;
        let automatic = apply(&one, &json!({"carrier": {"pool": auto}})).unwrap();
        assert!(automatic["paths"][0].get("connection_pool").is_none());
        // TLS look and fragmentation: only on the dialing side of a TLS carrier.
        let wss = json!({"mode": "client", "tunnel_key": iran()["tunnel_key"], "allowed_targets": ["127.0.0.1:*"],
            "paths": [{"addr": "203.0.113.10:443", "transport": "wss", "tls_auto": true}]});
        let on = apply(&wss, &json!({"carrier": {"tls_fragment": true}})).unwrap();
        assert_eq!(on["paths"][0]["tls_fragment"]["enabled"], true);
        let mut set = on.clone();
        set["paths"][0]["tls_fragment"]["min_bytes"] = json!(20);
        let off = apply(&set, &json!({"carrier": {"tls_fragment": false}})).unwrap();
        assert!(off["paths"][0].get("tls_fragment").is_none());
        // Choices the tunnel does not have are refused.
        for (config, carrier) in [
            (iran(), json!({"parallax_mode": "packet"})),
            (iran(), json!({"pool": 2})),
            (iran(), json!({"tls_fragment": true})),
            (iran(), json!({"speed": "fast"})),
            (foreign.clone(), json!({"speed": "fast"})),
            (foreign.clone(), json!({"pool": 17})),
            (foreign.clone(), json!({"parallax_mode": "turbo"})),
            (wss.clone(), json!({"tls_profile": "firefox"})),
        ] {
            assert!(apply(&config, &json!({"carrier": carrier})).is_err(), "{carrier}");
        }
    }

    #[test]
    fn game_mode_can_be_switched_from_edit() {
        let screen = editable(&iran()).unwrap();
        assert_eq!(screen["carrier"]["game"]["on"], false, "a UDP map offers Game mode");
        assert_eq!(screen["carrier"]["game"]["port"], 7001);
        let on = apply(&iran(), &json!({"carrier": {"game": {"on": true, "port": 45001, "copies": 3}}})).unwrap();
        assert_eq!(on["gaming"], json!({"control_address": "0.0.0.0:45001", "udp_bind": "0.0.0.0:45001", "copies": 3}));
        assert_eq!(editable(&on).unwrap()["carrier"]["game"]["on"], true);
        let off = apply(&on, &json!({"carrier": {"game": {"on": false}}})).unwrap();
        assert!(off.get("gaming").is_none());
        // A foreign end of a reverse tunnel connects to the Iran address it already dials.
        let foreign = json!({"mode": "client", "tunnel_key": iran()["tunnel_key"], "allowed_targets": ["127.0.0.1:*"],
            "paths": [{"addr": "203.0.113.10:7000", "transport": "fec-udp"}]});
        let on = apply(&foreign, &json!({"carrier": {"game": {"on": true, "port": 7001, "copies": 2}}})).unwrap();
        assert_eq!(on["gaming"]["control_address"], "203.0.113.10:7001");
        assert_eq!(on["paths"][0]["fec"]["interval_ms"], 10, "fast3 comes with it");
        // TCP-only forwarding: nothing to speed up.
        let mut tcp = iran();
        tcp["listeners"][0]["maps"] = json!([{"type": "tcp", "bind": "0.0.0.0:443", "target": "127.0.0.1:443"}]);
        assert!(editable(&tcp).unwrap()["carrier"]["game"].is_null());
        assert!(apply(&tcp, &json!({"carrier": {"game": {"on": true, "port": 7001, "copies": 3}}})).is_err());
        for bad in [json!({"on": true, "port": 0, "copies": 3}), json!({"on": true, "port": 7001, "copies": 9})] {
            assert!(apply(&iran(), &json!({"carrier": {"game": bad}})).is_err());
        }
    }

    #[test]
    fn changes_are_applied_checked_and_limited() {
        let config = iran();
        let edited = apply(&config, &json!({
            "ports": {"text": "443, 8443", "protocol": "tcp"},
            "quota": {"limit_gb": 500, "period_days": 30},
            "settings": [{"name": "stream_window", "place": "top", "value": 256}]
        }))
        .unwrap();
        let screen = editable(&edited).unwrap();
        assert_eq!(screen["ports"]["text"], "443, 8443");
        assert_eq!(screen["quota"]["limit_gb"], 500);
        assert_eq!(edited["stream_window"], 256);
        // PROXY protocol on the TCP maps only, and a scheduled restart.
        let more = apply(&edited, &json!({"proxy_protocol": 2, "restart_hours": 24})).unwrap();
        let maps = more["listeners"][0]["maps"].as_array().unwrap();
        assert!(maps.iter().all(|m| (m["type"] == "tcp") == (m["proxy_protocol"] == 2)), "{maps:?}");
        assert_eq!(more["schedule"]["restart_every_hours"], 24);
        let screen = editable(&more).unwrap();
        assert_eq!(screen["ports"]["proxy_protocol"], 2);
        assert_eq!(screen["restart_hours"], 24);
        let off = apply(&more, &json!({"proxy_protocol": 0, "restart_hours": 0})).unwrap();
        assert!(off["listeners"][0]["maps"].as_array().unwrap().iter().all(|m| m.get("proxy_protocol").is_none()));
        assert_eq!(editable(&off).unwrap()["restart_hours"], 0);
        assert!(apply(&more, &json!({"proxy_protocol": 3})).is_err());
        assert!(apply(&more, &json!({"restart_hours": 9000})).is_err());
        // Back to the default, and no limit.
        let back = apply(&edited, &json!({"quota": {"limit_gb": 0}, "settings": [{"name": "stream_window", "place": "top", "value": null}]})).unwrap();
        assert!(back.get("quota").is_none());
        assert!(back.get("stream_window").is_none());
        for bad in [
            json!({"settings": [{"name": "stream_window", "place": "top", "value": 999_999}]}),
            json!({"settings": [{"name": "rm -rf", "place": "top", "value": 1}]}),
            json!({"quota": {"limit_gb": 5, "period_days": 0}}),
            json!({"ports": {"text": "", "protocol": "tcp"}}),
            json!({"ports": {"text": "443", "protocol": "sctp"}}),
        ] {
            assert!(apply(&config, &bad).is_err(), "{bad}");
        }
    }
}
