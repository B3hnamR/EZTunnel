//! A new tunnel from the dashboard: both ends are built here from one form, with one fresh key, the
//! same way the terminal manager builds a tunnel and its pairing code, with the same per-carrier
//! options (TLS look and fragmentation, TCP congestion control, FEC pacer, speed mode, Parallax
//! mode, parallel connections). Raw-socket, TUN and Mirage tunnels and CDN setups need
//! measurements or choices on the machine, so they stay in the terminal manager.
use crate::{
    config::Transport,
    manager::plan::{self, Carry, Direction, Plan, Protocol, Side, check_name, parse_ports},
    tunnel_key::TunnelKey,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

/// The carriers the dashboard can set up, in the order it offers them.
pub const TRANSPORTS: [&str; 10] =
    ["tcp", "wss", "xhttps", "https", "parallax", "fec-udp", "kcp", "xhttp", "ws", "http"];

/// Which of the optional choices a carrier has, for the form (`GET /api/new-tunnel`).
pub fn options_of(transport: Transport) -> Value {
    json!({
        "tls": transport.uses_tls(),
        "congestion": !plan::uses_udp(transport) && !plan::is_raw(transport),
        "pacer": matches!(transport, Transport::FecUdp),
        "speed": crate::manager::speed::applies(transport, false),
        "parallax": transport == Transport::Parallax,
        "game": !plan::is_raw(transport),
    })
}

fn speed_of(word: &str) -> Result<crate::manager::speed::SpeedMode> {
    crate::manager::speed::SpeedMode::from_label(word).with_context(|| format!("unknown speed mode {word}"))
}

/// Both ends of a new tunnel.
#[derive(Debug, Clone, PartialEq)]
pub struct Built {
    pub iran: Value,
    pub foreign: Value,
    /// Which end listens and so is started first.
    pub listening: Side,
}

fn transport_of(word: &str) -> Result<Transport> {
    ensure!(TRANSPORTS.contains(&word), "{word} cannot be set up from the dashboard; use the terminal manager");
    serde_json::from_value(json!(word)).context("unknown transport")
}

/// The form: `name`, `transport`, `direction` ("reverse" or "direct"), `tunnel_port`, `address`
/// (where the dialing end connects), `carry` ("ports" or "socks"), `ports`, `protocol`
/// ("tcp", "udp" or "both"), `socks_bind`, `reach` ("local" or "any"); optional, each only where
/// the carrier has it: `parallax_mode` ("stream" or "packet"), `tls_profile` ("classic" or
/// "chrome"), `tls_fragment`, `tcp_congestion` (an algorithm name or "system"), `fec_pacer`,
/// `speed` ("default", "normal", "fast", "fast2", "fast3"), `pool` (1 to 16), `game` (Game mode:
/// game UDP on the direct datagram path in copies) with `game_port`, `game_copies` and, for a
/// direct tunnel, `iran_address` (how the foreign server reaches the Iran server).
pub fn build(form: &Value) -> Result<Built> {
    let text = |key: &str| form[key].as_str().unwrap_or("").trim().to_string();
    let name = text("name");
    check_name(&name)?;
    // IPv6 is the list's entry for routes that block IPv4: `ipv6_transport` runs between the
    // servers' IPv6 addresses. GAME is the entry for games: FEC-UDP with Game mode on.
    let ipv6_entry = text("transport") == "ipv6";
    let chosen = if ipv6_entry { text("ipv6_transport") } else { text("transport") };
    ensure!(!(ipv6_entry && chosen.is_empty()), "choose the transport to run over IPv6");
    let game_entry = chosen == "game";
    let transport = if game_entry { Transport::FecUdp } else { transport_of(&chosen)? };
    let direction = match text("direction").as_str() {
        "" | "reverse" => Direction::Reverse,
        "direct" => Direction::Direct,
        other => bail!("unknown direction {other}"),
    };
    let tunnel_port = match &form["tunnel_port"] {
        Value::Null => plan::default_tunnel_port(transport),
        value => value
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p > 0)
            .context("the tunnel port must be 1 to 65535")?,
    };
    let address = text("address");
    ensure!(!address.is_empty(), "the address of the server the other end connects to is missing");
    let ipv6 = ipv6_entry || address.trim_matches(['[', ']']).parse::<std::net::Ipv6Addr>().is_ok();
    ensure!(
        !ipv6_entry || address.trim_matches(['[', ']']).parse::<std::net::Ipv6Addr>().is_ok(),
        "an IPv6 tunnel needs the IPv6 address of the server the other end connects to"
    );
    ensure!(
        !address.contains(['/', ' ', '@']) && address.len() <= 253,
        "the address must be an IP address or a host name"
    );
    let carry = match text("carry").as_str() {
        "" | "ports" => Carry::Ports,
        "socks" => Carry::Socks,
        other => bail!("{other} cannot be set up from the dashboard; use the terminal manager"),
    };
    let protocol = match text("protocol").as_str() {
        "" | "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "both" => Protocol::Both,
        other => bail!("unknown protocol {other}"),
    };
    let options = options_of(transport);
    let flag = |key: &str| form[key].as_bool().unwrap_or(false);
    let offered = |key: &str, what: &str| -> Result<()> {
        ensure!(options[what] == true, "{key} does not apply to {}", text("transport"));
        Ok(())
    };
    let parallax_mode = match text("parallax_mode").as_str() {
        "" | "stream" => crate::parallax_carrier::Mode::Stream,
        "packet" => {
            offered("parallax_mode", "parallax")?;
            crate::parallax_carrier::Mode::Packet
        }
        other => bail!("unknown Parallax mode {other}"),
    };
    let tls_profile = match text("tls_profile").as_str() {
        "" | "classic" => crate::config::TlsProfile::Classic,
        "chrome" => {
            offered("tls_profile", "tls")?;
            crate::config::TlsProfile::Chrome
        }
        other => bail!("unknown TLS look {other}"),
    };
    if flag("tls_fragment") {
        offered("tls_fragment", "tls")?;
    }
    let congestion = match text("tcp_congestion").as_str() {
        "" => None,
        word => {
            offered("tcp_congestion", "congestion")?;
            ensure!(
                word.len() <= 16 && word.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "tcp_congestion must be an algorithm name such as bbr or cubic, or system"
            );
            Some(word.to_string())
        }
    };
    if flag("fec_pacer") {
        offered("fec_pacer", "pacer")?;
    }
    let speed = match text("speed").as_str() {
        "" => crate::manager::speed::SpeedMode::Default,
        word => {
            ensure!(
                crate::manager::speed::applies(transport, parallax_mode == crate::parallax_carrier::Mode::Packet),
                "a speed mode does not apply to {}",
                text("transport")
            );
            speed_of(word)?
        }
    };
    let pool = match &form["pool"] {
        Value::Null => None,
        value => Some(
            value
                .as_u64()
                .filter(|p| (1..=16).contains(p))
                .context("parallel connections must be 1 to 16")? as usize,
        ),
    };
    let game = if game_entry || flag("game") {
        offered("game", "game")?;
        ensure!(
            carry == Carry::Socks || protocol != Protocol::Tcp,
            "Game mode needs UDP: forward UDP (or TCP and UDP) or use SOCKS5"
        );
        let port = match &form["game_port"] {
            Value::Null => plan::game_port(tunnel_port),
            value => value.as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0)
                .context("the Game mode port must be 1 to 65535")?,
        };
        let copies = match &form["game_copies"] {
            Value::Null => plan::GAME_COPIES,
            value => value.as_u64().filter(|c| (1..=4).contains(c)).context("Game mode copies must be 1 to 4")? as u8,
        };
        let iran_host = match text("iran_address").as_str() {
            "" => None,
            host => {
                let host = host.trim_matches(['[', ']']);
                ensure!(host.parse::<std::net::IpAddr>().is_ok(), "the Iran address for Game mode must be an IP address");
                Some(host.to_string())
            }
        };
        ensure!(
            direction == Direction::Reverse || iran_host.is_some(),
            "Game mode in a direct tunnel needs the Iran server's address"
        );
        Some(plan::GamePlan { port, copies, iran_host })
    } else {
        None
    };
    let key = TunnelKey::generate()?.display();
    let plan_for = |side: Side| -> Result<Plan> {
        let mut plan = Plan::new(key.clone(), side, direction, transport);
        plan.tunnel_port = tunnel_port;
        plan.carry = carry;
        plan.protocol = protocol;
        plan.parallax_mode = parallax_mode;
        plan.tls_profile = tls_profile;
        plan.tls_fragment = flag("tls_fragment");
        plan.tcp_congestion = congestion.clone();
        plan.fec_pacer = flag("fec_pacer");
        plan.speed = speed;
        if game.is_some() {
            plan.set_game(true);
            plan.game = game.clone();
        }
        if let Some(pool) = pool {
            plan.pool = pool;
        }
        if plan.dials() {
            plan.peer_host = Some(address.clone());
        } else if ipv6 {
            // An IPv6 tunnel: the other end comes to this server's IPv6 address.
            plan.listen_on_both_families();
        }
        plan.ipv6 = ipv6;
        match carry {
            Carry::Ports => {
                plan.ports = parse_ports(&text("ports"))?;
                ensure!(!plan.ports.is_empty(), "give at least one port");
            }
            _ => {
                let bind = text("socks_bind");
                if !bind.is_empty() {
                    ensure!(bind.parse::<std::net::SocketAddr>().is_ok(), "the SOCKS5 address must look like 127.0.0.1:1080");
                    plan.socks_bind = bind;
                }
            }
        }
        if side == Side::Foreign {
            plan.allowed = match (carry, text("reach").as_str()) {
                (Carry::Socks, _) | (_, "any") => vec!["*".into()],
                _ => vec!["127.0.0.1:*".into()],
            };
        }
        Ok(plan)
    };
    let iran = plan_for(Side::Iran)?;
    let foreign = plan_for(Side::Foreign)?;
    let listening = if iran.dials() { Side::Foreign } else { Side::Iran };
    let (iran, foreign) = (iran.to_json()?, foreign.to_json()?);
    plan::check(&iran).context("the Iran end would not be valid")?;
    plan::check(&foreign).context("the foreign end would not be valid")?;
    Ok(Built { iran, foreign, listening })
}

/// Whether a configuration is one the dashboard may create (what `build` makes): an agent refuses
/// anything else, so a hub can never install a raw-socket or TUN tunnel on it.
pub fn creatable(config: &Value) -> Result<()> {
    ensure!(config.get("tun").is_none_or(Value::is_null), "TUN tunnels are set up in the terminal manager");
    let entries = config["listeners"].as_array().or(config["paths"].as_array()).context("no listener or path")?;
    ensure!(entries.len() == 1, "one listener or path is expected");
    let transport = entries[0]["transport"].as_str().unwrap_or("tcp");
    ensure!(TRANSPORTS.contains(&transport), "{transport} tunnels are set up in the terminal manager");
    ensure!(entries[0].get("raw").is_none_or(Value::is_null), "raw tunnels are set up in the terminal manager");
    plan::check(config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(transport: &str, direction: &str) -> Value {
        json!({"name": "game", "transport": transport, "direction": direction, "address": "203.0.113.7",
               "carry": "ports", "ports": "9392, 2083=443", "protocol": "both", "reach": "local"})
    }

    #[test]
    fn both_ends_share_one_key_and_the_right_end_dials() {
        for transport in TRANSPORTS {
            for direction in ["reverse", "direct"] {
                let f = form(transport, direction);
                let peer = "203.0.113.7:";
                let built = build(&f).unwrap_or_else(|e| panic!("{transport} {direction}: {e:#}"));
                assert_eq!(built.iran["tunnel_key"], built.foreign["tunnel_key"]);
                // The IPv6 entry with this transport: the dialing end goes to the IPv6 address,
                // the listening end listens on IPv6.
                {
                    let mut v6 = f.clone();
                    v6["transport"] = json!("ipv6");
                    v6["ipv6_transport"] = json!(transport);
                    v6["address"] = json!("2001:db8::7");
                    let built6 = build(&v6).unwrap_or_else(|e| panic!("{transport} {direction} over IPv6: {e:#}"));
                    let (listening, dialing) = if direction == "reverse" { (&built6.iran["listeners"][0], &built6.foreign["paths"][0]) } else { (&built6.foreign["paths"][0], &built6.iran["listeners"][0]) };
                    assert!(dialing["addr"].as_str().unwrap().starts_with("[2001:db8::7]:"), "{transport} {direction}: {dialing}");
                    assert!(listening["addr"].as_str().unwrap().starts_with("[::]:"), "{transport} {direction}: {listening}");
                    let mut v4_address = v6.clone();
                    v4_address["address"] = json!("203.0.113.7");
                    assert!(build(&v4_address).is_err(), "the IPv6 entry needs an IPv6 address");
                    crate::manager::plan::check(&built6.iran).unwrap();
                    crate::manager::plan::check(&built6.foreign).unwrap();
                }
                assert_eq!(built.iran["mode"], "server");
                assert_eq!(built.foreign["mode"], "client");
                let iran_addr = built.iran["listeners"][0]["addr"].as_str().unwrap();
                let foreign_addr = built.foreign["paths"][0]["addr"].as_str().unwrap();
                if direction == "reverse" {
                    assert_eq!(built.listening, Side::Iran);
                    assert!(foreign_addr.starts_with(peer), "{foreign_addr}");
                } else {
                    assert_eq!(built.listening, Side::Foreign);
                    assert_eq!(built.iran["server_dials"], true);
                    assert!(iran_addr.starts_with(peer), "{iran_addr}");
                }
                assert_eq!(built.foreign["allowed_targets"], json!(["127.0.0.1:*"]));
                creatable(&built.iran).unwrap();
                creatable(&built.foreign).unwrap();
            }
        }
        // Two tunnels never share a key.
        assert_ne!(build(&form("tcp", "reverse")).unwrap().iran["tunnel_key"], build(&form("tcp", "reverse")).unwrap().iran["tunnel_key"]);
    }

    #[test]
    fn ports_socks_and_reach_are_written_on_the_right_end() {
        let built = build(&form("tcp", "reverse")).unwrap();
        let maps = built.iran["listeners"][0]["maps"].as_array().unwrap();
        assert_eq!(maps.len(), 4, "{maps:?}");
        let mut socks = form("wss", "reverse");
        socks["carry"] = json!("socks");
        socks["socks_bind"] = json!("0.0.0.0:1080");
        let built = build(&socks).unwrap();
        assert_eq!(built.iran["socks5"], "0.0.0.0:1080");
        assert_eq!(built.foreign["allowed_targets"], json!(["*"]));
        let mut any = form("tcp", "reverse");
        any["reach"] = json!("any");
        assert_eq!(build(&any).unwrap().foreign["allowed_targets"], json!(["*"]));
    }

    #[test]
    fn carrier_options_reach_the_right_end() {
        // Parallax packet mode: both ends, since the mode must match.
        let mut parallax = form("parallax", "reverse");
        parallax["parallax_mode"] = json!("packet");
        parallax["speed"] = json!("fast2");
        parallax["pool"] = json!(3);
        let built = build(&parallax).unwrap();
        for end in [&built.iran, &built.foreign] {
            let entry = end.get("listeners").or(end.get("paths")).unwrap();
            assert_eq!(entry[0]["parallax"]["mode"], "packet");
            assert_eq!(entry[0]["fec"]["interval_ms"], 20, "speed mode on the packet session");
            creatable(end).unwrap();
        }
        assert_eq!(crate::manager::plan::pool_now(&built.foreign["paths"][0], crate::config::Transport::Parallax), 3, "the dialing end keeps the pool");
        // TLS look and fragmentation: only the dialing end (the foreign one in a reverse tunnel).
        let mut wss = form("wss", "reverse");
        // The browser-like look exists only in builds with that feature; others refuse it.
        if cfg!(feature = "browser-tls") {
            wss["tls_profile"] = json!("chrome");
        }
        wss["tls_fragment"] = json!(true);
        wss["tcp_congestion"] = json!("cubic");
        let built = build(&wss).unwrap();
        let path = &built.foreign["paths"][0];
        if cfg!(feature = "browser-tls") {
            assert_eq!(path["tls_profile"], "chrome");
        }
        assert_eq!(path["tls_fragment"]["enabled"], true);
        assert_eq!(path["tcp_congestion"], "cubic");
        let listener = &built.iran["listeners"][0];
        assert!(listener.get("tls_fragment").is_none() && listener.get("tcp_congestion").is_none());
        // FEC pacer on fec-udp.
        let mut fec = form("fec-udp", "direct");
        fec["fec_pacer"] = json!(true);
        let built = build(&fec).unwrap();
        assert_eq!(built.iran["paths"].get(0).or(built.iran["listeners"].get(0)).unwrap()["fec"]["pacer"], true);
        // An option the carrier does not have is refused, not silently dropped.
        for (transport, key, value) in [("tcp", "tls_fragment", json!(true)), ("tcp", "parallax_mode", json!("packet")),
            ("wss", "fec_pacer", json!(true)), ("kcp", "tcp_congestion", json!("cubic")), ("tcp", "speed", json!("fast")),
            ("parallax", "speed", json!("fast")), ("tcp", "pool", json!(17))] {
            let mut bad = form(transport, "reverse");
            bad[key] = value;
            assert!(build(&bad).is_err(), "{transport} {key}");
        }
    }

    #[test]
    fn game_mode_is_written_on_both_ends() {
        let mut game = form("fec-udp", "reverse");
        game["game"] = json!(true);
        let built = build(&game).unwrap();
        let port = plan::default_tunnel_port(Transport::FecUdp) + 1;
        assert_eq!(built.iran["gaming"]["control_address"], format!("0.0.0.0:{port}"));
        assert_eq!(built.foreign["gaming"]["control_address"], format!("203.0.113.7:{port}"));
        assert_eq!(built.foreign["gaming"]["copies"], 3);
        assert_eq!(built.foreign["paths"][0]["fec"]["interval_ms"], 10, "fast3 for the carrier");
        creatable(&built.iran).unwrap();
        creatable(&built.foreign).unwrap();
        // Direct: the foreign end needs the Iran address; TCP-only forwarding has no game UDP.
        let mut direct = form("tcp", "direct");
        direct["game"] = json!(true);
        assert!(build(&direct).is_err());
        direct["iran_address"] = json!("198.51.100.30");
        direct["game_port"] = json!(45001);
        direct["game_copies"] = json!(2);
        let built = build(&direct).unwrap();
        assert_eq!(built.foreign["gaming"]["control_address"], "198.51.100.30:45001");
        assert_eq!(built.foreign["gaming"]["copies"], 2);
        let mut tcp_only = form("tcp", "reverse");
        tcp_only["game"] = json!(true);
        tcp_only["protocol"] = json!("tcp");
        assert!(build(&tcp_only).is_err());
        for (key, value) in [("game_copies", json!(5)), ("game_port", json!(0))] {
            let mut bad = form("tcp", "reverse");
            bad["game"] = json!(true);
            bad[key] = value;
            assert!(build(&bad).is_err(), "{key}");
        }
    }

    #[test]
    fn the_game_entry_builds_fec_udp_with_game_mode() {
        let built = build(&form("game", "reverse")).unwrap();
        for end in [&built.iran, &built.foreign] {
            let entry = end.get("listeners").or(end.get("paths")).unwrap();
            assert_eq!(entry[0]["transport"], "fec-udp");
            assert_eq!(end["gaming"]["copies"], 3);
        }
        // With TCP-only forwarding there is no game UDP: refused, not silently without Game mode.
        let mut tcp = form("game", "reverse");
        tcp["protocol"] = json!("tcp");
        assert!(build(&tcp).is_err());
    }

    #[test]
    fn bad_forms_and_machine_specific_tunnels_are_refused() {
        let with = |key: &str, value: Value| {
            let mut f = form("tcp", "reverse");
            f[key] = value;
            f
        };
        for bad in [
            with("name", json!("../x")),
            with("transport", json!("fec-raw")),
            with("transport", json!("mirage")),
            with("carry", json!("tun")),
            with("ports", json!("")),
            with("tunnel_port", json!(0)),
            with("tunnel_port", json!(70000)),
            with("address", json!("")),
            with("address", json!("a b")),
            with("direction", json!("sideways")),
        ] {
            assert!(build(&bad).is_err(), "{bad}");
        }
        let mut raw = build(&form("tcp", "reverse")).unwrap().iran;
        raw["listeners"][0]["transport"] = json!("fec-raw");
        assert!(creatable(&raw).is_err());
        let mut tun = build(&form("tcp", "reverse")).unwrap().foreign;
        tun["tun"] = json!({"name": "ez0"});
        assert!(creatable(&tun).is_err());
    }
}
