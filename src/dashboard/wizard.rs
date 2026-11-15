//! A new tunnel from the dashboard: both ends are built here from one form, with one fresh key, the
//! same way the terminal manager builds a tunnel and its pairing code. Raw-socket, TUN, Parallax and
//! Mirage tunnels and CDN setups need measurements or choices on the machine, so they stay in the
//! terminal manager.
use crate::{
    config::Transport,
    manager::plan::{self, Carry, Direction, Plan, Protocol, Side, check_name, parse_ports},
    tunnel_key::TunnelKey,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

/// The carriers the dashboard can set up, in the order it offers them.
pub const TRANSPORTS: [&str; 10] = ["tcp", "wss", "xhttps", "https", "fec-udp", "kcp", "xhttp", "ws", "http", "tcp6"];

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
/// ("tcp", "udp" or "both"), `socks_bind`, `reach` ("local" or "any").
pub fn build(form: &Value) -> Result<Built> {
    let text = |key: &str| form[key].as_str().unwrap_or("").trim().to_string();
    let name = text("name");
    check_name(&name)?;
    let transport = transport_of(&text("transport"))?;
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
    let key = TunnelKey::generate()?.display();
    let plan_for = |side: Side| -> Result<Plan> {
        let mut plan = Plan::new(key.clone(), side, direction, transport);
        plan.tunnel_port = tunnel_port;
        plan.carry = carry;
        plan.protocol = protocol;
        if plan.dials() {
            plan.peer_host = Some(address.clone());
        }
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
                let mut f = form(transport, direction);
                let peer = if transport == "tcp6" { "[2001:db8::7]:" } else { "203.0.113.7:" };
                if transport == "tcp6" {
                    f["address"] = json!("2001:db8::7");
                }
                let built = build(&f).unwrap_or_else(|e| panic!("{transport} {direction}: {e:#}"));
                assert_eq!(built.iran["tunnel_key"], built.foreign["tunnel_key"]);
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
            with("transport", json!("parallax")),
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
