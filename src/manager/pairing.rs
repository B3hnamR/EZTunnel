//! Pairing codes: one line of text that carries a tunnel's settings to the other server.
//!
//! The first server makes the code from its saved tunnel; the second server pastes it and gets
//! the matching tunnel for its own side. The code holds the tunnel key, so it must be kept as
//! secret as the key. A version prefix and a checksum catch damaged or partly copied codes.
use super::plan::{
    Carry, CdnPlan, Direction, IpMode, Plan, Protocol, RawPlan, Side, TunPlan, format_ports,
    parse_ports, read_setting, relevant_settings, unicast_ipv4,
};
use crate::config::{Mode, Transport, XhttpMode};
use crate::tunnel_key::TunnelKey;
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const PREFIX: &str = "ezt1-";
const CHECK_BYTES: usize = 4;

/// Everything the other server needs. Short field names keep the code short.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pairing {
    /// Tunnel key.
    #[serde(rename = "k")]
    pub key: String,
    /// Side of the server that made the code: "iran" or "foreign".
    #[serde(rename = "s")]
    pub creator: String,
    /// Direct tunnel (the Iran server connects out).
    #[serde(rename = "d", default)]
    pub direct: bool,
    #[serde(rename = "t")]
    pub transport: Transport,
    /// Port of the connection between the servers.
    #[serde(rename = "p")]
    pub port: u16,
    /// Address of the creating server, when the other one has to reach it.
    #[serde(rename = "a", default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// CDN domain, when the tunnel goes through a CDN.
    #[serde(rename = "c", default, skip_serializing_if = "Option::is_none")]
    pub cdn: Option<String>,
    #[serde(rename = "h", default, skip_serializing_if = "Option::is_none")]
    pub http_path: Option<String>,
    #[serde(rename = "n", default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(rename = "x", default, skip_serializing_if = "Option::is_none")]
    pub xhttp_mode: Option<XhttpMode>,
    /// TLS ClientHello fragmentation on the dialing side.
    #[serde(rename = "g", default, skip_serializing_if = "std::ops::Not::not")]
    pub tls_fragment: bool,
    /// What the TLS client of the dialing side looks like ("chrome"); absent means the classic one.
    #[serde(rename = "l", default, skip_serializing_if = "Option::is_none")]
    pub tls_profile: Option<String>,
    /// Raw carriers: packet profile and proto58 mode.
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<(String, bool)>,
    /// "ports", "socks", "tun" or "tunports".
    #[serde(rename = "w", default = "ports_word")]
    pub carry: String,
    /// Forwarded ports in the short form, when the Iran server made the code.
    #[serde(rename = "f", default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    /// "tcp", "udp" or "both".
    #[serde(rename = "u", default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// TUN: the creator's own address, the other address, MTU and forwarding port.
    #[serde(rename = "v", default, skip_serializing_if = "Option::is_none")]
    pub tun: Option<(String, String, u16, Option<u16>)>,
    /// Connections in the pool of the dialing side.
    #[serde(rename = "o", default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<usize>,
    /// Wire format: 2 = probe resistance. Absent means 1 (a creator from before it existed).
    #[serde(
        rename = "e",
        default = "wire_one",
        skip_serializing_if = "wire_is_one"
    )]
    pub wire_version: u8,
    /// Tunables, by name.
    #[serde(rename = "z", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, u64>,
}

fn wire_one() -> u8 {
    1
}

fn wire_is_one(value: &u8) -> bool {
    *value == 1
}

fn ports_word() -> String {
    "ports".into()
}

fn checksum(json: &[u8]) -> [u8; CHECK_BYTES] {
    let digest = Blake2s256::new()
        .chain_update(b"eztunnel pairing code v1\0")
        .chain_update(json)
        .finalize();
    let mut check = [0u8; CHECK_BYTES];
    check.copy_from_slice(&digest[..CHECK_BYTES]);
    check
}

pub fn encode(pairing: &Pairing) -> Result<String> {
    let mut bytes = serde_json::to_vec(pairing)?;
    let check = checksum(&bytes);
    bytes.extend_from_slice(&check);
    Ok(format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    ))
}

pub fn decode(text: &str) -> Result<Pairing> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let body = text
        .strip_prefix(PREFIX)
        .context("this is not a pairing code (they start with ezt1-)")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .ok()
        .filter(|bytes| bytes.len() > CHECK_BYTES)
        .context("the pairing code is damaged or incomplete; copy it again")?;
    let (json, check) = bytes.split_at(bytes.len() - CHECK_BYTES);
    ensure!(
        checksum(json) == check,
        "the pairing code is damaged or incomplete; copy it again"
    );
    let pairing: Pairing =
        serde_json::from_slice(json).context("the pairing code comes from a newer EZTunnel")?;
    TunnelKey::parse(&pairing.key).context("the pairing code holds an invalid key")?;
    ensure!(
        matches!(pairing.creator.as_str(), "iran" | "foreign"),
        "the pairing code names an unknown server side"
    );
    Ok(pairing)
}

/// Values in a code that this version does not understand and `to_plan` therefore drops or
/// replaces by a default (a code from a newer version): shown to the person pasting it.
pub fn ignored_values(pairing: &Pairing) -> Vec<String> {
    let mut found = Vec::new();
    if let Some(profile) = pairing.tls_profile.as_deref()
        && !matches!(profile, "classic" | "chrome")
    {
        found.push(format!("the TLS look \"{profile}\""));
    }
    if pairing.tls_profile.as_deref() == Some("chrome") && !cfg!(feature = "browser-tls") {
        found.push("the Chrome TLS look (this build does not include it)".to_string());
    }
    if !matches!(
        pairing.carry.as_str(),
        "ports" | "socks" | "tun" | "tunports"
    ) {
        found.push(format!("the carry type \"{}\"", pairing.carry));
    }
    if let Some(protocol) = pairing.protocol.as_deref()
        && !matches!(protocol, "tcp" | "udp" | "both")
    {
        found.push(format!("the protocol \"{protocol}\""));
    }
    let known: Vec<&str> = crate::settings::all().iter().map(|s| s.name).collect();
    for name in pairing.settings.keys() {
        if !known.contains(&name.as_str()) {
            found.push(format!("the setting \"{name}\""));
        }
    }
    found
}

fn side_word(side: Side) -> &'static str {
    match side {
        Side::Iran => "iran",
        Side::Foreign => "foreign",
    }
}

/// The forwarded ports, protocol and user address of a saved Iran-side tunnel.
pub fn ports_from_config(config: &Value) -> (Vec<super::plan::PortRule>, Protocol, String) {
    let mut rules: Vec<super::plan::PortRule> = Vec::new();
    let (mut tcp, mut udp) = (false, false);
    let mut public_ip = "0.0.0.0".to_string();
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
            public_ip = ip.trim_start_matches('[').trim_end_matches(']').to_string();
            if let Ok(listen) = port.parse()
                && !rules.iter().any(|r| r.listen == listen)
            {
                rules.push(super::plan::PortRule { listen, target });
            }
        }
    }
    let protocol = match (tcp, udp) {
        (true, true) => Protocol::Both,
        (false, true) => Protocol::Udp,
        _ => Protocol::Tcp,
    };
    (rules, protocol, public_ip)
}

/// Whether the other server will need this server's address to reach it.
pub fn needs_address(config: &Value) -> bool {
    let server = config["mode"] == "server";
    let server_dials = config["server_dials"].as_bool().unwrap_or(false)
        || config["reverse"].as_bool().unwrap_or(false);
    let entry = if server {
        &config["listeners"][0]
    } else {
        &config["paths"][0]
    };
    let raw = entry.get("raw").is_some_and(|raw| !raw.is_null());
    // This server listens when it is the server of a reverse tunnel or the client of a direct
    // one; raw carriers always need the peer's real address.
    raw || server != server_dials
}

/// Builds the code for a saved tunnel. `address` is how the other server reaches this one
/// (needed when `needs_address`), `cdn` the CDN domain when the other server goes through one.
pub fn from_config(
    config: &Value,
    address: Option<String>,
    cdn: Option<String>,
) -> Result<Pairing> {
    let directional=if config["mode"]=="server"{&config["listeners"][0]["raw"]["mirage"]}else{&config["paths"][0]["raw"]["mirage"]};
    ensure!(directional.is_null(),"Mirage v2 has endpoint-local transmit sources and expected receive-source sets; configure both endpoints explicitly rather than export an incomplete pairing code. See docs/mirage.md");
    let key=if config["mode"]=="server"{"listeners"}else{"paths"};
    let entry=&config[key][0];
    ensure!(config["gaming"]["control_address"].is_null() && entry["fec"]["tcp_fallback"]["address"].is_null() && !entry["raw"]["hopping"]["enabled"].as_bool().unwrap_or(false),
        "this tunnel uses endpoint-local gaming/fallback/hopping settings; configure the other endpoint explicitly using docs/transport-upgrade.md instead of exporting an incomplete pairing code");
    let mode: Mode = serde_json::from_value(config["mode"].clone()).context("mode")?;
    let server = mode == Mode::Server;
    let direct = config["server_dials"].as_bool().unwrap_or(false)
        || config["reverse"].as_bool().unwrap_or(false);
    let entry = if server {
        &config["listeners"][0]
    } else {
        &config["paths"][0]
    };
    ensure!(entry.is_object(), "the tunnel has no connection settings");
    let transport: Transport =
        serde_json::from_value(entry.get("transport").cloned().unwrap_or(Value::Null))
            .unwrap_or_default();
    let raw = entry.get("raw").filter(|raw| !raw.is_null()).map(|raw| {
        (
            raw["profile"].as_str().unwrap_or("tcp").to_string(),
            raw["proto58_mode"].as_bool().unwrap_or(false),
        )
    });
    let port = match &raw {
        Some(_) => entry["raw"]["l4_port"].as_u64().unwrap_or(0) as u16,
        None => entry["addr"]
            .as_str()
            .and_then(|addr| addr.rsplit_once(':'))
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or(0),
    };
    ensure!(port != 0, "the tunnel has no port");
    let tun = config.get("tun").filter(|tun| !tun.is_null());
    let carry = if let Some(tun) = tun {
        if tun.get("forwarding_port").is_some_and(|p| !p.is_null()) {
            "tunports"
        } else {
            "tun"
        }
    } else if config.get("socks5").is_some_and(|s| !s.is_null()) {
        "socks"
    } else {
        "ports"
    };
    let (ports, protocol) = if server && carry != "tun" && carry != "socks" {
        let (rules, protocol, _) = ports_from_config(config);
        (
            (!rules.is_empty()).then(|| format_ports(&rules)),
            Some(
                match protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    Protocol::Both => "both",
                }
                .to_string(),
            ),
        )
    } else {
        (None, None)
    };
    // The compact port syntax has one target per numeric port. Refuse a lossy
    // export rather than omit a UDP target or widen the peer's allowlist.
    if server&&carry!="tun"&&carry!="socks"{
        let rules=ports.as_deref().map(parse_ports).transpose()?.unwrap_or_default();
        for map in entry["maps"].as_array().into_iter().flatten(){
            if let (Some(bind),Some(target))=(map["bind"].as_str(),map["target"].as_str()){
                let port=bind.rsplit_once(':').and_then(|(_,p)|p.parse::<u16>().ok());
                ensure!(rules.iter().any(|rule|Some(rule.listen)==port&&rule.target==target),"this tunnel uses protocol-specific targets on one port; compact pairing cannot represent them safely. Configure the peer allowlist explicitly.");
            }
        }
    }
    // A dialing creator already knows the CDN domain from its own settings.
    let cdn = cdn.or_else(|| entry["xhttp"]["host"].as_str().map(str::to_string));
    let mut settings = BTreeMap::new();
    for setting in relevant_settings(mode, transport, direct) {
        if is_local_only(setting.name) {
            continue;
        }
        if let Some(value) = read_setting(config, &setting) {
            settings.insert(setting.name.to_string(), value);
        }
    }
    let creator_dials = raw.is_none() && server == direct;
    Ok(Pairing {
        key: config["tunnel_key"]
            .as_str()
            .context("only tunnels with a tunnel key have a pairing code")?
            .to_string(),
        creator: side_word(Side::from_mode(mode)).into(),
        direct,
        transport,
        port,
        address: if needs_address(config) { address } else { None },
        cdn,
        http_path: entry["http_path"].as_str().map(str::to_string),
        sni: entry["server_name"].as_str().map(str::to_string),
        xhttp_mode: entry["xhttp"]
            .get("mode")
            .and_then(|m| serde_json::from_value(m.clone()).ok()),
        // Both only mean something on the side that dials; on a listener they are not in effect,
        // and sending them would switch them on at the other end without anyone asking.
        tls_fragment: creator_dials && entry["tls_fragment"]["enabled"].as_bool().unwrap_or(false),
        tls_profile: entry["tls_profile"]
            .as_str()
            .filter(|profile| creator_dials && *profile != "classic")
            .map(str::to_string),
        raw,
        carry: carry.into(),
        ports,
        protocol,
        tun: tun.map(|tun| {
            (
                tun["address"].as_str().unwrap_or_default().to_string(),
                tun["peer_address"].as_str().unwrap_or_default().to_string(),
                tun["mtu"].as_u64().unwrap_or(1400) as u16,
                tun["forwarding_port"].as_u64().map(|p| p as u16),
            )
        }),
        pool: creator_dials
            .then(|| entry["connection_pool"].as_u64())
            .flatten()
            .map(|p| p as usize),
        wire_version: config["wire_version"]
            .as_u64()
            .map_or(1, |version| version.min(u64::from(u8::MAX)) as u8),
        settings,
    })
}

/// What the importing server still has to answer itself.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Missing {
    /// The Iran server must say which ports to forward.
    pub ports: bool,
    /// The Iran server must choose between port forwarding and SOCKS5.
    pub carry: bool,
    /// This server is the origin behind the other server's CDN: the code holds the CDN's port
    /// (80 or 443), not the port the CDN forwards to, so this server must pick its own.
    pub port: bool,
}

/// The other server's tunnel, from a code.
pub fn to_plan(pairing: &Pairing) -> Result<(Plan, Missing)> {
    let creator = if pairing.creator == "iran" {
        Side::Iran
    } else {
        Side::Foreign
    };
    let side = creator.other();
    let direction = if pairing.direct {
        Direction::Direct
    } else {
        Direction::Reverse
    };
    let mut plan = Plan::new(
        TunnelKey::parse(&pairing.key)?.display(),
        side,
        direction,
        pairing.transport,
    );
    plan.tunnel_port = pairing.port;
    plan.wire_version = pairing.wire_version;
    let mut missing = Missing::default();
    if pairing.transport == Transport::Mirage {
        ensure!(
            pairing
                .raw
                .as_ref()
                .is_some_and(|(profile, proto)| profile == "tcp" && !*proto),
            "Mirage pairing requires the TCP-looking raw profile without proto58"
        );
    }
    if let Some((profile, proto58)) = &pairing.raw {
        let address = pairing
            .address
            .as_deref()
            .context("the code has no address for the other server")?;
        plan.raw = Some(RawPlan {
            profile: profile.clone(),
            peer_ip: unicast_ipv4(address)?,
            ip_mode: if *proto58 {
                IpMode::Proto58
            } else {
                IpMode::Normal
            },
            interface: None,
            local_ip: None,
            mirage: None,
        });
    } else if plan.dials() {
        match pairing.cdn.as_deref().filter(|d| !d.is_empty()) {
            Some(domain) => {
                plan.cdn = Some(CdnPlan {
                    domain: domain.to_string(),
                })
            }
            None => {
                plan.peer_host = Some(
                    pairing
                        .address
                        .clone()
                        .context("the code has no address for this server to connect to")?,
                )
            }
        }
    } else if pairing.cdn.is_some() {
        // This server is the CDN's origin.
        plan.cdn = Some(CdnPlan {
            domain: String::new(),
        });
        // The code has the port the other server dials on the CDN. The CDN forwards to a port of
        // the origin that only this server knows; suggest one the usual CDNs support.
        plan.tunnel_port = if plan.transport.uses_tls() {
            8443
        } else {
            8080
        };
        missing.port = true;
    }
    if let Some(path) = &pairing.http_path {
        plan.http_path = path.clone();
    }
    if plan.dials() && plan.cdn.is_none() {
        plan.sni = pairing.sni.clone();
    }
    if let Some(mode) = pairing.xhttp_mode {
        plan.xhttp_mode = mode;
    }
    plan.tls_fragment = pairing.tls_fragment;
    if pairing.tls_profile.as_deref() == Some("chrome") && cfg!(feature = "browser-tls") {
        plan.tls_profile = crate::config::TlsProfile::Chrome;
    }
    plan.carry = match pairing.carry.as_str() {
        "socks" => Carry::Socks,
        "tun" => Carry::Tun,
        "tunports" => Carry::TunPorts,
        _ => Carry::Ports,
    };
    if let Some((creator_ip, other_ip, mtu, forwarding_port)) = &pairing.tun {
        plan.tun = Some(TunPlan {
            name: "ez0".into(),
            local_ip: other_ip.clone(),
            peer_ip: creator_ip.clone(),
            mtu: *mtu,
            forwarding_port: *forwarding_port,
            fragment: false,
        });
        // The creator's MTU may not fit through this server's interface.
        if let (Some(raw), Some(tun)) = (&plan.raw, &mut plan.tun)
            && let Some((fits, _, _)) = super::iface::plan_tun_mtu(raw)
        {
            tun.mtu = tun.mtu.min(fits);
        }
    }
    match side {
        Side::Iran => {
            if matches!(plan.carry, Carry::Ports | Carry::TunPorts) {
                match &pairing.ports {
                    Some(ports) => plan.ports = parse_ports(ports)?,
                    None => missing.ports = true,
                }
                // A foreign server does not know whether ports or SOCKS5 are wanted.
                missing.carry = creator == Side::Foreign && plan.carry == Carry::Ports;
            }
            plan.protocol = match pairing.protocol.as_deref() {
                Some("udp") => Protocol::Udp,
                Some("both") => Protocol::Both,
                _ => Protocol::Tcp,
            };
        }
        Side::Foreign => {
            // What this server may reach for the other one. A SOCKS5 exit needs "*" (that is what
            // it is); port forwarding needs only the targets in the code, never "*": a code
            // from another server must not open the whole network of this one.
            plan.allowed = if plan.carry == Carry::Socks {
                vec!["*".into()]
            } else {
                let mut targets: Vec<String> = pairing
                    .ports
                    .as_deref()
                    .and_then(|ports| parse_ports(ports).ok())
                    .map(|rules| rules.into_iter().map(|rule| rule.target).collect())
                    .unwrap_or_default();
                targets.sort();
                targets.dedup();
                if targets.iter().all(|t| t.starts_with("127.0.0.1:")) {
                    vec!["127.0.0.1:*".into()]
                } else {
                    targets
                }
            };
        }
    }
    if plan.dials()
        && let Some(pool) = pairing.pool
    {
        plan.pool = pool;
    }
    for setting in relevant_settings(plan.mode(), plan.transport, pairing.direct) {
        if is_local_only(setting.name) {
            continue;
        }
        if let Some(value) = pairing.settings.get(setting.name) {
            plan.tuned.push((setting, *value));
        }
    }
    if plan.side == Side::Iran
        && !missing.ports
        && plan.ports.is_empty()
        && plan.carry == Carry::Ports
    {
        bail!("the pairing code has no ports to forward");
    }
    Ok((plan, missing))
}

/// Settings that belong to one server and never travel to the other one: its own restart
/// schedule and traffic quota.
fn is_local_only(name: &str) -> bool {
    matches!(name.split('.').next(), Some("schedule" | "quota"))
        // What a server can afford depends on that server: the other one must not decide how
        // much memory, how many threads or how many files this one uses, or how it pads.
        || matches!(
            name,
            "memory_budget_mb"
                | "worker_threads"
                | "stats_interval_sec"
                | "max_open_files"
                | "stealth.record_pad_max"
                | "stealth.jitter_ms"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::plan::check;

    fn plan(side: Side, direction: Direction, transport: Transport) -> Plan {
        let mut plan = Plan::new(
            TunnelKey::generate().unwrap().display(),
            side,
            direction,
            transport,
        );
        plan.ports = parse_ports("443, 2083=2053").unwrap();
        plan.peer_host = Some("203.0.113.7".into());
        plan
    }

    /// Makes a code on one side and builds the other side from it; both must validate and
    /// agree on everything that has to match.
    fn round_trip(creator: Plan, address: Option<&str>) -> Plan {
        let config = creator.to_json().unwrap();
        check(&config).unwrap();
        let code =
            encode(&from_config(&config, address.map(str::to_string), None).unwrap()).unwrap();
        let (mut other, missing) = to_plan(&decode(&code).unwrap()).unwrap();
        if missing.ports {
            other.ports = parse_ports("443").unwrap();
        }
        check(&other.to_json().unwrap()).unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(other.side, creator.side.other());
        assert_eq!(other.direction, creator.direction);
        assert_eq!(other.transport, creator.transport);
        assert_eq!(other.tunnel_port, creator.tunnel_port);
        assert_eq!(other.key, creator.key);
        assert_eq!(other.wire_version, creator.wire_version);
        assert_ne!(other.dials(), creator.dials());
        other
    }

    #[cfg(feature = "browser-tls")]
    #[test]
    fn the_tls_look_travels_in_the_code_and_only_the_dialing_side_uses_it() {
        use crate::config::TlsProfile;
        for direction in [Direction::Reverse, Direction::Direct] {
            let mut creator = plan(Side::Foreign, direction, Transport::Wss);
            creator.tls_profile = TlsProfile::Chrome;
            // The creator's own configuration only has the setting if it dials.
            let json = creator.to_json().unwrap();
            let entry = if creator.dials() {
                &json["paths"][0]
            } else {
                &json["listeners"][0]
            };
            assert_eq!(entry.get("tls_profile").is_some(), creator.dials());
            // The code carries what the creator's configuration holds: the look of the dialing side.
            let other = round_trip(creator.clone(), Some("198.51.100.1"));
            let expected = if creator.dials() {
                TlsProfile::Chrome
            } else {
                TlsProfile::Classic
            };
            assert_eq!(other.tls_profile, expected);
            let json = other.to_json().unwrap();
            let entry = if other.dials() {
                &json["paths"][0]
            } else {
                &json["listeners"][0]
            };
            assert!(
                entry.get("tls_profile").is_some()
                    == (other.dials() && expected == TlsProfile::Chrome)
            );
        }
        // The classic look adds nothing to the code.
        let classic = plan(Side::Iran, Direction::Reverse, Transport::Wss);
        let config = classic.to_json().unwrap();
        let code = encode(&from_config(&config, None, None).unwrap()).unwrap();
        assert!(decode(&code).unwrap().tls_profile.is_none());
    }

    #[test]
    fn the_origin_of_a_cdn_tunnel_is_asked_for_its_own_port() {
        // Foreign dials through a CDN (edge port 443); Iran is the origin and imports the code.
        let mut creator = plan(Side::Foreign, Direction::Reverse, Transport::Xhttps);
        creator.cdn = Some(CdnPlan {
            domain: "tunnel.example.com".into(),
        });
        let config = creator.to_json().unwrap();
        let code = encode(&from_config(&config, None, None).unwrap()).unwrap();
        let (origin, missing) = to_plan(&decode(&code).unwrap()).unwrap();
        assert!(missing.port, "the origin must be asked for its port");
        assert_eq!(origin.side, Side::Iran);
        assert_ne!(
            origin.tunnel_port, 443,
            "the CDN edge port is not the origin's"
        );
        // Without a CDN the port in the code is the one to listen on.
        let plain = plan(Side::Foreign, Direction::Reverse, Transport::Xhttps);
        let config = plain.to_json().unwrap();
        let code = encode(&from_config(&config, None, None).unwrap()).unwrap();
        let (_, missing) = to_plan(&decode(&code).unwrap()).unwrap();
        assert!(!missing.port);
    }

    /// A code that forwards to other machines lets the foreign server reach exactly those, not
    /// everything.
    #[test]
    fn forwarding_to_other_machines_allows_those_targets_and_not_everything() {
        let mut creator = plan(Side::Iran, Direction::Reverse, Transport::Wss);
        creator.ports = parse_ports("8080=10.0.0.5:80, 9090=db.example.com:5432, 443").unwrap();
        let other = round_trip(creator, Some("198.51.100.1"));
        assert_eq!(
            other.allowed,
            ["10.0.0.5:80", "127.0.0.1:443", "db.example.com:5432"]
        );
        // Only this server's own ports: the usual loopback grant.
        let mut local = plan(Side::Iran, Direction::Reverse, Transport::Wss);
        local.ports = parse_ports("443, 8000-8003").unwrap();
        assert_eq!(
            round_trip(local, Some("198.51.100.1")).allowed,
            ["127.0.0.1:*"]
        );
    }

    #[test]
    fn what_a_server_can_afford_never_travels_to_the_other_server() {
        for name in [
            "schedule.restart_hours",
            "quota.limit_gb",
            "memory_budget_mb",
            "worker_threads",
            "stats_interval_sec",
            "max_open_files",
            "stealth.record_pad_max",
            "stealth.jitter_ms",
        ] {
            assert!(is_local_only(name), "{name} travels in the code");
        }
        assert!(!is_local_only("stealth.pad_max") && !is_local_only("heartbeat_sec"));
    }

    #[cfg(feature = "browser-tls")]
    #[test]
    fn tls_options_set_on_a_listening_tunnel_are_not_sent_to_the_dialing_side() {
        let mut creator = plan(Side::Iran, Direction::Reverse, Transport::Wss);
        let mut config = creator.to_json().unwrap();
        // "Change settings" can write these into a listener entry although they do nothing there.
        config["listeners"][0]["tls_fragment"] = serde_json::json!({"enabled": true});
        config["listeners"][0]["tls_profile"] = serde_json::json!("chrome");
        creator.tls_fragment = false;
        let pairing = from_config(&config, None, None).unwrap();
        assert!(!pairing.tls_fragment && pairing.tls_profile.is_none());
    }

    #[test]
    fn codes_round_trip_for_every_side_direction_and_carrier() {
        for transport in [
            Transport::Tcp,
            Transport::Wss,
            Transport::Xhttps,
            Transport::Kcp,
            Transport::Parallax,
            Transport::FecUdp,
            Transport::Tcp6,
        ] {
            for side in [Side::Iran, Side::Foreign] {
                for direction in [Direction::Reverse, Direction::Direct] {
                    let mut creator = plan(side, direction, transport);
                    if transport == Transport::Tcp6 {
                        creator.peer_host = Some("2001:db8::7".into());
                    }
                    let address = if transport == Transport::Tcp6 {
                        "2001:db8::1"
                    } else {
                        "198.51.100.1"
                    };
                    let other = round_trip(creator.clone(), Some(address));
                    if other.dials() {
                        assert_eq!(other.peer_host.as_deref(), Some(address));
                    }
                    if creator.side == Side::Iran {
                        assert_eq!(other.allowed, vec!["127.0.0.1:*".to_string()]);
                    } else {
                        assert_eq!(format_ports(&other.ports), "443");
                    }
                }
            }
        }
    }

    #[test]
    fn the_wire_version_travels_in_the_code() {
        let mut creator = plan(Side::Foreign, Direction::Reverse, Transport::Wss);
        let version = crate::stealth::new_version();
        assert_eq!(
            creator.wire_version, version,
            "new tunnels use the current wire version"
        );
        assert_eq!(creator.to_json().unwrap()["wire_version"], version);
        assert_eq!(round_trip(creator.clone(), None).wire_version, version);
        creator.wire_version = 1;
        assert!(creator.to_json().unwrap().get("wire_version").is_none());
        let code = encode(&from_config(&creator.to_json().unwrap(), None, None).unwrap()).unwrap();
        assert_eq!(to_plan(&decode(&code).unwrap()).unwrap().0.wire_version, 1);
    }

    #[test]
    fn iran_ports_and_tuned_settings_travel_in_the_code() {
        let mut creator = plan(Side::Iran, Direction::Reverse, Transport::Kcp);
        let mtu = relevant_settings(Mode::Server, Transport::Kcp, false)
            .into_iter()
            .find(|s| s.name == "kcp.mtu")
            .unwrap();
        creator.tuned.push((mtu, 1200));
        let window = relevant_settings(Mode::Server, Transport::Kcp, false)
            .into_iter()
            .find(|s| s.name == "stream_window")
            .unwrap();
        creator.tuned.push((window, 512));
        let foreign = round_trip(creator, Some("198.51.100.1"));
        let names: Vec<(&str, u64)> = foreign.tuned.iter().map(|(s, v)| (s.name, *v)).collect();
        assert!(names.contains(&("kcp.mtu", 1200)), "{names:?}");
        assert!(names.contains(&("stream_window", 512)), "{names:?}");
    }

    #[test]
    fn raw_and_tun_tunnels_swap_addresses() {
        let mut creator = plan(Side::Iran, Direction::Reverse, Transport::FecRaw);
        creator.raw = Some(RawPlan {
            profile: "icmp".into(),
            peer_ip: "203.0.113.7".parse().unwrap(),
            ip_mode: IpMode::Proto58,
            interface: None,
            local_ip: None,
            mirage: None,
        });
        creator.carry = Carry::TunPorts;
        creator.tun = Some(TunPlan {
            name: "ez0".into(),
            local_ip: "10.77.0.1".into(),
            peer_ip: "10.77.0.2".into(),
            mtu: 1300,
            forwarding_port: Some(47475),
            fragment: false,
        });
        let config = creator.to_json().unwrap();
        let code =
            encode(&from_config(&config, Some("198.51.100.1".into()), None).unwrap()).unwrap();
        let (other, _) = to_plan(&decode(&code).unwrap()).unwrap();
        let raw = other.raw.as_ref().unwrap();
        assert_eq!(raw.peer_ip.to_string(), "198.51.100.1");
        assert_eq!(
            (raw.profile.as_str(), raw.ip_mode),
            ("icmp", IpMode::Proto58)
        );
        let tun = other.tun.as_ref().unwrap();
        assert_eq!(
            (tun.local_ip.as_str(), tun.peer_ip.as_str()),
            ("10.77.0.2", "10.77.0.1")
        );
        assert_eq!((tun.mtu, tun.forwarding_port), (1300, Some(47475)));
        check(&other.to_json().unwrap()).unwrap();
    }

    #[test]
    fn mirage_code_never_transfers_endpoint_spoofing_or_local_acceptance() {
        let mut creator = plan(Side::Iran, Direction::Reverse, Transport::Mirage);
        creator.raw = Some(RawPlan {
            profile: "tcp".into(),
            peer_ip: "192.0.2.2".parse().unwrap(),
            ip_mode: IpMode::Normal,
            interface: Some("eth9".into()),
            local_ip: Some("192.0.2.1".parse().unwrap()),
            mirage: Some(super::super::plan::MiragePlan {
                spoof_src_ip: "198.51.100.99".parse().unwrap(),
                advanced:None,
                spoof_dst_ip: Some("198.51.100.98".parse().unwrap()),
                gateway_ip: Some("192.0.2.254".parse().unwrap()),
                peer_mac: Some("02:00:00:00:00:01".into()),
            }),
        });
        let config = creator.to_json().unwrap();
        check(&config).unwrap();
        let code = from_config(&config, Some("192.0.2.1".into()), None).unwrap();
        let value = serde_json::to_string(&code).unwrap();
        assert!(
            !value.contains("198.51.100.99")
                && !value.contains("eth9")
                && !value.contains(crate::mirage::ACK)
        );
        let (other, _) = to_plan(&decode(&encode(&code).unwrap()).unwrap()).unwrap();
        let raw = other.raw.as_ref().unwrap();
        assert_eq!(
            raw.peer_ip,
            "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert!(raw.mirage.is_none() && raw.interface.is_none() && raw.local_ip.is_none());
        assert!(
            check(&other.to_json().unwrap()).is_err(),
            "local Mirage settings/acceptance must be supplied"
        );
    }

    #[test]
    fn damaged_and_foreign_codes_are_refused() {
        let creator = plan(Side::Iran, Direction::Reverse, Transport::Tcp);
        let code = encode(
            &from_config(
                &creator.to_json().unwrap(),
                Some("198.51.100.1".into()),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(decode(&code).is_ok());
        assert!(decode(&format!("  {}\n{}  ", &code[..20], &code[20..])).is_ok());
        assert!(decode(&code[..code.len() - 3]).is_err());
        let mut bytes = code.clone().into_bytes();
        let middle = bytes.len() / 2;
        bytes[middle] = if bytes[middle] == b'A' { b'B' } else { b'A' };
        assert!(decode(&String::from_utf8(bytes).unwrap()).is_err());
        assert!(decode("hello").is_err());
        assert!(decode(&creator.key).is_err());
        assert!(code.len() < 400, "code is {} characters", code.len());
    }

    #[test]
    fn a_listening_creator_must_give_its_address() {
        let creator = plan(Side::Iran, Direction::Reverse, Transport::Tcp);
        let config = creator.to_json().unwrap();
        assert!(needs_address(&config));
        let pairing = from_config(&config, None, None).unwrap();
        assert!(to_plan(&pairing).is_err());
        let dialing = plan(Side::Foreign, Direction::Reverse, Transport::Tcp);
        assert!(!needs_address(&dialing.to_json().unwrap()));
    }

    #[test]
    fn values_this_version_does_not_know_are_listed_not_dropped_silently() -> Result<()> {
        let key = TunnelKey::generate()?.display();
        let code: Pairing = serde_json::from_value(serde_json::json!({
            "k": key, "s": "iran", "t": "tcp", "p": 4000,
            "w": "satellite", "u": "sctp", "l": "firefox",
            "z": {"timeouts.probe_sec": 3, "nope.setting": 1, "other.nope": 2}
        }))?;
        let ignored = ignored_values(&code).join(" | ");
        for what in ["firefox", "satellite", "sctp", "nope.setting", "other.nope"] {
            assert!(ignored.contains(what), "{what}: {ignored}");
        }
        assert!(!ignored.contains("probe_sec"), "{ignored}");
        let known: Pairing = serde_json::from_value(serde_json::json!({
            "k": key, "s": "iran", "t": "tcp", "p": 4000, "w": "tun", "u": "both", "l": "classic"
        }))?;
        assert!(ignored_values(&known).is_empty());
        Ok(())
    }

    /// C22: TCP and UDP on one port with the same target pair fine; different targets on
    /// one port cannot be expressed in the compact syntax and must be refused, not dropped.
    #[test]
    fn protocol_specific_targets_on_one_port_are_refused_not_lossily_exported() -> Result<()> {
        let mut creator = plan(Side::Iran, Direction::Reverse, Transport::Wss);
        creator.ports = parse_ports("443, 8080=10.0.0.5:80")?;
        creator.protocol = Protocol::Both;
        let mut config = creator.to_json()?;
        check(&config)?;
        let maps = config["listeners"][0]["maps"].as_array().cloned().unwrap_or_default();
        assert!(maps.iter().any(|m| m["type"] == "udp"), "fixture needs a UDP map: {maps:?}");
        assert!(maps.iter().any(|m| m["type"] != "udp"), "fixture needs a TCP map: {maps:?}");
        // Compatible: same target for both protocols.
        let pairing = from_config(&config, Some("198.51.100.1".into()), None)?;
        let (other, _) = to_plan(&decode(&encode(&pairing)?)?)?;
        assert_eq!(other.allowed, ["10.0.0.5:80", "127.0.0.1:443"]);
        // Lossy: UDP on 443 goes elsewhere.
        for map in config["listeners"][0]["maps"].as_array_mut().unwrap() {
            if map["type"] == "udp" && map["bind"].as_str().is_some_and(|b| b.ends_with(":443")) {
                map["target"] = "127.0.0.1:5353".into();
            }
        }
        let error = from_config(&config, Some("198.51.100.1".into()), None).unwrap_err();
        assert!(format!("{error:#}").contains("protocol-specific"), "{error:#}");
        Ok(())
    }
}
