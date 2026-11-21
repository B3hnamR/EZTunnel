//! The answers of the new-tunnel wizard and the configuration they produce. Nothing here
//! touches the terminal or the system, so every combination can be checked by tests.
use crate::config::{Config, Mode, Transport, XhttpMode};
use crate::settings::{Place, Setting};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};
use std::net::Ipv4Addr;

/// Which of the two servers this machine is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The entry server in Iran: users connect here. Runs the `server` role.
    Iran,
    /// The exit server abroad: traffic leaves to the internet here. Runs the `client` role.
    Foreign,
}

impl Side {
    pub fn mode(self) -> Mode {
        match self {
            Self::Iran => Mode::Server,
            Self::Foreign => Mode::Client,
        }
    }

    pub fn from_mode(mode: Mode) -> Self {
        match mode {
            Mode::Server => Self::Iran,
            Mode::Client => Self::Foreign,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Iran => "Iran server",
            Self::Foreign => "Foreign server",
        }
    }

    pub fn other(self) -> Self {
        match self {
            Self::Iran => Self::Foreign,
            Self::Foreign => Self::Iran,
        }
    }
}

/// Which server opens the connection between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The foreign server connects to the Iran server (`server_dials` off).
    Reverse,
    /// The Iran server connects to the foreign server (`server_dials` on).
    Direct,
}

impl Direction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Reverse => "Reverse",
            Self::Direct => "Direct",
        }
    }
}

/// What the tunnel carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carry {
    Ports,
    Socks,
    Tun,
    TunPorts,
}

impl Carry {
    pub fn uses_tun(self) -> bool {
        matches!(self, Self::Tun | Self::TunPorts)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ports => "Port forwarding",
            Self::Socks => "SOCKS5 proxy",
            Self::Tun => "IP tunnel (TUN)",
            Self::TunPorts => "IP tunnel (TUN) + port forwarding",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Both => "TCP + UDP",
        }
    }
}

/// One forwarded port on the Iran server and where it arrives on the foreign server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRule {
    pub listen: u16,
    /// `host:port` reached from the foreign server.
    pub target: String,
}

/// Reads a port list such as `443, 8080, 2083=443, 9000-9003, 5000=10.0.0.2:5000`.
pub fn parse_ports(text: &str) -> Result<Vec<PortRule>> {
    let mut rules: Vec<PortRule> = Vec::new();
    for item in text.split([',', ' ']).filter(|item| !item.is_empty()) {
        let port = |value: &str| -> Result<u16> {
            let port: u16 = value
                .trim()
                .parse()
                .with_context(|| format!("'{value}' is not a port number"))?;
            ensure!(port != 0, "port 0 is not allowed");
            Ok(port)
        };
        // Checked before '-': a target host (after '=') may itself contain a dash
        // (e.g. "2083=db-prod.internal:5432"), which must not be read as a port range.
        if let Some((listen, target)) = item.split_once('=') {
            let listen = port(listen)?;
            let target = if target.contains(':') {
                let (host, target_port) = target.rsplit_once(':').context("target")?;
                ensure!(!host.is_empty(), "'{target}' needs a host before the port");
                port(target_port)?;
                target.to_string()
            } else {
                format!("127.0.0.1:{}", port(target)?)
            };
            rules.push(PortRule { listen, target });
        } else if let Some((first, last)) = item.split_once('-') {
            let (first, last) = (port(first)?, port(last)?);
            ensure!(first <= last, "range {item} goes backwards");
            ensure!(
                last - first < 1000,
                "range {item} is too large (at most 1000 ports)"
            );
            for listen in first..=last {
                rules.push(PortRule {
                    listen,
                    target: format!("127.0.0.1:{listen}"),
                });
            }
        } else {
            let listen = port(item)?;
            rules.push(PortRule {
                listen,
                target: format!("127.0.0.1:{listen}"),
            });
        }
    }
    ensure!(!rules.is_empty(), "enter at least one port");
    for (index, rule) in rules.iter().enumerate() {
        ensure!(
            rules[..index]
                .iter()
                .all(|other| other.listen != rule.listen),
            "port {} is listed twice",
            rule.listen
        );
    }
    ensure!(rules.len() <= 1000, "at most 1000 ports per tunnel");
    Ok(rules)
}

/// Writes rules back in the short form `parse_ports` reads.
pub fn format_ports(rules: &[PortRule]) -> String {
    rules
        .iter()
        .map(|rule| {
            if rule.target == format!("127.0.0.1:{}", rule.listen) {
                rule.listen.to_string()
            } else if let Some(port) = rule.target.strip_prefix("127.0.0.1:") {
                format!("{}={port}", rule.listen)
            } else {
                format!("{}={}", rule.listen, rule.target)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMode {
    Normal,
    Proto58,
}

/// Settings of the raw-packet carriers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPlan {
    pub profile: String,
    /// Real IPv4 address of the other server.
    pub peer_ip: Ipv4Addr,
    pub ip_mode: IpMode,
    pub interface: Option<String>,
    pub local_ip: Option<Ipv4Addr>,
    pub mirage: Option<MiragePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiragePlan {
    pub spoof_src_ip: Ipv4Addr,
    pub spoof_dst_ip: Option<Ipv4Addr>,
    pub gateway_ip: Option<Ipv4Addr>,
    pub peer_mac: Option<String>,
    pub advanced:Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunPlan {
    pub name: String,
    pub local_ip: String,
    pub peer_ip: String,
    pub mtu: u16,
    pub forwarding_port: Option<u16>,
    /// Lets `mtu` exceed what the raw profile's single outer packet can carry (`tun.fragment`).
    pub fragment: bool,
}

/// Going through a CDN (XHTTP only). Only the dialing side uses these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdnPlan {
    /// The domain the CDN serves for the other server.
    pub domain: String,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub key: String,
    pub side: Side,
    pub direction: Direction,
    pub transport: Transport,
    /// Port of the connection between the servers.
    pub tunnel_port: u16,
    /// Address of the other server, needed when this side dials.
    pub peer_host: Option<String>,
    /// Local address the listening side binds to.
    pub listen_ip: String,
    pub carry: Carry,
    pub ports: Vec<PortRule>,
    pub protocol: Protocol,
    /// Address users bind on the Iran server: `0.0.0.0` makes ports public.
    pub public_ip: String,
    pub socks_bind: String,
    /// What the foreign server may reach.
    pub allowed: Vec<String>,
    pub pool: usize,
    pub http_path: String,
    pub sni: Option<String>,
    /// Split the TLS ClientHello (used by the dialing side of a TLS carrier).
    pub tls_fragment: bool,
    /// What the TLS client of the dialing side looks like.
    pub tls_profile: crate::config::TlsProfile,
    /// Local IP address the dialing side connects from (`None` = the system's choice).
    pub local_address: Option<String>,
    /// Overrides the program-wide `tcp_congestion` for the dialing side only (`None` = unset).
    pub tcp_congestion: Option<String>,
    /// Paces KCP/FEC-family writes by measured RTT instead of only the fixed send window
    /// (`fec.pacer`). Applies on both sides when set, since it is a symmetric setting.
    pub fec_pacer: bool,
    /// The servers talk over IPv6 (the transport list's IPv6 entry): the dialing end connects
    /// to the other server's IPv6 address and the listening end listens on IPv6 too.
    pub ipv6: bool,
    /// FEC-RAW tuned for low delay (`fec.profile: "gaming"`): what the gaming profile does on the
    /// raw carriers, which cannot carry Game mode.
    pub low_delay: bool,
    pub xhttp_mode: XhttpMode,
    /// Parallax only: stream mode (v1) or packet mode. Both servers must use the same one.
    pub parallax_mode: crate::parallax_carrier::Mode,
    pub cdn: Option<CdnPlan>,
    pub raw: Option<RawPlan>,
    pub tun: Option<TunPlan>,
    /// Changed tunables as (setting, value).
    pub tuned: Vec<(Setting, u64)>,
    /// KCP/FEC timing mode (only for those carriers); `Default` writes nothing.
    pub speed: super::speed::SpeedMode,
    /// Wire format of the tunnel: 2 = probe resistance (new tunnels), 1 = 0.6.x and earlier.
    pub wire_version: u8,
    /// Game mode: game UDP goes on the direct datagram path, in copies over several ports.
    pub game: Option<GamePlan>,
    /// Failover: backup carriers after `transport`, in order of preference, as (transport,
    /// tunnel port). Each one gets its defaults; the ports and SOCKS5 stay with the tunnel.
    pub backups: Vec<(Transport, u16)>,
}

/// Game mode: the users' UDP (port maps and SOCKS UDP) skips the tunnel's ordered stream and goes
/// as authenticated datagrams, each sent `copies` times from different ports so the copies take
/// different paths; the first copy to arrive is used. Both servers must have it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GamePlan {
    /// TCP port of the authenticating control connection and UDP port of the datagrams (the Iran
    /// server listens on it for both).
    pub port: u16,
    pub copies: u8,
    /// How the foreign server reaches the Iran server for the control connection, when it does not
    /// dial the tunnel itself (a direct tunnel).
    pub iran_host: Option<String>,
}

/// Copies Game mode sends: in the live test 3 copies cut losses from up to 20% to 1-10% at the
/// same ping, for three times the game's own (small) bandwidth.
pub const GAME_COPIES: u8 = 3;

/// The default Game mode port: the one after the tunnel port.
pub fn game_port(tunnel_port: u16) -> u16 {
    if tunnel_port == u16::MAX { tunnel_port - 1 } else { tunnel_port + 1 }
}

/// The pool a listener or path entry has: its `connection_pool`, or the transport's automatic one.
pub fn pool_now(entry: &Value, transport: Transport) -> u64 {
    entry["connection_pool"].as_u64().filter(|pool| *pool > 0).unwrap_or(transport.auto_pool() as u64)
}

/// Sets an entry's pool; the automatic size is left unwritten so it follows the program.
pub fn set_pool(entry: &mut Value, transport: Transport, pool: u64) {
    if pool == transport.auto_pool() as u64 {
        if let Some(object) = entry.as_object_mut() {
            object.remove("connection_pool");
        }
    } else {
        entry["connection_pool"] = json!(pool);
    }
}

pub fn is_raw(transport: Transport) -> bool {
    matches!(
        transport,
        Transport::FecRaw | Transport::FecRawGaming | Transport::Tun | Transport::Mirage
    )
}

pub fn is_xhttp(transport: Transport) -> bool {
    matches!(transport, Transport::Xhttp | Transport::Xhttps)
}

pub fn transport_name(transport: Transport) -> String {
    serde_json::to_value(transport)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// A good first choice for the port between the servers.
pub fn default_tunnel_port(transport: Transport) -> u16 {
    match transport {
        Transport::Https | Transport::Wss | Transport::Xhttps => 8443,
        Transport::Http | Transport::Ws | Transport::Xhttp => 8080,
        Transport::FecRaw | Transport::FecRawGaming | Transport::Tun | Transport::Mirage => 4443,
        _ => 7000,
    }
}

/// Whether the carrier listens on UDP rather than TCP.
pub fn uses_udp(transport: Transport) -> bool {
    matches!(transport, Transport::Kcp | Transport::FecUdp)
}

impl Plan {
    pub fn new(key: String, side: Side, direction: Direction, transport: Transport) -> Self {
        Self {
            key,
            side,
            direction,
            transport,
            tunnel_port: default_tunnel_port(transport),
            peer_host: None,
            listen_ip: if transport == Transport::Tcp6 {
                "::".into()
            } else {
                "0.0.0.0".into()
            },
            carry: Carry::Ports,
            ports: Vec::new(),
            protocol: Protocol::Tcp,
            public_ip: "0.0.0.0".into(),
            socks_bind: "127.0.0.1:1080".into(),
            allowed: vec!["127.0.0.1:*".into()],
            pool: 4,
            http_path: "/tunnel".into(),
            sni: None,
            tls_fragment: false,
            tls_profile: crate::config::TlsProfile::Classic,
            local_address: None,
            tcp_congestion: None,
            fec_pacer: false,
            ipv6: false,
            low_delay: false,
            xhttp_mode: XhttpMode::StreamUp,
            parallax_mode: crate::parallax_carrier::Mode::Stream,
            cdn: None,
            raw: None,
            tun: None,
            tuned: Vec::new(),
            speed: super::speed::SpeedMode::Default,
            wire_version: crate::stealth::new_version(),
            game: None,
            backups: Vec::new(),
        }
    }

    pub fn mode(&self) -> Mode {
        self.side.mode()
    }

    /// Whether this machine opens the connection to the other server.
    pub fn dials(&self) -> bool {
        if is_raw(self.transport) {
            return false;
        }
        match (self.side, self.direction) {
            (Side::Foreign, Direction::Reverse) | (Side::Iran, Direction::Direct) => true,
            (Side::Iran, Direction::Reverse) | (Side::Foreign, Direction::Direct) => false,
        }
    }

    /// Whether users' UDP goes through this tunnel (what Game mode speeds up).
    pub fn carries_udp(&self) -> bool {
        match self.carry {
            Carry::Socks => true,
            // Only the Iran server knows which protocols its ports forward; the foreign server
            // follows whatever arrives.
            Carry::Ports => self.side == Side::Foreign || self.protocol != Protocol::Tcp,
            _ => false,
        }
    }

    /// Turns Game mode on with its defaults, or off. Also sets the fastest speed mode where the
    /// carrier has one, since the game path's control and any game TCP still use the carrier.
    /// Game mode, foreign end: the Iran server's IP for the control connection and the datagram
    /// path. The carrier's address serves only when it is an IP (not a host name or, through a
    /// CDN, the CDN's domain); otherwise `GamePlan::iran_host` must hold it.
    pub fn game_iran_ip(&self) -> Option<String> {
        let game = self.game.as_ref()?;
        let carrier = (self.direction == Direction::Reverse && self.cdn.is_none())
            .then(|| self.peer_host.clone())
            .flatten();
        [game.iran_host.clone(), carrier]
            .into_iter()
            .flatten()
            .map(|host| host.trim_matches(['[', ']']).to_string())
            .find(|host| host.parse::<std::net::IpAddr>().is_ok())
    }

    /// Game mode is on at the foreign end and the Iran server's IP is still missing.
    pub fn game_needs_iran_ip(&self) -> bool {
        self.game.is_some() && self.side == Side::Foreign && self.game_iran_ip().is_none()
    }

    /// The listening end of a new tunnel takes IPv4 and IPv6 on one socket (`[::]`), so either
    /// family can reach it: a route that drops one may carry the other. Raw carriers and TUN
    /// keep their own addressing.
    pub fn listen_on_both_families(&mut self) {
        if !self.dials() && self.listen_ip == "0.0.0.0" && !is_raw(self.transport) && self.tun.is_none() {
            self.listen_ip = "::".into();
        }
    }

    pub fn set_game(&mut self, on: bool) {
        if on {
            self.game = Some(GamePlan { port: game_port(self.tunnel_port), copies: GAME_COPIES, iran_host: None });
            let packet = self.parallax_mode == crate::parallax_carrier::Mode::Packet;
            if super::speed::applies(self.transport, packet) && self.speed == super::speed::SpeedMode::Default {
                self.speed = super::speed::SpeedMode::Fast3;
            }
        } else {
            self.game = None;
        }
    }

    fn host_port(host: &str, port: u16) -> String {
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }

    /// The configuration file content. With backup carriers (failover) every carrier is one more
    /// listener (Iran) or path (foreign) in order, under the same key; the maps stay on the first.
    pub fn to_json(&self) -> Result<Value> {
        let mut config = self.to_json_one()?;
        if self.backups.is_empty() {
            return Ok(config);
        }
        ensure!(self.raw.is_none() && self.tun.is_none() && self.cdn.is_none() && self.game.is_none(),
            "failover is for plain carriers: no raw, TUN, CDN or Game mode");
        let key = if self.mode() == Mode::Server { "listeners" } else { "paths" };
        for (transport, port) in &self.backups {
            ensure!(!is_raw(*transport) && *transport != Transport::Mirage, "a raw carrier cannot be a failover backup");
            let mut carrier = Plan::new(self.key.clone(), self.side, self.direction, *transport);
            carrier.tunnel_port = *port;
            carrier.peer_host = self.peer_host.clone();
            carrier.listen_ip = self.listen_ip.clone();
            carrier.ipv6 = self.ipv6;
            carrier.wire_version = self.wire_version;
            let mut entry = carrier.to_json_one()?[key][0].clone();
            if let Some(entry) = entry.as_object_mut() {
                entry.remove("maps");
            }
            config[key].as_array_mut().context("no carrier list")?.push(entry);
        }
        config["failover"] = json!({"enabled": true});
        Ok(config)
    }

    fn to_json_one(&self) -> Result<Value> {
        let mode = self.mode();
        let mut entry = Map::new();
        let dials = self.dials();
        let address = if let Some(raw) = &self.raw {
            match self.side {
                Side::Iran => format!(
                    "{}:{}",
                    raw.local_ip
                        .map_or("0.0.0.0".to_string(), |ip| ip.to_string()),
                    self.tunnel_port
                ),
                Side::Foreign => format!("{}:{}", raw.peer_ip, self.tunnel_port),
            }
        } else if dials {
            match &self.cdn {
                Some(cdn) => Self::host_port(
                    &cdn.domain,
                    if self.transport.uses_tls() { 443 } else { 80 },
                ),
                None => Self::host_port(
                    self.peer_host
                        .as_deref()
                        .context("the other server's address is missing")?,
                    self.tunnel_port,
                ),
            }
        } else {
            Self::host_port(&self.listen_ip, self.tunnel_port)
        };
        entry.insert("addr".into(), json!(address));
        entry.insert("transport".into(), json!(self.transport));
        if self.transport.uses_http() && self.http_path != "/tunnel" {
            entry.insert("http_path".into(), json!(self.http_path));
        }
        if self.transport.uses_tls() {
            if dials && self.cdn.is_some() {
                // The CDN shows a real certificate; it is checked against the system roots.
            } else {
                entry.insert("tls_auto".into(), json!(true));
            }
            // Through a CDN the certificate is the CDN's, for the CDN's domain.
            let name = self.sni.clone().or_else(|| {
                self.cdn
                    .as_ref()
                    .map(|cdn| cdn.domain.clone())
                    .filter(|domain| !domain.is_empty())
            });
            if dials && let Some(name) = name {
                entry.insert("server_name".into(), json!(name));
            }
            if dials && self.tls_fragment {
                entry.insert("tls_fragment".into(), json!({"enabled": true}));
            }
            if dials && !self.tls_profile.is_classic() {
                entry.insert("tls_profile".into(), json!(self.tls_profile));
            }
        }
        if dials && let Some(local) = &self.local_address {
            entry.insert("local_address".into(), json!(local));
        }
        if dials && let Some(congestion) = &self.tcp_congestion {
            entry.insert("tcp_congestion".into(), json!(congestion));
        }
        let mut fec = Map::new();
        if self.fec_pacer
            && matches!(
                self.transport,
                Transport::Kcp
                    | Transport::FecUdp
                    | Transport::FecRaw
                    | Transport::FecRawGaming
                    | Transport::Mirage
            )
        {
            fec.insert("pacer".into(), json!(true));
        }
        if self.low_delay && self.transport == Transport::FecRaw {
            fec.insert("profile".into(), json!("gaming"));
        }
        if !fec.is_empty() {
            entry.insert("fec".into(), Value::Object(fec));
        }
        if self.transport == Transport::Parallax
            && self.parallax_mode == crate::parallax_carrier::Mode::Packet
        {
            entry.insert("parallax".into(), json!({"mode": "packet"}));
        }
        if is_xhttp(self.transport) {
            let mut xhttp = Map::new();
            xhttp.insert("mode".into(), json!(self.xhttp_mode));
            if dials {
                if let Some(cdn) = &self.cdn {
                    xhttp.insert("host".into(), json!(cdn.domain));
                }
            } else if self.cdn.is_some() {
                // Behind a CDN every user arrives from a few edge addresses.
                xhttp.insert("max_requests_per_ip".into(), json!(0));
            }
            entry.insert("xhttp".into(), Value::Object(xhttp));
        }
        if let Some(raw) = &self.raw {
            let mut options = Map::new();
            options.insert("profile".into(), json!(raw.profile));
            options.insert("peer_ip".into(), json!(raw.peer_ip.to_string()));
            options.insert("l4_port".into(), json!(self.tunnel_port));
            if raw.ip_mode == IpMode::Proto58 {
                options.insert("proto58_mode".into(), json!(true));
            }
            if let Some(interface) = &raw.interface {
                options.insert("interface".into(), json!(interface));
            }
            if let Some(ip) = raw.local_ip {
                options.insert("local_ip".into(), json!(ip.to_string()));
            }
            if let Some(mirage) = &raw.mirage {
                if let Some(advanced)=&mirage.advanced {
                    options.insert("mirage".into(),advanced.clone());options.insert("mirage_acknowledgement".into(),json!("experimental-v2"));
                }else{
                    options.insert("spoof_src_ip".into(), json!(mirage.spoof_src_ip));
                    options.insert("mirage_acknowledgement".into(), json!(crate::mirage::ACK));
                }
                if let Some(ip) = mirage.spoof_dst_ip {
                    options.insert("spoof_dst_ip".into(), json!(ip));
                }
                if let Some(ip) = mirage.gateway_ip {
                    options.insert("gateway_ip".into(), json!(ip));
                }
                if let Some(mac) = &mirage.peer_mac {
                    options.insert("peer_mac".into(), json!(mac));
                }
            }
            entry.insert("raw".into(), Value::Object(options));
        }
        let single = is_raw(self.transport) || self.carry.uses_tun();
        if dials && !single && self.pool != self.transport.auto_pool() {
            entry.insert("connection_pool".into(), json!(self.pool));
        }
        let mut root = Map::new();
        root.insert("mode".into(), json!(mode));
        if self.direction == Direction::Direct && !is_raw(self.transport) {
            root.insert("server_dials".into(), json!(true));
        }
        root.insert("tunnel_key".into(), json!(self.key));
        if self.wire_version >= 2 {
            root.insert("wire_version".into(), json!(self.wire_version));
        }
        if let Some(tun) = &self.tun {
            let mut options = json!({"name": tun.name, "address": tun.local_ip,
                "peer_address": tun.peer_ip, "mtu": tun.mtu});
            if let Some(port) = tun.forwarding_port {
                options["forwarding_port"] = json!(port);
            }
            if tun.fragment {
                options["fragment"] = json!(true);
            }
            root.insert("tun".into(), options);
        }
        if let Some(game) = &self.game {
            ensure!(self.carries_udp(), "Game mode needs UDP: forward UDP ports or use SOCKS5");
            let (control, wildcard) = match mode {
                Mode::Server => {
                    // The foreign end sends to the Iran address it was given: when that is IPv6,
                    // listen on IPv6 too, whatever family the carrier uses.
                    let ipv6 = self.listen_ip.contains(':')
                        || game.iran_host.as_deref().is_some_and(|host| host.trim_matches(['[', ']']).parse::<std::net::Ipv6Addr>().is_ok());
                    let wildcard = if ipv6 { "[::]" } else { "0.0.0.0" };
                    (format!("{wildcard}:{}", game.port), wildcard)
                }
                Mode::Client => {
                    let host = self.game_iran_ip().context(
                        "Game mode needs the Iran server's IP address (a host name or a CDN domain cannot carry its datagrams)",
                    )?;
                    // The game socket sends to the Iran server: the same address family.
                    let wildcard = if host.contains(':') { "[::]" } else { "0.0.0.0" };
                    (Self::host_port(&host, game.port), wildcard)
                }
            };
            root.insert(
                "gaming".into(),
                json!({"control_address": control, "udp_bind": format!("{wildcard}:{}", game.port),
                       "copies": game.copies}),
            );
        }
        let forwards = matches!(self.carry, Carry::Ports | Carry::Socks | Carry::TunPorts);
        match mode {
            Mode::Server => {
                let mut maps = Vec::new();
                if matches!(self.carry, Carry::Ports | Carry::TunPorts) {
                    for rule in &self.ports {
                        let bind = Self::host_port(&self.public_ip, rule.listen);
                        if self.protocol != Protocol::Udp {
                            maps.push(json!({"type":"tcp","bind":bind,"target":rule.target}));
                        }
                        if self.protocol != Protocol::Tcp {
                            maps.push(json!({"type":"udp","bind":bind,"target":rule.target}));
                        }
                    }
                }
                entry.insert("maps".into(), Value::Array(maps));
                if self.carry == Carry::Socks {
                    root.insert("socks5".into(), json!(self.socks_bind));
                }
                root.insert("listeners".into(), Value::Array(vec![Value::Object(entry)]));
            }
            Mode::Client => {
                if forwards {
                    root.insert("allowed_targets".into(), json!(self.allowed));
                }
                root.insert("paths".into(), Value::Array(vec![Value::Object(entry)]));
            }
        }
        let mut config = Value::Object(root);
        // The speed mode writes the timing fields first, so a value set by hand (Customize, or
        // carried in a pairing code) wins over the mode instead of being erased by it.
        super::speed::apply_config(&mut config, self.transport, self.speed);
        for (setting, value) in &self.tuned {
            apply_setting(&mut config, setting, Some(*value))?;
        }
        Ok(config)
    }
}

/// Ready-made settings for a kind of use. Each one only writes ordinary settings, so the result
/// can still be changed one by one later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    General,
    ManyUsers,
    Gaming,
    Streaming,
}

impl Profile {
    pub const ALL: [Profile; 4] = [
        Profile::General,
        Profile::ManyUsers,
        Profile::Gaming,
        Profile::Streaming,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Profile::General => "General",
            Profile::ManyUsers => "Many users",
            Profile::Gaming => "Gaming / low delay",
            Profile::Streaming => "Streaming / big downloads",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Profile::General => "good speed for most links (recommended)",
            Profile::ManyUsers => "more connections and room for many users at once",
            Profile::Gaming => "Game mode: game UDP on its own fast path, in 3 copies; small queues (FEC-RAW: low-delay tuning)",
            Profile::Streaming => "bigger windows for fast single downloads",
        }
    }

    /// The preset with the same values; the wizard and later changes share one set of numbers.
    fn preset(self) -> super::presets::Preset {
        use super::presets::Preset;
        match self {
            Profile::General => Preset::Balanced,
            Profile::ManyUsers => Preset::ManyUsers,
            Profile::Gaming => Preset::Gaming,
            Profile::Streaming => Preset::Streaming,
        }
    }
}

impl Plan {
    /// Applies a profile, replacing earlier values of the same settings.
    pub fn apply_profile(&mut self, profile: Profile) {
        let scope = super::scope::Scope::of_plan(self);
        let (pool, values) =
            super::presets::for_plan(profile.preset(), &scope, self.tun.is_some(), super::presets::Capacity::here());
        self.pool = pool as usize;
        // A profile owns the same settings as a preset: switching profiles leaves nothing behind.
        self.tuned.retain(|(s, _)| !super::presets::MANAGED.contains(&s.name));
        // The gaming profile is the one-click choice for games: it also turns Game mode on.
        // A foreign server of a direct tunnel does not know the Iran address the control connects
        // to; there Customize offers Game mode and asks for it. Raw carriers keep their own path.
        // The same goes for a foreign server that reaches the Iran server by a host name or a CDN.
        let completes = self.side == Side::Iran
            || (self.direction == Direction::Reverse
                && self.cdn.is_none()
                && self
                    .peer_host
                    .as_deref()
                    .is_some_and(|host| host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok()));
        self.set_game(
            profile == Profile::Gaming
                && completes
                && self.carries_udp()
                && self.tun.is_none()
                && !is_raw(self.transport),
        );
        // On FEC-RAW the gaming profile is the low-delay KCP tuning instead.
        self.low_delay = profile == Profile::Gaming && self.transport == Transport::FecRaw;
        let available = super::scope::relevant(&super::scope::Scope::of_plan(self));
        for (name, value) in values {
            if let Some(setting) = available.iter().find(|s| s.name == name) {
                self.tuned.retain(|(s, _)| s.name != name);
                self.tuned.push((setting.clone(), value));
            }
        }
    }
}

/// Sets (or with `None` removes) one tunable in a configuration.
pub fn apply_setting(config: &mut Value, setting: &Setting, value: Option<u64>) -> Result<()> {
    let target = match setting.place {
        Place::Top => config,
        Place::Listener => config
            .get_mut("listeners")
            .and_then(|list| list.get_mut(0))
            .context("this tunnel has no listener")?,
        Place::Path => config
            .get_mut("paths")
            .and_then(|list| list.get_mut(0))
            .context("this tunnel has no path")?,
    };
    match value {
        Some(value) => crate::settings::set_dotted(target, setting.name, json!(value)),
        None => remove_dotted(target, setting.name),
    }
    Ok(())
}

pub fn read_setting(config: &Value, setting: &Setting) -> Option<u64> {
    let mut node = match setting.place {
        Place::Top => config,
        Place::Listener => config.get("listeners")?.get(0)?,
        Place::Path => config.get("paths")?.get(0)?,
    };
    for part in setting.name.split('.') {
        node = node.get(part)?;
    }
    node.as_u64()
}

fn remove_dotted(target: &mut Value, dotted: &str) {
    let mut node = target;
    let mut parts = dotted.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            if let Some(object) = node.as_object_mut() {
                object.remove(part);
            }
            return;
        }
        match node.get_mut(part) {
            Some(next) => node = next,
            None => return,
        }
    }
}

/// Checks the produced configuration with the program's own validation.
pub fn check(config: &Value) -> Result<Config> {
    let mut parsed: Config =
        serde_json::from_value(config.clone()).context("configuration structure")?;
    parsed.prepare()?;
    parsed.validate()?;
    crate::transport::validate_tls_config(&parsed)?;
    Ok(parsed)
}

/// A one-line description of a saved tunnel, read back from its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub side: Side,
    pub direction: Direction,
    pub transport: String,
    /// The connection between the servers: `listen :7000` or `→ 1.2.3.4:7000`.
    pub link: String,
    pub carry: String,
}

pub fn summarize(config: &Value) -> Result<Summary> {
    let mode: Mode =
        serde_json::from_value(config.get("mode").cloned().unwrap_or_default()).context("mode")?;
    let side = Side::from_mode(mode);
    let server_dials = config
        .get("server_dials")
        .or_else(|| config.get("reverse"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let direction = if server_dials {
        Direction::Direct
    } else {
        Direction::Reverse
    };
    let entry = match mode {
        Mode::Server => config.get("listeners").and_then(|l| l.get(0)),
        Mode::Client => config.get("paths").and_then(|l| l.get(0)),
    }
    .context("tunnel entry missing")?;
    let transport = entry
        .get("transport")
        .and_then(Value::as_str)
        .unwrap_or("tcp")
        .to_string();
    let addr = entry.get("addr").and_then(Value::as_str).unwrap_or("?");
    let raw = entry.get("raw").is_some_and(|raw| !raw.is_null());
    let listens = !raw && (mode == Mode::Server) != server_dials;
    let link = if raw {
        let peer = entry
            .pointer("/raw/peer_ip")
            .and_then(Value::as_str)
            .unwrap_or("?");
        format!("raw ↔ {peer}")
    } else if listens {
        format!("listen :{}", addr.rsplit_once(':').map_or(addr, |(_, p)| p))
    } else {
        format!("→ {addr}")
    };
    let tun = config.get("tun").is_some_and(|tun| !tun.is_null());
    let carry = if mode == Mode::Server {
        let mut ports: Vec<String> = Vec::new();
        for map in entry
            .get("maps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(port) = map
                .get("bind")
                .and_then(Value::as_str)
                .and_then(|bind| bind.rsplit_once(':'))
                .map(|(_, port)| port.to_string())
                && !ports.contains(&port)
            {
                ports.push(port);
            }
        }
        let mut parts = Vec::new();
        if tun {
            parts.push("TUN".to_string());
        }
        if !ports.is_empty() {
            let shown: Vec<_> = ports.iter().take(6).cloned().collect();
            let more = if ports.len() > 6 {
                format!(" +{}", ports.len() - 6)
            } else {
                String::new()
            };
            parts.push(format!("ports {}{more}", shown.join(",")));
        }
        if config.get("socks5").is_some_and(|s| !s.is_null()) {
            parts.push("SOCKS5".into());
        }
        parts.join(" + ")
    } else {
        let allowed: Vec<&str> = config
            .get("allowed_targets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let mut parts = Vec::new();
        if tun {
            parts.push("TUN".to_string());
        }
        if !allowed.is_empty() {
            parts.push(if allowed == ["*"] {
                "exit to anywhere".to_string()
            } else if allowed == ["127.0.0.1:*"] {
                "exit to this server's ports".to_string()
            } else {
                format!("exit to {}", allowed.join(", "))
            });
        }
        parts.join(" + ")
    };
    Ok(Summary {
        side,
        direction,
        transport,
        link,
        carry,
    })
}

/// Tunnel names become file and service names.
pub fn check_name(name: &str) -> Result<()> {
    ensure!(
        (1..=32).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !name.starts_with('-')
            && !name.ends_with('-'),
        "use 1 to 32 lowercase letters, digits and dashes (not at the start or end)"
    );
    // Tunnel services are `eztunnel-NAME.service`; these names belong to the management services.
    ensure!(
        !RESERVED_NAMES.contains(&name),
        "{name} is the name of an EZTunnel management service; choose another name"
    );
    Ok(())
}

/// Names a tunnel cannot have: `eztunnel-dashboard.service` and `eztunnel-agent.service` exist.
pub const RESERVED_NAMES: [&str; 2] = ["dashboard", "agent"];

/// Parses an IPv4 address that must belong to a real host.
pub fn unicast_ipv4(text: &str) -> Result<Ipv4Addr> {
    let ip: Ipv4Addr = text.trim().parse().context("enter an IPv4 address")?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        bail!("enter the address of a real host");
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel_key::TunnelKey;

    const TRANSPORTS: [Transport; 15] = [
        Transport::Tcp,
        Transport::Tcp6,
        Transport::Http,
        Transport::Https,
        Transport::Ws,
        Transport::Wss,
        Transport::Xhttp,
        Transport::Xhttps,
        Transport::Kcp,
        Transport::Parallax,
        Transport::Mirage,
        Transport::FecUdp,
        Transport::FecRaw,
        Transport::FecRawGaming,
        Transport::Tun,
    ];

    fn plan(side: Side, direction: Direction, transport: Transport, carry: Carry) -> Plan {
        let mut plan = Plan::new(
            TunnelKey::generate().unwrap().display(),
            side,
            direction,
            transport,
        );
        plan.carry = carry;
        plan.ports = parse_ports("443, 2083=2053").unwrap();
        plan.peer_host = Some(if transport == Transport::Tcp6 {
            "2001:db8::1".into()
        } else {
            "203.0.113.7".into()
        });
        if is_raw(transport) {
            plan.raw = Some(RawPlan {
                profile: "tcp".into(),
                peer_ip: "203.0.113.7".parse().unwrap(),
                ip_mode: IpMode::Normal,
                interface: None,
                local_ip: None,
                mirage: None,
            });
            if transport == Transport::Mirage {
                plan.raw.as_mut().unwrap().mirage = Some(MiragePlan {
                    spoof_src_ip: "198.51.100.8".parse().unwrap(),
                    advanced:None,
                    spoof_dst_ip: None,
                    gateway_ip: None,
                    peer_mac: None,
                });
            }
        }
        if carry.uses_tun() || transport == Transport::Tun {
            plan.tun = Some(TunPlan {
                name: "ez0".into(),
                local_ip: "10.77.0.1".into(),
                peer_ip: "10.77.0.2".into(),
                mtu: 1400,
                forwarding_port: (carry == Carry::TunPorts).then_some(47475),
                fragment: false,
            });
        }
        if carry == Carry::Socks && side == Side::Foreign {
            plan.allowed = vec!["*".into()];
        }
        plan
    }

    #[test]
    fn every_wizard_combination_produces_a_valid_configuration() {
        let mut checked = 0;
        for transport in TRANSPORTS {
            for side in [Side::Iran, Side::Foreign] {
                for direction in [Direction::Reverse, Direction::Direct] {
                    for carry in [Carry::Ports, Carry::Socks, Carry::Tun, Carry::TunPorts] {
                        if transport == Transport::Tun && !carry.uses_tun() {
                            continue;
                        }
                        for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Both] {
                            let mut plan = plan(side, direction, transport, carry);
                            plan.protocol = protocol;
                            let json = plan.to_json().unwrap();
                            check(&json).unwrap_or_else(|error| {
                                panic!(
                                    "{transport:?} {side:?} {direction:?} {carry:?} {protocol:?}: {error:#}\n{json:#}"
                                )
                            });
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert!(checked > 400, "{checked}");
    }

    /// The dialing side of a CDN tunnel is never asked for a TLS name; the CDN's domain is the name.
    #[test]
    fn a_dialing_cdn_tunnel_names_the_cdn_domain_in_tls() {
        for transport in [Transport::Https, Transport::Wss, Transport::Xhttps] {
            for direction in [Direction::Reverse, Direction::Direct] {
                let side = if direction == Direction::Reverse {
                    Side::Foreign
                } else {
                    Side::Iran
                };
                let mut plan = plan(side, direction, transport, Carry::Ports);
                plan.cdn = Some(CdnPlan {
                    domain: "tunnel.example.com".into(),
                });
                plan.sni = None;
                let json = plan.to_json().unwrap();
                check(&json).unwrap_or_else(|e| panic!("{transport:?}: {e:#}\n{json:#}"));
                let entry = json["paths"]
                    .get(0)
                    .or_else(|| json["listeners"].get(0))
                    .unwrap();
                if plan.dials() {
                    assert_eq!(entry["server_name"], "tunnel.example.com");
                }
            }
        }
    }

    /// A timing value set in Customize must reach the file whatever speed mode is selected.
    #[test]
    fn a_hand_set_kcp_timing_survives_the_speed_mode() {
        for speed in [
            crate::manager::speed::SpeedMode::Default,
            crate::manager::speed::SpeedMode::ALL[1],
        ] {
            let mut plan = plan(Side::Iran, Direction::Reverse, Transport::Kcp, Carry::Ports);
            plan.speed = speed;
            let setting = crate::manager::scope::relevant(&crate::manager::scope::Scope::new(Mode::Server, Transport::Kcp, false))
                .into_iter()
                .find(|s| s.name == "kcp.interval_ms")
                .expect("kcp.interval_ms is a setting");
            plan.tuned.push((setting, 25));
            let json = plan.to_json().unwrap();
            assert_eq!(
                json["listeners"][0]["kcp"]["interval_ms"], 25,
                "{speed:?} erased the value set by hand"
            );
            check(&json).unwrap();
        }
    }

    #[test]
    fn cdn_and_custom_options_are_valid() {
        for transport in [Transport::Xhttp, Transport::Xhttps] {
            for side in [Side::Iran, Side::Foreign] {
                for direction in [Direction::Reverse, Direction::Direct] {
                    let mut plan = plan(side, direction, transport, Carry::Ports);
                    plan.cdn = Some(CdnPlan {
                        domain: "tunnel.example.com".into(),
                    });
                    plan.xhttp_mode = XhttpMode::Auto;
                    plan.http_path = "/api/v2".into();
                    plan.sni = Some("www.example.com".into());
                    let json = plan.to_json().unwrap();
                    check(&json).unwrap_or_else(|e| panic!("{e:#}\n{json:#}"));
                }
            }
        }
        // Writing every offered setting explicitly at its default must always pass.
        let mut plan = plan(Side::Iran, Direction::Reverse, Transport::Kcp, Carry::Ports);
        for setting in crate::manager::scope::relevant(&crate::manager::scope::Scope::new(Mode::Server, Transport::Kcp, false)) {
            if let Some(value) = setting.default.as_u64() {
                plan.tuned.push((setting, value));
            }
        }
        check(&plan.to_json().unwrap()).unwrap();
    }

    #[test]
    fn the_two_sides_of_one_tunnel_agree() {
        for direction in [Direction::Reverse, Direction::Direct] {
            let iran = plan(Side::Iran, direction, Transport::Wss, Carry::Ports);
            let foreign = plan(Side::Foreign, direction, Transport::Wss, Carry::Ports);
            assert_ne!(iran.dials(), foreign.dials());
            let (i, f) = (iran.to_json().unwrap(), foreign.to_json().unwrap());
            assert_eq!(i.get("server_dials"), f.get("server_dials"));
        }
    }

    #[test]
    fn port_lists_are_read_and_written() {
        let rules = parse_ports("443, 8443=2053 9000-9002,5000=10.0.0.2:5001").unwrap();
        assert_eq!(rules.len(), 6);
        assert_eq!(rules[1].target, "127.0.0.1:2053");
        assert_eq!(rules[5].target, "10.0.0.2:5001");
        assert_eq!(parse_ports(&format_ports(&rules)).unwrap(), rules);
        assert!(parse_ports("").is_err());
        assert!(parse_ports("443,443").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("10-5").is_err());
        assert!(parse_ports("abc").is_err());
        // A target hostname may itself contain a dash; it must not be read as a port range.
        let dashed = parse_ports("2083=db-prod.internal:5432").unwrap();
        assert_eq!(dashed[0].target, "db-prod.internal:5432");
    }

    #[test]
    fn summaries_describe_saved_tunnels() {
        let iran = plan(Side::Iran, Direction::Reverse, Transport::Tcp, Carry::Ports);
        let summary = summarize(&iran.to_json().unwrap()).unwrap();
        assert_eq!(summary.side, Side::Iran);
        assert_eq!(summary.direction, Direction::Reverse);
        assert_eq!(summary.link, "listen :7000");
        assert_eq!(summary.carry, "ports 443,2083");
        let foreign = plan(
            Side::Foreign,
            Direction::Reverse,
            Transport::Kcp,
            Carry::Ports,
        );
        let summary = summarize(&foreign.to_json().unwrap()).unwrap();
        assert_eq!(summary.link, "→ 203.0.113.7:7000");
        let direct = plan(Side::Iran, Direction::Direct, Transport::Tcp, Carry::Ports);
        assert_eq!(
            summarize(&direct.to_json().unwrap()).unwrap().link,
            "→ 203.0.113.7:7000"
        );
    }

    #[test]
    fn every_profile_works_for_every_carrier_and_side() {
        for profile in Profile::ALL {
            for transport in TRANSPORTS {
                for side in [Side::Iran, Side::Foreign] {
                    for direction in [Direction::Reverse, Direction::Direct] {
                        let carry = if transport == Transport::Tun {
                            Carry::Tun
                        } else {
                            Carry::Ports
                        };
                        let mut plan = plan(side, direction, transport, carry);
                        plan.apply_profile(profile);
                        plan.apply_profile(profile);
                        let names: Vec<&str> = plan.tuned.iter().map(|(s, _)| s.name).collect();
                        let mut unique = names.clone();
                        unique.dedup();
                        assert_eq!(names.len(), unique.len(), "{names:?}");
                        check(&plan.to_json().unwrap()).unwrap_or_else(|e| {
                            panic!("{profile:?} {transport:?} {side:?} {direction:?}: {e:#}")
                        });
                        let expected = profile == Profile::Gaming
                            && plan.carries_udp()
                            && !is_raw(transport)
                            && !(side == Side::Foreign && direction == Direction::Direct);
                        assert_eq!(plan.to_json().unwrap().get("gaming").is_some(), expected,
                            "Game mode for {profile:?} {transport:?} {side:?} {direction:?}");
                        let config = plan.to_json().unwrap();
                        let low_delay = ["listeners", "paths"].iter().any(|list| {
                            config[*list][0]["fec"]["profile"].as_str() == Some("gaming")
                        });
                        assert_eq!(low_delay, profile == Profile::Gaming && transport == Transport::FecRaw,
                            "low delay for {profile:?} {transport:?} {side:?} {direction:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn the_streaming_profile_widens_only_the_udp_carriers_windows() {
        let value = |plan: &Plan, name: &str| {
            plan.tuned
                .iter()
                .find(|(setting, _)| setting.name == name)
                .map(|(_, value)| *value)
        };
        // FEC gets 2048-packet windows; KCP keeps its own (bigger KCP windows built up delay).
        let mut fec = plan(Side::Iran, Direction::Reverse, Transport::FecUdp, Carry::Ports);
        fec.apply_profile(Profile::Streaming);
        assert_eq!(value(&fec, "fec.sndwnd"), Some(2048));
        fec.apply_profile(Profile::Gaming);
        assert_eq!(value(&fec, "fec.sndwnd"), None, "switching profiles leaves nothing behind");
        let mut kcp = plan(Side::Iran, Direction::Reverse, Transport::Kcp, Carry::Ports);
        kcp.apply_profile(Profile::Streaming);
        assert_eq!(value(&kcp, "kcp.send_window"), None);
        let mut tcp = plan(Side::Iran, Direction::Reverse, Transport::Tcp, Carry::Ports);
        tcp.apply_profile(Profile::Streaming);
        assert_eq!(value(&tcp, "fec.sndwnd"), None);
        assert_eq!(value(&tcp, "kcp.send_window"), None);
        assert_eq!(value(&tcp, "stream_window"), Some(256));
    }

    #[test]
    fn every_speed_mode_gives_a_valid_configuration_for_every_kcp_and_fec_carrier() {
        use super::super::speed::SpeedMode;
        for transport in [
            Transport::Kcp,
            Transport::FecUdp,
            Transport::FecRaw,
            Transport::FecRawGaming,
        ] {
            for side in [Side::Iran, Side::Foreign] {
                for direction in [Direction::Reverse, Direction::Direct] {
                    if is_raw(transport) && direction == Direction::Direct {
                        continue;
                    }
                    for mode in SpeedMode::ALL {
                        let mut plan = plan(side, direction, transport, Carry::Ports);
                        plan.speed = mode;
                        let json = plan.to_json().unwrap();
                        check(&json).unwrap_or_else(|e| {
                            panic!("{mode:?} {transport:?} {side:?} {direction:?}: {e:#}")
                        });
                        let entry = if side == Side::Iran {
                            &json["listeners"][0]
                        } else {
                            &json["paths"][0]
                        };
                        let key = if transport == Transport::Kcp {
                            "kcp"
                        } else {
                            "fec"
                        };
                        match mode {
                            SpeedMode::Default => assert!(entry.get(key).is_none()),
                            SpeedMode::Fast3 => assert_eq!(entry[key]["interval_ms"], 10),
                            _ => assert!(entry[key]["interval_ms"].as_u64().unwrap() >= 20),
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn names_are_checked() {
        assert!(check_name("iran-1").is_ok());
        for reserved in RESERVED_NAMES {
            assert!(check_name(reserved).is_err(), "{reserved} is a management service");
        }
        for bad in ["", "Iran", "a b", "-x", "x-", "a/b", &"x".repeat(33)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn settings_can_be_set_read_and_removed() {
        let mut json = plan(Side::Iran, Direction::Reverse, Transport::Kcp, Carry::Ports)
            .to_json()
            .unwrap();
        let all = crate::manager::scope::relevant(&crate::manager::scope::Scope::new(Mode::Server, Transport::Kcp, false));
        let mtu = all.iter().find(|s| s.name == "kcp.mtu").unwrap();
        assert_eq!(read_setting(&json, mtu), None);
        apply_setting(&mut json, mtu, Some(1200)).unwrap();
        assert_eq!(read_setting(&json, mtu), Some(1200));
        check(&json).unwrap();
        apply_setting(&mut json, mtu, None).unwrap();
        assert_eq!(read_setting(&json, mtu), None);
        assert!(
            crate::manager::scope::relevant(&crate::manager::scope::Scope::new(Mode::Server, Transport::Tcp, false))
                .iter()
                .all(|s| !s.name.starts_with("kcp."))
        );
    }
}
