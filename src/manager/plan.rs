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
    pub xhttp_mode: XhttpMode,
    pub cdn: Option<CdnPlan>,
    pub raw: Option<RawPlan>,
    pub tun: Option<TunPlan>,
    /// Changed tunables as (setting, value).
    pub tuned: Vec<(Setting, u64)>,
    /// KCP/FEC timing mode (only for those carriers); `Default` writes nothing.
    pub speed: super::speed::SpeedMode,
    /// Wire format of the tunnel: 2 = probe resistance (new tunnels), 1 = 0.6.x and earlier.
    pub wire_version: u8,
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
            xhttp_mode: XhttpMode::StreamUp,
            cdn: None,
            raw: None,
            tun: None,
            tuned: Vec::new(),
            speed: super::speed::SpeedMode::Default,
            wire_version: crate::stealth::new_version(),
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

    fn host_port(host: &str, port: u16) -> String {
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }

    /// The configuration file content.
    pub fn to_json(&self) -> Result<Value> {
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
            entry.insert("fec".into(), json!({"pacer": true}));
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
        if dials && !single && self.pool != 1 {
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
            Profile::Gaming => "small queues and fast detection of a dead link",
            Profile::Streaming => "the largest window for fast single downloads",
        }
    }

    /// (pool, settings by name)
    fn values(self) -> (usize, &'static [(&'static str, u64)]) {
        match self {
            Profile::General => (4, &[("stream_window", 256)]),
            Profile::ManyUsers => (
                8,
                &[
                    ("stream_window", 128),
                    ("max_streams", 4096),
                    ("max_connections", 32),
                ],
            ),
            Profile::Gaming => (
                4,
                &[
                    ("stream_window", 64),
                    ("heartbeat_sec", 5),
                    ("dead_timeout_sec", 20),
                ],
            ),
            // The UDP carriers cap one connection at window x packet size per round trip
            // (about 100 Mbit/s at 90 ms with the default 1024 packets); their buffers must
            // hold the larger window.
            Profile::Streaming => (
                8,
                &[
                    ("stream_window", 512),
                    ("kcp.send_window", 4096),
                    ("kcp.recv_window", 4096),
                    ("kcp.socket_buf_bytes", 16_777_216),
                    ("fec.sndwnd", 4096),
                    ("fec.rcvwnd", 4096),
                    ("fec.socket_buf_bytes", 16_777_216),
                ],
            ),
        }
    }
}

impl Plan {
    /// Applies a profile, replacing earlier values of the same settings.
    pub fn apply_profile(&mut self, profile: Profile) {
        let (pool, values) = profile.values();
        self.pool = pool;
        let available = relevant_settings(
            self.mode(),
            self.transport,
            self.direction == Direction::Direct,
        );
        for (name, value) in values {
            if let Some(setting) = available.iter().find(|s| s.name == *name) {
                self.tuned.retain(|(s, _)| s.name != *name);
                self.tuned.push((setting.clone(), *value));
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

/// The tunables worth offering for one side and carrier.
pub fn relevant_settings(mode: Mode, transport: Transport, server_dials: bool) -> Vec<Setting> {
    let role = match mode {
        Mode::Server => "server",
        Mode::Client => "client",
    };
    crate::settings::all()
        .into_iter()
        .filter(|s| s.role == "both" || s.role == role)
        .filter(|s| match s.name.split_once('.').map(|(group, _)| group) {
            Some("kcp") => transport == Transport::Kcp,
            Some("parallax") => transport == Transport::Parallax,
            Some("fec") => matches!(
                transport,
                Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage
            ),
            Some("xhttp") => is_xhttp(transport),
            Some("tls_fragment") => transport.uses_tls(),
            _ => true,
        })
        .filter(|s| s.name != "timeouts.server_dial_sec" || server_dials)
        // The wizard asks for the pool directly.
        .filter(|s| s.name != "connection_pool")
        .collect()
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
    Ok(())
}

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
            let setting = relevant_settings(Mode::Server, Transport::Kcp, false)
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
        for setting in relevant_settings(Mode::Server, Transport::Kcp, false) {
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
        for (transport, window, buffer) in [
            (Transport::FecUdp, "fec.sndwnd", "fec.socket_buf_bytes"),
            (Transport::Kcp, "kcp.send_window", "kcp.socket_buf_bytes"),
        ] {
            let mut streaming = plan(Side::Iran, Direction::Reverse, transport, Carry::Ports);
            streaming.apply_profile(Profile::Streaming);
            assert_eq!(value(&streaming, window), Some(4096), "{transport:?}");
            // The buffer must hold the larger window.
            assert_eq!(value(&streaming, buffer), Some(16_777_216), "{transport:?}");
            let mut general = plan(Side::Iran, Direction::Reverse, transport, Carry::Ports);
            general.apply_profile(Profile::General);
            assert_eq!(value(&general, window), None, "{transport:?}");
        }
        let mut tcp = plan(Side::Iran, Direction::Reverse, Transport::Tcp, Carry::Ports);
        tcp.apply_profile(Profile::Streaming);
        assert_eq!(value(&tcp, "fec.sndwnd"), None);
        assert_eq!(value(&tcp, "kcp.send_window"), None);
        assert_eq!(value(&tcp, "stream_window"), Some(512));
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
        for bad in ["", "Iran", "a b", "-x", "x-", "a/b", &"x".repeat(33)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn settings_can_be_set_read_and_removed() {
        let mut json = plan(Side::Iran, Direction::Reverse, Transport::Kcp, Carry::Ports)
            .to_json()
            .unwrap();
        let all = relevant_settings(Mode::Server, Transport::Kcp, false);
        let mtu = all.iter().find(|s| s.name == "kcp.mtu").unwrap();
        assert_eq!(read_setting(&json, mtu), None);
        apply_setting(&mut json, mtu, Some(1200)).unwrap();
        assert_eq!(read_setting(&json, mtu), Some(1200));
        check(&json).unwrap();
        apply_setting(&mut json, mtu, None).unwrap();
        assert_eq!(read_setting(&json, mtu), None);
        assert!(
            relevant_settings(Mode::Server, Transport::Tcp, false)
                .iter()
                .all(|s| !s.name.starts_with("kcp."))
        );
    }
}
