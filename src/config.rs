use crate::stealth::{Stealth, WireOptions};
use crate::tunnel_key::{AutoTls, TunnelKey};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    Client,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MapKind {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Tcp,
    Kcp,
    Parallax,
    Mirage,
    Http,
    Https,
    Ws,
    Wss,
    Xhttp,
    Xhttps,
    Tcp6,
    #[serde(rename = "fec-udp")]
    FecUdp,
    #[serde(rename = "fec-raw")]
    FecRaw,
    #[serde(rename = "fec-raw-gaming")]
    FecRawGaming,
    Tun,
}

impl Transport {
    pub fn uses_tls(self) -> bool {
        matches!(self, Self::Https | Self::Wss | Self::Xhttps)
    }

    pub fn uses_http(self) -> bool {
        matches!(
            self,
            Self::Http | Self::Https | Self::Ws | Self::Wss | Self::Xhttp | Self::Xhttps
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    Auto,
    #[default]
    StreamUp,
    PacketUp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct XhttpOptions {
    pub mode: XhttpMode,
    pub host: Option<String>,
    pub edge_addrs: Vec<String>,
    pub user_agent: String,
    pub pad_min: usize,
    pub pad_max: usize,
    /// Fixed TCP socket buffer. Unset leaves sizing to the kernel, which grows the buffers
    /// with the link; a fixed value turns that off and caps one connection's speed.
    pub socket_buf_bytes: Option<usize>,
    pub up_max_bytes: usize,
    pub up_concurrency: usize,
    pub buffer_bytes: usize,
    pub probe_ms: u64,
    pub session_timeout_sec: u64,
    /// Server: simultaneous HTTP connections accepted before a request is parsed.
    pub max_requests: usize,
    /// Server: simultaneous XHTTP sessions.
    pub max_sessions: usize,
    /// Client: how long a failed edge address is skipped.
    pub edge_retry_sec: u64,
    /// Server: most simultaneous HTTP connections from one source address (0 = no limit).
    /// Behind a CDN every user shares a few edge addresses, so raise or disable this there.
    pub max_requests_per_ip: usize,
    /// Server: most simultaneous XHTTP sessions from one source address (0 = no limit). A session
    /// keeps counting for as long as it lives, unlike `max_requests_per_ip`, which only counts the
    /// request being read. Behind a CDN every user shares a few edge addresses: leave it at 0.
    pub max_sessions_per_ip: usize,
    /// Optional shared secret. When set, the server refuses to create a session for a request
    /// that does not carry a proof derived from it, before any session resources are used.
    /// Use the same value on both ends, and prefer TLS: without TLS the proof can be observed.
    pub access_token: Option<String>,
}

impl Default for XhttpOptions {
    fn default() -> Self {
        Self {
            mode: XhttpMode::StreamUp,
            host: None,
            edge_addrs: Vec::new(),
            user_agent: "eztunnel".into(),
            pad_min: 0,
            pad_max: 0,
            socket_buf_bytes: None,
            up_max_bytes: 65_536,
            up_concurrency: 8,
            buffer_bytes: 32_768,
            probe_ms: 8000,
            session_timeout_sec: 40,
            max_requests: 256,
            max_sessions: 64,
            edge_retry_sec: 60,
            max_requests_per_ip: 64,
            max_sessions_per_ip: 0,
            access_token: None,
        }
    }
}

impl XhttpOptions {
    fn validate(&self) -> Result<()> {
        ensure!(
            (1024..=1_048_576).contains(&self.up_max_bytes),
            "XHTTP up_max_bytes must be 1024..1048576"
        );
        ensure!(
            (1..=16).contains(&self.up_concurrency),
            "XHTTP up_concurrency must be 1..16"
        );
        ensure!(
            (1024..=1_048_576).contains(&self.buffer_bytes),
            "XHTTP buffer_bytes must be 1024..1048576"
        );
        ensure!(
            (100..=60_000).contains(&self.probe_ms),
            "XHTTP probe_ms must be 100..60000"
        );
        ensure!(
            (5..=3600).contains(&self.session_timeout_sec),
            "XHTTP session_timeout_sec must be 5..3600"
        );
        ensure!(
            (1..=65_536).contains(&self.max_requests),
            "XHTTP max_requests must be 1..65536"
        );
        ensure!(
            (1..=65_536).contains(&self.max_sessions),
            "XHTTP max_sessions must be 1..65536"
        );
        ensure!(
            (1..=3600).contains(&self.edge_retry_sec),
            "XHTTP edge_retry_sec must be 1..3600"
        );
        ensure!(
            self.max_requests_per_ip <= 65_536,
            "XHTTP max_requests_per_ip must be 0..65536 (0 = no limit)"
        );
        ensure!(
            self.max_sessions_per_ip <= 65_536,
            "XHTTP max_sessions_per_ip must be 0..65536 (0 = no limit)"
        );
        if let Some(token) = &self.access_token {
            ensure!(
                (16..=128).contains(&token.len())
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._~+/=-".contains(&b)),
                "XHTTP access_token must be 16..128 characters from A-Z a-z 0-9 . _ ~ + / = -"
            );
        }
        ensure!(
            self.edge_addrs.len() <= 16,
            "XHTTP edge_addrs supports at most 16 explicitly configured addresses"
        );
        ensure!(
            self.pad_min <= self.pad_max && self.pad_max <= 4096,
            "XHTTP padding range must be ordered and at most 4096 bytes"
        );
        ensure!(
            !self.user_agent.is_empty()
                && self.user_agent.len() <= 256
                && self.user_agent.is_ascii()
                && !self.user_agent.bytes().any(|b| b.is_ascii_control()),
            "XHTTP user_agent must be 1..256 ASCII bytes without control characters"
        );
        ensure!(
            self.socket_buf_bytes
                .is_none_or(|bytes| (65_536..=67_108_864).contains(&bytes)),
            "XHTTP socket_buf_bytes must be 65536..67108864 when set"
        );
        for addr in &self.edge_addrs {
            endpoint(addr).context("invalid XHTTP edge address")?;
        }
        if let Some(host) = &self.host {
            crate::carrier::http_authority(host)?;
            ensure!(
                !host.is_empty()
                    && host.len() <= 253
                    && host.is_ascii()
                    && !host.bytes().any(|b| b.is_ascii_control()
                        || b.is_ascii_whitespace()
                        || matches!(b, b'/' | b'\\' | b'?' | b'#')),
                "XHTTP host must be an ASCII HTTP authority without whitespace or URL path"
            );
        }
        Ok(())
    }
}

/// Settings for the plain `kcp` carrier. Both ends should use the same MTU.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KcpOptions {
    pub mtu: usize,
    pub send_window: u16,
    pub recv_window: u16,
    pub session_expire_sec: u64,
    /// Server: most simultaneous KCP sessions.
    pub max_sessions: usize,
    /// Server: most KCP sessions from one source address (0 = no limit).
    pub max_sessions_per_ip: usize,
    /// Send without waiting to collect a full packet, and retransmit sooner.
    pub nodelay: bool,
    /// How often KCP sends and resends, in milliseconds.
    pub interval_ms: u32,
    /// Resend a packet after this many later packets were acknowledged (0 = off).
    pub resend: u16,
    /// Slow down when packets are lost. Off sends at the full window on lossy links.
    pub congestion_control: bool,
    /// UDP socket send/receive buffer.
    pub socket_buf_bytes: usize,
    /// Most packets resent at once (per `interval_ms`) because their retransmission timer expired
    /// (0 = no limit).
    pub resend_burst: u32,
}

impl Default for KcpOptions {
    fn default() -> Self {
        Self {
            mtu: 1400,
            send_window: 1024,
            recv_window: 1024,
            session_expire_sec: 60,
            max_sessions: 1024,
            max_sessions_per_ip: 64,
            nodelay: true,
            interval_ms: 10,
            resend: 2,
            congestion_control: false,
            socket_buf_bytes: 4 * 1024 * 1024,
            resend_burst: 128,
        }
    }
}

impl KcpOptions {
    fn validate(&self) -> Result<()> {
        ensure!(
            (512..=9000).contains(&self.mtu),
            "kcp mtu must be 512..9000"
        );
        ensure!(
            (16..=8192).contains(&self.send_window) && (16..=8192).contains(&self.recv_window),
            "kcp send_window/recv_window must be 16..8192"
        );
        ensure!(
            (5..=3600).contains(&self.session_expire_sec),
            "kcp session_expire_sec must be 5..3600"
        );
        ensure!(
            (1..=65_536).contains(&self.max_sessions) && self.max_sessions_per_ip <= 65_536,
            "kcp max_sessions must be 1..65536 and max_sessions_per_ip 0..65536 (0 = no limit)"
        );
        ensure!(
            (10..=5000).contains(&self.interval_ms),
            "kcp interval_ms must be 10..5000"
        );
        ensure!(self.resend <= 255, "kcp resend must be 0..255");
        ensure!(
            (65_536..=67_108_864).contains(&self.socket_buf_bytes),
            "kcp socket_buf_bytes must be 65536..67108864"
        );
        ensure!(
            self.resend_burst <= 8192,
            "kcp resend_burst must be 0..8192"
        );
        Ok(())
    }
}

/// Time limits, all in seconds.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Timeouts {
    /// Time a new connection has to finish the key handshake (server side).
    pub handshake_sec: u64,
    /// Time allowed to connect to the real destination, and for a SOCKS5 greeting.
    pub connect_sec: u64,
    /// Time a stream may wait for the far side to confirm it opened.
    pub open_sec: u64,
    /// A forwarded UDP conversation with no traffic for this long is closed.
    pub udp_idle_sec: u64,
    /// A forwarded TCP connection with no data in either direction for this long is closed
    /// (0 = never). Without it, idle connections from a single address hold stream slots forever.
    pub tcp_idle_sec: u64,
    /// Longest pause between reconnect attempts.
    pub retry_max_sec: u64,
    /// On stopping, how long to keep running after telling the other server goodbye, so the
    /// notice is sent (0 = do not wait, and the notice may not get out).
    pub goodbye_wait_ms: u64,
    /// When the server dials (`server_dials`): time to reach the client and finish the handshake.
    #[serde(alias = "reverse_dial_sec")]
    pub server_dial_sec: u64,
    /// Server: when the other server connects again, its older sessions get a ping; one that
    /// hears nothing for this long is closed (the other server crashed or lost them), so users
    /// are not sent to it until the dead timeout.
    pub probe_sec: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            handshake_sec: 10,
            connect_sec: 10,
            open_sec: 15,
            udp_idle_sec: 120,
            tcp_idle_sec: 3600,
            retry_max_sec: 30,
            goodbye_wait_ms: 500,
            server_dial_sec: 30,
            probe_sec: 3,
        }
    }
}

impl Timeouts {
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("handshake_sec", self.handshake_sec),
            ("connect_sec", self.connect_sec),
            ("open_sec", self.open_sec),
            ("server_dial_sec", self.server_dial_sec),
        ] {
            ensure!(
                (1..=300).contains(&value),
                "timeouts.{name} must be 1..300 seconds"
            );
        }
        ensure!(
            (5..=86_400).contains(&self.udp_idle_sec),
            "timeouts.udp_idle_sec must be 5..86400 seconds"
        );
        ensure!(
            self.tcp_idle_sec <= 86_400,
            "timeouts.tcp_idle_sec must be 0..86400 seconds (0 = never)"
        );
        ensure!(
            (1..=3600).contains(&self.retry_max_sec),
            "timeouts.retry_max_sec must be 1..3600 seconds"
        );
        ensure!(
            self.goodbye_wait_ms <= 5000,
            "timeouts.goodbye_wait_ms must be 0..5000 milliseconds"
        );
        ensure!(
            (1..=60).contains(&self.probe_sec),
            "timeouts.probe_sec must be 1..60 seconds"
        );
        Ok(())
    }
}

/// How many frames may wait in memory. Larger values absorb bursts and use more memory.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Queues {
    /// Frames waiting for one stream. Must leave room for a full flow-control window.
    pub stream_frames: usize,
    /// Frames waiting to be sent or processed for one session.
    pub session_frames: usize,
}

impl Default for Queues {
    fn default() -> Self {
        Self {
            stream_frames: 32,
            session_frames: 128,
        }
    }
}

impl Queues {
    fn validate(&self) -> Result<()> {
        ensure!(
            (20..=4096).contains(&self.stream_frames),
            "queues.stream_frames must be 20..4096"
        );
        ensure!(
            (16..=65_536).contains(&self.session_frames),
            "queues.session_frames must be 16..65536"
        );
        Ok(())
    }
}

/// Planned restarts. The program exits cleanly and the service manager starts it again, which
/// clears any slow build-up (leaked memory in the kernel, stuck sockets) without anyone noticing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Schedule {
    /// Restart after running this many hours. 0 = never.
    pub restart_every_hours: u64,
}

impl Schedule {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.restart_every_hours <= 8760,
            "schedule.restart_every_hours must be 0 (never) to 8760"
        );
        Ok(())
    }
}

/// A limit on the data one tunnel carries per period. The tunnel counts what it sends to and
/// receives from the other server; when the limit is reached it stops carrying traffic until the
/// period ends, then starts again with a fresh count.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Quota {
    /// Gigabytes (10^9 bytes) per period, both directions together. 0 = no limit.
    pub limit_gb: u64,
    /// Length of one period in days. The first period starts when the tunnel first runs.
    pub period_days: u64,
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            limit_gb: 0,
            period_days: 30,
        }
    }
}

impl Quota {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.limit_gb <= 1_000_000,
            "quota.limit_gb must be 0 (no limit) to 1000000"
        );
        ensure!(
            (1..=3650).contains(&self.period_days),
            "quota.period_days must be 1..3650"
        );
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        self.limit_gb > 0
    }

    pub fn limit_bytes(&self) -> u64 {
        self.limit_gb.saturating_mul(1_000_000_000)
    }

    pub fn period_seconds(&self) -> u64 {
        self.period_days.saturating_mul(86_400)
    }
}

/// How the dialing side of a TLS carrier looks on the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsProfile {
    /// The program's own TLS client (rustls), as in every earlier version.
    #[default]
    Classic,
    /// A ClientHello like the one Chrome sends (BoringSSL): same cipher suites, extensions, groups,
    /// signature algorithms, GREASE, random extension order and ECH GREASE.
    Chrome,
}

impl TlsProfile {
    pub fn is_classic(&self) -> bool {
        *self == Self::Classic
    }
}

/// `tls_profile` other than classic needs the side that dials, a TLS carrier and a build with
/// the `browser-tls` feature.
fn validate_tls_profile(profile: TlsProfile, dials: bool, transport: Transport) -> Result<()> {
    if profile.is_classic() {
        return Ok(());
    }
    ensure!(
        dials,
        "tls_profile applies to the side that dials; set it on the other side, or leave it out"
    );
    ensure!(
        transport.uses_tls(),
        "tls_profile needs a TLS carrier (wss, https or xhttps)"
    );
    ensure!(
        cfg!(feature = "browser-tls"),
        "this build was made without the browser-tls feature, so tls_profile \"chrome\" is not available"
    );
    Ok(())
}

/// A per-path or per-listener `tcp_congestion` override: same rule as the top-level setting.
fn validate_tcp_congestion_override(value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    ensure!(
        (1..=15).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "tcp_congestion must be an algorithm name such as bbr or cubic, or system"
    );
    Ok(())
}

/// The local address a dialing side connects from (`local_address`).
pub fn parse_local_address(text: &str) -> Result<std::net::IpAddr> {
    let address: std::net::IpAddr = text
        .parse()
        .context("local_address must be an IP address without a port")?;
    ensure!(
        !address.is_unspecified() && !address.is_multicast(),
        "local_address must be one of this server's own unicast addresses"
    );
    Ok(address)
}

fn validate_local_address(value: Option<&str>, dials: bool, transport: Transport) -> Result<()> {
    let Some(text) = value else {
        return Ok(());
    };
    parse_local_address(text)?;
    ensure!(
        dials,
        "local_address applies to the side that dials; set it on the other side, or leave it out"
    );
    ensure!(
        server_can_dial(transport),
        "local_address does not apply to the raw carriers; use raw.local_ip"
    );
    Ok(())
}

impl Listener {
    /// Physical HTTP dial settings for a logical server in reverse mode.
    pub fn dial_path(&self, dial_timeout: u64) -> ClientPath {
        ClientPath {
            addr: self.addr.clone(),
            transport: self.transport,
            ca_file: self.ca_file.clone(),
            server_name: self.server_name.clone(),
            cert_file: None,
            key_file: None,
            xhttp: self.xhttp.clone(),
            fec: self.fec.clone(),
            kcp: self.kcp.clone(),
            parallax: self.parallax.clone(),
            parallax_key: self.parallax_key.clone(),
            raw: self.raw.clone(),
            http_path: self.http_path.clone(),
            tls_auto: self.tls_auto,
            tls_fragment: self.tls_fragment,
            auto_tls: self.auto_tls.clone(),
            wire: self.wire.clone(),
            server_public_key: String::new(),
            connection_pool: self.connection_pool,
            retry_interval: 1,
            dial_timeout,
            local_address: self.local_address.clone(),
            tls_profile: self.tls_profile,
            tcp_congestion: self.tcp_congestion.clone(),
        }
    }
}

impl ClientPath {
    /// Physical HTTP listening settings for a logical client in reverse mode.
    pub fn listen_config(&self) -> Listener {
        Listener {
            addr: self.addr.clone(),
            transport: self.transport,
            cert_file: self.cert_file.clone(),
            key_file: self.key_file.clone(),
            ca_file: None,
            server_name: None,
            connection_pool: 1,
            xhttp: self.xhttp.clone(),
            fec: self.fec.clone(),
            kcp: self.kcp.clone(),
            parallax: self.parallax.clone(),
            parallax_key: self.parallax_key.clone(),
            raw: self.raw.clone(),
            http_path: self.http_path.clone(),
            tls_auto: self.tls_auto,
            tls_fragment: self.tls_fragment,
            auto_tls: self.auto_tls.clone(),
            wire: self.wire.clone(),
            local_address: None,
            tls_profile: TlsProfile::Classic,
            tcp_congestion: self.tcp_congestion.clone(),
            maps: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortMap {
    #[serde(rename = "type")]
    pub kind: MapKind,
    pub bind: String,
    pub target: String,
    /// TCP maps only: send the user's real address to the destination in a PROXY protocol
    /// header of this version (1 = text, 2 = binary) before the user's data. The destination
    /// service must expect it. Off when absent. Needs EZTunnel 0.7.1 or later on both servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub addr: String,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default = "one")]
    pub connection_pool: usize,
    #[serde(default)]
    pub xhttp: XhttpOptions,
    #[serde(default)]
    pub fec: crate::fec_carrier::FecOptions,
    #[serde(default)]
    pub kcp: KcpOptions,
    #[serde(default)]
    pub parallax: crate::parallax_carrier::Options,
    #[serde(skip)]
    pub parallax_key: Option<crate::parallax_carrier::Key>,
    #[serde(default)]
    pub raw: Option<crate::raw_packet::RawOptions>,
    #[serde(default = "default_http_path")]
    pub http_path: String,
    /// Use the TLS certificate derived from the tunnel key instead of certificate files.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls_auto: bool,
    /// Split the TLS ClientHello when this side dials (off by default).
    #[serde(default, skip_serializing_if = "fragment_is_default")]
    pub tls_fragment: crate::fragment::TlsFragment,
    #[serde(skip)]
    pub auto_tls: Option<Arc<AutoTls>>,
    #[serde(skip)]
    pub wire: WireOptions,
    /// Server that dials (`server_dials`): connect from this local IP address instead of the
    /// one the system picks. Ignored by the raw carriers, which have their own `raw.local_ip`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_address: Option<String>,
    /// What the TLS client of a dialing server looks like (see `TlsProfile`).
    #[serde(default, skip_serializing_if = "TlsProfile::is_classic")]
    pub tls_profile: TlsProfile,
    /// Overrides the top-level `tcp_congestion` for this listener's TCP connections. Absent keeps
    /// the program-wide setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_congestion: Option<String>,
    #[serde(default)]
    pub maps: Vec<PortMap>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPath {
    pub addr: String,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub xhttp: XhttpOptions,
    #[serde(default)]
    pub fec: crate::fec_carrier::FecOptions,
    #[serde(default)]
    pub kcp: KcpOptions,
    #[serde(default)]
    pub parallax: crate::parallax_carrier::Options,
    #[serde(skip)]
    pub parallax_key: Option<crate::parallax_carrier::Key>,
    #[serde(default)]
    pub raw: Option<crate::raw_packet::RawOptions>,
    #[serde(default = "default_http_path")]
    pub http_path: String,
    /// Use the TLS certificate derived from the tunnel key instead of certificate files.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls_auto: bool,
    /// Split the TLS ClientHello when this side dials (off by default).
    #[serde(default, skip_serializing_if = "fragment_is_default")]
    pub tls_fragment: crate::fragment::TlsFragment,
    #[serde(skip)]
    pub auto_tls: Option<Arc<AutoTls>>,
    #[serde(skip)]
    pub wire: WireOptions,
    /// Derived from `tunnel_key` when that is used.
    #[serde(default)]
    pub server_public_key: String,
    #[serde(default = "one")]
    pub connection_pool: usize,
    #[serde(default = "one_u64")]
    pub retry_interval: u64,
    #[serde(default = "ten")]
    pub dial_timeout: u64,
    /// Connect from this local IP address instead of the one the system picks, for a server
    /// with more than one address. Only the side that dials uses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_address: Option<String>,
    /// What the TLS client of this side looks like (see `TlsProfile`).
    #[serde(default, skip_serializing_if = "TlsProfile::is_classic")]
    pub tls_profile: TlsProfile,
    /// Overrides the top-level `tcp_congestion` for this path's TCP connections. Absent keeps the
    /// program-wide setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_congestion: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    pub name: String,
    pub address: String,
    pub peer_address: String,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    /// Optional authenticated forwarding service carried by TCP over the inner TUN IPs.
    #[serde(default)]
    pub forwarding_port: Option<u16>,
    /// Lets an IP packet bigger than one outer raw packet go out in pieces instead of `mtu`
    /// being capped to what the chosen raw profile's single packet can carry. Off by default:
    /// relying on the network's own IP fragmentation across a filtered path is risky (fragments
    /// are a common thing to drop), so this still has a real cost (one more packet exchanged, and
    /// a lost piece loses the whole datagram), it is just paid for deliberately when a higher
    /// `mtu` is wanted.
    #[serde(default)]
    pub fragment: bool,
    /// Optional 2-data/1-XOR parity, raw TUN only; must match on both endpoints.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub parity: bool,
    /// Probe the authenticated raw carrier's usable datagram size and log an advisory
    /// inner MTU. Does not change the interface or turn stream payloads into PMTU claims.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mtu_probe: bool,
}

fn default_tun_mtu() -> u16 {
    1400
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub gaming: crate::gaming::Options,
    /// Free-form note for operators, ignored when loading (JSON has no comments).
    #[serde(default, rename = "_comment", skip_serializing)]
    pub note: Option<serde::de::IgnoredAny>,
    pub mode: Mode,
    /// Which side opens the connection between the servers. Normally the client dials the
    /// server; with this set the server dials the client instead. The server still holds the
    /// port maps and SOCKS5, and the client still reaches the targets.
    #[serde(default, alias = "reverse")]
    pub server_dials: bool,
    #[serde(default)]
    pub tun: Option<TunConfig>,
    /// The shared secret both peers hold (`eztunnel key` makes one). Both identities, the XHTTP
    /// access token and the `tls_auto` certificate are derived from it, so `private_key_file`,
    /// `peer_public_keys` and `server_public_key` are left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_key: Option<String>,
    /// File containing the legacy tunnel key; mutually exclusive with an inline key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_key_file: Option<PathBuf>,
    /// Level-2 parser plumbing. Unsupported levels fail closed until the new handshake lands.
    #[serde(default = "crypto_one")]
    pub crypto_level: u8,
    #[serde(default = "crypto_one")]
    pub crypto_min: u8,
    #[serde(skip)]
    derived_private_key: Option<Zeroizing<[u8; 32]>>,
    #[serde(default)]
    pub private_key_file: PathBuf,
    #[serde(default)]
    pub peer_public_keys: Vec<String>,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub paths: Vec<ClientPath>,
    #[serde(default)]
    pub socks5: Option<String>,
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    #[serde(default = "ten")]
    pub heartbeat_sec: u64,
    #[serde(default = "forty")]
    pub dead_timeout_sec: u64,
    #[serde(default = "streams")]
    pub max_streams: usize,
    /// Flow-control window per user connection, in 16 KiB frames. One connection moves at most
    /// window × 16 KiB per round trip between the servers.
    #[serde(default = "stream_window")]
    pub stream_window: usize,
    /// A new user connection sends its first data right behind the request to open it, instead
    /// of waiting for the other server to confirm: one round trip less per connection. The other
    /// server queues the data until the destination is connected (every version does).
    #[serde(default = "default_true")]
    pub stream_early_data: bool,
    /// Memory (MiB) the flow-control windows of all user connections may use beyond the first
    /// 256 KiB each. 0 = automatic: a quarter of the machine's memory, 64 MiB to 1 GiB. Once it
    /// is used up, new connections keep a small window (a lower speed on long links) instead of
    /// the server running out of memory.
    #[serde(default)]
    pub memory_budget_mb: u64,
    #[serde(default = "connections")]
    pub max_connections: usize,
    /// Prefer healthy measured sessions for new streams only. Off preserves round-robin.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub path_quality_steering: bool,
    /// Server: connections still waiting to finish the key handshake, over all listeners.
    #[serde(default = "pending_handshakes")]
    pub max_pending_handshakes: usize,
    /// Server: handshakes one source address may have waiting at the same time.
    #[serde(default = "pending_per_ip")]
    pub max_pending_per_ip: usize,
    /// Server: forwarded connections and UDP conversations one source address may have open at
    /// the same time through the maps and the SOCKS5 listener (0 = no limit).
    #[serde(default = "streams_per_ip")]
    pub max_streams_per_ip: usize,
    /// Raise the open-file limit to this many descriptors. When absent, the process raises its
    /// soft limit to the hard limit.
    #[serde(default)]
    pub max_open_files: Option<u64>,
    /// Log a one-line status summary this often (seconds). 0 turns it off.
    #[serde(default = "stats_interval")]
    pub stats_interval_sec: u64,
    /// Threads that run the tunnel's work. One is the most efficient: the work is many small
    /// network operations, and moving them between threads costs more CPU than it saves (measured
    /// on loopback: one thread carried KCP at 1.3 Gbit/s using 11 CPU-seconds per GB, six threads
    /// 0.7 Gbit/s using 28). Raise it only for a very fast FEC carrier, which is limited by what
    /// one core can encode and decode.
    #[serde(default = "one_thread")]
    pub worker_threads: usize,
    /// TCP congestion control for this program's tunnel connections, for example `bbr` or
    /// `cubic`; `system` keeps the machine's default. Only the tunnel's own sockets change.
    #[serde(default = "tcp_congestion")]
    pub tcp_congestion: String,
    /// Wire format: 1 = 0.6.x and earlier (the default when absent), 2 = probe resistance
    /// (stream mask, hold-then-close, derived names), 3 = authenticated session rotation
    /// for authenticated sessions. Both ends must use the same value.
    #[serde(
        default = "crate::stealth::default_version",
        skip_serializing_if = "crate::stealth::version_is_default"
    )]
    pub wire_version: u8,
    /// Settings of wire version 2.
    #[serde(default, skip_serializing_if = "crate::stealth::stealth_is_default")]
    pub stealth: Stealth,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default)]
    pub queues: Queues,
    /// Planned restarts (off by default).
    #[serde(default, skip_serializing_if = "is_default_schedule")]
    pub schedule: Schedule,
    /// Data limit per period (off by default).
    #[serde(default, skip_serializing_if = "is_default_quota")]
    pub quota: Quota,
}

fn is_default_schedule(value: &Schedule) -> bool {
    *value == Schedule::default()
}

fn is_default_quota(value: &Quota) -> bool {
    *value == Quota::default()
}

/// Wire version 2 replaces the default path `/tunnel` with one derived from the server key, the same
/// on both ends; any other path is kept.
fn v2_path(path: &str, wire: &WireOptions) -> String {
    if path == "/tunnel" {
        wire.derived_path()
    } else {
        path.to_string()
    }
}

/// User-Agent of XHTTP requests in wire version 2 unless one was chosen.
const BROWSER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

fn crypto_one() -> u8 {
    1
}

fn one() -> usize {
    1
}

fn fragment_is_default(value: &crate::fragment::TlsFragment) -> bool {
    *value == crate::fragment::TlsFragment::default()
}

fn default_http_path() -> String {
    "/tunnel".into()
}

fn validate_http_path(path: &str) -> Result<()> {
    ensure!(
        path.starts_with('/')
            && path.len() <= 512
            && path.is_ascii()
            && !path.bytes().any(|b| b.is_ascii_control()
                || b.is_ascii_whitespace()
                || matches!(b, b'?' | b'#' | b'\\')),
        "http_path must be an ASCII absolute URL path of at most 512 bytes without query or fragment"
    );
    Ok(())
}

fn validate_server_name(name: Option<&str>) -> Result<()> {
    let name = name.context("TLS dialer requires server_name matching the certificate")?;
    ensure!(
        !name.is_empty()
            && name.len() <= 253
            && name.is_ascii()
            && !name
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
        "invalid TLS server_name"
    );
    Ok(())
}

/// Whether the server can open the connection for this carrier (`server_dials`). The raw
/// carriers address a fixed peer from both ends, so the direction does not apply to them.
pub fn server_can_dial(transport: Transport) -> bool {
    !matches!(
        transport,
        Transport::FecRaw | Transport::FecRawGaming | Transport::Tun | Transport::Mirage
    )
}

fn validate_tls_auto(tls_auto: bool, transport: Transport, has_tunnel_key: bool) -> Result<()> {
    if tls_auto {
        ensure!(
            transport.uses_tls(),
            "tls_auto requires a TLS carrier (https, wss or xhttps)"
        );
        ensure!(
            has_tunnel_key,
            "tls_auto derives the certificate from tunnel_key; set tunnel_key"
        );
    }
    Ok(())
}

fn validate_transport_address(transport: Transport, addr: &str) -> Result<()> {
    if transport == Transport::Tcp6 {
        let address = addr
            .parse::<SocketAddr>()
            .context("tcp6 requires a literal [IPv6]:port address")?;
        ensure!(address.is_ipv6(), "tcp6 requires IPv6");
    }
    Ok(())
}

fn validate_carrier_options(
    transport: Transport,
    fec: &crate::fec_carrier::FecOptions,
    raw: Option<&crate::raw_packet::RawOptions>,
    tun: bool,
) -> Result<()> {
    fec.validate()?;
    ensure!(
        fec.peer_mtu.is_none()
            || matches!(
                transport,
                Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage
            ),
        "fec peer_mtu requires a raw FEC carrier"
    );
    if matches!(
        transport,
        Transport::FecRaw | Transport::FecRawGaming | Transport::Tun | Transport::Mirage
    ) {
        raw.context("fec-raw, fec-raw-gaming and tun require raw configuration")?
            .validate()?;
        if transport != Transport::Tun {
            ensure!(fec.mtu >= 512, "raw FEC MTU must be at least 512");
        }
        if transport == Transport::Mirage {
            crate::mirage::validate(raw)?;
        }
    } else {
        ensure!(
            raw.is_none(),
            "raw configuration requires fec-raw, fec-raw-gaming or tun"
        );
    }
    ensure!(
        transport != Transport::Tun || tun,
        "the tun carrier requires a root tun interface configuration"
    );
    Ok(())
}

fn resolve_optional_path(path: &mut Option<PathBuf>, base: &Path) -> Result<()> {
    if let Some(path) = path {
        ensure!(
            !path.as_os_str().is_empty(),
            "TLS file path must not be empty"
        );
        if path.is_relative() {
            *path = base.join(&*path);
        }
    }
    Ok(())
}
fn one_u64() -> u64 {
    1
}
fn ten() -> u64 {
    10
}
fn forty() -> u64 {
    40
}
fn streams() -> usize {
    1024
}
fn tcp_congestion() -> String {
    "bbr".into()
}
fn default_true() -> bool {
    true
}

fn stream_window() -> usize {
    64
}
fn connections() -> usize {
    16
}
fn stats_interval() -> u64 {
    60
}
fn one_thread() -> usize {
    1
}
fn pending_handshakes() -> usize {
    64
}
fn pending_per_ip() -> usize {
    16
}

fn streams_per_ip() -> usize {
    512
}

pub fn decode_key(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64,
        "key must contain exactly 64 hexadecimal characters"
    );
    let mut key = [0u8; 32];
    hex::decode_to_slice(value, &mut key).context("key contains invalid hexadecimal characters")?;
    ensure!(
        key.iter().any(|&b| b != 0),
        "all-zero keys are not accepted"
    );
    Ok(key)
}

fn endpoint(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 1024,
        "endpoint exceeds the wire protocol's 1024-byte target limit"
    );
    ensure!(
        !value.is_empty() && !value.chars().any(char::is_whitespace),
        "endpoint must be host:port without whitespace"
    );
    let (host, port) = value
        .rsplit_once(':')
        .context("endpoint must include a port")?;
    ensure!(!host.is_empty(), "endpoint must include a host");
    if host.contains(':') {
        ensure!(
            host.starts_with('[') && host.ends_with(']'),
            "IPv6 endpoints must use [address]:port"
        );
        host[1..host.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .context("invalid IPv6 address")?;
    } else {
        ensure!(
            host.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
            "invalid endpoint hostname"
        );
    }
    ensure!(
        port.parse::<u16>().context("invalid endpoint port")? != 0,
        "target port must be nonzero"
    );
    Ok(())
}

/// Names under `.invalid` never resolve (RFC 2606). The far end answers some of them itself,
/// such as the speed test target, so users must never be able to ask for them.
pub(crate) fn reserved_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "invalid" || host.ends_with(".invalid")
}

/// `addr`, with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) reduced to the plain IPv4 address
/// it really is on the wire, so the two compare equal to whatever actually shares that port.
fn wire_equivalent(addr: std::net::IpAddr) -> std::net::IpAddr {
    match addr {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, std::net::IpAddr::V4),
        v4 => v4,
    }
}

/// The addresses already taken by a configuration, for one protocol. Two binds conflict when they
/// are the same address (after `wire_equivalent`), when one is the wildcard of the same address
/// family (`0.0.0.0` or `[::]`) and the other has the same port, or when one is the IPv6 wildcard
/// at all: Linux leaves `IPV6_V6ONLY` off by default, so `[::]` is dual-stack and also claims the
/// port for IPv4. In every case the second `bind` would fail with "address in use".
#[derive(Default)]
struct Binds(Vec<SocketAddr>);

impl Binds {
    /// Takes `addr`; `false` when it conflicts with one taken before.
    fn insert(&mut self, addr: SocketAddr) -> bool {
        let is_ipv6_wildcard =
            |ip: std::net::IpAddr| matches!(ip, std::net::IpAddr::V6(v6) if v6.is_unspecified());
        let conflicts = self.0.iter().any(|taken| {
            if taken.port() != addr.port() {
                return false;
            }
            if is_ipv6_wildcard(taken.ip()) || is_ipv6_wildcard(addr.ip()) {
                return true;
            }
            let taken_ip = wire_equivalent(taken.ip());
            let addr_ip = wire_equivalent(addr.ip());
            // A genuine (non-mapped) IPv6 address never shares a port with an IPv4 one.
            taken_ip.is_ipv4() == addr_ip.is_ipv4()
                && (taken_ip == addr_ip || taken_ip.is_unspecified() || addr_ip.is_unspecified())
        });
        if !conflicts {
            self.0.push(addr);
        }
        !conflicts
    }
}

/// Whether `value` has a different setting from the defaults (compared as JSON).
fn is_default<T: Serialize + Default>(value: &T) -> bool {
    serde_json::to_value(value).ok() == serde_json::to_value(T::default()).ok()
}

/// The XHTTP settings are the defaults, apart from what `prepare()` fills in for every tunnel by
/// itself: the access token derived from a `tunnel_key`, and the browser user agent of wire v2.
fn xhttp_is_default(value: &XhttpOptions) -> bool {
    let default = XhttpOptions::default();
    let mut value = value.clone();
    value.access_token = default.access_token.clone();
    value.user_agent = default.user_agent.clone();
    is_default(&value)
}

fn bind_address(value: &str) -> Result<()> {
    value
        .parse::<SocketAddr>()
        .context("listen/bind address must be an IP address and port (IPv6 uses brackets)")?;
    Ok(())
}

impl Drop for Config {
    fn drop(&mut self) {
        self.tunnel_key.zeroize();
        for listener in &mut self.listeners {
            listener.xhttp.access_token.zeroize();
        }
        for path in &mut self.paths {
            path.xhttp.access_token.zeroize();
        }
    }
}

impl Config {
    /// What is probably a mistake but works: settings that do nothing on the chosen carrier, and a
    /// queue size that is raised to the stream window. Shown by `--check`, at start and by the
    /// manager; never an error, because configurations that run today must keep running.
    pub fn warnings(&self) -> Vec<String> {
        let mut found = Vec::new();
        let mut carrier = |label: String,
                           transport: Transport,
                           tls_fragment: &crate::fragment::TlsFragment,
                           tls_profile: TlsProfile,
                           xhttp: &XhttpOptions,
                           fec: &crate::fec_carrier::FecOptions,
                           kcp: &KcpOptions| {
            if !transport.uses_tls() {
                if !is_default(tls_fragment) {
                    found.push(format!(
                        "{label}: tls_fragment does nothing on {transport:?} (it needs a TLS carrier)"
                    ));
                }
                if tls_profile != TlsProfile::default() {
                    found.push(format!(
                        "{label}: tls_profile does nothing on {transport:?} (it needs a TLS carrier)"
                    ));
                }
            }
            if !matches!(transport, Transport::Xhttp | Transport::Xhttps)
                && !xhttp_is_default(xhttp)
            {
                found.push(format!(
                    "{label}: the xhttp settings do nothing on {transport:?}"
                ));
            }
            if !matches!(
                transport,
                Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage
            ) && !is_default(fec)
            {
                found.push(format!(
                    "{label}: the fec settings do nothing on {transport:?}"
                ));
            }
            if transport != Transport::Kcp && !is_default(kcp) {
                found.push(format!(
                    "{label}: the kcp settings do nothing on {transport:?}"
                ));
            }
        };
        for listener in &self.listeners {
            carrier(
                format!("listener {}", listener.addr),
                listener.transport,
                &listener.tls_fragment,
                listener.tls_profile,
                &listener.xhttp,
                &listener.fec,
                &listener.kcp,
            );
        }
        for path in &self.paths {
            carrier(
                format!("path {}", path.addr),
                path.transport,
                &path.tls_fragment,
                path.tls_profile,
                &path.xhttp,
                &path.fec,
                &path.kcp,
            );
        }
        let wanted = self.stream_window + 4;
        if self.queues.stream_frames != Queues::default().stream_frames
            && self.queues.stream_frames < wanted
        {
            found.push(format!(
                "queues.stream_frames ({}) is raised to stream_window + 4 ({wanted}) for every stream",
                self.queues.stream_frames
            ));
        }
        found
    }

    /// Checks only for tunnels the manager saves and starts as services: an address with port 0
    /// asks the system for any free port, so the peer could never find it again (tests use it).
    pub fn ensure_fixed_ports(&self) -> Result<()> {
        let fixed = |what: &str, addr: &str| -> Result<()> {
            if let Ok(parsed) = addr.parse::<SocketAddr>() {
                ensure!(
                    parsed.port() != 0,
                    "{what} {addr} uses port 0 (any free port); give it a fixed port"
                );
            }
            Ok(())
        };
        if !self.server_dials {
            for listener in &self.listeners {
                fixed("listener", &listener.addr)?;
            }
        } else {
            // server_dials inverts the roles: the client's own paths are what it binds and
            // waits on for the server to dial in, so they need a fixed port too.
            for path in &self.paths {
                fixed("path", &path.addr)?;
            }
        }
        for listener in &self.listeners {
            for map in &listener.maps {
                fixed("map bind", &map.bind)?;
            }
        }
        if let Some(socks) = &self.socks5 {
            fixed("socks5", socks)?;
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let input = Zeroizing::new(
            fs::read_to_string(path)
                .with_context(|| format!("read configuration {}", path.display()))?,
        );
        let mut config: Self =
            serde_json::from_str(&input).context("invalid configuration JSON")?;
        #[cfg(unix)]
        if config.tunnel_key.is_some() {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)
                .context("read configuration metadata")?
                .permissions()
                .mode();
            ensure!(
                mode & 0o077 == 0,
                "{} holds a tunnel key, so other users must not read it; use chmod 600",
                path.display()
            );
        }
        if !config.private_key_file.as_os_str().is_empty() && config.private_key_file.is_relative()
        {
            config.private_key_file = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&config.private_key_file);
        }
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve_optional_path(&mut config.tunnel_key_file, base)?;
        for listener in &mut config.listeners {
            resolve_optional_path(&mut listener.cert_file, base)?;
            resolve_optional_path(&mut listener.key_file, base)?;
            resolve_optional_path(&mut listener.ca_file, base)?;
        }
        for path in &mut config.paths {
            resolve_optional_path(&mut path.ca_file, base)?;
            resolve_optional_path(&mut path.cert_file, base)?;
            resolve_optional_path(&mut path.key_file, base)?;
        }
        config.prepare()?;
        config.validate()?;
        Ok(config)
    }

    /// Fills in everything derived from `tunnel_key`: this side's private key, the other side's
    /// public key, the XHTTP access token (unless one is set) and the `tls_auto` certificate.
    /// `load` calls this; code that builds a configuration in memory calls it before `validate`.
    pub fn prepare(&mut self) -> Result<()> {
        self.prepare_key()?;
        self.apply_wire()
    }

    /// Copies the wire version, its settings and the server's public key into each listener and
    /// path, where the carriers read them.
    fn apply_wire(&mut self) -> Result<()> {
        ensure!(
            crate::stealth::valid_version(self.wire_version),
            "wire_version must be 1, 2 or 3"
        );
        self.stealth.validate()?;
        let mut wire = WireOptions {
            version: self.wire_version,
            stealth: self.stealth.clone(),
            server_key: [0; 32],
        };
        if self.wire_version < 2 {
            for listener in &mut self.listeners {
                listener.wire = wire.clone();
            }
            for path in &mut self.paths {
                path.wire = wire.clone();
            }
            return Ok(());
        }
        match self.mode {
            Mode::Server => {
                wire.server_key = crate::tunnel_key::public_of(&*self.private_key()?)?;
                for listener in &mut self.listeners {
                    listener.wire = wire.clone();
                    if let Some(raw) = listener.raw.as_mut() {
                        raw.icmp_id_mirror = true;
                    }
                    listener.http_path = v2_path(&listener.http_path, &wire);
                }
            }
            Mode::Client => {
                for path in &mut self.paths {
                    let mut own = wire.clone();
                    own.server_key = decode_key(&path.server_public_key)
                        .context("wire_version 2 needs the server public key")?;
                    path.http_path = v2_path(&path.http_path, &own);
                    if path.xhttp.user_agent == "eztunnel" {
                        path.xhttp.user_agent = BROWSER_AGENT.into();
                    }
                    if let Some(raw) = path.raw.as_mut() {
                        raw.icmp_id_mirror = true;
                    }
                    path.wire = own;
                }
            }
        }
        Ok(())
    }

    fn prepare_key(&mut self) -> Result<()> {
        ensure!(
            self.tunnel_key.is_none() || self.tunnel_key_file.is_none(),
            "use tunnel_key or tunnel_key_file, not both"
        );
        let file_text;
        let text = if let Some(path) = &self.tunnel_key_file {
            use std::io::Read;
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
            }
            let file = options.open(path).context("open tunnel key file")?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() <= 256,
                "tunnel key must be a small regular file"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    metadata.permissions().mode() & 0o077 == 0,
                    "tunnel key file requires chmod 600"
                );
            }
            file_text = {
                let mut text = Zeroizing::new(String::new());
                file.take(257).read_to_string(&mut text)?;
                ensure!(text.len() <= 256, "tunnel key file exceeds size limit");
                text
            };
            Some(file_text.trim())
        } else {
            self.tunnel_key.as_deref()
        };
        let Some(text) = text else {
            return Ok(());
        };
        let key = TunnelKey::parse(text).context("invalid tunnel_key")?;
        ensure!(
            self.private_key_file.as_os_str().is_empty()
                && self.peer_public_keys.is_empty()
                && self.paths.iter().all(|p| p.server_public_key.is_empty()),
            "with tunnel_key, leave out private_key_file, peer_public_keys and server_public_key"
        );
        self.derived_private_key = Some(key.private_key(self.mode));
        let other = match self.mode {
            Mode::Server => Mode::Client,
            Mode::Client => Mode::Server,
        };
        let other = hex::encode(key.public_key(other)?);
        match self.mode {
            Mode::Server => self.peer_public_keys = vec![other],
            Mode::Client => {
                for path in &mut self.paths {
                    path.server_public_key = other.clone();
                }
            }
        }
        let tls = if self
            .listeners
            .iter()
            .map(|l| l.tls_auto)
            .chain(self.paths.iter().map(|p| p.tls_auto))
            .any(|auto| auto)
        {
            let name = (self.wire_version >= 2).then(|| {
                WireOptions {
                    version: 2,
                    stealth: Stealth::default(),
                    server_key: key.public_key(Mode::Server).unwrap_or([0; 32]),
                }
                .certificate_name()
            });
            Some(key.tls(name.as_deref())?)
        } else {
            None
        };
        let token = key.xhttp_token();
        for listener in &mut self.listeners {
            if listener.tls_auto {
                listener.auto_tls = tls.clone();
            }
            listener
                .xhttp
                .access_token
                .get_or_insert_with(|| token.clone());
            listener.parallax_key = Some(crate::parallax_carrier::Key::new(key.parallax_key()));
            listener.fec.packet_lane_key = Some(crate::packet_lane::Key::new(key.packet_lane_key()));
            if let Some(raw)=&mut listener.raw {raw.hopping.key=Some(crate::port_hop::Key::new(key.port_hop_key()));if let Some(spec)=&mut raw.mirage{spec.admission_key=Some(crate::spoof::AdmissionKey::new(key.mirage_key()));}}
        }
        for path in &mut self.paths {
            if path.tls_auto {
                path.auto_tls = tls.clone();
            }
            path.xhttp.access_token.get_or_insert_with(|| token.clone());
            path.parallax_key = Some(crate::parallax_carrier::Key::new(key.parallax_key()));
            path.fec.packet_lane_key = Some(crate::packet_lane::Key::new(key.packet_lane_key()));
            if let Some(raw)=&mut path.raw {raw.hopping.key=Some(crate::port_hop::Key::new(key.port_hop_key()));if let Some(spec)=&mut raw.mirage{spec.admission_key=Some(crate::spoof::AdmissionKey::new(key.mirage_key()));}}
        }
        Ok(())
    }

    /// Refuses a secret file that every user of the machine can read (group access is allowed:
    /// certificate tools often make a key readable by a group on purpose).
    pub(crate) fn ensure_not_world_readable(path: &Path, what: &str) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)
                .with_context(|| format!("read {what} metadata"))?
                .permissions()
                .mode();
            ensure!(
                mode & 0o007 == 0,
                "{what} {} can be read by every user of this machine; run: chmod o-rwx on it",
                path.display()
            );
        }
        let _ = (path, what);
        Ok(())
    }

    pub fn private_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        if let Some(key) = &self.derived_private_key {
            return Ok(key.clone());
        }
        let metadata = fs::metadata(&self.private_key_file).context("read private key metadata")?;
        ensure!(
            metadata.is_file() && metadata.len() <= 256,
            "private key must be a small regular hex text file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "private key permissions must exclude group and others; use chmod 600"
            );
        }
        let text = Zeroizing::new(
            fs::read_to_string(&self.private_key_file).context("read private key file")?,
        );
        decode_key(text.trim())
            .map(Zeroizing::new)
            .context("invalid private key file")
    }

    pub fn validate(&self) -> Result<()> {
        self.gaming.validate()?;
        let shared_key=self.tunnel_key.is_some()||self.tunnel_key_file.is_some();
        ensure!(!self.gaming.enabled()||shared_key,"direct gaming requires tunnel_key or tunnel_key_file for the configured peer identity set");
        ensure!(!self.gaming.enabled() || self.tun.is_none(),"direct gaming currently requires forwarding mode, not TUN");
        for (transport,fec,raw) in self.listeners.iter().map(|entry|(entry.transport,&entry.fec,entry.raw.as_ref())).chain(self.paths.iter().map(|entry|(entry.transport,&entry.fec,entry.raw.as_ref()))) {
            let raw_fec=matches!(transport,Transport::FecRaw|Transport::FecRawGaming|Transport::Mirage);
            ensure!(fec.tcp_fallback.address.is_none()||raw_fec,"TCP packet fallback requires a raw FEC carrier");
            ensure!(fec.tcp_fallback.address.is_none()||shared_key,"TCP packet fallback requires tunnel_key or tunnel_key_file");
            if let Some(raw)=raw {
                ensure!(!raw.hopping.enabled||raw_fec,"adaptive hopping currently requires a raw FEC carrier");
                ensure!(!raw.hopping.enabled||shared_key,"adaptive hopping requires tunnel_key or tunnel_key_file");
            }
        }
        ensure!(
            self.crypto_level == 1 && self.crypto_min == 1,
            "crypto level 2 is not implemented by this release"
        );
        match &self.tunnel_key {
            _ if self.tunnel_key.is_some() || self.tunnel_key_file.is_some() => ensure!(
                self.derived_private_key.is_some(),
                "tunnel_key has not been applied; call prepare() before validate()"
            ),
            _ => ensure!(
                !self.private_key_file.as_os_str().is_empty(),
                "set tunnel_key, or private_key_file with the peer public keys"
            ),
        }
        ensure!(
            (1..=3600).contains(&self.heartbeat_sec),
            "heartbeat_sec must be 1..3600"
        );
        ensure!(
            self.dead_timeout_sec > self.heartbeat_sec && self.dead_timeout_sec <= 86400,
            "dead_timeout_sec must exceed heartbeat_sec and be at most 86400"
        );
        // An idle tunnel only sends its heartbeat; a session that is reaped before the next one
        // would be torn down and rebuilt over and over.
        for (transport, xhttp_idle, fec_idle) in self
            .listeners
            .iter()
            .map(|l| {
                (
                    l.transport,
                    l.xhttp.session_timeout_sec,
                    l.fec.peer_idle_sec,
                )
            })
            .chain(self.paths.iter().map(|p| {
                (
                    p.transport,
                    p.xhttp.session_timeout_sec,
                    p.fec.peer_idle_sec,
                )
            }))
        {
            if matches!(transport, Transport::Xhttp | Transport::Xhttps) {
                ensure!(
                    xhttp_idle > self.heartbeat_sec,
                    "xhttp.session_timeout_sec ({xhttp_idle}) must exceed heartbeat_sec ({})",
                    self.heartbeat_sec
                );
            }
            if matches!(
                transport,
                Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage
            ) {
                ensure!(
                    fec_idle > self.heartbeat_sec,
                    "fec.peer_idle_sec ({fec_idle}) must exceed heartbeat_sec ({})",
                    self.heartbeat_sec
                );
            }
        }
        ensure!(
            (1..=65536).contains(&self.max_streams),
            "max_streams must be 1..65536"
        );
        ensure!(
            (1..=15).contains(&self.tcp_congestion.len())
                && self
                    .tcp_congestion
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "tcp_congestion must be an algorithm name such as bbr or cubic, or system"
        );
        ensure!(
            (16..=1024).contains(&self.stream_window),
            "stream_window must be 16..1024 frames"
        );
        ensure!(
            self.memory_budget_mb <= 1_048_576,
            "memory_budget_mb must be 0 (automatic) to 1048576"
        );
        ensure!(
            (1..=1024).contains(&self.max_connections),
            "max_connections must be 1..1024"
        );
        ensure!(
            (1..=64).contains(&self.worker_threads),
            "worker_threads must be 1..64"
        );
        ensure!(
            self.stats_interval_sec <= 86_400,
            "stats_interval_sec must be 0..86400 (0 turns the status line off)"
        );
        self.timeouts.validate()?;
        self.queues.validate()?;
        self.schedule.validate()?;
        self.quota.validate()?;
        ensure!(
            crate::stealth::valid_version(self.wire_version),
            "wire_version must be 1, 2 or 3"
        );
        self.stealth.validate()?;
        ensure!(
            self.wire_version >= 2
                || (self.stealth.record_pad_max == 0 && self.stealth.jitter_ms == 0),
            "stealth.record_pad_max and stealth.jitter_ms need wire_version 2"
        );
        if let Some(limit) = self.max_open_files {
            ensure!(
                (256..=16_777_216).contains(&limit),
                "max_open_files must be 256..16777216"
            );
        }
        ensure!(
            (1..=4096).contains(&self.max_pending_handshakes),
            "max_pending_handshakes must be 1..4096"
        );
        ensure!(
            (1..=256).contains(&self.max_pending_per_ip),
            "max_pending_per_ip must be 1..256"
        );
        ensure!(
            self.max_streams_per_ip <= 65_536,
            "max_streams_per_ip must be 0..65536 (0 = no limit)"
        );
        for key in &self.peer_public_keys {
            decode_key(key).context("invalid peer_public_keys entry")?;
        }
        for target in &self.allowed_targets {
            if target == "*" {
                continue;
            }
            match target.strip_suffix(":*") {
                Some(host) => endpoint(&format!("{host}:1")),
                None => endpoint(target),
            }
            .context("invalid allowed_targets entry (use host:port, host:* or *)")?;
        }
        if let Some(tun) = &self.tun {
            ensure!(
                !(tun.parity || tun.mtu_probe)
                    || match self.mode {
                        Mode::Server =>
                            self.listeners.len() == 1
                                && self.listeners[0].transport == Transport::Tun,
                        Mode::Client =>
                            self.paths.len() == 1 && self.paths[0].transport == Transport::Tun,
                    },
                "tun.parity and tun.mtu_probe require the raw tun carrier"
            );
            ensure!(
                !tun.name.is_empty()
                    && tun.name.len() <= 15
                    && tun
                        .name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')),
                "TUN name must contain 1..15 ASCII letters, digits, underscores or hyphens"
            );
            let address = tun
                .address
                .parse::<std::net::IpAddr>()
                .context("TUN address must be a literal IP without a prefix")?;
            let peer = tun
                .peer_address
                .parse::<std::net::IpAddr>()
                .context("TUN peer_address must be a literal IP without a prefix")?;
            ensure!(
                address.is_ipv4() == peer.is_ipv4() && address != peer,
                "TUN addresses must be distinct and use the same IP version"
            );
            ensure!(
                !address.is_unspecified()
                    && !address.is_multicast()
                    && !peer.is_unspecified()
                    && !peer.is_multicast(),
                "TUN addresses must be unicast"
            );
            ensure!(
                (576..=9000).contains(&tun.mtu) && (address.is_ipv4() || tun.mtu >= 1280),
                "TUN MTU must be 576..9000 (at least 1280 for IPv6)"
            );
            if let Some(port) = tun.forwarding_port {
                ensure!(port >= 1024, "tun.forwarding_port must be 1024..65535");
                ensure!(
                    !address.is_loopback() && !peer.is_loopback(),
                    "TUN forwarding addresses must not be loopback addresses"
                );
                for bind in self
                    .socks5
                    .iter()
                    .chain(self.listeners.iter().flat_map(|listener| {
                        listener
                            .maps
                            .iter()
                            .filter(|map| map.kind == MapKind::Tcp)
                            .map(|map| &map.bind)
                    }))
                {
                    let bind = bind
                        .parse::<SocketAddr>()
                        .context("invalid TUN forwarding service bind")?;
                    let bind_ip = wire_equivalent(bind.ip());
                    let tun_ip = wire_equivalent(address);
                    let same_wire_address = bind_ip == tun_ip || bind_ip.is_unspecified();
                    ensure!(
                        bind.port() != port || !same_wire_address,
                        "a TCP map or SOCKS bind conflicts with tun.forwarding_port"
                    );
                }
            } else {
                ensure!(
                    self.socks5.is_none()
                        && self.allowed_targets.is_empty()
                        && self.listeners.iter().all(|l| l.maps.is_empty()),
                    "TUN maps, socks5 or allowed_targets require tun.forwarding_port on both peers"
                );
            }
            match self.mode {
                Mode::Server => ensure!(
                    self.listeners.len() == 1 && self.listeners[0].connection_pool == 1,
                    "TUN server requires exactly one listener with connection_pool 1"
                ),
                Mode::Client => ensure!(
                    self.paths.len() == 1 && self.paths[0].connection_pool == 1,
                    "TUN client requires exactly one path with connection_pool 1"
                ),
            }
        }
        match self.mode {
            Mode::Server => {
                ensure!(
                    !self.listeners.is_empty(),
                    "server requires at least one listener"
                );
                ensure!(
                    !self.peer_public_keys.is_empty(),
                    "server requires at least one authorized peer_public_keys entry"
                );
                ensure!(self.paths.is_empty(), "paths are only valid in client mode");
                ensure!(
                    self.allowed_targets.is_empty(),
                    "allowed_targets are only valid in client mode"
                );
                if let Some(addr) = &self.socks5 {
                    bind_address(addr).context("invalid socks5 address")?;
                }
                let mut tcp_binds = Binds::default();
                let mut udp_binds = Binds::default();
                if self.server_dials {
                    let total = self
                        .listeners
                        .iter()
                        .try_fold(0usize, |n, l| n.checked_add(l.connection_pool))
                        .context("reverse connection pool total overflow")?;
                    ensure!(
                        total <= self.max_connections,
                        "reverse listener pools exceed max_connections"
                    );
                }
                if let Some(addr) = &self.socks5 {
                    tcp_binds.insert(addr.parse::<SocketAddr>()?);
                }
                for listener in &self.listeners {
                    if self.server_dials {
                        endpoint(&listener.addr)?;
                    } else {
                        bind_address(&listener.addr).context("invalid listener address")?;
                    }
                    validate_transport_address(listener.transport, &listener.addr)?;
                    validate_carrier_options(
                        listener.transport,
                        &listener.fec,
                        listener.raw.as_ref(),
                        self.tun.is_some(),
                    )?;
                    if listener.raw.is_some() {
                        ensure!(
                            listener.connection_pool == 1,
                            "raw carriers require one connection per configured peer"
                        );
                    }
                    validate_http_path(&listener.http_path)?;
                    listener.xhttp.validate()?;
                    listener.kcp.validate()?;
                    listener.parallax.validate()?;
                    ensure!(
                        listener.transport != Transport::Parallax
                            || listener.parallax_key.is_some(),
                        "Parallax requires tunnel_key"
                    );
                    listener.tls_fragment.validate()?;
                    validate_tcp_congestion_override(listener.tcp_congestion.as_deref())?;
                    ensure!(
                        (1..=self.max_connections).contains(&listener.connection_pool),
                        "listener connection_pool exceeds max_connections"
                    );
                    validate_tls_auto(
                        listener.tls_auto,
                        listener.transport,
                        self.tunnel_key.is_some() || self.tunnel_key_file.is_some(),
                    )?;
                    validate_local_address(
                        listener.local_address.as_deref(),
                        self.server_dials,
                        listener.transport,
                    )?;
                    validate_tls_profile(
                        listener.tls_profile,
                        self.server_dials,
                        listener.transport,
                    )?;
                    if self.server_dials {
                        ensure!(
                            server_can_dial(listener.transport),
                            "server_dials does not work with the raw carriers (fec-raw, fec-raw-gaming, tun)"
                        );
                        ensure!(
                            listener.cert_file.is_none() && listener.key_file.is_none(),
                            "a dialing server uses ca_file/server_name (or tls_auto) for TLS"
                        );
                        if listener.transport.uses_tls() {
                            if listener.tls_auto {
                                ensure!(listener.ca_file.is_none(), "tls_auto replaces ca_file");
                                if listener.server_name.is_some() {
                                    validate_server_name(listener.server_name.as_deref())?;
                                }
                            } else {
                                validate_server_name(listener.server_name.as_deref())?;
                            }
                        } else {
                            ensure!(
                                listener.ca_file.is_none() && listener.server_name.is_none(),
                                "ca_file and server_name require a TLS transport"
                            );
                        }
                    } else if listener.transport.uses_tls() {
                        ensure!(
                            listener.tls_auto
                                || listener.cert_file.is_some() && listener.key_file.is_some(),
                            "TLS listener requires tls_auto, or cert_file and key_file"
                        );
                        ensure!(
                            !listener.tls_auto
                                || listener.cert_file.is_none() && listener.key_file.is_none(),
                            "tls_auto replaces cert_file and key_file"
                        );
                    } else {
                        ensure!(
                            listener.cert_file.is_none() && listener.key_file.is_none(),
                            "cert_file and key_file require a TLS transport"
                        );
                    }
                    if !self.server_dials {
                        ensure!(
                            listener.ca_file.is_none() && listener.server_name.is_none(),
                            "ca_file/server_name require server_dials"
                        );
                        let addr = listener.addr.parse::<SocketAddr>()?;
                        let listener_binds =
                            if matches!(listener.transport, Transport::Kcp | Transport::FecUdp) {
                                &mut udp_binds
                            } else {
                                &mut tcp_binds
                            };
                        let binds_socket=!matches!(listener.transport,Transport::FecRaw|Transport::FecRawGaming|Transport::Mirage|Transport::Tun);
                        ensure!(
                            !binds_socket || addr.port() == 0 || listener_binds.insert(addr),
                            "duplicate listener bind address"
                        );
                        if listener.transport == Transport::FecUdp
                            && listener.fec.knock
                            && addr.port() != 0
                        {
                            ensure!(
                                udp_binds.insert(crate::fec_carrier::knock_address(addr)),
                                "the fec-udp knock port of {addr} (shown in the tunnel's box) is used by another bind address"
                            );
                        }
                    }
                    for map in &listener.maps {
                        bind_address(&map.bind).context("invalid mapping bind address")?;
                        endpoint(&map.target).context("invalid mapping target")?;
                        ensure!(
                            !map.target
                                .rsplit_once(':')
                                .is_some_and(|(host, _)| reserved_host(host)),
                            "mapping targets under .invalid are reserved for EZTunnel itself"
                        );
                        if let Some(version) = map.proxy_protocol {
                            ensure!(
                                map.kind == MapKind::Tcp,
                                "proxy_protocol is for TCP maps only"
                            );
                            ensure!(
                                matches!(version, 1 | 2),
                                "proxy_protocol must be 1 (text) or 2 (binary)"
                            );
                        }
                        let addr = map.bind.parse::<SocketAddr>()?;
                        let binds = match map.kind {
                            MapKind::Tcp => &mut tcp_binds,
                            MapKind::Udp => &mut udp_binds,
                        };
                        ensure!(
                            addr.port() == 0 || binds.insert(addr),
                            "duplicate mapping bind address"
                        );
                    }
                }
            }
            Mode::Client => {
                ensure!(!self.paths.is_empty(), "client requires at least one path");
                ensure!(
                    self.listeners.is_empty()
                        && self.socks5.is_none()
                        && self.peer_public_keys.is_empty(),
                    "listeners, socks5 and peer_public_keys are server-only settings"
                );
                let mut total = 0usize;
                for path in &self.paths {
                    endpoint(&path.addr).context("invalid path address")?;
                    if self.server_dials {
                        bind_address(&path.addr)?;
                    }
                    validate_transport_address(path.transport, &path.addr)?;
                    validate_carrier_options(
                        path.transport,
                        &path.fec,
                        path.raw.as_ref(),
                        self.tun.is_some(),
                    )?;
                    if path.raw.is_some() {
                        ensure!(
                            path.connection_pool == 1,
                            "raw carriers require connection_pool 1 per configured peer"
                        );
                    }
                    validate_http_path(&path.http_path)?;
                    path.xhttp.validate()?;
                    path.kcp.validate()?;
                    path.parallax.validate()?;
                    ensure!(
                        path.transport != Transport::Parallax || path.parallax_key.is_some(),
                        "Parallax requires tunnel_key"
                    );
                    path.tls_fragment.validate()?;
                    validate_tcp_congestion_override(path.tcp_congestion.as_deref())?;
                    validate_tls_auto(
                        path.tls_auto,
                        path.transport,
                        self.tunnel_key.is_some() || self.tunnel_key_file.is_some(),
                    )?;
                    validate_local_address(
                        path.local_address.as_deref(),
                        !self.server_dials,
                        path.transport,
                    )?;
                    validate_tls_profile(path.tls_profile, !self.server_dials, path.transport)?;
                    if self.server_dials {
                        ensure!(
                            server_can_dial(path.transport),
                            "server_dials does not work with the raw carriers (fec-raw, fec-raw-gaming, tun)"
                        );
                        ensure!(
                            path.ca_file.is_none() && path.server_name.is_none(),
                            "a listening client uses cert_file/key_file (or tls_auto) for TLS"
                        );
                        ensure!(
                            path.connection_pool == 1,
                            "with server_dials the client listens; the server's connection_pool sets the number of connections, so keep the client's at 1"
                        );
                        if path.transport.uses_tls() {
                            ensure!(
                                path.tls_auto
                                    || path.cert_file.is_some() && path.key_file.is_some(),
                                "a listening TLS client requires tls_auto, or cert_file and key_file"
                            );
                            ensure!(
                                !path.tls_auto
                                    || path.cert_file.is_none() && path.key_file.is_none(),
                                "tls_auto replaces cert_file and key_file"
                            );
                        } else {
                            ensure!(
                                path.cert_file.is_none() && path.key_file.is_none(),
                                "cert_file and key_file require a TLS transport"
                            );
                        }
                    } else if path.transport.uses_tls() {
                        if path.tls_auto {
                            ensure!(path.ca_file.is_none(), "tls_auto replaces ca_file");
                            if path.server_name.is_some() {
                                validate_server_name(path.server_name.as_deref())?;
                            }
                        } else {
                            validate_server_name(path.server_name.as_deref())?;
                        }
                    } else {
                        ensure!(
                            path.ca_file.is_none() && path.server_name.is_none(),
                            "ca_file and server_name require a TLS transport"
                        );
                    }
                    if !self.server_dials {
                        ensure!(
                            path.cert_file.is_none() && path.key_file.is_none(),
                            "cert_file/key_file require server_dials"
                        );
                    }
                    decode_key(&path.server_public_key).context("invalid server_public_key")?;
                    ensure!(
                        (1..=1024).contains(&path.connection_pool),
                        "connection_pool must be 1..1024"
                    );
                    ensure!(
                        (1..=30).contains(&path.retry_interval)
                            && path.retry_interval <= self.timeouts.retry_max_sec,
                        "retry_interval must be 1..30 seconds and not above timeouts.retry_max_sec"
                    );
                    ensure!(
                        (1..=300).contains(&path.dial_timeout),
                        "dial_timeout must be 1..300 seconds"
                    );
                    total = total
                        .checked_add(path.connection_pool)
                        .context("connection pool total overflow")?;
                }
                ensure!(
                    total <= self.max_connections,
                    "total connection_pool exceeds max_connections"
                );
            }
        }
        Ok(())
    }

    /// Builds the local forwarding overlay without re-entering TUN setup.
    pub(crate) fn tun_forwarding_config(&self) -> Result<Option<Self>> {
        let Some(tun) = &self.tun else {
            return Ok(None);
        };
        let Some(port) = tun.forwarding_port else {
            return Ok(None);
        };
        let mut inner = self.clone();
        inner.tun = None;
        inner.server_dials = false;
        match inner.mode {
            Mode::Server => {
                let listener = inner
                    .listeners
                    .first_mut()
                    .context("TUN forwarding listener missing")?;
                listener.addr = SocketAddr::new(tun.address.parse()?, port).to_string();
                listener.transport = Transport::Tcp;
                listener.raw = None;
                listener.fec = Default::default();
                listener.xhttp = Default::default();
                listener.http_path = default_http_path();
                listener.cert_file = None;
                listener.key_file = None;
                listener.ca_file = None;
                listener.server_name = None;
                listener.tls_auto = false;
                listener.auto_tls = None;
                listener.tls_fragment = Default::default();
                listener.tls_profile = Default::default();
                listener.local_address = None;
            }
            Mode::Client => {
                let path = inner
                    .paths
                    .first_mut()
                    .context("TUN forwarding path missing")?;
                path.addr = SocketAddr::new(tun.peer_address.parse()?, port).to_string();
                path.transport = Transport::Tcp;
                path.raw = None;
                path.fec = Default::default();
                path.xhttp = Default::default();
                path.http_path = default_http_path();
                path.cert_file = None;
                path.key_file = None;
                path.ca_file = None;
                path.server_name = None;
                path.tls_auto = false;
                path.auto_tls = None;
                path.tls_fragment = Default::default();
                path.tls_profile = Default::default();
                path.local_address = None;
            }
        }
        inner.validate()?;
        Ok(Some(inner))
    }
}

/// A fresh random access token (64 hex characters) for `xhttp.access_token`.
pub fn generate_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("operating-system random generator failed"))?;
    Ok(hex::encode(bytes))
}

pub fn generate_keypair(directory: &Path) -> Result<(PathBuf, String)> {
    fs::create_dir_all(directory).context("create key directory")?;
    let private_path = directory.join("private.key");
    let public_path = directory.join("public.key");
    if private_path.exists() || public_path.exists() {
        bail!("key files already exist; choose a new directory");
    }
    let params = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?;
    let pair = snow::Builder::new(params)
        .generate_keypair()
        .context("generate Noise keypair")?;
    let public = hex::encode(&pair.public);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut private_file = options
        .open(&private_path)
        .context("create private key without overwriting")?;
    writeln!(private_file, "{}", hex::encode(&pair.private)).context("write private key")?;
    private_file.sync_all()?;
    let mut public_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&public_path)
        .context("create public key without overwriting")?;
    writeln!(public_file, "{public}")?;
    public_file.sync_all()?;
    Ok((private_path, public))
}

pub fn generate_certificate(directory: &Path, names: Vec<String>) -> Result<(PathBuf, PathBuf)> {
    ensure!(
        !names.is_empty(),
        "at least one certificate name is required"
    );
    let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(names)
        .context("generate self-signed TLS certificate")?;
    fs::create_dir_all(directory).context("create certificate directory")?;
    let cert_path = directory.join("cert.pem");
    let key_path = directory.join("key.pem");
    ensure!(
        !cert_path.exists() && !key_path.exists(),
        "certificate or key already exists; choose a new directory"
    );
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut key_file = options
        .open(&key_path)
        .context("create TLS private key without overwriting")?;
    key_file.write_all(key_pair.serialize_pem().as_bytes())?;
    key_file.sync_all()?;
    let mut cert_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&cert_path)
        .context("create certificate without overwriting")?;
    cert_file.write_all(cert.pem().as_bytes())?;
    cert_file.sync_all()?;
    Ok((cert_path, key_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_level_two_and_invalid_minimum_fail_closed() {
        for field in ["crypto_level", "crypto_min"] {
            let mut value = client_with(serde_json::json!({}));
            value[field] = 2.into();
            let config: Config = serde_json::from_value(value).unwrap();
            assert!(config.validate().is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_tunnel_key_file_matches_inline_keys_and_rejects_symlinks_or_weak_modes() -> Result<()>
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir()?;
        let key = TunnelKey::generate()?;
        let secret = dir.path().join("tunnel.key");
        fs::write(&secret, key.display())?;
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))?;
        let make = |path: &Path| -> Result<Config> {
            let mut config: Config = serde_json::from_value(serde_json::json!({
                "mode":"server", "tunnel_key_file":path,
                "listeners":[{"addr":"127.0.0.1:7000","transport":"tcp"}]
            }))?;
            config.prepare()?;
            config.validate()?;
            Ok(config)
        };
        let config = make(&secret)?;
        assert_eq!(*config.private_key()?, *key.private_key(Mode::Server));
        assert!(config.tunnel_key.is_none());
        for suffix in ["\n","\r\n","  \n"]{fs::write(&secret,format!("{}{suffix}",key.display()))?;assert_eq!(*make(&secret)?.private_key()?,*key.private_key(Mode::Server));}
        fs::write(&secret,key.display())?;
        let mut advanced:Config=serde_json::from_value(serde_json::json!({"mode":"server","tunnel_key_file":secret,
            "listeners":[{"addr":"127.0.0.1:7000","transport":"fec-raw","raw":{"local_ip":"192.0.2.1","peer_ip":"192.0.2.2","profile":"tcp","hopping":{"enabled":true}},
                "fec":{"tcp_fallback":{"address":"127.0.0.1:7010"}}}],
            "gaming":{"control_address":"127.0.0.1:7011","udp_bind":"127.0.0.1:7012"}}))?;
        advanced.prepare()?;advanced.validate()?;
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644))?;
        assert!(make(&secret).is_err());
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))?;
        let alias = dir.path().join("alias.key");
        symlink(&secret, &alias)?;
        assert!(make(&alias).is_err());
        Ok(())
    }

    fn client_with(extra: serde_json::Value) -> serde_json::Value {
        let mut value = serde_json::json!({
            "mode":"client", "private_key_file":"private.key",
            "paths":[{"addr":"127.0.0.1:7000", "server_public_key":"11".repeat(32)}]
        });
        for (key, v) in extra.as_object().unwrap() {
            value[key] = v.clone();
        }
        value
    }

    #[cfg(unix)]
    #[test]
    fn a_secret_file_everyone_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("key.pem");
        std::fs::write(&file, "x").unwrap();
        for (mode, ok) in [(0o600, true), (0o640, true), (0o644, false), (0o604, false)] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                Config::ensure_not_world_readable(&file, "the TLS private key").is_ok(),
                ok,
                "mode {mode:o}"
            );
        }
    }

    #[test]
    fn the_idle_timeout_and_the_per_address_stream_limit_have_defaults_and_ranges() {
        assert_eq!(Timeouts::default().tcp_idle_sec, 3600);
        assert_eq!(streams_per_ip(), 512);
        let never = Timeouts {
            tcp_idle_sec: 0,
            ..Timeouts::default()
        };
        assert!(never.validate().is_ok(), "0 means never");
        let too_long = Timeouts {
            tcp_idle_sec: 86_401,
            ..Timeouts::default()
        };
        assert!(too_long.validate().is_err());
    }

    #[test]
    fn the_goodbye_wait_has_a_default_and_a_range() {
        assert_eq!(Timeouts::default().goodbye_wait_ms, 500);
        for (value, ok) in [(0, true), (5000, true), (5001, false)] {
            let timeouts = Timeouts {
                goodbye_wait_ms: value,
                ..Timeouts::default()
            };
            assert_eq!(timeouts.validate().is_ok(), ok, "{value}");
        }
    }

    #[test]
    fn tunable_defaults_keep_the_previous_behaviour() {
        let timeouts = Timeouts::default();
        assert_eq!(
            (
                timeouts.handshake_sec,
                timeouts.connect_sec,
                timeouts.open_sec,
                timeouts.udp_idle_sec,
                timeouts.retry_max_sec,
                timeouts.server_dial_sec
            ),
            (10, 10, 15, 120, 30, 30)
        );
        let queues = Queues::default();
        assert_eq!((queues.stream_frames, queues.session_frames), (32, 128));
        let kcp = KcpOptions::default();
        assert_eq!(
            (
                kcp.mtu,
                kcp.send_window,
                kcp.recv_window,
                kcp.session_expire_sec
            ),
            // Windows raised from 128 in 0.5.2: 128 packets capped one connection at about
            // 2 MB/s on a 90 ms link.
            (1400, 1024, 1024, 60)
        );
        assert!(kcp.nodelay && !kcp.congestion_control);
        assert_eq!((kcp.interval_ms, kcp.resend), (10, 2));
        assert_eq!(XhttpOptions::default().socket_buf_bytes, None);
        let xhttp = XhttpOptions::default();
        assert_eq!(
            (xhttp.max_requests, xhttp.max_sessions, xhttp.edge_retry_sec),
            (256, 64, 60)
        );
        let config: Config = serde_json::from_value(client_with(serde_json::json!({}))).unwrap();
        config.validate().unwrap();
        assert_eq!(config.max_open_files, None);
    }

    #[test]
    fn user_chosen_tunables_are_accepted_and_bad_ones_rejected() {
        let good = client_with(serde_json::json!({
            "timeouts": {"handshake_sec": 3, "connect_sec": 20, "open_sec": 30,
                         "udp_idle_sec": 600, "retry_max_sec": 10, "server_dial_sec": 60},
            "queues": {"stream_frames": 64, "session_frames": 512},
            "max_open_files": 65536
        }));
        let config: Config = serde_json::from_value(good).unwrap();
        config.validate().unwrap();
        assert_eq!(config.timeouts.handshake_sec, 3);
        assert_eq!(config.queues.session_frames, 512);
        for bad in [
            serde_json::json!({"timeouts": {"handshake_sec": 0}}),
            serde_json::json!({"timeouts": {"connect_sec": 301}}),
            serde_json::json!({"timeouts": {"udp_idle_sec": 1}}),
            serde_json::json!({"timeouts": {"retry_max_sec": 0}}),
            serde_json::json!({"queues": {"stream_frames": 10}}),
            serde_json::json!({"queues": {"session_frames": 1}}),
            serde_json::json!({"max_open_files": 10}),
            serde_json::json!({"timeouts": {"retry_max_sec": 1}, "paths": [{"addr":"127.0.0.1:7000",
                "server_public_key":"11".repeat(32), "retry_interval": 5}]}),
        ] {
            let parsed = serde_json::from_value::<Config>(client_with(bad.clone()));
            assert!(
                parsed.map(|c| c.validate()).map_or(true, |r| r.is_err()),
                "{bad} should be rejected"
            );
        }
        let unknown = client_with(serde_json::json!({"timeouts": {"handshake": 3}}));
        assert!(serde_json::from_value::<Config>(unknown).is_err());
    }

    #[test]
    fn kcp_and_xhttp_tunables_are_validated() {
        let mut value = client_with(serde_json::json!({}));
        value["paths"][0]["kcp"] = serde_json::json!({"mtu": 1200, "send_window": 256, "recv_window": 256, "session_expire_sec": 30});
        value["paths"][0]["xhttp"] =
            serde_json::json!({"max_requests": 1000, "max_sessions": 200, "edge_retry_sec": 15});
        serde_json::from_value::<Config>(value.clone())
            .unwrap()
            .validate()
            .unwrap();
        for (path, field, bad) in [
            ("kcp", "mtu", 100),
            ("kcp", "send_window", 4),
            ("kcp", "session_expire_sec", 1),
            ("xhttp", "max_requests", 0),
            ("xhttp", "max_sessions", 0),
            ("xhttp", "edge_retry_sec", 0),
        ] {
            let mut broken = value.clone();
            broken["paths"][0][path][field] = bad.into();
            assert!(
                serde_json::from_value::<Config>(broken)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{path}.{field}={bad} should be rejected"
            );
        }
    }

    #[test]
    fn generated_tokens_are_valid_and_different() {
        let first = generate_token().unwrap();
        let second = generate_token().unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
        let mut value = client_with(serde_json::json!({}));
        value["paths"][0]["xhttp"] = serde_json::json!({"access_token": first});
        serde_json::from_value::<Config>(value.clone())
            .unwrap()
            .validate()
            .unwrap();
        for bad in [
            "short",
            "has space in it 1234567890",
            &"x".repeat(129),
            "quote\"inside1234567890",
        ] {
            value["paths"][0]["xhttp"]["access_token"] = bad.into();
            assert!(
                serde_json::from_value::<Config>(value.clone())
                    .unwrap()
                    .validate()
                    .is_err(),
                "token {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        let value = serde_json::json!({"mode":"client","private_key_file":"private.key","unknown_option":"x"});
        assert!(serde_json::from_value::<Config>(value).is_err());
    }

    #[test]
    fn generated_keys_load_relative_to_config_without_overwrite() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let key_dir = directory.path().join("keys");
        let (private_path, public) = generate_keypair(&key_dir)?;
        let original = fs::read(&private_path)?;
        assert!(generate_keypair(&key_dir).is_err());
        assert_eq!(fs::read(&private_path)?, original);
        let config_path = directory.path().join("config.json");
        fs::write(
            &config_path,
            serde_json::to_vec(&serde_json::json!({
                "mode":"client", "private_key_file":"keys/private.key",
                "paths":[{"addr":"localhost:7000","server_public_key":public}]
            }))?,
        )?;
        let config = Config::load(&config_path)?;
        assert_eq!(config.private_key_file, private_path);
        assert_eq!(
            *config.private_key()?,
            decode_key(std::str::from_utf8(&original)?.trim())?
        );
        Ok(())
    }

    #[test]
    fn validates_endpoint_syntax_without_dns() {
        assert!(endpoint(&format!("{}:80", "a".repeat(1024))).is_err());
        for valid in ["localhost:80", "127.0.0.1:443", "[::1]:9000"] {
            assert!(endpoint(valid).is_ok());
        }
        for invalid in [
            "http://example.com:80",
            "::1:80",
            "host:0",
            "host:65536",
            "host",
            "host name:80",
        ] {
            assert!(endpoint(invalid).is_err());
        }
    }

    #[test]
    fn validates_transport_specific_settings() -> Result<()> {
        let mut value = serde_json::json!({
            "mode":"client", "private_key_file":"private.key",
            "paths":[{"addr":"127.0.0.1:7000", "transport":"wss", "server_public_key":"11".repeat(32)}]
        });
        assert!(
            serde_json::from_value::<Config>(value.clone())?
                .validate()
                .is_err()
        );
        value["paths"][0]["server_name"] = "localhost".into();
        serde_json::from_value::<Config>(value.clone())?.validate()?;
        value["paths"][0]["http_path"] = "/tunnel\r\ninjected: true".into();
        assert!(
            serde_json::from_value::<Config>(value.clone())?
                .validate()
                .is_err()
        );
        value["paths"][0]["http_path"] = "/tunnel".into();
        value["paths"][0]["transport"] = "fec-raw".into();
        assert!(serde_json::from_value::<Config>(value)?.validate().is_err());
        assert!(validate_transport_address(Transport::Tcp6, "127.0.0.1:7000").is_err());
        validate_transport_address(Transport::Tcp6, "[::1]:7000")?;
        Ok(())
    }

    #[test]
    fn certificate_generation_preserves_existing_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (cert, key) = generate_certificate(directory.path(), vec!["localhost".into()])?;
        let original_key = fs::read(&key)?;
        assert!(fs::read_to_string(cert)?.contains("BEGIN CERTIFICATE"));
        assert!(generate_certificate(directory.path(), vec!["localhost".into()]).is_err());
        assert_eq!(fs::read(&key)?, original_key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(key)?.permissions().mode() & 0o777, 0o600);
        }
        Ok(())
    }

    #[test]
    fn tun_validation_rejects_incompatible_routes_and_settings() -> Result<()> {
        let mut value = serde_json::json!({
            "mode":"client", "private_key_file":"private.key",
            "paths":[{"addr":"127.0.0.1:7000", "server_public_key":"11".repeat(32)}],
            "tun":{"name":"ez0", "address":"10.25.0.2", "peer_address":"10.25.0.1"}
        });
        serde_json::from_value::<Config>(value.clone())?.validate()?;
        for feature in ["parity", "mtu_probe"] {
            value["tun"][feature] = true.into();
            assert!(
                serde_json::from_value::<Config>(value.clone())?
                    .validate()
                    .is_err()
            );
            value["tun"][feature] = false.into();
        }
        value["tun"]["peer_address"] = "::1".into();
        assert!(
            serde_json::from_value::<Config>(value.clone())?
                .validate()
                .is_err()
        );
        value["tun"]["peer_address"] = "10.25.0.1".into();
        value["allowed_targets"] = serde_json::json!(["*"]);
        assert!(
            serde_json::from_value::<Config>(value.clone())?
                .validate()
                .is_err()
        );
        value["allowed_targets"] = serde_json::json!([]);
        value["paths"][0]["connection_pool"] = 2.into();
        assert!(serde_json::from_value::<Config>(value)?.validate().is_err());
        Ok(())
    }

    #[test]
    fn a_path_or_listener_may_override_tcp_congestion() -> Result<()> {
        let mut value = client_with(serde_json::json!({}));
        value["paths"][0]["tcp_congestion"] = "cubic".into();
        assert!(validates(value.clone()).is_ok());
        value["paths"][0]["tcp_congestion"] = "system".into();
        assert!(validates(value.clone()).is_ok());
        value["paths"][0]["tcp_congestion"] = "Not Valid!".into();
        assert!(
            validates(value).is_err(),
            "same character rule as the top-level setting"
        );

        let mut value = server_with(serde_json::json!([
            {"addr": "127.0.0.1:7000"}
        ]));
        value["listeners"][0]["tcp_congestion"] = "bbr".into();
        assert!(validates(value.clone()).is_ok());
        value["listeners"][0]["tcp_congestion"] = "".into();
        assert!(validates(value).is_err(), "empty is not a valid override");
        Ok(())
    }

    /// A server with the given listeners (a JSON array) and nothing else special.
    fn server_with(listeners: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "mode":"server", "private_key_file":"private.key", "peer_public_keys":["22".repeat(32)],
            "listeners": listeners
        })
    }

    fn validates(value: serde_json::Value) -> Result<()> {
        serde_json::from_value::<Config>(value)?.validate()
    }

    #[test]
    fn a_wildcard_bind_conflicts_with_an_address_of_its_family_on_the_same_port() {
        let two = |a: &str, b: &str| {
            server_with(serde_json::json!([
                {"addr": a, "transport": "tcp"}, {"addr": b, "transport": "tcp"}
            ]))
        };
        assert!(validates(two("0.0.0.0:4000", "127.0.0.1:4000")).is_err());
        assert!(validates(two("127.0.0.1:4000", "0.0.0.0:4000")).is_err());
        assert!(validates(two("[::]:4000", "[::1]:4000")).is_err());
        assert!(validates(two("127.0.0.1:4000", "127.0.0.1:4000")).is_err());
        // Different ports, different specific addresses, or another family are no conflict.
        assert!(validates(two("0.0.0.0:4000", "127.0.0.1:4001")).is_ok());
        assert!(validates(two("127.0.0.1:4000", "127.0.0.2:4000")).is_ok());
        assert!(validates(two("0.0.0.0:4000", "[::1]:4000")).is_ok());
        // The IPv6 wildcard is dual-stack by default on Linux (no IPV6_V6ONLY), so it also
        // claims the port for IPv4 - it conflicts with any family on the same port.
        assert!(validates(two("[::]:4000", "0.0.0.0:4000")).is_err());
        assert!(validates(two("[::]:4000", "127.0.0.1:4000")).is_err());
        // An IPv4-mapped IPv6 literal is the same address on the wire as the plain IPv4 one.
        assert!(validates(two("[::ffff:127.0.0.1]:4000", "127.0.0.1:4000")).is_err());
        // Port 0 means "any free port" and never conflicts.
        assert!(validates(two("0.0.0.0:0", "0.0.0.0:0")).is_ok());
        // TCP and UDP are separate: a UDP map may use a TCP listener's port.
        let mixed = server_with(serde_json::json!([{
            "addr": "0.0.0.0:4000", "transport": "tcp",
            "maps": [{"type": "udp", "bind": "0.0.0.0:4000", "target": "127.0.0.1:9"}]
        }]));
        assert!(validates(mixed).is_ok());
        // A map bind conflicts with a listener of the same protocol.
        let map = server_with(serde_json::json!([{
            "addr": "0.0.0.0:4000", "transport": "tcp",
            "maps": [{"type": "tcp", "bind": "127.0.0.1:4000", "target": "127.0.0.1:9"}]
        }]));
        assert!(validates(map).is_err());
    }

    #[test]
    fn the_fec_knock_port_is_part_of_the_bind_check() {
        let with_map = |knock: bool, bind: &str| {
            server_with(serde_json::json!([{
                "addr": "127.0.0.1:20000", "transport": "fec-udp", "fec": {"knock": knock},
                "maps": [{"type": "udp", "bind": bind, "target": "127.0.0.1:9"}]
            }]))
        };
        // The knock port of 20000 is 30000.
        assert!(validates(with_map(true, "127.0.0.1:30000")).is_err());
        assert!(validates(with_map(true, "0.0.0.0:30000")).is_err());
        assert!(validates(with_map(false, "127.0.0.1:30000")).is_ok());
        assert!(validates(with_map(true, "127.0.0.1:30001")).is_ok());
        // Above 55535 the knock port is 1000 lower.
        let high = server_with(serde_json::json!([{
            "addr": "127.0.0.1:60000", "transport": "fec-udp",
            "maps": [{"type": "udp", "bind": "127.0.0.1:59000", "target": "127.0.0.1:9"}]
        }]));
        assert!(validates(high).is_err());
    }

    #[test]
    fn saved_tunnels_need_fixed_ports_but_tests_may_use_port_zero() -> Result<()> {
        let zero = server_with(serde_json::json!([{"addr": "127.0.0.1:0", "transport": "tcp"}]));
        let config: Config = serde_json::from_value(zero)?;
        config.validate()?;
        assert!(config.ensure_fixed_ports().is_err());
        let map = server_with(serde_json::json!([{
            "addr": "127.0.0.1:4000", "transport": "tcp",
            "maps": [{"type": "tcp", "bind": "127.0.0.1:0", "target": "127.0.0.1:9"}]
        }]));
        assert!(
            serde_json::from_value::<Config>(map)?
                .ensure_fixed_ports()
                .is_err()
        );
        let fine = server_with(serde_json::json!([{"addr": "127.0.0.1:4000", "transport": "tcp"}]));
        serde_json::from_value::<Config>(fine)?.ensure_fixed_ports()?;
        // A dialing server's addresses are the peer's, not its own binds.
        let mut dialing =
            server_with(serde_json::json!([{"addr": "127.0.0.1:0", "transport": "tcp"}]));
        dialing["server_dials"] = true.into();
        serde_json::from_value::<Config>(dialing)?.ensure_fixed_ports()?;
        // server_dials inverts the client: its own paths are what IT binds and waits on, so
        // port 0 there is just as unreachable for the dialing server as a listener's would be.
        let mut listening_client = client_with(serde_json::json!({
            "paths": [{"addr": "127.0.0.1:0", "server_public_key": "11".repeat(32)}]
        }));
        listening_client["server_dials"] = true.into();
        assert!(
            serde_json::from_value::<Config>(listening_client)?
                .ensure_fixed_ports()
                .is_err()
        );
        // The ordinary case (the client dials out) still only cares about its own binds, which
        // it has none of, so a path's port 0 (the peer's address) is fine.
        let dialing_client = client_with(serde_json::json!({}));
        serde_json::from_value::<Config>(dialing_client)?.ensure_fixed_ports()?;
        Ok(())
    }

    #[test]
    fn settings_that_do_nothing_on_the_carrier_give_warnings_not_errors() -> Result<()> {
        let config: Config = serde_json::from_value(server_with(serde_json::json!([{
            "addr": "0.0.0.0:4000", "transport": "tcp",
            "tls_fragment": {"enabled": true}, "xhttp": {"up_concurrency": 2},
            "fec": {"mtu": 1300}, "kcp": {"mtu": 1300}
        }])))?;
        config.validate()?;
        let warnings = config.warnings().join("\n");
        for what in [
            "tls_fragment",
            "xhttp settings",
            "fec settings",
            "kcp settings",
        ] {
            assert!(warnings.contains(what), "{what}: {warnings}");
        }
        // The same settings on the carriers they belong to are fine.
        let right: Config = serde_json::from_value(server_with(serde_json::json!([
            {"addr": "0.0.0.0:4000", "transport": "kcp", "kcp": {"mtu": 1300}},
            {"addr": "0.0.0.0:4001", "transport": "fec-udp", "fec": {"mtu": 1300}},
        ])))?;
        assert!(right.warnings().is_empty(), "{:?}", right.warnings());
        // A queue below the window warns only when set on purpose.
        let queue: Config = serde_json::from_value(serde_json::json!({
            "mode":"client", "private_key_file":"private.key", "stream_window": 64,
            "queues": {"stream_frames": 40},
            "paths":[{"addr":"127.0.0.1:7000", "server_public_key":"11".repeat(32)}]
        }))?;
        assert!(
            queue
                .warnings()
                .join("")
                .contains("queues.stream_frames (40)")
        );
        let default: Config = serde_json::from_value(client_with(serde_json::json!({})))?;
        assert!(default.warnings().is_empty());
        Ok(())
    }

    /// What the program prepares by itself (the access token of a tunnel key, the browser agent of
    /// wire v2) must not count as settings the user made: every tunnel is started prepared.
    #[test]
    fn a_prepared_tunnel_key_configuration_has_no_warnings() -> Result<()> {
        let key = crate::tunnel_key::TunnelKey::generate()?.display();
        for transport in ["tcp", "wss", "kcp", "fec-udp", "xhttp"] {
            let mut server: Config = serde_json::from_value(serde_json::json!({
                "mode": "server", "tunnel_key": key, "wire_version": 2,
                "listeners": [{"addr": "0.0.0.0:4000", "transport": transport, "tls_auto": transport == "wss"}]
            }))?;
            server.prepare()?;
            server.validate()?;
            assert!(
                server.warnings().is_empty(),
                "{transport}: {:?}",
                server.warnings()
            );
            let mut client: Config = serde_json::from_value(serde_json::json!({
                "mode": "client", "tunnel_key": key, "wire_version": 2, "allowed_targets": ["127.0.0.1:*"],
                "paths": [{"addr": "192.0.2.1:4000", "transport": transport, "tls_auto": transport == "wss"}]
            }))?;
            client.prepare()?;
            client.validate()?;
            assert!(
                client.warnings().is_empty(),
                "{transport}: {:?}",
                client.warnings()
            );
        }
        // An xhttp setting the user made on another carrier is still reported.
        let mut odd: Config = serde_json::from_value(serde_json::json!({
            "mode": "server", "tunnel_key": key,
            "listeners": [{"addr": "0.0.0.0:4000", "transport": "tcp", "xhttp": {"up_concurrency": 2}}]
        }))?;
        odd.prepare()?;
        assert!(odd.warnings().join("").contains("xhttp settings"));
        Ok(())
    }

    #[test]
    fn the_example_configurations_have_no_warnings() -> Result<()> {
        let mut seen = 0;
        for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/examples"))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let config: Config = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
                assert!(
                    config.warnings().is_empty(),
                    "{}: {:?}",
                    path.display(),
                    config.warnings()
                );
                seen += 1;
            }
        }
        assert!(seen >= 10);
        Ok(())
    }

    #[test]
    fn tun_forwarding_uses_inner_ips_and_preserves_peer_authorization() -> Result<()> {
        for (local, peer) in [("10.25.0.1", "10.25.0.2"), ("fd42:25::1", "fd42:25::2")] {
            let server: Config = serde_json::from_value(serde_json::json!({
                "mode":"server", "private_key_file":"private.key", "peer_public_keys":["22".repeat(32)],
                "heartbeat_sec":2,"dead_timeout_sec":8,"socks5":"127.0.0.1:1080",
                "tun":{"name":"ez0","address":local,"peer_address":peer,"forwarding_port":47475},
                "listeners":[{"addr":"192.0.2.1:443","transport":"tun","raw":{"peer_ip":"192.0.2.2"},
                    "maps":[{"type":"tcp","bind":"127.0.0.1:2222","target":"127.0.0.1:22"}]}]
            }))?;
            server.validate()?;
            let inner = server.tun_forwarding_config()?.unwrap();
            assert!(inner.tun.is_none() && !inner.server_dials);
            assert_eq!(
                inner.listeners[0].addr,
                SocketAddr::new(local.parse()?, 47475).to_string()
            );
            assert_eq!(inner.listeners[0].transport, Transport::Tcp);
            assert!(inner.listeners[0].raw.is_none());
            assert_eq!(
                inner.listeners[0].maps[0].target,
                server.listeners[0].maps[0].target
            );
            assert_eq!(inner.socks5, server.socks5);
            assert_eq!(inner.peer_public_keys, server.peer_public_keys);
            assert_eq!(inner.private_key_file, server.private_key_file);
            assert_eq!((inner.heartbeat_sec, inner.dead_timeout_sec), (2, 8));
            let client: Config = serde_json::from_value(serde_json::json!({
                "mode":"client", "private_key_file":"private.key", "allowed_targets":["127.0.0.1:22"],
                "tun":{"name":"ez0","address":peer,"peer_address":local,"forwarding_port":47475},
                "paths":[{"addr":"192.0.2.1:443","transport":"tun","raw":{"peer_ip":"192.0.2.1"},
                    "server_public_key":"11".repeat(32),"retry_interval":2,"dial_timeout":5}]
            }))?;
            client.validate()?;
            let inner = client.tun_forwarding_config()?.unwrap();
            assert_eq!(
                inner.paths[0].addr,
                SocketAddr::new(local.parse()?, 47475).to_string()
            );
            assert_eq!(inner.paths[0].transport, Transport::Tcp);
            assert!(inner.paths[0].raw.is_none());
            // A value that happened to apply to the outer (raw) path is not valid for this
            // unrelated inner Tcp link and must not leak through unchanged.
            let mut with_local_address = client.clone();
            with_local_address.paths[0].local_address = Some("127.0.0.1".into());
            let inner = with_local_address.tun_forwarding_config()?.unwrap();
            assert!(inner.paths[0].local_address.is_none());
            assert_eq!(
                inner.paths[0].server_public_key,
                client.paths[0].server_public_key
            );
            assert_eq!(inner.allowed_targets, client.allowed_targets);
            assert_eq!(
                (inner.paths[0].retry_interval, inner.paths[0].dial_timeout),
                (2, 5)
            );
        }
        Ok(())
    }

    #[test]
    fn tun_forwarding_requires_explicit_port_and_rejects_service_collisions() -> Result<()> {
        let mut value = serde_json::json!({
            "mode":"server", "private_key_file":"private.key", "peer_public_keys":["22".repeat(32)],
            "tun":{"name":"ez0","address":"10.25.0.1","peer_address":"10.25.0.2"},
            "listeners":[{"addr":"192.0.2.1:443","transport":"tun","raw":{"peer_ip":"192.0.2.2"}}]
        });
        let packet_only: Config = serde_json::from_value(value.clone())?;
        packet_only.validate()?;
        assert!(packet_only.tun_forwarding_config()?.is_none());
        value["socks5"] = "127.0.0.1:1080".into();
        assert!(
            serde_json::from_value::<Config>(value.clone())?
                .validate()
                .is_err()
        );
        for port in [0, 1023] {
            value["tun"]["forwarding_port"] = port.into();
            assert!(
                serde_json::from_value::<Config>(value.clone())?
                    .validate()
                    .is_err()
            );
        }
        value["tun"]["forwarding_port"] = 47475.into();
        serde_json::from_value::<Config>(value.clone())?.validate()?;
        for bind in ["10.25.0.1:47475", "0.0.0.0:47475"] {
            value["socks5"] = bind.into();
            assert!(
                serde_json::from_value::<Config>(value.clone())?
                    .validate()
                    .is_err()
            );
        }
        value["socks5"] = "127.0.0.1:1080".into();
        value["listeners"][0]["maps"] = serde_json::json!([
            {"type":"tcp","bind":"0.0.0.0:47475","target":"127.0.0.1:22"}
        ]);
        assert!(serde_json::from_value::<Config>(value)?.validate().is_err());
        Ok(())
    }

    #[test]
    fn tun_forwarding_clears_outer_tls_and_http_options() -> Result<()> {
        let config: Config = serde_json::from_value(serde_json::json!({
            "mode":"client","reverse":true,"private_key_file":"private.key",
            "tun":{"name":"ez0","address":"fd42:25::2","peer_address":"fd42:25::1","forwarding_port":47475},
            "paths":[{"addr":"[::1]:443","transport":"xhttps","cert_file":"cert.pem","key_file":"key.pem",
                "http_path":"/outer","xhttp":{"host":"localhost","edge_addrs":["127.0.0.1:443"]},
                "server_public_key":"11".repeat(32)}]
        }))?;
        config.validate()?;
        let inner = config.tun_forwarding_config()?.unwrap();
        inner.validate()?;
        let path = &inner.paths[0];
        assert!(!inner.server_dials && inner.tun.is_none());
        assert!(
            path.cert_file.is_none()
                && path.key_file.is_none()
                && path.ca_file.is_none()
                && path.server_name.is_none()
        );
        assert!(path.xhttp.host.is_none() && path.xhttp.edge_addrs.is_empty());
        assert_eq!(path.http_path, default_http_path());
        assert_eq!(path.transport, Transport::Tcp);
        Ok(())
    }

    #[test]
    fn map_targets_under_invalid_are_reserved() -> Result<()> {
        let with_target = |target: &str| -> Result<()> {
            serde_json::from_value::<Config>(serde_json::json!({
                "mode":"server", "private_key_file":"private.key", "peer_public_keys":["22".repeat(32)],
                "listeners":[{"addr":"0.0.0.0:7000",
                    "maps":[{"type":"tcp","bind":"0.0.0.0:8080","target":target}]}]
            }))?
            .validate()
        };
        with_target("127.0.0.1:8080")?;
        with_target("invalid.example.com:80")?;
        for target in [
            "down.1048576.speedtest.eztunnel.invalid:9",
            "Some.Name.INVALID:443",
            "invalid:80",
        ] {
            assert!(with_target(target).is_err(), "{target} was accepted");
        }
        assert!(reserved_host("x.invalid.") && !reserved_host("invalidx.com"));
        Ok(())
    }

    /// The Chrome-like TLS look and `local_address` belong to the outer carrier. The inner
    /// forwarding link is plain TCP in the other direction, where neither is valid.
    #[cfg(feature = "browser-tls")]
    #[test]
    fn tun_forwarding_drops_the_tls_look_and_the_source_address() -> Result<()> {
        let key = TunnelKey::generate()?.display();
        for (mode, entry) in [
            (
                "client",
                serde_json::json!({"allowed_targets":["127.0.0.1:*"],
                    "paths":[{"addr":"203.0.113.7:443","transport":"wss","tls_auto":true,
                        "tls_profile":"chrome","local_address":"127.0.0.1"}]}),
            ),
            (
                "server",
                serde_json::json!({"server_dials":true,"listeners":[{"addr":"203.0.113.7:443",
                    "transport":"wss","tls_auto":true,"tls_profile":"chrome",
                    "local_address":"127.0.0.1",
                    "maps":[{"type":"tcp","bind":"0.0.0.0:8443","target":"127.0.0.1:443"}]}]}),
            ),
        ] {
            let (local, peer) = if mode == "server" {
                ("10.77.0.1", "10.77.0.2")
            } else {
                ("10.77.0.2", "10.77.0.1")
            };
            let mut value = entry;
            value["mode"] = mode.into();
            value["tunnel_key"] = key.clone().into();
            value["tun"] = serde_json::json!({"name":"ez0","address":local,"peer_address":peer,
                "forwarding_port":47475});
            let mut config: Config = serde_json::from_value(value)?;
            config.prepare()?;
            config.validate()?;
            let inner = config
                .tun_forwarding_config()
                .with_context(|| format!("{mode} inner forwarding config"))?
                .unwrap();
            let (look, bound) = match inner.mode {
                Mode::Server => (
                    inner.listeners[0].tls_profile,
                    inner.listeners[0].local_address.clone(),
                ),
                Mode::Client => (
                    inner.paths[0].tls_profile,
                    // The dialing side may keep binding its source address on plain TCP.
                    None,
                ),
            };
            assert!(look.is_classic(), "{mode}: no TLS look on a plain TCP link");
            assert!(
                bound.is_none(),
                "{mode}: the listening side has no source address"
            );
        }
        Ok(())
    }

    /// The manager writes `tls_auto` for every TLS carrier, including TUN + ports. The inner
    /// forwarding link is plain TCP, so it must drop `tls_auto` or the service never starts.
    #[test]
    fn tun_forwarding_over_a_tls_auto_carrier_is_valid() -> Result<()> {
        let key = TunnelKey::generate()?.display();
        let split = serde_json::json!({"enabled": true});
        for (mode, entry) in [
            (
                "server",
                serde_json::json!({"listeners":[{"addr":"0.0.0.0:443","transport":"wss",
                    "tls_auto":true,"tls_fragment":split,
                    "maps":[{"type":"tcp","bind":"0.0.0.0:8443","target":"127.0.0.1:443"}]}]}),
            ),
            (
                "client",
                serde_json::json!({"allowed_targets":["127.0.0.1:*"],
                    "paths":[{"addr":"203.0.113.7:443","transport":"wss","tls_auto":true,
                        "tls_fragment":split}]}),
            ),
        ] {
            let (local, peer) = if mode == "server" {
                ("10.77.0.1", "10.77.0.2")
            } else {
                ("10.77.0.2", "10.77.0.1")
            };
            let mut value = entry;
            value["mode"] = mode.into();
            value["tunnel_key"] = key.clone().into();
            value["tun"] = serde_json::json!({"name":"ez0","address":local,"peer_address":peer,
                "forwarding_port":47475});
            let mut config: Config = serde_json::from_value(value)?;
            config.prepare()?;
            config.validate()?;
            let inner = config
                .tun_forwarding_config()
                .with_context(|| format!("{mode} inner forwarding config"))?
                .unwrap();
            let (transport, tls_auto, fragment) = match inner.mode {
                Mode::Server => {
                    let l = &inner.listeners[0];
                    (
                        l.transport,
                        l.tls_auto || l.auto_tls.is_some(),
                        l.tls_fragment,
                    )
                }
                Mode::Client => {
                    let p = &inner.paths[0];
                    (
                        p.transport,
                        p.tls_auto || p.auto_tls.is_some(),
                        p.tls_fragment,
                    )
                }
            };
            assert_eq!(transport, Transport::Tcp);
            assert!(!tls_auto, "{mode}: inner link must not use TLS");
            assert!(
                !fragment.enabled,
                "{mode}: nothing to fragment on plain TCP"
            );
        }
        Ok(())
    }
}
    #[test]
    fn raw_metadata_does_not_reserve_a_tcp_socket_but_actual_maps_still_collide()->Result<()> {
        let key=TunnelKey::generate()?.display();
        let mut config:Config=serde_json::from_value(serde_json::json!({"mode":"server","tunnel_key":key,
            "listeners":[{"addr":"0.0.0.0:8443","transport":"fec-raw","raw":{"profile":"udp","local_ip":"192.0.2.1","peer_ip":"192.0.2.2","l4_port":7000},
                "maps":[{"type":"tcp","bind":"0.0.0.0:8443","target":"127.0.0.1:443"}]}]}))?;
        config.prepare()?;config.validate()?;
        let duplicate=config.listeners[0].maps[0].clone();config.listeners[0].maps.push(duplicate);assert!(config.validate().is_err());
        Ok(())
    }
