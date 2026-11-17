//! The transport checker: which transports work between two servers, in which direction, and how
//! well. Every case starts a real temporary tunnel with the configuration the wizard would write
//! (`manager::plan`), so a case passes only if such a tunnel would work. One server starts a
//! check and gets a check code; the other joins with it; the Iran server measures and both show
//! the same progress. Only the two servers are contacted, and everything is removed afterwards.
//!
pub mod case;
pub mod cli;
pub mod code;
pub mod control;
pub mod logbuf;
pub mod measure;
pub mod run;
pub mod service;

pub use run::View;

use crate::config::Transport;
use crate::raw_packet::RawProfile;
use serde::{Deserialize, Serialize};

/// Which server opens the connection between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Iran,
    Foreign,
}

impl Side {
    pub fn label(self) -> &'static str {
        match self {
            Self::Iran => "Iran",
            Self::Foreign => "foreign",
        }
    }

    pub fn other(self) -> Self {
        match self {
            Self::Iran => Self::Foreign,
            Self::Foreign => Self::Iran,
        }
    }
}

/// What the ranking of the results favours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    /// Steady connection first, then speed.
    #[default]
    Stability,
    /// Highest speed first.
    Speed,
    /// Looks like ordinary web traffic first (TLS, HTTP).
    Hiding,
    /// Best on a path that loses packets (error correction first).
    Lossy,
}

impl Priority {
    pub const ALL: [Self; 4] = [Self::Stability, Self::Speed, Self::Hiding, Self::Lossy];

    pub fn label(self) -> &'static str {
        match self {
            Self::Stability => "Stability",
            Self::Speed => "Speed",
            Self::Hiding => "Hiding",
            Self::Lossy => "Lossy path",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Stability => "steady connection first, then speed",
            Self::Speed => "the fastest transport first",
            Self::Hiding => "looks like ordinary web traffic (TLS, HTTP) first",
            Self::Lossy => "error correction first, for a path that loses packets",
        }
    }
}

/// Ready-made sets of measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Quick,
    Standard,
    Thorough,
}

impl Preset {
    pub fn label(self) -> &'static str {
        match self {
            Self::Quick => "Quick",
            Self::Standard => "Standard",
            Self::Thorough => "Thorough",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Quick => "handshake and ping only",
            Self::Standard => "+ speed 5 s each way + 30 s stability hold",
            Self::Thorough => "+ 4 streams, 60 s hold, path MTU, failures repeated",
        }
    }
}

/// What a check is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Every chosen transport with its default settings: which ones work on this route.
    #[default]
    Find,
    /// The chosen transports with every option each one has, each case `rounds` times: which
    /// setting of a working transport is best.
    Tune,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Find => "Find transports",
            Self::Tune => "Tune transports",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Find => "every transport with its default settings: which ones work here",
            Self::Tune => "a few transports with every option they have: which setting is best",
        }
    }
}

/// Rounds of every case a tune check runs, so one noisy run does not decide.
pub const TUNE_ROUNDS: u8 = 2;
/// How many of the best transports of a find check "Tune the best" takes.
pub const TUNE_BEST: usize = 3;

/// Everything chosen before the start. It travels in the check code, so the joining server sees
/// what will run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    /// Find (default settings) or tune (every option of each chosen transport).
    pub mode: Mode,
    /// How many times every case runs, one round after the other (1 to 3).
    pub rounds: u8,
    pub transports: Vec<Transport>,
    /// The servers that take turns opening the connection (raw transports ignore this).
    pub dialers: Vec<Side>,
    /// Stream pings per case; 0 = none.
    pub pings: u32,
    pub download: bool,
    pub upload: bool,
    /// Four downloads at once.
    pub parallel: bool,
    /// Seconds per transfer.
    pub speed_sec: u32,
    /// Stability hold, a ping every 2 s; 0 = none.
    pub hold_sec: u32,
    /// UDP packets through the test tunnel: loss and delay, idle and (with a download) under load.
    pub udp: bool,
    /// Plain TCP/UDP baseline and the largest datagram that crosses, once before the cases.
    pub mtu: bool,
    /// A failed case runs once more before it is reported.
    pub repeat_failed: bool,
    /// Also check each TLS transport with the browser-like TLS fingerprint.
    pub browser_tls: bool,
    /// Also check each TLS transport with the ClientHello split into fragments.
    pub tls_fragment: bool,
    /// Also check each TCP-based transport with `tcp_congestion` overridden to a non-default
    /// algorithm, to confirm the per-path override itself works.
    pub also_congestion: bool,
    /// Also check each `fec-udp`/`fec-raw`/`fec-raw-gaming` case with the adaptive pacer on.
    pub also_pacer: bool,
    /// Also check the raw TUN transport with fragmentation on and an MTU too big for one outer
    /// packet, so the case needs real splitting and reassembly.
    pub also_fragment: bool,
    /// Also check Parallax in packet mode (lanes under the FEC session), next to stream mode.
    pub parallax_packet: bool,
    /// Also check each non-raw transport with Game mode on (game UDP as datagram copies).
    pub also_game: bool,
    /// Also run every case (raw ones aside) between the servers' IPv6 addresses, when the code
    /// has both: a route that drops IPv4 may carry IPv6, and the other way round.
    pub ipv6: bool,
    /// Use IPv6 for both the control link and every test case.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ipv6_only: bool,
    /// Port for the TLS transports; 0 = the first free of `case::TLS_PORTS`.
    pub tls_port: u16,
    /// Port for every other transport; 0 = the first free of `case::HTTP_PORTS` for the HTTP
    /// transports, a random free port for the rest.
    pub port: u16,
    /// Port of the checker's own control link between the servers.
    pub control_port: u16,
    /// The packet types checked for the raw TUN transport (one case each).
    pub tun_profiles: Vec<RawProfile>,
    /// A working transport slower than this (Mbit/s, the slower direction) is reported as slow.
    pub slow_mbps: u32,
    pub priority: Priority,
}

/// The transports the first release checks, in the order they are shown. IPv6 is not a transport
/// of its own here: with both servers' IPv6 addresses every case also runs over IPv6.
pub const CHECKABLE: [Transport; 12] = [
    Transport::Tcp,
    Transport::Wss,
    Transport::Https,
    Transport::Xhttps,
    Transport::Ws,
    Transport::Http,
    Transport::Xhttp,
    Transport::Kcp,
    Transport::FecUdp,
    Transport::FecRaw,
    Transport::Tun,
    Transport::Parallax,
];

/// The transports a preset selects: everything that needs nothing special.
pub const RECOMMENDED: [Transport; 10] = [
    Transport::Tcp,
    Transport::Wss,
    Transport::Https,
    Transport::Xhttps,
    Transport::Ws,
    Transport::Http,
    Transport::Xhttp,
    Transport::Kcp,
    Transport::Parallax,
    Transport::FecUdp,
];

pub const DEFAULT_CONTROL_PORT: u16 = 47100;

/// Every packet type of the raw TUN transport.
pub const TUN_PROFILES: [RawProfile; 7] = [
    RawProfile::Tcp,
    RawProfile::Udp,
    RawProfile::Icmp,
    RawProfile::Gre,
    RawProfile::Ipip,
    RawProfile::Raw,
    RawProfile::Dns,
];

/// The name the wizard and the checker show for a raw packet type.
pub fn profile_name(profile: RawProfile) -> &'static str {
    match profile {
        RawProfile::Tcp => "tcp",
        RawProfile::Udp => "udp",
        RawProfile::Icmp => "icmp",
        RawProfile::Icmpv6 => "icmpv6",
        RawProfile::Bip => "bip",
        RawProfile::Gre => "gre",
        RawProfile::Ipip => "ipip",
        RawProfile::Raw => "raw",
        RawProfile::Dns => "dns",
    }
}

impl Default for Options {
    fn default() -> Self {
        Self::preset(Preset::Standard)
    }
}

impl Options {
    pub fn preset(preset: Preset) -> Self {
        let (pings, speed, hold, parallel, mtu, repeat) = match preset {
            Preset::Quick => (5, false, 0, false, false, false),
            Preset::Standard => (10, true, 30, false, false, true),
            Preset::Thorough => (10, true, 60, true, true, true),
        };
        Self {
            mode: Mode::Find,
            rounds: 1,
            transports: RECOMMENDED.to_vec(),
            dialers: vec![Side::Foreign, Side::Iran],
            pings,
            download: speed,
            upload: speed,
            parallel,
            speed_sec: 5,
            hold_sec: hold,
            udp: true,
            mtu,
            repeat_failed: repeat,
            browser_tls: false,
            tls_fragment: false,
            also_congestion: false,
            also_pacer: false,
            also_fragment: false,
            parallax_packet: true,
            also_game: false,
            ipv6: false,
            ipv6_only: false,
            tls_port: 0,
            port: 0,
            control_port: DEFAULT_CONTROL_PORT,
            tun_profiles: TUN_PROFILES.to_vec(),
            slow_mbps: 5,
            priority: Priority::Stability,
        }
    }

    /// A tune check of `transports` at the depth of `preset`: every option each one has, in
    /// `TUNE_ROUNDS` rounds. Failed cases are not repeated: the second round already is one.
    pub fn tune(preset: Preset, transports: Vec<Transport>) -> Self {
        Self {
            mode: Mode::Tune,
            rounds: TUNE_ROUNDS,
            transports,
            repeat_failed: false,
            ..Self::preset(preset)
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::ensure;
        ensure!(!self.transports.is_empty(), "choose at least one transport");
        ensure!((1..=3).contains(&self.rounds), "rounds must be 1 to 3");
        ensure!(
            self.transports.iter().all(|t| CHECKABLE.contains(t)),
            "a chosen transport cannot be checked"
        );
        ensure!(
            !self.ipv6_only || (self.ipv6 && !self.transports.iter().any(|&t| crate::manager::plan::is_raw(t))),
            "IPv6-only checks need IPv6-capable transports"
        );
        ensure!(
            !self.transports.contains(&Transport::Tun) || !self.tun_profiles.is_empty(),
            "choose at least one packet type for raw TUN"
        );
        ensure!(!self.dialers.is_empty(), "choose at least one direction");
        ensure!(self.pings <= 100, "pings must be 0..100");
        ensure!(
            (1..=60).contains(&self.speed_sec),
            "speed test seconds must be 1..60"
        );
        ensure!(self.hold_sec <= 600, "hold must be 0..600 seconds");
        ensure!(self.slow_mbps <= 10_000, "slow threshold must be 0..10000");
        ensure!(self.control_port != 0, "the control port must not be 0");
        ensure!(
            self.pings > 0 || self.download || self.upload || self.parallel || self.hold_sec > 0 || self.udp,
            "choose at least one measurement (ping, speed, hold or UDP)"
        );
        Ok(())
    }

    /// The cases these options produce, in run order.
    /// The variants checked for `transport`: the ones switched on, and in a tune check every one
    /// the transport has.
    pub fn variants(&self, transport: Transport) -> Vec<Variant> {
        let tune = self.mode == Mode::Tune;
        let mut variants = vec![Variant::Plain];
        if transport.uses_tls() {
            if tune || self.browser_tls {
                variants.push(Variant::BrowserTls);
            }
            if tune || self.tls_fragment {
                variants.push(Variant::TlsFragment);
            }
        }
        if (tune || self.also_congestion)
            && !crate::manager::plan::is_raw(transport)
            && !crate::manager::plan::uses_udp(transport)
        {
            variants.push(Variant::Congestion);
        }
        if (tune || self.also_pacer)
            // C42: fec.pacer is applied by the FEC carriers only; on plain kcp it is a no-op.
            && matches!(
                transport,
                Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming
            )
        {
            variants.push(Variant::Pacer);
        }
        if (tune || self.also_fragment) && transport == Transport::Tun {
            variants.push(Variant::Fragment);
        }
        // Both Parallax modes by default, so the report shows which one suits the route.
        if transport == Transport::Parallax && (tune || self.parallax_packet) {
            variants.push(Variant::Packet);
        }
        // Game mode works with every carrier that is not raw (those keep their own packet path).
        if (tune || self.also_game) && !crate::manager::plan::is_raw(transport) {
            variants.push(Variant::Game);
        }
        variants
    }

    pub fn cases(&self) -> Vec<CaseSpec> {
        let mut cases = Vec::new();
        for round in 0..self.rounds.max(1) {
        for &transport in &self.transports {
            let variants = self.variants(transport);
            for variant in variants {
                if transport == Transport::Tun {
                    for &profile in &self.tun_profiles {
                        cases.push(CaseSpec {
                            id: cases.len() as u32,
                            transport,
                            dialer: None,
                            variant,
                            profile: Some(profile),
                            round, ipv6: false,
                        });
                    }
                    continue;
                }
                if crate::manager::plan::is_raw(transport) {
                    cases.push(CaseSpec {
                        id: cases.len() as u32,
                        transport,
                        dialer: None,
                        variant,
                        profile: None,
                        round, ipv6: false,
                    });
                    continue;
                }
                let families: &[bool] = if self.ipv6_only {
                    &[true]
                } else if self.ipv6 && transport != Transport::Tcp6 {
                    &[false, true]
                } else {
                    &[false]
                };
                for &ipv6 in families {
                    for &dialer in &self.dialers {
                        cases.push(CaseSpec {
                            id: cases.len() as u32,
                            transport,
                            dialer: Some(dialer),
                            variant,
                            profile: None,
                            round,
                            ipv6,
                        });
                    }
                }
            }
        }
        }
        cases
    }

    /// Rough seconds one working case takes.
    pub fn case_seconds(&self) -> u64 {
        let transfers =
            u64::from(self.download) + u64::from(self.upload) + u64::from(self.parallel);
        // start-up and handshake, pings at about 0.3 s, transfers, hold, tear-down
        3 + u64::from(self.pings) * 3 / 10
            + u64::from(self.udp) * 3
            + transfers * (u64::from(self.speed_sec) + 1)
            + u64::from(self.hold_sec)
            + 1
    }

    /// Rough seconds the whole check takes when every case works.
    pub fn estimate_seconds(&self) -> u64 {
        let baseline = if self.mtu { 15 } else { 0 };
        baseline + self.cases().len() as u64 * self.case_seconds()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Variant {
    Plain,
    BrowserTls,
    TlsFragment,
    /// `tcp_congestion` set to a non-default algorithm, to confirm the override itself works
    /// (TCP-based carriers only).
    Congestion,
    /// `fec.pacer` on (`fec-udp`, `fec-raw`, `fec-raw-gaming` only; plain `kcp` ignores it).
    Pacer,
    /// `tun.fragment` on with an MTU well past one outer packet's budget, so the case genuinely
    /// exercises splitting and reassembly, not just the handshake (`tun` only).
    Fragment,
    /// Parallax packet mode, tested next to the classic stream mode (`parallax` only).
    Packet,
    /// Game mode: the UDP measurement's packets go as datagram copies over several ports (every
    /// transport except the raw ones). Uses the case port + 1 for its control and datagrams.
    Game,
}

impl Variant {
    pub fn label(self) -> &'static str {
        match self {
            Self::Plain => "",
            Self::BrowserTls => "browser TLS",
            Self::TlsFragment => "TLS fragment",
            Self::Congestion => "congestion",
            Self::Pacer => "pacer",
            Self::Fragment => "fragment",
            Self::Packet => "packet mode",
            Self::Game => "Game mode",
        }
    }
}

/// The algorithm `Variant::Congestion` sets, to differ from the program-wide default (`bbr`).
pub const CONGESTION_TEST_ALGORITHM: &str = "cubic";
/// The TUN MTU `Variant::Fragment` uses: well past what any raw profile's single outer packet
/// can carry, so the case needs real splitting, not just a bigger allowance.
pub const FRAGMENT_TEST_MTU: u16 = 4000;

/// One transport in one direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseSpec {
    pub id: u32,
    pub transport: Transport,
    /// `None` for raw transports, which send packets both ways.
    pub dialer: Option<Side>,
    pub variant: Variant,
    /// The packet type of a raw TUN case.
    #[serde(default)]
    pub profile: Option<RawProfile>,
    /// Which round of a check that runs every case more than once (0 = the first).
    #[serde(default)]
    pub round: u8,
    /// The case runs between the servers' IPv6 addresses (`CheckCode::iran_ip6`/`foreign_ip6`).
    /// A route that drops one family may carry the other.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ipv6: bool,
}

impl CaseSpec {
    pub fn transport_name(&self) -> String {
        let mut name = crate::manager::plan::transport_name(self.transport);
        if let Some(profile) = self.profile {
            name = format!("{name}/{}", profile_name(profile));
        }
        let name = match self.variant {
            Variant::Plain => name,
            variant => format!("{name} ({})", variant.label()),
        };
        let name = if self.ipv6 { format!("{name} over IPv6") } else { name };
        if self.round > 0 {
            format!("{name} #{}", self.round + 1)
        } else {
            name
        }
    }

    pub fn dialer_label(&self) -> &'static str {
        match self.dialer {
            Some(side) => side.label(),
            None => "both",
        }
    }
}

/// What a case showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Works,
    /// Connects and answers short requests; speed and stability were not measured (Quick).
    Reachable,
    Unstable,
    Slow,
    /// Small requests pass but transfers stall or reset.
    BulkBlocked,
    /// Download works but upload does not.
    DownloadOnly,
    /// Upload works but download does not.
    UploadOnly,
    /// Handshake, then nothing passes.
    BlockedAfterHandshake,
    NoHandshake,
    /// Cannot be checked on these servers (see the note).
    NotPossible,
    Skipped,
    /// The check stopped during this case.
    Stopped,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Works => "works",
            Self::Reachable => "reachable",
            Self::Unstable => "works, unstable",
            Self::Slow => "works, slow",
            Self::BulkBlocked => "bulk blocked",
            Self::DownloadOnly => "download only",
            Self::UploadOnly => "upload only",
            Self::BlockedAfterHandshake => "blocked after handshake",
            Self::NoHandshake => "no handshake",
            Self::NotPossible => "not possible here",
            Self::Skipped => "skipped",
            Self::Stopped => "stopped",
        }
    }

    /// The tunnel would carry traffic.
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Works | Self::Reachable | Self::Unstable | Self::Slow
        )
    }

    /// The path was really tested and refused (as opposed to skipped or impossible).
    pub fn failed(self) -> bool {
        matches!(
            self,
            Self::BulkBlocked
                | Self::DownloadOnly
                | Self::UploadOnly
                | Self::BlockedAfterHandshake
                | Self::NoHandshake
        )
    }
}

/// UDP packets sent through the test tunnel and what came back. A packet answered after more than
/// a second counts as `late`, not as answered: for a call or a game it is as good as lost.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UdpStats {
    pub sent: u32,
    /// Answered within a second.
    pub answered: u32,
    /// Answered after more than a second.
    pub late: u32,
    pub median_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}

impl UdpStats {
    /// Percent of the packets that did not come back in time.
    pub fn loss(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            f64::from(self.sent - self.answered.min(self.sent)) * 100.0 / f64::from(self.sent)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PingStats {
    pub sent: u32,
    pub answered: u32,
    pub median_ms: Option<f64>,
    pub worst_ms: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Transfer {
    pub mbps: f64,
    pub bytes: u64,
    /// Why it stopped early or failed.
    pub error: Option<String>,
}

impl Transfer {
    pub fn ok(&self) -> bool {
        self.error.is_none() && self.bytes > 0
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HoldStats {
    pub seconds: u32,
    pub pings: u32,
    pub failures: u32,
    pub reconnects: u64,
}

/// The measured result of one case (also used while it runs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseResult {
    /// Exact authenticated raw-carrier echo lower bound, not stream payload PMTU.
    #[serde(default)]
    pub raw_payload_echoed: Option<usize>,
    #[serde(default)]
    pub recommended_inner_mtu: Option<usize>,
    pub spec: CaseSpec,
    pub port: Option<u16>,
    /// Runs of this case (2 when a failure was repeated) and how many of them failed.
    pub runs: u32,
    pub failed_runs: u32,
    pub handshake_ms: Option<u64>,
    pub ping: Option<PingStats>,
    pub download: Option<Transfer>,
    pub upload: Option<Transfer>,
    pub parallel: Option<Transfer>,
    pub hold: Option<HoldStats>,
    /// UDP through the tunnel while nothing else runs.
    #[serde(default)]
    pub udp: Option<UdpStats>,
    /// UDP through the tunnel during the download.
    #[serde(default)]
    pub udp_loaded: Option<UdpStats>,
    /// The tunnel's own heartbeats: sent and answered.
    pub heartbeats: (u64, u64),
    /// The tunnel's own round trip (median of its heartbeats), comparable with `ping`.
    #[serde(default)]
    pub rtt_ms: Option<f64>,
    /// Game mode cases: whether the game path came up and carried the UDP measurement. A Game
    /// case whose UDP went through the tunnel instead (the fallback) did not test Game mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game_path: Option<bool>,
    pub verdict: Option<Verdict>,
    pub note: Option<String>,
}

impl CaseResult {
    pub fn new(spec: CaseSpec) -> Self {
        Self {
            spec,
            raw_payload_echoed: None,
            recommended_inner_mtu: None,
            port: None,
            runs: 0,
            failed_runs: 0,
            handshake_ms: None,
            ping: None,
            download: None,
            upload: None,
            parallel: None,
            hold: None,
            udp: None,
            udp_loaded: None,
            heartbeats: (0, 0),
            rtt_ms: None,
            game_path: None,
            verdict: None,
            note: None,
        }
    }

    /// The slower of the measured directions, if any transfer ran.
    pub fn slower_mbps(&self) -> Option<f64> {
        [&self.download, &self.upload, &self.parallel]
            .into_iter()
            .flatten()
            .filter(|t| t.ok())
            .map(|t| t.mbps)
            .reduce(f64::min)
    }

    /// Decides the verdict from what was measured. `handshake` is whether a session was ever
    /// authenticated.
    pub fn judge(&self, options: &Options) -> Verdict {
        if self.handshake_ms.is_none() {
            return Verdict::NoHandshake;
        }
        // Game mode that never carried anything is blocked, whatever the fallback carried.
        if self.spec.variant == Variant::Game && self.game_path != Some(true) {
            return Verdict::BlockedAfterHandshake;
        }
        let ping_ok = self.ping.as_ref().map(|p| p.answered > 0);
        let udp_selected=options.udp;
        let udp_ok=self.udp.as_ref().is_some_and(|udp|udp.answered>0);
        let any_data = ping_ok == Some(true)
            || udp_ok
            || [&self.download, &self.upload, &self.parallel]
                .into_iter()
                .flatten()
                .any(Transfer::ok)
            || self.hold.as_ref().is_some_and(|h| h.pings > h.failures)
            || self.heartbeats.1 > 0 && ping_ok.is_none()&&!udp_selected;
        if !any_data {
            return Verdict::BlockedAfterHandshake;
        }
        // Without transfers or a hold only reachability is known, not whether bulk data passes.
        let bulk_measured = self.download.is_some()
            || self.upload.is_some()
            || self.parallel.is_some()
            || self.hold.is_some();
        let lost_pings = self.ping.as_ref().is_some_and(|p| p.answered < p.sent);
        let lost_udp=udp_selected&&self.udp.as_ref().is_some_and(|udp|udp.answered<udp.sent);
        if !bulk_measured {
            return if lost_pings || lost_udp || self.failed_runs > 0 {
                Verdict::Unstable
            } else {
                Verdict::Reachable
            };
        }
        let down = self.download.as_ref().map(Transfer::ok);
        let up = self.upload.as_ref().map(Transfer::ok);
        match (down, up) {
            (Some(false), Some(false)) => return Verdict::BulkBlocked,
            (Some(true), Some(false)) => return Verdict::DownloadOnly,
            (Some(false), Some(true)) => return Verdict::UploadOnly,
            (Some(false), None) | (None, Some(false)) => return Verdict::BulkBlocked,
            _ => {}
        }
        if self.parallel.as_ref().is_some_and(|parallel|!parallel.ok()){
            return if down==Some(true)||up==Some(true){Verdict::Unstable}else{Verdict::BulkBlocked};
        }
        let shaky_hold = self
            .hold
            .as_ref()
            .is_some_and(|h| h.failures > 0 || h.reconnects > 0);
        if lost_pings || lost_udp || shaky_hold || self.failed_runs > 0 {
            return Verdict::Unstable;
        }
        if let Some(slower) = self.slower_mbps()
            && slower < f64::from(options.slow_mbps)
        {
            return Verdict::Slow;
        }
        Verdict::Works
    }
}

/// Shown under results that only checked reachability.
pub const REACHABLE_NOTE: &str = "\"reachable\": connects and answers short requests; speed and stability were not tested. Run Standard to see whether bulk data gets through and the link stays up.";

/// How well a transport hides as ordinary web traffic (higher is better).
fn hiding_rank(transport: Transport) -> u8 {
    match transport {
        Transport::Xhttps | Transport::Wss | Transport::Https => 3,
        Transport::Xhttp | Transport::Ws | Transport::Http => 2,
        Transport::Tcp | Transport::Tcp6 => 1,
        _ => 0,
    }
}

fn lossy_rank(transport: Transport) -> u8 {
    match transport {
        Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming => 2,
        Transport::Kcp => 1,
        _ => 0,
    }
}

fn verdict_rank(verdict: Option<Verdict>) -> u8 {
    match verdict {
        Some(Verdict::Works) => 4,
        Some(Verdict::Slow) => 3,
        Some(Verdict::Reachable) => 2,
        Some(Verdict::Unstable) => 1,
        _ => 0,
    }
}

/// The usable cases, best first for `priority`; one entry per transport (its best direction).
pub fn rank(results: &[CaseResult], priority: Priority) -> Vec<&CaseResult> {
    let mut usable: Vec<&CaseResult> = results
        .iter()
        .filter(|r| r.verdict.is_some_and(Verdict::usable) && r.failed_runs < r.runs.max(1))
        .collect();
    let speed = |r: &CaseResult| r.slower_mbps().unwrap_or(0.0);
    // UDP loss under load if measured, else idle; not measured counts as lost.
    let udp_loss = |r: &CaseResult| {
        r.udp_loaded
            .as_ref()
            .or(r.udp.as_ref())
            .map_or(100.0, |u| u.loss().round())
    };
    let ping = |r: &CaseResult| r.ping.as_ref().and_then(|p| p.worst_ms).unwrap_or(f64::MAX);
    usable.sort_by(|a, b| {
        let by_speed = speed(b).total_cmp(&speed(a));
        let by_stability = verdict_rank(b.verdict)
            .cmp(&verdict_rank(a.verdict))
            .then(ping(a).total_cmp(&ping(b)));
        match priority {
            Priority::Speed => by_speed.then(by_stability),
            Priority::Stability => by_stability.then(by_speed),
            Priority::Hiding => hiding_rank(b.spec.transport)
                .cmp(&hiding_rank(a.spec.transport))
                .then(verdict_rank(b.verdict).cmp(&verdict_rank(a.verdict)))
                .then(by_speed),
            // Measured loss first (whole percents, so noise does not decide), then the carriers
            // with error correction, which matter when the path loses packets.
            Priority::Lossy => udp_loss(a)
                .total_cmp(&udp_loss(b))
                .then(lossy_rank(b.spec.transport).cmp(&lossy_rank(a.spec.transport)))
                .then(verdict_rank(b.verdict).cmp(&verdict_rank(a.verdict)))
                .then(by_speed),
        }
    });
    let mut seen = Vec::new();
    usable.retain(|r| {
        let key = (r.spec.transport, r.spec.variant);
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
    usable
}

/// One option of one transport in a tune check, over all its rounds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TuneRow {
    pub transport: Transport,
    pub profile: Option<RawProfile>,
    pub variant: Variant,
    pub dialer: Option<Side>,
    #[serde(default)]
    pub ipv6: bool,
    /// Rounds that ran to a verdict.
    pub rounds: u32,
    /// Rounds that carried traffic.
    pub usable: u32,
    /// Usable rounds without lost pings, failed hold pings or reconnects.
    pub steady: u32,
    /// Averages over the usable rounds that measured them.
    pub down_mbps: Option<f64>,
    pub up_mbps: Option<f64>,
    /// The parallel downloads (several streams at once), when they were measured.
    #[serde(default)]
    pub parallel_mbps: Option<f64>,
    pub ping_ms: Option<f64>,
    pub udp_loss: Option<f64>,
    /// The best usable round of this option, for creating a tunnel from it.
    pub case_id: Option<u32>,
}

impl TuneRow {
    /// The slowest of what was measured (download, upload and parallel downloads): what limits
    /// the option, as one case's own figure does (`CaseResult::slower_mbps`).
    pub fn slower_mbps(&self) -> Option<f64> {
        [self.down_mbps, self.up_mbps, self.parallel_mbps].into_iter().flatten().reduce(f64::min)
    }

    /// "down / up" for the results, or the parallel downloads when only they ran.
    pub fn speed_text(&self) -> String {
        match (self.down_mbps, self.up_mbps, self.parallel_mbps) {
            (None, None, Some(parallel)) => format!("{parallel:.0} parallel"),
            (None, None, None) => "-".into(),
            (d, u, _) => format!(
                "{} / {}",
                d.map_or("-".into(), |v| format!("{v:.0}")),
                u.map_or("-".into(), |v| format!("{v:.0}"))
            ),
        }
    }

    /// The option alone, as the results show it ("default" for the plain case).
    pub fn option_label(&self) -> &'static str {
        match self.variant {
            Variant::Plain => "default",
            variant => variant.label(),
        }
    }
}

/// The options of one transport (one raw TUN packet type), best first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TuneGroup {
    pub transport: Transport,
    pub profile: Option<RawProfile>,
    #[serde(default)]
    pub ipv6: bool,
    pub rows: Vec<TuneRow>,
}

impl TuneGroup {
    pub fn name(&self) -> String {
        CaseSpec {
            id: 0,
            transport: self.transport,
            dialer: None,
            variant: Variant::Plain,
            profile: self.profile,
            round: 0, ipv6: self.ipv6,
        }
        .transport_name()
    }
}

fn mean(values: impl Iterator<Item = f64>) -> Option<f64> {
    let values: Vec<f64> = values.collect();
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

/// How much an option helps hiding as ordinary web traffic (higher is better).
fn variant_hiding(variant: Variant) -> u8 {
    // Game mode adds plain-looking UDP beside the carrier; it does not hide anything better.
    match variant {
        Variant::BrowserTls => 2,
        Variant::TlsFragment => 1,
        _ => 0,
    }
}

/// Orders two options for `priority`, better first. Small differences in ping (5 ms) and loss
/// (whole percents) count as equal, so noise does not decide.
fn compare_rows(a: &TuneRow, b: &TuneRow, priority: Priority) -> std::cmp::Ordering {
    let share = |r: &TuneRow| f64::from(r.usable) / f64::from(r.rounds.max(1));
    let speed = |r: &TuneRow| r.slower_mbps().unwrap_or(0.0);
    let ping = |r: &TuneRow| (r.ping_ms.unwrap_or(f64::MAX) / 5.0).round();
    let loss = |r: &TuneRow| r.udp_loss.map_or(100.0, f64::round);
    let steady = |r: &TuneRow| f64::from(r.steady) / f64::from(r.rounds.max(1));
    let works = share(b).total_cmp(&share(a));
    let by_speed = speed(b).total_cmp(&speed(a));
    let by_steady = steady(b).total_cmp(&steady(a));
    works.then(match priority {
        Priority::Speed => by_speed.then(by_steady).then(ping(a).total_cmp(&ping(b))),
        Priority::Stability => by_steady
            .then(loss(a).total_cmp(&loss(b)))
            .then(ping(a).total_cmp(&ping(b)))
            .then(by_speed),
        Priority::Lossy => loss(a).total_cmp(&loss(b)).then(by_steady).then(by_speed),
        Priority::Hiding => variant_hiding(b.variant)
            .cmp(&variant_hiding(a.variant))
            .then(by_steady)
            .then(by_speed),
    })
}

/// A tune check's results per transport: every option and direction over all rounds, best first,
/// and the transports in the order of their best option.
/// Which way and over which address family the servers can reach each other at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathState {
    pub ipv6: bool,
    /// The side that opened the connections.
    pub dialer: Side,
    /// Some case over this path carried traffic.
    pub works: bool,
}

/// One line per address family and direction that was tried, from every finished case: for a
/// route that drops one family or one direction, "IPv4 direct: blocked, IPv6 direct: works,
/// IPv4 reverse: works" says what to build on.
pub fn path_summary(results: &[CaseResult]) -> Vec<PathState> {
    let mut paths: Vec<PathState> = Vec::new();
    for case in results.iter().filter(|r| r.verdict.is_some_and(|v| v.usable() || v.failed())) {
        let Some(dialer) = case.spec.dialer else { continue };
        let ipv6 = case.spec.ipv6 || case.spec.transport == Transport::Tcp6;
        let works = case.verdict.is_some_and(Verdict::usable);
        match paths.iter_mut().find(|p| p.ipv6 == ipv6 && p.dialer == dialer) {
            Some(path) => path.works |= works,
            None => paths.push(PathState { ipv6, dialer, works }),
        }
    }
    paths.sort_by_key(|p| (p.ipv6, p.dialer == Side::Foreign));
    paths
}

/// "IPv4 direct: works" (the Iran server dials) or "IPv4 reverse: blocked" (the foreign one).
pub fn path_line(path: &PathState) -> String {
    format!(
        "{} {}: {}",
        if path.ipv6 { "IPv6" } else { "IPv4" },
        if path.dialer == Side::Iran { "direct" } else { "reverse" },
        if path.works { "works" } else { "blocked" }
    )
}

pub fn tune_summary(results: &[CaseResult], priority: Priority) -> Vec<TuneGroup> {
    let mut rows: Vec<TuneRow> = Vec::new();
    let finished: Vec<&CaseResult> = results
        .iter()
        .filter(|r| r.verdict.is_some_and(|v| v.usable() || v.failed()))
        .collect();
    for case in &finished {
        let spec = case.spec;
        if rows.iter().any(|r| {
            r.transport == spec.transport
                && r.profile == spec.profile
                && r.variant == spec.variant
                && r.dialer == spec.dialer
                && r.ipv6 == spec.ipv6
        }) {
            continue;
        }
        let same: Vec<&&CaseResult> = finished
            .iter()
            .filter(|r| {
                r.spec.transport == spec.transport
                    && r.spec.profile == spec.profile
                    && r.spec.variant == spec.variant
                    && r.spec.dialer == spec.dialer
                    && r.spec.ipv6 == spec.ipv6
            })
            .collect();
        let usable: Vec<&&&CaseResult> = same
            .iter()
            .filter(|r| r.verdict.is_some_and(Verdict::usable))
            .collect();
        let ok_mbps = |t: &Option<Transfer>| t.as_ref().filter(|t| t.ok()).map(|t| t.mbps);
        rows.push(TuneRow {
            transport: spec.transport,
            profile: spec.profile,
            variant: spec.variant,
            dialer: spec.dialer,
            ipv6: spec.ipv6,
            rounds: same.len() as u32,
            usable: usable.len() as u32,
            steady: usable
                .iter()
                .filter(|r| matches!(r.verdict, Some(Verdict::Works | Verdict::Slow | Verdict::Reachable)))
                .count() as u32,
            down_mbps: mean(usable.iter().filter_map(|r| ok_mbps(&r.download))),
            up_mbps: mean(usable.iter().filter_map(|r| ok_mbps(&r.upload))),
            parallel_mbps: mean(usable.iter().filter_map(|r| ok_mbps(&r.parallel))),
            ping_ms: mean(usable.iter().filter_map(|r| r.rtt_ms.or(r.ping.as_ref().and_then(|p| p.median_ms)))),
            udp_loss: mean(
                usable
                    .iter()
                    .filter_map(|r| r.udp_loaded.as_ref().or(r.udp.as_ref()).map(UdpStats::loss)),
            ),
            case_id: usable
                .iter()
                .max_by(|a, b| {
                    a.slower_mbps()
                        .unwrap_or(0.0)
                        .total_cmp(&b.slower_mbps().unwrap_or(0.0))
                })
                .map(|r| r.spec.id),
        });
    }
    let mut groups: Vec<TuneGroup> = Vec::new();
    for row in rows {
        match groups
            .iter_mut()
            .find(|g| g.transport == row.transport && g.profile == row.profile && g.ipv6 == row.ipv6)
        {
            Some(group) => group.rows.push(row),
            None => groups.push(TuneGroup {
                transport: row.transport,
                profile: row.profile,
                ipv6: row.ipv6,
                rows: vec![row],
            }),
        }
    }
    for group in &mut groups {
        group.rows.sort_by(|a, b| compare_rows(a, b, priority));
    }
    groups.sort_by(|a, b| {
        let hiding = if priority == Priority::Hiding {
            hiding_rank(b.transport).cmp(&hiding_rank(a.transport))
        } else {
            std::cmp::Ordering::Equal
        };
        hiding.then(compare_rows(&a.rows[0], &b.rows[0], priority))
    });
    groups
}

/// The transports a find check found best, for "Tune the best": distinct, best first.
pub fn best_transports(results: &[CaseResult], priority: Priority, count: usize) -> Vec<Transport> {
    let mut chosen = Vec::new();
    for case in rank(results, priority) {
        if !chosen.contains(&case.spec.transport) {
            chosen.push(case.spec.transport);
        }
        if chosen.len() == count {
            break;
        }
    }
    chosen
}

/// The whole check, as saved and shown at the end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    /// Unix seconds.
    pub started: u64,
    pub seconds: u64,
    pub iran_ip: String,
    pub foreign_ip: String,
    /// The IPv6 addresses the IPv6 cases used, when there were any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iran_ip6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_ip6: Option<String>,
    pub options: Options,
    pub baseline: Option<Baseline>,
    pub cases: Vec<CaseResult>,
    /// Set when the check did not run to the end.
    pub stopped: Option<String>,
}

/// Plain TCP/UDP between the servers and the largest datagram that crosses (the link test).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub tcp: bool,
    pub udp_loss_percent: Option<f64>,
    pub path_mtu: Option<usize>,
    pub error: Option<String>,
}

impl Report {
    /// A plain-text version for the saved `.txt` file and for terminals without the live view.
    pub fn text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "EZTunnel {} transport check: Iran {} <-> foreign {}\n",
            self.version, self.iran_ip, self.foreign_ip
        ));
        if let (Some(iran), Some(foreign)) = (&self.iran_ip6, &self.foreign_ip6) {
            out.push_str(&format!("IPv6: Iran {iran} <-> foreign {foreign}\n"));
        }
        let paths = path_summary(&self.cases);
        if !paths.is_empty() {
            out.push_str(&format!("Paths: {}\n", paths.iter().map(path_line).collect::<Vec<_>>().join(", ")));
        }
        if let Some(reason) = &self.stopped {
            out.push_str(&format!("Stopped early: {reason}\n"));
        }
        if let Some(baseline) = &self.baseline {
            out.push_str(&format!(
                "Baseline: plain TCP {}, UDP loss {}, path MTU {}{}\n",
                if baseline.tcp { "ok" } else { "failed" },
                baseline
                    .udp_loss_percent
                    .map_or("-".into(), |l| format!("{l:.0} %")),
                baseline.path_mtu.map_or("-".into(), |m| m.to_string()),
                baseline
                    .error
                    .as_ref()
                    .map_or(String::new(), |e| format!(" ({e})"))
            ));
        }
        out.push_str(&format!("{}  Result\n", table_header()));
        for case in &self.cases {
            out.push_str(&row_text(case));
            out.push('\n');
        }
        if self
            .cases
            .iter()
            .any(|c| c.verdict == Some(Verdict::Reachable))
        {
            out.push_str(&format!("\n{REACHABLE_NOTE}\n"));
        }
        if self.options.mode == Mode::Tune {
            out.push_str(&format!(
                "\nBest option per transport ({}, {} rounds each):\n",
                self.options.priority.label().to_lowercase(),
                self.options.rounds
            ));
            for group in tune_summary(&self.cases, self.options.priority) {
                out.push_str(&format!("  {}\n", group.name()));
                for (index, row) in group.rows.iter().enumerate() {
                    out.push_str(&format!(
                        "    {} {:<14} {:<8} dials  works {}/{}  {} Mbit/s  ping {}  UDP loss {}\n",
                        if index == 0 { "*" } else { " " },
                        row.option_label(),
                        row.dialer.map_or("both", Side::label),
                        row.usable,
                        row.rounds,
                        row.speed_text(),
                        fmt_ms(row.ping_ms),
                        row.udp_loss.map_or("-".into(), |v| format!("{v:.0} %")),
                    ));
                }
            }
            return out;
        }
        let ranked = rank(&self.cases, self.options.priority);
        if !ranked.is_empty() {
            out.push_str(&format!(
                "\nBest for this pair ({}):\n",
                self.options.priority.label().to_lowercase()
            ));
            for (index, case) in ranked.iter().take(3).enumerate() {
                out.push_str(&format!(
                    "  {}. {} · {} dials{}\n",
                    index + 1,
                    case.spec.transport_name(),
                    case.spec.dialer_label(),
                    case.slower_mbps()
                        .map_or(String::new(), |s| format!(" · {s:.0}+ Mbit/s"))
                ));
            }
        }
        out
    }
}

pub fn fmt_handshake(ms: Option<u64>) -> String {
    match ms {
        None => "-".into(),
        Some(ms) if ms < 1000 => format!("{ms} ms"),
        Some(ms) => format!("{:.1} s", ms as f64 / 1000.0),
    }
}

pub fn fmt_ms(value: Option<f64>) -> String {
    value.map_or("-".into(), |v| format!("{v:.0}"))
}

pub fn fmt_transfer(transfer: &Option<Transfer>) -> String {
    match transfer {
        None => "-".into(),
        Some(t) if t.ok() => format!("{:.0}", t.mbps),
        Some(_) => "fail".into(),
    }
}

/// Loss in percent of the idle / loaded UDP measurement: `0/3.6`.
pub fn fmt_udp_loss(case: &CaseResult) -> String {
    let one = |stats: &Option<UdpStats>| match stats {
        Some(s) if s.sent > 0 => {
            let loss = s.loss();
            if loss == 0.0 {
                "0".to_string()
            } else {
                format!("{loss:.1}")
            }
        }
        _ => "-".to_string(),
    };
    format!("{}/{}", one(&case.udp), one(&case.udp_loaded))
}

/// The 95th percentile round trip of UDP packets (ms): under load if measured, else idle.
pub fn fmt_udp_p95(case: &CaseResult) -> String {
    fmt_ms(
        case.udp_loaded
            .as_ref()
            .or(case.udp.as_ref())
            .and_then(|u| u.p95_ms),
    )
}

pub fn fmt_hold(hold: &Option<HoldStats>) -> String {
    match hold {
        None => "-".into(),
        Some(h) => format!("{}/{}", h.pings - h.failures.min(h.pings), h.pings),
    }
}

/// The transport and, once known, the port it used: `wss :8443`.
pub fn name_and_port(case: &CaseResult) -> String {
    match case.port {
        Some(port) => format!("{} :{port}", case.spec.transport_name()),
        None => case.spec.transport_name(),
    }
}

const TRANSPORT_COLUMN_WIDTH: usize = 42;

/// The column titles of every result table (the result column follows).
pub fn table_header() -> String {
    format!(
        "{:<TRANSPORT_COLUMN_WIDTH$} {:<8} {:>9} {:>6} {:>11} {:>8} {:>8} {:>10} {:>7} {:>7}",
        "Transport",
        "Dials",
        "Handshake",
        "RTT ms",
        "Conn ms",
        "↓ Mbit/s",
        "↑ Mbit/s",
        "UDP loss %",
        "UDP p95",
        "Hold"
    )
}

/// The measured columns of a result row. RTT is the tunnel's own round trip (like `ping`); Conn
/// is what a new connection costs until its first answer (median / worst): opening the stream at
/// the far side takes one round trip more.
pub fn table_cells(case: &CaseResult) -> String {
    format!(
        "{:<TRANSPORT_COLUMN_WIDTH$} {:<8} {:>9} {:>6} {:>11} {:>8} {:>8} {:>10} {:>7} {:>7}",
        name_and_port(case),
        case.spec.dialer_label(),
        fmt_handshake(case.handshake_ms),
        fmt_ms(case.rtt_ms),
        case.ping.as_ref().map_or("-".into(), |p| format!(
            "{}/{}",
            fmt_ms(p.median_ms),
            fmt_ms(p.worst_ms)
        )),
        fmt_transfer(&case.download),
        fmt_transfer(&case.upload),
        fmt_udp_loss(case),
        fmt_udp_p95(case),
        fmt_hold(&case.hold),
    )
}

fn row_text(case: &CaseResult) -> String {
    format!(
        "{}  {}{}",
        table_cells(case),
        case.verdict.map_or("…", Verdict::label),
        case.note
            .as_ref()
            .map_or(String::new(), |n| format!(" ({n})")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measured(spec: CaseSpec, verdict: Verdict, down: f64, up: f64, ping: f64) -> CaseResult {
        let mut r = CaseResult::new(spec);
        r.runs = 1;
        r.verdict = Some(verdict);
        if verdict.usable() {
            r.handshake_ms = Some(300);
            r.rtt_ms = Some(ping);
            r.download = Some(Transfer { mbps: down, bytes: 1, error: None });
            r.upload = Some(Transfer { mbps: up, bytes: 1, error: None });
            r.udp = Some(UdpStats { sent: 100, answered: 100, ..UdpStats::default() });
        }
        r
    }

    #[test]
    fn tune_mode_runs_every_option_of_each_transport_in_rounds() {
        let options = Options::tune(Preset::Quick, CHECKABLE.to_vec());
        assert!(options.validate().is_ok());
        let cases = options.cases();
        let count = |t: Transport, v: Variant| cases.iter().filter(|c| c.transport == t && c.variant == v).count();
        // Two directions, two rounds.
        for variant in [Variant::Plain, Variant::BrowserTls, Variant::TlsFragment, Variant::Congestion] {
            assert_eq!(count(Transport::Wss, variant), 4, "{variant:?}");
        }
        assert_eq!(count(Transport::Parallax, Variant::Packet), 4);
        assert_eq!(count(Transport::Parallax, Variant::Congestion), 4);
        assert_eq!(count(Transport::FecUdp, Variant::Pacer), 4);
        assert_eq!(count(Transport::FecUdp, Variant::Congestion), 0, "UDP carriers have no congestion case");
        assert_eq!(count(Transport::Kcp, Variant::Pacer), 0, "plain kcp ignores the pacer");
        assert_eq!(count(Transport::Tcp, Variant::BrowserTls), 0, "no TLS on tcp");
        // Raw: once per round (no direction); raw TUN once per packet type and per variant.
        assert_eq!(count(Transport::FecRaw, Variant::Pacer), 2);
        assert_eq!(count(Transport::Tun, Variant::Fragment), 2 * TUN_PROFILES.len());
        // Rounds run one after the other: every round-0 case comes before any round-1 case.
        let first_second = cases.iter().position(|c| c.round == 1).unwrap();
        assert!(cases[..first_second].iter().all(|c| c.round == 0));
        assert_eq!(cases.iter().filter(|c| c.round == 1).count(), first_second);
        // Ids stay unique across rounds.
        let mut ids: Vec<u32> = cases.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), cases.len());
        // The extra-check switches do not matter in tune mode, and do not leak into find mode.
        let find = Options::preset(Preset::Quick);
        assert_eq!(find.rounds, 1);
        assert!(!find.cases().iter().any(|c| c.variant == Variant::BrowserTls || c.round > 0));
        let mut bad = options.clone();
        bad.rounds = 0;
        assert!(bad.validate().is_err());
        bad.rounds = 4;
        assert!(bad.validate().is_err());
        // A later round is named as such.
        let later = cases.iter().find(|c| c.round == 1 && c.variant == Variant::TlsFragment).unwrap();
        assert!(later.transport_name().ends_with("(TLS fragment) #2"), "{}", later.transport_name());
        // A code from before the modes reads as a find check of one round.
        let mut old = serde_json::to_value(&find).unwrap();
        let object = old.as_object_mut().unwrap();
        object.remove("mode");
        object.remove("rounds");
        let read: Options = serde_json::from_value(old).unwrap();
        assert_eq!((read.mode, read.rounds), (Mode::Find, 1));
    }

    #[test]
    fn parallel_only_tune_checks_rank_by_their_parallel_speed() {
        let options = Options {
            dialers: vec![Side::Foreign],
            ..Options::tune(Preset::Standard, vec![Transport::Wss])
        };
        let cases = options.cases();
        let pick = |v: Variant| *cases.iter().find(|c| c.variant == v && c.round == 0).unwrap();
        let parallel = |spec: CaseSpec, mbps: f64, ping: f64| {
            let mut r = measured(spec, Verdict::Works, 0.0, 0.0, ping);
            (r.download, r.upload) = (None, None);
            r.parallel = Some(Transfer { mbps, bytes: 1, error: None });
            r
        };
        // The faster option has the worse ping; ranked by speed it must still win.
        let results = vec![parallel(pick(Variant::Plain), 20.0, 40.0), parallel(pick(Variant::Congestion), 90.0, 120.0)];
        let groups = tune_summary(&results, Priority::Speed);
        let best = &groups[0].rows[0];
        assert_eq!((best.variant, best.parallel_mbps), (Variant::Congestion, Some(90.0)));
        assert_eq!(best.slower_mbps(), Some(90.0));
        assert_eq!(best.speed_text(), "90 parallel");
        // Mixed: 100/100 with 1 Mbit/s parallel is slower than 50/50/50.
        let mixed = |spec: CaseSpec, single: f64, many: f64| {
            let mut r = measured(spec, Verdict::Works, single, single, 50.0);
            r.parallel = Some(Transfer { mbps: many, bytes: 1, error: None });
            r
        };
        let results = vec![mixed(pick(Variant::Plain), 100.0, 1.0), mixed(pick(Variant::Congestion), 50.0, 50.0)];
        assert_eq!(tune_summary(&results, Priority::Speed)[0].rows[0].variant, Variant::Congestion);
    }

    #[test]
    fn a_game_case_counts_only_when_its_own_udp_took_the_game_path() {
        let options = Options { udp: true, ..Options::default() };
        let spec = CaseSpec { id: 1, transport: Transport::FecUdp, dialer: Some(Side::Foreign), variant: Variant::Game, profile: None, round: 0, ipv6: false, };
        let mut game = CaseResult::new(spec);
        game.handshake_ms = Some(100);
        game.ping = Some(PingStats { sent: 5, answered: 5, ..PingStats::default() });
        game.udp = Some(UdpStats { sent: 100, answered: 100, ..UdpStats::default() });
        // Everything passed, but through the tunnel's fallback: not Game mode.
        for path in [None, Some(false)] {
            game.game_path = path;
            assert_eq!(game.judge(&options), Verdict::BlockedAfterHandshake, "{path:?}");
        }
        game.game_path = Some(true);
        assert!(game.judge(&options).usable());
        // Other variants never look at it.
        let plain = CaseResult { game_path: None, ..CaseResult::new(CaseSpec { variant: Variant::Plain, ..spec }) };
        assert!(CaseResult { handshake_ms: Some(100), ping: game.ping.clone(), udp: game.udp.clone(), ..plain }.judge(&options).usable());
    }

    #[test]
    fn tune_summary_averages_rounds_and_picks_the_best_option_per_transport() {
        let options = Options {
            dialers: vec![Side::Foreign],
            ..Options::tune(Preset::Standard, vec![Transport::Parallax, Transport::Wss])
        };
        let cases = options.cases();
        let pick = |t: Transport, v: Variant, round: u8| {
            *cases.iter().find(|c| c.transport == t && c.variant == v && c.round == round).unwrap()
        };
        let results = vec![
            // Parallax stream: 40 and 36 down; packet: 61 and 63 down but one round unstable.
            measured(pick(Transport::Parallax, Variant::Plain, 0), Verdict::Works, 40.0, 81.0, 96.0),
            measured(pick(Transport::Parallax, Variant::Plain, 1), Verdict::Works, 36.0, 80.0, 87.0),
            measured(pick(Transport::Parallax, Variant::Packet, 0), Verdict::Works, 61.0, 52.0, 89.0),
            measured(pick(Transport::Parallax, Variant::Packet, 1), Verdict::Unstable, 63.0, 67.0, 83.0),
            measured(pick(Transport::Parallax, Variant::Congestion, 0), Verdict::Works, 28.0, 60.0, 85.0),
            measured(pick(Transport::Parallax, Variant::Congestion, 1), Verdict::NoHandshake, 0.0, 0.0, 0.0),
            // wss: the browser look works both rounds, fragmentation is blocked.
            measured(pick(Transport::Wss, Variant::Plain, 0), Verdict::Works, 20.0, 20.0, 100.0),
            measured(pick(Transport::Wss, Variant::Plain, 1), Verdict::Works, 22.0, 18.0, 100.0),
            measured(pick(Transport::Wss, Variant::BrowserTls, 0), Verdict::Works, 30.0, 30.0, 100.0),
            measured(pick(Transport::Wss, Variant::BrowserTls, 1), Verdict::Works, 30.0, 32.0, 100.0),
            measured(pick(Transport::Wss, Variant::TlsFragment, 0), Verdict::NoHandshake, 0.0, 0.0, 0.0),
            measured(pick(Transport::Wss, Variant::TlsFragment, 1), Verdict::NoHandshake, 0.0, 0.0, 0.0),
        ];
        let speed = tune_summary(&results, Priority::Speed);
        let parallax = speed.iter().find(|g| g.transport == Transport::Parallax).unwrap();
        // Averages over the rounds that worked.
        let packet = parallax.rows.iter().find(|r| r.variant == Variant::Packet).unwrap();
        assert_eq!((packet.rounds, packet.usable, packet.steady), (2, 2, 1));
        assert_eq!(packet.down_mbps, Some(62.0));
        assert_eq!(packet.up_mbps, Some(59.5));
        let cubic = parallax.rows.iter().find(|r| r.variant == Variant::Congestion).unwrap();
        assert_eq!((cubic.rounds, cubic.usable), (2, 1));
        // Speed: packet mode wins (slower direction 59.5 against 38); cubic, which failed a
        // round, is last.
        assert_eq!(parallax.rows[0].variant, Variant::Packet);
        assert_eq!(parallax.rows.last().unwrap().variant, Variant::Congestion);
        // Its best round is the one to create a tunnel from.
        assert_eq!(packet.case_id, Some(pick(Transport::Parallax, Variant::Packet, 1).id));
        // Stability: the steady stream mode wins over packet mode with an unstable round.
        let steady = tune_summary(&results, Priority::Stability);
        let parallax = steady.iter().find(|g| g.transport == Transport::Parallax).unwrap();
        assert_eq!(parallax.rows[0].variant, Variant::Plain);
        // wss: the browser look first, the blocked option last with no case to create from.
        let wss = speed.iter().find(|g| g.transport == Transport::Wss).unwrap();
        assert_eq!(wss.rows[0].variant, Variant::BrowserTls);
        let blocked = wss.rows.last().unwrap();
        assert_eq!((blocked.variant, blocked.usable, blocked.case_id), (Variant::TlsFragment, 0, None));
        // Hiding puts the TLS transport first.
        assert_eq!(tune_summary(&results, Priority::Hiding)[0].transport, Transport::Wss);
        // Cases that were skipped or not reached count for nothing.
        let mut partial = results.clone();
        partial.push(CaseResult {
            verdict: Some(Verdict::Skipped),
            ..CaseResult::new(pick(Transport::Wss, Variant::Congestion, 0))
        });
        assert!(!tune_summary(&partial, Priority::Speed)
            .iter()
            .flat_map(|g| &g.rows)
            .any(|r| r.variant == Variant::Congestion && r.transport == Transport::Wss));
        // The report text has the per-transport section.
        let report = Report {
            version: "test".into(),
            started: 0,
            seconds: 1,
            iran_ip: "192.0.2.1".into(),
            foreign_ip: "192.0.2.2".into(),
            iran_ip6: None,
            foreign_ip6: None,
            options: options.clone(),
            baseline: None,
            cases: results,
            stopped: None,
        };
        let text = report.text();
        assert!(text.contains("Best option per transport"), "{text}");
        assert!(text.contains("browser TLS"), "{text}");
    }

    #[test]
    fn tune_the_best_takes_distinct_transports_in_ranking_order() {
        let options = Options::preset(Preset::Standard);
        let cases = options.cases();
        let first = |t: Transport, v: Variant| *cases.iter().find(|c| c.transport == t && c.variant == v).unwrap();
        let results = vec![
            measured(first(Transport::Parallax, Variant::Plain), Verdict::Works, 40.0, 80.0, 90.0),
            measured(first(Transport::Parallax, Variant::Packet), Verdict::Works, 60.0, 60.0, 90.0),
            measured(first(Transport::Wss, Variant::Plain), Verdict::Works, 30.0, 30.0, 90.0),
            measured(first(Transport::Tcp, Variant::Plain), Verdict::Works, 90.0, 90.0, 90.0),
            measured(first(Transport::Kcp, Variant::Plain), Verdict::Works, 10.0, 10.0, 90.0),
            measured(first(Transport::Xhttp, Variant::Plain), Verdict::NoHandshake, 0.0, 0.0, 0.0),
        ];
        let best = best_transports(&results, Priority::Speed, TUNE_BEST);
        assert_eq!(best, vec![Transport::Tcp, Transport::Parallax, Transport::Wss], "Parallax counted once");
        assert!(best_transports(&results[5..], Priority::Speed, TUNE_BEST).is_empty());
    }

    fn result(transport: Transport, verdict: Verdict, down: f64) -> CaseResult {
        let mut r = CaseResult::new(CaseSpec {
            id: 0,
            transport,
            dialer: Some(Side::Foreign),
            variant: Variant::Plain,
            profile: None,
                round: 0, ipv6: false,
        });
        r.runs = 1;
        r.verdict = Some(verdict);
        r.download = Some(Transfer {
            mbps: down,
            bytes: 1,
            error: None,
        });
        r
    }

    #[test]
    fn udp_loss_counts_late_packets_and_ranking_prefers_measured_loss() {
        let stats = |sent, answered, late| UdpStats {
            sent,
            answered,
            late,
            median_ms: Some(90.0),
            p95_ms: Some(120.0),
        };
        assert_eq!(stats(1000, 1000, 0).loss(), 0.0);
        assert_eq!(stats(1000, 964, 12).loss(), 3.6);
        assert_eq!(stats(0, 0, 0).loss(), 0.0);
        assert_eq!(stats(10, 12, 0).loss(), 0.0, "never negative");
        let mut lossy = result(Transport::Tcp, Verdict::Works, 50.0);
        lossy.udp = Some(stats(1000, 1000, 0));
        lossy.udp_loaded = Some(stats(1000, 900, 0));
        assert_eq!(fmt_udp_loss(&lossy), "0/10.0");
        assert_eq!(fmt_udp_p95(&lossy), "120");
        let mut clean = result(Transport::Kcp, Verdict::Works, 50.0);
        clean.udp = Some(stats(1000, 1000, 0));
        clean.udp_loaded = Some(stats(1000, 1000, 0));
        let fec = result(Transport::FecUdp, Verdict::Works, 50.0);
        // The measured clean case beats one with no UDP measurement, and a lossy one comes last.
        let all = [lossy.clone(), fec, clean];
        let order: Vec<Transport> = rank(&all, Priority::Lossy)
            .iter()
            .map(|r| r.spec.transport)
            .collect();
        assert_eq!(order, [Transport::Kcp, Transport::Tcp, Transport::FecUdp]);
        assert_eq!(
            fmt_udp_loss(&result(Transport::Tcp, Verdict::Works, 1.0)),
            "-/-"
        );
    }

    /// A `Transport :port` label wider than the Transport column overflows it instead of being
    /// truncated (`format!`'s `{:<N}` never shortens an over-long value), which desyncs the live
    /// view's redraw from what's actually on screen in a narrow terminal and leaves old frames
    /// behind on every tick - seen for real with `xhttps (tcp_congestion)` once Custom's "also
    /// check" variants were added. Every real case's longest possible label (5-digit port) must
    /// fit the column so this can't come back when a future variant gets a longer name.
    #[test]
    fn every_case_label_with_a_port_fits_the_transport_column() {
        let options = Options {
            transports: CHECKABLE.to_vec(),
            ipv6: true,
            also_congestion: true,
            also_pacer: true,
            also_fragment: true,
            browser_tls: true,
            tls_fragment: true,
            tun_profiles: TUN_PROFILES.to_vec(),
            ..Options::preset(Preset::Thorough)
        };
        // A tune check adds every option and a round number ("#3") to the name.
        let tune = Options { rounds: 3, ipv6: true, ..Options::tune(Preset::Thorough, CHECKABLE.to_vec()) };
        for spec in options.cases().into_iter().chain(tune.cases()) {
            let mut case = CaseResult::new(spec);
            case.port = Some(65535); // the widest possible port
            let label = name_and_port(&case);
            assert!(
                label.len() <= TRANSPORT_COLUMN_WIDTH,
                "{label:?} is {} chars, wider than the Transport column ({TRANSPORT_COLUMN_WIDTH})",
                label.len()
            );
        }
    }

    #[test]
    fn presets_and_cases() {
        for preset in [Preset::Quick, Preset::Standard, Preset::Thorough] {
            let options = Options::preset(preset);
            assert!(options.transports.contains(&Transport::Parallax));
            assert!(!options.transports.contains(&Transport::Mirage));
        }
        assert!(
            !CHECKABLE.contains(&Transport::Mirage),
            "checker has no spoof settings/consent"
        );
        let quick = Options::preset(Preset::Quick);
        assert!(quick.validate().is_ok());
        assert_eq!(quick.hold_sec, 0);
        assert!(!quick.download);
        // 10 transports, two directions each, plus Parallax packet mode in both directions
        assert_eq!(quick.cases().len(), 22);
        assert_eq!(
            quick
                .cases()
                .iter()
                .filter(|c| c.variant == Variant::Packet)
                .count(),
            2
        );
        assert!(
            quick
                .cases()
                .iter()
                .filter(|c| c.variant == Variant::Packet)
                .all(|c| c.transport == Transport::Parallax)
        );
        // Packet mode can be left out of a custom check; stream mode is always checked.
        let stream_only = Options { parallax_packet: false, ..quick.clone() };
        assert_eq!(stream_only.cases().len(), 20);
        assert!(stream_only.cases().iter().any(|c| c.transport == Transport::Parallax));
        assert!(!stream_only.cases().iter().any(|c| c.variant == Variant::Packet));
        // An older code without the field still checks both modes.
        let mut old = serde_json::to_value(&quick).unwrap();
        old.as_object_mut().unwrap().remove("parallax_packet");
        assert!(serde_json::from_value::<Options>(old).unwrap().parallax_packet);
        let mut raw = Options::preset(Preset::Standard);
        raw.transports = vec![Transport::FecRaw, Transport::Wss];
        raw.browser_tls = true;
        let cases = raw.cases();
        // fec-raw once (both ways), wss plain and browser TLS in two directions
        assert_eq!(cases.len(), 5);
        assert_eq!(cases[0].dialer, None);
        assert!(cases.iter().enumerate().all(|(i, c)| c.id == i as u32));
        assert!(raw.estimate_seconds() > 5 * 30);
        let mut none = quick.clone();
        none.transports.clear();
        assert!(none.validate().is_err());
        // Raw TUN: one case per packet type, and at least one type.
        let mut tun = quick;
        tun.transports = vec![Transport::Tun];
        assert!(tun.validate().is_ok());
        let cases = tun.cases();
        assert_eq!(cases.len(), TUN_PROFILES.len());
        assert_eq!(cases[3].transport_name(), "tun/gre");
        assert!(cases.iter().all(|c| c.dialer.is_none()));
        tun.tun_profiles.clear();
        assert!(tun.validate().is_err());
    }

    #[test]
    fn the_new_variants_are_gated_to_the_transports_they_apply_to() {
        // Congestion: TCP-based only (not kcp, a UDP carrier).
        let mut options = Options::preset(Preset::Quick);
        options.transports = vec![Transport::Tcp, Transport::Kcp];
        options.also_congestion = true;
        let cases = options.cases();
        assert!(
            cases
                .iter()
                .any(|c| c.transport == Transport::Tcp && c.variant == Variant::Congestion)
        );
        assert!(
            !cases
                .iter()
                .any(|c| c.transport == Transport::Kcp && c.variant == Variant::Congestion),
            "kcp is UDP-based; tcp_congestion does not apply to it"
        );

        // Pacer: fec-udp/fec-raw(-gaming) only (not plain tcp, and not plain kcp where it is a no-op).
        let mut options = Options::preset(Preset::Quick);
        options.transports = vec![Transport::Tcp, Transport::Kcp, Transport::FecUdp];
        options.also_pacer = true;
        let cases = options.cases();
        assert!(
            !cases
                .iter()
                .any(|c| c.transport == Transport::Tcp && c.variant == Variant::Pacer),
            "tcp has no KCP stream to pace"
        );
        assert!(
            !cases
                .iter()
                .any(|c| c.transport == Transport::Kcp && c.variant == Variant::Pacer),
            "plain kcp does not apply fec.pacer"
        );
        assert!(
            cases
                .iter()
                .any(|c| c.transport == Transport::FecUdp && c.variant == Variant::Pacer)
        );

        // Fragment: raw TUN only, one extra case per chosen packet type.
        let mut options = Options::preset(Preset::Quick);
        options.transports = vec![Transport::Tun];
        options.tun_profiles = vec![RawProfile::Tcp, RawProfile::Icmp];
        options.also_fragment = true;
        let cases = options.cases();
        assert_eq!(
            cases
                .iter()
                .filter(|c| c.variant == Variant::Fragment)
                .count(),
            2,
            "one Fragment case per packet type, alongside the Plain ones"
        );
        assert_eq!(cases.len(), 4, "2 packet types x (Plain + Fragment)");

        // Off by default: none of these appear unless explicitly turned on.
        let options = Options::preset(Preset::Standard);
        assert!(options.cases().iter().all(|c| !matches!(
            c.variant,
            Variant::Congestion | Variant::Pacer | Variant::Fragment
        )));
    }

    #[test]
    fn verdicts_separate_the_failure_kinds() {
        let options = Options::default();
        let spec = CaseSpec {
            id: 0,
            transport: Transport::Ws,
            dialer: Some(Side::Foreign),
            variant: Variant::Plain,
            profile: None,
                round: 0, ipv6: false,
        };
        let mut r = CaseResult::new(spec);
        assert_eq!(r.judge(&options), Verdict::NoHandshake);
        r.handshake_ms = Some(300);
        r.ping = Some(PingStats {
            sent: 10,
            answered: 0,
            ..Default::default()
        });
        assert_eq!(r.judge(&options), Verdict::BlockedAfterHandshake);
        r.ping = Some(PingStats {
            sent: 10,
            answered: 10,
            median_ms: Some(180.0),
            worst_ms: Some(200.0),
        });
        // Pings only (Quick): reachable, not "works".
        assert_eq!(r.judge(&options), Verdict::Reachable);
        let failed = Transfer {
            mbps: 0.0,
            bytes: 0,
            error: Some("stalled".into()),
        };
        let good = Transfer {
            mbps: 100.0,
            bytes: 1000,
            error: None,
        };
        r.download = Some(failed.clone());
        r.upload = Some(failed.clone());
        assert_eq!(r.judge(&options), Verdict::BulkBlocked);
        r.download = Some(good.clone());
        assert_eq!(r.judge(&options), Verdict::DownloadOnly);
        r.upload = Some(good.clone());
        assert_eq!(r.judge(&options), Verdict::Works);
        r.hold = Some(HoldStats {
            seconds: 30,
            pings: 15,
            failures: 1,
            reconnects: 0,
        });
        assert_eq!(r.judge(&options), Verdict::Unstable);
        r.hold = None;
        r.upload = Some(Transfer {
            mbps: 2.0,
            bytes: 10,
            error: None,
        });
        assert_eq!(r.judge(&options), Verdict::Slow);
    }
    /// C41: four-download-only is a measurement; nothing selected is still refused.
    #[test]
    fn parallel_only_options_are_valid_and_empty_measurements_are_not(){
        let mut options=Options::preset(Preset::Quick);
        assert!(options.validate().is_ok(),"preset stays valid");
        options.pings=0;options.download=false;options.upload=false;options.hold_sec=0;options.udp=false;options.parallel=true;
        assert!(options.validate().is_ok(),"parallel-only must be accepted");
        options.parallel=false;
        assert!(options.validate().is_err(),"no measurement at all");
        options.parallel=true;options.speed_sec=0;
        assert!(options.validate().is_err(),"invalid speed_sec with parallel");
        options.speed_sec=61;
        assert!(options.validate().is_err());
    }
    #[test]
    fn failed_parallel_bulk_never_becomes_works_and_udp_needs_application_answers(){
        let mut options=Options::default();options.parallel=true;options.download=false;options.upload=false;options.hold_sec=0;
        let mut result=CaseResult::new(CaseSpec{id:0,transport:Transport::Tcp,dialer:Some(Side::Foreign),variant:Variant::Plain,profile:None,round:0,ipv6:false});
        result.handshake_ms=Some(1);result.ping=Some(PingStats{sent:5,answered:5,..Default::default()});
        result.parallel=Some(Transfer{error:Some("one stream failed".into()),bytes:100,mbps:1.0});
        assert_eq!(result.judge(&options),Verdict::BulkBlocked);
        result.download=Some(Transfer{error:None,bytes:100,mbps:100.0});assert_eq!(result.judge(&options),Verdict::Unstable);
        result.parallel=None;result.download=None;result.ping=None;result.heartbeats=(5,5);options.udp=true;
        result.udp=Some(UdpStats{sent:5,answered:0,..Default::default()});assert_eq!(result.judge(&options),Verdict::BlockedAfterHandshake);
        result.udp=Some(UdpStats{sent:5,answered:4,..Default::default()});assert_eq!(result.judge(&options),Verdict::Unstable);
        result.udp=Some(UdpStats{sent:5,answered:5,..Default::default()});assert_eq!(result.judge(&options),Verdict::Reachable);
    }

    #[test]
    fn ranking_follows_the_priority() {
        let results = vec![
            result(Transport::Tcp, Verdict::Works, 300.0),
            result(Transport::Wss, Verdict::Works, 200.0),
            result(Transport::FecUdp, Verdict::Works, 100.0),
            result(Transport::Ws, Verdict::BlockedAfterHandshake, 0.0),
            result(Transport::Kcp, Verdict::Unstable, 400.0),
        ];
        let first = |p| rank(&results, p)[0].spec.transport;
        assert_eq!(first(Priority::Speed), Transport::Kcp);
        assert_eq!(first(Priority::Stability), Transport::Tcp);
        assert_eq!(first(Priority::Hiding), Transport::Wss);
        assert_eq!(first(Priority::Lossy), Transport::FecUdp);
        assert_eq!(
            rank(&results, Priority::Speed).len(),
            4,
            "the blocked one is left out"
        );
    }
}
