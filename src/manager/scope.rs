//! Which numeric settings belong to one tunnel. Every screen that lists settings (the wizard,
//! Change settings, bulk changes, the pairing code and the dashboard) asks this module, so a
//! tunnel only ever offers the settings its own carrier, mode and side really use.
use super::plan::{Direction, Plan, is_xhttp};
use crate::config::{Mode, Transport};
use crate::settings::Setting;
use anyhow::Result;
use serde_json::Value;

/// What decides which settings one tunnel uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    pub mode: Mode,
    pub transport: Transport,
    pub server_dials: bool,
    /// Parallax in packet mode (lanes under the FEC session) instead of stream mode.
    pub parallax_packet: bool,
    /// Wire version 2 or later: the traffic-shape (`stealth`) settings exist.
    pub wire_v2: bool,
    /// FEC-UDP with its UDP knock on.
    pub knock: bool,
    /// TLS fragmentation is turned on.
    pub tls_fragment: bool,
}

impl Scope {
    /// A new tunnel's defaults: wire version 3, knock on, no TLS fragmentation, stream mode.
    pub fn new(mode: Mode, transport: Transport, server_dials: bool) -> Self {
        Self {
            mode,
            transport,
            server_dials,
            parallax_packet: false,
            wire_v2: true,
            knock: true,
            tls_fragment: false,
        }
    }

    /// The scope of a saved tunnel, read from its configuration.
    pub fn of_config(config: &Value) -> Result<Self> {
        let mode: Mode = serde_json::from_value(config["mode"].clone())?;
        let server_dials = config
            .get("server_dials")
            .or_else(|| config.get("reverse"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let entry = match mode {
            Mode::Server => &config["listeners"][0],
            Mode::Client => &config["paths"][0],
        };
        let transport: Transport =
            serde_json::from_value(entry.get("transport").cloned().unwrap_or(Value::Null))
                .unwrap_or_default();
        Ok(Self {
            mode,
            transport,
            server_dials,
            parallax_packet: entry["parallax"]["mode"] == "packet",
            wire_v2: config["wire_version"].as_u64().unwrap_or(1) >= 2,
            knock: entry["fec"]["knock"].as_bool().unwrap_or(true),
            tls_fragment: entry["tls_fragment"]["enabled"].as_bool().unwrap_or(false),
        })
    }

    /// The scope of a tunnel the wizard is still building.
    pub fn of_plan(plan: &Plan) -> Self {
        Self {
            mode: plan.mode(),
            transport: plan.transport,
            server_dials: plan.direction == Direction::Direct,
            parallax_packet: plan.transport == Transport::Parallax
                && plan.parallax_mode == crate::parallax_carrier::Mode::Packet,
            wire_v2: plan.wire_version >= 2,
            knock: true,
            tls_fragment: plan.tls_fragment,
        }
    }

    /// Whether this side opens the connection between the servers.
    pub fn dials(&self) -> bool {
        (self.mode == Mode::Client) != self.server_dials
    }

    fn fec(&self) -> bool {
        matches!(
            self.transport,
            Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage
        )
    }

    fn packet_lanes(&self) -> bool {
        self.transport == Transport::Parallax && self.parallax_packet
    }

    /// The heading of the carrier's own settings.
    pub fn carrier_title(&self) -> String {
        match self.transport {
            Transport::Parallax if self.parallax_packet => "Parallax packet mode".into(),
            Transport::Parallax => "Parallax stream mode".into(),
            transport if is_xhttp(transport) => "XHTTP".into(),
            transport => super::plan::transport_name(transport).to_uppercase(),
        }
    }
}

/// Whether `setting` does anything on a tunnel with this scope.
pub fn applies(setting: &Setting, scope: &Scope) -> bool {
    let role = match scope.mode {
        Mode::Server => "server",
        Mode::Client => "client",
    };
    if setting.role != "both" && setting.role != role {
        return false;
    }
    let name = setting.name;
    match name.split_once('.').map(|(group, _)| group) {
        Some("kcp") => scope.transport == Transport::Kcp,
        Some("xhttp") => is_xhttp(scope.transport),
        // Only the side that opens TLS splits its ClientHello, and only when it is on.
        Some("tls_fragment") => scope.transport.uses_tls() && scope.dials() && scope.tls_fragment,
        Some("parallax") => {
            scope.transport == Transport::Parallax
                && match name {
                    "parallax.buffer_bytes" => !scope.parallax_packet,
                    // Only the side that dials opens lanes.
                    "parallax.lanes" => scope.parallax_packet && scope.dials(),
                    "parallax.warmup_min" | "parallax.warmup_max" => scope.parallax_packet,
                    _ => true,
                }
        }
        Some("fec") => match name {
            // The knock exists only on FEC-UDP, and only while it is on.
            "fec.knock_ttl_sec" => scope.transport == Transport::FecUdp && scope.knock,
            // Packet lanes are TCP: no UDP buffers, and every session has its own address.
            "fec.socket_buf_bytes" | "fec.max_peers_per_ip" => scope.fec(),
            _ => scope.fec() || scope.packet_lanes(),
        },
        // Wire version 2 only. Record padding, burst jitter and holding failed handshakes work on
        // every carrier; only the printable start padding is for streams TLS does not wrap.
        Some("stealth") => {
            scope.wire_v2
                && !(scope.transport.uses_tls() && matches!(name, "stealth.pad_min" | "stealth.pad_max"))
        }
        _ => match name {
            // Only level 1 exists; there is nothing to choose.
            "crypto_level" | "crypto_min" => false,
            "timeouts.server_dial_sec" => scope.server_dials,
            // Reconnect pauses belong to the client that dials; a listening client never retries.
            "retry_interval" => !scope.server_dials,
            // The wizard and Change settings ask for the pool on their own row.
            "connection_pool" | "connection_pool_max" => false,
            _ => true,
        },
    }
}

/// The settings a tunnel with this scope offers, in registry order.
pub fn relevant(scope: &Scope) -> Vec<Setting> {
    crate::settings::all()
        .into_iter()
        .filter(|setting| applies(setting, scope))
        .collect()
}

/// The groups the settings screens show, in the order they are listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Carrier,
    Keepalive,
    Capacity,
    Limits,
    Shape,
    Schedule,
}

impl Section {
    pub const ALL: [Section; 6] = [
        Section::Carrier,
        Section::Keepalive,
        Section::Capacity,
        Section::Limits,
        Section::Shape,
        Section::Schedule,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Section::Carrier => "carrier",
            Section::Keepalive => "keepalive",
            Section::Capacity => "capacity",
            Section::Limits => "limits",
            Section::Shape => "shape",
            Section::Schedule => "schedule",
        }
    }

    pub fn title(self, scope: &Scope) -> String {
        match self {
            Section::Carrier => format!("{} settings", scope.carrier_title()),
            Section::Keepalive => "Timeouts and reconnects".into(),
            Section::Capacity => "Streams, memory and threads".into(),
            Section::Limits => "Connection limits".into(),
            Section::Shape => "Traffic shape".into(),
            Section::Schedule => "Restarts, quota and logs".into(),
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            Section::Carrier => "used only by this tunnel's carrier; most must match on both servers",
            Section::Keepalive => "how fast a dead link is noticed and rebuilt",
            Section::Capacity => "how much each connection may keep in flight",
            Section::Limits => "how many sessions, handshakes and users this side accepts",
            Section::Shape => "padding and timing of the masked stream (wire version 2 and later)",
            Section::Schedule => "planned restarts, traffic quota and status logging on this server",
        }
    }
}

/// The group a setting is listed under.
pub fn section(setting: &Setting) -> Section {
    let name = setting.name;
    match name.split_once('.').map(|(group, _)| group) {
        Some("kcp" | "fec" | "parallax" | "xhttp" | "tls_fragment") => Section::Carrier,
        Some("stealth") => Section::Shape,
        Some("schedule" | "quota") => Section::Schedule,
        Some("timeouts") => Section::Keepalive,
        Some("queues") => Section::Capacity,
        _ => match name {
            "heartbeat_sec" | "dead_timeout_sec" | "retry_interval" | "dial_timeout" => {
                Section::Keepalive
            }
            "max_streams" | "stream_window" | "memory_budget_mb" | "worker_threads"
            | "max_open_files" => Section::Capacity,
            "stats_interval_sec" => Section::Schedule,
            _ => Section::Limits,
        },
    }
}

/// Settings that were set on a tunnel but no longer do anything after a change of its scope
/// (another Parallax mode, TLS fragmentation turned off). They are removed when it is saved.
pub fn stale(before: &Scope, after: &Scope, config: &Value) -> Vec<Setting> {
    crate::settings::all()
        .into_iter()
        .filter(|s| applies(s, before) && !applies(s, after))
        .filter(|s| super::plan::read_setting(config, s).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn names(scope: &Scope) -> Vec<&'static str> {
        relevant(scope).iter().map(|s| s.name).collect()
    }

    fn every_transport() -> Vec<Transport> {
        [
            "tcp", "tcp6", "kcp", "http", "https", "ws", "wss", "xhttp", "xhttps", "parallax",
            "fec-udp", "fec-raw", "fec-raw-gaming", "mirage", "tun",
        ]
        .iter()
        .filter_map(|name| serde_json::from_value(json!(name)).ok())
        .collect()
    }

    #[test]
    fn each_carrier_only_offers_its_own_group() {
        for transport in every_transport() {
            for mode in [Mode::Server, Mode::Client] {
                for dials in [false, true] {
                    let mut scope = Scope::new(mode, transport, dials);
                    scope.tls_fragment = true;
                    for name in names(&scope) {
                        let group = name.split_once('.').map(|(g, _)| g);
                        match group {
                            Some("kcp") => assert_eq!(transport, Transport::Kcp, "{name}"),
                            Some("xhttp") => assert!(is_xhttp(transport), "{name}"),
                            Some("parallax") => assert_eq!(transport, Transport::Parallax),
                            Some("tls_fragment") => assert!(transport.uses_tls() && scope.dials()),
                            Some("fec") => assert!(scope.fec(), "{name} on {transport:?}"),
                            Some("stealth") if matches!(name, "stealth.pad_min" | "stealth.pad_max") => {
                                assert!(!transport.uses_tls(), "{name}")
                            }
                            _ => {}
                        }
                        assert!(!name.starts_with("crypto_"), "{name}");
                    }
                }
            }
        }
    }

    #[test]
    fn parallax_modes_offer_their_own_settings() {
        for mode in [Mode::Server, Mode::Client] {
            let stream = Scope::new(mode, Transport::Parallax, false);
            let packet = Scope { parallax_packet: true, ..stream };
            let (s, p) = (names(&stream), names(&packet));
            assert!(s.contains(&"parallax.buffer_bytes"));
            assert!(!p.contains(&"parallax.buffer_bytes"));
            assert!(!s.iter().any(|n| n.starts_with("fec.") || n.contains("warmup")));
            for name in ["fec.sndwnd", "fec.rcvwnd", "fec.partial_flush_ms", "fec.resend_burst",
                         "fec.session_expire_sec", "parallax.warmup_min", "parallax.warmup_max"] {
                assert!(p.contains(&name), "{name} missing in packet mode ({mode:?})");
            }
            for name in ["fec.socket_buf_bytes", "fec.max_peers_per_ip", "fec.knock_ttl_sec"] {
                assert!(!p.contains(&name), "{name} offered in packet mode");
            }
        }
        let client = Scope { parallax_packet: true, ..Scope::new(Mode::Client, Transport::Parallax, false) };
        assert!(names(&client).contains(&"parallax.lanes"));
        // A direct tunnel: the Iran server (server) dials and opens the lanes; the listening
        // foreign server (client) has none to set.
        let dialing_server = Scope { server_dials: true, ..Scope { parallax_packet: true, ..Scope::new(Mode::Server, Transport::Parallax, false) } };
        assert!(names(&dialing_server).contains(&"parallax.lanes"));
        let listening_client = Scope { server_dials: true, ..client };
        assert!(!names(&listening_client).contains(&"parallax.lanes"));
        assert!(names(&listening_client).contains(&"parallax.warmup_min"), "warm-up is on both sides");
        let listening_server = Scope { parallax_packet: true, ..Scope::new(Mode::Server, Transport::Parallax, false) };
        assert!(!names(&listening_server).contains(&"parallax.lanes"));
        let server = Scope { parallax_packet: true, ..Scope::new(Mode::Server, Transport::Parallax, false) };
        assert!(names(&server).contains(&"fec.peer_idle_sec"));
    }

    #[test]
    fn conditional_settings_follow_the_tunnel() {
        let tcp = Scope::new(Mode::Client, Transport::Tcp, false);
        assert!(names(&tcp).contains(&"stealth.pad_max"));
        assert!(!names(&Scope { wire_v2: false, ..tcp }).iter().any(|n| n.starts_with("stealth.")));
        // Under TLS the start padding does nothing; record padding, jitter and the probe hold
        // still work and stay offered.
        let tls_names = names(&Scope::new(Mode::Client, Transport::Wss, false));
        assert!(!tls_names.iter().any(|n| matches!(*n, "stealth.pad_min" | "stealth.pad_max")));
        for name in ["stealth.record_pad_max", "stealth.jitter_ms", "stealth.probe_hold_sec"] {
            assert!(tls_names.contains(&name), "{name} missing under TLS");
        }
        let wss = Scope::new(Mode::Client, Transport::Wss, false);
        assert!(!names(&wss).iter().any(|n| n.starts_with("tls_fragment.")));
        assert!(names(&Scope { tls_fragment: true, ..wss }).contains(&"tls_fragment.min_bytes"));
        // The listening server never splits a ClientHello.
        let listening = Scope { tls_fragment: true, ..Scope::new(Mode::Server, Transport::Wss, false) };
        assert!(!names(&listening).iter().any(|n| n.starts_with("tls_fragment.")));
        let udp = Scope::new(Mode::Server, Transport::FecUdp, false);
        assert!(names(&udp).contains(&"fec.knock_ttl_sec"));
        assert!(!names(&Scope { knock: false, ..udp }).contains(&"fec.knock_ttl_sec"));
        assert!(!names(&Scope::new(Mode::Server, Transport::FecRaw, false)).contains(&"fec.knock_ttl_sec"));
        assert!(names(&tcp).contains(&"retry_interval"));
        assert!(!names(&Scope::new(Mode::Client, Transport::Tcp, true)).contains(&"retry_interval"));
        assert!(names(&Scope::new(Mode::Server, Transport::Tcp, true)).contains(&"timeouts.server_dial_sec"));
        assert!(!names(&Scope::new(Mode::Server, Transport::Tcp, false)).contains(&"timeouts.server_dial_sec"));
    }

    #[test]
    fn scope_is_read_from_the_saved_file() -> Result<()> {
        let config = json!({"mode":"client","wire_version":3,"paths":[{"addr":"192.0.2.1:7003",
            "transport":"parallax","parallax":{"mode":"packet"}}]});
        let scope = Scope::of_config(&config)?;
        assert!(scope.parallax_packet && scope.wire_v2 && !scope.server_dials);
        let old = json!({"mode":"server","reverse":true,"listeners":[{"addr":"192.0.2.1:1",
            "transport":"wss","tls_fragment":{"enabled":true}}]});
        let scope = Scope::of_config(&old)?;
        assert!(scope.server_dials && scope.tls_fragment && !scope.wire_v2);
        assert_eq!(scope.transport, Transport::Wss);
        Ok(())
    }

    #[test]
    fn every_setting_has_a_section_and_carrier_ones_are_first() {
        for setting in crate::settings::all() {
            let group = setting.name.split_once('.').map(|(g, _)| g);
            if matches!(group, Some("kcp" | "fec" | "parallax" | "xhttp" | "tls_fragment")) {
                assert_eq!(section(&setting), Section::Carrier, "{}", setting.name);
            } else {
                assert_ne!(section(&setting), Section::Carrier, "{}", setting.name);
            }
        }
    }

    #[test]
    fn a_mode_change_lists_the_values_that_no_longer_apply() {
        let config = json!({"mode":"client","paths":[{"addr":"192.0.2.1:1","transport":"parallax",
            "parallax":{"buffer_bytes":131072}}]});
        let stream = Scope::of_config(&config).unwrap();
        let packet = Scope { parallax_packet: true, ..stream };
        let gone: Vec<_> = stale(&stream, &packet, &config).iter().map(|s| s.name).collect();
        assert_eq!(gone, ["parallax.buffer_bytes"]);
        assert!(stale(&stream, &stream, &config).is_empty());
    }
}
