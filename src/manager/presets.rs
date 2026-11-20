//! Presets: ready-made settings for a kind of use, chosen per transport family, that can be
//! applied to a new or an existing tunnel from the terminal and from the dashboard.
//!
//! A preset only writes ordinary numeric settings (and the connection pool), so every value can
//! still be changed one by one afterwards. Each preset owns the same list of settings
//! (`MANAGED`): a setting the chosen preset does not name goes back to its default, so switching
//! from one preset to another never leaves the first one's values behind. Settings outside that
//! list (quota, schedule, traffic shape, timing set by the speed mode, ports...) are never touched.
//!
//! "Max capacity" has no fixed numbers: it sizes the limits to the server it runs on (memory and
//! CPU cores), so the hardware, not a default cap, decides how many users fit. The memory budget
//! it sets still bounds the flow-control windows, so a burst of users slows down instead of
//! exhausting memory. The unauthenticated-handshake limits are left alone: they only hold back
//! connections that have not proved the tunnel key.
use super::plan::{apply_setting, check, is_raw, read_setting};
use super::scope::{self, Scope};
use crate::config::Transport;
use crate::settings::{Place, Setting};
use anyhow::{Context, Result};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Balanced,
    ManyUsers,
    Gaming,
    Streaming,
    MaxCapacity,
}

impl Preset {
    pub const ALL: [Preset; 5] = [Preset::Balanced, Preset::ManyUsers, Preset::Gaming, Preset::Streaming, Preset::MaxCapacity];

    pub fn id(self) -> &'static str {
        match self {
            Preset::Balanced => "balanced",
            Preset::ManyUsers => "many-users",
            Preset::Gaming => "gaming",
            Preset::Streaming => "streaming",
            Preset::MaxCapacity => "max-capacity",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.id() == id)
    }

    pub fn label(self) -> &'static str {
        match self {
            Preset::Balanced => "Balanced",
            Preset::ManyUsers => "Many users",
            Preset::Gaming => "Gaming / low delay",
            Preset::Streaming => "Streaming / big downloads",
            Preset::MaxCapacity => "Max capacity",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Preset::Balanced => "good speed for most links (recommended)",
            Preset::ManyUsers => "room for many users at once: more sessions, connections and threads",
            Preset::Gaming => "small queues and fast failure detection for a steady low delay",
            Preset::Streaming => "bigger windows for fast single downloads",
            Preset::MaxCapacity => "no fixed caps: limits sized to this server's memory and CPU",
        }
    }
}

/// The groups of transports that share the same tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// TCP, TCP6, HTTP(S), WS(S): one TCP connection per session.
    Stream,
    /// XHTTP(S): many HTTP requests per session.
    Xhttp,
    Kcp,
    /// FEC-UDP, FEC-RAW, Mirage and Parallax packet mode: the FEC/KCP packet stack.
    Fec,
    /// Parallax stream mode: kernel TCP lanes.
    Parallax,
    /// A TUN tunnel: packets, one session.
    Tun,
}

impl Family {
    pub fn of(scope: &Scope, tun: bool) -> Self {
        if tun {
            return Family::Tun;
        }
        match scope.transport {
            Transport::Xhttp | Transport::Xhttps => Family::Xhttp,
            Transport::Kcp => Family::Kcp,
            Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage => Family::Fec,
            Transport::Parallax if scope.parallax_packet => Family::Fec,
            Transport::Parallax => Family::Parallax,
            Transport::Tun => Family::Tun,
            Transport::Tcp | Transport::Tcp6 | Transport::Http | Transport::Https | Transport::Ws | Transport::Wss => Family::Stream,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Family::Stream => "stream",
            Family::Xhttp => "xhttp",
            Family::Kcp => "kcp",
            Family::Fec => "fec",
            Family::Parallax => "parallax",
            Family::Tun => "tun",
        }
    }
}

/// What the server can give a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    pub memory_mb: u64,
    pub cores: u64,
}

impl Capacity {
    /// This machine (or the smaller limit of the container or service it runs in).
    pub fn here() -> Self {
        Self {
            memory_mb: crate::stats::usable_memory_mb().unwrap_or(1024),
            cores: std::thread::available_parallelism().map_or(1, |n| n.get() as u64),
        }
    }
}

/// The settings every preset owns. `connection_pool` is handled on its own (see `pool`).
pub const MANAGED: &[&str] = &[
    "stream_window",
    "max_streams",
    "max_streams_per_ip",
    "max_connections",
    "worker_threads",
    "memory_budget_mb",
    "max_open_files",
    "queues.stream_frames",
    "queues.session_frames",
    "heartbeat_sec",
    "dead_timeout_sec",
    "timeouts.probe_sec",
    "kcp.send_window",
    "kcp.recv_window",
    "kcp.socket_buf_bytes",
    "kcp.max_sessions",
    "kcp.max_sessions_per_ip",
    "fec.sndwnd",
    "fec.rcvwnd",
    "fec.socket_buf_bytes",
    "fec.max_peers_per_ip",
    "xhttp.max_requests",
    "xhttp.max_requests_per_ip",
    "xhttp.max_sessions",
    "xhttp.up_concurrency",
    "parallax.buffer_bytes",
    "parallax.max_sessions",
];

const MIB: u64 = 1_048_576;

/// The values a preset sets for a family: (setting name, value), plus the connection pool.
/// Names a transport does not have are skipped later.
/// `auto` is the transport's automatic pool (`Transport::auto_pool`); the pools follow it, so a
/// packet carrier keeps fewer sessions than a TCP one.
fn values(preset: Preset, family: Family, capacity: Capacity, auto: u64) -> (u64, Vec<(&'static str, u64)>) {
    let cores = capacity.cores.max(1);
    match preset {
        // The default stream window; FEC gets bigger packet windows, which measured faster
        // with no extra loss. KCP keeps its defaults: bigger KCP windows built up seconds of
        // delay on a full line.
        Preset::Balanced => {
            let list = match family {
                Family::Fec => vec![("fec.sndwnd", 2048), ("fec.rcvwnd", 2048)],
                _ => vec![],
            };
            (auto, list)
        }
        Preset::ManyUsers => {
            let mut list = vec![
                ("max_streams", 8192),
                ("max_streams_per_ip", 8192),
                ("max_connections", 64),
                ("worker_threads", cores.clamp(1, 8)),
                ("queues.session_frames", 512),
            ];
            match family {
                Family::Xhttp => list.extend([("xhttp.max_requests", 4096), ("xhttp.max_requests_per_ip", 4096), ("xhttp.max_sessions", 512)]),
                Family::Kcp => list.extend([("kcp.max_sessions", 8192), ("kcp.max_sessions_per_ip", 1024)]),
                Family::Fec => list.push(("fec.max_peers_per_ip", 1024)),
                Family::Parallax => list.push(("parallax.max_sessions", 512)),
                Family::Stream | Family::Tun => {}
            }
            (auto * 3 / 2, list)
        }
        Preset::Gaming => (auto.min(4), vec![("stream_window", 64), ("heartbeat_sec", 5), ("dead_timeout_sec", 20), ("timeouts.probe_sec", 2)]),
        Preset::Streaming => {
            // 256, not more: a window of 512 lost most UDP traffic once the line was full.
            let mut list = vec![("stream_window", 256)];
            match family {
                Family::Kcp => {}
                Family::Fec => list.extend([("fec.sndwnd", 2048), ("fec.rcvwnd", 2048)]),
                Family::Xhttp => list.push(("xhttp.up_concurrency", 16)),
                Family::Parallax => list.push(("parallax.buffer_bytes", 524_288)),
                Family::Stream | Family::Tun => {}
            }
            (auto + auto / 3, list)
        }
        Preset::MaxCapacity => {
            // Half of the memory for flow-control windows; about 64 KiB of buffers per user
            // connection on top, so the connection cap follows the same memory.
            let budget = (capacity.memory_mb / 2).clamp(64, 1_048_576);
            let streams = (capacity.memory_mb * 16).clamp(1024, 65_536);
            let sessions = (cores * 16).clamp(16, 1024);
            let mut list = vec![
                ("stream_window", 256),
                ("memory_budget_mb", budget),
                ("max_streams", streams),
                ("max_streams_per_ip", streams),
                ("max_connections", sessions),
                ("worker_threads", cores.clamp(1, 64)),
                ("max_open_files", (streams * 2 + 4096).min(16_777_216)),
                ("queues.session_frames", 1024),
            ];
            match family {
                Family::Xhttp => list.extend([
                    ("xhttp.max_requests", streams),
                    ("xhttp.max_requests_per_ip", streams),
                    ("xhttp.max_sessions", sessions * 4),
                    ("xhttp.up_concurrency", 16),
                ]),
                Family::Kcp => list.extend([("kcp.max_sessions", streams), ("kcp.max_sessions_per_ip", streams)]),
                Family::Fec => list.extend([
                    ("fec.max_peers_per_ip", 4096),
                    ("fec.sndwnd", 2048),
                    ("fec.rcvwnd", 2048),
                    ("fec.socket_buf_bytes", 8 * MIB),
                ]),
                Family::Parallax => list.push(("parallax.max_sessions", 4096)),
                Family::Stream | Family::Tun => {}
            }
            (cores.max(auto).min(auto * 2), list)
        }
    }
}

/// The values a preset gives a tunnel that is still being set up (the new-tunnel wizard):
/// (connection pool, settings by name).
pub fn for_plan(preset: Preset, scope: &Scope, tun: bool, capacity: Capacity) -> (u64, Vec<(&'static str, u64)>) {
    values(preset, Family::of(scope, tun), capacity, scope.transport.auto_pool() as u64)
}

/// One setting a preset changes: from the current value to the new one (`None` = default).
#[derive(Debug, Clone)]
pub struct Change {
    pub setting: Setting,
    pub from: Option<u64>,
    pub to: Option<u64>,
}

/// What a preset would do to a tunnel.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub preset: Preset,
    pub changes: Vec<Change>,
    /// The connection pool: (now, after), only where this side dials and can have one.
    pub pool: Option<(u64, u64)>,
}

impl Outcome {
    /// Whether the tunnel already has exactly this preset's values.
    pub fn active(&self) -> bool {
        self.changes.is_empty() && self.pool.is_none_or(|(now, after)| now == after)
    }
}

fn default_of(setting: &Setting) -> Option<u64> {
    setting.default.as_u64()
}

/// Whether this side has a connection pool (it dials, and the carrier is not single-session).
fn has_pool(config: &Value, scope: &Scope) -> bool {
    scope.dials() && !is_raw(scope.transport) && !config["tun"].is_object()
}

fn entry_key(scope: &Scope) -> &'static str {
    match scope.mode {
        crate::config::Mode::Server => "listeners",
        crate::config::Mode::Client => "paths",
    }
}

/// The changes `preset` makes to this tunnel's configuration, sized for `capacity`.
pub fn outcome(config: &Value, preset: Preset, capacity: Capacity) -> Result<Outcome> {
    let scope = Scope::of_config(config)?;
    let family = Family::of(&scope, config["tun"].is_object());
    let auto = scope.transport.auto_pool() as u64;
    let (pool, wanted) = values(preset, family, capacity, auto);
    let mut changes = Vec::new();
    for setting in scope::relevant(&scope) {
        if !MANAGED.contains(&setting.name) {
            continue;
        }
        let target = wanted
            .iter()
            .find(|(name, _)| *name == setting.name)
            .map(|(_, value)| (*value).clamp(setting.min, setting.max))
            .filter(|value| Some(*value) != default_of(&setting));
        let now = read_setting(config, &setting);
        // A value equal to the default counts as "not set".
        let now_effective = now.filter(|value| Some(*value) != default_of(&setting));
        if now_effective != target {
            changes.push(Change { setting, from: now, to: target });
        }
    }
    let pool = has_pool(config, &scope).then(|| {
        let now = config[entry_key(&scope)][0]["connection_pool"].as_u64().filter(|p| *p > 0).unwrap_or(auto);
        (now, pool.clamp(1, 16))
    });
    Ok(Outcome { preset, changes, pool })
}

/// The configuration with `preset` applied, checked by the program's own validation.
pub fn apply(config: &Value, preset: Preset, capacity: Capacity) -> Result<Value> {
    let outcome = outcome(config, preset, capacity)?;
    let mut edited = config.clone();
    for change in &outcome.changes {
        apply_setting(&mut edited, &change.setting, change.to)?;
    }
    if let Some((_, pool)) = outcome.pool {
        let scope = Scope::of_config(config)?;
        let entry = &mut edited[entry_key(&scope)][0];
        // The automatic pool is left unwritten, so a later default follows the program.
        if pool == scope.transport.auto_pool() as u64 {
            if let Some(object) = entry.as_object_mut() {
                object.remove("connection_pool");
            }
        } else {
            entry["connection_pool"] = json!(pool);
        }
    }
    check(&edited).with_context(|| format!("the {} preset does not fit this tunnel", preset.label()))?;
    Ok(edited)
}

fn place_word(place: Place) -> &'static str {
    match place {
        Place::Top => "top",
        Place::Listener => "listener",
        Place::Path => "path",
    }
}

/// Every preset with what it would change, for the dashboard's edit screen. A preset that does
/// not fit the tunnel (its values fail validation) is listed with its problem instead.
pub fn listed(config: &Value, capacity: Capacity) -> Value {
    let family = Scope::of_config(config).map(|scope| Family::of(&scope, config["tun"].is_object()).id()).unwrap_or("stream");
    let presets: Vec<Value> = Preset::ALL
        .into_iter()
        .map(|preset| {
            let problem = apply(config, preset, capacity).err().map(|error| format!("{error:#}"));
            match outcome(config, preset, capacity) {
                Ok(outcome) => json!({
                    "id": preset.id(), "label": preset.label(), "description": preset.description(),
                    "active": outcome.active(), "problem": problem,
                    "pool": outcome.pool.map(|(_, after)| after),
                    "changes": outcome.changes.iter().map(|c| json!({
                        "name": c.setting.name, "place": place_word(c.setting.place),
                        "from": c.from, "to": c.to, "default": c.setting.default, "unit": c.setting.unit,
                    })).collect::<Vec<_>>(),
                }),
                Err(error) => json!({"id": preset.id(), "label": preset.label(), "description": preset.description(),
                                     "active": false, "problem": format!("{error:#}"), "pool": null, "changes": []}),
            }
        })
        .collect();
    json!({"family": family, "capacity": {"memory_mb": capacity.memory_mb, "cores": capacity.cores}, "presets": presets})
}

/// The preset the tunnel's values match now, if any.
pub fn current(config: &Value, capacity: Capacity) -> Option<Preset> {
    Preset::ALL
        .into_iter()
        .find(|preset| outcome(config, *preset, capacity).is_ok_and(|o| o.active()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: Capacity = Capacity { memory_mb: 1024, cores: 1 };
    const BIG: Capacity = Capacity { memory_mb: 16_384, cores: 8 };

    fn key() -> String {
        crate::tunnel_key::TunnelKey::generate().unwrap().display()
    }

    /// The foreign end, which dials (TLS carriers use the certificate from the tunnel key).
    fn valid(transport: &str) -> Value {
        let tls = matches!(transport, "wss" | "https" | "xhttps");
        let mut path = json!({"addr": "203.0.113.10:7000", "transport": transport});
        if tls {
            path["tls_auto"] = json!(true);
        }
        let config = json!({"mode": "client", "tunnel_key": key(), "paths": [path]});
        check(&config).map(|_| config).unwrap()
    }

    /// The Iran end, which listens and forwards ports.
    fn server(transport: &str) -> Value {
        let mut config = json!({
            "mode": "server", "tunnel_key": key(),
            "listeners": [{"addr": "0.0.0.0:7000", "transport": transport,
                "maps": [{"type": "tcp", "bind": "0.0.0.0:443", "target": "127.0.0.1:443"}]}],
        });
        if matches!(transport, "wss" | "https" | "xhttps") {
            config["listeners"][0]["tls_auto"] = json!(true);
        }
        check(&config).map(|_| config).unwrap()
    }

    #[test]
    fn every_preset_fits_every_common_transport() {
        for transport in ["tcp", "ws", "wss", "http", "https", "xhttp", "xhttps", "kcp", "fec-udp", "parallax"] {
          for config in [valid(transport), server(transport)] {
            for preset in Preset::ALL {
                for capacity in [SMALL, BIG] {
                    let applied = apply(&config, preset, capacity).unwrap_or_else(|e| panic!("{transport} {preset:?}: {e:#}"));
                    assert!(outcome(&applied, preset, capacity).unwrap().active(), "{transport} {preset:?} applies fully");
                    assert_eq!(current(&applied, capacity), Some(preset), "{transport} {preset:?} is recognised");
                }
            }
          }
        }
    }

    #[test]
    fn switching_presets_leaves_nothing_behind() {
        let config = valid("kcp");
        let max = apply(&config, Preset::MaxCapacity, BIG).unwrap();
        assert!(max["paths"][0].get("kcp").and_then(|k| k.get("send_window")).is_none(), "KCP keeps its windows");
        let streaming = apply(&max, Preset::Streaming, BIG).unwrap();
        assert_eq!(streaming["stream_window"], 256);
        assert!(streaming.get("max_streams").is_none(), "Max capacity's limits are gone");
        let balanced = apply(&streaming, Preset::Balanced, BIG).unwrap();
        assert!(balanced.get("stream_window").is_none(), "back to the default");
        assert!(balanced["paths"][0].get("connection_pool").is_none(), "the automatic pool");
        assert_eq!(streaming["paths"][0]["connection_pool"], 4, "KCP: 3 automatic, a third more");

        let fec = apply(&valid("fec-udp"), Preset::Balanced, BIG).unwrap();
        assert_eq!(fec["paths"][0]["fec"]["sndwnd"], 2048);
        let gaming = apply(&fec, Preset::Gaming, BIG).unwrap();
        assert!(gaming["paths"][0].get("fec").and_then(|f| f.get("sndwnd")).is_none());
    }

    #[test]
    fn untouched_settings_stay() {
        let mut config = valid("tcp");
        config["quota"] = json!({"limit_gb": 50, "period_days": 30});
        config["timeouts"] = json!({"udp_idle_sec": 300});
        let applied = apply(&config, Preset::ManyUsers, SMALL).unwrap();
        assert_eq!(applied["quota"]["limit_gb"], 50);
        assert_eq!(applied["timeouts"]["udp_idle_sec"], 300);
        assert_eq!(applied["max_streams"], 8192);
    }

    #[test]
    fn max_capacity_follows_the_server() {
        let config = server("tcp");
        let small = apply(&config, Preset::MaxCapacity, SMALL).unwrap();
        let big = apply(&config, Preset::MaxCapacity, BIG).unwrap();
        assert!(big["max_streams"].as_u64() > small["max_streams"].as_u64());
        assert_eq!(big["worker_threads"], 8);
        assert_eq!(small["memory_budget_mb"], 512);
        assert_eq!(big["max_streams_per_ip"], big["max_streams"], "no per-address cap below the total");
    }

    #[test]
    fn the_listing_shows_changes_and_the_active_preset() {
        let config = apply(&server("xhttp"), Preset::Gaming, SMALL).unwrap();
        let listed = listed(&config, SMALL);
        assert_eq!(listed["family"], "xhttp");
        let gaming = listed["presets"].as_array().unwrap().iter().find(|p| p["id"] == "gaming").unwrap();
        assert_eq!(gaming["active"], true);
        let many = listed["presets"].as_array().unwrap().iter().find(|p| p["id"] == "many-users").unwrap();
        assert!(many["changes"].as_array().unwrap().iter().any(|c| c["name"] == "xhttp.max_requests"));
    }
}
