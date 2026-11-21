//! What the dashboard shows: a snapshot of this server and its tunnels, taken every few seconds,
//! and a short history of recent snapshots for the live charts.
use super::host::{Host, HostSampler};
use crate::manager::{
    figures::{loss_percent, rtt_figures},
    plan,
    service::{self, Health, LinkCheck, State},
    store::Store,
};
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::{Notify, broadcast};

/// How often a snapshot is taken.
pub const INTERVAL: Duration = Duration::from_secs(2);
/// Snapshots kept for the live chart: five minutes.
const HISTORY: usize = 150;
/// Heartbeat loss is measured over this window.
const LOSS_WINDOW: Duration = Duration::from_secs(60);
/// The journal is read this often per tunnel (it is the slowest source).
const HEALTH_EVERY: Duration = Duration::from_secs(30);
/// A tunnel that started this recently is not reported as disconnected yet.
const START_GRACE_SEC: u64 = 30;
/// Loss from this percentage on is reported.
const LOSS_WARNING: f64 = 1.0;
/// Heartbeats lost while a link comes up still count in the loss figure for about a minute.
const LOSS_GRACE_SEC: u64 = 90;
/// UDP datagrams dropped in the last minute from which it is reported. A new conversation can
/// lose a few in its first round trip; a steady count means datagrams are really being lost.
const UDP_DROP_WARNING: u64 = 20;

#[derive(Serialize, Clone, Debug)]
pub struct Snapshot {
    /// Milliseconds since 1970.
    pub at: u64,
    pub version: &'static str,
    pub demo: bool,
    pub host: Host,
    pub tunnels: Vec<Tunnel>,
    pub issues: Vec<Issue>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Carry {
    pub tun: bool,
    pub socks: bool,
    /// Forwarded ports (Iran side).
    pub ports: Vec<String>,
    /// Allowed destinations (foreign side).
    pub exits: Vec<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Quota {
    pub used: u64,
    pub limit: u64,
}

/// Game mode of a tunnel and what its datagram path did (since the tunnel started).
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Game {
    pub copies: u8,
    pub port: u16,
    /// The authenticated datagram path is up (at least one channel answered its challenge).
    /// None: a tunnel from before this figure existed, which cannot say whether it is up now.
    pub ready: Option<bool>,
    pub packets_out: u64,
    pub packets_in: u64,
    /// Later copies dropped because an earlier copy of the same packet had arrived.
    pub copies_absorbed: u64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Tunnel {
    pub name: String,
    /// "iran" or "foreign": which end this server is.
    pub side: &'static str,
    /// "reverse" or "direct".
    pub direction: &'static str,
    pub transport: String,
    /// The connection between the servers, for example `listen :7000` or `→ 203.0.113.5:7000`.
    pub link: String,
    pub carry: Carry,
    /// running, starting, stopped, failed or none (saved without a service).
    pub state: &'static str,
    /// working, no_traffic, not_connected, unconfirmed, silent, quota, down or unknown.
    pub link_state: &'static str,
    pub sessions: Option<u64>,
    pub streams: Option<u64>,
    pub reconnects: Option<u64>,
    pub rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_pct: Option<f64>,
    pub uptime_sec: Option<u64>,
    /// What users receive and send through the tunnel, bytes per second.
    pub down_bps: Option<f64>,
    pub up_bps: Option<f64>,
    /// Totals since the tunnel started.
    pub down_total: Option<u64>,
    pub up_total: Option<u64>,
    pub quota: Option<Quota>,
    pub last_drop: Option<String>,
    /// UDP datagrams the tunnel dropped since it started, and in the last minute.
    pub udp_dropped: Option<u64>,
    pub udp_dropped_recent: Option<u64>,
    /// Game mode, when the tunnel has it.
    pub game: Option<Game>,
    /// The configuration could not be read.
    pub error: Option<String>,
    /// The same for both ends of one tunnel (from their shared key, which it does not reveal),
    /// so the other end can be found on another managed server.
    pub pair: Option<String>,
    /// Failover tunnels: the carriers in order and, while it runs on the side with the user
    /// ports, which one is active and how each one is doing (the tunnel's own status).
    pub failover: Option<Value>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Issue {
    /// "bad" or "warn".
    pub level: &'static str,
    /// failed, not_connected, silent, no_traffic, quota, loss, udp_drops, failover_backup or
    /// carrier_down.
    pub kind: &'static str,
    pub tunnel: Option<String>,
    pub value: Option<f64>,
}

/// One point of the live chart.
#[derive(Serialize, Clone, Debug)]
pub struct Point {
    pub at: u64,
    pub down: f64,
    pub up: f64,
    /// Per tunnel: [down, up] bytes per second.
    pub t: BTreeMap<String, [f64; 2]>,
}

impl Point {
    fn of(snapshot: &Snapshot) -> Self {
        let t: BTreeMap<String, [f64; 2]> = snapshot
            .tunnels
            .iter()
            .map(|x| {
                (
                    x.name.clone(),
                    [x.down_bps.unwrap_or(0.0), x.up_bps.unwrap_or(0.0)],
                )
            })
            .collect();
        Self {
            at: snapshot.at,
            down: t.values().map(|v| v[0]).sum(),
            up: t.values().map(|v| v[1]).sum(),
            t,
        }
    }
}

pub fn issues(tunnels: &[Tunnel]) -> Vec<Issue> {
    let mut list = Vec::new();
    let mut add = |level, kind, tunnel: &Tunnel, value| {
        list.push(Issue {
            level,
            kind,
            tunnel: Some(tunnel.name.clone()),
            value,
        })
    };
    for tunnel in tunnels {
        let settled = tunnel.uptime_sec.is_none_or(|up| up >= START_GRACE_SEC);
        match (tunnel.state, tunnel.link_state) {
            ("failed", _) => add("bad", "failed", tunnel, None),
            ("running", "not_connected") if settled => add("bad", "not_connected", tunnel, None),
            ("running", "silent") => add("warn", "silent", tunnel, None),
            ("running", "no_traffic") if settled => add("warn", "no_traffic", tunnel, None),
            ("running", "quota") => add("warn", "quota", tunnel, None),
            _ => {}
        }
        if tunnel.state == "running"
            && tunnel.uptime_sec.is_none_or(|up| up >= LOSS_GRACE_SEC)
            && let Some(loss) = tunnel.loss_pct.filter(|l| *l >= LOSS_WARNING)
        {
            add("warn", "loss", tunnel, Some((loss * 10.0).round() / 10.0));
        }
        if tunnel.state == "running"
            && let Some(dropped) = tunnel.udp_dropped_recent.filter(|d| *d >= UDP_DROP_WARNING)
        {
            add("warn", "udp_drops", tunnel, Some(dropped as f64));
        }
        // Failover: users are on a backup carrier, or a carrier is down (the active one included
        // when nothing better is left).
        if tunnel.state == "running"
            && let Some(failover) = &tunnel.failover
            && let Some(active) = failover["active"].as_u64()
        {
            if active > 1 {
                // Which backup: the second carrier is backup 1.
                add("warn", "failover_backup", tunnel, Some((active - 1) as f64));
            }
            let down = failover["carriers"].as_array().into_iter().flatten().filter(|c| c["state"] == "down").count();
            if down > 0 {
                add("warn", "carrier_down", tunnel, Some(down as f64));
            }
        }
    }
    list.sort_by_key(|issue| issue.level != "bad");
    list
}

/// Where snapshots come from: this server, or sample data for the demo.
pub trait Source: Send {
    fn sample(&mut self) -> Snapshot;
}

pub struct Live {
    latest: RwLock<Option<Arc<Snapshot>>>,
    history: Mutex<VecDeque<Point>>,
    updates: broadcast::Sender<Arc<Snapshot>>,
    /// Takes the next snapshot now instead of at the next tick (after an action).
    nudge: Notify,
}

impl Live {
    /// Starts taking snapshots in the background.
    pub fn start(source: Box<dyn Source>, history: Option<Arc<super::history::History>>) -> Arc<Self> {
        let (updates, _) = broadcast::channel(8);
        let live = Arc::new(Self {
            latest: RwLock::new(None),
            history: Mutex::new(VecDeque::with_capacity(HISTORY)),
            updates,
            nudge: Notify::new(),
        });
        let source = Arc::new(Mutex::new(source));
        let task_live = live.clone();
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(INTERVAL);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticks.tick() => {}
                    _ = task_live.nudge.notified() => ticks.reset(),
                }
                let source = source.clone();
                let history = history.clone();
                let Ok(snapshot) = tokio::task::spawn_blocking(move || {
                    let snapshot = source.lock().unwrap().sample();
                    if let Some(history) = &history {
                        history.record(&snapshot);
                    }
                    snapshot
                })
                .await
                else {
                    continue;
                };
                task_live.publish(snapshot);
            }
        });
        live
    }

    fn publish(&self, snapshot: Snapshot) {
        let snapshot = Arc::new(snapshot);
        {
            let mut history = self.history.lock().unwrap();
            if history.len() == HISTORY {
                history.pop_front();
            }
            history.push_back(Point::of(&snapshot));
        }
        *self.latest.write().unwrap() = Some(snapshot.clone());
        let _ = self.updates.send(snapshot);
    }

    pub fn latest(&self) -> Option<Arc<Snapshot>> {
        self.latest.read().unwrap().clone()
    }

    pub fn history(&self) -> Vec<Point> {
        self.history.lock().unwrap().iter().cloned().collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Snapshot>> {
        self.updates.subscribe()
    }

    /// Asks for a fresh snapshot now, so a change made by an action shows at once.
    pub fn refresh(&self) {
        self.nudge.notify_one();
    }
}

fn millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// What one tunnel looked like at the previous snapshot.
#[derive(Default)]
struct Memory {
    counters: Option<(u64, u64, Instant)>,
    heartbeats: VecDeque<(Instant, u64, u64)>,
    udp_drops: VecDeque<(Instant, u64)>,
    health: Option<(Health, Instant)>,
}

/// The tunnels on this server, read through the manager's own functions.
pub struct LocalSource {
    store: Store,
    host: HostSampler,
    memory: HashMap<String, Memory>,
}

impl LocalSource {
    pub fn new() -> Result<Self> {
        Ok(Self {
            store: Store::open()?,
            host: HostSampler::default(),
            memory: HashMap::new(),
        })
    }

    fn tunnel(&mut self, name: &str) -> Tunnel {
        let mut view = Tunnel {
            name: name.to_string(),
            link_state: "unknown",
            ..Tunnel::default()
        };
        let config = match self.store.read(name) {
            Ok(config) => config,
            Err(error) => {
                view.state = "none";
                view.error = Some(format!("{error:#}"));
                return view;
            }
        };
        describe(&mut view, &config);
        view.game = crate::manager::pairing::game_of(&config)
            .map(|(port, copies)| Game { copies, port, ..Game::default() });
        let state = service::state(&self.store, name);
        view.state = state_word(state);
        let memory = self.memory.entry(name.to_string()).or_default();
        if !matches!(state, State::Running | State::Starting) {
            *memory = Memory::default();
            view.link_state = "down";
            view.quota = quota(name, &config);
            return view;
        }
        let status = service::control(name, &json!({"cmd": "status"}), Duration::from_millis(800)).ok();
        let now = Instant::now();
        let health = match &memory.health {
            Some((health, at)) if now.duration_since(*at) < HEALTH_EVERY => health.clone(),
            _ => {
                let health = service::health(name);
                memory.health = Some((health.clone(), now));
                health
            }
        };
        if let Some(status) = &status {
            read_status(&mut view, status, config["mode"] == "server", memory, now);
        } else {
            view.sessions = health.sessions;
        }
        view.last_drop = health.last_drop.clone();
        view.link_state = link_word(&health, status.as_ref());
        view.quota = quota(name, &config);
        view
    }
}

impl Source for LocalSource {
    fn sample(&mut self) -> Snapshot {
        let host = self.host.sample();
        let names = self.store.names().unwrap_or_default();
        self.memory.retain(|name, _| names.contains(name));
        let tunnels: Vec<Tunnel> = names.iter().map(|name| self.tunnel(name)).collect();
        Snapshot {
            at: millis_now(),
            version: env!("CARGO_PKG_VERSION"),
            demo: false,
            host,
            issues: issues(&tunnels),
            tunnels,
        }
    }
}

fn state_word(state: State) -> &'static str {
    match state {
        State::Running => "running",
        State::Starting => "starting",
        State::Stopped => "stopped",
        State::Failed => "failed",
        State::NoService => "none",
    }
}

pub(super) fn link_word(health: &Health, status: Option<&Value>) -> &'static str {
    if health.quota_exhausted {
        return "quota";
    }
    if health.silent {
        return "silent";
    }
    match service::classify_link(status, health.authenticated > 0) {
        LinkCheck::Working(_) => "working",
        LinkCheck::NoTraffic => "no_traffic",
        LinkCheck::NotConnected => "not_connected",
        LinkCheck::Unconfirmed => "unconfirmed",
    }
}

/// Fills in what the configuration says: side, direction, transport and what is carried.
fn describe(view: &mut Tunnel, config: &Value) {
    if let Ok(summary) = plan::summarize(config) {
        view.side = match summary.side {
            plan::Side::Iran => "iran",
            plan::Side::Foreign => "foreign",
        };
        view.direction = match summary.direction {
            plan::Direction::Reverse => "reverse",
            plan::Direction::Direct => "direct",
        };
        view.transport = summary.transport;
        view.link = summary.link;
    }
    view.carry = carry(config);
    view.pair = pair_of(config);
    view.failover = failover_of(config);
}

/// A failover tunnel's carriers in order, from its configuration.
pub fn failover_of(config: &Value) -> Option<Value> {
    if config["failover"]["enabled"] != true {
        return None;
    }
    let entries = config["listeners"].as_array().filter(|l| !l.is_empty()).or(config["paths"].as_array())?;
    let carriers: Vec<Value> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            json!({
                "order": index + 1,
                "carrier": format!("{} {}", entry["transport"].as_str().unwrap_or("tcp"), entry["addr"].as_str().unwrap_or("")),
            })
        })
        .collect();
    Some(json!({"carriers": carriers, "return_after_sec": config["failover"]["return_after_sec"].as_u64().unwrap_or(300)}))
}

/// A short fingerprint of the tunnel key, equal on both ends of a tunnel.
pub fn pair_of(config: &Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    let key = config["tunnel_key"].as_str().filter(|k| !k.is_empty())?;
    let digest = Sha256::new().chain_update(b"eztunnel dashboard pair\0").chain_update(key.as_bytes()).finalize();
    Some(digest[..8].iter().map(|b| format!("{b:02x}")).collect())
}

fn carry(config: &Value) -> Carry {
    let present = |key: &str| config.get(key).is_some_and(|v| !v.is_null());
    let mut ports: Vec<String> = Vec::new();
    for map in config["listeners"][0]["maps"].as_array().into_iter().flatten() {
        if let Some((_, port)) = map["bind"].as_str().and_then(|b| b.rsplit_once(':'))
            && !ports.iter().any(|p| p == port)
        {
            ports.push(port.to_string());
        }
    }
    Carry {
        tun: present("tun"),
        socks: present("socks5"),
        ports,
        exits: config["allowed_targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
    }
}

fn read_status(view: &mut Tunnel, status: &Value, server: bool, memory: &mut Memory, now: Instant) {
    let counter = |key: &str| status[key].as_u64();
    // Users download what the foreign server sends towards Iran (see the manager's live status).
    let (down_key, up_key) = if server {
        ("bytes_from_peer", "bytes_to_peer")
    } else {
        ("bytes_to_peer", "bytes_from_peer")
    };
    let down = counter(down_key).unwrap_or(0);
    let up = counter(up_key).unwrap_or(0);
    view.down_total = Some(down);
    view.up_total = Some(up);
    match memory.counters {
        Some((down0, up0, at)) if down >= down0 && up >= up0 => {
            let seconds = now.duration_since(at).as_secs_f64().max(0.001);
            view.down_bps = Some((down - down0) as f64 / seconds);
            view.up_bps = Some((up - up0) as f64 / seconds);
        }
        // First look, or the counters went back (the tunnel restarted).
        _ => {
            view.down_bps = Some(0.0);
            view.up_bps = Some(0.0);
        }
    }
    memory.counters = Some((down, up, now));
    if let Some(failover) = status.get("failover").filter(|f| f.is_object()) {
        view.failover = Some(failover.clone());
    }
    view.sessions = counter("sessions");
    view.streams = counter("streams");
    view.uptime_sec = counter("uptime_sec");
    view.reconnects = counter("connects")
        .zip(counter("sessions"))
        .map(|(connects, sessions)| connects.saturating_sub(sessions));
    let samples: Vec<f64> = status["rtt_ms"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_f64)
        .collect();
    if let Some((average, _, _, jitter)) = rtt_figures(&samples) {
        view.rtt_ms = Some(average);
        view.jitter_ms = Some(jitter);
    }
    let pongs = counter("pongs").unwrap_or(0);
    let lost = counter("pings_lost").unwrap_or(0);
    if memory
        .heartbeats
        .back()
        // Answers only ever grow while the tunnel runs: fewer means it restarted. The lost count
        // can fall a little on its own (a late answer takes a lost heartbeat back), which is a
        // correction, not a restart, and keeps the window.
        .is_some_and(|(_, p, _)| pongs < *p)
    {
        memory.heartbeats.clear();
    }
    memory.heartbeats.push_back((now, pongs, lost));
    while memory
        .heartbeats
        .front()
        .is_some_and(|(at, _, _)| now.duration_since(*at) > LOSS_WINDOW)
        && memory.heartbeats.len() > 2
    {
        memory.heartbeats.pop_front();
    }
    if let Some((_, pongs0, lost0)) = memory.heartbeats.front() {
        view.loss_pct = loss_percent(lost.saturating_sub(*lost0), pongs - pongs0);
    }
    if let Some(game) = &mut view.game {
        let extension = |key: &str| status["transport_extensions"][key].as_u64().unwrap_or(0);
        // Whether the path is usable now (a validated channel can expire); a tunnel from before
        // that figure existed only says whether it was ever validated.
        game.ready = status["gaming_ready"].as_bool();
        game.packets_out = extension("gaming_packets_sent");
        game.packets_in = extension("gaming_packets_received");
        game.copies_absorbed = extension("gaming_copies_absorbed");
    }
    if let Some(dropped) = counter("udp_dropped") {
        view.udp_dropped = Some(dropped);
        // A restart starts the count again.
        if memory.udp_drops.back().is_some_and(|(_, d)| dropped < *d) {
            memory.udp_drops.clear();
        }
        memory.udp_drops.push_back((now, dropped));
        while memory
            .udp_drops
            .get(1)
            .is_some_and(|(at, _)| now.duration_since(*at) >= LOSS_WINDOW)
        {
            memory.udp_drops.pop_front();
        }
        view.udp_dropped_recent = memory.udp_drops.front().map(|(_, first)| dropped - first);
    }
}

fn quota(name: &str, config: &Value) -> Option<Quota> {
    let limit_gb = config["quota"]["limit_gb"].as_u64().filter(|l| *l > 0)?;
    let period = config["quota"]["period_days"].as_u64().unwrap_or(30) * 86_400;
    let used = crate::quota::QuotaState::load(&crate::quota::service_state_path(name))
        .map(|mut state| {
            state.roll(crate::quota::now(), period);
            state.used_bytes
        })
        .unwrap_or(0);
    Some(Quota {
        used,
        limit: limit_gb * 1_000_000_000,
    })
}

/// Sample data for `eztunnel dashboard demo`: four tunnels whose figures move a little.
pub struct DemoSource {
    /// Shows a fresh install: this server and no tunnels.
    empty: bool,
    started: Instant,
    seed: u64,
    totals: [(f64, f64); 4],
    /// Start/stop/restart done in the demo.
    ops: Option<super::ops::DemoOps>,
}

impl DemoSource {
    pub fn new() -> Self {
        Self::with_tunnels(true)
    }

    pub fn with_tunnels(tunnels: bool) -> Self {
        Self {
            empty: !tunnels,
            started: Instant::now(),
            seed: 0x9e37_79b9_7f4a_7c15,
            totals: [
                (51.3e9, 4.2e9),
                (212.4e9, 18.6e9),
                (9.8e9, 1.1e9),
                (0.0, 0.0),
            ],
            ops: None,
        }
    }

    /// Sample data whose tunnels follow the demo's actions.
    pub fn with_ops(tunnels: bool, ops: super::ops::DemoOps) -> Self {
        Self { ops: Some(ops), ..Self::with_tunnels(tunnels) }
    }

    fn noise(&mut self) -> f64 {
        // xorshift: enough for wobbling sample figures.
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        (self.seed % 10_000) as f64 / 10_000.0
    }
}

impl Default for DemoSource {
    fn default() -> Self {
        Self::new()
    }
}

impl Source for DemoSource {
    fn sample(&mut self) -> Snapshot {
        let elapsed = self.started.elapsed().as_secs_f64();
        let wave = |period: f64, phase: f64| ((elapsed / period + phase) * std::f64::consts::TAU).sin();
        let seconds = INTERVAL.as_secs_f64();
        let specs: [(&str, &str, &str, &str, &[&str], f64, f64, bool); 4] = [
            ("game-fec", "fec-udp", "reverse", "listen :7000", &["9392"], 3.2e6, 82.0, true),
            ("web-wss", "wss", "reverse", "listen :443", &["443", "8443"], 11.0e6, 89.0, true),
            ("cdn-xhttps", "xhttps", "direct", "→ 198.51.100.20:2083", &["2083"], 0.9e6, 131.0, true),
            ("backup-tcp", "tcp", "reverse", "listen :7100", &["8080"], 1.5e6, 76.0, false),
        ];
        let mut tunnels = Vec::new();
        let empty = self.empty;
        let ops = self.ops.clone();
        for (index, (name, transport, direction, link, ports, rate, rtt, running)) in specs
            .into_iter()
            .enumerate()
            .filter(|(_, spec)| !empty && !ops.as_ref().is_some_and(|ops| ops.deleted(spec.0)))
        {
            let unstable = name == "cdn-xhttps";
            let running = self.ops.as_ref().map_or(running, |ops| ops.running(name, running));
            let mut tunnel = Tunnel {
                name: name.into(),
                side: "iran",
                direction,
                transport: transport.into(),
                link: link.into(),
                carry: Carry {
                    ports: ports.iter().map(|p| p.to_string()).collect(),
                    ..Carry::default()
                },
                state: if running { "running" } else { "stopped" },
                link_state: if !running {
                    "down"
                } else if unstable {
                    "no_traffic"
                } else {
                    "working"
                },
                ..Tunnel::default()
            };
            if running {
                let down = (rate * (1.0 + 0.35 * wave(40.0 + index as f64 * 7.0, index as f64 * 0.3))
                    * (0.85 + 0.3 * self.noise()))
                .max(0.0);
                let up = down * (0.08 + 0.04 * self.noise());
                self.totals[index].0 += down * seconds;
                self.totals[index].1 += up * seconds;
                tunnel.down_bps = Some(down);
                tunnel.up_bps = Some(up);
                tunnel.down_total = Some(self.totals[index].0 as u64);
                tunnel.up_total = Some(self.totals[index].1 as u64);
                tunnel.rtt_ms = Some(rtt + 4.0 * self.noise());
                tunnel.jitter_ms = Some(1.0 + 2.0 * self.noise());
                tunnel.loss_pct = Some(if unstable { 2.4 } else { 0.1 * self.noise() });
                tunnel.sessions = Some(if unstable { 2 } else { 4 });
                tunnel.streams = Some(8 + (self.noise() * 20.0) as u64);
                tunnel.reconnects = Some(if unstable { 7 } else { 0 });
                // A failover tunnel running on its first backup while its main carrier is down.
                if name == "web-wss" {
                    tunnel.failover = Some(json!({
                        "active": 2, "carrier": "wss 0.0.0.0:443", "switches": 1, "since_sec": 1260 + elapsed as u64,
                        "last_reason": "the active carrier is down", "return_after_sec": 300,
                        "carriers": [
                            {"order": 1, "carrier": "tcp 0.0.0.0:7100", "state": "down", "why": "no session answers", "for_sec": 1260 + elapsed as u64, "sessions": 0, "active": false},
                            {"order": 2, "carrier": "wss 0.0.0.0:443", "state": "healthy", "why": "", "for_sec": 86_400 + elapsed as u64, "sessions": 4, "active": true},
                            {"order": 3, "carrier": "xhttps 0.0.0.0:2083", "state": "healthy", "why": "", "for_sec": 86_400 + elapsed as u64, "sessions": 4, "active": false},
                        ],
                    }));
                }
                if name == "game-fec" {
                    let packets = (elapsed as u64 + 600) * 128;
                    tunnel.game = Some(Game { copies: 3, port: 7001, ready: Some(true), packets_out: packets,
                        packets_in: packets - packets / 90, copies_absorbed: packets * 19 / 10 });
                }
                tunnel.uptime_sec = Some(
                    [6 * 86_400 + 4 * 3600, 12 * 86_400 + 7 * 3600, 3 * 3600, 0][index]
                        + elapsed as u64,
                );
            }
            if name == "game-fec" {
                tunnel.quota = Some(Quota { used: 128_000_000_000, limit: 500_000_000_000 });
            }
            if name == "cdn-xhttps" {
                tunnel.quota = Some(Quota { used: 44_000_000_000, limit: 100_000_000_000 });
                tunnel.last_drop = Some("no heartbeat answer".into());
                tunnel.udp_dropped = Some(1840 + (elapsed as u64) / 2);
                tunnel.udp_dropped_recent = Some(30);
            }
            tunnels.push(tunnel);
        }
        // Tunnels created in the demo run quietly with small sample figures.
        for (name, config) in ops.as_ref().map(|ops| ops.created()).unwrap_or_default() {
            let mut tunnel = Tunnel { name, state: "running", link_state: "working", ..Tunnel::default() };
            describe(&mut tunnel, &config);
            tunnel.down_bps = Some(40_000.0 * self.noise());
            tunnel.up_bps = Some(8_000.0 * self.noise());
            tunnel.down_total = Some(0);
            tunnel.up_total = Some(0);
            tunnel.rtt_ms = Some(80.0 + 4.0 * self.noise());
            tunnel.loss_pct = Some(0.0);
            tunnel.sessions = Some(4);
            tunnel.uptime_sec = Some(elapsed as u64 % 600);
            tunnels.push(tunnel);
        }
        Snapshot {
            at: millis_now(),
            version: env!("CARGO_PKG_VERSION"),
            demo: true,
            host: Host {
                hostname: "tehran-1".into(),
                address: Some("203.0.113.10".into()),
                address6: Some("2001:db8:10::1".into()),
                os: Some("Ubuntu 24.04 LTS".into()),
                kernel: Some("6.8.0".into()),
                cores: 4,
                uptime_sec: Some(21 * 86_400 + elapsed as u64),
                congestion: Some("bbr".into()),
                cpu_pct: Some(18.0 + 10.0 * wave(30.0, 0.0).abs() + 4.0 * self.noise()),
                mem_pct: Some(41.0 + 2.0 * self.noise()),
                mem_total: Some(4 * 1024 * 1024 * 1024),
                disk_pct: Some(38.0),
                disk_total: Some(80_000_000_000),
                rx_bps: Some(16.0e6 * (0.9 + 0.2 * self.noise())),
                tx_bps: Some(15.0e6 * (0.9 + 0.2 * self.noise())),
            },
            issues: issues(&tunnels),
            tunnels,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn game_mode_figures_come_from_the_status() {
        let mut view = Tunnel { game: Some(Game { copies: 3, port: 7001, ..Game::default() }), ..Tunnel::default() };
        let mut status = json!({"sessions": 4, "gaming_ready": true, "transport_extensions": {"gaming_channels_validated": 2,
            "gaming_packets_sent": 500, "gaming_packets_received": 480, "gaming_copies_absorbed": 900}});
        read_status(&mut view, &status, true, &mut Memory::default(), Instant::now());
        assert_eq!(view.game, Some(Game { copies: 3, port: 7001, ready: Some(true), packets_out: 500, packets_in: 480, copies_absorbed: 900 }));
        // Every channel expired: validated once, but not up now.
        status["gaming_ready"] = json!(false);
        read_status(&mut view, &status, true, &mut Memory::default(), Instant::now());
        assert_eq!(view.game.as_ref().unwrap().ready, Some(false));
        // An older tunnel without the live figure: unknown, not "up" from a validation long ago.
        status.as_object_mut().unwrap().remove("gaming_ready");
        read_status(&mut view, &status, true, &mut Memory::default(), Instant::now());
        assert_eq!(view.game.as_ref().unwrap().ready, None);
        // A tunnel without Game mode shows none, whatever the counters say.
        let mut plain = Tunnel::default();
        read_status(&mut plain, &status, true, &mut Memory::default(), Instant::now());
        assert!(plain.game.is_none());
    }

    #[test]
    fn both_ends_of_a_tunnel_share_a_pair_that_does_not_show_the_key() {
        let key = crate::tunnel_key::TunnelKey::generate().unwrap().display();
        let iran = json!({"mode": "server", "tunnel_key": key});
        let foreign = json!({"mode": "client", "tunnel_key": key});
        let pair = pair_of(&iran).unwrap();
        assert_eq!(pair.len(), 16);
        assert_eq!(Some(pair.clone()), pair_of(&foreign));
        assert!(!key.contains(&pair));
        let other = json!({"tunnel_key": crate::tunnel_key::TunnelKey::generate().unwrap().display()});
        assert_ne!(pair_of(&other), Some(pair));
        assert_eq!(pair_of(&json!({"mode": "server"})), None);
    }

    fn tunnel(state: &'static str, link: &'static str) -> Tunnel {
        Tunnel {
            name: "t".into(),
            state,
            link_state: link,
            uptime_sec: Some(600),
            ..Tunnel::default()
        }
    }

    #[test]
    fn trouble_is_listed_worst_first() {
        let mut lossy = tunnel("running", "working");
        lossy.loss_pct = Some(2.44);
        let list = issues(&[
            lossy,
            tunnel("failed", "down"),
            tunnel("running", "working"),
            tunnel("stopped", "down"),
        ]);
        assert_eq!(list.len(), 2);
        assert_eq!((list[0].level, list[0].kind), ("bad", "failed"));
        assert_eq!((list[1].kind, list[1].value), ("loss", Some(2.4)));
    }

    #[test]
    fn loss_while_a_link_comes_up_is_not_a_problem_yet() {
        let mut fresh = tunnel("running", "working");
        fresh.loss_pct = Some(4.0);
        fresh.uptime_sec = Some(51);
        assert!(issues(&[fresh.clone()]).is_empty());
        fresh.uptime_sec = Some(LOSS_GRACE_SEC);
        assert_eq!(issues(&[fresh])[0].kind, "loss");
    }

    #[test]
    fn steady_udp_drops_are_reported_and_a_few_are_not() {
        let mut busy = tunnel("running", "working");
        busy.udp_dropped = Some(877);
        busy.udp_dropped_recent = Some(255);
        let mut quiet = tunnel("running", "working");
        quiet.udp_dropped = Some(12);
        quiet.udp_dropped_recent = Some(3);
        let list = issues(&[busy, quiet]);
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].kind, list[0].value), ("udp_drops", Some(255.0)));
    }

    #[test]
    fn udp_drops_of_the_last_minute_come_from_the_counter() {
        let mut memory = Memory::default();
        let start = Instant::now();
        let mut view = Tunnel::default();
        let status = |dropped: u64| json!({"bytes_from_peer": 0, "bytes_to_peer": 0, "udp_dropped": dropped});
        read_status(&mut view, &status(266), true, &mut memory, start);
        assert_eq!((view.udp_dropped, view.udp_dropped_recent), (Some(266), Some(0)));
        read_status(&mut view, &status(622), true, &mut memory, start + Duration::from_secs(30));
        assert_eq!(view.udp_dropped_recent, Some(356));
        read_status(&mut view, &status(877), true, &mut memory, start + Duration::from_secs(70));
        assert_eq!(view.udp_dropped_recent, Some(611), "from the newest sample at least a minute old");
        read_status(&mut view, &status(900), true, &mut memory, start + Duration::from_secs(95));
        assert_eq!(view.udp_dropped_recent, Some(278), "the oldest sample left the window");
        // A restart: the counter starts again and so does the window.
        read_status(&mut view, &status(4), true, &mut memory, start + Duration::from_secs(72));
        assert_eq!((view.udp_dropped, view.udp_dropped_recent), (Some(4), Some(0)));
    }

    #[test]
    fn a_tunnel_that_just_started_is_not_reported_disconnected() {
        let mut fresh = tunnel("running", "not_connected");
        fresh.uptime_sec = Some(5);
        assert!(issues(&[fresh]).is_empty());
        assert_eq!(issues(&[tunnel("running", "not_connected")])[0].kind, "not_connected");
    }

    #[test]
    fn rates_and_loss_come_from_counter_differences() {
        let mut memory = Memory::default();
        let start = Instant::now();
        let mut view = Tunnel::default();
        let status = |down: u64, pongs: u64, lost: u64| {
            json!({"bytes_from_peer": down, "bytes_to_peer": 10, "pongs": pongs, "pings_lost": lost,
                   "sessions": 2, "connects": 5, "rtt_ms": [80.0, 84.0]})
        };
        read_status(&mut view, &status(1_000, 10, 0), true, &mut memory, start);
        assert_eq!(view.down_bps, Some(0.0));
        assert_eq!(view.reconnects, Some(3));
        assert_eq!(view.rtt_ms, Some(82.0));
        read_status(&mut view, &status(5_000, 19, 1), true, &mut memory, start + Duration::from_secs(2));
        assert_eq!(view.down_bps, Some(2_000.0));
        assert_eq!(view.loss_pct, Some(10.0));
        // A late answer takes one lost heartbeat back: the window and the other loss stay.
        read_status(&mut view, &status(6_000, 29, 0), true, &mut memory, start + Duration::from_secs(3));
        assert_eq!(view.loss_pct, Some(0.0));
        read_status(&mut view, &status(7_000, 30, 2), true, &mut memory, start + Duration::from_millis(3500));
        assert!(view.loss_pct.is_some_and(|l| l > 0.0), "the window was kept: {:?}", view.loss_pct);
        // A restart resets the counters: no negative rate, loss starts over.
        read_status(&mut view, &status(100, 1, 0), true, &mut memory, start + Duration::from_secs(4));
        assert_eq!(view.down_bps, Some(0.0));
        assert_eq!(view.loss_pct, None);
    }

    #[test]
    fn the_client_side_swaps_download_and_upload() {
        let mut memory = Memory::default();
        let mut view = Tunnel::default();
        read_status(
            &mut view,
            &json!({"bytes_from_peer": 1, "bytes_to_peer": 99}),
            false,
            &mut memory,
            Instant::now(),
        );
        assert_eq!(view.down_total, Some(99));
        assert_eq!(view.up_total, Some(1));
    }

    #[test]
    fn what_a_tunnel_carries_is_read_from_its_configuration() {
        let config = json!({"listeners": [{"maps": [
            {"bind": "0.0.0.0:443", "type": "tcp"}, {"bind": "0.0.0.0:443", "type": "udp"},
            {"bind": "[::]:8443"}]}], "socks5": {"bind": "127.0.0.1:1080"}, "tun": null});
        let carry = carry(&config);
        assert_eq!(carry.ports, ["443", "8443"]);
        assert!(carry.socks);
        assert!(!carry.tun);
    }

    #[test]
    fn the_demo_reports_its_unstable_tunnel() {
        let mut demo = DemoSource::new();
        let snapshot = demo.sample();
        assert!(snapshot.demo);
        assert_eq!(snapshot.tunnels.len(), 4);
        assert!(snapshot.issues.iter().any(|i| i.kind == "loss"));
        let point = Point::of(&snapshot);
        assert_eq!(point.t.len(), 4);
        assert!(point.down > 0.0);
    }
}
