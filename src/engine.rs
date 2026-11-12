//! Authenticated reverse forwarding. Every task is owned by a enclosing JoinSet;
//! dropping `run` closes tunnels, listeners, and forwarded sockets.
use crate::{
    config::{ClientPath, Config, Listener, MapKind, Mode, decode_key},
    limits::{AcceptBackoff, PendingLimiter, RetryPause, jitter},
    stats::{Stats, report},
    transport::{self, SecureConnection},
    wire::{DATA_SIZE, Frame, StreamKind},
};
use anyhow::{Context, Result, anyhow, bail};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::{self, Instant},
};

mod control;
mod quality;
mod socks_udp;

/// Frames a sender may have in flight on a new stream before the receiver says more. Part of
/// the wire protocol: both ends start from it.
const CREDITS: usize = 16;
/// Largest window a receiver may open on one stream (frames). A protocol sanity bound; the
/// window actually used is the receiver's `stream_window` setting.
const MAX_WINDOW: usize = 4096;

/// Time limits taken from the configuration.
#[derive(Clone, Copy)]
struct Tuning {
    connect: Duration,
    open: Duration,
    udp_idle: Duration,
    /// `None` = idle TCP connections are never closed.
    tcp_idle: Option<Duration>,
    stream_queue: usize,
    /// Send a new connection's data without waiting for `Opened` (`stream_early_data`).
    early_data: bool,
}

impl Tuning {
    fn from_config(config: &Config) -> Self {
        Self {
            connect: Duration::from_secs(config.timeouts.connect_sec),
            open: Duration::from_secs(config.timeouts.open_sec),
            udp_idle: Duration::from_secs(config.timeouts.udp_idle_sec),
            tcp_idle: (config.timeouts.tcp_idle_sec > 0)
                .then(|| Duration::from_secs(config.timeouts.tcp_idle_sec)),
            stream_queue: config.queues.stream_frames,
            early_data: config.stream_early_data,
        }
    }
}

/// How a relay starts.
#[derive(Debug, Clone, Copy)]
enum Opening {
    /// The far side already confirmed the stream (`Opened` was received).
    Open,
    /// Early data: the far side is still connecting. It must answer `Opened` (or `Error`) within
    /// this time; data sent meanwhile waits in its stream queue.
    Pending(Duration),
}

impl Opening {
    fn for_new_stream(tuning: &Tuning) -> Self {
        Self::Pending(tuning.open)
    }
}

/// Fails when a pending stream was not confirmed in time; never completes otherwise.
async fn open_deadline(opening: Opening, opened: &AtomicBool) -> Result<()> {
    if let Opening::Pending(wait) = opening {
        time::sleep(wait).await;
        if !opened.load(Ordering::Acquire) {
            bail!("target open timeout");
        }
    }
    std::future::pending().await
}

struct StreamEntry {
    tx: mpsc::Sender<Frame>,
    credits: Arc<Semaphore>,
    /// The part of the memory budget this stream's wider window uses; given back when the entry
    /// is dropped, whether the stream ended or the whole session went away.
    reservation: Option<Reservation>,
}

/// Frames taken from `Stats::window_budget`, returned on drop.
struct Reservation {
    stats: Arc<Stats>,
    frames: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.stats.window_budget.release(self.frames);
    }
}

struct Session {
    tx: mpsc::Sender<Frame>,
    control: mpsc::Sender<Frame>,
    closed: watch::Sender<bool>,
    streams: Mutex<HashMap<u32, StreamEntry>>,
    alive: AtomicBool,
    next_id: AtomicU32,
    max_streams: usize,
    stream_queue: usize,
    /// Flow-control window this side opens for each stream it receives data on (frames).
    window: usize,
    stats: Arc<Stats>,
    /// The other server's identity (its static key).
    peer: Option<[u8; 32]>,
    /// When a frame last arrived (milliseconds on `clock()`). Shared with the dialing loop.
    heard: Arc<std::sync::atomic::AtomicU64>,
    /// When this side first sent something after the last frame arrived (`clock()`; 0 = not
    /// waiting for anything). Set by the writer task, cleared by the reader.
    waiting_since: Arc<std::sync::atomic::AtomicU64>,
    /// No answer for `2 × probe_sec` while waiting: new users are not sent to this session.
    suspect: AtomicBool,
    /// Told when a probe found the session dead: the session loop ends.
    unanswered: tokio::sync::Notify,
    /// Bytes of `Frame::Data` received on this session so far. Compared against sibling sessions
    /// of the same peer (`connection_pool` > 1) to find one that delivers far less than the
    /// others while still answering heartbeats (`Pool::evict_slow`).
    bytes_in: AtomicU64,
    /// `bytes_in` the last time `Pool::evict_slow` judged this session, and how many judged
    /// windows in a row it delivered far less than its siblings. Owned by the sweep task alone.
    slow_mark: AtomicU64,
    slow_strikes: AtomicU32,
    quality: Mutex<quality::Quality>,
}

/// What the dialing loop watches of a session it runs (see `run_slot`).
struct SessionWatch {
    /// `true` while the session is suspect.
    suspect: watch::Sender<bool>,
    heard: Arc<std::sync::atomic::AtomicU64>,
}

impl SessionWatch {
    fn new() -> Self {
        Self {
            suspect: watch::channel(false).0,
            heard: Arc::new(std::sync::atomic::AtomicU64::new(clock())),
        }
    }
}

/// How long a session has been waiting for any answer, judged against `probe` (`probe_sec`).
#[derive(Debug, PartialEq, Eq)]
enum Silence {
    /// Not waiting, or not for long.
    Fine,
    /// Waiting for `probe`: ask with a ping (any frame back counts).
    Probe,
    /// Waiting for `2 × probe`: no new users; the dialing side looks for a replacement.
    Suspect,
}

fn silence(waiting_since: u64, now: u64, probe: Duration) -> Silence {
    if waiting_since == 0 {
        return Silence::Fine;
    }
    let waited = now.saturating_sub(waiting_since);
    let probe = probe.as_millis() as u64;
    if waited >= 2 * probe {
        Silence::Suspect
    } else if waited >= probe {
        Silence::Probe
    } else {
        Silence::Fine
    }
}

/// Milliseconds since this program's first call; for `Session::heard`.
fn clock() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// The session ended because it did not answer a probe.
#[derive(Debug)]
struct Unanswered;
impl std::fmt::Display for Unanswered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the other server connected again and no longer answers on this session")
    }
}
impl std::error::Error for Unanswered {}

impl Session {
    fn register(&self, requested: Option<u32>) -> Result<(u32, mpsc::Receiver<Frame>)> {
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.alive.load(Ordering::Acquire) {
            bail!("tunnel disconnected");
        }
        if streams.len() >= self.max_streams {
            bail!("stream limit reached");
        }
        let id = match requested {
            Some(id) if id != 0 && !streams.contains_key(&id) => id,
            Some(_) => bail!("invalid or duplicate stream id"),
            None => loop {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                if id != 0 && !streams.contains_key(&id) {
                    break id;
                }
            },
        };
        // The queue must hold a full window plus the stream's control frames.
        let (tx, rx) = mpsc::channel(self.stream_queue.max(self.window + 4));
        streams.insert(
            id,
            StreamEntry {
                tx,
                credits: Arc::new(Semaphore::new(CREDITS)),
                reservation: None,
            },
        );
        self.stats.streams.fetch_add(1, Ordering::Relaxed);
        self.stats.streams_total.fetch_add(1, Ordering::Relaxed);
        Ok((id, rx))
    }

    async fn send(&self, frame: Frame) -> Result<()> {
        // EOF/Close/Open stay ordered behind stream data. Only out-of-band
        // credit and heartbeat frames may overtake queued data.
        let sender = if matches!(
            frame,
            Frame::Credit { .. } | Frame::Ping { .. } | Frame::Pong { .. }
        ) {
            &self.control
        } else {
            &self.tx
        };
        sender
            .send(frame)
            .await
            .map_err(|_| anyhow!("tunnel disconnected"))
    }

    async fn send_data(&self, id: u32, data: Vec<u8>) -> Result<()> {
        let credits = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&id)
            .map(|entry| entry.credits.clone())
            .context("stream closed")?;
        credits
            .acquire_owned()
            .await
            .context("stream closed")?
            .forget();
        self.send(Frame::Data { id, data }).await
    }

    fn grant(&self, id: u32, frames: u32) -> Result<()> {
        let entries = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = entries.get(&id) {
            if frames == 0 || frames as usize + entry.credits.available_permits() > MAX_WINDOW {
                bail!("invalid stream credit");
            }
            entry.credits.add_permits(frames as usize);
        }
        Ok(())
    }

    /// Lets the sender of a stream have `window` frames in flight instead of the initial
    /// `CREDITS`. Called once a stream is known at both ends. One stream's speed is at most
    /// window × 16 KiB per round trip, so a larger window is faster on long links.
    async fn open_window(&self, id: u32) -> Result<()> {
        // The wider window is what a slow user can leave queued in memory, so it is paid for
        // from the shared budget. When the budget is used up the stream keeps its initial window.
        let wanted = self.window.saturating_sub(CREDITS);
        let mut extra = self.stats.window_budget.reserve(wanted);
        if extra > 0 {
            let mut streams = self
                .streams
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match streams.get_mut(&id) {
                Some(entry) => {
                    entry.reservation = Some(Reservation {
                        stats: self.stats.clone(),
                        frames: extra,
                    });
                }
                None => {
                    // The stream is already gone.
                    self.stats.window_budget.release(extra);
                    return Ok(());
                }
            }
        }
        while extra > 0 {
            let frames = extra.min(16);
            self.send(Frame::Credit {
                id,
                frames: frames as u32,
            })
            .await?;
            extra -= frames;
        }
        Ok(())
    }

    fn remove(&self, id: u32) {
        if let Some(entry) = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&id)
        {
            entry.credits.close();
            self.stats.streams.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn deliver(&self, id: u32, frame: Frame) {
        let tx = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&id)
            .map(|entry| entry.tx.clone());
        if let Some(tx) = tx
            && tx.try_send(frame).is_err()
        {
            // A slow consumer must not block all other multiplexed streams.
            self.remove(id);
            let _ = self.tx.try_send(Frame::Close { id });
        }
    }
}

struct SessionGuard(Arc<Session>);
impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.alive.store(false, Ordering::Release);
        self.0.closed.send_replace(true);
        let mut streams = self
            .0
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for entry in streams.values() {
            entry.credits.close();
        }
        self.0
            .stats
            .streams
            .fetch_sub(streams.len(), Ordering::Relaxed);
        streams.clear();
        self.0.stats.sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

struct StreamGuard {
    session: Arc<Session>,
    id: u32,
}

/// A UDP datagram waiting to go into the tunnel. It holds one frame of the memory budget (a
/// datagram is at most one frame), given back when it has been sent or dropped.
struct QueuedDatagram {
    data: Vec<u8>,
    _held: Reservation,
}

/// Queues a UDP datagram for its conversation if the memory budget has room and the queue is not
/// full; otherwise drops it (UDP may drop) and counts it. Without this, every conversation's queue
/// (`queues.stream_frames` datagrams) sat outside `memory_budget_mb`.
fn queue_datagram(sender: &mpsc::Sender<QueuedDatagram>, data: &[u8], stats: &Arc<Stats>) {
    if stats.window_budget.reserve(1) == 0 {
        stats.udp_dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let datagram = QueuedDatagram {
        data: data.to_vec(),
        _held: Reservation {
            stats: stats.clone(),
            frames: 1,
        },
    };
    if sender.try_send(datagram).is_err() {
        stats.udp_dropped.fetch_add(1, Ordering::Relaxed);
    }
}
impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.session.remove(self.id);
        let _ = self.session.tx.try_send(Frame::Close { id: self.id });
    }
}

#[derive(Default)]
struct Pool {
    sessions: Mutex<Vec<Weak<Session>>>,
    turn: AtomicUsize,
    quality_steering: bool,
    quality_fresh_ms: u64,
}
impl Pool {
    fn insert(&self, session: &Arc<Session>) {
        let mut entries = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|entry| {
            entry
                .upgrade()
                .is_some_and(|s| s.alive.load(Ordering::Acquire))
        });
        entries.push(Arc::downgrade(session));
    }

    /// The other live sessions with the same peer as `session`.
    fn same_peer(&self, session: &Arc<Session>) -> Vec<Arc<Session>> {
        let Some(peer) = session.peer else {
            return Vec::new();
        };
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|other| {
                !Arc::ptr_eq(other, session)
                    && other.peer == Some(peer)
                    && other.alive.load(Ordering::Acquire)
            })
            .collect()
    }

    /// Whether the sessions are more than three quarters full of streams. Per-address limits are
    /// only enforced then: while there is room anybody may use it (many users behind one shared
    /// address are one address), and the last quarter is kept for addresses under their limit.
    fn crowded(&self) -> bool {
        let entries = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (mut used, mut capacity) = (0usize, 0usize);
        for session in entries.iter().filter_map(Weak::upgrade) {
            if session.alive.load(Ordering::Acquire) && !session.suspect.load(Ordering::Acquire) {
                used += session
                    .streams
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len();
                capacity += session.max_streams;
            }
        }
        capacity > 0 && used * 4 >= capacity * 3
    }

    fn pick(&self) -> Option<Arc<Session>> {
        let mut entries = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|entry| {
            entry
                .upgrade()
                .is_some_and(|s| s.alive.load(Ordering::Acquire))
        });
        if entries.is_empty() {
            return None;
        }
        let turn = self.turn.fetch_add(1, Ordering::Relaxed);
        let index = turn % entries.len();
        // Prefer a session with capacity, while retaining round-robin ordering. A suspect session
        // (no answer for a while) takes no new users.
        let mut candidates = (0..entries.len()).filter_map(|offset| {
            let session = entries[(index + offset) % entries.len()].upgrade()?;
            if session.suspect.load(Ordering::Acquire) {
                return None;
            }
            let available = session
                .streams
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
                < session.max_streams;
            available.then_some(session)
        });
        if !self.quality_steering || turn % 8 == 0 {
            return candidates.next();
        }
        let available: Vec<_> = candidates.collect();
        if self.quality_steering && turn % 8 != 0 {
            let now = clock();
            let mut best_by_peer = HashMap::<[u8; 32], u64>::new();
            for session in &available {
                if let Some(peer) = session.peer
                    && let Some(score) = session
                        .quality
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .score(now, self.quality_fresh_ms)
                {
                    best_by_peer
                        .entry(peer)
                        .and_modify(|best| *best = (*best).min(score))
                        .or_insert(score);
                }
            }
            return available
                .iter()
                .find(|session| {
                    let Some(peer) = session.peer else {
                        return true;
                    };
                    best_by_peer.get(&peer).is_none_or(|best| {
                        !session
                            .quality
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .avoid(*best, now, self.quality_fresh_ms)
                    })
                })
                .cloned()
                .or_else(|| available.first().cloned());
        }
        available.into_iter().next()
    }

    /// How many consecutive judged windows one of a peer's sessions may deliver far less than its
    /// siblings before it is closed. `evict_slow` is meant to run every `EVICT_SLOW_INTERVAL`.
    const SLOW_STRIKES: u32 = 3;
    /// A session moving less than this many bytes in one window is idle, not slow: it is left out
    /// of the comparison entirely rather than judged (as either a victim or part of what "typical"
    /// means). Without this, a session that has simply gone quiet for a while (its sender has
    /// nothing to send right now, or any other reason unrelated to the path) drags the computed
    /// "typical" share down to near its own near-zero number, which then unfairly condemns a
    /// genuinely active sibling sitting right next to that stale low bar.
    const SLOW_PER_SESSION_MIN_BYTES: u64 = 32 * 1024;

    /// Compares what each session of every peer with at least three sessions here that actually
    /// moved traffic this window (a pooled tunnel, `connection_pool` > 1, genuinely busy) delivered
    /// since the last call, and closes one that is persistently far behind its siblings' typical
    /// share, the same way `probe_older_sessions` already closes a stale one:
    /// `unanswered.notify_one()` ends the session cleanly and the dialing side's own retry logic
    /// reconnects it fresh. This does NOT use the `suspect` flag: a session carrying any traffic at
    /// all (just less than its share) keeps clearing `suspect` the moment the next frame arrives
    /// (`session.suspect.swap(false, ..)` on every received frame), so a soft mark here would be
    /// undone within milliseconds and never actually help — confirmed live on a real pooled fec-udp
    /// tunnel, where marking suspect only produced a "no new users / answers again" flap every
    /// judged window with no real effect.
    fn evict_slow(&self) {
        let mut groups: HashMap<[u8; 32], Vec<Arc<Session>>> = HashMap::new();
        for session in self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|s| s.alive.load(Ordering::Acquire))
        {
            if let Some(peer) = session.peer {
                groups.entry(peer).or_default().push(session);
            }
        }
        for group in groups.values() {
            let deltas: Vec<(&Arc<Session>, u64)> = group
                .iter()
                .map(|session| {
                    let now = session.bytes_in.load(Ordering::Relaxed);
                    let mark = session.slow_mark.swap(now, Ordering::Relaxed);
                    (session, now.saturating_sub(mark))
                })
                .collect();
            let active: Vec<(&Arc<Session>, u64)> = deltas
                .iter()
                .filter(|(_, delta)| *delta >= Self::SLOW_PER_SESSION_MIN_BYTES)
                .copied()
                .collect();
            if active.len() < 3 {
                // Too few genuinely busy siblings to compare fairly; do not let strikes carry over
                // (an idle session, or one that reconnected, should not inherit old strikes).
                for session in group {
                    session.slow_strikes.store(0, Ordering::Relaxed);
                }
                continue;
            }
            let mut sorted: Vec<u64> = active.iter().map(|(_, delta)| *delta).collect();
            sorted.sort_unstable();
            // The median, not the upper quartile that suits much larger pools: with a
            // small pool (3-4 sessions is a normal connection_pool size here) `len * 3 / 4` is the
            // single fastest session, not a representative "most sessions reach this" bar, and
            // compared every real session against its single busiest sibling.
            let typical = sorted[sorted.len() / 2];
            for (session, delta) in &active {
                // Under a quarter of the group's median, not under half: real traffic is bursty
                // (new streams land on a session round-robin, not a steady rate), so a session
                // can land legitimately behind the pack for a window or two without being stuck.
                if typical == 0 || 4 * delta >= typical {
                    session.slow_strikes.store(0, Ordering::Relaxed);
                    continue;
                }
                let strikes = session.slow_strikes.fetch_add(1, Ordering::Relaxed) + 1;
                if strikes >= Self::SLOW_STRIKES {
                    session.slow_strikes.store(0, Ordering::Relaxed);
                    tracing::info!(
                        delivered = delta,
                        typical,
                        "one session of a pooled tunnel delivers far less than its siblings for too long; closing it so it reconnects fresh"
                    );
                    session.unanswered.notify_one();
                }
            }
        }
    }
}

/// How often `Pool::evict_slow` judges a listener's pooled sessions.
const EVICT_SLOW_INTERVAL: Duration = Duration::from_secs(2);

pub async fn run(config: Config) -> Result<()> {
    run_with_stats(config, Arc::new(Stats::default())).await
}

/// Tells the other server that this side is stopping, then keeps `engine` (the running tunnel)
/// going for up to `wait` so the notice leaves the machine. The other side then drops its sessions
/// at once and reconnects as soon as this side is back, instead of after its dead timeout.
pub async fn say_goodbye<F: std::future::Future>(
    stats: &Stats,
    wait: Duration,
    engine: std::pin::Pin<&mut F>,
) {
    let told = stats.farewell.send();
    if told == 0 || wait.is_zero() {
        return;
    }
    tracing::info!(
        sessions = told,
        "told the other server that this one is stopping"
    );
    let _ = time::timeout(wait, engine).await;
}

/// Like `run`, but the caller keeps a handle to the live counters.
pub async fn run_with_stats(config: Config, stats: Arc<Stats>) -> Result<()> {
    config.validate()?;
    crate::carrier::set_tcp_congestion(&config.tcp_congestion);
    if config.tun.is_some() {
        #[cfg(target_os = "linux")]
        return crate::tun_device::run(config, stats).await;
        #[cfg(not(target_os = "linux"))]
        bail!("TUN mode requires Linux");
    }
    run_forwarding(config, stats).await
}

/// Runs normal authenticated forwarding, including the TCP overlay on a TUN.
pub(crate) async fn run_forwarding(config: Config, stats: Arc<Stats>) -> Result<()> {
    config.validate()?;
    if config.tun.is_some() {
        bail!("forwarding overlay must not contain TUN configuration");
    }
    let private = config.private_key()?;
    let config = Arc::new(config);
    let gaming=if config.gaming.enabled(){Some(crate::gaming::Hub::start(&config).await?)}else{None};
    let mut tasks = JoinSet::new();
    stats.start();
    let (budget_frames, automatic) = crate::stats::budget_frames(config.memory_budget_mb);
    stats.window_budget.set_limit(budget_frames);
    tracing::info!(
        budget_mib = budget_frames / crate::stats::FRAMES_PER_MIB,
        automatic,
        "memory budget for flow-control windows"
    );
    let control_path = std::env::var_os("EZTUNNEL_CONTROL").map(std::path::PathBuf::from);
    if config.stats_interval_sec > 0 {
        let every = Duration::from_secs(config.stats_interval_sec);
        let stats = stats.clone();
        tasks.spawn(async move {
            report(stats, every).await;
            Ok(())
        });
    }
    match config.mode {
        Mode::Server => {
            let all = Arc::new(Pool {
                quality_steering: config.path_quality_steering,
                quality_fresh_ms: config.heartbeat_sec.saturating_mul(3000).max(1000),
                ..Pool::default()
            });
            let slots = Arc::new(Semaphore::new(config.max_connections));
            let pending =
                PendingLimiter::new(config.max_pending_handshakes, config.max_pending_per_ip);
            // How many forwarded connections one source address may hold open (all maps and
            // SOCKS5 together); the global part is unlimited.
            let users = PendingLimiter::new(
                Semaphore::MAX_PERMITS,
                match config.max_streams_per_ip {
                    0 => usize::MAX,
                    limit => limit,
                },
            );
            if let Some(path) = control_path.clone() {
                let (all, stats, tuning) =
                    (all.clone(), stats.clone(), Tuning::from_config(&config));
                let gaming=gaming.clone();
                tasks.spawn(async move { control::serve(&path, Some(all), stats, tuning,gaming).await });
            }
            for listener in config.listeners.clone() {
                tasks.spawn(server_listener(
                    listener,
                    config.clone(),
                    private.clone(),
                    all.clone(),
                    slots.clone(),
                    pending.clone(),
                    users.clone(),
                    stats.clone(),
                    gaming.clone(),
                ));
            }
            if let Some(addr) = &config.socks5 {
                tasks.spawn(socks_listener(
                    addr.clone(),
                    all,
                    users.clone(),
                    config.max_streams,
                    Tuning::from_config(&config),
                    stats.clone(),
                    gaming.clone(),
                ));
            }
        }
        Mode::Client => {
            if let Some(path) = control_path.clone() {
                let (stats, tuning) = (stats.clone(), Tuning::from_config(&config));
                let gaming=gaming.clone();
                tasks.spawn(async move { control::serve(&path, None, stats, tuning,gaming).await });
            }
            let slots = Arc::new(Semaphore::new(config.max_connections));
            let pending =
                PendingLimiter::new(config.max_pending_handshakes, config.max_pending_per_ip);
            for path in &config.paths {
                if config.server_dials {
                    tasks.spawn(client_reverse_listener(
                        path.clone(),
                        config.clone(),
                        private.clone(),
                        slots.clone(),
                        pending.clone(),
                        stats.clone(),
                    ));
                    continue;
                }
                for _ in 0..path.connection_pool {
                    tasks.spawn(client_path(
                        path.clone(),
                        config.clone(),
                        private.clone(),
                        stats.clone(),
                    ));
                }
            }
        }
    }
    let result = tasks
        .join_next()
        .await
        .context("no tunnel tasks configured")?;
    result.context("tunnel task panicked")??;
    bail!("tunnel task exited unexpectedly")
}

#[allow(clippy::too_many_arguments)]
async fn server_listener(
    listener: Listener,
    config: Arc<Config>,
    private: zeroize::Zeroizing<[u8; 32]>,
    all: Arc<Pool>,
    slots: Arc<Semaphore>,
    pending: Arc<PendingLimiter>,
    users: Arc<PendingLimiter>,
    stats: Arc<Stats>,
    gaming: Option<Arc<crate::gaming::Hub>>,
) -> Result<()> {
    let mut socket = if config.server_dials {
        None
    } else {
        Some(
            crate::kcp_carrier::Acceptor::bind(&listener)
                .await
                .with_context(|| format!("bind tunnel listener {}", listener.addr))?,
        )
    };
    let allowed: Vec<[u8; 32]> = config
        .peer_public_keys
        .iter()
        .map(|key| decode_key(key))
        .collect::<Result<_>>()?;
    let allowed = Arc::new(allowed);
    let local = Arc::new(Pool {
        quality_steering: config.path_quality_steering,
        quality_fresh_ms: config.heartbeat_sec.saturating_mul(3000).max(1000),
        ..Pool::default()
    });
    let mut maps = JoinSet::new();
    for map in listener.maps.clone() {
        match map.kind {
            MapKind::Tcp => {
                maps.spawn(tcp_map(
                    map.bind,
                    map.target,
                    map.proxy_protocol,
                    local.clone(),
                    users.clone(),
                    config.max_streams,
                    Tuning::from_config(&config),
                    stats.clone(),
                ));
            }
            MapKind::Udp => {
                maps.spawn(udp_map(
                    map.bind,
                    map.target,
                    local.clone(),
                    users.clone(),
                    config.max_streams,
                    Tuning::from_config(&config),
                    stats.clone(),
                    gaming.clone(),
                ));
            }
        }
    }
    let mut connections = JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    // Tied to this listener's own loop, not a detached task: it must stop exactly when this
    // listener does, not outlive it (a process that creates many short-lived listeners, like the
    // transport checker, would otherwise accumulate one orphaned sweep per case, each still
    // locking a Pool nothing uses anymore).
    let mut evict_tick = time::interval(EVICT_SLOW_INTERVAL);
    evict_tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    if config.server_dials {
        for _ in 0..listener.connection_pool {
            connections.spawn(server_reverse_path(
                listener.clone(),
                config.clone(),
                private.clone(),
                allowed.clone(),
                local.clone(),
                all.clone(),
                slots.clone(),
                stats.clone(),
            ));
        }
    }
    tracing::info!(address = %listener.addr, "tunnel listener ready");
    loop {
        tokio::select! {
            accepted = async { match &mut socket { Some(socket) => socket.accept().await, None => std::future::pending().await } } => {
                let stream = match accepted {
                    Ok(stream) => { backoff.succeeded(); stream }
                    Err(error) => { backoff.failed("tunnel accept", error).await?; continue; }
                };
                // Stopping: the goodbye went out; a session started now would die with this side.
                if stats.farewell.stopping() { continue; }
                // A connection that has not proved its identity only waits in the pending
                // pool; it never takes a slot reserved for authenticated sessions.
                let peer = stream.peer_ip();
                let Some(waiting) = pending.try_enter(peer) else {
                    tracing::debug!("too many unauthenticated connections; dropping a new one");
                    stats.reject_connection();
                    continue;
                };
                let (config, allowed, local, all, slots, stats) = (config.clone(), allowed.clone(), local.clone(), all.clone(), slots.clone(), stats.clone());
                let listener = listener.clone();
                let private = private.clone();
                connections.spawn(async move {
                    let secure = match transport::accept_listener(stream, &listener, &private, &allowed, Duration::from_secs(config.timeouts.handshake_sec)).await {
                        Ok(secure) => secure,
                        Err(error) => { stats.reject_connection(); return Err(error); }
                    };
                    // V02: the slot is taken only after liveness proof (see Admission); until
                    // then the connection stays inside the pending-handshake limits.
                    let admission = Admission { slots, pending: Some(waiting) };
                    let announce: Announce =
                        Box::new(move || tracing::info!(peer = ?peer, "tunnel peer authenticated"));
                    session_loop_admitted(secure, config, Some((local, all)), stats, Some(announce), None, Some(admission)).await
                });
            }
            _ = evict_tick.tick() => {
                if !config.path_quality_steering{local.evict_slow();}
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(result) = result { match result {
                    Ok(Ok(())) => {},
                    Ok(Err(error)) => tracing::debug!(%error, "tunnel session closed"),
                    Err(error) => tracing::warn!(%error, "tunnel session task failed"),
                }}
            }
            result = maps.join_next(), if !maps.is_empty() => {
                result.context("map task missing")?.context("map task panicked")??;
                bail!("map listener stopped");
            }
        }
    }
}

// Each argument is a distinct piece of shared server state; bundling them would only rename them.
#[allow(clippy::too_many_arguments)]
async fn server_reverse_path(
    listener: Listener,
    config: Arc<Config>,
    private: zeroize::Zeroizing<[u8; 32]>,
    peers: Arc<Vec<[u8; 32]>>,
    local: Arc<Pool>,
    all: Arc<Pool>,
    slots: Arc<Semaphore>,
    stats: Arc<Stats>,
) -> Result<()> {
    let _permit = slots
        .acquire_owned()
        .await
        .context("connection slots closed")?;
    let dead = Duration::from_secs(config.dead_timeout_sec);
    let mut retry = RetryPause::new(1, config.timeouts.retry_max_sec, dead);
    loop {
        let started = Instant::now();
        match transport::connect_responder(
            &listener,
            &private,
            &peers,
            config.timeouts.server_dial_sec,
        )
        .await
        {
            Ok(secure) => {
                let ended = run_slot(
                    secure,
                    || {
                        transport::connect_responder(
                            &listener,
                            &private,
                            &peers,
                            config.timeouts.server_dial_sec,
                        )
                    },
                    |secure, watch| {
                        let address = listener.addr.clone();
                        let announce: Announce = Box::new(move || {
                            tracing::info!(address = %address, "reverse tunnel authenticated")
                        });
                        session_loop(
                            secure,
                            config.clone(),
                            Some((local.clone(), all.clone())),
                            stats.clone(),
                            Some(announce),
                            Some(watch),
                        )
                    },
                    Duration::from_secs(1),
                )
                .await;
                if let Err(error) = ended {
                    if crate::farewell::peer_stopped(&error) {
                        retry.peer_stopped();
                    }
                    tracing::debug!(%error, "reverse session closed");
                }
            }
            Err(error) => tracing::debug!(%error, "reverse dial failed"),
        }
        time::sleep(jitter(retry.next(started.elapsed(), dead))).await;
    }
}

async fn client_reverse_listener(
    path: ClientPath,
    config: Arc<Config>,
    private: zeroize::Zeroizing<[u8; 32]>,
    slots: Arc<Semaphore>,
    pending: Arc<PendingLimiter>,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut acceptor = crate::kcp_carrier::Acceptor::bind(&path.listen_config()).await?;
    let mut sessions = JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    loop {
        tokio::select! {
            incoming = acceptor.accept() => {
                let incoming = match incoming {
                    Ok(incoming) => { backoff.succeeded(); incoming }
                    Err(error) => { backoff.failed("tunnel accept", error).await?; continue; }
                };
                if stats.farewell.stopping() { continue; }
                let Some(waiting) = pending.try_enter(incoming.peer_ip()) else {
                    tracing::debug!("too many unauthenticated connections; dropping a new one");
                    stats.reject_connection();
                    continue;
                };
                let (path, config, slots, stats) = (path.clone(), config.clone(), slots.clone(), stats.clone());
                let private = private.clone();
                sessions.spawn(async move {
                    let secure = match transport::accept_initiator(incoming, &path, &private).await {
                        Ok(secure) => secure,
                        Err(error) => { stats.reject_connection(); return Err(error); }
                    };
                    let admission = Admission { slots, pending: Some(waiting) };
                    let announce: Announce =
                        Box::new(|| tracing::info!("tunnel peer authenticated"));
                    session_loop_admitted(secure, config, None, stats, Some(announce), None, Some(admission)).await
                });
            }
            result = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(result) = result { match result {
                    Ok(Ok(())) => {},
                    Ok(Err(error)) => tracing::debug!(%error, "reverse client session closed"),
                    Err(error) => tracing::warn!(%error, "reverse client session task failed"),
                }}
            }
        }
    }
}

async fn client_path(
    path: ClientPath,
    config: Arc<Config>,
    private: zeroize::Zeroizing<[u8; 32]>,
    stats: Arc<Stats>,
) -> Result<()> {
    let dead = Duration::from_secs(config.dead_timeout_sec);
    let mut retry = RetryPause::new(
        path.retry_interval.clamp(1, 30),
        config.timeouts.retry_max_sec,
        dead,
    );
    let pause = Duration::from_secs(path.retry_interval.clamp(1, 30));
    loop {
        let started = Instant::now();
        match transport::connect_path(&path, &private).await {
            Ok(connection) => {
                tracing::info!(address = %path.addr, "authenticated tunnel connected");
                let ended = run_slot(
                    connection,
                    || transport::connect_path(&path, &private),
                    |connection, watch| {
                        session_loop(
                            connection,
                            config.clone(),
                            None,
                            stats.clone(),
                            None,
                            Some(watch),
                        )
                    },
                    pause,
                )
                .await;
                if let Err(error) = ended {
                    if crate::farewell::peer_stopped(&error) {
                        retry.peer_stopped();
                    }
                    tracing::debug!(%error, "tunnel connection ended");
                }
            }
            Err(error) => tracing::debug!(address = %path.addr, %error, "tunnel connection failed"),
        }
        time::sleep(jitter(retry.next(started.elapsed(), dead))).await;
    }
}

/// Runs the sessions of one pool slot of the dialing side. When the running session turns suspect
/// (it has had no answer for `2 × probe_sec`), a fresh connection is dialed while it keeps going.
/// If the fresh one works and the old one is still silent, the other server is alive but no
/// longer answers on the old one (it crashed and came back, or that session's path is stuck):
/// the old session ends and the new one takes the slot. If the old one answers first, the fresh
/// connection is dropped. If dialing fails, it is tried again every `pause` while the old session
/// stays suspect (its dead timeout still applies). Returns how the last session ended.
async fn run_slot<D, DF, R, RF>(
    first: SecureConnection,
    dial: D,
    run: R,
    pause: Duration,
) -> Result<()>
where
    D: Fn() -> DF,
    DF: std::future::Future<Output = Result<SecureConnection>>,
    R: Fn(SecureConnection, SessionWatch) -> RF,
    RF: std::future::Future<Output = Result<()>>,
{
    let mut connection = first;
    loop {
        let watch = SessionWatch::new();
        let mut suspect = watch.suspect.subscribe();
        let heard = watch.heard.clone();
        let session = run(connection, watch);
        tokio::pin!(session);
        let replacement = loop {
            tokio::select! {
                result = &mut session => return result,
                closed = async { suspect.wait_for(|suspect| *suspect).await.is_err() } => {
                    if closed {
                        // The session is ending; its result follows.
                        return session.await;
                    }
                }
            }
            let since = clock();
            let found = tokio::select! {
                result = &mut session => return result,
                found = async {
                    loop {
                        if let Ok(fresh) = dial().await {
                            return (heard.load(Ordering::Relaxed) < since).then_some(fresh);
                        }
                        if heard.load(Ordering::Relaxed) >= since {
                            return None;
                        }
                        time::sleep(jitter(pause)).await;
                    }
                } => found,
            };
            if let Some(fresh) = found {
                break fresh;
            }
            // The old session answered meanwhile: keep it, and wait for the next suspicion.
            tokio::select! {
                result = &mut session => return result,
                _ = async { suspect.wait_for(|suspect| !*suspect).await.is_err() } => {}
            }
        };
        tracing::info!("a tunnel session stopped answering; replaced it with a new connection");
        connection = replacement;
    }
}

/// Runs one authenticated session and logs how it ended, so an operator can see why a tunnel
/// reconnects without turning on debug logging.
/// What a side that answered a connection logs once the peer has proved itself (see `session_body`).
type Announce = Box<dyn FnOnce() + Send>;

async fn session_loop(
    connection: SecureConnection,
    config: Arc<Config>,
    pools: Option<(Arc<Pool>, Arc<Pool>)>,
    stats: Arc<Stats>,
    announce: Option<Announce>,
    watch: Option<SessionWatch>,
) -> Result<()> {
    session_loop_admitted(connection, config, pools, stats, announce, watch, None).await
}

/// V02: an answering side's `max_connections` slot. A replayed IK first message completes
/// the handshake but can never send a record under the fresh session keys, so the slot is
/// acquired only when the first authenticated record arrives. Until then the connection
/// keeps its pending-handshake guard and is bounded by `max_pending_handshakes`/per-IP and
/// by `handshake_sec`, exactly like a connection that has not finished its handshake.
/// No wire change: the early heartbeat both sides already send provides that record.
struct Admission {
    slots: Arc<Semaphore>,
    pending: Option<crate::limits::PendingGuard>,
}

impl Admission {
    /// The slot once liveness is proved, or `None` when every slot is in use.
    fn admit(mut self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let slot = self.slots.clone().try_acquire_owned().ok();
        self.pending.take();
        slot
    }
}

async fn session_loop_admitted(
    connection: SecureConnection,
    config: Arc<Config>,
    pools: Option<(Arc<Pool>, Arc<Pool>)>,
    stats: Arc<Stats>,
    announce: Option<Announce>,
    watch: Option<SessionWatch>,
    admission: Option<Admission>,
) -> Result<()> {
    let started = Instant::now();
    let result = session_body(connection, config, pools, stats, announce, watch, admission).await;
    let lasted = started.elapsed().as_secs();
    match &result {
        Ok(()) => tracing::info!(seconds = lasted, "tunnel session closed"),
        Err(error) => tracing::info!(seconds = lasted, reason = %error, "tunnel session ended"),
    }
    result
}

/// `announce` is given by a side that answered the connection (it did not dial). The Noise
/// handshake alone does not prove that the peer is alive: its first message can be replayed by
/// anyone who recorded it. So such a session only joins the pools users are sent to, and only
/// counts as authenticated, once the peer has sent a record that decrypts under the session keys,
/// which a replay cannot do. If nothing arrives within `handshake_sec` the session is dropped.
async fn session_body(
    connection: SecureConnection,
    config: Arc<Config>,
    pools: Option<(Arc<Pool>, Arc<Pool>)>,
    stats: Arc<Stats>,
    announce: Option<Announce>,
    watch: Option<SessionWatch>,
    mut admission: Option<Admission>,
) -> Result<()> {
    let mut _slot = None;
    let peer = connection.peer_key();
    let watch = watch.unwrap_or_else(SessionWatch::new);
    let waiting_since = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (mut reader, mut writer) = connection.split();
    let session_queue = config.queues.session_frames;
    let (tx, mut outgoing) = mpsc::channel(session_queue);
    let (control, mut controls) = mpsc::channel(session_queue);
    let (closed, _) = watch::channel(false);
    let session = Arc::new(Session {
        tx,
        control,
        closed,
        streams: Mutex::new(HashMap::new()),
        alive: AtomicBool::new(true),
        next_id: AtomicU32::new(1),
        max_streams: config.max_streams,
        stream_queue: config.queues.stream_frames,
        window: config.stream_window,
        stats: stats.clone(),
        peer,
        heard: watch.heard.clone(),
        waiting_since: waiting_since.clone(),
        suspect: AtomicBool::new(false),
        unanswered: tokio::sync::Notify::new(),
        bytes_in: AtomicU64::new(0),
        slow_mark: AtomicU64::new(0),
        slow_strikes: AtomicU32::new(0),
        quality: Mutex::new(quality::Quality::default()),
    });
    stats.sessions.fetch_add(1, Ordering::Relaxed);
    stats.sessions_total.fetch_add(1, Ordering::Relaxed);
    stats.farewell.register(&session.control);
    let _guard = SessionGuard(session.clone());
    let server = pools.is_some();
    let mut unconfirmed = announce;
    let mut deferred = None;
    let probe = Duration::from_secs(config.timeouts.probe_sec);
    if let Some((local, all)) = pools {
        if unconfirmed.is_some() {
            deferred = Some((local, all));
        } else {
            local.insert(&session);
            all.insert(&session);
            probe_older_sessions(&all, &session, probe);
        }
    }
    let confirm_deadline = time::sleep(Duration::from_secs(config.timeouts.handshake_sec));
    tokio::pin!(confirm_deadline);
    let (received, mut incoming) = mpsc::channel(session_queue);
    let tuning = Tuning::from_config(&config);
    let dead = Duration::from_secs(config.dead_timeout_sec);
    let mut io = JoinSet::new();
    io.spawn(async move {
        loop {
            // Dedicated reader: never cancel a partially read encrypted frame.
            let frame = reader.recv().await?;
            if received.send(frame).await.is_err() {
                return Ok::<(), anyhow::Error>(());
            }
        }
    });
    io.spawn(async move {
        loop {
            let frame = tokio::select! {
                biased;
                frame = controls.recv() => frame,
                frame = outgoing.recv() => frame,
            };
            let Some(frame) = frame else {
                return Ok::<(), anyhow::Error>(());
            };
            // Waiting for an answer from now on, unless already waiting.
            let _ = waiting_since.compare_exchange(
                0,
                clock().max(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            time::timeout(dead, writer.send(&frame))
                .await
                .context("tunnel write timeout")??;
        }
    });
    let mut streams = JoinSet::new();
    let mut heartbeat = time::interval(Duration::from_secs(config.heartbeat_sec));
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut last_received = Instant::now();
    // Set once per silent period so the log gets one warning, not one per heartbeat.
    let mut silence_reported = false;
    // Whether this session has heard anything at all: silence after traffic means the other
    // server stopped or the link went down, silence from the start looks like a filter.
    let mut heard_any = false;
    let mut nonce = 0u64;
    // Heartbeats waiting for an answer.
    let mut pings: std::collections::VecDeque<PendingPing> = std::collections::VecDeque::new();
    // A second, quick heartbeat shortly after the first one. A carrier that is blocked right
    // after the handshake still passes the first packets, so a single answer proves little; two
    // answers within a few seconds are what the manager's connection check relies on.
    let early = time::sleep(Duration::from_millis(
        config.heartbeat_sec.saturating_mul(500).min(2000),
    ));
    tokio::pin!(early);
    let mut early_sent = false;
    // Checks how long this session has waited for an answer (`silence`).
    let mut silence_check = time::interval(Duration::from_millis(500));
    silence_check.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut probed = false;
    loop {
        tokio::select! {
            frame = incoming.recv() => {
                let frame = frame.context("tunnel reader closed")?;
                if crate::farewell::is_goodbye(&frame) {
                    return Err(crate::farewell::PeerStopped.into());
                }
                last_received = Instant::now();
                session.heard.store(clock(), Ordering::Relaxed);
                session.waiting_since.store(0, Ordering::Relaxed);
                if session.suspect.swap(false, Ordering::AcqRel) {
                    watch.suspect.send_replace(false);
                    tracing::info!("the other server answers on this session again");
                }
                silence_reported = false;
                heard_any = true;
                if let Some(admission) = admission.take() {
                    match admission.admit() {
                        Some(slot) => _slot = Some(slot),
                        None => {
                            tracing::warn!("connection limit reached; rejecting an authenticated peer");
                            session.stats.reject_connection();
                            return Ok(());
                        }
                    }
                }
                if let Some(announce) = unconfirmed.take() {
                    if let Some((local, all)) = deferred.take() {
                        local.insert(&session);
                        all.insert(&session);
                        probe_older_sessions(&all, &session, probe);
                    }
                    announce();
                }
                match frame {
                    Frame::Ping { nonce } => { let _ = session.control.try_send(Frame::Pong { nonce }); }
                    Frame::Pong { nonce } => {
                        if let Some(index) = pings.iter().position(|ping| ping.nonce == nonce) {
                            if let Some(ping) = pings.remove(index) {
                                if ping.counted_lost {
                                    session.stats.pings_lost.fetch_sub(1, Ordering::Relaxed);
                                }
                                session.stats.record_rtt(ping.sent_at.elapsed());
                                session.quality.lock().unwrap_or_else(|e|e.into_inner()).observe(ping.sent_at.elapsed(),clock());
                            }
                            session.stats.pongs.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Frame::Credit { id, frames } => session.grant(id, frames)?,
                    Frame::Open { id, kind, target, proxy } => {
                        if server { bail!("client attempted to open a reverse stream"); }
                        if session.streams.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains_key(&id) { bail!("duplicate stream id"); }
                        if streams.len() >= config.max_streams {
                            let _ = session.tx.try_send(Frame::Error { id, message: "stream capacity exhausted".into() });
                            continue;
                        }
                        if let Some((download, bytes)) = control::speedtest_target(&target) {
                            match session.register(Some(id)) {
                                Ok((_, rx)) => {
                                    let session = session.clone();
                                    streams.spawn(async move {
                                        let _guard = StreamGuard { session: session.clone(), id };
                                        if let Err(error) = control::answer_speedtest(session.clone(), id, rx, download, bytes).await {
                                            tracing::debug!(%error, "speed test stream ended");
                                        }
                                    });
                                }
                                Err(_) => { let _ = session.tx.try_send(Frame::Error { id, message: "invalid stream or capacity exhausted".into() }); }
                            }
                            continue;
                        }
                        if !config.allowed_targets.iter().any(|allowed| target_allowed(allowed, &target)) {
                            // Logged on the 1st, 2nd, 4th, 8th ... refusal: visible, but a peer
                            // that keeps asking cannot flood the log.
                            let count = session.stats.targets_denied.fetch_add(1, Ordering::Relaxed) + 1;
                            if count.is_power_of_two() {
                                tracing::warn!(
                                    target = %target.chars().take(100).collect::<String>(),
                                    refused = count,
                                    "the other server asked for a destination that allowed_targets does not list; refused"
                                );
                            }
                            let _ = session.tx.try_send(Frame::Error { id, message: "target not allowed".into() });
                            continue;
                        }
                        match session.register(Some(id)) {
                            Ok((_, rx)) => {
                                let session = session.clone();
                                streams.spawn(async move {
                                    let _guard = StreamGuard { session: session.clone(), id };
                                    if let Err(error) = close_stream(&session, id, target_stream(&session, id, kind, &target, proxy, rx, tuning)).await {
                                        tracing::debug!(%error, "target stream ended");
                                        let _ = session.tx.try_send(Frame::Error { id, message: "target unavailable".into() });
                                    }
                                });
                            }
                            Err(_) => { let _ = session.tx.try_send(Frame::Error { id, message: "invalid stream or capacity exhausted".into() }); }
                        }
                    }
                    Frame::Opened { id } => session.deliver(id, Frame::Opened { id }),
                    Frame::Data { id, data } => {
                        session.bytes_in.fetch_add(data.len() as u64, Ordering::Relaxed);
                        session.deliver(id, Frame::Data { id, data });
                    }
                    Frame::Eof { id } => session.deliver(id, Frame::Eof { id }),
                    Frame::Close { id } => session.deliver(id, Frame::Close { id }),
                    Frame::Error { id, message } => session.deliver(id, Frame::Error { id, message }),
                }
            }
            _ = heartbeat.tick() => {
                if last_received.elapsed() >= dead { bail!("tunnel heartbeat timeout"); }
                // Each side pings every heartbeat, so an authenticated session that hears
                // nothing for two heartbeats is almost always being blocked after the
                // handshake. Say so now instead of after the dead timeout. The manager
                // looks for this exact text.
                if !silence_reported && last_received.elapsed() >= Duration::from_secs(config.heartbeat_sec.saturating_mul(2)) {
                    silence_reported = true;
                    let seconds = last_received.elapsed().as_secs();
                    if heard_any {
                        tracing::warn!(
                            seconds,
                            "no traffic from the other server; it may have stopped or restarted, or the link is down"
                        );
                    } else {
                        tracing::warn!(
                            seconds,
                            "no traffic from the other server; a filter between the servers may be blocking this carrier after the handshake"
                        );
                    }
                }
                mark_lost_pings(&mut pings, Duration::from_secs(config.heartbeat_sec), &session.stats.pings_lost);
                send_heartbeat(&session, &mut nonce, &mut pings);
            }
            _ = &mut confirm_deadline, if unconfirmed.is_some() => {
                tracing::warn!(
                    seconds = config.timeouts.handshake_sec,
                    "no traffic from the other server; a filter between the servers may be blocking this carrier after the handshake"
                );
                bail!("the peer sent nothing after the handshake");
            }
            _ = &mut early, if !early_sent => {
                early_sent = true;
                send_heartbeat(&session, &mut nonce, &mut pings);
            }
            () = session.unanswered.notified() => {
                return Err(Unanswered.into());
            }
            _ = silence_check.tick() => {
                match silence(session.waiting_since.load(Ordering::Relaxed), clock(), probe) {
                    Silence::Fine => probed = false,
                    Silence::Probe => {
                        if !probed {
                            probed = true;
                            // A nonce no heartbeat uses; any frame back proves life.
                            let _ = session.control.try_send(Frame::Ping { nonce: u64::MAX });
                        }
                    }
                    Silence::Suspect => {
                        if !session.suspect.swap(true, Ordering::AcqRel) {
                            watch.suspect.send_replace(true);
                            tracing::info!(
                                seconds = 2 * probe.as_secs(),
                                "no answer from the other server on this session; no new users go to it"
                            );
                        }
                    }
                }
            }
            result = io.join_next() => {
                result.context("tunnel I/O tasks exited")?.context("tunnel I/O task panicked")??;
                return Ok(());
            }
            result = streams.join_next(), if !streams.is_empty() => {
                if let Some(Err(error)) = result { tracing::warn!(%error, "target stream task failed"); }
            }
        }
    }
}

/// A new session from a peer that already has sessions here: a peer that crashed (or lost its
/// network) and came back dials new sessions at once, while its old ones look alive here until
/// their dead timeout, and users sent to them wait in vain. So every older session of that peer
/// gets a ping now; one that hears nothing (any frame counts) within `probe` is ended. A healthy
/// one answers and stays. Nothing new on the wire: an extra ping is answered by every version.
fn probe_older_sessions(pool: &Pool, session: &Arc<Session>, probe: Duration) {
    for older in pool.same_peer(session) {
        tokio::spawn(async move {
            let asked = clock();
            // A nonce no heartbeat uses; the answer is not matched, any frame proves life.
            let _ = older.control.try_send(Frame::Ping { nonce: u64::MAX });
            let mut closed = older.closed.subscribe();
            tokio::select! {
                () = time::sleep(probe) => {}
                _ = closed.wait_for(|closed| *closed) => return,
            }
            if older.heard.load(Ordering::Relaxed) < asked && older.alive.load(Ordering::Acquire) {
                tracing::info!(
                    seconds = probe.as_secs(),
                    "the other server connected again; closing one of its older sessions that no longer answers"
                );
                older.unanswered.notify_one();
            }
        });
    }
}

/// A heartbeat waiting for its answer.
struct PendingPing {
    nonce: u64,
    sent_at: Instant,
    /// Already added to `Stats::pings_lost` (it stayed unanswered for a whole interval).
    counted_lost: bool,
}

/// Counts heartbeats that have waited longer than `after` as lost, once each. A heartbeat that
/// is merely in flight is not a loss, so the live loss figure does not flicker.
fn mark_lost_pings(
    pings: &mut std::collections::VecDeque<PendingPing>,
    after: Duration,
    lost: &std::sync::atomic::AtomicU64,
) {
    for ping in pings.iter_mut() {
        if !ping.counted_lost && ping.sent_at.elapsed() >= after {
            ping.counted_lost = true;
            lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Sends one heartbeat and remembers it so its answer can be timed.
fn send_heartbeat(
    session: &Session,
    nonce: &mut u64,
    pings: &mut std::collections::VecDeque<PendingPing>,
) {
    *nonce = nonce.wrapping_add(1);
    if session
        .control
        .try_send(Frame::Ping { nonce: *nonce })
        .is_ok()
    {
        if pings.len() == 8 {
            pings.pop_front();
        }
        pings.push_back(PendingPing {
            nonce: *nonce,
            sent_at: Instant::now(),
            counted_lost: false,
        });
        session.stats.pings.fetch_add(1, Ordering::Relaxed);
    }
}

/// `*` allows everything, `host:*` any port on that host, otherwise the text must match exactly.
/// Host names are case-insensitive (DNS), so `Example.com:443` allows `example.com:443`.
pub(crate) fn target_allowed(allowed: &str, target: &str) -> bool {
    if allowed == "*" || allowed.eq_ignore_ascii_case(target) {
        return true;
    }
    match (allowed.strip_suffix(":*"), target.rsplit_once(':')) {
        (Some(host), Some((target_host, _))) => host.eq_ignore_ascii_case(target_host),
        _ => false,
    }
}

async fn await_open(rx: &mut mpsc::Receiver<Frame>, wait: Duration) -> Result<()> {
    match time::timeout(wait, rx.recv())
        .await
        .context("target open timeout")?
    {
        Some(Frame::Opened { .. }) => Ok(()),
        Some(Frame::Error { message, .. }) => bail!("target rejected: {message}"),
        _ => bail!("target closed before opening"),
    }
}

/// Relays a TCP connection. With `idle`, a connection that moves no data in either direction for
/// that long is closed, so connections that only sit there cannot hold stream slots forever.
async fn relay_tcp(
    socket: TcpStream,
    session: &Session,
    id: u32,
    mut rx: mpsc::Receiver<Frame>,
    idle: Option<Duration>,
    opening: Opening,
) -> Result<()> {
    let opened = AtomicBool::new(matches!(opening, Opening::Open));
    // The receive window is widened only once the far side knows the stream: the credit frames
    // overtake queued frames, so sent earlier they could arrive before `Open` and be ignored.
    if opened.load(Ordering::Acquire) {
        session.open_window(id).await?;
    }
    let (mut read, mut write) = socket.into_split();
    let activity = Mutex::new(Instant::now());
    let touch = || {
        *activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
    };
    let upload = async {
        let mut buffer = vec![0; DATA_SIZE];
        loop {
            let count = read.read(&mut buffer).await?;
            if count == 0 {
                session.send(Frame::Eof { id }).await?;
                return Ok::<(), anyhow::Error>(());
            }
            touch();
            session.send_data(id, buffer[..count].to_vec()).await?;
            session
                .stats
                .bytes_to_peer
                .fetch_add(count as u64, Ordering::Relaxed);
        }
    };
    let download = async {
        loop {
            match rx.recv().await {
                Some(Frame::Opened { .. }) if !opened.load(Ordering::Acquire) => {
                    opened.store(true, Ordering::Release);
                    session.open_window(id).await?;
                }
                Some(Frame::Error { message, .. }) if !opened.load(Ordering::Acquire) => {
                    bail!("target rejected: {message}")
                }
                Some(Frame::Data { data, .. }) => {
                    write.write_all(&data).await?;
                    touch();
                    session
                        .stats
                        .bytes_from_peer
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    session.send(Frame::Credit { id, frames: 1 }).await?;
                }
                Some(Frame::Eof { .. }) => {
                    write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                Some(Frame::Close { .. }) | None => bail!("remote stream closed"),
                Some(Frame::Error { message, .. }) => bail!("remote stream error: {message}"),
                _ => bail!("invalid frame for TCP stream state"),
            }
        }
    };
    let watchdog = async {
        match idle {
            Some(idle) => {
                udp_idle(&activity, idle).await;
                Err(anyhow::anyhow!(
                    "stream idle for {} seconds",
                    idle.as_secs()
                ))
            }
            None => std::future::pending().await,
        }
    };
    // Keep receiving/crediting while upload waits for its own credit. Both
    // directions must reach EOF before returning (TCP half-close semantics).
    tokio::select! {
        result = async { tokio::try_join!(upload, download).map(|_| ()) } => result,
        result = watchdog => result,
        result = open_deadline(opening, &opened) => result,
    }
}

async fn session_scope<F>(session: &Session, future: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    let mut closed = session.closed.subscribe();
    if *closed.borrow() {
        bail!("tunnel disconnected");
    }
    tokio::select! {
        result = future => result,
        _ = closed.changed() => bail!("tunnel disconnected"),
    }
}

async fn close_stream<F>(session: &Session, id: u32, future: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    let result = future.await;
    // Queue Close after preceding data/EOF even when the output queue is full.
    // The Drop guard is only a best-effort fallback for cancellation.
    let _ = session.send(Frame::Close { id }).await;
    result
}

async fn target_stream(
    session: &Session,
    id: u32,
    kind: StreamKind,
    target: &str,
    proxy: Option<crate::wire::ProxyInfo>,
    rx: mpsc::Receiver<Frame>,
    tuning: Tuning,
) -> Result<()> {
    match kind {
        StreamKind::Tcp => {
            let mut socket = time::timeout(tuning.connect, TcpStream::connect(target))
                .await
                .context("target connect timeout")??;
            socket.set_nodelay(true)?;
            // The destination learns the user's address before any user data.
            if let Some(info) = &proxy {
                use tokio::io::AsyncWriteExt;
                socket
                    .write_all(&crate::proxy_protocol::header(info))
                    .await
                    .context("write the PROXY protocol header")?;
            }
            session.send(Frame::Opened { id }).await?;
            relay_tcp(socket, session, id, rx, tuning.tcp_idle, Opening::Open).await
        }
        StreamKind::Udp => {
            let addr = time::timeout(tuning.connect, tokio::net::lookup_host(target))
                .await
                .context("UDP target lookup timeout")??
                .next()
                .context("UDP target has no address")?;
            let socket = UdpSocket::bind(if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?;
            socket.connect(addr).await?;
            session.send(Frame::Opened { id }).await?;
            target_udp(socket, session, id, rx, tuning.udp_idle,&session.stats).await
        }
    }
}

async fn target_udp(
    socket: UdpSocket,
    session: &Session,
    id: u32,
    mut rx: mpsc::Receiver<Frame>,
    idle: Duration,
    stats:&Stats,
) -> Result<()> {
    session.open_window(id).await?;
    let activity = Mutex::new(Instant::now());
    let upload = async {
        let mut buffer = vec![0; 65536];
        loop {
            let count = socket.recv(&mut buffer).await?;
            *activity
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
            if count <= DATA_SIZE {
                session.send_data(id, buffer[..count].to_vec()).await?;
                stats.bytes_to_peer.fetch_add(count as u64,Ordering::Relaxed);
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let download = async {
        loop {
            match rx.recv().await {
                Some(Frame::Data { data, .. }) => {
                    socket.send(&data).await?;
                    stats.bytes_from_peer.fetch_add(data.len()as u64,Ordering::Relaxed);
                    *activity
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                    session.send(Frame::Credit { id, frames: 1 }).await?;
                }
                Some(Frame::Close { .. }) | Some(Frame::Eof { .. }) | None => {
                    return Ok::<(), anyhow::Error>(());
                }
                Some(Frame::Error { message, .. }) => bail!("remote UDP error: {message}"),
                _ => bail!("invalid frame for UDP stream"),
            }
        }
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
        _ = udp_idle(&activity, idle) => Ok(()),
    }
}

async fn udp_idle(activity: &Mutex<Instant>, idle: Duration) {
    loop {
        let deadline = *activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            + idle;
        time::sleep_until(deadline).await;
        if activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .elapsed()
            >= idle
        {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_map(
    bind: String,
    target: String,
    proxy_version: Option<u8>,
    pool: Arc<Pool>,
    users: Arc<PendingLimiter>,
    limit: usize,
    tuning: Tuning,
    stats: Arc<Stats>,
) -> Result<()> {
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind TCP map {bind}"))?;
    let permits = Arc::new(Semaphore::new(limit));
    let mut tasks = JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    tracing::info!(address = %bind, "TCP map ready");
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, user) = match accepted {
                    Ok(accepted) => { backoff.succeeded(); accepted }
                    Err(error) => { backoff.failed("accept", error).await?; continue; }
                };
                // Who connected to which address, for the destination's PROXY header.
                let proxy = proxy_version.and_then(|version| {
                    crate::wire::ProxyInfo::new(version, user, socket.local_addr().ok()?)
                });
                let local_crowded=local_reserve_reached(permits.available_permits(),limit);
                let Some(user_slot) = users.try_enter_when(Some(user.ip()), pool.crowded()||local_crowded) else {
                    tracing::debug!(%user, "too many open connections from this address");
                    stats.refuse_stream();
                    continue;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else { stats.refuse_stream(); continue; };
                let Some(session) = pool.pick() else { stats.refuse_stream(); continue; };
                let Ok((id, mut rx)) = session.register(None) else { stats.refuse_stream(); continue; };
                let guard = StreamGuard { session: session.clone(), id };
                let target = target.clone();
                tasks.spawn(async move {
                    let (_permit, _guard, _user) = (permit, guard, user_slot);
                    session_scope(&session, close_stream(&session, id, async {
                        socket.set_nodelay(true)?;
                        session.send(Frame::Open { id, kind: StreamKind::Tcp, target, proxy }).await?;
                        let opening = if tuning.early_data {
                            Opening::for_new_stream(&tuning)
                        } else {
                            await_open(&mut rx, tuning.open).await?;
                            Opening::Open
                        };
                        relay_tcp(socket, &session, id, rx, tuning.tcp_idle, opening).await
                    })).await
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => { log_forward_result(result); }
        }
    }
}

fn log_forward_result(result: Option<std::result::Result<Result<()>, tokio::task::JoinError>>) {
    match result {
        Some(Ok(Err(error))) => tracing::debug!(%error, "forwarded stream ended"),
        Some(Err(error)) => tracing::warn!(%error, "forwarding task failed"),
        _ => {}
    }
}

async fn udp_map(
    bind: String,
    target: String,
    pool: Arc<Pool>,
    users: Arc<PendingLimiter>,
    limit: usize,
    tuning: Tuning,
    stats: Arc<Stats>,
    gaming: Option<Arc<crate::gaming::Hub>>,
) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(&bind)
            .await
            .with_context(|| format!("bind UDP map {bind}"))?,
    );
    let mut peers: HashMap<SocketAddr, mpsc::Sender<QueuedDatagram>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    let mut buffer = vec![0; 65536];
    // Conversations that ended are forgotten on a timer, so a long run with many different
    // source addresses does not keep growing the table.
    let mut prune = time::interval(Duration::from_secs(5));
    prune.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    tracing::info!(address = %bind, "UDP map ready");
    loop {
        tokio::select! {
            _ = prune.tick() => {
                peers.retain(|_, sender| !sender.is_closed());
            }
            packet = socket.recv_from(&mut buffer) => {
                let (count, peer) = match packet {
                    Ok(received) => { backoff.succeeded(); received }
                    Err(error) => { backoff.failed("UDP receive", error).await?; continue; }
                };
                if count > DATA_SIZE { continue; }
                match peers.get(&peer) {
                    Some(sender) if !sender.is_closed() => {
                        queue_datagram(sender, &buffer[..count], &stats);
                        continue;
                    }
                    Some(_) => { peers.remove(&peer); }
                    None => {}
                }
                if peers.len() >= limit {
                    // Only now is an exact count worth the cost of a scan.
                    peers.retain(|_, sender| !sender.is_closed());
                }
                if peers.len() >= limit { stats.refuse_stream(); continue; }
                let local_crowded=local_reserve_reached(limit.saturating_sub(peers.len()),limit);
                let Some(user_slot) = users.try_enter_when(Some(peer.ip()), pool.crowded()||local_crowded) else { stats.refuse_stream(); continue; };
                if let Some(hub)=&gaming {
                    if hub.usable().await {
                        let (tx,mut packets)=mpsc::channel(tuning.stream_queue);
                        queue_datagram(&tx,&buffer[..count],&stats);peers.insert(peer,tx);
                        let (hub,socket,target)=(hub.clone(),socket.clone(),target.clone());
                        let stats=stats.clone();
                        tasks.spawn(async move {
                            let _user=user_slot;
                            let(flow,mut replies)=hub.register().await?;
                            let result=async {
                                let mut heard=Instant::now();
                                loop {
                                    let deadline=heard+tuning.udp_idle;
                                    tokio::select! {
                                        packet=packets.recv()=>{
                                            let Some(QueuedDatagram{data,_held})=packet else{break;};
                                            // Once a direct flow is established, a missing
                                            // path drops UDP rather than recreating the
                                            // target socket under an unrelated mux flow.
                                            if hub.send(flow,&target,&data).await.unwrap_or(false){stats.bytes_to_peer.fetch_add(data.len() as u64,Ordering::Relaxed);}
                                            else{stats.udp_dropped.fetch_add(1,Ordering::Relaxed);}
                                            heard=Instant::now();
                                        }
                                        reply=replies.recv()=>{
                                            let Some(data)=reply else{break;};socket.send_to(&data,peer).await?;
                                            stats.bytes_from_peer.fetch_add(data.len() as u64,Ordering::Relaxed);heard=Instant::now();
                                        }
                                        _=time::sleep_until(deadline)=>break,
                                    }
                                }
                                Ok::<(),anyhow::Error>(())
                            }.await;
                            hub.unregister(flow).await;result
                        });
                        continue;
                    }
                }
                let Some(session) = pool.pick() else { stats.refuse_stream(); continue; };
                let Ok((id, mut rx)) = session.register(None) else { stats.refuse_stream(); continue; };
                let guard = StreamGuard { session: session.clone(), id };
                let (tx, mut packets) = mpsc::channel(tuning.stream_queue);
                queue_datagram(&tx, &buffer[..count], &stats);
                peers.insert(peer, tx);
                let (socket, target) = (socket.clone(), target.clone());
                    // A flow opened before direct negotiation stays on its
                    // original reliable target socket; never switch it midflight.
                    tasks.spawn(async move {
                    let (_guard, _user) = (guard, user_slot);
                    let result=session_scope(&session, close_stream(&session, id, async {
                        session.send(Frame::Open { id, kind: StreamKind::Udp, target:target.clone(), proxy: None }).await?;
                        let opening = if tuning.early_data {
                            Opening::for_new_stream(&tuning)
                        } else {
                            await_open(&mut rx, tuning.open).await?;
                            Opening::Open
                        };
                        let opened = AtomicBool::new(matches!(opening, Opening::Open));
                        if opened.load(Ordering::Acquire) {
                            session.open_window(id).await?;
                        }
                        let activity = Mutex::new(Instant::now());
                        let upload = async {
                            while let Some(QueuedDatagram { data, _held }) = packets.recv().await {
                                let size=data.len();
                                session.send_data(id, data).await?;
                                session.stats.bytes_to_peer.fetch_add(size as u64,Ordering::Relaxed);
                                *activity.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                            }
                            Ok::<(), anyhow::Error>(())
                        };
                        let download = async {
                            loop {
                                match rx.recv().await {
                                    Some(Frame::Opened { .. }) if !opened.load(Ordering::Acquire) => {
                                        opened.store(true, Ordering::Release);
                                        session.open_window(id).await?;
                                    }
                                    Some(Frame::Error { message, .. }) if !opened.load(Ordering::Acquire) => {
                                        bail!("UDP target rejected: {message}")
                                    }
                                    Some(Frame::Data { data, .. }) => {
                                        socket.send_to(&data, peer).await?;
                                        session.stats.bytes_from_peer.fetch_add(data.len()as u64,Ordering::Relaxed);
                                        *activity.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                                        session.send(Frame::Credit { id, frames: 1 }).await?;
                                    }
                                    Some(Frame::Close { .. }) | Some(Frame::Eof { .. }) | None => return Ok::<(), anyhow::Error>(()),
                                    Some(Frame::Error { message, .. }) => bail!("remote UDP error: {message}"),
                                    _ => bail!("invalid UDP stream frame"),
                                }
                            }
                        };
                        tokio::select! {
                            result = upload => result,
                            result = download => result,
                            _ = udp_idle(&activity, tuning.udp_idle) => Ok(()),
                            result = open_deadline(opening, &opened) => result,
                        }
                    })).await;
                    result
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => { log_forward_result(result); }
        }
    }
}

async fn socks_listener(
    bind: String,
    pool: Arc<Pool>,
    users: Arc<PendingLimiter>,
    limit: usize,
    tuning: Tuning,
    stats: Arc<Stats>,
    gaming:Option<Arc<crate::gaming::Hub>>,
) -> Result<()> {
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind SOCKS5 listener {bind}"))?;
    let permits = Arc::new(Semaphore::new(limit));
    let mut tasks = JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    tracing::info!(address = %bind, "SOCKS5 listener ready");
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, user) = match accepted {
                    Ok(accepted) => { backoff.succeeded(); accepted }
                    Err(error) => { backoff.failed("accept", error).await?; continue; }
                };
                let crowded=pool.crowded()||local_reserve_reached(permits.available_permits(),limit);
                let Some(user_slot) = users.try_enter_when(Some(user.ip()), crowded) else { stats.refuse_stream(); continue; };
                let Ok(permit) = permits.clone().try_acquire_owned() else { stats.refuse_stream(); continue; };
                let (pool, stats, stream_users,gaming) = (pool.clone(), stats.clone(), users.clone(),gaming.clone());
                tasks.spawn(async move { let (_permit, _user) = (permit, user_slot); socks_stream(socket, pool, stream_users, limit, tuning, stats,gaming).await });
            }
            result = tasks.join_next(), if !tasks.is_empty() => { log_forward_result(result); }
        }
    }
}

/// What a SOCKS5 client asked for.
enum SocksCommand {
    /// CONNECT to `host:port`.
    Connect(String),
    /// UDP ASSOCIATE: a relay for datagrams (see `socks_udp`).
    UdpAssociate,
}

async fn socks_request(socket: &mut TcpStream) -> Result<SocksCommand> {
    let mut hello = [0; 2];
    socket.read_exact(&mut hello).await?;
    if hello[0] != 5 || hello[1] == 0 {
        bail!("invalid SOCKS5 greeting");
    }
    let mut methods = vec![0; hello[1] as usize];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        socket.write_all(&[5, 255]).await?;
        bail!("SOCKS5 requires no-auth method");
    }
    socket.write_all(&[5, 0]).await?;
    let mut request = [0; 4];
    socket.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        bail!("invalid SOCKS5 request");
    }
    let associate = match request[1] {
        1 => false,
        3 => true,
        _ => {
            socks_reply(socket, 7).await?;
            bail!("only SOCKS5 CONNECT and UDP ASSOCIATE are supported");
        }
    };
    let host = match request[3] {
        1 => {
            let mut octets = [0; 4];
            socket.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        4 => {
            let mut octets = [0; 16];
            socket.read_exact(&mut octets).await?;
            format!("[{}]", std::net::Ipv6Addr::from(octets))
        }
        3 => {
            let size = socket.read_u8().await? as usize;
            if size == 0 {
                bail!("empty SOCKS5 hostname");
            }
            let mut bytes = vec![0; size];
            socket.read_exact(&mut bytes).await?;
            let host = String::from_utf8(bytes).context("SOCKS5 hostname must be UTF-8")?;
            if host.contains([':', '/', '\\', '\0']) {
                bail!("invalid SOCKS5 hostname");
            }
            // The far end answers some .invalid names itself (the speed test), outside
            // allowed_targets; a proxy user must not reach them.
            if crate::config::reserved_host(&host) {
                socks_reply(socket, 2).await?;
                bail!("SOCKS5 hostname is reserved");
            }
            host
        }
        _ => {
            socks_reply(socket, 8).await?;
            bail!("unsupported SOCKS5 address type");
        }
    };
    let port = socket.read_u16().await?;
    if associate {
        // The address a UDP client names is where it will send from; it is often 0.0.0.0:0.
        return Ok(SocksCommand::UdpAssociate);
    }
    if port == 0 {
        bail!("SOCKS5 port must be nonzero");
    }
    Ok(SocksCommand::Connect(format!("{host}:{port}")))
}

async fn socks_reply(socket: &mut TcpStream, status: u8) -> Result<()> {
    socket
        .write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn socks_stream(
    mut socket: TcpStream,
    pool: Arc<Pool>,
    users: Arc<PendingLimiter>,
    limit: usize,
    tuning: Tuning,
    stats: Arc<Stats>,
    gaming:Option<Arc<crate::gaming::Hub>>,
) -> Result<()> {
    socket.set_nodelay(true)?;
    let command = time::timeout(tuning.connect, socks_request(&mut socket))
        .await
        .context("SOCKS5 handshake timeout")??;
    let target = match command {
        SocksCommand::Connect(target) => target,
        SocksCommand::UdpAssociate => {
            return socks_udp::associate(socket, pool, users, limit, tuning, stats,gaming).await;
        }
    };
    let Some(session) = pool.pick() else {
        stats.refuse_stream();
        socks_reply(&mut socket, 3).await?;
        bail!("no authenticated tunnel available");
    };
    let (id, mut rx) = match session.register(None) {
        Ok(stream) => stream,
        Err(error) => {
            stats.refuse_stream();
            socks_reply(&mut socket, 1).await?;
            return Err(error);
        }
    };
    let _guard = StreamGuard {
        session: session.clone(),
        id,
    };
    session_scope(
        &session,
        close_stream(&session, id, async {
            session
                .send(Frame::Open {
                    id,
                    kind: StreamKind::Tcp,
                    target,
                    proxy: None,
                })
                .await?;
            // With early data the client is told "connected" at once and sends its request
            // behind the open; a destination that fails then closes the connection instead.
            let opening = if tuning.early_data {
                Opening::for_new_stream(&tuning)
            } else {
                if let Err(error) = await_open(&mut rx, tuning.open).await {
                    socks_reply(&mut socket, 2).await?;
                    return Err(error);
                }
                Opening::Open
            };
            socks_reply(&mut socket, 0).await?;
            relay_tcp(socket, &session, id, rx, tuning.tcp_idle, opening).await
        }),
    )
    .await
}

/// C11/V03: the documented last-quarter reservation applied to the local resource whose
/// exhaustion actually refuses users (a map's permits, a UDP map's flow table, the SOCKS
/// listener), not only to aggregate mux occupancy.
fn local_reserve_reached(available: usize, limit: usize) -> bool {
    available <= limit.saturating_div(4).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// V02: a session that has not proved liveness holds only its pending-handshake guard;
    /// the connection slot is taken at proof, and refused (with the guard released) when
    /// every slot is in use.
    #[test]
    fn the_connection_slot_is_taken_only_after_liveness_proof() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let pending = crate::limits::PendingLimiter::new(4, 4);
        let ip: std::net::IpAddr = "192.0.2.10".parse().unwrap();
        let replay = Admission { slots: slots.clone(), pending: pending.try_enter(Some(ip)) };
        let live = Admission { slots: slots.clone(), pending: pending.try_enter(Some(ip)) };
        assert_eq!(slots.available_permits(), 1, "an unproved replay must not hold the sole slot");
        // The live peer proves first and gets the slot; the replay never proves anything.
        let slot = live.admit().expect("live peer admitted");
        assert_eq!(slots.available_permits(), 0);
        drop(replay); // its handshake_sec deadline ends it; only the pending guard goes away
        let late = Admission { slots: slots.clone(), pending: pending.try_enter(Some(ip)) };
        assert!(late.admit().is_none(), "a full limit still refuses");
        let held: Vec<_> = (0..4).filter_map(|_| pending.try_enter(Some(ip))).collect();
        assert_eq!(held.len(), 4, "every pending guard was released");
        drop(slot);
        assert_eq!(slots.available_permits(), 1);
    }

    /// C11: eight-slot map, per-IP limit two, two healthy pooled sessions (aggregate not
    /// crowded). One address bursts until the last quarter, is then refused, and a second
    /// address is still served.
    #[test]
    fn a_small_map_keeps_its_reserve_for_other_addresses() {
        let limit = 8;
        let permits = Arc::new(tokio::sync::Semaphore::new(limit));
        let users = crate::limits::PendingLimiter::new(64, 2);
        let first: std::net::IpAddr = "198.51.100.1".parse().unwrap();
        let second: std::net::IpAddr = "198.51.100.2".parse().unwrap();
        let mut held = Vec::new();
        loop {
            let crowded = local_reserve_reached(permits.available_permits(), limit);
            let Some(slot) = users.try_enter_when(Some(first), crowded) else { break };
            let permit = permits.clone().try_acquire_owned().expect("map permit");
            held.push((slot, permit));
        }
        assert_eq!(held.len(), 6, "low-load bursting above the per-IP limit stays allowed");
        assert!(local_reserve_reached(permits.available_permits(), limit));
        let crowded = local_reserve_reached(permits.available_permits(), limit);
        let slot = users.try_enter_when(Some(second), crowded).expect("another address is served");
        let _permit = permits.clone().try_acquire_owned().expect("reserved permit left for it");
        drop(slot);
        // Releasing the burst returns capacity.
        held.clear();
        assert!(!local_reserve_reached(permits.available_permits(), limit));
        assert!(!local_reserve_reached(16, 16) && local_reserve_reached(4, 16) && local_reserve_reached(1, 2));
    }

    /// A session with no peer: credits sent to the peer arrive on the returned receiver.
    fn lone_session(window: usize, stats: Arc<Stats>) -> (Session, mpsc::Receiver<Frame>) {
        let (tx, _unused) = mpsc::channel(64);
        let (control, credits) = mpsc::channel(256);
        let (closed, _) = watch::channel(false);
        let session = Session {
            tx,
            control,
            closed,
            streams: Mutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
            next_id: AtomicU32::new(1),
            max_streams: 16,
            stream_queue: 32,
            window,
            stats,
            peer: None,
            heard: Arc::new(std::sync::atomic::AtomicU64::new(clock())),
            waiting_since: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            suspect: AtomicBool::new(false),
            unanswered: tokio::sync::Notify::new(),
            bytes_in: AtomicU64::new(0),
            slow_mark: AtomicU64::new(0),
            slow_strikes: AtomicU32::new(0),
            quality: Mutex::new(quality::Quality::default()),
        };
        (session, credits)
    }

    /// C32: reliable UDP to a target counts each payload once per direction, nothing else.
    #[tokio::test]
    async fn reliable_udp_target_counts_exact_payload_bytes_both_ways() -> Result<()> {
        let echo = UdpSocket::bind("127.0.0.1:0").await?;
        let echo_addr = echo.local_addr()?;
        let echoing = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            loop {
                let Ok((n, from)) = echo.recv_from(&mut buffer).await else { break };
                let _ = echo.send_to(&buffer[..n], from).await;
            }
        });
        let stats = Arc::new(Stats::default());
        let (data_tx, mut data_rx) = mpsc::channel(64);
        let (mut session, _credits) = lone_session(CREDITS, stats.clone());
        session.tx = data_tx;
        let session = Arc::new(session);
        let (id, _registered) = session.register(None)?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(echo_addr).await?;
        let (frames_tx, frames_rx) = mpsc::channel(16);
        let relay = {
            let (session, stats) = (session.clone(), stats.clone());
            tokio::spawn(async move { target_udp(socket, &session, id, frames_rx, Duration::from_secs(30), &stats).await })
        };
        for size in [100usize, 200, 300] {
            frames_tx.send(Frame::Data { id, data: vec![7; size] }).await?;
        }
        let mut echoed = 0;
        while echoed < 600 {
            match tokio::time::timeout(Duration::from_secs(2), data_rx.recv()).await?.context("session closed")? {
                Frame::Data { data, .. } => echoed += data.len(),
                _ => {}
            }
        }
        assert_eq!(echoed, 600);
        // The counter is updated right after the frame is queued.
        for _ in 0..100 {
            if stats.bytes_to_peer.load(Ordering::Relaxed) == 600 { break; }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(stats.bytes_from_peer.load(Ordering::Relaxed), 600, "peer -> target payload");
        assert_eq!(stats.bytes_to_peer.load(Ordering::Relaxed), 600, "target -> peer payload");
        frames_tx.send(Frame::Close { id }).await?;
        tokio::time::timeout(Duration::from_secs(2), relay).await???;
        echoing.abort();
        Ok(())
    }

    /// C10: a download responder waiting for credit ends on a delivered Close/Error or a
    /// closed stream; the requester's Eof (half-close) does not cut the download short.
    #[tokio::test]
    async fn a_credit_blocked_speedtest_download_ends_on_close_but_not_on_half_close() -> Result<()> {
        for terminal in [Some(Frame::Close { id: 0 }), Some(Frame::Error { id: 0, message: "x".into() }), None] {
            let stats = Arc::new(Stats::default());
            let (data_tx, mut data_rx) = mpsc::channel(1024);
            let (mut session, _credits) = lone_session(CREDITS, stats.clone());
            session.tx = data_tx;
            let session = Arc::new(session);
            let (id, _registered) = session.register(None)?;
            let (frames_tx, frames_rx) = mpsc::channel(16);
            let drain = tokio::spawn(async move { while data_rx.recv().await.is_some() {} });
            let responder = tokio::spawn(control::answer_speedtest(session.clone(), id, frames_rx, true, ((CREDITS + 4) * DATA_SIZE) as u64));
            // Let it use up the initial window; no new credit is ever granted.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!responder.is_finished(), "fixture must stall on credit");
            frames_tx.send(Frame::Eof { id }).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!responder.is_finished(), "half-close must not end the download");
            match terminal {
                Some(Frame::Close { .. }) => frames_tx.send(Frame::Close { id }).await?,
                Some(Frame::Error { message, .. }) => frames_tx.send(Frame::Error { id, message }).await?,
                _ => drop(frames_tx),
            }
            tokio::time::timeout(Duration::from_secs(2), responder).await.context("responder stayed blocked")???;
            drain.abort();
        }
        Ok(())
    }

    #[test]
    fn silence_is_probed_then_suspected_and_idle_is_fine() {
        let probe = Duration::from_secs(3);
        assert_eq!(silence(0, 1_000_000, probe), Silence::Fine, "not waiting");
        assert_eq!(silence(10_000, 12_999, probe), Silence::Fine);
        assert_eq!(silence(10_000, 13_000, probe), Silence::Probe);
        assert_eq!(silence(10_000, 15_999, probe), Silence::Probe);
        assert_eq!(silence(10_000, 16_000, probe), Silence::Suspect);
        // A clock read before the mark (another thread) is not a wait.
        assert_eq!(silence(10_000, 9_000, probe), Silence::Fine);
    }

    #[test]
    fn suspect_sessions_take_no_new_users() {
        let pool = Pool::default();
        let (first, _a) = peer_session(1);
        let (second, _b) = peer_session(1);
        pool.insert(&first);
        pool.insert(&second);
        first.suspect.store(true, Ordering::Release);
        for _ in 0..4 {
            assert!(Arc::ptr_eq(&pool.pick().unwrap(), &second));
        }
        second.suspect.store(true, Ordering::Release);
        assert!(pool.pick().is_none(), "no session that answers");
        first.suspect.store(false, Ordering::Release);
        assert!(Arc::ptr_eq(&pool.pick().unwrap(), &first));
    }

    #[test]
    fn quality_steers_only_new_streams_with_capacity_and_periodic_exploration() {
        let pool = Pool {
            quality_steering: true,
            quality_fresh_ms: 60_000,
            ..Pool::default()
        };
        let (slow, _a) = peer_session(1);
        let (fast, _b) = peer_session(1);
        pool.insert(&slow);
        pool.insert(&fast);
        let (id, _) = slow.register(None).unwrap();
        for _ in 0..7 {
            slow.quality
                .lock()
                .unwrap()
                .observe(Duration::from_millis(300), clock());
            fast.quality
                .lock()
                .unwrap()
                .observe(Duration::from_millis(30), clock());
            for _ in 0..4 {
                pool.pick();
            }
        }
        let mut fast_count = 0;
        for _ in 0..32 {
            if Arc::ptr_eq(&pool.pick().unwrap(), &fast) {
                fast_count += 1;
            }
        }
        assert!(fast_count >= 28 && fast_count < 32);
        assert!(slow.streams.lock().unwrap().contains_key(&id));
        fast.suspect.store(true, Ordering::Relaxed);
        assert!(Arc::ptr_eq(&pool.pick().unwrap(), &slow));
        assert!(slow.alive.load(Ordering::Relaxed));
    }

    /// Whether `session.unanswered` has already been notified (consumes the stored permit, like
    /// `probe_older_sessions`' own use of the same field).
    fn was_notified(session: &Session) -> bool {
        let notified = session.unanswered.notified();
        tokio::pin!(notified);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        std::future::Future::poll(notified.as_mut(), &mut cx).is_ready()
    }

    #[test]
    fn a_session_delivering_far_less_than_its_pool_siblings_is_closed() {
        let pool = Pool::default();
        let (fast_a, _a) = peer_session(1);
        let (fast_b, _b) = peer_session(1);
        let (slow, _c) = peer_session(1);
        for session in [&fast_a, &fast_b, &slow] {
            pool.insert(session);
        }
        // Too few live sessions of one peer (fewer than 3) are never judged.
        let (lone_a, _d) = peer_session(2);
        let (lone_b, _e) = peer_session(2);
        pool.insert(&lone_a);
        pool.insert(&lone_b);
        lone_a.bytes_in.store(1_000_000, Ordering::Relaxed);
        pool.evict_slow();
        assert!(!was_notified(&lone_a));

        // One strike is not enough: it takes Pool::SLOW_STRIKES windows in a row. `slow` stays
        // above SLOW_PER_SESSION_MIN_BYTES every round (it is genuinely active, just far behind),
        // not idle: an idle session is excluded from judgment entirely, not judged as slow.
        for delivered in [400_000u64, 500_000, 600_000] {
            fast_a.bytes_in.fetch_add(delivered, Ordering::Relaxed);
            fast_b.bytes_in.fetch_add(delivered, Ordering::Relaxed);
            slow.bytes_in.fetch_add(40_000, Ordering::Relaxed);
            pool.evict_slow();
        }
        assert!(
            was_notified(&slow),
            "far behind its siblings for several windows in a row: closed to reconnect fresh"
        );
        assert!(!was_notified(&fast_a));
        assert!(!was_notified(&fast_b));
        assert!(pool.pick().is_some(), "the fast siblings still take users");

        // Natural burstiness (one session getting more than a third of the group's traffic for a
        // window or two) must not be enough on its own: only under a quarter of the group's
        // median counts as a strike, not under half.
        let (bursty_a, _f) = peer_session(4);
        let (bursty_b, _g) = peer_session(4);
        let (bursty_c, _h) = peer_session(4);
        for session in [&bursty_a, &bursty_b, &bursty_c] {
            pool.insert(session);
        }
        bursty_a.bytes_in.store(300_000, Ordering::Relaxed);
        bursty_b.bytes_in.store(150_000, Ordering::Relaxed);
        bursty_c.bytes_in.store(100_000, Ordering::Relaxed); // a third of bursty_a, not a quarter
        pool.evict_slow();
        assert_eq!(
            bursty_c.slow_strikes.load(Ordering::Relaxed),
            0,
            "within tolerance of the group's median, not just its fastest member"
        );

        // A near-idle window (every session moved almost nothing) is not judged at all, so the
        // slow session's streak does not grow from noise once traffic stops.
        let (healthy_a, _i) = peer_session(5);
        let (healthy_b, _j) = peer_session(5);
        let (catching_up, _k) = peer_session(5);
        for session in [&healthy_a, &healthy_b, &catching_up] {
            pool.insert(session);
        }
        pool.evict_slow();
        assert_eq!(catching_up.slow_strikes.load(Ordering::Relaxed), 0);
    }

    /// Regression test: two idle (but still technically alive, e.g. finished and not yet cleaned
    /// up) sessions of the same peer must not drag the computed "typical" down to near their own
    /// near-zero delivery, which would then unfairly flag a genuinely busy sibling sitting right
    /// next to that stale low bar. Caught live: the transport checker runs many short cases
    /// against the same two peers in sequence, so stray sessions from an already-finished case
    /// can still be in the pool while the next case's session is transferring real data — a build
    /// without the per-session activity floor closed that session mid-transfer every run.
    #[test]
    fn idle_siblings_do_not_drag_down_the_bar_for_a_genuinely_busy_session() {
        let pool = Pool::default();
        let (stale_a, _a) = peer_session(9);
        let (stale_b, _b) = peer_session(9);
        let (busy, _c) = peer_session(9);
        for session in [&stale_a, &stale_b, &busy] {
            pool.insert(session);
        }
        // stale_a/stale_b never move any bytes again (as if their case finished); busy keeps
        // transferring normally, round after round.
        for _ in 0..5 {
            busy.bytes_in.fetch_add(500_000, Ordering::Relaxed);
            pool.evict_slow();
        }
        assert!(
            !was_notified(&busy),
            "two idle siblings must not make a genuinely busy session look like the outlier"
        );
        assert_eq!(busy.slow_strikes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn allowed_targets_match_host_names_in_any_case_and_nothing_else() {
        assert!(target_allowed("*", "anything:1"));
        assert!(target_allowed("127.0.0.1:22", "127.0.0.1:22"));
        assert!(!target_allowed("127.0.0.1:22", "127.0.0.1:23"));
        assert!(target_allowed("Example.COM:443", "example.com:443"));
        assert!(target_allowed("example.com:443", "EXAMPLE.com:443"));
        assert!(target_allowed("Example.com:*", "example.COM:8080"));
        assert!(!target_allowed("example.com:*", "evil-example.com:80"));
        assert!(!target_allowed("example.com:*", "example.com.evil:80"));
        assert!(!target_allowed("example.com:443", "example.com:80"));
    }

    #[test]
    fn queued_udp_datagrams_are_paid_from_the_memory_budget() {
        let stats = Arc::new(Stats::default());
        stats.window_budget.set_limit(2);
        let (sender, mut queue) = mpsc::channel(8);
        for _ in 0..3 {
            queue_datagram(&sender, b"datagram", &stats);
        }
        // Two fit the budget, the third is dropped and counted.
        assert_eq!(stats.window_budget.used(), 2);
        assert_eq!(stats.udp_dropped.load(Ordering::Relaxed), 1);
        // Sent (taken from the queue and dropped): the frame comes back.
        let first = queue.try_recv().unwrap();
        assert_eq!(first.data, b"datagram");
        drop(first);
        assert_eq!(stats.window_budget.used(), 1);
        // With room in the budget, a full queue drops too, and gives the frame back at once.
        stats.window_budget.set_limit(10);
        let (small, _small_queue) = mpsc::channel(1);
        queue_datagram(&small, b"a", &stats);
        queue_datagram(&small, b"b", &stats);
        assert_eq!(stats.udp_dropped.load(Ordering::Relaxed), 2);
        assert_eq!(stats.window_budget.used(), 2);
    }

    /// A pooled session of `peer`; frames sent to the peer arrive on the returned receiver.
    fn peer_session(peer: u8) -> (Arc<Session>, mpsc::Receiver<Frame>) {
        let (mut session, control) = lone_session(16, Arc::new(Stats::default()));
        session.peer = Some([peer; 32]);
        (Arc::new(session), control)
    }

    #[tokio::test]
    async fn a_reconnecting_peer_closes_its_older_sessions_that_no_longer_answer() {
        let pool = Pool::default();
        let (dead, mut dead_control) = peer_session(1);
        let (healthy, mut healthy_control) = peer_session(1);
        let (stranger, mut stranger_control) = peer_session(2);
        let (new, _new_control) = peer_session(1);
        for session in [&dead, &healthy, &stranger, &new] {
            pool.insert(session);
        }
        // Make sure "heard" moves on from the sessions' start.
        time::sleep(Duration::from_millis(5)).await;
        probe_older_sessions(&pool, &new, Duration::from_millis(300));
        tokio::task::yield_now().await;
        // Both older sessions of that peer were asked, the other peer's session was not.
        assert!(matches!(dead_control.try_recv(), Ok(Frame::Ping { .. })));
        assert!(matches!(healthy_control.try_recv(), Ok(Frame::Ping { .. })));
        assert!(stranger_control.try_recv().is_err());
        // The healthy one answers.
        time::sleep(Duration::from_millis(50)).await;
        healthy.heard.store(clock(), Ordering::Relaxed);
        let ended = |session: &Arc<Session>| {
            let session = session.clone();
            async move {
                time::timeout(Duration::from_secs(1), session.unanswered.notified())
                    .await
                    .is_ok()
            }
        };
        let (dead_ended, healthy_ended, new_ended) =
            tokio::join!(ended(&dead), ended(&healthy), ended(&new));
        assert!(dead_ended, "the silent session is ended");
        assert!(!healthy_ended, "the answering session stays");
        assert!(!new_ended, "the new session is not probed");
    }

    fn credited(credits: &mut mpsc::Receiver<Frame>) -> usize {
        let mut total = 0;
        while let Ok(frame) = credits.try_recv() {
            if let Frame::Credit { frames, .. } = frame {
                total += frames as usize;
            }
        }
        total
    }

    #[tokio::test]
    async fn windows_are_paid_from_the_memory_budget_and_returned_when_streams_end() {
        let stats = Arc::new(Stats::default());
        stats.window_budget.set_limit(300);
        // Each stream asks for 256 - 16 = 240 frames beyond the initial window.
        let (session, mut credits) = lone_session(256, stats.clone());
        let (a, _keep_a) = session.register(None).unwrap();
        session.open_window(a).await.unwrap();
        assert_eq!(credited(&mut credits), 240);
        let (b, _keep_b) = session.register(None).unwrap();
        session.open_window(b).await.unwrap();
        assert_eq!(credited(&mut credits), 60, "only what the budget has left");
        let (c, _keep_c) = session.register(None).unwrap();
        session.open_window(c).await.unwrap();
        assert_eq!(
            credited(&mut credits),
            0,
            "used up: the stream keeps its small window"
        );
        assert_eq!(stats.window_budget.used(), 300);
        // A finished stream gives its frames back for the next one.
        session.remove(a);
        assert_eq!(stats.window_budget.used(), 60);
        let (d, _keep_d) = session.register(None).unwrap();
        session.open_window(d).await.unwrap();
        assert_eq!(credited(&mut credits), 240);
        // So does a session that ends with streams still open.
        drop(session);
        assert_eq!(stats.window_budget.used(), 0);
    }

    #[tokio::test]
    async fn without_a_budget_every_stream_gets_the_full_window() {
        let stats = Arc::new(Stats::default());
        let (session, mut credits) = lone_session(256, stats.clone());
        for _ in 0..4 {
            let (id, _keep) = session.register(None).unwrap();
            session.open_window(id).await.unwrap();
            assert_eq!(credited(&mut credits), 240);
        }
    }

    #[test]
    fn a_heartbeat_counts_as_lost_only_after_a_full_interval_and_only_once() {
        use std::{collections::VecDeque, sync::atomic::AtomicU64};
        let lost = AtomicU64::new(0);
        let waiting = |age: u64| PendingPing {
            nonce: age,
            sent_at: Instant::now() - Duration::from_secs(age),
            counted_lost: false,
        };
        let mut pings: VecDeque<PendingPing> = VecDeque::from([waiting(1), waiting(12)]);
        mark_lost_pings(&mut pings, Duration::from_secs(10), &lost);
        // The one in flight (1 s) is not a loss; the one waiting 12 s is.
        assert_eq!(lost.load(Ordering::Relaxed), 1);
        assert!(!pings[0].counted_lost && pings[1].counted_lost);
        // Looking again does not count it twice.
        mark_lost_pings(&mut pings, Duration::from_secs(10), &lost);
        assert_eq!(lost.load(Ordering::Relaxed), 1);
    }

    /// Feeds one SOCKS5 greeting and request to `socks_request` and returns its target.
    async fn socks_target(request: &[u8]) -> Result<String> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (mut server, _) = listener.accept().await?;
        client.write_all(request).await?;
        match socks_request(&mut server).await? {
            SocksCommand::Connect(target) => Ok(target),
            SocksCommand::UdpAssociate => bail!("UDP ASSOCIATE"),
        }
    }

    fn connect_to_name(name: &str) -> Vec<u8> {
        let mut request = vec![5, 1, 0, 5, 1, 0, 3, name.len() as u8];
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(&9u16.to_be_bytes());
        request
    }

    #[tokio::test]
    async fn udp_associate_is_accepted_with_an_unspecified_client_address() -> Result<()> {
        // CMD 3, ATYP 1, 0.0.0.0:0: what most clients send because they do not know their port yet.
        let associate = [5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0];
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (mut server, _) = listener.accept().await?;
        client.write_all(&associate).await?;
        assert!(matches!(
            socks_request(&mut server).await?,
            SocksCommand::UdpAssociate
        ));
        // CONNECT to port 0 is still refused, and BIND is not supported.
        assert!(
            socks_target(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .is_err()
        );
        assert!(
            socks_target(&[5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn socks_users_cannot_reach_reserved_speed_test_targets() -> Result<()> {
        assert_eq!(
            socks_target(&connect_to_name("example.com")).await?,
            "example.com:9"
        );
        for name in [
            "down.1073741824.speedtest.eztunnel.invalid",
            "UP.10.SPEEDTEST.EZTUNNEL.INVALID",
            "anything.invalid.",
        ] {
            assert!(
                socks_target(&connect_to_name(name)).await.is_err(),
                "{name} was accepted"
            );
        }
        Ok(())
    }
}
