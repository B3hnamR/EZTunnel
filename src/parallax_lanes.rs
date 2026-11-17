//! Parallax packet mode: the tunnel's KCP/FEC packets travel as small authenticated records over
//! several real TCP lanes at once.
//!
//! - Each lane opens with an encrypted warm-up of random length before it carries packets.
//! - Every lane feeds one receive path, so the KCP session above does not care which lane a
//!   packet took.
//! - A lane that breaks is dialed again while the KCP session carries on: KCP resends whatever
//!   the broken lane had queued, so user streams survive a lane cut.
//! - Lanes that are not carrying traffic send a small padding record now and then, so a lane a
//!   middlebox silently dropped is noticed and replaced before it is needed.
use crate::config::ClientPath;
use crate::limits::{AcceptBackoff, PendingLimiter};
use anyhow::{Context, Result, anyhow, ensure};
use snow::{Builder, TransportState};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};
use zeroize::Zeroizing;

const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const DOMAIN: &[u8] = b"eztunnel/parallax/packet-lanes/v2";
const VERSION: u8 = 1;
/// Largest tunnel packet one record carries (FEC packets are at most 1500 bytes here).
pub const MAX_PACKET: usize = 2048;
const MAX_RECORD: usize = 1 + MAX_PACKET + 16;
const HANDSHAKE: usize = 256;
const KIND_PAD: u8 = 1;
const KIND_PACKET: u8 = 2;
/// Padding is sent in records of this many bytes (the last one shorter).
const PAD_CHUNK: usize = 1400;
/// Packets one lane may hold before it counts as full. Kept short: what waits here waits in front
/// of every later packet (a game's too), and KCP already resends what a broken lane loses.
const LANE_QUEUE: usize = 128;
/// Unsent bytes the kernel may keep queued on a lane (`TCP_NOTSENT_LOWAT`). Data in flight is not
/// limited, so a lane still fills a long, fast route; only the waiting backlog is kept small.
const LANE_BACKLOG: u32 = 256 * 1024;

/// Keeps the kernel's unsent backlog of a lane small (Linux; elsewhere nothing changes).
fn limit_backlog(socket: &TcpStream) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let value: libc::c_int = LANE_BACKLOG as libc::c_int;
        // SAFETY: the pointer and length describe a live c_int for this call.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_NOTSENT_LOWAT,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            tracing::debug!(error = %std::io::Error::last_os_error(), "Parallax lane backlog limit not set");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = socket;
}
const INCOMING_QUEUE: usize = 4096;
/// A lane with nothing to send sends a small padding record this often.
const KEEPALIVE: Duration = Duration::from_secs(1);
/// A lane that received nothing (not even padding) for this long is given up and dialed again
/// (the default; `silence_for` follows the tunnel's probe time). It must stay under the tunnel's
/// own unanswered-probe time (2 x `timeouts.probe_sec`, 6 s by default), after which the dialing
/// side replaces the whole session and its streams: a lane that stalls silently (a black hole, no
/// reset) is closed here first, the other end sees it close through the direction that still
/// works, and both sides move to a lane that answers.
const SILENCE: Duration = Duration::from_secs(4);

/// The lane silence for a tunnel whose `timeouts.probe_sec` is `probe_sec`: two seconds under its
/// unanswered time (2 x probe_sec), between 2 and 4 seconds (keepalives come every second).
pub fn silence_for(probe_sec: u64) -> Duration {
    Duration::from_secs((2 * probe_sec).saturating_sub(2).clamp(2, SILENCE.as_secs()))
}

/// Milliseconds on one clock for the lanes' "last heard" marks.
fn clock_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}
/// How long an answering lane may wait for the first record under the fresh session keys. A
/// replayed first flight completes the NNpsk0 handshake but can never send one.
const PROOF: Duration = Duration::from_secs(30);
const REKEY: u64 = 1 << 20;
/// Lanes one session may have open at once.
pub const MAX_LANES: usize = 16;
/// A server session with no lane left is forgotten after this long.
const ORPHAN: Duration = Duration::from_secs(120);
const BATCH: usize = 32;

pub type SessionId = [u8; 16];

#[derive(Clone)]
pub struct Key(Zeroizing<[u8; 32]>);
impl Key {
    pub(crate) fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }
}
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ParallaxLaneKey(REDACTED)")
    }
}

/// What a lane pool or lane listener needs from the tunnel settings.
#[derive(Clone, Debug)]
pub struct Settings {
    pub lanes: usize,
    pub warmup_min: usize,
    pub warmup_max: usize,
    pub handshake_timeout: Duration,
    pub max_pending: usize,
    pub max_pending_per_ip: usize,
    pub max_sessions: usize,
    /// A lane that hears nothing for this long is redialed (see `silence_for`).
    pub silence: Duration,
    /// TCP congestion algorithm of the lanes (the listener's or path's override; `None` = the
    /// tunnel's global choice).
    pub tcp_congestion: Option<String>,
}
impl Settings {
    pub fn from_options(options: &crate::parallax_carrier::Options) -> Self {
        Self {
            lanes: options.lanes,
            warmup_min: options.warmup_min,
            warmup_max: options.warmup_max,
            handshake_timeout: Duration::from_secs(options.handshake_timeout_sec),
            max_pending: options.max_pending,
            max_pending_per_ip: options.max_pending_per_ip,
            max_sessions: options.max_sessions,
            silence: SILENCE,
            tcp_congestion: None,
        }
    }
    pub fn with_silence(mut self, silence: Option<Duration>) -> Self {
        if let Some(silence) = silence {
            self.silence = silence;
        }
        self
    }
    pub fn with_congestion(mut self, congestion: Option<String>) -> Self {
        self.tcp_congestion = congestion;
        self
    }
}

fn random(bytes: &mut [u8]) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(bytes)
        .map_err(|_| anyhow!("Parallax random source failed"))
}

/// A warm-up size picked at random in `[minimum, maximum]` (0 when both are 0).
fn warmup_size(minimum: usize, maximum: usize) -> Result<usize> {
    if maximum == 0 {
        return Ok(0);
    }
    let mut bytes = [0; 8];
    random(&mut bytes)?;
    let span = (maximum - minimum) as u64 + 1;
    Ok(minimum + (u64::from_le_bytes(bytes) % span) as usize)
}

/// The address the FEC layer sees for a session: unique per session id and stable across lane
/// reconnects, so the KCP conversation keeps its peer entry when a lane is replaced. It lives in
/// the IPv6 unique-local range and never touches the network.
pub fn virtual_address(session: &SessionId) -> SocketAddr {
    let mut ip = [0u8; 16];
    ip[0] = 0xfd;
    ip[1..].copy_from_slice(&session[..15]);
    SocketAddr::new(Ipv6Addr::from(ip).into(), u16::from(session[15]) + 1)
}

fn session_of(address: SocketAddr) -> Option<SessionId> {
    let SocketAddr::V6(address) = address else {
        return None;
    };
    let ip = address.ip().octets();
    if ip[0] != 0xfd || !(1..=256).contains(&address.port()) {
        return None;
    }
    let mut session = [0u8; 16];
    session[..15].copy_from_slice(&ip[1..]);
    session[15] = (address.port() - 1) as u8;
    Some(session)
}

async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> io::Result<()> {
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(bytes);
    writer.write_all(&framed).await
}

async fn read_frame(reader: &mut (impl AsyncRead + Unpin), buffer: &mut [u8]) -> Result<usize> {
    let size = reader.read_u16().await? as usize;
    ensure!(
        (1..=buffer.len()).contains(&size),
        "invalid Parallax lane record length"
    );
    reader.read_exact(&mut buffer[..size]).await?;
    Ok(size)
}

fn noise(key: &Key) -> Result<Builder<'_>> {
    Ok(Builder::new(PATTERN.parse()?)
        .prologue(DOMAIN)?
        .psk(0, &*key.0)?)
}

/// The dialing side: says which session and lane this is; the answer proves the other side knows
/// the key and, through its ephemeral key, that the answer is fresh.
async fn dial_handshake(
    socket: &mut TcpStream,
    key: &Key,
    session: &SessionId,
    lane: u8,
) -> Result<TransportState> {
    let mut handshake = noise(key)?.build_initiator()?;
    let mut hello = [0u8; 18];
    hello[0] = VERSION;
    hello[1..17].copy_from_slice(session);
    hello[17] = lane;
    let mut output = [0u8; HANDSHAKE];
    let n = handshake.write_message(&hello, &mut output)?;
    write_frame(socket, &output[..n]).await?;
    let mut input = [0u8; HANDSHAKE];
    let n = read_frame(socket, &mut input).await?;
    let n = handshake.read_message(&input[..n], &mut output)?;
    ensure!(
        n == 1 && output[0] == VERSION,
        "unexpected Parallax lane answer"
    );
    Ok(handshake.into_transport_mode()?)
}

async fn answer_handshake(
    socket: &mut TcpStream,
    key: &Key,
) -> Result<(SessionId, u8, TransportState)> {
    let mut handshake = noise(key)?.build_responder()?;
    let mut input = [0u8; HANDSHAKE];
    let n = read_frame(socket, &mut input).await?;
    let mut hello = [0u8; HANDSHAKE];
    let n = handshake.read_message(&input[..n], &mut hello)?;
    ensure!(
        n == 18 && hello[0] == VERSION,
        "unexpected Parallax lane hello"
    );
    let session: SessionId = hello[1..17].try_into()?;
    let lane = hello[17];
    let mut output = [0u8; HANDSHAKE];
    let n = handshake.write_message(&[VERSION], &mut output)?;
    write_frame(socket, &output[..n]).await?;
    Ok((session, lane, handshake.into_transport_mode()?))
}

/// Runs one authenticated lane until it breaks. Sends `warmup` bytes of encrypted padding first
/// (always at least one record, which is the dialing side's proof of freshness), then the packets
/// from `outbound`. Packets read from the lane go to `deliver` tagged with `source`. `on_first`,
/// when given, runs once the first authenticated record arrived and may refuse the lane.
async fn run_lane(
    socket: TcpStream,
    state: TransportState,
    warmup: usize,
    outbound: &mut mpsc::Receiver<Vec<u8>>,
    deliver: &mpsc::Sender<(Vec<u8>, SocketAddr)>,
    source: SocketAddr,
    on_first: Option<&(dyn Fn() -> bool + Sync)>,
    silence: Duration,
    heard: Option<&AtomicU64>,
) -> Result<()> {
    let proved = AtomicBool::new(on_first.is_none());
    let proof = tokio::sync::Notify::new();
    let (mut reader, mut writer) = socket.into_split();
    let state = Mutex::new(state);
    let seal = |kind: u8, body: &[u8], records: &mut u64| -> Result<Vec<u8>> {
        let mut plain = Vec::with_capacity(body.len() + 1);
        plain.push(kind);
        plain.extend_from_slice(body);
        let mut sealed = vec![0u8; plain.len() + 16];
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        let n = state.write_message(&plain, &mut sealed)?;
        *records += 1;
        if *records % REKEY == 0 {
            state.rekey_outgoing();
        }
        sealed.truncate(n);
        Ok(sealed)
    };
    let read = async {
        let mut sealed = vec![0u8; MAX_RECORD];
        let mut plain = vec![0u8; MAX_RECORD];
        let mut records = 0u64;
        loop {
            let n = timeout(silence, read_frame(&mut reader, &mut sealed))
                .await
                .context("Parallax lane went silent")??;
            // Padding counts: the lane, and the session on it, are alive.
            if let Some(heard) = heard {
                heard.store(clock_ms(), Ordering::Relaxed);
            }
            let n = {
                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                let n = state.read_message(&sealed[..n], &mut plain)?;
                records += 1;
                if records % REKEY == 0 {
                    state.rekey_incoming();
                }
                n
            };
            ensure!(n >= 1, "empty Parallax lane record");
            if !proved.load(Ordering::Acquire)
                && let Some(on_first) = on_first
            {
                ensure!(on_first(), "Parallax lane not admitted");
                proved.store(true, Ordering::Release);
                proof.notify_one();
            }
            match plain[0] {
                KIND_PAD => {}
                KIND_PACKET => {
                    ensure!(n > 1, "empty Parallax lane packet");
                    deliver
                        .send((plain[1..n].to_vec(), source))
                        .await
                        .map_err(|_| anyhow!("Parallax lane receiver closed"))?;
                }
                _ => anyhow::bail!("unknown Parallax lane record"),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let write = async {
        // The answering side says nothing until the dialing side has proved it holds the fresh
        // session keys: a replayed first flight gets no warm-up and no packets.
        while !proved.load(Ordering::Acquire) {
            let notified = proof.notified();
            if proved.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
        let mut records = 0u64;
        let mut left = warmup.max(1);
        let mut pad = vec![0u8; PAD_CHUNK];
        while left > 0 {
            let size = left.min(PAD_CHUNK);
            random(&mut pad[..size])?;
            let record = seal(KIND_PAD, &pad[..size], &mut records)?;
            write_frame(&mut writer, &record).await?;
            left -= size;
        }
        let mut batch = Vec::new();
        loop {
            let packet = match timeout(KEEPALIVE, outbound.recv()).await {
                Ok(Some(packet)) => packet,
                Ok(None) => return Ok(()),
                Err(_) => {
                    let mut tiny = [0u8; 16];
                    random(&mut tiny)?;
                    let size = 1 + usize::from(tiny[0] % 15);
                    let record = seal(KIND_PAD, &tiny[..size], &mut records)?;
                    write_frame(&mut writer, &record).await?;
                    continue;
                }
            };
            batch.clear();
            let mut take = Some(packet);
            let mut count = 0;
            while let Some(packet) = take {
                ensure!(
                    (1..=MAX_PACKET).contains(&packet.len()),
                    "Parallax lane packet length"
                );
                let record = seal(KIND_PACKET, &packet, &mut records)?;
                batch.extend_from_slice(&(record.len() as u16).to_be_bytes());
                batch.extend_from_slice(&record);
                count += 1;
                take = if count < BATCH {
                    outbound.try_recv().ok()
                } else {
                    None
                };
            }
            writer.write_all(&batch).await?;
        }
    };
    let unproved = async {
        tokio::time::sleep(PROOF).await;
        if proved.load(Ordering::Acquire) {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        result = read => result,
        result = write => result,
        _ = unproved => anyhow::bail!("Parallax lane peer sent nothing under the fresh keys"),
    }
}

/// One outgoing queue per lane; packets stick to one lane (so KCP does not see reordering and
/// resend for nothing) and spill to another only when that lane is full or gone.
struct Picker {
    current: AtomicUsize,
}
impl Picker {
    fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
        }
    }
    fn pick<'a>(
        &self,
        lanes: impl Iterator<Item = (bool, &'a mpsc::Sender<Vec<u8>>)> + Clone,
    ) -> Option<usize> {
        let current = self.current.load(Ordering::Relaxed);
        if let Some((true, sender)) = lanes.clone().nth(current)
            && !sender.is_closed()
            && sender.capacity() > LANE_QUEUE / 4
        {
            return Some(current);
        }
        let best = lanes
            .enumerate()
            .filter(|(_, (up, sender))| *up && !sender.is_closed())
            .max_by_key(|(_, (_, sender))| sender.capacity())
            .map(|(index, _)| index)?;
        self.current.store(best, Ordering::Relaxed);
        Some(best)
    }
}

async fn queue(sender: &mpsc::Sender<Vec<u8>>, data: &[u8]) {
    let packet = data.to_vec();
    if let Err(mpsc::error::TrySendError::Full(packet)) = sender.try_send(packet) {
        // A full lane holds the sender back briefly, which the FEC send queue turns into
        // backpressure on KCP; after that the packet is dropped like a lost datagram.
        let _ = timeout(Duration::from_millis(100), sender.send(packet)).await;
    }
}

struct ClientSlot {
    sender: mpsc::Sender<Vec<u8>>,
    connected: Arc<AtomicBool>,
}

/// The dialing side's lanes for one KCP session.
pub struct ClientLanes {
    slots: Vec<ClientSlot>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    picker: Picker,
    source: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
    /// Lane connections made so far (each redial adds one).
    generations: Arc<AtomicU64>,
}
impl Drop for ClientLanes {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl ClientLanes {
    pub fn open(path: ClientPath, key: Key, settings: Settings) -> Result<Self> {
        let mut session = [0u8; 16];
        random(&mut session)?;
        let source = virtual_address(&session);
        let (deliver, incoming) = mpsc::channel(INCOMING_QUEUE);
        let generations = Arc::new(AtomicU64::new(0));
        let path = Arc::new(path);
        let mut slots = Vec::new();
        let mut tasks = Vec::new();
        for lane in 0..settings.lanes.clamp(1, MAX_LANES) {
            let (sender, mut outbound) = mpsc::channel(LANE_QUEUE);
            let connected = Arc::new(AtomicBool::new(false));
            let (path, key, settings, deliver, up, generations) = (
                path.clone(),
                key.clone(),
                settings.clone(),
                deliver.clone(),
                connected.clone(),
                generations.clone(),
            );
            tasks.push(tokio::spawn(async move {
                let mut pause = Duration::from_millis(250);
                loop {
                    let started = Instant::now();
                    let result = async {
                        let (socket, state) = timeout(settings.handshake_timeout, async {
                            let mut socket = crate::carrier::tcp_for_path(&path).await?;
                            limit_backlog(&socket);
                            let state =
                                dial_handshake(&mut socket, &key, &session, lane as u8).await?;
                            Ok::<_, anyhow::Error>((socket, state))
                        })
                        .await
                        .context("Parallax lane handshake timeout")??;
                        up.store(true, Ordering::Release);
                        let made = generations.fetch_add(1, Ordering::Relaxed) + 1;
                        tracing::debug!(lane, connections = made, "Parallax lane up");
                        let warmup = warmup_size(settings.warmup_min, settings.warmup_max)?;
                        run_lane(
                            socket,
                            state,
                            warmup,
                            &mut outbound,
                            &deliver,
                            source,
                            None,
                            settings.silence,
                            None,
                        )
                        .await
                    }
                    .await;
                    up.store(false, Ordering::Release);
                    // Stale packets of a dead lane are dropped; KCP resends what matters.
                    while outbound.try_recv().is_ok() {}
                    if let Err(error) = result {
                        tracing::debug!(lane, %error, "Parallax lane ended; dialing again");
                    }
                    pause = if started.elapsed() > Duration::from_secs(10) {
                        Duration::from_millis(250)
                    } else {
                        (pause * 2).min(Duration::from_secs(5))
                    };
                    tokio::time::sleep(crate::limits::jitter(pause)).await;
                }
            }));
            slots.push(ClientSlot { sender, connected });
        }
        Ok(Self {
            slots,
            incoming: tokio::sync::Mutex::new(incoming),
            picker: Picker::new(),
            source,
            tasks,
            generations,
        })
    }
    pub fn source(&self) -> SocketAddr {
        self.source
    }
    /// How many lane connections this session has made, redials included.
    pub fn lane_connections(&self) -> u64 {
        self.generations.load(Ordering::Relaxed)
    }
    pub fn connected(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.connected.load(Ordering::Acquire))
            .count()
    }
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        if !(1..=MAX_PACKET).contains(&data.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let lanes = self
            .slots
            .iter()
            .map(|slot| (slot.connected.load(Ordering::Acquire), &slot.sender));
        if let Some(index) = self.picker.pick(lanes) {
            queue(&self.slots[index].sender, data).await;
        }
        // With no lane up the packet is lost like a datagram; KCP resends it.
        Ok(data.len())
    }
    pub async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }
}

struct ServerLane {
    id: u64,
    sender: mpsc::Sender<Vec<u8>>,
    /// When the lane last received a record (padding included), on `clock_ms`.
    heard: Arc<AtomicU64>,
}
struct Session {
    ip: IpAddr,
    lanes: Vec<ServerLane>,
    picker: Picker,
    orphaned: Option<Instant>,
}
type Sessions = Arc<Mutex<HashMap<SessionId, Session>>>;

/// The answering side: one TCP listener, any number of sessions, each with its own lanes.
pub struct ServerLanes {
    sessions: Sessions,
    incoming: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    local: SocketAddr,
    task: JoinHandle<()>,
}
impl Drop for ServerLanes {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Adds a proven lane to its session, creating the session when it is new. Refuses a lane from a
/// different address than the session's first lane, a session over the lane limit, or a new
/// session over the session limit (sessions without lanes for a while are dropped first).
fn admit(
    sessions: &Sessions,
    session: SessionId,
    ip: IpAddr,
    lane: ServerLane,
    max_sessions: usize,
) -> bool {
    let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
    if !sessions.contains_key(&session) {
        if sessions.len() >= max_sessions {
            sessions.retain(|_, entry| {
                !entry
                    .orphaned
                    .is_some_and(|since| since.elapsed() >= Duration::from_secs(5))
            });
        }
        if sessions.len() >= max_sessions {
            return false;
        }
        sessions.insert(
            session,
            Session {
                ip,
                lanes: Vec::new(),
                picker: Picker::new(),
                orphaned: None,
            },
        );
    }
    let Some(entry) = sessions.get_mut(&session) else {
        return false;
    };
    if entry.ip != ip || entry.lanes.len() >= MAX_LANES {
        return false;
    }
    entry.lanes.push(lane);
    entry.orphaned = None;
    true
}

fn release(sessions: &Sessions, session: &SessionId, id: u64) {
    let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = sessions.get_mut(session) {
        entry.lanes.retain(|lane| lane.id != id);
        if entry.lanes.is_empty() {
            entry.orphaned = Some(Instant::now());
        }
    }
}

impl ServerLanes {
    pub async fn bind(address: &str, key: Key, settings: Settings) -> Result<Self> {
        let listener = TcpListener::bind(address)
            .await
            .context("bind Parallax lane listener")?;
        Self::from_listener(listener, key, settings)
    }
    pub fn from_listener(listener: TcpListener, key: Key, settings: Settings) -> Result<Self> {
        let local = listener.local_addr()?;
        let sessions: Sessions = Arc::default();
        let (deliver, incoming) = mpsc::channel(INCOMING_QUEUE);
        let task_sessions = sessions.clone();
        let task = tokio::spawn(async move {
            let sessions = task_sessions;
            let pending = PendingLimiter::new(settings.max_pending, settings.max_pending_per_ip);
            let mut tasks = JoinSet::new();
            let mut backoff = AcceptBackoff::new();
            let mut cleanup = tokio::time::interval(Duration::from_secs(30));
            let next = Arc::new(AtomicU64::new(0));
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut socket, peer) = match accepted {
                            Ok(value) => { backoff.succeeded(); value }
                            Err(error) => { if backoff.failed("Parallax lane accept", error).await.is_err() { break; } continue; }
                        };
                        let ip = peer.ip().to_canonical();
                        let Some(permit) = pending.try_enter(Some(ip)) else { continue; };
                        let (key, settings, sessions, deliver, next) =
                            (key.clone(), settings.clone(), sessions.clone(), deliver.clone(), next.clone());
                        tasks.spawn(async move {
                            let _ = socket.set_nodelay(true);
                            crate::carrier::tune_tcp(&socket, settings.tcp_congestion.as_deref());
                            limit_backlog(&socket);
                            let Ok(Ok((session, _lane, state))) =
                                timeout(settings.handshake_timeout, answer_handshake(&mut socket, &key)).await
                            else {
                                tracing::debug!("Parallax lane handshake failed");
                                return;
                            };
                            // A replayed first flight completes the handshake too: the lane stays
                            // a pending one (counted against the pending limits) until its first
                            // record under the fresh keys proves it, or it ends.
                            let permit = std::sync::Mutex::new(Some(permit));
                            let id = next.fetch_add(1, Ordering::Relaxed);
                            let (sender, mut outbound) = mpsc::channel(LANE_QUEUE);
                            let heard = Arc::new(AtomicU64::new(clock_ms()));
                            let lane = std::sync::Mutex::new(Some(ServerLane { id, sender, heard: heard.clone() }));
                            let admitted = AtomicBool::new(false);
                            let on_first = || {
                                let Some(lane) = lane.lock().unwrap_or_else(|e| e.into_inner()).take() else { return false; };
                                let ok = admit(&sessions, session, ip, lane, settings.max_sessions);
                                admitted.store(ok, Ordering::Release);
                                drop(permit.lock().unwrap_or_else(|e| e.into_inner()).take());
                                ok
                            };
                            let warmup = warmup_size(settings.warmup_min, settings.warmup_max).unwrap_or(0);
                            let result = run_lane(socket, state, warmup, &mut outbound, &deliver,
                                virtual_address(&session), Some(&on_first), settings.silence, Some(&heard)).await;
                            if admitted.load(Ordering::Acquire) {
                                release(&sessions, &session, id);
                            }
                            if let Err(error) = result {
                                tracing::debug!(%error, "Parallax lane ended");
                            }
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                    _ = cleanup.tick() => {
                        sessions.lock().unwrap_or_else(|e| e.into_inner())
                            .retain(|_, entry| !entry.orphaned.is_some_and(|since| since.elapsed() >= ORPHAN));
                    }
                }
            }
        });
        Ok(Self {
            sessions,
            incoming: tokio::sync::Mutex::new(incoming),
            local,
            task,
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    /// Whether a lane of the session behind `peer` received anything within `within`: lane
    /// keepalives keep an idle tunnel's session alive in the FEC layer above.
    pub fn heard_within(&self, peer: SocketAddr, within: Duration) -> bool {
        let Some(session) = session_of(peer) else { return false };
        let now = clock_ms();
        let within = within.as_millis() as u64;
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).get(&session).is_some_and(|entry| {
            entry.lanes.iter().any(|lane| now.saturating_sub(lane.heard.load(Ordering::Relaxed)) < within)
        })
    }
    pub async fn send_to(&self, data: &[u8], peer: SocketAddr) -> io::Result<usize> {
        if !(1..=MAX_PACKET).contains(&data.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let Some(session) = session_of(peer) else {
            return Err(io::ErrorKind::AddrNotAvailable.into());
        };
        let sender = {
            let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions.get(&session).and_then(|entry| {
                let lanes = entry.lanes.iter().map(|lane| (true, &lane.sender));
                entry
                    .picker
                    .pick(lanes)
                    .map(|index| entry.lanes[index].sender.clone())
            })
        };
        if let Some(sender) = sender {
            queue(&sender, data).await;
        }
        Ok(data.len())
    }
    pub async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }
    #[cfg(test)]
    fn lanes_of(&self, session: &SessionId) -> usize {
        self.sessions
            .lock()
            .unwrap()
            .get(session)
            .map_or(0, |entry| entry.lanes.len())
    }
}

/// Either side, as the FEC layer uses it.
pub enum Lanes {
    Client(ClientLanes),
    Server(ServerLanes),
}
impl Lanes {
    /// See `ServerLanes::heard_within`; the dialing side has no peer table to keep.
    pub fn heard_within(&self, peer: SocketAddr, within: Duration) -> bool {
        match self {
            Self::Client(_) => false,
            Self::Server(lanes) => lanes.heard_within(peer, within),
        }
    }
    pub async fn send_to(&self, data: &[u8], peer: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Client(lanes) => lanes.send(data).await,
            Self::Server(lanes) => lanes.send_to(data, peer).await,
        }
    }
    pub async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        match self {
            Self::Client(lanes) => lanes.recv().await,
            Self::Server(lanes) => lanes.recv().await,
        }
    }
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Client(lanes) => lanes.source(),
            Self::Server(lanes) => lanes.local_addr(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Key {
        Key::new(Zeroizing::new([byte; 32]))
    }
    fn settings(lanes: usize) -> Settings {
        Settings {
            lanes,
            warmup_min: 4096,
            warmup_max: 8192,
            handshake_timeout: Duration::from_secs(5),
            max_pending: 64,
            max_pending_per_ip: 32,
            max_sessions: 8,
            silence: SILENCE,
            tcp_congestion: None,
        }
    }
    fn path(address: SocketAddr) -> ClientPath {
        serde_json::from_value(serde_json::json!({
            "addr": address.to_string(), "transport": "parallax",
            "server_public_key": "01".repeat(32)
        }))
        .unwrap()
    }
    async fn until(mut check: impl FnMut() -> bool) {
        for _ in 0..250 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("condition never became true");
    }

    #[test]
    fn the_lane_silence_stays_under_the_tunnels_own_probe_time() {
        assert_eq!(silence_for(3), Duration::from_secs(4), "the default probe time keeps 4 s");
        assert_eq!(silence_for(2), Duration::from_secs(2));
        assert_eq!(silence_for(1), Duration::from_secs(2), "never under 2 s (keepalives every second)");
        assert_eq!(silence_for(60), SILENCE);
    }

    /// An idle session with healthy lanes is still heard (keepalives), so the FEC peer table
    /// above keeps it; a session nothing was heard from for long is not.
    #[tokio::test]
    async fn lane_keepalives_count_as_hearing_the_session() -> Result<()> {
        let server = ServerLanes::bind("127.0.0.1:0", key(16), settings(1)).await?;
        let client = ClientLanes::open(path(server.local_addr()), key(16), settings(1))?;
        until(|| client.connected() == 1).await;
        client.send(b"x").await?;
        let (_, peer) = timeout(Duration::from_secs(5), server.recv()).await??;
        // No data for a while, only keepalives.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(server.heard_within(peer, Duration::from_secs(2)), "keepalives were heard");
        assert!(!server.heard_within("192.0.2.1:9".parse().unwrap(), Duration::from_secs(60)), "an address that is no session");
        drop(client);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!server.heard_within(peer, Duration::from_secs(1)), "nothing heard once the client went");
        Ok(())
    }

    #[test]
    fn virtual_addresses_round_trip_and_stay_apart_from_real_ones() {
        for byte in [0u8, 1, 127, 255] {
            let session = [byte; 16];
            assert_eq!(session_of(virtual_address(&session)), Some(session));
        }
        assert_eq!(session_of("192.0.2.1:443".parse().unwrap()), None);
        assert_eq!(session_of("[2001:db8::1]:5".parse().unwrap()), None);
        assert_ne!(virtual_address(&[1; 16]), virtual_address(&[2; 16]));
    }

    #[test]
    fn warmup_sizes_stay_in_range_and_vary() {
        let sizes: Vec<_> = (0..64).map(|_| warmup_size(1000, 2000).unwrap()).collect();
        assert!(sizes.iter().all(|size| (1000..=2000).contains(size)));
        assert!(sizes.iter().any(|size| *size != sizes[0]), "the size is random");
        assert_eq!(warmup_size(0, 0).unwrap(), 0);
        assert_eq!(warmup_size(5, 5).unwrap(), 5);
    }

    #[tokio::test]
    async fn packets_cross_both_ways_and_a_wrong_key_is_refused() -> Result<()> {
        let server = ServerLanes::bind("127.0.0.1:0", key(7), settings(2)).await?;
        let address = server.local_addr();
        let client = ClientLanes::open(path(address), key(7), settings(2))?;
        until(|| client.connected() == 2).await;
        for size in [1usize, 700, MAX_PACKET] {
            client.send(&vec![42; size]).await?;
            let (packet, from) = timeout(Duration::from_secs(5), server.recv()).await??;
            assert_eq!(packet, vec![42; size]);
            assert_eq!(from, client.source());
            server.send_to(&vec![43; size], from).await?;
            let (back, _) = timeout(Duration::from_secs(5), client.recv()).await??;
            assert_eq!(back, vec![43; size]);
        }
        assert!(client.send(&vec![0; MAX_PACKET + 1]).await.is_err());
        let stranger = ClientLanes::open(path(address), key(8), settings(1))?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(stranger.connected(), 0, "a lane with the wrong key never comes up");
        Ok(())
    }

    /// A recorded first flight replayed on a new connection gets an answer but can never send a
    /// record under the fresh keys, so it is never attached to a session.
    #[tokio::test]
    async fn a_replayed_first_flight_never_joins_a_session() -> Result<()> {
        let server = ServerLanes::bind("127.0.0.1:0", key(9), settings(1)).await?;
        let session = [5u8; 16];
        let mut initiator = noise(&key(9))?.build_initiator()?;
        let mut hello = [0u8; 18];
        hello[0] = VERSION;
        hello[1..17].copy_from_slice(&session);
        let mut first = [0u8; HANDSHAKE];
        let n = initiator.write_message(&hello, &mut first)?;
        let recorded = first[..n].to_vec();
        drop(initiator);
        let mut replay = TcpStream::connect(server.local_addr()).await?;
        write_frame(&mut replay, &recorded).await?;
        let mut answer = [0u8; HANDSHAKE];
        assert!(read_frame(&mut replay, &mut answer).await? > 0);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(server.lanes_of(&session), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_lane_from_another_address_cannot_join_a_session() {
        let sessions: Sessions = Arc::default();
        let lane = |id| ServerLane {
            id,
            sender: mpsc::channel(1).0,
            heard: Arc::default(),
        };
        let session = [3u8; 16];
        assert!(admit(&sessions, session, "192.0.2.1".parse().unwrap(), lane(0), 4));
        assert!(!admit(&sessions, session, "192.0.2.2".parse().unwrap(), lane(1), 4));
        assert!(admit(&sessions, session, "192.0.2.1".parse().unwrap(), lane(2), 4));
        for id in 3..(MAX_LANES as u64 + 5) {
            admit(&sessions, session, "192.0.2.1".parse().unwrap(), lane(id), 4);
        }
        assert_eq!(sessions.lock().unwrap()[&session].lanes.len(), MAX_LANES);
        for other in 10..13u8 {
            assert!(admit(&sessions, [other; 16], "192.0.2.9".parse().unwrap(), lane(99), 4));
        }
        assert!(
            !admit(&sessions, [20; 16], "192.0.2.9".parse().unwrap(), lane(100), 4),
            "the session limit holds"
        );
        release(&sessions, &[10; 16], 99);
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(
            admit(&sessions, [20; 16], "192.0.2.9".parse().unwrap(), lane(101), 4),
            "a session without lanes makes room"
        );
    }

    /// Losing the lane in use moves traffic to the other lane at once.
    #[tokio::test]
    async fn traffic_moves_to_another_lane_when_one_is_lost() -> Result<()> {
        let server = ServerLanes::bind("127.0.0.1:0", key(11), settings(2)).await?;
        let client = ClientLanes::open(path(server.local_addr()), key(11), settings(2))?;
        until(|| client.connected() == 2).await;
        client.send(b"first").await?;
        let (_, from) = timeout(Duration::from_secs(5), server.recv()).await??;
        let session = session_of(from).unwrap();
        until(|| server.lanes_of(&session) == 2).await;
        // The lane's TCP connection closes with its task; the server notices and drops it.
        client.tasks[0].abort();
        until(|| server.lanes_of(&session) == 1).await;
        for round in 0..20u8 {
            client.send(&[round; 100]).await?;
            let (packet, _) = timeout(Duration::from_secs(5), server.recv()).await??;
            assert_eq!(packet, vec![round; 100]);
            server.send_to(&[round; 50], from).await?;
            let (packet, _) = timeout(Duration::from_secs(5), client.recv()).await??;
            assert_eq!(packet, vec![round; 50]);
        }
        Ok(())
    }

    /// When every lane breaks (here: the server restarts on the same port) the client dials them
    /// again under the same session, so the FEC layer keeps seeing the same peer address.
    #[tokio::test]
    async fn broken_lanes_are_dialed_again_under_the_same_session() -> Result<()> {
        let server = ServerLanes::bind("127.0.0.1:0", key(12), settings(2)).await?;
        let address = server.local_addr();
        let client = ClientLanes::open(path(address), key(12), settings(2))?;
        until(|| client.connected() == 2).await;
        let before = client.lane_connections();
        drop(server);
        until(|| client.connected() == 0).await;
        let server = ServerLanes::bind(&address.to_string(), key(12), settings(2)).await?;
        until(|| client.connected() == 2).await;
        assert!(client.lane_connections() >= before + 2);
        client.send(b"again").await?;
        let (packet, from) = timeout(Duration::from_secs(5), server.recv()).await??;
        assert_eq!((packet.as_slice(), from), (&b"again"[..], client.source()));
        Ok(())
    }

    /// A replayed first flight stays a pending connection until it proves itself (it never does):
    /// it gets no warm-up, and it counts against the pending limit until it is gone.
    #[tokio::test]
    async fn a_replayed_first_flight_holds_a_pending_slot_and_gets_nothing() -> Result<()> {
        let mut tight = settings(1);
        tight.max_pending = 1;
        tight.max_pending_per_ip = 1;
        let server = ServerLanes::bind("127.0.0.1:0", key(14), tight).await?;
        let mut initiator = noise(&key(14))?.build_initiator()?;
        let mut hello = [0u8; 18];
        hello[0] = VERSION;
        let mut first = [0u8; HANDSHAKE];
        let n = initiator.write_message(&hello, &mut first)?;
        let mut replay = TcpStream::connect(server.local_addr()).await?;
        write_frame(&mut replay, &first[..n]).await?;
        let mut answer = [0u8; HANDSHAKE];
        assert!(read_frame(&mut replay, &mut answer).await? > 0);
        let mut more = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(500), replay.read(&mut more)).await.is_err(),
            "no warm-up before the proof"
        );
        let client = ClientLanes::open(path(server.local_addr()), key(14), settings(1))?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(client.connected(), 0, "the replay still holds the only pending slot");
        drop(replay);
        for _ in 0..500 {
            if client.connected() == 1 {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the slot was not given back when the replay went away");
    }

    /// Lanes that stall without closing (a black hole between the servers: no data, no reset)
    /// are given up within `SILENCE` and dialed again under the same session, well before the
    /// tunnel's own unanswered-probe time would replace the session and its streams.
    #[tokio::test]
    async fn silently_stalled_lanes_are_replaced_under_the_same_session() -> Result<()> {
        let server = ServerLanes::bind("127.0.0.1:0", key(15), settings(2)).await?;
        let target = server.local_addr();
        let relay = TcpListener::bind("127.0.0.1:0").await?;
        let relay_address = relay.local_addr()?;
        let frozen: Arc<Mutex<Vec<Arc<AtomicBool>>>> = Arc::default();
        let switches = frozen.clone();
        tokio::spawn(async move {
            while let Ok((inside, _)) = relay.accept().await {
                let Ok(outside) = TcpStream::connect(target).await else { continue };
                let stop = Arc::new(AtomicBool::new(false));
                switches.lock().unwrap().push(stop.clone());
                let (a_read, a_write) = inside.into_split();
                let (b_read, b_write) = outside.into_split();
                for (mut from, mut to, stop) in [
                    (Box::new(a_read) as Box<dyn AsyncRead + Unpin + Send>, Box::new(b_write) as Box<dyn AsyncWrite + Unpin + Send>, stop.clone()),
                    (Box::new(b_read) as Box<dyn AsyncRead + Unpin + Send>, Box::new(a_write) as Box<dyn AsyncWrite + Unpin + Send>, stop.clone()),
                ] {
                    tokio::spawn(async move {
                        let mut buffer = vec![0u8; 16384];
                        loop {
                            let Ok(n) = from.read(&mut buffer).await else { return };
                            if n == 0 {
                                return;
                            }
                            // Frozen: swallow everything, close nothing.
                            if !stop.load(Ordering::Relaxed) && to.write_all(&buffer[..n]).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            }
        });
        let client = ClientLanes::open(path(relay_address), key(15), settings(2))?;
        until(|| client.connected() == 2).await;
        client.send(b"before").await?;
        let (_, from) = timeout(Duration::from_secs(5), server.recv()).await??;
        assert_eq!(from, client.source());
        for stop in frozen.lock().unwrap().iter() {
            stop.store(true, Ordering::Relaxed);
        }
        let started = Instant::now();
        let packet = loop {
            client.send(b"after").await?;
            if let Ok(received) = timeout(Duration::from_millis(250), server.recv()).await {
                let (packet, from) = received?;
                assert_eq!(from, client.source(), "the same session carries on");
                if packet == b"after" {
                    break packet;
                }
            }
            assert!(started.elapsed() < Duration::from_secs(15), "the stalled lanes were never replaced");
        };
        assert_eq!(packet, b"after");
        assert!(started.elapsed() >= SILENCE / 2, "the frozen lanes really carried nothing");
        Ok(())
    }

    #[tokio::test]
    async fn several_clients_share_one_listener() -> Result<()> {
        let server = ServerLanes::bind("127.0.0.1:0", key(13), settings(2)).await?;
        let mut clients = Vec::new();
        for _ in 0..3 {
            clients.push(ClientLanes::open(path(server.local_addr()), key(13), settings(2))?);
        }
        for client in &clients {
            until(|| client.connected() == 2).await;
        }
        for (index, client) in clients.iter().enumerate() {
            client.send(&[index as u8; 10]).await?;
        }
        let mut seen = HashMap::new();
        for _ in 0..3 {
            let (packet, from) = timeout(Duration::from_secs(5), server.recv()).await??;
            seen.insert(packet[0], from);
        }
        for (index, client) in clients.iter().enumerate() {
            assert_eq!(seen[&(index as u8)], client.source());
            server.send_to(&[index as u8 + 100; 5], client.source()).await?;
            let (packet, _) = timeout(Duration::from_secs(5), client.recv()).await??;
            assert_eq!(packet, vec![index as u8 + 100; 5]);
        }
        Ok(())
    }
}
