//! Explicit-peer link diagnostics. Only operator-selected endpoints are contacted.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    sync::{Notify, Semaphore},
    task::JoinSet,
    time::{self, Instant},
};

const MAGIC: &[u8; 5] = b"EZLT\x01";
const SESSION: u8 = 0;
const ECHO: u8 = 1;
const UPLOAD: u8 = 2;
const DOWNLOAD: u8 = 3;
const REVERSE_TCP: u8 = 4;
const REVERSE_UDP: u8 = 5;
const FINISH: u8 = 6;
const MTU_REPORT: u8 = 7;
const REVERSE_MTU: u8 = 8;
const BLOCK: usize = 32_768;
const MAX_FRAME: usize = 65_536;
const MAX_TRANSFER_FRAMES: u64 = 8192; // 256 MiB per direction
const UDP_HEADER: usize = 41; // magic(5), token(32), counter(4)

/// UDP payload sizes the MTU sweep tries, smallest first. The ladder is denser near the usual
/// Ethernet limit (1472 bytes of payload in a 1500-byte IPv4 packet) and the few dozen bytes
/// below it that tunnels and PPPoE take away.
pub const MTU_SIZES: [usize; 16] = [
    548, 1000, 1200, 1252, 1280, 1300, 1332, 1350, 1372, 1392, 1400, 1412, 1432, 1452, 1464, 1472,
];
/// Pause between probe datagrams, so a burst does not fill a queue and look like a size limit.
const MTU_GAP: Duration = Duration::from_millis(2);

#[derive(Clone, Debug)]
pub struct ListenOptions {
    pub bind: SocketAddr,
    pub expected_peer: IpAddr,
    pub extra_ports: Vec<u16>,
    pub wait: Duration,
    pub keep: bool,
}
#[derive(Clone, Debug)]
pub struct ProbeOptions {
    pub peer: SocketAddr,
    pub bind: IpAddr,
    pub local_port: u16,
    pub extra_ports: Vec<u16>,
    pub seconds: Duration,
    pub timeout: Duration,
    pub quick: bool,
    /// Also measure the largest UDP datagram that crosses the path in each direction.
    pub mtu: bool,
}
impl ListenOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.expected_peer.is_unspecified() && !self.expected_peer.is_multicast(),
            "linktest requires one explicit unicast peer IP"
        );
        ensure!(
            self.bind.is_ipv4() == self.expected_peer.is_ipv4(),
            "linktest bind and peer IP families differ"
        );
        ensure!(
            (Duration::from_secs(1)..=Duration::from_secs(3600)).contains(&self.wait),
            "linktest wait must be 1..3600 seconds"
        );
        check_ports(&self.extra_ports)
    }
}
impl ProbeOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.peer.port() != 0
                && !self.peer.ip().is_unspecified()
                && !self.peer.ip().is_multicast(),
            "linktest requires an explicit unicast peer and nonzero port"
        );
        ensure!(
            self.bind.is_ipv4() == self.peer.is_ipv4(),
            "linktest bind and peer IP families differ"
        );
        ensure!(
            (Duration::from_millis(50)..=Duration::from_secs(30)).contains(&self.seconds),
            "linktest throughput duration must be 0.05..30 seconds"
        );
        ensure!(
            (Duration::from_millis(50)..=Duration::from_secs(60)).contains(&self.timeout),
            "linktest timeout must be 0.05..60 seconds"
        );
        check_ports(&self.extra_ports)
    }
}
fn check_ports(ports: &[u16]) -> Result<()> {
    ensure!(
        ports.len() <= 16 && ports.iter().all(|p| *p != 0),
        "linktest permits at most 16 explicit nonzero extra ports"
    );
    ensure!(
        ports.iter().copied().collect::<HashSet<_>>().len() == ports.len(),
        "linktest extra ports must be unique"
    );
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub ok: bool,
    pub round_trips: usize,
    pub rtt_ms: f64,
    pub error: Option<String>,
}
impl CheckResult {
    fn failure(error: impl std::fmt::Display) -> Self {
        Self {
            ok: false,
            round_trips: 0,
            rtt_ms: 0.,
            error: Some(error.to_string()),
        }
    }
}
#[derive(Debug, Serialize)]
pub struct DatagramResult {
    pub sent: usize,
    pub received: usize,
    pub loss_percent: f64,
    pub integrity: bool,
    pub rtt_ms: f64,
    pub error: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ThroughputResult {
    pub bytes: u64,
    pub seconds: f64,
    pub mbps: f64,
    pub integrity: bool,
    pub error: Option<String>,
}
impl ThroughputResult {
    fn new(bytes: u64, seconds: f64, integrity: bool) -> Self {
        Self {
            bytes,
            seconds,
            mbps: bytes as f64 * 8. / seconds.max(0.000001) / 1_000_000.,
            integrity,
            error: None,
        }
    }
    fn failure(error: impl std::fmt::Display) -> Self {
        Self {
            bytes: 0,
            seconds: 0.,
            mbps: 0.,
            integrity: false,
            error: Some(error.to_string()),
        }
    }
}
#[derive(Debug, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub tcp: CheckResult,
    pub udp: DatagramResult,
}
/// Datagrams of one payload size seen by the receiving side, per direction.
#[derive(Debug, Serialize)]
pub struct MtuSize {
    pub payload: usize,
    /// Received by the peer out of `probes_per_size`, sent from here.
    pub forward: u16,
    /// Received here out of `probes_per_size`, sent by the peer.
    pub reverse: u16,
    /// False when the sending machine's own network stack refused the size (its interface or a
    /// path limit it already learned is smaller).
    pub forward_sendable: bool,
    pub reverse_sendable: bool,
}
/// The largest UDP datagram that crosses the path, found with the don't-fragment bit set so a
/// router cannot hide the limit by fragmenting. Each direction is measured on its own: the
/// receiving side counts what arrived.
#[derive(Debug, Default, Serialize)]
pub struct MtuReport {
    pub probes_per_size: u8,
    /// Both machines managed to set the don't-fragment bit. Without it the numbers can be too
    /// high, because oversize datagrams may have been fragmented on the way.
    pub dont_fragment: bool,
    pub sizes: Vec<MtuSize>,
    pub forward_max_payload: Option<usize>,
    pub reverse_max_payload: Option<usize>,
    /// The smaller of the two directions.
    pub max_payload: Option<usize>,
    /// IP and UDP header bytes that come on top of the payload (28 for IPv4, 48 for IPv6).
    pub header_bytes: usize,
    /// `max_payload` plus `header_bytes`.
    pub path_mtu: Option<usize>,
    /// Every size tried passed: the path carries at least this much, the sweep stopped at its
    /// largest size.
    pub at_ladder_top: bool,
    /// A larger size passed after a smaller one failed (random loss or load balancing over paths
    /// with different limits). The result stops at the first failure.
    pub irregular: bool,
    pub error: Option<String>,
}
impl MtuReport {
    fn failed(error: impl std::fmt::Display) -> Self {
        Self {
            error: Some(error.to_string()),
            ..Self::default()
        }
    }
    /// Turns per-size counts into the largest size that works in each direction. A size works
    /// when more than half of its probes arrived; the answer is the largest size such that it and
    /// every smaller size work.
    pub fn from_counts(
        sizes: &[usize],
        probes: u8,
        forward: &[(u16, bool)],
        reverse: &[(u16, bool)],
        dont_fragment: bool,
        ipv4: bool,
    ) -> Self {
        let works = |counts: &[(u16, bool)], i: usize| {
            counts[i].1 && u32::from(probes) < u32::from(counts[i].0) * 2
        };
        let contiguous = |counts: &[(u16, bool)]| {
            let mut best = None;
            for (i, size) in sizes.iter().enumerate() {
                if works(counts, i) {
                    best = Some(*size);
                } else {
                    break;
                }
            }
            best
        };
        let irregular = |counts: &[(u16, bool)]| {
            let first_failure = (0..sizes.len()).find(|i| !works(counts, *i));
            first_failure.is_some_and(|f| (f + 1..sizes.len()).any(|i| works(counts, i)))
        };
        let forward_max = contiguous(forward);
        let reverse_max = contiguous(reverse);
        let max_payload = match (forward_max, reverse_max) {
            (Some(a), Some(b)) => Some(a.min(b)),
            _ => None,
        };
        let header_bytes = if ipv4 { 28 } else { 48 };
        let top = sizes.last().copied();
        Self {
            probes_per_size: probes,
            dont_fragment,
            sizes: sizes
                .iter()
                .enumerate()
                .map(|(i, size)| MtuSize {
                    payload: *size,
                    forward: forward[i].0,
                    reverse: reverse[i].0,
                    forward_sendable: forward[i].1,
                    reverse_sendable: reverse[i].1,
                })
                .collect(),
            forward_max_payload: forward_max,
            reverse_max_payload: reverse_max,
            max_payload,
            header_bytes,
            path_mtu: max_payload.map(|p| p + header_bytes),
            at_ladder_top: max_payload.is_some() && max_payload == top,
            irregular: irregular(forward) || irregular(reverse),
            error: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LinkReport {
    pub quick: bool,
    pub peer: SocketAddr,
    pub reverse_listener: SocketAddr,
    pub tcp: CheckResult,
    pub udp: DatagramResult,
    pub reverse_tcp: CheckResult,
    pub reverse_udp: DatagramResult,
    pub upload: ThroughputResult,
    pub download: ThroughputResult,
    pub ports: Vec<PortResult>,
    pub mtu: Option<MtuReport>,
    pub verdict: crate::linkverdict::Verdict,
}
impl LinkReport {
    pub fn passed(&self) -> bool {
        self.tcp.ok
            && self.reverse_tcp.ok
            && datagrams_passed(&self.udp)
            && datagrams_passed(&self.reverse_udp)
            && self.upload.integrity
            && self.download.integrity
            && self.upload.bytes > 0
            && self.download.bytes > 0
            && self.upload.error.is_none()
            && self.download.error.is_none()
            && self
                .ports
                .iter()
                .all(|p| p.tcp.ok && datagrams_passed(&p.udp))
    }
}
fn datagrams_passed(result: &DatagramResult) -> bool {
    result.sent > 0 && result.received == result.sent && result.integrity && result.error.is_none()
}

struct Session {
    peer: IpAddr,
    expires: Instant,
    udp_left: usize,
    tcp_left: usize,
    /// UDP datagrams received with this token, by datagram size (for the MTU sweep).
    sizes: HashMap<usize, u32>,
}
struct State {
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    peer: IpAddr,
    finished: Notify,
    keep: bool,
}
impl State {
    fn register(&self, token: [u8; 32]) -> Result<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("linktest session lock poisoned"))?;
        sessions.retain(|_, v| v.expires > Instant::now());
        ensure!(sessions.len() < 64, "linktest session capacity reached");
        sessions.insert(
            token,
            Session {
                peer: self.peer,
                expires: Instant::now() + Duration::from_secs(180),
                udp_left: 4096,
                tcp_left: 128,
                sizes: HashMap::new(),
            },
        );
        Ok(())
    }
    fn note_size(&self, token: &[u8; 32], size: usize) {
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(session) = sessions.get_mut(token)
        {
            let count = session.sizes.entry(size).or_insert(0);
            *count = count.saturating_add(1);
        }
    }
    fn sizes_seen(&self, token: &[u8; 32], sizes: &[usize]) -> Vec<u16> {
        let Ok(sessions) = self.sessions.lock() else {
            return vec![0; sizes.len()];
        };
        sizes
            .iter()
            .map(|size| {
                sessions
                    .get(token)
                    .and_then(|s| s.sizes.get(size))
                    .map_or(0, |count| (*count).min(u32::from(u16::MAX)) as u16)
            })
            .collect()
    }
    fn valid(&self, token: &[u8; 32], peer: IpAddr, udp: bool) -> bool {
        if peer != self.peer {
            return false;
        }
        let Ok(mut sessions) = self.sessions.lock() else {
            return false;
        };
        if let Some(session) = sessions.get_mut(token) {
            if session.peer != peer || session.expires <= Instant::now() {
                return false;
            }
            if udp {
                if session.udp_left == 0 {
                    return false;
                }
                session.udp_left -= 1;
            } else {
                if session.tcp_left == 0 {
                    return false;
                }
                session.tcp_left -= 1;
            }
            true
        } else {
            false
        }
    }
}
fn random_token() -> Result<[u8; 32]> {
    let mut token = [0; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut token)
        .map_err(|_| anyhow::anyhow!("linktest random token generation failed"))?;
    Ok(token)
}

/// Listen until the time limit or an authorized probe finishes (unless keep).
pub async fn listen(options: ListenOptions) -> Result<()> {
    options.validate()?;
    let state = Arc::new(State {
        sessions: Mutex::new(HashMap::new()),
        peer: options.expected_peer,
        finished: Notify::new(),
        keep: options.keep,
    });
    let mut tasks = JoinSet::new();
    let base = spawn_pair(options.bind, state.clone(), &mut tasks).await?;
    for port in options.extra_ports {
        if port != base.port() {
            spawn_pair(SocketAddr::new(base.ip(), port), state.clone(), &mut tasks).await?;
        }
    }
    tracing::info!(%base,peer=%options.expected_peer,"local linktest listeners ready");
    tokio::select! {
        _=time::sleep(options.wait)=>{},
        _=state.finished.notified()=>{},
        result=tasks.join_next()=> {if let Some(result)=result {result??;}}
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
async fn spawn_pair(
    bind: SocketAddr,
    state: Arc<State>,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<SocketAddr> {
    let tcp = TcpListener::bind(bind)
        .await
        .context("bind linktest TCP listener")?;
    let address = tcp.local_addr()?;
    let udp = UdpSocket::bind(address)
        .await
        .context("bind linktest UDP listener")?;
    tasks.spawn(tcp_server(tcp, state.clone()));
    tasks.spawn(udp_server(udp, state));
    Ok(address)
}
async fn tcp_server(listener: TcpListener, state: Arc<State>) -> Result<()> {
    let limit = Arc::new(Semaphore::new(16));
    let mut handlers = JoinSet::new();
    loop {
        tokio::select! {
            result=listener.accept()=> {
                // One failing accept (e.g. a pending error from a reset connection, or EMFILE)
                // must not end the whole listener, the same as udp_server below.
                let (stream,peer)=match result {
                    Ok(accepted)=>accepted,
                    Err(error)=>{
                        tracing::debug!(%error,"linktest TCP accept failed");
                        continue;
                    }
                };
                if peer.ip()!=state.peer {continue;}
                let Ok(permit)=limit.clone().try_acquire_owned()else {continue};
                let state=state.clone();handlers.spawn(async move {
                    let _permit=permit;
                    let _=time::timeout(Duration::from_secs(90),handle_tcp(stream,peer,state)).await;
                });
            },
            _=handlers.join_next(),if !handlers.is_empty()=>{}
        }
    }
}
async fn udp_server(socket: UdpSocket, state: Arc<State>) -> Result<()> {
    let mut bytes = vec![0; 8193];
    loop {
        // One failing receive or send is one lost datagram, not the end of the listener.
        let (size, peer) = match socket.recv_from(&mut bytes).await {
            Ok(received) => received,
            Err(error) => {
                tracing::debug!(%error, "linktest UDP receive failed");
                time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if !(UDP_HEADER..=8192).contains(&size) || bytes[..5] != *MAGIC {
            continue;
        }
        let token: [u8; 32] = bytes[5..37].try_into()?;
        if state.valid(&token, peer.ip(), true) {
            state.note_size(&token, size);
            if let Err(error) = socket.send_to(&bytes[..size], peer).await {
                tracing::debug!(%error, "linktest UDP reply failed");
            }
        }
    }
}
async fn handle_tcp(mut stream: TcpStream, peer: SocketAddr, state: Arc<State>) -> Result<()> {
    let mut header = [0; 38];
    stream.read_exact(&mut header).await?;
    ensure!(header[..5] == *MAGIC, "invalid linktest request");
    let token: [u8; 32] = header[6..].try_into()?;
    if header[5] == SESSION {
        let token = random_token()?;
        state.register(token)?;
        stream.write_all(&token).await?;
        return Ok(());
    }
    ensure!(
        state.valid(&token, peer.ip(), false),
        "unknown/expired linktest session"
    );
    match header[5] {
        ECHO => {
            let frame = read_frame(&mut stream).await?;
            write_frame(&mut stream, &frame).await?;
        }
        UPLOAD => {
            let (bytes, valid) = receive_transfer(&mut stream).await?;
            stream.write_u64(bytes).await?;
            stream.write_u8(u8::from(valid)).await?;
        }
        DOWNLOAD => {
            let millis = stream.read_u32().await?;
            ensure!((50..=30_000).contains(&millis), "invalid linktest duration");
            send_transfer(&mut stream, Duration::from_millis(u64::from(millis))).await?;
        }
        REVERSE_TCP => {
            let port = stream.read_u16().await?;
            ensure!(port != 0, "reverse port cannot be zero");
            let start = Instant::now();
            let result = tcp_check(
                SocketAddr::new(peer.ip(), port),
                stream.local_addr()?.ip(),
                token,
                Duration::from_secs(5),
            )
            .await;
            stream.write_u8(u8::from(result.ok)).await?;
            stream.write_u64(start.elapsed().as_micros() as u64).await?;
        }
        REVERSE_UDP => {
            let port = stream.read_u16().await?;
            ensure!(port != 0, "reverse port cannot be zero");
            let count = usize::from(stream.read_u8().await?);
            ensure!((1..=32).contains(&count), "invalid reverse datagram count");
            let socket = UdpSocket::bind(SocketAddr::new(stream.local_addr()?.ip(), 0)).await?;
            let result = udp_check(
                &socket,
                SocketAddr::new(peer.ip(), port),
                token,
                count,
                Duration::from_secs(5),
            )
            .await;
            stream.write_u32(result.received as u32).await?;
            stream.write_u8(u8::from(result.integrity)).await?;
            stream.write_u64((result.rtt_ms * 1000.) as u64).await?;
        }
        MTU_REPORT => {
            let count = usize::from(stream.read_u8().await?);
            ensure!((1..=32).contains(&count), "invalid MTU size count");
            let mut sizes = Vec::with_capacity(count);
            for _ in 0..count {
                sizes.push(usize::from(stream.read_u16().await?));
            }
            for seen in state.sizes_seen(&token, &sizes) {
                stream.write_u16(seen).await?;
            }
        }
        REVERSE_MTU => {
            let port = stream.read_u16().await?;
            ensure!(port != 0, "reverse port cannot be zero");
            let probes = usize::from(stream.read_u8().await?);
            ensure!((1..=10).contains(&probes), "invalid MTU probe count");
            let count = usize::from(stream.read_u8().await?);
            ensure!((1..=32).contains(&count), "invalid MTU size count");
            let mut sizes = Vec::with_capacity(count);
            for _ in 0..count {
                let size = usize::from(stream.read_u16().await?);
                ensure!(
                    (UDP_HEADER..=8192).contains(&size),
                    "invalid MTU probe size"
                );
                sizes.push(size);
            }
            let socket = UdpSocket::bind(SocketAddr::new(stream.local_addr()?.ip(), 0)).await?;
            let dont_fragment = set_dont_fragment(&socket);
            let sendable = send_ladder(
                &socket,
                SocketAddr::new(peer.ip(), port),
                token,
                &sizes,
                probes,
            )
            .await?;
            stream.write_u8(u8::from(dont_fragment)).await?;
            for accepted in sendable {
                stream.write_u8(u8::from(accepted)).await?;
            }
        }
        FINISH => {
            stream.write_u8(1).await?;
            if !state.keep {
                state.finished.notify_one();
            }
        }
        _ => anyhow::bail!("unknown linktest operation"),
    }
    Ok(())
}
async fn open(peer: SocketAddr, bind: IpAddr, token: [u8; 32], operation: u8) -> Result<TcpStream> {
    let socket = if peer.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.bind(SocketAddr::new(bind, 0))?;
    let mut stream = socket.connect(peer).await?;
    stream.set_nodelay(true)?;
    stream.write_all(MAGIC).await?;
    stream.write_u8(operation).await?;
    stream.write_all(&token).await?;
    Ok(stream)
}
async fn tcp_check(
    peer: SocketAddr,
    bind: IpAddr,
    token: [u8; 32],
    deadline: Duration,
) -> CheckResult {
    let start = Instant::now();
    let work = async {
        let mut stream = open(peer, bind, token, ECHO).await?;
        let bytes: Vec<_> = (0..4096).map(|i| (i % 251) as u8).collect();
        write_frame(&mut stream, &bytes).await?;
        ensure!(
            read_frame(&mut stream).await? == bytes,
            "TCP probe integrity mismatch"
        );
        Ok::<_, anyhow::Error>(())
    };
    match time::timeout(deadline, work).await {
        Ok(Ok(())) => CheckResult {
            ok: true,
            round_trips: 1,
            rtt_ms: start.elapsed().as_secs_f64() * 1000.,
            error: None,
        },
        Ok(Err(e)) => CheckResult::failure(e),
        Err(e) => CheckResult::failure(e),
    }
}
async fn udp_check(
    socket: &UdpSocket,
    peer: SocketAddr,
    token: [u8; 32],
    count: usize,
    deadline: Duration,
) -> DatagramResult {
    let start = Instant::now();
    let mut received = HashSet::new();
    let mut integrity = true;
    let mut sum = 0.;
    let mut sent_at = Vec::new();
    let mut error = None;
    for sequence in 0..count {
        let mut packet = vec![0; UDP_HEADER + 512];
        packet[..5].copy_from_slice(MAGIC);
        packet[5..37].copy_from_slice(&token);
        packet[37..41].copy_from_slice(&(sequence as u32).to_be_bytes());
        for (index, byte) in packet[41..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let now = Instant::now();
        if let Err(e) = socket.send_to(&packet, peer).await {
            error = Some(e.to_string());
            break;
        }
        sent_at.push(now);
    }
    let end = start + deadline;
    let mut packet = [0; 8193];
    let sent = sent_at.len();
    while received.len() < sent {
        match time::timeout_at(end, socket.recv_from(&mut packet)).await {
            Ok(Ok((size, from))) => {
                if from != peer
                    || size != UDP_HEADER + 512
                    || packet[..5] != *MAGIC
                    || packet[5..37] != token
                {
                    continue;
                }
                let sequence = u32::from_be_bytes(packet[37..41].try_into().unwrap()) as usize;
                if sequence >= sent {
                    continue;
                }
                integrity &= packet[41..size]
                    .iter()
                    .enumerate()
                    .all(|(i, b)| *b == (i % 251) as u8);
                if received.insert(sequence) {
                    sum += sent_at[sequence].elapsed().as_secs_f64() * 1000.;
                }
            }
            Ok(Err(e)) => {
                error = Some(e.to_string());
                break;
            }
            Err(_) => {
                break;
            }
        }
    }
    DatagramResult {
        sent,
        received: received.len(),
        loss_percent: (sent - received.len()) as f64 / sent.max(1) as f64 * 100.,
        integrity,
        rtt_ms: sum / received.len().max(1) as f64,
        error,
    }
}
async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_FRAME, "linktest frame exceeds limit");
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}
async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    ensure!(size <= MAX_FRAME, "linktest frame exceeds limit");
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn send_transfer(stream: &mut TcpStream, duration: Duration) -> Result<u64> {
    let mut block: Vec<_> = (0..BLOCK).map(|i| (i % 251) as u8).collect();
    let end = Instant::now() + duration;
    let mut sequence = 0u64;
    let mut bytes = 0;
    while Instant::now() < end && sequence < MAX_TRANSFER_FRAMES {
        block[..8].copy_from_slice(&sequence.to_be_bytes());
        write_frame(stream, &block).await?;
        sequence += 1;
        bytes += BLOCK as u64;
    }
    write_frame(stream, &[]).await?;
    Ok(bytes)
}
async fn receive_transfer(stream: &mut TcpStream) -> Result<(u64, bool)> {
    let mut sequence = 0u64;
    let mut bytes = 0;
    let mut valid = true;
    loop {
        let block = read_frame(stream).await?;
        if block.is_empty() {
            break;
        }
        ensure!(
            sequence < MAX_TRANSFER_FRAMES,
            "linktest transfer exceeds 256 MiB limit"
        );
        ensure!(block.len() == BLOCK, "invalid linktest transfer block size");
        valid &= u64::from_be_bytes(block[..8].try_into()?) == sequence
            && block[8..]
                .iter()
                .enumerate()
                .all(|(i, b)| *b == ((i + 8) % 251) as u8);
        bytes += block.len() as u64;
        sequence += 1;
    }
    Ok((bytes, valid))
}

/// Asks the kernel never to fragment our datagrams and to refuse (EMSGSIZE) one that does not fit
/// the interface or the path limit it has learned. Returns whether that worked.
#[cfg(target_os = "linux")]
fn set_dont_fragment(socket: &UdpSocket) -> bool {
    use std::os::fd::AsRawFd;
    let (level, name) = if socket.local_addr().map(|a| a.is_ipv4()).unwrap_or(true) {
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER)
    };
    // IP_PMTUDISC_DO and IPV6_PMTUDISC_DO are both 2.
    let value: libc::c_int = libc::IP_PMTUDISC_DO;
    // SAFETY: the descriptor belongs to `socket`, which outlives the call; `value` is a valid
    // c_int and its size is passed.
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0
    }
}
#[cfg(not(target_os = "linux"))]
fn set_dont_fragment(_socket: &UdpSocket) -> bool {
    false
}
fn mtu_packet(token: &[u8; 32], sequence: u32, size: usize) -> Vec<u8> {
    let mut packet = vec![0; size];
    packet[..5].copy_from_slice(MAGIC);
    packet[5..37].copy_from_slice(token);
    packet[37..41].copy_from_slice(&sequence.to_be_bytes());
    for (index, byte) in packet[UDP_HEADER..].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    packet
}
/// Sends `probes` datagrams of each size, smallest first, a few milliseconds apart. The answer
/// says, per size, whether the local network stack accepted it.
async fn send_ladder(
    socket: &UdpSocket,
    to: SocketAddr,
    token: [u8; 32],
    sizes: &[usize],
    probes: usize,
) -> Result<Vec<bool>> {
    let mut sendable = Vec::with_capacity(sizes.len());
    let mut sequence = 0u32;
    for size in sizes {
        let mut accepted = true;
        for _ in 0..probes {
            match socket
                .send_to(&mtu_packet(&token, sequence, *size), to)
                .await
            {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(libc::EMSGSIZE) => {
                    accepted = false;
                    break;
                }
                Err(e) => return Err(e.into()),
            }
            sequence += 1;
            time::sleep(MTU_GAP).await;
        }
        sendable.push(accepted);
    }
    Ok(sendable)
}
/// Largest UDP datagram each way: this side sends the ladder and asks the peer how many arrived,
/// then asks the peer to send the ladder to the reverse listener here and counts what arrives.
async fn mtu_sweep(
    options: &ProbeOptions,
    token: [u8; 32],
    state: &State,
    reverse_port: u16,
    wait: Duration,
) -> MtuReport {
    let work = mtu_sweep_inner(options, token, state, reverse_port, wait);
    match time::timeout(
        wait * 2 + options.timeout * 2 + Duration::from_secs(10),
        work,
    )
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(e)) => MtuReport::failed(e),
        Err(e) => MtuReport::failed(e),
    }
}
async fn mtu_sweep_inner(
    options: &ProbeOptions,
    token: [u8; 32],
    state: &State,
    reverse_port: u16,
    wait: Duration,
) -> Result<MtuReport> {
    let sizes = MTU_SIZES;
    let probes: u8 = if options.quick { 3 } else { 5 };
    let socket = UdpSocket::bind(SocketAddr::new(options.bind, 0)).await?;
    let local_df = set_dont_fragment(&socket);
    let forward_sendable =
        send_ladder(&socket, options.peer, token, &sizes, usize::from(probes)).await?;
    time::sleep(wait).await;
    let mut report = open(options.peer, options.bind, token, MTU_REPORT).await?;
    report.write_u8(sizes.len() as u8).await?;
    for size in sizes {
        report.write_u16(size as u16).await?;
    }
    let mut forward = Vec::with_capacity(sizes.len());
    for accepted in &forward_sendable {
        forward.push((report.read_u16().await?, *accepted));
    }
    let mut ask = open(options.peer, options.bind, token, REVERSE_MTU).await?;
    ask.write_u16(reverse_port).await?;
    ask.write_u8(probes).await?;
    ask.write_u8(sizes.len() as u8).await?;
    for size in sizes {
        ask.write_u16(size as u16).await?;
    }
    let peer_df = ask.read_u8().await? != 0;
    let mut reverse_sendable = Vec::with_capacity(sizes.len());
    for _ in sizes {
        reverse_sendable.push(ask.read_u8().await? != 0);
    }
    time::sleep(wait).await;
    let reverse: Vec<_> = state
        .sizes_seen(&token, &sizes)
        .into_iter()
        .zip(reverse_sendable)
        .collect();
    Ok(MtuReport::from_counts(
        &sizes,
        probes,
        &forward,
        &reverse,
        local_df && peer_df,
        options.peer.is_ipv4(),
    ))
}

/// Executes actual two-way probes, reverse inbound connectivity and TCP transfers.
pub async fn probe(options: ProbeOptions) -> Result<LinkReport> {
    options.validate()?;
    let mut hello = time::timeout(
        options.timeout,
        open(options.peer, options.bind, [0; 32], SESSION),
    )
    .await??;
    let mut token = [0; 32];
    time::timeout(options.timeout, hello.read_exact(&mut token)).await??;
    let state = Arc::new(State {
        sessions: Mutex::new(HashMap::new()),
        peer: options.peer.ip(),
        finished: Notify::new(),
        keep: true,
    });
    state.register(token)?;
    let mut reverse = JoinSet::new();
    let reverse_listener = spawn_pair(
        SocketAddr::new(options.bind, options.local_port),
        state.clone(),
        &mut reverse,
    )
    .await?;
    let socket = UdpSocket::bind(SocketAddr::new(options.bind, 0)).await?;
    let count = if options.quick { 4 } else { 16 };
    let tcp = tcp_check(options.peer, options.bind, token, options.timeout).await;
    let udp = udp_check(&socket, options.peer, token, count, options.timeout).await;
    let reverse_tcp_work = async {
        let mut s = open(options.peer, options.bind, token, REVERSE_TCP).await?;
        s.write_u16(reverse_listener.port()).await?;
        let ok = s.read_u8().await? != 0;
        let rtt = s.read_u64().await?;
        Ok::<_, anyhow::Error>(CheckResult {
            ok,
            round_trips: usize::from(ok),
            rtt_ms: rtt as f64 / 1000.,
            error: (!ok).then(|| "reverse TCP connection/integrity check failed".into()),
        })
    };
    let reverse_tcp =
        match time::timeout(options.timeout + Duration::from_secs(5), reverse_tcp_work).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => CheckResult::failure(e),
            Err(e) => CheckResult::failure(e),
        };
    let reverse_udp_work = async {
        let mut s = open(options.peer, options.bind, token, REVERSE_UDP).await?;
        s.write_u16(reverse_listener.port()).await?;
        s.write_u8(count as u8).await?;
        let received = s.read_u32().await? as usize;
        ensure!(received <= count, "invalid reverse UDP result");
        let integrity = s.read_u8().await? != 0;
        let rtt = s.read_u64().await?;
        Ok::<_, anyhow::Error>(DatagramResult {
            sent: count,
            received,
            loss_percent: (count - received) as f64 / count as f64 * 100.,
            integrity,
            rtt_ms: rtt as f64 / 1000.,
            error: None,
        })
    };
    let reverse_udp =
        match time::timeout(options.timeout + Duration::from_secs(5), reverse_udp_work).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => DatagramResult {
                sent: count,
                received: 0,
                loss_percent: 100.,
                integrity: false,
                rtt_ms: 0.,
                error: Some(e.to_string()),
            },
            Err(e) => DatagramResult {
                sent: count,
                received: 0,
                loss_percent: 100.,
                integrity: false,
                rtt_ms: 0.,
                error: Some(e.to_string()),
            },
        };
    let duration = if options.quick {
        options.seconds.min(Duration::from_millis(250))
    } else {
        options.seconds
    };
    let upload_work = async {
        let mut s = open(options.peer, options.bind, token, UPLOAD).await?;
        let start = Instant::now();
        let sent = send_transfer(&mut s, duration).await?;
        let got = s.read_u64().await?;
        let valid = s.read_u8().await? != 0;
        Ok::<_, anyhow::Error>(ThroughputResult::new(
            got,
            start.elapsed().as_secs_f64(),
            valid && got == sent,
        ))
    };
    let upload = match time::timeout(duration + options.timeout, upload_work).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => ThroughputResult::failure(e),
        Err(e) => ThroughputResult::failure(e),
    };
    let download_work = async {
        let mut s = open(options.peer, options.bind, token, DOWNLOAD).await?;
        s.write_u32(duration.as_millis() as u32).await?;
        let start = Instant::now();
        let (bytes, valid) = receive_transfer(&mut s).await?;
        Ok::<_, anyhow::Error>(ThroughputResult::new(
            bytes,
            start.elapsed().as_secs_f64(),
            valid,
        ))
    };
    let download = match time::timeout(duration + options.timeout, download_work).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => ThroughputResult::failure(e),
        Err(e) => ThroughputResult::failure(e),
    };
    let mut ports = Vec::new();
    for port in options.extra_ports.iter().copied() {
        let address = SocketAddr::new(options.peer.ip(), port);
        ports.push(PortResult {
            port,
            tcp: tcp_check(address, options.bind, token, options.timeout).await,
            udp: udp_check(&socket, address, token, count, options.timeout).await,
        });
    }
    // Long round trips need a longer wait for the last datagrams of each direction.
    let mtu = if options.mtu {
        let wait = if udp.received > 0 {
            Duration::from_secs_f64(udp.rtt_ms * 3. / 1000.)
        } else {
            Duration::ZERO
        }
        .clamp(Duration::from_millis(1200), Duration::from_secs(5));
        Some(mtu_sweep(&options, token, &state, reverse_listener.port(), wait).await)
    } else {
        None
    };
    let _ = time::timeout(options.timeout, async {
        let mut s = open(options.peer, options.bind, token, FINISH).await?;
        s.read_u8().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    reverse.abort_all();
    while reverse.join_next().await.is_some() {}
    let mut report = LinkReport {
        quick: options.quick,
        peer: options.peer,
        reverse_listener,
        tcp,
        udp,
        reverse_tcp,
        reverse_udp,
        upload,
        download,
        ports,
        mtu,
        verdict: crate::linkverdict::Verdict::default(),
    };
    report.verdict = crate::linkverdict::assess(&report);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZES: [usize; 5] = [548, 1000, 1400, 1452, 1472];
    fn counts(values: [u16; 5]) -> Vec<(u16, bool)> {
        values.iter().map(|v| (*v, true)).collect()
    }

    #[test]
    fn the_largest_size_that_works_in_each_direction_is_found() {
        let report = MtuReport::from_counts(
            &SIZES,
            5,
            &counts([5, 5, 5, 0, 0]),
            &counts([5, 5, 3, 3, 0]),
            true,
            true,
        );
        assert_eq!(report.forward_max_payload, Some(1400));
        assert_eq!(report.reverse_max_payload, Some(1452));
        assert_eq!(report.max_payload, Some(1400));
        assert_eq!(report.path_mtu, Some(1428));
        assert!(!report.at_ladder_top && !report.irregular);
    }

    #[test]
    fn a_size_needs_more_than_half_of_its_probes() {
        let report = MtuReport::from_counts(
            &SIZES,
            5,
            &counts([5, 2, 0, 0, 0]),
            &counts([5, 3, 0, 0, 0]),
            true,
            true,
        );
        assert_eq!(
            report.forward_max_payload,
            Some(548),
            "2 of 5 is not enough"
        );
        assert_eq!(report.reverse_max_payload, Some(1000), "3 of 5 is enough");
    }

    #[test]
    fn a_path_that_carries_everything_is_marked_as_a_lower_bound() {
        let report = MtuReport::from_counts(
            &SIZES,
            3,
            &counts([3, 3, 3, 3, 3]),
            &counts([3, 3, 3, 3, 2]),
            true,
            false,
        );
        assert_eq!(report.max_payload, Some(1472));
        assert_eq!(report.header_bytes, 48);
        assert_eq!(report.path_mtu, Some(1520));
        assert!(report.at_ladder_top);
    }

    #[test]
    fn nothing_arriving_gives_no_answer_and_a_refused_size_stops_the_climb() {
        let none = MtuReport::from_counts(&SIZES, 5, &counts([0; 5]), &counts([5; 5]), true, true);
        assert_eq!(none.forward_max_payload, None);
        assert_eq!(none.max_payload, None);
        assert_eq!(none.path_mtu, None);
        // The sender's own stack refused 1400 and above, although the counts say otherwise.
        let mut refused = counts([5, 5, 5, 5, 5]);
        for entry in &mut refused[2..] {
            entry.1 = false;
        }
        let report = MtuReport::from_counts(&SIZES, 5, &refused, &counts([5; 5]), true, true);
        assert_eq!(report.forward_max_payload, Some(1000));
    }

    #[test]
    fn a_later_success_after_a_failure_is_reported_as_irregular_and_ignored() {
        let report = MtuReport::from_counts(
            &SIZES,
            5,
            &counts([5, 5, 0, 5, 0]),
            &counts([5; 5]),
            true,
            true,
        );
        assert_eq!(report.forward_max_payload, Some(1000));
        assert!(report.irregular);
    }
}
