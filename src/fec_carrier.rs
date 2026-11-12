//! FEC family: KCP with a 10-data/1-parity FEC envelope.
//! FEC-UDP uses UDP and an optional P/A knock. Identity and payload encryption
//! are provided by Noise; no shared-secret header cipher is used.
use crate::{
    carrier::BoxIo,
    config::{ClientPath, Listener, Transport},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket,
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, Sleep, timeout},
};
use tokio_kcp::{
    KcpConfig, KcpNoDelayConfig, KcpSession, KcpSocket, KcpStream, PacketSink,
    batch::{Incoming, Outgoing},
};

#[path = "fec_tuning.rs"]
mod tuning;
pub use tuning::{FecTunerMode, FecTunerOptions};

const DATA: usize = 10;
const SHARDS: u32 = 11;
const TYPE_DATA: u16 = 0xf1;
const TYPE_PARITY: u16 = 0xf2;
/// Parity of a group that was cut short (nothing more to send for `partial_flush_ms`). The low
/// byte is the kind, the high byte how many data shards (1..9) it covers. Versions before 0.8.4
/// ignore it (they accept only 0xf1 and 0xf2), so they simply get no repair for those groups.
const KIND_PARTIAL: u8 = 0xf3;
const PAWS: u32 = u32::MAX / SHARDS * SHARDS;
// Row ten of V(11,10) * inverse(V(10,10)), GF(256), polynomial 0x11d.
const PARITY_COEFFICIENTS: [u8; DATA] = [129, 150, 175, 184, 210, 196, 254, 232, 3, 2];
/// Groups the decoder keeps open. A shard delayed behind a few later groups must still find
/// its group, or a repair it would allow is lost.
const MAX_GROUPS: usize = 8;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FecProfile {
    #[default]
    Default,
    Gaming,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FecOptions {
    pub mtu: usize,
    pub peer_mtu: Option<usize>,
    pub profile: FecProfile,
    pub knock: bool,
    pub knock_timeout_ms: u64,
    pub max_peers: usize,
    /// Server: most conversations (one per client connection) one source address may have at once
    /// (0 = no limit), so one address cannot take every peer slot.
    pub max_peers_per_ip: usize,
    pub sndwnd: u16,
    pub rcvwnd: u16,
    pub socket_buf_bytes: usize,
    pub tuner: FecTunerOptions,
    pub nodelay: Option<bool>,
    pub interval_ms: Option<u32>,
    pub resend: Option<u16>,
    pub congestion_control: Option<bool>,
    pub write_delay: Option<bool>,
    pub ack_no_delay: Option<bool>,
    /// Server: a peer with no traffic for this long is forgotten.
    pub peer_idle_sec: u64,
    /// Server: how long a knock keeps its source address admitted.
    pub knock_ttl_sec: u64,
    /// Inactive KCP sessions are closed after this long.
    pub session_expire_sec: u64,
    /// When fewer than 10 packets were sent and nothing follows for this long, a parity packet
    /// for those few is sent, so a loss among them is repaired at once instead of waiting for a
    /// retransmission (the end of every transfer, and short requests and answers). 0 = off.
    pub partial_flush_ms: u64,
    /// Most packets resent at once (per interval) because their retransmission timer expired
    /// (0 = no limit). Without a limit a timeout resends the whole window in one burst.
    pub resend_burst: u32,
    /// Paces how fast data is handed to KCP by its own measured round-trip time, instead of only
    /// by `sndwnd`/`congestion_control`: the rate grows while RTT stays near its observed minimum
    /// and shrinks once it grows past that (a queue building somewhere on the path), independent
    /// of loss (loss here is as likely to be ordinary path noise as congestion). Off by default:
    /// `sndwnd` and the resend-burst limit already bound how much is in flight; this is an
    /// additional, optional layer on top, not a replacement.
    pub pacer: bool,
    pub adaptive: crate::adaptive::AdaptiveOptions,
    pub tcp_fallback: crate::packet_lane::Options,
    #[serde(skip)]
    pub packet_lane_key: Option<crate::packet_lane::Key>,
    #[serde(skip)]
    pub packet_hopping_enabled: bool,
}
impl Default for FecOptions {
    fn default() -> Self {
        Self {
            mtu: 1350,
            peer_mtu: None,
            profile: FecProfile::Default,
            knock: true,
            knock_timeout_ms: 3000,
            max_peers: 256,
            max_peers_per_ip: 64,
            sndwnd: 1024,
            rcvwnd: 1024,
            socket_buf_bytes: 4 * 1024 * 1024,
            tuner: FecTunerOptions::default(),
            nodelay: None,
            interval_ms: None,
            resend: None,
            congestion_control: None,
            write_delay: None,
            ack_no_delay: None,
            peer_idle_sec: 60,
            knock_ttl_sec: 30,
            session_expire_sec: 60,
            partial_flush_ms: 10,
            resend_burst: 128,
            pacer: false,
            adaptive: crate::adaptive::AdaptiveOptions::default(),
            tcp_fallback: crate::packet_lane::Options::default(),
            packet_lane_key: None,
            packet_hopping_enabled: false,
        }
    }
}
impl FecOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (512..=9000).contains(&self.mtu),
            "fec mtu must be 512..9000"
        );
        ensure!(
            self.peer_mtu.is_none_or(|mtu| (512..=9000).contains(&mtu)),
            "fec peer_mtu must be 512..9000 when set"
        );
        ensure!(
            (500..=30_000).contains(&self.knock_timeout_ms),
            "fec knock_timeout_ms must be 500..30000"
        );
        ensure!(
            (1..=4096).contains(&self.max_peers),
            "fec max_peers must be 1..4096"
        );
        ensure!(
            self.max_peers_per_ip <= 4096,
            "fec max_peers_per_ip must be 0..4096 (0 = no limit)"
        );
        ensure!(
            (128..=8192).contains(&self.sndwnd) && (128..=8192).contains(&self.rcvwnd),
            "fec sndwnd/rcvwnd must be 128..8192"
        );
        ensure!(
            (256 * 1024..=64 * 1024 * 1024).contains(&self.socket_buf_bytes),
            "fec socket_buf_bytes must be 256 KiB..64 MiB"
        );
        self.tuner.validate()?;
        self.adaptive.validate()?;
        self.tcp_fallback.validate()?;
        ensure!(!self.adaptive.enabled || (!self.pacer && self.tuner.mode == FecTunerMode::Off && self.congestion_control != Some(true)), "adaptive controller owns pacing/windows; disable fec.pacer, auto tuner and legacy congestion_control");
        ensure!(
            (5..=3600).contains(&self.peer_idle_sec)
                && (5..=3600).contains(&self.knock_ttl_sec)
                && (5..=3600).contains(&self.session_expire_sec),
            "fec peer_idle_sec, knock_ttl_sec and session_expire_sec must be 5..3600"
        );
        ensure!(
            self.interval_ms
                .is_none_or(|interval| (10..=5000).contains(&interval)),
            "fec interval_ms must be 10..5000 when set"
        );
        ensure!(
            self.resend.is_none_or(|resend| resend <= 255),
            "fec resend must be 0..255 when set"
        );
        ensure!(
            self.partial_flush_ms <= 1000,
            "fec partial_flush_ms must be 0..1000"
        );
        ensure!(
            self.resend_burst <= 8192,
            "fec resend_burst must be 0..8192"
        );
        if self.tuner.mode == FecTunerMode::Auto {
            ensure!(
                self.tuner.memory_budget_mb * 1024 * 1024 >= 4 * self.minimum_allocation(),
                "fec tuner memory budget must cover one conversation's minimum allocation"
            );
            ensure!(
                self.tuner.max_window_bytes >= 256 * (self.envelope_mtu(false) - 8).max(512),
                "fec tuner max_window_bytes must cover the 256-segment minimum at the configured MTU"
            );
        }
        Ok(())
    }
    /// Packets one conversation may have waiting for the socket: twice its largest window (KCP
    /// sends at most a window at a time, plus retransmissions), at least 256 and at most
    /// `DELAYED_PACKETS`. On raw carriers every packet waits here, so this bounds the memory a
    /// slow socket can tie up per peer.
    fn send_queue(&self, raw: bool) -> usize {
        let segment = (self.envelope_mtu(raw) - 8).max(1);
        let window = if self.tuner.mode == FecTunerMode::Auto {
            self.tuner.max_window_bytes / segment
        } else {
            usize::from(self.sndwnd)
        };
        (2 * window).clamp(256, DELAYED_PACKETS)
    }
    fn partial_flush(&self) -> Option<Duration> {
        (self.partial_flush_ms > 0).then(|| Duration::from_millis(self.partial_flush_ms))
    }
    fn envelope_mtu(&self, raw: bool) -> usize {
        let mtu=if raw {
            (self.mtu.min(self.peer_mtu.unwrap_or(self.mtu)) - 100).clamp(512, 1500)
        } else {
            self.mtu.min(1500)
        };
        // Reserve room for the optional authenticated hopping envelope before
        // constructing KCP/FEC shards. Never rely on a too-large raw send failing.
        if raw && self.packet_hopping_enabled {mtu.saturating_sub(crate::port_hop::OVERHEAD).max(256)}else{mtu}
    }
    fn kcp(&self, raw: bool) -> KcpConfig {
        let gaming = self.profile == FecProfile::Gaming;
        let cap = if gaming { 1024 } else { 8192 };
        let wnd_size = if self.tuner.mode == FecTunerMode::Auto {
            let budget = tuning::window_budget(
                self.tuner.min_window_bytes,
                self.envelope_mtu(raw) - 8,
                gaming,
            );
            (budget, budget)
        } else {
            (self.sndwnd.min(cap), self.rcvwnd.min(cap))
        };
        let wnd_size = if self.adaptive.enabled { (self.adaptive.min_window, self.adaptive.max_window.max(1024)) } else { wnd_size };
        KcpConfig {
            mtu: self.envelope_mtu(raw) - 8,
            stream: true,
            wnd_size,
            nodelay: KcpNoDelayConfig {
                nodelay: self.nodelay.unwrap_or(!raw || gaming),
                interval: self.interval_ms.unwrap_or(10) as i32,
                resend: self.resend.unwrap_or(2) as i32,
                nc: !self.congestion_control.unwrap_or(false),
            },
            session_expire: Duration::from_secs(self.session_expire_sec),
            flush_write: !self.write_delay.unwrap_or(raw && !gaming),
            flush_acks_input: self.ack_no_delay.unwrap_or(!raw),
            resend_burst: self.resend_burst,
            ..KcpConfig::default()
        }
    }
    fn minimum_allocation(&self) -> usize {
        // Reserve enough for the 256-segment floor at either raw/UDP MTU.
        self.tuner
            .min_buffer_bytes
            .max(self.tuner.min_window_bytes)
            .max(256 * (self.envelope_mtu(false) - 8).max(512))
    }
    fn peer_limit(&self) -> usize {
        if self.tuner.mode == FecTunerMode::Auto {
            self.max_peers
                .min(self.tuner.memory_budget_mb * 1024 * 1024 / (4 * self.minimum_allocation()))
        } else {
            self.max_peers
        }
    }
    fn initial_buffer(&self) -> usize {
        if self.tuner.mode == FecTunerMode::Auto {
            self.socket_buf_bytes
                .clamp(self.tuner.min_buffer_bytes, self.tuner.max_buffer_bytes)
                .min(self.tuner.memory_budget_mb * 1024 * 1024 / 4)
        } else {
            self.socket_buf_bytes
        }
    }
}

enum NetworkSocket {
    Udp(UdpSocket),
    #[cfg(target_os = "linux")]
    Raw(crate::raw_socket::RawSocket),
    Multipath {
        raw: Box<NetworkSocket>,
        lane: Arc<crate::packet_lane::Lane>,
        peer: SocketAddr,
        last_raw: Mutex<Instant>,
        last_probe: Mutex<Instant>,
        idle: Duration,
    },
}
impl NetworkSocket {
    fn payload_limit(&self)->Option<usize>{match self{Self::Udp(_)=>None,Self::Raw(socket)=>Some(socket.max_payload()),Self::Multipath{raw,..}=>raw.payload_limit()}}
    fn lane_active(&self)->bool {
        match self {Self::Multipath{lane,last_raw,idle,..}=>lane.connected()&&last_raw.lock().unwrap_or_else(|e|e.into_inner()).elapsed()>=*idle,_=>false}
    }
    async fn send_to(&self, data: &[u8], peer: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.send_to(data, peer).await,
            #[cfg(target_os = "linux")]
            Self::Raw(socket) => socket.send_to(data, peer).await,
            Self::Multipath { raw, lane, last_raw, last_probe, idle, .. } => {
                if lane.connected() && last_raw.lock().unwrap_or_else(|e|e.into_inner()).elapsed() >= *idle {
                    let probe={let mut last=last_probe.lock().unwrap_or_else(|e|e.into_inner()); if last.elapsed()>=Duration::from_secs(2){*last=Instant::now();true}else{false}};
                    if probe {let _=Box::pin(raw.send_to(data,peer)).await;}
                    lane.send(data).await
                } else {Box::pin(raw.send_to(data,peer)).await}
            }
        }
    }
    /// Receives the datagrams that are waiting: up to 64 from a UDP socket in one system call,
    /// one from a raw socket. Returns how many; read them from `incoming`.
    async fn recv_batch(&self, incoming: &mut Incoming) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => incoming.receive(socket).await,
            #[cfg(target_os = "linux")]
            Self::Raw(socket) => {
                let (size, source) = socket.recv_from(incoming.slot_mut()).await?;
                Ok(incoming.finish_one(size, Some(source)))
            }
            Self::Multipath {raw,lane,peer,last_raw,..} => {
                tokio::select! {
                    result=Box::pin(raw.recv_batch(incoming))=>{
                        let count=result?;
                        *last_raw.lock().unwrap_or_else(|e|e.into_inner())=Instant::now();
                        Ok(count)
                    }
                    result=lane.recv()=>{
                        let packet=result?;
                        incoming.slot_mut()[..packet.len()].copy_from_slice(&packet);
                        Ok(incoming.finish_one(packet.len(),Some(*peer)))
                    }
                }
            }
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Udp(socket) => socket.local_addr(),
            #[cfg(target_os = "linux")]
            Self::Raw(socket) => Ok(socket.local_addr()),
            Self::Multipath {raw,..}=>raw.local_addr(),
        }
    }
    fn set_socket_buffer_bytes(&self, bytes: usize) -> io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Raw(socket) => socket.set_socket_buffer_bytes(bytes),
            Self::Udp(socket) => set_udp_buffers(socket, bytes),
            Self::Multipath {raw,..}=>raw.set_socket_buffer_bytes(bytes),
        }
    }

    async fn fallback(self, options:&FecOptions, server:bool, peer:SocketAddr)->Result<Self> {
        if options.tcp_fallback.address.is_none(){return Ok(self);}
        ensure!(!matches!(self,Self::Udp(_)),"packet TCP fallback currently requires a raw FEC carrier");
        let key=options.packet_lane_key.clone().context("TCP fallback requires tunnel_key")?;
        let lane=crate::packet_lane::Lane::open(&options.tcp_fallback,key,server).await?;
        Ok(Self::Multipath {raw:Box::new(self),lane,peer,last_raw:Mutex::new(Instant::now()),last_probe:Mutex::new(Instant::now()),idle:Duration::from_millis(options.tcp_fallback.idle_ms)})
    }
}

async fn raw_network(
    raw: Option<&crate::raw_packet::RawOptions>,
    server: bool,
    mtu: usize,
    socket_buf: usize,
) -> Result<NetworkSocket> {
    #[cfg(target_os = "linux")]
    {
        let mut options = raw.context("raw carrier options required")?.clone();
        options.sock_buf = socket_buf;
        if options.hopping.enabled {
            // Hopping authentication adds an outer envelope; do not exceed the
            // configured interface's single-frame payload budget.
            ensure!(options.hopping.key.is_some(),"raw port hopping requires tunnel_key");
        }
        let socket = crate::raw_socket::RawSocket::bind_fec(&options, server).await?;
        ensure!(
            mtu <= socket.max_payload(),
            "fec mtu exceeds raw interface capacity"
        );
        Ok(NetworkSocket::Raw(socket))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (raw, server, mtu, socket_buf);
        anyhow::bail!("fec raw carrier requires Linux")
    }
}

fn gf_multiply(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    while b != 0 {
        if b & 1 != 0 {
            out ^= a;
        }
        let high = a & 0x80 != 0;
        a <<= 1;
        if high {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    out
}
/// `table()[a][b]` is `gf_multiply(a, b)`. Multiplying a whole shard by one coefficient then
/// costs one table lookup per byte instead of up to eight shift-and-xor rounds.
fn multiplication_table() -> &'static [[u8; 256]; 256] {
    static TABLE: std::sync::OnceLock<Box<[[u8; 256]; 256]>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Box::new([[0u8; 256]; 256]);
        for (a, row) in table.iter_mut().enumerate() {
            for (b, cell) in row.iter_mut().enumerate() {
                *cell = gf_multiply(a as u8, b as u8);
            }
        }
        table
    })
}

/// `target[i] ^= coefficient * source[i]` for every byte of `source`.
fn multiply_add(target: &mut [u8], source: &[u8], coefficient: u8) {
    let row = &multiplication_table()[usize::from(coefficient)];
    for (out, &byte) in target.iter_mut().zip(source) {
        *out ^= row[usize::from(byte)];
    }
}

fn gf_inverse(a: u8) -> u8 {
    let mut out = 1;
    for _ in 0..254 {
        out = gf_multiply(out, a);
    }
    out
}

#[derive(Default)]
struct FecEncoder {
    next: u32,
    shards: Vec<Vec<u8>>,
}
impl FecEncoder {
    fn encode(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let size = (data.len() + 2) as u16;
        let mut shard = Vec::with_capacity(data.len() + 2);
        shard.extend(size.to_le_bytes());
        shard.extend_from_slice(data);
        let mut output = vec![self.envelope(TYPE_DATA, &shard)];
        self.shards.push(shard);
        if self.shards.len() == DATA {
            let mut parity = vec![0; self.shards.iter().map(Vec::len).max().unwrap_or(0)];
            for (index, shard) in self.shards.iter().enumerate() {
                multiply_add(&mut parity, shard, PARITY_COEFFICIENTS[index]);
            }
            output.push(self.envelope(TYPE_PARITY, &parity));
            self.shards.clear();
        }
        output
    }
    /// Ends a group that is not full with a parity packet for the shards it has, or `None` when
    /// there are none. The next data packet starts a new group (the unused slots are skipped).
    fn flush(&mut self) -> Option<Vec<u8>> {
        let count = self.shards.len();
        // Every KCP packet has its 24-byte header; the conversation is at shard bytes 2..6.
        if count == 0 || self.shards[0].len() < 6 {
            return None;
        }
        let mut parity = vec![0; self.shards.iter().map(Vec::len).max().unwrap_or(0)];
        for (index, shard) in self.shards.iter().enumerate() {
            multiply_add(&mut parity, shard, PARITY_COEFFICIENTS[index]);
        }
        // A full row of coefficients sums to one, so a full group's parity carries the
        // conversation where a data shard has it; a partial row does not. The conversation is
        // the same in every shard (one KCP session per sink), so those four bytes are not needed
        // for the repair: they carry the conversation itself, for demultiplexing.
        parity[2..6].copy_from_slice(&self.shards[0][2..6]);
        let base = self.next - count as u32;
        let mut packet = Vec::with_capacity(parity.len() + 6);
        packet.extend((base + DATA as u32).to_le_bytes());
        packet.extend([KIND_PARTIAL, count as u8]);
        packet.extend_from_slice(&parity);
        // A group never crosses PAWS (a multiple of SHARDS), so `base + SHARDS` is at most PAWS.
        self.next = base + SHARDS;
        if self.next == PAWS {
            self.next = 0;
        }
        self.shards.clear();
        Some(packet)
    }
    fn envelope(&mut self, kind: u16, shard: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(shard.len() + 6);
        packet.extend(self.next.to_le_bytes());
        packet.extend(kind.to_le_bytes());
        packet.extend_from_slice(shard);
        self.next += 1;
        if self.next == PAWS {
            self.next = 0;
        }
        packet
    }
}
struct FecGroup {
    id: u32,
    shards: [Option<Vec<u8>>; 11],
    delivered: [bool; 10],
    /// How many data shards the parity covers: 10, or fewer for a partial parity.
    covered: usize,
}
impl FecGroup {
    fn new(id: u32) -> Self {
        Self {
            id,
            shards: std::array::from_fn(|_| None),
            delivered: [false; 10],
            covered: DATA,
        }
    }
}
/// What an envelope is: `Some(None)` a data shard, `Some(Some(n))` a parity covering the first
/// `n` data shards of its group, `None` nothing this version reads.
fn envelope_kind(seq: u32, kind: u16) -> Option<Option<usize>> {
    let slot = (seq % SHARDS) as usize;
    let [low, high] = kind.to_le_bytes();
    if seq >= PAWS {
        None
    } else if slot < DATA && kind == TYPE_DATA {
        Some(None)
    } else if slot == DATA && kind == TYPE_PARITY {
        Some(Some(DATA))
    } else if slot == DATA && low == KIND_PARTIAL && (1..DATA).contains(&usize::from(high)) {
        Some(Some(usize::from(high)))
    } else {
        None
    }
}
#[derive(Default)]
struct FecDecoder {
    groups: VecDeque<FecGroup>,
}
impl FecDecoder {
    fn decode(&mut self, packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        if packet.len() < 8 || packet.len() > mtu {
            return vec![];
        }
        let seq = u32::from_le_bytes(packet[0..4].try_into().unwrap());
        let kind = u16::from_le_bytes(packet[4..6].try_into().unwrap());
        let slot = (seq % SHARDS) as usize;
        let Some(parity_covers) = envelope_kind(seq, kind) else {
            return vec![];
        };
        if parity_covers.is_none() && shard_payload(&packet[6..]).is_none() {
            return vec![];
        }
        if parity_covers.is_some_and(|covered| covered < DATA && packet.len() < 12) {
            return vec![];
        }
        let id = seq / SHARDS;
        let index = if let Some(index) = self.groups.iter().position(|g| g.id == id) {
            index
        } else {
            if self.groups.len() == MAX_GROUPS {
                self.groups.pop_front();
            }
            self.groups.push_back(FecGroup::new(id));
            self.groups.len() - 1
        };
        let group = &mut self.groups[index];
        if group.shards[slot].is_some() {
            return vec![];
        }
        group.shards[slot] = Some(packet[6..].to_vec());
        if let Some(covered) = parity_covers {
            group.covered = covered;
        }
        let covered = group.covered;
        let mut output = Vec::new();
        if slot < DATA {
            output.push(
                shard_payload(group.shards[slot].as_ref().unwrap())
                    .unwrap()
                    .to_vec(),
            );
            group.delivered[slot] = true;
        }
        let missing: Vec<_> = (0..covered)
            .filter(|&i| group.shards[i].is_none())
            .collect();
        if missing.len() == 1 && group.shards[DATA].is_some() {
            let parity = group.shards[DATA].as_ref().unwrap();
            let lost = missing[0];
            let mut recovered = parity.clone();
            for (index, shard) in group.shards[..covered].iter().enumerate() {
                if let Some(shard) = shard {
                    if shard.len() > recovered.len() {
                        return output;
                    }
                    multiply_add(&mut recovered, shard, PARITY_COEFFICIENTS[index]);
                }
            }
            let inverse = gf_inverse(PARITY_COEFFICIENTS[lost]);
            let row = &multiplication_table()[usize::from(inverse)];
            for byte in &mut recovered {
                *byte = row[usize::from(*byte)];
            }
            if covered < DATA {
                // The partial parity carries the conversation itself at these bytes.
                recovered[2..6].copy_from_slice(&parity[2..6]);
            }
            if let Some(payload) = shard_payload(&recovered) {
                if !group.delivered[lost] {
                    output.push(payload.to_vec());
                    group.delivered[lost] = true;
                }
                group.shards[lost] = Some(recovered);
            }
        }
        output
    }
}
fn shard_payload(shard: &[u8]) -> Option<&[u8]> {
    if shard.len() < 2 {
        return None;
    }
    let size = u16::from_le_bytes(shard[..2].try_into().ok()?) as usize;
    (size >= 2 && size <= shard.len()).then(|| &shard[2..size])
}

fn fec_conversation(packet: &[u8], mtu: usize) -> Option<u32> {
    if packet.len() < 32 || packet.len() > mtu {
        return None;
    }
    let seq = u32::from_le_bytes(packet[..4].try_into().ok()?);
    let kind = u16::from_le_bytes(packet[4..6].try_into().ok()?);
    let parity_covers = envelope_kind(seq, kind)?;
    if parity_covers.is_none() && shard_payload(&packet[6..])?.len() < 24 {
        return None;
    }
    // All KCP packets in a FEC group share a conversation. The parity row
    // sums to one in GF(256), so these four bytes are preserved in parity;
    // a partial parity carries them as they are.
    let conversation = u32::from_le_bytes(packet[8..12].try_into().ok()?);
    (conversation != 0).then_some(conversation)
}

/// Sets the receive and send buffers of a UDP socket. The kernel caps the value at
/// `net.core.rmem_max` / `wmem_max`.
pub fn set_udp_buffers(socket: &UdpSocket, bytes: usize) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let value = i32::try_from(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket buffer too large"))?;
        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            // SAFETY: the pointer addresses a live i32 for the duration of this call.
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&value as *const i32).cast(),
                    std::mem::size_of::<i32>() as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (socket, bytes);
    Ok(())
}

/// Where a fec-udp listener at `address` listens for knocks.
pub fn knock_address(address: SocketAddr) -> SocketAddr {
    let port = if address.port() <= 55_535 {
        address.port() + 10_000
    } else {
        address.port() - 1000
    };
    SocketAddr::new(address.ip(), port)
}
async fn resolve(addr: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(addr)
        .await
        .context("resolve fec peer")?
        .next()
        .context("fec peer has no address")
}
async fn knock(peer: SocketAddr, total: Duration, local: Option<&str>) -> Result<()> {
    let socket = crate::carrier::udp_for_peer(peer, local).await?;
    socket.connect(knock_address(peer)).await?;
    let attempt = (total / 3).clamp(Duration::from_millis(500), Duration::from_secs(3));
    for index in 0..3 {
        socket.send(b"P").await?;
        let mut response = [0; 32];
        if let Ok(Ok(size)) = timeout(attempt, socket.recv(&mut response)).await
            && size > 0
            && response[0] == b'A'
        {
            return Ok(());
        }
        if index < 2 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    anyhow::bail!("fec-udp knock timed out")
}

struct TaskGuard(JoinHandle<()>);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
/// Paces writes into a KCP stream by its own measured round-trip time (`FecOptions::pacer`), the
/// same idea as `sndwnd` but driven by delay instead of a fixed packet count: the rate grows while
/// RTT stays near its observed minimum, and shrinks once RTT grows past that (a queue building
/// somewhere), independent of loss. Delay, not loss, because on these links loss is often ordinary
/// path noise rather than congestion, and treating it as congestion punishes a clean but lossy path.
struct Pacer {
    rate: f64,
    min_rate: f64,
    max_rate: f64,
    tokens: f64,
    last_refill: Instant,
    min_rtt: Option<Duration>,
    min_rtt_at: Instant,
    last_tick: Instant,
    wait: Option<Pin<Box<Sleep>>>,
}
/// How often the rate is re-judged against a fresh SRTT sample.
const PACER_TICK: Duration = Duration::from_millis(50);
/// Below this many tokens, a write waits rather than sending a sliver: KCP's own per-segment
/// overhead makes many tiny sends less efficient than a few full ones.
const PACER_MIN_CHUNK: f64 = 1024.0;
/// How far the minimum round-trip time may be trusted before a fresh low sample is required, so a
/// path that got permanently slower is not judged against a stale, now-unreachable floor forever.
const PACER_MIN_RTT_MAX_AGE: Duration = Duration::from_secs(10);
/// The pacer's own floor and ceiling, bytes per second. `sndwnd` and KCP's own window already
/// bound the session; these just keep the pacer from either stalling a session completely or
/// (pointlessly) capping a fast, clean link below what it could otherwise reach.
const PACER_MIN_RATE: f64 = 64_000.0;
const PACER_MAX_RATE: f64 = 500_000_000.0;

impl Pacer {
    fn new(min_rate: f64, max_rate: f64) -> Self {
        let now = Instant::now();
        Self {
            rate: min_rate,
            min_rate,
            max_rate,
            tokens: 0.0,
            last_refill: now,
            min_rtt: None,
            min_rtt_at: now,
            last_tick: now,
            wait: None,
        }
    }

    /// Re-judges the rate from a fresh SRTT sample, at most once per `PACER_TICK`.
    fn observe(&mut self, srtt: Duration) {
        if srtt.is_zero() {
            return; // no sample yet (a fresh session)
        }
        let now = Instant::now();
        if now.duration_since(self.last_tick) < PACER_TICK {
            return;
        }
        self.last_tick = now;
        let stale = now.duration_since(self.min_rtt_at) > PACER_MIN_RTT_MAX_AGE;
        if stale || self.min_rtt.is_none_or(|min| srtt < min) {
            self.min_rtt = Some(srtt);
            self.min_rtt_at = now;
        }
        let min_rtt = self.min_rtt.unwrap_or(srtt);
        // A real ~100ms link's ordinary queueing delay under its own load runs tens of ms above
        // its idle floor (seen directly on a production Iran-foreign link: loaded p95 27-80ms above the
        // idle RTT) - the original min_rtt/8 with a 5ms floor read that as congestion almost every
        // tick and starved the session toward PACER_MIN_RATE instead of settling near what the
        // link can actually sustain.
        let slack = (min_rtt / 3).max(Duration::from_millis(20));
        if srtt > min_rtt + slack {
            self.rate = (self.rate * 0.93).max(self.min_rate);
        } else {
            self.rate = (self.rate * 1.10).min(self.max_rate);
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now;
        // A little over one tick's worth of burst, plus a floor so a very low rate still lets a
        // small write through instead of starving entirely.
        let ceiling = self.rate * PACER_TICK.as_secs_f64() * 1.2 + PACER_MIN_CHUNK;
        self.tokens = (self.tokens + self.rate * elapsed).min(ceiling);
    }

    /// `Poll::Pending` while there are not yet `PACER_MIN_CHUNK` tokens to spend; the caller must
    /// not proceed with a write until this returns `Ready`. Spends what it allows up to `want`.
    fn poll_ready(&mut self, cx: &mut TaskContext<'_>, srtt: Duration, want: usize) -> Poll<usize> {
        if let Some(wait) = &mut self.wait {
            match wait.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => self.wait = None,
            }
        }
        self.observe(srtt);
        self.refill();
        if self.tokens < PACER_MIN_CHUNK.min(want as f64) {
            let need = PACER_MIN_CHUNK.min(want as f64) - self.tokens;
            let wait_secs = (need / self.rate.max(1.0)).clamp(0.001, 1.0);
            let mut sleep = Box::pin(tokio::time::sleep(Duration::from_secs_f64(wait_secs)));
            // Poll once now so the timer is armed and this task's waker is registered with it;
            // otherwise nothing would ever wake this write up again.
            let polled = sleep.as_mut().poll(cx);
            debug_assert!(matches!(polled, Poll::Pending));
            self.wait = Some(sleep);
            return Poll::Pending;
        }
        let spend = self.tokens.min(want as f64);
        self.tokens -= spend;
        Poll::Ready(spend as usize)
    }
}

struct GuardedStream {
    stream: KcpStream,
    _bridge: Option<TaskGuard>,
    _tuner: Option<TaskGuard>,
    measurements: Option<tuning::SharedMeasurements>,
    pacer: Option<Pacer>,
}
impl Drop for GuardedStream{
    fn drop(&mut self){
        let bridge=self._bridge.take();let tuner=self._tuner.take();
        let session=self.stream.shared_session();
        if session.kcp_socket().lock().can_close(){return;}
        if let Ok(runtime)=tokio::runtime::Handle::try_current(){
            runtime.spawn(async move{
                let _retained=(bridge,tuner);
                let until=tokio::time::Instant::now()+Duration::from_secs(10);
                while tokio::time::Instant::now()<until&&!session.kcp_socket().lock().can_close(){tokio::time::sleep(Duration::from_millis(10)).await;}
            });
        }
    }
}
impl AsyncRead for GuardedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, out);
        if let Some(measurements) = &self.measurements {
            measurements
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .read(out.filled().len() - before);
        }
        result
    }
}
impl AsyncWrite for GuardedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        // KCP limits the number of fragments accepted by one send call.
        // AsyncWrite may accept a prefix; write_all handles the remainder.
        let mut size = bytes.len().min(16 * 1024);
        if self.pacer.is_some() {
            let srtt = self.stream.session().kcp_socket().lock().srtt();
            let pacer = self.pacer.as_mut().unwrap();
            match pacer.poll_ready(cx, Duration::from_millis(srtt as u64), size) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(allowed) => size = size.min(allowed.max(1)),
            }
        }
        let result = Pin::new(&mut self.stream).poll_write(cx, &bytes[..size]);
        if let Poll::Ready(Ok(size)) = &result
            && let Some(measurements) = &self.measurements
        {
            measurements
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .written(*size);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// When packets last crossed in either direction, for the idle clean-up.
#[derive(Default)]
struct Activity(AtomicU64);
fn since_start() -> u64 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}
impl Activity {
    fn touch(&self) {
        self.0.store(since_start(), Ordering::Relaxed);
    }
    fn idle(&self) -> Duration {
        Duration::from_millis(since_start().saturating_sub(self.0.load(Ordering::Relaxed)))
    }
}

/// The most packets that may wait for the socket in one conversation (see `send_queue`).
const DELAYED_PACKETS: usize = 8192;

struct SinkState {
    encoder: FecEncoder,
    encoded: Outgoing,
    /// Counts `send_batch` calls, so the flush task can tell whether anything was sent while it
    /// waited.
    batches: u64,
}
/// Where a KCP session's packets go: FEC-encoded, straight onto the network socket, in the same
/// call that KCP made. (Earlier versions sent them to a loopback socket first, where another
/// task read, encoded and forwarded them.)
struct FecSink {
    outside: Arc<NetworkSocket>,
    peer: SocketAddr,
    mtu: usize,
    state: Arc<Mutex<SinkState>>,
    measurements: Option<tuning::SharedMeasurements>,
    activity: Arc<Activity>,
    /// Encoded packets the socket would not take yet (and every packet of a raw socket, which
    /// only has an async send). Bounded (`FecOptions::send_queue`); a full queue drops, like a
    /// datagram lost on the way, and KCP resends.
    delayed: mpsc::Sender<Vec<u8>>,
    dropped: AtomicU64,
    _delay_task: TaskGuard,
    /// Wakes the flush task when a group was left partial (`None` when partial flush is off).
    partial: Option<Arc<tokio::sync::Notify>>,
    _flush_task: Option<TaskGuard>,
}
impl std::fmt::Debug for FecSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FecSink").field("peer", &self.peer).finish()
    }
}
impl FecSink {
    /// Must be called inside a Tokio runtime.
    fn new(
        outside: Arc<NetworkSocket>,
        peer: SocketAddr,
        mtu: usize,
        measurements: Option<tuning::SharedMeasurements>,
        activity: Arc<Activity>,
        partial_flush: Option<Duration>,
        queue_limit: usize,
    ) -> Self {
        let (delayed, mut queue) = mpsc::channel::<Vec<u8>>(queue_limit.max(1));
        let socket = outside.clone();
        let task = tokio::spawn(async move {
            while let Some(packet) = queue.recv().await {
                if let Err(error) = socket.send_to(&packet, peer).await {
                    tracing::debug!(%error, "fec delayed send failed");
                }
            }
        });
        activity.touch();
        let state = Arc::new(Mutex::new(SinkState {
            encoder: FecEncoder::default(),
            encoded: Outgoing::default(),
            batches: 0,
        }));
        let (partial, flush_task) = match partial_flush {
            Some(delay) => {
                let notify = Arc::new(tokio::sync::Notify::new());
                let task = tokio::spawn(flush_partial_groups(
                    state.clone(),
                    notify.clone(),
                    outside.clone(),
                    peer,
                    delay,
                ));
                (Some(notify), Some(TaskGuard(task)))
            }
            None => (None, None),
        };
        Self {
            outside,
            peer,
            mtu,
            state,
            measurements,
            activity,
            delayed,
            dropped: AtomicU64::new(0),
            _delay_task: TaskGuard(task),
            partial,
            _flush_task: flush_task,
        }
    }
}

/// Sends the parity of a partial group once nothing more was sent for `delay`: the last packets
/// of a burst are then protected like the others instead of waiting for KCP's retransmission.
async fn flush_partial_groups(
    state: Arc<Mutex<SinkState>>,
    notify: Arc<tokio::sync::Notify>,
    outside: Arc<NetworkSocket>,
    peer: SocketAddr,
    delay: Duration,
) {
    loop {
        notify.notified().await;
        loop {
            let seen = state.lock().unwrap_or_else(|e| e.into_inner()).batches;
            tokio::time::sleep(delay).await;
            let parity = {
                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                if state.batches != seen && !state.encoder.shards.is_empty() {
                    // Still sending: the group may fill up by itself.
                    continue;
                }
                state.encoder.flush()
            };
            if let Some(parity) = parity
                && let Err(error) = outside.send_to(&parity, peer).await
            {
                tracing::debug!(%error, "fec partial parity not sent");
            }
            break;
        }
    }
}
impl PacketSink for FecSink {
    fn send_batch(&self, packets: &Outgoing) -> io::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let SinkState {
            encoder,
            encoded,
            batches,
        } = &mut *state;
        *batches += 1;
        let now = Instant::now();
        for packet in packets.iter() {
            let packet = &packet[..packet.len().min(self.mtu)];
            if let Some(stats) = &self.measurements {
                stats
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .observe(packet, true, now);
            }
            for out in encoder.encode(packet) {
                encoded.push(&out);
            }
        }
        if let Some(partial) = &self.partial
            && !encoder.shards.is_empty()
        {
            partial.notify_one();
        }
        self.activity.touch();
        let sent = match &*self.outside {
            NetworkSocket::Udp(socket) => {
                encoded
                    .send(socket, Some(self.peer))
                    .unwrap_or_else(|error| {
                        // As with any datagram that is lost: KCP and the parity cover it.
                        tracing::debug!(%error, "fec send failed");
                        encoded.len()
                    })
            }
            #[cfg(target_os = "linux")]
            NetworkSocket::Raw(_) => 0,
            NetworkSocket::Multipath {..} => 0,
        };
        for packet in encoded.iter().skip(sent) {
            if self.delayed.try_send(packet.to_vec()).is_err() {
                let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if dropped.is_power_of_two() {
                    tracing::debug!(dropped, "fec send queue full; packets dropped");
                }
            }
        }
        encoded.clear();
        Ok(())
    }

    /// Congested at three quarters full: `poll_send` then waits (the KCP window already does the
    /// same at `snd_wnd`/`rmt_wnd`) instead of this sink dropping a packet it never had room to
    /// queue, which used to come back ~one timeout later as a KCP resend of something that was
    /// simply never sent. A quarter of headroom is left so one more burst still queues instead of
    /// drops while the writer notices congestion and backs off.
    fn congested(&self) -> bool {
        self.delayed.capacity() <= self.delayed.max_capacity() / 4
    }
}

pub async fn connect(path: &ClientPath) -> Result<BoxIo> {
    path.fec.validate()?;
    if path.transport == Transport::Mirage {
        crate::mirage::validate(path.raw.as_ref())?;
    }
    let raw = matches!(
        path.transport,
        Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage
    );
    let mut options = path.fec.clone();
    options.packet_hopping_enabled=path.raw.as_ref().is_some_and(|raw|raw.hopping.enabled);
    if path.transport == Transport::FecRawGaming {
        options.profile = FecProfile::Gaming;
    }
    let peer = if raw {
        let settings = path.raw.as_ref().context("raw carrier options required")?;
        SocketAddr::new(IpAddr::V4(settings.peer_ip), settings.l4_port)
    } else {
        resolve(&path.addr).await?
    };
    if !raw && options.knock {
        knock(
            peer,
            Duration::from_millis(options.knock_timeout_ms),
            path.local_address.as_deref(),
        )
        .await?;
    }
    let mut mtu = options.envelope_mtu(raw);
    let network = if raw {
        raw_network(path.raw.as_ref(), false, mtu, options.initial_buffer()).await?
    } else {
        let socket = crate::carrier::udp_for_peer(peer, path.local_address.as_deref()).await?;
        socket.connect(peer).await?;
        NetworkSocket::Udp(socket)
    };
    let outside = Arc::new(network.fallback(&options,false,peer).await?);
    if let Some(limit)=outside.payload_limit(){mtu=mtu.min(limit);ensure!(mtu>=512,"raw Mirage overhead leaves less than the minimum 512-byte FEC MTU; reduce padding/redundancy or increase interface MTU");}
    if raw{let outer=mtu+100+if options.packet_hopping_enabled{crate::port_hop::OVERHEAD}else{0};options.mtu=outer;options.peer_mtu=Some(outer);}
    outside.set_socket_buffer_bytes(options.initial_buffer())?;
    let measurements = tuning::Measurements::shared(&options);
    let registry = TuningRegistry::default();
    if let Some(stats) = &measurements {
        registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(0, stats.clone());
    }
    let sink = Arc::new(FecSink::new(
        outside.clone(),
        peer,
        mtu,
        measurements.clone(),
        Arc::new(Activity::default()),
        options.partial_flush(),
        options.send_queue(raw),
    ));
    let stream =
        KcpStream::connect_with_sink(&options.kcp(raw), sink).context("open fec KCP session")?;
    let conversation = stream.session().conv().await;
    let session = stream.shared_session();
    let buffers = tuning::SocketBuffers::shared(registry, options.initial_buffer());
    let mut controller = measurements.as_ref().map(|measurements| {
        TaskGuard(tuning::Control::spawn(
            measurements.clone(),
            options.clone(),
            outside.clone(),
            Arc::new(AtomicUsize::new(1)),
            buffers,
            raw,
            stream.shared_session(),
        ))
    });
    if options.adaptive.enabled {
        let path_key = format!("{}|{}|{:?}", peer.ip(), path.local_address.as_deref().unwrap_or(""), path.raw.as_ref().and_then(|r|r.interface.as_deref()));
        let network=outside.clone();
        controller = Some(TaskGuard(crate::adaptive::spawn(stream.shared_session(), options.adaptive.clone(), options.profile == FecProfile::Gaming, path_key,Arc::new(move||network.lane_active()))));
    }
    let receive_measurements = measurements.clone();
    let task = tokio::spawn(async move {
        // Datagrams are read in batches: one system call moves up to 64 of them.
        let mut received = Incoming::new();
        let mut decoder = FecDecoder::default();
        let mut inputs: Vec<Vec<u8>> = Vec::new();
        loop {
            let count = match outside.recv_batch(&mut received).await {
                Ok(count) => count,
                // A connected UDP socket reports an ICMP "port unreachable" (the server restarting,
                // a blip on the path) as an error on the next receive. That is one lost datagram,
                // not the end of the tunnel.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                    ) =>
                {
                    tracing::debug!(%error, "fec receive: transient error");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%error, "fec receive stopped");
                    break;
                }
            };
            for index in 0..count {
                let (packet, _) = received.packet(index);
                if fec_conversation(packet, mtu) != Some(conversation) {
                    continue;
                }
                for out in decoder.decode(packet, mtu) {
                    if let Some(stats) = &receive_measurements {
                        stats.lock().unwrap_or_else(|e| e.into_inner()).observe(
                            &out,
                            false,
                            Instant::now(),
                        );
                    }
                    inputs.push(out);
                }
            }
            session.input_direct(inputs.iter().map(Vec::as_slice));
            inputs.clear();
        }
    });
    let guard = TaskGuard(task);
    Ok(Box::new(GuardedStream {
        stream,
        _bridge: Some(guard),
        _tuner: controller,
        measurements,
        pacer: options
            .pacer
            .then(|| Pacer::new(PACER_MIN_RATE, PACER_MAX_RATE)),
    }))
}

/// One remote KCP conversation on a listener.
struct Peer {
    session: Arc<KcpSession>,
    decoder: FecDecoder,
    /// Decoded KCP packets of the current round, waiting to be input together.
    inbox: Vec<Vec<u8>>,
    activity: Arc<Activity>,
    measurements: Option<tuning::SharedMeasurements>,
    id: u64,
    registry: TuningRegistry,
    population: Arc<AtomicUsize>,
}
type TuningRegistry = Arc<Mutex<HashMap<u64, tuning::SharedMeasurements>>>;
impl Drop for Peer {
    fn drop(&mut self) {
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
        self.population.fetch_sub(1, Ordering::Relaxed);
        self.session.close();
    }
}
type Accepted = (KcpStream, Option<tuning::SharedMeasurements>, SocketAddr);
pub struct FecListener {
    accept_rx: mpsc::Receiver<Accepted>,
    _bridge: TaskGuard,
    address: SocketAddr,
    options: FecOptions,
    outside: Arc<NetworkSocket>,
    population: Arc<AtomicUsize>,
    raw: bool,
    buffers: Arc<tuning::SocketBuffers>,
}
impl FecListener {
    pub async fn bind(settings: &Listener) -> Result<Self> {
        settings.fec.validate()?;
        let raw = matches!(
            settings.transport,
            Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage
        );
        let mut options = settings.fec.clone();
        options.packet_hopping_enabled=settings.raw.as_ref().is_some_and(|raw|raw.hopping.enabled);
        if settings.transport == Transport::Mirage {
            crate::mirage::validate(settings.raw.as_ref())?;
        }
        if settings.transport == Transport::FecRawGaming {
            options.profile = FecProfile::Gaming;
        }
        if raw {
            options.knock = false;
        }
        let mut mtu = options.envelope_mtu(raw);
        let network = if raw {
            raw_network(settings.raw.as_ref(), true, mtu, options.initial_buffer()).await?
        } else {
            NetworkSocket::Udp(
                UdpSocket::bind(&settings.addr)
                    .await
                    .context("bind fec-udp UDP listener")?,
            )
        };
        let fallback_peer=if raw {
            let raw=settings.raw.as_ref().context("raw options")?;
            // RawSocket normalizes every physical source-port pair to l4_port.
            // The TCP lane must use the identical demux key, not the wire source port.
            SocketAddr::new(raw.peer_ip.into(),raw.l4_port)
        } else {network.local_addr()?};
        let outside = Arc::new(network.fallback(&options,true,fallback_peer).await?);
        if let Some(limit)=outside.payload_limit(){mtu=mtu.min(limit);ensure!(mtu>=512,"raw Mirage overhead leaves less than the minimum 512-byte FEC MTU; reduce padding/redundancy or increase interface MTU");}
        if raw{let outer=mtu+100+if options.packet_hopping_enabled{crate::port_hop::OVERHEAD}else{0};options.mtu=outer;options.peer_mtu=Some(outer);}
        outside.set_socket_buffer_bytes(options.initial_buffer())?;
        let address = outside.local_addr()?;
        let knock_socket = if options.knock {
            Some(
                UdpSocket::bind(knock_address(address))
                    .await
                    .context("bind fec-udp knock listener")?,
            )
        } else {
            None
        };
        let (accept_tx, accept_rx) = mpsc::channel::<Accepted>(1024);
        let registry = TuningRegistry::default();
        let task_registry = registry.clone();
        let buffers = tuning::SocketBuffers::shared(registry.clone(), options.initial_buffer());
        let population = Arc::new(AtomicUsize::new(0));
        let task_population = population.clone();
        let task_outside = outside.clone();
        let task_options = options.clone();
        let task = tokio::spawn(async move {
            let outside = task_outside;
            let options = task_options;
            let kcp = options.kcp(raw);
            let mut peers: HashMap<(SocketAddr, u32), Peer> = HashMap::new();
            let mut next_id = 0u64;
            let mut knocks: HashMap<IpAddr, Instant> = HashMap::new();
            let mut received = Incoming::new();
            let mut knock_buffer = [0; 64];
            let mut cleanup = tokio::time::interval(Duration::from_secs(5));
            loop {
                let result: io::Result<()> = tokio::select! {
                    count=outside.recv_batch(&mut received)=>async {
                        let mut touched: Vec<(SocketAddr,u32)> = Vec::new();
                        for index in 0..count? {
                            let (packet,source)=received.packet(index);
                            let Some(remote)=source else {continue;};
                            let Some(conversation)=fec_conversation(packet,mtu) else {continue;};
                            let key=(remote,conversation);
                            if !peers.contains_key(&key) {
                                if options.knock && !knocks.contains_key(&remote.ip()) { continue; }
                                if peers.len()>=options.peer_limit() { continue; }
                                if options.max_peers_per_ip>0
                                    && peers.keys().filter(|(address,_)|address.ip()==remote.ip()).count()>=options.max_peers_per_ip {
                                    continue;
                                }
                                let mut decoder=FecDecoder::default();
                                let packets=decoder.decode(packet,mtu);
                                if packets.iter().all(|p|p.len()<24) { continue; }
                                let id=next_id; next_id+=1;
                                let measurements=tuning::Measurements::shared(&options);
                                let activity=Arc::new(Activity::default());
                                let sink=Arc::new(FecSink::new(outside.clone(),remote,mtu,measurements.clone(),activity.clone(),options.partial_flush(),options.send_queue(raw)));
                                let socket=match KcpSocket::with_sink(&kcp,conversation,sink,kcp.stream) {
                                    Ok(socket)=>socket,
                                    Err(error)=>{ tracing::debug!(%error,"fec session not created"); continue; }
                                };
                                let session=KcpSession::new_shared_server(socket,kcp.session_expire);
                                let stream=KcpStream::with_session(session.clone());
                                if let Some(stats)=&measurements {
                                    task_registry.lock().unwrap_or_else(|e|e.into_inner()).insert(id,stats.clone());
                                }
                                task_population.fetch_add(1,Ordering::Relaxed);
                                // The peer owns the registry entry and the population count from here
                                // on, so a refused session cleans up by being dropped.
                                let mut peer=Peer {session,decoder,inbox:Vec::new(),activity,measurements:measurements.clone(),id,
                                    registry:task_registry.clone(),population:task_population.clone()};
                                if accept_tx.try_send((stream,measurements,remote)).is_err() { continue; }
                                for packet in packets { if packet.len()>=24 {
                                    if let Some(stats)=&peer.measurements {stats.lock().unwrap_or_else(|e|e.into_inner()).observe(&packet,false,Instant::now());}
                                    peer.inbox.push(packet);
                                } }
                                peers.insert(key,peer);
                                touched.push(key);
                            } else if let Some(peer)=peers.get_mut(&key) {
                                for packet in peer.decoder.decode(packet,mtu) {
                                    if packet.len()>=24 {
                                        if let Some(stats)=&peer.measurements {stats.lock().unwrap_or_else(|e|e.into_inner()).observe(&packet,false,Instant::now());}
                                        peer.inbox.push(packet);
                                    }
                                }
                                peer.activity.touch();
                                if !touched.contains(&key) { touched.push(key); }
                            }
                        }
                        // Everything decoded in this round goes into each session together.
                        for key in touched {
                            if let Some(peer)=peers.get_mut(&key) {
                                peer.session.input_direct(peer.inbox.iter().map(Vec::as_slice));
                                peer.inbox.clear();
                            }
                        }
                        Ok(())
                    }.await,
                    read=async { match &knock_socket { Some(socket)=>socket.recv_from(&mut knock_buffer).await,
                        None=>std::future::pending().await } }=>async {
                        let (size,remote)=read?;
                        if size==1 && knock_buffer[0]==b'P' {
                            // A full table drops its oldest entry instead of refusing: a flood of
                            // knocks from spoofed addresses must not lock real clients out.
                            if knocks.len()>=options.max_peers && !knocks.contains_key(&remote.ip())
                                && let Some(oldest)=knocks.iter().min_by_key(|(_,time)|**time).map(|(ip,_)|*ip)
                            {
                                knocks.remove(&oldest);
                            }
                            knocks.insert(remote.ip(),Instant::now());
                            if let Some(socket)=&knock_socket { socket.send_to(b"A",remote).await?; }
                        }
                        Ok(())
                    }.await,
                    _=cleanup.tick()=>{ peers.retain(|_,p|p.activity.idle()<Duration::from_secs(options.peer_idle_sec));
                        knocks.retain(|_,time|time.elapsed()<Duration::from_secs(options.knock_ttl_sec)); Ok(()) },
                };
                if let Err(error) = result {
                    // A single bad datagram or a transient send/recv error (e.g. an unrelated
                    // ICMP port-unreachable landing on this unconnected socket) must not take
                    // down every peer on the listener; the plain KCP listener tolerates the
                    // same class of error the same way (vendor/tokio_kcp/src/listener.rs).
                    tracing::debug!(%error, "fec listener socket error; continuing");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        });
        Ok(Self {
            accept_rx,
            _bridge: TaskGuard(task),
            address,
            options,
            outside,
            population,
            raw,
            buffers,
        })
    }
    pub async fn accept(&mut self) -> Result<BoxIo> {
        let (stream, measurements, peer) = self
            .accept_rx
            .recv()
            .await
            .context("fec listener stopped")?;
        let mut controller = measurements.as_ref().map(|stats| {
            TaskGuard(tuning::Control::spawn(
                stats.clone(),
                self.options.clone(),
                self.outside.clone(),
                self.population.clone(),
                self.buffers.clone(),
                self.raw,
                stream.shared_session(),
            ))
        });
        if self.options.adaptive.enabled {
            let path_key = format!("{}|{}|{}", peer.ip(), self.address.ip(), self.raw);
            let network=self.outside.clone();
            controller = Some(TaskGuard(crate::adaptive::spawn(stream.shared_session(), self.options.adaptive.clone(), self.options.profile == FecProfile::Gaming, path_key,Arc::new(move||network.lane_active()))));
        }
        Ok(Box::new(GuardedStream {
            stream,
            _bridge: None,
            _tuner: controller,
            measurements,
            pacer: self
                .options
                .pacer
                .then(|| Pacer::new(PACER_MIN_RATE, PACER_MAX_RATE)),
        }))
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_pacer_grows_on_a_clean_rtt_and_shrinks_once_it_grows() {
        let mut pacer = Pacer::new(1_000.0, 10_000.0);
        // observe is rate-limited to once per PACER_TICK since Pacer::new; nothing judged yet.
        pacer.observe(Duration::from_millis(50));
        assert_eq!(
            pacer.rate, 1_000.0,
            "too soon since new() to judge anything yet"
        );
        tokio::time::advance(PACER_TICK).await;
        pacer.observe(Duration::from_millis(50)); // first real sample: becomes min_rtt
        assert_eq!(pacer.rate, 1_100.0, "grew: at its own (new) minimum");
        tokio::time::advance(PACER_TICK).await;
        pacer.observe(Duration::from_millis(51)); // within slack of a 50ms min_rtt
        assert_eq!(pacer.rate, 1_210.0, "still grew: within slack");
        tokio::time::advance(PACER_TICK).await;
        pacer.observe(Duration::from_millis(200)); // well past min_rtt + slack: a queue is building
        assert_eq!(
            pacer.rate,
            (1_210.0_f64 * 0.93),
            "shrank: RTT grew past slack"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_pacer_never_leaves_its_floor_or_ceiling() {
        let mut pacer = Pacer::new(1_000.0, 2_000.0);
        for _ in 0..50 {
            tokio::time::advance(PACER_TICK).await;
            pacer.observe(Duration::from_millis(10)); // always clean: keeps growing
        }
        assert_eq!(pacer.rate, 2_000.0, "capped at max_rate");
        for _ in 0..50 {
            tokio::time::advance(PACER_TICK).await;
            pacer.observe(Duration::from_millis(500)); // always congested: keeps shrinking
        }
        assert_eq!(pacer.rate, 1_000.0, "floored at min_rate");
    }

    #[tokio::test(start_paused = true)]
    async fn poll_ready_waits_for_enough_tokens_then_spends_them() {
        let mut pacer = Pacer::new(1_000.0, 1_000.0); // fixed 1000 B/s for a predictable wait
        let waker = std::task::Waker::noop();
        let mut cx = TaskContext::from_waker(waker);
        // No tokens yet: PACER_MIN_CHUNK (1024) at 1000 B/s needs a bit over a second.
        assert!(
            pacer
                .poll_ready(&mut cx, Duration::from_millis(10), 2000)
                .is_pending()
        );
        tokio::time::advance(Duration::from_millis(200)).await;
        assert!(
            pacer
                .poll_ready(&mut cx, Duration::from_millis(10), 2000)
                .is_pending(),
            "not enough time has passed yet"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        match pacer.poll_ready(&mut cx, Duration::from_millis(10), 2000) {
            Poll::Ready(allowed) => assert!(
                (1..=2000).contains(&allowed),
                "spends what it has, capped at what was asked for"
            ),
            Poll::Pending => panic!("plenty of time has passed"),
        }
    }

    #[test]
    fn the_multiplication_table_is_the_field_multiplication() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(
                    multiplication_table()[usize::from(a)][usize::from(b)],
                    gf_multiply(a, b)
                );
            }
        }
    }

    #[test]
    fn multiply_add_matches_the_byte_by_byte_definition() {
        let source: Vec<u8> = (0..1500u32).map(|i| (i * 7 + 3) as u8).collect();
        for coefficient in [0, 1, 2, 3, 129, 255] {
            let mut fast: Vec<u8> = (0..1600u32).map(|i| (i * 13) as u8).collect();
            let mut slow = fast.clone();
            multiply_add(&mut fast, &source, coefficient);
            for (position, &byte) in source.iter().enumerate() {
                slow[position] ^= gf_multiply(coefficient, byte);
            }
            assert_eq!(fast, slow, "coefficient {coefficient}");
        }
    }

    #[test]
    fn parity_matches_independent_vandermonde_reference_and_recovers_each_loss() {
        let mut encoder = FecEncoder::default();
        let mut packets = Vec::new();
        for index in 0..10 {
            packets.extend(encoder.encode(&(0..=index).collect::<Vec<u8>>()));
        }
        assert_eq!(
            &packets[10][6..],
            &hex::decode("8e0000802cd604b872a50812").unwrap()
        );
        for lost in 0..10 {
            let mut decoder = FecDecoder::default();
            let mut recovered = Vec::new();
            for (index, packet) in packets.iter().enumerate() {
                if index != lost {
                    recovered.extend(decoder.decode(packet, 1350));
                }
            }
            assert_eq!(recovered.len(), 10, "loss at shard {lost}");
            assert!(recovered.contains(&(0..=lost as u8).collect::<Vec<_>>()));
        }
    }
    #[test]
    fn fec_data_and_parity_preserve_conversation_for_demultiplexing() {
        let conversation = 0x12345678_u32;
        let mut encoder = FecEncoder::default();
        let mut packets = Vec::new();
        for index in 0..10 {
            let mut payload = vec![index as u8; 24 + index];
            payload[..4].copy_from_slice(&conversation.to_le_bytes());
            packets.extend(encoder.encode(&payload));
        }
        assert_eq!(packets.len(), 11);
        for packet in packets {
            assert_eq!(fec_conversation(&packet, 1350), Some(conversation));
        }
    }
    /// A KCP-looking packet of conversation `conversation`: its 24-byte header, then `body`.
    fn kcp_packet(conversation: u32, body: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x51; 24];
        packet[..4].copy_from_slice(&conversation.to_le_bytes());
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn a_loss_in_a_partial_group_is_repaired_by_its_partial_parity() {
        let conversation = 0x0bad_cafe_u32;
        // Every size of a partial group, including those whose coefficients sum to zero (4, 8).
        for count in 1..DATA {
            let mut encoder = FecEncoder::default();
            // A full group first, so the partial one is not at sequence 0.
            let mut packets = Vec::new();
            let mut sent = Vec::new();
            for index in 0..DATA + count {
                let packet = kcp_packet(conversation, &vec![index as u8; 3 * index]);
                packets.extend(encoder.encode(&packet));
                sent.push(packet);
            }
            let parity = encoder.flush().expect("a partial parity");
            assert!(encoder.flush().is_none(), "the group was ended");
            assert_eq!(fec_conversation(&parity, 1350), Some(conversation));
            assert_eq!(u32::from_le_bytes(parity[..4].try_into().unwrap()), 21);
            assert_eq!(parity[4..6], [KIND_PARTIAL, count as u8]);
            // The next packet starts a new group.
            let next = encoder.encode(&kcp_packet(conversation, b"next")).remove(0);
            assert_eq!(u32::from_le_bytes(next[..4].try_into().unwrap()), 22);
            for lost in 0..count {
                let mut decoder = FecDecoder::default();
                let mut received = Vec::new();
                for (index, packet) in packets.iter().enumerate() {
                    // packets: 10 data, 1 parity, then the partial group's data.
                    if index != DATA + 1 + lost {
                        received.extend(decoder.decode(packet, 1350));
                    }
                }
                assert_eq!(received.len(), DATA + count - 1);
                received.extend(decoder.decode(&parity, 1350));
                assert_eq!(received.len(), DATA + count, "count {count}, lost {lost}");
                assert_eq!(received.last(), Some(&sent[DATA + lost]));
                // The parity again (a replay) adds nothing.
                assert!(decoder.decode(&parity, 1350).is_empty());
            }
        }
        // Nothing to end: no packet.
        assert!(FecEncoder::default().flush().is_none());
    }

    #[test]
    fn partial_parity_kinds_out_of_range_are_ignored() {
        let mut encoder = FecEncoder::default();
        for _ in 0..3 {
            encoder.encode(&kcp_packet(7, b"abc"));
        }
        let parity = encoder.flush().unwrap();
        for count in [0u8, 10, 11, 255] {
            let mut bad = parity.clone();
            bad[5] = count;
            assert_eq!(fec_conversation(&bad, 1350), None);
            assert!(FecDecoder::default().decode(&bad, 1350).is_empty());
        }
        // In a data slot it is not a parity.
        let mut misplaced = parity.clone();
        misplaced[..4].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(fec_conversation(&misplaced, 1350), None);
    }

    #[tokio::test]
    async fn an_idle_sink_sends_the_partial_parity() -> Result<()> {
        let receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let sender = UdpSocket::bind("127.0.0.1:0").await?;
        let sink = FecSink::new(
            Arc::new(NetworkSocket::Udp(sender)),
            receiver.local_addr()?,
            1350,
            None,
            Arc::new(Activity::default()),
            Some(Duration::from_millis(10)),
            256,
        );
        let mut batch = Outgoing::default();
        for index in 0..3 {
            batch.push(&kcp_packet(9, &[index; 40]));
        }
        sink.send_batch(&batch)?;
        let mut buffer = [0; 2048];
        let mut kinds = Vec::new();
        for _ in 0..4 {
            let size = timeout(Duration::from_secs(2), receiver.recv(&mut buffer)).await??;
            kinds.push((buffer[4], buffer[5], size));
        }
        assert_eq!(kinds[..3], [(0xf1, 0, 72), (0xf1, 0, 72), (0xf1, 0, 72)]);
        assert_eq!(kinds[3], (KIND_PARTIAL, 3, 72));
        // Only one per quiet moment.
        assert!(
            timeout(Duration::from_millis(100), receiver.recv(&mut buffer))
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_sink_near_its_queue_limit_reports_congested() -> Result<()> {
        let receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let sender = UdpSocket::bind("127.0.0.1:0").await?;
        let sink = FecSink::new(
            Arc::new(NetworkSocket::Udp(sender)),
            receiver.local_addr()?,
            1350,
            None,
            Arc::new(Activity::default()),
            None,
            8,
        );
        assert!(!sink.congested(), "an empty queue is not congested");
        // Fill the delayed queue directly (as a packet the socket would not take right away
        // would): three quarters full is where poll_send starts waiting instead of this sink
        // dropping what it has no room to queue.
        for _ in 0..5 {
            sink.delayed.try_send(Vec::new()).unwrap();
        }
        assert!(!sink.congested(), "5 of 8 is not yet three quarters full");
        sink.delayed.try_send(Vec::new()).unwrap();
        assert!(sink.congested(), "6 of 8 is three quarters full");
        Ok(())
    }

    #[test]
    fn the_send_queue_follows_the_window() {
        let mut options = FecOptions::default();
        assert_eq!(options.send_queue(false), 2048);
        options.sndwnd = 128;
        assert_eq!(options.send_queue(false), 256);
        options.sndwnd = 8192;
        assert_eq!(options.send_queue(false), DELAYED_PACKETS);
        options.tuner.mode = FecTunerMode::Auto;
        options.tuner.max_window_bytes = 4 << 20;
        assert_eq!(options.send_queue(false), 2 * (4 << 20) / (1350 - 8));
    }

    #[test]
    fn malformed_fec_and_replays_do_not_escape_or_grow_storage() {
        let mut decoder = FecDecoder::default();
        let mut encoder = FecEncoder::default();
        let packet = encoder.encode(b"valid").remove(0);
        assert_eq!(decoder.decode(&packet, 1350), vec![b"valid".to_vec()]);
        assert!(decoder.decode(&packet, 1350).is_empty());
        for size in 0..8 {
            assert!(decoder.decode(&packet[..size], 1350).is_empty());
        }
        let mut invalid = packet.clone();
        invalid[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(decoder.decode(&invalid, 1350).is_empty());
        invalid = packet.clone();
        invalid[..4].copy_from_slice(&10_u32.to_le_bytes());
        assert!(decoder.decode(&invalid, 1350).is_empty());
        for seq in (0..1000).step_by(11) {
            let mut next = packet.clone();
            next[..4].copy_from_slice(&(seq as u32).to_le_bytes());
            decoder.decode(&next, 1350);
            assert!(decoder.groups.len() <= MAX_GROUPS);
        }
    }
    #[test]
    fn knock_port_wrap_and_profiles_match_expected_parameters() {
        assert_eq!(
            knock_address("127.0.0.1:1234".parse().unwrap()).port(),
            11_234
        );
        assert_eq!(
            knock_address("127.0.0.1:60000".parse().unwrap()).port(),
            59_000
        );
        let mut options = FecOptions::default();
        assert!(!options.kcp(true).nodelay.nodelay);
        assert!(options.kcp(false).nodelay.nodelay);
        options.profile = FecProfile::Gaming;
        assert!(options.kcp(true).nodelay.nodelay);
        assert_eq!(options.kcp(true).nodelay.interval, 10);
        assert_eq!(options.kcp(true).nodelay.resend, 2);
        assert!(options.kcp(true).nodelay.nc);
        assert_eq!(options.kcp(false).mtu, 1342);
        assert!(!options.kcp(true).flush_acks_input);
        assert!(options.kcp(false).flush_acks_input);
        assert_eq!(options.kcp(true).mtu, 1242);
        options.mtu = 512;
        assert_eq!(options.kcp(true).mtu, 504);
        options.mtu = 9000;
        assert_eq!(options.kcp(true).mtu, 1492);
    }
    #[test]
    fn configured_windows_and_shared_auto_budget_are_bounded() {
        let mut options = FecOptions {
            sndwnd: 2048,
            rcvwnd: 4096,
            ..FecOptions::default()
        };
        assert_eq!(options.kcp(false).wnd_size, (2048, 4096));
        options.profile = FecProfile::Gaming;
        assert_eq!(options.kcp(true).wnd_size, (1024, 1024));
        options.tuner.mode = FecTunerMode::Auto;
        options.tuner.memory_budget_mb = 8;
        options.max_peers = 4096;
        assert!(options.peer_limit() < 4096);
        assert!(options.peer_limit() * 4 * options.minimum_allocation() <= 8 * 1024 * 1024);
        assert!(options.kcp(false).wnd_size.0 <= 1024);
        options.tuner.min_buffer_bytes = 64 * 1024 * 1024;
        options.tuner.max_buffer_bytes = 64 * 1024 * 1024;
        assert!(options.validate().is_err());
    }
    #[test]
    fn timing_overrides_map_to_kcp_flags_and_preserve_peer_mtu_minimum() {
        let mut options = FecOptions {
            nodelay: Some(false),
            interval_ms: Some(50),
            resend: Some(0),
            congestion_control: Some(true),
            write_delay: Some(true),
            ack_no_delay: Some(false),
            peer_mtu: Some(1000),
            ..FecOptions::default()
        };
        options.validate().unwrap();
        for raw in [false, true] {
            let profile = options.kcp(raw);
            assert!(!profile.nodelay.nodelay);
            assert_eq!(profile.nodelay.interval, 50);
            assert_eq!(profile.nodelay.resend, 0);
            assert!(!profile.nodelay.nc);
            assert!(!profile.flush_write);
            assert!(!profile.flush_acks_input);
        }
        assert_eq!(options.kcp(true).mtu, 892);
        assert_eq!(options.kcp(false).mtu, 1342);
        options.peer_mtu = Some(9000);
        assert_eq!(options.kcp(true).mtu, 1242);
        options.peer_mtu = Some(512);
        assert_eq!(options.kcp(true).mtu, 504);
        options.interval_ms = Some(9);
        assert!(options.validate().is_err());
        options.interval_ms = Some(5001);
        assert!(options.validate().is_err());
        options.interval_ms = Some(10);
        options.resend = Some(256);
        assert!(options.validate().is_err());
        options.resend = Some(255);
        options.tuner.mode = FecTunerMode::Auto;
        options.tuner.max_window_bytes = 256 * 1024;
        assert!(options.validate().is_err());
    }
}
