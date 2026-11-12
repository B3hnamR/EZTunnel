//! Unreliable IP datagrams over raw Ethernet/IPv4 envelopes.
//! Noise IK provides authentication. Independent nonces allow loss
//! and reordering; an authenticated sliding replay window rejects duplicates.
use crate::{
    config::{Config, Mode, decode_key},
    farewell::Farewell,
    raw_socket::RawSocket,
    transport::NOISE_PATTERN,
    tun_device::{TunDevice, validate_packet},
};
use anyhow::{Context, Result, ensure};
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::{collections::HashMap, time::Duration};
use tokio::time::{self, Instant};
mod mtu;
mod parity;

const MAGIC: &[u8; 5] = b"EZTU\x01";
const H1: u8 = 1;
const H2: u8 = 2;
const DATA: u8 = 3;
const IP: u8 = 1;
const PING: u8 = 2;
const PONG: u8 = 3;
/// The sender is stopping (0.8.5). A 0.8.4 receiver rejects the unknown type after
/// authenticating it, without touching the session, so it simply does not react.
const BYE: u8 = 4;
/// One piece of an IP packet too big for a single outer raw packet (`tun.fragment`, 0.8.11). A
/// peer that does not know this type rejects it the same way BYE taught an 0.8.4 peer to: after
/// authenticating, without touching the session, so it simply does not react (the whole datagram
/// is then incomplete and dropped once `FRAG_KEEP` passes, same as any other lost IP packet here).
const IP_FRAG: u8 = 5;
const MTU_PROBE: u8 = 6;
const MTU_REPLY: u8 = 7;
const HEADER: usize = 30; // magic(5), type(1), session(16), counter(8)
pub const DATAGRAM_OVERHEAD: usize = HEADER + 16 + 1;
/// Bytes of `IP_FRAG`'s own header before the piece of the original packet: type(1), frag id(2),
/// index(1), count(1).
const FRAG_HEADER: usize = 5;
/// Pieces an oversized datagram may be split into. u8-sized on the wire; this also bounds the
/// memory one incomplete reassembly can hold.
const FRAG_MAX_PIECES: usize = 64;
/// Incomplete datagrams kept at once, across every frag id; the oldest is dropped to make room.
const FRAG_PENDING: usize = 256;
/// An incomplete datagram older than this is dropped: a piece that will never arrive must not
/// hold memory forever.
const FRAG_KEEP: Duration = Duration::from_secs(2);
const PROLOGUE: &[u8] = crate::session_crypto::RAW_DOMAIN;
const SESSION_RENEW: Duration = Duration::from_secs(300);
const SESSION_LIMIT: Duration = Duration::from_secs(360);
/// Bound handshake input before passing it to Noise; outer packets must fit MTU.
const HANDSHAKE_PAYLOAD_MAX: usize = 4096;
fn prologue(version: u8, parity: bool) -> Result<Vec<u8>> {
    crate::session_crypto::prologue(PROLOGUE, version, parity)
}

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bits: [u64; 4],
}
impl ReplayWindow {
    fn seen(&self, nonce: u64) -> bool {
        if let Some(highest) = self.highest {
            if nonce > highest {
                return false;
            }
            let age = highest - nonce;
            age >= 256 || self.bits[age as usize / 64] & (1_u64 << (age % 64)) != 0
        } else {
            false
        }
    }
    fn mark(&mut self, nonce: u64) {
        match self.highest {
            None => {
                self.highest = Some(nonce);
                self.bits = [1, 0, 0, 0];
            }
            Some(highest) if nonce > highest => {
                let shift = nonce - highest;
                if shift >= 256 {
                    self.bits = [0; 4];
                } else {
                    let old = self.bits;
                    let words = shift as usize / 64;
                    let remainder = shift % 64;
                    for index in 0..4 {
                        self.bits[index] = if index >= words {
                            old[index - words] << remainder
                        } else {
                            0
                        };
                        if remainder > 0 && index > words {
                            self.bits[index] |= old[index - words - 1] >> (64 - remainder);
                        }
                    }
                }
                self.bits[0] |= 1;
                self.highest = Some(nonce);
            }
            Some(highest) => {
                let age = highest - nonce;
                if age < 256 {
                    self.bits[age as usize / 64] |= 1_u64 << (age % 64);
                }
            }
        }
    }
}

struct Session {
    cipher: StatelessTransportState,
    created: Instant,
    codecs: Option<crate::wire::Codecs>,
    id: [u8; 16],
    counter: u64,
    replay: ReplayWindow,
    /// Fragment state belongs to this authenticated cipher/session, not the device.
    fragments: Reassembly,
    parity: parity::Parity,
    mtu: mtu::Probe,
    mtu_reported: bool,
    last_authenticated: Instant,
    last_heartbeat: Instant,
    /// When the oldest ping that nothing has answered yet was sent.
    unanswered_since: Option<Instant>,
}
impl Session {
    fn finish(
        handshake: HandshakeState,
        version: u8,
    ) -> Result<Self> {
        let id = handshake.get_handshake_hash()[..16].try_into()?;
        let traffic = crate::session_crypto::stateless(handshake, version)?;
        Ok(Self {
            created: Instant::now(),
            cipher: traffic.state,
            codecs: traffic.codecs,
            id,
            counter: 0,
            replay: ReplayWindow::default(),
            fragments: Reassembly::default(),
            parity: parity::Parity::default(),
            mtu: mtu::Probe::default(),
            mtu_reported: false,
            last_authenticated: Instant::now(),
            last_heartbeat: Instant::now(),
            unanswered_since: None,
        })
    }
    /// A ping; the first one nothing answers starts the silence clock.
    fn ping(&mut self) -> Result<Vec<u8>> {
        self.last_heartbeat = Instant::now();
        self.unanswered_since.get_or_insert_with(Instant::now);
        self.encode(&[PING])
    }
    fn encode(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        ensure!(self.created.elapsed() < SESSION_LIMIT, "raw session key expired");
        ensure!(
            self.counter < u64::MAX,
            "raw TUN send nonce exhausted; reconnect required"
        );
        let rotated = self.codecs.as_ref().map(|codecs| {
            let mut bytes = payload.to_vec();
            codecs.tx.encode(self.counter, &mut bytes);
            bytes
        });
        let payload = rotated.as_deref().unwrap_or(payload);
        let mut packet = Vec::with_capacity(HEADER + payload.len() + 16);
        packet.extend_from_slice(MAGIC);
        packet.push(DATA);
        packet.extend_from_slice(&self.id);
        packet.extend(self.counter.to_be_bytes());
        packet.resize(HEADER + payload.len() + 16, 0);
        let size = self
            .cipher
            .write_message(self.counter, payload, &mut packet[HEADER..])?;
        packet.truncate(HEADER + size);
        self.counter += 1;
        Ok(packet)
    }
    fn decode(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        self.decode_inner(packet)
    }
    fn decode_inner(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        ensure!(self.created.elapsed() < SESSION_LIMIT, "raw session key expired");
        if packet.len() < HEADER + 17
            || &packet[..5] != MAGIC
            || packet[5] != DATA
            || packet[6..22] != self.id
        {
            return Ok(None);
        }
        let nonce = u64::from_be_bytes(packet[22..30].try_into()?);
        if nonce == u64::MAX || self.replay.seen(nonce) {
            return Ok(None);
        }
        let mut payload = vec![0; packet.len() - HEADER];
        let size = self
            .cipher
            .read_message(nonce, &packet[HEADER..], &mut payload)?;
        // Authentication MUST precede any replay-window advancement.
        self.replay.mark(nonce);
        payload.truncate(size);
        if let Some(codecs) = &self.codecs {
            codecs.rx.decode(nonce, &mut payload);
        }
        ensure!(
            !payload.is_empty()
                && matches!(
                    payload[0],
                    IP | PING | PONG | BYE | IP_FRAG | MTU_PROBE | MTU_REPLY | parity::TAG
                ),
            "unknown authenticated raw TUN payload"
        );
        ensure!(
            matches!(
                payload[0],
                IP | IP_FRAG | MTU_PROBE | MTU_REPLY | parity::TAG
            ) || payload.len() == 1,
            "invalid raw TUN heartbeat payload"
        );
        ensure!(
            payload[0] != IP_FRAG || payload.len() > FRAG_HEADER,
            "invalid raw TUN fragment payload"
        );
        self.last_authenticated = Instant::now();
        self.unanswered_since = None;
        Ok(Some(payload))
    }
}

struct Initiating {
    handshake: HandshakeState,
    version: u8,
    request: Vec<u8>,
    id: [u8; 16],
    started: Instant,
    last_sent: Instant,
}
impl Initiating {
    #[cfg(test)]
    fn new(private: &[u8; 32], server: &[u8; 32]) -> Result<Self> {
        Self::for_version(private, server, 1)
    }
    #[cfg(test)]
    fn for_version(private: &[u8; 32], server: &[u8; 32], version: u8) -> Result<Self> {
        Self::for_features(private, server, version, false)
    }
    fn for_features(
        private: &[u8; 32],
        server: &[u8; 32],
        version: u8,
        parity: bool,
    ) -> Result<Self> {
        let mut handshake = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(private)?
            .remote_public_key(server)?
            .prologue(&prologue(version, parity)?)?
            .build_initiator()?;
        let mut message = vec![0; HANDSHAKE_PAYLOAD_MAX + 96];
        let size = handshake.write_message(&[], &mut message)?;
        message.truncate(size);
        let id = message[..16].try_into()?;
        let mut request = MAGIC.to_vec();
        request.push(H1);
        request.extend(message);
        Ok(Self {
            handshake,
            version,
            request,
            id,
            started: Instant::now(),
            last_sent: Instant::now() - Duration::from_secs(1),
        })
    }
    fn finish(self, response: &[u8]) -> Result<Session> {
        self.finish_inner(response)
    }
    fn finish_inner(mut self, response: &[u8]) -> Result<Session> {
        ensure!(
            response.len() >= 22 && response[6..22] == self.id,
            "raw TUN handshake response identifier changed"
        );
        let mut payload = [0; HANDSHAKE_PAYLOAD_MAX];
        let size = self.handshake.read_message(&response[22..], &mut payload)?;
        ensure!(
            self.handshake.is_handshake_finished(),
            "incomplete raw TUN handshake"
        );
        ensure!(size == 0, "unexpected raw TUN handshake payload");
        Session::finish(self.handshake, self.version)
    }
}
struct Candidate {
    session: Session,
    created: Instant,
}
struct CachedHandshake {
    request: Vec<u8>,
    response: Vec<u8>,
    created: Instant,
}

struct FragEntry {
    parts: Vec<Option<Vec<u8>>>,
    have: usize,
    created: Instant,
}

/// Splits an oversized IP packet into `IP_FRAG` pieces to send, and rebuilds one from the pieces
/// received (`tun.fragment`). One side's own id counter and the peer's incomplete datagrams are
/// independent: each direction fragments its own packets.
#[derive(Default)]
struct Reassembly {
    next_id: u16,
    pending: HashMap<u16, FragEntry>,
    issued:std::collections::VecDeque<(u16,Instant)>,
}
impl Reassembly {
    /// Splits `payload` (already carrying its `IP` type byte) into `IP_FRAG` pieces of at most
    /// `piece` bytes of original data each. `None` when it does not fit even in `FRAG_MAX_PIECES`
    /// pieces (the caller drops the packet, like the unfragmented path already would refuse one
    /// too big for a single outer packet).
    fn split(&mut self, payload: &[u8], piece: usize) -> Option<Vec<Vec<u8>>> {
        let data = &payload[1..]; // payload[0] is IP; the pieces carry the same bytes
        if piece == 0 {
            return None;
        }
        let count = data.len().div_ceil(piece);
        if count > FRAG_MAX_PIECES {
            return None;
        }
        while self.issued.front().is_some_and(|(_,time)|time.elapsed()>=FRAG_KEEP){self.issued.pop_front();}
        // Never reuse a legacy16-bit ID inside the receive retention window.
        // At exhaustion dropping UDP is preferable to mixing two IP datagrams.
        if self.issued.front().is_some_and(|(id,_)|*id==self.next_id){return None;}
        let id = self.next_id;
        self.issued.push_back((id,Instant::now()));
        self.next_id = self.next_id.wrapping_add(1);
        Some(
            data.chunks(piece)
                .enumerate()
                .map(|(index, chunk)| {
                    let mut out = Vec::with_capacity(FRAG_HEADER + chunk.len());
                    out.push(IP_FRAG);
                    out.extend_from_slice(&id.to_be_bytes());
                    out.push(index as u8);
                    out.push(count as u8);
                    out.extend_from_slice(chunk);
                    out
                })
                .collect(),
        )
    }

    /// Stores one received piece; returns the reassembled IP packet (payload[0] still `IP`) once
    /// every piece of its datagram has arrived.
    fn receive(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let id = u16::from_be_bytes(payload[1..3].try_into().ok()?);
        let index = payload[3] as usize;
        let count = payload[4] as usize;
        if count == 0 || count > FRAG_MAX_PIECES || index >= count {
            return None;
        }
        let now = Instant::now();
        self.pending
            .retain(|_, entry| now.duration_since(entry.created) < FRAG_KEEP);
        if !self.pending.contains_key(&id) && self.pending.len() >= FRAG_PENDING {
            // Make room for the newest: an attacker flooding ids could otherwise starve real
            // reassembly, and a real sender's fragments all arrive close together in time.
            if let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, entry)| entry.created)
                .map(|(id, _)| *id)
            {
                self.pending.remove(&oldest);
            }
        }
        let entry = self.pending.entry(id).or_insert_with(|| FragEntry {
            parts: vec![None; count],
            have: 0,
            created: now,
        });
        if entry.parts.len() != count || entry.parts[index].is_some() {
            return None; // a resized or repeated piece: ignore rather than corrupt the datagram
        }
        entry.parts[index] = Some(payload[FRAG_HEADER..].to_vec());
        entry.have += 1;
        if entry.have < count {
            return None;
        }
        let entry = self.pending.remove(&id)?;
        let mut out = vec![IP];
        for part in entry.parts {
            out.extend_from_slice(&part?);
        }
        Some(out)
    }
}

impl Session {
    fn encode_data(&mut self, payload: &[u8], parity: bool) -> Result<Vec<Vec<u8>>> {
        if !parity {
            return Ok(vec![self.encode(payload)?]);
        }
        self.parity
            .send(payload)
            .context("raw parity input limit")?
            .iter()
            .map(|p| self.encode(p))
            .collect()
    }
    async fn deliver(&mut self, payload: &[u8], device: &TunDevice, mtu: usize,stats:Option<&crate::stats::Stats>,forwarding_port:Option<u16>) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let full = match payload[0] {
            IP => Some(payload.to_vec()),
            IP_FRAG if payload.len() > FRAG_HEADER => self.fragments.receive(payload),
            _ => None,
        };
        if let Some(full) = full {
            if validate_packet(&full[1..], mtu).is_ok() {
                device.inject(&full[1..]).await?;
                if let Some(stats)=stats.filter(|_|crate::tun_device::counts_as_user_traffic(&full[1..],forwarding_port)){stats.bytes_from_peer.fetch_add((full.len()-1)as u64,std::sync::atomic::Ordering::Relaxed);}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
fn respond(request: &[u8], private: &[u8; 32], allowed: &[[u8; 32]]) -> Result<(Session, Vec<u8>)> {
    respond_version(request, private, allowed, 1)
}

#[cfg(test)]
fn respond_version(
    request: &[u8],
    private: &[u8; 32],
    allowed: &[[u8; 32]],
    version: u8,
) -> Result<(Session, Vec<u8>)> {
    respond_version_inner(request, private, allowed, version)
}

#[cfg(test)]
fn respond_version_inner(
    request: &[u8],
    private: &[u8; 32],
    allowed: &[[u8; 32]],
    version: u8,
) -> Result<(Session, Vec<u8>)> {
    respond_features(request, private, allowed, version, false)
}
fn respond_features(
    request: &[u8],
    private: &[u8; 32],
    allowed: &[[u8; 32]],
    version: u8,
    parity: bool,
) -> Result<(Session, Vec<u8>)> {
    ensure!(
        request.len() >= 38 && request.len() <= HANDSHAKE_PAYLOAD_MAX + 102,
        "invalid raw TUN handshake request size"
    );
    let mut handshake = Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(private)?
        .prologue(&prologue(version, parity)?)?
        .build_responder()?;
    let mut payload = [0; HANDSHAKE_PAYLOAD_MAX];
    let size = handshake.read_message(&request[6..], &mut payload)?;
    ensure!(size == 0, "unexpected raw TUN handshake request payload");
    let public = handshake
        .get_remote_static()
        .context("raw TUN peer did not supply an identity")?;
    ensure!(
        allowed.iter().any(|key| key.as_slice() == public),
        "raw TUN peer identity is not allowed"
    );
    let mut message = [0; HANDSHAKE_PAYLOAD_MAX + 48];
    let size = handshake.write_message(&[], &mut message)?;
    let mut response = MAGIC.to_vec();
    response.push(H2);
    response.extend_from_slice(&request[6..22]);
    response.extend_from_slice(&message[..size]);
    Ok((
        Session::finish(handshake, version)?,
        response,
    ))
}

/// Runs one pinned raw peer. Lost IP packets stay lost; no KCP or byte stream
/// sits under this carrier. Heartbeats and fresh handshakes recover peer restarts.
pub async fn run(device: &TunDevice, config: &Config, farewell: &Farewell) -> Result<()> {
    run_with_stats(device, config, farewell, None).await
}
pub(crate) async fn run_with_stats(
    device: &TunDevice,
    config: &Config,
    farewell: &Farewell,
    stats: Option<&crate::stats::Stats>,
) -> Result<()> {
    let tun = config
        .tun
        .as_ref()
        .context("raw TUN interface settings missing")?;
    let server = config.mode == Mode::Server;
    let options = if server {
        config.listeners[0].raw.as_ref()
    } else {
        config.paths[0].raw.as_ref()
    }
    .context("raw TUN transport settings missing")?;
    let socket = RawSocket::bind(options, server).await?;
    let mut maximum = socket.max_payload();
    let socket_maximum = maximum;
    if tun.parity {
        maximum = maximum.saturating_sub(parity::OVERHEAD);
    }
    if tun.fragment {
        ensure!(
            maximum > DATAGRAM_OVERHEAD + FRAG_HEADER,
            "the authenticated raw packet limit {maximum} leaves no room for a fragment on this profile"
        );
        let piece = maximum - DATAGRAM_OVERHEAD - FRAG_HEADER;
        ensure!(
            usize::from(tun.mtu) <= piece * FRAG_MAX_PIECES,
            "raw TUN MTU {} needs more than {FRAG_MAX_PIECES} fragments on this profile ({piece} bytes each); lower tun.mtu",
            tun.mtu
        );
    } else {
        ensure!(
            maximum > DATAGRAM_OVERHEAD && usize::from(tun.mtu) <= maximum - DATAGRAM_OVERHEAD,
            "raw TUN MTU {} exceeds authenticated raw packet limit {}; lower tun.mtu, or turn on tun.fragment",
            tun.mtu,
            maximum.saturating_sub(DATAGRAM_OVERHEAD)
        );
    }
    let private = config.private_key()?;
    let allowed = config
        .peer_public_keys
        .iter()
        .map(|key| decode_key(key))
        .collect::<Result<Vec<_>>>()?;
    let server_key = if server {
        None
    } else {
        Some(decode_key(&config.paths[0].server_public_key)?)
    };
    let deadline = Duration::from_secs(config.dead_timeout_sec);
    let heartbeat = Duration::from_secs(config.heartbeat_sec);
    let probe = Duration::from_secs(config.timeouts.probe_sec);
    // The goodbye arrives here when the program is stopping (see `farewell`).
    let (goodbye, mut goodbyes) = tokio::sync::mpsc::channel(1);
    farewell.register(&goodbye);
    let handshake_deadline = if server {
        Duration::from_secs(config.timeouts.handshake_sec)
    } else {
        Duration::from_secs(config.paths[0].dial_timeout)
    };
    let mut active: Option<Session> = None;
    let mut initiating: Option<Initiating> = None;
    let mut candidate: Option<Candidate> = None;
    let mut cached: Option<CachedHandshake> = None;
    // Set once this side said goodbye: it is about to exit, so it must not take or start a new
    // handshake meanwhile (the peer would get a session that dies a moment later).
    let mut stopping = false;
    let mut network_buffer = vec![0; socket_maximum + 1];
    let mut ip_buffer = vec![0; usize::from(tun.mtu) + 1];
    let mut tick = time::interval(Duration::from_millis(250));
    tracing::info!(peer=%options.peer_ip,"raw TUN datagram carrier ready");
    loop {
        {
            if active
                .as_ref()
                .is_some_and(|s| s.created.elapsed() >= SESSION_LIMIT)
            {
                active = None;
                cached = None;
                tracing::info!("raw TUN session key expired; reconnecting");
            }
            if candidate
                .as_ref()
                .is_some_and(|c| c.session.created.elapsed() >= SESSION_LIMIT)
            {
                candidate = None;
                cached = None;
            }
        }
        tokio::select! {
            read=socket.recv(&mut network_buffer)=> {
                let size=read.context("receive raw TUN datagram")?;
                let packet=&network_buffer[..size];
                if packet.len()<6 || &packet[..5]!=MAGIC {continue;}
                match packet[5] {
                    H1 if server && !stopping=> {
                        if let Some(cache)=&cached
                            && cache.request==packet && cache.created.elapsed()<deadline {
                                socket.send(&cache.response).await?;continue;
                            }
                        // Keep one candidate and throttle replacement; a replayed
                        // initiator message must not evict an active session.
                        if candidate.as_ref().is_some_and(|c|c.created.elapsed()<Duration::from_secs(3)) {continue;}
                        match respond_features(packet,&private,&allowed,config.wire_version,tun.parity) {
                            Ok((session,response))=> {
                                socket.send(&response).await?;
                                candidate=Some(Candidate {session,created:Instant::now()});
                                cached=Some(CachedHandshake {request:packet.to_vec(),response,created:Instant::now()});
                            }
                            Err(error)=>tracing::debug!(%error,"raw TUN handshake rejected"),
                        }
                    }
                    H2 if !server=> {
                        if packet.len()>22+32+HANDSHAKE_PAYLOAD_MAX+16 || packet.len()<22 || initiating.as_ref().is_none_or(|p|packet[6..22]!=p.id) {continue;}
                        if let Some(pending)=initiating.take() {
                            match pending.finish(packet) {
                                Ok(mut session)=> {
                                    socket.send(&session.ping()?).await?;
                                    active=Some(session);tracing::info!("raw TUN peer authenticated");
                                }
                                Err(error)=>tracing::debug!(%error,"raw TUN handshake response rejected"),
                            }
                        }
                    }
                    DATA=> {
                        if packet.len()<HEADER+17 {continue;}
                        let is_candidate=candidate.as_ref().is_some_and(|c|packet[6..22]==c.session.id);
                        let decoded=if is_candidate {
                            candidate.as_mut().unwrap().session.decode(packet)
                        } else if let Some(session)=&mut active {session.decode(packet)}else {continue};
                        match decoded {
                            Ok(Some(payload))=> {
                                if is_candidate {active=Some(candidate.take().unwrap().session);tracing::info!("raw TUN peer authenticated");}
                                match payload[0] {
                                    IP|IP_FRAG=> {if !tun.parity{active.as_mut().unwrap().deliver(&payload,device,usize::from(tun.mtu),stats,tun.forwarding_port).await?;}},
                                    parity::TAG=> {if tun.parity{
                                        let session=active.as_mut().unwrap();
                                        for recovered in session.parity.receive(&payload){session.deliver(&recovered,device,usize::from(tun.mtu),stats,tun.forwarding_port).await?;}
                                    }},
                                    PING=> {if let Some(session)=&mut active {socket.send(&session.encode(&[PONG])?).await?;}},
                                    PONG=>{},
                                    MTU_PROBE=> {let session=active.as_mut().unwrap();
                                        if let Some(reply)=session.mtu.response(&payload,socket_maximum.saturating_sub(HEADER+16)){
                                            socket.send(&session.encode(&reply)?).await?;
                                        }
                                    },
                                    MTU_REPLY=> {active.as_mut().unwrap().mtu.received(&payload);},
                                    BYE=> {
                                        // The other side is stopping: forget the session now; the
                                        // client starts a new handshake at once (next tick).
                                        active=None;candidate=None;cached=None;initiating=None;
                                        tracing::info!("the other server is stopping or restarting");
                                    }
                                    _=>unreachable!(),
                                }
                            }
                            Ok(None)=>{},Err(error)=>tracing::debug!(%error,"raw TUN datagram authentication rejected"),
                        }
                    }
                    _=>{},
                }
            }
            read=device.receive(&mut ip_buffer), if active.is_some()=> {
                let size=read?;
                if validate_packet(&ip_buffer[..size],usize::from(tun.mtu)).is_err() {continue;}
                let mut payload=Vec::with_capacity(size+1);payload.push(IP);payload.extend_from_slice(&ip_buffer[..size]);
                if fits_single(size,maximum) {
                    if let Some(session)=&mut active {for packet in session.encode_data(&payload,tun.parity)?{socket.send(&packet).await?;}}
                    if crate::tun_device::counts_as_user_traffic(&ip_buffer[..size],tun.forwarding_port){if let Some(stats)=stats{stats.bytes_to_peer.fetch_add(size as u64,std::sync::atomic::Ordering::Relaxed);}}
                } else if tun.fragment {
                    let piece=maximum.saturating_sub(DATAGRAM_OVERHEAD+FRAG_HEADER);
                    let pieces=active.as_mut().and_then(|session|session.fragments.split(&payload,piece));
                    match pieces {
                        Some(pieces)=> {
                            for piece_payload in pieces {
                                if let Some(session)=&mut active {for packet in session.encode_data(&piece_payload,tun.parity)?{socket.send(&packet).await?;}}
                            }
                            if crate::tun_device::counts_as_user_traffic(&ip_buffer[..size],tun.forwarding_port){if let Some(stats)=stats{stats.bytes_to_peer.fetch_add(size as u64,std::sync::atomic::Ordering::Relaxed);}}
                        }
                        None=>tracing::debug!(size,"outgoing IP packet too big to fragment on this profile; dropped"),
                    }
                } else {
                    tracing::debug!(size,"outgoing IP packet too big for one raw packet; dropped");
                }
            }
            Some(_)=goodbyes.recv()=> {
                // Datagrams can be lost: say it three times, 30 ms apart.
                if let Some(session)=&mut active {
                    for attempt in 0..3 {
                        if attempt>0 {time::sleep(Duration::from_millis(30)).await;}
                        socket.send(&session.encode(&[BYE])?).await?;
                    }
                    tracing::info!("told the other server that this one is stopping");
                }
                stopping=true;active=None;candidate=None;cached=None;initiating=None;
            }
            _=tick.tick()=> {
                // Establish fresh session keys before their deadline while retaining the
                // current packet session. Inner TCP/IP state remains on the TUN device.
                if !server && !stopping && initiating.is_none()
                    && active.as_ref().is_some_and(|s|s.created.elapsed()>=SESSION_RENEW) {
                                 initiating=Some(Initiating::for_features(&private,server_key.as_ref().unwrap(),config.wire_version,tun.parity)?);
                }
                if active.as_ref().is_some_and(|s|s.last_authenticated.elapsed()>=deadline) {
                    active=None;tracing::info!("raw TUN peer silent; reconnecting");
                }
                if candidate.as_ref().is_some_and(|c|c.created.elapsed()>=deadline) {
                    candidate=None;
                    // Its response contains the now-discarded responder key.
                    // Never acknowledge a retry using an orphaned response.
                    cached=None;
                }
                // Client, crash of the other side (no goodbye): a ping unanswered for `probe` is
                // followed by one per second; after `2 × probe` a new handshake starts while the
                // old session is kept. Raw TUN sessions hold no stream state, so switching to the
                // new one costs nothing; if the server does not answer, the old one stays until
                // the dead timeout as before.
                if !server
                    && let Some(session)=&mut active
                    && let Some(since)=session.unanswered_since {
                        let waited=since.elapsed();
                        if waited>=probe && session.last_heartbeat.elapsed()>=Duration::from_secs(1) {
                            socket.send(&session.ping()?).await?;
                        }
                        if waited>=2*probe && initiating.is_none() {
                            initiating=Some(Initiating::for_features(&private,server_key.as_ref().unwrap(),config.wire_version,tun.parity)?);
                            tracing::info!(seconds=waited.as_secs(),"raw TUN peer not answering; trying a new handshake");
                        }
                    }
                if !server && !stopping && (active.is_none() || initiating.is_some()) {
                    if initiating.as_ref().is_some_and(|p|p.started.elapsed()>=handshake_deadline) {initiating=None;}
                    if initiating.is_none() && active.is_none() {initiating=Some(Initiating::for_features(&private,server_key.as_ref().unwrap(),config.wire_version,tun.parity)?);}
                    if let Some(pending)=&mut initiating
                        && pending.last_sent.elapsed()>=Duration::from_secs(1) {
                            socket.send(&pending.request).await?;pending.last_sent=Instant::now();
                        }
                }
                if let Some(session)=&mut active
                    && session.last_heartbeat.elapsed()>=heartbeat {
                        socket.send(&session.ping()?).await?;
                    }
                if tun.mtu_probe && let Some(session)=&mut active{
                    if let Some(request)=session.mtu.next(socket_maximum.saturating_sub(HEADER+16),session.id){
                        socket.send(&session.encode(&request)?).await?;
                    }
                    if session.mtu.finished()&&!session.mtu_reported{
                        session.mtu_reported=true;
                        if let Some(measured)=session.mtu.result(){
                            let budget=measured.saturating_sub(1+if tun.parity{parity::OVERHEAD}else{0});
                            if let Some(stats)=stats{
                                stats.raw_payload_echoed.store(measured,std::sync::atomic::Ordering::Relaxed);
                                stats.raw_inner_mtu_advisory.store(budget,std::sync::atomic::Ordering::Relaxed);
                            }
                            tracing::info!(profile=?options.profile,authenticated_payload_bytes=measured,recommended_inner_mtu=budget,
                                "raw carrier size advisory: largest echoed unfragmented payload, not proof of path ceiling; interface unchanged");
                        }else{tracing::info!("raw size probe inconclusive or peer unsupported; interface MTU unchanged");}
                    }
                }
            }
        }
    }
}

/// C34: whether an inner IP packet of `size` bytes goes out as one raw packet. The IP type
/// byte is part of `DATAGRAM_OVERHEAD` and is counted once, matching the startup check.
fn fits_single(size: usize, maximum: usize) -> bool {
    size <= maximum.saturating_sub(DATAGRAM_OVERHEAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C34: 1500-byte interface, plain TCP raw headers: maximum 1460, accepted MTU 1413.
    /// The boundary packet is one raw packet of exactly `maximum` bytes; one byte more is not.
    #[test]
    fn the_startup_mtu_boundary_packet_is_sent_as_one_raw_packet() -> Result<()> {
        let maximum = 1460;
        let boundary = maximum - DATAGRAM_OVERHEAD;
        assert_eq!(boundary, 1413);
        assert!(fits_single(boundary, maximum));
        assert!(!fits_single(boundary + 1, maximum));
        let (mut sender, mut receiver) = sessions()?;
        let mut payload = vec![IP];
        payload.extend(std::iter::repeat_n(0x45u8, boundary));
        let packets = sender.encode_data(&payload, false)?;
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].len(), maximum, "encoding the boundary fills the raw packet exactly");
        assert_eq!(receiver.decode(&packets[0])?, Some(payload));
        // With parity the startup budget is the socket maximum minus parity::OVERHEAD.
        let parity_maximum = maximum - parity::OVERHEAD;
        assert!(fits_single(parity_maximum - DATAGRAM_OVERHEAD, parity_maximum));
        assert!(!fits_single(parity_maximum - DATAGRAM_OVERHEAD + 1, parity_maximum));
        Ok(())
    }

    fn sessions() -> Result<(Session, Session)> {
        let client = Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
        let server = Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
        let pending = Initiating::new(
            &client.private.try_into().unwrap(),
            &server.public.try_into().unwrap(),
        )?;
        let (responder, response) = respond(
            &pending.request,
            &server.private.try_into().unwrap(),
            &[client.public.try_into().unwrap()],
        )?;
        Ok((pending.finish(&response)?, responder))
    }

    #[tokio::test(start_paused = true)]
    async fn raw_keys_expire_without_extending_their_nonce_or_replay_state() -> Result<()> {
        let (mut sender, mut receiver) = sessions()?;
        time::advance(SESSION_RENEW).await;
        let packet = sender.encode(&[PING])?;
        assert_eq!(receiver.decode(&packet)?, Some(vec![PING]));
        time::advance(SESSION_LIMIT - SESSION_RENEW).await;
        assert!(sender.encode(&[PING]).is_err());
        assert!(receiver.decode(&packet).is_err());
        let (mut fresh_sender, mut fresh_receiver) = sessions()?;
        assert!(fresh_receiver.decode(&packet)?.is_none());
        assert_eq!(fresh_receiver.decode(&fresh_sender.encode(&[PING])?)?, Some(vec![PING]));
        Ok(())
    }

    #[test]
    fn raw_all_wire_versions_authenticate_and_mismatched_versions_fail() -> Result<()> {
        let client = Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
        let server = Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
        let private = client.private.try_into().unwrap();
        let public = server.public.try_into().unwrap();
        let server_private = server.private.try_into().unwrap();
        let client_public = client.public.try_into().unwrap();
        for version in 1..=3 {
            let pending = Initiating::for_version(&private, &public, version)?;
            assert!(respond_version(&pending.request, &server_private, &[client_public], version % 3 + 1).is_err());
            let (mut responder, reply) = respond_version(&pending.request, &server_private, &[client_public], version)?;
            let mut initiator = pending.finish(&reply)?;
            assert_eq!(responder.decode(&initiator.encode(&[PING])?)?, Some(vec![PING]));
            assert_eq!(initiator.decode(&responder.encode(&[PONG])?)?, Some(vec![PONG]));
        }
        Ok(())
    }
    #[test]
    fn goodbye_is_understood_and_an_answer_clears_the_silence() -> Result<()> {
        let (mut client, mut server) = sessions()?;
        assert_eq!(server.decode(&client.encode(&[BYE])?)?, Some(vec![BYE]));
        // A 0.8.4 receiver: the same check without BYE rejects it after authentication and
        // leaves the session as it was.
        let packet = client.encode(&[BYE])?;
        let before = server.last_authenticated;
        let payload = {
            let nonce = u64::from_be_bytes(packet[22..30].try_into()?);
            let mut payload = vec![0; packet.len() - HEADER];
            let size = server
                .cipher
                .read_message(nonce, &packet[HEADER..], &mut payload)?;
            payload.truncate(size);
            payload
        };
        assert!(
            !matches!(payload[0], IP | PING | PONG),
            "0.8.4 would reject it"
        );
        assert_eq!(server.last_authenticated, before);
        // A ping starts the silence clock; anything authenticated stops it.
        let ping = client.ping()?;
        assert!(client.unanswered_since.is_some());
        let first = client.unanswered_since;
        let _ = client.ping()?;
        assert_eq!(
            client.unanswered_since, first,
            "the oldest unanswered ping counts"
        );
        assert_eq!(server.decode(&ping)?, Some(vec![PING]));
        let pong = server.encode(&[PONG])?;
        assert_eq!(client.decode(&pong)?, Some(vec![PONG]));
        assert!(client.unanswered_since.is_none());
        Ok(())
    }

    #[test]
    fn authenticated_fragments_from_replaced_sessions_cannot_mix() -> Result<()> {
        for responder_sends in [false, true] {
            let (mut old_sender, mut old_receiver) = sessions()?;
            let (mut new_sender, mut replacement) = sessions()?;
            if responder_sends {
                std::mem::swap(&mut old_sender, &mut old_receiver);
                std::mem::swap(&mut new_sender, &mut replacement);
            }
            // Identical IP headers make a mixed packet structurally valid, so an
            // IP-length check alone could never detect the session confusion.
            let mut old = vec![IP];
            let mut ip = vec![1u8; 40];
            ip[0] = 0x45;
            ip[2] = 0;
            ip[3] = 40;
            old.extend_from_slice(&ip);
            let mut new = old.clone();
            new[9] = 64;
            new[21..].fill(2);
            let old_parts = old_sender.fragments.split(&old, 20).unwrap();
            let new_parts = new_sender.fragments.split(&new, 20).unwrap();
            assert_eq!(
                &old_parts[0][1..3],
                &new_parts[0][1..3],
                "a restarted sender reuses its fragment id"
            );
            let old_first = old_sender.encode(&old_parts[0])?;
            let decoded = old_receiver.decode(&old_first)?.unwrap();
            assert!(old_receiver.fragments.receive(&decoded).is_none());
            assert_eq!(old_receiver.fragments.pending.len(), 1);
            let delayed_old = old_sender.encode(&old_parts[1])?;
            // This is the same ownership replacement used by both the initiator
            // response and responder candidate-promotion branches.
            let mut active = Some(old_receiver);
            assert_eq!(active.as_ref().unwrap().fragments.pending.len(), 1);
            active = Some(replacement);
            let receiver = active.as_mut().unwrap();
            assert!(receiver.fragments.pending.is_empty());
            let decoded = receiver
                .decode(&new_sender.encode(&new_parts[1])?)?
                .unwrap();
            assert!(
                receiver.fragments.receive(&decoded).is_none(),
                "new last piece must not combine with the previous session's first piece"
            );
            assert!(
                receiver.decode(&delayed_old)?.is_none(),
                "late old-session records must not enter the new assembly"
            );
            let decoded = receiver
                .decode(&new_sender.encode(&new_parts[0])?)?
                .unwrap();
            let full = receiver
                .fragments
                .receive(&decoded)
                .expect("new session's own pieces complete");
            assert_eq!(full, new);
            validate_packet(&full[1..], 1400)?;
        }
        Ok(())
    }

    #[test]
    fn datagrams_survive_loss_and_reordering_and_reject_replay() -> Result<()> {
        let (mut sender, mut receiver) = sessions()?;
        let mut packets = Vec::new();
        for _ in 0..300 {
            packets.push(sender.encode(&[PING])?);
        }
        assert_eq!(receiver.decode(&packets[40])?, Some(vec![PING]));
        assert_eq!(receiver.decode(&packets[3])?, Some(vec![PING]));
        assert!(receiver.decode(&packets[40])?.is_none());
        assert_eq!(receiver.decode(&packets[299])?, Some(vec![PING]));
        assert!(receiver.decode(&packets[3])?.is_none());
        assert_eq!(receiver.decode(&packets[298])?, Some(vec![PING]));
        assert!(receiver.decode(&packets[298])?.is_none());
        Ok(())
    }

    #[test]
    fn parity_uses_authenticated_session_state_and_recovers_one_missing_ciphertext() -> Result<()> {
        for missing in 0..3 {
            let (mut sender, mut receiver) = sessions()?;
            let mut packets = sender.encode_data(&[IP, 1, 2, 3], true)?;
            packets.extend(sender.encode_data(&[IP, 4, 5, 6, 7], true)?);
            let mut output = vec![];
            for n in [2, 1, 0] {
                if n != missing {
                    let data = receiver.decode(&packets[n])?.unwrap();
                    output.extend(receiver.parity.receive(&data));
                }
            }
            output.sort();
            assert_eq!(output, vec![vec![IP, 1, 2, 3], vec![IP, 4, 5, 6, 7]]);
            let (_, mut replacement) = sessions()?;
            assert!(replacement.decode(&packets[0])?.is_none());
            assert!(replacement.parity.receive(&[0]).is_empty());
        }
        Ok(())
    }

    #[test]
    fn controlled_single_member_loss_recovers_1000_groups_with_known_bandwidth_cost() -> Result<()>
    {
        let (mut sender, mut receiver) = sessions()?;
        let mut data = Vec::new();
        let mut sent_bytes = 0;
        for group in 0..1000u16 {
            let first = [IP, (group >> 8) as u8, group as u8, 0];
            let second = [IP, (group >> 8) as u8, group as u8, 1];
            let mut packets = sender.encode_data(&first, true)?;
            packets.extend(sender.encode_data(&second, true)?);
            assert_eq!(packets.len(), 3);
            sent_bytes += packets.iter().map(Vec::len).sum::<usize>();
            let lost = group as usize % 3;
            for n in [2, 0, 1] {
                if n != lost {
                    let plain = receiver.decode(&packets[n])?.unwrap();
                    data.extend(receiver.parity.receive(&plain));
                }
            }
        }
        assert_eq!(data.len(), 2000);
        assert_eq!(sent_bytes, 1000 * 3 * (HEADER + 16 + parity::OVERHEAD + 4));
        Ok(())
    }

    #[test]
    fn parity_feature_mismatch_fails_the_noise_handshake() -> Result<()> {
        let client = Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
        let server = Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
        let private: [u8; 32] = client.private.try_into().unwrap();
        let public: [u8; 32] = server.public.try_into().unwrap();
        let responder: [u8; 32] = server.private.try_into().unwrap();
        let allowed = [client.public.try_into().unwrap()];
        let pending = Initiating::for_features(&private, &public, 1, true)?;
        assert!(respond_features(&pending.request, &responder, &allowed, 1, false).is_err());
        let (receiver, response) =
            respond_features(&pending.request, &responder, &allowed, 1, true)?;
        let sender = pending.finish(&response)?;
        assert_eq!(sender.id, receiver.id);
        Ok(())
    }
    #[test]
    fn forged_large_nonce_does_not_advance_replay_window() -> Result<()> {
        let (mut sender, mut receiver) = sessions()?;
        let valid = sender.encode(&[PING])?;
        let mut forged = valid.clone();
        forged[22..30].copy_from_slice(&1_000_000_u64.to_be_bytes());
        assert!(receiver.decode(&forged).is_err());
        assert!(receiver.replay.highest.is_none());
        assert_eq!(receiver.decode(&valid)?, Some(vec![PING]));
        let mut wrong_session = sender.encode(&[PONG])?;
        wrong_session[6] ^= 1;
        assert!(receiver.decode(&wrong_session)?.is_none());
        sender.counter = u64::MAX;
        assert!(sender.encode(&[PING]).is_err());
        Ok(())
    }
    #[test]
    fn replay_bitmap_matches_reference_for_word_boundaries() {
        let mut window = ReplayWindow::default();
        let mut accepted = std::collections::HashSet::new();
        let mut highest = 0;
        for nonce in [
            0, 63, 64, 65, 128, 255, 256, 511, 512, 513, 300, 350, 600, 601, 599,
        ] {
            assert_eq!(
                window.seen(nonce),
                accepted.contains(&nonce) || (nonce <= highest && highest - nonce >= 256)
            );
            window.mark(nonce);
            accepted.insert(nonce);
            highest = highest.max(nonce);
            for probe in 0..=highest + 1 {
                assert_eq!(
                    window.seen(probe),
                    accepted.contains(&probe) || (probe <= highest && highest - probe >= 256),
                    "highest={highest},probe={probe}"
                );
            }
        }
    }

    #[test]
    fn an_oversized_packet_is_split_and_rebuilt_in_order() {
        let mut sender = Reassembly::default();
        let mut payload = vec![IP];
        payload.extend((0u16..1000).map(|n| n as u8));
        let pieces = sender
            .split(&payload, 300)
            .expect("fits in FRAG_MAX_PIECES");
        assert_eq!(pieces.len(), 4); // 1000 / 300 rounded up
        for (index, piece) in pieces.iter().enumerate() {
            assert_eq!(piece[0], IP_FRAG);
            assert_eq!(piece[3], index as u8);
            assert_eq!(piece[4], pieces.len() as u8);
        }

        let mut receiver = Reassembly::default();
        assert!(receiver.receive(&pieces[2]).is_none(), "not complete yet");
        assert!(receiver.receive(&pieces[0]).is_none());
        assert!(receiver.receive(&pieces[3]).is_none());
        // Out of order and a repeat of an already-received piece is ignored, not corrupted.
        assert!(receiver.receive(&pieces[2]).is_none());
        let rebuilt = receiver.receive(&pieces[1]).expect("every piece arrived");
        assert_eq!(rebuilt, payload);
        assert!(receiver.pending.is_empty(), "the finished entry is removed");
    }

    #[test]
    fn too_many_pieces_is_refused_up_front() {
        let mut sender = Reassembly::default();
        let payload = vec![IP; 2 + FRAG_MAX_PIECES]; // 1 tiny byte per piece would need one more
        assert!(sender.split(&payload, 1).is_none());
    }
    #[tokio::test(start_paused=true)]
    async fn fragment_ids_cannot_wrap_inside_the_receive_retention_window(){
        let mut fragments=Reassembly::default();let payload=[IP,1,2];
        for _ in 0..=u16::MAX{assert!(fragments.split(&payload,1).is_some());}
        assert!(fragments.split(&payload,1).is_none());
        time::advance(FRAG_KEEP+Duration::from_millis(1)).await;
        assert!(fragments.split(&payload,1).is_some());assert!(fragments.issued.len()<=65536);
    }

    #[test]
    fn an_incomplete_datagram_is_dropped_after_frag_keep() {
        let mut receiver = Reassembly::default();
        let piece = vec![IP_FRAG, 0, 7, 0, 2, 9];
        assert!(receiver.receive(&piece).is_none());
        assert_eq!(receiver.pending.len(), 1);
        receiver.pending.get_mut(&7).unwrap().created =
            Instant::now() - FRAG_KEEP - Duration::from_millis(1);
        // A later, unrelated piece triggers the sweep that ages the stale entry out.
        let other = vec![IP_FRAG, 0, 9, 0, 2, 1];
        assert!(receiver.receive(&other).is_none());
        assert!(!receiver.pending.contains_key(&7), "aged out");
        assert!(receiver.pending.contains_key(&9));
    }

    #[test]
    fn a_full_pending_table_makes_room_by_dropping_the_oldest() {
        let mut receiver = Reassembly::default();
        let started = Instant::now();
        for id in 0..FRAG_PENDING as u16 {
            let piece = vec![IP_FRAG, (id >> 8) as u8, id as u8, 0, 2, 1];
            assert!(receiver.receive(&piece).is_none());
            // Real wall-clock timing in a tight loop can tie or go out of order; make the
            // intended age explicit instead, oldest (id 0) first.
            receiver.pending.get_mut(&id).unwrap().created =
                started - Duration::from_millis(FRAG_PENDING as u64 - id as u64);
        }
        assert_eq!(receiver.pending.len(), FRAG_PENDING);
        let one_more = vec![
            IP_FRAG,
            (FRAG_PENDING >> 8) as u8,
            FRAG_PENDING as u8,
            0,
            2,
            1,
        ];
        assert!(receiver.receive(&one_more).is_none());
        assert_eq!(receiver.pending.len(), FRAG_PENDING, "stays bounded");
        assert!(!receiver.pending.contains_key(&0), "the oldest made room");
    }

    
}
