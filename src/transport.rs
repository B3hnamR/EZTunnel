//! Authenticated, encrypted TCP records with locally pinned X25519 identities.
//! A failed/cancelled send or receive requires dropping the connection; do not retry a record.
use crate::stealth::{Masked, WireOptions, hold_then_close};
use crate::wire::Frame;
use crate::{
    carrier::{BoxIo, client_carrier, server_carrier},
    config::{ClientPath, Listener},
};
use anyhow::{Context, Result, anyhow, ensure};
use snow::{Builder, TransportState};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = crate::session_crypto::STREAM_DOMAIN;
const MAX_RECORD: usize = 65_535;
const REKEY_RECORD: u8 = 13;
#[cfg(test)]
const REKEY_INTERVAL: Duration = Duration::from_secs(300);
#[cfg(test)]
const REKEY_RECORDS: u64 = 1 << 20;
const EPOCH_RECEIVE_LIMIT: Duration = Duration::from_secs(360);
/// When the server dials a KCP or FEC-UDP client, it sends this byte first. Those listeners
/// report a new session only once data arrives, and the Noise initiator (the client) speaks
/// first, so without it both ends would wait for each other.
const KCP_WAKE: u8 = 0x5a;

/// Version 2 masks the byte stream of every carrier that is not already wrapped in TLS.
fn masked(stream: BoxIo, transport: crate::config::Transport, wire: &WireOptions) -> BoxIo {
    if wire.v2() && !transport.uses_tls() {
        Box::new(Masked::new(stream, wire))
    } else {
        stream
    }
}

/// How this side shapes what it sends (wire version 2 settings; all off by default).
#[derive(Clone, Copy, Default)]
struct Shape {
    pad_max: usize,
    jitter_ms: u64,
}

/// A record sent less than this long after the previous one is not delayed by `jitter_ms`.
const BURST_GAP: Duration = Duration::from_millis(20);

pub struct SecureConnection {
    stream: BoxIo,
    state: TransportState,
    shape: Shape,
    codecs: Option<crate::wire::Codecs>,
}

pub struct SecureReader {
    stream: tokio::io::ReadHalf<BoxIo>,
    state: Arc<Mutex<TransportState>>,
    rotation: Option<crate::wire::Rotation>,
    epoch: u64,
    epoch_started: Instant,
    epoch_records: u64,
}

pub struct SecureWriter {
    stream: tokio::io::WriteHalf<BoxIo>,
    state: Arc<Mutex<TransportState>>,
    shape: Shape,
    last_send: Instant,
    rotation: Option<crate::wire::Rotation>,
    epoch: u64,
    epoch_started: Instant,
    epoch_records: u64,
}

type HandshakeTraffic = crate::session_crypto::Traffic<TransportState>;

impl SecureConnection {
    fn new(stream: BoxIo, traffic: HandshakeTraffic) -> Self {
        Self {
            stream,
            state: traffic.state,
            shape: Shape::default(),
            codecs: traffic.codecs,
        }
    }
    /// Applies the wire version 2 shaping settings (record padding, burst jitter) to what this
    /// side sends from now on.
    pub fn shaped(mut self, wire: &WireOptions) -> Self {
        if wire.v2() {
            self.shape = Shape {
                pad_max: usize::from(wire.stealth.record_pad_max),
                jitter_ms: u64::from(wire.stealth.jitter_ms),
            };
        }
        self
    }

    /// The other side's static public key, its identity (known once the handshake is done).
    pub fn peer_key(&self) -> Option<[u8; 32]> {
        self.state.get_remote_static()?.try_into().ok()
    }

    pub fn split(self) -> (SecureReader, SecureWriter) {
        let (read, write) = tokio::io::split(self.stream);
        let state = Arc::new(Mutex::new(self.state));
        let (tx, rx) = match self.codecs {
            Some(codecs) => (Some(codecs.tx), Some(codecs.rx)),
            None => (None, None),
        };
        (
            SecureReader {
                stream: read,
                state: state.clone(),
                rotation: rx,
                epoch: 0,
                epoch_started: Instant::now(),
                epoch_records: 0,
            },
            SecureWriter {
                stream: write,
                state,
                shape: self.shape,
                last_send: Instant::now(),
                rotation: tx,
                epoch: 0,
                epoch_started: Instant::now(),
                epoch_records: 0,
            },
        )
    }
}

impl SecureReader {
    pub async fn recv(&mut self) -> Result<Frame> {
        self.recv_inner().await
    }

    async fn recv_inner(&mut self) -> Result<Frame> {
        loop {
            let encrypted = read_record(&mut self.stream).await?;
            ensure!(encrypted.len() >= 16, "truncated encrypted record");
            let mut plaintext = vec![0; encrypted.len()];
            let size = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow!("cipher state poisoned"))?;
                let nonce = state.receiving_nonce();
                let size = state
                    .read_message(&encrypted, &mut plaintext)
                    .context("record authentication failed")?;
                if let Some(rotation) = &self.rotation {
                    rotation.decode(nonce, &mut plaintext[..size]);
                }
                size
            };
            if plaintext[..size].first() == Some(&REKEY_RECORD) {
                ensure!(size == 9, "invalid epoch marker");
                let epoch = u64::from_be_bytes(plaintext[1..9].try_into()?);
                ensure!(
                    self.epoch.checked_add(1) == Some(epoch),
                    "nonsequential epoch marker"
                );
                self.state
                    .lock()
                    .map_err(|_| anyhow!("cipher state poisoned"))?
                    .rekey_incoming();
                self.epoch = epoch;
                self.epoch_started = Instant::now();
                self.epoch_records = 0;
                continue;
            }
            {
                ensure!(
                    self.epoch_started.elapsed() < EPOCH_RECEIVE_LIMIT
                        && self.epoch_records < (1 << 20),
                    "receive key epoch expired"
                );
                self.epoch_records += 1;
            }
            return Frame::decode(&plaintext[..size]);
        }
    }
}

/// Test-only pair using the same authenticated session derivation as production.
#[cfg(test)]
fn test_pair() -> Result<[SecureConnection; 2]> {
    let server = Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
    let client = Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
    let mut a = Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(&client.private)?
        .remote_public_key(&server.public)?
        .prologue(PROLOGUE)?
        .build_initiator()?;
    let mut b = Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(&server.private)?
        .prologue(PROLOGUE)?
        .build_responder()?;
    let mut packet = [0u8; 1024];
    let mut payload = [0u8; 1024];
    let n = a.write_message(&[], &mut packet)?;
    b.read_message(&packet[..n], &mut payload)?;
    let n = b.write_message(&[], &mut packet)?;
    a.read_message(&packet[..n], &mut payload)?;
    let (a_io, b_io) = tokio::io::duplex(65536);
    Ok([
        SecureConnection::new(
            Box::new(a_io),
            crate::session_crypto::transport(a, 1)?,
        ),
        SecureConnection::new(
            Box::new(b_io),
            crate::session_crypto::transport(b, 1)?,
        ),
    ])
}

impl SecureWriter {
    pub async fn send(&mut self, frame: &Frame) -> Result<()> {
        self.send_inner(frame).await
    }

    async fn send_inner(&mut self, frame: &Frame) -> Result<()> {
        if crate::session_crypto::epoch_due(self.epoch_started.elapsed().as_secs(), self.epoch_records) {
            self.advance_epoch().await?;
        }
        let plaintext = if self.shape.pad_max > 0 {
            let room = (MAX_RECORD - 16).saturating_sub(frame.encode()?.len() + 2);
            let wanted = crate::stealth::random_below(self.shape.pad_max as u64 + 1)? as usize;
            frame.encode_padded(wanted.min(room).min(255))?
        } else {
            frame.encode()?
        };
        if self.shape.jitter_ms > 0 && self.last_send.elapsed() >= BURST_GAP {
            let delay = crate::stealth::random_below(self.shape.jitter_ms + 1)?;
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        self.write_plaintext(plaintext).await
    }

    async fn write_plaintext(&mut self, mut plaintext: Vec<u8>) -> Result<()> {
        let mut encrypted = vec![0; plaintext.len() + 16];
        let size = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow!("cipher state poisoned"))?;
            if let Some(rotation) = &self.rotation {
                rotation.encode(state.sending_nonce(), &mut plaintext);
            }
            state
                .write_message(&plaintext, &mut encrypted)
                .context("record encryption failed")?
        };
        let result = write_record(&mut self.stream, &encrypted[..size]).await;
        self.last_send = Instant::now();
        self.epoch_records = self.epoch_records.saturating_add(1);
        result
    }

    async fn advance_epoch(&mut self) -> Result<()> {
        let next = self
            .epoch
            .checked_add(1)
            .context("key epoch exhausted")?;
        let mut marker = vec![REKEY_RECORD];
        marker.extend_from_slice(&next.to_be_bytes());
        // The transition is authenticated with the old directional key. A failed or
        // cancelled write poisons this connection just like an ordinary record write.
        self.write_plaintext(marker).await?;
        self.state
            .lock()
            .map_err(|_| anyhow!("cipher state poisoned"))?
            .rekey_outgoing();
        self.epoch = next;
        self.epoch_started = Instant::now();
        self.epoch_records = 0;
        Ok(())
    }
}

// Checker control is authenticated but cannot handshake with a tunnel listener.
const CHECKER_PROLOGUE: &[u8] = crate::session_crypto::CHECKER_DOMAIN;

fn checker_connection(stream: BoxIo, handshake: snow::HandshakeState) -> Result<SecureConnection> {
    Ok(SecureConnection::new(
        stream,
        crate::session_crypto::transport(handshake, 1)?,
    ))
}

pub(crate) async fn connect_checker(
    addr: &str,
    private: &[u8; 32],
    public: &[u8; 32],
    timeout: Duration,
) -> Result<SecureConnection> {
    connect_control(addr,private,public,timeout,CHECKER_PROLOGUE).await
}

pub(crate) async fn connect_control(addr:&str,private:&[u8;32],public:&[u8;32],timeout:Duration,prologue:&[u8])->Result<SecureConnection> {
    tokio::time::timeout(timeout, async {
        let socket = TcpStream::connect(addr).await?;
        socket.set_nodelay(true)?;
        let mut stream: BoxIo = Box::new(socket);
        let mut handshake = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(private)?
            .remote_public_key(public)?
            .prologue(prologue)?
            .build_initiator()?;
        let mut output = vec![0; MAX_RECORD];
        let n = handshake.write_message(&[], &mut output)?;
        write_record(&mut stream, &output[..n]).await?;
        let response = read_record(&mut stream).await?;
        ensure!(
            handshake.read_message(&response, &mut output)? == 0
                && handshake.is_handshake_finished(),
            "invalid checker handshake"
        );
        checker_connection(stream, handshake)
    })
    .await
    .context("checker handshake timed out")?
}

pub(crate) async fn accept_checker(
    socket: TcpStream,
    private: &[u8; 32],
    allowed: &[[u8; 32]],
    timeout: Duration,
) -> Result<SecureConnection> {
    accept_control(socket,private,allowed,timeout,CHECKER_PROLOGUE).await
}

pub(crate) async fn accept_control(socket:TcpStream,private:&[u8;32],allowed:&[[u8;32]],timeout:Duration,prologue:&[u8])->Result<SecureConnection> {
    tokio::time::timeout(timeout, async {
        socket.set_nodelay(true)?;
        let mut stream: BoxIo = Box::new(socket);
        let mut handshake = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(private)?
            .prologue(prologue)?
            .build_responder()?;
        let request = read_record(&mut stream).await?;
        let mut output = vec![0; MAX_RECORD];
        ensure!(
            handshake.read_message(&request, &mut output)? == 0,
            "invalid checker handshake"
        );
        let peer = handshake
            .get_remote_static()
            .context("missing checker identity")?;
        ensure!(
            allowed.iter().any(|key| key.as_slice() == peer),
            "unknown checker identity"
        );
        let n = handshake.write_message(&[], &mut output)?;
        write_record(&mut stream, &output[..n]).await?;
        ensure!(
            handshake.is_handshake_finished(),
            "incomplete checker handshake"
        );
        checker_connection(stream, handshake)
    })
    .await
    .context("checker handshake timed out")?
}

pub async fn connect(
    addr: &str,
    private_key: &[u8; 32],
    server_public_key: &[u8; 32],
    timeout: Duration,
) -> Result<SecureConnection> {
    tokio::time::timeout(timeout, async {
        let stream = TcpStream::connect(addr)
            .await
            .context("connect to configured peer")?;
        stream.set_nodelay(true)?;
        initiate(Box::new(stream), private_key, server_public_key, 1).await
    })
    .await
    .context("peer connection/handshake timed out")?
}

pub async fn connect_path(path: &ClientPath, private_key: &[u8; 32]) -> Result<SecureConnection> {
    let server_key = crate::config::decode_key(&path.server_public_key)?;
    tokio::time::timeout(Duration::from_secs(path.dial_timeout), async {
        let stream = masked(client_carrier(path).await?, path.transport, &path.wire);
        Ok(
            initiate(stream, private_key, &server_key, path.wire.version)
                .await?
                .shaped(&path.wire),
        )
    })
    .await
    .context("peer connection/handshake timed out")?
}

async fn initiate(
    stream: BoxIo,
    private_key: &[u8; 32],
    server_public_key: &[u8; 32],
    version: u8,
) -> Result<SecureConnection> {
    initiate_as(stream, private_key, server_public_key, version).await
}

async fn initiate_as(
    mut stream: BoxIo,
    private_key: &[u8; 32],
    server_public_key: &[u8; 32],
    version: u8,
) -> Result<SecureConnection> {
    let prologue = crate::session_crypto::prologue(PROLOGUE, version, false)?;
    let mut handshake = Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(private_key)?
        .remote_public_key(server_public_key)?
        .prologue(&prologue)?
        .build_initiator()?;
    let mut output = vec![0; MAX_RECORD];
    let size = handshake.write_message(&[], &mut output)?;
    write_record(&mut stream, &output[..size]).await?;
    let response = read_record(&mut stream).await?;
    let size = handshake
        .read_message(&response, &mut output)
        .context("peer handshake authentication failed (check the tunnel key and wire_version on both servers)")?;
    ensure!(
        size == 0 && handshake.is_handshake_finished(),
        "unexpected handshake payload"
    );
    Ok(SecureConnection::new(
        stream,
        crate::session_crypto::transport(handshake, version)?,
    ))
}

pub async fn accept(
    stream: TcpStream,
    private_key: &[u8; 32],
    allowed_peers: &[[u8; 32]],
    timeout: Duration,
) -> Result<SecureConnection> {
    stream.set_nodelay(true)?;
    respond(
        Box::new(stream),
        private_key,
        allowed_peers,
        &WireOptions::default(),
        timeout,
    )
    .await
}

pub async fn accept_listener(
    stream: crate::kcp_carrier::Incoming,
    listener: &Listener,
    private_key: &[u8; 32],
    allowed_peers: &[[u8; 32]],
    timeout: Duration,
) -> Result<SecureConnection> {
    // Only the carrier setup (e.g. accepting TLS) is bounded here; respond() separately bounds
    // the handshake wait and, on failure, lets the probe-resistance hold run its own course.
    let stream: BoxIo = tokio::time::timeout(timeout, async {
        let stream: BoxIo = match stream {
            crate::kcp_carrier::Incoming::Tcp(stream) => server_carrier(stream, listener).await?,
            crate::kcp_carrier::Incoming::Kcp(stream, _) => Box::new(stream),
            crate::kcp_carrier::Incoming::Xhttp(stream) => stream,
            crate::kcp_carrier::Incoming::Fec(stream) => stream,
            crate::kcp_carrier::Incoming::Parallax(stream, _) => stream,
        };
        Ok::<_, anyhow::Error>(masked(stream, listener.transport, &listener.wire))
    })
    .await
    .context("peer handshake timed out")??;
    Ok(
        respond(stream, private_key, allowed_peers, &listener.wire, timeout)
            .await?
            .shaped(&listener.wire),
    )
}

pub async fn connect_responder(
    listener: &Listener,
    private: &[u8; 32],
    peers: &[[u8; 32]],
    dial_timeout_sec: u64,
) -> Result<SecureConnection> {
    let timeout = Duration::from_secs(dial_timeout_sec);
    let stream: BoxIo = tokio::time::timeout(timeout, async {
        let mut stream = client_carrier(&listener.dial_path(dial_timeout_sec)).await?;
        if matches!(
            listener.transport,
            crate::config::Transport::Kcp | crate::config::Transport::FecUdp
        ) {
            stream.write_u8(KCP_WAKE).await?;
            stream.flush().await?;
        }
        Ok::<_, anyhow::Error>(masked(stream, listener.transport, &listener.wire))
    })
    .await
    .context("reverse peer handshake timed out")??;
    Ok(respond(stream, private, peers, &listener.wire, timeout)
        .await?
        .shaped(&listener.wire))
}

pub async fn accept_initiator(
    incoming: crate::kcp_carrier::Incoming,
    path: &ClientPath,
    private: &[u8; 32],
) -> Result<SecureConnection> {
    let server_key = crate::config::decode_key(&path.server_public_key)?;
    tokio::time::timeout(Duration::from_secs(path.dial_timeout), async {
        let stream: BoxIo = match incoming {
            crate::kcp_carrier::Incoming::Tcp(stream) => {
                server_carrier(stream, &path.listen_config()).await?
            }
            crate::kcp_carrier::Incoming::Kcp(stream, _) => wake(Box::new(stream)).await?,
            crate::kcp_carrier::Incoming::Xhttp(stream) => stream,
            crate::kcp_carrier::Incoming::Fec(stream) => wake(stream).await?,
            crate::kcp_carrier::Incoming::Parallax(stream, _) => stream,
        };
        let stream = masked(stream, path.transport, &path.wire);
        Ok(initiate(stream, private, &server_key, path.wire.version)
            .await?
            .shaped(&path.wire))
    })
    .await
    .context("reverse peer handshake timed out")?
}

/// Reads the byte a dialing server sends first over KCP and FEC-UDP.
async fn wake(mut stream: BoxIo) -> Result<BoxIo> {
    ensure!(
        stream.read_u8().await? == KCP_WAKE,
        "unexpected first byte from the dialing server"
    );
    Ok(stream)
}

pub fn validate_tls_config(config: &crate::config::Config) -> Result<()> {
    crate::carrier::validate_tls_config(config)
}

/// Reads and answers the peer's handshake, bounded by `handshake_timeout`. On any failure to
/// complete it in time — a peer with the wrong key or version, or one that sends nothing at all
/// — the hold (`wire.stealth.probe_hold_sec`) runs on its own budget, so a silent probe is held
/// and closed exactly like one that sent quick garbage, and a longer `probe_hold_sec` than
/// `handshake_timeout` is not silently cut short by it.
async fn respond(
    mut stream: BoxIo,
    private_key: &[u8; 32],
    allowed_peers: &[[u8; 32]],
    wire: &WireOptions,
    handshake_timeout: Duration,
) -> Result<SecureConnection> {
    let outcome = tokio::time::timeout(
        handshake_timeout,
        respond_steps(&mut stream, private_key, allowed_peers, wire.version),
    )
    .await;
    match outcome {
        Ok(Ok(traffic)) => Ok(SecureConnection::new(stream, traffic)),
        Ok(Err(error)) => {
            // A probe or a peer with the wrong key or version gets silence, not an instant close.
            if wire.v2() {
                hold_then_close(&mut stream, wire.stealth.probe_hold_sec).await;
            }
            Err(error)
        }
        Err(_) => {
            if wire.v2() {
                hold_then_close(&mut stream, wire.stealth.probe_hold_sec).await;
            }
            Err(anyhow!("peer handshake timed out"))
        }
    }
}

async fn respond_steps(
    stream: &mut BoxIo,
    private_key: &[u8; 32],
    allowed_peers: &[[u8; 32]],
    version: u8,
) -> Result<HandshakeTraffic> {
    respond_steps_as(stream, private_key, allowed_peers, version).await
}

async fn respond_steps_as(
    stream: &mut BoxIo,
    private_key: &[u8; 32],
    allowed_peers: &[[u8; 32]],
    version: u8,
) -> Result<HandshakeTraffic> {
    ensure!(!allowed_peers.is_empty(), "no authorized peers configured");
    let prologue = crate::session_crypto::prologue(PROLOGUE, version, false)?;
    let mut handshake = Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(private_key)?
        .prologue(&prologue)?
        .build_responder()?;
    let request = read_record(stream).await?;
    let mut output = vec![0; MAX_RECORD];
    let size = handshake
        .read_message(&request, &mut output)
        .context("peer handshake authentication failed (check the tunnel key and wire_version on both servers)")?;
    ensure!(size == 0, "unexpected handshake payload");
    let remote = handshake
        .get_remote_static()
        .context("missing peer identity")?;
    // These are public keys; equality is not a secret-dependent comparison.
    ensure!(
        allowed_peers
            .iter()
            .any(|allowed| allowed.as_slice() == remote),
        "peer key is not authorized"
    );
    let size = handshake.write_message(&[], &mut output)?;
    write_record(stream, &output[..size]).await?;
    ensure!(handshake.is_handshake_finished(), "incomplete handshake");
    crate::session_crypto::transport(handshake, version)
}

async fn read_record(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let length = reader.read_u16().await.context("read record header")? as usize;
    ensure!(length > 0, "empty encrypted record");
    let mut data = vec![0; length];
    reader
        .read_exact(&mut data)
        .await
        .context("read encrypted record")?;
    Ok(data)
}

async fn write_record(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<()> {
    ensure!(
        !data.is_empty() && data.len() <= MAX_RECORD,
        "invalid record length"
    );
    writer.write_u16(data.len() as u16).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn keys() -> Result<snow::Keypair> {
        Ok(Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?)
    }

    #[tokio::test]
    async fn all_wire_versions_bind_the_handshake_and_carry_bidirectional_records() -> Result<()> {
        for version in 1..=3 {
            let server = keys()?;
            let client = keys()?;
            let server_public = server.public.try_into().unwrap();
            let client_public = client.public.try_into().unwrap();
            let server_private = server.private.try_into().unwrap();
            let client_private = client.private.try_into().unwrap();
            let (a, b) = tokio::io::duplex(65536);
            let mut responder: BoxIo = Box::new(b);
            let allowed = [client_public];
            let (a, b) = tokio::try_join!(
                initiate(Box::new(a), &client_private, &server_public, version),
                respond_steps(&mut responder, &server_private, &allowed, version)
            )?;
            let b = SecureConnection::new(responder, b);
            let (mut ar, mut aw) = a.split();
            let (mut br, mut bw) = b.split();
            let frame = Frame::Data { id: 1, data: vec![version; 4096] };
            aw.send(&frame).await?;
            assert_eq!(br.recv().await?, frame);
            bw.send(&frame).await?;
            assert_eq!(ar.recv().await?, frame);
        }
        Ok(())
    }

    #[tokio::test]
    async fn epochs_rekey_each_direction_and_preserve_record_nonces() -> Result<()> {
        let [a, b] = test_pair()?;
        let (mut ar, mut aw) = a.split();
        let (mut br, mut bw) = b.split();
        aw.rotation = Some(crate::wire::Rotation::new([11; 32]));
        br.rotation = Some(crate::wire::Rotation::new([11; 32]));
        bw.rotation = Some(crate::wire::Rotation::new([22; 32]));
        ar.rotation = Some(crate::wire::Rotation::new([22; 32]));
        for epoch in 1..=3 {
            aw.epoch_records = REKEY_RECORDS;
            bw.epoch_started = Instant::now() - REKEY_INTERVAL;
            let frame = Frame::Data {
                id: 1,
                data: vec![epoch as u8; 32],
            };
            aw.send(&frame).await?;
            assert_eq!(br.recv().await?, frame);
            bw.send(&frame).await?;
            assert_eq!(ar.recv().await?, frame);
            assert_eq!(
                (aw.epoch, br.epoch, bw.epoch, ar.epoch),
                (epoch, epoch, epoch, epoch)
            );
            assert_eq!(aw.state.lock().unwrap().sending_nonce(), epoch * 2);
            assert_eq!(br.state.lock().unwrap().receiving_nonce(), epoch * 2);
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn key_epochs_have_no_time_limit() -> Result<()> {
        let [a, b] = test_pair()?;
        let (_, mut write) = a.split();
        let (mut read, _) = b.split();
        write.advance_epoch().await?;
        tokio::time::advance(Duration::from_secs(3)).await;
        write.send(&Frame::Ping { nonce: 1 }).await?;
        assert_eq!(read.recv().await?, Frame::Ping { nonce: 1 });
        Ok(())
    }

    #[tokio::test]
    async fn epoch_records_refuse_skips_duplicates_and_truncation() -> Result<()> {
        for marker in [
            vec![REKEY_RECORD],
            {
                let mut b = vec![REKEY_RECORD];
                b.extend_from_slice(&2u64.to_be_bytes());
                b
            },
            {
                let mut b = vec![REKEY_RECORD];
                b.extend_from_slice(&0u64.to_be_bytes());
                b
            },
        ] {
            let [a, b] = test_pair()?;
            let (_, mut write) = a.split();
            let (mut read, _) = b.split();
            write.write_plaintext(marker).await?;
            assert!(read.recv().await.is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_honest_reader_requires_epoch_progression_before_more_application_data() -> Result<()>
    {
        for records in [false, true] {
            let [a, b] = test_pair()?;
            let (_, mut write) = a.split();
            let (mut read, _) = b.split();
            if records {
                read.epoch_records = 1 << 20;
            } else {
                read.epoch_started = Instant::now() - EPOCH_RECEIVE_LIMIT;
            }
            write
                .write_plaintext(Frame::Ping { nonce: 1 }.encode()?)
                .await?;
            assert!(read.recv().await.is_err());
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn idle_sessions_rekey_before_their_first_new_application_record() -> Result<()> {
        let [a, b] = test_pair()?;
        let (_, mut write) = a.split();
        let (mut read, _) = b.split();
        tokio::time::advance(Duration::from_secs(900)).await;
        let frame = Frame::Ping { nonce: 1 };
        write.send(&frame).await?;
        assert_eq!(read.recv().await?, frame);
        assert_eq!((write.epoch, read.epoch), (1, 1));
        Ok(())
    }

    #[tokio::test]
    async fn checker_setup_channel_authenticates_without_runtime_authority() -> Result<()> {
        let server = keys()?;
        let client = keys()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let public = server.public.try_into().unwrap();
        let peer = client.public.try_into().unwrap();
        let private = server.private.try_into().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let connection =
                accept_checker(stream, &private, &[peer], Duration::from_secs(2)).await?;
            let (mut read, mut write) = connection.split();
            let frame = read.recv().await?;
            write.send(&frame).await?;
            anyhow::Ok(())
        });
        let connection = connect_checker(
            &address,
            &client.private.try_into().unwrap(),
            &public,
            Duration::from_secs(2),
        )
        .await?;
        let (mut read, mut write) = connection.split();
        let frame = Frame::Data {
            id: 1,
            data: b"checker control".to_vec(),
        };
        write.send(&frame).await?;
        assert_eq!(read.recv().await?, frame);
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn checker_and_tunnel_handshakes_are_separate_protocols() -> Result<()> {
        for checker_dials in [true, false] {
            let server = keys()?;
            let client = keys()?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?.to_string();
            let public = server.public.try_into().unwrap();
            let peer = client.public.try_into().unwrap();
            let private = server.private.try_into().unwrap();
            let task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                if checker_dials {
                    assert!(
                        accept(stream, &private, &[peer], Duration::from_secs(2))
                            .await
                            .is_err()
                    );
                } else {
                    assert!(
                        accept_checker(stream, &private, &[peer], Duration::from_secs(2))
                            .await
                            .is_err()
                    );
                }
            });
            let private = client.private.try_into().unwrap();
            let result = if checker_dials {
                connect_checker(&address, &private, &public, Duration::from_secs(2)).await
            } else {
                connect(&address, &private, &public, Duration::from_secs(2)).await
            };
            assert!(result.is_err());
            task.await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn authenticated_bidirectional_records() -> Result<()> {
        let server = keys()?;
        let client = keys()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let public: [u8; 32] = server.public.try_into().unwrap();
        let peer: [u8; 32] = client.public.try_into().unwrap();
        let private: [u8; 32] = server.private.try_into().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let connection = accept(stream, &private, &[peer], Duration::from_secs(3)).await?;
            let (mut read, mut write) = connection.split();
            let frame = read.recv().await?;
            write.send(&frame).await?;
            anyhow::Ok(())
        });
        let client_private = client.private.try_into().unwrap();
        let connection =
            connect(&address, &client_private, &public, Duration::from_secs(3)).await?;
        let (mut read, mut write) = connection.split();
        let data = Frame::Data {
            id: 1,
            data: vec![42; crate::wire::DATA_SIZE],
        };
        write.send(&data).await?;
        assert_eq!(read.recv().await?, data);
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn untrusted_client_is_rejected() -> Result<()> {
        let server = keys()?;
        let client = keys()?;
        let trusted = keys()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let public = server.public.try_into().unwrap();
        let private = server.private.try_into().unwrap();
        let allowed = trusted.public.try_into().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            assert!(
                accept(stream, &private, &[allowed], Duration::from_secs(3))
                    .await
                    .is_err()
            );
        });
        assert!(
            connect(
                &address,
                &client.private.try_into().unwrap(),
                &public,
                Duration::from_secs(3)
            )
            .await
            .is_err()
        );
        task.await?;
        Ok(())
    }

    #[test]
    fn modified_and_replayed_ciphertext_is_rejected() -> Result<()> {
        let server = keys()?;
        let client = keys()?;
        let mut a = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&client.private)?
            .remote_public_key(&server.public)?
            .prologue(PROLOGUE)?
            .build_initiator()?;
        let mut b = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(&server.private)?
            .prologue(PROLOGUE)?
            .build_responder()?;
        let mut packet = [0; 1024];
        let mut plain = [0; 1024];
        let n = a.write_message(&[], &mut packet)?;
        b.read_message(&packet[..n], &mut plain)?;
        let n = b.write_message(&[], &mut packet)?;
        a.read_message(&packet[..n], &mut plain)?;
        let (mut a, mut b) = (a.into_transport_mode()?, b.into_transport_mode()?);
        let n = a.write_message(b"payload", &mut packet)?;
        let mut modified = packet;
        modified[0] ^= 1;
        assert!(b.read_message(&modified[..n], &mut plain).is_err());
        assert_eq!(b.read_message(&packet[..n], &mut plain)?, 7);
        assert!(b.read_message(&packet[..n], &mut plain).is_err());
        Ok(())
    }

    
}
