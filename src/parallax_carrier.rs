//! Parallax v1: independently authenticated directional TCP lanes. Lane framing
//! follows the recovered bounded-record architecture, not its vendor wire protocol.
//! Kernel TCP owns congestion/retransmission; EZTunnel retains its application mux,
//! paired authority and inner Noise epochs. A broken pair is never resumed in place.
use crate::carrier::BoxIo;
use crate::config::{ClientPath, Listener};
use crate::limits::{AcceptBackoff, PendingLimiter};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use snow::{Builder, TransportState};
use std::future::Future;
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use zeroize::Zeroizing;

const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const DOMAIN: &[u8] = b"eztunnel/parallax/tcp-lanes/v1";
const RECORD: usize = 2048;
const CHUNK: usize = RECORD - 16 - 9;
const HANDSHAKE: usize = 256;
const MAX_OFFSET: u64 = (1 << 62) - 1;
const REKEY_RECORDS: u64 = 1 << 20;
const BATCH_RECORDS: usize = 16;
const BATCH_BYTES: usize = (RECORD + 2) * BATCH_RECORDS;
const BATCH_WORK: Duration = Duration::from_micros(100);

/// Poll once without registering a second task or waiting to fill a batch. Tokio's
/// cooperative budget may return Pending; that simply ends the current batch.
fn read_ready(
    reader: &mut (impl AsyncRead + Unpin),
    bytes: &mut [u8],
) -> io::Result<Option<usize>> {
    let mut context = TaskContext::from_waker(std::task::Waker::noop());
    let mut buffer = ReadBuf::new(bytes);
    match Pin::new(reader).poll_read(&mut context, &mut buffer) {
        Poll::Ready(Ok(())) => Ok(Some(buffer.filled().len())),
        Poll::Ready(Err(error)) => Err(error),
        Poll::Pending => Ok(None),
    }
}

fn append_record(
    cipher: &mut TransportState,
    records: &mut u64,
    offset: &mut u64,
    data: &mut [u8],
    size: usize,
    batch: &mut [u8],
    used: &mut usize,
) -> Result<()> {
    data[0] = if size == 0 { 0x11 } else { 0x10 };
    data[1..9].copy_from_slice(&offset.to_be_bytes());
    *offset = offset
        .checked_add(size as u64)
        .filter(|n| *n <= MAX_OFFSET)
        .context("Parallax offset exhausted")?;
    let start = *used;
    let encrypted =
        cipher.write_message(&data[..size + 9], &mut batch[start + 2..start + 2 + RECORD])?;
    batch[start..start + 2].copy_from_slice(&(encrypted as u16).to_be_bytes());
    *used += encrypted + 2;
    *records += 1;
    if *records % REKEY_RECORDS == 0 {
        cipher.rekey_outgoing();
    }
    Ok(())
}

#[derive(Clone)]
pub struct Key(Zeroizing<[u8; 32]>);
impl Key {
    pub(crate) fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ParallaxKey(..)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Options {
    pub buffer_bytes: usize,
    pub handshake_timeout_sec: u64,
    pub max_pending: usize,
    pub max_pending_per_ip: usize,
    pub max_sessions: usize,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            buffer_bytes: 65536,
            handshake_timeout_sec: 10,
            max_pending: 128,
            max_pending_per_ip: 16,
            max_sessions: 64,
        }
    }
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (4096..=1048576).contains(&self.buffer_bytes),
            "Parallax buffer_bytes must be 4096..1048576"
        );
        ensure!(
            (1..=60).contains(&self.handshake_timeout_sec),
            "Parallax handshake_timeout_sec must be 1..60"
        );
        ensure!(
            (2..=4096).contains(&self.max_pending),
            "Parallax max_pending must be 2..4096"
        );
        ensure!(
            (2..=4096).contains(&self.max_pending_per_ip),
            "Parallax max_pending_per_ip must be 2..4096 (global limit also applies)"
        );
        ensure!(
            (1..=4096).contains(&self.max_sessions),
            "Parallax max_sessions must be 1..4096"
        );
        Ok(())
    }
}

struct Lane {
    socket: TcpStream,
    cipher: TransportState,
}
type Ticket = [u8; 32];
struct Pending {
    ip: IpAddr,
    sender: oneshot::Sender<Lane>,
}
type Pairs = Arc<Mutex<HashMap<Ticket, Pending>>>;
struct PairGuard {
    pairs: Pairs,
    ticket: Ticket,
}
impl Drop for PairGuard {
    fn drop(&mut self) {
        self.pairs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.ticket);
    }
}

fn random_ticket() -> Result<Ticket> {
    let mut ticket = [0; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut ticket)
        .map_err(|_| anyhow::anyhow!("Parallax random source failed"))?;
    Ok(ticket)
}
async fn read_record(socket: &mut TcpStream, maximum: usize) -> Result<Vec<u8>> {
    let size = socket.read_u16().await? as usize;
    ensure!(
        (1..=maximum).contains(&size),
        "invalid Parallax record length"
    );
    let mut bytes = vec![0; size];
    socket.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_record(socket: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= RECORD,
        "invalid Parallax output record"
    );
    // One write prevents a tiny prefix packet per record with TCP_NODELAY.
    let mut framed = [0u8; RECORD + 2];
    framed[..2].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed[2..bytes.len() + 2].copy_from_slice(bytes);
    socket.write_all(&framed[..bytes.len() + 2]).await?;
    Ok(())
}

async fn dial_lane(
    path: &ClientPath,
    key: &[u8; 32],
    role: u8,
    ticket: Ticket,
) -> Result<(Lane, Ticket)> {
    let mut socket = crate::carrier::tcp_for_path(path).await?;
    let mut handshake = Builder::new(PATTERN.parse()?)
        .prologue(DOMAIN)?
        .psk(0, key)?
        .build_initiator()?;
    let mut request = [0u8; 33];
    request[0] = role;
    request[1..].copy_from_slice(&ticket);
    let mut output = [0; HANDSHAKE];
    let n = handshake.write_message(&request, &mut output)?;
    write_record(&mut socket, &output[..n]).await?;
    let response = read_record(&mut socket, HANDSHAKE).await?;
    let n = handshake.read_message(&response, &mut output)?;
    ensure!(
        n == 33 && output[0] == role,
        "invalid Parallax lane response"
    );
    let received: Ticket = output[1..33].try_into()?;
    if role == 2 {
        ensure!(received == ticket, "Parallax lane association mismatch");
    }
    Ok((
        Lane {
            socket,
            cipher: handshake.into_transport_mode()?,
        },
        received,
    ))
}

pub async fn connect(path: &ClientPath) -> Result<BoxIo> {
    path.parallax.validate()?;
    let key = path
        .parallax_key
        .as_ref()
        .context("Parallax requires tunnel_key")?;
    timeout(
        Duration::from_secs(path.parallax.handshake_timeout_sec),
        async {
            let (up, ticket) = dial_lane(path, &key.0, 1, [0; 32]).await?;
            let (down, _) = dial_lane(path, &key.0, 2, ticket).await?;
            Ok::<BoxIo, anyhow::Error>(bridge(down, up, path.parallax.buffer_bytes, None))
        },
    )
    .await
    .context("Parallax lane handshake timeout")?
}

/// Owns all handshake and waiting-pair tasks; dropping the acceptor cancels them.
pub struct Acceptor {
    incoming: tokio::sync::mpsc::Receiver<(BoxIo, IpAddr)>,
    task: JoinHandle<()>,
}
impl Drop for Acceptor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Acceptor {
    pub async fn bind(listener: &Listener) -> Result<Self> {
        Self::from_listener(TcpListener::bind(&listener.addr).await?, listener.clone())
    }
    pub fn from_listener(socket: TcpListener, listener: Listener) -> Result<Self> {
        listener.parallax.validate()?;
        let key = listener
            .parallax_key
            .clone()
            .context("Parallax requires tunnel_key")?;
        let options = listener.parallax.clone();
        let (tx, incoming) = tokio::sync::mpsc::channel(options.max_sessions.min(64));
        let task = tokio::spawn(async move {
            let pairs: Pairs = Arc::new(Mutex::new(HashMap::new()));
            let pending = PendingLimiter::new(options.max_pending, options.max_pending_per_ip);
            let sessions = Arc::new(Semaphore::new(options.max_sessions));
            let mut tasks = JoinSet::new();
            let mut backoff = AcceptBackoff::new();
            loop {
                tokio::select! {
                    accepted = socket.accept() => {
                        let (socket,peer) = match accepted {
                            Ok(value) => { backoff.succeeded(); value },
                            Err(error) => { if backoff.failed("Parallax accept",error).await.is_err() { break; } continue; }
                        };
                        let Some(permit) = pending.try_enter(Some(peer.ip())) else { continue; };
                        let (pairs,sessions,tx,key,options) = (pairs.clone(),sessions.clone(),tx.clone(),key.clone(),options.clone());
                        let congestion = listener.tcp_congestion.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let result = timeout(Duration::from_secs(options.handshake_timeout_sec),
                                accept_lane(socket, peer.ip().to_canonical(), key, pairs, sessions, tx, options, congestion)).await;
                            if !matches!(result,Ok(Ok(()))) { tracing::debug!("Parallax lane handshake ended"); }
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        });
        Ok(Self { incoming, task })
    }
    pub async fn accept(&mut self) -> Result<(BoxIo, IpAddr)> {
        self.incoming
            .recv()
            .await
            .context("Parallax acceptor stopped")
    }
}

async fn accept_lane(
    mut socket: TcpStream,
    ip: IpAddr,
    key: Key,
    pairs: Pairs,
    sessions: Arc<Semaphore>,
    incoming: tokio::sync::mpsc::Sender<(BoxIo, IpAddr)>,
    options: Options,
    congestion: Option<String>,
) -> Result<()> {
    socket.set_nodelay(true)?;
    crate::carrier::tune_tcp(&socket, congestion.as_deref());
    let mut handshake = Builder::new(PATTERN.parse()?)
        .prologue(DOMAIN)?
        .psk(0, &*key.0)?
        .build_responder()?;
    let bytes = read_record(&mut socket, HANDSHAKE).await?;
    let mut output = [0u8; HANDSHAKE];
    let n = handshake.read_message(&bytes, &mut output)?;
    ensure!(
        n == 33 && matches!(output[0], 1 | 2),
        "invalid Parallax hello"
    );
    let role = output[0];
    let offered: Ticket = output[1..33].try_into()?;
    let (ticket, waiting, guard, slot) = if role == 1 {
        ensure!(offered == [0; 32], "unexpected Parallax initial ticket");
        let slot = sessions
            .try_acquire_owned()
            .context("Parallax session limit")?;
        let ticket = random_ticket()?;
        let (sender, waiting) = oneshot::channel();
        {
            let mut map = pairs.lock().unwrap_or_else(|e| e.into_inner());
            ensure!(!map.contains_key(&ticket), "Parallax ticket collision");
            map.insert(ticket, Pending { ip, sender });
        }
        let guard = PairGuard {
            pairs: pairs.clone(),
            ticket,
        };
        (ticket, Some(waiting), Some(guard), Some(slot))
    } else {
        (offered, None, None, None)
    };
    let sender = if role == 2 {
        let mut map = pairs.lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            map.get(&ticket).is_some_and(|p| p.ip == ip),
            "unknown Parallax pair"
        );
        Some(map.remove(&ticket).context("expired Parallax pair")?.sender)
    } else {
        None
    };
    let mut reply = [0u8; 33];
    reply[0] = role;
    reply[1..].copy_from_slice(&ticket);
    let n = handshake.write_message(&reply, &mut output)?;
    write_record(&mut socket, &output[..n]).await?;
    let lane = Lane {
        socket,
        cipher: handshake.into_transport_mode()?,
    };
    if let Some(sender) = sender {
        sender
            .send(lane)
            .map_err(|_| anyhow::anyhow!("Parallax pair expired"))?;
    } else {
        let down = waiting.context("missing Parallax pair waiter")?.await?;
        drop(guard);
        let io = bridge(lane, down, options.buffer_bytes, slot);
        incoming
            .send((io, ip))
            .await
            .map_err(|_| anyhow::anyhow!("Parallax acceptor closed"))?;
    }
    Ok(())
}

struct Stream {
    app: DuplexStream,
    task: JoinHandle<()>,
    sent_fin: oneshot::Receiver<()>,
    shutdown: bool,
    _slot: Option<OwnedSemaphorePermit>,
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.app).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if self.shutdown {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.app).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        match Pin::new(&mut self.sent_fin).poll(cx) {
            Poll::Ready(Ok(())) => {
                self.shutdown = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Parallax lane ended before FIN",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}
fn bridge(
    mut rx: Lane,
    mut tx: Lane,
    capacity: usize,
    slot: Option<OwnedSemaphorePermit>,
) -> BoxIo {
    let (app, transport) = tokio::io::duplex(capacity);
    let (finished, sent_fin) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut source, mut destination) = tokio::io::split(transport);
        let (read_finished, mut peer_finished) = tokio::sync::watch::channel(false);
        let send = async {
            let mut offset = 0u64;
            let mut data = [0u8; CHUNK + 9];
            let mut batch = vec![0u8; BATCH_BYTES];
            let mut records = 0u64;
            loop {
                let n = if *peer_finished.borrow() {
                    timeout(Duration::from_secs(30), source.read(&mut data[9..]))
                        .await
                        .context("Parallax half-close idle timeout")??
                } else {
                    tokio::select! {
                        result=source.read(&mut data[9..])=>result?,
                        _=peer_finished.changed()=>continue,
                    }
                };
                let started = std::time::Instant::now();
                let mut used = 0;
                let mut count = 1;
                let mut fin = n == 0;
                append_record(
                    &mut tx.cipher,
                    &mut records,
                    &mut offset,
                    &mut data,
                    n,
                    &mut batch,
                    &mut used,
                )?;
                while !fin && count < BATCH_RECORDS && started.elapsed() < BATCH_WORK {
                    let Some(n) = read_ready(&mut source, &mut data[9..])? else {
                        break;
                    };
                    append_record(
                        &mut tx.cipher,
                        &mut records,
                        &mut offset,
                        &mut data,
                        n,
                        &mut batch,
                        &mut used,
                    )?;
                    count += 1;
                    fin = n == 0;
                }
                timeout(Duration::from_secs(30), tx.socket.write_all(&batch[..used]))
                    .await
                    .context("Parallax write stalled")??;
                if fin {
                    tx.socket.shutdown().await?;
                    let _ = finished.send(());
                    return Ok::<(), anyhow::Error>(());
                }
                if count > 1 {
                    // Ready reads and socket writes can both complete synchronously.
                    // Give sibling interactive sessions a turn under sustained bulk load.
                    tokio::task::yield_now().await;
                }
            }
        };
        let receive = async {
            let mut offset = 0u64;
            let mut clear = [0u8; RECORD];
            let mut encrypted = [0u8; RECORD];
            let mut records = 0u64;
            loop {
                let size = rx.socket.read_u16().await? as usize;
                ensure!(
                    (1..=RECORD).contains(&size),
                    "invalid Parallax record length"
                );
                rx.socket.read_exact(&mut encrypted[..size]).await?;
                let n = rx.cipher.read_message(&encrypted[..size], &mut clear)?;
                records += 1;
                if records % REKEY_RECORDS == 0 {
                    rx.cipher.rekey_incoming();
                }
                ensure!(
                    n >= 9 && u64::from_be_bytes(clear[1..9].try_into()?) == offset,
                    "invalid Parallax sequence"
                );
                match clear[0] {
                    0x10 => {
                        ensure!(n > 9, "empty Parallax data");
                        offset = offset
                            .checked_add((n - 9) as u64)
                            .filter(|n| *n <= MAX_OFFSET)
                            .context("Parallax offset exhausted")?;
                        destination.write_all(&clear[9..n]).await?;
                    }
                    0x11 => {
                        ensure!(n == 9, "invalid Parallax FIN");
                        destination.shutdown().await?;
                        read_finished.send_replace(true);
                        return Ok::<(), anyhow::Error>(());
                    }
                    _ => anyhow::bail!("unknown Parallax record"),
                }
            }
        };
        if let Err(error) = tokio::try_join!(send, receive) {
            tracing::debug!(%error,"Parallax pair ended");
        }
    });
    Box::new(Stream {
        app,
        task,
        sent_fin,
        shutdown: false,
        _slot: slot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, tunnel_key::TunnelKey};

    #[tokio::test]
    async fn ready_reads_never_wait_and_do_not_lose_the_next_wakeup() -> Result<()> {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        let mut data = [0; 32];
        assert_eq!(read_ready(&mut reader, &mut data)?, None);
        writer.write_all(b"ready").await?;
        assert_eq!(read_ready(&mut reader, &mut data)?, Some(5));
        assert_eq!(&data[..5], b"ready");
        assert_eq!(read_ready(&mut reader, &mut data)?, None);
        let sending = tokio::spawn(async move {
            tokio::task::yield_now().await;
            writer.write_all(b"later").await?;
            writer.shutdown().await
        });
        assert_eq!(
            timeout(Duration::from_secs(1), reader.read(&mut data)).await??,
            5
        );
        assert_eq!(&data[..5], b"later");
        sending.await??;
        assert_eq!(read_ready(&mut reader, &mut data)?, Some(0));
        Ok(())
    }

    #[tokio::test]
    async fn a_coalesced_batch_keeps_old_framing_fin_and_rekey_boundaries() -> Result<()> {
        let (_accept, path) = fixture().await?;
        let key = path.parallax_key.as_ref().unwrap();
        let (mut up, _) = dial_lane(&path, &key.0, 1, [0; 32]).await?;
        let mut receiver = {
            // Establish a matching cipher independently; no binary mutation is used.
            let mut a = Builder::new(PATTERN.parse()?)
                .psk(0, &*key.0)?
                .build_initiator()?;
            let mut b = Builder::new(PATTERN.parse()?)
                .psk(0, &*key.0)?
                .build_responder()?;
            let mut message = [0u8; 256];
            let mut clear = [0u8; 256];
            let n = a.write_message(&[], &mut message)?;
            b.read_message(&message[..n], &mut clear)?;
            let n = b.write_message(&[], &mut message)?;
            a.read_message(&message[..n], &mut clear)?;
            up.cipher = a.into_transport_mode()?;
            b.into_transport_mode()?
        };
        let mut batch = vec![0u8; BATCH_BYTES];
        let mut data = [0u8; CHUNK + 9];
        let mut count = REKEY_RECORDS - 1;
        let mut offset = 0;
        let mut used = 0;
        for index in 0..BATCH_RECORDS {
            let size = if index + 1 == BATCH_RECORDS { 0 } else { CHUNK };
            data[9..].fill(index as u8);
            append_record(
                &mut up.cipher,
                &mut count,
                &mut offset,
                &mut data,
                size,
                &mut batch,
                &mut used,
            )?;
        }
        assert_eq!(used, (BATCH_RECORDS - 1) * (RECORD + 2) + 27);
        assert!(used <= BATCH_BYTES);
        let mut position = 0;
        let mut expected_offset = 0u64;
        let mut clear = [0u8; RECORD];
        for index in 0..BATCH_RECORDS {
            let size = u16::from_be_bytes(batch[position..position + 2].try_into()?) as usize;
            let n = receiver.read_message(&batch[position + 2..position + 2 + size], &mut clear)?;
            if index == 0 {
                receiver.rekey_incoming();
            }
            assert_eq!(u64::from_be_bytes(clear[1..9].try_into()?), expected_offset);
            if index + 1 == BATCH_RECORDS {
                assert_eq!((clear[0], n), (0x11, 9));
            } else {
                assert_eq!(clear[0], 0x10);
                assert!(clear[9..n].iter().all(|b| *b == index as u8));
                expected_offset += CHUNK as u64;
            }
            position += size + 2;
        }
        assert_eq!(position, used);
        Ok(())
    }

    async fn fixture() -> Result<(Acceptor, ClientPath)> {
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?.to_string();
        let key = TunnelKey::generate()?.display();
        let mut server: Config = serde_json::from_value(
            serde_json::json!({"mode":"server","tunnel_key":key,
            "listeners":[{"addr":address,"transport":"parallax","parallax":{"handshake_timeout_sec":1,"max_sessions":1}}]}),
        )?;
        let mut client: Config = serde_json::from_value(
            serde_json::json!({"mode":"client","tunnel_key":key,
            "allowed_targets":["127.0.0.1:*"],"paths":[{"addr":address,"transport":"parallax","parallax":{"handshake_timeout_sec":2}}]}),
        )?;
        server.prepare()?;
        client.prepare()?;
        Ok((
            Acceptor::from_listener(socket, server.listeners[0].clone())?,
            client.paths[0].clone(),
        ))
    }

    #[tokio::test]
    async fn tickets_are_single_use_and_unpaired_session_slots_expire() -> Result<()> {
        let (mut accept, path) = fixture().await?;
        let key = path.parallax_key.as_ref().unwrap();
        let (up, ticket) = dial_lane(&path, &key.0, 1, [0; 32]).await?;
        assert!(dial_lane(&path, &key.0, 2, [9; 32]).await.is_err());
        let (down, _) = dial_lane(&path, &key.0, 2, ticket).await?;
        let (server, _) = accept.accept().await?;
        assert!(dial_lane(&path, &key.0, 2, ticket).await.is_err());
        assert!(dial_lane(&path, &key.0, 1, [0; 32]).await.is_err());
        drop(server);
        drop(up);
        drop(down);
        let (orphan, _) = dial_lane(&path, &key.0, 1, [0; 32]).await?;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        drop(orphan);
        let client = connect(&path).await?;
        let (server, _) = accept.accept().await?;
        drop(client);
        drop(server);
        Ok(())
    }

    #[tokio::test]
    async fn dropping_acceptor_cancels_waiting_handshake_and_closes_port() -> Result<()> {
        let (accept, path) = fixture().await?;
        let (mut orphan, _) =
            dial_lane(&path, &path.parallax_key.as_ref().unwrap().0, 1, [0; 32]).await?;
        drop(accept);
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(1), orphan.socket.read(&mut byte)).await??,
            0
        );
        assert!(TcpStream::connect(&path.addr).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn oversized_and_zero_record_prefixes_are_rejected_before_body_allocation() -> Result<()>
    {
        for length in [0, 257, 65535] {
            let (accept, path) = fixture().await?;
            let mut socket = TcpStream::connect(&path.addr).await?;
            socket.write_u16(length).await?;
            let mut byte = [0];
            let result = timeout(Duration::from_secs(1), socket.read(&mut byte)).await?;
            assert!(matches!(result, Ok(0) | Err(_)));
            drop(accept);
        }
        Ok(())
    }

    #[tokio::test]
    async fn slow_consumer_applies_backpressure_without_blocking_another_session() -> Result<()> {
        let (mut accept, mut path) = fixture().await?;
        // A separate acceptor has enough pair slots; limits include accepted streams.
        drop(accept);
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        path.addr = socket.local_addr()?.to_string();
        let listener = Listener {
            parallax: Options {
                max_sessions: 4,
                ..Options::default()
            },
            ..path.listen_config()
        };
        accept = Acceptor::from_listener(socket, listener)?;
        let mut blocked = connect(&path).await?;
        let (slow, _) = accept.accept().await?;
        let sending = tokio::spawn(async move {
            let block = [42u8; 65536];
            for _ in 0..1024 {
                blocked.write_all(&block).await?;
            }
            Ok::<_, anyhow::Error>(())
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !sending.is_finished(),
            "unbounded buffering accepted 64 MiB without a reader"
        );
        let mut other = connect(&path).await?;
        let (mut peer, _) = accept.accept().await?;
        other.write_all(b"control progress").await?;
        let mut value = [0; 16];
        timeout(Duration::from_secs(1), peer.read_exact(&mut value)).await??;
        assert_eq!(&value, b"control progress");
        drop(slow);
        assert!(timeout(Duration::from_secs(2), sending).await??.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn authenticated_offsets_and_record_replays_fail_closed() -> Result<()> {
        for replay in [false, true] {
            let (mut accept, path) = fixture().await?;
            let key = path.parallax_key.as_ref().unwrap();
            let (mut up, ticket) = dial_lane(&path, &key.0, 1, [0; 32]).await?;
            let (_down, _) = dial_lane(&path, &key.0, 2, ticket).await?;
            let (mut server, _) = accept.accept().await?;
            let mut data = [0u8; 10];
            data[0] = 0x10;
            data[9] = 7;
            if !replay {
                data[8] = 1;
            }
            let mut encrypted = [0u8; RECORD];
            let n = up.cipher.write_message(&data, &mut encrypted)?;
            write_record(&mut up.socket, &encrypted[..n]).await?;
            if replay {
                let mut byte = [0];
                server.read_exact(&mut byte).await?;
                assert_eq!(byte, [7]);
                write_record(&mut up.socket, &encrypted[..n]).await?;
            }
            let mut byte = [0];
            assert_eq!(
                timeout(Duration::from_secs(1), server.read(&mut byte)).await??,
                0
            );
        }
        Ok(())
    }

    #[test]
    fn options_and_secrets_are_bounded_and_redacted() {
        let key = Key::new(Zeroizing::new([71; 32]));
        assert_eq!(format!("{key:?}"), "ParallaxKey(..)");
        let mut options = Options::default();
        assert!(options.validate().is_ok());
        options.buffer_bytes = usize::MAX;
        assert!(options.validate().is_err());
        options = Options::default();
        options.max_pending = 1;
        assert!(options.validate().is_err());
    }
}
