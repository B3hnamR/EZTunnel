//! HTTP request/body transport with bounded, sequenced packet uploads.
//! This is eztunnel's own framing.
use crate::limits::{AcceptBackoff, PendingGuard, PendingLimiter};
use crate::{
    carrier::{
        BoxIo, Headers, ManagedIo, accept_http, chunked_io, connect_http, http_authority,
        read_headers,
    },
    config::{ClientPath, Listener, XhttpMode, XhttpOptions},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use blake2::{Blake2s256, Digest};
use std::{
    collections::{BTreeMap, HashMap},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
    sync::{Semaphore, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};

const UPLOAD_WINDOW: usize = 16;
#[cfg(test)]
const MAX_CHUNK: usize = 65_536;

struct Upload {
    sequence: u64,
    body: Vec<u8>,
    acknowledged: oneshot::Sender<u16>,
}

struct Session {
    uploads: mpsc::Sender<Upload>,
    mode: XhttpMode,
    stream_started: AtomicBool,
    request_slots: Arc<Semaphore>,
}

type Sessions = Arc<Mutex<HashMap<String, Arc<Session>>>>;

/// Released when the single-request stream-up connection ends, so it stops counting toward
/// `max_sessions` alongside the id-based GET/POST sessions it shares that limit with.
struct SingleRequestSlot {
    count: Arc<AtomicUsize>,
}
impl Drop for SingleRequestSlot {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A stream with admission-control guards attached, released (freeing the slots) when the
/// engine drops the connection.
struct GuardedIo {
    io: BoxIo,
    _pending: PendingGuard,
    _slot: SingleRequestSlot,
}
impl AsyncRead for GuardedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for GuardedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// A guard removes a session even when the owning bridge task is cancelled.
struct SessionGuard {
    sessions: Sessions,
    id: String,
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&self.id);
        }
    }
}

/// Owns the HTTP listener and request tasks. The engine receives one stream
/// per GET session, regardless of how many upload requests that session uses.
pub struct Acceptor {
    incoming: mpsc::Receiver<BoxIo>,
    task: JoinHandle<()>,
}
impl Drop for Acceptor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Acceptor {
    pub async fn bind(listener: &Listener) -> Result<Self> {
        let socket = TcpListener::bind(&listener.addr).await?;
        Self::from_listener(socket, listener.clone())
    }

    /// Allows tests and embedders to supply an already bound listener.
    pub fn from_listener(socket: TcpListener, listener: Listener) -> Result<Self> {
        let (incoming_tx, incoming) = mpsc::channel(listener.xhttp.max_sessions);
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        // Single-request stream-up connections have no session id to track in `sessions`, but
        // still count toward `max_sessions` through this shared counter.
        let single_sessions = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(async move {
            // Global and per-source limits on simultaneous HTTP connections.
            let per_ip = match listener.xhttp.max_requests_per_ip {
                0 => listener.xhttp.max_requests,
                limit => limit,
            };
            let slots = PendingLimiter::new(listener.xhttp.max_requests, per_ip);
            // Sessions per source address, counted until the session ends (a session's
            // download connection outlives the request that created it).
            let session_slots = PendingLimiter::new(
                Semaphore::MAX_PERMITS,
                match listener.xhttp.max_sessions_per_ip {
                    0 => usize::MAX,
                    limit => limit,
                },
            );
            if listener.xhttp.access_token.is_none() {
                tracing::warn!(
                    address = %listener.addr,
                    "this XHTTP listener has no access_token: anyone who can reach it can open sessions (a tunnel_key configuration derives one)"
                );
            }
            let mut backoff = AcceptBackoff::new();
            let mut requests = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = socket.accept() => {
                        let (tcp, peer) = match accepted {
                            Ok(accepted) => { backoff.succeeded(); accepted }
                            Err(error) => {
                                if backoff.failed("XHTTP accept", error).await.is_err() { break; }
                                continue;
                            }
                        };
                        let Some(permit) = slots.try_enter(Some(peer.ip())) else { continue; };
                        let (listener, sessions, incoming_tx) = (listener.clone(), sessions.clone(), incoming_tx.clone());
                        let session_slots = session_slots.clone();
                        let single_sessions = single_sessions.clone();
                        requests.spawn(async move {
                            let _permit = permit;
                            let result = async {
                                let deadline = Duration::from_secs(listener.xhttp.session_timeout_sec);
                                let stream = timeout(deadline, accept_http(tcp, &listener)).await??;
                                handle_request(stream, &listener, sessions, incoming_tx, peer.ip(), session_slots, single_sessions).await
                            }.await;
                            if let Err(error) = result {
                                tracing::debug!(%error, "XHTTP request ended");
                            }
                        });
                    }
                    _ = requests.join_next(), if !requests.is_empty() => {}
                }
            }
        });
        Ok(Self { incoming, task })
    }

    pub async fn accept(&mut self) -> Result<BoxIo> {
        self.incoming.recv().await.context("XHTTP listener stopped")
    }
}

fn prefix(path: &str) -> &str {
    path.trim_end_matches('/')
}

/// First half of an id/proof is random; the second half is a keyed hash of it when an
/// access token is configured, so the server can recognise ids made by a holder of the token.
fn token_tag(token: &str, nonce: &[u8]) -> [u8; 16] {
    let mut hash = Blake2s256::new();
    hash.update(b"eztunnel/xhttp-access/v1");
    hash.update((token.len() as u32).to_be_bytes());
    hash.update(token.as_bytes());
    hash.update(nonce);
    let full = hash.finalize();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

/// An id (or access proof) has the shape of 64 hex characters. With a token configured the last
/// 32 must also be the keyed hash of the first 32.
fn valid_id(id: &str, token: Option<&str>) -> bool {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let Some(token) = token else {
        return true;
    };
    let Ok(bytes) = hex::decode(id) else {
        return false;
    };
    let expected = token_tag(token, &bytes[..16]);
    // Compare without stopping at the first difference.
    expected
        .iter()
        .zip(&bytes[16..])
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn host(path: &ClientPath) -> &str {
    path.xhttp.host.as_deref().unwrap_or(&path.addr)
}

fn chunked(headers: &Headers) -> bool {
    headers
        .value("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
}

fn random_bytes(bytes: &mut [u8]) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(bytes)
        .map_err(|_| anyhow!("operating-system random generator failed"))
}

fn pad_url(base: &str, options: &XhttpOptions) -> Result<String> {
    ensure!(
        options.pad_min <= options.pad_max && options.pad_max <= 4096,
        "invalid HTTP padding bounds"
    );
    let mut random = [0; 4];
    random_bytes(&mut random)?;
    let length = options.pad_min
        + u32::from_le_bytes(random) as usize % (options.pad_max - options.pad_min + 1);
    if length == 0 {
        return Ok(base.to_string());
    }
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut bytes = vec![0; length];
    random_bytes(&mut bytes)?;
    for byte in &mut bytes {
        *byte = ALPHABET[*byte as usize % ALPHABET.len()];
    }
    Ok(format!("{base}?v={}", String::from_utf8(bytes)?))
}

fn request_path(url: &str) -> Result<&str> {
    ensure!(
        url.is_ascii() && !url.bytes().any(|b| b.is_ascii_control()) && !url.contains('#'),
        "invalid HTTP tunnel URL"
    );
    if let Some((path, query)) = url.split_once('?') {
        let padding = query
            .strip_prefix("v=")
            .context("unknown HTTP tunnel query parameter")?;
        ensure!(
            padding.len() <= 4096 && padding.bytes().all(|b| b.is_ascii_alphanumeric()),
            "invalid HTTP tunnel query padding"
        );
        Ok(path)
    } else {
        Ok(url)
    }
}

fn user_agent(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 256
            && value.is_ascii()
            && !value.bytes().any(|b| b.is_ascii_control()),
        "invalid HTTP User-Agent"
    );
    Ok(())
}

async fn write_request(
    stream: &mut BoxIo,
    path: &ClientPath,
    method: &str,
    target: &str,
    fields: &str,
) -> Result<()> {
    http_authority(host(path))?;
    user_agent(&path.xhttp.user_agent)?;
    let url = pad_url(target, &path.xhttp)?;
    stream
        .write_all(
            format!(
                "{method} {url} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n{fields}\r\n",
                host(path),
                path.xhttp.user_agent
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;
    Ok(())
}

async fn response(stream: &mut BoxIo, status: u16) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Bad Request",
    };
    stream.write_all(format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n").as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// A request that is not ours: version 1 answers with the bare status; version 2 with a web-server
/// page, then holds the connection quiet for a while.
async fn reject(stream: &mut BoxIo, listener: &Listener, status: u16) -> Result<()> {
    if listener.wire.v2() {
        crate::carrier::reject_probe(stream, &listener.wire).await;
        return Ok(());
    }
    response(stream, status).await
}

async fn body_response(stream: &mut BoxIo) -> Result<()> {
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store, no-transform\r\nX-Accel-Buffering: no\r\nConnection: keep-alive\r\n\r\n").await?;
    stream.flush().await?;
    Ok(())
}

async fn handle_request(
    mut stream: BoxIo,
    listener: &Listener,
    sessions: Sessions,
    incoming: mpsc::Sender<BoxIo>,
    peer: std::net::IpAddr,
    session_slots: Arc<PendingLimiter>,
    single_sessions: Arc<AtomicUsize>,
) -> Result<()> {
    let deadline = Duration::from_secs(listener.xhttp.session_timeout_sec);
    loop {
        let header = timeout(deadline, read_headers(&mut stream)).await??;
        let parts: Vec<_> = header.first.split(' ').collect();
        if parts.len() != 3 || parts[2] != "HTTP/1.1" {
            reject(&mut stream, listener, 400).await?;
            return Ok(());
        }
        let method = parts[0];
        let url = match request_path(parts[1]) {
            Ok(url) => url,
            Err(_) => {
                reject(&mut stream, listener, 400).await?;
                return Ok(());
            }
        };
        if header
            .value("host")
            .is_none_or(|value| http_authority(value).is_err())
        {
            reject(&mut stream, listener, 400).await?;
            return Ok(());
        }
        // Single-request stream-up endpoint (no session id).
        if method == "POST" && url == listener.http_path {
            if let Some(token) = listener.xhttp.access_token.as_deref()
                && !valid_id(
                    header
                        .value(&listener.wire.xhttp_header("auth").to_ascii_lowercase())
                        .unwrap_or(""),
                    Some(token),
                )
            {
                reject(&mut stream, listener, 404).await?;
                return Ok(());
            }
            if !chunked(&header) || header.value("content-length").is_some() {
                reject(&mut stream, listener, 400).await?;
                return Ok(());
            }
            // This path has no session id to track in `sessions`, but a connection kept open
            // here is exactly as expensive as an id-based session, so it must count against the
            // same per-source and total `max_sessions` limits instead of being unbounded.
            let Some(pending) = session_slots.try_enter(Some(peer)) else {
                response(&mut stream, 503).await?;
                return Ok(());
            };
            // Checked and reserved under the same lock the id-based path below inserts under, so
            // the two kinds of session - which share one counter pair for one combined limit -
            // cannot both pass their own check before either one counts itself.
            let admitted = {
                let entries = sessions
                    .lock()
                    .map_err(|_| anyhow!("XHTTP session registry poisoned"))?;
                let active = entries.len() + single_sessions.load(Ordering::Relaxed);
                if active >= listener.xhttp.max_sessions {
                    false
                } else {
                    single_sessions.fetch_add(1, Ordering::Relaxed);
                    true
                }
            };
            if !admitted {
                response(&mut stream, 503).await?;
                return Ok(());
            }
            // Own the reservation before the first fallible/cancellable await.
            let slot = SingleRequestSlot {
                count: single_sessions.clone(),
            };
            body_response(&mut stream).await?;
            let guarded: BoxIo = Box::new(GuardedIo {
                io: chunked_io(stream),
                _pending: pending,
                _slot: slot,
            });
            incoming
                .send(guarded)
                .await
                .map_err(|_| anyhow!("XHTTP accept queue closed"))?;
            return Ok(());
        }
        let Some(suffix) = url.strip_prefix(&format!("{}/", prefix(&listener.http_path))) else {
            reject(&mut stream, listener, 404).await?;
            return Ok(());
        };
        let segments: Vec<_> = suffix.split('/').collect();
        if method == "POST"
            && segments.len() == 2
            && segments[0] == "probe"
            && valid_id(segments[1], listener.xhttp.access_token.as_deref())
        {
            if !chunked(&header) || header.value("content-length").is_some() {
                reject(&mut stream, listener, 400).await?;
                return Ok(());
            }
            let first = timeout(deadline, read_chunk(&mut stream, 1)).await??;
            ensure!(
                first.as_deref() == Some(&[0][..]),
                "invalid XHTTP streaming probe"
            );
            response(&mut stream, 200).await?;
            ensure!(
                timeout(deadline, read_chunk(&mut stream, 1))
                    .await??
                    .is_none(),
                "probe has trailing data"
            );
            continue;
        }
        if segments.is_empty() || !valid_id(segments[0], listener.xhttp.access_token.as_deref()) {
            reject(&mut stream, listener, 404).await?;
            return Ok(());
        }
        let id = segments[0].to_string();
        if method == "GET" && segments.len() == 1 {
            if header
                .value("content-length")
                .is_some_and(|value| value != "0")
                || header.value("transfer-encoding").is_some()
            {
                reject(&mut stream, listener, 400).await?;
                return Ok(());
            }
            let mode =
                match header.value(&listener.wire.xhttp_header("upload").to_ascii_lowercase()) {
                    Some("packet-up") => XhttpMode::PacketUp,
                    Some("stream-up") => XhttpMode::StreamUp,
                    _ => {
                        reject(&mut stream, listener, 400).await?;
                        return Ok(());
                    }
                };
            let Some(session_slot) = session_slots.try_enter(Some(peer)) else {
                response(&mut stream, 503).await?;
                return Ok(());
            };
            let (upload_tx, upload_rx) = mpsc::channel(UPLOAD_WINDOW);
            let session = Arc::new(Session {
                uploads: upload_tx,
                mode,
                stream_started: AtomicBool::new(false),
                request_slots: Arc::new(Semaphore::new(UPLOAD_WINDOW)),
            });
            let status = {
                let mut entries = sessions
                    .lock()
                    .map_err(|_| anyhow!("XHTTP session registry poisoned"))?;
                if entries.contains_key(&id) {
                    409
                } else if entries.len() + single_sessions.load(Ordering::Relaxed)
                    >= listener.xhttp.max_sessions
                {
                    503
                } else {
                    entries.insert(id.clone(), session);
                    200
                }
            };
            if status != 200 {
                response(&mut stream, status).await?;
                return Ok(());
            }
            let guard = SessionGuard { sessions, id };
            body_response(&mut stream).await?;
            let (io, bridge) = tokio::io::duplex(listener.xhttp.buffer_bytes);
            let task = tokio::spawn(async move {
                let (_guard, _slot) = (guard, session_slot);
                let (mut input, mut output) = tokio::io::split(bridge);
                let (mut from_client, mut to_client) = tokio::io::split(stream);
                // The download connection is dedicated to this session. If the client closes it,
                // the session is over now; waiting for the next write (or the upload deadline)
                // would keep the session's slots taken for up to `session_timeout_sec`.
                let result = tokio::select! {
                    result = async {
                        tokio::try_join!(
                            receive_uploads(upload_rx, &mut output, deadline),
                            send_chunks(&mut input, &mut to_client)
                        )
                        .map(|_| ())
                    } => result,
                    gone = client_gone(&mut from_client) => gone,
                };
                if let Err(error) = result {
                    tracing::debug!(%error, "XHTTP session ended");
                }
            });
            incoming
                .send(Box::new(ManagedIo { io, task }))
                .await
                .map_err(|_| anyhow!("XHTTP accept queue closed"))?;
            return Ok(());
        }
        let session = {
            sessions
                .lock()
                .map_err(|_| anyhow!("XHTTP session registry poisoned"))?
                .get(&id)
                .cloned()
        };
        let Some(session) = session else {
            response(&mut stream, 410).await?;
            return Ok(());
        };
        if method != "POST" {
            reject(&mut stream, listener, 404).await?;
            return Ok(());
        }
        if segments.len() == 1 && session.mode == XhttpMode::StreamUp {
            if !chunked(&header) || header.value("content-length").is_some() {
                reject(&mut stream, listener, 400).await?;
                return Ok(());
            }
            if session.stream_started.swap(true, Ordering::AcqRel) {
                response(&mut stream, 409).await?;
                return Ok(());
            }
            body_response(&mut stream).await?;
            write_chunk(&mut stream, b"+").await?;
            let mut sequence = 0;
            loop {
                let chunk = timeout(
                    deadline,
                    read_chunk(&mut stream, listener.xhttp.up_max_bytes),
                )
                .await??;
                let end = chunk.is_none();
                let status =
                    submit(&session, sequence, chunk.unwrap_or_default(), deadline).await?;
                ensure!(status == 200, "XHTTP streaming upload rejected");
                if end {
                    write_chunk(&mut stream, &[]).await?;
                    return Ok(());
                }
                sequence = sequence
                    .checked_add(1)
                    .context("XHTTP upload sequence exhausted")?;
            }
        }
        if segments.len() != 2 || session.mode != XhttpMode::PacketUp {
            response(&mut stream, 409).await?;
            return Ok(());
        }
        if segments[1].is_empty()
            || segments[1].len() > 20
            || !segments[1].bytes().all(|b| b.is_ascii_digit())
        {
            reject(&mut stream, listener, 400).await?;
            return Ok(());
        }
        let Ok(sequence) = segments[1].parse::<u64>() else {
            reject(&mut stream, listener, 400).await?;
            return Ok(());
        };
        if header.value("transfer-encoding").is_some() {
            reject(&mut stream, listener, 400).await?;
            return Ok(());
        }
        let Some(length) = header
            .value("content-length")
            .filter(|s| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<usize>().ok())
        else {
            reject(&mut stream, listener, 400).await?;
            return Ok(());
        };
        if length > listener.xhttp.up_max_bytes {
            response(&mut stream, 413).await?;
            return Ok(());
        }
        let Ok(_slot) = session.request_slots.clone().try_acquire_owned() else {
            response(&mut stream, 429).await?;
            return Ok(());
        };
        let mut body = vec![0; length];
        timeout(deadline, stream.read_exact(&mut body)).await??;
        let status = submit(&session, sequence, body, deadline).await?;
        response(&mut stream, status).await?;
        if length == 0 {
            return Ok(());
        }
    }
}

async fn submit(
    session: &Session,
    sequence: u64,
    body: Vec<u8>,
    deadline: Duration,
) -> Result<u16> {
    let (acknowledged, ack) = oneshot::channel();
    if timeout(
        deadline,
        session.uploads.send(Upload {
            sequence,
            body,
            acknowledged,
        }),
    )
    .await?
    .is_err()
    {
        return Ok(410);
    }
    Ok(timeout(deadline, ack).await?.unwrap_or(410))
}

async fn receive_uploads<W: AsyncWrite + Unpin>(
    mut uploads: mpsc::Receiver<Upload>,
    output: &mut W,
    deadline: Duration,
) -> Result<()> {
    let mut next = 0u64;
    let mut pending = BTreeMap::new();
    while let Some(upload) = timeout(deadline, uploads.recv()).await? {
        // A genuine duplicate (already delivered, or already waiting its turn) is reported as
        // 409: the sender can safely treat that as "no need to resend". A packet outside the
        // reorder window was never stored at all - reporting that as 409 too would let a retry
        // on a reused connection (`delivered_already_ok`) mistake "I could not take this" for
        // "I already have this" and never resend it, silently losing the packet. 429 ("try
        // again") keeps that retry honest.
        if upload.sequence < next || pending.contains_key(&upload.sequence) {
            let _ = upload.acknowledged.send(409);
            continue;
        }
        if upload.sequence - next >= UPLOAD_WINDOW as u64 {
            let _ = upload.acknowledged.send(429);
            continue;
        }
        pending.insert(upload.sequence, upload);
        while let Some(upload) = pending.remove(&next) {
            if upload.body.is_empty() {
                output.shutdown().await?;
                let _ = upload.acknowledged.send(200);
                return Ok(());
            }
            timeout(deadline, output.write_all(&upload.body)).await??;
            let _ = upload.acknowledged.send(200);
            next = next
                .checked_add(1)
                .context("XHTTP upload sequence exhausted")?;
        }
    }
    bail!("XHTTP upload session closed before EOF")
}

async fn write_chunk<W: AsyncWrite + Unpin>(stream: &mut W, body: &[u8]) -> Result<()> {
    stream
        .write_all(format!("{:x}\r\n", body.len()).as_bytes())
        .await?;
    stream.write_all(body).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    Ok(())
}

async fn read_chunk<R: AsyncRead + Unpin>(stream: &mut R, max: usize) -> Result<Option<Vec<u8>>> {
    let length = chunk_length(stream, max).await?;
    if length == 0 {
        finish_chunks(stream).await?;
        return Ok(None);
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    chunk_terminator(stream).await?;
    Ok(Some(body))
}

async fn chunk_length<R: AsyncRead + Unpin>(stream: &mut R, max: usize) -> Result<usize> {
    let mut line = Vec::new();
    while !line.ends_with(b"\r\n") {
        ensure!(line.len() < 256, "XHTTP chunk header too long");
        line.push(stream.read_u8().await?);
    }
    let line = std::str::from_utf8(&line[..line.len() - 2])?;
    ensure!(
        line.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
        "invalid HTTP chunk extension"
    );
    let digits = line.split(';').next().unwrap();
    ensure!(
        !digits.is_empty() && digits.len() <= 16 && digits.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid XHTTP chunk length"
    );
    // Parsed as u64 first (16 hex digits always fits) so a chunk length this big is reported as
    // "exceeds the limit" on every architecture, rather than as an opaque parse failure on a
    // 32-bit build, where usize is narrower than what the wire format can carry.
    let length = u64::from_str_radix(digits, 16)?;
    ensure!(length <= max as u64, "XHTTP chunk exceeds configured limit");
    Ok(length as usize)
}

async fn chunk_terminator<R: AsyncRead + Unpin>(stream: &mut R) -> Result<()> {
    let mut end = [0; 2];
    stream.read_exact(&mut end).await?;
    ensure!(&end == b"\r\n", "invalid XHTTP chunk terminator");
    Ok(())
}

async fn finish_chunks<R: AsyncRead + Unpin>(stream: &mut R) -> Result<()> {
    let mut total = 0;
    loop {
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            ensure!(total < 8192, "HTTP trailers too large");
            line.push(stream.read_u8().await?);
            total += 1;
        }
        if line == b"\r\n" {
            return Ok(());
        }
        let line = std::str::from_utf8(&line[..line.len() - 2])?;
        ensure!(
            line.contains(':') && !line.bytes().any(|b| b.is_ascii_control()),
            "invalid HTTP trailer"
        );
    }
}

async fn send_chunks<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> Result<()> {
    send_chunks_sized(reader, writer, 16_384).await
}

/// Ends with an error when the peer closes the connection (anything it still sends is ignored).
async fn client_gone<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut sink = [0u8; 256];
    loop {
        let count = reader.read(&mut sink).await?;
        ensure!(count != 0, "the client closed the download connection");
    }
}

async fn send_chunks_sized<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    size: usize,
) -> Result<()> {
    let mut buffer = vec![0; size];
    loop {
        let count = reader.read(&mut buffer).await?;
        write_chunk(writer, &buffer[..count]).await?;
        if count == 0 {
            return Ok(());
        }
    }
}

pub(crate) async fn receive_chunks<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> Result<()> {
    // A proxy may combine or split origin chunks. Consume large proxy chunks
    // with a fixed buffer so they cannot control the tunnel's allocation size.
    let mut buffer = vec![0; 16_384];
    loop {
        let mut remaining = chunk_length(reader, 16 * 1024 * 1024).await?;
        if remaining == 0 {
            finish_chunks(reader).await?;
            break;
        }
        while remaining != 0 {
            let count = remaining.min(buffer.len());
            reader.read_exact(&mut buffer[..count]).await?;
            writer.write_all(&buffer[..count]).await?;
            remaining -= count;
        }
        chunk_terminator(reader).await?;
    }
    writer.shutdown().await?;
    Ok(())
}

/// A fresh session id; with a token it doubles as proof that the sender knows the token.
fn session_id(token: Option<&str>) -> Result<String> {
    let mut random = [0; 32];
    random_bytes(&mut random)?;
    if let Some(token) = token {
        let tag = token_tag(token, &random[..16]);
        random[16..].copy_from_slice(&tag);
    }
    Ok(hex::encode(random))
}

async fn probe_stream(path: &ClientPath, id: &str) -> Result<()> {
    let mut stream = connect_http(path).await?;
    write_request(&mut stream,path,"POST",&format!("{}/probe/{id}",prefix(&path.http_path)),"Transfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n").await?;
    write_chunk(&mut stream, &[0]).await?;
    let headers = read_headers(&mut stream).await?;
    ensure!(
        headers.first == "HTTP/1.1 200 OK"
            && headers.value("content-length") == Some("0")
            && headers.value("transfer-encoding").is_none(),
        "streaming probe rejected"
    );
    write_chunk(&mut stream, &[]).await?;
    Ok(())
}

/// Uses only the configured peer address, Host/SNI and CA. It never discovers
/// edge addresses, contacts external services or downloads transport metadata.
pub async fn connect(path: &ClientPath) -> Result<BoxIo> {
    // Preserve the initial long-POST eztunnel stream framing by default.
    if path.xhttp.mode == XhttpMode::StreamUp {
        let mut stream = connect_http(path).await?;
        let auth = match path.xhttp.access_token.as_deref() {
            Some(token) => format!(
                "{}: {}\r\n",
                path.wire.xhttp_header("auth"),
                session_id(Some(token))?
            ),
            None => String::new(),
        };
        write_request(&mut stream,path,"POST",&path.http_path,&format!("Content-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n{auth}Connection: keep-alive\r\n")).await?;
        let header = read_headers(&mut stream).await?;
        ensure!(
            header.first == "HTTP/1.1 200 OK"
                && chunked(&header)
                && header.value("content-length").is_none(),
            "HTTP stream rejected"
        );
        return Ok(chunked_io(stream));
    }
    let id = session_id(path.xhttp.access_token.as_deref())?;
    let mode = if path.xhttp.mode == XhttpMode::Auto {
        let limit = path
            .xhttp
            .probe_ms
            .min(path.dial_timeout.saturating_mul(500))
            .max(1);
        if matches!(
            timeout(Duration::from_millis(limit), probe_stream(path, &id)).await,
            Ok(Ok(()))
        ) {
            XhttpMode::StreamUp
        } else {
            XhttpMode::PacketUp
        }
    } else {
        XhttpMode::PacketUp
    };
    let mut download = connect_http(path).await?;
    write_request(
        &mut download,
        path,
        "GET",
        &format!("{}/{id}", prefix(&path.http_path)),
        &format!(
            "{}: {}\r\nConnection: keep-alive\r\n",
            path.wire.xhttp_header("upload"),
            if mode == XhttpMode::PacketUp {
                "packet-up"
            } else {
                "stream-up"
            }
        ),
    )
    .await?;
    let headers = read_headers(&mut download).await?;
    ensure!(
        headers.first == "HTTP/1.1 200 OK"
            && chunked(&headers)
            && headers.value("content-length").is_none(),
        "XHTTP download rejected"
    );
    let upload = if mode == XhttpMode::StreamUp {
        let mut stream = connect_http(path).await?;
        write_request(&mut stream,path,"POST",&format!("{}/{id}",prefix(&path.http_path)),"Transfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n").await?;
        let headers = read_headers(&mut stream).await?;
        ensure!(
            headers.first == "HTTP/1.1 200 OK"
                && chunked(&headers)
                && headers.value("content-length").is_none(),
            "XHTTP upload rejected"
        );
        Some(stream)
    } else {
        None
    };
    let (io, bridge) = tokio::io::duplex(path.xhttp.buffer_bytes);
    let path = path.clone();
    let task = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(bridge);
        let upload = async {
            if let Some(stream) = upload {
                let (mut read, mut write) = tokio::io::split(stream);
                let mut discard = tokio::io::sink();
                tokio::try_join!(
                    send_chunks_sized(&mut input, &mut write, path.xhttp.up_max_bytes.min(16_384)),
                    receive_chunks(&mut read, &mut discard)
                )?;
            } else {
                packet_upload(&mut input, &path, &id).await?;
            }
            anyhow::Ok(())
        };
        if let Err(error) = tokio::try_join!(upload, receive_chunks(&mut download, &mut output)) {
            tracing::debug!(%error, "XHTTP carrier ended");
        }
    });
    Ok(Box::new(ManagedIo { io, task }))
}

struct Packet {
    sequence: u64,
    body: Vec<u8>,
}

async fn packet_upload<R: AsyncRead + Unpin>(
    reader: &mut R,
    path: &ClientPath,
    id: &str,
) -> Result<()> {
    let (sender, receiver) = mpsc::channel(path.xhttp.up_concurrency);
    let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
    let mut workers = JoinSet::new();
    for _ in 0..path.xhttp.up_concurrency {
        let (receiver, path, id) = (receiver.clone(), path.clone(), id.to_string());
        workers.spawn(packet_worker(receiver, path, id));
    }
    let producer = async move {
        let mut sequence = 0;
        loop {
            let mut body = vec![0; path.xhttp.up_max_bytes];
            let count = reader.read(&mut body).await?;
            body.truncate(count);
            sender
                .send(Packet { sequence, body })
                .await
                .context("XHTTP upload workers stopped")?;
            if count == 0 {
                return anyhow::Ok(());
            }
            sequence = sequence
                .checked_add(1)
                .context("XHTTP upload sequence exhausted")?;
        }
    };
    let completion = async {
        while let Some(result) = workers.join_next().await {
            result??;
        }
        anyhow::Ok(())
    };
    tokio::try_join!(producer, completion)?;
    Ok(())
}

/// Sends one packet as a POST on `stream` and reads the answer. Returns whether the connection
/// can be used again. With `delivered_already_ok`, a 409 (duplicate sequence) counts as success.
async fn post_packet(
    stream: &mut BoxIo,
    path: &ClientPath,
    id: &str,
    packet: &Packet,
    deadline: Duration,
    delivered_already_ok: bool,
) -> Result<bool> {
    timeout(deadline, async {
        write_request(stream,path,"POST",&format!("{}/{id}/{}",prefix(&path.http_path),packet.sequence),&format!("Content-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",packet.body.len())).await?;
        stream.write_all(&packet.body).await?;
        stream.flush().await?;
        let headers = read_headers(stream).await?;
        if delivered_already_ok && headers.first.starts_with("HTTP/1.1 409") {
            return anyhow::Ok(false);
        }
        ensure!(headers.first == "HTTP/1.1 200 OK", "XHTTP packet upload rejected: {}", headers.first);
        if chunked(&headers) && headers.value("content-length").is_none() {
            ensure!(read_chunk(stream,0).await?.is_none(), "XHTTP upload acknowledgement contained a body");
        } else {
            ensure!(headers.value("content-length") == Some("0") && headers.value("transfer-encoding").is_none(), "invalid XHTTP upload acknowledgement framing");
        }
        anyhow::Ok(!headers.value("connection").is_some_and(|value| value.split(',').any(|token| token.trim().eq_ignore_ascii_case("close"))))
    })
    .await?
}

/// A new HTTP connection in the middle of a session. The first connections of a session are bounded
/// by the dial timeout of the whole handshake; these need their own limit, or a reconnect into a
/// blackhole stalls the upload for the kernel's TCP connect timeout (about 2 minutes) or a TLS
/// handshake that never ends.
async fn reconnect(path: &ClientPath) -> Result<BoxIo> {
    timeout(Duration::from_secs(path.dial_timeout), connect_http(path))
        .await
        .context("XHTTP reconnect timed out")?
}

async fn packet_worker(
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet>>>,
    path: ClientPath,
    id: String,
) -> Result<()> {
    let mut connection: Option<BoxIo> = None;
    let mut used = Instant::now();
    let deadline = Duration::from_secs(path.xhttp.session_timeout_sec);
    loop {
        let packet = receiver.lock().await.recv().await;
        let Some(packet) = packet else {
            return Ok(());
        };
        if used.elapsed() >= deadline / 2 {
            connection = None;
        }
        let reused = connection.is_some();
        if connection.is_none() {
            connection = Some(reconnect(&path).await?);
        }
        let mut result = post_packet(
            connection.as_mut().unwrap(),
            &path,
            &id,
            &packet,
            deadline,
            false,
        )
        .await;
        // A connection kept open between packets may have been closed meanwhile by the server or
        // a proxy in front of it (their idle timeouts are often short). That shows up as an I/O
        // error, not as an HTTP answer. It is not the end of the session: the same packet goes
        // out again on a new connection.
        if reused
            && matches!(&result, Err(error) if error.downcast_ref::<std::io::Error>().is_some())
        {
            connection = Some(reconnect(&path).await?);
            // If the first attempt did get through and only its answer was lost, the server now
            // says 409 (it has this sequence number): that counts as delivered.
            result = post_packet(
                connection.as_mut().unwrap(),
                &path,
                &id,
                &packet,
                deadline,
                true,
            )
            .await;
        }
        if !result? {
            connection = None;
        }
        used = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single_request_response_failure_releases_capacity_before_next_request() -> Result<()> {
        for token in [None, Some(TOKEN)] {
            let listener: Listener = serde_json::from_value(serde_json::json!({
                "addr": "127.0.0.1:1", "transport": "xhttp",
                "xhttp": {"max_sessions": 1, "access_token": token}
            }))?;
            let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
            let count = Arc::new(AtomicUsize::new(0));
            let slots = PendingLimiter::new(1, 1);
            let (incoming, mut accepted) = mpsc::channel(1);
            let auth = token
                .map(|t| format!("X-EZ-Auth: {}\r\n", session_id(Some(t)).unwrap()))
                .unwrap_or_default();
            let header = format!(
                "POST /tunnel HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n{auth}\r\n"
            );
            // Input remains readable, but the response write has no reader.
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(header.as_bytes()).await?;
            drop(client);
            assert!(
                handle_request(
                    Box::new(server),
                    &listener,
                    sessions.clone(),
                    incoming.clone(),
                    "127.0.0.1".parse()?,
                    slots.clone(),
                    count.clone()
                )
                .await
                .is_err()
            );
            assert_eq!(count.load(Ordering::Relaxed), 0);
            assert!(accepted.try_recv().is_err());
            // Retry with the same limit: admission must recover without a restart.
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(header.as_bytes()).await?;
            handle_request(
                Box::new(server),
                &listener,
                sessions.clone(),
                incoming.clone(),
                "127.0.0.1".parse()?,
                slots.clone(),
                count.clone(),
            )
            .await?;
            let mut client: BoxIo = Box::new(client);
            assert_eq!(read_headers(&mut client).await?.first, "HTTP/1.1 200 OK");
            assert_eq!(count.load(Ordering::Relaxed), 1);
            drop(accepted.recv().await.context("missing accepted stream")?);
            assert_eq!(count.load(Ordering::Relaxed), 0);
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_single_request_response_releases_capacity() -> Result<()> {
        let listener: Listener = serde_json::from_value(serde_json::json!({
            "addr": "127.0.0.1:1", "transport": "xhttp", "xhttp": {"max_sessions": 1}
        }))?;
        let count = Arc::new(AtomicUsize::new(0));
        let (incoming, mut accepted) = mpsc::channel(1);
        let (mut client, server) = tokio::io::duplex(16);
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        let slots = PendingLimiter::new(1, 1);
        let handler = handle_request(
            Box::new(server),
            &listener,
            sessions,
            incoming,
            "127.0.0.1".parse()?,
            slots.clone(),
            count.clone(),
        );
        let send = async {
            client.write_all(b"POST /tunnel HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n").await?;
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert_eq!(
                count.load(Ordering::Relaxed),
                1,
                "response never reached the reserved slot"
            );
            std::future::pending::<Result<()>>().await
        };
        assert!(
            timeout(Duration::from_secs(1), async {
                tokio::join!(handler, send)
            })
            .await
            .is_err()
        );
        assert_eq!(count.load(Ordering::Relaxed), 0);
        assert!(accepted.try_recv().is_err());
        assert!(slots.try_enter(Some("127.0.0.1".parse()?)).is_some());
        Ok(())
    }

    fn queued(sequence: u64, body: &[u8]) -> (Upload, oneshot::Receiver<u16>) {
        let (acknowledged, receiver) = oneshot::channel();
        (
            Upload {
                sequence,
                body: body.to_vec(),
                acknowledged,
            },
            receiver,
        )
    }

    #[tokio::test]
    async fn uploads_order_and_reject_replays_and_unbounded_sequences() -> Result<()> {
        let (sender, receiver) = mpsc::channel(16);
        let (mut read, mut write) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            receive_uploads(receiver, &mut write, Duration::from_secs(2)).await
        });
        let (later, later_ack) = queued(1, b"second");
        sender.send(later).await?;
        let (first, first_ack) = queued(0, b"first");
        sender.send(first).await?;
        ensure!(
            first_ack.await? == 200 && later_ack.await? == 200,
            "ordered upload rejected"
        );
        let (duplicate, duplicate_ack) = queued(0, b"injected");
        sender.send(duplicate).await?;
        ensure!(duplicate_ack.await? == 409, "duplicate upload accepted");
        // Outside the reorder window, not a duplicate: never stored, so unlike 409 this must not
        // be read by a retry as "already have it" (see the dedicated test below).
        let (far, far_ack) = queued(u64::MAX, b"injected");
        sender.send(far).await?;
        ensure!(
            far_ack.await? == 429,
            "unbounded future upload was not rejected distinctly"
        );
        let (end, end_ack) = queued(2, b"");
        sender.send(end).await?;
        ensure!(end_ack.await? == 200, "EOF rejected");
        let mut actual = Vec::new();
        read.read_to_end(&mut actual).await?;
        ensure!(
            actual == b"firstsecond",
            "ordering or duplicate protection failed"
        );
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn upload_acknowledgement_waits_for_bounded_stream_capacity() -> Result<()> {
        let (sender, receiver) = mpsc::channel(16);
        let (mut read, mut write) = tokio::io::duplex(16);
        let task = tokio::spawn(async move {
            receive_uploads(receiver, &mut write, Duration::from_secs(2)).await
        });
        let (packet, mut ack) = queued(0, &[42; 64]);
        sender.send(packet).await?;
        ensure!(
            timeout(Duration::from_millis(30), &mut ack).await.is_err(),
            "upload was acknowledged before bounded stream accepted its body"
        );
        let mut body = [0; 64];
        read.read_exact(&mut body).await?;
        ensure!(
            body == [42; 64] && ack.await? == 200,
            "backpressured upload changed"
        );
        let (end, end_ack) = queued(1, b"");
        sender.send(end).await?;
        ensure!(end_ack.await? == 200, "EOF rejected");
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn chunk_decoder_rejects_oversize_and_bad_terminator() -> Result<()> {
        for bytes in [b"10001\r\n".as_slice(), b"1\r\nxZZ".as_slice()] {
            let mut reader = bytes;
            ensure!(
                read_chunk(&mut reader, MAX_CHUNK).await.is_err(),
                "malformed chunk accepted"
            );
        }
        Ok(())
    }

    async fn request(address: std::net::SocketAddr, text: String) -> Result<String> {
        let mut stream: BoxIo = Box::new(tokio::net::TcpStream::connect(address).await?);
        stream.write_all(text.as_bytes()).await?;
        stream.flush().await?;
        Ok(read_headers(&mut stream).await?.first)
    }

    async fn listener() -> Result<(Acceptor, std::net::SocketAddr)> {
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let listener: Listener = serde_json::from_value(
            serde_json::json!({"addr":address.to_string(),"transport":"xhttp"}),
        )?;
        Ok((Acceptor::from_listener(socket, listener)?, address))
    }

    async fn open_get(address: std::net::SocketAddr, id: &str) -> Result<BoxIo> {
        let mut stream: BoxIo = Box::new(tokio::net::TcpStream::connect(address).await?);
        stream
            .write_all(
                format!(
                    "GET /tunnel/{id} HTTP/1.1\r\nHost: localhost\r\nX-EZ-Upload: packet-up\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        stream.flush().await?;
        ensure!(
            read_headers(&mut stream).await?.first == "HTTP/1.1 200 OK",
            "download setup failed"
        );
        Ok(stream)
    }

    async fn listener_with(xhttp: serde_json::Value) -> Result<(Acceptor, std::net::SocketAddr)> {
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let listener: Listener = serde_json::from_value(serde_json::json!({
            "addr": address.to_string(), "transport": "xhttp", "xhttp": xhttp
        }))?;
        Ok((Acceptor::from_listener(socket, listener)?, address))
    }

    const TOKEN: &str = "0123456789abcdef-test-token";

    #[test]
    fn session_ids_need_the_keyed_tag_only_when_a_token_is_configured() {
        let plain = session_id(None).unwrap();
        assert!(valid_id(&plain, None));
        let proof = session_id(Some(TOKEN)).unwrap();
        assert_eq!(proof.len(), 64);
        assert!(valid_id(&proof, Some(TOKEN)));
        assert!(
            valid_id(&proof, None),
            "without a token only the shape is checked"
        );
        assert!(!valid_id(&proof, Some("a-different-token-value")));
        assert!(
            !valid_id(&plain, Some(TOKEN)),
            "a random id is not a valid proof"
        );
        let mut tampered = proof.clone().into_bytes();
        tampered[10] = if tampered[10] == b'0' { b'1' } else { b'0' };
        assert!(!valid_id(
            &String::from_utf8(tampered).unwrap(),
            Some(TOKEN)
        ));
        assert!(!valid_id("short", None));
        assert!(!valid_id(&"g".repeat(64), None));
    }

    #[tokio::test]
    async fn a_missing_or_wrong_proof_is_refused_before_a_session_exists() -> Result<()> {
        let (mut acceptor, address) =
            listener_with(serde_json::json!({"access_token": TOKEN})).await?;
        let get = |id: &str| {
            format!(
                "GET /tunnel/{id} HTTP/1.1\r\nHost: localhost\r\nX-EZ-Upload: packet-up\r\n\r\n"
            )
        };
        for id in [
            session_id(None)?,
            session_id(Some("some-other-token-value"))?,
        ] {
            let first = timeout(Duration::from_secs(2), request(address, get(&id))).await??;
            ensure!(
                first.starts_with("HTTP/1.1 404 "),
                "unauthenticated id was not refused: {first}"
            );
        }
        // The single-request endpoint needs the proof header.
        let bare = "POST /tunnel HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_string();
        let first = timeout(Duration::from_secs(2), request(address, bare)).await??;
        ensure!(
            first.starts_with("HTTP/1.1 404 "),
            "legacy endpoint accepted no proof: {first}"
        );
        let proof = session_id(Some(TOKEN))?;
        let with = format!(
            "POST /tunnel HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nX-EZ-Auth: {proof}\r\n\r\n"
        );
        let first = timeout(Duration::from_secs(2), request(address, with)).await??;
        ensure!(
            first.starts_with("HTTP/1.1 200 "),
            "legacy endpoint refused a valid proof: {first}"
        );
        // A valid proof creates a session as before.
        let _download = open_get(address, &session_id(Some(TOKEN))?).await?;
        let _accepted = timeout(Duration::from_secs(2), acceptor.accept()).await??;
        Ok(())
    }

    #[tokio::test]
    async fn one_source_address_cannot_use_all_http_connections() -> Result<()> {
        let (_acceptor, address) =
            listener_with(serde_json::json!({"max_requests_per_ip": 2})).await?;
        let mut silent = Vec::new();
        for _ in 0..6 {
            silent.push(tokio::net::TcpStream::connect(address).await?);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut open = 0;
        for stream in &mut silent {
            let mut byte = [0u8; 1];
            if timeout(Duration::from_millis(200), stream.read(&mut byte))
                .await
                .is_err()
            {
                open += 1;
            }
        }
        ensure!(
            open <= 2,
            "{open} silent connections from one address were kept"
        );
        // Another source address is unaffected.
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind("127.0.0.2:0".parse()?)?;
        let mut other: BoxIo = Box::new(socket.connect(address).await?);
        other
            .write_all(b"GET /nothing HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        other.flush().await?;
        let reply = timeout(Duration::from_secs(2), read_headers(&mut other)).await??;
        ensure!(
            reply.first.starts_with("HTTP/1.1 404 "),
            "other address was not served: {}",
            reply.first
        );
        Ok(())
    }

    /// A packet-up session lets only `UPLOAD_WINDOW` uploads be in flight: while that many are
    /// still arriving, the next one is answered `429 Too Many Requests` (the client's workers wait
    /// and try again) instead of piling up memory. The places come back when the uploads end.
    #[tokio::test]
    async fn too_many_uploads_in_flight_get_429_until_some_finish() -> Result<()> {
        let (_acceptor, address) = listener().await?;
        let id = session_id(None)?;
        let _download = open_get(address, &id).await?;
        // Every place is taken by an upload whose body never completes (10 bytes announced, 1 sent).
        let mut stalled = Vec::new();
        for sequence in 0..UPLOAD_WINDOW {
            let mut stream = tokio::net::TcpStream::connect(address).await?;
            stream
                .write_all(
                    format!(
                        "POST /tunnel/{id}/{sequence} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nx"
                    )
                    .as_bytes(),
                )
                .await?;
            stalled.push(stream);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let upload = |sequence: u64| {
            format!(
                "POST /tunnel/{id}/{sequence} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc"
            )
        };
        let reply = request(address, upload(20)).await?;
        ensure!(
            reply == "HTTP/1.1 429 Too Many Requests",
            "a full session answered: {reply}"
        );
        // The uploads end: the places are free again and a real upload goes through.
        drop(stalled);
        let mut answered = String::new();
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            answered = request(address, upload(0)).await?;
            if answered != "HTTP/1.1 429 Too Many Requests" {
                break;
            }
        }
        ensure!(
            answered == "HTTP/1.1 200 OK",
            "after the stalled uploads ended: {answered}"
        );
        Ok(())
    }

    /// Connections that stop talking are closed after `session_timeout_sec` (at least 5 seconds),
    /// so they do not keep a request place for ever: one that never sent a request, and a
    /// keep-alive upload connection that sent its last packet and then went quiet.
    #[tokio::test]
    async fn idle_connections_are_closed_after_the_session_timeout() -> Result<()> {
        let (_acceptor, address) =
            listener_with(serde_json::json!({"session_timeout_sec": 5})).await?;
        let id = session_id(None)?;
        let _download = open_get(address, &id).await?;
        let started = Instant::now();
        // A connection that never sends anything.
        let mut silent = tokio::net::TcpStream::connect(address).await?;
        // A keep-alive connection that sends one upload, is answered, and then says nothing.
        let mut quiet: BoxIo = Box::new(tokio::net::TcpStream::connect(address).await?);
        quiet
            .write_all(
                format!(
                    "POST /tunnel/{id}/0 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nabc"
                )
                .as_bytes(),
            )
            .await?;
        quiet.flush().await?;
        ensure!(
            read_headers(&mut quiet).await?.first == "HTTP/1.1 200 OK",
            "the upload was not accepted"
        );
        // Both are still open after a short time ...
        let mut byte = [0u8; 1];
        ensure!(
            timeout(Duration::from_secs(1), silent.read(&mut byte))
                .await
                .is_err(),
            "the silent connection was closed at once"
        );
        // ... and closed by the server soon after the timeout.
        let closed = timeout(Duration::from_secs(8), silent.read(&mut byte))
            .await
            .context("the silent connection was never closed")?;
        ensure!(matches!(closed, Ok(0) | Err(_)), "unexpected data");
        let closed = timeout(Duration::from_secs(8), quiet.read(&mut byte))
            .await
            .context("the quiet connection was never closed")?;
        ensure!(matches!(closed, Ok(0) | Err(_)), "unexpected data");
        let waited = started.elapsed();
        ensure!(
            waited >= Duration::from_secs(4) && waited < Duration::from_secs(9),
            "closed after {waited:?}"
        );
        Ok(())
    }

    /// A session counts against its source address for as long as it lives, not only while its
    /// first request is read.
    #[tokio::test]
    async fn sessions_can_be_limited_per_source_address() -> Result<()> {
        let (mut acceptor, address) =
            listener_with(serde_json::json!({"max_sessions_per_ip": 2})).await?;
        let first = open_get(address, &session_id(None)?).await?;
        let _accepted_first = acceptor.accept().await?;
        let second = open_get(address, &session_id(None)?).await?;
        let _accepted_second = acceptor.accept().await?;
        // A third session from the same address is refused ...
        ensure!(
            open_get(address, &session_id(None)?).await.is_err(),
            "a third session from one address was accepted"
        );
        // ... while another address is served ...
        let other_socket = tokio::net::TcpSocket::new_v4()?;
        other_socket.bind("127.0.0.2:0".parse()?)?;
        let mut other: BoxIo = Box::new(other_socket.connect(address).await?);
        other
            .write_all(
                format!(
                    "GET /tunnel/{} HTTP/1.1\r\nHost: localhost\r\nX-EZ-Upload: packet-up\r\n\r\n",
                    session_id(None)?
                )
                .as_bytes(),
            )
            .await?;
        other.flush().await?;
        ensure!(
            read_headers(&mut other).await?.first == "HTTP/1.1 200 OK",
            "another address was refused"
        );
        // ... and a slot comes back when a session ends.
        drop(first);
        drop(_accepted_first);
        let _again = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(stream) = open_get(address, &session_id(None)?).await {
                    return Ok::<_, anyhow::Error>(stream);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("the slot of an ended session was not freed")??;
        drop(second);
        Ok(())
    }

    #[tokio::test]
    async fn http_rejects_ambiguous_framing_bad_authority_and_oversize_before_body() -> Result<()> {
        let (mut acceptor, address) = listener().await?;
        let id = session_id(None)?;
        let _download = open_get(address, &id).await?;
        let _accepted = acceptor.accept().await?;
        let base = format!("POST /tunnel/{id}");
        for (text, status) in [
            (
                format!("GET /tunnel/{id} HTTP/1.1\r\nX-EZ-Upload: packet-up\r\n\r\n"),
                400,
            ),
            (
                format!(
                    "GET /tunnel/{id} HTTP/1.1\r\nHost: user@localhost\r\nX-EZ-Upload: packet-up\r\n\r\n"
                ),
                400,
            ),
            (
                format!(
                    "GET /tunnel/{id} HTTP/1.1\r\nHost: localhost\r\nX-EZ-Upload: packet-up\r\n\r\n"
                ),
                409,
            ),
            (
                format!(
                    "GET /tunnel/{id} HTTP/1.1\r\nHost: localhost\r\nX-EZ-Upload: packet-up\r\nContent-Length: 0\r\n\r\n"
                ),
                409,
            ),
            (
                format!(
                    "GET /tunnel/{id} HTTP/1.1\r\nHost: localhost\r\nX-EZ-Upload: packet-up\r\nContent-Length: 1\r\n\r\nx"
                ),
                400,
            ),
            (
                format!("{base}/+0 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx"),
                400,
            ),
            (
                format!("{base}/0 HTTP/1.1\r\nHost: localhost\r\nContent-Length: +1\r\n\r\nx"),
                400,
            ),
            (
                format!(
                    "{base}/0 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx"
                ),
                400,
            ),
            (
                format!("{base}/0 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 65537\r\n\r\n"),
                413,
            ),
            (
                // Sequence 16 is outside the 16-wide reorder window (next is still 0, nothing
                // delivered yet): 429, not 409 - it was never stored, so it must not be mistaken
                // by a retry for something already delivered.
                format!("{base}/16 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx"),
                429,
            ),
        ] {
            let first = timeout(Duration::from_secs(2), request(address, text)).await??;
            ensure!(
                first.starts_with(&format!("HTTP/1.1 {status} ")),
                "unexpected rejection: {first}"
            );
        }
        ensure!(request(address, format!("{base}/0 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx")).await.is_err(), "duplicate Content-Length accepted");
        // A space before the colon would hide a framing header from the checks: refused.
        for header in [
            "Transfer-Encoding : chunked",
            " Transfer-Encoding: chunked",
            "Bad Name: x",
            "X-Y\t: z",
        ] {
            ensure!(
                request(address, format!("{base}/0 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n{header}\r\n\r\nx")).await.is_err(),
                "header line {header:?} accepted"
            );
        }
        for host in [
            "user@localhost",
            "localhost:0",
            "localhost:65536",
            "bad host",
            "host/path",
            "host?query",
        ] {
            ensure!(
                http_authority(host).is_err(),
                "invalid HTTP authority accepted: {host}"
            );
        }
        for host in ["localhost", "cdn.test:8443", "127.0.0.1:8080", "[::1]:8080"] {
            http_authority(host)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_tunnel_removes_session_and_allows_new_download() -> Result<()> {
        let (mut acceptor, address) = listener().await?;
        let id = session_id(None)?;
        let mut download = open_get(address, &id).await?;
        let accepted = acceptor.accept().await?;
        drop(accepted);
        // Cancellation must close the original HTTP response and remove its
        // registry entry, so this ID can open a new download immediately.
        ensure!(
            timeout(Duration::from_secs(2), download.read_u8())
                .await?
                .is_err(),
            "cancelled bridge retained network task"
        );
        let _download = timeout(Duration::from_secs(2), open_get(address, &id)).await??;
        let _accepted = timeout(Duration::from_secs(2), acceptor.accept()).await??;
        Ok(())
    }

    #[tokio::test]
    async fn packet_worker_honors_proxy_connection_close_and_empty_chunked_ack() -> Result<()> {
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let id = session_id(None)?;
        let expected_id = id.clone();
        let server = tokio::spawn(async move {
            for sequence in 0..3 {
                let mut stream: BoxIo = Box::new(socket.accept().await?.0);
                let header = read_headers(&mut stream).await?;
                let parts: Vec<_> = header.first.split(' ').collect();
                ensure!(
                    parts.len() == 3
                        && parts[0] == "POST"
                        && request_path(parts[1])? == format!("/tunnel/{expected_id}/{sequence}"),
                    "proxy saw wrong packet sequence"
                );
                let size = if sequence == 2 { 0 } else { 3 };
                ensure!(
                    header.value("content-length") == Some(size.to_string().as_str()),
                    "proxy saw wrong packet length"
                );
                let mut body = vec![0; size];
                stream.read_exact(&mut body).await?;
                stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\nConnection: close\r\n\r\n0;complete=yes\r\nAck: empty\r\n\r\n").await?;
                stream.flush().await?;
            }
            anyhow::Ok(())
        });
        let path: ClientPath = serde_json::from_value(
            serde_json::json!({"addr":address.to_string(),"transport":"xhttp","server_public_key":"01".repeat(32),"xhttp":{"mode":"packet-up","host":"localhost"}}),
        )?;
        let (sender, receiver) = mpsc::channel(3);
        for (sequence, body) in [
            (0, b"one".as_slice()),
            (1, b"two".as_slice()),
            (2, b"".as_slice()),
        ] {
            sender
                .send(Packet {
                    sequence,
                    body: body.to_vec(),
                })
                .await?;
        }
        drop(sender);
        timeout(
            Duration::from_secs(3),
            packet_worker(Arc::new(tokio::sync::Mutex::new(receiver)), path, id),
        )
        .await??;
        timeout(Duration::from_secs(3), server).await???;
        Ok(())
    }

    /// A reconnect into a server that accepts TCP but never answers the TLS handshake gives up
    /// after `dial_timeout` instead of stalling the upload.
    #[tokio::test]
    async fn a_reconnect_that_never_completes_gives_up_after_the_dial_timeout() -> Result<()> {
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let silent = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = socket.accept().await {
                held.push(stream);
            }
        });
        let path: ClientPath = serde_json::from_value(serde_json::json!({
            "addr": address.to_string(), "transport": "xhttps", "dial_timeout": 1,
            "server_public_key": "01".repeat(32),
            "xhttp": {"mode": "packet-up", "host": "localhost"}
        }))?;
        let (sender, receiver) = mpsc::channel(1);
        sender
            .send(Packet {
                sequence: 0,
                body: b"one".to_vec(),
            })
            .await?;
        let started = Instant::now();
        let result = timeout(
            Duration::from_secs(10),
            packet_worker(
                Arc::new(tokio::sync::Mutex::new(receiver)),
                path,
                session_id(None)?,
            ),
        )
        .await?;
        let error = result.expect_err("the reconnect must fail");
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
        assert!(started.elapsed() < Duration::from_secs(3));
        silent.abort();
        Ok(())
    }

    /// The server (or a proxy) closes a kept-open upload connection while it is idle: the next
    /// packet must go out on a new connection instead of ending the session.
    #[tokio::test]
    async fn a_closed_keep_alive_connection_is_replaced_not_fatal() -> Result<()> {
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let id = session_id(None)?;
        let server = tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let mut stream: BoxIo = Box::new(socket.accept().await?.0);
                let header = read_headers(&mut stream).await?;
                let length: usize = header.value("content-length").unwrap_or("0").parse()?;
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await?;
                seen.push(header.first.clone());
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                    )
                    .await?;
                stream.flush().await?;
                // The connection is closed although the client was told to keep it.
                drop(stream);
            }
            anyhow::Ok(seen)
        });
        let path: ClientPath = serde_json::from_value(
            serde_json::json!({"addr":address.to_string(),"transport":"xhttp","server_public_key":"01".repeat(32),"xhttp":{"mode":"packet-up","host":"localhost"}}),
        )?;
        let (sender, receiver) = mpsc::channel(3);
        let worker = tokio::spawn(packet_worker(
            Arc::new(tokio::sync::Mutex::new(receiver)),
            path,
            id.clone(),
        ));
        sender
            .send(Packet {
                sequence: 0,
                body: b"one".to_vec(),
            })
            .await?;
        // Let the server close the first connection before the second packet is sent.
        tokio::time::sleep(Duration::from_millis(300)).await;
        sender
            .send(Packet {
                sequence: 1,
                body: b"two".to_vec(),
            })
            .await?;
        let seen = timeout(Duration::from_secs(5), server).await???;
        ensure!(
            seen.len() == 2 && seen[1].contains("/1 "),
            "the second packet did not arrive on a new connection: {seen:?}"
        );
        drop(sender);
        timeout(Duration::from_secs(5), worker).await???;
        Ok(())
    }

    #[test]
    fn padding_bounds_and_http_header_injection_are_rejected() -> Result<()> {
        let options = XhttpOptions {
            pad_min: 8,
            pad_max: 48,
            ..XhttpOptions::default()
        };
        for _ in 0..64 {
            let url = pad_url("/tunnel/session/0", &options)?;
            ensure!(
                request_path(&url)? == "/tunnel/session/0",
                "padding changed tunnel route"
            );
            let padding = url.split_once("?v=").context("padding missing")?.1;
            ensure!(
                (8..=48).contains(&padding.len())
                    && padding.bytes().all(|b| b.is_ascii_alphanumeric()),
                "padding outside bounds"
            );
        }
        let disabled = XhttpOptions {
            pad_min: 0,
            pad_max: 0,
            ..XhttpOptions::default()
        };
        ensure!(
            pad_url("/tunnel/session/0", &disabled)? == "/tunnel/session/0",
            "disabled padding added query"
        );
        for (min, max) in [(49, 48), (0, 4097)] {
            let bad = XhttpOptions {
                pad_min: min,
                pad_max: max,
                ..XhttpOptions::default()
            };
            ensure!(
                pad_url("/route", &bad).is_err(),
                "invalid padding bounds accepted"
            );
        }
        for url in [
            "/route?unknown=1",
            "/route?v=pad&other=2",
            "/route?v=bad%0d%0a",
            "/route#fragment",
        ] {
            ensure!(request_path(url).is_err(), "malformed query accepted");
        }
        ensure!(
            request_path(&format!("/route?v={}", "x".repeat(4097))).is_err(),
            "unbounded query accepted"
        );
        for value in ["", "agent\r\nInjected: yes", "agent\tother", "🙂"] {
            ensure!(user_agent(value).is_err(), "unsafe User-Agent accepted");
        }
        user_agent("eztunnel")?;
        Ok(())
    }
}
