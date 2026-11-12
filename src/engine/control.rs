//! Local control channel of a running tunnel: live status and speed tests.
//!
//! The service listens on a Unix socket given in `EZTUNNEL_CONTROL` (the manager sets it to a
//! private runtime directory). Each request is one JSON line, each answer one JSON line:
//! `{"cmd":"status"}` and `{"cmd":"speedtest","direction":"down"|"up","bytes":N,"streams":K}`.
//!
//! A speed test opens ordinary tunnel streams to a reserved target that the client side
//! answers itself: it sends N bytes (download) or reads them (upload). Nothing leaves the two
//! servers, and the client's `allowed_targets` are not involved.
use super::{Frame, Pool, Session, StreamGuard, Tuning, await_open};
use crate::stats::Stats;
use crate::wire::{DATA_SIZE, StreamKind};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
    sync::mpsc,
    time::timeout,
};

const TARGET_SUFFIX: &str = ".speedtest.eztunnel.invalid:9";
/// Largest speed test, so a mistyped request cannot run for hours.
const MAX_TEST_BYTES: u64 = 1 << 30;

/// How long a client may take to send its request line, and how many requests are served at once.
/// The socket is only open to root and the service account, so these only keep a stuck local
/// client (a script that connected and never wrote) from holding a task and a descriptor for ever.
/// They belong to the local control protocol, not to the tunnel, so they are not settings.
const REQUEST_WAIT: Duration = Duration::from_secs(5);
const MAX_REQUESTS: usize = 16;

/// What `serve` allows a client (tests use smaller values).
#[derive(Clone, Copy)]
struct Limits {
    request_wait: Duration,
    max_requests: usize,
}

/// A whole number from the request, `default` when the key is absent. Anything else (a string,
/// a fraction, a negative number) is refused instead of silently becoming the default.
fn whole_number(request: &Value, key: &str, default: u64) -> Result<u64> {
    match request.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value
            .as_u64()
            .with_context(|| format!("{key} must be a whole number")),
    }
}

/// The reserved target of a speed test stream: ("down" or "up", bytes).
pub(super) fn speedtest_target(target: &str) -> Option<(bool, u64)> {
    let name = target.strip_suffix(TARGET_SUFFIX)?;
    let (direction, bytes) = name.split_once('.')?;
    let bytes: u64 = bytes.parse().ok().filter(|b| *b <= MAX_TEST_BYTES)?;
    match direction {
        "down" => Some((true, bytes)),
        "up" => Some((false, bytes)),
        _ => None,
    }
}

/// Client side: answers one speed test stream.
pub(super) async fn answer_speedtest(
    session: Arc<Session>,
    id: u32,
    mut rx: mpsc::Receiver<Frame>,
    download: bool,
    bytes: u64,
) -> Result<()> {
    session.send(Frame::Opened { id }).await?;
    session.open_window(id).await?;
    if download {
        let chunk = vec![0u8; DATA_SIZE];
        let mut left = bytes;
        while left > 0 {
            let size = left.min(DATA_SIZE as u64) as usize;
            let sending=session.send_data(id, chunk[..size].to_vec());tokio::pin!(sending);
            loop{tokio::select!{
                result=&mut sending=>{result?;break;}
                // C10: a delivered Close/Error (or a closed stream) cancels a producer that is
                // waiting for credit. Eof is the requester's half-close: it still reads.
                frame=rx.recv()=>match frame{
                    Some(Frame::Close{..}|Frame::Error{..})|None=>return Ok(()),
                    _=>{},
                }
            }}
            left -= size as u64;
        }
        session.send(Frame::Eof { id }).await?;
        // Wait until the server closes, so the stream is not torn down mid-flight.
        while let Some(frame) = rx.recv().await {
            if matches!(frame, Frame::Close { .. } | Frame::Error { .. }) {
                break;
            }
        }
    } else {
        let mut received: u64 = 0;
        loop {
            match rx.recv().await {
                Some(Frame::Data { data, .. }) => {
                    received += data.len() as u64;
                    session.send(Frame::Credit { id, frames: 1 }).await?;
                }
                Some(Frame::Eof { .. }) => break,
                Some(Frame::Close { .. } | Frame::Error { .. }) | None => {
                    bail!("speed test stream closed early")
                }
                Some(_) => {}
            }
        }
        // Acknowledge with the byte count; the server stops its clock on this.
        session
            .send_data(id, received.to_be_bytes().to_vec())
            .await?;
        session.send(Frame::Eof { id }).await?;
    }
    Ok(())
}

/// Server side: one speed test stream. Returns the bytes moved.
async fn one_stream(pool: &Pool, download: bool, bytes: u64, tuning: Tuning) -> Result<u64> {
    let session = pool
        .pick()
        .context("the tunnel is not connected to the other server")?;
    let (id, mut rx) = session.register(None)?;
    let _guard = StreamGuard {
        session: session.clone(),
        id,
    };
    let direction = if download { "down" } else { "up" };
    session
        .send(Frame::Open {
            id,
            kind: StreamKind::Tcp,
            target: format!("{direction}.{bytes}{TARGET_SUFFIX}"),
            proxy: None,
        })
        .await?;
    await_open(&mut rx, tuning.open).await.context(
        "the other server did not answer the speed test (it needs EZTunnel 0.6 or newer)",
    )?;
    session.open_window(id).await?;
    let mut moved: u64 = 0;
    if download {
        loop {
            match rx.recv().await {
                Some(Frame::Data { data, .. }) => {
                    moved += data.len() as u64;
                    session.send(Frame::Credit { id, frames: 1 }).await?;
                }
                Some(Frame::Eof { .. }) => break,
                Some(Frame::Close { .. } | Frame::Error { .. }) | None => {
                    bail!("speed test stream closed early")
                }
                Some(_) => {}
            }
        }
    } else {
        let chunk = vec![0u8; DATA_SIZE];
        let mut left = bytes;
        while left > 0 {
            let size = left.min(DATA_SIZE as u64) as usize;
            session.send_data(id, chunk[..size].to_vec()).await?;
            left -= size as u64;
        }
        session.send(Frame::Eof { id }).await?;
        loop {
            match rx.recv().await {
                Some(Frame::Data { data, .. }) => {
                    if data.len() == 8 {
                        moved = u64::from_be_bytes(data[..8].try_into()?);
                    }
                    session.send(Frame::Credit { id, frames: 1 }).await?;
                }
                Some(Frame::Eof { .. }) => break,
                Some(Frame::Close { .. } | Frame::Error { .. }) | None => {
                    bail!("speed test stream closed early")
                }
                Some(_) => {}
            }
        }
    }
    let _ = session.send(Frame::Close { id }).await;
    Ok(moved)
}

async fn speedtest(pool: Arc<Pool>, request: &Value, tuning: Tuning) -> Result<Value> {
    let download = match request["direction"].as_str() {
        Some("down") => true,
        Some("up") => false,
        _ => bail!("direction must be down or up"),
    };
    let bytes = whole_number(request, "bytes", 20 << 20)?;
    let streams = whole_number(request, "streams", 1)?;
    ensure!(
        (1024..=MAX_TEST_BYTES).contains(&bytes),
        "bytes must be 1 KiB..1 GiB"
    );
    ensure!((1..=16).contains(&streams), "streams must be 1..16");
    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..streams {
        let pool = pool.clone();
        tasks.spawn(async move { one_stream(&pool, download, bytes / streams, tuning).await });
    }
    let mut moved = 0;
    while let Some(result) = tasks.join_next().await {
        moved += result.context("speed test task failed")??;
    }
    let seconds = started.elapsed().as_secs_f64().max(1e-6);
    Ok(json!({
        "ok": true,
        "direction": if download { "down" } else { "up" },
        "streams": streams,
        "bytes": moved,
        "seconds": seconds,
        "bytes_per_second": moved as f64 / seconds,
    }))
}

fn status(stats: &Stats, server: bool) -> Value {
    use std::sync::atomic::Ordering::Relaxed;
    let rtt: Vec<f64> = stats
        .rtt_samples()
        .into_iter()
        .map(|micros| micros as f64 / 1000.0)
        .collect();
    json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "role": if server { "server" } else { "client" },
        "uptime_sec": stats.uptime().as_secs(),
        "sessions": stats.sessions.load(Relaxed),
        "connects": stats.sessions_total.load(Relaxed),
        "streams": stats.streams.load(Relaxed),
        "streams_total": stats.streams_total.load(Relaxed),
        "refused": stats.streams_refused.load(Relaxed),
        "rejected": stats.connections_rejected.load(Relaxed),
        "udp_dropped": stats.udp_dropped.load(Relaxed),
        "bytes_to_peer": stats.bytes_to_peer.load(Relaxed),
        "bytes_from_peer": stats.bytes_from_peer.load(Relaxed),
        "pings": stats.pings.load(Relaxed),
        "pongs": stats.pongs.load(Relaxed),
        "pings_lost": stats.pings_lost.load(Relaxed),
        "window_frames_used": stats.window_budget.used(),
        "window_frames_limit": stats.window_budget.limit(),
        "rtt_ms": rtt,
        "transport_extensions":crate::transport_metrics::snapshot(),
    })
}

/// Tells a client that all places are taken. The request it already sent is read (and thrown away)
/// first: closing a socket with unread data resets the connection and the client would never see
/// the answer. A client that sends nothing is let go after a moment.
async fn refuse(mut stream: tokio::net::UnixStream) {
    let _ = stream
        .write_all(b"{\"ok\":false,\"error\":\"too many requests at once\"}\n")
        .await;
    let mut ignored = [0u8; 4096];
    let _ = timeout(Duration::from_millis(300), stream.read(&mut ignored)).await;
    let _ = stream.shutdown().await;
}

/// Serves the control socket until the tunnel stops.
pub(super) async fn serve(
    path: &Path,
    pool: Option<Arc<Pool>>,
    stats: Arc<Stats>,
    tuning: Tuning,
    gaming:Option<Arc<crate::gaming::Hub>>,
) -> Result<()> {
    let limits = Limits {
        request_wait: REQUEST_WAIT,
        max_requests: MAX_REQUESTS,
    };
    serve_with_gaming(path, pool, stats, tuning, limits,gaming).await
}

#[cfg(test)]
async fn serve_with(
    path: &Path,
    pool: Option<Arc<Pool>>,
    stats: Arc<Stats>,
    tuning: Tuning,
    limits: Limits,
) -> Result<()> {
    serve_with_gaming(path,pool,stats,tuning,limits,None).await
}

async fn serve_with_gaming(
    path:&Path,pool:Option<Arc<Pool>>,stats:Arc<Stats>,tuning:Tuning,limits:Limits,
    gaming:Option<Arc<crate::gaming::Hub>>,
) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("open the control socket {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    // Requests live in a set, so stopping the tunnel also stops a running speed test.
    let mut requests = tokio::task::JoinSet::new();
    // Clients turned away while all places are taken; each lives a moment (see `refuse`).
    let mut refusals = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            Some(_) = requests.join_next(), if !requests.is_empty() => continue,
            Some(_) = refusals.join_next(), if !refusals.is_empty() => continue,
        };
        let (stream, _) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%error, "control socket accept failed");
                continue;
            }
        };
        if requests.len() >= limits.max_requests {
            if refusals.len() < limits.max_requests {
                refusals.spawn(refuse(stream));
            }
            continue;
        }
        let (pool, stats,gaming) = (pool.clone(), stats.clone(),gaming.clone());
        requests.spawn(async move {
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            let mut reader = BufReader::new(read.take(4096));
            // A client that sends nothing is let go; a request that follows is not limited
            // (a speed test takes as long as it takes).
            if !matches!(
                timeout(limits.request_wait, reader.read_line(&mut line)).await,
                Ok(Ok(_))
            ) {
                return;
            }
            let answer = match serde_json::from_str::<Value>(&line) {
                Err(_) => json!({"ok": false, "error": "requests are one JSON object per line"}),
                Ok(request) => match request["cmd"].as_str() {
                    Some("status") => status(&stats, pool.is_some()),
                    Some("gaming-rebind")=>{
                        let parse=||->Result<(std::net::SocketAddr,Option<std::net::SocketAddr>)>{
                            let bind=request["bind"].as_str().context("gaming-rebind needs bind IP:port")?.parse()?;
                            let advertise=request.get("advertise").and_then(Value::as_str).map(str::parse).transpose()?;Ok((bind,advertise))
                        };
                        match (gaming,parse()) {
                            (Some(hub),Ok((bind,advertise)))=>match hub.rebind(bind,advertise).await{Ok(local)=>json!({"ok":true,"local":local.to_string(),"reauthentication_required":true}),Err(error)=>json!({"ok":false,"error":format!("{error:#}")})},
                            (None,_)=>json!({"ok":false,"error":"gaming is disabled"}),
                            (_,Err(error))=>json!({"ok":false,"error":format!("{error:#}")}),
                        }
                    }
                    Some("speedtest") => match pool {
                        None => json!({"ok": false,
                            "error": "run the speed test on the server side (the Iran server)"}),
                        Some(pool) => speedtest(pool, &request, tuning).await.unwrap_or_else(
                            |error| json!({"ok": false, "error": format!("{error:#}")}),
                        ),
                    },
                    _ => json!({"ok": false, "error": "unknown command"}),
                },
            };
            let mut text = answer.to_string();
            text.push('\n');
            let _ = write.write_all(text.as_bytes()).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stopping_the_server_also_ends_requests_still_being_served() {
        use tokio::net::UnixStream;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sock");
        let tuning = Tuning {
            connect: std::time::Duration::from_secs(1),
            open: std::time::Duration::from_secs(1),
            udp_idle: std::time::Duration::from_secs(1),
            tcp_idle: None,
            stream_queue: 32,
            early_data: true,
        };
        let server = {
            let path = path.clone();
            tokio::spawn(
                async move { serve(&path, None, Arc::new(Stats::default()), tuning,None).await },
            )
        };
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // A client that connects and never sends its request keeps a request task waiting.
        let mut idle = UnixStream::connect(&path).await.unwrap();
        // Another client gets its answer normally.
        let mut asking = UnixStream::connect(&path).await.unwrap();
        asking.write_all(b"{\"cmd\":\"status\"}\n").await.unwrap();
        let mut answer = String::new();
        BufReader::new(&mut asking)
            .read_line(&mut answer)
            .await
            .unwrap();
        assert!(answer.contains("\"ok\":true"), "{answer}");
        // Stopping the server drops the waiting request: its connection closes.
        server.abort();
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(std::time::Duration::from_secs(2), idle.read(&mut byte))
            .await
            .expect("the idle connection should be closed once the server stops");
        assert_eq!(closed.unwrap(), 0);
    }

    fn short_limits(max_requests: usize) -> Limits {
        Limits {
            request_wait: Duration::from_millis(300),
            max_requests,
        }
    }

    fn quick_tuning() -> Tuning {
        Tuning {
            connect: Duration::from_secs(1),
            open: Duration::from_secs(1),
            udp_idle: Duration::from_secs(1),
            tcp_idle: None,
            stream_queue: 32,
            early_data: true,
        }
    }

    async fn started(
        directory: &Path,
        limits: Limits,
    ) -> (tokio::task::JoinHandle<Result<()>>, std::path::PathBuf) {
        let path = directory.join("control.sock");
        let server = {
            let path = path.clone();
            tokio::spawn(async move {
                serve_with(
                    &path,
                    None,
                    Arc::new(Stats::default()),
                    quick_tuning(),
                    limits,
                )
                .await
            })
        };
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (server, path)
    }

    async fn ask(path: &Path, text: &str) -> String {
        use tokio::net::UnixStream;
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(text.as_bytes()).await.unwrap();
        let mut answer = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut answer)
            .await
            .unwrap();
        answer
    }

    #[tokio::test]
    async fn a_client_that_sends_nothing_is_let_go_and_others_are_still_served() {
        use tokio::net::UnixStream;
        let directory = tempfile::tempdir().unwrap();
        let (server, path) = started(directory.path(), short_limits(16)).await;
        let started_at = Instant::now();
        let mut silent = UnixStream::connect(&path).await.unwrap();
        // Served normally meanwhile.
        assert!(
            ask(&path, "{\"cmd\":\"status\"}\n")
                .await
                .contains("\"ok\":true")
        );
        // The silent connection is closed by the server after the wait, with no answer.
        let mut byte = [0u8; 1];
        let closed = timeout(Duration::from_secs(3), silent.read(&mut byte))
            .await
            .expect("the silent connection should be closed");
        assert_eq!(closed.unwrap(), 0);
        let waited = started_at.elapsed();
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_secs(2),
            "{waited:?}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn only_so_many_requests_are_served_at_once() {
        use tokio::net::UnixStream;
        let directory = tempfile::tempdir().unwrap();
        let limits = Limits {
            request_wait: Duration::from_secs(30),
            max_requests: 2,
        };
        let (server, path) = started(directory.path(), limits).await;
        let _first = UnixStream::connect(&path).await.unwrap();
        let _second = UnixStream::connect(&path).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The third gets an answer that says why, instead of waiting behind the two.
        let answer = timeout(Duration::from_secs(2), ask(&path, "{\"cmd\":\"status\"}\n"))
            .await
            .expect("a refused request is answered at once");
        assert!(answer.contains("too many requests"), "{answer}");
        // When one of them goes away there is room again.
        drop(_first);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            ask(&path, "{\"cmd\":\"status\"}\n")
                .await
                .contains("\"ok\":true")
        );
        server.abort();
    }

    #[test]
    fn speed_test_numbers_must_be_whole_numbers() {
        let request = json!({"bytes": 1024, "streams": "four", "fraction": 1.5, "negative": -1, "none": null});
        assert_eq!(whole_number(&request, "bytes", 7).unwrap(), 1024);
        assert_eq!(whole_number(&request, "missing", 7).unwrap(), 7);
        assert_eq!(whole_number(&request, "none", 7).unwrap(), 7);
        for key in ["streams", "fraction", "negative"] {
            let error = whole_number(&request, key, 7).unwrap_err().to_string();
            assert!(error.contains("must be a whole number"), "{key}: {error}");
        }
    }

    #[test]
    fn speedtest_targets_are_recognised_and_bounded() {
        assert_eq!(
            speedtest_target(&format!("down.1048576{TARGET_SUFFIX}")),
            Some((true, 1_048_576))
        );
        assert_eq!(
            speedtest_target(&format!("up.10{TARGET_SUFFIX}")),
            Some((false, 10))
        );
        assert_eq!(
            speedtest_target(&format!("up.{}{TARGET_SUFFIX}", u64::MAX)),
            None
        );
        assert_eq!(speedtest_target("down.10.example.com:9"), None);
        assert_eq!(
            speedtest_target(&format!("sideways.10{TARGET_SUFFIX}")),
            None
        );
    }
}
