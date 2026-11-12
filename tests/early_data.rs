//! A new connection sends its data right behind the open request (`stream_early_data`), so the
//! first answer comes after one round trip between the servers instead of two. A proxy between
//! the two tunnel ends delays each direction by 50 ms (a 100 ms round trip).
use std::{
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use eztunnel::{config, engine};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout},
};

const DELAY: Duration = Duration::from_millis(50);

struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn run_engine(path: &Path) -> Result<Task> {
    let cfg = config::Config::load(path)?;
    Ok(Task(tokio::spawn(async move {
        if let Err(error) = engine::run(cfg).await {
            eprintln!("test engine stopped: {error:#}");
        }
    })))
}

/// Copies `from` to `to`, delivering every chunk `DELAY` after it was read, in order.
async fn delayed_copy(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
) {
    let (queue, mut ready) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    let writer = tokio::spawn(async move {
        while let Some((due, data)) = ready.recv().await {
            tokio::time::sleep_until(due.into()).await;
            if data.is_empty() {
                let _ = to.shutdown().await;
                return;
            }
            if to.write_all(&data).await.is_err() {
                return;
            }
        }
    });
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = from.read(&mut buffer).await.unwrap_or(0);
        let _ = queue.send((Instant::now() + DELAY, buffer[..count].to_vec()));
        if count == 0 {
            break;
        }
    }
    drop(queue);
    let _ = writer.await;
}

/// A TCP proxy to `upstream` that adds `DELAY` in each direction.
async fn delay_proxy(upstream: SocketAddr) -> Result<(SocketAddr, Task)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = Task(tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect(upstream).await else {
                    return;
                };
                let _ = (client.set_nodelay(true), server.set_nodelay(true));
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                tokio::join!(
                    delayed_copy(client_read, server_write),
                    delayed_copy(server_read, client_write)
                );
            });
        }
    }));
    Ok((address, task))
}

/// Echo service; closes its side after the client closed its sending side.
async fn echo() -> Result<(SocketAddr, Task)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = Task(tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                let _ = writer.shutdown().await;
            });
        }
    }));
    Ok((address, task))
}

/// Sends `bytes` of zeros to every client as fast as it can, then closes.
async fn source(bytes: usize) -> Result<(SocketAddr, Task)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = Task(tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if stream.read_exact(&mut first).await.is_err() {
                    return;
                }
                let block = vec![0u8; 64 * 1024];
                let mut left = bytes;
                while left > 0 {
                    let n = left.min(block.len());
                    if stream.write_all(&block[..n]).await.is_err() {
                        return;
                    }
                    left -= n;
                }
                let _ = stream.shutdown().await;
            });
        }
    }));
    Ok((address, task))
}

struct Pair {
    map: SocketAddr,
    _tasks: Vec<Task>,
}

/// A tunnel whose Iran side (where users connect) maps one port to `target` and has early data
/// on or off; `allowed` is what the foreign side may reach.
async fn pair(target: SocketAddr, early: bool, allowed: &str) -> Result<Pair> {
    let directory = tempfile::tempdir()?;
    let (server_private, server_public) = config::generate_keypair(&directory.path().join("s"))?;
    let (client_private, client_public) = config::generate_keypair(&directory.path().join("c"))?;
    let tunnel = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
    let map = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
    let (proxy, proxy_task) = delay_proxy(tunnel).await?;
    let server = directory.path().join("server.json");
    std::fs::write(
        &server,
        serde_json::to_vec(&json!({
            "mode": "server", "private_key_file": server_private,
            "peer_public_keys": [client_public],
            "listeners": [{"addr": tunnel.to_string(), "maps": [
                {"type": "tcp", "bind": map.to_string(), "target": target.to_string()}
            ]}],
            "stream_early_data": early,
            "stats_interval_sec": 0,
        }))?,
    )?;
    let client = directory.path().join("client.json");
    std::fs::write(
        &client,
        serde_json::to_vec(&json!({
            "mode": "client", "private_key_file": client_private,
            "paths": [{"addr": proxy.to_string(), "server_public_key": server_public,
                       "connection_pool": 1, "retry_interval": 1, "dial_timeout": 3}],
            "allowed_targets": [allowed],
            "stats_interval_sec": 0,
        }))?,
    )?;
    let tasks = vec![proxy_task, run_engine(&server)?, run_engine(&client)?];
    // Wait until the tunnel is up (a refused target still accepts the user's connection).
    sleep(Duration::from_millis(1500)).await;
    std::mem::forget(directory);
    Ok(Pair { map, _tasks: tasks })
}

/// Time from connecting to the map until the echo of a short request arrives.
async fn first_answer(map: SocketAddr) -> Result<Duration> {
    let started = Instant::now();
    let mut stream = TcpStream::connect(map).await?;
    stream.set_nodelay(true)?;
    stream.write_all(b"hello").await?;
    let mut answer = [0u8; 5];
    timeout(Duration::from_secs(5), stream.read_exact(&mut answer))
        .await
        .context("no answer")??;
    ensure!(&answer == b"hello");
    Ok(started.elapsed())
}

async fn median_first_answer(map: SocketAddr) -> Result<Duration> {
    // The first one also warms the session up.
    first_answer(map).await?;
    let mut times = Vec::new();
    for _ in 0..7 {
        times.push(first_answer(map).await?);
    }
    times.sort();
    Ok(times[times.len() / 2])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_connection_answers_after_one_round_trip_instead_of_two() -> Result<()> {
    let (target, _echo) = echo().await?;
    let rtt = DELAY * 2;
    let early = pair(target, true, &target.to_string()).await?;
    let fast = median_first_answer(early.map).await?;
    let waiting = pair(target, false, &target.to_string()).await?;
    let slow = median_first_answer(waiting.map).await?;
    eprintln!("first answer: early data {fast:?}, waiting for Opened {slow:?} (RTT {rtt:?})");
    ensure!(
        fast < rtt * 3 / 2,
        "early data took {fast:?}, more than 1.5 round trips"
    );
    ensure!(
        slow >= rtt * 19 / 10,
        "without early data only {slow:?}: the test path is wrong"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_data_keeps_order_half_close_and_large_first_writes() -> Result<()> {
    let (target, _echo) = echo().await?;
    let tunnel = pair(target, true, &target.to_string()).await?;
    // A request followed at once by the end of the sending side still gets its full answer.
    let mut stream = TcpStream::connect(tunnel.map).await?;
    stream.write_all(b"request-then-close").await?;
    stream.shutdown().await?;
    let mut answer = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut answer))
        .await
        .context("no answer after half close")??;
    ensure!(answer == b"request-then-close", "got {answer:?}");
    // 1 MiB written at once (far more than the 16 frames allowed before the far side connects)
    // is paced, not dropped, and comes back unchanged.
    let data: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();
    let stream = TcpStream::connect(tunnel.map).await?;
    let (mut reader, mut writer) = stream.into_split();
    let sent = data.clone();
    let send = tokio::spawn(async move {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    });
    let mut back = Vec::new();
    timeout(Duration::from_secs(20), reader.read_to_end(&mut back))
        .await
        .context("the large write did not come back")??;
    send.await??;
    ensure!(
        back == data,
        "the large write came back changed ({} bytes)",
        back.len()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_destination_closes_the_users_connection_promptly() -> Result<()> {
    let (target, _echo) = echo().await?;
    // The foreign side may only reach some other address.
    let tunnel = pair(target, true, "127.0.0.1:9").await?;
    let started = Instant::now();
    let mut stream = TcpStream::connect(tunnel.map).await?;
    stream.write_all(b"hello").await?;
    let mut buffer = [0u8; 16];
    let read = timeout(Duration::from_secs(5), stream.read(&mut buffer))
        .await
        .context("a refused destination left the connection open")?;
    ensure!(
        matches!(read, Ok(0) | Err(_)),
        "data came back from a refused destination"
    );
    ensure!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downloads_after_early_data_get_the_full_window() -> Result<()> {
    // 8 MiB at a 100 ms round trip: with the full window (64 frames = 1 MiB per round trip) that
    // takes about a second; stuck at the initial 16 frames it would take over three.
    let size = 8 << 20;
    let (target, _source) = source(size).await?;
    let tunnel = pair(target, true, &target.to_string()).await?;
    let started = Instant::now();
    let mut stream = TcpStream::connect(tunnel.map).await?;
    stream.write_all(b"x").await?;
    let mut total = 0usize;
    let mut buffer = vec![0u8; 64 * 1024];
    while total < size {
        let n = timeout(Duration::from_secs(10), stream.read(&mut buffer))
            .await
            .context("download stalled")??;
        ensure!(n > 0, "closed after {total} bytes");
        total += n;
    }
    let took = started.elapsed();
    eprintln!("8 MiB in {took:?}");
    ensure!(
        took < Duration::from_millis(2500),
        "download too slow ({took:?}): window not widened?"
    );
    Ok(())
}
