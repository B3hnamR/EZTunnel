//! A recorded first handshake message, replayed by someone else, must not become a session users
//! are sent to.
use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use eztunnel::{config, engine};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

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

async fn roundtrip(addr: SocketAddr) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(b"tunnel roundtrip").await?;
    let mut response = [0; 16];
    stream.read_exact(&mut response).await?;
    ensure!(&response == b"tunnel roundtrip", "payload changed");
    Ok(())
}

/// Forwards bytes between a client and the real server and keeps the bytes the client sent before
/// the server's first reply: the first handshake message.
async fn recording_proxy(
    listener: TcpListener,
    server: SocketAddr,
    first_message: Arc<Mutex<Vec<u8>>>,
) {
    let recorded = Arc::new(AtomicBool::new(false));
    while let Ok((client, _)) = listener.accept().await {
        let first_message = first_message.clone();
        let recorded = recorded.clone();
        tokio::spawn(async move {
            let Ok(upstream) = TcpStream::connect(server).await else {
                return;
            };
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = upstream.into_split();
            let replied = Arc::new(AtomicBool::new(false));
            let marker = replied.clone();
            let down = tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(count) = server_read.read(&mut buffer).await {
                    if count == 0 || client_write.write_all(&buffer[..count]).await.is_err() {
                        break;
                    }
                    marker.store(true, Ordering::SeqCst);
                }
            });
            let mut buffer = [0u8; 4096];
            while let Ok(count) = client_read.read(&mut buffer).await {
                if count == 0 {
                    break;
                }
                // Only the first connection is recorded, and only up to the server's reply.
                if !replied.load(Ordering::SeqCst) && !recorded.load(Ordering::SeqCst) {
                    first_message
                        .lock()
                        .unwrap()
                        .extend_from_slice(&buffer[..count]);
                }
                if server_write.write_all(&buffer[..count]).await.is_err() {
                    break;
                }
            }
            recorded.store(true, Ordering::SeqCst);
            down.abort();
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_first_handshake_message_never_gets_user_traffic() -> Result<()> {
    timeout(Duration::from_secs(60), async {
        let directory = tempfile::tempdir()?;
        let (server_private, server_public) =
            config::generate_keypair(&directory.path().join("server"))?;
        let (client_private, client_public) =
            config::generate_keypair(&directory.path().join("client"))?;
        let echo = TcpListener::bind("127.0.0.1:0").await?;
        let target = echo.local_addr()?;
        let _echo_task = Task(tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        }));
        let mut reservations = Vec::new();
        for _ in 0..3 {
            reservations.push(TcpListener::bind("127.0.0.1:0").await?);
        }
        let tunnel_addr = reservations[0].local_addr()?;
        let map_addr = reservations[1].local_addr()?;
        let proxy_addr = reservations[2].local_addr()?;
        let proxy_socket = reservations.pop().unwrap();
        drop(reservations);

        let server_path = directory.path().join("server.json");
        let client_path = directory.path().join("client.json");
        std::fs::write(
            &server_path,
            serde_json::to_vec(&json!({
                "mode": "server", "private_key_file": server_private,
                "peer_public_keys": [client_public],
                "listeners": [{"addr": tunnel_addr.to_string(), "maps": [
                    {"type":"tcp", "bind":map_addr.to_string(), "target":target.to_string()}
                ]}],
                "heartbeat_sec": 1, "dead_timeout_sec": 5,
                "timeouts": {"handshake_sec": 3},
            }))?,
        )?;
        std::fs::write(
            &client_path,
            serde_json::to_vec(&json!({
                "mode":"client", "private_key_file":client_private,
                "paths":[{"addr":proxy_addr.to_string(), "server_public_key":server_public,
                          "connection_pool":1, "retry_interval":1, "dial_timeout":2}],
                "allowed_targets":[target.to_string()],
                "heartbeat_sec": 1, "dead_timeout_sec": 5,
            }))?,
        )?;
        let first_message = Arc::new(Mutex::new(Vec::new()));
        let _proxy = Task(tokio::spawn(recording_proxy(
            proxy_socket,
            tunnel_addr,
            first_message.clone(),
        )));
        let _server = run_engine(&server_path)?;
        let _client = run_engine(&client_path)?;
        timeout(Duration::from_secs(20), async {
            loop {
                if matches!(
                    timeout(Duration::from_millis(750), roundtrip(map_addr)).await,
                    Ok(Ok(()))
                ) {
                    return;
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("the tunnel did not come up")?;

        // Someone who recorded the client's first message sends it again.
        let recorded = first_message.lock().unwrap().clone();
        ensure!(recorded.len() >= 32, "no handshake message was recorded");
        let mut replay = TcpStream::connect(tunnel_addr).await?;
        replay.write_all(&recorded).await?;
        // The server answers (it cannot tell the replay from a new client) and then waits.
        let mut answer = [0u8; 16];
        let _ = timeout(Duration::from_secs(2), replay.read(&mut answer)).await;

        // While the replay is connected, every user connection must still work and be quick:
        // none may be handed to the replayed session, which cannot answer.
        let started = Instant::now();
        for round in 0..8 {
            timeout(Duration::from_secs(2), roundtrip(map_addr))
                .await
                .with_context(|| format!("round {round} hung on a dead session"))?
                .with_context(|| format!("round {round} failed"))?;
        }
        ensure!(started.elapsed() < Duration::from_secs(10), "too slow");

        // The server gives up on the silent connection after the handshake time.
        let closed = timeout(Duration::from_secs(8), async {
            let mut buffer = [0u8; 64];
            loop {
                match replay.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
        .await;
        ensure!(
            closed.is_ok(),
            "the server kept the replayed connection open"
        );
        roundtrip(map_addr).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("replay scenario timed out")?
}
