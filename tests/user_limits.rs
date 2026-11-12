//! One source address cannot use up the stream slots of a public map, and connections that only
//! sit there are closed after `timeouts.tcp_idle_sec`.
use std::{net::SocketAddr, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use eztunnel::{config, engine};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
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

/// Connects from `source` and proves the connection works end to end.
async fn open_from(source: &str, map: SocketAddr) -> Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(format!("{source}:0").parse()?)?;
    let mut stream = socket.connect(map).await?;
    stream.write_all(b"ping").await?;
    let mut answer = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut answer))
        .await
        .context("no answer through the tunnel")??;
    ensure!(&answer == b"ping", "payload changed");
    Ok(stream)
}

/// True when the other end closes the connection within `wait`.
async fn gets_closed(stream: &mut TcpStream, wait: Duration) -> bool {
    let mut buffer = [0u8; 8];
    matches!(
        timeout(wait, stream.read(&mut buffer)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_address_cannot_fill_the_map_and_idle_connections_are_closed() -> Result<()> {
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
        for _ in 0..2 {
            reservations.push(TcpListener::bind("127.0.0.1:0").await?);
        }
        let tunnel_addr = reservations[0].local_addr()?;
        let map_addr = reservations[1].local_addr()?;
        drop(reservations);

        std::fs::write(
            directory.path().join("server.json"),
            serde_json::to_vec(&json!({
                "mode": "server", "private_key_file": server_private,
                "peer_public_keys": [client_public],
                "listeners": [{"addr": tunnel_addr.to_string(), "maps": [
                    {"type":"tcp", "bind":map_addr.to_string(), "target":target.to_string()}
                ]}],
                "heartbeat_sec": 1, "dead_timeout_sec": 5,
                "max_streams_per_ip": 2, "max_streams": 8,
                "timeouts": {"tcp_idle_sec": 4},
            }))?,
        )?;
        std::fs::write(
            directory.path().join("client.json"),
            serde_json::to_vec(&json!({
                "mode":"client", "private_key_file":client_private,
                "paths":[{"addr":tunnel_addr.to_string(), "server_public_key":server_public,
                          "connection_pool":1, "retry_interval":1, "dial_timeout":2}],
                "allowed_targets":[target.to_string()],
                "heartbeat_sec": 1, "dead_timeout_sec": 5,
            }))?,
        )?;
        let _server = run_engine(&directory.path().join("server.json"))?;
        let _client = run_engine(&directory.path().join("client.json"))?;
        timeout(Duration::from_secs(20), async {
            loop {
                if open_from("127.0.0.1", map_addr).await.is_ok() {
                    return;
                }
                sleep(Duration::from_millis(150)).await;
            }
        })
        .await
        .context("the tunnel did not come up")?;
        // Let the connection used above be released.
        sleep(Duration::from_millis(500)).await;

        // The limit is 2 per address, but only while the 8 slots are three quarters (6) full: one
        // address may use six slots while there is room ...
        let mut held = Vec::new();
        for _ in 0..6 {
            held.push(open_from("127.0.0.1", map_addr).await?);
        }
        // ... and then it is held to its limit (the server closes the connection at once) ...
        let mut seventh = TcpStream::connect(map_addr).await?;
        ensure!(
            gets_closed(&mut seventh, Duration::from_secs(2)).await,
            "a seventh connection from the same address was served"
        );
        // ... while another address, under its limit, still gets the last slots.
        let _other = open_from("127.0.0.2", map_addr)
            .await
            .context("a second address was refused because of the first")?;

        // The three held connections never send anything again: they are closed once they have
        // been idle for tcp_idle_sec, which frees the slots.
        for stream in &mut held {
            ensure!(
                gets_closed(stream, Duration::from_secs(10)).await,
                "an idle connection was kept open"
            );
        }
        sleep(Duration::from_millis(500)).await;
        open_from("127.0.0.1", map_addr)
            .await
            .context("the slots were not freed")?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("limits scenario timed out")?
}
