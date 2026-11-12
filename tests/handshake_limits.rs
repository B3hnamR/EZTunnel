//! Connections that have not finished the key handshake must not use up the slots reserved for
//! authenticated sessions, and one source address must not be able to hold more than its share.

use std::{net::SocketAddr, path::Path, time::Duration};

use anyhow::{Context, Result};
use eztunnel::{config, engine};
use serde_json::{Value, json};
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

/// Opens a TCP connection to `target` from the given loopback source address and sends nothing.
async fn idle_connection(source: &str, target: SocketAddr) -> Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(format!("{source}:0").parse()?)?;
    Ok(socket.connect(target).await?)
}

/// True when the server has closed this connection (EOF or reset) within a short time.
async fn closed_by_peer(stream: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    match timeout(Duration::from_millis(300), stream.read(&mut byte)).await {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(_)) => false,
        Err(_) => false,
    }
}

async fn echo_roundtrip(addr: SocketAddr) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(b"limit check").await?;
    let mut response = [0; 11];
    stream.read_exact(&mut response).await?;
    anyhow::ensure!(&response == b"limit check", "payload changed");
    Ok(())
}

async fn forwarding_works_within(addr: SocketAddr, limit: Duration) -> bool {
    timeout(limit, async {
        loop {
            if matches!(
                timeout(Duration::from_millis(750), echo_roundtrip(addr)).await,
                Ok(Ok(()))
            ) {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok()
}

struct Setup {
    _directory: tempfile::TempDir,
    _echo: Task,
    _server: Task,
    tunnel: SocketAddr,
    map: SocketAddr,
    client_config: std::path::PathBuf,
}

/// Starts an echo service and a server. The client is *not* started, so the test decides when.
async fn setup(server_extra: Value) -> Result<Setup> {
    let directory = tempfile::tempdir()?;
    let (server_private, server_public) =
        config::generate_keypair(&directory.path().join("server"))?;
    let (client_private, client_public) =
        config::generate_keypair(&directory.path().join("client"))?;
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let target = echo.local_addr()?;
    let echo_task = Task(tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    }));
    let reservations = [
        TcpListener::bind("127.0.0.1:0").await?,
        TcpListener::bind("127.0.0.1:0").await?,
    ];
    let tunnel = reservations[0].local_addr()?;
    let map = reservations[1].local_addr()?;
    drop(reservations);

    let mut server = json!({
        "mode": "server", "private_key_file": server_private,
        "peer_public_keys": [client_public],
        "listeners": [{"addr": tunnel.to_string(), "maps": [
            {"type": "tcp", "bind": map.to_string(), "target": target.to_string()}
        ]}],
        "heartbeat_sec": 1, "dead_timeout_sec": 3,
    });
    for (key, value) in server_extra
        .as_object()
        .context("extra must be an object")?
    {
        server[key] = value.clone();
    }
    let server_path = directory.path().join("server.json");
    std::fs::write(&server_path, serde_json::to_vec(&server)?)?;
    let client_path = directory.path().join("client.json");
    std::fs::write(
        &client_path,
        serde_json::to_vec(&json!({
            "mode": "client", "private_key_file": client_private,
            "paths": [{"addr": tunnel.to_string(), "server_public_key": server_public,
                       "retry_interval": 1, "dial_timeout": 3}],
            "allowed_targets": [target.to_string()],
            "heartbeat_sec": 1, "dead_timeout_sec": 3,
        }))?,
    )?;
    let server_task = run_engine(&server_path)?;
    sleep(Duration::from_millis(300)).await;
    Ok(Setup {
        _directory: directory,
        _echo: echo_task,
        _server: server_task,
        tunnel,
        map,
        client_config: client_path,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_connections_do_not_block_a_real_client() -> Result<()> {
    // Only two authenticated sessions are allowed, but six unauthenticated connections sit idle.
    let setup = setup(json!({"max_connections": 2})).await?;
    let mut idle = Vec::new();
    for _ in 0..6 {
        idle.push(idle_connection("127.0.0.2", setup.tunnel).await?);
    }
    let _client = run_engine(&setup.client_config)?;
    anyhow::ensure!(
        forwarding_works_within(setup.map, Duration::from_secs(5)).await,
        "a real client could not connect while idle connections held the slots"
    );
    drop(idle);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_source_address_is_capped() -> Result<()> {
    let setup = setup(json!({})).await?; // defaults: 16 pending handshakes per source address
    let mut idle = Vec::new();
    for _ in 0..40 {
        idle.push(idle_connection("127.0.0.3", setup.tunnel).await?);
    }
    sleep(Duration::from_millis(500)).await;
    let mut still_open = 0;
    for stream in &mut idle {
        if !closed_by_peer(stream).await {
            still_open += 1;
        }
    }
    anyhow::ensure!(
        (1..=16).contains(&still_open),
        "expected at most 16 held connections from one address, found {still_open}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_pending_cap_is_configurable() -> Result<()> {
    let setup = setup(json!({"max_pending_handshakes": 5, "max_pending_per_ip": 5})).await?;
    let mut idle = Vec::new();
    for source in ["127.0.0.4", "127.0.0.5", "127.0.0.6"] {
        for _ in 0..5 {
            idle.push(idle_connection(source, setup.tunnel).await?);
        }
    }
    sleep(Duration::from_millis(500)).await;
    let mut still_open = 0;
    for stream in &mut idle {
        if !closed_by_peer(stream).await {
            still_open += 1;
        }
    }
    anyhow::ensure!(
        (1..=5).contains(&still_open),
        "expected at most 5 held connections in total, found {still_open}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_limit_values_are_rejected() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (private, _) = config::generate_keypair(&directory.path().join("server"))?;
    let (_, client_public) = config::generate_keypair(&directory.path().join("client"))?;
    for extra in [
        json!({"max_pending_handshakes": 0}),
        json!({"max_pending_handshakes": 100000}),
        json!({"max_pending_per_ip": 0}),
    ] {
        let mut value = json!({
            "mode": "server", "private_key_file": private,
            "peer_public_keys": [client_public],
            "listeners": [{"addr": "127.0.0.1:0"}],
        });
        for (key, v) in extra.as_object().unwrap() {
            value[key] = v.clone();
        }
        let path = directory.path().join("bad.json");
        std::fs::write(&path, serde_json::to_vec(&value)?)?;
        anyhow::ensure!(
            config::Config::load(&path).is_err(),
            "config {extra} should have been rejected"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_timeout_follows_the_setting() -> Result<()> {
    let setup = setup(json!({"timeouts": {"handshake_sec": 1}})).await?;
    let mut idle = idle_connection("127.0.0.7", setup.tunnel).await?;
    // The default is 10 seconds; with the setting at 1 the server must hang up within a few.
    let closed = timeout(Duration::from_secs(4), async {
        let mut byte = [0u8; 1];
        matches!(idle.read(&mut byte).await, Ok(0) | Err(_))
    })
    .await;
    anyhow::ensure!(
        matches!(closed, Ok(true)),
        "server did not close the idle connection after the configured 1 second"
    );
    Ok(())
}
