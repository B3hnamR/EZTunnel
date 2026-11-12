//! Many users at once: a thousand simultaneous connections through one tunnel must all work.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use eztunnel::{config, engine, stats::Stats};
use serde_json::json;
use std::sync::{Arc, atomic::Ordering::Relaxed};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{sleep, timeout},
};

const USERS: usize = 1000;
const PAYLOAD: usize = 8 * 1024;

async fn one_user(map: SocketAddr, id: usize) -> Result<()> {
    let mut stream = timeout(Duration::from_secs(30), TcpStream::connect(map)).await??;
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| ((i + id) % 251) as u8).collect();
    let mut echoed = vec![0; PAYLOAD];
    timeout(Duration::from_secs(60), async {
        stream.write_all(&payload).await?;
        stream.read_exact(&mut echoed).await
    })
    .await??;
    anyhow::ensure!(echoed == payload, "user {id} got different bytes back");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_thousand_simultaneous_users() -> Result<()> {
    // This one process holds both ends of every connection, so it needs many descriptors.
    let limit = eztunnel::sys::raise_open_file_limit(None)?;
    anyhow::ensure!(
        limit >= 8192,
        "open-file limit {limit} too low for this test"
    );

    let directory = tempfile::tempdir()?;
    let (server_private, server_public) =
        config::generate_keypair(&directory.path().join("server"))?;
    let (client_private, client_public) =
        config::generate_keypair(&directory.path().join("client"))?;
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let target = echo.local_addr()?;
    let echo_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    let reservations = [
        TcpListener::bind("127.0.0.1:0").await?,
        TcpListener::bind("127.0.0.1:0").await?,
    ];
    let tunnel = reservations[0].local_addr()?;
    let map = reservations[1].local_addr()?;
    drop(reservations);

    let server_path = directory.path().join("server.json");
    let client_path = directory.path().join("client.json");
    std::fs::write(
        &server_path,
        serde_json::to_vec(&json!({
            "mode": "server", "private_key_file": server_private,
            "peer_public_keys": [client_public],
            "listeners": [{"addr": tunnel.to_string(), "maps": [
                {"type": "tcp", "bind": map.to_string(), "target": target.to_string()}
            ]}],
            "max_streams": 1024, "max_connections": 8,
            // All the test users come from 127.0.0.1. The per-address limit (512 once the pool
            // is 75 % full) has its own test; here it would refuse users whenever fewer than all
            // four sessions carry them.
            "max_streams_per_ip": 0,
        }))?,
    )?;
    std::fs::write(
        &client_path,
        serde_json::to_vec(&json!({
            "mode": "client", "private_key_file": client_private,
            "paths": [{"addr": tunnel.to_string(), "server_public_key": server_public,
                       "connection_pool": 4, "retry_interval": 1, "dial_timeout": 5}],
            "allowed_targets": [target.to_string()],
            "max_streams": 1024, "max_connections": 8,
        }))?,
    )?;
    let server_cfg = config::Config::load(&server_path)?;
    let client_cfg = config::Config::load(&client_path)?;
    let server_stats = Arc::new(Stats::default());
    let counters = server_stats.clone();
    let server = tokio::spawn(async move {
        let _ = engine::run_with_stats(server_cfg, counters).await;
    });
    let client = tokio::spawn(async move {
        let _ = engine::run(client_cfg).await;
    });

    // Wait until the tunnel carries traffic and all four pooled sessions are up.
    timeout(Duration::from_secs(20), async {
        loop {
            if server_stats.sessions.load(Relaxed) == 4 && one_user(map, 0).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("tunnel did not come up")?;

    let started = std::time::Instant::now();
    let mut users = JoinSet::new();
    for id in 0..USERS {
        users.spawn(one_user(map, id));
    }
    let mut failed = 0;
    let mut first_error = None;
    while let Some(result) = users.join_next().await {
        if let Err(error) = result? {
            failed += 1;
            first_error.get_or_insert(error);
        }
    }
    eprintln!(
        "{USERS} users finished in {:.2}s, {failed} failed",
        started.elapsed().as_secs_f64()
    );
    // The status counters must agree with what happened.
    anyhow::ensure!(
        server_stats.streams_total.load(Relaxed) >= USERS as u64,
        "streams_total {} is below {USERS}",
        server_stats.streams_total.load(Relaxed)
    );
    anyhow::ensure!(
        server_stats.sessions.load(Relaxed) == 4,
        "expected the client's 4 pooled sessions, saw {}",
        server_stats.sessions.load(Relaxed)
    );
    anyhow::ensure!(
        server_stats.bytes_to_peer.load(Relaxed) >= (USERS * PAYLOAD) as u64
            && server_stats.bytes_from_peer.load(Relaxed) >= (USERS * PAYLOAD) as u64,
        "byte counters too low: {}",
        server_stats.summary()
    );
    anyhow::ensure!(
        server_stats.streams_refused.load(Relaxed) == 0,
        "no user should have been refused: {}",
        server_stats.summary()
    );
    // Once every user has gone, the open-stream gauge must return to zero.
    timeout(Duration::from_secs(10), async {
        while server_stats.streams.load(Relaxed) != 0 {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("open-stream gauge did not return to zero")?;
    eprintln!("final status: {}", server_stats.summary());
    server.abort();
    client.abort();
    echo_task.abort();
    anyhow::ensure!(
        failed == 0,
        "{failed} of {USERS} users failed; first error: {:#}",
        first_error.unwrap()
    );
    Ok(())
}
