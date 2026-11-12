//! TUN server (stream carriers): a silent connection must not delay the real peer, and a peer that
//! reconnects must replace its old session at once.
//!
//! Needs permission to create a TUN device, so it is ignored by default. Run it as root, or in a
//! throw-away namespace:
//!   unshare -Urn bash -c 'ip link set lo up && cargo test --release --test tun_accept -- --ignored'

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use eztunnel::{config, engine, transport, wire::Frame};
use serde_json::json;
use tokio::{
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

/// Reads frames until the Pong for `nonce` arrives; the server's own heartbeat Pings are skipped.
async fn expect_pong(reader: &mut transport::SecureReader, nonce: u64) -> Result<()> {
    timeout(Duration::from_secs(3), async {
        loop {
            if reader.recv().await? == (Frame::Pong { nonce }) {
                return anyhow::Ok(());
            }
        }
    })
    .await
    .context("no answer to the ping")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires permission to create a TUN device (root or a user namespace)"]
async fn silent_connections_do_not_delay_the_peer_and_reconnects_replace_sessions() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (server_private, server_public_hex) =
        config::generate_keypair(&directory.path().join("server"))?;
    let (client_private, client_public_hex) =
        config::generate_keypair(&directory.path().join("client"))?;
    let reservation = TcpListener::bind("127.0.0.1:0").await?;
    let address: SocketAddr = reservation.local_addr()?;
    drop(reservation);
    let config_path = directory.path().join("server.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&json!({
            "mode": "server", "private_key_file": server_private,
            "peer_public_keys": [client_public_hex],
            "listeners": [{"addr": address.to_string()}],
            "tun": {"name": "eztacc0", "address": "10.99.0.1", "peer_address": "10.99.0.2"},
            "heartbeat_sec": 1, "dead_timeout_sec": 5,
        }))?,
    )?;
    let server_config = config::Config::load(&config_path)?;
    let server = tokio::spawn(async move {
        if let Err(error) = engine::run(server_config).await {
            eprintln!("server stopped: {error:#}");
        }
    });

    // Wait for the listener.
    timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("server did not start (are TUN permissions available?)")?;

    let private = hex::decode(std::fs::read_to_string(&client_private)?.trim())?;
    let private: [u8; 32] = private.try_into().unwrap();
    let public = hex::decode(&server_public_hex)?;
    let public: [u8; 32] = public.try_into().unwrap();

    // 1. A connection that never speaks.
    let _silent = TcpStream::connect(address).await?;

    // 2. The real peer must still get through quickly.
    let first = timeout(
        Duration::from_secs(3),
        transport::connect(
            &address.to_string(),
            &private,
            &public,
            Duration::from_secs(3),
        ),
    )
    .await
    .context("handshake stalled behind a silent connection")??;
    let (mut first_reader, mut first_writer) = first.split();
    first_writer.send(&Frame::Ping { nonce: 1 }).await?;
    expect_pong(&mut first_reader, 1)
        .await
        .context("first session did not answer")?;

    // 3. The same peer reconnects while its old session still looks alive.
    let second = timeout(
        Duration::from_secs(3),
        transport::connect(
            &address.to_string(),
            &private,
            &public,
            Duration::from_secs(3),
        ),
    )
    .await
    .context("reconnect was not accepted while the old session was still open")??;
    let (mut second_reader, mut second_writer) = second.split();
    second_writer.send(&Frame::Ping { nonce: 2 }).await?;
    expect_pong(&mut second_reader, 2)
        .await
        .context("replacement session did not answer")?;

    // 4. The old session must have been closed by the server.
    let closed = timeout(Duration::from_secs(3), async {
        while first_reader.recv().await.is_ok() {}
    })
    .await;
    anyhow::ensure!(closed.is_ok(), "the replaced session was left open");

    server.abort();
    Ok(())
}
