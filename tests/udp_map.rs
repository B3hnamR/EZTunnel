//! UDP port maps keep one tunnel stream per remote address. Idle conversations must be released so
//! the map keeps accepting new addresses, and a returning address must get a fresh conversation.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use eztunnel::{config, engine};
use serde_json::json;
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};

async fn roundtrip(from: &UdpSocket, map: SocketAddr, payload: &[u8]) -> Result<()> {
    from.send_to(payload, map).await?;
    let mut buffer = [0u8; 64];
    let (size, _) = timeout(Duration::from_secs(3), from.recv_from(&mut buffer))
        .await
        .context("no answer from the UDP map")??;
    anyhow::ensure!(&buffer[..size] == payload, "UDP payload changed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_udp_conversations_are_released_and_addresses_can_return() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (server_private, server_public) =
        config::generate_keypair(&directory.path().join("server"))?;
    let (client_private, client_public) =
        config::generate_keypair(&directory.path().join("client"))?;

    let echo = UdpSocket::bind("127.0.0.1:0").await?;
    let target = echo.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((size, sender)) = echo.recv_from(&mut buffer).await {
            let _ = echo.send_to(&buffer[..size], sender).await;
        }
    });
    let tunnel_reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let tunnel = tunnel_reservation.local_addr()?;
    let map_reservation = UdpSocket::bind("127.0.0.1:0").await?;
    let map = map_reservation.local_addr()?;
    drop((tunnel_reservation, map_reservation));

    let server_path = directory.path().join("server.json");
    let client_path = directory.path().join("client.json");
    std::fs::write(
        &server_path,
        serde_json::to_vec(&json!({
            "mode": "server", "private_key_file": server_private,
            "peer_public_keys": [client_public],
            "listeners": [{"addr": tunnel.to_string(), "maps": [
                {"type": "udp", "bind": map.to_string(), "target": target.to_string()}
            ]}],
            // Room for only three conversations, and they expire after five seconds of silence.
            "max_streams": 3,
            "timeouts": {"udp_idle_sec": 5},
        }))?,
    )?;
    std::fs::write(
        &client_path,
        serde_json::to_vec(&json!({
            "mode": "client", "private_key_file": client_private,
            "paths": [{"addr": tunnel.to_string(), "server_public_key": server_public,
                       "retry_interval": 1, "dial_timeout": 3}],
            "allowed_targets": [target.to_string()],
            "timeouts": {"udp_idle_sec": 5},
        }))?,
    )?;
    let server_config = config::Config::load(&server_path)?;
    let client_config = config::Config::load(&client_path)?;
    let server = tokio::spawn(async move {
        let _ = engine::run(server_config).await;
    });
    let client = tokio::spawn(async move {
        let _ = engine::run(client_config).await;
    });

    // Wait for the tunnel.
    let probe = UdpSocket::bind("127.0.0.1:0").await?;
    timeout(Duration::from_secs(20), async {
        loop {
            if roundtrip(&probe, map, b"ready").await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("tunnel did not come up")?;

    // Fill the three slots (the probe already holds one).
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    roundtrip(&a, map, b"from a").await?;
    roundtrip(&b, map, b"from b").await?;

    // A fourth address is refused while all slots are busy...
    let c = UdpSocket::bind("127.0.0.1:0").await?;
    c.send_to(b"from c", map).await?;
    let mut buffer = [0u8; 64];
    anyhow::ensure!(
        timeout(Duration::from_millis(800), c.recv_from(&mut buffer))
            .await
            .is_err(),
        "a fourth address was served although the map is full"
    );

    // ...and served once the idle ones have been released.
    sleep(Duration::from_secs(7)).await;
    roundtrip(&c, map, b"c again").await?;
    // An address that went idle comes back and gets a fresh conversation.
    roundtrip(&a, map, b"a returns").await?;

    server.abort();
    client.abort();
    echo_task.abort();
    Ok(())
}
