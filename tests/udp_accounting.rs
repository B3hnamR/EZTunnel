//! C32: UDP carried by the tunnel counts toward the traffic counters (and so the quota)
//! exactly once per direction: a UDP port map and a SOCKS5 UDP association.
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering::Relaxed},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use eztunnel::{config, engine, stats::Stats};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};

fn free_port() -> Result<SocketAddr> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?)
}

fn write_private(path: &std::path::Path, value: &serde_json::Value) -> Result<()> {
    std::fs::write(path, serde_json::to_vec(value)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn echo(socket: UdpSocket) {
    let mut buffer = [0u8; 4096];
    while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
        let _ = socket.send_to(&buffer[..n], from).await;
    }
}

/// Waits until both counters are at least the given values (they are updated just after
/// the datagram is queued or sent).
async fn settle(stats: &Stats, to_peer: u64, from_peer: u64) {
    for _ in 0..200 {
        if stats.bytes_to_peer.load(Relaxed) >= to_peer && stats.bytes_from_peer.load(Relaxed) >= from_peer {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    sleep(Duration::from_millis(100)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_map_and_socks_udp_count_each_payload_once_per_direction() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let key = eztunnel::tunnel_key::TunnelKey::generate()?.display();
    let target_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let target = target_socket.local_addr()?;
    let echoing = tokio::spawn(echo(target_socket));
    let (tunnel, map, socks) = (free_port()?, free_port()?, free_port()?);
    let server_path = directory.path().join("server.json");
    let client_path = directory.path().join("client.json");
    write_private(&server_path, &json!({
        "mode": "server", "tunnel_key": key, "socks5": socks.to_string(),
        "listeners": [{"addr": tunnel.to_string(), "maps": [
            {"type": "udp", "bind": map.to_string(), "target": target.to_string()}]}],
    }))?;
    write_private(&client_path, &json!({
        "mode": "client", "tunnel_key": key, "allowed_targets": [target.to_string()],
        "paths": [{"addr": tunnel.to_string(), "retry_interval": 1, "dial_timeout": 5}],
    }))?;
    let stats = Arc::new(Stats::default());
    let server = {
        let (config, stats) = (config::Config::load(&server_path)?, stats.clone());
        tokio::spawn(async move { let _ = engine::run_with_stats(config, stats).await; })
    };
    let client = {
        let config = config::Config::load(&client_path)?;
        tokio::spawn(async move { let _ = engine::run(config).await; })
    };
    timeout(Duration::from_secs(20), async {
        while stats.sessions.load(Relaxed) == 0 {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("tunnel did not come up")?;
    sleep(Duration::from_millis(300)).await;

    // UDP port map: 100 + 200 + 300 bytes each way.
    let (to_before, from_before) = (stats.bytes_to_peer.load(Relaxed), stats.bytes_from_peer.load(Relaxed));
    let user = UdpSocket::bind("127.0.0.1:0").await?;
    let mut buffer = [0u8; 4096];
    for size in [100usize, 200, 300] {
        user.send_to(&vec![b'u'; size], map).await?;
        let (n, _) = timeout(Duration::from_secs(5), user.recv_from(&mut buffer)).await.context("no UDP map echo")??;
        ensure!(n == size, "UDP map echo size {n} != {size}");
    }
    settle(&stats, to_before + 600, from_before + 600).await;
    let to = stats.bytes_to_peer.load(Relaxed) - to_before;
    let from = stats.bytes_from_peer.load(Relaxed) - from_before;
    ensure!(to == 600 && from == 600, "UDP map counted to_peer={to} from_peer={from}, expected 600/600");

    // SOCKS5 UDP: the 10-byte SOCKS header is framing, not payload.
    let (to_before, from_before) = (stats.bytes_to_peer.load(Relaxed), stats.bytes_from_peer.load(Relaxed));
    let mut control = TcpStream::connect(socks).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0u8; 2];
    control.read_exact(&mut greeting).await?;
    ensure!(greeting == [5, 0], "SOCKS greeting rejected");
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await?;
    ensure!(reply[..4] == [5, 0, 0, 1], "UDP ASSOCIATE refused: {reply:?}");
    let relay = SocketAddr::from(([reply[4], reply[5], reply[6], reply[7]], u16::from_be_bytes([reply[8], reply[9]])));
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut header = vec![0, 0, 0, 1, 127, 0, 0, 1];
    header.extend_from_slice(&target.port().to_be_bytes());
    for size in [150usize, 250] {
        let mut packet = header.clone();
        packet.extend(std::iter::repeat_n(b's', size));
        socket.send_to(&packet, relay).await?;
        let (n, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.context("no SOCKS UDP answer")??;
        ensure!(n == header.len() + size, "SOCKS UDP answer size");
    }
    settle(&stats, to_before + 400, from_before + 400).await;
    let to = stats.bytes_to_peer.load(Relaxed) - to_before;
    let from = stats.bytes_from_peer.load(Relaxed) - from_before;
    ensure!(to == 400 && from == 400, "SOCKS UDP counted to_peer={to} from_peer={from}, expected 400/400");

    drop(control);
    server.abort();
    client.abort();
    echoing.abort();
    Ok(())
}
