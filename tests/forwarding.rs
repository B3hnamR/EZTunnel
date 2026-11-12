use std::{net::SocketAddr, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use eztunnel::{config, engine};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
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

async fn tcp_roundtrip(addr: SocketAddr) -> Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(b"tunnel roundtrip").await?;
    let mut response = [0; 16];
    stream.read_exact(&mut response).await?;
    anyhow::ensure!(&response == b"tunnel roundtrip", "TCP payload changed");
    Ok(())
}

async fn wait_for_forwarding(addr: SocketAddr) -> Result<()> {
    timeout(Duration::from_secs(20), async {
        loop {
            if matches!(
                timeout(Duration::from_millis(750), tcp_roundtrip(addr)).await,
                Ok(Ok(()))
            ) {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("forwarding did not become ready")?;
    Ok(())
}

async fn bulk_roundtrip(addr: SocketAddr) -> Result<()> {
    let stream = TcpStream::connect(addr).await?;
    let (mut reader, mut writer) = stream.into_split();
    let payload: Vec<u8> = (0..1_048_577).map(|index| (index % 251) as u8).collect();
    let mut echoed = Vec::new();
    let send = async {
        writer.write_all(&payload).await?;
        writer.shutdown().await
    };
    let receive = reader.read_to_end(&mut echoed);
    timeout(Duration::from_secs(15), async {
        tokio::try_join!(send, receive)
    })
    .await??;
    anyhow::ensure!(
        echoed == payload,
        "multi-frame TCP or half-close failed: expected {} bytes, got {}; first mismatch {:?}",
        payload.len(),
        echoed.len(),
        payload
            .iter()
            .zip(&echoed)
            .position(|(sent, received)| sent != received)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_udp_socks_allowlist_and_reconnect() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
    timeout(Duration::from_secs(60), exercise_forwarding())
        .await
        .context("integration scenario timed out")?
}

/// SOCKS5 UDP ASSOCIATE through the tunnel: answers come back with the destination's header,
/// a destination the far side does not allow gets no answer, only the client that opened the
/// association may use the relay, and closing the control connection ends it.
async fn socks_udp_associate(socks_addr: SocketAddr, udp_target: SocketAddr) -> Result<()> {
    let mut control = TcpStream::connect(socks_addr).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    control.read_exact(&mut greeting).await?;
    anyhow::ensure!(greeting == [5, 0], "SOCKS greeting rejected");
    // UDP ASSOCIATE with the usual unspecified client address 0.0.0.0:0.
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await?;
    anyhow::ensure!(
        reply[..4] == [5, 0, 0, 1],
        "UDP ASSOCIATE refused: {reply:?}"
    );
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));

    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let header_to = |port: u16| {
        let mut header = vec![0, 0, 0, 1, 127, 0, 0, 1];
        header.extend_from_slice(&port.to_be_bytes());
        header
    };
    let header = header_to(udp_target.port());
    let mut buffer = [0; 2048];
    for round in 0..2 {
        let mut packet = header.clone();
        packet.extend_from_slice(format!("socks udp {round}").as_bytes());
        client.send_to(&packet, relay).await?;
        let (size, from) = timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
            .await
            .context("no SOCKS5 UDP answer")??;
        anyhow::ensure!(from == relay, "answer from the wrong address");
        anyhow::ensure!(
            buffer[..header.len()] == header[..],
            "answer lost its header"
        );
        anyhow::ensure!(
            &buffer[header.len()..size] == format!("socks udp {round}").as_bytes(),
            "SOCKS5 UDP payload changed"
        );
    }

    // The far side's allow-list covers UDP too: a destination it does not list gets no answer.
    let mut packet = header_to(1);
    packet.extend_from_slice(b"not allowed");
    client.send_to(&packet, relay).await?;
    anyhow::ensure!(
        timeout(Duration::from_millis(1500), client.recv_from(&mut buffer))
            .await
            .is_err(),
        "a destination outside allowed_targets must not answer"
    );

    // Another local port is not the client that opened the association.
    let intruder = UdpSocket::bind("127.0.0.1:0").await?;
    let mut packet = header.clone();
    packet.extend_from_slice(b"intruder");
    intruder.send_to(&packet, relay).await?;
    anyhow::ensure!(
        timeout(Duration::from_millis(1500), intruder.recv_from(&mut buffer))
            .await
            .is_err(),
        "the relay answered a different port than the one that started the association"
    );

    // Closing the control connection ends the association.
    drop(control);
    sleep(Duration::from_millis(500)).await;
    let mut packet = header.clone();
    packet.extend_from_slice(b"after close");
    client.send_to(&packet, relay).await?;
    anyhow::ensure!(
        !matches!(
            timeout(Duration::from_millis(1500), client.recv_from(&mut buffer)).await,
            Ok(Ok(_))
        ),
        "the relay kept answering after the control connection closed"
    );
    Ok(())
}

async fn exercise_forwarding() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (server_private, server_public) =
        config::generate_keypair(&directory.path().join("server"))?;
    let (client_private, client_public) =
        config::generate_keypair(&directory.path().join("client"))?;

    let tcp_echo = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_target = tcp_echo.local_addr()?;
    let tcp_task = Task(tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        while let Ok((mut stream, _)) = tcp_echo.accept().await {
            children.spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    }));
    let udp_echo = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_target = udp_echo.local_addr()?;
    let udp_task = Task(tokio::spawn(async move {
        let mut buffer = [0; 16384];
        while let Ok((size, sender)) = udp_echo.recv_from(&mut buffer).await {
            let _ = udp_echo.send_to(&buffer[..size], sender).await;
        }
    }));

    // Hold TCP reservations together so the OS cannot return a duplicate port.
    let mut reservations = Vec::new();
    for _ in 0..4 {
        reservations.push(TcpListener::bind("127.0.0.1:0").await?);
    }
    let tunnel_addr = reservations[0].local_addr()?;
    let tcp_bind = reservations[1].local_addr()?;
    let socks_addr = reservations[2].local_addr()?;
    let denied_bind = reservations[3].local_addr()?;
    let udp_reservation = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_bind = udp_reservation.local_addr()?;
    // A real echo endpoint under a different requested hostname must still be denied.
    let denied_target = format!("localhost:{}", tcp_target.port());
    let server_path = directory.path().join("server.json");
    let client_path = directory.path().join("client.json");
    std::fs::write(
        &server_path,
        serde_json::to_vec(&json!({
            "mode": "server", "private_key_file": server_private,
            "peer_public_keys": [client_public],
            "listeners": [{"addr": tunnel_addr.to_string(), "maps": [
                {"type":"tcp", "bind":tcp_bind.to_string(), "target":tcp_target.to_string()},
                {"type":"udp", "bind":udp_bind.to_string(), "target":udp_target.to_string()},
                {"type":"tcp", "bind":denied_bind.to_string(), "target":denied_target}
            ]}], "socks5": socks_addr.to_string(),
            "heartbeat_sec":1, "dead_timeout_sec":3,
            "max_streams":32, "max_connections":4
        }))?,
    )?;
    std::fs::write(
        &client_path,
        serde_json::to_vec(&json!({
            "mode":"client", "private_key_file":client_private,
            "paths":[{"addr":tunnel_addr.to_string(), "server_public_key":server_public,
                      "connection_pool":2, "retry_interval":1, "dial_timeout":2}],
            "allowed_targets":[tcp_target.to_string(), udp_target.to_string()],
            "heartbeat_sec":1, "dead_timeout_sec":3,
            "max_streams":32, "max_connections":4
        }))?,
    )?;
    drop(reservations);
    drop(udp_reservation);
    let server = run_engine(&server_path)?;
    let client = run_engine(&client_path)?;
    wait_for_forwarding(tcp_bind).await?;

    // Exercise multiple frames and directional EOF, not just short messages.
    let mut bulk_tasks = tokio::task::JoinSet::new();
    for _ in 0..4 {
        bulk_tasks.spawn(bulk_roundtrip(tcp_bind));
    }
    while let Some(result) = bulk_tasks.join_next().await {
        result??;
    }

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.send_to(b"udp roundtrip", udp_bind).await?;
    let mut datagram = [0; 64];
    let (size, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut datagram)).await??;
    anyhow::ensure!(&datagram[..size] == b"udp roundtrip", "UDP payload changed");
    socket.send_to(&[], udp_bind).await?;
    let (size, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut datagram)).await??;
    anyhow::ensure!(size == 0, "empty UDP datagram was lost or changed");

    let mut socks = TcpStream::connect(socks_addr).await?;
    socks.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    socks.read_exact(&mut greeting).await?;
    anyhow::ensure!(greeting == [5, 0], "SOCKS greeting rejected");
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&tcp_target.port().to_be_bytes());
    socks.write_all(&request).await?;
    let mut reply = [0; 4];
    socks.read_exact(&mut reply).await?;
    anyhow::ensure!(reply[0] == 5 && reply[1] == 0, "SOCKS CONNECT failed");
    let tail_len = match reply[3] {
        1 => 6,
        4 => 18,
        3 => usize::from(socks.read_u8().await?) + 2,
        _ => bail!("invalid SOCKS reply address type"),
    };
    socks.read_exact(&mut vec![0; tail_len]).await?;
    socks.write_all(b"socks roundtrip").await?;
    let mut response = [0; 15];
    socks.read_exact(&mut response).await?;
    anyhow::ensure!(&response == b"socks roundtrip", "SOCKS payload changed");
    drop(socks);

    socks_udp_associate(socks_addr, udp_target).await?;

    let denied = timeout(Duration::from_secs(5), tcp_roundtrip(denied_bind)).await;
    anyhow::ensure!(
        matches!(denied, Ok(Err(_))),
        "denied destination must be closed, not forwarded or left hanging"
    );

    // Keep the client alive: its own retry loop must recover after server loss.
    drop(server);
    sleep(Duration::from_millis(500)).await;
    let replacement_server = run_engine(&server_path)?;
    wait_for_forwarding(tcp_bind).await?;

    drop((client, replacement_server, tcp_task, udp_task));
    Ok(())
}
