//! Real UDP/KCP/FEC tests, including loss of one data shard in every FEC block.
use anyhow::{Context, Result, ensure};
use eztunnel::{
    config::{ClientPath, Listener},
    fec_carrier::{self, FecListener},
};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    time::timeout,
};

fn listener(addr: &str, knock: bool) -> Result<Listener> {
    Ok(serde_json::from_value(
        json!({"addr":addr,"transport":"fec-udp",
        "fec":{"knock":knock},"maps":[]}),
    )?)
}
fn path(addr: SocketAddr, knock: bool) -> Result<ClientPath> {
    Ok(serde_json::from_value(
        json!({"addr":addr.to_string(),"transport":"fec-udp",
        "server_public_key":"00".repeat(32),"fec":{"knock":knock}}),
    )?)
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn dropping_a_large_accepted_tail_keeps_the_packet_bridge_until_delivery()->Result<()> {
    timeout(Duration::from_secs(15),async{
        let mut settings=listener("127.0.0.1:0",false)?;settings.fec.sndwnd=128;settings.fec.rcvwnd=128;
        let mut server=FecListener::bind(&settings).await?;let address=server.local_addr();
        let payload=(0..262_144).map(|n|(n%251)as u8).collect::<Vec<_>>();let expected=payload.clone();
        let receiving=tokio::spawn(async move{
            let mut stream=server.accept().await?;tokio::time::sleep(Duration::from_millis(100)).await;
            let mut got=vec![0;expected.len()];stream.read_exact(&mut got).await?;ensure!(got==expected,"dropped stream abandoned its accepted tail");Ok::<_,anyhow::Error>(())
        });
        let mut options=path(address,false)?;options.fec.sndwnd=128;options.fec.rcvwnd=128;
        let mut stream=fec_carrier::connect(&options).await?;
        stream.write_all(&payload).await?;
        drop(stream);
        receiving.await??;Ok::<_,anyhow::Error>(())
    }).await??;Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fec_udp_transfers_with_one_lost_data_shard_per_block() -> Result<()> {
    loss_run(Some(128)).await
}

/// The same with the default 1024-packet window and the relay's default socket buffer, which
/// holds far less than a window. Before 0.8.5 a retransmission timeout resent the whole window at
/// once, the relay dropped most of it again and the run took 15 s or more on a busy machine;
/// `fec.resend_burst` spreads the resends out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fec_udp_recovers_from_bursts_a_short_queue_drops() -> Result<()> {
    loss_run(None).await
}

/// `window`: a window the relay can hold (and a relay buffer as large as the kernel allows), or
/// `None` for the defaults.
async fn loss_run(window: Option<u16>) -> Result<()> {
    let losses = Arc::new(AtomicUsize::new(0));
    let parities = Arc::new(AtomicUsize::new(0));
    let client_stage = Arc::new(AtomicUsize::new(0));
    let server_stage = Arc::new(AtomicUsize::new(0));
    let result = timeout(Duration::from_secs(45), async {
        // The relay below is one task with one socket. When its socket buffer overflows, whole
        // bursts are lost, KCP (no congestion control) resends its whole window at every
        // timeout, and the timeout grows by half each round: a busy machine turned the test into
        // a 15 s or longer run. A window the relay can hold keeps the test about FEC.
        let mut settings = listener("127.0.0.1:0", false)?;
        if let Some(window) = window {
            settings.fec.sndwnd = window;
            settings.fec.rcvwnd = window;
        }
        let mut server = FecListener::bind(&settings).await?;
        let server_address = server.local_addr();
        let proxy = UdpSocket::bind("127.0.0.1:0").await?;
        if window.is_some() {
            // As large as the kernel allows (net.core.rmem_max).
            let _ = fec_carrier::set_udp_buffers(&proxy, 8 << 20);
        }
        let proxy_address = proxy.local_addr()?;
        let dropped = losses.clone();
        let parity = parities.clone();
        let proxy_task = tokio::spawn(async move {
            let mut client = None;
            let mut buffer = vec![0; 9001];
            while let Ok((size, remote)) = proxy.recv_from(&mut buffer).await {
                let target = if remote == server_address {
                    if let Some(address) = client {
                        address
                    } else {
                        continue;
                    }
                } else {
                    client = Some(remote);
                    server_address
                };
                if size >= 8 {
                    let seq = u32::from_le_bytes(buffer[..4].try_into().unwrap());
                    let kind = u16::from_le_bytes(buffer[4..6].try_into().unwrap());
                    if seq % 11 == 3 && kind == 0xf1 {
                        dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if kind == 0xf2 {
                        parity.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if proxy.send_to(&buffer[..size], target).await.is_err() {
                    break;
                }
            }
        });
        let echo_stage = server_stage.clone();
        let echo = tokio::spawn(async move {
            echo_stage.store(1, Ordering::Relaxed);
            let mut stream = server.accept().await?;
            let (mut read, mut write) = tokio::io::split(&mut stream);
            let mut payload = vec![0; 1_048_577];
            echo_stage.store(2, Ordering::Relaxed);
            read.read_exact(&mut payload).await?;
            echo_stage.store(3, Ordering::Relaxed);
            write.write_all(&payload).await?;
            echo_stage.store(4, Ordering::Relaxed);
            write.flush().await?;
            // Keep retransmissions alive until the client received the full echo.
            echo_stage.store(5, Ordering::Relaxed);
            let mut finished = [0; 4];
            read.read_exact(&mut finished).await?;
            ensure!(
                &finished == b"done",
                "missing final loss-test acknowledgement"
            );
            echo_stage.store(6, Ordering::Relaxed);
            Ok::<_, anyhow::Error>(())
        });
        let mut client_path = path(proxy_address, false)?;
        if let Some(window) = window {
            client_path.fec.sndwnd = window;
            client_path.fec.rcvwnd = window;
        }
        let mut client = fec_carrier::connect(&client_path).await?;
        client_stage.store(1, Ordering::Relaxed);
        let payload: Vec<_> = (0..1_048_577).map(|index| (index * 31) as u8).collect();
        let (mut reader, mut writer) = tokio::io::split(&mut client);
        let mut received = vec![0; payload.len()];
        tokio::try_join!(
            async {
                writer.write_all(&payload).await?;
                client_stage.fetch_max(2, Ordering::Relaxed);
                writer.flush().await?;
                client_stage.fetch_max(3, Ordering::Relaxed);
                Ok::<_, std::io::Error>(())
            },
            async {
                reader.read_exact(&mut received).await?;
                client_stage.fetch_max(4, Ordering::Relaxed);
                Ok::<_, std::io::Error>(())
            }
        )?;
        ensure!(received == payload, "FEC-UDP lost or changed bytes");
        ensure!(
            losses.load(Ordering::Relaxed) > 10,
            "loss injector was not exercised"
        );
        ensure!(
            parities.load(Ordering::Relaxed) > 10,
            "wire carried no parity packets"
        );
        writer.write_all(b"done").await?;
        writer.flush().await?;
        client_stage.store(5, Ordering::Relaxed);
        echo.await??;
        proxy_task.abort();
        Ok::<_, anyhow::Error>(())
    })
    .await;
    ensure!(
        result.is_ok(),
        "FEC-UDP loss deadline: client stage{} server stage{} lost shards{} parity packets{} (client4=received, server5=awaiting receipt)",
        client_stage.load(Ordering::Relaxed),
        server_stage.load(Ordering::Relaxed),
        losses.load(Ordering::Relaxed),
        parities.load(Ordering::Relaxed)
    );
    result??;
    Ok(())
}

/// The pacer (`fec.pacer`) sits above KCP and throttles writes by measured RTT; this is a real
/// client/server session (loopback, no lossy proxy) with it on at both ends, checking it neither
/// stalls the session nor corrupts data, not just the `Pacer` struct's own unit tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fec_udp_with_the_pacer_on_both_ends_still_transfers_correctly() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let mut settings = listener("127.0.0.1:0", false)?;
        settings.fec.pacer = true;
        let mut server = FecListener::bind(&settings).await?;
        let server_address = server.local_addr();
        let echo = tokio::spawn(async move {
            let mut stream = server.accept().await?;
            let (mut read, mut write) = tokio::io::split(&mut stream);
            let mut payload = vec![0; 262_144];
            read.read_exact(&mut payload).await?;
            write.write_all(&payload).await?;
            write.flush().await?;
            Ok::<_, anyhow::Error>(())
        });
        let mut client_path = path(server_address, false)?;
        client_path.fec.pacer = true;
        let mut client = fec_carrier::connect(&client_path).await?;
        let payload: Vec<_> = (0..262_144).map(|index| (index * 17) as u8).collect();
        let (mut reader, mut writer) = tokio::io::split(&mut client);
        let mut received = vec![0; payload.len()];
        tokio::try_join!(
            async {
                writer.write_all(&payload).await?;
                writer.flush().await?;
                Ok::<_, std::io::Error>(())
            },
            async {
                reader.read_exact(&mut received).await?;
                Ok::<_, std::io::Error>(())
            }
        )?;
        ensure!(received == payload, "paced FEC-UDP lost or changed bytes");
        echo.await??;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fec_udp_knock_connects_and_listener_drop_releases_both_ports() -> Result<()> {
    timeout(Duration::from_secs(10), async {
        let mut server = FecListener::bind(&listener("127.0.0.1:0", true)?).await?;
        let address = server.local_addr();
        let echo = tokio::spawn(async move {
            let mut stream = server.accept().await?;
            let mut data = [0; 4];
            stream.read_exact(&mut data).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok::<_, anyhow::Error>(())
        });
        let mut client = fec_carrier::connect(&path(address, true)?).await?;
        client.write_all(b"ping").await?;
        client.flush().await?;
        let mut response = [0; 4];
        client.read_exact(&mut response).await?;
        ensure!(
            &response == b"ping",
            "knock accepted but KCP transfer failed"
        );
        echo.await??;
        drop(client);
        let knock_port = if address.port() <= 55_535 {
            address.port() + 10_000
        } else {
            address.port() - 1000
        };
        // The listener's tasks are aborted when it is dropped, and the runtime frees their
        // sockets a moment later (on whichever worker thread gets to them); the ports must come
        // free promptly, but not before this task has yielded once.
        let started = std::time::Instant::now();
        let (_released, _knock_released) = loop {
            tokio::task::yield_now().await;
            let both = async {
                let first = UdpSocket::bind(address).await?;
                let second = UdpSocket::bind(SocketAddr::new(address.ip(), knock_port)).await?;
                anyhow::Ok((first, second))
            }
            .await;
            match both {
                Ok(sockets) => break sockets,
                Err(error) => {
                    ensure!(
                        started.elapsed() < Duration::from_secs(2),
                        "the listener's ports were not released within 2 s: {error}"
                    );
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        };
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

/// The knock table is bounded. When it is full the oldest entry goes, so knocks from spoofed
/// addresses cannot keep a real client from getting its answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_knock_table_makes_room_instead_of_refusing() -> Result<()> {
    timeout(Duration::from_secs(10), async {
        let mut settings = listener("127.0.0.1:0", true)?;
        settings.fec.max_peers = 2;
        let server = FecListener::bind(&settings).await?;
        let address = server.local_addr();
        let knock_port = if address.port() <= 55_535 {
            address.port() + 10_000
        } else {
            address.port() - 1000
        };
        // Four different source addresses (127.0.0.0/8 all belongs to this machine).
        for source in ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"] {
            let socket = UdpSocket::bind((source, 0)).await?;
            socket.send_to(b"P", (address.ip(), knock_port)).await?;
            let mut reply = [0u8; 8];
            let (size, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut reply))
                .await
                .with_context(|| format!("no answer to the knock from {source}"))??;
            ensure!(&reply[..size] == b"A", "unexpected knock answer");
        }
        drop(server);
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

/// One source address cannot take every peer slot of a public FEC listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_address_cannot_take_every_peer_slot() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let mut settings = listener("127.0.0.1:0", false)?;
        settings.fec.max_peers_per_ip = 2;
        let mut server = FecListener::bind(&settings).await?;
        let address = server.local_addr();
        // Four client connections from 127.0.0.1 (different ports, different conversations).
        let mut clients = Vec::new();
        for _ in 0..4 {
            let mut client = fec_carrier::connect(&path(address, false)?).await?;
            client.write_all(b"hi").await?;
            client.flush().await?;
            clients.push(client);
        }
        let mut accepted = 0;
        while timeout(Duration::from_secs(3), server.accept())
            .await
            .is_ok()
        {
            accepted += 1;
        }
        ensure!(
            accepted == 2,
            "{accepted} conversations from one address were accepted, 2 allowed"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_network_peer_can_reconnect_without_evicting_an_existing_conversation() -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let mut settings = listener("127.0.0.1:0", false)?;
        settings.fec.max_peers = 2;
        let mut server = FecListener::bind(&settings).await?;
        let address = server.local_addr();
        let proxy = UdpSocket::bind("127.0.0.1:0").await?;
        let proxy_address = proxy.local_addr()?;
        let proxy_task = tokio::spawn(async move {
            let mut clients = std::collections::HashMap::new();
            let mut buffer = vec![0; 1501];
            while let Ok((size, remote)) = proxy.recv_from(&mut buffer).await {
                if size < 32 {
                    continue;
                }
                let conversation = u32::from_le_bytes(buffer[8..12].try_into().unwrap());
                let target = if remote == address {
                    if let Some(client) = clients.get(&conversation) {
                        *client
                    } else {
                        continue;
                    }
                } else {
                    clients.insert(conversation, remote);
                    address
                };
                if proxy.send_to(&buffer[..size], target).await.is_err() {
                    break;
                }
            }
        });
        let echo = tokio::spawn(async move {
            let mut echoes = Vec::new();
            for _ in 0..2 {
                let mut stream = server.accept().await?;
                echoes.push(tokio::spawn(async move {
                    for _ in 0..2 {
                        let mut data = [0; 4];
                        stream.read_exact(&mut data).await?;
                        stream.write_all(&data).await?;
                        stream.flush().await?;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok::<_, anyhow::Error>(())
                }));
            }
            for task in echoes {
                task.await??;
            }
            Ok::<_, anyhow::Error>(())
        });
        async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
            stream: &mut S,
            payload: &[u8; 4],
        ) -> Result<()> {
            stream.write_all(payload).await?;
            stream.flush().await?;
            let mut response = [0; 4];
            stream.read_exact(&mut response).await?;
            ensure!(&response == payload, "conversation changed or lost bytes");
            Ok(())
        }
        let mut old = fec_carrier::connect(&path(proxy_address, false)?).await?;
        exchange(&mut old, b"old1").await?;
        let mut fresh = fec_carrier::connect(&path(proxy_address, false)?).await?;
        exchange(&mut fresh, b"new1").await?;
        let mut excess = fec_carrier::connect(&path(proxy_address, false)?).await?;
        excess.write_all(b"cap3").await?;
        excess.flush().await?;
        let mut ignored = [0; 4];
        ensure!(
            timeout(Duration::from_millis(200), excess.read_exact(&mut ignored))
                .await
                .is_err(),
            "conversation cap was not enforced"
        );
        exchange(&mut old, b"old2").await?;
        exchange(&mut fresh, b"new2").await?;
        echo.await??;
        proxy_task.abort();
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_adaptive_tuning_keeps_a_live_udp_stream_usable_across_timer_updates() -> Result<()>
{
    let _ = tracing_subscriber::fmt()
        .with_env_filter("eztunnel=debug")
        .try_init();
    let client_stage = Arc::new(AtomicUsize::new(0));
    let server_stage = Arc::new(AtomicUsize::new(0));
    let pushed = Arc::new(AtomicUsize::new(0));
    let acked = Arc::new(AtomicUsize::new(0));
    let largest_window = Arc::new(AtomicUsize::new(0));
    let result = timeout(Duration::from_secs(15), async {
        let mut settings = listener("127.0.0.1:0", false)?;
        settings.fec.tuner.mode = fec_carrier::FecTunerMode::Auto;
        settings.fec.tuner.memory_budget_mb = 32;
        settings.fec.socket_buf_bytes = 8 * 1024 * 1024;
        settings.fec.tuner.min_buffer_bytes = 4 * 1024 * 1024;
        settings.fec.nodelay = Some(false);
        settings.fec.interval_ms = Some(30);
        settings.fec.congestion_control = Some(true);
        settings.fec.write_delay = Some(true);
        settings.fec.ack_no_delay = Some(false);
        let mut server = FecListener::bind(&settings).await?;
        let address = server.local_addr();
        let proxy = UdpSocket::bind("127.0.0.1:0").await?;
        let proxy_address = proxy.local_addr()?;
        let observed_window = largest_window.clone();
        let observed_pushes = pushed.clone();
        let observed_acks = acked.clone();
        let proxy_task = tokio::spawn(async move {
            let mut client = None;
            let mut buffer = vec![0; 1501];
            while let Ok((size, remote)) = proxy.recv_from(&mut buffer).await {
                let target = if remote == address {
                    if let Some(client) = client {
                        client
                    } else {
                        continue;
                    }
                } else {
                    client = Some(remote);
                    address
                };
                if size >= 32 && u16::from_le_bytes(buffer[4..6].try_into().unwrap()) == 0xf1 {
                    // Data FEC header8bytes, then KCP's receive-window field6bytes in.
                    let window = u16::from_le_bytes(buffer[14..16].try_into().unwrap()) as usize;
                    observed_window.fetch_max(window, Ordering::Relaxed);
                    if buffer[12] == 81 {
                        observed_pushes.fetch_add(1, Ordering::Relaxed);
                    }
                    if buffer[12] == 82 {
                        observed_acks.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if proxy.send_to(&buffer[..size], target).await.is_err() {
                    break;
                }
            }
        });
        let echo_stage = server_stage.clone();
        let echo = tokio::spawn(async move {
            let mut stream = server.accept().await?;
            for iteration in 0..4 {
                echo_stage.store(iteration * 10 + 1, Ordering::Relaxed);
                let mut data = vec![0; 65_537];
                stream.read_exact(&mut data).await?;
                echo_stage.store(iteration * 10 + 2, Ordering::Relaxed);
                stream.write_all(&data).await?;
                echo_stage.store(iteration * 10 + 3, Ordering::Relaxed);
                stream.flush().await?;
                eprintln!("adaptive server echoed round {iteration}");
            }
            // A KCP flush schedules output; congestion control can leave a tail
            // queued. Keep the server alive until the client confirms receipt.
            echo_stage.store(40, Ordering::Relaxed);
            let mut finished = [0; 4];
            stream.read_exact(&mut finished).await?;
            ensure!(
                &finished == b"done",
                "missing final application acknowledgement"
            );
            Ok::<_, anyhow::Error>(())
        });
        let mut client_settings = path(proxy_address, false)?;
        client_settings.fec.tuner.mode = fec_carrier::FecTunerMode::Auto;
        client_settings.fec.tuner.memory_budget_mb = 32;
        client_settings.fec.socket_buf_bytes = 8 * 1024 * 1024;
        client_settings.fec.tuner.min_buffer_bytes = 4 * 1024 * 1024;
        client_settings.fec.nodelay = Some(false);
        client_settings.fec.interval_ms = Some(30);
        client_settings.fec.congestion_control = Some(true);
        client_settings.fec.write_delay = Some(true);
        client_settings.fec.ack_no_delay = Some(false);
        let mut client = fec_carrier::connect(&client_settings).await?;
        for iteration in 0..4 {
            client_stage.store(iteration * 10 + 1, Ordering::Relaxed);
            let payload: Vec<_> = (0..65_537)
                .map(|index| (index * 17 + iteration) as u8)
                .collect();
            client.write_all(&payload).await?;
            client_stage.store(iteration * 10 + 2, Ordering::Relaxed);
            client.flush().await?;
            client_stage.store(iteration * 10 + 3, Ordering::Relaxed);
            let mut response = vec![0; payload.len()];
            client.read_exact(&mut response).await?;
            client_stage.store(iteration * 10 + 4, Ordering::Relaxed);
            eprintln!("adaptive client received round {iteration}");
            ensure!(
                payload == response,
                "adaptive controller changed stream data"
            );
            if iteration < 3 {
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
        }
        ensure!(
            largest_window.load(Ordering::Relaxed) > 256,
            "live KCP window was never increased on the wire"
        );
        client_stage.store(40, Ordering::Relaxed);
        client.write_all(b"done").await?;
        client_stage.store(41, Ordering::Relaxed);
        client.flush().await?;
        echo.await??;
        proxy_task.abort();
        Ok::<_, anyhow::Error>(())
    })
    .await;
    ensure!(
        result.is_ok(),
        "adaptive deadline: client stage{} server stage{} PUSH packets{} ACK packets{} largest window{}",
        client_stage.load(Ordering::Relaxed),
        server_stage.load(Ordering::Relaxed),
        pushed.load(Ordering::Relaxed),
        acked.load(Ordering::Relaxed),
        largest_window.load(Ordering::Relaxed)
    );
    result??;
    Ok(())
}
