//! The plain `kcp` carrier creates a session from the first datagram of an unknown peer. The
//! listener must bound how many such sessions one address (or everyone) can create.

use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use eztunnel::{
    config::Listener,
    kcp_carrier::{Acceptor, Incoming},
};
use serde_json::json;
use tokio::{net::UdpSocket, time::timeout};

/// A minimal KCP segment header (24 bytes): conversation id, PUSH command, no payload.
fn first_packet(conversation: u32) -> Vec<u8> {
    let mut packet = vec![0u8; 24];
    packet[..4].copy_from_slice(&conversation.to_le_bytes());
    packet[4] = 81;
    packet
}

async fn free_udp_port() -> Result<u16> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    Ok(socket.local_addr()?.port())
}

async fn listener(kcp: serde_json::Value) -> Result<(Acceptor, SocketAddr)> {
    let port = free_udp_port().await?;
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let settings: Listener = serde_json::from_value(
        json!({"addr": address.to_string(), "transport": "kcp", "kcp": kcp}),
    )?;
    Ok((Acceptor::bind(&settings).await?, address))
}

/// Sends one first packet from each of `count` new sockets bound to `source`.
async fn start_sessions(source: &str, target: SocketAddr, count: usize) -> Result<Vec<UdpSocket>> {
    let mut sockets = Vec::new();
    for index in 0..count {
        let socket = UdpSocket::bind(format!("{source}:0")).await?;
        socket
            .send_to(&first_packet(1000 + index as u32), target)
            .await?;
        sockets.push(socket);
    }
    Ok(sockets)
}

/// How many sessions the listener hands out within a short time.
async fn accepted(acceptor: &mut Acceptor) -> usize {
    let mut kept = Vec::new();
    while let Ok(Ok(incoming)) = timeout(Duration::from_millis(700), acceptor.accept()).await {
        kept.push(incoming);
    }
    kept.iter()
        .filter(|incoming| matches!(incoming, Incoming::Kcp(..)))
        .count()
}

#[tokio::test]
async fn one_address_cannot_create_unlimited_sessions() -> Result<()> {
    let (mut acceptor, address) = listener(json!({"max_sessions_per_ip": 3})).await?;
    let _senders = start_sessions("127.0.0.1", address, 20).await?;
    let first = accepted(&mut acceptor).await;
    assert!(
        (1..=3).contains(&first),
        "expected 1..=3 sessions, got {first}"
    );
    // Another source address is not affected by the first one's limit.
    let _other = start_sessions("127.0.0.2", address, 2).await?;
    let second = accepted(&mut acceptor).await;
    assert!(second >= 1, "a different address must still be served");
    Ok(())
}

#[tokio::test]
async fn the_total_number_of_sessions_is_bounded() -> Result<()> {
    let (mut acceptor, address) =
        listener(json!({"max_sessions": 4, "max_sessions_per_ip": 0})).await?;
    let _a = start_sessions("127.0.0.1", address, 10).await?;
    let _b = start_sessions("127.0.0.2", address, 10).await?;
    let total = accepted(&mut acceptor).await;
    assert!(
        (1..=4).contains(&total),
        "expected at most 4 sessions, got {total}"
    );
    Ok(())
}

#[tokio::test]
async fn defaults_serve_a_normal_number_of_peers_from_one_address() -> Result<()> {
    let (mut acceptor, address) = listener(json!({})).await?;
    let _senders = start_sessions("127.0.0.1", address, 10).await?;
    let total = accepted(&mut acceptor).await;
    assert_eq!(total, 10, "default limits must not turn away ten peers");
    Ok(())
}
