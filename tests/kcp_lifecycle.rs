//! Regression coverage for the ordinary UDP-backed KCP carrier, before Noise framing.
use anyhow::Result;
use std::time::Duration;
use tokio::{net::UdpSocket, time::timeout};
use tokio_kcp::{KcpConfig, KcpListener, KcpStream};

fn packet(conv: u32, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 24];
    bytes[..4].copy_from_slice(&conv.to_le_bytes());
    bytes[4] = 81;
    bytes[6..8].copy_from_slice(&128u16.to_le_bytes());
    bytes[12..16].copy_from_slice(&sequence.to_le_bytes());
    bytes[20..24].copy_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

#[tokio::test]
async fn client_rejects_other_senders_and_established_conversation_changes() -> Result<()> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let client_address = socket.local_addr()?;
    let mut stream = KcpStream::connect_with_socket_conv(
        &KcpConfig::default(),
        1234,
        socket,
        peer.local_addr()?,
    )
    .await?;
    let stranger = UdpSocket::bind("127.0.0.2:0").await?;
    // A plausible, correctly numbered segment must not supply stream bytes either.
    stranger
        .send_to(&packet(1234, 0, b"untrusted"), client_address)
        .await?;
    let mut invalid = packet(5678, 0, b"");
    invalid[4] = 255;
    stranger.send_to(&invalid, client_address).await?;
    // Even the configured peer cannot silently change an established conversation.
    peer.send_to(&invalid, client_address).await?;
    peer.send_to(&packet(5678, 0, b"wrong conversation"), client_address)
        .await?;
    peer.send_to(&packet(1234, 0, b"expected"), client_address)
        .await?;
    let mut bytes = [0u8; 64];
    let n = timeout(Duration::from_secs(2), stream.recv(&mut bytes)).await??;
    assert_eq!(&bytes[..n], b"expected");
    assert_eq!(stream.shared_session().conv().await, 1234);
    Ok(())
}

#[tokio::test]
async fn reused_udp_address_keeps_the_replacement_stream_alive() -> Result<()> {
    let mut listener = KcpListener::bind(KcpConfig::default(), "127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let sender = UdpSocket::bind("127.0.0.1:0").await?;
    let mut held = Vec::new();
    for conv in [1234, 5678, 1234] {
        sender.send_to(&packet(conv, 0, b"first"), address).await?;
        let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept()).await??;
        let mut bytes = [0u8; 64];
        let n = timeout(Duration::from_secs(2), stream.recv(&mut bytes)).await??;
        assert_eq!(&bytes[..n], b"first");
        // Ensure old-session cleanup has had time to run; it must not close this stream.
        assert!(
            timeout(Duration::from_millis(100), stream.recv(&mut bytes))
                .await
                .is_err()
        );
        sender.send_to(&packet(conv, 1, b"next"), address).await?;
        let n = timeout(Duration::from_secs(2), stream.recv(&mut bytes)).await??;
        assert_eq!(&bytes[..n], b"next");
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        held.push(stream);
    }
    Ok(())
}

#[tokio::test]
async fn explicit_server_allocated_conversations_still_carry_data() -> Result<()> {
    let config = KcpConfig::default();
    let mut listener = KcpListener::bind(config, "127.0.0.1:0").await?;
    let mut client = KcpStream::connect_with_conv(&config, 0, listener.local_addr()?).await?;
    client.send(b"request").await?;
    let (mut server, _) = timeout(Duration::from_secs(2), listener.accept()).await??;
    let mut bytes = [0u8; 64];
    let n = timeout(Duration::from_secs(2), server.recv(&mut bytes)).await??;
    assert_eq!(&bytes[..n], b"request");
    server.send(b"reply").await?;
    let n = timeout(Duration::from_secs(2), client.recv(&mut bytes)).await??;
    assert_eq!(&bytes[..n], b"reply");
    assert_ne!(client.shared_session().conv().await, 0);
    Ok(())
}
