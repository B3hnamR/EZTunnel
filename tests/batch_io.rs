//! The batched UDP helpers of the vendored KCP crate (its own tests cannot run in this workspace).
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_kcp::batch::{Incoming, Outgoing};

async fn pair() -> (UdpSocket, UdpSocket) {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    (a, b)
}

#[tokio::test]
async fn a_batch_arrives_whole_in_order_with_its_source() {
    let (sender, receiver) = pair().await;
    let mut outgoing = Outgoing::default();
    let packets: Vec<Vec<u8>> = (0..50u8)
        .map(|i| vec![i; 1 + usize::from(i) * 20])
        .collect();
    for packet in &packets {
        outgoing.push(packet);
    }
    assert_eq!(outgoing.len(), 50);
    assert_eq!(outgoing.packet(7), packets[7].as_slice());
    let target = receiver.local_addr().unwrap();
    // tokio only lets a send through once the reactor has reported the socket writable.
    sender.writable().await.unwrap();
    assert_eq!(outgoing.send(&sender, Some(target)).unwrap(), 50);
    let mut incoming = Incoming::new();
    let mut seen = 0;
    while seen < 50 {
        let count = tokio::time::timeout(Duration::from_secs(2), incoming.receive(&receiver))
            .await
            .unwrap()
            .unwrap();
        for index in 0..count {
            let (packet, source) = incoming.packet(index);
            assert_eq!(packet, packets[seen].as_slice());
            assert_eq!(source, Some(sender.local_addr().unwrap()));
            seen += 1;
        }
    }
}

#[tokio::test]
async fn more_than_one_batch_and_a_connected_socket_work() {
    let (sender, receiver) = pair().await;
    sender
        .connect(receiver.local_addr().unwrap())
        .await
        .unwrap();
    let mut outgoing = Outgoing::default();
    for i in 0..150u32 {
        outgoing.push(&i.to_be_bytes());
    }
    sender.writable().await.unwrap();
    assert_eq!(outgoing.send(&sender, None).unwrap(), 150);
    let mut incoming = Incoming::new();
    let mut numbers = Vec::new();
    while numbers.len() < 150 {
        let count = tokio::time::timeout(Duration::from_secs(2), incoming.receive(&receiver))
            .await
            .unwrap()
            .unwrap();
        for index in 0..count {
            let (packet, _) = incoming.packet(index);
            numbers.push(u32::from_be_bytes(packet.try_into().unwrap()));
        }
    }
    assert_eq!(numbers, (0..150).collect::<Vec<u32>>());
}

#[tokio::test]
async fn an_empty_datagram_and_ipv6_are_carried() {
    let sender = UdpSocket::bind("[::1]:0").await.unwrap();
    let receiver = UdpSocket::bind("[::1]:0").await.unwrap();
    let mut outgoing = Outgoing::default();
    outgoing.push(&[]);
    outgoing.push(b"x");
    sender.writable().await.unwrap();
    assert_eq!(
        outgoing
            .send(&sender, Some(receiver.local_addr().unwrap()))
            .unwrap(),
        2
    );
    let mut incoming = Incoming::new();
    let mut lengths = Vec::new();
    while lengths.len() < 2 {
        let count = tokio::time::timeout(Duration::from_secs(2), incoming.receive(&receiver))
            .await
            .unwrap()
            .unwrap();
        for index in 0..count {
            let (packet, source) = incoming.packet(index);
            lengths.push(packet.len());
            assert_eq!(source, Some(sender.local_addr().unwrap()));
        }
    }
    assert_eq!(lengths, [0, 1]);
}
