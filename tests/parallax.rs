use anyhow::Result;
use eztunnel::{config::Config, parallax_carrier::Acceptor};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{Duration, timeout},
};

async fn setup() -> Result<(Acceptor, eztunnel::config::ClientPath)> {
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?.to_string();
    let key = eztunnel::tunnel_key::TunnelKey::generate()?.display();
    let mut server: Config = serde_json::from_value(
        serde_json::json!({"mode":"server","tunnel_key":key,
        "listeners":[{"addr":address,"transport":"parallax","parallax":{"max_pending_per_ip":64}}]}),
    )?;
    let mut client: Config =
        serde_json::from_value(serde_json::json!({"mode":"client","tunnel_key":key,
        "allowed_targets":["127.0.0.1:*"],"paths":[{"addr":address,"transport":"parallax"}]}))?;
    server.prepare()?;
    client.prepare()?;
    server.validate()?;
    client.validate()?;
    Ok((
        Acceptor::from_listener(socket, server.listeners[0].clone())?,
        client.paths[0].clone(),
    ))
}

#[tokio::test]
async fn large_simultaneous_duplex_and_half_close() -> Result<()> {
    timeout(Duration::from_secs(20), async {
        let (mut accept, path) = setup().await?;
        let mut client = eztunnel::parallax_carrier::connect(&path).await?;
        let (mut server, ip) = accept.accept().await?;
        assert!(ip.is_loopback());
        let payload: Vec<u8> = (0..1048576).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        let peer = tokio::spawn(async move {
            let (mut read, mut write) = tokio::io::split(&mut server);
            let send = async {
                write.write_all(&payload).await?;
                write.shutdown().await
            };
            let receive = async {
                let mut got = Vec::new();
                read.read_to_end(&mut got).await?;
                assert_eq!(got, payload);
                Ok::<_, std::io::Error>(())
            };
            tokio::try_join!(send, receive)?;
            Ok::<_, anyhow::Error>(())
        });
        let (mut read, mut write) = tokio::io::split(&mut client);
        let send = async {
            for part in expected.chunks(7) {
                write.write_all(part).await?;
            }
            write.shutdown().await
        };
        let receive = async {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await?;
            assert_eq!(got, expected);
            Ok::<_, std::io::Error>(())
        };
        tokio::try_join!(send, receive)?;
        peer.await??;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn independent_concurrent_pairs_and_reconnect() -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let (mut accept, path) = setup().await?;
        let mut clients = Vec::new();
        for n in 0..12u8 {
            let path = path.clone();
            clients.push(tokio::spawn(async move {
                let mut stream = eztunnel::parallax_carrier::connect(&path).await?;
                stream.write_all(&[n; 32768]).await?;
                stream.shutdown().await?;
                let mut got = Vec::new();
                stream.read_to_end(&mut got).await?;
                assert!(
                    got == vec![n; 32768],
                    "pair payload mismatch: {} bytes",
                    got.len()
                );
                Ok::<_, anyhow::Error>(())
            }));
        }
        let mut peers = Vec::new();
        for _ in 0..12 {
            let (mut stream, _) = accept.accept().await?;
            peers.push(tokio::spawn(async move {
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await?;
                stream.write_all(&data).await?;
                stream.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            }));
        }
        for task in clients {
            task.await??;
        }
        for task in peers {
            task.await??;
        }
        let mut next = eztunnel::parallax_carrier::connect(&path).await?;
        let (mut peer, _) = accept.accept().await?;
        next.write_all(b"fresh").await?;
        let mut got = [0; 5];
        peer.read_exact(&mut got).await?;
        assert_eq!(&got, b"fresh");
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn wrong_key_does_not_create_a_session() -> Result<()> {
    let (mut accept, mut path) = setup().await?;
    let mut wrong: Config = serde_json::from_value(serde_json::json!({"mode":"client",
        "tunnel_key":eztunnel::tunnel_key::TunnelKey::generate()?.display(),
        "allowed_targets":["127.0.0.1:*"],"paths":[{"addr":path.addr,"transport":"parallax"}]}))?;
    wrong.prepare()?;
    path.parallax_key = wrong.paths[0].parallax_key.clone();
    assert!(eztunnel::parallax_carrier::connect(&path).await.is_err());
    assert!(
        timeout(Duration::from_millis(50), accept.accept())
            .await
            .is_err()
    );
    Ok(())
}
