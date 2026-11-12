//! Exercise actual network carriers, rather than just carrier configuration names.
use anyhow::{Context, Result, ensure};
use eztunnel::{
    config::{self, ClientPath, Config, Listener},
    engine, transport,
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::{sleep, timeout},
};

fn configured(value: Value) -> Result<Config> {
    let mut config: Config = serde_json::from_value(value)?;
    config.prepare()?;
    config.validate()?;
    Ok(config)
}

async fn echo_tcp(address: SocketAddr, payload: &[u8]) -> Result<()> {
    let stream = TcpStream::connect(address).await?;
    let (mut reader, mut writer) = stream.into_split();
    let mut response = Vec::new();
    tokio::try_join!(
        async {
            writer.write_all(payload).await?;
            writer.shutdown().await
        },
        reader.read_to_end(&mut response)
    )?;
    ensure!(response == payload, "TCP data/EOF changed");
    Ok(())
}

async fn exercise_carrier(name: &str, wire_version: u8, chrome: bool) -> Result<()> {
    exercise_direction(name, wire_version, chrome, false).await
}

async fn exercise_direction(
    name: &str,
    wire_version: u8,
    chrome: bool,
    reverse: bool,
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (server_private, server_public) =
        config::generate_keypair(&directory.path().join("server"))?;
    let (client_private, client_public) =
        config::generate_keypair(&directory.path().join("client"))?;
    let tls = matches!(name, "https" | "wss" | "xhttps");
    let (cert, key) =
        config::generate_certificate(&directory.path().join("tls"), vec!["localhost".into()])?;
    let tunnel = TcpListener::bind(if name == "tcp6" {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    })
    .await
    .context("reserve tunnel socket")?;
    let kcp_reservation = if matches!(name, "kcp" | "fec-udp") {
        Some(UdpSocket::bind("127.0.0.1:0").await?)
    } else {
        None
    };
    let tunnel_addr = if let Some(socket) = &kcp_reservation {
        socket.local_addr()?
    } else {
        tunnel.local_addr()?
    };
    if name == "tcp6" {
        ensure!(tunnel_addr.is_ipv6(), "TCP6 test must use IPv6");
    }
    let tcp_reserve = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_bind = tcp_reserve.local_addr()?;
    let socks_reserve = TcpListener::bind("127.0.0.1:0").await?;
    let socks_bind = socks_reserve.local_addr()?;
    let udp_reserve = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_bind = udp_reserve.local_addr()?;
    let tcp_echo = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_target = tcp_echo.local_addr()?;
    let udp_echo = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_target = udp_echo.local_addr()?;
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    tasks.spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = tcp_echo.accept() => {
                    let (mut stream, _) = accepted?;
                    connections.spawn(async move {
                        let (mut read, mut write) = stream.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {},
            }
        }
    });
    tasks.spawn(async move {
        let mut buffer = vec![0; 65536];
        loop {
            let (count, sender) = udp_echo.recv_from(&mut buffer).await?;
            udp_echo.send_to(&buffer[..count], sender).await?;
        }
    });
    let mut listener = json!({"addr":tunnel_addr.to_string(), "transport":name, "http_path":"/integration/tunnel", "maps":[
        {"type":"tcp","bind":tcp_bind.to_string(),"target":tcp_target.to_string()},
        {"type":"udp","bind":udp_bind.to_string(),"target":udp_target.to_string()}
    ]});
    let mut path = json!({"addr":tunnel_addr.to_string(),"transport":name,"http_path":"/integration/tunnel", "server_public_key":server_public,"dial_timeout":3,"retry_interval":1});
    if name == "fec-udp" {
        listener["fec"] = json!({"knock":false});
        path["fec"] = json!({"knock":false});
    }
    if tls {
        listener["cert_file"] = json!(cert);
        listener["key_file"] = json!(key);
        path["ca_file"] = json!(cert);
        path["server_name"] = json!("localhost");
        if chrome {
            path["tls_profile"] = json!("chrome");
        }
    }
    // Version 2 runs with record padding and burst jitter on, so every carrier proves that the
    // shaped records still arrive intact.
    let shaping = if wire_version == 2 {
        json!({"record_pad_max": 200, "jitter_ms": 5})
    } else {
        json!({})
    };
    let mut server_value = json!({"mode":"server","wire_version":wire_version,"stealth":shaping,"private_key_file":server_private,"peer_public_keys":[client_public],"listeners":[listener],"socks5":socks_bind.to_string(),"heartbeat_sec":1,"dead_timeout_sec":5});
    let mut client_value = json!({"mode":"client","wire_version":wire_version,"stealth":shaping,"private_key_file":client_private,"paths":[path],"allowed_targets":[tcp_target.to_string(),udp_target.to_string()],"heartbeat_sec":1,"dead_timeout_sec":5});
    if name == "parallax" {
        let key = eztunnel::tunnel_key::TunnelKey::generate()?.display();
        server_value["tunnel_key"] = json!(key);
        client_value["tunnel_key"] = json!(key);
        server_value
            .as_object_mut()
            .unwrap()
            .remove("private_key_file");
        server_value
            .as_object_mut()
            .unwrap()
            .remove("peer_public_keys");
        client_value
            .as_object_mut()
            .unwrap()
            .remove("private_key_file");
        client_value["paths"][0]
            .as_object_mut()
            .unwrap()
            .remove("server_public_key");
    }
    server_value["server_dials"] = json!(reverse);
    client_value["server_dials"] = json!(reverse);
    let server = configured(server_value)?;
    let client = configured(client_value)?;
    drop((
        tunnel,
        kcp_reservation,
        tcp_reserve,
        socks_reserve,
        udp_reserve,
    ));
    tasks.spawn(engine::run(server));
    tasks.spawn(engine::run(client));
    timeout(Duration::from_secs(15), async {
        loop {
            if matches!(
                timeout(Duration::from_millis(600), echo_tcp(tcp_bind, b"ready")).await,
                Ok(Ok(()))
            ) {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("carrier did not become ready")?;
    // More than sixteen full-sized frames forces the credit window to refill.
    let payload: Vec<u8> = (0..1_048_577).map(|index| (index % 251) as u8).collect();
    timeout(Duration::from_secs(15), echo_tcp(tcp_bind, &payload))
        .await
        .context("bulk TCP credit/EOF timeout")??;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    for index in 0..40u8 {
        let message = vec![index; if index == 0 { 0 } else { 1000 }];
        socket.send_to(&message, udp_bind).await?;
        let mut response = vec![0; 16384];
        let (count, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut response))
            .await
            .context("UDP credit/empty datagram timeout")??;
        ensure!(response[..count] == message, "UDP payload changed");
    }
    let mut socks = TcpStream::connect(socks_bind).await?;
    socks.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    socks.read_exact(&mut greeting).await?;
    ensure!(greeting == [5, 0], "SOCKS greeting failed");
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&tcp_target.port().to_be_bytes());
    socks.write_all(&request).await?;
    let mut reply = [0; 10];
    socks.read_exact(&mut reply).await?;
    ensure!(reply[0..4] == [5, 0, 0, 1], "SOCKS CONNECT failed");
    socks.write_all(b"carrier socks").await?;
    let mut response = [0; 13];
    socks.read_exact(&mut response).await?;
    ensure!(&response == b"carrier socks", "SOCKS data changed");
    drop(socks);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_carriers_forward_tcp_udp_and_socks() -> Result<()> {
    for name in [
        "tcp", "http", "https", "ws", "wss", "xhttp", "xhttps", "tcp6", "kcp", "fec-udp",
    ] {
        eprintln!("testing carrier {name}");
        timeout(Duration::from_secs(35), exercise_carrier(name, 1, false))
            .await
            .with_context(|| format!("carrier {name} timed out"))?
            .with_context(|| format!("carrier {name}"))?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallax_forwards_tcp_udp_socks_and_all_wire_presentations() -> Result<()> {
    for wire in 1..=3 {
        timeout(
            Duration::from_secs(40),
            exercise_carrier("parallax", wire, false),
        )
        .await??;
    }
    timeout(
        Duration::from_secs(40),
        exercise_direction("parallax", 2, false, true),
    )
    .await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_carriers_forward_tcp_udp_and_socks_with_wire_version_2() -> Result<()> {
    for name in [
        "tcp", "http", "https", "ws", "wss", "xhttp", "xhttps", "tcp6", "kcp", "fec-udp",
    ] {
        eprintln!("testing carrier {name} (wire version 2)");
        timeout(Duration::from_secs(35), exercise_carrier(name, 2, false))
            .await
            .with_context(|| format!("carrier {name} timed out"))?
            .with_context(|| format!("carrier {name}"))?;
    }
    Ok(())
}

/// The Chrome-like TLS client checks a certificate file and a name through BoringSSL, and the
/// listener serves the ordinary certificate files it was given.
#[cfg(feature = "browser-tls")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_chrome_profile_works_with_certificate_files() -> Result<()> {
    for name in ["https", "wss", "xhttps"] {
        eprintln!("testing carrier {name} with the chrome profile and a CA file");
        timeout(Duration::from_secs(35), exercise_carrier(name, 2, true))
            .await
            .with_context(|| format!("carrier {name} timed out"))?
            .with_context(|| format!("carrier {name}"))?;
    }
    Ok(())
}

async fn rejected_handshake(name: &str, failure: &str) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (server_key, server_public) = config::generate_keypair(&directory.path().join("server"))?;
    let (client_key, client_public) = config::generate_keypair(&directory.path().join("client"))?;
    let server_private = config::decode_key(std::fs::read_to_string(server_key)?.trim())?;
    let client_private = config::decode_key(std::fs::read_to_string(client_key)?.trim())?;
    let authorized = config::decode_key(&client_public)?;
    let (cert, key) =
        config::generate_certificate(&directory.path().join("tls"), vec!["localhost".into()])?;
    let (other_cert, _) = config::generate_certificate(
        &directory.path().join("other-tls"),
        vec!["localhost".into()],
    )?;
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?.to_string();
    let tls = matches!(name, "https" | "wss" | "xhttps");
    let mut listener = json!({"addr":addr,"transport":name,"http_path":"/correct","maps":[]});
    let mut path = json!({"addr":addr,"transport":name,"http_path":"/correct","server_public_key":server_public,"dial_timeout":3});
    if tls {
        listener["cert_file"] = json!(cert);
        listener["key_file"] = json!(key);
        path["ca_file"] = json!(if failure == "ca" { &other_cert } else { &cert });
        path["server_name"] = json!(if failure == "hostname" {
            "wrong.invalid"
        } else {
            "localhost"
        });
    }
    if failure == "path" {
        path["http_path"] = json!("/wrong");
    }
    let listener: Listener = serde_json::from_value(listener)?;
    let path: ClientPath = serde_json::from_value(path)?;
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let (stream, _) = socket.accept().await?;
        transport::accept_listener(
            eztunnel::kcp_carrier::Incoming::Tcp(stream),
            &listener,
            &server_private,
            &[authorized],
            Duration::from_secs(3),
        )
        .await
    });
    let result = timeout(
        Duration::from_secs(5),
        transport::connect_path(&path, &client_private),
    )
    .await?;
    ensure!(result.is_err(), "{name} accepted incorrect {failure}");
    let accepted = timeout(Duration::from_secs(5), tasks.join_next())
        .await?
        .context("server task missing")??;
    ensure!(
        accepted.is_err(),
        "server returned authenticated connection after incorrect {failure}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn carriers_reject_bad_tls_trust_names_and_paths() -> Result<()> {
    for name in ["https", "wss", "xhttps"] {
        for failure in ["ca", "hostname"] {
            rejected_handshake(name, failure)
                .await
                .with_context(|| format!("{name} {failure}"))?;
        }
    }
    for name in ["http", "https", "ws", "wss", "xhttp", "xhttps"] {
        rejected_handshake(name, "path")
            .await
            .with_context(|| format!("{name} path"))?;
    }
    Ok(())
}
