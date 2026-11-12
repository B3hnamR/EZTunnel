//! Real HTTP sessions: direct packet uploads, TLS, reversed physical roles,
//! and auto fallback through a proxy that buffers streaming request bodies.
use anyhow::{Context, Result, ensure};
use eztunnel::{
    config::{self, ClientPath, Config, Listener},
    engine,
    kcp_carrier::Incoming,
    transport,
    xhttp_carrier::Acceptor,
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::{sleep, timeout},
};

#[derive(Default)]
struct Observations {
    probes: AtomicUsize,
    packets: AtomicUsize,
    downloads: AtomicUsize,
}

async fn headers<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        ensure!(bytes.len() < 8192, "proxy request header too large");
        bytes.push(reader.read_u8().await?);
    }
    Ok(bytes)
}

/// Deliberately buffers chunked uploads before contacting the origin. Auto
/// must detect this, abandon its unfinished probe, and send finite POSTs.
async fn buffering_proxy(
    listener: TcpListener,
    origin: SocketAddr,
    observations: Arc<Observations>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (client, _) = accepted?;
                let observations = observations.clone();
                connections.spawn(async move {
                    let origin = TcpStream::connect(origin).await?;
                    let (mut cr, mut cw) = client.into_split();
                    let (mut sr, mut sw) = origin.into_split();
                    let upload = async {
                        loop {
                            let header = headers(&mut cr).await?;
                            let text = std::str::from_utf8(&header)?;
                            ensure!(text.contains("\r\nHost: cdn.test\r\n"), "configured HTTP Host missing at edge");
                            ensure!(text.contains("\r\nUser-Agent: eztunnel-test\r\n"), "configured User-Agent missing at edge");
                            let url = text.lines().next().context("proxy request line missing")?.split(' ').nth(1).context("proxy request URL missing")?;
                            let padding = url.split_once("?v=").context("configured request padding missing at edge")?.1;
                            ensure!((8..=48).contains(&padding.len()) && padding.bytes().all(|b| b.is_ascii_alphanumeric()), "edge saw invalid query padding");
                            let mut body = Vec::new();
                            if text.contains("Transfer-Encoding: chunked\r\n") {
                                observations.probes.fetch_add(1, Ordering::Relaxed);
                                loop {
                                    let mut line = Vec::new();
                                    while !line.ends_with(b"\r\n") { line.push(cr.read_u8().await?); }
                                    ensure!(line.len() < 32, "proxy chunk length too large");
                                    let count = usize::from_str_radix(std::str::from_utf8(&line[..line.len()-2])?, 16)?;
                                    ensure!(body.len() + count <= 131_072, "proxy probe body too large");
                                    body.extend_from_slice(&line);
                                    let start = body.len();
                                    body.resize(start + count + 2, 0);
                                    cr.read_exact(&mut body[start..]).await?;
                                    if count == 0 { break; }
                                }
                            } else if let Some(length) = text.lines().find_map(|line| line.strip_prefix("Content-Length: ")) {
                                let count: usize = length.parse()?;
                                ensure!(count <= 65536, "packet exceeded configured finite request size");
                                body.resize(count, 0);
                                cr.read_exact(&mut body).await?;
                                observations.packets.fetch_add(1, Ordering::Relaxed);
                            } else {
                                ensure!(text.starts_with("GET "), "unexpected edge request");
                                observations.downloads.fetch_add(1, Ordering::Relaxed);
                            }
                            sw.write_all(&header).await?;
                            sw.write_all(&body).await?;
                            sw.flush().await?;
                        }
                        #[allow(unreachable_code)]
                        anyhow::Ok(())
                    };
                    let download = async { tokio::io::copy(&mut sr, &mut cw).await?; anyhow::Ok(()) };
                    tokio::try_join!(upload, download)?;
                    anyhow::Ok(())
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

fn configuration(value: Value) -> Result<Config> {
    let config: Config = serde_json::from_value(value)?;
    config.validate()?;
    Ok(config)
}

async fn echo(address: SocketAddr, body: &[u8]) -> Result<()> {
    let stream = TcpStream::connect(address).await?;
    let (mut read, mut write) = stream.into_split();
    let mut reply = Vec::new();
    tokio::try_join!(
        async {
            write.write_all(body).await?;
            write.shutdown().await
        },
        read.read_to_end(&mut reply)
    )?;
    ensure!(reply == body, "packet-up TCP data/half-close changed");
    Ok(())
}

async fn exercise(transport: &str, mode: &str, reverse: bool, proxy: bool) -> Result<()> {
    exercise_with(transport, mode, reverse, proxy, None).await
}

async fn exercise_with(
    transport: &str,
    mode: &str,
    reverse: bool,
    proxy: bool,
    token: Option<&str>,
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (server_private, server_public) =
        config::generate_keypair(&directory.path().join("server"))?;
    let (client_private, client_public) =
        config::generate_keypair(&directory.path().join("client"))?;
    let (cert, key) =
        config::generate_certificate(&directory.path().join("tls"), vec!["cdn.test".into()])?;
    let tunnel = TcpListener::bind("127.0.0.1:0").await?;
    let origin = tunnel.local_addr()?;
    let edge = if proxy {
        Some(TcpListener::bind("127.0.0.1:0").await?)
    } else {
        None
    };
    let dial = edge
        .as_ref()
        .map(|socket| socket.local_addr())
        .transpose()?
        .unwrap_or(origin);
    let unavailable = TcpListener::bind("127.0.0.1:0").await?;
    let unavailable_addr = unavailable.local_addr()?;
    let mut edge_addrs = vec![unavailable_addr.to_string(), dial.to_string()];
    let _invalid_tls_edge = if transport == "xhttps" {
        let (other_cert, other_key) = config::generate_certificate(
            &directory.path().join("wrong-edge"),
            vec!["unrelated.test".into()],
        )?;
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let listener: Listener = serde_json::from_value(
            json!({"addr":address.to_string(),"transport":"xhttps","cert_file":other_cert,"key_file":other_key}),
        )?;
        edge_addrs.insert(0, address.to_string());
        Some(Acceptor::from_listener(socket, listener)?)
    } else {
        None
    };
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
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = tcp_echo.accept() => {
                    let (stream, _) = accepted?;
                    connections.spawn(async move {
                        let (mut r, mut w) = stream.into_split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    });
    tasks.spawn(async move {
        let mut buffer = vec![0; 16384];
        loop {
            let (count, peer) = udp_echo.recv_from(&mut buffer).await?;
            udp_echo.send_to(&buffer[..count], peer).await?;
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    });
    let observations = Arc::new(Observations::default());
    if let Some(edge) = edge {
        tasks.spawn(buffering_proxy(edge, origin, observations.clone()));
    }
    let mut options = json!({"mode":mode,"host":"cdn.test","edge_addrs":edge_addrs,"up_max_bytes":8192,"up_concurrency":4,"buffer_bytes":16384,"probe_ms":250,"session_timeout_sec":20,"pad_min":8,"pad_max":48,"socket_buf_bytes":131072,"user_agent":"eztunnel-test"});
    if let Some(token) = token {
        options["access_token"] = json!(token);
    }
    let mut listener = json!({"addr":if reverse {dial} else {origin}.to_string(),"transport":transport,"http_path":"/cdn/test","xhttp":options,"maps":[
        {"type":"tcp","bind":tcp_bind.to_string(),"target":tcp_target.to_string()},
        {"type":"udp","bind":udp_bind.to_string(),"target":udp_target.to_string()}
    ]});
    let mut path = json!({"addr":if reverse {origin} else {dial}.to_string(),"transport":transport,"http_path":"/cdn/test","xhttp":options,"server_public_key":server_public,"dial_timeout":10,"retry_interval":1});
    if transport == "xhttps" {
        if reverse {
            listener["ca_file"] = json!(cert);
            listener["server_name"] = json!("unused.example");
            path["cert_file"] = json!(cert);
            path["key_file"] = json!(key);
        } else {
            listener["cert_file"] = json!(cert);
            listener["key_file"] = json!(key);
            path["ca_file"] = json!(cert);
            path["server_name"] = json!("unused.example");
        }
    }
    let server = configuration(
        json!({"mode":"server","reverse":reverse,"private_key_file":server_private,"peer_public_keys":[client_public],"listeners":[listener],"socks5":socks_bind.to_string(),"heartbeat_sec":1,"dead_timeout_sec":10}),
    )?;
    let client = configuration(
        json!({"mode":"client","reverse":reverse,"private_key_file":client_private,"paths":[path],"allowed_targets":[tcp_target.to_string(),udp_target.to_string()],"heartbeat_sec":1,"dead_timeout_sec":10}),
    )?;
    drop((tunnel, unavailable, tcp_reserve, socks_reserve, udp_reserve));
    tasks.spawn(engine::run(server));
    tasks.spawn(engine::run(client));
    timeout(Duration::from_secs(30), async {
        loop {
            if matches!(
                timeout(Duration::from_millis(750), echo(tcp_bind, b"ready")).await,
                Ok(Ok(()))
            ) {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("XHTTP tunnel did not become ready")?;
    let body: Vec<_> = (0..1_048_577).map(|i| (i % 251) as u8).collect();
    timeout(Duration::from_secs(45), echo(tcp_bind, &body))
        .await
        .context("XHTTP bulk transfer/half-close timed out")??;
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    for size in [0, 1, 512, 4096, 16384] {
        let body = vec![17; size];
        udp.send_to(&body, udp_bind).await?;
        let mut reply = vec![0; 16384];
        let (count, _) = timeout(Duration::from_secs(5), udp.recv_from(&mut reply)).await??;
        ensure!(reply[..count] == body, "XHTTP UDP payload changed");
    }
    let mut socks = TcpStream::connect(socks_bind).await?;
    socks.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    socks.read_exact(&mut greeting).await?;
    ensure!(greeting == [5, 0], "XHTTP SOCKS greeting failed");
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&tcp_target.port().to_be_bytes());
    socks.write_all(&request).await?;
    let mut response = [0; 10];
    socks.read_exact(&mut response).await?;
    ensure!(response[..4] == [5, 0, 0, 1], "XHTTP SOCKS CONNECT failed");
    socks.write_all(b"through edge").await?;
    let mut response = [0; 12];
    socks.read_exact(&mut response).await?;
    ensure!(&response == b"through edge", "XHTTP SOCKS data changed");
    if proxy {
        ensure!(
            observations.probes.load(Ordering::Relaxed) >= 1,
            "auto did not probe streaming"
        );
        ensure!(
            observations.packets.load(Ordering::Relaxed) > 8,
            "auto failed to select finite packet uploads"
        );
        ensure!(
            observations.downloads.load(Ordering::Relaxed) >= 1,
            "edge saw no download GET"
        );
    }
    drop(socks);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn packet_up_plain_and_tls_keep_logical_roles_in_both_directions() -> Result<()> {
    for transport in ["xhttp", "xhttps"] {
        for reverse in [false, true] {
            eprintln!("XHTTP packet-up {transport} reverse={reverse}");
            exercise(transport, "packet-up", reverse, false)
                .await
                .with_context(|| format!("{transport} packet-up reverse={reverse}"))?;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_falls_back_through_buffering_http_proxy_in_both_directions() -> Result<()> {
    for reverse in [false, true] {
        eprintln!("XHTTP auto buffering edge reverse={reverse}");
        exercise("xhttp", "auto", reverse, true)
            .await
            .with_context(|| format!("buffering edge reverse={reverse}"))?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnels_work_with_an_access_token_in_every_mode() -> Result<()> {
    let token = "integration-test-access-token";
    for mode in ["stream-up", "packet-up", "auto"] {
        exercise_with("xhttp", mode, false, false, Some(token))
            .await
            .with_context(|| format!("access token with mode {mode}"))?;
    }
    exercise_with("xhttps", "packet-up", true, false, Some(token))
        .await
        .context("access token with reversed roles over TLS")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_uses_streaming_when_origin_accepts_unfinished_upload() -> Result<()> {
    exercise("xhttp", "auto", false, false).await
}

async fn rejected_identity(reverse: bool, wrong_server_pin: bool) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (server_file, server_public) = config::generate_keypair(&directory.path().join("server"))?;
    let (client_file, client_public) = config::generate_keypair(&directory.path().join("client"))?;
    let (_, other_public) = config::generate_keypair(&directory.path().join("other"))?;
    let server_private = config::decode_key(std::fs::read_to_string(server_file)?.trim())?;
    let client_private = config::decode_key(std::fs::read_to_string(client_file)?.trim())?;
    let allowed = config::decode_key(if wrong_server_pin {
        &client_public
    } else {
        &other_public
    })?;
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?.to_string();
    let listener: Listener = serde_json::from_value(
        json!({"addr":address,"transport":"xhttp","xhttp":{"mode":"packet-up"}}),
    )?;
    let path: ClientPath = serde_json::from_value(
        json!({"addr":address,"transport":"xhttp","xhttp":{"mode":"packet-up"},"server_public_key":if wrong_server_pin {&other_public} else {&server_public},"dial_timeout":3}),
    )?;
    let mut acceptor = Acceptor::from_listener(socket, listener.clone())?;
    let mut tasks = JoinSet::new();
    let result = if reverse {
        tasks.spawn(async move {
            let io = acceptor.accept().await?;
            transport::accept_initiator(Incoming::Xhttp(io), &path, &client_private).await
        });
        timeout(
            Duration::from_secs(5),
            transport::connect_responder(&listener, &server_private, &[allowed], 30),
        )
        .await?
    } else {
        tasks.spawn(async move {
            let io = acceptor.accept().await?;
            transport::accept_listener(
                Incoming::Xhttp(io),
                &listener,
                &server_private,
                &[allowed],
                Duration::from_secs(3),
            )
            .await
        });
        timeout(
            Duration::from_secs(5),
            transport::connect_path(&path, &client_private),
        )
        .await?
    };
    ensure!(
        result.is_err(),
        "XHTTP accepted wrong logical peer identity"
    );
    let accepted = timeout(Duration::from_secs(5), tasks.join_next())
        .await?
        .context("identity task missing")??;
    ensure!(
        accepted.is_err(),
        "opposite physical role returned authenticated connection after identity failure"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reversed_http_connections_still_require_logical_pinned_identities() -> Result<()> {
    for reverse in [false, true] {
        for wrong_server_pin in [false, true] {
            rejected_identity(reverse, wrong_server_pin)
                .await
                .with_context(|| {
                    format!("reverse={reverse}, wrong_server_pin={wrong_server_pin}")
                })?;
        }
    }
    Ok(())
}
