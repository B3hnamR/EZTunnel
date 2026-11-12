//! Tunnels configured with one shared tunnel key, in both directions, over every normal carrier.
use anyhow::{Context, Result, ensure};
use eztunnel::{config::Config, engine, tunnel_key::TunnelKey};
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
    eztunnel::transport::validate_tls_config(&config)?;
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

/// Reserves a free local port of the kind the carrier listens on.
async fn free_tunnel_addr(name: &str) -> Result<SocketAddr> {
    Ok(if matches!(name, "kcp" | "fec-udp") {
        UdpSocket::bind("127.0.0.1:0").await?.local_addr()?
    } else if name == "tcp6" {
        TcpListener::bind("[::1]:0").await?.local_addr()?
    } else {
        TcpListener::bind("127.0.0.1:0").await?.local_addr()?
    })
}

async fn exercise(name: &str, server_dials: bool, key: &str, client_key: &str) -> Result<()> {
    exercise_with(name, server_dials, key, client_key, false, false).await
}

async fn exercise_with(
    name: &str,
    server_dials: bool,
    key: &str,
    client_key: &str,
    fragment: bool,
    chrome: bool,
) -> Result<()> {
    let wait = if key == client_key { 12 } else { 4 };
    let tunnel_addr = free_tunnel_addr(name).await?;
    let tcp_bind = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
    let udp_bind = UdpSocket::bind("127.0.0.1:0").await?.local_addr()?;
    let tcp_echo = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_target = tcp_echo.local_addr()?;
    let udp_echo = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_target = udp_echo.local_addr()?;
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    tasks.spawn(async move {
        loop {
            let (mut stream, _) = tcp_echo.accept().await?;
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    tasks.spawn(async move {
        let mut buffer = vec![0; 65536];
        loop {
            let (count, sender) = udp_echo.recv_from(&mut buffer).await?;
            udp_echo.send_to(&buffer[..count], sender).await?;
        }
    });
    let tls = matches!(name, "https" | "wss" | "xhttps");
    let mut listener = json!({"addr":tunnel_addr.to_string(),"transport":name,"maps":[
        {"type":"tcp","bind":tcp_bind.to_string(),"target":tcp_target.to_string()},
        {"type":"udp","bind":udp_bind.to_string(),"target":udp_target.to_string()}
    ]});
    let mut path = json!({"addr":tunnel_addr.to_string(),"transport":name,"dial_timeout":3,"retry_interval":1});
    if tls {
        listener["tls_auto"] = json!(true);
        path["tls_auto"] = json!(true);
        if chrome {
            // Only the side that dials has a TLS client to shape.
            if server_dials {
                listener["tls_profile"] = json!("chrome");
            } else {
                path["tls_profile"] = json!("chrome");
            }
        }
        if fragment {
            // Only the dialing side splits its ClientHello; setting it on both is harmless.
            let split = json!({"enabled": true, "min_bytes": 3, "max_bytes": 20, "delay_ms": 2});
            listener["tls_fragment"] = split.clone();
            path["tls_fragment"] = split;
        }
    }
    if server_dials {
        listener["connection_pool"] = json!(2);
    } else {
        path["connection_pool"] = json!(2);
    }
    let server = configured(json!({
        "mode":"server","server_dials":server_dials,"tunnel_key":key,"listeners":[listener],
        "heartbeat_sec":1,"dead_timeout_sec":5
    }))?;
    let client = configured(json!({
        "mode":"client","server_dials":server_dials,"tunnel_key":client_key,"paths":[path],
        "allowed_targets":["127.0.0.1:*"],"heartbeat_sec":1,"dead_timeout_sec":5
    }))?;
    tasks.spawn(engine::run(server));
    tasks.spawn(engine::run(client));
    let ready = timeout(Duration::from_secs(wait), async {
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
    .await;
    if ready.is_err() {
        tasks.abort_all();
        anyhow::bail!("tunnel did not become ready");
    }
    let payload: Vec<u8> = (0..300_000).map(|index| (index % 251) as u8).collect();
    timeout(Duration::from_secs(15), echo_tcp(tcp_bind, &payload))
        .await
        .context("bulk TCP timeout")??;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    for index in 0..10u8 {
        let message = vec![index; 700];
        socket.send_to(&message, udp_bind).await?;
        let mut response = vec![0; 2048];
        let (count, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut response))
            .await
            .context("UDP timeout")??;
        ensure!(response[..count] == message, "UDP payload changed");
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

const CARRIERS: [&str; 10] = [
    "tcp", "tcp6", "http", "https", "ws", "wss", "xhttp", "xhttps", "kcp", "fec-udp",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_tunnel_key_connects_every_carrier_in_both_directions() -> Result<()> {
    let key = TunnelKey::generate()?.display();
    for server_dials in [false, true] {
        for name in CARRIERS {
            eprintln!("carrier {name}, server_dials={server_dials}");
            timeout(
                Duration::from_secs(40),
                exercise(name, server_dials, &key, &key),
            )
            .await
            .with_context(|| format!("{name} server_dials={server_dials} timed out"))?
            .with_context(|| format!("{name} server_dials={server_dials}"))?;
        }
    }
    Ok(())
}

/// The Chrome-like TLS client talks to the same servers, in both directions, with and without a
/// split ClientHello, through every TLS carrier.
#[cfg(feature = "browser-tls")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_chrome_profile_connects_every_tls_carrier_in_both_directions() -> Result<()> {
    let key = TunnelKey::generate()?.display();
    for server_dials in [false, true] {
        for name in ["wss", "https", "xhttps"] {
            for fragment in [false, true] {
                eprintln!(
                    "chrome profile: {name}, server_dials={server_dials}, fragment={fragment}"
                );
                timeout(
                    Duration::from_secs(40),
                    exercise_with(name, server_dials, &key, &key, fragment, true),
                )
                .await
                .with_context(|| format!("{name} server_dials={server_dials} timed out"))?
                .with_context(|| {
                    format!("{name} server_dials={server_dials} fragment={fragment}")
                })?;
            }
        }
    }
    Ok(())
}

/// A Chrome-like client with the wrong tunnel key must not get through either.
#[cfg(feature = "browser-tls")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_chrome_profile_with_a_different_key_never_connects() -> Result<()> {
    let key = TunnelKey::generate()?.display();
    let other = TunnelKey::generate()?.display();
    for server_dials in [false, true] {
        let result = timeout(
            Duration::from_secs(30),
            exercise_with("wss", server_dials, &key, &other, false, true),
        )
        .await
        .context("wrong-key test hung")?;
        ensure!(
            result.is_err(),
            "wss server_dials={server_dials} connected with a different key"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_tunnel_key_never_connects() -> Result<()> {
    let key = TunnelKey::generate()?.display();
    let other = TunnelKey::generate()?.display();
    for server_dials in [false, true] {
        for name in ["tcp", "wss", "xhttps"] {
            let result = timeout(
                Duration::from_secs(30),
                exercise(name, server_dials, &key, &other),
            )
            .await
            .context("wrong-key test hung")?;
            ensure!(
                result.is_err(),
                "{name} server_dials={server_dials} connected with a different key"
            );
        }
    }
    Ok(())
}

#[test]
fn a_tunnel_key_config_must_not_be_readable_by_others() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("tunnel.json");
    let key = TunnelKey::generate()?.display();
    std::fs::write(
        &path,
        json!({"mode":"client","tunnel_key":key,"allowed_targets":["127.0.0.1:*"],
            "paths":[{"addr":"127.0.0.1:7000"}]})
        .to_string(),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        let error = Config::load(&path).expect_err("a readable key file was accepted");
        ensure!(format!("{error:#}").contains("chmod 600"), "{error:#}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let config = Config::load(&path)?;
    ensure!(config.paths[0].server_public_key.len() == 64);
    Ok(())
}

#[test]
fn tunnel_key_rules_are_enforced() -> Result<()> {
    let key = TunnelKey::generate()?.display();
    // One check symbol catches 31 of 32 single typos, so pick a typo it is known to catch.
    let typo = b"0123456789abcdefghjkmnpqrstvwxyz"
        .iter()
        .filter(|&&c| c != key.as_bytes()[0])
        .map(|&c| {
            let mut bytes = key.clone().into_bytes();
            bytes[0] = c;
            String::from_utf8(bytes).unwrap()
        })
        .find(|candidate| TunnelKey::parse(candidate).is_err())
        .context("no detectable typo found")?;
    let base = |extra: Value| {
        let mut value = json!({"mode":"client","tunnel_key":key,"allowed_targets":["127.0.0.1:*"],
            "paths":[{"addr":"127.0.0.1:7000"}]});
        for (name, item) in extra.as_object().unwrap() {
            value[name] = item.clone();
        }
        value
    };
    ensure!(configured(base(json!({}))).is_ok());
    ensure!(configured(base(json!({"tunnel_key":typo}))).is_err());
    ensure!(configured(base(json!({"private_key_file":"private.key"}))).is_err());
    ensure!(
        configured(base(
            json!({"paths":[{"addr":"127.0.0.1:7000","server_public_key":"11".repeat(32)}]})
        ))
        .is_err()
    );
    // tls_auto needs a TLS carrier and a tunnel key.
    ensure!(
        configured(base(
            json!({"paths":[{"addr":"127.0.0.1:7000","transport":"tcp","tls_auto":true}]})
        ))
        .is_err()
    );
    ensure!(
        configured(base(
            json!({"paths":[{"addr":"127.0.0.1:7000","transport":"wss","tls_auto":true}]})
        ))
        .is_ok()
    );
    // Raw carriers have no dialing direction.
    ensure!(
        configured(base(json!({"server_dials":true,
            "paths":[{"addr":"0.0.0.0:7000","transport":"fec-raw","raw":{"peer_ip":"192.0.2.1","l4_port":7000}}]})))
        .is_err()
    );
    // host:* allows every port of one host only.
    ensure!(configured(base(json!({"allowed_targets":["bad host:*"]}))).is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_carriers_work_with_clienthello_fragmentation() -> Result<()> {
    let key = TunnelKey::generate()?.display();
    for server_dials in [false, true] {
        for name in ["wss", "https", "xhttps"] {
            timeout(
                Duration::from_secs(40),
                exercise_with(name, server_dials, &key, &key, true, false),
            )
            .await
            .with_context(|| format!("{name} fragmented timed out"))?
            .with_context(|| format!("{name} fragmented server_dials={server_dials}"))?;
        }
    }
    Ok(())
}
