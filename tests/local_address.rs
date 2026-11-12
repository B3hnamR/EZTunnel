//! `local_address`: the dialing side leaves from the chosen local IP address, and the setting is
//! refused where it would have no effect.
use anyhow::Result;
use eztunnel::{
    config::{ClientPath, Config},
    transport,
};
use serde_json::{Value, json};
use std::{net::IpAddr, time::Duration};
use tokio::{
    net::{TcpListener, UdpSocket},
    time::timeout,
};

fn path(transport: &str, addr: String, local: Option<&str>) -> Result<ClientPath> {
    let mut value = json!({
        "addr": addr, "transport": transport, "server_public_key": "11".repeat(32),
        "dial_timeout": 1,
    });
    if transport == "fec-udp" {
        value["fec"] = json!({"knock": false});
    }
    if let Some(local) = local {
        value["local_address"] = json!(local);
    }
    Ok(serde_json::from_value(value)?)
}

/// Dials in the background and returns when the peer has been seen once.
async fn dial(path: ClientPath) {
    let _ = timeout(
        Duration::from_millis(1500),
        transport::connect_path(&path, &[7; 32]),
    )
    .await;
}

#[tokio::test]
async fn tcp_leaves_from_the_chosen_address() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    for (local, expected) in [(Some("127.0.0.2"), "127.0.0.2"), (None, "127.0.0.1")] {
        let task = tokio::spawn(dial(path("tcp", addr.clone(), local)?));
        let (_stream, peer) = timeout(Duration::from_secs(3), listener.accept()).await??;
        assert_eq!(peer.ip(), expected.parse::<IpAddr>()?);
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn udp_carriers_leave_from_the_chosen_address() -> Result<()> {
    for name in ["kcp", "fec-udp"] {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?.to_string();
        let task = tokio::spawn(dial(path(name, addr, Some("127.0.0.2"))?));
        let mut buffer = [0; 2048];
        let (_, source) = timeout(Duration::from_secs(3), socket.recv_from(&mut buffer)).await??;
        assert_eq!(source.ip(), "127.0.0.2".parse::<IpAddr>()?, "{name}");
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn an_address_that_does_not_fit_the_peer_is_an_error_not_a_silent_fallback() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    // An IPv6 source cannot reach an IPv4 peer.
    let error = transport::connect_path(&path("tcp", addr.clone(), Some("::1"))?, &[7; 32])
        .await
        .err()
        .expect("must fail");
    assert!(format!("{error:#}").contains("IPv6"), "{error:#}");
    // An address the server does not own cannot be bound.
    let error = transport::connect_path(&path("tcp", addr, Some("203.0.113.9"))?, &[7; 32])
        .await
        .err()
        .expect("must fail");
    assert!(format!("{error:#}").contains("local_address"), "{error:#}");
    Ok(())
}

fn accepted(config: Value) -> bool {
    serde_json::from_value::<Config>(config)
        .ok()
        .and_then(|mut config| {
            config.prepare().ok()?;
            config.validate().ok()
        })
        .is_some()
}

fn client(local: Option<&str>, transport: &str, server_dials: bool) -> Value {
    let mut entry = json!({"addr": "127.0.0.1:7000", "transport": transport,
        "server_public_key": "11".repeat(32)});
    if let Some(local) = local {
        entry["local_address"] = json!(local);
    }
    if transport == "fec-raw" {
        entry["raw"] = json!({"profile":"tcp","peer_ip":"192.0.2.1","l4_port":7000});
    }
    let mut config = json!({"mode":"client","private_key_file":"k","paths":[entry],
        "allowed_targets":["127.0.0.1:*"]});
    if server_dials {
        config["server_dials"] = json!(true);
        config["paths"][0]["tls_auto"] = json!(false);
    }
    config
}

#[test]
fn it_is_accepted_only_where_it_has_an_effect() {
    assert!(accepted(client(None, "tcp", false)));
    assert!(accepted(client(Some("192.0.2.5"), "tcp", false)));
    assert!(accepted(client(Some("2001:db8::5"), "kcp", false)));
    assert!(accepted(client(Some("192.0.2.5"), "fec-udp", false)));
    // Not an address, or an address that cannot be a source.
    assert!(!accepted(client(Some("example.com"), "tcp", false)));
    assert!(!accepted(client(Some("192.0.2.5:80"), "tcp", false)));
    assert!(!accepted(client(Some("0.0.0.0"), "tcp", false)));
    assert!(!accepted(client(Some("224.0.0.1"), "tcp", false)));
    // The raw carriers have their own raw.local_ip (the same tunnel is fine without it).
    assert!(accepted(client(None, "fec-raw", false)));
    assert!(!accepted(client(Some("192.0.2.5"), "fec-raw", false)));
    // With server_dials the client listens, so it never dials.
    assert!(accepted(client(None, "tcp", true)));
    assert!(!accepted(client(Some("192.0.2.5"), "tcp", true)));
}

#[test]
fn a_dialing_server_may_set_it_and_a_listening_one_may_not() {
    let server = |dials: bool, local: Option<&str>| {
        let mut listener = json!({"addr": if dials { "192.0.2.1:7000" } else { "0.0.0.0:7000" }});
        if let Some(local) = local {
            listener["local_address"] = json!(local);
        }
        let mut config = json!({"mode":"server","private_key_file":"k",
            "peer_public_keys":["11".repeat(32)],"listeners":[listener]});
        if dials {
            config["server_dials"] = json!(true);
        }
        config
    };
    assert!(accepted(server(true, Some("192.0.2.5"))));
    assert!(accepted(server(true, None)));
    assert!(!accepted(server(false, Some("192.0.2.5"))));
}
