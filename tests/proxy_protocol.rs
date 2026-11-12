//! A port map with `proxy_protocol` makes the tunnel's far end write a PROXY protocol header to
//! the destination, carrying the real user address.
use anyhow::{Result, ensure};
use eztunnel::{config::Config, engine, tunnel_key::TunnelKey};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{sleep, timeout},
};

fn configured(value: Value) -> Result<Config> {
    let mut config: Config = serde_json::from_value(value)?;
    config.prepare()?;
    config.validate()?;
    Ok(config)
}

struct Seen {
    /// Everything the destination service received, header included.
    data: Vec<u8>,
    /// The user's own address.
    user: SocketAddr,
    /// The address the user connected to (the map).
    map: SocketAddr,
}

/// Runs a tunnel whose map has the given `proxy_protocol` and returns what the destination
/// service received for one user connection that sent `payload`.
async fn seen_by_destination(proxy: Option<u8>, payload: &'static [u8]) -> Result<Seen> {
    let key = TunnelKey::generate()?.display();
    let tunnel = TcpListener::bind("127.0.0.1:0").await?;
    let tunnel_addr = tunnel.local_addr()?;
    let map = TcpListener::bind("127.0.0.1:0").await?;
    let map_addr = map.local_addr()?;
    let destination = TcpListener::bind("127.0.0.1:0").await?;
    let destination_addr = destination.local_addr()?;
    drop((tunnel, map));
    let mut map_entry =
        json!({"type":"tcp","bind":map_addr.to_string(),"target":destination_addr.to_string()});
    if let Some(version) = proxy {
        map_entry["proxy_protocol"] = json!(version);
    }
    let server = configured(json!({"mode":"server","tunnel_key":key,
        "heartbeat_sec":1,"dead_timeout_sec":5,
        "listeners":[{"addr":tunnel_addr.to_string(),"transport":"tcp","maps":[map_entry]}]}))?;
    let client = configured(json!({"mode":"client","tunnel_key":key,
        "heartbeat_sec":1,"dead_timeout_sec":5,
        "allowed_targets":[destination_addr.to_string()],
        "paths":[{"addr":tunnel_addr.to_string(),"transport":"tcp","dial_timeout":3,"retry_interval":1}]}))?;
    let mut tasks: JoinSet<Result<()>> = JoinSet::new();
    tasks.spawn(engine::run(server));
    tasks.spawn(engine::run(client));
    // The destination records what arrives on its first connection until the payload has come.
    let recorded = tokio::spawn(async move {
        let (mut stream, _) = destination.accept().await?;
        let mut data = Vec::new();
        let mut buffer = [0; 1024];
        while !data.ends_with(payload) {
            let count = stream.read(&mut buffer).await?;
            ensure!(count > 0, "the connection ended early");
            data.extend_from_slice(&buffer[..count]);
        }
        anyhow::Ok(data)
    });
    // The map accepts connections before the tunnel session is up, and drops them then; keep
    // trying until one of them reaches the destination.
    let mut recorded = recorded;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let (data, user_addr) = loop {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "the destination did not receive the payload"
        );
        let Ok(Ok(mut user)) =
            timeout(Duration::from_millis(500), TcpStream::connect(map_addr)).await
        else {
            sleep(Duration::from_millis(50)).await;
            continue;
        };
        let user_addr = user.local_addr()?;
        let _ = user.write_all(payload).await;
        if let Ok(done) = timeout(Duration::from_millis(1500), &mut recorded).await {
            break (done??, user_addr);
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(Seen {
        data,
        user: user_addr,
        map: map_addr,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_the_option_the_destination_gets_only_the_users_data() -> Result<()> {
    let seen = seen_by_destination(None, b"plain user data").await?;
    assert_eq!(seen.data, b"plain user data");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn version_1_gives_the_destination_the_real_user_address() -> Result<()> {
    let seen = seen_by_destination(Some(1), b"hello v1").await?;
    let expected = format!(
        "PROXY TCP4 127.0.0.1 127.0.0.1 {} {}\r\nhello v1",
        seen.user.port(),
        seen.map.port()
    );
    assert_eq!(String::from_utf8(seen.data)?, expected);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn version_2_gives_the_destination_the_real_user_address() -> Result<()> {
    let seen = seen_by_destination(Some(2), b"hello v2").await?;
    let data = seen.data;
    assert_eq!(&data[..12], b"\r\n\r\n\0\r\nQUIT\n");
    assert_eq!(&data[12..16], [0x21, 0x11, 0, 12]);
    assert_eq!(&data[16..20], [127, 0, 0, 1]);
    assert_eq!(&data[20..24], [127, 0, 0, 1]);
    assert_eq!(u16::from_be_bytes([data[24], data[25]]), seen.user.port());
    assert_eq!(u16::from_be_bytes([data[26], data[27]]), seen.map.port());
    assert_eq!(&data[28..], b"hello v2");
    Ok(())
}

#[test]
fn the_option_is_refused_where_it_cannot_work() {
    let key = TunnelKey::generate().unwrap().display();
    let server = |map: Value| {
        configured(json!({"mode":"server","tunnel_key":key,
            "listeners":[{"addr":"127.0.0.1:7000","maps":[map]}]}))
    };
    let tcp = |extra: Value| {
        let mut map = json!({"type":"tcp","bind":"127.0.0.1:8080","target":"127.0.0.1:80"});
        map["proxy_protocol"] = extra;
        map
    };
    assert!(server(tcp(json!(1))).is_ok());
    assert!(server(tcp(json!(2))).is_ok());
    assert!(server(tcp(json!(3))).is_err());
    assert!(server(tcp(json!(0))).is_err());
    let mut udp = json!({"type":"udp","bind":"127.0.0.1:8080","target":"127.0.0.1:80"});
    udp["proxy_protocol"] = json!(1);
    assert!(server(udp).is_err(), "UDP has no PROXY protocol here");
}
