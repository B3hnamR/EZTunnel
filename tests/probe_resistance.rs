//! Wire version 2: what a prober without the key sees.
use anyhow::{Context, Result, ensure};
use eztunnel::{
    config::{self, ClientPath, Listener},
    kcp_carrier::Incoming,
    stealth::{Stealth, WireOptions},
    transport,
    tunnel_key::public_of,
};
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};

struct Keys {
    server_private: [u8; 32],
    server_public_hex: String,
    client_private: [u8; 32],
    client_public: [u8; 32],
}

fn keys() -> Result<Keys> {
    let directory = tempfile::tempdir()?;
    let (server_key, server_public) = config::generate_keypair(&directory.path().join("server"))?;
    let (client_key, client_public) = config::generate_keypair(&directory.path().join("client"))?;
    Ok(Keys {
        server_private: config::decode_key(std::fs::read_to_string(server_key)?.trim())?,
        server_public_hex: server_public,
        client_private: config::decode_key(std::fs::read_to_string(client_key)?.trim())?,
        client_public: config::decode_key(&client_public)?,
    })
}

fn wire(version: u8, keys: &Keys, hold: u64) -> Result<WireOptions> {
    Ok(WireOptions {
        version,
        stealth: Stealth {
            probe_hold_sec: hold,
            ..Stealth::default()
        },
        server_key: public_of(&keys.server_private)?,
    })
}

fn listener(addr: &str, transport: &str, wire: WireOptions) -> Result<Listener> {
    let mut listener: Listener = serde_json::from_value(
        json!({"addr":addr,"transport":transport,"http_path":"/correct","maps":[]}),
    )?;
    listener.wire = wire;
    Ok(listener)
}

fn path(addr: &str, transport: &str, keys: &Keys, wire: WireOptions) -> Result<ClientPath> {
    let mut path: ClientPath = serde_json::from_value(json!({
        "addr":addr,"transport":transport,"http_path":"/correct",
        "server_public_key":keys.server_public_hex,"dial_timeout":2
    }))?;
    path.wire = wire;
    Ok(path)
}

/// Serves one connection with `accept_listener` and returns what it answered.
async fn probe(
    transport: &str,
    request: &[u8],
    hold: u64,
) -> Result<(Vec<u8>, Duration, anyhow::Result<()>)> {
    let keys = keys()?;
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?.to_string();
    let listener = listener(&addr, transport, wire(2, &keys, hold)?)?;
    let server = tokio::spawn(async move {
        let (stream, _) = socket.accept().await?;
        transport::accept_listener(
            Incoming::Tcp(stream),
            &listener,
            &keys.server_private,
            &[keys.client_public],
            Duration::from_secs(20),
        )
        .await
        .map(|_| ())
    });
    let mut stream = TcpStream::connect(&addr).await?;
    stream.write_all(request).await?;
    let started = Instant::now();
    let mut answer = Vec::new();
    let mut buffer = [0u8; 4096];
    // Read until the server closes (or 10 s pass).
    let _ = timeout(Duration::from_secs(10), async {
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => answer.extend_from_slice(&buffer[..n]),
            }
        }
    })
    .await;
    let elapsed = started.elapsed();
    let outcome = server.await?;
    Ok((answer, elapsed, outcome))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn random_bytes_to_a_tcp_listener_get_silence_then_a_close() -> Result<()> {
    let mut junk = vec![0u8; 200];
    for (index, byte) in junk.iter_mut().enumerate() {
        *byte = (index * 37 + 11) as u8;
    }
    let (answer, elapsed, outcome) = probe("tcp", &junk, 3).await?;
    ensure!(answer.is_empty(), "the listener answered a probe");
    ensure!(
        elapsed >= Duration::from_millis(1400),
        "closed too early: {elapsed:?}"
    );
    ensure!(
        elapsed <= Duration::from_secs(5),
        "held too long: {elapsed:?}"
    );
    ensure!(outcome.is_err(), "a probe was accepted");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_http_request_gets_an_ordinary_not_found_page() -> Result<()> {
    for transport in ["http", "ws"] {
        let (answer, _, outcome) = probe(
            transport,
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            1,
        )
        .await?;
        let text = String::from_utf8_lossy(&answer).to_string();
        ensure!(
            text.starts_with("HTTP/1.1 404 Not Found"),
            "{transport}: {text}"
        );
        ensure!(text.contains("nginx"), "{transport}: no server banner");
        ensure!(
            !text.to_ascii_lowercase().contains("eztunnel") && !text.contains("tunnel path"),
            "{transport}: the page names the project"
        );
        ensure!(outcome.is_err(), "{transport}: probe accepted");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_websocket_upgrade_for_the_wrong_path_gets_the_same_page() -> Result<()> {
    let (answer, _, outcome) = probe(
        "ws",
        b"GET /nothing HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        1,
    )
    .await?;
    let text = String::from_utf8_lossy(&answer).to_string();
    ensure!(text.starts_with("HTTP/1.1 404 Not Found"), "{text}");
    ensure!(outcome.is_err());
    Ok(())
}

/// A browser pointed at a TLS port with `http://` gets what nginx answers, not a silent close;
/// a TLS handshake on the same port still works (the carriers tests cover that).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_http_request_on_a_tls_port_gets_the_nginx_answer() -> Result<()> {
    for transport in ["https", "wss"] {
        let keys = keys()?;
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?.to_string();
        let mut listener = listener(&addr, transport, wire(2, &keys, 5)?)?;
        listener.tls_auto = false;
        let server = tokio::spawn(async move {
            let (stream, _) = socket.accept().await?;
            transport::accept_listener(
                Incoming::Tcp(stream),
                &listener,
                &keys.server_private,
                &[keys.client_public],
                Duration::from_secs(5),
            )
            .await
            .map(|_| ())
        });
        let mut stream = TcpStream::connect(&addr).await?;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
            .await?;
        let started = Instant::now();
        let mut answer = Vec::new();
        timeout(Duration::from_secs(5), stream.read_to_end(&mut answer))
            .await
            .context("the server kept the connection open")??;
        let text = String::from_utf8_lossy(&answer).to_string();
        ensure!(
            text.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{transport}: {text:?}"
        );
        ensure!(
            text.contains("The plain HTTP request was sent to HTTPS port")
                && text.contains("Server: nginx")
                && text.contains("\r\nDate: "),
            "{transport}: {text:?}"
        );
        ensure!(
            started.elapsed() < Duration::from_secs(3),
            "{transport}: closed late, like nothing a web server does"
        );
        ensure!(server.await?.is_err(), "{transport}: a probe was accepted");
    }
    Ok(())
}

/// The reply to a correct upgrade must be framed like any web server's: CRLF line endings.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_websocket_upgrade_reply_uses_crlf_line_endings() -> Result<()> {
    let keys = keys()?;
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?.to_string();
    let listener = listener(&addr, "ws", wire(2, &keys, 1)?)?;
    let server = tokio::spawn(async move {
        let (stream, _) = socket.accept().await?;
        transport::accept_listener(
            Incoming::Tcp(stream),
            &listener,
            &keys.server_private,
            &[keys.client_public],
            Duration::from_secs(3),
        )
        .await
        .map(|_| ())
    });
    let mut stream = TcpStream::connect(&addr).await?;
    stream
        .write_all(b"GET /correct HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        .await?;
    let mut answer = Vec::new();
    let mut buffer = [0u8; 512];
    timeout(Duration::from_secs(5), async {
        while !answer.windows(2).any(|w| w == b"\n\n")
            && !answer.windows(4).any(|w| w == b"\r\n\r\n")
        {
            let count = stream.read(&mut buffer).await?;
            ensure!(count > 0, "closed before the end of the reply");
            answer.extend_from_slice(&buffer[..count]);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("no reply")??;
    let text = String::from_utf8_lossy(&answer).to_string();
    ensure!(
        text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{text:?}"
    );
    ensure!(
        text.contains("\r\n\r\n"),
        "headers not ended by CRLF CRLF: {text:?}"
    );
    ensure!(
        !text.replace("\r\n", "").contains('\n'),
        "a bare line feed in the reply: {text:?}"
    );
    drop(stream);
    let _ = server.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_bytes_of_a_tcp_dial_have_no_fixed_length_or_value() -> Result<()> {
    let keys = keys()?;
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?.to_string();
    let mut dials = JoinSet::new();
    for _ in 0..40 {
        let path = path(&addr, "tcp", &keys, wire(2, &keys, 0)?)?;
        let private = keys.client_private;
        dials.spawn(async move {
            let _ = transport::connect_path(&path, &private).await;
        });
    }
    let mut firsts: Vec<Vec<u8>> = Vec::new();
    for _ in 0..40 {
        let (mut stream, _) = timeout(Duration::from_secs(5), socket.accept()).await??;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 2048];
        // The dial sends its first flight at once and then waits for the answer.
        let _ = timeout(Duration::from_millis(400), async {
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                }
            }
        })
        .await;
        firsts.push(bytes);
    }
    dials.abort_all();
    let lengths: std::collections::BTreeSet<usize> = firsts.iter().map(Vec::len).collect();
    ensure!(
        lengths.len() >= 12,
        "first flight lengths repeat too much: {} distinct of 40",
        lengths.len()
    );
    ensure!(firsts.iter().all(|first| first.len() >= 16 + 2 + 64 + 98));
    // The start is printable text, which keeps it from looking like uniform noise.
    for first in &firsts {
        ensure!(
            first[..18 + 64].iter().all(|b| (0x20..0x7f).contains(b)),
            "the start of a masked stream is not printable"
        );
    }
    // Bytes 16 and 17 are the two digits of the pad length (64..255 uses few values).
    for position in (0..16).chain(18..32) {
        let values: std::collections::BTreeSet<u8> = firsts.iter().map(|f| f[position]).collect();
        ensure!(
            values.len() >= 8,
            "byte {position} of the first flight is nearly constant ({} values of 40)",
            values.len()
        );
    }
    // Version 1 for comparison: the first record has a fixed length and a fixed length field.
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?.to_string();
    let path1 = path(&addr, "tcp", &keys, wire(1, &keys, 0)?)?;
    let private = keys.client_private;
    let dial = tokio::spawn(async move {
        let _ = transport::connect_path(&path1, &private).await;
    });
    let (mut stream, _) = socket.accept().await?;
    let mut first = vec![0u8; 98];
    stream.read_exact(&mut first).await?;
    ensure!(
        first[..2] == [0, 96],
        "version 1 should keep its old fixed first record"
    );
    dial.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn version_1_and_version_2_peers_do_not_pair_up() -> Result<()> {
    for (client_version, server_version) in [(2, 1), (1, 2)] {
        let keys = keys()?;
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?.to_string();
        let listener = listener(&addr, "tcp", wire(server_version, &keys, 1)?)?;
        let path = path(&addr, "tcp", &keys, wire(client_version, &keys, 1)?)?;
        let server = tokio::spawn(async move {
            let (stream, _) = socket.accept().await?;
            transport::accept_listener(
                Incoming::Tcp(stream),
                &listener,
                &keys.server_private,
                &[keys.client_public],
                Duration::from_secs(3),
            )
            .await
            .map(|_| ())
        });
        let client = timeout(
            Duration::from_secs(5),
            transport::connect_path(&path, &keys.client_private),
        )
        .await
        .context("client did not give up")?;
        ensure!(
            client.is_err(),
            "client {client_version} paired with server {server_version}"
        );
        let served = timeout(Duration::from_secs(6), server)
            .await
            .context("server did not give up")??;
        ensure!(
            served.is_err(),
            "server {server_version} paired with client {client_version}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_derived_certificate_pairs_up_and_looks_like_a_host_in_wire_version_2() -> Result<()> {
    use eztunnel::{config::Config, tunnel_key::TunnelKey};
    let key = TunnelKey::generate()?.display();
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?.to_string();
    let prepare = |value: serde_json::Value| -> Result<Config> {
        let mut config: Config = serde_json::from_value(value)?;
        config.prepare()?;
        config.validate()?;
        Ok(config)
    };
    let server = prepare(json!({"mode":"server","tunnel_key":key,"wire_version":2,
        "listeners":[{"addr":addr,"transport":"wss","tls_auto":true,"maps":[]}]}))?;
    let client = prepare(json!({"mode":"client","tunnel_key":key,"wire_version":2,
        "paths":[{"addr":addr,"transport":"wss","tls_auto":true,"server_name":"example.com","dial_timeout":3}]}))?;
    // The default path is replaced by the same derived path on both ends.
    ensure!(server.listeners[0].http_path != "/tunnel");
    ensure!(server.listeners[0].http_path == client.paths[0].http_path);
    let name = server.listeners[0].wire.certificate_name();
    let certificate = server.listeners[0]
        .auto_tls
        .as_ref()
        .context("derived certificate")?
        .certificate
        .clone();
    ensure!(
        certificate
            .as_ref()
            .windows(name.len())
            .any(|w| w == name.as_bytes()),
        "the certificate does not carry the derived host name"
    );
    ensure!(
        !certificate.as_ref().windows(8).any(|w| w == b"eztunnel"),
        "the certificate names the project"
    );
    let private = server.private_key()?;
    let allowed: Vec<[u8; 32]> = server
        .peer_public_keys
        .iter()
        .map(|key| config::decode_key(key))
        .collect::<Result<_>>()?;
    let listener = server.listeners[0].clone();
    let serving = tokio::spawn(async move {
        let (stream, _) = socket.accept().await?;
        transport::accept_listener(
            Incoming::Tcp(stream),
            &listener,
            &private,
            &allowed,
            Duration::from_secs(5),
        )
        .await
    });
    let dialed = timeout(
        Duration::from_secs(8),
        transport::connect_path(&client.paths[0], &*client.private_key()?),
    )
    .await
    .context("client timed out")?
    .map(|_| ());
    let served = serving.await?;
    ensure!(
        dialed.is_ok() && served.is_ok(),
        "client: {dialed:?}; server: {:?}",
        served.as_ref().err()
    );
    Ok(())
}
