//! What the TLS ClientHello of each profile looks like, compared with the ClientHello of Chrome 152
//! captured on 2026-10-10 (a page load and a WebSocket, from a desktop Chromium build).
#![cfg_attr(not(feature = "browser-tls"), allow(dead_code, unused_imports))]

use anyhow::Result;
use eztunnel::{
    config::TlsProfile,
    fingerprint::{ClientHello, is_grease},
    tlscheck::{client_hello, sample_path},
};
use std::collections::HashSet;

/// Chrome 152, WebSocket: the cipher list (sorted) and the extension list (sorted, without SNI and
/// ALPN) and signature algorithms, as printed by `ja4_r`.
const CHROME_CIPHERS: &str =
    "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9";
const CHROME_WEBSOCKET_EXTENSIONS: &str =
    "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,fe0d,ff01";
const CHROME_SIGNATURES: &str = "0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601";

fn raw_parts(hello: &ClientHello) -> (String, String, String) {
    let raw = hello.ja4_raw();
    let mut parts = raw.splitn(4, '_');
    let _ = parts.next();
    let ciphers = parts.next().unwrap_or_default().to_string();
    let extensions = parts.next().unwrap_or_default().to_string();
    let signatures = parts.next().unwrap_or_default().to_string();
    (ciphers, extensions, signatures)
}

async fn hello_of(profile: TlsProfile) -> Result<ClientHello> {
    client_hello(sample_path(profile, "www.example.org")?).await
}

#[cfg(feature = "browser-tls")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_chrome_profile_sends_chromes_hello() -> Result<()> {
    let hello = hello_of(TlsProfile::Chrome).await?;
    let (ciphers, extensions, signatures) = raw_parts(&hello);
    assert_eq!(ciphers, CHROME_CIPHERS);
    assert_eq!(extensions, CHROME_WEBSOCKET_EXTENSIONS);
    assert_eq!(signatures, CHROME_SIGNATURES);
    // The first part of the JA4: TLS 1.3, SNI present, 15 ciphers, 15 extensions with SNI and ALPN,
    // ALPN http/1.1.
    assert!(
        hello.ja4().starts_with("t13d1515h1_8daaf6152771_"),
        "{}",
        hello.ja4()
    );
    // The last part of the JA4 is the hash of Chrome's extension and signature lists.
    let expected = {
        use sha2::{Digest, Sha256};
        let text = format!("{CHROME_WEBSOCKET_EXTENSIONS}_{CHROME_SIGNATURES}");
        hex::encode(Sha256::digest(text.as_bytes()))[..12].to_string()
    };
    assert!(
        hello.ja4().ends_with(&expected),
        "{} should end with {expected}",
        hello.ja4()
    );
    let groups: Vec<u16> = hello
        .groups
        .iter()
        .copied()
        .filter(|g| !is_grease(*g))
        .collect();
    assert_eq!(
        groups,
        [0x11ec, 0x001d, 0x0017, 0x0018],
        "X25519MLKEM768, X25519, P-256, P-384"
    );
    assert_eq!(hello.alpn, ["http/1.1"]);
    assert_eq!(hello.server_name.as_deref(), Some("www.example.org"));
    assert!(hello.has_grease());
    assert!(hello.extensions.contains(&0xfe0d), "ECH GREASE");
    assert!(
        hello.extensions.contains(&0x001b),
        "certificate compression"
    );
    assert!(
        !hello.signature_algorithms.contains(&0x0807),
        "Chrome does not offer Ed25519"
    );
    assert_eq!(hello.point_formats, [0]);
    Ok(())
}

#[cfg(feature = "browser-tls")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_chrome_profile_shuffles_its_extensions_on_every_connection() -> Result<()> {
    let mut orders = HashSet::new();
    for _ in 0..8 {
        let hello = hello_of(TlsProfile::Chrome).await?;
        orders.insert(
            hello
                .extensions
                .iter()
                .map(|kind| if is_grease(*kind) { 0 } else { *kind })
                .collect::<Vec<_>>(),
        );
    }
    assert!(
        orders.len() >= 3,
        "only {} different orders in 8 connections",
        orders.len()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_classic_profile_requires_tls13_and_asks_for_http_1_1() -> Result<()> {
    let hello = hello_of(TlsProfile::Classic).await?;
    assert!(!hello.has_grease());
    assert_eq!(
        hello.alpn,
        ["http/1.1"],
        "a browser always names a protocol"
    );
    assert!(hello.signature_algorithms.contains(&0x0807), "Ed25519");
    assert_eq!(hello.supported_versions, [0x0304]);
    assert_eq!(hello.server_name.as_deref(), Some("www.example.org"));
    assert!(!hello.extensions.contains(&0xfe0d));
    Ok(())
}

#[cfg(feature = "browser-tls")]
#[tokio::test]
async fn chrome_rejects_a_pinned_tls12_server_before_sending_application_data() -> Result<()> {
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    let path = sample_path(TlsProfile::Chrome, "www.example.org")?;
    let resolver = path.auto_tls.as_ref().unwrap().server_config()?.cert_resolver.clone();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS12])?
        .with_no_client_auth().with_cert_resolver(resolver);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut secure = tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(stream).await.unwrap();
        let mut data = [0u8; 1];
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), secure.read(&mut data)).await;
        assert!(!matches!(result, Ok(Ok(n)) if n > 0), "application bytes crossed TLS 1.2");
    });
    let stream = tokio::net::TcpStream::connect(address).await?;
    let error = eztunnel::tls_boring::connect(&path, "www.example.org", stream).await.err().unwrap();
    assert!(error.to_string().contains("TLS 1.3 is required"));
    server.await?;
    Ok(())
}

#[cfg(not(feature = "browser-tls"))]
#[test]
fn without_the_feature_the_chrome_profile_is_refused() {
    let key = eztunnel::tunnel_key::TunnelKey::generate()
        .unwrap()
        .display();
    let mut config: eztunnel::config::Config = serde_json::from_value(serde_json::json!({
        "mode": "client", "tunnel_key": key, "allowed_targets": ["127.0.0.1:*"],
        "paths": [{"addr": "127.0.0.1:8443", "transport": "wss", "tls_auto": true,
                   "server_name": "example.org", "tls_profile": "chrome"}],
    }))
    .unwrap();
    config.prepare().unwrap();
    assert!(config.validate().is_err());
}

/// `eztunnel tlscheck --config FILE` on a configuration that uses a tunnel key: loading already
/// derives everything from the key, and preparing it a second time is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tlscheck_reads_a_tunnel_key_configuration_file() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let key = eztunnel::tunnel_key::TunnelKey::generate()?.display();
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("client.json");
    std::fs::write(
        &file,
        serde_json::to_vec(&serde_json::json!({
            "mode": "client", "tunnel_key": key, "allowed_targets": ["127.0.0.1:*"],
            "paths": [{"addr": "127.0.0.1:8443", "transport": "wss", "tls_auto": true,
                       "server_name": "www.example.org"}],
        }))?,
    )?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    let text = eztunnel::tlscheck::run(Some(file), None, "www.example.org").await?;
    anyhow::ensure!(
        text.contains("TLS profile: classic") && text.contains("JA4"),
        "{text}"
    );
    Ok(())
}

#[test]
fn the_profile_is_only_valid_where_it_has_an_effect() {
    let key = eztunnel::tunnel_key::TunnelKey::generate()
        .unwrap()
        .display();
    let accepted = |value: serde_json::Value| {
        let Ok(mut config) = serde_json::from_value::<eztunnel::config::Config>(value) else {
            return false;
        };
        config.prepare().is_ok() && config.validate().is_ok()
    };
    let client = |transport: &str, extra: serde_json::Value| {
        let mut path = serde_json::json!({"addr": "127.0.0.1:8443", "transport": transport,
            "tls_auto": transport != "tcp", "server_name": "example.org"});
        for (name, value) in extra.as_object().unwrap() {
            path[name] = value.clone();
        }
        serde_json::json!({"mode": "client", "tunnel_key": key,
            "allowed_targets": ["127.0.0.1:*"], "paths": [path]})
    };
    assert!(accepted(client("wss", serde_json::json!({}))));
    assert!(accepted(client(
        "wss",
        serde_json::json!({"tls_profile": "classic"})
    )));
    // Not a profile name.
    assert!(!accepted(client(
        "wss",
        serde_json::json!({"tls_profile": "firefox"})
    )));
    // A carrier without TLS has no ClientHello to shape.
    assert!(!accepted(client(
        "tcp",
        serde_json::json!({"tls_profile": "chrome"})
    )));
    // The listening side of a tunnel does not dial.
    let mut listening = client("wss", serde_json::json!({"tls_profile": "chrome"}));
    listening["server_dials"] = serde_json::json!(true);
    listening["paths"][0]["server_name"] = serde_json::Value::Null;
    listening["paths"][0]
        .as_object_mut()
        .unwrap()
        .remove("server_name");
    assert!(!accepted(listening));
    if cfg!(feature = "browser-tls") {
        assert!(accepted(client(
            "wss",
            serde_json::json!({"tls_profile": "chrome"})
        )));
        assert!(accepted(client(
            "xhttps",
            serde_json::json!({"tls_profile": "chrome"})
        )));
    }
}
