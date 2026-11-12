//! `eztunnel tlscheck`: shows the TLS ClientHello a path would send, so it can be compared with the
//! one a browser sends (JA3/JA4 on any fingerprint page, or a capture).
//!
//! It starts a listener on the loopback address of this machine, lets the dialer connect to it and
//! reads the first record. Nothing leaves the machine.
use crate::{
    carrier::client_carrier,
    config::{ClientPath, Config, Mode, TlsProfile},
    fingerprint::{ClientHello, parse_stream},
};
use anyhow::{Context, Result, bail, ensure};
use std::time::Duration;
use tokio::{io::AsyncReadExt, net::TcpListener};

/// The ClientHello that `path` sends. The path's own address is only used for the name that goes
/// into SNI; the connection goes to a throw-away listener on loopback.
pub async fn client_hello(mut path: ClientPath) -> Result<ClientHello> {
    ensure!(
        path.transport.uses_tls(),
        "this path does not use TLS (wss, https or xhttps)"
    );
    // Keep the name the real connection would send.
    if path.server_name.is_none() {
        let (host, _) = path.addr.rsplit_once(':').context("address without port")?;
        path.server_name = Some(host.trim_matches(['[', ']']).to_string());
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("open a loopback listener")?;
    path.addr = listener.local_addr()?.to_string();
    path.xhttp.edge_addrs.clear();
    path.local_address=None;
    path.dial_timeout = 2;
    let capture = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let count = socket.read(&mut buffer).await?;
            ensure!(count > 0, "the dialer closed before sending a ClientHello");
            bytes.extend_from_slice(&buffer[..count]);
            ensure!(bytes.len()<=65535+128*5,"ClientHello diagnostic capture too large");
            if let Ok(hello)=parse_stream(&bytes){return Ok(hello);}
        }
    });
    // The handshake cannot finish (nobody answers); the dialer is only there to speak first.
    let dial = tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(2), client_carrier(&path)).await;
    });
    struct Abort<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for Abort<T>{fn drop(&mut self){self.0.abort();}}
    let(mut capture,dial)=(Abort(capture),Abort(dial));
    let hello = tokio::time::timeout(Duration::from_secs(5), &mut capture.0)
        .await
        .context("no ClientHello arrived")?
        .context("capture task failed")??;
    dial.0.abort();
    Ok(hello)
}

/// A client path for a TLS carrier with a fresh tunnel key, for checking a profile on its own.
pub fn sample_path(profile: TlsProfile, sni: &str) -> Result<ClientPath> {
    let key = crate::tunnel_key::TunnelKey::generate()?.display();
    let mut config: Config = serde_json::from_value(serde_json::json!({
        "mode": "client",
        "tunnel_key": key,
        "allowed_targets": ["127.0.0.1:*"],
        "paths": [{
            "addr": "127.0.0.1:8443",
            "transport": "wss",
            "tls_auto": true,
            "server_name": sni,
            "tls_profile": profile,
        }],
    }))?;
    config.prepare()?;
    config.validate()?;
    config
        .paths
        .drain(..)
        .next()
        .context("the sample path is missing")
}

/// The first TLS path of a configuration (the dialing side of its first TLS listener, for a server
/// that dials).
pub fn path_of(config: &Config) -> Result<ClientPath> {
    match config.mode {
        Mode::Client => config
            .paths
            .iter()
            .find(|path| path.transport.uses_tls())
            .cloned(),
        Mode::Server => config
            .listeners
            .iter()
            .find(|listener| config.server_dials && listener.transport.uses_tls())
            .map(|listener| listener.dial_path(config.timeouts.server_dial_sec)),
    }
    .context("this tunnel has no TLS path that dials (wss, https or xhttps)")
}

/// What `eztunnel tlscheck` prints.
pub async fn run(
    config: Option<std::path::PathBuf>,
    profile: Option<TlsProfile>,
    sni: &str,
) -> Result<String> {
    let mut path = match config {
        Some(file) => {
            // `load` has already derived everything from the tunnel key.
            path_of(&Config::load(&file)?)?
        }
        None => sample_path(profile.unwrap_or_default(), sni)?,
    };
    if let Some(profile) = profile {
        path.tls_profile = profile;
    }
    if path.tls_profile == TlsProfile::Chrome && !cfg!(feature = "browser-tls") {
        bail!("this build was made without the browser-tls feature");
    }
    let hello = client_hello(path.clone()).await?;
    Ok(format!(
        "TLS profile: {}\n{}",
        match path.tls_profile {
            TlsProfile::Classic => "classic",
            TlsProfile::Chrome => "chrome",
        },
        hello.describe()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C38: XHTTPS edge overrides and a local bind address are dropped for the loopback
    /// capture, so the ClientHello reaches the capture listener and nothing is dialed out.
    #[tokio::test]
    async fn xhttps_edge_and_local_address_overrides_do_not_bypass_the_loopback_capture() -> Result<()> {
        let key = crate::tunnel_key::TunnelKey::generate()?.display();
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "mode": "client", "tunnel_key": key, "allowed_targets": ["127.0.0.1:*"],
            "paths": [{"addr": "tunnel.example.com:443", "transport": "xhttps", "tls_auto": true,
                "server_name": "tunnel.example.com",
                "xhttp": {"edge_addrs": ["192.0.2.1:443", "192.0.2.2:443"]}}],
        }))?;
        config.prepare()?;
        config.validate()?;
        let mut path = config.paths.drain(..).next().context("path")?;
        // A non-local bind address would make every dial fail if it were kept.
        path.local_address = Some("192.0.2.9".into());
        assert!(!path.xhttp.edge_addrs.is_empty() && path.local_address.is_some(), "fixture must carry overrides");
        let started = std::time::Instant::now();
        let hello = client_hello(path).await?;
        assert!(started.elapsed() < Duration::from_secs(4), "capture waited for the edge timeout");
        assert_eq!(hello.server_name.as_deref(), Some("tunnel.example.com"));
        Ok(())
    }

    /// C48: cancelling the caller does not leave the capture listener running.
    #[tokio::test]
    async fn a_cancelled_capture_releases_its_tasks() -> Result<()> {
        let path = sample_path(TlsProfile::Classic, "a.example")?;
        let before = tokio::runtime::Handle::current().metrics().num_alive_tasks();
        let _ = tokio::time::timeout(Duration::from_millis(1), client_hello(path)).await;
        for _ in 0..100 {
            if tokio::runtime::Handle::current().metrics().num_alive_tasks() <= before {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        bail!("capture/dial tasks still alive after cancellation")
    }
}
