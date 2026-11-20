//! The agent on a server managed by another server's dashboard. `eztunnel agent join CODE` admits
//! this server once and installs the `eztunnel-agent` service; `eztunnel agent run` (the service)
//! keeps a link to the dashboard open: it sends a snapshot of this server every few seconds and
//! does what the dashboard asks from a fixed list (list tunnels, start/stop/restart, read a log).
use super::{
    data::{LocalSource, Source},
    link::{self, JoinCode, LinkReader, LinkWriter},
    ops::{self, LocalOps, Ops},
};
use anyhow::{Context, Result, bail, ensure};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

pub const CONFIG_DIR: &str = "/etc/eztunnel-agent";
const CONFIG_FILE: &str = "agent.json";
pub(crate) const UNIT: &str = "eztunnel-agent.service";
const SNAPSHOT_EVERY: Duration = Duration::from_secs(2);
/// Logs the dashboard may follow on this server at once.
const MAX_FOLLOWS: usize = 8;

#[derive(Serialize, Deserialize, Clone)]
struct AgentConfig {
    host: String,
    port: u16,
    hub_key: String,
    private: String,
    name: String,
}

/// TLS only carries the link; who is at the other end is proved by the link's own handshake with
/// the hub key from the join code (a Let's Encrypt key changes every few days, so it cannot be
/// pinned). Signatures are still checked, so the TLS session itself is sound.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

type Stream = tokio_rustls::client::TlsStream<TcpStream>;

/// Opens the dashboard's port and switches the connection to the agent link.
async fn open(host: &str, port: u16, private: &[u8; 32], hub_key: &[u8; 32]) -> Result<(LinkReader<Stream>, LinkWriter<Stream>)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host.trim_matches(['[', ']']), port)))
        .await
        .context("connect to the dashboard: timed out")?
        .with_context(|| format!("connect to the dashboard at {host}:{port}"))?;
    tcp.set_nodelay(true)?;
    let name = ServerName::try_from(host.trim_matches(['[', ']']).to_string()).context("dashboard address")?;
    let mut tls = tokio::time::timeout(Duration::from_secs(15), tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp))
        .await
        .context("TLS with the dashboard: timed out")??;
    tokio::time::timeout(Duration::from_secs(15), async {
        tls.write_all(
            format!(
                "GET /agent HTTP/1.1\r\nhost: {host}:{port}\r\nconnection: upgrade\r\nupgrade: {}\r\n\r\n",
                link::UPGRADE
            )
            .as_bytes(),
        )
        .await?;
        // Read byte by byte so none of the Noise handshake after the header is consumed.
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            ensure!(header.len() < 4096, "the dashboard sent an unexpected answer");
            header.push(tls.read_u8().await.context("the dashboard closed the connection")?);
        }
        let text = String::from_utf8_lossy(&header);
        ensure!(
            text.starts_with("HTTP/1.1 101"),
            "the dashboard refused the agent connection ({}); is it a dashboard with server support?",
            text.lines().next().unwrap_or("")
        );
        Ok::<(), anyhow::Error>(())
    })
    .await.context("dashboard HTTP upgrade timed out")??;
    tokio::time::timeout(Duration::from_secs(15), link::connect(tls, private, hub_key))
        .await
        .context("agent handshake timed out")?
}

fn config_path(dir: &Path) -> std::path::PathBuf {
    dir.join(CONFIG_FILE)
}

/// The dashboard this server is joined to (`host:port`), if it is joined to one.
pub fn joined(dir: &Path) -> Option<String> {
    let config: AgentConfig = serde_json::from_str(&std::fs::read_to_string(config_path(dir)).ok()?).ok()?;
    let host = if config.host.contains(':') { format!("[{}]", config.host) } else { config.host };
    Some(format!("{host}:{}", config.port))
}

fn hello() -> Value {
    json!({
        "type": "hello",
        "version": env!("CARGO_PKG_VERSION"),
        "arch": std::env::consts::ARCH,
        "host": super::host::hostname(),
    })
}

/// Admits this server to a dashboard with a join code, then installs and starts the agent service.
pub async fn join(code: &str, dir: &Path, install_service: bool) -> Result<()> {
    ensure!(crate::manager::store::is_root(), "the agent manages system services; run it as root");
    let code = JoinCode::decode(code)?;
    ensure!(
        !config_path(dir).exists(),
        "this server is already joined to a dashboard; run `eztunnel agent leave` first"
    );
    let (private, _) = link::generate_keypair()?;
    println!("Connecting to the dashboard at {} …", code.address());
    let (mut reader, mut writer) = open(&code.host, code.port, &private, &code.hub_key).await?;
    let name = super::host::hostname();
    writer
        .send(&json!({"type": "join", "token": hex::encode(code.token), "name": name, "hello": hello()}))
        .await?;
    let answer = reader.recv().await.context("the dashboard closed the connection")?;
    match answer["type"].as_str() {
        Some("welcome") => {}
        Some("refused") => bail!("the dashboard refused this server: {}", answer["reason"].as_str().unwrap_or("no reason")),
        _ => bail!("the dashboard sent an unexpected answer"),
    }
    super::create_private_dir(dir)?;
    let config = AgentConfig {
        host: code.host.clone(),
        port: code.port,
        hub_key: hex::encode(code.hub_key),
        private: hex::encode(private),
        name,
    };
    super::write_private(&config_path(dir), &serde_json::to_vec_pretty(&config)?)?;
    println!("This server joined the dashboard.");
    if install_service {
        install(dir)?;
        println!("The agent service runs now and starts with the server ({UNIT}).");
    }
    Ok(())
}

fn install(dir: &Path) -> Result<()> {
    let binary = std::env::current_exe()?.canonicalize()?;
    let unit = format!(
        "[Unit]\nDescription=EZTunnel agent (managed by a dashboard)\nAfter=network-online.target\nWants=network-online.target\n\n\
         [Service]\nExecStart=\"{}\" agent run --config-dir {}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n",
        binary.display(),
        dir.display()
    );
    std::fs::write(format!("/etc/systemd/system/{UNIT}"), unit).context("write the agent service")?;
    for args in [vec!["daemon-reload"], vec!["enable", "--now", UNIT]] {
        let status = std::process::Command::new("systemctl").args(&args).status()?;
        ensure!(status.success(), "systemctl {} failed", args.join(" "));
    }
    Ok(())
}

/// Stops the agent service and forgets the dashboard. Tunnels on this server keep running.
pub fn leave(dir: &Path) -> Result<()> {
    ensure!(crate::manager::store::is_root(), "run it as root");
    let _ = std::process::Command::new("systemctl").args(["disable", "--now", "--quiet", UNIT]).status();
    let _ = std::fs::remove_file(format!("/etc/systemd/system/{UNIT}"));
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
    match std::fs::remove_file(config_path(dir)) {
        Ok(()) => println!("This server left its dashboard. Its tunnels keep running."),
        Err(_) => println!("This server was not joined to a dashboard."),
    }
    Ok(())
}

/// The agent service: keeps the link open, reconnecting with a growing wait (1 s to 60 s).
pub async fn run(dir: &Path) -> Result<()> {
    let text = std::fs::read_to_string(config_path(dir)).context("this server has not joined a dashboard; run `eztunnel agent join CODE`")?;
    let config: AgentConfig = serde_json::from_str(&text).context("unreadable agent configuration")?;
    let private: [u8; 32] = hex::decode(&config.private)?.try_into().map_err(|_| anyhow::anyhow!("key size"))?;
    let hub_key: [u8; 32] = hex::decode(&config.hub_key)?.try_into().map_err(|_| anyhow::anyhow!("key size"))?;
    let mut wait = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        match open(&config.host, config.port, &private, &hub_key).await {
            Ok((reader, writer)) => {
                let ended = serve(reader, writer).await;
                eprintln!("agent link ended: {}", ended.err().map_or("closed".into(), |e| format!("{e:#}")));
            }
            Err(error) => eprintln!("agent: {error:#}"),
        }
        if started.elapsed() > Duration::from_secs(60) {
            wait = Duration::from_secs(1);
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(Duration::from_secs(60));
    }
}

async fn serve(mut reader: LinkReader<Stream>, mut writer: LinkWriter<Stream>) -> Result<()> {
    let welcome = tokio::time::timeout(Duration::from_secs(15), async {
        writer.send(&hello()).await?;
        reader.recv().await
    }).await.context("the dashboard welcome timed out")??;
    ensure!(welcome["type"] == "welcome", "the dashboard did not accept this server: {}", welcome["reason"]);
    let (out_tx, mut out_rx) = mpsc::channel::<Value>(32);
    let mut writing = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            tokio::time::timeout(Duration::from_secs(30), writer.send(&message))
                .await.context("agent write timed out")??;
        }
        Ok::<(), anyhow::Error>(())
    });
    let snapshots = {
        let out = out_tx.clone();
        tokio::spawn(async move {
            let mut source = match tokio::task::spawn_blocking(LocalSource::new).await {
                Ok(Ok(source)) => source,
                _ => return,
            };
            loop {
                let (back, snapshot) = match tokio::task::spawn_blocking(move || {
                    let snapshot = source.sample();
                    (source, snapshot)
                })
                .await
                {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                source = back;
                if out.send(json!({"type": "snapshot", "snapshot": snapshot})).await.is_err() {
                    return;
                }
                tokio::time::sleep(SNAPSHOT_EVERY).await;
            }
        })
    };
    let mut follows: std::collections::HashMap<u64, tokio::task::JoinHandle<()>> = Default::default();
    let result = loop {
        let incoming = tokio::select! {
            incoming = reader.recv() => incoming,
            _ = &mut writing => break Err(anyhow::anyhow!("the dashboard writer ended")),
        };
        let request = match incoming {
            Ok(request) => request,
            Err(error) => break Err(error),
        };
        if request["type"] != "request" {
            continue;
        }
        match request["op"].as_str() {
            Some("follow") => {
                follows.retain(|_, task| !task.is_finished());
                let stream = request["stream"].as_u64().unwrap_or(0);
                let started = if follows.len() >= MAX_FOLLOWS {
                    Err(anyhow::anyhow!("too many logs followed on this server"))
                } else {
                    LocalOps.follow(request["name"].as_str().unwrap_or(""), request["after"].as_str().map(str::to_string))
                };
                let answer = match started {
                    Ok(mut log) => {
                        let out = out_tx.clone();
                        follows.insert(stream, tokio::spawn(async move {
                            while let Some((line, cursor)) = log.next_line().await {
                                if out.send(json!({"type": "log_line", "stream": stream, "line": line, "cursor": cursor})).await.is_err() {
                                    return;
                                }
                            }
                        }));
                        json!({"type": "response", "id": request["id"], "ok": true, "result": null})
                    }
                    Err(error) => json!({"type": "response", "id": request["id"], "ok": false, "error": format!("{error:#}")}),
                };
                let _ = out_tx.send(answer).await;
                continue;
            }
            Some("unfollow") => {
                if let Some(task) = request["stream"].as_u64().and_then(|s| follows.remove(&s)) {
                    // Dropping the log ends its journalctl.
                    task.abort();
                }
                continue;
            }
            _ => {}
        }
        let out = out_tx.clone();
        tokio::spawn(async move {
            let id = request["id"].clone();
            let answer = match tokio::task::spawn_blocking(move || answer(&request)).await {
                Ok(Ok(result)) => json!({"type": "response", "id": id, "ok": true, "result": result}),
                // The code is extra: a dashboard from before codes reads the words alone.
                Ok(Err(error)) => json!({"type": "response", "id": id, "ok": false, "error": format!("{error:#}"), "code": ops::code_of(&error)}),
                Err(_) => json!({"type": "response", "id": id, "ok": false, "error": "the agent failed"}),
            };
            let _ = out.send(answer).await;
        });
    };
    snapshots.abort();
    for (_, task) in follows {
        task.abort();
    }
    drop(out_tx);
    // In-flight operations may still hold senders; they must not keep a dead link alive.
    writing.abort();
    result
}

/// One request from the dashboard, from the fixed list.
fn answer(request: &Value) -> Result<Value> {
    ops::answer(&LocalOps, request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_fixed_requests_are_answered() {
        for request in [json!({"op": "shell", "cmd": "id"}), json!({"op": "act", "name": "x", "action": "delete"}), json!({})] {
            assert!(answer(&request).is_err(), "{request}");
        }
    }
}
