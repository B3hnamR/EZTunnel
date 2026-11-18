//! Terminal client for the dashboard's existing, authenticated management API.
//! The live Agent links belong to the dashboard process; this module never reads
//! a second copy of fleet state or talks to agents independently.
use anyhow::Result as AnyResult;
use bytes::Bytes;
use http::{Method, StatusCode, header};
use http_body_util::{BodyExt, Full};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{IsTerminal, Read},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpStream;
use zeroize::Zeroize;

use super::load_settings;

#[derive(Debug)]
pub struct FleetError {
    pub code: String,
    pub detail: String,
    pub status: Option<u16>,
}

impl std::fmt::Display for FleetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for FleetError {}

impl FleetError {
    fn new(code: &str, detail: impl std::fmt::Display) -> Self {
        Self {
            code: code.into(),
            detail: detail.to_string(),
            status: None,
        }
    }

    fn api(status: StatusCode, value: &Value) -> Self {
        let code = value["error"].as_str().unwrap_or("api_error");
        let detail = value["detail"].as_str().unwrap_or(code);
        Self {
            code: code.into(),
            detail: detail.into(),
            status: Some(status.as_u16()),
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self.status {
            Some(400 | 422) => 2,
            Some(401 | 403 | 429) => 3,
            Some(404) => 5,
            Some(409) => 6,
            Some(502 | 503 | 504) => 4,
            _ => match self.code.as_str() {
                "invalid_input" | "no_terminal" => 2,
                "authentication_failed" => 3,
                "remote_offline" | "dashboard_unavailable" => 4,
                "unknown_server" => 5,
                _ => 7,
            },
        }
    }

    pub fn as_json(&self) -> Value {
        json!({"ok": false, "error": self.code, "detail": self.detail, "http_status": self.status})
    }
}

type Result<T> = std::result::Result<T, FleetError>;

fn invalid(detail: impl std::fmt::Display) -> FleetError {
    FleetError::new("invalid_input", detail)
}

#[derive(Debug)]
struct LocalCertificate {
    /// Only certificates already saved by the local dashboard are trusted.
    digests: Vec<[u8; 32]>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for LocalCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.digests.contains(&actual) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the local dashboard TLS certificate differs from its saved certificate".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn local_certificate_pins(state_dir: &Path) -> Result<Vec<[u8; 32]>> {
    let mut digests = Vec::new();
    if let Ok(der) = std::fs::read(state_dir.join("cert.der")) {
        digests.push(Sha256::digest(&der).into());
    }
    if let Ok(mut certs) = CertificateDer::pem_file_iter(state_dir.join("acme-chain.pem"))
        && let Some(Ok(cert)) = certs.next()
    {
        digests.push(Sha256::digest(cert.as_ref()).into());
    }
    if digests.is_empty() {
        return Err(FleetError::new(
            "certificate_missing",
            "no local dashboard certificate was found",
        ));
    }
    Ok(digests)
}

fn password(from_stdin: bool) -> Result<String> {
    let mut password = if from_stdin {
        let mut value = String::new();
        std::io::stdin()
            .take(258)
            .read_to_string(&mut value)
            .map_err(|e| invalid(format!("read password on stdin: {e}")))?;
        value.truncate(value.trim_end_matches(['\r', '\n']).len());
        value
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(FleetError::new(
                "no_terminal",
                "use --password-stdin with a password supplied on standard input",
            ));
        }
        dialoguer::Password::new()
            .with_prompt("Dashboard password")
            .interact()
            .map_err(|e| invalid(format!("read dashboard password: {e}")))?
    };
    if password.is_empty() || password.len() > super::auth::MAX_PASSWORD_BYTES {
        password.zeroize();
        return Err(invalid("the dashboard password must be 1 to 256 bytes"));
    }
    Ok(password)
}

/// The operator's session stays in memory only. No token or password in argv,
/// persistent CLI files, JSON results, or process logs.
pub struct FleetClient {
    port: u16,
    tls: tokio_rustls::TlsConnector,
    cookie: Option<String>,
}

impl FleetClient {
    pub async fn connect(state_dir: &Path, from_stdin: bool) -> Result<Self> {
        let settings = load_settings(state_dir)
            .map_err(|e| FleetError::new("dashboard_not_configured", format!("{e:#}")))?;
        let pins = local_certificate_pins(state_dir)?;
        let mut secret = password(from_stdin)?;
        let result = Self::connect_ready(settings, pins, &secret).await;
        secret.zeroize();
        result
    }

    #[cfg(test)]
    async fn connect_password(state_dir: &Path, password: &str) -> Result<Self> {
        let settings = load_settings(state_dir)
            .map_err(|e| FleetError::new("dashboard_not_configured", format!("{e:#}")))?;
        let pins = local_certificate_pins(state_dir)?;
        Self::connect_ready(settings, pins, password).await
    }

    async fn connect_ready(
        settings: super::Settings,
        pins: Vec<[u8; 32]>,
        password: &str,
    ) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| FleetError::new("tls", e))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(LocalCertificate {
                digests: pins,
                provider,
            }))
            .with_no_client_auth();
        let mut client = Self {
            port: settings.port,
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
            cookie: None,
        };
        let (status, headers, body) = client
            .call(
                Method::POST,
                "/api/login",
                Some(json!({"password": password})),
            )
            .await?;
        if !status.is_success() {
            return Err(FleetError::api(status, &body));
        }
        let cookie = headers
            .get(header::SET_COOKIE)
            .and_then(|c| c.to_str().ok())
            .and_then(|c| c.split(';').next())
            .filter(|c| c.starts_with("__Host-ezd="))
            .ok_or_else(|| {
                FleetError::new(
                    "authentication_failed",
                    "the dashboard did not issue a secure session cookie",
                )
            })?;
        client.cookie = Some(cookie.to_string());
        Ok(client)
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, http::HeaderMap, Value)> {
        let port = self.port;
        let tls = self.tls.clone();
        let cookie = self.cookie.clone();
        let path = path.to_owned();
        tokio::time::timeout(Duration::from_secs(55), async move {
            let tcp = match TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => stream,
                Err(_) => TcpStream::connect(("::1", port)).await.map_err(|e| {
                    FleetError::new(
                        "dashboard_unavailable",
                        format!("cannot connect to local dashboard port {port}: {e}"),
                    )
                })?,
            };
            let name = ServerName::try_from("localhost".to_string())
                .map_err(|e| FleetError::new("tls", e))?;
            let stream = tls
                .connect(name, tcp)
                .await
                .map_err(|e| FleetError::new("tls", format!("dashboard TLS failed: {e}")))?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                    .await
                    .map_err(|e| FleetError::new("dashboard_unavailable", e))?;
            tokio::spawn(connection);
            let mut request = http::Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, format!("localhost:{port}"))
                .header("x-eztunnel", "1");
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            if body.is_some() {
                request = request.header(header::CONTENT_TYPE, "application/json");
            }
            let bytes = body
                .map(|value| serde_json::to_vec(&value))
                .transpose()
                .map_err(|e| FleetError::new("invalid_input", e))?
                .unwrap_or_default();
            let request = request
                .body(Full::new(Bytes::from(bytes)))
                .map_err(|e| FleetError::new("invalid_input", e))?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|e| FleetError::new("dashboard_unavailable", e))?;
            let status = response.status();
            let headers = response.headers().clone();
            let data = response
                .into_body()
                .collect()
                .await
                .map_err(|e| FleetError::new("dashboard_unavailable", e))?
                .to_bytes();
            let body = serde_json::from_slice(&data).map_err(|e| {
                FleetError::new(
                    "invalid_response",
                    format!("dashboard returned invalid JSON: {e}"),
                )
            })?;
            Ok((status, headers, body))
        })
        .await
        .map_err(|_| {
            FleetError::new(
                "dashboard_unavailable",
                "dashboard request did not finish within 55 seconds",
            )
        })?
    }

    async fn api(&self, method: Method, path: &str) -> Result<Value> {
        let (status, _, value) = self.call(method, path, None).await?;
        if status.is_success() {
            Ok(value)
        } else {
            Err(FleetError::api(status, &value))
        }
    }

    pub async fn logout(&mut self) {
        if self.cookie.is_some() {
            let _ = self.call(Method::POST, "/api/logout", None).await;
            if let Some(mut cookie) = self.cookie.take() {
                cookie.zeroize();
            }
        }
    }

    pub async fn servers(&self) -> Result<Value> {
        let mut remote = self.api(Method::GET, "/api/servers").await?;
        let local = self.api(Method::GET, "/api/snapshot").await?;
        remote["local"] = local["snapshot"].clone();
        remote["ok"] = json!(true);
        Ok(remote)
    }

    async fn remote(&self, id: &str) -> Result<Value> {
        let result = self.api(Method::GET, "/api/servers").await?;
        result["servers"]
            .as_array()
            .and_then(|list| list.iter().find(|r| r["id"].as_str() == Some(id)).cloned())
            .ok_or_else(|| {
                FleetError::new(
                    "unknown_server",
                    format!("no dashboard-enrolled server with ID {id}"),
                )
            })
    }

    pub async fn tunnels(&self, server: &str) -> Result<Value> {
        if server == "local" {
            let data = self.api(Method::GET, "/api/snapshot").await?;
            let snapshot = &data["snapshot"];
            return Ok(json!({
                "ok": true, "server": "local", "online": true,
                "last_seen_ms": snapshot["at"], "tunnels": snapshot["tunnels"],
            }));
        }
        let remote = self.remote(server).await?;
        let online = remote["online"].as_bool().unwrap_or(false);
        let tunnels = if online {
            remote["snapshot"]["tunnels"].clone()
        } else {
            Value::Null
        };
        Ok(json!({
            "ok": true, "server": server, "online": online,
            "last_seen_ms": remote["last_seen"].as_u64().map(|at| at.saturating_mul(1000)),
            "tunnels": tunnels,
        }))
    }

    pub async fn action(&self, server: &str, tunnel: &str, action: &str) -> Result<Value> {
        if !matches!(action, "start" | "stop" | "restart") {
            return Err(invalid("action must be start, stop or restart"));
        }
        let path = if server == "local" {
            format!("/api/tunnels/{}/{}", segment(tunnel), action)
        } else {
            if !self.remote(server).await?["online"]
                .as_bool()
                .unwrap_or(false)
            {
                return Err(FleetError::new(
                    "remote_offline",
                    format!("server {server} is currently offline"),
                ));
            }
            format!(
                "/api/servers/{}/tunnels/{}/{}",
                segment(server),
                segment(tunnel),
                action
            )
        };
        let result = self.api(Method::POST, &path).await?;
        Ok(
            json!({"ok": true, "server": server, "tunnel": tunnel, "action": action, "result": result}),
        )
    }

    pub async fn logs(&self, server: &str, tunnel: &str, lines: usize) -> Result<Value> {
        if !(1..=super::ops::MAX_LINES).contains(&lines) {
            return Err(invalid(format!(
                "lines must be 1 to {}",
                super::ops::MAX_LINES
            )));
        }
        let path = if server == "local" {
            format!("/api/tunnels/{}/logs?lines={lines}", segment(tunnel))
        } else {
            if !self.remote(server).await?["online"]
                .as_bool()
                .unwrap_or(false)
            {
                return Err(FleetError::new(
                    "remote_offline",
                    format!("server {server} is currently offline"),
                ));
            }
            format!(
                "/api/servers/{}/tunnels/{}/logs?lines={lines}",
                segment(server),
                segment(tunnel)
            )
        };
        let result = self.api(Method::GET, &path).await?;
        Ok(json!({"ok": true, "server": server, "tunnel": tunnel, "logs": result}))
    }
}

/// Escape each path component rather than allowing tunnel names to add path or query segments.
fn segment(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

pub enum Operation {
    Servers,
    Tunnels {
        server: String,
    },
    Action {
        server: String,
        tunnel: String,
        action: &'static str,
    },
    Logs {
        server: String,
        tunnel: String,
        lines: usize,
    },
}

pub async fn execute(state_dir: &Path, from_stdin: bool, operation: Operation) -> Result<Value> {
    let mut client = FleetClient::connect(state_dir, from_stdin).await?;
    let result = match operation {
        Operation::Servers => client.servers().await,
        Operation::Tunnels { server } => client.tunnels(&server).await,
        Operation::Action {
            server,
            tunnel,
            action,
        } => client.action(&server, &tunnel, action).await,
        Operation::Logs {
            server,
            tunnel,
            lines,
        } => client.logs(&server, &tunnel, lines).await,
    };
    client.logout().await;
    result
}

/// The same client and operation paths as the headless CLI; no separate menu state.
pub async fn menu(state_dir: &Path, from_stdin: bool) -> AnyResult<()> {
    use crate::manager::ui;
    let mut client = FleetClient::connect(state_dir, from_stdin).await?;
    let result = async {
        loop {
            ui::banner("Dashboard servers");
            let inventory = client.servers().await?;
            let mut items = vec!["local  This server".to_string()];
            let mut ids = vec!["local".to_string()];
            for server in inventory["servers"].as_array().into_iter().flatten() {
                let id = server["id"].as_str().unwrap_or("");
                if id.is_empty() {
                    continue;
                }
                let online = if server["online"] == true {
                    "online"
                } else {
                    "offline"
                };
                items.push(format!(
                    "{}  {} ({online})",
                    id,
                    server["name"].as_str().unwrap_or("server")
                ));
                ids.push(id.to_string());
            }
            items.push("Back".to_string());
            let Some(index) = ui::choose("Server", &items, 0)? else {
                break;
            };
            let Some(server) = ids.get(index) else {
                break;
            };
            let inventory = client.tunnels(server).await?;
            if inventory["online"] != true {
                ui::warn("This server is offline; no remote operation will be attempted.");
                ui::pause();
                continue;
            }
            let mut tunnels = Vec::new();
            for tunnel in inventory["tunnels"].as_array().into_iter().flatten() {
                if let Some(name) = tunnel["name"].as_str() {
                    let state = tunnel["state"].as_str().unwrap_or("unknown");
                    tunnels.push((name.to_string(), format!("{name}  ({state})")));
                }
            }
            if tunnels.is_empty() {
                ui::info("No tunnel snapshot is available (or there are no tunnels).");
                ui::pause();
                continue;
            }
            let mut choices: Vec<String> = tunnels.iter().map(|(_, label)| label.clone()).collect();
            choices.push("Back".into());
            let Some(tunnel_index) = ui::choose("Tunnel", &choices, 0)? else {
                continue;
            };
            let Some((name, _)) = tunnels.get(tunnel_index) else {
                continue;
            };
            let actions =
                ["Status", "Start", "Stop", "Restart", "Recent logs", "Back"].map(str::to_string);
            let Some(choice) = ui::choose("Action", &actions, 0)? else {
                continue;
            };
            let result = match choice {
                0 => client.tunnels(server).await,
                1..=3 => {
                    let action = match choice {
                        1 => "start",
                        2 => "stop",
                        _ => "restart",
                    };
                    if !ui::confirm(&format!("{action} {name} on {server}?"), false)? {
                        continue;
                    }
                    client.action(server, name, action).await
                }
                4 => client.logs(server, name, 40).await,
                _ => continue,
            };
            match result {
                Ok(value) => ui::info(&serde_json::to_string_pretty(&value)?),
                Err(error) => ui::warn(&error.to_string()),
            };
            ui::pause();
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    client.logout().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_dashboard_reports_configuration_before_prompting_for_password() {
        let dir = tempfile::tempdir().unwrap();
        let error = FleetClient::connect(dir.path(), false).await.err().unwrap();
        assert_eq!(error.code, "dashboard_not_configured");
    }

    #[test]
    fn path_components_cannot_inject_another_route() {
        assert_eq!(
            segment("node name/with?query=%"),
            "node%20name%2Fwith%3Fquery%3D%25"
        );
        assert_eq!(segment("a_b-1.2~x"), "a_b-1.2~x");
    }

    #[test]
    fn errors_have_distinct_exit_codes_and_json() {
        let bad = FleetError::new("remote_offline", "offline");
        assert_eq!(bad.exit_code(), 4);
        assert_eq!(bad.as_json()["error"], "remote_offline");
        let auth = FleetError::api(StatusCode::UNAUTHORIZED, &json!({"error":"signed_out"}));
        assert_eq!(auth.exit_code(), 3);
        let missing = FleetError::new("unknown_server", "missing");
        assert_eq!(missing.exit_code(), 5);
    }

    #[test]
    fn local_pins_refuse_unknown_certificate() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = CertificateDer::from(vec![1, 2, 3]);
        let verifier = LocalCertificate {
            digests: vec![Sha256::digest(b"known").into()],
            provider,
        };
        let name = ServerName::try_from("localhost".to_string()).unwrap();
        assert!(
            verifier
                .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_err()
        );
    }
    /// Exercises the real HTTPS router/session and fleet snapshot, without host services.
    /// This is protocol-level QA; it does not substitute for two managed physical nodes.
    #[tokio::test]
    async fn dashboard_and_terminal_client_share_actions_and_offline_truth() {
        use super::super::{audit, auth, data, fleet, history, http, ops, tls, write_private};
        use std::{
            net::{IpAddr, Ipv4Addr, SocketAddr},
            time::Duration,
        };

        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let settings = super::super::Settings {
            version: 1,
            port,
            password_hash: auth::hash_password("pw").unwrap(),
            created: 1,
            acme: None,
        };
        super::super::save_settings(dir.path(), &settings).unwrap();
        let (tls_config, _) = tls::load_or_create(dir.path(), "localhost").unwrap();
        write_private(
            &dir.path().join("agents.json"),
            br#"[{"id":"abcdef123456","key":"a","name":"offline-node","added":1}]"#,
        )
        .unwrap();

        let demo = ops::DemoOps::new(&["game-fec", "web-wss", "cdn-xhttps", "backup-tcp"]);
        let state = Arc::new(http::AppState {
            history: Arc::new(history::History::new(Box::new(history::DemoStore {
                tunnels: Vec::new(),
                started_minute: 0,
            }))),
            auth: auth::Auth::new(settings.password_hash),
            audit: audit::Audit::disabled(),
            live: data::Live::start(
                Box::new(data::DemoSource::with_ops(true, demo.clone())),
                None,
            ),
            ops: Arc::new(demo),
            busy: Default::default(),
            followers: Arc::new(tokio::sync::Semaphore::new(http::MAX_FOLLOWERS)),
            fleet: Some(fleet::Fleet::open(dir.path()).unwrap()),
            public: ("127.0.0.1".into(), port),
            agent_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            cert: None,
            demo: false,
            secure: true,
            state_dir: dir.path().into(),
            alerts: Default::default(),
        });
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let task = tokio::spawn(async move {
            let _ = http::serve(state, address, Some(tls_config)).await;
        });
        let mut ready = false;
        for _ in 0..80 {
            if TcpStream::connect(address).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            ready,
            "test HTTPS Dashboard must bind its own loopback listener"
        );

        let wrong = FleetClient::connect_password(dir.path(), "invalid").await;
        assert_eq!(wrong.err().unwrap().exit_code(), 3);

        let mut client = FleetClient::connect_password(dir.path(), "pw")
            .await
            .unwrap();
        let all = client.servers().await.unwrap();
        assert_eq!(all["servers"][0]["id"], "abcdef123456");
        assert_eq!(all["servers"][0]["online"], false);
        assert_eq!(all["servers"][0]["snapshot"], Value::Null);

        let unavailable = client.tunnels("abcdef123456").await.unwrap();
        assert_eq!(unavailable["online"], false);
        assert_eq!(unavailable["tunnels"], Value::Null);
        assert_eq!(
            client
                .action("abcdef123456", "game-fec", "start")
                .await
                .unwrap_err()
                .code,
            "remote_offline"
        );
        assert_eq!(
            client.tunnels("not-registered").await.unwrap_err().code,
            "unknown_server"
        );

        let local = client.tunnels("local").await.unwrap();
        assert_eq!(local["online"], true);
        assert!(
            local["tunnels"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["name"] == "game-fec")
        );

        let acted = client.action("local", "game-fec", "stop").await.unwrap();
        assert_eq!(acted["ok"], true);
        assert_eq!(acted["result"]["ok"], true);
        let mut reflected = false;
        for _ in 0..100 {
            let status = client.tunnels("local").await.unwrap();
            if status["tunnels"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["name"] == "game-fec" && t["state"] == "stopped")
            {
                reflected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(reflected, "the CLI action must appear in the Web snapshot");

        let lines = client.logs("local", "game-fec", 20).await.unwrap();
        assert_eq!(lines["ok"], true);
        assert!(lines["logs"]["lines"].is_array());
        assert_eq!(
            client
                .logs("local", "game-fec", 1001)
                .await
                .unwrap_err()
                .exit_code(),
            2
        );

        client.logout().await;
        assert_eq!(client.servers().await.unwrap_err().exit_code(), 3);

        // A different leaf certificate must never be silently trusted for the local API.
        std::fs::write(
            dir.path().join("cert.der"),
            b"not the originally saved cert",
        )
        .unwrap();
        assert_eq!(
            FleetClient::connect_password(dir.path(), "pw")
                .await
                .err()
                .unwrap()
                .code,
            "tls"
        );
        task.abort();
        let _ = task.await;
    }
}
