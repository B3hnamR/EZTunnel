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
    path::{Path, PathBuf},
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
    pub report: Option<Value>,
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
            report: None,
        }
    }

    fn partial(detail: impl std::fmt::Display, report: Value) -> Self {
        Self {
            code: "partial_failure".into(),
            detail: detail.to_string(),
            status: None,
            report: Some(report),
        }
    }

    fn api(status: StatusCode, value: &Value) -> Self {
        let code = value["error"].as_str().unwrap_or("api_error");
        let detail = value["detail"].as_str().unwrap_or(code);
        Self {
            code: code.into(),
            detail: detail.into(),
            status: Some(status.as_u16()),
            report: None,
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
                "remote_offline" | "snapshot_unavailable" | "dashboard_unavailable" => 4,
                "unknown_server" | "unknown_tunnel" => 5,
                "partial_failure" => 8,
                _ => 7,
            },
        }
    }

    pub fn as_json(&self) -> Value {
        let mut value = json!({"ok": false, "error": self.code, "detail": self.detail, "http_status": self.status});
        if let Some(report) = &self.report {
            value["report"] = report.clone();
        }
        value
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
        self.call_with_timeout(method, path, body, Duration::from_secs(55))
            .await
    }

    async fn call_with_timeout(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        deadline: Duration,
    ) -> Result<(StatusCode, http::HeaderMap, Value)> {
        let port = self.port;
        let tls = self.tls.clone();
        let cookie = self.cookie.clone();
        let path = path.to_owned();
        tokio::time::timeout(deadline, async move {
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
                format!(
                    "dashboard request did not finish within {} seconds",
                    deadline.as_secs()
                ),
            )
        })?
    }

    async fn api(&self, method: Method, path: &str) -> Result<Value> {
        self.api_body(method, path, None, Duration::from_secs(55))
            .await
    }

    async fn api_body(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        deadline: Duration,
    ) -> Result<Value> {
        let (status, _, value) = self.call_with_timeout(method, path, body, deadline).await?;
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
        self.action_guarded(server, tunnel, action, None).await
    }

    async fn action_guarded(&self, server: &str, tunnel: &str, action: &str, pair: Option<&str>) -> Result<Value> {
        if let Some(pair) = pair && !super::ops::valid_pair(pair) {
            return Err(invalid("expected pair fingerprint must be 16 hexadecimal characters"));
        }
        if !matches!(action, "start" | "stop" | "restart") {
            return Err(invalid("action must be start, stop or restart"));
        }
        let path = if server == "local" {
            format!("/api/tunnels/{}/{}", segment(tunnel),
                if pair.is_some() { format!("paired-{action}") } else { action.to_string() })
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
                if pair.is_some() { format!("paired-{action}") } else { action.to_string() }
            )
        };
        let result = self.api_body(
            Method::POST, &path,
            pair.map(|pair| json!({"expect_pair": pair})),
            Duration::from_secs(55),
        ).await?;
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

    fn tunnel_path(server: &str, name: &str) -> String {
        if server == "local" {
            format!("/api/tunnels/{}", segment(name))
        } else {
            format!("/api/servers/{}/tunnels/{}", segment(server), segment(name))
        }
    }

    async fn require_online(&self, server: &str) -> Result<()> {
        if server != "local"
            && !self.remote(server).await?["online"]
                .as_bool()
                .unwrap_or(false)
        {
            return Err(FleetError::new(
                "remote_offline",
                format!("server {server} is offline"),
            ));
        }
        Ok(())
    }

    pub async fn options(&self) -> Result<Value> {
        self.api(Method::GET, "/api/new-tunnel").await
    }

    pub async fn create(&self, form: Value) -> Result<Value> {
        if !form.is_object() {
            return Err(invalid("the tunnel form must be a JSON object"));
        }
        let iran = form["iran"]
            .as_str()
            .ok_or_else(|| invalid("form.iran must be a selected server ID or local"))?;
        let foreign = form["foreign"]
            .as_str()
            .ok_or_else(|| invalid("form.foreign must be a selected server ID or local"))?;
        if iran == foreign {
            return Err(invalid("select two different servers"));
        }
        self.require_online(iran).await?;
        self.require_online(foreign).await?;
        self.api_body(
            Method::POST,
            "/api/new-tunnel",
            Some(form),
            Duration::from_secs(135),
        )
        .await
    }

    pub async fn status(&self, server: &str, tunnel: &str) -> Result<Value> {
        let inventory = self.tunnels(server).await?;
        selected_status(inventory, tunnel)
    }

    pub async fn runtime(&self, server: &str, tunnel: &str) -> Result<Value> {
        self.require_online(server).await?;
        let live = self.api(Method::GET, &format!("{}/status", Self::tunnel_path(server, tunnel))).await?;
        Ok(json!({"ok":true,"server":server,"tunnel":tunnel,"runtime":live}))
    }

    pub async fn settings(&self, server: &str, tunnel: &str) -> Result<Value> {
        self.require_online(server).await?;
        self.api(
            Method::GET,
            &format!("{}/settings", Self::tunnel_path(server, tunnel)),
        )
        .await
    }

    pub async fn edit(&self, server: &str, tunnel: &str, changes: Value) -> Result<Value> {
        if !changes.is_object() {
            return Err(invalid("edit changes must be a JSON object"));
        }
        self.require_online(server).await?;
        self.api_body(
            Method::POST,
            &format!("{}/settings", Self::tunnel_path(server, tunnel)),
            Some(changes),
            Duration::from_secs(110),
        )
        .await
    }

    pub async fn undo(&self, server: &str, tunnel: &str) -> Result<Value> {
        self.require_online(server).await?;
        self.api_body(
            Method::POST,
            &format!("{}/undo", Self::tunnel_path(server, tunnel)),
            Some(json!({})),
            Duration::from_secs(110),
        )
        .await
    }

    pub async fn delete(
        &self,
        server: &str,
        tunnel: &str,
        expected_pair: Option<&str>,
    ) -> Result<Value> {
        self.require_online(server).await?;
        if let Some(pair) = expected_pair
            && !super::ops::valid_pair(pair)
        {
            return Err(invalid(
                "expect-pair must be a 16-character hexadecimal fingerprint",
            ));
        }
        let reply = self
            .api_body(
                Method::DELETE,
                &Self::tunnel_path(server, tunnel),
                expected_pair.map(|pair| json!({"expect_pair": pair})),
                Duration::from_secs(55),
            )
            .await?;
        Ok(json!({"ok":true,"server":server,"tunnel":tunnel,"deleted":reply["ok"]}))
    }

    pub async fn join_code(&self) -> Result<Value> {
        self.api_body(
            Method::POST,
            "/api/join-codes",
            Some(json!({})),
            Duration::from_secs(30),
        )
        .await
    }

    pub async fn remove_server(&self, server: &str) -> Result<Value> {
        if server == "local" {
            return Err(invalid("local is not an enrolled Agent"));
        }
        self.remote(server).await?;
        self.api(Method::DELETE, &format!("/api/servers/{}", segment(server)))
            .await
    }

    pub async fn health(&self, server: &str) -> Result<Value> {
        self.require_online(server).await?;
        self.api_body(
            Method::POST,
            &format!("/api/servers/{}/tools/health", segment(server)),
            Some(json!({})),
            Duration::from_secs(110),
        )
        .await
    }

    pub async fn restart_all(&self, server: &str) -> Result<Value> {
        self.require_online(server).await?;
        let path = if server == "local" {
            "/api/restart-all".to_string()
        } else {
            format!("/api/servers/{}/restart-all", segment(server))
        };
        let response = self.api_body(
            Method::POST,
            &path,
            Some(json!({})),
            Duration::from_secs(325),
        )
        .await?;
        classify_restart_all(server, response)
    }

    pub async fn tool(&self, server: &str, tunnel: &str, tool: &str, form: Value) -> Result<Value> {
        if !matches!(tool, "speedtest" | "pairing" | "quota_reset") {
            return Err(invalid("unknown tunnel tool"));
        }
        if !form.is_object() {
            return Err(invalid("tool arguments must be a JSON object"));
        }
        self.require_online(server).await?;
        self.api_body(
            Method::POST,
            &format!("{}/tools/{tool}", Self::tunnel_path(server, tunnel)),
            Some(form),
            Duration::from_secs(if tool == "speedtest" { 180 } else { 70 }),
        )
        .await
    }

    /// Build the set from the Dashboard's live snapshots; never read a local copy of Agent registry.
    async fn pair_targets(&self, server: &str, name: &str) -> Result<PairTargets> {
        let all = self.servers().await?;
        let mut places = vec![("local".to_string(), true, all["local"]["tunnels"].clone())];
        let mut unknown = Vec::new();
        for s in all["servers"].as_array().into_iter().flatten() {
            if let Some(id) = s["id"].as_str() {
                let online = s["online"] == true;
                if !online {
                    unknown.push(id.to_string());
                }
                places.push((id.to_string(), online, s["snapshot"]["tunnels"].clone()));
            }
        }
        let selected = places
            .iter()
            .find(|(id, _, _)| id == server)
            .ok_or_else(|| FleetError::new("unknown_server", format!("unknown server {server}")))?;
        if !selected.1 {
            return Err(FleetError::new(
                "remote_offline",
                format!("server {server} is offline"),
            ));
        }
        let candidate = selected
            .2
            .as_array()
            .and_then(|items| items.iter().find(|t| t["name"] == name))
            .ok_or_else(|| {
                FleetError::new(
                    "unknown_tunnel",
                    format!("no tunnel named {name} on {server}"),
                )
            })?;
        let pair = candidate["pair"]
            .as_str()
            .filter(|v| super::ops::valid_pair(v))
            .ok_or_else(|| {
                invalid("this tunnel has no known pair fingerprint; use a single-target operation")
            })?
            .to_owned();
        let mut targets = Vec::new();
        for (id, online, tunnels) in places {
            if !online {
                continue;
            }
            for tunnel in tunnels.as_array().into_iter().flatten() {
                if tunnel["pair"] == pair {
                    if let Some(name) = tunnel["name"].as_str() {
                        targets.push(PairTarget {
                            server: id.clone(),
                            name: name.to_owned(),
                            side: tunnel["side"].as_str().unwrap_or("").to_owned(),
                            direction: tunnel["direction"].as_str().unwrap_or("").to_owned(),
                        });
                    }
                }
            }
        }
        if targets.len() != 2 {
            return Err(FleetError::new(
                "pair_incomplete",
                format!(
                    "expected exactly two online endpoints for pair {pair}, found {}; no changes made (offline servers: {})",
                    targets.len(),
                    unknown.join(", ")
                ),
            ));
        }
        if targets[0].server == targets[1].server
            || !matches!(targets[0].direction.as_str(), "reverse" | "direct")
            || !targets.iter().any(|t| t.side == "iran")
            || !targets.iter().any(|t| t.side == "foreign")
            || targets.iter().skip(1).any(|t| t.direction != targets[0].direction)
        {
            return Err(FleetError::new(
                "pair_inconsistent",
                "endpoints disagree on direction or role; no changes made",
            ));
        }
        let listening = if targets[0].direction == "reverse" {
            "iran"
        } else {
            "foreign"
        };
        targets.sort_by_key(|t| if t.side == listening { 0 } else { 1 });
        Ok(PairTargets {
            pair,
            targets,
            offline_unverified: unknown,
        })
    }

    /// No distributed transaction exists in the Web UI either: apply in a stable order,
    /// record successes and failures, and return a recoverable nonzero result on partial work.
    pub async fn paired(&self, server: &str, tunnel: &str, operation: &str) -> Result<Value> {
        let group = self.pair_targets(server, tunnel).await?;
        self.paired_targets(group, operation).await
    }

    async fn paired_targets(&self, group: PairTargets, operation: &str) -> Result<Value> {
        if !matches!(operation, "start" | "stop" | "restart" | "delete") {
            return Err(invalid("unknown paired action"));
        }
        let mut attempts = Vec::new();
        let steps = if operation == "restart" {
            vec!["stop", "start"]
        } else {
            vec![operation]
        };
        for step in steps {
            let mut items = group.targets.clone();
            if step == "stop" || step == "delete" {
                items.reverse();
            } // dialer first
            for target in &items {
                let result = if step == "delete" {
                    self.delete(&target.server, &target.name, Some(&group.pair))
                        .await
                } else {
                    self.action_guarded(&target.server, &target.name, step, Some(&group.pair)).await
                };
                let bad_start =
                    matches!(&result, Ok(v) if step == "start" && v["result"]["came_up"] == false);
                let ok = result.is_ok() && !bad_start;
                attempts.push(json!({"server": target.server, "name": target.name,
                    "action":step,"ok":ok,"result":result.as_ref().ok(),
                    "error":result.as_ref().err().map(|e| e.as_json())}));
                if !ok {
                    return Err(FleetError::partial(
                        "paired operation is incomplete; inspect the completed and remaining endpoints before retrying",
                        json!({"pair":group.pair,"operation":operation,"attempts":attempts,
                            "remaining":items.iter().skip_while(|t| t.server != target.server || t.name != target.name)
                                .map(|t| json!({"server":t.server,"name":t.name})).collect::<Vec<_>>(),
                            "offline_unverified":group.offline_unverified}),
                    ));
                }
            }
        }
        Ok(
            json!({"ok":true,"pair":group.pair,"operation":operation,"attempts":attempts,
            "offline_unverified":group.offline_unverified}),
        )
    }
}

#[derive(Clone)]
struct PairTarget {
    server: String,
    name: String,
    side: String,
    direction: String,
}
#[derive(Clone)]
struct PairTargets {
    pair: String,
    targets: Vec<PairTarget>,
    offline_unverified: Vec<String>,
}

/// Read a bounded JSON object as data, without touching stdin (reserved for the password).
fn read_json_file(path: &Path) -> Result<Value> {
    if path.as_os_str() == "-" {
        return Err(invalid("use a file for JSON; standard input is reserved for the password"));
    }
    let file = std::fs::File::open(path)
        .map_err(|e| invalid(format!("cannot read {}: {e}", path.display())))?;
    let metadata = file.metadata()
        .map_err(|e| invalid(format!("cannot inspect {}: {e}", path.display())))?;
    if !metadata.is_file() || metadata.len() > 8192 {
        return Err(invalid("JSON file must be a regular file no larger than 8 KiB"));
    }
    // Bound the actual descriptor read too: metadata can go stale if the file grows.
    let mut bytes = Vec::with_capacity(8193);
    file.take(8193).read_to_end(&mut bytes)
        .map_err(|e| invalid(format!("cannot read {}: {e}", path.display())))?;
    if bytes.len() > 8192 {
        return Err(invalid("JSON file grew beyond 8 KiB while reading"));
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| invalid(format!("JSON file: {e}")))?;
    if !value.is_object() {
        return Err(invalid("JSON file must contain an object"));
    }
    Ok(value)
}

/// An HTTP 200 does not mean restart-all succeeded: both Dashboard handlers
/// deliberately return 200 with ok=false and per-tunnel outcomes on partial failure.
fn classify_restart_all(server: &str, response: Value) -> Result<Value> {
    match response["ok"].as_bool() {
        Some(true) => Ok(response),
        Some(false) => Err(FleetError::partial(
            format!("one or more tunnels on {server} failed to restart; inspect per-tunnel results"),
            json!({"server": server, "results": response["results"]}),
        )),
        None => Err(FleetError::new(
            "invalid_response",
            format!("restart-all on {server} returned no aggregate success indicator"),
        )),
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
    Options,
    Create {
        form_file: PathBuf,
    },
    Action {
        server: String,
        tunnel: String,
        action: &'static str,
        both: bool,
    },
    Status {
        server: String,
        tunnel: String,
        live: bool,
    },
    Logs {
        server: String,
        tunnel: String,
        lines: usize,
    },
    Settings {
        server: String,
        tunnel: String,
    },
    Edit {
        server: String,
        tunnel: String,
        changes_file: PathBuf,
    },
    Undo {
        server: String,
        tunnel: String,
    },
    Delete {
        server: String,
        tunnel: String,
        both: bool,
        expected_pair: Option<String>,
        confirm: String,
    },
    JoinCode,
    RemoveServer {
        server: String,
        confirm: String,
    },
    Health {
        server: String,
    },
    RestartAll {
        server: String,
    },
    Tool {
        server: String,
        tunnel: String,
        tool: String,
        form_file: Option<PathBuf>,
    },
}

pub async fn execute(state_dir: &Path, from_stdin: bool, operation: Operation) -> Result<Value> {
    // All local validation precedes Dashboard authentication, and never consumes password stdin.
    if let Operation::Logs { lines, .. } = &operation
        && !(1..=super::ops::MAX_LINES).contains(lines)
    {
        return Err(invalid(format!(
            "lines must be 1 to {}",
            super::ops::MAX_LINES
        )));
    }
    if let Operation::Delete {
        tunnel,
        confirm,
        expected_pair,
        ..
    } = &operation
    {
        if tunnel != confirm {
            return Err(invalid("--confirm must exactly match the tunnel name"));
        }
        if let Some(pair) = expected_pair
            && !super::ops::valid_pair(pair)
        {
            return Err(invalid("--expect-pair must be 16 hexadecimal characters"));
        }
    }
    if let Operation::RemoveServer { server, confirm } = &operation
        && (server == "local" || server != confirm)
    {
        return Err(invalid(
            "--confirm must exactly match the enrolled server ID",
        ));
    }
    let form = match &operation {
        Operation::Create { form_file } => Some(read_json_file(form_file)?),
        Operation::Edit { changes_file, .. } => Some(read_json_file(changes_file)?),
        Operation::Tool {
            form_file: Some(file),
            ..
        } => Some(read_json_file(file)?),
        _ => None,
    };
    let mut client = FleetClient::connect(state_dir, from_stdin).await?;
    let result = match operation {
        Operation::Servers => client.servers().await,
        Operation::Tunnels { server } => client.tunnels(&server).await,
        Operation::Options => client.options().await,
        Operation::Create { .. } => client.create(form.expect("validated form")).await,
        Operation::Action {
            server,
            tunnel,
            action,
            both,
        } => {
            if both {
                client.paired(&server, &tunnel, action).await
            } else {
                client.action(&server, &tunnel, action).await
            }
        }
        Operation::Status { server, tunnel, live } => {
            if live { client.runtime(&server, &tunnel).await } else { client.status(&server, &tunnel).await }
        },
        Operation::Logs {
            server,
            tunnel,
            lines,
        } => client.logs(&server, &tunnel, lines).await,
        Operation::Settings { server, tunnel } => client.settings(&server, &tunnel).await,
        Operation::Edit { server, tunnel, .. } => {
            client
                .edit(&server, &tunnel, form.expect("validated changes"))
                .await
        }
        Operation::Undo { server, tunnel } => client.undo(&server, &tunnel).await,
        Operation::Delete {
            server,
            tunnel,
            both,
            expected_pair,
            ..
        } => {
            if both {
                match client.pair_targets(&server, &tunnel).await {
                    Err(error) => Err(error),
                    Ok(group) if expected_pair.as_deref().is_some_and(|p| !p.eq_ignore_ascii_case(&group.pair)) => {
                        Err(FleetError::new(
                            "pair_mismatch",
                            "the selected tunnel has another pair fingerprint",
                        ))
                    }
                    Ok(group) => client.paired_targets(group, "delete").await,
                }
            } else {
                let observed = if expected_pair.is_none() {
                    client.status(&server, &tunnel).await.map(|v| v["tunnel"]["pair"].as_str().map(str::to_owned))
                } else { Ok(None) };
                match observed {
                    Err(error) => Err(error),
                    Ok(observed) => client.delete(&server, &tunnel, expected_pair.as_deref().or(observed.as_deref())).await,
                }
            }
        }
        Operation::JoinCode => client.join_code().await,
        Operation::RemoveServer { server, .. } => client.remove_server(&server).await,
        Operation::Health { server } => client.health(&server).await,
        Operation::RestartAll { server } => client.restart_all(&server).await,
        Operation::Tool {
            server,
            tunnel,
            tool,
            ..
        } => {
            client
                .tool(&server, &tunnel, &tool, form.unwrap_or_else(|| json!({})))
                .await
        }
    };
    client.logout().await;
    result
}

/// A confirmation's Back/Esc is navigation, not a failed tunnel operation.
fn confirm_action(answer: AnyResult<bool>) -> AnyResult<bool> {
    match answer {
        Err(error) if crate::manager::ui::is_back(&error) => Ok(false),
        other => other,
    }
}

fn selected_status(inventory: Value, name: &str) -> Result<Value> {
    let server = inventory["server"].as_str().unwrap_or("unknown");
    if inventory["online"] != true {
        return Err(FleetError::new(
            "remote_offline",
            format!("server {server} is offline; its tunnel state is unknown"),
        ));
    }
    let tunnels = inventory["tunnels"].as_array().ok_or_else(|| FleetError::new(
        "snapshot_unavailable",
        format!("server {server} has no current tunnel snapshot"),
    ))?;
    let tunnel = tunnels.iter()
        .find(|t| t["name"] == name)
        .cloned()
        .ok_or_else(|| FleetError::new("unknown_tunnel", format!("no tunnel named {name}")))?;
    Ok(json!({
        "ok": true, "server": inventory["server"], "online": true,
        "last_seen_ms": inventory["last_seen_ms"], "tunnel": tunnel,
    }))
}

/// Ask for a validated field; Esc and /back exit without changing Dashboard state.
fn menu_text(prompt: &str, default: Option<&str>) -> AnyResult<String> {
    crate::manager::ui::ask(prompt, default, |text: &String| {
        if text.trim().is_empty() {
            Err("a value is required".into())
        } else {
            Ok(())
        }
    })
}

fn menu_port(prompt: &str, default: u16) -> AnyResult<u16> {
    let entered =
        crate::manager::ui::ask(
            prompt,
            Some(&default.to_string()),
            |text: &String| match text.parse::<u16>() {
                Ok(v) if v > 0 => Ok(()),
                _ => Err("enter 1 to 65535".into()),
            },
        )?;
    Ok(entered.parse()?)
}

/// Use the effective carrier, including for the synthetic IPv6 selector,
/// instead of assuming that IPv6 inherits the TCP entry's options.
fn wizard_transport<'a>(transports: &'a [Value], name: &str) -> Result<&'a Value> {
    transports.iter()
        .find(|entry| entry["name"] == name)
        .ok_or_else(|| invalid(format!("unsupported Dashboard wizard carrier {name}")))
}

/// Game forwards datagrams, so TCP-only is not a valid guided Game choice.
fn guided_forward_protocols(is_game: bool) -> (&'static [&'static str], usize) {
    if is_game {
        (&["udp", "both"], 1)
    } else {
        (&["tcp", "udp", "both"], 0)
    }
}

fn menu_ip(prompt: &str) -> AnyResult<std::net::IpAddr> {
    let raw = crate::manager::ui::ask(prompt, None, |text: &String| {
        if text.trim().trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() {
            Ok(())
        } else {
            Err("enter a valid IPv4 or IPv6 address (not a hostname)".into())
        }
    })?;
    Ok(raw.trim().trim_matches(['[', ']']).parse()?)
}

/// Keep the guided Game form aligned with the shared Dashboard wizard requirements.
fn guided_game_form(
    form: &mut Value,
    is_game: bool,
    iran_address: Option<std::net::IpAddr>,
) -> Result<()> {
    if !is_game {
        return Ok(());
    }
    form["game"] = json!(true);
    if form["carry"] == "ports" && form["protocol"].as_str().unwrap_or("tcp") == "tcp" {
        return Err(invalid("Game requires UDP or both forwarding, or SOCKS5"));
    }
    if form["direction"] == "direct" {
        let ip = iran_address.ok_or_else(|| invalid("direct Game requires the Iran endpoint IP"))?;
        form["iran_address"] = json!(ip.to_string());
    }
    Ok(())
}

async fn menu_create(client: &FleetClient) -> AnyResult<()> {
    use crate::manager::ui;
    let ways = [
        "Guided new tunnel (Dashboard-supported carriers)",
        "Use a Web-compatible JSON form file",
        "Back",
    ]
    .map(str::to_string);
    let Some(way) = ui::choose("Create paired tunnel", &ways, 0)? else {
        return Ok(());
    };
    if way == ways.len() - 1 { return Ok(()); }
    let form = if way == 1 {
        let file = menu_text("JSON form file", None)?;
        read_json_file(Path::new(&file))?
    } else {
        let servers = client.servers().await?;
        let mut places = vec![("local".to_string(), "local · This server".to_string())];
        for entry in servers["servers"].as_array().into_iter().flatten() {
            if entry["online"] != true {
                continue;
            }
            if let Some(id) = entry["id"].as_str() {
                places.push((
                    id.to_owned(),
                    format!("{} · {}", id, entry["name"].as_str().unwrap_or("server")),
                ));
            }
        }
        if places.len() < 2 {
            ui::warn("Enroll and connect another server first.");
            return Ok(());
        }
        let labels: Vec<String> = places.iter().map(|(_, label)| label.clone()).collect();
        let iran_index = ui::choose_required("Iran endpoint", &labels, 0)?;
        let iran = places[iran_index].0.clone();
        let others: Vec<_> = places.iter().filter(|(id, _)| id != &iran).collect();
        let foreign_index = ui::choose_required(
            "Foreign endpoint",
            &others.iter().map(|p| p.1.clone()).collect::<Vec<_>>(),
            0,
        )?;
        let foreign = others[foreign_index].0.clone();
        let name = menu_text("Tunnel name", None)?;
        let options = client.options().await?;
        let types = options["transports"]
            .as_array()
            .ok_or_else(|| invalid("Dashboard did not return transport options"))?;
        let kinds: Vec<String> = types
            .iter()
            .map(|v| v["name"].as_str().unwrap_or("unknown").to_owned())
            .collect();
        let chosen_index = ui::choose_required("Transport", &kinds, 0)?;
        let transport = kinds[chosen_index].clone();
        let ipv6_transport = if transport == "ipv6" {
            let over = types[chosen_index]["transports"]
                .as_array().ok_or_else(|| invalid("missing IPv6 transport list"))?;
            let candidates: Vec<String> = over.iter()
                .filter_map(|v| v.as_str().map(str::to_owned)).collect();
            let choice = ui::choose_required("IPv6 transport", &candidates, 0)?;
            Some(candidates[choice].clone())
        } else {
            None
        };
        let effective = wizard_transport(types, ipv6_transport.as_deref().unwrap_or(&transport))?;
        let is_game = effective["name"] == "game";
        let port = menu_port(
            "Tunnel listen port",
            effective["port"].as_u64().unwrap_or(7000) as u16,
        )?;
        let directions = ["reverse (Iran listens)", "direct (Foreign listens)"].map(str::to_string);
        let direction = if ui::choose_required("Direction", &directions, 0)? == 0 {
            "reverse"
        } else {
            "direct"
        };
        ui::note("Supply the address reachable from the dialing endpoint. This is NOT automatically inferred from a private Agent IP.");
        let address = menu_text("Public IP or hostname of the listening endpoint", None)?;
        let iran_address = if is_game && direction == "direct" {
            Some(menu_ip("Iran endpoint IP reachable from the Foreign server (for Game UDP)")?)
        } else {
            None
        };
        let mut form = json!({"iran": iran, "foreign": foreign, "name": name, "transport": transport,
            "direction": direction, "address": address, "tunnel_port": port, "reach": "local"});
        if let Some(carrier) = ipv6_transport {
            form["ipv6_transport"] = json!(carrier);
        }
        let carry_options = ["Forward ports", "SOCKS5"].map(str::to_string);
        if ui::choose_required("Carry", &carry_options, 0)? == 0 {
            form["carry"] = json!("ports");
            form["ports"] = json!(menu_text("Forwarded ports (e.g. 8080, 8081=80)", None)?);
            let (protocols, default) = guided_forward_protocols(is_game);
            let labels: Vec<String> = protocols.iter().map(|p| (*p).to_owned()).collect();
            let selected = ui::choose_required("Forward protocol", &labels, default)?;
            form["protocol"] = json!(protocols[selected]);
            let reach = ["Loopback targets only (recommended)", "Any target"].map(str::to_string);
            if ui::choose_required("Foreign reach policy", &reach, 0)? == 1 {
                form["reach"] = json!("any");
            }
        } else {
            form["carry"] = json!("socks");
            form["socks_bind"] = json!(menu_text("SOCKS5 bind address", Some("127.0.0.1:1080"))?);
        }
        if effective["options"]["parallax"] == true {
            let modes = ["stream", "packet"].map(str::to_string);
            form["parallax_mode"] = json!(modes[ui::choose_required("Parallax mode", &modes, 0)?]);
        }
        if effective["options"]["tls"] == true {
            let tls = ["classic", "chrome"].map(str::to_string);
            form["tls_profile"] = json!(tls[ui::choose_required("TLS profile", &tls, 0)?]);
            form["tls_fragment"] = json!(ui::confirm("Fragment TLS handshake?", false)?);
        }
        if effective["options"]["pacer"] == true {
            form["fec_pacer"] = json!(ui::confirm("Enable FEC pacer?", false)?);
        }
        guided_game_form(&mut form, is_game, iran_address)?;
        ui::note(
            "Advanced settings such as speed, pool, game, congestion and carrier-specific options can also be supplied through a JSON form file.",
        );
        form
    };
    ui::info(&serde_json::to_string_pretty(&form)?);
    if !confirm_action(ui::confirm("Create and start BOTH endpoints?", false))? {
        return Ok(());
    }
    let value = client.create(form).await?;
    ui::info(&serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn menu_edit(client: &FleetClient, server: &str, name: &str) -> AnyResult<()> {
    use crate::manager::ui;
    loop {
        let editable = client.settings(server, name).await?;
        let mut choices = vec![
            "View editable settings".into(),
            "Change traffic quota".into(),
            "Change restart interval".into(),
            "Change numeric setting".into(),
        ];
        let ports = editable["ports"].is_object();
        if ports {
            choices.push("Change forwarded ports".into());
        }
        choices.push("Apply JSON changes file (all Web options)".into());
        if editable["can_undo"] == true {
            choices.push("Undo previous change".into());
        }
        choices.push("Back".into());
        let Some(choice) = ui::choose("Edit settings", &choices, 0)? else {
            return Ok(());
        };
        let chosen = choices[choice].as_str();
        if chosen == "View editable settings" {
            ui::info(&serde_json::to_string_pretty(&editable)?);
            ui::pause();
            continue;
        }
        let changes = match chosen {
            "Change traffic quota" => {
                let old = editable["quota"]["limit_gb"].as_u64().unwrap_or(0);
                let limit = ui::ask(
                    "Quota in GB (0 = unlimited)",
                    Some(&old.to_string()),
                    |v: &String| {
                        v.parse::<u64>()
                            .ok()
                            .filter(|n| *n <= 1_000_000)
                            .map(|_| ())
                            .ok_or("enter 0..1000000".into())
                    },
                )?
                .parse::<u64>()?;
                let old_days = editable["quota"]["period_days"].as_u64().unwrap_or(30);
                let days = ui::ask(
                    "Quota period in days",
                    Some(&old_days.to_string()),
                    |v: &String| {
                        v.parse::<u64>()
                            .ok()
                            .filter(|n| (1..=3650).contains(n))
                            .map(|_| ())
                            .ok_or("enter 1..3650".into())
                    },
                )?
                .parse::<u64>()?;
                json!({"quota":{"limit_gb":limit,"period_days":days}})
            }
            "Change restart interval" => {
                let old = editable["restart_hours"].as_u64().unwrap_or(0);
                let hours = ui::ask(
                    "Restart every hours (0 = never)",
                    Some(&old.to_string()),
                    |v: &String| {
                        v.parse::<u64>()
                            .ok()
                            .filter(|n| *n <= 8760)
                            .map(|_| ())
                            .ok_or("enter 0..8760".into())
                    },
                )?
                .parse::<u64>()?;
                json!({"restart_hours":hours})
            }
            "Change numeric setting" => {
                let settings = editable["settings"]
                    .as_array()
                    .ok_or_else(|| invalid("no settings available"))?;
                let rows: Vec<String> = settings
                    .iter()
                    .map(|item| {
                        format!(
                            "{} · {} ({}..{})",
                            item["name"].as_str().unwrap_or(""),
                            item["place"].as_str().unwrap_or("top"),
                            item["min"],
                            item["max"]
                        )
                    })
                    .collect();
                if rows.is_empty() {
                    ui::warn("No numeric settings on this tunnel.");
                    continue;
                }
                let index = ui::choose_required("Numeric setting", &rows, 0)?;
                let item = &settings[index];
                let default = item["value"]
                    .as_u64()
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                let min = item["min"].as_u64().unwrap_or(0);
                let max = item["max"].as_u64().unwrap_or(u64::MAX);
                let value = ui::ask(
                    "Value (empty = carrier default)",
                    Some(&default),
                    |v: &String| {
                        if v.is_empty()
                            || v.parse::<u64>()
                                .ok()
                                .is_some_and(|n| (min..=max).contains(&n))
                        {
                            Ok(())
                        } else {
                            Err(format!("enter {min}..{max} or empty"))
                        }
                    },
                )?;
                json!({"settings":[{"name":item["name"],"place":item["place"],
                    "value": if value.is_empty() { Value::Null } else { json!(value.parse::<u64>()?) }}]})
            }
            "Change forwarded ports" => {
                let text = menu_text("Port mappings", editable["ports"]["text"].as_str())?;
                let choices = ["tcp", "udp", "both"].map(str::to_string);
                let protocol = choices[ui::choose_required("Protocol", &choices, 0)?].clone();
                json!({"ports":{"text":text,"protocol":protocol}})
            }
            "Apply JSON changes file (all Web options)" => {
                let path = menu_text("JSON changes file", None)?;
                read_json_file(Path::new(&path))?
            }
            "Undo previous change" => {
                if confirm_action(ui::confirm(
                    &format!("Undo settings of {name} on {server}?"),
                    false,
                ))? {
                    let outcome = client.undo(server, name).await?;
                    ui::info(&serde_json::to_string_pretty(&outcome)?);
                    ui::pause();
                }
                continue;
            }
            _ => return Ok(()),
        };
        ui::info(&serde_json::to_string_pretty(&changes)?);
        if confirm_action(ui::confirm(
            &format!("Apply settings to {name} on {server}?"),
            false,
        ))? {
            let outcome = client.edit(server, name, changes).await?;
            ui::info(&serde_json::to_string_pretty(&outcome)?);
            ui::pause();
        }
    }
}

async fn menu_tunnel(client: &FleetClient, server: &str, name: &str) -> AnyResult<()> {
    use crate::manager::ui;
    loop {
        ui::banner(&format!("Dashboard tunnel · {server}/{name}"));
        let actions = [
            "Status",
            "Start",
            "Stop",
            "Restart",
            "Recent logs",
            "Settings / Edit",
            "Start both paired endpoints",
            "Stop both paired endpoints",
            "Restart both paired endpoints",
            "Delete tunnel (this end or both)",
            "Live control status", "Generate pairing code", "Speed test", "Reset traffic quota",
            "Back",
        ]
        .map(str::to_string);
        let Some(choice) = ui::choose("Action", &actions, 0)? else {
            return Ok(());
        };
        let result: Result<Value> = match choice {
            0 => client.status(server, name).await,
            1..=3 | 6..=8 => {
                let (action, both) = match choice {
                    1 => ("start", false),
                    2 => ("stop", false),
                    3 => ("restart", false),
                    6 => ("start", true),
                    7 => ("stop", true),
                    _ => ("restart", true),
                };
                if !confirm_action(ui::confirm(
                    &format!(
                        "{action} {} on {server}?",
                        if both { "both paired endpoints" } else { name }
                    ),
                    false,
                ))? {
                    continue;
                }
                if both {
                    client.paired(server, name, action).await
                } else {
                    client.action(server, name, action).await
                }
            }
            4 => client.logs(server, name, 40).await,
            5 => {
                if let Err(error) = menu_edit(client, server, name).await {
                    if !ui::is_back(&error) {
                        ui::warn(&format!("{error:#}"));
                        ui::pause();
                    }
                }
                continue;
            }
            9 => {
                let choices = [
                    "Delete BOTH verified paired endpoints",
                    "Delete only this endpoint",
                    "Back",
                ]
                .map(str::to_string);
                let Some(which) = ui::choose("Deletion scope", &choices, 0)? else {
                    continue;
                };
                if which == choices.len() - 1 { continue; }
                let typed = menu_text("Type the exact tunnel name to confirm deletion", None)?;
                if typed != name {
                    ui::warn("Tunnel name did not match: nothing deleted.");
                    continue;
                }
                if !confirm_action(ui::confirm(
                    "Delete the selected owned configuration and service resources?",
                    false,
                ))? {
                    continue;
                }
                if which == 0 {
                    client.paired(server, name, "delete").await
                } else {
                    let status = client.status(server, name).await?;
                    client
                        .delete(server, name, status["tunnel"]["pair"].as_str())
                        .await
                }
            }
            10 => client.runtime(server, name).await,
            11 => {
                if !confirm_action(ui::confirm("Generate a one-time pairing code (secret)?", false))? { continue; }
                let answer = client.tool(server, name, "pairing", json!({})).await;
                if let Ok(ref value) = answer && value["needs_address"] == true {
                    let address = menu_text("Address reachable by the other end", None)?;
                    client.tool(server, name, "pairing", json!({"address":address})).await
                } else { answer }
            }
            12 => {
                if !confirm_action(ui::confirm("Run a live 2 MiB speed test through this tunnel?", false))? { continue; }
                client.tool(server, name, "speedtest", json!({"direction":"down","bytes":2097152,"streams":1})).await
            }
            13 => {
                if !confirm_action(ui::confirm("Reset the tunnel traffic quota and restart its service?", false))? { continue; }
                client.tool(server, name, "quota_reset", json!({})).await
            }
            _ => return Ok(()),
        };
        let success = result.is_ok();
        match result {
            Ok(value) => ui::info(&serde_json::to_string_pretty(&value)?),
            Err(error) => ui::warn(&serde_json::to_string_pretty(&error.as_json())?),
        };
        ui::pause();
        if choice == 9 && success {
            return Ok(());
        }
    }
}

/// All interactive entries use exactly the same authenticated client and state as headless CLI.
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
            items.extend(
                [
                    "Create paired tunnel",
                    "Generate Agent join code",
                    "Remove enrolled Agent",
                    "Back",
                ]
                .map(str::to_string),
            );
            let Some(index) = ui::choose("Server", &items, 0)? else {
                break;
            };
            if index == items.len() - 1 { break; }
            if index >= ids.len() {
                let outcome: AnyResult<()> = async {
                    match index - ids.len() {
                        0 => menu_create(&client).await,
                        1 => {
                            let value = client.join_code().await?;
                            ui::info("Treat the one-time join code like a secret.");
                            ui::info(&serde_json::to_string_pretty(&value)?);
                            Ok(())
                        }
                        2 => {
                            let candidates: Vec<String> = ids.iter().skip(1).cloned().collect();
                            if candidates.is_empty() {
                                ui::warn("No enrolled agents.");
                                Ok(())
                            } else {
                                let selected = ui::choose_required(
                                    "Agent to forget (its tunnels remain)",
                                    &candidates,
                                    0,
                                )?;
                                let id = &candidates[selected];
                                let typed = menu_text("Type server ID to confirm", None)?;
                                if typed == *id
                                    && confirm_action(ui::confirm(
                                        &format!("Forget {id}? Tunnel services keep running."),
                                        false,
                                    ))?
                                {
                                    let reply = client.remove_server(id).await?;
                                    ui::info(&serde_json::to_string_pretty(&reply)?);
                                }
                                Ok(())
                            }
                        }
                        _ => return Ok(()),
                    }
                }
                .await;
                if let Err(error) = outcome {
                    if !ui::is_back(&error) {
                        ui::warn(&format!("{error:#}"));
                    }
                }
                ui::pause();
                continue;
            }
            let server = &ids[index];
            loop {
                ui::banner(&format!("Dashboard tunnels · {server}"));
                let inventory = client.tunnels(server).await?;
                if inventory["online"] != true {
                    ui::warn(
                        "Server offline: its tunnel state is unknown. No mutation is available.",
                    );
                    ui::pause();
                    break;
                }
                let mut tunnels = Vec::new();
                for tunnel in inventory["tunnels"].as_array().into_iter().flatten() {
                    if let Some(name) = tunnel["name"].as_str() {
                        let state = tunnel["state"].as_str().unwrap_or("unknown");
                        tunnels.push((name.to_string(), format!("{name}  ({state})")));
                    }
                }
                if tunnels.is_empty() {
                    ui::info("No tunnels here yet.");
                }
                let mut choices: Vec<String> =
                    tunnels.iter().map(|(_, label)| label.clone()).collect();
                choices.extend(
                    [
                        "Create paired tunnel",
                        "Server health",
                        "Restart all tunnels",
                        "Back",
                    ]
                    .map(str::to_string),
                );
                let Some(choice) = ui::choose("Tunnel", &choices, 0)? else {
                    break;
                };
                if choice == choices.len() - 1 { break; }
                if let Some((name, _)) = tunnels.get(choice) {
                    if let Err(error) = menu_tunnel(&client, server, name).await {
                        if !ui::is_back(&error) {
                            ui::warn(&format!("{error:#}"));
                            ui::pause();
                        }
                    }
                    continue;
                }
                let outcome: AnyResult<()> = async {
                    match choice - tunnels.len() {
                        0 => menu_create(&client).await,
                        1 => {
                            let value = client.health(server).await?;
                            ui::info(&serde_json::to_string_pretty(&value)?);
                            Ok(())
                        }
                        2 => {
                            if confirm_action(ui::confirm(
                                &format!("Restart all tunnels on {server}?"),
                                false,
                            ))? {
                                match client.restart_all(server).await {
                                    Ok(value) => ui::info(&serde_json::to_string_pretty(&value)?),
                                    Err(error) => ui::warn(&serde_json::to_string_pretty(&error.as_json())?),
                                }
                            }
                            Ok(())
                        }
                        _ => return Ok(()),
                    }
                }
                .await;
                if let Err(error) = outcome {
                    if !ui::is_back(&error) {
                        ui::warn(&format!("{error:#}"));
                    }
                }
                ui::pause();
            }
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
    fn cancelled_confirmation_stays_in_menu_without_mutating() {
        assert!(!confirm_action(Err(crate::manager::ui::Back.into())).unwrap());
        assert!(!confirm_action(Ok(false)).unwrap());
        assert!(confirm_action(Ok(true)).unwrap());
        assert!(confirm_action(Err(anyhow::anyhow!("terminal failed"))).is_err());
    }

    #[test]
    fn tunnel_status_is_about_the_selected_tunnel() {
        let inventory = json!({"server": "agent-a", "online": true, "last_seen_ms": 123,
            "tunnels": [{"name": "first", "state": "running"}, {"name": "second", "state": "stopped"}]});
        let status = selected_status(inventory.clone(), "second").unwrap();
        assert_eq!(status["tunnel"]["name"], "second");
        assert_eq!(status["tunnel"]["state"], "stopped");
        assert_eq!(status["last_seen_ms"], 123);
        assert!(status.get("tunnels").is_none());
        assert_eq!(
            selected_status(inventory, "missing")
                .unwrap_err()
                .exit_code(),
            5
        );
    }

    #[test]
    fn offline_or_missing_snapshot_is_not_an_unknown_tunnel() {
        let offline = json!({"server":"joined-1", "online":false,
            "tunnels":null, "last_seen_ms":10});
        let error = selected_status(offline, "qa").unwrap_err();
        assert_eq!(error.code, "remote_offline");
        assert_eq!(error.exit_code(), 4);

        let awaiting = json!({"server":"joined-1", "online":true,
            "tunnels":null, "last_seen_ms":10});
        let error = selected_status(awaiting, "qa").unwrap_err();
        assert_eq!(error.code, "snapshot_unavailable");
        assert_eq!(error.exit_code(), 4);

        let available = json!({"server":"joined-1", "online":true,
            "tunnels":[{"name":"qa", "state":"stopped"}]});
        assert_eq!(selected_status(available.clone(), "qa").unwrap()["tunnel"]["name"], "qa");
        assert_eq!(selected_status(available, "not-found").unwrap_err().exit_code(), 5);
    }

    #[test]
    fn restart_all_keeps_each_result_and_exits_nonzero_on_partial_failure() {
        for server in ["local", "joined-1"] {
            let successes = json!({"ok":true, "results":[{"name":"first","ok":true,"came_up":true}]});
            assert_eq!(classify_restart_all(server, successes).unwrap()["ok"], true);
            let mixed = json!({"ok":false,"results":[
                {"name":"first","ok":true,"came_up":true},
                {"name":"second","ok":false,"detail":"service failed"}]});
            let error = classify_restart_all(server, mixed.clone()).unwrap_err();
            assert_eq!(error.code, "partial_failure");
            assert_eq!(error.exit_code(), 8);
            assert_eq!(error.as_json()["report"]["server"], server);
            assert_eq!(error.as_json()["report"]["results"], mixed["results"]);
            assert!(classify_restart_all(server, json!({"results":[]})).is_err());
        }
    }

    #[test]
    fn guided_game_forms_pass_existing_wizard_for_reverse_direct_and_ipv6() {
        let (normal, normal_default) = guided_forward_protocols(false);
        assert_eq!(normal[normal_default], "tcp");
        let (game_protocols, game_default) = guided_forward_protocols(true);
        assert_eq!(game_protocols[game_default], "both");
        assert!(!game_protocols.contains(&"tcp"));

        for (transport, direction, address, iran_ip) in [
            ("game", "reverse", "203.0.113.10", None),
            ("game", "direct", "203.0.113.10", Some("198.51.100.30")),
            ("ipv6", "direct", "2001:db8::10", Some("2001:db8::30")),
        ] {
            let mut form = json!({
                "name":"qa-game", "transport":transport, "direction":direction,
                "address":address, "tunnel_port":7770, "carry":"ports",
                "ports":"9392", "protocol":game_protocols[game_default], "reach":"local",
            });
            if transport == "ipv6" {
                form["ipv6_transport"] = json!("game");
            }
            let iran_address = iran_ip.map(|ip| ip.parse().unwrap());
            guided_game_form(&mut form, true, iran_address).unwrap();
            assert_eq!(form["protocol"], "both");
            assert_eq!(form["game"], true);
            if direction == "direct" {
                assert_eq!(form["iran_address"], iran_ip.unwrap());
            } else {
                assert!(form.get("iran_address").is_none());
            }
            let built = super::super::wizard::build(&form)
                .unwrap_or_else(|e| panic!("{transport} {direction}: {e:#}"));
            for endpoint in [&built.iran, &built.foreign] {
                assert_eq!(endpoint["gaming"]["copies"], 3);
                super::super::wizard::creatable(endpoint).unwrap();
                crate::manager::plan::check(endpoint).unwrap();
            }
        }

        let mut tcp_only = json!({"carry":"ports", "protocol":"tcp", "direction":"reverse"});
        assert!(guided_game_form(&mut tcp_only, true, None).is_err());
        let mut missing_ip = json!({"carry":"socks", "direction":"direct"});
        assert!(guided_game_form(&mut missing_ip, true, None).is_err());
        let mut regular = json!({"carry":"ports", "protocol":"tcp", "direction":"direct"});
        guided_game_form(&mut regular, false, None).unwrap();
        assert!(regular.get("game").is_none());
    }

    #[test]
    fn guided_ipv6_transport_uses_actual_wizard_carrier_options() {
        let mut types = Vec::new();
        for name in super::super::wizard::TRANSPORTS {
            let transport: crate::config::Transport = serde_json::from_value(json!(name)).unwrap();
            types.push(json!({"name":name,"port":crate::manager::plan::default_tunnel_port(transport),
                "options": super::super::wizard::options_of(transport)}));
        }
        for (name, option) in [("tcp","congestion"),("parallax","parallax"),
            ("fec-udp","pacer"),("wss","tls")] {
            let effective = wizard_transport(&types, name).unwrap();
            assert_eq!(effective["options"][option], true, "{name}: {option}");
            let mut form = json!({"name":"test-v6","transport":"ipv6", "ipv6_transport":name,
                "address":"2001:db8::10", "ports":"9392", "carry":"ports",
                "tunnel_port":effective["port"]});
            match name {
                "parallax" => form["parallax_mode"] = json!("packet"),
                "fec-udp" => form["fec_pacer"] = json!(true),
                "wss" => form["tls_profile"] = json!("classic"),
                _ => {},
            }
            let built = super::super::wizard::build(&form).unwrap();
            assert_eq!(built.iran["tunnel_key"], built.foreign["tunnel_key"]);
        }
        assert!(wizard_transport(&types, "not-listed").is_err());
    }

    #[tokio::test]
    async fn invalid_log_lines_are_rejected_before_dashboard_sign_in() {
        let dir = tempfile::tempdir().unwrap();
        let error = execute(
            dir.path(),
            false,
            Operation::Logs {
                server: "local".into(),
                tunnel: "qa-test".into(),
                lines: 0,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "invalid_input");
        assert_eq!(error.exit_code(), 2);
    }

    #[tokio::test]
    async fn destructive_commands_validate_before_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let error = execute(
            dir.path(),
            false,
            Operation::Delete {
                server: "local".into(),
                tunnel: "qa".into(),
                both: true,
                expected_pair: None,
                confirm: "not-qa".into(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.code, "invalid_input");
        let error = execute(
            dir.path(),
            false,
            Operation::RemoveServer {
                server: "someone".into(),
                confirm: "another".into(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.exit_code(), 2);
        let error = execute(
            dir.path(),
            false,
            Operation::Delete {
                server: "local".into(),
                tunnel: "qa".into(),
                both: false,
                expected_pair: Some("oops".into()),
                confirm: "qa".into(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.exit_code(), 2);
        let error = execute(
            dir.path(),
            false,
            Operation::Create {
                form_file: dir.path().join("missing.json"),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(
            FleetError::partial("test", json!({"remaining":[1]})).as_json()["report"]["remaining"]
                [0],
            1
        );
        assert_eq!(FleetError::partial("test", json!({})).exit_code(), 8);
    }

    #[test]
    fn form_files_are_bounded_and_do_not_consume_secret_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let form = dir.path().join("form.json");
        std::fs::write(&form, b"{\"name\":\"qa\"}").unwrap();
        assert_eq!(read_json_file(&form).unwrap()["name"], "qa");
        std::fs::write(&form, b"[]").unwrap();
        assert_eq!(read_json_file(&form).unwrap_err().code, "invalid_input");
        // Exact boundary (including JSON framing), not a byte more.
        std::fs::write(&form, format!("{{\"x\":\"{}\"}}", "a".repeat(8192 - 8))).unwrap();
        assert_eq!(std::fs::metadata(&form).unwrap().len(), 8192);
        assert_eq!(read_json_file(&form).unwrap()["x"].as_str().unwrap().len(), 8192 - 8);
        std::fs::write(&form, format!("{{\"x\":\"{}\"}}", "a".repeat(8193 - 8))).unwrap();
        assert_eq!(read_json_file(&form).unwrap_err().code, "invalid_input");
        std::fs::write(&form, vec![b'x'; 8193]).unwrap();
        assert_eq!(read_json_file(&form).unwrap_err().code, "invalid_input");
        assert_eq!(read_json_file(dir.path()).unwrap_err().code, "invalid_input");
        assert_eq!(
            read_json_file(Path::new("-")).unwrap_err().code,
            "invalid_input"
        );
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
    /// Two independently joined in-process Agent links exercise the real Hub/Agent protocol
    /// through HTTPS. No remote service/systemd commands run in this fixture.
    async fn mock_joined_agent(
        fleet: Arc<super::super::fleet::Fleet>,
        name: &str,
        fail_restart_all: bool,
    ) -> (
        String,
        super::super::ops::DemoOps,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        use super::super::{link, ops};
        let (code, _) = fleet.join_code("127.0.0.1", 12345).unwrap();
        let code = link::JoinCode::decode(&code).unwrap();
        let (stream, hub_stream) = tokio::io::duplex(1 << 20);
        let hub = fleet.clone();
        let hub_task = tokio::spawn(async move {
            let _ = hub.serve(hub_stream, |_, _| {}).await;
        });
        let name = name.to_owned();
        let demo = ops::DemoOps::new(&["qa-test"]);
        let inspect_demo = demo.clone();
        let (id_tx, id_rx) = tokio::sync::oneshot::channel();
        let agent_task = tokio::spawn(async move {
            let (private, _) = link::generate_keypair().unwrap();
            let (mut reader, mut writer) = link::connect(stream, &private, &code.hub_key)
                .await
                .unwrap();
            writer
                .send(&json!({"type":"join","token":hex::encode(code.token),"name":name}))
                .await
                .unwrap();
            let welcome = reader.recv().await.unwrap();
            assert_eq!(welcome["type"], "welcome");
            id_tx
                .send(welcome["id"].as_str().unwrap().to_owned())
                .unwrap();
            let snapshot = |demo: &ops::DemoOps| {
                let mut tunnels = vec![json!({"name":"qa-test","state":
                    if demo.running("qa-test", true) {"running"} else {"stopped"}})];
                for (name, config) in demo.created() {
                    tunnels.push(json!({"name":name,
                        "state":if demo.running(&name, true) {"running"} else {"stopped"},
                        "pair": super::super::data::pair_of(&config),
                        "side":if config["mode"] == "server" {"iran"} else {"foreign"},
                        "direction":"reverse"}));
                }
                json!({"type":"snapshot","snapshot":{"tunnels":tunnels}})
            };
            writer.send(&snapshot(&demo)).await.unwrap();
            while let Ok(request) = reader.recv().await {
                if request["type"] != "request" {
                    continue;
                }
                let response = if request["op"] == "restart_all" && fail_restart_all {
                    json!({"type":"response","id":request["id"],"ok":true,
                        "result":[{"name":"qa-test","ok":false,
                            "detail":"simulated single-tunnel restart failure"}]})
                } else { match ops::answer(&demo, &request) {
                    Ok(result) => {
                        json!({"type":"response","id":request["id"],"ok":true,"result":result})
                    }
                    Err(error) => json!({
                        "type":"response","id":request["id"],"ok":false,
                        "error": format!("{error:#}"),
                        "error_code": if error.downcast_ref::<ops::UnknownTunnel>().is_some() {
                            Some("unknown_tunnel")
                        } else if error.downcast_ref::<ops::PairMismatch>().is_some() {
                            Some("pair_mismatch")
                        } else { None }
                    }),
                } };
                writer.send(&response).await.unwrap();
                if ["act", "act_pair", "create", "delete", "delete_pair", "edit", "undo"]
                    .contains(&request["op"].as_str().unwrap_or(""))
                {
                    writer.send(&snapshot(&demo)).await.unwrap();
                }
            }
        });
        let id = id_rx.await.unwrap();
        (id, inspect_demo, agent_task, hub_task)
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
        let qa_fleet = fleet::Fleet::open(dir.path()).unwrap();
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
            fleet: Some(qa_fleet.clone()),
            public: ("127.0.0.1".into(), port),
            agent_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            cert: None,
            demo: false,
            secure: true,
            state_dir: dir.path().into(),
            alerts: Default::default(),
        });
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let qa_state = state.clone();
        let verifier_state = state.clone();
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

        // Both independently enrolled synthetic Agents flow through the same live
        // encrypted Hub links, authenticated HTTPS routes and terminal client.
        let (id_a, _demo_a, agent_a, link_a) = mock_joined_agent(qa_fleet.clone(), "qa-agent-a", true).await;
        let (id_b, demo_b, agent_b, link_b) = mock_joined_agent(qa_fleet.clone(), "qa-agent-b", false).await;
        assert_ne!(id_a, id_b);
        let mut online = false;
        for _ in 0..100 {
            let inventory = client.servers().await.unwrap();
            if inventory["servers"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|s| {
                    (s["id"] == id_a || s["id"] == id_b)
                        && s["online"] == true
                        && s["snapshot"]["tunnels"].is_array()
                })
                .count()
                == 2
            {
                online = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            online,
            "both independent Agent links must publish snapshots"
        );
        let inventory_a = client.tunnels(&id_a).await.unwrap();
        assert_eq!(inventory_a["tunnels"][0]["name"], "qa-test");
        let inventory_b = client.tunnels(&id_b).await.unwrap();
        assert_eq!(inventory_b["online"], true);

        assert_eq!(
            client.action(&id_a, "qa-test", "stop").await.unwrap()["ok"],
            true
        );
        let mut stopped = false;
        for _ in 0..100 {
            if client.tunnels(&id_a).await.unwrap()["tunnels"][0]["state"] == "stopped" {
                stopped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(stopped, "remote action must update the Web/CLI inventory");
        assert_eq!(
            client.tunnels(&id_b).await.unwrap()["tunnels"][0]["state"],
            "running"
        );
        assert_eq!(
            client.logs(&id_b, "qa-test", 10).await.unwrap()["logs"]["lines"]
                .as_array()
                .unwrap()
                .len(),
            10
        );
        assert_eq!(
            client
                .action(&id_a, "missing", "stop")
                .await
                .unwrap_err()
                .exit_code(),
            5
        );
        assert_eq!(
            client
                .logs(&id_b, "missing", 10)
                .await
                .unwrap_err()
                .exit_code(),
            5
        );
        // Full HTTPS -> Agent response -> HTTP-200 aggregate -> Fleet error classification.
        let partial_restart = client.restart_all(&id_a).await.unwrap_err();
        assert_eq!(partial_restart.exit_code(), 8);
        assert_eq!(partial_restart.as_json()["report"]["results"][0]["name"], "qa-test");
        assert_eq!(partial_restart.as_json()["report"]["results"][0]["ok"], false);
        assert_eq!(client.restart_all(&id_b).await.unwrap()["ok"], true);
        assert_eq!(client.restart_all("local").await.unwrap()["ok"], true);

        // End-to-end protocol test: the CLI and Web use the same builder, both encrypted
        // Agent links and session/CSRF guard; the pair appears in Dashboard snapshots.
        let available = client.options().await.unwrap();
        assert!(
            available["transports"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["name"] == "tcp")
        );
        let created = client.create(json!({
            "iran":id_a,"foreign":id_b,"name":"paired-qa","transport":"tcp",
            "direction":"reverse","address":"127.0.0.1","carry":"ports","ports":"8080","protocol":"tcp"
        })).await.unwrap();
        assert_eq!(created["ok"], true);
        assert_eq!(created["iran"]["came_up"], true);
        assert_eq!(created["foreign"]["came_up"], true);
        // An old Hub does not recognize the distinct paired-* action name;
        // a current Hub requires the fingerprint for that name, rejecting
        // any unguarded or mismatched URL/body combination before dispatch.
        assert!(super::super::ops::parse_action("paired-start").is_none());
        let guarded_path = format!("/api/servers/{id_b}/tunnels/paired-qa/paired-start");
        let missing = client.api_body(Method::POST, &guarded_path, Some(json!({})),
            Duration::from_secs(10)).await.unwrap_err();
        assert_eq!(missing.code, "invalid_pair");
        assert_eq!(missing.status, Some(400));
        let mixed_path = format!("/api/servers/{id_b}/tunnels/paired-qa/start");
        let invalid = client.api_body(Method::POST, &mixed_path,
            Some(json!({"expect_pair":"0000000000000000"})),
            Duration::from_secs(10)).await.unwrap_err();
        assert_eq!(invalid.code, "invalid_pair");
        let mut found = false;
        for _ in 0..100 {
            let left = client.tunnels(&id_a).await.unwrap();
            let right = client.tunnels(&id_b).await.unwrap();
            let a = left["tunnels"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == "paired-qa");
            let b = right["tunnels"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == "paired-qa");
            if a.is_some_and(|t| t["pair"].is_string())
                && b.is_some_and(|t| t["pair"] == a.unwrap()["pair"])
            {
                found = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(found, "both Web snapshots must show the same paired tunnel");
        let pair = client.status(&id_a, "paired-qa").await.unwrap()["tunnel"]["pair"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            client
                .pair_targets(&id_a, "paired-qa")
                .await
                .unwrap()
                .targets
                .len(),
            2
        );
        assert_eq!(
            client.settings(&id_a, "paired-qa").await.unwrap()["quota"]["period_days"],
            30
        );
        assert_eq!(
            client
                .edit(
                    &id_a,
                    "paired-qa",
                    json!({"quota":{"limit_gb":1,"period_days":30}})
                )
                .await
                .unwrap()["changed"],
            true
        );
        assert_eq!(
            client.undo(&id_a, "paired-qa").await.unwrap()["changed"],
            true
        );
        let stopped_both = client.paired(&id_a, "paired-qa", "stop").await.unwrap();
        assert_eq!(stopped_both["attempts"].as_array().unwrap().len(), 2);
        let started_both = client.paired(&id_a, "paired-qa", "start").await.unwrap();
        assert_eq!(started_both["attempts"].as_array().unwrap().len(), 2);
        // Deterministic partial failure: dialer stops, the listening endpoint is busy.
        // The caller receives an explicit reconciliation report, never false success.
        let held_key = format!("{id_a}/paired-qa");
        verifier_state.busy.lock().unwrap().insert(held_key.clone());
        let partial = client.paired(&id_b, "paired-qa", "stop").await.unwrap_err();
        assert_eq!(partial.exit_code(), 8);
        let report = partial.as_json()["report"].clone();
        assert_eq!(report["pair"], pair);
        assert_eq!(report["attempts"].as_array().unwrap().len(), 2);
        assert_eq!(report["attempts"][0]["server"], id_b);
        assert_eq!(report["attempts"][0]["ok"], true);
        assert_eq!(report["attempts"][1]["server"], id_a);
        assert_eq!(report["attempts"][1]["ok"], false);
        assert_eq!(report["attempts"][1]["error"]["error"], "busy");
        assert!(report["remaining"].as_array().unwrap().iter().any(|v| v["server"] == id_a));
        verifier_state.busy.lock().unwrap().remove(&held_key);
        let recovered = client.paired(&id_a, "paired-qa", "start").await.unwrap();
        assert_eq!(recovered["attempts"].as_array().unwrap().len(), 2);

        // Snapshot discovery sees pair A, then Agent B's persisted key changes
        // before dispatch. All three paired lifecycle actions must refuse B.
        let stale_group = client.pair_targets(&id_a, "paired-qa").await.unwrap();
        let previous = demo_b.added.lock().unwrap().iter().rev()
            .find(|(name, _)| name == "paired-qa").unwrap().1.clone();
        let mut replacement = previous.clone();
        replacement["tunnel_key"] = json!("replacement-unrelated-key");
        assert_ne!(super::super::data::pair_of(&replacement).as_deref(), Some(pair.as_str()));
        demo_b.added.lock().unwrap().push(("paired-qa".to_owned(), replacement));
        let before = demo_b.overrides.lock().unwrap().get("paired-qa").copied();
        for action in ["start", "stop", "restart"] {
            let error = client.paired_targets(stale_group.clone(), action).await.unwrap_err();
            assert_eq!(error.exit_code(), 8, "{action}");
            let attempted = error.as_json()["report"]["attempts"].as_array().unwrap().clone();
            assert!(attempted.iter().any(|entry| entry["server"] == id_b
                && entry["error"]["error"] == "pair_mismatch"), "{action}: {attempted:?}");
            assert_eq!(demo_b.overrides.lock().unwrap().get("paired-qa").copied(), before,
                "{action} mutated replacement B");
            let direct_error = client.action_guarded(&id_b, "paired-qa", action, Some(&pair)).await.unwrap_err();
            assert_eq!(direct_error.code, "pair_mismatch");
            assert_eq!(direct_error.status, Some(409));
            assert_eq!(demo_b.overrides.lock().unwrap().get("paired-qa").copied(), before);
        }
        // Restore the fixture's original pair and refresh its published snapshot.
        let restored = demo_b.added.lock().unwrap().pop().unwrap();
        assert_eq!(restored.0, "paired-qa");
        client.action(&id_b, "paired-qa", "start").await.unwrap();
        let mut reflected = false;
        for _ in 0..100 {
            if client.status(&id_b, "paired-qa").await.unwrap()["tunnel"]["pair"] == pair {
                reflected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(reflected, "the Agent snapshot must reflect the restored pair identity");
        assert_eq!(
            client
                .delete(&id_a, "paired-qa", Some("0000000000000000"))
                .await
                .unwrap_err()
                .code,
            "pair_mismatch"
        );
        assert_eq!(
            client.status(&id_a, "paired-qa").await.unwrap()["tunnel"]["pair"],
            pair
        );
        let deleted = client.paired(&id_a, "paired-qa", "delete").await.unwrap();
        assert_eq!(deleted["attempts"].as_array().unwrap().len(), 2);
        for _ in 0..100 {
            if client.tunnels(&id_a).await.unwrap()["tunnels"]
                .as_array()
                .unwrap()
                .iter()
                .all(|t| t["name"] != "paired-qa")
                && client.tunnels(&id_b).await.unwrap()["tunnels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|t| t["name"] != "paired-qa")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            client.tunnels(&id_a).await.unwrap()["tunnels"]
                .as_array()
                .unwrap()
                .iter()
                .all(|t| t["name"] != "paired-qa")
        );
        assert!(
            client.tunnels(&id_b).await.unwrap()["tunnels"]
                .as_array()
                .unwrap()
                .iter()
                .all(|t| t["name"] != "paired-qa")
        );

        let busy = format!("{id_a}/qa-test");
        qa_state.busy.lock().unwrap().insert(busy.clone());
        assert_eq!(
            client
                .action(&id_a, "qa-test", "start")
                .await
                .unwrap_err()
                .exit_code(),
            6
        );
        qa_state.busy.lock().unwrap().remove(&busy);

        agent_a.abort();
        let _ = agent_a.await;
        let mut disconnected = false;
        for _ in 0..100 {
            if client.tunnels(&id_a).await.unwrap()["online"] == false {
                disconnected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(disconnected, "lost Agent connection must become offline");
        assert_eq!(
            client
                .action(&id_a, "qa-test", "start")
                .await
                .unwrap_err()
                .exit_code(),
            4
        );
        assert_eq!(client.tunnels(&id_b).await.unwrap()["online"], true);
        agent_b.abort();
        let _ = agent_b.await;
        let _ = link_a.await;
        let _ = link_b.await;

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
