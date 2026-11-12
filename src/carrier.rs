//! Network carriers. Noise authenticates and encrypts every carrier's payload.
use crate::config::{ClientPath, Config, Listener, Transport};
use anyhow::{Context, Result, bail, ensure};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::pem::PemObject;
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, LazyLock, Mutex},
    task::{Context as TaskContext, Poll},
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::TcpStream,
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};

pub trait TunnelIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> TunnelIo for T {}
pub type BoxIo = Box<dyn TunnelIo>;

fn certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read certificate {}", path.display()))?;
    let result = rustls::pki_types::CertificateDer::pem_slice_iter(&bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse certificate {}", path.display()))?;
    ensure!(
        !result.is_empty(),
        "certificate file contains no certificates"
    );
    Ok(result)
}

/// Size and modification time of a file; changes whenever the file is replaced or rewritten.
type FileStamp = (Option<SystemTime>, u64);

type TlsCache = HashMap<(PathBuf, PathBuf), ((FileStamp, FileStamp), Arc<rustls::ServerConfig>)>;

static SERVER_TLS_CACHE: LazyLock<Mutex<TlsCache>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Most distinct certificate/key pairs kept in memory.
const TLS_CACHE_LIMIT: usize = 64;

fn file_stamp(path: &Path) -> FileStamp {
    match std::fs::metadata(path) {
        Ok(meta) => (meta.modified().ok(), meta.len()),
        Err(_) => (None, 0),
    }
}

/// The server's TLS settings for this listener. They are read from disk once and reused for
/// every connection; if the certificate or key file changes (for example after a renewal) the
/// new files are picked up automatically, and if they cannot be read at that moment the
/// previous settings stay in use.
fn server_tls(listener: &Listener) -> Result<Arc<rustls::ServerConfig>> {
    if listener.tls_auto {
        return listener
            .auto_tls
            .as_ref()
            .context("tls_auto needs the tunnel key")?
            .server_config();
    }
    let cert = listener
        .cert_file
        .as_deref()
        .context("cert_file required")?;
    let key = listener.key_file.as_deref().context("key_file required")?;
    let stamp = (file_stamp(cert), file_stamp(key));
    let id = (cert.to_path_buf(), key.to_path_buf());
    let previous = {
        let cache = SERVER_TLS_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match cache.get(&id) {
            Some((cached_stamp, config)) if *cached_stamp == stamp => return Ok(config.clone()),
            Some((_, config)) => Some(config.clone()),
            None => None,
        }
    };
    match load_server_tls(listener) {
        Ok(config) => {
            let mut cache = SERVER_TLS_CACHE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if cache.len() >= TLS_CACHE_LIMIT {
                cache.clear();
            }
            cache.insert(id, (stamp, config.clone()));
            Ok(config)
        }
        Err(error) => match previous {
            Some(config) => {
                tracing::warn!(%error, "could not reload the TLS certificate; keeping the previous one");
                Ok(config)
            }
            None => Err(error),
        },
    }
}

fn load_server_tls(listener: &Listener) -> Result<Arc<rustls::ServerConfig>> {
    let certificates = certs(
        listener
            .cert_file
            .as_deref()
            .context("cert_file required")?,
    )?;
    let key_path = listener.key_file.as_deref().context("key_file required")?;
    crate::config::Config::ensure_not_world_readable(key_path, "the TLS private key")?;
    let bytes = std::fs::read(key_path)?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&bytes)
        .context("TLS key file contains no usable private key")?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certificates, key)?;
    Ok(Arc::new(config))
}

fn client_tls(path: &ClientPath) -> Result<Arc<rustls::ClientConfig>> {
    if path.tls_auto {
        return path
            .auto_tls
            .as_ref()
            .context("tls_auto needs the tunnel key")?
            .client_config();
    }
    let mut roots = rustls::RootCertStore::empty();
    if let Some(file) = &path.ca_file {
        for cert in certs(file)? {
            roots.add(cert)?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    // Every browser says which protocol it wants; a client with no ALPN at all stands out.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub fn validate_tls_config(config: &Config) -> Result<()> {
    for listener in &config.listeners {
        if listener.transport.uses_tls() {
            if config.server_dials {
                let path = listener.dial_path(config.timeouts.server_dial_sec);
                client_tls(&path)?;
                tls_server_name(&path)?;
                #[cfg(feature = "browser-tls")]
                if path.tls_profile == crate::config::TlsProfile::Chrome {
                    crate::tls_boring::validate(&path)?;
                }
            } else {
                server_tls(listener)?;
            }
        }
    }
    for path in &config.paths {
        if path.transport.uses_tls() {
            if config.server_dials {
                server_tls(&path.listen_config())?;
            } else {
                client_tls(path)?;
                tls_server_name(path)?;
                #[cfg(feature = "browser-tls")]
                if path.tls_profile == crate::config::TlsProfile::Chrome {
                    crate::tls_boring::validate(path)?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn http_authority(
    value: &str,
) -> Result<tokio_tungstenite::tungstenite::http::uri::Authority> {
    ensure!(
        !value.is_empty() && value.len() <= 253 && value.is_ascii() && !value.contains('@'),
        "invalid HTTP Host authority"
    );
    let authority: tokio_tungstenite::tungstenite::http::uri::Authority =
        value.parse().context("invalid HTTP Host authority")?;
    let host = authority.host();
    ensure!(!host.is_empty(), "HTTP Host must contain a hostname or IP");
    if host.starts_with('[') {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::Ipv6Addr>()
            .context("invalid HTTP Host IPv6 address")?;
    } else {
        ensure!(
            host.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')),
            "invalid HTTP Host hostname"
        );
    }
    let suffix = &value[host.len()..];
    if !suffix.is_empty() {
        let digits = suffix
            .strip_prefix(':')
            .context("invalid HTTP Host port separator")?;
        ensure!(
            !digits.is_empty()
                && digits.len() <= 5
                && digits.bytes().all(|b| b.is_ascii_digit())
                && digits.parse::<u16>().is_ok_and(|port| port != 0),
            "invalid HTTP Host port"
        );
    }
    Ok(authority)
}

fn tls_server_name(path: &ClientPath) -> Result<rustls::pki_types::ServerName<'static>> {
    Ok(rustls::pki_types::ServerName::try_from(tls_host(path)?)?)
}

/// The name a TLS dialer sends as SNI (an IP address sends none).
pub(crate) fn tls_host(path: &ClientPath) -> Result<String> {
    let name = if let Some(host) = &path.xhttp.host {
        let authority = http_authority(host)?;
        authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    } else if let Some(name) = &path.server_name {
        name.clone()
    } else if path.tls_auto {
        // The certificate is pinned, so the name only decides what is sent as SNI. An IP
        // address sends none.
        let (host, _) = path.addr.rsplit_once(':').context("address without port")?;
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    } else {
        anyhow::bail!("server_name required")
    };
    Ok(name)
}

static FAILED_EDGES: LazyLock<Mutex<HashMap<String, tokio::time::Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) async fn connect_http(path: &ClientPath) -> Result<BoxIo> {
    if !matches!(path.transport, Transport::Xhttp | Transport::Xhttps)
        || path.xhttp.edge_addrs.is_empty()
    {
        return connect_to(&path.addr, path).await;
    }
    let key = |addr: &str| {
        format!(
            "{addr}|{}|{:?}",
            path.xhttp.host.as_deref().unwrap_or(&path.addr),
            path.transport
        )
    };
    let now = tokio::time::Instant::now();
    let mut candidates: Vec<_> = {
        let mut failed = FAILED_EDGES
            .lock()
            .map_err(|_| anyhow::anyhow!("edge retry state poisoned"))?;
        failed.retain(|_, retry| *retry > now);
        path.xhttp
            .edge_addrs
            .iter()
            .filter(|addr| !failed.contains_key(&key(addr)))
            .collect()
    };
    // When every edge recently failed, retry the configured list immediately
    // instead of turning a temporary blacklist into a total outage.
    if candidates.is_empty() {
        candidates = path.xhttp.edge_addrs.iter().collect();
    }
    // Each edge gets an equal share of the configured dial timeout (never less than 100 ms).
    let total_ms = path.dial_timeout.saturating_mul(1000);
    let per_edge =
        Duration::from_millis((total_ms / candidates.len() as u64).clamp(100, total_ms.max(100)));
    let mut error = None;
    for address in candidates {
        let result = tokio::time::timeout(per_edge, connect_to(address, path))
            .await
            .map_err(|_| anyhow::anyhow!("configured edge connection timed out"))
            .and_then(|result| result);
        match result {
            Ok(stream) => {
                if let Ok(mut failed) = FAILED_EDGES.lock() {
                    failed.remove(&key(address));
                }
                return Ok(stream);
            }
            Err(reason) => {
                if let Ok(mut failed) = FAILED_EDGES.lock() {
                    // The cache remains bounded even across many configs.
                    if failed.len() >= 1024 {
                        failed.clear();
                    }
                    failed.insert(
                        key(address),
                        tokio::time::Instant::now()
                            + Duration::from_secs(path.xhttp.edge_retry_sec),
                    );
                }
                error = Some(reason.context(format!("configured edge {address}")));
            }
        }
    }
    Err(error.context("no configured XHTTP edge address")?)
}

/// TCP congestion control for tunnel connections (`tcp_congestion`); `None` keeps the system's.
static TCP_CONGESTION: Mutex<Option<String>> = Mutex::new(None);

/// Chooses the congestion control used on tunnel TCP connections from now on.
pub fn set_tcp_congestion(algorithm: &str) {
    *TCP_CONGESTION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        (algorithm != "system").then(|| algorithm.to_string());
}

/// Applies the chosen congestion control to one tunnel connection. It only affects this
/// socket. If the kernel does not offer the algorithm to this program, the system default
/// stays in use. `path_override` is the path's or listener's own `tcp_congestion`, if set
/// (`Some("system")` explicitly keeps the kernel default for this connection, even when the
/// program-wide setting picks one); `None` falls back to the program-wide setting.
pub(crate) fn tune_tcp(socket: &TcpStream, path_override: Option<&str>) {
    let algorithm = match path_override {
        Some("system") => None,
        Some(algorithm) => Some(algorithm.to_string()),
        None => TCP_CONGESTION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
    };
    let Some(algorithm) = algorithm else {
        return;
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the pointer and length describe the live string bytes for this call.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                algorithm.as_ptr().cast(),
                algorithm.len() as libc::socklen_t,
            )
        };
        if result != 0 {
            // Keyed by algorithm name, not a single Once, so a different per-path algorithm
            // that also fails still gets its own warning.
            static WARNED: Mutex<Vec<String>> = Mutex::new(Vec::new());
            let error = io::Error::last_os_error();
            let mut warned = WARNED
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !warned.contains(&algorithm) {
                tracing::info!(%error, algorithm, "TCP congestion control not available; using the system default");
                warned.push(algorithm);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (socket, algorithm);
}

/// Opens a TCP connection to `address`, leaving from the local IP address `local` when one is
/// configured (`local_address`), otherwise from the one the system picks.
pub(crate) async fn dial_tcp(address: &str, local: Option<&str>) -> Result<TcpStream> {
    let Some(local) = local else {
        return TcpStream::connect(address)
            .await
            .context("connect to configured peer");
    };
    let local = crate::config::parse_local_address(local)?;
    let mut last = None;
    for peer in tokio::net::lookup_host(address)
        .await
        .context("resolve the peer address")?
        .filter(|peer| peer.is_ipv4() == local.is_ipv4())
    {
        let socket = if local.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket
            .bind(std::net::SocketAddr::new(local, 0))
            .with_context(|| format!("use local_address {local}"))?;
        match socket.connect(peer).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    match last {
        Some(error) => {
            Err(error).with_context(|| format!("connect to configured peer from {local}"))
        }
        None => bail!(
            "local_address {local} is {} but the peer {address} has no {} address",
            if local.is_ipv4() { "IPv4" } else { "IPv6" },
            if local.is_ipv4() { "IPv4" } else { "IPv6" }
        ),
    }
}

/// Opens the UDP socket a dialing KCP or FEC carrier talks to `peer` from.
pub(crate) async fn udp_for_peer(
    peer: std::net::SocketAddr,
    local: Option<&str>,
) -> Result<tokio::net::UdpSocket> {
    let bind = match local {
        Some(text) => {
            let local = crate::config::parse_local_address(text)?;
            ensure!(
                local.is_ipv4() == peer.is_ipv4(),
                "local_address {local} and the peer {peer} are not the same IP version"
            );
            std::net::SocketAddr::new(local, 0)
        }
        None if peer.is_ipv6() => "[::]:0".parse()?,
        None => "0.0.0.0:0".parse()?,
    };
    tokio::net::UdpSocket::bind(bind)
        .await
        .with_context(|| format!("bind the UDP socket {bind}"))
}

async fn connect_to(address: &str, path: &ClientPath) -> Result<BoxIo> {
    let tcp = dial_tcp(address, path.local_address.as_deref()).await?;
    tcp.set_nodelay(true)?;
    tune_tcp(&tcp, path.tcp_congestion.as_deref());
    if matches!(path.transport, Transport::Xhttp | Transport::Xhttps) {
        set_http_socket_buffers(&tcp, path.xhttp.socket_buf_bytes)?;
    }
    let mut stream: BoxIo = if path.transport.uses_tls() && path.tls_fragment.enabled {
        Box::new(crate::fragment::FragmentWriter::new(tcp, path.tls_fragment))
    } else {
        Box::new(tcp)
    };
    if path.transport.uses_tls() {
        if path.tls_profile == crate::config::TlsProfile::Chrome {
            #[cfg(feature = "browser-tls")]
            {
                stream = crate::tls_boring::connect(path, &tls_host(path)?, stream).await?;
            }
            #[cfg(not(feature = "browser-tls"))]
            bail!("tls_profile \"chrome\" needs a build with the browser-tls feature");
        } else {
            let name = tls_server_name(path)?;
            stream = Box::new(
                TlsConnector::from(client_tls(path)?)
                    .connect(name, stream)
                    .await
                    .context("TLS peer verification failed")?,
            );
        }
    }
    Ok(stream)
}

pub(crate) async fn tcp_for_path(path: &ClientPath) -> Result<TcpStream> {
    let tcp = dial_tcp(&path.addr, path.local_address.as_deref()).await?;
    tcp.set_nodelay(true)?;
    tune_tcp(&tcp, path.tcp_congestion.as_deref());
    Ok(tcp)
}

pub(crate) async fn accept_http(mut tcp: TcpStream, listener: &Listener) -> Result<BoxIo> {
    tcp.set_nodelay(true)?;
    tune_tcp(&tcp, listener.tcp_congestion.as_deref());
    set_http_socket_buffers(&tcp, listener.xhttp.socket_buf_bytes)?;
    if listener.transport.uses_tls() {
        answer_plain_http(&mut tcp, &listener.wire).await?;
    }
    let mut stream: BoxIo = Box::new(tcp);
    if listener.transport.uses_tls() {
        stream = Box::new(
            TlsAcceptor::from(server_tls(listener)?)
                .accept(stream)
                .await?,
        );
    }
    Ok(stream)
}

fn set_http_socket_buffers(socket: &TcpStream, bytes: Option<usize>) -> Result<()> {
    // Unset: the kernel sizes the buffers itself and grows them on long links.
    let Some(bytes) = bytes else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let value: libc::c_int = bytes
            .try_into()
            .context("socket buffer size exceeds kernel integer range")?;
        for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            // The descriptor remains owned by TcpStream, the integer is valid
            // for the entire call, and its exact size is supplied to Linux.
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&value as *const libc::c_int).cast(),
                    std::mem::size_of_val(&value) as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error())
                    .context("set configured HTTP socket buffer");
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (socket, bytes);
    Ok(())
}

pub async fn client_carrier(path: &ClientPath) -> Result<BoxIo> {
    if path.transport == Transport::Parallax {
        return crate::parallax_carrier::connect(path).await;
    }
    if path.transport == Transport::Tun {
        bail!("raw TUN carrier runs through the dedicated TUN device engine");
    }
    if matches!(
        path.transport,
        Transport::FecRaw | Transport::FecUdp | Transport::FecRawGaming | Transport::Mirage
    ) {
        return crate::fec_carrier::connect(path).await;
    }
    if path.transport == Transport::Kcp {
        return Ok(Box::new(
            crate::kcp_carrier::connect(&path.addr, &path.kcp, path.local_address.as_deref())
                .await?,
        ));
    }
    if matches!(path.transport, Transport::Xhttp | Transport::Xhttps) {
        return crate::xhttp_carrier::connect(path).await;
    }
    let mut stream = connect_http(path).await?;
    match path.transport {
        Transport::Tcp | Transport::Tcp6 | Transport::Kcp => Ok(stream),
        Transport::Ws | Transport::Wss => {
            let url = format!(
                "{}://{}{}",
                if path.transport.uses_tls() {
                    "wss"
                } else {
                    "ws"
                },
                path.addr,
                path.http_path
            );
            let (socket, _) =
                tokio_tungstenite::client_async_with_config(url, stream, Some(ws_config())).await?;
            Ok(websocket_io(socket))
        }
        Transport::Http | Transport::Https => {
            let token = path.wire.upgrade_token();
            stream.write_all(format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: {token}\r\n\r\n", path.http_path, path.addr).as_bytes()).await?;
            stream.flush().await?;
            let header = read_headers(&mut stream).await?;
            ensure!(
                header.first == "HTTP/1.1 101 Switching Protocols"
                    && header.value("upgrade") == Some(token.as_str()),
                "HTTP upgrade rejected"
            );
            Ok(stream)
        }
        Transport::Xhttp
        | Transport::Xhttps
        | Transport::FecRaw
        | Transport::FecUdp
        | Transport::FecRawGaming
        | Transport::Mirage
        | Transport::Tun
        | Transport::Parallax => unreachable!("handled before TCP connect"),
    }
}

pub async fn server_carrier(mut tcp: TcpStream, listener: &Listener) -> Result<BoxIo> {
    tcp.set_nodelay(true)?;
    if listener.transport.uses_tls() {
        answer_plain_http(&mut tcp, &listener.wire).await?;
    }
    let mut stream: BoxIo = Box::new(tcp);
    if listener.transport.uses_tls() {
        stream = Box::new(
            TlsAcceptor::from(server_tls(listener)?)
                .accept(stream)
                .await?,
        );
    }
    match listener.transport {
        Transport::Tcp | Transport::Tcp6 | Transport::Kcp => Ok(stream),
        Transport::FecRaw
        | Transport::FecUdp
        | Transport::FecRawGaming
        | Transport::Mirage
        | Transport::Tun
        | Transport::Parallax => {
            bail!("raw/FEC sessions require their dedicated acceptor")
        }
        Transport::Ws | Transport::Wss if listener.wire.v2() => {
            accept_websocket_v2(stream, listener).await
        }
        Transport::Ws | Transport::Wss => {
            let path = listener.http_path.clone();
            let wire = listener.wire.clone();
            // Tungstenite requires its HTTP response as the callback error type.
            #[allow(clippy::result_large_err)]
            let callback =
                move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                      response| {
                    if request.uri().path_and_query().map(|v| v.as_str()) == Some(path.as_str()) {
                        Ok(response)
                    } else {
                        Err(not_found(&wire))
                    }
                };
            let socket = tokio_tungstenite::accept_hdr_async_with_config(
                stream,
                callback,
                Some(ws_config()),
            )
            .await?;
            Ok(websocket_io(socket))
        }
        Transport::Http | Transport::Https => {
            let token = listener.wire.upgrade_token();
            let checked = async {
                let header = read_headers(&mut stream).await?;
                ensure!(
                    header.first == format!("GET {} HTTP/1.1", listener.http_path)
                        && header.value("upgrade") == Some(token.as_str())
                        && header.value("content-length").is_none()
                        && header.value("transfer-encoding").is_none(),
                    "invalid HTTP upgrade"
                );
                Ok(())
            }
            .await;
            if let Err(error) = checked {
                reject_probe(&mut stream, &listener.wire).await;
                return Err(error);
            }
            stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: {token}\r\n\r\n").as_bytes()).await?;
            stream.flush().await?;
            Ok(stream)
        }
        Transport::Xhttp | Transport::Xhttps => {
            let header = read_headers(&mut stream).await?;
            ensure!(
                header.first == format!("POST {} HTTP/1.1", listener.http_path)
                    && header.value("transfer-encoding") == Some("chunked")
                    && header.value("content-length").is_none(),
                "invalid HTTP streaming request"
            );
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\n\r\n").await?;
            stream.flush().await?;
            Ok(chunked_io(stream))
        }
    }
}

/// The answer a WebSocket request for the wrong path gets: the old one-line body in wire version 1,
/// an ordinary web-server page in version 2.
fn not_found(
    wire: &crate::stealth::WireOptions,
) -> tokio_tungstenite::tungstenite::http::Response<Option<String>> {
    use tokio_tungstenite::tungstenite::http::Response;
    if !wire.v2() {
        return Response::builder()
            .status(404)
            .body(Some("unknown tunnel path".to_string()))
            .unwrap();
    }
    let page = crate::stealth::decoy_response(wire.stealth.decoy_status);
    let page = String::from_utf8_lossy(&page);
    let body = page
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Response::builder()
        .status(wire.stealth.decoy_status)
        .header("Server", "nginx")
        .header("Content-Type", "text/html")
        .body(Some(body))
        .unwrap()
}

/// Wire version 2 WebSocket accept: reads the request itself, so anything that is not a correct
/// upgrade for our path (a browser, a scanner, a wrong path) gets the decoy page and a quiet hold
/// instead of a bare close.
async fn accept_websocket_v2(mut stream: BoxIo, listener: &Listener) -> Result<BoxIo> {
    let header = match read_headers(&mut stream).await {
        Ok(header) => header,
        Err(error) => {
            reject_probe(&mut stream, &listener.wire).await;
            return Err(error);
        }
    };
    let key = header.value("sec-websocket-key").map(str::to_string);
    let upgrade = header
        .value("upgrade")
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let valid = header.first == format!("GET {} HTTP/1.1", listener.http_path)
        && upgrade
        && header.value("sec-websocket-version") == Some("13")
        && key.is_some();
    let Some(key) = key.filter(|_| valid) else {
        reject_probe(&mut stream, &listener.wire).await;
        bail!("invalid WebSocket request");
    };
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;
    let socket = WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        Some(ws_config()),
    )
    .await;
    Ok(websocket_io(socket))
}

/// Wire version 2: answers a request that is not ours with a plain web page and closes like a web
/// server that said `Connection: close`. Version 1 does nothing (the caller closes).
pub(crate) async fn reject_probe(stream: &mut BoxIo, wire: &crate::stealth::WireOptions) {
    if !wire.v2() {
        return;
    }
    let _ = stream
        .write_all(&crate::stealth::decoy_response(wire.stealth.decoy_status))
        .await;
    linger_close(stream).await;
}

/// Sends the end of the stream, then reads what the peer still sends for a moment, so a client
/// that is mid-request sees the whole page and a clean end instead of a reset.
async fn linger_close<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    let mut sink = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

/// Whether the first bytes of a connection to a TLS port are a plain HTTP request, not a TLS
/// handshake. Peeks, so nothing is consumed.
async fn looks_like_plain_http(tcp: &TcpStream) -> bool {
    const METHODS: [&[u8; 4]; 9] = [
        b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC", b"CONN", b"TRAC",
    ];
    let mut first = [0u8; 4];
    for _ in 0..100 {
        match tcp.peek(&mut first).await {
            Ok(0) | Err(_) => return false,
            Ok(count) => {
                // 0x16 starts every TLS handshake record.
                if first[0] == 0x16 {
                    return false;
                }
                if count >= 4 {
                    return METHODS.contains(&&first);
                }
                if !METHODS.iter().any(|method| method[0] == first[0]) {
                    return false;
                }
            }
        }
        // Part of the method has arrived; give the rest a moment.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Wire version 2: a plain HTTP request on a TLS port gets the answer nginx gives (a 400 saying
/// so) instead of a bare close, which no ordinary web server does. Fails the connection if it
/// answered; returns Ok to let the TLS handshake go ahead.
async fn answer_plain_http(tcp: &mut TcpStream, wire: &crate::stealth::WireOptions) -> Result<()> {
    if wire.v2() && looks_like_plain_http(tcp).await {
        let _ = tcp
            .write_all(&crate::stealth::plain_http_on_tls_response())
            .await;
        linger_close(tcp).await;
        bail!("a plain HTTP request was sent to a TLS port");
    }
    Ok(())
}

pub(crate) struct Headers {
    pub(crate) first: String,
    pub(crate) fields: Vec<(String, String)>,
}
impl Headers {
    pub(crate) fn value(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, v)| v.as_str())
    }
}

pub(crate) async fn read_headers(reader: &mut BoxIo) -> Result<Headers> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        ensure!(bytes.len() < 8192, "HTTP headers too large");
        bytes.push(reader.read_u8().await?);
    }
    let text = std::str::from_utf8(&bytes)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let first = lines.next().context("empty HTTP header")?.to_string();
    let mut fields = Vec::new();
    for line in lines {
        let (key, value) = line.split_once(':').context("invalid HTTP header")?;
        // A name is a token: no space before the colon (RFC 9112 requires refusing that) and no
        // folded continuation lines, which would hide a framing header from the checks below.
        ensure!(
            !key.is_empty()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
            "invalid HTTP header name"
        );
        let key = key.to_ascii_lowercase();
        ensure!(
            !fields.iter().any(|(prior, _)| prior == &key),
            "duplicate HTTP header"
        );
        fields.push((key, value.trim().to_string()));
    }
    Ok(Headers { first, fields })
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(65_536))
        .max_frame_size(Some(65_536))
}

/// Owns the bridge task so dropping a tunnel cannot leave network tasks behind.
pub(crate) struct ManagedIo {
    pub(crate) io: DuplexStream,
    pub(crate) task: JoinHandle<()>,
}
impl Drop for ManagedIo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for ManagedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for ManagedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

fn websocket_io(socket: WebSocketStream<BoxIo>) -> BoxIo {
    let (io, bridge) = tokio::io::duplex(65_536);
    let task = tokio::spawn(async move {
        let (mut sink, mut source) = socket.split();
        let (mut input, mut output) = tokio::io::split(bridge);
        let upload = async {
            let mut buffer = vec![0; 16_384];
            loop {
                let count = input.read(&mut buffer).await?;
                if count == 0 {
                    sink.close().await?;
                    return anyhow::Ok(());
                }
                sink.send(Message::Binary(buffer[..count].to_vec().into()))
                    .await?;
            }
        };
        let download = async {
            while let Some(message) = source.next().await {
                match message? {
                    Message::Binary(bytes) => output.write_all(&bytes).await?,
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => {}
                    _ => bail!("expected binary WebSocket message"),
                }
            }
            output.shutdown().await?;
            anyhow::Ok(())
        };
        if let Err(error) = tokio::try_join!(upload, download) {
            tracing::debug!(%error,"WebSocket carrier ended");
        }
    });
    Box::new(ManagedIo { io, task })
}

pub(crate) fn chunked_io(stream: BoxIo) -> BoxIo {
    let (io, bridge) = tokio::io::duplex(65_536);
    let task = tokio::spawn(async move {
        let (mut network_read, mut network_write) = tokio::io::split(stream);
        let (mut input, mut output) = tokio::io::split(bridge);
        let upload = async {
            let mut buffer = vec![0; 16_384];
            loop {
                let count = input.read(&mut buffer).await?;
                network_write
                    .write_all(format!("{count:x}\r\n").as_bytes())
                    .await?;
                network_write.write_all(&buffer[..count]).await?;
                network_write.write_all(b"\r\n").await?;
                network_write.flush().await?;
                if count == 0 {
                    return anyhow::Ok(());
                }
            }
        };
        // C40: the same proxy-tolerant decoder as packet-up/stream-one: chunk extensions,
        // trailers and proxy-combined chunks up to 16 MiB through a fixed 16 KiB buffer.
        let download = crate::xhttp_carrier::receive_chunks(&mut network_read, &mut output);
        if let Err(error) = tokio::try_join!(upload, download) {
            tracing::debug!(%error,"HTTP body carrier ended");
        }
    });
    Box::new(ManagedIo { io, task })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(cert: &Path, key: &Path) -> Listener {
        serde_json::from_value(serde_json::json!({
            "addr": "127.0.0.1:0", "transport": "wss",
            "cert_file": cert, "key_file": key
        }))
        .unwrap()
    }

    #[test]
    fn tls_settings_are_reused_until_the_files_change() {
        let directory = tempfile::tempdir().unwrap();
        let (cert, key) =
            crate::config::generate_certificate(directory.path(), vec!["a.example".into()])
                .unwrap();
        let listener = listener(&cert, &key);
        let first = server_tls(&listener).unwrap();
        let second = server_tls(&listener).unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "unchanged files must reuse the loaded settings"
        );

        // Renew: write a different certificate over the same paths.
        let other = tempfile::tempdir().unwrap();
        let (new_cert, new_key) =
            crate::config::generate_certificate(other.path(), vec!["b.example".into()]).unwrap();
        std::fs::copy(&new_cert, &cert).unwrap();
        std::fs::copy(&new_key, &key).unwrap();
        let later = SystemTime::now() + Duration::from_secs(5);
        for path in [&cert, &key] {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(later)
                .unwrap();
        }
        let third = server_tls(&listener).unwrap();
        assert!(
            !Arc::ptr_eq(&first, &third),
            "a renewed certificate must be picked up"
        );

        // If the files vanish, the last good settings keep working.
        std::fs::remove_file(&cert).unwrap();
        let fourth = server_tls(&listener).unwrap();
        assert!(
            Arc::ptr_eq(&third, &fourth),
            "must fall back to the previous settings"
        );
    }

    #[test]
    fn missing_tls_files_without_a_previous_copy_are_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let listener = listener(
            &directory.path().join("no.pem"),
            &directory.path().join("no.key"),
        );
        assert!(server_tls(&listener).is_err());
    }

    /// C40: stream-up accepts ordinary proxy framing: chunk extensions, a chunk above
    /// 64 KiB (well under the 16 MiB proxy limit), arbitrary split delivery and trailers.
    #[tokio::test]
    async fn stream_up_decoder_accepts_proxy_framing_and_rejects_malformed_chunks() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let big: Vec<u8> = (0..65_537u32).map(|i| (i % 251) as u8).collect();
        let mut wire = b"1;foo=bar\r\nx\r\n".to_vec();
        wire.extend_from_slice(format!("{:x}\r\n", big.len()).as_bytes());
        wire.extend_from_slice(&big);
        wire.extend_from_slice(b"\r\n0\r\nX-Trailer: 1\r\n\r\n");
        let (local, mut remote) = tokio::io::duplex(1 << 20);
        let mut io = chunked_io(Box::new(local));
        let writer = tokio::spawn(async move {
            for piece in wire.chunks(17) {
                remote.write_all(piece).await?;
                tokio::task::yield_now().await;
            }
            remote.flush().await?;
            anyhow::Ok(remote)
        });
        let mut received = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(20), io.read_to_end(&mut received)).await??;
        let mut expected = b"x".to_vec();
        expected.extend_from_slice(&big);
        assert_eq!(received.len(), expected.len());
        assert!(received == expected, "payload changed in transit");
        drop(writer.await??);
        for bad in [
            b"zz\r\n".as_slice(),
            b"1\r\nxZZ".as_slice(),
            b"0\r\nno-colon\r\n\r\n".as_slice(),
            b"1000001\r\n".as_slice(),
        ] {
            let (local, mut remote) = tokio::io::duplex(4096);
            let mut io = chunked_io(Box::new(local));
            remote.write_all(bad).await?;
            remote.flush().await?;
            let mut out = Vec::new();
            // Malformed framing ends the carrier: EOF with nothing (or only the valid
            // prefix) delivered, never a clean trailer-terminated stream of garbage.
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), io.read_to_end(&mut out)).await;
            assert!(result.is_ok(), "decoder hung on {bad:?}");
            assert!(out.len() <= 1, "malformed input produced data: {bad:?}");
            drop(remote);
        }
        Ok(())
    }
}
