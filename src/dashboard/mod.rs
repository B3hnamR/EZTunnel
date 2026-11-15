//! The web dashboard: an HTTPS server that shows the tunnels on this server.
//!
//! `eztunnel dashboard setup` creates the state directory (random port, a random password shown
//! once, a self-signed certificate); `eztunnel dashboard serve` runs the server; `eztunnel
//! dashboard demo` serves the same interface with sample data on the loopback address only.
mod acme;
mod agent;
mod alerts;
mod assets;
mod audit;
mod auth;
mod data;
mod edit;
mod fleet;
mod history;
mod host;
mod http;
mod link;
mod ops;
mod conntest;
mod maintain;
mod prefs;
mod relay;
mod service;
mod spoofcheck;
mod sshadd;
mod tls;
mod tools;
mod wizard;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Where the dashboard keeps its settings, certificate and audit log.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/eztunnel-dashboard";
const SETTINGS_FILE: &str = "settings.json";
const PASSWORD_LENGTH: usize = 20;
/// Letters and digits that cannot be mistaken for each other when read from a screen.
const PASSWORD_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// The random port is chosen from this range.
const PORT_RANGE: std::ops::RangeInclusive<u16> = 20_000..=60_999;

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    version: u32,
    port: u16,
    password_hash: String,
    created: u64,
    /// A Let's Encrypt certificate for this address instead of the self-signed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme: Option<acme::AcmeSettings>,
}

fn settings_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SETTINGS_FILE)
}

fn load_settings(state_dir: &Path) -> Result<Settings> {
    let path = settings_path(state_dir);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read {}; run `eztunnel dashboard setup` first",
            path.display()
        )
    })?;
    let settings: Settings = serde_json::from_str(&text).context("unreadable dashboard settings")?;
    ensure!(settings.version == 1, "unknown dashboard settings version");
    Ok(settings)
}

/// Saves a new password hash (changed from the Settings screen).
pub(crate) fn save_password_hash(state_dir: &Path, hash: &str) -> Result<()> {
    let mut settings = load_settings(state_dir)?;
    settings.password_hash = hash.to_string();
    save_settings(state_dir, &settings)
}

fn save_settings(state_dir: &Path, settings: &Settings) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(settings)?;
    write_private(&settings_path(state_dir), &bytes)
}

/// Fills `bytes` from the operating system's random source.
pub(crate) fn random_bytes(bytes: &mut [u8]) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(bytes)
        .map_err(|_| anyhow::anyhow!("no random source"))
}

fn random_password() -> Result<String> {
    // Rejection sampling keeps every letter equally likely.
    let limit = 256 - 256 % PASSWORD_ALPHABET.len();
    let mut password = String::with_capacity(PASSWORD_LENGTH);
    let mut buffer = [0u8; 64];
    while password.len() < PASSWORD_LENGTH {
        random_bytes(&mut buffer)?;
        for byte in buffer {
            if (byte as usize) < limit && password.len() < PASSWORD_LENGTH {
                password.push(PASSWORD_ALPHABET[byte as usize % PASSWORD_ALPHABET.len()] as char);
            }
        }
    }
    Ok(password)
}

fn random_free_port() -> Result<u16> {
    let span = (*PORT_RANGE.end() - *PORT_RANGE.start()) as u32 + 1;
    for _ in 0..200 {
        let mut bytes = [0u8; 4];
        random_bytes(&mut bytes)?;
        let port = *PORT_RANGE.start() + (u32::from_le_bytes(bytes) % span) as u16;
        if std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok() {
            return Ok(port);
        }
    }
    bail!("no free port found")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect {}", dir.display()))?;
    }
    Ok(())
}

/// Writes a file readable only by its owner, through a temporary file so a crash never leaves
/// half a file behind.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let temporary = path.with_extension("tmp");
    let _ = std::fs::remove_file(&temporary);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn require_root() -> Result<()> {
    ensure!(
        crate::manager::store::is_root(),
        "the dashboard manages system services; run it as root"
    );
    Ok(())
}

/// The address to print for this server: its outgoing IPv4 address, or a placeholder.
fn shown_address() -> String {
    crate::manager::local_ip().unwrap_or_else(|| "SERVER-IP".to_string())
}

/// Creates the dashboard's settings: a random port, a random password (printed once) and a
/// self-signed certificate; with `service`, installs and starts its system service. A dashboard
/// that was removed but kept its settings only gets its service back.
pub fn setup(state_dir: &Path, port: Option<u16>, service: bool) -> Result<()> {
    require_root()?;
    if settings_path(state_dir).exists() {
        ensure!(
            service && !service::installed(),
            "the dashboard is already set up; use `eztunnel dashboard reset-password` for a new password"
        );
        load_settings(state_dir)?;
        service::install(state_dir)?;
        println!("The dashboard runs again with its earlier settings and password ({}).", service::UNIT);
        return Ok(());
    }
    create_private_dir(state_dir)?;
    let port = match port {
        Some(port) => port,
        None => random_free_port()?,
    };
    let password = random_password()?;
    let settings = Settings {
        version: 1,
        port,
        password_hash: auth::hash_password(&password)?,
        created: now(),
        acme: None,
    };
    let address = shown_address();
    tls::load_or_create(state_dir, &address)?;
    save_settings(state_dir, &settings)?;
    println!("Dashboard is set up.");
    println!();
    println!("  Address:   https://{address}:{port}");
    println!("  Password:  {password}");
    println!();
    println!("The password is shown only this once. Keep it somewhere safe.");
    println!("The certificate is self-signed, so the browser warns once before it opens the page.");
    if service {
        service::install(state_dir)?;
        println!("The dashboard runs now and starts with the server ({}).", service::UNIT);
    } else {
        println!("Start it with: eztunnel dashboard serve");
    }
    Ok(())
}

/// Moves the dashboard to another port.
pub fn set_port(state_dir: &Path, port: u16) -> Result<()> {
    require_root()?;
    ensure!(port >= 1024, "use a port from 1024 to 65535");
    let mut settings = load_settings(state_dir)?;
    if settings.port == port {
        println!("The dashboard already uses port {port}.");
        return Ok(());
    }
    std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
        .with_context(|| format!("port {port} is in use by another program"))?;
    settings.port = port;
    save_settings(state_dir, &settings)?;
    println!("The dashboard's port is {port} now. Open it in the firewall if one is in use.");
    service::apply("the new port")
}

/// Stops the dashboard and removes its service. Its settings, history and backups stay unless
/// `delete_data` is set. Joined servers keep their tunnels; they lose the dashboard.
pub fn remove(state_dir: &Path, delete_data: bool) -> Result<()> {
    require_root()?;
    service::remove();
    if delete_data {
        if state_dir.exists() {
            std::fs::remove_dir_all(state_dir).with_context(|| format!("delete {}", state_dir.display()))?;
        }
        println!("The dashboard is removed with its settings, history and backups.");
    } else {
        println!("The dashboard is stopped and its service removed.");
        println!("Its settings, history and backups stay in {}; set it up again to run it with them.", state_dir.display());
    }
    println!("Tunnels on this server and on joined servers keep running.");
    Ok(())
}

/// The dashboard's system service.
pub const DASHBOARD_UNIT: &str = service::UNIT;

pub fn service_start() -> Result<()> {
    require_root()?;
    service::start()
}

pub fn service_stop() -> Result<()> {
    require_root()?;
    service::stop()
}

pub fn service_restart() -> Result<()> {
    require_root()?;
    service::restart()
}

/// Restarts the agent service, for example after an update so it runs the new program.
pub fn agent_restart() -> Result<()> {
    require_root()?;
    let status = std::process::Command::new("systemctl").args(["restart", agent::UNIT]).status()?;
    ensure!(status.success(), "systemctl restart {} failed", agent::UNIT);
    Ok(())
}

/// What `eztunnel dashboard status` and the manager's Web dashboard screen show.
pub struct Summary {
    pub set_up: bool,
    pub service_installed: bool,
    pub running: bool,
    pub url: String,
    pub certificate: String,
    /// The dashboard this server is joined to as an agent.
    pub joined_to: Option<String>,
    pub agent_running: bool,
}

pub fn summary(state_dir: &Path) -> Summary {
    let settings = load_settings(state_dir).ok();
    let certificate = match settings.as_ref().and_then(|s| s.acme.as_ref()) {
        None => "self-signed".to_string(),
        Some(wanted) => {
            let staging = if wanted.staging { ", staging" } else { "" };
            match acme::load(state_dir).and_then(|issued| issued.validity().ok()) {
                Some((_, until)) => format!("Let's Encrypt for {}{staging}, valid until {}", wanted.address, acme::utc_text(until)),
                None => format!("Let's Encrypt for {}{staging}, not issued yet", wanted.address),
            }
        }
    };
    let url = settings.as_ref().map_or_else(String::new, |s| {
        let host = s.acme.as_ref().map_or_else(shown_address, |a| a.address.clone());
        let host = if host.contains(':') { format!("[{host}]") } else { host };
        format!("https://{host}:{}", s.port)
    });
    Summary {
        set_up: settings.is_some(),
        service_installed: service::installed(),
        running: service::active(service::UNIT),
        url,
        certificate,
        joined_to: agent::joined(Path::new(agent::CONFIG_DIR)),
        agent_running: service::active(agent::UNIT),
    }
}

/// `eztunnel dashboard status`.
pub fn status(state_dir: &Path) -> Result<()> {
    let s = summary(state_dir);
    if s.set_up {
        let state = match (s.service_installed, s.running) {
            (_, true) => "running",
            (true, false) => "stopped",
            (false, false) => "no service (run `eztunnel dashboard setup` to add it)",
        };
        println!("Dashboard:    {state}");
        println!("Address:      {}", s.url);
        println!("Certificate:  {}", s.certificate);
    } else {
        println!("Dashboard:    not set up on this server");
    }
    match &s.joined_to {
        Some(hub) => println!("Agent:        joined to the dashboard at {hub} ({})", if s.agent_running { "running" } else { "stopped" }),
        None => println!("Agent:        not joined to a dashboard"),
    }
    Ok(())
}

/// Replaces the password with a new random one, printed once. Signed-in browsers are signed out
/// when the dashboard restarts.
pub fn reset_password(state_dir: &Path) -> Result<()> {
    require_root()?;
    let mut settings = load_settings(state_dir)?;
    let password = random_password()?;
    settings.password_hash = auth::hash_password(&password)?;
    save_settings(state_dir, &settings)?;
    println!("New password (shown only this once): {password}");
    service::apply("the new password; every browser signed in with the old one is signed out")
}

/// Runs the dashboard over HTTPS with the settings made by `setup`.
pub async fn serve(state_dir: &Path, listen: Option<IpAddr>) -> Result<()> {
    require_root()?;
    let settings = load_settings(state_dir)?;
    let swap = Arc::new(tls::Swap::self_signed(state_dir, &shown_address())?);
    let tls = tls::server_config(swap.clone())?;
    let audit = audit::Audit::open(&state_dir.join("audit.log"))?;
    let history = Arc::new(history::History::new(Box::new(history::FileStore::open(
        &state_dir.join("history"),
    )?)));
    let live = data::Live::start(Box::new(data::LocalSource::new()?), Some(history.clone()));
    let state = Arc::new(http::AppState {
        history,
        auth: auth::Auth::new(settings.password_hash),
        audit,
        live,
        ops: Arc::new(ops::LocalOps),
        busy: Default::default(),
        followers: Arc::new(tokio::sync::Semaphore::new(http::MAX_FOLLOWERS)),
        fleet: Some(fleet::Fleet::open(state_dir)?),
        public: (
            settings.acme.as_ref().map_or_else(shown_address, |a| a.address.clone()),
            settings.port,
        ),
        agent_slots: Arc::new(tokio::sync::Semaphore::new(256)),
        cert: Some(swap.clone()),
        demo: false,
        secure: true,
        state_dir: state_dir.to_path_buf(),
        alerts: Default::default(),
    });
    tokio::spawn(http::backup_loop(state.clone()));
    tokio::spawn(http::alert_loop(state.clone()));
    let address = SocketAddr::new(listen.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), settings.port);
    audit_start(&state, address);
    if let Some(acme_settings) = settings.acme.clone() {
        let reporter = state.clone();
        tokio::spawn(acme::keep_renewed(
            state_dir.to_path_buf(),
            acme_settings,
            swap,
            move |result| match result {
                Ok(next) => reporter.audit.record(
                    None,
                    "certificate",
                    &format!("Let's Encrypt certificate in use; next renewal {}", acme::utc_text(next)),
                ),
                Err(error) => {
                    eprintln!("Let's Encrypt certificate: {error}");
                    reporter.audit.record(None, "certificate_failed", &error);
                }
            },
        ));
    }
    http::serve(state, address, Some(tls)).await
}

/// Switches the dashboard to a Let's Encrypt certificate for `address` (this server's address
/// when not given), ordering the first one now so a problem shows at once; or back to the
/// self-signed certificate. The running dashboard uses the change after a restart.
pub async fn certificate(state_dir: &Path, lets_encrypt: bool, staging: bool, address: Option<String>) -> Result<()> {
    require_root()?;
    let mut settings = load_settings(state_dir)?;
    if !lets_encrypt {
        settings.acme = None;
        save_settings(state_dir, &settings)?;
        acme::forget(state_dir);
        println!("The dashboard uses its self-signed certificate again.");
        return service::apply("the self-signed certificate");
    }
    let address = address.unwrap_or_else(shown_address);
    ensure!(address != "SERVER-IP", "this server's address was not found; give it with --address");
    let wanted = acme::AcmeSettings { address: address.clone(), staging };
    println!("Asking Let's Encrypt for a certificate for {address}.");
    println!("It checks this server over port 80, which must be free and open for about a minute.");
    let issued = acme::issue(state_dir, &wanted, 80).await?;
    let (_, until) = issued.validity()?;
    settings.acme = Some(wanted);
    save_settings(state_dir, &settings)?;
    let kind = if staging { " (staging, not trusted by browsers)" } else { "" };
    println!("Certificate ready{kind}, valid until {}.", acme::utc_text(until));
    println!("The dashboard renews it by itself from now on.");
    service::apply("the new certificate")
}

/// Serves the interface with sample data on the loopback address, over plain HTTP. Nothing on
/// the machine is read or changed; the password is printed at start.
pub async fn demo(port: u16, empty: bool) -> Result<()> {
    let password = random_password()?;
    let now_minute = now() / 60;
    let demo_tunnels = if empty {
        Vec::new()
    } else {
        vec![("game-fec", 3.2e6, true), ("web-wss", 11.0e6, true), ("cdn-xhttps", 0.9e6, true), ("backup-tcp", 1.5e6, false)]
    };
    let names: Vec<&str> = demo_tunnels.iter().map(|t| t.0).collect();
    let demo_ops = ops::DemoOps::new(&names);
    let state = Arc::new(http::AppState {
        history: Arc::new(history::History::new(Box::new(history::DemoStore {
            tunnels: demo_tunnels,
            started_minute: now_minute,
        }))),
        auth: auth::Auth::new(auth::hash_password(&password)?),
        audit: audit::Audit::disabled().with_samples(),
        live: data::Live::start(Box::new(data::DemoSource::with_ops(!empty, demo_ops.clone())), None),
        ops: Arc::new(demo_ops),
        busy: Default::default(),
        followers: Arc::new(tokio::sync::Semaphore::new(http::MAX_FOLLOWERS)),
        fleet: None,
        public: ("203.0.113.10".into(), port),
        agent_slots: Arc::new(tokio::sync::Semaphore::new(4)),
        cert: None,
        demo: true,
        secure: false,
        state_dir: std::env::temp_dir().join(format!("eztunnel-demo-{}", std::process::id())),
        alerts: Default::default(),
    });
    tokio::spawn(http::alert_loop(state.clone()));
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    println!("Dashboard demo with sample data: http://{address}");
    println!("Password: {password}");
    http::serve(state, address, None).await
}

/// `eztunnel agent join CODE`: admits this server to a dashboard and installs the agent service.
pub async fn agent_join(code: &str) -> Result<()> {
    agent::join(code, Path::new(agent::CONFIG_DIR), true).await
}

/// `eztunnel agent run`: the agent service.
pub async fn agent_run(config_dir: &Path) -> Result<()> {
    agent::run(config_dir).await
}

/// `eztunnel agent leave`: stops the agent and forgets the dashboard.
pub fn agent_leave() -> Result<()> {
    agent::leave(Path::new(agent::CONFIG_DIR))
}

fn audit_start(state: &http::AppState, address: SocketAddr) {
    state
        .audit
        .record(None, "start", &format!("listening on {address}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_are_long_and_use_only_unambiguous_letters() {
        let password = random_password().unwrap();
        assert_eq!(password.len(), PASSWORD_LENGTH);
        assert!(password.bytes().all(|b| PASSWORD_ALPHABET.contains(&b)));
        assert_ne!(password, random_password().unwrap());
    }

    #[test]
    fn settings_are_written_privately_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            version: 1,
            port: 31_000,
            password_hash: "x".into(),
            created: 1,
            acme: Some(acme::AcmeSettings { address: "203.0.113.10".into(), staging: true }),
        };
        save_settings(dir.path(), &settings).unwrap();
        let back = load_settings(dir.path()).unwrap();
        assert_eq!(back.port, 31_000);
        assert_eq!(back.acme, settings.acme);
        // Settings written before certificates existed still load.
        write_private(&settings_path(dir.path()), br#"{"version":1,"port":1,"password_hash":"x","created":1}"#).unwrap();
        assert_eq!(load_settings(dir.path()).unwrap().acme, None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(settings_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
