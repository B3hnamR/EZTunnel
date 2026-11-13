//! The web dashboard: an HTTPS server that shows the tunnels on this server.
//!
//! `eztunnel dashboard setup` creates the state directory (random port, a random password shown
//! once, a self-signed certificate); `eztunnel dashboard serve` runs the server; `eztunnel
//! dashboard demo` serves the same interface with sample data on the loopback address only.
mod assets;
mod audit;
mod auth;
mod data;
mod history;
mod host;
mod http;
mod tls;

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
/// self-signed certificate.
pub fn setup(state_dir: &Path, port: Option<u16>) -> Result<()> {
    require_root()?;
    ensure!(
        !settings_path(state_dir).exists(),
        "the dashboard is already set up; use `eztunnel dashboard reset-password` for a new password"
    );
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
    println!("Start it with: eztunnel dashboard serve");
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
    println!("Restart the dashboard to sign out every browser that used the old one.");
    Ok(())
}

/// Runs the dashboard over HTTPS with the settings made by `setup`.
pub async fn serve(state_dir: &Path, listen: Option<IpAddr>) -> Result<()> {
    require_root()?;
    let settings = load_settings(state_dir)?;
    let (tls, _pin) = tls::load_or_create(state_dir, &shown_address())?;
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
        demo: false,
        secure: true,
    });
    let address = SocketAddr::new(listen.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), settings.port);
    audit_start(&state, address);
    http::serve(state, address, Some(tls)).await
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
    let state = Arc::new(http::AppState {
        history: Arc::new(history::History::new(Box::new(history::DemoStore {
            tunnels: demo_tunnels,
            started_minute: now_minute,
        }))),
        auth: auth::Auth::new(auth::hash_password(&password)?),
        audit: audit::Audit::disabled(),
        live: data::Live::start(Box::new(data::DemoSource::with_tunnels(!empty)), None),
        demo: true,
        secure: false,
    });
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    println!("Dashboard demo with sample data: http://{address}");
    println!("Password: {password}");
    http::serve(state, address, None).await
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
        };
        save_settings(dir.path(), &settings).unwrap();
        let back = load_settings(dir.path()).unwrap();
        assert_eq!(back.port, 31_000);
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
