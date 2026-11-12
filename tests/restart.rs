//! A restarted side says goodbye before it stops, so the other side reconnects within seconds
//! instead of after `dead_timeout_sec` (set to 30 s here). On the UDP carriers (fec-udp, kcp) there
//! is no connection to close, so before 0.7.8 the client only noticed after the dead timeout.
// These tests exercise actual process restarts.
#![cfg(unix)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde_json::json;

const BINARY: &str = env!("CARGO_BIN_EXE_eztunnel");

struct Process {
    child: Child,
    log: PathBuf,
}

impl Process {
    fn start(config: &Path, log: &Path) -> Result<Self> {
        let output = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)?;
        let child = Command::new(BINARY)
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(output)
            .spawn()?;
        Ok(Self {
            child,
            log: log.to_path_buf(),
        })
    }

    /// Sends SIGTERM (what `systemctl stop` and `restart` send) and waits for a clean exit.
    fn stop(&mut self) -> Result<()> {
        // SAFETY: plain system call with a valid process id and signal number.
        let sent = unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        ensure!(sent == 0, "could not send SIGTERM");
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait()? {
                ensure!(status.success(), "unclean exit: {status}");
                return Ok(());
            }
            ensure!(
                started.elapsed() < Duration::from_secs(5),
                "the program ignored SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn keypair(directory: &Path, name: &str) -> Result<String> {
    let status = Command::new(BINARY)
        .args(["keygen", "--out"])
        .arg(directory.join(name))
        .stdout(Stdio::null())
        .status()?;
    ensure!(status.success(), "keygen failed");
    Ok(
        std::fs::read_to_string(directory.join(name).join("public.key"))?
            .trim()
            .to_owned(),
    )
}

/// A free local port for the tunnel. FEC-UDP also needs its knock port (port + 10000) free.
fn tunnel_port(transport: &str) -> Result<u16> {
    for _ in 0..50 {
        let port = if transport == "tcp" {
            TcpListener::bind("127.0.0.1:0")?.local_addr()?.port()
        } else {
            UdpSocket::bind("127.0.0.1:0")?.local_addr()?.port()
        };
        if transport != "fec-udp" {
            return Ok(port);
        }
        if port <= 55_535 && UdpSocket::bind(("127.0.0.1", port + 10_000)).is_ok() {
            return Ok(port);
        }
    }
    bail!("no free port pair")
}

fn echo_server() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buffer = [0u8; 4096];
                while let Ok(count) = stream.read(&mut buffer) {
                    if count == 0 || stream.write_all(&buffer[..count]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(address)
}

/// One request and answer through the tunnel's port map.
fn works(map: SocketAddr) -> bool {
    let attempt = || -> Result<()> {
        let mut stream = TcpStream::connect_timeout(&map, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.write_all(b"ping")?;
        let mut answer = [0u8; 4];
        stream.read_exact(&mut answer)?;
        ensure!(&answer == b"ping", "payload changed");
        Ok(())
    };
    attempt().is_ok()
}

fn wait_until_works(map: SocketAddr, limit: Duration) -> Result<Duration> {
    let started = Instant::now();
    while started.elapsed() < limit {
        if works(map) {
            return Ok(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("the tunnel did not carry data within {limit:?}")
}

fn wait_for_log(process: &Process, text: &str, limit: Duration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < limit {
        if process.log().contains(text) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!(
        "{text:?} not logged within {limit:?}; log:\n{}",
        process.log()
    )
}

fn scenario(transport: &str) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let server_public = keypair(directory.path(), "server")?;
    let client_public = keypair(directory.path(), "client")?;
    let echo = echo_server()?;
    let tunnel: SocketAddr = format!("127.0.0.1:{}", tunnel_port(transport)?).parse()?;
    let map = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let server_config = directory.path().join("server.json");
    std::fs::write(
        &server_config,
        serde_json::to_vec(&json!({
            "mode": "server",
            "private_key_file": directory.path().join("server/private.key"),
            "peer_public_keys": [client_public],
            "listeners": [{"addr": tunnel.to_string(), "transport": transport, "maps": [
                {"type": "tcp", "bind": map.to_string(), "target": echo.to_string()}
            ]}],
            "heartbeat_sec": 2, "dead_timeout_sec": 30,
        }))?,
    )?;
    let client_config = directory.path().join("client.json");
    std::fs::write(
        &client_config,
        serde_json::to_vec(&json!({
            "mode": "client",
            "private_key_file": directory.path().join("client/private.key"),
            "paths": [{"addr": tunnel.to_string(), "transport": transport,
                       "server_public_key": server_public, "connection_pool": 2,
                       "retry_interval": 1, "dial_timeout": 2}],
            "allowed_targets": [echo.to_string()],
            "heartbeat_sec": 2, "dead_timeout_sec": 30,
        }))?,
    )?;
    let server_log = directory.path().join("server.log");
    let client_log = directory.path().join("client.log");
    let mut server = Process::start(&server_config, &server_log)?;
    let mut client = Process::start(&client_config, &client_log)?;
    wait_until_works(map, Duration::from_secs(30)).context("first connection")?;

    // The server restarts: it tells the client, and the client is back within seconds.
    server.stop()?;
    ensure!(
        server
            .log()
            .contains("told the other server that this one is stopping"),
        "{transport}: the server did not say goodbye; log:\n{}",
        server.log()
    );
    wait_for_log(
        &client,
        "the other server is stopping or restarting",
        Duration::from_secs(3),
    )
    .with_context(|| format!("{transport}: the client did not hear the goodbye"))?;
    let restarted = Process::start(&server_config, &server_log)?;
    let took = wait_until_works(map, Duration::from_secs(12)).with_context(|| {
        format!(
            "{transport}: no fast reconnect after the server restarted; client log:\n{}",
            client.log()
        )
    })?;
    eprintln!("{transport}: server restart, carrying data again after {took:?}");
    server = restarted;

    // The client restarts: the server drops the client's sessions at once, so no user connection
    // waits on a dead one.
    ensure!(
        !server
            .log()
            .contains("the other server is stopping or restarting"),
        "{transport}: the server heard a goodbye before the client stopped"
    );
    client.stop()?;
    wait_for_log(
        &server,
        "the other server is stopping or restarting",
        Duration::from_secs(3),
    )
    .with_context(|| format!("{transport}: the server kept the stopped client's sessions"))?;
    client = Process::start(&client_config, &client_log)?;
    let took = wait_until_works(map, Duration::from_secs(12))
        .with_context(|| format!("{transport}: no reconnect after the client restarted"))?;
    eprintln!("{transport}: client restart, carrying data again after {took:?}");
    drop(client);
    drop(server);
    Ok(())
}

/// The client crashes (no goodbye) and starts again. On the UDP carriers the server cannot tell
/// that the old sessions are dead and would keep sending users to them until the dead timeout
/// (30 s here); the client's new sessions make it probe and close them within seconds.
fn crash_scenario(transport: &str) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let server_public = keypair(directory.path(), "server")?;
    let client_public = keypair(directory.path(), "client")?;
    let echo = echo_server()?;
    let tunnel: SocketAddr = format!("127.0.0.1:{}", tunnel_port(transport)?).parse()?;
    let map = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let server_config = directory.path().join("server.json");
    std::fs::write(
        &server_config,
        serde_json::to_vec(&json!({
            "mode": "server",
            "private_key_file": directory.path().join("server/private.key"),
            "peer_public_keys": [client_public],
            "listeners": [{"addr": tunnel.to_string(), "transport": transport, "maps": [
                {"type": "tcp", "bind": map.to_string(), "target": echo.to_string()}
            ]}],
            "heartbeat_sec": 10, "dead_timeout_sec": 30,
        }))?,
    )?;
    let client_config = directory.path().join("client.json");
    std::fs::write(
        &client_config,
        serde_json::to_vec(&json!({
            "mode": "client",
            "private_key_file": directory.path().join("client/private.key"),
            "paths": [{"addr": tunnel.to_string(), "transport": transport,
                       "server_public_key": server_public, "connection_pool": 2,
                       "retry_interval": 1, "dial_timeout": 2}],
            "allowed_targets": [echo.to_string()],
            "heartbeat_sec": 10, "dead_timeout_sec": 30,
        }))?,
    )?;
    let server_log = directory.path().join("server.log");
    let client_log = directory.path().join("client.log");
    let server = Process::start(&server_config, &server_log)?;
    let client = Process::start(&client_config, &client_log)?;
    wait_until_works(map, Duration::from_secs(30)).context("first connection")?;
    // Crash: SIGKILL, so nothing is said.
    drop(client);
    let crashed = Instant::now();
    let client = Process::start(&client_config, &client_log)?;
    wait_until_works(map, Duration::from_secs(12)).context("no reconnect after the crash")?;
    wait_for_log(
        &server,
        "closing one of its older sessions that no longer answers",
        Duration::from_secs(10),
    )
    .with_context(|| format!("{transport}: the dead sessions were kept"))?;
    // Every user now gets a working session.
    for attempt in 0..10 {
        ensure!(
            works(map),
            "{transport}: user {attempt} failed after the old sessions were closed; server log:
{}",
            server.log()
        );
    }
    let took = crashed.elapsed();
    ensure!(
        took < Duration::from_secs(20),
        "{transport}: took {took:?}, close to the dead timeout"
    );
    eprintln!("{transport}: crash, every user served again after {took:?}");
    drop(client);
    drop(server);
    Ok(())
}

/// The server crashes (no goodbye) and starts again. On the UDP carriers the client's sessions
/// point at a program that no longer knows them and nothing tells the client; before 0.8.5 it
/// waited for the dead timeout (60 s here). Now a session that gets no answer turns suspect and
/// the client replaces it with a fresh connection as soon as one works.
fn server_crash_scenario(transport: &str) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let server_public = keypair(directory.path(), "server")?;
    let client_public = keypair(directory.path(), "client")?;
    let echo = echo_server()?;
    let tunnel: SocketAddr = format!("127.0.0.1:{}", tunnel_port(transport)?).parse()?;
    let map = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let server_config = directory.path().join("server.json");
    std::fs::write(
        &server_config,
        serde_json::to_vec(&json!({
            "mode": "server",
            "private_key_file": directory.path().join("server/private.key"),
            "peer_public_keys": [client_public],
            "listeners": [{"addr": tunnel.to_string(), "transport": transport, "maps": [
                {"type": "tcp", "bind": map.to_string(), "target": echo.to_string()}
            ]}],
            "heartbeat_sec": 5, "dead_timeout_sec": 60,
        }))?,
    )?;
    let client_config = directory.path().join("client.json");
    std::fs::write(
        &client_config,
        serde_json::to_vec(&json!({
            "mode": "client",
            "private_key_file": directory.path().join("client/private.key"),
            "paths": [{"addr": tunnel.to_string(), "transport": transport,
                       "server_public_key": server_public, "connection_pool": 2,
                       "retry_interval": 1, "dial_timeout": 2}],
            "allowed_targets": [echo.to_string()],
            "heartbeat_sec": 5, "dead_timeout_sec": 60,
        }))?,
    )?;
    let server_log = directory.path().join("server.log");
    let client_log = directory.path().join("client.log");
    let server = Process::start(&server_config, &server_log)?;
    let client = Process::start(&client_config, &client_log)?;
    wait_until_works(map, Duration::from_secs(30)).context("first connection")?;
    // Crash: SIGKILL, so nothing is said.
    drop(server);
    let crashed = Instant::now();
    let server = Process::start(&server_config, &server_log)?;
    let took = wait_until_works(map, Duration::from_secs(25)).with_context(|| {
        format!(
            "{transport}: no recovery well before the dead timeout; client log:
{}",
            client.log()
        )
    })?;
    wait_for_log(
        &client,
        "replaced it with a new connection",
        Duration::from_secs(10),
    )?;
    // Both pooled sessions end up working: every user is served.
    std::thread::sleep(Duration::from_secs(8));
    for attempt in 0..10 {
        ensure!(
            works(map),
            "{transport}: user {attempt} failed; client log:
{}",
            client.log()
        );
    }
    eprintln!(
        "{transport}: server crash, carrying data again after {took:?} ({:?} since the crash)",
        crashed.elapsed()
    );
    drop(client);
    drop(server);
    Ok(())
}

#[test]
fn fec_udp_recovers_quickly_after_the_server_crashed() -> Result<()> {
    server_crash_scenario("fec-udp")
}

#[test]
fn kcp_recovers_quickly_after_the_server_crashed() -> Result<()> {
    server_crash_scenario("kcp")
}

#[test]
fn fec_udp_closes_the_dead_sessions_of_a_crashed_client() -> Result<()> {
    crash_scenario("fec-udp")
}

#[test]
fn kcp_closes_the_dead_sessions_of_a_crashed_client() -> Result<()> {
    crash_scenario("kcp")
}

#[test]
fn fec_udp_reconnects_within_seconds_after_either_side_restarts() -> Result<()> {
    scenario("fec-udp")
}

#[test]
fn kcp_reconnects_within_seconds_after_either_side_restarts() -> Result<()> {
    scenario("kcp")
}

#[test]
fn tcp_reconnects_within_seconds_after_either_side_restarts() -> Result<()> {
    scenario("tcp")
}
