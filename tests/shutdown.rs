//! `systemctl stop` sends SIGTERM; the program must stop promptly, report it, and exit cleanly.

use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde_json::json;

fn spawn_server(directory: &std::path::Path) -> Result<std::process::Child> {
    let binary = env!("CARGO_BIN_EXE_eztunnel");
    for name in ["server", "client"] {
        let status = Command::new(binary)
            .args(["keygen", "--out"])
            .arg(directory.join(name))
            .stdout(Stdio::null())
            .status()?;
        anyhow::ensure!(status.success(), "keygen failed");
    }
    let client_public = std::fs::read_to_string(directory.join("client/public.key"))?;
    let config = directory.join("server.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "mode": "server",
            "private_key_file": directory.join("server/private.key"),
            "peer_public_keys": [client_public.trim()],
            "listeners": [{"addr": "127.0.0.1:0"}],
        }))?,
    )?;
    Ok(Command::new(binary)
        .arg("--config")
        .arg(&config)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?)
}

#[cfg(unix)]
#[test]
fn sigterm_stops_the_program_cleanly() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut child = spawn_server(directory.path())?;
    // Give it time to bind and install its signal handlers.
    std::thread::sleep(Duration::from_millis(800));
    anyhow::ensure!(
        child.try_wait()?.is_none(),
        "the program exited before it was signalled"
    );
    // SAFETY: plain system call with a valid process id and signal number.
    let sent = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    anyhow::ensure!(sent == 0, "could not send SIGTERM");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            bail!("the program ignored SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut log = String::new();
    child
        .stderr
        .take()
        .context("stderr missing")?
        .read_to_string(&mut log)?;
    anyhow::ensure!(
        status.success(),
        "expected a clean exit, got {status}; log: {log}"
    );
    anyhow::ensure!(log.contains("shutting down"), "no shutdown message: {log}");
    Ok(())
}
