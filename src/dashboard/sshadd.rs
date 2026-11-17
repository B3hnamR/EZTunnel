//! Adding a server over SSH: the dashboard has its own SSH key (made once, kept in its state
//! folder). The operator adds the public half to the new server's authorized_keys, then the
//! dashboard logs in with it and runs the same one-time join command Easy connect shows. No
//! password is ever handled, the host key is pinned on first use, and only the join command runs.
use anyhow::{Context, Result, bail, ensure};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

fn key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("ssh").join("id_ed25519")
}

/// The dashboard's public SSH key, made on first use.
pub fn public_key(state_dir: &Path) -> Result<String> {
    let key = key_path(state_dir);
    if !key.exists() {
        let dir = key.parent().context("key folder")?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)?;
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "eztunnel-dashboard", "-f"])
            .arg(&key)
            .stdin(Stdio::null())
            .status()
            .context("run ssh-keygen")?;
        ensure!(status.success(), "ssh-keygen failed");
    }
    Ok(std::fs::read_to_string(key.with_extension("pub"))?.trim().to_string())
}

/// A host name or IP address, nothing an ssh option could hide in.
pub fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

pub fn user_ok(user: &str) -> bool {
    !user.is_empty() && user.len() <= 32 && !user.starts_with('-') && user.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// Logs in and runs the join command (with sudo when the user is not root). Returns the last
/// lines the server printed.
pub fn run_join(state_dir: &Path, host: &str, port: u16, user: &str, command: &str) -> Result<String> {
    ensure!(host_ok(host), "the host must be a host name or an IP address");
    ensure!(user_ok(user), "the user name may hold lowercase letters, digits, _ and -");
    ensure!(port > 0, "the port must be 1 to 65535");
    // The join command is ours (a fixed form with the code); it is passed as one argument to bash.
    ensure!(command.starts_with("s=$(curl ") && !command.contains(['\n', '\r']), "unexpected join command");
    let key = key_path(state_dir);
    ensure!(key.exists(), "the dashboard has no SSH key yet; open Add over SSH first");
    let known = state_dir.join("ssh").join("known_hosts");
    let quoted = format!("'{}'", command.replace('\'', "'\\''"));
    let remote = if user == "root" { format!("bash -c {quoted}") } else { format!("sudo -n bash -c {quoted}") };
    let mut child = Command::new("ssh")
        .arg("-i")
        .arg(&key)
        .args(["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known.display()))
        .args(["-p", &port.to_string(), "-l", user, "--", host, &remote])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("run ssh")?;
    // Both outputs are read while it runs: a full pipe would stop the program before it exits.
    let drain = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            if let Some(mut pipe) = pipe {
                let mut buffer = [0u8; 8192];
                while let Ok(n) = pipe.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    kept.extend_from_slice(&buffer[..n]);
                    // Only the end is shown; keep at most the last 64 KiB.
                    if kept.len() > 128 * 1024 {
                        kept.drain(..kept.len() - 64 * 1024);
                    }
                }
            }
            kept
        })
    };
    let stdout = drain(child.stdout.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>));
    let stderr = drain(child.stderr.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>));
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(300) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("the server did not finish joining within 5 minutes");
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    let (stdout, stderr) = (stdout.join().unwrap_or_default(), stderr.join().unwrap_or_default());
    let output = std::process::Output { status, stdout, stderr };
    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let tail: Vec<&str> = text.lines().rev().take(15).collect::<Vec<_>>().into_iter().rev().collect();
    let tail = tail.join("\n");
    if !output.status.success() {
        if text.contains("Permission denied") {
            bail!("the server refused the dashboard's key; add it to {user}'s ~/.ssh/authorized_keys first");
        }
        if text.contains("sudo") && text.contains("password") {
            bail!("{user} needs passwordless sudo, or use root");
        }
        bail!("joining failed: {tail}");
    }
    Ok(tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_users_cannot_carry_options() {
        for good in ["203.0.113.5", "srv1.example.com", "2001:db8::5"] {
            assert!(host_ok(good), "{good}");
        }
        for bad in ["-oProxyCommand=x", "a b", "host;id", "", "x$(id)"] {
            assert!(!host_ok(bad), "{bad}");
        }
        assert!(user_ok("root") && user_ok("ubuntu") && user_ok("deploy_1"));
        for bad in ["-l", "Root", "a b", "x;id", ""] {
            assert!(!user_ok(bad), "{bad}");
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(run_join(dir.path(), "203.0.113.5", 22, "root", "s=$(curl -fsSL http://x/join.sh) && bash -c \"$s\" join.sh ezj1-x").is_err(), "no key yet");
        assert!(run_join(dir.path(), "203.0.113.5", 22, "root", "rm -rf /").is_err());
    }
}
