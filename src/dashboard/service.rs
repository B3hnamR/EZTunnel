//! The dashboard's own system service: it keeps running after the terminal closes and starts
//! with the server.
use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

pub const UNIT: &str = "eztunnel-dashboard.service";

fn unit_path() -> PathBuf {
    Path::new("/etc/systemd/system").join(UNIT)
}

/// The program the service runs: the installed one when there is one, so an update reaches it.
fn program() -> Result<PathBuf> {
    let installed = Path::new(crate::manager::update::INSTALLED);
    if installed.exists() {
        return Ok(installed.to_path_buf());
    }
    Ok(std::env::current_exe()?.canonicalize()?)
}

pub fn unit_text(program: &Path, state_dir: &Path) -> String {
    format!(
        "[Unit]\nDescription=EZTunnel web dashboard\nAfter=network-online.target\nWants=network-online.target\n\n\
         [Service]\nExecStart=\"{}\" dashboard serve --state-dir \"{}\"\nRestart=always\nRestartSec=5\n\n\
         [Install]\nWantedBy=multi-user.target\n",
        program.display(),
        state_dir.display()
    )
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl").args(args).status().context("run systemctl")?;
    ensure!(status.success(), "systemctl {} failed", args.join(" "));
    Ok(())
}

/// Writes the service, starts it now and at every boot.
pub fn install(state_dir: &Path) -> Result<()> {
    std::fs::write(unit_path(), unit_text(&program()?, state_dir)).context("write the dashboard service")?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", UNIT])
}

pub fn installed() -> bool {
    unit_path().exists()
}

pub fn active(unit: &str) -> bool {
    Command::new("systemctl").args(["is-active", "--quiet", unit]).status().is_ok_and(|s| s.success())
}

pub fn start() -> Result<()> {
    systemctl(&["start", UNIT])
}

pub fn stop() -> Result<()> {
    systemctl(&["stop", UNIT])
}

pub fn restart() -> Result<()> {
    systemctl(&["restart", UNIT])
}

/// Stops the service and removes it. The settings stay unless the caller deletes them.
pub fn remove() {
    let _ = Command::new("systemctl").args(["disable", "--now", "--quiet", UNIT]).status();
    let _ = std::fs::remove_file(unit_path());
    let _ = Command::new("systemctl").arg("daemon-reload").status();
}

/// After a changed setting: restarts a running dashboard so it is used, or says how to start it.
pub fn apply(what: &str) -> Result<()> {
    if active(UNIT) {
        restart()?;
        println!("The dashboard restarted and uses {what} now.");
    } else if installed() {
        println!("The dashboard is stopped; it uses {what} when it starts (systemctl start {UNIT}).");
    } else {
        println!("Run the dashboard to use {what}: eztunnel dashboard serve");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_serves_the_given_state_and_restarts_by_itself() {
        let unit = unit_text(Path::new("/usr/local/bin/eztunnel"), Path::new("/var/lib/eztunnel-dashboard"));
        assert!(unit.contains("ExecStart=\"/usr/local/bin/eztunnel\" dashboard serve --state-dir \"/var/lib/eztunnel-dashboard\"\n"));
        assert!(unit.contains("Restart=always\n"));
        assert!(unit.contains("WantedBy=multi-user.target\n"));
    }
}
