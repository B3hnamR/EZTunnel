//! Tools → Web dashboard: set up the optional browser dashboard on this server, run and manage
//! it, or join this server to a dashboard on another server.
#[cfg(not(feature = "dashboard"))]
use super::ui;

#[cfg(not(feature = "dashboard"))]
pub(super) fn screen() -> anyhow::Result<()> {
    ui::banner("Web dashboard");
    ui::info("This build of EZTunnel has no web dashboard (it was built without the dashboard feature).");
    ui::pause();
    Ok(())
}

#[cfg(not(feature = "dashboard"))]
pub(super) fn on_uninstall() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(feature = "dashboard")]
pub(super) use with_dashboard::{on_uninstall, screen};

#[cfg(feature = "dashboard")]
mod with_dashboard {
    use crate::manager::ui;
    use crate::dashboard::{self, Summary};
    use anyhow::{Context, Result};
    use std::path::Path;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Step {
        SetUp,
        Reinstall,
        Start,
        Stop,
        Restart,
        Password,
        Port,
        LetsEncrypt,
        SelfSigned,
        Log,
        Remove,
        Join,
        AgentRestart,
        Leave,
    }

    fn state_dir() -> &'static Path {
        Path::new(dashboard::DEFAULT_STATE_DIR)
    }

    /// The steps that fit the state of this server, in the order shown.
    fn steps(s: &Summary) -> Vec<(Step, &'static str)> {
        let mut steps = Vec::new();
        if !s.set_up {
            steps.push((Step::SetUp, "Set up the web dashboard on this server"));
        } else if !s.service_installed {
            steps.push((Step::Reinstall, "Run the dashboard again with its earlier settings"));
        } else {
            if s.running {
                steps.push((Step::Restart, "Restart the dashboard"));
                steps.push((Step::Stop, "Stop the dashboard"));
            } else {
                steps.push((Step::Start, "Start the dashboard"));
            }
            steps.push((Step::Password, "Reset the password (signs every browser out)"));
            steps.push((Step::Port, "Change the port"));
            steps.push((Step::LetsEncrypt, "Use a Let's Encrypt certificate (no browser warning)"));
            if s.certificate != "self-signed" {
                steps.push((Step::SelfSigned, "Go back to the self-signed certificate"));
            }
            steps.push((Step::Log, "Show the dashboard's recent log"));
        }
        if s.set_up {
            steps.push((Step::Remove, "Remove the dashboard from this server"));
        }
        match (&s.joined_to, s.set_up) {
            (Some(_), _) => {
                steps.push((Step::AgentRestart, "Restart the agent"));
                steps.push((Step::Leave, "Leave the dashboard (tunnels keep running)"));
            }
            (None, false) => steps.push((Step::Join, "Join this server to a dashboard on another server")),
            (None, true) => {}
        }
        steps
    }

    fn show(s: &Summary) {
        if s.set_up {
            let state = match (s.service_installed, s.running) {
                (_, true) => "running".to_string(),
                (true, false) => "stopped".to_string(),
                (false, false) => "removed (its settings are kept)".to_string(),
            };
            ui::info(&format!("Dashboard: {state}"));
            ui::info(&format!("Address: {}", ui::accent(&s.url)));
            ui::info(&format!("Certificate: {}", s.certificate));
        } else {
            ui::info("Dashboard: not set up on this server");
            ui::note(
                "The web dashboard is optional. It runs on one server (usually the Iran server), shows every
tunnel live and lets you create, edit, start and stop tunnels on all your servers from a browser.",
            );
        }
        match &s.joined_to {
            Some(hub) => ui::info(&format!(
                "Agent: joined to the dashboard at {hub} ({})",
                if s.agent_running { "running" } else { "stopped" }
            )),
            None if !s.set_up => ui::note("Agent: not joined. To manage this server from a dashboard elsewhere, join it with the code that dashboard shows."),
            None => {}
        }
        eprintln!();
    }

    pub fn screen() -> Result<()> {
        loop {
            ui::banner("Web dashboard");
            let summary = dashboard::summary(state_dir());
            show(&summary);
            let steps = steps(&summary);
            let mut items: Vec<String> = steps.iter().map(|(_, label)| label.to_string()).collect();
            items.push(ui::dim("← Back"));
            let Some(step) = ui::choose("Web dashboard", &items, 0)?.and_then(|i| steps.get(i).map(|(s, _)| *s)) else {
                return Ok(());
            };
            if let Err(error) = run(step, &summary) {
                if ui::is_back(&error) {
                    continue;
                }
                ui::fail(&format!("{error:#}"));
            }
            ui::pause();
        }
    }

    /// Part of uninstalling EZTunnel: removes the dashboard's service (its data only if asked) and
    /// leaves the dashboard this server is joined to.
    pub fn on_uninstall() -> Result<()> {
        let s = dashboard::summary(state_dir());
        if s.set_up || s.service_installed {
            let delete = ui::confirm("Also delete the web dashboard's settings, history and backups?", false)?;
            dashboard::remove(state_dir(), delete)?;
        }
        if s.joined_to.is_some() {
            dashboard::agent_leave()?;
        }
        Ok(())
    }

    /// Runs this program with `args`, on the terminal, for the steps that talk to the network.
    fn run_self(args: &[&str]) -> Result<()> {
        let program = std::env::current_exe()?;
        let status = ui::with_interrupt_for_children(|| std::process::Command::new(program).args(args).status())
            .context("start eztunnel")?;
        anyhow::ensure!(status.success(), "it did not finish (see above)");
        Ok(())
    }

    fn ask_port() -> Result<u16> {
        let text = ui::ask("Port (1024 to 65535)", None, |text: &String| match text.trim().parse::<u16>() {
            Ok(port) if port >= 1024 && crate::manager::service::port_busy(port, "tcp") => {
                Err(format!("port {port} is already in use on this server; choose another"))
            }
            Ok(port) if port >= 1024 => Ok(()),
            _ => Err("enter a port from 1024 to 65535".to_string()),
        })?;
        Ok(text.trim().parse()?)
    }

    fn run(step: Step, s: &Summary) -> Result<()> {
        match step {
            Step::SetUp => {
                let choices = ["A random port (recommended: harder to find)", "A port I choose"].map(str::to_string);
                let port = match ui::choose_required("Which port should the dashboard use?", &choices, 0)? {
                    0 => None,
                    _ => Some(ask_port()?),
                };
                dashboard::setup(state_dir(), port, true)?;
                ui::note(
                    "Open the address in a browser and sign in with the password above. The browser warns once
about the self-signed certificate; a Let's Encrypt certificate (on this screen) removes the warning.
Add your other servers on the dashboard's Servers page.",
                );
            }
            Step::Reinstall => dashboard::setup(state_dir(), None, true)?,
            Step::Start => {
                dashboard::service_start()?;
                ui::ok("The dashboard runs.");
            }
            Step::Stop => {
                if ui::confirm("Stop the dashboard? Tunnels keep running; it starts again at the next boot.", true)? {
                    dashboard::service_stop()?;
                    ui::ok("The dashboard is stopped.");
                }
            }
            Step::Restart => {
                dashboard::service_restart()?;
                ui::ok("The dashboard restarted.");
            }
            Step::Password => {
                if ui::confirm("Make a new random password? The old one stops working.", true)? {
                    dashboard::reset_password(state_dir())?;
                }
            }
            Step::Port => dashboard::set_port(state_dir(), ask_port()?)?,
            Step::LetsEncrypt => {
                ui::note(
                    "Let's Encrypt checks this server over port 80 for about a minute: it must be free and open.
The certificate names an IP address or a domain that points to this server, and renews by itself.",
                );
                let current = s.url.trim_start_matches("https://").rsplit_once(':').map(|(host, _)| host.trim_matches(['[', ']']).to_string());
                let address = ui::ask("Address for the certificate (IP or domain)", current.as_deref(), |text: &String| {
                    if text.trim().is_empty() { Err("enter an address".to_string()) } else { Ok(()) }
                })?;
                run_self(&["dashboard", "certificate", "--lets-encrypt", "--address", address.trim()])?;
            }
            Step::SelfSigned => run_self(&["dashboard", "certificate", "--self-signed"])?,
            Step::Log => {
                let _ = std::process::Command::new("journalctl")
                    .args(["-u", dashboard::DASHBOARD_UNIT, "-n", "40", "--no-pager", "-o", "short-iso"])
                    .status();
            }
            Step::Remove => {
                if !ui::confirm("Remove the dashboard from this server? Tunnels keep running.", false)? {
                    return Ok(());
                }
                let delete = ui::confirm(
                    "Also delete its settings, history and backups? (No keeps them for a later setup.)",
                    false,
                )?;
                dashboard::remove(state_dir(), delete)?;
            }
            Step::Join => {
                ui::note("On the dashboard, open Servers → Add a server and copy the join code (ezj1-…).");
                let code = ui::ask("Join code", None, |text: &String| {
                    if text.trim().starts_with("ezj1-") { Ok(()) } else { Err("a join code starts with ezj1-".to_string()) }
                })?;
                run_self(&["agent", "join", code.trim()])?;
            }
            Step::AgentRestart => {
                dashboard::agent_restart()?;
                ui::ok("The agent restarted.");
            }
            Step::Leave => {
                if ui::confirm("Leave the dashboard? It stops managing this server; tunnels keep running.", false)? {
                    dashboard::agent_leave()?;
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn summary(set_up: bool, service: bool, running: bool, joined: bool) -> Summary {
            Summary {
                set_up,
                service_installed: service,
                running,
                url: "https://203.0.113.10:40000".into(),
                certificate: "self-signed".into(),
                joined_to: joined.then(|| "198.51.100.20:40000".to_string()),
                agent_running: joined,
            }
        }

        #[test]
        fn each_state_offers_only_the_steps_that_fit_it() {
            let only = |s: &Summary| steps(s).into_iter().map(|(step, _)| step).collect::<Vec<_>>();
            assert_eq!(only(&summary(false, false, false, false)), [Step::SetUp, Step::Join]);
            assert_eq!(only(&summary(false, false, false, true)), [Step::SetUp, Step::AgentRestart, Step::Leave]);
            assert_eq!(only(&summary(true, false, false, false)), [Step::Reinstall, Step::Remove]);
            let running = only(&summary(true, true, true, false));
            assert_eq!(running[..2], [Step::Restart, Step::Stop]);
            assert!(running.contains(&Step::Password) && running.contains(&Step::Port) && running.contains(&Step::LetsEncrypt));
            assert!(!running.contains(&Step::SelfSigned) && !running.contains(&Step::Join));
            assert_eq!(only(&summary(true, true, false, false))[0], Step::Start);
        }
    }
}
