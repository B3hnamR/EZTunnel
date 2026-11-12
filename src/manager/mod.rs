//! The interactive tunnel manager, opened by running `eztunnel` on a terminal.
//!
//! It creates tunnels step by step, writes their configuration, and runs each one as its own
//! systemd service. Everything it writes is an ordinary configuration file that the program
//! checks with the same rules as at start-up.
pub mod backup;
pub mod bulk;
pub mod checker;
pub mod iface;
pub mod manage;
mod mirage;
mod mirage_flow;
mod mirage_screen;
mod setup;
/// Direct entry to the guided flow; other manager screens remain unchanged.
pub fn mirage_tests()->Result<()> {ui::exit_on_interrupt();mirage_flow::menu(&store::Store::open()?)}
pub mod optimize;
pub mod pairing;
pub mod plan;
pub mod rawfw;
pub mod service;
pub mod speed;
pub mod store;
pub mod tune;
pub mod ui;
pub mod update;
pub mod wizard;

use anyhow::{Context, Result};
use store::Store;

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_string())
        .unwrap_or_else(|_| "this server".into())
}

/// The address this server uses towards the internet. No packet is sent: connecting a UDP
/// socket only selects a route.
pub(crate) fn local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn status_line(store: &Store) -> String {
    let names = store.names().unwrap_or_default();
    let running = names
        .iter()
        .filter(|name| service::state(store, name) == service::State::Running)
        .count();
    let mut parts = vec![hostname()];
    parts.extend(local_ip());
    parts.push(match names.len() {
        0 => "no tunnels yet".to_string(),
        1 => format!("1 tunnel, {running} running"),
        n => format!("{n} tunnels, {running} running"),
    });
    parts.join(" · ")
}

pub fn run() -> Result<()> {
    ui::exit_on_interrupt();
    let store = match Store::open() {
        Ok(store) => store,
        Err(error) => {
            ui::fail(&format!("{error:#}"));
            std::process::exit(1);
        }
    };
    loop {
        ui::banner(&status_line(&store));
        if !store.system {
            ui::warn(&format!(
                "Test mode: tunnels are saved in {} and no services are started.",
                store.root().display()
            ));
        } else if std::env::var_os("EZTUNNEL_HOME").is_some() {
            ui::warn(&format!(
                "EZTUNNEL_HOME is set ({}), but you are root on a systemd machine: the tunnels you create here become REAL services.",
                store.root().display()
            ));
        }
        if let Some(note) = running_copy_note() {
            ui::warn(&note);
        }
        let count = store.names()?.len();
        let items = vec![
            format!(
                "{}  {}",
                ui::bold("New tunnel     "),
                ui::dim("set up a tunnel step by step")
            ),
            format!(
                "{}  {}",
                ui::bold("Manage tunnels "),
                ui::dim(&format!("logs, edit, restart, stop or delete ({count})"))
            ),
            format!(
                "{}  {}",
                ui::bold("Tools          "),
                ui::dim("transport checker, tunnel key, link test")
            ),
            format!(
                "{}  {}",
                ui::bold("Uninstall      "),
                ui::dim("remove EZTunnel from this server")
            ),
            ui::dim("Exit").to_string(),
        ];
        let choice = ui::choose("Main menu", &items, if count == 0 { 0 } else { 1 })?;
        let result = match choice {
            Some(0) => wizard::new_tunnel(&store).map(|_| ()),
            Some(1) => manage::manage(&store),
            Some(2) => tools(&store),
            Some(3) => uninstall(&store),
            _ => {
                eprintln!();
                return Ok(());
            }
        };
        if let Err(error) = result {
            if !ui::is_back(&error) {
                ui::fail(&format!("{error:#}"));
                ui::pause();
            }
        }
    }
}

/// Undoes "Optimize this server", then puts back the UDP buffer ceiling the installed KCP/FEC
/// tunnels ask for: the restored value may be lower, and nothing else would raise it again
/// before the next reboot. Returns how many settings were restored.
pub fn undo_optimize() -> Result<usize> {
    let restored = optimize::undo()?;
    if let Ok(store) = Store::open()
        && store.system
        && let Err(error) = service::restore_udp_buffers(&store)
    {
        ui::fail(&format!(
            "Could not raise the UDP buffer limit for the installed tunnels again: {error:#}"
        ));
    }
    Ok(restored)
}

fn optimize_screen() -> Result<()> {
    ui::banner("Optimize this server");
    if !store::is_root() {
        ui::fail("Changing kernel settings needs root: sudo eztunnel");
        ui::pause();
        return Ok(());
    }
    let changes = optimize::plan();
    if changes.is_empty() {
        ui::ok("This server already has the recommended network settings.");
        ui::pause();
        return Ok(());
    }
    ui::note(
        "Recommended for tunnels between distant servers. A numeric limit only changes if it is worse\nthan the recommendation; a named setting (queueing, congestion control) is set outright. The old\nvalues are saved, and Undo restores them.",
    );
    eprintln!();
    let lines: Vec<String> = changes
        .iter()
        .flat_map(|c| {
            [
                format!(
                    "{}  {} → {}",
                    ui::bold(&c.key),
                    ui::dim(&c.current),
                    ui::accent(&c.wanted)
                ),
                format!("   {}", ui::dim(&c.why)),
            ]
        })
        .collect();
    ui::boxed(&format!("{} change(s)", changes.len()), &lines);
    eprintln!();
    if !ui::confirm("Apply them now? They stay after a reboot.", true)? {
        return Ok(());
    }
    let failed = optimize::apply(&changes)?;
    if failed.is_empty() {
        ui::ok("Applied. Running tunnels use the new settings for new connections.");
    } else {
        ui::warn(&format!(
            "Applied, except: {} (this system does not allow changing them)",
            failed.join(", ")
        ));
    }
    ui::pause();
    Ok(())
}

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
enum ToolAction{Checker,Optimize,Undo,Key,CheckConfigs,Export,Import,Update,Rollback,LinkTest,Mirage}
const TOOLS:[ToolAction;11]=[ToolAction::Checker,ToolAction::Optimize,ToolAction::Undo,ToolAction::Key,ToolAction::CheckConfigs,ToolAction::Export,ToolAction::Import,ToolAction::Update,ToolAction::Rollback,ToolAction::LinkTest,ToolAction::Mirage];
fn tool_label(action:ToolAction)->String{
    use console::style;
    let(category,title,description,color)=match action{
        ToolAction::Checker=>("TEST","Transport checker","compare transports between servers",6),
        ToolAction::Mirage=>("TEST","Mirage source tests","find working spoof IPs and create a tunnel",6),
        ToolAction::LinkTest=>("TEST","Link test","listen or probe TCP, UDP and MTU",6),
        ToolAction::Optimize=>("NETWORK","Optimize this server",if optimize::applied(){"BBR and tuning (applied)"}else{"BBR and network tuning"},2),
        ToolAction::Undo=>("NETWORK","Undo the server optimization","restore previous network settings",2),
        ToolAction::Key=>("KEYS","Create a tunnel key","generate a private shared tunnel key",5),
        ToolAction::CheckConfigs=>("FILES","Check every tunnel's configuration","validate saved files without starting",4),
        ToolAction::Export=>("FILES","Export all tunnels to a file (backup)","private configuration backup",4),
        ToolAction::Import=>("FILES","Import tunnels from a file","restore a private backup",4),
        ToolAction::Update=>("RELEASE","Update EZTunnel from a downloaded file","verify and install an official release",3),
        ToolAction::Rollback=>("RELEASE","Roll back to the previous version","restore the recorded previous release",3),
    };
    format!("{} {}  {}",style(format!("[{category:<7}]")).for_stderr().color256(color).bold(),title,ui::dim(description))
}
fn link_test_menu()->Result<()> {
    let choices=["Wait for the other server  listen for its probes","Test the link to the other server  send probes","Back"].map(str::to_string);
    match ui::choose("Link test",&choices,0)?{Some(0)=>link_test(true),Some(1)=>link_test(false),_=>Ok(())}
}
fn tools(store: &Store) -> Result<()> {
    loop {
        ui::banner("Tools");
        let mut items=TOOLS.iter().copied().map(tool_label).collect::<Vec<_>>();items.push(ui::dim("← Back"));
        let Some(action)=ui::choose("Tool",&items,0)?.and_then(|index|TOOLS.get(index).copied())else{return Ok(());};
        let result = (|| -> Result<()> {
            match action {
                ToolAction::Checker => checker::menu(store)?,
                ToolAction::Optimize => optimize_screen()?,
                ToolAction::Undo => {
                    if ui::confirm(
                        "Restore the network settings from before the optimization?",
                        false,
                    )? {
                        let restored = undo_optimize()?;
                        ui::ok(&format!(
                            "Restored {restored} setting(s); the optimization is removed."
                        ));
                    }
                    ui::pause();
                }
                ToolAction::Key => {
                    {
                        let key = crate::tunnel_key::TunnelKey::generate()?.display();
                        ui::boxed("New tunnel key", &[ui::accent(&key)]);
                        ui::note("Use it when creating a tunnel on both servers.");
                    }
                    ui::pause();
                }
                ToolAction::CheckConfigs => {
                    let names = store.names()?;
                    if names.is_empty() {
                        ui::info("There are no saved tunnel configurations to check.");
                    }
                    for name in names {
                        match store::check_file(&store.path(&name)) {
                            Ok(_) => ui::ok(&name),
                            Err(error) => ui::fail(&format!("{name}: {error:#}")),
                        }
                    }
                    ui::pause();
                }
                ToolAction::Export => export_screen(store)?,
                ToolAction::Import => import_screen(store)?,
                ToolAction::Update => update::update_screen()?,
                ToolAction::Rollback => update::rollback_screen()?,
                ToolAction::LinkTest => link_test_menu()?,
                ToolAction::Mirage => mirage::tester(store)?,
            }
            Ok(())
        })();
        if let Err(error) = result {
            if !ui::is_back(&error) {
                ui::fail(&format!("{error:#}"));
                ui::pause();
            }
        }
    }
}

fn export_screen(store: &Store) -> Result<()> {
    ui::banner("Export all tunnels");
    let count = store.names()?.len();
    if count == 0 {
        ui::info("There are no tunnels to export.");
        ui::pause();
        return Ok(());
    }
    ui::note(&format!(
        "Saves the configuration of all {count} tunnel(s) in one file. The file contains the
secret tunnel keys: keep it private. It is readable by its owner only."
    ));
    let default = "/root/eztunnel-tunnels.json";
    let path = ui::form(|| {
        let path = ui::ask("File to write", Some(default), |t: &String| {
            if t.trim().is_empty() {
                Err("enter a file path".to_string())
            } else {
                Ok(())
            }
        })?;
        let path = std::path::PathBuf::from(path.trim());
        if path.exists() && !ui::confirm(&format!("{} exists. Replace it?", path.display()), false)?
        {
            return Err(ui::Back.into());
        }
        Ok(path)
    })?;
    let (written, skipped) = backup::write_export(store, &path)?;
    ui::ok(&format!("Saved {written} tunnel(s) to {}", path.display()));
    if !skipped.is_empty() {
        ui::warn(&format!(
            "Could not read and so left out of the backup: {}",
            skipped.join(", ")
        ));
    }
    ui::note("Import it on another server with Tools → Import tunnels from a file.");
    ui::pause();
    Ok(())
}

fn import_screen(store: &Store) -> Result<()> {
    ui::banner("Import tunnels");
    ui::note(
        "Reads a file made by 'Export all tunnels'. Every tunnel is checked before it is saved.",
    );
    let path = ui::ask("File to read", None, |t: &String| {
        if t.trim().is_empty() {
            Err("enter a file path".to_string())
        } else {
            Ok(())
        }
    })?;
    let text =
        std::fs::read_to_string(path.trim()).with_context(|| format!("read {}", path.trim()))?;
    let tunnels = backup::parse_export(&text)?;
    if tunnels.iter().any(|(_, value)| {
        ["listeners", "paths"].iter().any(|key| {
            value[*key]
                .as_array()
                .is_some_and(|entries| entries.iter().any(|entry| entry["transport"] == "mirage"))
        })
    }) && !mirage::consent()?
    {
        return Ok(());
    }
    let existing: Vec<&str> = tunnels
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| store.exists(name))
        .collect();
    ui::info(&format!(
        "The file holds {} tunnel(s): {}",
        tunnels.len(),
        tunnels
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let replace = if existing.is_empty() {
        false
    } else {
        ui::warn(&format!("Already on this server: {}", existing.join(", ")));
        ui::confirm("Replace those with the versions from the file?", false)?
    };
    let report = backup::import(store, &tunnels, replace);
    for name in &report.imported {
        ui::ok(&format!("Imported {name}"));
    }
    for name in &report.skipped {
        ui::note(&format!("Kept the existing {name}"));
    }
    for (name, error) in &report.failed {
        ui::fail(&format!("{name}: {error}"));
    }
    if store.system
        && !report.imported.is_empty()
        && ui::confirm("Start the imported tunnels now?", true)?
    {
        for name in &report.imported {
            match service::install(store, name) {
                Ok(()) => ui::ok(&format!("Started {name}")),
                Err(error) => ui::fail(&format!("{name}: {error:#}")),
            }
        }
        ui::note(
            "Raw TCP firewall rules are not part of the export: turn them on again from each tunnel's menu.",
        );
    }
    ui::pause();
    Ok(())
}

/// A warning when the program that runs the manager is not the installed one: the services it
/// creates or restarts run this very file.
fn running_copy_note() -> Option<String> {
    let installed = std::path::Path::new(update::INSTALLED);
    let running = std::env::current_exe().ok()?.canonicalize().ok()?;
    let installed = installed.canonicalize().ok()?;
    (running != installed).then(|| {
        format!(
            "This copy ({}) is not the installed program ({}). Services you create or restart now run THIS file; move it to the installed place first (Tools → Update) or run: sudo eztunnel",
            running.display(),
            installed.display()
        )
    })
}

/// Runs the link tester as a separate program, so Ctrl-C only stops the test.
fn link_test(listen: bool) -> Result<()> {
    let arguments = ui::form(|| link_test_arguments(listen))?;
    let binary = std::env::current_exe()?;
    let mut command = std::process::Command::new(binary);
    command.arg("linktest");
    command.args(arguments);
    ui::note("Press Ctrl+C to stop and return.");
    let status = ui::with_interrupt_for_children(|| command.status()).context("start link test")?;
    check_link_exit(status)?;
    ui::pause();
    Ok(())
}

fn link_test_arguments(listen: bool) -> Result<Vec<String>> {
    if listen {
        ui::note("Start this first, then run the test on the other server.");
        let peer =
            ui::ask("IP address of the other server", None, |t: &String| match t
                .parse::<std::net::IpAddr>()
            {
                Ok(ip) if !ip.is_unspecified() && !ip.is_multicast() => Ok(()),
                _ => Err("enter the other server's unicast IP address".to_string()),
            })?;
        let port = ui::ask("Port to listen on", Some("47000"), |t: &String| {
            match t.parse::<u16>() {
                Ok(port) if port > 0 => Ok(()),
                _ => Err("enter a port from 1 to 65535".to_string()),
            }
        })?;
        // The listener must be of the same address family as the peer.
        let any = if peer
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_ipv6())
        {
            format!("[::]:{port}")
        } else {
            format!("0.0.0.0:{port}")
        };
        Ok(vec![
            "listen".into(),
            "--bind".into(),
            any,
            "--peer".into(),
            peer,
        ])
    } else {
        ui::note("The other server must be waiting (Tools → Link test: wait).");
        let peer = ui::ask("Other server as IP:port", None, |t: &String| match t
            .parse::<std::net::SocketAddr>()
        {
            Ok(peer)
                if peer.port() > 0 && !peer.ip().is_unspecified() && !peer.ip().is_multicast() =>
            {
                Ok(())
            }
            _ => Err("enter a unicast IP:port with port 1..65535".to_string()),
        })?;
        Ok(vec![
            "probe".into(),
            "--peer".into(),
            peer,
            "--quick".into(),
            "--text".into(),
        ])
    }
}

fn check_link_exit(status: std::process::ExitStatus) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if status.signal() == Some(libc::SIGINT) {
            return Ok(());
        }
    }
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "link test did not complete successfully ({status}); check connectivity and the peer listener"
        )
    }
}

#[cfg(all(test, unix))]
#[test]
fn link_test_failures_are_not_silently_reported_as_success() {
    use std::os::unix::process::ExitStatusExt;
    assert!(check_link_exit(std::process::ExitStatus::from_raw(0)).is_ok());
    assert!(check_link_exit(std::process::ExitStatus::from_raw(256)).is_err());
    assert!(check_link_exit(std::process::ExitStatus::from_raw(libc::SIGINT)).is_ok());
    assert!(check_link_exit(std::process::ExitStatus::from_raw(libc::SIGKILL)).is_err());
}

/// Removes the program, the setup helper next to it and the manager's sysctl file. The raised
/// UDP buffer ceiling itself stays until the next reboot.
fn remove_program_files(binary: &std::path::Path, buffer_sysctl: &std::path::Path) -> Result<()> {
    let _ = std::fs::remove_file(buffer_sysctl);
    if let Some(dir) = binary.parent() {
        let _ = std::fs::remove_file(dir.join("eztunnel-setup"));
    }
    std::fs::remove_file(binary)?;
    Ok(())
}

fn uninstall(store: &Store) -> Result<()> {
    ui::banner("Uninstall");
    let names = store.names()?;
    ui::warn(&format!(
        "This stops and removes {} tunnel service(s) and the eztunnel program.",
        names.len()
    ));
    if !ui::confirm("Uninstall EZTunnel from this server?", false)? {
        return Ok(());
    }
    // Without the program there is no Undo, and the saved original values live in the config
    // directory, so offer to restore them now.
    if optimize::applied() {
        if ui::confirm(
            "Also undo \"Optimize this server\" (restore the previous network settings)?",
            true,
        )? {
            match optimize::undo() {
                Ok(restored) => ui::ok(&format!(
                    "Restored {restored} network setting(s); the optimization is removed."
                )),
                Err(error) => {
                    ui::fail(&format!("Could not undo the optimization: {error:#}"));
                    // The saved original values live in the config directory that is deleted
                    // below; without them the settings can no longer be restored.
                    if !ui::confirm(
                        "Continue the uninstall anyway? (the saved values may be lost)",
                        false,
                    )? {
                        return Ok(());
                    }
                }
            }
        } else {
            ui::note(&format!(
                "The network settings stay. Delete {} to stop applying them at boot.",
                optimize::SYSCTL_FILE
            ));
        }
    }
    let keep = ui::confirm(
        &format!("Keep the tunnel configs in {}?", store.root().display()),
        true,
    )?;
    let mut every_service_removed = true;
    if store.system {
        for name in &names {
            match service::remove(name) {
                Ok(()) => ui::ok(&format!("Removed service {}", service::unit_name(name))),
                Err(error) => {
                    ui::fail(&format!("{name}: {error:#}"));
                    every_service_removed = false;
                }
            }
        }
    }
    if !keep {
        if !every_service_removed {
            ui::warn(&format!(
                "Not deleting {}: a service above could not be removed and may still be running without a unit.",
                store.root().display()
            ));
        } else {
            std::fs::remove_dir_all(store.root())?;
            ui::ok(&format!("Deleted {}", store.root().display()));
            if store.system && store::user_exists(store::SERVICE_USER) {
                let removed = std::process::Command::new("userdel")
                    .arg(store::SERVICE_USER)
                    .status()
                    .is_ok_and(|status| status.success());
                if removed {
                    ui::ok(&format!("Removed the {} account", store::SERVICE_USER));
                }
            }
        }
    }
    // The installed program has a fixed path on a real install; the file that happens to be
    // running (Tools → Uninstall run from a downloaded copy) may not be it.
    let binary = if store.is_system_install() {
        std::path::PathBuf::from(update::INSTALLED)
    } else {
        std::env::current_exe()?
    };
    if store.is_system_install() {
        remove_program_files(&binary, std::path::Path::new(service::BUFFER_SYSCTL_FILE))?;
        ui::ok(&format!("Removed {}", binary.display()));
    } else {
        // A test directory (EZTUNNEL_HOME) must not take the running program, or the real
        // system buffer file, with it.
        ui::note("Test directory: the program and the system buffer file were left in place.");
    }
    ui::ok("EZTunnel is uninstalled.");
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_have_one_stable_route_per_action_and_one_combined_link_test(){
        let mut seen=std::collections::HashSet::new();
        for action in TOOLS{assert!(seen.insert(format!("{action:?}")));let label=tool_label(action);assert!(!console::strip_ansi_codes(&label).is_empty());}
        assert_eq!(TOOLS.iter().filter(|action|**action==ToolAction::LinkTest).count(),1);
        assert_eq!(TOOLS.len(),11);
    }

    #[test]
    fn uninstalling_removes_the_program_its_helper_and_the_buffer_file() {
        let directory = tempfile::tempdir().unwrap();
        let (binary, helper, sysctl, other) = (
            directory.path().join("eztunnel"),
            directory.path().join("eztunnel-setup"),
            directory.path().join("60-eztunnel.conf"),
            directory.path().join("keep-me"),
        );
        for file in [&binary, &helper, &sysctl, &other] {
            std::fs::write(file, "x").unwrap();
        }
        remove_program_files(&binary, &sysctl).unwrap();
        assert!(!binary.exists() && !helper.exists() && !sysctl.exists());
        assert!(other.exists(), "unrelated files stay");
        // Nothing left to remove is an error for the program itself, never for the helpers.
        assert!(remove_program_files(&binary, &sysctl).is_err());
    }
}
