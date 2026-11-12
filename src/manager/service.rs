//! systemd services, logs and the firewall for managed tunnels.
use super::store::Store;
use super::store::{SERVICE_USER, user_exists};
use crate::config::{Config, MapKind, Mode};
use anyhow::{Context, Result, ensure};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

pub fn unit_name(name: &str) -> String {
    format!("eztunnel-{name}.service")
}

fn unit_path(name: &str) -> String {
    format!("/etc/systemd/system/{}", unit_name(name))
}

/// Writes a unit (or drop-in) file so a crash mid-write cannot leave it truncated: writes a
/// temporary file in the same directory, then renames it into place, atomic on one filesystem.
pub(super) fn write_unit(path: impl AsRef<Path>, contents: &str) -> Result<()> {
    let path = path.as_ref();
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    std::fs::write(&temp, contents).with_context(|| format!("write {}", temp.display()))?;
    std::fs::rename(&temp, path).with_context(|| format!("replace {}", path.display()))
}

/// Linux privileges a tunnel needs beyond an ordinary account.
fn privileges(config: &Config) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut capabilities = Vec::new();
    let mut families = vec!["AF_INET", "AF_INET6", "AF_UNIX"];
    if config.tun.is_some() {
        capabilities.push("CAP_NET_ADMIN");
        families.push("AF_NETLINK");
    }
    let raw = config
        .listeners
        .iter()
        .map(|l| l.raw.is_some())
        .chain(config.paths.iter().map(|p| p.raw.is_some()))
        .any(|raw| raw);
    if raw {
        capabilities.push("CAP_NET_RAW");
        families.push("AF_PACKET");
        if !families.contains(&"AF_NETLINK") {
            families.push("AF_NETLINK");
        }
    }
    let mut binds: Vec<&str> = Vec::new();
    if config.mode == Mode::Server {
        binds.extend(config.socks5.as_deref());
        for listener in &config.listeners {
            binds.extend(listener.maps.iter().map(|map| map.bind.as_str()));
            if !config.server_dials && listener.raw.is_none() {
                binds.push(&listener.addr);
            }
        }
    } else if config.server_dials {
        binds.extend(config.paths.iter().map(|path| path.addr.as_str()));
    }
    if binds.iter().any(|bind| {
        bind.parse::<SocketAddr>()
            .is_ok_and(|addr| (1..1024).contains(&addr.port()))
    }) {
        capabilities.push("CAP_NET_BIND_SERVICE");
    }
    (capabilities, families)
}

/// The unit file for one tunnel, written for the program this build installs.
pub fn unit_text(name: &str, binary: &Path, config_path: &Path, config: &Config) -> String {
    unit_text_with(
        name,
        binary,
        config_path,
        config,
        false,
    )
}

/// Generate the isolated service unit; execution never requires a launcher.
pub fn unit_text_with(
    name: &str,
    binary: &Path,
    config_path: &Path,
    config: &Config,
    launch: bool,
) -> String {
    let (capabilities, families) = privileges(config);
    let capability_lines = if capabilities.is_empty() {
        String::new()
    } else {
        let list = capabilities.join(" ");
        format!("AmbientCapabilities={list}\nCapabilityBoundingSet={list}\n")
    };
    let (user_line, launch_mode) = unit_user_and_launch(launch);
    let open_files = config.max_open_files.unwrap_or(1_048_576);
    // The read-only service filesystem gets a writable exception only for quota state.
    let mut state_directories: Vec<String> = Vec::new();
    if config.quota.enabled() {
        state_directories.push(format!("eztunnel-{name}"));
    }
    let state_line = if state_directories.is_empty() {
        String::new()
    } else {
        format!(
            "StateDirectory={}\nStateDirectoryMode=0700\n",
            state_directories.join(" ")
        )
    };
    let quota_line = if config.quota.enabled() {
        format!(
            "Environment=EZTUNNEL_QUOTA_FILE={}\n",
            crate::quota::service_state_path(name).display()
        )
    } else {
        String::new()
    };
    let runtime_extra = "";
    let write_paths = String::new();
    format!(
        "[Unit]
Description=EZTunnel tunnel {name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
{user_line}ExecStart=\"{binary}\" {launch_mode}\"{config}\"
Restart=always
RestartSec=3
TimeoutStopSec=10
UMask=0077
LimitNOFILE={open_files}
LimitCORE=0
Environment=RUST_LOG=info
Environment=EZTUNNEL_CONTROL=/run/eztunnel-{name}/control.sock
RuntimeDirectory=eztunnel-{name}{runtime_extra}
RuntimeDirectoryMode=0700
{state_line}{quota_line}{write_paths}NoNewPrivileges=true
{capability_lines}PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
RestrictAddressFamilies={families}

[Install]
WantedBy=multi-user.target
",
        user_line = user_line,
        launch_mode = launch_mode,
        binary = binary.display(),
        config = config_path.display(),
        families = families.join(" "),
        write_paths = write_paths,
    )
}

/// Direct startup under the dedicated account, with only carrier-required capabilities.
fn unit_user_and_launch(launch: bool) -> (&'static str, &'static str) {
    let _ = launch;
    ("User=eztunnel\n", "--config ")
}

pub(super) fn systemctl(arguments: &[&str]) -> Result<()> {
    let output = Command::new("systemctl")
        .args(arguments)
        .output()
        .context("run systemctl")?;
    ensure!(
        output.status.success(),
        "systemctl {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn ensure_service_user(store: &Store) -> Result<()> {
    if !user_exists(SERVICE_USER) {
        let status = Command::new("useradd")
            .args([
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
            ])
            .arg("--home-dir")
            .arg(store.root())
            .arg(SERVICE_USER)
            .status()
            .context("create the service account")?;
        ensure!(status.success(), "useradd {SERVICE_USER} failed");
    }
    Ok(())
}

/// Creates or updates the service of a saved tunnel and (re)starts it.
pub fn install(store: &Store, name: &str) -> Result<()> {
    let binary = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .context("locate the eztunnel program")?;
    install_with(store, name, &binary)
}

/// Like `install`, for a service that runs the program at `binary` (an update installs the new
/// program under the usual path before the services are written again).
pub fn install_with(store: &Store, name: &str, binary: &Path) -> Result<()> {
    ensure!(store.system, "systemd is not available on this machine");
    ensure_service_user(store)?;
    let path = store.path(name);
    store.give_to_service(&path);
    let config = super::store::check_file(&path)?;
    if let Err(error) = allow_udp_buffers(&config) {
        tracing::debug!(%error, "could not raise the UDP buffer limit");
    }
    let binary = binary.to_path_buf();
    {
        // Verify that the service account can read all referenced configuration files.
        let status = Command::new("runuser")
            .args(["-u", SERVICE_USER, "--"])
            .arg(&binary)
            .arg("--config")
            .arg(&path)
            .arg("--check")
            .stdout(Stdio::null())
            .status();
        if let Ok(status) = status {
            ensure!(
                status.success(),
                "the service account cannot read the configuration"
            );
        }
    }
    let launch = false;
    write_unit(
        unit_path(name),
        &unit_text_with(name, &binary, &path, &config, launch),
    )
    .context("write the service unit")?;
    systemctl(&["daemon-reload"])?;
    // Raw TCP firewall rules (if switched on) follow the tunnel's current ports.
    if let Err(error) = super::rawfw::refresh(name, &config) {
        super::ui::warn(&format!("Could not update the firewall rules: {error:#}"));
    }
    systemctl(&["enable", "--quiet", &unit_name(name)])?;
    systemctl(&["restart", &unit_name(name)])
}

fn debug_drop_in(name: &str) -> String {
    format!("/etc/systemd/system/{}.d/debug.conf", unit_name(name))
}

/// Whether the tunnel logs at debug level (a systemd drop-in next to its unit).
pub fn debug_logging(name: &str) -> bool {
    Path::new(&debug_drop_in(name)).exists()
}

/// Switches debug logging on or off and restarts the tunnel.
pub fn set_debug_logging(name: &str, on: bool) -> Result<()> {
    let file = debug_drop_in(name);
    if on {
        let dir = Path::new(&file).parent().context("drop-in directory")?;
        std::fs::create_dir_all(dir).context("create the drop-in directory")?;
        write_unit(&file, "[Service]\nEnvironment=RUST_LOG=debug\n")
            .context("write the drop-in")?;
    } else {
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("remove the drop-in"),
        }
        if let Some(dir) = Path::new(&file).parent() {
            let _ = std::fs::remove_dir(dir);
        }
    }
    systemctl(&["daemon-reload"])?;
    restart(name)
}

/// The UDP socket buffer a tunnel asks for (KCP and FEC carriers), if any.
pub fn udp_buffer_wanted(config: &Config) -> Option<usize> {
    use crate::config::Transport;
    let wanted = |transport: Transport, kcp: usize, fec: usize| match transport {
        Transport::Kcp => Some(kcp),
        Transport::FecUdp | Transport::FecRaw | Transport::FecRawGaming | Transport::Mirage => {
            Some(fec)
        }
        _ => None,
    };
    config
        .listeners
        .iter()
        .filter_map(|l| wanted(l.transport, l.kcp.socket_buf_bytes, l.fec.socket_buf_bytes))
        .chain(
            config.paths.iter().filter_map(|p| {
                wanted(p.transport, p.kcp.socket_buf_bytes, p.fec.socket_buf_bytes)
            }),
        )
        .max()
}

/// Kernel buffer limits for KCP/FEC tunnels. Sorts before the optimizer's file, which may set more.
pub const BUFFER_SYSCTL_FILE: &str = "/etc/sysctl.d/60-eztunnel.conf";

/// Linux silently caps socket buffers at `net.core.rmem_max` / `wmem_max` (often 208 KB),
/// which halves FEC and KCP speed on long links. When a tunnel asks for more, raise those
/// maximums (only the allowed ceiling; other programs keep their defaults) and keep the
/// change in a sysctl file so it survives a reboot.
fn allow_udp_buffers(config: &Config) -> Result<()> {
    match udp_buffer_wanted(config) {
        Some(wanted) => raise_udp_buffer_limit(wanted),
        None => Ok(()),
    }
}

/// The largest UDP socket buffer any of these tunnels asks for.
fn largest_udp_buffer<'a>(configs: impl IntoIterator<Item = &'a Config>) -> Option<usize> {
    configs.into_iter().filter_map(udp_buffer_wanted).max()
}

/// Puts the UDP buffer ceiling back for the installed tunnels. "Undo Optimize" restores the
/// ceiling the machine had before, which may be below what a KCP/FEC tunnel asks for, and
/// nothing else would raise it again until the next reboot.
pub fn restore_udp_buffers(store: &Store) -> Result<()> {
    let configs: Vec<Config> = store
        .names()?
        .iter()
        .filter_map(|name| super::store::check_file(&store.path(name)).ok())
        .collect();
    match largest_udp_buffer(&configs) {
        Some(wanted) => raise_udp_buffer_limit(wanted),
        None => Ok(()),
    }
}

fn raise_udp_buffer_limit(wanted: usize) -> Result<()> {
    let read = |name: &str| -> usize {
        std::fs::read_to_string(format!("/proc/sys/net/core/{name}"))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    };
    let Some((rmem, wmem)) = buffer_ceilings(wanted, read("rmem_max"), read("wmem_max")) else {
        return Ok(());
    };
    std::fs::write(BUFFER_SYSCTL_FILE, buffer_sysctl_text(rmem, wmem))
        .context("write the sysctl file")?;
    for (name, limit) in [("rmem_max", rmem), ("wmem_max", wmem)] {
        if read(name) < limit {
            std::fs::write(format!("/proc/sys/net/core/{name}"), limit.to_string())
                .with_context(|| format!("raise net.core.{name}"))?;
        }
    }
    super::ui::ok(&format!(
        "Raised the kernel's UDP buffer limit to {} MB for this carrier ({BUFFER_SYSCTL_FILE})",
        rmem.min(wmem) / (1024 * 1024)
    ));
    Ok(())
}

/// C26: the ceilings to persist, or `None` when both already allow `wanted`. Each key is
/// raised to at least max(wanted, 16 MiB) and never below its own current value, so a
/// larger ceiling set elsewhere is kept after a reboot.
fn buffer_ceilings(wanted: usize, rmem: usize, wmem: usize) -> Option<(usize, usize)> {
    if rmem >= wanted && wmem >= wanted {
        return None;
    }
    let target = wanted.max(16 * 1024 * 1024);
    Some((target.max(rmem), target.max(wmem)))
}

fn buffer_sysctl_text(rmem: usize, wmem: usize) -> String {
    format!(
        "# Written by the EZTunnel manager: room for KCP/FEC socket buffers.\n\
         net.core.rmem_max = {rmem}\nnet.core.wmem_max = {wmem}\n"
    )
}

pub fn start(name: &str) -> Result<()> {
    systemctl(&["start", &unit_name(name)])
}

/// Saved-only configurations (guided setup and peer imports) have no unit yet.
/// Ordinary stopped units must not be rewritten or restarted when choosing Start.
pub fn start_saved(store: &Store, name: &str) -> Result<()> {
    ensure!(store.system, "systemd is not available on this machine");
    start_saved_with(state(store, name), || install(store, name), || start(name))
}

fn start_saved_with(
    state: State,
    install: impl FnOnce() -> Result<()>,
    start: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if state == State::NoService { install() } else { start() }
}

pub fn stop(name: &str) -> Result<()> {
    systemctl(&["stop", &unit_name(name)])?;
    if super::rawfw::enabled(name){systemctl(&["stop",&super::rawfw::unit_name(name)])?;}
    Ok(())
}

pub fn restart(name: &str) -> Result<()> {
    systemctl(&["restart", &unit_name(name)])
}

/// How long a restarted tunnel may take to come up, how long it must then keep running, and how
/// often that is looked at.
const COME_UP: Duration = Duration::from_secs(10);
const STAY_UP: Duration = Duration::from_secs(5);
const STEP: Duration = Duration::from_millis(500);

/// Watches a service that was just (re)started: it must be running within `COME_UP` and then at
/// every look during `STAY_UP`. A configuration can pass every check and still not start (a port
/// taken by another program); the service then restarts again and again, which this sees as a
/// look that finds it not running.
pub fn watch_started(mut running: impl FnMut() -> bool, mut sleep: impl FnMut(Duration)) -> bool {
    let mut waited = Duration::ZERO;
    while !running() {
        if waited >= COME_UP {
            return false;
        }
        sleep(STEP);
        waited += STEP;
    }
    let mut stayed = Duration::ZERO;
    while stayed < STAY_UP {
        sleep(STEP);
        stayed += STEP;
        if !running() {
            return false;
        }
    }
    true
}

/// Whether an `is-active` answer means the service runs or is on its way up or down.
fn running_word(answer: &str) -> bool {
    matches!(
        answer.trim(),
        "active" | "activating" | "deactivating" | "reloading"
    )
}

fn still_running(name: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", &unit_name(name)])
        .output()
        .map(|output| running_word(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or(false)
}

/// Stops the service and removes its unit. Missing services are not an error; a service that
/// will not stop is: removing its unit and configuration would leave a tunnel running that the
/// manager can no longer see.
pub fn remove(name: &str) -> Result<()> {
    let _ = systemctl(&["disable", "--now", "--quiet", &unit_name(name)]);
    if still_running(name) {
        let _ = systemctl(&["stop", &unit_name(name)]);
        ensure!(
            !still_running(name),
            "the service {unit} did not stop, so nothing was deleted; stop it with `systemctl stop {unit}` and delete the tunnel again",
            unit = unit_name(name)
        );
    }
    // Take the firewall rules of a raw TCP tunnel out with it.
    super::rawfw::disable(name)?;
    let _ = std::fs::remove_file(debug_drop_in(name));
    if let Some(dir) = Path::new(&debug_drop_in(name)).parent() {
        let _ = std::fs::remove_dir(dir);
    }
    match std::fs::remove_file(unit_path(name)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove the service unit"),
    }
    // The traffic count of a quota, if the tunnel had one.
    let _ = std::fs::remove_dir_all(format!("/var/lib/eztunnel-{name}"));
    systemctl(&["daemon-reload"])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Running,
    Starting,
    Stopped,
    Failed,
    NoService,
}

pub fn state(store: &Store, name: &str) -> State {
    if !store.system || !Path::new(&unit_path(name)).exists() {
        return State::NoService;
    }
    let output = Command::new("systemctl")
        .args(["is-active", &unit_name(name)])
        .output();
    match output
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .as_deref()
    {
        Ok("active") => State::Running,
        Ok("activating") | Ok("reloading") => State::Starting,
        Ok("failed") => State::Failed,
        _ => State::Stopped,
    }
}

/// Shows the journal of a tunnel live until Ctrl-C.
pub fn follow_logs(name: &str) -> Result<()> {
    super::ui::with_interrupt_for_children(|| {
        Command::new("journalctl")
            .args(["-u", &unit_name(name), "-f", "-n", "40", "-o", "cat"])
            .status()
    })
    .context("run journalctl")?;
    Ok(())
}

pub fn recent_logs(name: &str, lines: usize) -> String {
    Command::new("journalctl")
        .args([
            "-u",
            &unit_name(name),
            "-n",
            &lines.to_string(),
            "-o",
            "cat",
        ])
        .arg("--no-pager")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

pub fn status_text(name: &str) -> String {
    Command::new("systemctl")
        .args(["status", &unit_name(name), "--no-pager", "-n", "0"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// What the journal says about the link between the two servers since the last start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Health {
    /// Authenticated sessions seen since the service started.
    pub authenticated: usize,
    /// Open sessions in the newest status line.
    pub sessions: Option<u64>,
    /// Sessions opened between the two newest status lines (one interval).
    pub recent_connects: Option<u64>,
    /// Reason given for the newest session that ended.
    pub last_drop: Option<String>,
    /// The newest session was authenticated but then heard nothing from the other server
    /// (the engine's early "no traffic" warning): the carrier is probably being blocked.
    pub silent: bool,
    /// The traffic quota is used up and the tunnel is idle until the period ends.
    pub quota_exhausted: bool,
}

/// The engine's warning for an authenticated session that hears nothing.
const SILENCE_WARNING: &str = "no traffic from the other server";

/// Whether a journal line says a session was authenticated. The leading space matters: debug
/// and warning lines also contain the word "unauthenticated" ("too many unauthenticated
/// connections", the XHTTP warning about a listener without a token), which is not a session.
fn authenticated(line: &str) -> bool {
    line.contains(" authenticated")
}

fn field(line: &str, name: &str) -> Option<u64> {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(name)?.strip_prefix('=')?.parse().ok())
}

/// Reads the plain journal text of one tunnel (newest last).
pub fn parse_health(journal: &str) -> Health {
    // Only what happened since the service last started.
    let lines: Vec<&str> = journal.lines().collect();
    let start = lines
        .iter()
        .rposition(|line| line.starts_with("Started "))
        .map_or(0, |index| index + 1);
    let lines = &lines[start..];
    let statuses: Vec<&&str> = lines.iter().filter(|l| l.contains("status:")).collect();
    let newest = statuses.last();
    let recent_connects = match (statuses.len().checked_sub(2).map(|i| statuses[i]), newest) {
        (Some(before), Some(now)) => field(now, "connects")
            .zip(field(before, "connects"))
            .map(|(now, before)| now.saturating_sub(before)),
        _ => None,
    };
    // Silent until a newer session starts or the silent one ends.
    let mut silent = false;
    for line in lines.iter() {
        if line.contains(SILENCE_WARNING) {
            silent = true;
        } else if authenticated(line) || line.contains("tunnel session ended") {
            silent = false;
        }
    }
    // Idle from the quota message until a session authenticates again.
    let mut quota_exhausted = false;
    for line in lines.iter() {
        if line.contains(crate::quota::EXHAUSTED_MESSAGE) {
            quota_exhausted = true;
        } else if authenticated(line) {
            quota_exhausted = false;
        }
    }
    Health {
        silent,
        quota_exhausted,
        authenticated: lines.iter().filter(|l| authenticated(l)).count(),
        sessions: newest.and_then(|line| field(line, "sessions")),
        recent_connects,
        last_drop: lines
            .iter()
            .rev()
            .find(|line| line.contains("tunnel session ended"))
            .and_then(|line| {
                line.split_once("reason=")
                    .map(|(_, r)| r.trim().to_string())
            }),
    }
}

pub fn health(name: &str) -> Health {
    parse_health(&recent_logs(name, 400))
}

/// What the first seconds of a tunnel showed about the link to the other server.
#[derive(Debug, Clone, PartialEq)]
pub enum LinkCheck {
    /// No authenticated session within the wait.
    NotConnected,
    /// A session is authenticated but fewer than two heartbeat answers came back: a filter
    /// between the servers is probably dropping the traffic after the handshake.
    NoTraffic,
    /// Authenticated, and at least two heartbeat answers came back (newest round trip in
    /// milliseconds, if known).
    Working(Option<f64>),
    /// Authenticated, but this tunnel has no status channel (a pure TUN tunnel), so traffic
    /// cannot be confirmed.
    Unconfirmed,
}

/// Decides what the live status (`None` when the control socket does not answer) and the
/// journal say. A handshake alone proves nothing: blocked carriers authenticate and then pass
/// no data, so success needs a heartbeat answer (`pongs`) from the other server.
pub fn classify_link(status: Option<&serde_json::Value>, authenticated: bool) -> LinkCheck {
    let Some(status) = status else {
        return if authenticated {
            LinkCheck::Unconfirmed
        } else {
            LinkCheck::NotConnected
        };
    };
    if status["sessions"].as_u64().unwrap_or(0) == 0 {
        return LinkCheck::NotConnected;
    }
    // The engine sends a second heartbeat 2 s after the first. A carrier blocked right after the
    // handshake answers the first one and then goes quiet (plain WS did exactly that), so one
    // answer is not enough.
    if status["pongs"].as_u64().unwrap_or(0) < 2 {
        return LinkCheck::NoTraffic;
    }
    LinkCheck::Working(
        status["rtt_ms"]
            .as_array()
            .and_then(|a| a.last())
            .and_then(|v| v.as_f64()),
    )
}

/// Waits up to `seconds` for an authenticated session after a (re)start, then up to a few more
/// seconds for the first heartbeat answer, and reports what it saw.
pub fn wait_link(name: &str, seconds: u64) -> LinkCheck {
    let request = serde_json::json!({"cmd": "status"});
    let started = std::time::Instant::now();
    let mut connected_at: Option<std::time::Instant> = None;
    loop {
        let status = control(name, &request, std::time::Duration::from_secs(1)).ok();
        let authenticated = status.is_some() || health(name).authenticated > 0;
        let check = classify_link(status.as_ref(), authenticated);
        match check {
            LinkCheck::Working(_) | LinkCheck::Unconfirmed => return check,
            LinkCheck::NoTraffic => {
                connected_at.get_or_insert_with(std::time::Instant::now);
            }
            LinkCheck::NotConnected => {}
        }
        let answer_grace_over = connected_at.is_none_or(|at| at.elapsed().as_secs() >= 5);
        if started.elapsed().as_secs() >= seconds && answer_grace_over {
            return check;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// The control socket of a running tunnel (see the engine's control module).
pub fn control_path(name: &str) -> String {
    format!("/run/eztunnel-{name}/control.sock")
}

/// Sends one request to a running tunnel and returns its answer.
pub fn control(
    name: &str,
    request: &serde_json::Value,
    timeout: std::time::Duration,
) -> Result<serde_json::Value> {
    use std::io::{BufRead, Write};
    let path = control_path(name);
    let mut stream = std::os::unix::net::UnixStream::connect(&path).with_context(|| {
        if Path::new(&path).exists() {
            "the tunnel does not answer".to_string()
        } else {
            "no live data: restart the tunnel once so it opens its status channel".to_string()
        }
    })?;
    stream.set_read_timeout(Some(timeout))?;
    stream.write_all(format!("{request}\n").as_bytes())?;
    let mut line = String::new();
    std::io::BufReader::new(stream)
        .read_line(&mut line)
        .context("no answer from the tunnel")?;
    let answer: serde_json::Value = serde_json::from_str(&line).context("unreadable answer")?;
    if answer["ok"] != true {
        anyhow::bail!(
            "{}",
            answer["error"]
                .as_str()
                .unwrap_or("the tunnel refused the request")
        );
    }
    Ok(answer)
}

/// Whether ufw is installed and enabled.
pub fn ufw_active() -> bool {
    Command::new("ufw")
        .arg("status")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active"))
}

pub fn ufw_allow(port: u16, protocol: &str) -> Result<()> {
    let status = Command::new("ufw")
        .args(["allow", &format!("{port}/{protocol}")])
        .stdout(Stdio::null())
        .status()
        .context("run ufw")?;
    ensure!(status.success(), "ufw allow {port}/{protocol} failed");
    Ok(())
}

/// Ports this tunnel listens on, as (port, "tcp" | "udp").
pub fn listening_ports(config: &Config) -> Vec<(u16, &'static str)> {
    let mut ports = Vec::new();
    let mut add = |addr: &str, protocol: &'static str| {
        if let Ok(addr) = addr.parse::<SocketAddr>()
            && addr.port() != 0
            && !ports.contains(&(addr.port(), protocol))
        {
            ports.push((addr.port(), protocol));
        }
    };
    let udp_carrier = |transport| super::plan::uses_udp(transport);
    match config.mode {
        Mode::Server => {
            // C25: a remote-facing SOCKS5 listener needs its own allowance; the default
            // loopback-only proxy does not.
            if let Some(bind)=&config.socks5
                && bind.parse::<SocketAddr>().is_ok_and(|addr|!addr.ip().is_loopback())
            {
                add(bind,"tcp");
            }
            for listener in &config.listeners {
                if !config.server_dials && listener.raw.is_none() {
                    add(
                        &listener.addr,
                        if udp_carrier(listener.transport) {
                            "udp"
                        } else {
                            "tcp"
                        },
                    );
                }
                for map in &listener.maps {
                    add(
                        &map.bind,
                        match map.kind {
                            MapKind::Tcp => "tcp",
                            MapKind::Udp => "udp",
                        },
                    );
                }
            }
        }
        Mode::Client => {
            if config.server_dials {
                for path in &config.paths {
                    add(
                        &path.addr,
                        if udp_carrier(path.transport) {
                            "udp"
                        } else {
                            "tcp"
                        },
                    );
                }
            }
        }
    }
    ports
}

/// Whether something else already listens on a local port.
pub fn port_busy(port: u16, protocol: &str) -> bool {
    match protocol {
        "udp" => std::net::UdpSocket::bind(("0.0.0.0", port)).is_err(),
        _ => std::net::TcpListener::bind(("0.0.0.0", port)).is_err(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_start_installs_a_saved_only_tunnel_and_propagates_failure() {
        use std::cell::Cell;
        let installed=Cell::new(0);
        let started=Cell::new(0);
        start_saved_with(State::NoService,||{installed.set(installed.get()+1);Ok(())},||{started.set(started.get()+1);Ok(())}).unwrap();
        assert_eq!((installed.get(),started.get()),(1,0));
        assert!(start_saved_with(State::NoService,||anyhow::bail!("cannot install unit"),||panic!("must not start after failed install")).is_err());
    }

    #[test]
    fn start_existing_units_does_not_reinstall_or_restart_them() {
        for state in [State::Stopped,State::Failed,State::Running,State::Starting] {
            start_saved_with(state,||panic!("existing unit must not be rewritten"),||Ok(())).unwrap();
            assert!(start_saved_with(state,||panic!("existing unit must not be rewritten"),||anyhow::bail!("systemctl start failed")).is_err());
        }
    }
    use crate::manager::plan::{Carry, Direction, Plan, Side, check, parse_ports};
    use crate::{config::Transport, tunnel_key::TunnelKey};

    fn config(side: Side, direction: Direction, transport: Transport, ports: &str) -> Config {
        let mut plan = Plan::new(
            TunnelKey::generate().unwrap().display(),
            side,
            direction,
            transport,
        );
        plan.peer_host = Some("192.0.2.1".into());
        plan.carry = Carry::Ports;
        plan.ports = parse_ports(ports).unwrap();
        check(&plan.to_json().unwrap()).unwrap()
    }

    #[test]
    fn units_get_only_the_privileges_they_need() {
        let plain = config(Side::Iran, Direction::Reverse, Transport::Tcp, "8080");
        let text = unit_text(
            "a",
            Path::new("/usr/local/bin/eztunnel"),
            Path::new("/etc/eztunnel/tunnels/a.json"),
            &plain,
        );
        assert!(!text.contains("Capabilit"), "{text}");
        
        
        
        assert!(text.contains(
            "ExecStart=\"/usr/local/bin/eztunnel\" --config \"/etc/eztunnel/tunnels/a.json\""
        ));
        
        assert!(text.contains("User=eztunnel"));
        // A crash must not leave the tunnel key in a core dump.
        assert!(
            text.contains(
                "LimitCORE=0
"
            ),
            "{text}"
        );
        let low = config(Side::Iran, Direction::Reverse, Transport::Tcp, "443");
        let text = unit_text("b", Path::new("/x"), Path::new("/y"), &low);
        assert!(
            text.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"),
            "{text}"
        );
    }

    #[test]
    fn health_is_read_from_the_journal_since_the_last_start() {
        let journal = "Started eztunnel-a.service - EZTunnel tunnel a.
x INFO eztunnel::engine: authenticated tunnel connected address=1.2.3.4:7000
x INFO eztunnel::engine: tunnel session ended seconds=41 reason=old run
Started eztunnel-a.service - EZTunnel tunnel a.
x INFO eztunnel::engine: authenticated tunnel connected address=1.2.3.4:7000
x INFO eztunnel::engine: authenticated tunnel connected address=1.2.3.4:7000
x INFO eztunnel::stats: status: sessions=2 connects=2 streams=0
x INFO eztunnel::engine: tunnel session ended seconds=41 reason=tunnel heartbeat timeout
x INFO eztunnel::engine: authenticated tunnel connected address=1.2.3.4:7000
x INFO eztunnel::stats: status: sessions=2 connects=5 streams=0
";
        let health = parse_health(journal);
        assert_eq!(health.authenticated, 3);
        assert_eq!(health.sessions, Some(2));
        assert_eq!(health.recent_connects, Some(3));
        assert_eq!(
            health.last_drop.as_deref(),
            Some("tunnel heartbeat timeout")
        );
        assert_eq!(parse_health("").authenticated, 0);
        assert_eq!(parse_health("").sessions, None);
        assert!(!health.silent);
    }

    #[test]
    fn the_word_unauthenticated_is_not_a_session() {
        let base = "Started eztunnel-a.service - EZTunnel tunnel a.\n";
        let noise = "x DEBUG eztunnel::engine: too many unauthenticated connections; dropping a new one\nx WARN eztunnel::xhttp_carrier: this XHTTP listener has no access_token: it would accept unauthenticated sessions\n";
        assert_eq!(parse_health(&format!("{base}{noise}")).authenticated, 0);
        // The real lines of every carrier and direction still count.
        let real = "x INFO eztunnel::engine: tunnel peer authenticated peer=Some(1.2.3.4)\nx INFO eztunnel::engine: authenticated tunnel connected address=1.2.3.4:7000\nx INFO eztunnel::engine: reverse tunnel authenticated address=1.2.3.4:7000\n";
        assert_eq!(
            parse_health(&format!("{base}{real}{noise}")).authenticated,
            3
        );
        // A flood of such lines does not clear a silent session or an exhausted quota.
        let silent = "x WARN eztunnel::engine: no traffic from the other server; may have stopped seconds=20\n";
        assert!(parse_health(&format!("{base}{real}{silent}{noise}")).silent);
        let quota = format!(
            "x WARN eztunnel: {}: stopping until the period ends\n",
            crate::quota::EXHAUSTED_MESSAGE
        );
        assert!(parse_health(&format!("{base}{quota}{noise}")).quota_exhausted);
        assert!(!parse_health(&format!("{base}{quota}{real}")).quota_exhausted);
    }

    #[test]
    fn only_the_answers_of_a_living_service_count_as_running() {
        for answer in ["active\n", "activating\n", "deactivating", "reloading"] {
            assert!(running_word(answer), "{answer}");
        }
        for answer in ["inactive\n", "failed\n", "unknown", ""] {
            assert!(!running_word(answer), "{answer:?}");
        }
    }

    /// Runs `watch_started` against a service that is running at the looks in `up` (look
    /// number, counting from 0) and returns the verdict.
    fn watched(up: impl Fn(usize) -> bool) -> (bool, Duration) {
        let looks = std::cell::Cell::new(0usize);
        let slept = std::cell::Cell::new(Duration::ZERO);
        let verdict = watch_started(
            || {
                let look = looks.get();
                looks.set(look + 1);
                up(look)
            },
            |pause| slept.set(slept.get() + pause),
        );
        (verdict, slept.get())
    }

    #[test]
    fn a_restarted_service_must_come_up_and_stay_up() {
        // Running at once and for the whole window.
        let (verdict, slept) = watched(|_| true);
        assert!(verdict);
        assert_eq!(slept, STAY_UP);
        // Late but within the time allowed.
        assert!(watched(|look| look >= 8).0);
        // Never comes up: gives up after COME_UP.
        let (verdict, slept) = watched(|_| false);
        assert!(!verdict);
        assert_eq!(slept, COME_UP);
        // Comes up and then falls over (the service restarts in a loop): not healthy.
        assert!(!watched(|look| look < 4).0);
        // One look that finds it down inside the window is enough.
        assert!(!watched(|look| look != 6).0);
    }

    #[test]
    fn a_silent_session_is_reported_until_a_new_one_starts_or_it_ends() {
        let warning = "x WARN eztunnel::engine: no traffic from the other server; a filter between the servers may be blocking this carrier after the handshake seconds=20";
        let base = "Started eztunnel-a.service - EZTunnel tunnel a.\nx INFO eztunnel::engine: authenticated tunnel connected address=1.2.3.4:7000\n";
        // Handshake done, then the engine's warning: blocked after the handshake.
        assert!(parse_health(&format!("{base}{warning}\n")).silent);
        // The silent session ended: no longer silent (the drop reason shows instead).
        let ended = format!(
            "{base}{warning}\nx INFO eztunnel::engine: tunnel session ended seconds=41 reason=tunnel heartbeat timeout\n"
        );
        assert!(!parse_health(&ended).silent);
        // A silent session from before a restart does not count.
        let restarted =
            format!("{base}{warning}\nStarted eztunnel-a.service - EZTunnel tunnel a.\n");
        assert!(!parse_health(&restarted).silent);
        // A healthy session never is.
        assert!(!parse_health(base).silent);
    }

    #[test]
    fn a_used_up_quota_is_reported_until_a_session_authenticates_again() {
        let base = "Started eztunnel-a.service - EZTunnel tunnel a.
";
        let idle = format!(
            "{base}x WARN eztunnel::quota: {}: the tunnel stays off until the period ends
",
            crate::quota::EXHAUSTED_MESSAGE
        );
        assert!(parse_health(&idle).quota_exhausted);
        let resumed = format!(
            "{idle}x INFO eztunnel::engine: authenticated tunnel connected address=1.2.3.4:7000
"
        );
        assert!(!parse_health(&resumed).quota_exhausted);
        assert!(!parse_health(base).quota_exhausted);
        // A restart with room left forgets the old message.
        let restarted = format!(
            "{idle}Started eztunnel-a.service - EZTunnel tunnel a.
"
        );
        assert!(!parse_health(&restarted).quota_exhausted);
    }

    #[test]
    fn a_quota_gives_the_service_a_state_directory() {
        let mut quota = config(Side::Iran, Direction::Reverse, Transport::Tcp, "8080");
        let plain = unit_text("a", Path::new("/x"), Path::new("/y"), &quota);
        assert!(!plain.contains("EZTUNNEL_QUOTA_FILE="));
        assert!(!plain.contains("StateDirectory"), "{plain}");
        quota.quota.limit_gb = 5;
        let text = unit_text("a", Path::new("/x"), Path::new("/y"), &quota);
        assert!(
            text.contains("Environment=EZTUNNEL_QUOTA_FILE=/var/lib/eztunnel-a/quota.json\n"),
            "{text}"
        );
        let other = unit_text("b", Path::new("/x"), Path::new("/y"), &quota);
        assert!(
            other.contains("Environment=EZTUNNEL_QUOTA_FILE=/var/lib/eztunnel-b/quota.json\n"),
            "{other}"
        );
        
        
        assert!(text.contains("StateDirectory=eztunnel-a\n"), "{text}");
    }

    #[test]
    fn a_handshake_alone_is_not_a_working_link() {
        use serde_json::json;
        let status = |sessions: u64, pongs: u64| json!({"ok": true, "sessions": sessions, "pongs": pongs, "rtt_ms": [91.2, 88.4]});
        // No status channel: only the journal can say anything.
        assert_eq!(classify_link(None, false), LinkCheck::NotConnected);
        assert_eq!(classify_link(None, true), LinkCheck::Unconfirmed);
        // Status channel, nothing authenticated.
        assert_eq!(
            classify_link(Some(&status(0, 0)), true),
            LinkCheck::NotConnected
        );
        // Authenticated but no heartbeat ever answered: the blocked-after-handshake case.
        assert_eq!(
            classify_link(Some(&status(1, 0)), true),
            LinkCheck::NoTraffic
        );
        // One answer and then silence is what a carrier blocked after the handshake looks like
        // (plain WS on a real Iran link answered the first heartbeat only).
        assert_eq!(
            classify_link(Some(&status(1, 1)), true),
            LinkCheck::NoTraffic
        );
        // Two heartbeats answered: traffic passes, and the newest round trip is reported.
        assert_eq!(
            classify_link(Some(&status(1, 3)), true),
            LinkCheck::Working(Some(88.4))
        );
        // Answers from an earlier session do not count once the session is gone.
        assert_eq!(
            classify_link(Some(&status(0, 3)), true),
            LinkCheck::NotConnected
        );
        // Status without any round-trip samples yet is still working.
        assert_eq!(
            classify_link(Some(&json!({"sessions": 1, "pongs": 2})), true),
            LinkCheck::Working(None)
        );
    }

    #[test]
    fn the_buffer_ceiling_follows_the_largest_request_of_all_tunnels() {
        let tcp = config(Side::Iran, Direction::Reverse, Transport::Tcp, "443");
        let kcp = config(Side::Iran, Direction::Reverse, Transport::Kcp, "444");
        assert_eq!(largest_udp_buffer([&tcp]), None);
        assert_eq!(largest_udp_buffer([&tcp, &kcp]), udp_buffer_wanted(&kcp));
        assert_eq!(largest_udp_buffer([&kcp, &tcp]), Some(4 * 1024 * 1024));
        assert_eq!(largest_udp_buffer(std::iter::empty()), None);
    }

    #[test]
    fn only_udp_carriers_ask_for_bigger_kernel_buffers() {
        assert_eq!(
            udp_buffer_wanted(&config(
                Side::Iran,
                Direction::Reverse,
                Transport::Tcp,
                "443"
            )),
            None
        );
        assert_eq!(
            udp_buffer_wanted(&config(
                Side::Iran,
                Direction::Reverse,
                Transport::Kcp,
                "443"
            )),
            Some(4 * 1024 * 1024)
        );
        assert_eq!(
            udp_buffer_wanted(&config(
                Side::Foreign,
                Direction::Reverse,
                Transport::FecUdp,
                "443"
            )),
            Some(4 * 1024 * 1024)
        );
    }

    #[test]
    fn listening_ports_follow_the_direction() {
        let iran = config(Side::Iran, Direction::Reverse, Transport::Kcp, "443,8080");
        assert_eq!(
            listening_ports(&iran),
            vec![(7000, "udp"), (443, "tcp"), (8080, "tcp")]
        );
        let iran_direct = config(Side::Iran, Direction::Direct, Transport::Tcp, "443");
        assert_eq!(listening_ports(&iran_direct), vec![(443, "tcp")]);
        let foreign_direct = config(Side::Foreign, Direction::Direct, Transport::Tcp, "443");
        assert_eq!(listening_ports(&foreign_direct), vec![(7000, "tcp")]);
        let foreign = config(Side::Foreign, Direction::Reverse, Transport::Tcp, "443");
        assert!(listening_ports(&foreign).is_empty());
    }

    /// C25: a remote-facing SOCKS5 bind is offered to UFW; the loopback default is not.
    #[test]
    fn firewall_ports_include_remote_socks_but_not_loopback_socks() {
        let mut iran = config(Side::Iran, Direction::Reverse, Transport::Tcp, "443");
        iran.socks5 = Some("0.0.0.0:1081".into());
        assert!(listening_ports(&iran).contains(&(1081, "tcp")));
        iran.socks5 = Some("127.0.0.1:1080".into());
        assert!(!listening_ports(&iran).iter().any(|(port, _)| *port == 1080));
        iran.socks5 = Some("[::1]:1080".into());
        assert!(!listening_ports(&iran).iter().any(|(port, _)| *port == 1080));
    }

    /// C26: 64 MiB rmem from an earlier file, 208 KiB wmem, tunnel wants 4 MiB.
    #[test]
    fn persisted_udp_ceilings_never_lower_a_larger_existing_value() {
        const MIB: usize = 1024 * 1024;
        assert_eq!(buffer_ceilings(4 * MIB, 64 * MIB, 212_992), Some((64 * MIB, 16 * MIB)));
        assert_eq!(buffer_ceilings(32 * MIB, 212_992, 212_992), Some((32 * MIB, 32 * MIB)));
        assert_eq!(buffer_ceilings(4 * MIB, 8 * MIB, 8 * MIB), None, "both already allow it");
        let text = buffer_sysctl_text(64 * MIB, 16 * MIB);
        assert!(text.contains(&format!("net.core.rmem_max = {}\n", 64 * MIB)), "{text}");
        assert!(text.contains(&format!("net.core.wmem_max = {}\n", 16 * MIB)), "{text}");
    }
}
