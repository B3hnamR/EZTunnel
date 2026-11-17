//! Server tools for the dashboard: the health check with its fixes, the kernel optimization
//! (preview, apply, undo) and where the files are. Each check names a fix from a fixed list;
//! nothing here runs a command the dashboard sends.
use crate::{
    config::Config,
    manager::{
        optimize,
        service::{self, State},
        store::Store,
    },
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{path::Path, process::Command, time::Duration};

/// One finding: `id` names what was checked (the screen explains it), `subject` the tunnel (or
/// ""), `level` ok, warn or bad, `value` what was found, `fix` the repair it offers (or null).
fn finding(id: &str, subject: &str, level: &str, value: impl Into<Value>, fix: Option<String>) -> Value {
    json!({"id": id, "subject": subject, "level": level, "value": value.into(), "fix": fix})
}

fn proc_text(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|t| t.trim().to_string())
}

/// What `ufw status` says about a port for traffic from any address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Firewall {
    Open,
    Closed,
    /// Rules for some sources only: whether the tunnel's other server is let in cannot be told.
    Unknown,
}

/// Whether a rule's "To" column covers `port`/`protocol`: `Some(true)` when it names it (a port, a
/// list or a range, with or without the protocol), `Some(false)` when it names other ports only,
/// `None` when it cannot be told here (every port, an application profile, an interface).
fn rule_covers(to: &str, port: u16, protocol: &str) -> Option<bool> {
    let (ports, proto) = match to.split_once('/') {
        Some((ports, proto)) => (ports, Some(proto)),
        None => (to, None),
    };
    if proto.is_some_and(|p| p != protocol) {
        return Some(false);
    }
    let mut known = true;
    let covers = ports.split(',').any(|part| match part.split_once(':') {
        Some((low, high)) => match (low.parse::<u16>(), high.parse::<u16>()) {
            (Ok(low), Ok(high)) => (low..=high).contains(&port),
            _ => {
                known = false;
                false
            }
        },
        None => match part.parse::<u16>() {
            Ok(single) => single == port,
            Err(_) => {
                known = false;
                false
            }
        },
    });
    if covers { Some(true) } else if known { Some(false) } else { None }
}

/// Reads the rules for `port` in order, as ufw applies them (the first match wins), for IPv4,
/// the family tunnels listen on by default. A rule for the port and every source decides. Rules
/// that may apply but cannot be told apart here (for some sources only, for every port, by an
/// application name, or for IPv6 only) make the answer unknown, never open.
pub fn ufw_port(status: &str, port: u16, protocol: &str) -> Firewall {
    let (mut some_allowed, mut maybe_denied, mut v6_allowed) = (false, false, false);
    for line in status.lines() {
        let v6 = line.contains("(v6)");
        let words: Vec<&str> = line.split_whitespace().filter(|w| *w != "(v6)").collect();
        let Some(at) = words.iter().position(|w| matches!(*w, "ALLOW" | "DENY" | "REJECT" | "LIMIT")) else { continue };
        if at == 0 || words.get(at + 1) == Some(&"OUT") {
            continue;
        }
        let to = words[..at].join(" ");
        let covers = if to == "Anywhere" { None } else { rule_covers(words[0], port, protocol).filter(|_| at == 1) };
        if covers == Some(false) {
            continue;
        }
        let from = words[at + 1..].iter().find(|w| **w != "IN").copied().unwrap_or("Anywhere");
        let allow = matches!(words[at], "ALLOW" | "LIMIT");
        if v6 {
            v6_allowed |= allow;
            continue;
        }
        match (covers, from == "Anywhere", allow) {
            // This port, every source: decides, unless something before may have applied.
            (Some(true), true, true) => {
                return if maybe_denied { Firewall::Unknown } else { Firewall::Open };
            }
            (Some(true), true, false) => {
                return if some_allowed { Firewall::Unknown } else { Firewall::Closed };
            }
            // Every port from every source.
            (None, true, true) if to == "Anywhere" => {
                return if maybe_denied { Firewall::Unknown } else { Firewall::Open };
            }
            (_, _, true) => some_allowed = true,
            (_, _, false) => maybe_denied = true,
        }
    }
    if some_allowed || v6_allowed { Firewall::Unknown } else { Firewall::Closed }
}

/// Whether `ufw status` lets in a port from every address.
pub fn ufw_allows(status: &str, port: u16, protocol: &str) -> bool {
    ufw_port(status, port, protocol) == Firewall::Open
}

fn disk_used_pct(path: &str) -> Option<f64> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs fills the struct it is given; the path is a valid C string.
    if unsafe { libc::statvfs(c.as_ptr(), &mut stats) } != 0 || stats.f_blocks == 0 {
        return None;
    }
    let free = stats.f_bavail as f64 / stats.f_blocks as f64;
    Some((1.0 - free) * 100.0)
}

fn mem_available_pct() -> Option<f64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let field = |name: &str| -> Option<f64> {
        text.lines().find(|l| l.starts_with(name))?.split_whitespace().nth(1)?.parse().ok()
    };
    Some(field("MemAvailable:")? / field("MemTotal:")? * 100.0)
}

/// Every check for this server and its tunnels.
pub fn health(store: &Store) -> Result<Value> {
    let mut found = Vec::new();
    // Time: TLS certificates and the tunnels' replay windows need a correct clock.
    if let Ok(out) = Command::new("timedatectl").args(["show", "-p", "NTPSynchronized", "--value"]).output()
        && out.status.success()
    {
        let synced = String::from_utf8_lossy(&out.stdout).trim() == "yes";
        found.push(finding("time_sync", "", if synced { "ok" } else { "warn" }, synced, None));
    }
    let congestion = proc_text("/proc/sys/net/ipv4/tcp_congestion_control").unwrap_or_default();
    found.push(finding("congestion", "", if congestion == "bbr" { "ok" } else { "warn" }, congestion.clone(), (congestion != "bbr").then(|| "optimize".into())));
    let changes = optimize::plan();
    found.push(finding("optimize", "", if changes.is_empty() { "ok" } else { "warn" }, changes.len(), (!changes.is_empty()).then(|| "optimize".into())));
    if let Some(used) = disk_used_pct("/") {
        found.push(finding("disk", "", if used >= 95.0 { "bad" } else if used >= 85.0 { "warn" } else { "ok" }, (used * 10.0).round() / 10.0, None));
    }
    if let Some(free) = mem_available_pct() {
        found.push(finding("memory", "", if free < 5.0 { "bad" } else if free < 12.0 { "warn" } else { "ok" }, (free * 10.0).round() / 10.0, None));
    }
    let ufw = service::ufw_active().then(|| {
        Command::new("ufw").arg("status").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
    });
    let names = store.names()?;
    let mut configs = Vec::new();
    for name in &names {
        match store.read(name).and_then(|value| crate::manager::plan::check(&value).map(|c| (value, c))) {
            Ok((value, config)) => configs.push((name.clone(), value, config)),
            Err(error) => found.push(finding("config", name, "bad", format!("{error:#}"), None)),
        }
    }
    // Kernel buffers for KCP/FEC tunnels, and IP forwarding for TUN tunnels.
    let wanted = configs.iter().filter_map(|(_, _, c)| service::udp_buffer_wanted(c)).max();
    if let Some(wanted) = wanted {
        let ceiling: usize = proc_text("/proc/sys/net/core/rmem_max").and_then(|t| t.parse().ok()).unwrap_or(0);
        let short = ceiling < wanted;
        found.push(finding("udp_buffers", "", if short { "warn" } else { "ok" }, json!({"have": ceiling, "want": wanted}), short.then(|| "udp_buffers".into())));
    }
    if configs.iter().any(|(_, v, _)| v.get("tun").is_some_and(|t| !t.is_null())) {
        let on = proc_text("/proc/sys/net/ipv4/ip_forward").as_deref() == Some("1");
        found.push(finding("ip_forward", "", if on { "ok" } else { "warn" }, on, None));
    }
    for (name, _, config) in &configs {
        tunnel_checks(store, name, config, ufw.as_deref(), &mut found);
    }
    Ok(json!({"checks": found, "tunnels": names.len()}))
}

fn tunnel_checks(store: &Store, name: &str, config: &Config, ufw: Option<&str>, found: &mut Vec<Value>) {
    let state = service::state(store, name);
    match state {
        State::Failed => found.push(finding("service", name, "bad", "failed", Some(format!("restart:{name}")))),
        State::Stopped => found.push(finding("service", name, "warn", "stopped", Some(format!("start:{name}")))),
        State::NoService => found.push(finding("service", name, "warn", "none", Some(format!("start:{name}")))),
        State::Running | State::Starting => found.push(finding("service", name, "ok", "running", None)),
    }
    if matches!(state, State::Running) {
        let status = service::control(name, &json!({"cmd": "status"}), Duration::from_millis(800)).ok();
        let health = service::health(name);
        let word = super::data::link_word(&health, status.as_ref());
        let level = match word {
            "working" => "ok",
            "not_connected" => "bad",
            _ => "warn",
        };
        found.push(finding("link", name, level, json!({"state": word, "last_drop": health.last_drop}), (level != "ok").then(|| format!("restart:{name}"))));
        if let Some(version) = status.as_ref().and_then(|s| s["version"].as_str())
            && version != env!("CARGO_PKG_VERSION")
        {
            found.push(finding("program", name, "warn", version, Some(format!("restart:{name}"))));
        }
    }
    if service::debug_logging(name) {
        found.push(finding("debug_logging", name, "warn", true, Some(format!("debug_off:{name}"))));
    }
    if let Some(status) = ufw {
        for (port, protocol) in service::listening_ports(config) {
            let (level, fix) = match ufw_port(status, port, protocol) {
                Firewall::Open => ("ok", None),
                // Rules for some sources only: shown, not "fixed" by opening it to everyone.
                Firewall::Unknown => ("warn", None),
                Firewall::Closed => ("bad", Some(format!("ufw:{port}/{protocol}"))),
            };
            found.push(finding("firewall", name, level, format!("{port}/{protocol}"), fix));
        }
    }
}

/// Runs one fix a check offered.
pub fn fix(store: &Store, fix: &str) -> Result<Value> {
    let (kind, arg) = fix.split_once(':').unwrap_or((fix, ""));
    let known = |name: &str| -> Result<()> {
        if !store.names()?.iter().any(|n| n == name) {
            bail!("no tunnel named {name}");
        }
        Ok(())
    };
    match kind {
        "optimize" => {
            let failed = optimize::apply(&optimize::plan())?;
            Ok(json!({"done": true, "failed": failed}))
        }
        "udp_buffers" => {
            service::restore_udp_buffers(store)?;
            Ok(json!({"done": true}))
        }
        "restart" | "start" => {
            known(arg)?;
            let _lock = store.lock(arg, false)?;
            if service::state(store, arg) == State::NoService {
                service::install_with(store, arg, &super::ops::installed_program())?;
            } else if kind == "restart" {
                service::restart(arg)?;
            } else {
                service::start(arg)?;
            }
            let up = service::watch_started(|| service::state(store, arg) == State::Running, std::thread::sleep);
            Ok(json!({"done": true, "came_up": up}))
        }
        "debug_off" => {
            known(arg)?;
            service::set_debug_logging(arg, false)?;
            Ok(json!({"done": true}))
        }
        "ufw" => {
            let (port, protocol) = arg.split_once('/').context("a firewall fix names port/protocol")?;
            let port: u16 = port.parse().context("a bad port")?;
            if !matches!(protocol, "tcp" | "udp") {
                bail!("the protocol must be tcp or udp");
            }
            // Only ports one of the tunnels listens on may be opened this way.
            let listened = store.names()?.iter().any(|name| {
                store
                    .read(name)
                    .and_then(|v| crate::manager::plan::check(&v))
                    .is_ok_and(|c| service::listening_ports(&c).contains(&(port, if protocol == "tcp" { "tcp" } else { "udp" })))
            });
            if !listened {
                bail!("no tunnel listens on {port}/{protocol}");
            }
            service::ufw_allow(port, protocol)?;
            Ok(json!({"done": true}))
        }
        _ => bail!("unknown fix"),
    }
}

/// The kernel optimization: what would change, whether it is in place.
pub fn optimize_plan() -> Value {
    let changes: Vec<Value> = optimize::plan()
        .into_iter()
        .map(|c| json!({"key": c.key, "current": c.current, "wanted": c.wanted, "why": c.why}))
        .collect();
    json!({"changes": changes, "applied": optimize::applied()})
}

/// Where this program keeps things on the server, with sizes and times.
pub fn files(store: &Store) -> Result<Value> {
    let entry = |label: &str, path: &Path| -> Value {
        let meta = std::fs::metadata(path).ok();
        let size = meta.as_ref().map(|m| if m.is_dir() { dir_size(path) } else { m.len() });
        let modified = meta.and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs());
        json!({"label": label, "path": path.display().to_string(), "exists": size.is_some(), "size": size, "modified": modified})
    };
    let mut list = vec![
        entry("configs", &store.dir()),
        entry("program", Path::new(super::ops::INSTALLED)),
        entry("previous_program", &crate::manager::update::previous_path(Path::new(super::ops::INSTALLED))),
        entry("sysctl", Path::new(service::BUFFER_SYSCTL_FILE)),
    ];
    for name in store.names()? {
        list.push(entry("tunnel", &store.path(&name)));
        list.push(entry("unit", Path::new(&format!("/etc/systemd/system/{}", service::unit_name(&name)))));
    }
    Ok(json!({"files": list}))
}

fn dir_size(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .map(|entries| entries.flatten().filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len()).sum())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_rules_are_read_from_ufw_status() {
        let status = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n7000                       ALLOW       Anywhere\n9392/udp                   DENY        Anywhere\n";
        assert!(ufw_allows(status, 22, "tcp"));
        assert!(!ufw_allows(status, 22, "udp"));
        assert!(ufw_allows(status, 7000, "udp"), "a rule without a protocol covers both");
        assert!(!ufw_allows(status, 9392, "udp"), "a deny is not an allow");
        assert!(!ufw_allows(status, 443, "tcp"));
        // A rule for one source only is not "open" for the tunnel's other server.
        let scoped = "To Action From\n7000/tcp ALLOW IN 203.0.113.5\n";
        assert_eq!(ufw_port(scoped, 7000, "tcp"), Firewall::Unknown);
        // The first match wins: a deny for everyone before an allow closes it.
        let order = "To Action From\n7000 DENY IN Anywhere\n7000 ALLOW IN Anywhere\n";
        assert_eq!(ufw_port(order, 7000, "tcp"), Firewall::Closed);
        // A source deny before an allow for everyone: that source may be the other server.
        let mixed = "To Action From\n7000 DENY 198.51.100.0/24\n7000 ALLOW Anywhere\n";
        assert_eq!(ufw_port(mixed, 7000, "tcp"), Firewall::Unknown);
        // An IPv6-only allow says nothing about IPv4.
        let v6 = "To Action From\n7000/tcp (v6) ALLOW IN Anywhere (v6)\n";
        assert_eq!(ufw_port(v6, 7000, "tcp"), Firewall::Unknown);
        let both = "To Action From\n7000/tcp ALLOW IN Anywhere\n7000/tcp (v6) ALLOW IN Anywhere (v6)\n";
        assert_eq!(ufw_port(both, 7000, "tcp"), Firewall::Open);
        // Ranges and lists cover the port.
        assert_eq!(ufw_port("7000:7100/tcp ALLOW IN Anywhere\n", 7004, "tcp"), Firewall::Open);
        assert_eq!(ufw_port("80,443,7004/tcp ALLOW IN Anywhere\n", 7004, "tcp"), Firewall::Open);
        assert_eq!(ufw_port("7000:7100/udp ALLOW IN Anywhere\n", 7004, "tcp"), Firewall::Closed);
        // A deny for every port from one source, before the allow: that source may be the peer.
        let earlier = "Anywhere DENY IN 203.0.113.0/24\n7000/tcp ALLOW IN Anywhere\n";
        assert_eq!(ufw_port(earlier, 7000, "tcp"), Firewall::Unknown);
        // An application profile cannot be read here.
        assert_eq!(ufw_port("OpenSSH DENY IN Anywhere\n7000/tcp ALLOW IN Anywhere\n", 7000, "tcp"), Firewall::Unknown);
    }

    #[test]
    fn unknown_or_unsafe_fixes_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::for_test(directory.path().to_path_buf());
        for bad in ["rm -rf /", "restart:nothing", "ufw:22/tcp", "ufw:abc/tcp", "ufw:7000/sctp", "debug_off:../x"] {
            assert!(fix(&store, bad).is_err(), "{bad}");
        }
    }
}
