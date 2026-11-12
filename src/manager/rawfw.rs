//! Firewall rules for the raw TCP carriers (`fec-raw`, `fec-raw-gaming`, and `tun` with the
//! `tcp` profile).
//!
//! These carriers build TCP packets themselves and never open a socket, so the kernel sees
//! segments for a port nobody listens on. It answers with TCP resets, which confuse NATs and
//! stateful firewalls on the path, and connection tracking may mark the packets invalid. Two
//! rules keep the kernel out of it: bypass connection tracking for the packets from the peer,
//! and drop the resets the kernel would send from the two raw ports.
//!
//! The rules are never added silently. The manager offers them, scopes them to the peer's address
//! and the two ports, and keeps them in a small systemd unit that is started before the tunnel
//! and removes the rules when it is stopped, disabled or deleted. Nothing needs saving with
//! `iptables-save`. Every rule carries its tunnel's name as an iptables comment, so two tunnels
//! that need the same rule each have their own, and stopping one never removes the other's.
use super::service;
use crate::{
    config::{Config, Transport},
    raw_packet::RawProfile,
};
use anyhow::{Context, Result, bail};
use std::{
    net::Ipv4Addr,
    path::Path,
    process::{Command, Stdio},
};

/// What the firewall rules need to know about a raw TCP tunnel: each of its raw TCP endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTcp {
    pub endpoints: Vec<RawEndpoint>,
}

/// One raw TCP listener or path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEndpoint {
    /// The other server. `None` when addresses are spoofed: the packets then do not carry the
    /// peer's real address, so the rules are limited by port only.
    pub peer: Option<Ipv4Addr>,
    /// The service port and the client's source port.
    pub ports: Vec<u16>,
}

fn carries_raw(transport: Transport) -> bool {
    matches!(
        transport,
        Transport::FecRaw | Transport::FecRawGaming | Transport::Tun | Transport::Mirage
    )
}

/// The raw TCP endpoints of a tunnel (every raw listener and path), or `None` when it sends no
/// TCP-looking raw packets (other carriers, other raw profiles, proto58 mode).
pub fn endpoints(config: &Config) -> Option<RawTcp> {
    let endpoints: Vec<RawEndpoint> = config
        .listeners
        .iter()
        .filter(|l| carries_raw(l.transport))
        .filter_map(|l| l.raw.as_ref())
        .chain(
            config
                .paths
                .iter()
                .filter(|p| carries_raw(p.transport))
                .filter_map(|p| p.raw.as_ref()),
        )
        .filter(|raw| raw.profile == RawProfile::Tcp && !raw.proto58_mode)
        .map(|raw| {
            // The same default the packet encoder uses for the client's source port.
            let source = raw.source_port.unwrap_or(if raw.l4_port == u16::MAX {
                u16::MAX - 1
            } else {
                raw.l4_port + 1
            });
            let mut ports = vec![raw.l4_port];
            if source != raw.l4_port {
                ports.push(source);
            }
            let spoofed = raw.spoof_src_ip.is_some() || raw.spoof_dst_ip.is_some();
            RawEndpoint {
                peer: (!spoofed).then_some(raw.peer_ip),
                ports,
            }
        })
        .collect();
    (!endpoints.is_empty()).then_some(RawTcp { endpoints })
}

/// One iptables rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    table: &'static str,
    chain: &'static str,
    spec: Vec<String>,
}

impl Rule {
    /// The iptables arguments for `action`: `-C` (check), `-I` (insert) or `-D` (delete).
    pub fn args(&self, action: &str) -> Vec<String> {
        let mut args: Vec<String> = ["-w", "2", "-t", self.table, action, self.chain]
            .into_iter()
            .map(str::to_string)
            .collect();
        args.extend(self.spec.iter().cloned());
        args
    }

    /// The same as a command line, for the unit file and for showing the operator.
    pub fn command(&self, action: &str) -> String {
        format!("iptables {}", self.args(action).join(" "))
    }
}

/// The rules for a raw TCP tunnel: per endpoint and raw port, bypass connection tracking for
/// packets from the peer, and drop the kernel's own resets towards the peer. `owner` (the tunnel's
/// name) goes into each rule as a comment.
pub fn rules(raw: &RawTcp, owner: &str) -> Vec<Rule> {
    let mut rules: Vec<Rule> = Vec::new();
    for endpoint in &raw.endpoints {
        for rule in endpoint_rules(endpoint, owner) {
            if !rules.contains(&rule) {
                rules.push(rule);
            }
        }
    }
    rules
}

fn endpoint_rules(raw: &RawEndpoint, owner: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let tag = [
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        format!("eztunnel:{owner}"),
    ];
    for port in &raw.ports {
        let mut track = vec!["-p".to_string(), "tcp".to_string()];
        let mut reset = track.clone();
        if let Some(peer) = raw.peer {
            track.extend(["-s".into(), peer.to_string()]);
            reset.extend(["-d".into(), peer.to_string()]);
        }
        track.extend(tag.iter().cloned());
        reset.extend(tag.iter().cloned());
        track.extend([
            "--dport".into(),
            port.to_string(),
            "-j".into(),
            "CT".into(),
            "--notrack".into(),
        ]);
        reset.extend([
            "--sport".into(),
            port.to_string(),
            "--tcp-flags".into(),
            "RST".into(),
            "RST".into(),
            "-j".into(),
            "DROP".into(),
        ]);
        rules.push(Rule {
            table: "raw",
            chain: "PREROUTING",
            spec: track,
        });
        rules.push(Rule {
            table: "mangle",
            chain: "OUTPUT",
            spec: reset,
        });
    }
    rules
}

/// The unit's name. Tunnel names cannot contain a dot, so this never collides with a tunnel.
pub fn unit_name(name: &str) -> String {
    format!("eztunnel-{name}.firewall.service")
}

fn unit_path(name: &str) -> String {
    format!("/etc/systemd/system/{}", unit_name(name))
}

/// The unit that adds the rules before the tunnel starts and removes them when it stops.
pub fn unit_text(name: &str, raw: &RawTcp) -> String {
    let mut text = format!(
        "[Unit]
Description=EZTunnel firewall rules for the raw TCP packets of {name}
Before=eztunnel-{name}.service
PartOf=eztunnel-{name}.service
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=15
TimeoutStopSec=15
"
    );
    let rules = rules(raw, name);
    for rule in &rules {
        // Add only when missing, so starting twice never doubles a rule.
        text.push_str(&format!(
            "ExecStart=/bin/sh -c \"{} 2>/dev/null || {}\"\n",
            rule.command("-C"),
            rule.command("-I")
        ));
    }
    // C23: one unmasked stop script attempts every deletion. An absent rule is fine
    // (the check fails, nothing to delete); a failed deletion makes the stop fail instead
    // of being hidden by systemd's '-' prefix. `$$` is systemd's escape for `$`.
    let mut stop = String::from("rc=0;");
    for rule in rules.iter().rev() {
        stop.push_str(&format!(
            " while {} 2>/dev/null; do {} || {{ rc=1; break; }}; done;",
            rule.command("-C"),
            rule.command("-D")
        ));
    }
    stop.push_str(" exit $$rc");
    text.push_str(&format!("ExecStop=/bin/sh -c \"{stop}\"\n"));
    text.push_str(&format!(
        "
[Install]
WantedBy=eztunnel-{name}.service
"
    ));
    text
}

/// Whether the operator has switched the rules on for this tunnel.
pub fn enabled(name: &str) -> bool {
    Path::new(&unit_path(name)).exists()
}

/// Whether `iptables` can be run.
pub fn iptables_available() -> bool {
    Command::new("iptables")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Whether every rule of tunnel `name` is in the kernel now (`None` without iptables).
pub fn rules_present(name: &str, raw: &RawTcp) -> Option<bool> {
    let mut all = true;
    for rule in rules(raw, name) {
        let status = Command::new("iptables")
            .args(rule.args("-C"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        all &= status.success();
    }
    Some(all)
}

/// Switches the rules on (or re-applies them after the ports changed).
pub fn enable(name: &str, config: &Config) -> Result<()> {
    let Some(raw) = endpoints(config) else {
        bail!("this tunnel does not send raw TCP packets");
    };
    if !iptables_available() {
        bail!(
            "iptables was not found; install it, or add the rules by hand (docs/raw-protocol.md)"
        );
    }
    // Stop the old definition first: its stop commands remove the old rules.
    if enabled(name) {
        disable(name)?;
    }
    service::write_unit(unit_path(name), &unit_text(name, &raw))
        .context("write the firewall unit")?;
    service::systemctl(&["daemon-reload"])?;
    service::systemctl(&["enable", "--now", "--quiet", &unit_name(name)])
}

/// The two chains the rules live in.
const CHAINS: [(&str, &str); 2] = [("raw", "PREROUTING"), ("mangle", "OUTPUT")];

/// C23: delete arguments for every rule in one `iptables -S CHAIN` listing that carries
/// exactly this tunnel's owner comment (`eztunnel:job` never matches `eztunnel:job2`).
fn owned_deletes(listing: &str, table: &str, owner: &str) -> Vec<Vec<String>> {
    let tag = format!("eztunnel:{owner}");
    listing
        .lines()
        .filter_map(|line| {
            let words: Vec<String> = line
                .split_whitespace()
                .map(|word| word.trim_matches('"').to_string())
                .collect();
            let owned = words.windows(2).any(|pair| pair[0] == "--comment" && pair[1] == tag);
            (owned && words.first().is_some_and(|w| w == "-A")).then(|| {
                let mut args: Vec<String> = ["-w", "2", "-t", table, "-D"].map(String::from).to_vec();
                args.extend(words.into_iter().skip(1));
                args
            })
        })
        .collect()
}

/// Rules still tagged for this tunnel, deleting each one found. Returns what could not be
/// removed; `Ok(None)` when iptables is not installed (nothing this tool can inspect).
fn remove_leftovers(owner: &str) -> Result<Option<Vec<String>>> {
    let mut failed = Vec::new();
    for (table, chain) in CHAINS {
        let listing = match Command::new("iptables").args(["-w", "2", "-t", table, "-S", chain]).stderr(Stdio::null()).output() {
            Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout).into_owned(),
            Ok(output) => bail!("iptables -t {table} -S {chain} failed ({})", output.status),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("run iptables"),
        };
        for args in owned_deletes(&listing, table, owner) {
            let ok = Command::new("iptables").args(&args).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
            if !ok {
                failed.push(format!("iptables {}", args.join(" ")));
            }
        }
    }
    Ok(Some(failed))
}

/// Removes the rules and the unit. The unit file is only deleted once no rule tagged for
/// this tunnel remains, so a failed cleanup can be retried.
pub fn disable(name: &str) -> Result<()> {
    if !enabled(name){return Ok(());}
    let stopped = service::systemctl(&["disable", "--now", "--quiet", &unit_name(name)]);
    match remove_leftovers(name)? {
        Some(failed) if !failed.is_empty() => bail!(
            "raw firewall cleanup left {} rule(s) for {name}; the unit is kept for retry:\n{}",
            failed.len(),
            failed.join("\n")
        ),
        Some(_) => {}
        None => super::ui::warn("iptables is not installed, so leftover raw firewall rules cannot be checked."),
    }
    stopped.context("raw firewall cleanup failed; retaining its unit for retry")?;
    match std::fs::remove_file(unit_path(name)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove the firewall unit"),
    }
    service::systemctl(&["daemon-reload"])
}

/// Brings the rules in line with the tunnel's current ports after it was edited: re-applied when
/// the ports changed, removed when the tunnel no longer sends raw TCP packets. Does nothing when
/// the operator never switched them on.
pub fn refresh(name: &str, config: &Config) -> Result<()> {
    if !enabled(name) {
        return Ok(());
    }
    match endpoints(config) {
        None => disable(name),
        Some(raw) => {
            let current = std::fs::read_to_string(unit_path(name)).unwrap_or_default();
            if current == unit_text(name, &raw) {
                Ok(())
            } else {
                enable(name, config)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(transport: &str, raw: serde_json::Value) -> Config {
        serde_json::from_value(json!({
            "mode": "client",
            "tunnel_key": "k7m2q-9xa4b-c3d5e-f6g7h-j8k9m",
            "allowed_targets": ["127.0.0.1:*"],
            "paths": [{"addr": "192.0.2.7:4443", "transport": transport, "raw": raw}],
        }))
        .unwrap()
    }

    fn tcp_raw(extra: serde_json::Value) -> serde_json::Value {
        let mut raw = json!({"profile": "tcp", "peer_ip": "192.0.2.7", "l4_port": 4443,
                             "interface": "eth0"});
        raw.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        raw
    }

    #[test]
    fn only_raw_tcp_tunnels_need_the_rules() {
        for transport in ["fec-raw", "fec-raw-gaming", "tun"] {
            let found = endpoints(&config(transport, tcp_raw(json!({})))).unwrap();
            assert_eq!(
                found.endpoints[0].peer,
                Some("192.0.2.7".parse().unwrap()),
                "{transport}"
            );
            assert_eq!(found.endpoints[0].ports, vec![4443, 4444], "{transport}");
        }
        for profile in ["udp", "icmp", "gre", "ipip", "raw"] {
            let raw = tcp_raw(json!({"profile": profile}));
            assert_eq!(endpoints(&config("fec-raw", raw)), None, "{profile}");
        }
        // Protocol 58 mode carries no TCP header.
        assert_eq!(
            endpoints(&config("tun", tcp_raw(json!({"proto58_mode": true})))),
            None
        );
    }

    #[test]
    fn ports_follow_the_source_port_rules_of_the_encoder() {
        let explicit =
            endpoints(&config("fec-raw", tcp_raw(json!({"source_port": 50000})))).unwrap();
        assert_eq!(explicit.endpoints[0].ports, vec![4443, 50000]);
        let top = endpoints(&config("fec-raw", tcp_raw(json!({"l4_port": 65535})))).unwrap();
        assert_eq!(top.endpoints[0].ports, vec![65535, 65534]);
    }

    #[test]
    fn spoofed_addresses_limit_the_rules_by_port_only() {
        let spoofed = endpoints(&config(
            "fec-raw",
            tcp_raw(json!({"spoof_src_ip": "198.51.100.9"})),
        ))
        .unwrap();
        assert_eq!(spoofed.endpoints[0].peer, None);
        let commands: Vec<String> = rules(&spoofed, "job")
            .iter()
            .map(|r| r.command("-I"))
            .collect();
        assert!(
            commands
                .iter()
                .all(|c| !c.contains(" -s ") && !c.contains(" -d "))
        );
    }

    fn one_endpoint(peer: Option<&str>, ports: &[u16]) -> RawTcp {
        RawTcp {
            endpoints: vec![RawEndpoint {
                peer: peer.map(|p| p.parse().unwrap()),
                ports: ports.to_vec(),
            }],
        }
    }

    #[test]
    fn rules_are_scoped_to_the_peer_and_the_two_ports() {
        let raw = one_endpoint(Some("192.0.2.7"), &[4443, 4444]);
        let commands: Vec<String> = rules(&raw, "job").iter().map(|r| r.command("-I")).collect();
        assert_eq!(
            commands,
            vec![
                "iptables -w 2 -t raw -I PREROUTING -p tcp -s 192.0.2.7 -m comment --comment eztunnel:job --dport 4443 -j CT --notrack",
                "iptables -w 2 -t mangle -I OUTPUT -p tcp -d 192.0.2.7 -m comment --comment eztunnel:job --sport 4443 --tcp-flags RST RST -j DROP",
                "iptables -w 2 -t raw -I PREROUTING -p tcp -s 192.0.2.7 -m comment --comment eztunnel:job --dport 4444 -j CT --notrack",
                "iptables -w 2 -t mangle -I OUTPUT -p tcp -d 192.0.2.7 -m comment --comment eztunnel:job --sport 4444 --tcp-flags RST RST -j DROP",
            ]
        );
        assert_eq!(
            rules(&raw, "job")[0].command("-C"),
            "iptables -w 2 -t raw -C PREROUTING -p tcp -s 192.0.2.7 -m comment --comment eztunnel:job --dport 4443 -j CT --notrack"
        );
    }

    #[test]
    fn every_raw_endpoint_gets_rules_once() {
        let mut two = config("fec-raw", tcp_raw(json!({})));
        let mut second = two.paths[0].clone();
        let mut raw = second.raw.clone().unwrap();
        raw.peer_ip = "192.0.2.8".parse().unwrap();
        raw.l4_port = 5000;
        second.raw = Some(raw);
        // The same endpoint twice adds nothing.
        two.paths.push(two.paths[0].clone());
        two.paths.push(second);
        let found = endpoints(&two).unwrap();
        assert_eq!(found.endpoints.len(), 3);
        let commands: Vec<String> = rules(&found, "job")
            .iter()
            .map(|r| r.command("-I"))
            .collect();
        assert_eq!(commands.len(), 8, "{commands:#?}");
        assert!(
            commands
                .iter()
                .any(|c| c.contains("-s 192.0.2.8") && c.contains("--dport 5000"))
        );
        // A tunnel whose other endpoint is not raw TCP still gets rules for the raw TCP one.
        let mut mixed = config("fec-raw", tcp_raw(json!({"profile": "udp"})));
        mixed
            .paths
            .push(config("fec-raw", tcp_raw(json!({}))).paths[0].clone());
        assert_eq!(endpoints(&mixed).unwrap().endpoints.len(), 1);
    }

    #[test]
    fn two_tunnels_with_the_same_port_have_separate_rules() {
        let raw = one_endpoint(Some("192.0.2.7"), &[4443]);
        let first = rules(&raw, "one");
        let second = rules(&raw, "two");
        assert!(first.iter().all(|rule| !second.contains(rule)));
        // So stopping "one" (its -D commands) cannot remove a rule of "two".
        let stop_one = unit_text("one", &raw);
        assert!(!stop_one.contains("eztunnel:two"));
    }

    #[test]
    fn the_unit_adds_each_rule_once_and_removes_every_rule_on_stop() {
        let raw = one_endpoint(Some("192.0.2.7"), &[4443, 4444]);
        let text = unit_text("job", &raw);
        assert!(text.contains("Before=eztunnel-job.service"));
        assert!(text.contains("WantedBy=eztunnel-job.service"));
        assert!(text.contains("Type=oneshot") && text.contains("RemainAfterExit=yes"));
        let starts = text.lines().filter(|l| l.starts_with("ExecStart=")).count();
        let stops: Vec<&str> = text.lines().filter(|l| l.starts_with("ExecStop=")).collect();
        assert_eq!((starts, stops.len()), (4, 1));
        // Idempotent add: check first, insert only when the check fails.
        assert!(text.contains("-C PREROUTING -p tcp -s 192.0.2.7 -m comment --comment eztunnel:job --dport 4443 -j CT --notrack 2>/dev/null || iptables -w 2 -t raw -I PREROUTING"));
        // C23: deletion failures are not masked, every rule is attempted, absent is fine.
        let stop = stops[0];
        assert!(!stop.starts_with("ExecStop=-"), "{stop}");
        assert_eq!(stop.matches(" -D ").count(), 4, "{stop}");
        assert!(stop.contains("while iptables -w 2 -t mangle -C OUTPUT"));
        assert!(stop.contains("|| { rc=1; break; }") && stop.ends_with("exit $$rc\""), "{stop}");
        // C24: stopping the tunnel stops this unit too.
        assert!(text.contains("PartOf=eztunnel-job.service"));
        // A tunnel name has no dot, so a tunnel can never be called like this unit.
        assert_eq!(unit_name("job"), "eztunnel-job.firewall.service");
    }

    /// C23: leftovers are found by exact owner tag in `iptables -S` output.
    #[test]
    fn leftover_rules_are_matched_by_exact_owner_tag() {
        let listing = "-P PREROUTING ACCEPT\n\
-A PREROUTING -s 192.0.2.7/32 -p tcp -m comment --comment eztunnel:job -m tcp --dport 4443 -j CT --notrack\n\
-A PREROUTING -s 192.0.2.7/32 -p tcp -m comment --comment eztunnel:job2 -m tcp --dport 4443 -j CT --notrack\n\
-A PREROUTING -p tcp -m comment --comment \"eztunnel:job\" -m tcp --dport 4444 -j CT --notrack\n\
-A PREROUTING -p udp -j ACCEPT\n";
        let deletes = owned_deletes(listing, "raw", "job");
        assert_eq!(deletes.len(), 2, "{deletes:?}");
        assert_eq!(
            deletes[0].join(" "),
            "-w 2 -t raw -D PREROUTING -s 192.0.2.7/32 -p tcp -m comment --comment eztunnel:job -m tcp --dport 4443 -j CT --notrack"
        );
        assert!(deletes[1].contains(&"eztunnel:job".to_string()));
        assert!(owned_deletes(listing, "raw", "jo").is_empty());
        assert!(owned_deletes("", "mangle", "job").is_empty());
    }
}
