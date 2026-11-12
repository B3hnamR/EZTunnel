//! One side of one case: the temporary configuration (written by the wizard's own `Plan`, so it is
//! what a real tunnel would use), the port, and the in-process tunnel that runs it.
use super::{CaseSpec, Options, Side, Variant};
use crate::config::{Config, Transport};
use crate::manager::plan::{
    self, Carry, Direction, IpMode, Plan, PortRule, Protocol, RawPlan, TunPlan,
};
use crate::stats::Stats;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, OnceLock, atomic::Ordering::Relaxed},
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;

/// What one side needs to know to build its half of a case.
#[derive(Debug, Clone)]
pub struct Setup {
    pub spec: CaseSpec,
    /// This machine.
    pub side: Side,
    pub key: String,
    pub iran_ip: IpAddr,
    pub foreign_ip: IpAddr,
    /// Port of the connection between the servers.
    pub port: u16,
    /// Iran only: the local port the measurements connect to.
    pub map_port: u16,
    /// Port of the test service on the foreign server's 127.0.0.1.
    pub service_port: u16,
    /// Iran only: also map the port for UDP (the UDP measurement).
    pub udp: bool,
}

impl Setup {
    /// Whether this side opens the connection (raw transports: neither does).
    pub fn dials(&self) -> bool {
        !plan::is_raw(self.spec.transport) && self.spec.dialer == Some(self.side)
    }

    /// Whether this side binds the case's port: the side that does not dial, and for raw
    /// transports the Iran server (both sides use the same port there).
    pub fn listens(&self) -> bool {
        if plan::is_raw(self.spec.transport) {
            self.side == Side::Iran
        } else {
            !self.dials()
        }
    }

    pub fn config(&self) -> Result<Value> {
        let side = match self.side {
            Side::Iran => plan::Side::Iran,
            Side::Foreign => plan::Side::Foreign,
        };
        let direction = match self.spec.dialer {
            Some(Side::Iran) => Direction::Direct,
            _ => Direction::Reverse,
        };
        let mut plan = Plan::new(self.key.clone(), side, direction, self.spec.transport);
        // Match the control channel's wire version.
        plan.wire_version = 2;
        plan.tunnel_port = self.port;
        let other = match self.side {
            Side::Iran => self.foreign_ip,
            Side::Foreign => self.iran_ip,
        };
        let own = match self.side {
            Side::Iran => self.iran_ip,
            Side::Foreign => self.foreign_ip,
        };
        if own.is_loopback() {
            // Tests run both sides on one machine; a wildcard UDP listener there would answer
            // from the wrong local address.
            plan.listen_ip = own.to_string();
        } else if other.is_ipv6() {
            plan.listen_ip = "::".into();
        }
        plan.peer_host = Some(other.to_string());
        let target = format!("127.0.0.1:{}", self.service_port);
        plan.carry = Carry::Ports;
        plan.protocol = if self.udp && self.side == Side::Iran {
            Protocol::Both
        } else {
            Protocol::Tcp
        };
        plan.public_ip = "127.0.0.1".into();
        plan.ports = vec![PortRule {
            listen: self.map_port,
            target: target.clone(),
        }];
        plan.allowed = vec![target];
        match self.spec.variant {
            Variant::Plain | Variant::Fragment => {}
            Variant::BrowserTls => plan.tls_profile = crate::config::TlsProfile::Chrome,
            Variant::TlsFragment => plan.tls_fragment = true,
            Variant::Congestion => {
                plan.tcp_congestion = Some(super::CONGESTION_TEST_ALGORITHM.into())
            }
            Variant::Pacer => plan.fec_pacer = true,
        }
        if plan::is_raw(self.spec.transport) {
            let IpAddr::V4(peer_ip) = other else {
                bail!("raw transports need the other server's IPv4 address");
            };
            let profile = self.spec.profile.unwrap_or_default();
            let raw = RawPlan {
                profile: super::profile_name(profile).into(),
                peer_ip,
                ip_mode: IpMode::Normal,
                interface: None,
                local_ip: None,
                mirage: None,
            };
            if self.spec.transport == Transport::Tun {
                let fragment = self.spec.variant == Variant::Fragment;
                // Raw TUN carries IP packets between two TUN interfaces; the test map runs over
                // the forwarding service inside them, as "TUN + ports" in the wizard does. The
                // MTU fits this server's interface and stays at most 1280, so both sides agree —
                // except the Fragment variant, which deliberately asks for more than one outer
                // packet can carry, since that is the one thing it is testing.
                let mtu = if fragment {
                    super::FRAGMENT_TEST_MTU
                } else {
                    crate::manager::iface::plan_tun_mtu(&raw)
                        .map_or(TUN_MTU, |(mtu, _, _)| mtu.min(TUN_MTU))
                };
                let (local_ip, peer_ip) = match self.side {
                    Side::Iran => (TUN_IRAN, TUN_FOREIGN),
                    Side::Foreign => (TUN_FOREIGN, TUN_IRAN),
                };
                plan.carry = Carry::TunPorts;
                plan.tun = Some(TunPlan {
                    name: TUN_NAME.into(),
                    local_ip: local_ip.into(),
                    peer_ip: peer_ip.into(),
                    mtu,
                    forwarding_port: Some(TUN_FORWARDING_PORT),
                    fragment,
                });
            }
            plan.raw = Some(raw);
        }
        let mut config = plan.to_json()?;
        if self.spec.transport == Transport::Tun {
            config["tun"]["mtu_probe"] = true.into();
        }
        // The live status line every minute is noise here; the checker reads the counters.
        config["stats_interval_sec"] = 0.into();
        Ok(config)
    }
}

/// The TUN interface of a raw TUN case (exists only while the case runs).
pub const TUN_NAME: &str = "ezchk0";
/// The TUN addresses of a raw TUN case: a private pair no tunnel the wizard writes uses.
pub const TUN_IRAN: &str = "10.234.170.1";
pub const TUN_FOREIGN: &str = "10.234.170.2";
pub const TUN_MTU: u16 = 1280;
pub const TUN_FORWARDING_PORT: u16 = 47476;

/// Why a case cannot run on this machine, if it cannot.
pub fn impossible(spec: &CaseSpec, iran_ip: IpAddr, foreign_ip: IpAddr) -> Option<String> {
    if plan::is_raw(spec.transport) {
        if !crate::manager::store::is_root() {
            return Some("needs root (run the manager with sudo)".into());
        }
        if !(iran_ip.is_ipv4() && foreign_ip.is_ipv4()) {
            return Some("needs the IPv4 addresses of both servers".into());
        }
        if !cfg!(target_os = "linux") {
            return Some("needs Linux".into());
        }
    }
    if spec.transport == Transport::Tcp6 && !(iran_ip.is_ipv6() && foreign_ip.is_ipv6()) {
        return Some("needs the IPv6 addresses of both servers".into());
    }
    if spec.variant == Variant::BrowserTls && !cfg!(feature = "browser-tls") {
        return Some("this build has no browser TLS".into());
    }
    None
}

fn tcp_free(port: u16) -> bool {
    std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

fn udp_free(port: u16) -> bool {
    std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

/// The FEC-UDP knock port that goes with `port` (the rule of `fec_carrier`).
fn knock_port(port: u16) -> u16 {
    if port <= 55_535 {
        port + 10_000
    } else {
        port - 1000
    }
}

fn port_free(transport: Transport, port: u16) -> bool {
    match transport {
        Transport::FecUdp => udp_free(port) && udp_free(knock_port(port)),
        Transport::Kcp => udp_free(port),
        // Raw packets have no socket; a program on the port would get them too.
        Transport::FecRaw | Transport::FecRawGaming | Transport::Tun | Transport::Mirage => {
            tcp_free(port) && udp_free(port)
        }
        _ => tcp_free(port),
    }
}

fn random_port(transport: Transport) -> Result<u16> {
    for _ in 0..200 {
        let port = 20_000 + (crate::stealth::random_below(35_000)? as u16);
        if port_free(transport, port) {
            return Ok(port);
        }
    }
    bail!("no free port found")
}

/// Ordinary HTTPS ports: the ones Cloudflare proxies, which filters treat as web traffic. The TLS
/// transports use the first free one when no port is chosen.
pub const TLS_PORTS: [u16; 6] = [443, 8443, 2053, 2083, 2087, 2096];
/// The same for plain HTTP; the ws, http and xhttp transports use the first free one.
pub const HTTP_PORTS: [u16; 7] = [80, 8080, 8880, 2052, 2082, 2086, 2095];

fn chosen(transport: Transport, port: u16) -> Result<u16> {
    if port_free(transport, port) {
        Ok(port)
    } else {
        bail!("port {port} is in use on this server")
    }
}

/// The port the listening side uses for `spec`: the one the user chose, otherwise the first free
/// web port for the TLS and HTTP transports, otherwise a free random port.
pub fn choose_port(spec: &CaseSpec, options: &Options) -> Result<u16> {
    let transport = spec.transport;
    let web: &[u16] = if transport.uses_tls() {
        if options.tls_port != 0 {
            return chosen(transport, options.tls_port);
        }
        &TLS_PORTS
    } else {
        if options.port != 0 {
            return chosen(transport, options.port);
        }
        if transport.uses_http() {
            &HTTP_PORTS
        } else {
            &[]
        }
    };
    match web.iter().find(|port| port_free(transport, **port)) {
        Some(port) => Ok(*port),
        None => random_port(transport),
    }
}

/// A free local port for the Iran server's test map.
pub fn local_port() -> Result<u16> {
    // The map is TCP and UDP on the same number, so both must be free.
    for _ in 0..50 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    bail!("no local port is free for both TCP and UDP")
}

/// How long a freshly started tunnel is watched for a start-up failure.
pub const START_WAIT: Duration = Duration::from_millis(300);

/// One side of a running case. Dropping it stops the tunnel and removes its firewall rules.
pub struct Running {
    task: JoinHandle<Result<()>>,
    pub stats: Arc<Stats>,
    firewall: Vec<crate::manager::rawfw::Rule>,
    /// Time from the start until the first authenticated session.
    handshake: Arc<OnceLock<Duration>>,
    watcher: JoinHandle<()>,
}

impl Running {
    /// Starts the tunnel for `setup` and gives it a moment to fail on start-up (port in use, no
    /// permission), which is reported as an error.
    pub async fn start(setup: &Setup) -> Result<Self> {
        let value = setup.config()?;
        let config: Config = plan::check(&value).context("test configuration")?;
        let mut firewall = Vec::new();
        if let Some(raw) = crate::manager::rawfw::endpoints(&config)
            && crate::manager::rawfw::iptables_available()
        {
            firewall = insert_rules(crate::manager::rawfw::rules(&raw, "check")).await;
        }
        let stats = Arc::new(Stats::default());
        let started = Instant::now();
        let task = tokio::spawn(crate::engine::run_with_stats(config, stats.clone()));
        let handshake = Arc::new(OnceLock::new());
        let watcher = {
            let (stats, handshake) = (stats.clone(), handshake.clone());
            tokio::spawn(async move {
                while stats.sessions_total.load(Relaxed) == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let _ = handshake.set(started.elapsed());
            })
        };
        let mut running = Self {
            task,
            stats,
            firewall,
            handshake,
            watcher,
        };
        tokio::time::sleep(START_WAIT).await;
        if running.task.is_finished() {
            let outcome = (&mut running.task).await;
            let error = match outcome {
                Ok(Err(error)) => format!("{error:#}"),
                Ok(Ok(())) => "the test tunnel stopped at once".into(),
                Err(error) => error.to_string(),
            };
            bail!("{error}");
        }
        Ok(running)
    }

    /// Time from the start until the first authenticated session, once there was one.
    pub fn handshake(&self) -> Option<Duration> {
        self.handshake.get().copied()
    }

    /// Whether the tunnel task ended (it never ends on its own while healthy).
    pub fn finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// How long one diagnostic firewall command may run (its own lock wait is `-w 2`).
const FIREWALL_DEADLINE: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Succeeded,
    Failed,
    /// Killed at the deadline and reaped.
    TimedOut,
}

/// C01: runs a command as an owned child with a wall deadline; on timeout it is killed and
/// reaped, so neither a held xtables lock nor a stuck process can hold up the checker.
fn run_bounded(program: &str, args: &[String], deadline: Duration) -> Outcome {
    let Ok(mut child) = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return Outcome::Failed;
    };
    let until = Instant::now() + deadline;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return if status.success() { Outcome::Succeeded } else { Outcome::Failed },
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Outcome::TimedOut;
            }
        }
    }
}

fn run_iptables(args: &[String]) -> Outcome {
    run_bounded("iptables", args, FIREWALL_DEADLINE)
}

/// Inserts the rules off the async workers; returns those that were added. If the caller
/// is cancelled (Stop) meanwhile, the rules added so far are removed at once instead of
/// being left behind unrecorded.
async fn insert_rules(rules: Vec<crate::manager::rawfw::Rule>) -> Vec<crate::manager::rawfw::Rule> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let added: Vec<_> = rules
            .into_iter()
            .filter(|rule| match run_iptables(&rule.args("-I")) {
                Outcome::Succeeded => true,
                outcome => {
                    tracing::warn!(?outcome, rule = %rule.command("-I"), "checker firewall rule not added");
                    false
                }
            })
            .collect();
        if let Err(added) = sender.send(added) {
            for left in remove_rules(&added) {
                tracing::warn!(rule = %left, "checker firewall rule could not be removed; delete it by hand");
            }
        }
    });
    receiver.await.unwrap_or_default()
}

/// Removes every recorded rule, each within the deadline, and names the ones left behind.
fn remove_rules(rules: &[crate::manager::rawfw::Rule]) -> Vec<String> {
    rules
        .iter()
        .filter(|rule| run_iptables(&rule.args("-D")) != Outcome::Succeeded)
        .map(|rule| rule.command("-D"))
        .collect()
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
        self.watcher.abort();
        // Bounded: at most FIREWALL_DEADLINE per recorded rule (4 rules per raw endpoint), and
        // off the async workers when a runtime is running, so cleanup never stalls other tasks.
        let rules = std::mem::take(&mut self.firewall);
        if rules.is_empty() {
            return;
        }
        let cleanup = move || {
            for left in remove_rules(&rules) {
                tracing::warn!(rule = %left, "checker firewall rule could not be removed; delete it by hand");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => drop(runtime.spawn_blocking(cleanup)),
            Err(_) => cleanup(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C01: a command that never exits is killed and reaped at the deadline; ordinary
    /// success/failure and a missing program are reported without waiting.
    #[test]
    fn firewall_commands_have_a_wall_deadline_and_are_reaped() {
        let started = Instant::now();
        assert_eq!(run_bounded("sleep", &["30".into()], Duration::from_millis(300)), Outcome::TimedOut);
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(300) && took < Duration::from_secs(3), "{took:?}");
        assert_eq!(run_bounded("true", &[], FIREWALL_DEADLINE), Outcome::Succeeded);
        assert_eq!(run_bounded("false", &[], FIREWALL_DEADLINE), Outcome::Failed);
        assert_eq!(run_bounded("/nonexistent/eztunnel-iptables", &[], FIREWALL_DEADLINE), Outcome::Failed);
    }

    fn setup(transport: Transport, dialer: Option<Side>, side: Side) -> Setup {
        Setup {
            spec: CaseSpec {
                id: 0,
                transport,
                dialer,
                variant: Variant::Plain,
                profile: None,
            },
            side,
            key: crate::tunnel_key::TunnelKey::generate().unwrap().display(),
            iran_ip: "192.0.2.1".parse().unwrap(),
            foreign_ip: "192.0.2.2".parse().unwrap(),
            port: 31000,
            map_port: 32000,
            service_port: 33000,
            udp: false,
        }
    }

    #[test]
    fn both_halves_are_valid_wizard_configurations() {
        for transport in super::super::RECOMMENDED
            .into_iter()
            .chain([Transport::Parallax])
        {
            for dialer in [Side::Iran, Side::Foreign] {
                for side in [Side::Iran, Side::Foreign] {
                    let setup = setup(transport, Some(dialer), side);
                    let value = setup.config().unwrap();
                    assert_eq!(
                        value["wire_version"], 2,
                        "carrier probes explicitly select their wire setting"
                    );
                    let config = plan::check(&value)
                        .unwrap_or_else(|e| panic!("{transport:?} {dialer:?} {side:?}: {e:#}"));
                    assert_eq!(setup.dials(), dialer == side);
                    assert_eq!(setup.listens(), dialer != side);
                    if side == Side::Iran {
                        let maps = &config.listeners[0].maps;
                        assert_eq!(maps.len(), 1);
                        assert_eq!(maps[0].bind, "127.0.0.1:32000", "the map is never public");
                    } else {
                        assert_eq!(config.allowed_targets, vec!["127.0.0.1:33000".to_string()]);
                    }
                }
            }
        }
    }

    #[test]
    fn raw_tun_cases_are_valid_tun_plus_ports_configurations() {
        for profile in super::super::TUN_PROFILES {
            for side in [Side::Iran, Side::Foreign] {
                let mut setup = setup(Transport::Tun, None, side);
                setup.spec.profile = Some(profile);
                let value = setup.config().unwrap();
                let config =
                    plan::check(&value).unwrap_or_else(|e| panic!("{profile:?} {side:?}: {e:#}"));
                let tun = config.tun.as_ref().expect("a TUN section");
                assert_eq!(tun.name, TUN_NAME);
                assert_eq!(tun.forwarding_port, Some(TUN_FORWARDING_PORT));
                assert!(tun.mtu <= TUN_MTU);
                assert_eq!(setup.listens(), side == Side::Iran);
                let inner = config.tun_forwarding_config().unwrap().expect("forwarding");
                if side == Side::Iran {
                    assert_eq!(inner.listeners[0].maps[0].bind, "127.0.0.1:32000");
                }
            }
        }
    }

    #[test]
    fn the_congestion_pacer_and_fragment_variants_produce_valid_configurations() {
        // Congestion: the dialing side only, like local_address/tls_profile already work.
        let mut dialer_setup = setup(Transport::Wss, Some(Side::Foreign), Side::Foreign);
        dialer_setup.spec.variant = Variant::Congestion;
        let value = dialer_setup.config().unwrap();
        let config = plan::check(&value).unwrap();
        assert_eq!(
            config.paths[0].tcp_congestion.as_deref(),
            Some(super::super::CONGESTION_TEST_ALGORITHM)
        );
        // The listening side's own config is untouched: the override is the dialer's own choice.
        let mut listener_setup = setup(Transport::Wss, Some(Side::Foreign), Side::Iran);
        listener_setup.spec.variant = Variant::Congestion;
        let value = listener_setup.config().unwrap();
        let config = plan::check(&value).unwrap();
        assert_eq!(config.listeners[0].tcp_congestion, None);

        // Pacer: fec.pacer on for a KCP-family transport.
        let mut pacer_setup = setup(Transport::FecUdp, Some(Side::Foreign), Side::Foreign);
        pacer_setup.spec.variant = Variant::Pacer;
        let value = pacer_setup.config().unwrap();
        let config = plan::check(&value).unwrap();
        assert!(config.paths[0].fec.pacer);

        // Fragment: TUN with fragmentation on and an MTU bigger than TUN_MTU (the plain cases'
        // ceiling), so the case genuinely needs to split a packet, not just carry small ones.
        let mut tun_setup = setup(Transport::Tun, None, Side::Iran);
        tun_setup.spec.variant = Variant::Fragment;
        tun_setup.spec.profile = Some(crate::raw_packet::RawProfile::Tcp);
        let value = tun_setup.config().unwrap();
        let config = plan::check(&value).unwrap();
        let tun = config.tun.as_ref().expect("a TUN section");
        assert!(tun.fragment);
        assert_eq!(tun.mtu, super::super::FRAGMENT_TEST_MTU);
        assert!(
            tun.mtu > TUN_MTU,
            "must exceed the plain cases' ceiling or nothing is actually fragmented"
        );
    }

    #[test]
    fn raw_cases_and_impossible_ones() {
        let raw = setup(Transport::FecRaw, None, Side::Iran);
        assert!(raw.listens() && !raw.dials());
        assert!(!setup(Transport::FecRaw, None, Side::Foreign).listens());
        let value = raw.config().unwrap();
        assert_eq!(value["listeners"][0]["raw"]["peer_ip"], "192.0.2.2");
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let tcp6 = CaseSpec {
            id: 0,
            transport: Transport::Tcp6,
            dialer: Some(Side::Iran),
            variant: Variant::Plain,
            profile: None,
        };
        assert!(impossible(&tcp6, v4, v4).is_some());
        assert!(impossible(&tcp6, v6, v6).is_none());
    }

    #[test]
    fn a_chosen_port_in_use_is_reported() {
        let busy = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let options = Options {
            port: busy.local_addr().unwrap().port(),
            ..Options::default()
        };
        let spec = CaseSpec {
            id: 0,
            transport: Transport::Tcp,
            dialer: Some(Side::Foreign),
            variant: Variant::Plain,
            profile: None,
        };
        assert!(choose_port(&spec, &options).is_err());
        let random = choose_port(
            &spec,
            &Options {
                port: 0,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(random >= 20_000);
        // HTTP and TLS transports take a free web port (as a normal user, 80 and 443 are not
        // available, so one of the high ones).
        let web = |transport| CaseSpec { transport, ..spec };
        let http = choose_port(&web(Transport::Ws), &Options::default()).unwrap();
        assert!(HTTP_PORTS.contains(&http) || http >= 20_000, "{http}");
        let tls = choose_port(&web(Transport::Wss), &Options::default()).unwrap();
        assert!(TLS_PORTS.contains(&tls) || tls >= 20_000, "{tls}");
    }
}
