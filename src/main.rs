// musl's allocator is slow for the many small buffers each packet needs (see Cargo.toml).
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use eztunnel::{
    config::{Config, generate_certificate, generate_keypair},
    engine,
};
use std::path::PathBuf;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[derive(Parser)]
#[command(
    version,
    about = "Encrypted tunnels between two servers. Run without arguments to open the manager."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(short, long, conflicts_with = "gen")]
    config: Option<PathBuf>,
    #[arg(long, requires = "config")]
    check: bool,
    #[arg(long, value_enum)]
    r#gen: Option<ExampleMode>,
}

#[derive(Subcommand)]
enum Command {
    /// Open the interactive tunnel manager (the same as running without arguments).
    Menu,
    /// Print a fresh tunnel key to share between the two servers.
    Key,
    /// Show what each preset (balanced, many-users, gaming, streaming, max-capacity) would change
    /// in a tunnel configuration, or apply one: the result is printed, or saved with --write
    /// (restart the tunnel afterwards). Set the same preset on both servers of a tunnel.
    Preset {
        /// The tunnel's configuration file.
        config: PathBuf,
        /// The preset to apply; without it every preset and its changes are listed.
        preset: Option<String>,
        /// Save the result in the configuration file instead of printing it.
        #[arg(long, requires = "preset")]
        write: bool,
    },
    /// Show (or with --apply set) kernel network settings that help long-distance tunnels,
    /// such as BBR. --undo restores the previous values.
    Optimize {
        #[arg(long, conflicts_with = "undo")]
        apply: bool,
        #[arg(long)]
        undo: bool,
    },
    /// Find which transports work between two servers, in which direction and how fast. Start on
    /// one server (prints a code), join on the other with the code.
    Check {
        #[command(subcommand)]
        action: CheckCommand,
    },
    /// Diagnose a link using only explicitly selected peers and ports.
    Linktest {
        #[command(subcommand)]
        action: LinkTestCommand,
    },
    /// Test explicitly permitted spoof sources/profiles, one direction at a time.
    Spooftest {
        #[command(subcommand)]
        action:SpoofTestCommand,
    },
    /// Install this program file over the installed one, keep the old one, restart the running
    /// tunnels and go back by itself if one does not stay up.
    Update {
        /// Where the program is installed.
        #[arg(long, default_value = eztunnel::manager::update::INSTALLED)]
        target: PathBuf,
        /// Install even when the installed version is newer or the same.
        #[arg(long)]
        allow_downgrade: bool,
        /// Only replace the file; leave the running tunnels as they are.
        #[arg(long)]
        no_restart: bool,
    },
    /// Go back to the program that was installed before the last update.
    Rollback {
        #[arg(long, default_value = eztunnel::manager::update::INSTALLED)]
        target: PathBuf,
        #[arg(long)]
        no_restart: bool,
    },
    /// Show the TLS ClientHello a TLS carrier would send (JA3, JA4, extension order), to compare with
    /// a browser. Nothing leaves this machine.
    Tlscheck {
        /// A tunnel configuration file; without it a sample wss path is checked.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Check this profile instead of the one in the configuration.
        #[arg(long, value_enum)]
        profile: Option<ProfileArg>,
        /// The server name to send (SNI) for the sample path.
        #[arg(long, default_value = "www.example.org")]
        sni: String,
    },
    /// Print every numeric setting with its default and allowed range, as JSON.
    Settings,
    /// Print a fresh random access token for `xhttp.access_token`.
    Token,
    /// Generate a fresh keypair. Existing files are never replaced.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// The web dashboard: set it up once, then serve it.
    #[cfg(feature = "dashboard")]
    Dashboard {
        #[command(subcommand)]
        action: DashboardCommand,
    },
    /// Let a dashboard on another server manage this server's tunnels.
    #[cfg(feature = "dashboard")]
    Agent {
        #[command(subcommand)]
        action: AgentCommand,
    },
    /// Generate a local TLS certificate. Copy cert.pem to the client's ca_file.
    Certgen {
        #[arg(long)]
        out: PathBuf,
        /// Certificate DNS name or IP address; may be repeated.
        #[arg(long, default_value = "localhost")]
        name: Vec<String>,
    },
}

#[cfg(feature = "dashboard")]
#[derive(Subcommand)]
enum AgentCommand {
    /// Join this server to a dashboard with the one-time code it shows, and start the agent.
    Join { code: String },
    /// Run the agent (the eztunnel-agent service does this).
    Run {
        #[arg(long, default_value = "/etc/eztunnel-agent")]
        config_dir: PathBuf,
    },
    /// Stop the agent and forget the dashboard. Tunnels on this server keep running.
    Leave,
}

#[cfg(feature = "dashboard")]
#[derive(Subcommand)]
enum DashboardCommand {
    /// Create the settings (a random port, a random password shown once, a certificate) and
    /// start the dashboard's service, which also starts with the server.
    Setup {
        /// Use this port instead of a random one.
        #[arg(long)]
        port: Option<u16>,
        /// Only create the settings; run the dashboard yourself with `eztunnel dashboard serve`.
        #[arg(long)]
        no_service: bool,
        #[arg(long, default_value = eztunnel::dashboard::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Show whether the dashboard runs, its address and certificate, and whether this server is
    /// joined to a dashboard.
    Status {
        #[arg(long, default_value = eztunnel::dashboard::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Move the dashboard to another port.
    Port {
        port: u16,
        #[arg(long, default_value = eztunnel::dashboard::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Stop the dashboard and remove its service. Settings, history and backups stay unless
    /// --delete-data is given. Tunnels keep running.
    Remove {
        /// Also delete the settings, history and backups.
        #[arg(long)]
        delete_data: bool,
        #[arg(long, default_value = eztunnel::dashboard::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Run the dashboard over HTTPS.
    Serve {
        #[arg(long, default_value = eztunnel::dashboard::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
        /// Listen only on this address (default: all addresses).
        #[arg(long)]
        listen: Option<IpAddr>,
    },
    /// Use a Let's Encrypt certificate for this server's address (an IP address works), renewed
    /// automatically; or go back to the self-signed one with --self-signed.
    Certificate {
        /// Order a Let's Encrypt certificate now and keep renewing it.
        #[arg(long, conflicts_with = "self_signed", required_unless_present = "self_signed")]
        lets_encrypt: bool,
        /// Go back to the self-signed certificate.
        #[arg(long)]
        self_signed: bool,
        /// The address the certificate names (default: this server's address).
        #[arg(long)]
        address: Option<String>,
        /// Use Let's Encrypt's staging service (for testing; browsers do not trust it).
        #[arg(long)]
        staging: bool,
        #[arg(long, default_value = eztunnel::dashboard::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Replace the password with a new random one, shown once.
    ResetPassword {
        #[arg(long, default_value = eztunnel::dashboard::DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Serve the interface with sample data on 127.0.0.1 only, over plain HTTP.
    Demo {
        #[arg(long, default_value_t = 47832)]
        port: u16,
        /// Show a fresh install with no tunnels.
        #[arg(long)]
        empty: bool,
    },
}

#[derive(Subcommand)]
enum SpoofTestCommand {
    /// Guided source tests: enter IPs, share an invitation, review saved results.
    Menu,
    /// Internal manager worker: invitation/secret lives in a private file, never argv.
    #[command(hide=true)]
    GuidedHost {#[arg(long)]invitation:PathBuf,#[arg(long)]output:PathBuf},
    #[command(hide=true)]
    GuidedJoin {#[arg(long)]invitation:PathBuf,#[arg(long)]output:PathBuf},
    /// Receive one bounded authenticated candidate run; does not change firewall/routes.
    Listen {#[arg(long)]config:PathBuf,#[arg(long)]bind:SocketAddr},
    /// Send bounded probes only to the configured peer; all missing candidates are reported.
    Run {#[arg(long)]config:PathBuf,#[arg(long)]peer:SocketAddr,#[arg(long)]output:PathBuf},
}

fn print_spoof_row(reverse:bool,row:&eztunnel::spoof_test::Row){
    if row.stage=="receiving-case-complete-awaiting-sender-report"{
        eprintln!("{:<15} {:<8} {:>2}/{:<2} {:>5.1}%  Receiving done; waiting for peer RTT report  {}",row.source,format!("{:?}",row.profile).to_lowercase(),row.received,row.sent,row.loss_percent,if reverse{"Iran -> Foreign"}else{"Foreign -> Iran"});return;
    }
    let status=if row.error.is_some(){"Error"}else if row.received==0{"No receipt"}else if row.received<usize::from(row.sent){"Lossy sample"}else if row.raw_reply_received<usize::from(row.sent){"Received; return lossy"}else{"Passed sample"};
    eprintln!("{:<15} {:<8} {:>2}/{:<2} {:>5.1}% {:>9}  {}  {}",row.source,format!("{:?}",row.profile).to_lowercase(),row.received,row.sent,row.loss_percent,
        row.rtt_p95_ms.map(|v|format!("{v:.1}ms")).unwrap_or_else(||"-".into()),status,if reverse{"Iran -> Foreign"}else{"Foreign -> Iran"});
    if let Some(error)=&row.error{eprintln!("  {error}");}
}

#[derive(Subcommand)]
enum CheckCommand {
    /// Start a check: prints the code for the other server, then waits for it and runs.
    Start {
        /// Which server this is.
        #[arg(long, value_enum)]
        role: RoleArg,
        /// This server's public IP address.
        #[arg(long)]
        this_ip: IpAddr,
        /// The other server's IP address.
        #[arg(long)]
        peer_ip: IpAddr,
        /// find: every transport with its defaults. tune: the --transports with every option each
        /// one has, in --rounds rounds.
        #[arg(long, value_enum, default_value = "find")]
        mode: ModeArg,
        /// How deep each case measures.
        #[arg(long, value_enum, default_value = "standard")]
        preset: PresetArg,
        /// Transports to check, comma separated (default: the preset's; required to tune).
        #[arg(long, value_delimiter = ',')]
        transports: Vec<String>,
        /// Rounds of every case, 1 to 3 (default: 1, or 2 to tune).
        #[arg(long)]
        rounds: Option<u8>,
        /// Raw TUN packet types, comma separated (default: all of tcp,udp,icmp,gre,ipip,raw,dns).
        #[arg(long, value_delimiter = ',')]
        tun_types: Vec<String>,
        /// Which server opens the connections.
        #[arg(long, value_enum, default_value = "both")]
        directions: DirectionsArg,
        /// Port for the TLS transports (0 = the first free of 443, 8443, 2053, 2083, 2087, 2096).
        #[arg(long, default_value_t = 0)]
        tls_port: u16,
        /// Port for the other transports (0 = ws/http/xhttp: the first free of 80, 8080, 8880,
        /// 2052, 2082, 2086, 2095; the rest: a free random port per case).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// TCP port of the checker's own connection; must be open between the servers.
        #[arg(long, default_value_t = eztunnel::checker::DEFAULT_CONTROL_PORT)]
        control_port: u16,
        /// What the ranking of the results favours.
        #[arg(long, value_enum, default_value = "stability")]
        priority: PriorityArg,
        /// Leave out the UDP loss and delay measurement (it adds about 3 seconds per case).
        #[arg(long)]
        no_udp: bool,
        /// Also check TLS transports again with a browser-like TLS ClientHello.
        #[arg(long)]
        also_browser_tls: bool,
        /// Also check TLS transports again with the ClientHello split into fragments.
        #[arg(long)]
        also_tls_fragment: bool,
        /// Check Parallax in stream mode only (by default packet mode is checked too).
        #[arg(long)]
        no_parallax_packet: bool,
        /// Also check each non-raw transport with Game mode on.
        #[arg(long)]
        also_game: bool,
        /// Also check TCP-based transports again with tcp_congestion set to cubic.
        #[arg(long)]
        also_congestion: bool,
        /// Also check kcp/fec-udp/fec-raw(-gaming) again with the adaptive pacer on.
        #[arg(long)]
        also_pacer: bool,
        /// Also check raw TUN again with packet splitting on and an MTU too big for one packet.
        #[arg(long)]
        also_fragment: bool,
        /// Also save the report as JSON here.
        #[arg(long)]
        json: Option<PathBuf>,
        /// Reach the other server's control port at this address instead (the local end of a
        /// forward through a machine both servers can reach, such as an SSH port forward).
        #[arg(long)]
        control_via: Option<SocketAddr>,
    },
    /// Join a check started on the other server.
    Join {
        code: String,
        /// Also save the report as JSON here.
        #[arg(long)]
        json: Option<PathBuf>,
        /// Reach the other server's control port at this address instead (the local end of a
        /// forward through a machine both servers can reach, such as an SSH port forward).
        #[arg(long)]
        control_via: Option<SocketAddr>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RoleArg {
    Iran,
    Foreign,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Find,
    Tune,
}

#[derive(Clone, Copy, ValueEnum)]
enum PresetArg {
    Quick,
    Standard,
    Thorough,
}

#[derive(Clone, Copy, ValueEnum)]
enum DirectionsArg {
    Both,
    Iran,
    Foreign,
}

#[derive(Clone, Copy, ValueEnum)]
enum PriorityArg {
    Stability,
    Speed,
    Hiding,
    Lossy,
}

#[derive(Subcommand)]
enum LinkTestCommand {
    /// Listen for the selected peer's connectivity and throughput probes.
    Listen {
        #[arg(long, default_value = "127.0.0.1:47000")]
        bind: SocketAddr,
        #[arg(long)]
        peer: IpAddr,
        #[arg(long, value_delimiter = ',')]
        extra_ports: Vec<u16>,
        #[arg(long,default_value_t=900,value_parser=clap::value_parser!(u64).range(1..=3600))]
        wait_secs: u64,
        #[arg(long)]
        keep: bool,
    },
    /// Check TCP/UDP in both directions, integrity and local test throughput.
    Probe {
        #[arg(long)]
        peer: SocketAddr,
        #[arg(long)]
        bind: Option<IpAddr>,
        #[arg(long, default_value_t = 0)]
        local_port: u16,
        #[arg(long, value_delimiter = ',')]
        extra_ports: Vec<u16>,
        #[arg(long,default_value="4",value_parser=throughput_seconds)]
        seconds: f64,
        #[arg(long,default_value_t=3,value_parser=clap::value_parser!(u64).range(1..=60))]
        timeout_secs: u64,
        #[arg(long)]
        quick: bool,
        /// Skip the datagram size sweep (the largest UDP datagram that crosses the path).
        #[arg(long)]
        no_mtu: bool,
        /// Print the verdict, notes and advice as text instead of JSON.
        #[arg(long)]
        text: bool,
        #[arg(long)]
        save: Option<PathBuf>,
    },
}

fn throughput_seconds(value: &str) -> std::result::Result<f64, String> {
    let seconds = value
        .parse::<f64>()
        .map_err(|_| "seconds must be a number".to_string())?;
    if seconds.is_finite() && (0.05..=30.0).contains(&seconds) {
        Ok(seconds)
    } else {
        Err("seconds must be 0.05..30".into())
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    Classic,
    Chrome,
}

#[derive(Clone, Copy, ValueEnum)]
enum ExampleMode {
    Server,
    Client,
}

fn example(mode: ExampleMode) -> serde_json::Value {
    match mode {
        ExampleMode::Server => serde_json::json!({
            "_comment":"Server (the Iran side): users connect to a map's bind address. 127.0.0.1 means this machine only; 0.0.0.0:PORT accepts users from other machines. Put the same tunnel key (eztunnel key) in both files and chmod 600 them.",
            "mode":"server", "tunnel_key":"REPLACE-WITH-THE-TUNNEL-KEY",
            "listeners":[{"addr":"0.0.0.0:7000","maps":[
                {"type":"tcp","bind":"127.0.0.1:8080","target":"127.0.0.1:8080"}
            ]}]
        }),
        ExampleMode::Client => serde_json::json!({
            "_comment":"Client (the foreign side): set addr to the server's address and port, use the same tunnel key as the server, and list what this machine may reach in allowed_targets (host:port, host:* or *).",
            "mode":"client", "tunnel_key":"REPLACE-WITH-THE-TUNNEL-KEY",
            "allowed_targets":["127.0.0.1:8080"],
            "paths":[{"addr":"127.0.0.1:7000","connection_pool":4}]
        }),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // A running tunnel uses the thread count from its configuration; the other commands are short.
    let workers = match (&cli.config, &cli.command, cli.check) {
        (Some(path), None, false) => Config::load(path).ok().map(|config| config.worker_threads),
        _ => None,
    };
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all();
    if let Some(workers) = workers {
        runtime.worker_threads(workers);
    }
    runtime
        .build()
        .context("start the runtime")?
        .block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    if let Some(command) = cli.command {
        anyhow::ensure!(
            cli.config.is_none() && cli.r#gen.is_none() && !cli.check,
            "subcommands cannot be combined with configuration options"
        );
        match command {
            Command::Menu => eztunnel::manager::run()?,
            Command::Key => println!("{}", eztunnel::tunnel_key::TunnelKey::generate()?.display()),
            #[cfg(feature = "dashboard")]
            Command::Agent { action } => match action {
                AgentCommand::Join { code } => eztunnel::dashboard::agent_join(&code).await?,
                AgentCommand::Run { config_dir } => eztunnel::dashboard::agent_run(&config_dir).await?,
                AgentCommand::Leave => eztunnel::dashboard::agent_leave()?,
            },
            #[cfg(feature = "dashboard")]
            Command::Dashboard { action } => match action {
                DashboardCommand::Setup { port, no_service, state_dir } => eztunnel::dashboard::setup(&state_dir, port, !no_service)?,
                DashboardCommand::Status { state_dir } => eztunnel::dashboard::status(&state_dir)?,
                DashboardCommand::Port { port, state_dir } => eztunnel::dashboard::set_port(&state_dir, port)?,
                DashboardCommand::Remove { delete_data, state_dir } => eztunnel::dashboard::remove(&state_dir, delete_data)?,
                DashboardCommand::Serve { state_dir, listen } => eztunnel::dashboard::serve(&state_dir, listen).await?,
                DashboardCommand::Certificate { lets_encrypt, self_signed: _, address, staging, state_dir } => {
                    eztunnel::dashboard::certificate(&state_dir, lets_encrypt, staging, address).await?
                }
                DashboardCommand::ResetPassword { state_dir } => eztunnel::dashboard::reset_password(&state_dir)?,
                DashboardCommand::Demo { port, empty } => eztunnel::dashboard::demo(port, empty).await?,
            },
            Command::Spooftest {action}=>{
                match action {
                    SpoofTestCommand::Menu=>eztunnel::manager::mirage_tests()?,
                    SpoofTestCommand::GuidedHost{invitation,output}=>{
                        let invite:eztunnel::spoof_session::Invitation=eztunnel::spoof_session::read_private(&invitation)?;
                        std::fs::remove_file(&invitation).context("remove consumed temporary invitation file")?;
                        invite.validate(eztunnel::spoof_session::now()?)?;
                        let listener=tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED,invite.control_port)).await?;
                        eprintln!("Waiting for the other server. Invitation expires after ten minutes. Ctrl+C cancels.");
                        eztunnel::spoof_session::host(listener,invite,&output,&mut |reverse,row|print_spoof_row(reverse,row)).await?;
                    }
                    SpoofTestCommand::GuidedJoin{invitation,output}=>{
                        let invite:eztunnel::spoof_session::Invitation=eztunnel::spoof_session::read_private(&invitation)?;
                        std::fs::remove_file(&invitation).context("remove consumed temporary invitation file")?;
                        eztunnel::spoof_session::join(invite,&output,&mut |reverse,row|print_spoof_row(reverse,row)).await?;
                    }
                    SpoofTestCommand::Listen{config,bind}=>eztunnel::spoof_test::listen(bind,eztunnel::spoof_test::Settings::load(&config)?).await?,
                    SpoofTestCommand::Run{config,peer,output}=>{eztunnel::spoof_test::run(peer,eztunnel::spoof_test::Settings::load(&config)?,&output).await?;}
                }
            }
            Command::Optimize { apply, undo } => {
                use eztunnel::manager::optimize;
                if undo {
                    println!(
                        "Restored {} setting(s).",
                        eztunnel::manager::undo_optimize()?
                    );
                } else {
                    let changes = optimize::plan();
                    for change in &changes {
                        println!(
                            "{:<36} {} -> {}   ({})",
                            change.key, change.current, change.wanted, change.why
                        );
                    }
                    if changes.is_empty() {
                        println!("Already optimized.");
                    } else if apply {
                        let failed = optimize::apply(&changes)?;
                        anyhow::ensure!(failed.is_empty(), "could not set: {}", failed.join(", "));
                        println!("Applied {} change(s); kept after reboot.", changes.len());
                    } else {
                        println!("Run with --apply to make these changes.");
                    }
                }
            }
            Command::Check { action } => {
                use eztunnel::checker::{Options, Preset, Priority, Side, code};
                match action {
                    CheckCommand::Start {
                        role,
                        this_ip,
                        peer_ip,
                        mode,
                        preset,
                        transports,
                        rounds,
                        tun_types,
                        directions,
                        tls_port,
                        port,
                        control_port,
                        priority,
                        no_udp,
                        also_browser_tls,
                        also_tls_fragment,
                        no_parallax_packet,
                        also_game,
                        also_congestion,
                        also_pacer,
                        also_fragment,
                        json,
                        control_via,
                    } => {
                        if let Some(via) = control_via {
                            eztunnel::checker::control::set_control_via(Some(via));
                        }
                        let preset = match preset {
                            PresetArg::Quick => Preset::Quick,
                            PresetArg::Standard => Preset::Standard,
                            PresetArg::Thorough => Preset::Thorough,
                        };
                        let chosen: Vec<eztunnel::config::Transport> = transports
                            .iter()
                            .map(|name| {
                                serde_json::from_value(serde_json::json!(name.trim()))
                                    .with_context(|| format!("unknown transport {name}"))
                            })
                            .collect::<Result<_>>()?;
                        let mut options = match mode {
                            ModeArg::Find => Options::preset(preset),
                            ModeArg::Tune => {
                                anyhow::ensure!(!chosen.is_empty(), "--mode tune needs --transports: the ones to tune");
                                Options::tune(preset, chosen.clone())
                            }
                        };
                        if !chosen.is_empty() {
                            options.transports = chosen;
                        }
                        if let Some(rounds) = rounds {
                            options.rounds = rounds;
                        }
                        if !tun_types.is_empty() {
                            options.tun_profiles = tun_types
                                .iter()
                                .map(|name| {
                                    serde_json::from_value(serde_json::json!(name.trim()))
                                        .with_context(|| format!("unknown TUN packet type {name}"))
                                })
                                .collect::<Result<_>>()?;
                        }
                        options.browser_tls = also_browser_tls;
                        options.tls_fragment = also_tls_fragment;
                        options.parallax_packet = !no_parallax_packet;
                        options.also_game = also_game;
                        options.dialers = match directions {
                            DirectionsArg::Both => vec![Side::Foreign, Side::Iran],
                            DirectionsArg::Iran => vec![Side::Iran],
                            DirectionsArg::Foreign => vec![Side::Foreign],
                        };
                        options.tls_port = tls_port;
                        options.port = port;
                        options.control_port = control_port;
                        options.udp = !no_udp;
                        options.also_congestion = also_congestion;
                        options.also_pacer = also_pacer;
                        options.also_fragment = also_fragment;
                        options.priority = match priority {
                            PriorityArg::Stability => Priority::Stability,
                            PriorityArg::Speed => Priority::Speed,
                            PriorityArg::Hiding => Priority::Hiding,
                            PriorityArg::Lossy => Priority::Lossy,
                        };
                        options.validate()?;
                        let me = match role {
                            RoleArg::Iran => Side::Iran,
                            RoleArg::Foreign => Side::Foreign,
                        };
                        let (iran, foreign) = match me {
                            Side::Iran => (this_ip, peer_ip),
                            Side::Foreign => (peer_ip, this_ip),
                        };
                        let check = code::CheckCode::new(me, iran, foreign, options)?;
                        eprintln!("On the other server run:");
                        println!("eztunnel check join {}", code::encode(&check)?);
                        eztunnel::checker::cli::run(check, me, json.as_deref()).await?;
                    }
                    CheckCommand::Join { code: text, json, control_via } => {
                        if let Some(via) = control_via {
                            eztunnel::checker::control::set_control_via(Some(via));
                        }
                        let check = code::decode(&text)?;
                        let me = check.starter.other();
                        eztunnel::checker::cli::run(check, me, json.as_deref()).await?;
                    }
                }
            }
            Command::Linktest { action } => match action {
                LinkTestCommand::Listen {
                    bind,
                    peer,
                    extra_ports,
                    wait_secs,
                    keep,
                } => {
                    eprintln!("Link tester listening on {bind} for peer {peer}");
                    let options = eztunnel::linktest::ListenOptions {
                        bind,
                        expected_peer: peer,
                        extra_ports,
                        wait: Duration::from_secs(wait_secs),
                        keep,
                    };
                    tokio::select! {
                        result=eztunnel::linktest::listen(options)=>result?,
                        result=tokio::signal::ctrl_c()=>result.context("install shutdown signal handler")?,
                    }
                }
                LinkTestCommand::Probe {
                    peer,
                    bind,
                    local_port,
                    extra_ports,
                    seconds,
                    timeout_secs,
                    quick,
                    no_mtu,
                    text,
                    save,
                } => {
                    let bind = bind.unwrap_or_else(|| {
                        if peer.is_ipv4() {
                            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                        } else {
                            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                        }
                    });
                    let report = eztunnel::linktest::probe(eztunnel::linktest::ProbeOptions {
                        peer,
                        bind,
                        local_port,
                        extra_ports,
                        seconds: Duration::from_secs_f64(seconds),
                        timeout: Duration::from_secs(timeout_secs),
                        quick,
                        mtu: !no_mtu,
                    })
                    .await?;
                    let json = serde_json::to_string_pretty(&report)?;
                    if let Some(path) = save {
                        std::fs::write(&path, &json)
                            .with_context(|| format!("save link report {}", path.display()))?;
                    }
                    if text {
                        print!("{}", eztunnel::linkverdict::render(&report));
                    } else {
                        println!("{json}");
                    }
                    anyhow::ensure!(
                        report.passed(),
                        "one or more link checks failed; see JSON results"
                    );
                }
            },
            Command::Update {
                target,
                allow_downgrade,
                no_restart,
            } => eztunnel::manager::update::run_update(
                &target,
                &eztunnel::manager::update::Options {
                    allow_downgrade,
                    no_restart,
                },
            )?,
            Command::Rollback { target, no_restart } => eztunnel::manager::update::run_rollback(
                &target,
                &eztunnel::manager::update::Options {
                    allow_downgrade: true,
                    no_restart,
                },
            )?,
            Command::Tlscheck {
                config,
                profile,
                sni,
            } => {
                let profile = profile.map(|profile| match profile {
                    ProfileArg::Classic => eztunnel::config::TlsProfile::Classic,
                    ProfileArg::Chrome => eztunnel::config::TlsProfile::Chrome,
                });
                println!("{}", eztunnel::tlscheck::run(config, profile, &sni).await?);
            }
            Command::Settings => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&eztunnel::settings::all())?
                );
            }
            Command::Preset { config, preset, write } => {
                use eztunnel::manager::presets::{self, Capacity, Preset};
                let text = std::fs::read_to_string(&config).with_context(|| format!("read {}", config.display()))?;
                let value: serde_json::Value = serde_json::from_str(&text).context("the configuration is not valid JSON")?;
                let capacity = Capacity::here();
                match preset {
                    None => println!("{}", serde_json::to_string_pretty(&presets::listed(&value, capacity))?),
                    Some(id) => {
                        let names = Preset::ALL.map(|p| p.id()).join(", ");
                        let chosen = Preset::from_id(&id).with_context(|| format!("unknown preset {id}; use one of {names}"))?;
                        let edited = serde_json::to_string_pretty(&presets::apply(&value, chosen, capacity)?)? + "\n";
                        if write {
                            let temporary = config.with_extension("preset-new");
                            std::fs::write(&temporary, &edited).with_context(|| format!("write {}", temporary.display()))?;
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
                            }
                            std::fs::rename(&temporary, &config).with_context(|| format!("replace {}", config.display()))?;
                            eprintln!("{} saved in {}; restart the tunnel to use it", chosen.label(), config.display());
                        } else {
                            print!("{edited}");
                        }
                    }
                }
            }
            Command::Token => {
                println!("{}", eztunnel::config::generate_token()?);
            }
            Command::Keygen { out } => {
                let (path, public) = generate_keypair(&out)?;
                println!(
                    "Private key saved to {}\nPublic key: {public}",
                    path.display()
                );
            }
            Command::Certgen { out, name } => {
                let (cert, key) = generate_certificate(&out, name)?;
                println!(
                    "Certificate saved to {}\nTLS private key saved to {}",
                    cert.display(),
                    key.display()
                );
            }
        }
        return Ok(());
    }
    if let Some(mode) = cli.r#gen {
        println!("{}", serde_json::to_string_pretty(&example(mode))?);
        return Ok(());
    }
    let Some(path) = cli.config else {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            return eztunnel::manager::run();
        }
        anyhow::bail!("provide --config <file>, or run on a terminal to open the manager");
    };
    let config = Config::load(&path)?;
    config.private_key()?;
    eztunnel::transport::validate_tls_config(&config)?;
    // Validation never opens tunnel sockets or changes persistent state.
    if cli.check {
        println!("Configuration and keys are valid.");
        for warning in config.warnings() {
            println!("Warning: {warning}");
        }
        return Ok(());
    }
    let open_files = eztunnel::sys::raise_open_file_limit(config.max_open_files);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    match open_files {
        Ok(limit) => tracing::debug!(limit, "open-file limit in effect"),
        Err(error) => tracing::warn!(%error, "could not raise the open-file limit"),
    }
    for warning in config.warnings() {
        tracing::warn!("configuration: {warning}");
    }
    // A used-up quota keeps the tunnel off (and its ports free) until the period ends.
    let quota_file = eztunnel::quota::state_path(&path);
    tokio::select! {
        () = eztunnel::quota::wait_until_available(&config.quota, &quota_file) => {}
        signal = eztunnel::sys::shutdown_signal() => {
            signal.context("install shutdown signal handler")?;
            tracing::info!("shutting down");
            return Ok(());
        }
    }
    let stats = std::sync::Arc::new(eztunnel::stats::Stats::default());
    let tracker: eztunnel::quota::SharedTracker = std::sync::Arc::new(std::sync::Mutex::new(
        eztunnel::quota::Tracker::new(config.quota.clone(), quota_file, stats.clone()),
    ));
    let schedule = config.schedule.clone();
    let goodbye_wait = std::time::Duration::from_millis(config.timeouts.goodbye_wait_ms);
    let engine = engine::run_with_stats(config, stats.clone());
    tokio::pin!(engine);
    // `None`: this side is stopping on purpose and says goodbye first.
    let finished = tokio::select! {
        result = &mut engine => Some(result),
        signal = eztunnel::sys::shutdown_signal() => {
            signal.context("install shutdown signal handler")?;
            tracing::info!("shutting down");
            None
        }
        () = eztunnel::quota::watch(tracker.clone()) => {
            tracing::warn!("{}: stopping until the period ends", eztunnel::quota::EXHAUSTED_MESSAGE);
            None
        }
        () = eztunnel::quota::restart_due(&schedule) => {
            tracing::info!(hours = schedule.restart_every_hours, "planned restart");
            None
        }
    };
    let outcome = match finished {
        Some(result) => result,
        None => {
            engine::say_goodbye(&stats, goodbye_wait, engine.as_mut()).await;
            Ok(())
        }
    };
    // Count what was carried since the last sample before leaving.
    tracker
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .sample();
    outcome
}
