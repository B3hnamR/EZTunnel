//! The step-by-step "New tunnel" screen.
use super::plan::{
    Carry, CdnPlan, Direction, IpMode, Plan, Profile, Protocol, RawPlan, Side, TunPlan, check,
    check_name, format_ports, is_raw, is_xhttp, parse_ports, transport_name, unicast_ipv4,
};
use super::store::Store;
use super::{rawfw, service, tune, ui};
use crate::config::{Transport, XhttpMode};
use crate::tunnel_key::TunnelKey;
use crate::raw_packet::RawProfile;
use anyhow::Result;

const STEPS: usize = 6;

fn step(number: usize, title: &str) {
    ui::heading(
        &format!("New tunnel · {title}"),
        &format!("step {number} of {STEPS}   (Back / Esc = previous page)"),
    );
}

/// Transports offered, with a short explanation of each.
fn transports() -> Vec<(Transport, &'static str)> {
    vec![
        (
            Transport::Tcp,
            "TCP        plain and fast; a good first choice",
        ),
        (
            Transport::Wss,
            "WSS        WebSocket inside TLS; looks like HTTPS (good where TCP is filtered)",
        ),
        (
            Transport::Ws,
            "WS         WebSocket without TLS; often blocked, most of all when the foreign server dials in; prefer WSS",
        ),
        (
            Transport::Xhttp,
            "XHTTP      HTTP requests; also works through a CDN",
        ),
        (
            Transport::Xhttps,
            "XHTTPS     XHTTP inside TLS; works through a CDN",
        ),
        (
            Transport::Http,
            "HTTP       HTTP upgrade without TLS; often blocked, most of all when the foreign server dials in; prefer HTTPS",
        ),
        (Transport::Https, "HTTPS      HTTP upgrade inside TLS"),
        (
            Transport::Kcp,
            "KCP        over UDP; plain KCP is easy to spot and often blocked, most of all when the foreign server dials in",
        ),
        (
            Transport::FecUdp,
            "FEC-UDP    UDP with error correction; very lossy links",
        ),
        (Transport::Tcp6, "TCP6       TCP between IPv6 addresses"),
        (
            Transport::FecRaw,
            "FEC-RAW    raw IP packets with error correction (advanced)",
        ),
        (
            Transport::FecRawGaming,
            "FEC-RAW-G  the same tuned for low delay (advanced)",
        ),
        (
            Transport::Tun,
            "RAW-TUN    raw IP packets for a TUN tunnel (advanced)",
        ),
        (
            Transport::Parallax,
            "Parallax   authenticated directional TCP lanes; both endpoints need Parallax support",
        ),
        (
            Transport::Mirage,
            "Mirage     experimental spoofed IPv4 over reliable raw TCP-looking packets",
        ),
    ]
}

fn transport_label(transport: Transport, label: &str) -> String {
    match transport {
        Transport::Parallax => ui::accent(label),
        Transport::Mirage => console::style(label)
            .for_stderr()
            .yellow()
            .bold()
            .to_string(),
        _ => label.to_string(),
    }
}

#[cfg(test)]
#[test]
fn featured_transports_are_last_and_keep_readable_labels() {
    let list = transports();
    assert_eq!(list[list.len() - 2].0, Transport::Parallax);
    assert_eq!(list.last().unwrap().0, Transport::Mirage);
    for (transport, label) in list {
        assert_eq!(
            console::strip_ansi_codes(&transport_label(transport, label)),
            label
        );
    }
}

/// Answers that a transport check already gave: the wizard skips those questions.
#[derive(Debug, Clone)]
pub struct Prefill {
    pub side: Side,
    pub direction: Direction,
    pub transport: Transport,
    /// The port the check used; offered as the default.
    pub port: Option<u16>,
    /// The other server's address; offered as the default.
    pub peer_host: Option<String>,
    pub tested:Option<crate::checker::CaseSpec>,
}

/// Runs the wizard. Returns the name of the created tunnel, or `None` if it was cancelled.
pub fn new_tunnel(store: &Store) -> Result<Option<String>> {
    new_tunnel_with(store, None)
}

/// The wizard with the first answers given (from a transport check).
pub fn new_tunnel_with(store: &Store, prefill: Option<Prefill>) -> Result<Option<String>> {
    let mut prefill = prefill;
    let mut previous = None;
    loop {
        ui::banner("New tunnel");
        let (side, direction, transport) = match &prefill {
            Some(prefill) => {
                ui::note("From the transport check:");
                ui::ok(&format!("This server · {}", prefill.side.label()));
                if !is_raw(prefill.transport) {
                    ui::ok(&format!("Tunnel type · {}", prefill.direction.label()));
                }
                ui::ok(&format!(
                    "Transport · {}",
                    transport_name(prefill.transport)
                ));
                (prefill.side, prefill.direction, prefill.transport)
            }
            None => match first_questions(store, previous)? {
                First::Answers(side, direction, transport) => (side, direction, transport),
                First::Pairing(result) => return Ok(result),
                First::Cancelled => return Ok(None),
            },
        };
        if prefill.is_some() && transport == Transport::Mirage && !super::mirage::consent()? {
            return Ok(None);
        }
        match finish_wizard(store, side, direction, transport, prefill.clone()) {
            Err(error) if ui::is_back(&error) => {
                previous = Some((side, direction, transport));
                prefill = None;
                continue;
            }
            result => return result,
        }
    }
}

enum First {
    Answers(Side, Direction, Transport),
    Pairing(Option<String>),
    Cancelled,
}

/// How to set up, which server, which direction, which transport.
fn first_questions(store: &Store, previous: Option<(Side, Direction, Transport)>) -> Result<First> {
    let mut page = if previous.is_some() { 3 } else { 0 };
    let mut chosen_side = usize::from(previous.is_some_and(|p| p.0 == Side::Foreign));
    let mut chosen_direction = usize::from(previous.is_some_and(|p| p.1 == Direction::Direct));
    let mut chosen_transport = previous
        .and_then(|p| transports().iter().position(|(t, _)| *t == p.2))
        .unwrap_or(0);
    loop {
        if page == 0 {
            let methods = vec![
                format!(
                    "{}  {}",
                    ui::bold("Step by step       "),
                    ui::dim("the first server of a tunnel, or to choose everything yourself")
                ),
                format!(
                    "{}  {}",
                    ui::bold("Paste a pairing code"),
                    ui::dim("the other server already has the tunnel and showed a code")
                ),
            ];
            match ui::choose("How do you want to set it up?", &methods, 0)? {
                Some(0) => {
                    page = 1;
                }
                Some(_) => match import_pairing(store) {
                    Ok(Some(name)) => return Ok(First::Pairing(Some(name))),
                    Ok(None) => continue,
                    Err(error) if ui::is_back(&error) => continue,
                    Err(error) => return Err(error),
                },
                None => return Ok(First::Cancelled),
            }
        }
        ui::note(
            "Run this on both servers. Answer the same way on both,\nexcept for the first question.",
        );

        // 1. Which server.
        step(1, "this server");
        let sides = vec![
            format!(
                "{}  {}",
                ui::bold("Iran server   "),
                ui::dim("entry: users connect to this server")
            ),
            format!(
                "{}  {}",
                ui::bold("Foreign server"),
                ui::dim("exit: traffic leaves to the internet from here")
            ),
        ];
        if page == 1 {
            let Some(side) = ui::choose("Which server is this?", &sides, chosen_side)? else {
                page = 0;
                continue;
            };
            chosen_side = side;
            page = 2;
        }
        let side = chosen_side;
        let side = if side == 0 { Side::Iran } else { Side::Foreign };

        // 2. Direction.
        step(2, "tunnel type");
        let directions = vec![
            format!(
                "{}  {}",
                ui::bold("Reverse tunnel"),
                ui::dim("the foreign server connects to the Iran server (recommended)")
            ),
            format!(
                "{}  {}",
                ui::bold("Direct tunnel "),
                ui::dim("the Iran server connects to the foreign server")
            ),
        ];
        if page == 2 {
            let Some(direction) = ui::choose("Tunnel type", &directions, chosen_direction)? else {
                page = 1;
                continue;
            };
            chosen_direction = direction;
            page = 3;
        }
        let direction = chosen_direction;
        let direction = if direction == 0 {
            Direction::Reverse
        } else {
            Direction::Direct
        };

        // 3. Transport.
        step(3, "transport");
        ui::note("The transport is how the two servers talk. Both servers must use the same one.");
        let list = transports();
        let labels: Vec<String> = list
            .iter()
            .map(|(transport, label)| transport_label(*transport, label))
            .collect();
        let Some(choice) = ui::choose("Transport", &labels, chosen_transport)? else {
            page = 2;
            continue;
        };
        chosen_transport = choice;
        let transport = list[choice].0;
        if transport == Transport::Mirage && !super::mirage::consent()? {
            continue;
        }
        if transport==Transport::Mirage {
            let choices=["Test my spoof IPs first  guided invitation and saved results","Use existing results / import peer setup","Configure Mirage manually"].map(str::to_string);
            match ui::choose("Mirage setup",&choices,0)?{
                Some(0)|Some(1)=>{super::mirage_flow::menu(store)?;return Ok(First::Pairing(None));}
                Some(2)=>{},_=>continue,
            }
        }
        if is_raw(transport) {
            ui::warn(
                "Raw carriers send packets in both directions; the tunnel type does not apply.",
            );
            ui::warn("They need root rights and the real IPv4 address of each server.");
        }
        return Ok(First::Answers(side, direction, transport));
    }
}

/// The rest of the wizard, from the tunnel key on.
fn finish_wizard(
    store: &Store,
    side: Side,
    direction: Direction,
    transport: Transport,
    prefill: Option<Prefill>,
) -> Result<Option<String>> {
    // 4. Shared tunnel key, with pairing-code import available from the first page.
    let (key, created_key) = {
        step(4, "tunnel key");
        ui::note(
            "Both servers share one tunnel key (PSK). Paste the same key on both.\nUse `eztunnel key` or 'Create a new key' to generate one.",
        );
        let options = vec![
            format!(
                "{}  {}",
                ui::bold("Create a new key"),
                ui::dim("this is the first of the two servers")
            ),
            format!(
                "{}  {}",
                ui::bold("Paste a key     "),
                ui::dim("the other server already has the tunnel")
            ),
        ];
        let Some(choice) = ui::choose("Tunnel key", &options, 1)? else {
            return Err(ui::Back.into());
        };
        let created_key = choice == 0;
        let key = if created_key {
            let key = TunnelKey::generate()?.display();
            ui::ok(&format!("New key: {}", ui::accent(&key)));
            ui::note(
                "At the end you get a pairing code that sets up the other server in one step.",
            );
            key
        } else {
            let text = ui::ask("Paste the tunnel key", None, |text: &String| {
                TunnelKey::parse(text)
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })?;
            TunnelKey::parse(&text)?.display()
        };
        (key, created_key)
    };
    let mut plan = Plan::new(key, side, direction, transport);
    if let Some(prefill) = &prefill {
        if let Some(port) = prefill.port {
            plan.tunnel_port = port;
        }
        plan.peer_host = prefill.peer_host.clone();
    }

    let mut page = 0usize;
    let mut settings_choice = 0usize;
    let mut applied_choice = None;
    loop {
        if page == 0 {
            // 5. Connection between the servers.
            step(5, "connection");
            let base = plan.clone();
            match ui::form(|| {
                let mut draft = base.clone();
                connection(&mut draft)?;
                Ok(draft)
            }) {
                Ok(draft) => plan = draft,
                Err(error) if ui::is_back(&error) => return Err(error),
                Err(error) => return Err(error),
            }
            page = 1;
        }

        // 6. What to carry.
        if page == 1 {
            step(6, "what to carry");
            let base = plan.clone();
            match ui::form(|| {
                let mut draft = base.clone();
                if !carry(&mut draft)? {
                    return Err(ui::Back.into());
                }
                Ok(draft)
            }) {
                Ok(draft) => plan = draft,
                Err(error) if ui::is_back(&error) => {
                    page = 0;
                    continue;
                }
                Err(error) => return Err(error),
            }
            if let Some(tun) = &mut plan.tun {
                tun.name = free_tun_name(store);
                if tun.forwarding_port.is_some() {
                    tun.forwarding_port = Some(free_forwarding_port(store));
                }
            }
        }

        // Settings.
        ui::heading("Settings", "what will the tunnel mostly be used for?");
        let mut choices: Vec<String> = Profile::ALL
            .iter()
            .map(|p| format!("{:<26}  {}", p.label(), ui::dim(p.description())))
            .collect();
        choices.push(format!(
            "{:<26}  {}",
            "Customize",
            ui::dim(&format!(
                "start from General, then change {} options and limits",
                transport_name(transport)
            ))
        ));
        // Esc leaves the wizard, like at every other step.
        let Some(choice) = ui::choose("Settings", &choices, settings_choice)? else {
            page = 1;
            continue;
        };
        settings_choice = choice;
        select_settings(&mut plan,&mut applied_choice,choice,prefill.as_ref().and_then(|prefill|prefill.tested));
        if choice == Profile::ALL.len() {
            if let Err(error) = tune::tune_plan(&mut plan) {
                if ui::is_back(&error) {
                    page = 2;
                    continue;
                }
                return Err(error);
            }
        }
        match finish(store, plan.clone(), created_key) {
            Err(error) if ui::is_back(&error) => {
                page = 2;
                continue;
            }
            result => return result,
        }
    }
}

/// C30/C31: an imported TUN setup gets a free local interface name, but the inner
/// forwarding port is agreed by both endpoints and is never rewritten here; a busy port
/// only produces a warning.
fn localize_imported_tun(tun:&mut TunPlan,free_name:String,busy:impl Fn(u16)->bool)->Option<String>{
    tun.name=free_name;
    let port=tun.forwarding_port?;
    busy(port).then(||format!("The paired inner forwarding port {port} is occupied locally. It is preserved because both endpoints must agree; free it or explicitly change both endpoints before starting."))
}

/// Applies the chosen profile and then the measured checker variant, but only when the
/// choice changed: going back to the same choice keeps the user's own edits.
fn select_settings(plan:&mut Plan,applied:&mut Option<usize>,choice:usize,tested:Option<crate::checker::CaseSpec>){
    if *applied==Some(choice){return;}
    plan.apply_profile(profile_for_choice(choice));
    if let Some(spec)=tested{apply_tested(plan,spec);}
    *applied=Some(choice);
}

fn apply_tested(plan:&mut Plan,spec:crate::checker::CaseSpec){
    match spec.variant{
        crate::checker::Variant::BrowserTls=>plan.tls_profile=crate::config::TlsProfile::Chrome,
        crate::checker::Variant::TlsFragment=>plan.tls_fragment=true,
        crate::checker::Variant::Congestion=>plan.tcp_congestion=Some(crate::checker::CONGESTION_TEST_ALGORITHM.into()),
        crate::checker::Variant::Pacer=>plan.fec_pacer=true,
        crate::checker::Variant::Plain|crate::checker::Variant::Fragment=>{},
    }
    if let(Some(profile),Some(raw))=(spec.profile,&mut plan.raw){raw.profile=crate::checker::profile_name(profile).into();}
    if spec.variant==crate::checker::Variant::Fragment&&let Some(tun)=&mut plan.tun{tun.fragment=true;tun.mtu=crate::checker::FRAGMENT_TEST_MTU;}
}

/// The profile a row of the "Settings" list stands for. The row after the profiles is
/// "Customize", which starts from General.
fn profile_for_choice(choice: usize) -> Profile {
    Profile::ALL
        .get(choice)
        .copied()
        .unwrap_or(Profile::General)
}

/// Sets up the other server's side from a pairing code.
fn import_pairing(store: &Store) -> Result<Option<String>> {
    ui::heading("New tunnel · pairing code", "from the other server");
    ui::note("On the other server: Manage tunnels → the tunnel → Show the pairing code.");
    let text = ui::paste("Paste the pairing code", |text: &String| {
        if text.trim().starts_with("ezm-setup1-"){
            return crate::spoof_session::SetupBundle::decode(text,crate::spoof_session::now().unwrap_or(u64::MAX)).map(|_|()).map_err(|error|format!("{error:#}"));
        }
        if text.trim().starts_with("ezm-test1-"){return Err("This is a temporary test invitation. Use Mirage source tests -> Join on Foreign, not tunnel pairing.".into());}
        super::pairing::decode(text)
            .and_then(|code| super::pairing::to_plan(&code))
            .map(|_| ())
            .map_err(|e| format!("{e:#}"))
    },|text|format!("Pairing code accepted ({} chars)",text.chars().count()))?;
    if text.trim().starts_with("ezm-setup1-"){
        return super::mirage_flow::import_bundle(store,crate::spoof_session::SetupBundle::decode(&text,crate::spoof_session::now()?)?);
    }
    let code = super::pairing::decode(&text)?;
    let (mut plan, missing) = super::pairing::to_plan(&code)?;
    if plan.transport == Transport::Mirage {
        if !super::mirage::consent()? {
            return Ok(None);
        }
        let (settings, interface, local_ip) = ui::form(|| {
            let settings = super::mirage::settings(None)?;
            let (interface, local_ip) = super::mirage::local_settings(None, None)?;
            Ok((settings, interface, local_ip))
        })?;
        let raw = plan
            .raw
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Mirage pairing code requires raw profile"))?;
        raw.mirage = Some(settings);
        (raw.interface, raw.local_ip) = (interface, local_ip);
    }
    for ignored in super::pairing::ignored_values(&code) {
        ui::warn(&format!(
            "The pairing code has {ignored}, which this version does not know; it is not used."
        ));
    }
    ui::ok(&format!(
        "This server becomes the {} of a {} tunnel over {}.",
        plan.side.label(),
        plan.direction.label().to_lowercase(),
        transport_name(plan.transport)
    ));
    let base = plan.clone();
    plan = ui::form(|| {
        let mut plan = base.clone();
        if missing.carry {
            let options = vec![
                "Port forwarding   users connect to ports on this server".to_string(),
                "SOCKS5 proxy      a proxy on this server that exits abroad".to_string(),
            ];
            if ui::choose_required("What should the tunnel carry?", &options, 0)? == 1 {
                plan.carry = Carry::Socks;
            }
        }
        if missing.port {
            ui::note(
                "The other server connects through a CDN. The CDN must forward to a port of this server\n(the origin port). Use one the CDN supports, for example 8080 or 2052 for HTTP and 8443 or 2053 for HTTPS.",
            );
            let prompt = "Tunnel port on this server (where the CDN forwards to)";
            plan.tunnel_port = ask_free_port(prompt, plan.tunnel_port, &["tcp"])?;
        }
        if plan.carry == Carry::Socks {
            match plan.side {
                Side::Iran => {
                    plan.socks_bind =
                        ui::ask("SOCKS5 address", Some("127.0.0.1:1080"), |text: &String| {
                            text.parse::<std::net::SocketAddr>()
                                .map(|_| ())
                                .map_err(|_| "use IP:port, for example 127.0.0.1:1080".to_string())
                        })?;
                    if let Ok(bind) = plan.socks_bind.parse::<std::net::SocketAddr>()
                        && service::port_busy(bind.port(), "tcp")
                    {
                        ui::warn(&format!(
                            "Port {} is already in use on this server; the tunnel cannot use it until it is free.",
                            bind.port()
                        ));
                    }
                }
                Side::Foreign => {
                    // Otherwise it keeps the plan's port-forwarding default (127.0.0.1 only), which
                    // would leave the proxy unable to reach anything but this server's own localhost.
                    plan.allowed = vec!["*".into()];
                    ui::note("A SOCKS5 proxy may reach any address from this server.");
                }
            }
        } else if missing.ports {
            let text = ui::ask("Ports to forward", Some("443"), |text: &String| {
                parse_ports(text).map(|_| ()).map_err(|e| e.to_string())
            })?;
            plan.ports = parse_ports(&text)?;
            let protocols = [Protocol::Tcp, Protocol::Udp, Protocol::Both];
            let labels: Vec<String> = protocols.iter().map(|p| p.label().to_string()).collect();
            plan.protocol = protocols[ui::choose_required("Protocol", &labels, 0)?];
        }
        if let Some(tun) = &mut plan.tun
            && let Some(warning)=localize_imported_tun(tun,free_tun_name(store),|port|service::port_busy(port,"tcp"))
        {
            ui::warn(&warning);
        }
        Ok(plan)
    })?;
    finish(store, plan, false)
}

/// Names, checks, saves and starts a tunnel, then explains the other side.
pub(super) fn from_mirage_result(store:&Store,report:&crate::spoof_session::Report,index:usize)->Result<()> {
    let row=report.iran_bound.get(index).ok_or_else(||anyhow::anyhow!("selected result no longer exists"))?;
    anyhow::ensure!(row.received>0&&row.error.is_none(),"selected source did not reach Iran");
    let sides=["Iran server  users connect here","Foreign server  traffic exits here"].map(str::to_string);
    let side=if ui::choose_required("Which server is this?",&sides,0)?==0{Side::Iran}else{Side::Foreign};
    if !super::mirage::consent()?{return Ok(());}
    let mut plan=Plan::new(TunnelKey::generate()?.display(),side,Direction::Reverse,Transport::Mirage);
    let down=crate::spoof_session::Report::ranked(&report.foreign_bound).into_iter().find_map(|i|{
        let row=&report.foreign_bound[i];(row.stage=="authenticated-interface-admission"&&row.received>0&&row.error.is_none()).then_some(row)
    });
    let (down_profile,iran_source)=if let Some(row)=down{
        let choices=[format!("Use measured return: {:?}, source {}",row.profile,row.source),"Choose a different return profile/source".into()];
        if ui::choose_required("Iran -> Foreign return path",&choices,0)?==0{(row.profile,row.source)}else{
            let profiles=[RawProfile::Udp,RawProfile::Tcp,RawProfile::Icmp,RawProfile::Gre,RawProfile::Ipip,RawProfile::Bip,RawProfile::Icmpv6];
            let labels=profiles.iter().map(|p|format!("{p:?}")).collect::<Vec<_>>();
            let selected=profiles[ui::choose_required("Return packet type (manual choice is not measured)",&labels,0)?];
            let text=ui::ask("Iran sends as ('real' or one permitted spoof IPv4)",Some("real"),|value:&String|if value=="real"{Ok(())}else{unicast_ipv4(value).map(|_|()).map_err(|e|e.to_string())})?;
            (selected,if text=="real"{report.iran}else{unicast_ipv4(&text)?})
        }
    }else{
        ui::warn("The Iran -> Foreign direction was not measured successfully. Choose it explicitly; this result is not a verified bidirectional tunnel.");
        let profiles=[RawProfile::Tcp,RawProfile::Udp,RawProfile::Icmp,RawProfile::Gre,RawProfile::Ipip,RawProfile::Bip,RawProfile::Icmpv6];
        let names=profiles.iter().map(|p|format!("{p:?}")).collect::<Vec<_>>();
        (profiles[ui::choose_required("Iran -> Foreign packet type",&names,1)?],report.iran)
    };
    let local=if side==Side::Iran{report.iran}else{report.foreign};
    let outgoing=if side==Side::Iran{iran_source}else{row.source};
    let incoming=if side==Side::Iran{row.source}else{iran_source};
    let advanced=serde_json::json!({"uplink":row.profile,"downlink":down_profile,"allow_real_source":outgoing==local,
        "source_pool":if outgoing==local{vec![]}else{vec![outgoing]},"expected_sources":[incoming],"echo_mode":"replies"});
    plan.peer_host=Some(if side==Side::Iran{report.foreign}else{report.iran}.to_string());
    plan.tunnel_port=report.raw_port;
    plan.raw=Some(super::plan::RawPlan{profile:serde_json::to_value(row.profile)?.as_str().unwrap().into(),peer_ip:if side==Side::Iran{report.foreign}else{report.iran},
        ip_mode:super::plan::IpMode::Normal,interface:None,local_ip:Some(local),mirage:Some(super::plan::MiragePlan{spoof_src_ip:outgoing,spoof_dst_ip:None,gateway_ip:None,peer_mac:None,advanced:Some(advanced)})});
    ui::note("Source/profile answers are filled from measured samples. The test key is NOT reused: a fresh tunnel key is generated. Configure the other endpoint from the final setup bundle; nothing starts before your confirmation.");
    if !carry(&mut plan)?{return Ok(());}
    if let Some(tun)=&mut plan.tun{tun.name=free_tun_name(store);if tun.forwarding_port.is_some(){tun.forwarding_port=Some(free_forwarding_port(store));}}
    if side==Side::Foreign&&matches!(plan.carry,Carry::Ports|Carry::TunPorts){
        ui::note("The Iran peer also needs the forwarding ports. Enter them here so its setup code is complete.");
        let text=ui::ask("Ports users will connect to on Iran",Some("443"),|text:&String|parse_ports(text).map(|_|()).map_err(|error|error.to_string()))?;
        plan.ports=parse_ports(&text)?;
        let protocols=[Protocol::Tcp,Protocol::Udp,Protocol::Both];let labels=protocols.iter().map(|p|p.label().to_string()).collect::<Vec<_>>();
        plan.protocol=protocols[ui::choose_required("Forwarding protocol",&labels,0)?];
    }
    let peer=mirage_peer_plan(&plan,report,row.profile,row.source,down_profile,iran_source)?;
    let local_config=plan.to_json()?;super::plan::check(&local_config)?;
    let peer_config=peer.to_json()?;super::plan::check(&peer_config)?;
    let bundle=crate::spoof_session::SetupBundle::new(peer_config)?;
    let default=suggest_name(store,&plan);
    let name=ui::ask("Name for this tunnel",Some(&default),|name:&String|{
        check_name(name).map_err(|e|e.to_string())?;
        if store.exists(name){Err("a tunnel with this name already exists".into())}else{Ok(())}
    })?;
    ui::boxed("Measured Mirage tunnel",&summary_lines(&plan));
    ui::note("Save and start is the normal setup. The peer also needs its code imported before the authenticated link can come up. Firewall rules are not changed automatically.");
    if let Some(action)=super::setup::choose(store)?{
        // Always show the peer code after saving, including a local startup
        // error, so the user can complete or repair the opposite endpoint.
        let started=super::setup::save(store,&name,&local_config,action);
        ui::heading("Set up the other endpoint", "New tunnel -> Paste a pairing code (or Mirage -> Import peer tunnel setup)");
        eprintln!("\n{}\n",bundle.encode()?);
        ui::warn("Secret setup code contains the new tunnel key. Valid for 24 hours; share privately. The peer must review and accept local Mirage consent before saving.");ui::pause();
        started?;
    }
    Ok(())
}

fn mirage_peer_plan(plan:&Plan,report:&crate::spoof_session::Report,up:RawProfile,foreign_source:std::net::Ipv4Addr,down:RawProfile,iran_source:std::net::Ipv4Addr)->Result<Plan>{
    let local=if plan.side==Side::Iran{report.iran}else{report.foreign};
    let mut peer=plan.clone();peer.side=plan.side.other();peer.peer_host=Some(local.to_string());
    let peer_local=if peer.side==Side::Iran{report.iran}else{report.foreign};
    let peer_out=if peer.side==Side::Iran{iran_source}else{foreign_source};let peer_in=if peer.side==Side::Iran{foreign_source}else{iran_source};
    peer.raw=Some(super::plan::RawPlan{profile:serde_json::to_value(up)?.as_str().unwrap().into(),peer_ip:local,
        ip_mode:super::plan::IpMode::Normal,interface:None,local_ip:Some(peer_local),mirage:Some(super::plan::MiragePlan{spoof_src_ip:peer_out,spoof_dst_ip:None,gateway_ip:None,peer_mac:None,
        advanced:Some(serde_json::json!({"uplink":up,"downlink":down,"allow_real_source":peer_out==peer_local,"source_pool":if peer_out==peer_local{vec![]}else{vec![peer_out]},"expected_sources":[peer_in],"echo_mode":"replies"}))})});
    if peer.side==Side::Foreign {
        peer.allowed=if peer.carry==Carry::Socks{vec!["*".into()]}else{peer.ports.iter().map(|rule|rule.target.clone()).collect()};
    }
    if let Some(tun)=&mut peer.tun{std::mem::swap(&mut tun.local_ip,&mut tun.peer_ip);}
    Ok(peer)
}

fn finish(
    store: &Store,
    mut plan: Plan,
    show_pairing: bool,
) -> Result<Option<String>> {
    // Check the whole configuration before asking for a name: rules that involve several answers
    // are found here, and the answers are not lost (Customize reopens with everything kept).
    let config = loop {
        match plan
            .to_json()
            .and_then(|json| check(&json).map(|parsed| (json, parsed)))
        {
            Ok((json, parsed)) => {
                for warning in parsed.warnings() {
                    ui::warn(&warning);
                }
                break json;
            }
            Err(error) => {
                ui::fail(&format!(
                    "These answers do not form a working tunnel: {error:#}"
                ));
                let options = vec![
                    "Change the settings (Customize); your other answers are kept".to_string(),
                    "Cancel".to_string(),
                ];
                match ui::choose("What now?", &options, 0)? {
                    Some(0) => tune::tune_plan(&mut plan)?,
                    _ => return Ok(None),
                }
            }
        }
    };

    // Name.
    let default_name = suggest_name(store, &plan);
    let name = ui::form(|| {
        let name = ui::ask(
            "Name for this tunnel",
            Some(&default_name),
            |name: &String| {
                check_name(name).map_err(|e| e.to_string())?;
                if store.exists(name) {
                    return Err("a tunnel with this name already exists".into());
                }
                Ok(())
            },
        )?;

        // Summary and confirmation.
        eprintln!();
        ui::boxed(&format!("Tunnel {name}"), &summary_lines(&plan));
        eprintln!();
        let action = if store.system {
            "Create the tunnel and start it now?"
        } else {
            "Save the tunnel?"
        };
        if !ui::confirm(action, true)? {
            return Err(ui::Back.into());
        }
        Ok(name)
    })?;
    store.save(&name, &config)?;
    ui::ok(&format!("Saved {}", store.path(&name).display()));
    if store.system {
        match service::install(store, &name) {
            Ok(()) => {
                ui::ok(&format!("Service {} started", service::unit_name(&name)));
                offer_firewall(store, &name)?;
                offer_raw_rules(store, &name)?;
                wait_for_start(store, &name, !show_pairing);
            }
            Err(error) => ui::fail(&format!("Could not start the service: {error:#}")),
        }
    } else {
        ui::info(&format!(
            "Start it with: eztunnel --config {}",
            store.path(&name).display()
        ));
    }
    eprintln!();
    if show_pairing {
        if let Err(error) = show_pairing_code(&config) {
            ui::warn(&format!("No pairing code: {error:#}"));
            other_server_instructions(&plan);
        }
    } else {
        if plan.transport==Transport::Mirage{ui::note("Local settings saved. Confirm the other endpoint is configured before expecting a connection.");}else{ui::ok("Both sides are set up.");}
    }
    ui::pause();
    Ok(Some(name))
}

/// Prints the pairing code of a saved tunnel, asking for this server's address when the other
/// server needs it.
pub fn show_pairing_code(config: &serde_json::Value) -> Result<()> {
    let address = if super::pairing::needs_address(config) {
        let detected = super::local_ip().unwrap_or_default();
        ui::note("The other server needs this server's address to reach it.");
        Some(ui::ask(
            "This server's public IP or domain",
            (!detected.is_empty()).then_some(detected.as_str()),
            |text: &String| check_host(text, Transport::Tcp),
        )?)
    } else {
        None
    };
    let origin = config["listeners"][0]["xhttp"]["max_requests_per_ip"] == 0
        || config["paths"][0]["xhttp"]["max_requests_per_ip"] == 0;
    let cdn = if origin && super::pairing::needs_address(config) {
        let domain = ui::ask(
            "CDN domain the other server connects to (empty if none)",
            Some(""),
            |text: &String| {
                if text.is_empty() {
                    return Ok(());
                }
                crate::carrier::http_authority(text)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            },
        )?;
        (!domain.is_empty()).then_some(domain)
    } else {
        None
    };
    let pairing = super::pairing::from_config(config, address, cdn)?;
    let code = super::pairing::encode(&pairing)?;
    let other = if pairing.creator == "iran" {
        "Foreign server"
    } else {
        "Iran server"
    };
    ui::boxed(
        "On the other server",
        &[
            format!("1. Run  {}  on the {other}", ui::accent("sudo eztunnel")),
            "2. New tunnel → Paste a pairing code".to_string(),
            "3. Paste the code below".to_string(),
        ],
    );
    eprintln!();
    eprintln!("{}", ui::accent(&code));
    eprintln!();
    ui::note("The code holds the tunnel key: whoever has it can join this tunnel.");
    Ok(())
}

fn connection(plan: &mut Plan) -> Result<()> {
    let other = plan.side.other().label();
    if let Some(raw) = raw_details(plan)? {
        if raw.profile == "dns" {
            // Port 53 is where a real resolver listens; anything else would be an odd-looking
            // "DNS" destination. The default raw tunnel port (4443) is never asked for a raw
            // profile, so it is overridden here instead.
            plan.tunnel_port = 53;
        }
        plan.raw = Some(raw);
        return Ok(());
    }
    if is_xhttp(plan.transport) {
        plan.cdn = None;
        let choices = vec![
            "No, the servers connect directly".to_string(),
            "Yes, through a CDN such as Cloudflare".to_string(),
        ];
        if ui::choose_required("Does this tunnel go through a CDN?", &choices, 0)? == 1 {
            plan.xhttp_mode = XhttpMode::Auto;
            if plan.dials() {
                let domain = ui::ask(
                    &format!("CDN domain that leads to the {other}"),
                    None,
                    |text: &String| {
                        crate::carrier::http_authority(text)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    },
                )?;
                plan.cdn = Some(CdnPlan { domain });
                ui::note(&format!(
                    "This server will connect to {} through the CDN.",
                    plan.cdn.as_ref().map_or("", |c| c.domain.as_str())
                ));
            } else {
                plan.cdn = Some(CdnPlan {
                    domain: String::new(),
                });
                ui::note(
                    "Point the CDN at this server's tunnel port (origin). Use a port the\nCDN supports, for example 8080 or 2052 for HTTP and 8443 or 2053 for HTTPS.",
                );
            }
        }
    }
    let port_prompt = if plan.dials() {
        format!("Tunnel port on the {other}")
    } else {
        "Tunnel port on this server".to_string()
    };
    if plan.dials() && plan.cdn.is_some() {
        return Ok(());
    }
    if plan.dials() {
        let known = plan.peer_host.clone();
        let transport = plan.transport;
        let host = ui::ask(
            &format!("Address of the {other} (IP or domain)"),
            known.as_deref(),
            |text: &String| check_host(text, transport),
        )?;
        plan.peer_host = Some(
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
        );
    }
    if plan.dials() {
        plan.tunnel_port = ask_port(&port_prompt, plan.tunnel_port)?;
    } else {
        let protocol = if super::plan::uses_udp(plan.transport) {
            "udp"
        } else {
            "tcp"
        };
        plan.tunnel_port = ask_free_port(&port_prompt, plan.tunnel_port, &[protocol])?;
    }
    Ok(())
}

fn raw_details(plan: &Plan) -> Result<Option<RawPlan>> {
    if !is_raw(plan.transport) {
        return Ok(None);
    }
    let other = plan.side.other().label();
    let peer = ui::ask(
        &format!("Real IPv4 address of the {other}"),
        None,
        |text: &String| unicast_ipv4(text).map(|_| ()).map_err(|e| e.to_string()),
    )?;
    if plan.transport == Transport::Mirage {
        let mirage = super::mirage::settings(None)?;
        let (interface, local_ip) = super::mirage::local_settings(None, None)?;
        return Ok(Some(RawPlan {
            profile: "tcp".into(),
            peer_ip: unicast_ipv4(&peer)?,
            ip_mode: IpMode::Normal,
            interface,
            local_ip,
            mirage: Some(mirage),
        }));
    }
    let profiles = ["tcp", "udp", "icmp", "gre", "ipip", "raw", "dns"];
    let labels: Vec<String> = [
        "TCP     packets look like TCP (recommended)",
        "UDP     packets look like UDP",
        "ICMP    packets look like ping",
        "GRE     GRE packets",
        "IPIP    IP-in-IP packets",
        "RAW     IP protocol 253",
        "DNS     packets look like DNS queries and answers, over UDP port 53",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let profile = ui::choose_required("Packet type (same on both servers)", &labels, 0)?;
    Ok(Some(RawPlan {
        profile: profiles[profile].into(),
        peer_ip: unicast_ipv4(&peer)?,
        ip_mode: IpMode::Normal,
        interface: None,
        local_ip: None,
        mirage: None,
    }))
}

/// Returns false when cancelled.
fn carry(plan: &mut Plan) -> Result<bool> {
    plan.tun = None;
    let mut options = vec![
        (
            Carry::Ports,
            "Port forwarding   users connect to ports on the Iran server (recommended)",
        ),
        (
            Carry::Socks,
            "SOCKS5 proxy      a proxy on the Iran server that exits abroad",
        ),
        (
            Carry::TunPorts,
            "TUN + ports       the virtual network and port forwarding",
        ),
        (
            Carry::Tun,
            "IP tunnel (TUN)   a virtual network between the two servers",
        ),
    ];
    if plan.transport == Transport::Tun {
        options.retain(|(carry, _)| carry.uses_tun());
    }
    let labels: Vec<String> = options.iter().map(|(_, l)| l.to_string()).collect();
    let Some(choice) = ui::choose("What should the tunnel carry?", &labels, 0)? else {
        return Ok(false);
    };
    plan.carry = options[choice].0;
    if plan.carry.uses_tun() {
        let (local, peer) = match plan.side {
            Side::Iran => ("10.77.0.1", "10.77.0.2"),
            Side::Foreign => ("10.77.0.2", "10.77.0.1"),
        };
        ui::note(
            "Both servers get an address on a private network. Use the same pair on both,\nswapped.",
        );
        let local_ip = ui::ask("This server's tunnel IP", Some(local), |t: &String| {
            check_ip(t)
        })?;
        let peer_ip = ui::ask("Other server's tunnel IP", Some(peer), |t: &String| {
            check_ip(t)
        })?;
        // A raw tunnel must fit inside one packet of the interface it leaves from.
        let mut mtu = super::iface::DEFAULT_TUN_MTU;
        if plan.transport == Transport::Tun
            && let Some(raw) = &plan.raw
            && let Some((suggested, interface, interface_mtu)) = super::iface::plan_tun_mtu(raw)
            && suggested < mtu
        {
            mtu = suggested;
            ui::note(&format!(
                "The interface {interface} has MTU {interface_mtu}, so the TUN MTU is set to {mtu}                  to fit the raw packets (change it under Customize)."
            ));
        }
        plan.tun = Some(TunPlan {
            name: "ez0".into(),
            local_ip,
            peer_ip,
            mtu,
            forwarding_port: (plan.carry == Carry::TunPorts).then_some(47475),
            fragment: false,
        });
    }
    match plan.side {
        Side::Iran => match plan.carry {
            Carry::Ports | Carry::TunPorts => {
                ui::note(
                    "Examples:  443   443, 8443   2083=443 (Iran port 2083 to foreign port 443)\n           9000-9010   5000=10.0.0.5:5000 (to another host)",
                );
                // The tunnel's own port cannot also be a forwarded port on a listening server.
                let reserved = (!plan.dials() && !super::plan::uses_udp(plan.transport))
                    .then_some(plan.tunnel_port);
                let text = ui::ask("Ports to forward", Some("443"), |text: &String| {
                    let rules = parse_ports(text).map_err(|e| e.to_string())?;
                    match reserved {
                        Some(port) if rules.iter().any(|r| r.listen == port) => Err(format!(
                            "port {port} is the tunnel port; choose other ports"
                        )),
                        _ => Ok(()),
                    }
                })?;
                plan.ports = parse_ports(&text)?;
                let protocols = [Protocol::Tcp, Protocol::Udp, Protocol::Both];
                let labels: Vec<String> = protocols.iter().map(|p| p.label().to_string()).collect();
                plan.protocol = protocols[ui::choose_required("Protocol", &labels, 0)?];
                for rule in &plan.ports {
                    let busy = match plan.protocol {
                        Protocol::Udp => service::port_busy(rule.listen, "udp"),
                        Protocol::Tcp => service::port_busy(rule.listen, "tcp"),
                        Protocol::Both => {
                            service::port_busy(rule.listen, "tcp")
                                || service::port_busy(rule.listen, "udp")
                        }
                    };
                    if busy {
                        ui::warn(&format!(
                            "Port {} is already in use on this server; the tunnel cannot use it until it is free.",
                            rule.listen
                        ));
                    }
                }
            }
            Carry::Socks => {
                ui::note(
                    "The proxy has no password. 127.0.0.1 keeps it on this server only;\n0.0.0.0 opens it to everyone (protect it with a firewall).",
                );
                plan.socks_bind =
                    ui::ask("SOCKS5 address", Some("127.0.0.1:1080"), |text: &String| {
                        text.parse::<std::net::SocketAddr>()
                            .map(|_| ())
                            .map_err(|_| "use IP:port, for example 127.0.0.1:1080".to_string())
                    })?;
                if let Ok(bind) = plan.socks_bind.parse::<std::net::SocketAddr>()
                    && service::port_busy(bind.port(), "tcp")
                {
                    ui::warn(&format!(
                        "Port {} is already in use on this server; the tunnel cannot use it until it is free.",
                        bind.port()
                    ));
                }
            }
            Carry::Tun => {}
        },
        Side::Foreign => match plan.carry {
            Carry::Socks => {
                plan.allowed = vec!["*".into()];
                ui::note("A SOCKS5 proxy may reach any address from this server.");
            }
            Carry::Ports | Carry::TunPorts => {
                let choices = vec![
                    "Only services on this server (127.0.0.1, any port) - recommended".to_string(),
                    "Any address (needed when ports lead to other hosts)".to_string(),
                ];
                plan.allowed =
                    if ui::choose_required("Where may forwarded ports lead?", &choices, 0)? == 0 {
                        vec!["127.0.0.1:*".into()]
                    } else {
                        vec!["*".into()]
                    };
            }
            Carry::Tun => {}
        },
    }
    Ok(true)
}

/// The first `ezN` interface name that no saved tunnel uses yet.
pub(super) fn free_tun_name(store: &Store) -> String {
    let used: Vec<String> = store
        .names()
        .unwrap_or_default()
        .iter()
        .filter_map(|name| store.read(name).ok())
        .filter_map(|config| config["tun"]["name"].as_str().map(str::to_string))
        .collect();
    first_free_tun_name(&used, |name| std::path::Path::new("/sys/class/net").join(name).exists())
}

/// C31: the first `ezN` that neither a saved tunnel nor an existing interface uses.
fn first_free_tun_name(used: &[String], exists: impl Fn(&str) -> bool) -> String {
    (0..4096)
        .map(|n| format!("ez{n}"))
        .find(|name| !used.contains(name) && !exists(name))
        .unwrap_or_else(|| "ez0".into())
}

/// The default `tun.forwarding_port`, or the first free one above it that no saved tunnel
/// already uses: a second TUN + ports (or SOCKS) tunnel would otherwise collide with it silently,
/// failing only at runtime.
fn free_forwarding_port(store: &Store) -> u16 {
    const DEFAULT: u16 = 47475;
    let used: Vec<u16> = store
        .names()
        .unwrap_or_default()
        .iter()
        .filter_map(|name| store.read(name).ok())
        .filter_map(|config| config["tun"]["forwarding_port"].as_u64())
        .filter_map(|port| u16::try_from(port).ok())
        .collect();
    (DEFAULT..)
        .find(|port| !used.contains(port))
        .unwrap_or(DEFAULT)
}

fn check_ip(text: &str) -> std::result::Result<(), String> {
    text.parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|_| "enter an IP address such as 10.77.0.1".to_string())
}

fn check_host(text: &str, transport: Transport) -> std::result::Result<(), String> {
    let host = text.trim_start_matches('[').trim_end_matches(']');
    if transport == Transport::Tcp6 {
        return host
            .parse::<std::net::Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| "TCP6 needs an IPv6 address".to_string());
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let valid = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if valid {
        Ok(())
    } else {
        Err("enter an IP address or a domain name".into())
    }
}

fn ask_port(prompt: &str, default: u16) -> Result<u16> {
    let text = ui::ask(
        prompt,
        Some(&default.to_string()),
        |text: &String| match text.parse::<u16>() {
            Ok(port) if port > 0 => Ok(()),
            _ => Err("enter a port from 1 to 65535".into()),
        },
    )?;
    Ok(text.parse()?)
}

/// Like `ask_port`, but warns and asks again (offering what was just entered as the new default)
/// for as long as the answer is already in use for any of `protocols` ("tcp", "udp", or both).
fn ask_free_port(prompt: &str, mut default: u16, protocols: &[&str]) -> Result<u16> {
    loop {
        let port = ask_port(prompt, default)?;
        if !protocols
            .iter()
            .any(|protocol| service::port_busy(port, protocol))
        {
            return Ok(port);
        }
        ui::warn(&format!("Port {port} is already in use on this server."));
        default = port;
    }
}

fn suggest_name(store: &Store, plan: &Plan) -> String {
    let base = format!(
        "{}-{}",
        match plan.side {
            Side::Iran => "iran",
            Side::Foreign => "foreign",
        },
        transport_name(plan.transport)
    );
    if !store.exists(&base) {
        return base;
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|name| !store.exists(name))
        .unwrap_or(base)
}

pub fn summary_lines(plan: &Plan) -> Vec<String> {
    let other = plan.side.other().label();
    let mut lines = vec![
        format!("{}  {}", ui::dim("This server  "), plan.side.label()),
        format!(
            "{}  {}",
            ui::dim("Tunnel type  "),
            if is_raw(plan.transport) {
                "raw packets".to_string()
            } else {
                format!("{} tunnel", plan.direction.label())
            }
        ),
        format!(
            "{}  {}",
            ui::dim("Transport    "),
            transport_name(plan.transport)
        ),
    ];
    let link = if let Some(cdn) = plan.cdn.as_ref().filter(|_| plan.dials()) {
        format!("connects to {other} through CDN {}", cdn.domain)
    } else if let Some(raw) = &plan.raw {
        format!(
            "raw packets with {} on port {}",
            raw.peer_ip, plan.tunnel_port
        )
    } else if plan.dials() {
        format!(
            "connects to {} at {}:{}",
            other,
            plan.peer_host.as_deref().unwrap_or("?"),
            plan.tunnel_port
        )
    } else {
        format!("waits for the {other} on port {}", plan.tunnel_port)
    };
    lines.push(format!("{}  {link}", ui::dim("Connection   ")));
    if let Some(mirage) = plan.raw.as_ref().and_then(|raw| raw.mirage.as_ref()) {
        lines.push(format!(
            "Mirage source {} -> destination {} (experimental)",
            mirage.spoof_src_ip,
            mirage
                .spoof_dst_ip
                .map_or("real peer".into(), |ip| ip.to_string())
        ));
    }
    let carry = match (plan.side, plan.carry) {
        (Side::Iran, Carry::Ports | Carry::TunPorts) => format!(
            "{}{} {} ({})",
            if plan.carry == Carry::TunPorts {
                "TUN + "
            } else {
                ""
            },
            "ports",
            format_ports(&plan.ports),
            plan.protocol.label()
        ),
        (Side::Iran, Carry::Socks) => format!("SOCKS5 proxy on {}", plan.socks_bind),
        (_, carry) => carry.label().to_string(),
    };
    lines.push(format!("{}  {carry}", ui::dim("Carries      ")));
    if plan.side == Side::Foreign && plan.carry != Carry::Tun {
        lines.push(format!(
            "{}  {}",
            ui::dim("May reach    "),
            plan.allowed.join(", ")
        ));
    }
    if let Some(tun) = &plan.tun {
        lines.push(format!(
            "{}  {} ↔ {}",
            ui::dim("TUN          "),
            tun.local_ip,
            tun.peer_ip
        ));
    }
    if !plan.tuned.is_empty() {
        lines.push(format!(
            "{}  {} changed",
            ui::dim("Settings     "),
            plan.tuned.len()
        ));
    }
    lines.push(format!("{}  {}", ui::dim("Tunnel key   "), plan.key));
    lines
}

/// What to do on the other server, so both sides match.
pub fn other_server_instructions(plan: &Plan) {
    let other = plan.side.other();
    let mut lines = vec![
        format!(
            "1. Run  {}  on the {}",
            ui::accent("sudo eztunnel"),
            other.label()
        ),
        format!("2. New tunnel → {}", ui::bold(other.label())),
    ];
    if is_raw(plan.transport) {
        lines.push(format!(
            "3. Transport {} · same packet type and port {}",
            ui::bold(&transport_name(plan.transport)),
            plan.tunnel_port
        ));
    } else {
        lines.push(format!(
            "3. {} tunnel · transport {} · port {}",
            ui::bold(plan.direction.label()),
            ui::bold(&transport_name(plan.transport)),
            plan.tunnel_port
        ));
    }
    lines.push(format!("4. Paste a key → {}", ui::accent(&plan.key)));
    if plan.carry.uses_tun() {
        lines.push(format!("5. Carry {}", ui::bold(plan.carry.label())));
    }
    ui::boxed("On the other server", &lines);
    ui::note("Keep the key secret: whoever has it can join this tunnel.");
}

fn offer_firewall(store: &Store, name: &str) -> Result<()> {
    if !service::ufw_active() {
        return Ok(());
    }
    let config = super::store::check_file(&store.path(name))?;
    let ports = service::listening_ports(&config);
    if ports.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = ports
        .iter()
        .map(|(p, proto)| format!("{p}/{proto}"))
        .collect();
    if ui::confirm(
        &format!("The ufw firewall is on. Open {}?", list.join(", ")),
        true,
    )? {
        for (port, protocol) in ports {
            match service::ufw_allow(port, protocol) {
                Ok(()) => ui::ok(&format!("Opened {port}/{protocol}")),
                Err(error) => ui::fail(&format!("{error:#}")),
            }
        }
    }
    Ok(())
}

/// Raw TCP carriers send packets the kernel does not expect; offer the two rules that keep its
/// resets and connection tracking out of the way (see `rawfw`).
fn offer_raw_rules(store: &Store, name: &str) -> Result<()> {
    let Ok(config) = super::store::check_file(&store.path(name)) else {
        return Ok(());
    };
    let Some(raw) = rawfw::endpoints(&config) else {
        return Ok(());
    };
    if rawfw::enabled(name) {
        return Ok(());
    }
    ui::note(
        "This carrier sends TCP-looking packets that no program owns, so the Linux kernel\nanswers them with resets that can break the link through NATs and firewalls.\nTwo firewall rules prevent that. They only touch the other server's address and\nthe two raw ports, and they are removed when the tunnel is deleted.",
    );
    if !rawfw::iptables_available() {
        ui::warn(
            "iptables was not found, so the rules cannot be added here. See docs/raw-protocol.md.",
        );
        return Ok(());
    }
    for rule in rawfw::rules(&raw, name) {
        ui::note(&format!("  {}", rule.command("-I")));
    }
    if ui::confirm("Add these rules now? (recommended)", true)? {
        match rawfw::enable(name, &config) {
            Ok(()) => ui::ok("Firewall rules added (they start with the tunnel)"),
            Err(error) => ui::fail(&format!("Could not add the rules: {error:#}")),
        }
    }
    Ok(())
}

/// `check_link` is false for the side that just created a new key: the other server almost
/// certainly is not set up yet, so waiting here for a session that cannot exist would only hold
/// up the wizard before telling the operator something they already know. The side that pasted
/// an existing key is normally joining an already-running peer, where the check is worth it.
fn wait_for_start(store: &Store, name: &str, check_link: bool) {
    std::thread::sleep(std::time::Duration::from_millis(1500));
    match service::state(store, name) {
        service::State::Running => {
            ui::ok("The tunnel is running.");
            if !check_link {
                return;
            }
            ui::info("Checking the connection to the other server...");
            match service::wait_link(name, 12) {
                service::LinkCheck::Working(rtt) => {
                    let delay = rtt.map_or(String::new(), |ms| format!(" (round trip {ms:.0} ms)"));
                    ui::ok(&format!(
                        "Connected to the other server, and traffic passes{delay}."
                    ));
                }
                service::LinkCheck::Unconfirmed => {
                    ui::ok("Connected to the other server.");
                    ui::note("This tunnel has no status channel, so traffic could not be checked.");
                }
                service::LinkCheck::NoTraffic => {
                    ui::warn("The servers found each other, but no traffic comes back.");
                    ui::note(
                        "A filter between them is probably blocking this carrier after the handshake.\nTry another transport, or the other direction (direct instead of reverse);\nplain WS, HTTP and KCP are the ones most often blocked.",
                    );
                }
                service::LinkCheck::NotConnected => {
                    ui::note(
                        "Not connected yet. That is expected if the other server is not set up yet;\nManage tunnels shows the link once both sides run.",
                    );
                }
            }
        }
        state => {
            ui::fail(&format!("The service is {state:?}. Recent log lines:"));
            for line in service::recent_logs(name, 8).lines() {
                ui::note(line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measured_peer_setup_preserves_carry_and_swaps_only_endpoint_state()->Result<()> {
        let report=crate::spoof_session::Report{session:"1".repeat(24),created_at:0,finished:true,depth:crate::spoof_session::Depth::Quick,
            iran:"192.0.2.1".parse()?,foreign:"192.0.2.2".parse()?,raw_port:45670,iran_bound:vec![],foreign_bound:vec![],error:None};
        for side in [Side::Iran,Side::Foreign]{for carry in [Carry::Ports,Carry::Socks,Carry::Tun,Carry::TunPorts]{
            let mut plan=Plan::new(TunnelKey::generate()?.display(),side,Direction::Reverse,Transport::Mirage);
            plan.tunnel_port=45670;plan.carry=carry;plan.peer_host=Some(if side==Side::Iran{report.foreign}else{report.iran}.to_string());
            plan.ports=parse_ports("8443=127.0.0.1:443")?;plan.protocol=Protocol::Both;plan.allowed=vec!["127.0.0.1:443".into()];
            if carry.uses_tun(){plan.tun=Some(TunPlan{name:"ez0".into(),local_ip:if side==Side::Iran{"10.77.0.1"}else{"10.77.0.2"}.into(),peer_ip:if side==Side::Iran{"10.77.0.2"}else{"10.77.0.1"}.into(),mtu:1400,forwarding_port:(carry==Carry::TunPorts).then_some(47475),fragment:false});}
            let peer=mirage_peer_plan(&plan,&report,RawProfile::Udp,"198.51.100.1".parse()?,RawProfile::Icmp,report.iran)?;
            assert_eq!(peer.side,side.other());assert_eq!(peer.key,plan.key);assert_eq!(peer.carry,carry);
            let value=peer.to_json()?;check(&value)?;
            let bundle=crate::spoof_session::SetupBundle::new(value)?;let encoded=bundle.encode()?;
            assert!(crate::spoof_session::SetupBundle::decode(&encoded,crate::spoof_session::now()?).is_ok());
            let raw=&bundle.config[if peer.side==Side::Iran{"listeners"}else{"paths"}][0]["raw"];
            assert_eq!(raw["peer_ip"],if side==Side::Iran{report.iran}else{report.foreign}.to_string());
            assert_eq!(raw["mirage"]["uplink"],"udp");assert_eq!(raw["mirage"]["downlink"],"icmp");
            if let (Some(a),Some(b))=(&plan.tun,&peer.tun){assert_eq!(a.local_ip,b.peer_ip);assert_eq!(a.peer_ip,b.local_ip);}
        }}Ok(())
    }

    /// The "Settings" list has the four profiles and then "Customize", which starts from General.
    #[test]
    fn customize_starts_from_general_and_each_profile_is_itself() {
        for (index, profile) in Profile::ALL.iter().enumerate() {
            assert_eq!(profile_for_choice(index), *profile);
        }
        assert_eq!(profile_for_choice(Profile::ALL.len()), Profile::General);
        assert_eq!(profile_for_choice(99), Profile::General);
    }

    fn spec(transport:Transport,variant:crate::checker::Variant,profile:Option<RawProfile>)->crate::checker::CaseSpec{
        crate::checker::CaseSpec{id:1,transport,dialer:None,variant,profile}
    }

    /// C18: the measured variant is the starting state of the chosen settings, and a manual
    /// edit survives returning to the same choice; a different choice re-applies it.
    #[test]
    fn measured_variant_is_applied_once_per_choice_and_manual_edits_survive()->Result<()>{
        use crate::checker::Variant;
        let key=||TunnelKey::generate().map(|k|k.display());
        let mut plan=Plan::new(key()?,Side::Iran,Direction::Reverse,Transport::Wss);
        let tested=Some(spec(Transport::Wss,Variant::BrowserTls,None));
        let mut applied=None;
        select_settings(&mut plan,&mut applied,0,tested);
        assert_eq!(plan.tls_profile,crate::config::TlsProfile::Chrome);
        plan.tls_profile=crate::config::TlsProfile::Classic;
        select_settings(&mut plan,&mut applied,0,tested);
        assert_eq!(plan.tls_profile,crate::config::TlsProfile::Classic,"same choice must keep the manual edit");
        select_settings(&mut plan,&mut applied,Profile::ALL.len(),tested);
        assert_eq!(plan.tls_profile,crate::config::TlsProfile::Chrome,"a new choice starts from the tested variant");

        for (variant,check) in [
            (Variant::TlsFragment,(|p:&Plan|p.tls_fragment) as fn(&Plan)->bool),
            (Variant::Congestion,|p:&Plan|p.tcp_congestion.as_deref()==Some(crate::checker::CONGESTION_TEST_ALGORITHM)),
        ]{
            let mut plan=Plan::new(key()?,Side::Iran,Direction::Reverse,Transport::Wss);
            select_settings(&mut plan,&mut None,0,Some(spec(Transport::Wss,variant,None)));
            assert!(check(&plan),"{variant:?} not applied");
        }
        let mut plan=Plan::new(key()?,Side::Iran,Direction::Reverse,Transport::Kcp);
        select_settings(&mut plan,&mut None,0,Some(spec(Transport::Kcp,Variant::Pacer,None)));
        assert!(plan.fec_pacer);

        // Raw TUN: packet type and fragmented MTU come from the measured case.
        let mut plan=Plan::new(key()?,Side::Iran,Direction::Reverse,Transport::Tun);
        plan.raw=Some(RawPlan{profile:"tcp".into(),peer_ip:"192.0.2.2".parse()?,ip_mode:IpMode::Normal,interface:None,local_ip:None,mirage:None});
        plan.tun=Some(TunPlan{name:"ez0".into(),local_ip:"10.77.0.1".into(),peer_ip:"10.77.0.2".into(),mtu:1400,forwarding_port:None,fragment:false});
        select_settings(&mut plan,&mut None,0,Some(spec(Transport::Tun,Variant::Fragment,Some(RawProfile::Udp))));
        assert_eq!(plan.raw.as_ref().map(|r|r.profile.as_str()),Some(crate::checker::profile_name(RawProfile::Udp)));
        let tun=plan.tun.as_ref().expect("tun");
        assert!(tun.fragment);assert_eq!(tun.mtu,crate::checker::FRAGMENT_TEST_MTU);

        // Without a measured case nothing beyond the profile changes.
        let mut plan=Plan::new(key()?,Side::Iran,Direction::Reverse,Transport::Wss);
        select_settings(&mut plan,&mut None,0,None);
        assert!(plan.tls_profile.is_classic());assert!(!plan.tls_fragment);assert!(plan.tcp_congestion.is_none());
        Ok(())
    }

    /// C30: a busy agreed forwarding port is kept and reported; only the local name changes.
    #[test]
    fn imported_tun_keeps_the_agreed_port_even_when_busy(){
        let tun=||TunPlan{name:"ez0".into(),local_ip:"10.77.0.2".into(),peer_ip:"10.77.0.1".into(),mtu:1400,forwarding_port:Some(47475),fragment:false};
        let mut busy=tun();
        let warning=localize_imported_tun(&mut busy,"ez3".into(),|port|port==47475);
        assert_eq!(busy.forwarding_port,Some(47475));assert_eq!(busy.name,"ez3");
        assert!(warning.is_some_and(|w|w.contains("47475")));
        let mut free=tun();
        assert!(localize_imported_tun(&mut free,"ez1".into(),|_|false).is_none());
        assert_eq!(free.forwarding_port,Some(47475));assert_eq!(free.name,"ez1");
        let mut plain=TunPlan{forwarding_port:None,..tun()};
        assert!(localize_imported_tun(&mut plain,"ez2".into(),|_|true).is_none());
        assert_eq!(plain.forwarding_port,None);
    }

    /// C31: the free name skips both saved tunnels' names.
    #[test]
    fn free_tun_name_skips_names_saved_tunnels_use(){
        let (_directory, store) = store_with(&[("a", tun_config(47475))]);
        assert_ne!(free_tun_name(&store),"ez0");
        // An interface that exists on the system (another program's, or a stale one) is skipped too.
        let used=vec!["ez0".to_string()];
        assert_eq!(first_free_tun_name(&used,|name|name=="ez1"||name=="ez2"),"ez3");
        assert_eq!(first_free_tun_name(&[],|_|false),"ez0");
    }

    fn store_with(tunnels: &[(&str, serde_json::Value)]) -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::for_test(directory.path().to_path_buf());
        for (name, config) in tunnels {
            store.save(name, config).unwrap();
        }
        (directory, store)
    }

    fn tun_config(forwarding_port: u16) -> serde_json::Value {
        serde_json::json!({"mode":"client",
            "tunnel_key": crate::tunnel_key::TunnelKey::generate().unwrap().display(),
            "tun": {"name": "ez0", "address": "10.77.0.2", "peer_address": "10.77.0.1",
                "mtu": 1400, "forwarding_port": forwarding_port},
            "allowed_targets": ["127.0.0.1:*"],
            "paths": [{"addr": "192.0.2.1:4443", "transport": "tun",
                "raw": {"profile": "tcp", "peer_ip": "192.0.2.1", "l4_port": 4443}}]})
    }

    #[test]
    fn free_forwarding_port_skips_every_port_a_saved_tunnel_already_uses() {
        let (_directory, store) = store_with(&[]);
        assert_eq!(
            free_forwarding_port(&store),
            47475,
            "the default when nothing is taken"
        );
        let (_directory, store) = store_with(&[("a", tun_config(47475))]);
        assert_eq!(free_forwarding_port(&store), 47476);
        // Gaps are filled before counting further up.
        let (_directory, store) = store_with(&[("a", tun_config(47475)), ("b", tun_config(47477))]);
        assert_eq!(free_forwarding_port(&store), 47476);
    }
}
