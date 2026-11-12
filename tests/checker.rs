//! The transport checker end to end on one machine: the "Iran server" is 127.0.0.2 and the
//! "foreign server" 127.0.0.1, each running its half in this process, paired over the control link.
use std::{net::IpAddr, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use eztunnel::checker::{
    Options, Report, Side, Verdict,
    code::CheckCode,
    control::Command,
    run::{self, Handle},
};
use eztunnel::config::Transport;

fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

fn code(options: Options) -> Result<CheckCode> {
    let iran: IpAddr = "127.0.0.2".parse()?;
    let foreign: IpAddr = "127.0.0.1".parse()?;
    CheckCode::new(Side::Iran, iran, foreign, options)
}

async fn finish(handle: Handle, limit: Duration) -> Result<Report> {
    tokio::time::timeout(limit, handle.task)
        .await
        .context("the check did not finish in time")??
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_sides_check_every_case_and_agree_on_the_report() -> Result<()> {
    let options = Options {
        transports: vec![
            Transport::Tcp,
            Transport::Wss,
            Transport::Xhttp,
            Transport::Kcp,
            Transport::FecUdp,
            Transport::FecRaw,
        ],
        dialers: vec![Side::Foreign, Side::Iran],
        pings: 3,
        download: true,
        upload: true,
        parallel: true,
        speed_sec: 3,
        hold_sec: 2,
        mtu: true,
        repeat_failed: false,
        tls_port: free_port()?,
        control_port: free_port()?,
        ..Options::default()
    };
    let code = code(options)?;
    let iran = run::spawn(code.clone(), Side::Iran);
    let foreign = run::spawn(code, Side::Foreign);
    let mut view = foreign.view.clone();
    let (iran, foreign) = tokio::join!(
        finish(iran, Duration::from_secs(240)),
        finish(foreign, Duration::from_secs(240))
    );
    let (iran, foreign) = (iran?, foreign?);
    // The foreign server saw the same live view and got the same report.
    ensure!(
        view.borrow_and_update().finished,
        "the foreign view did not finish"
    );
    let summary = |report: &Report| {
        report
            .cases
            .iter()
            .map(|c| {
                (
                    c.spec,
                    c.verdict,
                    c.port,
                    c.handshake_ms,
                    c.download.clone(),
                    c.udp.clone(),
                    c.udp_loaded.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    ensure!(
        summary(&foreign) == summary(&iran),
        "the two reports differ"
    );
    ensure!(iran.stopped.is_none(), "stopped: {:?}", iran.stopped);
    eprintln!("{}", iran.text());
    let baseline = iran.baseline.as_ref().context("no baseline")?;
    ensure!(baseline.tcp, "baseline: {baseline:?}");
    for case in &iran.cases {
        let verdict = case.verdict.context("a case without verdict")?;
        if case.spec.transport == Transport::FecRaw {
            // Raw packets need root; as a normal user the case says so instead of failing.
            ensure!(
                verdict == Verdict::NotPossible || verdict.usable(),
                "fec-raw: {verdict:?} {:?}",
                case.note
            );
            continue;
        }
        // A busy test machine can make the UDP-based ones slow or shaky; every case must carry
        // data, and the TCP-based ones must not be shaky.
        let tcp_based = !matches!(case.spec.transport, Transport::Kcp | Transport::FecUdp);
        ensure!(
            verdict.usable() && (!tcp_based || verdict != Verdict::Unstable),
            "{} dialed by {}: {verdict:?} ({:?})",
            case.spec.transport_name(),
            case.spec.dialer_label(),
            case
        );
        ensure!(case.port.is_some());
        let handshake = case.handshake_ms.context("no handshake time")?;
        ensure!(
            handshake > 0 && handshake < 5000,
            "handshake {handshake} ms"
        );
        let ping = case.ping.as_ref().context("no ping")?;
        ensure!(ping.answered == 3, "{ping:?}");
        ensure!(case.download.as_ref().is_some_and(|t| t.ok()));
        ensure!(case.upload.as_ref().is_some_and(|t| t.ok()));
        // Four streams at once on a busy test machine may stall one of them; data must move.
        ensure!(case.parallel.as_ref().is_some_and(|t| t.bytes > 0));
        ensure!(case.hold.as_ref().is_some_and(|h| h.pings > 0));
        ensure!(case.heartbeats.1 > 0 || case.hold.is_some());
        // UDP went through the tunnel's map, idle and during the download. On loopback nothing
        // is lost by the network; a busy machine may drop a few under load.
        let udp = case.udp.as_ref().context("no UDP measurement")?;
        ensure!(udp.sent == 300 && udp.answered >= 270, "{udp:?}");
        ensure!(udp.median_ms.is_some() && udp.p95_ms.is_some());
        let loaded = case
            .udp_loaded
            .as_ref()
            .context("no loaded UDP measurement")?;
        ensure!(loaded.sent == 300 && loaded.answered >= 150, "{loaded:?}");
        ensure!(case.note.as_deref() != Some("UDP not carried"));
    }
    let best = eztunnel::checker::rank(&iran.cases, iran.options.priority);
    ensure!(!best.is_empty());
    Ok(())
}

/// The three new case variants (`also_congestion`, `also_pacer`, `also_fragment`) end to end:
/// each must actually produce a working case, not just a config that parses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_congestion_pacer_and_fragment_variants_actually_work() -> Result<()> {
    use eztunnel::checker::Variant;
    let options = Options {
        transports: vec![Transport::Tcp, Transport::FecUdp, Transport::Tun],
        dialers: vec![Side::Foreign],
        tun_profiles: vec![eztunnel::raw_packet::RawProfile::Tcp],
        pings: 3,
        download: true,
        upload: true,
        hold_sec: 0,
        mtu: false,
        udp: false,
        repeat_failed: false,
        also_congestion: true,
        also_pacer: true,
        also_fragment: true,
        tls_port: free_port()?,
        control_port: free_port()?,
        ..Options::default()
    };
    let code = code(options)?;
    let iran = run::spawn(code.clone(), Side::Iran);
    let foreign = run::spawn(code, Side::Foreign);
    let (iran, foreign) = tokio::join!(
        finish(iran, Duration::from_secs(120)),
        finish(foreign, Duration::from_secs(120))
    );
    let (iran, _foreign) = (iran?, foreign?);
    ensure!(iran.stopped.is_none(), "stopped: {:?}", iran.stopped);
    eprintln!("{}", iran.text());

    let congestion = iran
        .cases
        .iter()
        .find(|c| c.spec.transport == Transport::Tcp && c.spec.variant == Variant::Congestion)
        .context("no tcp_congestion case")?;
    ensure!(
        congestion.verdict.is_some_and(|v| v.usable()),
        "tcp_congestion override: {:?} ({:?})",
        congestion.verdict,
        congestion.note
    );
    ensure!(congestion.download.as_ref().is_some_and(|t| t.ok()));

    let pacer = iran
        .cases
        .iter()
        .find(|c| c.spec.transport == Transport::FecUdp && c.spec.variant == Variant::Pacer)
        .context("no pacer case")?;
    ensure!(
        pacer.verdict.is_some_and(|v| v.usable()),
        "fec.pacer: {:?} ({:?})",
        pacer.verdict,
        pacer.note
    );
    ensure!(pacer.download.as_ref().is_some_and(|t| t.ok()));
    ensure!(pacer.upload.as_ref().is_some_and(|t| t.ok()));

    let fragment = iran
        .cases
        .iter()
        .find(|c| c.spec.transport == Transport::Tun && c.spec.variant == Variant::Fragment)
        .context("no tun.fragment case")?;
    // Raw TUN needs root and, depending on the machine, a real Ethernet/veth interface to bind a
    // raw socket to (WSL's virtualised networking has neither a loopback one nor always root, so
    // this is genuinely environment-dependent, the same as the existing fec-raw case above: a
    // test machine without the prerequisites gets a clear "not possible here", and only a usable
    // verdict is actually checked for real data movement).
    match fragment.verdict {
        Some(Verdict::NotPossible) => {}
        Some(verdict) if verdict.usable() => {
            // The real proof: data actually moved through a packet too big for one outer packet,
            // which only works if it was genuinely split and reassembled.
            ensure!(
                fragment.download.as_ref().is_some_and(|t| t.ok() && t.bytes > 0),
                "{:?}",
                fragment.download
            );
            ensure!(
                fragment.upload.as_ref().is_some_and(|t| t.ok() && t.bytes > 0),
                "{:?}",
                fragment.upload
            );
        }
        other => bail!("tun.fragment: {other:?} ({:?})", fragment.note),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_from_the_foreign_server_ends_the_check_with_a_partial_report() -> Result<()> {
    let options = Options {
        transports: vec![Transport::Tcp, Transport::Kcp],
        dialers: vec![Side::Foreign],
        pings: 2,
        download: false,
        upload: false,
        hold_sec: 60,
        mtu: false,
        control_port: free_port()?,
        ..Options::default()
    };
    let code = code(options)?;
    let iran = run::spawn(code.clone(), Side::Iran);
    let foreign = run::spawn(code, Side::Foreign);
    // Wait until the first case is holding, then press "stop" on the foreign server.
    let mut view = foreign.view.clone();
    tokio::time::timeout(
        Duration::from_secs(60),
        view.wait_for(|v| v.step.contains("stability hold")),
    )
    .await
    .context("never reached the hold")??;
    foreign.commands.send(Command::Stop)?;
    let (iran, foreign) = tokio::join!(
        finish(iran, Duration::from_secs(30)),
        finish(foreign, Duration::from_secs(30))
    );
    let (iran, _foreign) = (iran?, foreign?);
    ensure!(iran.stopped.is_some(), "not marked as stopped");
    ensure!(
        iran.cases[0].verdict == Some(Verdict::Stopped),
        "{:?}",
        iran.cases[0]
    );
    ensure!(iran.cases[1].verdict == Some(Verdict::Skipped));
    ensure!(iran.seconds < 40, "the stop took too long");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_works_while_waiting_for_the_other_server() -> Result<()> {
    let options = Options {
        transports: vec![Transport::Tcp],
        control_port: free_port()?,
        ..Options::default()
    };
    for side in [Side::Iran, Side::Foreign] {
        let handle = run::spawn(code(options.clone())?, side);
        tokio::time::sleep(Duration::from_millis(500)).await;
        handle.commands.send(Command::Stop)?;
        let outcome = tokio::time::timeout(Duration::from_secs(10), handle.task)
            .await
            .context("stop was ignored while waiting")??;
        ensure!(
            outcome.is_err(),
            "a check without the other server cannot have a report"
        );
    }
    Ok(())
}
