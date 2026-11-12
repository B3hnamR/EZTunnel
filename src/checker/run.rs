//! Running a check. The Iran server coordinates: it runs the measurements (its test map is where
//! users would connect) and tells the foreign server when to start and stop its half of each
//! case. Both servers show the same live view and either can pause, skip or stop.
use super::case::{self, Running, Setup};
use super::code::CheckCode;
use super::control::{self, Command, Link, Message};
use super::{
    Baseline, CaseResult, CaseSpec, HoldStats, Options, Report, Side, Verdict, logbuf, measure,
    service::Service,
};
use anyhow::{Context, Result, bail,ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering::Relaxed},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time,
};

/// Longest wait for a tunnel to answer again after the transfers, before the hold.
const SETTLE_LIMIT: Duration = Duration::from_secs(15);
/// How long a case waits for the first authenticated session.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(15);
/// How long pairing waits for the other server, at the start and after a lost connection.
const PAIR_LIMIT: Duration = Duration::from_secs(600);
const REPAIR_LIMIT: Duration = Duration::from_secs(60);

/// What both screens show while a check runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct View {
    pub iran_ip: String,
    pub foreign_ip: String,
    pub rows: Vec<CaseResult>,
    /// The case running now.
    pub current: Option<u32>,
    /// What is happening, in a few words.
    pub step: String,
    pub paused: bool,
    /// Pause was pressed; it takes effect after the current step.
    #[serde(default)]
    pub pause_requested: bool,
    pub connected: bool,
    pub elapsed_sec: u64,
    pub remaining_sec: u64,
    pub baseline: Option<Baseline>,
    pub finished: bool,
}

/// A check running in the background.
pub struct Handle {
    pub view: watch::Receiver<View>,
    pub commands: mpsc::UnboundedSender<Command>,
    pub task: JoinHandle<Result<Report>>,
}

/// Starts this server's part of the check described by `code`.
pub fn spawn(code: CheckCode, me: Side) -> Handle {
    logbuf::capture();
    let (view_tx, view) = watch::channel(View {
        iran_ip: code.iran_ip.to_string(),
        foreign_ip: code.foreign_ip.to_string(),
        rows: code
            .options
            .cases()
            .into_iter()
            .map(CaseResult::new)
            .collect(),
        step: "starting".into(),
        remaining_sec: code.options.estimate_seconds(),
        ..View::default()
    });
    let (commands, commands_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        match me {
            Side::Iran => coordinate(code, view_tx, commands_rx).await,
            Side::Foreign => follow(code, view_tx, commands_rx).await,
        }
    });
    Handle {
        view,
        commands,
        task,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Pause, skip and stop, shared by the keys of both servers and the running case.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct GateState {
    paused: bool,
    stop: bool,
    /// Grows by one per skip; a case remembers the value it started with.
    skips: u64,
}

#[derive(Clone)]
struct Gate(Arc<watch::Sender<GateState>>);

impl Gate {
    fn new() -> Self {
        Self(Arc::new(watch::Sender::new(GateState::default())))
    }

    fn apply(&self, command: Command) {
        self.0.send_modify(|state| match command {
            Command::Pause => state.paused = true,
            Command::Resume => state.paused = false,
            Command::Skip => state.skips += 1,
            Command::Stop => {
                state.stop = true;
                state.paused = false;
            }
        });
    }

    fn state(&self) -> GateState {
        *self.0.borrow()
    }

    /// Waits while paused. Returns false when the check is to stop.
    async fn wait_unpaused(&self) -> bool {
        let mut watcher = self.0.subscribe();
        let state = watcher
            .wait_for(|state| !state.paused || state.stop)
            .await
            .map(|s| *s)
            .unwrap_or(GateState {
                stop: true,
                ..GateState::default()
            });
        !state.stop
    }

    /// Completes when the check is to stop.
    async fn stopped(&self) {
        let mut watcher = self.0.subscribe();
        let _ = watcher.wait_for(|state| state.stop).await;
    }

    /// Completes when the case that started at `skips` is to end (skipped or stopped).
    async fn interrupted(&self, skips: u64) {
        let mut watcher = self.0.subscribe();
        let _ = watcher
            .wait_for(|state| state.stop || state.skips != skips)
            .await;
    }
}

/// The coordinator's view of the check, published to its own screen at once and to the other
/// server a few times a second.
struct Board {
    view: watch::Sender<View>,
    started: Instant,
    options: Options,
}

impl Board {
    fn update(&self, change: impl FnOnce(&mut View)) {
        self.view.send_modify(|view| {
            change(view);
            view.elapsed_sec = self.started.elapsed().as_secs();
            let left = view.rows.iter().filter(|r| r.verdict.is_none()).count() as u64;
            view.remaining_sec = left * self.options.case_seconds();
        });
    }

    fn step(&self, text: impl Into<String>) {
        let text = text.into();
        self.update(|view| view.step = text);
    }

    fn row(&self, id: u32, change: impl FnOnce(&mut CaseResult)) {
        self.update(|view| {
            if let Some(row) = view.rows.iter_mut().find(|r| r.spec.id == id) {
                change(row);
            }
        });
    }
}

/// Messages from the foreign server, sorted: keys go straight to the gate, the rest to the
/// coordinator in order.
struct Inbox {
    replies: mpsc::Receiver<Message>,
    _task: JoinHandle<()>,
}

impl Inbox {
    fn new(link: Link, gate: Gate) -> (mpsc::Sender<Message>, Self) {
        let sender = link.sender.clone();
        let (deliver, replies) = mpsc::channel(64);
        let task = tokio::spawn(async move {
            let mut link = link;
            while let Ok(message) = link.recv().await {
                match message {
                    Message::Command(command) => gate.apply(command),
                    Message::Bye => {
                        gate.apply(Command::Stop);
                        break;
                    }
                    other => {
                        if deliver.send(other).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        (
            sender,
            Self {
                replies,
                _task: task,
            },
        )
    }

    /// The next reply; an error when the link is gone or nothing came in `limit`.
    async fn next(&mut self, limit: Duration) -> Result<Message> {
        time::timeout(limit, self.replies.recv())
            .await
            .context("the other server did not answer")?
            .context("the connection to the other server was lost")
    }
}

struct Peer {
    sender: mpsc::Sender<Message>,
    inbox: Inbox,
    service_port: u16,
    _publisher: JoinHandle<()>,
}

impl Peer {
    async fn send(&self, message: Message) -> Result<()> {
        self.sender
            .send(message)
            .await
            .map_err(|_| anyhow::anyhow!("the connection to the other server was lost"))
    }
}

/// Pairs with the foreign server (again, after a lost connection) and waits for its test service.
async fn connect_peer(
    code: &CheckCode,
    board: &Board,
    gate: &Gate,
    limit: Duration,
) -> Result<Peer> {
    board.update(|view| view.connected = false);
    let link = control::pair(code, Side::Iran, limit, |status| board.step(status)).await?;
    let (sender, mut inbox) = Inbox::new(link, gate.clone());
    let service_port = loop {
        match inbox.next(Duration::from_secs(30)).await? {
            Message::Ready { service_port } => break service_port,
            _ => continue,
        }
    };
    board.update(|view| view.connected = true);
    // The live view goes to the other server whenever it changed, at most four times a second.
    let mut watcher = board.view.subscribe();
    let link_sender = sender.clone();
    let publisher = tokio::spawn(async move {
        loop {
            if watcher.changed().await.is_err() {
                return;
            }
            let view = watcher.borrow_and_update().clone();
            if link_sender
                .send(Message::View(Box::new(view)))
                .await
                .is_err()
            {
                return;
            }
            time::sleep(Duration::from_millis(250)).await;
        }
    });
    Ok(Peer {
        sender,
        inbox,
        service_port,
        _publisher: publisher,
    })
}

async fn coordinate(
    code: CheckCode,
    view: watch::Sender<View>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) -> Result<Report> {
    let options = code.options.clone();
    let board = Board {
        view,
        started: Instant::now(),
        options: options.clone(),
    };
    let gate = Gate::new();
    {
        // Both screens show a pause as soon as it is pressed, not only once it took effect.
        let view = board.view.clone();
        let mut state = gate.0.subscribe();
        tokio::spawn(async move {
            while state.changed().await.is_ok() {
                let now = *state.borrow_and_update();
                view.send_modify(|v| v.pause_requested = now.paused && !now.stop);
            }
        });
    }
    {
        let gate = gate.clone();
        tokio::spawn(async move {
            while let Some(command) = commands.recv().await {
                gate.apply(command);
            }
        });
    }
    let started_at = now_unix();
    // Stop works while waiting for the other server too.
    let mut peer = tokio::select! {
        peer = connect_peer(&code, &board, &gate, PAIR_LIMIT) => peer?,
        () = gate.stopped() => bail!("stopped before the other server joined"),
    };
    let mut baseline = None;
    if options.mtu && checkpoint(&board, &gate).await {
        board.step("baseline: plain TCP/UDP and the largest datagram");
        baseline = Some(
            run_baseline(&code, &mut peer)
                .await
                .unwrap_or_else(|error| Baseline {
                    error: Some(format!("{error:#}")),
                    ..Baseline::default()
                }),
        );
        let measured = baseline.clone();
        board.update(|view| view.baseline = measured);
    }
    let mut stopped = None;
    let cases = options.cases();
    let mut index = 0;
    while index < cases.len() {
        let spec = cases[index];
        if !checkpoint(&board, &gate).await {
            stopped = Some("stopped by the user".to_string());
            break;
        }
        board.update(|view| view.current = Some(spec.id));
        let outcome = run_case_with_repeat(&code, &board, &gate, &mut peer, spec).await;
        match outcome {
            Ok(()) => index += 1,
            Err(error) => {
                // The control connection was lost: clean up, reconnect, run the case again.
                logbuf::push(format!("control connection lost: {error:#}"));
                board.row(spec.id, |row| *row = CaseResult::new(spec));
                board.step("lost the connection to the other server; reconnecting");
                match connect_peer(&code, &board, &gate, REPAIR_LIMIT).await {
                    Ok(again) => peer = again,
                    Err(error) => {
                        stopped = Some(format!("lost the other server: {error:#}"));
                        break;
                    }
                }
            }
        }
        if gate.state().stop {
            stopped = Some("stopped by the user".to_string());
            break;
        }
    }
    board.update(|view| {
        view.current = None;
        view.finished = true;
        view.step = match &stopped {
            Some(reason) => format!("stopped: {reason}"),
            None => "finished".into(),
        };
        for row in &mut view.rows {
            if row.verdict.is_none() {
                row.verdict = Some(Verdict::Skipped);
                row.note = Some("not run".into());
            }
        }
    });
    let report = Report {
        version: env!("CARGO_PKG_VERSION").into(),
        started: started_at,
        seconds: board.started.elapsed().as_secs(),
        iran_ip: code.iran_ip.to_string(),
        foreign_ip: code.foreign_ip.to_string(),
        options,
        baseline,
        cases: board.view.borrow().rows.clone(),
        stopped,
    };
    let _ = peer.send(Message::Done(Box::new(report.clone()))).await;
    // Let the report leave before the link closes.
    time::sleep(Duration::from_millis(300)).await;
    Ok(report)
}

async fn run_baseline(code: &CheckCode, peer: &mut Peer) -> Result<Baseline> {
    peer.send(Message::BaselineListen).await?;
    let Message::BaselineReady { port, error } = wait_for_mut(peer, Duration::from_secs(20), |m| {
        matches!(m, Message::BaselineReady { .. })
    })
    .await?
    else {
        unreachable!("filtered above")
    };
    if let Some(error) = error {
        bail!("the foreign server could not start the link test: {error}");
    }
    let port = port.context("no link test port")?;
    let report = crate::linktest::probe(crate::linktest::ProbeOptions {
        peer: SocketAddr::new(code.foreign_ip, port),
        bind: local_or_any(code.iran_ip, code.foreign_ip),
        local_port: 0,
        extra_ports: Vec::new(),
        seconds: Duration::from_secs(2),
        timeout: Duration::from_secs(5),
        quick: true,
        mtu: true,
    })
    .await?;
    let loss = (report.udp.sent > 0).then_some(report.udp.loss_percent);
    Ok(Baseline {
        tcp: report.tcp.ok,
        udp_loss_percent: loss,
        path_mtu: report.mtu.as_ref().and_then(|m| m.path_mtu),
        error: None,
    })
}

/// `own` when this machine has that address (the link test listener on the other side only
/// accepts it), otherwise any address of the same family as `other`.
fn local_or_any(own: IpAddr, other: IpAddr) -> IpAddr {
    if std::net::UdpSocket::bind((own, 0)).is_ok() {
        own
    } else {
        unspecified(other)
    }
}

fn unspecified(like: IpAddr) -> IpAddr {
    if like.is_ipv6() {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    }
}

/// The next reply that `wanted` accepts within `limit` (others are dropped).
async fn wait_for_mut(
    peer: &mut Peer,
    limit: Duration,
    wanted: impl Fn(&Message) -> bool,
) -> Result<Message> {
    let deadline = Instant::now() + limit;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let message = peer.inbox.next(left).await?;
        if wanted(&message) {
            return Ok(message);
        }
    }
}

/// Runs a case, and once more when it failed and the options say so. An `Err` means the control
/// connection was lost; every other problem ends up in the row.
/// UDP packets of the idle measurement: three seconds at `measure::UDP_RATE`.
const UDP_IDLE_PACKETS: u32 = 300;

/// V01: the follower starts only cases that are in the plan this side accepted; the
/// coordinator cannot add, say, a raw TUN case to a TCP-only check.
fn accepted_case(options: &Options, spec: &CaseSpec) -> Result<()> {
    ensure!(options.cases().contains(spec), "peer requested a checker case outside the locally accepted plan");
    Ok(())
}

/// C04: a loaded UDP sample is kept only when it was measured and the load it ran under
/// completed without error.
fn loaded_sample(loaded: super::UdpStats, transfer: &super::Transfer) -> Option<super::UdpStats> {
    (loaded.sent > 0 && transfer.error.is_none() && transfer.bytes > 0).then_some(loaded)
}

enum Retry {
    /// The retry ended with an explicit Stopped/Skipped/NotPossible: report it as is.
    Terminal(CaseResult),
    Measured(CaseResult, Verdict),
}

/// C05: merges a measured first failure with its retry. A retry that ended with an
/// explicit terminal verdict keeps that verdict and its explanation; only the one
/// measured failure is counted, not "failed 2 of 2".
fn combine_retry(first: CaseResult, first_verdict: Verdict, mut second: CaseResult, options: &Options) -> Retry {
    second.runs = 2;
    if let Some(terminal) = second.verdict {
        second.failed_runs = 1;
        let reason = second.note.take();
        second.note = Some(match reason {
            Some(reason) => format!("first run failed ({}); retry {}: {reason}", first_verdict.label(), terminal.label()),
            None => format!("first run failed ({}); retry {}", first_verdict.label(), terminal.label()),
        });
        return Retry::Terminal(second);
    }
    let second_verdict = second.judge(options);
    if second_verdict.usable() {
        // Worked the second time: report it, marked as flaky.
        second.failed_runs = 1;
        second.note = Some("failed 1 of 2 runs".into());
        return Retry::Measured(second, second_verdict);
    }
    let mut first = first;
    first.runs = 2;
    first.failed_runs = 2;
    first.note = Some("failed 2 of 2 runs".into());
    Retry::Measured(first, first_verdict)
}

async fn run_case_with_repeat(
    code: &CheckCode,
    board: &Board,
    gate: &Gate,
    peer: &mut Peer,
    spec: CaseSpec,
) -> Result<()> {
    let options = &code.options;
    let first = run_case(code, board, gate, peer, spec).await?;
    let mut result = first;
    result.runs = 1;
    // `run_case` already decided this one (not possible on this machine, the user skipped or
    // stopped it): there was no handshake to repeat, so `judge` would read that as NoHandshake
    // and retry a case that was never attempted.
    if result.verdict.is_some() {
        board.row(spec.id, |row| *row = result);
        return Ok(());
    }
    let mut verdict = result.judge(options);
    if verdict.failed() && options.repeat_failed && !gate.state().stop {
        board.step(format!(
            "{} · {} dials · failed ({}), trying once more",
            spec.transport_name(),
            spec.dialer_label(),
            verdict.label()
        ));
        let second = run_case(code, board, gate, peer, spec).await?;
        match combine_retry(result, verdict, second, options) {
            Retry::Terminal(row) => {
                board.row(spec.id, |slot| *slot = row);
                return Ok(());
            }
            Retry::Measured(row, merged) => {
                result = row;
                verdict = merged;
            }
        }
    } else if verdict.failed() {
        result.failed_runs = 1;
    }
    if result.verdict.is_none() {
        result.verdict = Some(verdict);
    }
    // The tunnel works but carries no UDP (a stream carrier that does not map it, or a filter).
    if verdict.usable()
        && result.note.is_none()
        && result
            .udp
            .as_ref()
            .is_some_and(|u| u.sent > 0 && u.answered == 0)
    {
        result.note = Some("UDP not carried".into());
    }
    board.row(spec.id, |row| *row = result);
    Ok(())
}

/// One run of one case. The row is updated as it goes; the returned result has no verdict unless
/// the case could not be measured (not possible, skipped, stopped).
async fn run_case(
    code: &CheckCode,
    board: &Board,
    gate: &Gate,
    peer: &mut Peer,
    spec: CaseSpec,
) -> Result<CaseResult> {
    let options = &code.options;
    let label = format!("{} · {} dials", spec.transport_name(), spec.dialer_label());
    let mut result = CaseResult::new(spec);
    board.row(spec.id, |row| *row = result.clone());
    if let Some(reason) = case::impossible(&spec, code.iran_ip, code.foreign_ip) {
        result.verdict = Some(Verdict::NotPossible);
        result.note = Some(reason);
        return Ok(result);
    }
    board.step(format!("{label} · starting the test tunnel"));
    let map_port = match case::local_port() {
        Ok(port) => port,
        Err(error) => return Ok(not_possible(result, format!("{error:#}"))),
    };
    let mut setup = Setup {
        spec,
        side: Side::Iran,
        key: code.key.clone(),
        iran_ip: code.iran_ip,
        foreign_ip: code.foreign_ip,
        port: 0,
        map_port,
        service_port: peer.service_port,
        udp: options.udp,
    };
    // Start the listening half first, then the dialing half.
    let iran_listens = setup.listens();
    let mut iran_tunnel = None;
    if iran_listens {
        setup.port = match case::choose_port(&spec, options) {
            Ok(port) => port,
            Err(error) => return Ok(not_possible(result, format!("Iran server: {error:#}"))),
        };
        match Running::start(&setup).await {
            Ok(running) => iran_tunnel = Some(running),
            Err(error) => return Ok(not_possible(result, format!("Iran server: {error:#}"))),
        }
    }
    peer.send(Message::Start {
        spec,
        port: iran_listens.then_some(setup.port),
        map_port,
    })
    .await?;
    let reply = wait_for_mut(
        peer,
        Duration::from_secs(20),
        |m| matches!(m, Message::Started { id, .. } if *id == spec.id),
    )
    .await?;
    let replied = Instant::now();
    let Message::Started {
        port,
        error,
        handshake_ms,
        ..
    } = reply
    else {
        unreachable!("filtered above")
    };
    if let Some(error) = error {
        stop_remote(peer, spec.id).await?;
        return Ok(not_possible(result, format!("foreign server: {error}")));
    }
    if !iran_listens {
        setup.port = port.context("the foreign server sent no port")?;
        match Running::start(&setup).await {
            Ok(running) => iran_tunnel = Some(running),
            Err(error) => {
                stop_remote(peer, spec.id).await?;
                return Ok(not_possible(result, format!("Iran server: {error:#}")));
            }
        }
    }
    let tunnel = iran_tunnel.expect("started above");
    result.port = Some(setup.port);
    board.row(spec.id, |row| row.port = Some(setup.port));
    let map = SocketAddr::from(([127, 0, 0, 1], map_port));
    // The side that dials times its own handshake; the foreign server sends its time along when
    // it already has it, otherwise it is taken here, counting the foreign start-up wait.
    let clock = if spec.dialer == Some(Side::Iran) {
        Clock::Own
    } else {
        Clock::Remote {
            known: handshake_ms,
            since: replied,
        }
    };
    let skips = gate.state().skips;
    let measured = tokio::select! {
        result = measure_case(board, gate, &tunnel, map, &label, clock, result.clone()) => Some(result),
        () = gate.interrupted(skips) => None,
    };
    let mut result = match measured {
        Some(result) => result,
        None => {
            let mut interrupted = result;
            let stop = gate.state().stop;
            interrupted.verdict = Some(if stop {
                Verdict::Stopped
            } else {
                Verdict::Skipped
            });
            interrupted
        }
    };
    let (pings, pongs) = (
        tunnel.stats.pings.load(Relaxed),
        tunnel.stats.pongs.load(Relaxed),
    );
    result.heartbeats = (pings, pongs);
    result.rtt_ms = median_rtt(&tunnel);
    result.raw_payload_echoed =
        Some(tunnel.stats.raw_payload_echoed.load(Relaxed)).filter(|n| *n > 0);
    result.recommended_inner_mtu =
        Some(tunnel.stats.raw_inner_mtu_advisory.load(Relaxed)).filter(|n| *n > 0);
    if let Some(mtu) = result.recommended_inner_mtu {
        result.note = Some(format!(
            "raw carrier echoed size: inner MTU {mtu} advisory; loss is not proof of a ceiling"
        ));
    }
    board.step(format!("{label} · removing the test tunnel"));
    drop(tunnel);
    let remote = stop_remote(peer, spec.id).await?;
    // The foreign server timed its own handshake when it dialed (for raw transports it is the
    // client inside); that beats the estimate.
    if spec.dialer != Some(Side::Iran)
        && result.handshake_ms.is_some()
        && let Some(ms) = remote
    {
        result.handshake_ms = Some(ms);
    }
    Ok(result)
}

/// The median of the tunnel's heartbeat round trips, in milliseconds.
fn median_rtt(tunnel: &Running) -> Option<f64> {
    let mut samples = tunnel.stats.rtt_samples();
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    Some(measure::tenths(
        f64::from(samples[samples.len() / 2]) / 1000.0,
    ))
}

fn not_possible(mut result: CaseResult, reason: String) -> CaseResult {
    result.verdict = Some(Verdict::NotPossible);
    result.note = Some(reason);
    result
}

/// Stops the foreign half; returns its handshake time when it dialed.
async fn stop_remote(peer: &mut Peer, id: u32) -> Result<Option<u64>> {
    peer.send(Message::StopCase { id }).await?;
    let reply = wait_for_mut(
        peer,
        Duration::from_secs(15),
        |m| matches!(m, Message::CaseStopped { id: stopped, .. } if *stopped == id),
    )
    .await?;
    Ok(match reply {
        Message::CaseStopped { handshake_ms, .. } => handshake_ms,
        _ => None,
    })
}

/// A point where a pause takes effect: shows it, waits for resume, and says whether to go on.
async fn checkpoint(board: &Board, gate: &Gate) -> bool {
    if !gate.state().paused {
        return !gate.state().stop;
    }
    let before = board.view.borrow().step.clone();
    board.update(|view| {
        view.paused = true;
        view.step = "paused · press r to resume".into();
    });
    let go = gate.wait_unpaused().await;
    board.update(|view| {
        view.paused = false;
        view.step = before;
    });
    go
}

/// Where the handshake time of a case comes from.
#[derive(Debug, Clone, Copy)]
enum Clock {
    /// This server dialed; its tunnel timed the handshake.
    Own,
    /// The foreign server dialed (or raw packets): its time if it sent one, otherwise the time
    /// since its reply plus its start-up wait.
    Remote { known: Option<u64>, since: Instant },
}

/// The measurements of one case, in order, each one optional.
async fn measure_case(
    board: &Board,
    gate: &Gate,
    tunnel: &Running,
    map: SocketAddr,
    label: &str,
    clock: Clock,
    mut result: CaseResult,
) -> CaseResult {
    let options = &board.options;
    let id = result.spec.id;
    board.step(format!("{label} · waiting for the handshake"));
    let started = Instant::now();
    while tunnel.stats.sessions_total.load(Relaxed) == 0 {
        if started.elapsed() > HANDSHAKE_LIMIT || tunnel.finished() {
            board.row(id, |row| row.note = Some("no handshake".into()));
            return result;
        }
        time::sleep(Duration::from_millis(50)).await;
    }
    let handshake = match clock {
        Clock::Own => loop {
            // The tunnel's watcher notices within a few milliseconds.
            if let Some(time) = tunnel.handshake() {
                break time.as_millis() as u64;
            }
            time::sleep(Duration::from_millis(5)).await;
        },
        Clock::Remote {
            known: Some(ms), ..
        } => ms,
        Clock::Remote { known: None, since } => {
            since.elapsed().as_millis() as u64 + case::START_WAIT.as_millis() as u64
        }
    };
    result.handshake_ms = Some(handshake);
    board.row(id, |row| row.handshake_ms = Some(handshake));
    // Let the first session confirm itself before the first stream.
    time::sleep(Duration::from_millis(300)).await;
    let hold_sec = options.hold_sec;
    if options.pings > 0 && checkpoint(board, gate).await {
        board.step(format!("{label} · ping"));
        let stats = measure::pings(map, options.pings, |stats| {
            let stats = stats.clone();
            board.row(id, |row| row.ping = Some(stats));
        })
        .await;
        result.ping = Some(stats);
        let rtt = median_rtt(tunnel);
        result.rtt_ms = rtt;
        board.row(id, |row| row.rtt_ms = rtt);
    }
    let seconds = Duration::from_secs(u64::from(options.speed_sec));
    let nothing_passes = result.ping.as_ref().is_some_and(|p| p.answered == 0);
    if options.udp && !nothing_passes && checkpoint(board, gate).await {
        board.step(format!("{label} · UDP"));
        let stats = measure::udp_probe(map, UDP_IDLE_PACKETS, |stats| {
            let stats = stats.clone();
            board.row(id, |row| row.udp = Some(stats));
        })
        .await;
        board.row(id, |row| row.udp = Some(stats.clone()));
        result.udp = Some(stats);
    }
    // UDP that does not come back at all is not worth a second try under load.
    let udp_carried = result.udp.as_ref().is_some_and(|u| u.answered > 0);
    if options.download && !nothing_passes && checkpoint(board, gate).await {
        board.step(format!("{label} · download {}s", options.speed_sec));
        let transfer = if udp_carried {
            let packets = options.speed_sec * measure::UDP_RATE;
            let(warm_tx,warm_rx)=tokio::sync::oneshot::channel();
            let(load_tx,load_rx)=tokio::sync::oneshot::channel();
            let (transfer, loaded) = tokio::join!(
                async{let _=warm_rx.await;measure::download_started(map,seconds,load_tx).await},
                measure::udp_probe_started(map, packets, |stats| {
                    let stats = stats.clone();
                    board.row(id, |row| row.udp_loaded = Some(stats));
                },Some(warm_tx),Some(load_rx))
            );
            // C04: the counted sends start at the first download byte and last as long as the
            // download. If the download failed, part of the sample ran without load, so it is
            // not reported as "UDP during download".
            match loaded_sample(loaded, &transfer) {
                Some(loaded) => {board.row(id, |row| row.udp_loaded = Some(loaded.clone()));result.udp_loaded = Some(loaded);}
                None => board.row(id, |row| row.udp_loaded = None),
            }
            transfer
        } else {
            measure::download(map, seconds).await
        };
        board.row(id, |row| row.download = Some(transfer.clone()));
        result.download = Some(transfer);
    }
    if options.upload && !nothing_passes && checkpoint(board, gate).await {
        board.step(format!("{label} · upload {}s", options.speed_sec));
        let transfer = measure::upload(map, seconds).await;
        board.row(id, |row| row.upload = Some(transfer.clone()));
        result.upload = Some(transfer);
    }
    if options.parallel && !nothing_passes && checkpoint(board, gate).await {
        board.step(format!("{label} · 4 downloads at once"));
        let transfer = measure::parallel(map, seconds, 4).await;
        board.row(id, |row| row.parallel = Some(transfer.clone()));
        result.parallel = Some(transfer);
    }
    if hold_sec > 0 && !nothing_passes && checkpoint(board, gate).await {
        // Data of a transfer may still be queued in a slow tunnel; let it drain before the hold
        // starts counting, so a backlog is not mistaken for instability.
        board.step(format!("{label} · waiting for the transfers to drain"));
        let settle = Instant::now();
        while settle.elapsed() < SETTLE_LIMIT && measure::ping(map).await.is_err() {
            time::sleep(Duration::from_millis(50)).await;
        }
        let before = tunnel.stats.sessions_total.load(Relaxed);
        let mut hold = HoldStats {
            seconds: hold_sec,
            ..HoldStats::default()
        };
        let length = Duration::from_secs(u64::from(hold_sec));
        let mut end = Instant::now() + length;
        while Instant::now() < end {
            // A pause can take effect between the pings of a long hold; paused time does not count.
            let waited = Instant::now();
            if !checkpoint(board, gate).await {
                break;
            }
            end += waited.elapsed();
            let done = length.saturating_sub(end.saturating_duration_since(Instant::now()));
            board.step(format!(
                "{label} · stability hold {} of {} s · {} failed",
                done.as_secs(),
                hold_sec,
                hold.failures
            ));
            let tick = Instant::now();
            hold.pings += 1;
            if measure::ping(map).await.is_err() {
                hold.failures += 1;
            }
            hold.reconnects = tunnel
                .stats
                .sessions_total
                .load(Relaxed)
                .saturating_sub(before);
            let snapshot = hold.clone();
            board.row(id, |row| row.hold = Some(snapshot));
            time::sleep(Duration::from_secs(2).saturating_sub(tick.elapsed())).await;
        }
        result.hold = Some(hold);
    }
    result
}

/// The foreign server's part: runs its half of each case on request, forwards its keys, shows
/// the view it receives.
async fn follow(
    code: CheckCode,
    view: watch::Sender<View>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) -> Result<Report> {
    let service = Service::start().await?;
    let mut limit = PAIR_LIMIT;
    loop {
        let pairing = control::pair(&code, Side::Foreign, limit, |status| {
            view.send_modify(|v| {
                v.step = status.to_string();
                v.connected = false;
            })
        });
        // Stop works while waiting for the other server too.
        let link = tokio::select! {
            link = pairing => link?,
            () = async {
                while let Some(command) = commands.recv().await {
                    if command == Command::Stop {
                        return;
                    }
                }
                std::future::pending::<()>().await;
            } => bail!("stopped before the other server joined"),
        };
        view.send_modify(|v| v.connected = true);
        match serve(&code, &service, link, &view, &mut commands).await {
            Ok(report) => return Ok(report),
            Err(error) if error.is::<Finished>() => {
                bail!("{error:#}")
            }
            Err(error) => {
                logbuf::push(format!("control connection lost: {error:#}"));
                view.send_modify(|v| {
                    v.step = "lost the connection to the other server; reconnecting".into();
                    v.connected = false;
                });
                limit = REPAIR_LIMIT;
            }
        }
    }
}

/// The other server ended the check on purpose; no reconnecting.
#[derive(Debug)]
struct Finished(String);
impl std::fmt::Display for Finished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Finished {}

async fn serve(
    code: &CheckCode,
    service: &Service,
    mut link: Link,
    view: &watch::Sender<View>,
    commands: &mut mpsc::UnboundedReceiver<Command>,
) -> Result<Report> {
    link.send(Message::Ready {
        service_port: service.address.port(),
    })
    .await?;
    // The running half: case id, tunnel, and whether this side dialed.
    let mut current: Option<(u32, Running, bool)> = None;
    let mut baseline: Option<JoinHandle<Result<()>>> = None;
    let result = loop {
        tokio::select! {
            message = link.recv() => {
                let message = match message {
                    Ok(message) => message,
                    Err(error) => break Err(error),
                };
                match message {
                    Message::Start { spec, port, map_port } => {
                        accepted_case(&code.options,&spec)?;
                        current = None;
                        let (reply, running) = start_half(code, service, spec, port, map_port).await;
                        if let Some(running) = running {
                            current = Some((spec.id, running, spec.dialer != Some(Side::Iran)));
                        }
                        link.send(reply).await?;
                    }
                    Message::StopCase { id } => {
                        let mut handshake_ms = None;
                        if let Some((running_id, running, dials)) = &current
                            && *running_id == id
                        {
                            if *dials {
                                handshake_ms = running.handshake().map(|time| time.as_millis() as u64);
                            }
                            current = None;
                        }
                        link.send(Message::CaseStopped { id, handshake_ms }).await?;
                    }
                    Message::BaselineListen => {
                        let (reply, task) = start_baseline(code).await;
                        baseline = task;
                        link.send(reply).await?;
                    }
                    Message::View(new) => {
                        let _ = view.send(*new);
                    }
                    Message::Done(report) => {
                        // The last view may still be on its way; the report is the final word.
                        view.send_modify(|v| {
                            v.rows = report.cases.clone();
                            v.current = None;
                            v.finished = true;
                            v.paused = false;
                            v.remaining_sec = 0;
                            v.elapsed_sec = report.seconds;
                            v.baseline = report.baseline.clone();
                            v.step = match &report.stopped {
                                Some(reason) => format!("stopped: {reason}"),
                                None => "finished".into(),
                            };
                        });
                        break Ok(*report);
                    }
                    Message::Bye => break Err(Finished("the other server stopped the check".into()).into()),
                    _ => {}
                }
            }
            Some(command) = commands.recv() => {
                link.send(Message::Command(command)).await?;
            }
        }
    };
    drop(current);
    if let Some(task) = baseline {
        task.abort();
    }
    result
}

async fn start_half(
    code: &CheckCode,
    service: &Service,
    spec: CaseSpec,
    port: Option<u16>,
    map_port: u16,
) -> (Message, Option<Running>) {
    let failed = |error: String| {
        (
            Message::Started {
                id: spec.id,
                port: None,
                error: Some(error),
                handshake_ms: None,
            },
            None,
        )
    };
    let mut setup = Setup {
        spec,
        side: Side::Foreign,
        key: code.key.clone(),
        iran_ip: code.iran_ip,
        foreign_ip: code.foreign_ip,
        port: 0,
        map_port,
        service_port: service.address.port(),
        udp: false,
    };
    setup.port = match port {
        Some(port) => port,
        None => match case::choose_port(&spec, &code.options) {
            Ok(port) => port,
            Err(error) => return failed(format!("{error:#}")),
        },
    };
    match Running::start(&setup).await {
        Ok(running) => (
            Message::Started {
                id: spec.id,
                port: setup.listens().then_some(setup.port),
                error: None,
                handshake_ms: setup
                    .dials()
                    .then(|| running.handshake())
                    .flatten()
                    .map(|time| time.as_millis() as u64),
            },
            Some(running),
        ),
        Err(error) => failed(format!("{error:#}")),
    }
}

async fn start_baseline(code: &CheckCode) -> (Message, Option<JoinHandle<Result<()>>>) {
    let port = match case::local_port().and_then(|_| {
        let socket = std::net::TcpListener::bind((unspecified(code.foreign_ip), 0))?;
        Ok(socket.local_addr()?.port())
    }) {
        Ok(port) => port,
        Err(error) => {
            return (
                Message::BaselineReady {
                    port: None,
                    error: Some(format!("{error:#}")),
                },
                None,
            );
        }
    };
    let options = crate::linktest::ListenOptions {
        bind: SocketAddr::new(unspecified(code.foreign_ip), port),
        expected_peer: code.iran_ip,
        extra_ports: Vec::new(),
        wait: Duration::from_secs(120),
        keep: false,
    };
    let task = tokio::spawn(crate::linktest::listen(options));
    time::sleep(Duration::from_millis(200)).await;
    // `listen` only returns this quickly when the bind itself failed: on success it keeps
    // running for `wait`. That happens when something else won the free port between the probe
    // above and this rebind, which the probe cannot itself prevent (the bind it tests with is
    // dropped to free the port again) - catching it here keeps a lost race from being reported
    // as a working baseline.
    if task.is_finished() {
        let error = match task.await {
            Ok(Err(error)) => format!("{error:#}"),
            Ok(Ok(())) => "the baseline listener stopped at once".to_string(),
            Err(error) => format!("{error:#}"),
        };
        return (
            Message::BaselineReady {
                port: None,
                error: Some(error),
            },
            None,
        );
    }
    (
        Message::BaselineReady {
            port: Some(port),
            error: None,
        },
        Some(task),
    )
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::config::Transport;

    fn failed_first() -> CaseResult {
        let mut first = CaseResult::new(CaseSpec { id: 3, transport: Transport::Tcp, dialer: Some(Side::Foreign), variant: super::super::Variant::Plain, profile: None });
        first.handshake_ms = Some(5);
        first.runs = 1;
        first
    }

    /// C05: an explicit terminal retry is reported as itself with one counted failure.
    #[test]
    fn a_terminal_retry_keeps_its_verdict_and_counts_one_measured_failure() {
        let options = Options::default();
        let first = failed_first();
        let first_verdict = first.judge(&options);
        assert!(first_verdict.failed(), "fixture must be a measured failure: {first_verdict:?}");
        for terminal in [Verdict::Stopped, Verdict::Skipped, Verdict::NotPossible] {
            let mut second = CaseResult::new(first.spec);
            second.verdict = Some(terminal);
            second.note = (terminal == Verdict::NotPossible).then(|| "port 7000 busy".to_string());
            let Retry::Terminal(row) = combine_retry(first.clone(), first_verdict, second, &options) else {
                panic!("{terminal:?} retry was re-judged");
            };
            assert_eq!(row.verdict, Some(terminal));
            assert_eq!((row.runs, row.failed_runs), (2, 1));
            let note = row.note.unwrap_or_default();
            assert!(!note.contains("2 of 2"), "{note}");
            assert!(note.contains(terminal.label()), "{note}");
            if terminal == Verdict::NotPossible { assert!(note.contains("port 7000 busy"), "{note}"); }
        }
        // A measured second failure is still "failed 2 of 2".
        let second = failed_first();
        let Retry::Measured(row, verdict) = combine_retry(first.clone(), first_verdict, second, &options) else { panic!() };
        assert_eq!((row.runs, row.failed_runs), (2, 2));
        assert_eq!(verdict, first_verdict);
        assert_eq!(row.note.as_deref(), Some("failed 2 of 2 runs"));
    }
}

#[cfg(test)]
mod loaded_tests {
    use super::*;
    use super::super::{Transfer, UdpStats};

    /// V01: only cases from the locally accepted plan may be started by the peer.
    #[test]
    fn the_follower_refuses_cases_outside_the_accepted_plan() {
        use crate::config::Transport;
        let mut options = super::super::Options::preset(super::super::Preset::Quick);
        options.transports = vec![Transport::Tcp];
        let cases = options.cases();
        assert!(!cases.is_empty());
        for spec in &cases {
            assert!(accepted_case(&options, spec).is_ok());
        }
        let mut tun = cases[0];
        tun.transport = Transport::Tun;
        tun.dialer = None;
        tun.profile = Some(crate::raw_packet::RawProfile::Tcp);
        assert!(accepted_case(&options, &tun).is_err(), "raw TUN outside a TCP-only plan");
        let mut variant = cases[0];
        variant.variant = super::super::Variant::Fragment;
        assert!(accepted_case(&options, &variant).is_err());
        let mut renumbered = cases[0];
        renumbered.id = 9999;
        assert!(accepted_case(&options, &renumbered).is_err());
    }

    /// C04: no loaded-UDP row from a failed or empty load; a completed load keeps it.
    #[test]
    fn loaded_udp_is_dropped_when_the_download_failed() {
        let sample = UdpStats { sent: 300, answered: 290, ..Default::default() };
        let ok = Transfer { mbps: 50.0, bytes: 1_000_000, error: None };
        let failed = Transfer { mbps: 1.0, bytes: 20_000, error: Some("stalled after 20 KB".into()) };
        let empty = Transfer { mbps: 0.0, bytes: 0, error: None };
        assert_eq!(loaded_sample(sample.clone(), &ok), Some(sample.clone()));
        assert_eq!(loaded_sample(sample.clone(), &failed), None);
        assert_eq!(loaded_sample(sample.clone(), &empty), None);
        assert_eq!(loaded_sample(UdpStats::default(), &ok), None, "never started (load never began)");
    }
}
