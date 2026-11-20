//! What the dashboard may do to tunnels: a fixed list of operations, never a shell. The hub's own
//! server runs them in-process (`LocalOps`); servers joined later answer the same calls over the
//! agent link, so both paths share this interface.
use crate::manager::{
    bulk::{self, Action, Step},
    service::{self, State},
    store::Store,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Lines a logs request may ask for.
pub const MAX_LINES: usize = 1000;
/// Longest log line passed on; the rest is cut.
const MAX_LINE: usize = 2000;

pub fn parse_action(word: &str) -> Option<Action> {
    match word {
        "start" => Some(Action::Start),
        "stop" => Some(Action::Stop),
        "restart" => Some(Action::Restart),
        _ => None,
    }
}

pub fn action_word(action: Action) -> &'static str {
    match action {
        Action::Start => "start",
        Action::Stop => "stop",
        Action::Restart => "restart",
    }
}

/// What saving changed settings (or going back to the previous ones) did.
#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub struct EditOutcome {
    /// The settings differ from before and were saved.
    pub changed: bool,
    /// The tunnel's service was written again and restarted.
    pub restarted: bool,
    /// The tunnel came up and stayed up with the saved settings.
    pub came_up: Option<bool>,
    /// It did not stay up, so the previous settings were put back (and started again).
    pub reverted: bool,
    pub detail: Option<String>,
}

/// What an action did.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Outcome {
    /// Something was done (starting a running tunnel changes nothing).
    pub changed: bool,
    /// After a start or restart: the tunnel came up and stayed up for a few seconds.
    pub came_up: Option<bool>,
}

pub trait Ops: Send + Sync {
    /// The tunnels that exist; every other call checks its name against this list.
    fn names(&self) -> Vec<String>;
    /// Unlike the user-facing inventory, validation must propagate store read errors.
    fn has_tunnel(&self, name: &str) -> Result<bool> {
        Ok(self.names().iter().any(|existing| existing == name))
    }
    /// Blocking: runs the action and, after a start, watches the tunnel come up.
    fn act(&self, name: &str, action: Action) -> Result<Outcome>;
    /// Run a paired lifecycle action only while the saved tunnel still has its expected
    /// fingerprint. An older Agent must refuse this distinct allowlisted operation.
    fn act_pair(&self, name: &str, action: Action, pair: &str) -> Result<Outcome> {
        let _ = (name, action, pair);
        bail!("pair-guarded lifecycle is unsupported")
    }
    /// Blocking: the last `lines` lines of the tunnel's log.
    fn logs(&self, name: &str, lines: usize) -> Result<LogTail>;
    /// New log lines as they are written, until the returned value is dropped: those after
    /// `after` (a journal cursor from `logs` or an earlier line), else only new ones.
    fn follow(&self, name: &str, after: Option<String>) -> Result<Follow>;
    /// Blocking: what the edit screen shows (see `edit::editable`), and whether there is a
    /// previous version to go back to.
    fn editable(&self, name: &str) -> Result<serde_json::Value>;
    /// Blocking: saves the changed settings and restarts the tunnel; if it does not stay up, puts
    /// the previous settings back.
    fn edit(&self, name: &str, changes: &serde_json::Value) -> Result<EditOutcome>;
    /// Blocking: goes back to the previous settings (one step).
    fn undo(&self, name: &str) -> Result<EditOutcome>;
    /// Blocking: stops the tunnel and removes its service, firewall rules, traffic count and
    /// configuration, as the terminal manager's Delete does.
    fn delete(&self, name: &str) -> Result<()>;
    /// Delete only when the current saved tunnel has the requested public pair fingerprint.
    /// The check and removal must share the store's exclusive lock so a reused name is safe.
    fn delete_pair(&self, name: &str, pair: &str) -> Result<()> {
        let _ = (name, pair);
        bail!("pair-guarded deletion is unsupported")
    }
    /// Blocking: saves a new tunnel (one `wizard::creatable` accepts), installs its service and
    /// watches it come up. A name that is taken is refused.
    fn create(&self, name: &str, config: &serde_json::Value) -> Result<Outcome>;
    /// Blocking: deletes the tunnel only when it is the one with `tunnel_key`, i.e. the one a
    /// create of the dashboard made, never a tunnel of the same name someone else made meanwhile.
    fn delete_own(&self, name: &str, tunnel_key: &str) -> Result<()> {
        let _ = tunnel_key;
        self.delete(name)
    }
    /// Blocking: the running tunnel's own figures (its control socket's status answer).
    fn status(&self, name: &str) -> Result<serde_json::Value>;
    /// Blocking: a speed test through the tunnel, run from its Iran end.
    fn speedtest(&self, name: &str, download: bool, bytes: u64, streams: u64) -> Result<serde_json::Value>;
    /// Blocking: the pairing code for setting up the other end by hand. `address` is how the other
    /// server reaches this one, when this end listens (`needs_address` says so).
    fn pairing(&self, name: &str, address: Option<String>) -> Result<serde_json::Value>;
    /// Blocking: forgets the traffic counted for the limit and restarts the tunnel (a new period).
    fn quota_reset(&self, name: &str) -> Result<Outcome>;
    /// Blocking: a server tool, `{"tool": ...}`: `health`, `fix` ({fix}), `optimize_plan`,
    /// `optimize_apply`, `optimize_undo`, `files` or `check` ({check: the transport-check request}).
    fn server(&self, request: &serde_json::Value) -> Result<serde_json::Value>;
}

/// The longest speed test: the control socket allows up to 1 GiB, the dashboard 200 MiB.
pub const MAX_SPEEDTEST: u64 = 200 << 20;

fn check_speedtest(bytes: u64, streams: u64) -> Result<()> {
    anyhow::ensure!((1 << 20..=MAX_SPEEDTEST).contains(&bytes), "the test size must be 1 to 200 MiB");
    anyhow::ensure!((1..=16).contains(&streams), "connections must be 1 to 16");
    Ok(())
}

/// The code and what it needs, from a saved configuration (shared by real and demo servers).
fn pairing_of(config: &serde_json::Value, address: Option<String>) -> Result<serde_json::Value> {
    use crate::manager::pairing;
    let needs = pairing::needs_address(config);
    if needs && address.as_deref().is_none_or(|a| a.trim().is_empty()) {
        return Ok(serde_json::json!({"needs_address": true, "suggested": crate::manager::local_ip()}));
    }
    let made = pairing::from_config(config, needs.then(|| address.unwrap_or_default().trim().to_string()), None)?;
    let code = pairing::encode(&made)?;
    Ok(serde_json::json!({"needs_address": needs, "code": code, "creator": made.creator}))
}

/// Answers one request of the fixed list, for the agent and for the hub's own server alike.
pub fn answer(ops: &dyn Ops, request: &serde_json::Value) -> Result<serde_json::Value> {
    use serde_json::json;
    let name = request["name"].as_str().unwrap_or("");
    match request["op"].as_str() {
        Some("names") => Ok(json!(ops.names())),
        Some("act") => {
            let action = parse_action(request["action"].as_str().unwrap_or("")).context("unknown action")?;
            if !ops.has_tunnel(name)? {
                return Err(unknown_tunnel(name));
            }
            Ok(serde_json::to_value(ops.act(name, action)?)?)
        }
        // Never piggyback on 'act' with an optional ignored field: old Agents must fail closed.
        Some("act_pair") => {
            let action = parse_action(request["action"].as_str().unwrap_or("")).context("unknown action")?;
            let pair = request["expect_pair"].as_str().filter(|p| valid_pair(p))
                .context("the expected pair fingerprint is missing or invalid")?;
            Ok(serde_json::to_value(ops.act_pair(name, action, pair)?)?)
        }
        Some("logs") => {
            if !ops.has_tunnel(name)? {
                return Err(unknown_tunnel(name));
            }
            let lines = request["lines"].as_u64().unwrap_or(200) as usize;
            Ok(serde_json::to_value(ops.logs(name, lines)?)?)
        }
        Some("editable") => ops.editable(name),
        Some("edit") => Ok(serde_json::to_value(ops.edit(name, &request["changes"])?)?),
        Some("undo") => Ok(serde_json::to_value(ops.undo(name)?)?),
        // A dashboard before `expect_pair` sends none and deletes by name, as it always did.
        Some("delete") => {
            match (request["expect_key"].as_str(), request.get("expect_pair").filter(|p| !p.is_null())) {
                (Some(key), _) => ops.delete_own(name, key)?,
                (None, Some(pair)) => {
                    let pair = pair.as_str().filter(|p| valid_pair(p)).context("the pair fingerprint is not valid")?;
                    ops.delete_pair(name, pair)?
                }
                (None, None) => ops.delete(name)?,
            }
            Ok(json!({"deleted": true}))
        }
        // Distinct allowlisted operation: an older Agent must fail closed rather than
        // ignore an unknown optional fingerprint and delete a reused tunnel name.
        Some("delete_pair") => {
            let pair = request["expect_pair"].as_str().filter(|p| valid_pair(p))
                .context("the expected pair fingerprint is missing or invalid")?;
            ops.delete_pair(name, pair)?;
            Ok(json!({"deleted": true}))
        }
        Some("create") => Ok(serde_json::to_value(ops.create(name, &request["config"])?)?),
        Some("status") => ops.status(name),
        Some("speedtest") => ops.speedtest(
            name,
            request["direction"] != "up",
            request["bytes"].as_u64().unwrap_or(10 << 20),
            request["streams"].as_u64().unwrap_or(1),
        ),
        Some("pairing") => ops.pairing(name, request["address"].as_str().map(str::to_string)),
        Some("quota_reset") => Ok(serde_json::to_value(ops.quota_reset(name)?)?),
        Some("server") => ops.server(request),
        // One after another, as the terminal manager's Restart all does.
        Some("restart_all") => Ok(json!(ops
            .names()
            .iter()
            .map(|name| match ops.act(name, Action::Restart) {
                Ok(outcome) => json!({"name": name, "ok": true, "came_up": outcome.came_up}),
                Err(error) => json!({"name": name, "ok": false, "detail": format!("{error:#}")}),
            })
            .collect::<Vec<_>>())),
        _ => bail!("unknown request"),
    }
}

fn clip(line: &str) -> String {
    match line.char_indices().nth(MAX_LINE) {
        Some((cut, _)) => format!("{}…", &line[..cut]),
        None => line.to_string(),
    }
}

/// A live log: the journal of a tunnel, or sample lines in the demo.
/// The end of a log, and the journal cursor of its last line: following from there misses nothing
/// written in between.
#[derive(serde::Serialize, Debug, Default)]
pub struct LogTail {
    pub lines: Vec<String>,
    /// Where the tail ends: a journal cursor, or `@<unix seconds>` when the log had nothing yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// A journal cursor as journalctl prints it (`s=...;i=...;...`); anything else is not passed on.
pub fn cursor_ok(cursor: &str) -> bool {
    if let Some(seconds) = cursor.strip_prefix('@') {
        return (1..=20).contains(&seconds.len()) && seconds.bytes().all(|b| b.is_ascii_digit());
    }
    (1..=512).contains(&cursor.len()) && cursor.bytes().all(|b| b.is_ascii_alphanumeric() || b"=;-_".contains(&b))
}

pub enum Follow {
    Journal {
        _child: tokio::process::Child,
        lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    },
    Demo {
        name: String,
        tick: tokio::time::Interval,
        count: u64,
    },
}

impl Follow {
    /// The next line and its journal cursor, or `None` when the log ended.
    pub async fn next_line(&mut self) -> Option<(String, Option<String>)> {
        match self {
            Follow::Journal { lines, .. } => loop {
                let line = lines.next_line().await.ok().flatten()?;
                // journalctl -o json: one object per entry; MESSAGE is text, or bytes when it
                // is not valid UTF-8.
                let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                let message = match &entry["MESSAGE"] {
                    serde_json::Value::String(text) => text.clone(),
                    serde_json::Value::Array(bytes) => String::from_utf8_lossy(
                        &bytes.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect::<Vec<u8>>(),
                    )
                    .into_owned(),
                    _ => continue,
                };
                let cursor = entry["__CURSOR"].as_str().filter(|c| cursor_ok(c)).map(str::to_string);
                return Some((clip(&message), cursor));
            },
            Follow::Demo { name, tick, count } => {
                tick.tick().await;
                *count += 1;
                Some((demo_line(name, *count), None))
            }
        }
    }
}

/// Where the system's EZTunnel lives. Tunnel services run this program, never the one serving
/// the dashboard or the agent, which may be a copy elsewhere (a test build, a newer download).
pub const INSTALLED: &str = "/usr/local/bin/eztunnel";

/// The program a tunnel service written by the dashboard runs: the installed one when there is
/// one, else this program.
pub fn installed_program() -> std::path::PathBuf {
    program_for(std::path::Path::new(INSTALLED))
}

fn program_for(installed: &std::path::Path) -> std::path::PathBuf {
    if installed.is_file() {
        return installed.to_path_buf();
    }
    std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .unwrap_or_else(|_| installed.to_path_buf())
}

/// Starts an error that was raised before anything was changed: whoever asked has nothing to
/// clean up on this server.
pub const UNCHANGED: &str = "nothing was changed";

/// A failure with a short code beside its message, so the dashboard can answer it properly
/// (not found, busy, another tunnel now) instead of a plain "failed". The message stays exactly
/// what it was, so versions that only read the words understand it too.
#[derive(Debug)]
pub struct Refused {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refused {}

/// The codes a failure may carry, between the agent and the dashboard and on to the page.
pub const CODES: &[&str] = &["unknown_tunnel", "busy", "pair_changed", "offline", "timeout"];

pub fn refused(code: &'static str, message: impl Into<String>) -> anyhow::Error {
    debug_assert!(CODES.contains(&code));
    Refused { code, message: message.into() }.into()
}

/// The code of a failure, from anywhere in its chain; `None` for an ordinary failure.
pub fn code_of(error: &anyhow::Error) -> Option<&'static str> {
    error.chain().find_map(|cause| {
        if let Some(refused) = cause.downcast_ref::<Refused>() {
            Some(refused.code)
        } else {
            cause.downcast_ref::<crate::manager::store::Busy>().map(|_| "busy")
        }
    })
}

/// A code as a peer sent it, if it is one of ours (anything else is treated as no code).
pub fn known_code(code: &str) -> Option<&'static str> {
    CODES.iter().copied().find(|known| *known == code)
}

fn unknown_tunnel(name: &str) -> anyhow::Error {
    refused("unknown_tunnel", format!("no tunnel named {name}"))
}

/// A pair fingerprint as the dashboard shows it (`data::pair_of`): 16 hexadecimal characters.
pub fn valid_pair(pair: &str) -> bool {
    pair.len() == 16 && pair.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The tunnels of this server, through the terminal manager's own functions.
pub struct LocalOps;

impl LocalOps {
    fn store() -> Result<Store> {
        Store::open()
    }

    fn known(store: &Store, name: &str) -> Result<()> {
        if !store.names()?.iter().any(|n| n == name) {
            return Err(unknown_tunnel(name));
        }
        Ok(())
    }

    /// Deletes the tunnel unless `refuse` objects to its saved configuration. The check and the
    /// delete happen under the same change lock, so nothing can replace the tunnel in between.
    fn delete_if(store: &Store, name: &str, refuse: impl FnOnce(&serde_json::Value) -> Option<anyhow::Error>) -> Result<()> {
        Self::known(store, name)?;
        let _lock = store.lock(name, false)?;
        if let Some(refusal) = refuse(&store.read(name)?) {
            return Err(refusal);
        }
        if store.system {
            service::remove(name)?;
        }
        store.remove_locked(name)
    }
}

/// Why a delete by pair fingerprint must not go ahead: the tunnel saved under that name now
/// belongs to another pair (or has no tunnel key to tell).
fn pair_differs(config: &serde_json::Value, name: &str, pair: &str) -> Option<anyhow::Error> {
    let same = super::data::pair_of(config).is_some_and(|now| now.eq_ignore_ascii_case(pair));
    (!same).then(|| refused("pair_changed", format!("{UNCHANGED}: {name} here is now another tunnel, not the one chosen for deleting")))
}

impl LocalOps {
    fn install_new(store: &Store, name: &str, install: impl FnOnce() -> Result<()>, remove_service: impl FnOnce() -> Result<()>) -> Result<()> {
        if let Err(error) = install() {
            if let Err(cleanup) = remove_service().and_then(|_| store.remove_locked(name)) {
                return Err(error.context(format!("new tunnel cleanup failed: {cleanup:#}")));
            }
            return Err(error);
        }
        Ok(())
    }

    /// Writes the service again with the current file and watches it come up.
    fn restart_saved(store: &Store, name: &str) -> (bool, Option<String>) {
        match service::install_with(store, name, &installed_program()) {
            Ok(()) => {
                let up = service::watch_started(|| service::state(store, name) == State::Running, std::thread::sleep);
                (up, (!up).then(|| "it did not stay up with these settings (see its log)".to_string()))
            }
            Err(error) => (false, Some(format!("{error:#}"))),
        }
    }

    /// Saves `edited` (keeping the old file as the previous version) and, when the tunnel has a
    /// service, restarts it; if it does not stay up, the previous file goes back.
    fn save_with_revert(store: &Store, name: &str, edited: &serde_json::Value) -> Result<EditOutcome> {
        let had_service = service::state(store, name) != State::NoService;
        let earlier = store.previous_bytes(name);
        store.save(name, edited)?;
        if !store.system || !had_service {
            return Ok(EditOutcome { changed: true, ..EditOutcome::default() });
        }
        let (up, problem) = Self::restart_saved(store, name);
        if up {
            return Ok(EditOutcome { changed: true, restarted: true, came_up: Some(true), ..EditOutcome::default() });
        }
        store.take_back_save(name, earlier.as_deref()).context("put the previous settings back")?;
        let (back_up, _) = Self::restart_saved(store, name);
        Ok(EditOutcome { changed: true, restarted: true, came_up: Some(back_up), reverted: true, detail: problem })
    }
}

impl LocalOps {
    /// Caller holds this tunnel's exclusive store lock and has checked its identity.
    fn act_locked(store: &Store, name: &str, action: Action) -> Result<Outcome> {
        if !store.system {
            bail!("tunnel services need root and systemd");
        }
        let Some(step) = bulk::step_for(action, service::state(store, name)) else {
            return Ok(Outcome { changed: false, came_up: None });
        };
        match step {
            Step::Start => service::start(name)?,
            Step::Install => service::install_with(store, name, &installed_program())?,
            Step::Stop => service::stop(name)?,
        }
        let came_up = (step != Step::Stop).then(|| {
            service::watch_started(
                || service::state(store, name) == State::Running,
                std::thread::sleep,
            )
        });
        Ok(Outcome { changed: true, came_up })
    }
}

impl Ops for LocalOps {
    fn names(&self) -> Vec<String> {
        Self::store().and_then(|s| s.names()).unwrap_or_default()
    }

    fn has_tunnel(&self, name: &str) -> Result<bool> {
        Ok(Self::store()?.names()?.iter().any(|existing| existing == name))
    }

    fn act(&self, name: &str, action: Action) -> Result<Outcome> {
        let store = Self::store()?;
        let _lock = store.lock(name, false)?;
        Self::known(&store, name)?;
        Self::act_locked(&store, name, action)
    }

    fn act_pair(&self, name: &str, action: Action, pair: &str) -> Result<Outcome> {
        let store = Self::store()?;
        let _lock = store.lock(name, false)?;
        Self::known(&store, name)?;
        if let Some(failure) = pair_differs(&store.read(name)?, name, pair) {
            return Err(failure);
        }
        Self::act_locked(&store, name, action)
    }

    fn logs(&self, name: &str, lines: usize) -> Result<LogTail> {
        let store = Self::store()?;
        Self::known(&store, name)?;
        let output = std::process::Command::new("journalctl")
            .args(["-u", &service::unit_name(name), "-n", &lines.clamp(1, MAX_LINES).to_string(), "-o", "cat", "--show-cursor", "--no-pager"])
            .stdin(std::process::Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        // Taken before the tail: lines written while it is read are followed, not lost.
        let read_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let mut tail = LogTail::default();
        for line in output.lines() {
            match line.strip_prefix("-- cursor: ") {
                Some(cursor) if cursor_ok(cursor.trim()) => tail.cursor = Some(cursor.trim().to_string()),
                _ => tail.lines.push(clip(line)),
            }
        }
        if tail.cursor.is_none() {
            tail.cursor = Some(format!("@{read_at}"));
        }
        Ok(tail)
    }

    fn editable(&self, name: &str) -> Result<serde_json::Value> {
        let store = Self::store()?;
        Self::known(&store, name)?;
        let mut screen = super::edit::editable(&store.read(name)?)?;
        screen["can_undo"] = store.has_previous(name).into();
        Ok(screen)
    }

    fn edit(&self, name: &str, changes: &serde_json::Value) -> Result<EditOutcome> {
        let store = Self::store()?;
        Self::known(&store, name)?;
        let _lock = store.lock(name, false)?;
        let config = store.read(name)?;
        let edited = super::edit::apply(&config, changes)?;
        if edited == config {
            return Ok(EditOutcome::default());
        }
        Self::save_with_revert(&store, name, &edited)
    }

    fn undo(&self, name: &str) -> Result<EditOutcome> {
        let store = Self::store()?;
        Self::known(&store, name)?;
        let _lock = store.lock(name, false)?;
        if !store.has_previous(name) {
            bail!("there is no previous version of this tunnel's settings");
        }
        let had_service = service::state(&store, name) != State::NoService;
        let earlier = store.previous_bytes(name);
        store.restore_previous(name)?;
        if !store.system || !had_service {
            return Ok(EditOutcome { changed: true, ..EditOutcome::default() });
        }
        let (up, problem) = Self::restart_saved(&store, name);
        if up {
            return Ok(EditOutcome { changed: true, restarted: true, came_up: Some(true), ..EditOutcome::default() });
        }
        // The version gone back to does not stay up either: the settings from before the undo
        // return, and the undone version stays the one to go back to.
        store.take_back_save(name, earlier.as_deref()).context("put the settings from before back")?;
        let (back_up, _) = Self::restart_saved(&store, name);
        Ok(EditOutcome { changed: true, restarted: true, came_up: Some(back_up), reverted: true, detail: problem })
    }

    fn create(&self, name: &str, config: &serde_json::Value) -> Result<Outcome> {
        let store = (|| {
            crate::manager::plan::check_name(name)?;
            super::wizard::creatable(config)?;
            Self::store()
        })()
        .map_err(|error| anyhow::anyhow!("{UNCHANGED}: {error:#}"))?;
        // As context, so a busy lock keeps its code under the same words.
        let _lock = store.lock(name, false).context(UNCHANGED)?;
        if store.names()?.iter().any(|n| n == name) {
            bail!("{UNCHANGED}: a tunnel named {name} already exists on this server");
        }
        store.save(name, config)?;
        if !store.system {
            return Ok(Outcome { changed: true, came_up: None });
        }
        Self::install_new(&store, name, || service::install_with(&store, name, &installed_program()), || service::remove(name))?;
        let up = service::watch_started(|| service::state(&store, name) == State::Running, std::thread::sleep);
        Ok(Outcome { changed: true, came_up: Some(up) })
    }

    fn server(&self, request: &serde_json::Value) -> Result<serde_json::Value> {
        use super::tools;
        let store = Self::store()?;
        match request["tool"].as_str() {
            Some("health") => tools::health(&store),
            Some("fix") => tools::fix(&store, request["fix"].as_str().unwrap_or("")),
            Some("optimize_plan") => Ok(tools::optimize_plan()),
            Some("optimize_apply") => {
                let failed = crate::manager::optimize::apply(&crate::manager::optimize::plan())?;
                // Undo of an earlier optimization may have lowered the UDP ceiling; put it back.
                let _ = service::restore_udp_buffers(&store);
                Ok(serde_json::json!({"done": true, "failed": failed}))
            }
            Some("optimize_undo") => {
                let restored = crate::manager::optimize::undo()?;
                let _ = service::restore_udp_buffers(&store);
                Ok(serde_json::json!({"done": true, "restored": restored}))
            }
            Some("files") => tools::files(&store),
            Some("check") => super::conntest::answer(&request["check"]),
            Some("spoof") => super::spoofcheck::answer(&request["spoof"]),
            // Runs on a blocking thread of the runtime, which may wait for async work.
            Some("path") => tokio::runtime::Handle::current().block_on(super::relay::answer(&request["path"])),
            Some("versions") => Ok(super::maintain::versions()),
            Some("receive") => super::maintain::receive(request),
            Some("install") => super::maintain::install_received(request["allow_downgrade"] == true),
            Some("rollback") => super::maintain::rollback(),
            Some("export") => super::maintain::export(&store),
            Some("import") => {
                let text = request["text"].as_str().context("the backup is missing")?;
                // What ran before: a replaced tunnel that was running restarts on its restored
                // settings; one that was stopped stays stopped. Added tunnels are started.
                let before: HashMap<String, State> = store
                    .names()?
                    .into_iter()
                    .map(|name| { let state = service::state(&store, &name); (name, state) })
                    .collect();
                let mut report = super::maintain::import(&store, text, request["replace"] == true)?;
                let imported: Vec<String> = report["imported"].as_array().into_iter().flatten()
                    .filter_map(|n| n.as_str().map(str::to_string)).collect();
                let mut started = Vec::new();
                if store.system {
                    for name in &imported {
                        let _lock = store.lock(name, false)?;
                        match before.get(name) {
                            // Added, or replaced while it ran: on its restored settings now.
                            None | Some(State::Running) => {
                                let (up, problem) = Self::restart_saved(&store, name);
                                started.push(serde_json::json!({"name": name, "came_up": up, "problem": problem}));
                            }
                            // Saved only, no service: as it was.
                            Some(State::NoService) => {}
                            // Stopped: its unit follows the restored file, so a later Start runs
                            // what the file needs (a privileged port, for example); still stopped.
                            Some(_) => {
                                if let Err(error) = service::rewrite(&store, name, &installed_program()) {
                                    started.push(serde_json::json!({"name": name, "came_up": false, "problem": format!("{error:#}")}));
                                }
                            }
                        }
                    }
                }
                report["started"] = serde_json::json!(started);
                Ok(report)
            }
            _ => bail!("unknown tool"),
        }
    }

    fn status(&self, name: &str) -> Result<serde_json::Value> {
        let store = Self::store()?;
        Self::known(&store, name)?;
        service::control(name, &serde_json::json!({"cmd": "status"}), Duration::from_secs(3))
            .context("the tunnel is not running or has no status channel")
    }

    fn speedtest(&self, name: &str, download: bool, bytes: u64, streams: u64) -> Result<serde_json::Value> {
        check_speedtest(bytes, streams)?;
        let store = Self::store()?;
        Self::known(&store, name)?;
        let request = serde_json::json!({"cmd": "speedtest", "direction": if download { "down" } else { "up" }, "bytes": bytes, "streams": streams});
        let answer = service::control(name, &request, Duration::from_secs(120))?;
        if answer["ok"] == false {
            bail!("{}", answer["error"].as_str().unwrap_or("the speed test failed"));
        }
        Ok(answer)
    }

    fn pairing(&self, name: &str, address: Option<String>) -> Result<serde_json::Value> {
        let store = Self::store()?;
        Self::known(&store, name)?;
        pairing_of(&store.read(name)?, address)
    }

    fn quota_reset(&self, name: &str) -> Result<Outcome> {
        let store = Self::store()?;
        Self::known(&store, name)?;
        if !store.system {
            bail!("tunnel services need root and systemd");
        }
        let _lock = store.lock(name, false)?;
        crate::manager::manage::reset_quota_with(
            || service::stop(name),
            || std::fs::remove_file(crate::quota::service_state_path(name)),
            || service::start(name),
        )?;
        let up = service::watch_started(|| service::state(&store, name) == State::Running, std::thread::sleep);
        Ok(Outcome { changed: true, came_up: Some(up) })
    }

    fn delete(&self, name: &str) -> Result<()> {
        Self::delete_if(&Self::store()?, name, |_| None)
    }

    fn delete_own(&self, name: &str, tunnel_key: &str) -> Result<()> {
        Self::delete_if(&Self::store()?, name, |config| {
            // Same name, other key: someone else's tunnel; it stays.
            (config["tunnel_key"].as_str() != Some(tunnel_key))
                .then(|| anyhow::anyhow!("{UNCHANGED}: {name} here is another tunnel, not the one being created"))
        })
    }

    fn delete_pair(&self, name: &str, pair: &str) -> Result<()> {
        Self::delete_if(&Self::store()?, name, |config| pair_differs(config, name, pair))
    }

    fn follow(&self, name: &str, after: Option<String>) -> Result<Follow> {
        let store = Self::store()?;
        Self::known(&store, name)?;
        // From the cursor the reader already has (nothing lost in between), else only new lines.
        let start = match after.filter(|c| cursor_ok(c)) {
            Some(seconds) if seconds.starts_with('@') => format!("--since={seconds}"),
            Some(cursor) => format!("--after-cursor={cursor}"),
            None => "--lines=0".to_string(),
        };
        let mut child = tokio::process::Command::new("journalctl")
            .args(["-u", &service::unit_name(name), "-f", &start, "-o", "json", "--no-pager"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("run journalctl")?;
        let stdout = child.stdout.take().context("journalctl output")?;
        Ok(Follow::Journal { _child: child, lines: BufReader::new(stdout).lines() })
    }
}

/// The demo: actions change the sample tunnels' state, logs are made up. Nothing on the machine
/// is touched.
#[derive(Clone, Default)]
pub struct DemoOps {
    /// Tunnels whose running state was changed by an action: name → running.
    pub overrides: Arc<Mutex<HashMap<String, bool>>>,
    pub names: Vec<String>,
    /// Sample tunnels deleted in this demo.
    pub removed: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Tunnels created in this demo: name and configuration.
    pub added: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
    /// Pause after an action, as a real service takes a moment.
    pub delay: Duration,
    /// When the demo's transport check started, and whether the optimization is "applied".
    pub check_started: Arc<Mutex<Option<u64>>>,
    /// The options of the sample check, from its code (a find or a tune check).
    pub check_options: Arc<Mutex<Option<crate::checker::Options>>>,
    pub spoof_started: Arc<Mutex<Option<u64>>>,
    pub optimized: Arc<Mutex<bool>>,
}

impl DemoOps {
    pub fn new(names: &[&str]) -> Self {
        Self {
            overrides: Arc::default(),
            names: names.iter().map(|n| n.to_string()).collect(),
            removed: Arc::default(),
            added: Arc::default(),
            check_started: Arc::default(),
            check_options: Arc::default(),
            spoof_started: Arc::default(),
            optimized: Arc::default(),
            delay: Duration::from_millis(900),
        }
    }

    /// Whether the demo deleted this sample tunnel.
    pub fn deleted(&self, name: &str) -> bool {
        self.removed.lock().unwrap().contains(name)
    }

    /// The tunnels created in this demo.
    pub fn created(&self) -> Vec<(String, serde_json::Value)> {
        let added = self.added.lock().unwrap();
        let mut seen = std::collections::HashSet::new();
        added.iter().rev()
            .filter(|(n, _)| seen.insert(n.clone()) && !self.deleted(n))
            .cloned().collect()
    }

    fn known(&self, name: &str) -> Result<()> {
        if !self.names().iter().any(|n| n == name) {
            return Err(unknown_tunnel(name));
        }
        Ok(())
    }

    /// Running state for the demo source: the override if an action set one.
    pub fn running(&self, name: &str, default: bool) -> bool {
        self.overrides.lock().unwrap().get(name).copied().unwrap_or(default)
    }
}

impl Ops for DemoOps {
    fn names(&self) -> Vec<String> {
        let added = self.added.lock().unwrap().iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
        let mut seen = std::collections::HashSet::new();
        self.names.iter().chain(added.iter())
            .filter(|n| !self.deleted(n) && seen.insert((*n).clone()))
            .cloned().collect()
    }

    fn create(&self, name: &str, config: &serde_json::Value) -> Result<Outcome> {
        crate::manager::plan::check_name(name)?;
        super::wizard::creatable(config)?;
        if self.names().iter().any(|n| n == name) {
            bail!("{UNCHANGED}: a tunnel named {name} already exists on this server");
        }
        std::thread::sleep(self.delay * 2);
        self.removed.lock().unwrap().remove(name);
        self.added.lock().unwrap().push((name.to_string(), config.clone()));
        Ok(Outcome { changed: true, came_up: Some(true) })
    }

    fn server(&self, request: &serde_json::Value) -> Result<serde_json::Value> {
        use serde_json::json;
        let optimized = *self.optimized.lock().unwrap();
        let now = super::now();
        match request["tool"].as_str() {
            Some("health") => {
                let mut checks = vec![
                    json!({"id": "time_sync", "subject": "", "level": "ok", "value": true, "fix": null}),
                    json!({"id": "congestion", "subject": "", "level": if optimized { "ok" } else { "warn" }, "value": if optimized { "bbr" } else { "cubic" }, "fix": if optimized { None } else { Some("optimize") }}),
                    json!({"id": "optimize", "subject": "", "level": if optimized { "ok" } else { "warn" }, "value": if optimized { 0 } else { 6 }, "fix": if optimized { None } else { Some("optimize") }}),
                    json!({"id": "disk", "subject": "", "level": "ok", "value": 38.0, "fix": null}),
                    json!({"id": "memory", "subject": "", "level": "ok", "value": 58.2, "fix": null}),
                    json!({"id": "udp_buffers", "subject": "", "level": "ok", "value": {"have": 33554432, "want": 16777216}, "fix": null}),
                ];
                for name in self.names() {
                    let running = self.running(&name, name != "backup-tcp");
                    checks.push(if running {
                        json!({"id": "service", "subject": name, "level": "ok", "value": "running", "fix": null})
                    } else {
                        json!({"id": "service", "subject": name, "level": "warn", "value": "stopped", "fix": format!("start:{name}")})
                    });
                    if running && name == "cdn-xhttps" {
                        checks.push(json!({"id": "link", "subject": name, "level": "warn", "value": {"state": "no_traffic", "last_drop": "no heartbeat answer"}, "fix": format!("restart:{name}")}));
                    } else if running {
                        checks.push(json!({"id": "link", "subject": name, "level": "ok", "value": {"state": "working", "last_drop": null}, "fix": null}));
                    }
                    if name == "game-fec" {
                        checks.push(json!({"id": "firewall", "subject": name, "level": "bad", "value": "7000/udp", "fix": "ufw:7000/udp"}));
                    }
                }
                Ok(json!({"checks": checks, "tunnels": self.names().len()}))
            }
            Some("fix") => {
                let fix = request["fix"].as_str().unwrap_or("");
                std::thread::sleep(self.delay);
                match fix.split_once(':') {
                    Some(("start" | "restart", name)) => {
                        self.known(name)?;
                        self.overrides.lock().unwrap().insert(name.to_string(), true);
                    }
                    _ if fix == "optimize" => *self.optimized.lock().unwrap() = true,
                    _ => {}
                }
                Ok(json!({"done": true, "came_up": true}))
            }
            Some("optimize_plan") => Ok(json!({"applied": optimized, "changes": if optimized { json!([]) } else { json!([
                {"key": "net.ipv4.tcp_congestion_control", "current": "cubic", "wanted": "bbr", "why": "BBR keeps speed up on long, lossy links"},
                {"key": "net.core.default_qdisc", "current": "fq_codel", "wanted": "fq", "why": "BBR paces packets best with the fq queue"},
                {"key": "net.core.rmem_max", "current": "212992", "wanted": "67108864", "why": "Larger receive buffers for fast long-distance links"},
                {"key": "net.core.wmem_max", "current": "212992", "wanted": "67108864", "why": "Larger send buffers for fast long-distance links"},
                {"key": "net.ipv4.tcp_fastopen", "current": "1", "wanted": "3", "why": "Saves a round trip when connections open"},
                {"key": "fs.file-max", "current": "524288", "wanted": "2097152", "why": "Room for many user connections"},
            ]) }})),
            Some("optimize_apply") => {
                std::thread::sleep(self.delay);
                *self.optimized.lock().unwrap() = true;
                Ok(json!({"done": true, "failed": []}))
            }
            Some("optimize_undo") => {
                std::thread::sleep(self.delay);
                *self.optimized.lock().unwrap() = false;
                Ok(json!({"done": true, "restored": 6}))
            }
            Some("files") => {
                let mut files = vec![
                    json!({"label": "configs", "path": "/etc/eztunnel/tunnels", "exists": true, "size": 4_812, "modified": now - 3_600}),
                    json!({"label": "program", "path": INSTALLED, "exists": true, "size": 17_268_776, "modified": now - 86_400 * 3}),
                    json!({"label": "previous_program", "path": "/usr/local/bin/eztunnel.previous", "exists": true, "size": 17_160_224, "modified": now - 86_400 * 20}),
                    json!({"label": "dashboard_state", "path": "/var/lib/eztunnel-dashboard", "exists": true, "size": 1_904_221, "modified": now - 60}),
                ];
                for name in self.names() {
                    files.push(json!({"label": "tunnel", "path": format!("/etc/eztunnel/tunnels/{name}.json"), "exists": true, "size": 412, "modified": now - 86_400}));
                    files.push(json!({"label": "unit", "path": format!("/etc/systemd/system/eztunnel-{name}.service"), "exists": true, "size": 702, "modified": now - 86_400}));
                }
                Ok(json!({"files": files}))
            }
            Some("check") => {
                let check = &request["check"];
                let mut started = self.check_started.lock().unwrap();
                match check["action"].as_str() {
                    Some("start") | Some("join") => {
                        *started = Some(now);
                        *self.check_options.lock().unwrap() = check["code"]
                            .as_str()
                            .and_then(|text| crate::checker::code::decode(text).ok())
                            .map(|code| code.options);
                        Ok(json!({"started": true}))
                    }
                    Some("stop") => {
                        *started = None;
                        Ok(json!({"stopping": true}))
                    }
                    _ => Ok(match *started {
                        Some(at) => super::conntest::demo_status(self.check_options.lock().unwrap().as_ref(), at, now),
                        None => json!({"state": "idle"}),
                    }),
                }
            }
            Some("spoof") => {
                let mut started = self.spoof_started.lock().unwrap();
                match request["spoof"]["action"].as_str() {
                    Some("host") | Some("join") => {
                        *started = Some(now);
                        Ok(json!({"started": true}))
                    }
                    Some("stop") => {
                        *started = None;
                        Ok(json!({"stopping": true}))
                    }
                    _ => Ok(match *started {
                        Some(at) => super::spoofcheck::demo_status(at, now),
                        None => json!({"state": "idle"}),
                    }),
                }
            }
            Some("path") => {
                std::thread::sleep(Duration::from_millis(400));
                let step = request["path"]["step"].as_str().unwrap_or("");
                let target = request["path"]["target"].as_str().unwrap_or("");
                Ok(match step {
                    "probe" => json!({"reachable": false, "ping": false, "tcp": [[22, "timeout"], [80, "timeout"], [443, "timeout"], [8443, "timeout"]]}),
                    "known" => json!({"known": super::relay::KNOWN.iter().enumerate().map(|(i, (n, ip))| json!({"name": n, "ip": ip, "result": if i == 0 { "open" } else { "timeout" }})).collect::<Vec<_>>()}),
                    "echo_check" | "banner_check" if target.starts_with("198.51.100.20") => json!({"ok": false, "error": "no answer"}),
                    "echo_check" | "banner_check" => json!({"ok": true, "ms": 96, "greeting": "SSH-2.0-OpenSSH_9.6"}),
                    _ => json!({"listening": true, "forwarding": true}),
                })
            }
            Some("versions") => Ok(json!({"installed": env!("CARGO_PKG_VERSION"), "previous": "0.9.13", "has_previous": true,
                                          "running": env!("CARGO_PKG_VERSION"), "arch": "x86_64"})),
            Some("receive") => Ok(json!({"ready": true, "written": request["offset"]})),
            Some("install") | Some("rollback") => {
                std::thread::sleep(self.delay * 2);
                Ok(json!({"done": true, "output": "The demo installs nothing."}))
            }
            Some("export") => Ok(json!({"backup": {"eztunnel_backup": 1, "program": env!("CARGO_PKG_VERSION"),
                "tunnels": self.names().iter().map(|n| (n.clone(), json!({"mode": "server", "tunnel_key": "demo"}))).collect::<serde_json::Map<_, _>>()},
                "skipped": []})),
            Some("import") => {
                std::thread::sleep(self.delay);
                Ok(json!({"imported": [], "skipped": self.names(), "failed": [], "started": []}))
            }
            _ => bail!("unknown tool"),
        }
    }

    fn status(&self, name: &str) -> Result<serde_json::Value> {
        self.known(name)?;
        if !self.running(name, name != "backup-tcp") {
            bail!("the tunnel is not running or has no status channel");
        }
        Ok(serde_json::json!({
            "ok": true, "version": env!("CARGO_PKG_VERSION"), "role": "server", "uptime_sec": 532_800,
            "sessions": 4, "connects": 9, "streams": 23, "streams_total": 48_210, "refused": 0, "rejected": 2,
            "udp_dropped": 0, "udp_oversize": 0, "bytes_to_peer": 4_512_000_000u64, "bytes_from_peer": 51_520_000_000u64,
            "pings": 106_560, "pongs": 106_541, "pings_lost": 19, "rtt_ms": [81.2, 83.0, 84.9, 82.4, 90.1, 82.7],
            "window_frames_used": 384, "window_frames_limit": 16_384,
            "transport_extensions": {"fec_recovered": 1_942, "fec_unrecoverable": 3},
        }))
    }

    fn speedtest(&self, name: &str, download: bool, bytes: u64, streams: u64) -> Result<serde_json::Value> {
        check_speedtest(bytes, streams)?;
        self.known(name)?;
        let rate = if download { 9.6e6 } else { 7.1e6 } * if streams > 1 { 2.3 } else { 1.0 };
        let seconds = bytes as f64 / rate;
        std::thread::sleep(Duration::from_secs_f64(seconds.min(3.0)));
        Ok(serde_json::json!({"ok": true, "direction": if download { "down" } else { "up" }, "streams": streams,
                              "bytes": bytes, "seconds": seconds, "bytes_per_second": rate}))
    }

    fn pairing(&self, name: &str, address: Option<String>) -> Result<serde_json::Value> {
        self.known(name)?;
        let config = serde_json::json!({"mode": "server", "tunnel_key": "EZK1-demo-key-not-real-0000000000",
            "listeners": [{"addr": "0.0.0.0:7000", "transport": "tcp", "maps": [{"type": "tcp", "bind": "0.0.0.0:9392", "target": "127.0.0.1:9392"}]}]});
        if address.as_deref().is_none_or(|a| a.trim().is_empty()) {
            return Ok(serde_json::json!({"needs_address": true, "suggested": "203.0.113.10"}));
        }
        let _ = config;
        Ok(serde_json::json!({"needs_address": true, "code": "ezp1-demo-code-it-pairs-nothing", "creator": "iran"}))
    }

    fn quota_reset(&self, name: &str) -> Result<Outcome> {
        self.known(name)?;
        std::thread::sleep(self.delay);
        Ok(Outcome { changed: true, came_up: Some(true) })
    }

    fn act_pair(&self, name: &str, action: Action, pair: &str) -> Result<Outcome> {
        self.known(name)?;
        let latest = self.added.lock().unwrap().iter().rev()
            .find(|(n, _)| n == name).map(|(_, v)| v.clone());
        if let Some(failure) = latest.as_ref().and_then(|config| pair_differs(config, name, pair)) {
            return Err(failure);
        }
        if latest.is_none() {
            return Err(refused("pair_changed", format!("{UNCHANGED}: {name} has no current saved pair")));
        }
        self.act(name, action)
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.known(name)?;
        std::thread::sleep(self.delay);
        self.removed.lock().unwrap().insert(name.to_string());
        Ok(())
    }

    /// A tunnel made in this demo is checked like a real one; the samples have no saved key.
    fn delete_pair(&self, name: &str, pair: &str) -> Result<()> {
        self.known(name)?;
        let made = self.added.lock().unwrap().iter().rev().find(|(n, _)| n == name).map(|(_, config)| config.clone());
        if let Some(refusal) = made.and_then(|config| pair_differs(&config, name, pair)) {
            return Err(refusal);
        }
        self.delete(name)
    }

    fn act(&self, name: &str, action: Action) -> Result<Outcome> {
        self.known(name)?;
        let running = self.running(name, name != "backup-tcp");
        let state = if running { State::Running } else { State::Stopped };
        let Some(step) = bulk::step_for(action, state) else {
            return Ok(Outcome { changed: false, came_up: None });
        };
        std::thread::sleep(self.delay);
        let now_running = step != Step::Stop;
        self.overrides.lock().unwrap().insert(name.to_string(), now_running);
        Ok(Outcome { changed: true, came_up: now_running.then_some(true) })
    }

    fn logs(&self, name: &str, lines: usize) -> Result<LogTail> {
        self.known(name)?;
        let lines = lines.clamp(1, MAX_LINES).min(60) as u64;
        Ok(LogTail { lines: (1..=lines).map(|n| demo_line(name, n)).collect(), cursor: None })
    }

    fn editable(&self, name: &str) -> Result<serde_json::Value> {
        self.known(name)?;
        let settings = serde_json::json!([
            {"name": "stream_window", "place": "top", "unit": "frames", "min": 16, "max": 1024, "default": 128, "value": null,
             "description": "Data one user connection may have in flight, in 16 KiB frames."},
            {"name": "heartbeat_sec", "place": "top", "unit": "seconds", "min": 1, "max": 300, "default": 10, "value": 5,
             "description": "How often each session is checked."},
        ]);
        let ports = match name {
            "game-fec" => serde_json::json!({"text": "9392", "protocol": "both", "several_addresses": false, "proxy_protocol": 0}),
            "web-wss" => serde_json::json!({"text": "443, 8443", "protocol": "tcp", "several_addresses": false, "proxy_protocol": 2}),
            _ => serde_json::Value::Null,
        };
        Ok(serde_json::json!({"ports": ports, "quota": {"limit_gb": if name == "game-fec" { 500 } else { 0 }, "period_days": 30},
                              "settings": settings, "can_undo": name == "web-wss", "restart_hours": if name == "web-wss" { 24 } else { 0 }}))
    }

    fn edit(&self, name: &str, changes: &serde_json::Value) -> Result<EditOutcome> {
        self.known(name)?;
        if let Some(text) = changes["ports"]["text"].as_str() {
            crate::manager::plan::parse_ports(text)?;
        }
        std::thread::sleep(self.delay * 2);
        Ok(EditOutcome { changed: true, restarted: true, came_up: Some(true), ..EditOutcome::default() })
    }

    fn undo(&self, name: &str) -> Result<EditOutcome> {
        self.known(name)?;
        std::thread::sleep(self.delay * 2);
        Ok(EditOutcome { changed: true, restarted: true, came_up: Some(true), ..EditOutcome::default() })
    }

    fn follow(&self, name: &str, _after: Option<String>) -> Result<Follow> {
        self.known(name)?;
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Ok(Follow::Demo { name: name.to_string(), tick, count: 100 })
    }
}

/// A made-up log line in the format the tunnel writes (sample data).
fn demo_line(name: &str, n: u64) -> String {
    let second = n % 60;
    let minute = (n / 60) % 60;
    let time = format!("2026-11-13T10:{minute:02}:{second:02}.000000Z");
    match n % 12 {
        0 => format!("{time}  INFO eztunnel::stats: status: sessions=4 connects={} streams={} streams_total={} refused=0 rejected=0 udp_dropped=0 sent=1.2 GiB received=14.8 GiB", 4 + n / 40, 8 + n % 9, 120 + n),
        5 if name == "cdn-xhttps" => format!("{time}  WARN eztunnel::engine: tunnel session ended seconds=611 reason=no heartbeat answer"),
        7 if name == "cdn-xhttps" => format!("{time}  INFO eztunnel::engine: authenticated tunnel connected address=198.51.100.20:2083"),
        _ => format!("{time} DEBUG eztunnel::engine: stream opened id={} kind=tcp", 1000 + n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_three_actions_are_understood() {
        assert_eq!(parse_action("start"), Some(Action::Start));
        assert_eq!(parse_action("stop"), Some(Action::Stop));
        assert_eq!(parse_action("restart"), Some(Action::Restart));
        for word in ["", "Start", "delete", "start;reboot", "../stop"] {
            assert_eq!(parse_action(word), None, "{word}");
        }
        for action in [Action::Start, Action::Stop, Action::Restart] {
            assert_eq!(parse_action(action_word(action)), Some(action));
        }
    }

    #[test]
    fn remote_action_and_logs_report_typed_unknown_tunnel_without_parsing_messages() {
        let demo = DemoOps::new(&["exists"]);
        for request in [
            serde_json::json!({"op": "act", "name": "missing", "action": "stop"}),
            serde_json::json!({"op": "logs", "name": "missing", "lines": 20}),
        ] {
            let err = answer(&demo, &request).unwrap_err();
            assert_eq!(code_of(&err), Some("unknown_tunnel"));
        }
    }

    #[test]
    fn demo_actions_change_state_like_the_manager_and_only_for_known_tunnels() {
        let mut ops = DemoOps::new(&["game-fec", "backup-tcp"]);
        ops.delay = Duration::ZERO;
        // Starting a running tunnel changes nothing, as in the terminal manager.
        assert_eq!(ops.act("game-fec", Action::Start).unwrap(), Outcome { changed: false, came_up: None });
        assert_eq!(ops.act("game-fec", Action::Stop).unwrap(), Outcome { changed: true, came_up: None });
        assert!(!ops.running("game-fec", true));
        assert_eq!(ops.act("game-fec", Action::Stop).unwrap().changed, false);
        assert_eq!(ops.act("game-fec", Action::Restart).unwrap(), Outcome { changed: true, came_up: Some(true) });
        assert!(ops.running("game-fec", false));
        assert!(ops.act("backup-tcp", Action::Start).unwrap().changed);
        assert!(ops.act("nothing", Action::Start).is_err());
        assert!(ops.logs("../etc", 10).is_err());
        assert!(cursor_ok("s=739ad463348b4ceca5a9e69c95a3c93f;i=4ece7;b=6c7c6013a8914b6b;m=95fe5ac;t=4f45f6a3a1b5f;x=f48c8dc8d0c0d24"));
        assert!(cursor_ok("@1763390000"), "the time of an empty tail");
        for bad in ["", "a b", "--since=yesterday x", "s=1\n", "x;$(id)", "@", "@12a", "@-1"] {
            assert!(!cursor_ok(bad), "{bad}");
        }
        assert!(ops.follow("nothing", None).is_err());
    }

    #[test]
    fn paired_action_and_delete_refuse_a_recreated_tunnel_with_the_same_name() {
        // Use the actual wizard model: both key fingerprints are valid, but different.
        let form = serde_json::json!({"name":"qa-reuse", "transport":"tcp",
            "address":"203.0.113.10", "ports":"9392"});
        let original = super::super::wizard::build(&form).unwrap().foreign;
        let replacement = super::super::wizard::build(&form).unwrap().foreign;
        let old_pair = super::super::data::pair_of(&original).unwrap();
        let new_pair = super::super::data::pair_of(&replacement).unwrap();
        assert_ne!(old_pair, new_pair);
        let mut demo = DemoOps::new(&[]);
        demo.delay = Duration::ZERO;
        demo.create("qa-reuse", &original).unwrap();
        demo.delete("qa-reuse").unwrap();
        demo.create("qa-reuse", &replacement).unwrap();
        assert_eq!(demo.names().iter().filter(|n| *n == "qa-reuse").count(), 1);
        assert_eq!(demo.created().iter().filter(|(n, _)| n == "qa-reuse").count(), 1);
        assert_eq!(super::super::data::pair_of(&demo.created()[0].1).as_deref(), Some(new_pair.as_str()));
        assert!(demo.running("qa-reuse", true));

        // Pair A was captured earlier, then B took the exact same server/name.
        for action in ["start", "stop", "restart"] {
            let request = serde_json::json!({"op":"act_pair", "name":"qa-reuse",
                "action":action, "expect_pair":old_pair});
            let error = answer(&demo, &request).unwrap_err();
            assert_eq!(code_of(&error), Some("pair_changed"), "{action}: {error:#}");
            assert!(demo.running("qa-reuse", true), "{action} touched replacement B");
        }
        assert_eq!(code_of(&answer(&demo, &serde_json::json!({"op":"delete_pair",
            "name":"qa-reuse", "expect_pair":old_pair})).unwrap_err()), Some("pair_changed"));
        assert!(demo.names().iter().any(|n| n == "qa-reuse"));
        // Correct current key works even with uppercase user input.
        let stopped = answer(&demo, &serde_json::json!({"op":"act_pair", "name":"qa-reuse",
            "action":"stop", "expect_pair":new_pair.to_uppercase()})).unwrap();
        assert_eq!(stopped["changed"], true);
        assert!(!demo.running("qa-reuse", true));
        answer(&demo, &serde_json::json!({"op":"delete_pair", "name":"qa-reuse",
            "expect_pair":new_pair.to_uppercase()})).unwrap();
        assert!(demo.deleted("qa-reuse"));
    }

    #[test]
    fn paired_lifecycle_requires_fingerprint_and_allowlisted_action() {
        let demo = DemoOps::new(&["qa"]);
        for request in [
            serde_json::json!({"op":"act_pair", "name":"qa", "action":"start"}),
            serde_json::json!({"op":"act_pair", "name":"qa", "action":"start", "expect_pair":"invalid"}),
            serde_json::json!({"op":"act_pair", "name":"qa", "action":"remove", "expect_pair":"0123456789abcdef"}),
        ] {
            assert!(answer(&demo, &request).is_err());
        }
        assert!(demo.running("qa", true));
    }

    #[test]
    fn failed_create_cleanup_removes_the_saved_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::for_test(dir.path().to_path_buf());
        let config = super::super::wizard::build(&serde_json::json!({"name": "game", "transport": "tcp", "address": "192.0.2.1", "ports": "9392"})).unwrap().foreign;
        store.save("game", &config).unwrap();
        let result = LocalOps::install_new(&store, "game", || Err(anyhow::anyhow!("install failed")), || Ok(()));
        assert!(result.is_err());
        assert!(!store.path("game").exists());
    }

    #[test]
    fn a_delete_by_pair_spares_a_tunnel_made_again_under_the_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::for_test(dir.path().to_path_buf());
        let form = serde_json::json!({"name": "game", "transport": "tcp", "address": "192.0.2.1", "ports": "9392"});
        let chosen = super::super::wizard::build(&form).unwrap().foreign;
        let replacement = super::super::wizard::build(&form).unwrap().foreign;
        let old = super::super::data::pair_of(&chosen).unwrap();
        let new = super::super::data::pair_of(&replacement).unwrap();
        assert_ne!(old, new);
        // The one chosen was deleted and another made under its name in the meantime.
        store.save("game", &replacement).unwrap();
        let refused = LocalOps::delete_if(&store, "game", |config| pair_differs(config, "game", &old)).unwrap_err();
        assert_eq!(code_of(&refused), Some("pair_changed"));
        assert!(format!("{refused:#}").starts_with(UNCHANGED), "{refused:#}");
        assert!(store.path("game").exists(), "the other tunnel stays");
        // Held elsewhere: busy, and still there.
        let held = store.lock("game", false).unwrap();
        let busy = LocalOps::delete_if(&store, "game", |config| pair_differs(config, "game", &new)).unwrap_err();
        assert_eq!(code_of(&busy), Some("busy"));
        drop(held);
        // Its own fingerprint (in any case) deletes it.
        LocalOps::delete_if(&store, "game", |config| pair_differs(config, "game", &new.to_uppercase())).unwrap();
        assert!(!store.path("game").exists());
        let gone = LocalOps::delete_if(&store, "game", |_| None).unwrap_err();
        assert_eq!((code_of(&gone), format!("{gone:#}").as_str()), (Some("unknown_tunnel"), "no tunnel named game"));
        // A configuration without a tunnel key has no pair: never deleted by one.
        assert!(pair_differs(&serde_json::json!({"mode": "server"}), "x", &old).is_some());
    }

    #[test]
    fn delete_requests_check_the_pair_when_one_is_sent_and_not_otherwise() {
        let form = serde_json::json!({"name": "web", "transport": "tcp", "address": "192.0.2.1", "ports": "8080"});
        let first = super::super::wizard::build(&form).unwrap().foreign;
        let second = super::super::wizard::build(&form).unwrap().foreign;
        let old = super::super::data::pair_of(&first).unwrap();
        let mut demo = DemoOps::new(&["sample"]);
        demo.delay = Duration::ZERO;
        demo.create("web", &first).unwrap();
        demo.delete("web").unwrap();
        demo.create("web", &second).unwrap();
        let request = |pair: serde_json::Value| serde_json::json!({"op": "delete", "name": "web", "expect_pair": pair});
        let refused = answer(&demo, &request(serde_json::json!(old))).unwrap_err();
        assert_eq!(code_of(&refused), Some("pair_changed"));
        assert!(demo.names().contains(&"web".to_string()));
        for bad in [serde_json::json!("not-a-pair"), serde_json::json!(7)] {
            assert!(answer(&demo, &request(bad)).is_err());
        }
        assert!(demo.names().contains(&"web".to_string()), "a bad fingerprint deletes nothing");
        // No fingerprint (a dashboard from before it, or `null`): by name, as always.
        answer(&demo, &request(serde_json::Value::Null)).unwrap();
        assert!(!demo.names().contains(&"web".to_string()));
        let missing = answer(&demo, &serde_json::json!({"op": "delete", "name": "web"})).unwrap_err();
        assert_eq!(code_of(&missing), Some("unknown_tunnel"));
        // Codes are only ours; anything a peer makes up is no code.
        assert_eq!(known_code("busy"), Some("busy"));
        assert_eq!(known_code("drop_tables"), None);
        assert_eq!(code_of(&anyhow::anyhow!("plain")), None);
        assert_eq!(code_of(&anyhow::Error::from(Refused { code: "busy", message: "m".into() }).context("outer")), Some("busy"));
    }

    #[test]
    fn services_use_the_installed_program_when_there_is_one() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("eztunnel");
        // Not installed: this program.
        assert_eq!(program_for(&installed), std::env::current_exe().unwrap().canonicalize().unwrap());
        std::fs::write(&installed, b"x").unwrap();
        assert_eq!(program_for(&installed), installed);
    }

    #[test]
    fn logs_are_limited_and_long_lines_cut() {
        let ops = DemoOps::new(&["game-fec"]);
        assert_eq!(ops.logs("game-fec", 0).unwrap().lines.len(), 1);
        assert!(ops.logs("game-fec", 50_000).unwrap().lines.len() <= MAX_LINES);
        let long = "x".repeat(MAX_LINE + 50);
        let cut = clip(&long);
        assert_eq!(cut.chars().count(), MAX_LINE + 1);
        assert!(cut.ends_with('…'));
        assert_eq!(clip("short"), "short");
        // Cutting never splits a character.
        let persian = "س".repeat(MAX_LINE + 3);
        assert!(clip(&persian).starts_with('س'));
    }

    #[tokio::test(start_paused = true)]
    async fn the_demo_log_follows_with_new_lines() {
        let ops = DemoOps::new(&["game-fec"]);
        let mut follow = ops.follow("game-fec", None).unwrap();
        let (first, _) = follow.next_line().await.unwrap();
        let (second, _) = follow.next_line().await.unwrap();
        assert_ne!(first, second);
        assert!(first.contains("eztunnel::"));
    }
}
