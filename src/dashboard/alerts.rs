//! Alerts: every 30 seconds the dashboard collects the problems its servers report (tunnel issues,
//! servers that went offline, a full disk, a certificate about to expire). A problem that is still
//! there on the next look fires an alert; one that is gone clears it. Both are kept in a history
//! file and, when Telegram is set up, sent there.
use super::prefs::{Prefs, Telegram};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const HISTORY_FILE: &str = "alerts.jsonl";
/// Looks a problem must survive before it fires (one look is 30 seconds).
const CONFIRM_LOOKS: u32 = 2;
/// History kept on disk before the oldest half is dropped.
const MAX_HISTORY_BYTES: u64 = 2 << 20;

/// One problem as seen now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Problem {
    /// `server:kind:subject`, stable while the problem lasts.
    pub key: String,
    pub server: String,
    pub server_name: String,
    /// failed, not_connected, silent, no_traffic, quota, loss, udp_drops, failover_backup,
    /// carrier_down, offline, disk, cert.
    pub kind: String,
    pub subject: String,
    /// "bad" or "warn".
    pub level: String,
    pub value: Option<f64>,
}

impl Problem {
    pub fn new(server: &str, server_name: &str, kind: &str, subject: &str, level: &str, value: Option<f64>) -> Self {
        Self {
            key: format!("{server}:{kind}:{subject}"),
            server: server.into(),
            server_name: server_name.into(),
            kind: kind.into(),
            subject: subject.into(),
            level: level.into(),
            value,
        }
    }
}

/// The problems in one server's snapshot (as the dashboard and agents send it).
pub fn problems_of(server: &str, server_name: &str, snapshot: &Value) -> Vec<Problem> {
    let mut out: Vec<Problem> = snapshot["issues"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|issue| {
            Some(Problem::new(
                server,
                server_name,
                issue["kind"].as_str()?,
                issue["tunnel"].as_str().unwrap_or(""),
                issue["level"].as_str().unwrap_or("warn"),
                issue["value"].as_f64(),
            ))
        })
        .collect();
    if let Some(disk) = snapshot["host"]["disk_pct"].as_f64().filter(|d| *d >= 90.0) {
        out.push(Problem::new(server, server_name, "disk", "", if disk >= 97.0 { "bad" } else { "warn" }, Some(disk)));
    }
    out
}

/// An alert that fired and has not cleared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Active {
    #[serde(flatten)]
    pub problem: Problem,
    pub since: u64,
    /// The worst level it reached: its recovery is sent to whoever heard about that level, even
    /// when it got better before it ended.
    #[serde(default)]
    pub worst: String,
}

/// What changed in one look.
#[derive(Debug, Default)]
pub struct Changes {
    pub fired: Vec<Active>,
    /// Active warnings that escalated to bad.
    pub escalated: Vec<Active>,
    /// Cleared alerts, with how long they lasted (seconds).
    pub cleared: Vec<(Active, u64)>,
}

/// The alert state between looks.
#[derive(Debug, Default)]
pub struct Engine {
    active: BTreeMap<String, Active>,
    pending: HashMap<String, u32>,
}

impl Engine {
    /// Takes one look: `now` problems at time `at`.
    pub fn look(&mut self, now: Vec<Problem>, at: u64) -> Changes {
        self.look_with(now, at, &[])
    }

    /// `look`, where the servers in `unseen` reported nothing this time (connected again, no
    /// snapshot yet): their problems are unknown, not over.
    pub fn look_with(&mut self, now: Vec<Problem>, at: u64, unseen: &[String]) -> Changes {
        let mut changes = Changes::default();
        let seen: HashMap<String, Problem> = now.into_iter().map(|p| (p.key.clone(), p)).collect();
        self.pending.retain(|key, _| seen.contains_key(key));
        for (key, problem) in &seen {
            if let Some(active) = self.active.get_mut(key) {
                // The level may change while it lasts (warn becomes bad); the alert stays one.
                let escalated = active.problem.level != "bad" && problem.level == "bad";
                active.problem.level = problem.level.clone();
                if problem.level == "bad" {
                    active.worst = "bad".into();
                }
                active.problem.value = problem.value;
                if escalated {
                    changes.escalated.push(active.clone());
                }
                continue;
            }
            let looks = self.pending.entry(key.clone()).or_insert(0);
            *looks += 1;
            if *looks >= CONFIRM_LOOKS {
                self.pending.remove(key);
                let active = Active { problem: problem.clone(), since: at, worst: problem.level.clone() };
                self.active.insert(key.clone(), active.clone());
                changes.fired.push(active);
            }
        }
        // A server that is offline says nothing about its tunnels: their problems are not over,
        // only unseen, and stay until the server reports again.
        let unseen: std::collections::HashSet<&str> = seen
            .values()
            .filter(|p| p.kind == "offline")
            .map(|p| p.server.as_str())
            .chain(unseen.iter().map(String::as_str))
            .collect();
        let gone: Vec<String> = self
            .active
            .iter()
            .filter(|(k, a)| !seen.contains_key(*k) && !(a.problem.kind != "offline" && unseen.contains(a.problem.server.as_str())))
            .map(|(k, _)| k.clone())
            .collect();
        for key in gone {
            if let Some(mut active) = self.active.remove(&key) {
                let lasted = at.saturating_sub(active.since);
                if active.worst == "bad" {
                    active.problem.level = "bad".into();
                }
                changes.cleared.push((active, lasted));
            }
        }
        changes
    }

    pub fn active(&self) -> Vec<Active> {
        let mut list: Vec<Active> = self.active.values().cloned().collect();
        list.sort_by_key(|a| (a.problem.level != "bad", std::cmp::Reverse(a.since)));
        list
    }
}

pub fn history_path(state_dir: &Path) -> PathBuf {
    state_dir.join(HISTORY_FILE)
}

/// Adds the look's changes to the history file (newest last).
pub fn record(state_dir: &Path, changes: &Changes, at: u64) -> Result<()> {
    if changes.fired.is_empty() && changes.escalated.is_empty() && changes.cleared.is_empty() {
        return Ok(());
    }
    let path = history_path(state_dir);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_HISTORY_BYTES) {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, lines[lines.len() / 2..].join("\n") + "\n")?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).context("open the alert history")?;
    for active in &changes.fired {
        writeln!(file, "{}", json!({"at": at, "state": "fired", "problem": active.problem}))?;
    }
    for active in &changes.escalated {
        writeln!(file, "{}", json!({"at": at, "state": "escalated", "problem": active.problem}))?;
    }
    for (active, lasted) in &changes.cleared {
        writeln!(file, "{}", json!({"at": at, "state": "cleared", "since": active.since, "lasted": lasted, "problem": active.problem}))?;
    }
    Ok(())
}

/// The newest `limit` history entries, newest first.
pub fn history(state_dir: &Path, limit: usize) -> Vec<Value> {
    let text = std::fs::read_to_string(history_path(state_dir)).unwrap_or_default();
    text.lines().rev().filter_map(|line| serde_json::from_str(line).ok()).take(limit).collect()
}

fn words(lang: &str, kind: &str) -> &'static str {
    let fa = lang == "fa";
    match kind {
        "failed" => if fa { "تونل با خطا متوقف شد" } else { "tunnel failed" },
        "not_connected" => if fa { "تونل وصل نیست" } else { "tunnel not connected" },
        "silent" => if fa { "از سر دیگر چیزی نمی‌رسد" } else { "nothing arrives from the other end" },
        "no_traffic" => if fa { "هارت‌بیت‌ها بی‌پاسخ مانده‌اند" } else { "heartbeats get no answer" },
        "quota" => if fa { "سقف ترافیک پر شد" } else { "traffic limit used up" },
        "loss" => if fa { "افت بسته بالاست" } else { "high packet loss" },
        "udp_drops" => if fa { "بسته‌های UDP دور ریخته می‌شوند" } else { "UDP datagrams are being dropped" },
        "failover_backup" => if fa { "تونل روی ترنسپورت پشتیبان کار می‌کند" } else { "tunnel runs on a backup carrier" },
        "carrier_down" => if fa { "یکی از ترنسپورت‌های فیل‌اور از کار افتاده" } else { "a failover carrier is down" },
        "offline" => if fa { "سرور از داشبورد قطع است" } else { "server is offline" },
        "disk" => if fa { "دیسک تقریباً پر است" } else { "disk almost full" },
        "cert" => if fa { "اعتبار سرتیفیکیت داشبورد به‌زودی تمام می‌شود" } else { "dashboard certificate expires soon" },
        _ => if fa { "مشکل" } else { "problem" },
    }
}

/// Text for Telegram's HTML mode: names and tunnels may hold `<`, `>` or `&`.
fn html(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Persian digits for the Persian messages.
fn digits(lang: &str, text: String) -> String {
    if lang != "fa" {
        return text;
    }
    text.chars().map(|c| c.to_digit(10).and_then(|d| char::from_u32(0x06F0 + d)).unwrap_or(c)).collect()
}

/// Problems that belong to one tunnel; the others are about the whole server.
fn about_tunnel(kind: &str) -> bool {
    matches!(kind, "failed" | "not_connected" | "silent" | "no_traffic" | "quota" | "loss" | "udp_drops" | "failover_backup" | "carrier_down")
}

/// The Telegram message for an alert that fired or cleared (HTML mode): a coloured mark and the
/// state on the first line, then where it is, then the figure when there is one.
pub fn message(lang: &str, problem: &Problem, cleared: Option<u64>) -> String {
    let fa = lang == "fa";
    let what = words(lang, &problem.kind);
    let head = match (cleared, problem.level.as_str(), fa) {
        (Some(lasted), _, false) => format!("🟢 <b>Resolved</b> · {what}\n⏱ Lasted {} min", lasted.div_ceil(60)),
        (Some(lasted), _, true) => format!("🟢 <b>برطرف شد</b> · {what}\n⏱ مدت: {} دقیقه", digits(lang, lasted.div_ceil(60).to_string())),
        (None, "bad", false) => format!("🔴 <b>Problem</b> · {what}"),
        (None, _, false) => format!("🟠 <b>Warning</b> · {what}"),
        (None, "bad", true) => format!("🔴 <b>مشکل</b> · {what}"),
        (None, _, true) => format!("🟠 <b>هشدار</b> · {what}"),
    };
    let mut lines = vec![head, format!("🖥 {} <b>{}</b>", if fa { "سرور:" } else { "Server:" }, html(&problem.server_name))];
    if !problem.subject.is_empty() {
        let label = match (about_tunnel(&problem.kind), fa) {
            (true, false) => "Tunnel:",
            (true, true) => "تونل:",
            (false, false) => "About:",
            (false, true) => "مورد:",
        };
        lines.push(format!("🔗 {label} <code>{}</code>", html(&problem.subject)));
    }
    if cleared.is_none() {
        match (problem.kind.as_str(), problem.value) {
            ("loss", Some(v)) => lines.push(format!("📉 {} {}%", if fa { "افت بسته:" } else { "Packet loss:" }, digits(lang, format!("{v:.1}")))),
            ("disk", Some(v)) => lines.push(format!("💾 {} {}%", if fa { "دیسک پر:" } else { "Disk used:" }, digits(lang, format!("{v:.0}")))),
            _ => {}
        }
    }
    lines.push(if fa { "<i>داشبورد EZTunnel</i>".into() } else { "<i>EZTunnel dashboard</i>".into() });
    lines.join("\n")
}

/// The message **Send test message** sends.
pub fn test_message(lang: &str) -> String {
    if lang == "fa" {
        "✅ <b>اتصال به تلگرام برقرار است</b>\nاز این پس هشدارهای داشبورد در این چت می‌رسد.\n🔴 مشکل · 🟠 هشدار · 🟢 برطرف شد\n<i>داشبورد EZTunnel</i>".into()
    } else {
        "✅ <b>Telegram is connected</b>\nAlerts from the dashboard will arrive in this chat.\n🔴 Problem · 🟠 Warning · 🟢 Resolved\n<i>EZTunnel dashboard</i>".into()
    }
}

/// Sends a Telegram message to every chat. The token goes to curl on its standard input, so it
/// never shows in the process list. A refusal reports Telegram's own reason (a wrong chat id, a
/// bot that was never started in the chat).
pub fn send_telegram(telegram: &Telegram, proxy: Option<&str>, text: &str) -> Result<()> {
    ensure!(!telegram.token.is_empty() && !telegram.chats.is_empty(), "Telegram needs a bot token and a chat id");
    let mut failures = Vec::new();
    for chat in &telegram.chats {
        let config = format!(
            "url = \"https://api.telegram.org/bot{}/sendMessage\"\ndata-urlencode = \"text={}\"\ndata = \"chat_id={chat}\"\ndata = \"parse_mode=HTML\"\ndata = \"disable_web_page_preview=true\"\n",
            telegram.token,
            text.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
        );
        let mut command = Command::new("curl");
        command.args(["--silent", "--show-error", "--proto", "=https", "--max-time", "20", "--write-out", "\n%{http_code}", "--config", "-"]);
        if let Some(proxy) = proxy.filter(|p| !p.is_empty()) {
            command.args(["--proxy", proxy]);
        }
        let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().context("run curl")?;
        child.stdin.take().context("curl input")?.write_all(config.as_bytes())?;
        let output = child.wait_with_output()?;
        let body = String::from_utf8_lossy(&output.stdout);
        let (answer, code) = body.rsplit_once('\n').unwrap_or(("", &body));
        if !output.status.success() || code.trim() != "200" {
            // curl prints the URL in some errors; the token must not reach the logs.
            let detail = telegram_refusal(answer)
                .unwrap_or_else(|| String::from_utf8_lossy(&output.stderr).trim().to_string())
                .replace(&telegram.token, "<token>");
            let detail = if detail.is_empty() { format!("HTTP {}", code.trim()) } else { detail };
            failures.push(format!("chat {chat}: {detail}"));
        }
    }
    ensure!(failures.is_empty(), "{}", failures.join("; "));
    Ok(())
}

const DELIVERY_FILE: &str = "telegram-last.json";

/// Keeps the outcome of the latest Telegram send (a test or an alert) for the Settings screen.
pub fn record_delivery(state_dir: &std::path::Path, kind: &str, result: &Result<()>) {
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let record = json!({"at": at, "kind": kind, "ok": result.is_ok(), "detail": result.as_ref().err().map(|e| format!("{e:#}"))});
    let _ = std::fs::write(state_dir.join(DELIVERY_FILE), record.to_string());
}

/// The latest Telegram send (a test or an alert), if there was one.
pub fn last_delivery(state_dir: &std::path::Path) -> Value {
    std::fs::read(state_dir.join(DELIVERY_FILE)).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or(Value::Null)
}

/// Telegram's reason in a refused request (`{"ok":false,"description":"Bad Request: chat not found"}`).
fn telegram_refusal(answer: &str) -> Option<String> {
    let value: Value = serde_json::from_str(answer.trim()).ok()?;
    value["description"].as_str().map(|d| format!("Telegram says: {d}"))
}

/// Whether Telegram gets this change, by the chosen level.
pub fn wanted(prefs: &Prefs, problem: &Problem, cleared: bool) -> bool {
    let t = &prefs.telegram;
    t.enabled && (t.level == "all" || problem.level == "bad") && (!cleared || t.resolved)
}

/// Metrics for an external monitor (Prometheus text format), from the latest snapshots.
pub fn metrics(servers: &[(String, String, Value)], active: usize) -> String {
    let mut out = String::new();
    let label = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    out.push_str("# TYPE eztunnel_alerts_active gauge\n");
    out.push_str(&format!("eztunnel_alerts_active {active}\n"));
    let gauges: [(&str, &str); 7] = [
        ("eztunnel_tunnel_up", "state"),
        ("eztunnel_tunnel_sessions", "sessions"),
        ("eztunnel_tunnel_rtt_ms", "rtt_ms"),
        ("eztunnel_tunnel_loss_percent", "loss_pct"),
        ("eztunnel_tunnel_down_bytes_per_second", "down_bps"),
        ("eztunnel_tunnel_up_bytes_per_second", "up_bps"),
        ("eztunnel_tunnel_received_bytes_total", "down_total"),
    ];
    for (metric, field) in gauges {
        out.push_str(&format!("# TYPE {metric} gauge\n"));
        for (id, name, snapshot) in servers {
            for tunnel in snapshot["tunnels"].as_array().into_iter().flatten() {
                let value = if field == "state" {
                    Some(if tunnel["state"] == "running" { 1.0 } else { 0.0 })
                } else {
                    tunnel[field].as_f64()
                };
                if let Some(value) = value {
                    out.push_str(&format!(
                        "{metric}{{server=\"{}\",server_name=\"{}\",tunnel=\"{}\"}} {value}\n",
                        label(id),
                        label(name),
                        label(tunnel["name"].as_str().unwrap_or(""))
                    ));
                }
            }
        }
    }
    out.push_str("# TYPE eztunnel_host_cpu_percent gauge\n");
    for (id, name, snapshot) in servers {
        if let Some(cpu) = snapshot["host"]["cpu_pct"].as_f64() {
            out.push_str(&format!("eztunnel_host_cpu_percent{{server=\"{}\",server_name=\"{}\"}} {cpu}\n", label(id), label(name)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent that disconnects does not resolve its tunnels' problems; they end only when the
    /// server reports again without them.
    #[test]
    fn an_offline_server_keeps_its_tunnel_problems() {
        let mut engine = Engine::default();
        let failed = Problem::new("a1", "nl", "failed", "game", "bad", None);
        for at in [0, 30, 60] {
            engine.look(vec![failed.clone()], at);
        }
        assert_eq!(engine.active().len(), 1);
        let offline = Problem::new("a1", "nl", "offline", "", "bad", None);
        let changed = engine.look(vec![offline.clone()], 90);
        assert!(changed.cleared.is_empty(), "nothing was resolved");
        // Back online, still failed: no new alert either.
        let changed = engine.look(vec![failed.clone()], 120);
        assert!(changed.cleared.iter().all(|(a, _)| a.problem.kind == "offline") && changed.fired.is_empty());
        // Connected again but no report yet: still not resolved.
        engine.look(vec![offline.clone()], 125);
        let changed = engine.look_with(vec![], 130, &["a1".to_string()]);
        assert!(changed.cleared.iter().all(|(a, _)| a.problem.kind != "failed"), "unknown is not fixed");
        // Back online and fixed: now it is resolved.
        let changed = engine.look(vec![], 150);
        assert!(changed.cleared.iter().any(|(a, _)| a.problem.kind == "failed"));
    }

    /// bad -> warn -> clear: the recovery of an alert that was bad is sent at the bad level.
    #[test]
    fn a_recovery_is_sent_to_whoever_heard_the_bad_level() {
        let mut engine = Engine::default();
        let bad = Problem::new("local", "server", "disk", "", "bad", Some(98.0));
        for at in [0, 30, 60] {
            engine.look(vec![bad.clone()], at);
        }
        let warn = Problem::new("local", "server", "disk", "", "warn", Some(94.0));
        engine.look(vec![warn], 90);
        let changed = engine.look(vec![], 120);
        assert_eq!(changed.cleared.len(), 1);
        assert_eq!(changed.cleared[0].0.problem.level, "bad");
        let mut prefs = Prefs::default();
        prefs.telegram.enabled = true;
        prefs.telegram.level = "bad".into();
        prefs.telegram.resolved = true;
        assert!(wanted(&prefs, &changed.cleared[0].0.problem, true));
    }

    #[test]
    fn an_active_warning_escalates_once_without_resetting_its_age() {
        let mut engine = Engine::default();
        let warning = Problem::new("local", "server", "disk", "", "warn", Some(90.0));
        engine.look(vec![warning.clone()], 100);
        engine.look(vec![warning], 130);
        let bad = Problem::new("local", "server", "disk", "", "bad", Some(97.0));
        let changed = engine.look(vec![bad.clone()], 160);
        assert_eq!(changed.escalated.len(), 1);
        assert_eq!(changed.escalated[0].since, 130);
        assert!(changed.fired.is_empty());
        assert!(engine.look(vec![bad], 190).escalated.is_empty());
        let mut prefs = Prefs::default();
        prefs.telegram.enabled = true;
        assert!(wanted(&prefs, &changed.escalated[0].problem, false));
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), &changed, 160).unwrap();
        assert_eq!(history(dir.path(), 1)[0]["state"], "escalated");
    }

    fn problem(kind: &str) -> Problem {
        Problem::new("local", "tehran-1", kind, "game", "bad", None)
    }

    #[test]
    fn a_problem_fires_on_the_second_look_and_clears_when_gone() {
        let mut engine = Engine::default();
        assert!(engine.look(vec![problem("failed")], 100).fired.is_empty(), "one look is not enough");
        let second = engine.look(vec![problem("failed")], 130);
        assert_eq!(second.fired.len(), 1);
        assert_eq!(engine.active().len(), 1);
        assert!(engine.look(vec![problem("failed")], 160).fired.is_empty(), "fires once");
        let cleared = engine.look(vec![], 400);
        assert_eq!(cleared.cleared.len(), 1);
        assert_eq!(cleared.cleared[0].1, 270);
        assert!(engine.active().is_empty());
        // A flicker that is gone by the next look never fires.
        engine.look(vec![problem("loss")], 500);
        assert!(engine.look(vec![], 530).fired.is_empty());
        assert!(engine.look(vec![problem("loss")], 560).fired.is_empty());
    }

    #[test]
    fn history_is_kept_newest_first_and_messages_name_the_place() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::default();
        engine.look(vec![problem("failed")], 1);
        record(dir.path(), &engine.look(vec![problem("failed")], 31), 31).unwrap();
        record(dir.path(), &engine.look(vec![], 91), 91).unwrap();
        let list = history(dir.path(), 10);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["state"], "cleared");
        assert_eq!(list[1]["problem"]["kind"], "failed");
        let text = message("en", &problem("failed"), None);
        assert!(text.starts_with("🔴 <b>Problem</b> · tunnel failed"), "{text}");
        assert!(text.contains("<b>tehran-1</b>") && text.contains("Tunnel: <code>game</code>"), "{text}");
        let fa = message("fa", &problem("failed"), Some(61));
        assert!(fa.starts_with("🟢 <b>برطرف شد</b>") && fa.contains("۲ دقیقه"), "{fa}");
        let mut named = problem("disk");
        named.server_name = "vps1136".into();
        named.value = Some(95.0);
        let fa = message("fa", &named, None);
        assert!(fa.contains("<b>vps1136</b>") && fa.contains("۹۵%"), "{fa}");
        let mut odd = problem("loss");
        odd.subject = "a<b>&c".into();
        odd.level = "warn".into();
        odd.value = Some(12.34);
        let text = message("en", &odd, None);
        assert!(text.starts_with("🟠") && text.contains("a&lt;b&gt;&amp;c") && text.contains("12.3%"), "{text}");
        assert_eq!(telegram_refusal(r#"{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}"#).unwrap(), "Telegram says: Bad Request: chat not found");
        assert!(test_message("fa").starts_with("✅") && test_message("en").contains("Telegram is connected"));
        let snapshot = json!({"issues": [{"kind": "not_connected", "level": "bad", "tunnel": "web", "value": null}], "host": {"disk_pct": 95.0}});
        let found = problems_of("a1", "frankfurt", &snapshot);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].key, "a1:not_connected:web");
        let text = metrics(&[("local".into(), "tehran-1".into(), json!({"tunnels": [{"name": "game", "state": "running", "sessions": 4.0}], "host": {"cpu_pct": 12.5}}))], 1);
        assert!(text.contains("eztunnel_tunnel_up{server=\"local\",server_name=\"tehran-1\",tunnel=\"game\"} 1"), "{text}");
        assert!(text.contains("eztunnel_host_cpu_percent{server=\"local\",server_name=\"tehran-1\"} 12.5"));
    }
}
