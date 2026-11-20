//! The dashboard's own preferences, changed from its Settings screen: automatic backups, the
//! proxy for downloads and Telegram, alert delivery and the metrics endpoint. Kept in the state
//! folder (mode 0600); the bot token and the metrics token never leave the server once saved.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Mutex;

const FILE: &str = "prefs.json";
static SAVE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Prefs {
    /// Back up every server when the newest backup is this many days old; 0 = never.
    pub auto_backup_days: u64,
    /// Proxy for release downloads and Telegram, such as `socks5h://127.0.0.1:1080` (a SOCKS5
    /// tunnel on this server can reach what this server cannot).
    pub proxy: Option<String>,
    pub telegram: Telegram,
    /// Bearer token for `/metrics`; `None` keeps the endpoint off.
    pub metrics_token: Option<String>,
    /// Display name of this server on the dashboard; `None` shows its hostname.
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Telegram {
    pub enabled: bool,
    pub token: String,
    /// Chat ids that receive alerts.
    pub chats: Vec<i64>,
    /// "en" or "fa".
    pub lang: String,
    /// Which alerts are sent: "bad" (problems only) or "all" (warnings too).
    pub level: String,
    /// Also send a message when an alert clears.
    pub resolved: bool,
}

impl Default for Telegram {
    fn default() -> Self {
        Self { enabled: false, token: String::new(), chats: Vec::new(), lang: "en".into(), level: "bad".into(), resolved: true }
    }
}

impl Default for Prefs {
    fn default() -> Self {
        Self { auto_backup_days: 7, proxy: None, telegram: Telegram::default(), metrics_token: None, server_name: None }
    }
}

pub fn load(state_dir: &Path) -> Prefs {
    std::fs::read(state_dir.join(FILE)).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
}

pub fn save(state_dir: &Path, prefs: &Prefs) -> Result<()> {
    let _lock = SAVE_LOCK.lock().unwrap();
    save_locked(state_dir, prefs)
}

fn save_locked(state_dir: &Path, prefs: &Prefs) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join(FILE);
    let temporary = state_dir.join(".prefs.json.new");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&temporary)?.write_all(serde_json::to_string_pretty(prefs)?.as_bytes())?;
    std::fs::rename(&temporary, &path).context("save the preferences")
}

/// Atomically applies one read-modify-write preference update.
pub fn change_and_save<F>(state_dir: &Path, change: F) -> Result<(Prefs, Option<String>)>
where
    F: FnOnce(&mut Prefs) -> Result<Option<String>>,
{
    let _lock = SAVE_LOCK.lock().unwrap();
    let mut prefs = load(state_dir);
    let created = change(&mut prefs)?;
    save_locked(state_dir, &prefs)?;
    Ok((prefs, created))
}

/// What the Settings screen shows: secrets only as "set" or not.
pub fn shown(prefs: &Prefs) -> Value {
    json!({
        "auto_backup_days": prefs.auto_backup_days,
        "proxy": prefs.proxy,
        "telegram": {
            "enabled": prefs.telegram.enabled, "token_set": !prefs.telegram.token.is_empty(),
            // The bot's id (before the colon) is public; the secret after it never leaves.
            "bot_id": prefs.telegram.token.split_once(':').map(|(id, _)| id),
            "chats": prefs.telegram.chats, "lang": prefs.telegram.lang, "level": prefs.telegram.level, "resolved": prefs.telegram.resolved,
        },
        "metrics": prefs.metrics_token.is_some(),
    })
}

fn proxy_ok(text: &str) -> bool {
    let rest = ["http://", "https://", "socks5://", "socks5h://"].iter().find_map(|scheme| text.strip_prefix(scheme));
    rest.is_some_and(|rest| !rest.is_empty() && rest.len() < 200 && !rest.contains(char::is_whitespace))
}

/// Applies a change from the Settings screen. A token of `null` keeps the saved one, `""` clears
/// it. `metrics` true creates a token (returned once), false removes it.
pub fn change(prefs: &mut Prefs, change: &Value) -> Result<Option<String>> {
    if let Some(days) = change.get("auto_backup_days").filter(|v| !v.is_null()) {
        let days = days.as_u64().filter(|d| *d <= 365).context("automatic backups: 0 (off) to 365 days")?;
        prefs.auto_backup_days = days;
    }
    if let Some(proxy) = change.get("proxy") {
        prefs.proxy = match proxy.as_str().map(str::trim) {
            None | Some("") => None,
            Some(text) => {
                ensure!(proxy_ok(text), "the proxy looks like socks5h://127.0.0.1:1080 or http://host:port");
                Some(text.to_string())
            }
        };
    }
    if let Some(telegram) = change.get("telegram").filter(|v| v.is_object()) {
        if let Some(enabled) = telegram["enabled"].as_bool() {
            prefs.telegram.enabled = enabled;
        }
        if let Some(token) = telegram["token"].as_str() {
            let token = token.trim();
            ensure!(
                token.is_empty() || (token.len() < 100 && token.split_once(':').is_some_and(|(id, secret)| id.bytes().all(|b| b.is_ascii_digit()) && !secret.is_empty() && secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))),
                "a bot token looks like 123456789:ABC..."
            );
            prefs.telegram.token = token.to_string();
        }
        if let Some(chats) = telegram.get("chats").filter(|v| !v.is_null()) {
            let list = chats.as_array().context("chats is a list")?;
            ensure!(list.len() <= 10, "up to 10 chats");
            prefs.telegram.chats = list.iter().map(|c| c.as_i64().context("a chat id is a number")).collect::<Result<_>>()?;
        }
        if let Some(lang) = telegram["lang"].as_str() {
            ensure!(lang == "en" || lang == "fa", "the language is en or fa");
            prefs.telegram.lang = lang.into();
        }
        if let Some(level) = telegram["level"].as_str() {
            ensure!(level == "bad" || level == "all", "the level is bad or all");
            prefs.telegram.level = level.into();
        }
        if let Some(resolved) = telegram["resolved"].as_bool() {
            prefs.telegram.resolved = resolved;
        }
        ensure!(!prefs.telegram.enabled || (!prefs.telegram.token.is_empty() && !prefs.telegram.chats.is_empty()), "Telegram needs a bot token and at least one chat id");
    }
    let mut created = None;
    if let Some(metrics) = change["metrics"].as_bool() {
        if metrics && prefs.metrics_token.is_none() {
            let mut random = [0u8; 24];
            crate::stealth::random_bytes(&mut random)?;
            let token = hex::encode(random);
            prefs.metrics_token = Some(token.clone());
            created = Some(token);
        } else if !metrics {
            prefs.metrics_token = None;
        }
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_partial_changes_preserve_both_updates() {
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            let path = dir.path();
            scope.spawn(move || change_and_save(path, |prefs| change(prefs, &json!({"auto_backup_days": 3}))).unwrap());
            scope.spawn(move || change_and_save(path, |prefs| change(prefs, &json!({"proxy": "http://localhost:1080"}))).unwrap());
        });
        let prefs = load(dir.path());
        assert_eq!(prefs.auto_backup_days, 3);
        assert_eq!(prefs.proxy.as_deref(), Some("http://localhost:1080"));
    }

    #[test]
    fn preferences_are_checked_saved_and_shown_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let mut prefs = load(dir.path());
        assert_eq!(prefs, Prefs::default());
        change(&mut prefs, &json!({"auto_backup_days": 3, "proxy": "socks5h://127.0.0.1:1080",
            "telegram": {"enabled": true, "token": "123456:abc_DEF-1", "chats": [42, -1001], "lang": "fa"}})).unwrap();
        let token = change(&mut prefs, &json!({"metrics": true})).unwrap().unwrap();
        assert_eq!(token.len(), 48);
        save(dir.path(), &prefs).unwrap();
        let back = load(dir.path());
        assert_eq!(back, prefs);
        let shown = shown(&back).to_string();
        assert!(!shown.contains("abc_DEF") && !shown.contains(&token), "{shown}");
        // A missing token keeps the saved one; bad values are refused.
        change(&mut prefs, &json!({"telegram": {"lang": "en"}})).unwrap();
        assert_eq!(prefs.telegram.token, "123456:abc_DEF-1");
        for bad in [
            json!({"auto_backup_days": 1000}),
            json!({"proxy": "ftp://x"}),
            json!({"telegram": {"token": "not a token"}}),
            json!({"telegram": {"chats": ["x"]}}),
            json!({"telegram": {"enabled": true, "token": "", "chats": []}}),
            json!({"telegram": {"lang": "de"}}),
        ] {
            let mut copy = prefs.clone();
            assert!(change(&mut copy, &bad).is_err(), "{bad}");
        }
        change(&mut prefs, &json!({"metrics": false, "proxy": ""})).unwrap();
        assert!(prefs.metrics_token.is_none() && prefs.proxy.is_none());
    }
}
