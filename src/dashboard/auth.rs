//! Sign-in: the password hash, signed-in sessions and the limits on wrong passwords.
use anyhow::{Result, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::Mutex,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

/// A session ends after this long without a request.
const IDLE: Duration = Duration::from_secs(12 * 3600);
/// And in any case after this long.
const LIFETIME: Duration = Duration::from_secs(7 * 24 * 3600);
/// The oldest session is ended when one more would exceed this.
const MAX_SESSIONS: usize = 64;

/// Wrong passwords from one address inside `WINDOW` before it is locked out.
const FAILURES_BEFORE_LOCK: usize = 5;
const WINDOW: Duration = Duration::from_secs(15 * 60);
/// The first lockout; each further one doubles, up to `MAX_LOCK`.
const FIRST_LOCK: Duration = Duration::from_secs(5 * 60);
const MAX_LOCK: Duration = Duration::from_secs(24 * 3600);
/// Wrong passwords from all addresses together within a minute before every sign-in pauses.
const GLOBAL_FAILURES: usize = 30;
const GLOBAL_PAUSE: Duration = Duration::from_secs(60);
/// Addresses remembered by the limiter before old entries are dropped.
const MAX_TRACKED: usize = 10_000;
pub const MAX_PASSWORD_BYTES: usize = 256;

pub fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    super::random_bytes(&mut salt)?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow!("salt: {e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("hash the password: {e}"))?
        .to_string())
}

fn password_matches(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash)
        .is_ok_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

fn token_key(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

struct Session {
    created: Instant,
    last_seen: Instant,
    /// Where it signed in from.
    ip: Option<IpAddr>,
}

#[derive(Default)]
struct Tracked {
    failures: VecDeque<Instant>,
    lockouts: u32,
    locked_until: Option<Instant>,
    last_seen: Option<Instant>,
}

#[derive(Default)]
struct Limiter {
    addresses: HashMap<IpAddr, Tracked>,
    recent: VecDeque<Instant>,
    paused_until: Option<Instant>,
}

impl Limiter {
    /// Seconds to wait before this address may try again, if it must wait.
    fn wait(&self, ip: IpAddr, now: Instant) -> Option<u64> {
        let until = [
            self.paused_until,
            self.addresses.get(&ip).and_then(|t| t.locked_until),
        ]
        .into_iter()
        .flatten()
        .filter(|until| *until > now)
        .max()?;
        Some((until - now).as_secs().max(1))
    }

    fn failed(&mut self, ip: IpAddr, now: Instant) {
        if self.addresses.len() >= MAX_TRACKED && !self.addresses.contains_key(&ip) {
            self.addresses
                .retain(|_, t| t.locked_until.is_some_and(|u| u > now) || t.last_seen.is_some_and(|s| now - s < WINDOW));
        }
        let tracked = self.addresses.entry(ip).or_default();
        tracked.last_seen = Some(now);
        tracked.failures.retain(|at| now - *at < WINDOW);
        tracked.failures.push_back(now);
        if tracked.failures.len() >= FAILURES_BEFORE_LOCK {
            let lock = FIRST_LOCK
                .saturating_mul(1 << tracked.lockouts.min(16))
                .min(MAX_LOCK);
            tracked.locked_until = Some(now + lock);
            tracked.lockouts += 1;
            tracked.failures.clear();
        }
        self.recent.retain(|at| now - *at < Duration::from_secs(60));
        self.recent.push_back(now);
        if self.recent.len() >= GLOBAL_FAILURES {
            self.paused_until = Some(now + GLOBAL_PAUSE);
            self.recent.clear();
        }
    }

    fn succeeded(&mut self, ip: IpAddr) {
        self.addresses.remove(&ip);
    }
}

pub enum Login {
    /// The new session token for the cookie.
    Ok(String),
    Wrong,
    /// Try again after this many seconds.
    Wait(u64),
}

pub struct Auth {
    hash: Mutex<String>,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    limiter: Mutex<Limiter>,
    /// Serializes password transitions with session creation.
    transition: tokio::sync::Mutex<()>,
    generation: AtomicU64,
    /// Password checks are slow on purpose; only a few run at once.
    checks: Semaphore,
}

impl Auth {
    pub fn new(hash: String) -> Self {
        Self {
            hash: Mutex::new(hash),
            sessions: Mutex::new(HashMap::new()),
            limiter: Mutex::new(Limiter::default()),
            transition: tokio::sync::Mutex::new(()),
            generation: AtomicU64::new(0),
            checks: Semaphore::new(2),
        }
    }

    pub async fn login(&self, ip: IpAddr, password: String) -> Result<Login> {
        if let Some(seconds) = self.limiter.lock().unwrap().wait(ip, Instant::now()) {
            return Ok(Login::Wait(seconds));
        }
        let generation = self.generation.load(Ordering::Acquire);
        let matches = {
            // Lock order: a check slot is never held while waiting for `transition` (a password
            // change holds `transition` while it waits for a slot). The lockout is looked at again
            // once the slot is ours, and once more in `finish_login` before any session is made,
            // so attempts that queued while the address got locked out cannot sign in.
            let _permit = self.checks.acquire().await?;
            if let Some(seconds) = self.limiter.lock().unwrap().wait(ip, Instant::now()) {
                return Ok(Login::Wait(seconds));
            }
            let hash = self.hash.lock().unwrap().clone();
            tokio::task::spawn_blocking(move || password_matches(&hash, &password)).await?
        };
        self.finish_login(ip, matches, generation).await
    }

    async fn finish_login(&self, ip: IpAddr, matches: bool, generation: u64) -> Result<Login> {
        let _transition = self.transition.lock().await;
        if generation != self.generation.load(Ordering::Acquire) {
            return Ok(Login::Wrong);
        }
        let mut limiter = self.limiter.lock().unwrap();
        // Locked out while this attempt was checked (by the other slot): no session either way.
        if let Some(seconds) = limiter.wait(ip, Instant::now()) {
            return Ok(Login::Wait(seconds));
        }
        if !matches {
            limiter.failed(ip, Instant::now());
            return Ok(Login::Wrong);
        }
        limiter.succeeded(ip);
        drop(limiter);
        let mut bytes = [0u8; 32];
        super::random_bytes(&mut bytes)?;
        use base64::Engine;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| alive(s, now));
        if sessions.len() >= MAX_SESSIONS
            && let Some(oldest) = sessions.iter().min_by_key(|(_, s)| s.created).map(|(k, _)| *k)
        {
            sessions.remove(&oldest);
        }
        sessions.insert(
            token_key(&token),
            Session {
                created: now,
                last_seen: now,
                ip: Some(ip),
            },
        );
        Ok(Login::Ok(token))
    }

    /// Whether the token belongs to a live session; a valid one counts as activity.
    pub fn check(&self, token: &str) -> bool {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap();
        let key = token_key(token);
        match sessions.get_mut(&key) {
            Some(session) if alive(session, now) => {
                session.last_seen = now;
                true
            }
            Some(_) => {
                sessions.remove(&key);
                false
            }
            None => false,
        }
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap().remove(&token_key(token));
    }

    /// The signed-in sessions: a short id, where from, age and idle time; `current` marks the
    /// one asking.
    pub fn sessions(&self, current: &str) -> Vec<serde_json::Value> {
        let now = Instant::now();
        let mine = token_key(current);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| alive(s, now));
        let mut list: Vec<(Instant, serde_json::Value)> = sessions
            .iter()
            .map(|(key, s)| {
                (s.created, serde_json::json!({
                    "id": session_id(key),
                    "ip": s.ip.map(|ip| ip.to_string()),
                    "age_sec": (now - s.created).as_secs(),
                    "idle_sec": (now - s.last_seen).as_secs(),
                    "current": *key == mine,
                }))
            })
            .collect();
        list.sort_by_key(|(created, _)| std::cmp::Reverse(*created));
        list.into_iter().map(|(_, v)| v).collect()
    }

    /// Ends one session by its id, or every session but `current` with `"others"`. Returns how
    /// many ended.
    pub fn revoke(&self, id: &str, current: &str) -> usize {
        let mine = token_key(current);
        let mut sessions = self.sessions.lock().unwrap();
        let before = sessions.len();
        sessions.retain(|key, _| if id == "others" { *key == mine } else { session_id(key) != id || *key == mine });
        before - sessions.len()
    }

    /// Changes the password after checking the current one, ends every other session, and
    /// returns the new hash for saving.
    pub async fn change_password(&self, current_token: &str, current: String, new: String) -> Result<String> {
        anyhow::ensure!(new.chars().count() >= 12, "the new password needs at least 12 characters");
        anyhow::ensure!(new.len() <= MAX_PASSWORD_BYTES, "the new password is too long");
        let _transition = self.transition.lock().await;
        anyhow::ensure!(self.check(current_token), "the session ended; sign in again");
        let matches = {
            let _permit = self.checks.acquire().await?;
            let hash = self.hash.lock().unwrap().clone();
            tokio::task::spawn_blocking(move || password_matches(&hash, &current)).await?
        };
        anyhow::ensure!(matches, "the current password is wrong");
        let hash = tokio::task::spawn_blocking(move || hash_password(&new)).await??;
        *self.hash.lock().unwrap() = hash.clone();
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.revoke("others", current_token);
        Ok(hash)
    }
}

/// A session's short public id: never enough to sign in with.
fn session_id(key: &[u8; 32]) -> String {
    key[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn alive(session: &Session, now: Instant) -> bool {
    now - session.last_seen < IDLE && now - session.created < LIFETIME
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([198, 51, 100, last])
    }

    /// Attempts that queued for a password check while the address got locked out are refused
    /// when their turn comes, a correct password included: no session after the lockout.
    #[tokio::test]
    async fn queued_attempts_respect_a_lockout_reached_while_they_waited() {
        let auth = std::sync::Arc::new(Auth::new(hash_password("right one").unwrap()));
        // Both check slots busy: the attempts below pass the first look and queue.
        let held = auth.checks.acquire_many(2).await.unwrap();
        let queued: Vec<_> = ["wrong", "right one"]
            .into_iter()
            .map(|password| {
                let auth = auth.clone();
                tokio::spawn(async move { auth.login(ip(7), password.into()).await.unwrap() })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(100)).await;
        {
            let mut limiter = auth.limiter.lock().unwrap();
            for _ in 0..FAILURES_BEFORE_LOCK {
                limiter.failed(ip(7), Instant::now());
            }
        }
        drop(held);
        for attempt in queued {
            assert!(matches!(attempt.await.unwrap(), Login::Wait(_)));
        }
        assert!(auth.sessions.lock().unwrap().is_empty());
        // The lockout also holds at the last step, for an attempt already checked.
        assert!(matches!(auth.finish_login(ip(7), true, auth.generation.load(Ordering::Acquire)).await.unwrap(), Login::Wait(_)));
        assert!(auth.sessions.lock().unwrap().is_empty());
    }

    /// Logins that hold both check slots and a password change that holds the change lock must
    /// not wait on each other: everything finishes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn logins_and_a_password_change_at_once_never_deadlock() {
        let auth = std::sync::Arc::new(Auth::new(hash_password("old password 1").unwrap()));
        let Login::Ok(token) = auth.login(ip(1), "old password 1".into()).await.unwrap() else { panic!() };
        for round in 0..5 {
            let logins: Vec<_> = (0..2)
                .map(|n| {
                    let auth = auth.clone();
                    tokio::spawn(async move { auth.login(ip(20 + n), "wrong".into()).await })
                })
                .collect();
            // The change starts while the logins are checking (they hold both slots).
            tokio::task::yield_now().await;
            let change = {
                let (auth, token) = (auth.clone(), token.clone());
                let new = format!("new password {round:02}");
                tokio::spawn(async move { auth.change_password(&token, "wrong guess".into(), new).await })
            };
            let all = async {
                for login in logins {
                    login.await.unwrap().unwrap();
                }
                let _ = change.await.unwrap();
            };
            tokio::time::timeout(Duration::from_secs(30), all).await.expect("logins and the change finished");
        }
    }

    #[tokio::test]
    async fn a_login_checked_before_a_password_change_cannot_create_a_session() {
        let auth = Auth::new(hash_password("old password").unwrap());
        let generation = auth.generation.load(Ordering::Acquire);
        auth.generation.fetch_add(1, Ordering::AcqRel);
        assert!(matches!(auth.finish_login(ip(1), true, generation).await.unwrap(), Login::Wrong));
        assert!(auth.sessions.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn password_changes_use_the_login_byte_limit() {
        let auth = Auth::new(hash_password("old password").unwrap());
        let Login::Ok(token) = auth.login(ip(1), "old password".into()).await.unwrap() else { panic!() };
        assert!(auth.change_password(&token, "old password".into(), "\u{e9}".repeat(129)).await.is_err());
        let accepted = "\u{e9}".repeat(128);
        auth.change_password(&token, "old password".into(), accepted.clone()).await.unwrap();
        assert!(matches!(auth.login(ip(1), accepted).await.unwrap(), Login::Ok(_)));
    }

    #[test]
    fn the_hash_accepts_only_its_password() {
        let hash = hash_password("correct horse").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(password_matches(&hash, "correct horse"));
        assert!(!password_matches(&hash, "correct horsE"));
        assert!(!password_matches("not a hash", "x"));
    }

    #[test]
    fn five_wrong_passwords_lock_the_address_and_locks_grow() {
        let mut limiter = Limiter::default();
        let start = Instant::now();
        for _ in 0..4 {
            limiter.failed(ip(1), start);
        }
        assert!(limiter.wait(ip(1), start).is_none());
        limiter.failed(ip(1), start);
        assert_eq!(limiter.wait(ip(1), start), Some(FIRST_LOCK.as_secs()));
        assert!(limiter.wait(ip(2), start).is_none(), "other addresses are not locked");
        let later = start + FIRST_LOCK + Duration::from_secs(1);
        assert!(limiter.wait(ip(1), later).is_none());
        for _ in 0..5 {
            limiter.failed(ip(1), later);
        }
        assert_eq!(limiter.wait(ip(1), later), Some(2 * FIRST_LOCK.as_secs()));
    }

    #[test]
    fn a_success_clears_the_count() {
        let mut limiter = Limiter::default();
        let now = Instant::now();
        for _ in 0..4 {
            limiter.failed(ip(1), now);
        }
        limiter.succeeded(ip(1));
        limiter.failed(ip(1), now);
        assert!(limiter.wait(ip(1), now).is_none());
    }

    #[test]
    fn many_failures_from_many_addresses_pause_every_sign_in() {
        let mut limiter = Limiter::default();
        let now = Instant::now();
        for n in 0..GLOBAL_FAILURES {
            limiter.failed(ip(n as u8), now);
        }
        assert!(limiter.wait(ip(250), now).is_some());
        assert!(limiter.wait(ip(250), now + GLOBAL_PAUSE).is_none());
    }

    #[test]
    fn the_lock_never_exceeds_a_day() {
        let mut limiter = Limiter::default();
        let mut now = Instant::now();
        for _ in 0..40 {
            for _ in 0..5 {
                limiter.failed(ip(9), now);
            }
            let wait = limiter.wait(ip(9), now).unwrap();
            assert!(wait <= MAX_LOCK.as_secs());
            now += Duration::from_secs(wait + 1);
        }
    }

    #[tokio::test]
    async fn sessions_start_with_the_password_and_end_on_logout() {
        let auth = Auth::new(hash_password("pw").unwrap());
        assert!(matches!(auth.login(ip(1), "nope".into()).await.unwrap(), Login::Wrong));
        let Login::Ok(token) = auth.login(ip(1), "pw".into()).await.unwrap() else {
            panic!("the right password must sign in")
        };
        assert!(auth.check(&token));
        assert!(!auth.check("forged"));
        auth.logout(&token);
        assert!(!auth.check(&token));
    }

    #[tokio::test]
    async fn sessions_are_listed_revoked_and_ended_by_a_new_password() {
        let auth = Auth::new(hash_password("correct horse battery").unwrap());
        let Login::Ok(mine) = auth.login(ip(1), "correct horse battery".into()).await.unwrap() else { panic!() };
        let Login::Ok(other) = auth.login(ip(2), "correct horse battery".into()).await.unwrap() else { panic!() };
        let list = auth.sessions(&mine);
        assert_eq!(list.len(), 2);
        assert_eq!(list.iter().filter(|s| s["current"] == true).count(), 1);
        assert!(!list.iter().any(|s| s["id"].as_str().unwrap().len() > 12), "ids are short");
        let other_id = list.iter().find(|s| s["current"] == false).unwrap()["id"].as_str().unwrap().to_string();
        assert_eq!(auth.revoke(&other_id, &mine), 1);
        assert!(!auth.check(&other) && auth.check(&mine));
        // The current session cannot be revoked by id.
        let mine_id = auth.sessions(&mine)[0]["id"].as_str().unwrap().to_string();
        assert_eq!(auth.revoke(&mine_id, &mine), 0);
        let Login::Ok(third) = auth.login(ip(3), "correct horse battery".into()).await.unwrap() else { panic!() };
        assert!(auth.change_password(&mine, "wrong".into(), "a brand new password".into()).await.is_err());
        assert!(auth.change_password(&mine, "correct horse battery".into(), "short".into()).await.is_err());
        auth.change_password(&mine, "correct horse battery".into(), "a brand new password".into()).await.unwrap();
        assert!(auth.check(&mine) && !auth.check(&third), "other sessions end");
        assert!(matches!(auth.login(ip(4), "correct horse battery".into()).await.unwrap(), Login::Wrong));
        assert!(matches!(auth.login(ip(4), "a brand new password".into()).await.unwrap(), Login::Ok(_)));
    }

    #[test]
    fn idle_and_old_sessions_are_not_alive() {
        let now = Instant::now();
        let fresh = Session { created: now, last_seen: now, ip: None };
        assert!(alive(&fresh, now));
        assert!(!alive(&fresh, now + IDLE));
        let old = Session { created: now, last_seen: now + LIFETIME, ip: None };
        assert!(!alive(&old, now + LIFETIME));
    }
}
