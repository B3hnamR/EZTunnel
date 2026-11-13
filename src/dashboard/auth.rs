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
    hash: String,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    limiter: Mutex<Limiter>,
    /// Password checks are slow on purpose; only a few run at once.
    checks: Semaphore,
}

impl Auth {
    pub fn new(hash: String) -> Self {
        Self {
            hash,
            sessions: Mutex::new(HashMap::new()),
            limiter: Mutex::new(Limiter::default()),
            checks: Semaphore::new(2),
        }
    }

    pub async fn login(&self, ip: IpAddr, password: String) -> Result<Login> {
        if let Some(seconds) = self.limiter.lock().unwrap().wait(ip, Instant::now()) {
            return Ok(Login::Wait(seconds));
        }
        let matches = {
            let _permit = self.checks.acquire().await?;
            let hash = self.hash.clone();
            tokio::task::spawn_blocking(move || password_matches(&hash, &password)).await?
        };
        let mut limiter = self.limiter.lock().unwrap();
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

    #[test]
    fn idle_and_old_sessions_are_not_alive() {
        let now = Instant::now();
        let fresh = Session { created: now, last_seen: now };
        assert!(alive(&fresh, now));
        assert!(!alive(&fresh, now + IDLE));
        let old = Session { created: now, last_seen: now + LIFETIME };
        assert!(!alive(&old, now + LIFETIME));
    }
}
