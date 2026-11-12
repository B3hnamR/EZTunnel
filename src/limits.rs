//! Admission control for connections that have not yet proved their identity.
//!
//! A peer that connects but has not finished the key handshake costs the server a socket and a
//! task, but it must not use up the slots reserved for authenticated sessions. This limiter
//! bounds how many such connections can wait at once, both overall and per source address.

use anyhow::{Result, bail};
use std::{
    collections::HashMap,
    fmt::Display,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub struct PendingLimiter {
    global: Arc<Semaphore>,
    per_ip: usize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}

/// Held while a connection is waiting for its handshake. Dropping it frees the place.
pub struct PendingGuard {
    limiter: Arc<PendingLimiter>,
    ip: Option<IpAddr>,
    _permit: OwnedSemaphorePermit,
}

impl PendingLimiter {
    pub fn new(global: usize, per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            global: Arc::new(Semaphore::new(global)),
            per_ip,
            counts: Mutex::new(HashMap::new()),
        })
    }

    /// Reserves a waiting place, or returns `None` when a limit is reached.
    /// `ip` is `None` for carriers that cannot report a source address; only the global limit
    /// applies to those.
    pub fn try_enter(self: &Arc<Self>, ip: Option<IpAddr>) -> Option<PendingGuard> {
        self.try_enter_when(ip, true)
    }

    /// Like `try_enter`, but the per-address limit only applies while `enforce` is true. The
    /// address is counted either way, so one that grew while there was room is held to the
    /// limit as soon as there is none.
    pub fn try_enter_when(
        self: &Arc<Self>,
        ip: Option<IpAddr>,
        enforce: bool,
    ) -> Option<PendingGuard> {
        let ip = ip.map(|address| address.to_canonical());
        if let Some(address) = ip {
            let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
            let count = counts.entry(address).or_insert(0);
            if enforce && *count >= self.per_ip {
                return None;
            }
            *count += 1;
        }
        match self.global.clone().try_acquire_owned() {
            Ok(permit) => Some(PendingGuard {
                limiter: self.clone(),
                ip,
                _permit: permit,
            }),
            Err(_) => {
                self.release(ip);
                None
            }
        }
    }

    fn release(&self, ip: Option<IpAddr>) {
        let Some(address) = ip else {
            return;
        };
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&address) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&address);
            }
        }
    }

    #[cfg(test)]
    fn tracked_addresses(&self) -> usize {
        self.counts.lock().unwrap().len()
    }
}

/// `base` plus a random extra of up to a quarter of it. Several reconnecting sessions (a pool, or
/// both ends after a restart) then retry at slightly different moments instead of all at once.
pub fn jitter(base: Duration) -> Duration {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    static COUNTER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    // The clock separates runs; the counter separates callers that ask in the same instant.
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as u64);
    let mut x = COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Relaxed) ^ clock.rotate_left(17);
    // xorshift64*
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    let fraction = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64;
    base + base.mul_f64(0.25 * fraction)
}

/// The pause between reconnect attempts: it doubles after each failure up to `max`, and starts
/// again from `base` after a session that lasted. After the other server said goodbye it stays at
/// `base` for a while, because that server is restarting and is usually back within seconds.
pub struct RetryPause {
    base: u64,
    max: u64,
    current: u64,
    quick_for: Duration,
    quick_until: Option<std::time::Instant>,
}

impl RetryPause {
    pub fn new(base: u64, max: u64, quick_for: Duration) -> Self {
        Self {
            base,
            max,
            current: base,
            quick_for,
            quick_until: None,
        }
    }

    /// Call when a session ended because the other server said goodbye.
    pub fn peer_stopped(&mut self) {
        self.quick_until = Some(std::time::Instant::now() + self.quick_for);
    }

    fn quick(&self) -> bool {
        self.quick_until
            .is_some_and(|until| std::time::Instant::now() < until)
    }

    /// The pause before the next attempt. `lasted` is how long the last attempt (and its session)
    /// ran; one that ran for `healthy` or longer starts the doubling over.
    pub fn next(&mut self, lasted: Duration, healthy: Duration) -> Duration {
        let quick = self.quick();
        if quick || lasted >= healthy {
            self.current = self.base;
        }
        let pause = self.current;
        if !quick {
            self.current = self.current.saturating_mul(2).min(self.max);
        }
        Duration::from_secs(pause)
    }
}

/// Keeps an accept/receive loop alive across temporary failures such as running out of file
/// descriptors. Each consecutive failure waits a little longer (up to one second); only a long
/// unbroken run of failures, which means the listener is really gone, is returned as an error.
pub struct AcceptBackoff {
    consecutive: u32,
}

impl AcceptBackoff {
    const GIVE_UP_AFTER: u32 = 120;

    pub fn new() -> Self {
        Self { consecutive: 0 }
    }

    /// Call after every successful accept.
    pub fn succeeded(&mut self) {
        self.consecutive = 0;
    }

    /// How long to pause after the next failure.
    fn delay(&self) -> Duration {
        Duration::from_millis((25u64 << self.consecutive.min(6)).min(1000))
    }

    /// Counts one more failure; returns how long to wait, or an error once the run is too long.
    fn record_failure(&mut self, what: &str, error: &dyn Display) -> Result<Duration> {
        self.consecutive += 1;
        if self.consecutive >= Self::GIVE_UP_AFTER {
            bail!("{what} keeps failing: {error}");
        }
        if self.consecutive == 1 || self.consecutive.is_multiple_of(20) {
            tracing::warn!(%error, attempts = self.consecutive, "{what} failed; retrying");
        }
        Ok(self.delay())
    }

    /// Records a failure, logs it, and waits before the caller tries again.
    pub async fn failed(&mut self, what: &str, error: impl Display) -> Result<()> {
        let pause = self.record_failure(what, &error)?;
        tokio::time::sleep(pause).await;
        Ok(())
    }
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Option<IpAddr> {
        Some(IpAddr::from([192, 0, 2, last]))
    }

    #[test]
    fn per_address_limit_is_enforced_and_released() {
        let limiter = PendingLimiter::new(100, 2);
        let a = limiter.try_enter(ip(1)).unwrap();
        let _b = limiter.try_enter(ip(1)).unwrap();
        assert!(limiter.try_enter(ip(1)).is_none());
        assert!(limiter.try_enter(ip(2)).is_some());
        drop(a);
        assert!(limiter.try_enter(ip(1)).is_some());
    }

    #[test]
    fn global_limit_is_enforced_and_does_not_leak_address_counts() {
        let limiter = PendingLimiter::new(2, 8);
        let a = limiter.try_enter(ip(1)).unwrap();
        let b = limiter.try_enter(ip(2)).unwrap();
        assert!(limiter.try_enter(ip(3)).is_none());
        assert_eq!(
            limiter.tracked_addresses(),
            2,
            "rejected address must not stay tracked"
        );
        drop((a, b));
        assert_eq!(limiter.tracked_addresses(), 0);
        assert!(limiter.try_enter(ip(3)).is_some());
    }

    #[test]
    fn unknown_source_uses_only_the_global_limit() {
        let limiter = PendingLimiter::new(3, 1);
        let guards: Vec<_> = (0..3).map(|_| limiter.try_enter(None).unwrap()).collect();
        assert!(limiter.try_enter(None).is_none());
        drop(guards);
        assert!(limiter.try_enter(None).is_some());
    }

    #[test]
    fn backoff_grows_then_resets_and_eventually_gives_up() {
        let mut backoff = AcceptBackoff::new();
        let mut last = Duration::ZERO;
        for _ in 0..8 {
            backoff.consecutive += 1;
            let delay = backoff.delay();
            assert!(delay >= last && delay <= Duration::from_secs(1));
            last = delay;
        }
        assert_eq!(
            last,
            Duration::from_millis(1000).min(Duration::from_millis(25 << 6))
        );
        backoff.succeeded();
        assert_eq!(backoff.consecutive, 0);
        assert_eq!(backoff.delay(), Duration::from_millis(25));
    }

    #[test]
    fn backoff_returns_an_error_only_after_a_long_unbroken_run() {
        let mut backoff = AcceptBackoff::new();
        for _ in 0..(AcceptBackoff::GIVE_UP_AFTER - 1) {
            backoff.record_failure("test accept", &"boom").unwrap();
        }
        assert!(backoff.record_failure("test accept", &"boom").is_err());
        let mut fresh = AcceptBackoff::new();
        for _ in 0..(AcceptBackoff::GIVE_UP_AFTER - 2) {
            fresh.record_failure("test accept", &"boom").unwrap();
        }
        fresh.succeeded();
        for _ in 0..(AcceptBackoff::GIVE_UP_AFTER - 1) {
            fresh.record_failure("test accept", &"boom").unwrap();
        }
    }

    #[test]
    fn jitter_stays_within_a_quarter_and_varies() {
        let base = Duration::from_secs(8);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let value = jitter(base);
            assert!(value >= base && value <= base + base / 4, "{value:?}");
            seen.insert(value.as_nanos());
        }
        assert!(
            seen.len() > 32,
            "jitter barely varies: {} distinct values",
            seen.len()
        );
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn mapped_ipv4_addresses_count_as_ipv4() {
        let limiter = PendingLimiter::new(10, 1);
        let mapped: IpAddr = "::ffff:192.0.2.9".parse().unwrap();
        let plain: IpAddr = "192.0.2.9".parse().unwrap();
        let _a = limiter.try_enter(Some(mapped)).unwrap();
        assert!(limiter.try_enter(Some(plain)).is_none());
    }
}
