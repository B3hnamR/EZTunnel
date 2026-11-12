//! Local authenticated-heartbeat measurements. Only selection of a new stream
//! consults this state; it never closes or migrates an existing stream.
use std::time::Duration;

#[derive(Default)]
pub(super) struct Quality {
    samples: u64,
    rtt_us: u64,
    jitter_us: u64,
    updated_ms: u64,
    judged: u64,
    strikes: u8,
    avoid_until: u64,
}

impl Quality {
    pub fn observe(&mut self, elapsed: Duration, now: u64) {
        let value = elapsed.as_micros().min(60_000_000) as u64;
        if self.samples == 0 {
            self.rtt_us = value;
        } else {
            self.jitter_us = (self.jitter_us * 3 + self.rtt_us.abs_diff(value)) / 4;
            self.rtt_us = (self.rtt_us * 7 + value) / 8;
        }
        self.samples = self.samples.saturating_add(1);
        self.updated_ms = now;
    }

    pub fn score(&self, now: u64, fresh_ms: u64) -> Option<u64> {
        (self.samples >= 5 && now.saturating_sub(self.updated_ms) <= fresh_ms)
            .then_some(self.rtt_us.saturating_add(self.jitter_us.saturating_mul(2)))
    }

    pub fn avoid(&mut self, best: u64, now: u64, fresh_ms: u64) -> bool {
        let Some(score) = self.score(now, fresh_ms) else {
            self.strikes = 0;
            self.avoid_until = 0;
            return false;
        };
        if self.judged != self.samples {
            self.judged = self.samples;
            // A small RTT difference is not a useful reason to steer. Require
            // three distinct measurements, at least 50% and 20 ms worse.
            if score > best.saturating_mul(3) / 2 + 20_000 {
                self.strikes = self.strikes.saturating_add(1);
                if self.strikes >= 3 {
                    self.avoid_until = now.saturating_add(30_000);
                }
            } else if now >= self.avoid_until {
                self.strikes = 0;
            }
        }
        now < self.avoid_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steering_requires_real_samples_and_recovers_after_cooldown() {
        let mut quality = Quality::default();
        for n in 0..4 {
            quality.observe(Duration::from_millis(300), n);
            assert_eq!(quality.score(n, 1000), None);
        }
        quality.observe(Duration::from_millis(300), 4);
        assert!(!quality.avoid(50_000, 4, 1000));
        for _ in 0..100 {
            assert!(!quality.avoid(50_000, 4, 1000));
        }
        quality.observe(Duration::from_millis(300), 5);
        assert!(!quality.avoid(50_000, 5, 1000));
        quality.observe(Duration::from_millis(300), 6);
        assert!(quality.avoid(50_000, 6, 1000));
        assert!(!quality.avoid(50_000, 40_000, 1000)); // stale = neutral
        for n in 0..100 {
            quality.observe(Duration::from_millis(50), 40_000 + n);
        }
        assert!(!quality.avoid(50_000, 40_100, 1000));
    }

    #[test]
    fn small_differences_do_not_cause_flapping() {
        let mut quality = Quality::default();
        for n in 0..20 {
            quality.observe(Duration::from_millis(80), n);
            assert!(!quality.avoid(50_000, n, 1000));
        }
    }
}
