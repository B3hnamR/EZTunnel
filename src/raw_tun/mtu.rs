//! Advisory unfragmented raw-carrier measurement. Only an exact authenticated
//! echo advances the lower bound. Loss is not proof of a path MTU ceiling.
use tokio::time::{Duration, Instant};
#[derive(Default)]
pub(super) struct Probe {
    low: usize,
    high: usize,
    attempts: u8,
    waiting: Option<(Vec<u8>, Instant, usize)>,
    done: bool,
    reply_at: Option<Instant>,
}
impl Probe {
    pub fn next(&mut self, maximum: usize, session: [u8; 16]) -> Option<Vec<u8>> {
        if self.done {
            return None;
        }
        if let Some((_, when, size)) = &self.waiting {
            if when.elapsed() < Duration::from_secs(1) {
                return None;
            }
            self.high = size.saturating_sub(1);
            self.waiting = None;
        }
        if self.attempts == 0 {
            self.high = maximum;
        }
        if self.attempts >= 12 || self.high <= self.low || self.high < 128 {
            self.done = true;
            return None;
        }
        let size = if self.low == 0 {
            128.min(self.high)
        } else {
            self.low + (self.high - self.low).div_ceil(2)
        };
        let mut bytes = vec![0x5a; size];
        bytes[0] = super::MTU_PROBE;
        // An unpredictable challenge prevents an already-authenticated peer from
        // pre-acknowledging an unreceived size using public session metadata.
        let mut challenge = [0u8; 16];
        if rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut challenge)
            .is_err()
        {
            self.done = true;
            return None;
        }
        bytes[1..17].copy_from_slice(&challenge);
        bytes[17] = self.attempts;
        bytes[18..34].copy_from_slice(&session);
        self.attempts += 1;
        self.waiting = Some((bytes.clone(), Instant::now(), size));
        Some(bytes)
    }
    pub fn received(&mut self, reply: &[u8]) {
        if let Some((sent, _, size)) = &self.waiting {
            if reply.len() == sent.len()
                && reply.first() == Some(&super::MTU_REPLY)
                && reply[1..] == sent[1..]
            {
                self.low = *size;
                self.waiting = None;
            }
        }
    }
    pub fn response(&mut self, request: &[u8], maximum: usize) -> Option<Vec<u8>> {
        if request.len() < 128
            || request.len() > maximum
            || self
                .reply_at
                .is_some_and(|t| t.elapsed() < Duration::from_millis(200))
        {
            return None;
        }
        self.reply_at = Some(Instant::now());
        let mut reply = request.to_vec();
        reply[0] = super::MTU_REPLY;
        Some(reply)
    }
    pub fn result(&self) -> Option<usize> {
        (self.done && self.low > 0).then_some(self.low)
    }
    pub fn finished(&self) -> bool {
        self.done
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn only_matched_authenticated_echoes_advance_and_work_is_bounded() {
        let mut probe = Probe::default();
        let mut responder = Probe::default();
        for _ in 0..40 {
            if let Some(request) = probe.next(1400, [3; 16]) {
                let mut wrong = request.clone();
                wrong[0] = super::super::MTU_REPLY;
                wrong[20] ^= 1;
                probe.received(&wrong);
                if request.len() <= 1100 {
                    probe.received(&responder.response(&request, 1400).unwrap());
                }
            }
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert!(probe.finished());
        assert!(
            probe
                .result()
                .is_some_and(|size| (1090..=1100).contains(&size))
        );
        assert!(probe.attempts <= 12);
    }
    #[tokio::test(start_paused = true)]
    async fn unsupported_peer_never_produces_an_mtu_claim() {
        let mut probe = Probe::default();
        probe.next(1400, [0; 16]);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(probe.next(1400, [0; 16]).is_none());
        assert!(probe.result().is_none());
    }
}
