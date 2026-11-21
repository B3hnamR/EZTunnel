//! Failover between the carriers of one tunnel (`config::Failover`).
//!
//! The server keeps every carrier (one listener each) connected and judges each one every second
//! from its own sessions: whether any of them answers, how many heartbeats come back, how the
//! round trip compares with the carrier's usual one, and whether users opened on it get any data
//! at all. New users go to the active carrier; the decision of which carrier is active is made
//! here and nowhere else. Users already on a carrier stay on it until their connection ends.
//! Nothing of this is on the wire: the other server only sees sessions on several carriers.
use super::{Pool, Session, clock};
use crate::config;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

/// Seconds of samples a carrier is judged on.
const WINDOW: usize = 60;
/// Heartbeats a window needs before their loss counts.
const LOSS_MIN_HEARTBEATS: u64 = 6;
/// Lost heartbeats (percent) that make a carrier degraded.
const LOSS_DEGRADED_PERCENT: u64 = 30;
/// A round trip is slow when it is this many times the carrier's usual one ...
const SLOW_FACTOR: u64 = 3;
/// ... and at least this much above it (microseconds), so a short link is not judged on a few ms.
const SLOW_MARGIN_US: u64 = 100_000;
/// Share (percent) of the measured seconds in a window that must be slow.
const SLOW_PERCENT: usize = 80;
/// Measured seconds a window needs before slowness counts.
const SLOW_MIN_SAMPLES: usize = 20;
/// User connections opened on a carrier in one window that all got no data at all.
const STALL_MIN_OPENS: u64 = 5;
/// A carrier that is degraded is only left for one healthy at least this long ...
const HEALTHY_TO_TAKE_OVER: u64 = 10;
/// ... and not sooner than this after the last change, so two poor carriers do not alternate.
const DEGRADED_HOLD: u64 = 60;
/// On the way back, a carrier ready earlier waits for a more preferred one that will be ready
/// within this many seconds.
const RETURN_PATIENCE: u64 = 60;
/// A carrier that has never had a session is down after this long (at least `down_after_sec`).
const FIRST_CONNECT_GRACE: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    /// Not connected yet since the tunnel started.
    Starting,
    Healthy,
    Degraded,
    Down,
}

impl State {
    fn word(self) -> &'static str {
        match self {
            State::Starting => "starting",
            State::Healthy => "healthy",
            State::Degraded => "degraded",
            State::Down => "down",
        }
    }
}

/// What one carrier did during one second.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Sample {
    /// Sessions that answer.
    pub live: usize,
    pub heartbeats: u64,
    pub answers: u64,
    /// The best round-trip score among its sessions (microseconds), once measured.
    pub rtt_us: Option<u64>,
    /// User connections opened, and data bytes received.
    pub opens: u64,
    pub bytes_in: u64,
}

/// The judgement of one carrier, fed one `Sample` per second.
#[derive(Debug)]
pub(super) struct Judge {
    window: VecDeque<Sample>,
    state: State,
    /// When the state last changed, and since when it has been healthy (seconds).
    since: u64,
    healthy_since: Option<u64>,
    /// Since when no session has answered.
    silent_since: Option<u64>,
    /// The usual round trip: follows a lower one at once and a higher one only slowly.
    baseline_us: Option<u64>,
    /// Why it is degraded, for the log and the status.
    why: &'static str,
}

impl Judge {
    pub fn new(now: u64) -> Self {
        Self {
            window: VecDeque::with_capacity(WINDOW),
            state: State::Starting,
            since: now,
            healthy_since: None,
            silent_since: Some(now),
            baseline_us: None,
            why: "",
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Seconds it has been healthy without a break (0 when it is not).
    pub fn healthy_for(&self, now: u64) -> u64 {
        self.healthy_since.map_or(0, |since| now.saturating_sub(since))
    }

    /// Takes one second's sample and returns the state when it changed.
    pub fn observe(&mut self, sample: Sample, now: u64, down_after: u64) -> Option<State> {
        if self.window.len() == WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(sample);
        if let Some(rtt) = sample.rtt_us {
            self.baseline_us = Some(match self.baseline_us {
                Some(baseline) if rtt >= baseline => baseline + (rtt - baseline) / 600,
                _ => rtt,
            });
        }
        let next = if sample.live > 0 {
            self.silent_since = None;
            self.judge_live()
        } else {
            let silent = *self.silent_since.get_or_insert(now);
            if self.state == State::Starting {
                if now.saturating_sub(silent) >= down_after.max(FIRST_CONNECT_GRACE) { State::Down } else { State::Starting }
            } else if now.saturating_sub(silent) >= down_after {
                State::Down
            } else {
                // A short gap (a session being replaced) keeps the last judgement.
                self.state
            }
        };
        if next == State::Down {
            self.why = if self.state == State::Starting { "never connected" } else { "no session answers" };
        }
        if next == self.state {
            return None;
        }
        self.state = next;
        self.since = now;
        self.healthy_since = (next == State::Healthy).then_some(now);
        Some(next)
    }

    fn judge_live(&mut self) -> State {
        let heartbeats: u64 = self.window.iter().map(|s| s.heartbeats).sum();
        let answers: u64 = self.window.iter().map(|s| s.answers).sum();
        if heartbeats >= LOSS_MIN_HEARTBEATS && answers.min(heartbeats) * 100 <= heartbeats * (100 - LOSS_DEGRADED_PERCENT) {
            self.why = "heartbeats are lost";
            return State::Degraded;
        }
        if let Some(baseline) = self.baseline_us {
            let slow_above = (baseline * SLOW_FACTOR).max(baseline + SLOW_MARGIN_US);
            let measured: Vec<u64> = self.window.iter().filter_map(|s| s.rtt_us).collect();
            let slow = measured.iter().filter(|rtt| **rtt > slow_above).count();
            if measured.len() >= SLOW_MIN_SAMPLES && slow * 100 >= measured.len() * SLOW_PERCENT {
                self.why = "the round trip is far above its usual one";
                return State::Degraded;
            }
        }
        let opens: u64 = self.window.iter().map(|s| s.opens).sum();
        let bytes: u64 = self.window.iter().map(|s| s.bytes_in).sum();
        if self.window.len() >= WINDOW / 2 && opens >= STALL_MIN_OPENS && bytes == 0 {
            self.why = "users get no data";
            return State::Degraded;
        }
        self.why = "";
        State::Healthy
    }
}

/// Why the active carrier changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reason {
    Down,
    Degraded,
    Return,
}

impl Reason {
    fn word(self) -> &'static str {
        match self {
            Reason::Down => "the active carrier is down",
            Reason::Degraded => "the active carrier works badly and another one is healthy",
            Reason::Return => "a preferred carrier has been healthy long enough",
        }
    }
}

/// Which carrier new users should go to. `carriers` holds each carrier's state and how long it
/// has been healthy, in order of preference; `held` is how long ago the active one last changed.
pub(super) fn choose(active: usize, carriers: &[(State, u64)], return_after: u64, held: u64) -> Option<(usize, Reason)> {
    let first = |wanted: &dyn Fn(&(State, u64)) -> bool| carriers.iter().position(wanted);
    let (state, _) = carriers[active];
    match state {
        State::Down => {
            let to = first(&|(s, _)| *s == State::Healthy).or_else(|| first(&|(s, _)| *s == State::Degraded))?;
            (to != active).then_some((to, Reason::Down))
        }
        // Still connecting: only give up on it for a carrier that already works.
        State::Starting => {
            let to = first(&|(s, _)| *s == State::Healthy)?;
            (to != active).then_some((to, Reason::Down))
        }
        State::Degraded => {
            let to = first(&|(s, healthy)| *s == State::Healthy && *healthy >= HEALTHY_TO_TAKE_OVER)?;
            (held >= DEGRADED_HOLD).then_some((to, Reason::Degraded))
        }
        // Back up the order in one step: to the most preferred healthy carrier once it has been
        // healthy long enough. One between them that is ready earlier is only taken when the
        // preferred one is still far from ready, so users do not move twice within a minute.
        State::Healthy => {
            let above = &carriers[..active];
            let top = above.iter().position(|(s, _)| *s == State::Healthy)?;
            let top_healthy = above[top].1;
            if top_healthy >= return_after {
                return Some((top, Reason::Return));
            }
            let ready = above.iter().position(|(s, healthy)| *s == State::Healthy && *healthy >= return_after)?;
            (return_after - top_healthy > RETURN_PATIENCE).then_some((ready, Reason::Return))
        }
    }
}

pub(super) struct Carrier {
    /// For people: transport and address, e.g. "wss 0.0.0.0:8443".
    pub label: String,
    pub pool: Arc<Pool>,
}

/// The counters a session had at the last look, to take differences.
#[derive(Default, Clone, Copy)]
struct Seen {
    heartbeats: u64,
    answers: u64,
    opens: u64,
    bytes_in: u64,
}

struct View {
    judges: Vec<Judge>,
    seen: Vec<HashMap<usize, Seen>>,
    switches: u64,
    changed_at: u64,
    last_reason: Option<Reason>,
}

pub(super) struct Failover {
    carriers: Vec<Carrier>,
    active: AtomicUsize,
    options: config::Failover,
    view: Mutex<View>,
}

fn seconds() -> u64 {
    clock() / 1000
}

impl Failover {
    pub fn new(carriers: Vec<Carrier>, options: config::Failover) -> Self {
        let now = seconds();
        let count = carriers.len();
        Self {
            carriers,
            active: AtomicUsize::new(0),
            options,
            view: Mutex::new(View {
                judges: (0..count).map(|_| Judge::new(now)).collect(),
                seen: vec![HashMap::new(); count],
                switches: 0,
                changed_at: now,
                last_reason: None,
            }),
        }
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// A session for a new user: the active carrier's, else the next carrier in order that has
    /// one. Never none while any carrier has a session that answers.
    pub fn pick(&self) -> Option<Arc<Session>> {
        let active = self.active();
        self.carriers[active]
            .pool
            .pick()
            .or_else(|| self.carriers.iter().enumerate().filter(|(index, _)| *index != active).find_map(|(_, carrier)| carrier.pool.pick()))
    }

    pub fn crowded(&self) -> bool {
        self.carriers[self.active()].pool.crowded()
    }

    /// One second's sample of a carrier, from its sessions' counters.
    fn sample(carrier: &Carrier, seen: &mut HashMap<usize, Seen>, fresh_ms: u64) -> Sample {
        let sessions: Vec<Arc<Session>> = carrier
            .pool
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|session| session.alive.load(Ordering::Acquire))
            .collect();
        let now = clock();
        let mut sample = Sample::default();
        let mut next = HashMap::with_capacity(sessions.len());
        for session in &sessions {
            if !session.suspect.load(Ordering::Acquire) {
                sample.live += 1;
            }
            let counts = Seen {
                heartbeats: session.counts.heartbeats.load(Ordering::Relaxed),
                answers: session.counts.answers.load(Ordering::Relaxed),
                opens: session.counts.opens.load(Ordering::Relaxed),
                bytes_in: session.bytes_in.load(Ordering::Relaxed),
            };
            let key = Arc::as_ptr(session) as usize;
            let before = seen.get(&key).copied().unwrap_or_default();
            sample.heartbeats += counts.heartbeats.saturating_sub(before.heartbeats);
            sample.answers += counts.answers.saturating_sub(before.answers);
            sample.opens += counts.opens.saturating_sub(before.opens);
            sample.bytes_in += counts.bytes_in.saturating_sub(before.bytes_in);
            next.insert(key, counts);
            if let Some(score) = session.quality.lock().unwrap_or_else(|e| e.into_inner()).score(now, fresh_ms) {
                sample.rtt_us = Some(sample.rtt_us.map_or(score, |best: u64| best.min(score)));
            }
        }
        *seen = next;
        sample
    }

    /// Judges every carrier once and moves new users when needed.
    fn tick(&self, fresh_ms: u64) {
        let now = seconds();
        let mut view = self.view.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for (index, carrier) in self.carriers.iter().enumerate() {
            let sample = Self::sample(carrier, &mut view.seen[index], fresh_ms);
            let judge = &mut view.judges[index];
            if let Some(state) = judge.observe(sample, now, self.options.down_after_sec) {
                match state {
                    State::Healthy => tracing::info!(carrier = %carrier.label, "failover: carrier is healthy"),
                    State::Starting => {}
                    _ => tracing::warn!(carrier = %carrier.label, state = state.word(), why = judge.why, "failover: carrier changed state"),
                }
            }
        }
        let states: Vec<(State, u64)> = view.judges.iter().map(|judge| (judge.state(), judge.healthy_for(now))).collect();
        let active = self.active();
        if let Some((to, reason)) = choose(active, &states, self.options.return_after_sec, now.saturating_sub(view.changed_at)) {
            self.active.store(to, Ordering::Release);
            view.switches += 1;
            view.changed_at = now;
            view.last_reason = Some(reason);
            tracing::warn!(
                from = %self.carriers[active].label,
                to = %self.carriers[to].label,
                reason = reason.word(),
                "failover: new users now go to another carrier"
            );
        }
    }

    /// For the status: the active carrier, the number of changes and every carrier's state.
    pub fn snapshot(&self) -> serde_json::Value {
        let now = seconds();
        let view = self.view.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let active = self.active();
        let carriers: Vec<serde_json::Value> = self
            .carriers
            .iter()
            .zip(&view.judges)
            .enumerate()
            .map(|(index, (carrier, judge))| {
                let sessions = carrier
                    .pool
                    .sessions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .iter()
                    .filter_map(Weak::upgrade)
                    .filter(|session| session.alive.load(Ordering::Acquire) && !session.suspect.load(Ordering::Acquire))
                    .count();
                serde_json::json!({
                    "order": index + 1,
                    "carrier": carrier.label,
                    "state": judge.state().word(),
                    "why": judge.why,
                    "for_sec": now.saturating_sub(judge.since),
                    "sessions": sessions,
                    "active": index == active,
                })
            })
            .collect();
        serde_json::json!({
            "active": active + 1,
            "carrier": self.carriers[active].label,
            "switches": view.switches,
            "since_sec": now.saturating_sub(view.changed_at),
            "last_reason": view.last_reason.map(Reason::word),
            "return_after_sec": self.options.return_after_sec,
            "carriers": carriers,
        })
    }

    /// Runs the judgement every second and keeps the status current.
    pub async fn watch(self: Arc<Self>, stats: Arc<crate::stats::Stats>, fresh_ms: u64) -> anyhow::Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            self.tick(fresh_ms);
            stats.set_failover(self.snapshot(), &self.carriers[self.active()].label);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Sample {
        Sample { live: 2, heartbeats: 1, answers: 1, rtt_us: Some(50_000), opens: 1, bytes_in: 1000 }
    }

    fn silent() -> Sample {
        Sample::default()
    }

    #[test]
    fn a_carrier_that_never_connects_is_down_after_the_grace() {
        let mut judge = Judge::new(0);
        for now in 1..FIRST_CONNECT_GRACE {
            judge.observe(silent(), now, 20);
            assert_eq!(judge.state(), State::Starting);
        }
        judge.observe(silent(), FIRST_CONNECT_GRACE, 20);
        assert_eq!(judge.state(), State::Down);
    }

    #[test]
    fn a_carrier_is_down_only_after_staying_silent() {
        let mut judge = Judge::new(0);
        judge.observe(healthy(), 1, 20);
        assert_eq!(judge.state(), State::Healthy);
        // A short gap while a session is replaced changes nothing.
        for now in 2..21 {
            judge.observe(silent(), now, 20);
            assert_eq!(judge.state(), State::Healthy, "second {now}");
        }
        judge.observe(silent(), 22, 20);
        assert_eq!(judge.state(), State::Down);
        judge.observe(healthy(), 23, 20);
        assert_eq!(judge.state(), State::Healthy);
        assert_eq!(judge.healthy_for(33), 10);
    }

    #[test]
    fn lost_heartbeats_degrade_a_carrier_and_answers_heal_it() {
        let mut judge = Judge::new(0);
        let lossy = Sample { answers: 0, ..healthy() };
        // One heartbeat in ten lost is normal on a busy link.
        for now in 1..=60 {
            judge.observe(if now % 10 == 0 { lossy } else { healthy() }, now, 20);
        }
        assert_eq!(judge.state(), State::Healthy);
        for now in 61..=90 {
            judge.observe(lossy, now, 20);
        }
        assert_eq!(judge.state(), State::Degraded);
        for now in 91..=160 {
            judge.observe(healthy(), now, 20);
        }
        assert_eq!(judge.state(), State::Healthy);
    }

    #[test]
    fn a_round_trip_far_above_the_usual_one_degrades_a_carrier() {
        let mut judge = Judge::new(0);
        for now in 1..=30 {
            judge.observe(healthy(), now, 20);
        }
        let slow = Sample { rtt_us: Some(900_000), ..healthy() };
        for now in 31..=60 {
            judge.observe(slow, now, 20);
        }
        assert_eq!(judge.state(), State::Healthy, "half the window is slow");
        for now in 61..=90 {
            judge.observe(slow, now, 20);
        }
        assert_eq!(judge.state(), State::Degraded);
        // A slightly slower link (not 3x and +100 ms) is never degraded.
        let mut steady = Judge::new(0);
        for now in 1..=200 {
            steady.observe(Sample { rtt_us: Some(if now > 30 { 120_000 } else { 50_000 }), ..healthy() }, now, 20);
        }
        assert_eq!(steady.state(), State::Healthy);
    }

    #[test]
    fn users_that_get_no_data_degrade_a_carrier() {
        let mut judge = Judge::new(0);
        let stalled = Sample { opens: 1, bytes_in: 0, ..healthy() };
        for now in 1..=40 {
            judge.observe(stalled, now, 20);
        }
        assert_eq!(judge.state(), State::Degraded);
        // An idle carrier (no users) is not stalled.
        let mut idle = Judge::new(0);
        for now in 1..=80 {
            idle.observe(Sample { opens: 0, bytes_in: 0, ..healthy() }, now, 20);
        }
        assert_eq!(idle.state(), State::Healthy);
    }

    #[test]
    fn choosing_follows_the_order_and_waits_before_returning() {
        use State::*;
        // Active down: the first healthy one, else the first degraded one.
        assert_eq!(choose(0, &[(Down, 0), (Degraded, 0), (Healthy, 5)], 300, 0), Some((2, Reason::Down)));
        assert_eq!(choose(0, &[(Down, 0), (Degraded, 0), (Down, 0)], 300, 0), Some((1, Reason::Down)));
        assert_eq!(choose(0, &[(Down, 0), (Down, 0)], 300, 0), None, "nothing better: keep it");
        // Still connecting at start: wait for it unless another one already works.
        assert_eq!(choose(0, &[(Starting, 0), (Starting, 0)], 300, 0), None);
        assert_eq!(choose(0, &[(Starting, 0), (Healthy, 1)], 300, 0), Some((1, Reason::Down)));
        // Degraded: only for a carrier healthy a while, and not right after a change.
        assert_eq!(choose(0, &[(Degraded, 0), (Healthy, 3)], 300, 100), None);
        assert_eq!(choose(0, &[(Degraded, 0), (Healthy, 30)], 300, 10), None);
        assert_eq!(choose(0, &[(Degraded, 0), (Healthy, 30)], 300, 100), Some((1, Reason::Degraded)));
        // Healthy backup in use: back to the preferred one after return_after, not before, and in
        // one step: the second one, ready first, waits for the first one when it is nearly ready.
        assert_eq!(choose(2, &[(Healthy, 299), (Healthy, 400), (Healthy, 500)], 300, 999), None);
        assert_eq!(choose(2, &[(Healthy, 241), (Healthy, 400), (Healthy, 500)], 300, 999), None);
        assert_eq!(choose(2, &[(Healthy, 300), (Healthy, 400), (Healthy, 500)], 300, 999), Some((0, Reason::Return)));
        // The first one far from ready (or down): the second one is taken meanwhile.
        assert_eq!(choose(2, &[(Healthy, 100), (Healthy, 400), (Healthy, 500)], 300, 999), Some((1, Reason::Return)));
        assert_eq!(choose(2, &[(Down, 0), (Healthy, 400), (Healthy, 500)], 300, 999), Some((1, Reason::Return)));
        assert_eq!(choose(1, &[(Healthy, 100), (Healthy, 400)], 300, 999), None);
        assert_eq!(choose(0, &[(Healthy, 1000), (Healthy, 400)], 300, 999), None, "the first one never returns anywhere");
    }
}
