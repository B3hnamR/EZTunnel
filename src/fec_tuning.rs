//! Locally measured KCP tuning. No probes, remote endpoint or shared secret is used.
use super::{FecOptions, FecProfile, NetworkSocket, TuningRegistry};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tokio_kcp::KcpSession;

const MIN_BUFFER: usize = 256 * 1024;
const MAX_BUFFER: usize = 64 * 1024 * 1024;
const MAX_PENDING: usize = 8192;
const RTT_MAX_AGE: Duration = Duration::from_secs(60);
const BASE_MAX_AGE: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FecTunerMode {
    #[default]
    Off,
    Auto,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FecTunerOptions {
    pub mode: FecTunerMode,
    pub min_buffer_bytes: usize,
    pub max_buffer_bytes: usize,
    pub min_window_bytes: usize,
    pub max_window_bytes: usize,
    pub memory_budget_mb: usize,
    pub queue_delay_ms: Option<u64>,
}
impl Default for FecTunerOptions {
    fn default() -> Self {
        Self {
            mode: FecTunerMode::Off,
            min_buffer_bytes: MIN_BUFFER,
            max_buffer_bytes: 16 * 1024 * 1024,
            min_window_bytes: MIN_BUFFER,
            max_window_bytes: 16 * 1024 * 1024,
            memory_budget_mb: 128,
            queue_delay_ms: None,
        }
    }
}
impl FecTunerOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (MIN_BUFFER..=MAX_BUFFER).contains(&self.min_buffer_bytes)
                && (self.min_buffer_bytes..=MAX_BUFFER).contains(&self.max_buffer_bytes),
            "fec tuner buffer range must be ordered within 256 KiB..64 MiB"
        );
        ensure!(
            (MIN_BUFFER..=MAX_BUFFER).contains(&self.min_window_bytes)
                && (self.min_window_bytes..=MAX_BUFFER).contains(&self.max_window_bytes),
            "fec tuner window byte range must be ordered within 256 KiB..64 MiB"
        );
        ensure!(
            (8..=4096).contains(&self.memory_budget_mb),
            "fec tuner memory_budget_mb must be 8..4096"
        );
        ensure!(
            self.queue_delay_ms.is_none_or(|value| value <= 2000),
            "fec tuner queue_delay_ms must be 0..2000"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Stamp {
    conv: u32,
    sn: u32,
    ts: u32,
}
#[derive(Default)]
pub(super) struct Measurements {
    sent: u64,
    received: u64,
    requested_buffer: usize,
    pending: HashMap<Stamp, Instant>,
    order: VecDeque<(Stamp, Instant)>,
    srtt: Option<f64>,
    base: Option<(f64, Instant)>,
    last_rtt: Option<Instant>,
}
pub(super) type SharedMeasurements = Arc<Mutex<Measurements>>;

impl Measurements {
    pub(super) fn shared(options: &FecOptions) -> Option<SharedMeasurements> {
        (options.tuner.mode == FecTunerMode::Auto).then(|| {
            Arc::new(Mutex::new(Self {
                requested_buffer: options.initial_buffer(),
                ..Self::default()
            }))
        })
    }
    fn prune(&mut self, now: Instant) {
        while self
            .order
            .front()
            .is_some_and(|(_, when)| now.saturating_duration_since(*when) >= RTT_MAX_AGE)
        {
            let (key, when) = self.order.pop_front().unwrap();
            if self.pending.get(&key) == Some(&when) {
                self.pending.remove(&key);
            }
        }
        if self
            .last_rtt
            .is_some_and(|when| now.saturating_duration_since(when) >= RTT_MAX_AGE)
        {
            self.srtt = None;
            self.base = None;
            self.last_rtt = None;
        }
    }
    pub(super) fn observe(&mut self, mut packet: &[u8], outgoing: bool, now: Instant) {
        self.prune(now);
        while packet.len() >= 24 {
            let length = u32::from_le_bytes(packet[20..24].try_into().unwrap()) as usize;
            let Some(end) = 24usize
                .checked_add(length)
                .filter(|&end| end <= packet.len())
            else {
                break;
            };
            let key = Stamp {
                conv: u32::from_le_bytes(packet[..4].try_into().unwrap()),
                sn: u32::from_le_bytes(packet[12..16].try_into().unwrap()),
                ts: u32::from_le_bytes(packet[8..12].try_into().unwrap()),
            };
            if outgoing && packet[4] == 81 && !self.pending.contains_key(&key) {
                while self.order.len() >= MAX_PENDING {
                    let (old, when) = self.order.pop_front().unwrap();
                    if self.pending.get(&old) == Some(&when) {
                        self.pending.remove(&old);
                    }
                }
                self.pending.insert(key, now);
                self.order.push_back((key, now));
            } else if !outgoing
                && packet[4] == 82
                && let Some(when) = self.pending.remove(&key)
            {
                let sample =
                    (now.saturating_duration_since(when).as_secs_f64() * 1000.0).clamp(1.0, 2000.0);
                self.srtt = Some(
                    self.srtt
                        .map_or(sample, |previous| previous * 0.875 + sample * 0.125),
                );
                if self.base.is_none_or(|(base, time)| {
                    sample < base || now.saturating_duration_since(time) >= BASE_MAX_AGE
                }) {
                    self.base = Some((sample, now));
                }
                self.last_rtt = Some(now);
            }
            packet = &packet[end..];
        }
    }
    pub(super) fn read(&mut self, bytes: usize) {
        self.received = self.received.saturating_add(bytes as u64);
    }
    pub(super) fn written(&mut self, bytes: usize) {
        self.sent = self.sent.saturating_add(bytes as u64);
    }
    fn sample(&mut self, now: Instant) -> Sample {
        self.prune(now);
        Sample {
            sent: std::mem::take(&mut self.sent),
            received: std::mem::take(&mut self.received),
            srtt: self.srtt.unwrap_or(80.0),
            base: self.base.map(|(base, _)| base),
        }
    }
}
struct Sample {
    sent: u64,
    received: u64,
    srtt: f64,
    base: Option<f64>,
}

fn ewma(previous: f64, sample: f64) -> f64 {
    previous * 0.6 + sample * 0.4
}

fn aggregate_buffer_target(options: &FecOptions, requests: impl Iterator<Item = usize>) -> usize {
    let upper = options
        .tuner
        .max_buffer_bytes
        .min(MAX_BUFFER)
        .min(options.tuner.memory_budget_mb * 1024 * 1024 / 4);
    requests
        .fold(0usize, usize::saturating_add)
        .clamp(MIN_BUFFER, upper)
}
pub(super) struct SocketBuffers {
    registry: TuningRegistry,
    current: Mutex<usize>,
}
impl SocketBuffers {
    pub(super) fn shared(registry: TuningRegistry, initial: usize) -> Arc<Self> {
        Arc::new(Self {
            registry,
            current: Mutex::new(initial),
        })
    }
    fn refresh(&self, options: &FecOptions, outside: &NetworkSocket) -> io::Result<()> {
        // One listener descriptor receives traffic from every conversation.
        // Aggregate requests before changing it; a quiet peer must not replace
        // another peer's larger request. Lock the applied target across syscall.
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        let registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let target = aggregate_buffer_target(
            options,
            registry.values().map(|stats| {
                stats
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .requested_buffer
            }),
        );
        if target != *current {
            outside.set_socket_buffer_bytes(target)?;
            *current = target;
        }
        Ok(())
    }
}
pub(super) fn window_budget(bytes: usize, mtu: usize, gaming: bool) -> u16 {
    (bytes / mtu.max(512)).clamp(256, if gaming { 1024 } else { 8192 }) as u16
}
#[derive(Clone, Copy)]
struct WindowPolicy {
    gaming: bool,
    queue_ms: u64,
}
fn target_window(
    current: u16,
    budget: u16,
    mtu: usize,
    rate: f64,
    srtt: f64,
    base: Option<f64>,
    policy: WindowPolicy,
) -> u16 {
    let WindowPolicy { gaming, queue_ms } = policy;
    let current = current as usize;
    let budget = (budget as usize).max(256);
    let mtu = mtu.max(512);
    let srtt = srtt.clamp(1.0, 2000.0);
    let bdp = (rate.max(0.0) * srtt / 1000.0).min(usize::MAX as f64) as usize;
    let extra = if gaming { 128 } else { 256 };
    let minimum = if gaming { 128 } else { 512 };
    let mut target = bdp.saturating_mul(2) / mtu + extra;
    if bdp >= current.saturating_mul(mtu) * 3 / 5 {
        target = target.max(current + current / 4);
    }
    let ratio = if gaming { 1.0 } else { 1.5 };
    if base.is_some_and(|base| srtt > base * ratio + queue_ms as f64) {
        target = target.min(current * 3 / 4);
    }
    target = target.max(minimum).min(budget);
    if current > 0 {
        target = target.min(current.saturating_mul(2));
    }
    target as u16
}

struct Governor {
    sent_ewma: f64,
    recv_ewma: f64,
    window: u16,
    down_count: u8,
    ticks: u64,
}
impl Governor {
    fn new(window: u16) -> Self {
        Self {
            sent_ewma: 0.0,
            recv_ewma: 0.0,
            window,
            down_count: 0,
            ticks: 0,
        }
    }
    fn step(
        &mut self,
        sample: &Sample,
        elapsed: f64,
        options: &FecOptions,
        mtu: usize,
        population: usize,
    ) -> (usize, Option<u16>) {
        self.ticks += 1;
        self.sent_ewma = ewma(self.sent_ewma, sample.sent as f64 / elapsed.max(0.001));
        self.recv_ewma = ewma(self.recv_ewma, sample.received as f64 / elapsed.max(0.001));
        let tuner = &options.tuner;
        let gaming = options.profile == FecProfile::Gaming;
        let queue_ms = tuner.queue_delay_ms.unwrap_or(if gaming { 15 } else { 20 });
        // Reserve two socket queues and two KCP windows per active conversation.
        // Kernel accounting may double SO_*BUF, so this is a target, not an RSS limit.
        let fair = tuner.memory_budget_mb * 1024 * 1024 / population.max(1) / 4;
        let upper = tuner.max_buffer_bytes.min(fair.max(tuner.min_buffer_bytes));
        let total = self.sent_ewma + self.recv_ewma;
        let wanted =
            (total * (sample.srtt + queue_ms as f64) * 0.004).min(MAX_BUFFER as f64) as usize;
        let buffer = wanted.clamp(tuner.min_buffer_bytes, upper);
        let window_bytes = buffer
            .clamp(tuner.min_window_bytes, tuner.max_window_bytes)
            .min(fair.max(tuner.min_window_bytes));
        let budget = window_budget(window_bytes, mtu, gaming);
        if !self.ticks.is_multiple_of(2) {
            return (buffer, None);
        }
        let mut candidate = target_window(
            self.window,
            budget,
            mtu,
            self.sent_ewma.max(self.recv_ewma),
            sample.srtt,
            sample.base,
            WindowPolicy { gaming, queue_ms },
        );
        let urgent = budget < self.window
            || sample
                .base
                .is_some_and(|base| sample.srtt > base * 1.5 + queue_ms as f64);
        if urgent {
            self.down_count = 0;
        } else if candidate < self.window {
            self.down_count = self.down_count.saturating_add(1);
            if self.down_count < 10 {
                candidate = self.window;
            } else {
                candidate = candidate.max(self.window - self.window / 8);
            }
        } else {
            self.down_count = 0;
        }
        let changed = (candidate != self.window).then_some(candidate);
        self.window = candidate;
        (buffer, changed)
    }
}

pub(super) struct Control {
    measurements: SharedMeasurements,
    options: FecOptions,
    outside: Arc<NetworkSocket>,
    population: Arc<AtomicUsize>,
    mtu: usize,
    interval: Interval,
    /// The last update failed (the next failure is then not reported again).
    failing: bool,
    last: Instant,
    governor: Governor,
    buffers: Arc<SocketBuffers>,
}
impl Control {
    fn new(
        measurements: SharedMeasurements,
        options: FecOptions,
        outside: Arc<NetworkSocket>,
        population: Arc<AtomicUsize>,
        buffers: Arc<SocketBuffers>,
        raw: bool,
    ) -> Self {
        let mtu = options.envelope_mtu(raw) - 8;
        let window = options.kcp(raw).wnd_size.0.min(options.kcp(raw).wnd_size.1);
        let mut interval = tokio::time::interval_at(
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Self {
            measurements,
            mtu,
            buffers,
            options,
            outside,
            population,
            interval,
            failing: false,
            last: Instant::now(),
            governor: Governor::new(window),
        }
    }
    pub(super) fn spawn(
        measurements: SharedMeasurements,
        options: FecOptions,
        outside: Arc<NetworkSocket>,
        population: Arc<AtomicUsize>,
        buffers: Arc<SocketBuffers>,
        raw: bool,
        session: Arc<KcpSession>,
    ) -> tokio::task::JoinHandle<()> {
        let mut control = Self::new(measurements, options, outside, population, buffers, raw);
        tokio::spawn(async move {
            loop {
                control.interval.tick().await;
                let result = control.update(&session);
                control.failing = report_update(result, control.failing);
            }
        })
    }
    fn update(&mut self, session: &KcpSession) -> io::Result<()> {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        let sample = self
            .measurements
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sample(now);
        let (buffer, window) = self.governor.step(
            &sample,
            elapsed,
            &self.options,
            self.mtu,
            self.population.load(Ordering::Relaxed),
        );
        self.measurements
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .requested_buffer = buffer;
        let buffer_result=self.buffers.refresh(&self.options, &self.outside);
        apply_then_report(window, buffer_result, |window| {
            session.kcp_socket().lock().set_window_size(window, window);
            session.notify();
            tracing::debug!(window, buffer, rtt_ms = sample.srtt, "fec adaptive tuning");
        })
    }
}

/// C12: the governor has already committed `window`, so it is applied to KCP even when the
/// socket-buffer refresh failed; the refresh error is still reported (and retried next tick
/// because SocketBuffers only commits after success).
fn apply_then_report(window: Option<u16>, refresh: io::Result<()>, apply: impl FnOnce(u16)) -> io::Result<()> {
    if let Some(window) = window {
        apply(window);
    }
    refresh
}

/// What to do with the result of one update: a failure (a socket option the kernel refused, for
/// example) is reported once and the next interval tries again; it does not end the tuning of a
/// connection that works. Returns whether the controller is failing now.
fn report_update(result: io::Result<()>, was_failing: bool) -> bool {
    match result {
        Ok(()) => {
            if was_failing {
                tracing::info!("fec adaptive controller works again");
            }
            false
        }
        Err(error) => {
            if was_failing {
                tracing::debug!(%error, "fec adaptive controller: still failing");
            } else {
                tracing::warn!(%error, "fec adaptive controller: could not apply a change; trying again at the next interval");
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_buffer_refresh_error_does_not_lose_the_window_change() {
        let mut applied = None;
        let result = apply_then_report(Some(512), Err(io::Error::from_raw_os_error(12)), |w| applied = Some(w));
        assert_eq!(applied, Some(512), "window must be installed despite the buffer error");
        assert!(result.is_err(), "the buffer error is still reported");
        let mut applied = None;
        assert!(apply_then_report(None, Ok(()), |w| applied = Some(w)).is_ok());
        assert_eq!(applied, None);
    }
    #[test]
    fn a_failed_update_is_reported_once_and_does_not_end_the_tuning() {
        let failure = || Err(io::Error::from_raw_os_error(12));
        // First failure: now failing. Further failures keep it failing (and are not logged at warn).
        assert!(report_update(failure(), false));
        assert!(report_update(failure(), true));
        // A success clears it; the next failure is a new one.
        assert!(!report_update(Ok(()), true));
        assert!(!report_update(Ok(()), false));
        assert!(report_update(failure(), false));
    }
    fn segment(command: u8, conv: u32, sn: u32, ts: u32) -> Vec<u8> {
        let mut bytes = vec![0; 24];
        bytes[..4].copy_from_slice(&conv.to_le_bytes());
        bytes[4] = command;
        bytes[8..12].copy_from_slice(&ts.to_le_bytes());
        bytes[12..16].copy_from_slice(&sn.to_le_bytes());
        bytes
    }
    #[test]
    fn ack_samples_require_matching_conversation_sequence_and_timestamp_and_expire() {
        let start = Instant::now();
        let mut stats = Measurements::default();
        stats.observe(&segment(81, 7, 1, 42), true, start);
        for (conv, sn, ts) in [(8, 1, 42), (7, 2, 42), (7, 1, 43)] {
            stats.observe(
                &segment(82, conv, sn, ts),
                false,
                start + Duration::from_millis(10),
            );
        }
        assert!(stats.srtt.is_none());
        stats.observe(
            &segment(82, 7, 1, 42),
            false,
            start + Duration::from_millis(20),
        );
        assert_eq!(stats.srtt, Some(20.0));
        stats.observe(
            &segment(82, 7, 1, 42),
            false,
            start + Duration::from_millis(200),
        );
        assert_eq!(stats.srtt, Some(20.0));
        stats.observe(&segment(81, 7, 3, 50), true, start);
        stats.prune(start + Duration::from_secs(61));
        assert!(stats.pending.is_empty());
        assert!(stats.srtt.is_none());
        for sn in 0..20_000 {
            stats.observe(
                &segment(81, 7, sn, 100),
                true,
                start + Duration::from_secs(62),
            );
        }
        assert_eq!(stats.order.len(), MAX_PENDING);
        assert!(stats.pending.len() <= MAX_PENDING);
    }
    #[test]
    fn ewma_window_budget_and_profile_targets_match_expected_constants() {
        assert_eq!(ewma(100.0, 200.0), 140.0);
        assert_eq!(window_budget(1, 1242, false), 256);
        assert_eq!(window_budget(64 * 1024 * 1024, 1242, false), 8192);
        assert_eq!(window_budget(64 * 1024 * 1024, 1242, true), 1024);
        let profile = WindowPolicy {
            gaming: false,
            queue_ms: 20,
        };
        assert_eq!(
            target_window(1024, 4096, 1000, 0.0, 80.0, Some(80.0), profile),
            512
        );
        assert_eq!(
            target_window(1024, 4096, 1000, 20_000_000.0, 80.0, Some(80.0), profile),
            2048
        );
        assert_eq!(
            target_window(1024, 4096, 1000, 20_000_000.0, 200.0, Some(80.0), profile),
            768
        );
    }
    #[test]
    fn slow_shrink_waits_ten_window_updates_but_inflation_shrinks_immediately() {
        let options = FecOptions {
            tuner: FecTunerOptions {
                max_buffer_bytes: 4 * 1024 * 1024,
                min_buffer_bytes: 4 * 1024 * 1024,
                min_window_bytes: 4 * 1024 * 1024,
                ..FecTunerOptions::default()
            },
            ..FecOptions::default()
        };
        let sample = Sample {
            sent: 0,
            received: 0,
            srtt: 80.0,
            base: Some(80.0),
        };
        let mut policy = Governor::new(1024);
        for _ in 0..18 {
            policy.step(&sample, 1.0, &options, 1242, 1);
            assert_eq!(policy.window, 1024);
        }
        policy.step(&sample, 1.0, &options, 1242, 1);
        assert_eq!(policy.step(&sample, 1.0, &options, 1242, 1).1, Some(896));
        let inflated = Sample {
            srtt: 200.0,
            ..sample
        };
        let mut policy = Governor::new(1024);
        policy.step(&inflated, 1.0, &options, 1242, 1);
        assert_eq!(policy.step(&inflated, 1.0, &options, 1242, 1).1, Some(512));
    }
    #[test]
    fn shared_socket_aggregates_peers_and_caps_global_memory_and_configured_maximum() {
        let mut options = FecOptions::default();
        let active = 4 * 1024 * 1024;
        let quiet = 256 * 1024;
        assert_eq!(
            aggregate_buffer_target(&options, [active, quiet].into_iter()),
            active + quiet
        );
        assert_eq!(
            aggregate_buffer_target(&options, [quiet, active].into_iter()),
            active + quiet
        );
        assert_eq!(
            aggregate_buffer_target(&options, [MAX_BUFFER, MAX_BUFFER].into_iter()),
            16 * 1024 * 1024
        );
        options.tuner.memory_budget_mb = 8;
        assert_eq!(
            aggregate_buffer_target(&options, [active, quiet].into_iter()),
            2 * 1024 * 1024
        );
        assert_eq!(
            aggregate_buffer_target(&options, std::iter::empty()),
            MIN_BUFFER
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guarded_controller_changes_idle_session_window_without_io_polls_and_stops_on_drop()
    -> Result<()> {
        use tokio::{
            io::AsyncWriteExt,
            net::UdpSocket,
            time::{sleep, timeout},
        };
        timeout(Duration::from_secs(8), async {
            let options = FecOptions {
                socket_buf_bytes: 8 * 1024 * 1024,
                tuner: FecTunerOptions {
                    mode: FecTunerMode::Auto,
                    memory_budget_mb: 32,
                    min_buffer_bytes: 4 * 1024 * 1024,
                    ..FecTunerOptions::default()
                },
                ..FecOptions::default()
            };
            options.validate()?;
            let receiver = UdpSocket::bind("127.0.0.1:0").await?;
            let mut stream =
                tokio_kcp::KcpStream::connect(&options.kcp(false), receiver.local_addr()?).await?;
            let outside = Arc::new(NetworkSocket::Udp(UdpSocket::bind("127.0.0.1:0").await?));
            outside.set_socket_buffer_bytes(options.initial_buffer())?;
            let measurements = Measurements::shared(&options).unwrap();
            let registry = TuningRegistry::default();
            registry.lock().unwrap().insert(0, measurements.clone());
            let buffers = SocketBuffers::shared(registry, options.initial_buffer());
            let guard = super::super::TaskGuard(Control::spawn(
                measurements.clone(),
                options.clone(),
                outside,
                Arc::new(AtomicUsize::new(1)),
                buffers.clone(),
                false,
                stream.shared_session(),
            ));
            // Deliberately do not poll this stream during either controller tick.
            sleep(Duration::from_millis(2150)).await;
            assert_eq!(*buffers.current.lock().unwrap(), 4 * 1024 * 1024);
            stream.write_all(b"idle").await?;
            let mut packet = [0; 1500];
            let (size, _) = receiver.recv_from(&mut packet).await?;
            ensure!(size >= 28 && packet[4] == 81, "missing idle-session PUSH");
            assert_eq!(u16::from_le_bytes(packet[6..8].try_into().unwrap()), 512);
            drop(guard);
            tokio::task::yield_now().await;
            measurements.lock().unwrap().requested_buffer = 8 * 1024 * 1024;
            sleep(Duration::from_millis(1100)).await;
            assert_eq!(
                measurements.lock().unwrap().requested_buffer,
                8 * 1024 * 1024,
                "dropped controller still updated requests"
            );
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
}
