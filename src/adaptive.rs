//! Optional local KCP congestion scheduling. No wire or authentication changes.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::{Arc, Mutex, OnceLock, atomic::{AtomicU64, Ordering}}, time::Duration};
use tokio::time::Instant;
use tokio_kcp::KcpSession;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdaptiveOptions {
    pub enabled: bool,
    pub shared_bandwidth: bool,
    pub min_window: u16,
    pub max_window: u16,
    pub min_rate: u64,
    pub max_rate: u64,
}

impl Default for AdaptiveOptions {
    fn default() -> Self {
        Self { enabled: false, shared_bandwidth: false, min_window: 128,
               max_window: 4096, min_rate: 100_000, max_rate: 500_000_000 }
    }
}

impl AdaptiveOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!((32..=8192).contains(&self.min_window) && (self.min_window..=8192).contains(&self.max_window), "adaptive window must be ordered within 32..8192");
        ensure!((16_000..=1_250_000_000).contains(&self.min_rate) && (self.min_rate..=1_250_000_000).contains(&self.max_rate), "adaptive rate must be ordered within 16000..1250000000 bytes/s");
        ensure!(!self.shared_bandwidth || self.enabled, "shared bandwidth requires the adaptive controller");
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub acknowledged: u64,
    pub first: u64,
    pub retransmitted: u64,
    pub queued: usize,
    pub rtt_ms: u32,
    pub mss: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct Decision {
    pub window: u16,
    pub rate: u64,
    pub min_rto_ms: u32,
    pub loaded: bool,
    pub clean: bool,
}

pub struct Controller {
    options: AdaptiveOptions,
    gaming: bool,
    last: Instant,
    previous: Observation,
    base_rtt: f64,
    base_epoch: Instant,
    epoch_min: f64,
    bandwidth: f64,
    rate: f64,
    window: u16,
    started: Instant,
    paced: bool,
    last_probe: Instant,
}

impl Controller {
    pub fn new(options: AdaptiveOptions, gaming: bool, now: Instant, initial: Observation) -> Self {
        Self { window: options.min_window, rate: options.min_rate as f64, options, gaming,
               last: now, previous: initial, base_rtt: 0.0, base_epoch: now,
               epoch_min: f64::INFINITY, bandwidth: 0.0, started: now, paced: false, last_probe: now }
    }

    pub fn update(&mut self, now: Instant, input: Observation) -> Decision {
        let seconds = now.saturating_duration_since(self.last).as_secs_f64();
        if seconds <= 0.0 {
            return self.decision(input.rtt_ms, input.queued, true);
        }
        // A counter reset cannot become an enormous delivery sample.
        let delivered = input.acknowledged.saturating_sub(self.previous.acknowledged) as f64 / seconds;
        let first = input.first.saturating_sub(self.previous.first);
        let resent = input.retransmitted.saturating_sub(self.previous.retransmitted);
        let loss = resent as f64 / first.saturating_add(resent).max(1) as f64;
        self.previous = input;
        self.last = now;
        let rtt = input.rtt_ms as f64;
        if rtt > 0.0 {
            self.epoch_min = self.epoch_min.min(rtt);
            if self.base_rtt == 0.0 || rtt < self.base_rtt { self.base_rtt = rtt; }
            if now.saturating_duration_since(self.base_epoch) >= Duration::from_secs(30) {
                self.base_rtt = self.epoch_min;
                self.epoch_min = rtt;
                self.base_epoch = now;
            }
        }
        // At a low startup rate, pacing itself may keep the queue below a full
        // window. That is still demand: requiring 70% occupancy can pin a clean
        // path permanently to its bootstrap rate.
        let loaded = input.queued > 0 && (input.queued >= usize::from(self.window) * 7 / 10 || delivered >= self.rate * 0.50);
        let low = if self.gaming { (self.base_rtt / 16.0).max(3.0) } else { (self.base_rtt * 0.22).max(12.0) };
        let high = if self.gaming { (self.base_rtt / 8.0).max(8.0) } else { (self.base_rtt * 0.45).max(30.0) };
        let delay = (rtt - self.base_rtt).max(0.0);
        if delivered > 0.0 {
            let alpha = (seconds / 0.5).clamp(0.02, 1.0);
            self.bandwidth = if self.bandwidth == 0.0 { delivered } else { self.bandwidth * (1.0-alpha) + delivered * alpha };
        }
        if self.base_rtt > 0.0 {
            if !self.paced && (delay > high || (loaded && now.saturating_duration_since(self.started).as_secs_f64() > 1.0)) {
                self.paced = true;
            }
            if delay > high {
                self.rate *= 0.85f64.powf((seconds / 0.1).min(1.0));
                self.window = ((self.window as f64 * 0.85) as u16).max(self.options.min_window);
            } else if input.queued > 0 && delay < low {
                let gain = if self.paced { 1.05f64 } else { 1.25f64 };
                self.rate *= gain.powf((seconds / (self.base_rtt / 1000.0).max(0.04)).min(1.0));
                if now.saturating_duration_since(self.last_probe) >= Duration::from_secs(2) {
                    self.rate *= 1.10;
                    self.last_probe = now;
                }
            }
            let target = self.bandwidth * if delay < low && loss < 0.05 { 1.25 } else { 1.0 };
            if target > self.rate && delay < high { self.rate = target.min(self.rate * 1.25); }
            self.rate = self.rate.clamp(self.options.min_rate as f64, self.options.max_rate as f64);
            let bdp = self.rate * (self.base_rtt.max(10.0) / 1000.0) / input.mss.max(1) as f64;
            self.window = ((bdp * 1.4 + 16.0) as u16).clamp(self.options.min_window, self.options.max_window);
        }
        self.decision(input.rtt_ms, input.queued, delay < low && loss <= 0.05)
    }

    fn decision(&self, rtt: u32, queued: usize, clean: bool) -> Decision {
        Decision { window: self.window, rate: self.rate as u64,
                   min_rto_ms: (rtt.saturating_add((rtt / 2).max(20))).clamp(30, 2000),
                   loaded: queued > 0, clean }
    }
}

#[derive(Clone)]
struct Demand { rate: u64, loaded: bool, clean: bool, touched: Instant }
#[derive(Default)]
struct PathAllocation { members: HashMap<u64, Demand>, capacity: u64, epoch: Option<Instant> }
#[derive(Default)]
pub struct Allocator { paths: HashMap<String, PathAllocation> }
impl Allocator {
    pub fn allocate(&mut self, path: &str, id: u64, now: Instant, requested: u64, loaded: bool, clean: bool) -> u64 {
        self.paths.retain(|_, path| {
            path.members.retain(|_, demand| now.saturating_duration_since(demand.touched) < Duration::from_millis(600));
            !path.members.is_empty()
        });
        if !self.paths.contains_key(path) && self.paths.len() >= 4096 { return requested; }
        let state = self.paths.entry(path.to_owned()).or_default();
        let members = &mut state.members;
        if !members.contains_key(&id) && members.len() >= 4096 { return requested; }
        members.insert(id, Demand { rate: requested, loaded, clean, touched: now });
        let active = members.values().filter(|d| d.loaded);
        let count=active.clone().count();
        if !loaded || count < 2 { return requested; }
        let observed = active.clone().map(|d| d.rate).max().unwrap_or(requested);
        // Keep a path estimate across calls: dividing each member's last share again
        // would collapse all rates geometrically as more samples arrive.
        let congested=active.filter(|d|!d.clean).count()*2>count;
        if state.epoch.is_none_or(|epoch| now.saturating_duration_since(epoch) >= Duration::from_secs(4)) {
            // Congested paths must be able to shed an old high-water capacity.
            state.capacity = if congested {(state.capacity as f64*0.85) as u64}else{state.capacity.max(observed)}.max(observed);
            state.epoch = Some(now);
        } else {
            state.capacity = state.capacity.max(observed);
        }
        let factor = if congested { 0.98 } else { 1.02 };
        ((state.capacity as f64 * factor) as u64 / count as u64).min(requested).max(1)
    }
    fn remove(&mut self, path: &str, id: u64) {
        if let Some(path) = self.paths.get_mut(path) { path.members.remove(&id); }
        self.paths.retain(|_, path| !path.members.is_empty());
    }
}

fn shared() -> &'static Mutex<Allocator> {
    static STATE: OnceLock<Mutex<Allocator>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(Allocator::default()))
}

pub fn spawn(session: Arc<KcpSession>, options: AdaptiveOptions, gaming: bool, path: String,lane_active:Arc<dyn Fn()->bool+Send+Sync>) -> tokio::task::JoinHandle<()> {
    static IDS: AtomicU64 = AtomicU64::new(1);
    let id = IDS.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        struct Registration(String, u64);
        impl Drop for Registration {
            fn drop(&mut self) { shared().lock().unwrap_or_else(|e|e.into_inner()).remove(&self.0, self.1); }
        }
        let _registration = Registration(path.clone(), id);
        let observe = || {
            let socket = session.kcp_socket().lock();
            let (first, retransmitted, acknowledged) = socket.traffic_stats();
            Observation { acknowledged, first, retransmitted, queued: socket.pending_segments(), rtt_ms: socket.srtt(), mss: socket.segment_size() }
        };
        let mut controller = Controller::new(options.clone(), gaming, Instant::now(), observe());
        let mut interval = tokio::time::interval(Duration::from_millis(25));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let mut decision = controller.update(Instant::now(), observe());
            if options.shared_bandwidth {
                decision.rate = shared().lock().unwrap_or_else(|e|e.into_inner()).allocate(&path, id, Instant::now(), decision.rate, decision.loaded, decision.clean);
            }
            {
                let mut socket = session.kcp_socket().lock();
                socket.set_window_size(decision.window, options.max_window.max(1024));
                // A reliable TCP underlay handles its own loss; avoid premature
                // nested KCP retransmit bursts while still bounding recovery.
                socket.set_controller_min_rto(if lane_active(){decision.min_rto_ms.max(600)}else{decision.min_rto_ms});
                socket.set_pacing_rate(decision.rate);
            }
            session.notify();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation() -> Observation { Observation { acknowledged:0, first:0, retransmitted:0, queued:1024, rtt_ms:40, mss:1200 } }
    #[test]
    fn queue_inflation_reduces_rate_and_all_outputs_are_bounded() {
        let options = AdaptiveOptions::default();
        let now = Instant::now();
        let mut control = Controller::new(options.clone(), true, now, observation());
        let clean = control.update(now + Duration::from_millis(100), observation());
        let mut busy = observation(); busy.rtt_ms = 300;
        let congested = control.update(now + Duration::from_millis(200), busy);
        assert!(congested.rate <= clean.rate);
        assert!(!congested.clean);
        assert!((options.min_window..=options.max_window).contains(&congested.window));
        assert!((30..=2000).contains(&congested.min_rto_ms));
    }
    #[test]
    fn allocator_is_path_scoped_expires_and_releases_members() {
        let now = Instant::now(); let mut allocator = Allocator::default();
        assert_eq!(allocator.allocate("a",1,now,1_000_000,true,true),1_000_000);
        assert_eq!(allocator.allocate("a",2,now,1_000_000,true,true),510_000);
        assert_eq!(allocator.allocate("b",3,now,1_000_000,true,true),1_000_000);
        allocator.remove("a",1);
        assert_eq!(allocator.allocate("a",2,now,1_000_000,true,true),1_000_000);
        assert_eq!(allocator.allocate("a",4,now+Duration::from_secs(1),1_000_000,true,true),1_000_000);
        assert_eq!(allocator.paths.len(),1);
    }
    #[test]
    fn invalid_settings_and_backwards_samples_do_not_create_unbounded_rates() {
        let mut options = AdaptiveOptions::default(); options.shared_bandwidth = true;
        assert!(options.validate().is_err()); options.enabled = true; assert!(options.validate().is_ok());
        let now = Instant::now(); let mut initial=observation(); initial.acknowledged=u64::MAX;
        let mut control=Controller::new(options.clone(),false,now,initial);
        let decision=control.update(now+Duration::from_secs(1),observation());
        assert!(decision.rate<=options.max_rate);
        assert_eq!(control.update(now,observation()).rate,decision.rate);
    }

    #[test]
    fn allocator_feedback_does_not_repeatedly_divide_an_existing_share() {
        let now=Instant::now(); let mut allocator=Allocator::default();
        allocator.allocate("path",1,now,1_000_000,true,true);
        let mut share=allocator.allocate("path",2,now,1_000_000,true,true);
        for tick in 1..100 {
            let time=now+Duration::from_millis(tick*25);
            allocator.allocate("path",1,time,share,true,true);
            share=allocator.allocate("path",2,time,share,true,true);
            assert_eq!(share,510_000);
        }
    }

    #[test]
    fn below_window_queue_can_grow_a_clean_pacing_limited_path() {
        let now=Instant::now(); let mut initial=observation(); initial.queued=4;
        let mut control=Controller::new(AdaptiveOptions::default(),false,now,initial);
        let initial_rate=control.rate;
        for tick in 1..=40 {
            let mut sample=initial; sample.acknowledged=tick*2500; sample.first=tick*3;
            control.update(now+Duration::from_millis(tick*25),sample);
        }
        assert!(control.rate>initial_rate*2.0);
    }

    #[test]
    fn paced_kcp_ack_metrics_count_payload_once_and_do_not_starve_short_flows() {
        use std::io::{self, Write};
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<Vec<u8>>>>);
        impl Write for Capture {
            fn write(&mut self, bytes:&[u8])->io::Result<usize>{self.0.lock().unwrap().push(bytes.to_vec());Ok(bytes.len())}
            fn flush(&mut self)->io::Result<()>{Ok(())}
        }
        let aout=Arc::new(Mutex::new(Vec::new())); let bout=Arc::new(Mutex::new(Vec::new()));
        let mut a=kcp::Kcp::new_stream(77,Capture(aout.clone()));
        let mut b=kcp::Kcp::new_stream(77,Capture(bout.clone()));
        a.set_nodelay(true,10,2,true); b.set_nodelay(true,10,2,true);
        a.set_wndsize(128,128); b.set_wndsize(128,128);
        a.set_pacing_rate(64_000);
        let data=vec![17;16*1024]; a.send(&data).unwrap();
        let mut received=Vec::new(); let mut buffer=vec![0;32*1024];
        let mut duplicate_ack=None;
        for time in (0..3000).step_by(10) {
            a.update(time).unwrap(); b.update(time).unwrap();
            for packet in std::mem::take(&mut *aout.lock().unwrap()) { b.input(&packet).unwrap(); }
            for packet in std::mem::take(&mut *bout.lock().unwrap()) {
                duplicate_ack=Some(packet.clone()); a.input(&packet).unwrap();
            }
            while let Ok(size)=b.recv(&mut buffer) { received.extend_from_slice(&buffer[..size]); }
            if received.len()==data.len() && a.wait_snd()==0 {break;}
        }
        assert_eq!(received,data);
        let (first,_,acked)=a.traffic_stats(); assert!(first>1); assert_eq!(acked,data.len() as u64);
        if let Some(packet)=duplicate_ack { a.input(&packet).unwrap(); }
        assert_eq!(a.traffic_stats().2,acked);
    }
    #[test]
    fn ack_only_flush_emits_a_small_tail_without_waiting_for_an_update_tick(){
        use std::io::{self,Write};
        #[derive(Clone)]struct Capture(Arc<Mutex<Vec<Vec<u8>>>>);
        impl Write for Capture{fn write(&mut self,data:&[u8])->io::Result<usize>{self.0.lock().unwrap().push(data.to_vec());Ok(data.len())}fn flush(&mut self)->io::Result<()>{Ok(())}}
        let sent=Arc::new(Mutex::new(Vec::new()));let acked=Arc::new(Mutex::new(Vec::new()));
        let mut sender=kcp::Kcp::new_stream(991,Capture(sent.clone()));let mut receiver=kcp::Kcp::new_stream(991,Capture(acked.clone()));
        sender.set_nodelay(true,10,2,true);receiver.set_nodelay(true,10,2,true);sender.update(0).unwrap();receiver.update(0).unwrap();
        sender.send(b"one").unwrap();sender.flush().unwrap();
        for packet in std::mem::take(&mut *sent.lock().unwrap()){receiver.input(&packet).unwrap();}
        assert!(acked.lock().unwrap().is_empty());receiver.flush_ack().unwrap();
        let packets=std::mem::take(&mut *acked.lock().unwrap());assert_eq!(packets.len(),1,"ACK-only flush retained its final partial buffer");
        for packet in packets{sender.input(&packet).unwrap();}assert_eq!(sender.wait_snd(),0);
    }
    #[test]
    fn deferred_timeout_burst_respects_positive_next_update_and_spacing(){
        use std::io::{self,Write};
        #[derive(Clone)]struct Capture(Arc<Mutex<Vec<Vec<u8>>>>);
        impl Write for Capture{fn write(&mut self,data:&[u8])->io::Result<usize>{self.0.lock().unwrap().push(data.to_vec());Ok(data.len())}fn flush(&mut self)->io::Result<()>{Ok(())}}
        let out=Arc::new(Mutex::new(Vec::new()));let mut kcp=kcp::Kcp::new_stream(818,Capture(out.clone()));
        kcp.set_nodelay(true,10,2,true);kcp.set_wndsize(32,32);kcp.set_resend_burst(1);kcp.update(0).unwrap();
        let payload=vec![8;kcp.mss()*4];kcp.send(&payload).unwrap();kcp.flush().unwrap();out.lock().unwrap().clear();
        kcp.update(250).unwrap();let first=std::mem::take(&mut *out.lock().unwrap());assert!(!first.is_empty());
        let delay=kcp.check(250);assert!(delay>0&&delay<=10,"deferred packets caused zero-delay scheduling: {delay}");
        kcp.update(251).unwrap();assert!(out.lock().unwrap().is_empty(),"same burst escaped configured update interval");
        kcp.update(250+delay).unwrap();assert!(!out.lock().unwrap().is_empty());
    }
}
