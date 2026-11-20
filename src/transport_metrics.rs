//! Process-local observations, not security decisions or high-cardinality peer labels.
use std::sync::atomic::{AtomicU64,Ordering::Relaxed};

pub static GAMING_CHANNELS:AtomicU64=AtomicU64::new(0);
/// Game datagrams that could not be sent on the game path (see `gaming::send_failed`).
pub static GAMING_SEND_FAILURES:AtomicU64=AtomicU64::new(0);
pub static GAMING_MIGRATIONS:AtomicU64=AtomicU64::new(0);
pub static GAMING_TX:AtomicU64=AtomicU64::new(0);
pub static GAMING_RX:AtomicU64=AtomicU64::new(0);
pub static GAMING_REJECTED:AtomicU64=AtomicU64::new(0);
pub static GAMING_FRAGMENTS:AtomicU64=AtomicU64::new(0);
/// Later copies of a gaming datagram that already arrived over another port (the race was won).
pub static GAMING_COPIES_ABSORBED:AtomicU64=AtomicU64::new(0);
pub static LANE_SESSIONS:AtomicU64=AtomicU64::new(0);
pub static LANE_TX:AtomicU64=AtomicU64::new(0);
pub static LANE_RX:AtomicU64=AtomicU64::new(0);
pub static HOP_CHANGES:AtomicU64=AtomicU64::new(0);
pub static HOP_RX:AtomicU64=AtomicU64::new(0);

pub fn snapshot()->serde_json::Value {
    serde_json::json!({"gaming_channels_validated":GAMING_CHANNELS.load(Relaxed),"gaming_send_failures":GAMING_SEND_FAILURES.load(Relaxed),
        "gaming_flow_migrations":GAMING_MIGRATIONS.load(Relaxed),"gaming_packets_sent":GAMING_TX.load(Relaxed),
        "gaming_packets_received":GAMING_RX.load(Relaxed),"gaming_packets_rejected":GAMING_REJECTED.load(Relaxed),
        "gaming_fragments_reassembled":GAMING_FRAGMENTS.load(Relaxed),
        "gaming_copies_absorbed":GAMING_COPIES_ABSORBED.load(Relaxed),
        "tcp_packet_lane_sessions":LANE_SESSIONS.load(Relaxed),"tcp_packet_lane_packets_sent":LANE_TX.load(Relaxed),
        "tcp_packet_lane_packets_received":LANE_RX.load(Relaxed),"raw_port_changes":HOP_CHANGES.load(Relaxed),
        "authenticated_hopping_packets_received":HOP_RX.load(Relaxed)})
}
