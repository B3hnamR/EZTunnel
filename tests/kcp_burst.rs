//! The vendored KCP core: after a retransmission timeout, at most `resend_burst` segments go out
//! per flush, and every timed-out segment is still resent within a few flushes. Before 0.8.5 the
//! whole window (with congestion control off) was resent in one burst.
use kcp::Kcp;
use std::{
    cell::RefCell,
    io::{self, Write},
    rc::Rc,
};

/// Collects what KCP sends: one entry per packet.
#[derive(Clone, Default)]
struct Wire(Rc<RefCell<Vec<Vec<u8>>>>);

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().push(buf.to_vec());
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const PUSH: u8 = 81;
const WINDOW: usize = 128;

/// The sequence numbers of the data segments in `packets` (a packet can hold several segments).
fn pushed(packets: &[Vec<u8>]) -> Vec<u32> {
    let mut found = Vec::new();
    for packet in packets {
        let mut rest = packet.as_slice();
        while rest.len() >= 24 {
            let command = rest[4];
            let sequence = u32::from_le_bytes(rest[12..16].try_into().unwrap());
            let length = u32::from_le_bytes(rest[20..24].try_into().unwrap()) as usize;
            if command == PUSH {
                found.push(sequence);
            }
            rest = &rest[(24 + length).min(rest.len())..];
        }
    }
    found
}

/// A sender with a full window in flight and no acknowledgement ever coming back. Without a word
/// from the peer KCP assumes its receive window is 128 segments, so 128 are in flight.
fn stalled(burst: u32) -> (Kcp<Wire>, Wire) {
    let wire = Wire::default();
    let mut kcp = Kcp::new(7, wire.clone());
    kcp.set_mtu(1400).unwrap();
    kcp.set_nodelay(true, 10, 2, true);
    kcp.set_wndsize(1024, 1024);
    kcp.set_resend_burst(burst);
    let segment = vec![0u8; 1000];
    for _ in 0..WINDOW {
        kcp.send(&segment).unwrap();
    }
    kcp.update(0).unwrap();
    assert_eq!(
        pushed(&wire.0.borrow()).len(),
        WINDOW,
        "the window goes out once"
    );
    wire.0.borrow_mut().clear();
    (kcp, wire)
}

#[test]
fn a_timeout_resends_at_most_the_burst_per_flush_and_everything_soon() {
    let (mut kcp, wire) = stalled(32);
    let mut resent = std::collections::BTreeSet::new();
    let mut per_flush = Vec::new();
    // The first timer expires after about 200 ms; then one flush every 10 ms.
    for now in (10..=400).step_by(10) {
        kcp.update(now).unwrap();
        let sent = pushed(&wire.0.borrow());
        wire.0.borrow_mut().clear();
        if !sent.is_empty() {
            per_flush.push(sent.len());
            resent.extend(sent);
        }
    }
    assert!(per_flush.iter().all(|&count| count <= 32), "{per_flush:?}");
    assert_eq!(
        resent.len(),
        WINDOW,
        "every segment was resent: {per_flush:?}"
    );
    // The first flush after the timeout resent a full burst, the next ones the rest.
    assert_eq!(per_flush[0], 32);
}

#[test]
fn no_limit_keeps_the_upstream_burst() {
    let (mut kcp, wire) = stalled(0);
    let mut first = None;
    for now in (10..=400).step_by(10) {
        kcp.update(now).unwrap();
        let sent = pushed(&wire.0.borrow()).len();
        wire.0.borrow_mut().clear();
        if sent > 0 && first.is_none() {
            first = Some(sent);
        }
    }
    assert_eq!(first, Some(WINDOW));
}

#[test]
fn malformed_allocation_does_not_change_the_conversation() {
    let mut core = Kcp::new(0, Wire::default());
    core.input_conv();
    let mut packet = vec![0u8; 24];
    packet[..4].copy_from_slice(&5678u32.to_le_bytes());
    packet[4] = 255; // invalid command
    assert!(core.input(&packet).is_err());
    assert_eq!(core.conv(), 0);
    assert!(core.waiting_conv());
    packet[4] = PUSH;
    packet[20..24].copy_from_slice(&1u32.to_le_bytes()); // missing payload
    assert!(core.input(&packet).is_err());
    assert_eq!(core.conv(), 0);
    assert!(core.waiting_conv());
    packet.push(42);
    core.input(&packet).unwrap();
    assert_eq!(core.conv(), 5678);
    assert!(!core.waiting_conv());
}
