//! Two immediate data records plus one authenticated XOR parity record. All input
//! is inside the session AEAD before this cache is touched. No data waits for a pair.
use std::collections::{HashMap, VecDeque};
use tokio::time::{Duration, Instant};

pub(super) const TAG: u8 = 8;
pub(super) const OVERHEAD: usize = 14; // tag, group u64, slot, two u16 lengths
const GROUPS: usize = 64;
const KEEP: Duration = Duration::from_millis(250);
const MAX: usize = 16384;

struct Group {
    parts: [Option<Vec<u8>>; 2],
    parity: Option<Vec<u8>>,
    lengths: [usize; 2],
    created: Instant,
}
#[derive(Default)]
pub(super) struct Parity {
    next: u64,
    outgoing: Option<(u64, Vec<u8>, Instant)>,
    pending: HashMap<u64, Group>,
    completed: VecDeque<u64>,
    highest: Option<u64>,
}
fn record(group: u64, slot: u8, lengths: [usize; 2], bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![TAG];
    out.extend(group.to_be_bytes());
    out.push(slot);
    out.extend((lengths[0] as u16).to_be_bytes());
    out.extend((lengths[1] as u16).to_be_bytes());
    out.extend(bytes);
    out
}
impl Parity {
    fn retire(&mut self, group: u64) {
        self.pending.remove(&group);
        self.completed.push_back(group);
        if self.completed.len() > 512 {
            self.completed.pop_front();
        }
    }
    pub fn send(&mut self, data: &[u8]) -> Option<Vec<Vec<u8>>> {
        if data.is_empty() || data.len() > MAX {
            return None;
        }
        if self
            .outgoing
            .as_ref()
            .is_some_and(|(_, _, when)| when.elapsed() >= KEEP)
        {
            self.outgoing = None;
        }
        if let Some((group, first, _)) = self.outgoing.take() {
            let lengths = [first.len(), data.len()];
            let mut xor = vec![0; lengths[0].max(lengths[1])];
            for (n, b) in first.iter().enumerate() {
                xor[n] ^= b;
            }
            for (n, b) in data.iter().enumerate() {
                xor[n] ^= b;
            }
            Some(vec![
                record(group, 1, [0, data.len()], data),
                record(group, 2, lengths, &xor),
            ])
        } else {
            let group = self.next;
            self.next = self.next.checked_add(1)?;
            self.outgoing = Some((group, data.to_vec(), Instant::now()));
            Some(vec![record(group, 0, [data.len(), 0], data)])
        }
    }
    pub fn receive(&mut self, wire: &[u8]) -> Vec<Vec<u8>> {
        if wire.len() <= OVERHEAD || wire[0] != TAG {
            return vec![];
        }
        let group = u64::from_be_bytes(wire[1..9].try_into().unwrap());
        let slot = wire[9] as usize;
        let lengths = [
            u16::from_be_bytes(wire[10..12].try_into().unwrap()) as usize,
            u16::from_be_bytes(wire[12..14].try_into().unwrap()) as usize,
        ];
        let data = &wire[OVERHEAD..];
        if slot > 2
            || data.len() > MAX
            || lengths.iter().any(|n| *n > MAX)
            || (slot < 2 && (lengths[slot] != data.len() || lengths[1 - slot] != 0))
            || (slot == 2 && (lengths.contains(&0) || data.len() != lengths[0].max(lengths[1])))
            || self.completed.contains(&group)
        {
            return vec![];
        }
        if self
            .highest
            .is_some_and(|high| group < high.saturating_sub(255))
        {
            return vec![];
        }
        self.highest = Some(self.highest.map_or(group, |high| high.max(group)));
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, g)| g.created.elapsed() >= KEEP)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.retire(id);
        }
        if self.completed.contains(&group) {
            return vec![];
        }
        if !self.pending.contains_key(&group) && self.pending.len() >= GROUPS {
            if let Some(old) = self
                .pending
                .iter()
                .min_by_key(|(_, g)| g.created)
                .map(|(id, _)| *id)
            {
                self.retire(old);
            }
        }
        let state = self.pending.entry(group).or_insert_with(|| Group {
            parts: [None, None],
            parity: None,
            lengths: [0, 0],
            created: Instant::now(),
        });
        let mut ready = Vec::new();
        if slot < 2 {
            if state.parts[slot].is_some()
                || state.lengths[slot] != 0 && state.lengths[slot] != data.len()
            {
                return ready;
            }
            state.lengths[slot] = data.len();
            state.parts[slot] = Some(data.to_vec());
            ready.push(data.to_vec());
        } else {
            if state.parity.is_some()
                || state
                    .lengths
                    .iter()
                    .zip(lengths)
                    .any(|(old, new)| *old != 0 && *old != new)
            {
                return ready;
            }
            state.lengths = lengths;
            state.parity = Some(data.to_vec());
        }
        if state.parts.iter().filter(|p| p.is_some()).count() == 1 && state.parity.is_some() {
            let missing = usize::from(state.parts[0].is_some());
            let have = 1 - missing;
            let mut recovered = state.parity.as_ref().unwrap().clone();
            for (n, b) in state.parts[have].as_ref().unwrap().iter().enumerate() {
                recovered[n] ^= b;
            }
            recovered.truncate(state.lengths[missing]);
            state.parts[missing] = Some(recovered.clone());
            ready.push(recovered);
        }
        if state.parts.iter().all(|p| p.is_some()) {
            self.retire(group);
        }
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_single_loss_and_reordering_recovers_without_duplicates() {
        for lost in 0..3 {
            for order in [[0, 1, 2], [2, 1, 0], [1, 0, 2]] {
                let mut tx = Parity::default();
                let mut packets = tx.send(b"first").unwrap();
                packets.extend(tx.send(b"different second").unwrap());
                let mut rx = Parity::default();
                let mut data = Vec::new();
                for n in order {
                    if n != lost {
                        data.extend(rx.receive(&packets[n]));
                    }
                }
                data.sort();
                assert_eq!(data, vec![b"different second".to_vec(), b"first".to_vec()]);
                for p in packets {
                    assert!(rx.receive(&p).is_empty());
                }
            }
        }
    }
    #[tokio::test(start_paused = true)]
    async fn odd_packets_are_immediate_and_pending_state_expires() {
        let mut tx = Parity::default();
        let first = tx.send(b"first").unwrap();
        assert_eq!(first.len(), 1);
        let mut rx = Parity::default();
        assert_eq!(rx.receive(&first[0]), vec![b"first".to_vec()]);
        tokio::time::advance(KEEP).await;
        assert_eq!(tx.send(b"next").unwrap().len(), 1);
        for group in 1..200 {
            rx.receive(&record(group, 0, [1, 0], b"x"));
        }
        assert!(rx.pending.len() <= GROUPS);
    }
    #[tokio::test(start_paused = true)]
    async fn expired_partial_groups_cannot_redeliver_already_emitted_data() {
        let mut tx = Parity::default();
        let first = tx.send(b"a").unwrap();
        let rest = tx.send(b"b").unwrap();
        let mut rx = Parity::default();
        assert_eq!(rx.receive(&first[0]), vec![b"a".to_vec()]);
        tokio::time::advance(KEEP).await;
        for packet in rest {
            assert!(rx.receive(&packet).is_empty());
        }
    }
    #[test]
    fn malformed_lengths_and_two_losses_do_not_invent_data() {
        let mut rx = Parity::default();
        assert!(rx.receive(&record(0, 2, [100, 1], b"x")).is_empty());
        assert!(rx.pending.is_empty());
        assert!(rx.receive(&record(0, 2, [1, 1], b"x")).is_empty());
    }
}
