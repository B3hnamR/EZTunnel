//! Saying goodbye before stopping. A side that stops tells every connected peer first, inside the
//! encrypted session, so the peer drops that session at once and reconnects as soon as this side is
//! back. Without it a peer on a connectionless carrier (UDP, KCP, FEC, raw) only notices after
//! `dead_timeout_sec` of silence, and a server keeps sending users to the dead session meanwhile.
use crate::wire::Frame;
use std::sync::Mutex;
use tokio::sync::mpsc;

/// The notice: `Close` for stream 0, which no stream can use. Peers older than 0.7.8 refuse the
/// frame and end the session, which is also the right outcome.
pub const GOODBYE: Frame = Frame::Close { id: 0 };

pub fn is_goodbye(frame: &Frame) -> bool {
    matches!(frame, Frame::Close { id: 0 })
}

/// Why a session ended when the peer said goodbye. Reconnect loops look for it to retry quickly.
#[derive(Debug)]
pub struct PeerStopped;

impl std::fmt::Display for PeerStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the other server is stopping or restarting")
    }
}

impl std::error::Error for PeerStopped {}

/// Whether `error` is (or wraps) a goodbye from the peer.
pub fn peer_stopped(error: &anyhow::Error) -> bool {
    error.is::<PeerStopped>()
}

/// The sessions to tell. Weak, so a finished session is not kept alive by this list.
#[derive(Default)]
pub struct Farewell {
    sessions: Mutex<Vec<mpsc::WeakSender<Frame>>>,
    /// Set by `send`: this side is about to exit, so its listeners take no new connections (a
    /// peer reconnecting at once would get a session that dies a moment later).
    stopping: std::sync::atomic::AtomicBool,
}

impl Farewell {
    /// Adds a session's out-of-band sender (frames on it overtake queued user data).
    pub fn register(&self, sender: &mpsc::Sender<Frame>) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|session| session.strong_count() > 0);
        sessions.push(sender.downgrade());
    }

    /// Whether the goodbye was sent (this side is stopping).
    pub fn stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Queues the goodbye on every live session and returns how many were told.
    pub fn send(&self) -> usize {
        self.stopping
            .store(true, std::sync::atomic::Ordering::Release);
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|session| session.strong_count() > 0);
        sessions
            .iter()
            .filter_map(mpsc::WeakSender::upgrade)
            .filter(|sender| sender.try_send(GOODBYE).is_ok())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_goodbye_survives_the_wire_and_no_stream_frame_uses_stream_zero() {
        let bytes = GOODBYE.encode().expect("encode");
        let decoded = Frame::decode(&bytes).expect("decode");
        assert!(is_goodbye(&decoded));
        let padded = GOODBYE.encode_padded(7).expect("padded");
        assert!(is_goodbye(&Frame::decode(&padded).expect("decode padded")));
        // Every other frame still refuses stream 0.
        assert!(Frame::Eof { id: 0 }.encode().is_err());
        assert!(
            Frame::Data {
                id: 0,
                data: vec![1]
            }
            .encode()
            .is_err()
        );
        let mut eof = Frame::Eof { id: 1 }.encode().unwrap();
        eof[1..5].copy_from_slice(&0u32.to_be_bytes());
        assert!(Frame::decode(&eof).is_err());
    }

    #[test]
    fn after_the_goodbye_this_side_counts_as_stopping() {
        let farewell = Farewell::default();
        assert!(!farewell.stopping());
        farewell.send();
        assert!(farewell.stopping());
    }

    #[test]
    fn only_live_sessions_are_told_and_finished_ones_are_forgotten() {
        let farewell = Farewell::default();
        let (live, mut live_rx) = mpsc::channel(4);
        let (gone, gone_rx) = mpsc::channel(4);
        farewell.register(&live);
        farewell.register(&gone);
        drop(gone);
        drop(gone_rx);
        assert_eq!(farewell.send(), 1);
        assert!(is_goodbye(&live_rx.try_recv().expect("told")));
        assert_eq!(farewell.sessions.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_goodbye_error_is_recognised_through_context() {
        let error = anyhow::Error::new(PeerStopped).context("tunnel session");
        assert!(peer_stopped(&error));
        assert!(!peer_stopped(&anyhow::anyhow!("tunnel heartbeat timeout")));
    }
}
