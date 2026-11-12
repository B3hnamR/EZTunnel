//! Where the packets of a KCP session go.
//!
//! A session normally writes straight to a UDP socket (`UdpSink`). Added by eztunnel so the FEC
//! carrier can encode and send the packets itself, without a loopback socket in between.
use std::{fmt, io, net::SocketAddr, sync::Arc};

use log::error;
use tokio::{net::UdpSocket, sync::mpsc};

use crate::batch::Outgoing;

/// Takes the packets a KCP session produces. `send_batch` is called with the session lock held,
/// so it must not wait: whatever the network cannot take right now has to be queued or dropped
/// (KCP resends what is lost).
pub trait PacketSink: Send + Sync + fmt::Debug + 'static {
    fn send_batch(&self, packets: &Outgoing) -> io::Result<()>;

    /// Whether the sink's own queue of packets the network has not taken yet is close to full.
    /// `poll_send` treats this the same as the KCP send window being full: it returns `Pending`
    /// instead of handing the sink another packet to queue (or drop). A sink with no such queue
    /// reports pressure before accepting more stream data.
    fn congested(&self) -> bool {
        false
    }
}

/// Writes packets to a UDP socket, many per system call. A socket whose buffer is full takes
/// only some; the rest follow through a queue, so none is lost.
#[derive(Debug)]
pub struct UdpSink {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    delay_tx: mpsc::Sender<Vec<u8>>,
    task:tokio::task::JoinHandle<()>,
}

impl UdpSink {
    /// Must be called inside a Tokio runtime: it starts the task that sends the delayed packets.
    pub fn new(socket: Arc<UdpSocket>, target: SocketAddr) -> Self {
        let (delay_tx, mut delay_rx) = mpsc::channel::<Vec<u8>>(256);
        let delayed_socket = socket.clone();
        let task=tokio::spawn(async move {
            while let Some(buf) = delay_rx.recv().await {
                if let Err(err) = delayed_socket.send_to(&buf, target).await {
                    error!("[SEND] UDP delayed send failed, error: {}", err);
                }
            }
        });
        Self {
            socket,
            target,
            delay_tx,
            task,
        }
    }
}

impl PacketSink for UdpSink {
    fn congested(&self)->bool{self.delay_tx.capacity()<64}
    fn send_batch(&self, packets: &Outgoing) -> io::Result<()> {
        let total = packets.len();
        let sent = match packets.send(&self.socket, Some(self.target)) {
            Ok(sent) => sent,
            Err(err) => {
                error!("[SEND] UDP send failed, error: {}", err);
                total
            }
        };
        for packet in packets.iter().skip(sent) {
            log::trace!("[SEND] UDP send EAGAIN, delayed send");
            // Bounded local queue; overflow is ordinary packet loss, retained
            // KCP state retransmits it instead of allocating without limit.
            let _ = self.delay_tx.try_send(packet.to_vec());
        }
        Ok(())
    }
}
impl Drop for UdpSink{fn drop(&mut self){self.task.abort();}}
