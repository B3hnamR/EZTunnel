use std::{
    io::{self, ErrorKind, Write},
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use futures_util::future;
use kcp::{Error as KcpError, Kcp, KcpResult};
use log::{error, trace};
use tokio::net::UdpSocket;

use crate::{batch::Outgoing, sink::{PacketSink, UdpSink}, utils::now_millis, KcpConfig};

/// The packets KCP has produced and not yet handed to the network. KCP writes them one by one
/// while it works; `KcpSocket::send_batch` then hands everything it produced to the sink at once
/// (one system call for a UDP socket).
#[derive(Debug)]
struct OutputState {
    sink: Arc<dyn PacketSink>,
    pending: Outgoing,
}

type SharedOutput = Arc<Mutex<OutputState>>;

/// Writer KCP uses for its packets: it only collects them.
struct UdpOutput {
    state: SharedOutput,
}

impl UdpOutput {
    fn new(sink: Arc<dyn PacketSink>) -> (UdpOutput, SharedOutput) {
        let state = Arc::new(Mutex::new(OutputState {
            sink,
            pending: Outgoing::default(),
        }));
        (
            UdpOutput {
                state: state.clone(),
            },
            state,
        )
    }
}

impl Write for UdpOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending
            .push(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct KcpSocket {
    kcp: Kcp<UdpOutput>,
    output: SharedOutput,
    last_update: Instant,
    /// The UDP socket the session reads from itself (client sessions over a plain UDP socket).
    /// `None` when the packets come in through `KcpSession::input_direct` instead.
    socket: Option<Arc<UdpSocket>>,
    flush_write: bool,
    flush_ack_input: bool,
    sent_first: bool,
    pending_sender: Option<Waker>,
    pending_receiver: Option<Waker>,
    pending_drainer:Option<Waker>,
    closed: bool,
    allow_recv_empty_packet: bool,
}

impl KcpSocket {
    /// Local controller telemetry; no protocol change or peer authority implied.
    pub fn traffic_stats(&self) -> (u64, u64, u64) {
        self.kcp.traffic_stats()
    }

    pub fn set_controller_min_rto(&mut self, milliseconds: u32) {
        self.kcp.set_controller_min_rto(milliseconds);
    }

    pub fn set_pacing_rate(&mut self, bytes_per_second: u64) {
        self.kcp.set_pacing_rate(bytes_per_second);
    }

    pub fn pending_segments(&self) -> usize {
        self.kcp.wait_snd()
    }

    pub fn segment_size(&self) -> usize {
        self.kcp.mss()
    }
    pub fn new(
        c: &KcpConfig,
        conv: u32,
        socket: Arc<UdpSocket>,
        target_addr: SocketAddr,
        stream: bool,
    ) -> KcpResult<KcpSocket> {
        let sink = Arc::new(UdpSink::new(socket.clone(), target_addr));
        KcpSocket::build(c, conv, sink, Some(socket), stream)
    }

    /// A session whose packets go to `sink` instead of a UDP socket. Its incoming packets must be
    /// handed to `KcpSession::input_direct`.
    pub fn with_sink(
        c: &KcpConfig,
        conv: u32,
        sink: Arc<dyn PacketSink>,
        stream: bool,
    ) -> KcpResult<KcpSocket> {
        KcpSocket::build(c, conv, sink, None, stream)
    }

    fn build(
        c: &KcpConfig,
        conv: u32,
        sink: Arc<dyn PacketSink>,
        socket: Option<Arc<UdpSocket>>,
        stream: bool,
    ) -> KcpResult<KcpSocket> {
        let (output, shared_output) = UdpOutput::new(sink);
        let mut kcp = if stream {
            Kcp::new_stream(conv, output)
        } else {
            Kcp::new(conv, output)
        };
        c.apply_config(&mut kcp);

        // Ask server to allocate one
        if conv == 0 {
            kcp.input_conv();
        }

        kcp.update(now_millis())?;

        let mut created = KcpSocket {
            kcp,
            output: shared_output,
            last_update: Instant::now(),
            socket,
            flush_write: c.flush_write,
            flush_ack_input: c.flush_acks_input,
            sent_first: false,
            pending_sender: None,
            pending_receiver: None,
            pending_drainer:None,
            closed: false,
            allow_recv_empty_packet: c.allow_recv_empty_packet,
        };
        created.send_batch();
        Ok(created)
    }

    /// Hands the packets KCP produced since the last call to the sink, all at once.
    fn send_batch(&mut self) {
        let mut state = self
            .output
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.pending.is_empty() {
            return;
        }
        if let Err(err) = state.sink.send_batch(&state.pending) {
            error!("[SEND] send failed, error: {}", err);
        }
        state.pending.clear();
    }

    /// Call every time you got data from transmission
    pub fn input(&mut self, buf: &[u8]) -> KcpResult<bool> {
        let result = self.input_inner(buf);
        self.send_batch();
        result
    }

    fn input_inner(&mut self, buf: &[u8]) -> KcpResult<bool> {
        match self.kcp.input(buf) {
            Ok(..) => {}
            Err(KcpError::ConvInconsistent(expected, actual)) => {
                trace!(
                    "[INPUT] Conv expected={} actual={} ignored",
                    expected,
                    actual
                );
                return Ok(false);
            }
            Err(err) => return Err(err),
        }
        self.last_update = Instant::now();

        if self.flush_ack_input {
            self.kcp.flush_ack()?;
        }

        Ok(self.try_wake_pending_waker())
    }

    /// Call if you want to send some data
    pub fn poll_send(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<KcpResult<usize>> {
        let result = self.poll_send_inner(cx, buf);
        self.send_batch();
        result
    }

    fn poll_send_inner(&mut self, cx: &mut Context<'_>, mut buf: &[u8]) -> Poll<KcpResult<usize>> {
        if self.closed {
            return Err(io::Error::from(ErrorKind::BrokenPipe).into()).into();
        }

        // If:
        //     1. Have sent the first packet (asking for conv)
        //     2. Too many pending packets, or the sink's own queue is close to full
        // The sink check (eztunnel: FecSink, whose queue is bounded and otherwise drops instead
        // of blocking inside send_batch, which may not wait) turns a drop-then-KCP-resend round
        // trip into ordinary backpressure: the writer waits here instead of the packet being
        // queued past the sink's own limit and lost.
        let sink_congested = self
            .output
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sink
            .congested();
        if self.sent_first
            && (self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize
                || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize
                || self.kcp.waiting_conv()
                || sink_congested)
        {
            trace!(
                "[SEND] waitsnd={} sndwnd={} rmtwnd={} excceeded or waiting conv={} or sink congested={}",
                self.kcp.wait_snd(),
                self.kcp.snd_wnd(),
                self.kcp.rmt_wnd(),
                self.kcp.waiting_conv(),
                sink_congested
            );

            if let Some(waker) = self.pending_sender.replace(cx.waker().clone()) {
                if !cx.waker().will_wake(&waker) {
                    waker.wake();
                }
            }
            return Poll::Pending;
        }

        if !self.sent_first && self.kcp.waiting_conv() && buf.len() > self.kcp.mss() {
            buf = &buf[..self.kcp.mss()];
        }

        let n = self.kcp.send(buf)?;
        self.sent_first = true;

        if self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize
            || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize
        {
            self.kcp.flush()?;
        }

        self.last_update = Instant::now();

        if self.flush_write {
            self.kcp.flush()?;
        }

        Ok(n).into()
    }

    /// Call if you want to send some data
    #[allow(dead_code)]
    pub async fn send(&mut self, buf: &[u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_send(cx, buf)).await
    }

    #[allow(dead_code)]
    pub fn try_recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        if self.closed {
            return Ok(0);
        }
        self.kcp.recv(buf)
    }

    pub fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<KcpResult<usize>> {
        if self.closed {
            return Ok(0).into();
        }

        match self.kcp.recv(buf) {
            e @ (Err(KcpError::RecvQueueEmpty) | Err(KcpError::ExpectingFragment)) => {
                trace!(
                    "[RECV] rcvwnd={} peeksize={} r={:?}",
                    self.kcp.rcv_wnd(),
                    self.kcp.peeksize().unwrap_or(0),
                    e
                );
            }
            Err(err) => return Err(err).into(),
            Ok(n) => {
                if n == 0 && !self.allow_recv_empty_packet {
                    trace!(
                        "[RECV] rcvwnd={} peeksize={} r=Ok(0)",
                        self.kcp.rcv_wnd(),
                        self.kcp.peeksize().unwrap_or(0),
                    );
                } else {
                    self.last_update = Instant::now();
                    return Ok(n).into();
                }
            }
        }

        if let Some(waker) = self.pending_receiver.replace(cx.waker().clone()) {
            if !cx.waker().will_wake(&waker) {
                waker.wake();
            }
        }

        Poll::Pending
    }

    #[allow(dead_code)]
    pub async fn recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    pub fn flush(&mut self) -> KcpResult<()> {
        let result = self.kcp.flush();
        self.send_batch();
        result?;
        self.last_update = Instant::now();
        Ok(())
    }

    fn try_wake_pending_waker(&mut self) -> bool {
        let mut waked = false;
        if self.kcp.queued_unsent()==0{if let Some(waker)=self.pending_drainer.take(){waker.wake();waked=true;}}

        if self.pending_sender.is_some()
            && self.kcp.wait_snd() < self.kcp.snd_wnd() as usize
            && self.kcp.wait_snd() < self.kcp.rmt_wnd() as usize
            && !self.kcp.waiting_conv()
            && !self
                .output
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .sink
                .congested()
        {
            let waker = self.pending_sender.take().unwrap();
            waker.wake();

            waked = true;
        }

        if self.pending_receiver.is_some() {
            if let Ok(peek) = self.kcp.peeksize() {
                if self.allow_recv_empty_packet || peek > 0 {
                    let waker = self.pending_receiver.take().unwrap();
                    waker.wake();

                    waked = true;
                }
            }
        }

        waked
    }

    pub fn update(&mut self) -> KcpResult<Instant> {
        let now = now_millis();
        let updated = self.kcp.update(now);
        self.send_batch();
        updated?;
        let next = self.kcp.check(now);

        self.try_wake_pending_waker();

        Ok(Instant::now() + Duration::from_millis(next as u64))
    }

    pub fn close(&mut self) {
        self.closed = true;
        if let Some(waker)=self.pending_drainer.take(){waker.wake();}
        if let Some(w) = self.pending_sender.take() {
            w.wake();
        }
        if let Some(w) = self.pending_receiver.take() {
            w.wake();
        }
    }
    pub fn is_closed(&self)->bool{self.closed}

    pub fn udp_socket(&self) -> Option<&Arc<UdpSocket>> {
        self.socket.as_ref()
    }

    /// Feeds several packets that arrived together: each is input, the acknowledgements they
    /// ask for are flushed once, and everything produced goes out in one batch.
    pub fn input_batch<'a>(&mut self, packets: impl IntoIterator<Item = &'a [u8]>) -> bool {
        let mut waked = false;
        let mut accepted = false;
        for packet in packets {
            match self.kcp.input(packet) {
                Ok(..) => accepted = true,
                Err(KcpError::ConvInconsistent(expected, actual)) => {
                    trace!(
                        "[INPUT] Conv expected={} actual={} ignored",
                        expected,
                        actual
                    );
                }
                Err(err) => trace!("[INPUT] kcp input failed: {}", err),
            }
        }
        if accepted {
            self.last_update = Instant::now();
            if self.flush_ack_input {
                let _ = self.kcp.flush_ack();
            }
            waked = self.try_wake_pending_waker();
        }
        self.send_batch();
        waked
    }

    pub fn can_close(&self) -> bool {
        self.kcp.wait_snd() == 0
    }
    pub fn poll_drain(&mut self,cx:&mut Context<'_>)->Poll<KcpResult<()>>{
        if let Err(error)=self.flush(){return Poll::Ready(Err(error));}
        if self.kcp.queued_unsent()==0{return Poll::Ready(Ok(()));}
        if self.closed{return Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe).into()));}
        self.pending_drainer=Some(cx.waker().clone());Poll::Pending
    }

    /// Smoothed round-trip time in milliseconds (0 before the first sample). eztunnel's FEC
    /// pacer reads this; nothing in tokio_kcp itself uses it.
    pub fn srtt(&self) -> u32 {
        self.kcp.srtt()
    }

    pub fn conv(&self) -> u32 {
        self.kcp.conv()
    }

    pub fn set_conv(&mut self, conv: u32) {
        self.kcp.set_conv(conv);
    }

    pub fn waiting_conv(&self) -> bool {
        self.kcp.waiting_conv()
    }

    pub fn peek_size(&self) -> KcpResult<usize> {
        self.kcp.peeksize()
    }

    pub fn last_update_time(&self) -> Instant {
        self.last_update
    }

    pub fn need_flush(&self) -> bool {
        (self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize
            || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize)
            && !self.kcp.waiting_conv()
    }

    /// Changes live flow-control windows while the session lock is held.
    /// Added by eztunnel for its explicitly enabled local adaptive tuner.
    pub fn set_window_size(&mut self, send: u16, receive: u16) {
        self.kcp.set_wndsize(send, receive);
    }
}

#[cfg(test)]
mod test {

    use kcp::Error as KcpError;
    use log::trace;
    use std::sync::Arc;
    use tokio::{
        net::UdpSocket,
        sync::Mutex,
        time::{self, Instant},
    };

    use super::KcpSocket;
    use crate::config::KcpConfig;

    #[tokio::test]
    async fn kcp_echo() {
        let _ = env_logger::try_init();

        static CONV: u32 = 0xdeadbeef;

        // s1 connects s2
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let s1_addr = s1.local_addr().unwrap();
        let s2_addr = s2.local_addr().unwrap();

        let s1 = Arc::new(s1);
        let s2 = Arc::new(s2);

        let config = KcpConfig::default();
        let kcp1 = KcpSocket::new(&config, 0, s1.clone(), s2_addr, true).unwrap();
        let kcp2 = KcpSocket::new(&config, CONV, s2.clone(), s1_addr, true).unwrap();

        let kcp1 = Arc::new(Mutex::new(kcp1));
        let kcp2 = Arc::new(Mutex::new(kcp2));

        let kcp1_task = {
            let kcp1 = kcp1.clone();
            tokio::spawn(async move {
                loop {
                    let mut kcp = kcp1.lock().await;
                    let next = kcp.update().expect("update");
                    trace!("kcp1 next tick {:?}", next);
                    time::sleep_until(Instant::from_std(next)).await;
                }
            })
        };

        let kcp2_task = {
            let kcp2 = kcp2.clone();
            tokio::spawn(async move {
                loop {
                    let mut kcp = kcp2.lock().await;
                    let next = kcp.update().expect("update");
                    trace!("kcp2 next tick {:?}", next);
                    time::sleep_until(Instant::from_std(next)).await;
                }
            })
        };

        const SEND_BUFFER: &[u8] = b"HELLO WORLD";

        {
            let n = kcp1.lock().await.send(SEND_BUFFER).await.unwrap();
            assert_eq!(n, SEND_BUFFER.len());
        }

        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            loop {
                let n = s2.recv(&mut buf).await.unwrap();

                let packet = &mut buf[..n];

                let conv = kcp::get_conv(packet);
                if conv == 0 {
                    kcp::set_conv(packet, CONV);
                }

                let mut kcp2 = kcp2.lock().await;
                kcp2.input(packet).unwrap();

                match kcp2.try_recv(&mut buf) {
                    Ok(n) => {
                        let received = &buf[..n];
                        kcp2.send(received).await.unwrap();
                    }
                    Err(KcpError::RecvQueueEmpty) => {
                        continue;
                    }
                    Err(err) => {
                        panic!("kcp.recv error: {:?}", err);
                    }
                }
            }
        });

        {
            let mut buf = [0u8; 1024];

            loop {
                let n = s1.recv(&mut buf).await.unwrap();

                let packet = &buf[..n];

                let mut kcp1 = kcp1.lock().await;
                kcp1.input(packet).unwrap();

                match kcp1.try_recv(&mut buf) {
                    Ok(n) => {
                        let received = &buf[..n];
                        assert_eq!(received, SEND_BUFFER);
                        break;
                    }
                    Err(KcpError::RecvQueueEmpty) => {
                        continue;
                    }
                    Err(err) => {
                        panic!("kcp.recv error: {:?}", err);
                    }
                }
            }
        }

        echo_task.abort();
        kcp1_task.abort();
        kcp2_task.abort();
    }
}
