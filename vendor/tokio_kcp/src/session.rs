use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Debug},
    net::SocketAddr,
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
    time::Duration,
};

use byte_string::ByteStr;
use kcp::KcpResult;
use log::{debug, error, trace};
use spin::Mutex as SpinMutex;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Notify},
    time::{self, Instant},
};

use crate::{batch::Incoming, skcp::KcpSocket, KcpConfig};

pub struct KcpSession {
    socket: SpinMutex<KcpSocket>,
    closed: AtomicBool,
    session_expire: Duration,
    session_close_notifier: Option<(mpsc::Sender<(SocketAddr, Weak<KcpSession>)>, SocketAddr)>,
    input_tx: mpsc::Sender<Vec<u8>>,
    notifier: Notify,
}

impl Drop for KcpSession {
    fn drop(&mut self) {
        trace!(
            "[SESSION] KcpSession conv {} is dropping, closed? {}",
            self.socket.lock().conv(),
            self.closed.load(Ordering::Acquire),
        );
    }
}

impl Debug for KcpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KcpSession")
            .field("socket", self.socket.lock().deref())
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("session_expired", &self.session_expire)
            .field("session_close_notifier", &self.session_close_notifier)
            .field("input_tx", &self.input_tx)
            .field("notifier", &self.notifier)
            .finish()
    }
}

impl KcpSession {
    fn new(
        socket: KcpSocket,
        session_expire: Duration,
        session_close_notifier: Option<(mpsc::Sender<(SocketAddr, Weak<KcpSession>)>, SocketAddr)>,
        input_tx: mpsc::Sender<Vec<u8>>,
    ) -> KcpSession {
        KcpSession {
            socket: SpinMutex::new(socket),
            closed: AtomicBool::new(false),
            session_expire,
            session_close_notifier,
            input_tx,
            notifier: Notify::new(),
        }
    }

    pub fn new_shared(
        socket: KcpSocket,
        session_expire: Duration,
        session_close_notifier: Option<(mpsc::Sender<(SocketAddr, Weak<KcpSession>)>, SocketAddr)>,
    ) -> Arc<KcpSession> {
        let is_client = session_close_notifier.is_none();
        KcpSession::new_shared_as(socket, session_expire, session_close_notifier, is_client)
    }

    /// A server-side session that nobody else owns: it expires on its own when idle and is
    /// closed by `close`. Its packets arrive through `input_direct`. Added by eztunnel.
    pub fn new_shared_server(socket: KcpSocket, session_expire: Duration) -> Arc<KcpSession> {
        KcpSession::new_shared_as(socket, session_expire, None, false)
    }

    fn new_shared_as(
        socket: KcpSocket,
        session_expire: Duration,
        session_close_notifier: Option<(mpsc::Sender<(SocketAddr, Weak<KcpSession>)>, SocketAddr)>,
        is_client: bool,
    ) -> Arc<KcpSession> {
        let (input_tx, mut input_rx) = mpsc::channel(64);

        let udp_socket = socket.udp_socket().cloned();

        let session = Arc::new(KcpSession::new(
            socket,
            session_expire,
            session_close_notifier,
            input_tx,
        ));

        let io_task_handle = {
            let session = session.clone();
            tokio::spawn(async move {
                // Up to 64 datagrams per system call.
                let mut incoming = Incoming::new();

                loop {
                    tokio::select! {
                        // recv() then input()
                        // Drives the KCP machine forward
                        recv_result = async {
                            match &udp_socket {
                                Some(socket) => incoming.receive(socket).await,
                                None => std::future::pending().await,
                            }
                        }, if is_client => {
                            match recv_result {
                                Err(err) => {
                                    error!("[SESSION] UDP recv failed, error: {}", err);
                                }
                                Ok(count) => for index in 0..count {
                                    let (input_buffer, _) = incoming.packet(index);
                                    let n = input_buffer.len();

                                    if input_buffer.len() < kcp::KCP_OVERHEAD {
                                        debug!("packet too short, received {} bytes, but at least {} bytes",
                                               input_buffer.len(),
                                               kcp::KCP_OVERHEAD);
                                        continue;
                                    }

                                    let input_conv = kcp::get_conv(input_buffer);
                                    trace!("[SESSION] UDP recv {} bytes, conv: {}, going to input {:?}",
                                           n, input_conv, ByteStr::new(input_buffer));

                                    let mut socket = session.socket.lock();

                                    // Only the explicit conv=0 allocation path may learn an id.
                                    // An established conversation must never follow an incoming id.
                                    match socket.input(input_buffer) {
                                        Ok(true) => {
                                            trace!("[SESSION] UDP input {} bytes and waked sender/receiver", n);
                                        }
                                        Ok(false) => {}
                                        Err(err) => {
                                            debug!("[SESSION] UDP input {} bytes error: {}, input buffer {:?}",
                                                   n, err, ByteStr::new(input_buffer));
                                        }
                                    }
                                }
                            }
                        }

                        // bytes received from listener socket
                        input_opt = input_rx.recv() => {
                            if let Some(input_buffer) = input_opt {
                                let mut socket = session.socket.lock();
                                match socket.input(&input_buffer) {
                                    Ok(waked) => {
                                        // trace!("[SESSION] UDP input {} bytes from channel {:?}",
                                        //        input_buffer.len(), ByteStr::new(&input_buffer));
                                        trace!("[SESSION] UDP input {} bytes from channel, waked? {} sender/receiver",
                                               input_buffer.len(), waked);
                                    }
                                    Err(err) => {
                                        debug!("[SESSION] UDP input {} bytes from channel failed, error: {}, input buffer {:?}",
                                               input_buffer.len(), err, ByteStr::new(&input_buffer));
                                    }
                                }
                            }
                        }
                    }
                }
            })
        };

        // Per-session updater
        {
            let session = session.clone();
            tokio::spawn(async move {
                let mut closing_since=None;
                loop {
                    let next = {
                        let mut socket = session.socket.lock();

                        let is_closed = session.closed.load(Ordering::Acquire);
                        if is_closed&&closing_since.get_or_insert_with(Instant::now).elapsed()>=Duration::from_secs(10){break;}
                        if is_closed && socket.can_close() {
                            trace!("[SESSION] KCP session closing");
                            break;
                        }

                        // server socket expires
                        if !is_client {
                            // If this is a server stream, close it automatically after a period of time
                            let last_update_time = socket.last_update_time();
                            let elapsed = last_update_time.elapsed();

                            if elapsed > session.session_expire {
                                if elapsed > session.session_expire * 2 {
                                    // Force close. Client may have already gone.
                                    trace!(
                                        "[SESSION] force close inactive session, conv: {}, last_update: {}s ago",
                                        socket.conv(),
                                        elapsed.as_secs()
                                    );
                                    break;
                                }

                                if !is_closed {
                                    trace!(
                                        "[SESSION] closing inactive session, conv: {}, last_update: {}s ago",
                                        socket.conv(),
                                        elapsed.as_secs()
                                    );
                                    session.closed.store(true, Ordering::Release);
                                }
                            }
                        }

                        // If window is full, flush it immediately
                        if socket.need_flush() {
                            let _ = socket.flush();
                        }

                        match socket.update() {
                            Ok(next_next) => Instant::from_std(next_next),
                            Err(err) => {
                                error!("[SESSION] KCP update failed, error: {}", err);
                                Instant::now() + Duration::from_millis(10)
                            }
                        }
                    };

                    tokio::select! {
                        _ = time::sleep_until(next) => {},
                        _ = session.notifier.notified() => {},
                    }
                }

                {
                    // Close the socket.
                    // Wake all pending tasks and let all send/recv return EOF

                    let mut socket = session.socket.lock();
                    socket.close();
                }

                if let Some((ref notifier, peer_addr)) = session.session_close_notifier {
                    let _ = notifier.send((peer_addr, Arc::downgrade(&session))).await;
                }

                session.closed.store(true, Ordering::Release);
                io_task_handle.abort();

                trace!("[SESSION] KCP session closed");
            });
        }

        session
    }

    pub fn kcp_socket(&self) -> &SpinMutex<KcpSocket> {
        &self.socket
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify();
    }

    pub async fn input(&self, buf: &[u8]) -> Result<(), SessionClosedError> {
        if self.socket.lock().is_closed(){return Err(SessionClosedError);}
        self.input_tx
            .send(buf.to_owned())
            .await
            .map_err(|_| SessionClosedError)
    }

    /// Feeds packets that arrived together straight into the KCP machine, without the channel
    /// hop `input` takes. Added by eztunnel for carriers that receive the packets themselves.
    pub fn input_direct<'a>(&self, packets: impl IntoIterator<Item = &'a [u8]>) {
        let mut socket=self.socket.lock();
        if !socket.is_closed(){socket.input_batch(packets);}
    }

    pub async fn conv(&self) -> u32 {
        let socket = self.socket.lock();
        socket.conv()
    }

    pub fn notify(&self) {
        self.notifier.notify_one();
    }
}

pub struct SessionClosedError;

struct KcpSessionUniq(Arc<KcpSession>);

impl Drop for KcpSessionUniq {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl Deref for KcpSessionUniq {
    type Target = KcpSession;

    fn deref(&self) -> &KcpSession {
        &self.0
    }
}

pub struct KcpSessionManager {
    sessions: HashMap<SocketAddr, KcpSessionUniq>,
}

impl KcpSessionManager {
    pub fn new() -> KcpSessionManager {
        KcpSessionManager {
            sessions: HashMap::new(),
        }
    }

    #[inline]
    pub fn alloc_conv(&mut self) -> u32 {
        let mut conv = rand::random();
        while conv == 0 {
            conv = rand::random()
        }
        conv
    }

    /// True when a session for this peer address already exists.
    pub fn contains(&self, peer_addr: &SocketAddr) -> bool {
        self.sessions.contains_key(peer_addr)
    }

    /// Number of sessions currently kept.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Number of sessions whose peer has this IP address.
    pub fn count_for_ip(&self, ip: std::net::IpAddr) -> usize {
        self.sessions.keys().filter(|peer| peer.ip() == ip).count()
    }

    pub fn close_peer(&mut self, peer_addr: SocketAddr) {
        self.sessions.remove(&peer_addr);
    }

    /// An old session may finish after its address has already been reused. Pointer
    /// identity also distinguishes replacement sessions that reuse a conversation id.
    pub fn close_if_current(&mut self, peer_addr: SocketAddr, closed: &Weak<KcpSession>) {
        if self
            .sessions
            .get(&peer_addr)
            .is_some_and(|current| Weak::ptr_eq(closed, &Arc::downgrade(&current.0)))
        {
            self.sessions.remove(&peer_addr);
        }
    }

    pub async fn get_or_create(
        &mut self,
        config: &KcpConfig,
        conv: u32,
        sn: u32,
        udp: &Arc<UdpSocket>,
        peer_addr: SocketAddr,
        session_close_notifier: &mpsc::Sender<(SocketAddr, Weak<KcpSession>)>,
    ) -> KcpResult<(Arc<KcpSession>, bool)> {
        match self.sessions.entry(peer_addr) {
            Entry::Occupied(mut occ) => {
                let session = occ.get();

                if sn == 0 && session.conv().await != conv {
                    // This is the first packet received from this peer.
                    // Recreate a new session for this specific client.

                    let socket =
                        KcpSocket::new(config, conv, udp.clone(), peer_addr, config.stream)?;
                    let session = KcpSession::new_shared(
                        socket,
                        config.session_expire,
                        Some((session_close_notifier.clone(), peer_addr)),
                    );

                    let old_session = occ.insert(KcpSessionUniq(session.clone()));
                    let old_conv = old_session.conv().await;
                    trace!(
                        "replaced session with conv: {} (old: {}), peer: {}",
                        conv,
                        old_conv,
                        peer_addr
                    );

                    Ok((session, true))
                } else {
                    Ok((session.0.clone(), false))
                }
            }
            Entry::Vacant(vac) => {
                let socket = KcpSocket::new(config, conv, udp.clone(), peer_addr, config.stream)?;
                let session = KcpSession::new_shared(
                    socket,
                    config.session_expire,
                    Some((session_close_notifier.clone(), peer_addr)),
                );
                trace!("created session for conv: {}, peer: {}", conv, peer_addr);
                vac.insert(KcpSessionUniq(session.clone()));
                Ok((session, true))
            }
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[tokio::test]
    async fn stale_close_notifications_cannot_remove_replacements_even_with_reused_conv() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = "127.0.0.1:54321".parse().unwrap();
        let config = KcpConfig::default();
        let (tx, mut rx) = mpsc::channel(8);
        let mut manager = KcpSessionManager::new();
        let (first, _) = manager
            .get_or_create(&config, 1234, 0, &udp, peer, &tx)
            .await
            .unwrap();
        let (second, _) = manager
            .get_or_create(&config, 5678, 0, &udp, peer, &tx)
            .await
            .unwrap();
        let (third, _) = manager
            .get_or_create(&config, 1234, 0, &udp, peer, &tx)
            .await
            .unwrap();
        for _ in 0..2 {
            let (address, closed) = time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            manager.close_if_current(address, &closed);
            assert!(
                manager.contains(&peer),
                "a stale notification removed the replacement"
            );
        }
        let (current, created) = manager
            .get_or_create(&config, 1234, 1, &udp, peer, &tx)
            .await
            .unwrap();
        assert!(!created);
        assert!(Arc::ptr_eq(&current, &third));
        assert!(!Arc::ptr_eq(&first, &third));
        assert!(!Arc::ptr_eq(&second, &third));
        third.close();
        let (address, closed) = time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        manager.close_if_current(address, &closed);
        assert!(
            !manager.contains(&peer),
            "current close must still reclaim its entry"
        );
    }
}
