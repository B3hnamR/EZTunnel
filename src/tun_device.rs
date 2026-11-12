//! Linux point-to-point layer-3 forwarding through authenticated tunnel carriers.
//! The nonpersistent interface belongs to its file descriptor and disappears on drop.
use crate::{
    config::{Config, Mode, TunConfig, decode_key},
    farewell::Farewell,
    kcp_carrier::Acceptor,
    limits::{AcceptBackoff, PendingLimiter, RetryPause, jitter},
    stats::Stats,
    transport::{self, SecureConnection, SecureReader, SecureWriter},
    wire::{DATA_SIZE, Frame},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs::{File, OpenOptions},
    future::Future,
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{io::unix::AsyncFd, process::Command, sync::mpsc, task::JoinSet, time};

pub struct TunDevice {
    fd: AsyncFd<File>,
    mtu: usize,
}

impl TunDevice {
    /// Creates a fresh interface. Never attaches to, or removes, an existing device.
    pub async fn create(config: &TunConfig) -> Result<Self> {
        ensure!(
            !config.name.is_empty()
                && config.name.len() < libc::IFNAMSIZ
                && config
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid TUN interface name"
        );
        ensure!(
            usize::from(config.mtu) <= DATA_SIZE,
            "MTU exceeds frame size"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")
            .context("open /dev/net/tun (Linux TUN support and CAP_NET_ADMIN are required)")?;
        {
            // SAFETY: ifreq is a C POD struct; zeroed fields are valid. The ioctl
            // receives its exact ABI layout and a live pointer for this call only.
            // Keep the pointer-containing union out of the future's suspended state.
            let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
            for (slot, byte) in request.ifr_name.iter_mut().zip(config.name.bytes()) {
                *slot = byte as libc::c_char;
            }
            request.ifr_ifru.ifru_flags =
                (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as _;
            let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) };
            if result < 0 {
                return Err(io::Error::last_os_error())
                    .context("create exclusive nonpersistent TUN interface");
            }
        }
        let device = Self {
            fd: AsyncFd::new(file)?,
            mtu: usize::from(config.mtu),
        };
        let local = config.address.to_string();
        let peer = config.peer_address.to_string();
        let mtu = config.mtu.to_string();
        if local.parse::<std::net::IpAddr>()?.is_ipv6() {
            // These explicit point-to-point /128 addresses need no neighbour discovery.
            // Disable DAD only on this owned address so the inner TCP bind is ready immediately.
            ip(&[
                "-6",
                "address",
                "add",
                &local,
                "peer",
                &peer,
                "dev",
                &config.name,
                "nodad",
            ])
            .await?;
        } else {
            ip(&["address", "add", &local, "peer", &peer, "dev", &config.name]).await?;
        }
        ip(&["link", "set", "dev", &config.name, "mtu", &mtu, "up"]).await?;
        // Linux installs the IPv4 peer route automatically, but the IPv6 address
        // operation installs a local-address route instead. Add only the explicit
        // peer host route; never replace an existing route or change defaults.
        if local.parse::<std::net::IpAddr>()?.is_ipv6() {
            let destination = format!("{peer}/128");
            ip(&["-6", "route", "add", &destination, "dev", &config.name]).await?;
        }
        tracing::info!(interface = %config.name, %local, %peer, mtu = config.mtu, "TUN interface ready");
        Ok(device)
    }

    pub async fn receive(&self, buffer: &mut [u8]) -> Result<usize> {
        loop {
            let mut ready = self.fd.readable().await?;
            match ready.try_io(|fd| {
                // SAFETY: buffer points to its writable length; fd stays owned by self.
                let count = unsafe {
                    libc::read(
                        fd.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Ok(Ok(count)) => return Ok(count),
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => continue,
            }
        }
    }

    pub async fn inject(&self, packet: &[u8]) -> Result<()> {
        validate_packet(packet, self.mtu)?;
        loop {
            let mut ready = self.fd.writable().await?;
            match ready.try_io(|fd| {
                // SAFETY: packet points to readable bytes and fd remains live for write.
                let count = unsafe {
                    libc::write(
                        fd.get_ref().as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                    )
                };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Ok(Ok(count)) => {
                    ensure!(count == packet.len(), "partial TUN packet write");
                    return Ok(());
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => continue,
            }
        }
    }
}

async fn ip(arguments: &[&str]) -> Result<()> {
    let result = Command::new("ip")
        .args(arguments)
        .kill_on_drop(true)
        .output()
        .await
        .context("run iproute2 (the ip command is required)")?;
    ensure!(
        result.status.success(),
        "iproute2 failed: {}",
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(())
}

/// C32: whether a TUN IP packet counts as user traffic for the byte counters. With
/// `tun.forwarding_port` the inner forwarding TCP connection (to or from that port) is
/// already counted by the inner relay, so only it is excluded; every other routed packet
/// counts once. Without a forwarding port every packet counts.
pub fn counts_as_user_traffic(packet: &[u8], forwarding_port: Option<u16>) -> bool {
    let Some(port) = forwarding_port else {
        return true;
    };
    let (protocol, transport) = match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 15) * 4;
            let fragment_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
            if fragment_offset != 0 || header < 20 || packet.len() < header + 4 {
                return true;
            }
            (packet[9], &packet[header..])
        }
        Some(6) if packet.len() >= 44 => (packet[6], &packet[40..]),
        _ => return true,
    };
    if protocol != 6 {
        return true;
    }
    let source = u16::from_be_bytes([transport[0], transport[1]]);
    let destination = u16::from_be_bytes([transport[2], transport[3]]);
    source != port && destination != port
}

/// Rejects truncated, oversized, or non-IP datagrams before kernel injection.
pub fn validate_packet(packet: &[u8], mtu: usize) -> Result<()> {
    ensure!(
        !packet.is_empty() && packet.len() <= mtu && packet.len() <= DATA_SIZE,
        "IP packet outside MTU"
    );
    match packet[0] >> 4 {
        4 => {
            ensure!(packet.len() >= 20, "truncated IPv4 header");
            let header = usize::from(packet[0] & 15) * 4;
            ensure!(
                header >= 20 && header <= packet.len(),
                "invalid IPv4 header length"
            );
            ensure!(
                usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len(),
                "IPv4 packet length mismatch"
            );
        }
        6 => {
            ensure!(packet.len() >= 40, "truncated IPv6 header");
            ensure!(
                usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len(),
                "IPv6 packet length mismatch or unsupported jumbogram"
            );
        }
        _ => bail!("TUN accepts IPv4 or IPv6 packets only"),
    }
    Ok(())
}

pub async fn run(config: Config, stats: Arc<Stats>) -> Result<()> {
    config.validate()?;
    transport::validate_tls_config(&config)?;
    let tun = config.tun.as_ref().context("TUN configuration missing")?;
    let device = TunDevice::create(tun).await?;
    if let Some(inner) = config.tun_forwarding_config()? {
        tracing::info!(port = ?tun.forwarding_port, "authenticated forwarding over inner TUN TCP enabled");
        tokio::try_join!(
            run_packets(&device, &config, &stats),
            crate::engine::run_forwarding(inner, stats.clone())
        )?;
        return Ok(());
    }
    run_packets(&device, &config, &stats).await
}

async fn run_packets(device: &TunDevice, config: &Config, stats: &Stats) -> Result<()> {
    let farewell = &stats.farewell;
    let carrier = match config.mode {
        Mode::Server => config.listeners[0].transport,
        Mode::Client => config.paths[0].transport,
    };
    if carrier == crate::config::Transport::Tun {
        return crate::raw_tun::run_with_stats(device, config, farewell, Some(stats)).await;
    }
    let private = config.private_key()?;
    match config.mode {
        Mode::Server => {
            let peers = config
                .peer_public_keys
                .iter()
                .map(|key| decode_key(key))
                .collect::<Result<Vec<_>>>()?;
            if !config.server_dials {
                return serve_listener(device, config, private, Arc::new(peers), farewell,stats).await;
            }
            // Reverse mode: this side dials out, so there is nothing to accept.
            let listener = &config.listeners[0];
            loop {
                let connection = transport::connect_responder(
                    listener,
                    &private,
                    &peers,
                    config.timeouts.server_dial_sec,
                )
                .await;
                match connection {
                    Ok(connection) => {
                        if let Err(error) = pump(device, connection, config, farewell,stats).await {
                            tracing::debug!(%error, "TUN session ended");
                        }
                    }
                    Err(error) => tracing::debug!(%error, "TUN peer rejected"),
                }
                time::sleep(Duration::from_secs(1)).await;
            }
        }
        Mode::Client => {
            let path = &config.paths[0];
            let mut acceptor = if config.server_dials {
                Some(Acceptor::bind(&path.listen_config()).await?)
            } else {
                None
            };
            let dead = Duration::from_secs(config.dead_timeout_sec);
            let mut retry = RetryPause::new(
                path.retry_interval.clamp(1, 30),
                config.timeouts.retry_max_sec,
                dead,
            );
            let mut backoff = AcceptBackoff::new();
            loop {
                let started = time::Instant::now();
                let connection = if let Some(acceptor) = &mut acceptor {
                    let incoming = match acceptor.accept().await {
                        Ok(incoming) => {
                            backoff.succeeded();
                            incoming
                        }
                        Err(error) => {
                            backoff.failed("tunnel accept", error).await?;
                            continue;
                        }
                    };
                    transport::accept_initiator(incoming, path, &private).await
                } else {
                    transport::connect_path(path, &private).await
                };
                match connection {
                    Ok(connection) => {
                        if let Err(error) = pump(device, connection, config, farewell,stats).await {
                            if crate::farewell::peer_stopped(&error) {
                                retry.peer_stopped();
                            }
                            tracing::debug!(%error, "TUN session ended");
                        }
                    }
                    Err(error) => tracing::debug!(%error, "TUN connection failed"),
                }
                time::sleep(jitter(retry.next(started.elapsed(), dead))).await;
            }
        }
    }
}

/// Accepts tunnel connections for a TUN server. Handshakes run concurrently and are bounded by the
/// pending-connection limits, so a slow or silent connection cannot hold up the real peer. When a
/// peer authenticates, it replaces any session already running (a peer that restarted behind a
/// NAT will often reconnect before the old session has timed out).
async fn serve_listener(
    device: &TunDevice,
    config: &Config,
    private: zeroize::Zeroizing<[u8; 32]>,
    peers: Arc<Vec<[u8; 32]>>,
    farewell: &Farewell,
    stats:&Stats,
) -> Result<()> {
    type Session<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    let listener = config.listeners[0].clone();
    let mut acceptor = Acceptor::bind(&listener).await?;
    let pending = PendingLimiter::new(config.max_pending_handshakes, config.max_pending_per_ip);
    let handshake_timeout = Duration::from_secs(config.timeouts.handshake_sec);
    let mut handshakes: JoinSet<Option<(SecureReader, SecureWriter, Frame)>> = JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    let mut active: Option<Session<'_>> = None;
    loop {
        tokio::select! {
            incoming = acceptor.accept() => {
                let incoming = match incoming {
                    Ok(incoming) => { backoff.succeeded(); incoming }
                    Err(error) => { backoff.failed("tunnel accept", error).await?; continue; }
                };
                let Some(waiting) = pending.try_enter(incoming.peer_ip()) else {
                    tracing::debug!("too many unauthenticated connections; dropping a new one");
                    continue;
                };
                let (listener, peers) = (listener.clone(), peers.clone());
                let private = private.clone();
                handshakes.spawn(async move {
                    let result = transport::accept_listener(
                        incoming, &listener, &private, &peers, handshake_timeout,
                    )
                    .await;
                    let confirmed = match result {
                        Ok(connection) => {
                            // The handshake alone does not prove the peer is alive (its first message
                            // can be replayed by someone who recorded it). Nothing is replaced until
                            // the peer has sent a record that decrypts under the session keys.
                            let (mut reader, writer) = connection.split();
                            match time::timeout(handshake_timeout, reader.recv()).await {
                                Ok(Ok(first)) => Some((reader, writer, first)),
                                _ => {
                                    tracing::debug!("TUN peer sent nothing after the handshake");
                                    None
                                }
                            }
                        }
                        Err(error) => {
                            tracing::debug!(%error, "TUN peer rejected");
                            None
                        }
                    };
                    drop(waiting);
                    confirmed
                });
            }
            Some(done) = handshakes.join_next(), if !handshakes.is_empty() => {
                if let Ok(Some((reader, writer, first))) = done {
                    if active.is_some() {
                        tracing::info!("TUN peer reconnected; replacing the previous session");
                    }
                    active = Some(Box::pin(pump_with(device, reader, writer, Some(first), config, farewell,stats)));
                }
            }
            result = async { active.as_mut().expect("guarded by the branch condition").await }, if active.is_some() => {
                active = None;
                if let Err(error) = result {
                    tracing::debug!(%error, "TUN session ended");
                }
            }
        }
    }
}

async fn pump(
    device: &TunDevice,
    connection: SecureConnection,
    config: &Config,
    farewell: &Farewell,
    stats:&Stats,
) -> Result<()> {
    let (reader, writer) = connection.split();
    pump_with(device, reader, writer, None, config, farewell,stats).await
}

/// Runs a TUN session. `first` is a frame already read from the peer (the one that confirmed it).
async fn pump_with(
    device: &TunDevice,
    mut reader: SecureReader,
    mut writer: SecureWriter,
    first: Option<Frame>,
    config: &Config,
    farewell: &Farewell,
    stats:&Stats,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<Frame>(32);
    farewell.register(&tx);
    let deadline = Duration::from_secs(config.dead_timeout_sec);
    let mut first = first;
    let inbound = async {
        let mut dropped = 0u64;
        loop {
            // Timeout always ends the session: a partially received encrypted frame
            // must never be cancelled and retried on the same cipher stream.
            let frame = match first.take() {
                Some(frame) => frame,
                None => time::timeout(deadline, reader.recv())
                    .await
                    .context("TUN peer timed out")??,
            };
            match frame {
                Frame::Data { id: 1, data } => {
                    // A packet that does not fit this side's MTU (the two sides were set up with
                    // different sizes) is dropped, as the raw carriers do; it is not a reason to
                    // end the session and reconnect forever.
                    if let Err(error) = validate_packet(&data, device.mtu) {
                        dropped += 1;
                        if dropped == 1 || dropped.is_multiple_of(1000) {
                            tracing::warn!(
                                %error,
                                dropped,
                                mtu = device.mtu,
                                "dropping packets from the peer that do not fit this side's TUN MTU; both sides should use the same tun.mtu"
                            );
                        }
                        continue;
                    }
                    time::timeout(deadline, device.inject(&data))
                        .await
                        .context("TUN device write timed out")??;
                    if counts_as_user_traffic(&data,config.tun.as_ref().and_then(|tun|tun.forwarding_port)){stats.bytes_from_peer.fetch_add(data.len()as u64,std::sync::atomic::Ordering::Relaxed);}
                }
                Frame::Ping { nonce } => tx
                    .send(Frame::Pong { nonce })
                    .await
                    .context("TUN writer stopped")?,
                Frame::Pong { .. } => {}
                frame if crate::farewell::is_goodbye(&frame) => {
                    return Err(crate::farewell::PeerStopped.into());
                }
                _ => bail!("unexpected frame in TUN session"),
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };
    let outbound = async {
        let mut heartbeat = time::interval(Duration::from_secs(config.heartbeat_sec));
        heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut nonce = 0u64;
        loop {
            let frame = tokio::select! {
                // Complete each record outside select; never cancel/retry a partial write.
                biased;
                frame = rx.recv() => frame.context("TUN producers stopped")?,
                _ = heartbeat.tick() => { nonce = nonce.wrapping_add(1); Frame::Ping { nonce } }
            };
            time::timeout(deadline, writer.send(&frame))
                .await
                .context("TUN send timed out")??;
            if let Frame::Data{data,..}=&frame&&counts_as_user_traffic(data,config.tun.as_ref().and_then(|tun|tun.forwarding_port)){stats.bytes_to_peer.fetch_add(data.len()as u64,std::sync::atomic::Ordering::Relaxed);}
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };
    let packets = async {
        let mut buffer = vec![0; device.mtu + 1];
        loop {
            let count = device.receive(&mut buffer).await?;
            if let Err(error) = validate_packet(&buffer[..count], device.mtu) {
                tracing::debug!(%error, "dropping an invalid packet from the TUN device");
                continue;
            }
            tx.send(Frame::Data {
                id: 1,
                data: buffer[..count].to_vec(),
            })
            .await
            .context("TUN writer stopped")?;
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };
    tokio::try_join!(inbound, outbound, packets)?;
    Ok(())
}

#[cfg(test)]
mod accounting_tests {
    use super::counts_as_user_traffic;

    fn ipv4(protocol: u8, source: u16, destination: u16, fragment_offset: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[6..8].copy_from_slice(&fragment_offset.to_be_bytes());
        packet[9] = protocol;
        packet[20..22].copy_from_slice(&source.to_be_bytes());
        packet[22..24].copy_from_slice(&destination.to_be_bytes());
        packet
    }

    fn ipv6(next: u8, source: u16, destination: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&20u16.to_be_bytes());
        packet[6] = next;
        packet[40..42].copy_from_slice(&source.to_be_bytes());
        packet[42..44].copy_from_slice(&destination.to_be_bytes());
        packet
    }

    /// C32: with a forwarding port only the inner forwarding TCP flow is left to the inner
    /// relay's counters; other routed traffic on the same TUN still counts.
    #[test]
    fn only_the_inner_forwarding_tcp_flow_is_excluded_from_tun_counters() {
        let port = Some(47475);
        assert!(!counts_as_user_traffic(&ipv4(6, 50000, 47475, 0), port));
        assert!(!counts_as_user_traffic(&ipv4(6, 47475, 50000, 0), port));
        assert!(!counts_as_user_traffic(&ipv6(6, 50000, 47475), port));
        assert!(counts_as_user_traffic(&ipv4(6, 50000, 443, 0), port), "other TCP routed over TUN");
        assert!(counts_as_user_traffic(&ipv4(17, 50000, 47475, 0), port), "UDP is not the TCP overlay");
        assert!(counts_as_user_traffic(&ipv6(17, 1, 2), port));
        assert!(counts_as_user_traffic(&ipv4(6, 50000, 47475, 0x0010), port), "non-first fragment has no ports");
        assert!(counts_as_user_traffic(&ipv4(6, 50000, 47475, 0), None), "no overlay: everything counts");
        assert!(counts_as_user_traffic(&[], port));
    }
}
