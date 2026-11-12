//! Linux Ethernet packet transport for the raw IPv4 profiles.
//! No route, sysctl, firewall or neighbor entry is changed by this module.
pub use crate::raw_packet::RawOptions;
use crate::raw_packet::{self, PacketOptions};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::CString,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};
use tokio::{io::unix::AsyncFd, process::Command, time};

pub struct RawSocket {
    fd: AsyncFd<OwnedFd>,
    interface_index: i32,
    packet: PacketOptions,
    receive_packet: PacketOptions,
    receive_sources: Vec<Ipv4Addr>,
    source_pool: Vec<Ipv4Addr>,
    envelope:Option<std::sync::Mutex<crate::spoof::Envelope>>,
    mirage_options:Option<crate::spoof::MirageOptions>,
    repair_tx:Option<std::sync::Mutex<crate::spoof_fec::Encoder>>,
    repair_rx:Option<std::sync::Mutex<crate::spoof_fec::Decoder>>,
    repaired:std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
    _no_reply_udp:Option<tokio::net::UdpSocket>,
    _no_reply_protocol:Option<OwnedFd>,
    peer: SocketAddr,
    mtu: usize,
    sequence: AtomicU32,
    /// Required IPv4 source of received frames; `None` when spoofing makes it unpredictable.
    expected_source: Option<Ipv4Addr>,
    /// The receive buffer, kept between calls (it is 64 KiB, and a call is made per datagram).
    frame: std::sync::Mutex<Option<Vec<u8>>>,
    hopping: Option<std::sync::Mutex<crate::port_hop::State>>,
}

/// A receive buffer on loan; it goes back to the socket when dropped, also when the receiving
/// future is cancelled.
struct LentFrame<'a> {
    home: &'a std::sync::Mutex<Option<Vec<u8>>>,
    buffer: Option<Vec<u8>>,
}
impl Drop for LentFrame<'_> {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            *self.home.lock().unwrap_or_else(|e| e.into_inner()) = Some(buffer);
        }
    }
}

impl RawSocket {
    /// Opens one packet socket on a physical/veth Ethernet interface.
    /// A supplied peer_mac is a next-hop MAC, including when spoof_dst_ip is used.
    pub async fn bind(options: &RawOptions, server: bool) -> Result<Self> {
        Self::bind_inner(options, server, false).await
    }
    pub async fn bind_fec(options: &RawOptions, server: bool) -> Result<Self> {
        Self::bind_inner(options, server, true).await
    }
    async fn bind_inner(options: &RawOptions, server: bool, fec: bool) -> Result<Self> {
        options.validate()?;
        let mut route_args = vec![
            "-j".to_string(),
            "route".into(),
            "get".into(),
            options.peer_ip.to_string(),
        ];
        if let Some(interface) = &options.interface {
            route_args.extend(["oif".into(), interface.clone()]);
        }
        let routes = ip_json(&route_args).await?;
        let route = routes
            .as_array()
            .and_then(|v| v.first())
            .context("ip route get returned no route")?;
        let interface = options
            .interface
            .as_deref()
            .or_else(|| route["dev"].as_str())
            .context("raw interface cannot be determined")?;
        let local_ip = options
            .local_ip
            .or_else(|| route["prefsrc"].as_str().and_then(|s| s.parse().ok()))
            .context("raw local_ip cannot be determined")?;
        let next_hop = options
            .gateway_ip
            .or_else(|| route["gateway"].as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(options.peer_ip);
        let links = ip_json(&[
            "-j".into(),
            "link".into(),
            "show".into(),
            "dev".into(),
            interface.into(),
        ])
        .await?;
        let link = links
            .as_array()
            .and_then(|v| v.first())
            .context("raw interface does not exist")?;
        ensure!(
            link["link_type"].as_str() == Some("ether"),
            "raw profiles require an Ethernet/veth interface"
        );
        let source_mac = raw_packet::parse_mac(
            link["address"]
                .as_str()
                .context("interface MAC unavailable")?,
        )?;
        let mtu = link["mtu"].as_u64().context("interface MTU unavailable")? as usize;
        let name = CString::new(interface)?;
        // SAFETY: CString is terminated and remains live during if_nametoindex.
        let interface_index = unsafe { libc::if_nametoindex(name.as_ptr()) } as i32;
        ensure!(interface_index > 0, "interface index unavailable");
        // SAFETY: socket has no borrowed pointers; successful fd is owned below.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("open raw socket (CAP_NET_RAW is required)");
        }
        // SAFETY: successful socket returns a fresh descriptor owned exclusively.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut address = link_address(interface_index, [0; 6]);
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        // SAFETY: pointer references a fully initialized sockaddr_ll with its size.
        let result = unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error()).context("bind raw interface");
        }
        set_socket_buffers(fd, options.sock_buf).context("set raw socket buffers")?;
        let fd = AsyncFd::new(owned)?;
        let destination_mac = if let Some(mac) = &options.peer_mac {
            raw_packet::parse_mac(mac)?
        } else {
            resolve_arp(&fd, interface_index, source_mac, local_ip, next_hop).await?
        };
        let client_port = options.source_port.unwrap_or_else(|| {
            if options.l4_port == u16::MAX {
                options.l4_port - 1
            } else {
                options.l4_port + 1
            }
        });
        let (source_port, destination_port) = if server {
            (options.l4_port, client_port)
        } else {
            (client_port, options.l4_port)
        };
        let tcp_flags = options.tcp_flags.bytes().fold(0u8, |flags, v| {
            flags
                | match v {
                    b'f' => 1,
                    b's' => 2,
                    b'r' => 4,
                    b'p' => 8,
                    b'a' => 16,
                    b'u' => 32,
                    _ => 0,
                }
        });
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let packet = PacketOptions {
            source_mac,
            destination_mac,
            source_ip: options.spoof_src_ip.unwrap_or(local_ip),
            destination_ip: options.spoof_dst_ip.unwrap_or(options.peer_ip),
            source_port,
            destination_port,
            profile: options.profile,
            proto58: options.proto58_enabled(),
            server,
            tcp_camouflage: fec,
            tcp_flags,
            timestamp_seed: seed,
            icmp_id_mirror: options.icmp_id_mirror,
        };
        if options.mirage_acknowledgement.is_some() && options.mirage.is_none() {
            ensure!(
                options.spoof_src_ip.is_some_and(|ip| ip != local_ip),
                "Mirage requires a spoofed source distinct from the detected real local IPv4"
            );
        }
        let mut packet=packet;
        let mut receive_packet=packet.clone();
        let mut receive_sources=Vec::new();let mut source_pool=Vec::new();
        if let Some(spec)=&options.mirage {
            let(tx,rx)=spec.profiles(options.profile,server);
            packet.profile=tx;receive_packet.profile=rx;
            packet.destination_ip=options.peer_ip;
            match spec.echo_mode {
                crate::spoof::EchoMode::Split=>{},
                crate::spoof::EchoMode::Requests=>{packet.server=false;packet.icmp_id_mirror=false;receive_packet.server=true;receive_packet.icmp_id_mirror=false;},
                crate::spoof::EchoMode::Replies=>{packet.server=true;packet.icmp_id_mirror=false;receive_packet.server=false;receive_packet.icmp_id_mirror=false;},
            }
            receive_sources=if spec.expected_sources.is_empty(){vec![options.peer_ip]}else{spec.expected_sources.clone()};
            source_pool=spec.source_pool.clone();
            // decode's role describes our side, and its source_port is the
            // destination expected on ingress. Addresses are admitted separately.
            receive_packet.source_ip=local_ip;
            receive_packet.destination_ip=options.peer_ip;
        }
        let expected_source = if !receive_sources.is_empty() {
            (receive_sources.len()==1).then(||receive_sources[0])
        } else if options.spoof_src_ip.is_none() && options.spoof_dst_ip.is_none() {
            Some(options.peer_ip)
        } else {
            None
        };
        // The address resolution above needed to see ARP replies, so the filter comes last.
        let filtered = options.kernel_filter
            && match attach_kernel_filter(fd.get_ref().as_raw_fd(), &receive_packet, expected_source) {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(%error, "could not attach the kernel packet filter; filtering in user space");
                    false
                }
            };
        tracing::info!(%interface,%local_ip,peer=%options.peer_ip,profile=?options.profile,proto58=options.proto58_enabled(),kernel_filter=filtered,"raw packet interface ready");
        let hopping=if options.hopping.enabled {Some(std::sync::Mutex::new(crate::port_hop::State::new(options.hopping.clone(),source_port,destination_port)?))}else{None};
        let envelope=if let Some(spec)=&options.mirage{Some(std::sync::Mutex::new(crate::spoof::Envelope::new(spec.admission_key.clone().context("Mirage v2 requires tunnel_key")?,packet.profile,receive_packet.profile)?.with_options(spec)?))}else{None};
        let repair_tx=options.mirage.as_ref().and_then(|spec|spec.redundancy).map(|fec|crate::spoof_fec::Encoder::new(fec.data,fec.parity).map(std::sync::Mutex::new)).transpose()?;
        let repair_rx=options.mirage.as_ref().and_then(|spec|spec.redundancy).map(|fec|crate::spoof_fec::Decoder::new(fec.data,fec.parity).map(std::sync::Mutex::new)).transpose()?;
        let mut no_reply_udp=None;let mut no_reply_protocol=None;
        if options.mirage.is_some(){
            match receive_packet.profile{
                crate::raw_packet::RawProfile::Udp=>{
                    no_reply_udp=Some(tokio::net::UdpSocket::bind((local_ip,receive_packet.source_port)).await.context("reserve Mirage UDP receive port without automatic ICMP errors; choose an unused port")?);
                }
                crate::raw_packet::RawProfile::Gre|crate::raw_packet::RawProfile::Ipip|crate::raw_packet::RawProfile::Bip|crate::raw_packet::RawProfile::Icmpv6=>{
                    let fd=unsafe{libc::socket(libc::AF_INET,libc::SOCK_RAW|libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC,i32::from(receive_packet.profile.protocol()))};
                    if fd<0{return Err(io::Error::last_os_error()).context("claim Mirage raw protocol without automatic unreachable replies");}
                    no_reply_protocol=Some(unsafe{OwnedFd::from_raw_fd(fd)});
                }
                _=>{}
            }
        }
        Ok(Self {
            fd,
            interface_index,
            packet,
            receive_packet,
            receive_sources,
            source_pool,
            envelope,
            mirage_options:options.mirage.clone(),
            repair_tx,repair_rx,repaired:std::sync::Mutex::new(std::collections::VecDeque::new()),
            _no_reply_udp:no_reply_udp,_no_reply_protocol:no_reply_protocol,
            peer: SocketAddr::V4(SocketAddrV4::new(options.peer_ip, options.l4_port)),
            mtu,
            sequence: AtomicU32::new(1),
            expected_source,
            frame: std::sync::Mutex::new(None),
            hopping,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            self.packet.source_ip,
            self.packet.source_port,
        ))
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    pub fn max_payload(&self) -> usize {
        let shaping=self.mirage_options.as_ref().map_or(0,|spec|usize::from(spec.padding_max)+if spec.padding_max>0{2}else{0}+if spec.fake_tls{5}else{0});
        self.mtu.saturating_sub(20 + self.packet.header_len().max(self.receive_packet.header_len()) + if self.hopping.is_some(){crate::port_hop::OVERHEAD}else{0}+if self.envelope.is_some(){crate::spoof::ENVELOPE_OVERHEAD}else{0}+shaping+if self.repair_tx.is_some(){crate::spoof_fec::OVERHEAD}else{0})
    }

    /// Adjusts this socket's buffers without changing host-wide limits.
    pub fn set_socket_buffer_bytes(&self, bytes: usize) -> io::Result<()> {
        set_socket_buffers(self.fd.get_ref().as_raw_fd(), bytes)
    }

    pub async fn send(&self, payload: &[u8]) -> io::Result<usize> {
        if payload.len() > self.max_payload() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw payload exceeds interface MTU",
            ));
        }
        let packets=if let Some(encoder)=&self.repair_tx{encoder.lock().unwrap_or_else(|e|e.into_inner()).encode(payload).map_err(io::Error::other)?}else{vec![payload.to_vec()]};
        for packet in packets{self.send_packet(&packet).await?;}
        Ok(payload.len())
    }
    async fn send_packet(&self,payload:&[u8])->io::Result<usize>{
        let mut packet=self.packet.clone();
        let sequence=self.sequence.fetch_add(1,Ordering::Relaxed);
        if !self.source_pool.is_empty(){packet.source_ip=self.source_pool[sequence as usize%self.source_pool.len()];}
        if let Some(range)=self.mirage_options.as_ref().and_then(|spec|spec.source_port_range){if matches!(packet.profile,crate::raw_packet::RawProfile::Tcp|crate::raw_packet::RawProfile::Udp){packet.source_port=crate::spoof::shuffled_port(range).map_err(io::Error::other)?;}}
        let wrapped=if let Some(hopping)=&self.hopping {
            let mut hopping=hopping.lock().unwrap_or_else(|e|e.into_inner());
            let pair=hopping.selected();packet.source_port=pair.0;packet.destination_port=pair.1;
            Some(hopping.wrap(payload).map_err(io::Error::other)?)
        }else{None};
        let bytes=wrapped.as_deref().unwrap_or(payload);
        let shaped=if let Some(spec)=&self.mirage_options{Some(crate::spoof::shape(bytes,spec).map_err(io::Error::other)?)}else{None};
        let bytes=shaped.as_deref().unwrap_or(bytes);
        let admitted=if let Some(envelope)=&self.envelope{Some(envelope.lock().unwrap_or_else(|e|e.into_inner()).encode(bytes).map_err(io::Error::other)?)}else{None};
        let mut frame = raw_packet::encode(
            &packet,
            admitted.as_deref().unwrap_or(bytes),
            sequence,
        )
        .map_err(io::Error::other)?;
        if let Some(spec)=&self.mirage_options {
            if let Some(ttl)=spec.ttl{frame[22]=ttl;}
            if let Some(dscp)=spec.dscp{frame[15]=dscp<<2;}
            frame[24..26].fill(0);let checksum=raw_packet::checksum(&frame[14..34]);frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        }
        match send_frame(
            &self.fd,
            self.interface_index,
            self.packet.destination_mac,
            &frame,
        )
        .await
        {
            Ok(()) => {}
            // A full transmit queue or an interface that is briefly down loses this packet, as
            // any datagram can be lost; it must not end the carrier (the service would restart,
            // look the next hop up again and renegotiate the session).
            Err(error) if is_transient_send_error(&error) => {
                tracing::debug!(%error, "raw send dropped a packet");
            }
            Err(error) => return Err(error),
        }
        Ok(payload.len())
    }

    pub async fn recv(&self, payload: &mut [u8]) -> io::Result<usize> {
        if let Some(packet)=self.repaired.lock().unwrap_or_else(|e|e.into_inner()).pop_front(){if packet.len()<=payload.len(){payload[..packet.len()].copy_from_slice(&packet);return Ok(packet.len());}}
        let mut lent = LentFrame {
            home: &self.frame,
            buffer: Some(
                self.frame
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                    .unwrap_or_else(|| vec![0; 65_549]),
            ),
        };
        let frame = lent.buffer.as_mut().expect("a receive buffer was lent");
        loop {
            let (length, outgoing) = receive_frame(&self.fd, frame).await?;
            if outgoing || length < 14 || frame[..6] != self.packet.source_mac {
                continue;
            }
            if !raw_packet::source_matches(&frame[..length], self.expected_source) {
                continue;
            }
            if !self.receive_sources.is_empty() {
                if length<34 || frame[30..34]!=self.receive_packet.source_ip.octets(){continue;}
                let source=Ipv4Addr::new(frame[26],frame[27],frame[28],frame[29]);
                if !self.receive_sources.contains(&source){continue;}
            }
            let mut packet=self.receive_packet.clone();
            if let Some([first,last])=self.mirage_options.as_ref().and_then(|spec|spec.source_port_range){if matches!(packet.profile,crate::raw_packet::RawProfile::Tcp|crate::raw_packet::RawProfile::Udp){
                if length<38{continue;}let offset=14+usize::from(frame[14]&15)*4;if offset<34||offset+4>length{continue;}
                let source=u16::from_be_bytes(frame[offset..offset+2].try_into().unwrap());if !(first..=last).contains(&source){continue;}packet.destination_port=source;
            }}
            let mut observed=None;
            if self.hopping.is_some() {
                if length<38 {continue;}
                let offset=14+usize::from(frame[14]&15)*4;
                if offset<34 || offset+4>length {continue;}
                let source=u16::from_be_bytes(frame[offset..offset+2].try_into().unwrap());
                let destination=u16::from_be_bytes(frame[offset+2..offset+4].try_into().unwrap());
                packet.source_port=destination;packet.destination_port=source;observed=Some((source,destination));
            }
            if let Ok(data) = raw_packet::decode(&packet, &frame[..length]) {
                let mut envelope=self.envelope.as_ref().map(|e|e.lock().unwrap_or_else(|e|e.into_inner()));
                let data=if let Some(envelope)=&mut envelope{match envelope.decode(data){Ok(bytes)=>bytes,Err(error)=>{tracing::debug!(%error,"Mirage packet rejected");continue;}}}else{data};
                let data=if let Some(spec)=&self.mirage_options{match crate::spoof::unshape(data,spec){Ok(bytes)=>bytes,Err(error)=>{tracing::debug!(%error,"Mirage shaping contract mismatch");continue;}}}else{data};
                let mut guard=self.hopping.as_ref().map(|h|h.lock().unwrap_or_else(|e|e.into_inner()));
                let data=if let (Some(hopping),Some((source,destination)))=(&mut guard,observed) {
                    match hopping.unwrap(data,source,destination){Ok(data)=>data,Err(_)=>continue}
                }else{data};
                if let Some(decoder)=&self.repair_rx{
                    let packets=match decoder.lock().unwrap_or_else(|e|e.into_inner()).decode(data){Ok(packets)=>packets,Err(error)=>{tracing::debug!(%error,"Mirage redundancy packet rejected");continue;}};
                    let mut packets=packets.into_iter();let Some(first)=packets.next()else{continue;};
                    if first.len()>payload.len(){continue;}
                    self.repaired.lock().unwrap_or_else(|e|e.into_inner()).extend(packets);
                    payload[..first.len()].copy_from_slice(&first);return Ok(first.len());
                }
                // Ignore an oversized datagram instead of terminating the carrier.
                if data.len() > payload.len() {
                    continue;
                }
                payload[..data.len()].copy_from_slice(data);
                return Ok(data.len());
            }
        }
    }
    pub async fn recv_from(&self, payload: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Ok((self.recv(payload).await?, self.peer))
    }
    pub async fn send_to(&self, payload: &[u8], destination: SocketAddr) -> io::Result<usize> {
        if destination.ip() != self.peer.ip() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw socket is pinned to its configured peer",
            ));
        }
        self.send(payload).await
    }
}

/// The classic BPF program that admits only frames this socket would accept anyway: IPv4, sent
/// to this interface's MAC address, with the carrier's IP protocol and (without address spoofing)
/// the peer's source address. Ports, flags and checksums are still checked by `raw_packet::decode`.
/// The checks are a subset of what `decode` requires, so the filter never drops a frame it would
/// have accepted.
fn kernel_filter_program(
    packet: &PacketOptions,
    expected_source: Option<Ipv4Addr>,
) -> Vec<libc::sock_filter> {
    const LD_W: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const LD_H: u16 = (libc::BPF_LD | libc::BPF_H | libc::BPF_ABS) as u16;
    const LD_B: u16 = (libc::BPF_LD | libc::BPF_B | libc::BPF_ABS) as u16;
    const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    let mut program = Vec::new();
    // Load a field; if it equals `value` skip the drop instruction after the comparison.
    let mut guard = |load: u16, offset: u32, value: u32| {
        program.push(libc::sock_filter {
            code: load,
            jt: 0,
            jf: 0,
            k: offset,
        });
        program.push(libc::sock_filter {
            code: JEQ,
            jt: 1,
            jf: 0,
            k: value,
        });
        program.push(libc::sock_filter {
            code: RET,
            jt: 0,
            jf: 0,
            k: 0,
        });
    };
    let mac = packet.source_mac;
    guard(LD_H, 12, 0x0800);
    guard(
        LD_W,
        0,
        u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]),
    );
    guard(LD_H, 4, u32::from(u16::from_be_bytes([mac[4], mac[5]])));
    guard(
        LD_B,
        14 + 9,
        if packet.proto58 {
            58
        } else {
            u32::from(packet.profile.protocol())
        },
    );
    if let Some(source) = expected_source {
        guard(LD_W, 14 + 12, u32::from(source));
    }
    program.push(libc::sock_filter {
        code: RET,
        jt: 0,
        jf: 0,
        k: 65_535,
    });
    program
}

/// Attaches `kernel_filter_program` to the packet socket, and asks the kernel (4.20 and later) not
/// to hand this socket the frames it sends itself.
fn attach_kernel_filter(
    fd: i32,
    packet: &PacketOptions,
    expected_source: Option<Ipv4Addr>,
) -> io::Result<()> {
    let program = kernel_filter_program(packet, expected_source);
    let descriptor = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_ptr().cast_mut(),
    };
    // SAFETY: the descriptor points at `program`, which stays alive for the call; the kernel
    // copies the instructions.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&descriptor as *const libc::sock_fprog).cast(),
            std::mem::size_of_val(&descriptor) as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // Not available before Linux 4.20; the user-space check of the packet type still applies.
    let on: libc::c_int = 1;
    // SAFETY: `on` is an initialized int that lives for the call.
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            23, // PACKET_IGNORE_OUTGOING
            (&on as *const libc::c_int).cast(),
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    Ok(())
}

fn set_socket_buffers(fd: i32, bytes: usize) -> io::Result<()> {
    if !(256 * 1024..=64 * 1024 * 1024).contains(&bytes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "raw socket buffers must be 256 KiB..64 MiB",
        ));
    }
    let buffer = bytes as i32;
    for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        // SAFETY: value is initialized and remains live for the system call.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&buffer as *const i32).cast(),
                std::mem::size_of_val(&buffer) as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn link_address(index: i32, mac: [u8; 6]) -> libc::sockaddr_ll {
    // SAFETY: sockaddr_ll is a C POD structure where all-zero fields are valid.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    address.sll_ifindex = index;
    address.sll_halen = 6;
    address.sll_addr[..6].copy_from_slice(&mac);
    address
}

async fn send_frame(
    fd: &AsyncFd<OwnedFd>,
    index: i32,
    mac: [u8; 6],
    frame: &[u8],
) -> io::Result<()> {
    let address = link_address(index, mac);
    loop {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| {
            // SAFETY: frame and sockaddr buffers are initialized and live until return.
            let result = unsafe {
                libc::sendto(
                    inner.get_ref().as_raw_fd(),
                    frame.as_ptr().cast(),
                    frame.len(),
                    0,
                    (&address as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else if result as usize != frame.len() {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short Ethernet write",
                ))
            } else {
                Ok(())
            }
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn receive_frame(fd: &AsyncFd<OwnedFd>, frame: &mut [u8]) -> io::Result<(usize, bool)> {
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|inner| {
            // SAFETY: POD sockaddr is initialized and mutable receive buffers are valid.
            let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut size = std::mem::size_of_val(&address) as libc::socklen_t;
            let result = unsafe {
                libc::recvfrom(
                    inner.get_ref().as_raw_fd(),
                    frame.as_mut_ptr().cast(),
                    frame.len(),
                    0,
                    (&mut address as *mut libc::sockaddr_ll).cast(),
                    &mut size,
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok((
                    result as usize,
                    address.sll_pkttype == libc::PACKET_OUTGOING,
                ))
            }
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

/// Errors of `sendto` that mean "not now", not "this socket is broken".
fn is_transient_send_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::ENOBUFS
                | libc::ENOMEM
                | libc::ENETDOWN
                | libc::ENETUNREACH
                | libc::EHOSTUNREACH
                | libc::EINTR
        )
    )
}

async fn resolve_arp(
    fd: &AsyncFd<OwnedFd>,
    index: i32,
    mac: [u8; 6],
    local: Ipv4Addr,
    peer: Ipv4Addr,
) -> Result<[u8; 6]> {
    let mut request = vec![0; 42];
    request[..6].fill(0xff);
    request[6..12].copy_from_slice(&mac);
    request[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    request[22..28].copy_from_slice(&mac);
    request[28..32].copy_from_slice(&local.octets());
    request[38..42].copy_from_slice(&peer.octets());
    for _ in 0..3 {
        send_frame(fd, index, [0xff; 6], &request).await?;
        let attempt = async {
            let mut frame = vec![0; 2048];
            loop {
                let (n, outgoing) = receive_frame(fd, &mut frame).await?;
                if !outgoing
                    && n >= 42
                    && frame[12..22] == [8, 6, 0, 1, 8, 0, 6, 4, 0, 2]
                    && frame[28..32] == peer.octets()
                    && frame[38..42] == local.octets()
                    && frame[32..38] == mac
                {
                    let mut found = [0; 6];
                    found.copy_from_slice(&frame[22..28]);
                    if found[0] & 1 == 0 && found != [0; 6] {
                        return Ok::<_, io::Error>(found);
                    }
                }
            }
        };
        if let Ok(result) = time::timeout(Duration::from_secs(1), attempt).await {
            return Ok(result?);
        }
    }
    anyhow::bail!("ARP next-hop resolution failed; configure peer_mac explicitly")
}

async fn ip_json(arguments: &[String]) -> Result<serde_json::Value> {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .await
        .context("execute iproute2 for interface lookup")?;
    ensure!(
        output.status.success(),
        "iproute2 interface lookup failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    serde_json::from_slice(&output.stdout).context("parse iproute2 interface information")
}
