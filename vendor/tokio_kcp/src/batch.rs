//! Several UDP datagrams per system call.
//!
//! One `sendto` and one `recvfrom` per packet is what limits a KCP or FEC tunnel on a fast link:
//! at 1400 bytes per packet, 100 Mbit/s is 9000 packets a second, each paying for a system call
//! and a wake-up. On Linux these helpers hand the kernel a whole batch through `sendmmsg` and
//! `recvmmsg`; elsewhere they fall back to one packet per call, so behaviour is the same.
use std::{io, net::SocketAddr};

use tokio::net::UdpSocket;

/// Most datagrams one call hands to the kernel.
pub const MAX_BATCH: usize = 64;

/// Largest datagram a receive slot holds. KCP and FEC MTUs are at most 9000 bytes.
pub const SLOT_SIZE: usize = 9216;

/// Datagrams to send in one batch, kept in one buffer.
#[derive(Default, Debug)]
pub struct Outgoing {
    data: Vec<u8>,
    lens: Vec<usize>,
}

impl Outgoing {
    pub fn push(&mut self, packet: &[u8]) {
        self.data.extend_from_slice(packet);
        self.lens.push(packet.len());
    }

    pub fn is_empty(&self) -> bool {
        self.lens.is_empty()
    }

    pub fn len(&self) -> usize {
        self.lens.len()
    }

    pub fn clear(&mut self) {
        self.data.clear();
        self.lens.clear();
    }

    /// Every datagram, in order.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        let mut start = 0;
        self.lens.iter().map(move |&length| {
            let packet = &self.data[start..start + length];
            start += length;
            packet
        })
    }

    /// The `index`-th datagram.
    pub fn packet(&self, index: usize) -> &[u8] {
        let start: usize = self.lens[..index].iter().sum();
        &self.data[start..start + self.lens[index]]
    }

    /// Sends as many datagrams as the socket takes right now, from the first one on, and
    /// returns how many. `target` is `None` for a connected socket. A full socket buffer is not
    /// an error: it just returns fewer (possibly 0) and the caller decides what to do with the
    /// rest.
    pub fn send(&self, socket: &UdpSocket, target: Option<SocketAddr>) -> io::Result<usize> {
        send_many(socket, target, &self.data, &self.lens)
    }
}

#[cfg(target_os = "linux")]
fn send_many(
    socket: &UdpSocket,
    target: Option<SocketAddr>,
    data: &[u8],
    lens: &[usize],
) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let mut sent_total = 0;
    let mut offset = 0;
    let storage = target.map(sockaddr);
    while sent_total < lens.len() {
        let batch = (lens.len() - sent_total).min(MAX_BATCH);
        let mut vectors: Vec<libc::iovec> = Vec::with_capacity(batch);
        let mut position = offset;
        for &length in &lens[sent_total..sent_total + batch] {
            vectors.push(libc::iovec {
                iov_base: data[position..].as_ptr() as *mut libc::c_void,
                iov_len: length,
            });
            position += length;
        }
        let mut messages: Vec<libc::mmsghdr> = (0..batch)
            .map(|index| {
                // SAFETY: an all-zero mmsghdr is a valid empty message.
                let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
                message.msg_hdr.msg_iov = &mut vectors[index];
                message.msg_hdr.msg_iovlen = 1;
                if let Some((address, length)) = &storage {
                    message.msg_hdr.msg_name = address as *const _ as *mut libc::c_void;
                    message.msg_hdr.msg_namelen = *length;
                }
                message
            })
            .collect();
        let result = socket.try_io(Interest::WRITABLE, || {
            // SAFETY: `messages` points at `vectors` and `storage`, which outlive the call, and
            // each vector points into `data`, which is not modified meanwhile.
            let sent = unsafe {
                libc::sendmmsg(
                    socket.as_raw_fd(),
                    messages.as_mut_ptr(),
                    batch as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                )
            };
            if sent < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(sent as usize)
            }
        });
        match result {
            Ok(sent) => {
                offset += lens[sent_total..sent_total + sent].iter().sum::<usize>();
                sent_total += sent;
                if sent < batch {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => {
                if sent_total > 0 {
                    break;
                }
                return Err(error);
            }
        }
    }
    Ok(sent_total)
}

#[cfg(not(target_os = "linux"))]
fn send_many(
    socket: &UdpSocket,
    target: Option<SocketAddr>,
    data: &[u8],
    lens: &[usize],
) -> io::Result<usize> {
    let mut offset = 0;
    for (sent, &length) in lens.iter().enumerate() {
        let packet = &data[offset..offset + length];
        let result = match target {
            Some(target) => socket.try_send_to(packet, target),
            None => socket.try_send(packet),
        };
        match result {
            Ok(_) => offset += length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(sent),
            Err(error) if sent > 0 => {
                let _ = error;
                return Ok(sent);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(lens.len())
}

#[cfg(target_os = "linux")]
fn sockaddr(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: an all-zero sockaddr_storage is a valid blank address.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match address {
        SocketAddr::V4(v4) => {
            let target = (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>();
            // SAFETY: sockaddr_storage is large and aligned enough for a sockaddr_in.
            unsafe {
                (*target).sin_family = libc::AF_INET as libc::sa_family_t;
                (*target).sin_port = v4.port().to_be();
                (*target).sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                };
            }
            (storage, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        SocketAddr::V6(v6) => {
            let target = (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
            // SAFETY: sockaddr_storage is large and aligned enough for a sockaddr_in6.
            unsafe {
                (*target).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*target).sin6_port = v6.port().to_be();
                (*target).sin6_flowinfo = v6.flowinfo();
                (*target).sin6_addr = libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                };
                (*target).sin6_scope_id = v6.scope_id();
            }
            (storage, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

/// Reads up to `MAX_BATCH` datagrams per call into fixed slots.
pub struct Incoming {
    buffer: Vec<u8>,
    lengths: Vec<usize>,
    sources: Vec<Option<SocketAddr>>,
    count: usize,
}

impl Default for Incoming {
    fn default() -> Self {
        Self::new()
    }
}

impl Incoming {
    pub fn new() -> Self {
        Self {
            buffer: vec![0; MAX_BATCH * SLOT_SIZE],
            lengths: vec![0; MAX_BATCH],
            sources: vec![None; MAX_BATCH],
            count: 0,
        }
    }

    /// Waits for at least one datagram, then takes every datagram that is already queued (up to
    /// the batch size). Returns how many; look at them with `packet`.
    pub async fn receive(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        loop {
            socket.readable().await?;
            match self.try_receive(socket) {
                Ok(count) => {
                    self.count = count;
                    return Ok(count);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }

    /// Room for one datagram, for a source that delivers them one by one; follow it with `finish_one`.
    pub fn slot_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..SLOT_SIZE]
    }

    /// Records that `slot_mut` now holds a datagram of `length` bytes from `source`.
    pub fn finish_one(&mut self, length: usize, source: Option<SocketAddr>) -> usize {
        self.lengths[0] = length.min(SLOT_SIZE);
        self.sources[0] = source;
        self.count = 1;
        1
    }

    /// Where the `index`-th datagram of the last `receive` came from.
    pub fn source(&self, index: usize) -> Option<SocketAddr> {
        self.sources[index]
    }

    /// The `index`-th datagram of the last `receive`, for a caller that rewrites it in place.
    pub fn packet_mut(&mut self, index: usize) -> &mut [u8] {
        let start = index * SLOT_SIZE;
        &mut self.buffer[start..start + self.lengths[index]]
    }

    /// The `index`-th datagram of the last `receive` and where it came from.
    pub fn packet(&self, index: usize) -> (&[u8], Option<SocketAddr>) {
        let start = index * SLOT_SIZE;
        (&self.buffer[start..start + self.lengths[index]], self.sources[index])
    }

    #[cfg(target_os = "linux")]
    fn try_receive(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        use tokio::io::Interest;

        // SAFETY: all-zero values are valid blank addresses.
        let mut names: Vec<libc::sockaddr_storage> =
            (0..MAX_BATCH).map(|_| unsafe { std::mem::zeroed() }).collect();
        let mut vectors: Vec<libc::iovec> = (0..MAX_BATCH)
            .map(|index| libc::iovec {
                iov_base: self.buffer[index * SLOT_SIZE..].as_mut_ptr().cast(),
                iov_len: SLOT_SIZE,
            })
            .collect();
        let mut messages: Vec<libc::mmsghdr> = (0..MAX_BATCH)
            .map(|index| {
                // SAFETY: an all-zero mmsghdr is a valid empty message.
                let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
                message.msg_hdr.msg_iov = &mut vectors[index];
                message.msg_hdr.msg_iovlen = 1;
                message.msg_hdr.msg_name = (&mut names[index] as *mut libc::sockaddr_storage).cast();
                message.msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                message
            })
            .collect();
        let received = socket.try_io(Interest::READABLE, || {
            // SAFETY: `messages` points at `vectors` and `names`, and the vectors at the slots of
            // `self.buffer`; all of them stay alive and untouched during the call.
            let count = unsafe {
                libc::recvmmsg(
                    socket.as_raw_fd(),
                    messages.as_mut_ptr(),
                    MAX_BATCH as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                    std::ptr::null_mut(),
                )
            };
            if count < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(count as usize)
            }
        })?;
        for index in 0..received {
            let truncated = messages[index].msg_hdr.msg_flags & libc::MSG_TRUNC != 0;
            self.lengths[index] = if truncated {
                0
            } else {
                (messages[index].msg_len as usize).min(SLOT_SIZE)
            };
            self.sources[index] = parse_sockaddr(&names[index], messages[index].msg_hdr.msg_namelen);
        }
        Ok(received)
    }

    #[cfg(not(target_os = "linux"))]
    fn try_receive(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        let (length, source) = socket.try_recv_from(&mut self.buffer[..SLOT_SIZE])?;
        self.lengths[0] = length;
        self.sources[0] = Some(source);
        Ok(1)
    }
}

#[cfg(target_os = "linux")]
fn parse_sockaddr(storage: &libc::sockaddr_storage, length: libc::socklen_t) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET if length as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family says this storage holds a sockaddr_in.
            let address = unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            )))
        }
        libc::AF_INET6 if length as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: the family says this storage holds a sockaddr_in6.
            let address = unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )))
        }
        _ => None,
    }
}
