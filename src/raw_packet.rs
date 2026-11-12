//! IPv4 outer packet layouts for the raw carriers. Payload protection belongs
//! to the caller; these routines never contact a remote service or use a shared secret.
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub const PROTO58_MARKER: [u8; 4] = [0xda, 0x66, 0xe7, 0x01];
pub const ETHERNET_HEADER: usize = 14;
pub const IPV4_HEADER: usize = 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RawProfile {
    #[default]
    Tcp,
    Udp,
    Icmp,
    /// ICMPv6 echo-shaped header inside IPv4 protocol58, not outerIPv6.
    Icmpv6,
    /// Bare protocol58, distinct from marker-based legacy proto58_mode.
    #[serde(alias="proto58")]
    Bip,
    Gre,
    Ipip,
    Raw,
    Dns,
}

/// Fixed sizes of the `dns` profile's envelope: an 8-byte UDP header, a 12-byte DNS header, a
/// 28-byte question (an 8-hex-character label derived from the peer and port, a fixed plausible
/// domain, type A, class IN), and an 11-byte EDNS0 OPT record whose RDATA is the tunnel payload.
const DNS_UDP_HDR: usize = 8;
const DNS_HEADER: usize = 12;
const DNS_QUESTION: usize = 28;
const DNS_OPT: usize = 11;
const DNS_OVERHEAD: usize = DNS_UDP_HDR + DNS_HEADER + DNS_QUESTION + DNS_OPT;

impl RawProfile {
    pub fn protocol(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp | Self::Dns => 17,
            Self::Icmp => 1,
            Self::Icmpv6 | Self::Bip => 58,
            Self::Gre => 47,
            Self::Ipip => 4,
            Self::Raw => 253,
        }
    }
    pub fn header_len(self) -> usize {
        match self {
            Self::Tcp => 20,
            Self::Udp | Self::Icmp | Self::Icmpv6 => 8,
            Self::Gre => 4,
            Self::Ipip | Self::Raw | Self::Bip => 0,
            Self::Dns => DNS_OVERHEAD,
        }
    }
}

/// The question section of the `dns` profile: one label derived from the two addresses and the
/// port (the same regardless of which side computes it), a fixed plausible second-level domain,
/// type A, class IN. Different per tunnel pair, unlike a single name every installation shares.
fn dns_question(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> [u8; DNS_QUESTION] {
    use blake2::{Blake2s256, Digest};
    let (ip_lo, ip_hi) = if source_ip <= destination_ip {
        (source_ip, destination_ip)
    } else {
        (destination_ip, source_ip)
    };
    let (port_lo, port_hi) = if source_port <= destination_port {
        (source_port, destination_port)
    } else {
        (destination_port, source_port)
    };
    let digest = Blake2s256::new()
        .chain_update(b"eztunnel raw dns name\0")
        .chain_update(ip_lo.octets())
        .chain_update(ip_hi.octets())
        .chain_update(port_lo.to_be_bytes())
        .chain_update(port_hi.to_be_bytes())
        .finalize();
    let label = hex::encode(&digest[..4]);
    let mut question = [0u8; DNS_QUESTION];
    let mut at = 0;
    for part in [label.as_bytes(), b"cdn-cache".as_slice(), b"net".as_slice()] {
        question[at] = part.len() as u8;
        at += 1;
        question[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    question[at] = 0; // root label
    at += 1;
    question[at..at + 2].copy_from_slice(&1u16.to_be_bytes()); // QTYPE A
    at += 2;
    question[at..at + 2].copy_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    at += 2;
    debug_assert_eq!(at, DNS_QUESTION);
    question
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawOptions {
    pub profile: RawProfile,
    pub interface: Option<String>,
    pub local_ip: Option<Ipv4Addr>,
    pub peer_ip: Ipv4Addr,
    pub l4_port: u16,
    pub source_port: Option<u16>,
    pub hopping: crate::port_hop::Options,
    pub proto58_mode: bool,
    pub spoof_src_ip: Option<Ipv4Addr>,
    pub spoof_dst_ip: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirage_acknowledgement: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub mirage: Option<crate::spoof::MirageOptions>,
    pub peer_mac: Option<String>,
    pub gateway_ip: Option<Ipv4Addr>,
    pub sock_buf: usize,
    pub tcp_flags: String,
    /// Let the kernel drop every frame that is not from the peer (wrong MAC, protocol or source
    /// address) before it reaches this program, instead of copying all traffic of the interface
    /// to user space. On by default; turn it off only to diagnose a problem.
    pub kernel_filter: bool,
    /// Set from `wire_version` 2: the `icmp` profile uses the client's port as the echo id in both
    /// directions, like a real ping reply that copies the id of its request. The network between
    /// the tested servers passes echo replies from Iran only when their id matches a recent request.
    #[serde(skip)]
    pub icmp_id_mirror: bool,
}

impl Default for RawOptions {
    fn default() -> Self {
        Self {
            profile: RawProfile::Tcp,
            interface: None,
            local_ip: None,
            peer_ip: Ipv4Addr::UNSPECIFIED,
            l4_port: 443,
            source_port: None,
            hopping: crate::port_hop::Options::default(),
            proto58_mode: false,
            spoof_src_ip: None,
            spoof_dst_ip: None,
            mirage_acknowledgement: None,
            mirage: None,
            peer_mac: None,
            gateway_ip: None,
            sock_buf: 4_194_304,
            tcp_flags: "pa".into(),
            kernel_filter: true,
            icmp_id_mirror: false,
        }
    }
}

impl RawOptions {
    pub fn proto58_enabled(&self) -> bool {
        self.proto58_mode
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(spec)=&self.mirage {spec.validate(self)?;}
        self.hopping.validate()?;
        ensure!(!self.hopping.enabled || matches!(self.profile,RawProfile::Tcp|RawProfile::Udp),"raw hopping supports TCP/UDP profiles only");
        ensure!(
            !self.peer_ip.is_unspecified()
                && !self.peer_ip.is_multicast()
                && !self.peer_ip.is_broadcast(),
            "raw peer_ip requires a unicast IPv4 address"
        );
        ensure!(
            self.l4_port != 0 && self.source_port != Some(0),
            "raw ports cannot be zero"
        );
        ensure!(
            (262_144..=67_108_864).contains(&self.sock_buf),
            "raw sock_buf must be 262144..67108864"
        );
        for ip in [
            self.local_ip,
            self.spoof_src_ip,
            self.spoof_dst_ip,
            self.gateway_ip,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
                "raw IP fields require unicast IPv4 addresses"
            );
        }
        if let Some(interface) = &self.interface {
            ensure!(
                !interface.is_empty()
                    && interface.len() < 16
                    && interface
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'_' | b'-' | b'.')),
                "invalid raw interface name"
            );
        }
        if let Some(mac) = &self.peer_mac {
            parse_mac(mac)?;
        }
        ensure!(
            !self.tcp_flags.is_empty()
                && self.tcp_flags.len() <= 6
                && self.tcp_flags.bytes().all(|v| b"fsrpau".contains(&v)),
            "raw tcp_flags require f/s/r/p/a/u"
        );
        // proto58 mode uses the real configured IPv4 endpoints.
        ensure!(
            !self.proto58_enabled() || (self.spoof_src_ip.is_none() && self.spoof_dst_ip.is_none()),
            "proto58 mode and IP spoofing cannot be combined"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PacketOptions {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub profile: RawProfile,
    pub proto58: bool,
    pub server: bool,
    pub tcp_camouflage: bool,
    pub tcp_flags: u8,
    pub timestamp_seed: u32,
    /// `icmp` profile: both directions carry the client's port as the echo id.
    pub icmp_id_mirror: bool,
}

impl PacketOptions {
    /// The echo id of the `icmp` profile for packets this side sends.
    fn icmp_send_id(&self) -> u16 {
        if self.icmp_id_mirror && self.server {
            self.destination_port
        } else {
            self.source_port
        }
    }

    /// The echo sequence number of an outgoing packet. In mirror mode the server's replies carry
    /// the top bit and the client's requests do not, so an echo reply that the server's kernel
    /// makes of a request (same id, same payload, the request's sequence number) is never taken
    /// for a packet of the tunnel.
    fn icmp_send_sequence(&self, sequence: u32) -> u16 {
        if self.icmp_id_mirror {
            (sequence as u16 & 0x7fff) | if self.server { 0x8000 } else { 0 }
        } else {
            sequence as u16
        }
    }

    /// The echo id expected in packets this side receives.
    fn icmp_receive_id(&self) -> u16 {
        if self.icmp_id_mirror && !self.server {
            self.source_port
        } else {
            self.destination_port
        }
    }
}

impl PacketOptions {
    pub fn header_len(&self) -> usize {
        if self.proto58 {
            4
        } else if self.tcp_camouflage && self.profile == RawProfile::Tcp {
            if self.tcp_flags & 2 != 0 { 40 } else { 32 }
        } else {
            self.profile.header_len()
        }
    }
}

/// Ethernet II, a 20-byte IPv4 header, the selected outer header, then payload.
/// TCP is deliberately a packet disguise, without a TCP handshake or TCP state.
pub fn encode(options: &PacketOptions, payload: &[u8], sequence: u32) -> Result<Vec<u8>> {
    let extra = options.header_len();
    let ip_length = IPV4_HEADER + extra + payload.len();
    ensure!(
        ip_length <= u16::MAX as usize,
        "raw IPv4 payload exceeds packet size"
    );
    let mut frame = vec![0; ETHERNET_HEADER + ip_length];
    frame[..6].copy_from_slice(&options.destination_mac);
    frame[6..12].copy_from_slice(&options.source_mac);
    frame[12..14].copy_from_slice(&[8, 0]);
    let ip = &mut frame[14..34];
    ip[0] = 0x45;
    if options.tcp_camouflage && options.profile == RawProfile::Tcp && !options.proto58 {
        ip[1] = 0xb8; // FEC IPv4 template: DSCP 46, ECN zero.
        ip[6] = 0x40; // FEC's raw TCP template also forbids fragmentation.
    }
    ip[2..4].copy_from_slice(&(ip_length as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = if options.proto58 {
        58
    } else {
        options.profile.protocol()
    };
    if options.proto58 {
        ip[4..6].copy_from_slice(&(sequence as u16).to_be_bytes());
        ip[6] = 0x40; // proto58 mode forbids fragmentation.
    }
    ip[12..16].copy_from_slice(&options.source_ip.octets());
    ip[16..20].copy_from_slice(&options.destination_ip.octets());
    let sum = checksum(ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    let body = &mut frame[34..];
    if options.proto58 {
        body[..4].copy_from_slice(&PROTO58_MARKER);
    } else {
        match options.profile {
            RawProfile::Tcp | RawProfile::Udp => {
                body[..2].copy_from_slice(&options.source_port.to_be_bytes());
                body[2..4].copy_from_slice(&options.destination_port.to_be_bytes());
                if options.profile == RawProfile::Tcp {
                    body[4..8].copy_from_slice(&sequence.to_be_bytes());
                    body[12..16].copy_from_slice(&[0x50, 0x18, 0xff, 0xff]);
                    if options.tcp_camouflage {
                        let syn = options.tcp_flags & 2 != 0;
                        let tsval = (sequence >> 3).wrapping_add(options.timestamp_seed);
                        let tsecr = tsval.wrapping_sub(sequence % 200).wrapping_sub(50);
                        let seq = if syn {
                            (sequence & 7) + 1
                        } else {
                            sequence
                                .wrapping_mul(128)
                                .wrapping_add(options.timestamp_seed)
                        };
                        let ack = if syn {
                            if options.tcp_flags & 16 != 0 {
                                (sequence & 7) + 2
                            } else {
                                0
                            }
                        } else {
                            seq.wrapping_sub(sequence & 1023).wrapping_add(1400)
                        };
                        body[4..8].copy_from_slice(&seq.to_be_bytes());
                        body[8..12].copy_from_slice(&ack.to_be_bytes());
                        body[12] = (extra as u8 / 4) << 4;
                        body[13] = options.tcp_flags;
                        let offset = if syn {
                            body[20..28].copy_from_slice(&[2, 4, 5, 180, 4, 2, 8, 10]);
                            body[36..40].copy_from_slice(&[1, 3, 3, 8]);
                            28
                        } else {
                            body[20..24].copy_from_slice(&[1, 1, 8, 10]);
                            24
                        };
                        body[offset..offset + 4].copy_from_slice(&tsval.to_be_bytes());
                        body[offset + 4..offset + 8].copy_from_slice(&tsecr.to_be_bytes());
                    }
                } else {
                    let udp_length = body.len() as u16;
                    body[4..6].copy_from_slice(&udp_length.to_be_bytes());
                    // An IPv4 UDP checksum of zero matches the encoder.
                }
            }
            RawProfile::Icmp | RawProfile::Icmpv6 => {
                body[0] = if options.profile==RawProfile::Icmpv6 {if options.server {129}else{128}}else if options.server {0}else{8};
                body[4..6].copy_from_slice(&options.icmp_send_id().to_be_bytes());
                body[6..8].copy_from_slice(&options.icmp_send_sequence(sequence).to_be_bytes());
            }
            RawProfile::Gre => body[..4].copy_from_slice(&[0, 0, 8, 0]),
            RawProfile::Ipip | RawProfile::Raw | RawProfile::Bip => {}
            RawProfile::Dns => {
                body[..2].copy_from_slice(&options.source_port.to_be_bytes());
                body[2..4].copy_from_slice(&options.destination_port.to_be_bytes());
                let udp_length = body.len() as u16;
                body[4..6].copy_from_slice(&udp_length.to_be_bytes());
                let dns = &mut body[DNS_UDP_HDR..];
                dns[..2].copy_from_slice(&(sequence as u16).to_be_bytes());
                if options.server {
                    dns[2] = 0x81; // QR=1, RD=1
                    dns[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN): a believable, answer-free response
                } else {
                    dns[2] = 0x01; // RD=1
                    dns[3] = 0x00;
                }
                dns[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
                dns[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT
                dns[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT
                dns[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT (the OPT record)
                let question = dns_question(
                    options.source_ip,
                    options.destination_ip,
                    options.source_port,
                    options.destination_port,
                );
                dns[DNS_HEADER..DNS_HEADER + DNS_QUESTION].copy_from_slice(&question);
                let opt = &mut dns[DNS_HEADER + DNS_QUESTION..DNS_HEADER + DNS_QUESTION + DNS_OPT];
                opt[0] = 0; // root owner name
                opt[1..3].copy_from_slice(&41u16.to_be_bytes()); // TYPE OPT
                opt[3..5].copy_from_slice(&4096u16.to_be_bytes()); // CLASS: UDP payload size
                // opt[5..9] left zero: extended RCODE, EDNS version, flags
                opt[9..11].copy_from_slice(&(payload.len() as u16).to_be_bytes()); // RDLENGTH
            }
        }
    }
    body[extra..].copy_from_slice(payload);
    if !options.proto58 {
        if options.profile == RawProfile::Tcp {
            let sum = transport_checksum(options.source_ip, options.destination_ip, 6, body);
            body[16..18].copy_from_slice(&sum.to_be_bytes());
        } else if matches!(options.profile, RawProfile::Icmp | RawProfile::Icmpv6) {
            let sum = checksum(body);
            body[2..4].copy_from_slice(&sum.to_be_bytes());
        } else if options.profile == RawProfile::Dns {
            let sum = transport_checksum(options.source_ip, options.destination_ip, 17, body);
            body[6..8].copy_from_slice(&sum.to_be_bytes());
        }
    }
    Ok(frame)
}

/// Validates lengths and checksums before returning a borrowed datagram payload.
/// Ethernet padding is excluded using IPv4's total length.
pub fn decode<'a>(options: &PacketOptions, frame: &'a [u8]) -> Result<&'a [u8]> {
    ensure!(
        frame.len() >= 34 && frame[12..14] == [8, 0],
        "not Ethernet IPv4"
    );
    let ip = &frame[14..];
    let ihl = usize::from(ip[0] & 15) * 4;
    ensure!(
        ip[0] >> 4 == 4 && ihl >= 20 && ihl <= ip.len(),
        "invalid IPv4 header"
    );
    let length = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    ensure!(length >= ihl && length <= ip.len(), "truncated IPv4 packet");
    ensure!(checksum(&ip[..ihl]) == 0, "IPv4 checksum mismatch");
    let fragment = u16::from_be_bytes([ip[6], ip[7]]);
    ensure!(fragment & 0x3fff == 0, "fragmented raw IPv4 packet");
    ensure!(
        ip[9]
            == if options.proto58 {
                58
            } else {
                options.profile.protocol()
            },
        "wrong outer protocol"
    );
    let body = &ip[ihl..length];
    if options.proto58 {
        ensure!(
            body.len() >= 4 && body[..4] == PROTO58_MARKER,
            "invalid proto58 mode marker"
        );
        return Ok(&body[4..]);
    }
    let header = match options.profile {
        RawProfile::Tcp => {
            ensure!(body.len() >= 20, "truncated raw TCP header");
            let offset = usize::from(body[12] >> 4) * 4;
            ensure!(
                offset >= 20 && offset <= body.len(),
                "invalid TCP data offset"
            );
            ensure!(
                u16::from_be_bytes([body[2], body[3]]) == options.source_port,
                "wrong TCP destination port"
            );
            ensure!(
                u16::from_be_bytes([body[0], body[1]]) == options.destination_port,
                "wrong TCP source port"
            );
            let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            ensure!(
                transport_checksum(src, dst, 6, body) == 0,
                "TCP checksum mismatch"
            );
            offset
        }
        RawProfile::Udp => {
            ensure!(
                body.len() >= 8
                    && usize::from(u16::from_be_bytes([body[4], body[5]])) == body.len(),
                "invalid UDP length"
            );
            ensure!(
                u16::from_be_bytes([body[2], body[3]]) == options.source_port,
                "wrong UDP destination port"
            );
            ensure!(
                u16::from_be_bytes([body[0], body[1]]) == options.destination_port,
                "wrong UDP source port"
            );
            if body[6..8] != [0, 0] {
                let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
                let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
                ensure!(
                    transport_checksum(src, dst, 17, body) == 0,
                    "UDP checksum mismatch"
                );
            }
            8
        }
        RawProfile::Icmp | RawProfile::Icmpv6 => {
            let expected=if options.profile==RawProfile::Icmpv6 {if options.server {128}else{129}}else if options.server {8}else{0};
            ensure!(
                body.len() >= 8 && body[1] == 0 && body[0] == expected,
                "invalid ICMP echo disguise"
            );
            ensure!(
                u16::from_be_bytes([body[4], body[5]]) == options.icmp_receive_id(),
                "unexpected ICMP peer identifier"
            );
            ensure!(
                !options.icmp_id_mirror || (body[6] & 0x80 != 0) != options.server,
                "ICMP echo reflected by the peer's kernel"
            );
            ensure!(checksum(body) == 0, "ICMP checksum mismatch");
            8
        }
        RawProfile::Gre => {
            ensure!(
                body.len() >= 4 && body[..4] == [0, 0, 8, 0],
                "unsupported GRE header"
            );
            4
        }
        RawProfile::Ipip | RawProfile::Raw | RawProfile::Bip => 0,
        RawProfile::Dns => {
            ensure!(body.len() >= DNS_OVERHEAD, "truncated DNS disguise");
            ensure!(
                usize::from(u16::from_be_bytes([body[4], body[5]])) == body.len(),
                "invalid UDP length"
            );
            ensure!(
                u16::from_be_bytes([body[2], body[3]]) == options.source_port,
                "wrong UDP destination port"
            );
            ensure!(
                u16::from_be_bytes([body[0], body[1]]) == options.destination_port,
                "wrong UDP source port"
            );
            if body[6..8] != [0, 0] {
                let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
                let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
                ensure!(
                    transport_checksum(src, dst, 17, body) == 0,
                    "UDP checksum mismatch"
                );
            }
            let dns = &body[DNS_UDP_HDR..];
            // The peer's role is the opposite of ours: a server receives query-shaped packets
            // from the client, a client receives the response-shaped answer the server sends.
            let expect_response = !options.server;
            ensure!(
                (dns[2] & 0x80 != 0) == expect_response,
                "unexpected DNS disguise direction"
            );
            ensure!(
                !expect_response || dns[3] & 0x0f == 3,
                "unexpected DNS disguise response code"
            );
            ensure!(
                u16::from_be_bytes([dns[4], dns[5]]) == 1
                    && u16::from_be_bytes([dns[10], dns[11]]) == 1,
                "invalid DNS disguise record counts"
            );
            let question = dns_question(
                options.source_ip,
                options.destination_ip,
                options.source_port,
                options.destination_port,
            );
            ensure!(
                dns[DNS_HEADER..DNS_HEADER + DNS_QUESTION] == question,
                "unexpected DNS disguise question"
            );
            let opt = &dns[DNS_HEADER + DNS_QUESTION..DNS_HEADER + DNS_QUESTION + DNS_OPT];
            ensure!(
                opt[0] == 0 && u16::from_be_bytes([opt[1], opt[2]]) == 41,
                "invalid DNS disguise OPT record"
            );
            let rdlength = usize::from(u16::from_be_bytes([opt[9], opt[10]]));
            ensure!(
                rdlength == body.len() - DNS_OVERHEAD,
                "invalid DNS disguise RDLENGTH"
            );
            DNS_OVERHEAD
        }
    };
    Ok(&body[header..])
}

/// True when the frame's IPv4 source address is the expected one. `None` accepts any source;
/// it is used when address spoofing is configured, because the peer's outer address then differs
/// from its real one on purpose. A frame too short to hold an IPv4 header never matches.
pub fn source_matches(frame: &[u8], expected: Option<Ipv4Addr>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    frame.len() >= ETHERNET_HEADER + IPV4_HEADER
        && frame[ETHERNET_HEADER + 12..ETHERNET_HEADER + 16] == expected.octets()
}

pub fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let parts: Vec<_> = value.split(':').collect();
    ensure!(parts.len() == 6, "MAC address requires six octets");
    let mut bytes = [0; 6];
    for (slot, value) in bytes.iter_mut().zip(parts) {
        ensure!(
            value.len() == 2,
            "MAC address octets require two hex digits"
        );
        *slot = u8::from_str_radix(value, 16)?;
    }
    if bytes == [0; 6] || bytes[0] & 1 != 0 {
        bail!("peer MAC must be a nonzero unicast address");
    }
    Ok(bytes)
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u32::from(pair[0]) << 8;
        if pair.len() == 2 {
            sum += u32::from(pair[1]);
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn transport_checksum(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, data: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(data.len() + 12);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&[0, protocol]);
    pseudo.extend_from_slice(&(data.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(data);
    checksum(&pseudo)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options(profile: RawProfile, server: bool) -> PacketOptions {
        PacketOptions {
            source_mac: [2, 0, 0, 0, 0, 1],
            destination_mac: [2, 0, 0, 0, 0, 2],
            source_ip: Ipv4Addr::new(192, 0, 2, 1),
            destination_ip: Ipv4Addr::new(192, 0, 2, 2),
            source_port: 443,
            destination_port: 444,
            profile,
            proto58: false,
            server,
            tcp_camouflage: false,
            tcp_flags: 24,
            timestamp_seed: 0,
            icmp_id_mirror: false,
        }
    }
    fn peer(options: &PacketOptions) -> PacketOptions {
        let mut p = options.clone();
        p.source_port = options.destination_port;
        p.destination_port = options.source_port;
        p.server = !options.server;
        p
    }
    #[test]
    fn outer_layout_vectors() {
        let mut o = options(RawProfile::Gre, false);
        let f = encode(&o, &[0x45, 0, 0, 20], 0).unwrap();
        assert_eq!(
            hex::encode(&f),
            "02000000000202000000000108004500001c00000000402ff6afc0000201c00002020000080045000014"
        );
        o.proto58 = true;
        let f = encode(&o, &[0x45, 0, 0, 20], 0x1234).unwrap();
        assert_eq!(
            hex::encode(&f),
            "02000000000202000000000108004500001c12344000403aa470c0000201c0000202da66e70145000014"
        );
    }
    #[test]
    fn profiles_decode_both_directions_and_padding() {
        for profile in [
            RawProfile::Tcp,
            RawProfile::Udp,
            RawProfile::Icmp,
            RawProfile::Icmpv6,
            RawProfile::Bip,
            RawProfile::Gre,
            RawProfile::Ipip,
            RawProfile::Raw,
            RawProfile::Dns,
        ] {
            for server in [true, false] {
                for proto58 in [true, false] {
                    let mut o = options(profile, server);
                    o.proto58 = proto58;
                    for payload in [
                        vec![],
                        vec![1],
                        (0..1400).map(|v| (v % 251) as u8).collect(),
                    ] {
                        let mut f = encode(&o, &payload, 0x10203040).unwrap();
                        f.extend_from_slice(&[0; 30]);
                        assert_eq!(decode(&peer(&o), &f).unwrap(), payload);
                    }
                }
            }
        }
    }
    #[test]
    fn icmp_id_mirror_uses_the_client_port_in_both_directions() {
        let mut client = options(RawProfile::Icmp, false);
        client.icmp_id_mirror = true;
        let server = peer(&client);
        // Ethernet 14 + IPv4 20 + ICMP type, code, checksum (4) = the id field.
        let id = |frame: &[u8]| u16::from_be_bytes([frame[38], frame[39]]);
        let request = encode(&client, b"data", 1).unwrap();
        let reply = encode(&server, b"data", 1).unwrap();
        assert_eq!(id(&request), client.source_port);
        assert_eq!(
            id(&reply),
            client.source_port,
            "the reply must copy the request id"
        );
        assert_eq!(decode(&server, &request).unwrap(), b"data");
        assert_eq!(decode(&client, &reply).unwrap(), b"data");
        // Version 1 peers use their own port as the id and do not accept the mirrored form.
        let mut old_client = client.clone();
        old_client.icmp_id_mirror = false;
        let old_reply = encode(&peer(&old_client), b"data", 1).unwrap();
        assert_ne!(id(&old_reply), id(&reply));
        assert!(decode(&client, &old_reply).is_err());
        assert!(decode(&old_client, &reply).is_err());
        // The server's kernel answers a request with a reply of the same id and payload: the
        // client must not take that for a tunnel packet.
        let mut reflected = request.clone();
        reflected[34] = 0;
        reflected[36] = 0;
        reflected[37] = 0;
        let sum = checksum(&reflected[34..]);
        reflected[36..38].copy_from_slice(&sum.to_be_bytes());
        assert!(decode(&client, &reflected).is_err());
    }

    #[test]
    fn bare58_and_echo58_are_distinct_and_legacy_marker_is_unchanged(){
        let bare=options(RawProfile::Bip,false);
        let echo=options(RawProfile::Icmpv6,false);
        let mut legacy=options(RawProfile::Tcp,false);legacy.proto58=true;
        let payload=b"authenticated-payload";
        let a=encode(&bare,payload,7).unwrap();let b=encode(&echo,payload,7).unwrap();let c=encode(&legacy,payload,7).unwrap();
        assert_eq!(a[23],58);assert_eq!(&a[34..],payload);
        assert_eq!(b[34],128);assert_eq!(&b[42..],payload);
        assert_eq!(&c[34..38],&PROTO58_MARKER);
        assert!(decode(&peer(&echo),&a).is_err());assert!(decode(&peer(&legacy),&a).is_err());
        assert_eq!(decode(&peer(&bare),&a).unwrap(),payload);
    }

    #[test]
    fn malformed_outer_packets_rejected() {
        for profile in [
            RawProfile::Tcp,
            RawProfile::Udp,
            RawProfile::Icmp,
            RawProfile::Gre,
            RawProfile::Ipip,
            RawProfile::Raw,
            RawProfile::Dns,
        ] {
            let o = options(profile, false);
            let f = encode(&o, &[1, 2, 3], 7).unwrap();
            for length in 0..f.len() {
                assert!(decode(&peer(&o), &f[..length]).is_err());
            }
            let mut corrupt = f.clone();
            corrupt[30] ^= 1;
            assert!(decode(&peer(&o), &corrupt).is_err());
            let mut fragment = f.clone();
            fragment[20] = 0x20;
            fragment[24] = 0;
            fragment[25] = 0;
            let sum = checksum(&fragment[14..34]);
            fragment[24..26].copy_from_slice(&sum.to_be_bytes());
            assert!(decode(&peer(&o), &fragment).is_err());
        }
        let mut o = options(RawProfile::Tcp, false);
        o.proto58 = true;
        let mut f = encode(&o, &[1, 2, 3], 7).unwrap();
        f[34] ^= 1;
        assert!(decode(&peer(&o), &f).is_err());
    }
    #[test]
    fn fec_tcp_camouflage_options() {
        let mut o = options(RawProfile::Tcp, false);
        o.tcp_camouflage = true;
        o.timestamp_seed = 10;
        let f = encode(&o, &[1, 2, 3], 17).unwrap();
        assert_eq!(f[46], 0x80);
        assert_eq!(&f[54..58], &[1, 1, 8, 10]);
        assert_eq!(&f[38..42], &2186u32.to_be_bytes());
        assert_eq!(decode(&peer(&o), &f).unwrap(), [1, 2, 3]);
        o.tcp_flags = 2;
        let f = encode(&o, &[1, 2, 3], 17).unwrap();
        assert_eq!(f[46], 0xa0);
        assert_eq!(&f[54..62], &[2, 4, 5, 180, 4, 2, 8, 10]);
        assert_eq!(&f[70..74], &[1, 3, 3, 8]);
        assert_eq!(decode(&peer(&o), &f).unwrap(), [1, 2, 3]);
    }
    #[test]
    fn fec_and_proto58_ipv4_templates_are_distinct() {
        let mut o = options(RawProfile::Tcp, false);
        let ordinary = encode(&o, &[1, 2, 3], 17).unwrap();
        assert_eq!(&ordinary[14..16], &[0x45, 0]);
        assert_eq!(&ordinary[18..22], &[0, 0, 0, 0]);
        assert_eq!(ordinary[23], 6);
        o.tcp_camouflage = true;
        let fec = encode(&o, &[1, 2, 3], 17).unwrap();
        assert_eq!(&fec[14..16], &[0x45, 0xb8]);
        assert_eq!(&fec[18..22], &[0, 0, 0x40, 0]);
        assert_eq!(fec[23], 6);
        assert_eq!(decode(&peer(&o), &fec).unwrap(), [1, 2, 3]);
        o.proto58 = true;
        let proto58 = encode(&o, &[1, 2, 3], 17).unwrap();
        assert_eq!(&proto58[14..16], &[0x45, 0]);
        assert_eq!(&proto58[18..22], &[0, 17, 0x40, 0]);
        assert_eq!(proto58[23], 58);
        assert_eq!(&proto58[34..38], &PROTO58_MARKER);
        assert_eq!(decode(&peer(&o), &proto58).unwrap(), [1, 2, 3]);
    }
    #[test]
    fn proto58_mode_selects_protocol_58_and_rejects_unknown_fields() {
        for proto58_mode in [false, true] {
            let raw: RawOptions = serde_json::from_value(
                serde_json::json!({"peer_ip":"192.0.2.2","proto58_mode":proto58_mode}),
            )
            .unwrap();
            raw.validate().unwrap();
            assert_eq!(raw.proto58_enabled(), proto58_mode);
            let mut packet = options(RawProfile::Tcp, false);
            packet.proto58 = raw.proto58_enabled();
            let frame = encode(&packet, &[1, 2, 3], 7).unwrap();
            assert_eq!(frame[23], if proto58_mode { 58 } else { 6 });
            if raw.proto58_enabled() {
                assert_eq!(&frame[34..38], &PROTO58_MARKER);
            }
            assert_eq!(decode(&peer(&packet), &frame).unwrap(), [1, 2, 3]);
        }
        assert!(
            serde_json::from_value::<RawOptions>(
                serde_json::json!({"peer_ip":"192.0.2.2","proto58":true})
            )
            .is_err()
        );
        let spoof: RawOptions = serde_json::from_value(
            serde_json::json!({"peer_ip":"192.0.2.2","proto58_mode":true,"spoof_src_ip":"192.0.2.3"}),
        )
        .unwrap();
        assert!(spoof.validate().is_err());
    }

    #[test]
    fn source_check_compares_the_ipv4_source_address() {
        let o = options(RawProfile::Raw, false);
        let frame = encode(&o, &[1, 2, 3], 1).unwrap();
        assert!(source_matches(&frame, None));
        assert!(source_matches(&frame, Some(o.source_ip)));
        assert!(!source_matches(
            &frame,
            Some(Ipv4Addr::new(203, 0, 113, 77))
        ));
        assert!(!source_matches(&frame[..20], Some(o.source_ip)));
        assert!(source_matches(&frame[..20], None));
    }

    #[test]
    fn dns_disguise_looks_like_a_real_query_and_answer() {
        let client = options(RawProfile::Dns, false);
        let server = peer(&client);
        let request = encode(&client, b"hello", 5).unwrap();
        let reply = encode(&server, b"world", 9).unwrap();
        // Ethernet 14 + IPv4 20 + UDP 8 = where the DNS header starts.
        fn dns(f: &[u8]) -> &[u8] {
            &f[42..]
        }
        // A query: QR=0, RD=1, NXDOMAIN is not set, one question, no answer.
        assert_eq!(dns(&request)[2] & 0x80, 0, "query must not set QR");
        assert_eq!(&dns(&request)[4..6], &1u16.to_be_bytes(), "one question");
        assert_eq!(&dns(&request)[6..8], &0u16.to_be_bytes(), "no answer yet");
        // A reply: QR=1, RCODE=NXDOMAIN (3) -- a believable, answer-free response.
        assert_eq!(dns(&reply)[2] & 0x80, 0x80, "reply must set QR");
        assert_eq!(dns(&reply)[3] & 0x0f, 3, "reply must be NXDOMAIN");
        // The IDs are the sequence numbers, like a real resolver's.
        assert_eq!(&dns(&request)[..2], &5u16.to_be_bytes());
        assert_eq!(&dns(&reply)[..2], &9u16.to_be_bytes());
        // Both round-trip normally.
        assert_eq!(decode(&server, &request).unwrap(), b"hello");
        assert_eq!(decode(&client, &reply).unwrap(), b"world");
    }

    #[test]
    fn dns_disguise_question_differs_per_tunnel_and_rejects_a_mismatch() {
        let a = options(RawProfile::Dns, false);
        let mut b = a.clone();
        b.destination_ip = Ipv4Addr::new(203, 0, 113, 9);
        let fa = encode(&a, b"data", 1).unwrap();
        let fb = encode(&b, b"data", 1).unwrap();
        // A different peer makes a different question: not one name every tunnel shares.
        assert_ne!(&fa[42 + 12..42 + 12 + 28], &fb[42 + 12..42 + 12 + 28]);
        // Ports still match (b only changed its peer address), but the question does not: a
        // packet built for one tunnel pair is rejected by another pair's decoder.
        assert!(decode(&peer(&b), &fa).is_err());
        assert!(decode(&peer(&a), &fa).is_ok());
    }

    #[test]
    fn dns_disguise_rejects_a_tampered_question_or_opt_record() {
        let client = options(RawProfile::Dns, false);
        let server = peer(&client);
        let frame = encode(&client, b"hello", 5).unwrap();
        // Flip a byte inside the question label.
        let mut bad_question = frame.clone();
        bad_question[42 + 12] ^= 1;
        assert!(decode(&server, &bad_question).is_err());
        // Claim the OPT record is a different type.
        let mut bad_opt = frame.clone();
        bad_opt[42 + 12 + 28 + 1] ^= 1;
        assert!(decode(&server, &bad_opt).is_err());
        // Lie about the OPT record's RDLENGTH.
        let mut bad_length = frame.clone();
        let at = 42 + 12 + 28 + 9;
        bad_length[at..at + 2].copy_from_slice(&999u16.to_be_bytes());
        assert!(decode(&server, &bad_length).is_err());
    }
}
