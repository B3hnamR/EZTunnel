//! Version 1 multiplexing frames, carried exclusively inside authenticated Noise records.
use anyhow::{Result, bail, ensure};
use std::net::{IpAddr, SocketAddr};

pub const DATA_SIZE: usize = 16 * 1024;
const TEXT_SIZE: usize = 1024;
/// Frame tag of the padded envelope.
const PADDED: u8 = 11;

/// Wire v3's direction-specific per-session format transform. Noise remains the cipher.
#[derive(Clone)]
pub struct Rotation {
    key: [u8; 32],
    order: [[u8; 5]; 6],
}

impl Rotation {
    pub fn new(key: [u8; 32]) -> Self {
        let mut random = blake3::Hasher::new_keyed(&key);
        random.update(b"eztunnel wire v3 header order");
        let mut stream = random.finalize_xof();
        let mut order = [[0; 5]; 6];
        for length in 1..=5 {
            for (index, entry) in order[length][..length].iter_mut().enumerate() {
                *entry = index as u8;
            }
            for index in (1..length).rev() {
                // Rejection sampling keeps Fisher-Yates unbiased.
                let range = index + 1;
                let cap = 256 - 256 % range;
                let selected = loop {
                    let mut byte = [0];
                    stream.fill(&mut byte);
                    if usize::from(byte[0]) < cap {
                        break usize::from(byte[0]) % range;
                    }
                };
                order[length].swap(index, selected);
            }
        }
        Self { key, order }
    }

    fn mask(&self, nonce: u64, bytes: &mut [u8]) {
        let mut mask = blake3::Hasher::new_keyed(&self.key);
        mask.update(b"eztunnel wire v3 record mask");
        mask.update(&nonce.to_be_bytes());
        let mut stream = mask.finalize_xof();
        let mut block = [0; 256];
        for chunk in bytes.chunks_mut(block.len()) {
            stream.fill(&mut block[..chunk.len()]);
            for (byte, mask) in chunk.iter_mut().zip(&block) {
                *byte ^= mask;
            }
        }
    }

    pub fn encode(&self, nonce: u64, bytes: &mut [u8]) {
        self.mask(nonce, bytes);
        let length = bytes.len().min(5);
        let mut header = [0; 5];
        header[..length].copy_from_slice(&bytes[..length]);
        for index in 0..length {
            bytes[index] = header[usize::from(self.order[length][index])];
        }
    }

    pub fn decode(&self, nonce: u64, bytes: &mut [u8]) {
        let length = bytes.len().min(5);
        let mut header = [0; 5];
        header[..length].copy_from_slice(&bytes[..length]);
        for index in 0..length {
            bytes[usize::from(self.order[length][index])] = header[index];
        }
        self.mask(nonce, bytes);
    }
}

impl Drop for Rotation {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.order.zeroize();
    }
}

pub struct Codecs {
    pub tx: Rotation,
    pub rx: Rotation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Tcp,
    Udp,
}

/// Who connected to a forwarded port: the destination service gets this in a PROXY protocol
/// header, so it can see the real user address instead of the tunnel's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyInfo {
    /// PROXY protocol version to write: 1 (text) or 2 (binary).
    pub version: u8,
    /// The user's address.
    pub source: SocketAddr,
    /// The address the user connected to.
    pub destination: SocketAddr,
}

impl ProxyInfo {
    /// Both addresses must be of one IP family; an IPv4-mapped IPv6 address counts as IPv4.
    pub fn new(version: u8, source: SocketAddr, destination: SocketAddr) -> Option<Self> {
        let canonical =
            |address: SocketAddr| SocketAddr::new(address.ip().to_canonical(), address.port());
        let (source, destination) = (canonical(source), canonical(destination));
        (matches!(version, 1 | 2) && source.is_ipv4() == destination.is_ipv4()).then_some(Self {
            version,
            source,
            destination,
        })
    }
}

fn push_address(output: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&address.port().to_be_bytes());
}

/// Reads one address written by `push_address`; returns it and the bytes that follow.
fn take_address(input: &[u8]) -> Result<(SocketAddr, &[u8])> {
    let length = match input.first() {
        Some(4) => 4,
        Some(6) => 16,
        _ => bail!("invalid address family"),
    };
    ensure!(input.len() >= 1 + length + 2, "truncated address");
    let octets = &input[1..1 + length];
    let ip = if length == 4 {
        IpAddr::from(<[u8; 4]>::try_from(octets)?)
    } else {
        // Canonical, like ProxyInfo::new: an IPv4-mapped IPv6 address sent as a 16-byte address
        // must still compare as IPv4 against a plain 4-byte one from the other end.
        IpAddr::from(<[u8; 16]>::try_from(octets)?).to_canonical()
    };
    let port = u16::from_be_bytes([input[1 + length], input[2 + length]]);
    Ok((SocketAddr::new(ip, port), &input[3 + length..]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Open {
        id: u32,
        kind: StreamKind,
        target: String,
        /// Only for TCP streams of a port map that has `proxy_protocol` set.
        proxy: Option<ProxyInfo>,
    },
    Opened {
        id: u32,
    },
    Data {
        id: u32,
        data: Vec<u8>,
    },
    Eof {
        id: u32,
    },
    Close {
        id: u32,
    },
    Error {
        id: u32,
        message: String,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Credit {
        id: u32,
        frames: u32,
    },
}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        match self {
            Self::Open {
                id,
                kind,
                target,
                proxy,
            } => {
                ensure!(
                    !target.is_empty() && target.len() <= TEXT_SIZE,
                    "invalid target length"
                );
                ensure!(!target.contains('\0'), "invalid target");
                match proxy {
                    // Tag 10: a TCP open that also carries the user's address. Streams without
                    // one keep the original tag-1 bytes.
                    Some(info) => {
                        ensure!(
                            *kind == StreamKind::Tcp,
                            "PROXY protocol is for TCP streams"
                        );
                        ensure!(
                            matches!(info.version, 1 | 2)
                                && info.source.is_ipv4() == info.destination.is_ipv4(),
                            "invalid PROXY information"
                        );
                        header(&mut output, 10, *id)?;
                        output.push(info.version);
                        push_address(&mut output, info.source);
                        push_address(&mut output, info.destination);
                    }
                    None => {
                        header(&mut output, 1, *id)?;
                        output.push(match kind {
                            StreamKind::Tcp => 1,
                            StreamKind::Udp => 2,
                        });
                    }
                }
                output.extend_from_slice(target.as_bytes());
            }
            Self::Opened { id } => header(&mut output, 2, *id)?,
            Self::Data { id, data } => {
                ensure!(data.len() <= DATA_SIZE, "data exceeds frame limit");
                header(&mut output, 3, *id)?;
                output.extend_from_slice(data);
            }
            Self::Eof { id } => header(&mut output, 4, *id)?,
            // Stream 0 is the session's own goodbye (see `farewell`); every other frame refuses it.
            Self::Close { id } => {
                output.push(5);
                output.extend_from_slice(&id.to_be_bytes());
            }
            Self::Error { id, message } => {
                ensure!(message.len() <= TEXT_SIZE, "error exceeds frame limit");
                header(&mut output, 6, *id)?;
                output.extend_from_slice(message.as_bytes());
            }
            Self::Credit { id, frames } => {
                ensure!((1..=16).contains(frames), "invalid flow-control credit");
                header(&mut output, 9, *id)?;
                output.extend_from_slice(&frames.to_be_bytes());
            }
            Self::Ping { nonce } | Self::Pong { nonce } => {
                output.push(if matches!(self, Self::Ping { .. }) {
                    7
                } else {
                    8
                });
                output.extend_from_slice(&nonce.to_be_bytes());
            }
        }
        Ok(output)
    }

    /// Like `encode`, with `padding` extra bytes inside the same encrypted record so that the
    /// record's size no longer shows the frame's size (tag 11: padding length, frame, padding).
    pub fn encode_padded(&self, padding: usize) -> Result<Vec<u8>> {
        ensure!(padding <= 255, "padding exceeds 255 bytes");
        let inner = self.encode()?;
        let mut output = Vec::with_capacity(inner.len() + padding + 2);
        output.push(PADDED);
        output.push(padding as u8);
        output.extend_from_slice(&inner);
        output.resize(output.len() + padding, 0);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        ensure!(!input.is_empty(), "empty frame");
        let kind = input[0];
        if kind == 12 {
            anyhow::bail!("reserved frame type");
        }
        if kind == PADDED {
            ensure!(input.len() >= 3, "truncated padded frame");
            let padding = usize::from(input[1]);
            ensure!(input.len() > 2 + padding, "invalid padding length");
            let inner = &input[2..input.len() - padding];
            ensure!(inner[0] != PADDED, "nested padding");
            return Self::decode(inner);
        }
        if kind == 7 || kind == 8 {
            ensure!(input.len() == 9, "invalid heartbeat frame");
            let nonce = u64::from_be_bytes(input[1..9].try_into()?);
            return Ok(if kind == 7 {
                Self::Ping { nonce }
            } else {
                Self::Pong { nonce }
            });
        }
        ensure!(input.len() >= 5, "truncated frame");
        let id = u32::from_be_bytes(input[1..5].try_into()?);
        ensure!(
            id != 0 || (kind == 5 && input.len() == 5),
            "stream zero is reserved"
        );
        let tail = &input[5..];
        Ok(match kind {
            1 => {
                ensure!(
                    tail.len() >= 2 && tail.len() <= TEXT_SIZE + 1,
                    "invalid open frame"
                );
                let kind = match tail[0] {
                    1 => StreamKind::Tcp,
                    2 => StreamKind::Udp,
                    _ => bail!("unknown stream kind"),
                };
                let target = std::str::from_utf8(&tail[1..])?.to_owned();
                ensure!(!target.contains('\0'), "invalid target");
                Self::Open {
                    id,
                    kind,
                    target,
                    proxy: None,
                }
            }
            10 => {
                ensure!(tail.len() >= 2, "invalid proxied open frame");
                let version = tail[0];
                ensure!(matches!(version, 1 | 2), "unknown PROXY protocol version");
                let (source, rest) = take_address(&tail[1..])?;
                let (destination, rest) = take_address(rest)?;
                ensure!(
                    source.is_ipv4() == destination.is_ipv4(),
                    "PROXY addresses of different families"
                );
                ensure!(
                    !rest.is_empty() && rest.len() <= TEXT_SIZE,
                    "invalid target length"
                );
                let target = std::str::from_utf8(rest)?.to_owned();
                ensure!(!target.contains('\0'), "invalid target");
                Self::Open {
                    id,
                    kind: StreamKind::Tcp,
                    target,
                    proxy: Some(ProxyInfo {
                        version,
                        source,
                        destination,
                    }),
                }
            }
            2 | 4 | 5 => {
                ensure!(tail.is_empty(), "trailing frame bytes");
                match kind {
                    2 => Self::Opened { id },
                    4 => Self::Eof { id },
                    _ => Self::Close { id },
                }
            }
            3 => {
                ensure!(tail.len() <= DATA_SIZE, "oversized data frame");
                Self::Data {
                    id,
                    data: tail.to_vec(),
                }
            }
            6 => {
                ensure!(tail.len() <= TEXT_SIZE, "oversized error frame");
                Self::Error {
                    id,
                    message: std::str::from_utf8(tail)?.to_owned(),
                }
            }
            9 => {
                ensure!(tail.len() == 4, "invalid credit frame");
                let frames = u32::from_be_bytes(tail.try_into()?);
                ensure!((1..=16).contains(&frames), "invalid flow-control credit");
                Self::Credit { id, frames }
            }
            _ => bail!("unknown frame type"),
        })
    }
}

fn header(output: &mut Vec<u8>, tag: u8, id: u32) -> Result<()> {
    ensure!(id != 0, "stream zero is reserved");
    output.push(tag);
    output.extend_from_slice(&id.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_transforms_short_datagrams_padded_frames_and_large_records_reversibly() {
        let codec = Rotation::new([81; 32]);
        for length in [1, 2, 3, 4, 5, 7, 16, 300, 65519] {
            let plain: Vec<u8> = (0..length).map(|n| n as u8).collect();
            for nonce in [0, 1, 99, u64::MAX - 1] {
                let mut rotated = plain.clone();
                codec.encode(nonce, &mut rotated);
                assert_ne!(rotated, plain);
                assert_eq!(rotated.len(), plain.len());
                codec.decode(nonce, &mut rotated);
                assert_eq!(rotated, plain);
            }
        }
        let frame = Frame::Data {
            id: 3,
            data: b"rotated and padded".to_vec(),
        };
        let mut bytes = frame.encode_padded(255).unwrap();
        codec.encode(5, &mut bytes);
        codec.decode(5, &mut bytes);
        assert_eq!(Frame::decode(&bytes).unwrap(), frame);
    }

    #[test]
    fn v3_sessions_directions_and_record_nonces_use_different_formats() {
        let frame = Frame::Open {
            id: 9,
            kind: StreamKind::Tcp,
            target: "localhost:80".into(),
            proxy: None,
        }
        .encode()
        .unwrap();
        let mut a = frame.clone();
        let mut b = frame.clone();
        let mut c = frame.clone();
        Rotation::new([1; 32]).encode(0, &mut a);
        Rotation::new([2; 32]).encode(0, &mut b);
        Rotation::new([1; 32]).encode(1, &mut c);
        assert_ne!(a, b);
        assert_ne!(a, c);
        Rotation::new([2; 32]).decode(0, &mut a);
        assert_ne!(a, frame);
    }

    #[test]
    fn all_frame_types_roundtrip() -> Result<()> {
        let frames = [
            Frame::Open {
                id: 7,
                kind: StreamKind::Tcp,
                target: "localhost:80".into(),
                proxy: None,
            },
            Frame::Open {
                id: 8,
                kind: StreamKind::Udp,
                target: "[::1]:53".into(),
                proxy: None,
            },
            Frame::Open {
                id: 9,
                kind: StreamKind::Tcp,
                target: "127.0.0.1:2256".into(),
                proxy: ProxyInfo::new(
                    2,
                    "203.0.113.7:51234".parse().unwrap(),
                    "198.51.100.1:443".parse().unwrap(),
                ),
            },
            Frame::Open {
                id: 10,
                kind: StreamKind::Tcp,
                target: "127.0.0.1:80".into(),
                proxy: ProxyInfo::new(
                    1,
                    "[2001:db8::7]:51234".parse().unwrap(),
                    "[2001:db8::1]:443".parse().unwrap(),
                ),
            },
            Frame::Opened { id: 7 },
            Frame::Data {
                id: 7,
                data: vec![0, 255, 3],
            },
            Frame::Data {
                id: 8,
                data: vec![],
            },
            Frame::Eof { id: 7 },
            Frame::Close { id: 7 },
            Frame::Error {
                id: 7,
                message: "denied".into(),
            },
            Frame::Ping { nonce: u64::MAX },
            Frame::Pong { nonce: 1 },
            Frame::Credit { id: 7, frames: 16 },
        ];
        for frame in frames {
            assert_eq!(Frame::decode(&frame.encode()?)?, frame);
        }
        Ok(())
    }

    #[test]
    fn padding_changes_the_size_but_not_the_frame() -> Result<()> {
        let frame = Frame::Data {
            id: 5,
            data: vec![1, 2, 3, 4],
        };
        let plain = frame.encode()?;
        for padding in [0, 1, 17, 255] {
            let padded = frame.encode_padded(padding)?;
            assert_eq!(padded.len(), plain.len() + 2 + padding);
            assert_eq!(Frame::decode(&padded)?, frame);
        }
        for frame in [Frame::Ping { nonce: 9 }, Frame::Eof { id: 3 }] {
            assert_eq!(Frame::decode(&frame.encode_padded(40)?)?, frame);
        }
        assert!(frame.encode_padded(256).is_err());
        // A padded record that lies about its padding, or wraps another padded one, is refused.
        assert!(Frame::decode(&[PADDED, 0]).is_err());
        assert!(Frame::decode(&[PADDED, 9, 2, 0, 0, 0, 1]).is_err());
        let mut nested = vec![PADDED, 0];
        nested.extend_from_slice(&frame.encode_padded(2)?);
        assert!(Frame::decode(&nested).is_err());
        Ok(())
    }

    #[test]
    fn malformed_frames_are_rejected_without_panics() {
        assert!(
            Frame::Open {
                id: 1,
                kind: StreamKind::Tcp,
                target: "host\0:80".into(),
                proxy: None,
            }
            .encode()
            .is_err()
        );
        // PROXY information only goes with TCP, and its addresses must be of one family.
        let source = "203.0.113.7:1".parse().unwrap();
        let destination = "198.51.100.1:2".parse().unwrap();
        let info = ProxyInfo::new(1, source, destination);
        assert!(
            Frame::Open {
                id: 1,
                kind: StreamKind::Udp,
                target: "x:1".into(),
                proxy: info,
            }
            .encode()
            .is_err()
        );
        assert!(ProxyInfo::new(3, source, destination).is_none());
        assert!(ProxyInfo::new(1, source, "[2001:db8::1]:2".parse().unwrap()).is_none());
        // An IPv4-mapped IPv6 address is treated as IPv4.
        assert_eq!(
            ProxyInfo::new(1, "[::ffff:203.0.113.7]:1".parse().unwrap(), destination)
                .unwrap()
                .source,
            source
        );
        for bad in [
            vec![],
            vec![1],
            vec![1, 0, 0, 0, 1],
            vec![2, 0, 0, 0, 0],
            vec![2, 0, 0, 0, 1, 0],
            vec![1, 0, 0, 0, 1, 8, 65],
            vec![7, 0],
            vec![6, 0, 0, 0, 1, 255],
            vec![255, 0, 0, 0, 1],
            vec![10, 0, 0, 0, 1],
            vec![
                10, 0, 0, 0, 1, 3, 4, 1, 1, 1, 1, 0, 80, 4, 1, 1, 1, 1, 0, 80, b'x',
            ],
            vec![
                10, 0, 0, 0, 1, 1, 4, 1, 1, 1, 1, 0, 80, 4, 1, 1, 1, 1, 0, 80,
            ],
            vec![10, 0, 0, 0, 1, 1, 4, 1, 1, 1, 1, 0, 80, 6, 0, 0],
        ] {
            assert!(Frame::decode(&bad).is_err(), "{bad:?}");
        }
        for tag in 0..=255u8 {
            for len in 0..40 {
                let mut input = vec![tag; len];
                if len > 0 {
                    input[0] = tag;
                }
                let _ = Frame::decode(&input);
            }
        }
        assert!(
            Frame::Data {
                id: 1,
                data: vec![0; DATA_SIZE + 1]
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn a_decoded_proxy_frame_treats_an_ipv4_mapped_address_as_ipv4() -> Result<()> {
        // A peer may encode one side as a plain 4-byte IPv4 address and the other as the
        // equivalent 16-byte IPv4-mapped IPv6 address; the family check must not see those as
        // different families, the way ProxyInfo::new already does not.
        let mapped = std::net::Ipv4Addr::new(198, 51, 100, 1).to_ipv6_mapped();
        let mut bytes = vec![10, 0, 0, 0, 1, 1, 4, 203, 0, 113, 7, 0, 1];
        bytes.push(6);
        bytes.extend_from_slice(&mapped.octets());
        bytes.extend_from_slice(&[0, 2]);
        bytes.push(b'x');
        let frame = Frame::decode(&bytes)?;
        let Frame::Open {
            proxy: Some(proxy), ..
        } = frame
        else {
            panic!("expected an Open frame with PROXY information: {frame:?}");
        };
        assert_eq!(proxy.source, "203.0.113.7:1".parse().unwrap());
        assert_eq!(proxy.destination, "198.51.100.1:2".parse().unwrap());
        assert!(proxy.source.is_ipv4() && proxy.destination.is_ipv4());
        Ok(())
    }
}
