//! The PROXY protocol header (versions 1 and 2) that tells a destination service which user is
//! really connecting. Without it every user looks like the tunnel (127.0.0.1) to the service
//! behind it, so its logs, limits and bans cannot tell users apart.
//!
//! The server side of a port map with `proxy_protocol` set sends the user's address through the
//! tunnel; the client side writes this header to the destination before any user data. The
//! destination must expect it (for example nginx `proxy_protocol`);
//! a service that does not will read it as garbage.
use crate::wire::ProxyInfo;
use std::net::{IpAddr, SocketAddr};

/// The fixed start of a version 2 header.
const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// The bytes to write to the destination before the user's data.
pub fn header(info: &ProxyInfo) -> Vec<u8> {
    match info.version {
        1 => v1(info.source, info.destination),
        _ => v2(info.source, info.destination),
    }
}

fn v1(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let family = if source.is_ipv4() { "TCP4" } else { "TCP6" };
    format!(
        "PROXY {family} {} {} {} {}\r\n",
        source.ip(),
        destination.ip(),
        source.port(),
        destination.port()
    )
    .into_bytes()
}

fn v2(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut output = V2_SIGNATURE.to_vec();
    // Version 2, command PROXY.
    output.push(0x21);
    let mut addresses = Vec::new();
    let family = match (source.ip(), destination.ip()) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            addresses.extend_from_slice(&from.octets());
            addresses.extend_from_slice(&to.octets());
            0x11 // TCP over IPv4
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => {
            addresses.extend_from_slice(&from.octets());
            addresses.extend_from_slice(&to.octets());
            0x21 // TCP over IPv6
        }
        // Different families cannot be described; ProxyInfo::new never produces them.
        _ => return v2_local(),
    };
    addresses.extend_from_slice(&source.port().to_be_bytes());
    addresses.extend_from_slice(&destination.port().to_be_bytes());
    output.push(family);
    output.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
    output.extend_from_slice(&addresses);
    output
}

/// A version 2 header with command LOCAL: the receiver uses the real connection's addresses.
fn v2_local() -> Vec<u8> {
    let mut output = V2_SIGNATURE.to_vec();
    output.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(version: u8, source: &str, destination: &str) -> ProxyInfo {
        ProxyInfo::new(
            version,
            source.parse().unwrap(),
            destination.parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn version_1_is_the_documented_text_line() {
        assert_eq!(
            header(&info(1, "203.0.113.7:51234", "198.51.100.1:443")),
            b"PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n"
        );
        assert_eq!(
            header(&info(1, "[2001:db8::7]:51234", "[2001:db8::1]:443")),
            b"PROXY TCP6 2001:db8::7 2001:db8::1 51234 443\r\n"
        );
        // The longest legal line is 107 bytes.
        let longest = header(&info(
            1,
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
        ));
        assert!(longest.len() <= 107, "{}", longest.len());
    }

    #[test]
    fn version_2_has_the_signature_the_family_and_the_addresses() {
        let header = header(&info(2, "203.0.113.7:51234", "198.51.100.1:443"));
        assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(header[12], 0x21, "version 2, command PROXY");
        assert_eq!(header[13], 0x11, "TCP over IPv4");
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 12);
        assert_eq!(&header[16..20], [203, 0, 113, 7]);
        assert_eq!(&header[20..24], [198, 51, 100, 1]);
        assert_eq!(u16::from_be_bytes([header[24], header[25]]), 51234);
        assert_eq!(u16::from_be_bytes([header[26], header[27]]), 443);
        assert_eq!(header.len(), 28);

        let header = super::header(&info(2, "[2001:db8::7]:1", "[2001:db8::1]:2"));
        assert_eq!(header[13], 0x21, "TCP over IPv6");
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 36);
        assert_eq!(header.len(), 16 + 36);
    }
}
