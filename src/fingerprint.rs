//! Reading a TLS ClientHello: the parts a network observer fingerprints (cipher suites, extensions,
//! groups, signature algorithms, ALPN, server name) and the JA3 and JA4 strings made from them.
//!
//! It is used by `eztunnel tlscheck`, which shows what a tunnel's TLS client would send, and by the
//! tests that compare that with what Chrome sends.
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

/// The values a client puts in a list to keep servers honest (RFC 8701): `0x0a0a`, `0x1a1a`, ...
pub fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    /// Extension types in the order they were sent.
    pub extensions: Vec<u16>,
    pub groups: Vec<u16>,
    pub point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub alpn: Vec<String>,
    pub server_name: Option<String>,
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        ensure!(self.data.len() >= count, "the ClientHello is cut short");
        let (head, tail) = self.data.split_at(count);
        self.data = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn vector8(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }
    fn vector16(&mut self) -> Result<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

fn u16_list(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect()
}

/// Parses the first TLS record of a connection, which must hold a ClientHello.
pub fn parse(record: &[u8]) -> Result<ClientHello> {
    let mut outer = Reader { data: record };
    ensure!(outer.u8()? == 0x16, "not a TLS handshake record");
    outer.take(2)?; // record version
    let handshake = outer.vector16()?;
    let mut reader = Reader { data: handshake };
    ensure!(reader.u8()? == 1, "not a ClientHello");
    let length = {
        let bytes = reader.take(3)?;
        usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2])
    };
    let mut body = Reader {
        data: reader.take(length)?,
    };
    let mut hello = ClientHello {
        legacy_version: body.u16()?,
        ..ClientHello::default()
    };
    body.take(32)?; // random
    body.vector8()?; // session id
    hello.ciphers = u16_list(body.vector16()?);
    body.vector8()?; // compression methods
    let mut extensions = Reader {
        data: body.vector16()?,
    };
    while !extensions.data.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vector16()?;
        hello.extensions.push(kind);
        let mut inner = Reader { data };
        match kind {
            0 => {
                let mut list = Reader {
                    data: inner.vector16()?,
                };
                while !list.data.is_empty() {
                    let name_type = list.u8()?;
                    let name = list.vector16()?;
                    if name_type == 0 && hello.server_name.is_none() {
                        hello.server_name = Some(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            10 => hello.groups = u16_list(inner.vector16()?),
            11 => hello.point_formats = inner.vector8()?.to_vec(),
            13 => hello.signature_algorithms = u16_list(inner.vector16()?),
            16 => {
                let mut list = Reader {
                    data: inner.vector16()?,
                };
                while !list.data.is_empty() {
                    let name = list.vector8()?;
                    hello.alpn.push(String::from_utf8_lossy(name).into_owned());
                }
            }
            43 => hello.supported_versions = u16_list(inner.vector8()?),
            _ => {}
        }
    }
    Ok(hello)
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn hash12(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))[..12].to_string()
}

impl ClientHello {
    fn without_grease(values: &[u16]) -> Vec<u16> {
        values
            .iter()
            .copied()
            .filter(|value| !is_grease(*value))
            .collect()
    }

    /// Whether the hello carries any GREASE value (in ciphers, extensions, groups, versions or
    /// signature algorithms).
    pub fn has_grease(&self) -> bool {
        [
            &self.ciphers,
            &self.extensions,
            &self.groups,
            &self.supported_versions,
            &self.signature_algorithms,
        ]
        .iter()
        .any(|list| list.iter().any(|value| is_grease(*value)))
    }

    /// JA3 before hashing: version, ciphers, extensions, groups and point formats, in the order
    /// sent, GREASE left out.
    pub fn ja3(&self) -> String {
        let join = |values: Vec<u16>| {
            values
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("-")
        };
        let points = self
            .point_formats
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-");
        format!(
            "{},{},{},{},{}",
            self.legacy_version,
            join(Self::without_grease(&self.ciphers)),
            join(Self::without_grease(&self.extensions)),
            join(Self::without_grease(&self.groups)),
            points
        )
    }

    /// The parts of JA4 that are hashed, in the readable form (`ja4_r`).
    pub fn ja4_raw(&self) -> String {
        let ciphers = Self::without_grease(&self.ciphers);
        let extensions = Self::without_grease(&self.extensions);
        let versions = Self::without_grease(&self.supported_versions);
        let highest = versions
            .iter()
            .copied()
            .max()
            .unwrap_or(self.legacy_version);
        let version = match highest {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        };
        let alpn = self
            .alpn
            .first()
            .filter(|name| !name.is_empty())
            .map(|name| {
                let bytes = name.as_bytes();
                format!("{}{}", bytes[0] as char, bytes[bytes.len() - 1] as char)
            })
            .unwrap_or_else(|| "00".to_string());
        let first = format!(
            "t{version}{}{:02}{:02}{alpn}",
            if self.server_name.is_some() { 'd' } else { 'i' },
            ciphers.len().min(99),
            extensions.len().min(99)
        );
        let mut sorted_ciphers = ciphers;
        sorted_ciphers.sort_unstable();
        let mut sorted_extensions: Vec<u16> = extensions
            .into_iter()
            .filter(|kind| *kind != 0 && *kind != 16)
            .collect();
        sorted_extensions.sort_unstable();
        let signatures = Self::without_grease(&self.signature_algorithms);
        let mut third = hex_list(&sorted_extensions);
        if !signatures.is_empty() {
            third.push('_');
            third.push_str(&hex_list(&signatures));
        }
        format!("{first}_{}_{third}", hex_list(&sorted_ciphers))
    }

    /// JA4: the raw form with the two lists replaced by the first 12 hex digits of their SHA-256.
    pub fn ja4(&self) -> String {
        let raw = self.ja4_raw();
        let mut parts = raw.splitn(3, '_');
        let (first, ciphers, rest) = (
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
        );
        format!("{first}_{}_{}", hash12(ciphers), hash12(rest))
    }

    /// Short human summary used by `tlscheck`.
    pub fn describe(&self) -> String {
        let order = self
            .extensions
            .iter()
            .map(|kind| {
                if is_grease(*kind) {
                    "GREASE".to_string()
                } else {
                    format!("{kind:04x}")
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "JA4     {}\nJA4_r   {}\nJA3     {}\nSNI     {}\nALPN    {}\nGREASE  {}\nextension order as sent: {order}",
            self.ja4(),
            self.ja4_raw(),
            self.ja3(),
            self.server_name.as_deref().unwrap_or("(none)"),
            if self.alpn.is_empty() {
                "(none)".to_string()
            } else {
                self.alpn.join(", ")
            },
            if self.has_grease() { "yes" } else { "no" },
        )
    }
}

/// Reads one ClientHello from the start of a stream of bytes (more than one record is not needed:
/// a ClientHello, even with a post-quantum key share, fits in one).
pub fn parse_stream(bytes: &[u8]) -> Result<ClientHello> {
    let mut offset=0;let mut handshake=Vec::new();
    while offset+5<=bytes.len(){
        ensure!(bytes[offset]==0x16,"not a TLS handshake record");
        let size=usize::from(u16::from_be_bytes(bytes[offset+3..offset+5].try_into().unwrap()));
        ensure!(size<=18432&&offset+5+size<=bytes.len(),"ClientHello TLS record is incomplete or oversized");
        handshake.extend_from_slice(&bytes[offset+5..offset+5+size]);ensure!(handshake.len()<=65535,"ClientHello exceeds diagnostic bound");
        if handshake.len()>=4{
            ensure!(handshake[0]==1,"not a ClientHello");
            let wanted=4+(usize::from(handshake[1])<<16|usize::from(handshake[2])<<8|usize::from(handshake[3]));
            ensure!(wanted<=65535,"ClientHello exceeds diagnostic bound");
            if handshake.len()>=wanted{handshake.truncate(wanted);let mut record=vec![0x16,3,3];record.extend_from_slice(&(wanted as u16).to_be_bytes());record.extend_from_slice(&handshake);return parse(&record).context("parse reassembled ClientHello");}
        }
        offset+=5+size;
    }
    bail!("ClientHello is incomplete across TLS records")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_hello_split_across_tls_records_has_the_same_fingerprint(){
        let bytes=sample();let expected=parse_stream(&bytes).unwrap();let handshake=&bytes[5..];
        for split in [1,3,17,handshake.len()-1]{
            let mut fragmented=Vec::new();for part in [&handshake[..split],&handshake[split..]]{fragmented.extend_from_slice(&[0x16,3,3]);fragmented.extend_from_slice(&(part.len()as u16).to_be_bytes());fragmented.extend_from_slice(part);}
            let actual=parse_stream(&fragmented).unwrap();assert_eq!(actual.ja3(),expected.ja3());assert_eq!(actual.ja4(),expected.ja4());
            assert!(parse_stream(&fragmented[..fragmented.len()-1]).is_err());
        }
    }

    #[test]
    fn grease_values_are_recognised() {
        for value in [0x0a0a, 0x1a1a, 0x5a5a, 0x8a8a, 0xfafa] {
            assert!(is_grease(value), "{value:04x}");
        }
        for value in [0x0a1a, 0x1301, 0xc02b, 0x0000, 0x002b, 0xff01] {
            assert!(!is_grease(value), "{value:04x}");
        }
    }

    #[test]
    fn ja4_hashes_match_what_chrome_152_reported() {
        // The raw form and the hashes printed for Chrome 152 by a public fingerprint service.
        let ciphers = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9";
        let rest = "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601";
        assert_eq!(hash12(ciphers), "8daaf6152771");
        assert_eq!(hash12(rest), "806a8c22fdea");
    }

    /// A small hand-made ClientHello: one GREASE cipher, SNI, ALPN, groups, signature algorithms.
    fn sample() -> Vec<u8> {
        let mut extensions = Vec::new();
        let mut add = |kind: u16, data: &[u8]| {
            extensions.extend_from_slice(&kind.to_be_bytes());
            extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(data);
        };
        add(0x0a0a, &[]);
        let name = b"example.org";
        let mut sni = vec![0, (name.len() + 3) as u8, 0, 0, name.len() as u8];
        sni.extend_from_slice(name);
        add(0, &sni);
        add(10, &[0, 6, 0x0a, 0x0a, 0x00, 0x1d, 0x00, 0x17]);
        add(11, &[1, 0]);
        add(13, &[0, 4, 0x04, 0x03, 0x08, 0x04]);
        add(
            16,
            &[0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'],
        );
        add(43, &[4, 0x03, 0x04, 0x03, 0x03]);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 6, 0x0a, 0x0a, 0x13, 0x01, 0xc0, 0x2b]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        // handshake header is type + 3-byte length
        let mut message = vec![1, 0, (body.len() >> 8) as u8, (body.len() & 0xff) as u8];
        message.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    #[test]
    fn a_clienthello_is_read_and_fingerprinted() {
        let hello = parse_stream(&sample()).unwrap();
        assert_eq!(hello.ciphers, [0x0a0a, 0x1301, 0xc02b]);
        assert_eq!(hello.server_name.as_deref(), Some("example.org"));
        assert_eq!(hello.alpn, ["http/1.1"]);
        assert_eq!(hello.groups, [0x0a0a, 0x001d, 0x0017]);
        assert_eq!(hello.signature_algorithms, [0x0403, 0x0804]);
        assert_eq!(hello.supported_versions, [0x0304, 0x0303]);
        assert!(hello.has_grease());
        // 2 ciphers and 7 extensions without GREASE counted: GREASE is left out of the counts.
        assert_eq!(
            hello.ja4_raw(),
            "t13d0206h1_1301,c02b_000a,000b,000d,002b_0403,0804"
        );
        assert_eq!(hello.ja3(), "771,4865-49195,0-10-11-13-16-43,29-23,0");
        assert!(hello.describe().contains("GREASE  yes"));
    }

    #[test]
    fn garbage_and_cut_records_are_errors() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0x17, 3, 3, 0, 0]).is_err());
        let sample = sample();
        assert!(parse_stream(&sample[..sample.len() - 1]).is_err());
        assert!(parse_stream(&sample[..3]).is_err());
    }
}
