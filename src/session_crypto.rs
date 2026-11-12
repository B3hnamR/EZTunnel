//! Session domains and key separation.
use anyhow::{Result, ensure};
use hkdf::Hkdf;
use sha2::Sha256;
use snow::{HandshakeState, StatelessTransportState, TransportState};
use zeroize::Zeroizing;

pub const STREAM_DOMAIN: &[u8] = b"eztunnel/open-source/stream/epochs/v1";
pub const RAW_DOMAIN: &[u8] = b"eztunnel/open-source/raw/epochs/v1";
pub const CHECKER_DOMAIN: &[u8] = b"eztunnel/open-source/checker/v1";
pub const REKEY_SECONDS: u64 = 300;
pub const REKEY_RECORDS: u64 = 1 << 20;
pub const RECEIVE_SECONDS: u64 = 360;

pub fn prologue(domain: &[u8], version: u8, parity: bool) -> Result<Vec<u8>> {
    ensure!((1..=3).contains(&version), "unsupported wire version");
    let mut bytes = domain.to_vec();
    bytes.push(version);
    bytes.push(u8::from(parity));
    Ok(bytes)
}

pub fn epoch_due(elapsed: u64, records: u64) -> bool {
    elapsed >= REKEY_SECONDS || records >= REKEY_RECORDS
}

pub struct Traffic<T> {
    pub state: T,
    pub codecs: Option<crate::wire::Codecs>,
}

fn keys(handshake: &mut HandshakeState, version: u8) -> Result<(Zeroizing<[u8; 64]>, Option<crate::wire::Codecs>)> {
    ensure!(handshake.is_handshake_finished(), "incomplete session handshake");
    ensure!((1..=3).contains(&version), "unsupported wire version");
    let split = Zeroizing::new(handshake.dangerously_get_raw_split());
    let mut secret = Zeroizing::new([0u8; 64]);
    secret[..32].copy_from_slice(&split.0);
    secret[32..].copy_from_slice(&split.1);
    let mut salt = blake3::Hasher::new();
    salt.update(b"eztunnel open-source session keys v1\0");
    salt.update(handshake.get_handshake_hash());
    salt.update(&[version]);
    let salt = salt.finalize();
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), secret.as_ref());
    let mut traffic = Zeroizing::new([0; 64]);
    hk.expand(b"traffic initiator v1", &mut traffic[..32]).expect("fixed HKDF length");
    hk.expand(b"traffic responder v1", &mut traffic[32..]).expect("fixed HKDF length");
    let codecs = if version == 3 {
        let mut a = Zeroizing::new([0; 32]);
        let mut b = Zeroizing::new([0; 32]);
        hk.expand(b"wire initiator v1", &mut *a).expect("fixed HKDF length");
        hk.expand(b"wire responder v1", &mut *b).expect("fixed HKDF length");
        if !handshake.is_initiator() {
            std::mem::swap(&mut a, &mut b);
        }
        Some(crate::wire::Codecs { tx: crate::wire::Rotation::new(*a), rx: crate::wire::Rotation::new(*b) })
    } else {
        None
    };
    Ok((traffic, codecs))
}

pub fn transport(mut handshake: HandshakeState, version: u8) -> Result<Traffic<TransportState>> {
    let (keys, codecs) = keys(&mut handshake, version)?;
    let mut state = handshake.into_transport_mode()?;
    state.rekey_manually(Some(keys[..32].try_into().expect("32-byte key")), Some(keys[32..].try_into().expect("32-byte key")));
    Ok(Traffic { state, codecs })
}

pub fn stateless(mut handshake: HandshakeState, version: u8) -> Result<Traffic<StatelessTransportState>> {
    let (keys, codecs) = keys(&mut handshake, version)?;
    let mut state = handshake.into_stateless_transport_mode()?;
    state.rekey_manually(Some(keys[..32].try_into().expect("32-byte key")), Some(keys[32..].try_into().expect("32-byte key")));
    Ok(Traffic { state, codecs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_versions_parity_and_epoch_boundaries_are_explicit() {
        assert_ne!(prologue(STREAM_DOMAIN, 1, false).unwrap(), prologue(RAW_DOMAIN, 1, false).unwrap());
        assert_ne!(prologue(RAW_DOMAIN, 1, false).unwrap(), prologue(RAW_DOMAIN, 1, true).unwrap());
        assert_ne!(prologue(STREAM_DOMAIN, 1, false).unwrap(), prologue(STREAM_DOMAIN, 2, false).unwrap());
        assert!(prologue(STREAM_DOMAIN, 0, false).is_err());
        assert!(prologue(STREAM_DOMAIN, 4, false).is_err());
        assert!(!epoch_due(299, REKEY_RECORDS - 1));
        assert!(epoch_due(300, 0));
        assert!(epoch_due(0, REKEY_RECORDS));
    }

    #[test]
    fn older_protocol_domains_are_rejected_before_application_traffic() -> Result<()> {
        let server = snow::Builder::new(crate::transport::NOISE_PATTERN.parse()?).generate_keypair()?;
        let client = snow::Builder::new(crate::transport::NOISE_PATTERN.parse()?).generate_keypair()?;
        let older: &[&[u8]] = &[
            b"eztunnel/reverse-tunnel/v1",
            b"eztunnel/raw-tun/v1",
        ];
        for old in older {
            for domain in [STREAM_DOMAIN, RAW_DOMAIN] {
                for version in 1..=3 {
                    for parity in [false, true] {
                        let new = prologue(domain, version, parity)?;
                        for (initiator_domain, responder_domain) in [(*old, new.as_slice()), (new.as_slice(), *old)] {
                            let mut a = snow::Builder::new(crate::transport::NOISE_PATTERN.parse()?)
                                .local_private_key(&client.private)?.remote_public_key(&server.public)?
                                .prologue(initiator_domain)?.build_initiator()?;
                            let mut b = snow::Builder::new(crate::transport::NOISE_PATTERN.parse()?)
                                .local_private_key(&server.private)?.prologue(responder_domain)?.build_responder()?;
                            let mut wire = [0; 512];
                            let mut plain = [0; 512];
                            let n = a.write_message(&[], &mut wire)?;
                            assert!(b.read_message(&wire[..n], &mut plain).is_err());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn authenticated_split_derives_matching_directional_keys_for_all_versions() -> Result<()> {
        for version in 1..=3 {
            let pattern = crate::transport::NOISE_PATTERN.parse()?;
            let server = snow::Builder::new(pattern).generate_keypair()?;
            let client = snow::Builder::new(crate::transport::NOISE_PATTERN.parse()?).generate_keypair()?;
            let prologue = prologue(STREAM_DOMAIN, version, false)?;
            let mut a = snow::Builder::new(crate::transport::NOISE_PATTERN.parse()?).local_private_key(&client.private)?.remote_public_key(&server.public)?.prologue(&prologue)?.build_initiator()?;
            let mut b = snow::Builder::new(crate::transport::NOISE_PATTERN.parse()?).local_private_key(&server.private)?.prologue(&prologue)?.build_responder()?;
            let mut message = [0; 512];
            let mut plain = [0; 512];
            let n = a.write_message(&[], &mut message)?;
            assert_eq!(b.read_message(&message[..n], &mut plain)?, 0);
            let n = b.write_message(&[], &mut message)?;
            assert_eq!(a.read_message(&message[..n], &mut plain)?, 0);
            let (mut a, mut b) = (transport(a, version)?, transport(b, version)?);
            let mut data = b"open source".to_vec();
            if let Some(codecs) = &a.codecs { codecs.tx.encode(0, &mut data); }
            let n = a.state.write_message(&data, &mut message)?;
            let n = b.state.read_message(&message[..n], &mut plain)?;
            if let Some(codecs) = &b.codecs { codecs.rx.decode(0, &mut plain[..n]); }
            assert_eq!(&plain[..n], b"open source");
            let n = b.state.write_message(b"reply", &mut message)?;
            let n = a.state.read_message(&message[..n], &mut plain)?;
            assert_eq!(&plain[..n], b"reply");
        }
        Ok(())
    }
}
