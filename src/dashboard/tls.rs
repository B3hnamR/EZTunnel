//! The dashboard's certificate. Phase 1 uses a self-signed certificate kept in the state
//! directory; its key fingerprint lets a join command pin it.
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};

const CERT_FILE: &str = "cert.der";
const KEY_FILE: &str = "key.der";

/// Loads the certificate, creating it on first use, and returns the TLS settings with the
/// SHA-256 of the public key (base64), the value `curl --pinnedpubkey` expects.
pub fn load_or_create(state_dir: &Path, address: &str) -> Result<(Arc<rustls::ServerConfig>, String)> {
    let cert_path = state_dir.join(CERT_FILE);
    let key_path = state_dir.join(KEY_FILE);
    if !cert_path.exists() || !key_path.exists() {
        let mut names = vec!["localhost".to_string()];
        if address.parse::<std::net::IpAddr>().is_ok() {
            names.push(address.to_string());
        }
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(names).context("create the certificate")?;
        super::write_private(&key_path, &key_pair.serialize_der())?;
        super::write_private(&cert_path, cert.der())?;
    }
    let cert = CertificateDer::from(std::fs::read(&cert_path).context("read the certificate")?);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        std::fs::read(&key_path).context("read the certificate key")?,
    ));
    let pin = public_key_pin(&cert)?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .context("use the certificate")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((Arc::new(config), pin))
}

/// SHA-256 of the certificate's SubjectPublicKeyInfo, base64.
fn public_key_pin(cert: &CertificateDer) -> Result<String> {
    use base64::Engine;
    let spki = spki_of(cert.as_ref()).context("read the certificate's public key")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki)))
}

/// Finds the SubjectPublicKeyInfo inside a DER certificate: the seventh element of the
/// TBSCertificate when the version field is present (it always is for rcgen certificates).
fn spki_of(der: &[u8]) -> Option<&[u8]> {
    let certificate = inner(der)?;
    let mut rest = inner(certificate)?;
    let mut index = 0;
    while !rest.is_empty() {
        let (length, whole) = element(rest)?;
        // [0] version, serial, signature, issuer, validity, subject, subjectPublicKeyInfo
        if index == 6 {
            return Some(whole);
        }
        rest = &rest[length..];
        index += 1;
    }
    None
}

/// Returns (total length, whole element) of the first DER element in `bytes`.
fn element(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let (header, length) = header(bytes)?;
    let total = header.checked_add(length)?;
    Some((total, bytes.get(..total)?))
}

/// The contents of the first DER element.
fn inner(bytes: &[u8]) -> Option<&[u8]> {
    let (header, length) = header(bytes)?;
    bytes.get(header..header.checked_add(length)?)
}

fn header(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.get(1)?;
    if first < 0x80 {
        return Some((2, first as usize));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 {
        return None;
    }
    let mut length = 0usize;
    for byte in bytes.get(2..2 + count)? {
        length = (length << 8) | *byte as usize;
    }
    Some((2 + count, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pin_is_the_hash_of_the_certificate_public_key() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = CertificateDer::from(cert.der().to_vec());
        let spki = spki_of(der.as_ref()).unwrap();
        assert_eq!(spki, key_pair.public_key_der().as_slice());
        assert_eq!(public_key_pin(&der).unwrap().len(), 44);
    }

    #[test]
    fn the_certificate_is_created_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let (_, first) = load_or_create(dir.path(), "203.0.113.10").unwrap();
        let (_, second) = load_or_create(dir.path(), "203.0.113.10").unwrap();
        assert_eq!(first, second);
    }
}
