//! The tunnel key: one short secret that both servers hold.
//!
//! Everything a pair of peers needs to trust each other is derived from it: the Noise identity
//! of each role, the XHTTP access token and a TLS certificate that the dialing side pins. The
//! operator therefore copies a single value between the machines instead of two public keys,
//! a certificate and a token.
//!
//! A key is 24 random symbols (120 bits) plus one check symbol, written in five groups of five,
//! for example `k7m2q-9xa4b-...`. The check symbol catches almost every copying mistake before
//! a connection is attempted. Anyone who has the key can act as either side, so it must be
//! kept as secret as a private key.
use crate::config::Mode;
use anyhow::{Context, Result, ensure};
use blake2::{Blake2s256, Digest};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
const DATA_SYMBOLS: usize = 24;
const GROUP: usize = 5;

/// A validated tunnel key in canonical form (24 lowercase data symbols, no separators).
#[derive(Clone, PartialEq, Eq)]
pub struct TunnelKey {
    data: String,
}

impl Drop for TunnelKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for TunnelKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl std::fmt::Debug for TunnelKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TunnelKey(..)")
    }
}

fn check_symbol(data: &str) -> u8 {
    let digest = Blake2s256::new()
        .chain_update(b"eztunnel tunnel key check\0")
        .chain_update(data.as_bytes())
        .finalize();
    ALPHABET[(digest[0] & 31) as usize]
}

impl TunnelKey {
    /// A fresh key from the operating system's random generator.
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; DATA_SYMBOLS]);
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut *bytes)
            .map_err(|_| anyhow::anyhow!("operating-system random generator failed"))?;
        let data = bytes
            .iter()
            .map(|b| ALPHABET[(b & 31) as usize] as char)
            .collect();
        Ok(Self { data })
    }

    /// Reads a key as people type or paste it: case does not matter, dashes and spaces are
    /// ignored, and the look-alike letters o, i and l are read as 0, 1 and 1.
    pub fn parse(text: &str) -> Result<Self> {
        let mut symbols = Zeroizing::new(String::with_capacity(DATA_SYMBOLS + 1));
        for c in text.chars() {
            let c = match c.to_ascii_lowercase() {
                '-' | ' ' | '\t' => continue,
                'o' => '0',
                'i' | 'l' => '1',
                c => c,
            };
            ensure!(
                c.is_ascii() && ALPHABET.contains(&(c as u8)),
                "a tunnel key contains only digits and the letters a-z (not u); found '{c}'"
            );
            symbols.push(c);
        }
        ensure!(
            symbols.len() == DATA_SYMBOLS + 1,
            "a tunnel key has {} letters and digits in five groups of five; dashes and spaces are ignored (you entered {} letters and digits)",
            DATA_SYMBOLS + 1,
            symbols.len()
        );
        let data = symbols[..DATA_SYMBOLS].to_string();
        ensure!(
            symbols.as_bytes()[DATA_SYMBOLS] == check_symbol(&data),
            "this tunnel key has a typo; copy it again from the other server"
        );
        Ok(Self { data })
    }

    /// The key as it should be shown and stored: five groups of five symbols.
    pub fn display(&self) -> String {
        let mut all = Zeroizing::new(self.data.clone());
        all.push(check_symbol(&self.data) as char);
        all.as_bytes()
            .chunks(GROUP)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("-")
    }

    fn derive(&self, purpose: &str) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(
            Blake2s256::new()
                .chain_update(b"eztunnel tunnel key v1\0")
                .chain_update(purpose.as_bytes())
                .chain_update(b"\0")
                .chain_update(self.data.as_bytes())
                .finalize()
                .into(),
        )
    }

    /// The Noise private key of one role.
    pub fn private_key(&self, mode: Mode) -> Zeroizing<[u8; 32]> {
        self.derive(match mode {
            Mode::Server => "noise server identity",
            Mode::Client => "noise client identity",
        })
    }

    /// The Noise public key of one role.
    pub fn public_key(&self, mode: Mode) -> Result<[u8; 32]> {
        public_of(&self.private_key(mode))
    }

    /// The XHTTP access token both ends use when none is configured explicitly.
    pub fn xhttp_token(&self) -> String {
        hex::encode(&*self.derive("xhttp access token"))
    }

    pub(crate) fn parallax_key(&self) -> Zeroizing<[u8; 32]> {
        self.derive("parallax carrier v1 authentication")
    }

    pub(crate) fn packet_lane_key(&self) -> Zeroizing<[u8; 32]> {
        self.derive("packet fallback lane v1 authentication")
    }

    pub(crate) fn port_hop_key(&self) -> Zeroizing<[u8; 32]> {
        self.derive("authenticated raw port hopping v1")
    }
    pub(crate) fn mirage_key(&self)->Zeroizing<[u8;32]>{self.derive("Mirage v2 packet admission")}

    /// The certificate and key that a TLS listener presents and a TLS dialer pins.
    pub fn tls(&self, name: Option<&str>) -> Result<Arc<AutoTls>> {
        // Wire version 2 passes a host-like name derived from the key and a shorter, ordinary
        // validity period; version 1 keeps the fixed name and the long period.
        let host = name.unwrap_or(AUTO_TLS_NAME);
        let (until_year, from_year) = if name.is_some() {
            (2030, 2025)
        } else {
            (2125, 2025)
        };
        // An Ed25519 key in PKCS#8 v1 form is a fixed prefix followed by the 32-byte seed.
        let mut pkcs8 = Zeroizing::new(vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        pkcs8.extend_from_slice(&*self.derive("tls certificate key"));
        let der = PrivatePkcs8KeyDer::from(pkcs8.to_vec());
        let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_ED25519)
            .context("derive TLS key")?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
            .context("TLS certificate name")?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.serial_number = Some(rcgen::SerialNumber::from_slice(
            &self.derive("tls certificate serial")[..16],
        ));
        params.not_before = rcgen::date_time_ymd(from_year, 1, 1);
        params.not_after = rcgen::date_time_ymd(until_year, 1, 1);
        // Ed25519 signatures are deterministic, so both ends build the identical certificate.
        let certificate = params
            .self_signed(&key_pair)
            .context("build TLS certificate")?;
        let mut tls = AutoTls {
            certificate: certificate.der().clone(),
            key: der.secret_pkcs8_der().to_vec(),
            #[cfg(feature = "browser-tls")]
            ecdsa: self.ecdsa_identity(host, from_year, until_year)?,
            client: None,
            server: None,
        };
        tls.client = Some(tls.build_client_config()?);
        tls.server = Some(tls.build_server_config()?);
        Ok(Arc::new(tls))
    }

    /// The ECDSA P-256 certificate that a Chrome-like TLS client can accept (it does not offer
    /// Ed25519). ECDSA signatures are randomised, so the two ends do not build the same certificate;
    /// they agree on the public key instead, and the dialing side pins that.
    #[cfg(feature = "browser-tls")]
    fn ecdsa_identity(&self, host: &str, from_year: i32, until_year: i32) -> Result<EcdsaIdentity> {
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
        // A random 32-byte value is a valid P-256 scalar with overwhelming probability; the counter
        // makes the derivation total.
        let secret = (0u8..=255)
            .find_map(|counter| {
                p256::SecretKey::from_slice(&*self.derive(&format!("tls ecdsa key {counter}"))).ok()
            })
            .context("derive the ECDSA key")?;
        let pkcs8 = secret
            .to_pkcs8_der()
            .map_err(|error| anyhow::anyhow!("encode the ECDSA key: {error}"))?;
        let spki = secret
            .public_key()
            .to_public_key_der()
            .map_err(|error| anyhow::anyhow!("encode the ECDSA public key: {error}"))?
            .as_bytes()
            .to_vec();
        let der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
        let key_pair =
            rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_ECDSA_P256_SHA256)
                .context("load the ECDSA key")?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
            .context("TLS certificate name")?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.serial_number = Some(rcgen::SerialNumber::from_slice(
            &self.derive("tls certificate serial")[..16],
        ));
        params.not_before = rcgen::date_time_ymd(from_year, 1, 1);
        params.not_after = rcgen::date_time_ymd(until_year, 1, 1);
        let certificate = params
            .self_signed(&key_pair)
            .context("build the ECDSA TLS certificate")?;
        Ok(EcdsaIdentity {
            certificate: certificate.der().clone(),
            key: der.secret_pkcs8_der().to_vec(),
            spki,
        })
    }
}

/// The ECDSA P-256 half of the derived TLS identity (see `TunnelKey::ecdsa_identity`).
#[cfg(feature = "browser-tls")]
struct EcdsaIdentity {
    certificate: CertificateDer<'static>,
    key: Vec<u8>,
    /// The DER of the public key; both ends derive the same bytes.
    spki: Vec<u8>,
}

/// Name inside the derived certificate. The dialer pins the whole certificate, so the name it
/// sends in TLS (SNI) does not have to match this.
const AUTO_TLS_NAME: &str = "eztunnel.invalid";

/// A TLS certificate and key derived from a tunnel key.
pub struct AutoTls {
    pub certificate: CertificateDer<'static>,
    key: Vec<u8>,
    #[cfg(feature = "browser-tls")]
    ecdsa: EcdsaIdentity,
    client: Option<Arc<rustls::ClientConfig>>,
    server: Option<Arc<rustls::ServerConfig>>,
}

impl Drop for AutoTls {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(feature = "browser-tls")]
        self.ecdsa.key.zeroize();
    }
}

impl std::fmt::Debug for AutoTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AutoTls(..)")
    }
}

impl AutoTls {
    #[cfg(not(feature = "browser-tls"))]
    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()))
    }

    /// TLS client settings that accept exactly this certificate.
    pub fn client_config(&self) -> Result<Arc<rustls::ClientConfig>> {
        self.client.clone().context("TLS client settings missing")
    }

    /// TLS server settings that present this certificate.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        self.server.clone().context("TLS server settings missing")
    }

    fn build_client_config(&self) -> Result<Arc<rustls::ClientConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinnedCertificate {
            expected: self.certificate.clone(),
            provider: provider.clone(),
        });
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        // Every browser says which protocol it wants; a client with no ALPN at all stands out.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// The DER of the public key that a Chrome-like dialing side pins (see `ecdsa_identity`).
    #[cfg(feature = "browser-tls")]
    pub fn ecdsa_public_key(&self) -> &[u8] {
        &self.ecdsa.spki
    }

    fn build_server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth();
        #[cfg(feature = "browser-tls")]
        {
            // Two certificates, chosen by what the client says it can verify: Ed25519 for this
            // program's own TLS client, ECDSA for a client that looks like Chrome.
            let certified = |certificate: &CertificateDer<'static>, key: &[u8]| -> Result<_> {
                let key = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
                    PrivatePkcs8KeyDer::from(key.to_vec()),
                ))?;
                Ok(Arc::new(rustls::sign::CertifiedKey::new(
                    vec![certificate.clone()],
                    key,
                )))
            };
            let resolver = BySignatureSchemes {
                ed25519: certified(&self.certificate, &self.key)?,
                ecdsa: certified(&self.ecdsa.certificate, &self.ecdsa.key)?,
            };
            Ok(Arc::new(builder.with_cert_resolver(Arc::new(resolver))))
        }
        #[cfg(not(feature = "browser-tls"))]
        {
            Ok(Arc::new(builder.with_single_cert(
                vec![self.certificate.clone()],
                self.private_key(),
            )?))
        }
    }
}

/// Picks the certificate by the signature schemes the client offers: a client that can verify
/// Ed25519 gets that certificate, one that cannot (Chrome) gets the ECDSA one.
#[cfg(feature = "browser-tls")]
struct BySignatureSchemes {
    ed25519: Arc<rustls::sign::CertifiedKey>,
    ecdsa: Arc<rustls::sign::CertifiedKey>,
}

#[cfg(feature = "browser-tls")]
impl std::fmt::Debug for BySignatureSchemes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BySignatureSchemes(..)")
    }
}

#[cfg(feature = "browser-tls")]
impl rustls::server::ResolvesServerCert for BySignatureSchemes {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let schemes = hello.signature_schemes();
        if !schemes.contains(&rustls::SignatureScheme::ED25519)
            && schemes.contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256)
        {
            Some(self.ecdsa.clone())
        } else {
            Some(self.ed25519.clone())
        }
    }
}

/// Accepts one exact certificate and checks that the peer holds its key. This is stricter than
/// checking a certificate authority and a name.
#[derive(Debug)]
struct PinnedCertificate {
    expected: CertificateDer<'static>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if intermediates.is_empty() && end_entity.as_ref() == self.expected.as_ref() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The X25519 public key that belongs to a private key.
pub fn public_of(private: &[u8; 32]) -> Result<[u8; 32]> {
    use snow::resolvers::CryptoResolver;
    let mut dh = snow::resolvers::DefaultResolver
        .resolve_dh(&snow::params::DHChoice::Curve25519)
        .context("X25519 is not available")?;
    dh.set(private);
    dh.pubkey()
        .try_into()
        .context("unexpected X25519 public key length")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_kdf_golden_vectors_and_explicit_secret_erasure() {
        let mut key = TunnelKey {
            data: "0".repeat(24),
        };
        for (label, expected) in [
            (
                "noise server identity",
                "7d9b62c8657c1b04b4bd4eaa7bbbf6f62e9fcf12a6d16b5eff26d65df24c4d4f",
            ),
            (
                "noise client identity",
                "122d410fe570fc5f2662223d602c68eff3395c16868e9a08278da76ba7a9baf1",
            ),
            (
                "xhttp access token",
                "b505a6d9980ea877fb11a8867609e48a9eb453f8ee5924a0b28d6afd958285fb",
            ),
            (
                "tls certificate key",
                "b7fbc0bec38bc4acf183023ea65908050160df6792596edf8d92693be704b0c6",
            ),
            (
                "tls certificate serial",
                "800054aa751ef572e07c870e6924ab775e7c1f09404a32572ae8c2e1679133e1",
            ),
        ] {
            assert_eq!(hex::encode(&*key.derive(label)), expected);
        }
        key.zeroize();
        assert!(key.data.is_empty());
    }

    #[test]
    fn generated_keys_round_trip_and_look_right() -> Result<()> {
        let key = TunnelKey::generate()?;
        let shown = key.display();
        assert_eq!(shown.len(), 29, "{shown}");
        assert_eq!(shown.matches('-').count(), 4);
        assert_eq!(TunnelKey::parse(&shown)?, key);
        assert_eq!(TunnelKey::parse(&shown.to_uppercase())?, key);
        assert_eq!(TunnelKey::parse(&shown.replace('-', " "))?, key);
        assert_ne!(TunnelKey::generate()?, key);
        Ok(())
    }

    #[test]
    fn typos_and_wrong_lengths_are_reported() -> Result<()> {
        let shown = TunnelKey::generate()?.display();
        assert!(TunnelKey::parse(&shown[..shown.len() - 1]).is_err());
        assert!(TunnelKey::parse(&format!("{shown}0")).is_err());
        assert!(TunnelKey::parse(&shown.replacen('-', "u", 1)).is_err());
        let mut typos = 0;
        for index in [0, 7, 13, 20, 28] {
            let mut bytes = shown.clone().into_bytes();
            if bytes[index] == b'-' {
                continue;
            }
            bytes[index] = if bytes[index] == b'7' { b'8' } else { b'7' };
            if TunnelKey::parse(std::str::from_utf8(&bytes)?).is_err() {
                typos += 1;
            }
        }
        assert!(typos >= 3, "the check symbol caught only {typos} typos");
        Ok(())
    }

    #[test]
    fn look_alike_letters_are_accepted() -> Result<()> {
        let key = TunnelKey::generate()?;
        let shown = key.display();
        let swapped = shown.replace('0', "o").replace('1', "l");
        assert_eq!(TunnelKey::parse(&swapped)?, key);
        Ok(())
    }

    #[test]
    fn a_key_that_starts_with_ezt_still_parses() {
        let key = TunnelKey {
            data: format!("ezt{}", "0".repeat(21)),
        };
        let shown = key.display().replace('-', "");
        assert_eq!(
            TunnelKey::parse(&format!("ezt-{}", &shown[3..])).unwrap(),
            key
        );
    }

    #[test]
    fn roles_get_different_matching_identities() -> Result<()> {
        let key = TunnelKey::parse(&TunnelKey::generate()?.display())?;
        assert_ne!(key.private_key(Mode::Server), key.private_key(Mode::Client));
        assert_ne!(key.public_key(Mode::Server)?, key.public_key(Mode::Client)?);
        let other = TunnelKey::generate()?;
        assert_ne!(
            key.public_key(Mode::Server)?,
            other.public_key(Mode::Server)?
        );
        // A Noise handshake between the derived identities succeeds.
        let params: snow::params::NoiseParams = crate::transport::NOISE_PATTERN.parse()?;
        let mut client = snow::Builder::new(params.clone())
            .local_private_key(&*key.private_key(Mode::Client))?
            .remote_public_key(&key.public_key(Mode::Server)?)?
            .build_initiator()?;
        let mut server = snow::Builder::new(params)
            .local_private_key(&*key.private_key(Mode::Server))?
            .build_responder()?;
        let (mut a, mut b) = ([0u8; 256], [0u8; 256]);
        let n = client.write_message(&[], &mut a)?;
        server.read_message(&a[..n], &mut b)?;
        assert_eq!(
            server.get_remote_static(),
            Some(&key.public_key(Mode::Client)?[..])
        );
        Ok(())
    }

    #[test]
    fn both_ends_derive_the_same_certificate() -> Result<()> {
        let key = TunnelKey::generate()?;
        let copy = TunnelKey::parse(&key.display())?;
        assert_eq!(
            key.tls(None)?.certificate.as_ref(),
            copy.tls(None)?.certificate.as_ref()
        );
        assert_ne!(
            key.tls(None)?.certificate.as_ref(),
            TunnelKey::generate()?.tls(None)?.certificate.as_ref()
        );
        key.tls(None)?.server_config()?;
        key.tls(None)?.client_config()?;
        assert_eq!(key.xhttp_token().len(), 64);
        Ok(())
    }

    #[cfg(feature = "browser-tls")]
    #[test]
    fn both_ends_derive_the_same_ecdsa_public_key() -> Result<()> {
        let key = TunnelKey::generate()?;
        let copy = TunnelKey::parse(&key.display())?;
        let (a, b) = (key.tls(None)?, copy.tls(None)?);
        assert_eq!(a.ecdsa_public_key(), b.ecdsa_public_key());
        assert!(!a.ecdsa_public_key().is_empty());
        // The certificates themselves differ (randomised signature) but carry the pinned key.
        assert_ne!(a.ecdsa.certificate.as_ref(), b.ecdsa.certificate.as_ref());
        assert_ne!(
            a.ecdsa_public_key(),
            TunnelKey::generate()?.tls(None)?.ecdsa_public_key()
        );
        // The name a wire-version-2 tunnel passes in works for the ECDSA certificate too.
        key.tls(Some("0123abcd.cdn-edge.net"))?.server_config()?;
        Ok(())
    }
}
