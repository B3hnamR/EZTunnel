//! A TLS client whose ClientHello is the one Chrome sends, built on BoringSSL (the library Chrome
//! itself uses). Used when a path has `tls_profile: "chrome"`.
//!
//! What is copied from Chrome 152, measured on 2026-10-10 with a WebSocket and a page load against a
//! fingerprint service: the 15 cipher suites in Chrome's order, the groups `X25519MLKEM768`,
//! `X25519`, `P-256`, `P-384`, the signature algorithms (including the three ML-DSA ones Chrome
//! lists first), GREASE values, a random extension order on every connection, ECH GREASE,
//! certificate compression (brotli), OCSP and SCT requests, the session-ticket extension and ALPN
//! `http/1.1` (what Chrome sends for a WebSocket; every carrier here speaks HTTP/1.1).
//!
//! Only the dialing side uses this. The listening side stays rustls and serves an ECDSA certificate
//! to a client that cannot verify Ed25519 (see `tunnel_key.rs`).
use crate::{carrier::BoxIo, config::ClientPath};
use anyhow::{Context, Result, anyhow, bail, ensure};
use boring::{
    ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, SslAlert, SslConnector, SslMethod,
        SslSignatureAlgorithm, SslVerifyError, SslVerifyMode, SslVersion,
    },
    x509::{X509, store::X509StoreBuilder},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// Chrome's TLS 1.2 cipher suites in its order (the TLS 1.3 suites are added by BoringSSL itself).
const CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:\
AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

const GROUPS: &str = "X25519MLKEM768:X25519:P-256:P-384";

/// The signature algorithms Chrome 152 offers, in its order: three ML-DSA (draft codepoints
/// 0x0904-0x0906), then ECDSA and RSA.
const SIGNATURE_ALGORITHMS: [u16; 11] = [
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// ALPN wire form of `http/1.1`.
const ALPN_HTTP1: &[u8] = b"\x08http/1.1";

/// A server may send its certificate compressed with brotli because the hello offered it.
struct Brotli;

impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        // RFC7932 window bits are at most24. The locked generic decoder also
        // accepts a nonstandard large-window escape by default, which TLS
        // certificate compression must reject BEFORE history allocation.
        if input.is_empty() || input[0]&0x7f==0x11 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"nonstandard or missing Brotli certificate window"));
        }
        let mut input = input;
        brotli_decompressor::BrotliDecompress(&mut input, output)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn nonstandard_large_window_certificate_is_refused_before_any_output(){
        let decoder=Brotli;let mut out=Vec::new();
        for extension in [0x11,0x91]{assert!(decoder.decompress(&[extension,30,0,0],&mut out).is_err());assert!(out.is_empty());}
    }
}

/// How the server's certificate is checked.
enum Trust {
    /// `tls_auto`: the certificate must carry the public key derived from the tunnel key.
    Pinned(Vec<u8>),
    /// A file of trusted certificates, and the name must match.
    File(std::path::PathBuf),
    /// The system's trusted roots, and the name must match.
    System,
}

fn trust_of(path: &ClientPath) -> Result<Trust> {
    if path.tls_auto {
        let auto = path
            .auto_tls
            .as_ref()
            .context("tls_auto needs the tunnel key")?;
        return Ok(Trust::Pinned(auto.ecdsa_public_key().to_vec()));
    }
    Ok(match &path.ca_file {
        Some(file) => Trust::File(file.clone()),
        None => Trust::System,
    })
}

fn signature_algorithms() -> &'static [SslSignatureAlgorithm] {
    static ALGORITHMS:std::sync::OnceLock<Vec<SslSignatureAlgorithm>>=std::sync::OnceLock::new();
    // Use the pinned dependency's public typed constructor rather than making
    // application layout assumptions at an unsafe slice boundary.
    ALGORITHMS.get_or_init(||SIGNATURE_ALGORITHMS.iter().copied().map(SslSignatureAlgorithm::from).collect())
}

fn connector(path: &ClientPath) -> Result<(SslConnector, Trust)> {
    let trust = trust_of(path)?;
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    // Everything below is what makes the hello look like Chrome's.
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();
    // Keep Chrome's advertised versions/ciphers. Require TLS 1.3 after negotiation,
    // before handing any application bytes to the connection.
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_cipher_list(CIPHERS)?;
    builder.set_curves_list(GROUPS)?;
    builder.set_verify_algorithm_prefs(signature_algorithms())?;
    builder.add_certificate_compression_algorithm(Brotli)?;
    builder.set_alpn_protos(ALPN_HTTP1)?;
    match &trust {
        Trust::Pinned(public_key) => {
            let public_key = public_key.clone();
            builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                let presented = ssl
                    .peer_certificate()
                    .and_then(|certificate| certificate.public_key().ok())
                    .and_then(|key| key.public_key_to_der().ok());
                match presented {
                    Some(presented) if presented == public_key => Ok(()),
                    _ => Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE)),
                }
            });
        }
        Trust::File(file) => {
            // `SslConnector::builder` already loaded the system's trusted roots. With a CA file the
            // classic client trusts only that file, so this one replaces the store instead of adding
            // to it.
            let pem = std::fs::read(file)
                .with_context(|| format!("read the CA file {}", file.display()))?;
            let certificates = X509::stack_from_pem(&pem)
                .with_context(|| format!("the CA file {} is not valid PEM", file.display()))?;
            if certificates.is_empty() {
                bail!("the CA file {} holds no certificate", file.display());
            }
            let mut store = X509StoreBuilder::new()?;
            for certificate in certificates {
                store.add_cert(certificate)?;
            }
            builder.set_cert_store(store.build());
        }
        Trust::System => builder
            .set_default_verify_paths()
            .context("load the system's trusted certificates")?,
    }
    Ok((builder.build(), trust))
}

/// Checks that the settings of a path can build a Chrome-like TLS client (files exist, the key
/// is there), without connecting.
pub fn validate(path: &ClientPath) -> Result<()> {
    connector(path).map(|_| ())
}

/// Runs the TLS handshake over `stream` with the Chrome-like hello and returns the encrypted
/// stream. `host` is the name to send as SNI (an IP address sends none, like Chrome).
pub async fn connect<S>(path: &ClientPath, host: &str, stream: S) -> Result<BoxIo>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (connector, trust) = connector(path)?;
    let mut configuration = connector.configure()?;
    configuration.set_enable_ech_grease(true);
    if matches!(trust, Trust::Pinned(_)) {
        // The pinned key is the identity; the name in the certificate means nothing.
        configuration.set_verify_hostname(false);
    }
    match tokio_boring::connect(configuration, host, stream).await {
        Ok(secure) => {
            ensure!(secure.ssl().version2() == Some(SslVersion::TLS1_3), "TLS 1.3 is required");
            Ok(Box::new(secure))
        }
        Err(error) => bail!(anyhow!("TLS peer verification failed: {error}")),
    }
}
