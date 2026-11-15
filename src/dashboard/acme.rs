//! A Let's Encrypt certificate for the dashboard's address, so browsers trust it without a
//! warning. An IP address gets a short-lived certificate (about six days, the only kind Let's
//! Encrypt issues for addresses); it is renewed after two thirds of its life and swapped into the
//! running server, so nobody has to restart anything.
//!
//! Validation is HTTP-01: for the minute an order takes, a small server answers on port 80 with
//! the challenge text and nothing else.
use super::tls::{self, Swap};
use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType,
    HttpClient, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, pem::PemObject};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpStream;

const CHAIN_FILE: &str = "acme-chain.pem";
const KEY_FILE: &str = "acme-key.der";
const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
/// How often the renewal task looks at the certificate.
const CHECK_EVERY: Duration = Duration::from_secs(30 * 60);
/// Waits after a failed order: 5 minutes, doubling to at most 6 hours.
const RETRY_FIRST: Duration = Duration::from_secs(5 * 60);
const RETRY_MAX: Duration = Duration::from_secs(6 * 3600);

/// What the dashboard's certificate should be, kept in its settings.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AcmeSettings {
    /// The address the certificate names: an IP address or a domain.
    pub address: String,
    /// Use Let's Encrypt's staging service (certificates browsers do not trust; for testing).
    #[serde(default)]
    pub staging: bool,
}

impl AcmeSettings {
    fn directory(&self) -> &'static str {
        if self.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        }
    }

    fn account_file(&self) -> &'static str {
        if self.staging { "acme-account-staging.json" } else { "acme-account.json" }
    }
}

/// A certificate with its chain and key, as stored and served.
pub struct Issued {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivatePkcs8KeyDer<'static>,
}

impl Issued {
    /// Seconds since 1970: (not before, not after) of the certificate itself.
    pub fn validity(&self) -> Result<(u64, u64)> {
        let leaf = self.chain.first().context("empty certificate chain")?;
        validity_of(leaf.as_ref()).context("read the certificate's validity")
    }

    /// When to order the next certificate: after two thirds of this one's life.
    pub fn renew_at(&self) -> Result<u64> {
        let (from, until) = self.validity()?;
        Ok(renew_time(from, until))
    }
}

pub fn renew_time(not_before: u64, not_after: u64) -> u64 {
    not_before + not_after.saturating_sub(not_before) * 2 / 3
}

pub fn load(state_dir: &Path) -> Option<Issued> {
    let chain = CertificateDer::pem_file_iter(state_dir.join(CHAIN_FILE))
        .ok()?
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let key = PrivatePkcs8KeyDer::from(std::fs::read(state_dir.join(KEY_FILE)).ok()?);
    (!chain.is_empty()).then_some(Issued { chain, key })
}

fn save(state_dir: &Path, pem_chain: &str, key: &[u8]) -> Result<()> {
    super::write_private(&state_dir.join(KEY_FILE), key)?;
    super::write_private(&state_dir.join(CHAIN_FILE), pem_chain.as_bytes())
}

/// Removes a stored Let's Encrypt certificate (going back to the self-signed one).
pub fn forget(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(CHAIN_FILE));
    let _ = std::fs::remove_file(state_dir.join(KEY_FILE));
}

/// HTTPS for the ACME requests over the program's own TLS stack and bundled root certificates.
struct Https {
    tls: tokio_rustls::TlsConnector,
}

impl Https {
    fn new() -> Result<Self> {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
        })
    }
}

impl HttpClient for Https {
    fn request(
        &self,
        request: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let tls = self.tls.clone();
        Box::pin(async move {
            send(tls, request)
                .await
                .map_err(|error| instant_acme::Error::Other(error.into()))
        })
    }
}

async fn send(
    tls: tokio_rustls::TlsConnector,
    mut request: http::Request<BodyWrapper<Bytes>>,
) -> Result<BytesResponse> {
    let uri = request.uri().clone();
    ensure!(uri.scheme_str() == Some("https"), "ACME requests must use HTTPS");
    let host = uri.host().context("ACME URL without a host")?.to_string();
    let port = uri.port_u16().unwrap_or(443);
    let tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host.as_str(), port)))
        .await
        .context("connect to the certificate service: timed out")??;
    let name = ServerName::try_from(host.clone()).context("certificate service name")?;
    let stream = tokio::time::timeout(Duration::from_secs(15), tls.connect(name, tcp))
        .await
        .context("TLS with the certificate service: timed out")??;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    tokio::spawn(connection);
    let authority = uri.authority().context("ACME URL without a host")?.as_str().to_string();
    request.headers_mut().insert(http::header::HOST, authority.parse()?);
    *request.uri_mut() = uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .parse()?;
    let response = tokio::time::timeout(Duration::from_secs(30), sender.send_request(request))
        .await
        .context("the certificate service did not answer")??;
    Ok(BytesResponse::from(response))
}

async fn account(state_dir: &Path, settings: &AcmeSettings) -> Result<Account> {
    let path = state_dir.join(settings.account_file());
    if let Ok(text) = std::fs::read_to_string(&path) {
        let credentials: AccountCredentials =
            serde_json::from_str(&text).context("unreadable ACME account file")?;
        return Account::builder_with_http(Box::new(Https::new()?))
            .from_credentials(credentials)
            .await
            .context("load the Let's Encrypt account");
    }
    let (account, credentials) = Account::builder_with_http(Box::new(Https::new()?))
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            settings.directory().to_string(),
            None,
        )
        .await
        .context("create a Let's Encrypt account")?;
    super::write_private(&path, &serde_json::to_vec_pretty(&credentials)?)?;
    Ok(account)
}

/// The tokens being validated and their answers.
type Answers = Arc<Mutex<HashMap<String, String>>>;

/// Answers HTTP-01 requests on port 80 until dropped. Every other request gets 404.
struct ChallengeServer {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ChallengeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ChallengeServer {
    async fn start(answers: Answers, port: u16, require_ipv6: bool) -> Result<Self> {
        let listeners = super::relay::listeners(port)
            .await
            .with_context(|| {
                format!("listen on port {port}: Let's Encrypt checks the address over port {port}, so it must be free and open")
            })?;
        let mut listeners = listeners;
        let ipv4 = listeners.remove(0);
        let ipv6 = listeners.pop();
        ensure!(!require_ipv6 || ipv6.is_some(), "IPv6 HTTP-01 listening is unavailable; use an IPv4 address or enable IPv6");
        let task = tokio::spawn(async move {
            loop {
                let accepted = if let Some(ipv6) = &ipv6 {
                    tokio::select! {
                        result = ipv4.accept() => result,
                        result = ipv6.accept() => result,
                    }
                } else {
                    ipv4.accept().await
                };
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                let answers = answers.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                        let answer = challenge_answer(&answers, request.uri().path());
                        async move {
                            let response = match answer {
                                Some(text) => hyper::Response::builder()
                                    .header("content-type", "application/octet-stream")
                                    .body(http_body_util::Full::new(Bytes::from(text))),
                                None => hyper::Response::builder()
                                    .status(404)
                                    .body(http_body_util::Full::new(Bytes::new())),
                            };
                            response
                        }
                    });
                    let _ = tokio::time::timeout(
                        Duration::from_secs(20),
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service),
                    )
                    .await;
                });
            }
        });
        Ok(Self { task })
    }
}

/// The answer for a challenge path, or `None` for anything else.
fn challenge_answer(answers: &Answers, path: &str) -> Option<String> {
    let token = path.strip_prefix(CHALLENGE_PREFIX)?;
    answers.lock().unwrap().get(token).cloned()
}

/// Orders a certificate for `settings.address` and stores it. `port` is where the HTTP-01
/// answers are served (80, except in tests).
pub async fn issue(state_dir: &Path, settings: &AcmeSettings, port: u16) -> Result<Issued> {
    let ip = settings.address.parse::<IpAddr>().ok();
    let identifier = match ip {
        Some(ip) => Identifier::Ip(ip),
        None => Identifier::Dns(settings.address.clone()),
    };
    let account = account(state_dir, settings).await?;
    let identifiers = [identifier];
    let mut new_order = NewOrder::new(&identifiers);
    if ip.is_some() {
        // Let's Encrypt issues address certificates only with this profile.
        new_order = new_order.profile("shortlived");
    }
    let mut order = account.new_order(&new_order).await.context("order the certificate")?;

    let answers: Answers = Arc::default();
    let _server = ChallengeServer::start(answers.clone(), port, matches!(ip, Some(IpAddr::V6(_)))).await?;
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization.context("read the authorization")?;
        match authorization.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            status => bail!("authorization is {status:?}"),
        }
        let mut challenge = authorization
            .challenge(ChallengeType::Http01)
            .context("Let's Encrypt offered no HTTP-01 check for this address")?;
        answers
            .lock()
            .unwrap()
            .insert(challenge.token.clone(), challenge.key_authorization().as_str().to_string());
        challenge.set_ready().await.context("start the check")?;
    }
    let status = order
        .poll_ready(&RetryPolicy::new().timeout(Duration::from_secs(120)))
        .await
        .context("wait for the check")?;
    if status != OrderStatus::Ready {
        let detail = order
            .state()
            .error
            .as_ref()
            .and_then(|problem| problem.detail.clone())
            .unwrap_or_default();
        bail!("Let's Encrypt did not confirm the address ({status:?}) {detail}");
    }

    let key = rcgen::KeyPair::generate().context("create the certificate key")?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.subject_alt_names = vec![match ip {
        Some(ip) => rcgen::SanType::IpAddress(ip),
        None => rcgen::SanType::DnsName(settings.address.clone().try_into()?),
    }];
    let request = params.serialize_request(&key).context("create the certificate request")?;
    order.finalize_csr(request.der()).await.context("send the certificate request")?;
    let pem = order
        .poll_certificate(&RetryPolicy::new().timeout(Duration::from_secs(120)))
        .await
        .context("download the certificate")?;
    let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow!("unreadable certificate: {error:?}"))?;
    ensure!(!chain.is_empty(), "the certificate service sent no certificate");
    let key_der = key.serialize_der();
    save(state_dir, &pem, &key_der)?;
    Ok(Issued {
        chain,
        key: PrivatePkcs8KeyDer::from(key_der),
    })
}

/// Serves the stored certificate if it is still valid, else keeps what `swap` has.
pub fn install_stored(state_dir: &Path, swap: &Swap) -> Option<u64> {
    let issued = load(state_dir)?;
    let (_, until) = issued.validity().ok()?;
    if until <= super::now() {
        return None;
    }
    let certified = tls::certified(issued.chain.clone(), PrivateKeyDer::Pkcs8(issued.key.clone_key())).ok()?;
    swap.set(certified);
    issued.renew_at().ok()
}

/// Keeps a valid certificate in `swap`: orders one now if there is none, and a new one after two
/// thirds of the current one's life. `report` is told about every order.
pub async fn keep_renewed(
    state_dir: PathBuf,
    settings: AcmeSettings,
    swap: Arc<Swap>,
    report: impl Fn(Result<u64, String>) + Send + 'static,
) {
    let mut renew_at = install_stored(&state_dir, &swap).unwrap_or(0);
    let mut wait_after_failure = RETRY_FIRST;
    loop {
        if super::now() >= renew_at {
            match issue(&state_dir, &settings, 80).await.and_then(|issued| {
                let next = issued.renew_at()?;
                swap.set(tls::certified(issued.chain, PrivateKeyDer::Pkcs8(issued.key))?);
                Ok(next)
            }) {
                Ok(next) => {
                    renew_at = next;
                    wait_after_failure = RETRY_FIRST;
                    report(Ok(next));
                }
                Err(error) => {
                    report(Err(format!("{error:#}")));
                    renew_at = super::now() + wait_after_failure.as_secs();
                    wait_after_failure = (wait_after_failure * 2).min(RETRY_MAX);
                }
            }
        }
        let wait = renew_at.saturating_sub(super::now()).clamp(1, CHECK_EVERY.as_secs());
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}

/// A time as "2026-11-19 06:04 UTC".
pub fn utc_text(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // Inverse of days_from_civil (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02} UTC", rest / 3600, rest % 3600 / 60)
}

/// (notBefore, notAfter) in seconds since 1970 from a DER certificate.
pub fn validity_of(der: &[u8]) -> Option<(u64, u64)> {
    let certificate = tls::inner(der)?;
    let mut rest = tls::inner(certificate)?;
    // TBSCertificate: [0] version, serial, signature, issuer, validity, ...
    for _ in 0..4 {
        let (length, _) = tls::element(rest)?;
        rest = rest.get(length..)?;
    }
    let validity = tls::inner(rest)?;
    let (first, _) = tls::element(validity)?;
    let not_before = time_of(validity)?;
    let not_after = time_of(validity.get(first..)?)?;
    Some((not_before, not_after))
}

/// A DER UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) as seconds since 1970.
fn time_of(element: &[u8]) -> Option<u64> {
    let tag = *element.first()?;
    let text = std::str::from_utf8(tls::inner(element)?).ok()?;
    let text = text.strip_suffix('Z')?;
    let (year, rest) = match (tag, text.len()) {
        (0x17, 12) => {
            let yy: i64 = text.get(..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, text.get(2..)?)
        }
        (0x18, 14) => (text.get(..4)?.parse().ok()?, text.get(4..)?),
        _ => return None,
    };
    let field = |at: usize| -> Option<i64> { rest.get(at..at + 2)?.parse().ok() };
    let (month, day, hour, minute, second) = (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

/// Days since 1970-01-01 for a date in the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http01_is_reachable_on_ipv6_when_the_host_supports_it() {
        let listeners = super::super::relay::listeners(0).await.unwrap();
        if listeners.len() != 2 { return; }
        let port = listeners[0].local_addr().unwrap().port();
        drop(listeners);
        let answers: Answers = Arc::default();
        answers.lock().unwrap().insert("ipv6-token".into(), "ipv6-answer".into());
        let _server = ChallengeServer::start(answers, port, true).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, port)).await.unwrap();
        stream.write_all(b"GET /.well-known/acme-challenge/ipv6-token HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_string(&mut response)).await.unwrap().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.ends_with("ipv6-answer"));
    }

    fn certificate(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> (Vec<u8>, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        (params.self_signed(&key).unwrap().der().to_vec(), key)
    }

    #[test]
    fn validity_is_read_from_the_certificate() {
        // 2026-11-13 and 2026-11-19 (a six-day certificate), UTCTime.
        let (der, _) = certificate((2026, 11, 13), (2026, 11, 19));
        assert_eq!(validity_of(&der), Some((1_794_528_000, 1_795_046_400)));
        // Dates from 2050 on are GeneralizedTime.
        let (der, _) = certificate((2049, 12, 31), (2051, 3, 1));
        let (from, until) = validity_of(&der).unwrap();
        assert_eq!(from, 2_524_521_600);
        assert_eq!(until, 2_561_241_600);
        assert_eq!(validity_of(b"not a certificate"), None);
    }

    #[test]
    fn calendar_arithmetic_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
        assert_eq!(time_of(&[0x17, 13, b'7', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z']), Some(0));
        // Malformed times are refused, not misread.
        assert_eq!(time_of(&[0x17, 13, b'7', b'0', b'1', b'3', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z']), None);
        assert_eq!(time_of(&[0x17, 12, b'7', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0']), None);
    }

    #[test]
    fn times_are_written_as_utc_dates() {
        assert_eq!(utc_text(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_text(1_795_046_400 + 6 * 3600 + 4 * 60), "2026-11-19 06:04 UTC");
        assert_eq!(utc_text(1_709_164_800), "2024-02-29 00:00 UTC");
        for days in [0i64, 59, 60, 365, 11_016, 19_782, 29_644] {
            let text = utc_text(days as u64 * 86_400);
            let (y, m, d) = (text[..4].parse().unwrap(), text[5..7].parse().unwrap(), text[8..10].parse().unwrap());
            assert_eq!(days_from_civil(y, m, d), days, "{text}");
        }
    }

    #[test]
    fn renewal_comes_after_two_thirds_of_the_life() {
        let day = 86_400;
        assert_eq!(renew_time(0, 6 * day), 4 * day);
        assert_eq!(renew_time(1000, 1000 + 90 * day), 1000 + 60 * day);
        assert_eq!(renew_time(10, 5), 10, "a broken range renews at once");
    }

    #[test]
    fn a_stored_certificate_is_loaded_and_served_while_valid() {
        let dir = tempfile::tempdir().unwrap();
        let now = super::super::now() as i64;
        let date = |offset_days: i64| {
            let secs = now + offset_days * 86_400;
            let days = secs.div_euclid(86_400);
            // Back from days to a civil date by searching around the estimate.
            let mut year = 1970 + (days / 366) as i32;
            while days_from_civil(year as i64 + 1, 1, 1) <= days {
                year += 1;
            }
            let mut month = 1u8;
            while month < 12 && days_from_civil(year as i64, month as i64 + 1, 1) <= days {
                month += 1;
            }
            let day = (days - days_from_civil(year as i64, month as i64, 1) + 1) as u8;
            (year, month, day)
        };
        let (der, key) = certificate(date(-1), date(5));
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der)
        );
        save(dir.path(), &pem, &key.serialize_der()).unwrap();
        let swap = Swap::self_signed(dir.path(), "203.0.113.10").unwrap();
        let before = swap.current();
        let renew = install_stored(dir.path(), &swap).expect("valid certificate installed");
        assert!(!Arc::ptr_eq(&before, &swap.current()), "the served certificate changed");
        assert_eq!(swap.current().cert[0].as_ref(), der.as_slice());
        assert!(renew > now as u64 && renew < (now + 5 * 86_400) as u64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(KEY_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // An expired one is not served.
        let (der, key) = certificate(date(-10), date(-1));
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &der)
        );
        save(dir.path(), &pem, &key.serialize_der()).unwrap();
        let swap = Swap::self_signed(dir.path(), "203.0.113.10").unwrap();
        assert!(install_stored(dir.path(), &swap).is_none());
        forget(dir.path());
        assert!(load(dir.path()).is_none());
    }

    #[tokio::test]
    async fn the_challenge_server_answers_only_known_tokens() {
        let answers: Answers = Arc::default();
        answers.lock().unwrap().insert("tok123".into(), "tok123.thumb".into());
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let _server = ChallengeServer::start(answers, port, false).await.unwrap();
        let get = |path: &'static str| async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut text = String::new();
            stream.read_to_string(&mut text).await.unwrap();
            text
        };
        let found = get("/.well-known/acme-challenge/tok123").await;
        assert!(found.starts_with("HTTP/1.1 200") && found.ends_with("tok123.thumb"), "{found}");
        assert!(get("/.well-known/acme-challenge/other").await.starts_with("HTTP/1.1 404"));
        assert!(get("/").await.starts_with("HTTP/1.1 404"));
        assert!(get("/.well-known/acme-challenge/../tok123").await.starts_with("HTTP/1.1 404"));
    }
}
