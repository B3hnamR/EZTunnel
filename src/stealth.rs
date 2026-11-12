//! Wire version 2 ("probe resistance"): a mask that makes a plain TCP connection look
//! like random bytes of random length, a hold-then-close answer for connections that fail the
//! handshake, and names derived from the server's public key instead of fixed project strings.
//!
//! Version 1 is the format of 0.6.x and earlier. A configuration without `wire_version` is
//! version 1, so existing tunnels keep working after an upgrade. Both ends must use the same
//! version. This is protection against fixed fingerprints and cheap probes, not against traffic
//! analysis.
use anyhow::{Result, ensure};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// Largest padding a reader accepts at the start of a masked stream.
const MAX_ACCEPTED_PAD: usize = 4095;
/// The start of a stream is printable characters only (nonce, pad length and pad). A network that
/// cuts connections whose first packet looks uniformly random lets these through, while the data
/// after the start is masked and random.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const NONCE: usize = 16;
const CHUNK: usize = 16 * 1024;

fn one() -> u8 {
    1
}
fn is_one(value: &u8) -> bool {
    *value == 1
}
fn pad_min() -> u16 {
    64
}
fn pad_max() -> u16 {
    255
}
fn hold() -> u64 {
    5
}
fn status() -> u16 {
    404
}

/// Settings of wire version 2. They have no effect on version 1.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stealth {
    /// Printable padding (this many bytes at least) at the start of each direction of a masked
    /// stream. A long printable start keeps the first packet from looking like uniform noise.
    #[serde(default = "pad_min")]
    pub pad_min: u16,
    /// Padding at most this many bytes.
    #[serde(default = "pad_max")]
    pub pad_max: u16,
    /// A connection that fails the handshake is read and ignored for up to this many seconds
    /// before it is closed, so a probe sees silence instead of an instant close. 0 = close at once.
    #[serde(default = "hold")]
    pub probe_hold_sec: u64,
    /// HTTP status of the page a wrong request gets (404 is the usual choice).
    #[serde(default = "status")]
    pub decoy_status: u16,
    /// Pad every record the tunnel sends by a random 0..=this many bytes, so that record sizes
    /// no longer show what is inside (acknowledgements, heartbeats, small requests). 0 = off.
    /// Costs about half this many bytes per record.
    #[serde(default)]
    pub record_pad_max: u16,
    /// Delay the start of each burst of sending by a random 0..=this many milliseconds, so the
    /// timing of sporadic traffic is not a copy of the user's. Records that follow within 20 ms
    /// of the previous one are not delayed, so bulk transfers keep their speed. 0 = off.
    #[serde(default)]
    pub jitter_ms: u16,
}

impl Default for Stealth {
    fn default() -> Self {
        Self {
            pad_min: pad_min(),
            pad_max: pad_max(),
            probe_hold_sec: hold(),
            decoy_status: status(),
            record_pad_max: 0,
            jitter_ms: 0,
        }
    }
}

impl Stealth {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            usize::from(self.pad_max) <= MAX_ACCEPTED_PAD,
            "stealth.pad_max must be 0..{MAX_ACCEPTED_PAD}"
        );
        // pad_min has its own ceiling, same as pad_max, but no pad_min <= pad_max cross-check:
        // Masked::new already clamps pad_min down to pad_max, so setting only pad_max (e.g. to
        // 0, to disable padding) must not be rejected just because pad_min is still at its own,
        // larger default.
        ensure!(
            usize::from(self.pad_min) <= MAX_ACCEPTED_PAD,
            "stealth.pad_min must be 0..{MAX_ACCEPTED_PAD}"
        );
        ensure!(
            self.probe_hold_sec <= 120,
            "stealth.probe_hold_sec must be 0..120"
        );
        ensure!(
            self.record_pad_max <= 255,
            "stealth.record_pad_max must be 0..255"
        );
        ensure!(self.jitter_ms <= 1000, "stealth.jitter_ms must be 0..1000");
        ensure!(
            matches!(self.decoy_status, 200 | 400 | 403 | 404 | 421),
            "stealth.decoy_status must be one of 200, 400, 403, 404, 421"
        );
        Ok(())
    }
}

/// The wire settings a carrier needs, copied into each listener and path when the configuration
/// is prepared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireOptions {
    pub version: u8,
    pub stealth: Stealth,
    /// The server's public key; every derived name and the mask key come from it.
    pub server_key: [u8; 32],
}

impl Default for WireOptions {
    fn default() -> Self {
        Self {
            version: 1,
            stealth: Stealth::default(),
            server_key: [0; 32],
        }
    }
}

pub(crate) fn default_version() -> u8 {
    one()
}

pub fn valid_version(version: u8) -> bool {
    (1..=3).contains(&version)
}

/// New tunnels opt into rotation; existing configs retain their stored version.
pub fn new_version() -> u8 {
    3
}
pub(crate) fn version_is_default(value: &u8) -> bool {
    is_one(value)
}
pub(crate) fn stealth_is_default(value: &Stealth) -> bool {
    *value == Stealth::default()
}

impl WireOptions {
    pub fn v2(&self) -> bool {
        self.version >= 2
    }

    fn derive(&self, purpose: &str) -> [u8; 32] {
        Blake2s256::new()
            .chain_update(b"eztunnel wire v2\0")
            .chain_update(purpose.as_bytes())
            .chain_update(b"\0")
            .chain_update(self.server_key)
            .finalize()
            .into()
    }

    /// Token of the `http`/`https` Upgrade header.
    pub fn upgrade_token(&self) -> String {
        if self.v2() {
            hex::encode(&self.derive("upgrade token")[..6])
        } else {
            "eztunnel-v1".into()
        }
    }

    /// Name of an XHTTP request header; `kind` is `auth` or `upload`.
    pub fn xhttp_header(&self, kind: &str) -> String {
        if self.v2() {
            let tag = hex::encode(&self.derive(&format!("xhttp header {kind}"))[..3]);
            match kind {
                "auth" => format!("X-Req-{tag}"),
                _ => format!("X-Ref-{tag}"),
            }
        } else {
            match kind {
                "auth" => "X-EZ-Auth".into(),
                _ => "X-EZ-Upload".into(),
            }
        }
    }

    /// Path prefix for XHTTP and WebSocket tunnels created by the wizard.
    pub fn derived_path(&self) -> String {
        format!("/{}", hex::encode(&self.derive("path")[..4]))
    }

    /// Host name inside the derived TLS certificate.
    pub fn certificate_name(&self) -> String {
        let name = self.derive("certificate name");
        let label = hex::encode(&name[..4]);
        format!("{label}.cdn-edge.net")
    }

    /// Stream-mask key, from the server's public key.
    fn mask_key(&self) -> [u8; 32] {
        self.derive("stream mask")
    }
}

/// The page a wrong HTTP request gets in version 2: an ordinary web-server 404 (or the chosen
/// status), with the usual headers, then the connection stays quiet until it is closed.
pub fn decoy_response(status: u16) -> Vec<u8> {
    let (line, body) = match status {
        200 => (
            "200 OK",
            "<!DOCTYPE html>\n<html><head><title>Welcome</title></head><body><h1>It works</h1></body></html>\n",
        ),
        400 => (
            "400 Bad Request",
            "<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
        ),
        403 => (
            "403 Forbidden",
            "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
        ),
        421 => (
            "421 Misdirected Request",
            "<html>\r\n<head><title>421 Misdirected Request</title></head>\r\n<body>\r\n<center><h1>421 Misdirected Request</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
        ),
        _ => (
            "404 Not Found",
            "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
        ),
    };
    format!(
        "HTTP/1.1 {line}\r\nServer: nginx\r\nDate: {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        http_date(std::time::SystemTime::now()),
        body.len()
    )
    .into_bytes()
}

/// What nginx answers when a plain HTTP request arrives on a TLS port.
pub fn plain_http_on_tls_response() -> Vec<u8> {
    let body = "<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<center>The plain HTTP request was sent to HTTPS port</center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
    format!(
        "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nDate: {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        http_date(std::time::SystemTime::now()),
        body.len()
    )
    .into_bytes()
}

/// An HTTP date such as `Sun, 06 Nov 1994 08:49:37 GMT` (every real web server sends one).
pub fn http_date(time: std::time::SystemTime) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let seconds = time
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[((days + 4).rem_euclid(7)) as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

pub(crate) fn random_bytes(bytes: &mut [u8]) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(bytes)
        .map_err(|_| anyhow::anyhow!("operating-system random generator failed"))
}

pub(crate) fn random_below(limit: u64) -> Result<u64> {
    if limit == 0 {
        return Ok(0);
    }
    let mut raw = [0; 8];
    random_bytes(&mut raw)?;
    Ok(u64::from_le_bytes(raw) % limit)
}

/// Reads and ignores whatever the peer sends for a random time of `max_sec / 2 ..= max_sec`
/// seconds (or until it closes), so a failed probe cannot tell this port from a slow service.
/// Returns at once when `max_sec` is 0.
pub async fn hold_then_close<S>(stream: &mut S, max_sec: u64)
where
    S: AsyncRead + Unpin,
{
    if max_sec == 0 {
        return;
    }
    let low = max_sec * 500;
    let millis = low + random_below(max_sec * 1000 - low + 1).unwrap_or(0);
    let mut sink = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_millis(millis), async {
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

/// XORs `data` with the keystream of one direction, starting at byte `position` after the nonce.
fn apply_keystream(key: &[u8; 32], nonce: &[u8; NONCE], position: u64, data: &mut [u8]) {
    let mut done = 0;
    while done < data.len() {
        let absolute = position + done as u64;
        let block = absolute / 32;
        let offset = (absolute % 32) as usize;
        let stream: [u8; 32] = Blake2s256::new()
            .chain_update(key)
            .chain_update(nonce)
            .chain_update(block.to_le_bytes())
            .finalize()
            .into();
        let take = (32 - offset).min(data.len() - done);
        for (byte, mask) in data[done..done + take].iter_mut().zip(&stream[offset..]) {
            *byte ^= mask;
        }
        done += take;
    }
}

enum ReadState {
    Nonce {
        buf: [u8; NONCE],
        filled: usize,
    },
    PadLen {
        buf: [u8; 2],
        filled: usize,
    },
    Skip {
        remaining: usize,
    },
    Data,
    /// The start was not a valid masked stream: pass the bytes on unchanged (the caller is
    /// about to hold and close the connection).
    Passthrough,
}

/// A stream whose bytes look random in both directions. Each direction starts with a random
/// 16-byte nonce and a random-length pad, both sent as printable bytes without masking; every
/// byte of real data after that pad is XORed with a keystream (BLAKE2s in counter mode, keyed
/// from the server's public key). The 2-byte record lengths of the layer above are masked too,
/// so no field there has a fixed value. The mask gives no integrity or secrecy of its own; Noise
/// inside does.
pub struct Masked<S> {
    inner: S,
    key: [u8; 32],
    pad_min: u16,
    pad_max: u16,
    // write side
    out_nonce: Option<[u8; NONCE]>,
    pending: Vec<u8>,
    pending_sent: usize,
    write_position: u64,
    // read side
    state: ReadState,
    in_nonce: [u8; NONCE],
    read_position: u64,
}

impl<S> Masked<S> {
    pub fn new(inner: S, wire: &WireOptions) -> Self {
        Self {
            inner,
            key: wire.mask_key(),
            pad_min: wire.stealth.pad_min.min(wire.stealth.pad_max),
            pad_max: wire.stealth.pad_max,
            out_nonce: None,
            pending: Vec::new(),
            pending_sent: 0,
            write_position: 0,
            state: ReadState::Nonce {
                buf: [0; NONCE],
                filled: 0,
            },
            in_nonce: [0; NONCE],
            read_position: 0,
        }
    }

    fn start_writing(&mut self) -> io::Result<()> {
        let mut nonce = [0; NONCE];
        random_bytes(&mut nonce).map_err(io::Error::other)?;
        for byte in &mut nonce {
            *byte = ALPHABET[usize::from(*byte & 63)];
        }
        let span = u64::from(self.pad_max - self.pad_min) + 1;
        let pad =
            usize::from(self.pad_min) + random_below(span).map_err(io::Error::other)? as usize;
        let mut head = vec![0u8; 2 + pad];
        random_bytes(&mut head).map_err(io::Error::other)?;
        for byte in &mut head {
            *byte = ALPHABET[usize::from(*byte & 63)];
        }
        head[0] = ALPHABET[(pad >> 6) & 63];
        head[1] = ALPHABET[pad & 63];
        self.write_position = 0;
        self.pending = nonce.to_vec();
        self.pending.extend_from_slice(&head);
        self.out_nonce = Some(nonce);
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Masked<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                ReadState::Nonce { buf, filled } => {
                    let mut read = ReadBuf::new(&mut buf[*filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let got = read.filled().len();
                            if got == 0 {
                                return Poll::Ready(if *filled == 0 {
                                    Ok(())
                                } else {
                                    Err(io::ErrorKind::UnexpectedEof.into())
                                });
                            }
                            *filled += got;
                            if *filled == NONCE {
                                this.in_nonce = *buf;
                                this.state = ReadState::PadLen {
                                    buf: [0; 2],
                                    filled: 0,
                                };
                            }
                        }
                    }
                }
                ReadState::PadLen { buf, filled } => {
                    let mut read = ReadBuf::new(&mut buf[*filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let got = read.filled().len();
                            if got == 0 {
                                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                            }
                            *filled += got;
                            if *filled == 2 {
                                let digit = |c: u8| ALPHABET.iter().position(|a| *a == c);
                                let pad = match (digit(buf[0]), digit(buf[1])) {
                                    (Some(high), Some(low)) => (high << 6) | low,
                                    _ => usize::MAX,
                                };
                                if pad > MAX_ACCEPTED_PAD {
                                    this.state = ReadState::Passthrough;
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "masked stream: bad padding length",
                                    )));
                                }
                                this.read_position = 0;
                                this.state = if pad == 0 {
                                    ReadState::Data
                                } else {
                                    ReadState::Skip { remaining: pad }
                                };
                            }
                        }
                    }
                }
                ReadState::Skip { remaining } => {
                    let mut scratch = [0u8; 512];
                    let want = (*remaining).min(scratch.len());
                    let mut read = ReadBuf::new(&mut scratch[..want]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let got = read.filled().len();
                            if got == 0 {
                                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                            }
                            *remaining -= got;
                            if *remaining == 0 {
                                this.state = ReadState::Data;
                            }
                        }
                    }
                }
                ReadState::Passthrough => return Pin::new(&mut this.inner).poll_read(cx, out),
                ReadState::Data => {
                    let before = out.filled().len();
                    match Pin::new(&mut this.inner).poll_read(cx, out) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            let fresh = &mut out.filled_mut()[before..];
                            apply_keystream(&this.key, &this.in_nonce, this.read_position, fresh);
                            this.read_position += fresh.len() as u64;
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Masked<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.out_nonce.is_none() {
            this.start_writing()?;
        }
        while this.pending_sent < this.pending.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.pending_sent..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => this.pending_sent += n,
            }
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let nonce = this.out_nonce.unwrap_or([0; NONCE]);
        let take = data.len().min(CHUNK);
        let mut masked = data[..take].to_vec();
        apply_keystream(&this.key, &nonce, this.write_position, &mut masked);
        match Pin::new(&mut this.inner).poll_write(cx, &masked) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(n)) => {
                this.write_position += n as u64;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.pending_sent < this.pending.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.pending_sent..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => this.pending_sent += n,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn wire(key: u8, pad_max: u16) -> WireOptions {
        WireOptions {
            version: 2,
            stealth: Stealth {
                pad_max,
                ..Stealth::default()
            },
            server_key: [key; 32],
        }
    }

    #[tokio::test]
    async fn masked_stream_round_trips_both_directions() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let w = wire(7, 255);
        let mut a = Masked::new(a, &w);
        let mut b = Masked::new(b, &w);
        let payload: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let send = payload.clone();
        let writer = tokio::spawn(async move {
            a.write_all(&send).await.unwrap();
            a.flush().await.unwrap();
            let mut back = vec![0; 5];
            a.read_exact(&mut back).await.unwrap();
            back
        });
        let mut got = vec![0; payload.len()];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        b.write_all(b"hello").await.unwrap();
        b.flush().await.unwrap();
        assert_eq!(writer.await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn the_wire_bytes_are_masked_and_vary_in_length() {
        let w = wire(9, 255);
        let mut lengths = std::collections::BTreeSet::new();
        for _ in 0..20 {
            let (a, mut b) = tokio::io::duplex(1 << 16);
            let mut a = Masked::new(a, &w);
            a.write_all(&[0u8; 64]).await.unwrap();
            a.flush().await.unwrap();
            drop(a);
            let mut raw = Vec::new();
            b.read_to_end(&mut raw).await.unwrap();
            lengths.insert(raw.len());
            // 64 zero bytes would show as 64 zero bytes if the mask did nothing.
            assert!(raw.iter().filter(|byte| **byte == 0).count() < raw.len() / 4);
        }
        assert!(lengths.len() > 5, "start of stream has a fixed length");
    }

    #[tokio::test]
    async fn the_start_of_the_stream_is_printable() {
        let w = wire(3, 255);
        let (a, mut b) = tokio::io::duplex(1 << 16);
        let mut a = Masked::new(a, &w);
        a.write_all(&[0u8; 8]).await.unwrap();
        a.flush().await.unwrap();
        drop(a);
        let mut raw = Vec::new();
        b.read_to_end(&mut raw).await.unwrap();
        // nonce (16) + length (2) + at least 64 bytes of padding, then 8 masked bytes
        assert!(raw.len() >= 16 + 2 + 64 + 8);
        assert!(raw[..16 + 2 + 64].iter().all(|b| (0x20..0x7f).contains(b)));
    }

    #[test]
    fn http_dates_look_like_a_web_servers() {
        use std::time::{Duration, UNIX_EPOCH};
        let at = |seconds: u64| http_date(UNIX_EPOCH + Duration::from_secs(seconds));
        assert_eq!(at(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(at(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(at(1_000_000_000), "Sun, 09 Sep 2001 01:46:40 GMT");
        assert_eq!(at(1_709_164_800), "Thu, 29 Feb 2024 00:00:00 GMT");
        let page = String::from_utf8(decoy_response(404)).unwrap();
        assert!(page.contains("\r\nDate: ") && page.contains("GMT\r\n"));
    }

    #[tokio::test]
    async fn a_different_server_key_does_not_decode() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut a = Masked::new(a, &wire(1, 0));
        let mut b = Masked::new(b, &wire(2, 0));
        a.write_all(b"secret text here").await.unwrap();
        a.flush().await.unwrap();
        let mut got = vec![0; 16];
        if b.read_exact(&mut got).await.is_ok() {
            assert_ne!(got, b"secret text here");
        }
    }

    #[test]
    fn names_are_stable_per_key_and_differ_between_keys() {
        let a = wire(1, 255);
        let b = wire(2, 255);
        assert_eq!(a.upgrade_token(), a.upgrade_token());
        assert_ne!(a.upgrade_token(), b.upgrade_token());
        assert_ne!(a.xhttp_header("auth"), a.xhttp_header("upload"));
        assert_ne!(a.derived_path(), b.derived_path());
        assert_ne!(a.certificate_name(), b.certificate_name());
        let v1 = WireOptions::default();
        assert_eq!(v1.upgrade_token(), "eztunnel-v1");
        assert_eq!(v1.xhttp_header("auth"), "X-EZ-Auth");
    }

    #[test]
    fn decoy_pages_declare_their_own_length() {
        for status in [200, 400, 403, 404, 421] {
            let page = String::from_utf8(decoy_response(status)).unwrap();
            let (head, body) = page.split_once("\r\n\r\n").unwrap();
            assert!(head.contains(&format!("Content-Length: {}", body.len())));
        }
    }

    #[test]
    fn settings_are_checked() {
        assert!(Stealth::default().validate().is_ok());
        assert!(
            Stealth {
                pad_max: 5000,
                ..Stealth::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Stealth {
                decoy_status: 302,
                ..Stealth::default()
            }
            .validate()
            .is_err()
        );
        // Setting only pad_max (to disable padding) must not be rejected just because pad_min
        // is still at its own, larger default; Masked::new clamps that combination fine.
        assert!(
            Stealth {
                pad_max: 0,
                ..Stealth::default()
            }
            .validate()
            .is_ok()
        );
    }
}
