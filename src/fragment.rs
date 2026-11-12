//! TLS ClientHello fragmentation for the dialing side of TLS carriers.
//!
//! Some filters read the server name (SNI) from the first TLS packet of a connection. This
//! writer splits the first TLS handshake record into several smaller TLS records (allowed by
//! the TLS standard; every TLS server reassembles them) and sends each one in its own TCP
//! packet, optionally after a short random pause. Everything after the first record passes
//! through unchanged, so only the connection setup is affected.
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Settings of ClientHello fragmentation. Off unless `enabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsFragment {
    pub enabled: bool,
    /// Smallest piece of the ClientHello per TLS record.
    pub min_bytes: usize,
    /// Largest piece of the ClientHello per TLS record.
    pub max_bytes: usize,
    /// Longest random pause between pieces, in milliseconds (0 = no pause).
    pub delay_ms: u64,
}

impl Default for TlsFragment {
    fn default() -> Self {
        Self {
            enabled: false,
            min_bytes: 10,
            max_bytes: 60,
            delay_ms: 5,
        }
    }
}

impl TlsFragment {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=1024).contains(&self.min_bytes)
                && (1..=1024).contains(&self.max_bytes)
                && self.min_bytes <= self.max_bytes,
            "tls_fragment min_bytes and max_bytes must be 1..1024, min not above max"
        );
        anyhow::ensure!(
            self.delay_ms <= 1000,
            "tls_fragment delay_ms must be 0..1000"
        );
        Ok(())
    }
}

/// Small random numbers for piece sizes and pauses; not used for anything secret.
struct Shuffle(u64);

impl Shuffle {
    fn new() -> Self {
        let mut seed = [0u8; 8];
        let _ = rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut seed);
        Self(u64::from_le_bytes(seed) | 1)
    }

    fn below(&mut self, bound: u64) -> u64 {
        // xorshift64
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        if bound == 0 { 0 } else { self.0 % bound }
    }
}

/// Where the server name (SNI) sits inside a ClientHello handshake message, as
/// (start, length) within `hello`.
fn find_sni(hello: &[u8]) -> Option<(usize, usize)> {
    let u16_at = |at: usize| -> Option<usize> {
        Some(u16::from_be_bytes([*hello.get(at)?, *hello.get(at + 1)?]) as usize)
    };
    // Handshake type 1 (ClientHello), 3-byte length, version, 32-byte random.
    if *hello.first()? != 1 {
        return None;
    }
    let mut at = 4 + 2 + 32;
    at += 1 + *hello.get(at)? as usize; // session id
    at += 2 + u16_at(at)?; // cipher suites
    at += 1 + *hello.get(at)? as usize; // compression methods
    let end = (at + 2 + u16_at(at)?).min(hello.len());
    at += 2;
    while at + 4 <= end {
        let (kind, length) = (u16_at(at)?, u16_at(at + 2)?);
        if kind == 0 {
            // server_name: list length, name type, name length, name.
            let name_length = u16_at(at + 4 + 3)?;
            let start = at + 4 + 5;
            return (start + name_length <= end).then_some((start, name_length));
        }
        at += 4 + length;
    }
    None
}

/// Splits one complete TLS record into several records carrying pieces of its payload. A cut
/// always falls inside the server name, so no single piece contains the whole name.
fn split_record(record: &[u8], settings: &TlsFragment, shuffle: &mut Shuffle) -> Vec<Vec<u8>> {
    let (header, payload) = record.split_at(5);
    let forced_cut = find_sni(payload)
        .filter(|&(_, length)| length >= 2)
        .map(|(start, length)| start + length / 2);
    let mut pieces = Vec::new();
    let mut rest = payload;
    let mut offset = 0;
    while !rest.is_empty() {
        let span = (settings.max_bytes - settings.min_bytes + 1) as u64;
        let mut size = (settings.min_bytes + shuffle.below(span) as usize).min(rest.len());
        if let Some(cut) = forced_cut
            && offset < cut
            && cut < offset + size
        {
            size = cut - offset;
        }
        offset += size;
        let (piece, tail) = rest.split_at(size);
        let mut record = Vec::with_capacity(5 + piece.len());
        record.extend_from_slice(&header[..3]);
        record.extend_from_slice(&(piece.len() as u16).to_be_bytes());
        record.extend_from_slice(piece);
        pieces.push(record);
        rest = tail;
    }
    pieces
}

/// The length of the complete TLS handshake record at the start of `data`, if it is one.
fn handshake_record_len(data: &[u8]) -> Option<usize> {
    if data.len() < 5 || data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }
    let length = u16::from_be_bytes([data[3], data[4]]) as usize;
    (length > 0 && data.len() >= 5 + length).then_some(5 + length)
}

enum State {
    /// Waiting for the first write.
    First,
    /// Sending the pieces of the first record; `accepted` bytes are reported when done.
    Sending {
        pieces: VecDeque<Vec<u8>>,
        written: usize,
        accepted: usize,
        pause: Option<Pin<Box<tokio::time::Sleep>>>,
    },
    /// Everything else passes straight through.
    Through,
}

pub struct FragmentWriter<S> {
    inner: S,
    settings: TlsFragment,
    shuffle: Shuffle,
    state: State,
}

impl<S> FragmentWriter<S> {
    pub fn new(inner: S, settings: TlsFragment) -> Self {
        Self {
            inner,
            settings,
            shuffle: Shuffle::new(),
            state: State::First,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentWriter<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentWriter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            match &mut this.state {
                State::Through => return Pin::new(&mut this.inner).poll_write(cx, buf),
                State::First => match handshake_record_len(buf) {
                    Some(length) if this.settings.enabled => {
                        let pieces =
                            split_record(&buf[..length], &this.settings, &mut this.shuffle);
                        this.state = State::Sending {
                            pieces: pieces.into(),
                            written: 0,
                            accepted: length,
                            pause: None,
                        };
                    }
                    None if this.settings.enabled => {
                        // The whole ClientHello record was not in this one write (an unusual
                        // caller, not a sign of a malformed handshake), so there is nothing here
                        // to split - but silently falling through to plain, unfragmented writes
                        // would turn the anti-DPI feature off for this connection without saying
                        // so anywhere.
                        tracing::warn!(
                            "tls_fragment: the ClientHello did not arrive in one write; this connection is not fragmented"
                        );
                        this.state = State::Through;
                    }
                    _ => this.state = State::Through,
                },
                State::Sending {
                    pieces,
                    written,
                    accepted,
                    pause,
                } => {
                    if let Some(sleep) = pause {
                        if sleep.as_mut().poll(cx).is_pending() {
                            return Poll::Pending;
                        }
                        *pause = None;
                    }
                    let Some(piece) = pieces.front() else {
                        let accepted = *accepted;
                        this.state = State::Through;
                        return Poll::Ready(Ok(accepted));
                    };
                    match Pin::new(&mut this.inner).poll_write(cx, &piece[*written..]) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        Poll::Ready(Ok(count)) => {
                            *written += count;
                            if *written == piece.len() {
                                pieces.pop_front();
                                *written = 0;
                                if !pieces.is_empty() && this.settings.delay_ms > 0 {
                                    let wait = this.shuffle.below(this.settings.delay_ms + 1);
                                    *pause = Some(Box::pin(tokio::time::sleep(
                                        Duration::from_millis(wait),
                                    )));
                                }
                            }
                        }
                        other => return other,
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client_hello(payload_len: usize) -> Vec<u8> {
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(payload_len as u16).to_be_bytes());
        record.extend((0..payload_len).map(|i| (i % 251) as u8));
        record
    }

    /// Reads TLS records back and returns their payloads.
    fn records(mut data: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while data.len() >= 5 {
            let len = u16::from_be_bytes([data[3], data[4]]) as usize;
            out.push(data[5..5 + len].to_vec());
            data = &data[5 + len..];
        }
        assert!(data.is_empty());
        out
    }

    #[tokio::test]
    async fn the_first_record_is_split_and_the_rest_passes_unchanged() {
        let settings = TlsFragment {
            enabled: true,
            min_bytes: 10,
            max_bytes: 60,
            delay_ms: 2,
        };
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let mut writer = FragmentWriter::new(client, settings);
        let hello = client_hello(517);
        writer.write_all(&hello).await.unwrap();
        writer.write_all(b"after the hello").await.unwrap();
        writer.shutdown().await.unwrap();
        drop(writer);
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        let tail = b"after the hello";
        let (fragmented, rest) = received.split_at(received.len() - tail.len());
        assert_eq!(rest, tail);
        let pieces = records(fragmented);
        assert!(pieces.len() >= 517 / 60, "{} pieces", pieces.len());
        assert!(pieces.iter().all(|p| (1..=60).contains(&p.len())));
        assert_eq!(pieces.concat(), hello[5..].to_vec());
    }

    /// A ClientHello shaped like a real one, carrying `name` in its server_name extension.
    fn hello_with_sni(name: &str) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([7u8; 32]); // random
        body.push(0); // session id
        body.extend([0, 2, 0x13, 0x01]); // one cipher suite
        body.extend([1, 0]); // compression
        let mut sni = vec![];
        sni.extend(((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend((name.len() as u16).to_be_bytes());
        sni.extend(name.as_bytes());
        let mut extensions = vec![0, 0x0a, 0, 2, 0, 0x1d]; // another extension first
        extensions.extend([0, 0]);
        extensions.extend((sni.len() as u16).to_be_bytes());
        extensions.extend(sni);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let mut hello = vec![1, 0];
        hello.extend((body.len() as u16).to_be_bytes());
        hello.extend(body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend((hello.len() as u16).to_be_bytes());
        record.extend(hello);
        record
    }

    #[test]
    fn the_server_name_is_always_cut() {
        let name = "www.example.com";
        let record = hello_with_sni(name);
        assert_eq!(
            find_sni(&record[5..]).map(|(s, l)| &record[5 + s..5 + s + l]),
            Some(name.as_bytes())
        );
        let settings = TlsFragment {
            enabled: true,
            min_bytes: 40,
            max_bytes: 200,
            delay_ms: 0,
        };
        for _ in 0..200 {
            let pieces = split_record(&record, &settings, &mut Shuffle::new());
            assert!(
                pieces
                    .iter()
                    .all(|p| !p.windows(name.len()).any(|w| w == name.as_bytes()))
            );
            let joined: Vec<u8> = pieces.iter().flat_map(|p| p[5..].to_vec()).collect();
            assert_eq!(joined, record[5..].to_vec());
        }
    }

    #[tokio::test]
    async fn disabled_or_non_tls_data_is_not_touched() {
        for (settings, data) in [
            (TlsFragment::default(), client_hello(300)),
            (
                TlsFragment {
                    enabled: true,
                    ..TlsFragment::default()
                },
                b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            ),
        ] {
            let (client, mut server) = tokio::io::duplex(1 << 16);
            let mut writer = FragmentWriter::new(client, settings);
            writer.write_all(&data).await.unwrap();
            writer.shutdown().await.unwrap();
            drop(writer);
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, data);
        }
    }

    #[test]
    fn settings_are_checked() {
        assert!(TlsFragment::default().validate().is_ok());
        for bad in [(0, 10), (20, 10), (1, 2000)] {
            let settings = TlsFragment {
                min_bytes: bad.0,
                max_bytes: bad.1,
                ..TlsFragment::default()
            };
            assert!(settings.validate().is_err());
        }
    }
}
