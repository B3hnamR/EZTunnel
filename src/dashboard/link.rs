//! The encrypted link between the dashboard (hub) and the agents on other servers.
//!
//! An agent opens the dashboard's HTTPS port, asks to switch the connection to this link, and then
//! runs Noise IK over it: the agent knows the hub's key from its join code, the hub learns the
//! agent's key and admits it if it is registered (or if its first message carries a valid one-time
//! join token). The prologue is this link's own, so these handshakes can never be mistaken for a
//! tunnel's. Messages are JSON, split over Noise records.
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use snow::{Builder, StatelessTransportState};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

/// Bound to this link only; tunnels use their own prologues.
pub const PROLOGUE: &[u8] = b"eztunnel/open-source/dashboard-agent/v1";
/// The HTTP `Upgrade` value an agent asks for.
pub const UPGRADE: &str = "eztunnel-agent";
const PATTERN: &str = crate::transport::NOISE_PATTERN;
/// Largest Noise message; a record carries up to this much plaintext minus the tag and a flag.
const RECORD: usize = 65_535;
const TAG: usize = 16;
const CHUNK: usize = RECORD - TAG - 1;
/// Largest JSON message accepted (a snapshot of many tunnels, a batch of log lines).
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;

pub fn generate_keypair() -> Result<([u8; 32], [u8; 32])> {
    let pair = Builder::new(PATTERN.parse()?).generate_keypair()?;
    let private: [u8; 32] = pair.private.as_slice().try_into().context("key size")?;
    let public: [u8; 32] = pair.public.as_slice().try_into().context("key size")?;
    Ok((private, public))
}

async fn read_record(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let length = reader.read_u16().await? as usize;
    let mut buffer = vec![0; length];
    reader.read_exact(&mut buffer).await?;
    Ok(buffer)
}

async fn write_record(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<()> {
    ensure!(data.len() <= RECORD, "record too large");
    let mut framed = Vec::with_capacity(data.len() + 2);
    framed.extend_from_slice(&(data.len() as u16).to_be_bytes());
    framed.extend_from_slice(data);
    writer.write_all(&framed).await?;
    writer.flush().await?;
    Ok(())
}

/// Sends messages; one per link, owned by one task.
pub struct LinkWriter<S> {
    io: WriteHalf<S>,
    state: Arc<StatelessTransportState>,
    nonce: u64,
}

/// Receives messages; one per link, owned by one task.
pub struct LinkReader<S> {
    io: ReadHalf<S>,
    state: Arc<StatelessTransportState>,
    nonce: u64,
}

impl<S: AsyncWrite> LinkWriter<S> {
    pub async fn send(&mut self, message: &Value) -> Result<()> {
        let bytes = serde_json::to_vec(message)?;
        ensure!(bytes.len() <= MAX_MESSAGE, "message too large");
        // An empty message is still one record.
        let parts: Vec<&[u8]> = if bytes.is_empty() { vec![&[]] } else { bytes.chunks(CHUNK).collect() };
        let mut output = vec![0; RECORD];
        for (index, part) in parts.iter().enumerate() {
            let mut plain = Vec::with_capacity(part.len() + 1);
            plain.push(u8::from(index + 1 < parts.len()));
            plain.extend_from_slice(part);
            let n = self.state.write_message(self.nonce, &plain, &mut output)?;
            self.nonce += 1;
            write_record(&mut self.io, &output[..n]).await?;
        }
        Ok(())
    }
}

impl<S: AsyncRead> LinkReader<S> {
    /// Must be polled to completion. Callers selecting on other work must own this reader in
    /// a dedicated task and select on its completed-message channel instead.
    pub async fn recv(&mut self) -> Result<Value> {
        let mut message = Vec::new();
        let mut plain = vec![0; RECORD];
        loop {
            let record = read_record(&mut self.io).await?;
            let n = self
                .state
                .read_message(self.nonce, &record, &mut plain)
                .context("damaged or forged agent message")?;
            self.nonce += 1;
            ensure!(n >= 1, "empty agent record");
            message.extend_from_slice(&plain[1..n]);
            ensure!(message.len() <= MAX_MESSAGE, "agent message too large");
            if plain[0] == 0 {
                break;
            }
        }
        serde_json::from_slice(&message).context("unreadable agent message")
    }
}

fn split<S: AsyncRead + AsyncWrite>(stream: S, state: StatelessTransportState) -> (LinkReader<S>, LinkWriter<S>) {
    let state = Arc::new(state);
    let (read, write) = tokio::io::split(stream);
    (
        LinkReader { io: read, state: state.clone(), nonce: 0 },
        LinkWriter { io: write, state, nonce: 0 },
    )
}

/// The agent's side: proves it holds `private` and that the other end holds `hub_public`.
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    private: &[u8; 32],
    hub_public: &[u8; 32],
) -> Result<(LinkReader<S>, LinkWriter<S>)> {
    let mut handshake = Builder::new(PATTERN.parse()?)
        .local_private_key(private)?
        .remote_public_key(hub_public)?
        .prologue(PROLOGUE)?
        .build_initiator()?;
    let mut output = vec![0; RECORD];
    let n = handshake.write_message(&[], &mut output)?;
    write_record(&mut stream, &output[..n]).await?;
    let answer = read_record(&mut stream).await?;
    handshake
        .read_message(&answer, &mut output)
        .context("the dashboard did not prove its key; is this the right join code?")?;
    ensure!(handshake.is_handshake_finished(), "incomplete agent handshake");
    Ok(split(stream, handshake.into_stateless_transport_mode()?))
}

/// The hub's side: returns the agent's public key; the caller decides whether it is admitted.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    private: &[u8; 32],
) -> Result<(LinkReader<S>, LinkWriter<S>, [u8; 32])> {
    let mut handshake = Builder::new(PATTERN.parse()?)
        .local_private_key(private)?
        .prologue(PROLOGUE)?
        .build_responder()?;
    let request = read_record(&mut stream).await?;
    let mut output = vec![0; RECORD];
    ensure!(handshake.read_message(&request, &mut output)? == 0, "unexpected agent handshake payload");
    let peer: [u8; 32] = handshake
        .get_remote_static()
        .context("agent without a key")?
        .try_into()
        .context("agent key size")?;
    let n = handshake.write_message(&[], &mut output)?;
    write_record(&mut stream, &output[..n]).await?;
    ensure!(handshake.is_handshake_finished(), "incomplete agent handshake");
    let (reader, writer) = split(stream, handshake.into_stateless_transport_mode()?);
    Ok((reader, writer, peer))
}

/// What a join code carries: where the hub is, the key it proves, and a one-time token.
#[derive(Debug, Clone, PartialEq)]
pub struct JoinCode {
    pub host: String,
    pub port: u16,
    pub hub_key: [u8; 32],
    pub token: [u8; 16],
}

const CODE_PREFIX: &str = "ezj1-";

impl JoinCode {
    pub fn encode(&self) -> String {
        use base64::Engine;
        let mut bytes = Vec::with_capacity(32 + 16 + 2 + self.host.len());
        bytes.extend_from_slice(&self.hub_key);
        bytes.extend_from_slice(&self.token);
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes.extend_from_slice(self.host.as_bytes());
        format!("{CODE_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(text: &str) -> Result<Self> {
        use base64::Engine;
        let Some(body) = text.trim().strip_prefix(CODE_PREFIX) else {
            bail!("this is not a join code (it starts with {CODE_PREFIX})");
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .context("the join code is damaged; copy it again")?;
        ensure!(bytes.len() > 50 && bytes.len() <= 50 + 253, "the join code is damaged; copy it again");
        let host = String::from_utf8(bytes[50..].to_vec()).context("the join code is damaged")?;
        ensure!(
            host.chars().all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c)),
            "the join code names an invalid address"
        );
        Ok(Self {
            hub_key: bytes[..32].try_into()?,
            token: bytes[32..48].try_into()?,
            port: u16::from_be_bytes([bytes[48], bytes[49]]),
            host,
        })
    }

    /// `host:port`, with brackets for an IPv6 address.
    pub fn address(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn both_ends_prove_their_keys_and_exchange_messages() {
        let (hub_private, hub_public) = generate_keypair().unwrap();
        let (agent_private, agent_public) = generate_keypair().unwrap();
        let (a, b) = tokio::io::duplex(1 << 20);
        let hub = tokio::spawn(async move { accept(b, &hub_private).await.unwrap() });
        let (mut agent_rx, mut agent_tx) = connect(a, &agent_private, &hub_public).await.unwrap();
        let (mut hub_rx, mut hub_tx, seen) = hub.await.unwrap();
        assert_eq!(seen, agent_public);
        agent_tx.send(&json!({"type": "hello", "host": "frankfurt-1"})).await.unwrap();
        assert_eq!(hub_rx.recv().await.unwrap()["host"], "frankfurt-1");
        // A message larger than one record, and an empty one, both arrive whole.
        let big = json!({"lines": vec!["x".repeat(1000); 300]});
        hub_tx.send(&big).await.unwrap();
        hub_tx.send(&json!({})).await.unwrap();
        assert_eq!(agent_rx.recv().await.unwrap(), big);
        assert_eq!(agent_rx.recv().await.unwrap(), json!({}));
    }

    #[tokio::test]
    async fn an_agent_with_the_wrong_hub_key_is_refused() {
        let (hub_private, _) = generate_keypair().unwrap();
        let (_, other_public) = generate_keypair().unwrap();
        let (agent_private, _) = generate_keypair().unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let _ = accept(b, &hub_private).await;
        });
        assert!(connect(a, &agent_private, &other_public).await.is_err());
    }

    #[tokio::test]
    async fn a_tampered_record_is_rejected() {
        let (hub_private, hub_public) = generate_keypair().unwrap();
        let (agent_private, _) = generate_keypair().unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        let hub = tokio::spawn(async move { accept(b, &hub_private).await.unwrap() });
        let (_, mut agent_tx) = connect(a, &agent_private, &hub_public).await.unwrap();
        let (mut hub_rx, _, _) = hub.await.unwrap();
        // Send a correct message, then raw garbage in place of the next record.
        agent_tx.send(&json!({"ok": 1})).await.unwrap();
        assert_eq!(hub_rx.recv().await.unwrap()["ok"], 1);
        write_record(&mut agent_tx.io, &[7u8; 40]).await.unwrap();
        assert!(hub_rx.recv().await.is_err());
    }

    #[test]
    fn join_codes_round_trip_and_reject_damage() {
        let code = JoinCode { host: "203.0.113.10".into(), port: 38_471, hub_key: [9; 32], token: [4; 16] };
        let text = code.encode();
        assert!(text.starts_with("ezj1-"));
        assert_eq!(JoinCode::decode(&text).unwrap(), code);
        assert_eq!(JoinCode::decode(&format!("  {text}\n")).unwrap().address(), "203.0.113.10:38471");
        assert!(JoinCode::decode("hello").is_err());
        assert!(JoinCode::decode(&text[..text.len() - 20]).is_ok_and(|c| c != code) || JoinCode::decode(&text[..text.len() - 20]).is_err());
        let v6 = JoinCode { host: "2001:db8::5".into(), ..code.clone() };
        assert_eq!(JoinCode::decode(&v6.encode()).unwrap().address(), "[2001:db8::5]:38471");
        let bad = JoinCode { host: "evil.example;rm -rf /".into(), ..code };
        assert!(JoinCode::decode(&bad.encode()).is_err(), "only address characters");
    }
}
