//! The check code: what the joining server needs, in one line to copy (`ezc1-…`). It holds a fresh
//! key for this check only (the control link and every test tunnel are authenticated with it),
//! both servers' addresses and the chosen options.
use super::{Options, Side};
use crate::tunnel_key::TunnelKey;
use anyhow::{Context, Result, ensure};
use base64::Engine;
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const PREFIX: &str = "ezc1-";
const CHECK_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckCode {
    pub key: String,
    /// The server that started the check.
    pub starter: Side,
    pub iran_ip: IpAddr,
    pub foreign_ip: IpAddr,
    pub options: Options,
}

impl CheckCode {
    pub fn new(
        starter: Side,
        iran_ip: IpAddr,
        foreign_ip: IpAddr,
        options: Options,
    ) -> Result<Self> {
        Ok(Self {
            key: TunnelKey::generate()?.display(),
            starter,
            iran_ip,
            foreign_ip,
            options,
        })
    }

    pub fn ip(&self, side: Side) -> IpAddr {
        match side {
            Side::Iran => self.iran_ip,
            Side::Foreign => self.foreign_ip,
        }
    }
}

fn checksum(json: &[u8]) -> [u8; CHECK_BYTES] {
    let digest = Blake2s256::new()
        .chain_update(b"eztunnel check code v1\0")
        .chain_update(json)
        .finalize();
    let mut check = [0u8; CHECK_BYTES];
    check.copy_from_slice(&digest[..CHECK_BYTES]);
    check
}

pub fn encode(code: &CheckCode) -> Result<String> {
    let mut bytes = serde_json::to_vec(code)?;
    let check = checksum(&bytes);
    bytes.extend_from_slice(&check);
    Ok(format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    ))
}

pub fn decode(text: &str) -> Result<CheckCode> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let body = text
        .strip_prefix(PREFIX)
        .context("this is not a check code (they start with ezc1-)")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .ok()
        .filter(|bytes| bytes.len() > CHECK_BYTES)
        .context("the check code is damaged or incomplete; copy it again")?;
    let (json, check) = bytes.split_at(bytes.len() - CHECK_BYTES);
    ensure!(
        checksum(json) == check,
        "the check code is damaged or incomplete; copy it again"
    );
    let code: CheckCode =
        serde_json::from_slice(json).context("the check code comes from a newer EZTunnel")?;
    TunnelKey::parse(&code.key).context("the check code holds an invalid key")?;
    code.options.validate()?;
    ensure!(
        code.iran_ip != code.foreign_ip,
        "the check code names the same address for both servers"
    );
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_damage() {
        let code = CheckCode::new(
            Side::Foreign,
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            Options::default(),
        )
        .unwrap();
        let text = encode(&code).unwrap();
        assert!(text.starts_with("ezc1-"));
        assert_eq!(decode(&text).unwrap(), code);
        // Line breaks from a terminal are ignored; a changed character is caught.
        let wrapped = format!("{}\n  {}", &text[..30], &text[30..]);
        assert_eq!(decode(&wrapped).unwrap(), code);
        let mut damaged = text.into_bytes();
        let last = damaged.len() - 3;
        damaged[last] = if damaged[last] == b'A' { b'B' } else { b'A' };
        assert!(decode(&String::from_utf8(damaged).unwrap()).is_err());
        assert!(decode("ezt1-abc").is_err());
    }
}
