//! Explicit experimental spoofed-IPv4 carrier policy, separate from legacy raw options.
use crate::raw_packet::{RawOptions, RawProfile};
use anyhow::{Context, Result, ensure};

pub const DISCLAIMER: &str = "Mirage is an experimental transport that uses raw IPv4 packets with explicitly configured spoofed addresses. It is intended for controlled testing on systems and networks you own or are authorized to use.\n\nOperation is not guaranteed and may cause connectivity failures or violate your network provider's policies. You are responsible for your configuration, authorization, and use. To the extent permitted by applicable law, the EZTunnel project and its maintainers disclaim liability for loss, disruption, or other consequences arising from its use.\n\nBy continuing, you acknowledge these limitations and accept the associated risks.";
pub const ACCEPT: &str = "I Accept and Continue";
pub const BACK: &str = "Back";
pub const ACK: &str = "experimental-v1";

pub fn validate(raw: Option<&RawOptions>) -> Result<()> {
    let raw = raw.context("Mirage requires raw configuration")?;
    raw.validate()?;
    if let Some(spec)=&raw.mirage {return spec.validate(raw);}
    ensure!(
        raw.mirage_acknowledgement.as_deref() == Some(ACK),
        "Mirage requires explicit experimental-v1 risk acknowledgement"
    );
    ensure!(
        raw.profile == RawProfile::Tcp,
        "Mirage v1 requires the TCP-looking raw profile"
    );
    ensure!(!raw.proto58_enabled(), "Mirage cannot use proto58");
    let source = raw
        .spoof_src_ip
        .context("Mirage requires an explicit spoof_src_ip; no unspoofed fallback")?;
    ensure!(
        raw.local_ip != Some(source),
        "Mirage spoof_src_ip must differ from the real local_ip"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_missing_consent_or_unspoofed_fallback() {
        let mut raw = RawOptions {
            peer_ip: "192.0.2.2".parse().unwrap(),
            ..RawOptions::default()
        };
        assert!(validate(Some(&raw)).is_err());
        raw.mirage_acknowledgement = Some(ACK.into());
        assert!(validate(Some(&raw)).is_err());
        raw.spoof_src_ip = Some("198.51.100.1".parse().unwrap());
        assert!(validate(Some(&raw)).is_ok());
        raw.local_ip = raw.spoof_src_ip;
        assert!(validate(Some(&raw)).is_err());
        raw.local_ip = None;
        raw.proto58_mode = true;
        assert!(validate(Some(&raw)).is_err());
        raw.proto58_mode = false;
        raw.profile = RawProfile::Udp;
        assert!(validate(Some(&raw)).is_err());
    }
}
