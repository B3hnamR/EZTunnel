#![cfg(target_os = "linux")]

use anyhow::Result;
use eztunnel::{
    config::TunConfig,
    tun_device::{TunDevice, validate_packet},
};

#[test]
fn ip_packet_boundaries_are_checked() {
    let mut ipv4 = vec![0u8; 20];
    ipv4[0] = 0x45;
    ipv4[3] = 20;
    assert!(validate_packet(&ipv4, 1400).is_ok());
    assert!(validate_packet(&ipv4, 19).is_err());
    ipv4[0] = 0x44;
    assert!(validate_packet(&ipv4, 1400).is_err());
    ipv4[0] = 0x45;
    ipv4[3] = 21;
    assert!(validate_packet(&ipv4, 1400).is_err());
    assert!(validate_packet(&[], 1400).is_err());
    let mut ipv6 = vec![0u8; 48];
    ipv6[0] = 0x60;
    ipv6[5] = 8;
    assert!(validate_packet(&ipv6, 1280).is_ok());
    ipv6[5] = 9;
    assert!(validate_packet(&ipv6, 1280).is_err());
    assert!(validate_packet(&ipv6[..30], 1280).is_err());
    ipv6[0] = 0x70;
    assert!(validate_packet(&ipv6, 1280).is_err());
}

#[tokio::test]
#[ignore = "requires Linux /dev/net/tun, iproute2 and CAP_NET_ADMIN"]
async fn creates_exclusive_interface_and_removes_it_on_drop() -> Result<()> {
    let name = format!("drt{}", std::process::id());
    let cfg = TunConfig {
        name: name.clone(),
        address: "198.18.254.1".into(),
        peer_address: "198.18.254.2".into(),
        mtu: 1400,
        forwarding_port: None,
        fragment: false,
        parity: false,
        mtu_probe: false,
    };
    let device = TunDevice::create(&cfg).await?;
    assert!(std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
    assert!(
        TunDevice::create(&cfg).await.is_err(),
        "must never attach to an existing interface"
    );
    assert!(std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
    drop(device);
    assert!(!std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
    Ok(())
}
