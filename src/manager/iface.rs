//! Facts about the network interface the tunnel's packets leave from.
use super::plan::RawPlan;
use crate::raw_packet::RawProfile;
use std::net::Ipv4Addr;

/// What the tunnel adds to every IP packet it carries inside a raw packet (header, nonce,
/// authentication tag).
#[cfg(target_os = "linux")]
const TUNNEL_OVERHEAD: usize = crate::raw_tun::DATAGRAM_OVERHEAD;
#[cfg(not(target_os = "linux"))]
const TUNNEL_OVERHEAD: usize = 47;

/// The ordinary TUN MTU, used whenever the interface leaves room for it.
pub const DEFAULT_TUN_MTU: u16 = 1400;

/// Smallest MTU the TUN device accepts.
const SMALLEST_TUN_MTU: usize = 576;

/// The interface the packets to `peer` leave from, and its MTU. `interface` forces a choice.
pub fn outgoing_interface(
    peer: Option<Ipv4Addr>,
    interface: Option<&str>,
) -> Option<(String, u32)> {
    let name = match interface {
        Some(name) => name.to_string(),
        None => route_device(peer)?,
    };
    let mtu = std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some((name, mtu))
}

/// The device a route to `peer` (or the default route) uses.
fn route_device(peer: Option<Ipv4Addr>) -> Option<String> {
    if let Some(peer) = peer {
        let output = std::process::Command::new("ip")
            .args(["-j", "route", "get", &peer.to_string()])
            .output()
            .ok()?;
        if output.status.success()
            && let Ok(routes) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
            && let Some(device) = routes[0]["dev"].as_str()
        {
            return Some(device.to_string());
        }
    }
    default_route_device(&std::fs::read_to_string("/proc/net/route").ok()?)
}

/// The device of the default route in the text of `/proc/net/route`.
fn default_route_device(table: &str) -> Option<String> {
    table.lines().skip(1).find_map(|line| {
        let mut columns = line.split_whitespace();
        let device = columns.next()?;
        (columns.next()? == "00000000").then(|| device.to_string())
    })
}

/// The largest TUN MTU that fits through an interface with MTU `interface_mtu` when the tunnel
/// packets look like `profile` (an IPv4 header, the profile's own header, then the tunnel's
/// overhead), but never more than the ordinary default: the interface cannot say what the rest
/// of the path allows, so it can only lower the value.
pub fn tun_mtu_for(interface_mtu: u32, profile: RawProfile) -> u16 {
    let room = room_for_tun(interface_mtu, profile.header_len()).max(SMALLEST_TUN_MTU);
    room.min(usize::from(DEFAULT_TUN_MTU)) as u16
}

/// The largest IP packet a raw tunnel can carry through an interface with this MTU when the
/// outer packet has a `header_len`-byte header after the IPv4 header. The raw TUN carrier
/// refuses to start with a larger TUN MTU.
fn room_for_tun(interface_mtu: u32, header_len: usize) -> usize {
    (interface_mtu as usize).saturating_sub(20 + header_len + TUNNEL_OVERHEAD)
}

/// For a saved raw TUN tunnel (its `raw` settings): the largest TUN MTU that fits, with the
/// interface and interface MTU it is based on. `None` when the interface cannot be found.
pub fn max_tun_mtu(raw: &serde_json::Value) -> Option<(usize, String, u32)> {
    let profile: RawProfile = serde_json::from_value(raw.get("profile")?.clone()).ok()?;
    let peer: Ipv4Addr = raw.get("peer_ip")?.as_str()?.parse().ok()?;
    let proto58 = raw
        .get("proto58_mode")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let header = if proto58 { 4 } else { profile.header_len() };
    let (name, mtu) =
        outgoing_interface(Some(peer), raw.get("interface").and_then(|v| v.as_str()))?;
    Some((room_for_tun(mtu, header), name, mtu))
}

/// The TUN MTU to propose for a raw tunnel to `peer`, with the interface and MTU it is based on.
pub fn suggested_tun_mtu(
    peer: Option<Ipv4Addr>,
    interface: Option<&str>,
    profile: RawProfile,
) -> Option<(u16, String, u32)> {
    let (name, mtu) = outgoing_interface(peer, interface)?;
    Some((tun_mtu_for(mtu, profile), name, mtu))
}

/// The TUN MTU for the raw settings of a plan, with the interface and MTU it is based on.
pub fn plan_tun_mtu(raw: &RawPlan) -> Option<(u16, String, u32)> {
    let profile: RawProfile = serde_json::from_value(serde_json::json!(raw.profile)).ok()?;
    suggested_tun_mtu(Some(raw.peer_ip), raw.interface.as_deref(), profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_interface_keeps_the_default_and_a_small_one_lowers_it() {
        for profile in [
            RawProfile::Tcp,
            RawProfile::Udp,
            RawProfile::Icmp,
            RawProfile::Gre,
            RawProfile::Ipip,
            RawProfile::Raw,
        ] {
            assert_eq!(tun_mtu_for(1500, profile), 1400, "{profile:?}");
            assert_eq!(tun_mtu_for(9000, profile), 1400, "{profile:?}");
        }
        // 1400 - IPv4 header (20) - TCP header (20) - tunnel overhead (47)
        assert_eq!(tun_mtu_for(1400, RawProfile::Tcp), 1400 - 87);
        assert_eq!(tun_mtu_for(1400, RawProfile::Ipip), 1400 - 67);
        assert_eq!(tun_mtu_for(1400, RawProfile::Gre), 1400 - 71);
        // The dns disguise's larger envelope (59 bytes) does not leave room for the default TUN
        // MTU on an ordinary 1500-byte interface, unlike the other profiles above; a larger
        // interface (9000) still reaches it, same as them.
        assert_eq!(tun_mtu_for(1500, RawProfile::Dns), 1500 - 20 - 59 - 47);
        assert_eq!(tun_mtu_for(9000, RawProfile::Dns), 1400);
        // 1400 - IPv4 header (20) - DNS disguise header (59) - tunnel overhead (47)
        assert_eq!(tun_mtu_for(1400, RawProfile::Dns), 1400 - 126);
        // Never below what the TUN device accepts.
        assert_eq!(tun_mtu_for(300, RawProfile::Tcp), 576);
        assert_eq!(tun_mtu_for(0, RawProfile::Tcp), 576);
    }

    #[test]
    fn the_proposed_mtu_always_fits_the_raw_socket_limit() {
        // raw_tun refuses a TUN MTU above the interface MTU minus the IPv4 header, the profile
        // header and the tunnel overhead, so every proposal must stay inside that limit.
        for interface in [1280u32, 1400, 1500, 1492, 9000] {
            for profile in [
                RawProfile::Tcp,
                RawProfile::Icmp,
                RawProfile::Gre,
                RawProfile::Dns,
            ] {
                let proposed = usize::from(tun_mtu_for(interface, profile));
                let limit = (interface as usize).saturating_sub(20 + profile.header_len() + 47);
                assert!(proposed <= limit.max(576), "{interface} {profile:?}");
            }
        }
    }

    #[test]
    fn the_largest_fitting_mtu_is_not_capped_at_the_default() {
        assert_eq!(room_for_tun(1500, 20), 1500 - 87);
        assert_eq!(room_for_tun(1400, 4), 1400 - 71);
        assert_eq!(room_for_tun(80, 20), 0);
        assert!(
            max_tun_mtu(&serde_json::json!({"profile": "nonsense", "peer_ip": "192.0.2.1"}))
                .is_none()
        );
        assert!(max_tun_mtu(&serde_json::json!({"profile": "tcp"})).is_none());
    }

    #[test]
    fn the_default_route_is_found_in_the_kernel_table() {
        let table =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        assert_eq!(default_route_device(table).as_deref(), Some("eth0"));
        assert_eq!(default_route_device("Iface\tDestination\n"), None);
        assert_eq!(default_route_device(""), None);
    }
}
