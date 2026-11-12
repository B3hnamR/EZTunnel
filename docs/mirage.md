# Mirage: Directional Spoof Carriers And Tester

**Start with the [guided workflow](mirage-guided.md)** in0.9.4: enter your spoof
IPs and test choices, share a temporary invitation, review saved results, then
create reciprocal tunnel settings without manually preparing JSON or keys. This
document retains the advanced packet/configuration and scripted-CLI reference.

Mirage v2 is opt-in experimental raw networking. It preserves the existing
Noise IK authentication, pinned identities, encryption, replay protection, mux,
and session rekeying. A packet's claimed IP address is never a credential.
Local root/CAP_NET_RAW access and a suitable Ethernet IPv4 route are required.
Provider/source filtering differs by address, protocol, direction and time.

## Compatibility

Existing `experimental-v1` TCP-only configurations retain their meaning.
`spoof_dst_ip` remains the old outgoing destination override; it is NOT renamed
into an expected receive-source field. New v2 requires `raw.mirage` and
`mirage_acknowledgement:"experimental-v2"`, and always routes to real `peer_ip`.
Do not configure `spoof_dst_ip` or legacy `proto58_mode` with v2. Ordinary
non-Mirage tunnels remain compatible with0.9.2. Both Mirage v2 endpoints must
run the new version and agree on directional profiles and shaping/repair contract.

## Profiles And Address Model

| Value | Outer IPv4 protocol | Wrapper |
|---|---:|---|
|`tcp`|6|TCP-looking header, not a real reliable TCP connection|
|`udp`|17|UDP header|
|`icmp`|1|ICMP echo header|
|`icmpv6`|58|Echo-shaped header inside IPv4, not outer IPv6|
|`gre`|47|Minimal GRE header before tunnel bytes|
|`ipip`|4|Tunnel bytes directly after outer IPv4|
|`bip` or `proto58`|58|Bare tunnel bytes, no echo header|

Bare BIP differs from both `icmpv6` and EZTunnel's older marker-based
`proto58_mode`. Existing ordinary `raw`253 and DNS-shaped profiles remain separate.

- Uplink means **foreign/client -> Iran/server**, regardless of physical dialing.
- Downlink means **Iran/server -> foreign/client**.
- `peer_ip` is always the real routing destination.
- `spoof_src_ip` selects one outgoing source, OR `mirage.source_pool` selects a
  bounded round-robin per-packet set. Do not configure both.
- `mirage.expected_sources` is an explicit receive-source allowlist. Empty means
  real `peer_ip`, not every address. It is independent from outgoing source.
- `allow_real_source:true` explicitly permits a direction to use its detected or
  configured real source instead of pretending all traffic must be spoofed.

Only use source addresses for which you have permission. A famous/domestic IP
is not inherently reachable. Normal replies addressed to a spoofed IP do not
automatically return to the sender; our reverse path still uses configured real
peer routing and independently selected transmit source/profile.

## Example Raw Entry

The following is an entry's `raw` object, not a complete tunnel configuration:

```json
{
  "profile":"udp",
  "interface":"eth0",
  "local_ip":"192.0.2.10",
  "peer_ip":"198.51.100.20",
  "l4_port":45670,
  "tcp_flags":"r",
  "mirage_acknowledgement":"experimental-v2",
  "mirage":{
    "uplink":"udp",
    "downlink":"icmp",
    "allow_real_source":true,
    "source_pool":[],
    "expected_sources":["203.0.113.30"],
    "echo_mode":"replies",
    "padding_max":0,
    "fake_tls":false
  }
}
```

The peer uses reciprocal real local/peer addresses and the same uplink/downlink
values. It transmits its permitted spoof source and expects this endpoint's
chosen transmit source. Example IPs above are documentation addresses, not working
public spoof candidates. Use a common private tunnel key in the enclosing config.

Echo modes are `split`(client request/server reply), `requests`, or `replies`.
The tester uses echo replies and TCP RST-shaped packets to avoid soliciting kernel
responses toward candidate addresses. Ordinary v2 reserves its unused UDP receive
port and claims bare raw protocols to avoid kernel unreachable replies. A port
conflict fails explicitly; no firewall/sysctl/route is modified automatically.
TCP/ICMP request traffic may still interact with host behavior: do not enable
request/SYN-style modes on live networks without understanding that side effect.

## Shaping, Source Pools And Redundancy

Optional `raw.mirage` fields:

| Field | Bounds / behavior |
|---|---|
|`source_pool`|0-64 explicit unicast IPv4 addresses; rotates per packet|
|`expected_sources`|0-64 explicit unicast IPv4 sources; empty pins real peer|
|`ttl`|1-255; absent retains existing profile default|
|`dscp`|0-63; absent retains existing profile default|
|`source_port_range`|`[first,last]`,1-256 nonprivileged ports; both ends agree|
|`padding_max`|0-256 random suffix bytes with bounded length header|
|`fake_tls`|Cosmetic TLS-like prefix, NOT a real TLS connection|
|`redundancy`|`{"data":6,"parity":2}`;1-16 data and1-4 repair shards|

Mirage admission authenticates the profile pair and a fingerprint of echo,
padding, fake-TLS, port-range and redundancy settings before replay commit.
It detects a matching-format authenticated disagreement; an entirely different
outer profile can still be filtered before decoding, so the tester is essential.
Admission MAC does not replace the inner Noise handshake/AEAD. The outer envelope
has boot randomness, a counter and a +/-30-second timestamp window; synchronize
host clocks. At most 64 boot replay windows remain, for 61 seconds.

Shaping/padding is within outer admission authentication; it is not a claim of
TLS camouflage effectiveness or additional plaintext confidentiality. Packet
budgets reserve the larger directional header,62-byte admission envelope, maximum
padding and repair overhead. Too little usable MTU fails clearly instead of
silently truncating. No automatic interface MTU or kernel IP fragmentation change.

Redundancy delivers originals immediately. A full group emits systematic Cauchy
GF256 repair shards; up to the configured parity count of missing shards can be
recovered if enough distinct shards arrive. Partial groups do not delay originals
waiting for repair. Receiver groups are bounded to 32 for 2 seconds; retired group IDs are
bounded to 8192 ranges for 32 seconds. Recovered payloads still pass the inner transport checks.
Existing KCP/FEC remains; extra redundancy costs bandwidth and CPU and should be
measured, not assumed faster. v2 rejects simultaneous legacy adaptive port hopping
to avoid conflicting source/admission ownership. Source-port shuffle is separate.

## Integrated Directional Tester

Manager: **Tools -> Mirage: directional spoof source tester**. It can create a
new private settings file, listen for one run, or send probes. Config files have
mode 0600/0400 and contain a shared tunnel key. Reports contain no tunnel key.
CLI equivalents:

```sh
# On the receiving host first:
sudo eztunnel spooftest listen --config /root/spooftest.json --bind 0.0.0.0:45671
# On the sending host:
sudo eztunnel spooftest run --config /root/spooftest.json \
  --peer REAL_RECEIVER_IP:45671 --output /root/spooftest-results.json
```

Settings format (use actual authorized addresses and a generated shared key):

```json
{
  "tunnel_key":"REPLACE_WITH_A_GENERATED_TUNNEL_KEY",
  "raw":{"interface":"eth0","local_ip":"192.0.2.10","peer_ip":"198.51.100.20","l4_port":45670},
  "candidates":["203.0.113.30","203.0.113.31"],
  "profiles":["tcp","udp","icmp","icmpv6","gre","ipip","bip"],
  "attempts":5,
  "delay_ms":150,
  "receive_ms":2000
}
```

Receiver settings must explicitly permit every requested candidate/profile.
Use reciprocal real local/peer addresses and the same raw port/key/list. Listening
is a bounded one-run authenticated control service, not a permanent public daemon.
No automatic CIDR sweep, candidate discovery or firewall opening. Limits: 64 sources,
7 profiles, 1-20 attempts, 50-5000 ms spacing, maximum 10-second receive window per case,
bounded session operations and lifetime. Use an unused port; conflicts are errors.

Repeat with roles reversed to measure the other direction. A row reports:
- `received/loss_percent`: unique authenticated packets accepted by the receiver's
  AF_PACKET/socket admission path. This does NOT prove ordinary kernel UDP-socket
  delivery or full application-tunnel health.
- `raw_reply_received/raw_reply_loss_percent`: explicit replies routed to the
  sender's REAL IP, not candidate address. Their loss can differ from one-way loss.
- `rtt_median_ms/rtt_p95_ms`: real received raw round trips; absent if none return.
- `error`: setup/admission errors, separate from zero packet receipt.

All zero-result candidates remain explicit rows. JSON is atomically replaced as
each case completes, private mode 0600, refusing symlink/nonregular destinations.
Control disconnect leaves completed rows; it is not a passed complete matrix.
No receipt cannot locate a drop at egress, transit, receiving provider or host.
Follow promising probe rows with an authenticated tunnel payload/reconnect/MTU/
long-running test. A5packet sample is not a stability score or capacity benchmark.

## XDP Status

`scripts/xdp/mirage-monitor.c` is a GPL-2.0-only BPF
**feasibility monitor**, not an application receive accelerator. It was tested
on disposable private veths: exact selector counting and XDP_PASS preserved
ordinary processing. No live NIC was attached. It is not automatically compiled,
loaded or attached by EZTunnel. The AGPL-3.0 application remains separate.

A production fast path requires audited ownership/detach, complete per-profile
selectors, fragment handling, bounded ring behavior and working socket fallback
under ring saturation, plus measured benefit. It is deliberately not advertised
as implemented by this release. Do not attach it to a live interface merely
because the isolated monitor loaded successfully.
