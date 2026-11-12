# Adaptive Paths And Gaming

All six additions are **opt-in**. Ordinary 0.9.0 Noise, mux and wire versions
1-3 remain unchanged. Old peers never receive unknown mux frames. Controller and
allocation are local scheduling; fallback, hopping and direct gaming require
both endpoints to be configured for the extension.

## Adaptive Controller And Shared Allocation

Under a FEC entry, `listeners[].fec` or `paths[].fec`:

```json
{"adaptive":{"enabled":true,"shared_bandwidth":true,"min_window":128,"max_window":4096,"min_rate":100000,"max_rate":500000000}}
```

Rates are bytes per second. The controller observes KCP first transmissions,
retransmissions, once-acknowledged payload bytes, RTT and queue occupancy, and
owns PUSH pacing, window and minimum RTO. ACKs remain unpaced. Do not combine it
with `pacer:true`, `tuner.mode:"auto"`, or `congestion_control:true`; configuration
validation rejects multiple owners. Shared allocation groups sessions by remote
IP and local binding/interface context, expires idle contributors and shares a
bounded path estimate among loaded members. This is not a BBR-equivalence claim.

## Authenticated TCP Packet Fallback

For raw FEC or Mirage entries, with a common tunnel key:

```json
{"tcp_fallback":{"address":"203.0.113.10:45000","idle_ms":1000,"handshake_sec":5}}
```

The listening endpoint uses its bind address, such as `0.0.0.0:45000`; the dialing
endpoint uses that server's reachable IP and port. Choose a separate unused TCP
port. A dedicated tunnel-key KDF label and Noise NNpsk0 domain authenticate the
outer lane. Encrypted records retain KCP/FEC packet boundaries, and the existing
inner Noise IK handshake still authenticates the tunnel. The mux is unchanged.

Raw packets are primary. After raw inactivity, a connected lane carries packets;
periodic raw probes permit return. Queues hold at most 256 packets, with maximum
packet size 2,048 bytes. Directional rekey occurs at 2^20 records and a fresh
handshake at 300 seconds. Partial I/O failure discards the lane. With the adaptive
controller enabled, lane-active minimum RTO is at least 600 ms to limit premature
nested retransmissions. TCP can introduce head-of-line blocking: this is a
reachability fallback, not a promised latency improvement.

## Adaptive Raw Ports

Under `raw`, for TCP/UDP raw FEC profiles:

```json
{"hopping":{"enabled":true,"first_port":40000,"last_port":40063,"retry_ms":1500}}
```

Both endpoints need the same bounded range of 1-256 nonprivileged ports and the
same tunnel key. A stalled path chooses a new pair. The authenticated envelope
binds boot randomness, counter, timestamp, source/destination ports and payload
using truncated HMAC-SHA256. Only authenticated fresh packets can update the
return ports. A 1,024-packet replay window and bounded boot table constrain state.
The timestamp window is +/-30 seconds, requiring reasonably synchronized clocks.

The MAC is admission, not payload confidentiality; inner Noise remains required.
The envelope adds 56 bytes, reserved in the FEC packet budget. Software port
admission is bounded; kernel capture remains pinned to peer IP/protocol. No
iptables/nftables rules are added automatically. The operator must ensure the
configured ports are reachable without interfering with other applications.

## Direct Gaming Datagrams And UDP Migration

Top-level configuration, alongside existing UDP maps or SOCKS:

```json
{"gaming":{"control_address":"203.0.113.10:45001","udp_bind":"0.0.0.0:45002","advertise":"203.0.113.10:45002","migrate":true,"mtu":1200,"renewal_sec":300,"max_flows":1024}}
```

The logical server binds `control_address`; the logical client connects to it.
Each host selects its own UDP bind and advertised address. A separate Noise IK
domain authenticates the existing static identities and mutually negotiates
version, direct/migration capability, MTU and UDP address. The advertised UDP IP
must match the authenticated TCP peer's observed IP, preventing arbitrary
third-party reflection. A new UDP path must answer an encrypted challenge before
outbound application use.

NATs that do not preserve ports require an explicit known advertised mapping.
There is no unauthenticated discovery or arbitrary IP rebinding. This extension
supports forwarding/SOCKS UDP, not TUN mode; TUN retains its existing encrypted
datagram transport.

Channel AEAD keys derive from fresh Noise secrets and transcript, never a static
PSK reused as traffic keys. The 1,024-packet replay window commits only after
authentication. Keys expire at 360 seconds; fresh negotiated handshakes occur at
5-300 seconds, default 300. Stable 128-bit flow IDs, generations and cross-channel
packet sequences reject stale/duplicate traffic. The destination UDP socket stays
alive across channel replacement. Target allowlists use ordinary mux rules.

New flows select direct mode only after the path is ready; flows that began on
the reliable mux stay there. During a direct-path outage, UDP drops rather than
silently opening a different destination socket. These datagrams are intentionally
unreliable and unordered; no lossless-delivery guarantee is added.

The existing 16 KiB user-payload limit remains. Larger-than-MTU messages use
authenticated fragments: at most 128 pieces, 17,500 serialized bytes, 16 partial
groups per channel, and a 2-second TTL. Nested fragments are rejected. Losing one
fragment loses the datagram; there is no fragment retransmission. Queue limits
are 16 MiB aggregate queued payload per process, 32 packets per flow, and 16
channels, with at most two older channels plus the newest per peer. Closed-flow
tombstones last 361 seconds. `max_flows` accepts 1-4,096. Resource accounting also
includes one consumer-owned packet per flow and bounded reassembly/control state.

### Explicit Local Rebinding

The existing private Unix control socket accepts:

```json
{"cmd":"gaming-rebind","bind":"0.0.0.0:45003","advertise":"203.0.113.10:45003"}
```

This local administrative action rebinds the UDP socket, retains flow identities,
invalidates old outbound readiness and requires fresh authenticated control and
UDP challenge. It requires migration enabled, and still does not change firewall
rules. Handover can briefly interrupt delivery. It is not transparent migration
to a new unverified IP or automatic NAT traversal.

Status includes `transport_extensions` counters for validated channels, migrated
flows, fragment reassembly, rejected packets, TCP packet lanes and raw port changes.

## Manager And Pairing

Use **Manage tunnels -> Change settings -> Adaptive paths and gaming**. Existing
rendering, navigation and other menus are retained. Extension endpoints are local
to each host. Pairing export refuses enabled gaming/fallback/hopping instead of
silently producing an incomplete opposite-end configuration. Configure the other
endpoint explicitly using this document. Default 0.9.0 pairing is unchanged.

## Validation Limits

Functional tests do not establish WAN losslessness, optimal throughput, or an
independent cryptographic audit.
Live tests are bounded and rate-capped, not production-link saturation tests.
