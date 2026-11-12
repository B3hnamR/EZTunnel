# Raw TUN datagrams


The `tun` carrier sends individual IP packets over a Linux packet socket. Its outer IPv4 profiles are TCP camouflage, UDP, ICMP, GRE, IP-in-IP, protocol 253 raw packets, and DNS-disguised UDP (see `raw-protocol.md`). proto58 mode uses IPv4 protocol 58 with a fixed 4-byte marker. Optional source/destination spoof addresses and next-hop MAC settings are local configuration. Interface discovery uses `iproute2` and ARP on the selected interface.

This carrier preserves unreliable datagram delivery: losing one packet does not block later packets, and packet reordering is allowed. `fec-raw` and `fec-udp` provide a separate KCP/FEC transport for reliable streams.

Peer authentication uses locally pinned X25519 keys and `Noise_IK_25519_ChaChaPoly_BLAKE2s`, with the raw domain and HKDF derivation specified in [protocol.md](protocol.md). Both endpoints must run 0.9.0 or a compatible newer protocol version. Shared tunnel keys or explicit per-endpoint identities remain supported.

Raw sessions renew with a fresh handshake after 300 seconds and refuse old-session
encryption/decryption after 360 seconds. Optional `tun.parity` provides bounded
authenticated2+1 XOR recovery and is bound into the Noise prologue. Optional
`tun.mtu_probe` echoes authenticated challenges to report an advisory capacity;
it does not automatically change interface MTU. These are ordinary session and
packet features.

Each packet begins five magic/version bytes (`EZTU` followed by `01`) and a one-byte message kind. An initial Noise message has kind 1. Its response has kind 2, the first 16 bytes of the initiator's first Noise message as an identifier, and the second Noise message. The initiator retransmits the same initial message once per second until it receives an authenticated response; a timed-out attempt starts a new Noise handshake with fresh ephemeral keys.

Transport packets have kind 3, a 16-byte session identifier from the completed Noise handshake hash, and a 64-bit big-endian nonce. The following ciphertext authenticates one payload kind (1 IP, 2 ping, 3 pong, 4 goodbye, 5 IP fragment) and its contents. Directional Noise keys and a fresh handshake make counters independent in each direction. A 256-packet replay window accepts reordered packets and rejects duplicates or packets older than the window. The receiver advances this window only after successful AEAD authentication, so a forged high nonce cannot invalidate real traffic.

**Goodbye and recovery (0.8.5).** A side that stops sends the goodbye payload (kind 4, no contents) three times, 30 ms apart, on its active session; the receiver forgets the session at once and the client starts a new handshake, so a restart costs about a second instead of `dead_timeout_sec`. A receiver older than 0.8.5 rejects the unknown kind after authenticating it and leaves the session alone. After a crash (no goodbye) the client notices that its pings go unanswered: after `timeouts.probe_sec` it pings every second, after twice that it starts a new handshake while keeping the old session, and the new session replaces it as soon as the server answers.

The responder keeps one active session and one pending candidate. A candidate becomes active after its first authenticated transport datagram; replaying an old initial handshake therefore cannot directly evict an active peer. The latest handshake response is cached for retransmission. Authenticated heartbeat silence for `dead_timeout_sec` ends the session and causes the client to establish fresh keys.

The plaintext inner IP packet plus authentication framing adds 47 bytes to the raw envelope. At startup, the core checks `tun.mtu <= raw-interface-payload-capacity - 47`. MTU 1400 fits a 1500-byte Ethernet interface with the default TCP profile. A smaller physical MTU requires a smaller TUN MTU; the core rejects an oversize configuration rather than silently fragmenting an encrypted packet.

**Fragmentation (0.8.11, `tun.fragment`).** Off by default, matching the behaviour above. When set, `tun.mtu` may exceed the single-packet limit: an inner IP packet bigger than one raw envelope leaves as several kind-5 pieces (a 2-byte fragment id, a 1-byte index, a 1-byte count, then a slice of the original packet), up to 64 pieces, and the far side rebuilds the original packet once every piece has arrived. An incomplete packet is dropped after 2 seconds, and at most 256 incomplete packets are kept at once (the oldest is dropped to make room for a new one), so a lost or never-completed piece costs bounded memory, not a stall. This exists for traffic whose own packets are bigger than the chosen raw profile's single-packet budget (a 1420-byte inner MTU, for example) without lowering the TUN MTU; it is not the default because relying on it costs an extra packet exchange per oversized datagram and, unlike the unfragmented path, a single lost piece loses the whole packet instead of nothing being sent too large to begin with.

There is one configured raw peer per service. The service requires `/dev/net/tun`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `iproute2`, and an Ethernet or veth interface. The nonpersistent TUN interface disappears when its process closes the descriptor. Raw socket setup does not change default routes, sysctls, firewall rules, or neighbour entries.

## Port forwarding and SOCKS alongside IP packets

Set the same optional `tun.forwarding_port` on both peers to run TCP/UDP maps and SOCKS5 CONNECT while the TUN continues to carry IP packets. The port must be 1024–65535; it has no automatic default. For example, `"forwarding_port": 47475` starts the server's inner TCP listener on its configured `tun.address`. The client dials its own `tun.peer_address`, which must equal the server's `tun.address`, at that port over the TUN's explicit peer route. The inner listener never binds a wildcard or physical underlay address.

The normal forwarding engine then authenticates a second Noise session with the same local identities and pinned/allowed public keys. Existing `listeners[].maps`, server `socks5`, client `allowed_targets`, heartbeat and retry settings apply. Only configured targets are permitted; an empty allowlist denies forwarding destinations. The outer TUN remains an independent authenticated packet carrier. The inner TCP relay supplies reliable, ordered delivery for the forwarded records, while unrelated TUN IP traffic retains normal datagram delivery. The additional TCP/Noise layer has bandwidth and memory overhead.

Use [server-tun-forwarding.json](../examples/server-tun-forwarding.json) and [client-tun-forwarding.json](../examples/client-tun-forwarding.json) as a pair, exchanging public keys and replacing the example underlay addresses. The example maps reach services on the client's loopback interface. SOCKS requests share the same target allowlist. For IPv6 inner TUN addresses, the relay uses bracketed IPv6 endpoints automatically. The core configures only its owned TUN address and peer route; it does not enable host forwarding, add NAT rules, or change default routes.

Without `forwarding_port`, the TUN remains packet-only and maps/SOCKS/target allowlists are rejected. A TCP map or SOCKS bind must not collide with the server's inner relay address and port. A mismatched port on the two peers leaves the inner forwarding connection unavailable even when IP tunneling works.


Unit tests exercise datagram loss and reordering, duplicate rejection, malformed nonce authentication, and replay-window boundaries. The privileged local namespace harness exercises actual packet sockets and TUN interfaces; consult the release test report for the completed runs and their limits.

`sudo bash tests/tun_forwarding_vm.sh target/release/eztunnel` exercises IPv4/IPv6 TUN packets together with TCP/UDP maps, SOCKS, large half-close transfers, actual inner identity rejection, target denial, server restart and interface cleanup. The test observes that the inner listener binds the selected TUN address. Its presence here describes test coverage; only the release test report establishes that a particular executable passed it.
