# Architecture


Normally the client establishes outbound connections to one or more server paths. A carrier supplies an ordered byte stream: TCP, IPv6 TCP, KCP, HTTP upgrade, WebSocket, XHTTP bodies, or FEC KCP/FEC. With `server_dials` (a *direct* tunnel in the manager) the server connects to the client instead, over any carrier except the raw ones; the authentication and forwarding roles stay the same. TLS verifies the listening side's certificate first (with `tls_auto`, a certificate derived from the tunnel key and pinned by the dialer). Noise IK authenticates both static peer identities and encrypts every application record. The client pins the server's public key; the server allows only configured client public keys. With a tunnel key both are derived from the one shared secret.

## Port forwarding

Server map listeners accept local TCP connections or UDP datagrams. They choose an authenticated session associated with that tunnel listener and send an Open frame with the target and transport kind. Before dialing, the client checks the exact target string against `allowed_targets`. A successful open is acknowledged; failures close that stream rather than granting access to another target.

TCP data travels in bounded 16 KiB chunks and preserves ordering and half-close. Per-stream credits bound in-flight frames so a slow destination does not block all other streams. UDP maps associate each sender with a connected client UDP socket; associations expire after idle time. A UDP payload is one Data frame and is limited to 16 KiB.

SOCKS5 accepts unauthenticated TCP CONNECT and UDP ASSOCIATE requests on the configured server socket (UDP: a relay socket on the interface the client connected to, one tunnel UDP stream per destination, answers returned with the destination's SOCKS5 header; datagram fragmentation is not supported). Requests use the same target authorization and stream machinery as maps. SOCKS can select any authenticated server session, whereas each map uses only sessions connected to its listener. The application does not match public-key identities to separate per-client destination namespaces.

Clients maintain configured connection pools and reconnect with bounded backoff. Heartbeats detect inactive peers. A lost tunnel terminates its active streams; reconnect supports new streams, not resumption or replay of an interrupted application connection. Resource limits cap sessions, streams, queues, and record sizes. Shutdown drops owned task trees and socket resources.

## Linux TUN

Optional TUN mode creates a point-to-point interface with the configured local and peer IP addresses. IP packets travel through the authenticated carrier. It uses one server listener or one client path with pool size one. Optional `tun.forwarding_port` starts an additional authenticated TCP multiplexer between the inner TUN addresses, allowing port maps, SOCKS and target allowlists alongside ordinary IP traffic. The kernel transports this TCP connection through the existing packet pump. Without that explicit port, TUN mode forwards IP packets only. It requires `iproute2`, `/dev/net/tun`, and suitable privileges. Only the point-to-point interface is configured; choosing additional routes, forwarding, NAT, and firewall policy is the administrator's responsibility.

With `transport: "tun"`, each IP packet is an independent encrypted datagram on a raw packet socket. Its authenticated session uses explicit nonces and a sliding replay window, permitting packet loss and reordering. Other carriers carry length-delimited IP packets on reliable streams. [Raw TUN framing](raw-tun.md) describes handshakes, heartbeats and reconnection. [Raw IPv4 carriers](raw-protocol.md) describes the TCP/UDP/ICMP/GRE/IPIP layouts, TCP camouflage, spoofing and proto58 mode. These outer formats wrap this project's Noise payloads.

## Source layout

| Module | Responsibility |
| --- | --- |
| `config.rs` | Strict JSON, limits, key and certificate generation. |
| `tunnel_key.rs` | The shared tunnel key: format, check symbol, derived identities, token and pinned TLS certificate. |
| `carrier.rs` | TLS, HTTP, WebSocket, and streaming HTTP adapters. |
| `kcp_carrier.rs` | Reliable UDP stream carrier. |
| `parallax_carrier.rs` | Paired directional authenticated TCP lanes, bounded records and cooperative batching. |
| `mirage.rs` | Experimental local raw-spoof consent and configuration rules. |
| `fec_carrier.rs` | 10+1 FEC, UDP knock, FEC over UDP and raw stream adapters. |
| `fec_tuning.rs` | Local RTT/throughput measurements, bounded adaptive socket buffers and KCP windows. |
| `xhttp_carrier.rs` | Bounded packet uploads, streaming probes, HTTP session cleanup. |
| `raw_packet.rs` | IPv4/transport checksums, outer packet layouts and validation. |
| `raw_socket.rs` | Linux packet socket, interface discovery and next-hop ARP. |
| `raw_tun.rs` | Authenticated unreliable IP datagrams and replay protection. |
| `transport.rs` | Noise handshake, peer authorization, encrypted records. |
| `session_crypto.rs` | Protocol domains, HKDF key separation and epoch thresholds. |
| `release.rs` | Official update-file Ed25519 verification. |
| `wire.rs` | Multiplexing frame encoding and validation. |
| `stealth.rs` | Wire version 2: the masked start of plain streams, decoy replies and names derived from the key. |
| `engine.rs` | Sessions, forwarding, flow control, reconnects, liveness, and replacing sessions that stop answering. |
| `engine/control.rs`, `engine/socks_udp.rs` | The local control socket (status, speed test) and SOCKS5 UDP ASSOCIATE. |
| `farewell.rs` | The goodbye a tunnel sends to its peers before a planned stop. |
| `limits.rs`, `stats.rs` | Admission and retry limits; counters, the memory budget and the status line. |
| `quota.rs` | Traffic quota and planned restarts. |
| `proxy_protocol.rs` | PROXY protocol headers for the real user address at the destination. |
| `fragment.rs`, `fingerprint.rs`, `tls_boring.rs`, `tlscheck.rs` | TLS ClientHello fragmentation; reading a ClientHello (JA3/JA4); the Chrome-like TLS client; `eztunnel tlscheck`. |
| `checker/` | The transport checker: control link, cases, measurements (`eztunnel check`). |
| `settings.rs`, `sys.rs` | The list of numeric settings; small operating-system helpers. |
| `tun_device.rs` | Linux virtual network interface. |
| `main.rs` | CLI, validation, shutdown; opens the manager when run on a terminal without arguments. |
| `manager/` | The interactive tunnel manager: wizard (`wizard.rs`), the answers-to-configuration model (`plan.rs`), customize screens (`tune.rs`), the tunnel list (`manage.rs`), files (`store.rs`), systemd/ufw (`service.rs`) and the terminal look (`ui.rs`), plus the updater (`update.rs`), backup and bulk actions (`backup.rs`, `bulk.rs`), the raw firewall rules (`rawfw.rs`) and the checker screens (`checker.rs`). |
| `linktest.rs`, `linkverdict.rs` | Explicit-peer TCP/UDP connectivity and throughput diagnostics, and the score and advice built from them. |

HTTP carriers expose their protocol headers/path to the network unless wrapped in TLS. The payload remains protected by Noise in every mode. No component downloads code at runtime.

When a TUN server uses a stream carrier (everything except `transport: "tun"`), handshakes run concurrently and are bounded by `max_pending_handshakes` / `max_pending_per_ip`, so a silent connection cannot delay the real peer. A peer that authenticates replaces any session already running, which lets a peer that restarted behind a NAT reconnect immediately instead of waiting for the old session to time out. One bad packet read from the TUN device is dropped; it does not end the session.
