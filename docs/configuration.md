# Configuration reference


The tunnel manager (`sudo eztunnel`) writes these files for you, one per tunnel in `/etc/eztunnel/tunnels/`. This page describes what is inside, for editing by hand (Manage tunnels → Edit the config file) or for running `eztunnel --config FILE` yourself.

Strict JSON rejects unknown settings. Bind addresses are literal IP:port, with brackets for IPv6. Peer addresses/targets can use hostnames except `tcp6`, which requires literal IPv6. Key and TLS file paths resolve relative to the config file. Key hex strings are exactly 64 characters; all-zero keys and placeholder text are rejected.

| Field | Role | Meaning/default |
| --- | --- | --- |
| `_comment` | Both | Optional free-form note. Ignored when loading; JSON has no comment syntax. |
| `mode` | Both | Required `server` or `client`. |
| `tunnel_key` | Both | The shared secret of the tunnel, for example `k7m2q-9xa4b-c3d5e-f6g7h-j8k9m` (make one with `eztunnel key`). Both ends use the same value. It replaces `private_key_file`, `peer_public_keys` and `server_public_key`, which must then be left out, and it also supplies the XHTTP access token and the `tls_auto` certificate. A file that contains it must not be readable by other users (`chmod 600`). |
| `server_dials` | Both | Default false: the client connects to the server (a *reverse* tunnel: the foreign server connects to the Iran server). True: the server connects to the client (a *direct* tunnel). Works with every carrier except the raw ones. Both ends must agree. The older name `reverse` is still accepted. |
| `private_key_file` | Both | Without `tunnel_key`: the local Noise private hex key; Unix mode must exclude group/other access. |
| `heartbeat_sec` | Both | Default 10; 1..3600 seconds. |
| `dead_timeout_sec` | Both | Default 40; greater than heartbeat, at most 86400. |
| `max_streams` | Both | Default 1024; 1..65536. Per-session stream ceiling with additional forwarding admission limits. |
| `max_connections` | Both | Default 16; 1..1024. Total configured client pools must fit. |
| `max_pending_handshakes` | Server | Default 64; 1..4096. Connections that have connected but not yet finished the key handshake, counted over all listeners. They wait in this pool and never use a `max_connections` slot; extra ones are dropped. |
| `max_streams_per_ip` | Server | Default 512; 0..65536 (0 = no limit). The most forwarded connections and UDP conversations one source address may have open at once through the maps and the SOCKS5 listener. The limit is enforced only while the sessions are more than three quarters full of streams: while there is room an address may use all of it (many users behind one shared address, carrier-grade NAT, count as one address), but it cannot take the last quarter, which stays available to addresses under their limit. |
| `max_pending_per_ip` | Server | Default 16; 1..256. The most handshakes one source address may have waiting at once (a client restarting a large `connection_pool` opens them together). Carriers that cannot report a source address (XHTTP, FEC) are limited only by `max_pending_handshakes`. |
| `peer_public_keys` | Server | Without `tunnel_key`: the authorized client keys (at least one). |
| `listeners` | Server | Required nonempty list of tunnel listeners. |
| `listeners[].addr` | Server | Local carrier bind address; with `server_dials`, the client's address to connect to. |
| `listeners[].connection_pool` | Server | Default 1; with `server_dials`, the number of parallel connections the server opens. |
| `listeners[].tls_auto`, `paths[].tls_auto` | Both | Default false. With a TLS carrier and `tunnel_key`: the listening side presents a certificate derived from the key, and the dialing side accepts exactly that certificate. No certificate files are needed and the TLS name (SNI) can be anything. |
| `listeners[].maps[]` | Server | `type`: `tcp` or `udp`, local `bind`, client-side `target`. Targets under `.invalid` are refused: they are reserved for the speed test. |
| `socks5` | Server | Optional local SOCKS5 bind: TCP CONNECT and UDP ASSOCIATE (DNS, QUIC and other UDP through the tunnel). No password. |
| `paths` | Client | Required nonempty server connection paths. |
| `paths[].addr` | Client | Server endpoint; TCP or UDP according to carrier. With `server_dials`, the local address the client listens on. |
| `paths[].server_public_key` | Client | Without `tunnel_key`: the pinned server key. |
| `paths[].connection_pool` | Client | Default 1; 1..1024. |
| `paths[].retry_interval` | Client | Default 1; 1..30 seconds; reconnect delay capped at 30. |
| `paths[].dial_timeout` | Client | Default 10; 1..300 seconds, including connection/handshake. |
| `listeners[].tls_fragment`, `paths[].tls_fragment` | Both | Off by default. `{"enabled": true}` makes the dialing side of a TLS carrier (`wss`, `https`, `xhttps`) split its ClientHello into small TLS records, each in its own TCP packet, with a cut inside the server name. `min_bytes` (10), `max_bytes` (60) and `delay_ms` (5, random pause up to this) tune it. Any TLS server accepts the result, but some filters drop split packets: then the tunnel never connects. Test it before relying on it, and turn it off if the link does not come up. |
| `listeners[].tls_profile`, `paths[].tls_profile` | Both | Default `classic`. `chrome` makes the dialing side of a TLS carrier (`wss`, `https`, `xhttps`) send the TLS ClientHello of Chrome 152 (cipher suites, extensions, groups, signature algorithms, GREASE, ECH GREASE, a different extension order each time) instead of this program's own. Only the dialing side uses it; the other side must run 0.7.3 or later. Not allowed on carriers without TLS or on the listening side of a tunnel, and refused by a build made without the `browser-tls` feature. Compare with a browser using `eztunnel tlscheck`. It changes how the handshake looks, nothing else; whether a particular filter treats it differently has to be tested on the link. Can be combined with `tls_fragment`. |
| `listeners[].maps[].proxy_protocol` | Server | TCP maps only. `1` (text) or `2` (binary) makes the far end write a PROXY protocol header with the user's real address and the address the user connected to before any user data, so the service behind the tunnel (for example nginx with `proxy_protocol`) can see who is connecting. The destination MUST be set to expect it, otherwise it reads the header as garbage and every connection fails. Absent = off. Needs EZTunnel 0.7.1 or later on both servers. Manage tunnels → *PROXY protocol to the destination*. |
| `listeners[].raw.kernel_filter`, `paths[].raw.kernel_filter` | Both | Default `true`. Raw carriers only: let the kernel drop frames that are not from the peer before they reach the program. See [raw-protocol.md](raw-protocol.md). |
| `listeners[].local_address`, `paths[].local_address` | Both | Optional. The local IP address the side that **dials** connects from, for a server with more than one address (by default the system picks one). It applies to `tcp`, `tcp6`, `ws`, `wss`, `http`, `https`, `xhttp`, `xhttps`, `kcp` and `fec-udp`; the raw carriers have `raw.local_ip`. Set it on the dialing side only (a `paths[]` entry without `server_dials`, a `listeners[]` entry with it); anywhere else the configuration is refused. It must be an address the server owns and of the same IP version as the peer, otherwise the connection fails with a clear error. Manage tunnels → Change settings → *Connect from address*. |
| `schedule` | Both | Planned restarts, see below. |
| `quota` | Both | Data limit per period, see below. |
| `tcp_congestion` | Both | Default `bbr`. TCP congestion control for this program's tunnel connections only (`bbr`, `cubic`, ...); `system` keeps the machine default. If the kernel does not offer it, the system default stays. |
| `listeners[].tcp_congestion`, `paths[].tcp_congestion` | Both | Optional (0.8.11). Overrides the top-level `tcp_congestion` for this one path/listener's TCP connections only; absent keeps the program-wide setting. Same values, including `system`. |
| `allowed_targets` | Client | Destinations the server may ask for: `host:port` strings (host names match in any letter case), `host:*` for every port of one host (for example `127.0.0.1:*`), or `"*"` for anything. Empty denies all. |
| `tun` | Both | Optional layer-3 mode described below. |

## Carrier settings

Every listener and path can specify `transport`: `tcp` (default), `kcp`, `http`, `https`, `ws`, `wss`, `xhttp`, `xhttps`, `tcp6`, `fec-udp`, `fec-raw`, `fec-raw-gaming`, or `tun`. Both ends must match. KCP and FEC-UDP use UDP; FEC-raw/gaming/TUN use raw IPv4; the other carriers use TCP. `tcp6` requires `[IPv6]:port` at both ends.

`http_path` defaults to `/tunnel` and must match on both ends for HTTP/WebSocket modes. It is an ASCII absolute path, at most 512 bytes, without whitespace, control characters, query, or fragment. XHTTP has a nested `xhttp` object with `mode` (`stream-up`, `packet-up`, `auto`), optional `host` and `edge_addrs`, upload body/concurrency bounds, buffering limits, streaming-probe timeouts, User-Agent and query padding. See [XHTTP settings](xhttp.md).

TLS listeners (`https`, `wss`, `xhttps`) need `tls_auto` (with `tunnel_key`) or `cert_file` and `key_file`. With `tls_auto` the dialing side pins the derived certificate and `server_name` only sets the name sent in TLS; without it, TLS clients require `server_name` matching the certificate, and may set `ca_file` to a PEM trust certificate. Without `ca_file`, bundled public roots are used. TLS settings are rejected on non-TLS carriers. Noise peer keys remain required in addition to certificates. `certgen --out keys/tls --name tunnel.example.com` generates local PEM files without overwriting existing files; copy only the certificate to the opposite machine.

With `server_dials: true`, the server's listener supplies the address it connects to and, for TLS, `ca_file`/`server_name` (or `tls_auto`); the client's path supplies its local listening address and, for TLS, `cert_file`/`key_file` (or `tls_auto`). The server still holds the port maps and SOCKS5 and the client still checks `allowed_targets`; only the direction of the connection between them changes. An XHTTP `host` override selects the HTTP authority and TLS SNI hostname. Over `kcp` and `fec-udp` the dialing server sends one wake-up byte first, because those listeners notice a new session only when data arrives.

FEC transports accept a nested `fec` object: `mtu` defaults to 1350 (512..9000), `profile` defaults to `default` with optional `gaming`, `knock` defaults to true, `knock_timeout_ms` defaults to 3000 (500..30000), and `max_peers` defaults to 256 (1..4096). FEC-UDP uses an additional UDP knock port: data port + 10000, or data port - 1000 when the first value would overflow. Both ends must agree on knock. Raw FEC-raw/gaming require `raw` settings and one connection; see [raw protocol](raw-protocol.md). The gaming transport forces its gaming profile. Send/receive windows, socket buffers, and an opt-in adaptive RTT/window controller are described in [FEC tuning](fec-tuning.md), including its memory accounting boundaries.

`fec.pacer` (default false) adds RTT-aware pacing to `fec-udp`, `fec-raw` and
`fec-raw-gaming`. Plain `kcp` does not use the FEC stream wrapper, so this setting
does not pace plain KCP. It complements window/resend settings rather than
changing wire framing. Measure loaded latency/throughput before enabling it;
sharing an underlying KCP crate does not imply sharing this wrapper's scheduler.

The raw carriers (`fec-raw`, `fec-raw-gaming`, `tun`) accept `raw.profile` (`tcp`, `udp`, `icmp`, `gre`, `ipip`, `raw`, `dns`), required real `peer_ip`, optional interface/local address/next-hop settings, `l4_port`, socket buffers, `proto58_mode`, and optional `spoof_src_ip`/`spoof_dst_ip`. proto58 mode and spoof settings are mutually exclusive. Raw carriers use one configured peer and connection pool one. `addr` is configuration metadata; the actual raw peer is `raw.peer_ip`. The manager derives consistent endpoint metadata.

## TUN settings

```json
"tun": {
  "name": "ez0",
  "address": "10.77.0.1",
  "peer_address": "10.77.0.2",
  "mtu": 1400
}
```

Addresses are plain IP literals **without a prefix**, use the same address family, and must differ. Reverse local/peer addresses on the other host. Names contain 1..15 ASCII letters, digits, underscores, or hyphens. MTU defaults to 1400, ranges from 576 to 9000, and must be at least 1280 for IPv6. TUN requires exactly one server listener or one client path with `connection_pool: 1`. Optional `forwarding_port` (1024..65535) enables the existing authenticated port/SOCKS multiplexer over an inner TCP connection between the two TUN IPs. Set the same port on both peers; the manager defaults this relay to 47475. Maps, SOCKS and `allowed_targets` require that field in TUN mode. Without it, only IP packet forwarding runs. `transport: "tun"` selects independent raw IP datagrams and requires this block plus `raw` settings. Other carriers can also carry TUN packets. Raw TUN's inner MTU must fit the selected interface MTU after outer headers and 47 bytes of authenticated datagram overhead; an incompatible MTU is rejected at runtime, unless `fragment` is on.

`tun.fragment` (0.8.11, default false) lets `mtu` exceed what the chosen raw profile's single outer packet can carry: a bigger IP packet leaves in up to 64 numbered pieces and the far side reassembles them before re-injecting it, instead of the startup check refusing the configuration. An incomplete datagram (a lost piece) is dropped after 2 seconds. Meant for traffic whose own packets are bigger than the profile's budget (a 1420-byte inner MTU, for example); costs an extra packet exchange per oversized datagram and, unlike the unfragmented path, one lost piece loses the whole packet. See [raw-tun.md](raw-tun.md).

`--check` parses configuration, loads the private key, and validates relevant TLS files. It does not bind sockets, verify peer reachability, configure TUN, resolve target DNS, or establish a tunnel. `RUST_LOG=debug` enables operational diagnostics.

## Changing settings

Open the manager with `sudo eztunnel`, choose **Manage tunnels**, pick the tunnel, then:

- **Change settings** lists every setting that applies to that tunnel's side and carrier, with its current value (values that differ from the default are highlighted). Choose one, type a new value or `default`, then **Save and restart**.
- **Change forwarded ports** (Iran server) edits the port list in the same short form the wizard uses: `443, 8443, 2083=443, 9000-9010, 5000=10.0.0.5:5000`.
- **Edit the config file** opens the JSON in your editor (`$EDITOR`, otherwise nano or vi).

Every change is checked with the program's own validation before it replaces the file, and the previous version is kept as `NAME.json.bak`. A file that fails the check is never saved; the editor offers to edit again or discard.

## Tunable settings

Generated from `eztunnel settings`, which prints this list as JSON (name, default, allowed range). Nothing here is fixed in the program: set any of these in the configuration file. Values outside the range are rejected by `--check`. The manager's Customize and Change settings screens use this same list.

| Setting | Where | Used by | Default | Range | Meaning |
| --- | --- | --- | --- | --- | --- |
| `heartbeat_sec` | top level | both | 10 seconds | 1..3600 | How often each side checks that the other is alive. On XHTTP carriers it must be smaller than `xhttp.session_timeout_sec`, and on FEC carriers smaller than `fec.peer_idle_sec`: an idle tunnel only sends its heartbeat, and a session reaped before the next one would be rebuilt over and over. |
| `dead_timeout_sec` | top level | both | 40 seconds | 2..86400 | A silent peer is declared dead after this long. Must be larger than heartbeat_sec. |
| `max_streams` | top level | both | 1024 streams | 1..65536 | Most simultaneous user connections carried by one tunnel session. |
| `stream_early_data` | top level | both | true | true/false | A new user connection sends its first data right behind the request to open it instead of waiting for the other server's confirmation: one round trip less per new connection (about 90 ms instead of 180 ms on a 90 ms path). The other server queues the data until the destination is connected; every version does, so mixed versions work. With it, SOCKS5 clients are told "connected" at once, and a destination that fails closes the connection. `false` = wait for the confirmation first. |
| `stream_window` | top level | both | 64 frames | 16..1024 | Data one user connection may have in flight, in 16 KiB frames. One connection's speed is at most window x 16 KiB per round trip (64 = 1 MiB, about 11 MB/s at 90 ms). Larger is faster on long links and uses more memory for slow users. |
| `memory_budget_mb` | top level | both | 0 MiB | 0..1048576 | Total memory the flow-control windows of all user connections may use beyond the first 256 KiB each. 0 = automatic: a quarter of the server's memory, between 64 MiB and 1 GiB. When it is used up, new connections keep a small window (a lower speed on long links) instead of the server running out of memory. |
| `worker_threads` | top level | both | 1 thread | 1..64 | Threads that run the tunnel. One is the most efficient: the work is many small network operations, and moving them between threads costs more CPU than it saves (see "CPU use" below). Raise it only for a very fast FEC carrier, which one core cannot encode and decode fast enough. Needs a restart. |
| `stats_interval_sec` | top level | both | 60 seconds | 0..86400 | Log a one-line status summary this often. 0 turns it off. |
| `schedule.restart_every_hours` | top level | both | 0 hours | 0..8760 | Restart the tunnel after it has run this long: it exits cleanly and the service starts it again. 0 = never. |
| `quota.limit_gb` | top level | both | 0 GB | 0..1000000 | Most data (both directions together, 1 GB = 10^9 bytes) this tunnel carries per period. When it is reached the tunnel stops carrying traffic until the period ends. 0 = no limit. |
| `quota.period_days` | top level | both | 30 days | 1..3650 | Length of one quota period. The first period starts when the tunnel first runs. |
| `max_connections` | top level | both | 16 sessions | 1..1024 | Most simultaneous authenticated tunnel sessions. |
| `max_pending_handshakes` | top level | server | 64 connections | 1..4096 | Connections allowed to wait for the key handshake, over all listeners. |
| `max_pending_per_ip` | top level | server | 16 connections | 1..256 | Handshakes one source address may have waiting at once. |
| `max_streams_per_ip` | top level | server | 512 streams | 0..65536 | Forwarded connections and UDP conversations one source address may have open at once through the maps and SOCKS5, enforced while the sessions are more than 75 % full; 0 = no limit. |
| `timeouts.handshake_sec` | top level | server | 10 seconds | 1..300 | Time a new connection has to finish the key handshake. |
| `timeouts.connect_sec` | top level | both | 10 seconds | 1..300 | Time allowed to reach the real destination, and for a SOCKS5 greeting. |
| `timeouts.open_sec` | top level | both | 15 seconds | 1..300 | Time a stream may wait for the far side to confirm it opened. |
| `wire_version` | top level | both | 1 (new manager tunnels: 3) | 1, 2 or 3 | 1 retains unshaped framing; 2 adds probe-resistance shaping; 3 also rotates frame bytes using authenticated session-specific directional keys. Both endpoints must use the same value and the 0.9 protocol. A missing value means 1. Raw sessions also bind this value into their handshake. |
| `stealth.pad_min` | top level | both | 64 bytes | 0..4095 | Wire version 2: printable padding at the start of each direction of a masked stream, at least this long. A long printable start keeps the first packet from looking like uniform noise, which the tested Iranian network cut after the first packets. |
| `stealth.pad_max` | top level | both | 255 bytes | 0..4095 | Wire version 2: padding at most this long (must not be below `stealth.pad_min`). |
| `stealth.probe_hold_sec` | top level | both | 5 seconds | 0..120 | Wire version 2: how long a failed connection is ignored before it is closed (random between half and all of this). 0 closes at once. |
| `stealth.decoy_status` | top level | both | 404 | 200, 400, 403, 404, 421 | Wire version 2: status of the web-server page a wrong HTTP request gets. Not in the settings menu. |
| `stealth.record_pad_max` | top level | both | 0 bytes | 0..255 | Wire version 2: pad every record this side sends by a random 0..this many bytes, so record sizes no longer show what is inside (acknowledgements, heartbeats, small requests). Costs about half this many bytes per record. 0 = off. Each side sets its own. Needs `wire_version: 2` on both servers and 0.7.1 or later. |
| `stealth.jitter_ms` | top level | both | 0 ms | 0..1000 | Wire version 2: delay the start of each burst of sending by a random 0..this many milliseconds, so the timing of sporadic traffic is not a copy of the user's. Records that follow within 20 ms of the previous one are not delayed, so bulk transfers keep their speed. 0 = off. Each side sets its own. |
| `timeouts.udp_idle_sec` | top level | both | 120 seconds | 5..86400 | A forwarded UDP conversation with no traffic for this long is closed. |
| `timeouts.goodbye_wait_ms` | top level | both | 500 ms | 0..5000 | When the tunnel stops (restart, update, stop, planned restart, used-up quota) it first tells the other server goodbye inside the encrypted session; the other server drops those sessions at once and reconnects as soon as this side is back, instead of after `dead_timeout_sec`. This is how long the tunnel keeps running so the notice is sent; 0 = stop at once. Needs 0.7.8 on the receiving side (an older one ends the session too, with a decode error in its log). |
| `timeouts.probe_sec` | top level | both | 3 seconds | 1..60 | How long a session may go without any answer while this side waits for one. After this long a ping asks (any frame back counts); after twice this long the session takes no new users, and the side that dialed it tries a fresh connection: if that works while the old session is still silent (the other server crashed and came back, or that session's path is stuck), the fresh one replaces it. A session carrying traffic is replaced about 6 s after the other server died, an idle one after at most `heartbeat_sec` + 6 s, instead of `dead_timeout_sec`. Also (0.8.4): when the other server connects again, its older sessions get a ping and those silent for this long are closed. Raw TUN uses it the same way (a new handshake after twice this long without an answer to its pings). |
| `timeouts.tcp_idle_sec` | top level | both | 3600 seconds | 0..86400 | A forwarded TCP connection with no data in either direction for this long is closed; 0 = never. Idle connections otherwise hold stream slots for ever. |
| `timeouts.retry_max_sec` | top level | both | 30 seconds | 1..3600 | Longest pause between reconnect attempts (each wait also gets a random extra of up to 25%, so pooled sessions do not retry in lockstep). |
| `timeouts.server_dial_sec` | top level | both | 30 seconds | 1..300 | When the server dials (server_dials): time to reach the client and finish the handshake. |
| `queues.stream_frames` | top level | both | 32 frames | 20..4096 | Frames that may wait in memory for one stream. |
| `queues.session_frames` | top level | both | 128 frames | 16..65536 | Frames that may wait in memory for one session. |
| `kcp.mtu` | each `listeners[]` entry | server | 1400 bytes | 512..9000 | Packet size of the plain kcp carrier. Use the same value on both ends. |
| `kcp.send_window` | each `listeners[]` entry | server | 1024 packets | 16..8192 | Plain kcp send window: packets in flight. Speed is at most window x MTU per round trip. |
| `kcp.recv_window` | each `listeners[]` entry | server | 1024 packets | 16..8192 | Plain kcp receive window. |
| `kcp.session_expire_sec` | each `listeners[]` entry | server | 60 seconds | 5..3600 | Inactive plain kcp sessions are closed after this long. |
| `kcp.mtu` | each `paths[]` entry | client | 1400 bytes | 512..9000 | Packet size of the plain kcp carrier. Use the same value on both ends. |
| `kcp.send_window` | each `paths[]` entry | client | 1024 packets | 16..8192 | Plain kcp send window: packets in flight. Speed is at most window x MTU per round trip. |
| `kcp.recv_window` | each `paths[]` entry | client | 1024 packets | 16..8192 | Plain kcp receive window. |
| `kcp.session_expire_sec` | each `paths[]` entry | client | 60 seconds | 5..3600 | Inactive plain kcp sessions are closed after this long. |
| `kcp.interval_ms` | each `listeners[]` entry | server | 10 ms | 10..5000 | Plain kcp: how often packets are sent and resent. Lower reacts faster and uses more CPU. |
| `kcp.resend` | each `listeners[]` entry | server | 2 packets | 0..255 | Plain kcp: resend a packet after this many later ones arrived (0 = wait for the timer). |
| `kcp.socket_buf_bytes` | each `listeners[]` entry | server | 4194304 bytes | 65536..67108864 | Plain kcp: UDP socket buffer. Must hold a full window; the kernel caps it at net.core.rmem_max. |
| `fec.sndwnd` | each `listeners[]` entry | server | 1024 packets | 128..8192 | FEC: packets in flight. With the buffers it bounds speed: window x packet size per round trip. |
| `fec.rcvwnd` | each `listeners[]` entry | server | 1024 packets | 128..8192 | FEC: packets this side accepts ahead of the reader. |
| `fec.socket_buf_bytes` | each `listeners[]` entry | server | 4194304 bytes | 262144..67108864 | FEC: UDP socket buffers (outside and internal). The kernel caps them at net.core.rmem_max. |
| `kcp.interval_ms` | each `paths[]` entry | client | 10 ms | 10..5000 | Plain kcp: how often packets are sent and resent. Lower reacts faster and uses more CPU. |
| `kcp.resend` | each `paths[]` entry | client | 2 packets | 0..255 | Plain kcp: resend a packet after this many later ones arrived (0 = wait for the timer). |
| `kcp.socket_buf_bytes` | each `paths[]` entry | client | 4194304 bytes | 65536..67108864 | Plain kcp: UDP socket buffer. Must hold a full window; the kernel caps it at net.core.rmem_max. |
| `fec.sndwnd` | each `paths[]` entry | client | 1024 packets | 128..8192 | FEC: packets in flight. With the buffers it bounds speed: window x packet size per round trip. |
| `fec.rcvwnd` | each `paths[]` entry | client | 1024 packets | 128..8192 | FEC: packets this side accepts ahead of the reader. |
| `fec.socket_buf_bytes` | each `paths[]` entry | client | 4194304 bytes | 262144..67108864 | FEC: UDP socket buffers (outside and internal). The kernel caps them at net.core.rmem_max. |
| `kcp.max_sessions` | each `listeners[]` entry | server | 1024 sessions | 1..65536 | Plain kcp: most simultaneous sessions. |
| `kcp.max_sessions_per_ip` | each `listeners[]` entry | server | 64 sessions | 0..65536 | Plain kcp: most sessions from one source address; 0 = no limit. |
| `fec.peer_idle_sec` | each `listeners[]` entry | server | 60 seconds | 5..3600 | A FEC peer with no traffic for this long is forgotten. |
| `fec.knock_ttl_sec` | each `listeners[]` entry | server | 30 seconds | 5..3600 | How long a knock keeps its source address admitted. |
| `fec.session_expire_sec` | each `listeners[]` entry | server | 60 seconds | 5..3600 | Inactive FEC KCP sessions are closed after this long. |
| `fec.session_expire_sec` | each `paths[]` entry | client | 60 seconds | 5..3600 | Inactive FEC KCP sessions are closed after this long. |
| `fec.partial_flush_ms` | each `listeners[]` entry | server | 10 ms | 0..1000 | FEC: when fewer than 10 packets were sent and nothing follows for this long, a parity packet for those few is sent, so a loss among them is repaired at once instead of waiting for a retransmission (the end of every transfer, short requests and answers). Costs at most one packet per pause. 0 = off. A receiver older than 0.8.4 ignores these packets. |
| `fec.partial_flush_ms` | each `paths[]` entry | client | 10 ms | 0..1000 | FEC: when fewer than 10 packets were sent and nothing follows for this long, a parity packet for those few is sent, so a loss among them is repaired at once instead of waiting for a retransmission (the end of every transfer, short requests and answers). Costs at most one packet per pause. 0 = off. A receiver older than 0.8.4 ignores these packets. |
| `kcp.resend_burst` | each `listeners[]` entry | server | 128 packets | 0..8192 | Plain kcp: most packets resent at once (per `kcp.interval_ms`) because their retransmission timer expired; the others follow in the next intervals, oldest first. Without a limit a timeout resends the whole window in one burst, and a short queue on the path drops most of it again (the transfer then stalls for seconds). 0 = no limit (the behaviour before 0.8.5). |
| `kcp.resend_burst` | each `paths[]` entry | client | 128 packets | 0..8192 | Plain kcp: most packets resent at once (per `kcp.interval_ms`) because their retransmission timer expired; the others follow in the next intervals, oldest first. Without a limit a timeout resends the whole window in one burst, and a short queue on the path drops most of it again (the transfer then stalls for seconds). 0 = no limit (the behaviour before 0.8.5). |
| `fec.resend_burst` | each `listeners[]` entry | server | 128 packets | 0..8192 | FEC: most packets resent at once (per interval) because their retransmission timer expired; the others follow in the next intervals, oldest first. Without a limit a timeout resends the whole window in one burst, and a short queue on the path drops most of it again (the transfer then stalls for seconds). 0 = no limit (the behaviour before 0.8.5). |
| `fec.resend_burst` | each `paths[]` entry | client | 128 packets | 0..8192 | FEC: most packets resent at once (per interval) because their retransmission timer expired; the others follow in the next intervals, oldest first. Without a limit a timeout resends the whole window in one burst, and a short queue on the path drops most of it again (the transfer then stalls for seconds). 0 = no limit (the behaviour before 0.8.5). |
| `xhttp.max_requests` | each `listeners[]` entry | server | 256 connections | 1..65536 | XHTTP: simultaneous HTTP connections accepted. |
| `xhttp.max_sessions_per_ip` | each `listeners[]` entry | server | 0 (no limit) | 0..65536 | XHTTP: most simultaneous sessions from one source address, counted for the whole life of the session. Behind a CDN every user shares a few edge addresses: leave it at 0 there. |
| `fec.max_peers_per_ip` | each `listeners[]` entry | server | 64 conversations | 0..4096 | FEC: most conversations (one per client connection) one source address may have at once; 0 = no limit. |
| `xhttp.max_requests_per_ip` | each `listeners[]` entry | server | 64 connections | 0..65536 | XHTTP: most simultaneous HTTP connections from one source address; 0 = no limit (use 0 or a high value behind a CDN). |
| `xhttp.max_sessions` | each `listeners[]` entry | server | 64 sessions | 1..65536 | XHTTP: simultaneous sessions. |
| `xhttp.edge_retry_sec` | each `paths[]` entry | client | 60 seconds | 1..3600 | XHTTP: how long a failed edge address is skipped. |
| `xhttp.up_concurrency` | each `listeners[]` entry | server | 8 requests | 1..16 | XHTTP packet-up: uploads in flight at once. Upload speed is at most this x up_max_bytes per round trip, so long links need more. |
| `xhttp.up_concurrency` | each `paths[]` entry | client | 8 requests | 1..16 | XHTTP packet-up: uploads in flight at once. Upload speed is at most this x up_max_bytes per round trip, so long links need more. |
| `retry_interval` | each `paths[]` entry | client | 1 seconds | 1..30 | First pause before reconnecting; it doubles up to timeouts.retry_max_sec. |
| `dial_timeout` | each `paths[]` entry | client | 10 seconds | 1..300 | Time allowed to connect and finish the handshake. |
| `connection_pool` | each `paths[]` entry | client | 1 sessions | 1..1024 | Parallel tunnel sessions to keep open. More sessions spread users and limit the effect of one dropping. |
| `xhttp.socket_buf_bytes` | each `listeners[]` entry | server | unset | 65536..67108864 | XHTTP: fixed TCP socket buffer. Unset lets the kernel grow it with the link (fastest); a fixed value caps one connection's speed. |
| `xhttp.socket_buf_bytes` | each `paths[]` entry | client | unset | 65536..67108864 | XHTTP: fixed TCP socket buffer. Unset lets the kernel grow it with the link (fastest); a fixed value caps one connection's speed. |
| `tls_fragment.min_bytes` | each `listeners[]` entry | server | 10 bytes | 1..1024 | TLS fragmentation (when on): smallest piece of the ClientHello per TLS record. |
| `tls_fragment.max_bytes` | each `listeners[]` entry | server | 60 bytes | 1..1024 | TLS fragmentation (when on): largest piece of the ClientHello per TLS record. |
| `tls_fragment.delay_ms` | each `listeners[]` entry | server | 5 ms | 0..1000 | TLS fragmentation (when on): longest random pause between pieces; 0 = none. |
| `tls_fragment.min_bytes` | each `paths[]` entry | client | 10 bytes | 1..1024 | TLS fragmentation (when on): smallest piece of the ClientHello per TLS record. |
| `tls_fragment.max_bytes` | each `paths[]` entry | client | 60 bytes | 1..1024 | TLS fragmentation (when on): largest piece of the ClientHello per TLS record. |
| `tls_fragment.delay_ms` | each `paths[]` entry | client | 5 ms | 0..1000 | TLS fragmentation (when on): longest random pause between pieces; 0 = none. |
| `max_open_files` | top level | both | unset | 256..16777216 | Open-file limit to request. When unset, the hard limit is used. |

Not settings (fixed by the wire protocol, both ends must agree): frame size 16 KiB, the initial flow-control window of 16 frames that every stream starts with (each receiver then opens its own `stream_window`), the Noise handshake and its prologue, and the packet markers.

### Speed on long links

One user connection can only have a limited amount of data in flight before the other side confirms it, so its speed is at most *data in flight ÷ round-trip time*. At the 90 ms typical between Iran and Europe:

| Carrier | What limits one connection | Default | About |
| --- | --- | --- | --- |
| all | `stream_window` (frames of 16 KiB) | 64 = 1 MiB | 11 MB/s; 256 gives about 45 MB/s |
| `kcp` | `kcp.send_window`/`recv_window` × MTU, and `kcp.socket_buf_bytes` | 1024 packets, 4 MiB | 15 MB/s |
| `fec-udp`, `fec-raw` | `fec.sndwnd`/`rcvwnd` × MTU, and `fec.socket_buf_bytes` | 1024 packets, 4 MiB | 15 MB/s |
| `xhttp`, `xhttps` | `xhttp.socket_buf_bytes` when set (unset = the kernel sizes it) | unset | link speed |

The *Streaming / big downloads* profile raises the KCP and FEC windows to 4096 packets with 16 MiB socket buffers (about 4x the speed ceiling at 90 ms); the other profiles leave them at the defaults. On a real Iran link the default windows measured about 100 Mbit/s and a 4096-packet window 125-150 Mbit/s.

Linux caps UDP socket buffers at `net.core.rmem_max`/`wmem_max` (208 KB on many systems). When a KCP or FEC tunnel asks for more, the manager raises that ceiling in `/etc/sysctl.d/60-eztunnel.conf`. Larger windows use more memory only for users that read slower than the tunnel delivers.

### Memory budget for the windows

A user connection starts with a small window (16 frames, 256 KiB). The receiving side then opens
it to `stream_window` frames so that one connection can fill a long link. A slow user can leave
that whole window queued in memory: with `stream_window` 256 that is up to 4 MiB per connection, so
hundreds of slow users on a small server could use gigabytes.

`memory_budget_mb` caps the total of those extra frames over all connections of a tunnel. `0` (the
default) means automatic: a quarter of the machine's memory, between 64 MiB and 1 GiB. When the
budget is used up, a new connection simply keeps the small window, so it is slower on a long link
(256 KiB per round trip is about 23 Mbit/s at 90 ms) instead of the server running out of memory,
and it gets frames back as other connections end. Nothing changes on the wire: only the receiving
side decides how many credits to hand out, so the two servers need not agree. The log shows the
chosen budget at start (`memory budget for flow-control windows`) and Live status shows how much is
in use.

Measured on the real test link with `stream_window` 256 (one connection, upload and four
connections, Mbit/s): automatic (1 GiB there) 175-212 / 201-228 / 357-384; a 16 MiB budget 213 /
235 / 404; a 1 MiB budget 95 / 96 / 150, the speed of a window of about 80 frames.

### Speed modes (KCP and FEC carriers)

KCP resends and acknowledges on a timer. The manager (New tunnel → Customize, and Manage tunnels →
Change settings) offers a **Speed mode** for `kcp`, `fec-udp`, `fec-raw` and `fec-raw-gaming`. A
mode is only a shortcut for the timing fields below; nothing changes on the wire, and the two
servers may use different modes.

| Mode | `nodelay` | `interval_ms` | `resend` | `congestion_control` | `write_delay` (FEC) | `ack_no_delay` (FEC) |
| --- | --- | --- | --- | --- | --- | --- |
| default | not set: the program's own values (already fast) | | | | | |
| normal | false | 40 | 2 | false | true | false |
| fast | false | 30 | 2 | false | true | false |
| fast2 | true | 20 | 2 | false | false | true |
| fast3 | true | 10 | 2 | false | false | true |

The program's defaults are already at the fast end, so the gentler modes are for servers that run
out of CPU, not for more speed. On the real Iran link used for testing (88 ms, two small VPSs) the
four modes gave the same speed within the noise of the path, and `fast3` used the most CPU. The FEC
carriers are limited by CPU there: the tunnel process used about 90-100 % of one core during a
transfer in every mode, which is why `fec-udp` stops near 100 Mbit/s. If you set these fields by hand,
the manager shows the mode as "custom".

### CPU use

The tunnel does a great many small network operations, so most of its CPU goes to the system calls and thread
wake-ups around them, not to encryption. Three things keep that low:

- **One worker thread by default** (`worker_threads`). Earlier versions used one thread per core. Measured on a
  loopback pair on a 6-core machine: with one thread the `kcp` carrier carried 1.46 Gbit/s using 10 CPU-seconds
  per gigabyte (both ends together); with six threads it carried 0.73 Gbit/s using 28. The `tcp` and `wss`
  carriers showed the same pattern (about 5 CPU-seconds per GB against 11). A single thread is limited to one
  core, which is about 400-470 Mbit/s for the FEC carriers on that machine; raise `worker_threads` if a very fast
  FEC tunnel needs more.
- **Datagrams in batches.** KCP and FEC send and receive up to 64 UDP datagrams per system call on Linux
  (`sendmmsg`/`recvmmsg`) instead of one.
- **Faster FEC parity.** The parity shard is computed with a multiplication table instead of bit by bit; the bytes on
  the wire are unchanged.

Together: `fec-udp` download on that loopback pair went from 317 Mbit/s using 64 CPU-seconds per GB to about 460
Mbit/s using 25, and `kcp` from 625 Mbit/s using 34 to 1460 using 10. A loopback pair has no real network, so
expect smaller figures between real servers; the saving in CPU per GB is what carries over. On the two real test
servers (88 ms apart, speeds of 80-90 Mbit/s) the tunnel process of `fec-udp` went from 113 % to 55 % of a core and
that of `kcp` from 75 % to 48 %, with the same or better speed.

### Planned restarts and the traffic quota

Both are per server (a pairing code never carries them) and both rely on the service manager: the
program ends cleanly and `Restart=always` of the manager's units starts it again. Run by hand without
such a supervisor, the tunnel simply stops.

- `schedule.restart_every_hours` restarts the tunnel after that many hours of running. A restart drops the
  tunnel sessions for a few seconds; users reconnect by themselves.
- `quota` counts the data the tunnel carries for users (what it sends to and receives from the other server,
  heartbeats excluded). When `quota.limit_gb` is reached the tunnel logs `traffic quota used up`, closes
  all connections and stops serving: the process stays alive but idle, holds no port and opens no connection,
  until the period ends (`quota.period_days` after the period started; a tunnel that was off for several
  periods lands in the one that contains the present). Then it starts again with a fresh count. The count
  is kept in a small file (`/var/lib/eztunnel-NAME/quota.json` for the manager's services, which add
  `StateDirectory=` to the unit when a quota is set) so restarts and reboots do not lose it; deleting the
  file starts a new period. Manage tunnels shows the used amount and the time to the next period, and has
  *Reset the quota counter*. A quota set on only one server stops only that server's side: the other side
  keeps trying to reconnect.

## Status line

Every `stats_interval_sec` seconds (default 60; 0 turns it off) the program logs one summary line at `info` level, for example:

```
status: sessions=4 connects=4 streams=118 streams_total=9812 refused=0 rejected=3 sent=1.2 GiB received=3.4 GiB
```

`sessions` and `streams` are open right now; `connects` counts tunnel sessions opened since start (if it keeps growing while `sessions` stays the same, the link between the servers keeps dropping; each drop is logged as `tunnel session ended` with its reason and duration); `streams_total` counts all user connections since start; `refused` counts user connections turned away for lack of a session or capacity; `rejected` counts tunnel connections dropped (too many waiting, failed handshake, no free slot).
