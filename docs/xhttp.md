# XHTTP uploads and HTTP proxies


The Rust core supports stream-up, packet-up, and automatic detection of buffered uploads. Packet-up carries the encrypted tunnel through finite HTTP POST requests and a separate streaming GET response. A proxy can forward those requests without understanding Noise or the tunnel's streams. Only the addresses, HTTP Host, TLS name and certificate trust configured by the operator are used.

The session URLs, framing and authentication belong to eztunnel.

## Upload modes

Set `xhttp` inside the physical dialer's listener/path entry:

```json
"xhttp": {
  "mode": "packet-up",
  "host": "tunnel.example.com",
  "edge_addrs": ["203.0.113.10:8443", "203.0.113.11:8443"],
  "up_max_bytes": 65536,
  "up_concurrency": 8,
  "buffer_bytes": 32768,
  "user_agent": "eztunnel",
  "pad_min": 8,
  "pad_max": 48,
  "socket_buf_bytes": 131072,
  "probe_ms": 8000,
  "session_timeout_sec": 40
}
```

| Option | Default | Behavior |
|---|---|---|
| `mode` | `stream-up` | `stream-up`, `packet-up`, or `auto` |
| `host` | address from `addr` | HTTP Host authority and, for TLS, certificate/SNI hostname; a port is removed from the TLS name |
| `edge_addrs` | empty | Explicit addresses tried in order instead of `addr`; maximum 16, no edge discovery or scanning |
| `up_max_bytes` | 65536 | Maximum finite POST body, 1024–1048576 bytes; receiver must allow at least the sender's maximum |
| `up_concurrency` | 8 | Number of concurrent finite POST workers, 1–16. Upload speed in packet-up mode is at most this × `up_max_bytes` per round trip (at 180 ms and 64 KiB: 2 workers about 6 Mbit/s, 8 workers about 23 Mbit/s) |
| `buffer_bytes` | 32768 | Bounded byte-stream buffer, 1024–1048576 bytes |
| `user_agent` | `eztunnel` | Operator supplied ASCII HTTP User-Agent, 1–256 bytes; control characters are rejected |
| `pad_min` / `pad_max` | 0 / 0 | Random alphanumeric `?v=` query padding length, 0–4096 bytes; equal zero disables padding |
| `socket_buf_bytes` | 1048576 | Requested Linux send/receive socket buffers, 65536–67108864 bytes; kernel limits may cap the applied size |
| `probe_ms` | 8000 | Auto-mode streaming probe deadline; capped at half the enclosing dial deadline to leave time for fallback |
| `session_timeout_sec` | 40 | Upload/header idle deadline; maximum 3600 seconds |

The listener accepts either upload shape. Its `mode` does not restrict incoming sessions. Its body limit, buffer, socket buffer and timeout still apply. On the physical dialer, `mode` chooses the upload shape. User-Agent and padding are applied to every outgoing XHTTP request. Padding is validated and removed before routing an incoming request; unknown query parameters are rejected. These fields contain no automatic operating-system, user-account or device identifier.

`stream-up` uses one long, bidirectional, chunked POST on a single connection. It requires a path that forwards unfinished request bodies. `auto` probes the path with an unfinished chunked request. An immediate acknowledgement selects streaming uploads over separate upload/download connections. If the request is buffered or the probe fails, the core starts a new packet-up session. `packet-up` skips this probe and always sends numbered finite requests. The implementation uses HTTP/1.1; packet uploads require connections separate from the long download response. No HTTP/2 multiplexing or `separate_conns=false` packet mode is claimed.

Failed configured edges receive a local cooldown of `edge_retry_sec` (default 60 seconds); if all are cooling,
the configured list is tried again. Each TCP/TLS attempt receives
`dial_timeout*1000/candidate_count` milliseconds, clamped to at least 100 ms and at
most the configured timeout (or 100 ms if smaller). This is a per-candidate budget,
not a universal three-second cap or strict whole-list total; enclosing dial/
reconnect deadlines still apply. Active sessions remain pinned; reconnect creates
a fresh session. Packet uploads may retry once on a fresh connection after an
I/O/framing error on a reused connection. A 409 duplicate then counts as delivered
only on that retry. Arbitrary HTTP errors, 429, or ambiguous fresh-request failures
end the session; no general retry loop or fixed whole-edge-list deadline is claimed.

## The server dials the CDN

Set `"server_dials": true` in both configurations (the older name `reverse` is still accepted). The server keeps its port mappings and SOCKS listener, but connects out to the HTTP edge. The client becomes the HTTP origin and keeps its target allowlist. Noise authentication keeps the same server/client roles. In the manager this is a *direct* tunnel through a CDN; a *reverse* tunnel through a CDN has the foreign server dial the edge instead.

For the server, use the listener's `addr` as the edge endpoint. The edge shows a real certificate, so leave out `ca_file` (the bundled public roots are used) and set the name with `server_name` or `xhttp.host`. The following listener fragment uses documentation-only example addresses; replace them with your own endpoint and domain:

```json
"server_dials": true,
"listeners": [{
  "addr": "203.0.113.10:8443",
  "transport": "xhttps",
  "http_path": "/tunnel-api",
  "server_name": "tunnel.example.com",
  "xhttp": {
    "mode": "packet-up",
    "host": "tunnel.example.com",
    "edge_addrs": ["203.0.113.10:8443", "203.0.113.11:8443"],
    "up_concurrency": 8
  },
  "maps": [{"type":"tcp", "bind":"127.0.0.1:8080", "target":"127.0.0.1:8000"}]
}]
```

For the client, use the path's `addr` as the origin bind address. `tls_auto` gives the origin a certificate derived from the tunnel key; most CDNs accept a self-signed origin certificate (Cloudflare's "Full" mode, not "Full (strict)"). With a strict CDN, use `cert_file`/`key_file` with a certificate the CDN trusts instead:

```json
"server_dials": true,
"paths": [{
  "addr": "0.0.0.0:8443",
  "transport": "xhttps",
  "http_path": "/tunnel-api",
  "tls_auto": true
}],
"allowed_targets": ["127.0.0.1:8000"]
```

These fragments accompany the usual `mode` and `tunnel_key`. Complete files are in `examples/server-xhttp-cdn-server-dials.json` and `examples/client-xhttp-cdn-server-dials.json`. Without `server_dials`, the server listens and the client dials as usual. Behind a CDN every user arrives from a few edge addresses, so set `xhttp.max_requests_per_ip` to 0 on the listening side (the manager does this when you answer that the tunnel goes through a CDN).

Configure your own proxy/CDN to route the Host and path to the origin, preserve request bodies, disable caching, and stream the download response. The core sends `Cache-Control: no-store, no-transform` and `X-Accel-Buffering: no`. TLS verification stays enabled; no insecure TLS switch is provided. A custom origin CA can be supplied explicitly. An HTTP proxy/CDN must support streaming responses; finite uploads do not remove that requirement. External CDN deployments have not been verified merely by the local tests.

## Packet framing and limits

A 32-byte random session identifier is hex encoded. The downloader starts `GET <http_path>/<session>` with an explicit upload-mode header. Packet uploads use `POST <http_path>/<session>/<sequence>` and a `Content-Length`; sequence numbers start at zero. An empty body at the next sequence ends upload. Streaming uploads use a chunked POST to the session URL. Both shapes carry the same encrypted Noise byte stream.

The receiver reorders a window of 16 uploads. Duplicate/old sequence numbers return
409; outside-window uploads return 429 because they were not retained. A body is
acknowledged only after bounded downstream acceptance. Request/session queues
are bounded. Oversize returns 413; a missing session 410. Dropping a tunnel aborts
its bridge and removes the session, including handshake failure.

Download chunks may be split or combined by an HTTP proxy. The decoder uses a fixed 16 KiB copy buffer, accepts ordinary chunk extensions/trailers, and caps an individual proxy chunk at 16 MiB. Empty chunked upload acknowledgements and `Connection: close` responses are supported. Header/trailer sizes remain bounded. Incoming HTTP/1.1 requests require a valid Host authority; ambiguous length/encoding headers and malformed numeric fields are rejected. Wire records are still authenticated by Noise; the HTTP session identifier does not replace peer authentication.

## Local verification

`tests/xhttp.rs` exercises packet-up over HTTP and verified TLS in both physical directions, transferring 1,048,577 TCP bytes with half-close, UDP datagrams of 0–16384 bytes, and SOCKS TCP data. Each case supplies an unavailable edge followed by a working edge; TLS cases also try an edge with the wrong certificate. Host/SNI override and logical pinned identities are checked in both directions. The harness also checks auto fallback through a local proxy that deliberately buffers unfinished chunked requests, in both directions, and direct auto streaming. The proxy verifies the configured User-Agent and 8–48-byte query padding. Unit tests exercise out-of-order uploads, duplicate/far-future rejection, bounded-stream acknowledgement backpressure, invalid chunk/HTTP framing, cancellation cleanup, proxy acknowledgement/connection-close behavior, padding bounds and header-injection rejection.


## Access token and connection limits

`xhttp.access_token` (optional, same value on both ends) is a shared secret of 16..128 characters from `A-Z a-z 0-9 . _ ~ + / = -`; `eztunnel token` prints a random one. With a token set, the server answers `404` to any request whose session id (or, for the single-request mode, `X-EZ-Auth` header) is not a keyed hash made with the token, before any session resources are used. The session id keeps its 64-hex-character shape: 32 random characters followed by a 32-character keyed hash of them. The token itself is never sent, but a proof seen on the wire can be replayed while its session is open, so use the token together with TLS (`xhttps`, or a CDN that terminates TLS). What a replay can do on plain `xhttp` is limited: a second download request for the same id is answered `409` (the session cannot be taken over), and uploads posted into it are Noise records that fail authentication, so the worst case is that the session ends, which anyone who can inject packets on the path can do anyway. Confidentiality and integrity are not affected.

`xhttp.max_sessions_per_ip` (default 0 = off) limits the sessions one source address may hold, counted until the session ends; use it when the server is reached directly, not through a CDN. A listener without an access token (a `tunnel_key` configuration always has one) logs a warning at start, because anyone who can reach it can then open sessions. The server ends a session as soon as the client closes its download connection; it does not wait for the upload deadline.

`xhttp.max_requests` limits simultaneous HTTP connections overall and `xhttp.max_requests_per_ip` (default 64, `0` = no per-address limit) limits them per source address. Behind a CDN every user appears from a few edge addresses, so raise the per-address value or set it to 0 there.
