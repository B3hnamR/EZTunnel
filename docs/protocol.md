# Protocol, 0.9.0

## Compatibility Boundary

Both endpoints must run the 0.9 protocol. Binaries before 0.9.0 cannot
authenticate with it, and there is no automatic downgrade. Migrate both endpoints
together and keep the old configurations and binaries for a coordinated rollback. Changing `wire_version` does not
cross this protocol boundary.

The byte authority is `src/session_crypto.rs` and `src/transport.rs`. Stream Noise
IK uses `eztunnel/open-source/stream/epochs/v1` followed by one wire-version byte
(1..3) and one parity byte(0). Raw Noise uses
`eztunnel/open-source/raw/epochs/v1` followed by the wire-version and parity byte.
Checker control uses separate domain `eztunnel/open-source/checker/v1`.
Handshake application payloads are empty; configured X25519 peer identities still
authenticate both directions. Logical client remains Noise initiator even when
the server opens the physical connection.

After handshake, concatenate the two 32-byte raw Noise split secrets as HKDF IKM.
Salt is BLAKE3(`eztunnel open-source session keys v1\0` || final handshake hash ||
wire-version byte). HKDF-SHA256 info labels are exact `traffic initiator v1`,
`traffic responder v1`, and for wire3 `wire initiator v1`, `wire responder v1`.
Directional keys replace Noise split keys before the first transport record. No
other input supplies key material. Raw session IDs use the
first 16 bytes of the final handshake hash. Rotation keys remain session-specific.

Stream send direction renews after 300 seconds or 2^20 records. An authenticated
plaintext tag 13 plus U64BE sequential next epoch is sent under the OLD key, then
Noise REKEY changes only that direction's key. Nonces do not reset. Receive
application records require age < 360 seconds and count < 2^20. Duplicate/skipped/short
markers fail the connection. Raw sessions start a fresh handshake at 300 seconds
and reject old-key records at 360 seconds; replay bitmap and fragment/parity state
belong to the new session. Application tag 12 is reserved and rejected.


This describes the eztunnel wire protocol. Both peers must use compatible versions and matching carriers.

## Carrier layer

TCP/TCP6 expose an ordered byte stream; TCP6 additionally requires IPv6 endpoints. KCP provides an ordered stream over UDP. HTTP modes exchange `GET <http_path> HTTP/1.1` with `Upgrade: eztunnel-v1`, receive status 101, and then carry raw encrypted records. WS modes use a standard WebSocket upgrade on the configured path and binary messages; WebSocket message boundaries are not Noise-record boundaries.

XHTTP stream-up exchanges a long chunked POST and a status-200 chunked response. Packet-up uses a random 32-byte session identifier encoded as 64 hexadecimal characters, a persistent chunked GET download and finite numbered POST uploads. Auto probes streaming before falling back to packet-up. Physical HTTP roles can be reversed while logical Noise roles remain unchanged. Chunk boundaries are independent of record boundaries. HTTPS/WSS/XHTTPS add verified TLS below these exchanges. [XHTTP framing](xhttp.md) describes request paths, acknowledgement ordering, limits and cleanup.

`fec-udp` supplies a reliable KCP stream over UDP with a 10+1 Reed-Solomon FEC envelope. `fec-raw` and `fec-raw-gaming` supply that stream over the configured raw IPv4 packet adapter. A clear FEC header contains little-endian sequence/type fields, and the data shard starts with its two-byte little-endian size. Types: `0xf1` data (slots 0..9 of a group of 11), `0xf2` parity of a full group (slot 10). Since 0.8.4 a group that stays partial for `fec.partial_flush_ms` ends with a partial parity in slot 10: first type byte `0xf3`, second byte the number of data shards it covers (1..9); its shard bytes 2..5 carry the KCP conversation as is (the repaired shard gets them back from there), and the next data packet starts a new group. Older receivers ignore type `0xf3`. Raw outer headers and TCP camouflage are described in [raw-protocol.md](raw-protocol.md).

## Wire version 2 (probe resistance)

Selected by `wire_version: 2` on both peers; absent or 1 is the format described in the rest of this file. Version 2 changes only what surrounds the Noise records, not the records or the frames:

- **Stream mask** (every carrier that is not already inside TLS: `tcp`, `tcp6`, `http`, `ws`, `xhttp`, `kcp`, `fec-udp`, `fec-raw`). Each direction starts with printable characters only (alphabet `A-Za-z0-9-_`): a 16-character nonce, two characters that give the pad length (6 bits each, high digit first; `stealth.pad_min` to `stealth.pad_max`, at most 4095 accepted), and that many random printable characters. After the pad, every byte is XORed with a keystream made of 32-byte blocks `BLAKE2s(key || nonce || counter)`, where the nonce is the 16 characters as sent, the counter is the block number (counted from the first byte after the pad) as a 64-bit little-endian integer, and `key = BLAKE2s("eztunnel wire v2\0stream mask\0" || server public key)`. The ordinary records follow, length fields included. The printable start is deliberate: on the Iranian link used for testing, a stream that was uniformly random from the first byte was cut after about 300 bytes (connections made from outside to the Iran server), while a printable start passed.
- **Hold then close.** A connection that fails the handshake is read and discarded for a random time between half of and all of `stealth.probe_hold_sec`, then closed.
- **Names.** The `Upgrade` token of `http`/`https` is the first 6 bytes, in hex, of `BLAKE2s("eztunnel wire v2\0upgrade token\0" || server public key)`. XHTTP request headers are `X-Req-<hex6>` (session proof) and `X-Ref-<hex6>` (upload mode), `<hex6>` from the same derivation with the purposes `xhttp header auth` and `xhttp header upload`. The default `http_path` `/tunnel` becomes `/<hex8>` (purpose `path`). The default XHTTP `user_agent` becomes a browser string. The `tls_auto` certificate name becomes `<hex8>.cdn-edge.net` (purpose `certificate name`) with a validity of 2025 to 2030.
- **Wrong requests.** `http`, `ws` and `xhttp` answer anything that is not a correct request with a plain page (`stealth.decoy_status`, 404 by default) and then hold as above. For `ws`, version 2 reads the HTTP request itself and completes the standard WebSocket handshake.

A version 1 and a version 2 peer cannot pair: the handshake fails and the log suggests checking `wire_version` on both servers.

## Authentication and records

Noise pattern: `Noise_IK_25519_ChaChaPoly_BLAKE2s`, with the prologue and key derivation specified above. The initiator knows the responder's static key; the responder checks the initiator's static key against its allowed list before completing the handshake. Both handshake payloads are empty. Flow control starts with 16 Data frames per stream; a receiver returns Credit 1..16 after delivery. Once opened, each receiver grants `stream_window` minus 16 extra frames; sender maximum 4096. When the server dials KCP/FEC-UDP, it first sends 0x5a to wake the physical listener; the logical client discards it before starting Noise. Tunnel keys are never sent as handshake payloads.

Handshake and transport messages are prefixed by a two-byte unsigned **big-endian** length. Zero-length records are rejected; the maximum encoded record is 65535 bytes. Transport records have a 16-byte authentication tag and Noise-managed directional nonce counters. Modified and replayed records fail authentication. A failed or cancelled record read/write requires discarding the connection; record retries with a reused cipher state are not supported.

## Multiplexing frames

One plaintext record contains one frame. Except heartbeats, frames start with a one-byte tag and a nonzero four-byte big-endian stream ID. The remainder has no extra length field because the record provides the boundary.

| Tag | Frame | Remaining bytes |
| --- | --- | --- |
| 1 | Open | Kind byte (`1` TCP, `2` UDP), then UTF-8 target, 1..1024 bytes. |
| 2 | Opened | Empty. The opener does not have to wait for it: it may send Data (and Eof) for the stream right after Open, within the initial 16-frame window. The receiver registers the stream when Open arrives and queues those frames until the destination is connected, then writes them in order (behind the PROXY header). If the destination fails, it answers Error and drops them. An opener widens its own receive window only after Opened. |
| 3 | Data | 0..16384 payload bytes. |
| 4 | Eof | Empty; TCP write half-close. |
| 5 | Close | Empty. With stream id 0 (the only frame that may use it): goodbye, the sender is stopping and the session ends now. The receiver drops the session and reconnects without waiting for the dead timeout. Peers older than 0.7.8 reject the frame, which also ends the session. |
| 6 | Error | UTF-8 message, at most 1024 bytes. |
| 7 | Ping | Eight-byte big-endian nonce directly after tag; no stream ID. |
| 8 | Pong | Same layout as Ping. |
| 9 | Credit | Four-byte big-endian frame count, 1..16. |
| 10 | Open with PROXY information | TCP only. Version byte (`1` or `2`), the user's address, the address the user connected to, then the UTF-8 target as in Open. Each address is a family byte (`4` or `6`) followed by 4 or 16 address bytes and a two-byte big-endian port; both addresses are of one family. Sent only for a map with `proxy_protocol`; the receiving end writes the PROXY protocol header of that version to the target before any data. Peers older than 0.7.1 reject this tag. |
| 11 | Padded record | One byte of padding length P (0..255), then a complete frame of any other tag, then P padding bytes (zeros; the record is encrypted). Sent only when `stealth.record_pad_max` is set (wire version 2); every receiver of 0.7.1 or later accepts it. A padded record cannot contain another padded record. |

Each side sends a Ping when the session starts, a second one shortly after (two seconds, or half the heartbeat if that is shorter), and then one every `heartbeat_sec`. The quick second Ping lets the manager tell a carrier that is blocked right after the handshake (which passes the first packets) from a working one within a few seconds. Nothing changes on the wire: older peers answer it like any Ping. A session that hears nothing for two heartbeats logs `no traffic from the other server`.

Since 0.8.4/0.8.5 a side also pings outside the heartbeat schedule, with the nonce `u64::MAX` (heartbeats count up from 1 and never reach it): to check an older session of a peer that just connected again (0.8.4), and to ask a session that has been waiting `timeouts.probe_sec` for any answer (0.8.5). The answer is not matched; any frame from the peer counts. A session waiting twice that long is *suspect*: it gets no new users, and the side that dialed it opens a fresh connection and replaces it if the fresh one works while it is still silent. Nothing changes on the wire.

Unknown tags, invalid IDs, invalid UTF-8, oversize payloads, wrong fixed lengths, and trailing bytes on fixed-size frames are rejected. Each UDP Data frame represents one complete datagram. TCP Data frames may split application writes. Credits bound unconsumed data per stream. Control and close processing must not turn a slow target into an unbounded queue.

TUN mode over a stream carrier carries each IP packet in a Data frame with stream ID 1, with Ping/Pong for liveness. There is no Open/Opened exchange or port-forwarding credit negotiation in this mode. With the dedicated `tun` raw carrier, packets use independent authenticated datagrams and a replay window instead of ordered records; [raw-tun.md](raw-tun.md) specifies this framing. IP version, declared packet length, and configured MTU are checked before injection. Configure TUN consistently on both ends; it is not negotiated automatically with a forwarding peer.
