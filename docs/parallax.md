# Parallax

Parallax carries the tunnel over real TCP connections between the two servers ("lanes"). It
has two modes. Both servers must use the same one.

| | Stream mode (default) | Packet mode |
|---|---|---|
| Lanes | Two per tunnel connection: one upload, one download | `lanes` per tunnel connection (default 2) |
| Reliability | Kernel TCP retransmits | The tunnel's own KCP with 10+1 error correction, above the lanes |
| A lane breaks | The tunnel connection ends and is built again; open streams end | The lane is dialed again; the tunnel connection and its streams carry on |
| First bytes of a lane | Handshake, then data | Handshake, then encrypted padding of a random size, then data |
| Settings | `parallax.*` | `parallax.*` plus the `fec` object (MTU, windows, timing) |

## Packet mode

In packet mode each tunnel connection is one KCP session with forward error correction, the same
reliable stream the FEC carriers use. Its packets travel as small encrypted records over several
TCP lanes at once:

- **One receive path.** A packet may arrive on any lane; they all feed the same session.
- **Sticky lanes.** Packets stay on one lane while it keeps up, so KCP does not see reordering.
  They spill to another lane when that lane's queue fills or the lane is gone.
- **Lanes are replaced on their own.** A lane that breaks, or that receives nothing for 4
  seconds (a silent stall, with no reset), is dialed again (after 0.25 s, backing off to 5 s). What it had queued is lost and KCP
  resends it, so a stream in flight completes intact. The tunnel connection ends only when the
  usual `dead_timeout_sec` passes with no lane working.
- **Idle lanes stay alive.** A lane with nothing to send sends a small padding record every
  second, so a lane that a middlebox dropped is noticed within seconds, before the tunnel would
  give up on its connection and the streams on it.
- **Warm-up.** Each side starts every lane with encrypted padding of a random size between
  `warmup_min` and `warmup_max` bytes (default 32 KiB to 64 KiB). The size changes per lane and
  the bytes are encrypted, so there is no fixed pattern.

Each lane authenticates with `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` under a key derived from the
tunnel key, and every record is encrypted and authenticated. The answering server adds a lane to
its session only after the first record under the new keys, and sends nothing (not even its
warm-up) before that record, so a recorded handshake replayed on a
new connection never carries traffic. Later lanes of a session must come from the same address
as its first lane. The tunnel's own Noise IK session runs inside, unchanged.

Both directions work: with `server_dials` the server opens the lanes.

### Settings

In `parallax` on the listener and the path:

| Setting | Default | Range | Meaning |
|---|---|---|---|
| `mode` | `stream` | `stream`, `packet` | Must match on both servers. |
| `lanes` | 2 | 1..16 | Packet mode, dialing side: TCP lanes per tunnel connection. |
| `warmup_min` | 32768 | 0..1048576 | Packet mode: smallest warm-up this side sends, in bytes. |
| `warmup_max` | 65536 | 0..1048576 | Packet mode: largest warm-up; 0 and 0 turn it off. |
| `handshake_timeout_sec` | 10 | 1..60 | Deadline for one lane's handshake. |
| `max_pending`, `max_pending_per_ip` | 128, 16 | 2..4096 | Lanes still in their handshake, in total and per address. |
| `max_sessions` | 64 | 1..4096 | Packet mode: tunnel connections the server keeps lanes for. |

`buffer_bytes` applies to stream mode only. Packet mode reads the `fec` object for MTU, windows,
timing and `partial_flush_ms`, as in [FEC tuning](fec-tuning.md); the UDP knock does not apply.

Example:

```json
{"addr": "203.0.113.10:443", "transport": "parallax", "parallax": {"mode": "packet", "lanes": 3}}
```

In the manager, pick **Parallax** and then the mode. For a saved tunnel the mode is under
**Manage tunnels → Change settings**. The pairing code carries it to the other server. In the
dashboard, the mode is among the carrier options of a new tunnel and of **Edit**. The transport
checker tests Parallax in both modes, and its tune mode compares them in rounds.

### Which mode to use

Start with the transport checker. Packet mode suits routes where long TCP connections get cut or
stall: a cut costs a moment instead of every open stream. Stream mode uses less CPU, since kernel
TCP does the retransmitting.
