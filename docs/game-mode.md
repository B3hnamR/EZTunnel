# Game mode

Game mode is the one choice for a tunnel that carries games. Turn it on and the users' game UDP
takes its own fast path between the two servers, instead of the tunnel's ordered stream:

- **Datagrams, not a stream.** Each game packet travels as its own authenticated, encrypted
  datagram. A packet that is lost or late never holds the next one back, which is what a reliable
  stream does (one resend delays everything behind it).
- **Copies over different ports.** Every packet is sent in 3 copies (1 to 4), each from its own UDP
  port. A route treats each port pair as a separate flow and may send them different ways, so the
  copies take different paths; the receiver uses whichever copy arrives first and drops the rest.
  This beats both packet loss and a slow path. It costs the game's own bandwidth times the copies,
  which for games is small (tens to a few hundred kbit/s per player).
- **The fastest timer for the rest.** On carriers with speed modes (kcp, fec-udp, the raw FEC
  carriers, Parallax packet mode) Game mode also selects `fast3`, for the game's TCP and the path's
  control connection.

Everything else (web, downloads, game TCP) still goes through the tunnel as before.

## Turning it on

- **New tunnel, terminal:** pick the **Gaming / low delay** settings profile, or turn on
  **Customize → Game mode**.
- **Saved tunnel, terminal:** **Manage tunnels → the tunnel → Change settings → Game mode**.
- **Dashboard:** **Carrier options → Game mode** when creating a tunnel, and **Edit → Carrier →
  Game mode** for a saved one.
- The **pairing code** carries Game mode to the other server.

Both servers need it, with the same port and copies. It needs users' UDP in the tunnel: forwarded
UDP ports (UDP, or TCP and UDP) or SOCKS5. With a proxy or VPN between the players and the tunnel,
use a protocol that keeps game UDP as UDP packets; one that wraps UDP inside a TCP connection sends
it through the tunnel's stream and does not reach the fast path.

## Ports

Game mode uses one port, by default the tunnel port + 1. On the Iran server it is TCP (a short,
authenticated control connection) and UDP (the datagrams); on the foreign server UDP. Open it in
both servers' firewalls. The foreign server connects to the Iran server's control port, also in a
direct tunnel, and sends its datagrams to the Iran server's IP address. When the tunnel itself
does not give that IP (a direct tunnel, a host name, or a CDN in between), Game mode asks for it;
the pairing code and the dashboard fill it in where they know it. A host name cannot be used here.
The foreign server's game socket uses the same address family (IPv4 or IPv6) as that IP. The
extra copies leave from random local ports, which need no opening.

Game mode uses the same port for the control connection and the datagrams. A hand-made `gaming`
block with separate ports works, but it is endpoint-local: it is not put in a pairing code.

## Configuration

Game mode writes the `gaming` block of [Adaptive paths and gaming](transport-upgrade.md):

```json
// Iran server
{"gaming": {"control_address": "0.0.0.0:7001", "udp_bind": "0.0.0.0:7001", "copies": 3}}
// foreign server
{"gaming": {"control_address": "IRAN-IP:7001", "udp_bind": "0.0.0.0:7001", "copies": 3}}
```

Without `advertise`, each server announces the address the other one reached it at during the
authenticated control handshake, so no public address has to be configured.

## What it fixes, measured

On a test route between an Iran and a foreign server, 128 game packets per second:

| Game UDP path | Round trip | Delivered |
|---|---|---|
| through the tunnel's stream | 104–198 ms (varies by run) | ~98% |
| Game mode, 1 copy | 79 ms | 80–94% |
| Game mode, 3 copies | 79 ms | 90–99% |

The direct UDP round trip of that route was 79 ms: with Game mode the game sees the route's own
ping. The status (`gaming_copies_absorbed`, `gaming_packets_received`) shows the race at work.
