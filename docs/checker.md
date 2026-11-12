# Transport checker

Finds which transports work between your two servers, in which direction, and how well, before
you create a tunnel. Every check starts a real, temporary tunnel with the same settings the
new-tunnel wizard writes, so a transport that passes here works as a tunnel. Only the two servers
are contacted, and everything the checker opens is removed afterwards.

## Running a check

1. On either server: `sudo eztunnel` → **Tools → Transport checker → Start a check**. Say which
   server this is and the other server's IP, confirm this server's public IP, pick what to check and
   what matters most in the results. You get a **check code** (`ezc1-…`).
2. On the other server: **Tools → Transport checker → Join a check**, paste the code. The screen
   shows what will run; confirm.
3. Both screens show the same live view until the check ends, then the results.

Both servers must run the same EZTunnel version: a newer one sends results an older one cannot
read. When they differ, the check stops right after the servers find each other and both screens
say which version each one runs (the command line exits with code 1). Servers before 0.8.4 only
note the difference in their log and stop when the newer side leaves.

The code holds a key made for this check only; it is not a tunnel key and is thrown away at the end.
The servers find each other on the **control port** (TCP 47100 by default): both listen on it and
both try to reach the other, so it is enough that one direction is open.

### What to check

| Preset | Measurements | Time for the 9 default transports in both directions |
|---|---|---|
| Quick | handshake, 5 pings | about 2 min |
| Standard | 10 pings, download and upload 5 s each, 30 s stability hold, failed cases repeated once | about 15 min |
| Thorough | Standard plus 4 downloads at once, 60 s hold, baseline and path MTU | about 25 min |
| Custom | every choice below | |

Custom lets you choose:

- **Transports**: tcp, wss, https, xhttps, ws, http, xhttp, kcp, fec-udp, fec-raw, fec-raw-gaming,
  raw TUN and tcp6. fec-raw and raw TUN need root on both servers and IPv4 addresses; tcp6 needs the
  IPv6 addresses of both servers. Raw TUN is checked once per chosen packet type (tcp, udp, icmp, gre,
  ipip, raw, dns): each case creates a TUN interface `ezchk0` (10.234.170.1 ⇄ .2, MTU at most 1280) on both
  servers and measures through the forwarding service inside it, as the wizard's "TUN + ports" does;
  the interface disappears when the case ends.
- **Directions**: the foreign server dials (reverse tunnel), the Iran server dials (direct tunnel),
  or both. Raw transports send packets both ways and are checked once.
- **Measurements**: pings (count), download and upload speed (seconds each), four downloads at once,
  stability hold (a ping every 2 s for the chosen time), a baseline of plain TCP/UDP with the largest
  packet that crosses the path (the link test's MTU sweep), repeating a failed case once, the
  TLS transports again with the browser-like TLS fingerprint or a split ClientHello, the TCP-based
  transports again with `tcp_congestion` set to `cubic` (0.8.11), the `fec-udp`/`fec-raw`/
  `fec-raw-gaming` cases again with the adaptive pacer on (0.8.11; plain `kcp` does not use the
  pacer, so it gets no pacer case since 0.9.13), and raw TUN again with packet
  splitting on and the MTU raised to 4000 (well past one outer packet's budget, so the case needs a
  real split and reassembly, 0.8.11).
- **Ports**: TLS transports (wss, https, xhttps) use the first free of 443, 8443, 2053, 2083, 2087
  and 2096, and the HTTP ones (ws, http, xhttp) the first free of 80, 8080, 8880, 2052, 2082, 2086
  and 2095: the ports Cloudflare proxies, which filters treat as ordinary web traffic. The others
  use a free random port per case. Some filters block by port, so you can enter the port you plan
  to use instead. The port each case used is shown next to its transport. The control port is also
  yours to choose.
- **Slow below**: a working transport under this many Mbit/s (the slower direction) is called slow.
- **What matters most** (ranking): stability, speed, hiding (looks like ordinary web traffic), or a
  lossy path (error correction first).

Every screen goes back: each list and checklist ends with a "← Back" row (Esc does the same), and
an empty answer on a typed question goes back. In a checklist Enter turns the row under the cursor
on or off; "all / none", "✔ Done" and "← Back" are the last rows. Going back from a checklist leaves
the options as they were.

The raw transports (fec-raw, fec-raw-gaming and raw TUN) are part of every preset when the check runs
as root and both addresses are IPv4; otherwise they are listed as not available, with the reason.

## The live view

```
  Transport checker   Iran 203.0.113.10 ⇄ foreign 198.51.100.20   ● running  03:12 / ~05:00 left
  ──────────────────────────────────────────────────────────────────────────────────────────────
   Transport                Dials    Handshake RTT ms     Conn ms ↓ Mbit/s ↑ Mbit/s UDP loss % UDP p95    Hold  Result
   tcp :27962               foreign     182 ms     88     181/187       87       81        0/0     301   15/15  ✔ works
 ▸ wss :8443                foreign     341 ms     89     172/174       80       80        0/-       -    6/15  … stability hold 12 of 30 s
   ws :8080                 foreign     256 ms      -           -        -        -        -/-       -       -  ✘ blocked after handshake
   fec-udp                  foreign          -      -           -        -        -        -/-       -       -  waiting
  ──────────────────────────────────────────────────────────────────────────────────────────────
  ▸ wss · foreign dials · stability hold 12 of 30 s · 0 failed
  [p] pause  [s] skip case  [l] log  [d] details  [↑↓] select  [q] stop
```

| Key | Does |
|---|---|
| p / r | pause after the current step (during a hold: after the current ping) / resume |
| s | skip the case that is running |
| q | stop the check (press twice); the results so far are kept |
| l | show the log of the test tunnels under the table |
| d, Enter | details of the selected (or running) case: errors, heartbeats, runs |
| ↑ ↓ | select a case |
| Ctrl+C | the same as stop: the test tunnels are removed first |

Either server can press the keys; they apply to both. If the connection between the servers drops,
both remove the running case and reconnect for up to a minute, then run that case again.

## Results

| Result | Meaning |
|---|---|
| works | handshake, every ping, both transfers and the hold passed |
| reachable | connects and answers every ping, but no speed test or hold ran (Quick): bulk data may still be blocked |
| works, unstable | works, but pings were lost, the hold saw failures or reconnects, or it failed once of two runs |
| works, slow | works, but slower than your threshold |
| bulk blocked | small requests pass, transfers stall or reset |
| download only / upload only | one direction of bulk data gets through |
| blocked after handshake | the handshake passes, then nothing does |
| no handshake | nothing gets through |
| not possible here | the case cannot run on these servers (the note says why: root, port in use, IPv6) |

The results screen lists the best three transports for your priority (one line per transport, its
best direction), what is blocked, and offers **Create a tunnel with …**: the new-tunnel wizard opens
with the server, direction, transport, port and the other server's address filled in; its pairing
code sets up the other server as usual.

**RTT** is the tunnel's own round trip (the median of its heartbeats), the number to compare with
`ping` between the servers. **Conn** is what a new connection costs until its first answer (median /
worst of the pings): the tunnel first opens the stream at the far side, so a new connection takes
one round trip more than RTT (about twice the RTT); later requests on an open connection take one
RTT.

**UDP loss %** and **UDP p95** come from 300 small UDP packets (100 per second, 120 bytes) sent through
the test tunnel to an echo on the foreign server, once while nothing else runs and once during the
download (500 packets over the speed test): the column shows idle/loaded loss, and the 95th
percentile round trip in ms (under load if measured). A packet that comes back after more than a
second counts as lost, like a call or a game would see it. Carriers that run over TCP (tcp, wss,
xhttp ...) re-send what the network drops, so they show no loss but a long p95 when the link is full;
the UDP carriers (kcp, fec-udp, raw TUN) show real loss and keep the delay low. A case where no UDP
packet comes back gets the note *UDP not carried*. With the *Lossy path* priority the ranking puts
measured loss first (whole percents). The measurement adds about 3 seconds per case; leave it out
with the *UDP loss and delay* row of the measurements list, or `--no-udp` on the command line.

Speeds are measured where the data arrives (download on the Iran server, upload on the foreign
server), so data still queued on the way does not count. The handshake time is measured by the side
that dials.

Reports are saved as JSON and text in `/var/lib/eztunnel/checks/` (the newest 20) and listed under
**Transport checker → Past checks**.

## Command line

```sh
# on the Iran server
sudo eztunnel check start --role iran --this-ip 203.0.113.10 --peer-ip 198.51.100.20 \
     --preset standard --transports tcp,wss,kcp,fec-udp --directions both --json report.json
# prints: eztunnel check join ezc1-...   (run that on the foreign server)
```

Options: `--no-udp`, `--preset quick|standard|thorough`, `--transports` (comma separated), `--directions
both|iran|foreign`, `--tls-port`, `--port`, `--control-port`, `--priority
stability|speed|hiding|lossy`, `--also-congestion`, `--also-pacer`, `--also-fragment` (0.8.13, the
three re-checks described above), `--json FILE`. Progress goes to standard error one line per step, the
report to standard output. Ctrl+C stops the check and removes the test tunnels.

## Safety

- Each case's tunnel runs inside the checker's own process; its port map listens on 127.0.0.1 only
  and its far end may only reach the checker's test service on 127.0.0.1.
- Ports are checked free before use. Existing tunnels and their ports are never touched.
- fec-raw cases add the same two firewall rules the wizard adds, and remove them when the case ends.
- The control link and every test tunnel are authenticated with the check's key; strangers that
  connect to the control port fail the handshake.
- Nothing is sent anywhere except between the two servers.
