# Transport checker

Finds which transports work between your two servers, in which direction, and how well, before
you create a tunnel. Every check starts a real, temporary tunnel with the same settings the
new-tunnel wizard writes, so a transport that passes here works as a tunnel. Only the two servers
are contacted, and everything the checker opens is removed afterwards.

## Running a check

1. On either server: `sudo eztunnel` → **Tools → Transport checker → Start a check**. Say which
   server this is and the other server's IP, confirm this server's public IP, choose **Find** or
   **Tune** (below), how deep and what matters most in the results. You get a **check code**
   (`ezc1-…`).
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

### Find and tune

A check has one of two jobs:

| Mode | Checks | Use it |
|---|---|---|
| **Find transports** (default) | every transport with the settings the wizard writes | first, to see which transports work on the route |
| **Tune transports** | the transports you pick, each with every option it has, every case twice | after a find check, to see which setting of a working transport is best |

What tuning tries per transport, besides its default settings:

| Transport | Options |
|---|---|
| wss, https, xhttps | browser-like TLS look, split ClientHello (TLS fragmentation), `tcp_congestion` cubic, [Game mode](game-mode.md) |
| tcp, ws, http, xhttp | `tcp_congestion` cubic, Game mode |
| parallax | packet mode, `tcp_congestion` cubic, Game mode |
| fec-udp | the adaptive pacer, Game mode |
| kcp | Game mode |
| fec-raw | the adaptive pacer |
| raw TUN | each chosen packet type, and packet splitting with an MTU of 4000 |

A Game mode case sends its UDP measurement over Game mode's datagram copies. It needs the port
after the case port free on both servers (TCP and UDP on the Iran server, UDP on the foreign
server). The case waits up to 10 seconds for the datagram path after the handshake and counts only
when its own UDP measurement went over it: a Game mode case whose UDP fell back to the tunnel is
shown as blocked, with the reason. Compare its UDP loss and p95 with the case without it.

A tune check runs every case in **2 rounds** (1 to 3 in Custom), one round after the other, because a
single run on a real route varies too much to rank close options. The results then show, for each
transport, every option and direction averaged over its rounds, best first: how many rounds it
worked, download and upload, ping and UDP loss. "Create a tunnel" takes the best option with it.

The results of a find check offer **Tune the best 3**: a new check of the three best transports, with
the same measurements, in tune mode. A tune check started from the menu preselects the best
transports of the last find check between the same two servers.

### How deep

The depth is the same for both modes:

| Preset | Measurements | Time for the 9 default transports in both directions |
|---|---|---|
| Quick | handshake, 5 pings | about 2 min |
| Standard | 10 pings, download and upload 5 s each, 30 s stability hold, failed cases repeated once | about 15 min |
| Thorough | Standard plus 4 downloads at once, 60 s hold, baseline and path MTU | about 25 min |
| Custom | every choice below | |

A tune check takes about as long per case; the case count and the estimate are shown before it
starts. Custom lets you choose:

- **Transports**: tcp, wss, https, xhttps, ws, http, xhttp, kcp, fec-udp, fec-raw and
  raw TUN. fec-raw and raw TUN need root on both servers and IPv4 addresses. IPv6 is not a separate
  transport here: see IPv4 and IPv6 below. Raw TUN is checked once per chosen packet type (tcp, udp, icmp, gre,
  ipip, raw, dns): each case creates a TUN interface `ezchk0` (10.234.170.1 ⇄ .2, MTU at most 1280) on both
  servers and measures through the forwarding service inside it, as the wizard's "TUN + ports" does;
  the interface disappears when the case ends.
- **Directions**: the foreign server dials (reverse tunnel), the Iran server dials (direct tunnel),
  or both. Raw transports send packets both ways and are checked once.
- **Parallax** is checked in both of its modes, stream and packet, so the report shows which one
  suits the route ([Parallax](parallax.md)); Custom can leave packet mode out.
- **Measurements**: pings (count), download and upload speed (seconds each), four downloads at once,
  stability hold (a ping every 2 s for the chosen time), a baseline of plain TCP/UDP with the largest
  packet that crosses the path (the link test's MTU sweep), repeating a failed case once, the
  TLS transports again with the browser-like TLS fingerprint or a split ClientHello, the TCP-based
  transports again with `tcp_congestion` set to `cubic` (0.8.11), the `fec-udp`/`fec-raw`
  cases again with the adaptive pacer on (0.8.11; plain `kcp` does not use the
  pacer, so it gets no pacer case since 0.9.13), and raw TUN again with packet
  splitting on and the MTU raised to 4000 (well past one outer packet's budget, so the case needs a
  real split and reassembly, 0.8.11). Only the extra checks that fit the chosen transports are
  offered. In tune mode every one of them runs anyway, and Custom asks for the rounds instead.
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

The raw transports (fec-raw and raw TUN) are part of every preset when the check runs
as root and both addresses are IPv4; otherwise they are listed as not available, with the reason.

## IPv4 and IPv6

A route can drop one address family and carry the other, or let only one server open
connections. In the dashboard, **Address family** applies to both Find and Tune. **IPv6** runs the
control link and all selected cases over IPv6, and requires both servers to report an IPv6 address.
Find and Tune let you select the transports to run over IPv6.
**IPv4 + IPv6** compares both families using an IPv4 control link. It is the default when both
servers report IPv6. Raw-socket transports are available only for IPv4 cases. The terminal checker
asks for the other server's IPv6 address when this server has one and includes IPv6 cases when given.
The results start with one line per family and direction that was tried, for example
`IPv4 direct: blocked, IPv4 reverse: works, IPv6 direct: works` ("direct": the Iran server dials;
"reverse": the foreign server dials), and IPv6 cases are named "over IPv6". Creating a tunnel from
an IPv6 result makes it on the IPv6 address.

## When the servers cannot reach each other

The two servers coordinate a check over a control connection (TCP port 47100 by default) before
any test tunnel starts. While one waits for the other, it looks at the path every 45 seconds (ping
and TCP on 22, 80, 443, 8443 and the control port) and says why the other server has not joined:
no path at all, a control port that gets no answer, or simply that the other side has not joined yet.

When the servers cannot reach each other on the control port but your computer reaches both, choose
**Through my computer over SSH** when the checker asks how the two servers coordinate. It shows one
command to keep running on your computer:

```sh
ssh -N -R 47101:<other server's IP>:47100 root@<this server>
```

This server's local port 47101 then leads, through your computer, to the other server's control
port. Do it for one of the two servers only. If your computer cannot reach the other server's port
47100 directly, use two windows instead: `ssh -N -L 47102:127.0.0.1:47100 root@<other server>` and
`ssh -N -R 47101:127.0.0.1:47102 root@<this server>`.

Only the control messages take this way. Every test tunnel still connects the two servers directly,
so each transport gets its real result; when nothing gets through between them, every row says so.

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
with the server, direction, transport, port, the tested option and the other server's address
filled in; its pairing code sets up the other server as usual. After a tune check the results
list every transport's options best first instead, each averaged over its rounds; a case of a
later round shows its round after its name (`wss (TLS fragment) #2`).

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

# then tune the ones that worked
sudo eztunnel check start --role iran --this-ip 203.0.113.10 --peer-ip 198.51.100.20      --mode tune --transports wss,parallax,fec-udp --json tune.json
```

Options: `--mode find|tune` (tune needs `--transports`), `--rounds 1..3`, `--no-udp`, `--preset
quick|standard|thorough`, `--transports` (comma separated), `--tun-types` (comma separated raw TUN
packet types), `--directions both|iran|foreign`, `--tls-port`, `--port`, `--control-port`,
`--priority stability|speed|hiding|lossy`, `--also-browser-tls`, `--also-tls-fragment`,
`--also-congestion`, `--also-pacer`, `--also-fragment`, `--also-game` (the re-checks described above),
`--no-parallax-packet`, `--json FILE`, `--control-via ADDRESS:PORT` (reach the other server's
control port through a forward, as described in "When the servers cannot reach each other"; also on
`check join`). Progress goes to standard error one line per step, the
report to standard output. Ctrl+C stops the check and removes the test tunnels.

## Safety

- Each case's tunnel runs inside the checker's own process; its port map listens on 127.0.0.1 only
  and its far end may only reach the checker's test service on 127.0.0.1.
- Ports are checked free before use. Existing tunnels and their ports are never touched.
- fec-raw cases add the same two firewall rules the wizard adds, and remove them when the case ends.
- The control link and every test tunnel are authenticated with the check's key; strangers that
  connect to the control port fail the handshake.
- Nothing is sent anywhere except between the two servers.
