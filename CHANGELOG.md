# Changelog

## 0.9.14 (2026-11-11)

- KCP/FEC: `flush` hands data to KCP and returns again; only shutdown waits for the queued
  tail (the 0.9.13 tail-loss fix made every tunnel record wait for the KCP send window, which
  under load or path loss stalled the session writer: offline A/B with 2% loss, saturated
  tunnel, UDP loss 22.8% -> 19.0% and TCP 61.8 -> 65.3 Mbps with the fix).
- Guided Mirage test: a connection that completes the handshake but sends no encrypted Start
  within 10 s (such as a replayed first flight) is dropped and the host keeps waiting for the
  real peer, instead of ending the session. The invitation is still consumed only by a valid
  Start (live check on two servers showed the old host ended 30 s after a replay).

## 0.9.13 (2026-11-11)

Fixes from the 2026-11-10 source review (48 correctness findings, 14 security leads).
No wire-format change; 0.9.x peers interoperate.

- Checker: failed parallel downloads and heartbeat-only UDP no longer count as working;
  loaded UDP is reported only for a completed download; parallel-only runs are valid;
  a stopped/skipped/not-possible retry keeps its own result; the measured variant is the
  wizard's starting point and manual edits are kept; plain `kcp` gets no no-op pacer case;
  diagnostic firewall commands have a killable wall deadline.
- KCP/FEC: ACK-only tails are flushed; timeout bursts are spaced; shutdown and drop drain
  accepted data (bounded 10 s); plain-KCP UDP output is bounded; closed sockets ignore
  input; a buffer error no longer loses the tuner's window change.
- Raw TUN: the exact startup MTU packet is sent as one packet; fragment IDs cannot wrap
  inside the receive window. Mirage repair dedup no longer refuses fresh groups.
- Traffic counters: reliable UDP, SOCKS UDP and TUN traffic count toward the quota; on a
  TUN with `forwarding_port` only the inner forwarding TCP flow is left to the inner relay.
- Admission: per-IP reservation applies to the map/SOCKS resource that refuses users; an
  answering side takes its connection slot, packet-lane publication and gaming channel
  admission only after a record under the fresh session keys (replayed first flights
  cannot hold them); a gaming Close before the first Data blocks that Data.
- XHTTP stream-up uses the proxy-tolerant chunk decoder (extensions, trailers, chunks up to
  16 MiB). tlscheck ignores edge/local-address overrides and cancels its tasks.
- Manager: firewall disable keeps its unit until no tagged rule remains; tunnel stop stops
  the firewall unit; UFW offers remote SOCKS only; persisted UDP ceilings never lower a
  larger value; installation errors reach the previous-settings recovery; quota reset
  stops first; nested extension edits keep hidden fields; legacy Mirage conversion is
  transactional and TCP-only; imported TUN pairings keep the agreed port; lossy compact
  pairing codes are refused; bulk changes apply the default number; fragmented TUN MTU is
  not capped to one packet; configuration backups are atomic.
- Build: the x86-64 static browser-TLS build uses one consistent musl C/C++ toolchain
  (`scripts/build-x86_64-musl.sh`); the glibc libstdc++ shim is removed.
- Docs: UFW narrowing, pacer scope, current version baseline, XHTTP retry/budget contract,
  third-party notice index, and spacing fixes.

## 0.9.12 (2026-11-10)

- Reorganized the README around installation, guided setup, transports, Mirage testing
  and diagnostics.
- Added a GitHub latest-release installer with archive checksum and CPU checks, atomic
  replacement and a backup of the previous binary. It never restarts tunnels or changes tuning.

## 0.9.11 (2026-11-10)

- Guided Mirage tests: every attempt writes its own private worker log, so a failed earlier
  attempt no longer blocks a retry. Existing logs and reports are never overwritten.

## 0.9.10 (2026-11-10)

- Pasted pairing, setup and invitation codes and source lists are shown in full while typing
  and wrap across rows. Long input shows its last rows while editing and the whole text on submit.

## 0.9.9 (2026-11-10)

- Guided Mirage: the Iran invitation stays on screen until Enter, and `i` in the live view
  shows the same code again without stopping the worker. An expired code is explained
  instead of silently replaced.

## 0.9.8 (2026-11-10)

- Long pasted input shows a scrolling tail and a character count instead of wrapping into
  repeated confirmation lines.

## 0.9.7 (2026-11-09)

- New terminal input: bounded foreground-terminal reading with bracketed multi-line paste,
  UTF-8 backspace, cancellation and terminal restoration. Fixes the manager dropping back to
  the shell during a paste.

## 0.9.6 (2026-11-09)

- Unified Mirage peer-code import with New tunnel -> Paste a pairing code.
- Added consistent Save and start defaults for measured Mirage creation and peer
  import, with Save only available and startup errors reported without deleting
  the saved configuration. Running and peer-connected remain distinct states.
- Added checker-style Mirage live/saved viewports with bounded rows, elapsed
  progress, direction/filter/details/log keys and confirmed cancellation.
- Merged Link test listener/probe entries into one submenu; Tools now use colored
  text categories and typed action routing without dropping either workflow.
- Added compact non-echoed long-list/code input to avoid wrapped duplicate
  confirmations and accidental secret-code echo. Existing transports/protocols
  and legacy pairing remain supported.

## 0.9.5 (2026-11-09)

- Fixed Manage tunnels -> Start for configurations saved without a systemd unit,
  including guided Mirage results and imported peer setup codes. Explicit Start
  now installs the missing unit before starting; existing units are not rewritten.
- Start checks that the service remains running and distinguishes process startup
  from peer connectivity. Save/import still does not start services automatically.

## 0.9.4 (2026-11-09)

- Added guided Mirage start/join sessions with expiring one-run invitations,
  automatic private files/keys, per-direction progress and saved partial results.
- Added transparent result ranking, extended retests, and measured-result tunnel
  creation with fresh keys and reciprocal expiring peer setup codes.
- Added explicit peer import preview/consent and save-only behavior; no service
  or firewall changes start automatically from the guided result workflow.
- Simplified Mirage basic setup; expert tuning remains optional and existing
  source/shaping settings are preserved when edited. Legacy v1 remains supported
  for existing configurations, not promoted as a normal new-tunnel choice.
- Preserved ordinary0.9.3transport/mux/Noise protocols and manual tester CLI.

## 0.9.3 (2026-11-07)

- Added opt-in Mirage v2 with TCP, UDP, ICMP, echo-shaped protocol58, bare BIP58,
  GRE and IPIP, and independent Foreign->Iran/Iran->Foreign profile selection.
- Separated real peer routing from transmitted spoof source/source pools and
  expected incoming source sets. Legacy Mirage v1 meanings remain unchanged.
- Added authenticated option contracts, bounded replay admission, source-port
  shuffle, TTL/DSCP, optional padding/fake-TLS shaping and systematic datagram repair.
- Added bounded authenticated directional `spooftest` with explicit per-candidate
  receipt/loss/raw-return RTT and manager settings generation/workflows.
- Preserved inner Noise security, mux and ordinary0.9.2compatibility. No firewall,
  route or kernel setting is changed automatically. Read docs/mirage.md.
- XDP classifier feasibility tested only on disposable interfaces; no production
  receive accelerator or live attachment is supplied or claimed.

## 0.9.2 (2026-11-07)

- Added full Linux ARM64 static builds alongside x86-64, with default browser TLS
  and all six optional0.9.1transport capabilities retained.
- Added architecture-aware installation and packaging; wrong CPU binaries are
  rejected before execution or destination writes. Packages derive architecture
  from ELF metadata, not the build host.
- Tightened updater ELF validation to64-bit little-endian headers and retained
  strict release signature and same-machine checks.
- Added documented ARM64 cross-toolchain configuration. No protocol or default
  transport behavior changed; no production services are updated automatically.

## 0.9.1 (2026-11-06)

- Optional FEC adaptive controller with actual KCP telemetry and shared path bandwidth allocation.
- Optional authenticated TCP packet fallback and bounded authenticated adaptive raw ports.
- Optional Noise-negotiated direct gaming UDP with stable flow migration, explicit local
  authenticated port rebind, bounded fragmentation and queue/replay/tombstone limits.
- Added local status counters and manager configuration for transport extensions.
- Defaults keep 0.9.0 stream/mux compatibility; 0.9.0 peers need no new frames.
- Extension endpoints/ports must be configured explicitly on both sides; no host firewall,
  sysctl, routes or services are changed automatically. See docs/transport-upgrade.md.

## 0.9.0 (2026-11-05)

- New session protocol: fresh Noise prologue domains, HKDF directional traffic keys and
  per-session wire 3 rotation. Both endpoints must update together; earlier versions cannot
  connect.
- Authenticated Noise handshakes, stream rekey epochs, raw session renewal and replay
  protection work with every carrier and tool: Parallax, Mirage, raw/TUN, FEC/KCP, steering,
  the transport checker and the manager.
- The updater keeps verifying official release signatures; ordinary update and rollback
  cannot cross the 0.9.0 protocol boundary.
- Refreshed Linux dependency notices.

## 0.8.18 (2026-10-27)

- Transport hardening: key holders and temporary buffers are zeroized, `tunnel_key_file` must
  be private, key derivation has golden test vectors, and tunnel TLS connections use TLS 1.3 only.

## 0.8.17 (2026-10-22)

- Added a credit line under the banner's version/tagline on every top-level screen: "made by
  B3hnamR · Telegram @B3hnamR".

## 0.8.16 (2026-10-19)

22 correctness and robustness fixes found by an independent code review and verified directly
against this source tree before fixing. Grouped by what they protect:

- **Quota**: the saved transfer count is now fsync'd before being swapped into place, and a
  damaged or unreadable count file is logged instead of silently restarting the period at zero.
  A fast tunnel is now checked against the limit every 500ms instead of only every 10s, cutting
  how much it can carry past the limit before it is stopped. A clock moved back by more than an
  hour now logs that it reset the period, instead of doing so silently.
- **Saved-tunnel validation**: a manager-saved reverse tunnel with a client path bound to port 0
  (unreachable by its peer) is now rejected, matching the existing check for listeners. Bind-
  conflict detection now catches an IPv6 wildcard colliding with an IPv4 bind on the same port
  (Linux's `IPV6_V6ONLY` is off by default) and an IPv4-mapped IPv6 literal colliding with the
  plain IPv4 address it really is on the wire.
- **Transport checker**: a stolen free-port race between the baseline's own port probe and its
  real listener is now detected and reported, instead of silently claiming the baseline is ready
  when it never bound. A ping-retry loop during the stability hold's settle phase no longer busy-
  spins. Checker reports (server IPs, which transports are blocked) are now written 0600 like the
  tunnel configs they sit next to, not world-readable.
- **New-tunnel wizard**: importing a pairing code for a Foreign-side SOCKS5 tunnel now opens it to
  the whole internet like the step-by-step wizard already does, instead of leaving it restricted
  to the foreign server's own localhost. TUN `forwarding_port` is now picked from a free-port scan
  instead of a hardcoded value a second TUN tunnel would silently collide with; a busy `socks_bind`
  is now warned about. A forwarded port's busy-check now covers UDP too when the protocol is
  "Both", not just TCP, and the re-ask after a busy-port warning is now actually re-checked instead
  of being accepted unconditionally.
- **Optimize this server**: a damaged backup of the pre-optimization values is now a hard error in
  both Apply and Undo (previously Apply silently treated it as empty and could overwrite it with
  already-optimized values; Undo correctly refused). Every file this feature writes is now written
  atomically (temp file + rename), and a failure to write the reboot-persistence file is reported
  through the existing "could not be set" list instead of silently leaving the kernel tuned live
  with no way to make that stick across a reboot.
- **All tunnels / backup**: "change one setting everywhere" no longer restarts (and re-enables) a
  tunnel you stopped on purpose - only tunnels already running are restarted. One corrupt tunnel
  file no longer blocks the whole bulk-settings screen or the whole backup export; export now
  reports which tunnels, if any, could not be read and so are missing from it.
- **Manager UI**: the editor it opens for a tunnel's raw file now runs `$EDITOR` directly instead
  of through a shell, so it can no longer run anything beyond the editor itself. The "Forwarded
  ports" screen now warns and asks before silently collapsing a hand-edited config's distinct
  per-map bind addresses onto one.
- **XHTTP carrier**: an upload packet outside the reorder window is now rejected with 429, not
  409: a retry on a reused connection (`delivered_already_ok`) could previously read that 409 as
  "already delivered" and never resend the packet, silently losing it. The two paths that admit a
  new session (id-based and single-request) now check and reserve against one combined count
  under one lock, closing a race that could over-admit past `max_sessions`. Fragmentation that
  gives up because a ClientHello did not arrive in one write now logs it, instead of silently
  sending that connection unfragmented. A 16-hex-digit chunk length now reports "exceeds the
  configured limit" consistently instead of an opaque parse error on a 32-bit build.

## 0.8.15 (2026-10-18)

- **Transport checker: fixed the live view corrupting itself in Custom runs.** The Transport column
  of the live table and the results table was a fixed 24 characters; a transport name combined with
  one of the new "also check" variant labels and a port number (for example
  `xhttps (tcp_congestion) :38722`, 30 characters) overflowed it instead of being truncated, and in
  a terminal narrower than the resulting line that overflow wrapped to a second row the live view's
  redraw didn't know about - it under-cleared by one line every tick, leaving a growing trail of
  stale "waiting"/status lines behind. Only Custom runs could hit this: no base transport name was
  ever long enough on its own. Widened the column to 30 (the real worst case across every
  transport/variant/port combination) and added a test that checks every one of them so a future,
  longer variant label can't silently reintroduce this.

## 0.8.14 (2026-10-18)

- **`fec.pacer` retuned after a real-link test collapsed its throughput.** Running the checker's
  new `--also-pacer` case for real between two servers (0.8.13) showed `fec-udp` drop from
  ~100 Mbit/s to as low as 0 Mbit/s with the pacer on, on an otherwise clean ~100ms link.
  The pacer's congestion-vs-clean threshold (`min_rtt/8`, floored at 5ms) was only ever validated
  against synthetic loopback deltas; on the real link, ordinary queueing delay under load (27-80ms
  above idle RTT, measured via the checker's own loaded UDP p95) was almost always read as
  congestion, so the rate decayed toward its floor instead of settling near what the link could
  sustain. The margin is now `min_rtt/3` floored at 20ms. If you updated to 0.8.13 for the checker
  changes below, update to 0.8.14; the checker itself is unchanged.

## 0.8.13 (2026-10-18)

- **Transport checker: three new "also check" measurements.** Alongside the existing browser-TLS
  and split-ClientHello re-checks, Custom now offers: TCP-based transports checked again with
  `tcp_congestion` set to `cubic`; `kcp`/`fec-udp`/`fec-raw`/`fec-raw-gaming` checked again with
  the adaptive pacer (`fec.pacer`) on; and raw TUN checked again with `tun.fragment` on and the
  MTU raised to 4000, well past what one outer packet can carry, so the case needs a genuine
  split and reassembly to pass. Slow-session eviction and FEC backpressure needed no new
  measurement: every non-raw case already runs with `connection_pool: 4` (what the wizard would
  create), and the backpressure code path already runs on every FEC/KCP case.

## 0.8.12 (2026-10-18)

Fixes a 0.8.11 regression found live on a real production tunnel minutes after that update: the new
slow-session eviction (below) could close a healthy, actively-transferring session, because two parts
of its judgment were wrong at a normal pool size. Comparing against the group's upper quartile
degenerates at 3-4 sessions (a normal `connection_pool`) into comparing everyone against the single
fastest session, so ordinary traffic variance alone made every other session look "far behind" on
nearly every judged window; and an idle or already-finished session sharing the same peer key dragged
the computed "typical" share down toward its own near-zero number, unfairly condemning a genuinely
busy sibling next to it. Fixed: judges against the group's median instead, only counts a session
toward that comparison once it has moved a meaningful amount in the window (an idle one is excluded,
not judged as slow), and widens the tolerance. Also fixed in the same pass: the periodic sweep that
runs this check was a detached task with no lifecycle tied to its listener, so a process that creates
many short-lived listeners in one run (the transport checker) leaked one orphaned sweep per case; it
now stops exactly when its listener does. If you updated to 0.8.11, update to 0.8.12.

## 0.8.11 (2026-10-18)

Five additive options. Nothing here changes default behaviour except where noted; every existing
tunnel and config keeps working unchanged.

- **TCP congestion control can now be set per path/listener.** `tcp_congestion` was already a
  program-wide setting (default `bbr`); a path or listener may now override it with its own
  `tcp_congestion`, for example to A/B `cubic` against `bbr` on one carrier without changing every
  other tunnel on the box.
- **Pooled sessions now evict a persistently slow one.** With `connection_pool` > 2, a session that
  keeps delivering far less than its siblings (while still answering heartbeats, so the existing
  silent-session detection would not catch it) is marked suspect the same way a silent one already
  is: `Pool::pick` stops sending it new users, and the dialing side's existing make-before-break
  replaces it.
- **FEC-UDP/FEC-raw: a full send queue now applies backpressure instead of silently dropping.**
  Previously, a burst that filled the queue of packets waiting for the socket dropped the overflow,
  which came back about one timeout later as a KCP resend of something that was simply never sent.
  The write side now waits instead, the same way the KCP send window already does.
- **Raw TUN packets bigger than one outer packet can now be split (`tun.fragment`, off by
  default).** Today, `tun.mtu` is capped to what the chosen raw profile's single packet can carry,
  and a bigger one is refused at startup. With `tun.fragment: true`, `tun.mtu` may be set higher:
  an oversized packet leaves as up to 64 numbered pieces and the far side reassembles them (an
  incomplete one is dropped after 2 seconds). This exists for traffic whose own packets exceed the
  chosen profile's budget (a 1420-byte inner MTU, for example) without lowering the TUN MTU or
  relying on the network's own IP fragmentation, which a filtered path commonly drops outright.
- **FEC-UDP/FEC-raw/KCP: an optional delay-based pacer (`fec.pacer`, off by default).** Paces how
  fast data is handed to KCP by its own measured round-trip time instead of only by the fixed send
  window: the rate grows while RTT stays near its observed minimum and shrinks once a queue starts
  building, independent of ordinary packet loss (on these links, loss is as often path noise as
  real congestion).

See `docs/raw-tun.md` (fragment, new payload kind 5), `docs/raw-protocol.md`, and the `fec` and
path/listener `tcp_congestion` settings in `docs/configuration.md` for details.

## 0.8.10 (2026-10-15)

- **New raw packet type: `dns`.** The raw carriers (`fec-raw`, `fec-raw-gaming`, `tun`) can now
  disguise every packet as a real, protocol-legal DNS message over UDP port 53 instead of TCP,
  UDP, ICMP, GRE, IP-in-IP or raw protocol 253: a standard DNS header, one question, and an
  EDNS0 OPT record whose RDATA is the tunnel payload. The dialing side's packets are framed as
  ordinary queries; the listening side's as NXDOMAIN answers, matching the fact that the fake
  question does not exist. That question is not one fixed string every installation shares — it
  is derived from both endpoints' addresses and the shared port, so each tunnel pair looks
  different on the wire. This is only a new outer disguise: the Noise handshake, encryption and
  replay protection underneath are identical to every other raw profile. `l4_port` defaults to 53
  for this profile in the wizard (every other raw profile keeps 4443).
- **New tunnel wizard:** "TUN + ports" is now the first and default choice over plain "IP tunnel
  (TUN)" in the "what should the tunnel carry?" menu, since plain TUN cannot carry port forwarding
  at all. Creating a tunnel with a freshly generated key no longer spends 12 seconds "Checking the
  connection to the other server..." before reporting what it already knew (the other server
  cannot be set up yet); that check now only runs for the side that pasted an existing key or
  pairing code, where the peer is normally already running.
- **Link test (`eztunnel linktest`, Tools → Link test):** the text report is redesigned — colored
  pass/fail icons (auto-disabled when the output is not a terminal, e.g. piped or saved), UDP loss
  spelled out as a percentage instead of just a raw count, and the measured path MTU shown
  directly on the datagram-size line instead of only in the notes when something was wrong.

## 0.8.9 (2026-10-15)

Fixes from a full code review (eight areas, cross-checked against the real source). Nothing here
changes the wire format; every existing tunnel keeps working.

- **FEC-UDP/FEC-raw listener:** a single bad or unexpected socket error (for example an unrelated
  ICMP port-unreachable landing on the listener's socket) used to end the whole listener, dropping
  every peer on it. It now logs the error and keeps going, the same way the plain KCP listener
  already did.
- **XHTTP:** the single-request "stream-up" endpoint (no session id) did not count against
  `max_sessions`/`max_sessions_per_ip`, so it could open unlimited sessions past the configured
  limit. It is now admission-controlled the same as the id-based sessions.
- **SOCKS5 UDP ASSOCIATE:** each destination opened its own tunnel stream without checking the
  per-address stream limit the ASSOCIATE connection itself was charged against, so one client
  talking to many destinations could exceed `max_streams_per_ip`. Each destination now takes a
  slot from the same limit.
- **TUN + port forwarding:** the inner forwarding link's client path could inherit the outer TUN
  tunnel's `local_address`, which is not valid for the unrelated inner connection. It is now
  cleared, matching the listener side (already correct).
- **Manager:** uninstall no longer deletes tunnel configurations when a service failed to stop
  (it used to, leaving an unseen tunnel running with no config); it also now removes the actually
  installed program, not whichever copy happened to be running it. `eztunnel rollback` now
  refuses, with nothing changed, if the program being rolled back to cannot read a saved tunnel's
  configuration.
- **Manager:** "Ports to forward" rejected a target hostname containing a dash (for example
  `2083=db-prod.internal:5432`), reading it as an invalid port range.
- **Manager:** config saves refuse to write through a symlink planted at the candidate file's
  path, closing a local privilege-escalation path (the tunnels directory can be writable by the
  unprivileged `eztunnel` service account). Systemd unit and drop-in files are now written
  atomically (temporary file, then rename) so a crash mid-write cannot leave one truncated.
  Corrected the "Optimize this server" wording, which claimed every change only raises a value
  that was too low; settings with no ordering (a queueing discipline, a congestion-control
  algorithm) are always set to the recommendation.
- **New tunnel wizard:** creating a tunnel with a freshly generated key no longer spends 12
  seconds "Checking the connection to the other server..." before reporting what it already knew
  (the other server cannot be set up yet). That check now only runs for the side that pasted an
  existing key or pairing code, where the peer is normally already running.
- **Transport checker:** a case that could not run on this machine (not possible, or skipped)
  was retried and reported as "failed 2 of 2 runs" instead of being left as it was.
- **Wire version 2 (probe resistance):** a connection that sent nothing at all used to be cut at
  a fixed time with no randomized hold, unlike one that sent quick garbage; the hold is also no
  longer silently capped by `handshake_sec` when `probe_hold_sec` is set higher. `stealth.pad_max:
  0` alone (to turn padding off) no longer fails validation just because `pad_min` is still at its
  default. A tag-10 PROXY frame now canonicalizes an IPv4-mapped IPv6 address on decode, matching
  how one is already handled when such a frame is built.
- **`eztunnel linktest listen`:** one failing `accept()` used to end that listener entirely; it
  now tolerates the error, the same as its UDP side already did.
- **Documentation and scripts:** `build-static.sh --no-default-features` no longer needs
  `musl-tools`/`g++` (it was still running the BoringSSL-only shim step regardless of the flag);
  several stale or incomplete references corrected in `build-from-source.md`, `linktest.md`,
  `two-server-test.md`, `first-tunnel.md`, `offline-runner.sh.in`, and two notes in the link
  tester's own verdict text.

## 0.8.8 (2026-10-14)

Fixes for the open points of the 0.7.5 review.

- **Manager: a settings change is watched.** After Change settings, the new file is saved and the tunnel restarted as before, but the
  manager now watches the service for up to 15 seconds. A change that passes every check and still cannot start (a port another
  program holds, a missing interface) used to leave the tunnel restarting every few seconds under "Restarted with the new settings";
  now it says so and offers **Go back to the previous settings** (the file kept as `NAME.json.bak`; going back can itself be
  undone the same way).
- **Manager: delete checks that the service stopped.** If `systemctl` could not stop the service, the unit and configuration were
  removed anyway and the tunnel kept running unseen. Now nothing is deleted and the message says how to stop it.
- **Link line:** the journal scan counted the word "unauthenticated" (the debug line "too many unauthenticated connections", the XHTTP
  warning for a listener without a token) as an authenticated session.
- **Control socket:** a client that connects and sends nothing is let go after 5 seconds, and at most 16 requests are served at once
  (a client over the limit gets "too many requests at once"). A speed-test request with a number of the wrong type is refused
  instead of running with a default.
- **FEC adaptive tuner** (`fec.tuner.mode: "auto"`): a failed change (the kernel refusing a socket option) is reported once and tried
  again at the next interval; it used to end the tuning of that connection for good.
- **Tests:** XHTTP answers `429 Too Many Requests` while a session's upload places are all taken and serves again when they are free;
  idle XHTTP connections (no request at all, or a quiet keep-alive upload connection) are closed after `session_timeout_sec`.
- **Documentation:** `xhttp.md` says what replaying a session id on plain XHTTP can and cannot do; `security.md` describes the
  control socket limits; the module table of `architecture.md`, the version examples of `build-from-source.md` and the frame table of
  `protocol.md` (broken since 0.8.5) are corrected; the release bundle now includes `vendor/kcp`'s license and patch note.

## 0.8.7 (2026-10-13)

- **Fix (0.8.6):** a tunnel that uses a `tunnel_key` (every tunnel the wizard makes) logged "the xhttp settings do nothing
  on Wss" (or Tcp, Kcp ...) at every start. The program fills in the XHTTP access token and the wire v2 user agent
  itself, and the new check counted them as settings you made. They are ignored now.

## 0.8.6 (2026-10-13)

- **Transport checker: UDP loss and delay.** Every case sends 300 small UDP packets through the test tunnel to an echo
  on the foreign server, idle, and 500 during the download. New columns *UDP loss %* (idle/loaded) and *UDP p95* (ms);
  a packet answered after more than a second counts as lost. TCP-based carriers show no loss but a long p95 when the
  link is full; the UDP carriers show real loss. A tunnel that carries no UDP gets the note *UDP not carried*. The
  *Lossy path* priority ranks by measured loss first. About 3 seconds more per case; the *UDP loss and delay* row of the
  measurements list or `--no-udp` leaves it out.
- **Configuration checks.** A wildcard bind (`0.0.0.0`, `[::]`) conflicts with an address of the same family on the same
  port (was: only identical addresses); the fec-udp knock port (listener port + 10000, or - 1000 above 55535) is part of
  the check; tunnels saved by the manager must use fixed ports (port 0 only works in tests). New warnings, never errors,
  in `--check`, at start and in the wizard: settings that do nothing on the chosen carrier (`tls_fragment`,
  `tls_profile`, `xhttp`, `fec`, `kcp`) and a `queues.stream_frames` below `stream_window + 4`. `allowed_targets` host
  names match in any letter case. The setting descriptions mention the rules between settings (heartbeat against the
  timeouts).
- **Wizard:** the whole configuration is checked before the name is asked; a combination that cannot work no longer ends
  the wizard and loses every answer: it offers *Customize* with the answers kept. The TUN MTU asked in Customize is
  limited to what fits through the raw interface. A pairing code with values this version does not know (settings, TLS
  look, carry type, protocol) lists them instead of dropping them silently.

## 0.8.5 (2026-10-13)

- **Faster recovery when the other server crashed.** A session that gets no answer for `timeouts.probe_sec` (3 s)
  while waiting for one is asked with a ping; after twice that it takes no new users, and the side that dialed it opens
  a fresh connection and replaces the silent session as soon as the fresh one works. After the Iran server was killed
  and started again, test tunnels carried data again after 6-8 s on fec-udp and kcp, and after 6.7 s on the real link
  (0.8.4: 48 s, the dead timeout). A session that answers again keeps its users. Every carrier, no wire change.
- **Raw TUN (`transport: "tun"`):** says goodbye when it stops (the other side reconnects at once instead of after the
  dead timeout; older peers ignore the new packet), and after a crash the client starts a new handshake when its pings
  go unanswered for twice `timeouts.probe_sec`, keeping the old session until the new one works. On the test servers:
  a planned restart of the Iran side (2 s down) cost 3.6 s of pings, a crash 12.6 s (before: the dead timeout).
- **Goodbye:** a side that has said goodbye accepts no new connections while it finishes stopping. Before, a peer that
  reconnected within `timeouts.goodbye_wait_ms` (raw TUN at once; other carriers only with that setting raised above
  about a second) got a session that died a moment later and waited for the dead timeout.
- **KCP and FEC carriers: no more full-window bursts after a timeout.** With congestion control off, a retransmission
  timeout resent the whole window at once (up to 1024 packets); a short queue on the path dropped most of it again and
  the timeouts grew, stalling transfers for seconds (a test run with a small relay buffer took 15-60 s under CPU load,
  now under 1.5 s). New settings `kcp.resend_burst` and `fec.resend_burst` (default 128 packets per interval, 0 = the
  old behaviour). The `kcp` crate is now vendored under `vendor/kcp` with this patch.
- **XHTTP:** a new HTTP connection in the middle of a session (uploads) gives up after `dial_timeout` instead of
  waiting for the kernel's TCP timeout or a TLS handshake that never ends.
- **Memory:** UDP datagrams waiting to enter the tunnel (UDP maps, SOCKS5 UDP) take their share of `memory_budget_mb`
  and are dropped (counted as `udp_dropped` in the status line) when it is used up; the FEC send queue holds at most
  twice the window instead of 8192 packets per conversation.
- **Raw TCP firewall rules:** every raw endpoint of a tunnel gets its rules (before: only the first), and each rule
  carries the tunnel's name, so two tunnels on the same port no longer remove each other's rules.

## 0.8.4 (2026-10-13)

- **Updates survive an SSH drop.** `eztunnel update` and `eztunnel rollback` (and Tools → Update) keep going when the
  terminal goes away, so an update whose restart cuts the SSH session still checks the tunnels and rolls back by itself
  if needed. What they print is also written to `/var/log/eztunnel-update.log`.
- **Transport checker:** two servers with different versions stop right after they find each other, with "the other
  server runs EZTunnel X, this one Y: update both to the same version first" on both screens (exit code 1 on the
  command line), instead of a live view that breaks on values the older one cannot read.
- **FEC carriers (fec-udp, fec-raw, fec-raw-gaming):** a burst that ends before a full group of 10 packets (the end of
  every transfer, most requests and answers) gets a partial parity packet after `fec.partial_flush_ms` (10 ms), so a loss
  there is repaired at once instead of waiting for a retransmission. The receiver keeps 8 groups open instead of 3, so a
  delayed packet still finds its group. Receivers before 0.8.4 ignore the new packets.
- **Faster recovery after a crash.** When the other server connects again while its older sessions still look alive
  (it crashed, was killed or lost its network, so no goodbye came), those sessions get a ping and are closed if they do
  not answer within `timeouts.probe_sec` (3 s). Users were sent to them until the dead timeout (about 50 s) before. On
  the test machine, every user is served again about 3 s after the client crashed and restarted (fec-udp and kcp).
- **Tests:** the FEC loss test no longer slows down to 15 s or more on a busy machine (its relay socket overflowed; it
  now uses a window that fits); the 1000-user test turns off the per-address limit it is not about and waits for all
  four sessions.

## 0.8.3 (2026-10-13)

- **Transport checker:** every list and checklist has a visible "← Back" row (Esc still works); checklists are toggle
  lists (Enter turns a row on or off, with "all / none", "✔ Done" and "← Back" rows).
- **Transport checker:** fec-raw, fec-raw-gaming and raw TUN are included in every preset when they can run (root,
  IPv4 addresses).

## 0.8.2 (2026-10-13)

- **Faster new connections.** A new user connection sends its data right behind the request to open it instead of
  waiting for the other server's confirmation, so it costs one round trip instead of two (about 90 ms instead of 180 ms
  between the test servers). The other server queues the data until the destination is connected, which every version
  already does, so mixed versions keep working. TCP maps, UDP maps and SOCKS5 (which now answers "connected" at once).
  `stream_early_data: false` restores the old wait.
- **Transport checker:** a run without speed tests or a hold (Quick) reports *reachable* instead of *works*, with a note
  that bulk data and stability were not tested (on the test pair xhttp passed Quick but fails as soon as data flows).
- **Transport checker:** raw TUN is checked, once per chosen packet type (tcp, udp, icmp, gre, ipip, raw), through a
  temporary TUN interface on both servers. The handshake time of raw cases is the foreign server's own.

## 0.8.1 (2026-10-13)

- **Transport checker:** an RTT column (the tunnel's own round trip, comparable with `ping`) next to the connection time,
  which is now called Conn (a new connection takes one round trip more: the stream is opened at the far side first).
- **Transport checker:** every screen goes back: Esc on the lists and checklists (the options stay as they were), an empty
  answer on the address and code questions.

## 0.8.0 (2026-10-13)

- **Transport checker** (Tools → Transport checker, or `eztunnel check start|join`): finds which transports work
  between the two servers, in which direction and how fast. Start on one server (options: Quick, Standard, Thorough or
  every choice by hand: transports, directions, pings, download/upload/4-stream speed, stability hold, baseline and path
  MTU, repeat failures, browser-TLS and TLS-fragment variants, ports, slow threshold, ranking priority), join on the other
  with the check code. Each case is a real temporary tunnel built by the wizard's own configuration code; results
  separate *no handshake*, *blocked after handshake*, *bulk blocked*, *download/upload only*, *unstable*, *slow* and
  *works*. Both servers show the same live view (pause, resume, skip, stop, live log, details); the results rank the
  transports by the chosen priority, are saved (JSON and text, newest 20) and offer to create the tunnel with the wizard
  filled in. Only the two servers are contacted; temporary ports and firewall rules are removed afterwards.
- The new-tunnel wizard offers the other server's address as the default when it is already known.

## 0.7.8 (2026-10-12)

- **Fast reconnect after a restart.** A tunnel that stops (restart, `eztunnel update`, stop, switching the log detail, a planned
  restart, a used-up quota) first tells the other server goodbye inside the encrypted session and keeps running for
  `timeouts.goodbye_wait_ms` (default 500) so the notice is sent. The other server drops those sessions at once, so no user
  connection is sent to a dead session, and reconnects at its base retry interval until this side is back: a few seconds instead
  of `dead_timeout_sec` (about 50 s on the UDP carriers, which have no connection to close). Works for every carrier and for TUN
  over the normal carriers, in both directions. Raw TUN (`transport: "tun"`) and crashes still wait for the dead timeout.
- **No false quota warning at shutdown.** A tunnel without a quota tried to save a traffic count when it stopped and logged
  "could not save the quota count" on a read-only system. A tunnel without a quota now counts nothing.
- **The silence warning says what is likely.** After a session has carried traffic, "no traffic from the other server" now says the
  other server may have stopped or restarted (the old text about a filter blocking the carrier is kept for a session that never
  heard anything).

## 0.7.7 (2026-10-12)

Abuse resistance for public servers, and the fixes found after 0.7.6.

- **A replayed first handshake message no longer gets user traffic.** Someone who recorded the first message of a handshake and sent
  it again got a session: it joined the pool users are sent to (those users then waited for an answer that never came) and, in TUN
  mode, replaced the running session. Now a side that accepted a connection trusts it only after the peer has sent a record that
  decrypts under the session keys (within `timeouts.handshake_sec`); the "authenticated" log line is written at that moment.
  Verified by a test that replays a recorded handshake: it fails on 0.7.5 and passes now.
- **A plain HTTP request sent to a TLS port** (`wss`, `https`, `xhttps`, `wire_version` 2) gets the 400 answer nginx gives, not a
  silent close. The decoy pages carry a `Date` header and the connection is closed afterwards like a server that said
  `Connection: close` (it used to be held open for a random time).
- **TUN over TCP carriers:** a packet from the peer that does not fit this side's MTU is dropped with a warning instead of ending
  the session (two sides with different `tun.mtu` reconnected forever).
- **Setup wizard:** the origin server of a CDN tunnel is asked for its own port (the code only holds the CDN's port 80/443); a timing
  value set in Customize (`kcp.interval_ms`, `resend`, ...) is no longer erased by the speed mode.
- **Public-server limits.** `max_streams_per_ip` (default 512, 0 = off): one source address can no longer take the last quarter of the
  stream slots of a public map or SOCKS5 listener (enforced only while the sessions are more than 75 % full, so users behind one
  shared address can still use all the room that is there). `timeouts.tcp_idle_sec` (default 3600, 0 = never): forwarded TCP connections that move no data for
  that long are closed. `xhttp.max_sessions_per_ip` (default 0 = off) and `fec.max_peers_per_ip` (default 64) do the same for XHTTP
  sessions and FEC conversations. The XHTTP server ends a session as soon as the client closes its download connection (it used to
  keep the slot until the upload deadline) and logs a warning for a listener without an access token.
- **Pairing code:** forwarding to other machines allows exactly those targets on the foreign server instead of `*` (only a SOCKS5 exit
  gets `*`).
- **Key-file hygiene:** a TLS private key readable by every user is refused; an export is written to a new file and renamed into place
  (a link at the target is replaced, not written through); deleting a tunnel also deletes its unfinished edit draft, which held the key.
- **Container-aware memory budget:** the automatic flow-control budget uses the smaller of the machine's memory and the cgroup limit
  (Docker, LXC, systemd `MemoryMax`).
- **XHTTP uploads:** a kept-open upload connection that the server or a proxy closed while idle is replaced and the packet resent,
  instead of ending the session.
- **Visible refusals:** a request for a destination that `allowed_targets` does not list is logged (1st, 2nd, 4th, 8th ... refusal).
- **Raw carriers:** a full transmit queue or a briefly down interface drops one packet instead of ending the carrier.
- Documentation corrections (security, FEC tuning, link test, README build and defaults).

## 0.7.6 (2026-10-12)

Fixes from a whole-project review.

- **`tls_profile: chrome` with `ca_file`** also trusted the system's roots; it now trusts only the file, like the classic path.
- **WebSocket upgrade reply (wire version 2)** used bare line feeds instead of CRLF.
- **HTTP header names are validated** (a space before the colon used to hide `Transfer-Encoding` from the framing checks).
- **XHTTP edge dial timeout** is an equal share of `dial_timeout` instead of at most 3 s.
- **`eztunnel tlscheck --config`** failed for every tunnel-key configuration (0.7.3).
- **TUN + ports** with `tls_profile` or `local_address` passed `--check` and then failed to start.
- **Updater:** a tunnel must stay up for the whole watch window, not only at its end.
- **Optimize / Undo:** a backup key can no longer point outside `/proc/sys`; values that could not be restored stay in the backup.
- **Quota:** a period saved while the clock was far in the future is replaced.
- **FEC:** the client no longer stops receiving after an ICMP "port unreachable"; a full knock table drops its oldest entry instead
  of refusing new knocks; linear instead of quadratic queue handling; raw sockets keep their receive buffer.
- **Validation:** `heartbeat_sec` must be smaller than `xhttp.session_timeout_sec` and `fec.peer_idle_sec`.
- **Link test:** a transfer that does not complete or a UDP probe stopped by an error now count in the score; the advice no
  longer promises carriers it did not test; the MTU penalty uses the path MTU; the UDP listener survives a socket error; the
  manager's listener prompt accepts an IPv6 peer.
- **Manager:** uninstall asks before going on after a failed Undo; warnings when `EZTUNNEL_HOME` makes real services and when the
  running copy is not the installed one. **Wizard:** "Customize" started from the Streaming profile (now General), Esc on the
  Settings list no longer picks General, and a tunnel that dials through a CDN gets the CDN domain as its TLS name.
  **Pairing code:** TLS fragmentation and the TLS look travel only from a creator that dials, and per-server resource settings
  (`memory_budget_mb`, `worker_threads`, `stats_interval_sec`, `max_open_files`, record padding, jitter) stay on their server.
- Documentation corrections (security, FEC tuning, link test, README build and defaults).

## 0.7.5 (2026-10-11)

`fec-udp` and `fec-raw` no longer send every packet through a loopback socket, and the static build has a faster allocator.

- **Faster allocator in the static (musl) build.** musl's own `malloc` is several times slower than glibc's for the many small
  buffers each packet needs, which halved the speed of the KCP and FEC carriers. The static program now uses `mimalloc` (MIT,
  compiled in; about 150 KB). Loopback benchmark of the static program, hop already removed: `fec-udp` 580 -> 1100 Mbit/s and
  CPU per GB 11.5 / 13.7 -> 6.5 / 7.1 (server / client); `kcp` 830 -> 1510 Mbit/s and 6.8 / 8.4 -> 4.8 / 5.3. The price is
  memory: about 8 MiB more per process when idle, and memory freed after a burst of connections stays with the process
  (+10-20 MiB retained in the 300-connection test) instead of going back to the system.

- **No loopback hop.** KCP used to write to a loopback UDP socket, where another task read each packet, FEC-encoded it and
  sent it to the network (and the reverse way). KCP now hands its packets to the FEC layer directly, which encodes and sends
  them in the same call, and received packets are fed straight into the session. The wire format is unchanged and old and new
  versions interoperate. Loopback benchmark, same source before and after, CPU seconds per GB (server / client): glibc build
  9.1 / 14.1 -> 5.8 / 6.3, speed 489 -> 1265 Mbit/s; static build 13.4 / 18.0 -> 11.5 / 13.6. On the two test servers
  (`fec-udp`, 88 ms, 80-90 Mbit/s) the tunnel process used 56 % of a core before and 47-51 % after, at the same or a higher
  speed.
- The vendored `tokio_kcp` gained a packet-sink interface and direct input (`LOCAL-PATCH.md`); plain `kcp` is unchanged.
- A send error on the network socket of a FEC carrier is now logged and counts as a lost datagram instead of stopping the
  carrier's relay.

## 0.7.4 (2026-10-11)

The link tester measures datagram sizes and gives a verdict.

- **Datagram size sweep (`eztunnel linktest probe`, on by default, `--no-mtu` skips it).** Finds the largest UDP datagram
  that crosses the path in each direction, with the don't-fragment bit set, and the path MTU. Both machines must run this
  version. Verified on a loopback with a lowered MTU and through a routed hop with a 1400-byte link (both found 1372 bytes of
  payload), and on the two test servers (88 ms apart: at least 1472 bytes both ways).
- **Verdict.** Every report has a score (0-100), a rating, notes and advice: which carriers can work (for example "UDP does not
  pass: use a TCP-based carrier"), which side should dial when TCP passes one way only, and which of `kcp.mtu` and `fec.mtu`
  to lower. `--text` prints it for a person; the manager's *Link test* uses it.
- The JSON report gained `quick`, `mtu` and `verdict`; `ProbeOptions` gained `mtu`.

## 0.7.3 (2026-10-10)

A TLS handshake that looks like Chrome's.

- **`tls_profile` (`classic` or `chrome`) for the TLS carriers (`wss`, `https`, `xhttps`).** `chrome` makes the side that
  dials send the ClientHello of Chrome 152 (BoringSSL, the same TLS library as Chrome): its cipher suites, extensions,
  groups (X25519MLKEM768 first), signature algorithms, GREASE values, ECH GREASE, certificate compression, and a different
  extension order on every connection. Set on the dialing side only; the other server needs no change except that it must
  be 0.7.3 or later (it presents an extra ECDSA certificate to clients that do not offer Ed25519). Default `classic`
  (the previous behaviour). Pairing codes carry it; Tools → *Change settings* and the wizard have a **TLS look** row.
- **`eztunnel tlscheck`** prints the JA3 and JA4 of the ClientHello a profile or a saved tunnel would send (it captures it
  on a loopback listener; nothing leaves the machine), to compare with a fingerprint page. Tested against a Chrome 152 capture:
  cipher list, extension set, signature algorithms and the JA4 hashes match the WebSocket handshake of Chrome.
- **Build.** The `browser-tls` cargo feature (on by default) links BoringSSL: building needs `cmake`, a C++ compiler and
  `clang`; `scripts/build-static.sh` builds the static musl program (it links a small file of glibc stand-ins,
  `scripts/musl-glibc-shims.c`, because BoringSSL's C++ library is the host's). The static program grows from 9.5 to 11.9 MB. `cargo build --no-default-features` builds without it (then only `classic`).
- **Limits (unverified against a real filter).** Only the ClientHello is imitated, not the server side of the handshake,
  packet timing or the traffic after it. Chrome and Edge only; Firefox and Safari use other TLS libraries.

## 0.7.2 (2026-10-10)

CPU use of the KCP and FEC carriers (and the others).

- **One worker thread by default (`worker_threads`, new setting, 1..64).** The tunnel used one thread per core, and moving
  its many small tasks between threads cost more CPU than the work itself. Loopback measurements (both ends together):
  `kcp` 625 → 1460 Mbit/s and 34 → 10 CPU-seconds per GB; `tcp` and `wss` about half the CPU per GB. One thread is limited
  to one core: a very fast FEC tunnel (above roughly 400 Mbit/s) should raise `worker_threads`. **Existing tunnels pick up
  the new default when the program is updated.**
- **Batched UDP.** The KCP and FEC carriers send and receive up to 64 datagrams per system call (`sendmmsg`/`recvmmsg`).
- **Faster FEC parity.** Table-driven multiplication instead of bit-by-bit; identical bytes on the wire.
- `fec-udp` download: 317 → ~460 Mbit/s and 64 → 25 CPU-seconds per GB on a loopback pair. On the two real test servers
  (88 ms apart, 80-90 Mbit/s) the tunnel process of `fec-udp` used 55 % of a core instead of 113 %, and `kcp` 48 % instead of 75 %.

## 0.7.1 (2026-10-09)

Updates with a way back, the real user address for the destination, record padding, a kernel packet filter, and small operator items.

- **Update and rollback (`eztunnel update`, `eztunnel rollback`).** The new program file installs itself over
  `/usr/local/bin/eztunnel` after checking its checksum output, version (older or equal needs `--allow-downgrade`),
  CPU architecture and that it reads every saved tunnel; keeps the old program as `eztunnel.previous`; restarts only
  the tunnels that were running; and puts the old program back by itself if one does not stay up (a failed update also
  leaves an older backup alone). Tested on a real server, including an update that undid itself. No network access.
- **PROXY protocol to the destination (`maps[].proxy_protocol`).** The service behind the tunnel can see each user's real
  address. New frame tag 10; needs 0.7.1 on both servers.
- **Record padding and burst jitter (`stealth.record_pad_max`, `stealth.jitter_ms`).** Wire version 2 only, off by
  default, each side sets its own; padded records are a new frame tag 11 that every 0.7.1 receiver accepts.
- **Kernel packet filter for the raw carriers (`raw.kernel_filter`, on by default).** The kernel drops frames that are
  not from the peer. All 52 raw namespace runs (IPv4 and IPv6) pass; on the two tested servers CPU use did not change,
  so the gain is expected only on a busy interface.
- **`LimitCORE=0` in every service unit**, so a crash cannot leave the tunnel key in a core dump.

- **Bulk actions (Manage tunnels → All tunnels).** Start, stop or restart every tunnel, delete all of them (two
  confirmations), or change one numeric setting in every tunnel that has it; each tunnel is checked before it is
  saved and one that would become invalid is left as it was.
- **Source address for ordinary carriers (`local_address`).** The side that dials can connect from a chosen local IP
  for `tcp`, `tcp6`, `ws`, `wss`, `http`, `https`, `xhttp`, `xhttps`, `kcp` and `fec-udp` (also in Customize and
  Change settings). Refused where it would do nothing (a listening side, the raw carriers).
- **Planned restart and traffic quota.** `schedule.restart_every_hours` restarts a tunnel after that long;
  `quota.limit_gb` and `quota.period_days` stop a tunnel from carrying more than a set amount per period and resume it
  when the period ends. The count survives restarts; Manage tunnels shows it and can reset it. Neither is carried by
  pairing codes. See `docs/configuration.md`.
- **Export and import of all tunnels (Tools).** One private file with every tunnel configuration (it contains the tunnel
  keys); import checks each tunnel, keeps existing ones unless told to replace them, and can start the imported tunnels.
- **TUN MTU from the interface.** The wizard proposes the raw TUN MTU from the MTU of the interface the packets leave
  from (minus the IPv4 header, the profile header and the tunnel's 47 bytes), never above the usual 1400, so a server
  whose interface has a smaller MTU (1400 on one of the test servers) no longer needs a manual change. A pairing code's
  MTU is lowered to fit the receiving server. The real path MTU is still not measured (the transport checker will).
  Change settings on a saved tunnel now has a **TUN MTU** row; for a raw TUN tunnel it shows the largest value that fits
  the interface and refuses larger ones (the tunnel would not start with them).

## 0.7.0 (2026-10-09)

Probe resistance.

- **Wire version 2 (`wire_version: 2`).** Existing tunnels keep version 1 (nothing changes after an
  upgrade); tunnels made by the wizard from now on use version 2, and the pairing code carries it. Manage
  tunnels has a switch per tunnel; the other server must be switched too, and both must run this version or
  later. Version 2: plain TCP, KCP and FEC streams start with printable padding and are masked after it
  (a stream that was random from the first byte was cut by the tested network), so the first packet has no fixed
  length or value (the old plain `tcp` carrier began with a fixed 98-byte record); connections that fail the
  handshake are ignored for a random time before they are closed; wrong HTTP and WebSocket requests get an
  ordinary web-server 404 page; and project names leave the wire (the HTTP Upgrade token, XHTTP header names,
  the default path, the default User-Agent and the name in the derived certificate come from the server key).
  Settings: `stealth.pad_min`, `stealth.pad_max`, `stealth.probe_hold_sec`, `stealth.decoy_status`. Not covered: raw `tun`,
  `fec-raw` packet shapes and the `fec-udp` knock port, and traffic-shape analysis. See `docs/security.md` and
  `docs/protocol.md`.
- **Raw `icmp` profile with wire version 2 copies the request id.** The network between the tested servers passes an
  echo reply from Iran only when its id matches a recent request, so replies with the server's own port as id were
  mostly dropped and the carrier worked only sometimes. With version 2 both directions use the client's port as the
  id and the server's sequence numbers carry the top bit (so the server kernel's own echo reply is not taken for a
  tunnel packet). `tun/icmp` connected 3 of 3 times on the real link.

## 0.6.2 (2026-10-09)

Stability and quick wins from real-link testing.

- **Firewall rules for the raw TCP carriers.** `fec-raw`, `fec-raw-gaming` and `tun` with the `tcp`
  profile send TCP packets no program owns, so the kernel answers them with resets that can break the
  link through NATs and firewalls. The wizard now offers two rules (bypass connection tracking, drop
  the kernel's resets), scoped to the other server and the two raw ports, and Manage tunnels can turn
  them on, off or re-apply them. They live in `eztunnel-NAME.firewall.service`, start before the
  tunnel, vanish with it, and are never added without asking. See `docs/raw-protocol.md`.
- **Speed modes for KCP and FEC carriers.** A named timing mode (normal, fast, fast2, fast3) in the
  wizard's Customize screen and in Change settings, written into the carrier's ordinary timing
  fields; "default" keeps the program's own (already fast) values. Each server may use its own
  mode. Measured on a real link: the modes gave similar speeds and differ mostly in CPU; the FEC carriers use about one full
  core in every mode, which is what limits `fec-udp` near 100 Mbit/s.
- **A memory budget for the flow-control windows (`memory_budget_mb`).** Each user connection's window
  can be left queued in memory by a slow user (up to 4-8 MiB with the General and Streaming
  profiles), so hundreds of slow users could use gigabytes of a small server. The extra window is now
  paid from a shared budget (default: a quarter of the memory, 64 MiB to 1 GiB). When it is used up,
  new connections keep a small window and are slower on long links instead of exhausting memory.
  Nothing changes on the wire. Shown in the log at start and in Live status.
- **SOCKS5 UDP ASSOCIATE.** The SOCKS5 listener now relays UDP (DNS, QUIC, anything a SOCKS5 client
  sends over UDP) through the tunnel, as well as TCP CONNECT. The relay answers only the client that opened
  the association, ends with its TCP connection, uses one tunnel stream per destination, and applies the far
  side's `allowed_targets` and the reserved-name rule. Fragmented SOCKS5 datagrams are not supported. On the
  two test servers 20 of 20 datagrams came back through a `wss` tunnel with a median of 93 ms (link 88 ms).

## 0.6.1 (2026-10-09)

Fixes from the review of 0.6.0 and from a real Iran <-> foreign test campaign.

- **TUN + ports over `wss`, `https` or `xhttps` now starts.** The inner forwarding link between
  the two TUN addresses is plain TCP, but it kept the outer carrier's `tls_auto`, so the service
  failed at every start with "tls_auto requires a TLS carrier". The wizard offered this
  combination and its check passed, because only the service builds the inner link.
- **Speed test target no longer reachable by users.** The foreign side answers
  `*.speedtest.eztunnel.invalid:9` itself, outside `allowed_targets`. A SOCKS5 user could ask
  for that name and make the foreign server send up to 1 GiB per request. SOCKS5 now refuses
  every `.invalid` name, and map targets under `.invalid` are refused when a configuration loads.
- **Optimize survives a reboot.** Its file is now `/etc/sysctl.d/61-eztunnel-optimize.conf`.
  The old name sorted before the manager's `60-eztunnel.conf`, whose smaller buffer limits for
  KCP/FEC tunnels then replaced the optimized ones at every boot. Applying or undoing removes the
  old file.
- **Uninstall offers to undo Optimize.** Before, it left the optimizer's sysctl and module files
  in place and, when configs were not kept, deleted the saved original values, so the changes
  stayed for good with no way back.
- **The wizard no longer calls a blocked link "connected".** It used to print "Connected to the
  other server" as soon as the key handshake worked. Some carriers authenticate and then pass no
  traffic (on a real Iran link: plain WS, HTTP and KCP when the foreign server dials in, XHTTP,
  and several raw profiles). Each side now also sends a second, quick heartbeat two seconds after
  the first (older peers answer it like any Ping), and the check needs both answers; otherwise it
  says that no traffic comes back and suggests another transport or direction. Limit: a carrier
  that passes small packets and blocks bulk data (XHTTP stream-up on that link) still looks
  working here; the silent-link warning below and the Link line catch it after about 20 s.
- **A silent link is reported after two heartbeats, not after the dead timeout.** An
  authenticated session that hears nothing logs "no traffic from the other server" (20 s with
  the default heartbeat instead of 40-50 s), and Manage tunnels shows it on the Link line.
- **XHTTP packet-up uploads are faster by default.** `xhttp.up_concurrency` now defaults to 8
  (it was 2), which limited uploads over a 90 ms link to about 4 Mbit/s; it is also a tunable
  setting now.
- **The Streaming profile widens the KCP and FEC windows** to 4096 packets with 16 MiB buffers
  (the defaults cap one connection near 100 Mbit/s at 90 ms). Other profiles are unchanged.
- **Honest hints**: the plain WS, HTTP and KCP entries say they are most often blocked when the
  foreign server dials in, and the TLS fragmentation help warns that some filters drop split
  packets so the tunnel may not connect at all.
- **Live status loss no longer flickers.** A heartbeat still in flight was counted as lost (one
  in five at the start); it now counts only after a whole heartbeat interval without an answer
  (`pings_lost` in the status).
- **TUN-only tunnels no longer offer a live status** that told you to "restart the tunnel once"
  and never worked; the menu explains that they only forward IP packets.
- **Undoing Optimize puts the UDP buffer ceiling back** for the installed KCP/FEC tunnels (before,
  the restored lower value halved their speed until the next reboot). `eztunnel optimize` without
  `--apply` no longer loads the BBR kernel module, and applying loads it only if needed.
- **The control socket's request tasks stop with the tunnel**, so a running speed test ends when
  the tunnel stops.
- **Uninstalling in a test directory** (`EZTUNNEL_HOME`) no longer deletes the running program or
  the system buffer file.
- README and the first-tunnel guide said peers need 0.5.x; they need 0.5.2 or newer, because
  older versions refuse the larger flow-control window.

## 0.6.0

- **Pairing code**: after New tunnel on the first server, and from Manage → Show the pairing code
  and key, the manager prints one line (`ezt1-...`) with every setting. On the second server,
  New tunnel → Paste a pairing code creates the matching side; only machine-specific questions
  remain (for example the ports when the foreign server made the code). A version prefix and a
  checksum refuse damaged or partly copied codes. The code holds the tunnel key.
- **TLS ClientHello fragmentation** (`tls_fragment`, off by default) for `wss`, `https` and
  `xhttps`: the dialing side splits its first TLS message into several small TLS records, each
  sent in its own TCP packet with an optional random pause, and always cuts inside the server
  name, so no single packet shows the whole name. Any TLS server accepts this (older EZTunnel
  versions too). Toggle in Customize and Manage → Change settings; piece sizes and pause are
  settings.
- **Live status** (Manage → the tunnel): connections to the other server, reconnects, ping /
  jitter / loss from the heartbeats, current and peak download and upload, users, totals and
  uptime, refreshed every second.
- **Speed test** (Manage → the tunnel, on the Iran server): download and upload through the
  tunnel with one and with four connections. The foreign side answers a reserved test target
  itself; nothing leaves the two servers and `allowed_targets` is not involved.
- Each service has a private status channel (`/run/eztunnel-NAME/control.sock`, readable only
  by the tunnel's account and root). Restart now rewrites the service file, so a tunnel made by
  an older version gains it after one restart.
- **Usage profiles** in New tunnel: General (window 256, 4 connections), Many users (window
  128, 8 connections, more streams and connections), Gaming / low delay (window 64, 5 s
  heartbeat, dead link noticed in 20 s), Streaming / big downloads (window 512, 8 connections),
  or Customize (starts from General). Profiles only write ordinary settings, which the pairing
  code carries to the other side.
- Optimizer: also lowers `tcp_fin_timeout` to 15 s and raises the UDP minimum buffers to
  16 KB (shown first, only when worse, undoable like the rest).

## 0.5.3

- New setting `tcp_congestion` (default `bbr`): the congestion control used on the tunnel's own
  TCP connections, without changing the system default. On the real link, foreign -> Iran
  transfers went from 3-12 MB/s with the system's cubic to 19 MB/s with bbr; this was why
  downloads were much slower than uploads (the Iran server already used bbr). If the kernel
  does not offer the algorithm, the system default stays (logged once). `system` keeps it.
- Tools -> **Optimize this server** (also `eztunnel optimize [--apply|--undo]`): BBR with the
  fq queue, no slow start after idle, MTU probing, 32 MB socket buffer limits, larger TCP
  windows, fast open, and larger connection backlogs. It lists every change with the current
  and new value, only raises values that are worse, keeps them across reboots
  (/etc/sysctl.d/60-eztunnel-optimize.conf) and saves the old values so **Undo** restores them.
- A tunnel-key test no longer fails 1 run in 32 (it assumed every typo changes the check symbol).


## 0.5.2

Speed on long links (Iran ↔ Europe is about 90 ms). Both servers must run 0.5.2: an older
peer refuses the larger flow-control window.

- New setting `stream_window` (default 64 frames = 1 MiB, 16..1024). It was fixed at 16 frames
  (256 KiB), which capped one user connection at about 2.7 MB/s at 90 ms, on every carrier.
  On the real Iran ↔ foreign link one WSS connection went from 1.3 to 5.9 MB/s with 256.
- `kcp`: fast settings by default (10 ms tick, fast resend after 2, no congestion back-off),
  windows 1024 instead of 128, and a 4 MiB socket buffer. One connection at 90 ms: 0.3 → 13 MB/s.
  New settings: `kcp.nodelay`, `kcp.interval_ms`, `kcp.resend`, `kcp.congestion_control`,
  `kcp.socket_buf_bytes`.
- `fec-udp` / `fec-raw`: the internal relay sockets now get the configured buffer too (they
  dropped bursts). One connection at 90 ms: 1.9 → 11.7 MB/s. `fec.sndwnd`, `fec.rcvwnd` and
  `fec.socket_buf_bytes` are now in the settings screens.
- `xhttp` / `xhttps`: `socket_buf_bytes` is now unset by default, letting the kernel size TCP
  buffers; the fixed 1 MiB (capped by the kernel at about 208 KB) limited one connection to
  about 3.3 MB/s at 90 ms. Now about 24 MB/s.
- The manager raises `net.core.rmem_max`/`wmem_max` when a KCP or FEC tunnel needs larger
  buffers than the kernel allows (`/etc/sysctl.d/60-eztunnel.conf`; removed by Uninstall).


## 0.5.1

From the first test on a real Iran ↔ foreign server pair.

- A tunnel session that ends is now logged at normal level with how long it lasted and why
  (`tunnel session ended seconds=41 reason=tunnel heartbeat timeout`). Before, a link that kept
  dropping only showed repeated reconnects unless debug logging was on.
- The status line has a new `connects=` counter: sessions opened since start. If it keeps
  growing while `sessions` stays the same, the link keeps dropping.
- The side that accepts connections (the server, or a listening client in a direct tunnel) logs
  each authenticated peer.
- Manage tunnels shows a **Link** line for each tunnel: connected and stable, reconnecting (with
  the last drop reason), not connected, or waiting for the other server.
- After creating a tunnel, the wizard checks whether it actually connected to the other server
  and says so.
- The installer removes its unpacked copy before opening the manager, so leaving the menu with
  Ctrl-C no longer leaves a folder in /tmp.
- The transport list puts WSS second and warns that plain WS, HTTP and KCP are often blocked by
  filtering (on the test link they were blackholed right after the handshake).

## 0.5.0

Both servers must run 0.5.x when they use a tunnel key or a direct tunnel over a carrier other
than XHTTP. Configurations written for 0.4 still load unchanged.

### Tunnel manager
- Running `eztunnel` (or `sudo eztunnel`) on a terminal opens a menu: **New tunnel**,
  **Manage tunnels**, **Tools** and **Uninstall**. It replaces the old `eztunnel-setup` script
  (still available as a short alias) and no longer needs Python.
- New tunnel asks, step by step: which server this is (Iran or foreign), the tunnel type
  (reverse or direct), the transport, the tunnel key, the connection, and what to carry (ports,
  SOCKS5, TUN). Settings can stay at the recommended values or be customized per carrier.
  At the end it saves the tunnel, creates and starts its systemd service, offers to open the
  ports in ufw, and shows exactly what to do on the other server.
- Several tunnels per server, each in `/etc/eztunnel/tunnels/NAME.json` with its own service
  `eztunnel-NAME`, running as the `eztunnel` account with only the capabilities it needs.
- Manage tunnels: state of every tunnel; live logs, status, start/stop/restart, debug logging
  on/off, change ports, change settings, edit the file (checked before saving), show the key,
  delete.
- Port lists accept `443, 8443`, `2083=443`, ranges `9000-9010` and `5000=10.0.0.5:5000`.

### Tunnel key
- `tunnel_key` replaces the two key pairs: one short key (`eztunnel key`) with a check symbol that
  catches copying mistakes. Both identities, the XHTTP access token and a TLS certificate are
  derived from it.
- `tls_auto`: TLS carriers need no certificate files; the dialing side pins the derived
  certificate, so any TLS name (SNI) can be used.
- A configuration that contains a tunnel key must not be readable by other users.

### Direct tunnels for every carrier
- `server_dials` (the former `reverse`, which is still accepted) now works with `tcp`, `tcp6`,
  `http`, `https`, `ws`, `wss`, `xhttp`, `xhttps`, `kcp` and `fec-udp`, so the Iran server can
  connect out to the foreign server. `timeouts.reverse_dial_sec` is now
  `timeouts.server_dial_sec` (the old name is accepted).

### Other
- `allowed_targets` accepts `host:*` for every port of one host.
- Logs are plain text when they do not go to a terminal, so the systemd journal stays readable.
- Configuration files keep their field order when written.


## 0.4.0

First release.

### Names
- Binary and service names: `eztunnel`, `eztunnel-setup` and `/etc/eztunnel`.
- Carriers: `fec-udp`, `fec-raw`, `fec-raw-gaming` and `tcp6`. The raw option is
  `proto58_mode`.

### Stability
- Connections that have not finished the key handshake wait in a separate pool and no longer use
  the slots reserved for authenticated sessions (`max_pending_handshakes`, `max_pending_per_ip`).
- Temporary accept errors (for example running out of file descriptors) no longer stop the tunnel;
  loops back off and retry. The process raises its open-file limit at start.
- Clean shutdown on SIGTERM.
- TUN server: handshakes run concurrently; a peer that reconnects replaces its old session at once;
  one invalid local packet is dropped instead of ending the session.
- Reconnect waits get a small random spread. UDP maps release finished conversations on a timer.
- Internal locks no longer turn a task panic into a session-wide failure.
- A one-line status summary is logged every `stats_interval_sec` seconds.

### Carriers
- XHTTP: optional `access_token` (refuses unauthenticated sessions before using resources),
  per-address connection cap (`max_requests_per_ip`), listener survives accept errors.
- Plain `kcp`: caps on total and per-address sessions; junk datagrams logged at debug level.
- Raw carriers: the IPv4 source address of received frames must be the configured peer (not applied
  when address spoofing is configured).
- TLS certificate and key are read once and reloaded automatically when the files change.

### Configuration
- Every timeout, queue size and limit is now a setting with a default and range
  (`timeouts`, `queues`, `kcp`, `fec`, `xhttp`, `max_open_files`, `stats_interval_sec`).
  `eztunnel settings` prints the full list; defaults: `max_streams` is now 1024.
- `eztunnel token` generates an access token. `--gen` templates carry an explanatory note.

### Setup script
- `eztunnel-setup settings | show | set | apply` change any setting without editing JSON.
  The wizard has an optional advanced step; menu item 12 walks through existing settings.
  The service unit gets `LimitNOFILE` from the configuration and a chosen log level.

### Security and dependencies
- Updated `time` (RUSTSEC-2026-0009) and replaced the unmaintained `rustls-pemfile`;
  `cargo audit` reports nothing. Requires Rust 1.88 to build.

### Tests
- 96 automated tests, plus privileged scenario scripts for TUN over ten carriers, TUN with port
  forwarding and the raw-packet matrix.
