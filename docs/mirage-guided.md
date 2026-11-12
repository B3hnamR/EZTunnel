# Mirage: Enter IPs, Test, Then Create A Tunnel

Use **Tools -> Mirage source tests**, or run:

```sh
sudo eztunnel spooftest menu
```

The manager creates private files, temporary keys, and separate test ports. You
do not need to write JSON or copy permanent keys to run the normal workflow.
It does not use SSH credentials, install a tunnel, start a service, or open a
firewall rule during testing.

## 1. Start On Iran

Choose **Start on Iran** and answer:

1. The foreign server's real IPv4 address.
2. Iran's real IPv4 address; a route-selected local address is suggested. Confirm
   the correct public address if the host is behind NAT.
3. **Spoof IPs Foreign should send toward Iran**. Paste permitted IPv4 addresses,
   separated by commas, spaces, semicolons, or whitespace. Duplicates are removed;
   CIDR ranges are not scanned.
4. Packet types: the common TCP/UDP/ICMP set, all seven, or one selected profile.
5. Quick (5 probes) or extended (20 probes) reachability sample.
6. Whether to test the return direction too. For Iran's outgoing source, `real`
   keeps Iran's real IP; an explicit source list is also accepted.

Leave **Choose unused ports automatically** selected unless you need specific
reachable ports. No firewall changes are automatic. If arbitrary inbound TCP ports
are blocked, choose a permitted control port or use Advanced/manual mode. A free
local port does not guarantee provider reachability.

Review the scope, then create the invitation. Keep Iran's manager open. All typed
and pasted input is visible in full, wrapping and redrawing as needed; no hidden
input or head/tail-only preview is used. Press Enter to submit. Invitation and
setup contents contain credentials, so use a private terminal and do not publish
screenshots or terminal logs containing them. A short confirmation avoids
unnecessarily printing the entire list or code a second time.

The invitation remains visible until you confirm that you have copied it. Press
Enter on Iran to start listening/open the live table before Foreign joins. In
the live host screen, `i` displays the same invitation and joining instructions
again without stopping the worker. A canceled run needs a fresh invitation.

## 2. Join On Foreign

Choose **Join on Foreign**, paste the `ezm-test1-...` invitation from Iran, review
the host/IP/profile scope, and explicitly permit the test on this server.

The invitation is a bearer secret: share privately. It contains a fresh temporary
test key, explicit endpoints, candidate lists, profile/depth scope, and ports.
It expires after **10 minutes** and can start one run. Anyone holding it can
impersonate this test peer during that window. Its checksum detects copy damage;
it is not an issuer signature or authorization to use someone else's IP address.
Both endpoints still authenticate with Noise using the temporary key.

The worker removes its private invitation file immediately after loading it. The
manager does not put the secret in process arguments. Saved result files do not
contain the test key. An exclusive consumed marker prevents reopening the Iran
run. A canceled or expired run needs a new invitation, not a credential override.
Expiration bounds joining; an accepted run may continue beyond that join window
within the overall test deadline.

## 3. Watch Results

Iran-bound probes run first, followed by the optional reverse-direction matrix.
Both screens show completed cases and then share the full sender measurements.
Receiving progress says **waiting for peer RTT report** until those values exist.

The checker-style live viewport shows elapsed time, observed/total cases, final
RTT-report count, and a scrollable color-coded table. Arrows select rows, Tab
switches direction, `w` filters to received rows, `d` shows details and `l` shows
recent worker logs; `i` on Iran reopens the invitation. `q` asks for confirmation; press it again within five seconds
to stop. Ctrl+C cancels immediately. Terminal size changes are handled without
printing an unbounded stream of duplicate rows. There is no pause command because
the current test protocol does not negotiate synchronized pausing.

| Label | Meaning |
|---|---|
| No receipt | This receiver did not accept any authenticated probe in the sample |
| Lossy sample | Some probes arrived, but not all |
| Received; return lossy | Receiver saw probes, but not all explicit raw replies returned |
| Passed sample | All probes and replies in this bounded sample returned |
| Error | Setup, scope, or another explicit operation failed |
| Awaiting peer report | One-way observation exists; final return measurement is not yet shared |

Rows are ordered by one-way loss, return loss, then p95 RTT. There is no artificial
score or claim of stable long-running operation from 5 or 20 packets. RTT is an
application raw round trip, not necessarily player-to-game-server latency.
AF_PACKET/admission receipt is not ordinary kernel UDP-socket acceptance or a
verified forwarding tunnel. A source/profile/direction can work on one route and
fail on another. Zero receipt does not identify where a provider/path dropped it.

Ctrl+C stops the active test. Completed rows are saved privately as a **partial**
run, not a pass. The other endpoint ends on control disconnect. A failure before
the first completed row may leave no useful result. Reports are under the active
manager root's `mirage-tests/`, normally `/etc/eztunnel/mirage-tests/`; private
files use mode 0600 and newly created state directories use mode 0700.

## 4. Use A Result

Open **Saved results**, select a session, then a source/profile row. You can:

- Create a tunnel from a completed row that actually reached Iran.
- Retest that source/profile with an extended sample and a fresh peer invitation.
- Inspect both directions' receipts, return counts, and RTT.

Saved results use the same viewport; Enter opens actions for the selected
original row even after sorting/filtering. Partial receiving-only rows remain
explicit and cannot be used as finished tunnel evidence.

Creating a tunnel asks which endpoint this is, retains local Mirage consent,
offers the measured return profile/source or an explicit manual alternative,
then asks what to carry: ports, SOCKS, TUN, or TUN+ports. Manual unmeasured return
choices are clearly identified; they are not promoted into measured results.
The source/expected-source relationship is filled correctly for the selected role.

The setup generates a **fresh permanent tunnel key**, never reusing the temporary
test key. Review the local configuration. On systemd-capable hosts the default
finish action is **Save and start**, matching ordinary tunnel setup. **Save only**
remains available; when systemd is unavailable, only saving is offered. A missing
unit is installed on explicit start. No firewall rule changes automatically.
The `ezm-setup1-...` peer code is shown after saving, even if local startup fails,
so the opposite endpoint can still be configured. A failed start is an error,
not a success message; saved configuration is retained for logs/repair.

## 5. Import On The Other Endpoint

Use the ordinary **New tunnel -> Paste a pairing code** screen and paste the
`ezm-setup1-...` code, just like other tunnel pairing codes. The Mirage menu's
**Import peer tunnel setup** remains a convenience alias to the same flow.
The setup code is a
different bearer secret containing the new tunnel key and reciprocal config; it
expires after **24 hours**. Share privately. It does not carry SSH access or skip
the other host's local Mirage risk consent.

The preview shows role, real peer, source settings, directional profiles, ports,
forwarding destinations/allowlists, and any TUN settings. Import refuses arbitrary
private-key/TLS file paths and local gateway/MAC/interface overrides. Review the
configuration, give it a new name, and choose **Save and start** (default) or
**Save only**. Existing tunnel names are not overwritten. Explicitly confirming
Save and start installs/starts the local service; no remote SSH action occurs.
The running process may still be **waiting for peer** until the other endpoint
starts. Only authenticated session health establishes a connected link. If
startup fails, configuration remains saved and the error directs you to logs.
No manual Start on both sides is required after choosing Save and start.

Do not paste `ezm-test1-...` here: that is a temporary testing invitation and the
pairing screen directs it to **Join on Foreign** instead.

The setup bundle has a corruption checksum, not a trusted publisher signature.
Only import a privately shared code from the endpoint/operator you trust. Anyone
holding it possesses that tunnel credential. Existing configurations retain their
ordinary private-file rules and Noise identity checks.

## Manual Setup And Advanced Tuning

New Mirage setup defaults to the current v2 workflow. Basic manual setup asks for
directional packet types and this/peer source lists, then offers **Use these
settings** or **Advanced tuning**. TTL/DSCP, padding, fake-TLS prefix, source-port
shuffle, redundancy and echo modes stay available in Advanced. Basic edits preserve
all existing expert values; entering the form no longer resets sources to `real`
or padding/repair to defaults.

Existing Mirage v1 configurations continue to load/run. They are not offered as
the normal new-tunnel choice. Explicit legacy configuration is under compatibility
when editing; conversion is never an automatic downgrade and requires both ends
to match. TCP/TCP v2 is not v1-compatible. Other carriers and the old manual
`spooftest listen/run --config ...` CLI remain supported for automation.

See [mirage.md](mirage.md) for packet formats, profile/MTU/source semantics,
shaping and XDP limitations. XDP remains isolated feasibility work, not a supplied
production receive accelerator. This UX release does not remove known0.9.1
adaptive/gaming performance risks or claim universal spoof reachability.
