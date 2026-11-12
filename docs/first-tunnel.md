# Your first tunnel between two servers

Scenario: a service (for example a VPN panel) runs on the **foreign** server on port `443`. Users should reach it through the **Iran** server at `IRAN_IP:443`.

- The **Iran server** is where users connect. In the files it has the `server` role.
- The **foreign server** is where traffic leaves to the internet. It has the `client` role.
- Both servers should run the same 0.9.x version. Versions before 0.9.0 use a
  different protocol and cannot connect; wire 1..3 settings do not change that.

Needs on both servers: a matching Linux x86-64 or ARM64 executable, systemd for
managed services, suitable permissions and reachable peer ports. TUN also needs
iproute2 and `/dev/net/tun`; raw networking needs the privileges/interface described
in the architecture guide. Running the executable does not install these tools.

## 1. Install (both servers)

Check the installer on your own computer against `SHA256SUMS` (obtained from a separate place), copy it to both servers, then:

```sh
sudo bash eztunnel-linux-x86_64.run
```

The manager opens by itself. To open it again later: `sudo eztunnel`. Use the arrow keys and Enter; Esc or `q` goes back.

## 2. The first server

Either server can go first. Here the Iran server goes first. Choose **New tunnel** and answer:

| Screen | Answer |
| --- | --- |
| Which server is this? | **Iran server** |
| Tunnel type | **Reverse tunnel**: the foreign server connects to this one. Choose *Direct* if the Iran server should connect out instead. |
| Transport | **TCP** or **WSS** (plain WS, HTTP and KCP are often blocked by filtering) |
| Tunnel key | **Create a new key** |
| Tunnel port on this server | `7000` (any free port) |
| What should the tunnel carry? | **Port forwarding** |
| Ports to forward | `443` |
| Protocol | **TCP** (or TCP + UDP if the service also uses UDP) |
| Settings | **Use the recommended settings** |
| Name | keep the suggestion, for example `iran-tcp` |

Confirm with `y`. The manager saves the tunnel, starts the service `eztunnel-iran-tcp`, and, if the ufw firewall is on, offers to open the ports. It then shows the tunnel key and what to do on the other server:

```text
╭─ On the other server ──────────────────────────────╮
│ 1. Run  sudo eztunnel  on the Foreign server        │
│ 2. New tunnel → Foreign server                      │
│ 3. Reverse tunnel · transport tcp · port 7000       │
│ 4. Paste a key → k7m2q-9xa4b-c3d5e-f6g7h-j8k9m      │
╰─────────────────────────────────────────────────────╯
```

Keep the key secret: whoever has it can join this tunnel.

## 3. The second server

At the end, the first server printed a **pairing code**, one line starting with `ezt1-`. On the foreign server choose **New tunnel → Paste a pairing code** and paste it. The foreign side is created from it, already matching the first server; confirm with `y`. (Manage tunnels → the tunnel → *Show the pairing code and key* prints it again later.)

Or answer the questions yourself: choose **New tunnel → Step by step** and answer:

| Screen | Answer |
| --- | --- |
| Which server is this? | **Foreign server** |
| Tunnel type | the same: **Reverse tunnel** |
| Transport | the same: **TCP** |
| Tunnel key | **Paste a key**, then paste it (a typo is caught right away) |
| Address of the Iran server | `IRAN_IP` |
| Tunnel port on the Iran server | `7000` |
| What should the tunnel carry? | **Port forwarding** |
| Where may forwarded ports lead? | **Only services on this server** |
| Settings | **Use the recommended settings** |

Confirm with `y`. The service `eztunnel-foreign-tcp` starts and connects.

### Port forms

`443` forwards Iran port 443 to port 443 on the foreign server. `2083=443` forwards Iran port 2083 to foreign port 443. `9000-9010` forwards a range. `5000=10.0.0.5:5000` leads to another host reachable from the foreign server (then answer *Any address* to "Where may forwarded ports lead?" on the foreign server). Separate several with commas: `443, 8443, 2083=443`.

## 4. Optimize both servers (recommended)

In the manager: **Tools → Optimize this server**, on both servers. It turns on BBR and a few network settings that make long-distance tunnels much faster (on a real Iran ↔ foreign pair, downloads went from 3-12 to 19 MB/s). It shows each change first, and **Undo the server optimization** restores the old values. The changes are kept in `/etc/sysctl.d/61-eztunnel-optimize.conf`, so they survive a reboot; Uninstall offers to undo them.

## 5. Firewall

If you use ufw, the manager offers to open the ports it listens on. Make the tunnel port private if you can: allow it only from the other server's address, for example on the Iran server:

```sh
sudo ufw allow from FOREIGN_IP to any port 7000 proto tcp
```

Inspect `sudo ufw status numbered` first: an existing broad `allow 7000/tcp`
still permits everyone even after adding the narrow rule. Remove only that
specific broad rule before relying on source restriction; preserve SSH and
unrelated rules. Provider firewall controls remain separate.

If your hosting provider has its own firewall panel, open the same ports there. For UDP carriers (`kcp`, `fec-udp`) open UDP instead of TCP, and for `fec-udp` also the knock port (tunnel port + 10000).

## 6. Test

From any computer, connect to `IRAN_IP:443` the way your users will (for example with your VPN client). Then in the manager choose **Manage tunnels**: both tunnels should show `● running`. Pick one: its **Link** line should say `● 4 connection(s), stable` (it says *reconnecting* with the reason if the link keeps dropping). **Live logs** shows `authenticated tunnel connected` and, about a minute later, a line like

```text
status: sessions=4 connects=4 streams=3 streams_total=57 refused=0 rejected=0 sent=1.2 MiB received=3.4 MiB
```

`sessions` equals the number of parallel connections (4 by default) when the tunnel is healthy. Press Ctrl+C to go back to the menu.

## 7. Changing things later

**Manage tunnels** → pick the tunnel:

- **Change forwarded ports** (Iran server): edit the port list; the service restarts.
- **Change settings**: every limit and timeout for that carrier, with its default; values you changed are highlighted.
- **Edit the config file**: opens the file in nano; it is checked before it is saved.
- **Show the pairing code and key**: to set up the other side again.
- **Restart**, **Stop**, **Start**, **Delete this tunnel**.

To change the transport, create a new tunnel on both servers with the new transport and the same key (Manage → Show the pairing code and key), then delete the old ones.

## If it does not work

If the tunnel connects but keeps reconnecting (Link says *reconnecting*, and the log shows `tunnel session ended ... reason=tunnel heartbeat timeout` about every 40 seconds), the network between the servers is dropping that kind of traffic after the handshake. Create the tunnel again with another transport (TCP, WSS, HTTPS, XHTTPS or FEC-UDP) and the same key.


1. Is the service running? Manage tunnels shows the state; Live logs shows why.
2. Same answers on both sides? Tunnel type, transport and port must match.
3. Same key? A different key is refused; the log shows `peer handshake authentication failed`.
4. Is the port open? Check ufw and the provider's panel.
5. More detail in the logs: Manage → the tunnel → **Log detail** switches debug logging on (and off again when you are done).
6. Measure the link between the servers: Tools → Link test.

A fuller test of a real server pair, including every carrier, is in [two-server-test.md](two-server-test.md).
