# Two-server test checklist (foreign server + Iran server)

Goal: prove that each carrier you plan to use works on the real link between your two servers,
and learn which ones survive your network. Do the steps in order. Take notes in the table at
the end.

Roles: the **Iran server** has the ports users connect to (`server` role). The **foreign
server** runs the real service (`client` role). Replace `IRAN_IP` and `FOREIGN_IP` below.

## 0. Before you start

- Release files: the `.run` installer and `SHA256SUMS`. Check the installer against `SHA256SUMS`
  on your own PC first: `sha256sum -c SHA256SUMS`.
- Both servers: Linux x86-64 with systemd. Root access.
- Firewall (very important): allow the tunnel port only from the other server's address.
  For a reverse tunnel on the Iran server: `ufw allow from FOREIGN_IP to any port 7000 proto tcp`,
  and the user ports, for example `ufw allow 18080/tcp`. For UDP carriers (`kcp`, `fec-udp`)
  allow UDP instead of TCP, and for `fec-udp` also the knock port (tunnel port + 10000).
- A test service on the foreign server, for example `python3 -m http.server 8080 --bind 127.0.0.1`.

## 1. Install (both servers)

```sh
sudo bash eztunnel-linux-x86_64.run
```

The manager opens. The banner shows the version of the program you installed.

## 2. Basic tunnel with `tcp` (the reference)

On the Iran server: **New tunnel**. On the foreign server afterwards: **New tunnel** again.

| Screen | Iran server | Foreign server |
| --- | --- | --- |
| Which server is this? | Iran server | Foreign server |
| Tunnel type | Reverse | Reverse |
| Transport | TCP | TCP |
| Tunnel key | Create a new key | Paste a key (from the Iran server) |
| Connection | tunnel port `7000` | Iran address `IRAN_IP`, port `7000` |
| What to carry | Port forwarding, ports `18080=8080`, TCP | Port forwarding, only services on this server |
| Settings | recommended | recommended |

Check:

1. From your PC: `curl http://IRAN_IP:18080/` returns the test service's page.
2. Manage tunnels shows both as `● running`. Live logs shows `authenticated tunnel connected`;
   after a minute a `status:` line appears with `sessions=4`.
3. Speed and loss: Tools → *Link test: wait for the other server* on the Iran server, then
   Tools → *Link test: test the link* on the foreign server with `IRAN_IP:47000`. Save the output.

Then repeat with **Direct** as the tunnel type on both servers (the Iran server asks for
`FOREIGN_IP`, and the firewall rule moves to the foreign server's tunnel port).

## 3. Resilience checks (repeat for every carrier you will use)

| Check | How | Expected |
| --- | --- | --- |
| Restart one side | Manage → the tunnel → Restart | Back within about 10-30 seconds; new connections work |
| Restart the other side | the same on the other server | Same |
| Link cut | On the foreign server: `iptables -I OUTPUT -d IRAN_IP -j DROP`, wait 60 s, then remove the rule with `iptables -D OUTPUT -d IRAN_IP -j DROP` | Recovers by itself within the retry cap (default 30 s) |
| Stop is clean | Manage → Stop | Log says "shutting down"; exit is clean |
| Reboot | Reboot one server | The service starts by itself and reconnects |
| Several users | Run 20 `curl` requests at once through the map | All succeed |

## 4. Try each carrier

Create a new tunnel on both servers with the next transport and the same key (Manage → Show the
pairing code and key), and delete the previous one. Repeat sections 2-3. Suggested order, simplest first:
`tcp`, `ws`, `wss`, `xhttp`/`xhttps`, `kcp`, `fec-udp`. TLS carriers (`https`, `wss`, `xhttps`)
need nothing extra: the certificate comes from the tunnel key. `fec-raw`, `fec-raw-gaming` and
`tun` need a VPS that allows raw packets and the real IPv4 address of each server; try them last
and read [raw-protocol.md](raw-protocol.md) first.

If one carrier is blocked or very slow on your link, that is a result, not a failure: note it.

## 5. Soak

Leave the best carrier running for 24 to 72 hours. Look at the `status:` line from time to time
(Live logs, or `journalctl -u eztunnel-NAME | grep status | tail`). Warning signs: `refused` or
`rejected` growing steadily, `sessions` dropping below the pool size for long periods, or
repeated reconnect messages.

## 6. What to send back when something fails

- The version from the banner, the carrier and the tunnel type.
- The config with the key removed (`/etc/eztunnel/tunnels/NAME.json`; replace the `tunnel_key` value).
- Logs from both sides around the time of the problem, with debug detail
  (Manage → the tunnel → Log detail → debug).
- The link test output, and what the network was doing (provider, any filtering you suspect).

## Results table

| Carrier | Reverse works? | Direct works? | Speed (Mbit/s) | Loss % | Survives link cut | Survives restart | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| tcp | | | | | | | |
| ws / wss | | | | | | | |
| xhttp / xhttps | | | | | | | |
| kcp | | | | | | | |
| fec-udp | | | | | | | |
| tun | | | | | | | |
