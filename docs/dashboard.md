# Web dashboard

The web dashboard is optional. It runs on one server, usually the Iran server, and shows every
tunnel on that server and on the servers you join to it, live, in a browser. From it you can
create, edit, start, stop and delete tunnels, read their logs, run connection checks, update
EZTunnel, keep backups and get alerts on Telegram. It comes in English and Persian, with a dark and
a light theme.

The local terminal manager (`sudo eztunnel`) remains available when the dashboard is stopped.
The central terminal can also view and operate on enrolled servers while the dashboard is running.
Tunnels do not depend on the dashboard: stopping or removing it never stops a tunnel.

## Set it up

On the server that should run it:

```sh
sudo eztunnel
```

**Tools → Web dashboard → Set up the web dashboard on this server.** Choose a random port
(recommended) or your own. The screen shows the address and a random password, once:

```text
  Address:   https://203.0.113.10:41873
  Password:  k7Qm2xRtaP9vYhW3nBcE
```

Keep the password somewhere safe. The dashboard now runs as the `eztunnel-dashboard` service and
starts with the server. Open the address in a browser and sign in. The certificate is self-signed
at first, so the browser warns once; see [Certificate](#certificate) to remove the warning.

If a firewall is in use, open the dashboard's port (TCP) on this server.

The same from the command line:

```sh
sudo eztunnel dashboard setup            # random port; --port 41873 for your own
sudo eztunnel dashboard status
```

## Add your other servers

Each other server runs a small agent that connects out to the dashboard over its HTTPS port, so
nothing has to be opened on the other server. There are two ways to add one, both on the
dashboard's **Servers** page:

- **Join command.** Create a join command and run it on the other server as root. It installs
  EZTunnel from the official release if the server does not have a version that can join, then
  joins and starts the `eztunnel-agent` service. A join command works once and expires.
- **Over SSH.** Add the dashboard's own SSH key (shown on the page) to the other server's
  `authorized_keys`, then give the address, SSH port and user. The dashboard logs in with its key
  and runs the join for you. No password is used or stored; the server's host key is remembered the
  first time.

On the other server, **Tools → Web dashboard → Join this server to a dashboard on another server**
does the same with a join code, and **Leave the dashboard** ends it. Leaving never stops a tunnel.

## Manage enrolled servers from the central terminal

On the server **running the Dashboard**, these commands reuse the same authenticated Dashboard
and Agent actions as the browser (there is no separate terminal registry or Agent connection):

```sh
sudo eztunnel fleet servers                            # all server IDs and freshness (JSON)
sudo eztunnel fleet tunnels --server SERVER_ID         # inventory and online/offline state (JSON)
sudo eztunnel fleet tunnels --server local             # the central host
sudo eztunnel fleet start TUNNEL --server SERVER_ID
sudo eztunnel fleet stop TUNNEL --server SERVER_ID
sudo eztunnel fleet restart TUNNEL --server SERVER_ID
sudo eztunnel fleet logs TUNNEL --server SERVER_ID --lines 80
sudo eztunnel fleet menu                               # interactive selection and operations
```

Use an ID returned by `fleet servers`, not a hostname that might change. Commands
prompt for the Dashboard password without echoing it. For unattended use, pass the password
through **standard input**, for example from your existing secret manager:

```sh
secret-manager-command | sudo eztunnel fleet --password-stdin servers
```

The executable never expects a password or session token in an argument, and it does not save
terminal sessions to disk. `fleet --state-dir PATH` selects a different **local Dashboard**
state directory; this is not a remote dashboard URL. It connects over loopback HTTPS and pins
the Dashboard's locally stored certificate. Keep that state directory root-readable only.

Headless commands print JSON to stdout. Errors (including invalid fleet command arguments)
print JSON to stderr with a nonzero exit code:
2 invalid input; 3 authentication/authorization; 4 offline/unavailable/timeout; 5 unknown server
or tunnel; 6 conflicting operation; 7 other failure. `fleet --help` retains normal CLI help.
For remote operations, typed Agent and connection failure codes are mapped to the same statuses
as local operations; an older Agent that does not provide a typed error code cannot have its
free-form failure text safely guessed, so it is reported as an internal error.
An offline server's tunnel list is **null**
(unknown), not an empty list. A completed HTTP operation is not proof that the data plane has
connected; inspect the resulting status separately.

Remote work requires the Dashboard and the target Agent to be connected. **Local** management
with `sudo eztunnel menu` still works when the Dashboard is offline, and stopping the Dashboard
never stops existing tunnels. Create/pair/edit/delete and specialized TUN/Raw/CDN workflows
remain available through their established interfaces; this initial CLI covers fleet inventory,
basic tunnel actions and recent logs only.

## What it shows and does

| Page | What it is for |
|---|---|
| Overview | Every server and tunnel at a glance: traffic, ping, loss, sessions, CPU, memory and disk, with 24 hours, 7 days and 30 days of history. |
| Tunnels | Each tunnel's live figures and status, as cards or as a compact list (the choice is remembered). Open one for its own page: speed, traffic limit, history, the two ends of the pair, and its log. Create a tunnel on any two servers in four steps (a dice button picks a free random port), with the carrier's own options (Parallax mode, speed mode, TLS look and fragmentation, TCP congestion control, FEC pacer, parallel connections); edit its settings (with a review of the changes and an undo): the carrier's choices, and only the numeric settings its carrier, mode and side use, grouped as in the terminal manager; start, stop, restart or delete it. When the other end of the pair is on a managed server, stop, start, restart and delete offer to do the same there. |
| Servers | The servers in the dashboard, online or not, with their version; add or remove servers. |
| Health | A score for every server at once; open one for its checks (time sync, network tuning, UDP buffers, memory, disk, firewall, tunnel files and services) and fix what it can with one click. |
| Connection test | The transport checker between two servers ([checker](checker.md)): **Find transports** (every transport with its defaults) or **Tune transports** (the chosen ones with every option they have, in rounds), each with a depth preset or **Custom** (transports, raw TUN packet types, measurements, extra checks, rounds and ports chosen by hand). Find results offer **Tune the best 3**; tune results list every transport's options best first. A tunnel is created from any result with its tested option; the path finder (can the two servers reach each other, over IPv4 and, when both have one, IPv6; what the Iran server reaches abroad; which other server could relay); and the Mirage source test ([Mirage](mirage.md)), whose results can be filtered, sorted, copied and saved as CSV or JSON. |
| Logs | Any tunnel's log, live, with level filter, search, copy and download; and the dashboard's own activity log (sign-ins, every action). |
| Maintenance | The EZTunnel version on each server. **Update** brings a server to the newest official release: the dashboard knows each server's CPU and downloads and checks the right file itself. **Update all** does every server in turn and stops at the first one that fails. A program file can also be uploaded (only officially signed files are accepted) and installed on one server or on all of them in turn (the first one as a canary), or a server rolled back. Back up every server's tunnels now or on a schedule, and restore a kept backup, or a backup file, on any server. A restore starts the tunnels it adds; with **Replace**, tunnels that were running restart with the restored settings and stopped ones stay stopped. |
| Alerts | Problems found now (a tunnel down, high loss, steady UDP drops, a traffic limit reached, a server offline, low disk) and their history. |
| Settings | Language and theme, password and signed-in sessions, Telegram alerts, a proxy for downloads and Telegram, and a metrics endpoint. |

Installing a new version uses each server's own updater: it accepts only officially signed
EZTunnel programs, keeps the old program, restarts that server's tunnels one by one and goes back by
itself if one does not stay up. The updater replaces only a program that is itself a signed release: a
server still on v0.9.14 or older moves to v0.10.0 once with the installer. Backups contain the tunnel keys; keep downloaded backup files
private.

## Telegram alerts

Create a bot with @BotFather, add it to the chat or channel that should get the alerts, and enter
the bot's token and the chat in **Settings → Telegram alerts**. Choose **Problems only** or **Problems and warnings**, and whether a message also goes out when an
alert clears. **Send test message** checks it at once, with the values in the form whether they are
saved or not, and the panel shows how the last message went. If Telegram is not reachable directly from the server, set a proxy under
**Settings → Proxy** (`socks5h://` also resolves names through the proxy).

## Certificate

To open the dashboard without a browser warning, use a free Let's Encrypt certificate for the
server's IP address or for a domain that points to it: **Tools → Web dashboard → Use a Let's
Encrypt certificate**, or

```sh
sudo eztunnel dashboard certificate --lets-encrypt --address 203.0.113.10
```

Let's Encrypt checks the server over port 80 for about a minute, so port 80 must be free and open
while it runs. The dashboard renews the certificate by itself. `--self-signed` goes back to the
self-signed certificate.

## Managing the dashboard

**Tools → Web dashboard** shows whether the dashboard runs, its address and its certificate, and
offers what fits:

| Step | Command line |
|---|---|
| Start, stop or restart it | `sudo systemctl start eztunnel-dashboard` (or `stop`, `restart`) |
| Reset the password (every browser is signed out) | `sudo eztunnel dashboard reset-password` |
| Change the port | `sudo eztunnel dashboard port 41874` |
| Let's Encrypt or self-signed certificate | `sudo eztunnel dashboard certificate --lets-encrypt` / `--self-signed` |
| Show its recent log | `sudo journalctl -u eztunnel-dashboard -n 40` |
| Remove it (tunnels keep running) | `sudo eztunnel dashboard remove` (add `--delete-data` to delete its settings, history and backups too) |

A removed dashboard that kept its data runs again with the same settings and password after
**Set up** (or `sudo eztunnel dashboard setup`).

Uninstalling EZTunnel (**Uninstall** in the main menu) also removes the dashboard's service and asks
whether to delete its data, and a joined server leaves its dashboard.

After an update, the dashboard and the agents keep running the program they started with until
they restart: **Restart the dashboard** and, on joined servers, **Restart the agent** on the same
screen.

## Security

- HTTPS only, with a random port and a random 20-character password. Five wrong passwords from one
  address within 15 minutes lock it out for 5 minutes, then longer each time (up to a day).
- Sessions end after 12 hours without use and after 7 days in any case; you can see and end other signed-in sessions in
  Settings. Changing the password ends every other session.
- The link between an agent and the dashboard is encrypted and both ends prove their keys; an agent
  answers only a fixed list of requests.
- Every sign-in and action is written to the activity log (`/var/lib/eztunnel-dashboard/audit.log`).
  Repeated refused sign-ins from one address are written once a minute with a count, and the log
  moves to `audit.log.1` when it passes 8 MiB, so it stays small whatever is sent to the dashboard.
- Every server reports its IPv4 address and, when it has one, its stable IPv6 address (shown on
  Servers). **IPv6** in the new-tunnel transport list runs the transport chosen under it between
  the servers' IPv6 addresses, for a route that blocks IPv4 (the transport check shows which
  family works); the listening server must have an IPv6 address.
- Tunnels cannot be named `dashboard` or `agent`: those are the names of the dashboard's and the
  agent's own services.
- The dashboard's settings, history and backups are in `/var/lib/eztunnel-dashboard/`, readable by
  root only.

## Try it without a server

```sh
eztunnel dashboard demo
```

serves the interface with sample data on `http://127.0.0.1:47832` only, and prints a password.
Nothing on the machine is read or changed.
