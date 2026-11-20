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

The browser, interactive central menu and headless CLI reuse the **same authenticated Dashboard HTTPS
API and live Agent connections**. No terminal-only server registry, management database or alternate
Agent exists. Run these on the **server hosting the Dashboard** (not on an Agent):

```sh
sudo eztunnel fleet servers                       # online/offline and current inventories (JSON)
sudo eztunnel fleet tunnels --server SERVER_ID
sudo eztunnel fleet options                       # currently supported central-create transports
sudo eztunnel fleet status TUNNEL --server SERVER_ID
sudo eztunnel fleet status TUNNEL --server SERVER_ID --live  # control-socket figures
sudo eztunnel fleet logs TUNNEL --server SERVER_ID --lines 80
sudo eztunnel fleet settings TUNNEL --server SERVER_ID
sudo eztunnel fleet preset TUNNEL --server SERVER_ID --preset gaming       # preview
sudo eztunnel fleet preset TUNNEL --server SERVER_ID --preset gaming --write # apply
sudo eztunnel fleet rename-server SERVER_ID --name 'Display name'
sudo eztunnel fleet health --server SERVER_ID
sudo eztunnel fleet tool TUNNEL pairing --server SERVER_ID --form /root/pairing-options.json
sudo eztunnel fleet tool TUNNEL speedtest --server SERVER_ID --form /root/speedtest-options.json
sudo eztunnel fleet tool TUNNEL quota_reset --server SERVER_ID
sudo eztunnel fleet start TUNNEL --server SERVER_ID
sudo eztunnel fleet stop TUNNEL --server SERVER_ID --both
sudo eztunnel fleet restart TUNNEL --server SERVER_ID --both
sudo eztunnel fleet restart-all --server SERVER_ID
sudo eztunnel fleet join-code                      # secret, single-use Agent enrollment code
sudo eztunnel fleet remove-server SERVER_ID --confirm SERVER_ID
sudo eztunnel fleet menu                           # interactive server and tunnel operations
```

`SERVER_ID` is an ID from `fleet servers`; `local` means the Dashboard host (and is the default).
An Agent can enroll with the generated join code by running `sudo eztunnel agent join CODE`
**on that Agent**. The Dashboard's optional SSH-based automatic installer remains a browser-only
shortcut; direct terminal enrollment does not require SSH to the Agent.

### Create both ends, edit, undo and delete

The JSON form uses the **same fields as the Dashboard's new-tunnel wizard**, not separate
config-generation code. Choose two distinct online enrolled servers, or one and `local`. Specify
the **reachable address of the listening endpoint**; never assume the Agent's reported private IP
is reachable from the other end. Example `/root/new-pair.json` for a reverse TCP tunnel:

```json
{
  "iran": "local",
  "foreign": "SERVER_ID",
  "name": "site-link",
  "transport": "tcp",
  "direction": "reverse",
  "address": "203.0.113.10",
  "tunnel_port": 7000,
  "carry": "ports",
  "ports": "8080",
  "protocol": "tcp",
  "reach": "local"
}
```

```sh
sudo eztunnel fleet create --form /root/new-pair.json
sudo eztunnel fleet settings site-link --server local
```

Both endpoint configurations are built with one fresh tunnel key. The listener is created and
started before the dialing end. Creation uses the Dashboard's existing busy locks, audit trail,
service installation and key-guarded cleanup attempts if creation fails. The Dashboard and Fleet
inventory share the resulting pair fingerprint.

For configuration changes, save **only** the fields to change (same as the browser's edit panel)
in `/root/changes.json`:

```json
{
  "quota": {"limit_gb": 100, "period_days": 30},
  "settings": [{"name": "heartbeat_sec", "place": "top", "value": 15}]
}
```

```sh
sudo eztunnel fleet edit site-link --server local --changes /root/changes.json
sudo eztunnel fleet undo site-link --server local
sudo eztunnel fleet delete site-link --server local --both --confirm site-link
# If only the matching remote endpoint remains after a partial failure:
sudo eztunnel fleet delete site-link --server SERVER_ID --expect-pair PAIR_FINGERPRINT --confirm site-link
```

`settings` returns editable fields, types, ranges, the 0.12.0 performance presets with their
server-specific values, and whether undo is available. `fleet preset` previews the current
server's numeric and connection-pool changes. `--write` applies them through the existing
Dashboard edit/undo path; without it, no configuration is changed. Apply the same preset
separately to both tunnel endpoints, using each server's own hardware-dependent values.
`fleet rename-server` changes only the Dashboard display name (an empty name resets it).
Edit and undo reuse the existing validate/apply/restart/revert behavior. A plain deletion requires the exact
name via `--confirm`; `--both` requires **exactly two visible online endpoints** with the same
pair fingerprint and consistent roles before modifying either endpoint. Paired start, stop,
restart and delete report results separately for each side. Starting is listener-first; stopping
and deleting are dialer-first; paired restart stops both before starting the listener. There is
no distributed two-phase transaction: if one request fails or times out, the CLI exits nonzero
(code **8** for a partially executed pair) and prints completed attempts and remaining targets in
JSON for operator reconciliation. It does not claim rollback or safe blind retry.

For guarded deletion, the current saved tunnel fingerprint is checked under its own exclusive
store lock immediately before removing its service, configuration and task-owned resources. A
reused tunnel name with another key is refused (HTTP 409). The same lock-protected identity
guard applies to paired start/stop/restart. **Both Hub and Agent must support `act_pair` and
`delete_pair`** for protected pair operations. Older Agents refuse these new allowlisted
operations instead of silently ignoring a fingerprint. Paired lifecycle requests use distinct
`paired-start/stop/restart` action names on the **existing** Dashboard URL, so older Hubs also
reject them instead of silently ignoring an extra field. Upgrade both before protected paired
actions. The Web deletion dialog distinguishes a stale pair from ordinary Busy errors and
disables retry until the operator refreshes and reselects the target.
An offline Agent's snapshot is unknown (not an empty list); Fleet lists any offline server IDs
as **unverified**, not as confirmed non-members of the pair. On a partial deletion, inspect the
current inventory and retry only a specific remaining endpoint with `--expect-pair`.

### Input, credentials and automation

The CLI prompts privately for the Dashboard password. For automation, pass it on **stdin** from
your secret manager (never via argv or an environment variable):

```sh
secret-manager-command | sudo eztunnel fleet --password-stdin create --form /root/new-pair.json
```

Form and change inputs must be regular JSON-object files no larger than 8 KiB (the Dashboard API body limit). `-` is not a
supported form path, because stdin is reserved for the password. All **headless** Fleet commands
return JSON on stdout and JSON errors on stderr; `fleet menu` uses interactive prompts
instead, and `fleet --help` remains regular human-readable help.
Errors use these nonzero codes: **2** invalid input, **3** auth, **4** disconnected/timeout,
**5** unknown server/tunnel, **6** busy/conflict, **7** other error,
**8** partially failed paired operation or restart-all. Restart-all returns all per-tunnel
results with a nonzero exit code if any restart fails; the interactive menu displays the same
structured failure. Offline status requests return exit **4** (unknown live state), not
`unknown_tunnel`.
A successful HTTP action does not establish that an encrypted tunnel carries traffic: inspect
status, connection checks and actual application traffic separately. Join codes and pairing
codes are secrets; handle output and temporary files accordingly.

The interactive `fleet menu` offers guided creation with the supported carriers, or a JSON form
file for specialized wizard options; selecting a server offers Health and Restart all; selecting
a tunnel offers edit, undo, single/paired lifecycle and single/paired deletion. Back/Esc/No do not
submit mutations. With the Dashboard offline, the **local** `sudo eztunnel menu` still manages
local tunnels without the central Agent fleet.

### Current central-management coverage

| Capability | Web | Central interactive menu | Headless Fleet CLI | Limit |
|---|---|---|---|---|
| Server list, connectivity, tunnel inventory | Yes | Yes | `servers`, `tunnels` | Offline snapshot unknown |
| Tunnel details, recent logs | Yes | Yes | `status`, `logs` | Continuous log follow remains Web-only |
| Create/pair/start both ends | Yes | Guided + JSON form | `create --form` | Dashboard wizard-supported carriers only |
| TCP/UDP, TLS/WSS, Parallax, FEC/KCP, IPv6/Game variants | Yes | Wizard options / JSON file | Same wizard JSON | Not a new transport implementation |
| Edit / undo tunnel configuration | Yes | Fields + JSON changes file | `settings`, `edit`, `undo` | Side-specific settings are edited per endpoint |
| 0.12.0 performance presets and automatic pool | Yes | Preview/apply inside Edit settings | `preset --preset NAME [--write]` | Server-specific values; apply on each end |
| Start/stop/restart one or both matched ends | Yes | Yes | `start/stop/restart [--both]` | Both sides online and identified |
| Delete both ends, with guarded target identity | Yes (manual pair selection) | Yes | `delete --both --confirm` | Pair guard requires updated Agent |
| Server health, tunnel speed test / quota / pairing | Yes | Health; settings / operations | `health`, `tool` | Detailed diagnostic views remain Web-first |
| Enroll / forget Agent | Yes | Code / forget | `join-code`, `remove-server` + `agent join` | SSH auto-install remains Web-only |
| Rename server display name | Yes | Yes | `rename-server ID --name NAME` | Host identity and tunnels unchanged |
| Restart every tunnel on a selected server | Yes | Yes | `restart-all` | Sequential; affects multiple services |
| Backups, restores, binary updates, advanced checks, charts and alert configuration | Yes | Local manager / Web | Dashboard and existing local commands | Not exposed as new Fleet shortcuts |
| Path Finder cancellation, connection-test filtering, Alerts history (0.12) | Yes | Web Dashboard | Web Dashboard | Browser workflows; not duplicated as terminal screens |
| Local Raw/TUN, Mirage and specialist CDN setup | Local manager where available | Local manager | Existing local commands | The Dashboard wizard cannot create these centrally |

The matrix distinguishes **practical central parity** from engine support. An operation unavailable
in the Dashboard/Agent architecture is not magically implemented by exposing a CLI entry point.

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
