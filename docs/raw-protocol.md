# Raw IPv4 carriers



These are the Ethernet II and IPv4 outer packet layouts used by the raw carriers. They wrap
this project's own locally authenticated tunnel payloads.

| Profile | IPv4 protocol | Header following IPv4 |
|---|---:|---|
| `tcp` | 6 | 20-byte TCP; data offset 5, PSH + ACK, window 65535 |
| `udp` | 17 | 8-byte UDP; zero UDP checksum permitted for IPv4 |
| `icmp` | 1 | 8-byte ICMP echo request from client, reply from server |
| `gre` | 47 | `00 00 08 00`, then payload |
| `ipip` | 4 | Payload directly after IPv4 |
| `raw` | 253 | Payload directly after IPv4 |
| `dns` | 17 | 8-byte UDP (port 53) + 12-byte DNS header + 28-byte question + 11-byte EDNS0 OPT record carrying the payload |
| proto58 mode | 58 | `da 66 e7 01`, then payload |

Every ordinary packet has a 20-byte IPv4 header, TTL 64, and a valid IPv4
checksum. TCP has a valid IPv4 pseudoheader checksum; ICMP has its own checksum.
proto58 mode is IPv4 carrying protocol 58. It does not use an IPv6 outer header. Its
IPv4 DF bit is set; the decoder rejects fragments, invalid checksums, unexpected
protocols, invalid lengths and an incorrect four-byte marker. Ethernet padding
is excluded using IPv4's total-length field.

The `dns` profile disguises every packet as a real, protocol-legal DNS message to UDP port 53: a
standard header, one question, and an EDNS0 OPT additional record whose RDATA is the tunnel
payload (real resolvers use OPT records for message-size negotiation, so this is not malformed).
The client's packets are framed as ordinary recursive queries (QR=0); the server's are framed as
NXDOMAIN answers (QR=1, RCODE 3) with no answer records, matching the fact that the fake question
name does not exist. That name is not a fixed string every installation shares — it is an 8
hex-character label under `cdn-cache.net`, derived from both endpoints' addresses and the shared
port (the same value regardless of which side computes it), so each tunnel pair looks different on
the wire. None of this adds authentication of its own: the UDP checksum and the DNS header, question
and OPT record are all checked, but acceptance and real security still come entirely from the Noise
handshake above, exactly as for every other profile.

proto58 mode is selected with `proto58_mode: true`. IPv6 traffic inside the tunnel is supported
independently of the outer IPv4 carrier.

The `raw` options sit inside a listener or client path:

```json
"raw": {
  "profile": "tcp",
  "interface": "eth0",
  "local_ip": "192.0.2.1",
  "peer_ip": "192.0.2.2",
  "l4_port": 443,
  "proto58_mode": false,
  "sock_buf": 4194304
}
```

After the next hop is resolved, the socket gets a kernel packet filter (classic BPF) that lets
through only IPv4 frames addressed to the interface's MAC address, with the carrier's IP protocol
and, unless addresses are spoofed, the peer's source address; the kernel also stops handing the
socket the frames it sends itself (Linux 4.20 and later). Everything else on the interface never
reaches the program. Ports, flags and checksums are still checked by the program, and the filter
admits a subset of what the program accepts, never less. `raw.kernel_filter` (default `true`) turns
it off for diagnosis. On the two tested servers it made no measurable difference to CPU use: the
interfaces carry little other traffic, so the gain is expected only on a busy interface.

The runtime reads the existing route and interface information through
iproute2, binds one `AF_PACKET` socket to the selected interface, and resolves
the next-hop MAC using ARP. It requires `CAP_NET_RAW`; creating the inner TUN
also requires `CAP_NET_ADMIN`. It changes no route, firewall, sysctl or neighbor
entry. The interface must be Ethernet or veth. `interface`, `local_ip` and
`gateway_ip` can be supplied explicitly. The next hop is looked up once, when the tunnel starts: if the router or gateway between the two servers is replaced (new hardware address), restart the tunnel. `peer_mac` supplies an explicit
next-hop MAC and skips ARP, useful for isolated tests or unusual network paths.

`spoof_src_ip` and `spoof_dst_ip` change the outer IPv4 fields while transmission
continues to the real peer's Ethernet next hop. Both peers must have a network
path that actually delivers those frames. Destination spoofing therefore
requires deliberate network configuration; a normal routed Internet path
may forward or discard the packet according to its destination field. proto58 mode
and spoofing are mutually exclusive.
Peer authentication remains in Noise and does not depend on a claimed outer
source IP.

The `fec-raw` TCP disguise adds timestamp options and sequence /
acknowledgement pattern. The default `tcp_flags: "pa"` emits PSH + ACK with two
NOP bytes and a TCP timestamp option (32-byte TCP header). Including `s` emits
the MSS 1460, SACK-permitted, timestamp and window-scale 8 options
(40-byte header). Supported flag letters are `f`, `s`, `r`, `p`, `a`, `u`.
The timestamp seed is generated locally. Raw TUN keeps a plain
20-byte TCP header. The `fec-raw` TCP IPv4 header sets TOS `0xb8` (DSCP 46,
ECN zero) and the DF bit, as this carrier's packet template.
Raw TUN retains TOS zero and no IPv4 flags; proto58 mode retains its separate
TOS-zero, protocol-58, DF-set template.

The server's outer TCP/UDP source port is `l4_port`, and the client's source port
is `source_port` when configured, otherwise `l4_port + 1` (65534 when the service
port is 65535). Both ends must specify the same `source_port` override. The packet
socket pins transmission to one configured peer; independent peer pairs use
separate profile configurations.

ICMP identifiers use the sender's configured port and receivers check the
peer's identifier. This direction check discards automatic kernel echo replies
that merely reflect an outgoing tunnel datagram, while authenticated tunnel
responses carry the other peer's identifier. 

`tests/raw_vm.sh` defines a root-only local namespace matrix. It covers all
seven profiles, proto58 mode, source spoofing, destination spoofing, their combination,
ARP resolution, `fec-raw` transport and the gaming profile. Each scenario
tests inner IPv4 and IPv6 ICMP, UDP and TCP half-close, a server restart and TUN
cleanup. The TCP default scenarios introduce 2% packet loss inside the client
namespace. Execution results belong in the test report; the script's existence
alone does not establish a passed test.

## Kernel replies and firewall rules (raw TCP)

The raw TCP profile (`fec-raw`, `fec-raw-gaming`, and `tun` with `profile: "tcp"`) builds its own
TCP packets and opens no socket. The kernel therefore sees TCP segments for a port that nobody
listens on, and answers each one with a TCP reset (RST). Resets can break the link through NATs
and stateful firewalls on the path, and connection tracking may mark the packets invalid.

Two rules keep the kernel out of it, for each of the two raw ports (the service port `l4_port` and
the client's source port, `source_port` or `l4_port + 1`), limited to the other server's address
(when addresses are spoofed, to the ports only):

```
iptables -t raw    -I PREROUTING -p tcp -s PEER -m comment --comment eztunnel:NAME --dport PORT -j CT --notrack
iptables -t mangle -I OUTPUT     -p tcp -d PEER -m comment --comment eztunnel:NAME --sport PORT --tcp-flags RST RST -j DROP
```

Every raw TCP listener and path of the tunnel gets its rules (before 0.8.5 only the first one did). The comment names
the tunnel: two tunnels that need the same rule each add their own, so stopping one never removes the other's. A
tunnel's rules from before 0.8.5 (without the comment) are replaced by the tagged ones the next time the tunnel is
restarted by the manager or an update.

**The manager offers them; they are never added silently.** After creating a raw TCP tunnel the
wizard shows the exact commands and asks. Manage tunnels has a line, *Raw TCP firewall rules*, to
turn them on or off and to re-apply them when they went missing. The rules live in a small
systemd unit, `eztunnel-NAME.firewall.service`, that is started before the tunnel and removes the
rules when it is stopped, disabled or when the tunnel is deleted. They survive a reboot without
`iptables-save`, and editing the tunnel's ports updates them. The unit needs `iptables` (the nft
backend is fine); without it the manager says so and you can run the commands above by hand.

The rules are not a cure for a path that drops the packets: on a real Iran link the whole raw TCP
family still failed with them in place (the network dropped the packets, not the kernel), so test
a raw carrier with the transport checker or `eztunnel linktest` before relying on it. Avoid
ports such as 80 and 443 for the raw port; the rules also match outgoing packets from that port.
