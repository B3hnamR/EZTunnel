//! A machine-readable list of every numeric setting an operator may change.
//!
//! `eztunnel settings` prints this list as JSON so that tools such as the setup script can show
//! defaults and allowed ranges without repeating them. A unit test checks every entry against the
//! real configuration validator, so the list cannot drift away from the program's behaviour.

use serde::Serialize;
use serde_json::{Value, json};

/// Where in the configuration file a setting lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Place {
    /// Top level of the file.
    Top,
    /// Inside each entry of `listeners` (server).
    Listener,
    /// Inside each entry of `paths` (client).
    Path,
}

#[derive(Debug, Clone, Serialize)]
pub struct Setting {
    /// Dotted name inside its place, for example `timeouts.handshake_sec`.
    pub name: &'static str,
    pub place: Place,
    /// Which machine uses it: `server`, `client` or `both`.
    pub role: &'static str,
    /// Default value, or `null` when the setting is off unless set.
    pub default: Value,
    pub min: u64,
    pub max: u64,
    pub unit: &'static str,
    pub description: &'static str,
    /// Other settings that must be set first for the range above to be accepted. A name that
    /// starts with `./` lives in the same place (listener or path) as this setting.
    #[serde(skip)]
    pub needs: &'static [(&'static str, u64)],
}

#[allow(clippy::too_many_arguments)]
const fn s(
    name: &'static str,
    place: Place,
    role: &'static str,
    default: u64,
    min: u64,
    max: u64,
    unit: &'static str,
    description: &'static str,
) -> (
    &'static str,
    Place,
    &'static str,
    u64,
    u64,
    u64,
    &'static str,
    &'static str,
) {
    (name, place, role, default, min, max, unit, description)
}

pub fn all() -> Vec<Setting> {
    use Place::{Listener, Path, Top};
    let rows = [
        s(
            "parallax.buffer_bytes",
            Listener,
            "server",
            65536,
            4096,
            1048576,
            "bytes",
            "Parallax: bounded byte buffer per direction; TCP supplies retransmission and congestion control.",
        ),
        s(
            "parallax.buffer_bytes",
            Path,
            "client",
            65536,
            4096,
            1048576,
            "bytes",
            "Parallax: bounded byte buffer per direction.",
        ),
        s(
            "parallax.handshake_timeout_sec",
            Listener,
            "server",
            10,
            1,
            60,
            "seconds",
            "Parallax: deadline for authenticated lane setup and pairing.",
        ),
        s(
            "parallax.handshake_timeout_sec",
            Path,
            "client",
            10,
            1,
            60,
            "seconds",
            "Parallax: total deadline to establish both directional lanes.",
        ),
        s(
            "parallax.max_pending",
            Listener,
            "server",
            128,
            2,
            4096,
            "lanes",
            "Parallax: simultaneous handshakes and unpaired lanes.",
        ),
        s(
            "parallax.max_pending_per_ip",
            Listener,
            "server",
            16,
            2,
            4096,
            "lanes",
            "Parallax: pending lanes per source IP; the global max_pending ceiling also applies.",
        ),
        s(
            "parallax.max_sessions",
            Listener,
            "server",
            64,
            1,
            4096,
            "pairs",
            "Parallax: accepted and pending lane-pair limit.",
        ),
        s(
            "crypto_level",
            Top,
            "both",
            1,
            1,
            1,
            "level",
            "Configured dialing crypto level; level 2 is rejected until its handshake is implemented.",
        ),
        s(
            "crypto_min",
            Top,
            "both",
            1,
            1,
            1,
            "level",
            "Minimum accepted crypto level; currently only level 1 is implemented.",
        ),
        s(
            "heartbeat_sec",
            Top,
            "both",
            10,
            1,
            3600,
            "seconds",
            "How often each side checks that the other is alive. Must be smaller than dead_timeout_sec, than fec.peer_idle_sec on FEC carriers and than xhttp.session_timeout_sec on XHTTP carriers.",
        ),
        s(
            "dead_timeout_sec",
            Top,
            "both",
            40,
            2,
            86_400,
            "seconds",
            "A silent peer is declared dead after this long. Must be larger than heartbeat_sec.",
        ),
        s(
            "max_streams",
            Top,
            "both",
            1024,
            1,
            65_536,
            "streams",
            "Most simultaneous user connections carried by one tunnel session.",
        ),
        s(
            "stream_window",
            Top,
            "both",
            64,
            16,
            1024,
            "frames",
            "Data one user connection may have in flight, in 16 KiB frames. One connection's speed is at most window x 16 KiB per round trip (64 = 1 MiB, about 11 MB/s at 90 ms). Larger is faster on long links and uses more memory for slow users.",
        ),
        s(
            "memory_budget_mb",
            Top,
            "both",
            0,
            0,
            1_048_576,
            "MiB",
            "Total memory the flow-control windows of all user connections may use beyond the first 256 KiB each. 0 = automatic: a quarter of the server's memory, between 64 MiB and 1 GiB. When it is used up, new connections keep a small window (a lower speed on long links) instead of the server running out of memory.",
        ),
        s(
            "worker_threads",
            Top,
            "both",
            1,
            1,
            64,
            "threads",
            "Threads that run the tunnel. One is the most efficient (moving work between threads costs more CPU than it saves); raise it only for a very fast FEC carrier, which one core cannot encode and decode fast enough. Needs a restart.",
        ),
        s(
            "stats_interval_sec",
            Top,
            "both",
            60,
            0,
            86_400,
            "seconds",
            "Log a one-line status summary this often. 0 turns it off.",
        ),
        s(
            "max_connections",
            Top,
            "both",
            16,
            1,
            1024,
            "sessions",
            "Most simultaneous authenticated tunnel sessions.",
        ),
        s(
            "max_pending_handshakes",
            Top,
            "server",
            64,
            1,
            4096,
            "connections",
            "Connections allowed to wait for the key handshake, over all listeners.",
        ),
        s(
            "max_pending_per_ip",
            Top,
            "server",
            16,
            1,
            256,
            "connections",
            "Handshakes one source address may have waiting at once.",
        ),
        s(
            "max_streams_per_ip",
            Top,
            "server",
            512,
            0,
            65_536,
            "streams",
            "Forwarded connections and UDP conversations one source address may have open at once through the maps and the SOCKS5 listener. Enforced only while the sessions are more than three quarters full, so an address (many users behind one shared address are one address) may use all the room there is, but cannot take the last quarter from the others. 0 = no limit.",
        ),
        s(
            "timeouts.handshake_sec",
            Top,
            "server",
            10,
            1,
            300,
            "seconds",
            "Time a new connection has to finish the key handshake.",
        ),
        s(
            "timeouts.connect_sec",
            Top,
            "both",
            10,
            1,
            300,
            "seconds",
            "Time allowed to reach the real destination, and for a SOCKS5 greeting.",
        ),
        s(
            "timeouts.open_sec",
            Top,
            "both",
            15,
            1,
            300,
            "seconds",
            "Time a stream may wait for the far side to confirm it opened.",
        ),
        s(
            "stealth.pad_min",
            Top,
            "both",
            64,
            0,
            4095,
            "bytes",
            "Wire version 2: printable padding at the start of each direction of a plain TCP, KCP or FEC stream, at least this many bytes. A long printable start keeps the first packet from looking like uniform noise.",
        ),
        s(
            "stealth.pad_max",
            Top,
            "both",
            255,
            0,
            4095,
            "bytes",
            "Wire version 2: printable padding (at most this many bytes) at the start of each direction of a plain TCP, KCP or FEC stream, so its first packet has no fixed length.",
        ),
        s(
            "stealth.probe_hold_sec",
            Top,
            "both",
            5,
            0,
            120,
            "seconds",
            "Wire version 2: a connection that fails the handshake is ignored for a random time up to this long before it is closed, so a probe sees silence instead of an instant close. 0 closes at once.",
        ),
        s(
            "stealth.record_pad_max",
            Top,
            "both",
            0,
            0,
            255,
            "bytes",
            "Wire version 2: pad every record this side sends by a random 0..this many bytes, so record sizes no longer show what is inside (acknowledgements, heartbeats, small requests). Costs about half this many bytes per record. 0 = off. Each side sets its own.",
        ),
        s(
            "stealth.jitter_ms",
            Top,
            "both",
            0,
            0,
            1000,
            "ms",
            "Wire version 2: delay the start of each burst of sending by a random 0..this many milliseconds, so the timing of sporadic traffic is not a copy of the user's. Records following within 20 ms of the previous one are not delayed, so bulk transfers keep their speed. 0 = off. Each side sets its own.",
        ),
        s(
            "timeouts.udp_idle_sec",
            Top,
            "both",
            120,
            5,
            86_400,
            "seconds",
            "A forwarded UDP conversation with no traffic for this long is closed.",
        ),
        s(
            "timeouts.tcp_idle_sec",
            Top,
            "both",
            3600,
            0,
            86_400,
            "seconds",
            "A forwarded TCP connection with no data in either direction for this long is closed. 0 = never.",
        ),
        s(
            "timeouts.goodbye_wait_ms",
            Top,
            "both",
            500,
            0,
            5000,
            "ms",
            "When the tunnel stops (restart, update, stop), it first tells the other server, which then reconnects as soon as this side is back instead of after its dead timeout. This is how long it keeps running so that notice is sent. 0 = stop at once.",
        ),
        s(
            "timeouts.probe_sec",
            Top,
            "both",
            3,
            1,
            60,
            "seconds",
            "How long a session may go without any answer: after this long a ping asks (any frame back counts), after twice this long the session takes no new users and the side that dialed it tries a fresh connection, replacing the silent session if the fresh one works. Also: when the other server connects again, its older sessions get a ping and those silent for this long are closed.",
        ),
        s(
            "timeouts.retry_max_sec",
            Top,
            "both",
            30,
            1,
            3600,
            "seconds",
            "Longest pause between reconnect attempts (each wait also gets a random extra of up to 25%, so pooled sessions do not retry in lockstep).",
        ),
        s(
            "timeouts.server_dial_sec",
            Top,
            "both",
            30,
            1,
            300,
            "seconds",
            "When the server dials (server_dials): time to reach the client and finish the handshake.",
        ),
        s(
            "queues.stream_frames",
            Top,
            "both",
            32,
            20,
            4096,
            "frames",
            "Frames that may wait in memory for one stream. Raised to stream_window + 4 when smaller, so a full window always fits.",
        ),
        s(
            "queues.session_frames",
            Top,
            "both",
            128,
            16,
            65_536,
            "frames",
            "Frames that may wait in memory for one session.",
        ),
        s(
            "kcp.mtu",
            Listener,
            "server",
            1400,
            512,
            9000,
            "bytes",
            "Packet size of the plain kcp carrier. Use the same value on both ends.",
        ),
        s(
            "kcp.send_window",
            Listener,
            "server",
            1024,
            16,
            8192,
            "packets",
            "Plain kcp send window: packets in flight. Speed is at most window x MTU per round trip.",
        ),
        s(
            "kcp.recv_window",
            Listener,
            "server",
            1024,
            16,
            8192,
            "packets",
            "Plain kcp receive window.",
        ),
        s(
            "kcp.session_expire_sec",
            Listener,
            "server",
            60,
            5,
            3600,
            "seconds",
            "Inactive plain kcp sessions are closed after this long.",
        ),
        s(
            "kcp.mtu",
            Path,
            "client",
            1400,
            512,
            9000,
            "bytes",
            "Packet size of the plain kcp carrier. Use the same value on both ends.",
        ),
        s(
            "kcp.send_window",
            Path,
            "client",
            1024,
            16,
            8192,
            "packets",
            "Plain kcp send window: packets in flight. Speed is at most window x MTU per round trip.",
        ),
        s(
            "kcp.recv_window",
            Path,
            "client",
            1024,
            16,
            8192,
            "packets",
            "Plain kcp receive window.",
        ),
        s(
            "kcp.session_expire_sec",
            Path,
            "client",
            60,
            5,
            3600,
            "seconds",
            "Inactive plain kcp sessions are closed after this long.",
        ),
        s(
            "kcp.interval_ms",
            Listener,
            "server",
            10,
            10,
            5000,
            "ms",
            "Plain kcp: how often packets are sent and resent. Lower reacts faster and uses more CPU.",
        ),
        s(
            "kcp.resend",
            Listener,
            "server",
            2,
            0,
            255,
            "packets",
            "Plain kcp: resend a packet after this many later ones arrived (0 = wait for the timer).",
        ),
        s(
            "kcp.socket_buf_bytes",
            Listener,
            "server",
            4_194_304,
            65_536,
            67_108_864,
            "bytes",
            "Plain kcp: UDP socket buffer. Must hold a full window; the kernel caps it at net.core.rmem_max.",
        ),
        s(
            "fec.sndwnd",
            Listener,
            "server",
            1024,
            128,
            8192,
            "packets",
            "FEC: packets in flight. With the buffers it bounds speed: window x packet size per round trip.",
        ),
        s(
            "fec.rcvwnd",
            Listener,
            "server",
            1024,
            128,
            8192,
            "packets",
            "FEC: packets this side accepts ahead of the reader.",
        ),
        s(
            "fec.socket_buf_bytes",
            Listener,
            "server",
            4_194_304,
            262_144,
            67_108_864,
            "bytes",
            "FEC: UDP socket buffers (outside and internal). The kernel caps them at net.core.rmem_max.",
        ),
        s(
            "kcp.interval_ms",
            Path,
            "client",
            10,
            10,
            5000,
            "ms",
            "Plain kcp: how often packets are sent and resent. Lower reacts faster and uses more CPU.",
        ),
        s(
            "kcp.resend",
            Path,
            "client",
            2,
            0,
            255,
            "packets",
            "Plain kcp: resend a packet after this many later ones arrived (0 = wait for the timer).",
        ),
        s(
            "kcp.socket_buf_bytes",
            Path,
            "client",
            4_194_304,
            65_536,
            67_108_864,
            "bytes",
            "Plain kcp: UDP socket buffer. Must hold a full window; the kernel caps it at net.core.rmem_max.",
        ),
        s(
            "fec.sndwnd",
            Path,
            "client",
            1024,
            128,
            8192,
            "packets",
            "FEC: packets in flight. With the buffers it bounds speed: window x packet size per round trip.",
        ),
        s(
            "fec.rcvwnd",
            Path,
            "client",
            1024,
            128,
            8192,
            "packets",
            "FEC: packets this side accepts ahead of the reader.",
        ),
        s(
            "fec.socket_buf_bytes",
            Path,
            "client",
            4_194_304,
            262_144,
            67_108_864,
            "bytes",
            "FEC: UDP socket buffers (outside and internal). The kernel caps them at net.core.rmem_max.",
        ),
        s(
            "kcp.max_sessions",
            Listener,
            "server",
            1024,
            1,
            65_536,
            "sessions",
            "Plain kcp: most simultaneous sessions.",
        ),
        s(
            "kcp.max_sessions_per_ip",
            Listener,
            "server",
            64,
            0,
            65_536,
            "sessions",
            "Plain kcp: most sessions from one source address; 0 = no limit.",
        ),
        s(
            "fec.peer_idle_sec",
            Listener,
            "server",
            60,
            5,
            3600,
            "seconds",
            "A FEC peer with no traffic for this long is forgotten. Must be larger than heartbeat_sec (an idle tunnel only sends its heartbeat).",
        ),
        s(
            "fec.knock_ttl_sec",
            Listener,
            "server",
            30,
            5,
            3600,
            "seconds",
            "How long a knock keeps its source address admitted.",
        ),
        s(
            "fec.session_expire_sec",
            Listener,
            "server",
            60,
            5,
            3600,
            "seconds",
            "Inactive FEC KCP sessions are closed after this long.",
        ),
        s(
            "fec.session_expire_sec",
            Path,
            "client",
            60,
            5,
            3600,
            "seconds",
            "Inactive FEC KCP sessions are closed after this long.",
        ),
        s(
            "fec.partial_flush_ms",
            Listener,
            "server",
            10,
            0,
            1000,
            "ms",
            "FEC: when fewer than 10 packets were sent and nothing follows for this long, a parity packet for those few is sent, so a loss among them is repaired at once instead of waiting for a retransmission; 0 = off.",
        ),
        s(
            "fec.partial_flush_ms",
            Path,
            "client",
            10,
            0,
            1000,
            "ms",
            "FEC: when fewer than 10 packets were sent and nothing follows for this long, a parity packet for those few is sent, so a loss among them is repaired at once instead of waiting for a retransmission; 0 = off.",
        ),
        s(
            "kcp.resend_burst",
            Listener,
            "server",
            128,
            0,
            8192,
            "packets",
            "Plain kcp: most packets resent at once (per interval) after their retransmission timer expired; the rest follow in the next intervals. 0 = no limit (the whole window at once, which a short queue on the path drops again).",
        ),
        s(
            "kcp.resend_burst",
            Path,
            "client",
            128,
            0,
            8192,
            "packets",
            "Plain kcp: most packets resent at once (per interval) after their retransmission timer expired; the rest follow in the next intervals. 0 = no limit (the whole window at once, which a short queue on the path drops again).",
        ),
        s(
            "fec.resend_burst",
            Listener,
            "server",
            128,
            0,
            8192,
            "packets",
            "FEC: most packets resent at once (per interval) after their retransmission timer expired; the rest follow in the next intervals. 0 = no limit (the whole window at once, which a short queue on the path drops again).",
        ),
        s(
            "fec.resend_burst",
            Path,
            "client",
            128,
            0,
            8192,
            "packets",
            "FEC: most packets resent at once (per interval) after their retransmission timer expired; the rest follow in the next intervals. 0 = no limit (the whole window at once, which a short queue on the path drops again).",
        ),
        s(
            "xhttp.max_requests",
            Listener,
            "server",
            256,
            1,
            65_536,
            "connections",
            "XHTTP: simultaneous HTTP connections accepted.",
        ),
        s(
            "xhttp.max_requests_per_ip",
            Listener,
            "server",
            64,
            0,
            65_536,
            "connections",
            "XHTTP: most simultaneous HTTP connections from one source address; 0 = no limit (use 0 or a high value behind a CDN).",
        ),
        s(
            "fec.max_peers_per_ip",
            Listener,
            "server",
            64,
            0,
            4096,
            "conversations",
            "FEC: most conversations (one per client connection) one source address may have at once, so one address cannot take every peer slot; 0 = no limit.",
        ),
        s(
            "xhttp.max_sessions_per_ip",
            Listener,
            "server",
            0,
            0,
            65_536,
            "sessions",
            "XHTTP: most simultaneous sessions from one source address, counted for the whole life of the session; 0 = no limit (the default; behind a CDN every user shares a few edge addresses).",
        ),
        s(
            "xhttp.max_sessions",
            Listener,
            "server",
            64,
            1,
            65_536,
            "sessions",
            "XHTTP: simultaneous sessions.",
        ),
        s(
            "xhttp.edge_retry_sec",
            Path,
            "client",
            60,
            1,
            3600,
            "seconds",
            "XHTTP: how long a failed edge address is skipped.",
        ),
        s(
            "retry_interval",
            Path,
            "client",
            1,
            1,
            30,
            "seconds",
            "First pause before reconnecting; it doubles up to timeouts.retry_max_sec.",
        ),
        s(
            "dial_timeout",
            Path,
            "client",
            10,
            1,
            300,
            "seconds",
            "Time allowed to connect and finish the handshake.",
        ),
        s(
            "connection_pool",
            Path,
            "client",
            1,
            1,
            1024,
            "sessions",
            "Parallel tunnel sessions to keep open. More sessions spread users and limit the effect of one dropping.",
        ),
        s(
            "schedule.restart_every_hours",
            Top,
            "both",
            0,
            0,
            8760,
            "hours",
            "Restart the tunnel after it has run this long: it exits cleanly and the service starts it again. 0 = never.",
        ),
        s(
            "quota.limit_gb",
            Top,
            "both",
            0,
            0,
            1_000_000,
            "GB",
            "Most data (both directions together, 1 GB = 10^9 bytes) this tunnel carries per period. When it is reached the tunnel stops carrying traffic until the period ends. 0 = no limit.",
        ),
        s(
            "quota.period_days",
            Top,
            "both",
            30,
            1,
            3650,
            "days",
            "Length of one quota period. The first period starts when the tunnel first runs.",
        ),
    ];
    let mut list: Vec<Setting> = rows
        .into_iter()
        .map(
            |(name, place, role, default, min, max, unit, description)| Setting {
                name,
                place,
                role,
                default: json!(default),
                min,
                max,
                unit,
                description,
                needs: match name {
                    "dead_timeout_sec" => &[("heartbeat_sec", 1)],
                    "heartbeat_sec" => &[("dead_timeout_sec", 7200)],
                    "connection_pool" => &[("max_connections", 1024)],
                    "stealth.pad_min" => &[("stealth.pad_max", 4095)],
                    "stealth.pad_max" => &[("stealth.pad_min", 0)],
                    "stealth.record_pad_max" | "stealth.jitter_ms" => &[("wire_version", 2)],
                    _ => &[],
                },
            },
        )
        .collect();
    list.push(Setting {
        name: "xhttp.socket_buf_bytes",
        place: Listener,
        role: "server",
        default: Value::Null,
        min: 65_536,
        max: 67_108_864,
        unit: "bytes",
        description: "XHTTP: fixed TCP socket buffer. Unset lets the kernel grow it with the link (fastest); a fixed value caps one connection's speed.",
        needs: &[],
    });
    list.push(Setting {
        name: "xhttp.socket_buf_bytes",
        place: Path,
        role: "client",
        default: Value::Null,
        min: 65_536,
        max: 67_108_864,
        unit: "bytes",
        description: "XHTTP: fixed TCP socket buffer. Unset lets the kernel grow it with the link (fastest); a fixed value caps one connection's speed.",
        needs: &[],
    });
    for (place, role) in [(Listener, "server"), (Path, "client")] {
        list.push(Setting {
            name: "xhttp.up_concurrency",
            place,
            role,
            default: json!(8),
            min: 1,
            max: 16,
            unit: "requests",
            description: "XHTTP packet-up: uploads in flight at once. Upload speed is at most this x up_max_bytes per round trip, so long links need more.",
            needs: &[],
        });
    }
    list.push(Setting {
        name: "tls_fragment.min_bytes",
        place: Listener,
        role: "server",
        default: json!(10),
        min: 1,
        max: 1024,
        unit: "bytes",
        description: "TLS fragmentation (when on): smallest piece of the ClientHello per TLS record.",
        needs: &[("./tls_fragment.max_bytes", 1024)],
    });
    list.push(Setting {
        name: "tls_fragment.max_bytes",
        place: Listener,
        role: "server",
        default: json!(60),
        min: 1,
        max: 1024,
        unit: "bytes",
        description: "TLS fragmentation (when on): largest piece of the ClientHello per TLS record.",
        needs: &[("./tls_fragment.min_bytes", 1)],
    });
    list.push(Setting {
        name: "tls_fragment.delay_ms",
        place: Listener,
        role: "server",
        default: json!(5),
        min: 0,
        max: 1000,
        unit: "ms",
        description: "TLS fragmentation (when on): longest random pause between pieces; 0 = none.",
        needs: &[],
    });
    list.push(Setting {
        name: "tls_fragment.min_bytes",
        place: Path,
        role: "client",
        default: json!(10),
        min: 1,
        max: 1024,
        unit: "bytes",
        description: "TLS fragmentation (when on): smallest piece of the ClientHello per TLS record.",
        needs: &[("./tls_fragment.max_bytes", 1024)],
    });
    list.push(Setting {
        name: "tls_fragment.max_bytes",
        place: Path,
        role: "client",
        default: json!(60),
        min: 1,
        max: 1024,
        unit: "bytes",
        description: "TLS fragmentation (when on): largest piece of the ClientHello per TLS record.",
        needs: &[("./tls_fragment.min_bytes", 1)],
    });
    list.push(Setting {
        name: "tls_fragment.delay_ms",
        place: Path,
        role: "client",
        default: json!(5),
        min: 0,
        max: 1000,
        unit: "ms",
        description: "TLS fragmentation (when on): longest random pause between pieces; 0 = none.",
        needs: &[],
    });
    list.push(Setting {
        name: "max_open_files",
        place: Top,
        role: "both",
        default: Value::Null,
        min: 256,
        max: 16_777_216,
        unit: "files",
        description: "Open-file limit to request. When unset, the hard limit is used.",
        needs: &[],
    });
    list
}

/// Sets `dotted` (for example `timeouts.open_sec`) inside a JSON object, creating objects on the way.
pub fn set_dotted(target: &mut Value, dotted: &str, value: Value) {
    let mut node = target;
    let parts: Vec<&str> = dotted.split('.').collect();
    for (index, part) in parts.iter().enumerate() {
        if index + 1 == parts.len() {
            node[*part] = value;
            return;
        }
        if !node[*part].is_object() {
            node[*part] = json!({});
        }
        node = &mut node[*part];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn base(role: &str) -> Value {
        let key = "11".repeat(32);
        if role == "server" {
            json!({"mode":"server","private_key_file":"k","peer_public_keys":[key],
                   "listeners":[{"addr":"127.0.0.1:7000"}]})
        } else {
            json!({"mode":"client","private_key_file":"k",
                   "paths":[{"addr":"127.0.0.1:7000","server_public_key":key}]})
        }
    }

    fn apply(setting: &Setting, config: &mut Value, value: u64) {
        apply_with(setting, config, value, true);
    }

    fn target<'a>(setting: &Setting, config: &'a mut Value) -> &'a mut Value {
        match setting.place {
            Place::Top => config,
            Place::Listener => &mut config["listeners"][0],
            Place::Path => &mut config["paths"][0],
        }
    }

    fn apply_with(setting: &Setting, config: &mut Value, value: u64, with_needs: bool) {
        if with_needs {
            for (name, needed) in setting.needs {
                match name.strip_prefix("./") {
                    Some(local) => set_dotted(target(setting, config), local, json!(needed)),
                    None => set_dotted(config, name, json!(needed)),
                }
            }
        }
        set_dotted(target(setting, config), setting.name, json!(value));
    }

    fn accepted(config: &Value) -> bool {
        serde_json::from_value::<Config>(config.clone())
            .map(|c| c.validate().is_ok())
            .unwrap_or(false)
    }

    #[test]
    fn every_listed_range_matches_the_real_validation() {
        for setting in all() {
            let roles: &[&str] = match setting.role {
                "server" => &["server"],
                "client" => &["client"],
                _ => &["server", "client"],
            };
            for role in roles {
                for good in [setting.min, setting.max] {
                    if setting.name == "retry_interval" && good > 30 {
                        continue;
                    }
                    let mut config = base(role);
                    apply(&setting, &mut config, good);
                    assert!(
                        accepted(&config),
                        "{} = {good} should be accepted for the {role}",
                        setting.name
                    );
                }
                for bad in [setting.min.wrapping_sub(1), setting.max + 1] {
                    let mut config = base(role);
                    apply(&setting, &mut config, bad);
                    assert!(
                        !accepted(&config),
                        "{} = {bad} should be rejected for the {role}",
                        setting.name
                    );
                }
            }
        }
    }

    #[test]
    fn every_listed_default_is_what_the_program_uses() {
        for setting in all() {
            if setting.default.is_null() {
                continue;
            }
            let role = if setting.role == "client" {
                "client"
            } else {
                "server"
            };
            let mut config = base(role);
            apply_with(
                &setting,
                &mut config,
                setting.default.as_u64().unwrap(),
                false,
            );
            let defaulted = base(role);
            let a: Config = serde_json::from_value(config).unwrap();
            let b: Config = serde_json::from_value(defaulted).unwrap();
            assert_eq!(
                serde_json::to_value(&a).unwrap(),
                serde_json::to_value(&b).unwrap(),
                "setting {} default differs from the built-in default",
                setting.name
            );
        }
    }

    #[test]
    fn names_are_unique_per_place() {
        let list = all();
        for (index, one) in list.iter().enumerate() {
            for other in &list[index + 1..] {
                assert!(
                    !(one.name == other.name && one.place == other.place),
                    "duplicate setting {}",
                    one.name
                );
            }
        }
    }
}
