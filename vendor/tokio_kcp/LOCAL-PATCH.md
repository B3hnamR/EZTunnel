# Local patch

This is `tokio_kcp` version 0.9.8 from Matrix-Zhang/tokio_kcp, distributed under the MIT license in `LICENSE`. Its upstream README and attribution are retained.

The patch adds `KcpSocket::set_window_size(send, receive)` and `KcpStream::shared_session()`, and reexports the existing public `KcpSession` type. The caller holds the existing session lock before changing the underlying KCP windows. The owned session handle lets eztunnel run one independently timed controller task per explicitly enabled adaptive stream; a drop guard aborts that task. Dropping `KcpStream` still closes its session. These API additions do not change the KCP wire format or congestion algorithm.

Upstream: https://github.com/Matrix-Zhang/tokio_kcp

## Listener limits and logging (EZTunnel)

`KcpConfig` gained `max_sessions` and `max_sessions_per_ip` (both default to `usize::MAX`, which keeps the upstream behaviour). The listener ignores packets that would start a new session beyond those limits. Malformed or unexpected packets are logged at `debug` instead of `error`, so a stream of junk datagrams cannot flood the log.

## Packet sinks and direct input (EZTunnel)

A session can write its packets to a `PacketSink` instead of a UDP socket (`KcpSocket::with_sink`, `KcpStream::connect_with_sink`; the plain UDP behaviour is the `UdpSink` it always had), and packets that arrive elsewhere are fed in with `KcpSession::input_direct` (`KcpSocket::input_batch`: several packets, the acknowledgements they ask for flushed once, one batch out). `KcpSession::new_shared_server` makes a server-side session without a listener. `KcpStream::with_session` is public, `batch::Outgoing::iter` was added, and the `AsRawFd` / `AsRawSocket` impls of `KcpStream` were removed because a session no longer always has a socket. The FEC carrier uses this to encode and send in the same task instead of through a loopback socket. The KCP wire format is unchanged.

## Resend burst (EZTunnel)

`KcpConfig::resend_burst` (default 0 = no limit) is applied with `Kcp::set_resend_burst` of the vendored `kcp` crate
(`../kcp`, see its `LOCAL-PATCH.md`).

## Sink backpressure and SRTT (EZTunnel, 0.8.11)

`PacketSink` gained `congested(&self) -> bool` (default `false`, so `UdpSink` and any other existing implementation
is unaffected). `KcpSocket::poll_send_inner` and `try_wake_pending_waker` both treat a congested sink the same as
the KCP send window being full: `poll_send` returns `Pending` and is woken again once the sink is no longer
congested (checked on every KCP `update()` tick, not only on an explicit wake, so this can never hang). EZTunnel's
`FecSink` (`fec_carrier.rs`) uses this so a full send queue applies backpressure instead of silently dropping a
packet that then comes back as a spurious KCP resend. `KcpSocket::srtt()` exposes the underlying `Kcp::srtt()` for
EZTunnel's optional pacer (`fec.pacer`). Neither changes the KCP wire format.

## Peer pinning and replacement cleanup (EZTunnel)

UDP-backed client streams connect their socket to the configured peer, including batched receives. Established conversation IDs are no longer replaced by incoming packet IDs; explicit conv=0 allocation remains supported. Session close notifications carry a weak identity reference, and the listener removes only that exact session, even if an address and conversation ID have been reused. The wire format is unchanged.
