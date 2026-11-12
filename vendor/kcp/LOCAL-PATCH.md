# Local patch

This is `kcp` version 0.5.3 from Matrix-Zhang/kcp, distributed under the MIT license in `LICENSE`. Its upstream
README is retained; the upstream tests are not included. The manifest is the published one without its
dev-dependencies.

## Resend burst limit (EZTunnel)

With congestion control off (`nocwnd`, which EZTunnel uses for speed), a retransmission timeout resent every timed-out
segment of the window in one flush: up to the whole window at once (about 1.4 MB at 1024 segments). When the queue at
the bottleneck is smaller than that burst, most of it is dropped again, the timers grow by half (nodelay) and the
transfer stalls for seconds. `Kcp::set_resend_burst(n)` limits the segments one flush resends **because their timer
expired** to `n`; the others keep their expired timer and go out in the next flushes, oldest first. New data, fast
retransmission (duplicate acknowledgements) and the windows are unchanged. `0` (the default) keeps the upstream
behaviour. The wire format is unchanged.

Also: two uses of the deprecated `u32::max_value()` became `u32::MAX` (a path dependency's warnings show in
EZTunnel's build).

## SRTT accessor (EZTunnel, 0.8.11)

`Kcp::srtt()` exposes the already-tracked `rx_srtt` field (0 before the first round-trip sample). Read by
EZTunnel's optional FEC/KCP pacer (`fec.pacer`) through `tokio_kcp`'s own `KcpSocket::srtt()`, which wraps this.
No change to KCP's own behaviour; a getter only.

Upstream: https://github.com/Matrix-Zhang/kcp

## Allocation validation (EZTunnel)

When explicitly learning a server-allocated conversation ID, validate the segment command and payload length before committing the ID. Malformed allocation responses leave the pending allocation unchanged. Established conversations still reject mismatched IDs.
