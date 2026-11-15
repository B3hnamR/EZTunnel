//! Reaching a target that may be a host name (a SOCKS5 request with a name, a port map to a name).
//!
//! A name often has IPv4 and IPv6 addresses. A server can have an IPv6 address that does not
//! actually work (an address on a VPN interface, a provider that hands out IPv6 without
//! routing it), and the system's address order then puts the broken IPv6 addresses first. Trying
//! them one after another under a single deadline spends the whole deadline on the first dead
//! address and never reaches a working one. So the addresses are tried IPv4 first, alternating
//! with IPv6, and a new attempt starts every `STAGGER` (or at once when one fails) while the
//! earlier ones keep trying; the first connection wins (the "Happy Eyeballs" way, RFC 8305).
use anyhow::{Context, Result, anyhow, ensure};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{collections::VecDeque, future::Future, io, net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, time};

/// How long an attempt runs alone before the next address is tried as well.
pub const STAGGER: Duration = Duration::from_millis(250);

/// Every address once, IPv4 first, then alternating between the two families.
pub fn order(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = Vec::new();
    for address in addresses {
        if !seen.contains(&address) {
            seen.push(address);
        }
    }
    let (mut v4, mut v6): (VecDeque<_>, VecDeque<_>) = seen.into_iter().partition(SocketAddr::is_ipv4);
    let mut ordered = Vec::with_capacity(v4.len() + v6.len());
    while !v4.is_empty() || !v6.is_empty() {
        ordered.extend(v4.pop_front());
        ordered.extend(v6.pop_front());
    }
    ordered
}

async fn resolve(target: &str) -> Result<Vec<SocketAddr>> {
    if let Ok(address) = target.parse::<SocketAddr>() {
        return Ok(vec![address]);
    }
    let addresses = order(tokio::net::lookup_host(target).await.context("resolve the target")?);
    ensure!(!addresses.is_empty(), "the target name has no address");
    Ok(addresses)
}

/// A TCP connection to `target` (`host:port` or `address:port`) within `deadline`.
pub async fn tcp(target: &str, deadline: Duration) -> Result<TcpStream> {
    time::timeout(deadline, async {
        let addresses = resolve(target).await?;
        race(addresses, STAGGER, TcpStream::connect).await
    })
    .await
    .context("target connect timeout")?
}

/// The address a UDP conversation with `target` uses: IPv4 when the name has one, since a UDP
/// socket cannot tell a working family from a dead one before it is too late.
pub async fn udp_address(target: &str, deadline: Duration) -> Result<SocketAddr> {
    let addresses = time::timeout(deadline, resolve(target)).await.context("UDP target lookup timeout")??;
    addresses.into_iter().next().context("UDP target has no address")
}

/// Tries `addresses` in order with staggered starts; the first success wins and the attempts
/// still running are dropped.
async fn race<F, Fut, T>(addresses: Vec<SocketAddr>, stagger: Duration, connect: F) -> Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut waiting: VecDeque<SocketAddr> = addresses.into();
    let mut running = FuturesUnordered::new();
    let mut last: Option<(SocketAddr, io::Error)> = None;
    let attempt = |address: SocketAddr| {
        let connecting = connect(address);
        async move { (address, connecting.await) }
    };
    loop {
        if running.is_empty() {
            match waiting.pop_front() {
                Some(address) => running.push(attempt(address)),
                None => break,
            }
        }
        tokio::select! {
            Some((address, result)) = running.next() => match result {
                Ok(connected) => return Ok(connected),
                Err(error) => {
                    last = Some((address, error));
                    if let Some(next) = waiting.pop_front() {
                        running.push(attempt(next));
                    }
                }
            },
            _ = time::sleep(stagger), if !waiting.is_empty() => {
                if let Some(next) = waiting.pop_front() {
                    running.push(attempt(next));
                }
            }
        }
    }
    Err(match last {
        Some((address, error)) => anyhow!(error).context(format!("connect to {address}")),
        None => anyhow!("the target has no address"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn a(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn ipv4_goes_first_and_the_families_alternate() {
        let ordered = order([a("[2001:db8::1]:443"), a("[2001:db8::2]:443"), a("192.0.2.1:443"), a("192.0.2.2:443"), a("192.0.2.1:443")]);
        assert_eq!(ordered, vec![a("192.0.2.1:443"), a("[2001:db8::1]:443"), a("192.0.2.2:443"), a("[2001:db8::2]:443")]);
        assert_eq!(order([a("[2001:db8::1]:80")]), vec![a("[2001:db8::1]:80")]);
    }

    /// The broken-IPv6 server: the first address never answers, the next one works. The working
    /// one must win soon after the stagger, not after the dead one's timeout.
    #[tokio::test(start_paused = true)]
    async fn a_silent_address_does_not_hold_up_a_working_one() {
        let tried = Arc::new(Mutex::new(Vec::new()));
        let log = tried.clone();
        let started = time::Instant::now();
        let winner = race(vec![a("[2001:db8::1]:443"), a("192.0.2.1:443")], STAGGER, move |address: SocketAddr| {
            log.lock().unwrap().push(address);
            async move {
                if address.is_ipv6() {
                    std::future::pending::<()>().await;
                }
                Ok::<_, io::Error>(address)
            }
        })
        .await
        .unwrap();
        assert_eq!(winner, a("192.0.2.1:443"));
        assert_eq!(started.elapsed(), STAGGER);
        assert_eq!(tried.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_address_moves_on_at_once_and_all_failing_reports_the_last() {
        let started = time::Instant::now();
        let winner = race(vec![a("192.0.2.1:443"), a("192.0.2.2:443")], STAGGER, |address: SocketAddr| async move {
            if address == a("192.0.2.1:443") {
                Err(io::Error::from(io::ErrorKind::ConnectionRefused))
            } else {
                Ok(address)
            }
        })
        .await
        .unwrap();
        assert_eq!(winner, a("192.0.2.2:443"));
        assert_eq!(started.elapsed(), Duration::ZERO, "a refusal starts the next attempt without waiting");
        let failed = race(vec![a("192.0.2.1:443"), a("192.0.2.2:443")], STAGGER, |_| async {
            Err::<(), _>(io::Error::from(io::ErrorKind::ConnectionRefused))
        })
        .await
        .unwrap_err();
        assert!(format!("{failed:#}").contains("192.0.2.2:443"), "{failed:#}");
    }

    /// Real sockets, without the system resolver (test sandboxes may have none): a closed port
    /// first, then a listening one.
    #[tokio::test]
    async fn real_sockets_skip_a_closed_port_and_reach_a_listener() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        let accepting = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let stream = time::timeout(Duration::from_secs(5), race(vec![closed, open], STAGGER, TcpStream::connect)).await.unwrap().unwrap();
        assert_eq!(stream.peer_addr().unwrap(), open);
        accepting.await.unwrap().unwrap();
        // An address is used as it is, with no lookup.
        tcp(&open.to_string(), Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(udp_address(&open.to_string(), Duration::from_secs(1)).await.unwrap(), open);
    }
}
