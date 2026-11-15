//! Path finding for the dashboard: what each server can reach, and whether a third managed
//! server can carry traffic between two that cannot reach each other. Every piece is temporary:
//! an echo listener or a forwarder lives for at most two minutes and then closes by itself, so a
//! relay server is never left changed.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

/// Separate sockets avoid relying on the host's IPv6 dual-stack default.
pub(super) async fn listeners(port: u16) -> Result<Vec<TcpListener>> {
    let v4 = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).await?;
    let port = v4.local_addr()?.port();
    let ipv6 = tokio::net::TcpSocket::new_v6()
        .and_then(|socket| {
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                let enabled: libc::c_int = 1;
                // SAFETY: the pointer and size name a live integer; setsockopt copies it.
                let result = unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY,
                        (&enabled as *const libc::c_int).cast(),
                        std::mem::size_of_val(&enabled) as libc::socklen_t,
                    )
                };
                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            socket.bind(SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port))?;
            socket.listen(128)
        });
    let mut listeners = vec![v4];
    match ipv6 {
        Ok(listener) => listeners.push(listener),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::Unsupported | std::io::ErrorKind::AddrNotAvailable) => {},
        #[cfg(target_os = "linux")]
        Err(error) if matches!(error.raw_os_error(), Some(libc::EAFNOSUPPORT) | Some(libc::EPROTONOSUPPORT)) => {},
        Err(error) => return Err(error).context("bind the IPv6 listener"),
    }
    Ok(listeners)
}

/// Longest a temporary listener or forwarder stays open.
const MAX_LIFE: u64 = 120;

/// Well-known addresses abroad: reaching some but not others shows a whitelist, and the
/// reachable ones are what a relay path could use.
pub const KNOWN: [(&str, &str); 16] = [
    ("GitHub", "140.82.121.4"),
    ("GitHub", "140.82.112.3"),
    ("Cloudflare DNS", "1.1.1.1"),
    ("Cloudflare CDN", "104.16.132.229"),
    ("Google DNS", "8.8.8.8"),
    ("Google", "142.250.185.78"),
    ("Fastly", "151.101.1.140"),
    ("Akamai", "23.215.0.136"),
    ("AWS", "52.94.236.248"),
    ("Azure", "20.70.246.20"),
    ("Microsoft", "13.107.42.14"),
    ("Telegram", "149.154.167.50"),
    ("Hetzner", "88.198.248.254"),
    ("OVH", "51.91.40.88"),
    ("DigitalOcean", "104.131.0.69"),
    ("Gcore", "92.223.84.84"),
];

fn port_ok(port: u64) -> Result<u16> {
    u16::try_from(port).ok().filter(|p| *p >= 1024).context("the port must be 1024 to 65535")
}

fn target_port_ok(port: u16) -> bool {
    port == 22 || port >= 1024
}

fn life(request: &Value) -> Duration {
    Duration::from_secs(request["secs"].as_u64().unwrap_or(60).clamp(5, MAX_LIFE))
}

/// Echoes one complete 16-byte path-check marker, then closes.
async fn echo(port: u16, life: Duration) -> Result<()> {
    let listeners = listeners(port).await.with_context(|| format!("listen on {port} over IPv4 and IPv6"))?;
    for listener in listeners {
        tokio::spawn(async move {
            let _ = timeout(life, async {
                while let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut marker = [0u8; 16];
                        if let Ok(Ok(_)) = timeout(Duration::from_secs(10), stream.read_exact(&mut marker)).await {
                            let _ = timeout(Duration::from_secs(10), stream.write_all(&marker)).await;
                        }
                    });
                }
            })
            .await;
        });
    }
    Ok(())
}

/// A forwarder from a local port to a target, for a short while.
async fn forward(port: u16, target: SocketAddr, life: Duration) -> Result<()> {
    let listeners = listeners(port).await.with_context(|| format!("listen on {port} over IPv4 and IPv6"))?;
    ensure!(target.is_ipv4() || listeners.len() > 1, "IPv6 relay listening is unavailable on this host");
    for listener in listeners {
        tokio::spawn(async move {
            let _ = timeout(life, async {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        if let Ok(Ok(mut outbound)) = timeout(Duration::from_secs(10), TcpStream::connect(target)).await {
                            let _ = timeout(Duration::from_secs(30), tokio::io::copy_bidirectional(&mut inbound, &mut outbound)).await;
                        }
                    });
                }
            })
            .await;
        });
    }
    Ok(())
}

/// Connects, sends a random marker and checks that it comes back.
async fn echo_check(target: SocketAddr) -> Value {
    let mut marker = [0u8; 16];
    let _ = crate::stealth::random_bytes(&mut marker);
    let started = std::time::Instant::now();
    let result = timeout(Duration::from_secs(12), async {
        let mut stream = TcpStream::connect(target).await?;
        stream.write_all(&marker).await?;
        let mut back = [0u8; 16];
        stream.read_exact(&mut back).await?;
        Ok::<bool, std::io::Error>(back == marker)
    })
    .await;
    match result {
        Ok(Ok(true)) => json!({"ok": true, "ms": started.elapsed().as_millis() as u64}),
        Ok(Ok(false)) => json!({"ok": false, "error": "a different answer came back"}),
        Ok(Err(e)) => json!({"ok": false, "error": e.to_string()}),
        Err(_) => json!({"ok": false, "error": "no answer"}),
    }
}

/// A server's side: `{"step": "probe", host, ports}`, `"known"`, `"echo"` ({port, secs}),
/// `"forward"` ({port, target, secs}) or `"echo_check"` ({target}).
pub async fn answer(request: &Value) -> Result<Value> {
    match request["step"].as_str() {
        Some("probe") => {
            let host: IpAddr = request["host"].as_str().unwrap_or("").parse().context("the host must be an IP address")?;
            let extra: Vec<u16> = request["ports"].as_array().into_iter().flatten().filter_map(|p| p.as_u64()).filter_map(|p| u16::try_from(p).ok()).take(8).collect();
            let path = crate::pathprobe::probe(host, &extra, Duration::from_secs(5)).await;
            Ok(json!({"reachable": path.reachable(), "ping": path.ping, "tcp": path.tcp}))
        }
        Some("known") => {
            let mut set = tokio::task::JoinSet::new();
            for (name, ip) in KNOWN {
                set.spawn(async move {
                    let ip: IpAddr = ip.parse().expect("listed address");
                    let result = crate::pathprobe::tcp(ip, 443, Duration::from_secs(5)).await;
                    json!({"name": name, "ip": ip, "result": result})
                });
            }
            let mut list = Vec::new();
            while let Some(Ok(row)) = set.join_next().await {
                list.push(row);
            }
            list.sort_by_key(|r| KNOWN.iter().position(|(_, ip)| r["ip"] == *ip));
            Ok(json!({"known": list}))
        }
        Some("echo") => {
            echo(port_ok(request["port"].as_u64().unwrap_or(0))?, life(request)).await?;
            Ok(json!({"listening": true}))
        }
        Some("forward") => {
            let target: SocketAddr = request["target"].as_str().unwrap_or("").parse().context("the target must be address:port")?;
            ensure!(target_port_ok(target.port()), "the target port must be 22 (SSH path check) or 1024 or higher");
            forward(port_ok(request["port"].as_u64().unwrap_or(0))?, target, life(request)).await?;
            Ok(json!({"forwarding": true}))
        }
        // Something that greets on connect (an SSH server): proves the path without help there.
        Some("banner_check") => {
            let target: SocketAddr = request["target"].as_str().unwrap_or("").parse().context("the target must be address:port")?;
            let started = std::time::Instant::now();
            let result = timeout(Duration::from_secs(12), async {
                let mut stream = TcpStream::connect(target).await?;
                let mut first = [0u8; 64];
                let n = stream.read(&mut first).await?;
                Ok::<String, std::io::Error>(String::from_utf8_lossy(&first[..n]).lines().next().unwrap_or("").to_string())
            })
            .await;
            Ok(match result {
                Ok(Ok(line)) if !line.is_empty() => json!({"ok": true, "ms": started.elapsed().as_millis() as u64, "greeting": line.chars().take(40).collect::<String>()}),
                Ok(Ok(_)) => json!({"ok": false, "error": "connected, but nothing came back"}),
                Ok(Err(e)) => json!({"ok": false, "error": e.to_string()}),
                Err(_) => json!({"ok": false, "error": "no answer"}),
            })
        }
        Some("echo_check") => {
            let target: SocketAddr = request["target"].as_str().unwrap_or("").parse().context("the target must be address:port")?;
            Ok(echo_check(target).await)
        }
        _ => bail!("unknown path request"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_offline_ssh_probe_may_use_a_privileged_target_port() {
        assert!(target_port_ok(22));
        assert!(target_port_ok(1024));
        assert!(!target_port_ok(21));
        assert!(!target_port_ok(0));
        assert!(!target_port_ok(443));
        assert!(!target_port_ok(1023));
    }

    #[tokio::test]
    async fn fragmented_markers_are_echoed_whole() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        echo(port, Duration::from_secs(5)).await.unwrap();
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
        stream.write_all(&[7; 3]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        stream.write_all(&[7; 13]).await.unwrap();
        let mut back = [0; 16];
        timeout(Duration::from_secs(1), stream.read_exact(&mut back)).await.unwrap().unwrap();
        assert_eq!(back, [7; 16]);
    }

    #[tokio::test]
    async fn temporary_listeners_cover_both_address_families_when_available() {
        let listeners = listeners(0).await.unwrap();
        assert!(listeners[0].local_addr().unwrap().is_ipv4());
        if listeners.len() == 2 {
            let port = listeners[0].local_addr().unwrap().port();
            assert_eq!(listeners[1].local_addr().unwrap().port(), port);
            let _client = TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, port)).await.unwrap();
            timeout(Duration::from_secs(1), listeners[1].accept()).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn an_echo_through_a_forwarder_proves_the_relay_path() {
        let free = || std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (end, relay) = (free(), free());
        answer(&json!({"step": "echo", "port": end, "secs": 10})).await.unwrap();
        answer(&json!({"step": "forward", "port": relay, "target": format!("127.0.0.1:{end}"), "secs": 10})).await.unwrap();
        let direct = answer(&json!({"step": "echo_check", "target": format!("127.0.0.1:{end}")})).await.unwrap();
        assert_eq!(direct["ok"], true, "{direct}");
        let relayed = answer(&json!({"step": "echo_check", "target": format!("127.0.0.1:{relay}")})).await.unwrap();
        assert_eq!(relayed["ok"], true, "{relayed}");
        let nothing = answer(&json!({"step": "echo_check", "target": format!("127.0.0.1:{}", free())})).await.unwrap();
        assert_eq!(nothing["ok"], false);
        for bad in [json!({"step": "echo", "port": 80}), json!({"step": "forward", "port": 40000, "target": "127.0.0.1:23"}), json!({"step": "shell"})] {
            assert!(answer(&bad).await.is_err(), "{bad}");
        }
    }
}
