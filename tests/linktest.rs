//! Actual local sockets verify the diagnostic protocol in both directions.
use anyhow::{Context, Result, ensure};
use eztunnel::linktest::{self, ListenOptions, ProbeOptions};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    task::JoinHandle,
    time::{sleep, timeout},
};

type ListenerTask = JoinHandle<Result<()>>;

fn reserve(ip: IpAddr) -> Result<(std::net::TcpListener, std::net::UdpSocket)> {
    let tcp = std::net::TcpListener::bind(SocketAddr::new(ip, 0))?;
    let udp = std::net::UdpSocket::bind(tcp.local_addr()?)?;
    Ok((tcp, udp))
}

async fn start(
    ip: IpAddr,
    expected_peer: IpAddr,
    extras: usize,
) -> Result<(SocketAddr, Vec<u16>, ListenerTask)> {
    let base = reserve(ip)?;
    let address = base.0.local_addr()?;
    let mut reservations = Vec::new();
    let mut extra_ports = Vec::new();
    for _ in 0..extras {
        let pair = reserve(ip)?;
        extra_ports.push(pair.0.local_addr()?.port());
        reservations.push(pair);
    }
    let options = ListenOptions {
        bind: address,
        expected_peer,
        extra_ports: extra_ports.clone(),
        wait: Duration::from_secs(10),
        keep: false,
    };
    drop(base);
    drop(reservations);
    let task = tokio::spawn(linktest::listen(options));
    timeout(Duration::from_secs(2), async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .context("diagnostic listener did not start")?;
    Ok((address, extra_ports, task))
}

fn options(peer: SocketAddr, bind: IpAddr, extra_ports: Vec<u16>) -> ProbeOptions {
    ProbeOptions {
        peer,
        bind,
        local_port: 0,
        extra_ports,
        seconds: Duration::from_millis(50),
        timeout: Duration::from_secs(2),
        quick: false,
        mtu: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv4_bidirectional_integrity_and_explicit_extra_port() -> Result<()> {
    let ip = "127.0.0.1".parse()?;
    let (peer, ports, listener) = start(ip, ip, 1).await?;
    let report = linktest::probe(options(peer, ip, ports)).await?;
    ensure!(
        report.passed(),
        "failed diagnostics: {}",
        serde_json::to_string_pretty(&report)?
    );
    ensure!(report.udp.sent == 16 && report.udp.received == 16);
    ensure!(report.reverse_udp.sent == 16 && report.reverse_udp.received == 16);
    ensure!(report.upload.bytes >= 32768 && report.download.bytes >= 32768);
    ensure!(report.upload.mbps > 0. && report.download.mbps > 0.);
    ensure!(report.ports.len() == 1);
    let json = serde_json::to_string(&report)?;
    ensure!(
        !json.contains("token") && !json.contains("session"),
        "report exposed transient authorization material"
    );
    timeout(Duration::from_secs(2), listener).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_datagram_size_sweep_measures_both_directions_and_the_verdict_is_good() -> Result<()> {
    let ip = "127.0.0.1".parse()?;
    let (peer, _, listener) = start(ip, ip, 0).await?;
    let mut probe = options(peer, ip, Vec::new());
    probe.mtu = true;
    probe.quick = true;
    let report = linktest::probe(probe).await?;
    let mtu = report.mtu.as_ref().context("no MTU report")?;
    ensure!(mtu.error.is_none(), "sweep failed: {:?}", mtu.error);
    // The loopback interface takes anything, so every size of the ladder passes both ways.
    let top = *linktest::MTU_SIZES.last().unwrap();
    ensure!(mtu.sizes.len() == linktest::MTU_SIZES.len());
    ensure!(mtu.forward_max_payload == Some(top), "{mtu:?}");
    ensure!(mtu.reverse_max_payload == Some(top), "{mtu:?}");
    ensure!(mtu.at_ladder_top && !mtu.irregular);
    ensure!(mtu.path_mtu == Some(top + 28));
    ensure!(
        mtu.dont_fragment,
        "this platform could not set the don't-fragment bit"
    );
    ensure!(
        mtu.sizes.iter().all(|s| s.forward == 3 && s.reverse == 3),
        "every probe should arrive on loopback: {mtu:?}"
    );
    ensure!(report.passed());
    ensure!(report.verdict.score == 100, "{:?}", report.verdict);
    let text = eztunnel::linkverdict::render(&report);
    ensure!(text.contains("GOOD (100/100)"), "{text}");
    timeout(Duration::from_secs(2), listener).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_source_ip_is_used_for_tcp_and_udp() -> Result<()> {
    let server = "127.0.0.1".parse()?;
    let client = "127.0.0.2".parse()?;
    let (peer, _, listener) = start(server, client, 0).await?;
    let report = linktest::probe(options(peer, client, Vec::new())).await?;
    ensure!(
        report.passed(),
        "selected source did not work: {}",
        serde_json::to_string_pretty(&report)?
    );
    ensure!(report.reverse_listener.ip() == client);
    timeout(Duration::from_secs(2), listener).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_bidirectional_integrity() -> Result<()> {
    let ip = "::1".parse()?;
    let (peer, _, listener) = start(ip, ip, 0).await?;
    let mut probe = options(peer, ip, Vec::new());
    probe.quick = true;
    let report = linktest::probe(probe).await?;
    ensure!(
        report.passed(),
        "IPv6 diagnostics failed: {}",
        serde_json::to_string_pretty(&report)?
    );
    ensure!(report.reverse_listener.is_ipv6() && report.udp.sent == 4);
    timeout(Duration::from_secs(2), listener).await???;
    Ok(())
}

#[tokio::test]
async fn udp_requires_a_registered_token_and_oversized_frames_are_ignored() -> Result<()> {
    let ip = "127.0.0.1".parse()?;
    let (peer, _, listener) = start(ip, ip, 0).await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut request = vec![0; 41 + 16];
    request[..5].copy_from_slice(b"EZLT\x01");
    socket.send_to(&request, peer).await?;
    let mut response = [0; 9000];
    ensure!(
        timeout(Duration::from_millis(50), socket.recv_from(&mut response))
            .await
            .is_err(),
        "unknown token was reflected"
    );
    let mut session = TcpStream::connect(peer).await?;
    session.write_all(b"EZLT\x01\x00").await?;
    session.write_all(&[0; 32]).await?;
    let mut token = [0; 32];
    session.read_exact(&mut token).await?;
    request[5..37].copy_from_slice(&token);
    request[41..].fill(7);
    let mut oversized = vec![0; 8193];
    oversized[..request.len()].copy_from_slice(&request);
    socket.send_to(&oversized, peer).await?;
    ensure!(
        timeout(Duration::from_millis(50), socket.recv_from(&mut response))
            .await
            .is_err(),
        "oversized datagram was reflected"
    );
    socket.send_to(&request, peer).await?;
    let (size, from) = timeout(Duration::from_secs(1), socket.recv_from(&mut response)).await??;
    ensure!(
        from == peer && response[..size] == request,
        "authorized echo changed bytes"
    );
    let mut malformed = TcpStream::connect(peer).await?;
    malformed.write_all(b"EZLT\x01\x02").await?;
    malformed.write_all(&token).await?;
    malformed.write_u32(7).await?;
    malformed.write_all(&[0; 7]).await?;
    ensure!(
        timeout(Duration::from_secs(1), malformed.read_u64())
            .await?
            .is_err(),
        "malformed transfer block was accepted"
    );
    let mut finish = TcpStream::connect(peer).await?;
    finish.write_all(b"EZLT\x01\x06").await?;
    finish.write_all(&token).await?;
    ensure!(finish.read_u8().await? == 1);
    timeout(Duration::from_secs(2), listener).await???;
    Ok(())
}

#[tokio::test]
async fn unreachable_extra_port_is_reported_as_failure() -> Result<()> {
    let ip = "127.0.0.1".parse()?;
    let unused = reserve(ip)?;
    let closed = unused.0.local_addr()?.port();
    let (peer, _, listener) = start(ip, ip, 0).await?;
    drop(unused);
    let mut probe = options(peer, ip, vec![closed]);
    probe.timeout = Duration::from_millis(100);
    probe.quick = true;
    let report = linktest::probe(probe).await?;
    ensure!(!report.passed() && report.tcp.ok && report.reverse_tcp.ok);
    ensure!(
        !report.ports[0].tcp.ok
            && report.ports[0].udp.received == 0
            && report.ports[0].udp.loss_percent == 100.
    );
    timeout(Duration::from_secs(2), listener).await???;
    Ok(())
}

#[test]
fn rejects_implicit_peers_duplicate_ports_and_unbounded_work() -> Result<()> {
    let mut probe = options("127.0.0.1:12345".parse()?, "127.0.0.1".parse()?, Vec::new());
    probe.peer = "0.0.0.0:12345".parse()?;
    ensure!(probe.validate().is_err());
    probe.peer = "127.0.0.1:12345".parse()?;
    probe.extra_ports = vec![12346, 12346];
    ensure!(probe.validate().is_err());
    probe.extra_ports.clear();
    probe.seconds = Duration::from_secs(31);
    ensure!(probe.validate().is_err());
    let listener = ListenOptions {
        bind: "127.0.0.1:12345".parse()?,
        expected_peer: "224.0.0.1".parse()?,
        extra_ports: Vec::new(),
        wait: Duration::from_secs(1),
        keep: false,
    };
    ensure!(listener.validate().is_err());
    Ok(())
}
