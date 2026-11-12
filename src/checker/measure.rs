//! Measurements through a test tunnel's port map, made on the Iran server against the test
//! service (`service.rs`) on the foreign server.
use super::service::{DOWNLOAD, ECHO, UPLOAD, fill, matches};
use super::{PingStats, Transfer, UdpStats};
use anyhow::{Context, Result, bail, ensure};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

const BLOCK: usize = 64 * 1024;
/// No byte moving for this long means the transfer is stuck.
pub const STALL: Duration = Duration::from_secs(5);
/// Longest wait for one ping's answer.
pub const PING_WAIT: Duration = Duration::from_secs(5);

/// Opens a stream through the tunnel and gets a short echo back: what a user's first request
/// costs, stream opening included.
pub async fn ping(map: SocketAddr) -> Result<Duration> {
    let started = Instant::now();
    timeout(PING_WAIT, async {
        let mut stream = TcpStream::connect(map).await?;
        stream.set_nodelay(true)?;
        let probe = *b"Eezt-ping";
        debug_assert_eq!(probe[0], ECHO);
        stream.write_all(&probe).await?;
        let mut answer = [0u8; 8];
        stream.read_exact(&mut answer).await?;
        ensure!(answer == probe[1..], "the echo came back changed");
        anyhow::Ok(())
    })
    .await
    .context("no answer")??;
    Ok(started.elapsed())
}

/// `count` pings, one after the other. `each` is told about every answer (for the live view).
pub async fn pings(map: SocketAddr, count: u32, mut each: impl FnMut(&PingStats)) -> PingStats {
    let mut times = Vec::new();
    let mut stats = PingStats::default();
    for _ in 0..count {
        stats.sent += 1;
        if let Ok(rtt) = ping(map).await {
            stats.answered += 1;
            times.push(tenths(rtt.as_secs_f64() * 1000.0));
            times.sort_by(f64::total_cmp);
            stats.median_ms = Some(times[times.len() / 2]);
            stats.worst_ms = times.last().copied();
        }
        each(&stats);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    stats
}

/// UDP packets per second sent by `udp_probe`, and their size.
pub const UDP_RATE: u32 = 100;
const UDP_SIZE: usize = 120;
/// How long after the last packet the answers are still waited for.
const UDP_TAIL: Duration = Duration::from_secs(2);
/// An answer after this long is late: as good as lost for a call or a game.
const UDP_LATE: Duration = Duration::from_secs(1);

/// Sends `count` small UDP packets through the tunnel's map, `UDP_RATE` per second, to the test
/// service's echo, and reports what came back and how fast. `each` is told every 25 packets.
pub async fn udp_probe(map: SocketAddr, count: u32, mut each: impl FnMut(&UdpStats)) -> UdpStats {
    udp_probe_started(map,count,&mut each,None,None).await
}
pub(super) async fn udp_probe_started(map:SocketAddr,count:u32,mut each:impl FnMut(&UdpStats),ready:Option<tokio::sync::oneshot::Sender<()>>,load:Option<tokio::sync::oneshot::Receiver<()>>)->UdpStats{
    let mut stats = UdpStats::default();
    let Ok(socket) = UdpSocket::bind("127.0.0.1:0").await else {
        return stats;
    };
    if socket.connect(map).await.is_err() {
        return stats;
    }
    let mut sent_at: Vec<Instant> = Vec::with_capacity(count as usize);
    let mut seen = vec![false; count as usize];
    let mut times: Vec<f64> = Vec::new();
    let mut buffer = [0u8; 2048];
    let mut packet = [0u8; UDP_SIZE];
    let mut tick = tokio::time::interval(Duration::from_secs(1) / UDP_RATE);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    // The first datagram of a conversation makes the far side open a stream, which costs a round
    // trip more. That is not what loss and delay are about, so one packet goes first and is waited
    // for (not counted); the timed packets then see an open conversation.
    for _ in 0..3 {
        packet[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        let _ = socket.send(&packet).await;
        if timeout(Duration::from_secs(1), socket.recv(&mut buffer))
            .await
            .is_ok_and(|received| received.is_ok())
        {
            break;
        }
    }
    tick.reset();
    if let Some(ready)=ready{let _=ready.send(());}
    if let Some(load)=load{if !matches!(timeout(Duration::from_secs(20),load).await,Ok(Ok(()))){return stats;}tick.reset();}
    let mut deadline = None;
    loop {
        tokio::select! {
            _ = tick.tick(), if stats.sent < count => {
                packet[..4].copy_from_slice(&stats.sent.to_be_bytes());
                sent_at.push(Instant::now());
                // A refused or failed send is a lost packet.
                let _ = socket.send(&packet).await;
                stats.sent += 1;
                if stats.sent % 25 == 0 {
                    each(&stats);
                }
                if stats.sent == count {
                    deadline = Some(tokio::time::Instant::now() + UDP_TAIL);
                }
            }
            received = socket.recv(&mut buffer) => {
                // An ICMP "port unreachable" shows up as an error here; it is one lost packet.
                let Ok(size) = received else { continue };
                if size < 4 {
                    continue;
                }
                let sequence = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;
                if sequence >= sent_at.len() || seen[sequence] {
                    continue;
                }
                seen[sequence] = true;
                let rtt = sent_at[sequence].elapsed();
                if rtt > UDP_LATE {
                    stats.late += 1;
                } else {
                    stats.answered += 1;
                    times.push(rtt.as_secs_f64() * 1000.0);
                }
            }
            _ = async { tokio::time::sleep_until(deadline.unwrap()).await }, if deadline.is_some() => break,
        }
        if stats.answered + stats.late >= count && stats.sent == count {
            break;
        }
    }
    times.sort_by(f64::total_cmp);
    if !times.is_empty() {
        stats.median_ms = Some(tenths(times[times.len() / 2]));
        stats.p95_ms = Some(tenths(times[(times.len() * 95 / 100).min(times.len() - 1)]));
    }
    each(&stats);
    stats
}

/// One decimal is all a report needs, and it survives being sent as JSON unchanged.
pub fn tenths(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    tenths(bytes as f64 * 8.0 / elapsed.as_secs_f64().max(0.001) / 1_000_000.0)
}

/// Downloads the test pattern for `seconds` and checks every byte.
pub async fn download(map: SocketAddr, seconds: Duration) -> Transfer {
    download_with_signal(map,seconds,None).await
}
pub(super) async fn download_started(map:SocketAddr,seconds:Duration,ready:tokio::sync::oneshot::Sender<()>)->Transfer{
    download_with_signal(map,seconds,Some(ready)).await
}
async fn download_with_signal(map:SocketAddr,seconds:Duration,mut ready:Option<tokio::sync::oneshot::Sender<()>>)->Transfer{
    let mut started = Instant::now();
    let mut bytes = 0u64;
    let result: Result<()> = async {
        let mut stream = timeout(PING_WAIT, TcpStream::connect(map))
            .await
            .context("could not open a stream")??;
        stream.write_u8(DOWNLOAD).await?;
        let mut buffer = vec![0u8; BLOCK];
        while started.elapsed() < seconds {
            let count = match timeout(STALL, stream.read(&mut buffer)).await {
                Err(_) => bail!("stalled after {}", size(bytes)),
                Ok(Err(error)) => bail!("{} after {}", short(&error), size(bytes)),
                Ok(Ok(0)) => bail!("closed after {}", size(bytes)),
                Ok(Ok(count)) => count,
            };
            ensure!(matches(&buffer[..count], bytes), "data arrived changed");
            bytes += count as u64;
            if let Some(ready)=ready.take(){started=Instant::now();let _=ready.send(());}
        }
        Ok(())
    }
    .await;
    Transfer {
        mbps: mbps(bytes, started.elapsed()),
        bytes,
        error: result.err().map(|e| format!("{e:#}")),
    }
}

/// Several downloads at once; the speed is their sum.
pub async fn parallel(map: SocketAddr, seconds: Duration, streams: usize) -> Transfer {
    let runs = futures_util::future::join_all((0..streams).map(|_| download(map, seconds))).await;
    let error = runs.iter().find_map(|r| r.error.clone());
    Transfer {
        mbps: tenths(runs.iter().map(|r| r.mbps).sum()),
        bytes: runs.iter().map(|r| r.bytes).sum(),
        error,
    }
}

/// Uploads the test pattern for `seconds`. The far side reports what arrived several times a
/// second; the speed is what had arrived when the time was up, so data still queued on the way
/// does not count.
pub async fn upload(map: SocketAddr, seconds: Duration) -> Transfer {
    let started = Instant::now();
    let mut arrived = 0u64;
    let result: Result<()> = async {
        let stream = timeout(PING_WAIT, TcpStream::connect(map))
            .await
            .context("could not open a stream")??;
        let (mut reader, mut writer) = stream.into_split();
        writer.write_u8(UPLOAD).await?;
        let sender = tokio::spawn(async move {
            let mut buffer = vec![0u8; BLOCK];
            let mut sent = 0u64;
            loop {
                fill(&mut buffer, sent);
                if writer.write_all(&buffer).await.is_err() {
                    return;
                }
                sent += BLOCK as u64;
            }
        });
        let _stop_sending = AbortOnDrop(sender);
        let mut answer = [0u8; 9];
        let mut last_progress = Instant::now();
        while started.elapsed() < seconds {
            let left = seconds.saturating_sub(started.elapsed());
            match timeout(left.min(STALL), reader.read_exact(&mut answer)).await {
                Err(_) if started.elapsed() >= seconds => break,
                Err(_) => {}
                Ok(Err(error)) => bail!("{} after {}", short(&error), size(arrived)),
                Ok(Ok(_)) => {
                    ensure!(answer[8] == 1, "data arrived changed");
                    let now = u64::from_be_bytes(answer[..8].try_into()?);
                    if now > arrived {
                        arrived = now;
                        last_progress = Instant::now();
                    }
                }
            }
            if last_progress.elapsed() >= STALL {
                bail!("stalled after {}", size(arrived));
            }
        }
        ensure!(arrived > 0, "nothing arrived");
        Ok(())
    }
    .await;
    Transfer {
        mbps: mbps(arrived, started.elapsed()),
        bytes: arrived,
        error: result.err().map(|e| format!("{e:#}")),
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn short(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::ConnectionReset => "reset".into(),
        std::io::ErrorKind::BrokenPipe => "closed".into(),
        _ => error.to_string(),
    }
}

fn size(bytes: u64) -> String {
    if bytes >= 1 << 20 {
        format!("{:.1} MiB", bytes as f64 / f64::from(1 << 20))
    } else {
        format!("{:.0} KiB", bytes as f64 / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checker::service::Service;

    #[tokio::test]
    async fn measurements_against_the_service_directly() -> Result<()> {
        let service = Service::start().await?;
        assert!(ping(service.address).await? < PING_WAIT);
        let stats = pings(service.address, 3, |_| {}).await;
        assert_eq!((stats.sent, stats.answered), (3, 3));
        let down = download(service.address, Duration::from_secs(1)).await;
        assert!(down.ok(), "{down:?}");
        assert!(down.mbps > 1.0);
        let up = upload(service.address, Duration::from_secs(1)).await;
        assert!(up.ok(), "{up:?}");
        let many = parallel(service.address, Duration::from_secs(1), 4).await;
        assert!(many.ok(), "{many:?}");
        Ok(())
    }

    #[tokio::test]
    async fn udp_packets_are_counted_timed_and_a_silent_port_loses_them_all() -> Result<()> {
        let service = Service::start().await?;
        let mut updates = 0;
        let stats = udp_probe(service.address, 100, |_| updates += 1).await;
        assert_eq!(
            (stats.sent, stats.answered, stats.late),
            (100, 100, 0),
            "{stats:?}"
        );
        assert_eq!(stats.loss(), 0.0);
        let (median, p95) = (stats.median_ms.unwrap(), stats.p95_ms.unwrap());
        assert!(median <= p95 && p95 < 1000.0, "{stats:?}");
        assert!(updates >= 4, "the live view is told as it goes: {updates}");
        // A port nobody answers on: nothing comes back, and it does not wait for ever.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0")?.local_addr()?;
        let started = Instant::now();
        let lost = udp_probe(silent, 50, |_| {}).await;
        assert_eq!((lost.sent, lost.answered), (50, 0), "{lost:?}");
        assert_eq!(lost.loss(), 100.0);
        assert!(lost.median_ms.is_none() && lost.p95_ms.is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
        Ok(())
    }

    #[tokio::test]
    async fn a_dead_port_fails_quickly() -> Result<()> {
        let free = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        assert!(ping(free).await.is_err());
        let down = download(free, Duration::from_millis(300)).await;
        assert!(!down.ok());
        Ok(())
    }
    #[tokio::test]
    async fn loaded_probe_does_not_send_measured_packets_before_the_first_load_byte()->Result<()> {
        let server=tokio::net::UdpSocket::bind("127.0.0.1:0").await?;let address=server.local_addr()?;
        let(first_tx,first_rx)=tokio::sync::oneshot::channel();
        let echo=tokio::spawn(async move{
            let mut first=Some(first_tx);let mut bytes=[0;2048];
            loop{let(size,peer)=server.recv_from(&mut bytes).await?;
                if bytes[..4]!=u32::MAX.to_be_bytes(){if let Some(first)=first.take(){let _=first.send(Instant::now());}}
                server.send_to(&bytes[..size],peer).await?;
            }
            #[allow(unreachable_code)] Ok::<(),std::io::Error>(())
        });
        let(warm_tx,warm_rx)=tokio::sync::oneshot::channel();let(load_tx,load_rx)=tokio::sync::oneshot::channel();
        let probe=tokio::spawn(udp_probe_started(address,10,|_|{},Some(warm_tx),Some(load_rx)));
        warm_rx.await?;let mut first_rx=Box::pin(first_rx);
        assert!(timeout(Duration::from_millis(100),&mut first_rx).await.is_err(),"probe measured before load was active");
        let load_started=Instant::now();load_tx.send(()).unwrap();
        assert!(timeout(Duration::from_secs(1),&mut first_rx).await??>=load_started);
        let stats=probe.await?;assert_eq!((stats.sent,stats.answered),(10,10));echo.abort();Ok(())
    }
}
