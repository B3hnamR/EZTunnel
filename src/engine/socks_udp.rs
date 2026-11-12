//! SOCKS5 UDP ASSOCIATE (RFC 1928, section 7).
//!
//! A SOCKS5 client asks for a UDP relay on the ordinary TCP connection and keeps that connection
//! open for as long as it wants the relay. The relay is a UDP socket on the interface the client
//! connected to; the client sends datagrams to it, each with a small header naming the real
//! destination, and receives the answers with the same header naming where they came from.
//!
//! Every destination gets its own tunnel stream (`StreamKind::Udp`), exactly like a UDP map's
//! conversations, so the far side's `allowed_targets`, the idle timeout and the stream limits all
//! apply as for any other forwarded UDP. Fragmented SOCKS5 datagrams are not supported.
use super::{
    DATA_SIZE, Frame, Pool, StreamGuard, StreamKind, Tuning, await_open, close_stream,
    log_forward_result, session_scope, udp_idle,
};
use crate::limits::PendingLimiter;
use crate::stats::Stats;
use anyhow::{Result, bail, ensure};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinSet,
    time::{self, Instant},
};

/// A datagram from the SOCKS5 client, taken apart.
pub(super) struct ClientDatagram<'a> {
    /// `host:port` the client wants to reach.
    pub target: String,
    /// The header as the client wrote it. Answers from `target` get exactly this header back.
    pub header: &'a [u8],
    pub data: &'a [u8],
}

/// Reads the SOCKS5 UDP header (`RSV(2) FRAG ATYP ADDR PORT`) and splits off the payload.
pub(super) fn parse_datagram(packet: &[u8]) -> Result<ClientDatagram<'_>> {
    ensure!(packet.len() >= 4, "short SOCKS5 UDP datagram");
    ensure!(
        packet[0] == 0 && packet[1] == 0,
        "SOCKS5 UDP reserved bytes must be zero"
    );
    ensure!(
        packet[2] == 0,
        "fragmented SOCKS5 UDP datagrams are not supported"
    );
    let (host, end) = match packet[3] {
        1 => {
            ensure!(packet.len() >= 10, "short SOCKS5 UDP datagram");
            let octets: [u8; 4] = packet[4..8].try_into()?;
            (Ipv4Addr::from(octets).to_string(), 8)
        }
        4 => {
            ensure!(packet.len() >= 22, "short SOCKS5 UDP datagram");
            let octets: [u8; 16] = packet[4..20].try_into()?;
            (format!("[{}]", Ipv6Addr::from(octets)), 20)
        }
        3 => {
            ensure!(packet.len() >= 5, "short SOCKS5 UDP datagram");
            let size = usize::from(packet[4]);
            ensure!(size > 0, "empty SOCKS5 hostname");
            ensure!(packet.len() >= 5 + size + 2, "short SOCKS5 UDP datagram");
            let host = std::str::from_utf8(&packet[5..5 + size])?.to_string();
            ensure!(
                !host.contains([':', '/', '\\', '\0']),
                "invalid SOCKS5 hostname"
            );
            // The far end answers some .invalid names itself (the speed test); a proxy user must
            // not reach them, over UDP either.
            ensure!(
                !crate::config::reserved_host(&host),
                "SOCKS5 hostname is reserved"
            );
            (host, 5 + size)
        }
        _ => bail!("unsupported SOCKS5 address type"),
    };
    let port = u16::from_be_bytes([packet[end], packet[end + 1]]);
    ensure!(port != 0, "SOCKS5 port must be nonzero");
    Ok(ClientDatagram {
        target: format!("{host}:{port}"),
        header: &packet[..end + 2],
        data: &packet[end + 2..],
    })
}

/// The success reply of an association: the address the client must send its datagrams to.
fn bound_reply(address: SocketAddr) -> Vec<u8> {
    let mut reply = vec![5, 0, 0];
    match address {
        SocketAddr::V4(address) => {
            reply.push(1);
            reply.extend(address.ip().octets());
        }
        SocketAddr::V6(address) => {
            reply.push(4);
            reply.extend(address.ip().octets());
        }
    }
    reply.extend(address.port().to_be_bytes());
    reply
}

/// Serves one association until the client closes its TCP connection.
///
/// Only the host that opened the association may use the relay, and only from the port its first
/// datagram came from.
pub(super) async fn associate(
    mut control: TcpStream,
    pool: Arc<Pool>,
    users: Arc<PendingLimiter>,
    limit: usize,
    tuning: Tuning,
    stats: Arc<Stats>,
    gaming:Option<Arc<crate::gaming::Hub>>,
) -> Result<()> {
    let local = control.local_addr()?;
    let client_host = control.peer_addr()?.ip();
    let relay = Arc::new(UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?);
    control.write_all(&bound_reply(relay.local_addr()?)).await?;
    tracing::debug!(relay = %relay.local_addr()?, client = %client_host, "SOCKS5 UDP association opened");
    let mut client: Option<SocketAddr> = None;
    let mut flows: HashMap<String, mpsc::Sender<super::QueuedDatagram>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0; 65536];
    let mut stray = [0; 64];
    let mut prune = time::interval(Duration::from_secs(5));
    prune.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            // The association lives exactly as long as the control connection.
            read = control.read(&mut stray) => {
                if matches!(read, Ok(0) | Err(_)) { return Ok(()); }
            }
            _ = prune.tick() => { flows.retain(|_, sender| !sender.is_closed()); }
            result = tasks.join_next(), if !tasks.is_empty() => { log_forward_result(result); }
            packet = relay.recv_from(&mut buffer) => {
                let (count, from) = packet?;
                if from.ip() != client_host { continue; }
                match client {
                    None => client = Some(from),
                    Some(known) if known != from => continue,
                    Some(_) => {}
                }
                let datagram = match parse_datagram(&buffer[..count]) {
                    Ok(datagram) if datagram.data.len() <= DATA_SIZE => datagram,
                    Ok(_) => continue,
                    Err(error) => { tracing::debug!(%error, "SOCKS5 UDP datagram dropped"); continue; }
                };
                if let Some(sender) = flows.get(&datagram.target) {
                    if !sender.is_closed() {
                        super::queue_datagram(sender, datagram.data, &stats);
                        continue;
                    }
                    flows.remove(&datagram.target);
                }
                if flows.len() >= limit {
                    flows.retain(|_, sender| !sender.is_closed());
                }
                if flows.len() >= limit { stats.refuse_stream(); continue; }
                // Each destination opens its own tunnel stream, exactly like a UDP map's
                // conversations, so it must take a slot from the same per-address stream limit
                // those use (the association's control connection only reserves its own slot).
                let Some(user_slot) = users.try_enter_when(Some(client_host), pool.crowded())
                else {
                    stats.refuse_stream();
                    continue;
                };
                if let Some(hub)=&gaming {
                    if hub.usable().await {
                        let(tx,mut packets)=mpsc::channel(tuning.stream_queue);
                        super::queue_datagram(&tx,datagram.data,&stats);flows.insert(datagram.target.clone(),tx);
                        let(hub,relay,target,header,stats)=(hub.clone(),relay.clone(),datagram.target.clone(),datagram.header.to_vec(),stats.clone());
                        tasks.spawn(async move {
                            let _user=user_slot;let(flow,mut answers)=hub.register().await?;
                            let result=async {
                                let mut activity=Instant::now();
                                loop {let deadline=activity+tuning.udp_idle;tokio::select!{
                                    packet=packets.recv()=>{
                                        let Some(super::QueuedDatagram{data,_held})=packet else{break;};
                                        if hub.send(flow,&target,&data).await.unwrap_or(false){stats.bytes_to_peer.fetch_add(data.len() as u64,std::sync::atomic::Ordering::Relaxed);}else{stats.udp_dropped.fetch_add(1,std::sync::atomic::Ordering::Relaxed);}
                                        activity=Instant::now();
                                    }
                                    answer=answers.recv()=>{
                                        let Some(answer)=answer else{break;};let mut bytes=header.clone();bytes.extend_from_slice(&answer);relay.send_to(&bytes,from).await?;activity=Instant::now();
                                        stats.bytes_from_peer.fetch_add(answer.len() as u64,std::sync::atomic::Ordering::Relaxed);
                                    }
                                    _=time::sleep_until(deadline)=>break,
                                }}
                                Ok::<(),anyhow::Error>(())
                            }.await;
                            hub.unregister(flow).await;result
                        });
                        continue;
                    }
                }
                let Some(session) = pool.pick() else { stats.refuse_stream(); continue; };
                let Ok((id, mut rx)) = session.register(None) else { stats.refuse_stream(); continue; };
                let guard = StreamGuard { session: session.clone(), id };
                let (tx, mut packets) = mpsc::channel(tuning.stream_queue);
                super::queue_datagram(&tx, datagram.data, &stats);
                let (target, header) = (datagram.target.clone(), datagram.header.to_vec());
                flows.insert(datagram.target.clone(), tx);
                let relay = relay.clone();
                tasks.spawn(async move {
                    let (_guard, _user_slot) = (guard, user_slot);
                    session_scope(&session, close_stream(&session, id, async {
                        session.send(Frame::Open { id, kind: StreamKind::Udp, target, proxy: None }).await?;
                        await_open(&mut rx, tuning.open).await?;
                        session.open_window(id).await?;
                        let activity = Mutex::new(Instant::now());
                        let upload = async {
                            while let Some(super::QueuedDatagram { data, _held }) = packets.recv().await {
                                let size=data.len();
                                session.send_data(id, data).await?;
                                session.stats.bytes_to_peer.fetch_add(size as u64,std::sync::atomic::Ordering::Relaxed);
                                *activity.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                            }
                            Ok::<(), anyhow::Error>(())
                        };
                        let download = async {
                            loop {
                                match rx.recv().await {
                                    Some(Frame::Data { data, .. }) => {
                                        // The answer carries the header the client used for this
                                        // destination, so it knows where it came from.
                                        let mut reply = header.clone();
                                        reply.extend_from_slice(&data);
                                        relay.send_to(&reply, from).await?;
                                        session.stats.bytes_from_peer.fetch_add(data.len()as u64,std::sync::atomic::Ordering::Relaxed);
                                        *activity.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                                        session.send(Frame::Credit { id, frames: 1 }).await?;
                                    }
                                    Some(Frame::Close { .. }) | Some(Frame::Eof { .. }) | None => return Ok::<(), anyhow::Error>(()),
                                    Some(Frame::Error { message, .. }) => bail!("remote UDP error: {message}"),
                                    _ => bail!("invalid UDP stream frame"),
                                }
                            }
                        };
                        tokio::select! {
                            result = upload => result,
                            result = download => result,
                            _ = udp_idle(&activity, tuning.udp_idle) => Ok(()),
                        }
                    })).await
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(atyp_and_address: &[u8], port: u16, data: &[u8]) -> Vec<u8> {
        let mut packet = vec![0, 0, 0];
        packet.extend_from_slice(atyp_and_address);
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(data);
        packet
    }

    #[test]
    fn an_ipv4_ipv6_or_name_destination_is_read_with_its_payload() {
        let packet = datagram(&[1, 192, 0, 2, 9], 5353, b"hello");
        let parsed = parse_datagram(&packet).unwrap();
        assert_eq!(parsed.target, "192.0.2.9:5353");
        assert_eq!(parsed.data, b"hello");
        assert_eq!(parsed.header, &packet[..10], "the header is kept verbatim");

        let mut v6 = vec![4];
        v6.extend(Ipv6Addr::LOCALHOST.octets());
        let packet = datagram(&v6, 53, b"");
        let parsed = parse_datagram(&packet).unwrap();
        assert_eq!(parsed.target, "[::1]:53");
        assert!(parsed.data.is_empty(), "empty datagrams are valid");

        let mut name = vec![3, 11];
        name.extend_from_slice(b"example.com");
        let packet = datagram(&name, 443, b"x");
        let parsed = parse_datagram(&packet).unwrap();
        assert_eq!(parsed.target, "example.com:443");
        assert_eq!(parsed.header.len(), 3 + 1 + 1 + 11 + 2);
    }

    #[test]
    fn fragments_reserved_names_and_malformed_headers_are_refused() {
        let good = datagram(&[1, 192, 0, 2, 9], 53, b"q");
        let mut fragmented = good.clone();
        fragmented[2] = 1;
        assert!(parse_datagram(&fragmented).is_err(), "FRAG != 0");
        let mut reserved = good.clone();
        reserved[0] = 1;
        assert!(parse_datagram(&reserved).is_err(), "RSV != 0");
        assert!(
            parse_datagram(&datagram(&[1, 192, 0, 2, 9], 0, b"q")).is_err(),
            "port 0"
        );
        assert!(parse_datagram(&good[..7]).is_err(), "truncated address");
        assert!(
            parse_datagram(&[0, 0, 0, 9, 1, 2, 3, 4, 0, 1]).is_err(),
            "unknown ATYP"
        );
        for name in [
            "down.1073741824.speedtest.eztunnel.invalid",
            "UP.10.SPEEDTEST.EZTUNNEL.INVALID",
            "anything.invalid",
        ] {
            let mut bytes = vec![3, name.len() as u8];
            bytes.extend_from_slice(name.as_bytes());
            assert!(
                parse_datagram(&datagram(&bytes, 9, b"x")).is_err(),
                "{name} must stay out of reach over UDP too"
            );
        }
        let mut with_colon = vec![3, 3];
        with_colon.extend_from_slice(b"a:b");
        assert!(parse_datagram(&datagram(&with_colon, 9, b"x")).is_err());
    }

    #[test]
    fn the_reply_names_the_relay_address() {
        let v4: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        assert_eq!(bound_reply(v4), vec![5, 0, 0, 1, 127, 0, 0, 1, 0x9c, 0x40]);
        let v6: SocketAddr = "[::1]:1".parse().unwrap();
        let reply = bound_reply(v6);
        assert_eq!(&reply[..4], &[5, 0, 0, 4]);
        assert_eq!(reply.len(), 4 + 16 + 2);
        assert_eq!(&reply[20..], &[0, 1]);
    }
}
