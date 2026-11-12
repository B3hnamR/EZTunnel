//! The test service behind every test tunnel. It runs on the foreign server, on 127.0.0.1, and is
//! the target of the test tunnel's port map; the Iran server reaches it through the tunnel.
//!
//! The first byte of a connection chooses: `E` echoes everything back, `D` sends the test pattern
//! until the other side closes, `U` reads the test pattern and reports what arrived every
//! `REPORT_EVERY` (and when the sender closes): the byte count (8 bytes) and 1 when every byte was
//! right so far. Speeds are measured where the data arrives, so data still queued in buffers on
//! the way does not count.
use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};

pub const ECHO: u8 = b'E';
pub const DOWNLOAD: u8 = b'D';
pub const UPLOAD: u8 = b'U';

const BLOCK: usize = 64 * 1024;
pub const REPORT_EVERY: std::time::Duration = std::time::Duration::from_millis(100);
/// A prime period, so the pattern does not line up with block or frame sizes.
const PERIOD: usize = 251;

/// The pattern byte at stream offset `offset`.
pub fn pattern_byte(offset: u64) -> u8 {
    (offset % PERIOD as u64) as u8
}

/// Fills `buffer` with the pattern starting at stream offset `offset`.
pub fn fill(buffer: &mut [u8], offset: u64) {
    let start = (offset % PERIOD as u64) as usize;
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = ((start + index) % PERIOD) as u8;
    }
}

/// Whether `data` is the pattern starting at stream offset `offset`.
pub fn matches(data: &[u8], offset: u64) -> bool {
    let start = (offset % PERIOD as u64) as usize;
    data.iter()
        .enumerate()
        .all(|(index, byte)| *byte == ((start + index) % PERIOD) as u8)
}

/// The running service; it stops when dropped. Besides the TCP service there is a UDP echo on the
/// same port number, for the UDP measurement.
pub struct Service {
    pub address: SocketAddr,
    task: JoinHandle<()>,
    udp_task: JoinHandle<()>,
}

impl Drop for Service {
    fn drop(&mut self) {
        self.task.abort();
        self.udp_task.abort();
    }
}

impl Service {
    pub async fn start() -> Result<Self> {
        // The TCP and the UDP port number must be the same (the tunnel's map has one target).
        let mut found = None;
        for _ in 0..50 {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();
            if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)).await {
                found = Some((listener, udp));
                break;
            }
        }
        let (listener, udp) = found.context("no port is free for both TCP and UDP")?;
        let address = listener.local_addr()?;
        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048];
            while let Ok((count, from)) = udp.recv_from(&mut buffer).await {
                let _ = udp.send_to(&buffer[..count], from).await;
            }
        });
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        connections.spawn(async move { let _ = serve(stream).await; });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(Self {
            address,
            task,
            udp_task,
        })
    }
}

async fn serve(mut stream: TcpStream) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let command = stream.read_u8().await?;
    let mut buffer = vec![0u8; BLOCK];
    match command {
        ECHO => loop {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Ok(());
            }
            stream.write_all(&buffer[..count]).await?;
        },
        DOWNLOAD => {
            let mut offset = 0u64;
            loop {
                fill(&mut buffer, offset);
                stream.write_all(&buffer).await?;
                offset += BLOCK as u64;
            }
        }
        UPLOAD => {
            let (mut reader, mut writer) = stream.into_split();
            let mut offset = 0u64;
            let mut intact = true;
            let mut tick = tokio::time::interval(REPORT_EVERY);
            loop {
                tokio::select! {
                    read = reader.read(&mut buffer) => {
                        let count = read?;
                        if count == 0 {
                            break;
                        }
                        intact &= matches(&buffer[..count], offset);
                        offset += count as u64;
                    }
                    _ = tick.tick() => {
                        writer.write_all(&report(offset, intact)).await?;
                    }
                }
            }
            writer.write_all(&report(offset, intact)).await?;
            writer.shutdown().await?;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn report(bytes: u64, intact: bool) -> [u8; 9] {
    let mut out = [0u8; 9];
    out[..8].copy_from_slice(&bytes.to_be_bytes());
    out[8] = u8::from(intact);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_service_echoes_udp_on_its_tcp_port() -> Result<()> {
        let service = Service::start().await?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.send_to(b"hello", service.address).await?;
        let mut buffer = [0u8; 16];
        let (count, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buffer),
        )
        .await??;
        assert_eq!(&buffer[..count], b"hello");
        Ok(())
    }

    #[test]
    fn the_pattern_continues_across_blocks() {
        let mut first = vec![0u8; 300];
        let mut second = vec![0u8; 300];
        fill(&mut first, 0);
        fill(&mut second, 300);
        let whole: Vec<u8> = first.iter().chain(second.iter()).copied().collect();
        assert!(matches(&whole, 0));
        assert!(matches(&whole[7..], 7));
        assert!(!matches(&whole[7..], 8));
        assert_eq!(pattern_byte(252), 1);
    }
}
