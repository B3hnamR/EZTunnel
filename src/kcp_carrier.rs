//! Reliable KCP byte streams over UDP. Authentication is provided by the same
//! Noise handshake as every other carrier, before streams enter the engine.
use crate::config::{KcpOptions, Listener, Transport};
use anyhow::{Context, Result};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_kcp::{KcpConfig, KcpListener, KcpNoDelayConfig, KcpStream};

pub fn configuration(options: &KcpOptions) -> KcpConfig {
    KcpConfig {
        mtu: options.mtu,
        stream: true,
        wnd_size: (options.send_window, options.recv_window),
        session_expire: Duration::from_secs(options.session_expire_sec),
        max_sessions: options.max_sessions,
        max_sessions_per_ip: match options.max_sessions_per_ip {
            0 => usize::MAX,
            limit => limit,
        },
        flush_write: true,
        resend_burst: options.resend_burst,
        nodelay: KcpNoDelayConfig {
            nodelay: options.nodelay,
            interval: options.interval_ms as i32,
            resend: options.resend as i32,
            nc: !options.congestion_control,
        },
        ..KcpConfig::default()
    }
}

pub async fn connect(
    addr: &str,
    options: &KcpOptions,
    local_address: Option<&str>,
) -> Result<KcpStream> {
    // KCP creates a UDP session without a network handshake; the enclosing
    // Noise handshake supplies authentication and the connection deadline.
    let address = tokio::net::lookup_host(addr)
        .await
        .context("resolve KCP peer")?
        .next()
        .context("KCP peer has no address")?;
    let socket = crate::carrier::udp_for_peer(address, local_address)
        .await
        .context("bind KCP UDP socket")?;
    crate::fec_carrier::set_udp_buffers(&socket, options.socket_buf_bytes)
        .context("set KCP socket buffers")?;
    KcpStream::connect_with_socket(&configuration(options), socket, address)
        .await
        .context("open KCP session")
}

pub enum Incoming {
    Tcp(TcpStream),
    Kcp(KcpStream, SocketAddr),
    Xhttp(crate::carrier::BoxIo),
    Fec(crate::carrier::BoxIo),
    Parallax(crate::carrier::BoxIo, IpAddr),
}

impl Incoming {
    /// Source address of the remote peer, when the carrier can report one.
    pub fn peer_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Tcp(stream) => stream.peer_addr().ok().map(|a| a.ip()),
            Self::Kcp(_, peer) => Some(peer.ip()),
            Self::Xhttp(_) | Self::Fec(_) => None,
            Self::Parallax(_, ip) => Some(*ip),
        }
    }
}

pub enum Acceptor {
    Tcp(TcpListener, Option<String>),
    Kcp(KcpListener),
    Xhttp(crate::xhttp_carrier::Acceptor),
    Fec(Box<crate::fec_carrier::FecListener>),
    Parallax(crate::parallax_carrier::Acceptor),
}

impl Acceptor {
    pub async fn bind(listener: &Listener) -> Result<Self> {
        if listener.transport == Transport::Parallax {
            return Ok(Self::Parallax(
                crate::parallax_carrier::Acceptor::bind(listener).await?,
            ));
        }
        if matches!(
            listener.transport,
            Transport::FecUdp | Transport::FecRawGaming | Transport::FecRaw | Transport::Mirage
        ) {
            Ok(Self::Fec(Box::new(
                crate::fec_carrier::FecListener::bind(listener).await?,
            )))
        } else if matches!(listener.transport, Transport::Xhttp | Transport::Xhttps) {
            Ok(Self::Xhttp(
                crate::xhttp_carrier::Acceptor::bind(listener).await?,
            ))
        } else if listener.transport == Transport::Kcp {
            let socket = tokio::net::UdpSocket::bind(&listener.addr)
                .await
                .context("bind KCP UDP listener")?;
            crate::fec_carrier::set_udp_buffers(&socket, listener.kcp.socket_buf_bytes)
                .context("set KCP socket buffers")?;
            Ok(Self::Kcp(
                KcpListener::from_socket(configuration(&listener.kcp), socket)
                    .await
                    .context("start KCP listener")?,
            ))
        } else {
            Ok(Self::Tcp(
                TcpListener::bind(&listener.addr)
                    .await
                    .context("bind TCP listener")?,
                listener.tcp_congestion.clone(),
            ))
        }
    }

    pub async fn accept(&mut self) -> Result<Incoming> {
        match self {
            Self::Tcp(listener, tcp_congestion) => {
                let stream = listener.accept().await?.0;
                crate::carrier::tune_tcp(&stream, tcp_congestion.as_deref());
                Ok(Incoming::Tcp(stream))
            }
            Self::Kcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok(Incoming::Kcp(stream, peer))
            }
            Self::Xhttp(listener) => Ok(Incoming::Xhttp(listener.accept().await?)),
            Self::Fec(listener) => Ok(Incoming::Fec(listener.accept().await?)),
            Self::Parallax(listener) => {
                let (io, ip) = listener.accept().await?;
                Ok(Incoming::Parallax(io, ip))
            }
        }
    }
}
