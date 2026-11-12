//! The control link: a small encrypted channel between the two servers that coordinates the cases
//! and carries the live view. It uses a dedicated Noise prologue (keys from the check key)
//! over plain TCP on the control port.
//!
//! One direction may be filtered, so both servers listen on the control port and both dial the
//! other: the foreign server at once, the Iran server after a few seconds. Every connection that
//! authenticates exchanges a hello; then each side picks one (the one the foreign server dialed
//! when both made it) and the two confirm their choice on it. A mismatch starts over.
use super::{CaseSpec, Report, Side, View};
use crate::config::Mode;
use crate::transport::{self, SecureReader, SecureWriter};
use crate::tunnel_key::TunnelKey;
use crate::wire::{DATA_SIZE, Frame};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{net::TcpListener, sync::mpsc, task::JoinSet, time};

/// A link that sends nothing for this long is gone (each side sends a ping every 5 s).
pub const SILENCE: Duration = Duration::from_secs(20);
const PING_EVERY: Duration = Duration::from_secs(5);
const HANDSHAKE: Duration = Duration::from_secs(8);

/// What a key pressed on either server asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Command {
    Pause,
    Resume,
    Skip,
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Message {
    Hello {
        side: Side,
        dialed_by: Side,
        version: String,
    },
    Chosen,
    Ping,
    /// Foreign → Iran after pairing: where the test service listens.
    Ready {
        service_port: u16,
    },
    /// Iran → foreign: start your half of a case. `port` is set when the Iran server listens.
    Start {
        spec: CaseSpec,
        port: Option<u16>,
        map_port: u16,
    },
    /// Foreign → Iran: the half is running (`port` when the foreign server listens) or failed.
    Started {
        id: u32,
        port: Option<u16>,
        error: Option<String>,
        /// When the foreign server dials: how long its handshake took, if it is done already.
        #[serde(default)]
        handshake_ms: Option<u64>,
    },
    StopCase {
        id: u32,
    },
    CaseStopped {
        id: u32,
        /// When the foreign server dialed: how long its handshake took.
        #[serde(default)]
        handshake_ms: Option<u64>,
    },
    /// Iran → foreign: start the link test listener for the baseline.
    BaselineListen,
    BaselineReady {
        port: Option<u16>,
        error: Option<String>,
    },
    /// Iran → foreign: the live view.
    View(Box<View>),
    /// Foreign → Iran: a key pressed on the foreign server.
    Command(Command),
    /// Iran → foreign: the final report.
    Done(Box<Report>),
    /// Leaving on purpose (stop, Ctrl+C); the other side cleans up at once.
    Bye,
}

/// An established control link.
pub struct Link {
    pub sender: mpsc::Sender<Message>,
    receiver: mpsc::Receiver<Message>,
    _tasks: JoinSet<()>,
    pub dialed_by: Side,
}

impl Link {
    /// The next message; an error when the link is gone.
    pub async fn recv(&mut self) -> Result<Message> {
        self.receiver
            .recv()
            .await
            .context("the connection to the other server was lost")
    }

    pub async fn send(&self, message: Message) -> Result<()> {
        self.sender
            .send(message)
            .await
            .map_err(|_| anyhow::anyhow!("the connection to the other server was lost"))
    }

    fn start(reader: SecureReader, writer: SecureWriter, dialed_by: Side) -> Self {
        let (sender, mut outgoing) = mpsc::channel::<Message>(64);
        let (deliver, receiver) = mpsc::channel::<Message>(64);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let _ = read_loop(reader, deliver).await;
        });
        tasks.spawn(async move {
            let mut writer = writer;
            let mut ping = time::interval(PING_EVERY);
            loop {
                let message = tokio::select! {
                    message = outgoing.recv() => match message { Some(m) => m, None => return },
                    _ = ping.tick() => Message::Ping,
                };
                if write_message(&mut writer, &message).await.is_err() {
                    return;
                }
            }
        });
        Self {
            sender,
            receiver,
            _tasks: tasks,
            dialed_by,
        }
    }
}

async fn write_message(writer: &mut SecureWriter, message: &Message) -> Result<()> {
    let json = serde_json::to_vec(message)?;
    for chunk in json.chunks(DATA_SIZE) {
        time::timeout(
            SILENCE,
            writer.send(&Frame::Data {
                id: 1,
                data: chunk.to_vec(),
            }),
        )
        .await
        .context("control write timed out")??;
    }
    time::timeout(SILENCE, writer.send(&Frame::Eof { id: 1 }))
        .await
        .context("control write timed out")??;
    Ok(())
}

/// Reads one message, or fails after `SILENCE` without a frame.
async fn read_message(reader: &mut SecureReader) -> Result<Message> {
    let mut json = Vec::new();
    loop {
        let frame = time::timeout(SILENCE, reader.recv())
            .await
            .context("the other server went silent")??;
        match frame {
            Frame::Data { id: 1, data } => {
                ensure!(
                    json.len() + data.len() <= 16 << 20,
                    "control message too large"
                );
                json.extend_from_slice(&data);
            }
            Frame::Eof { id: 1 } => {
                return serde_json::from_slice(&json).context("unreadable control message");
            }
            _ => bail!("unexpected control frame"),
        }
    }
}

async fn read_loop(mut reader: SecureReader, deliver: mpsc::Sender<Message>) -> Result<()> {
    loop {
        let message = read_message(&mut reader).await?;
        if matches!(message, Message::Ping) {
            continue;
        }
        if deliver.send(message).await.is_err() {
            return Ok(());
        }
    }
}

/// The identities of the control link: the side that accepts uses the server one.
struct Keys {
    server_private: zeroize::Zeroizing<[u8; 32]>,
    server_public: [u8; 32],
    client_private: zeroize::Zeroizing<[u8; 32]>,
    client_public: [u8; 32],
}

fn keys(code_key: &str) -> Result<Keys> {
    let key = TunnelKey::parse(code_key)?;
    Ok(Keys {
        server_private: key.private_key(Mode::Server),
        server_public: key.public_key(Mode::Server)?,
        client_private: key.private_key(Mode::Client),
        client_public: key.public_key(Mode::Client)?,
    })
}

/// A link that passed the hello: its halves, who dialed it, and the other side's version.
type Accepted = (SecureReader, SecureWriter, Side, String);

/// Exchanges hellos on a fresh connection; returns the halves when the other side is the server
/// we expect.
async fn hello(
    connection: transport::SecureConnection,
    me: Side,
    dialed_by: Side,
    mine: &str,
) -> Result<Accepted> {
    let (mut reader, mut writer) = connection.split();
    write_message(
        &mut writer,
        &Message::Hello {
            side: me,
            dialed_by,
            version: mine.into(),
        },
    )
    .await?;
    let answer = time::timeout(HANDSHAKE, read_message(&mut reader))
        .await
        .context("no hello")??;
    match answer {
        Message::Hello {
            side,
            dialed_by: theirs,
            version,
        } => {
            ensure!(side == me.other(), "both servers chose the same side");
            ensure!(
                theirs == dialed_by,
                "the servers disagree on the connection"
            );
            Ok((reader, writer, dialed_by, version))
        }
        _ => bail!("unexpected first control message"),
    }
}

/// Where the control listener binds: every address of this machine (a server behind NAT does not
/// have its public address locally), except for a loopback address, which tests use to run both
/// sides on one machine.
fn bind_address(own: IpAddr, other: IpAddr, port: u16) -> SocketAddr {
    if own.is_loopback() {
        return SocketAddr::new(own, port);
    }
    if other.is_ipv6() {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port)
    }
}

/// Connects to the other server: listens and dials until a link is agreed on or `limit` passes.
/// `status` is told what is happening (for the waiting screen).
pub async fn pair(
    code: &super::code::CheckCode,
    me: Side,
    limit: Duration,
    status: impl Fn(&str),
) -> Result<Link> {
    pair_as(code, me, limit, status, env!("CARGO_PKG_VERSION")).await
}

/// The two servers must run the same version: a newer one sends values (a new verdict, a new
/// field) that an older one cannot read, which would break its live view in the middle of a run.
pub fn same_version(mine: &str, theirs: &str) -> Result<()> {
    ensure!(
        mine == theirs,
        "the other server runs EZTunnel {theirs}, this one {mine}: update both to the same version first"
    );
    Ok(())
}

/// `pair` claiming to be version `mine` (tests fake an older or newer server).
async fn pair_as(
    code: &super::code::CheckCode,
    me: Side,
    limit: Duration,
    status: impl Fn(&str),
    mine: &str,
) -> Result<Link> {
    let mine = mine.to_string();
    let Keys {
        server_private,
        server_public,
        client_private,
        client_public,
    } = keys(&code.key)?;
    let port = code.options.control_port;
    let other_ip = code.ip(me.other());
    let listener = TcpListener::bind(bind_address(code.ip(me), other_ip, port))
        .await
        .with_context(|| format!("cannot listen on the control port {port} (in use?)"))?;
    let deadline = time::Instant::now() + limit;
    let (found, mut links) = mpsc::channel::<Accepted>(8);
    let mut tasks = JoinSet::new();
    {
        let found = found.clone();
        let mine = mine.clone();
        tasks.spawn(async move {
            let mut handshakes = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        // Any source address: a server with several addresses may not dial from
                        // the one in the code. The handshake proves who it is; strangers are
                        // limited to a few at a time.
                        let Ok((stream, _)) = accepted else { continue };
                        if handshakes.len() >= 8 {
                            continue;
                        }
                        let found = found.clone();
                        let mine = mine.clone();
                        let server_private = server_private.clone();
                        handshakes.spawn(async move {
                            let Ok(connection) =
                                transport::accept_checker(stream, &server_private, &[client_public], HANDSHAKE).await
                            else {
                                return;
                            };
                            if let Ok(link) = hello(connection, me, me.other(), &mine).await {
                                let _ = found.send(link).await;
                            }
                        });
                    }
                    Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
                }
            }
        });
    }
    {
        let found = found.clone();
        let target = SocketAddr::new(other_ip, port).to_string();
        let mine = mine.clone();
        tasks.spawn(async move {
            // The foreign server dials first; the Iran server joins in when that does not work.
            if me == Side::Iran {
                time::sleep(Duration::from_secs(4)).await;
            }
            loop {
                if let Ok(connection) =
                    transport::connect_checker(&target, &client_private, &server_public, HANDSHAKE)
                        .await
                    && let Ok(link) = hello(connection, me, me, &mine).await
                {
                    let _ = found.send(link).await;
                }
                time::sleep(Duration::from_secs(2)).await;
            }
        });
    }
    drop(found);
    status(&format!(
        "waiting for the other server ({other_ip}, control port {port})"
    ));
    loop {
        let first = time::timeout_at(deadline, links.recv())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "the other server did not connect: check that the check is joined there and that TCP port {port} is open between the servers"
                )
            })?
            .context("pairing stopped")?;
        // A second link may finish at the same moment; prefer the one the foreign server dialed,
        // as the other side does.
        let mut candidates = vec![first];
        let settle = time::sleep(Duration::from_millis(600));
        tokio::pin!(settle);
        loop {
            tokio::select! {
                _ = &mut settle => break,
                Some(more) = links.recv() => candidates.push(more),
            }
        }
        let pick = candidates
            .iter()
            .position(|(_, _, dialed_by, _)| *dialed_by == Side::Foreign)
            .unwrap_or(0);
        let (mut reader, mut writer, dialed_by, theirs) = candidates.swap_remove(pick);
        drop(candidates);
        if write_message(&mut writer, &Message::Chosen).await.is_ok()
            && matches!(
                time::timeout(Duration::from_secs(4), read_message(&mut reader)).await,
                Ok(Ok(Message::Chosen))
            )
        {
            tasks.abort_all();
            if let Err(error) = same_version(&mine, &theirs) {
                // Agreed on the link first: an older version (0.8.0 to 0.8.3) only checks the
                // version in its log, and stops cleanly on a `Bye` once paired; during pairing it
                // would keep retrying instead.
                let _ = write_message(&mut writer, &Message::Bye).await;
                return Err(error);
            }
            status("connected to the other server");
            return Ok(Link::start(reader, writer, dialed_by));
        }
        status("the servers chose different connections; trying again");
        ensure!(
            time::Instant::now() < deadline,
            "could not agree on a connection with the other server"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Options, code::CheckCode};
    use super::*;

    /// A check code for the two sides on this machine, with a free control port.
    fn local_code() -> Result<CheckCode> {
        let free = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let options = Options {
            control_port: free,
            ..Options::default()
        };
        CheckCode::new(
            Side::Iran,
            "127.0.0.2".parse()?,
            "127.0.0.1".parse()?,
            options,
        )
    }

    /// The foreign side's first dial and hello, claiming to be `version`. One machine cannot
    /// listen twice on the control port, so in tests the Iran side runs `pair` and the foreign
    /// side only dials (from 127.0.0.1, its address in the code), as it does first.
    async fn foreign_dials(code: &CheckCode, version: &str) -> Result<Accepted> {
        let free = code.options.control_port;
        let Keys {
            server_public,
            client_private,
            ..
        } = keys(&code.key)?;
        let mut tries = 0;
        let connection = loop {
            match transport::connect_checker(
                &format!("127.0.0.2:{free}"),
                &client_private,
                &server_public,
                HANDSHAKE,
            )
            .await
            {
                Ok(connection) => break connection,
                Err(_) if tries < 50 => {
                    tries += 1;
                    time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        };
        hello(connection, Side::Foreign, Side::Foreign, version).await
    }

    #[tokio::test]
    async fn two_sides_pair_and_exchange_messages() -> Result<()> {
        let code = local_code()?;
        let iran_code = code.clone();
        let iran = tokio::spawn(async move {
            pair(&iran_code, Side::Iran, Duration::from_secs(15), |_| {}).await
        });
        let (mut reader, mut writer, _, _) =
            foreign_dials(&code, env!("CARGO_PKG_VERSION")).await?;
        write_message(&mut writer, &Message::Chosen).await?;
        assert!(matches!(read_message(&mut reader).await?, Message::Chosen));
        let mut foreign = Link::start(reader, writer, Side::Foreign);
        let mut iran = iran.await??;
        assert_eq!(iran.dialed_by, Side::Foreign);
        foreign.send(Message::Ready { service_port: 7 }).await?;
        assert!(matches!(
            iran.recv().await?,
            Message::Ready { service_port: 7 }
        ));
        // A large message is split into frames and put back together.
        let big = Report {
            version: "x".repeat(100_000),
            started: 0,
            seconds: 0,
            iran_ip: String::new(),
            foreign_ip: String::new(),
            options: Options::default(),
            baseline: None,
            cases: Vec::new(),
            stopped: None,
        };
        iran.send(Message::Done(Box::new(big))).await?;
        match foreign.recv().await? {
            Message::Done(report) => assert_eq!(report.version.len(), 100_000),
            other => panic!("unexpected {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn different_versions_end_the_pairing_with_a_clear_message() -> Result<()> {
        let ours = env!("CARGO_PKG_VERSION");
        // The other side is older (it only reads `Bye` once paired) or newer than this one.
        for (iran_version, foreign_version) in [(ours, "0.8.1"), ("0.8.1", ours)] {
            let code = local_code()?;
            let iran_code = code.clone();
            let claimed = iran_version.to_string();
            let iran = tokio::spawn(async move {
                pair_as(
                    &iran_code,
                    Side::Iran,
                    Duration::from_secs(15),
                    |_| {},
                    &claimed,
                )
                .await
            });
            let (mut reader, mut writer, _, theirs) = foreign_dials(&code, foreign_version).await?;
            assert_eq!(theirs, iran_version);
            write_message(&mut writer, &Message::Chosen).await?;
            assert!(matches!(read_message(&mut reader).await?, Message::Chosen));
            // The Iran side leaves before anything runs.
            assert!(matches!(read_message(&mut reader).await?, Message::Bye));
            let error = iran.await?.err().expect("pairing must fail").to_string();
            assert_eq!(
                error,
                format!(
                    "the other server runs EZTunnel {foreign_version}, this one {iran_version}: update both to the same version first"
                )
            );
            // The foreign side's own check says the same, from its side.
            let error = same_version(foreign_version, &theirs)
                .unwrap_err()
                .to_string();
            assert!(error.contains(&format!(
                "runs EZTunnel {iran_version}, this one {foreign_version}"
            )));
        }
        assert!(same_version(ours, ours).is_ok());
        Ok(())
    }
}
