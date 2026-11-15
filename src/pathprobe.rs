//! A quick look at the path to another server: ping and TCP connects to a few common ports.
//! A refused connection still proves the path (a reset came back); only timeouts mean the
//! packets are lost on the way. Used while a check waits for the other server, so a blocked pair
//! is explained instead of waiting in silence.
use serde::Serialize;
use std::{net::IpAddr, time::Duration};
use tokio::{net::TcpStream, time::timeout};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tcp {
    /// Something accepted the connection.
    Open,
    /// A reset came back: the path works, nothing listens there.
    Refused,
    /// No answer at all.
    Timeout,
    /// The network said there is no route.
    Unreachable,
}

#[derive(Debug, Clone, Serialize)]
pub struct Path {
    pub peer: IpAddr,
    /// `None` when ping could not run here.
    pub ping: Option<bool>,
    pub tcp: Vec<(u16, Tcp)>,
}

/// Ports a server usually answers on (SSH, web), plus the ones the caller cares about.
pub const COMMON: [u16; 4] = [22, 80, 443, 8443];

pub async fn tcp(peer: IpAddr, port: u16, wait: Duration) -> Tcp {
    match timeout(wait, TcpStream::connect((peer, port))).await {
        Ok(Ok(_)) => Tcp::Open,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Tcp::Refused,
        Ok(Err(_)) => Tcp::Unreachable,
        Err(_) => Tcp::Timeout,
    }
}

pub async fn ping(peer: IpAddr) -> Option<bool> {
    let mut command = tokio::process::Command::new("ping");
    if peer.is_ipv6() {
        command.arg("-6");
    }
    let output = command
        .args(["-c", "3", "-W", "2", "-n"])
        .arg(peer.to_string())
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    let output = timeout(Duration::from_secs(10), output).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !text.contains("packets transmitted") {
        return None;
    }
    Some(!text.contains(" 0 received"))
}

/// Pings the peer and tries every port at once (each up to `wait`).
pub async fn probe(peer: IpAddr, extra: &[u16], wait: Duration) -> Path {
    let mut ports: Vec<u16> = COMMON.to_vec();
    for port in extra {
        if !ports.contains(port) {
            ports.push(*port);
        }
    }
    let mut set = tokio::task::JoinSet::new();
    for port in ports.clone() {
        set.spawn(async move { (port, tcp(peer, port, wait).await) });
    }
    let all = async {
        let mut found = Vec::new();
        while let Some(Ok(result)) = set.join_next().await {
            found.push(result);
        }
        found
    };
    let (ping, mut tcp) = tokio::join!(ping(peer), all);
    tcp.sort_by_key(|(port, _)| ports.iter().position(|p| p == port));
    Path { peer, ping, tcp }
}

impl Path {
    /// Whether anything at all came back from the peer.
    pub fn reachable(&self) -> bool {
        self.ping == Some(true) || self.tcp.iter().any(|(_, r)| matches!(r, Tcp::Open | Tcp::Refused))
    }

    /// One line for a waiting screen.
    pub fn hint(&self, control_port: u16) -> String {
        let ports: Vec<String> = self.tcp.iter().map(|(p, _)| p.to_string()).collect();
        if !self.reachable() {
            return format!(
                "no path to {}: ping and TCP on {} get no answer at all. The networks between the two servers block each other (one of them is filtered), so no transport can connect directly. Use a relay server both can reach, or try again once the block lifts.",
                self.peer,
                ports.join(", ")
            );
        }
        let control = self.tcp.iter().find(|(p, _)| *p == control_port).map(|(_, r)| *r);
        match control {
            Some(Tcp::Timeout) => format!(
                "{} answers, but the check's control port {control_port} gets no answer: a firewall on the way or on that server drops it; allow TCP {control_port} there",
                self.peer
            ),
            _ => format!("{} is reachable; it has not joined this check yet (start or join it there with this code)", self.peer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_refused_port_proves_the_path_and_silence_does_not() {
        // Something on loopback refuses at once: the path works.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let path = probe("127.0.0.1".parse().unwrap(), &[open, closed], Duration::from_secs(2)).await;
        assert!(path.reachable());
        assert!(path.tcp.contains(&(open, Tcp::Open)));
        assert!(path.tcp.contains(&(closed, Tcp::Refused)));
        assert!(path.hint(closed).contains("reachable"));
        let silent = Path { peer: "192.0.2.1".parse().unwrap(), ping: Some(false), tcp: vec![(22, Tcp::Timeout), (443, Tcp::Timeout)] };
        assert!(!silent.reachable());
        assert!(silent.hint(47100).starts_with("no path to 192.0.2.1"));
        let control = Path { peer: "192.0.2.1".parse().unwrap(), ping: Some(true), tcp: vec![(22, Tcp::Open), (47100, Tcp::Timeout)] };
        assert!(control.hint(47100).contains("control port 47100"));
    }
}
