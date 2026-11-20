//! The hub's side of other servers: which agents may connect, the one-time join tokens, and the
//! agents connected now with their latest snapshot. Requests to an agent (start a tunnel, read a
//! log) go over its link and wait for the answer.
use super::link::{self, JoinCode};
use super::ops::refused;
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

const KEY_FILE: &str = "agent-key.json";
const REGISTRY_FILE: &str = "agents.json";
/// How long a join code works.
pub const JOIN_VALID: Duration = Duration::from_secs(10 * 60);
/// Join codes waiting at once (an attacker who signed in still cannot fill memory).
const MAX_TOKENS: usize = 32;
/// The first message after the handshake must arrive within this time.
const FIRST_MESSAGE: Duration = Duration::from_secs(15);
/// An agent that sent nothing for this long is shown as offline.
pub const OFFLINE_AFTER: u64 = 20;

#[derive(Serialize, Deserialize, Clone)]
struct HubKey {
    private: String,
    public: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Registered {
    pub id: String,
    pub key: String,
    pub name: String,
    pub added: u64,
    /// A display name set on the dashboard; `name` keeps what the server called itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// An agent connected now.
struct Connected {
    hello: Value,
    snapshot: Option<Value>,
    seen: u64,
    requests: mpsc::Sender<Request>,
    /// Tells the link to close (the server was removed).
    close: Option<oneshot::Sender<()>>,
    /// Which link this is; a reconnect replaces the entry with a new number.
    link: u64,
    /// Logs followed on this agent: stream number -> where its lines go.
    streams: Streams,
}

/// A followed log's lines, with their journal cursors when the agent sends them.
type Streams = Arc<Mutex<HashMap<u64, mpsc::Sender<(String, Option<String>)>>>>;
type Hold = Arc<dyn Send + Sync>;
type Request = (Value, oneshot::Sender<Value>, Option<Hold>);

struct LinkReadTask(tokio::task::JoinHandle<()>);

impl Drop for LinkReadTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A log followed on another server. Dropping it tells the agent to stop.
pub struct RemoteFollow {
    pub lines: mpsc::Receiver<(String, Option<String>)>,
    stream: u64,
    streams: Streams,
    requests: mpsc::Sender<Request>,
}

impl Drop for RemoteFollow {
    fn drop(&mut self) {
        self.streams.lock().unwrap().remove(&self.stream);
        let (answer, _) = oneshot::channel();
        let requests = self.requests.clone();
        let request = (json!({"op": "unfollow", "stream": self.stream}), answer, None);
        // Unfollow is best-effort, but must wait for a temporarily full queue rather than
        // silently losing cleanup and consuming one of the agent's limited follow slots.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = requests.send(request).await;
            });
        } else {
            let _ = requests.try_send(request);
        }
    }
}

pub struct Fleet {
    dir: PathBuf,
    private: [u8; 32],
    public: [u8; 32],
    registry: Mutex<Vec<Registered>>,
    tokens: Mutex<HashMap<[u8; 16], u64>>,
    live: Mutex<HashMap<String, Connected>>,
    next_request: AtomicU64,
    /// Each joined server's history, kept by this server (`history/servers/ID`).
    histories: Mutex<HashMap<String, Arc<super::history::History>>>,
}

fn id_of(key: &[u8; 32]) -> String {
    hex::encode(&key[..6])
}

impl Fleet {
    /// Loads the hub's agent key (made on first use) and the registered agents.
    pub fn open(dir: &Path) -> Result<Arc<Self>> {
        let key_path = dir.join(KEY_FILE);
        let key: HubKey = match std::fs::read_to_string(&key_path) {
            Ok(text) => serde_json::from_str(&text).context("unreadable agent key")?,
            Err(_) => {
                let (private, public) = link::generate_keypair()?;
                let key = HubKey { private: hex::encode(private), public: hex::encode(public) };
                super::write_private(&key_path, &serde_json::to_vec_pretty(&key)?)?;
                key
            }
        };
        let decode = |text: &str| -> Result<[u8; 32]> {
            hex::decode(text)?.try_into().map_err(|_| anyhow!("agent key size"))
        };
        let registry = match std::fs::read_to_string(dir.join(REGISTRY_FILE)) {
            Ok(text) => serde_json::from_str(&text).context("unreadable agents.json")?,
            Err(_) => Vec::new(),
        };
        Ok(Arc::new(Self {
            dir: dir.to_path_buf(),
            private: decode(&key.private)?,
            public: decode(&key.public)?,
            registry: Mutex::new(registry),
            tokens: Mutex::default(),
            live: Mutex::default(),
            next_request: AtomicU64::new(1),
            histories: Mutex::default(),
        }))
    }

    fn history_dir(&self, id: &str) -> Option<PathBuf> {
        // Ids are hex; anything else never becomes a path.
        (!id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| self.dir.join("history").join("servers").join(id))
    }

    /// The history of a registered server (opened on first use).
    pub fn history(&self, id: &str) -> Option<Arc<super::history::History>> {
        if !self.registry.lock().unwrap().iter().any(|r| r.id == id) {
            return None;
        }
        let mut histories = self.histories.lock().unwrap();
        if let Some(history) = histories.get(id) {
            return Some(history.clone());
        }
        let store = super::history::FileStore::open(&self.history_dir(id)?).ok()?;
        let history = Arc::new(super::history::History::new(Box::new(store)));
        histories.insert(id.to_string(), history.clone());
        Some(history)
    }

    fn save_registry(&self, registry: &[Registered]) -> Result<()> {
        super::write_private(&self.dir.join(REGISTRY_FILE), &serde_json::to_vec_pretty(registry)?)
    }

    /// A one-time code for `eztunnel agent join`, valid for `JOIN_VALID`.
    pub fn join_code(&self, host: &str, port: u16) -> Result<(String, u64)> {
        let now = super::now();
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|_, expires| *expires > now);
        ensure!(tokens.len() < MAX_TOKENS, "too many join codes are waiting; wait a few minutes");
        let mut token = [0u8; 16];
        super::random_bytes(&mut token)?;
        let expires = now + JOIN_VALID.as_secs();
        tokens.insert(token, expires);
        let code = JoinCode { host: host.to_string(), port, hub_key: self.public, token };
        Ok((code.encode(), expires))
    }

    /// Whether a join code from `join_code` admitted a server (it is no longer waiting).
    pub fn code_used(&self, code: &str) -> bool {
        let Ok(code) = super::link::JoinCode::decode(code) else { return false };
        !self.tokens.lock().unwrap().contains_key(&code.token)
    }

    fn take_token(&self, token: &[u8; 16]) -> bool {
        let now = super::now();
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|_, expires| *expires > now);
        tokens.remove(token).is_some()
    }

    /// The registered servers with what is known about each now.
    pub fn servers(&self) -> Vec<Value> {
        let now = super::now();
        let registry = self.registry.lock().unwrap().clone();
        let live = self.live.lock().unwrap();
        registry
            .iter()
            .map(|r| {
                let connected = live.get(&r.id);
                let seen = connected.map(|c| c.seen);
                json!({
                    "id": r.id,
                    "name": r.label.as_ref().unwrap_or(&r.name),
                    "joined_name": r.name,
                    "added": r.added,
                    "online": seen.is_some_and(|s| now.saturating_sub(s) < OFFLINE_AFTER),
                    "last_seen": seen,
                    "hello": connected.map(|c| c.hello.clone()),
                    "snapshot": connected.and_then(|c| c.snapshot.clone()),
                })
            })
            .collect()
    }

    /// Sets (or with `None` clears) a registered server's display name. False if unknown.
    pub fn rename(&self, id: &str, label: Option<String>) -> Result<bool> {
        let mut registry = self.registry.lock().unwrap();
        let Some(server) = registry.iter_mut().find(|r| r.id == id) else {
            return Ok(false);
        };
        server.label = label;
        self.save_registry(&registry)?;
        Ok(true)
    }

    pub fn remove(&self, id: &str) -> Result<bool> {
        let mut registry = self.registry.lock().unwrap();
        let before = registry.len();
        registry.retain(|r| r.id != id);
        if registry.len() == before {
            return Ok(false);
        }
        self.save_registry(&registry)?;
        self.histories.lock().unwrap().remove(id);
        if let Some(dir) = self.history_dir(id) {
            let _ = std::fs::remove_dir_all(dir);
        }
        if let Some(mut connected) = self.live.lock().unwrap().remove(id)
            && let Some(close) = connected.close.take()
        {
            let _ = close.send(());
        }
        Ok(true)
    }

    /// Sends `request` to an agent and waits for its answer.
    pub async fn request(&self, id: &str, request: Value, timeout: Duration) -> Result<Value> {
        self.request_inner(id, request, timeout, None).await
    }

    /// Retains an operation guard until the actual response or link termination, even if the
    /// caller's deadline expires after dispatch.
    pub async fn request_held<H: Send + Sync + 'static>(&self, id: &str, request: Value, timeout: Duration, hold: Arc<H>) -> Result<Value> {
        self.request_inner(id, request, timeout, Some(hold)).await
    }

    async fn request_inner(&self, id: &str, request: Value, timeout: Duration, hold: Option<Hold>) -> Result<Value> {
        let sender = self
            .live
            .lock()
            .unwrap()
            .get(id)
            .map(|c| c.requests.clone())
            .ok_or_else(|| refused("offline", "that server is not connected"))?;
        self.request_on(&sender, request, timeout, hold).await
    }

    /// A request over one given link (not whichever link the server has by the time it is sent).
    async fn request_on(&self, sender: &mpsc::Sender<Request>, mut request: Value, timeout: Duration, hold: Option<Hold>) -> Result<Value> {
        request["id"] = json!(self.next_request.fetch_add(1, Ordering::Relaxed));
        let (answer_tx, answer_rx) = oneshot::channel();
        let answer = tokio::time::timeout(timeout, async {
            sender.send((request, answer_tx, hold)).await
                .map_err(|_| refused("offline", "that server is not connected"))?;
            answer_rx.await.map_err(|_| refused("offline", "the connection to that server ended"))
        }).await.map_err(|_| refused("timeout", "that server did not answer in time"))??;
        if answer["ok"] == true {
            return Ok(answer["result"].clone());
        }
        let message = answer["error"].as_str().unwrap_or("the server could not do it").to_string();
        // An agent from before codes sends the words alone.
        match answer["code"].as_str().and_then(super::ops::known_code) {
            Some(code) => Err(refused(code, message)),
            None => Err(anyhow!(message)),
        }
    }


    /// Follows a tunnel's log on another server: its new lines arrive on `lines`.
    pub async fn follow(&self, id: &str, name: &str, after: Option<String>) -> Result<RemoteFollow> {
        let (streams, requests) = {
            let live = self.live.lock().unwrap();
            let connected = live.get(id).ok_or_else(|| refused("offline", "that server is not connected"))?;
            (connected.streams.clone(), connected.requests.clone())
        };
        let stream = self.next_request.fetch_add(1, Ordering::Relaxed);
        let (tx, lines) = mpsc::channel(256);
        streams.lock().unwrap().insert(stream, tx);
        let follow = RemoteFollow { lines, stream, streams, requests: requests.clone() };
        // On the link whose stream map holds this follow: a reconnect in between ends the follow
        // (its map is cleared with the old link) instead of leaving it on neither.
        self.request_on(&requests, json!({"op": "follow", "name": name, "stream": stream, "after": after}), Duration::from_secs(15), None).await?;
        Ok(follow)
    }

    /// Runs one agent link until it ends. Returns why it ended. `event` hears about joins and
    /// refused joins (for the audit log).
    pub async fn serve<S>(self: &Arc<Self>, stream: S, event: impl Fn(&str, String)) -> Result<String>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer, key) =
            tokio::time::timeout(Duration::from_secs(10), link::accept(stream, &self.private))
                .await
                .context("agent handshake timed out")??;
        let id = id_of(&key);
        let known = self.registry.lock().unwrap().iter().any(|r| r.key == hex::encode(key));
        let first = tokio::time::timeout(FIRST_MESSAGE, reader.recv())
            .await
            .context("agent sent nothing")??;
        if !known {
            ensure!(first["type"] == "join", "unknown agent key");
            let token: [u8; 16] = hex::decode(first["token"].as_str().unwrap_or(""))
                .ok()
                .and_then(|t| t.try_into().ok())
                .context("join without a token")?;
            if !self.take_token(&token) {
                let _ = writer.send(&json!({"type": "refused", "reason": "the join code is unknown, used or expired"})).await;
                event("server_refused", "join code unknown, used or expired".into());
                bail!("join with an unknown, used or expired code");
            }
            let name: String = first["name"]
                .as_str()
                .unwrap_or("server")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
                .take(63)
                .collect();
            let mut registry = self.registry.lock().unwrap();
            registry.retain(|r| r.id != id);
            let name = if name.is_empty() { "server".to_string() } else { name };
            registry.push(Registered { id: id.clone(), key: hex::encode(key), name: name.clone(), added: super::now(), label: None });
            self.save_registry(&registry)?;
            event("server_joined", format!("{name} ({id})"));
        }
        writer.send(&json!({"type": "welcome", "id": id})).await?;
        let history = self.history(&id).context("open the server's history")?;

        // Complete frames outside select: losing a select branch must not discard bytes.
        let (messages_tx, mut messages_rx) = mpsc::channel(16);
        let _reader_task = LinkReadTask(tokio::spawn(async move {
            loop {
                let message = reader.recv().await;
                let ended = message.is_err();
                if messages_tx.send(message).await.is_err() || ended {
                    break;
                }
            }
        }));

        let (requests_tx, mut requests_rx) = mpsc::channel::<Request>(16);
        let (close_tx, mut close_rx) = oneshot::channel();
        let hello = if first["type"] == "hello" { first.clone() } else { first.get("hello").cloned().unwrap_or(Value::Null) };
        let link = self.next_request.fetch_add(1, Ordering::Relaxed);
        let streams: Streams = Arc::default();
        let replaced = self.live.lock().unwrap().insert(
            id.clone(),
            Connected { hello, snapshot: None, seen: super::now(), requests: requests_tx, close: Some(close_tx), link, streams: streams.clone() },
        );
        // An older link of the same agent (it reconnected) is told to end.
        if let Some(mut old) = replaced
            && let Some(close) = old.close.take()
        {
            let _ = close.send(());
        }
        let mut waiting: HashMap<u64, (oneshot::Sender<Value>, Option<Hold>)> = HashMap::new();
        let mut cleanup = tokio::time::interval(Duration::from_secs(1));
        let ended = loop {
            // Expired reads need no reply state. Dispatched mutations keep their guard until
            // their real response or disconnect, rather than unlocking on an HTTP timeout.
            waiting.retain(|_, (reply, hold)| !reply.is_closed() || hold.is_some());
            tokio::select! {
                message = messages_rx.recv() => {
                    let Some(message) = message else { break "agent reader ended".to_string() };
                    let message = match message { Ok(m) => m, Err(error) => break format!("{error:#}") };
                    let mut live = self.live.lock().unwrap();
                    let Some(connected) = live.get_mut(&id) else { break "removed".to_string() };
                    if connected.link != link { break "replaced".to_string(); }
                    connected.seen = super::now();
                    match message["type"].as_str() {
                        Some("hello") => connected.hello = message,
                        Some("snapshot") => {
                            connected.snapshot = Some(message["snapshot"].clone());
                            // History writes files: not while every other link waits on this lock.
                            drop(live);
                            history.record_value(&message["snapshot"], super::now() * 1000);
                        }
                        Some("log_line") => {
                            let stream = message["stream"].as_u64().unwrap_or(0);
                            let line = message["line"].as_str().unwrap_or("").to_string();
                            let cursor = message["cursor"].as_str().filter(|c| super::ops::cursor_ok(c)).map(str::to_string);
                            let mut streams = streams.lock().unwrap();
                            // A reader too slow for the log: its follow ends rather than skipping
                            // lines; the browser follows again from the last cursor it received.
                            if let Some(sender) = streams.get(&stream)
                                && sender.try_send((line, cursor)).is_err()
                            {
                                streams.remove(&stream);
                            }
                        }
                        Some("response") => {
                            if let Some((reply, _hold)) = message["id"].as_u64().and_then(|n| waiting.remove(&n)) {
                                let _ = reply.send(message);
                            }
                        }
                        _ => {}
                    }
                }
                Some((request, reply, hold)) = requests_rx.recv() => {
                    let mut request = request;
                    if !request["id"].is_null() && reply.is_closed() {
                        continue;
                    }
                    if request["id"].is_null() {
                        request["id"] = json!(self.next_request.fetch_add(1, Ordering::Relaxed));
                    } else if let Some(n) = request["id"].as_u64() {
                        waiting.insert(n, (reply, hold));
                    }
                    request["type"] = json!("request");
                    match tokio::time::timeout(Duration::from_secs(30), writer.send(&request)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => break format!("{error:#}"),
                        // A partial write cannot be resumed safely; close this link on timeout.
                        Err(_) => break "agent write timed out".to_string(),
                    }
                }
                _ = cleanup.tick() => {}
                _ = &mut close_rx => break "removed".to_string(),
            }
        };
        // Logs followed over this link end with it: their readers see the end and the browser
        // follows again over the next link, instead of waiting on a link that is gone.
        streams.lock().unwrap().clear();
        let mut live = self.live.lock().unwrap();
        if live.get(&id).is_some_and(|c| c.link == link) {
            live.remove(&id);
        }
        Ok(ended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_fragmented_snapshot_survives_a_concurrent_outgoing_request() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = Fleet::open(dir.path()).unwrap();
        let (code, _) = fleet.join_code("h", 1).unwrap();
        let code = JoinCode::decode(&code).unwrap();
        let (a, b) = tokio::io::duplex(256);
        let hub = fleet.clone();
        let serving = tokio::spawn(async move { hub.serve(b, |_, _| {}).await });
        let (mut rx, mut tx, _) = agent_side(a, fleet.public,
            json!({"type": "join", "token": hex::encode(code.token), "name": "n"})).await;
        let id = fleet.servers()[0]["id"].as_str().unwrap().to_string();
        let sending = tokio::spawn(async move {
            tx.send(&json!({"type": "snapshot", "snapshot": {"padding": "x".repeat(150_000)}})).await.unwrap();
            tx
        });
        let hub = fleet.clone();
        let request_id = id.clone();
        let request = tokio::spawn(async move {
            hub.request(&request_id, json!({"op": "names"}), Duration::from_secs(5)).await
        });
        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        let mut tx = sending.await.unwrap();
        tx.send(&json!({"type": "response", "id": received["id"], "ok": true, "result": []})).await.unwrap();
        assert_eq!(request.await.unwrap().unwrap(), json!([]));
        assert_eq!(fleet.servers()[0]["snapshot"]["padding"].as_str().unwrap().len(), 150_000);
        fleet.remove(&id).unwrap();
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_dispatched_operation_keeps_its_guard_after_the_caller_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = Fleet::open(dir.path()).unwrap();
        let (code, _) = fleet.join_code("h", 1).unwrap();
        let code = JoinCode::decode(&code).unwrap();
        let (a, b) = tokio::io::duplex(256);
        let hub = fleet.clone();
        let serving = tokio::spawn(async move { hub.serve(b, |_, _| {}).await });
        let (mut rx, mut tx, _) = agent_side(a, fleet.public,
            json!({"type": "join", "token": hex::encode(code.token), "name": "n"})).await;
        let id = loop {
            if let Some(server) = fleet.servers().first() {
                break server["id"].as_str().unwrap().to_string();
            }
            tokio::task::yield_now().await;
        };
        let hold = Arc::new(());
        let weak = Arc::downgrade(&hold);
        let (dispatched, seen) = oneshot::channel();
        let (finish, done) = oneshot::channel();
        let agent = tokio::spawn(async move {
            let request = rx.recv().await.unwrap();
            dispatched.send(()).unwrap();
            done.await.unwrap();
            tx.send(&json!({"type": "response", "id": request["id"], "ok": true, "result": null})).await.unwrap();
            (rx, tx)
        });
        let caller_fleet = fleet.clone();
        let caller_id = id.clone();
        let caller = tokio::spawn(async move {
            caller_fleet.request_held(&caller_id, json!({"op": "act"}), Duration::from_millis(100), hold).await
        });
        seen.await.unwrap();
        assert!(caller.await.unwrap().is_err());
        assert!(weak.upgrade().is_some(), "dispatched work retains the operation guard");
        finish.send(()).unwrap();
        let _agent_link = agent.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while weak.upgrade().is_some() { tokio::task::yield_now().await; }
        }).await.unwrap();
        fleet.remove(&id).unwrap();
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_full_request_queue_is_covered_by_the_request_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = Fleet::open(dir.path()).unwrap();
        let (requests, mut queued) = mpsc::channel(1);
        let (reply, _answer) = oneshot::channel();
        requests.send((json!({"id": 99}), reply, None)).await.unwrap();
        fleet.live.lock().unwrap().insert("test".into(), Connected {
            hello: Value::Null, snapshot: None, seen: super::super::now(),
            requests, close: None, link: 1, streams: Arc::default(),
        });
        let result = tokio::time::timeout(Duration::from_secs(1),
            fleet.request("test", json!({"op": "names"}), Duration::from_millis(10))).await;
        assert!(result.unwrap().unwrap_err().to_string().contains("in time"));
        assert_eq!(queued.recv().await.unwrap().0["id"], 99);
        assert!(queued.try_recv().is_err(), "expired request was not enqueued later");
    }

    #[tokio::test]
    async fn dropping_a_follow_waits_for_space_to_send_unfollow() {
        let (requests, mut queued) = mpsc::channel(1);
        let (reply, _answer) = oneshot::channel();
        requests.send((json!({"op": "names"}), reply, None)).await.unwrap();
        let (tx, lines) = mpsc::channel(1);
        let streams: Streams = Arc::default();
        streams.lock().unwrap().insert(7, tx);
        drop(RemoteFollow { lines, stream: 7, streams: streams.clone(), requests });
        assert!(streams.lock().unwrap().is_empty());
        assert_eq!(queued.recv().await.unwrap().0["op"], "names");
        let (stop, _, _) = tokio::time::timeout(Duration::from_secs(1), queued.recv()).await.unwrap().unwrap();
        assert_eq!(stop["op"], "unfollow");
        assert_eq!(stop["stream"], 7);
    }

    async fn agent_side(
        stream: tokio::io::DuplexStream,
        hub_public: [u8; 32],
        first: Value,
    ) -> (link::LinkReader<tokio::io::DuplexStream>, link::LinkWriter<tokio::io::DuplexStream>, Value) {
        let (private, _) = link::generate_keypair().unwrap();
        let (mut rx, mut tx) = link::connect(stream, &private, &hub_public).await.unwrap();
        tx.send(&first).await.unwrap();
        let answer = rx.recv().await.unwrap_or(Value::Null);
        (rx, tx, answer)
    }

    #[tokio::test]
    async fn a_join_code_admits_one_agent_once() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = Fleet::open(dir.path()).unwrap();
        let (code, expires) = fleet.join_code("203.0.113.10", 38_471).unwrap();
        assert!(expires > super::super::now());
        let code = JoinCode::decode(&code).unwrap();
        assert_eq!(code.hub_key, fleet.public);
        let join = json!({"type": "join", "token": hex::encode(code.token), "name": "frankfurt-1; rm"});

        let (a, b) = tokio::io::duplex(1 << 20);
        let hub = fleet.clone();
        let serving = tokio::spawn(async move { hub.serve(b, |_, _| {}).await });
        let (_rx, mut tx, welcome) = agent_side(a, fleet.public, join.clone()).await;
        assert_eq!(welcome["type"], "welcome");
        tx.send(&json!({"type": "snapshot", "snapshot": {"tunnels": []}})).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let servers = fleet.servers();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["name"], "frankfurt-1rm", "only name characters kept");
        assert_eq!(servers[0]["online"], true);
        assert!(servers[0]["snapshot"].is_object());

        // The same code does not work twice.
        let (a, b) = tokio::io::duplex(1 << 20);
        let hub = fleet.clone();
        let second = tokio::spawn(async move { hub.serve(b, |_, _| {}).await });
        let (_, _, answer) = agent_side(a, fleet.public, join).await;
        assert_eq!(answer["type"], "refused");
        assert!(second.await.unwrap().is_err());
        assert_eq!(fleet.servers().len(), 1);

        // A dashboard name replaces the shown name, survives a reload and can be cleared.
        let id = servers[0]["id"].as_str().unwrap().to_string();
        assert!(fleet.rename(&id, Some("Tehran game".into())).unwrap());
        assert!(!fleet.rename("ffffffffffff", Some("x".into())).unwrap(), "unknown server");
        assert_eq!(fleet.servers()[0]["name"], "Tehran game");
        assert_eq!(fleet.servers()[0]["joined_name"], "frankfurt-1rm");
        assert_eq!(Fleet::open(dir.path()).unwrap().servers()[0]["name"], "Tehran game", "the name is saved");
        assert!(fleet.rename(&id, None).unwrap());
        assert_eq!(fleet.servers()[0]["name"], "frankfurt-1rm");

        // Removing the server ends its link and it cannot come back.
        assert!(fleet.remove(&id).unwrap());
        assert_eq!(serving.await.unwrap().unwrap(), "removed");
        assert!(fleet.servers().is_empty());
        let reloaded = Fleet::open(dir.path()).unwrap();
        assert!(reloaded.servers().is_empty(), "removal is saved");
        assert_eq!(reloaded.public, fleet.public, "the hub key stays");
    }

    #[tokio::test]
    async fn a_followed_remote_log_streams_lines_and_stops_when_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = Fleet::open(dir.path()).unwrap();
        let (code, _) = fleet.join_code("h", 1).unwrap();
        let code = JoinCode::decode(&code).unwrap();
        let (a, b) = tokio::io::duplex(1 << 20);
        let hub = fleet.clone();
        tokio::spawn(async move { hub.serve(b, |_, _| {}).await });
        let (mut rx, mut tx, _) =
            agent_side(a, fleet.public, json!({"type": "join", "token": hex::encode(code.token), "name": "n"})).await;
        let id = fleet.servers()[0]["id"].as_str().unwrap().to_string();
        let agent = tokio::spawn(async move {
            let request = rx.recv().await.unwrap();
            assert_eq!(request["op"], "follow");
            let stream = request["stream"].clone();
            tx.send(&json!({"type": "response", "id": request["id"], "ok": true, "result": null})).await.unwrap();
            for n in 0..3 {
                tx.send(&json!({"type": "log_line", "stream": stream, "line": format!("line {n}")})).await.unwrap();
            }
            // The hub tells the agent to stop once the browser is gone.
            let stop = rx.recv().await.unwrap();
            assert_eq!(stop["op"], "unfollow");
            assert_eq!(stop["stream"], stream);
        });
        let mut follow = fleet.follow(&id, "t", None).await.unwrap();
        for n in 0..3 {
            assert_eq!(follow.lines.recv().await.unwrap().0, format!("line {n}"));
        }
        drop(follow);
        tokio::time::timeout(Duration::from_secs(5), agent).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_unknown_agent_without_a_code_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = Fleet::open(dir.path()).unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        let hub = fleet.clone();
        let serving = tokio::spawn(async move { hub.serve(b, |_, _| {}).await });
        let (private, _) = link::generate_keypair().unwrap();
        let (_rx, mut tx) = link::connect(a, &private, &fleet.public).await.unwrap();
        tx.send(&json!({"type": "hello"})).await.unwrap();
        assert!(serving.await.unwrap().is_err());
        assert!(fleet.servers().is_empty());
    }

    #[tokio::test]
    async fn requests_reach_the_agent_and_its_answers_come_back() {
        let dir = tempfile::tempdir().unwrap();
        let fleet = Fleet::open(dir.path()).unwrap();
        let (code, _) = fleet.join_code("h", 1).unwrap();
        let code = JoinCode::decode(&code).unwrap();
        let (a, b) = tokio::io::duplex(1 << 20);
        let hub = fleet.clone();
        tokio::spawn(async move { hub.serve(b, |_, _| {}).await });
        let (mut rx, mut tx, _) =
            agent_side(a, fleet.public, json!({"type": "join", "token": hex::encode(code.token), "name": "n"})).await;
        let id = fleet.servers()[0]["id"].as_str().unwrap().to_string();
        let agent = tokio::spawn(async move {
            for _ in 0..4 {
                let request = rx.recv().await.unwrap();
                let answer = if request["op"] == "names" {
                    json!({"type": "response", "id": request["id"], "ok": true, "result": ["t1"]})
                } else if request["name"] == "x" {
                    json!({"type": "response", "id": request["id"], "ok": false, "error": "no tunnel named x"})
                } else if request["name"] == "coded" {
                    json!({"type": "response", "id": request["id"], "ok": false, "error": "no tunnel named coded", "code": "unknown_tunnel"})
                } else {
                    // A code this version does not know counts as none.
                    json!({"type": "response", "id": request["id"], "ok": false, "error": "odd", "code": "made_up"})
                };
                tx.send(&answer).await.unwrap();
            }
        });
        let names = fleet.request(&id, json!({"op": "names"}), Duration::from_secs(5)).await.unwrap();
        assert_eq!(names, json!(["t1"]));
        // An agent from before codes: the words only.
        let failed = fleet.request(&id, json!({"op": "act", "name": "x"}), Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(failed.to_string(), "no tunnel named x");
        assert_eq!(super::super::ops::code_of(&failed), None);
        let coded = fleet.request(&id, json!({"op": "act", "name": "coded"}), Duration::from_secs(5)).await.unwrap_err();
        assert_eq!((coded.to_string().as_str(), super::super::ops::code_of(&coded)), ("no tunnel named coded", Some("unknown_tunnel")));
        let odd = fleet.request(&id, json!({"op": "act", "name": "odd"}), Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(super::super::ops::code_of(&odd), None);
        agent.await.unwrap();
        let offline = fleet.request("nothing", json!({}), Duration::from_secs(1)).await.unwrap_err();
        assert_eq!(super::super::ops::code_of(&offline), Some("offline"));
    }
}
