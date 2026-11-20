//! The HTTP side: sign-in, the JSON API, live updates (Server-Sent Events) and the UI files.
use super::{assets, audit::Audit, auth, data::Live, ops::{self, Ops}};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::Semaphore,
};

/// Connections served at once; more wait in the kernel's queue.
const MAX_CONNECTIONS: usize = 256;
/// Default JSON body limit; program uploads and backup imports use their own larger caps.
const MAX_BODY: usize = 8 * 1024;
/// The header every state-changing request must carry. Browsers do not let other sites set it
/// without the dashboard's permission, which it never gives.
const CSRF_HEADER: &str = "x-eztunnel";
/// Longest an action may take, including watching a started tunnel come up (about 15 s).
const ACTION_TIMEOUT: Duration = Duration::from_secs(40);
/// Longest restart-all may take.
const ALL_TIMEOUT: Duration = Duration::from_secs(300);
/// Live logs watched at once, across every browser.
pub const MAX_FOLLOWERS: usize = 8;
/// The name `busy` uses while every tunnel is being restarted.
const ALL: &str = "*";
/// How long a signed-in browser may take to upload a file.
const UPLOAD_DEADLINE: Duration = Duration::from_secs(15 * 60);

pub struct AppState {
    pub history: Arc<super::history::History>,
    pub auth: auth::Auth,
    pub audit: Audit,
    pub live: Arc<Live>,
    pub ops: Arc<dyn Ops>,
    /// Tunnels with an action under way ("*": restart all), so two never overlap.
    pub busy: Mutex<HashSet<String>>,
    /// Live logs being watched.
    pub followers: Arc<Semaphore>,
    /// Other servers (agents); `None` in the demo, which shows sample servers.
    pub fleet: Option<Arc<super::fleet::Fleet>>,
    /// The address and port join codes point agents to.
    pub public: (String, u16),
    /// Agent links open at once.
    pub agent_slots: Arc<Semaphore>,
    /// The certificate being served (HTTPS only): join commands pin its key.
    pub cert: Option<Arc<super::tls::Swap>>,
    pub demo: bool,
    /// HTTPS: cookies are marked Secure and carry the __Host- prefix.
    pub secure: bool,
    /// Where the dashboard keeps its data (releases and backups live below it).
    pub state_dir: std::path::PathBuf,
    /// Alerts that fired and have not cleared.
    pub alerts: Mutex<super::alerts::Engine>,
}

impl AppState {
    fn cookie_name(&self) -> &'static str {
        if self.secure { "__Host-ezd" } else { "ezd" }
    }

    fn token(&self, headers: &HeaderMap) -> Option<String> {
        let wanted = self.cookie_name();
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .find_map(|pair| {
                let (name, value) = pair.trim().split_once('=')?;
                (name == wanted).then(|| value.to_string())
            })
    }

    fn signed_in(&self, headers: &HeaderMap) -> bool {
        self.token(headers).is_some_and(|token| self.auth.check(&token))
    }

    fn cookie(&self, value: &str, max_age: u64) -> HeaderValue {
        let secure = if self.secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
            self.cookie_name()
        ))
        .expect("cookie text is ASCII")
    }
}

/// The address of the browser, set per connection.
#[derive(Clone, Copy)]
struct ClientIp(IpAddr);

fn client_ip(request: &Request) -> Option<IpAddr> {
    request.extensions().get::<ClientIp>().map(|ip| ip.0)
}

pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/api/session", get(session))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/snapshot", get(snapshot))
        .route("/api/events", get(events))
        .route("/api/history", get(history))
        .route("/api/restart-all", post(restart_all))
        .route("/api/activity", get(activity))
        .route("/agent", get(agent_link))
        .route("/join.sh", get(join_script))
        .route("/api/servers", get(servers))
        .route("/api/join-codes", post(join_code))
        .route("/api/servers/{id}", axum::routing::delete(remove_server))
        .route("/api/servers/{id}/restart-all", post(server_restart_all))
        .route("/api/servers/{id}/name", post(server_rename))
        .route("/api/servers/{id}/tunnels/{name}/logs", get(server_logs))
        .route("/api/servers/{id}/tunnels/{name}/logs/follow", get(server_follow))
        .route("/api/servers/{id}/tunnels/{name}/{action}", post(server_act))
        .route("/api/tunnels/{name}/logs", get(logs))
        .route("/api/tunnels/{name}/settings", get(local_editable).post(local_edit))
        .route("/api/tunnels/{name}/undo", post(local_undo))
        .route("/api/tunnels/{name}", axum::routing::delete(local_delete))
        .route("/api/new-tunnel", get(new_tunnel_options).post(new_tunnel))
        .route("/api/tunnels/{name}/status", get(local_status))
        .route("/api/servers/{id}/tools/{tool}", post(server_tool_answer))
        .route("/api/conntest", get(conntest_status).post(conntest_start))
        .route("/api/conntest/stop", post(conntest_stop))
        .route("/api/mirage-test", get(mirage_status).post(mirage_start))
        .route("/api/mirage-test/stop", post(mirage_stop))
        .route("/api/ssh-key", get(ssh_key))
        .route("/api/pathfinder", post(pathfinder))
        .route("/api/pathfinder/cancel", post(pathfinder_cancel))
        .route("/api/servers/ssh", post(ssh_add))
        .route("/api/releases", get(releases))
        .route("/api/alerts", get(alerts_list))
        .route("/api/alerts/test", post(alerts_test))
        .route("/api/settings", get(settings_get).post(settings_set))
        .route("/api/password", post(password_set))
        .route("/api/sessions", get(sessions_list))
        .route("/api/sessions/revoke", post(sessions_revoke))
        .route("/metrics", get(metrics))
        .route("/api/releases/check", post(release_check))
        .route("/api/releases/fetch", post(release_fetch))
        .route("/api/releases/upload", post(release_upload))
        .route("/api/servers/{id}/install", post(server_install))
        .route("/api/backups", get(backup_list).post(backup_now))
        .route("/api/backups/{file}", get(backup_download).delete(backup_delete))
        .route("/api/servers/{id}/restore", post(server_restore))
        .route("/api/servers/{id}/tunnels/{name}/status", get(server_status))
        .route("/api/tunnels/{name}/tools/{op}", post(local_tool))
        .route("/api/servers/{id}/tunnels/{name}/tools/{op}", post(server_tool))
        .route("/api/servers/{id}/tunnels/{name}", axum::routing::delete(server_delete))
        .route("/api/servers/{id}/tunnels/{name}/settings", get(server_editable).post(server_edit))
        .route("/api/servers/{id}/tunnels/{name}/undo", post(server_undo))
        .route("/api/tunnels/{name}/logs/follow", get(follow))
        .route("/api/tunnels/{name}/{action}", post(act));
    Router::new()
        .merge(api)
        .fallback(get(assets::serve))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

/// Every response gets the security headers; every request that changes something must come
/// from the dashboard's own page.
async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let api = request.uri().path().starts_with("/api/");
    if request.method() != Method::GET && request.method() != Method::HEAD {
        let headers = request.headers();
        let marked = headers.get(CSRF_HEADER).is_some_and(|v| v == "1");
        let same_origin = match (headers.get(header::ORIGIN), headers.get(header::HOST)) {
            (None, _) => true,
            (Some(origin), Some(host)) => {
                let scheme = if state.secure { "https" } else { "http" };
                origin.to_str().ok() == host.to_str().ok().map(|h| format!("{scheme}://{h}")).as_deref()
            }
            (Some(_), None) => false,
        };
        if !marked || !same_origin {
            return with_headers((StatusCode::FORBIDDEN, Json(json!({"error": "forbidden"}))).into_response(), api);
        }
    }
    with_headers(next.run(request).await, api)
}

async fn read_body(request: Request, limit: usize) -> Result<bytes::Bytes, Response> {
    read_body_with_deadline(request.into_body(), limit, Duration::from_secs(30)).await
}

/// A file uploaded by a signed-in browser (a program, a backup): megabytes that a slow link needs
/// minutes for, so it gets longer than an ordinary request body. Callers check the session first.
async fn read_upload(request: Request, limit: usize) -> Result<bytes::Bytes, Response> {
    read_body_with_deadline(request.into_body(), limit, UPLOAD_DEADLINE).await
}

async fn read_body_with_deadline(body: Body, limit: usize, deadline: Duration) -> Result<bytes::Bytes, Response> {
    let status = match tokio::time::timeout(deadline, axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => return Ok(bytes),
        Ok(Err(_)) => StatusCode::PAYLOAD_TOO_LARGE,
        Err(_) => StatusCode::REQUEST_TIMEOUT,
    };
    let mut response = status.into_response();
    response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    Err(response)
}

fn with_headers(mut response: Response, api: bool) -> Response {
    let headers = response.headers_mut();
    let mut set = |name: &'static str, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    );
    set("x-content-type-options", "nosniff");
    set("x-frame-options", "DENY");
    set("referrer-policy", "no-referrer");
    set("cross-origin-opener-policy", "same-origin");
    set("cross-origin-resource-policy", "same-origin");
    set("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()");
    if api {
        set("cache-control", "no-store");
    }
    response
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "signed_out"}))).into_response()
}

async fn session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    Json(json!({
        "signed_in": state.signed_in(&headers),
        "demo": state.demo,
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct LoginBody {
    password: String,
}

async fn login(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let ip = client_ip(&request);
    let bytes = match read_body(request, MAX_BODY).await { Ok(bytes) => bytes, Err(response) => return response };
    let Ok(body) = serde_json::from_slice::<LoginBody>(&bytes) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request"}))).into_response();
    };
    let Some(ip) = ip else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if body.password.is_empty() || body.password.len() > auth::MAX_PASSWORD_BYTES {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "wrong_password"}))).into_response();
    }
    match state.auth.login(ip, body.password).await {
        Ok(auth::Login::Ok(token)) => {
            state.audit.record(Some(ip), "login", "signed in");
            let mut response = Json(json!({"ok": true})).into_response();
            response
                .headers_mut()
                .insert(header::SET_COOKIE, state.cookie(&token, 7 * 24 * 3600));
            response
        }
        Ok(auth::Login::Wrong) => {
            state.audit.record(Some(ip), "login_failed", "wrong password");
            (StatusCode::UNAUTHORIZED, Json(json!({"error": "wrong_password"}))).into_response()
        }
        Ok(auth::Login::Wait(seconds)) => {
            // Refusals cost nothing to send; one line per address and minute is enough.
            state.audit.record_repeated(Some(ip), "login_refused", &format!("locked for {seconds} s"));
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "locked", "retry_after": seconds})),
            )
                .into_response();
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn logout(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let ip = client_ip(&request);
    if let Some(token) = state.token(request.headers()) {
        if state.auth.check(&token) {
            state.audit.record(ip, "logout", "signed out");
        }
        state.auth.logout(&token);
    }
    let mut response = Json(json!({"ok": true})).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, state.cookie("", 0));
    response
}

async fn snapshot(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    Json(json!({
        "snapshot": state.live.latest().as_deref(),
        "history": state.live.history(),
        "interval_ms": super::data::INTERVAL.as_millis() as u64,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct HistoryQuery {
    range: String,
    series: String,
    /// The viewer's offset from UTC in minutes (Tehran: 210), for daily buckets.
    #[serde(default)]
    tz: i64,
    /// A joined server's id; this server when missing or "local".
    #[serde(default)]
    server: String,
}

async fn history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<HistoryQuery>,
) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let tz = query.tz.clamp(-14 * 60, 14 * 60);
    let history = match (&state.fleet, query.server.as_str()) {
        (_, "" | "local") | (None, _) => state.history.clone(),
        (Some(fleet), id) => match fleet.history(id) {
            Some(history) => history,
            None => return error(StatusCode::NOT_FOUND, "unknown_server"),
        },
    };
    let answer = tokio::task::spawn_blocking(move || history.query(&query.range, &query.series, now, tz)).await;
    match answer {
        Ok(Some(value)) => Json(value).into_response(),
        Ok(None) => (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request"}))).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Sends every new snapshot as it is taken. The stream ends when the session does, so a signed
/// out browser stops receiving data within one interval.
async fn events(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(token) = state.token(&headers).filter(|t| state.auth.check(t)) else {
        return unauthorized();
    };
    let receiver = state.live.subscribe();
    let stream = futures_util::stream::unfold(
        (receiver, state, token),
        |(mut receiver, state, token)| async move {
            loop {
                match receiver.recv().await {
                    Ok(snapshot) => {
                        if !state.auth.check(&token) {
                            return None;
                        }
                        let event = Event::default()
                            .event("snapshot")
                            .json_data(&*snapshot)
                            .unwrap_or_else(|_| Event::default().comment("unserializable"));
                        return Some((Ok::<_, Infallible>(event), (receiver, state, token)));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// Marks tunnels as having an action under way until dropped.
struct Busy {
    state: Arc<AppState>,
    names: Vec<String>,
}

impl Busy {
    /// `None` when one of `names`, or restart-all, is already under way. Restart-all (`ALL`)
    /// also waits until no single action is under way.
    fn take(state: &Arc<AppState>, names: Vec<String>) -> Option<Arc<Self>> {
        let mut busy = state.busy.lock().unwrap();
        let conflicts = |a: &str, b: &str| {
            a == ALL || b == ALL || a == b
                || a.strip_suffix("/*").is_some_and(|server| b.starts_with(&format!("{server}/")))
                || b.strip_suffix("/*").is_some_and(|server| a.starts_with(&format!("{server}/")))
        };
        if names.iter().any(|name| busy.iter().any(|held| conflicts(name, held))) {
            return None;
        }
        busy.extend(names.iter().cloned());
        drop(busy);
        Some(Arc::new(Self { state: state.clone(), names }))
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        let mut busy = self.state.busy.lock().unwrap();
        for name in &self.names {
            busy.remove(name);
        }
    }
}

fn error(status: StatusCode, word: &str) -> Response {
    (status, Json(json!({"error": word}))).into_response()
}

/// A failed request's answer. A failure with a code (`ops::code_of`, also from a joined server)
/// gets its own status and word; any other keeps `otherwise` and "failed", as before. The
/// message is always in `detail`.
fn failure_response(failure: &anyhow::Error, otherwise: StatusCode) -> Response {
    let (status, word) = match ops::code_of(failure) {
        Some("unknown_tunnel") => (StatusCode::NOT_FOUND, "unknown_tunnel"),
        Some("busy") => (StatusCode::CONFLICT, "busy"),
        Some("pair_changed") => (StatusCode::CONFLICT, "pair_changed"),
        Some("offline") => (StatusCode::BAD_GATEWAY, "offline"),
        Some("timeout") => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
        _ => (otherwise, "failed"),
    };
    (status, Json(json!({"error": word, "detail": format!("{failure:#}")}))).into_response()
}

/// The tunnel names that exist, read off the async threads.
async fn tunnel_names(state: &Arc<AppState>) -> Vec<String> {
    let ops = state.ops.clone();
    tokio::task::spawn_blocking(move || ops.names()).await.unwrap_or_default()
}

/// Use a distinct action-name variant on the EXISTING URL so an older Hub
/// also fails closed (its legacy parse_action rejects paired-start/stop/restart).
fn action_route(word: &str) -> Option<(crate::manager::bulk::Action, bool)> {
    if let Some(legacy) = ops::parse_action(word) {
        return Some((legacy, false));
    }
    word.strip_prefix("paired-")
        .and_then(ops::parse_action)
        .map(|action| (action, true))
}

/// A guarded lifecycle request uses the existing action URL, with an expected pair
/// identity checked atomically inside the target Agent (or LocalOps) store lock.
async fn action_pair_guard(request: Request) -> Result<Option<String>, Response> {
    let bytes = read_body(request, MAX_BODY).await?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "bad_request"))?;
    if !body.is_object() {
        return Err(error(StatusCode::BAD_REQUEST, "bad_request"));
    }
    match body.get("expect_pair") {
        None => Ok(None),
        Some(Value::String(pair)) if ops::valid_pair(pair) => Ok(Some(pair.to_ascii_lowercase())),
        _ => Err(error(StatusCode::BAD_REQUEST, "invalid_pair")),
    }
}

/// Start, stop or restart one tunnel. Answers when the action is done; after a start it also
/// says whether the tunnel came up and stayed up.
async fn act(
    State(state): State<Arc<AppState>>,
    Path((name, action)): Path<(String, String)>,
    request: Request,
) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let Some((action, paired)) = action_route(&action) else {
        return error(StatusCode::NOT_FOUND, "unknown_action");
    };
    if !tunnel_names(&state).await.contains(&name) {
        return error(StatusCode::NOT_FOUND, "unknown_tunnel");
    }
    let expected_pair = match action_pair_guard(request).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if expected_pair.is_some() != paired {
        return error(StatusCode::BAD_REQUEST, "invalid_pair");
    }
    let Some(busy) = Busy::take(&state, vec![name.clone()]) else {
        return error(StatusCode::CONFLICT, "busy");
    };
    let word = ops::action_word(action);
    state.audit.record(ip, "action", &format!("{word} {name}"));
    let ops = state.ops.clone();
    let task_name = name.clone();
    // The guard moves into the task: a request that times out keeps the tunnel marked busy
    // until the action really ends.
    let task = tokio::task::spawn_blocking(move || {
        let _busy = busy;
        match expected_pair {
            Some(pair) => ops.act_pair(&task_name, action, &pair),
            None => ops.act(&task_name, action),
        }
    });
    let answer = tokio::time::timeout(ACTION_TIMEOUT, task).await;
    state.live.refresh();
    match answer {
        Ok(Ok(Ok(outcome))) => {
            if outcome.came_up == Some(false) {
                state.audit.record(ip, "action_result", &format!("{word} {name}: did not stay up"));
            }
            Json(json!({"ok": true, "changed": outcome.changed, "came_up": outcome.came_up})).into_response()
        }
        Ok(Ok(Err(failure))) => {
            let detail = format!("{failure:#}");
            state.audit.record(ip, "action_failed", &format!("{word} {name}: {detail}"));
            failure_response(&failure, StatusCode::INTERNAL_SERVER_ERROR)
        }
        Ok(Err(_)) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "timeout"),
    }
}

/// Restarts every tunnel, one after another, as the terminal manager's "Restart all" does.
async fn restart_all(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let names = tunnel_names(&state).await;
    let Some(busy) = Busy::take(&state, vec![ALL.to_string()]) else {
        return error(StatusCode::CONFLICT, "busy");
    };
    state.audit.record(ip, "action", &format!("restart all ({} tunnels)", names.len()));
    let ops = state.ops.clone();
    let live = state.live.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _busy = busy;
        names
            .iter()
            .map(|name| {
                let result = ops.act(name, crate::manager::bulk::Action::Restart);
                live.refresh();
                match result {
                    Ok(outcome) => json!({"name": name, "ok": true, "came_up": outcome.came_up}),
                    Err(failure) => json!({"name": name, "ok": false, "detail": format!("{failure:#}")}),
                }
            })
            .collect::<Vec<_>>()
    });
    match tokio::time::timeout(ALL_TIMEOUT, task).await {
        Ok(Ok(results)) => {
            let failed = results
                .iter()
                .filter(|r| r["ok"] != true || r["came_up"] == false)
                .count();
            state.audit.record(ip, "action_result", &format!("restart all: {failed} not up"));
            Json(json!({"ok": failed == 0, "results": results})).into_response()
        }
        Ok(Err(_)) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "timeout"),
    }
}

#[derive(Deserialize)]
struct ActivityQuery {
    #[serde(default = "default_lines")]
    limit: usize,
}

/// The dashboard's own activity (the audit log), newest first: sign-ins, actions, certificates.
async fn activity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ActivityQuery>,
) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    let reader = state.clone();
    match tokio::task::spawn_blocking(move || reader.audit.recent(query.limit)).await {
        Ok(events) => Json(json!({"events": events})).into_response(),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
    }
}

/// Where a followed log continues: the browser's `Last-Event-ID` after a reconnect, else the
/// cursor the log's tail ended at (`?after=`).
#[derive(Deserialize)]
struct FollowQuery {
    after: Option<String>,
}

fn resume_cursor(headers: &HeaderMap, query: FollowQuery) -> Option<String> {
    headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or(query.after)
        .filter(|c| ops::cursor_ok(c))
}

#[derive(Deserialize)]
struct LogsQuery {
    #[serde(default = "default_lines")]
    lines: usize,
}

fn default_lines() -> usize {
    200
}

/// The last lines of a tunnel's log.
async fn logs(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(query): Query<LogsQuery>,
) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    if !tunnel_names(&state).await.contains(&name) {
        return error(StatusCode::NOT_FOUND, "unknown_tunnel");
    }
    let ops = state.ops.clone();
    let lines = query.lines.min(ops::MAX_LINES);
    match tokio::task::spawn_blocking(move || ops.logs(&name, lines)).await {
        Ok(Ok(tail)) => Json(tail).into_response(),
        _ => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
    }
}

/// A tunnel's log as it is written, one event per line. Ends when the browser goes away, the
/// session ends or the log does.
async fn follow(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(query): Query<FollowQuery>,
) -> Response {
    let Some(token) = state.token(&headers).filter(|t| state.auth.check(t)) else {
        return unauthorized();
    };
    if !tunnel_names(&state).await.contains(&name) {
        return error(StatusCode::NOT_FOUND, "unknown_tunnel");
    }
    let Ok(permit) = state.followers.clone().try_acquire_owned() else {
        return error(StatusCode::TOO_MANY_REQUESTS, "too_many");
    };
    let Ok(log) = state.ops.follow(&name, resume_cursor(&headers, query)) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "failed");
    };
    sse_lines(state, token, permit, LineSource::Local(log))
}

/// The script a join command runs (not secret: the code is given to it on the command line).
async fn join_script() -> Response {
    let mut response = include_str!("join.sh").into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

/// The command shown for a join code. It downloads the join script from this dashboard and pins
/// the key of the certificate it serves now, so the script cannot be swapped on the way, even with
/// a self-signed certificate. A Let's Encrypt key changes every few days, but a code only lives
/// for ten minutes.
fn join_command(public: &(String, u16), cert: Option<&super::tls::Swap>, code: &str) -> String {
    let (host, port) = public;
    let host = if host.contains(':') { format!("[{host}]") } else { host.clone() };
    let pin = cert
        .and_then(|swap| swap.current().cert.first().cloned())
        .and_then(|leaf| super::tls::public_key_pin(&leaf).ok());
    // The script runs only when it arrived whole: a failed download stops the command with
    // curl's error instead of running nothing and reporting success.
    match pin {
        Some(pin) => format!("s=$(curl -fsSLk --pinnedpubkey 'sha256//{pin}' https://{host}:{port}/join.sh) && bash -c \"$s\" join.sh {code}"),
        None => format!("s=$(curl -fsSL http://{host}:{port}/join.sh) && bash -c \"$s\" join.sh {code}"),
    }
}

/// Where an agent switches its HTTPS connection to the agent link. Anyone may ask; only the link's
/// handshake (a registered key, or a valid one-time join code) admits a server.
async fn agent_link(State(state): State<Arc<AppState>>, mut request: Request) -> Response {
    let Some(fleet) = state.fleet.clone() else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    let wanted = request
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case(super::link::UPGRADE));
    if !wanted {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    }
    let Ok(slot) = state.agent_slots.clone().try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "busy");
    };
    let Some(upgrade) = request.extensions_mut().remove::<hyper::upgrade::OnUpgrade>() else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let ip = client_ip(&request);
    let events = state.clone();
    tokio::spawn(async move {
        let _slot = slot;
        if let Ok(upgraded) = upgrade.await {
            let io = hyper_util::rt::TokioIo::new(upgraded);
            let _ = fleet.serve(io, |event, detail| events.audit.record(ip, event, &detail)).await;
        }
    });
    let mut response = StatusCode::SWITCHING_PROTOCOLS.into_response();
    response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    response.headers_mut().insert(header::UPGRADE, HeaderValue::from_static(super::link::UPGRADE));
    response
}

/// Sample servers for the demo: one online with tunnels, one that stopped answering.
fn demo_servers(local: Option<&super::data::Snapshot>) -> Vec<serde_json::Value> {
    let now = super::now();
    let mut online = local.map(|s| serde_json::to_value(s).unwrap_or_default()).unwrap_or_default();
    if let Some(snapshot) = online.as_object_mut() {
        snapshot.insert("host".into(), json!({"hostname": "frankfurt-1", "address": "198.51.100.20", "cores": 8, "cpu_pct": 23.0, "mem_pct": 37.0, "disk_pct": 22.0, "uptime_sec": 3_888_000}));
        if let Some(tunnels) = snapshot.get_mut("tunnels").and_then(|t| t.as_array_mut()) {
            // Two of the samples, plus tunnels made with the demo's new-tunnel form.
            let samples = ["game-fec", "web-wss", "cdn-xhttps", "backup-tcp"];
            let mut kept = 0;
            tunnels.retain(|t| {
                let sample = samples.contains(&t["name"].as_str().unwrap_or(""));
                kept += usize::from(sample);
                !sample || kept <= 2
            });
            for tunnel in tunnels.iter_mut() {
                tunnel["side"] = json!("foreign");
            }
        }
        snapshot.insert("issues".into(), json!([]));
    }
    vec![
        json!({"id": "a1b2c3d4e5f6", "name": "frankfurt-1", "added": now - 9 * 86_400, "online": true, "last_seen": now,
               "hello": {"version": env!("CARGO_PKG_VERSION"), "arch": "x86_64", "host": "frankfurt-1"}, "snapshot": online}),
        json!({"id": "0f9e8d7c6b5a", "name": "mashhad-1", "added": now - 30 * 86_400, "online": false, "last_seen": now - 3 * 3600,
               "hello": {"version": "0.9.14", "arch": "aarch64", "host": "mashhad-1"}, "snapshot": null}),
    ]
}

/// The other servers, each with its latest snapshot.
async fn servers(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    let list = match &state.fleet {
        Some(fleet) => fleet.servers(),
        None => demo_servers(state.live.latest().as_deref()),
    };
    let local_name = super::prefs::load(&state.state_dir).server_name;
    Json(json!({"servers": list, "offline_after": super::fleet::OFFLINE_AFTER, "local_name": local_name})).into_response()
}

/// A display name typed on the dashboard: trimmed, 1..=40 characters of letters, digits, spaces
/// and `-_.()#`. Empty means "go back to the server's own name". Anything else is refused, so a
/// name is safe in alerts, metrics labels and the page.
fn server_label(text: &str) -> Result<Option<String>, ()> {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        return Ok(None);
    }
    let fine = text.chars().count() <= 40 && text.chars().all(|c| c.is_alphanumeric() || c == ' ' || "-_.()#".contains(c));
    if fine { Ok(Some(text)) } else { Err(()) }
}

/// The name this server is shown under: the one set on the dashboard, else its hostname.
fn local_name(state: &AppState, hostname: &str) -> String {
    super::prefs::load(&state.state_dir).server_name.unwrap_or_else(|| hostname.to_string())
}

/// Renames a server on the dashboard (`local` is this server). Only the display name changes:
/// the server's hostname, id and tunnels are not touched.
async fn server_rename(State(state): State<Arc<AppState>>, Path(id): Path<String>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let Ok(body) = axum::body::to_bytes(request.into_body(), 4096).await else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let Some(given) = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["name"].as_str().map(str::to_string)) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let Ok(label) = server_label(&given) else {
        return error(StatusCode::BAD_REQUEST, "bad_name");
    };
    let shown = label.clone().unwrap_or_default();
    if id == "local" {
        let saved = super::prefs::change_and_save(&state.state_dir, |prefs| {
            prefs.server_name = label.clone();
            Ok(None)
        });
        if saved.is_err() {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "failed");
        }
    } else {
        let Some(fleet) = &state.fleet else {
            return Json(json!({"ok": true, "name": label})).into_response();
        };
        match fleet.rename(&id, label.clone()) {
            Ok(true) => {}
            Ok(false) => return error(StatusCode::NOT_FOUND, "unknown_server"),
            Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
        }
    }
    let detail = if shown.is_empty() { format!("{id}: back to its own name") } else { format!("{id}: {shown}") };
    state.audit.record(ip, "server_renamed", &detail);
    Json(json!({"ok": true, "name": label})).into_response()
}

/// A one-time join command for another server.
async fn join_code(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let (code, expires) = match &state.fleet {
        Some(fleet) => match fleet.join_code(&state.public.0, state.public.1) {
            Ok(made) => made,
            Err(failure) => return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "failed", "detail": format!("{failure:#}")}))).into_response(),
        },
        // The demo shows the shape of a code; it admits nothing.
        None => (
            super::link::JoinCode { host: state.public.0.clone(), port: state.public.1, hub_key: [7; 32], token: [3; 16] }.encode(),
            super::now() + super::fleet::JOIN_VALID.as_secs(),
        ),
    };
    state.audit.record(ip, "join_code", "created a join command");
    let command = join_command(&state.public, state.cert.as_deref(), &code);
    Json(json!({"code": code, "command": command, "expires": expires})).into_response()
}

async fn remove_server(State(state): State<Arc<AppState>>, Path(id): Path<String>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let Some(fleet) = &state.fleet else {
        return Json(json!({"ok": true})).into_response();
    };
    match fleet.remove(&id) {
        Ok(true) => {
            state.audit.record(client_ip(&request), "server_removed", &id);
            Json(json!({"ok": true})).into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, "unknown_server"),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
    }
}

/// Start, stop or restart a tunnel on another server.
async fn server_act(
    State(state): State<Arc<AppState>>,
    Path((id, name, action)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let Some((action, paired)) = action_route(&action) else {
        return error(StatusCode::NOT_FOUND, "unknown_action");
    };
    let expected_pair = match action_pair_guard(request).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if expected_pair.is_some() != paired {
        return error(StatusCode::BAD_REQUEST, "invalid_pair");
    }
    let Some(fleet) = state.fleet.clone() else {
        if expected_pair.is_some() {
            return error(StatusCode::BAD_GATEWAY, "remote_offline");
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
        return Json(json!({"ok": true, "changed": true, "came_up": (action != crate::manager::bulk::Action::Stop).then_some(true)})).into_response();
    };
    if state.busy.lock().unwrap().contains(&format!("{id}/*")) {
        return error(StatusCode::CONFLICT, "busy");
    }
    let Some(busy) = Busy::take(&state, vec![format!("{id}/{name}")]) else {
        return error(StatusCode::CONFLICT, "busy");
    };
    let word = ops::action_word(action);
    state.audit.record(ip, "action", &format!("{word} {name} on {id}"));
    let answer = fleet.request_held(&id,
        json!({"op": if expected_pair.is_some() { "act_pair" } else { "act" },
            "name": name, "action": word, "expect_pair": expected_pair}),
        ACTION_TIMEOUT, busy.clone()).await;
    drop(busy);
    match answer {
        Ok(outcome) => Json(json!({"ok": true, "changed": outcome["changed"], "came_up": outcome["came_up"]})).into_response(),
        Err(failure) => {
            let detail = format!("{failure:#}");
            state.audit.record(ip, "action_failed", &format!("{word} {name} on {id}: {detail}"));
            failure_response(&failure, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Where an edit runs: this server's operations, or a joined server through its agent.
async fn run_edit(state: &Arc<AppState>, server: &str, name: &str, request: Value) -> Result<Value> {
    if server == "local" {
        let ops = state.ops.clone();
        let name = name.to_string();
        return tokio::task::spawn_blocking(move || -> Result<Value> {
            Ok(match request["op"].as_str() {
                Some("editable") => ops.editable(&name)?,
                Some("edit") => serde_json::to_value(ops.edit(&name, &request["changes"])?)?,
                _ => serde_json::to_value(ops.undo(&name)?)?,
            })
        })
        .await?;
    }
    let fleet = state.fleet.clone().ok_or_else(|| anyhow::anyhow!("no such server"))?;
    let mut request = request;
    request["name"] = json!(name);
    fleet.request(server, request, ACTION_TIMEOUT * 2).await
}

async fn editable_answer(state: Arc<AppState>, server: String, name: String, headers: &HeaderMap) -> Response {
    if !state.signed_in(headers) {
        return unauthorized();
    }
    match run_edit(&state, &server, &name, json!({"op": "editable"})).await {
        Ok(screen) => Json(screen).into_response(),
        Err(failure) => failure_response(&failure, StatusCode::BAD_REQUEST),
    }
}

/// Saves changed settings (`undo`: goes back one version) and reports what happened.
async fn change_answer(state: Arc<AppState>, server: String, name: String, request: Request, undo: bool) -> Response {
    tokio::spawn(change_answer_owned(state, server, name, request, undo)).await.unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "failed"))
}

async fn change_answer_owned(state: Arc<AppState>, server: String, name: String, request: Request, undo: bool) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let changes = if undo {
        Value::Null
    } else {
        let bytes = match read_body(request, MAX_BODY).await { Ok(bytes) => bytes, Err(response) => return response };
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(changes) if changes.is_object() => changes,
            _ => return error(StatusCode::BAD_REQUEST, "bad_request"),
        }
    };
    let key = if server == "local" { name.clone() } else { format!("{server}/{name}") };
    if state.busy.lock().unwrap().contains(&format!("{server}/*")) {
        return error(StatusCode::CONFLICT, "busy");
    }
    let Some(busy) = Busy::take(&state, vec![key]) else {
        return error(StatusCode::CONFLICT, "busy");
    };
    let what = if undo { "undo" } else { "edit" };
    let place = if server == "local" { String::new() } else { format!(" on {server}") };
    let parts: Vec<&str> = ["ports", "quota", "settings"].into_iter().filter(|k| !changes[*k].is_null()).collect();
    state.audit.record(ip, "action", &format!("{what} {name}{place} {}", parts.join(", ")));
    let request = if undo { json!({"op": "undo"}) } else { json!({"op": "edit", "changes": changes}) };
    let mut request = request;
    request["name"] = json!(name);
    let answer = run_on_held(&state, &server, request, ACTION_TIMEOUT * 2, Some(busy.clone())).await;
    drop(busy);
    state.live.refresh();
    match answer {
        Ok(outcome) => {
            if outcome["reverted"] == true || outcome["came_up"] == false {
                state.audit.record(ip, "action_result", &format!("{what} {name}{place}: reverted={} up={}", outcome["reverted"], outcome["came_up"]));
            }
            Json(outcome).into_response()
        }
        Err(failure) => {
            let detail = format!("{failure:#}");
            state.audit.record(ip, "action_failed", &format!("{what} {name}{place}: {detail}"));
            failure_response(&failure, StatusCode::BAD_REQUEST)
        }
    }
}

async fn local_editable(State(state): State<Arc<AppState>>, Path(name): Path<String>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) { return unauthorized(); }
    if !tunnel_names(&state).await.contains(&name) {
        return error(StatusCode::NOT_FOUND, "unknown_tunnel");
    }
    editable_answer(state, "local".into(), name, &headers).await
}

async fn local_edit(State(state): State<Arc<AppState>>, Path(name): Path<String>, request: Request) -> Response {
    if !state.signed_in(request.headers()) { return unauthorized(); }
    if !tunnel_names(&state).await.contains(&name) {
        return error(StatusCode::NOT_FOUND, "unknown_tunnel");
    }
    change_answer(state, "local".into(), name, request, false).await
}

async fn local_undo(State(state): State<Arc<AppState>>, Path(name): Path<String>, request: Request) -> Response {
    if !state.signed_in(request.headers()) { return unauthorized(); }
    if !tunnel_names(&state).await.contains(&name) {
        return error(StatusCode::NOT_FOUND, "unknown_tunnel");
    }
    change_answer(state, "local".into(), name, request, true).await
}

async fn server_editable(State(state): State<Arc<AppState>>, Path((id, name)): Path<(String, String)>, headers: HeaderMap) -> Response {
    if state.fleet.is_none() {
        return editable_answer(state, "local".into(), name, &headers).await;
    }
    editable_answer(state, id, name, &headers).await
}

async fn server_edit(State(state): State<Arc<AppState>>, Path((id, name)): Path<(String, String)>, request: Request) -> Response {
    let id = if state.fleet.is_none() { "local".to_string() } else { id };
    change_answer(state, id, name, request, false).await
}

async fn server_undo(State(state): State<Arc<AppState>>, Path((id, name)): Path<(String, String)>, request: Request) -> Response {
    let id = if state.fleet.is_none() { "local".to_string() } else { id };
    change_answer(state, id, name, request, true).await
}

/// Runs one request of the fixed list on this server (`local`) or a joined one.
async fn run_on(state: &Arc<AppState>, server: &str, request: Value, timeout: Duration) -> Result<Value> {
    run_on_held(state, server, request, timeout, None).await
}

async fn run_on_held(state: &Arc<AppState>, server: &str, request: Value, timeout: Duration, busy: Option<Arc<Busy>>) -> Result<Value> {
    if server == "local" {
        let ops = state.ops.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _busy = busy;
            ops::answer(&*ops, &request)
        });
        return match tokio::time::timeout(timeout, task).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(anyhow::anyhow!("the task stopped")),
            Err(_) => Err(anyhow::anyhow!("no answer in time")),
        };
    }
    let fleet = state.fleet.clone().ok_or_else(|| anyhow::anyhow!("no such server"))?;
    match busy {
        Some(busy) => fleet.request_held(server, request, timeout, busy).await,
        None => fleet.request(server, request, timeout).await,
    }
}

/// Without joined servers (the demo), a server path means this server.
fn place_of(state: &AppState, id: String) -> String {
    if state.fleet.is_none() { "local".into() } else { id }
}

/// A tunnel's own figures from its control socket.
async fn status_answer(state: Arc<AppState>, server: String, name: String, headers: &HeaderMap) -> Response {
    if !state.signed_in(headers) {
        return unauthorized();
    }
    if server == "local" && !tunnel_names(&state).await.contains(&name) {
        return error(StatusCode::NOT_FOUND, "unknown_tunnel");
    }
    match run_on(&state, &server, json!({"op": "status", "name": name}), Duration::from_secs(10)).await {
        Ok(status) => Json(status).into_response(),
        Err(failure) => failure_response(&failure, StatusCode::BAD_REQUEST),
    }
}

async fn local_status(State(state): State<Arc<AppState>>, Path(name): Path<String>, headers: HeaderMap) -> Response {
    status_answer(state, "local".into(), name, &headers).await
}

async fn server_status(State(state): State<Arc<AppState>>, Path((id, name)): Path<(String, String)>, headers: HeaderMap) -> Response {
    let server = place_of(&state, id);
    status_answer(state, server, name, &headers).await
}

/// The per-tunnel tools: `speedtest` ({direction, bytes, streams}), `pairing` ({address}) and
/// `quota_reset`. The pairing code holds the tunnel key, so showing it is written to the audit log.
async fn tool_answer(state: Arc<AppState>, server: String, name: String, op: String, request: Request) -> Response {
    tokio::spawn(tool_answer_owned(state, server, name, op, request)).await.unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "failed"))
}

async fn tool_answer_owned(state: Arc<AppState>, server: String, name: String, op: String, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    if !["speedtest", "pairing", "quota_reset"].contains(&op.as_str()) {
        return error(StatusCode::NOT_FOUND, "unknown_tool");
    }
    if server == "local" && !tunnel_names(&state).await.contains(&name) {
        return error(StatusCode::NOT_FOUND, "unknown_tunnel");
    }
    let bytes = match read_body(request, MAX_BODY).await { Ok(bytes) => bytes, Err(response) => return response };
    let body: Value = if bytes.is_empty() { json!({}) } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
    if !body.is_object() {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    }
    let key = if server == "local" { name.clone() } else { format!("{server}/{name}") };
    // Reading the pairing code changes nothing; the other tools hold the tunnel.
    let busy = if op == "pairing" {
        None
    } else {
        if server != "local" && state.busy.lock().unwrap().contains(&format!("{server}/*")) {
            return error(StatusCode::CONFLICT, "busy");
        }
        match Busy::take(&state, vec![key]) {
            Some(busy) => Some(busy),
            None => return error(StatusCode::CONFLICT, "busy"),
        }
    };
    let place = if server == "local" { String::new() } else { format!(" on {server}") };
    let what = match op.as_str() {
        "speedtest" => "speed test",
        "pairing" => "pairing code",
        _ => "traffic count reset",
    };
    let mut request = body;
    request["op"] = json!(op);
    request["name"] = json!(name);
    if op != "pairing" || request["address"].as_str().is_some_and(|a| !a.trim().is_empty()) {
        state.audit.record(ip, "action", &format!("{what} {name}{place}"));
    }
    let timeout = if op == "speedtest" { Duration::from_secs(150) } else { ACTION_TIMEOUT };
    let answer = run_on_held(&state, &server, request, timeout, busy.clone()).await;
    drop(busy);
    if op == "quota_reset" {
        state.live.refresh();
    }
    match answer {
        Ok(answer) => Json(answer).into_response(),
        Err(failure) => {
            let detail = format!("{failure:#}");
            state.audit.record(ip, "action_failed", &format!("{what} {name}{place}: {detail}"));
            failure_response(&failure, StatusCode::BAD_REQUEST)
        }
    }
}

async fn local_tool(State(state): State<Arc<AppState>>, Path((name, op)): Path<(String, String)>, request: Request) -> Response {
    tool_answer(state, "local".into(), name, op, request).await
}

async fn server_tool(State(state): State<Arc<AppState>>, Path((id, name, op)): Path<(String, String, String)>, request: Request) -> Response {
    let server = place_of(&state, id);
    tool_answer(state, server, name, op, request).await
}

/// A server path: `local` is always this server; without joined servers (the demo) every id is.
fn server_of(state: &AppState, id: String) -> String {
    if id == "local" || state.fleet.is_none() { "local".into() } else { id }
}

/// Server tools: `health`, `optimize_plan` and `files` read; `fix`, `optimize_apply` and
/// `optimize_undo` change the server and are written to the audit log.
async fn server_tool_answer(State(state): State<Arc<AppState>>, Path((id, tool)): Path<(String, String)>, request: Request) -> Response {
    tokio::spawn(server_tool_answer_owned(State(state), Path((id, tool)), request)).await.unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "failed"))
}

async fn server_tool_answer_owned(State(state): State<Arc<AppState>>, Path((id, tool)): Path<(String, String)>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let server = server_of(&state, id);
    let changes = match tool.as_str() {
        "health" | "optimize_plan" | "files" | "versions" => false,
        "fix" | "optimize_apply" | "optimize_undo" | "rollback" => true,
        _ => return error(StatusCode::NOT_FOUND, "unknown_tool"),
    };
    let bytes = match read_body(request, MAX_BODY).await { Ok(bytes) => bytes, Err(response) => return response };
    let body: Value = if bytes.is_empty() { json!({}) } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
    if !body.is_object() {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    }
    let busy = if changes {
        let all = if server == "local" { ALL.to_string() } else { format!("{server}/*") };
        match Busy::take(&state, vec![all]) {
            Some(busy) => Some(busy),
            None => return error(StatusCode::CONFLICT, "busy"),
        }
    } else {
        None
    };
    let place = if server == "local" { String::new() } else { format!(" on {server}") };
    let what = match tool.as_str() {
        "fix" => format!("fix {}", body["fix"].as_str().unwrap_or("")),
        "optimize_apply" => "optimize the kernel settings".into(),
        "rollback" => "roll back the program".into(),
        _ => "undo the kernel optimization".into(),
    };
    if changes {
        state.audit.record(ip, "action", &format!("{what}{place}"));
    }
    let mut request = body;
    request["op"] = json!("server");
    request["tool"] = json!(tool);
    let answer = run_on_held(&state, &server, request, Duration::from_secs(90), busy.clone()).await;
    drop(busy);
    if changes {
        state.live.refresh();
    }
    match answer {
        Ok(answer) => Json(answer).into_response(),
        Err(failure) => {
            let detail = format!("{failure:#}");
            if changes {
                state.audit.record(ip, "action_failed", &format!("{what}{place}: {detail}"));
            }
            failure_response(&failure, StatusCode::BAD_REQUEST)
        }
    }
}

/// Every server's problems right now, for the alert engine.
fn current_problems(state: &AppState) -> Vec<super::alerts::Problem> {
    use super::alerts::{Problem, problems_of};
    let mut found = Vec::new();
    if let Some(snapshot) = state.live.latest() {
        let value = serde_json::to_value(&*snapshot).unwrap_or_default();
        let name = local_name(state, value["host"]["hostname"].as_str().unwrap_or("this server"));
        found.extend(problems_of("local", &name, &value));
    }
    let servers = match &state.fleet {
        Some(fleet) => fleet.servers(),
        None => demo_servers(state.live.latest().as_deref()),
    };
    for server in servers {
        let id = server["id"].as_str().unwrap_or("");
        let name = server["name"].as_str().unwrap_or(id);
        if server["online"] == true {
            found.extend(problems_of(id, name, &server["snapshot"]));
        } else {
            found.push(Problem::new(id, name, "offline", "", "bad", None));
        }
    }
    if let Some(cert) = &state.cert
        && let Some(left) = cert.not_after().map(|end| end.saturating_sub(super::now()))
        // Short-lived certificates are renewed with about two days left, so only a renewal that
        // did not happen gets this close.
        && left < 36 * 3600
    {
        found.push(Problem::new("local", "dashboard", "cert", "", if left < 12 * 3600 { "bad" } else { "warn" }, Some((left / 3600) as f64)));
    }
    found
}

/// One look of the alert engine: records what fired or cleared and tells Telegram.
pub(super) async fn alert_look(state: &Arc<AppState>) {
    let now = super::now();
    let problems = current_problems(state);
    // Connected, but no snapshot since: nothing is known about its tunnels yet.
    let unseen: Vec<String> = state
        .fleet
        .as_ref()
        .map(|fleet| {
            fleet
                .servers()
                .into_iter()
                .filter(|s| s["online"] == true && s["snapshot"].is_null())
                .filter_map(|s| s["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let changes = state.alerts.lock().unwrap().look_with(problems, now, &unseen);
    if changes.fired.is_empty() && changes.escalated.is_empty() && changes.cleared.is_empty() {
        return;
    }
    if let Err(failure) = super::alerts::record(&state.state_dir, &changes, now) {
        eprintln!("alert history: {failure:#}");
    }
    let prefs = super::prefs::load(&state.state_dir);
    let mut messages = Vec::new();
    for active in changes.fired.iter().chain(&changes.escalated) {
        if super::alerts::wanted(&prefs, &active.problem, false) {
            messages.push(super::alerts::message(&prefs.telegram.lang, &active.problem, None));
        }
    }
    for (active, lasted) in &changes.cleared {
        if super::alerts::wanted(&prefs, &active.problem, true) {
            messages.push(super::alerts::message(&prefs.telegram.lang, &active.problem, Some(*lasted)));
        }
    }
    if messages.is_empty() || state.demo {
        return;
    }
    let reporter = state.clone();
    tokio::task::spawn_blocking(move || {
        let text = messages.join("\n\n");
        let result = super::alerts::send_telegram(&prefs.telegram, prefs.proxy.as_deref(), &text);
        super::alerts::record_delivery(&reporter.state_dir, "alert", &result);
        if let Err(failure) = result {
            reporter.audit.record(None, "action_failed", &format!("Telegram alert: {failure:#}"));
        }
    });
}

pub async fn alert_loop(state: Arc<AppState>) {
    // Give agents time to connect before their absence counts.
    tokio::time::sleep(Duration::from_secs(60)).await;
    loop {
        alert_look(&state).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

async fn alerts_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    let active = state.alerts.lock().unwrap().active();
    Json(json!({"active": active, "history": super::alerts::history(&state.state_dir, 300)})).into_response()
}

/// Sends a test message with the saved Telegram settings, or with the form's unsaved token, chats
/// and language when the body carries them (`{"telegram": {...}}`), so a setup can be tried first.
async fn alerts_test(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let body = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    state.audit.record(ip, "action", "send a Telegram test message");
    let mut prefs = super::prefs::load(&state.state_dir);
    if let Some(form) = body.get("telegram").filter(|v| v.is_object()) {
        let mut form = form.clone();
        if let Some(fields) = form.as_object_mut() {
            fields.remove("enabled");
        }
        prefs.telegram.enabled = false;
        if let Err(failure) = super::prefs::change(&mut prefs, &json!({"telegram": form})) {
            return failed_with(StatusCode::BAD_REQUEST, format!("{failure:#}"));
        }
    }
    if state.demo {
        return failed_with(StatusCode::BAD_REQUEST, "the demo sends nothing");
    }
    let text = super::alerts::test_message(&prefs.telegram.lang);
    let dir = state.state_dir.clone();
    match tokio::task::spawn_blocking(move || {
        let result = super::alerts::send_telegram(&prefs.telegram, prefs.proxy.as_deref(), &text);
        super::alerts::record_delivery(&dir, "test", &result);
        result
    })
    .await
    {
        Ok(Ok(())) => Json(json!({"ok": true})).into_response(),
        Ok(Err(failure)) => failed_with(StatusCode::BAD_GATEWAY, format!("{failure:#}")),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
    }
}

/// The Settings screen: the dashboard's preferences and how it is reached.
async fn settings_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    let prefs = super::prefs::load(&state.state_dir);
    let cert = state.cert.as_ref().map(|c| json!({"not_after": c.not_after(), "lets_encrypt": state.state_dir.join("acme-chain.pem").exists()}));
    Json(json!({
        "prefs": super::prefs::shown(&prefs),
        "telegram_last": super::alerts::last_delivery(&state.state_dir),
        "panel": {"address": state.public.0, "port": state.public.1, "https": state.secure, "cert": cert, "version": env!("CARGO_PKG_VERSION"), "state_dir": state.state_dir.display().to_string()},
    }))
    .into_response()
}

async fn settings_set(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let body = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let mut invalid = false;
    let (prefs, created) = match super::prefs::change_and_save(&state.state_dir, |prefs| {
        super::prefs::change(prefs, &body).inspect_err(|_| invalid = true)
    }) {
        Ok(result) => result,
        Err(failure) => return failed_with(if invalid { StatusCode::BAD_REQUEST } else { StatusCode::INTERNAL_SERVER_ERROR }, format!("{failure:#}")),
    };
    let parts: Vec<&str> = ["auto_backup_days", "proxy", "telegram", "metrics"].into_iter().filter(|k| body.get(*k).is_some()).collect();
    state.audit.record(ip, "action", &format!("change settings: {}", parts.join(", ")));
    Json(json!({"prefs": super::prefs::shown(&prefs), "metrics_token": created})).into_response()
}

async fn password_set(State(state): State<Arc<AppState>>, request: Request) -> Response {
    tokio::spawn(password_set_owned(State(state), request)).await.unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "failed"))
}

async fn password_set_owned(State(state): State<Arc<AppState>>, request: Request) -> Response {
    static CHANGE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let Some(token) = state.token(request.headers()).filter(|t| state.auth.check(t)) else {
        return unauthorized();
    };
    let ip = client_ip(&request);
    let body = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let _change = CHANGE.lock().await;
    let current = body["current"].as_str().unwrap_or("").to_string();
    let new = body["new"].as_str().unwrap_or("").to_string();
    match state.auth.change_password(&token, current, new).await {
        Ok(hash) => {
            if !state.demo && let Err(failure) = super::save_password_hash(&state.state_dir, &hash) {
                return failed_with(StatusCode::INTERNAL_SERVER_ERROR, format!("the new password works until a restart, but saving it failed: {failure:#}"));
            }
            state.audit.record(ip, "action", "changed the password; other sessions ended");
            Json(json!({"ok": true})).into_response()
        }
        Err(failure) => {
            state.audit.record(ip, "action_failed", &format!("change the password: {failure:#}"));
            failed_with(StatusCode::BAD_REQUEST, format!("{failure:#}"))
        }
    }
}

async fn sessions_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(token) = state.token(&headers).filter(|t| state.auth.check(t)) else {
        return unauthorized();
    };
    Json(json!({"sessions": state.auth.sessions(&token)})).into_response()
}

async fn sessions_revoke(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let Some(token) = state.token(request.headers()).filter(|t| state.auth.check(t)) else {
        return unauthorized();
    };
    let ip = client_ip(&request);
    let body = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let id = body["id"].as_str().unwrap_or("");
    let ended = state.auth.revoke(id, &token);
    state.audit.record(ip, "action", &format!("ended {ended} session(s)"));
    Json(json!({"ended": ended})).into_response()
}

/// Metrics for an external monitor; on only when a token is set, and only with that token.
async fn metrics(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(token) = super::prefs::load(&state.state_dir).metrics_token else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    let given = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    use sha2::{Digest, Sha256};
    if Sha256::digest(given.as_bytes()) != Sha256::digest(token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")], "").into_response();
    }
    let mut servers = Vec::new();
    if let Some(snapshot) = state.live.latest() {
        let value = serde_json::to_value(&*snapshot).unwrap_or_default();
        let name = local_name(&state, value["host"]["hostname"].as_str().unwrap_or(""));
        servers.push(("local".to_string(), name, value));
    }
    if let Some(fleet) = &state.fleet {
        for server in fleet.servers().into_iter().filter(|s| s["online"] == true) {
            servers.push((server["id"].as_str().unwrap_or("").into(), server["name"].as_str().unwrap_or("").into(), server["snapshot"].clone()));
        }
    }
    let active = state.alerts.lock().unwrap().active().len();
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], super::alerts::metrics(&servers, active)).into_response()
}

fn releases_dir(state: &AppState) -> std::path::PathBuf {
    state.state_dir.join("releases")
}

fn backups_dir(state: &AppState) -> std::path::PathBuf {
    state.state_dir.join("backups")
}

fn failed_with(status: StatusCode, failure: impl std::fmt::Display) -> Response {
    (status, Json(json!({"error": "failed", "detail": failure.to_string()}))).into_response()
}

async fn read_json(request: Request) -> Result<Value, Response> {
    let bytes = read_body(request, MAX_BODY).await?;
    let body: Value = if bytes.is_empty() { json!({}) } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
    if body.is_object() { Ok(body) } else { Err(error(StatusCode::BAD_REQUEST, "bad_request")) }
}

/// Program files kept on this server for installing.
async fn releases(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    Json(json!({"kept": super::maintain::kept(&releases_dir(&state)), "running": env!("CARGO_PKG_VERSION")})).into_response()
}

/// The newest official release and its notes.
async fn release_check(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    if state.demo {
        return Json(json!({"version": "0.9.15", "published": "2026-11-20T10:00:00Z", "url": null,
            "notes": "### Changes\n- Sample release notes for the demo."})).into_response();
    }
    let proxy = super::prefs::load(&state.state_dir).proxy;
    match tokio::task::spawn_blocking(move || super::maintain::latest(proxy.as_deref())).await {
        Ok(Ok(latest)) => Json(latest).into_response(),
        Ok(Err(failure)) => failed_with(StatusCode::BAD_GATEWAY, format!("{failure:#}")),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
    }
}

/// Downloads and checks an official release for one CPU type.
async fn release_fetch(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let body = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let version = body["version"].as_str().unwrap_or("latest").to_string();
    let arch = body["arch"].as_str().unwrap_or("x86_64").to_string();
    state.audit.record(ip, "action", &format!("download release {version} for {arch}"));
    if state.demo {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        return failed_with(StatusCode::BAD_REQUEST, "the demo downloads nothing");
    }
    let dir = releases_dir(&state);
    let proxy = super::prefs::load(&state.state_dir).proxy;
    match tokio::task::spawn_blocking(move || super::maintain::fetch(&version, &arch, &dir, proxy.as_deref())).await {
        Ok(Ok(kept)) => Json(kept).into_response(),
        Ok(Err(failure)) => {
            state.audit.record(ip, "action_failed", &format!("download release: {failure:#}"));
            failed_with(StatusCode::BAD_GATEWAY, format!("{failure:#}"))
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
    }
}

/// A program file sent from the browser: kept only when it carries the official signature.
async fn release_upload(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let bytes = match read_upload(request, super::maintain::MAX_PROGRAM as usize).await { Ok(bytes) => bytes, Err(response) => return response };
    let dir = releases_dir(&state);
    match tokio::task::spawn_blocking(move || super::maintain::keep(&bytes, &dir)).await {
        Ok(Ok(kept)) => {
            state.audit.record(ip, "action", &format!("uploaded program {}", kept["sha256"].as_str().unwrap_or("")));
            Json(kept).into_response()
        }
        Ok(Err(failure)) => failed_with(StatusCode::BAD_REQUEST, format!("{failure:#}")),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
    }
}

/// Sends a kept program to a server in pieces and has its updater install it.
async fn server_install(State(state): State<Arc<AppState>>, Path(id): Path<String>, request: Request) -> Response {
    tokio::spawn(server_install_owned(State(state), Path(id), request)).await.unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "failed"))
}

async fn server_install_owned(State(state): State<Arc<AppState>>, Path(id): Path<String>, request: Request) -> Response {
    use base64::Engine;
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let server = server_of(&state, id);
    let body = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let file = body["file"].as_str().unwrap_or("").to_string();
    let all = if server == "local" { ALL.to_string() } else { format!("{server}/*") };
    let Some(busy) = Busy::take(&state, vec![all]) else {
        return error(StatusCode::CONFLICT, "busy");
    };
    let place = if server == "local" { "this server".to_string() } else { server.clone() };
    state.audit.record(ip, "action", &format!("install {file} on {place}"));
    let result: Result<Value> = async {
        if state.demo {
            return run_on(&state, &server, json!({"op": "server", "tool": "install"}), Duration::from_secs(30)).await;
        }
        let bytes = super::maintain::read_kept(&releases_dir(&state), &file)?;
        let sum = super::maintain::sha256_hex(&bytes);
        run_on_held(&state, &server, json!({"op": "server", "tool": "receive", "step": "begin", "size": bytes.len(), "sha256": sum}), ACTION_TIMEOUT, Some(busy.clone())).await?;
        for (index, piece) in bytes.chunks(super::maintain::PIECE).enumerate() {
            let data = base64::engine::general_purpose::STANDARD.encode(piece);
            let offset = index * super::maintain::PIECE;
            run_on_held(&state, &server, json!({"op": "server", "tool": "receive", "step": "piece", "offset": offset, "data": data}), ACTION_TIMEOUT, Some(busy.clone())).await?;
        }
        run_on_held(&state, &server, json!({"op": "server", "tool": "install", "allow_downgrade": body["allow_downgrade"] == true}), Duration::from_secs(300), Some(busy.clone())).await
    }
    .await;
    drop(busy);
    state.live.refresh();
    match result {
        Ok(answer) => Json(answer).into_response(),
        Err(failure) => {
            state.audit.record(ip, "action_failed", &format!("install on {place}: {failure:#}"));
            failed_with(StatusCode::BAD_GATEWAY, format!("{failure:#}"))
        }
    }
}

async fn backup_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    let prefs = super::prefs::load(&state.state_dir);
    Json(json!({"backups": super::maintain::backups(&backups_dir(&state)), "auto": prefs.auto_backup_days})).into_response()
}

/// Backs up this server and every joined server that is online now.
pub(super) async fn backup_all(state: &Arc<AppState>) -> Vec<Value> {
    let mut servers = vec!["local".to_string()];
    if let Some(fleet) = &state.fleet {
        servers.extend(fleet.servers().iter().filter(|s| s["online"] == true).filter_map(|s| s["id"].as_str().map(str::to_string)));
    }
    // All at once: the whole backup takes as long as the slowest server, not the sum of all of
    // them, and fits in the time the page waits.
    futures_util::future::join_all(servers.into_iter().map(|server| async move {
        let answer = run_on(state, &server, json!({"op": "server", "tool": "export"}), ACTION_TIMEOUT).await;
        let result = answer.and_then(|answer| save_export(&backups_dir(state), &server, &answer));
        result.unwrap_or_else(|failure| json!({"server": server, "error": format!("{failure:#}")}))
    }))
    .await
}

fn save_export(dir: &std::path::Path, server: &str, answer: &Value) -> Result<Value> {
    let file = super::maintain::save_backup(dir, server, &answer["backup"], 12)?;
    let skipped = answer["skipped"].as_array().cloned().unwrap_or_default();
    let mut result = json!({"server": server, "file": file, "skipped": skipped});
    if !skipped.is_empty() {
        result["error"] = json!("incomplete backup: unreadable tunnel configurations were omitted");
    }
    Ok(result)
}

async fn backup_now(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    state.audit.record(ip, "action", "back up all servers");
    Json(json!({"results": backup_all(&state).await})).into_response()
}

/// A backup file for the browser to save. It holds tunnel keys, so the download is logged.
async fn backup_download(State(state): State<Arc<AppState>>, Path(file): Path<String>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    if !super::maintain::backup_name_ok(&file) {
        return error(StatusCode::NOT_FOUND, "unknown_backup");
    }
    let Ok(bytes) = std::fs::read(backups_dir(&state).join(&file)) else {
        return error(StatusCode::NOT_FOUND, "unknown_backup");
    };
    state.audit.record(client_ip(&request), "action", &format!("download backup {file}"));
    (
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"eztunnel-backup-{file}\"")),
        ],
        bytes,
    )
        .into_response()
}

async fn backup_delete(State(state): State<Arc<AppState>>, Path(file): Path<String>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    if !super::maintain::backup_name_ok(&file) || std::fs::remove_file(backups_dir(&state).join(&file)).is_err() {
        return error(StatusCode::NOT_FOUND, "unknown_backup");
    }
    state.audit.record(client_ip(&request), "action", &format!("delete backup {file}"));
    Json(json!({"ok": true})).into_response()
}

/// Restores tunnels on a server from a kept backup (`file`) or a backup sent along (`text`).
async fn server_restore(State(state): State<Arc<AppState>>, Path(id): Path<String>, request: Request) -> Response {
    tokio::spawn(server_restore_owned(State(state), Path(id), request)).await.unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "failed"))
}

async fn server_restore_owned(State(state): State<Arc<AppState>>, Path(id): Path<String>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let server = server_of(&state, id);
    let bytes = match read_upload(request, 4 << 20).await { Ok(bytes) => bytes, Err(response) => return response };
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let text = match (body["file"].as_str(), body["text"].as_str()) {
        (Some(file), _) if super::maintain::backup_name_ok(file) => match std::fs::read_to_string(backups_dir(&state).join(file)) {
            Ok(text) => text,
            Err(_) => return error(StatusCode::NOT_FOUND, "unknown_backup"),
        },
        (None, Some(text)) => text.to_string(),
        _ => return error(StatusCode::BAD_REQUEST, "bad_request"),
    };
    let all = if server == "local" { ALL.to_string() } else { format!("{server}/*") };
    let Some(busy) = Busy::take(&state, vec![all]) else {
        return error(StatusCode::CONFLICT, "busy");
    };
    state.audit.record(ip, "action", &format!("restore a backup on {server}"));
    let answer = run_on_held(&state, &server, json!({"op": "server", "tool": "import", "text": text, "replace": body["replace"] == true}), Duration::from_secs(120), Some(busy.clone())).await;
    drop(busy);
    state.live.refresh();
    match answer {
        Ok(report) => Json(report).into_response(),
        Err(failure) => failed_with(StatusCode::BAD_REQUEST, format!("{failure:#}")),
    }
}

/// Backs up every server when the newest backup is older than the chosen number of days.
pub async fn backup_loop(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let days = super::prefs::load(&state.state_dir).auto_backup_days;
        if days == 0 {
            continue;
        }
        let newest = super::maintain::backups(&backups_dir(&state)).first().and_then(|b| b["at"].as_u64()).unwrap_or(0);
        if super::now().saturating_sub(newest) >= days * 86_400 {
            let results = backup_all(&state).await;
            let failed = results.iter().filter(|r| r.get("error").is_some()).count();
            state.audit.record(None, "action", &format!("automatic backup of {} server(s), {failed} failed", results.len()));
        }
    }
}

/// The transport check the dashboard runs: which servers, and since when.
#[derive(Clone)]
struct CheckRun {
    iran: String,
    foreign: String,
    started: u64,
    /// The job on both servers; stops name it, so they never end another check.
    id: String,
    /// The demo has no second server; only this one answers.
    pretend: bool,
}

static CHECK: std::sync::Mutex<Option<CheckRun>> = std::sync::Mutex::new(None);

/// How long a check or test whose server stopped answering still counts as running: its
/// servers end it by themselves well before that.
const UNANSWERED_HOLD: u64 = 3 * 3600;

/// After a failed start: whether every end that may have started was told to stop.
fn stop_note(stopped: bool) -> &'static str {
    if stopped { "" } else { " (it may have started anyway and could not be told to stop; use Stop)" }
}
static CHECK_START: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn check_on(state: &Arc<AppState>, server: &str, check: Value) -> Result<Value> {
    run_on(state, server, json!({"op": "server", "tool": "check", "check": check}), Duration::from_secs(20)).await
}

/// Starts a transport check: the Iran server starts it, the foreign server joins.
async fn conntest_start(State(state): State<Arc<AppState>>, request: Request) -> Response {
    tokio::spawn(conntest_start_owned(State(state), request)).await.unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "failed"))
}

async fn conntest_start_owned(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let Ok(_reservation) = CHECK_START.try_lock() else { return error(StatusCode::CONFLICT, "busy"); };
    let ip = client_ip(&request);
    let bytes = match read_body(request, MAX_BODY).await { Ok(bytes) => bytes, Err(response) => return response };
    let Ok(form) = serde_json::from_slice::<Value>(&bytes) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let failed = |status: StatusCode, detail: String| (status, Json(json!({"error": "failed", "detail": detail}))).into_response();
    let iran = server_of(&state, form["iran"].as_str().unwrap_or("local").to_string());
    let foreign_id = form["foreign"].as_str().unwrap_or("").to_string();
    let pretend = state.fleet.is_none();
    let foreign = if pretend { foreign_id.clone() } else { server_of(&state, foreign_id.clone()) };
    if iran == foreign || foreign.is_empty() {
        return failed(StatusCode::BAD_REQUEST, "the two ends must be on different servers".into());
    }
    let current = CHECK.lock().unwrap().clone();
    if let Some(run) = current {
        // A check that ended on the starting server no longer blocks a new one; one whose server
        // does not answer may still be running and is not forgotten.
        match check_on(&state, &run.iran, json!({"action": "status"})).await {
            Ok(answer) if answer["state"] == "running" => {
                return failed(StatusCode::CONFLICT, "a transport check is already running".into());
            }
            Err(_) if super::now().saturating_sub(run.started) < UNANSWERED_HOLD => {
                return failed(StatusCode::CONFLICT, "the server of the last check does not answer, so it may still be running; try again once it answers".into());
            }
            _ => {}
        }
    }
    let code = match super::conntest::make_code(&form).and_then(|c| crate::checker::code::encode(&c)) {
        Ok(code) => code,
        Err(problem) => return failed(StatusCode::BAD_REQUEST, format!("{problem:#}")),
    };
    let id = super::conntest::job_id(&code);
    state.audit.record(ip, "action", &format!("transport check between {iran} and {foreign}"));
    // Recorded before anything is sent: a start whose answer is lost may still run, and must stay
    // visible to the status and the Stop button.
    *CHECK.lock().unwrap() = Some(CheckRun { iran: iran.clone(), foreign: foreign.clone(), started: super::now(), pretend, id: id.clone() });
    // Stops name this check: one already running there (from before a restart) is left alone.
    let stop = json!({"action": "stop", "id": id});
    if let Err(problem) = check_on(&state, &iran, json!({"action": "start", "code": code})).await {
        let stopped = check_on(&state, &iran, stop.clone()).await.is_ok();
        return failed(StatusCode::BAD_GATEWAY, format!("Iran server: {problem:#}{}", stop_note(stopped)));
    }
    if !pretend && let Err(problem) = check_on(&state, &foreign, json!({"action": "join", "code": code})).await {
        let foreign_stopped = check_on(&state, &foreign, stop.clone()).await.is_ok();
        let iran_stopped = check_on(&state, &iran, stop.clone()).await.is_ok();
        return failed(StatusCode::BAD_GATEWAY, format!("foreign server: {problem:#}{}", stop_note(foreign_stopped && iran_stopped)));
    }
    Json(json!({"ok": true})).into_response()
}

/// The check's progress, from the server that started it.
async fn conntest_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    let Some(run) = CHECK.lock().unwrap().clone() else {
        return Json(json!({"state": "idle"})).into_response();
    };
    let mut answer = check_on(&state, &run.iran, json!({"action": "status"})).await.unwrap_or_else(|e| json!({"state": "unknown", "error": format!("{e:#}")}));
    answer["iran"] = json!(run.iran);
    answer["foreign"] = json!(run.foreign);
    answer["started"] = json!(run.started);
    Json(answer).into_response()
}

async fn conntest_stop(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let Ok(_reservation) = CHECK_START.try_lock() else { return error(StatusCode::CONFLICT, "busy"); };
    let Some(run) = CHECK.lock().unwrap().clone() else {
        return Json(json!({"ok": true})).into_response();
    };
    state.audit.record(ip, "action", "stop the transport check");
    let stop = json!({"action": "stop", "id": run.id});
    let mut unreached = Vec::new();
    if let Err(problem) = check_on(&state, &run.iran, stop.clone()).await {
        unreached.push(format!("Iran server: {problem:#}"));
    }
    if !run.pretend && let Err(problem) = check_on(&state, &run.foreign, stop).await {
        unreached.push(format!("foreign server: {problem:#}"));
    }
    if !unreached.is_empty() {
        return failed_with(StatusCode::BAD_GATEWAY, format!("the stop did not reach every server ({})", unreached.join("; ")));
    }
    Json(json!({"ok": true})).into_response()
}

/// The Mirage source test the dashboard runs: which servers.
static MIRAGE: std::sync::Mutex<Option<CheckRun>> = std::sync::Mutex::new(None);
static MIRAGE_START: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn spoof_on(state: &Arc<AppState>, server: &str, spoof: Value) -> Result<Value> {
    run_on(state, server, json!({"op": "server", "tool": "spoof", "spoof": spoof}), Duration::from_secs(20)).await
}

/// Starts a Mirage source test: the Iran server hosts it, the foreign server joins.
async fn mirage_start(State(state): State<Arc<AppState>>, request: Request) -> Response {
    tokio::spawn(mirage_start_owned(State(state), request)).await.unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "failed"))
}

async fn mirage_start_owned(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let Ok(_reservation) = MIRAGE_START.try_lock() else { return error(StatusCode::CONFLICT, "busy"); };
    let ip = client_ip(&request);
    let bytes = match read_body(request, 64 * 1024).await { Ok(bytes) => bytes, Err(response) => return response };
    let Ok(form) = serde_json::from_slice::<Value>(&bytes) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let iran = server_of(&state, form["iran"].as_str().unwrap_or("local").to_string());
    let pretend = state.fleet.is_none();
    let foreign_id = form["foreign"].as_str().unwrap_or("").to_string();
    let foreign = if pretend { foreign_id } else { server_of(&state, foreign_id) };
    if iran == foreign || foreign.is_empty() {
        return failed_with(StatusCode::BAD_REQUEST, "the two ends must be on different servers");
    }
    let current = MIRAGE.lock().unwrap().clone();
    if let Some(run) = current {
        match spoof_on(&state, &run.iran, json!({"action": "status"})).await {
            Ok(answer) if answer["state"] == "running" => {
                return failed_with(StatusCode::CONFLICT, "a Mirage source test is already running");
            }
            Err(_) if super::now().saturating_sub(run.started) < UNANSWERED_HOLD => {
                return failed_with(StatusCode::CONFLICT, "the server of the last test does not answer, so it may still be running; try again once it answers");
            }
            _ => {}
        }
    }
    let (text, id) = match super::spoofcheck::invitation(&form).and_then(|i| Ok((i.encode()?, i.session.clone()))) {
        Ok(made) => made,
        Err(problem) => return failed_with(StatusCode::BAD_REQUEST, format!("{problem:#}")),
    };
    state.audit.record(ip, "action", &format!("Mirage source test between {iran} and {foreign}"));
    // Recorded before anything is sent, as for the transport check.
    *MIRAGE.lock().unwrap() = Some(CheckRun { iran: iran.clone(), foreign: foreign.clone(), started: super::now(), pretend, id: id.clone() });
    let stop = json!({"action": "stop", "id": id});
    if let Err(problem) = spoof_on(&state, &iran, json!({"action": "host", "invitation": text})).await {
        let stopped = spoof_on(&state, &iran, stop.clone()).await.is_ok();
        return failed_with(StatusCode::BAD_GATEWAY, format!("Iran server: {problem:#}{}", stop_note(stopped)));
    }
    if !pretend && let Err(problem) = spoof_on(&state, &foreign, json!({"action": "join", "invitation": text})).await {
        let foreign_stopped = spoof_on(&state, &foreign, stop.clone()).await.is_ok();
        let iran_stopped = spoof_on(&state, &iran, stop.clone()).await.is_ok();
        return failed_with(StatusCode::BAD_GATEWAY, format!("foreign server: {problem:#}{}", stop_note(foreign_stopped && iran_stopped)));
    }
    Json(json!({"ok": true})).into_response()
}

async fn mirage_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    // The packet types the test accepts, so the page never offers one it refuses.
    let profiles = json!(crate::spoof_session::TEST_PROFILES);
    let Some(run) = MIRAGE.lock().unwrap().clone() else {
        return Json(json!({"state": "idle", "profiles": profiles})).into_response();
    };
    let mut answer = spoof_on(&state, &run.iran, json!({"action": "status"})).await.unwrap_or_else(|e| json!({"state": "unknown", "error": format!("{e:#}")}));
    // Rows toward the Iran server are measured there; rows toward the foreign one, abroad.
    if !run.pretend
        && let Ok(theirs) = spoof_on(&state, &run.foreign, json!({"action": "status"})).await
        && let (Some(mine), Some(more)) = (answer["rows"].as_array().cloned(), theirs["rows"].as_array())
    {
        let mut all = mine;
        for row in more {
            if row["toward"] == "foreign" && !all.iter().any(|r| r["toward"] == "foreign" && r["source"] == row["source"] && r["profile"] == row["profile"]) {
                all.push(row.clone());
            }
        }
        answer["rows"] = json!(all);
    }
    answer["iran"] = json!(run.iran);
    answer["foreign"] = json!(run.foreign);
    answer["started"] = json!(run.started);
    answer["profiles"] = profiles;
    Json(answer).into_response()
}

async fn mirage_stop(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let Ok(_reservation) = MIRAGE_START.try_lock() else { return error(StatusCode::CONFLICT, "busy"); };
    let Some(run) = MIRAGE.lock().unwrap().clone() else {
        return Json(json!({"ok": true})).into_response();
    };
    state.audit.record(client_ip(&request), "action", "stop the Mirage source test");
    let stop = json!({"action": "stop", "id": run.id});
    let mut unreached = Vec::new();
    if let Err(problem) = spoof_on(&state, &run.iran, stop.clone()).await {
        unreached.push(format!("Iran server: {problem:#}"));
    }
    if !run.pretend && let Err(problem) = spoof_on(&state, &run.foreign, stop).await {
        unreached.push(format!("foreign server: {problem:#}"));
    }
    if !unreached.is_empty() {
        return failed_with(StatusCode::BAD_GATEWAY, format!("the stop did not reach every server ({})", unreached.join("; ")));
    }
    Json(json!({"ok": true})).into_response()
}

/// Every server the dashboard can ask right now: (id, name, address).
fn online_servers(state: &AppState) -> Vec<(String, String, String)> {
    let mut list = Vec::new();
    if let Some(snapshot) = state.live.latest() {
        let value = serde_json::to_value(&*snapshot).unwrap_or_default();
        list.push(("local".into(), value["host"]["hostname"].as_str().unwrap_or("this server").into(), value["host"]["address"].as_str().unwrap_or("").into()));
    }
    let servers = match &state.fleet {
        Some(fleet) => fleet.servers(),
        None => demo_servers(state.live.latest().as_deref()),
    };
    for s in servers.into_iter().filter(|s| s["online"] == true) {
        list.push((
            s["id"].as_str().unwrap_or("").into(),
            s["name"].as_str().unwrap_or("").into(),
            s["snapshot"]["host"]["address"].as_str().unwrap_or("").into(),
        ));
    }
    list
}

/// One path search at a time: two would open their echo and relay ports on the same numbers.
static PATH_SEARCH: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Cancel (`POST /api/pathfinder/cancel`) wakes the search running now.
static PATH_CANCEL: std::sync::LazyLock<tokio::sync::Notify> = std::sync::LazyLock::new(tokio::sync::Notify::new);

/// Stops the path search that is running, if one is. Its test ports are closed on every server.
async fn pathfinder_cancel(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    if PATH_SEARCH.try_lock().is_ok() {
        return Json(json!({"ok": true, "running": false})).into_response();
    }
    state.audit.record(None, "action", "cancel the path search");
    PATH_CANCEL.notify_waiters();
    Json(json!({"ok": true, "running": true})).into_response()
}

/// Finds a way between two servers: the direct path both ways, what the Iran server reaches
/// abroad, and every other managed server tried as a relay (a temporary forwarder there, checked
/// end to end). When the foreign server cannot be asked (offline from here), its SSH greeting
/// stands in for an echo.
async fn pathfinder(State(state): State<Arc<AppState>>, request: Request) -> Response {
    const ECHO: u16 = 47131;
    const RELAY: u16 = 47132;
    const BACK: u16 = 47133;
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let Ok(_running) = PATH_SEARCH.try_lock() else {
        return failed_with(StatusCode::CONFLICT, "a path search is already running; wait for it to finish");
    };
    let ip = client_ip(&request);
    let body = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let iran = server_of(&state, body["iran"].as_str().unwrap_or("local").to_string());
    let foreign_id = body["foreign"].as_str().unwrap_or("").to_string();
    let parse = |key: &str| body[key].as_str().unwrap_or("").trim().parse::<std::net::IpAddr>();
    let (Ok(iran_ip), Ok(foreign_ip)) = (parse("iran_ip"), parse("foreign_ip")) else {
        return failed_with(StatusCode::BAD_REQUEST, "both addresses must be IP addresses");
    };
    // The IPv6 addresses, when both servers have one: the direct path is tried over IPv6 too.
    let ipv6 = match (parse("iran_ip6"), parse("foreign_ip6")) {
        (Ok(a), Ok(b)) if a.is_ipv6() && b.is_ipv6() && a != b => Some((a, b)),
        _ => None,
    };
    let online = online_servers(&state);
    let pretend = state.fleet.is_none();
    let foreign = if foreign_id.is_empty() { String::new() } else if pretend { "local".into() } else { server_of(&state, foreign_id.clone()) };
    let foreign_online = !foreign.is_empty() && (pretend || online.iter().any(|(id, _, _)| *id == foreign));
    if !online.iter().any(|(id, _, _)| *id == iran) {
        return failed_with(StatusCode::BAD_REQUEST, "the Iran server must be connected to this dashboard");
    }
    if !pretend && foreign == iran {
        return failed_with(StatusCode::BAD_REQUEST, "the two ends must be on different servers");
    }
    state.audit.record(ip, "action", &format!("find a path between {iran_ip} and {foreign_ip}"));
    let path = |server: String, step: Value| {
        let state = state.clone();
        async move { run_on(&state, &server, json!({"op": "server", "tool": "path", "path": step}), Duration::from_secs(40)).await.unwrap_or_else(|e| json!({"ok": false, "error": format!("{e:#}")})) }
    };
    // Cancel may come at any step: listen for it from the start.
    let cancelled = PATH_CANCEL.notified();
    tokio::pin!(cancelled);
    cancelled.as_mut().enable();
    let scan = async {
    let mut out = serde_json::Map::new();
    out.insert("from_iran".into(), path(iran.clone(), json!({"step": "probe", "host": foreign_ip.to_string(), "ports": [ECHO]})).await);
    out.insert("known".into(), path(iran.clone(), json!({"step": "known"})).await["known"].clone());
    // The direct path, each way, end to end.
    let (to_foreign, target) = if foreign_online {
        path(foreign.clone(), json!({"step": "echo", "port": ECHO, "secs": 110})).await;
        (path(iran.clone(), json!({"step": "echo_check", "target": SocketAddr::new(foreign_ip, ECHO).to_string()})).await, SocketAddr::new(foreign_ip, ECHO))
    } else {
        (path(iran.clone(), json!({"step": "banner_check", "target": SocketAddr::new(foreign_ip, 22).to_string()})).await, SocketAddr::new(foreign_ip, 22))
    };
    out.insert("iran_to_foreign".into(), to_foreign);
    if foreign_online {
        out.insert("from_foreign".into(), path(foreign.clone(), json!({"step": "probe", "host": iran_ip.to_string(), "ports": [BACK]})).await);
        path(iran.clone(), json!({"step": "echo", "port": BACK, "secs": 30})).await;
        out.insert("foreign_to_iran".into(), path(foreign.clone(), json!({"step": "echo_check", "target": SocketAddr::new(iran_ip, BACK).to_string()})).await);
        // The same two directions over IPv6: a route that drops one family may carry the other.
        // The echo listeners take both families.
        if let Some((iran6, foreign6)) = ipv6 {
            out.insert("iran_to_foreign_v6".into(), path(iran.clone(), json!({"step": "echo_check", "target": SocketAddr::new(foreign6, ECHO).to_string()})).await);
            out.insert("foreign_to_iran_v6".into(), path(foreign.clone(), json!({"step": "echo_check", "target": SocketAddr::new(iran6, BACK).to_string()})).await);
        }
    }
    // Every other server as a relay: Iran → relay → foreign.
    let check = if foreign_online { "echo_check" } else { "banner_check" };
    let mut relays = Vec::new();
    for (id, name, address) in online.iter().filter(|(id, _, _)| *id != iran && *id != foreign && !(pretend && id != "local")) {
        let Ok(relay_ip) = address.parse::<std::net::IpAddr>() else {
            relays.push(json!({"server": id, "name": name, "ok": false, "error": "its address is unknown"}));
            continue;
        };
        // The destination's echo lives two minutes; a long scan renews it for every relay.
        if foreign_online {
            path(foreign.clone(), json!({"step": "echo", "port": ECHO, "secs": 110})).await;
        }
        let forward = path(id.clone(), json!({"step": "forward", "port": RELAY, "target": target.to_string(), "secs": 30})).await;
        if forward.get("error").is_some() {
            relays.push(json!({"server": id, "name": name, "address": address, "ok": false, "error": forward["error"]}));
            continue;
        }
        let through = path(iran.clone(), json!({"step": check, "target": SocketAddr::new(relay_ip, RELAY).to_string()})).await;
        relays.push(json!({"server": id, "name": name, "address": address, "ok": through["ok"], "ms": through["ms"], "error": through["error"]}));
        // This relay is done: its forwarder goes now, not when its time runs out.
        path(id.clone(), json!({"step": "close", "port": RELAY})).await;
    }
    // Nothing of this scan stays open.
    if foreign_online {
        path(foreign.clone(), json!({"step": "close", "port": ECHO})).await;
        path(iran.clone(), json!({"step": "close", "port": BACK})).await;
    }
    out.insert("relays".into(), json!(relays));
    out.insert("foreign_asked".into(), json!(foreign_online));
    Json(Value::Object(out)).into_response()
    };
    tokio::select! {
        response = scan => response,
        () = &mut cancelled => {
            // Whatever the search had opened goes now: the echo on each end, the relay forwarders.
            if foreign_online {
                path(foreign.clone(), json!({"step": "close", "port": ECHO})).await;
            }
            path(iran.clone(), json!({"step": "close", "port": BACK})).await;
            for (id, _, _) in online.iter().filter(|(id, _, _)| *id != iran && *id != foreign) {
                path(id.clone(), json!({"step": "close", "port": RELAY})).await;
            }
            Json(json!({"cancelled": true})).into_response()
        }
    }
}

/// The dashboard's public SSH key, for adding servers over SSH.
async fn ssh_key(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    if state.demo {
        return Json(json!({"key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoKeyOnlyNothingWorksWithIt0000000000 eztunnel-dashboard"})).into_response();
    }
    let dir = state.state_dir.clone();
    match tokio::task::spawn_blocking(move || super::sshadd::public_key(&dir)).await {
        Ok(Ok(key)) => Json(json!({"key": key})).into_response(),
        Ok(Err(failure)) => failed_with(StatusCode::INTERNAL_SERVER_ERROR, format!("{failure:#}")),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
    }
}

/// Logs in to a server with the dashboard's key and runs a fresh one-time join command there.
async fn ssh_add(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let body = match read_json(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let host = body["host"].as_str().unwrap_or("").trim().to_string();
    let user = body["user"].as_str().unwrap_or("root").trim().to_string();
    let port = body["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(22);
    if !super::sshadd::host_ok(&host) || !super::sshadd::user_ok(&user) {
        return failed_with(StatusCode::BAD_REQUEST, "check the host and the user name");
    }
    state.audit.record(ip, "action", &format!("add server {user}@{host}:{port} over SSH"));
    if state.demo {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        return failed_with(StatusCode::BAD_REQUEST, "the demo connects to nothing");
    }
    let Some(fleet) = state.fleet.clone() else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    let code = match fleet.join_code(&state.public.0, state.public.1) {
        Ok((code, _)) => code,
        Err(failure) => return failed_with(StatusCode::TOO_MANY_REQUESTS, format!("{failure:#}")),
    };
    let command = join_command(&state.public, state.cert.as_deref(), &code);
    let dir = state.state_dir.clone();
    match tokio::task::spawn_blocking(move || super::sshadd::run_join(&dir, &host, port, &user, &command)).await {
        Ok(Ok(output)) => {
            // The command finished; the server has joined only once it used the code here.
            for _ in 0..40 {
                if fleet.code_used(&code) {
                    return Json(json!({"ok": true, "output": output})).into_response();
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let failure = format!("the command finished but the server did not join this dashboard: {output}");
            state.audit.record(ip, "action_failed", &format!("add server over SSH: {failure}"));
            failed_with(StatusCode::BAD_GATEWAY, failure)
        }
        Ok(Err(failure)) => {
            state.audit.record(ip, "action_failed", &format!("add server over SSH: {failure:#}"));
            failed_with(StatusCode::BAD_GATEWAY, format!("{failure:#}"))
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
    }
}

/// What the new-tunnel form offers: the transports the dashboard can set up.
async fn new_tunnel_options(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    let transports: Vec<Value> = super::wizard::TRANSPORTS
        .iter()
        .map(|word| {
            let transport: crate::config::Transport = serde_json::from_value(json!(word)).expect("listed transport");
            json!({"name": word, "port": crate::manager::plan::default_tunnel_port(transport), "udp": crate::manager::plan::uses_udp(transport),
                   "options": super::wizard::options_of(transport)})
        })
        .collect();
    // GAME first among the special entries: FEC-UDP with Game mode switched on.
    let mut transports = transports;
    // IPv6: any of these transports between the servers' IPv6 addresses.
    let mut over_ipv6: Vec<&str> = super::wizard::TRANSPORTS.to_vec();
    over_ipv6.push("game");
    transports.push(json!({"name": "ipv6", "ipv6": true, "transports": over_ipv6,
        "port": crate::manager::plan::default_tunnel_port(crate::config::Transport::Tcp), "udp": false,
        "options": super::wizard::options_of(crate::config::Transport::Tcp)}));
    transports.push(json!({"name": "game", "port": crate::manager::plan::default_tunnel_port(crate::config::Transport::FecUdp),
        "udp": true, "game": true, "options": super::wizard::options_of(crate::config::Transport::FecUdp)}));
    Json(json!({"transports": transports})).into_response()
}

/// Builds both ends of a new tunnel and starts them: the listening end first, then the dialing
/// end. If an end cannot be created or does not stay up, whatever was created is removed again.
/// In the demo without joined servers, the end on another server is only pretended.
async fn new_tunnel(State(state): State<Arc<AppState>>, request: Request) -> Response {
    tokio::spawn(new_tunnel_owned(State(state), request)).await.unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "failed"))
}

async fn new_tunnel_owned(State(state): State<Arc<AppState>>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let bytes = match read_body(request, MAX_BODY).await { Ok(bytes) => bytes, Err(response) => return response };
    let Ok(form) = serde_json::from_slice::<Value>(&bytes) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let failed = |status: StatusCode, detail: String| (status, Json(json!({"error": "failed", "detail": detail}))).into_response();
    let place = |key: &str| form[key].as_str().unwrap_or("local").to_string();
    let (iran_at, foreign_at) = (place("iran"), place("foreign"));
    if iran_at == foreign_at {
        return failed(StatusCode::BAD_REQUEST, "the two ends must be on different servers".into());
    }
    let pretend = state.fleet.is_none();
    for at in [&iran_at, &foreign_at] {
        let known = at == "local" || state.fleet.as_ref().is_some_and(|f| f.servers().iter().any(|s| s["id"] == **at && s["online"] == true));
        if !known && !(pretend && at != "local") {
            return failed(StatusCode::BAD_REQUEST, format!("server {at} is not connected"));
        }
    }
    let built = match super::wizard::build(&form) {
        Ok(built) => built,
        Err(problem) => return failed(StatusCode::BAD_REQUEST, format!("{problem:#}")),
    };
    let name = form["name"].as_str().unwrap_or("").trim().to_string();
    let key_of = |at: &str| if at == "local" { name.clone() } else { format!("{at}/{name}") };
    if [&iran_at, &foreign_at].iter().any(|at| state.busy.lock().unwrap().contains(&format!("{at}/*"))) {
        return error(StatusCode::CONFLICT, "busy");
    }
    let Some(busy) = Busy::take(&state, vec![key_of(&iran_at), key_of(&foreign_at)]) else {
        return error(StatusCode::CONFLICT, "busy");
    };
    let real = |at: &str| at == "local" || !pretend;
    // A taken name is found before anything is written.
    for at in [&iran_at, &foreign_at] {
        if !real(at) {
            continue;
        }
        match run_on(&state, at, json!({"op": "names"}), ACTION_TIMEOUT).await {
            Ok(names) if names.as_array().is_some_and(|n| n.iter().any(|x| x == name.as_str())) => {
                return failed(StatusCode::CONFLICT, format!("a tunnel named {name} already exists on {}", if at == "local" { "this server" } else { at }));
            }
            Ok(_) => {}
            Err(problem) => return failed(StatusCode::BAD_GATEWAY, format!("{problem:#}")),
        }
    }
    let transport = form["transport"].as_str().unwrap_or("");
    state.audit.record(ip, "action", &format!("create {name} ({transport}; Iran end on {iran_at}, foreign end on {foreign_at})"));
    let (first, second) = match built.listening {
        crate::manager::plan::Side::Iran => ((&iran_at, &built.iran, "iran"), (&foreign_at, &built.foreign, "foreign")),
        crate::manager::plan::Side::Foreign => ((&foreign_at, &built.foreign, "foreign"), (&iran_at, &built.iran, "iran")),
    };
    let mut created: Vec<(&str, &str)> = Vec::new();
    let mut report = serde_json::Map::new();
    let mut problem: Option<String> = None;
    for (at, config, side) in [first, second] {
        if !real(at) {
            tokio::time::sleep(Duration::from_millis(900)).await;
            report.insert(side.into(), json!({"server": at, "came_up": true}));
            continue;
        }
        // Counted before it is sent: a create whose answer is lost (a timeout) may still have
        // happened on that server, and must be cleaned up like one that answered. A refusal
        // before anything was written (a name taken meanwhile) leaves nothing of ours there.
        created.push((at, side));
        let outcome = run_on_held(&state, at, json!({"op": "create", "name": name, "config": config}), ACTION_TIMEOUT, Some(busy.clone())).await;
        if let Err(failure) = &outcome
            && format!("{failure:#}").contains(ops::UNCHANGED)
        {
            created.pop();
        }
        match outcome {
            Ok(outcome) => {
                report.insert(side.into(), json!({"server": at, "came_up": outcome["came_up"]}));
                if outcome["came_up"] == false {
                    problem = Some(format!(
                        "the {} end did not stay up (often because {} is taken or blocked by a firewall), so nothing was kept",
                        if side == "iran" { "Iran" } else { "foreign" },
                        config["listeners"][0]["addr"].as_str().or(config["paths"][0]["addr"].as_str()).unwrap_or("")
                    ));
                    break;
                }
            }
            Err(failure) => {
                problem = Some(format!("{} end: {failure:#}", if side == "iran" { "Iran" } else { "foreign" }));
                break;
            }
        }
    }
    if let Some(mut problem) = problem {
        let mut left = Vec::new();
        for (at, side) in created.iter().rev() {
            // Only the tunnel this create made (its key), never one of the same name made by
            // someone else meanwhile.
            let key = if *side == "iran" { &built.iran["tunnel_key"] } else { &built.foreign["tunnel_key"] };
            match run_on_held(&state, at, json!({"op": "delete", "name": name, "expect_key": key}), ACTION_TIMEOUT, Some(busy.clone())).await {
                Ok(_) => {}
                // The create never got there, or the tunnel there is not ours: nothing to clean up.
                Err(failure) if format!("{failure:#}").contains("no tunnel named") || format!("{failure:#}").contains(ops::UNCHANGED) => {}
                Err(failure) => {
                    left.push(format!("{at}: {failure:#}"));
                    // A create whose answer was lost may still be running there (holding the
                    // tunnel's lock) and finish later: keep trying to remove what it made.
                    let (state, at, name, key) = (state.clone(), at.to_string(), name.clone(), key.clone());
                    tokio::spawn(async move {
                        for _ in 0..30 {
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            match run_on(&state, &at, json!({"op": "delete", "name": name, "expect_key": key}), ACTION_TIMEOUT).await {
                                Ok(_) => {
                                    state.audit.record(None, "action", &format!("removed the half-made tunnel {name} on {at}"));
                                    return;
                                }
                                Err(failure) if format!("{failure:#}").contains("no tunnel named") || format!("{failure:#}").contains(ops::UNCHANGED) => return,
                                Err(_) => {}
                            }
                        }
                        state.audit.record(None, "action_failed", &format!("the half-made tunnel {name} on {at} could not be removed; delete it by hand"));
                    });
                }
            }
        }
        if !left.is_empty() {
            problem = format!("{problem}. The half-made tunnel {name} could not be removed everywhere yet; the dashboard keeps trying for five minutes, then delete it by hand ({})", left.join("; "));
        }
        drop(busy);
        state.live.refresh();
        state.audit.record(ip, "action_failed", &format!("create {name}: {problem}"));
        return failed(StatusCode::INTERNAL_SERVER_ERROR, problem);
    }
    drop(busy);
    state.live.refresh();
    report.insert("ok".into(), json!(true));
    report.insert("name".into(), json!(name));
    Json(Value::Object(report)).into_response()
}

/// Deletes a tunnel here or on a joined server.
async fn delete_answer(
    state: Arc<AppState>,
    server: String,
    name: String,
    request: Request,
) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    // Optional `{"pair": ...}`: the fingerprint the tunnel was chosen by, checked on its server
    // under the tunnel's lock. A page from before it sends no body and deletes by name.
    let pair = match read_body(request, MAX_BODY).await {
        Ok(bytes) if bytes.is_empty() => None,
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(body) if body.is_object() => match body.get("pair") {
                None | Some(Value::Null) => None,
                Some(Value::String(pair)) if ops::valid_pair(pair) => Some(pair.to_ascii_lowercase()),
                Some(_) => return error(StatusCode::BAD_REQUEST, "bad_pair"),
            },
            _ => return error(StatusCode::BAD_REQUEST, "bad_request"),
        },
        Err(response) => return response,
    };
    let local = server == "local";
    let key = if local {
        name.clone()
    } else {
        format!("{server}/{name}")
    };
    if !local && state.busy.lock().unwrap().contains(&format!("{server}/*")) {
        return error(StatusCode::CONFLICT, "busy");
    }
    let Some(busy) = Busy::take(&state, vec![key]) else {
        return error(StatusCode::CONFLICT, "busy");
    };
    let place = if local {
        String::new()
    } else {
        format!(" on {server}")
    };
    state
        .audit
        .record(ip, "action", &format!("delete {name}{place}"));
    let answer: Result<()> = if local {
        let ops = state.ops.clone();
        let task_name = name.clone();
        let task_pair = pair.clone();
        // The guard moves into the task, so a slow delete keeps the tunnel marked busy.
        let task = tokio::task::spawn_blocking(move || {
            let _busy = busy;
            match task_pair {
                Some(pair) => ops.delete_pair(&task_name, &pair),
                None => ops.delete(&task_name),
            }
        });
        match tokio::time::timeout(ACTION_TIMEOUT, task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow::anyhow!("the delete task stopped")),
            Err(_) => return error(StatusCode::GATEWAY_TIMEOUT, "timeout"),
        }
    } else {
        let Some(fleet) = state.fleet.clone() else {
            return error(StatusCode::NOT_FOUND, "unknown_server");
        };
        // Guarded removal is an explicit Agent operation: older Agents without it reject
        // the request rather than ignore a fingerprint and delete a replacement tunnel.
        let op = if pair.is_some() { "delete_pair" } else { "delete" };
        let answer = fleet.request_held(&server,
            json!({"op": op, "name": name, "expect_pair": pair}),
            ACTION_TIMEOUT, busy.clone()).await.map(|_| ());
        drop(busy);
        answer
    };
    state.live.refresh();
    match answer {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(failure) => {
            let detail = format!("{failure:#}");
            state.audit.record(ip, "action_failed", &format!("delete {name}{place}: {detail}"));
            failure_response(&failure, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn local_delete(State(state): State<Arc<AppState>>, Path(name): Path<String>, request: Request) -> Response {
    if !state.signed_in(request.headers()) { return unauthorized(); }
    if !tunnel_names(&state).await.contains(&name) {
        return error(StatusCode::NOT_FOUND, "unknown_tunnel");
    }
    delete_answer(state, "local".into(), name, request).await
}

async fn server_delete(State(state): State<Arc<AppState>>, Path((id, name)): Path<(String, String)>, request: Request) -> Response {
    if state.fleet.is_none() {
        return local_delete(State(state), Path(name), request).await;
    }
    delete_answer(state, id, name, request).await
}

/// Restarts every tunnel on another server, one after another.
async fn server_restart_all(State(state): State<Arc<AppState>>, Path(id): Path<String>, request: Request) -> Response {
    if !state.signed_in(request.headers()) {
        return unauthorized();
    }
    let ip = client_ip(&request);
    let Some(fleet) = state.fleet.clone() else {
        tokio::time::sleep(Duration::from_millis(900)).await;
        return Json(json!({"ok": true, "results": [{"name": "game-fec", "ok": true, "came_up": true}, {"name": "web-wss", "ok": true, "came_up": true}]})).into_response();
    };
    let Some(busy) = Busy::take(&state, vec![format!("{id}/*")]) else {
        return error(StatusCode::CONFLICT, "busy");
    };
    state.audit.record(ip, "action", &format!("restart all on {id}"));
    let answer = fleet.request_held(&id, json!({"op": "restart_all"}), ALL_TIMEOUT, busy.clone()).await;
    drop(busy);
    match answer {
        Ok(results) => {
            let list = results.as_array().cloned().unwrap_or_default();
            let failed = list.iter().filter(|r| r["ok"] != true || r["came_up"] == false).count();
            state.audit.record(ip, "action_result", &format!("restart all on {id}: {failed} not up"));
            Json(json!({"ok": failed == 0, "results": list})).into_response()
        }
        Err(failure) => {
            let detail = format!("{failure:#}");
            state.audit.record(ip, "action_failed", &format!("restart all on {id}: {detail}"));
            failure_response(&failure, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// The last lines of a tunnel's log on another server.
async fn server_logs(
    State(state): State<Arc<AppState>>,
    Path((id, name)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<LogsQuery>,
) -> Response {
    if !state.signed_in(&headers) {
        return unauthorized();
    }
    let lines = query.lines.min(ops::MAX_LINES);
    let Some(fleet) = state.fleet.clone() else {
        let ops = ops::DemoOps::new(&[&name]);
        return Json(ops.logs(&name, lines).unwrap_or_default()).into_response();
    };
    match fleet.request(&id, json!({"op": "logs", "name": name, "lines": lines}), Duration::from_secs(20)).await {
        // An agent from before the cursor sends the lines alone.
        Ok(lines) if lines.is_array() => Json(json!({"lines": lines})).into_response(),
        Ok(tail) => Json(tail).into_response(),
        Err(failure) => failure_response(&failure, StatusCode::BAD_GATEWAY),
    }
}

/// A tunnel's log on another server as it is written, one event per line.
async fn server_follow(
    State(state): State<Arc<AppState>>,
    Path((id, name)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<FollowQuery>,
) -> Response {
    let after = resume_cursor(&headers, query);
    let Some(token) = state.token(&headers).filter(|t| state.auth.check(t)) else {
        return unauthorized();
    };
    let Ok(permit) = state.followers.clone().try_acquire_owned() else {
        return error(StatusCode::TOO_MANY_REQUESTS, "too_many");
    };
    let Some(fleet) = state.fleet.clone() else {
        // The demo follows its own sample lines.
        let Ok(log) = ops::DemoOps::new(&[&name]).follow(&name, None) else {
            return error(StatusCode::NOT_FOUND, "unknown_tunnel");
        };
        return sse_lines(state, token, permit, LineSource::Local(log));
    };
    match fleet.follow(&id, &name, after).await {
        Ok(follow) => sse_lines(state, token, permit, LineSource::Remote(follow)),
        Err(failure) => failure_response(&failure, StatusCode::BAD_GATEWAY),
    }
}

enum LineSource {
    Local(ops::Follow),
    Remote(super::fleet::RemoteFollow),
}

impl LineSource {
    async fn next_line(&mut self) -> Option<(String, Option<String>)> {
        match self {
            LineSource::Local(log) => log.next_line().await,
            LineSource::Remote(follow) => follow.lines.recv().await,
        }
    }
}

/// Lines as Server-Sent Events until the source ends or the session does.
fn sse_lines(state: Arc<AppState>, token: String, permit: tokio::sync::OwnedSemaphorePermit, source: LineSource) -> Response {
    let stream = futures_util::stream::unfold(
        (source, state, token, permit),
        |(mut source, state, token, permit)| async move {
            loop {
                tokio::select! {
                    line = source.next_line() => {
                        let (line, cursor) = line?;
                        if !state.auth.check(&token) {
                            return None;
                        }
                        let mut event = Event::default().event("line").data(line.replace(['\r', '\n'], " "));
                        // The browser sends it back as Last-Event-ID when it reconnects.
                        if let Some(cursor) = cursor {
                            event = event.id(cursor);
                        }
                        return Some((Ok::<_, Infallible>(event), (source, state, token, permit)));
                    }
                    _ = tokio::time::sleep(Duration::from_secs(15)) => {
                        if !state.auth.check(&token) {
                            return None;
                        }
                    }
                }
            }
        },
    );
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// Accepts connections until the process ends. With `tls`, every connection is HTTPS.
pub async fn serve(
    state: Arc<AppState>,
    address: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("listen on {address}"))?;
    let app = router(state);
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = slots.clone().acquire_owned().await?;
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let app = app.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match acceptor {
                Some(acceptor) => {
                    if let Ok(Ok(stream)) =
                        tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await
                    {
                        connection(stream, peer.ip(), app).await;
                    }
                }
                None => connection(stream, peer.ip(), app).await,
            }
        });
    }
}

async fn connection<I>(io: I, ip: IpAddr, app: Router)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tower_service::Service;
    let service = hyper::service::service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
        request.extensions_mut().insert(ClientIp(ip));
        let mut app = app.clone();
        async move { app.call(request.map(Body::new)).await }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15))
        .max_buf_size(64 * 1024)
        .serve_connection(hyper_util::rt::TokioIo::new(io), service)
        // Agents switch their connection to the agent link (`GET /agent`).
        .with_upgrades()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unfinished_bodies_time_out_and_oversized_bodies_are_rejected() {
        let pending = Body::from_stream(futures_util::stream::pending::<Result<bytes::Bytes, Infallible>>());
        let response = read_body_with_deadline(pending, 10, Duration::from_millis(1)).await.unwrap_err();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(response.headers()[header::CONNECTION], "close");
        let response = read_body_with_deadline(Body::from("12345"), 4, Duration::from_secs(1)).await.unwrap_err();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn incomplete_exports_are_kept_but_never_reported_as_complete_backups() {
        let dir = tempfile::tempdir().unwrap();
        let result = save_export(dir.path(), "local", &json!({"backup": {"tunnels": {}}, "skipped": ["broken"]})).unwrap();
        assert!(result["file"].is_string());
        assert_eq!(result["skipped"], json!(["broken"]));
        assert!(result["error"].is_string());
    }

    #[tokio::test]
    async fn server_wildcards_conflict_with_existing_tunnel_work_in_both_orders() {
        let (_, state) = app().await;
        let tunnel = Busy::take(&state, vec!["server-a/game".into()]).unwrap();
        assert!(Busy::take(&state, vec!["server-a/*".into()]).is_none());
        assert!(Busy::take(&state, vec!["server-b/*".into()]).is_some());
        drop(tunnel);
        let all = Busy::take(&state, vec!["server-a/*".into()]).unwrap();
        assert!(Busy::take(&state, vec!["server-a/game".into()]).is_none());
        drop(all);
    }

    #[tokio::test]
    async fn a_timed_out_local_operation_keeps_its_busy_guard_until_it_finishes() {
        let (app, mut state) = app().await;
        drop(app);
        let mut ops = demo_ops();
        ops.delay = Duration::from_millis(100);
        Arc::get_mut(&mut state).unwrap().ops = Arc::new(ops);
        let busy = Busy::take(&state, vec!["game-fec".into()]).unwrap();
        let answer = run_on_held(&state, "local", json!({"op": "act", "name": "game-fec", "action": "stop"}), Duration::from_millis(1), Some(busy.clone())).await;
        assert!(answer.is_err());
        drop(busy);
        assert!(Busy::take(&state, vec!["game-fec".into()]).is_none());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(Busy::take(&state, vec!["game-fec".into()]).is_some());
    }

    async fn app() -> (Router, Arc<AppState>) {
        let state = Arc::new(AppState {
            history: Arc::new(super::super::history::History::new(Box::new(super::super::history::DemoStore {
                tunnels: vec![("game-fec", 1e6, true)],
                started_minute: 30_000_000,
            }))),
            auth: auth::Auth::new(auth::hash_password("pw").unwrap()),
            audit: Audit::disabled(),
            live: Live::start(Box::new(super::super::data::DemoSource::new()), None),
            ops: Arc::new(demo_ops()),
            busy: Default::default(),
            followers: Arc::new(Semaphore::new(MAX_FOLLOWERS)),
            fleet: None,
            public: ("203.0.113.10".into(), 38_471),
            agent_slots: Arc::new(Semaphore::new(4)),
            cert: None,
            demo: true,
            secure: false,
            state_dir: std::env::temp_dir().join(format!("ezd-test-{}-{:?}", std::process::id(), std::thread::current().id()).replace(['(', ')'], "")),
            alerts: Default::default(),
        });
        (router(state.clone()), state)
    }

    async fn call(app: &Router, request: hyper::Request<Body>) -> Response {
        use tower_service::Service;
        let mut request = request;
        request
            .extensions_mut()
            .insert(ClientIp(IpAddr::from([127, 0, 0, 1])));
        app.clone().call(request).await.unwrap()
    }

    fn post(path: &str, body: &str, marked: bool) -> hyper::Request<Body> {
        let mut builder = hyper::Request::post(path).header(header::CONTENT_TYPE, "application/json");
        if marked {
            builder = builder.header(CSRF_HEADER, "1");
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn cookie_of(response: &Response) -> String {
        let set = response.headers()[header::SET_COOKIE].to_str().unwrap();
        set.split(';').next().unwrap().to_string()
    }

    fn demo_ops() -> ops::DemoOps {
        let mut ops = ops::DemoOps::new(&["game-fec", "backup-tcp"]);
        ops.delay = Duration::ZERO;
        ops
    }

    async fn signed_in(app: &Router) -> String {
        let response = call(app, post("/api/login", r#"{"password":"pw"}"#, true)).await;
        assert_eq!(response.status(), StatusCode::OK);
        cookie_of(&response)
    }

    fn with_cookie(mut request: hyper::Request<Body>, cookie: &str) -> hyper::Request<Body> {
        request.headers_mut().insert(header::COOKIE, cookie.parse().unwrap());
        request
    }

    async fn json_of(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn actions_need_a_session_and_the_header_and_name_a_known_tunnel() {
        let (app, _) = app().await;
        let response = call(&app, post("/api/tunnels/game-fec/stop", "", true)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let cookie = signed_in(&app).await;
        let response = call(&app, with_cookie(post("/api/tunnels/game-fec/stop", "", false), &cookie)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "no CSRF header");
        for (path, status) in [
            ("/api/tunnels/nothing/stop", StatusCode::NOT_FOUND),
            ("/api/tunnels/game-fec/delete", StatusCode::NOT_FOUND),
            ("/api/tunnels/..%2Fetc/stop", StatusCode::NOT_FOUND),
        ] {
            let response = call(&app, with_cookie(post(path, "", true), &cookie)).await;
            assert_eq!(response.status(), status, "{path}");
        }
        // A GET never changes anything.
        let request = with_cookie(hyper::Request::get("/api/tunnels/game-fec/stop").body(Body::empty()).unwrap(), &cookie);
        assert_ne!(call(&app, request).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_second_path_search_waits_for_the_first() {
        let (app, _) = app().await;
        let cookie = signed_in(&app).await;
        let held = PATH_SEARCH.lock().await;
        let body = r#"{"iran":"local","foreign":"x","iran_ip":"203.0.113.10","foreign_ip":"198.51.100.20"}"#;
        let response = call(&app, with_cookie(post("/api/pathfinder", body, true), &cookie)).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        drop(held);
    }

    /// Cancel needs a session; with no search running it says so and changes nothing.
    #[tokio::test]
    async fn the_path_search_can_be_cancelled() {
        let (app, _) = app().await;
        let cookie = signed_in(&app).await;
        assert_eq!(call(&app, post("/api/pathfinder/cancel", "{}", true)).await.status(), StatusCode::UNAUTHORIZED);
        let idle = json_of(call(&app, with_cookie(post("/api/pathfinder/cancel", "{}", true), &cookie)).await).await;
        assert_eq!(idle, json!({"ok": true, "running": false}));
        // A search that is waiting is woken by Cancel.
        let waiting = PATH_CANCEL.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        PATH_CANCEL.notify_waiters();
        tokio::time::timeout(Duration::from_secs(1), waiting).await.expect("Cancel reaches the search");
    }

    /// Only safe display names are kept; empty means the server's own name again.
    #[test]
    fn server_names_are_checked() {
        assert_eq!(server_label("  Tehran   game (2) "), Ok(Some("Tehran game (2)".into())));
        assert_eq!(server_label("سرور ایران"), Ok(Some("سرور ایران".into())));
        assert_eq!(server_label("   "), Ok(None));
        for bad in ["<b>x</b>", "a\"b", "a\\b", "x&y", "line\u{7}", &"n".repeat(41)] {
            assert_eq!(server_label(bad), Err(()), "{bad:?}");
        }
    }

    /// Renaming needs a session, refuses bad names and unknown servers, and shows the new name.
    #[tokio::test]
    async fn this_server_can_be_renamed() {
        let (app, _) = app().await;
        let cookie = signed_in(&app).await;
        let rename = |id: &str, body: &str| post(&format!("/api/servers/{id}/name"), body, true);
        assert_eq!(call(&app, rename("local", r#"{"name":"x"}"#)).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, with_cookie(rename("local", r#"{"name":"<x>"}"#), &cookie)).await.status(), StatusCode::BAD_REQUEST);
        let renamed = json_of(call(&app, with_cookie(rename("local", r#"{"name":"Iran edge"}"#), &cookie)).await).await;
        assert_eq!(renamed, json!({"ok": true, "name": "Iran edge"}));
        let listed = json_of(call(&app, with_cookie(hyper::Request::get("/api/servers").body(Body::empty()).unwrap(), &cookie)).await).await;
        assert_eq!(listed["local_name"], "Iran edge");
        let cleared = json_of(call(&app, with_cookie(rename("local", r#"{"name":""}"#), &cookie)).await).await;
        assert_eq!(cleared, json!({"ok": true, "name": null}));
        let listed = json_of(call(&app, with_cookie(hyper::Request::get("/api/servers").body(Body::empty()).unwrap(), &cookie)).await).await;
        assert_eq!(listed["local_name"], Value::Null);
    }

    #[tokio::test]
    async fn stop_and_start_report_what_they_did() {
        let (app, state) = app().await;
        let cookie = signed_in(&app).await;
        let stop = || with_cookie(post("/api/tunnels/game-fec/stop", "", true), &cookie);
        let answer = json_of(call(&app, stop()).await).await;
        assert_eq!(answer, json!({"ok": true, "changed": true, "came_up": null}));
        let answer = json_of(call(&app, stop()).await).await;
        assert_eq!(answer["changed"], false, "already stopped");
        let start = with_cookie(post("/api/tunnels/game-fec/start", "", true), &cookie);
        let answer = json_of(call(&app, start).await).await;
        assert_eq!(answer, json!({"ok": true, "changed": true, "came_up": true}));
        assert!(state.busy.lock().unwrap().is_empty(), "nothing left marked busy");
    }

    #[tokio::test]
    async fn an_action_under_way_blocks_another_on_the_same_tunnel() {
        let (app, state) = app().await;
        let cookie = signed_in(&app).await;
        let held = Busy::take(&state, vec!["game-fec".into()]).unwrap();
        let response = call(&app, with_cookie(post("/api/tunnels/game-fec/restart", "", true), &cookie)).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = call(&app, with_cookie(post("/api/restart-all", "", true), &cookie)).await;
        assert_eq!(response.status(), StatusCode::CONFLICT, "restart all waits for single actions");
        let response = call(&app, with_cookie(post("/api/tunnels/backup-tcp/start", "", true), &cookie)).await;
        assert_eq!(response.status(), StatusCode::OK, "other tunnels are free");
        drop(held);
        let all = Busy::take(&state, vec![ALL.into()]).unwrap();
        let response = call(&app, with_cookie(post("/api/tunnels/backup-tcp/stop", "", true), &cookie)).await;
        assert_eq!(response.status(), StatusCode::CONFLICT, "nothing runs during restart all");
        drop(all);
    }

    #[tokio::test]
    async fn restart_all_restarts_every_tunnel_and_says_how_each_went() {
        let (app, _) = app().await;
        let cookie = signed_in(&app).await;
        let answer = json_of(call(&app, with_cookie(post("/api/restart-all", "", true), &cookie)).await).await;
        assert_eq!(answer["ok"], true);
        let names: Vec<&str> = answer["results"].as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["game-fec", "backup-tcp"]);
        assert!(answer["results"].as_array().unwrap().iter().all(|r| r["came_up"] == true));
    }

    #[tokio::test]
    async fn settings_are_read_and_saved_for_known_tunnels_with_the_header() {
        let (app, state) = app().await;
        let cookie = signed_in(&app).await;
        let get = with_cookie(hyper::Request::get("/api/tunnels/game-fec/settings").body(Body::empty()).unwrap(), &cookie);
        let screen = json_of(call(&app, get).await).await;
        assert_eq!(screen["ports"]["text"], "9392");
        let save = |body: &str, marked: bool| with_cookie(post("/api/tunnels/game-fec/settings", body, marked), &cookie);
        assert_eq!(call(&app, save(r#"{"ports":{"text":"9392, 9393","protocol":"both"}}"#, false)).await.status(), StatusCode::FORBIDDEN);
        let answer = json_of(call(&app, save(r#"{"ports":{"text":"9392, 9393","protocol":"both"}}"#, true)).await).await;
        assert_eq!(answer["came_up"], true);
        assert_eq!(call(&app, save(r#"{"ports":{"text":"not a port","protocol":"tcp"}}"#, true)).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(call(&app, save("[1,2]", true)).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(call(&app, with_cookie(post("/api/tunnels/nothing/settings", "{}", true), &cookie)).await.status(), StatusCode::NOT_FOUND);
        let held = Busy::take(&state, vec!["game-fec".into()]).unwrap();
        assert_eq!(call(&app, save("{}", true)).await.status(), StatusCode::CONFLICT);
        drop(held);
        let undo = json_of(call(&app, with_cookie(post("/api/tunnels/game-fec/undo", "", true), &cookie)).await).await;
        assert_eq!(undo["changed"], true);
        let events = state.audit.recent(3);
        assert!(events.iter().any(|e| e["detail"] == "edit game-fec ports"), "{events:?}");
    }

    #[tokio::test]
    async fn a_tunnel_is_deleted_only_when_signed_in_marked_known_and_free() {
        let (app, state) = app().await;
        let cookie = signed_in(&app).await;
        let delete = |path: &str, marked: bool| {
            let mut builder = hyper::Request::delete(path);
            if marked {
                builder = builder.header(CSRF_HEADER, "1");
            }
            with_cookie(builder.body(Body::empty()).unwrap(), &cookie)
        };
        assert_eq!(call(&app, delete("/api/tunnels/backup-tcp", false)).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(call(&app, delete("/api/tunnels/nothing", true)).await.status(), StatusCode::NOT_FOUND);
        let held = Busy::take(&state, vec!["backup-tcp".into()]).unwrap();
        assert_eq!(call(&app, delete("/api/tunnels/backup-tcp", true)).await.status(), StatusCode::CONFLICT);
        drop(held);
        // Without a server list, the server form of the path means this server.
        let answer = json_of(call(&app, delete("/api/servers/local/tunnels/backup-tcp", true)).await).await;
        assert_eq!(answer["ok"], true);
        assert!(!tunnel_names(&state).await.contains(&"backup-tcp".to_string()));
        assert_eq!(call(&app, delete("/api/tunnels/backup-tcp", true)).await.status(), StatusCode::NOT_FOUND);
        let events = state.audit.recent(3);
        assert!(events.iter().any(|e| e["detail"] == "delete backup-tcp"), "{events:?}");
        let unsigned = hyper::Request::delete("/api/tunnels/game-fec").header(CSRF_HEADER, "1").body(Body::empty()).unwrap();
        assert_eq!(call(&app, unsigned).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_delete_with_a_pair_spares_a_tunnel_made_again_under_its_name() {
        let (app, state) = app().await;
        let cookie = signed_in(&app).await;
        let form = json!({"name": "web", "transport": "tcp", "address": "192.0.2.1", "ports": "8080"});
        let first = super::super::wizard::build(&form).unwrap().foreign;
        let second = super::super::wizard::build(&form).unwrap().foreign;
        let (old, new) = (super::super::data::pair_of(&first).unwrap(), super::super::data::pair_of(&second).unwrap());
        state.ops.create("web", &first).unwrap();
        state.ops.delete("web").unwrap();
        state.ops.create("web", &second).unwrap();
        let delete = |body: &str| {
            let request = hyper::Request::delete("/api/tunnels/web").header(CSRF_HEADER, "1").header(header::CONTENT_TYPE, "application/json");
            with_cookie(request.body(Body::from(body.to_string())).unwrap(), &cookie)
        };
        let refused = call(&app, delete(&json!({"pair": old}).to_string())).await;
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        assert_eq!(json_of(refused).await["error"], "pair_changed");
        for bad in [r#"{"pair": "zz"}"#, r#"{"pair": 5}"#, "[1]", "not json"] {
            assert_eq!(call(&app, delete(bad)).await.status(), StatusCode::BAD_REQUEST, "{bad}");
        }
        assert!(tunnel_names(&state).await.contains(&"web".to_string()), "nothing was deleted");
        let answer = call(&app, delete(&json!({"pair": new.to_uppercase()}).to_string())).await;
        assert_eq!(answer.status(), StatusCode::OK);
        assert!(!tunnel_names(&state).await.contains(&"web".to_string()));
    }

    #[test]
    fn coded_failures_get_their_own_status_and_others_keep_theirs() {
        let cases = [
            ("unknown_tunnel", StatusCode::NOT_FOUND),
            ("busy", StatusCode::CONFLICT),
            ("pair_changed", StatusCode::CONFLICT),
            ("offline", StatusCode::BAD_GATEWAY),
            ("timeout", StatusCode::GATEWAY_TIMEOUT),
        ];
        for (code, status) in cases {
            assert_eq!(failure_response(&ops::refused(code, "words"), StatusCode::BAD_REQUEST).status(), status, "{code}");
        }
        let busy = anyhow::Error::from(crate::manager::store::Busy("t".into())).context("nothing was changed");
        assert_eq!(failure_response(&busy, StatusCode::BAD_REQUEST).status(), StatusCode::CONFLICT);
        assert_eq!(failure_response(&anyhow::anyhow!("plain"), StatusCode::BAD_REQUEST).status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_new_tunnel_is_built_checked_and_refused_when_taken() {
        let (app, state) = app().await;
        let cookie = signed_in(&app).await;
        let create = |body: Value, marked: bool| with_cookie(post("/api/new-tunnel", &body.to_string(), marked), &cookie);
        let form = json!({"name": "new-game", "iran": "local", "foreign": "a1b2c3d4e5f6", "transport": "tcp",
                          "direction": "reverse", "address": "203.0.113.10", "carry": "ports", "ports": "9393", "protocol": "both"});
        assert_eq!(call(&app, create(form.clone(), false)).await.status(), StatusCode::FORBIDDEN);
        let options = json_of(call(&app, with_cookie(hyper::Request::get("/api/new-tunnel").body(Body::empty()).unwrap(), &cookie)).await).await;
        assert_eq!(options["transports"][0]["name"], "tcp");
        let answer = json_of(call(&app, create(form.clone(), true)).await).await;
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["iran"]["came_up"], true);
        assert!(tunnel_names(&state).await.contains(&"new-game".to_string()));
        // The name is taken now; the same server twice and a machine-specific carrier are refused.
        assert_eq!(call(&app, create(form.clone(), true)).await.status(), StatusCode::CONFLICT);
        let mut same = form.clone();
        same["foreign"] = json!("local");
        same["name"] = json!("other");
        assert_eq!(call(&app, create(same, true)).await.status(), StatusCode::BAD_REQUEST);
        let mut raw = form.clone();
        raw["name"] = json!("other");
        raw["transport"] = json!("fec-raw");
        assert_eq!(call(&app, create(raw, true)).await.status(), StatusCode::BAD_REQUEST);
        let events = state.audit.recent(5);
        assert!(events.iter().any(|e| e["detail"].as_str().unwrap_or("").starts_with("create new-game (tcp;")), "{events:?}");
    }

    #[tokio::test]
    async fn tunnel_tools_answer_and_unknown_ones_are_refused() {
        let (app, state) = app().await;
        let cookie = signed_in(&app).await;
        let get = |path: &str| with_cookie(hyper::Request::get(path).body(Body::empty()).unwrap(), &cookie);
        let status = json_of(call(&app, get("/api/tunnels/game-fec/status")).await).await;
        assert_eq!(status["sessions"], 4);
        assert_eq!(call(&app, get("/api/tunnels/nothing/status")).await.status(), StatusCode::NOT_FOUND);
        let tool = |op: &str, body: &str| with_cookie(post(&format!("/api/tunnels/game-fec/tools/{op}"), body, true), &cookie);
        let speed = json_of(call(&app, tool("speedtest", r#"{"direction":"down","bytes":1048576,"streams":1}"#)).await).await;
        assert!(speed["bytes_per_second"].as_f64().unwrap() > 0.0, "{speed}");
        assert_eq!(call(&app, tool("speedtest", r#"{"bytes":5}"#)).await.status(), StatusCode::BAD_REQUEST);
        let ask = json_of(call(&app, tool("pairing", "")).await).await;
        assert_eq!(ask["needs_address"], true);
        let code = json_of(call(&app, tool("pairing", r#"{"address":"203.0.113.10"}"#)).await).await;
        assert!(code["code"].is_string(), "{code}");
        assert_eq!(call(&app, tool("quota_reset", "")).await.status(), StatusCode::OK);
        assert_eq!(call(&app, tool("shell", "")).await.status(), StatusCode::NOT_FOUND);
        let unmarked = with_cookie(post("/api/tunnels/game-fec/tools/quota_reset", "", false), &cookie);
        assert_eq!(call(&app, unmarked).await.status(), StatusCode::FORBIDDEN);
        let events = state.audit.recent(6);
        assert!(events.iter().any(|e| e["detail"] == "pairing code game-fec"), "{events:?}");
    }

    #[tokio::test]
    async fn server_tools_and_the_transport_check_answer() {
        let (app, state) = app().await;
        let cookie = signed_in(&app).await;
        let tool = |name: &str, body: &str| with_cookie(post(&format!("/api/servers/local/tools/{name}"), body, true), &cookie);
        let health = json_of(call(&app, tool("health", "")).await).await;
        assert!(health["checks"].as_array().unwrap().iter().any(|c| c["id"] == "optimize"), "{health}");
        let plan = json_of(call(&app, tool("optimize_plan", "")).await).await;
        assert_eq!(plan["applied"], false);
        assert_eq!(json_of(call(&app, tool("optimize_apply", "")).await).await["done"], true);
        assert_eq!(json_of(call(&app, tool("optimize_plan", "")).await).await["applied"], true);
        assert!(json_of(call(&app, tool("files", "")).await).await["files"].as_array().unwrap().len() > 3);
        assert_eq!(call(&app, tool("shell", "")).await.status(), StatusCode::NOT_FOUND);
        let fixed = json_of(call(&app, tool("fix", r#"{"fix":"start:backup-tcp"}"#)).await).await;
        assert_eq!(fixed["done"], true);
        // The transport check: start, progress, stop.
        let start = with_cookie(post("/api/conntest", r#"{"iran":"local","foreign":"a1b2c3d4e5f6","iran_ip":"203.0.113.10","foreign_ip":"198.51.100.20","preset":"quick"}"#, true), &cookie);
        assert_eq!(json_of(call(&app, start).await).await["ok"], true);
        let progress = json_of(call(&app, with_cookie(hyper::Request::get("/api/conntest").body(Body::empty()).unwrap(), &cookie)).await).await;
        assert_eq!(progress["state"], "running", "{progress}");
        let bad = with_cookie(post("/api/conntest", r#"{"iran":"local","foreign":"local","iran_ip":"203.0.113.10","foreign_ip":"198.51.100.20"}"#, true), &cookie);
        assert_eq!(call(&app, bad).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_of(call(&app, with_cookie(post("/api/conntest/stop", "", true), &cookie)).await).await["ok"], true);
        let events = state.audit.recent(10);
        assert!(events.iter().any(|e| e["detail"] == "optimize the kernel settings"), "{events:?}");
    }

    #[tokio::test]
    async fn releases_and_backups_are_kept_listed_and_restored() {
        let (app, state) = app().await;
        let _ = std::fs::remove_dir_all(&state.state_dir);
        let cookie = signed_in(&app).await;
        let get = |path: &str| with_cookie(hyper::Request::get(path).body(Body::empty()).unwrap(), &cookie);
        assert_eq!(json_of(call(&app, get("/api/releases")).await).await["kept"], json!([]));
        assert_eq!(json_of(call(&app, with_cookie(post("/api/releases/check", "", true), &cookie)).await).await["version"], "0.9.15");
        let upload = with_cookie(post("/api/releases/upload", "not a program", true), &cookie);
        assert_eq!(call(&app, upload).await.status(), StatusCode::BAD_REQUEST);
        let versions = json_of(call(&app, with_cookie(post("/api/servers/local/tools/versions", "", true), &cookie)).await).await;
        assert!(versions["installed"].is_string());
        // Back up now, then list, download, restore and delete.
        let made = json_of(call(&app, with_cookie(post("/api/backups", "", true), &cookie)).await).await;
        let file = made["results"][0]["file"].as_str().unwrap().to_string();
        let list = json_of(call(&app, get("/api/backups")).await).await;
        assert_eq!(list["backups"][0]["file"], file.as_str());
        let download = call(&app, get(&format!("/api/backups/{file}"))).await;
        assert_eq!(download.status(), StatusCode::OK);
        assert_eq!(call(&app, get("/api/backups/..%2Fsecret.json")).await.status(), StatusCode::NOT_FOUND);
        let restore = with_cookie(post("/api/servers/local/restore", &json!({"file": file}).to_string(), true), &cookie);
        assert!(json_of(call(&app, restore).await).await["skipped"].is_array());
        let delete = with_cookie(hyper::Request::delete(format!("/api/backups/{file}")).header(CSRF_HEADER, "1").body(Body::empty()).unwrap(), &cookie);
        assert_eq!(call(&app, delete).await.status(), StatusCode::OK);
        assert_eq!(json_of(call(&app, get("/api/backups")).await).await["backups"], json!([]));
        let events = state.audit.recent(10);
        assert!(events.iter().any(|e| e["detail"].as_str().unwrap_or("").starts_with("download backup")), "{events:?}");
        let _ = std::fs::remove_dir_all(&state.state_dir);
    }

    #[tokio::test]
    async fn settings_password_sessions_alerts_and_metrics() {
        let (app, state) = app().await;
        let _ = std::fs::remove_dir_all(&state.state_dir);
        let cookie = signed_in(&app).await;
        let other = signed_in(&app).await;
        let get = |path: &str, cookie: &str| with_cookie(hyper::Request::get(path).body(Body::empty()).unwrap(), cookie);
        let settings = json_of(call(&app, get("/api/settings", &cookie)).await).await;
        assert_eq!(settings["prefs"]["auto_backup_days"], 7);
        let changed = json_of(call(&app, with_cookie(post("/api/settings", r#"{"auto_backup_days":3,"metrics":true}"#, true), &cookie)).await).await;
        let token = changed["metrics_token"].as_str().unwrap().to_string();
        assert_eq!(changed["prefs"]["auto_backup_days"], 3);
        assert_eq!(call(&app, with_cookie(post("/api/settings", r#"{"proxy":"ftp://x"}"#, true), &cookie)).await.status(), StatusCode::BAD_REQUEST);
        // Metrics need the token.
        assert_eq!(call(&app, hyper::Request::get("/metrics").body(Body::empty()).unwrap()).await.status(), StatusCode::UNAUTHORIZED);
        let with_token = hyper::Request::get("/metrics").header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap();
        let response = call(&app, with_token).await;
        assert_eq!(response.status(), StatusCode::OK);
        let text = String::from_utf8(axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
        assert!(text.contains("eztunnel_alerts_active"), "{text}");
        // Sessions: two, and the other one can be ended.
        let sessions = json_of(call(&app, get("/api/sessions", &cookie)).await).await;
        assert_eq!(sessions["sessions"].as_array().unwrap().len(), 2);
        let ended = json_of(call(&app, with_cookie(post("/api/sessions/revoke", r#"{"id":"others"}"#, true), &cookie)).await).await;
        assert_eq!(ended["ended"], 1);
        assert_eq!(call(&app, get("/api/sessions", &other)).await.status(), StatusCode::UNAUTHORIZED);
        // Password: the current one is required.
        assert_eq!(call(&app, with_cookie(post("/api/password", r#"{"current":"nope","new":"a long new password"}"#, true), &cookie)).await.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_of(call(&app, with_cookie(post("/api/password", r#"{"current":"pw","new":"a long new password"}"#, true), &cookie)).await).await["ok"], true);
        // Alerts: two looks fire what the demo reports; the list shows them.
        alert_look(&state).await;
        alert_look(&state).await;
        let alerts = json_of(call(&app, get("/api/alerts", &cookie)).await).await;
        assert!(!alerts["active"].as_array().unwrap().is_empty(), "{alerts}");
        assert!(!alerts["history"].as_array().unwrap().is_empty());
        // Telegram: the saved bot shows by its public id only; a test checks the form's values
        // first; the last delivery is shown once there was one.
        let saved = json_of(call(&app, with_cookie(post("/api/settings", r#"{"telegram":{"token":"123456:abc_DEF-1","chats":[42]}}"#, true), &cookie)).await).await;
        assert_eq!(saved["prefs"]["telegram"]["bot_id"], "123456");
        assert!(!saved.to_string().contains("abc_DEF"), "{saved}");
        let refused = call(&app, with_cookie(post("/api/alerts/test", r#"{"telegram":{"token":"not a token"}}"#, true), &cookie)).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(json_of(refused).await["detail"].as_str().unwrap().contains("bot token"));
        assert_eq!(json_of(call(&app, get("/api/settings", &cookie)).await).await["telegram_last"], Value::Null);
        super::super::alerts::record_delivery(&state.state_dir, "test", &Err(anyhow::anyhow!("chat 42: Telegram says: Bad Request: chat not found")));
        let last = json_of(call(&app, get("/api/settings", &cookie)).await).await["telegram_last"].clone();
        assert_eq!((last["kind"].as_str(), last["ok"].as_bool()), (Some("test"), Some(false)));
        assert!(last["detail"].as_str().unwrap().contains("chat not found"));
        let _ = std::fs::remove_dir_all(&state.state_dir);
    }

    #[tokio::test]
    async fn the_join_script_is_public_and_the_command_pins_the_certificate() {
        let (app, state) = app().await;
        let response = call(&app, hyper::Request::get("/join.sh").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let script = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(script.starts_with("#!/usr/bin/env bash") && script.contains("agent join"));
        assert!(script.contains("--prefix"), "tries the release before installing it");
        assert!(join_command(&state.public, None, "ezj1-x").starts_with("s=$(curl -fsSL http://203.0.113.10:38471/join.sh) && bash -c \"$s\" join.sh ezj1-x"));
        let dir = tempfile::tempdir().unwrap();
        let swap = super::super::tls::Swap::self_signed(dir.path(), "203.0.113.10").unwrap();
        let command = join_command(&("2001:db8::1".into(), 443), Some(&swap), "ezj1-x");
        assert!(command.contains("--pinnedpubkey 'sha256//"), "{command}");
        assert!(command.contains("https://[2001:db8::1]:443/join.sh) && bash -c \"$s\" join.sh ezj1-x"), "{command}");
    }

    #[tokio::test]
    async fn activity_lists_sign_ins_and_actions_newest_first_for_signed_in_users() {
        let (app, _) = app().await;
        let request = hyper::Request::get("/api/activity").body(Body::empty()).unwrap();
        assert_eq!(call(&app, request).await.status(), StatusCode::UNAUTHORIZED);
        let wrong = call(&app, post("/api/login", r#"{"password":"no"}"#, true)).await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let cookie = signed_in(&app).await;
        call(&app, with_cookie(post("/api/tunnels/game-fec/stop", "", true), &cookie)).await;
        let get = with_cookie(hyper::Request::get("/api/activity?limit=3").body(Body::empty()).unwrap(), &cookie);
        let answer = json_of(call(&app, get).await).await;
        let events: Vec<(&str, &str)> = answer["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["event"].as_str().unwrap(), e["detail"].as_str().unwrap()))
            .collect();
        assert_eq!(events, [("action", "stop game-fec"), ("login", "signed in"), ("login_failed", "wrong password")]);
    }

    #[tokio::test]
    async fn logs_are_read_for_known_tunnels_only_and_live_logs_are_limited() {
        let (app, state) = app().await;
        let cookie = signed_in(&app).await;
        let get = |path: &str| with_cookie(hyper::Request::get(path).body(Body::empty()).unwrap(), &cookie);
        let answer = json_of(call(&app, get("/api/tunnels/game-fec/logs?lines=5")).await).await;
        assert_eq!(answer["lines"].as_array().unwrap().len(), 5);
        assert_eq!(call(&app, get("/api/tunnels/nothing/logs")).await.status(), StatusCode::NOT_FOUND);
        let response = call(&app, hyper::Request::get("/api/tunnels/game-fec/logs").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = call(&app, get("/api/tunnels/game-fec/logs/follow")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/event-stream"));
        let taken = state.followers.clone().try_acquire_many_owned(MAX_FOLLOWERS as u32 - 1).unwrap();
        assert_eq!(call(&app, get("/api/tunnels/game-fec/logs/follow")).await.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(response);
        drop(taken);
        assert_eq!(call(&app, get("/api/tunnels/game-fec/logs/follow")).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn data_needs_a_session_and_sign_in_needs_the_header() {
        let (app, _) = app().await;
        let response = call(&app, hyper::Request::get("/api/snapshot").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("content-security-policy"));

        let response = call(&app, post("/api/login", r#"{"password":"pw"}"#, false)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "no CSRF header");

        let response = call(&app, post("/api/login", r#"{"password":"no"}"#, true)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = call(&app, post("/api/login", r#"{"password":"pw"}"#, true)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let set = response.headers()[header::SET_COOKIE].to_str().unwrap().to_string();
        assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict"));
        let cookie = cookie_of(&response);

        let request = hyper::Request::get("/api/snapshot")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let response = call(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");

        let request = hyper::Request::get("/api/history?range=7d&series=all&tz=210")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(&app, request).await.status(), StatusCode::OK);
        let request = hyper::Request::get("/api/history?range=forever&series=all")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(&app, request).await.status(), StatusCode::BAD_REQUEST);

        let mut request = post("/api/logout", "", true);
        request.headers_mut().insert(header::COOKIE, cookie.parse().unwrap());
        call(&app, request).await;
        let request = hyper::Request::get("/api/snapshot")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(&app, request).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_request_from_another_site_is_refused() {
        let (app, _) = app().await;
        let mut request = post("/api/login", r#"{"password":"pw"}"#, true);
        request.headers_mut().insert(header::HOST, "127.0.0.1:1".parse().unwrap());
        request
            .headers_mut()
            .insert(header::ORIGIN, "http://evil.example".parse().unwrap());
        assert_eq!(call(&app, request).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn the_page_is_served_for_any_route_and_unknown_api_paths_are_not_found() {
        let (app, _) = app().await;
        let response = call(&app, hyper::Request::get("/").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/html"));
        let response = call(&app, hyper::Request::get("/api/nothing").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
