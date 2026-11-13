//! The HTTP side: sign-in, the JSON API, live updates (Server-Sent Events) and the UI files.
use super::{assets, audit::Audit, auth, data::Live};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::Semaphore,
};

/// Connections served at once; more wait in the kernel's queue.
const MAX_CONNECTIONS: usize = 256;
/// A request body (only sign-in sends one) may not be larger than this.
const MAX_BODY: usize = 8 * 1024;
/// The header every state-changing request must carry. Browsers do not let other sites set it
/// without the dashboard's permission, which it never gives.
const CSRF_HEADER: &str = "x-eztunnel";

pub struct AppState {
    pub history: Arc<super::history::History>,
    pub auth: auth::Auth,
    pub audit: Audit,
    pub live: Arc<Live>,
    pub demo: bool,
    /// HTTPS: cookies are marked Secure and carry the __Host- prefix.
    pub secure: bool,
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
        .route("/api/history", get(history));
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
    let Ok(bytes) = axum::body::to_bytes(request.into_body(), MAX_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let Ok(body) = serde_json::from_slice::<LoginBody>(&bytes) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad_request"}))).into_response();
    };
    let Some(ip) = ip else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if body.password.is_empty() || body.password.len() > 256 {
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
            state.audit.record(Some(ip), "login_refused", &format!("locked for {seconds} s"));
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
    let history = state.history.clone();
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
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn app() -> (Router, Arc<AppState>) {
        let state = Arc::new(AppState {
            history: Arc::new(super::super::history::History::new(Box::new(super::super::history::DemoStore {
                tunnels: vec![("game-fec", 1e6, true)],
                started_minute: 30_000_000,
            }))),
            auth: auth::Auth::new(auth::hash_password("pw").unwrap()),
            audit: Audit::disabled(),
            live: Live::start(Box::new(super::super::data::DemoSource::new()), None),
            demo: true,
            secure: false,
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
