//! `GET /agent` on the app port (plan S6): the WebSocket upgrade, `hello`,
//! and one connection task per socket.
//!
//! - **Upgrade**, in this order: the peer guard (middleware); draining → 503
//!   `draining`; `/run` not seen → 503 `not_run` with `Retry-After: 1`;
//!   [`MAX_UNAUTHENTICATED`] sockets without a completed hello → 503 `busy`;
//!   then axum 0.8.9's checks, done here by hand (axum is built without
//!   `ws`) — non-GET 405; `Connection` (a token list: it must contain
//!   `upgrade` and must not contain `close`, which would make hyper rewrite
//!   the 101 to a header the client refuses), `Upgrade: websocket`,
//!   `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`, each 400; no hyper
//!   `OnUpgrade` (an HTTP/1.0 request) 426 — then 101 with `Connection:
//!   upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Accept`, never
//!   `Sec-WebSocket-Protocol`, and `WebSocketStream::from_raw_socket(Role::Server,
//!   wire::frame::ws_config())`. Every refusal reads the request body first
//!   (`peer::drain`), so the client gets it, not a reset. Each attempt logs
//!   one line: the connection id (101 only), the status, the peer and its
//!   uid when the guard looked it up, the HTTP version and the request's
//!   header NAMES.
//! - **Hello** within [`HELLO_DEADLINE`] of the upgrade (else Close 4408):
//!   no `/run` payload → `hello_err no_commitment` + 4403; a token that does
//!   not match the commitment (`RunHookPayload::matches`) → `hello_err
//!   bad_token` + 4403; an unknown `v` → `hello_err version` + 4426; else
//!   `SpawnManager::attach(resume)` and `hello_ok` (status from
//!   `SpawnManager::status`, taken after the attach), then the outbox replays.
//! - **Connection task**: the reader never awaits a spawn for long (only
//!   `SpawnManager::spawn`, which is bounded, is async); the writer is its own
//!   task and sends one frame at a time — control first (hello_ok, spawned,
//!   spawn_err, pong, error, in the reader's order), then the spawn
//!   manager's [`Outbox`] — each send bounded by [`SEND_TIMEOUT`]. A spawn's
//!   own outbox frames never go before its `spawned` (`Unannounced`). The
//!   reader waits for room in the control queue only until the hello
//!   deadline, then the idle one: a client that sends but reads nothing is
//!   dropped then (no Close can reach it), not after a send timeout. A binary
//!   message gets `error binary_rejected` (the socket stays up); malformed
//!   JSON, or a text over [`CONTROL_FRAME_MAX`] (no v1 frame is larger),
//!   `error bad_frame` + Close 1008; an unknown `t` `error unknown_frame`
//!   (ignored); a message over the 16 MiB cap Close 1009, then a half-close
//!   and a bounded drain of the raw stream so the client reads the Close
//!   instead of a reset (critic L2). No inbound frame for `idle_s` → Close
//!   1001. Once past hello, a socket that ends for any reason →
//!   `SpawnManager::connection_lost` (spawns detached deliberately are no
//!   longer attached to it).
//! - **Registry**: every connection gets a generation ([`ConnGen`]);
//!   [`AgentRegistry::close_all_with`] (stop, `/suspend`, `/terminate`) sends
//!   an optional event to the sockets past hello, then Close with its code,
//!   to every socket, and waits at most 1 s.
//!
//! Logging is lifecycle only: never a frame body, a token or an argument.
use crate::shim::health::ShimState;
use crate::shim::peer::{drain, Peer, PeerFacts};
pub use crate::shim::spawn::ConnGen;
use crate::shim::spawn::{Outbox, SpawnRequest};
use crate::wire::frame::{
    ClientInfo, ErrorCode, Frame, HelloErrCode, ResumePoint, SpawnId, WireError, CLOSE_GOING_AWAY, CLOSE_HELLO_DEADLINE, CLOSE_HELLO_REFUSED, CLOSE_PROTOCOL, CLOSE_TOO_BIG, CLOSE_WIRE_VERSION, CONTROL_FRAME_MAX, HELLO_DEADLINE, IDLE_DEFAULT_S,
    IDLE_MAX_S, IDLE_MIN_S, MAX_UNAUTHENTICATED, SEND_TIMEOUT, WIRE_VERSION, WS_MAX_MESSAGE,
};
use crate::wire::redact::Secret;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

/// How long [`AgentRegistry::close_all_with`] waits for the sockets to go.
pub const CLOSE_ALL_WAIT: Duration = Duration::from_secs(1);
/// After the shim's Close, how long the client gets to answer with its own.
const CLOSE_LINGER: Duration = Duration::from_secs(1);
/// A reader-initiated close's budget (the queued frames, then Close).
const CLOSE_BUDGET: Duration = Duration::from_secs(2);
/// After a stream error (a message over the cap), what is read and dropped
/// from the raw socket before closing it: just over one maximal message, or
/// this long.
const DRAIN_BYTES: usize = WS_MAX_MESSAGE + 1024 * 1024;
const DRAIN_FOR: Duration = Duration::from_secs(2);
/// Control frames the reader may queue ahead of the writer.
const CONTROL_QUEUE: usize = 64;
/// Longest client name or version a log line shows.
const LOG_FIELD_MAX: usize = 64;

/// The connection's timers; tests shorten them.
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// `hello` must arrive this soon after the upgrade.
    hello: Duration,
    /// One second of `hello.idle_s`.
    idle_unit: Duration,
    send: Duration,
}

impl Timing {
    const LIVE: Timing = Timing { hello: HELLO_DEADLINE, idle_unit: Duration::from_secs(1), send: SEND_TIMEOUT };
}

// ---- registry ---------------------------------------------------------------------------

/// A close the registry asks of one socket (stop, `/suspend`, `/terminate`).
#[derive(Debug, Clone)]
struct CloseReq {
    code: u16,
    reason: String,
    /// Sent first, to sockets past hello only.
    event: Option<Frame>,
    by: Instant,
}

#[derive(Debug)]
struct Entry {
    authenticated: bool,
    close: watch::Sender<Option<CloseReq>>,
}

/// The open `/agent` sockets, from the 101 to the end of their task.
#[derive(Debug, Default)]
pub struct AgentRegistry {
    next: AtomicU64,
    conns: Mutex<BTreeMap<ConnGen, Entry>>,
    /// Notified whenever a socket leaves.
    gone: Notify,
}

impl AgentRegistry {
    #[must_use]
    pub fn new() -> AgentRegistry {
        AgentRegistry::default()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<ConnGen, Entry>> {
        self.conns.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A fresh connection generation (never 0).
    pub fn next_gen(&self) -> ConnGen {
        self.next.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// (open sockets, sockets past hello).
    #[must_use]
    pub fn counts(&self) -> (u32, u32) {
        let conns = self.lock();
        let authenticated = conns.values().filter(|e| e.authenticated).count();
        (u32::try_from(conns.len()).unwrap_or(u32::MAX), u32::try_from(authenticated).unwrap_or(u32::MAX))
    }

    fn unauthenticated(conns: &BTreeMap<ConnGen, Entry>) -> usize {
        conns.values().filter(|e| !e.authenticated).count()
    }

    /// A place for a new socket, or why not (`draining`, `busy`). `draining`
    /// is read under the registry's lock, so a socket either sees it or is
    /// in the set a later `close_all` closes.
    fn reserve(&self, draining: impl Fn() -> bool) -> Result<(ConnGen, watch::Receiver<Option<CloseReq>>), &'static str> {
        let mut conns = self.lock();
        if draining() {
            return Err("draining");
        }
        if Self::unauthenticated(&conns) >= MAX_UNAUTHENTICATED {
            return Err("busy");
        }
        let gen = self.next_gen();
        let (tx, rx) = watch::channel(None);
        conns.insert(gen, Entry { authenticated: false, close: tx });
        Ok((gen, rx))
    }

    fn authenticate(&self, gen: ConnGen) {
        if let Some(e) = self.lock().get_mut(&gen) {
            e.authenticated = true;
        }
    }

    fn release(&self, gen: ConnGen) {
        self.lock().remove(&gen);
        self.gone.notify_waiters();
    }

    /// Close every socket with `code` (stop); at most [`CLOSE_ALL_WAIT`].
    pub async fn close_all(&self, code: u16, reason: &str) {
        self.close_all_with(code, reason, None).await;
    }

    /// Close every socket with `code`, sending `event` first to each socket
    /// past hello (`/suspend`, `/terminate`), and wait until they are gone or
    /// [`CLOSE_ALL_WAIT`] passed.
    pub async fn close_all_with(&self, code: u16, reason: &str, event: Option<Frame>) {
        let by = Instant::now() + CLOSE_ALL_WAIT;
        let gens: Vec<ConnGen> = {
            let conns = self.lock();
            for e in conns.values() {
                e.close.send_replace(Some(CloseReq { code, reason: reason.to_string(), event: event.clone(), by }));
            }
            conns.keys().copied().collect()
        };
        if gens.is_empty() {
            return;
        }
        errln!("ai-env: agent close_all code={code} reason={reason} sockets={}", gens.len());
        loop {
            let gone = self.gone.notified();
            tokio::pin!(gone);
            gone.as_mut().enable();
            let left = {
                let conns = self.lock();
                gens.iter().filter(|g| conns.contains_key(g)).count()
            };
            if left == 0 {
                return;
            }
            if tokio::time::timeout_at(by, gone).await.is_err() {
                errln!("ai-env: agent close_all: {left} of {} sockets still open after {} ms", gens.len(), CLOSE_ALL_WAIT.as_millis());
                return;
            }
        }
    }
}

/// A socket's place in the registry, released whatever ends its task.
struct Registration {
    state: Arc<ShimState>,
    gen: ConnGen,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.state.agents.release(self.gen);
    }
}

// ---- upgrade ----------------------------------------------------------------------------

fn status_json(status: StatusCode, name: &'static str) -> Response {
    (status, Json(serde_json::json!({"status": name}))).into_response()
}

/// The `Connection` header as a lowercase token list (every value).
fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers.get_all(header::CONNECTION).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect()
}

/// axum 0.8.9's WebSocket checks, in its order, with `Connection` parsed as
/// a token list (axum tests a substring) and `close` refused: the refusal,
/// if any.
fn handshake_refusal(method: &Method, headers: &HeaderMap) -> Option<Response> {
    if method != Method::GET {
        let mut res = (StatusCode::METHOD_NOT_ALLOWED, "ai-env: /agent takes GET (a WebSocket upgrade)\n").into_response();
        res.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET"));
        return Some(res);
    }
    let tokens = connection_tokens(headers);
    let bad = |text: &'static str| Some((StatusCode::BAD_REQUEST, text).into_response());
    if !tokens.iter().any(|t| t == "upgrade") || tokens.iter().any(|t| t == "close") {
        return bad("ai-env: /agent needs `Connection: upgrade` (and never `close`)\n");
    }
    if !headers.get(header::UPGRADE).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket")) {
        return bad("ai-env: /agent needs `Upgrade: websocket`\n");
    }
    if headers.get(header::SEC_WEBSOCKET_KEY).is_none_or(HeaderValue::is_empty) {
        return bad("ai-env: /agent needs a `Sec-WebSocket-Key`\n");
    }
    if !headers.get(header::SEC_WEBSOCKET_VERSION).is_some_and(|v| v.as_bytes() == b"13") {
        return bad("ai-env: /agent needs `Sec-WebSocket-Version: 13`\n");
    }
    None
}

/// `GET /agent`: the ordered checks, then 101 and the connection task.
pub async fn upgrade(State(state): State<Arc<ShimState>>, mut req: Request) -> Response {
    let conn = req.extensions().get::<ConnectInfo<Peer>>().map(|c| c.0);
    let uid = req.extensions().get::<PeerFacts>().and_then(|f| f.row).map_or("-".to_string(), |(_, r)| r.uid.to_string());
    let names = req.headers().keys().map(|k| k.as_str()).collect::<Vec<_>>().join(",");
    let version = req.version();
    let log = |gen: Option<ConnGen>, status: StatusCode| {
        errln!(
            "ai-env: agent upgrade conn={} status={} peer={} peer_uid={uid} http={version:?} headers={names}",
            gen.map_or("-".to_string(), |g| g.to_string()),
            status.as_u16(),
            conn.map_or("-".to_string(), |c| c.peer.to_string())
        );
    };
    let refusal = if state.is_draining() {
        Some(status_json(StatusCode::SERVICE_UNAVAILABLE, "draining"))
    } else if !state.run.view().seen {
        let mut res = status_json(StatusCode::SERVICE_UNAVAILABLE, "not_run");
        res.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        Some(res)
    } else if AgentRegistry::unauthenticated(&state.agents.lock()) >= MAX_UNAUTHENTICATED {
        Some(status_json(StatusCode::SERVICE_UNAVAILABLE, "busy"))
    } else {
        handshake_refusal(req.method(), req.headers())
    };
    if let Some(res) = refusal {
        log(None, res.status());
        drain(req).await;
        return res;
    }
    let Some(on_upgrade) = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>() else {
        log(None, StatusCode::UPGRADE_REQUIRED);
        drain(req).await;
        return (StatusCode::UPGRADE_REQUIRED, "ai-env: /agent needs an HTTP/1.1 upgrade\n").into_response();
    };
    let accept = req.headers().get(header::SEC_WEBSOCKET_KEY).map(|k| derive_accept_key(k.as_bytes())).and_then(|a| HeaderValue::try_from(a).ok());
    let Some(accept) = accept else {
        log(None, StatusCode::BAD_REQUEST);
        drain(req).await;
        return (StatusCode::BAD_REQUEST, "ai-env: /agent needs a `Sec-WebSocket-Key`\n").into_response();
    };
    let (gen, close_rx) = match state.agents.reserve(|| state.is_draining()) {
        Ok(r) => r,
        Err(why) => {
            log(None, StatusCode::SERVICE_UNAVAILABLE);
            drain(req).await;
            return status_json(StatusCode::SERVICE_UNAVAILABLE, why);
        }
    };
    let reg = Registration { state: state.clone(), gen };
    tokio::spawn(async move {
        let timing = Timing::LIVE;
        let upgraded = match tokio::time::timeout(timing.hello, on_upgrade).await {
            Ok(Ok(u)) => u,
            Ok(Err(e)) => {
                errln!("ai-env: agent conn={gen} upgrade failed: {e}");
                return;
            }
            Err(_) => {
                errln!("ai-env: agent conn={gen} upgrade did not complete within {} s", timing.hello.as_secs());
                return;
            }
        };
        let ws = WebSocketStream::from_raw_socket(hyper_util::rt::TokioIo::new(upgraded), Role::Server, Some(crate::wire::frame::ws_config())).await;
        serve(reg, close_rx, ws, timing).await;
    });
    log(Some(gen), StatusCode::SWITCHING_PROTOCOLS);
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let h = res.headers_mut();
    h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    h.insert(header::SEC_WEBSOCKET_ACCEPT, accept);
    res
}

// ---- connection -------------------------------------------------------------------------

/// What the reader asks of the writer, in order.
enum Cmd {
    Frame(Frame),
    /// A `spawn`'s answer (`spawned` or `spawn_err`): once it is out, the
    /// spawn's outbox frames may follow ([`Unannounced`]).
    Answer(SpawnId, Frame),
    /// hello_ok is queued: from here on the spawn manager's outbox feeds the socket.
    Outbox(Outbox),
    /// Close with this code and reason after everything queued before it.
    Close(u16, &'static str),
}

/// Spawns the reader handed to the spawn manager whose answer is not on the
/// wire yet, with how many answers each still owes (an id may come twice).
/// The reader adds one before the manager can know the spawn; the writer
/// takes it off as it sends the answer and holds the spawn's outbox frames
/// until then, so none goes before its `spawned` (the Mac starts a spawn on
/// that frame), however late the manager returns.
#[derive(Debug, Default)]
struct Unannounced(Mutex<BTreeMap<SpawnId, u32>>);

impl Unannounced {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<SpawnId, u32>> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn add(&self, id: &SpawnId) {
        *self.lock().entry(id.clone()).or_default() += 1;
    }

    /// One answer for `id` is going out.
    fn answered(&self, id: &SpawnId) {
        let mut owed = self.lock();
        match owed.get_mut(id) {
            Some(n) if *n > 1 => *n -= 1,
            Some(_) => {
                owed.remove(id);
            }
            None => {}
        }
    }

    /// `frame` is about a spawn whose answer is not out yet.
    fn holds(&self, frame: &Frame) -> bool {
        frame.spawn_id().is_some_and(|id| self.lock().contains_key(id))
    }
}

/// How the writer stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WriteEnd {
    /// Our Close went out with this code and reason.
    Closed(u16, String),
    /// A send failed or timed out (the reason is a kind, never data).
    Failed(String),
    /// The reader ended first.
    Dropped,
}

type Sink<S> = SplitSink<WebSocketStream<S>, Message>;

/// How the reader stopped.
enum ReadEnd {
    /// The shim asked the writer to close; the stream still reads (the client's Close follows).
    Closing,
    /// A stream error: the writer was asked to close, and only the raw socket can still be read.
    Broken,
    /// The client closed, or the stream ended.
    Ended,
    /// The writer stopped on its own (a registry close, or a failed send).
    WriterDone,
    /// The deadline passed while the control queue was full: the client
    /// reads nothing, so no Close can reach it.
    Stalled,
}

/// What one inbound message leads to.
enum Flow {
    Continue,
    /// A Close was queued.
    Close,
    /// The writer is gone.
    Gone,
    /// The deadline passed while the control queue was full.
    Stalled,
}

/// A client-chosen string as one log word: printable ASCII, at most [`LOG_FIELD_MAX`] characters.
fn loggable(s: &str) -> String {
    let mut out: String = s.chars().take(LOG_FIELD_MAX).map(|c| if c.is_ascii_graphic() { c } else { '?' }).collect();
    if out.is_empty() {
        out.push('-');
    }
    out
}

fn error_text(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::BinaryRejected => "binary messages are not accepted on /agent",
        ErrorCode::BadFrame => "malformed frame",
        ErrorCode::UnknownFrame => "unknown frame kind (ignored)",
        ErrorCode::NotAttached => "the spawn is not attached to this socket",
        ErrorCode::Superseded => "a newer socket attached this spawn",
        ErrorCode::StdinOverflow => "more unacknowledged stdin than the window allows",
        ErrorCode::StdinGap => "a stdin seq skipped ahead",
        ErrorCode::Draining => "the VM is draining",
        ErrorCode::Other => "refused",
    }
}

/// A tungstenite error as a kind: never a payload.
fn ws_error_kind(e: &WsError) -> String {
    match e {
        WsError::Io(io) => format!("io: {:?}", io.kind()),
        WsError::Capacity(_) => "message too big".into(),
        WsError::Protocol(p) => format!("protocol: {p}"),
        WsError::Utf8 => "text is not UTF-8".into(),
        WsError::ConnectionClosed | WsError::AlreadyClosed => "closed".into(),
        _ => "websocket error".into(),
    }
}

/// The reader's side of one socket.
struct Session {
    state: Arc<ShimState>,
    gen: ConnGen,
    tx: mpsc::Sender<Cmd>,
    unannounced: Arc<Unannounced>,
    authenticated: bool,
    idle: Duration,
    idle_unit: Duration,
    /// The hello deadline, then (past hello) the idle one: the reader waits
    /// for an inbound message, and for room in the control queue, until then.
    deadline: Instant,
    /// How the socket ended, for the last log line.
    summary: String,
}

impl Session {
    /// Queue `cmd`, waiting for room at most until the deadline: a client
    /// that reads nothing fills the queue, and must not hold the socket (and,
    /// before hello, a [`MAX_UNAUTHENTICATED`] slot) for a send timeout.
    async fn queue(&self, cmd: Cmd) -> Flow {
        tokio::select! {
            biased;
            r = self.tx.send(cmd) => if r.is_ok() { Flow::Continue } else { Flow::Gone },
            () = tokio::time::sleep_until(self.deadline) => Flow::Stalled,
        }
    }

    async fn send(&self, frame: Frame) -> Flow {
        self.queue(Cmd::Frame(frame)).await
    }

    async fn error(&self, code: ErrorCode, spawn_id: Option<SpawnId>) -> Flow {
        self.send(Frame::error(code, error_text(code), spawn_id)).await
    }

    /// Queue Close (after everything queued before it).
    async fn close(&mut self, code: u16, reason: &'static str) -> Flow {
        self.summary = format!("close code={code} reason={reason}");
        match self.queue(Cmd::Close(code, reason)).await {
            Flow::Continue => Flow::Close,
            other => other,
        }
    }

    /// `error <code>` and Close 1008: the client broke the protocol.
    async fn violation(&mut self, code: ErrorCode, spawn_id: Option<SpawnId>) -> Flow {
        match self.error(code, spawn_id).await {
            Flow::Continue => self.close(CLOSE_PROTOCOL, if code == ErrorCode::BadFrame { "bad_frame" } else { "protocol" }).await,
            other => other,
        }
    }

    async fn refuse_hello(&mut self, code: HelloErrCode, message: String, close: u16, reason: &'static str) -> Flow {
        match self.send(Frame::HelloErr { code, message }).await {
            Flow::Continue => self.close(close, reason).await,
            other => other,
        }
    }

    async fn on_message(&mut self, msg: Message) -> Flow {
        match msg {
            Message::Text(t) => self.on_text(t.as_str()).await,
            Message::Binary(_) => self.error(ErrorCode::BinaryRejected, None).await,
            Message::Close(f) => {
                // tungstenite answers it; the stream ends right after.
                self.summary = format!("closed by client code={}", f.map_or("-".to_string(), |f| u16::from(f.code).to_string()));
                Flow::Continue
            }
            // Pings are answered by tungstenite; a read never yields a raw frame.
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Flow::Continue,
        }
    }

    async fn on_text(&mut self, text: &str) -> Flow {
        if text.len() > CONTROL_FRAME_MAX {
            return self.violation(ErrorCode::BadFrame, None).await;
        }
        match Frame::from_json(text) {
            Err(WireError::UnknownKind(_)) => self.error(ErrorCode::UnknownFrame, None).await,
            Err(WireError::Version(v)) if !self.authenticated => self.refuse_hello(HelloErrCode::Version, format!("this shim speaks wire v{WIRE_VERSION}, not v{v}"), CLOSE_WIRE_VERSION, "version").await,
            Err(_) => self.violation(ErrorCode::BadFrame, None).await,
            Ok(Frame::Hello { session_token, client, resume, idle_s }) if !self.authenticated => self.hello(&session_token, &client, &resume, idle_s).await,
            // The first frame must be hello.
            Ok(_) if !self.authenticated => self.violation(ErrorCode::BadFrame, None).await,
            Ok(frame) => self.on_frame(frame).await,
        }
    }

    async fn hello(&mut self, token: &Secret<String>, client: &ClientInfo, resume: &[ResumePoint], idle_s: Option<u32>) -> Flow {
        let (gen, name, version) = (self.gen, loggable(&client.name), loggable(&client.version));
        let Some(payload) = self.state.run.payload() else {
            errln!("ai-env: agent conn={gen} hello refused code=no_commitment client={name} {version}");
            return self.refuse_hello(HelloErrCode::NoCommitment, "this VM's /run carried no session commitment: terminate it and run a new one".into(), CLOSE_HELLO_REFUSED, "no_commitment").await;
        };
        if !payload.matches(token.expose().as_bytes()) {
            errln!("ai-env: agent conn={gen} hello refused code=bad_token client={name} {version}");
            return self.refuse_hello(HelloErrCode::BadToken, "the session token does not match this VM's /run commitment".into(), CLOSE_HELLO_REFUSED, "bad_token").await;
        }
        let idle_s = idle_s.map_or(IDLE_DEFAULT_S, |s| s.clamp(IDLE_MIN_S, IDLE_MAX_S));
        self.idle = self.idle_unit.saturating_mul(idle_s);
        // Attach first, so `attached` in the status means "to another socket" after this hello.
        let resumed = self.state.spawns.attach(gen, resume);
        let spawns = self.state.spawns.status(Some(gen));
        let h = self.state.health().await;
        let ok = Frame::HelloOk {
            wire: WIRE_VERSION,
            shim_version: h.shim_version,
            claude_version: h.claude_version,
            microvm_id: h.microvm_id,
            image_version: self.state.image_version.clone(),
            boot_nonce: h.boot_nonce.unwrap_or_default(),
            owner: h.owner,
            has_credentials: false,
            uptime_s: h.uptime_s,
            run_hook_seen: h.run_hook_seen,
            spawns,
            resumed,
        };
        self.state.agents.authenticate(gen);
        self.authenticated = true;
        self.deadline = Instant::now() + self.idle;
        errln!("ai-env: agent conn={gen} hello ok client={name} {version} resume={} idle_s={idle_s}", resume.len());
        match self.send(ok).await {
            Flow::Continue => self.queue(Cmd::Outbox(self.state.spawns.outbox(gen))).await,
            other => other,
        }
    }

    /// A spawn call's result: nothing, an error frame, or (stdin gap or overflow) an error and Close 1008.
    async fn outcome(&mut self, spawn_id: SpawnId, r: Result<(), ErrorCode>) -> Flow {
        match r {
            Ok(()) => Flow::Continue,
            Err(code @ (ErrorCode::StdinGap | ErrorCode::StdinOverflow)) => self.violation(code, Some(spawn_id)).await,
            Err(code) => self.error(code, Some(spawn_id)).await,
        }
    }

    async fn on_frame(&mut self, frame: Frame) -> Flow {
        let (state, gen) = (self.state.clone(), self.gen);
        let spawns = &state.spawns;
        match frame {
            Frame::Spawn { .. } => match SpawnRequest::from_frame(frame) {
                Some(req) => {
                    let id = req.spawn_id.clone();
                    // Before the manager knows the spawn: its frames wait for this answer.
                    self.unannounced.add(&id);
                    let reply = spawns.spawn(gen, req).await;
                    self.queue(Cmd::Answer(id, reply)).await
                }
                None => self.violation(ErrorCode::BadFrame, None).await,
            },
            Frame::Stdin { spawn_id, seq, data } => match crate::wire::chunk::decode(&data) {
                Ok(bytes) => {
                    let r = spawns.stdin(gen, &spawn_id, seq, bytes);
                    self.outcome(spawn_id, r).await
                }
                Err(_) => self.violation(ErrorCode::BadFrame, Some(spawn_id)).await,
            },
            Frame::StdinEof { spawn_id, seq } => {
                let r = spawns.stdin_eof(gen, &spawn_id, seq);
                self.outcome(spawn_id, r).await
            }
            Frame::Signal { spawn_id, sig, scope: _ } => {
                let r = spawns.signal(gen, &spawn_id, sig);
                self.outcome(spawn_id, r).await
            }
            Frame::Ack { spawn_id, seq, err_seq } => {
                let r = spawns.ack(gen, &spawn_id, seq, err_seq);
                self.outcome(spawn_id, r).await
            }
            Frame::Detach { spawn_id, is_final } => {
                let r = spawns.detach(gen, &spawn_id, is_final);
                self.outcome(spawn_id, r).await
            }
            Frame::Ping { ts } => self.send(Frame::Pong { ts }).await,
            // A second hello, or a kind only the VM sends.
            Frame::Hello { .. }
            | Frame::HelloOk { .. }
            | Frame::HelloErr { .. }
            | Frame::Spawned { .. }
            | Frame::SpawnErr { .. }
            | Frame::StdinAck { .. }
            | Frame::Stdout { .. }
            | Frame::Stderr { .. }
            | Frame::Exit { .. }
            | Frame::Pong { .. }
            | Frame::Event { .. }
            | Frame::Error { .. } => self.violation(ErrorCode::BadFrame, None).await,
        }
    }

    /// A stream error: what to tell the client, and how the reader ends.
    async fn broken(&mut self, e: &WsError) -> ReadEnd {
        let flow = match e {
            WsError::Capacity(_) => self.close(CLOSE_TOO_BIG, "too_big").await,
            WsError::Utf8 => self.violation(ErrorCode::BadFrame, None).await,
            WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
                self.summary = "reset without a close".into();
                return ReadEnd::Ended;
            }
            WsError::Protocol(_) => self.close(CLOSE_PROTOCOL, "protocol").await,
            other => {
                self.summary = format!("read error ({})", ws_error_kind(other));
                return ReadEnd::Ended;
            }
        };
        match flow {
            Flow::Close => ReadEnd::Broken,
            Flow::Stalled => ReadEnd::Stalled,
            Flow::Continue | Flow::Gone => ReadEnd::Ended,
        }
    }
}

/// One socket, from the upgrade to its end.
async fn serve<S>(reg: Registration, close_rx: watch::Receiver<Option<CloseReq>>, ws: WebSocketStream<S>, timing: Timing)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (gen, state) = (reg.gen, reg.state.clone());
    let started = Instant::now();
    let (sink, mut stream) = ws.split();
    let (tx, rx) = mpsc::channel(CONTROL_QUEUE);
    let unannounced = Arc::new(Unannounced::default());
    let mut writer = tokio::spawn(write_loop(sink, rx, close_rx, unannounced.clone(), timing.send));
    let mut s = Session { state: state.clone(), gen, tx, unannounced, authenticated: false, idle: Duration::ZERO, idle_unit: timing.idle_unit, deadline: started + timing.hello, summary: "stream ended".into() };
    let mut joined = None;
    let end = loop {
        let msg = tokio::select! {
            biased;
            w = &mut writer => {
                joined = Some(w);
                break ReadEnd::WriterDone;
            }
            m = stream.next() => m,
            () = tokio::time::sleep_until(s.deadline) => {
                let flow = if s.authenticated { s.close(CLOSE_GOING_AWAY, "idle").await } else { s.close(CLOSE_HELLO_DEADLINE, "hello_deadline").await };
                break if matches!(flow, Flow::Stalled) { ReadEnd::Stalled } else { ReadEnd::Closing };
            }
        };
        // Every inbound message restarts the idle clock (hello starts it).
        if s.authenticated {
            s.deadline = Instant::now() + s.idle;
        }
        let flow = match msg {
            None => break ReadEnd::Ended,
            Some(Err(e)) => break s.broken(&e).await,
            Some(Ok(m)) => s.on_message(m).await,
        };
        match flow {
            Flow::Continue => {}
            Flow::Close => break ReadEnd::Closing,
            Flow::Gone => break ReadEnd::WriterDone,
            Flow::Stalled => break ReadEnd::Stalled,
        }
    };
    let authenticated = s.authenticated;
    let mut summary = std::mem::take(&mut s.summary);
    // The reader's last word is queued; the writer finishes it, then stops (Dropped once the queue is empty).
    drop(s);
    if matches!(end, ReadEnd::Stalled) {
        // The writer is stuck on a client that reads nothing: no Close can reach it.
        writer.abort();
        errln!(
            "ai-env: agent conn={gen} end the {} deadline passed with {CONTROL_QUEUE} frames queued (the client reads nothing) after {} ms",
            if authenticated { "idle" } else { "hello" },
            started.elapsed().as_millis()
        );
        if authenticated {
            state.spawns.connection_lost(gen);
        }
        return;
    }
    let joined = match joined {
        Some(j) => j,
        None => {
            if let Ok(j) = tokio::time::timeout(CLOSE_BUDGET + Duration::from_secs(1), &mut writer).await {
                j
            } else {
                writer.abort();
                errln!("ai-env: agent conn={gen} end {summary} (the writer did not stop)");
                if authenticated {
                    state.spawns.connection_lost(gen);
                }
                return;
            }
        }
    };
    let Ok((sink, wend)) = joined else {
        errln!("ai-env: agent conn={gen} end {summary} (the writer failed)");
        if authenticated {
            state.spawns.connection_lost(gen);
        }
        return;
    };
    match &wend {
        WriteEnd::Closed(code, reason) if matches!(end, ReadEnd::WriterDone) => summary = format!("close code={code} reason={reason}"),
        WriteEnd::Failed(why) => summary = format!("{summary}; send failed ({why})"),
        _ => {}
    }
    match (end, wend) {
        // A stream error: only the raw socket is left. Half-close after our Close, then read
        // (bounded) what the client is still sending, so it gets the Close and not a reset.
        (ReadEnd::Broken, WriteEnd::Closed(..)) => {
            if let Ok(mut ws) = stream.reunite(sink) {
                drain_raw(ws.get_mut()).await;
            }
        }
        // Our Close went out with the stream intact: give the client a moment to answer it.
        (ReadEnd::Closing | ReadEnd::WriterDone, WriteEnd::Closed(..)) => {
            let _ = tokio::time::timeout(CLOSE_LINGER, async { while let Some(Ok(_)) = stream.next().await {} }).await;
        }
        _ => {}
    }
    errln!("ai-env: agent conn={gen} end {summary} after {} ms", started.elapsed().as_millis());
    if authenticated {
        state.spawns.connection_lost(gen);
    }
    drop(reg);
}

/// Half-close, then read and drop at most [`DRAIN_BYTES`] for at most [`DRAIN_FOR`].
async fn drain_raw<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S) {
    let _ = tokio::time::timeout(DRAIN_FOR, async {
        let _ = io.shutdown().await;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0;
        while total < DRAIN_BYTES {
            match io.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
    })
    .await;
}

async fn wait_outbox(outbox: &mut Option<Outbox>) {
    match outbox {
        Some(o) => o.changed().await,
        None => std::future::pending().await,
    }
}

/// The next outbox frame to send: the held one once its spawn is announced,
/// else the outbox's next, which is held instead while its spawn is not.
fn next_out(held: &mut Option<Frame>, outbox: Option<&mut Outbox>, unannounced: &Unannounced) -> Option<Frame> {
    let frame = match held.take() {
        Some(f) => f,
        None => outbox?.try_next()?,
    };
    if unannounced.holds(&frame) {
        *held = Some(frame);
        return None;
    }
    Some(frame)
}

/// The writer: the queued control frames in order, then the outbox, one
/// send at a time, each bounded; a spawn's outbox frames wait for its
/// answer; a registry close interrupts a send and wins over everything
/// queued after it.
async fn write_loop<S>(mut sink: Sink<S>, mut cmds: mpsc::Receiver<Cmd>, mut close: watch::Receiver<Option<CloseReq>>, unannounced: Arc<Unannounced>, send_timeout: Duration) -> (Sink<S>, WriteEnd)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut outbox: Option<Outbox> = None;
    let mut pending: Option<Cmd> = None;
    // An outbox frame of a spawn not announced yet: the outbox waits until it goes.
    let mut held: Option<Frame> = None;
    loop {
        let req = close.borrow_and_update().clone();
        if let Some(req) = req {
            let end = finish(&mut sink, pending.take(), &mut cmds, (req.code, req.reason), req.event, outbox.is_some(), req.by).await;
            return (sink, end);
        }
        let cmd = match pending.take() {
            Some(c) => Some(c),
            None => match cmds.try_recv() {
                Ok(c) => Some(c),
                Err(TryRecvError::Disconnected) => return (sink, WriteEnd::Dropped),
                Err(TryRecvError::Empty) => None,
            },
        };
        let frame = match cmd {
            Some(Cmd::Frame(f)) => f,
            Some(Cmd::Answer(id, f)) => {
                unannounced.answered(&id);
                f
            }
            Some(Cmd::Outbox(o)) => {
                outbox = Some(o);
                continue;
            }
            Some(Cmd::Close(code, reason)) => {
                let end = finish(&mut sink, None, &mut cmds, (code, reason.to_string()), None, outbox.is_some(), Instant::now() + CLOSE_BUDGET).await;
                return (sink, end);
            }
            None => {
                if let Some(f) = next_out(&mut held, outbox.as_mut(), &unannounced) {
                    f
                } else {
                    tokio::select! {
                        biased;
                        r = close.changed() => if r.is_err() {
                            return (sink, WriteEnd::Dropped);
                        },
                        c = cmds.recv() => match c {
                            Some(c) => pending = Some(c),
                            None => return (sink, WriteEnd::Dropped),
                        },
                        // Only the reader's answer (a command) releases a held frame.
                        () = wait_outbox(&mut outbox), if held.is_none() => {}
                    }
                    continue;
                }
            }
        };
        tokio::select! {
            biased;
            r = close.changed() => if r.is_err() {
                return (sink, WriteEnd::Dropped);
            },
            r = tokio::time::timeout(send_timeout, sink.send(Message::from(&frame))) => match r {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return (sink, WriteEnd::Failed(ws_error_kind(&e))),
                Err(_) => return (sink, WriteEnd::Failed(format!("a send took over {} s", send_timeout.as_secs()))),
            },
        }
    }
}

/// The command the writer had already taken (`first`), then those still
/// queued (a registry close skips none of the reader's answers), then
/// `event` when the socket is past hello (its hello_ok sent, or among those
/// commands), then Close — all by `by`.
async fn finish<S>(sink: &mut Sink<S>, first: Option<Cmd>, cmds: &mut mpsc::Receiver<Cmd>, (code, reason): (u16, String), event: Option<Frame>, mut past_hello: bool, by: Instant) -> WriteEnd
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut frames = Vec::new();
    for cmd in first.into_iter().chain(std::iter::from_fn(|| cmds.try_recv().ok())) {
        match cmd {
            Cmd::Frame(f) | Cmd::Answer(_, f) => frames.push(f),
            Cmd::Outbox(_) => past_hello = true,
            Cmd::Close(..) => {}
        }
    }
    frames.extend(event.filter(|_| past_hello));
    let close = CloseFrame { code: CloseCode::from(code), reason: reason.clone().into() };
    let out = async {
        for f in &frames {
            sink.send(Message::from(f)).await?;
        }
        sink.send(Message::Close(Some(close))).await
    };
    match tokio::time::timeout_at(by, out).await {
        Ok(Ok(())) => WriteEnd::Closed(code, reason),
        Ok(Err(e)) => WriteEnd::Failed(format!("close {code}: {}", ws_error_kind(&e))),
        Err(_) => WriteEnd::Failed(format!("close {code} timed out")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shim::state::RunRecord;
    use crate::wire::frame::{ws_config, EventKind, ResumeStatus, RunHookPayload, CLOSE_NORMAL};
    use std::path::PathBuf;
    use tokio::io::DuplexStream;

    type Client = WebSocketStream<DuplexStream>;

    const FAST: Timing = Timing { hello: Duration::from_millis(300), idle_unit: Duration::from_millis(10), send: Duration::from_secs(5) };

    fn token() -> String {
        format!("agent-unit-{}", "k".repeat(24))
    }

    /// A state after `/run`: with the commitment to [`token`], or fail-closed.
    fn state(commit: bool) -> Arc<ShimState> {
        let s = Arc::new(ShimState::new(PathBuf::from("/nonexistent/claude")));
        let payload = commit.then(|| RunHookPayload::new(&Secret::new(token()), "mike@mbp", "2026-10-03T08:00:00Z"));
        s.run.claim(&[1; 32], || RunRecord { microvm_id: Some("mvm-unit".into()), payload, body_sha256: [1; 32], at: std::time::Instant::now(), boot_nonce: "0".repeat(32) });
        s.run.mark_seen();
        s
    }

    /// A served socket over an in-memory pipe; the client end.
    async fn connect(state: &Arc<ShimState>, timing: Timing) -> Client {
        let (server, client) = tokio::io::duplex(256 * 1024);
        let (gen, close_rx) = state.agents.reserve(|| false).unwrap();
        let reg = Registration { state: state.clone(), gen };
        let ws = WebSocketStream::from_raw_socket(server, Role::Server, Some(ws_config())).await;
        tokio::spawn(serve(reg, close_rx, ws, timing));
        WebSocketStream::from_raw_socket(client, Role::Client, Some(ws_config())).await
    }

    fn hello_frame(token: &str, resume: Vec<ResumePoint>, idle_s: Option<u32>) -> Frame {
        Frame::Hello { session_token: Secret::new(token.to_string()), client: ClientInfo { name: "unit".into(), version: "0.0.1".into(), host: "test@host".into() }, resume, idle_s }
    }

    async fn send(c: &mut Client, f: &Frame) {
        c.send(Message::from(f)).await.unwrap();
    }

    /// The next frame, or the close code (`Err(None)`: the stream ended or failed without one).
    async fn next(c: &mut Client) -> Result<Frame, Option<u16>> {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), c.next()).await.expect("a message within 5 s") {
                Some(Ok(Message::Text(t))) => return Ok(Frame::from_json(t.as_str()).unwrap()),
                Some(Ok(Message::Close(f))) => return Err(f.map(|f| u16::from(f.code))),
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return Err(None),
            }
        }
    }

    async fn hello_ok(state: &Arc<ShimState>, timing: Timing) -> Client {
        let mut c = connect(state, timing).await;
        send(&mut c, &hello_frame(&token(), vec![], None)).await;
        assert!(matches!(next(&mut c).await, Ok(Frame::HelloOk { .. })));
        c
    }

    async fn ping_pong(c: &mut Client, ts: u64) {
        send(c, &Frame::Ping { ts }).await;
        assert_eq!(next(c).await, Ok(Frame::Pong { ts }), "the socket is up");
    }

    async fn wait_counts(state: &ShimState, want: (u32, u32)) {
        let until = Instant::now() + Duration::from_secs(5);
        while state.agents.counts() != want {
            assert!(Instant::now() < until, "counts {:?}, want {want:?}", state.agents.counts());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn hello_ok_reports_the_vm_and_resumes() {
        let s = state(true);
        let mut c = connect(&s, FAST).await;
        assert_eq!(s.agents.counts(), (1, 0));
        let id = SpawnId::new_v7();
        send(&mut c, &hello_frame(&token(), vec![ResumePoint { spawn_id: id.clone(), from_seq: Some(3), err_from_seq: None }], Some(90))).await;
        let Ok(Frame::HelloOk { wire, microvm_id, boot_nonce, owner, has_credentials, run_hook_seen, resumed, .. }) = next(&mut c).await else { panic!("hello_ok") };
        assert_eq!((wire, microvm_id.as_deref(), owner.as_deref(), has_credentials, run_hook_seen), (1, Some("mvm-unit"), Some("mike@mbp"), false, true));
        assert_eq!(boot_nonce.len(), 32);
        assert_eq!(resumed.len(), 1, "one entry per resume point");
        assert_eq!(resumed[0].spawn_id, id);
        assert!(matches!(resumed[0].status, ResumeStatus::Ok | ResumeStatus::Gap | ResumeStatus::Unknown));
        assert_eq!(s.agents.counts(), (1, 1));
        ping_pong(&mut c, 7).await;
        c.close(None).await.unwrap();
        wait_counts(&s, (0, 0)).await;
    }

    #[tokio::test]
    async fn hello_refusals_close_4403_and_4426() {
        let s = state(true);
        let mut c = connect(&s, FAST).await;
        send(&mut c, &hello_frame("not-the-token", vec![], None)).await;
        assert!(matches!(next(&mut c).await, Ok(Frame::HelloErr { code: HelloErrCode::BadToken, .. })));
        assert_eq!(next(&mut c).await, Err(Some(CLOSE_HELLO_REFUSED)));
        let fail_closed = state(false);
        let mut c = connect(&fail_closed, FAST).await;
        send(&mut c, &hello_frame(&token(), vec![], None)).await;
        assert!(matches!(next(&mut c).await, Ok(Frame::HelloErr { code: HelloErrCode::NoCommitment, .. })));
        assert_eq!(next(&mut c).await, Err(Some(CLOSE_HELLO_REFUSED)));
        let mut c = connect(&s, FAST).await;
        c.send(Message::text("{\"v\":2,\"t\":\"hello\"}")).await.unwrap();
        assert!(matches!(next(&mut c).await, Ok(Frame::HelloErr { code: HelloErrCode::Version, .. })));
        assert_eq!(next(&mut c).await, Err(Some(CLOSE_WIRE_VERSION)));
        wait_counts(&s, (0, 0)).await;
        wait_counts(&fail_closed, (0, 0)).await;
    }

    #[tokio::test]
    async fn no_hello_within_the_deadline_is_4408() {
        let s = state(true);
        let t = Instant::now();
        let mut c = connect(&s, FAST).await;
        // A binary message before hello is answered, and does not extend the deadline.
        c.send(Message::binary(vec![1u8, 2])).await.unwrap();
        assert!(matches!(next(&mut c).await, Ok(Frame::Error { code: ErrorCode::BinaryRejected, .. })));
        assert_eq!(next(&mut c).await, Err(Some(CLOSE_HELLO_DEADLINE)));
        assert!(t.elapsed() >= FAST.hello && t.elapsed() < FAST.hello * 4, "{:?}", t.elapsed());
        wait_counts(&s, (0, 0)).await;
    }

    #[tokio::test]
    async fn the_first_frame_must_be_hello() {
        let s = state(true);
        let mut c = connect(&s, FAST).await;
        send(&mut c, &Frame::Ping { ts: 1 }).await;
        assert!(matches!(next(&mut c).await, Ok(Frame::Error { code: ErrorCode::BadFrame, .. })));
        assert_eq!(next(&mut c).await, Err(Some(CLOSE_PROTOCOL)));
    }

    #[tokio::test]
    async fn an_idle_socket_is_closed_1001() {
        let s = state(true);
        let mut c = connect(&s, FAST).await;
        // idle_s 1 is clamped up to IDLE_MIN_S (30 units of 10 ms here).
        send(&mut c, &hello_frame(&token(), vec![], Some(1))).await;
        assert!(matches!(next(&mut c).await, Ok(Frame::HelloOk { .. })));
        let t = Instant::now();
        for ts in 0..3 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            ping_pong(&mut c, ts).await;
        }
        assert!(t.elapsed() > FAST.idle_unit * IDLE_MIN_S, "pings kept it open past one idle period");
        let quiet = Instant::now();
        assert_eq!(next(&mut c).await, Err(Some(CLOSE_GOING_AWAY)));
        assert!(quiet.elapsed() >= FAST.idle_unit * (IDLE_MIN_S - 5), "{:?}", quiet.elapsed());
    }

    #[tokio::test]
    async fn binary_and_unknown_frames_keep_the_socket_up() {
        let s = state(true);
        let mut c = hello_ok(&s, FAST).await;
        c.send(Message::binary(vec![0u8; 10])).await.unwrap();
        assert!(matches!(next(&mut c).await, Ok(Frame::Error { code: ErrorCode::BinaryRejected, spawn_id: None, .. })));
        ping_pong(&mut c, 1).await;
        c.send(Message::text("{\"v\":1,\"t\":\"from_the_future\",\"x\":1}")).await.unwrap();
        assert!(matches!(next(&mut c).await, Ok(Frame::Error { code: ErrorCode::UnknownFrame, .. })));
        ping_pong(&mut c, 2).await;
    }

    #[tokio::test]
    async fn protocol_violations_close_1008() {
        let s = state(true);
        let id = SpawnId::new_v7();
        let cases: Vec<(&str, Message)> = vec![
            ("malformed JSON", Message::text("{not json")),
            ("a known kind missing a field", Message::text("{\"v\":1,\"t\":\"ping\"}")),
            ("a second hello", Message::from(&hello_frame(&token(), vec![], None))),
            ("a kind only the VM sends", Message::from(&Frame::Pong { ts: 1 })),
            ("a v2 frame after hello", Message::text("{\"v\":2,\"t\":\"ping\",\"ts\":1}")),
            ("a bad stdin chunk", Message::from(&Frame::Stdin { spawn_id: id.clone(), seq: 1, data: crate::wire::frame::Chunk { text: Some("a".into()), b64: Some("YQ==".into()) } })),
            // A well-formed ping padded past the 4 MiB frame cap (unknown fields are otherwise ignored).
            ("a frame over CONTROL_FRAME_MAX", Message::text(format!("{{\"v\":1,\"t\":\"ping\",\"ts\":1,\"pad\":\"{}\"}}", "x".repeat(CONTROL_FRAME_MAX)))),
        ];
        for (what, msg) in cases {
            let mut c = hello_ok(&s, FAST).await;
            c.send(msg).await.unwrap();
            assert!(matches!(next(&mut c).await, Ok(Frame::Error { code: ErrorCode::BadFrame, .. })), "{what}");
            assert_eq!(next(&mut c).await, Err(Some(CLOSE_PROTOCOL)), "{what}");
        }
        wait_counts(&s, (0, 0)).await;
    }

    /// The writer relays the spawn manager's answers: `spawn_err` for a
    /// refused spawn (an empty argv: refused before any fork; real spawns
    /// through the socket run in tests/shim_local.rs), an error frame naming
    /// the spawn for a refused call; the socket stays up.
    #[tokio::test]
    async fn spawn_frames_are_relayed_to_the_spawn_manager() {
        let s = state(true);
        let mut c = hello_ok(&s, FAST).await;
        let id = SpawnId::new_v7();
        let spawn = Frame::Spawn { spawn_id: id.clone(), argv: vec![], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: crate::wire::frame::Deliver::Fd, detach_grace_s: None };
        send(&mut c, &spawn).await;
        assert!(matches!(next(&mut c).await, Ok(Frame::SpawnErr { spawn_id, .. }) if spawn_id == id));
        let unknown = SpawnId::new_v7();
        send(&mut c, &Frame::Signal { spawn_id: unknown.clone(), sig: crate::wire::frame::Sig::Term, scope: crate::wire::frame::Scope::Group }).await;
        assert!(matches!(next(&mut c).await, Ok(Frame::Error { spawn_id: Some(sid), .. }) if sid == unknown));
        ping_pong(&mut c, 8).await;
    }

    #[tokio::test]
    async fn a_message_over_the_cap_closes_1009_and_drains() {
        let s = state(true);
        let mut c = hello_ok(&s, FAST).await;
        let big = "x".repeat(WS_MAX_MESSAGE + 1);
        let t = Instant::now();
        tokio::time::timeout(Duration::from_secs(20), c.send(Message::text(big))).await.expect("the shim drains the message").unwrap();
        assert_eq!(next(&mut c).await, Err(Some(CLOSE_TOO_BIG)));
        assert!(t.elapsed() < DRAIN_FOR + Duration::from_secs(3), "{:?}", t.elapsed());
        drop(c);
        wait_counts(&s, (0, 0)).await;
        // The registry and the state serve new sockets.
        let mut again = hello_ok(&s, FAST).await;
        ping_pong(&mut again, 9).await;
    }

    #[tokio::test]
    async fn close_all_sends_the_event_past_hello_then_closes_every_socket() {
        let s = state(true);
        let mut authed = hello_ok(&s, FAST).await;
        let mut fresh = connect(&s, Timing { hello: Duration::from_secs(30), ..FAST }).await;
        assert_eq!(s.agents.counts(), (2, 1));
        let event = Frame::Event { kind: EventKind::HookSuspend, at: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()), reference: None };
        let t = Instant::now();
        let ((), a, f) = tokio::join!(s.agents.close_all_with(CLOSE_GOING_AWAY, "suspend", Some(event)), async { (next(&mut authed).await, next(&mut authed).await) }, next(&mut fresh));
        assert!(matches!(a.0, Ok(Frame::Event { kind: EventKind::HookSuspend, .. })), "{:?}", a.0);
        assert_eq!(a.1, Err(Some(CLOSE_GOING_AWAY)));
        assert_eq!(f, Err(Some(CLOSE_GOING_AWAY)), "no event before a hello_ok");
        assert!(t.elapsed() <= CLOSE_ALL_WAIT + Duration::from_millis(500), "{:?}", t.elapsed());
        wait_counts(&s, (0, 0)).await;
        s.agents.close_all(CLOSE_NORMAL, "nothing open").await;
    }

    /// A client that sends but never reads fills the socket, then the control
    /// queue. The reader waits for room only until its deadline (hello, then
    /// idle), so the socket and its slot go then, not after the writer's send
    /// timeout (5 s here).
    #[tokio::test]
    async fn a_client_that_reads_nothing_goes_at_its_deadline() {
        for past_hello in [false, true] {
            let s = state(true);
            let (server, client) = tokio::io::duplex(4096);
            let (gen, close_rx) = s.agents.reserve(|| false).unwrap();
            let ws = WebSocketStream::from_raw_socket(server, Role::Server, Some(ws_config())).await;
            tokio::spawn(serve(Registration { state: s.clone(), gen }, close_rx, ws, FAST));
            let mut c = WebSocketStream::from_raw_socket(client, Role::Client, Some(ws_config())).await;
            let deadline = if past_hello {
                send(&mut c, &hello_frame(&token(), vec![], Some(IDLE_MIN_S))).await;
                assert!(matches!(next(&mut c).await, Ok(Frame::HelloOk { .. })));
                FAST.idle_unit * IDLE_MIN_S
            } else {
                FAST.hello
            };
            let t = Instant::now();
            // Each binary message queues an error frame; nothing is read.
            let flood = tokio::spawn(async move { while c.send(Message::binary(vec![0u8; 8])).await.is_ok() {} });
            wait_counts(&s, (0, 0)).await;
            assert!(t.elapsed() < deadline + Duration::from_secs(1), "past hello {past_hello}: {:?}", t.elapsed());
            flood.abort();
        }
    }

    /// A spawn's own frames never go out before its answer, however late the
    /// reader queues it: the real reader (`Session::on_frame`) announces the
    /// spawn and hands it to the manager, and its queue is held here until
    /// echo's stdout and exit wait in the outbox, which the writer pulls
    /// meanwhile; `spawned` still comes first. Both halves count: the
    /// reader's announcement before the manager knows the spawn, and the
    /// writer's hold.
    #[tokio::test]
    async fn a_spawns_frames_wait_for_its_spawned() {
        use crate::shim::health::{ProbeSpec, ShimOpts};
        let home = tempfile::tempdir().unwrap();
        let opts = ShimOpts { home: std::fs::canonicalize(home.path()).unwrap(), ..ShimOpts::default() };
        let s = Arc::new(ShimState::with(PathBuf::from("/nonexistent/claude"), opts, ProbeSpec::default(), Arc::new(crate::shim::sys::RealSys)));
        let (server, client) = tokio::io::duplex(256 * 1024);
        let (sink, _stream) = WebSocketStream::from_raw_socket(server, Role::Server, Some(ws_config())).await.split();
        let mut c = WebSocketStream::from_raw_socket(client, Role::Client, Some(ws_config())).await;
        let (_close, close_rx) = watch::channel(None);
        let (tx, rx) = mpsc::channel(CONTROL_QUEUE);
        let unannounced = Arc::new(Unannounced::default());
        let gen = s.agents.next_gen();
        tokio::spawn(write_loop(sink, rx, close_rx, unannounced.clone(), FAST.send));
        assert!(tx.send(Cmd::Outbox(s.spawns.outbox(gen))).await.is_ok());
        // The reader's queue, held by the test.
        let (held, mut queued) = mpsc::channel(CONTROL_QUEUE);
        let mut reader = Session { state: s.clone(), gen, tx: held, unannounced, authenticated: true, idle: Duration::from_secs(60), idle_unit: FAST.idle_unit, deadline: Instant::now() + Duration::from_secs(60), summary: String::new() };
        let id = SpawnId::new_v7();
        let spawn = Frame::Spawn { spawn_id: id.clone(), argv: vec!["/bin/echo".into(), "hi".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: crate::wire::frame::Deliver::Fd, detach_grace_s: None };
        assert!(matches!(reader.on_frame(spawn).await, Flow::Continue));
        let until = Instant::now() + Duration::from_secs(5);
        while s.spawns.status(None).iter().all(|st| st.exit.is_none()) {
            assert!(Instant::now() < until, "echo did not exit");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The writer has had time to send what the outbox holds.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let answer = queued.recv().await.expect("the reader queued its answer");
        assert!(matches!(&answer, Cmd::Answer(a, Frame::Spawned { .. }) if *a == id), "the answer is spawned");
        assert!(tx.send(answer).await.is_ok());
        let mut kinds = Vec::new();
        loop {
            let f = next(&mut c).await.unwrap_or_else(|e| panic!("the socket ended ({e:?}) after {kinds:?}"));
            assert_eq!(f.spawn_id(), Some(&id), "{f:?}");
            kinds.push(f.kind());
            if f.kind() == "exit" {
                break;
            }
        }
        assert_eq!((kinds.first(), kinds.contains(&"stdout")), (Some(&"spawned"), true), "{kinds:?}");
    }

    /// A registry close sends what the writer had already taken from the
    /// queue (`pending`: any of the reader's answers) before the rest; an
    /// outbox command among them makes the socket past hello, so the event
    /// goes too.
    #[tokio::test]
    async fn a_registry_close_sends_the_command_the_writer_took() {
        let s = state(true);
        let event = Frame::Event { kind: EventKind::HookSuspend, at: "2026-10-03T08:00:00Z".into(), reference: None };
        let cases: Vec<(Cmd, Vec<Cmd>, Vec<&str>)> = vec![
            (Cmd::Frame(Frame::Pong { ts: 1 }), vec![Cmd::Frame(Frame::Pong { ts: 2 })], vec!["pong", "pong"]),
            (Cmd::Answer(SpawnId::new_v7(), Frame::Pong { ts: 3 }), vec![], vec!["pong"]),
            (Cmd::Outbox(s.spawns.outbox(7)), vec![], vec!["event"]),
        ];
        for (first, queued, want) in cases {
            let (server, client) = tokio::io::duplex(64 * 1024);
            let (mut sink, _stream) = WebSocketStream::from_raw_socket(server, Role::Server, Some(ws_config())).await.split();
            let mut c = WebSocketStream::from_raw_socket(client, Role::Client, Some(ws_config())).await;
            let (tx, mut rx) = mpsc::channel(CONTROL_QUEUE);
            for cmd in queued {
                assert!(tx.send(cmd).await.is_ok());
            }
            let end = finish(&mut sink, Some(first), &mut rx, (CLOSE_GOING_AWAY, "suspend".into()), Some(event.clone()), false, Instant::now() + Duration::from_secs(2)).await;
            assert_eq!(end, WriteEnd::Closed(CLOSE_GOING_AWAY, "suspend".into()));
            let mut got = Vec::new();
            let close = loop {
                match next(&mut c).await {
                    Ok(f) => got.push(f.kind()),
                    Err(code) => break code,
                }
            };
            assert_eq!((got, close), (want, Some(CLOSE_GOING_AWAY)));
        }
    }

    #[tokio::test]
    async fn busy_after_max_unauthenticated_and_draining_refused_at_reserve() {
        let s = state(true);
        let held: Vec<_> = (0..MAX_UNAUTHENTICATED).map(|_| s.agents.reserve(|| false).unwrap()).collect();
        assert_eq!(s.agents.reserve(|| false).unwrap_err(), "busy");
        s.agents.authenticate(held[0].0);
        assert!(s.agents.reserve(|| false).is_ok(), "a socket past hello frees a slot");
        assert_eq!(s.agents.reserve(|| true).unwrap_err(), "draining");
    }

    #[test]
    fn the_handshake_checks_follow_axum_with_a_token_list() {
        let h = |pairs: &[(&str, &str)]| {
            let mut m = HeaderMap::new();
            for (k, v) in pairs {
                m.append(header::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
            }
            m
        };
        let good = [("connection", "keep-alive, Upgrade"), ("upgrade", "WebSocket"), ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="), ("sec-websocket-version", "13")];
        assert!(handshake_refusal(&Method::GET, &h(&good)).is_none());
        let status = |m: &Method, pairs: &[(&str, &str)]| handshake_refusal(m, &h(pairs)).map(|r| r.status());
        assert_eq!(status(&Method::POST, &good), Some(StatusCode::METHOD_NOT_ALLOWED));
        assert_eq!(status(&Method::HEAD, &good), Some(StatusCode::METHOD_NOT_ALLOWED));
        let without = |name: &str| good.iter().copied().filter(|(k, _)| *k != name).collect::<Vec<_>>();
        let with = |name: &str, value: &'static str| good.iter().map(|&(k, v)| if k == name { (k, value) } else { (k, v) }).collect::<Vec<_>>();
        for pairs in [
            without("connection"),
            without("upgrade"),
            without("sec-websocket-key"),
            without("sec-websocket-version"),
            with("connection", "upgrade, close"),
            with("connection", "upgraded"),
            with("upgrade", "h2c"),
            with("sec-websocket-version", "8"),
            with("sec-websocket-key", ""),
        ] {
            assert_eq!(status(&Method::GET, &pairs), Some(StatusCode::BAD_REQUEST), "{pairs:?}");
        }
        // Two Connection headers form one list.
        let mut split = good.to_vec();
        split[0] = ("connection", "keep-alive");
        split.push(("connection", "upgrade"));
        assert!(handshake_refusal(&Method::GET, &h(&split)).is_none());
        // RFC 6455's known answer.
        assert_eq!(derive_accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn client_strings_are_one_bounded_log_word() {
        assert_eq!(loggable("ai-env"), "ai-env");
        assert_eq!(loggable("a b\nc"), "a?b?c");
        assert_eq!(loggable(""), "-");
        assert_eq!(loggable(&"x".repeat(100)).len(), LOG_FIELD_MAX);
    }
}
