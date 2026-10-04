//! One `/agent` socket (plan S6): dial through `transport::dial_agent`,
//! `hello`, frames in and out (text only, through `wire::frame`), WebSocket
//! Pings (the peer's are answered by tungstenite while reading), the close,
//! and the time since the last inbound message (the caller's dead timer). The
//! probes use it directly; [`super::session`] splits it into a sender and a
//! receiver so the socket is read while a send is in flight.
//!
//! - [`AgentConn::open`] dials (a [`DialError`] says what to do about a refusal);
//! - [`AgentConn::hello`] sends `hello` and returns the [`HelloOk`] fields;
//!   `hello_err` is `BridgeError::HelloRefused` once the Close that follows
//!   was read (at most [`CLOSE_WAIT`]); the caller bounds the wait for the answer;
//! - [`AgentConn::recv`]: `None` when the socket closed (the peer's Close, if
//!   any, in [`AgentConn::close_frame`]); a binary message, malformed JSON or
//!   another wire version is `BridgeError::Protocol`; an unknown `t` is skipped;
//!   a read failure is `BridgeError::Transport`;
//! - every send is bounded by `SEND_TIMEOUT`; [`AgentConn::close`] sends a
//!   Close and reads until the peer's (at most [`CLOSE_WAIT`]).
//!
//! TRACE (`AI_ENV_BRIDGE_TRACE`, [`Trace`]): `1` logs one line per frame (the
//! frame's own `Debug`: kind, spawn, seq and sizes); `2` also appends every
//! frame's JSON to `<root>/logs/frames-<pid>.jsonl` (0600) with data, the
//! session token, secret and environment values and argv past argv[0]
//! replaced by `[masked:<len>]`.
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::transport::{dial_agent, AgentDial, AgentSocket, DialError};
use crate::wire::frame::{ClientInfo, Frame, HelloErrCode, ResumePoint, Resumed, SpawnStatus, WireError, SEND_TIMEOUT};
use crate::wire::redact::{scrub, Secret};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

/// How long a close waits for the peer's Close.
pub const CLOSE_WAIT: Duration = Duration::from_secs(1);

/// Sockets of this process, numbered for the log and the TRACE file.
static SOCKETS: AtomicU64 = AtomicU64::new(0);

/// The fields of `hello_ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloOk {
    pub wire: u8,
    pub shim_version: String,
    pub claude_version: Option<String>,
    pub microvm_id: Option<String>,
    pub image_version: Option<String>,
    pub boot_nonce: String,
    pub owner: Option<String>,
    pub has_credentials: bool,
    pub uptime_s: u64,
    pub run_hook_seen: bool,
    pub spawns: Vec<SpawnStatus>,
    /// One per `hello.resume` entry; replay follows for every `ok`.
    pub resumed: Vec<Resumed>,
}

/// One socket: the sending and the receiving half.
pub struct AgentConn {
    tx: AgentSender,
    rx: AgentReceiver,
}

/// The sending half (frames, WebSocket Pings, the Close).
pub struct AgentSender {
    sink: SplitSink<AgentSocket, Message>,
    n: u64,
    trace: Trace,
}

/// The receiving half.
pub struct AgentReceiver {
    stream: SplitStream<AgentSocket>,
    n: u64,
    trace: Trace,
    activity: Activity,
    closed: Option<(u16, String)>,
}

/// When the last inbound message (any: a frame, a Ping, a Pong, a Close) arrived.
#[derive(Debug, Clone)]
pub struct Activity {
    base: Instant,
    last_ms: Arc<AtomicU64>,
}

impl Activity {
    fn new() -> Activity {
        Activity { base: Instant::now(), last_ms: Arc::new(AtomicU64::new(0)) }
    }

    fn touch(&self) {
        self.last_ms.store(u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// How long the socket has been silent (since it opened when nothing arrived yet).
    #[must_use]
    pub fn idle(&self) -> Duration {
        self.base.elapsed().saturating_sub(Duration::from_millis(self.last_ms.load(Ordering::Relaxed)))
    }
}

impl AgentConn {
    /// Dial `/agent` of `endpoint` with the endpoint token (`transport::dial_agent`).
    pub async fn open(dial: &AgentDial, endpoint: &str, token: &Secret<String>) -> Result<AgentConn, DialError> {
        Ok(AgentConn::from_socket(dial_agent(dial, endpoint, token).await?))
    }

    /// A socket that is already upgraded (probe e0's `upgrade_probe`).
    #[must_use]
    pub fn from_socket(ws: AgentSocket) -> AgentConn {
        let n = SOCKETS.fetch_add(1, Ordering::Relaxed) + 1;
        let (sink, stream) = ws.split();
        let trace = Trace::default();
        AgentConn { tx: AgentSender { sink, n, trace: trace.clone() }, rx: AgentReceiver { stream, n, trace, activity: Activity::new(), closed: None } }
    }

    /// Frames of this socket go to `trace`.
    #[must_use]
    pub fn with_trace(mut self, trace: Trace) -> AgentConn {
        self.tx.trace = trace.clone();
        self.rx.trace = trace;
        self
    }

    /// This socket's number in the process (log lines, the TRACE file).
    #[must_use]
    pub fn number(&self) -> u64 {
        self.tx.n
    }

    #[must_use]
    pub fn activity(&self) -> Activity {
        self.rx.activity.clone()
    }

    /// The peer's Close (code, scrubbed reason), once one was read.
    #[must_use]
    pub fn close_frame(&self) -> Option<(u16, String)> {
        self.rx.closed.clone()
    }

    /// `hello` (this client, `resume`, `idle_s`), then the answer: the
    /// `hello_ok` fields, or `HelloRefused` naming the `hello_err` code once
    /// its Close was read. Any other first frame is a protocol error.
    pub async fn hello(&mut self, session_token: &Secret<String>, resume: Vec<ResumePoint>, idle_s: Option<u32>) -> Result<HelloOk, BridgeError> {
        let client = ClientInfo { name: "ai-env".into(), version: env!("CARGO_PKG_VERSION").into(), host: crate::bridge::vm::owner() };
        self.send(&Frame::Hello { session_token: session_token.clone(), client, resume, idle_s }).await?;
        match self.recv().await? {
            Some(Frame::HelloOk { wire, shim_version, claude_version, microvm_id, image_version, boot_nonce, owner, has_credentials, uptime_s, run_hook_seen, spawns, resumed }) => {
                Ok(HelloOk { wire, shim_version, claude_version, microvm_id, image_version, boot_nonce, owner, has_credentials, uptime_s, run_hook_seen, spawns, resumed })
            }
            Some(Frame::HelloErr { code, message }) => {
                let _ = tokio::time::timeout(CLOSE_WAIT, async { while let Ok(Some(_)) = self.recv().await {} }).await;
                Err(BridgeError::HelloRefused { code: hello_err_name(code), message: scrub(&message).into_owned() })
            }
            Some(other) => Err(BridgeError::Protocol(format!("socket {}: expected hello_ok, got {}", self.tx.n, other.kind()))),
            None => Err(BridgeError::Transport(format!("socket {} closed before hello_ok{}", self.tx.n, close_text(self.rx.closed.as_ref())))),
        }
    }

    pub async fn send(&mut self, frame: &Frame) -> Result<(), BridgeError> {
        self.tx.send(frame).await
    }

    pub async fn recv(&mut self) -> Result<Option<Frame>, BridgeError> {
        self.rx.recv().await
    }

    /// A WebSocket Ping (the peer's Pong counts as activity).
    pub async fn ping(&mut self) -> Result<(), BridgeError> {
        self.tx.ping().await
    }

    /// Close with `code` and read until the peer's Close (at most [`CLOSE_WAIT`]).
    pub async fn close(mut self, code: u16) {
        self.tx.close(code).await;
        let _ = tokio::time::timeout(CLOSE_WAIT, async { while let Ok(Some(_)) = self.rx.recv().await {} }).await;
    }

    /// The two halves, for a reader that runs while a send is in flight.
    #[must_use]
    pub fn split(self) -> (AgentSender, AgentReceiver) {
        (self.tx, self.rx)
    }
}

impl AgentSender {
    /// One frame, within `SEND_TIMEOUT`.
    pub async fn send(&mut self, frame: &Frame) -> Result<(), BridgeError> {
        self.trace.frame(self.n, "mac", frame);
        self.put(Message::from(frame), frame.kind()).await
    }

    /// A WebSocket Ping.
    pub async fn ping(&mut self) -> Result<(), BridgeError> {
        self.put(Message::Ping(Vec::new().into()), "WebSocket Ping").await
    }

    /// A Close with `code` (best effort, at most [`CLOSE_WAIT`]).
    pub async fn close(&mut self, code: u16) {
        let _ = tokio::time::timeout(CLOSE_WAIT, self.sink.send(Message::Close(Some(CloseFrame { code: code.into(), reason: "".into() })))).await;
    }

    async fn put(&mut self, msg: Message, what: &str) -> Result<(), BridgeError> {
        match tokio::time::timeout(SEND_TIMEOUT, self.sink.send(msg)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(BridgeError::Transport(format!("socket {}: sending {what} failed: {}", self.n, scrub(&e.to_string())))),
            Err(_) => Err(BridgeError::Transport(format!("socket {}: sending {what} took longer than {} s", self.n, SEND_TIMEOUT.as_secs()))),
        }
    }
}

impl AgentReceiver {
    /// The next frame; `None` when the socket closed (see the module doc).
    pub async fn recv(&mut self) -> Result<Option<Frame>, BridgeError> {
        loop {
            let Some(msg) = self.stream.next().await else { return Ok(None) };
            let msg = msg.map_err(|e| BridgeError::Transport(format!("socket {}: {}", self.n, scrub(&e.to_string()))))?;
            self.activity.touch();
            match msg {
                Message::Text(text) => match Frame::from_json(text.as_str()) {
                    Ok(frame) => {
                        self.trace.frame(self.n, "vm", &frame);
                        return Ok(Some(frame));
                    }
                    Err(WireError::UnknownKind(t)) => tracing::debug!("socket {}: skipping a frame of unknown kind {t:?}", self.n),
                    // A serde message can quote the offending value: name the place, never the text.
                    Err(WireError::Json(e)) => return Err(BridgeError::Protocol(format!("socket {}: malformed frame ({:?} error at column {})", self.n, e.classify(), e.column()))),
                    Err(e) => return Err(BridgeError::Protocol(format!("socket {}: {e}", self.n))),
                },
                Message::Binary(_) => return Err(BridgeError::Protocol(format!("socket {}: the shim sent a binary message", self.n))),
                Message::Close(frame) => {
                    // 1005: a Close without a code (RFC 6455).
                    self.closed = Some(frame.map_or((1005, String::new()), |f| (u16::from(f.code), scrub(f.reason.as_str()).into_owned())));
                    return Ok(None);
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }

    /// The peer's Close (code, scrubbed reason), once one was read.
    #[must_use]
    pub fn close_frame(&self) -> Option<(u16, String)> {
        self.closed.clone()
    }
}

/// ` (Close <code> <reason>)` for a log line, empty without a Close.
#[must_use]
pub fn close_text(close: Option<&(u16, String)>) -> String {
    match close {
        Some((code, reason)) if reason.is_empty() => format!(" (Close {code})"),
        Some((code, reason)) => format!(" (Close {code} {reason})"),
        None => String::new(),
    }
}

/// The wire name of a `hello_err` code (`bad_token`, …).
fn hello_err_name(code: HelloErrCode) -> String {
    serde_json::to_value(code).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "other".into())
}

// ---- TRACE ---------------------------------------------------------------------------

/// `AI_ENV_BRIDGE_TRACE`: `0` off, `1` a log line per frame, `2` also the
/// masked frames file (see the module doc). Shared by the sockets of a session.
#[derive(Clone, Default)]
pub struct Trace {
    level: u8,
    file: Option<Arc<Mutex<std::fs::File>>>,
}

impl Trace {
    pub const ENV: &'static str = "AI_ENV_BRIDGE_TRACE";

    /// The level `AI_ENV_BRIDGE_TRACE` asks for (anything but `1`/`2` is off).
    #[must_use]
    pub fn from_env(paths: &Paths) -> Trace {
        let level = match std::env::var(Self::ENV).ok().as_deref().map(str::trim) {
            Some("1") => 1,
            Some("2") => 2,
            _ => 0,
        };
        Trace::new(level, paths)
    }

    /// Level `level` (`2` opens the frames file; when it cannot be opened the
    /// log says why and the level stays `1`).
    #[must_use]
    pub fn new(level: u8, paths: &Paths) -> Trace {
        let file = if level >= 2 {
            match crate::bridge::logging::open_log_file(&Trace::frames_path(paths)) {
                Ok(f) => Some(Arc::new(Mutex::new(f))),
                Err(e) => {
                    tracing::warn!("{}=2: the frames file was not opened ({e}); frames are logged without their JSON", Self::ENV);
                    None
                }
            }
        } else {
            None
        };
        Trace { level: level.min(2), file }
    }

    /// `<root>/logs/frames-<pid>.jsonl`.
    #[must_use]
    pub fn frames_path(paths: &Paths) -> PathBuf {
        paths.logs().join(format!("frames-{}.jsonl", std::process::id()))
    }

    /// One frame of socket `n` going `dir` (`mac`: sent, `vm`: received).
    fn frame(&self, n: u64, dir: &str, frame: &Frame) {
        if self.level == 0 {
            return;
        }
        tracing::info!("agent socket {n} {dir}: {frame:?}");
        let Some(file) = &self.file else { return };
        let mut line = serde_json::json!({"ts": crate::wire::time::unix_now_ms(), "socket": n, "dir": dir, "frame": masked(frame)}).to_string();
        line.push('\n');
        let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = f.write_all(line.as_bytes()) {
            tracing::warn!("{}=2: a frame was not written to the frames file: {e}", Self::ENV);
        }
    }
}

/// The frame's JSON with every value that may carry data or a secret
/// replaced by `[masked:<len>]`: chunk `text`/`b64`, `session_token`, the
/// values of `secrets` and `env`, and argv past argv[0].
fn masked(frame: &Frame) -> serde_json::Value {
    use serde_json::Value;
    let mut v: Value = serde_json::from_str(&frame.to_json()).unwrap_or(Value::Null);
    let mask = |x: &mut Value| {
        let len = x.as_str().map_or(0, str::len);
        *x = Value::String(format!("[masked:{len}]"));
    };
    if let Some(map) = v.as_object_mut() {
        for key in ["text", "b64", "session_token"] {
            if let Some(x) = map.get_mut(key) {
                mask(x);
            }
        }
        for key in ["env", "secrets"] {
            if let Some(Value::Object(m)) = map.get_mut(key) {
                m.values_mut().for_each(mask);
            }
        }
        if let Some(Value::Array(argv)) = map.get_mut("argv") {
            argv.iter_mut().skip(1).for_each(mask);
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::frame::{Chunk, Deliver, HelloErrCode, ResumeStatus, SpawnId, CLOSE_HELLO_REFUSED, CLOSE_NORMAL};
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    const HOST: &str = "bed07657-5d0f-abe5-1e5e-6bc7bcb0b637.lambda-microvm.eu-central-1.on.aws";

    /// Every async test ends within 30 s.
    async fn bounded<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(30), f).await.expect("the test ran past its limit")
    }

    /// A WebSocket server on loopback running `serve` on its first connection.
    async fn server<F, Fut>(serve: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            serve(tokio_tungstenite::accept_async(tcp).await.unwrap()).await;
        });
        (addr, task)
    }

    async fn open(addr: SocketAddr) -> AgentConn {
        AgentConn::open(&AgentDial { local: Some(addr) }, HOST, &Secret::new("conn-test-token".into())).await.unwrap()
    }

    fn hello_ok() -> Frame {
        Frame::HelloOk {
            wire: 1,
            shim_version: "0.1.0".into(),
            claude_version: None,
            microvm_id: None,
            image_version: None,
            boot_nonce: "n".into(),
            owner: None,
            has_credentials: false,
            uptime_s: 3,
            run_hook_seen: true,
            spawns: vec![],
            resumed: vec![Resumed { spawn_id: SpawnId("0192f1e0-2b7c-7c3a-9a1b-4d5e6f708192".into()), status: ResumeStatus::Gap }],
        }
    }

    async fn next_frame(ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> Frame {
        loop {
            match ws.next().await.unwrap().unwrap() {
                Message::Text(t) => return Frame::from_json(t.as_str()).unwrap(),
                Message::Ping(_) | Message::Pong(_) => continue,
                other => panic!("{other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn hello_returns_the_hello_ok_fields() {
        bounded(async {
            let (addr, task) = server(|mut ws| async move {
                let Frame::Hello { session_token, client, resume, idle_s } = next_frame(&mut ws).await else { panic!("not a hello") };
                assert_eq!(session_token.expose(), "session-token-for-hello");
                assert_eq!((client.name.as_str(), client.version.as_str(), client.host.as_str()), ("ai-env", env!("CARGO_PKG_VERSION"), crate::bridge::vm::owner().as_str()));
                assert_eq!((resume.len(), idle_s), (1, Some(120)));
                ws.send(Message::from(&hello_ok())).await.unwrap();
                // The client's WebSocket Ping, then its Close.
                assert!(matches!(ws.next().await.unwrap().unwrap(), Message::Ping(_)));
                assert!(matches!(ws.next().await.unwrap().unwrap(), Message::Close(Some(f)) if f.code == CloseCode::from(CLOSE_NORMAL)));
            })
            .await;
            let mut conn = open(addr).await;
            let point = ResumePoint { spawn_id: SpawnId("0192f1e0-2b7c-7c3a-9a1b-4d5e6f708192".into()), from_seq: Some(9), err_from_seq: None };
            let ok = conn.hello(&Secret::new("session-token-for-hello".into()), vec![point], Some(120)).await.unwrap();
            assert_eq!((ok.wire, ok.uptime_s, ok.resumed[0].status), (1, 3, ResumeStatus::Gap));
            assert!(conn.activity().idle() < Duration::from_secs(5));
            conn.ping().await.unwrap();
            conn.close(CLOSE_NORMAL).await;
            task.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn hello_err_is_refused_after_its_close() {
        bounded(async {
            let (addr, task) = server(|mut ws| async move {
                let _ = next_frame(&mut ws).await;
                ws.send(Message::from(&Frame::HelloErr { code: HelloErrCode::BadToken, message: "the token does not match".into() })).await.unwrap();
                ws.close(Some(CloseFrame { code: CloseCode::from(CLOSE_HELLO_REFUSED), reason: "bad_token".into() })).await.unwrap();
                while let Some(Ok(_)) = ws.next().await {}
            })
            .await;
            let mut conn = open(addr).await;
            let e = conn.hello(&Secret::new("wrong-session-token".into()), vec![], None).await.unwrap_err();
            assert!(matches!(&e, BridgeError::HelloRefused { code, .. } if code == "bad_token"), "{e}");
            assert_eq!(conn.close_frame(), Some((CLOSE_HELLO_REFUSED, "bad_token".into())), "the Close was consumed");
            assert_eq!(crate::errors::CliError::from(e).exit_code(), 8);
            drop(conn);
            task.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn recv_skips_unknown_kinds_and_refuses_binary_and_malformed_input() {
        bounded(async {
            let (addr, task) = server(|mut ws| async move {
                ws.send(Message::text(r#"{"v":1,"t":"from_the_future","x":1}"#)).await.unwrap();
                ws.send(Message::Ping(vec![7].into())).await.unwrap();
                ws.send(Message::text(r#"{"v":1,"t":"pong","ts":5}"#)).await.unwrap();
                ws.send(Message::Binary(vec![1, 2].into())).await.unwrap();
                let _ = ws.next().await;
            })
            .await;
            let mut conn = open(addr).await;
            assert_eq!(conn.recv().await.unwrap(), Some(Frame::Pong { ts: 5 }), "unknown kinds and Pings are skipped");
            assert!(matches!(conn.recv().await, Err(BridgeError::Protocol(m)) if m.contains("binary")));
            drop(conn);
            task.await.unwrap();

            let (addr, task) = server(|mut ws| async move {
                ws.send(Message::text(r#"{"v":1,"t":"stdout","spawn_id":"s","seq":"secret-looking-text","text":"x"}"#)).await.unwrap();
                ws.send(Message::text(r#"{"v":2,"t":"pong","ts":1}"#)).await.unwrap();
                let _ = ws.next().await;
            })
            .await;
            let mut conn = open(addr).await;
            let e = conn.recv().await.unwrap_err();
            assert!(matches!(&e, BridgeError::Protocol(m) if m.contains("malformed") && !m.contains("secret-looking-text")), "{e}");
            assert!(matches!(conn.recv().await, Err(BridgeError::Protocol(m)) if m.contains("version 2")));
            drop(conn);
            task.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn the_peers_close_ends_recv_and_is_kept() {
        bounded(async {
            let (addr, task) = server(|mut ws| async move {
                ws.close(Some(CloseFrame { code: CloseCode::from(1001), reason: "suspend".into() })).await.unwrap();
                while let Some(Ok(_)) = ws.next().await {}
            })
            .await;
            let mut conn = open(addr).await;
            assert_eq!(conn.recv().await.unwrap(), None);
            assert_eq!(conn.close_frame(), Some((1001, "suspend".into())));
            assert_eq!(close_text(conn.close_frame().as_ref()), " (Close 1001 suspend)");
            let e = conn.hello(&Secret::new("late-session-token".into()), vec![], None).await.unwrap_err();
            assert!(matches!(e, BridgeError::Transport(_)), "a closed socket cannot hello: {e}");
            drop(conn);
            task.await.unwrap();
        })
        .await;
    }

    #[test]
    fn masked_frames_keep_the_shape_and_drop_every_value() {
        let sid = SpawnId("0192f1e0-2b7c-7c3a-9a1b-4d5e6f708192".into());
        let hello = Frame::Hello { session_token: Secret::new("trace-session-token".into()), client: ClientInfo { name: "ai-env".into(), version: "0.1.0".into(), host: "u@h".into() }, resume: vec![], idle_s: None };
        let spawn = Frame::Spawn {
            spawn_id: sid.clone(),
            argv: vec!["/usr/bin/claude".into(), "--print".into(), "the prompt".into()],
            cwd: Some("/Users/mike/w".into()),
            env: BTreeMap::from([("LANG".to_string(), "C.UTF-8".to_string())]),
            secrets: BTreeMap::from([("SOME_NAME".to_string(), Secret::new("dummy-secret-value".to_string()))]),
            deliver_secret: Deliver::Fd,
            detach_grace_s: None,
        };
        let out = Frame::Stdout { spawn_id: sid.clone(), seq: 3, data: Chunk { text: Some("private output".into()), b64: None } };
        let bin = Frame::Stdin { spawn_id: sid, seq: 4, data: Chunk { text: None, b64: Some("AP8K".into()) } };
        let all = [masked(&hello), masked(&spawn), masked(&out), masked(&bin)].map(|v| v.to_string()).join("\n");
        for leak in ["trace-session-token", "--print", "the prompt", "C.UTF-8", "dummy-secret-value", "private output", "AP8K"] {
            assert!(!all.contains(leak), "{leak}: {all}");
        }
        assert_eq!(masked(&spawn)["argv"], serde_json::json!(["/usr/bin/claude", "[masked:7]", "[masked:10]"]));
        assert_eq!(masked(&spawn)["env"]["LANG"], "[masked:7]");
        assert_eq!(masked(&out)["text"], "[masked:14]");
        assert_eq!(masked(&out)["seq"], 3);
        assert_eq!(masked(&hello)["session_token"], "[masked:19]");
    }

    #[test]
    fn trace_level_2_writes_masked_frames_to_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let off = Trace::new(1, &paths);
        off.frame(1, "mac", &Frame::Ping { ts: 1 });
        assert!(!Trace::frames_path(&paths).exists(), "level 1 writes no file");
        let t = Trace::new(2, &paths);
        let sid = SpawnId("0192f1e0-2b7c-7c3a-9a1b-4d5e6f708192".into());
        t.frame(7, "vm", &Frame::Stdout { spawn_id: sid, seq: 1, data: Chunk { text: Some("visible?".into()), b64: None } });
        t.frame(7, "mac", &Frame::Ping { ts: 2 });
        let path = Trace::frames_path(&paths);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!((lines[0]["socket"].as_u64(), lines[0]["dir"].as_str(), lines[0]["frame"]["t"].as_str()), (Some(7), Some("vm"), Some("stdout")));
        assert!(!text.contains("visible?"), "{text}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
