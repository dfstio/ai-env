//! The tests' MicroVM endpoint for `/agent` (plan S6 D4, W4): listens on
//! 127.0.0.1, checks each upgrade's `x-aws-proxy-auth` against the
//! file-backed fake's state (`FakeState::endpoint_check`, which also resumes
//! a SUSPENDED VM with auto-resume), can answer scripted 403/429 (with and
//! without `Retry-After`)/502, cut sockets (after a while, or before a
//! given frame reaches the client), hold a request a while (a slow upgrade),
//! until the test releases it, or while it posts `/resume` like the
//! platform, and otherwise forwards the connection to a native or Docker
//! shim with the `x-aws-proxy-*` headers stripped (the platform strips them
//! too). Every attempt is recorded with the status the client got. Its own
//! thread runs a current-thread runtime, so sync and async tests use it
//! alike. Shared by `tests/shim_bridge_local.rs`, `tests/vm/exec_cli.rs` and `tests/docker_exec.rs` (`#[path]`).
#![allow(dead_code)]

use ai_env_cli::bridge::api::{AuthToken, TOKEN_HEADER};
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use ai_env_cli::wire::redact::Secret;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Largest request or response head read.
const HEAD_MAX: usize = 64 * 1024;
/// How long a head, an upstream connect or the `/resume` post may take.
const STEP_LIMIT: Duration = Duration::from_secs(10);

/// What the endpoint does with one connection (the script's next entry, or `Forward`).
#[derive(Debug, Clone)]
pub enum Action {
    /// The proxy's token and state check, then the upstream.
    Forward,
    /// This answer, before any check; the upstream is never reached.
    Respond { status: u16, headers: Vec<(String, String)>, body: String },
    /// `Forward`, then both sides are cut `after` the upstream answered.
    ForwardThenCut { after: Duration },
    /// `Forward` until the upstream sends bytes holding `text` (for example
    /// `"t":"spawned"`): both sides are cut instead, so the client never gets them.
    ForwardUntil { text: String },
    /// The check, then `POST /resume` to the shim's hooks port (the platform's
    /// auto-resume holds the request meanwhile), then `Forward`.
    HoldThenResume { hooks: SocketAddr },
    /// `Forward` once the request was held `by` (a slow upgrade).
    Delay { by: Duration },
    /// `Forward` once the test called [`FakeEndpoint::release`] (a redial held back meanwhile).
    Held,
}

impl Action {
    /// `Respond` with an empty body.
    #[must_use]
    pub fn status(status: u16, headers: &[(&str, &str)]) -> Action {
        Action::Respond { status, headers: headers.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect(), body: String::new() }
    }
}

/// One connection as the endpoint saw it.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub at: Instant,
    /// The status the client got (101: upgraded); 0 when it got none.
    pub status: u16,
    pub path: String,
}

struct Shared {
    fake: PathBuf,
    upstream: SocketAddr,
    script: Mutex<VecDeque<Action>>,
    attempts: Mutex<Vec<Attempt>>,
    /// Bumped by [`FakeEndpoint::cut_all`]: every forwarded connection ends.
    cut: tokio::sync::watch::Sender<u64>,
    /// Set by [`FakeEndpoint::release`]: `Held` requests go on.
    released: tokio::sync::watch::Sender<bool>,
    resumes: Mutex<u32>,
    /// Connections accepted (an attempt is recorded only once it is answered).
    accepted: Mutex<u32>,
}

/// The endpoint; stopped (every connection dropped) when dropped.
pub struct FakeEndpoint {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeEndpoint {
    /// Listen on 127.0.0.1 (a free port) in front of `upstream`, checking
    /// tokens against the file-backed fake at `fake`.
    #[must_use]
    pub fn start(fake: &Path, upstream: SocketAddr) -> FakeEndpoint {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the fake endpoint");
        listener.set_nonblocking(true).expect("nonblocking listener");
        let addr = listener.local_addr().expect("the endpoint's address");
        let shared = Arc::new(Shared {
            fake: fake.to_path_buf(),
            upstream,
            script: Mutex::new(VecDeque::new()),
            attempts: Mutex::new(Vec::new()),
            cut: tokio::sync::watch::channel(0).0,
            released: tokio::sync::watch::channel(false).0,
            resumes: Mutex::new(0),
            accepted: Mutex::new(0),
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let s = shared.clone();
        let thread = std::thread::Builder::new()
            .name("fake-endpoint".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("the endpoint's runtime");
                rt.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).expect("a tokio listener");
                    let accept = async {
                        while let Ok((client, _)) = listener.accept().await {
                            let _ = client.set_nodelay(true);
                            *s.accepted.lock().unwrap() += 1;
                            tokio::spawn(serve(client, s.clone()));
                        }
                    };
                    tokio::select! {
                        () = accept => {}
                        _ = stopped => {}
                    }
                });
                rt.shutdown_background();
            })
            .expect("the endpoint's thread");
        FakeEndpoint { addr, shared, stop: Some(stop), thread: Some(thread) }
    }

    /// Queue `actions` for the next connections, in order.
    pub fn script(&self, actions: impl IntoIterator<Item = Action>) {
        self.shared.script.lock().unwrap().extend(actions);
    }

    /// Every connection so far, in order.
    #[must_use]
    pub fn attempts(&self) -> Vec<Attempt> {
        self.shared.attempts.lock().unwrap().clone()
    }

    /// Cut every forwarded connection now (no Close on either side).
    pub fn cut_all(&self) {
        self.shared.cut.send_modify(|n| *n += 1);
    }

    /// Let every `Held` request go on, now and from now on.
    pub fn release(&self) {
        self.shared.released.send_modify(|r| *r = true);
    }

    /// How many `POST /resume` the endpoint sent to a shim.
    #[must_use]
    pub fn resumes(&self) -> u32 {
        *self.shared.resumes.lock().unwrap()
    }

    /// How many connections were accepted (answered or not yet).
    #[must_use]
    pub fn accepted(&self) -> u32 {
        *self.shared.accepted.lock().unwrap()
    }
}

impl Drop for FakeEndpoint {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// A parsed request head.
struct Head {
    raw: Vec<u8>,
    path: String,
    /// Lowercased name → value, in order.
    headers: Vec<(String, String)>,
    /// Bytes read past the head (forwarded as they are).
    rest: Vec<u8>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The head with every `x-aws-proxy-*` header removed (as the platform forwards it).
    fn stripped(&self) -> Vec<u8> {
        let text = String::from_utf8_lossy(&self.raw);
        let mut out = String::new();
        for line in text.split("\r\n") {
            if line.to_ascii_lowercase().starts_with("x-aws-proxy-") {
                continue;
            }
            out.push_str(line);
            out.push_str("\r\n");
        }
        // The split leaves the head's final empty pair; keep exactly one blank line.
        while out.ends_with("\r\n\r\n\r\n") {
            out.truncate(out.len() - 2);
        }
        out.into_bytes()
    }
}

/// Read up to the end of a head (`\r\n\r\n`), at most [`HEAD_MAX`] bytes.
async fn read_head(s: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Some((buf, rest));
        }
        if buf.len() > HEAD_MAX {
            return None;
        }
        match tokio::time::timeout(STEP_LIMIT, s.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return None,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn parse(raw: Vec<u8>, rest: Vec<u8>) -> Head {
    let text = String::from_utf8_lossy(&raw).into_owned();
    let mut lines = text.split("\r\n");
    let path = lines.next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or_default().to_string();
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    Head { raw, path, headers, rest }
}

fn record(shared: &Shared, status: u16, path: &str) {
    shared.attempts.lock().unwrap().push(Attempt { at: Instant::now(), status, path: path.to_string() });
}

/// `HTTP/1.1 <status>` with `headers` and `body`, then close.
async fn answer(client: &mut TcpStream, status: u16, headers: &[(String, String)], body: &str) {
    let reason = http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason()).unwrap_or("Status");
    let mut text = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in headers {
        text.push_str(&format!("{k}: {v}\r\n"));
    }
    text.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()));
    let _ = client.write_all(text.as_bytes()).await;
    let _ = client.shutdown().await;
}

/// The proxy's check through the fake's state: `Err((status, x-aws-proxy-error))` when it refuses.
async fn check(shared: &Shared, head: &Head) -> Result<(), (u16, String)> {
    let host = head.header("host").unwrap_or_default().to_string();
    let value = head.header("x-aws-proxy-auth").unwrap_or_default().to_string();
    let port: u16 = head.header("x-aws-proxy-port").and_then(|p| p.parse().ok()).unwrap_or(0);
    let fake = shared.fake.clone();
    let checked = tokio::task::spawn_blocking(move || {
        let token = AuthToken { headers: BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new(value))]), port, expires_at_unix: 0 };
        FileFakeMicrovmApi::open(&fake).and_then(|api| api.with(|s| Ok(s.endpoint_check(&host, &token, port))))
    })
    .await
    .expect("the check ran");
    match checked {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(refusal)) => Err((refusal.status, refusal.proxy_error.unwrap_or_default())),
        Err(e) => Err((500, format!("fake state: {e}"))),
    }
}

/// `POST /aws/lambda-microvms/runtime/v1/resume` to `hooks`; whether it answered 200.
async fn post_resume(hooks: SocketAddr) -> bool {
    let run = async {
        let mut s = TcpStream::connect(hooks).await.ok()?;
        let req = format!("POST /aws/lambda-microvms/runtime/v1/resume HTTP/1.1\r\nHost: {hooks}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
        s.write_all(req.as_bytes()).await.ok()?;
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.ok()?;
        Some(out.starts_with(b"HTTP/1.1 200"))
    };
    tokio::time::timeout(STEP_LIMIT, run).await.ok().flatten().unwrap_or(false)
}

async fn serve(mut client: TcpStream, shared: Arc<Shared>) {
    let Some((raw, rest)) = read_head(&mut client).await else {
        record(&shared, 0, "");
        return;
    };
    let head = parse(raw, rest);
    let action = shared.script.lock().unwrap().pop_front().unwrap_or(Action::Forward);
    let (cut_after, until) = match action {
        Action::Respond { status, headers, body } => {
            record(&shared, status, &head.path);
            answer(&mut client, status, &headers, &body).await;
            return;
        }
        Action::ForwardThenCut { after } => (Some(after), None),
        Action::ForwardUntil { ref text } => (None, Some(text.clone())),
        Action::Delay { by } => {
            tokio::time::sleep(by).await;
            (None, None)
        }
        Action::Held => {
            let _ = shared.released.subscribe().wait_for(|r| *r).await;
            (None, None)
        }
        Action::Forward | Action::HoldThenResume { .. } => (None, None),
    };
    if let Err((status, proxy_error)) = check(&shared, &head).await {
        record(&shared, status, &head.path);
        answer(&mut client, status, &[("x-aws-proxy-error".into(), proxy_error)], "").await;
        return;
    }
    if let Action::HoldThenResume { hooks } = action {
        if post_resume(hooks).await {
            *shared.resumes.lock().unwrap() += 1;
        }
    }
    let Ok(Ok(mut upstream)) = tokio::time::timeout(STEP_LIMIT, TcpStream::connect(shared.upstream)).await else {
        record(&shared, 502, &head.path);
        answer(&mut client, 502, &[("x-aws-proxy-error".into(), "BAD_GATEWAY".into())], "").await;
        return;
    };
    let _ = upstream.set_nodelay(true);
    let mut sent = head.stripped();
    sent.extend_from_slice(&head.rest);
    if upstream.write_all(&sent).await.is_err() {
        record(&shared, 0, &head.path);
        return;
    }
    // The upstream's answer head goes back first: its status is the attempt's.
    let Some((reply, more)) = read_head(&mut upstream).await else {
        record(&shared, 0, &head.path);
        return;
    };
    let status = String::from_utf8_lossy(&reply).split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    record(&shared, status, &head.path);
    if client.write_all(&reply).await.is_err() || client.write_all(&more).await.is_err() {
        return;
    }
    let mut cut = shared.cut.subscribe();
    let timer = async {
        match cut_after {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    };
    match until {
        None => tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
            () = timer => {}
            _ = cut.changed() => {}
        },
        Some(text) => {
            let ((mut from_client, mut to_client), (mut from_upstream, mut to_upstream)) = (client.split(), upstream.split());
            tokio::select! {
                _ = tokio::io::copy(&mut from_client, &mut to_upstream) => {}
                () = copy_until(&mut from_upstream, &mut to_client, text.as_bytes()) => {}
                () = timer => {}
                _ = cut.changed() => {}
            }
        }
    }
    // Dropping both streams cuts the connection on both sides.
}

/// Copy `from` to `to` until `from` sends bytes holding `text` (those are
/// not written), or either side ends.
async fn copy_until(from: &mut (impl AsyncRead + Unpin), to: &mut (impl AsyncWrite + Unpin), text: &[u8]) {
    let mut buf = vec![0u8; 64 * 1024];
    // What came last, for a `text` split across two reads.
    let mut seen = Vec::new();
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        seen.extend_from_slice(&buf[..n]);
        if seen.windows(text.len()).any(|w| w == text) || to.write_all(&buf[..n]).await.is_err() {
            return;
        }
        seen.drain(..seen.len().saturating_sub(text.len()));
    }
}
