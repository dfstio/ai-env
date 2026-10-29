//! The helpers of `tests/relay_client.rs`: certificates made at run time by the OpenSSL 3 CLI (in a tempdir; no key
//! is committed), a fake relay (`relay_server::RelayServer` over TLS 1.3 on 127.0.0.1) whose sources are named after
//! what they do (`echo`, `lines`, `slow`, `fail`), the real `ai-env-relay-client` with its session on fd 3 (a file of
//! the test's tempdir opened onto it) and the real `ai-env-relay-mcp` as this test process's child. The test process
//! is every client's leader unless a test says otherwise. Tokens are built at run time and never printed.
#![allow(dead_code)]

use ai_env_relay_proto::v1::relay_server::{Relay, RelayServer};
use ai_env_relay_proto::v1::{CallChunk, CallRequest, Error, Limits, ListSourcesRequest, ListSourcesResponse, OpDescriptor, SourceDescriptor, SourceStatus};
use base64::Engine as _;
use serde_json::{json, Value};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

/// Every wait of these tests.
pub const LIMIT: Duration = Duration::from_secs(20);
/// The request id the fake relay answers with (a placeholder uuid): on its chunks, on a call stream's initial metadata
/// and on a call's refusal status (R-30), as `x-ai-env-request-id`.
pub const REQUEST_ID: &str = "0199a1b2-0000-7000-8000-00000000000a";

/// `metadata` with [`REQUEST_ID`] under the relay's request id key (R-30; the key spelled out, as the relay sends it).
fn tag(metadata: &mut tonic::metadata::MetadataMap) {
    metadata.insert("x-ai-env-request-id", tonic::metadata::MetadataValue::from_static(REQUEST_ID));
}

pub fn client_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env-relay-client")
}

pub fn mcp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env-relay-mcp")
}

/// This process's euid.
pub fn uid() -> u32 {
    // SAFETY: geteuid never fails.
    unsafe { libc::geteuid() }
}

/// A token for one test, built at run time from low-entropy parts.
pub fn token() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!("relay-test-{:08x}-{:04x}", std::process::id(), N.fetch_add(1, Ordering::SeqCst))
}

// ---- certificates ------------------------------------------------------------------------------

/// The OpenSSL CLI: Homebrew's when present, else the PATH's (OpenSSL 3; macOS's own is LibreSSL).
pub fn openssl() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let brew = Path::new("/opt/homebrew/bin/openssl");
        let bin = if brew.is_file() { brew.to_path_buf() } else { PathBuf::from("openssl") };
        let out = Command::new(&bin).arg("version").output().unwrap_or_else(|e| panic!("{}: {e}", bin.display()));
        let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let major: u32 = version.strip_prefix("OpenSSL ").and_then(|v| v.split('.').next()).and_then(|m| m.parse().ok()).unwrap_or(0);
        assert!(major >= 3, "{} is {version:?}: these tests need the OpenSSL 3+ CLI (brew install openssl)", bin.display());
        bin
    })
}

fn run_ok(cmd: &mut Command) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "{cmd:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// A CA and a leaf it signed, in a tempdir: PEM for `openssl s_server`, DER for rustls.
pub struct Pki {
    pub dir: tempfile::TempDir,
    pub ca_der: Vec<u8>,
    pub leaf_der: Vec<u8>,
    pub leaf_key_der: Vec<u8>,
    pub leaf_pem: PathBuf,
    pub leaf_key_pem: PathBuf,
}

impl Pki {
    /// A P-256 CA and a leaf for `san` (`IP:127.0.0.1`), each valid one day.
    pub fn new(san: &str) -> Pki {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        let key = |path: PathBuf| run_ok(Command::new(openssl()).args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out"]).arg(path));
        key(p("ca.key"));
        run_ok(Command::new(openssl()).args(["req", "-x509", "-new", "-key"]).arg(p("ca.key")).args(["-subj", "/CN=relay test CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out"]).arg(p("ca.pem")));
        key(p("leaf.key"));
        run_ok(Command::new(openssl()).args(["req", "-new", "-key"]).arg(p("leaf.key")).args(["-subj", "/CN=relay test", "-out"]).arg(p("leaf.csr")));
        std::fs::write(p("leaf.cnf"), format!("[leaf]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\nsubjectAltName = {san}\n")).unwrap();
        run_ok(Command::new(openssl()).args(["x509", "-req", "-in"]).arg(p("leaf.csr")).arg("-CA").arg(p("ca.pem")).arg("-CAkey").arg(p("ca.key")).args(["-set_serial", "7", "-days", "1", "-extfile"]).arg(p("leaf.cnf")).args(["-extensions", "leaf", "-out"]).arg(p("leaf.pem")));
        run_ok(Command::new(openssl()).args(["x509", "-in"]).arg(p("ca.pem")).args(["-outform", "DER", "-out"]).arg(p("ca.der")));
        run_ok(Command::new(openssl()).args(["x509", "-in"]).arg(p("leaf.pem")).args(["-outform", "DER", "-out"]).arg(p("leaf.der")));
        run_ok(Command::new(openssl()).args(["pkey", "-in"]).arg(p("leaf.key")).args(["-outform", "DER", "-out"]).arg(p("leaf.key.der")));
        let read = |n: &str| std::fs::read(p(n)).unwrap();
        let (ca_der, leaf_der, leaf_key_der) = (read("ca.der"), read("leaf.der"), read("leaf.key.der"));
        Pki { ca_der, leaf_der, leaf_key_der, leaf_pem: p("leaf.pem"), leaf_key_pem: p("leaf.key"), dir }
    }

    pub fn ca_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.ca_der)
    }
}

/// The session JSON for the client's fd 3.
pub fn session_json(token: &str, addr: &str, server_name: &str, ca_b64: &str) -> String {
    format!("{{\"v\":1,\"token\":\"{token}\",\"addr\":\"{addr}\",\"server_name\":\"{server_name}\",\"ca_der_b64\":\"{ca_b64}\"}}")
}

// ---- the fake relay ----------------------------------------------------------------------------

/// What the fake relay saw.
#[derive(Default)]
pub struct Seen {
    /// Requests that reached a handler (any RPC).
    pub requests: AtomicUsize,
    /// Requests whose `x-ai-env-session` was the token (compared here, never printed).
    pub header_ok: AtomicUsize,
    /// TLS handshakes completed.
    pub handshakes: AtomicUsize,
    /// Call streams dropped by the client before they ended.
    pub dropped: AtomicUsize,
    /// The last call's `deadline_ms` and `limits.max_bytes`.
    pub last_call: Mutex<Option<(u32, Option<u64>)>>,
}

/// The fake's handlers.
struct Fake {
    token: String,
    sources: Vec<SourceStatus>,
    seen: Arc<Seen>,
    release: tokio::sync::watch::Receiver<bool>,
}

/// The §V-vm.3.6 example's `echo` source, and a status without a descriptor (which no catalog shows).
pub fn echo_sources() -> Vec<SourceStatus> {
    let op = OpDescriptor {
        name: "echo".into(),
        description: "Return params".into(),
        params_json_schema: "{\"type\":\"object\"}".into(),
        output: 1,
        read_only: true,
        default_limits: Some(Limits { max_bytes: 65_536, max_rows: 0, max_chunks: 0 }),
        max_limits: Some(Limits { max_bytes: 1_048_576, max_rows: 0, max_chunks: 0 }),
        examples: vec!["{\"x\":1}".into()],
    };
    vec![
        SourceStatus { descriptor: Some(SourceDescriptor { name: "echo".into(), version: "0.1.0".into(), description: "Echo its parameters".into(), kind: 7, env: "test".into(), sensitivity: 2, ops: vec![op] }), available: true, last_seen_unix_ms: 1_761_730_000_000 },
        SourceStatus { descriptor: None, available: false, last_seen_unix_ms: 0 },
    ]
}

/// §V-vm.3.6's catalog line of [`echo_sources`], as a tool's text.
pub const ECHO_CATALOG_TEXT: &str = r#"{"sources":[{"name":"echo","version":"0.1.0","description":"Echo its parameters","kind":"other","env":"test","sensitivity":"internal","available":true,"last_seen_unix_ms":1761730000000,"ops":[{"name":"echo","description":"Return params","params_schema":{"type":"object"},"output":"json","read_only":true,"default_limits":{"max_bytes":65536,"max_rows":0,"max_chunks":0},"max_limits":{"max_bytes":1048576,"max_rows":0,"max_chunks":0},"examples":[{"x":1}]}]}],"truncated":false}"#;

/// `n` sources of one `description_len`-byte description each (`test-<i>`).
pub fn many_sources(n: usize, description_len: usize) -> Vec<SourceStatus> {
    (0..n)
        .map(|i| SourceStatus { descriptor: Some(SourceDescriptor { name: format!("test-{i}"), version: "0.1.0".into(), description: "d".repeat(description_len), kind: 7, env: "test".into(), sensitivity: 1, ops: Vec::new() }), available: true, last_seen_unix_ms: 1 })
        .collect()
}

fn chunk(seq: u64, data: Vec<u8>, content_type: &str, last: bool) -> CallChunk {
    CallChunk { request_id: REQUEST_ID.into(), seq, data, content_type: content_type.into(), r#final: last, error: None, truncated: false }
}

/// `n` bytes of numbered text lines.
pub fn lines_of(seq: u64, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0u64;
    while out.len() < n {
        out.extend_from_slice(format!("chunk {seq} line {i}\n").as_bytes());
        i += 1;
    }
    out.truncate(n);
    out
}

impl Fake {
    fn check<T>(&self, req: &tonic::Request<T>) -> Result<(), tonic::Status> {
        self.seen.requests.fetch_add(1, Ordering::SeqCst);
        match req.metadata().get("x-ai-env-session").and_then(|v| v.to_str().ok()) {
            Some(t) if t == self.token => {
                self.seen.header_ok.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            _ => Err(tonic::Status::unauthenticated("authentication failed")),
        }
    }
}

type ChunkTx = tokio::sync::mpsc::Sender<Result<CallChunk, tonic::Status>>;

/// Until the client drops the stream: then it is counted.
async fn count_drop(tx: ChunkTx, seen: Arc<Seen>) {
    tx.closed().await;
    seen.dropped.fetch_add(1, Ordering::SeqCst);
}

#[tonic::async_trait]
impl Relay for Fake {
    async fn list_sources(&self, req: tonic::Request<ListSourcesRequest>) -> Result<tonic::Response<ListSourcesResponse>, tonic::Status> {
        self.check(&req)?;
        Ok(tonic::Response::new(ListSourcesResponse { sources: self.sources.clone() }))
    }

    type CallStream = tokio_stream::wrappers::ReceiverStream<Result<CallChunk, tonic::Status>>;

    async fn call(&self, req: tonic::Request<CallRequest>) -> Result<tonic::Response<Self::CallStream>, tonic::Status> {
        self.check(&req)?;
        let r = req.into_inner();
        *self.seen.last_call.lock().unwrap() = Some((r.deadline_ms, r.limits.map(|l| l.max_bytes)));
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let send = |c: CallChunk| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Ok(c)).await;
            }
        };
        match (r.source.as_str(), r.op.as_str()) {
            ("echo", "echo") => send(chunk(0, r.params_json, "application/json", true)).await,
            ("lines", "head") => send(CallChunk { truncated: true, ..chunk(0, b"a\nb\n".to_vec(), "text/plain", true) }).await,
            ("lines", "tail") => {
                let (tx, seen) = (tx.clone(), self.seen.clone());
                tokio::spawn(async move {
                    for seq in 0..3 {
                        if tx.send(Ok(chunk(seq, lines_of(seq, 65_536), "text/plain", false))).await.is_err() {
                            break;
                        }
                    }
                    count_drop(tx, seen).await;
                });
            }
            ("fail", "denied") => {
                let mut refused = tonic::Status::permission_denied("denied by grant");
                tag(refused.metadata_mut());
                return Err(refused);
            }
            // Under a head that names nothing (below): the error chunk is the one place the request id is.
            ("fail", "missing") => send(CallChunk { error: Some(Error { code: 5, message: "no such entry".into() }), ..chunk(0, Vec::new(), "", true) }).await,
            // An error chunk that names nothing, under a tagged head: the head's id names the failure.
            ("fail", "anonymous") => send(CallChunk { request_id: String::new(), error: Some(Error { code: 9, message: "not now".into() }), ..chunk(0, Vec::new(), "", true) }).await,
            ("fail", "cut") => send(chunk(0, b"part".to_vec(), "text/plain", false)).await,
            // A status (with no request id) ends the stream after its first chunk.
            ("fail", "abort") => {
                send(chunk(0, b"part".to_vec(), "text/plain", false)).await;
                let _ = tx.send(Err(tonic::Status::aborted("the stream broke"))).await;
            }
            ("fail", "gap") => {
                send(chunk(1, b"one".to_vec(), "text/plain", false)).await;
                send(chunk(3, b"three".to_vec(), "text/plain", true)).await;
            }
            ("slow", "wait") => {
                let (tx, seen, mut release) = (tx.clone(), self.seen.clone(), self.release.clone());
                tokio::spawn(async move {
                    tokio::select! {
                        released = async { release.wait_for(|go| *go).await.is_ok() } => {
                            if released {
                                let _ = tx.send(Ok(chunk(0, b"released".to_vec(), "text/plain", true))).await;
                            }
                        }
                        () = count_drop(tx.clone(), seen) => {}
                    }
                });
            }
            _ => return Err(tonic::Status::not_found("no such op")),
        }
        let mut response = tonic::Response::new(tokio_stream::wrappers::ReceiverStream::new(rx));
        if (r.source.as_str(), r.op.as_str()) != ("fail", "missing") {
            tag(response.metadata_mut());
        }
        Ok(response)
    }
}

/// A TLS stream as tonic's server takes it.
struct Io(tokio_rustls::server::TlsStream<tokio::net::TcpStream>);

impl tonic::transport::server::Connected for Io {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl tokio::io::AsyncRead for Io {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Io {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// The fake relay on 127.0.0.1 (TLS 1.3, ALPN h2, `pki`'s leaf), answering `token` alone.
pub struct FakeRelay {
    pub addr: std::net::SocketAddr,
    pub seen: Arc<Seen>,
    release: tokio::sync::watch::Sender<bool>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl FakeRelay {
    pub async fn start(pki: &Pki, token: &str, sources: Vec<SourceStatus>) -> FakeRelay {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(pki.leaf_key_der.clone().into());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![pki.leaf_der.clone().into()], key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Seen::default());
        let (release, release_rx) = tokio::sync::watch::channel(false);
        let fake = Fake { token: token.to_string(), sources, seen: seen.clone(), release: release_rx };
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Io, std::io::Error>>(16);
        let counted = seen.clone();
        let server = tokio::spawn(async move {
            let accept = async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let (acceptor, tx, counted) = (acceptor.clone(), tx.clone(), counted.clone());
                    tokio::spawn(async move {
                        if let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await {
                            counted.handshakes.fetch_add(1, Ordering::SeqCst);
                            let _ = tx.send(Ok(Io(tls))).await;
                        }
                    });
                }
            };
            let serve = tonic::transport::Server::builder().add_service(RelayServer::new(fake)).serve_with_incoming(tokio_stream::wrappers::ReceiverStream::new(rx));
            tokio::select! {
                () = accept => {}
                _ = serve => {}
            }
        });
        FakeRelay { addr, seen, release, server }
    }

    /// Every `slow` call held now answers.
    pub fn release(&self) {
        let _ = self.release.send(true);
    }

    pub fn requests(&self) -> usize {
        self.seen.requests.load(Ordering::SeqCst)
    }
}

/// Polls `cond` every 20 ms until it holds or `limit` passes.
pub async fn eventually(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while !cond() {
        if Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

// ---- the real client ---------------------------------------------------------------------------

/// A running `ai-env-relay-client serve`, its stderr gathered.
pub struct Client {
    pub child: tokio::process::Child,
    pub socket: PathBuf,
    pub stderr: Arc<Mutex<String>>,
    pub dir: tempfile::TempDir,
}

/// The test's spawns hold this between making a descriptor for a child and its spawn (none leaks into another's).
pub static SPAWN: Mutex<()> = Mutex::new(());

/// `ai-env-relay-client serve --leader <leader> --socket <dir>/<leader>.sock --agent-uid <uid>` with `session` on fd 3
/// (`None`: no fd 3), `extra` after, in a tempdir of its own (the socket's directory 0750); its stderr gathered.
pub fn spawn_client(session: Option<&[u8]>, leader: u32, agent_uid: u32, extra: &[&str]) -> Client {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let relay = dir.path().join("relay");
    std::fs::create_dir(&relay).unwrap();
    std::fs::set_permissions(&relay, std::fs::Permissions::from_mode(0o750)).unwrap();
    let socket = relay.join(format!("{leader}.sock"));
    let (child, stderr) = spawn_client_at(session, leader, agent_uid, &socket, dir.path(), extra);
    Client { child, socket, stderr, dir }
}

/// [`spawn_client`] at a given socket path, its session file in `scratch`.
pub fn spawn_client_at(session: Option<&[u8]>, leader: u32, agent_uid: u32, socket: &Path, scratch: &Path, extra: &[&str]) -> (tokio::process::Child, Arc<Mutex<String>>) {
    static N: AtomicU64 = AtomicU64::new(0);
    let mut cmd = tokio::process::Command::new(client_bin());
    cmd.args(["serve", "--leader", &leader.to_string(), "--socket"]).arg(socket).args(["--agent-uid", &agent_uid.to_string()]).args(extra);
    cmd.env_clear().env("PATH", "/usr/bin:/bin").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true);
    // std opens it close-on-exec: it reaches this child alone, on fd 3.
    let file = session.map(|bytes| {
        let path = scratch.join(format!("session-{}.json", N.fetch_add(1, Ordering::SeqCst)));
        std::fs::write(&path, bytes).unwrap();
        std::fs::File::open(&path).unwrap()
    });
    if let Some(f) = &file {
        let fd = std::os::fd::AsRawFd::as_raw_fd(f);
        // SAFETY: dup2/fcntl on a descriptor this process owns, between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                let rc = if fd == 3 { libc::fcntl(3, libc::F_SETFD, 0) } else { libc::dup2(fd, 3) };
                if rc == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = {
        let _held = SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        cmd.spawn().unwrap()
    };
    drop(file);
    let stderr = Arc::new(Mutex::new(String::new()));
    let (pipe, sink) = (child.stderr.take().unwrap(), stderr.clone());
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(pipe).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            let mut s = sink.lock().unwrap();
            s.push_str(&l);
            s.push('\n');
        }
    });
    (child, stderr)
}

/// One request line on a fresh connection to `socket`, its answer line.
pub async fn ask_at(socket: &Path, line: &str) -> Value {
    let mut s = tokio::net::UnixStream::connect(socket).await.unwrap();
    s.write_all(format!("{line}\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    tokio::time::timeout(LIMIT, s.read_to_string(&mut out)).await.expect("an answer").unwrap();
    serde_json::from_str(out.trim_end()).unwrap_or_else(|e| panic!("{e}: {out:?}"))
}

impl Client {
    /// A client of this test process (its leader) and `uid` for `session`, ready to serve.
    pub async fn ready(session: &str, extra: &[&str]) -> Client {
        let c = spawn_client(Some(session.as_bytes()), std::process::id(), uid(), extra);
        c.wait_ready().await;
        c
    }

    pub async fn wait_ready(&self) {
        assert!(eventually(LIMIT, || self.log().contains("ai-env-relay-client: ready ")).await, "no ready line: {}", self.log());
    }

    pub fn log(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// The exit code within `limit` (the child reaped).
    pub async fn exit_within(&mut self, limit: Duration) -> Option<i32> {
        tokio::time::timeout(limit, self.child.wait()).await.ok().map(|s| s.unwrap().code().unwrap_or(-1))
    }

    /// One request line on a fresh connection, its answer line.
    pub async fn ask(&self, line: &str) -> Value {
        ask_at(&self.socket, line).await
    }
}

/// A `sleep 60` that stands for a leader that is not this process; killed on drop.
pub fn sleeper() -> tokio::process::Child {
    let _held = SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    tokio::process::Command::new("sleep").arg("60").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap()
}

// ---- the real MCP server -----------------------------------------------------------------------

/// A running `ai-env-relay-mcp`, this process's child.
pub struct Mcp {
    pub child: tokio::process::Child,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    pub stdout_seen: String,
    pub stderr: Arc<Mutex<String>>,
}

impl Mcp {
    /// `ai-env-relay-mcp <args>`, initialized.
    pub async fn start(args: &[&str]) -> Mcp {
        let mut cmd = tokio::process::Command::new(mcp_bin());
        cmd.args(args).env_clear().env("PATH", "/usr/bin:/bin").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        let mut child = {
            let _held = SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            cmd.spawn().unwrap()
        };
        let stderr = Arc::new(Mutex::new(String::new()));
        let (mut pipe, sink) = (child.stderr.take().unwrap(), stderr.clone());
        tokio::spawn(async move {
            let mut buf = String::new();
            let _ = pipe.read_to_string(&mut buf).await;
            sink.lock().unwrap().push_str(&buf);
        });
        let stdin = child.stdin.take();
        let stdout = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut m = Mcp { child, stdin, stdout, stdout_seen: String::new(), stderr };
        m.send(&json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "relay-test", "version": "0"}}})).await;
        let init = m.next().await;
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18", "{init}");
        m.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
        m
    }

    pub async fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(format!("{message}\n").as_bytes()).await.unwrap();
        stdin.flush().await.unwrap();
    }

    /// The next line, parsed.
    pub async fn next(&mut self) -> Value {
        let line = tokio::time::timeout(LIMIT, self.stdout.next_line()).await.expect("an MCP line in time").unwrap().expect("a line before EOF");
        self.stdout_seen.push_str(&line);
        self.stdout_seen.push('\n');
        serde_json::from_str(&line).unwrap()
    }

    /// The next line within `wait`, if any.
    pub async fn next_within(&mut self, wait: Duration) -> Option<Value> {
        let line = tokio::time::timeout(wait, self.stdout.next_line()).await.ok()?.ok()??;
        self.stdout_seen.push_str(&line);
        self.stdout_seen.push('\n');
        Some(serde_json::from_str(&line).unwrap())
    }

    /// `tools/call` of `name` with `args`; the tool's text (parsed) and `isError`.
    pub async fn tool(&mut self, id: u64, name: &str, args: Value) -> (Value, bool) {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})).await;
        let reply = self.next().await;
        assert_eq!(reply["id"], id, "{reply}");
        tool_text(&reply)
    }

    /// stdin closed: the server finishes and exits.
    pub fn close(&mut self) {
        self.stdin = None;
    }
}

/// A tool result's text (parsed) and `isError`.
pub fn tool_text(reply: &Value) -> (Value, bool) {
    let r = &reply["result"];
    let text = r["content"][0]["text"].as_str().unwrap_or_else(|| panic!("a text content: {reply}"));
    (serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}")), r["isError"].as_bool().unwrap())
}

/// The raw text of a tool result.
pub fn raw_text(reply: &Value) -> String {
    reply["result"]["content"][0]["text"].as_str().unwrap().to_string()
}

/// A file's bytes, for tests that read what a child wrote.
pub fn read_all(path: &Path) -> String {
    let mut s = String::new();
    let _ = std::fs::File::open(path).and_then(|mut f| f.read_to_string(&mut s));
    s
}
