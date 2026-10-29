//! The in-process relay (I-L2): `RelayApp` with a `ManualClock`, a `MemorySink` and `params_key` `[9u8; 32]`,
//! both faces served over `tokio::io::duplex` streams wrapped in `Peered::new`, and a live directory written at
//! run time (the three lists, `tls.pem` and `fetched`).

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ai_env_relay::files::{FETCHED_FILE, TLS_FILE};
use ai_env_relay::lists::{Grant, SignerEntry, WorkerEntry, GRANTS_FILE, SIGNERS_FILE, WORKERS_FILE};
use ai_env_relay::reqlog::MemorySink;
use ai_env_relay::{Config, Deps, Limits, Peered, RelayApp, RelayError};
use ai_env_relay_proto::v1::relay_client::RelayClient;
use ai_env_relay_proto::v1::{CallChunk, CallRequest, ListSourcesRequest, ListSourcesResponse, OpDescriptor, SourceDescriptor};
use ai_env_worker::keys::SigningKey;
use ai_env_worker::policy;
use ai_env_worker::session::{self, SessionClaims, SESSION_AUD};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tonic::transport::{Channel, Endpoint, Uri};

use super::certs;
use super::clock::ManualClock;

/// The rig's wall clock at start: 2027-01-15T08:00:00Z.
pub const T0: u64 = 1_800_000_000;
/// The workers' and the signer's `not_after` (well after `T0`).
pub const NOT_AFTER: &str = "2027-06-01T00:00:00Z";
/// The rig's relay id.
pub const RELAY_ID: &str = "relay-test";
/// The workers' address on the public face (a documentation range).
pub const WORKER_IP: &str = "198.51.100.10";
/// The VMs' address on the private face.
pub const VM_IP: &str = "10.42.1.10";
/// The VM id in every token.
pub const VM_ID: &str = "microvm-0199a1b2-0000-7000-8000-000000000001";

/// A whitelist entry of a seed's key.
pub fn worker_entry(id: &str, seed: u8, globs: &[&str], not_after: &str) -> WorkerEntry {
    WorkerEntry {
        worker_id: id.into(),
        alg: "ed25519".into(),
        public_key: SigningKey::from_seed(&[seed; 32]).unwrap().public_key().b64(),
        sources: globs.iter().map(|g| g.to_string()).collect(),
        not_after: not_after.into(),
    }
}

/// A, B and C as §R-relay.7 seeds them.
pub fn default_workers() -> Vec<WorkerEntry> {
    vec![
        worker_entry("worker-a", 1, &["example.alpha*"], NOT_AFTER),
        worker_entry("worker-b", 2, &["example.beta*"], NOT_AFTER),
        worker_entry("worker-c", 5, &["example.gamma*"], NOT_AFTER),
    ]
}

/// The token signer `mac` (seed 7).
pub fn mac_signer(not_after: &str) -> SignerEntry {
    SignerEntry { signer_id: "mac".into(), alg: "ed25519".into(), public_key: SigningKey::from_seed(&[7; 32]).unwrap().public_key().b64(), not_after: not_after.into() }
}

/// `g-all` (`*/*`), `g-alpha-get` (`example.alpha/get`) and `g-example` (`example.*/*`).
pub fn default_grants() -> Vec<Grant> {
    vec![
        Grant { grant_id: "g-all".into(), allow: vec!["*/*".into()] },
        Grant { grant_id: "g-alpha-get".into(), allow: vec!["example.alpha/get".into()] },
        Grant { grant_id: "g-example".into(), allow: vec!["example.*/*".into()] },
    ]
}

/// A source with these ops (JSON output, read-only, an object schema).
pub fn source(name: &str, ops: &[&str]) -> SourceDescriptor {
    SourceDescriptor {
        name: name.into(),
        version: "1.0.0".into(),
        description: "a test source".into(),
        kind: 7,
        env: "test".into(),
        sensitivity: 2,
        ops: ops
            .iter()
            .map(|o| OpDescriptor {
                name: o.to_string(),
                description: "a test op".into(),
                params_json_schema: "{\"type\":\"object\"}".into(),
                output: 1,
                read_only: true,
                ..Default::default()
            })
            .collect(),
    }
}

/// A's catalog: `example.alpha` (its `get` capped at {2 MiB, 500 rows, 0}) and `example.alpha.logs`.
pub fn catalog_a() -> Vec<SourceDescriptor> {
    let mut alpha = source("example.alpha", &["get", "list"]);
    alpha.ops[0].max_limits = Some(ai_env_relay_proto::v1::Limits { max_bytes: 2 << 20, max_rows: 500, max_chunks: 0 });
    vec![alpha, source("example.alpha.logs", &["get", "list"])]
}

/// B's catalog: `example.beta`.
pub fn catalog_b() -> Vec<SourceDescriptor> {
    vec![source("example.beta", &["get", "list"])]
}

/// C's catalog: `example.gamma`.
pub fn catalog_c() -> Vec<SourceDescriptor> {
    vec![source("example.gamma", &["get"])]
}

/// The rig's limits: the defaults, with the HTTP/2 keepalive off.
pub fn limits() -> Limits {
    Limits { h2_keepalive_s: 0, ..Limits::default() }
}

/// One side of a connection the test can pause (its reads stop) or cut (the stream is dropped).
pub struct Link {
    ctl: Arc<LinkCtl>,
}

struct LinkCtl {
    io: Mutex<Option<DuplexStream>>,
    paused: AtomicBool,
    waker: Mutex<Option<Waker>>,
    /// When the relay's end went (the client read the connection's end), on tokio's clock.
    peer_closed: Mutex<Option<tokio::time::Instant>>,
}

impl Link {
    /// Stops reading: the peer's writes fill the pipe and then wait.
    pub fn pause(&self) {
        self.ctl.paused.store(true, Ordering::SeqCst);
    }

    /// Reads again.
    pub fn resume(&self) {
        self.ctl.paused.store(false, Ordering::SeqCst);
        if let Some(w) = self.ctl.waker.lock().unwrap().take() {
            w.wake();
        }
    }

    /// Drops the transport: the peer sees the connection end.
    pub fn cut(&self) {
        self.ctl.io.lock().unwrap().take();
        if let Some(w) = self.ctl.waker.lock().unwrap().take() {
            w.wake();
        }
    }

    /// When the relay closed the connection (the client read its end), if it did.
    pub fn peer_closed_at(&self) -> Option<tokio::time::Instant> {
        *self.ctl.peer_closed.lock().unwrap()
    }
}

/// The client's end of a `Link`.
pub struct LinkIo(Arc<LinkCtl>);

impl AsyncRead for LinkIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.0.paused.load(Ordering::SeqCst) {
            *self.0.waker.lock().unwrap() = Some(cx.waker().clone());
            if self.0.paused.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        let mut io = self.0.io.lock().unwrap();
        match io.as_mut() {
            Some(s) => {
                let before = buf.filled().len();
                let read = Pin::new(s).poll_read(cx, buf);
                if matches!(read, Poll::Ready(Ok(()))) && buf.filled().len() == before && buf.remaining() > 0 {
                    self.0.peer_closed.lock().unwrap().get_or_insert_with(tokio::time::Instant::now);
                }
                read
            }
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for LinkIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut io = self.0.io.lock().unwrap();
        match io.as_mut() {
            Some(s) => Pin::new(s).poll_write(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut io = self.0.io.lock().unwrap();
        match io.as_mut() {
            Some(s) => Pin::new(s).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut io = self.0.io.lock().unwrap();
        match io.as_mut() {
            Some(s) => Pin::new(s).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

type Incoming = mpsc::UnboundedSender<Result<Peered<DuplexStream>, io::Error>>;

/// A client over a new duplex connection to one face; the endpoint's options are the caller's.
pub async fn connect_with(tx: &Incoming, ip: IpAddr, endpoint: Endpoint, pipe: usize) -> (Channel, Link) {
    let (client, server) = tokio::io::duplex(pipe);
    tx.send(Ok(Peered::new(server, ip))).expect("the face is served");
    let ctl = Arc::new(LinkCtl { io: Mutex::new(Some(client)), paused: AtomicBool::new(false), waker: Mutex::new(None), peer_closed: Mutex::new(None) });
    let mut once = Some(LinkIo(Arc::clone(&ctl)));
    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let io = once.take();
            async move { io.map(hyper_util::rt::TokioIo::new).ok_or_else(|| io::Error::other("one connection per channel")) }
        }))
        .await
        .expect("the duplex connects");
    (channel, Link { ctl })
}

/// The relay in-process.
pub struct Rig {
    pub app: RelayApp,
    pub clock: Arc<ManualClock>,
    pub sink: Arc<MemorySink>,
    pub dir: tempfile::TempDir,
    public: Incoming,
    private: Incoming,
    pub public_srv: Option<JoinHandle<Result<(), RelayError>>>,
    pub private_srv: Option<JoinHandle<Result<(), RelayError>>>,
    sessions: AtomicU64,
}

impl Rig {
    /// The rig with the rig's limits.
    pub async fn start() -> Rig {
        Rig::start_with(limits()).await
    }

    /// The rig with these limits, every live file written and polled once.
    pub async fn start_with(limits: Limits) -> Rig {
        Rig::start_without(limits, &[]).await
    }

    /// The rig with these limits and every live file but `skip` written, then polled once.
    pub async fn start_without(limits: Limits, skip: &[&str]) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let clock = ManualClock::at(T0);
        let sink = Arc::new(MemorySink::default());
        let cfg = Config {
            relay_id: RELAY_ID.into(),
            public_addr: "127.0.0.1:0".parse().unwrap(),
            private_addr: "127.0.0.1:0".parse().unwrap(),
            private_peers: vec!["10.42.1.0/24".parse().unwrap()],
            live_dir: dir.path().to_path_buf(),
            request_log: dir.path().join("requests.log"),
            limits,
        };
        let deps = Deps { clock: clock.clone(), sink: sink.clone(), params_key: [9; 32], notifier: ai_env_relay::notify::Notifier::disabled() };
        let app = RelayApp::new(cfg, deps).expect("the rig's config is valid");
        let (public, public_rx) = mpsc::unbounded_channel();
        let (private, private_rx) = mpsc::unbounded_channel();
        let public_srv = tokio::spawn({
            let app = app.clone();
            async move { app.serve_public(tokio_stream::wrappers::UnboundedReceiverStream::new(public_rx)).await }
        });
        let private_srv = tokio::spawn({
            let app = app.clone();
            async move { app.serve_private(tokio_stream::wrappers::UnboundedReceiverStream::new(private_rx)).await }
        });
        let rig = Rig { app, clock, sink, dir, public, private, public_srv: Some(public_srv), private_srv: Some(private_srv), sessions: AtomicU64::new(1) };
        if !skip.contains(&WORKERS_FILE) {
            rig.write_workers(&default_workers());
        }
        if !skip.contains(&SIGNERS_FILE) {
            rig.write_signers(&[mac_signer(NOT_AFTER)]);
        }
        if !skip.contains(&GRANTS_FILE) {
            rig.write_grants(&default_grants());
        }
        if !skip.contains(&TLS_FILE) {
            let ca = certs::Ca::new("test relay CA", [11; 32]);
            let leaf = ca.leaf(1, &["ai-env-relay"], &[[10, 42, 0, 20]], [12; 32]);
            rig.write(TLS_FILE, certs::tls_pem(&leaf, &ca).as_bytes());
        }
        if !skip.contains(&FETCHED_FILE) {
            rig.write_fetched(T0);
        }
        rig.app.poll_files();
        rig
    }

    pub fn path(&self, file: &str) -> PathBuf {
        self.dir.path().join(file)
    }

    /// Replaces a live file by one rename, as I's reload does.
    pub fn write(&self, file: &str, bytes: &[u8]) {
        let tmp = self.dir.path().join(format!(".{file}.tmp"));
        std::fs::write(&tmp, bytes).unwrap();
        std::fs::rename(&tmp, self.path(file)).unwrap();
    }

    pub fn remove(&self, file: &str) {
        let _ = std::fs::remove_file(self.path(file));
    }

    pub fn write_workers(&self, list: &[WorkerEntry]) {
        self.write(WORKERS_FILE, policy::render_workers(list).unwrap().as_bytes());
    }

    pub fn write_signers(&self, list: &[SignerEntry]) {
        self.write(SIGNERS_FILE, policy::render_signers(list).unwrap().as_bytes());
    }

    pub fn write_grants(&self, list: &[Grant]) {
        self.write(GRANTS_FILE, policy::render_grants(list).unwrap().as_bytes());
    }

    pub fn write_fetched(&self, unix: u64) {
        self.write(FETCHED_FILE, format!("{unix}\n").as_bytes());
    }

    /// The live files' bytes.
    pub fn read(&self, file: &str) -> Vec<u8> {
        std::fs::read(self.path(file)).unwrap()
    }

    /// `poll_files()`.
    pub fn poll(&self) -> [(&'static str, ai_env_relay::files::Poll); 4] {
        self.app.poll_files()
    }

    /// A worker's connection to the public face.
    pub async fn public_channel(&self) -> (Channel, Link) {
        connect_with(&self.public, WORKER_IP.parse().unwrap(), Endpoint::from_static("http://ai-env-relay"), 1 << 20).await
    }

    /// A worker's connection with these endpoint options and pipe size.
    pub async fn public_channel_with(&self, endpoint: Endpoint, pipe: usize) -> (Channel, Link) {
        connect_with(&self.public, WORKER_IP.parse().unwrap(), endpoint, pipe).await
    }

    /// A VM's connection to the private face.
    pub async fn private_channel(&self) -> (Channel, Link) {
        connect_with(&self.private, VM_IP.parse().unwrap(), Endpoint::from_static("http://10.42.0.20"), 1 << 20).await
    }

    /// A VM's connection with these endpoint options and pipe size.
    pub async fn private_channel_with(&self, endpoint: Endpoint, pipe: usize) -> (Channel, Link) {
        connect_with(&self.private, VM_IP.parse().unwrap(), endpoint, pipe).await
    }

    /// A bare connection to the private face, its client's end, for a test that speaks HTTP/2 frame by frame.
    pub fn private_raw(&self, pipe: usize) -> DuplexStream {
        let (client, server) = tokio::io::duplex(pipe);
        self.private.send(Ok(Peered::new(server, VM_IP.parse().unwrap()))).expect("the face is served");
        client
    }

    /// A VM client.
    pub async fn client(&self) -> RelayClient<Channel> {
        RelayClient::new(self.private_channel().await.0)
    }

    /// A fresh session id.
    pub fn session_id(&self) -> String {
        format!("0199a1b2-0000-7000-8000-{:012x}", self.sessions.fetch_add(1, Ordering::SeqCst))
    }

    /// The claims of a fresh session with `grant_id`, issued now for an hour.
    pub fn claims(&self, grant_id: &str) -> SessionClaims {
        let iat = self.clock.unix();
        SessionClaims {
            kid: "mac".into(),
            aud: SESSION_AUD.into(),
            caller_id: "mac".into(),
            session_id: self.session_id(),
            chat_id: None,
            grant_id: grant_id.into(),
            vm_id: VM_ID.into(),
            iat,
            exp: iat + 3600,
        }
    }

    /// A token of a fresh session with `grant_id`, minted with W/M's `session::mint` by `mac` (seed 7).
    pub fn token(&self, grant_id: &str) -> String {
        mint(7, &self.claims(grant_id))
    }

    /// The request log's lines of one kind.
    pub fn lines(&self, ev: &str) -> Vec<serde_json::Value> {
        self.sink.lines().iter().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()).filter(|v| v["ev"] == ev).collect()
    }

    /// Waits (polling, on tokio's clock) until `f` holds; panics after `within`.
    pub async fn until(&self, within: Duration, what: &str, f: impl Fn(&Rig) -> bool) {
        let until = tokio::time::Instant::now() + within;
        while !f(self) {
            assert!(tokio::time::Instant::now() < until, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// Waits until `n` tunnels are installed.
    pub async fn tunnels(&self, n: u64) {
        self.until(Duration::from_secs(10), &format!("{n} tunnels"), |r| r.app.snapshot().tunnels == n).await;
    }
}

/// A token of `claims` signed by a seed's key.
pub fn mint(seed: u8, claims: &SessionClaims) -> String {
    session::mint(&SigningKey::from_seed(&[seed; 32]).unwrap(), claims, claims.iat).expect("W/M's mint")
}

/// A request carrying `token` in `x-ai-env-session`.
pub fn with_token<T>(msg: T, token: &str) -> tonic::Request<T> {
    let mut r = tonic::Request::new(msg);
    r.metadata_mut().insert(ai_env_relay::session::SESSION_HEADER, token.parse().unwrap());
    r
}

/// `ListSources` with `token`.
pub async fn list(client: &mut RelayClient<Channel>, token: &str) -> Result<ListSourcesResponse, tonic::Status> {
    client.list_sources(with_token(ListSourcesRequest {}, token)).await.map(|r| r.into_inner())
}

/// A `Call` of `source`/`op` with `params` and `token`; its stream.
pub async fn call(client: &mut RelayClient<Channel>, token: &str, source: &str, op: &str, params: &[u8]) -> Result<tonic::Streaming<CallChunk>, tonic::Status> {
    call_with(client, token, CallRequest { source: source.into(), op: op.into(), params_json: params.to_vec(), deadline_ms: 0, limits: None }).await
}

/// A `Call` of this request with `token`.
pub async fn call_with(client: &mut RelayClient<Channel>, token: &str, req: CallRequest) -> Result<tonic::Streaming<CallChunk>, tonic::Status> {
    client.call(with_token(req, token)).await.map(|r| r.into_inner())
}

/// Every chunk of a call's stream, then its status.
pub async fn drain(mut s: tonic::Streaming<CallChunk>) -> (Vec<CallChunk>, Result<(), tonic::Status>) {
    let mut out = Vec::new();
    loop {
        match s.message().await {
            Ok(Some(c)) => out.push(c),
            Ok(None) => return (out, Ok(())),
            Err(e) => return (out, Err(e)),
        }
    }
}

/// The names (and availability) `ListSources` shows.
pub fn names(r: &ListSourcesResponse) -> Vec<(String, bool)> {
    r.sources.iter().map(|s| (s.descriptor.as_ref().unwrap().name.clone(), s.available)).collect()
}

/// A path under the rig (for tests that write extra files).
pub fn join(dir: &Path, file: &str) -> PathBuf {
    dir.join(file)
}

/// A `Call` with `token`, its whole response (the request id is in its metadata).
pub async fn call_response(client: &mut RelayClient<Channel>, token: &str, req: CallRequest) -> Result<tonic::Response<tonic::Streaming<CallChunk>>, tonic::Status> {
    client.call(with_token(req, token)).await
}

/// A call request with no deadline and no limits.
pub fn request(source: &str, op: &str, params: &[u8]) -> CallRequest {
    CallRequest { source: source.into(), op: op.into(), params_json: params.to_vec(), deadline_ms: 0, limits: None }
}

/// The request id a response or a refusal carries (R-30).
pub fn request_id(metadata: &tonic::metadata::MetadataMap) -> String {
    metadata.get(ai_env_relay::private::REQUEST_ID_HEADER).expect("x-ai-env-request-id").to_str().unwrap().to_string()
}
