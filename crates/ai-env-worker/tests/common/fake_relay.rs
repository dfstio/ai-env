//! A scripted relay for the worker's tests (§WM-worker-mac.8.2): `WorkerTunnel` (tonic's server) behind a
//! tokio-rustls acceptor, over the server half of a `tokio::io::duplex` the worker dials through
//! `RelayEndpoint::dialer`, or over TCP on `127.0.0.1:0`. It sends the `Challenge`, verifies the `AuthProof`
//! with §P's transcript and `PublicKey::verify`, answers `AuthOk`, takes the `Catalog`, and then hands the
//! tunnel to the test, which sends frames and reads the worker's. It records each dial, each TLS connection
//! (and the ALPN it negotiated) and each tunnel's end.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ai_env_worker::ai_env_source::wire;
use ai_env_worker::keys::PublicKey;
use ai_env_worker::{Dial, Io};
use ai_env_relay_proto::v1::worker_tunnel_server::{WorkerTunnel, WorkerTunnelServer};
use ai_env_relay_proto::v1::{relay_frame, worker_frame, AuthOk, Catalog, Challenge, Chunk, Hello, Invoke, Limits, RelayFrame, WorkerFrame};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_stream::wrappers::{ReceiverStream, UnboundedReceiverStream};
use tonic::{Request, Response, Status, Streaming};

use super::certs::Pair;

/// The relay id the fake's challenges carry.
pub const RELAY_ID: &str = "relay-test";
/// The tunnel id of every `AuthOk`.
pub const TUNNEL_ID: &str = "0199a1b2-0000-7000-8000-00000000000a";
/// The whitelist version of every `AuthOk`.
pub const WHITELIST_VERSION: u64 = 0x0123_4567_89ab_cdef;
/// Every wait of the fake on the worker.
pub const WAIT: Duration = Duration::from_secs(10);

/// How the fake answers the next handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    /// Challenge, Hello, AuthProof (verified), AuthOk, Catalog; then the test drives.
    Accept,
    /// The proof is answered `UNAUTHENTICATED`, as the relay answers every failed handshake (P-R9).
    RefuseProof,
    /// The test drives from right after the AuthProof (no AuthOk yet).
    AfterProof,
    /// A challenge of protocol 0: an older relay.
    OldProtocol,
}

/// What the fake recorded.
#[derive(Default)]
struct Log {
    dials: Vec<Instant>,
    alpn: Vec<Option<Vec<u8>>>,
    ends: Vec<Instant>,
}

struct Shared {
    connections: AtomicUsize,
    log: Mutex<Log>,
    script: Mutex<VecDeque<Script>>,
    tunnels: mpsc::UnboundedSender<Tunnel>,
}

impl Shared {
    fn next_script(&self) -> Script {
        self.script.lock().expect("script").pop_front().unwrap_or(Script::Accept)
    }

    fn ended(&self) {
        self.log.lock().expect("log").ends.push(Instant::now());
    }
}

/// A fake relay; dropped, it stops serving.
pub struct FakeRelay {
    shared: Arc<Shared>,
    tunnels: mpsc::UnboundedReceiver<Tunnel>,
    conns: mpsc::UnboundedSender<DuplexStream>,
    /// The TCP port when it listens on `127.0.0.1`.
    pub port: Option<u16>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// The worker's dialer: a new duplex per dial, the other half to the fake.
pub struct DuplexDialer {
    shared: Arc<Shared>,
    conns: mpsc::UnboundedSender<DuplexStream>,
}

impl Dial for DuplexDialer {
    fn dial(&self) -> ai_env_worker::BoxFuture<'static, std::io::Result<Box<dyn Io>>> {
        self.shared.log.lock().expect("log").dials.push(Instant::now());
        let (client, server) = tokio::io::duplex(1 << 17);
        let sent = self.conns.send(server);
        Box::pin(async move {
            sent.map_err(|_| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "the fake relay is gone"))?;
            Ok(Box::new(client) as Box<dyn Io>)
        })
    }
}

/// The server's rustls configuration: TLS 1.3, ALPN h2, the given leaf.
pub fn server_config(pair: &Pair) -> Arc<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pair.cert_pem).collect::<Result<_, _>>().expect("certs");
    let key = PrivateKeyDer::from_pem_slice(&pair.key_pem).expect("a key");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("a server config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

impl FakeRelay {
    /// A fake over duplex streams (`dialer()`), serving `pair`.
    pub fn start(pair: &Pair) -> FakeRelay {
        Self::start_with(pair, false)
    }

    /// A fake that also listens on TCP `127.0.0.1:<port>`.
    pub async fn start_tcp(pair: &Pair) -> FakeRelay {
        let mut fake = Self::start_with(pair, false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        fake.port = Some(listener.local_addr().expect("addr").port());
        let shared = fake.shared.clone();
        let tls = tokio_rustls::TlsAcceptor::from(server_config(pair));
        let (to_server, incoming) = mpsc::unbounded_channel::<Result<Conn<tokio::net::TcpStream>, std::io::Error>>();
        fake.tasks.push(tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                shared.log.lock().expect("log").dials.push(Instant::now());
                let (tls, shared, to_server) = (tls.clone(), shared.clone(), to_server.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = tls.accept(tcp).await {
                        shared.connections.fetch_add(1, Ordering::SeqCst);
                        shared.log.lock().expect("log").alpn.push(stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec));
                        let _ = to_server.send(Ok(Conn(stream)));
                    }
                });
            }
        }));
        let service = WorkerTunnelServer::new(Fake { shared: fake.shared.clone() });
        fake.tasks.push(tokio::spawn(async move {
            let incoming = UnboundedReceiverStream::new(incoming);
            let _ = tonic::transport::Server::builder().serve_with_incoming(service, incoming).await;
        }));
        fake
    }

    fn start_with(pair: &Pair, _tcp: bool) -> FakeRelay {
        let (tunnels_tx, tunnels) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared { connections: AtomicUsize::new(0), log: Mutex::default(), script: Mutex::default(), tunnels: tunnels_tx });
        let (conns, mut accepted) = mpsc::unbounded_channel::<DuplexStream>();
        let (to_server, incoming) = mpsc::unbounded_channel::<Result<Conn<DuplexStream>, std::io::Error>>();
        let tls = tokio_rustls::TlsAcceptor::from(server_config(pair));
        let accept_shared = shared.clone();
        let acceptor = tokio::spawn(async move {
            while let Some(server_half) = accepted.recv().await {
                let (tls, shared, to_server) = (tls.clone(), accept_shared.clone(), to_server.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = tls.accept(server_half).await {
                        shared.connections.fetch_add(1, Ordering::SeqCst);
                        shared.log.lock().expect("log").alpn.push(stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec));
                        let _ = to_server.send(Ok(Conn(stream)));
                    }
                });
            }
        });
        let service = WorkerTunnelServer::new(Fake { shared: shared.clone() });
        let server = tokio::spawn(async move {
            let incoming = UnboundedReceiverStream::new(incoming);
            let _ = tonic::transport::Server::builder().serve_with_incoming(service, incoming).await;
        });
        FakeRelay { shared, tunnels, conns, port: None, tasks: vec![acceptor, server] }
    }

    /// The worker's `Dial` into this fake.
    pub fn dialer(&self) -> Arc<dyn Dial> {
        Arc::new(DuplexDialer { shared: self.shared.clone(), conns: self.conns.clone() })
    }

    /// How the next handshakes go, in order (then `Accept`).
    pub fn script(&self, steps: &[Script]) {
        self.shared.script.lock().expect("script").extend(steps.iter().copied());
    }

    /// The next tunnel past its handshake, within `within`.
    pub async fn tunnel(&mut self, within: Duration) -> Tunnel {
        tokio::time::timeout(within, self.tunnels.recv()).await.expect("a tunnel in time").expect("the fake runs")
    }

    /// No tunnel within `within`.
    pub async fn no_tunnel(&mut self, within: Duration) -> bool {
        tokio::time::timeout(within, self.tunnels.recv()).await.is_err()
    }

    /// TLS connections accepted so far.
    pub fn connections(&self) -> usize {
        self.shared.connections.load(Ordering::SeqCst)
    }

    /// Each dial's time.
    pub fn dials(&self) -> Vec<Instant> {
        self.shared.log.lock().expect("log").dials.clone()
    }

    /// Each connection's ALPN.
    pub fn alpn(&self) -> Vec<Option<Vec<u8>>> {
        self.shared.log.lock().expect("log").alpn.clone()
    }

    /// When the fake ended each handshake it refused.
    pub fn refusals(&self) -> Vec<Instant> {
        self.shared.log.lock().expect("log").ends.clone()
    }

    /// Waits until `n` dials happened (or `within` passed): the dials' times.
    pub async fn wait_dials(&self, n: usize, within: Duration) -> Vec<Instant> {
        let until = Instant::now() + within;
        loop {
            let dials = self.dials();
            if dials.len() >= n || Instant::now() >= until {
                return dials;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// A TLS stream as tonic's server takes it.
struct Conn<S>(tokio_rustls::server::TlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Conn<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Conn<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S> tonic::transport::server::Connected for Conn<S> {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

/// The service.
struct Fake {
    shared: Arc<Shared>,
}

#[tonic::async_trait]
impl WorkerTunnel for Fake {
    type OpenStream = ReceiverStream<Result<RelayFrame, Status>>;

    async fn open(&self, request: Request<Streaming<WorkerFrame>>) -> Result<Response<Self::OpenStream>, Status> {
        let (tx, rx) = mpsc::channel(256);
        let inbound = request.into_inner();
        let script = self.shared.next_script();
        let shared = self.shared.clone();
        tokio::spawn(async move { handshake(shared, script, inbound, tx).await });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// The next frame's arm from the worker within `WAIT`.
async fn next_msg(inbound: &mut Streaming<WorkerFrame>) -> Option<worker_frame::Msg> {
    match tokio::time::timeout(WAIT, inbound.message()).await {
        Ok(Ok(Some(WorkerFrame { msg }))) => msg,
        _ => None,
    }
}

async fn handshake(shared: Arc<Shared>, script: Script, mut inbound: Streaming<WorkerFrame>, tx: mpsc::Sender<Result<RelayFrame, Status>>) {
    let mut nonce = vec![0u8; wire::NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).expect("random");
    let protocol = if script == Script::OldProtocol { 0 } else { 1 };
    let challenge = Challenge { nonce: nonce.clone(), relay_id: RELAY_ID.into(), protocol };
    if tx.send(Ok(RelayFrame { msg: Some(relay_frame::Msg::Challenge(challenge)) })).await.is_err() {
        return;
    }
    let Some(worker_frame::Msg::Hello(hello)) = next_msg(&mut inbound).await else {
        shared.ended();
        return;
    };
    let Some(worker_frame::Msg::AuthProof(proof)) = next_msg(&mut inbound).await else {
        shared.ended();
        return;
    };
    let transcript = wire::transcript(RELAY_ID, &nonce, &hello.worker_id, hello.alg as u32, &hello.public_key, hello.protocol);
    let proof_ok = PublicKey::from_bytes(&hello.public_key).is_ok_and(|k| k.verify(&transcript, &proof.signature));
    if script == Script::RefuseProof || !proof_ok {
        let _ = tx.send(Err(Status::unauthenticated("authentication failed"))).await;
        shared.ended();
        return;
    }
    if script == Script::AfterProof {
        let _ = shared.tunnels.send(Tunnel { hello, proof_ok, catalog: None, tx, inbound, opened: Instant::now(), pending: HashMap::new() });
        return;
    }
    let ok = AuthOk { tunnel_id: TUNNEL_ID.into(), whitelist_version: WHITELIST_VERSION };
    if tx.send(Ok(RelayFrame { msg: Some(relay_frame::Msg::AuthOk(ok)) })).await.is_err() {
        return;
    }
    let Some(worker_frame::Msg::Catalog(catalog)) = next_msg(&mut inbound).await else {
        shared.ended();
        return;
    };
    let _ = shared.tunnels.send(Tunnel { hello, proof_ok, catalog: Some(catalog), tx, inbound, opened: Instant::now(), pending: HashMap::new() });
}

/// What the worker sent next.
#[derive(Debug)]
pub enum Next {
    Frame(worker_frame::Msg),
    /// A frame with no arm.
    Unknown,
    /// The worker ended its stream.
    End,
    /// The stream broke (a status).
    Broken(Status),
    Timeout,
}

/// One tunnel the fake accepted.
pub struct Tunnel {
    pub hello: Hello,
    pub proof_ok: bool,
    pub catalog: Option<Catalog>,
    pub opened: Instant,
    tx: mpsc::Sender<Result<RelayFrame, Status>>,
    inbound: Streaming<WorkerFrame>,
    /// Chunks read while waiting for others, by request id.
    pending: HashMap<String, Vec<Chunk>>,
}

/// A tunnel's sending half, for a task that sends while the test reads.
#[derive(Clone)]
pub struct Sender(mpsc::Sender<Result<RelayFrame, Status>>);

impl Sender {
    /// One relay frame to the worker.
    pub async fn send(&self, msg: relay_frame::Msg) {
        self.0.send(Ok(RelayFrame { msg: Some(msg) })).await.expect("the tunnel is open");
    }
}

impl Tunnel {
    /// A sending half of this tunnel.
    pub fn sender(&self) -> Sender {
        Sender(self.tx.clone())
    }

    /// One relay frame to the worker.
    pub async fn send(&self, msg: relay_frame::Msg) {
        self.tx.send(Ok(RelayFrame { msg: Some(msg) })).await.expect("the tunnel is open");
    }

    /// A frame with no arm (a newer relay's).
    pub async fn send_unknown(&self) {
        self.tx.send(Ok(RelayFrame { msg: None })).await.expect("the tunnel is open");
    }

    /// The fake ends the stream with `status`; when it did.
    pub async fn fail(self, status: Status) -> Instant {
        let _ = self.tx.send(Err(status)).await;
        Instant::now()
    }

    /// A `Close`, then the stream's end (R-27); when the fake ended it.
    pub async fn close(self, code: u32, reason: &str) -> Instant {
        let _ = self.tx.send(Ok(RelayFrame { msg: Some(relay_frame::Msg::Close(ai_env_relay_proto::v1::Close { code, reason: reason.into() })) })).await;
        Instant::now()
    }

    /// The fake drops the stream without a `Close`; when it did.
    pub fn drop_stream(self) -> Instant {
        drop(self);
        Instant::now()
    }

    /// What the worker sent next, within `within`.
    pub async fn next(&mut self, within: Duration) -> Next {
        match tokio::time::timeout(within, self.inbound.message()).await {
            Err(_) => Next::Timeout,
            Ok(Err(status)) => Next::Broken(status),
            Ok(Ok(None)) => Next::End,
            Ok(Ok(Some(WorkerFrame { msg: None }))) => Next::Unknown,
            Ok(Ok(Some(WorkerFrame { msg: Some(m) }))) => Next::Frame(m),
        }
    }

    /// The worker's stream ended (or broke) within `within`, all frames before it skipped.
    pub async fn ended(&mut self, within: Duration) -> bool {
        let until = Instant::now() + within;
        loop {
            match self.next(until.saturating_duration_since(Instant::now())).await {
                Next::End | Next::Broken(_) => return true,
                Next::Timeout => return false,
                Next::Frame(_) | Next::Unknown => {}
            }
        }
    }

    /// Every chunk of `request_id` through its final one, within `within`; chunks of other calls read
    /// meanwhile are kept for them.
    pub async fn call(&mut self, request_id: &str, within: Duration) -> Vec<Chunk> {
        let until = Instant::now() + within;
        loop {
            if self.pending.get(request_id).is_some_and(|c| c.last().is_some_and(|l| l.r#final)) {
                return self.pending.remove(request_id).unwrap_or_default();
            }
            match self.next(until.saturating_duration_since(Instant::now())).await {
                Next::Frame(worker_frame::Msg::Chunk(c)) => self.pending.entry(c.request_id.clone()).or_default().push(c),
                Next::Frame(_) | Next::Unknown => {}
                other => panic!("waiting for {request_id}: {other:?}; so far {:?}", self.pending.get(request_id).map(Vec::len)),
            }
        }
    }

    /// Chunks of `request_id` read so far (without waiting).
    pub fn seen(&self, request_id: &str) -> usize {
        self.pending.get(request_id).map_or(0, Vec::len)
    }

    /// Reads for `within`, keeping every chunk: no frame may name a request id outside `allowed`.
    pub async fn drain(&mut self, within: Duration) -> Vec<worker_frame::Msg> {
        let until = Instant::now() + within;
        let mut out = Vec::new();
        loop {
            match self.next(until.saturating_duration_since(Instant::now())).await {
                Next::Frame(m) => out.push(m),
                Next::Unknown => {}
                _ => return out,
            }
        }
    }
}

/// An `Invoke` of `op` on `source` with `params`, a deadline and limits (0: not given).
pub fn invoke(request_id: &str, source: &str, op: &str, params: &str, deadline_ms: u32, limits: (u64, u32, u32)) -> relay_frame::Msg {
    relay_frame::Msg::Invoke(Invoke {
        request_id: request_id.into(),
        source: source.into(),
        op: op.into(),
        params_json: params.as_bytes().to_vec(),
        caller: Some(ai_env_relay_proto::v1::Caller {
            caller_id: "mac".into(),
            session_id: "0199a1b2-0000-7000-8000-000000000002".into(),
            grant_id: "default".into(),
            vm_id: "microvm-0199a1b2-0000-7000-8000-000000000001".into(),
        }),
        deadline_ms,
        limits: Some(Limits { max_bytes: limits.0, max_rows: limits.1, max_chunks: limits.2 }),
    })
}

/// A `Cancel`.
pub fn cancel(request_id: &str) -> relay_frame::Msg {
    relay_frame::Msg::Cancel(ai_env_relay_proto::v1::Cancel { request_id: request_id.into(), reason: wire::cancel::CALLER_GONE.into() })
}

/// A `Ping`.
pub fn ping(seq: u64) -> relay_frame::Msg {
    relay_frame::Msg::Ping(ai_env_relay_proto::v1::Ping { seq })
}
