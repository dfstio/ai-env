//! The relay's TLS and process (§R-relay.7, tls 1 to 10): real loopback sockets through `run`, or
//! `tokio::io::duplex` through `admit`; certificates from `tests/common/certs.rs`, built at run time.

mod common;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ai_env_relay::files::TLS_FILE;
use ai_env_relay::lists::{GRANTS_FILE, SIGNERS_FILE, WORKERS_FILE};
use ai_env_relay::notify::Notifier;
use ai_env_relay::reqlog::MemorySink;
use ai_env_relay::{Config, Deps, Face, Limits, RelayApp};
use ai_env_relay_proto::v1::relay_client::RelayClient;
use ai_env_relay_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use ai_env_relay_proto::v1::{worker_frame, ListSourcesRequest, WorkerFrame};
use ai_env_worker::policy;
use common::certs::{self, Ca, Leaf};
use common::clock::ManualClock;
use common::rig::{catalog_a, default_grants, default_workers, mac_signer, mint, with_token, NOT_AFTER, T0};
use common::worker::{hello, proof, Script, TestWorker};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::Code;

/// One test of this binary at a time: tls 4 sets `WATCHDOG_USEC` for `run` to read, and every other test's `run`
/// reads it too, as C code beside them may (aws-lc reads the environment at its first use); `setenv` must never run
/// beside those reads. A tokio lock, held across each test's awaits (R-73 keeps `std::sync` guards off them).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `WATCHDOG_USEC` set for one test (with no `WATCHDOG_PID`: any pid), and removed when it ends, pass or fail.
struct WatchdogEnv;

impl WatchdogEnv {
    fn set(usec: &str) -> WatchdogEnv {
        std::env::set_var("WATCHDOG_USEC", usec);
        std::env::remove_var("WATCHDOG_PID");
        WatchdogEnv
    }
}

impl Drop for WatchdogEnv {
    fn drop(&mut self) {
        std::env::remove_var("WATCHDOG_USEC");
    }
}

/// A relay with its live directory, for `run` or `admit`.
struct Box_ {
    app: RelayApp,
    sink: Arc<MemorySink>,
    dir: tempfile::TempDir,
    ca: Ca,
    clock: Arc<ManualClock>,
}

fn write(dir: &std::path::Path, file: &str, bytes: &[u8]) {
    let tmp = dir.join(format!(".{file}.tmp"));
    std::fs::write(&tmp, bytes).unwrap();
    std::fs::rename(&tmp, dir.join(file)).unwrap();
}

fn leaf(ca: &Ca, serial: u64, seed: u8) -> Leaf {
    ca.leaf(serial, &["ai-env-relay"], &[[10, 42, 0, 20]], [seed; 32])
}

fn relay(limits: Limits, peers: &[&str], with_tls: bool, notifier: Notifier) -> Box_ {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("test relay CA", [11; 32]);
    write(dir.path(), WORKERS_FILE, policy::render_workers(&default_workers()).unwrap().as_bytes());
    write(dir.path(), SIGNERS_FILE, policy::render_signers(&[mac_signer(NOT_AFTER)]).unwrap().as_bytes());
    write(dir.path(), GRANTS_FILE, policy::render_grants(&default_grants()).unwrap().as_bytes());
    write(dir.path(), "fetched", format!("{T0}\n").as_bytes());
    if with_tls {
        write(dir.path(), TLS_FILE, certs::tls_pem(&leaf(&ca, 1, 12), &ca).as_bytes());
    }
    let clock = ManualClock::at(T0);
    let sink = Arc::new(MemorySink::default());
    let cfg = Config {
        relay_id: "relay-test".into(),
        public_addr: "127.0.0.1:0".parse().unwrap(),
        private_addr: "127.0.0.1:0".parse().unwrap(),
        private_peers: peers.iter().map(|p| p.parse().unwrap()).collect(),
        live_dir: dir.path().to_path_buf(),
        request_log: dir.path().join("requests.log"),
        limits,
    };
    let app = RelayApp::new(cfg, Deps { clock: clock.clone(), sink: sink.clone(), params_key: [9; 32], notifier }).unwrap();
    Box_ { app, sink, dir, ca, clock }
}

fn limits() -> Limits {
    Limits { h2_keepalive_s: 0, ..Limits::default() }
}

/// Starts `run` and waits for both faces to be bound.
async fn running(b: &Box_) -> (tokio::task::JoinHandle<Result<(), ai_env_relay::RelayError>>, SocketAddr, SocketAddr) {
    let app = b.app.clone();
    let task = tokio::spawn(async move { app.run().await });
    for _ in 0..500 {
        if let Some((public, private)) = b.app.bound() {
            return (task, public, private);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("run never bound its faces");
}

fn client_config(roots: &[&Ca], versions: &[&'static rustls::SupportedProtocolVersion]) -> Arc<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    for ca in roots {
        store.add(CertificateDer::from(ca.cert_der.clone())).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(store)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

async fn tls_connect(addr: SocketAddr, cfg: Arc<rustls::ClientConfig>) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    tokio_rustls::TlsConnector::from(cfg).connect(ServerName::try_from("ai-env-relay").unwrap(), tcp).await
}

async fn channel(addr: SocketAddr, cfg: Arc<rustls::ClientConfig>) -> Channel {
    Endpoint::from_static("http://ai-env-relay")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let cfg = Arc::clone(&cfg);
            async move { tls_connect(addr, cfg).await.map(hyper_util::rt::TokioIo::new) }
        }))
        .await
        .expect("a TLS channel")
}

fn token() -> String {
    let claims = ai_env_worker::session::SessionClaims {
        kid: "mac".into(),
        aud: ai_env_worker::session::SESSION_AUD.into(),
        caller_id: "mac".into(),
        session_id: "0199a1b2-0000-7000-8000-000000000002".into(),
        chat_id: None,
        grant_id: "g-all".into(),
        vm_id: common::rig::VM_ID.into(),
        iat: T0,
        exp: T0 + 3600,
    };
    mint(7, &claims)
}

fn rustls_error(e: &io::Error) -> Option<&rustls::Error> {
    e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>())
}

/// Reads until the peer closes; the bytes it wrote.
async fn read_to_close(mut s: TcpStream, within: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    tokio::time::timeout(within, s.read_to_end(&mut out)).await.expect("closed in time").ok();
    out
}

/// TLS 1.
#[tokio::test]
async fn the_relay_speaks_tls13_only() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    let (task, _public, private) = running(&b).await;
    let mut client = RelayClient::new(channel(private, client_config(&[&b.ca], &[&rustls::version::TLS13])).await);
    let listed = client.list_sources(with_token(ListSourcesRequest {}, &token())).await.expect("ListSources over TLS 1.3");
    assert!(listed.into_inner().sources.is_empty());

    let old = tls_connect(private, client_config(&[&b.ca], &[&rustls::version::TLS12])).await.expect_err("TLS 1.2 refused");
    assert!(matches!(rustls_error(&old), Some(rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion))), "{old:?}");

    let other = Ca::new("another CA", [21; 32]);
    let refused = tls_connect(private, client_config(&[&other], &[&rustls::version::TLS13])).await.expect_err("another CA");
    assert!(
        matches!(rustls_error(&refused), Some(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))),
        "{refused:?}"
    );

    let mismatched = certs::tls_pem_with_key(&leaf(&b.ca, 2, 12), &b.ca, &leaf(&b.ca, 3, 13));
    assert!(ai_env_relay::tls::server_config(mismatched.as_bytes()).is_err());
    let config = ai_env_relay::tls::server_config(certs::tls_pem(&leaf(&b.ca, 4, 14), &b.ca).as_bytes()).unwrap();
    assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
    assert_eq!((config.max_early_data_size, config.send_tls13_tickets), (0, 0));
    b.app.shutdown();
    task.await.unwrap().unwrap();
}

/// TLS 2.
#[tokio::test]
async fn no_tls_material_means_no_service() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], false, Notifier::disabled());
    let (task, _public, private) = running(&b).await;
    let tcp = TcpStream::connect(private).await.unwrap();
    assert!(read_to_close(tcp, Duration::from_secs(5)).await.is_empty(), "closed with no byte written");
    assert!(b.sink.lines().iter().any(|l| l.contains("\"reason\":\"no_tls\"")));

    write(b.dir.path(), TLS_FILE, certs::tls_pem(&leaf(&b.ca, 1, 12), &b.ca).as_bytes());
    b.app.poll_files();
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let mut old = RelayClient::new(channel(private, Arc::clone(&cfg)).await);
    old.list_sources(with_token(ListSourcesRequest {}, &token())).await.expect("served once tls.pem is there");

    let new_leaf = leaf(&b.ca, 2, 13);
    write(b.dir.path(), TLS_FILE, certs::tls_pem(&new_leaf, &b.ca).as_bytes());
    b.app.poll_files();
    let fresh = tls_connect(private, Arc::clone(&cfg)).await.unwrap();
    let seen = fresh.get_ref().1.peer_certificates().unwrap()[0].as_ref().to_vec();
    assert_eq!(seen, new_leaf.cert_der, "a new connection sees the new leaf");
    old.list_sources(with_token(ListSourcesRequest {}, &token())).await.expect("an older connection keeps working");
    // A TLS connection that never speaks HTTP/2 would hold the drain to its 5 s.
    drop((fresh, old));
    b.app.shutdown();
    task.await.unwrap().unwrap();
}

/// TLS 3.
#[tokio::test]
async fn a_peer_outside_the_vm_cidr_is_dropped() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["10.42.1.0/24"], true, Notifier::disabled());
    let (task, _public, private) = running(&b).await;
    let tcp = TcpStream::connect(private).await.unwrap();
    assert!(read_to_close(tcp, Duration::from_secs(5)).await.is_empty());
    let peers: Vec<serde_json::Value> = b.sink.lines().iter().map(|l| serde_json::from_str(l).unwrap()).filter(|v: &serde_json::Value| v["ev"] == "peer").collect();
    assert_eq!(peers.len(), 1);
    assert_eq!((peers[0]["face"].as_str(), peers[0]["reason"].as_str()), (Some("private"), Some("not_in_peers")));
    b.app.shutdown();
    task.await.unwrap().unwrap();

    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    let (task, _public, private) = running(&b).await;
    tls_connect(private, client_config(&[&b.ca], &[&rustls::version::TLS13])).await.expect("inside the peers, TLS completes");
    b.app.shutdown();
    task.await.unwrap().unwrap();
}

/// TLS 4.
#[tokio::test]
async fn run_binds_both_faces_then_notifies_ready_and_pings_the_watchdog() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("n.sock");
    let sock = tokio::net::UnixDatagram::bind(&path).unwrap();
    // A 200 ms watchdog interval: a third of WATCHDOG_USEC, read by `run` (no WATCHDOG_PID: any pid).
    let _env = WatchdogEnv::set("600000");
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::with_socket(path.clone()));
    let app = b.app.clone();
    let task = tokio::spawn(async move { app.run().await });
    let mut buf = [0u8; 256];
    let first = datagram(&sock, &mut buf).await;
    assert!(first.contains("READY=1"), "{first}");
    let (public, private) = b.app.bound().expect("bound before READY");
    TcpStream::connect(public).await.expect("the public face accepts");
    TcpStream::connect(private).await.expect("the private face accepts");
    let start = tokio::time::Instant::now();
    let mut pings = 0;
    while start.elapsed() < Duration::from_secs(1) {
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(300), sock.recv(&mut buf)).await {
            if &buf[..n] == b"WATCHDOG=1\n" {
                pings += 1;
            }
        }
    }
    assert!(pings >= 3, "{pings} pings in a second");
    let stopped = tokio::time::Instant::now();
    b.app.shutdown();
    let mut stopping = false;
    for _ in 0..20 {
        if datagram(&sock, &mut buf).await == "STOPPING=1\n" {
            stopping = true;
            break;
        }
    }
    assert!(stopping, "STOPPING=1 after shutdown");
    let done = tokio::time::timeout(Duration::from_secs(6), task).await.expect("run returns within 6 s");
    assert!(done.unwrap().is_ok());
    assert!(stopped.elapsed() <= Duration::from_secs(6));
}

/// The next sd_notify datagram.
async fn datagram(sock: &tokio::net::UnixDatagram, buf: &mut [u8; 256]) -> String {
    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(buf)).await.expect("a datagram").unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

/// TLS 5.
#[tokio::test]
async fn a_slow_tls_client_is_cut() {
    let _serial = SERIAL.lock().await;
    let b = relay(Limits { tls_handshake_timeout_ms: 300, ..limits() }, &["127.0.0.0/8"], true, Notifier::disabled());
    let (task, public, _private) = running(&b).await;
    let tcp = TcpStream::connect(public).await.unwrap();
    let t0 = std::time::Instant::now();
    read_to_close(tcp, Duration::from_secs(5)).await;
    let took = t0.elapsed();
    assert!(took >= Duration::from_millis(300) && took <= Duration::from_millis(600), "{took:?}");
    assert!(b.sink.lines().iter().any(|l| l.contains("\"reason\":\"tls_timeout\"")));
    b.app.shutdown();
    task.await.unwrap().unwrap();
}

/// Both ends of an admitted duplex connection.
type Admitted = (ai_env_relay::Peered<tokio_rustls::server::TlsStream<tokio::io::DuplexStream>>, tokio_rustls::client::TlsStream<tokio::io::DuplexStream>);

/// One connection through `admit` over duplex from `ip`, its TLS client run beside it; Some when admitted.
async fn admitted(app: &RelayApp, cfg: Arc<rustls::ClientConfig>, ip: IpAddr) -> Option<Admitted> {
    let (client, server) = tokio::io::duplex(1 << 16);
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let (served, client) = tokio::join!(app.admit(Face::Public, server, ip), connector.connect(ServerName::try_from("ai-env-relay").unwrap(), client));
    match (served, client) {
        (Some(s), Ok(c)) => Some((s, c)),
        _ => None,
    }
}

/// TLS 6.
#[tokio::test]
async fn public_admission_limits_per_ip() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let one: IpAddr = "198.51.100.7".parse().unwrap();
    for i in 0..20 {
        assert!(admitted(&b.app, Arc::clone(&cfg), one).await.is_some(), "connection {i} within the burst");
    }
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let t0 = std::time::Instant::now();
    assert!(b.app.admit(Face::Public, server, one).await.is_none(), "the 21st within a minute");
    assert!(t0.elapsed() < Duration::from_millis(100));
    let mut got = Vec::new();
    client.write_all(b"\x16\x03\x01").await.ok();
    client.read_to_end(&mut got).await.ok();
    assert!(got.is_empty(), "closed before any TLS byte");
    assert!(admitted(&b.app, Arc::clone(&cfg), "203.0.113.9".parse().unwrap()).await.is_some(), "another IP completes");

    let ip: IpAddr = "198.51.100.8".parse().unwrap();
    let mut live = Vec::new();
    for _ in 0..8 {
        live.push(admitted(&b.app, Arc::clone(&cfg), ip).await.expect("eight live from one IP"));
    }
    assert!(admitted(&b.app, Arc::clone(&cfg), ip).await.is_none(), "the ninth live connection");
    let reasons: Vec<String> = b.sink.lines().iter().filter(|l| l.contains("\"ev\":\"peer\"")).cloned().collect();
    assert!(reasons.iter().any(|l| l.contains("rate_limited")) && reasons.iter().any(|l| l.contains("too_many_connections")), "{reasons:?}");
    drop(live);
}

/// TLS 7.
#[tokio::test]
async fn each_face_serves_its_one_service() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    let (task, public, private) = running(&b).await;
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let mut wrong = RelayClient::new(channel(public, Arc::clone(&cfg)).await);
    let s = wrong.list_sources(with_token(ListSourcesRequest {}, &token())).await.expect_err("Relay is not on the public face");
    assert_eq!(s.code(), Code::Unimplemented);
    assert!(!b.sink.lines().iter().any(|l| l.contains("\"ev\":\"list\"") || l.contains("\"ev\":\"call\"")), "no session or call line");

    let (out, rx) = tokio::sync::mpsc::channel::<WorkerFrame>(8);
    let h = common::worker::hello("worker-a", 1);
    out.send(common::worker::wf(worker_frame::Msg::Hello(h))).await.unwrap();
    let mut tunnel = WorkerTunnelClient::new(channel(private, cfg).await);
    let s = tunnel.open(tokio_stream::wrappers::ReceiverStream::new(rx)).await.expect_err("WorkerTunnel is not on the private face");
    assert_eq!(s.code(), Code::Unimplemented);
    assert_eq!(b.app.snapshot().tunnels, 0);
    let _ = (b.clock.unix(), b.dir.path());
    b.app.shutdown();
    task.await.unwrap().unwrap();
}

/// The public face served in-process on the connections a test admits through `admit`.
type PublicFace = tokio::sync::mpsc::UnboundedSender<Result<ai_env_relay::Peered<tokio_rustls::server::TlsStream<tokio::io::DuplexStream>>, io::Error>>;

fn public_face(app: &RelayApp) -> PublicFace {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let app = app.clone();
    tokio::spawn(async move { app.serve_public(tokio_stream::wrappers::UnboundedReceiverStream::new(rx)).await });
    tx
}

/// When a client saw the relay close its connection, on tokio's clock.
type Closed = Arc<Mutex<Option<tokio::time::Instant>>>;

/// A client's TLS stream that notes when the relay closed it (its read ended).
struct Watched {
    io: tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
    closed: Closed,
}

impl AsyncRead for Watched {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let read = Pin::new(&mut self.io).poll_read(cx, buf);
        let ended = match &read {
            Poll::Ready(Ok(())) => buf.filled().len() == before && buf.remaining() > 0,
            Poll::Ready(Err(_)) => true,
            Poll::Pending => false,
        };
        if ended {
            self.closed.lock().unwrap().get_or_insert_with(tokio::time::Instant::now);
        }
        read
    }
}

impl AsyncWrite for Watched {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// A worker's HTTP/2 channel over one connection admitted from `ip` and served on `face`, and its close's instant.
async fn worker_channel(app: &RelayApp, face: &PublicFace, cfg: Arc<rustls::ClientConfig>, ip: &str) -> (Channel, Closed) {
    let (served, client) = admitted(app, cfg, ip.parse().unwrap()).await.expect("admitted");
    face.send(Ok(served)).unwrap();
    let closed: Closed = Arc::default();
    let mut once = Some(Watched { io: client, closed: Arc::clone(&closed) });
    let channel = Endpoint::from_static("http://ai-env-relay")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let io = once.take();
            async move { io.map(hyper_util::rt::TokioIo::new).ok_or_else(|| io::Error::other("one connection per channel")) }
        }))
        .await
        .expect("HTTP/2 over the admitted connection");
    (channel, closed)
}

/// Waits (on tokio's clock, at most a second) until the relay watches `n` public connections (R-2a); when it did.
async fn watching(app: &RelayApp, n: usize) -> tokio::time::Instant {
    for _ in 0..1000 {
        if app.public_conns() == n {
            return tokio::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("{} public connections watched, not {n}", app.public_conns());
}

/// The peer lines with reason `open_timeout` so far.
fn open_timeouts(b: &Box_) -> Vec<String> {
    b.sink.lines().into_iter().filter(|l| l.contains("\"reason\":\"open_timeout\"")).collect()
}

/// Waits (on tokio's clock) for the relay's close of a connection; when the client saw it.
async fn closed_at(closed: &Closed) -> tokio::time::Instant {
    for _ in 0..120_000 {
        let seen = *closed.lock().unwrap();
        if let Some(at) = seen {
            return at;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("the relay never closed the connection");
}

/// TLS 8 (paused): a public connection with no `Open` within `handshake_timeout_ms` (5 s) of its TLS accept is closed
/// then, not before, with a peer line `open_timeout`, and its slot is free again (R-2, R-2a): from one IP, eight idle
/// connections are served and watched, and a ninth is refused; at 5 s the eight are closed and no longer watched,
/// and a ninth is admitted.
#[tokio::test(start_paused = true)]
async fn an_idle_public_connection_is_closed_and_frees_its_slot() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    let t0 = tokio::time::Instant::now();
    let mut idle = Vec::new();
    for _ in 0..8 {
        let (served, client) = admitted(&b.app, Arc::clone(&cfg), ip).await.expect("eight from one IP");
        face.send(Ok(served)).unwrap();
        idle.push(client);
    }
    assert!(admitted(&b.app, Arc::clone(&cfg), ip).await.is_none(), "a ninth while the eight are up");
    watching(&b.app, 8).await;
    for mut client in idle {
        // The relay's SETTINGS, then the connection's end (with no close_notify: an error, or none).
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(60), client.read_to_end(&mut rest)).await.expect("closed by the relay");
        assert_eq!(t0.elapsed(), Duration::from_secs(5), "closed at handshake_timeout_ms, not before");
    }
    assert_eq!(b.app.public_conns(), 0, "each watch ended with its cut");
    let lines = open_timeouts(&b);
    assert_eq!(lines.len(), 8, "{lines:?}");
    assert!(lines.iter().all(|l| l.contains("\"face\":\"public\"") && l.contains("\"peer\":\"198.51.100.7\"")), "{lines:?}");
    assert!(admitted(&b.app, cfg, ip).await.is_some(), "the slots are free again: a ninth is admitted");
}

/// TLS 9 (paused): a public connection closes 1 s after its tunnel ends, and never while the tunnel lives (R-2a). A
/// handshake that fails: the worker reads its 16, and the connection's close 1 s later. An `Open` at 4.9 s: the
/// tunnel outlives the 5 s deadline (still registered 30 s on, its connection up); revoked, the worker reads its
/// `Close{1, "revoked"}` and the stream's end, and the connection's close 1 s after the revocation.
#[tokio::test(start_paused = true)]
async fn a_public_connection_closes_after_its_tunnel_and_never_before() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);

    let (channel, closed) = worker_channel(&b.app, &face, Arc::clone(&cfg), "198.51.100.7").await;
    let mut w = TestWorker::open_on(channel).await.expect("the Challenge");
    let h = hello("worker-a", 1);
    let mut p = proof(&w.challenge, &h, 1);
    p.signature[0] ^= 1;
    w.send(worker_frame::Msg::Hello(h)).await;
    w.send(worker_frame::Msg::AuthProof(p)).await;
    assert_eq!(w.end().await.expect_err("a failed handshake").code(), Code::Unauthenticated);
    let ended = tokio::time::Instant::now();
    assert_eq!(closed_at(&closed).await - ended, Duration::from_secs(1), "closed 1 s after the tunnel's end");
    assert_eq!(b.app.public_conns(), 0, "the watch ended with its cut");

    let (channel, closed) = worker_channel(&b.app, &face, cfg, "198.51.100.8").await;
    tokio::time::sleep(Duration::from_millis(4900)).await;
    let mut a = TestWorker::open_on(channel).await.expect("an Open before the deadline");
    a.authenticate("worker-a", 1).await.expect("authenticated");
    a.register(catalog_a()).await;
    let a = a.serve(Script::silent());
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(b.app.snapshot().tunnels, 1, "the tunnel outlives the deadline");
    assert!(closed.lock().unwrap().is_none(), "its connection is up");
    assert!(a.closes().is_empty());

    let others: Vec<_> = default_workers().into_iter().filter(|e| e.worker_id != "worker-a").collect();
    write(b.dir.path(), WORKERS_FILE, policy::render_workers(&others).unwrap().as_bytes());
    b.app.poll_files();
    let revoked = tokio::time::Instant::now();
    let close = a.closed().await;
    assert_eq!((close.code, close.reason.as_str()), (1, "revoked"));
    a.until("the stream's end", |r| r.ended.is_some()).await;
    assert_eq!(a.log.lock().unwrap().ended, Some(Ok(())), "status 0 after the Close: the cut came after both");
    assert_eq!(closed_at(&closed).await - revoked, Duration::from_secs(1), "closed 1 s after the tunnel's end");
    assert_eq!(b.app.public_conns(), 0, "the watch ended with its cut");
}

/// TLS 10 (paused): a public connection is watched from its TLS accept to its end, and no longer (R-2a). (i) A client
/// that leaves at 1 s with no `Open`: the relay forgets the connection then, and by 6 s has written no `open_timeout`
/// line. (ii) A connection the face takes 3 s after its TLS accept (`run` queues admitted connections for the
/// server): closed 5 s after the accept, 2 s after the face took it, with one `open_timeout` line.
#[tokio::test(start_paused = true)]
async fn a_public_connection_is_watched_from_its_accept_to_its_end() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);

    let t0 = tokio::time::Instant::now();
    let (served, client) = admitted(&b.app, Arc::clone(&cfg), "198.51.100.7".parse().unwrap()).await.expect("admitted");
    face.send(Ok(served)).unwrap();
    watching(&b.app, 1).await;
    tokio::time::sleep_until(t0 + Duration::from_secs(1)).await;
    drop(client);
    let left = tokio::time::Instant::now();
    let forgotten = watching(&b.app, 0).await;
    assert!(forgotten - left < Duration::from_millis(10), "forgotten as the client left, not at the deadline: {:?}", forgotten - left);
    tokio::time::sleep_until(t0 + Duration::from_secs(6)).await;
    assert!(open_timeouts(&b).is_empty(), "a connection that ended before its deadline has no open_timeout line");

    let (served, mut client) = admitted(&b.app, cfg, "198.51.100.8".parse().unwrap()).await.expect("admitted");
    let accepted = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(3)).await;
    face.send(Ok(served)).unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(60), client.read_to_end(&mut rest)).await.expect("closed by the relay");
    assert_eq!(accepted.elapsed(), Duration::from_secs(5), "the deadline counts from the TLS accept, not from the face's take");
    assert_eq!(b.app.public_conns(), 0);
    let lines = open_timeouts(&b);
    assert!(lines.len() == 1 && lines[0].contains("\"peer\":\"198.51.100.8\""), "{lines:?}");
}
