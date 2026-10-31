//! The relay's TLS and process (§R-relay.7, tls 1 to 16 and 19 to 24): real loopback sockets through `run`, or
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
    // The rig's peers (R-89): loopback and the two documentation ranges every test of this file dials from.
    write(dir.path(), ai_env_relay::lists::PEERS_FILE, policy::render_peers(&common::rig::default_peers()).unwrap().as_bytes());
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

/// TLS 5: a TCP connection that never starts TLS is cut at `tls_handshake_timeout_ms` (R-2), here a tenth of the
/// default's 3 s (F24), with a peer line `tls_timeout`.
#[tokio::test]
async fn a_slow_tls_client_is_cut() {
    let _serial = SERIAL.lock().await;
    assert_eq!(Limits::default().tls_handshake_timeout_ms, 3000, "F24: 3 s, not 10");
    let b = relay(Limits { tls_handshake_timeout_ms: Limits::default().tls_handshake_timeout_ms / 10, ..limits() }, &["127.0.0.0/8"], true, Notifier::disabled());
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
    admitted_over(app, cfg, ip, 1 << 16).await
}

/// `admitted` over a pipe of `pipe` bytes each way.
async fn admitted_over(app: &RelayApp, cfg: Arc<rustls::ClientConfig>, ip: IpAddr, pipe: usize) -> Option<Admitted> {
    let (client, server) = tokio::io::duplex(pipe);
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let (served, client) = tokio::join!(app.admit(Face::Public, server, ip), connector.connect(ServerName::try_from("ai-env-relay").unwrap(), client));
    match (served, client) {
        (Some(s), Ok(c)) => Some((s, c)),
        _ => None,
    }
}

/// TLS 6 (R-2): the accept bucket and the live count per IP; after the stop, on either face, a peer line `shutting_down`.
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

    // R-2's first check: after the stop, on either face, a peer line `shutting_down` (with no check, `admit` still ends
    // in None, but after the TLS timeout and with another line).
    b.app.shutdown();
    for (face, word, ip) in [(Face::Public, "public", "198.51.100.9"), (Face::Private, "private", "127.0.0.1")] {
        let (_client, server) = tokio::io::duplex(1 << 16);
        assert!(b.app.admit(face, server, ip.parse().unwrap()).await.is_none(), "{word}: nobody is admitted after the stop");
        let lines = peer_lines(&b, "shutting_down");
        assert!(lines.last().is_some_and(|l| l["face"] == word && l["peer"] == ip), "{word}: {lines:?}");
    }
    assert_eq!(peer_lines(&b, "shutting_down").len(), 2);
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

/// The public face's peer lines so far, as (reason, peer).
fn public_refusals(b: &Box_) -> Vec<(String, String)> {
    b.sink
        .lines()
        .iter()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|v| v["ev"] == "peer" && v["face"] == "public")
        .map(|v| (v["reason"].as_str().unwrap().to_string(), v["peer"].as_str().unwrap().to_string()))
        .collect()
}

/// A TLS client's first flight for `cfg`: a whole ClientHello, which a relay that began TLS would answer.
fn client_hello(cfg: &Arc<rustls::ClientConfig>) -> Vec<u8> {
    let mut conn = rustls::ClientConnection::new(Arc::clone(cfg), ServerName::try_from("ai-env-relay").unwrap()).unwrap();
    let mut flight = Vec::new();
    conn.write_tls(&mut flight).unwrap();
    assert_eq!(flight.first(), Some(&0x16), "a handshake record");
    flight
}

/// One public connection through `admit` that must be refused before any TLS byte: a whole ClientHello (`flight`)
/// already waits in the pipe, `admit` gives nothing within 100 ms (as TLS 6's refusal; TLS would have waited up to
/// `tls_handshake_timeout_ms`), and the client reads the end with no byte (a relay that began TLS answers it).
async fn refused_before_tls(app: &RelayApp, flight: &[u8], ip: &str) {
    let (mut client, server) = tokio::io::duplex(1 << 16);
    client.write_all(flight).await.unwrap();
    let t0 = std::time::Instant::now();
    assert!(app.admit(Face::Public, server, ip.parse().unwrap()).await.is_none(), "{ip} refused");
    assert!(t0.elapsed() < Duration::from_millis(100), "{ip}: refused at once, not after a handshake: {:?}", t0.elapsed());
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.ok();
    assert!(got.is_empty(), "{ip}: closed before any TLS byte");
}

/// TLS 12 (R-89): the public face admits the peers file's in-force networks alone, before its per-IP state and any
/// TLS byte. Through `run`, with no peers.json: a loopback client of the public face sends a whole ClientHello and is
/// closed at once (well within `tls_handshake_timeout_ms`) with no byte written and one peer line `no_peers`, while
/// the private face completes TLS (it never reads the file). Through `admit`, with one accept a minute per address: a
/// listed `/32` and an address inside a listed `/24` are admitted; an address beside them is refused `not_in_peers`
/// five times and never `rate_limited` (the check precedes the bucket); a lapsed entry's address is refused; the file
/// turned stale refuses a listed address `no_peers` while the private face still admits; `poll_files` gives five
/// outcomes, peers last. Each refusal answers no ClientHello and comes at once (`refused_before_tls`).
#[tokio::test]
async fn the_public_face_admits_listed_peers_only() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    std::fs::remove_file(b.dir.path().join(ai_env_relay::lists::PEERS_FILE)).unwrap();
    let (task, public, private) = running(&b).await;
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let flight = client_hello(&cfg);
    let mut tcp = TcpStream::connect(public).await.unwrap();
    let t0 = std::time::Instant::now();
    // The relay may have closed already: then the write fails, or the close it meets resets the connection.
    tcp.write_all(&flight).await.ok();
    assert!(read_to_close(tcp, Duration::from_secs(5)).await.is_empty(), "closed with no byte written, the ClientHello unanswered");
    let budget = Duration::from_millis(u64::from(limits().tls_handshake_timeout_ms));
    assert!(t0.elapsed() < budget / 3, "closed before any handshake's wait: {:?}", t0.elapsed());
    assert_eq!(public_refusals(&b), [("no_peers".to_string(), "127.0.0.1".to_string())]);
    tls_connect(private, Arc::clone(&cfg)).await.expect("the private face never reads the peers file");
    let mut client = RelayClient::new(channel(private, cfg).await);
    client.list_sources(with_token(ListSourcesRequest {}, &token())).await.expect("a ListSources on the private face");
    drop(client);
    b.app.shutdown();
    task.await.unwrap().unwrap();

    let b = relay(Limits { public_accepts_burst: 1, public_accepts_per_min: 1, ..limits() }, &["127.0.0.0/8"], true, Notifier::disabled());
    let lapsed = policy::PeerEntry { not_after: "2027-01-15T07:59:59Z".into(), ..common::rig::peer_entry("192.0.2.0/24", "lapsed") };
    let until_t0 = policy::PeerEntry { not_after: "2027-01-15T08:00:00Z".into(), ..common::rig::peer_entry("203.0.113.0/24", "office") };
    let list = [common::rig::peer_entry("198.51.100.7/32", "host"), until_t0, lapsed];
    write(b.dir.path(), ai_env_relay::lists::PEERS_FILE, policy::render_peers(&list).unwrap().as_bytes());
    let polled = b.app.poll_files();
    let names: Vec<&str> = polled.iter().map(|(file, _)| *file).collect();
    assert_eq!(names, ["workers", "token-signers", "grants", "tls", "peers"]);
    assert!(matches!(polled[4].1, ai_env_relay::files::Poll::Loaded { .. }), "{polled:?}");
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let flight = client_hello(&cfg);
    assert!(admitted(&b.app, Arc::clone(&cfg), "198.51.100.7".parse().unwrap()).await.is_some(), "a listed /32");
    assert!(admitted(&b.app, Arc::clone(&cfg), "203.0.113.9".parse().unwrap()).await.is_some(), "inside a listed /24, in force through T0");
    assert!(admitted(&b.app, Arc::clone(&cfg), "::ffff:203.0.113.10".parse().unwrap()).await.is_some(), "an IPv4-mapped address is its IPv4 address");
    for _ in 0..5 {
        refused_before_tls(&b.app, &flight, "198.51.100.8").await;
    }
    refused_before_tls(&b.app, &flight, "192.0.2.7").await;
    refused_before_tls(&b.app, &flight, "2001:db8::7").await;
    let reasons = public_refusals(&b);
    assert_eq!(reasons.iter().filter(|(r, ip)| r == "not_in_peers" && ip == "198.51.100.8").count(), 5, "{reasons:?}");
    assert!(reasons.contains(&("not_in_peers".to_string(), "192.0.2.7".to_string())), "the lapsed entry's address: {reasons:?}");
    assert!(reasons.contains(&("not_in_peers".to_string(), "2001:db8::7".to_string())), "{reasons:?}");
    assert!(reasons.iter().all(|(r, _)| r == "not_in_peers"), "never rate_limited: {reasons:?}");

    // Stale: every list past its fetch's 900 s. A listed address meets `no_peers`, not its spent bucket (the peers
    // check comes first); the private face admits as before.
    b.clock.set(T0 + 901);
    assert_eq!(b.app.poll_files()[4].1, ai_env_relay::files::Poll::Stale);
    refused_before_tls(&b.app, &flight, "198.51.100.7").await;
    assert_eq!(public_refusals(&b).last(), Some(&("no_peers".to_string(), "198.51.100.7".to_string())));
    let (server_end, client_end) = tokio::io::duplex(1 << 16);
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let (served, client) = tokio::join!(b.app.admit(Face::Private, server_end, "127.0.0.1".parse().unwrap()), connector.connect(ServerName::try_from("ai-env-relay").unwrap(), client_end));
    assert!(served.is_some() && client.is_ok(), "the private face never reads the peers file");
}

/// TLS 13 (R-91): `ai-env-relay check`, the built binary, on a temporary env file and live directory: five lines in
/// poll order, the fifth `peers.json: loaded version=<16 hex> entries=1 age_s=<n>`, exit 0 with every file loaded and
/// every list fresh. peers.json refused, then removed: its line says so, the other four stand, and the exit is 1.
#[tokio::test]
async fn check_prints_one_line_per_live_file() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live");
    std::fs::create_dir(&live).unwrap();
    let ca = Ca::new("test relay CA", [11; 32]);
    write(&live, WORKERS_FILE, policy::render_workers(&default_workers()).unwrap().as_bytes());
    write(&live, SIGNERS_FILE, policy::render_signers(&[mac_signer(NOT_AFTER)]).unwrap().as_bytes());
    write(&live, GRANTS_FILE, policy::render_grants(&default_grants()).unwrap().as_bytes());
    write(&live, TLS_FILE, certs::tls_pem(&leaf(&ca, 1, 12), &ca).as_bytes());
    let peers = policy::render_peers(&[common::rig::peer_entry("198.51.100.0/24", "office")]).unwrap();
    write(&live, ai_env_relay::lists::PEERS_FILE, peers.as_bytes());
    // `check` reads the real clock: the reload's stamp is now.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    write(&live, "fetched", format!("{now}\n").as_bytes());
    let env = dir.path().join("relay.env");
    let vars = format!(
        "AI_ENV_RELAY_PUBLIC_ADDR=127.0.0.1:0\nAI_ENV_RELAY_PRIVATE_ADDR=127.0.0.1:0\nAI_ENV_RELAY_PRIVATE_PEERS=127.0.0.0/8\nAI_ENV_RELAY_LIVE_DIR={}\nAI_ENV_RELAY_REQUEST_LOG={}\n",
        live.display(),
        dir.path().join("requests.log").display()
    );
    std::fs::write(&env, vars).unwrap();
    let check = || {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_ai-env-relay")).arg("check").arg("--env-file").arg(&env).output().expect("the built binary runs");
        (out.status.code(), String::from_utf8(out.stdout).unwrap())
    };
    let files = [WORKERS_FILE, SIGNERS_FILE, GRANTS_FILE, TLS_FILE, ai_env_relay::lists::PEERS_FILE];

    let (code, stdout) = check();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "{stdout}");
    for (line, file) in lines.iter().zip(files) {
        assert!(line.starts_with(&format!("{file}: loaded ")), "poll order: {stdout}");
    }
    let version = ai_env_relay::files::content_version(peers.as_bytes());
    let fifth = lines[4].strip_prefix(&format!("peers.json: loaded version={version:016x} entries=1 age_s=")).unwrap_or_else(|| panic!("{stdout}"));
    assert!(fifth.parse::<u64>().is_ok_and(|age| age < 600), "a fresh list's age: {stdout}");
    assert_eq!(code, Some(0), "{stdout}");

    write(&live, ai_env_relay::lists::PEERS_FILE, b"[");
    let (code, stdout) = check();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "{stdout}");
    assert_eq!(lines[4], "peers.json: refused (peers: not a JSON array (line 1, column 1))");
    assert!(lines[..4].iter().zip(files).all(|(line, file)| line.starts_with(&format!("{file}: loaded "))), "{stdout}");
    assert_eq!(code, Some(1), "{stdout}");

    std::fs::remove_file(live.join(ai_env_relay::lists::PEERS_FILE)).unwrap();
    let (code, stdout) = check();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "{stdout}");
    assert_eq!(lines[4], "peers.json: missing");
    assert!(lines[..4].iter().zip(files).all(|(line, file)| line.starts_with(&format!("{file}: loaded "))), "{stdout}");
    assert_eq!(code, Some(1), "{stdout}");
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
    served_channel(face, served, client).await
}

/// A worker's HTTP/2 channel over one admitted connection, served on `face`, and its close's instant.
async fn served_channel(face: &PublicFace, served: ai_env_relay::Peered<tokio_rustls::server::TlsStream<tokio::io::DuplexStream>>, client: tokio_rustls::client::TlsStream<tokio::io::DuplexStream>) -> (Channel, Closed) {
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
/// handshake that fails: the worker reads its 16, and the connection's close 1 s later. An `Open` at 4.9 s with its
/// `Hello` and `AuthProof` at once, inside the same 5 s from the accept (F24): the tunnel outlives the deadline
/// (still registered 30 s on, its connection up); revoked, the worker reads its `Close{1, "revoked"}` and the
/// stream's end, and the connection's close 1 s after the revocation.
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
    let accepted = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(4900)).await;
    let mut a = TestWorker::open_on(channel).await.expect("an Open before the deadline");
    a.authenticate("worker-a", 1).await.expect("authenticated");
    assert!(accepted.elapsed() < Duration::from_secs(5), "authenticated within the accept's 5 s: {:?}", accepted.elapsed());
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

/// TLS 11 (paused): an `Open` at 4.9 s after the TLS accept gets no fresh 5 s (F24): its `Hello` and `AuthProof` share
/// the accept's budget, so a `Hello` at 5.5 s finds the handshake refused at 5 s exactly (a tunnel line
/// `refused/timeout`, the worker's 16 `authentication failed`), and the connection closed 1 s later, at 6 s: an
/// unauthenticated connection lives at most 3 + 5 + 1 s, not 21.
#[tokio::test(start_paused = true)]
async fn an_open_late_in_its_window_gets_no_fresh_budget() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let (channel, closed) = worker_channel(&b.app, &face, cfg, "198.51.100.7").await;
    let accepted = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(4900)).await;
    let mut w = TestWorker::open_on(channel).await.expect("an Open before the deadline gets its Challenge");
    let h = hello("worker-a", 1);
    let p = proof(&w.challenge, &h, 1);
    let out = w.out.clone();
    tokio::spawn(async move {
        tokio::time::sleep_until(accepted + Duration::from_millis(5500)).await;
        let _ = out.send(common::worker::wf(worker_frame::Msg::Hello(h))).await;
        let _ = out.send(common::worker::wf(worker_frame::Msg::AuthProof(p))).await;
    });
    let status = w.end().await.expect_err("the budget ran out at the accept's 5 s");
    assert_eq!((status.code(), status.message()), (Code::Unauthenticated, "authentication failed"));
    assert_eq!(accepted.elapsed(), Duration::from_secs(5), "refused 5 s from the accept, not from the Open (9.9 s)");
    let refused: Vec<String> = b.sink.lines().into_iter().filter(|l| l.contains("\"ev\":\"tunnel\"") && l.contains("\"outcome\":\"refused\"")).collect();
    assert!(refused.len() == 1 && refused[0].contains("\"reason\":\"timeout\""), "{refused:?}");
    assert_eq!(closed_at(&closed).await - accepted, Duration::from_secs(6), "closed 1 s after the refusal");
    assert_eq!(b.app.public_conns(), 0, "the watch ended with its cut");
    assert_eq!(b.app.snapshot().tunnels, 0);
}

/// The private face served in-process on the connections a test admits through `admit` (TLS 15, 16).
fn private_face(app: &RelayApp) -> PublicFace {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let app = app.clone();
    tokio::spawn(async move { app.serve_private(tokio_stream::wrappers::UnboundedReceiverStream::new(rx)).await });
    tx
}

/// One connection through `admit` on the private face over duplex from `ip`, its TLS client run beside it; Some when
/// admitted.
async fn admitted_private(app: &RelayApp, cfg: Arc<rustls::ClientConfig>, ip: IpAddr) -> Option<Admitted> {
    let (client, server) = tokio::io::duplex(1 << 16);
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let (served, client) = tokio::join!(app.admit(Face::Private, server, ip), connector.connect(ServerName::try_from("ai-env-relay").unwrap(), client));
    match (served, client) {
        (Some(s), Ok(c)) => Some((s, c)),
        _ => None,
    }
}

/// A VM's HTTP/2 channel over one connection admitted from `ip` and served on the private face, and its close's
/// instant.
async fn vm_channel(app: &RelayApp, face: &PublicFace, cfg: Arc<rustls::ClientConfig>, ip: IpAddr) -> (Channel, Closed) {
    let (served, client) = admitted_private(app, cfg, ip).await.expect("admitted on the private face");
    face.send(Ok(served)).unwrap();
    let closed: Closed = Arc::default();
    let mut once = Some(Watched { io: client, closed: Arc::clone(&closed) });
    let channel = Endpoint::from_static("http://10.42.0.20")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let io = once.take();
            async move { io.map(hyper_util::rt::TokioIo::new).ok_or_else(|| io::Error::other("one connection per channel")) }
        }))
        .await
        .expect("HTTP/2 over the admitted connection");
    (channel, closed)
}

/// The peer lines with this reason so far.
fn peer_lines(b: &Box_, reason: &str) -> Vec<serde_json::Value> {
    b.sink.lines().iter().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()).filter(|v| v["ev"] == "peer" && v["reason"] == reason).collect()
}

/// The tunnel lines of `ip` so far.
fn tunnel_lines(b: &Box_, ip: &str) -> Vec<serde_json::Value> {
    b.sink.lines().iter().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()).filter(|v| v["ev"] == "tunnel" && v["peer"] == ip).collect()
}

/// A handshake from `ip` whose proof `breaks` or not; its end, 16 (the AuthOk when it authenticates).
async fn handshake(app: &RelayApp, face: &PublicFace, cfg: Arc<rustls::ClientConfig>, ip: &str, breaks: bool) -> Result<TestWorker, Code> {
    let (channel, _closed) = worker_channel(app, face, cfg, ip).await;
    let mut w = TestWorker::open_on(channel).await.expect("the Challenge");
    let h = hello("worker-a", 1);
    let mut p = proof(&w.challenge, &h, 1);
    if breaks {
        p.signature[0] ^= 1;
    }
    w.send(worker_frame::Msg::Hello(h)).await;
    w.send(worker_frame::Msg::AuthProof(p)).await;
    match w.next().await {
        Ok(Some(ai_env_relay_proto::v1::RelayFrame { msg: Some(ai_env_relay_proto::v1::relay_frame::Msg::AuthOk(_)) })) => Ok(w),
        Ok(other) => panic!("an AuthOk or a status, not {other:?}"),
        Err(s) => Err(s.code()),
    }
}

/// TLS 14 (paused, through `admit`): twenty faults ban an address for `ban_s` (R-98 to R-102). Twenty bad handshakes
/// (`bad_signature`) from one address, then its next connection is refused `banned` before any TLS byte, with a peer
/// line `banned`; another address authenticates; `ban_s` later the first authenticates. An `open_timeout` counts.
/// Never a fault, 25 times each from an address of its own: a refusal while the workers file is not loaded
/// (`not_loaded`) or stale (`no_peers` at admission, `stale` for a connection admitted before), a client's end of
/// stream after its `Hello` (`eof`), and a TCP connection closed before any byte (a peer line `tls_failed`). R-102's TLS faults ban too (review B finding 6), each set from
/// an address of its own: 20 connections that send one byte and fail TLS (`tls_failed`), and 20 that send nothing
/// until the TLS timeout (`tls_timeout`). R-98's exemption, through `Tunnel::run`: an address holding a live tunnel takes 25
/// bad handshakes and is still admitted, with no `banned` line; `ban_window_s` and a second after its tunnel's end,
/// twenty bad handshakes ban it.
#[tokio::test(start_paused = true)]
async fn twenty_faults_ban_an_address_for_ban_s() {
    let _serial = SERIAL.lock().await;
    // R-2's bucket and live counts out of the way: the ban is the subject.
    let l = Limits { public_accepts_burst: 1000, public_accepts_per_min: 6000, public_conns_per_ip: 1024, public_conns_max: 4096, ..limits() };
    let b = relay(l, &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let banned = |b: &Box_, ip: &str| peer_lines(b, "banned").iter().filter(|l| l["peer"] == ip && l["face"] == "public").count();

    let a = "198.51.100.7";
    for i in 0..20 {
        assert_eq!(handshake(&b.app, &face, Arc::clone(&cfg), a, true).await.err(), Some(Code::Unauthenticated), "bad handshake {i}");
    }
    let (mut client, server) = tokio::io::duplex(1 << 16);
    assert!(b.app.admit(Face::Public, server, a.parse().unwrap()).await.is_none(), "the 21st connection is refused");
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.ok();
    assert!(got.is_empty(), "refused before any TLS byte");
    assert_eq!(banned(&b, a), 1);
    handshake(&b.app, &face, Arc::clone(&cfg), "203.0.113.9", false).await.expect("another address authenticates");
    tokio::time::sleep(Duration::from_secs(u64::from(Limits::default().ban_s))).await;
    handshake(&b.app, &face, Arc::clone(&cfg), a, false).await.expect("ban_s later the first authenticates");

    // Nineteen bad handshakes and one connection with no `Open`: the `open_timeout` is the twentieth fault.
    let c = "198.51.100.20";
    for _ in 0..19 {
        assert!(handshake(&b.app, &face, Arc::clone(&cfg), c, true).await.is_err());
    }
    let (served, mut idle) = admitted(&b.app, Arc::clone(&cfg), c.parse().unwrap()).await.expect("admitted after 19 faults");
    face.send(Ok(served)).unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(60), idle.read_to_end(&mut rest)).await.expect("cut at open_timeout");
    assert!(admitted(&b.app, Arc::clone(&cfg), c.parse().unwrap()).await.is_none(), "banned by its open_timeout");
    assert_eq!(banned(&b, c), 1);

    // The relay's own refusals: the workers file missing, then stale.
    let (d, e, f, g) = ("198.51.100.21", "198.51.100.22", "198.51.100.23", "198.51.100.24");
    let workers = std::fs::read(b.dir.path().join(WORKERS_FILE)).unwrap();
    std::fs::remove_file(b.dir.path().join(WORKERS_FILE)).unwrap();
    b.app.poll_files();
    for _ in 0..25 {
        assert_eq!(handshake(&b.app, &face, Arc::clone(&cfg), d, false).await.err(), Some(Code::Unauthenticated), "not_loaded");
    }
    write(b.dir.path(), WORKERS_FILE, &workers);
    b.app.poll_files();
    // Stale: `fetched` is the peers file's too, so nobody new is admitted (R-89's `no_peers`) ...
    b.clock.set(T0 + 901);
    b.app.poll_files();
    for _ in 0..25 {
        assert!(admitted(&b.app, Arc::clone(&cfg), e.parse().unwrap()).await.is_none(), "no_peers");
    }
    assert_eq!(peer_lines(&b, "no_peers").iter().filter(|l| l["peer"] == e).count(), 25);
    // ... and a connection admitted before that meets the workers file's own refusal at its Hello.
    for _ in 0..25 {
        b.clock.set(T0);
        b.app.poll_files();
        let (channel, _closed) = worker_channel(&b.app, &face, Arc::clone(&cfg), e).await;
        let mut w = TestWorker::open_on(channel).await.expect("the Challenge");
        b.clock.set(T0 + 901);
        b.app.poll_files();
        let h = hello("worker-a", 1);
        let p = proof(&w.challenge, &h, 1);
        w.send(worker_frame::Msg::Hello(h)).await;
        w.send(worker_frame::Msg::AuthProof(p)).await;
        assert_eq!(w.next().await.expect_err("stale").code(), Code::Unauthenticated);
    }
    write(b.dir.path(), "fetched", format!("{}\n", T0 + 901).as_bytes());
    b.app.poll_files();
    // A client's end of stream after its Hello.
    for _ in 0..25 {
        let (channel, _closed) = worker_channel(&b.app, &face, Arc::clone(&cfg), f).await;
        let w = TestWorker::open_on(channel).await.expect("the Challenge");
        w.send(worker_frame::Msg::Hello(hello("worker-a", 1))).await;
        let TestWorker { out, mut inbound, .. } = w;
        drop(out);
        assert_eq!(inbound.message().await.expect_err("eof: 16").code(), Code::Unauthenticated);
    }
    // TCP connections closed before any byte (a bare probe, `relay status`'s among them).
    for _ in 0..25 {
        let (client, server) = tokio::io::duplex(1 << 16);
        drop(client);
        assert!(b.app.admit(Face::Public, server, g.parse().unwrap()).await.is_none());
    }
    assert_eq!(peer_lines(&b, "tls_failed").iter().filter(|l| l["peer"] == g).count(), 25);
    for ip in [d, e, f, g] {
        handshake(&b.app, &face, Arc::clone(&cfg), ip, false).await.unwrap_or_else(|code| panic!("{ip} was banned: {code:?}"));
    }
    assert_eq!(peer_lines(&b, "banned").len(), 2, "only the first two addresses were ever banned");

    // The TLS faults: one byte, then the client's end; then silence until the TLS timeout.
    let (h, i) = ("198.51.100.25", "198.51.100.26");
    for _ in 0..20 {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();
        assert!(b.app.admit(Face::Public, server, h.parse().unwrap()).await.is_none(), "one byte and no TLS");
    }
    assert_eq!(peer_lines(&b, "tls_failed").iter().filter(|l| l["peer"] == h).count(), 20);
    for _ in 0..20 {
        let (_client, server) = tokio::io::duplex(1 << 16);
        let start = tokio::time::Instant::now();
        assert!(b.app.admit(Face::Public, server, i.parse().unwrap()).await.is_none(), "no TLS");
        assert_eq!(start.elapsed(), Duration::from_millis(u64::from(Limits::default().tls_handshake_timeout_ms)), "cut at the TLS timeout");
    }
    assert_eq!(peer_lines(&b, "tls_timeout").iter().filter(|l| l["peer"] == i).count(), 20);
    for ip in [h, i] {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        assert!(b.app.admit(Face::Public, server, ip.parse().unwrap()).await.is_none(), "{ip}: refused");
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.ok();
        assert!(got.is_empty(), "{ip}: refused before any TLS byte");
        assert_eq!(banned(&b, ip), 1, "{ip}: banned by its TLS faults");
    }

    // A frame that does not decode before AuthOk (here a Hello over `catalog_max_bytes`) is `malformed`, a fault: 20
    // of them ban their address.
    let j = "198.51.100.27";
    for _ in 0..20 {
        let (channel, _closed) = worker_channel(&b.app, &face, Arc::clone(&cfg), j).await;
        let w = TestWorker::open_on(channel).await.expect("the Challenge");
        let mut h = hello("worker-a", 1);
        h.public_key = vec![0; 300_000];
        w.send(worker_frame::Msg::Hello(h)).await;
        let TestWorker { out, mut inbound, .. } = w;
        assert_eq!(inbound.message().await.expect_err("refused").code(), Code::Unauthenticated);
        drop(out);
    }
    let lines: Vec<String> = b.sink.lines().into_iter().filter(|l| l.contains("\"ev\":\"tunnel\"") && l.contains(&format!("\"peer\":\"{j}\""))).collect();
    assert!(lines.len() == 20 && lines.iter().all(|l| l.contains("\"reason\":\"malformed\"")), "{lines:?}");
    let (_client, server) = tokio::io::duplex(1 << 16);
    assert!(b.app.admit(Face::Public, server, j.parse().unwrap()).await.is_none());
    assert_eq!(banned(&b, j), 1, "banned by its undecodable frames");

    // R-98's exemption, wired: `Tunnel::run`'s `Exempt`, at the tunnel's AuthOk and at its end.
    let k = "198.51.100.28";
    let w = handshake(&b.app, &face, Arc::clone(&cfg), k, false).await.expect("authenticated");
    w.register(catalog_a()).await;
    installed(&b.app, 1).await;
    for i in 0..25 {
        assert_eq!(handshake(&b.app, &face, Arc::clone(&cfg), k, true).await.err(), Some(Code::Unauthenticated), "bad handshake {i} beside a live tunnel");
    }
    assert!(admitted(&b.app, Arc::clone(&cfg), k.parse().unwrap()).await.is_some(), "a live tunnel's address is never banned");
    assert_eq!(banned(&b, k), 0);
    drop(w);
    tokio::time::sleep(Duration::from_secs(u64::from(Limits::default().ban_window_s) + 1)).await;
    for i in 0..20 {
        assert_eq!(handshake(&b.app, &face, Arc::clone(&cfg), k, true).await.err(), Some(Code::Unauthenticated), "bad handshake {i} after its tunnel's window");
    }
    assert!(admitted(&b.app, Arc::clone(&cfg), k.parse().unwrap()).await.is_none(), "the 21st connection is refused");
    assert_eq!(banned(&b, k), 1, "banned, its tunnel's end long past");
}

/// Waits (on tokio's clock, at most a second) until `n` tunnels are installed (R-12's count).
async fn installed(app: &RelayApp, n: u64) {
    for _ in 0..1000 {
        if app.snapshot().tunnels == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("{} tunnels installed, not {n}", app.snapshot().tunnels);
}

/// TLS 15 (paused): a private connection is watched from its TLS accept (R-103). With no request it is cut 5 s after
/// its accept (`handshake_timeout_ms`), with a peer line `auth_timeout`, and its slot is free again (the face's one
/// here); one that sent refused tokens at 2 s and 4 s is cut at 5 s the same way (a refused request restarts
/// nothing); one whose token verified is cut `private_idle_s` (600 s) after its last request with a peer line `idle`,
/// and never while a call is pending. One whose client closes at 1 s leaves no `auth_timeout` at 5 s. After a verified
/// token, a refused request at 300 s moves the idle cut to 900 s: every request counts, refused or not.
#[tokio::test(start_paused = true)]
async fn an_idle_private_connection_is_cut_and_frees_its_slot() {
    let _serial = SERIAL.lock().await;
    let b = relay(Limits { private_conns_max: 1, ..limits() }, &["10.42.1.0/24"], true, Notifier::disabled());
    b.app.poll_files();
    let private = private_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let vm: IpAddr = "10.42.1.10".parse().unwrap();

    let (channel, closed) = vm_channel(&b.app, &private, Arc::clone(&cfg), vm).await;
    let accepted = tokio::time::Instant::now();
    assert!(admitted_private(&b.app, Arc::clone(&cfg), vm).await.is_none(), "its one slot is held");
    assert_eq!(closed_at(&closed).await - accepted, Duration::from_secs(5), "cut 5 s after its accept");
    drop(channel);

    let (channel, closed) = vm_channel(&b.app, &private, Arc::clone(&cfg), vm).await;
    let accepted = tokio::time::Instant::now();
    let mut client = RelayClient::new(channel);
    for at in [2, 4] {
        tokio::time::sleep_until(accepted + Duration::from_secs(at)).await;
        let s = client.list_sources(with_token(ListSourcesRequest {}, "v1.not-a-token.x")).await.expect_err("refused");
        assert_eq!(s.code(), Code::Unauthenticated);
    }
    assert_eq!(closed_at(&closed).await - accepted, Duration::from_secs(5), "a refused request restarts nothing");
    let lines = peer_lines(&b, "auth_timeout");
    assert!(lines.len() == 2 && lines.iter().all(|l| l["face"] == "private" && l["peer"] == "10.42.1.10"), "{lines:?}");
    drop(client);

    // A verified token, then a call pending its whole 600 s deadline: no cut while it is pending; the idle cut 600 s
    // after it ended.
    let public = public_face(&b.app);
    let (wchannel, _wclosed) = worker_channel(&b.app, &public, Arc::clone(&cfg), "198.51.100.7").await;
    let mut w = TestWorker::open_on(wchannel).await.expect("the Challenge");
    w.authenticate("worker-a", 1).await.expect("authenticated");
    w.register(catalog_a()).await;
    let _w = w.serve(Script::silent());
    for _ in 0..1000 {
        if b.app.snapshot().sources_live == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let (channel, closed) = vm_channel(&b.app, &private, Arc::clone(&cfg), vm).await;
    let mut client = RelayClient::new(channel);
    client.list_sources(with_token(ListSourcesRequest {}, &token())).await.expect("a verified token");
    tokio::time::sleep(Duration::from_secs(10)).await;
    let started = tokio::time::Instant::now();
    let call = {
        let mut c = client.clone();
        tokio::spawn(async move {
            let req = ai_env_relay_proto::v1::CallRequest { deadline_ms: 600_000, ..common::rig::request("example.alpha", "get", b"{}") };
            common::rig::drain(common::rig::call_with(&mut c, &token(), req).await.expect("a call")).await
        })
    };
    tokio::time::sleep_until(started + Duration::from_secs(610)).await;
    assert!(closed.lock().unwrap().is_none(), "never cut while its call was pending");
    let (chunks, _) = call.await.unwrap();
    assert_eq!(chunks.last().and_then(|c| c.error.as_ref()).map(|e| e.code), Some(4), "the call's deadline ended it");
    tokio::time::sleep_until(started + Duration::from_secs(1199)).await;
    assert!(closed.lock().unwrap().is_none(), "not before 600 s after its last request");
    assert_eq!(closed_at(&closed).await - started, Duration::from_secs(1200), "cut 600 s after the call ended");
    let lines = peer_lines(&b, "idle");
    assert!(lines.len() == 1 && lines[0]["face"] == "private", "{lines:?}");

    // A client that closes at 1 s: the watch ends with it, with no line then or at its deadline, and the slot is free.
    let (served, client) = admitted_private(&b.app, Arc::clone(&cfg), vm).await.expect("the slot is free");
    private.send(Ok(served)).unwrap();
    let accepted = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(client);
    tokio::time::sleep_until(accepted + Duration::from_secs(6)).await;
    assert_eq!(peer_lines(&b, "auth_timeout").len(), 2, "no line for a connection its client closed");

    // Verified, then a refused request at 300 s: idle 600 s after that request, not after the verified one.
    let (channel, closed) = vm_channel(&b.app, &private, Arc::clone(&cfg), vm).await;
    let verified = tokio::time::Instant::now();
    let mut client = RelayClient::new(channel);
    client.list_sources(with_token(ListSourcesRequest {}, &token())).await.expect("a verified token");
    tokio::time::sleep_until(verified + Duration::from_secs(300)).await;
    let s = client.list_sources(with_token(ListSourcesRequest {}, "v1.not-a-token.x")).await.expect_err("refused");
    assert_eq!(s.code(), Code::Unauthenticated);
    tokio::time::sleep_until(verified + Duration::from_secs(899)).await;
    assert!(closed.lock().unwrap().is_none(), "a refused request moved the idle cut");
    assert_eq!(closed_at(&closed).await - verified, Duration::from_secs(900), "cut 600 s after the refused request");
    assert_eq!(peer_lines(&b, "idle").len(), 2);
}

/// TLS 16 (paused): 32 idle private connections hold the face's 32 slots; the 33rd is refused
/// `too_many_connections`, and admitted once the token deadline cuts them, 5 s after their accept (R-103, R-2).
#[tokio::test(start_paused = true)]
async fn the_thirty_third_private_connection_waits_for_a_cut() {
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["10.42.1.0/24"], true, Notifier::disabled());
    b.app.poll_files();
    let private = private_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let vm: IpAddr = "10.42.1.10".parse().unwrap();
    assert_eq!(Limits::default().private_conns_max, 32);
    let t0 = tokio::time::Instant::now();
    let mut idle = Vec::new();
    for _ in 0..32 {
        idle.push(vm_channel(&b.app, &private, Arc::clone(&cfg), vm).await);
    }
    assert!(admitted_private(&b.app, Arc::clone(&cfg), vm).await.is_none(), "the 33rd");
    let refused = peer_lines(&b, "too_many_connections");
    assert!(refused.len() == 1 && refused[0]["face"] == "private", "{refused:?}");
    for (_, closed) in &idle {
        assert_eq!(closed_at(closed).await - t0, Duration::from_secs(5));
    }
    assert_eq!(peer_lines(&b, "auth_timeout").len(), 32);
    assert!(admitted_private(&b.app, cfg, vm).await.is_some(), "admitted after the cut");

    // R-104's order (LD-R42): an address outside `private_peers` is refused before the face's one bucket, so with a
    // burst of 4, five of them take none of its tokens (each `not_in_peers`, none `rate_limited`), and a VM is
    // admitted after them.
    let b = relay(Limits { private_accepts_burst: 4, ..limits() }, &["10.42.1.0/24"], true, Notifier::disabled());
    b.app.poll_files();
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let outside: IpAddr = "198.51.100.7".parse().unwrap();
    for _ in 0..5 {
        assert!(admitted_private(&b.app, Arc::clone(&cfg), outside).await.is_none());
    }
    assert_eq!(peer_lines(&b, "not_in_peers").len(), 5);
    assert!(peer_lines(&b, "rate_limited").is_empty(), "none took a token of the face's bucket");
    assert!(admitted_private(&b.app, cfg, vm).await.is_some(), "a VM is admitted after them");
}

/// A bare HTTP/2 client over an admitted connection (relay.rs's `h2raw`, over TLS): it writes what it likes and reads
/// what the relay answers (RFC 9113 §4, RFC 7541).
mod h2bare {
    use ai_env_relay_proto::prost::Message as _;
    use ai_env_relay_proto::v1::{RelayFrame, WorkerFrame};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    /// A frame type HTTP/2 does not define, which a receiver ignores whole (RFC 9113 §4.1).
    pub const UNKNOWN: u8 = 0xfa;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    /// RST_STREAM's REFUSED_STREAM and GOAWAY's ENHANCE_YOUR_CALM (RFC 9113 §7).
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const ENHANCE_YOUR_CALM: u32 = 0xb;

    /// One frame's bytes.
    pub fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
        let id = stream.to_be_bytes();
        let mut f = vec![len[1], len[2], len[3], kind, flags, id[0], id[1], id[2], id[3]];
        f.extend_from_slice(payload);
        f
    }

    /// The next frame the relay wrote, as (kind, flags, stream, payload); None once it ended the connection.
    pub async fn next<R: AsyncRead + Unpin>(r: &mut R) -> Option<(u8, u8, u32, Vec<u8>)> {
        let mut head = [0u8; 9];
        r.read_exact(&mut head).await.ok()?;
        let mut payload = vec![0u8; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
        r.read_exact(&mut payload).await.ok()?;
        Some((head[3], head[4], u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff, payload))
    }

    /// Exactly `bytes` (at least 9) of frames the relay reads and ignores: an unknown one, then PING ACKs of no PING.
    pub fn filler(bytes: usize) -> Vec<u8> {
        let ack = frame(PING, ACK, 0, &[0; 8]);
        let pad = (bytes - 9) % ack.len();
        let mut f = frame(UNKNOWN, 0, 0, &vec![0; pad]);
        f.extend(ack.repeat((bytes - 9 - pad) / ack.len()));
        f
    }

    /// One worker frame's gRPC message as DATA frames of stream 1, at most 16 KiB a frame.
    pub fn grpc_data(message: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8];
        body.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        body.extend_from_slice(message);
        body.chunks(16_384).flat_map(|c| frame(DATA, 0, 1, c)).collect()
    }

    /// Writes `bytes` to the relay and flushes them; how many.
    pub async fn put<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> usize {
        w.write_all(bytes).await.unwrap();
        w.flush().await.unwrap();
        bytes.len()
    }

    /// `frame` with bytes of an unknown field appended, `len` encoded bytes in all.
    pub fn padded(frame: &WorkerFrame, len: usize) -> Vec<u8> {
        let mut b = frame.encode_to_vec();
        // Field 100, length-delimited, with a three-byte length: five bytes before the padding.
        let pad = len - b.len() - 5;
        let l = u32::try_from(pad).unwrap();
        b.extend_from_slice(&[0xa2, 0x06, (l & 0x7f) as u8 | 0x80, ((l >> 7) & 0x7f) as u8 | 0x80, (l >> 14) as u8]);
        b.resize(len, 0);
        b
    }

    /// What a bare client has read of the relay's answers.
    #[derive(Default)]
    pub struct Seen {
        /// The relay's SETTINGS frames, its acks left out.
        pub settings: u32,
        /// The PINGs answered.
        pub pings: Vec<Vec<u8>>,
        /// Stream 1's gRPC messages.
        pub messages: Vec<RelayFrame>,
        /// Stream 1's bytes of a message not yet whole.
        partial: Vec<u8>,
        /// The WINDOW_UPDATE credit so far: the connection's, then stream 1's.
        pub credit: (u64, u64),
    }

    impl Seen {
        /// Reads frames until `done` holds; false if the relay ended the connection first.
        pub async fn read_until<R: AsyncRead + Unpin>(&mut self, r: &mut R, done: impl Fn(&Seen) -> bool) -> bool {
            while !done(self) {
                let Some((kind, flags, stream, payload)) = next(r).await else { return false };
                match kind {
                    SETTINGS if flags & ACK == 0 => self.settings += 1,
                    PING if flags & ACK != 0 => self.pings.push(payload),
                    WINDOW_UPDATE => {
                        let increment = u64::from(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]));
                        match stream {
                            0 => self.credit.0 += increment,
                            1 => self.credit.1 += increment,
                            _ => {}
                        }
                    }
                    DATA if stream == 1 => {
                        self.partial.extend_from_slice(&payload);
                        while self.partial.len() >= 5 {
                            let len = u32::from_be_bytes([self.partial[1], self.partial[2], self.partial[3], self.partial[4]]) as usize;
                            if self.partial.len() < 5 + len {
                                break;
                            }
                            self.messages.push(RelayFrame::decode(&self.partial[5..5 + len]).expect("a relay frame"));
                            self.partial.drain(..5 + len);
                        }
                    }
                    _ => {}
                }
            }
            true
        }

        /// Reads every frame until the relay ends the connection.
        pub async fn read_to_end<R: AsyncRead + Unpin>(&mut self, r: &mut R) {
            assert!(!self.read_until(r, |_| false).await);
        }
    }

    /// `WorkerTunnel.Open`'s header block: literal fields, never indexed, never Huffman-coded, each short.
    pub fn open_headers() -> Vec<u8> {
        let fields: [(&str, &str); 6] = [
            (":method", "POST"),
            (":scheme", "http"),
            (":path", "/ai_env.relay.v1.WorkerTunnel/Open"),
            (":authority", "ai-env-relay"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ];
        let mut b = Vec::new();
        for (name, value) in fields {
            b.push(0x00);
            b.push(u8::try_from(name.len()).unwrap());
            b.extend_from_slice(name.as_bytes());
            b.push(u8::try_from(value.len()).unwrap());
            b.extend_from_slice(value.as_bytes());
        }
        b
    }

    /// `open_headers` and one field more, so the header list's size (RFC 9113 §6.5.2: 32 a field beside its name and
    /// value) is `list` exactly.
    pub fn open_headers_of_size(list: usize) -> Vec<u8> {
        const FIELDS: usize = 6;
        const NAME: &[u8] = b"x-pad";
        let mut b = open_headers();
        let names_and_values = b.len() - 3 * FIELDS;
        let value = list - (names_and_values + 32 * FIELDS) - (NAME.len() + 32);
        b.push(0x00);
        b.push(u8::try_from(NAME.len()).unwrap());
        b.extend_from_slice(NAME);
        // RFC 7541 §5.1: a length past the 7-bit prefix.
        let rest = u32::try_from(value - 127).unwrap();
        b.extend_from_slice(&[0x7f, (rest & 0x7f) as u8 | 0x80, (rest >> 7) as u8]);
        b.resize(b.len() + value, b'a');
        b
    }
}

/// `ban_faults` 2 makes one address's faults countable: with exactly one so far, its next connection is admitted, and
/// that connection's own `open_timeout` then bans the address.
async fn assert_one_fault(b: &Box_, face: &PublicFace, cfg: &Arc<rustls::ClientConfig>, ip: &str) {
    let lines = |b: &Box_| peer_lines(b, "banned").iter().filter(|l| l["peer"] == ip).count();
    let (served, mut idle) = admitted(&b.app, Arc::clone(cfg), ip.parse().unwrap()).await.unwrap_or_else(|| panic!("{ip}: more than one fault"));
    assert_eq!(lines(b), 0);
    face.send(Ok(served)).unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(60), idle.read_to_end(&mut rest)).await.expect("cut at its open_timeout");
    assert!(admitted(&b.app, Arc::clone(cfg), ip.parse().unwrap()).await.is_none(), "{ip}: no fault before that open_timeout");
    assert_eq!(lines(b), 1);
}

/// Runs the other tasks until `f` holds, without moving tokio's clock (a read budget refills with time).
async fn settled(what: &str, f: impl Fn() -> bool) {
    for _ in 0..200_000 {
        if f() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("never: {what}");
}

/// A public connection's read budget before its `AuthOk` (LD-R60), on a clock that stands still, so with no refill:
/// `2 * public_window()`, as the unit's budget says.
const UNAUTHENTICATED_READS: usize = 557_056;

/// TLS 19 (paused, through `admit`; LD-R60): a public connection's reads are budgeted from its TLS accept. On a pipe
/// wide enough to take all it writes, a raw client that sends exactly the 557 056 bytes has the PING that ends them
/// answered, and the next PING not; a raw client that sends a PING (answered) and then 1 MiB of PING ACKs before any
/// `Open` has the PING after them never answered. Each is cut at its 5 s deadline, with one peer line `open_timeout` and
/// one fault. The budget's entry lasts as long as the connection, however it ends: the deadline's cut, a client that
/// leaves first, a refused handshake's cut, or a tunnel's end after its `AuthOk`.
#[tokio::test(start_paused = true)]
async fn a_flood_before_auth_meets_its_read_budget() {
    use ai_env_relay::tls::is_metered;
    use h2bare::*;
    let _serial = SERIAL.lock().await;
    let b = relay(Limits { ban_faults: 2, ..limits() }, &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let ack = frame(PING, ACK, 0, &[0; 8]);
    let ping = |payload: &[u8; 8]| frame(PING, 0, 0, payload);
    // Reads frames until the relay ends the connection, or until `until`'s PING is answered: the PINGs answered so far.
    async fn answers<R: AsyncRead + Unpin>(r: &mut R, until: Option<&[u8]>) -> Vec<Vec<u8>> {
        let mut seen = Vec::new();
        while let Some((kind, flags, _, payload)) = next(r).await {
            if kind == PING && flags & ACK != 0 {
                let done = until == Some(payload.as_slice());
                seen.push(payload);
                if done {
                    break;
                }
            }
        }
        seen
    }

    // Exactly the budget, the PING at its end answered: one byte over it would not be.
    let exact = "198.51.100.7";
    let accepted = tokio::time::Instant::now();
    let (served, client) = admitted_over(&b.app, Arc::clone(&cfg), exact.parse().unwrap(), 1 << 22).await.expect("admitted");
    let seq = served.info().conn_seq;
    face.send(Ok(served)).unwrap();
    settled("its read budget", || is_metered(seq)).await;
    let (mut rd, mut wr) = tokio::io::split(client);
    let mut flight = PREFACE.to_vec();
    flight.extend(frame(SETTINGS, 0, 0, &[]));
    let tail = ping(b"at-limit");
    flight.extend(filler(UNAUTHENTICATED_READS - flight.len() - tail.len()));
    flight.extend(&tail);
    assert_eq!(flight.len(), UNAUTHENTICATED_READS);
    wr.write_all(&flight).await.unwrap();
    wr.flush().await.unwrap();
    assert_eq!(answers(&mut rd, Some(b"at-limit")).await, [b"at-limit".to_vec()], "the budget's last bytes are read");
    assert_eq!(accepted.elapsed(), Duration::ZERO, "no virtual time for a refill");
    wr.write_all(&ping(b"past-end")).await.unwrap();
    wr.flush().await.unwrap();
    assert!(answers(&mut rd, None).await.is_empty(), "past the budget nothing more is read");
    assert_eq!(accepted.elapsed(), Duration::from_secs(5), "cut at its deadline");
    watching(&b.app, 0).await;
    assert_eq!(peer_lines(&b, "open_timeout").iter().filter(|l| l["peer"] == exact).count(), 1);
    assert!(!is_metered(seq), "the deadline's cut forgets its budget");
    drop((rd, wr));
    assert_one_fault(&b, &face, &cfg, exact).await;

    // 1 MiB of PING ACKs with no `Open`: a PING before them answered, the PING after them never.
    let flood = "198.51.100.8";
    let (served, client) = admitted_over(&b.app, Arc::clone(&cfg), flood.parse().unwrap(), 1 << 22).await.expect("admitted");
    let seq = served.info().conn_seq;
    let accepted = tokio::time::Instant::now();
    face.send(Ok(served)).unwrap();
    let (mut rd, mut wr) = tokio::io::split(client);
    let mut flight = PREFACE.to_vec();
    flight.extend(frame(SETTINGS, 0, 0, &[]));
    flight.extend(ping(b"before-1"));
    wr.write_all(&flight).await.unwrap();
    wr.flush().await.unwrap();
    assert_eq!(answers(&mut rd, Some(b"before-1")).await, [b"before-1".to_vec()], "a PING inside the budget");
    let mut flight = ack.repeat((1 << 20) / ack.len());
    flight.extend(ping(b"after-1m"));
    wr.write_all(&flight).await.unwrap();
    wr.flush().await.unwrap();
    assert!(answers(&mut rd, None).await.is_empty(), "the PING after the flood is never answered");
    assert_eq!(accepted.elapsed(), Duration::from_secs(5), "cut at its deadline, with nothing more read");
    watching(&b.app, 0).await;
    assert_eq!(peer_lines(&b, "open_timeout").iter().filter(|l| l["peer"] == flood).count(), 1);
    assert!(!is_metered(seq), "no entry outlives its connection");
    drop((rd, wr));
    assert_one_fault(&b, &face, &cfg, flood).await;

    // A client that leaves first.
    let (served, client) = admitted(&b.app, Arc::clone(&cfg), "198.51.100.9".parse().unwrap()).await.expect("admitted");
    let seq = served.info().conn_seq;
    face.send(Ok(served)).unwrap();
    settled("its read budget", || is_metered(seq)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(client);
    watching(&b.app, 0).await;
    assert!(!is_metered(seq), "the client's leaving forgets it");

    // A refused handshake: the cut a second after it.
    let (served, client) = admitted(&b.app, Arc::clone(&cfg), "198.51.100.10".parse().unwrap()).await.expect("admitted");
    let seq = served.info().conn_seq;
    let (channel, closed) = served_channel(&face, served, client).await;
    let mut w = TestWorker::open_on(channel).await.expect("the Challenge");
    let h = hello("worker-a", 1);
    let mut p = proof(&w.challenge, &h, 1);
    p.signature[0] ^= 1;
    w.send(worker_frame::Msg::Hello(h)).await;
    w.send(worker_frame::Msg::AuthProof(p)).await;
    assert_eq!(w.end().await.expect_err("a failed handshake").code(), Code::Unauthenticated);
    assert!(is_metered(seq), "metered through its grace");
    closed_at(&closed).await;
    watching(&b.app, 0).await;
    assert!(!is_metered(seq), "the refused handshake's cut forgets it");

    // A tunnel: its own budget replaces this one at its AuthOk, and goes at its end.
    let (served, client) = admitted(&b.app, Arc::clone(&cfg), "198.51.100.11".parse().unwrap()).await.expect("admitted");
    let seq = served.info().conn_seq;
    let (channel, _closed) = served_channel(&face, served, client).await;
    let mut w = TestWorker::open_on(channel).await.expect("the Challenge");
    w.authenticate("worker-a", 1).await.expect("authenticated");
    w.register(catalog_a()).await;
    installed(&b.app, 1).await;
    assert!(is_metered(seq), "its tunnel's");
    drop(w);
    watching(&b.app, 0).await;
    assert!(!is_metered(seq), "the tunnel's end forgets it");
}

/// TLS 20 (paused, through `admit`; R-12, R-102): at `tunnels_max` a new worker's handshake reads 8 `too many tunnels`
/// after its proof, 25 times from one address, and that is no fault: its next connection is admitted, with no `banned`
/// line. The tunnel's own worker may still reconnect (R-12 spares the id it holds).
#[tokio::test(start_paused = true)]
async fn too_many_tunnels_is_refused_and_no_fault() {
    let _serial = SERIAL.lock().await;
    let l = Limits { tunnels_max: 1, public_accepts_burst: 1000, public_accepts_per_min: 6000, public_conns_per_ip: 1024, public_conns_max: 4096, ..limits() };
    let b = relay(l, &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let (channel, _closed) = worker_channel(&b.app, &face, Arc::clone(&cfg), "198.51.100.7").await;
    let mut a = TestWorker::open_on(channel).await.expect("the Challenge");
    a.authenticate("worker-a", 1).await.expect("authenticated");
    a.register(catalog_a()).await;
    installed(&b.app, 1).await;

    // A different address, so worker-a's exemption (R-98) hides no fault.
    let other = "203.0.113.9";
    for i in 0..25 {
        let (channel, _closed) = worker_channel(&b.app, &face, Arc::clone(&cfg), other).await;
        let mut w = TestWorker::open_on(channel).await.expect("the Challenge");
        let s = w.authenticate("worker-b", 2).await.expect_err("the one tunnel is worker-a's");
        assert_eq!((s.code(), s.message()), (Code::ResourceExhausted, "too many tunnels"), "attempt {i}");
    }
    let refused = b.sink.lines().into_iter().filter(|l| l.contains("\"reason\":\"too_many_tunnels\"") && l.contains(other)).count();
    assert_eq!(refused, 25);
    assert!(admitted(&b.app, Arc::clone(&cfg), other.parse().unwrap()).await.is_some(), "no fault: its next connection is admitted");
    assert!(peer_lines(&b, "banned").is_empty(), "{:?}", peer_lines(&b, "banned"));
    let (channel, _closed) = worker_channel(&b.app, &face, cfg, other).await;
    let mut again = TestWorker::open_on(channel).await.expect("the Challenge");
    again.authenticate("worker-a", 1).await.expect("the holder of the one tunnel may reconnect");
}

/// TLS 21 (paused, through `admit`; R-5): refused streams count toward `http2_max_local_error_reset_streams` (64), as
/// h2 0.4.20 counts them. With the face's one stream held by an `Open`, a raw client's further HEADERS are refused
/// REFUSED_STREAM, 64 of them; the 65th brings GOAWAY(ENHANCE_YOUR_CALM), and the connection ends. The `Open`'s
/// handshake reads that as a stream error: one tunnel line `refused`, `malformed`, and one fault.
#[tokio::test(start_paused = true)]
async fn sixty_five_refused_streams_end_a_connection_with_a_fault() {
    use h2bare::*;
    let _serial = SERIAL.lock().await;
    let b = relay(Limits { ban_faults: 2, ..limits() }, &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let ip = "198.51.100.7";
    let (served, client) = admitted_over(&b.app, Arc::clone(&cfg), ip.parse().unwrap(), 1 << 20).await.expect("admitted");
    face.send(Ok(served)).unwrap();
    let (mut rd, mut wr) = tokio::io::split(client);
    let headers = open_headers();
    let mut flight = PREFACE.to_vec();
    flight.extend(frame(SETTINGS, 0, 0, &[]));
    flight.extend(frame(HEADERS, END_HEADERS, 1, &headers));
    wr.write_all(&flight).await.unwrap();
    wr.flush().await.unwrap();
    // The Challenge: the `Open` holds the one stream.
    loop {
        let (kind, _, stream, _) = next(&mut rd).await.expect("the Challenge");
        if kind == DATA && stream == 1 {
            break;
        }
    }
    let flight: Vec<u8> = (0..65u32).flat_map(|i| frame(HEADERS, END_HEADERS, 2 * i + 3, &headers)).collect();
    wr.write_all(&flight).await.unwrap();
    wr.flush().await.unwrap();
    let (mut refused, mut away) = (0, None);
    while let Some((kind, _, _, payload)) = next(&mut rd).await {
        let code = |at: usize| u32::from_be_bytes([payload[at], payload[at + 1], payload[at + 2], payload[at + 3]]);
        match kind {
            RST_STREAM if code(0) == REFUSED_STREAM => refused += 1,
            GOAWAY => away = Some(code(4)),
            _ => {}
        }
    }
    assert_eq!(refused, 64, "the budget's refusals");
    assert_eq!(away, Some(ENHANCE_YOUR_CALM), "the 65th ends the connection");
    drop((rd, wr));
    watching(&b.app, 0).await;
    settled("the tunnel line", || b.sink.lines().iter().any(|l| l.contains("\"ev\":\"tunnel\""))).await;
    let lines: Vec<serde_json::Value> = b.sink.lines().iter().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()).filter(|v| v["ev"] == "tunnel").collect();
    assert!(lines.len() == 1 && lines[0]["outcome"] == "refused" && lines[0]["reason"] == "malformed" && lines[0]["peer"] == ip, "{lines:?}");
    assert!(peer_lines(&b, "open_timeout").is_empty());
    assert_one_fault(&b, &face, &cfg, ip).await;
}

/// The Challenge that opened a bare client's stream.
fn challenge_of(seen: &h2bare::Seen) -> ai_env_relay_proto::v1::Challenge {
    match seen.messages.first().and_then(|m| m.msg.clone()) {
        Some(ai_env_relay_proto::v1::relay_frame::Msg::Challenge(c)) => c,
        other => panic!("the first frame is the Challenge, not {other:?}"),
    }
}

/// TLS 22 (paused, through `admit`; LD-R60's second exit): a raw client that holds an `Open` and then floods, 1 MiB of
/// PING ACKs, has the PING after them never answered. A stalled read cannot end the connection early, so the handshake's
/// budget ends it: at 5 s one tunnel line `refused`, `timeout`, and one fault; a second later the cut. No peer line
/// `open_timeout`: the `Open` came in time.
#[tokio::test(start_paused = true)]
async fn a_flood_with_an_open_held_meets_the_handshake_timeout() {
    use ai_env_relay::tls::is_metered;
    use h2bare::*;
    let _serial = SERIAL.lock().await;
    let b = relay(Limits { ban_faults: 2, ..limits() }, &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let ip = "198.51.100.7";
    let (served, client) = admitted_over(&b.app, Arc::clone(&cfg), ip.parse().unwrap(), 1 << 22).await.expect("admitted");
    let seq = served.info().conn_seq;
    let accepted = tokio::time::Instant::now();
    face.send(Ok(served)).unwrap();
    let (mut rd, mut wr) = tokio::io::split(client);
    let mut seen = Seen::default();
    put(&mut wr, &[PREFACE.to_vec(), frame(SETTINGS, 0, 0, &[]), frame(HEADERS, END_HEADERS, 1, &open_headers())].concat()).await;
    assert!(seen.read_until(&mut rd, |s| !s.messages.is_empty()).await, "the Challenge");
    let mut flood = filler(1 << 20);
    flood.extend(frame(PING, 0, 0, b"after-1m"));
    put(&mut wr, &flood).await;
    seen.read_to_end(&mut rd).await;
    assert!(seen.pings.is_empty(), "the PING after the flood is never answered: {:?}", seen.pings);
    assert_eq!(accepted.elapsed(), Duration::from_secs(6), "the handshake's 5 s and the cut's second");
    watching(&b.app, 0).await;
    assert!(!is_metered(seq), "no entry outlives its connection");
    let lines = tunnel_lines(&b, ip);
    assert!(lines.len() == 1 && lines[0]["outcome"] == "refused" && lines[0]["reason"] == "timeout", "{lines:?}");
    assert!(peer_lines(&b, "open_timeout").is_empty(), "its `Open` came in time");
    drop((rd, wr));
    assert_one_fault(&b, &face, &cfg, ip).await;
}

/// TLS 23 (paused, through `admit`; LD-R60): the largest handshake the face's caps let through fits its read budget. A
/// raw client, minding the windows R-5 sets, sends a header list of 16 383 bytes (h2 takes one under its cap), a `Hello`
/// of `catalog_max_bytes` padded in `sdk_version` and an `AuthProof` of `catalog_max_bytes` padded with an unknown field,
/// over 540 KB in all, and reads its `AuthOk`. The tunnel's budget then replaces this one: more than was left of it is
/// read.
#[tokio::test(start_paused = true)]
async fn the_largest_handshake_fits_its_read_budget() {
    use ai_env_relay_proto::prost::Message as _;
    use ai_env_relay_proto::v1::relay_frame;
    use common::worker::wf;
    use h2bare::*;
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let cap = limits().catalog_max_bytes as usize;
    let (served, client) = admitted_over(&b.app, cfg, "198.51.100.7".parse().unwrap(), 1 << 22).await.expect("admitted");
    let accepted = tokio::time::Instant::now();
    face.send(Ok(served)).unwrap();
    let (mut rd, mut wr) = tokio::io::split(client);
    let mut seen = Seen::default();

    // The windows: h2's default until the relay's SETTINGS is acked and its connection's WINDOW_UPDATE read.
    let window = (UNAUTHENTICATED_READS / 2) as u64;
    let mut sent = put(&mut wr, &[PREFACE.to_vec(), frame(SETTINGS, 0, 0, &[])].concat()).await;
    assert!(seen.read_until(&mut rd, |s| s.settings == 1 && 65_535 + s.credit.0 >= window).await, "the relay's SETTINGS and window");
    sent += put(&mut wr, &frame(SETTINGS, ACK, 0, &[])).await;
    sent += put(&mut wr, &frame(HEADERS, END_HEADERS, 1, &open_headers_of_size(16_383))).await;
    assert!(seen.read_until(&mut rd, |s| !s.messages.is_empty()).await, "the Challenge");

    // A `Hello` at the decode cap, its windows back, then an `AuthProof` at the decode cap.
    let mut h = hello("worker-a", 1);
    let p = proof(&challenge_of(&seen), &h, 1);
    h.sdk_version = "0".repeat(cap - 1024);
    let over = wf(worker_frame::Msg::Hello(h.clone())).encoded_len() - (cap - 1024);
    h.sdk_version = "0".repeat(cap - over);
    let hello_frame = wf(worker_frame::Msg::Hello(h)).encode_to_vec();
    assert_eq!(hello_frame.len(), cap);
    let data = (cap + 5) as u64;
    sent += put(&mut wr, &grpc_data(&hello_frame)).await;
    assert!(seen.read_until(&mut rd, |s| (65_535 + s.credit.0).min(window + s.credit.1) >= 2 * data).await, "the `Hello`'s windows back");
    sent += put(&mut wr, &grpc_data(&padded(&wf(worker_frame::Msg::AuthProof(p)), cap))).await;
    assert!(seen.read_until(&mut rd, |s| s.messages.len() == 2).await, "the largest handshake reaches its AuthOk");
    assert!(matches!(seen.messages[1].msg, Some(relay_frame::Msg::AuthOk(_))), "{:?}", seen.messages[1]);
    assert!(sent > 540_000 && sent <= UNAUTHENTICATED_READS, "{sent} bytes");
    assert_eq!(accepted.elapsed(), Duration::ZERO, "no virtual time for a refill");

    // The tunnel's budget from here: more than was left of the first is read.
    let mut more = filler(UNAUTHENTICATED_READS - sent + 1);
    more.extend(frame(PING, 0, 0, b"its-own!"));
    put(&mut wr, &more).await;
    assert!(seen.read_until(&mut rd, |s| !s.pings.is_empty()).await, "the tunnel's budget replaced what was left");
    assert_eq!(seen.pings, [b"its-own!".to_vec()]);
    assert_eq!(accepted.elapsed(), Duration::ZERO, "no virtual time for a refill");
}

/// TLS 24 (paused, through `admit`; LD-R60, R-107): a read budget that runs short with a good proof already read stays
/// short past the `AuthOk`, so the bytes it dropped are followed by no others. With 32 KiB of the budget left beside the
/// proof, one flight holds the `AuthProof` and twice that: the relay's reads, 8 KiB each, take the proof and then run
/// short, in one turn of the connection's task, before the handshake's task runs (on this paused clock, one thread and
/// a pinned tokio; if that order ever changes, this test fails at the PING's assert). The client reads
/// `Close{3, "inbound rate"}`, which overtakes the queued `AuthOk` (R-27); a PING after it is never answered; the cut
/// comes a second after the tunnel's end, and the entry goes with it.
#[tokio::test(start_paused = true)]
async fn a_read_budget_short_at_the_auth_ok_stays_short() {
    use ai_env_relay::tls::is_metered;
    use ai_env_relay_proto::prost::Message as _;
    use ai_env_relay_proto::v1::relay_frame;
    use common::worker::wf;
    use h2bare::*;
    const LEFT: usize = 32 * 1024;
    let _serial = SERIAL.lock().await;
    let b = relay(limits(), &["127.0.0.0/8"], true, Notifier::disabled());
    b.app.poll_files();
    let face = public_face(&b.app);
    let cfg = client_config(&[&b.ca], &[&rustls::version::TLS13]);
    let ip = "198.51.100.7";
    let (served, client) = admitted_over(&b.app, cfg, ip.parse().unwrap(), 1 << 22).await.expect("admitted");
    let seq = served.info().conn_seq;
    let accepted = tokio::time::Instant::now();
    face.send(Ok(served)).unwrap();
    let (mut rd, mut wr) = tokio::io::split(client);
    let mut seen = Seen::default();
    let sent = put(&mut wr, &[PREFACE.to_vec(), frame(SETTINGS, 0, 0, &[]), frame(HEADERS, END_HEADERS, 1, &open_headers())].concat()).await;
    assert!(seen.read_until(&mut rd, |s| !s.messages.is_empty()).await, "the Challenge");

    // The `Hello` and frames to spend the budget, all read (the PING at their end answered), LEFT bytes to spare after
    // the proof, and no virtual time for a refill.
    let h = hello("worker-a", 1);
    let the_proof = grpc_data(&wf(worker_frame::Msg::AuthProof(proof(&challenge_of(&seen), &h, 1))).encode_to_vec());
    let mut flight = grpc_data(&wf(worker_frame::Msg::Hello(h)).encode_to_vec());
    let last = frame(PING, 0, 0, b"its-last");
    flight.extend(filler(UNAUTHENTICATED_READS - sent - flight.len() - last.len() - the_proof.len() - LEFT));
    flight.extend(&last);
    put(&mut wr, &flight).await;
    assert!(seen.read_until(&mut rd, |s| !s.pings.is_empty()).await, "all of it is read");
    assert_eq!(accepted.elapsed(), Duration::ZERO, "no virtual time for a refill");

    let mut flight = the_proof;
    flight.extend(filler(2 * LEFT));
    put(&mut wr, &flight).await;
    assert!(seen.read_until(&mut rd, |s| s.messages.len() >= 2).await, "the tunnel's first answer");
    put(&mut wr, &frame(PING, 0, 0, b"past-end")).await;
    seen.read_to_end(&mut rd).await;
    assert_eq!(seen.pings, [b"its-last".to_vec()], "the bytes it dropped are followed by no others");
    match seen.messages.last().and_then(|m| m.msg.as_ref()) {
        Some(relay_frame::Msg::Close(c)) => assert_eq!((c.code, c.reason.as_str()), (3, "inbound rate")),
        other => panic!("a Close, not {other:?}"),
    }
    assert_eq!(accepted.elapsed(), Duration::from_secs(1), "the cut, a second after the tunnel's end");
    watching(&b.app, 0).await;
    assert!(!is_metered(seq), "no entry outlives its connection");
    let lines = tunnel_lines(&b, ip);
    assert!(lines.len() == 2 && lines[0]["outcome"] == "ok" && lines[1]["outcome"] == "closed" && lines[1]["reason"] == "rate", "{lines:?}");
}
