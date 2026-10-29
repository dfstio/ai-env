//! The worker's TLS client over real TCP on `127.0.0.1` (§WM-worker-mac.8.2: WM-T31, WM-T32, WM-T50): only
//! the pinned CA, only TLS 1.3, only the right name; proxy variables never read; and the relay's production
//! certificate profile (`certs`) served by a rustls acceptor and verified for both of its names.

mod common;

use std::net::Ipv4Addr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ai_env_worker::certs::{self, CertError};
use ai_env_worker::{CheckReport, RelayEndpoint, Worker, WorkerError};
use common::certs::{openssl, pki, Pair};
use common::fake_relay::{ping, FakeRelay, WAIT};
use common::{quick, signer, sources};

/// Set only in the child process `proxy_variables_are_ignored` re-executes.
const CHILD: &str = "AI_ENV_WORKER_PROXY_CHILD";

/// A worker for `addr` pinning `ca_pem`, checking the certificate against `name`.
fn worker(addr: &str, ca_pem: &[u8], name: &str) -> Arc<Worker> {
    let endpoint = RelayEndpoint::new(addr).expect("an address").ca_pem(ca_pem).expect("a CA").server_name(name).expect("a name");
    Arc::new(Worker::builder().worker_id("worker-a").relay(endpoint).signer(signer()).source(sources::echo()).tuning(quick()).build().expect("builds"))
}

/// `check` against `relay`: when its tunnel comes, the relay pings and the check accepts.
async fn check(relay: &mut FakeRelay, worker: Arc<Worker>) -> Result<CheckReport, WorkerError> {
    let mut checking = tokio::spawn(async move { worker.check().await });
    tokio::select! {
        r = &mut checking => r.expect("joined"),
        tunnel = relay.tunnel(WAIT) => {
            tunnel.send(ping(1)).await;
            checking.await.expect("joined")
        }
    }
}

/// `check` of a worker that dials `relay` over TCP, pinning `ca_pem`, for `name`.
async fn check_tcp(relay: &mut FakeRelay, ca_pem: &[u8], name: &str) -> Result<CheckReport, WorkerError> {
    let w = worker(&local(relay), ca_pem, name);
    check(relay, w).await
}

fn local(relay: &FakeRelay) -> String {
    format!("127.0.0.1:{}", relay.port.expect("a TCP port"))
}

/// The TLS failure's text.
fn tls_text(r: Result<CheckReport, WorkerError>) -> String {
    match r {
        Err(WorkerError::Tls(text)) => text,
        other => panic!("not a TLS failure: {other:?}"),
    }
}

/// `openssl s_server` on `127.0.0.1` with `pair` and `-tls1_2` alone; killed on drop.
struct TlsTwelve {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for TlsTwelve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl TlsTwelve {
    fn start(pair: &Pair) -> TlsTwelve {
        let dir = tempfile::tempdir().expect("a temp dir");
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        std::fs::write(&cert, &pair.cert_pem).expect("cert");
        std::fs::write(&key, &pair.key_pem).expect("key");
        for _ in 0..5 {
            let port = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind").local_addr().expect("addr").port();
            let mut child = Command::new(openssl())
                .args(["s_server", "-accept", &format!("127.0.0.1:{port}"), "-cert"])
                .arg(&cert)
                .arg("-key")
                .arg(&key)
                .args(["-tls1_2", "-www", "-quiet"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("s_server runs");
            let until = std::time::Instant::now() + Duration::from_secs(10);
            while std::time::Instant::now() < until {
                if std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(200)).is_ok() {
                    return TlsTwelve { child, port, _dir: dir };
                }
                if child.try_wait().expect("wait").is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("openssl s_server -tls1_2 never listened");
    }
}

/// WM-T31.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_trusts_only_its_pinned_ca_over_tls13() {
    let pki = pki();
    let mut relay = FakeRelay::start_tcp(&pki.relay_a).await;
    let report = check_tcp(&mut relay, &pki.ca_a, "ai-env-relay").await.expect("CA A: the handshake completes");
    assert_eq!(report.relay_id, "relay-test");

    let mut other_ca = FakeRelay::start_tcp(&pki.relay_b).await;
    let text = tls_text(check_tcp(&mut other_ca, &pki.ca_a, "ai-env-relay").await);
    assert!(text.contains("UnknownIssuer"), "{text}");
    assert!(other_ca.no_tunnel(Duration::from_millis(200)).await, "refused before any frame");
    assert_eq!(other_ca.connections(), 0);

    let twelve = TlsTwelve::start(&pki.relay_a);
    let addr = format!("127.0.0.1:{}", twelve.port);
    let text = tls_text(worker(&addr, &pki.ca_a, "ai-env-relay").check().await);
    assert!(text.contains("ProtocolVersion"), "a TLS 1.2-only server: {text}");

    let mut wrong_name = FakeRelay::start_tcp(&pki.other_name_a).await;
    let text = tls_text(check_tcp(&mut wrong_name, &pki.ca_a, "ai-env-relay").await);
    assert!(text.contains("not valid for name"), "{text}");

    let with_key = [pki.ca_a.clone(), pki.relay_a.key_pem.clone()].concat();
    let refused = RelayEndpoint::new("127.0.0.1:443").expect("an address").ca_pem(&with_key).err().expect("a CA file with a key");
    assert!(refused.to_string().contains("private key"), "{refused}");
    let no_ca = RelayEndpoint::new("127.0.0.1:443").expect("an address").ca_pem(b"no PEM here").err().expect("no certificate");
    assert!(no_ca.to_string().contains("no certificate"), "{no_ca}");
}

/// WM-T32: the same handshake in a child process of this binary with every proxy variable at a closed port.
#[test]
fn proxy_variables_are_ignored() {
    let exe = std::env::current_exe().expect("the test binary");
    let out = common::certs::output_within(
        Command::new(exe)
            .args(["--exact", "proxy_variables_are_ignored_child", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("https_proxy", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env("all_proxy", "http://127.0.0.1:9")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy"),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("proxy-child: handshake done"), "{stdout}");
}

/// The child half of `proxy_variables_are_ignored` (nothing in the parent).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_variables_are_ignored_child() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    // The parent set four of them; they are counted by their names' shape, none read.
    let proxies = std::env::vars_os().filter(|(name, _)| name.to_string_lossy().to_ascii_lowercase().ends_with("_proxy")).count();
    assert!(proxies >= 4, "{proxies} proxy variables");
    let pki = pki();
    let mut relay = FakeRelay::start_tcp(&pki.relay_a).await;
    check_tcp(&mut relay, &pki.ca_a, "ai-env-relay").await.expect("the handshake completes");
    println!("proxy-child: handshake done");
}

/// WM-T50.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_profile_serves_both_names_and_nothing_else() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("time").as_secs();
    let ca = certs::relay_ca(now).expect("a CA");
    let leaf = certs::relay_leaf(&ca, Ipv4Addr::new(10, 42, 0, 20), now).expect("a leaf");
    let ca_pem = certs::pem("CERTIFICATE", &ca.cert_der);
    let pair = Pair { cert_pem: certs::pem("CERTIFICATE", &leaf.cert_der).into_bytes(), key_pem: certs::pem("PRIVATE KEY", &leaf.key_pkcs8).into_bytes() };
    let value = [String::from_utf8(pair.cert_pem.clone()).expect("PEM"), ca_pem.clone(), String::from_utf8(pair.key_pem.clone()).expect("PEM")].concat();
    assert!(value.len() <= 4096, "the leaf, the CA and the key as PEM: {} bytes", value.len());

    let mut relay = FakeRelay::start_tcp(&pair).await;
    for name in ["ai-env-relay", "10.42.0.20"] {
        check_tcp(&mut relay, ca_pem.as_bytes(), name).await.unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let text = tls_text(check_tcp(&mut relay, ca_pem.as_bytes(), "relay.example.test").await);
    assert!(text.contains("not valid for name"), "{text}");
    let text = tls_text(check_tcp(&mut relay, &pki().ca_a, "ai-env-relay").await);
    assert!(text.contains("UnknownIssuer"), "another CA: {text}");

    let other = certs::relay_ca(now).expect("another CA");
    assert_eq!(certs::ca_from_parts(&ca.cert_der, &other.key_pkcs8).err(), Some(CertError::Mismatch));
    assert_eq!(certs::ca_from_parts(&ca.cert_der, &ca.key_pkcs8).expect("the same CA").cert_der, ca.cert_der);
}
