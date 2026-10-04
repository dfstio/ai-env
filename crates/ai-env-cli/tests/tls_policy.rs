//! S6 T6.1's TLS half (plan S6, W5): the Mac's one client policy
//! (`bridge::tls`) against local listeners. `openssl s_server` serves a P-256
//! key and a self-signed certificate for localhost, both made in a tempdir at
//! test time (no key is committed): the WebSocket connector, the reqwest
//! client and the SDK's HTTP client refuse it (UnknownIssuer: Amazon Root CA
//! 1–4 are the only anchors), and a `-tls1_2`-only listener gets a
//! protocol-version alert from the 1.3-only WebSocket and reqwest paths (the
//! SDK client negotiates 1.2 by the documented exception in `tls.rs`, then
//! refuses the certificate). In a child process of this binary — a fresh
//! process with `HTTPS_PROXY`/`ALL_PROXY` (both spellings) at 127.0.0.1:9 and
//! no `NO_PROXY` — the same dials still reach the listeners (their TLS
//! errors, never a refused proxy connect), and the process default crypto
//! provider is none before the three clients are built and aws-lc-rs after.
//! The WebSocket leg reproduces `transport`'s handshake (its own TCP connect,
//! then `tls::ws_connector()`): it checks the connector in a proxy-env
//! process, while `dial_agent`'s immunity to the proxy rests on transport's
//! own `TcpStream::connect` (no other file may dial: `make lint`), since the
//! production path cannot be aimed at a local `s_server` (wss dials port 443
//! and the lab knob forces `ws://`).
use ai_env_cli::bridge::tls;
use rustls::crypto::CryptoProvider;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Every wait of these tests (a dial, a listener coming up, the child).
const LIMIT: Duration = Duration::from_secs(30);

/// Set (to the mode) only in the child process this binary re-executes.
const CHILD: &str = "AI_ENV_TLS_POLICY_CHILD";

/// The program and its arguments, never the environment (`Command`'s `Debug` shows both).
fn shown(cmd: &Command) -> String {
    std::iter::once(cmd.get_program()).chain(cmd.get_args()).map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" ")
}

/// `cmd` to its end within `limit`, stdout and stderr collected; killed and
/// failed past it.
fn output_within(cmd: &mut Command, limit: Duration) -> Output {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap_or_else(|e| panic!("{}: {e}", shown(cmd)));
    let drain = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.read_to_end(&mut buf);
            buf
        })
    };
    let (out, err) = (drain(Box::new(child.stdout.take().unwrap())), drain(Box::new(child.stderr.take().unwrap())));
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{} did not finish within {limit:?}", shown(cmd));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output { status, stdout: out.join().unwrap(), stderr: err.join().unwrap() }
}

fn run_ok(cmd: &mut Command) {
    let out = output_within(cmd, LIMIT);
    assert!(out.status.success(), "{}: {}", shown(cmd), String::from_utf8_lossy(&out.stderr));
}

/// The openssl CLI: Homebrew's when present, else the PATH's; OpenSSL 3 or
/// later (macOS's own `openssl` is LibreSSL). Checked once per process.
fn openssl() -> &'static Path {
    static BIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let brew = Path::new("/opt/homebrew/bin/openssl");
        let bin = if brew.is_file() { brew.to_path_buf() } else { PathBuf::from("openssl") };
        let out = output_within(Command::new(&bin).arg("version"), LIMIT);
        let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let major: u32 = version.strip_prefix("OpenSSL ").and_then(|v| v.split('.').next()).and_then(|m| m.parse().ok()).unwrap_or(0);
        assert!(major >= 3, "{} is {version:?}: the TLS negatives need the OpenSSL 3+ CLI (brew install openssl)", bin.display());
        bin
    })
}

/// The self-signed certificate's extensions: a leaf (`req -x509` would
/// otherwise mark it a CA, which webpki refuses as `CaUsedAsEndEntity`
/// before it asks who issued it).
const LEAF_CNF: &str = "[req]\ndistinguished_name = dn\nx509_extensions = leaf\nprompt = no\n[dn]\nCN = localhost\n\
                        [leaf]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\n\
                        subjectAltName = DNS:localhost,IP:127.0.0.1\n";

/// A P-256 key and a self-signed leaf certificate for localhost (SAN
/// DNS:localhost, IP:127.0.0.1) in `dir`: (key, cert).
fn self_signed(dir: &Path) -> (PathBuf, PathBuf) {
    let (key, cert, cnf) = (dir.join("key.pem"), dir.join("cert.pem"), dir.join("leaf.cnf"));
    std::fs::write(&cnf, LEAF_CNF).unwrap();
    run_ok(Command::new(openssl()).args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out"]).arg(&key));
    run_ok(Command::new(openssl()).args(["req", "-x509", "-key"]).arg(&key).arg("-out").arg(&cert).args(["-days", "1", "-config"]).arg(&cnf));
    (key, cert)
}

/// A port nobody listens on right now (s_server binds it next; a lost race is retried).
fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

/// `openssl s_server` on 127.0.0.1 with the self-signed pair and one protocol
/// version (`-tls1_3` or `-tls1_2`); killed on drop.
struct Server {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn start(version: &str) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let (key, cert) = self_signed(dir.path());
        let log = dir.path().join("s_server.log");
        for _ in 0..5 {
            let port = free_port();
            let mut child = Command::new(openssl())
                .args(["s_server", "-accept", &format!("127.0.0.1:{port}"), "-cert"])
                .arg(&cert)
                .arg("-key")
                .arg(&key)
                .args([version, "-www", "-quiet"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(&log).unwrap())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + LIMIT;
            loop {
                if std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(200)).is_ok() {
                    return Server { child, port, _dir: dir };
                }
                // Exited: the port was taken between the probe and its bind.
                if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        panic!("openssl s_server {version} never listened: {}", std::fs::read_to_string(&log).unwrap_or_default());
    }
}

/// What rustls reported, anywhere in `e`'s chain: an `io::Error` carries it
/// inside, where `source()` does not look.
fn rustls_error(e: &(dyn std::error::Error + 'static)) -> Option<rustls::Error> {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(r) = err.downcast_ref::<rustls::Error>() {
            return Some(r.clone());
        }
        if let Some(inner) = err.downcast_ref::<std::io::Error>().and_then(std::io::Error::get_ref) {
            if let Some(r) = rustls_error(inner) {
                return Some(r);
            }
        }
        cur = err.source();
    }
    None
}

/// The rustls error of a failed dial, or a panic naming the whole chain (a
/// refused proxy connect has none).
fn tls_failure(what: &str, e: &(dyn std::error::Error + 'static)) -> rustls::Error {
    rustls_error(e).unwrap_or_else(|| {
        let mut chain = vec![e.to_string()];
        let mut cur = e.source();
        while let Some(s) = cur {
            chain.push(s.to_string());
            cur = s.source();
        }
        panic!("{what}: not a TLS error: {}", chain.join(": "))
    })
}

fn unknown_issuer() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
}

fn protocol_version_alert() -> rustls::Error {
    rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion)
}

/// The WebSocket dial as `transport::dial_agent` makes it (a copy, not a
/// call): a TCP connect of its own (no proxy setting can apply), then the
/// one connector.
async fn ws_dial(port: u16) -> rustls::Error {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let dial = tokio_tungstenite::client_async_tls_with_config(format!("wss://localhost:{port}/agent"), tcp, None, Some(tls::ws_connector()));
    match tokio::time::timeout(LIMIT, dial).await.expect("the WebSocket dial ends in time") {
        Ok(_) => panic!("the WebSocket connector accepted the listener on {port}"),
        Err(e) => tls_failure("the WebSocket dial", &e),
    }
}

async fn reqwest_get(port: u16) -> rustls::Error {
    let get = tls::reqwest_client().unwrap().get(format!("https://localhost:{port}/")).send();
    match tokio::time::timeout(LIMIT, get).await.expect("the reqwest GET ends in time") {
        Ok(r) => panic!("reqwest got {} from the listener on {port}", r.status()),
        Err(e) => tls_failure("the reqwest GET", &e),
    }
}

/// One `ListMicrovms` through the SDK with `tls::sdk_http_client()`, its
/// endpoint the listener: static test credentials, no retry, nothing read
/// from the environment or a profile.
async fn sdk_call(port: u16) -> rustls::Error {
    use aws_sdk_lambdamicrovms::config::retry::RetryConfig;
    use aws_sdk_lambdamicrovms::config::timeout::TimeoutConfig;
    use aws_sdk_lambdamicrovms::config::{BehaviorVersion, Credentials, Region};
    let conf = aws_sdk_lambdamicrovms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(ai_env_cli::bridge::config::REGION))
        .endpoint_url(format!("https://localhost:{port}"))
        .credentials_provider(Credentials::new("tls-policy-test", "tls-policy-test", None, None, "tls_policy"))
        .retry_config(RetryConfig::disabled())
        .timeout_config(TimeoutConfig::builder().operation_timeout(LIMIT).build())
        .http_client(tls::sdk_http_client())
        .build();
    let call = aws_sdk_lambdamicrovms::Client::from_conf(conf).list_microvms().send();
    match tokio::time::timeout(LIMIT + Duration::from_secs(5), call).await.expect("the SDK call ends in time") {
        Ok(_) => panic!("the SDK client accepted the listener on {port}"),
        Err(e) => tls_failure("the SDK call", &e),
    }
}

/// Every client against both listeners: the self-signed one is refused by
/// all three; the 1.2-only one gets the alert from the 1.3-only paths, and
/// the SDK path (1.2 allowed) refuses its certificate.
async fn dial_all(self_signed: u16, tls12: u16) {
    assert_eq!(ws_dial(self_signed).await, unknown_issuer(), "WebSocket, self-signed");
    assert_eq!(ws_dial(tls12).await, protocol_version_alert(), "WebSocket, TLS 1.2 only");
    assert_eq!(reqwest_get(self_signed).await, unknown_issuer(), "reqwest, self-signed");
    assert_eq!(reqwest_get(tls12).await, protocol_version_alert(), "reqwest, TLS 1.2 only");
    assert_eq!(sdk_call(self_signed).await, unknown_issuer(), "SDK, self-signed");
    assert_eq!(sdk_call(tls12).await, unknown_issuer(), "SDK, TLS 1.2 only: negotiated, then the certificate refused");
}

#[tokio::test]
async fn the_ws_connector_refuses_self_signed_and_tls12_listeners() {
    let (ss, t12) = (Server::start("-tls1_3"), Server::start("-tls1_2"));
    assert_eq!(ws_dial(ss.port).await, unknown_issuer());
    assert_eq!(ws_dial(t12.port).await, protocol_version_alert());
}

#[tokio::test]
async fn the_reqwest_client_refuses_self_signed_and_tls12_listeners() {
    let (ss, t12) = (Server::start("-tls1_3"), Server::start("-tls1_2"));
    assert_eq!(reqwest_get(ss.port).await, unknown_issuer());
    assert_eq!(reqwest_get(t12.port).await, protocol_version_alert());
}

/// The SDK's client has no 1.3 floor (`tls.rs`, documented exception), but
/// the same four anchors: the self-signed listener is refused under either
/// version.
#[tokio::test]
async fn the_sdk_client_refuses_a_self_signed_listener() {
    let (ss, t12) = (Server::start("-tls1_3"), Server::start("-tls1_2"));
    assert_eq!(sdk_call(ss.port).await, unknown_issuer());
    assert_eq!(sdk_call(t12.port).await, unknown_issuer());
}

/// This binary again, running only [`child_mode`] with `mode`, the
/// environment cleared but for `env`: its stdout once it passed.
fn child(mode: &str, env: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["child_mode", "--exact", "--ignored", "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env(CHILD, mode)
        .envs(env.iter().copied());
    let out = output_within(&mut cmd, 4 * LIMIT);
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout).to_string(), String::from_utf8_lossy(&out.stderr).to_string());
    assert!(out.status.success() && stdout.contains("1 passed"), "child {mode:?} ({}):\n{stdout}\n{stderr}", out.status);
    stdout
}

/// `HTTPS_PROXY`, `ALL_PROXY` and both lowercase spellings at 127.0.0.1:9
/// (nothing listens; a client that honoured them would fail to connect, with
/// no TLS error), `NO_PROXY` unset: every client still reaches the listeners.
#[test]
fn the_proxy_environment_is_ignored() {
    let (ss, t12) = (Server::start("-tls1_3"), Server::start("-tls1_2"));
    let proxy = "http://127.0.0.1:9";
    let env = [("HTTPS_PROXY", proxy), ("ALL_PROXY", proxy), ("https_proxy", proxy), ("all_proxy", proxy)];
    let stdout = child(&format!("proxy {} {}", ss.port, t12.port), &env);
    assert!(stdout.contains("tls_policy child: proxy env set, every dial reached its listener"), "{stdout}");
}

/// In a fresh process: no default crypto provider before the clients are
/// built; after the WebSocket connector, the reqwest client and the SDK
/// client, the default is aws-lc-rs's (the crate has no other provider).
#[test]
fn one_crypto_provider_aws_lc_rs() {
    let stdout = child("provider", &[]);
    assert!(stdout.contains("tls_policy child: the default provider is aws-lc-rs"), "{stdout}");
}

/// The child process of the two tests above (`AI_ENV_TLS_POLICY_CHILD` names
/// the mode); run directly it does nothing.
#[tokio::test]
#[ignore = "child mode of the_proxy_environment_is_ignored and one_crypto_provider_aws_lc_rs"]
async fn child_mode() {
    let Ok(mode) = std::env::var(CHILD) else { return };
    match mode.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["proxy", ss, t12] => {
            for v in ["HTTPS_PROXY", "ALL_PROXY", "https_proxy", "all_proxy"] {
                assert_eq!(std::env::var(v).as_deref(), Ok("http://127.0.0.1:9"), "{v}");
            }
            assert!(std::env::var_os("NO_PROXY").is_none() && std::env::var_os("no_proxy").is_none());
            dial_all(ss.parse().unwrap(), t12.parse().unwrap()).await;
            println!("tls_policy child: proxy env set, every dial reached its listener");
        }
        ["provider"] => {
            assert!(CryptoProvider::get_default().is_none(), "a fresh process has no default provider yet");
            let _ = tls::ws_connector();
            let _ = tls::reqwest_client().unwrap();
            let _ = tls::sdk_http_client();
            let installed = CryptoProvider::get_default().expect("a default provider once the clients exist");
            let aws_lc = rustls::crypto::aws_lc_rs::default_provider();
            assert_eq!(format!("{:?}", installed.key_provider), "AwsLcRs", "{installed:?}");
            assert_eq!(format!("{installed:?}"), format!("{aws_lc:?}"), "aws-lc-rs's default provider, unchanged");
            println!("tls_policy child: the default provider is aws-lc-rs");
        }
        other => panic!("unknown child mode {other:?}"),
    }
}
