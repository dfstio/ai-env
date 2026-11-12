//! The template's sources against ai-env-source's conformance checks (P-R85): offline, so the
//! `HttpJsonSource` below never reaches its address. And its binary's `tls-keygen` and client certificate
//! config (WM-T57), offline too; and `run`'s stop on SIGINT and SIGTERM though its parent blocked both (R-162),
//! against a relay address that refuses every dial.

#[allow(dead_code)]
#[path = "../src/config.rs"]
mod config;
#[allow(dead_code)]
#[path = "../src/sources.rs"]
mod sources;

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ai_env_source::testkit::{assert_conforms, context};
use ai_env_source::{CallRequest, DataSource, Limits, SourceError};
use ai_env_worker::certs::{self, ClientPoint};
use ai_env_worker::keys;
use ai_env_worker::RelayEndpoint;
use nix::sys::signal::{kill, SigSet, Signal};
use nix::unistd::Pid;
use serde_json::json;

/// This package's binary, as cargo built it for its tests (its name follows the package's).
const BIN: &str = env!(concat!("CARGO_BIN_EXE_", env!("CARGO_PKG_NAME")));

#[tokio::test]
async fn the_example_sources_conform() {
    assert_conforms(Arc::new(sources::EchoSource::new("example-echo"))).await;
    assert_conforms(Arc::new(sources::HttpJsonSource::new("example-http", "http://127.0.0.1:9", vec!["/v1/".into()], None))).await;
}

/// `HttpJsonSource` refuses, before any I/O, a path outside its prefixes and one the URL parser would read
/// otherwise: percent-encoded dots, a backslash, a prefix not on a segment boundary, a query, a fragment, a
/// control character (the parser drops it, and `.\t.` becomes `..`).
#[tokio::test]
async fn the_http_source_refuses_paths_outside_its_prefixes() {
    let source = sources::HttpJsonSource::new("example-http", "http://127.0.0.1:9", vec!["/v1/status".into()], None);
    let get = |path: &str| source.call(CallRequest::new("get", json!({ "path": path })), context("example-http", Limits::DEFAULT, Duration::from_secs(2)));
    let refused = [
        "/v1/status/%2e%2e/%2e%2e/admin",
        "/v1/status/.%2E/admin",
        "/v1/status\\%2e%2e\\admin",
        "/v1/status\\..\\admin",
        "/v1/statusX",
        "/v1/status/../admin",
        "/v1/status/.\t./admin",
        "/v1/status/\n",
        "/v1/status/ x",
        "/v1/status?admin=1",
        "/v1/status#admin",
        "/v1/status/é",
        "v1/status",
        "/v2/status",
        "",
    ];
    for path in refused {
        match get(path).await {
            Err(SourceError::InvalidArgument(m)) => assert_eq!(m, "params: path is not allowed", "{path:?}"),
            other => panic!("{path:?} is refused before any I/O: {other:?}"),
        }
    }
    // These pass the check (the request then fails on the closed port, whatever the error).
    for path in ["/v1/status", "/v1/status/", "/v1/status/x.json"] {
        assert!(!matches!(get(path).await, Err(SourceError::InvalidArgument(_))), "{path:?} is allowed");
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("the binary runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("UTF-8")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// WM-T57: `tls-keygen` writes the worker's 0600 P-256 key and prints its point and the next command; a config
/// takes the client certificate and its key together or not at all, the key read as the worker key is (R-119),
/// refuses a misspelt key, and `check` presents the pair.
#[test]
fn tls_keygen_writes_its_key_and_the_config_takes_both_files() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("tls-keygen");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a directory");
    let path = |name: &str| dir.join(name).display().to_string();

    let key = path("relay-client.key");
    let out = run(&["tls-keygen", "--out", &key]);
    assert!(out.status.success(), "{}", stderr(&out));
    let printed = stdout(&out);
    let lines: Vec<&str> = printed.lines().collect();
    assert_eq!(lines.len(), 2, "two lines: {printed:?}");
    assert!(lines[0].len() == 93 && lines[0].starts_with("p256:"), "{}", lines[0]);
    let first_point = ClientPoint::parse_text(lines[0]).expect("a P-256 point's text");
    let next = format!(
        "next, on the Mac: ai-env as deployer -- ai-env relay allow <worker-id> --key <its ed25519 key> --sources <its globs> --tls-key {}; the certificate it prints goes to relay_client_cert",
        lines[0]
    );
    assert_eq!(lines[1], next);
    assert_eq!(std::fs::metadata(&key).expect("the key").permissions().mode() & 0o777, 0o600);
    let first = keys::read_private_pem(Path::new(&key)).expect("the one reader of key files");

    // Again: refused without --force, the key unchanged; replaced with it.
    let again = run(&["tls-keygen", "--out", &key]);
    assert!(!again.status.success() && stderr(&again).contains("already exists: --force replaces it"), "{}", stderr(&again));
    assert!(keys::read_private_pem(Path::new(&key)).expect("read") == first, "the key unchanged");
    let forced = run(&["tls-keygen", "--out", &key, "--force"]);
    assert!(forced.status.success(), "{}", stderr(&forced));
    let point = ClientPoint::parse_text(stdout(&forced).lines().next().unwrap_or_default()).expect("a point");
    assert_ne!(point, first_point, "a new key, a new point");
    assert!(keys::read_private_pem(Path::new(&key)).expect("read") != first, "the key replaced");

    // The certificate the deployer would issue for the printed point (here under a CA of the test's).
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after 1970").as_secs();
    let ca = certs::relay_ca(now).expect("a CA");
    std::fs::write(path("relay-ca.pem"), certs::pem("CERTIFICATE", &ca.cert_der)).expect("the CA");
    let cert_der = certs::client_leaf(&ca, "example-worker", &point, now, now + 86_400).expect("a client certificate");
    let cert_pem = certs::pem("CERTIFICATE", &cert_der);
    std::fs::write(path("relay-client.pem"), &cert_pem).expect("the certificate");
    let key_pem = keys::read_private_pem(Path::new(&key)).expect("the key");
    assert!(RelayEndpoint::new("203.0.113.10:443").expect("an address").client_identity(cert_pem.as_bytes(), &key_pem).is_ok(), "the key of the printed point");
    let worker_key = path("worker.key");
    assert!(run(&["keygen", "--out", &worker_key]).status.success());

    let config = |name: &str, extra: &str| {
        let text = format!(
            "worker_id = \"example-worker\"\nrelay = \"203.0.113.10:443\"\nserver_name = \"ai-env-relay\"\nrelay_ca = {:?}\n{extra}signer = \"file\"\nkey_file = {worker_key:?}\n\n[[source]]\nkind = \"echo\"\nname = \"example-echo\"\n",
            path("relay-ca.pem"),
        );
        let p = path(name);
        std::fs::write(&p, text).expect("a config");
        p
    };
    let cert_line = format!("relay_client_cert = {:?}\n", path("relay-client.pem"));
    let key_line = format!("relay_client_key = {key:?}\n");
    for (name, extra) in [("cert-alone.toml", cert_line.clone()), ("key-alone.toml", key_line.clone())] {
        let p = config(name, &extra);
        let e = config::Config::load(Path::new(&p)).expect_err("one of the two");
        assert_eq!(format!("{e:#}"), format!("{p}: relay_client_cert and relay_client_key go together"));
        let out = run(&["check", "--config", &p, "--offline"]);
        assert!(!out.status.success() && stderr(&out).contains("relay_client_cert and relay_client_key go together"), "{}", stderr(&out));
    }
    let both = config("both.toml", &format!("{cert_line}{key_line}"));
    let loaded = config::Config::load(Path::new(&both)).expect("both");
    assert!(loaded.relay_client_cert.is_some() && loaded.relay_client_key.is_some());
    let out = run(&["check", "--config", &both, "--offline"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).starts_with("config ok: worker example-worker, 1 source(s), key fp "), "{}", stdout(&out));
    // The certificate in the file, by what `ai-env relay status` shows of the entry's tls_fp (RO-4).
    assert!(stdout(&out).ends_with(&format!(", cert fp {}\n", &certs::tls_fp(&cert_der)[..16])), "{}", stdout(&out));
    let neither = config("neither.toml", "");
    let out = run(&["check", "--config", &neither, "--offline"]);
    assert!(out.status.success() && !stdout(&out).contains("cert fp"), "no certificate, no fingerprint: {}", stdout(&out));

    // The binary reads relay_client_key as it reads the worker key (R-119's one reader): a key file with group or
    // other bits, or a symlink to the key, is refused at build.
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
    let out = run(&["check", "--config", &both, "--offline"]);
    let refused = format!("my-worker: {key}: has mode 0644: a key file is 0600 (chmod 600)");
    assert!(!out.status.success() && stderr(&out).contains(&refused), "{}", stderr(&out));
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    let link = path("relay-client-link.key");
    std::os::unix::fs::symlink(&key, &link).expect("a symlink");
    let linked = config("linked.toml", &format!("{cert_line}relay_client_key = {link:?}\n"));
    let out = run(&["check", "--config", &linked, "--offline"]);
    let refused = format!("my-worker: {link}: is a symlink: point the config at the key file itself");
    assert!(!out.status.success() && stderr(&out).contains(&refused), "{}", stderr(&out));
    assert!(run(&["check", "--config", &both, "--offline"]).status.success(), "the key file itself, 0600");

    // A misspelt key is refused (R-122's `deny_unknown_fields`): ignored, neither real key would be set, `check` would
    // say ok, and a relay that requires a client certificate would refuse the worker at TLS.
    let typo = config("typo.toml", "relay_client_crt = \"x\"\n");
    let out = run(&["check", "--config", &typo, "--offline"]);
    assert!(!out.status.success() && stderr(&out).contains("unknown field `relay_client_crt`"), "{}", stderr(&out));

    // A certificate of another key is refused at build.
    let other_key = certs::client_key().expect("another key");
    let other = certs::client_leaf(&ca, "example-worker", &certs::client_point(&other_key).expect("its point"), now, now + 86_400).expect("a certificate");
    std::fs::write(path("relay-client.pem"), certs::pem("CERTIFICATE", &other)).expect("another certificate");
    let out = run(&["check", "--config", &both, "--offline"]);
    assert!(!out.status.success() && stderr(&out).contains("the client key does not match the client certificate"), "{}", stderr(&out));
    let _ = std::fs::remove_dir_all(&dir);
}

/// What `run` logs each time a dial ends (the SDK's line).
const DIAL_ENDED: &str = "the relay tunnel ended; the next dial waits";

/// A worker process, killed (SIGKILL) and reaped when the test ends before it does.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Each line of a child's stderr, as it comes; the channel closes with the stream.
fn lines_of(stream: ChildStderr) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// R-162: `run` stops on SIGINT and on SIGTERM though the thread that started it had both blocked, as a shell that
/// blocked them would: std passes that mask to the child, and `main` unblocks both. The worker logs `stopping` and
/// exits 0 within 10 s of the signal; one still running then is killed. Its relay, 127.0.0.1:1, refuses every dial
/// at once, so it waits between dials when the signal comes.
#[test]
fn run_stops_on_sigint_and_sigterm_started_with_both_blocked() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("stop-signals");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a directory");
    let path = |name: &str| dir.join(name).display().to_string();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("after 1970").as_secs();
    std::fs::write(path("relay-ca.pem"), certs::pem("CERTIFICATE", &certs::relay_ca(now).expect("a CA").cert_der)).expect("the CA");
    let key = path("worker.key");
    assert!(run(&["keygen", "--out", &key]).status.success());
    let config = path("worker.toml");
    let text = format!(
        "worker_id = \"example-worker\"\nrelay = \"127.0.0.1:1\"\nserver_name = \"ai-env-relay\"\nrelay_ca = {:?}\nsigner = \"file\"\nkey_file = {key:?}\n\n[[source]]\nkind = \"echo\"\nname = \"example-echo\"\n",
        path("relay-ca.pem"),
    );
    std::fs::write(&config, text).expect("a config");

    for signal in [Signal::SIGINT, Signal::SIGTERM] {
        // A thread of its own blocks both (this list, not `main`'s) and starts the worker: the test's other threads
        // keep their masks. `NO_COLOR` keeps the worker's lines plain in a failure's text.
        let config = config.clone();
        let started = std::thread::spawn(move || {
            [Signal::SIGINT, Signal::SIGTERM].into_iter().collect::<SigSet>().thread_block().expect("both blocked on this thread");
            let mut cmd = Command::new(BIN);
            cmd.args(["run", "--config", &config]).env("RUST_LOG", "info").env("NO_COLOR", "1");
            cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("the binary runs")
        });
        let mut worker = Killed(started.join().expect("the starting thread"));
        let pid = Pid::from_raw(i32::try_from(worker.0.id()).expect("a pid"));
        let lines = lines_of(worker.0.stderr.take().expect("its stderr"));
        let mut seen: Vec<String> = Vec::new();

        // The second dial's end, not the first's: it comes after `run_until`'s first poll, which polls `shutdown`
        // and so installs both handlers; the first can come out of that same poll, before them.
        let until = Instant::now() + Duration::from_secs(30);
        while seen.iter().filter(|line| line.contains(DIAL_ENDED)).count() < 2 {
            match lines.recv_timeout(until.saturating_duration_since(Instant::now())) {
                Ok(line) => seen.push(line),
                Err(e) => panic!("{signal}: no second dial ended within 30 s ({e}):\n{}", seen.join("\n")),
            }
        }
        kill(pid, signal).expect("the signal");

        // Its stderr to the end, then its status, within 10 s of the signal.
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            match lines.recv_timeout(until.saturating_duration_since(Instant::now())) {
                Ok(line) => seen.push(line),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => panic!("{signal}: the worker still runs 10 s after the signal (killed):\n{}", seen.join("\n")),
            }
        }
        let status = loop {
            if let Some(status) = worker.0.try_wait().expect("its status") {
                break status;
            }
            assert!(Instant::now() < until, "{signal}: the worker closed its stderr but still runs 10 s after the signal (killed)");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "{signal}: {status}:\n{}", seen.join("\n"));
        assert!(seen.iter().any(|line| line.ends_with(" stopping")), "{signal}: no `stopping`:\n{}", seen.join("\n"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
