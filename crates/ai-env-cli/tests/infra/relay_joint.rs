//! S13 I2: the joint tests of slice M with R, V and W (plans/s13-contracts.md §WM-worker-mac.8.5, §X.3), through the
//! real `ai-env relay` with the fake aws and age of tests/infra/relay_mac.rs's [`World`]. WM-J3: every list `allow`,
//! `revoke` and `grant` render (M's `params.rs`) parses with the relay's loader (R's `lists.rs`) into the entries it
//! was given. WM-J4 (also WM-T49, B-8): the CA and the `tls` value `relay tls init` issues (W's `certs`, the
//! production profile) are served by the relay's `run` on both faces; the VM's client (V) verifies `10.42.0.20` under
//! `state/relay-ca.der`, a worker (W) verifies `ai-env-relay` under `state/relay-ca.pem`, and another CA or another
//! name fails. No key, token or certificate is committed: each comes from a low-entropy seed at run time or from the
//! run itself; every name is generic.
use super::common::stderr;
use super::relay_mac::{Who, World};
use ai_env_cli::bridge::relay::tls::ca_der_b64;
use ai_env_cli::wire::redact::Secret;
use ai_env_cli::wire::relay::RelaySpawn;
use ai_env_cli::wire::time::{rfc3339_utc, unix_now};
use ai_env_relay::files::{content_version, Live, Poll, FETCHED_FILE, TLS_FILE};
use ai_env_relay::lists::{self, GRANTS_FILE, SIGNERS_FILE, WORKERS_FILE};
use ai_env_relay::notify::Notifier;
use ai_env_relay::reqlog::MemorySink;
use ai_env_relay::{Config, Deps, Limits, RelayApp, SystemClock};
use ai_env_relay_client::dial::RelayLink;
use ai_env_relay_client::local::Code;
use ai_env_relay_client::session::Session;
use ai_env_worker::ai_env_source::{BoxFuture, CallContext, CallRequest, DataSource, OpDescriptor, Output, SourceDescriptor, SourceError};
use ai_env_worker::certs;
use ai_env_worker::keys::{PublicKey, SigningKey};
use ai_env_worker::policy::{self, Grant, SignerEntry, WorkerEntry};
use ai_env_worker::session::{self, SessionClaims, SESSION_AUD};
use ai_env_worker::signer::FileSigner;
use ai_env_worker::{CheckReport, RelayEndpoint, Worker, WorkerError};
use base64::Engine as _;
use std::fs;
use std::path::Path;
use std::process::Output as Ran;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// The name a VM verifies on the private face: the contract's literal (X-3, R-3a, WM-R62), not M's `RELAY_IP`, which
/// M's leaf follows too, so a drifted relay address fails V's handshake here.
const VM_SERVER_NAME: &str = "10.42.0.20";

/// The relay's TLS parameter (`<prefix>/tls`, M's WM-R59).
fn tls_param() -> String {
    format!("{}/tls", policy::PARAMETER_PREFIX)
}

fn code(o: &Ran) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn key_of(seed: u8) -> PublicKey {
    SigningKey::from_seed(&[seed; 32]).unwrap().public_key()
}

/// The UTC day `days` after today, `YYYY-MM-DD` (`allow`'s default is 365).
fn day_in(days: u64) -> String {
    let now = unix_now();
    rfc3339_utc(now - now % 86_400 + days * 86_400)[..10].to_string()
}

/// `ai-env relay <args>` as ai-env-deployer: exit 0.
fn deployer(w: &World, args: &[&str]) {
    let o = w.run(args, Who::Deployer);
    assert_eq!(code(&o), 0, "relay {}: {}", args.join(" "), stderr(&o));
}

/// `allow <args>` by the default day, and the day M should have stamped: today + 365 on the test's clock just before
/// the run, or just after it when a UTC midnight fell during the run (`stamped` reads the entry's `not_after` back).
/// Any other day fails the caller's equality check, so the day is bounded on both sides.
fn allow_by_default_day(w: &World, args: &[&str], stamped: impl FnOnce(&World) -> Option<String>) -> String {
    let before = day_in(365);
    deployer(w, args);
    if stamped(w).is_some_and(|not_after| not_after.starts_with(&before)) { before } else { day_in(365) }
}

/// Parameter `name`'s value as the fake aws holds it.
fn value(w: &World, name: &str) -> String {
    w.param(name).unwrap_or_else(|| panic!("{name} was never written")).0
}

/// The entries the operator gave: the key's base64, the globs sorted, the day's last second (WM-R43).
fn worker(id: &str, seed: u8, globs: &[&str], day: &str) -> WorkerEntry {
    WorkerEntry {
        worker_id: id.into(),
        alg: "ed25519".into(),
        public_key: key_of(seed).b64(),
        sources: globs.iter().map(|g| (*g).to_string()).collect(),
        not_after: format!("{day}T23:59:59Z"),
    }
}

fn signer(id: &str, seed: u8, day: &str) -> SignerEntry {
    SignerEntry { signer_id: id.into(), alg: "ed25519".into(), public_key: key_of(seed).b64(), not_after: format!("{day}T23:59:59Z") }
}

fn grant(id: &str, rules: &[&str]) -> Grant {
    Grant { grant_id: id.into(), allow: rules.iter().map(|r| (*r).to_string()).collect() }
}

/// The three lists as the relay's loader (`ai_env_relay::lists::parse_*`, over the bytes) reads M's values.
fn workers(w: &World) -> Vec<WorkerEntry> {
    lists::parse_workers(value(w, policy::WORKERS).as_bytes()).unwrap_or_else(|e| panic!("R's loader refuses M's workers: {e}")).entries
}

fn signers(w: &World) -> Vec<SignerEntry> {
    lists::parse_signers(value(w, policy::TOKEN_SIGNERS).as_bytes()).unwrap_or_else(|e| panic!("R's loader refuses M's token-signers: {e}")).entries
}

fn grants(w: &World) -> Vec<Grant> {
    lists::parse_grants(value(w, policy::GRANTS).as_bytes()).unwrap_or_else(|e| panic!("R's loader refuses M's grants: {e}")).entries
}

/// WM-J3 (with R): each render of `allow`, `revoke` and `grant` (workers and token signers added, by the default
/// day and by `--not-after`, globs given unsorted, then revoked, the workers down to `[]`; grants set, rules given
/// unsorted and twice, then removed) parses with the relay's loader into exactly the entries given; the three,
/// published as I's reload publishes them, load in the relay's live directory and answer its lookups as given.
#[test]
fn the_lists_m_writes_are_the_lists_r_reads() {
    let w = World::new();
    let month = day_in(30);
    let year_a = allow_by_default_day(&w, &["allow", "worker-a", "--key", &key_of(1).text(), "--sources", "example-*"], |w| workers(w).first().map(|e| e.not_after.clone()));
    let a = worker("worker-a", 1, &["example-*"], &year_a);
    assert_eq!(workers(&w), std::slice::from_ref(&a));
    deployer(&w, &["allow", "worker-b", "--key", &key_of(2).text(), "--sources", "other-*,example.beta*", "--not-after", &month]);
    let b = worker("worker-b", 2, &["example.beta*", "other-*"], &month);
    assert_eq!(workers(&w), [a.clone(), b.clone()]);
    let year_mac = allow_by_default_day(&w, &["allow", "mac", "--token-signer", "--key", &key_of(7).text()], |w| signers(w).first().map(|e| e.not_after.clone()));
    let mac = signer("mac", 7, &year_mac);
    assert_eq!(signers(&w), std::slice::from_ref(&mac));
    deployer(&w, &["allow", "mac-2", "--token-signer", "--key", &key_of(8).text(), "--not-after", &month]);
    let mac2 = signer("mac-2", 8, &month);
    assert_eq!(signers(&w), [mac.clone(), mac2]);
    deployer(&w, &["grant", "default", "example-*/list", "example-*/get", "example-*/list"]);
    let default = grant("default", &["example-*/get", "example-*/list"]);
    assert_eq!(grants(&w), std::slice::from_ref(&default));
    deployer(&w, &["grant", "g-beta", "example.beta*/*"]);
    let beta = grant("g-beta", &["example.beta*/*"]);
    assert_eq!(grants(&w), [default, beta.clone()]);

    // Published as I's reload publishes them (each value a file, then `fetched`), all three load in the live
    // directory, each at the content version of M's bytes, and answer as given.
    let dir = tempfile::tempdir().unwrap();
    let bodies = [(WORKERS_FILE, policy::WORKERS), (SIGNERS_FILE, policy::TOKEN_SIGNERS), (GRANTS_FILE, policy::GRANTS)].map(|(file, name)| (file, value(&w, name)));
    for (file, body) in &bodies {
        fs::write(dir.path().join(file), body).unwrap();
    }
    let (now, now_unix) = (SystemTime::now(), unix_now());
    fs::write(dir.path().join(FETCHED_FILE), format!("{now_unix}\n")).unwrap();
    let live = Live::new(dir.path());
    let max = Duration::from_secs(900);
    let polled = live.poll(now, max);
    for (i, (name, (_, body))) in ["workers", "token-signers", "grants"].iter().zip(&bodies).enumerate() {
        assert_eq!(polled[i], (*name, Poll::Loaded { version: content_version(body.as_bytes()) }), "{name}");
    }
    let (live_workers, live_signers, live_grants) = (live.workers.fresh(now, max).unwrap(), live.signers.fresh(now, max).unwrap(), live.grants.fresh(now, max).unwrap());
    assert!(live_workers.in_force("worker-a", now_unix).is_some_and(|e| e.allows_source("example-x") && !e.allows_source("example.beta-1")));
    assert!(live_workers.in_force("worker-b", now_unix).is_some_and(|e| e.allows_source("example.beta-1") && e.allows_source("other-x") && !e.allows_source("example-x")));
    for (id, seed, day) in [("mac", 7, &year_mac), ("mac-2", 8, &month)] {
        let k = live_signers.key(id).unwrap_or_else(|| panic!("{id} signs tokens"));
        assert_eq!((k.public_key, k.not_after), (key_of(seed), policy::unix_of(&format!("{day}T23:59:59Z")).unwrap()), "{id}");
    }
    assert!(live_grants.get("default").is_some_and(|g| g.allows("example-x", "get") && g.allows("example-x", "list") && !g.allows("example-x", "put")));
    assert!(live_grants.get("g-beta").is_some_and(|g| g.allows("example.beta-1", "any") && !g.allows("example-x", "get")));

    // The renders of `revoke` and `grant --remove` parse back too, down to the empty list.
    deployer(&w, &["revoke", "worker-a"]);
    assert_eq!(workers(&w), [b]);
    deployer(&w, &["revoke", "mac-2", "--token-signer"]);
    assert_eq!(signers(&w), [mac]);
    deployer(&w, &["grant", "default", "--remove"]);
    assert_eq!(grants(&w), [beta]);
    deployer(&w, &["revoke", "worker-b"]);
    assert_eq!(value(&w, policy::WORKERS), "[]");
    assert!(workers(&w).is_empty());
}

/// A generic source with one op, `get`, answering `{"ok":true}`.
struct Example;

impl DataSource for Example {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor::new("example-alpha", "1.0.0", "A generic example source.").env("test").op(OpDescriptor::new("get", "Answers a fixed object.").read_only(true))
    }

    fn call<'s, 'f>(&'s self, _req: CallRequest, _ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        Box::pin(async { Ok(Output::json(serde_json::json!({"ok": true}))) })
    }
}

/// `worker-a` (seed 1, the key `allow` whitelisted) serving [`Example`], dialing `public` pinning `ca_pem`, checking
/// the certificate against `name`.
fn worker_a(public: std::net::SocketAddr, ca_pem: &[u8], name: &str) -> Worker {
    let endpoint = RelayEndpoint::new(&public.to_string()).expect("the public face").ca_pem(ca_pem).expect("a CA").server_name(name).expect("a name");
    let signer = Arc::new(FileSigner::from_key(SigningKey::from_seed(&[1; 32]).unwrap()));
    Worker::builder().worker_id("worker-a").relay(endpoint).signer(signer).source(Arc::new(Example)).build().expect("a worker")
}

/// The VM's client on a spawn's session (M's `RelaySpawn`, its fd-3 payload, V's `Session::parse`).
fn vm_link(spawn: &RelaySpawn) -> RelayLink {
    spawn.check().expect("V-R3's shapes");
    let session = Session::parse(&spawn.session()).expect("V-R16's shapes");
    RelayLink::new(&session, Duration::from_secs(60)).expect("a link")
}

/// A session token of the token signer `mac` (seed 7) for the grant `default`, an hour from now.
fn session_token() -> String {
    let now = unix_now();
    let claims = SessionClaims {
        kid: "mac".into(),
        aud: SESSION_AUD.into(),
        caller_id: "mac".into(),
        session_id: "0199a1b2-0000-7000-8000-000000000002".into(),
        chat_id: None,
        grant_id: "default".into(),
        vm_id: "microvm-0199a1b2-0000-7000-8000-000000000001".into(),
        iat: now,
        exp: now + 3600,
    };
    session::mint(&SigningKey::from_seed(&[7; 32]).unwrap(), &claims, now).expect("W/M's mint")
}

/// `f` polled every 10 ms until it gives a value; a panic naming `what` after 20 s.
async fn until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(tokio::time::Instant::now() < deadline, "{what}: not within 20 s");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// WM-J4, also WM-T49 (with R, V and W; B-8): the CA and the `tls` value `relay tls init` issues, published with
/// the lists `allow` and `grant` wrote, are R's `tls::server_config` and serve both faces of R's `run` on
/// `127.0.0.1:0`. A worker pinning `state/relay-ca.pem` verifies `ai-env-relay` and authenticates; the VM's client on
/// a spawn's session naming the private face, `10.42.0.20` and `state/relay-ca.der` lists the worker's source and
/// calls it; either client pinned to another CA, or asking for `relay.example.test`, fails its handshake.
#[test]
fn the_tls_value_m_writes_serves_both_faces() {
    let w = World::new();
    deployer(&w, &["tls", "init"]);
    deployer(&w, &["allow", "worker-a", "--key", &key_of(1).text(), "--sources", "example-*"]);
    deployer(&w, &["allow", "mac", "--token-signer", "--key", &key_of(7).text()]);
    deployer(&w, &["grant", "default", "example-*/get"]);
    let tls_name = tls_param();
    ai_env_relay::tls::server_config(value(&w, &tls_name).as_bytes()).expect("R's server config takes M's tls value");
    let live = tempfile::tempdir().unwrap();
    for (file, name) in [(TLS_FILE, tls_name.as_str()), (WORKERS_FILE, policy::WORKERS), (SIGNERS_FILE, policy::TOKEN_SIGNERS), (GRANTS_FILE, policy::GRANTS)] {
        fs::write(live.path().join(file), value(&w, name)).unwrap();
    }
    fs::write(live.path().join(FETCHED_FILE), format!("{}\n", unix_now())).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(serve_both_faces(&w, live.path()));
}

async fn serve_both_faces(w: &World, live: &Path) {
    let ca_pem = fs::read(w.bridge().join("state").join("relay-ca.pem")).unwrap();
    let ca_der = fs::read(w.bridge().join("state").join("relay-ca.der")).unwrap();
    let sink = Arc::new(MemorySink::default());
    let cfg = Config {
        relay_id: "ai-env-relay".into(),
        public_addr: "127.0.0.1:0".parse().unwrap(),
        private_addr: "127.0.0.1:0".parse().unwrap(),
        private_peers: vec!["127.0.0.0/8".parse().unwrap()],
        live_dir: live.to_path_buf(),
        request_log: live.join("requests.log"),
        // A Ping each second, so a worker's `check` hears the relay at once; no HTTP/2 keepalive (R's own tests').
        limits: Limits { h2_keepalive_s: 0, ping_interval_ms: 1000, ..Limits::default() },
    };
    let deps = Deps { clock: Arc::new(SystemClock), sink: sink.clone(), params_key: [9; 32], notifier: Notifier::disabled() };
    let app = RelayApp::new(cfg, deps).expect("a valid config");
    let running = tokio::spawn({
        let app = app.clone();
        async move { app.run().await }
    });
    let (public, private) = until("both faces bound", || app.bound()).await;
    let workers_version = content_version(value(w, policy::WORKERS).as_bytes());
    let status = app.snapshot();
    assert!(status.tls_loaded, "run loaded M's tls value");
    assert_eq!(status.workers_version, format!("{workers_version:016x}"), "run loaded M's workers");

    // W: a worker pinning state/relay-ca.pem, for ai-env-relay, on the public face: TLS, then its whitelisted key.
    let report = worker_a(public, &ca_pem, "ai-env-relay").check().await.expect("W verifies ai-env-relay under M's CA and authenticates");
    assert_eq!((report.relay_id.as_str(), report.sources, report.whitelist_version), ("ai-env-relay", 1, workers_version));
    until("the check's tunnel to end", || (app.snapshot().tunnels == 0).then_some(())).await;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(worker_a(public, &ca_pem, "ai-env-relay").run_until(async move {
        let _ = stopped.await;
    }));
    until("worker-a's tunnel and source", || {
        let s = app.snapshot();
        (s.tunnels == 1 && s.sources_live == 1).then_some(())
    })
    .await;

    // V: a spawn's session naming the private face, 10.42.0.20 and state/relay-ca.der (as M builds it, WM-R62).
    let ca_b64 = ca_der_b64(&w.paths()).expect("state/relay-ca.der");
    assert_eq!(base64::engine::general_purpose::STANDARD.decode(&ca_b64).unwrap(), ca_der);
    let token = session_token();
    let spawn = |ca_der_b64: &str, server_name: &str| RelaySpawn {
        token: Secret::new(token.clone()),
        addr: format!("127.0.0.1:{}", private.port()),
        server_name: server_name.to_string(),
        ca_der_b64: ca_der_b64.to_string(),
    };
    {
        let link = vm_link(&spawn(&ca_b64, VM_SERVER_NAME));
        let (sources, truncated) = link.catalog(None).await.expect("V verifies 10.42.0.20 under M's CA and lists the catalog");
        assert!(!truncated);
        assert_eq!(sources.iter().map(|s| (s.name.as_str(), s.available)).collect::<Vec<_>>(), [("example-alpha", true)]);
        let out = link.call("example-alpha", "get", &serde_json::json!({}), 65_536, 0, std::future::pending()).await.expect("a call across both faces");
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&out.data).unwrap(), serde_json::json!({"ok": true}));
    }

    // Another CA, or another name: neither client completes a handshake. The other CA is W's profile too, as another
    // `tls init --force` makes it: its subject is the same `CN=ai-env relay CA`, so the client builds the chain to it
    // by name and the leaf's signature fails (`BadSignature`; a CA of another name would be `UnknownIssuer`).
    let other = certs::relay_ca(unix_now()).expect("another CA");
    let tls_failure = |r: Result<CheckReport, WorkerError>| match r {
        Err(WorkerError::Tls(text)) => text,
        other => panic!("not a TLS failure: {other:?}"),
    };
    let text = tls_failure(worker_a(public, certs::pem("CERTIFICATE", &other.cert_der).as_bytes(), "ai-env-relay").check().await);
    assert!(text.contains("invalid peer certificate: BadSignature"), "W pinned to another CA: {text}");
    let text = tls_failure(worker_a(public, &ca_pem, "relay.example.test").check().await);
    assert!(text.contains("not valid for name"), "W asking for relay.example.test: {text}");
    let other_b64 = base64::engine::general_purpose::STANDARD.encode(&other.cert_der);
    let failure = vm_link(&spawn(&other_b64, VM_SERVER_NAME)).catalog(None).await.expect_err("V pinned to another CA");
    assert!(failure.code == Code::Unavailable && failure.message.contains("invalid peer certificate: BadSignature"), "{failure:?}");
    let failure = vm_link(&spawn(&ca_b64, "relay.example.test")).catalog(None).await.expect_err("V asking for relay.example.test");
    assert!(failure.code == Code::Unavailable && failure.message.contains("not valid for name"), "{failure:?}");
    // R saw each of the four handshakes fail, two on each face.
    let failed = |face: &str| {
        sink.lines()
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["ev"] == "peer" && v["face"] == face && v["reason"] == "tls_failed")
            .count()
    };
    until("the relay's two tls_failed lines on each face", || (failed("public") == 2 && failed("private") == 2).then_some(())).await;

    let _ = stop.send(());
    serving.await.unwrap().expect("the worker stops");
    app.shutdown();
    tokio::time::timeout(Duration::from_secs(10), running).await.expect("run stops").unwrap().expect("run ends cleanly");
}
