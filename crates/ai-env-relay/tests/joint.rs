//! WM-J2 `a_worker_behind_the_real_relay` (§WM-worker-mac.8.5, §R-relay.6.1 I-L2, §V-vm.6.1): the plan's
//! integration test, on tokio's paused clock.
//!
//! The relay runs in process through R's I-L2 API: `RelayApp::new` with a manual wall clock, a `MemorySink` and
//! `Notifier::disabled()`, one `poll_files` before any handshake, `serve_public` and `serve_private` on in-process
//! streams, `snapshot`, `shutdown`. Two of W's workers (the runtime, each source a `RecordingSource` over the
//! testkit's `EchoSource`) dial it through W's `Dial` seam over `tokio::io::duplex`, and a third runs W's `check` in
//! (b). W runs TLS 1.3 under the pinned CA on every stream it dials (WM-R11: there is no plaintext path), so the
//! relay's end of each dial goes through `RelayApp::admit`, the public face's own admission and TLS from the live
//! `tls.pem`, before `serve_public`. V's client joins the private face through `RelayLink::over`, its duplex end
//! served as `Peered::new(duplex_end, ip)`.
//!
//! Every key, token and certificate is built at run time from a seed (R's `tests/common`); every name is generic.

mod common;

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ai_env_relay::files::{Poll, FETCHED_FILE, TLS_FILE};
use ai_env_relay::lists::{Grant, GRANTS_FILE, SIGNERS_FILE, WORKERS_FILE};
use ai_env_relay::notify::Notifier;
use ai_env_relay::reqlog::MemorySink;
use ai_env_relay::{Config, Deps, Face, Limits, Peered, RelayApp, RelayError};
use ai_env_relay_client::dial::{CallOut, Failure, RelayLink};
use ai_env_relay_client::local::Code;
use ai_env_source::testkit::EchoSource;
use ai_env_source::wire::close;
use ai_env_source::{BoxFuture, CallContext, CallRequest, DataSource, Health, Output, Redactor, SourceDescriptor, SourceError};
use ai_env_worker::keys::SigningKey;
use ai_env_worker::session::{self, SessionClaims, SESSION_AUD};
use ai_env_worker::signer::FileSigner;
use ai_env_worker::{policy, Dial, Io, RelayEndpoint, Tuning, Worker, WorkerError};
use common::certs;
use common::clock::ManualClock;
use common::rig::{mac_signer, worker_entry, NOT_AFTER, RELAY_ID, T0, VM_ID, VM_IP};
use serde_json::json;
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};

/// The interleaved calls of (a).
const CALLS: usize = 1000;
/// V's links (one HTTP/2 connection each) and the sessions they carry. The private face allows a connection 16
/// streams at once (§Q.8 F1's `max_concurrent_streams(16)`), so 32 links keep up to 512 calls in flight together:
/// twice (a)'s floor of `CALLS / 4` (8 links would cap it at 128).
const LINKS: usize = 32;
const SESSIONS: u64 = 4;
/// Worker A serves two sources, worker B one; (a) cycles through them so each worker gets about half the calls.
const ROUTES: [(&str, &str); 4] = [("example.alpha", "worker-a"), ("example.beta", "worker-b"), ("example.alpha.logs", "worker-a"), ("example.beta", "worker-b")];
/// The workers' addresses on the public face (a documentation range).
const IP_A: &str = "198.51.100.10";
const IP_B: &str = "198.51.100.11";
const IP_C: &str = "198.51.100.12";

type PublicTx = mpsc::UnboundedSender<Result<Peered<TlsStream<DuplexStream>>, io::Error>>;
type PrivateTx = mpsc::UnboundedSender<Result<Peered<DuplexStream>, io::Error>>;

/// The relay in process, its live directory and its two faces' incoming streams.
struct Relay {
    app: RelayApp,
    sink: Arc<MemorySink>,
    dir: tempfile::TempDir,
    /// The run-time CA's certificate: W's only trust anchor.
    ca_pem: String,
    public: PublicTx,
    private: PrivateTx,
    servers: Vec<JoinHandle<Result<(), RelayError>>>,
}

/// The defaults with the HTTP/2 keepalive off (as R's rig) and room for a thousand calls in flight at once.
fn limits() -> Limits {
    Limits {
        h2_keepalive_s: 0,
        calls_in_flight_max: 2048,
        calls_per_tunnel: 1024,
        calls_per_session: 512,
        session_burst: 10_000,
        session_per_min: 60_000,
        tunnel_queue: 1024,
        ..Limits::default()
    }
}

/// Replaces a live file by one rename, as I's reload does.
fn write_live(dir: &Path, file: &str, bytes: &[u8]) {
    let tmp = dir.join(format!(".{file}.tmp"));
    std::fs::write(&tmp, bytes).unwrap();
    std::fs::rename(&tmp, dir.join(file)).unwrap();
}

/// The whitelist of these workers, rendered with W/M's `policy::render_workers`: A is seed 1 (`example.alpha*`),
/// B seed 2 (`example.beta*`), C seed 5 (`example.gamma*`).
fn write_workers(dir: &Path, ids: &[&str]) {
    let all = [
        worker_entry("worker-a", 1, &["example.alpha*"], NOT_AFTER),
        worker_entry("worker-b", 2, &["example.beta*"], NOT_AFTER),
        worker_entry("worker-c", 5, &["example.gamma*"], NOT_AFTER),
    ];
    let list: Vec<_> = all.into_iter().filter(|e| ids.contains(&e.worker_id.as_str())).collect();
    write_live(dir, WORKERS_FILE, policy::render_workers(&list).unwrap().as_bytes());
}

/// I-L2: the live directory written at run time, `RelayApp::new`, one poll, then both faces served.
async fn start() -> Relay {
    let dir = tempfile::tempdir().unwrap();
    let ca = certs::Ca::new("test relay CA", [11; 32]);
    let leaf = ca.leaf(1, &["ai-env-relay"], &[[10, 42, 0, 20]], [12; 32]);
    write_workers(dir.path(), &["worker-a", "worker-b", "worker-c"]);
    write_live(dir.path(), SIGNERS_FILE, policy::render_signers(&[mac_signer(NOT_AFTER)]).unwrap().as_bytes());
    let grants = [Grant { grant_id: "g-all".into(), allow: vec!["*/*".into()] }];
    write_live(dir.path(), GRANTS_FILE, policy::render_grants(&grants).unwrap().as_bytes());
    write_live(dir.path(), TLS_FILE, certs::tls_pem(&leaf, &ca).as_bytes());
    write_live(dir.path(), FETCHED_FILE, format!("{T0}\n").as_bytes());
    let cfg = Config {
        relay_id: RELAY_ID.into(),
        public_addr: "127.0.0.1:0".parse().unwrap(),
        private_addr: "127.0.0.1:0".parse().unwrap(),
        private_peers: vec!["10.42.1.0/24".parse().unwrap()],
        live_dir: dir.path().to_path_buf(),
        request_log: dir.path().join("requests.log"),
        limits: limits(),
    };
    let sink = Arc::new(MemorySink::default());
    let deps = Deps { clock: ManualClock::at(T0), sink: sink.clone(), params_key: [9; 32], notifier: Notifier::disabled() };
    let app = RelayApp::new(cfg, deps).expect("the config is valid");
    // R's I-L2 note: the in-process relay needs one poll before any handshake (the poll tick is `run`'s alone).
    for (file, outcome) in app.poll_files() {
        assert!(matches!(outcome, Poll::Loaded { .. }), "{file} is loaded by the first poll");
    }
    let (public, public_rx) = mpsc::unbounded_channel();
    let (private, private_rx) = mpsc::unbounded_channel();
    let servers = vec![
        tokio::spawn({
            let app = app.clone();
            async move { app.serve_public(UnboundedReceiverStream::new(public_rx)).await }
        }),
        tokio::spawn({
            let app = app.clone();
            async move { app.serve_private(UnboundedReceiverStream::new(private_rx)).await }
        }),
    ];
    Relay { app, sink, dir, ca_pem: certs::ca_pem(&ca), public, private, servers }
}

/// The request log's lines of one kind.
fn lines(sink: &MemorySink, ev: &str) -> Vec<serde_json::Value> {
    sink.lines().iter().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()).filter(|v| v["ev"] == ev).collect()
}

/// Waits on tokio's clock until `f` holds; fails after `within`.
async fn until(within: Duration, what: &str, f: impl Fn() -> bool) {
    let end = Instant::now() + within;
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// W's `Dial` seam: each dial is a new duplex whose relay end the public face admits (R-2's admission, then TLS
/// 1.3 from the live `tls.pem`) and serves; each dial's instant is kept.
struct DuplexDial {
    app: RelayApp,
    ip: IpAddr,
    public: PublicTx,
    dials: Arc<Mutex<Vec<Instant>>>,
}

impl Dial for DuplexDial {
    fn dial(&self) -> ai_env_worker::BoxFuture<'static, io::Result<Box<dyn Io>>> {
        self.dials.lock().unwrap().push(Instant::now());
        let (client, server) = tokio::io::duplex(1 << 20);
        let (app, ip, public) = (self.app.clone(), self.ip, self.public.clone());
        tokio::spawn(async move {
            if let Some(admitted) = app.admit(Face::Public, server, ip).await {
                let _ = public.send(Ok(admitted));
            }
        });
        Box::pin(std::future::ready(Ok(Box::new(client) as Box<dyn Io>)))
    }
}

/// Each source's recorder: the request ids of the calls W ran on it, by source name.
type Seen = Vec<(String, Arc<Mutex<Vec<String>>>)>;

/// A test double (P-R88 (d)): the `EchoSource` it wraps answers every call, and each call's request id is kept, so
/// the test sees which of a worker's sources W ran a call on.
struct RecordingSource {
    inner: EchoSource,
    seen: Arc<Mutex<Vec<String>>>,
}

impl DataSource for RecordingSource {
    fn descriptor(&self) -> SourceDescriptor {
        self.inner.descriptor()
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        self.seen.lock().unwrap().push(ctx.request_id.clone());
        self.inner.call(req, ctx)
    }

    fn health<'s, 'f>(&'s self) -> BoxFuture<'f, Health>
    where
        's: 'f,
        Self: 'f,
    {
        self.inner.health()
    }

    fn redactor(&self) -> Redactor {
        self.inner.redactor()
    }
}

/// One of W's workers, built: its dials and its sources' recorders.
struct Built {
    worker: Worker,
    dials: Arc<Mutex<Vec<Instant>>>,
    seen: Seen,
}

/// One of W's workers, running.
struct Running {
    dials: Arc<Mutex<Vec<Instant>>>,
    seen: Seen,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), WorkerError>>,
}

impl Running {
    fn dials(&self) -> Vec<Instant> {
        self.dials.lock().unwrap().clone()
    }
}

/// W's builder: the worker id, the relay under the run-time CA (`expect_relay_id` too), a `FileSigner` of the
/// seed's key, a `RecordingSource` over an `EchoSource` per name; the default `Tuning`.
fn build_worker(relay: &Relay, id: &str, seed: u8, ip: &str, sources: &[&str]) -> Built {
    let dials = Arc::new(Mutex::new(Vec::new()));
    let dial = DuplexDial { app: relay.app.clone(), ip: ip.parse().unwrap(), public: relay.public.clone(), dials: dials.clone() };
    let endpoint = RelayEndpoint::new("ai-env-relay:443")
        .unwrap()
        .ca_pem(relay.ca_pem.as_bytes())
        .expect("the CA's PEM")
        .expect_relay_id(RELAY_ID)
        .unwrap()
        .dialer(Arc::new(dial));
    let signer = FileSigner::from_key(SigningKey::from_seed(&[seed; 32]).unwrap());
    let mut builder = Worker::builder().worker_id(id).relay(endpoint).signer(Arc::new(signer)).max_in_flight(64).max_queued(1024);
    let mut seen = Seen::new();
    for name in sources {
        let recorder = Arc::new(Mutex::new(Vec::new()));
        builder = builder.source(Arc::new(RecordingSource { inner: EchoSource::named(*name), seen: recorder.clone() }));
        seen.push(((*name).to_owned(), recorder));
    }
    let worker = builder.build().expect("W's builder takes the worker");
    Built { worker, dials, seen }
}

/// A worker of `build_worker`, then `run_until` its stop.
fn spawn_worker(relay: &Relay, id: &str, seed: u8, ip: &str, sources: &[&str]) -> Running {
    let Built { worker, dials, seen } = build_worker(relay, id, seed, ip, sources);
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(worker.run_until(async move {
        let _ = stopped.await;
    }));
    Running { dials, seen, stop, task }
}

/// A new HTTP/2 connection to the private face from the VM subnet: its relay end is `Peered::new(duplex_end, ip)`.
async fn vm_channel(relay: &Relay) -> Channel {
    let (client, server) = tokio::io::duplex(1 << 20);
    relay.private.send(Ok(Peered::new(server, VM_IP.parse().unwrap()))).expect("the private face is served");
    let mut once = Some(client);
    Endpoint::from_static("http://10.42.0.20:7443")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let io = once.take();
            async move { io.map(hyper_util::rt::TokioIo::new).ok_or_else(|| io::Error::other("one connection per channel")) }
        }))
        .await
        .expect("the private face's duplex connects")
}

/// A session's claims under `kid`: grant `g-all`, issued at the relay's `T0` for an hour.
fn claims(kid: &str, session: u64) -> SessionClaims {
    SessionClaims {
        kid: kid.into(),
        aud: SESSION_AUD.into(),
        caller_id: "mac".into(),
        session_id: format!("0199a1b2-0000-7000-8000-{session:012x}"),
        chat_id: None,
        grant_id: "g-all".into(),
        vm_id: VM_ID.into(),
        iat: T0,
        exp: T0 + 3600,
    }
}

/// A token of these claims from W/M's `session::mint`, signed by a seed's key (`mac`, the whitelisted signer, is 7).
fn token(seed: u8, claims: &SessionClaims) -> String {
    session::mint(&SigningKey::from_seed(&[seed; 32]).unwrap(), claims, claims.iat).expect("W/M's mint")
}

/// One call of `EchoSource` through V's link.
async fn call(link: &RelayLink, source: &str, op: &str, params: &serde_json::Value) -> Result<CallOut, Failure> {
    link.call(source, op, params, 4096, 0, std::future::pending()).await
}

/// One `echo` through V's link, its text a nonce.
async fn echo(link: &RelayLink, source: &str, nonce: &str) -> Result<CallOut, Failure> {
    call(link, source, "echo", &json!({ "text": nonce })).await
}

/// Call `i` of (a): its op, its params and the one answer that is its own. An even call echoes a text naming it
/// (answered at once); an odd call sleeps a number of milliseconds no other call sleeps (`i * 389 mod 1000`, a
/// permutation) and answers that number, so the calls end in another order than they were made.
fn nth(i: usize, source: &str) -> (&'static str, serde_json::Value, serde_json::Value) {
    if i.is_multiple_of(2) {
        let nonce = format!("nonce-{i:04}-{source}");
        ("echo", json!({ "text": nonce }), json!({ "text": nonce }))
    } else {
        let ms = (i * 389) % 1000;
        ("sleep", json!({ "ms": ms }), json!({ "slept_ms": ms }))
    }
}

/// The answer is this call's own: exactly the JSON it expects, untruncated.
fn assert_answer(out: &CallOut, expected: &serde_json::Value, what: &str) {
    let body: serde_json::Value = serde_json::from_slice(&out.data).unwrap_or_else(|e| panic!("{what}: not JSON ({e})"));
    assert_eq!(&body, expected, "{what}: another call's answer");
    assert!(!out.truncated, "{what}: truncated");
}

/// The answer is the echo of exactly this nonce.
fn assert_own(out: &CallOut, nonce: &str, what: &str) {
    assert_answer(out, &json!({ "text": nonce }), what);
}

/// The source names V's catalog lists.
async fn listed(link: &RelayLink) -> Vec<String> {
    let (entries, truncated) = link.catalog(None).await.expect("the catalog");
    assert!(!truncated);
    entries.into_iter().map(|e| e.name).collect()
}

/// WM-J2.
#[tokio::test(start_paused = true)]
async fn a_worker_behind_the_real_relay() {
    let relay = start().await;
    let a = spawn_worker(&relay, "worker-a", 1, IP_A, &["example.alpha", "example.alpha.logs"]);
    let b = spawn_worker(&relay, "worker-b", 2, IP_B, &["example.beta"]);
    until(Duration::from_secs(10), "both tunnels and their three sources", || {
        let s = relay.app.snapshot();
        s.tunnels == 2 && s.sources_live == 3
    })
    .await;
    let auth: Vec<_> = lines(&relay.sink, "tunnel").into_iter().filter(|l| l["phase"] == "auth" && l["outcome"] == "ok").collect();
    let mut authed: Vec<&str> = auth.iter().map(|l| l["worker"].as_str().unwrap()).collect();
    authed.sort_unstable();
    assert_eq!(authed, ["worker-a", "worker-b"], "W's handshake, each worker once");
    assert!(auth.iter().all(|l| l["sdk"] == ai_env_worker::SDK_VERSION), "W's Hello: {auth:?}");

    // (a) A thousand interleaved calls over both workers' sources, all in flight together: each answer is its own.
    let tokens: Vec<String> = (1..=SESSIONS).map(|n| token(7, &claims("mac", n))).collect();
    let mut links = Vec::new();
    for i in 0..LINKS {
        links.push(Arc::new(RelayLink::over(vm_channel(&relay).await, &tokens[i % tokens.len()]).expect("a link over the duplex")));
    }
    assert_eq!(listed(&links[0]).await, ["example.alpha", "example.alpha.logs", "example.beta"]);
    let running = Arc::new(AtomicBool::new(true));
    let peak = Arc::new(AtomicU64::new(0));
    // Samples the calls in flight each virtual millisecond (a sleep, not a yield: the paused clock must advance).
    let sampler = tokio::spawn({
        let (app, running, peak) = (relay.app.clone(), running.clone(), peak.clone());
        async move {
            while running.load(Ordering::SeqCst) {
                peak.fetch_max(app.snapshot().calls_in_flight, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    });
    let mut calls = Vec::with_capacity(CALLS);
    for i in 0..CALLS {
        let link = links[i % LINKS].clone();
        let (source, worker) = ROUTES[(i / LINKS) % ROUTES.len()];
        calls.push(tokio::spawn(async move {
            let (op, params, expected) = nth(i, source);
            let out = call(&link, source, op, &params).await;
            (i, source, worker, expected, out)
        }));
    }
    let mut routed: BTreeMap<String, (&str, &str)> = BTreeMap::new();
    for task in calls {
        let (i, source, worker, expected, out) = task.await.expect("a call's task");
        let out = out.unwrap_or_else(|f| panic!("call {i} to {source}: {f:?}"));
        assert_answer(&out, &expected, &format!("call {i} to {source}"));
        assert!(routed.insert(out.request_id.clone(), (source, worker)).is_none(), "request id {} twice", out.request_id);
    }
    running.store(false, Ordering::SeqCst);
    sampler.await.unwrap();
    assert_eq!(routed.len(), CALLS);
    let peak = peak.load(Ordering::SeqCst);
    assert!(peak >= CALLS as u64 / 4, "the calls were in flight at the relay together (peak {peak})");
    // W ran each call on the source it was routed to: each request id is in that source's recorder and no other.
    let mut ran: BTreeMap<String, String> = BTreeMap::new();
    for (source, seen) in a.seen.iter().chain(&b.seen) {
        for id in seen.lock().unwrap().iter() {
            assert!(ran.insert(id.clone(), source.clone()).is_none(), "request id {id} ran twice");
        }
    }
    assert_eq!(ran.len(), CALLS, "W ran each call once");
    for (id, (source, _)) in &routed {
        assert_eq!(ran.get(id).map(String::as_str), Some(*source), "request id {id} ran on its own source");
    }
    until(Duration::from_secs(10), "every call's line", || lines(&relay.sink, "call").len() == CALLS).await;
    for line in lines(&relay.sink, "call") {
        let id = line["request_id"].as_str().unwrap();
        let (source, worker) = routed.get(id).unwrap_or_else(|| panic!("a call line of no call: {line}"));
        assert_eq!((line["source"].as_str(), line["worker"].as_str(), line["outcome"].as_str()), (Some(*source), Some(*worker), Some("ok")), "{line}");
    }
    let s = relay.app.snapshot();
    assert_eq!((s.tunnels, s.calls_in_flight), (2, 0));
    assert_eq!((a.dials().len(), b.dials().len()), (1, 1), "no tunnel was lost on the way");

    // (b) A revoke: worker-a leaves the whitelist while its tunnel is live, and so does worker-c, whose W `check`
    // (WM-R33) hands the test the Close a worker receives; worker-b keeps serving. The revoke comes well inside
    // check's 3 s wait, and the relay's first Ping is 15 s away.
    let worker_c = build_worker(&relay, "worker-c", 5, IP_C, &["example.gamma"]).worker;
    let check = tokio::spawn(async move { worker_c.check().await });
    until(Duration::from_secs(2), "worker-c's tunnel and its source", || {
        let s = relay.app.snapshot();
        s.tunnels == 3 && s.sources_live == 4
    })
    .await;
    let revoked_at = Instant::now();
    write_workers(relay.dir.path(), &["worker-b"]);
    let polled = relay.app.poll_files();
    assert!(polled.iter().any(|(file, outcome)| *file == "workers" && matches!(outcome, Poll::Loaded { .. })), "the new whitelist is loaded");
    let closes = || lines(&relay.sink, "tunnel").into_iter().filter(|l| l["phase"] == "close").collect::<Vec<_>>();
    until(Duration::from_secs(5), "the revoked tunnels closed", || relay.app.snapshot().tunnels == 1 && closes().len() >= 2).await;
    let closes = closes();
    let mut closed: Vec<(&str, &str)> = closes.iter().map(|l| (l["worker"].as_str().unwrap_or_default(), l["reason"].as_str().unwrap_or_default())).collect();
    closed.sort_unstable();
    assert_eq!(closed, [("worker-a", "revoked"), ("worker-c", "revoked")], "the relay's close lines: {closes:?}");
    // What W received: the Close's own code and reason. W's refusal floor below cannot tell REVOKED from
    // SUPERSEDED, PROTOCOL or CATALOG_REFUSED (WM-R15), and the relay's close line reads the Close it stored.
    let checked = tokio::time::timeout(Duration::from_secs(5), check).await.expect("check ends").expect("check's task");
    assert!(matches!(&checked, Err(WorkerError::Refused { code: close::REVOKED, reason }) if reason == "revoked"), "worker-c's check: {checked:?}");
    assert_eq!(listed(&links[1]).await, ["example.beta"], "worker-a's and worker-c's sources are gone, not offline");
    let gone = echo(&links[2], "example.alpha", "nonce-gone").await.expect_err("worker-a's source is gone");
    assert_eq!((gone.code, gone.message.as_str()), (Code::NotFound, "no such source"));
    let mut beta = Vec::new();
    for i in 0..100 {
        let link = links[i % LINKS].clone();
        beta.push(tokio::spawn(async move {
            let nonce = format!("nonce-beta-{i:03}");
            (echo(&link, "example.beta", &nonce).await, nonce)
        }));
    }
    for call in beta {
        let (out, nonce) = call.await.unwrap();
        assert_own(&out.expect("worker-b still serves"), &nonce, &nonce);
    }
    // W takes REVOKED as a refusal: its next dial waits the refused floor, never the transient backoff.
    let floor = Tuning::default().refused_floor;
    until(floor + Duration::from_secs(10), "worker-a's next dial", || a.dials().len() >= 2).await;
    let gap = a.dials()[1] - revoked_at;
    assert!(gap >= floor && gap < floor + Duration::from_secs(1), "worker-a dialed again {gap:?} after the revoke (floor {floor:?})");
    until(Duration::from_secs(10), "the refused handshake's line", || {
        lines(&relay.sink, "tunnel").iter().any(|l| l["phase"] == "auth" && l["worker"] == "worker-a" && l["reason"] == "unknown_worker")
    })
    .await;
    until(floor + Duration::from_secs(10), "worker-a's third dial", || a.dials().len() >= 3).await;
    let dials = a.dials();
    assert!(dials[2] - dials[1] >= floor, "the refused handshake waits the floor too: {:?}", dials[2] - dials[1]);
    assert_eq!((relay.app.snapshot().tunnels, b.dials().len()), (1, 1), "worker-b's one tunnel lived through it");
    let out = echo(&links[3], "example.beta", "nonce-beta-after").await.expect("worker-b still serves");
    assert_own(&out, "nonce-beta-after", "after the floor");

    // (c) A token of the whitelisted signer is accepted; one of an unknown signer, or of mac's id under another
    // key, is refused before any routing.
    let ok = || lines(&relay.sink, "call").iter().filter(|l| l["outcome"] == "ok").count();
    let ok_before = ok();
    let accepted = RelayLink::over(vm_channel(&relay).await, &token(7, &claims("mac", 100))).unwrap();
    assert_eq!(listed(&accepted).await, ["example.beta"]);
    assert_own(&echo(&accepted, "example.beta", "nonce-accepted").await.expect("accepted"), "nonce-accepted", "accepted");
    until(Duration::from_secs(5), "the accepted call's line", || ok() == ok_before + 1).await;
    for (what, refused) in [("an unknown signer", token(4, &claims("stranger", 101))), ("mac's id under another key", token(4, &claims("mac", 102)))] {
        let link = RelayLink::over(vm_channel(&relay).await, &refused).unwrap();
        let listing = link.catalog(None).await.expect_err(what);
        assert_eq!((listing.code, listing.message.as_str()), (Code::Unauthenticated, "authentication failed"), "{what}");
        let called = echo(&link, "example.beta", "nonce-refused").await.expect_err(what);
        assert_eq!((called.code, called.message.as_str()), (Code::Unauthenticated, "authentication failed"), "{what}");
    }
    assert_eq!(ok(), ok_before + 1, "only the accepted token's call reached a worker");

    // The end: each worker's `run_until` returns within W's 2 s of its stop (WM-R32), short of the 2 s shutdown
    // budget whose end would mean its tunnel did not end; then the relay.
    drop((links, accepted));
    for w in [a, b] {
        let asked = Instant::now();
        let _ = w.stop.send(());
        tokio::time::timeout(Duration::from_secs(5), w.task).await.expect("the worker stops").expect("its task").expect("run_until is Ok");
        let took = asked.elapsed();
        assert!(took < Duration::from_secs(2), "run_until returned {took:?} after its stop (WM-R32: within 2 s)");
    }
    until(Duration::from_secs(5), "no tunnel", || relay.app.snapshot().tunnels == 0).await;
    relay.app.shutdown();
    for server in relay.servers {
        tokio::time::timeout(Duration::from_secs(10), server).await.expect("the face stops").expect("its task").expect("it served");
    }
}
