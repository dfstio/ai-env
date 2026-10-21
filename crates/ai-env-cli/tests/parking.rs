//! S10 §D: an idle remote session parks, against the in-process shim (its
//! real `park_v1`) behind the tests' fake endpoint playing the platform (its
//! auto-run, its hooks, its auto-resume), over the file-backed fake API: the
//! unpark on the open socket, the redial at the next input after the shim
//! closed the parked socket, a suspend while parked and the resume the next
//! input brings (by the endpoint's auto-resume, or one ResumeMicrovm), a
//! close while parked with no socket (nothing dialed; its claude stays
//! parked under its owner), and `agent::stop_spawn` ending that claude (the
//! reaper's tool). The session is driven directly with a park control the
//! test builds (the pipeline's use of `run_spawn_parked` is the continuity
//! engine's); the scripted shim's cases are `agent/session.rs`' (the golden,
//! the frames a parked session never sends, the refusals, the probe).
//! Never AWS, never the developer's claude: the spawn is `cat`. Every wait
//! is bounded.

mod common;

use ai_env_cli::bridge::agent::{run_spawn_parked, spawn_channels, stop_spawn, AgentEnv, AgentTarget, ConsumerIo, ParkReport, RemoteExit, RunPolicy, SpawnEvent, SpawnInput, SpawnOutcome, SpawnSpec, Start};
use ai_env_cli::bridge::api::{Call, FakeMicrovmApi, FakeState, IdleSpec, MicrovmApi, RunSpec, VmInfo, VmState, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::codeout::{CodeoutCtx, CodeoutTrigger};
use ai_env_cli::bridge::config::{BridgeConfig, Keepalive, Paths, Rotation};
use ai_env_cli::bridge::dataplane::{HttpsEndpoint, MintingTokens};
use ai_env_cli::bridge::lab::VmKnobs;
use ai_env_cli::bridge::park::{ParkCtl, ParkPolicy, QuietState, Verdict};
use ai_env_cli::bridge::transport::AgentDial;
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use ai_env_cli::bridge::workspace::{Head, WorkspaceRef, WsKind};
use ai_env_cli::shim::health::{ProbeSpec, ShimOpts, ShimState};
use ai_env_cli::shim::peer::Peer;
use ai_env_cli::shim::sys::RealSys;
use ai_env_cli::wire::frame::{ParkOwner, RunHookPayload, SpawnDetail, SpawnId, CLOSE_GOING_AWAY};
use ai_env_cli::wire::redact::Secret;
use common::fake_endpoint::FakeEndpoint;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

/// Every wait of these tests.
const LIMIT: Duration = Duration::from_secs(30);

/// The wrapper every `park` names here (a pid and a start; the shim reports it back).
const OWNER: ParkOwner = ParkOwner { pid: 51_234, started: 1_792_483_200 };

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

async fn bounded<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(60), f).await.expect("the test ran past its limit")
}

/// One in-process shim (its app and hooks routers on loopback), the fake
/// endpoint in front of it playing the platform, and one VM of the
/// file-backed fake whose `/run` payload commits to `token`.
struct World {
    api: FileFakeMicrovmApi,
    vm: VmInfo,
    token: String,
    shim: Arc<ShimState>,
    endpoint: FakeEndpoint,
    paths: Paths,
    _tmp: tempfile::TempDir,
}

async fn serve(router: axum::Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router.into_make_service_with_connect_info::<Peer>()).await.unwrap() });
    addr
}

/// A world whose VM auto-resumes (`auto_resume`) or does not.
async fn world(auto_resume: bool) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    std::fs::create_dir_all(root.join("home")).unwrap();
    let fake = root.join("fake.json");
    std::fs::write(&fake, serde_json::to_string_pretty(&FakeState { auto_advance: true, ..FakeState::new() }).unwrap()).unwrap();
    let api = FileFakeMicrovmApi::open(&fake).unwrap();
    // SAFETY: getuid and getgid cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let opts = ShimOpts { home: root.join("home"), uid, gid, ..ShimOpts::default() };
    let shim = Arc::new(ShimState::with(PathBuf::from("/nonexistent/claude"), opts, ProbeSpec::default(), Arc::new(RealSys)));
    shim.set_bound();
    let hooks = serve(ai_env_cli::shim::hooks::router(shim.clone())).await;
    let app = serve(ai_env_cli::shim::health::router(shim.clone())).await;
    let endpoint = FakeEndpoint::start_platform(&fake, app, hooks);
    // Built at run time: never a credential-looking literal.
    let token = format!("park-session-{}", "t".repeat(24));
    let payload = RunHookPayload::new(&Secret::new(token.clone()), "mike@mbp", "2026-10-20T08:00:00Z").to_json().unwrap();
    let spec = RunSpec {
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        execution_role_arn: None,
        ingress_connectors: vec![],
        egress_connectors: vec![],
        idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume },
        max_duration_s: 900,
        run_hook_payload: payload,
        client_token: uuid::Uuid::now_v7().to_string(),
    };
    let vm = api.run(&spec).await.unwrap();
    let paths = Paths::from_root_and_env(root.join("bridge"), None);
    World { api, vm, token, shim, endpoint, paths, _tmp: tmp }
}

/// Small timers, pings and keep-alives off (the scripted shim's tests count those).
fn policy() -> RunPolicy {
    RunPolicy {
        ping: Duration::from_secs(3600),
        ws_ping: Duration::from_secs(3600),
        dead_after: Duration::from_secs(5),
        ack_bytes: ai_env_cli::wire::frame::ACK_EVERY_BYTES,
        ack_every: ms(10),
        rotation: Rotation::Lazy,
        keepalive: Keepalive::Frames,
        keepalive_every: Duration::from_secs(3600),
        suspend_wait: ms(200),
        backoff_min: ms(10),
        backoff_max: ms(100),
        stable_after: Duration::from_secs(1),
        reconnect_budget: Duration::from_secs(10),
        not_run_budget: Duration::from_secs(2),
        token_minutes: 60,
        remint_below: Duration::from_secs(60),
        rotate_before: Duration::from_secs(120),
        idle_s: Some(90),
    }
}

/// The park's terms: a quiet of 200 ms, a window of 0 (the turn's stdio a
/// moment ago is no refusal here), a 500 ms probe, a 2 s answer wait.
fn terms() -> ParkPolicy {
    ParkPolicy { after: ms(200), grace_s: 600, min_quiet_s: 0, cpu_busy_ms: 500, hold_output: false, probe: ms(500), answer_wait: Duration::from_secs(2) }
}

impl World {
    fn env(&self) -> AgentEnv<'_, FileFakeMicrovmApi, FileFakeMicrovmApi> {
        AgentEnv {
            api: &self.api,
            ep: &self.api,
            paths: &self.paths,
            target: AgentTarget { vm_id: self.vm.id.clone(), endpoint: self.vm.endpoint.clone(), session_token: Secret::new(self.token.clone()), vpc: false, shell: false },
            policy: policy(),
            dial: AgentDial { local: Some(self.endpoint.addr) },
        }
    }

    fn calls(&self, f: impl Fn(&Call) -> bool) -> usize {
        self.api.snapshot().unwrap().calls.iter().filter(|c| f(c)).count()
    }

    fn state(&self) -> VmState {
        self.api.snapshot().unwrap().vms[&self.vm.id].state.clone()
    }

    /// The shim's spawns, as `/health/detail` reports them.
    fn spawns(&self) -> Vec<SpawnDetail> {
        self.shim.spawns.detail()
    }

    fn audit(&self, event: &str) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(self.paths.audit()).unwrap_or_default();
        text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).collect()
    }

    /// The shim's spawns ended (each test's last step; a test that failed
    /// leaves its `cat` to the end of the process, which closes its stdin).
    async fn finish(&self) {
        let _ = tokio::time::timeout(Duration::from_secs(6), self.shim.spawns.shutdown("test")).await;
    }

    /// The pump's side of a parking control (its quiet), and the control, idle since now.
    fn park_ctl(&self) -> (ParkCtl, Pump) {
        let (tx, rx) = watch::channel(QuietState { verdict: Verdict::Idle, since: tokio::time::Instant::now(), last_host: None });
        let ws = WorkspaceRef {
            cwd: "/nonexistent/park".into(),
            root: "/nonexistent/park".into(),
            vm_cwd: "/nonexistent/park".into(),
            vm_root: "/nonexistent/park".into(),
            slug: "-nonexistent-park".into(),
            kind: WsKind::Git { git_dir: "/nonexistent/park/.git".into(), common_dir: "/nonexistent/park/.git".into(), object_format: ai_env_cli::wire::workspace::ObjectFormat::Sha1 },
            head: Head::Detached { sha: "a".repeat(40) },
            seed_branch: None,
        };
        // Its fetch never runs here: a trigger nobody asks is quiet.
        let unused = Arc::new(FakeMicrovmApi::new());
        let target = AgentTarget { vm_id: self.vm.id.clone(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: false, shell: false };
        let trigger = CodeoutTrigger::spawn(CodeoutCtx {
            api: unused.clone(),
            dp: Arc::new(HttpsEndpoint::new(&VmKnobs::default()).unwrap()),
            tokens: Arc::new(MintingTokens::new(unused, &self.paths, &self.vm.id, false)),
            paths: self.paths.clone(),
            cfg: Arc::new(BridgeConfig::default()),
            target,
            ws,
            capture_settings: false,
            transcript: None,
        });
        (ParkCtl { quiet: rx, trigger: trigger.watch(), policy: terms(), owner: OWNER }, Pump { quiet: tx, _trigger: trigger })
    }
}

/// The test's side of the pump: what it last forwarded.
struct Pump {
    quiet: watch::Sender<QuietState>,
    _trigger: CodeoutTrigger,
}

impl Pump {
    /// The pump forwarded a line: `verdict` from now on, `last_host` the last host frame's kind.
    fn line(&self, verdict: Verdict, last_host: Option<&'static str>) {
        self.quiet.send_replace(QuietState { verdict, since: tokio::time::Instant::now(), last_host });
    }
}

/// `cat`, under a name the test picks (the reaper's `stop_spawn` names it).
fn cat(id: &SpawnId) -> SpawnSpec {
    SpawnSpec { argv: vec!["cat".into()], cwd: None, env: BTreeMap::new(), detach_grace_s: Some(60), id: Some(id.clone()) }
}

/// What the session told its consumer, as it came.
#[derive(Debug, Default)]
struct Told {
    stdout: Vec<u8>,
    notes: Vec<String>,
    links: Vec<bool>,
    parks: Vec<ParkReport>,
    exit: Option<RemoteExit>,
}

impl Told {
    /// The parks reported so far.
    fn parked(&self) -> usize {
        self.parks.iter().filter(|r| matches!(r, ParkReport::Parked { .. })).count()
    }
}

/// Every event into `told` until the session ends, stdout marked consumed as it comes.
async fn consume_into(c: &mut ConsumerIo, told: &Mutex<Told>) {
    while let Some(ev) = c.events.recv().await {
        let mut t = told.lock().unwrap();
        match ev {
            SpawnEvent::Stdout { seq, bytes } => {
                t.stdout.extend(bytes);
                c.consumed.stdout_done(seq);
            }
            SpawnEvent::Stderr { seq, .. } => c.consumed.stderr_done(seq),
            SpawnEvent::Note(n) => t.notes.push(n),
            SpawnEvent::Link(up) => t.links.push(up),
            SpawnEvent::Park(r) => t.parks.push(r),
            SpawnEvent::Exit(e) => t.exit = Some(e),
            SpawnEvent::Started { .. } => {}
        }
    }
}

/// Until `f` holds of what the consumer was told (within `LIMIT`).
async fn until(told: &Mutex<Told>, what: &str, f: impl Fn(&Told) -> bool) {
    let deadline = Instant::now() + LIMIT;
    while !f(&told.lock().unwrap()) {
        assert!(Instant::now() < deadline, "{what}: {:?}", told.lock().unwrap());
        tokio::time::sleep(ms(5)).await;
    }
}

/// Until `f` holds (within `LIMIT`).
async fn until_true(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + LIMIT;
    while !f() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(ms(5)).await;
    }
}

/// The host's line `text`: the pump's last host frame a `user` line, sent to the session.
async fn type_line(input: &mpsc::Sender<SpawnInput>, pump: &Pump, text: &str) {
    pump.line(Verdict::Busy, Some("user"));
    input.send(SpawnInput::Stdin(text.as_bytes().to_vec())).await.unwrap();
}

/// Parked on the shim: the session said so, and the shim names its owner.
async fn parked_on_the_shim(w: &World, told: &Mutex<Told>, n: usize) {
    until(told, "parked", |t| t.parked() == n).await;
    let d = w.spawns();
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!((d[0].parked, d[0].status.alive), (Some(OWNER), true), "the shim parked it under its owner: {d:?}");
}

/// A park report's words, for the assertions.
fn words(parks: &[ParkReport]) -> Vec<String> {
    parks
        .iter()
        .map(|r| match r {
            ParkReport::Parked { why, .. } => format!("parked:{why}"),
            ParkReport::Refused { reason } => format!("refused:{reason}"),
            ParkReport::Unparked { by, vm_state, .. } => format!("unparked:{by}:{vm_state}"),
            ParkReport::Off { why } => format!("off:{why}"),
        })
        .collect()
}

/// Parked with its socket open, the host's next line unparks it on that
/// socket: the shim has it again (unparked, by the `unpark`), the line is
/// echoed, and nothing was dialed; the EOF then ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unparks_on_the_open_socket_with_no_new_dial() {
    bounded(async {
        let w = world(true).await;
        let env = w.env();
        let (ctl, pump) = w.park_ctl();
        let (sio, mut cio) = spawn_channels(8);
        let input = cio.input.clone();
        let told = Mutex::new(Told::default());
        let id = SpawnId::new_v7();
        let driver = async {
            type_line(&input, &pump, "hello\n").await;
            until(&told, "the first echo", |t| t.stdout == b"hello\n").await;
            pump.line(Verdict::Idle, Some("user"));
            parked_on_the_shim(&w, &told, 1).await;
            let dials = w.endpoint.attempts().len();
            type_line(&input, &pump, "again\n").await;
            until(&told, "the unparked echo", |t| t.stdout == b"hello\nagain\n").await;
            assert_eq!(w.spawns()[0].parked, None, "unparked on the shim");
            assert_eq!(w.endpoint.attempts().len(), dials, "no new dial");
            input.send(SpawnInput::StdinEof).await.unwrap();
        };
        let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat(&id)), sio, None, ctl), consume_into(&mut cio, &told), driver);
        let out = result.unwrap();
        assert_eq!((out.exit.status(), out.parked_close), (0, false));
        {
            let t = told.lock().unwrap();
            assert_eq!(words(&t.parks), ["parked:idle", "unparked:user:running"]);
            assert!(t.links.is_empty(), "{:?}", t.links);
        }
        assert_eq!(w.audit("session_unpark")[0]["detail"]["by"], "user");
        w.finish().await;
    })
    .await;
}

/// The shim closes the parked socket (no suspend): the spawn stays parked
/// on the shim, under its park grace, and the session dials nothing until
/// the host's next line; that line redials, the `hello` resumes the spawn
/// (unparking it), and the line goes out on the new socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redials_after_the_shim_closes_the_parked_socket() {
    bounded(async {
        let w = world(true).await;
        let env = w.env();
        let (ctl, pump) = w.park_ctl();
        let (sio, mut cio) = spawn_channels(8);
        let input = cio.input.clone();
        let told = Mutex::new(Told::default());
        let id = SpawnId::new_v7();
        let driver = async {
            type_line(&input, &pump, "hello\n").await;
            until(&told, "the first echo", |t| t.stdout == b"hello\n").await;
            pump.line(Verdict::Idle, Some("user"));
            parked_on_the_shim(&w, &told, 1).await;
            let dials = w.endpoint.attempts().len();
            w.shim.agents.close_all(CLOSE_GOING_AWAY, "test").await;
            until(&told, "parked with no socket", |t| t.notes.iter().any(|n| n.contains("stays parked until the next input"))).await;
            tokio::time::sleep(ms(300)).await;
            assert_eq!(w.endpoint.attempts().len(), dials, "nothing dialed while no input came");
            let d = w.spawns();
            assert!(d[0].parked == Some(OWNER) && d[0].detach_left_s.is_some_and(|left| left > 500), "its park grace, not the detach grace: {d:?}");
            type_line(&input, &pump, "again\n").await;
            until(&told, "the echo over the redial", |t| t.stdout == b"hello\nagain\n").await;
            assert_eq!(w.endpoint.attempts().len(), dials + 1, "one redial");
            assert_eq!(w.spawns()[0].parked, None, "the resuming hello unparked it");
            input.send(SpawnInput::StdinEof).await.unwrap();
        };
        let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat(&id)), sio, None, ctl), consume_into(&mut cio, &told), driver);
        assert_eq!(result.unwrap().exit.status(), 0);
        {
            let t = told.lock().unwrap();
            assert_eq!(words(&t.parks), ["parked:idle", "unparked:user:running"]);
            assert!(t.links.is_empty(), "a parked socket's end is no lost link: {:?}", t.links);
        }
        w.finish().await;
    })
    .await;
}

/// S10's wrapper twin of `hook_suspend_gives_up_after_suspend_wait_naming_resume_and_attach`:
/// parked, the VM is suspended (the platform's `/suspend` closes the socket
/// with `hook_suspend`); past `suspend_wait` the session has neither ended
/// (no exit 8) nor dialed nor asked GetMicrovm; the host's next line asks
/// GetMicrovm once and dials, the endpoint's auto-resume wakes the VM (one
/// ResumeMicrovm for a VM without it), the `hello` resumes the spawn, and
/// the line is echoed (`vm_state` `suspended`). No Touch ID: nothing is
/// unsealed, and claude keeps what it had.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hook_suspend_while_parked_waits_for_input_then_resumes() {
    for auto_resume in [true, false] {
        bounded(async {
            let w = world(auto_resume).await;
            let env = w.env();
            let (ctl, pump) = w.park_ctl();
            let (sio, mut cio) = spawn_channels(8);
            let input = cio.input.clone();
            let told = Mutex::new(Told::default());
            let id = SpawnId::new_v7();
            let driver = async {
                type_line(&input, &pump, "hello\n").await;
                until(&told, "the first echo", |t| t.stdout == b"hello\n").await;
                pump.line(Verdict::Idle, Some("user"));
                parked_on_the_shim(&w, &told, 1).await;
                w.api.suspend(&w.vm.id).await.unwrap();
                until(&told, "parked with no socket", |t| t.notes.iter().any(|n| n.contains("was suspended: spawn"))).await;
                let (dials, gets) = (w.endpoint.attempts().len(), w.calls(|c| matches!(c, Call::Get(_))));
                tokio::time::sleep(ms(600)).await;
                assert_eq!(w.state(), VmState::Suspended);
                assert_eq!((w.endpoint.attempts().len(), w.calls(|c| matches!(c, Call::Get(_)))), (dials, gets), "no dial and no GetMicrovm past suspend_wait (auto_resume {auto_resume})");
                assert!(told.lock().unwrap().exit.is_none(), "no exit 8");
                type_line(&input, &pump, "again\n").await;
                until(&told, "the echo after the resume", |t| t.stdout == b"hello\nagain\n").await;
                assert_eq!(w.state(), VmState::Running);
                input.send(SpawnInput::StdinEof).await.unwrap();
            };
            let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat(&id)), sio, None, ctl), consume_into(&mut cio, &told), driver);
            assert_eq!(result.unwrap().exit.status(), 0, "auto_resume {auto_resume}");
            {
                let t = told.lock().unwrap();
                assert_eq!(words(&t.parks), ["parked:idle", "unparked:user:suspended"], "auto_resume {auto_resume}");
                assert!(t.links.is_empty(), "{:?}", t.links);
            }
            assert_eq!(w.calls(|c| matches!(c, Call::Resume(_))), usize::from(!auto_resume), "one ResumeMicrovm without auto-resume, none with it");
            w.finish().await;
        })
        .await;
    }
}

/// A close (the host's EOF) while parked with no socket ends the session at
/// once with `parked_close` and exit 0, having dialed nothing, asked no
/// GetMicrovm and resumed nothing, however the socket went: the VM
/// suspended under it (`hook_suspend`), or the shim closing it while the VM
/// runs. Its claude stays on the VM, parked under its owner (frozen with a
/// suspended VM), for the next start there to reap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eof_while_parked_with_no_socket_dials_nothing() {
    for suspended in [true, false] {
        bounded(async {
            let w = world(true).await;
            let env = w.env();
            let (ctl, pump) = w.park_ctl();
            let (sio, mut cio) = spawn_channels(8);
            let input = cio.input.clone();
            let told = Mutex::new(Told::default());
            let id = SpawnId::new_v7();
            let closed_at = Mutex::new(None);
            let driver = async {
                type_line(&input, &pump, "hello\n").await;
                until(&told, "the first echo", |t| t.stdout == b"hello\n").await;
                pump.line(Verdict::Idle, Some("user"));
                parked_on_the_shim(&w, &told, 1).await;
                if suspended {
                    w.api.suspend(&w.vm.id).await.unwrap();
                } else {
                    w.shim.agents.close_all(CLOSE_GOING_AWAY, "test").await;
                }
                until(&told, "parked with no socket", |t| t.notes.iter().any(|n| n.contains("stays parked until the next input"))).await;
                *closed_at.lock().unwrap() = Some((Instant::now(), w.api.snapshot().unwrap().calls.len(), w.endpoint.attempts().len()));
                input.send(SpawnInput::StdinEof).await.unwrap();
            };
            let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat(&id)), sio, None, ctl), consume_into(&mut cio, &told), driver);
            let (at, calls, dials) = closed_at.lock().unwrap().expect("closed");
            let out: SpawnOutcome = result.unwrap();
            assert!(at.elapsed() < Duration::from_secs(2), "at once: {:?} (suspended {suspended})", at.elapsed());
            assert_eq!((out.exit.status(), out.parked_close, out.spawn_id.clone()), (0, true, id.clone()), "suspended {suspended}");
            assert_eq!(w.endpoint.attempts().len(), dials, "no dial (suspended {suspended})");
            assert_eq!(w.api.snapshot().unwrap().calls.len(), calls, "no API call: no GetMicrovm, no ResumeMicrovm, no mint (suspended {suspended})");
            assert_eq!(w.state(), if suspended { VmState::Suspended } else { VmState::Running });
            let d = w.spawns();
            assert!(d.len() == 1 && d[0].parked == Some(OWNER) && d[0].status.alive && d[0].frozen == suspended, "its claude stays parked under its owner: {d:?}");
            assert!(told.lock().unwrap().notes.iter().any(|n| n.starts_with("closed while parked")), "{:?}", told.lock().unwrap().notes);
            w.finish().await;
        })
        .await;
    }
}

/// The reaper's tool on the claude a parked close left: `stop_spawn`
/// dials (the endpoint's auto-resume wakes the VM), resumes the spawn
/// (unparking it), sends TERM and takes its exit: the shim holds no spawn
/// after it. Asked again, the spawn is gone already: `true` too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_spawn_ends_a_claude_a_parked_close_left() {
    bounded(async {
        let w = world(true).await;
        let env = w.env();
        let (ctl, pump) = w.park_ctl();
        let (sio, mut cio) = spawn_channels(8);
        let input = cio.input.clone();
        let told = Mutex::new(Told::default());
        let id = SpawnId::new_v7();
        let driver = async {
            type_line(&input, &pump, "hello\n").await;
            until(&told, "the first echo", |t| t.stdout == b"hello\n").await;
            pump.line(Verdict::Idle, Some("user"));
            parked_on_the_shim(&w, &told, 1).await;
            w.api.suspend(&w.vm.id).await.unwrap();
            until(&told, "parked with no socket", |t| t.notes.iter().any(|n| n.contains("was suspended: spawn"))).await;
            input.send(SpawnInput::StdinEof).await.unwrap();
        };
        let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat(&id)), sio, None, ctl), consume_into(&mut cio, &told), driver);
        assert!(result.unwrap().parked_close);
        let t = Instant::now();
        let stopped = stop_spawn(&env, &id, Duration::from_secs(3)).await;
        assert!(matches!(stopped, Ok(true)), "{stopped:?}");
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        until_true("the shim released it", || w.spawns().is_empty()).await;
        assert_eq!(w.state(), VmState::Running, "the dial resumed the VM");
        let again = stop_spawn(&env, &id, Duration::from_secs(3)).await;
        assert!(matches!(again, Ok(true)), "gone already: {again:?}");
        w.finish().await;
    })
    .await;
}

// ---- S10 I2 (the lead): a parked chat's VM ends under it -----------------------------------------

/// S10's joint cases at the session (I2; `tests/continuity.rs`' `joint`
/// has them end to end): a parked session whose VM ends learns it as
/// `Terminated` (`LossCause::VmGone`, which the pump re-addresses), never by
/// dialing the ended VM and never by unparking into it.
mod joint {
    use super::*;
    use ai_env_cli::bridge::errors::BridgeError;
    use ai_env_cli::bridge::remote::link::LossCause;

    /// I2 (a), the session's half: parked with no socket (its VM suspended
    /// under it), the VM ends (its wall, or a terminate: a `/terminate` no
    /// socket hears). The next input finds it gone at the GetMicrovm before
    /// any dial: the session ends `Terminated` (`VmGone`; the pump moves the
    /// chat with that input), parked once and never unparked, nothing dialed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_next_input_finds_a_vm_ended_while_parked_before_any_dial() {
        bounded(async {
            let w = world(true).await;
            let env = w.env();
            let (ctl, pump) = w.park_ctl();
            let (sio, mut cio) = spawn_channels(8);
            let input = cio.input.clone();
            let told = Mutex::new(Told::default());
            let id = SpawnId::new_v7();
            let dials = Mutex::new(None);
            let driver = async {
                type_line(&input, &pump, "hello\n").await;
                until(&told, "the first echo", |t| t.stdout == b"hello\n").await;
                pump.line(Verdict::Idle, Some("user"));
                parked_on_the_shim(&w, &told, 1).await;
                w.api.suspend(&w.vm.id).await.unwrap();
                until(&told, "parked with no socket", |t| t.notes.iter().any(|n| n.contains("was suspended: spawn"))).await;
                w.api.terminate(&w.vm.id).await.unwrap();
                until_true("the VM ended", || w.state().is_terminal()).await;
                *dials.lock().unwrap() = Some(w.endpoint.attempts().len());
                type_line(&input, &pump, "again\n").await;
            };
            let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat(&id)), sio, None, ctl), consume_into(&mut cio, &told), driver);
            let e = result.expect_err("the next input finds the VM gone");
            assert!(matches!(e, BridgeError::Terminated(_)), "{e}");
            assert_eq!(LossCause::of(&e), LossCause::VmGone, "{e}");
            assert_eq!(Some(w.endpoint.attempts().len()), *dials.lock().unwrap(), "nothing dialed into the ended VM");
            {
                let t = told.lock().unwrap();
                assert_eq!(words(&t.parks), ["parked:idle"], "parked once, never unparked");
                assert!(t.exit.is_none() && t.stdout == b"hello\n" && t.links.is_empty(), "{t:?}");
            }
            assert!(w.audit("session_unpark").is_empty(), "{:?}", w.audit("session_unpark"));
            w.finish().await;
        })
        .await;
    }

    /// I2 (b), the session's half: parked with its socket open, the VM is
    /// terminated. The shim's `/terminate` sends `hook_terminate` on the
    /// parked socket, and the session ends at once with no input,
    /// `Terminated` (`VmGone`: the pump waits for the next line to move the
    /// chat), parked once and never unparked, nothing dialed after the park.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_vm_ended_under_the_open_parked_socket_ends_the_session_at_once() {
        bounded(async {
            let w = world(true).await;
            let env = w.env();
            let (ctl, pump) = w.park_ctl();
            let (sio, mut cio) = spawn_channels(8);
            let input = cio.input.clone();
            let told = Mutex::new(Told::default());
            let id = SpawnId::new_v7();
            let dials = Mutex::new(None);
            let driver = async {
                type_line(&input, &pump, "hello\n").await;
                until(&told, "the first echo", |t| t.stdout == b"hello\n").await;
                pump.line(Verdict::Idle, Some("user"));
                parked_on_the_shim(&w, &told, 1).await;
                *dials.lock().unwrap() = Some(w.endpoint.attempts().len());
                w.api.terminate(&w.vm.id).await.unwrap();
            };
            let (result, (), ()) = tokio::join!(run_spawn_parked(&env, Start::New(cat(&id)), sio, None, ctl), consume_into(&mut cio, &told), driver);
            let e = result.expect_err("the parked session hears the VM end");
            assert!(matches!(e, BridgeError::Terminated(_)), "{e}");
            assert_eq!(LossCause::of(&e), LossCause::VmGone, "{e}");
            assert_eq!(Some(w.endpoint.attempts().len()), *dials.lock().unwrap(), "nothing dialed after the park");
            {
                let t = told.lock().unwrap();
                assert_eq!(words(&t.parks), ["parked:idle"], "parked once, never unparked");
                assert!(t.exit.is_none(), "{t:?}");
            }
            assert!(w.audit("session_unpark").is_empty(), "{:?}", w.audit("session_unpark"));
            w.finish().await;
        })
        .await;
    }
}
