//! S6 offline interop (plan S6 T6.1, T6.2, the fake half of T6.6): the real
//! shim and the real Mac client. First the lead's end-to-end checks of wave 1
//! (in-process: the shim's app and hooks routers on loopback, the session's
//! `run_spawn` through the debug knob's plain dial); then (W4) the real
//! `ai-env vm exec` / `vm attach` processes through the fake endpoint of
//! `common/fake_endpoint.rs` with the file-backed fake API, against an
//! in-process shim (log mode, this user's uid): bytes, bad tokens, cuts and
//! reattach (one pid throughout), a spawn whose `spawned` was lost (never
//! run twice), gaps, a `--from-seq` past the stream, a
//! full window then kill -9, a takeover by `vm attach`, its stdin left
//! alone, a stderr flood, process groups, the exit mapping, the spawn limit,
//! signals (before the start, while reconnecting, and ignored on entry) and
//! EPIPE, 429/403/502, a resume Conflict, the suspend hook, the vpc proxy
//! variables, and `vm smoke --exec`. Never AWS, never the
//! developer's `claude` or `aws`: the spawns are `cat`, `sh`, `seq`, `yes`,
//! `head` and `sleep` from /usr/bin:/bin, and a `claude` script the test
//! writes. Every wait is bounded.
#[path = "common/fake_endpoint.rs"]
mod fake_endpoint;

use ai_env_cli::bridge::agent::{run_spawn, spawn_channels, AgentEnv, AgentTarget, RemoteExit, RunPolicy, SpawnEvent, SpawnInput, SpawnSpec, Start};
use ai_env_cli::bridge::api::{FakeMicrovmApi, IdleSpec, MicrovmApi, RunSpec, VmInfo, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::config::{Paths, TransportCfg};
use ai_env_cli::bridge::transport::AgentDial;
use ai_env_cli::bridge::vm::registry::VmRow;
use ai_env_cli::shim::health::{ProbeSpec, ShimOpts, ShimState};
use ai_env_cli::shim::peer::Peer;
use ai_env_cli::shim::sys::RealSys;
use ai_env_cli::wire::frame::RunHookPayload;
use ai_env_cli::wire::redact::Secret;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Every wait of these tests.
const LIMIT: Duration = Duration::from_secs(60);

/// One in-process shim (app and hooks routers on 127.0.0.1, port 0) with
/// `/run` done for `token`, and a RUNNING fake VM for the session's mints.
struct Rig {
    app: SocketAddr,
    api: FakeMicrovmApi,
    vm: VmInfo,
    paths: Paths,
    token: String,
    _home: tempfile::TempDir,
    _root: tempfile::TempDir,
}

async fn serve(router: axum::Router) -> SocketAddr {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router.into_make_service_with_connect_info::<Peer>()).await.unwrap() });
    addr
}

/// `POST <path>` with `body`; the status code.
fn post(addr: SocketAddr, path: &str, body: &str) -> u16 {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(LIMIT)).unwrap();
    s.write_all(format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or_else(|| panic!("no status in {out:?}"))
}

async fn rig() -> Rig {
    let home = tempfile::tempdir().unwrap();
    let (uid, gid) = (nix_uid(), nix_gid());
    let opts = ShimOpts { home: home.path().to_path_buf(), uid, gid, ..ShimOpts::default() };
    let state = Arc::new(ShimState::with(PathBuf::from("/nonexistent/claude"), opts, ProbeSpec::default(), Arc::new(RealSys)));
    state.set_bound();
    let hooks = serve(ai_env_cli::shim::hooks::router(state.clone())).await;
    let app = serve(ai_env_cli::shim::health::router(state.clone())).await;
    let api = FakeMicrovmApi::new();
    let spec = RunSpec {
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "1.0".into(),
        execution_role_arn: None,
        ingress_connectors: vec![],
        egress_connectors: vec![],
        idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
        max_duration_s: 900,
        run_hook_payload: "{}".into(),
        client_token: uuid::Uuid::now_v7().to_string(),
    };
    let vm = api.run(&spec).await.unwrap();
    api.advance_all();
    // Built at runtime: never a credential-looking literal.
    let token = format!("e2e-session-{}", "t".repeat(24));
    let payload = RunHookPayload::new(&Secret::new(token.clone()), "mike@mbp", "2026-10-03T08:00:00Z").to_json().unwrap();
    let body = serde_json::json!({ "microvmId": vm.id, "runHookPayload": payload }).to_string();
    assert_eq!(tokio::task::spawn_blocking(move || post(hooks, "/aws/lambda-microvms/runtime/v1/run", &body)).await.unwrap(), 200);
    let root = tempfile::tempdir().unwrap();
    let paths = Paths::from_root_and_env(root.path().join("bridge"), None);
    Rig { app, api, vm, paths, token, _home: home, _root: root }
}

fn nix_uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

fn nix_gid() -> u32 {
    // SAFETY: getgid cannot fail.
    unsafe { libc::getgid() }
}

impl Rig {
    fn env(&self) -> AgentEnv<'_, FakeMicrovmApi, FakeMicrovmApi> {
        AgentEnv {
            api: &self.api,
            ep: &self.api,
            paths: &self.paths,
            target: AgentTarget { vm_id: self.vm.id.clone(), endpoint: self.vm.endpoint.clone(), session_token: Secret::new(self.token.clone()), vpc: false, shell: false },
            policy: RunPolicy::from_cfg(&TransportCfg::default(), &VmRow::default(), None),
            dial: AgentDial { local: Some(self.app) },
        }
    }

    /// Run `argv` with `stdin` (then EOF): stdout, stderr, the reported pid
    /// and the exit, every chunk marked consumed as it arrives.
    async fn run(&self, argv: &[&str], stdin: Vec<u8>) -> (Vec<u8>, Vec<u8>, Option<u32>, RemoteExit) {
        let (io, c) = spawn_channels(16);
        let feed = c.input.clone();
        let feeder = tokio::spawn(async move {
            for chunk in stdin.chunks(64 * 1024) {
                if feed.send(SpawnInput::Stdin(chunk.to_vec())).await.is_err() {
                    return;
                }
            }
            let _ = feed.send(SpawnInput::StdinEof).await;
        });
        let mut events = c.events;
        let consumed = c.consumed.clone();
        let consumer = tokio::spawn(async move {
            let (mut out, mut err, mut pid, mut exit) = (Vec::new(), Vec::new(), None, None);
            while let Some(ev) = events.recv().await {
                match ev {
                    SpawnEvent::Started { pid: p, .. } => pid = Some(p),
                    SpawnEvent::Stdout { seq, bytes } => {
                        out.extend_from_slice(&bytes);
                        consumed.stdout_done(seq);
                    }
                    SpawnEvent::Stderr { seq, bytes, .. } => {
                        err.extend_from_slice(&bytes);
                        consumed.stderr_done(seq);
                    }
                    SpawnEvent::Exit(e) => exit = Some(e),
                    SpawnEvent::Note(_) | SpawnEvent::Link(_) => {}
                }
            }
            (out, err, pid, exit)
        });
        let spec = SpawnSpec { argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: BTreeMap::new(), detach_grace_s: None };
        let env = self.env();
        let outcome = tokio::time::timeout(LIMIT, run_spawn(&env, Start::New(spec), io)).await.expect("the spawn ends in time").unwrap_or_else(|e| panic!("run_spawn: {e}"));
        drop(env);
        drop(c.input);
        drop(c.control);
        feeder.abort();
        let (out, err, pid, exit) = tokio::time::timeout(LIMIT, consumer).await.expect("the events end").unwrap();
        assert_eq!(exit, Some(outcome.exit), "the exit event is the outcome's");
        (out, err, pid, outcome.exit)
    }
}

/// Wave 1 end to end: `/bin/cat` through the real shim and the real session
/// returns every byte (text, non-UTF-8, a 64 KiB-spanning run, an
/// unterminated last line) in order, reports the spawn's pid, and exits 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_cat_round_trips_bytes_through_the_real_shim_and_session() {
    let r = rig().await;
    let mut input = b"hello\n".to_vec();
    input.extend_from_slice(&[0x00, 0xff, 0xfe, b'\n']);
    input.extend(std::iter::repeat_n(b'x', 200_000));
    input.extend_from_slice("€ unterminated".as_bytes());
    let (out, err, pid, exit) = r.run(&["cat"], input.clone()).await;
    assert_eq!(out.len(), input.len());
    assert!(out == input, "stdout differs from stdin");
    assert!(err.is_empty(), "{}", String::from_utf8_lossy(&err));
    assert!(pid.is_some_and(|p| p > 1), "{pid:?}");
    assert_eq!((exit.code, exit.signal, exit.stdout_truncated), (Some(0), None, false));
}

/// The remote status, stderr and a signal death come back as they are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_exit_status_stderr_and_signal() {
    let r = rig().await;
    let (out, err, _, exit) = r.run(&["sh", "-c", "printf out; printf err >&2; exit 7"], Vec::new()).await;
    assert_eq!((out.as_slice(), err.as_slice()), (b"out".as_slice(), b"err".as_slice()));
    assert_eq!((exit.code, exit.signal, exit.status()), (Some(7), None, 7));
    let (_, _, _, killed) = r.run(&["sh", "-c", "kill -TERM $$"], Vec::new()).await;
    assert_eq!((killed.code, killed.signal, killed.status()), (None, Some(15), 143));
}

// ---- W4: `ai-env vm exec` / `vm attach` / `vm smoke --exec` as processes -------------------

use ai_env_cli::bridge::api::{Call, FakeFailure, FakeState, VmState};
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use fake_endpoint::{Action, FakeEndpoint};
use std::io::BufRead;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::Instant;

/// The process tests' lab knob: one second of the session's policy is this
/// many ms (dead after 4.5 s, a ping every 2 s, reconnects from 100 ms, one
/// second of `Retry-After` = 100 ms).
const KNOB_MS: u64 = 100;

/// One process-level world: a temp root (`bridge/` with its bridge.toml,
/// `keys/`, `home/` the agent's HOME, `ws/`), the file-backed fake
/// (`fake.json`, PENDING → RUNNING on the first GetMicrovm), an in-process
/// shim (app and hooks on loopback, log mode, this user's uid) and the fake
/// endpoint in front of its app port; `id` is the VM `ai-env vm run`
/// started, whose payload went to the shim's `/run`. The shim's spawns are
/// stopped when the world is dropped.
struct World {
    root: PathBuf,
    shim: Arc<ShimState>,
    hooks: SocketAddr,
    endpoint: FakeEndpoint,
    id: String,
    rt: tokio::runtime::Runtime,
    _tmp: tempfile::TempDir,
}

impl World {
    /// A world without a VM; `claude` (a script's text) is what argv[0] `claude` runs.
    fn bare(claude: Option<&str>) -> World {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in ["bridge", "keys", "home", "ws"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let toml = format!("[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\n\n[workspaces]\nroots = [{:?}]\n", root.join("ws").display().to_string());
        std::fs::write(root.join("bridge").join("bridge.toml"), toml).unwrap();
        let state = FakeState { auto_advance: true, ..FakeState::new() };
        std::fs::write(root.join("fake.json"), serde_json::to_string_pretty(&state).unwrap()).unwrap();
        let claude = match claude {
            Some(text) => {
                use std::os::unix::fs::PermissionsExt;
                let path = root.join("claude");
                std::fs::write(&path, text).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
                path
            }
            None => PathBuf::from("/nonexistent/claude"),
        };
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let opts = ShimOpts { home: root.join("home"), uid: nix_uid(), gid: nix_gid(), ..ShimOpts::default() };
        let shim = Arc::new(ShimState::with(claude, opts, ProbeSpec::default(), Arc::new(RealSys)));
        shim.set_bound();
        let (hooks, app) = rt.block_on(async { (serve(ai_env_cli::shim::hooks::router(shim.clone())).await, serve(ai_env_cli::shim::health::router(shim.clone())).await) });
        let endpoint = FakeEndpoint::start(&root.join("fake.json"), app);
        World { root, shim, hooks, endpoint, id: String::new(), rt, _tmp: tmp }
    }

    /// A world with a VM: `vm run --egress internet` (plus `extra`), its payload POSTed to the shim's `/run`.
    fn new(extra: &[&str]) -> World {
        let mut w = World::bare(None);
        let mut args = vec!["vm", "run", "--egress", "internet", "--json"];
        args.extend_from_slice(extra);
        let mut cmd = w.cmd(&args);
        cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1");
        let o = run(cmd, None);
        assert!(o.status.success(), "vm run: {}", text(&o.stderr));
        w.id = serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap()["id"].as_str().unwrap().to_string();
        assert_eq!(post_run(&w.fake_path(), w.hooks, &w.id), 200);
        w
    }

    fn fake_path(&self) -> PathBuf {
        self.root.join("fake.json")
    }

    /// The fake's state (under its lock: `ai-env` processes may be using it).
    fn fake(&self) -> FakeState {
        FileFakeMicrovmApi::open(&self.fake_path()).unwrap().snapshot().unwrap()
    }

    fn update_fake(&self, f: impl FnOnce(&mut FakeState)) {
        FileFakeMicrovmApi::open(&self.fake_path())
            .unwrap()
            .with(|s| {
                f(s);
                Ok(())
            })
            .unwrap();
    }

    /// `ai-env <args>`: the fake API, the knob at [`KNOB_MS`], `/agent` through the
    /// fake endpoint; the developer's AWS and ai-env variables removed, PATH
    /// pinned, SIGINT/SIGTERM/SIGHUP at their defaults.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ai-env"));
        default_signals(&mut c);
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().to_string();
            if k.starts_with("AWS_") || k.starts_with("AI_ENV_") || k.starts_with("PULUMI_") || k == "RUST_LOG" {
                c.env_remove(&k);
            }
        }
        c.args(args)
            .env("HOME", &self.root)
            .env("PATH", "/usr/bin:/bin")
            .env("AI_ENV_BRIDGE_DIR", self.root.join("bridge"))
            .env("AI_ENV_DIR", self.root.join("keys"))
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AI_ENV_BRIDGE_LAB_FAKE_API", self.fake_path())
            .env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", KNOB_MS.to_string())
            .env("AI_ENV_BRIDGE_LAB_AGENT_ADDR", self.endpoint.addr.to_string())
            .stdin(Stdio::null());
        c
    }

    /// `ai-env vm exec <id> <args>`.
    fn exec(&self, args: &[&str]) -> Command {
        let mut all = vec!["vm", "exec", self.id.as_str()];
        all.extend_from_slice(args);
        self.cmd(&all)
    }

    /// Port(8080) tokens minted so far.
    fn mints(&self) -> usize {
        self.fake().calls.iter().filter(|c| matches!(c, Call::Token { port: 8080, .. })).count()
    }

    fn audit(&self, event: &str) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(self.root.join("bridge").join("audit.jsonl")).unwrap_or_default();
        text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).collect()
    }

    fn cli_log(&self) -> String {
        std::fs::read_to_string(self.root.join("bridge").join("logs").join("ai-env.log")).unwrap_or_default()
    }

    /// The ids of the shim's spawns.
    fn spawn_ids(&self) -> Vec<String> {
        self.shim.spawns.status(None).into_iter().map(|s| s.spawn_id.0).collect()
    }

    /// Cut every socket with the next `n` dials throttled (`Retry-After: retry_after`
    /// seconds of the session's policy); returns once the first redial got its 429.
    fn cut_throttled(&self, retry_after: &str, n: usize) {
        let before = self.endpoint.attempts().len();
        self.endpoint.script((0..n).map(|_| Action::status(429, &[("Retry-After", retry_after)])));
        self.endpoint.cut_all();
        wait_for("the redial's 429", || self.endpoint.attempts().iter().skip(before).any(|a| a.status == 429));
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let shim = self.shim.clone();
        self.rt.block_on(async move {
            let _ = tokio::time::timeout(Duration::from_secs(6), shim.spawns.shutdown("test")).await;
        });
    }
}

/// The child starts with SIGINT, SIGTERM and SIGHUP at their defaults, as
/// from a terminal: a test run started under `nohup` or as a background job
/// would hand them over ignored, and `vm exec` leaves an ignored signal so.
fn default_signals(c: &mut Command) {
    set_signals(c, libc::SIG_DFL, &[libc::SIGINT, libc::SIGTERM, libc::SIGHUP]);
}

/// `signals` get `disposition` in the child, before it execs.
fn set_signals(c: &mut Command, disposition: libc::sighandler_t, signals: &[libc::c_int]) {
    use std::os::unix::process::CommandExt;
    let signals = signals.to_vec();
    // SAFETY: signal(2) is async-signal-safe, and the closure allocates nothing between fork and exec.
    unsafe {
        c.pre_exec(move || {
            for &sig in &signals {
                libc::signal(sig, disposition);
            }
            Ok(())
        });
    }
}

/// Poll `f` until it holds, within `LIMIT`.
fn wait_for(what: &str, f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < LIMIT, "{what}: not within {LIMIT:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// POST the payload RunMicrovm carried for `id` to the shim's `/run` (the platform's run hook).
fn post_run(fake: &std::path::Path, hooks: SocketAddr, id: &str) -> u16 {
    let st = FileFakeMicrovmApi::open(fake).unwrap().snapshot().unwrap();
    let token = st.tokens.iter().find(|(_, v)| v.as_str() == id).map(|(k, _)| k.clone()).expect("the VM's client token");
    let payload = st.specs.iter().find(|s| s.client_token == token).expect("the VM's run spec").run_hook_payload.clone();
    let body = serde_json::json!({ "microvmId": id, "runHookPayload": payload }).to_string();
    post(hooks, "/aws/lambda-microvms/runtime/v1/run", &body)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

/// stderr without ai-env's own lines (the knob banner, notes).
fn remote_stderr(o: &Output) -> String {
    text(&o.stderr).lines().filter(|l| !l.starts_with("ai-env: ")).map(|l| format!("{l}\n")).collect()
}

fn read_all(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = r.read_to_end(&mut v);
        v
    })
}

/// The exit of `child`, within `LIMIT` (killed and failed past it).
fn wait_bounded(child: &mut Child) -> ExitStatus {
    let t = Instant::now();
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s;
        }
        if t.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the process ran past {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Run `cmd` to its end with `stdin` (`None`: /dev/null), bounded by `LIMIT`.
fn run(mut cmd: Command, stdin: Option<Vec<u8>>) -> Output {
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let feeder = stdin.map(|bytes| {
        let mut sink = child.stdin.take().unwrap();
        std::thread::spawn(move || {
            let _ = sink.write_all(&bytes);
        })
    });
    let (out, err) = (read_all(child.stdout.take().unwrap()), read_all(child.stderr.take().unwrap()));
    let status = wait_bounded(&mut child);
    if let Some(f) = feeder {
        f.join().unwrap();
    }
    Output { status, stdout: out.join().unwrap(), stderr: err.join().unwrap() }
}

/// A started `vm exec` whose stdout is read line by line on a thread.
struct Live {
    child: Child,
    lines: std::sync::mpsc::Receiver<String>,
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
}

impl Live {
    fn start(mut cmd: Command) -> Live {
        let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        let out = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(out).lines().map_while(std::result::Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let stderr = Some(read_all(child.stderr.take().unwrap()));
        Live { child, lines, stderr }
    }

    /// The next stdout line, within `LIMIT`.
    fn line(&self) -> String {
        self.lines.recv_timeout(LIMIT).expect("a stdout line in time")
    }

    fn signal(&self, sig: i32) {
        // SAFETY: kill(2) on our own child's pid.
        assert_eq!(unsafe { libc::kill(i32::try_from(self.child.id()).unwrap(), sig) }, 0);
    }

    /// The exit status, the rest of stdout and all of stderr.
    fn finish(mut self) -> (ExitStatus, Vec<String>, String) {
        let status = wait_bounded(&mut self.child);
        let rest = self.lines.iter().collect();
        (status, rest, text(&self.stderr.take().unwrap().join().unwrap()))
    }
}

/// A sleep argument no other process carries (`sleep` takes the fraction).
fn marker(n: u32) -> String {
    format!("300.{}{n:03}", std::process::id())
}

/// Whether a process whose command line matches `pattern` (extended regex, `pgrep -f`) runs.
fn running(pattern: &str) -> bool {
    Command::new("/usr/bin/pgrep").args(["-f", pattern]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

/// Whether every process matching `pattern` is gone within 5 s.
fn gone(pattern: &str) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(5) {
        if !running(pattern) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn sha256(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

/// T6.1: `cat` returns every byte: 1 000 lines with a 1 MiB, a 4 MiB+1 and a
/// 20 MiB line, non-UTF-8 bytes, an unterminated last line.
#[test]
fn exec_cat_round_trips_every_byte_through_the_endpoint_and_the_shim() {
    let w = World::new(&[]);
    let mut input = Vec::new();
    for i in 0..1000u32 {
        match i {
            10 => input.extend(std::iter::repeat_n(b'a', 1024 * 1024)),
            20 => input.extend(std::iter::repeat_n(b'b', 4 * 1024 * 1024 + 1)),
            30 => input.extend(std::iter::repeat_n(b'c', 20 * 1024 * 1024)),
            40 => input.extend_from_slice(&[0xff, 0xfe, 0x00, 0x80, b'\r', 0xc3]),
            _ => input.extend_from_slice(format!("line {i} €").as_bytes()),
        }
        if i < 999 {
            input.push(b'\n');
        }
    }
    let o = run(w.exec(&["--", "cat"]), Some(input.clone()));
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(o.stdout.len(), input.len());
    assert_eq!(sha256(&o.stdout), sha256(&input), "stdout differs from stdin");
    assert_eq!(w.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![101], "one upgrade, no reconnect");
    let rows = w.audit("vm_exec");
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0]["detail"]["argv0"].as_str(), rows[0]["detail"]["status"].as_str(), rows[0]["detail"]["id"].as_str()), (Some("cat"), Some("0"), Some(w.id.as_str())));
}

/// T6.1: a row whose session token is not the one `/run` committed to.
#[test]
fn a_token_the_vm_did_not_commit_to_is_bad_token_exit_8() {
    let w = World::new(&[]);
    let path = w.root.join("bridge").join("state").join("vms").join(format!("{}.toml", w.id));
    let mut row: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    row.insert("session_token".into(), "w".repeat(64).into());
    std::fs::write(&path, toml::to_string(&row).unwrap()).unwrap();
    let o = run(w.exec(&["--", "true"]), None);
    assert_eq!(code(&o), 8, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("refused this Mac's session token"), "{}", text(&o.stderr));
    assert!(!text(&o.stderr).contains(&"w".repeat(64)), "the token is never shown");
    assert!(w.spawn_ids().is_empty(), "nothing ran");
}

/// T6.2: a 100 k-line producer whose socket the endpoint cuts twice (stdin
/// null): every line exactly once, in order, from one process — the shim
/// holds one spawn with one pid from before the first cut to after the
/// second reattach.
#[test]
fn a_producer_cut_twice_loses_and_doubles_no_line() {
    let w = World::new(&[]);
    w.endpoint.script([Action::ForwardThenCut { after: Duration::from_millis(700) }, Action::ForwardThenCut { after: Duration::from_millis(700) }]);
    let producer = "for b in $(seq 0 99); do seq $((b*1000+1)) $((b*1000+1000)); sleep 0.03; done";
    let (shim, done) = (w.shim.clone(), Arc::new(std::sync::atomic::AtomicBool::new(false)));
    let stop = done.clone();
    let sampler = std::thread::spawn(move || {
        let mut seen = Vec::new();
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            seen.extend(shim.spawns.status(None).into_iter().map(|s| (Instant::now(), s.spawn_id.0, s.pid)));
            std::thread::sleep(Duration::from_millis(20));
        }
        seen
    });
    let o = run(w.exec(&["--", "sh", "-c", producer]), None);
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let seen = sampler.join().unwrap();
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let want: String = (1..=100_000).map(|i| format!("{i}\n")).collect();
    let got = text(&o.stdout);
    if got != want {
        let first = got.lines().zip(want.lines()).position(|(a, b)| a != b);
        panic!("{} bytes (want {}), first difference at line {first:?}", got.len(), want.len());
    }
    let upgrades: Vec<Instant> = w.endpoint.attempts().iter().filter(|a| a.status == 101).map(|a| a.at).collect();
    assert_eq!(upgrades.len(), 3, "{:?}", w.endpoint.attempts());
    assert_eq!(text(&o.stderr).matches("ai-env: reattached to spawn").count(), 2, "{}", text(&o.stderr));
    let spawns: std::collections::BTreeSet<(&str, u32)> = seen.iter().map(|(_, id, pid)| (id.as_str(), *pid)).collect();
    assert_eq!(spawns.len(), 1, "one spawn, one pid: {spawns:?}");
    assert!(seen.iter().any(|(t, ..)| *t < upgrades[1]) && seen.iter().any(|(t, ..)| *t > upgrades[2]), "the pid was seen before the first reattach and after the second");
}

/// T6.2: `vm attach --from-seq 1` once that output was acknowledged is a gap.
#[test]
fn attach_from_seq_1_after_the_output_was_acknowledged_is_a_gap_exit_8() {
    let w = World::new(&[]);
    let m = marker(1);
    let live = Live::start(w.exec(&["--", "sh", "-c", &format!("echo first; exec sleep {m}")]));
    assert_eq!(live.line(), "first");
    // The ack timer (250 ms) acknowledges the written line: the shim trims seq 1.
    wait_for("the first line acknowledged", || w.shim.spawns.status(None).first().is_some_and(|s| s.out_from > 1));
    live.signal(libc::SIGKILL);
    let _ = live.finish();
    let ids = w.spawn_ids();
    assert_eq!(ids.len(), 1, "the spawn outlives its client (detach grace)");
    let o = run(w.cmd(&["vm", "attach", &w.id, "--spawn", &ids[0], "--from-seq", "1"]), None);
    assert_eq!(code(&o), 8, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains(&format!("spawn {} no longer holds its stdout from seq 1", ids[0])), "{}", text(&o.stderr));
    assert!(running(&format!("^sleep {m}$")), "a refused attach leaves the spawn alone");
}

/// A client killed mid-run: `vm attach` replays what the shim still holds and exits with the remote status.
#[test]
fn attach_after_the_client_died_replays_and_exits_with_the_remote_status() {
    let w = World::new(&[]);
    let live = Live::start(w.exec(&["--", "sh", "-c", "echo first; sleep 2; echo second; exit 3"]));
    assert_eq!(live.line(), "first");
    wait_for("the first line acknowledged", || w.shim.spawns.status(None).first().is_some_and(|s| s.out_from > 1));
    live.signal(libc::SIGKILL);
    let _ = live.finish();
    let ids = w.spawn_ids();
    assert_eq!(ids.len(), 1);
    let o = run(w.cmd(&["vm", "attach", &w.id, "--spawn", &ids[0]]), None);
    assert_eq!(code(&o), 3, "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout), "second\n", "acknowledged output is not replayed");
    let rows = w.audit("vm_attach");
    assert_eq!((rows.len(), rows[0]["detail"]["spawn"].as_str(), rows[0]["detail"]["status"].as_str()), (1, Some(ids[0].as_str()), Some("3")));
}

/// `vm attach --from-seq` past the end of the spawn's stdout starts at its
/// next chunk, as the shim does (`Cursor::resume`): the attach shows what
/// the command prints from then on, with a note, and exits with its status
/// — never a silent hang while the unacknowledged window fills.
#[test]
fn attach_from_a_seq_past_the_stream_shows_what_comes_next() {
    let w = World::new(&[]);
    let gate = w.root.join("gate-from-seq");
    let script = r#"echo first; while [ ! -e "$GATE" ]; do sleep 0.05; done; i=0; while [ $i -lt 2000 ]; do echo after-$i; i=$((i+1)); done; exit 5"#;
    let live = Live::start(w.exec(&["--env", &format!("GATE={}", gate.display()), "--", "sh", "-c", script]));
    assert_eq!(live.line(), "first");
    wait_for("the first line acknowledged", || w.shim.spawns.status(None).first().is_some_and(|s| s.out_from > 1));
    live.signal(libc::SIGKILL);
    let _ = live.finish();
    wait_for("the killed client detached", || w.shim.spawns.status(None).first().is_some_and(|s| !s.attached));
    let ids = w.spawn_ids();
    let attach = Live::start(w.cmd(&["vm", "attach", &w.id, "--spawn", &ids[0], "--from-seq", "1000000"]));
    wait_for("the attach took the spawn", || w.shim.spawns.status(None).first().is_some_and(|s| s.attached));
    std::fs::write(&gate, "").unwrap();
    let (status, rest, err) = attach.finish();
    assert_eq!(status.code(), Some(5), "{err}");
    let want: Vec<String> = (0..2000).map(|i| format!("after-{i}")).collect();
    assert!(rest == want, "{} lines, not after-0..after-1999: {err}", rest.len());
    assert!(err.contains(&format!("ai-env: stdout seq 1000000 is past the end of spawn {}'s stdout (seq 1): showing it from seq 2", ids[0])), "{err}");
}

/// T6.2: a full stdout window (nobody reads `vm exec`'s stdout, so it stops
/// acknowledging and the producer blocks), then kill -9 of the client and of
/// the remote command: `vm attach` replays everything the client never
/// acknowledged, byte for byte, then the exit — not cut short — as 137.
#[test]
fn a_full_window_then_kill_9_then_attach_replays_it_and_exits_137() {
    let w = World::new(&[]);
    // `%.0f`: BSD seq prints 1e+06 otherwise.
    let mut child = w.exec(&["--", "seq", "-f", "%.0f", "1", "2000000"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let err = read_all(child.stderr.take().unwrap());
    let t = Instant::now();
    let mut grew = (0u64, Instant::now());
    let full = loop {
        assert!(t.elapsed() < LIMIT, "the stdout window never filled");
        if let Some(s) = w.shim.spawns.status(None).into_iter().next() {
            if s.out_seq != grew.0 {
                grew = (s.out_seq, Instant::now());
            } else if s.out_seq > 0 && grew.1.elapsed() >= Duration::from_secs(1) {
                break s;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(full.alive && full.exit.is_none(), "the producer is blocked, not done: {full:?}");
    child.kill().unwrap();
    let _ = wait_bounded(&mut child);
    let _ = err.join();
    let mut written = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut written).unwrap();
    // SAFETY: kill(2) on the spawn's pid, a child of this process's shim, still unreaped (alive above).
    assert_eq!(unsafe { libc::kill(i32::try_from(full.pid).unwrap(), libc::SIGKILL) }, 0);
    let o = run(w.cmd(&["vm", "attach", &w.id, "--spawn", &full.spawn_id.0]), None);
    assert_eq!(code(&o), 137, "{}", text(&o.stderr));
    assert!(!text(&o.stderr).contains("cut short"), "the exit is not truncated: {}", text(&o.stderr));
    let mut expected = Vec::with_capacity(15 * 1024 * 1024);
    for i in 1..=2_000_000u32 {
        writeln!(expected, "{i}").unwrap();
    }
    let replay = o.stdout;
    assert!(expected.starts_with(&written), "what the killed client wrote ({} bytes) starts the stream", written.len());
    assert!(replay.len() > 7 * 1024 * 1024, "the whole window comes back: {} bytes", replay.len());
    // The replay starts at the first chunk the client had not acknowledged, within what it wrote.
    let from = (written.len().saturating_sub(1024 * 1024)..=written.len()).find(|&p| expected[p..].starts_with(&replay));
    assert!(from.is_some(), "the replay ({} bytes) continues the {} bytes the client wrote, without a gap", replay.len(), written.len());
}

/// `vm attach` takes over a spawn from a live `vm exec` (the newest
/// attachment wins): the first client exits 8 naming the takeover, the
/// attach gets the rest of the output and the remote status. The remote
/// goes on only once the test made its gate file, after the takeover: no
/// timing race between the attach's start and the remote's end.
#[test]
fn an_attach_supersedes_a_live_exec_which_exits_8() {
    let w = World::new(&[]);
    let gate = w.root.join("gate-supersede");
    let script = r#"echo first; while [ ! -e "$GATE" ]; do sleep 0.05; done; echo second; exit 4"#;
    let live = Live::start(w.exec(&["--env", &format!("GATE={}", gate.display()), "--", "sh", "-c", script]));
    assert_eq!(live.line(), "first");
    // The ack timer (250 ms) trims `first` once written: the attach does not replay it.
    wait_for("the first line acknowledged", || w.shim.spawns.status(None).first().is_some_and(|s| s.out_from > 1));
    let ids = w.spawn_ids();
    assert_eq!(ids.len(), 1);
    let attach = Live::start(w.cmd(&["vm", "attach", &w.id, "--spawn", &ids[0]]));
    let (status, rest, err) = live.finish();
    assert_eq!(status.code(), Some(8), "{err}");
    assert!(err.contains(&format!("ai-env: superseded: another client attached spawn {} of {}", ids[0], w.id)), "{err}");
    assert!(rest.is_empty(), "{rest:?}");
    std::fs::write(&gate, "").unwrap();
    let (status, rest, err) = attach.finish();
    assert_eq!(status.code(), Some(4), "{err}");
    assert_eq!(rest, vec!["second".to_string()], "{err}");
}

/// `vm attach` whose stdin is not a terminal (here /dev/null) leaves the
/// remote's stdin as it is: a `cat` reading it goes on waiting, where a
/// forwarded EOF would have closed it for good.
#[test]
fn an_attach_without_a_terminal_leaves_the_remote_stdin_open() {
    let w = World::new(&[]);
    let mut exec = w.exec(&["--", "sh", "-c", "echo started; cat; echo cat-ended-$?; exec sleep 30"]);
    // stdin held open (and never written) by this test.
    exec.stdin(Stdio::piped());
    let live = Live::start(exec);
    assert_eq!(live.line(), "started");
    wait_for("the first line acknowledged", || w.shim.spawns.status(None).first().is_some_and(|s| s.out_from > 1));
    live.signal(libc::SIGKILL);
    let _ = live.finish();
    let ids = w.spawn_ids();
    assert_eq!(ids.len(), 1);
    let attach = Live::start(w.cmd(&["vm", "attach", &w.id, "--spawn", &ids[0]]));
    let quiet = attach.lines.recv_timeout(Duration::from_secs(2));
    attach.signal(libc::SIGTERM);
    let (status, rest, err) = attach.finish();
    assert!(quiet.is_err(), "the remote printed {quiet:?}: its stdin was closed ({err})");
    assert!(rest.iter().all(|l| !l.starts_with("cat-ended")), "{rest:?}");
    assert_eq!(status.code(), Some(143), "{err}");
}

/// T6.2: a 50 MB stderr flood, with stderr not even read until stdout is
/// complete: stdout never waits behind it, and the dropped bytes are said.
#[test]
fn a_stderr_flood_never_holds_stdout_back() {
    let w = World::new(&[]);
    let script = "yes 0123456789abcdef | head -c 50000000 >&2 & i=0; while [ $i -lt 2000 ]; do echo out-$i; i=$((i+1)); done; wait";
    let mut child = w.exec(&["--", "sh", "-c", script]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (done_tx, done) = std::sync::mpsc::channel();
    let out = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in std::io::BufReader::new(out).lines().map_while(std::result::Result::ok) {
            let last = line == "out-1999";
            lines.push(line);
            if last {
                let _ = done_tx.send(());
            }
        }
        lines
    });
    let err = child.stderr.take().unwrap();
    let complete = done.recv_timeout(LIMIT).is_ok();
    let err = read_all(err);
    let status = wait_bounded(&mut child);
    let lines = reader.join().unwrap();
    let err = text(&err.join().unwrap());
    assert!(complete, "stdout did not complete while stderr was not read");
    assert_eq!(status.code(), Some(0), "{}", err.lines().filter(|l| l.starts_with("ai-env: ")).collect::<Vec<_>>().join("\n"));
    assert_eq!(lines, (0..2000).map(|i| format!("out-{i}")).collect::<Vec<_>>());
    assert!(err.contains("bytes of the remote's stderr dropped so far"), "{}", err.lines().filter(|l| l.starts_with("ai-env: ")).collect::<Vec<_>>().join("\n"));
}

/// T6.2: a process left behind dies with its group.
#[test]
fn a_background_process_dies_with_its_group() {
    let w = World::new(&[]);
    let m = marker(2);
    let o = run(w.exec(&["--", "sh", "-c", &format!("sleep {m} & exit 0")]), None);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(gone(&format!("^sleep {m}$")), "the background sleep outlived its group");
}

/// D8: the remote status verbatim, 128 + N for a signal; no `ai-env:` line for either.
#[test]
fn the_remote_status_is_the_exit_status() {
    let w = World::new(&[]);
    let o = run(w.exec(&["--", "sh", "-c", "printf out; printf err >&2; exit 7"]), None);
    assert_eq!(code(&o), 7, "{}", text(&o.stderr));
    assert_eq!((text(&o.stdout).as_str(), remote_stderr(&o).trim_end()), ("out", "err"));
    assert!(!text(&o.stderr).contains("exit status"), "the remote's status is silent: {}", text(&o.stderr));
    let o = run(w.exec(&["--", "sh", "-c", "kill -TERM $$"]), None);
    assert_eq!(code(&o), 143, "{}", text(&o.stderr));
    let o = run(w.exec(&["--env", "GREETING=hello", "--cwd", &w.root.join("home").join("made").join("here").display().to_string(), "--", "sh", "-c", "printf '%s %s' \"$GREETING\" \"$(pwd)\""]), None);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout), format!("hello {}", w.root.join("home").join("made").join("here").display()), "--env and --cwd reach the spawn");
}

/// A command the VM cannot start exits like a shell's: 127 for a program
/// that does not exist, 126 for one that cannot run, each with an
/// `ai-env: vm exec:` line; a working directory that cannot be made is
/// ai-env's exit 1 — never the "VM lost" exit 8.
#[test]
fn a_command_that_cannot_start_exits_127_126_or_1() {
    let w = World::new(&[]);
    let o = run(w.exec(&["--", "no-such-program-for-ai-env-tests"]), None);
    assert_eq!(code(&o), 127, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("ai-env: vm exec: ") && text(&o.stderr).contains("not found on PATH"), "{}", text(&o.stderr));
    let not_executable = w.root.join("home").join("not-executable");
    std::fs::write(&not_executable, "#!/bin/sh\n").unwrap();
    let o = run(w.exec(&["--", &not_executable.display().to_string()]), None);
    assert_eq!(code(&o), 126, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("ai-env: vm exec: "), "{}", text(&o.stderr));
    // A read-only system directory: the cwd cannot be made, as the agent.
    let o = run(w.exec(&["--cwd", "/usr/ai-env-tests-cannot-make-this", "--", "true"]), None);
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("ai-env: vm exec: cannot create or enter the working directory"), "{}", text(&o.stderr));
}

/// The shim's limit of eight live spawns is a refusal (exit 9) naming
/// `vm health --detail`, never the "VM lost" exit 8.
#[test]
fn a_ninth_command_is_refused_with_exit_9() {
    let w = World::new(&[]);
    let m = marker(14);
    let lives: Vec<Live> = (0..8).map(|i| Live::start(w.exec(&["--", "sh", "-c", &format!("echo ready-{i}; exec sleep {m}")]))).collect();
    for (i, live) in lives.iter().enumerate() {
        assert_eq!(live.line(), format!("ready-{i}"));
    }
    let o = run(w.exec(&["--", "true"]), None);
    assert_eq!(code(&o), 9, "{}", text(&o.stderr));
    let line = format!("ai-env: refused: {id} already runs 8 commands, the most its shim allows: wait for one to end (`ai-env vm health {id} --detail` lists them)", id = w.id);
    assert!(text(&o.stderr).contains(&line), "{}", text(&o.stderr));
    for live in lives {
        live.signal(libc::SIGKILL);
        let _ = live.finish();
    }
}

/// Ctrl-C: INT reaches the remote group (its trap decides the status).
#[test]
fn sigint_reaches_the_remote() {
    // The in-process shim's spawns inherit this process's dispositions, and a
    // shell cannot trap a signal it started with ignored (POSIX): a test run
    // started as a background job (`cargo test &`) would hand it SIGINT ignored.
    // SAFETY: SIG_DFL is SIGINT's ordinary disposition; nothing here relies on another.
    unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
    let w = World::new(&[]);
    let live = Live::start(w.exec(&["--", "sh", "-c", "trap 'exit 42' INT; echo ready; sleep 30"]));
    assert_eq!(live.line(), "ready");
    live.signal(libc::SIGINT);
    let (status, _, err) = live.finish();
    assert_eq!(status.code(), Some(42), "{err}");
}

/// A second Ctrl-C within 3 s sends KILL (here the remote ignores INT): 128 + 9.
#[test]
fn a_second_sigint_within_3_s_kills_the_remote() {
    let w = World::new(&[]);
    let m = marker(5);
    let live = Live::start(w.exec(&["--", "sh", "-c", &format!("trap '' INT; echo ready; exec sleep {m}")]));
    assert_eq!(live.line(), "ready");
    live.signal(libc::SIGINT);
    std::thread::sleep(Duration::from_millis(300));
    live.signal(libc::SIGINT);
    let (status, _, err) = live.finish();
    assert_eq!(status.code(), Some(137), "{err}");
    assert!(gone(&format!("^sleep {m}$")));
}

/// Ctrl-C before the command started (the endpoint throttles the dial with
/// `Retry-After: 20`, 2 s each at the knob): `vm exec` gives up at once with
/// 130 and nothing ever starts on the VM — the interrupt is not queued for a
/// command that would start once a socket comes up.
#[test]
fn sigint_before_the_command_started_starts_nothing_and_exits_130() {
    let w = World::new(&[]);
    let throttled = || Action::status(429, &[("Retry-After", "20")]);
    w.endpoint.script([throttled(), throttled(), throttled()]);
    let live = Live::start(w.exec(&["--", "sh", "-c", "echo started"]));
    wait_for("the first 429", || !w.endpoint.attempts().is_empty());
    let t = Instant::now();
    live.signal(libc::SIGINT);
    let (status, rest, err) = live.finish();
    let took = t.elapsed();
    assert_eq!(status.code(), Some(130), "{err}");
    assert!(took < Duration::from_millis(1500), "gave up in {took:?}, not after the 429's wait");
    assert!(rest.is_empty() && err.contains("ai-env: interrupted before the command started on"), "{rest:?} {err}");
    assert_eq!(w.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![429], "no dial after the interrupt");
    assert!(w.spawn_ids().is_empty(), "nothing started");
    let rows = w.audit("vm_exec");
    assert_eq!((rows.len(), rows[0]["detail"]["status"].as_str(), rows[0]["detail"]["spawn"].as_str()), (1, Some("130"), Some("-")));
}

/// Ctrl-C while the upgrade itself is slow (the endpoint holds it 1 s, as an
/// auto-resume does): the session drops the dial on the pump's `detach
/// final` (it watches its controls mid-dial), so `vm exec` exits 130 and no
/// command is ever left running, not even one that ignores INT (how soon it
/// gives up: `sigint_while_the_upgrade_is_held_gives_up_at_once`).
#[test]
fn sigint_during_a_slow_upgrade_never_leaves_the_command_running() {
    let w = World::new(&[]);
    w.endpoint.script([Action::Delay { by: Duration::from_secs(1) }]);
    let m = marker(9);
    let live = Live::start(w.exec(&["--", "sh", "-c", &format!("trap '' INT; exec sleep {m}")]));
    wait_for("the held upgrade", || w.endpoint.accepted() > 0);
    let t = Instant::now();
    live.signal(libc::SIGINT);
    let (status, _, err) = live.finish();
    let took = t.elapsed();
    assert_eq!(status.code(), Some(130), "{err}");
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert!(err.contains("ai-env: interrupted before the command started on"), "{err}");
    assert!(gone(&format!("^sleep {m}$")), "the command was left running: {err}");
    assert!(w.spawn_ids().is_empty(), "the session gave up during the upgrade: nothing was spawned ({:?})", w.spawn_ids());
}

/// Ctrl-C while the endpoint holds the upgrade (as long as it likes): the
/// session gives the dial up at once, not after the pump's 3 s detach wait
/// (nor the dial's 60 s), and nothing is spawned.
#[test]
fn sigint_while_the_upgrade_is_held_gives_up_at_once() {
    let w = World::new(&[]);
    w.endpoint.script([Action::Held]);
    let live = Live::start(w.exec(&["--", "sh", "-c", "echo started"]));
    wait_for("the held upgrade", || w.endpoint.accepted() > 0);
    let t = Instant::now();
    live.signal(libc::SIGINT);
    let (status, rest, err) = live.finish();
    let took = t.elapsed();
    w.endpoint.release();
    assert_eq!(status.code(), Some(130), "{err}");
    assert!(took < Duration::from_millis(1500), "gave up in {took:?}: the session sat in the held dial until the pump's detach wait");
    assert!(rest.is_empty() && err.contains("ai-env: interrupted before the command started on"), "{rest:?} {err}");
    assert!(w.spawn_ids().is_empty(), "nothing was spawned ({:?})", w.spawn_ids());
}

/// Ctrl-C while `vm attach` is still dialing gives the attach up and leaves
/// the spawn as it was (running under its detach grace): no INT reaches it.
#[test]
fn sigint_before_an_attach_completed_leaves_the_spawn_alone() {
    let w = World::new(&[]);
    let m = marker(8);
    let live = Live::start(w.exec(&["--", "sh", "-c", &format!("echo ready; exec sleep {m}")]));
    assert_eq!(live.line(), "ready");
    live.signal(libc::SIGKILL);
    let _ = live.finish();
    let ids = w.spawn_ids();
    assert_eq!(ids.len(), 1);
    let throttled = || Action::status(429, &[("Retry-After", "20")]);
    w.endpoint.script([throttled(), throttled()]);
    let before = w.endpoint.attempts().len();
    let attach = Live::start(w.cmd(&["vm", "attach", &w.id, "--spawn", &ids[0]]));
    wait_for("the attach's 429", || w.endpoint.attempts().len() > before);
    let t = Instant::now();
    attach.signal(libc::SIGINT);
    let (status, _, err) = attach.finish();
    let took = t.elapsed();
    assert_eq!(status.code(), Some(130), "{err}");
    assert!(took < Duration::from_millis(1500), "gave up in {took:?}");
    assert!(err.contains(&format!("ai-env: interrupted before spawn {} was reattached", ids[0])), "{err}");
    assert!(running(&format!("^sleep {m}$")), "no INT reached the spawn");
    assert_eq!(w.spawn_ids(), ids);
}

/// A signal ignored when `vm exec` started stays ignored, as ssh leaves it:
/// under `nohup` a hangup never stops the remote, and a SIGINT ignored by a
/// non-interactive shell's background job never reaches it.
#[test]
fn signals_ignored_on_entry_stay_ignored() {
    let w = World::new(&[]);
    let script = "trap 'exit 41' HUP INT TERM; echo ready; sleep 1; echo done; exit 6";
    let exec = w.exec(&["--", "sh", "-c", script]);
    let mut nohup = Command::new("/usr/bin/nohup");
    nohup.arg(exec.get_program()).args(exec.get_args()).stdin(Stdio::null());
    for (k, v) in exec.get_envs() {
        match v {
            Some(v) => nohup.env(k, v),
            None => nohup.env_remove(k),
        };
    }
    default_signals(&mut nohup);
    let live = Live::start(nohup);
    assert_eq!(live.line(), "ready");
    live.signal(libc::SIGHUP);
    let (status, rest, err) = live.finish();
    assert_eq!((status.code(), rest), (Some(6), vec!["done".to_string()]), "nohup: {err}");
    assert!(w.cli_log().contains(&format!("signal {} was ignored when ai-env started", libc::SIGHUP)), "{}", w.cli_log());
    let mut exec = w.exec(&["--", "sh", "-c", script]);
    set_signals(&mut exec, libc::SIG_IGN, &[libc::SIGINT]);
    let live = Live::start(exec);
    assert_eq!(live.line(), "ready");
    live.signal(libc::SIGINT);
    let (status, rest, err) = live.finish();
    assert_eq!((status.code(), rest), (Some(6), vec!["done".to_string()]), "SIGINT ignored: {err}");
}

/// SIGHUP (the terminal went away) ends the attachment like SIGTERM: exit 143, the remote stopped.
#[test]
fn sighup_detaches_final_and_exits_143() {
    let w = World::new(&[]);
    let m = marker(6);
    let live = Live::start(w.exec(&["--", "sh", "-c", &format!("trap '' TERM; echo ready; exec sleep {m}")]));
    assert_eq!(live.line(), "ready");
    live.signal(libc::SIGHUP);
    let (status, _, err) = live.finish();
    assert_eq!(status.code(), Some(143), "{err}");
    assert!(gone(&format!("^sleep {m}$")), "detach final ran the ladder");
}

/// `--detach-grace` reaches the shim: a client that dies leaves its command 1 s, not 60.
#[test]
fn detach_grace_reaches_the_shim() {
    let w = World::new(&[]);
    let m = marker(7);
    let live = Live::start(w.exec(&["--detach-grace", "1", "--", "sh", "-c", &format!("echo first; exec sleep {m}")]));
    assert_eq!(live.line(), "first");
    live.signal(libc::SIGKILL);
    let _ = live.finish();
    assert!(gone(&format!("^sleep {m}$")), "the 1 s grace ended the orphaned spawn");
}

/// A spawn whose `spawned` was lost with its socket never runs twice: the
/// endpoint cuts the first socket as the shim's `spawned` comes back, and
/// holds the redial until the command (done at once) was released after its
/// 1 s detach grace. The resume answers `unknown`, the spawn goes out again
/// (a note says so, not "reattached"), the shim refuses its used id, and
/// `vm exec` exits 8 naming `vm attach`: the command ran exactly once.
#[test]
fn a_spawn_whose_spawned_was_lost_never_runs_twice() {
    let w = World::new(&[]);
    let runs = w.root.join("runs");
    w.endpoint.script([Action::ForwardUntil { text: r#""t":"spawned""#.into() }, Action::Held]);
    let live = Live::start(w.exec(&["--detach-grace", "1", "--env", &format!("RUNS={}", runs.display()), "--", "sh", "-c", r#"echo ran >> "$RUNS""#]));
    // The redial follows the cut, which followed the shim's start of the spawn.
    wait_for("the redial", || w.endpoint.accepted() >= 2);
    wait_for("the spawn released after its grace", || w.spawn_ids().is_empty());
    w.endpoint.release();
    let (status, rest, err) = live.finish();
    assert_eq!(status.code(), Some(8), "{err}");
    assert!(rest.is_empty(), "{rest:?}");
    let id = err.split("ai-env: transport: spawn ").nth(1).and_then(|r| r.split(' ').next()).unwrap_or_default();
    let says = format!("ai-env: transport: spawn {id} reached {vm} before the connection was lost: it ran, or still runs, without this client and was not started again (`ai-env vm attach {vm} --spawn {id}` reattaches to it while it runs)", vm = w.id);
    assert!(!id.is_empty() && err.contains(&says), "{err}");
    // In order: the loss, the spawn sent again on socket 2 (this process's second), the refusal.
    let line = |f: &dyn Fn(&str) -> bool| err.lines().position(f);
    let lost = line(&|l| l.starts_with("ai-env: lost the connection to "));
    let again = line(&|l| l.starts_with(&format!("ai-env: sent spawn {id} again after ")) && l.ends_with(" ms (socket 2): the VM did not hold it"));
    let refused = line(&|l| l.contains(&says));
    assert!(matches!((lost, again, refused), (Some(l), Some(a), Some(r)) if l < a && a < r), "{err}");
    assert!(!err.contains("ai-env: reattached to spawn"), "nothing was reattached: {err}");
    assert_eq!(std::fs::read_to_string(&runs).unwrap(), "ran\n", "the command ran exactly once");
    assert!(w.spawn_ids().is_empty(), "nothing started again");
}

/// SIGTERM: TERM to the remote, at most 2 s for its exit, then `detach final`
/// (the shim's ladder kills what ignored TERM) and exit 143.
#[test]
fn sigterm_sends_term_then_detaches_final_and_exits_143() {
    let w = World::new(&[]);
    let m = marker(3);
    let live = Live::start(w.exec(&["--", "sh", "-c", &format!("trap '' TERM; echo ready; exec sleep {m}")]));
    assert_eq!(live.line(), "ready");
    let t = Instant::now();
    live.signal(libc::SIGTERM);
    let (status, _, err) = live.finish();
    let took = t.elapsed();
    assert_eq!(status.code(), Some(143), "{err}");
    assert!(took >= Duration::from_millis(1900) && took < Duration::from_secs(10), "TERM, 2 s, detach: {took:?}");
    assert!(gone(&format!("^sleep {m}$")), "detach final ran the ladder (KILL after an ignored TERM)");
}

/// SIGTERM exits 143 even when the remote handles TERM and exits 0 within
/// the 2 s (plan S6: TERM, at most 2 s, then exit 143); the output up to
/// that exit is still written.
#[test]
fn sigterm_exits_143_even_when_the_remote_exits_0_on_term() {
    let w = World::new(&[]);
    let live = Live::start(w.exec(&["--", "sh", "-c", "trap 'echo bye; exit 0' TERM; echo ready; sleep 30 & wait"]));
    assert_eq!(live.line(), "ready");
    let t = Instant::now();
    live.signal(libc::SIGTERM);
    let (status, rest, err) = live.finish();
    assert_eq!(status.code(), Some(143), "{err}");
    assert_eq!(rest, vec!["bye".to_string()], "{err}");
    assert!(t.elapsed() < Duration::from_millis(1900), "the remote's exit ended the wait: {:?}", t.elapsed());
}

/// EPIPE: a reader that closes early ends the remote command, and `vm exec` exits 0.
#[test]
fn a_reader_that_closes_early_stops_the_remote_and_exits_0() {
    let w = World::new(&[]);
    let m = marker(4);
    let mut child = w.exec(&["--", "sh", "-c", &format!("exec yes {m}")]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let out = child.stdout.take().unwrap();
    let (tx, first) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        // The reader is dropped with this statement: the client's next write is EPIPE.
        let _ = std::io::BufReader::new(out).read_line(&mut line);
        let _ = tx.send(line);
    });
    let err = read_all(child.stderr.take().unwrap());
    let first = first.recv_timeout(LIMIT);
    if first.is_err() {
        let _ = child.kill();
    }
    assert_eq!(first.expect("a first line in time"), format!("{m}\n"), "the reader read one line, then closed");
    let status = wait_bounded(&mut child);
    let err = text(&err.join().unwrap());
    assert_eq!(status.code(), Some(0), "{err}");
    assert!(gone(&format!("^yes {m}$")), "TERM reached the remote");
}

/// SIGTERM while the socket is down and every redial is throttled
/// (`Retry-After: 100`, 10 s at the knob): nothing can reach the VM, so the
/// stop waits for the connection at most 10 of the session's seconds (1 s
/// here), then `vm exec` exits 143 saying so — the command runs on under its
/// detach grace (not a final detach), and the line names how to stop it.
#[test]
fn sigterm_while_reconnecting_says_the_stop_did_not_reach_the_vm() {
    let w = World::new(&[]);
    let m = marker(11);
    let live = Live::start(w.exec(&["--detach-grace", "30", "--", "sh", "-c", &format!("echo ready; exec sleep {m}")]));
    assert_eq!(live.line(), "ready");
    w.cut_throttled("100", 3);
    let t = Instant::now();
    live.signal(libc::SIGTERM);
    let (status, _, err) = live.finish();
    let took = t.elapsed();
    assert_eq!(status.code(), Some(143), "{err}");
    assert!(took < Duration::from_secs(6), "the wait for the connection is bounded: {took:?}");
    assert!(err.contains(&format!("ai-env: not connected to {} (reconnecting): stopping the command waits for the connection at most 1.0 s", w.id)), "{err}");
    let ids = w.spawn_ids();
    assert_eq!(ids.len(), 1);
    let line = format!("ai-env: the stop could not reach {id}: spawn {s} may keep running until its detach grace (30 s) ends it; `ai-env vm attach {id} --spawn {s}` can stop it sooner", id = w.id, s = ids[0]);
    assert!(err.contains(&line), "{err}");
    assert!(running(&format!("^sleep {m}$")), "the TERM never reached the VM");
    let d = w.shim.spawns.detail();
    assert!(d[0].status.alive && d[0].detach_left_s.is_some_and(|s| s > 0), "it runs under its grace, not a final detach: {d:?}");
}

/// SIGTERM during a short loss (the knob at 1000 ms keeps real seconds: the
/// first redial is throttled 3 s, past TERM's 2 s and within the 10 s the
/// stop waits): TERM goes out with the reattach and gets its 2 s, then
/// `detach final` ends the command that ignored it — exit 143, and nothing
/// is left to a grace.
#[test]
fn sigterm_during_a_short_loss_reaches_the_command_once_reattached() {
    let w = World::new(&[]);
    let m = marker(12);
    let mut cmd = w.exec(&["--", "sh", "-c", &format!("trap '' TERM; echo ready; exec sleep {m}")]);
    cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1000");
    let live = Live::start(cmd);
    assert_eq!(live.line(), "ready");
    w.cut_throttled("3", 1);
    live.signal(libc::SIGTERM);
    let (status, _, err) = live.finish();
    assert_eq!(status.code(), Some(143), "{err}");
    assert!(gone(&format!("^sleep {m}$")), "TERM, then detach final reached the VM (its ladder killed what ignored TERM): {err}");
    assert!(err.contains("stopping the command waits for the connection at most 10.0 s") && err.contains("ai-env: reattached to spawn"), "{err}");
    assert!(!err.contains("could not reach"), "{err}");
}

/// Ctrl-C while the socket is down: the interrupt is queued, `vm exec` says
/// so, and INT reaches the remote group once the session reattached (its
/// trap decides the status).
#[test]
fn a_sigint_while_reconnecting_is_queued_and_reaches_the_command_once_back() {
    let w = World::new(&[]);
    let live = Live::start(w.exec(&["--", "sh", "-c", "trap 'exit 42' INT; echo ready; sleep 30"]));
    assert_eq!(live.line(), "ready");
    w.cut_throttled("20", 1);
    live.signal(libc::SIGINT);
    let (status, _, err) = live.finish();
    assert_eq!(status.code(), Some(42), "{err}");
    assert!(err.contains(&format!("ai-env: not connected to {} (reconnecting): the interrupt reaches the command once the connection is back; Ctrl-C again within 3 s gives up", w.id)), "{err}");
    assert!(err.contains("ai-env: reattached to spawn"), "{err}");
}

/// A second Ctrl-C within 3 s while nothing reaches the VM gives up: exit
/// 130 at once (not after the reconnect budget), saying the stop did not
/// reach the VM; the command runs on under its detach grace.
#[test]
fn a_second_sigint_while_reconnecting_gives_up_with_130() {
    let w = World::new(&[]);
    let m = marker(13);
    let live = Live::start(w.exec(&["--detach-grace", "30", "--", "sh", "-c", &format!("echo ready; exec sleep {m}")]));
    assert_eq!(live.line(), "ready");
    w.cut_throttled("100", 3);
    live.signal(libc::SIGINT);
    std::thread::sleep(Duration::from_millis(300));
    let t = Instant::now();
    live.signal(libc::SIGINT);
    let (status, _, err) = live.finish();
    let took = t.elapsed();
    assert_eq!(status.code(), Some(130), "{err}");
    assert!(took < Duration::from_secs(5), "gave up at once: {took:?}");
    assert!(err.contains("the interrupt reaches the command once the connection is back") && err.contains(&format!("ai-env: interrupted again while not connected to {}: giving up", w.id)), "{err}");
    let ids = w.spawn_ids();
    assert!(err.contains(&format!("ai-env: the stop could not reach {}: spawn {} may keep running until its detach grace (30 s) ends it", w.id, ids[0])), "{err}");
    assert!(running(&format!("^sleep {m}$")), "no INT reached the VM");
}

/// T6.6: a 429 with `Retry-After: 3` waits 3 s (the knob at 1000 ms keeps seconds), never re-mints, and is audited.
#[test]
fn throttled_with_retry_after_waits_it_once_and_never_remints() {
    let w = World::new(&[]);
    let before = w.mints();
    w.endpoint.script([Action::status(429, &[("Retry-After", "3")])]);
    let mut cmd = w.exec(&["--", "true"]);
    cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1000");
    let o = run(cmd, None);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let a = w.endpoint.attempts();
    assert_eq!(a.iter().map(|x| x.status).collect::<Vec<_>>(), vec![429, 101]);
    let waited = a[1].at - a[0].at;
    assert!(waited >= Duration::from_secs(3), "{waited:?}");
    assert_eq!(w.mints() - before, 1, "exactly one mint");
    let rows = w.audit("endpoint_429");
    assert_eq!((rows.len(), rows[0]["detail"]["retry_after"].as_str()), (1, Some("3")));
    assert!(text(&o.stderr).contains("throttled /agent (HTTP 429)"), "{}", text(&o.stderr));
}

/// T6.6 (critic L9): a 429 without `Retry-After` backs off exponentially, never re-mints.
#[test]
fn throttled_without_retry_after_backs_off_exponentially() {
    let w = World::new(&[]);
    let before = w.mints();
    w.endpoint.script([Action::status(429, &[]), Action::status(429, &[]), Action::status(429, &[])]);
    // Steps of 200 ms (not the world's 100): the doubling check below keeps 100 ms of slack for a loaded gate.
    let mut cmd = w.exec(&["--", "true"]);
    cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "200");
    let o = run(cmd, None);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let a = w.endpoint.attempts();
    assert_eq!(a.iter().map(|x| x.status).collect::<Vec<_>>(), vec![429, 429, 429, 101]);
    let gaps: Vec<Duration> = a.windows(2).map(|p| p[1].at - p[0].at).collect();
    // Backoff 200, 400, 800 ms, each ±25 %: the third wait is at least twice the first (its floor 600 ms, the first's ceiling 250 ms), which no constant step is, jittered or not.
    assert!(gaps[0] >= Duration::from_millis(150) && gaps[0] < Duration::from_millis(600) && gaps[1] >= Duration::from_millis(300) && gaps[2] >= Duration::from_millis(600) && gaps[2] >= gaps[0] * 2, "{gaps:?}");
    assert_eq!(w.mints() - before, 1, "a 429 never re-mints");
    let rows = w.audit("endpoint_429");
    assert!(rows.len() == 3 && rows.iter().all(|r| r["detail"]["retry_after"] == "none"), "{rows:?}");
}

/// T6.6: 403 twice: one re-mint, then exit 7 naming the proxy's refusal.
#[test]
fn forbidden_twice_remints_once_then_exits_7() {
    let w = World::new(&[]);
    let before = w.mints();
    let forbidden = || Action::status(403, &[("x-aws-proxy-error", "UNAUTHORIZED")]);
    w.endpoint.script([forbidden(), forbidden()]);
    let o = run(w.exec(&["--", "true"]), None);
    assert_eq!(code(&o), 7, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("token rejected: HTTP 403 for port 8080 (x-aws-proxy-error: UNAUTHORIZED)"), "{}", text(&o.stderr));
    assert_eq!(w.mints() - before, 2, "the session's token and one re-mint");
    assert_eq!(w.audit("agent_remint").len(), 1);
    assert!(w.spawn_ids().is_empty());
}

/// T6.6: the socket is lost while the VM is SUSPENDED without auto-resume:
/// the endpoint answers 502, GetMicrovm says SUSPENDED, one ResumeMicrovm,
/// then the spawn is reattached and finishes.
#[test]
fn a_502_with_the_vm_suspended_resumes_it_and_reattaches() {
    let w = World::new(&["--no-auto-resume"]);
    let live = Live::start(w.exec(&["--", "sh", "-c", "for i in $(seq 1 30); do echo $i; sleep 0.1; done"]));
    assert_eq!(live.line(), "1");
    let id = w.id.clone();
    w.update_fake(|s| s.vms.get_mut(&id).unwrap().state = VmState::Suspended);
    w.endpoint.cut_all();
    let (status, rest, err) = live.finish();
    assert_eq!(status.code(), Some(0), "{err}");
    let mut all = vec!["1".to_string()];
    all.extend(rest);
    assert_eq!(all, (1..=30).map(|i| i.to_string()).collect::<Vec<_>>());
    assert_eq!(w.fake().calls.iter().filter(|c| matches!(c, Call::Resume(r) if *r == w.id)).count(), 1, "one ResumeMicrovm");
    let statuses: Vec<u16> = w.endpoint.attempts().iter().map(|a| a.status).collect();
    assert!(statuses.windows(2).any(|p| p == [502, 101]), "502 (MICROVM_SUSPENDED), then the reattach: {statuses:?}");
    assert!(err.contains("suspended without auto-resume: resuming it") && err.contains("ai-env: reattached to spawn"), "{err}");
}

/// T6.6: ResumeMicrovm answered with a Conflict (another resume already
/// under way) is tolerated: the client polls GetMicrovm until the VM runs,
/// then reattaches and the spawn finishes.
#[test]
fn a_resume_conflict_is_tolerated_and_the_spawn_reattached_once_the_vm_runs() {
    let w = World::new(&["--no-auto-resume"]);
    let live = Live::start(w.exec(&["--", "sh", "-c", "for i in $(seq 1 30); do echo $i; sleep 0.1; done"]));
    assert_eq!(live.line(), "1");
    let id = w.id.clone();
    w.update_fake(|s| {
        s.vms.get_mut(&id).unwrap().state = VmState::Suspended;
        s.failures.push_back(FakeFailure { kind: "conflict".into(), message: "a resume is already in progress".into(), on: Some("resume".into()), after_effect: false });
    });
    w.endpoint.cut_all();
    // That other resume completes once the client's own was refused.
    wait_for("the client's ResumeMicrovm", || w.fake().calls.iter().any(|c| matches!(c, Call::Resume(r) if *r == id)));
    w.update_fake(|s| s.vms.get_mut(&id).unwrap().state = VmState::Running);
    let (status, rest, err) = live.finish();
    assert_eq!(status.code(), Some(0), "{err}");
    let mut all = vec!["1".to_string()];
    all.extend(rest);
    assert_eq!(all, (1..=30).map(|i| i.to_string()).collect::<Vec<_>>());
    assert_eq!(w.fake().calls.iter().filter(|c| matches!(c, Call::Resume(r) if *r == w.id)).count(), 1, "one ResumeMicrovm (refused), no retry");
    assert!(w.fake().failures.is_empty(), "the Conflict was served");
    assert!(err.contains("suspended without auto-resume: resuming it") && err.contains("ai-env: reattached to spawn"), "{err}");
}

/// vpc rows: the spawn gets the six proxy variables ai-env sets
/// (`egress::proxy_env`, the default proxy address here), next to the
/// operator's `--env`.
#[test]
fn a_vpc_row_gets_the_six_proxy_variables() {
    let w = World::new(&[]);
    let path = w.root.join("bridge").join("state").join("vms").join(format!("{}.toml", w.id));
    let mut row: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    row.insert("egress".into(), "vpc".into());
    std::fs::write(&path, toml::to_string(&row).unwrap()).unwrap();
    let o = run(w.exec(&["--env", "LANG=C", "--", "sh", "-c", "env | grep -i _proxy; echo count=$(env | grep -ci _proxy) LANG=$LANG"]), None);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    let mut lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.pop(), Some("count=6 LANG=C"), "{out}");
    let got: std::collections::BTreeSet<String> = lines.into_iter().map(str::to_string).collect();
    let want: std::collections::BTreeSet<String> = ai_env_cli::bridge::egress::proxy_env(ai_env_cli::bridge::egress::PROXY_IP, ai_env_cli::bridge::egress::PROXY_PORT).into_iter().map(|(k, v)| format!("{k}={v}")).collect();
    assert_eq!(got, want);
}

/// After `/suspend` (event hook_suspend) the client never dials on its own;
/// once the VM runs again it reattaches, and the platform's hold posts
/// `/resume` to the shim first.
#[test]
fn after_hook_suspend_no_dial_until_running_then_reattach() {
    let w = World::new(&[]);
    let live = Live::start(w.exec(&["--", "sh", "-c", "for i in $(seq 1 20); do echo $i; sleep 0.1; done"]));
    assert_eq!(live.line(), "1");
    let id = w.id.clone();
    w.update_fake(|s| s.vms.get_mut(&id).unwrap().state = VmState::Suspended);
    assert_eq!(post(w.hooks, "/aws/lambda-microvms/runtime/v1/suspend", "{}"), 200);
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(w.endpoint.attempts().len(), 1, "no dial while suspended");
    w.endpoint.script([Action::HoldThenResume { hooks: w.hooks }]);
    w.update_fake(|s| s.vms.get_mut(&id).unwrap().state = VmState::Running);
    let (status, rest, err) = live.finish();
    assert_eq!(status.code(), Some(0), "{err}");
    let mut all = vec!["1".to_string()];
    all.extend(rest);
    assert_eq!(all, (1..=20).map(|i| i.to_string()).collect::<Vec<_>>());
    assert_eq!(w.endpoint.resumes(), 1, "the hold posted /resume");
    assert!(err.contains("was suspended; not reconnecting") && err.contains("ai-env: reattached to spawn"), "{err}");
}

/// `vm smoke --exec` through the endpoint and the shim (a fake `claude`
/// printing `2.1.284 (Claude Code)`), with `infra` as state/infra.toml (none:
/// no file): the steps' fields are in the record; the claude step passes as
/// `want`, and `id -u` is 1000 only where the test runs as 1000, so
/// elsewhere the record says exec_ok false with that step as its one problem
/// and the smoke exits 1 — after the VM was terminated and the record written.
fn smoke_exec_judges_its_steps(infra: Option<&str>, want: &str) {
    let w = World::bare(Some("#!/bin/sh\necho '2.1.284 (Claude Code)'\n"));
    if let Some(infra) = infra {
        let state = w.root.join("bridge").join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("infra.toml"), infra).unwrap();
    }
    let (fake, hooks) = (w.fake_path(), w.hooks);
    // The platform's run hook: once RunMicrovm created the smoke's VM, its payload goes to the shim.
    let poster = std::thread::spawn(move || {
        let t = Instant::now();
        while t.elapsed() < LIMIT {
            let st = FileFakeMicrovmApi::open(&fake).unwrap().snapshot().unwrap();
            if let Some(id) = st.vms.keys().next() {
                return post_run(&fake, hooks, id);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        0
    });
    let o = run(w.cmd(&["vm", "smoke", "--exec", "--json"]), None);
    assert_eq!(poster.join().unwrap(), 200);
    let rec: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}\n{}", text(&o.stdout), text(&o.stderr)));
    let uid = nix_uid().to_string();
    assert_eq!(rec["exec_claude"], "2.1.284 (Claude Code)", "{}", text(&o.stderr));
    assert_eq!(rec["exec_uid"], uid.as_str());
    assert!(rec.get("exec_curl").is_none() && rec.get("exec_proxy_vars").is_none(), "an internet smoke runs no proxy steps");
    let ok = uid == "1000";
    assert_eq!((rec["exec_ok"].as_bool(), rec["ok"].as_bool(), code(&o)), (Some(ok), Some(ok), if ok { 0 } else { 1 }), "{}", text(&o.stderr));
    assert!(rec["exec_ms"].as_u64().is_some());
    assert!(text(&o.stderr).contains(&format!("(expected {want:?}, exit 0): ok")), "the claude step wanted {want}: {}", text(&o.stderr));
    let problems: Vec<&str> = rec["exec_problems"].as_array().unwrap().iter().map(|p| p.as_str().unwrap()).collect();
    if ok {
        assert!(problems.is_empty(), "{problems:?}");
    } else {
        let id_u = problems.first().copied().unwrap_or_default();
        assert!(problems.len() == 1 && id_u.starts_with(&format!("exec id -u → \"{uid}\" in ")) && id_u.ends_with(" ms (expected \"1000\", exit 0): MISMATCH"), "{problems:?}");
        assert!(text(&o.stderr).contains(&format!("ai-env: smoke --exec: {id_u}\n")), "{}", text(&o.stderr));
    }
    let id = rec["id"].as_str().unwrap();
    assert!(w.fake().vms[id].state.is_terminal(), "the smoke's VM is terminated");
}

/// The image lock's claude recorded, as `make infra-status WRITE=1` records
/// it: `claude --version` must print exactly that version (here the fake's
/// own; another would stop the smoke at /health).
#[test]
fn smoke_exec_runs_its_steps_over_agent_and_judges_them() {
    smoke_exec_judges_its_steps(Some("claude_version = \"2.1.284\"\n"), "2.1.284 (Claude Code)");
}

/// No state/infra.toml (live until `make infra-status WRITE=1` recorded the
/// image lock's claude): any `<x.y.z> (Claude Code)` line passes.
#[test]
fn smoke_exec_without_a_recorded_claude_takes_any_version_line() {
    smoke_exec_judges_its_steps(None, "<x.y.z> (Claude Code)");
}
