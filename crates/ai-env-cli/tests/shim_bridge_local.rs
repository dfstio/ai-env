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
        World::bare_with(claude, false)
    }

    /// [`World::bare`] whose endpoint is also the platform's hook client for
    /// the shim (`FakeEndpoint::start_platform`): a VM's first `/agent` runs
    /// it with its RunMicrovm payload, and `/suspend`, `/resume` and
    /// `/terminate` follow its state. For one VM: the shim takes one `/run`.
    fn platform(claude: Option<&str>) -> World {
        World::bare_with(claude, true)
    }

    fn bare_with(claude: Option<&str>, platform: bool) -> World {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in ["bridge", "keys", "home", "ws"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        // The agent's curl (a vpc smoke's API step) takes its proxy from here
        // over the environment ai-env sets (`[aws].proxy_private_ip` must be
        // RFC 1918, so 10.42.0.10 offline): a loopback port that refuses at
        // once, so no test reaches past this Mac or waits out curl's timeout.
        std::fs::write(root.join("home").join(".curlrc"), "proxy = \"http://127.0.0.1:9\"\n").unwrap();
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
        let endpoint = if platform { FakeEndpoint::start_platform(&root.join("fake.json"), app, hooks) } else { FakeEndpoint::start(&root.join("fake.json"), app) };
        World { root, shim, hooks, endpoint, id: String::new(), rt, _tmp: tmp }
    }

    /// A world with a VM: `vm run --egress internet` (plus `extra`), its payload POSTed to the shim's `/run`.
    fn new(extra: &[&str]) -> World {
        World::new_with(None, extra)
    }

    /// [`World::new`] whose `claude` is the script `claude`.
    fn new_with(claude: Option<&str>, extra: &[&str]) -> World {
        let w = World::bare(claude).with_vm(extra);
        assert_eq!(post_run(&w.fake_path(), w.hooks, &w.id), 200);
        w
    }

    /// This world with a VM `vm run --egress internet` (plus `extra`) started; nothing posted to the shim.
    fn with_vm(mut self, extra: &[&str]) -> World {
        let mut args = vec!["vm", "run", "--egress", "internet", "--json"];
        args.extend_from_slice(extra);
        let mut cmd = self.cmd(&args);
        cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1");
        let o = run(cmd, None);
        assert!(o.status.success(), "vm run: {}", text(&o.stderr));
        self.id = serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap()["id"].as_str().unwrap().to_string();
        self
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
            if k.starts_with("AWS_") || k.starts_with("AI_ENV_") || k.starts_with("PULUMI_") || k.starts_with("CLAUDE_CODE_") || k.starts_with("FAKE_") || k == "RUST_LOG" {
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


// ---- S7: `vm exec --with-credential` through the binary -----------------------------------

/// The documentation account's made-up egress connector (the fixture's ARN).
const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
/// The public test recipients of tests/cli.rs: an SE tag one and an X25519 recovery one.
const SE_REC: &str = "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";
/// The fake image version's build (`FakeState::new`).
const BUILD: i64 = 1_789_804_800;

fn connector_doc() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/egress/lambda-core.get-network-connector.json")).unwrap()
}

/// A stand-in setup-token of the real shape, built at run time with `tail`.
fn setup_token(tail: &str) -> String {
    format!("sk-ant-oat01-{}{tail}", "Kq4_".repeat(20))
}

impl World {
    fn bin(&self) -> PathBuf {
        self.root.join("bin")
    }

    fn age_log(&self) -> PathBuf {
        self.root.join("age.log")
    }

    /// `ai-env <args>` with the fake age first on PATH and its log; the sealed
    /// runtime key is unsealed even with the fake API; a hidden paste reads stdin.
    fn sealed_cmd(&self, args: &[&str]) -> Command {
        let mut c = self.cmd(args);
        c.env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("FAKE_AGE_LOG", self.age_log())
            .env("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1")
            .env("AI_ENV_PASTE_STDIN", "1");
        c
    }

    /// `ai-env vm exec <id> <args>` as [`Self::sealed_cmd`].
    fn cred_exec(&self, args: &[&str]) -> Command {
        let mut all = vec!["vm", "exec", self.id.as_str()];
        all.extend_from_slice(args);
        self.sealed_cmd(&all)
    }

    /// Decrypts (Touch IDs) the fake age served so far.
    fn decrypts(&self) -> usize {
        std::fs::read_to_string(self.age_log()).unwrap_or_default().lines().filter(|l| l.starts_with("age -d ")).count()
    }

    fn row(&self) -> VmRow {
        ai_env_cli::bridge::vm::registry::read_row(&Paths::from_root_and_env(self.root.join("bridge"), None), &self.id).unwrap().unwrap()
    }

    /// Edit the VM's row as TOML.
    fn edit_row(&self, f: impl FnOnce(&mut toml::Table)) {
        let path = self.root.join("bridge").join("state").join("vms").join(format!("{}.toml", self.id));
        let mut row: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        f(&mut row);
        std::fs::write(&path, toml::to_string(&row).unwrap()).unwrap();
    }

    /// A world whose VM may receive a credential: a vpc row whose echo gate
    /// passed and the fake VM's matching echo; the configured connector and
    /// its answer; a passing `egress check` recorded an hour ago for exactly
    /// this image version, connector facts and build; a `no-dns` dns-path
    /// verdict; the fake keystore key; and the runtime key and `token` sealed
    /// by the real `creds` commands with the fake age (no combined.env, so
    /// the token is a Touch ID of its own).
    fn credentialed(token: &str) -> World {
        World::credentialed_with(token, None)
    }

    /// [`World::credentialed`] whose `claude` is the script `claude`.
    fn credentialed_with(token: &str, claude: Option<&str>) -> World {
        let w = World::new_with(claude, &[]);
        let version = w.row().image_version;
        w.seed_credentials(token, &version);
        w.edit_row(|row| {
            row.insert("egress".into(), "vpc".into());
            row.insert("egress_gate".into(), "passed".into());
            row.insert("egress_connectors".into(), toml::Value::Array(vec![CONNECTOR.into()]));
        });
        let id = w.id.clone();
        w.update_fake(|s| s.vms.get_mut(&id).unwrap().egress = vec![CONNECTOR.to_string()]);
        w
    }

    /// Everything but a VM a credential needs: the fake age and keystore key,
    /// the configured connector and its answer, the fake shim's `/health`
    /// offering the credential cache, a passing `egress check` recorded an
    /// hour ago for `image_version` with the connector's facts and the fake's
    /// build, a `no-dns` dns-path verdict, and the runtime key and `token`
    /// sealed by the real `creds` commands (no combined.env).
    fn seed_credentials(&self, token: &str, image_version: &str) {
        use ai_env_cli::bridge::egress::{ConnectorFacts, EgressVerified, VerifiedRecord, DNS_NONE, DNS_RULE};
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::create_dir_all(self.bin()).unwrap();
        for name in ["age", "age-keygen", "age-plugin-se"] {
            let dst = self.bin().join(name);
            std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/age.sh"), &dst).unwrap();
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let key = self.root.join("keys").join("keys").join("ai-env-bridge");
        std::fs::create_dir_all(&key).unwrap();
        std::fs::write(key.join("identity.txt"), format!("# public key: {SE_REC}\nAGE-PLUGIN-SE-1FAKEFAKE\n")).unwrap();
        std::fs::write(key.join("recipients.txt"), format!("{SE_REC}\n{X_REC}\n")).unwrap();
        std::fs::write(key.join("meta.toml"), "created = \"2026-09-29\"\naccess_control = \"none\"\n").unwrap();
        let toml = format!("[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\negress_connector_arn = \"{CONNECTOR}\"\n\n[workspaces]\nroots = [{:?}]\n", self.root.join("ws").display().to_string());
        std::fs::write(self.root.join("bridge").join("bridge.toml"), toml).unwrap();
        self.update_fake(|s| {
            s.connectors.insert(CONNECTOR.to_string(), connector_doc());
            s.health_caps = vec![ai_env_cli::wire::frame::CAP_CREDENTIAL_CACHE.to_string()];
        });
        let now = ai_env_cli::wire::time::unix_now();
        let record = VerifiedRecord {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: image_version.into(),
            connector: CONNECTOR.into(),
            vm_id: "microvm-checked".into(),
            at: ai_env_cli::wire::time::rfc3339_utc(now - 3600),
            dns: DNS_NONE.into(),
            dns_rule: DNS_RULE,
            connector_facts: ConnectorFacts::from_get(&connector_doc()).unwrap(),
            image_created_at: Some(BUILD),
            ..VerifiedRecord::default()
        };
        std::fs::create_dir_all(self.root.join("bridge").join("state")).unwrap();
        std::fs::write(self.root.join("bridge").join("state").join("egress-verified.toml"), toml::to_string(&EgressVerified { records: vec![record], ..EgressVerified::default() }).unwrap()).unwrap();
        std::fs::create_dir_all(self.root.join("bridge").join("lab")).unwrap();
        let dns_row = serde_json::json!({ "probe": "dns-path", "verdict": DNS_NONE, "ts": ai_env_cli::wire::time::rfc3339_utc(now - 7200) });
        std::fs::write(self.root.join("bridge").join("lab").join("probes.jsonl"), format!("{dns_row}\n")).unwrap();
        let secret = format!("{}cred", "Tq8+".repeat(9));
        let aws = format!("{{\"AccessKey\": {{\"UserName\": \"ai-env-runtime\", \"AccessKeyId\": \"AKIA{}\", \"Status\": \"Active\", \"SecretAccessKey\": \"{secret}\"}}}}", "CRED".repeat(4));
        let o = run(self.sealed_cmd(&["creds", "aws-set"]), Some(aws.into_bytes()));
        assert!(o.status.success(), "creds aws-set: {}", text(&o.stderr));
        let o = run(self.sealed_cmd(&["creds", "setup-token", "--stdin", "--no-combined"]), Some(format!("{token}\n").into_bytes()));
        assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
    }
}

/// S7 T7.3 offline: `vm exec --with-credential` passes the gate, unseals the
/// runtime key and the token (two Touch IDs without combined.env), delivers,
/// and the command reads the token on fd 3, with nothing under its name in
/// the environment. A second command finds the VM holding it: one delivery
/// for both. The audit says so, never the value; the row records the seal;
/// no file under the world's root holds the token.
#[test]
fn exec_with_credential_delivers_on_fd_3_and_the_vm_keeps_it() {
    let token = setup_token("Aa");
    let w = World::credentialed(&token);
    let read = ["--with-credential", "--", "/bin/sh", "-c", "cat <&3; echo; echo \"$CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR\"; env | grep -c '^CLAUDE_CODE_OAUTH_TOKEN=' || true"];
    let before = w.decrypts();
    let o = run(w.cred_exec(&read), None);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout) == format!("{token}\n3\n0\n"), "stdout of {} bytes", o.stdout.len());
    assert_eq!(w.decrypts() - before, 2, "the runtime key and the token");
    assert!(w.shim.spawns.credential().has(), "the shim keeps a copy");
    let o2 = run(w.cred_exec(&read), None);
    assert_eq!(code(&o2), 0, "{}", text(&o2.stderr));
    assert!(text(&o2.stdout) == format!("{token}\n3\n0\n"), "the second reads it from the cache");
    assert_eq!(w.audit("credential_deliver").len(), 1, "one delivery for two commands");
    let gates = w.audit("credential_gate");
    assert!(gates.len() == 2 && gates.iter().all(|r| r["detail"]["result"] == "passed"), "{gates:?}");
    assert!(w.audit("credential_unseal").iter().any(|r| r["detail"]["source"] == "setup-token" && r["detail"]["outcome"] == "ok"));
    let row = w.row();
    let tag = ai_env_cli::bridge::agent::credential::seal_tag(&w.root.join("bridge").join("credentials").join("setup-token.env")).unwrap();
    assert_eq!((row.credential_at.is_some(), row.credential_tag.as_deref()), (true, Some(tag.as_str())));
    let audit = std::fs::read_to_string(w.root.join("bridge").join("audit.jsonl")).unwrap();
    let log = w.cli_log();
    for (what, hay) in [("the audit", &audit), ("the CLI log", &log), ("stderr", &text(&o.stderr)), ("stderr 2", &text(&o2.stderr))] {
        assert!(!hay.contains(&token[13..]), "{what} holds the token");
    }
    assert_token_off_disk(&w, &token);
}

/// What is refused before any Touch ID: an internet VM (exit 9), `--deliver
/// env` without `[creds] deliver = "env"` (9), `claude --bare` (2),
/// `--deliver` alone (2), and no sealed token (5). The fake age is never
/// asked; the token is nowhere in any refusal's output or under the world's root.
#[test]
fn exec_with_credential_refuses_before_any_touch_id() {
    let token = setup_token("Bb");
    let w = World::credentialed(&token);
    let before = w.decrypts();
    let o = run(w.cred_exec(&["--with-credential", "--deliver", "env", "--", "true"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 9, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("[creds] deliver = \"env\""), "{}", text(&o.stderr));
    let o = run(w.cred_exec(&["--with-credential", "--", "claude", "--bare", "-p", "hi"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 2, "{}", text(&o.stderr));
    let o = run(w.cred_exec(&["--deliver", "fd", "--", "true"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 2, "{}", text(&o.stderr));
    w.edit_row(|row| {
        row.insert("egress".into(), "internet".into());
    });
    let o = run(w.cred_exec(&["--with-credential", "--", "true"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 9, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("not vpc"), "{}", text(&o.stderr));
    assert_eq!(w.audit("credential_gate").last().unwrap()["detail"]["condition"], "egress_row");
    w.edit_row(|row| {
        row.insert("egress".into(), "vpc".into());
    });
    std::fs::remove_file(w.root.join("bridge").join("credentials").join("setup-token.env")).unwrap();
    let o = run(w.cred_exec(&["--with-credential", "--", "true"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 5, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("ai-env creds setup-token"), "{}", text(&o.stderr));
    assert_eq!(w.decrypts(), before, "no Touch ID for any refusal");
    assert!(!w.shim.spawns.credential().has());
}

/// `--credential-file`: that container's token goes to that one command
/// inline and is never cached on the VM. It is in no file under the world's
/// root, nor in stderr (stdout holds it: the command prints fd 3).
#[test]
fn a_credential_file_reaches_one_command_and_is_never_cached() {
    let token = setup_token("Cc");
    let w = World::credentialed(&token);
    let file = w.root.join("other.env");
    std::fs::copy(w.root.join("bridge").join("credentials").join("setup-token.env"), &file).unwrap();
    let path = file.display().to_string();
    let o = run(w.cred_exec(&["--credential-file", &path, "--", "/bin/sh", "-c", "cat <&3"]), None);
    assert!(!text(&o.stderr).contains(&token[13..]), "stderr holds the token ({} bytes)", o.stderr.len());
    assert_token_off_disk(&w, &token);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout) == token, "stdout of {} bytes", o.stdout.len());
    assert!(!w.shim.spawns.credential().has(), "a one-command credential is not cached");
    let rows = w.audit("credential_deliver");
    assert_eq!((rows.len(), rows[0]["detail"]["source"].as_str()), (1, Some("file")));
}


/// A `claude` that answers as Anthropic refusing its token. Each start adds
/// a line to `$HOME/starts` (the spawn's HOME, the world's `home/`), so a
/// test counts the starts themselves, not the spawns the shim still lists.
/// It starts `sleep MARKER` in its group (a stand-in for retrying on: only a
/// stop ends it), prints three `api_retry` 401 lines (stream-json) and waits;
/// `stubborn` ignores TERM first, so only a KILL ends it and its marker;
/// `held` is stubborn and also leaves an escaper, a `sleep` in a group of its
/// own (job control) whose pid is in `$HOME/escaper`, holding its output;
/// `gated` prints the third line only once `$HOME/go` exists; `text` prints
/// the 401 line and exits 1; `fail` fails some other way.
const REFUSED_CLAUDE: &str = r#"#!/bin/sh
echo start >> "$HOME/starts"
case "$1" in
  text) echo 'API Error: 401 {"type":"error","error":{"type":"authentication_error"}}' >&2; exit 1 ;;
  fail) echo 'Error: something else went wrong' >&2; exit 1 ;;
  stubborn) trap '' TERM ;;
  held) trap '' TERM; set -m; sleep 30 & echo $! > "$HOME/escaper"; set +m ;;
esac
sleep MARKER &
for i in 1 2 3; do
  if [ "$i" = 3 ] && [ "$1" = gated ]; then
    until [ -e "$HOME/go" ]; do sleep 0.05; done
  fi
  printf '{"type":"system","subtype":"api_retry","attempt":%s,"error_status":401,"error":"authentication_failed"}\n' "$i"
  sleep 0.2
done
wait
"#;

/// [`REFUSED_CLAUDE`] whose stand-in for retrying on is `sleep marker`.
fn refused_claude(marker: &str) -> String {
    REFUSED_CLAUDE.replace("MARKER", marker)
}

/// How many times the world's [`REFUSED_CLAUDE`] started.
fn starts(w: &World) -> usize {
    std::fs::read_to_string(w.root.join("home").join("starts")).unwrap_or_default().lines().count()
}

/// The `/health/detail` reads the fake API answered so far.
fn detail_reads(w: &World) -> usize {
    w.fake().calls.iter().filter(|c| matches!(c, Call::HealthDetail { .. })).count()
}

/// S7 D6: the third retry 401 stops the command: TERM to its group ends a
/// `claude` that does not ignore it (and its marker) well before the KILL
/// due 3 s later; the child-gone check reads `/health/detail` after the stop
/// (the fake lists no spawn: gone; counted from before the third line, which
/// waits for the test's go-ahead, so the delivery's reads are not), and `vm
/// exec` exits 5 saying the command was stopped. The rejection is audited and
/// recorded against the seal, so the next credentialed command refuses at
/// once (exit 5) without a Touch ID; `claude` started exactly once (M29:
/// counted by its starts). The token is nowhere in either's output or under
/// the world's root.
#[test]
fn a_refused_token_stops_claude_with_exit_5_and_blocks_its_seal() {
    let token = setup_token("Dd");
    let m = marker(41);
    let w = World::credentialed_with(&token, Some(&refused_claude(&m)));
    let live = Live::start(w.cred_exec(&["--with-credential", "--", "claude", "gated", "-p", "hi", "--output-format", "stream-json"]));
    let mut out: Vec<String> = (0..2).map(|_| live.line()).collect();
    let reads = detail_reads(&w);
    std::fs::write(w.root.join("home").join("go"), "").unwrap();
    out.push(live.line());
    let t3 = Instant::now();
    let (status, rest, err) = live.finish();
    let took = t3.elapsed();
    out.extend(rest);
    assert_token_nowhere(&w, &Output { status, stdout: out.join("\n").into_bytes(), stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "{err}");
    assert_eq!(out.iter().filter(|l| l.contains("\"subtype\":\"api_retry\"")).count(), 3, "the output passed through up to the stop: {out:?}");
    assert!(took < Duration::from_millis(2500), "TERM ended it, not the KILL due 3 s after the third line: {took:?}");
    assert!(gone(&format!("^sleep {m}$")), "TERM reached its group");
    assert!(err.contains("ai-env: Anthropic refused the delivered setup-token (HTTP 401): the command was stopped and is not started again; seal a fresh one with `claude setup-token`, then `ai-env creds setup-token`"), "{err}");
    assert!(detail_reads(&w) > reads && !err.contains("was not seen gone"), "the child-gone check read /health/detail after the stop: {err}");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
    let before = w.decrypts();
    let o = run(w.cred_exec(&["--with-credential", "--", "claude", "-p", "hi"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 5, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("was refused by Anthropic") && text(&o.stderr).contains("ai-env creds setup-token"), "{}", text(&o.stderr));
    assert_eq!(w.decrypts(), before, "a known-bad seal costs no Touch ID");
    assert_eq!(starts(&w), 1, "never started again");
}

/// A text 401 counts with exit 1 (exit 5, recorded, the line saying the
/// command exited: nothing was stopped, M20); another failure passes its own
/// status through and records nothing. The token is nowhere in either's
/// output or under the world's root.
#[test]
fn a_text_401_is_exit_5_and_other_failures_keep_their_status() {
    let token = setup_token("Ee");
    let w = World::credentialed_with(&token, Some(&refused_claude(&marker(45))));
    let o = run(w.cred_exec(&["--with-credential", "--", "claude", "fail"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    assert!(w.audit("credential_rejected").is_empty());
    let o = run(w.cred_exec(&["--with-credential", "--", "claude", "text"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 5, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("API Error: 401"), "the command's own stderr passes through: {}", text(&o.stderr));
    let err = text(&o.stderr);
    assert!(err.contains("Anthropic refused the delivered setup-token (HTTP 401): the command exited and is not started again") && !err.contains("was stopped"), "{err}");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("text")));
}


/// S7: `vm smoke --exec --with-credential` runs on a vpc VM of its own and,
/// after the exec steps, delivers the token and runs `claude -p 'Reply OK'
/// --output-format json` with it: `cred_ok` when the answer is OK (here a
/// `claude` that answers only if fd 3 holds exactly the token, which it
/// knows by its sha256 alone). The vpc proxy steps cannot pass offline, so
/// only the credential step is judged here; the API step tried the world's
/// loopback proxy, nothing past this Mac. The endpoint runs the smoke's VM
/// on its first `/agent`, as the platform's run hook, and tells the shim
/// when the smoke terminated it. The token is nowhere in the output (the
/// record) or under the world's root.
#[test]
fn smoke_with_credential_delivers_and_judges_the_answer() {
    const CLAUDE: &str = "#!/bin/sh\nsha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }\ncase \"$1\" in\n  --version) echo '2.1.284 (Claude Code)' ;;\n  -p) [ \"$(sha <&3)\" = WANT ] && printf '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"OK\"}\\n' ;;\nesac\n";
    let token = setup_token("Ff");
    let w = World::platform(Some(&CLAUDE.replace("WANT", &sha256(token.as_bytes()))));
    w.seed_credentials(&token, "1.0");
    let o = run(w.sealed_cmd(&["vm", "smoke", "--exec", "--with-credential", "--json"]), None);
    assert_token_nowhere(&w, &o, &token);
    let err = text(&o.stderr);
    let rec: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}\n{err}", text(&o.stdout)));
    assert_eq!((rec["cred_ok"].as_bool(), rec["cred_is_error"].as_bool(), rec["cred_token"].as_str()), (Some(true), Some(false), Some("setup-token")), "{err}");
    assert!(err.contains("(credential: setup-token): exit 0, answered OK"), "{err}");
    let problems: Vec<&str> = rec["exec_problems"].as_array().map(|a| a.iter().filter_map(|p| p.as_str()).collect()).unwrap_or_default();
    assert!(problems.iter().all(|p| !p.contains("Reply OK")), "the credential step passed: {problems:?}");
    let curl = problems.iter().find(|p| p.starts_with("exec curl ")).copied().unwrap_or_default();
    assert!(curl.contains("127.0.0.1 port 9"), "the API step tried the world's loopback proxy: {curl}");
    assert_eq!(w.audit("credential_deliver").len(), 1);
    let id = rec["id"].as_str().unwrap();
    assert!(w.fake().vms[id].state.is_terminal(), "the smoke's VM is terminated");
    wait_for("the shim told of the terminate", || w.endpoint.hooks().len() >= 2);
    assert_eq!(hook_names(&w, id), [("run", 200), ("terminate", 200)], "the endpoint ran the smoke's VM, then told the shim it ended");
}

/// The hooks the endpoint posted for `vm` as the platform: (name, status).
fn hook_names(w: &World, vm: &str) -> Vec<(&'static str, u16)> {
    w.endpoint.hooks().into_iter().filter(|h| h.vm == vm).map(|h| (h.name, h.status)).collect()
}

/// S7: `vm warm WORKSPACE` starts the workspace's vpc VM (the endpoint runs
/// it on its first `/agent`, as the platform's run hook), reads its
/// `/health`, passes the gate and delivers the setup-token with no spawn; a
/// second `vm warm` reuses the VM and finds it held: nothing is sent again.
/// After each, the token is nowhere in its output or under the world's root.
#[test]
fn warm_delivers_ahead_of_time_and_finds_it_held_next_time() {
    let token = setup_token("Gg");
    let w = World::platform(None);
    w.seed_credentials(&token, "1.0");
    let ws = w.root.join("ws").join("project");
    std::fs::create_dir_all(&ws).unwrap();
    let ws = ws.display().to_string();
    let o = run(w.sealed_cmd(&["vm", "warm", &ws]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let id = w.fake().vms.keys().next().cloned().expect("the workspace's VM");
    assert_eq!(hook_names(&w, &id), [("run", 200)], "the endpoint ran the VM on its first /agent");
    assert!(text(&o.stdout).contains(" now holds the setup-token (seal "), "{}", text(&o.stdout));
    assert!(w.shim.spawns.credential().has(), "the VM holds it");
    assert!(w.shim.spawns.status(None).is_empty(), "warming starts nothing");
    let rows = w.audit("credential_deliver");
    assert_eq!((rows.len(), rows[0]["detail"]["source"].as_str()), (1, Some("warm")));
    let o = run(w.sealed_cmd(&["vm", "warm", &ws, "--json"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o.stdout)));
    assert_eq!((v["warmed"].as_str(), v["reused"].as_bool()), (Some("already_held"), Some(true)));
    assert_eq!(w.audit("credential_deliver").len(), 1, "nothing sent again");
}

// ---- S7: the emulated platform (the endpoint's auto-run and hook bridge) and `lab run` -------

/// The endpoint as the platform's hook client, driven by the fake's state
/// alone. `vm run` posts nothing; the VM's first `/agent` runs it (`vm exec`
/// works with no `/run` from the test). A suspend and a resume recorded
/// between two looks both reach the shim, in order (the state alone shows
/// no move). A suspension with no call behind it (the state edited)
/// reaches it, and the next `vm exec`'s auto-resume posts `/resume` before
/// its request goes on. A terminate the fake refused (a scripted failure,
/// recorded all the same) is no move: nothing is posted, and the next `vm
/// exec` runs. A terminate ends it. Each hook once, each answered 200, each
/// seen by the shim itself.
#[test]
fn the_platform_runs_the_vm_on_its_first_agent_and_tells_the_shim_each_move() {
    let w = World::platform(None).with_vm(&[]);
    let id = w.id.clone();
    assert!(w.endpoint.hooks().is_empty(), "vm run posts no hook");
    let o = run(w.exec(&["--", "sh", "-c", "echo ran"]), None);
    assert_eq!((code(&o), text(&o.stdout).as_str()), (0, "ran\n"), "{}", text(&o.stderr));
    assert_eq!(hook_names(&w, &id), [("run", 200)], "the first /agent ran the VM");
    let upgraded = |a: &fake_endpoint::Attempt| (a.status, a.hooks);
    assert_eq!(w.endpoint.attempts().iter().map(upgraded).collect::<Vec<_>>(), [(101, 1)], "/run was answered before the request went on");
    w.update_fake(|s| {
        s.suspend(&id).unwrap();
        s.resume(&id).unwrap();
    });
    wait_for("the suspend and the resume", || w.endpoint.hooks().len() >= 3);
    assert_eq!(hook_names(&w, &id), [("run", 200), ("suspend", 200), ("resume", 200)], "replayed from the recorded calls");
    w.update_fake(|s| s.vms.get_mut(&id).unwrap().state = VmState::Suspended);
    wait_for("the suspension with no call", || w.endpoint.hooks().len() >= 4);
    let o = run(w.exec(&["--", "true"]), None);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(w.fake().vms[&id].state, VmState::Running, "the check resumed it");
    assert_eq!(hook_names(&w, &id), [("run", 200), ("suspend", 200), ("resume", 200), ("suspend", 200), ("resume", 200)], "the auto-resume's /resume");
    assert_eq!(w.endpoint.attempts().iter().map(upgraded).collect::<Vec<_>>(), [(101, 1), (101, 5)], "the auto-resume's /resume was answered before the request went on");
    w.update_fake(|s| {
        s.failures.push_back(FakeFailure { kind: "throttled".into(), message: "Rate exceeded".into(), on: Some("terminate".into()), after_effect: false });
        assert!(s.terminate(&id).is_err(), "the scripted failure");
    });
    let o = run(w.exec(&["--", "true"]), None);
    assert_eq!(code(&o), 0, "the refused terminate drained nothing: {}", text(&o.stderr));
    assert_eq!(w.endpoint.attempts().iter().map(upgraded).collect::<Vec<_>>(), [(101, 1), (101, 5), (101, 5)], "nothing posted for it");
    w.update_fake(|s| s.terminate(&id).unwrap());
    wait_for("the terminate", || w.endpoint.hooks().len() >= 6);
    assert_eq!(hook_names(&w, &id).last(), Some(&("terminate", 200)));
    assert_eq!(w.endpoint.hooks().len(), 6, "each hook once");
    assert!(w.shim.is_draining(), "the shim stops on /terminate");
    let seen: Vec<String> = w.shim.hook_peers.lock().unwrap().keys().cloned().collect();
    assert_eq!(seen, ["resume", "run", "suspend", "terminate"], "the shim saw each hook");
    assert_eq!(w.endpoint.resumes(), 2);
}

/// What a VM is owed goes out before its next request is checked, not only
/// on the endpoint's tick: with the tick stopped (nothing is posted between
/// requests meanwhile), a suspend reaches the shim as the next `vm exec`
/// comes in, ahead of the check that auto-resumes the VM, and that
/// auto-resume's `/resume` follows, both answered before the request goes on.
#[test]
fn the_platform_posts_what_a_vm_is_owed_before_its_next_request_is_checked() {
    let w = World::platform(None).with_vm(&[]);
    let id = w.id.clone();
    let o = run(w.exec(&["--", "true"]), None);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    w.endpoint.ticking(false);
    w.update_fake(|s| s.suspend(&id).unwrap());
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(hook_names(&w, &id), [("run", 200)], "ten ticks' time with the tick stopped: nothing posted");
    let o = run(w.exec(&["--", "true"]), None);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(w.fake().vms[&id].state, VmState::Running, "the check resumed it");
    assert_eq!(hook_names(&w, &id), [("run", 200), ("suspend", 200), ("resume", 200)]);
    let upgraded: Vec<(u16, usize)> = w.endpoint.attempts().iter().map(|a| (a.status, a.hooks)).collect();
    assert_eq!(upgraded, [(101, 1), (101, 3)], "both answered before the request went on");
}

/// A `claude` for the S7 probes that knows the token only by its sha256
/// (`WANT`), read as `GOT` says: "logged in" only then, when it answers
/// `claude -p … --output-format json` with an OK result, and as a
/// stream-json host's claude each `initialize` with its control response and
/// each user message with an OK result, until EOF; otherwise it answers as a
/// CLI that is not logged in (exit 1).
const PROBE_CLAUDE: &str = r#"#!/bin/sh
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }
GOT
if [ "$got" != WANT ]; then
  printf '{"type":"result","subtype":"error_during_execution","is_error":true,"result":"Not logged in"}\n'
  exit 1
fi
case " $* " in
  *" --input-format stream-json "*)
    while IFS= read -r line; do
      case "$line" in
        *'"control_request"'*)
          id=$(printf '%s\n' "$line" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
          printf '{"type":"control_response","response":{"subtype":"success","request_id":"%s","response":{}}}\n' "$id" ;;
        *'"type":"user"'*) printf '{"type":"result","subtype":"success","is_error":false,"result":"OK"}\n' ;;
      esac
    done ;;
  *) printf '{"type":"result","subtype":"success","is_error":false,"result":"OK"}\n' ;;
esac
"#;

/// [`PROBE_CLAUDE`] for `token`, which it reads from fd 3 alone (`fd`: and
/// only with nothing under `CLAUDE_CODE_OAUTH_TOKEN`, so its answer also says
/// the spawn's environment held no token) or from `CLAUDE_CODE_OAUTH_TOKEN`
/// alone (`env`).
fn probe_claude(token: &str, how: &str) -> String {
    let got = if how == "fd" { "got=$([ -z \"${CLAUDE_CODE_OAUTH_TOKEN:-}\" ] && sha 2>/dev/null <&3)" } else { "got=$(printf %s \"${CLAUDE_CODE_OAUTH_TOKEN:-}\" | sha)" };
    PROBE_CLAUDE.replace("GOT", got).replace("WANT", &sha256(token.as_bytes()))
}

/// `s` with `token` (and its part after the kind prefix) masked, for an assertion's message.
fn masked(s: &str, token: &str) -> String {
    s.replace(token, "<the token>").replace(&token[13..], "<the token's tail>")
}

/// The newest row `ai-env lab run` recorded for `probe` in the world's `lab/probes.jsonl`.
fn probe_row(w: &World, probe: &str) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(w.root.join("bridge").join("lab").join("probes.jsonl")).unwrap_or_default();
    text.lines().rev().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).find(|r| r["probe"] == probe)
}

/// The files under `dir` (recursively, links not followed) whose bytes hold `needle`.
fn files_holding(dir: &std::path::Path, needle: &[u8]) -> Vec<PathBuf> {
    let (mut out, mut todo) = (Vec::new(), vec![dir.to_path_buf()]);
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => todo.push(e.path()),
                Ok(t) if t.is_file() && std::fs::read(e.path()).is_ok_and(|b| b.windows(needle.len()).any(|x| x == needle)) => out.push(e.path()),
                _ => {}
            }
        }
    }
    out
}

/// The token's part after the kind prefix is nowhere in `o`'s output nor in any file under the world's root.
fn assert_token_nowhere(w: &World, o: &Output, token: &str) {
    let tail = &token[13..];
    assert!(!text(&o.stdout).contains(tail) && !text(&o.stderr).contains(tail), "the output holds the token ({} and {} bytes)", o.stdout.len(), o.stderr.len());
    assert_token_off_disk(w, token);
}

/// The token's part after the kind prefix is in no file under the world's
/// root (for a command whose stdout holds the token by design).
fn assert_token_off_disk(w: &World, token: &str) {
    let leaks = files_holding(&w.root, &token.as_bytes()[13..]);
    assert!(leaks.is_empty(), "{} files hold the token: {leaks:?}", leaks.len());
}

/// S7 T7.3 offline: `ai-env lab run fd-delivery` end to end on the emulated
/// platform (the fake API and the agent address; the endpoint runs the VM
/// and bridges its hooks). The scan spawn reads the whole token on fd 3,
/// with nothing under its name in the environment (here the scan reads
/// `env`: no /proc); claude, as a stream-json host's, answers with fd 3
/// alone (it knows the token only by its sha256, and answers only with
/// nothing under its name in its environment): fd-honoured. The probe's
/// suspend and resume reach the shim: its cache held the token when
/// `/suspend` came and was empty by `/resume`; `/terminate` follows the
/// terminate guard. Two Touch IDs (the runtime key, then the token), one
/// delivery (the claude spawn was served from the cache), and the token
/// nowhere in the output or under the world's root.
#[test]
fn lab_fd_delivery_runs_offline_and_its_suspend_empties_the_shims_cache() {
    let token = setup_token("Hh");
    let w = World::platform(Some(&probe_claude(&token, "fd")));
    w.seed_credentials(&token, "1.0");
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (shim, seen) = (w.shim.clone(), held.clone());
    w.endpoint.before_hook(move |_, hook| seen.lock().unwrap().push((hook.to_string(), shim.spawns.credential().has())));
    let before = w.decrypts();
    let o = run(w.sealed_cmd(&["lab", "run", "fd-delivery"]), None);
    assert_eq!(code(&o), 0, "{}", masked(&text(&o.stderr), &token));
    let row = probe_row(&w, "fd-delivery").expect("a fd-delivery row");
    let note = masked(row["note"].as_str().unwrap_or_default(), &token);
    assert_eq!(row["verdict"], "fd-honoured", "{note}");
    assert!(note.contains(&format!("environ entries with the token's name or a value of its kind 0, fd 3 {} bytes; claude via fd answered, {}", token.len(), environs_words())), "{note}");
    assert!(note.contains("; via env not tried; "), "{note}");
    assert!(note.ends_with("has_credentials after a suspend and a resume: false (the fake API's /health/detail, not the shim's)"), "{note}");
    let id = w.fake().vms.keys().next().cloned().expect("the probe's VM");
    assert!(w.fake().vms[&id].state.is_terminal(), "the terminate guard ended it");
    wait_for("the shim told of the terminate", || w.endpoint.hooks().len() >= 4);
    assert_eq!(hook_names(&w, &id), [("run", 200), ("suspend", 200), ("resume", 200), ("terminate", 200)]);
    let held = held.lock().unwrap().clone();
    let held: Vec<(&str, bool)> = held.iter().map(|(h, has)| (h.as_str(), *has)).collect();
    assert_eq!(held, [("run", false), ("suspend", true), ("resume", false), ("terminate", false)], "what the shim's cache held as each hook came");
    assert!(!w.shim.spawns.credential().has());
    assert_eq!(w.decrypts() - before, 2, "the runtime key and the token");
    assert_eq!(w.audit("credential_deliver").len(), 1, "delivered once: the claude spawn named the cached copy");
    assert_token_nowhere(&w, &o, &token);
}

/// S7 T7.3's other answer offline: a `claude` that takes the token only from
/// its environment does not answer with fd 3, so the probe asks again with
/// the token in that one claude's environment, says so in the note, and
/// records env-only — not the expected verdict, so `lab run` exits 1 after
/// recording it. The token is nowhere in the output or under the world's root.
#[test]
fn lab_fd_delivery_records_env_only_for_a_claude_that_reads_only_its_environment() {
    let token = setup_token("Jj");
    let w = World::platform(Some(&probe_claude(&token, "env")));
    w.seed_credentials(&token, "1.0");
    let o = run(w.sealed_cmd(&["lab", "run", "fd-delivery"]), None);
    let err = masked(&text(&o.stderr), &token);
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.contains("probe verdict differs from the expectation: fd-delivery=env-only (expected fd-honoured)"), "{err}");
    let row = probe_row(&w, "fd-delivery").expect("the env-only row is recorded");
    let note = masked(row["note"].as_str().unwrap_or_default(), &token);
    assert_eq!(row["verdict"], "env-only", "{note}");
    assert!(note.contains(&format!("fd 3 {} bytes; claude via fd did not answer, its environments while it ran: ", token.len())), "{note}");
    assert!(note.contains("; via env (the token put in that one claude's environment, to classify) answered; "), "{note}");
    let id = w.fake().vms.keys().next().cloned().expect("the probe's VM");
    wait_for("the shim told of the terminate", || w.endpoint.hooks().len() >= 4);
    assert_eq!(hook_names(&w, &id), [("run", 200), ("suspend", 200), ("resume", 200), ("terminate", 200)]);
    assert_token_nowhere(&w, &o, &token);
}

/// S7 T7.7 offline: `ai-env lab run init-budget` on the emulated platform
/// times a cold credentialed claude (the gate, the unseal, the delivery and
/// the spawn) and a warm one (the VM holds the token) to their answers to
/// `initialize` (a `claude` that answers only with the token on fd 3):
/// within-budget, with each leg in the note, the token's own unseal among
/// them (without combined.env); one delivery for both spawns, no suspend,
/// and the shim told of the terminate.
#[test]
fn lab_init_budget_runs_offline_within_budget() {
    let token = setup_token("Kk");
    let w = World::platform(Some(&probe_claude(&token, "fd")));
    w.seed_credentials(&token, "1.0");
    let before = w.decrypts();
    let o = run(w.sealed_cmd(&["lab", "run", "init-budget"]), None);
    assert_eq!(code(&o), 0, "{}", masked(&text(&o.stderr), &token));
    let row = probe_row(&w, "init-budget").expect("an init-budget row");
    let note = masked(row["note"].as_str().unwrap_or_default(), &token);
    assert_eq!(row["verdict"], "within-budget", "{note}");
    assert!(note.contains(" ms, the sum of RUNNING and /health ") && note.contains(" (of which the token's unseal, its own Touch ID, ") && note.contains("), the delivery and spawn to the initialize answer "), "{note}");
    assert!(note.contains("; warm ") && note.contains("not counted, each session's close after its answer: ") && note.contains("budgets 30000 and 5000 ms"), "{note}");
    assert_eq!(w.decrypts() - before, 2, "the runtime key and the token");
    assert_eq!(w.audit("credential_deliver").len(), 1, "the warm spawn named the cached copy");
    let id = w.fake().vms.keys().next().cloned().expect("the probe's VM");
    wait_for("the shim told of the terminate", || w.endpoint.hooks().len() >= 2);
    assert_eq!(hook_names(&w, &id), [("run", 200), ("terminate", 200)]);
    assert_token_nowhere(&w, &o, &token);
}

/// The credential probes take the fake for the service only on the
/// emulated platform: without the agent address `lab run fd-delivery`
/// refuses as the S6 probes do (exit 9, nothing recorded, its VM ended,
/// nothing dialed), and with it an S6 probe still refuses. After each run,
/// the token is nowhere in its output or under the world's root.
#[test]
fn lab_credential_probes_need_the_emulated_platform_and_s6_probes_still_refuse_it() {
    let token = setup_token("Mm");
    let w = World::platform(Some(&probe_claude(&token, "fd")));
    w.seed_credentials(&token, "1.0");
    let mut cmd = w.sealed_cmd(&["lab", "run", "fd-delivery"]);
    cmd.env_remove("AI_ENV_BRIDGE_LAB_AGENT_ADDR");
    let o = run(cmd, None);
    assert_token_nowhere(&w, &o, &token);
    let err = text(&o.stderr);
    assert_eq!(code(&o), 9, "{err}");
    assert!(err.contains("lab run fd-delivery: the file-backed fake has no shim behind its endpoint"), "{err}");
    assert!(probe_row(&w, "fd-delivery").is_none(), "nothing recorded");
    let o = run(w.sealed_cmd(&["lab", "run", "e0"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 9, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("lab run e0: the file-backed fake has no shim behind its endpoint"), "{}", text(&o.stderr));
    assert!(probe_row(&w, "e0").is_none(), "nothing recorded");
    let st = w.fake();
    assert!(st.vms.len() == 2 && st.vms.values().all(|v| v.state.is_terminal()), "each probe started its VM and ended it: {:?}", st.vms.values().map(|v| v.state.as_str()).collect::<Vec<_>>());
    assert_eq!(w.endpoint.accepted(), 0, "nothing was dialed");
    assert!(w.endpoint.hooks().is_empty());
}

// ---- S7 fix wave: delivery ----

/// M38: a `creds setup-token` that seals a new token while a credentialed
/// `vm exec` waits for a Touch ID (here the runtime key's) is caught when
/// that command unseals the token: exit 5 saying so, and nothing sent (no
/// `credential_deliver`, nothing cached), never the new token under the old
/// seal id. The run after it delivers the new token under its own seal id.
/// Neither token is in any run's output (but that run's stdout, which is the
/// new one by design) or under the world's root.
#[test]
fn a_token_sealed_anew_while_a_command_waits_is_refused_never_sent_under_the_old_seal() {
    let (old, new) = (setup_token("Na"), setup_token("Pa"));
    let w = World::credentialed(&old);
    let granted = w.root.join("touch-id-granted");
    let before = w.decrypts();
    let mut cmd = w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3"]);
    cmd.env("FAKE_AGE_WAIT_FILE", &granted);
    let waiting = std::thread::spawn(move || run(cmd, None));
    wait_for("the runtime key's Touch ID", || w.decrypts() > before);
    let o = run(w.sealed_cmd(&["creds", "setup-token", "--stdin", "--no-combined"]), Some(format!("{new}\n").into_bytes()));
    for token in [&old, &new] {
        assert_token_nowhere(&w, &o, token);
    }
    assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
    std::fs::write(&granted, "").unwrap();
    let o = waiting.join().unwrap();
    for token in [&old, &new] {
        assert_token_nowhere(&w, &o, token);
    }
    let err = text(&o.stderr);
    assert_eq!(code(&o), 5, "{err}");
    assert!(err.contains("setup-token.env was sealed anew while this command ran") && err.contains("nothing was sent; run the command again"), "{err}");
    assert!(w.audit("credential_deliver").is_empty() && !w.shim.spawns.credential().has(), "nothing was sent");
    let o = run(w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3"]), None);
    // Its stdout is the new token by design: stderr holds neither token, and stdout not the old one.
    assert!(!text(&o.stdout).contains(&old[13..]) && [&old, &new].iter().all(|t| !text(&o.stderr).contains(&t[13..])), "the output holds a token ({} and {} bytes)", o.stdout.len(), o.stderr.len());
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout) == new, "the new token: stdout of {} bytes", o.stdout.len());
    let tag = ai_env_cli::bridge::agent::credential::seal_tag(&w.root.join("bridge").join("credentials").join("setup-token.env")).unwrap();
    assert_eq!(w.row().credential_tag.as_deref(), Some(tag.as_str()), "recorded under its own seal id");
    for token in [&old, &new] {
        assert_token_off_disk(&w, token);
    }
}

/// M50: a delivery whose row cannot record it (here `state/vms` read-only)
/// still runs, and stderr says, once, that the VM may hold the token though
/// `creds status` and `creds forget` will not list it, naming `vm
/// terminate`. The token is nowhere in the output or under the world's root.
#[test]
fn a_delivery_its_row_cannot_record_is_a_warning_on_stderr() {
    use std::os::unix::fs::PermissionsExt as _;
    // SAFETY: geteuid cannot fail. Root writes through the mode: nothing to show there.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let token = setup_token("Qa");
    let w = World::credentialed(&token);
    let vms = w.root.join("bridge").join("state").join("vms");
    std::fs::set_permissions(&vms, std::fs::Permissions::from_mode(0o500)).unwrap();
    let o = run(w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3 >/dev/null"]), None);
    std::fs::set_permissions(&vms, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_token_nowhere(&w, &o, &token);
    let err = text(&o.stderr);
    assert_eq!(code(&o), 0, "{err}");
    let says = format!("ai-env: warning: {} may hold the setup-token (seal ", w.id);
    assert!(err.matches(&says).count() == 1 && err.contains("will not list it; only `ai-env vm terminate ") && err.contains(&format!("vm terminate {}`", w.id)), "{err}");
    assert!(w.row().credential_at.is_none(), "the record failed");
    assert_eq!(w.audit("credential_deliver").len(), 1, "delivered and acknowledged");
}

/// M50: a registry row that cannot be read is never taken for no holder,
/// and never hides the holders the other rows name. `creds status` lists it
/// as a `[!! ]` line naming the file once with the parser's words (no error
/// class), beside any holder (with none, never "none"); its `--json` gives it
/// in `holders_unreadable` beside `holders`; `creds forget` prints it beside
/// the `vm terminate` lines and counts it in its audit row. None of this is
/// left to stderr, where a `--json` reader would miss it. The token is
/// nowhere in any of these commands' output or under the world's root.
#[test]
fn a_registry_row_that_cannot_be_read_is_never_taken_for_no_holder() {
    let token = setup_token("Sa");
    let w = World::credentialed(&token);
    let broken = "microvm-00000000-0000-4000-8000-0000000000c8.toml";
    std::fs::write(w.root.join("bridge").join("state").join("vms").join(broken), "status = [broken").unwrap();
    let says = "a VM registry row cannot be read, so its VM may hold the token unlisted: ";
    // `<path>: <parser message>`: the file named once, no `config:`.
    let named = |l: &str| l.matches(broken).count() == 1 && l.contains(&format!("{broken}: TOML parse error")) && !l.contains("config:");
    let listed = |out: &str| out.lines().any(|l| l.starts_with(&format!("[!! ] {says}")) && named(l));
    let o = run(w.cmd(&["creds", "status"]), None);
    assert_token_nowhere(&w, &o, &token);
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(!out.contains("VMs that may hold the token: none") && listed(&out), "{out}");
    let o = run(w.cred_exec(&["--with-credential", "--", "true"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let o = run(w.cmd(&["creds", "status"]), None);
    assert_token_nowhere(&w, &o, &token);
    let out = text(&o.stdout);
    assert!(code(&o) == 0 && !text(&o.stderr).contains(broken), "{}", text(&o.stderr));
    assert!(out.contains(&format!("[!! ] {} (running) received the token at ", w.id)) && listed(&out), "{out}");
    let o = run(w.cmd(&["creds", "status", "--json"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert!(code(&o) == 0 && !text(&o.stderr).contains(broken), "{}", text(&o.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(doc["holders"].as_array().map(|h| h.iter().map(|h| h["id"].as_str().unwrap_or_default().to_string()).collect::<Vec<_>>()), Some(vec![w.id.clone()]), "{doc}");
    assert!(doc["holders_unreadable"].as_array().is_some_and(|u| u.len() == 1 && u[0].as_str().is_some_and(named)), "{doc}");
    for args in [&["creds", "forget"][..], &["creds", "forget", "--yes"]] {
        let o = run(w.cmd(args), None);
        assert_token_nowhere(&w, &o, &token);
        let out = text(&o.stdout);
        assert!(code(&o) == 0 && !text(&o.stderr).contains(broken), "{}", text(&o.stderr));
        assert!(out.contains(&format!("only terminating it clears its copies: ai-env vm terminate {}", w.id)), "{out}");
        assert!(out.lines().any(|l| l.starts_with(says) && named(l) && l.ends_with("; only terminating its VM clears its copies (`ai-env vm list` shows the VMs)")), "{out}");
    }
    let forgot = w.audit("creds_forget");
    assert!(forgot.len() == 1 && forgot[0]["detail"]["holders"] == "1" && forgot[0]["detail"]["holders_unreadable"] == "1", "the holder and the unreadable row are counted: {forgot:?}");
}

// ---- S7 fix wave: auth401 ----

/// M29: a refused `claude` that ignores TERM is KILLed 3 s after the third
/// retry 401: its marker (in its group, TERM ignored) dies about 3 s after
/// that line, not at once and not by the final detach's own ladder (whose
/// KILL comes 1.2 s after the detach, about 4.2 s); exit 5 saying it was
/// stopped (the child-gone check saw it gone), one start, and the token
/// nowhere in the output or under the world's root.
#[test]
fn a_refused_token_that_ignores_term_is_killed_3_s_later() {
    let token = setup_token("Xa");
    let m = marker(42);
    let w = World::credentialed_with(&token, Some(&refused_claude(&m)));
    let live = Live::start(w.cred_exec(&["--with-credential", "--", "claude", "stubborn", "--output-format", "stream-json"]));
    let mut out: Vec<String> = (0..3).map(|_| live.line()).collect();
    let t3 = Instant::now();
    let pattern = format!("^sleep {m}$");
    assert!(running(&pattern), "the stubborn claude's marker runs");
    let died = loop {
        if !running(&pattern) {
            break t3.elapsed();
        }
        assert!(t3.elapsed() < Duration::from_secs(10), "the marker outlived the stop");
        std::thread::sleep(Duration::from_millis(20));
    };
    let (status, rest, err) = live.finish();
    out.extend(rest);
    assert_token_nowhere(&w, &Output { status, stdout: out.join("\n").into_bytes(), stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "{err}");
    assert!(died >= Duration::from_millis(2500) && died < Duration::from_millis(3900), "KILL 3 s after the third retry 401 (the ladder's own would be about 4.2 s): {died:?}");
    assert_eq!(out.iter().filter(|l| l.contains("\"subtype\":\"api_retry\"")).count(), 3, "{out:?}");
    assert!(err.contains("Anthropic refused the delivered setup-token (HTTP 401): the command was stopped and is not started again"), "{err}");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
}

/// M20: the stop of a refused `claude` that cannot reach the VM (the
/// command ignores TERM, then the socket is cut and every redial is
/// throttled) with a `/health/detail` that cannot be read: `vm exec` still
/// ends, bounded (KILL due at 3 s, held at most 1 s for the link, then the
/// final detach and the 5 s child-gone check: without that detach it would
/// wait out the throttled redials), names `ai-env vm terminate`, and exits
/// 5 without claiming a stop it did not see. The command does run on.
#[test]
fn a_refused_token_whose_stop_cannot_reach_the_vm_names_vm_terminate() {
    let token = setup_token("Xb");
    let m = marker(43);
    let w = World::credentialed_with(&token, Some(&refused_claude(&m)));
    let live = Live::start(w.cred_exec(&["--with-credential", "--detach-grace", "30", "--", "claude", "stubborn", "--output-format", "stream-json"]));
    let mut out: Vec<String> = (0..3).map(|_| live.line()).collect();
    w.update_fake(|s| s.failures.extend((0..64).map(|_| FakeFailure { kind: "endpoint".into(), message: "the endpoint did not answer".into(), on: Some("health_detail".into()), after_effect: false })));
    let reads = detail_reads(&w);
    let t = Instant::now();
    w.cut_throttled("100", 3);
    let (status, rest, err) = live.finish();
    let took = t.elapsed();
    out.extend(rest);
    assert_token_nowhere(&w, &Output { status, stdout: out.join("\n").into_bytes(), stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "{err}");
    assert!(took >= Duration::from_secs(5) && took < Duration::from_secs(15), "bounded, and the check waited its 5 s: {took:?}");
    let ids = w.spawn_ids();
    assert_eq!(ids.len(), 1, "the shim still holds the spawn");
    assert!(err.contains(&format!("ai-env: the stop could not reach {}", w.id)), "{err}");
    assert!(err.contains(&format!("ai-env: spawn {s} was not seen gone from {vm} within 5 s (it holds the refused token): `ai-env vm terminate {vm}` ends it", s = ids[0], vm = w.id)), "{err}");
    assert!(err.contains("Anthropic refused the delivered setup-token (HTTP 401): the stop was sent, but the command was not seen to end (see above); it is not started again") && !err.contains("was stopped"), "{err}");
    assert!(detail_reads(&w) >= reads + 2, "the check read /health/detail until its time was up");
    assert!(running(&format!("^sleep {m}$")), "the KILL never reached the VM: the command runs on under its grace");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
}

/// M15: a `--credential-file` container whose token Anthropic refuses is
/// named in the exit-5 line with advice about it alone (the sealed
/// setup-token is not affected); the next command given it refuses at once
/// in the same terms, without a Touch ID; the sealed setup-token still
/// reaches a command. The refused token is in no output and neither token
/// is under the world's root.
#[test]
fn a_refused_credential_file_names_that_file_and_spares_the_sealed_token() {
    let refused = setup_token("Xc");
    let w = World::credentialed_with(&refused, Some(&refused_claude(&marker(44))));
    let file = w.root.join("other.env");
    std::fs::copy(w.root.join("bridge").join("credentials").join("setup-token.env"), &file).unwrap();
    // The setup-token is sealed anew with another token: other.env keeps a seal of its own.
    let sealed = setup_token("Xd");
    let o = run(w.sealed_cmd(&["creds", "setup-token", "--stdin", "--no-combined"]), Some(format!("{sealed}\n").into_bytes()));
    assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
    let path = file.display().to_string();
    let o = run(w.cred_exec(&["--credential-file", &path, "--", "claude", "-p", "hi", "--output-format", "stream-json"]), None);
    assert_token_nowhere(&w, &o, &refused);
    assert_eq!(code(&o), 5, "{}", text(&o.stderr));
    let err = text(&o.stderr);
    assert!(err.contains(&format!("ai-env: Anthropic refused the delivered setup-token from {path} (HTTP 401): the command was stopped")) && err.contains("give another one (the sealed setup-token is not affected)") && !err.contains("ai-env creds setup-token"), "{err}");
    let before = w.decrypts();
    let o = run(w.cred_exec(&["--credential-file", &path, "--", "claude", "-p", "hi"]), None);
    assert_token_nowhere(&w, &o, &refused);
    assert_eq!(code(&o), 5, "{}", text(&o.stderr));
    let err = text(&o.stderr);
    assert!(err.contains("the token given with --credential-file (seal ") && err.contains("the sealed setup-token is not affected; nothing was unsealed") && !err.contains("ai-env creds setup-token"), "{err}");
    assert_eq!(w.decrypts(), before, "a known-bad container costs no Touch ID");
    let o = run(w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3"]), None);
    assert!(!text(&o.stderr).contains(&sealed[13..]) && !text(&o.stderr).contains(&refused[13..]) && !text(&o.stdout).contains(&refused[13..]), "a token in the output ({} and {} bytes)", o.stdout.len(), o.stderr.len());
    assert_eq!(code(&o), 0, "the sealed setup-token is not refused: {}", text(&o.stderr));
    assert!(text(&o.stdout) == sealed, "stdout of {} bytes", o.stdout.len());
    assert_token_off_disk(&w, &refused);
    assert_token_off_disk(&w, &sealed);
    assert_eq!(starts(&w), 1, "claude started once");
}

/// M52: `vm smoke --exec --with-credential` runs `vm exec`'s watch over its
/// claude's output: a result refusing the token, then exit 1, fails the
/// credential step naming the refusal, audits `credential_rejected` (text)
/// and records it against the seal, so the next smoke refuses before any VM
/// or Touch ID (exit 5). The token is nowhere in either's output or under
/// the world's root.
#[test]
fn a_smoke_whose_token_is_refused_records_the_rejection() {
    const CLAUDE: &str = r#"#!/bin/sh
case "$1" in
  --version) echo '2.1.284 (Claude Code)' ;;
  -p) printf '{"type":"result","subtype":"success","is_error":true,"result":"API Error: 401 {}"}\n'; exit 1 ;;
esac
"#;
    let token = setup_token("Xe");
    let w = World::platform(Some(CLAUDE));
    w.seed_credentials(&token, "1.0");
    let o = run(w.sealed_cmd(&["vm", "smoke", "--exec", "--with-credential", "--json"]), None);
    assert_token_nowhere(&w, &o, &token);
    let err = text(&o.stderr);
    let rec: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}\n{err}", text(&o.stdout)));
    assert_eq!((rec["cred_ok"].as_bool(), rec["cred_is_error"].as_bool()), (Some(false), Some(true)), "{err}");
    assert!(err.contains("(credential: setup-token): exit 1, Anthropic refused the delivered setup-token (HTTP 401), which is recorded"), "{err}");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("text")));
    let (decrypts, vms) = (w.decrypts(), w.fake().vms.len());
    let o = run(w.sealed_cmd(&["vm", "smoke", "--exec", "--with-credential", "--json"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 5, "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("was refused by Anthropic") && text(&o.stderr).contains("ai-env creds setup-token"), "{}", text(&o.stderr));
    assert_eq!((w.decrypts(), w.fake().vms.len()), (decrypts, vms), "refused before any Touch ID or VM");
}

/// M14 through the binary: a credentialed `claude` (stream-json) whose
/// requests each meet one transient retry 401 and then answer is never
/// stopped: its own status (0) and every line pass through, nothing is
/// audited or recorded, and the next credentialed command is not refused.
/// The token is nowhere in either's output or under the world's root.
#[test]
fn transient_401s_a_claude_recovered_from_never_stop_it() {
    const CLAUDE: &str = r#"#!/bin/sh
for turn in 1 2 3 4; do
  printf '{"type":"system","subtype":"api_retry","attempt":1,"error_status":401,"error":"authentication_failed"}\n'
  printf '{"type":"assistant","message":{"model":"claude-x","role":"assistant","content":[{"type":"text","text":"ok"}]}}\n'
  printf '{"type":"result","subtype":"success","is_error":false,"result":"ok"}\n'
done
"#;
    let token = setup_token("Xf");
    let w = World::credentialed_with(&token, Some(CLAUDE));
    let o = run(w.cred_exec(&["--with-credential", "--", "claude", "-p", "hi", "--output-format", "stream-json", "--verbose"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout).lines().filter(|l| l.contains("api_retry")).count(), 4, "every line passed through");
    assert!(!text(&o.stderr).contains("Anthropic refused"), "{}", text(&o.stderr));
    assert!(w.audit("credential_rejected").is_empty());
    let o = run(w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3 >/dev/null; echo read"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!((code(&o), text(&o.stdout).as_str()), (0, "read\n"), "not refused: {}", text(&o.stderr));
}

/// M29: the stop's final detach on a live link. A refused `claude` that
/// ignores TERM leaves an escaper outside its group holding its output: the
/// KILL 3 s after the third retry 401 ends the group, but its exit cannot
/// come back before the shim gives up the pipes, 2 s after the leader died.
/// The final detach sent with the KILL reaches the shim, which holds the
/// spawn as detached for good (`detach_left_s` 0) meanwhile, and `vm exec`
/// ends without waiting for that exit: exit 5 saying the command was stopped
/// (the check saw it gone), one start, and the token nowhere in the output
/// or under the world's root.
#[test]
fn a_refused_tokens_stop_detaches_for_good_without_waiting_for_its_exit() {
    let token = setup_token("Xg");
    let m = marker(46);
    let w = World::credentialed_with(&token, Some(&refused_claude(&m)));
    let live = Live::start(w.cred_exec(&["--with-credential", "--", "claude", "held", "--output-format", "stream-json"]));
    let mut out: Vec<String> = (0..3).map(|_| live.line()).collect();
    let t3 = Instant::now();
    let escaper: i32 = std::fs::read_to_string(w.root.join("home").join("escaper")).unwrap().trim().parse().unwrap();
    let detached = loop {
        if w.shim.spawns.detail().iter().any(|d| d.detach_left_s == Some(0)) {
            break Some(t3.elapsed());
        }
        if t3.elapsed() > Duration::from_secs(8) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (status, rest, err) = live.finish();
    let took = t3.elapsed();
    // SAFETY: kill(2) on the pid the script recorded for its escaper.
    unsafe { libc::kill(escaper, libc::SIGKILL) };
    out.extend(rest);
    assert_token_nowhere(&w, &Output { status, stdout: out.join("\n").into_bytes(), stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "{err}");
    assert!(detached.is_some_and(|t| t >= Duration::from_millis(2500)), "the shim saw the final detach, sent with the KILL: {detached:?}");
    assert!(took < Duration::from_millis(4500), "vm exec did not wait for the exit the escaper held up (2 s after the KILL): {took:?}");
    assert!(gone(&format!("^sleep {m}$")), "the KILL reached the group");
    assert!(err.contains("Anthropic refused the delivered setup-token (HTTP 401): the command was stopped and is not started again"), "{err}");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
}

/// M20: a signal that ends the child-gone check (here a SIGTERM sent during
/// the refused command's 3 s of TERM, kept pending until the check) makes
/// the `vm terminate` hint say so, never that the check looked for 5 s; the
/// check takes that signal, so `vm exec` still exits 5 (never 143) at once,
/// its line claiming no stop it did not see (F27), and records the
/// rejection; the token is nowhere in the output or under the world's root.
#[test]
fn a_signal_that_ends_the_child_gone_check_is_named_in_its_hint() {
    let token = setup_token("Xh");
    let m = marker(47);
    let w = World::credentialed_with(&token, Some(&refused_claude(&m)));
    let live = Live::start(w.cred_exec(&["--with-credential", "--", "claude", "stubborn", "--output-format", "stream-json"]));
    let mut out: Vec<String> = (0..3).map(|_| live.line()).collect();
    let t3 = Instant::now();
    live.signal(libc::SIGTERM);
    let (status, rest, err) = live.finish();
    let took = t3.elapsed();
    out.extend(rest);
    assert_token_nowhere(&w, &Output { status, stdout: out.join("\n").into_bytes(), stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "the signal does not undo the refusal: {err}");
    let vm = &w.id;
    assert!(err.contains(&format!(" was not seen gone from {vm} before a signal ended the check (it holds the refused token): `ai-env vm terminate {vm}` ends it")) && !err.contains("within 5 s"), "{err}");
    assert!(err.contains("Anthropic refused the delivered setup-token (HTTP 401): the stop was sent, but the command was not seen to end (see above); it is not started again") && !err.contains("was stopped"), "the check was cut short, and no exit came back: {err}");
    assert!(took < Duration::from_millis(4500), "the KILL at 3 s, then no wait for the check: {took:?}");
    assert!(gone(&format!("^sleep {m}$")), "the KILL reached the group");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
}

// ---- S7 fix wave: unseal ----

/// The unseal fixes' tests, in a module of their own: their helpers and
/// imports stay theirs.
mod unseal_fixes {
    use super::*;
    use ai_env_cli::bridge::agent::credential::{cached_on_vm, prepare, seal_tag, CredentialPlan, CredentialSupply};
    use ai_env_cli::bridge::api::{managed_connector_arn, AuthToken, EndpointClient, HealthDetailReply, HealthReply};
    use ai_env_cli::bridge::config::BridgeConfig;
    use ai_env_cli::bridge::errors::BridgeError;
    use ai_env_cli::bridge::lab::VmKnobs;
    use ai_env_cli::bridge::vm::cmd::Ctx;
    use ai_env_cli::store::Keystore;
    use ai_env_cli::wire::frame::{Deliver, CAP_CREDENTIAL_CACHE};

    /// Seal `token` once more, this time with `combined.env` (`creds
    /// setup-token --stdin` without `--no-combined`; its one Touch ID unseals
    /// the runtime key to build it): from then on a credentialed command makes
    /// one Touch ID for both.
    fn seal_combined(w: &World, token: &str) {
        let o = run(w.sealed_cmd(&["creds", "setup-token", "--stdin"]), Some(format!("{token}\n").into_bytes()));
        assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
        assert!(w.root.join("bridge").join("credentials").join("combined.env").exists(), "combined.env was built");
    }

    /// Append `lines` to the world's bridge.toml as its `[creds]` table.
    fn creds_cfg(w: &World, lines: &str) {
        let path = w.root.join("bridge").join("bridge.toml");
        let mut toml = std::fs::read_to_string(&path).unwrap();
        toml.push_str(&format!("\n[creds]\n{lines}\n"));
        std::fs::write(&path, toml).unwrap();
    }

    /// `cmd` with the unseal budget at 2 s (the lab knob, in place of
    /// `[creds].unseal_timeout_s`, whose range starts at 10 s): a deadline
    /// test waits 2 s for each prompt nobody answers, not 10.
    fn budgeted(mut cmd: Command) -> Command {
        cmd.env("AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS", "2000");
        cmd
    }

    /// `ws/project`, created: the workspace `vm warm` is given.
    fn project(w: &World) -> String {
        let ws = w.root.join("ws").join("project");
        std::fs::create_dir_all(&ws).unwrap();
        ws.display().to_string()
    }

    /// The seal id of the world's sealed setup-token.
    fn tag(w: &World) -> String {
        seal_tag(&w.root.join("bridge").join("credentials").join("setup-token.env")).unwrap()
    }

    /// The world's fake age, once `answered` decrypts are in its log, hangs as
    /// an unanswered Touch ID dialog would: a wrapper in front of it in the
    /// world's bin sets `FAKE_AGE_HANG` and `FAKE_AGE_PIDFILE` for the decrypts
    /// after those. Returns the reaper of the hanging decrypt's group.
    fn hang_after(w: &World, answered: usize) -> Reaper {
        use std::os::unix::fs::PermissionsExt as _;
        let real = w.root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/age.sh"), real.join("age")).unwrap();
        let pidfile = w.root.join("age.pid");
        let _ = std::fs::remove_file(&pidfile);
        let wrapper = format!(
            "#!/bin/sh\nn=$(grep -c '^age -d ' \"$FAKE_AGE_LOG\" 2>/dev/null)\nif [ \"${{1:-}}\" = -d ] && [ \"${{n:-0}}\" -ge {answered} ]; then\n  FAKE_AGE_HANG=1 FAKE_AGE_PIDFILE='{}'\n  export FAKE_AGE_HANG FAKE_AGE_PIDFILE\nfi\nexec /bin/sh '{}' \"$@\"\n",
            pidfile.display(),
            real.join("age").display()
        );
        let age = w.bin().join("age");
        std::fs::write(&age, wrapper).unwrap();
        std::fs::set_permissions(&age, std::fs::Permissions::from_mode(0o755)).unwrap();
        Reaper { pidfile, fake: real.join("age").display().to_string() }
    }

    /// The world's plain fake age again, every decrypt answered.
    fn plain_age(w: &World) {
        use std::os::unix::fs::PermissionsExt as _;
        let age = w.bin().join("age");
        std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/age.sh"), &age).unwrap();
        std::fs::set_permissions(&age, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The VM's ingress echo becomes HTTP_INGRESS and SHELL_INGRESS: the live gate's `ingress_echo` refuses it.
    fn shell_ingress(w: &World) {
        let id = w.id.clone();
        w.update_fake(|s| s.vms.get_mut(&id).unwrap().ingress = vec![managed_connector_arn("HTTP_INGRESS"), managed_connector_arn("SHELL_INGRESS")]);
    }

    /// Every audit row of the world, in order: (event, detail).
    fn audit_rows(w: &World) -> Vec<(String, serde_json::Value)> {
        let text = std::fs::read_to_string(w.root.join("bridge").join("audit.jsonl")).unwrap_or_default();
        text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).map(|r| (r["event"].as_str().unwrap_or_default().to_string(), r["detail"].clone())).collect()
    }

    /// Kills the group of a hanging fake decrypt when dropped, only if its
    /// leader is still that fake: a test that fails while the dialog stands
    /// leaves nothing behind.
    struct Reaper {
        pidfile: PathBuf,
        /// The fake's path, which the leader's command line holds.
        fake: String,
    }

    impl Reaper {
        /// The group the hanging decrypt leads (its pid), once it hangs.
        fn group(&self) -> i32 {
            wait_for("the hanging decrypt", || std::fs::read_to_string(&self.pidfile).is_ok_and(|t| t.trim().parse::<i32>().is_ok()));
            std::fs::read_to_string(&self.pidfile).unwrap().trim().parse().unwrap()
        }
    }

    impl Drop for Reaper {
        fn drop(&mut self) {
            let Some(pgid) = std::fs::read_to_string(&self.pidfile).ok().and_then(|t| t.trim().parse::<i32>().ok()) else { return };
            let leader = Command::new("/bin/ps").args(["-o", "command=", "-p", &pgid.to_string()]).output();
            if leader.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains(&self.fake)) {
                // SAFETY: this test's own hanging fake, checked just above: its group, or (a decrypt that was given
                // no group of its own) the process alone.
                unsafe {
                    if libc::killpg(pgid, libc::SIGKILL) != 0 {
                        libc::kill(pgid, libc::SIGKILL);
                    }
                }
            }
        }
    }

    /// The token's part after its kind prefix is not in a live command's
    /// `stdout` lines or `stderr`, nor in the CLI log or any file under the
    /// world's root; `stderr` comes back masked, for an assertion's message.
    fn token_kept_out(w: &World, stdout: &[String], stderr: &str, token: &str) -> String {
        assert!(!stdout.iter().any(|l| l.contains(&token[13..])), "stdout holds the token ({} lines)", stdout.len());
        assert!(!stderr.contains(&token[13..]), "stderr holds the token ({} bytes)", stderr.len());
        assert!(!w.cli_log().contains(&token[13..]), "the CLI log holds the token");
        assert_token_off_disk(w, token);
        masked(stderr, token)
    }

    /// Whether process group `pgid` is gone within 5 s.
    fn group_gone(pgid: i32) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(5) {
            // SAFETY: a plain existence check; signal 0 sends nothing.
            if unsafe { libc::killpg(pgid, 0) } != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// S7 D4 offline (M30): with a current `combined.env`, `vm exec
    /// --with-credential` makes ONE Touch ID for the runtime key and the token
    /// (audited `credential_unseal source=combined`, nothing else unsealed), the
    /// runtime key it connects with is the one combined.env holds, and the
    /// command reads on fd 3 the token that unseal gave. The token is in no file
    /// under the world's root and not in stderr.
    #[test]
    fn exec_with_a_current_combined_env_makes_one_touch_id_for_both() {
        let token = setup_token("Ua");
        let w = World::credentialed(&token);
        seal_combined(&w, &token);
        let (before, unseals) = (w.decrypts(), w.audit("credential_unseal").len());
        let o = run(w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3"]), None);
        let err = masked(&text(&o.stderr), &token);
        assert_eq!(code(&o), 0, "{err}");
        assert!(text(&o.stdout) == token, "stdout of {} bytes", o.stdout.len());
        assert_eq!(w.decrypts() - before, 1, "one Touch ID for the runtime key and the token");
        let rows = w.audit("credential_unseal");
        assert_eq!(rows.len() - unseals, 1, "one unseal: {err}");
        assert_eq!((rows[unseals]["detail"]["source"].as_str(), rows[unseals]["detail"]["outcome"].as_str()), (Some("combined"), Some("ok")));
        assert!(err.contains("runtime key \u{2026}CRED (credentials/aws.env) (unsealed; the fake API does not use it)"), "{err}");
        assert_eq!(w.audit("credential_deliver").len(), 1);
        assert!(!text(&o.stderr).contains(&token[13..]), "stderr holds the token");
        assert_token_off_disk(&w, &token);
    }

    /// S7 D4 and the live gate (M22, M30): with a current `combined.env` the
    /// token is unsealed with the runtime key before any AWS call, and a live
    /// refusal (here the VM's ingress echo names SHELL_INGRESS) drops it unsent:
    /// exit 9 `ingress_echo` (half `live`), one Touch ID, the combined unseal
    /// audited before the refusal, no delivery, nothing in the shim's cache and
    /// no spawn; the token nowhere in the output or under the world's root.
    #[test]
    fn a_live_refusal_after_a_combined_unseal_sends_nothing() {
        let token = setup_token("Ub");
        let w = World::credentialed(&token);
        seal_combined(&w, &token);
        shell_ingress(&w);
        let (before, rows) = (w.decrypts(), audit_rows(&w).len());
        let o = run(w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3"]), None);
        assert_token_nowhere(&w, &o, &token);
        assert_eq!(code(&o), 9, "{}", text(&o.stderr));
        assert_eq!(w.decrypts() - before, 1, "the runtime key and the token, together, at the start");
        let new = &audit_rows(&w)[rows..];
        let unsealed = new.iter().position(|(e, d)| e == "credential_unseal" && d["source"] == "combined" && d["outcome"] == "ok").expect("the combined unseal");
        let refused = new.iter().position(|(e, d)| e == "credential_gate" && d["result"] == "refused").expect("the gate's refusal");
        assert!(unsealed < refused, "unsealed at the start, refused after: {new:?}");
        assert_eq!((new[refused].1["condition"].as_str(), new[refused].1["half"].as_str()), (Some("ingress_echo"), Some("live")));
        assert!(w.audit("credential_deliver").is_empty(), "nothing delivered");
        assert!(!w.shim.spawns.credential().has() && w.spawn_ids().is_empty(), "nothing reached the VM");
    }

    /// The gate before the token (M30): without `combined.env` the same live
    /// refusal costs one Touch ID, the runtime key's: the token is never
    /// unsealed for a VM the gate refuses (a `prepare` that unsealed before the
    /// gate makes two).
    #[test]
    fn a_live_refusal_without_combined_env_unseals_only_the_runtime_key() {
        let token = setup_token("Uc");
        let w = World::credentialed(&token);
        shell_ingress(&w);
        let before = w.decrypts();
        let o = run(w.cred_exec(&["--with-credential", "--", "true"]), None);
        assert_token_nowhere(&w, &o, &token);
        assert_eq!(code(&o), 9, "{}", text(&o.stderr));
        assert_eq!(w.decrypts() - before, 1, "the runtime key only");
        assert!(w.audit("credential_unseal").is_empty(), "no token unsealed: {:?}", w.audit("credential_unseal"));
        assert_eq!(w.audit("credential_gate").last().unwrap()["detail"]["condition"], "ingress_echo");
    }

    /// The world's fake endpoint, but its `/health/detail` says what the test
    /// makes the shim hold and offer (the fake's own never holds anything).
    struct Held<'a> {
        fake: &'a FileFakeMicrovmApi,
        has: bool,
        name: &'a str,
        tag: &'a str,
        caps: Vec<String>,
    }

    impl EndpointClient for Held<'_> {
        async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
            self.fake.get_health(endpoint, token, port_header).await
        }

        async fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &Secret<String>) -> Result<HealthDetailReply, BridgeError> {
            let mut reply = self.fake.get_health_detail(endpoint, token, bearer).await?;
            if let Some(d) = reply.detail.as_mut() {
                d.has_credentials = self.has;
                d.credential.credential_name = Some(self.name.to_string());
                d.credential.credential_tag = Some(self.tag.to_string());
                d.health.caps.clone_from(&self.caps);
            }
            Ok(reply)
        }
    }

    /// `cached_on_vm` (M30, M11): a hit only when the shim holds this name AND
    /// this seal AND offers the cache; another seal (a rotated token), another
    /// name, nothing held, a shim without the cache, a 502 and a failed read are
    /// all "not held". The caps it reads go into the row, as a `/health`
    /// refresh records them; an answer that carries none leaves the row as it was.
    #[test]
    fn cached_on_vm_needs_this_name_this_seal_and_the_cache() {
        let token = setup_token("Ud");
        let w = World::credentialed(&token);
        let paths = Paths::from_root_and_env(w.root.join("bridge"), None);
        let fake = FileFakeMicrovmApi::open(&w.fake_path()).unwrap();
        let (seal, cap) = (tag(&w), vec![CAP_CREDENTIAL_CACHE.to_string()]);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let row = w.row();
        let vm = rt.block_on(fake.get(&w.id)).unwrap();
        // What the shim holds and offers, asked about the seal sealed now.
        let held = |has: bool, name: &'static str, tag: &str, caps: &[String]| rt.block_on(async { cached_on_vm(&paths, &fake, &Held { fake: &fake, has, name, tag, caps: caps.to_vec() }, &row, &vm, &seal).await });
        assert!(held(true, "CLAUDE_CODE_OAUTH_TOKEN", &seal, &cap), "this name and this seal: held");
        assert_eq!(w.row().caps, Some(cap.clone()), "the caps read are recorded");
        assert!(!held(true, "CLAUDE_CODE_OAUTH_TOKEN", "0000000000000000", &cap), "another seal (a rotated token)");
        assert!(!held(true, "ANOTHER_TOKEN", &seal, &cap), "another name");
        assert!(!held(false, "CLAUDE_CODE_OAUTH_TOKEN", &seal, &cap), "nothing held");
        assert!(!held(true, "CLAUDE_CODE_OAUTH_TOKEN", &seal, &[]), "a shim without the cache holds nothing");
        assert_eq!(w.row().caps, Some(Vec::new()), "recorded: the next command refuses at its check");
        let id = w.id.clone();
        w.update_fake(|s| {
            s.health_script.insert(id.clone(), std::collections::VecDeque::from([502]));
        });
        assert!(!held(true, "CLAUDE_CODE_OAUTH_TOKEN", &seal, &cap), "a 502");
        w.update_fake(|s| s.failures.push_back(FakeFailure { kind: "throttled".into(), message: "Rate exceeded".into(), on: Some("health_detail".into()), after_effect: false }));
        assert!(!held(true, "CLAUDE_CODE_OAUTH_TOKEN", &seal, &cap), "a failed read");
        assert_eq!(w.row().caps, Some(Vec::new()), "no answer, nothing recorded");
        assert_token_off_disk(&w, &token);
    }

    /// The hit that spares the unseal (M30): `prepare` without the token in hand,
    /// on a VM whose shim holds this seal, passes the gate and binds the delivery
    /// to it with no value: source `cached`, and the fake age is never asked.
    #[test]
    fn prepare_takes_a_seal_the_vm_holds_without_a_touch_id() {
        let token = setup_token("Ue");
        let w = World::credentialed(&token);
        let paths = Paths::from_root_and_env(w.root.join("bridge"), None);
        let cfg = BridgeConfig::load(&paths).unwrap().unwrap();
        let ctx = Ctx { paths, cfg, knobs: VmKnobs::default() };
        let fake = FileFakeMicrovmApi::open(&w.fake_path()).unwrap();
        let store = Keystore::resolve(Some(w.root.join("keys"))).unwrap();
        let tag = tag(&w);
        let plan = CredentialPlan { deliver: Deliver::Fd, file: None, tag: tag.clone() };
        let ep = Held { fake: &fake, has: true, name: "CLAUDE_CODE_OAUTH_TOKEN", tag: &tag, caps: vec![CAP_CREDENTIAL_CACHE.to_string()] };
        let (before, gates) = (w.decrypts(), w.audit("credential_gate").len());
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let row = w.row();
        let prepared = rt.block_on(async {
            let vm = fake.get(&w.id).await.unwrap();
            prepare(&ctx, &fake, &ep, &row, &vm, &plan, CredentialSupply { store: &store, token: None }).await
        });
        let prepared = prepared.unwrap_or_else(|e| panic!("prepare: {e}"));
        assert_eq!(prepared.source, "cached");
        assert_eq!(w.decrypts(), before, "no Touch ID: the VM holds this seal");
        let gate = &w.audit("credential_gate")[gates..];
        assert!(gate.len() == 1 && gate[0]["detail"]["result"] == "passed", "the gate ran first: {gate:?}");
        assert!(w.audit("credential_unseal").is_empty());
        assert_token_off_disk(&w, &token);
    }

    /// M11: a VM whose shim cannot hold a credential, never read (`vm run` reads
    /// no `/health`), costs the runtime key's Touch ID only: `cached_on_vm` reads
    /// its caps, the token is never unsealed for it, and the command exits 7
    /// naming the capability. The caps are recorded, so the next command refuses
    /// at its check, before any Touch ID. Nothing is delivered.
    #[test]
    fn a_shim_without_the_cache_never_costs_the_token_a_touch_id() {
        let token = setup_token("Uf");
        let w = World::credentialed(&token);
        w.update_fake(|s| s.health_caps = Vec::new());
        assert_eq!(w.row().caps, None, "vm run never read /health");
        let before = w.decrypts();
        let o = run(w.cred_exec(&["--with-credential", "--", "true"]), None);
        assert_token_nowhere(&w, &o, &token);
        assert_eq!(code(&o), 7, "{}", text(&o.stderr));
        assert!(text(&o.stderr).contains("does not offer the credential_cache capability"), "{}", text(&o.stderr));
        assert_eq!(w.decrypts() - before, 1, "the runtime key only");
        assert!(w.audit("credential_unseal").is_empty(), "the token was not unsealed");
        assert_eq!(w.row().caps, Some(Vec::new()), "recorded for the next command");
        let before = w.decrypts();
        let o = run(w.cred_exec(&["--with-credential", "--", "true"]), None);
        assert_token_nowhere(&w, &o, &token);
        assert_eq!(code(&o), 7, "{}", text(&o.stderr));
        assert_eq!(w.decrypts(), before, "refused at the check, before any Touch ID");
        assert!(w.audit("credential_deliver").is_empty() && !w.shim.spawns.credential().has());
    }

    /// M12 and M31: what `vm warm` and `vm smoke --with-credential` refuse
    /// before any Touch ID and before any VM. The gate's local half on the VM a
    /// run would start: a passing check older than 7 days (9, `record_age`), a
    /// dns-path verdict not accepted (9, `dns_path`); a smoke asked for internet
    /// egress (9); a seal Anthropic refused (5); no sealed token (5). The fake
    /// age is never asked, no VM is started, and the token is nowhere in any
    /// output or under the world's root.
    #[test]
    fn warm_and_smoke_refuse_before_any_touch_id_or_vm() {
        use ai_env_cli::bridge::egress::EgressVerified;
        let token = setup_token("Ug");
        let w = World::platform(None);
        w.seed_credentials(&token, "1.0");
        let ws = project(&w);
        let before = w.decrypts();
        let refused = |args: &[&str], want: i32, says: &str| {
            let o = run(w.sealed_cmd(args), None);
            assert_token_nowhere(&w, &o, &token);
            assert_eq!(code(&o), want, "{args:?}: {}", text(&o.stderr));
            assert!(text(&o.stderr).contains(says), "{args:?}: {}", text(&o.stderr));
        };
        let warm = ["vm", "warm", ws.as_str()];
        let smoke = ["vm", "smoke", "--exec", "--with-credential", "--json"];
        refused(&["vm", "smoke", "--exec", "--with-credential", "--egress", "internet"], 9, "never enters a VM with internet egress");
        // The passing check was recorded 8 days ago (D7 allows 7).
        let verified = w.root.join("bridge").join("state").join("egress-verified.toml");
        let fresh = std::fs::read_to_string(&verified).unwrap();
        let mut old: EgressVerified = toml::from_str(&fresh).unwrap();
        old.records[0].at = ai_env_cli::wire::time::rfc3339_utc(ai_env_cli::wire::time::unix_now() - 8 * 86_400);
        std::fs::write(&verified, toml::to_string(&old).unwrap()).unwrap();
        refused(&warm, 9, "more than 7 days ago");
        refused(&smoke, 9, "more than 7 days ago");
        let gate = w.audit("credential_gate").last().unwrap().clone();
        assert_eq!((gate["detail"]["condition"].as_str(), gate["detail"]["half"].as_str(), gate["detail"]["id"].as_str()), (Some("record_age"), Some("local"), Some("-")));
        // A fresh check, but the newest dns-path verdict is not accepted.
        std::fs::write(&verified, &fresh).unwrap();
        let probes = w.root.join("bridge").join("lab").join("probes.jsonl");
        let row = serde_json::json!({ "probe": "dns-path", "verdict": "platform-dns:169.254.169.253", "ts": ai_env_cli::wire::time::rfc3339_utc(ai_env_cli::wire::time::unix_now()) });
        let kept = std::fs::read_to_string(&probes).unwrap();
        std::fs::write(&probes, format!("{kept}{row}\n")).unwrap();
        refused(&warm, 9, "is not accepted");
        std::fs::write(&probes, kept).unwrap();
        // Anthropic refused this seal.
        let state = w.root.join("bridge").join("state").join("creds.toml");
        std::fs::write(&state, format!("[[rejected]]\ntag = \"{}\"\nat = \"2026-10-08T00:00:00Z\"\nvm = \"microvm-refused\"\n", tag(&w))).unwrap();
        refused(&warm, 5, "was refused by Anthropic");
        refused(&smoke, 5, "was refused by Anthropic");
        std::fs::remove_file(&state).unwrap();
        // No sealed token.
        std::fs::remove_file(w.root.join("bridge").join("credentials").join("setup-token.env")).unwrap();
        refused(&warm, 5, "ai-env creds setup-token");
        refused(&smoke, 5, "ai-env creds setup-token");
        assert_eq!(w.decrypts(), before, "no Touch ID for any refusal");
        assert!(w.fake().vms.is_empty(), "no VM was started");
    }

    /// M31: the unseal's own exits on `vm exec --with-credential`. A dismissed
    /// dialog is 3, for the runtime key's prompt and for combined.env's (audited
    /// `exit 3`); a `[creds].key` naming no key is 4 with no Touch ID. Nothing is
    /// delivered, nothing spawned.
    #[test]
    fn a_dismissed_dialog_is_3_and_a_missing_key_is_4() {
        let token = setup_token("Uh");
        let w = World::credentialed(&token);
        let mut cancelled = w.cred_exec(&["--with-credential", "--", "true"]);
        cancelled.env("FAKE_AGE_FAIL", "cancel");
        let o = run(cancelled, None);
        assert_token_nowhere(&w, &o, &token);
        assert_eq!(code(&o), 3, "the runtime key's prompt: {}", text(&o.stderr));
        seal_combined(&w, &token);
        let mut cancelled = w.cred_exec(&["--with-credential", "--", "true"]);
        cancelled.env("FAKE_AGE_FAIL", "cancel");
        let o = run(cancelled, None);
        assert_token_nowhere(&w, &o, &token);
        assert_eq!(code(&o), 3, "combined.env's prompt: {}", text(&o.stderr));
        assert_eq!(w.audit("credential_unseal").last().unwrap()["detail"]["outcome"], "exit 3");
        creds_cfg(&w, "key = \"no-such-key\"");
        let before = w.decrypts();
        let o = run(w.cred_exec(&["--with-credential", "--", "true"]), None);
        assert_token_nowhere(&w, &o, &token);
        assert_eq!(code(&o), 4, "{}", text(&o.stderr));
        assert_eq!(w.decrypts(), before, "no Touch ID without the key");
        assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty());
    }

    /// M56 and M55: without combined.env the runtime key's prompt has the same
    /// deadline as the token's (before, it waited for ever): exit 5 after the
    /// unseal budget (here the lab knob's 2 s, in place of
    /// `[creds].unseal_timeout_s`), its countdown on stderr, the decrypt's whole
    /// group killed, and a failure that says nothing was started and that every
    /// credentialed command asks for this prompt, never sending the operator to
    /// `vm warm`. Nothing delivered, nothing spawned.
    #[test]
    fn the_runtime_keys_prompt_has_a_deadline_without_combined_env() {
        let token = setup_token("Ui");
        let w = World::credentialed(&token);
        let reaper = hang_after(&w, w.decrypts());
        let o = run(budgeted(w.cred_exec(&["--with-credential", "--", "true"])), None);
        assert_token_nowhere(&w, &o, &token);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 5, "{err}");
        assert!(err.contains("ai-env: waiting for Touch ID to unseal the runtime key, 2 s left"), "{err}");
        assert!(err.contains("no Touch ID within 2 s, so the runtime key stayed sealed (nothing was started; every credentialed command asks for this prompt"), "{err}");
        assert!(!err.contains("vm warm"), "{err}");
        assert!(group_gone(reaper.group()), "the dialog's group was killed");
        assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty());
    }

    /// M55: the deadline of combined.env's prompt (the runtime key's too) never
    /// names `vm warm`, which cannot spare it; the token's own prompt on `vm
    /// exec` does, after saying nothing was delivered or started.
    #[test]
    fn only_the_tokens_own_deadline_on_vm_exec_names_vm_warm() {
        let token = setup_token("Uj");
        let w = World::credentialed(&token);
        // The runtime key answers; the token's own prompt goes unanswered.
        let reaper = hang_after(&w, w.decrypts() + 1);
        let o = run(budgeted(w.cred_exec(&["--with-credential", "--", "true"])), None);
        assert_token_nowhere(&w, &o, &token);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 5, "{err}");
        assert!(err.contains("so the setup token stayed sealed (nothing was delivered;") && err.contains("nothing was started; `ai-env vm warm <workspace>` delivers the token"), "{err}");
        assert!(group_gone(reaper.group()));
        assert_eq!(w.audit("credential_unseal").last().unwrap()["detail"]["outcome"], "exit 5");
        drop(reaper);
        plain_age(&w);
        seal_combined(&w, &token);
        let reaper = hang_after(&w, w.decrypts());
        let o = run(budgeted(w.cred_exec(&["--with-credential", "--", "true"])), None);
        assert_token_nowhere(&w, &o, &token);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 5, "{err}");
        assert!(err.contains("so the runtime key and the setup token stayed sealed (nothing was started; every credentialed command asks for this prompt"), "{err}");
        assert!(!err.contains("vm warm"), "{err}");
        assert!(group_gone(reaper.group()));
    }

    /// M55 in `vm warm`: when the token's own prompt goes unanswered after
    /// `select` started the workspace's VM, the failure names that VM (it keeps
    /// running, and the next warm reuses it) instead of claiming nothing was
    /// started, and never sends the operator to run `vm warm <workspace>`.
    #[test]
    fn a_warm_whose_token_prompt_times_out_names_the_vm_it_started() {
        let token = setup_token("Uk");
        let w = World::platform(None);
        w.seed_credentials(&token, "1.0");
        let ws = project(&w);
        let reaper = hang_after(&w, w.decrypts() + 1);
        let o = run(budgeted(w.sealed_cmd(&["vm", "warm", &ws])), None);
        assert_token_nowhere(&w, &o, &token);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 5, "{err}");
        let id = w.fake().vms.keys().next().cloned().expect("the workspace's VM");
        assert!(err.contains(&format!("{id} was started for this workspace and keeps running")), "{err}");
        assert!(!err.contains("nothing was started") && !err.contains("vm warm <workspace>"), "{err}");
        assert!(group_gone(reaper.group()));
        assert!(w.audit("credential_deliver").is_empty() && !w.shim.spawns.credential().has());
    }

    /// M31 and M2: SIGINT, SIGTERM or SIGHUP while Touch ID is awaited closes the
    /// dialog (the decrypt's whole group is gone) and ends `vm exec
    /// --with-credential` with 130 or 143 and an `ai-env:` line; the unseal is
    /// audited with that exit, nothing is delivered, nothing spawned.
    #[test]
    fn a_signal_while_touch_id_is_awaited_closes_the_dialog() {
        let token = setup_token("Ul");
        let w = World::credentialed(&token);
        seal_combined(&w, &token);
        for (sig, name, status) in [(libc::SIGINT, "SIGINT", 130), (libc::SIGTERM, "SIGTERM", 143), (libc::SIGHUP, "SIGHUP", 143)] {
            let reaper = hang_after(&w, w.decrypts());
            let live = Live::start(w.cred_exec(&["--with-credential", "--", "true"]));
            let pgid = reaper.group();
            live.signal(sig);
            let (exit, rest, err) = live.finish();
            let err = token_kept_out(&w, &rest, &err, &token);
            assert_eq!(exit.code(), Some(status), "{name}: {err}");
            assert!(err.contains(&format!("ai-env: stopped while waiting for Touch ID ({name}): the dialog was closed and the runtime key and the setup token stayed sealed")), "{name}: {err}");
            assert!(group_gone(pgid), "{name}: the dialog's group outlived the stop");
            assert_eq!(w.audit("credential_unseal").last().unwrap()["detail"]["outcome"], format!("exit {status}"));
        }
        assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty());
    }

    /// M2: once the Touch ID was answered, `vm warm` still stops on SIGINT (130),
    /// SIGTERM or SIGHUP (143) while it waits for its VM, before anything is
    /// delivered (before, tokio's handler, left installed by the unseal, dropped
    /// the signal and the warm delivered anyway). The VM it started is named and
    /// keeps running; nothing reaches the shim's cache.
    #[test]
    fn a_stop_after_the_unseal_ends_vm_warm_before_any_delivery() {
        for (sig, name, status) in [(libc::SIGINT, "SIGINT", 130), (libc::SIGTERM, "SIGTERM", 143), (libc::SIGHUP, "SIGHUP", 143)] {
            let token = setup_token("Um");
            let w = World::platform(None);
            w.seed_credentials(&token, "1.0");
            seal_combined(&w, &token);
            let ws = project(&w);
            // The new VM stays PENDING: the warm waits for RUNNING.
            w.update_fake(|s| s.auto_advance = false);
            let before = w.decrypts();
            let live = Live::start(w.sealed_cmd(&["vm", "warm", &ws]));
            wait_for("RunMicrovm", || !w.fake().vms.is_empty());
            let id = w.fake().vms.keys().next().cloned().unwrap();
            wait_for("the VM's row", || w.root.join("bridge").join("state").join("vms").join(format!("{id}.toml")).exists());
            let t = Instant::now();
            live.signal(sig);
            std::thread::sleep(Duration::from_millis(300));
            // A warm that dropped the signal would now go on and deliver.
            w.update_fake(|s| s.auto_advance = true);
            let (exit, rest, err) = live.finish();
            let err = token_kept_out(&w, &rest, &err, &token);
            assert_eq!(exit.code(), Some(status), "{name}: {err}");
            assert!(t.elapsed() < Duration::from_secs(5), "{name}: stopped after {:?}", t.elapsed());
            assert!(err.contains(&format!("({name}) before the setup-token was sent: nothing was delivered")), "{name}: {err}");
            assert!(err.contains(&format!("{id} was started for this workspace and keeps running")), "{name}: {err}");
            assert_eq!(w.decrypts() - before, 1, "{name}: the one Touch ID");
            assert!(w.audit("credential_deliver").is_empty() && !w.shim.spawns.credential().has(), "{name}: nothing delivered");
        }
    }

    /// M2: SIGTERM after the unseal ends `vm smoke --exec --with-credential`
    /// (143, its VM terminated) instead of being dropped: here while the
    /// smoke's VM is still starting, after one Touch ID for both credentials.
    #[test]
    fn a_sigterm_after_the_unseal_ends_the_credentialed_smoke_and_its_vm() {
        let token = setup_token("Un");
        let w = World::platform(None);
        w.seed_credentials(&token, "1.0");
        seal_combined(&w, &token);
        w.update_fake(|s| s.auto_advance = false);
        let live = Live::start(w.sealed_cmd(&["vm", "smoke", "--exec", "--with-credential", "--json"]));
        wait_for("RunMicrovm", || !w.fake().vms.is_empty());
        live.signal(libc::SIGTERM);
        std::thread::sleep(Duration::from_millis(300));
        w.update_fake(|s| s.auto_advance = true);
        let (exit, rest, err) = live.finish();
        let err = token_kept_out(&w, &rest, &err, &token);
        assert_eq!(exit.code(), Some(143), "{err}");
        assert!(err.contains("ai-env: terminated (SIGTERM): ending the smoke and its VM"), "{err}");
        let st = w.fake();
        assert!(st.vms.values().all(|v| v.state.is_terminal()), "the smoke's VM was ended: {:?}", st.vms.values().map(|v| v.state.as_str()).collect::<Vec<_>>());
        assert!(w.audit("credential_deliver").is_empty());
    }

    /// M8: Ctrl-C at the smoke's token dialog (without combined.env the token is
    /// a second Touch ID, inside the smoke) cancels the smoke (exit 3, its VM
    /// ended) and closes the dialog: the decrypt's group is gone, never left
    /// behind (an outer arm that won the race) and never turned into a failed
    /// credential step (an inner one).
    #[test]
    fn a_ctrl_c_at_the_smokes_token_dialog_cancels_and_closes_it() {
        let token = setup_token("Uo");
        let w = World::platform(None);
        w.seed_credentials(&token, "1.0");
        let reaper = hang_after(&w, w.decrypts() + 1);
        let live = Live::start(w.sealed_cmd(&["vm", "smoke", "--exec", "--with-credential", "--json"]));
        let pgid = reaper.group();
        live.signal(libc::SIGINT);
        let (exit, rest, err) = live.finish();
        let err = token_kept_out(&w, &rest, &err, &token);
        assert_eq!(exit.code(), Some(3), "{err}");
        assert!(group_gone(pgid), "the token's dialog outlived the cancel");
        let st = w.fake();
        assert!(!st.vms.is_empty() && st.vms.values().all(|v| v.state.is_terminal()), "the smoke's VM was ended");
        assert!(w.audit("credential_deliver").is_empty());
    }

    /// M9: a signal ignored when a credentialed `vm exec` started stays ignored
    /// through its Touch IDs and its command, as without the credential: under
    /// `nohup` a hangup during the unseal neither closes the dialog nor stops the
    /// command, nor does one while it runs; a SIGINT a script's background job
    /// ignores never reaches the remote.
    #[test]
    fn credentialed_signals_ignored_on_entry_stay_ignored() {
        let token = setup_token("Up");
        let w = World::credentialed(&token);
        let script = "trap 'exit 41' HUP INT TERM; echo ready; sleep 1; echo done; exit 6";
        let pidfile = w.root.join("slow.pid");
        let mut exec = w.cred_exec(&["--with-credential", "--", "sh", "-c", script]);
        // Each decrypt answers after 1.5 s, its pid written first: the hangup lands while one waits.
        exec.env("FAKE_AGE_DELAY_MS", "1500").env("FAKE_AGE_PIDFILE", &pidfile);
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
        wait_for("the first decrypt", || pidfile.exists());
        live.signal(libc::SIGHUP);
        assert_eq!(live.line(), "ready");
        live.signal(libc::SIGHUP);
        let (status, rest, err) = live.finish();
        let err = token_kept_out(&w, &rest, &err, &token);
        assert_eq!((status.code(), rest), (Some(6), vec!["done".to_string()]), "nohup: {err}");
        assert!(w.cli_log().contains(&format!("signal {} was ignored when ai-env started", libc::SIGHUP)), "{}", w.cli_log());
        let mut exec = w.cred_exec(&["--with-credential", "--", "sh", "-c", script]);
        set_signals(&mut exec, libc::SIG_IGN, &[libc::SIGINT]);
        let live = Live::start(exec);
        assert_eq!(live.line(), "ready");
        live.signal(libc::SIGINT);
        let (status, rest, err) = live.finish();
        let err = token_kept_out(&w, &rest, &err, &token);
        assert_eq!((status.code(), rest), (Some(6), vec!["done".to_string()]), "SIGINT ignored: {err}");
    }

    /// M10: the setup-token never reaches `age` (nor its plugin, which
    /// inherits age's environment) through its environment, even when
    /// ai-env's own environment holds it: `creds setup-token --from-env` (its
    /// preflight, the seal, and the combined.env rebuild's decrypt and seal)
    /// and a credentialed `vm exec` run beside it; neither starts
    /// `age-keygen` (every call that does: age_cmd's
    /// `no_call_that_starts_age_or_age_keygen_hands_it_a_credential`). A
    /// wrapper in front of the fake age logs, for every call, whether the
    /// variable was set, never its value. Neither token is in either
    /// command's output or in any file under the world's root.
    #[test]
    fn the_token_never_reaches_ages_environment() {
        use std::os::unix::fs::PermissionsExt as _;
        let token = setup_token("Uq");
        let w = World::credentialed(&token);
        let real = w.root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/age.sh"), real.join("age")).unwrap();
        let seen = w.root.join("age-env.log");
        let wrapper = format!("#!/bin/sh\nprintf 'token=%s\\n' \"${{CLAUDE_CODE_OAUTH_TOKEN+set}}\" >> '{}'\nexec /bin/sh '{}' \"$@\"\n", seen.display(), real.join("age").display());
        std::fs::write(w.bin().join("age"), wrapper).unwrap();
        std::fs::set_permissions(w.bin().join("age"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let rotated = setup_token("Ur");
        let mut seal = w.sealed_cmd(&["creds", "setup-token", "--from-env"]);
        seal.env("CLAUDE_CODE_OAUTH_TOKEN", &rotated);
        let sealed = run(seal, None);
        assert_eq!(code(&sealed), 0, "{}", masked(&text(&sealed.stderr), &rotated));
        let mut exec = w.cred_exec(&["--with-credential", "--", "true"]);
        exec.env("CLAUDE_CODE_OAUTH_TOKEN", &rotated);
        let o = run(exec, None);
        assert_eq!(code(&o), 0, "{}", masked(&text(&o.stderr), &rotated));
        let calls: Vec<String> = std::fs::read_to_string(&seen).unwrap().lines().map(str::to_string).collect();
        assert!(calls.len() >= 4, "the probe, the seal, the rebuild's decrypt and seal, the exec's decrypt: {calls:?}");
        assert!(calls.iter().all(|c| c == "token="), "an age call saw the variable set: {calls:?}");
        for t in [&token, &rotated] {
            // Neither command's output, nor any file, holds either token (each check covers the disk too).
            assert_token_nowhere(&w, &sealed, t);
            assert_token_nowhere(&w, &o, t);
        }
    }

    /// M31: `[creds] deliver = "env"` delivers the token in the command's
    /// environment and nowhere else (fd 3 is not open), audited `deliver=env`.
    #[test]
    fn env_delivery_puts_the_token_in_the_environment_only() {
        let token = setup_token("Us");
        let w = World::credentialed(&token);
        creds_cfg(&w, "deliver = \"env\"");
        let o = run(w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "printf %s \"$CLAUDE_CODE_OAUTH_TOKEN\"; [ -e /dev/fd/3 ] && echo fd3; true"]), None);
        assert_eq!(code(&o), 0, "{}", masked(&text(&o.stderr), &token));
        assert!(text(&o.stdout) == token, "stdout of {} bytes (the token alone, no fd 3)", o.stdout.len());
        assert_eq!(w.audit("credential_deliver").last().unwrap()["detail"]["deliver"], "env");
        assert!(!text(&o.stderr).contains(&token[13..]));
        assert_token_off_disk(&w, &token);
    }

    /// M12 (review E1): a deploy made 2.0 the active version and
    /// `state/infra.toml` records it, but the only passing `egress check` is
    /// 1.0's. `vm warm` and `vm smoke --with-credential` judge the version a
    /// run would start, never any version with a record, so both refuse (exit
    /// 9, half `local`, image version 2.0, naming `make infra-status WRITE=1`)
    /// before any Touch ID and before any VM.
    #[test]
    fn a_new_active_version_without_a_check_is_refused_before_any_touch_id() {
        let token = setup_token("Ut");
        let w = World::platform(None);
        w.seed_credentials(&token, "1.0");
        let ws = project(&w);
        w.update_fake(|s| {
            s.versions.push(ai_env_cli::bridge::api::ImageVersion { version: "2.0".into(), state: "SUCCESSFUL".into(), status: "ACTIVE".into(), memory_mib: Some(2048), created_at_unix: Some(1_789_904_800) });
            s.image.as_mut().unwrap().latest_active = Some("2.0".into());
        });
        std::fs::write(w.root.join("bridge").join("state").join("infra.toml"), format!("image_arn = \"{FAKE_IMAGE_ARN}\"\nlatest_active_image_version = \"2.0\"\n")).unwrap();
        let before = w.decrypts();
        for args in [vec!["vm", "warm", ws.as_str()], vec!["vm", "smoke", "--exec", "--with-credential", "--json"]] {
            let o = run(w.sealed_cmd(&args), None);
            assert_token_nowhere(&w, &o, &token);
            let err = text(&o.stderr);
            assert_eq!(code(&o), 9, "{args:?}: {err}");
            assert!(err.contains("no credential for a vpc VM of image version 2.0 (the active version state/infra.toml records;") && err.contains("make infra-status WRITE=1"), "{args:?}: {err}");
            let gate = w.audit("credential_gate").last().unwrap().clone();
            assert_eq!((gate["detail"]["half"].as_str(), gate["detail"]["image_version"].as_str(), gate["detail"]["condition"].as_str()), (Some("local"), Some("2.0"), Some("no_record")), "{args:?}");
        }
        assert_eq!(w.decrypts(), before, "no Touch ID");
        assert!(w.fake().vms.is_empty(), "no VM was started");
    }

    /// M12 (review E2): `[aws].egress_connector_arn` with a `:N` version
    /// qualifier, which the gate ignores everywhere (records hold the connector
    /// without it). With no active version in `state/infra.toml` the
    /// provisional gate falls back to the versions a passing check is recorded
    /// for, finds 1.0's under the configured connector, and lets `vm warm` go
    /// on: one Touch ID, and the live gate passes the VM it starts.
    #[test]
    fn a_versioned_connector_arn_passes_the_provisional_gate() {
        let token = setup_token("Ux");
        let w = World::platform(None);
        w.seed_credentials(&token, "1.0");
        seal_combined(&w, &token);
        let ws = project(&w);
        let path = w.root.join("bridge").join("bridge.toml");
        let toml = std::fs::read_to_string(&path).unwrap().replace(&format!("egress_connector_arn = \"{CONNECTOR}\""), &format!("egress_connector_arn = \"{CONNECTOR}:3\""));
        assert!(toml.contains(&format!("{CONNECTOR}:3\"")), "the qualifier is configured");
        std::fs::write(&path, toml).unwrap();
        // The live gate's GetNetworkConnector asks by the configured identifier, qualifier and all.
        w.update_fake(|s| {
            s.connectors.insert(format!("{CONNECTOR}:3"), connector_doc());
        });
        assert!(!w.root.join("bridge").join("state").join("infra.toml").exists(), "no active version recorded");
        let before = w.decrypts();
        let o = run(w.sealed_cmd(&["vm", "warm", &ws]), None);
        assert_token_nowhere(&w, &o, &token);
        let err = text(&o.stderr);
        assert!(!err.contains("no credential for a vpc VM"), "{err}");
        assert_eq!(code(&o), 0, "{err}");
        assert_eq!(w.decrypts() - before, 1, "the one Touch ID, after the provisional gate");
        let gate = w.audit("credential_gate").last().unwrap().clone();
        assert_eq!(gate["detail"]["result"], "passed", "the live gate on the VM: {gate}");
        assert_eq!(w.audit("credential_deliver").len(), 1);
    }

    /// M2 (review E3): a stop while `vm warm`'s delivery is on its way (the
    /// endpoint holds the `/agent` upgrade: no `hello`, no frame) gives the
    /// delivery up at once, rather than finishing it: 130 after SIGINT, 143
    /// after SIGTERM or SIGHUP, a line saying nothing was delivered, and the VM
    /// it started named (it keeps running). Once the endpoint lets the held
    /// upgrade go, nothing follows: no `credential_deliver`, nothing in the
    /// shim's cache, and the VM's row names no delivery.
    #[test]
    fn a_stop_during_warms_delivery_gives_it_up_before_the_frame() {
        for (sig, name, status) in [(libc::SIGINT, "SIGINT", 130), (libc::SIGTERM, "SIGTERM", 143), (libc::SIGHUP, "SIGHUP", 143)] {
            let token = setup_token("Uv");
            let w = World::platform(None);
            w.seed_credentials(&token, "1.0");
            seal_combined(&w, &token);
            let ws = project(&w);
            w.endpoint.script([Action::Held]);
            let before = w.endpoint.accepted();
            let live = Live::start(w.sealed_cmd(&["vm", "warm", &ws]));
            wait_for("the held /agent upgrade", || w.endpoint.accepted() > before);
            live.signal(sig);
            // A warm that finished its delivery first would deliver once the upgrade goes on.
            std::thread::sleep(Duration::from_millis(500));
            w.endpoint.release();
            let (exit, rest, err) = live.finish();
            let err = token_kept_out(&w, &rest, &err, &token);
            let id = w.fake().vms.keys().next().cloned().expect("the workspace's VM");
            assert_eq!(exit.code(), Some(status), "{name}: {err}");
            assert!(err.contains(&format!("({name}) while the setup-token was being delivered to {id}: the delivery was given up; nothing was delivered")), "{name}: {err}");
            assert!(err.contains(&format!("{id} was started for this workspace and keeps running")), "{name}: {err}");
            // Time for whatever the released upgrade could still carry.
            std::thread::sleep(Duration::from_millis(300));
            assert!(w.audit("credential_deliver").is_empty() && !w.shim.spawns.credential().has(), "{name}: delivered after the stop");
            let row = ai_env_cli::bridge::vm::registry::read_row(&Paths::from_root_and_env(w.root.join("bridge"), None), &id).unwrap().unwrap();
            assert_eq!((row.credential_at, row.credential_tag), (None, None), "{name}: the row names no delivery");
        }
    }

    /// M2 (a stop while the command is busy): SIGINT during a step that does
    /// not yield (here the `age --version` that precedes the token's prompt,
    /// after the runtime key's Touch ID) is answered as soon as the command
    /// yields, before the token's dialog opens. The exec's own listeners,
    /// taken before GetMicrovm, answer it and end `vm exec --with-credential`
    /// there: 130, their line (nothing was sent), one Touch ID (the runtime
    /// key's); the token's unseal, dropped before its prompt, is audited
    /// `stopped`; nothing delivered or spawned. (The unseal's own check for a
    /// stop that came before it is not what answers here: it answers at the
    /// first prompt, before any phase listens:
    /// `a_stop_before_the_first_prompt_never_opens_its_dialog`.)
    #[test]
    fn a_stop_before_the_tokens_prompt_spares_its_dialog() {
        use std::os::unix::fs::PermissionsExt as _;
        let token = setup_token("Uw");
        let w = World::credentialed(&token);
        let real = w.root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/age.sh"), real.join("age")).unwrap();
        // Once the runtime key's decrypt is logged, `age --version` says it runs and takes 2 s.
        let probing = w.root.join("probing");
        let wrapper = format!(
            "#!/bin/sh\nn=$(grep -c '^age -d ' \"$FAKE_AGE_LOG\" 2>/dev/null)\nif [ \"${{1:-}}\" = --version ] && [ \"${{n:-0}}\" -ge {} ]; then\n  : > '{}'\n  sleep 2\nfi\nexec /bin/sh '{}' \"$@\"\n",
            w.decrypts() + 1,
            probing.display(),
            real.join("age").display()
        );
        std::fs::write(w.bin().join("age"), wrapper).unwrap();
        std::fs::set_permissions(w.bin().join("age"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let before = w.decrypts();
        let live = Live::start(w.cred_exec(&["--with-credential", "--", "true"]));
        wait_for("the probe before the token's prompt", || probing.exists());
        live.signal(libc::SIGINT);
        let (exit, rest, err) = live.finish();
        let err = token_kept_out(&w, &rest, &err, &token);
        assert_eq!(exit.code(), Some(130), "{err}");
        assert!(err.contains(&format!("ai-env: interrupted (SIGINT) before the command started on {}: nothing was sent", w.id)), "{err}");
        assert_eq!(w.decrypts() - before, 1, "the runtime key's Touch ID only: the token's dialog never opened");
        let unsealed = w.audit("credential_unseal");
        assert!(unsealed.len() == 1 && unsealed[0]["detail"]["source"] == "setup-token" && unsealed[0]["detail"]["outcome"] == "stopped", "the token's unseal, stopped before its prompt: {unsealed:?}");
        assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty());
    }

    /// M2 in `vm exec` (the unseal fixer's leftover 1): from the first Touch ID
    /// until its command starts, a credentialed exec's stop drops whatever is
    /// under way. Here the token's own prompt (no combined.env: the runtime
    /// key answered first) waits when SIGINT, SIGTERM or SIGHUP comes: the exec
    /// ends at once with 130 or 143 and its own line (nothing was sent), the
    /// dialog's whole group is gone, the dropped unseal is still audited
    /// (`credential_unseal`, outcome `stopped`), nothing is delivered or
    /// spawned, and the token is nowhere in the output or under the world's
    /// root. (A stop during a slow GetMicrovm:
    /// `a_stop_during_a_slow_getmicrovm_ends_vm_exec_at_once`.)
    #[test]
    fn a_stop_during_the_tokens_own_prompt_ends_vm_exec_with_nothing_sent() {
        let token = setup_token("Ia");
        let w = World::credentialed(&token);
        for (n, (sig, name, status, word)) in [(libc::SIGINT, "SIGINT", 130, "interrupted"), (libc::SIGTERM, "SIGTERM", 143, "terminated"), (libc::SIGHUP, "SIGHUP", 143, "terminated")].into_iter().enumerate() {
            // The runtime key answers; the token's own prompt goes unanswered.
            let reaper = hang_after(&w, w.decrypts() + 1);
            let live = Live::start(w.cred_exec(&["--with-credential", "--", "true"]));
            let pgid = reaper.group();
            live.signal(sig);
            let (exit, rest, err) = live.finish();
            let err = token_kept_out(&w, &rest, &err, &token);
            assert_eq!(exit.code(), Some(status), "{name}: {err}");
            assert!(err.contains(&format!("ai-env: {word} ({name}) before the command started on {}: nothing was sent", w.id)), "{name}: {err}");
            assert!(group_gone(pgid), "{name}: the dialog's group outlived the stop");
            let unsealed = w.audit("credential_unseal");
            let last = &unsealed.last().expect("the token's unseal is audited")["detail"];
            assert!(unsealed.len() == n + 1 && last["source"] == "setup-token" && last["id"] == w.id.as_str() && last["outcome"] == "stopped", "{name}: {unsealed:?}");
        }
        assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty() && !w.shim.spawns.credential().has());
    }

    /// M2, the unseal's own check for a stop that came before it: SIGINT
    /// while a credentialed `vm exec`'s first unseal is busy before its
    /// prompt (here in its `age --version`, held until the signal is sent),
    /// before any phase listens (the listeners the command took at its start
    /// hold it), is seen by that unseal before its dialog would open: 130, its
    /// own line (stopped before Touch ID was asked for), no countdown, no
    /// decrypt. Without combined.env that unseal is the runtime key's; with
    /// it, the runtime key's and the token's together, audited `exit 130`.
    /// Nothing delivered or spawned; the token nowhere in the output or under
    /// the world's root.
    #[test]
    fn a_stop_before_the_first_prompt_never_opens_its_dialog() {
        use std::os::unix::fs::PermissionsExt as _;
        for (combined, what, tail) in [(false, "the runtime key", "If"), (true, "the runtime key and the setup token", "Ig")] {
            let token = setup_token(tail);
            let w = World::credentialed(&token);
            if combined {
                seal_combined(&w, &token);
            }
            let real = w.root.join("real");
            std::fs::create_dir_all(&real).unwrap();
            std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/age.sh"), real.join("age")).unwrap();
            // The first `age --version` (the first unseal's) says it runs, then waits (at most 30 s) for `go`.
            let (probing, go) = (w.root.join("probing"), w.root.join("go"));
            let wrapper = format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = --version ] && [ ! -e '{p}' ]; then\n  : > '{p}'\n  n=0\n  while [ ! -e '{g}' ] && [ \"$n\" -lt 3000 ]; do sleep 0.01; n=$((n + 1)); done\nfi\nexec /bin/sh '{r}' \"$@\"\n",
                p = probing.display(),
                g = go.display(),
                r = real.join("age").display()
            );
            std::fs::write(w.bin().join("age"), wrapper).unwrap();
            std::fs::set_permissions(w.bin().join("age"), std::fs::Permissions::from_mode(0o755)).unwrap();
            let (before, unseals) = (w.decrypts(), w.audit("credential_unseal").len());
            let live = Live::start(w.cred_exec(&["--with-credential", "--", "true"]));
            wait_for("the first unseal's age --version", || probing.exists());
            live.signal(libc::SIGINT);
            std::fs::write(&go, "").unwrap();
            let (exit, rest, err) = live.finish();
            let err = token_kept_out(&w, &rest, &err, &token);
            assert_eq!(exit.code(), Some(130), "{what}: {err}");
            assert!(err.contains(&format!("ai-env: stopped before Touch ID was asked for (SIGINT): {what} stayed sealed")), "{what}: {err}");
            assert!(!err.contains("waiting for Touch ID"), "{what}: a countdown: {err}");
            assert_eq!(w.decrypts(), before, "{what}: a decrypt started");
            if combined {
                let rows = w.audit("credential_unseal");
                assert!(rows.len() == unseals + 1 && rows[unseals]["detail"]["source"] == "combined" && rows[unseals]["detail"]["outcome"] == "exit 130", "{what}: {rows:?}");
            }
            assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty(), "{what}: something was sent");
        }
    }

    /// M2 in `vm exec`, what the exec's own listeners are for: from the first
    /// Touch ID until its command starts, a stop drops whatever is under way at
    /// once, a call in flight included. Here GetMicrovm answers 10 s late (the
    /// fake parks it) with the token already in hand (a current combined.env):
    /// SIGINT, SIGTERM or SIGHUP ends the exec well within that, with 130 or
    /// 143 and its line (nothing was sent), before the gate ran (no
    /// `credential_gate` row); nothing is delivered or spawned, and the token
    /// is nowhere in the output or under the world's root. (A stop used to
    /// wait in the kept listeners for the late answer and the gate, until the
    /// pump took it.)
    #[test]
    fn a_stop_during_a_slow_getmicrovm_ends_vm_exec_at_once() {
        let token = setup_token("Ih");
        let w = World::credentialed(&token);
        seal_combined(&w, &token);
        for (sig, name, status, word) in [(libc::SIGINT, "SIGINT", 130, "interrupted"), (libc::SIGTERM, "SIGTERM", 143, "terminated"), (libc::SIGHUP, "SIGHUP", 143, "terminated")] {
            w.update_fake(|s| s.park_get_ms = 10_000);
            let gates = w.audit("credential_gate").len();
            let live = Live::start(w.cred_exec(&["--with-credential", "--", "true"]));
            wait_for("the parked GetMicrovm", || w.fake().park_get_ms == 0);
            let stopped = Instant::now();
            live.signal(sig);
            let (exit, rest, err) = live.finish();
            let took = stopped.elapsed();
            let err = token_kept_out(&w, &rest, &err, &token);
            assert_eq!(exit.code(), Some(status), "{name}: {err}");
            assert!(took < Duration::from_secs(5), "{name}: ended {} ms after the stop, not at once: {err}", took.as_millis());
            assert!(err.contains(&format!("ai-env: {word} ({name}) before the command started on {}: nothing was sent", w.id)), "{name}: {err}");
            assert_eq!(w.audit("credential_gate").len(), gates, "{name}: the gate ran");
        }
        assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty() && !w.shim.spawns.credential().has());
    }
}

// ---- S7 fix wave: probes ----

/// What fd-delivery's note says of the environments read while claude ran,
/// on this host, up to what varies by run: where there is no /proc (a Mac)
/// the emulated platform's shim cannot be scanned, and the probe says so
/// (then names claude's pid).
fn environs_words() -> &'static str {
    if std::path::Path::new("/proc/self").is_dir() {
        "its environments while it ran: 0 entries with the token in "
    } else {
        "its environments while it ran: not judged (no /proc where the emulated platform's shim runs: claude's pid "
    }
}

/// The number right after `label` in `note` (`cold 1234 ms` → 1234).
fn figure(note: &str, label: &str) -> Option<u128> {
    note.split(label).nth(1)?.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

/// S7 T7.3 under `[creds] deliver = "env"` (what tree A may decide):
/// fd-delivery still measures fd delivery. Its scan spawn gets the token on
/// fd 3, with nothing under its name in its environment, and claude answers
/// with the fd alone: fd-honoured, the delivery audited as fd. (The scan
/// spawn used to follow `[creds]`: the token in its environment and fd 3
/// closed, recorded as a shim bug.) The token is nowhere in the output or
/// under the world's root.
#[test]
fn lab_fd_delivery_delivers_on_fd_whatever_creds_deliver_says() {
    let token = setup_token("Nn");
    let w = World::platform(Some(&probe_claude(&token, "fd")));
    w.seed_credentials(&token, "1.0");
    let toml_path = w.root.join("bridge").join("bridge.toml");
    let cfg = std::fs::read_to_string(&toml_path).unwrap();
    std::fs::write(&toml_path, format!("{cfg}\n[creds]\ndeliver = \"env\"\n")).unwrap();
    let o = run(w.sealed_cmd(&["lab", "run", "fd-delivery"]), None);
    assert_eq!(code(&o), 0, "{}", masked(&text(&o.stderr), &token));
    let row = probe_row(&w, "fd-delivery").expect("a fd-delivery row");
    let note = masked(row["note"].as_str().unwrap_or_default(), &token);
    assert_eq!(row["verdict"], "fd-honoured", "{note}");
    assert!(note.contains(&format!("environ entries with the token's name or a value of its kind 0, fd 3 {} bytes; claude via fd answered, {}", token.len(), environs_words())), "{note}");
    let delivered = w.audit("credential_deliver");
    assert_eq!((delivered.len(), delivered[0]["detail"]["deliver"].as_str()), (1, Some("fd")));
    assert_token_nowhere(&w, &o, &token);
}

/// S7 T7.3's custody half: a pass needs has_credentials read after the
/// suspend and the resume. Here `/health/detail` cannot be read at all (the
/// fake fails it twice: the delivery's cache check, then the read after the
/// resume), so the verdict is gap:has-credentials, not fd-honoured, and `lab
/// run` exits 1 after recording it. (It used to record fd-honoured.) The
/// token is nowhere in the output or under the world's root.
#[test]
fn lab_fd_delivery_is_no_pass_without_has_credentials_read() {
    let token = setup_token("Pp");
    let w = World::platform(Some(&probe_claude(&token, "fd")));
    w.seed_credentials(&token, "1.0");
    w.update_fake(|s| {
        for _ in 0..2 {
            s.failures.push_back(FakeFailure { kind: "endpoint".into(), message: "the detail is unreadable".into(), on: Some("health_detail".into()), after_effect: false });
        }
    });
    let o = run(w.sealed_cmd(&["lab", "run", "fd-delivery"]), None);
    let err = masked(&text(&o.stderr), &token);
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.contains("probe verdict differs from the expectation: fd-delivery=gap:has-credentials (expected fd-honoured)"), "{err}");
    let row = probe_row(&w, "fd-delivery").expect("the row is recorded");
    let note = masked(row["note"].as_str().unwrap_or_default(), &token);
    assert!(note.contains("claude via fd answered") && note.contains("has_credentials after a suspend and a resume: unread"), "{note}");
    assert!(w.fake().failures.is_empty(), "both reads failed as scripted");
    assert_token_nowhere(&w, &o, &token);
}

/// S7 T7.3: fd-delivery asks claude the same way both times, as a
/// stream-json host, so its two answers differ in the delivery alone. This
/// claude takes the token from fd 3 or from its environment, whichever it
/// is given, but has no host mode (it exits 2 on `--input-format
/// stream-json`): it answered neither way, never env-only, and `lab run`
/// exits 1 after recording that. (The env attempt used to be a one-shot
/// `claude -p`, which it answers: env-only, which would send tree A to
/// `[creds] deliver = "env"`.) The token is nowhere in the output or under
/// the world's root.
#[test]
fn lab_fd_delivery_asks_both_ways_as_a_host() {
    let token = setup_token("Ww");
    let either = "got=$(if [ -n \"${CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR:-}\" ]; then sha <&3; else printf %s \"${CLAUDE_CODE_OAUTH_TOKEN:-}\" | sha; fi)";
    let no_host = "#!/bin/sh\ncase \" $* \" in *\" --input-format stream-json \"*) echo 'error: unknown option --input-format' >&2; exit 2 ;; esac\n";
    let claude = PROBE_CLAUDE.replace("GOT", either).replace("WANT", &sha256(token.as_bytes())).replacen("#!/bin/sh\n", no_host, 1);
    assert!(claude.contains("exit 2 ;;") && claude.contains("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"), "the stand-in reads either way and has no host mode");
    let w = World::platform(Some(&claude));
    w.seed_credentials(&token, "1.0");
    let o = run(w.sealed_cmd(&["lab", "run", "fd-delivery"]), None);
    let err = masked(&text(&o.stderr), &token);
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.contains("probe verdict differs from the expectation: fd-delivery=fd-unread:claude-answered-neither-way (expected fd-honoured)"), "{err}");
    let row = probe_row(&w, "fd-delivery").expect("the row is recorded");
    let note = masked(row["note"].as_str().unwrap_or_default(), &token);
    assert!(note.contains("claude via fd did not answer, its environments while it ran: unread (claude gave no result); via env (the token put in that one claude's environment, to classify) did not answer; "), "{note}");
    assert_token_nowhere(&w, &o, &token);
}

/// S7 T7.3's environment scan runs while claude still runs, told claude's
/// own pid. This claude writes its pid next to itself and exits at its
/// stdin's EOF, so a scan sent after the EOF, or told another pid, reads
/// otherwise: where there is no /proc (a Mac) the note names the pid the
/// scan was told and that the process was still running; where there is
/// /proc, claude's own environment is among those read. One claude ran (it
/// answered with the fd alone). The token is nowhere in the output or under
/// the world's root.
#[test]
fn lab_fd_delivery_scans_claudes_environment_while_it_runs() {
    let token = setup_token("Xx");
    let claude = probe_claude(&token, "fd").replacen("#!/bin/sh\n", "#!/bin/sh\necho $$ >>\"$(dirname \"$0\")/claude-pids\"\n", 1);
    let w = World::platform(Some(&claude));
    w.seed_credentials(&token, "1.0");
    let o = run(w.sealed_cmd(&["lab", "run", "fd-delivery"]), None);
    assert_eq!(code(&o), 0, "{}", masked(&text(&o.stderr), &token));
    let pids = std::fs::read_to_string(w.root.join("claude-pids")).unwrap_or_default();
    let pids: Vec<&str> = pids.split_whitespace().collect();
    assert_eq!(pids.len(), 1, "one claude: {pids:?}");
    let note = masked(probe_row(&w, "fd-delivery").expect("a fd-delivery row")["note"].as_str().unwrap_or_default(), &token);
    if std::path::Path::new("/proc/self").is_dir() {
        assert!(note.contains("claude via fd answered, its environments while it ran: 0 entries with the token in ") && note.contains(" read, claude's own among them; "), "{note}");
    } else {
        assert!(note.contains(&format!("claude via fd answered, {}{} running at the scan); ", environs_words(), pids[0])), "{note}");
    }
    assert_token_nowhere(&w, &o, &token);
}

/// S7 T7.7: init-budget judges each figure at claude's answer to
/// `initialize`, not at its session's end. This claude's second (warm) run
/// lingers 6 s after its stdin closes: the note shows that as the warm
/// session's close, not counted, and the warm figure (the gate, then the
/// spawn to the answer) stays within its 5 s. (Taken at the session's end it
/// read over:warm.) The token is nowhere in the output or under the world's root.
#[test]
fn lab_init_budget_judges_the_answer_not_the_sessions_close() {
    let token = setup_token("Qq");
    let lingering = probe_claude(&token, "fd").replace("    done ;;\n", "    done\n    m=\"$(dirname \"$0\")/warm-mark\"\n    if [ -e \"$m\" ]; then sleep 6; fi\n    : >\"$m\" ;;\n");
    assert_ne!(lingering, probe_claude(&token, "fd"), "the stand-in lingers on its second run");
    let w = World::platform(Some(&lingering));
    w.seed_credentials(&token, "1.0");
    let o = run(w.sealed_cmd(&["lab", "run", "init-budget"]), None);
    assert_eq!(code(&o), 0, "{}", masked(&text(&o.stderr), &token));
    let row = probe_row(&w, "init-budget").expect("an init-budget row");
    let note = masked(row["note"].as_str().unwrap_or_default(), &token);
    assert_eq!(row["verdict"], "within-budget", "{note}");
    let warm = figure(&note, "; warm ").expect("the warm figure");
    let closes = note.split("each session's close after its answer: ").nth(1).expect("the sessions' closes");
    let warm_close = figure(closes, " and ").expect("the warm close");
    assert!(warm < 5_000 && warm_close >= 6_000, "warm {warm} ms judged, its close {warm_close} ms not: {note}");
    assert_token_nowhere(&w, &o, &token);
}

/// S7 T7.7 with a current combined.env: the one Touch ID that unseals the
/// runtime key and the token comes before the VM is started, and the cold
/// figure counts it (plan S7 §7's cold path), named as its own leg: here a
/// Touch ID answered after 5 s. One decrypt for both. (The clock used to
/// start after it.) The token is nowhere in the output or under the world's root.
#[test]
fn lab_init_budget_counts_the_combined_unseal_in_the_cold_path() {
    let token = setup_token("Rr");
    let w = World::platform(Some(&probe_claude(&token, "fd")));
    w.seed_credentials(&token, "1.0");
    let o = run(w.sealed_cmd(&["creds", "setup-token", "--stdin"]), Some(format!("{token}\n").into_bytes()));
    assert!(o.status.success(), "creds setup-token, combined.env rebuilt: {}", masked(&text(&o.stderr), &token));
    assert!(w.root.join("bridge").join("credentials").join("combined.env").is_file(), "combined.env built");
    let before = w.decrypts();
    let mut cmd = w.sealed_cmd(&["lab", "run", "init-budget"]);
    cmd.env("FAKE_AGE_DELAY_MS", "5000");
    let o = run(cmd, None);
    assert_eq!(code(&o), 0, "{}", masked(&text(&o.stderr), &token));
    assert_eq!(w.decrypts() - before, 1, "one Touch ID for the runtime key and the token");
    let row = probe_row(&w, "init-budget").expect("an init-budget row");
    let note = masked(row["note"].as_str().unwrap_or_default(), &token);
    assert_eq!(row["verdict"], "within-budget", "{note}");
    assert!(note.contains(" ms (combined: the one Touch ID for the runtime key and the token, before the VM was started), "), "{note}");
    let (unseal, cold) = (figure(&note, "the token's unseal ").expect("the unseal leg"), figure(&note, ": cold ").expect("the cold figure"));
    assert!(unseal >= 5_000 && cold >= unseal, "cold {cold} ms counts the unseal's {unseal} ms: {note}");
    assert_token_nowhere(&w, &o, &token);
}

/// A `claude` on this Mac for oauth-t1 (found on PATH: no Cursor bundle
/// under the world's HOME): its version, and in stream-json host mode, for
/// the user message, a refresh request and an error result, then its exit.
/// It asks for the refresh only when offered it as the real CLI must be
/// (F1): `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH` set and an entrypoint of its
/// `SDK_OAUTH_REFRESH_ENTRYPOINTS`.
const OAUTH_CLAUDE: &str = r#"#!/bin/sh
case "$1" in --version) echo '2.1.290 (Claude Code)'; exit 0 ;; esac
while IFS= read -r line; do
  case "$line" in
    *'"type":"user"'*)
      case "${CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH:-}:${CLAUDE_CODE_ENTRYPOINT:-}" in
        1:claude-desktop|1:local-agent|1:claude-vscode) printf '%s\n' '{"type":"control_request","request_id":"r1","request":{"subtype":"oauth_token_refresh"}}' ;;
      esac
      printf '%s\n' '{"type":"result","subtype":"error_during_execution","is_error":true}'
      exit 1 ;;
  esac
done
"#;

/// S7 T7.6: oauth-t1 never sends a seal Anthropic refused as its valid
/// reply. With a rejection recorded against the sealed setup-token the valid
/// run is skipped, said at once, with no Touch ID, and the row says why;
/// with none recorded the valid run goes ahead (one Touch ID). Its row
/// carries nothing of the image (it measured this Mac's CLI, whose version
/// the note names). The token is nowhere in either output or under the
/// world's root.
#[test]
fn lab_oauth_t1_never_replies_with_a_refused_seal() {
    use std::os::unix::fs::PermissionsExt as _;
    let token = setup_token("Ss");
    let w = World::bare(None);
    w.seed_credentials(&token, "1.0");
    let claude = w.bin().join("claude");
    std::fs::write(&claude, OAUTH_CLAUDE).unwrap();
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
    let state = w.root.join("bridge").join("state");
    std::fs::write(state.join("infra.toml"), "latest_active_image_version = \"6.0\"\nclaude_version = \"2.1.288\"\n").unwrap();
    let tag = ai_env_cli::bridge::agent::credential::seal_tag(&w.root.join("bridge").join("credentials").join("setup-token.env")).unwrap();
    std::fs::write(state.join("creds.toml"), format!("[[rejected]]\ntag = \"{tag}\"\nat = \"2026-10-08T09:00:00Z\"\nvm = \"microvm-refused\"\n")).unwrap();
    let before = w.decrypts();
    let o = run(w.sealed_cmd(&["lab", "run", "oauth-t1"]), None);
    assert_token_nowhere(&w, &o, &token);
    let err = text(&o.stderr);
    assert_eq!(code(&o), 0, "{err}");
    assert_eq!(w.decrypts(), before, "a refused seal is never unsealed");
    assert!(err.contains(&format!("the valid reply will be skipped: the sealed token (seal {tag}) was refused by Anthropic")), "{err}");
    let row = probe_row(&w, "oauth-t1").expect("an oauth-t1 row");
    let note = row["note"].as_str().unwrap_or_default().to_string();
    assert_eq!(row["verdict"], "refresh-requested", "{note}");
    assert!(note.contains("(2.1.290 (Claude Code))") && note.contains(&format!("valid: skipped (the sealed token (seal {tag}) was refused by Anthropic on 2026-10-08T09:00:00Z (microvm-refused)")), "{note}");
    assert!(row.get("claude").is_none() && row.get("image_version").is_none() && row["ext"].is_null(), "nothing of the image: {row}");
    std::fs::remove_file(state.join("creds.toml")).unwrap();
    let o = run(w.sealed_cmd(&["lab", "run", "oauth-t1"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert_eq!(w.decrypts() - before, 1, "the valid reply's Touch ID");
    let note = probe_row(&w, "oauth-t1").unwrap()["note"].as_str().unwrap_or_default().to_string();
    assert!(note.contains("; valid: refresh@"), "{note}");
}

/// S7: a SIGTERM while a credential probe's own unseal waits for Touch ID
/// (without combined.env the token is a second Touch ID, after the VM
/// started) exits 143, as `vm exec` does for the same stop, never 1 with a
/// `config:` line. `lab run` takes the stop itself (M2: SIGTERM and SIGHUP
/// end a probe as Ctrl-C does, where they used to be left to the unseal or
/// swallowed): its line, the dialog closed with the probe (the decrypt's
/// group is gone, the dropped unseal audited `stopped`), the probe's VM
/// ended, nothing recorded. The token is nowhere in the output or under the
/// world's root. (A credential step's own failure keeping its class through
/// a probe: `lab_run_keeps_a_credential_steps_exit_class`.)
#[test]
fn lab_a_sigterm_at_a_probes_token_prompt_ends_lab_run_with_143() {
    use std::os::unix::fs::PermissionsExt as _;
    let token = setup_token("Tt");
    let w = World::platform(Some(&probe_claude(&token, "fd")));
    w.seed_credentials(&token, "1.0");
    // The run's second decrypt (the token's, after the runtime key's) hangs as an unanswered dialog does.
    let real = w.bin().join("real");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::rename(w.bin().join("age"), real.join("age")).unwrap();
    let (count, pidfile) = (w.root.join("decrypts"), w.root.join("age.pid"));
    let wrapper = format!(
        "#!/bin/sh\ncase \" $* \" in\n  *\" -d \"*)\n    n=$(cat '{c}' 2>/dev/null || echo 0); n=$((n + 1)); echo \"$n\" >'{c}'\n    if [ \"$n\" -ge 2 ]; then FAKE_AGE_HANG=1; FAKE_AGE_PIDFILE='{p}'; export FAKE_AGE_HANG FAKE_AGE_PIDFILE; fi ;;\nesac\nexec '{r}' \"$@\"\n",
        c = count.display(),
        p = pidfile.display(),
        r = real.join("age").display()
    );
    std::fs::write(w.bin().join("age"), wrapper).unwrap();
    std::fs::set_permissions(w.bin().join("age"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut cmd = w.sealed_cmd(&["lab", "run", "init-budget"]);
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (out, err) = (read_all(child.stdout.take().unwrap()), read_all(child.stderr.take().unwrap()));
    wait_for("the token's unseal waiting for Touch ID", || pidfile.is_file());
    // The unseal takes the signals once its dialog is up.
    std::thread::sleep(Duration::from_millis(300));
    // SAFETY: kill(2) on our own child's pid.
    assert_eq!(unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGTERM) }, 0);
    let pgid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
    let status = wait_bounded(&mut child);
    let (out, err) = (text(&out.join().unwrap()), text(&err.join().unwrap()));
    assert!(!out.contains(&token[13..]) && !err.contains(&token[13..]), "the output holds the token ({} and {} bytes)", out.len(), err.len());
    assert_eq!(status.code(), Some(143), "{err}");
    assert!(err.contains("lab: terminated (SIGTERM): ending every VM this probe started") && !err.contains("config:"), "{err}");
    let t = Instant::now();
    // SAFETY: a plain existence check of the hanging decrypt's group; signal 0 sends nothing.
    while unsafe { libc::killpg(pgid, 0) } == 0 {
        assert!(t.elapsed() < Duration::from_secs(5), "the dialog's group {pgid} outlived the stop");
        std::thread::sleep(Duration::from_millis(20));
    }
    let unsealed = w.audit("credential_unseal");
    assert!(unsealed.iter().any(|r| r["detail"]["source"] == "setup-token" && r["detail"]["outcome"] == "stopped"), "the dropped unseal is audited: {unsealed:?}");
    assert!(probe_row(&w, "init-budget").is_none(), "nothing recorded");
    assert!(w.fake().vms.values().all(|v| v.state.is_terminal()), "the probe's VM is ended");
    assert_token_off_disk(&w, &token);
}

/// S7 (M54): a credential step's own failure keeps its exit class and its
/// words through `lab run`, as `vm exec` gives them. Here init-budget's token
/// unseal, after the probe's VM started, finds no key named `[creds].key` in
/// the keystore (the runtime key is not unsealed: the fake API without its
/// unseal knob): exit 4 with the keystore's own words, never 1 behind a
/// `config:` prefix. That unseal is audited `exit 4`, the probe's VM is
/// ended, nothing is recorded, and the token is nowhere in the output or
/// under the world's root.
#[test]
fn lab_run_keeps_a_credential_steps_exit_class() {
    let token = setup_token("Ii");
    let w = World::platform(Some(&probe_claude(&token, "fd")));
    w.seed_credentials(&token, "1.0");
    let toml_path = w.root.join("bridge").join("bridge.toml");
    let cfg = std::fs::read_to_string(&toml_path).unwrap();
    std::fs::write(&toml_path, format!("{cfg}\n[creds]\nkey = \"no-such-key\"\n")).unwrap();
    let mut cmd = w.sealed_cmd(&["lab", "run", "init-budget"]);
    cmd.env_remove("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL");
    let o = run(cmd, None);
    assert_token_nowhere(&w, &o, &token);
    let err = text(&o.stderr);
    assert_eq!(code(&o), 4, "{err}");
    assert!(err.contains("ai-env: key \"no-such-key\" does not exist (ai-env keys list)") && !err.contains("config:"), "{err}");
    let unsealed = w.audit("credential_unseal");
    assert!(unsealed.iter().any(|r| r["detail"]["source"] == "setup-token" && r["detail"]["outcome"] == "exit 4"), "{unsealed:?}");
    assert!(probe_row(&w, "init-budget").is_none(), "nothing recorded");
    let vms = w.fake().vms;
    assert!(!vms.is_empty() && vms.values().all(|v| v.state.is_terminal()), "the probe's VM was started, and is ended");
}

/// S7: a credential probe refuses on what this Mac holds, before any Touch
/// ID, judged on the VM it would start as `vm warm` judges its own: with the
/// only passing `egress check` 8 days old, `lab run fd-delivery` and `lab
/// run init-budget` exit 9 naming its age, with no decrypt, no VM started,
/// nothing recorded, and the local half's refusal audited. (They used to
/// unseal the runtime key and start a VM first.) The token is nowhere in
/// either output or under the world's root.
#[test]
fn lab_credential_probes_refuse_a_stale_check_before_any_touch_id() {
    use ai_env_cli::bridge::egress::EgressVerified;
    let token = setup_token("Uu");
    let w = World::platform(Some(&probe_claude(&token, "fd")));
    w.seed_credentials(&token, "1.0");
    let path = w.root.join("bridge").join("state").join("egress-verified.toml");
    let mut verified: EgressVerified = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    verified.records[0].at = ai_env_cli::wire::time::rfc3339_utc(ai_env_cli::wire::time::unix_now() - 8 * 24 * 3600);
    std::fs::write(&path, toml::to_string(&verified).unwrap()).unwrap();
    let before = w.decrypts();
    for probe in ["fd-delivery", "init-budget"] {
        let o = run(w.sealed_cmd(&["lab", "run", probe]), None);
        assert_token_nowhere(&w, &o, &token);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 9, "{err}");
        assert!(err.contains("no credential for a vpc VM of image version 1.0") && err.contains("more than 7 days ago") && err.contains("nothing was unsealed or started"), "{err}");
        assert!(probe_row(&w, probe).is_none(), "nothing recorded");
    }
    assert_eq!(w.decrypts(), before, "no Touch ID");
    assert!(w.fake().vms.is_empty(), "no VM started");
    assert_eq!(w.audit("credential_gate").iter().filter(|r| r["detail"]["condition"] == "record_age" && r["detail"]["half"] == "local").count(), 2);
}

// ---- S7 integration: the fix wave's leftovers ----

/// The tests of what the integration applied from the fixers' leftovers, in
/// a module of their own: their helpers and imports stay theirs.
mod integration_fixes {
    use super::*;
    use ai_env_cli::bridge::agent::credential::{prepare, seal_tag, CredentialPlan, CredentialSupply};
    use ai_env_cli::bridge::config::BridgeConfig;
    use ai_env_cli::bridge::lab::VmKnobs;
    use ai_env_cli::bridge::setup_token::parse_token;
    use ai_env_cli::bridge::vm::cmd::Ctx;
    use ai_env_cli::store::Keystore;
    use ai_env_cli::wire::frame::Deliver;

    /// The world's sealed setup-token.
    fn token_env(w: &World) -> PathBuf {
        w.root.join("bridge").join("credentials").join("setup-token.env")
    }

    /// What `prepare` needs of a credentialed world: the command's context,
    /// the file-backed fake, the keystore, the plan `check` would make (the
    /// sealed setup-token's seal id, on fd) and the VM as GetMicrovm reports it.
    fn prepared_world(w: &World, rt: &tokio::runtime::Runtime) -> (Ctx, FileFakeMicrovmApi, Keystore, CredentialPlan, VmInfo) {
        let paths = Paths::from_root_and_env(w.root.join("bridge"), None);
        let cfg = BridgeConfig::load(&paths).unwrap().unwrap();
        let fake = FileFakeMicrovmApi::open(&w.fake_path()).unwrap();
        let store = Keystore::resolve(Some(w.root.join("keys"))).unwrap();
        let plan = CredentialPlan { deliver: Deliver::Fd, file: None, tag: seal_tag(&token_env(w)).unwrap() };
        let vm = rt.block_on(fake.get(&w.id)).unwrap();
        (Ctx { paths, cfg, knobs: VmKnobs::default() }, fake, store, plan, vm)
    }

    /// M38 (C5), the token in hand: with a current `combined.env` the token
    /// comes with the runtime key, and with the seal id that text records for
    /// it (`token_file_sha256`). `prepare` sends it only under the seal id
    /// `check` read: one recorded for another seal (a `combined.env` rebuilt
    /// from a token sealed anew while the command waited) is refused, exit 5,
    /// nothing sent; the seal checked binds the delivery, value in hand. (A
    /// token in hand used to be sent under the checked seal id whatever it was
    /// sealed as.) The token is nowhere under the world's root.
    #[test]
    fn a_token_in_hand_goes_out_only_under_the_seal_it_was_checked_under() {
        let token = setup_token("Ib");
        let w = World::credentialed(&token);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (ctx, fake, store, plan, vm) = prepared_world(&w, &rt);
        let row = w.row();
        let in_hand = |recorded: &str| CredentialSupply { store: &store, token: Some((parse_token(&token).unwrap_or_else(|f| panic!("{}", f.message)), recorded.to_string())) };
        let other = "0123456789abcdef";
        let e = rt.block_on(prepare(&ctx, &fake, &fake, &row, &vm, &plan, in_hand(other))).err().expect("a token recorded for another seal is refused");
        assert_eq!(e.exit_code(), 5, "{}", masked(&e.to_string(), &token));
        let says = format!("setup-token.env was sealed anew while this command ran (seal {} when it was checked, {other} in what was unsealed): nothing was sent; run the command again", plan.tag);
        assert!(e.to_string().contains(&says), "{}", masked(&e.to_string(), &token));
        let prepared = rt.block_on(prepare(&ctx, &fake, &fake, &row, &vm, &plan, in_hand(&plan.tag))).unwrap_or_else(|e| panic!("prepare: {}", masked(&e.to_string(), &token)));
        assert_eq!((prepared.source, prepared.delivery.tag(), prepared.delivery.holds_value()), ("combined", plan.tag.as_str(), true));
        assert!(w.audit("credential_deliver").is_empty() && w.audit("credential_unseal").is_empty(), "prepare sends and unseals nothing here");
        assert_token_off_disk(&w, &token);
    }

    /// M46 (C8): a token of a shape the scrubber's rules do not mask whole is
    /// masked only while a handle registered it, and `prepare` drops its
    /// handle before the value is sent: the delivery's copy keeps it masked
    /// from then until the delivery drops it, so a line quoting it while the
    /// session runs is still masked; once the delivery is gone it is not
    /// registered any more (no copy outlives the value). Neither the odd
    /// token nor the sealed one is in any file under the world's root.
    #[test]
    fn a_token_of_an_unrecognised_shape_stays_masked_while_its_delivery_holds_it() {
        use ai_env_cli::wire::redact::scrub;
        let token = setup_token("Ic");
        let w = World::credentialed(&token);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (ctx, fake, store, plan, vm) = prepared_world(&w, &rt);
        let row = w.row();
        let odd = format!("odd-shape-integration-{}", "Ic7".repeat(9));
        let masked_now = || !scrub(&format!("x {odd} y")).contains(&odd);
        let supply = CredentialSupply { store: &store, token: Some((parse_token(&odd).unwrap_or_else(|f| panic!("{}", f.message)), plan.tag.clone())) };
        assert!(masked_now(), "the handle registered it");
        let prepared = rt.block_on(prepare(&ctx, &fake, &fake, &row, &vm, &plan, supply)).unwrap_or_else(|e| panic!("prepare: {}", e.exit_code()));
        assert!(prepared.delivery.holds_value());
        assert!(masked_now(), "the handle is gone, the delivery's copy keeps it masked");
        drop(prepared);
        assert!(!masked_now(), "forgotten with the delivery");
        let leaks = files_holding(&w.root, odd.as_bytes());
        assert!(leaks.is_empty(), "{} files hold the odd token: {leaks:?}", leaks.len());
        assert_token_off_disk(&w, &token);
    }

    /// C14: `vm health --detail` says what this Mac's row records the VM
    /// received, beside what its shim says it caches: `--json` gives `row`
    /// with `credential_at` and `credential_tag`, both null before any
    /// delivery and the delivery's time and seal after one (as the row records
    /// them), and the summary's credentials line adds them. The token is in
    /// none of these outputs and in no file under the world's root.
    #[test]
    fn vm_health_detail_names_what_this_macs_row_says_the_vm_received() {
        let token = setup_token("Ij");
        let w = World::credentialed(&token);
        let detail = |json: bool| {
            let mut args = vec!["vm", "health", w.id.as_str(), "--detail"];
            if json {
                args.push("--json");
            }
            let o = run(w.cmd(&args), None);
            assert_token_nowhere(&w, &o, &token);
            assert_eq!(code(&o), 0, "{}", text(&o.stderr));
            text(&o.stdout)
        };
        let doc: serde_json::Value = serde_json::from_str(&detail(true)).unwrap();
        assert!(doc["row"].is_object() && doc["row"]["credential_at"].is_null() && doc["row"]["credential_tag"].is_null(), "no delivery yet: {doc}");
        assert!(!detail(false).contains("this Mac's row"), "no delivery yet");
        let o = run(w.cred_exec(&["--with-credential", "--", "true"]), None);
        assert_token_nowhere(&w, &o, &token);
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        let row = w.row();
        let at = ai_env_cli::wire::time::rfc3339_utc(row.credential_at.expect("the delivery is recorded"));
        let tag = row.credential_tag.expect("with its seal");
        assert_eq!(tag, seal_tag(&token_env(&w)).unwrap());
        let doc: serde_json::Value = serde_json::from_str(&detail(true)).unwrap();
        assert_eq!((doc["row"]["credential_at"].as_str(), doc["row"]["credential_tag"].as_str()), (Some(at.as_str()), Some(tag.as_str())), "{doc}");
        let summary = detail(false);
        assert!(summary.contains(&format!("; this Mac's row: a token was last sent to it (seal {tag}) at {at}")), "{summary}");
    }

    /// M38 (C5), the one rule: a token goes out only under the seal id of the
    /// bytes it was decrypted from, never of a second read of its file. Here
    /// `setup-token.env` is sealed anew while the token's own prompt is up,
    /// after its unseal read the file (one sealed anew before that read is
    /// refused before the prompt, F16: `fix_wave_2_gate::a_token_sealed_anew_before_its_unseal_costs_no_touch_id`):
    /// the token that goes out is the one those bytes hold, under their seal
    /// id, the one `check` read, though the file reads as another seal by then;
    /// a second read of it would have refused the delivery, or named the new
    /// seal. Neither token is in the output (but the command's stdout, the old
    /// one by design) or under the world's root.
    #[test]
    fn a_token_is_sent_only_under_the_seal_of_the_bytes_it_was_decrypted_from() {
        use std::os::unix::fs::PermissionsExt as _;
        let (old, new) = (setup_token("Id"), setup_token("Ie"));
        let w = World::credentialed(&old);
        let file = token_env(&w);
        let old_bytes = std::fs::read(&file).unwrap();
        let o = run(w.sealed_cmd(&["creds", "setup-token", "--stdin", "--no-combined"]), Some(format!("{new}\n").into_bytes()));
        for token in [&old, &new] {
            assert_token_nowhere(&w, &o, token);
        }
        assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
        let new_bytes = std::fs::read(&file).unwrap();
        let (old_tag, new_tag) = (sha256(&old_bytes)[..16].to_string(), sha256(&new_bytes)[..16].to_string());
        // `check` reads the old seal.
        std::fs::write(&file, &old_bytes).unwrap();
        // The runtime key's decrypt waits for `key-go`, the token's for `token-go`.
        let real = w.root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/age.sh"), real.join("age")).unwrap();
        let (key_go, token_go) = (w.root.join("key-go"), w.root.join("token-go"));
        let base = w.decrypts();
        let wrapper = format!(
            "#!/bin/sh\nn=$(grep -c '^age -d ' \"$FAKE_AGE_LOG\" 2>/dev/null)\nif [ \"${{1:-}}\" = -d ] && [ \"${{n:-0}}\" -eq {base} ]; then FAKE_AGE_WAIT_FILE='{}'; export FAKE_AGE_WAIT_FILE; fi\nif [ \"${{1:-}}\" = -d ] && [ \"${{n:-0}}\" -eq {} ]; then FAKE_AGE_WAIT_FILE='{}'; export FAKE_AGE_WAIT_FILE; fi\nexec /bin/sh '{}' \"$@\"\n",
            key_go.display(),
            base + 1,
            token_go.display(),
            real.join("age").display()
        );
        std::fs::write(w.bin().join("age"), wrapper).unwrap();
        std::fs::set_permissions(w.bin().join("age"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let cmd = w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3"]);
        let waiting = std::thread::spawn(move || run(cmd, None));
        wait_for("the runtime key's decrypt", || w.decrypts() > base);
        std::fs::write(&key_go, "").unwrap();
        wait_for("the token's decrypt", || w.decrypts() > base + 1);
        // Sealed anew once the token's unseal has read it, while its prompt is up.
        std::fs::write(&file, &new_bytes).unwrap();
        std::fs::write(&token_go, "").unwrap();
        let o = waiting.join().unwrap();
        // Its stdout is the old token by design: stderr holds neither token, and stdout not the new one.
        let err = text(&o.stderr);
        assert!(!text(&o.stdout).contains(&new[13..]) && [&old, &new].iter().all(|t| !err.contains(&t[13..])), "the output holds a token ({} and {} bytes)", o.stdout.len(), o.stderr.len());
        for token in [&old, &new] {
            assert_token_off_disk(&w, token);
        }
        assert_eq!(code(&o), 0, "{err}");
        assert!(text(&o.stdout) == old, "the token the decrypted bytes hold: stdout of {} bytes", o.stdout.len());
        assert_ne!(old_tag, new_tag);
        let delivered = w.audit("credential_deliver");
        assert_eq!(delivered.last().and_then(|r| r["detail"]["tag"].as_str()), Some(old_tag.as_str()), "sent under the seal id of the bytes decrypted");
        assert_eq!(w.row().credential_tag.as_deref(), Some(old_tag.as_str()), "and recorded under it");
    }
}

// ---- S7 fix wave 2: gate ----

/// The gate fixer's tests of the second fix wave (F2, F3, F4, F7, F8, F13,
/// F14, F16, F19), in a module of their own: their helpers and imports stay
/// theirs. F20's and F28's are unit tests (`vm::cmd`, `age_cmd`).
mod fix_wave_2_gate {
    use super::*;
    use ai_env_cli::bridge::agent::credential::{prepare, seal_tag, CredentialPlan, CredentialSupply};
    use ai_env_cli::bridge::api::{AuthToken, EndpointClient, HealthDetailReply, HealthReply};
    use ai_env_cli::bridge::config::BridgeConfig;
    use ai_env_cli::bridge::egress::EgressVerified;
    use ai_env_cli::bridge::errors::BridgeError;
    use ai_env_cli::bridge::lab::VmKnobs;
    use ai_env_cli::bridge::vm::cmd::Ctx;
    use ai_env_cli::store::Keystore;
    use ai_env_cli::wire::frame::{Deliver, CAP_CREDENTIAL_CACHE};
    use ai_env_cli::wire::time::{rfc3339_utc, unix_now};
    use std::path::Path;

    /// The world's `credentials/`.
    fn creds_dir(w: &World) -> PathBuf {
        w.root.join("bridge").join("credentials")
    }

    /// `ws/project`, created: the workspace `vm warm` is given.
    fn project(w: &World) -> String {
        let ws = w.root.join("ws").join("project");
        std::fs::create_dir_all(&ws).unwrap();
        ws.display().to_string()
    }

    /// `creds setup-token --stdin` of `token`, run to its end: building
    /// combined.env when `combined` (one Touch ID), else `--no-combined`.
    fn seal(w: &World, token: &str, combined: bool) -> Output {
        let mut args = vec!["creds", "setup-token", "--stdin"];
        if !combined {
            args.push("--no-combined");
        }
        run(w.sealed_cmd(&args), Some(format!("{token}\n").into_bytes()))
    }

    /// A runtime key for `creds aws-set`, built at run time from `tag` (four
    /// of `[A-Z0-9]`): its secret, and the JSON that command reads.
    fn runtime_key(tag: &str) -> (String, String) {
        let secret = format!("{}{}", "Tq8+".repeat(9), tag.to_lowercase());
        let json = format!("{{\"AccessKey\": {{\"UserName\": \"ai-env-runtime\", \"AccessKeyId\": \"AKIA{}\", \"Status\": \"Active\", \"SecretAccessKey\": \"{secret}\"}}}}", tag.repeat(4));
        (secret, json)
    }

    /// The runtime key `seed_credentials` sealed: its secret.
    fn seeded_key() -> String {
        format!("{}cred", "Tq8+".repeat(9))
    }

    /// `cmd` run on a thread with `stdin`, every decrypt of it held until
    /// `go` exists (an unanswered Touch ID: the fake waits at most 30 s);
    /// returns once its first decrypt began.
    fn held(w: &World, mut cmd: Command, stdin: Option<Vec<u8>>, go: &Path) -> std::thread::JoinHandle<Output> {
        let before = w.decrypts();
        cmd.env("FAKE_AGE_WAIT_FILE", go);
        let waiting = std::thread::spawn(move || run(cmd, stdin));
        wait_for("the held command's first decrypt", || w.decrypts() > before);
        waiting
    }

    /// What a container the fake age sealed holds (its `age -e` writes the
    /// plaintext as hex after its `--- ` line): for an assertion on which
    /// credentials a `combined.env` holds, never printed. Empty when there is
    /// none.
    fn opened(path: &Path) -> String {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let Ok(cont) = ai_env_cli::container::read(&text) else { return String::new() };
        let body = String::from_utf8_lossy(&cont.data).into_owned();
        let hex = body.split_once("\n--- ").and_then(|(_, rest)| rest.split_once('\n')).map_or("", |(_, h)| h.trim());
        String::from_utf8(hex::decode(hex).unwrap_or_default()).unwrap_or_default()
    }

    /// `creds status --json` of the world.
    fn status_json(w: &World) -> serde_json::Value {
        let o = run(w.cmd(&["creds", "status", "--json"]), None);
        assert_eq!(code(&o), 0, "creds status: {}", text(&o.stderr));
        serde_json::from_slice(&o.stdout).unwrap()
    }

    /// `o`'s output holds no token (its part after the kind prefix) and no runtime key secret of these.
    fn assert_output_clean(o: &Output, tokens: &[&String], secrets: &[&String]) {
        let (out, err) = (text(&o.stdout), text(&o.stderr));
        for t in tokens {
            assert!(!out.contains(&t[13..]) && !err.contains(&t[13..]), "the output holds a token ({} and {} bytes)", out.len(), err.len());
        }
        for s in secrets {
            assert!(!out.contains(s.as_str()) && !err.contains(s.as_str()), "the output holds a runtime key's secret ({} and {} bytes)", out.len(), err.len());
        }
    }

    /// No file under the world's root holds a runtime key's `secret`.
    fn assert_secret_off_disk(w: &World, secret: &str) {
        let leaks = files_holding(&w.root, secret.as_bytes());
        assert!(leaks.is_empty(), "{} files hold a runtime key's secret: {leaks:?}", leaks.len());
    }

    /// The token's part after its kind prefix is not in a live command's
    /// `stdout` lines or `stderr`, nor in the CLI log or any file under the
    /// world's root; `stderr` comes back masked, for an assertion's message.
    fn kept_out(w: &World, stdout: &[String], stderr: &str, token: &str) -> String {
        assert!(!stdout.iter().any(|l| l.contains(&token[13..])), "stdout holds the token ({} lines)", stdout.len());
        assert!(!stderr.contains(&token[13..]), "stderr holds the token ({} bytes)", stderr.len());
        assert!(!w.cli_log().contains(&token[13..]), "the CLI log holds the token");
        assert_token_off_disk(w, token);
        masked(stderr, token)
    }

    /// F2: `creds aws-set` (a new runtime key) waits on its rebuild's Touch
    /// ID, which unseals the sealed token t1, while `creds setup-token
    /// --no-combined` seals t2 (sealing needs no Touch ID). Once answered,
    /// aws-set builds no combined.env from t1 and says why (exit 0): one
    /// would record setup-token.env's sha256 with t2 there, read as current,
    /// and hand t1 to every credentialed command under t2's seal id. The next
    /// `vm exec --with-credential` reads t2, under its own seal id. No token
    /// or key is in any output (the exec's stdout is t2 by design) or under
    /// the world's root.
    #[test]
    fn a_rebuild_never_pairs_the_token_it_unsealed_with_a_seal_made_while_it_waited() {
        let (t1, t2) = (setup_token("Gwa"), setup_token("Gwb"));
        let w = World::credentialed(&t1);
        let (k2, json) = runtime_key("GWKA");
        let go = w.root.join("go");
        let waiting = held(&w, w.sealed_cmd(&["creds", "aws-set"]), Some(json.into_bytes()), &go);
        let o = seal(&w, &t2, false);
        assert_output_clean(&o, &[&t1, &t2], &[&k2]);
        assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
        std::fs::write(&go, "").unwrap();
        let o = waiting.join().unwrap();
        assert_output_clean(&o, &[&t1, &t2], &[&k2]);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 0, "{err}");
        assert!(err.contains("warning: combined.env not built (setup-token.env was sealed anew or removed while this command waited: none is built from what that replaced)"), "{err}");
        assert!(!creds_dir(&w).join("combined.env").exists(), "no combined.env pairs t1 with t2's seal");
        assert_eq!(status_json(&w)["combined_env"]["state"], "absent");
        let o = run(w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3"]), None);
        let err = text(&o.stderr);
        assert!(!text(&o.stdout).contains(&t1[13..]) && [&t1, &t2].iter().all(|t| !err.contains(&t[13..])), "the output holds a token ({} and {} bytes)", o.stdout.len(), o.stderr.len());
        assert_eq!(code(&o), 0, "{err}");
        assert!(text(&o.stdout) == t2, "the token sealed last: stdout of {} bytes", o.stdout.len());
        let t2_tag = seal_tag(&creds_dir(&w).join("setup-token.env")).unwrap();
        assert_eq!(w.audit("credential_deliver").last().and_then(|r| r["detail"]["tag"].as_str()), Some(t2_tag.as_str()), "under its own seal id");
        for t in [&t1, &t2] {
            assert_token_off_disk(&w, t);
        }
        assert_secret_off_disk(&w, &k2);
    }

    /// F2, the runtime key's side: `creds setup-token` (t2) waits on its
    /// rebuild's Touch ID, which unseals the runtime key k1, while `creds
    /// aws-set` seals k2 and builds combined.env from k2 and t2. Once
    /// answered, setup-token builds none from k1 and says so, and that the
    /// one there now matches its sources (exit 0): combined.env still holds
    /// k2 and t2, and is current. No token or key is in any output or under
    /// the world's root.
    #[test]
    fn a_rebuild_never_pairs_the_key_it_unsealed_with_a_hash_of_another() {
        let (t1, t2) = (setup_token("Gwc"), setup_token("Gwd"));
        let w = World::platform(None);
        w.seed_credentials(&t1, "1.0");
        let (k1, (k2, json)) = (seeded_key(), runtime_key("GWKB"));
        let go = w.root.join("go");
        let waiting = held(&w, w.sealed_cmd(&["creds", "setup-token", "--stdin"]), Some(format!("{t2}\n").into_bytes()), &go);
        let o = run(w.sealed_cmd(&["creds", "aws-set"]), Some(json.into_bytes()));
        assert_output_clean(&o, &[&t1, &t2], &[&k1, &k2]);
        assert!(o.status.success(), "creds aws-set: {}", text(&o.stderr));
        let combined = creds_dir(&w).join("combined.env");
        let built = opened(&combined);
        assert!(built.contains(&k2) && built.contains(&t2), "aws-set built combined.env from k2 and t2 ({} bytes)", built.len());
        std::fs::write(&go, "").unwrap();
        let o = waiting.join().unwrap();
        assert_output_clean(&o, &[&t1, &t2], &[&k1, &k2]);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 0, "{err}");
        assert!(err.contains("warning: combined.env not built (aws.env was sealed anew or removed while this command waited") && err.contains("the combined.env there now, which another command built, matches its sources"), "{err}");
        let kept = opened(&combined);
        assert!(kept.contains(&k2) && kept.contains(&t2) && !kept.contains(&k1), "combined.env holds k2 and t2 only ({} bytes)", kept.len());
        assert_eq!(status_json(&w)["combined_env"]["state"], "current");
        for t in [&t1, &t2] {
            assert_token_off_disk(&w, t);
        }
        for k in [&k1, &k2] {
            assert_secret_off_disk(&w, k);
        }
    }

    /// F2, a token forgotten meanwhile: `creds aws-set` waits on its
    /// rebuild's Touch ID, which unseals t1, while `creds forget --yes`
    /// deletes it (and, the second time, `creds setup-token --no-combined`
    /// seals t2 after it). Once answered, aws-set builds no combined.env
    /// (exit 0): t1 is never on disk again, neither in one that would read as
    /// current under t2's seal nor in a stale one. No token or key is in any
    /// output or under the world's root.
    #[test]
    fn a_rebuild_never_puts_back_a_token_forgotten_while_it_waited() {
        for (resealed, first, second, tag) in [(false, "Gwe", "Gwf", "GWKC"), (true, "Gwg", "Gwh", "GWKD")] {
            let (t1, t2) = (setup_token(first), setup_token(second));
            let w = World::platform(None);
            w.seed_credentials(&t1, "1.0");
            let (k2, json) = runtime_key(tag);
            let go = w.root.join("go");
            let waiting = held(&w, w.sealed_cmd(&["creds", "aws-set"]), Some(json.into_bytes()), &go);
            let o = run(w.cmd(&["creds", "forget", "--yes"]), None);
            assert_output_clean(&o, &[&t1, &t2], &[&k2]);
            assert!(o.status.success(), "creds forget: {}", text(&o.stderr));
            if resealed {
                let o = seal(&w, &t2, false);
                assert_output_clean(&o, &[&t1, &t2], &[&k2]);
                assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
            }
            std::fs::write(&go, "").unwrap();
            let o = waiting.join().unwrap();
            assert_output_clean(&o, &[&t1, &t2], &[&k2]);
            assert_eq!(code(&o), 0, "resealed {resealed}: {}", text(&o.stderr));
            let combined = creds_dir(&w).join("combined.env");
            assert!(!opened(&combined).contains(&t1), "resealed {resealed}: the forgotten token is in combined.env again");
            assert!(!combined.exists(), "resealed {resealed}: no combined.env");
            for t in [&t1, &t2] {
                assert_token_off_disk(&w, t);
            }
            assert_secret_off_disk(&w, &k2);
        }
    }

    /// F2, a late rebuild: `creds aws-set` (k2) waits on its rebuild's Touch
    /// ID, which unseals t1, while `creds setup-token` seals t2 and builds
    /// combined.env from k2 and t2. Once answered, aws-set leaves that one as
    /// it is and says so (exit 0), never replacing it with t1 under t2's
    /// seal: it holds k2 and t2, and is current. No token or key is in any
    /// output or under the world's root.
    #[test]
    fn a_late_rebuild_never_replaces_a_combined_env_that_matches_its_sources() {
        let (t1, t2) = (setup_token("Gwi"), setup_token("Gwj"));
        let w = World::platform(None);
        w.seed_credentials(&t1, "1.0");
        let (k2, json) = runtime_key("GWKE");
        let go = w.root.join("go");
        let waiting = held(&w, w.sealed_cmd(&["creds", "aws-set"]), Some(json.into_bytes()), &go);
        let o = seal(&w, &t2, true);
        assert_output_clean(&o, &[&t1, &t2], &[&k2]);
        assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
        let combined = creds_dir(&w).join("combined.env");
        let built = opened(&combined);
        assert!(built.contains(&k2) && built.contains(&t2), "setup-token built combined.env from k2 and t2 ({} bytes)", built.len());
        std::fs::write(&go, "").unwrap();
        let o = waiting.join().unwrap();
        assert_output_clean(&o, &[&t1, &t2], &[&k2]);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 0, "{err}");
        assert!(err.contains("warning: combined.env not built (setup-token.env was sealed anew or removed while this command waited") && err.contains("the combined.env there now, which another command built, matches its sources"), "{err}");
        let kept = opened(&combined);
        assert!(kept.contains(&k2) && kept.contains(&t2) && !kept.contains(&t1), "combined.env holds k2 and t2 only ({} bytes)", kept.len());
        assert_eq!(status_json(&w)["combined_env"]["state"], "current");
        for t in [&t1, &t2] {
            assert_token_off_disk(&w, t);
        }
        assert_secret_off_disk(&w, &k2);
    }

    /// F2, two `creds setup-token` runs: A seals tA and waits on its
    /// rebuild's Touch ID (the runtime key) while B seals tB (`dismissed`:
    /// B rebuilds and its prompt is dismissed; else `--no-combined`). Once
    /// answered, A builds no combined.env from tA and says why (exit 0): one
    /// would record setup-token.env's sha256 with tB there, read as current,
    /// and hand tA to every credentialed command under tB's seal id. It pins
    /// the hash A records of its own token: that of the text it sealed, read
    /// before its rebuild's Touch ID, never after. No token or key is in any
    /// output or under the world's root. `tails` name t0 (sealed first), tA
    /// and tB.
    fn two_setup_token_runs(dismissed: bool, tails: [&str; 3]) {
        let [t0, ta, tb] = tails.map(setup_token);
        let w = World::platform(None);
        w.seed_credentials(&t0, "1.0");
        let k1 = seeded_key();
        let go = w.root.join("go");
        let waiting = held(&w, w.sealed_cmd(&["creds", "setup-token", "--stdin"]), Some(format!("{ta}\n").into_bytes()), &go);
        // B's backup of setup-token.env (A's tA) is named by a second of its own.
        std::thread::sleep(Duration::from_millis(1100));
        let mut b = w.sealed_cmd(&["creds", "setup-token", "--stdin"]);
        if dismissed {
            b.env("FAKE_AGE_FAIL", "cancel");
        } else {
            b.arg("--no-combined");
        }
        let o = run(b, Some(format!("{tb}\n").into_bytes()));
        assert_output_clean(&o, &[&t0, &ta, &tb], &[&k1]);
        let err = text(&o.stderr);
        assert!(o.status.success() && (!dismissed || err.contains("warning: combined.env not built (")), "B: {err}");
        std::fs::write(&go, "").unwrap();
        let o = waiting.join().unwrap();
        assert_output_clean(&o, &[&t0, &ta, &tb], &[&k1]);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 0, "{err}");
        let combined = creds_dir(&w).join("combined.env");
        let state = status_json(&w)["combined_env"]["state"].as_str().unwrap_or("?").to_string();
        assert!(!opened(&combined).contains(&ta), "combined.env holds tA (it reads {state})");
        assert!(!combined.exists() && state == "absent", "no combined.env (it reads {state})");
        assert!(err.contains("warning: combined.env not built (setup-token.env was sealed anew or removed while this command waited: none is built from what that replaced)"), "{err}");
        for t in [&t0, &ta, &tb] {
            assert_token_off_disk(&w, t);
        }
        assert_secret_off_disk(&w, &k1);
    }

    /// F2, `two_setup_token_runs` with B sealing tB `--no-combined`: A's
    /// late rebuild builds nothing from tA.
    #[test]
    fn a_rebuild_never_pairs_its_own_token_with_a_seal_made_while_it_waited() {
        two_setup_token_runs(false, ["Gxa", "Gxb", "Gxc"]);
    }

    /// F2, `two_setup_token_runs` with B's own rebuild dismissed (so B
    /// leaves no combined.env either): A's late rebuild builds nothing from
    /// tA.
    #[test]
    fn a_rebuild_never_pairs_its_own_token_with_a_seal_whose_rebuild_was_dismissed() {
        two_setup_token_runs(true, ["Gxd", "Gxe", "Gxf"]);
    }

    /// A pipe whose buffer is already full: a process given its write end as
    /// stdout blocks in its first write until the read end is drained.
    fn full_pipe() -> (std::io::PipeReader, std::io::PipeWriter) {
        use std::os::fd::AsRawFd as _;
        let (reader, mut writer) = std::io::pipe().unwrap();
        let fd = writer.as_raw_fd();
        // SAFETY: fcntl on the write end this function holds.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: as above.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) }, 0);
        let chunk = [b'.'; 4096];
        for piece in [&chunk[..], &chunk[..1]] {
            loop {
                match writer.write(piece) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("filling the pipe: {e}"),
                }
            }
        }
        // SAFETY: as above; the child gets a blocking write end.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) }, 0);
        (reader, writer)
    }

    /// F2, the runtime key's own window: `creds aws-set` A seals kA and is
    /// held at its first stdout line (a full pipe), after its seal and audit
    /// row and before its rebuild; meanwhile `creds aws-set` B seals kB and
    /// builds combined.env from kB and the sealed token. Once A's stdout is
    /// read, A builds no combined.env from kA and says why (exit 0): one
    /// recording the hash of aws.env read only then (kB's text) would read as
    /// current and hand kA, a replaced key, to every credentialed command.
    /// No token or key is in any output or under the world's root.
    #[test]
    fn an_aws_set_whose_key_is_replaced_before_its_rebuild_builds_nothing_from_it() {
        let t1 = setup_token("Gya");
        let w = World::platform(None);
        w.seed_credentials(&t1, "1.0");
        let k1 = seeded_key();
        let ((ka, json_a), (kb, json_b)) = (runtime_key("GYKA"), runtime_key("GYKB"));
        let (sealed_rows, decrypts) = (w.audit("creds_aws_set").len(), w.decrypts());
        let (held_out, full) = full_pipe();
        let mut cmd = w.sealed_cmd(&["creds", "aws-set"]);
        cmd.stdin(Stdio::piped()).stdout(full).stderr(Stdio::piped());
        let mut a = cmd.spawn().unwrap();
        // This process's copy of the write end closed: the pipe ends with A.
        drop(cmd);
        a.stdin.take().unwrap().write_all(json_a.as_bytes()).unwrap();
        let a_err = read_all(a.stderr.take().unwrap());
        wait_for("A's seal and its audit row", || w.audit("creds_aws_set").len() > sealed_rows);
        // B's backup of aws.env (A's kA) is named by a second of its own.
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(w.decrypts(), decrypts, "A is held before its rebuild's Touch ID");
        let o = run(w.sealed_cmd(&["creds", "aws-set"]), Some(json_b.into_bytes()));
        assert_output_clean(&o, &[&t1], &[&k1, &ka, &kb]);
        assert!(o.status.success(), "B: {}", text(&o.stderr));
        let combined = creds_dir(&w).join("combined.env");
        let built = opened(&combined);
        assert!(built.contains(&kb) && built.contains(&t1), "B built combined.env from kB and the token ({} bytes)", built.len());
        let a_out = read_all(held_out);
        let status = wait_bounded(&mut a);
        let o = Output { status, stdout: a_out.join().unwrap(), stderr: a_err.join().unwrap() };
        assert_output_clean(&o, &[&t1], &[&k1, &ka, &kb]);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 0, "{err}");
        assert!(err.contains("warning: combined.env not built (aws.env was sealed anew or removed while this command waited: none is built from what that replaced)"), "{err}");
        let state = status_json(&w)["combined_env"]["state"].as_str().unwrap_or("?").to_string();
        let kept = opened(&combined);
        assert!(!kept.contains(&ka), "combined.env holds kA, a replaced key (it reads {state})");
        assert!(state == "absent" || (state == "current" && kept.contains(&kb)), "combined.env reads {state}");
        assert_token_off_disk(&w, &t1);
        for k in [&k1, &ka, &kb] {
            assert_secret_off_disk(&w, k);
        }
    }

    /// F16: a token sealed anew while a credentialed `vm exec` waits for the
    /// runtime key's Touch ID is refused before the token's own: its unseal
    /// reads the file, whose seal id is no longer the one `check` read, and
    /// opens no dialog: exit 5 saying so (nothing unsealed, nothing sent),
    /// the token's `credential_unseal` row `exit 5`, one decrypt in all (the
    /// runtime key's). Neither token is in the output or under the root.
    #[test]
    fn a_token_sealed_anew_before_its_unseal_costs_no_touch_id() {
        let (old, new) = (setup_token("Gwk"), setup_token("Gwl"));
        let w = World::credentialed(&old);
        let old_tag = seal_tag(&creds_dir(&w).join("setup-token.env")).unwrap();
        let (before, unseals) = (w.decrypts(), w.audit("credential_unseal").len());
        let go = w.root.join("go");
        let waiting = held(&w, w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3"]), None, &go);
        let o = seal(&w, &new, false);
        assert_output_clean(&o, &[&old, &new], &[]);
        assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
        let new_tag = seal_tag(&creds_dir(&w).join("setup-token.env")).unwrap();
        std::fs::write(&go, "").unwrap();
        let o = waiting.join().unwrap();
        for token in [&old, &new] {
            assert_token_nowhere(&w, &o, token);
        }
        let err = text(&o.stderr);
        assert_eq!(code(&o), 5, "{err}");
        let says = format!("setup-token.env was sealed anew while this command ran (seal {old_tag} when it was checked, {new_tag} in what was about to be unsealed): nothing was unsealed, nothing was sent; run the command again");
        assert!(err.contains(&says), "{err}");
        assert_eq!(w.decrypts(), before + 1, "the runtime key's Touch ID only");
        let rows = &w.audit("credential_unseal")[unseals..];
        assert!(rows.len() == 1 && rows[0]["detail"]["source"] == "setup-token" && rows[0]["detail"]["outcome"] == "exit 5", "{rows:?}");
        assert!(w.audit("credential_deliver").is_empty() && !w.shim.spawns.credential().has() && w.spawn_ids().is_empty(), "nothing was sent");
    }

    /// F16 with `--credential-file`: the container is replaced (by a byte
    /// copy of a token sealed anew) while the command waits for the runtime
    /// key's Touch ID, and refused before its own: exit 5 naming that file,
    /// nothing unsealed or sent, one decrypt in all. Neither token is in the
    /// output or under the world's root.
    #[test]
    fn a_credential_file_replaced_before_its_unseal_costs_no_touch_id() {
        let (old, new) = (setup_token("Gwm"), setup_token("Gwn"));
        let w = World::credentialed(&old);
        let file = w.root.join("other.env");
        std::fs::copy(creds_dir(&w).join("setup-token.env"), &file).unwrap();
        let path = file.display().to_string();
        let before = w.decrypts();
        let go = w.root.join("go");
        let waiting = held(&w, w.cred_exec(&["--credential-file", &path, "--", "/bin/sh", "-c", "cat <&3"]), None, &go);
        let o = seal(&w, &new, false);
        assert_output_clean(&o, &[&old, &new], &[]);
        assert!(o.status.success(), "creds setup-token: {}", text(&o.stderr));
        std::fs::copy(creds_dir(&w).join("setup-token.env"), &file).unwrap();
        std::fs::write(&go, "").unwrap();
        let o = waiting.join().unwrap();
        for token in [&old, &new] {
            assert_token_nowhere(&w, &o, token);
        }
        let err = text(&o.stderr);
        assert_eq!(code(&o), 5, "{err}");
        assert!(err.contains(&format!("{path} was sealed anew while this command ran (seal ")) && err.contains(" in what was about to be unsealed): nothing was unsealed, nothing was sent"), "{err}");
        assert_eq!(w.decrypts(), before + 1, "the runtime key's Touch ID only");
        assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty(), "nothing was sent");
    }

    /// The world's age, in front of the fake: the first `age --version`
    /// after `answered` decrypts are in the log says it runs (`probing`),
    /// then waits (at most 30 s) for `go`.
    fn hold_a_probe(w: &World, answered: usize, probing: &Path, go: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        let real = w.root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/age.sh"), real.join("age")).unwrap();
        let wrapper = format!(
            "#!/bin/sh\nn=$(grep -c '^age -d ' \"$FAKE_AGE_LOG\" 2>/dev/null)\nif [ \"${{1:-}}\" = --version ] && [ \"${{n:-0}}\" -ge {answered} ] && [ ! -e '{p}' ]; then\n  : > '{p}'\n  k=0\n  while [ ! -e '{g}' ] && [ \"$k\" -lt 3000 ]; do sleep 0.01; k=$((k + 1)); done\nfi\nexec /bin/sh '{r}' \"$@\"\n",
            p = probing.display(),
            g = go.display(),
            r = real.join("age").display()
        );
        std::fs::write(w.bin().join("age"), wrapper).unwrap();
        std::fs::set_permissions(w.bin().join("age"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// `vm exec --with-credential -- true` in a process group of its own,
    /// SIGINT sent to that whole group (as a terminal's Ctrl-C reaches its
    /// foreground job) while the probe `hold_a_probe` holds runs, then the
    /// probe released: (exit status, the rest of stdout, stderr).
    fn ctrl_c_at_a_probe(w: &World, probing: &Path, go: &Path) -> (ExitStatus, Vec<String>, String) {
        use std::os::unix::process::CommandExt as _;
        let mut cmd = w.cred_exec(&["--with-credential", "--", "true"]);
        cmd.process_group(0);
        let live = Live::start(cmd);
        wait_for("the held age --version", || probing.exists());
        let pgid = i32::try_from(live.child.id()).unwrap();
        // SAFETY: killpg(2) on the group our own child leads.
        assert_eq!(unsafe { libc::killpg(pgid, libc::SIGINT) }, 0);
        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(go, "").unwrap();
        live.finish()
    }

    /// F19: a terminal's Ctrl-C reaches ai-env and the first unseal's
    /// `age --version` alike (held here until the signal is sent): the stop
    /// is what ai-env answers, never the empty version the killed probe
    /// printed: 130, its line (stopped before Touch ID was asked for), no
    /// decrypt; with combined.env its unseal is audited `exit 130`. Nothing
    /// is delivered or spawned; the token is nowhere in the output or under
    /// the world's root.
    #[test]
    fn a_terminal_ctrl_c_during_the_first_unseals_probe_is_a_stop() {
        for (combined, what, tail) in [(false, "the runtime key", "Gwo"), (true, "the runtime key and the setup token", "Gwp")] {
            let token = setup_token(tail);
            let w = World::credentialed(&token);
            if combined {
                let o = seal(&w, &token, true);
                assert!(o.status.success() && creds_dir(&w).join("combined.env").exists(), "combined.env: {}", masked(&text(&o.stderr), &token));
            }
            let (probing, go) = (w.root.join("probing"), w.root.join("go"));
            hold_a_probe(&w, 0, &probing, &go);
            let (before, unseals) = (w.decrypts(), w.audit("credential_unseal").len());
            let (exit, rest, err) = ctrl_c_at_a_probe(&w, &probing, &go);
            let err = kept_out(&w, &rest, &err, &token);
            assert_eq!(exit.code(), Some(130), "{what}: {err}");
            assert!(err.contains(&format!("ai-env: stopped before Touch ID was asked for (SIGINT): {what} stayed sealed")) && !err.contains("cannot parse age version"), "{what}: {err}");
            assert_eq!(w.decrypts(), before, "{what}: a decrypt started");
            if combined {
                let rows = w.audit("credential_unseal");
                assert!(rows.len() == unseals + 1 && rows[unseals]["detail"]["source"] == "combined" && rows[unseals]["detail"]["outcome"] == "exit 130", "{what}: {rows:?}");
            }
            assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty(), "{what}: something was sent");
        }
    }

    /// F19, the token's own unseal: its `age --version` comes after the
    /// runtime key's Touch ID, while `vm exec`'s own listeners wait; a
    /// terminal's Ctrl-C there ends it with 130 and its line (nothing was
    /// sent), the token's unseal audited `stopped`, one decrypt in all (the
    /// runtime key's). The token is nowhere in the output or under the root.
    #[test]
    fn a_terminal_ctrl_c_during_the_tokens_probe_is_a_stop() {
        let token = setup_token("Gwq");
        let w = World::credentialed(&token);
        let (probing, go) = (w.root.join("probing"), w.root.join("go"));
        hold_a_probe(&w, w.decrypts() + 1, &probing, &go);
        let (before, unseals) = (w.decrypts(), w.audit("credential_unseal").len());
        let (exit, rest, err) = ctrl_c_at_a_probe(&w, &probing, &go);
        let err = kept_out(&w, &rest, &err, &token);
        assert_eq!(exit.code(), Some(130), "{err}");
        assert!(err.contains(&format!("ai-env: interrupted (SIGINT) before the command started on {}: nothing was sent", w.id)) && !err.contains("cannot parse age version"), "{err}");
        assert_eq!(w.decrypts() - before, 1, "the runtime key's Touch ID only");
        let rows = &w.audit("credential_unseal")[unseals..];
        assert!(rows.len() == 1 && rows[0]["detail"]["source"] == "setup-token" && rows[0]["detail"]["outcome"] == "stopped", "{rows:?}");
        assert!(w.audit("credential_deliver").is_empty() && w.spawn_ids().is_empty(), "something was sent");
    }

    /// `[aws].image_version = version` in the world's bridge.toml.
    fn pin(w: &World, version: &str) {
        let path = w.root.join("bridge").join("bridge.toml");
        let toml = std::fs::read_to_string(&path).unwrap().replacen("[aws]\n", &format!("[aws]\nimage_version = \"{version}\"\n"), 1);
        std::fs::write(&path, toml).unwrap();
    }

    /// The world's recorded passing checks, edited.
    fn edit_verified(w: &World, f: impl FnOnce(&mut EgressVerified)) {
        let path = w.root.join("bridge").join("state").join("egress-verified.toml");
        let mut verified: EgressVerified = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        f(&mut verified);
        std::fs::write(&path, toml::to_string(&verified).unwrap()).unwrap();
    }

    /// `args` refused by the gate's local half before anything: exit 9, no
    /// Touch ID, no VM, the token nowhere. Its stderr and the detail of the
    /// `credential_gate` row it wrote.
    fn local_refusal(w: &World, args: &[&str], token: &str) -> (String, serde_json::Value) {
        let before = w.decrypts();
        let o = run(w.sealed_cmd(args), None);
        assert_token_nowhere(w, &o, token);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 9, "{args:?}: {err}");
        assert_eq!(w.decrypts(), before, "{args:?}: no Touch ID");
        assert!(w.fake().vms.is_empty(), "{args:?}: no VM");
        (err, w.audit("credential_gate").last().map(|r| r["detail"].clone()).unwrap_or_default())
    }

    /// F4: `[aws].image_version = "1"` starts version 1.0 (the service lists
    /// `N.M`), whose passing check is recorded; what stops a credential
    /// there (no dns-path verdict recorded) is what `vm warm`, `vm smoke
    /// --with-credential` and `lab run init-budget` say and audit, for image
    /// version 1.0, naming `lab run dns-path`: never "no check recorded for
    /// image version 1" and `egress check`, which cannot clear it. With the
    /// verdict back and 1.0's check 8 days old, the refusal is that age, for
    /// 1.0. With no check recorded at all, both refuse alike (a tie: the
    /// later candidate is named): no check recorded, for 1.0, the version the
    /// doctor's row judges. Exit 9 each time, no Touch ID, no VM.
    #[test]
    fn a_pinned_major_version_names_what_stops_its_n_dot_0() {
        let token = setup_token("Gwr");
        let w = World::platform(None);
        w.seed_credentials(&token, "1.0");
        let ws = project(&w);
        pin(&w, "1");
        let probes = w.root.join("bridge").join("lab").join("probes.jsonl");
        let dns_rows = std::fs::read_to_string(&probes).unwrap();
        std::fs::remove_file(&probes).unwrap();
        for args in [vec!["vm", "warm", ws.as_str()], vec!["vm", "smoke", "--exec", "--with-credential", "--json"], vec!["lab", "run", "init-budget"]] {
            let (err, gate) = local_refusal(&w, &args, &token);
            assert!(err.contains("no credential for a vpc VM of image version 1.0: no dns-path verdict is recorded (run `ai-env lab run dns-path`) (nothing was unsealed or started)"), "{args:?}: {err}");
            assert_eq!((gate["condition"].as_str(), gate["image_version"].as_str(), gate["half"].as_str()), (Some("dns_path_missing"), Some("1.0"), Some("local")), "{args:?}");
        }
        std::fs::write(&probes, dns_rows).unwrap();
        edit_verified(&w, |v| v.records[0].at = rfc3339_utc(unix_now() - 8 * 86_400));
        let (err, gate) = local_refusal(&w, &["vm", "warm", ws.as_str()], &token);
        assert!(err.contains("no credential for a vpc VM of image version 1.0: the passing `ai-env egress check` was recorded ") && err.contains("more than 7 days ago"), "{err}");
        assert_eq!((gate["condition"].as_str(), gate["image_version"].as_str()), (Some("record_age"), Some("1.0")));
        edit_verified(&w, |v| v.records.clear());
        let (err, gate) = local_refusal(&w, &["vm", "warm", ws.as_str()], &token);
        assert!(err.contains("no credential for a vpc VM of image version 1.0: no passing `ai-env egress check` is recorded for image version 1.0 with "), "{err}");
        assert_eq!((gate["condition"].as_str(), gate["image_version"].as_str()), (Some("no_record"), Some("1.0")));
    }

    /// F4, the `active` fallback: `state/infra.toml` records no active
    /// version, so the versions a passing check is recorded for are judged:
    /// here 0.9's, 8 days old and first in the file, and 1.0's, fresh, with
    /// no dns-path verdict recorded. The refusal names what stops 1.0 (the
    /// version recorded last; the verdict stops every version), with `make
    /// infra-status WRITE=1`, never 0.9's age, which no `egress check` of the
    /// version new VMs run would refresh. With the verdict back and both
    /// checks stale (0.9's 9 days old, 1.0's 8), both refuse alike (a tie:
    /// the later candidate is named): 1.0's age, never 0.9's. Exit 9 each
    /// time, no Touch ID, no VM.
    #[test]
    fn the_active_fallback_names_what_stops_the_newest_recorded_version() {
        let token = setup_token("Gws");
        let w = World::platform(None);
        w.seed_credentials(&token, "1.0");
        let ws = project(&w);
        assert!(!w.root.join("bridge").join("state").join("infra.toml").exists(), "no active version recorded");
        let probes = w.root.join("bridge").join("lab").join("probes.jsonl");
        let dns_rows = std::fs::read_to_string(&probes).unwrap();
        std::fs::remove_file(&probes).unwrap();
        edit_verified(&w, |v| {
            let mut old = v.records[0].clone();
            old.image_version = "0.9".into();
            old.at = rfc3339_utc(unix_now() - 8 * 86_400);
            v.records.insert(0, old);
        });
        let (err, gate) = local_refusal(&w, &["vm", "warm", ws.as_str()], &token);
        assert!(err.contains("no credential for a vpc VM of image version 1.0 (state/infra.toml records no active version of this image: `make infra-status WRITE=1` records it): no dns-path verdict is recorded (run `ai-env lab run dns-path`)"), "{err}");
        assert_eq!((gate["condition"].as_str(), gate["image_version"].as_str()), (Some("dns_path_missing"), Some("1.0")));
        std::fs::write(&probes, dns_rows).unwrap();
        edit_verified(&w, |v| {
            for r in &mut v.records {
                let days = if r.image_version == "0.9" { 9 } else { 8 };
                r.at = rfc3339_utc(unix_now() - days * 86_400);
            }
        });
        let (err, gate) = local_refusal(&w, &["vm", "warm", ws.as_str()], &token);
        assert!(err.contains("no credential for a vpc VM of image version 1.0 (state/infra.toml records no active version of this image: `make infra-status WRITE=1` records it): the passing `ai-env egress check` was recorded ") && err.contains("more than 7 days ago"), "{err}");
        assert_eq!((gate["condition"].as_str(), gate["image_version"].as_str()), (Some("record_age"), Some("1.0")));
    }

    /// The world's fake endpoint, but its `/health/detail` answers after
    /// `after` that the shim holds `tag` under the token's name and offers
    /// the cache (the fake's own never holds anything).
    struct SlowHit<'a> {
        fake: &'a FileFakeMicrovmApi,
        tag: String,
        after: Duration,
    }

    impl EndpointClient for SlowHit<'_> {
        async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
            self.fake.get_health(endpoint, token, port_header).await
        }

        async fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &Secret<String>) -> Result<HealthDetailReply, BridgeError> {
            tokio::time::sleep(self.after).await;
            let mut reply = self.fake.get_health_detail(endpoint, token, bearer).await?;
            if let Some(d) = reply.detail.as_mut() {
                d.has_credentials = true;
                d.credential.credential_name = Some("CLAUDE_CODE_OAUTH_TOKEN".into());
                d.credential.credential_tag = Some(self.tag.clone());
                d.health.caps = vec![CAP_CREDENTIAL_CACHE.to_string()];
            }
            Ok(reply)
        }
    }

    /// What `prepare` needs of a credentialed world: the command's context,
    /// the file-backed fake, the keystore, the plan `check` would make (the
    /// sealed setup-token's seal id, on fd) and the VM as GetMicrovm reports it.
    fn prepared(w: &World, rt: &tokio::runtime::Runtime) -> (Ctx, FileFakeMicrovmApi, Keystore, CredentialPlan, VmInfo) {
        let paths = Paths::from_root_and_env(w.root.join("bridge"), None);
        let cfg = BridgeConfig::load(&paths).unwrap().unwrap();
        let fake = FileFakeMicrovmApi::open(&w.fake_path()).unwrap();
        let store = Keystore::resolve(Some(w.root.join("keys"))).unwrap();
        let plan = CredentialPlan { deliver: Deliver::Fd, file: None, tag: seal_tag(&creds_dir(w).join("setup-token.env")).unwrap() };
        let vm = rt.block_on(fake.get(&w.id)).unwrap();
        (Ctx { paths, cfg, knobs: VmKnobs::default() }, fake, store, plan, vm)
    }

    /// F7: `prepare` on a VM whose shim holds the seal checked (a predicted
    /// cache hit: nothing unsealed) records the VM as a holder at once, when
    /// its row names no delivery (one whose record failed, or a row from
    /// before such records): a session that then fails before its
    /// `hello_ok` still leaves the VM in the list `creds status` reads. A row
    /// that names a delivery keeps its time (a VM seen holding the seal is
    /// not one it was just sent to). No Touch ID; the token nowhere on disk.
    #[test]
    fn prepare_records_a_vm_it_finds_holding_the_seal() {
        let token = setup_token("Gwt");
        let w = World::credentialed(&token);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (ctx, fake, store, plan, vm) = prepared(&w, &rt);
        let ep = SlowHit { fake: &fake, tag: plan.tag.clone(), after: Duration::ZERO };
        let row = w.row();
        assert_eq!((row.credential_at, row.credential_tag.as_deref()), (None, None), "no delivery recorded yet");
        let before = w.decrypts();
        let hit = || rt.block_on(prepare(&ctx, &fake, &ep, &row, &vm, &plan, CredentialSupply { store: &store, token: None })).unwrap_or_else(|e| panic!("prepare: {e}"));
        assert_eq!(hit().source, "cached");
        let seen = w.row();
        assert_eq!((seen.credential_at.is_some(), seen.credential_tag.as_deref()), (true, Some(plan.tag.as_str())), "the hit names the VM before any session");
        let earlier = seen.credential_at.unwrap() - 3600;
        ai_env_cli::bridge::vm::registry::update_row(&ctx.paths, &w.id, |r| r.credential_at = Some(earlier)).unwrap();
        assert_eq!(hit().source, "cached");
        let kept = w.row();
        assert_eq!((kept.credential_at, kept.credential_tag.as_deref()), (Some(earlier), Some(plan.tag.as_str())), "an earlier delivery's time is kept");
        assert_eq!(w.decrypts(), before, "no Touch ID");
        assert_token_off_disk(&w, &token);
    }

    /// F8 (M6, at `prepare` itself): when what comes between the gate and
    /// the delivery outlasts half the pass's life (here the VM's
    /// `/health/detail` answering after 46 s; a Touch ID answered late does
    /// the same), `prepare` gates again, with no prompt, so the session's
    /// dial never starts on a pass about to age out: two `credential_gate`
    /// rows, both passed, for the one `prepare`, which still hands back its
    /// delivery (a cache hit here), bound to the second pass (given at least
    /// 46 s after `prepare` began; the first, before). It takes 46 s. The
    /// token is nowhere on disk.
    #[test]
    fn prepare_gates_again_once_its_pass_is_past_half_its_life() {
        use ai_env_cli::bridge::egress::GATE_PASS_MAX_AGE_S;
        let token = setup_token("Gwu");
        let w = World::credentialed(&token);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (ctx, fake, store, plan, vm) = prepared(&w, &rt);
        let ep = SlowHit { fake: &fake, tag: plan.tag.clone(), after: Duration::from_secs(GATE_PASS_MAX_AGE_S / 2 + 1) };
        let row = w.row();
        let gates = w.audit("credential_gate").len();
        let began = unix_now();
        let prepared = rt.block_on(prepare(&ctx, &fake, &ep, &row, &vm, &plan, CredentialSupply { store: &store, token: None })).unwrap_or_else(|e| panic!("prepare: {e}"));
        assert_eq!((prepared.source, prepared.delivery.vm_id()), ("cached", w.id.as_str()));
        let rows = &w.audit("credential_gate")[gates..];
        assert!(rows.len() == 2 && rows.iter().all(|r| r["detail"]["result"] == "passed"), "gated, then gated again once the pass was past half its life: {rows:?}");
        assert!(prepared.gated_at() > began + GATE_PASS_MAX_AGE_S / 2, "the delivery is bound to the second pass: given {} s after prepare began", prepared.gated_at().saturating_sub(began));
        assert_token_off_disk(&w, &token);
    }

    /// F13: the VM received the token (its row records the delivery), then
    /// its row file is replaced by a symlink to a copy of itself, which
    /// `read_row` refuses: `creds status` lists it as a row that cannot be
    /// read (never "none"), its `--json` gives it in `holders_unreadable`,
    /// and `creds forget --yes` prints it and counts it in its audit row. The
    /// token is nowhere in any output or under the world's root.
    #[test]
    fn a_symlinked_registry_row_is_never_taken_for_no_holder() {
        let token = setup_token("Gwv");
        let w = World::credentialed(&token);
        let o = run(w.cred_exec(&["--with-credential", "--", "true"]), None);
        assert_token_nowhere(&w, &o, &token);
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        assert!(w.row().credential_at.is_some(), "the delivery is recorded");
        let file = w.root.join("bridge").join("state").join("vms").join(format!("{}.toml", w.id));
        let copy = w.root.join("row-copy.toml");
        std::fs::rename(&file, &copy).unwrap();
        std::os::unix::fs::symlink(&copy, &file).unwrap();
        let named = format!("{} is a symlink; refusing to read it", file.display());
        let says = format!("a VM registry row cannot be read, so its VM may hold the token unlisted: {named}");
        let o = run(w.cmd(&["creds", "status"]), None);
        assert_token_nowhere(&w, &o, &token);
        let out = text(&o.stdout);
        assert!(code(&o) == 0 && !out.contains("VMs that may hold the token: none") && out.lines().any(|l| l == format!("[!! ] {says}")), "{out}");
        let o = run(w.cmd(&["creds", "status", "--json"]), None);
        assert_token_nowhere(&w, &o, &token);
        let doc: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(doc["holders_unreadable"], serde_json::json!([named]), "{doc}");
        let o = run(w.cmd(&["creds", "forget", "--yes"]), None);
        assert_token_nowhere(&w, &o, &token);
        let out = text(&o.stdout);
        assert!(code(&o) == 0 && out.contains(&format!("{says}; only terminating its VM clears its copies (`ai-env vm list` shows the VMs)")), "{out}");
        let forgot = w.audit("creds_forget");
        assert!(forgot.len() == 1 && forgot[0]["detail"]["holders_unreadable"] == "1", "{forgot:?}");
    }

    /// `vm warm WS` stopped by SIGINT on its held `/agent` upgrade, before
    /// its frame: the exit code and stderr (masked for `token`, which is
    /// nowhere in the output or under the world's root).
    fn stopped_warm(w: &World, ws: &str, token: &str) -> (Option<i32>, String) {
        w.endpoint.script([Action::Held]);
        let before = w.endpoint.accepted();
        let live = Live::start(w.sealed_cmd(&["vm", "warm", ws]));
        wait_for("the held /agent upgrade", || w.endpoint.accepted() > before);
        live.signal(libc::SIGINT);
        std::thread::sleep(Duration::from_millis(500));
        w.endpoint.release();
        let (exit, rest, err) = live.finish();
        (exit.code(), kept_out(w, &rest, &err, token))
    }

    /// The ids `creds status --json` lists as holders.
    fn holders(w: &World) -> Vec<String> {
        status_json(w)["holders"].as_array().map(|a| a.iter().filter_map(|h| h["id"].as_str().map(str::to_string)).collect()).unwrap_or_default()
    }

    /// F14: a stop during `vm warm`'s delivery names the VM, with `ai-env vm
    /// terminate`, whenever its row records a delivery, as `creds status`
    /// lists it, whatever the seal: here the first warm delivered S0, then
    /// `creds setup-token` sealed S1 (S0 leaked, say), and the second warm
    /// is stopped before its frame. Its line says this run delivered nothing
    /// but the VM may hold a token sent to it earlier (seal S0), never
    /// "nothing was delivered" alone. Neither token is in any output or under
    /// the world's root.
    #[test]
    fn a_stopped_warm_names_a_vm_that_holds_an_earlier_seal() {
        let (t0, t1) = (setup_token("Gww"), setup_token("Gwx"));
        let w = World::platform(None);
        w.seed_credentials(&t0, "1.0");
        let o = seal(&w, &t0, true);
        assert!(o.status.success(), "combined.env: {}", masked(&text(&o.stderr), &t0));
        let ws = project(&w);
        let o = run(w.sealed_cmd(&["vm", "warm", &ws]), None);
        assert_token_nowhere(&w, &o, &t0);
        assert_eq!(code(&o), 0, "the first warm: {}", text(&o.stderr));
        let id = w.fake().vms.keys().next().cloned().expect("the workspace's VM");
        let s0 = seal_tag(&creds_dir(&w).join("setup-token.env")).unwrap();
        // A backup is named by the second: a second re-seal within it would collide.
        std::thread::sleep(Duration::from_millis(1100));
        let o = seal(&w, &t1, true);
        assert_output_clean(&o, &[&t0, &t1], &[]);
        assert!(o.status.success(), "the re-seal: {}", text(&o.stderr));
        let (exit, err) = stopped_warm(&w, &ws, &t1);
        assert_token_off_disk(&w, &t0);
        assert_eq!(exit, Some(130), "{err}");
        let row = ai_env_cli::bridge::vm::registry::read_row(&Paths::from_root_and_env(w.root.join("bridge"), None), &id).unwrap().unwrap();
        assert_eq!(row.credential_tag.as_deref(), Some(s0.as_str()), "the row still records S0: this run sent nothing");
        assert!(holders(&w).contains(&id), "creds status lists the VM");
        let says = format!("while the setup-token was being delivered to {id}: the delivery was given up; nothing was delivered by this run, but {id} may hold a token sent to it earlier (seal {s0}, as its row records): `ai-env vm terminate {id}` clears it");
        assert!(err.contains(&says), "{err}");
    }

    /// F14 with a one-shot between two warms: `vm exec --credential-file`
    /// made the VM's row name that file's seal (F) while its cache holds the
    /// setup-token's (S0); a warm of S0 stopped before its frame names the
    /// VM (seal F, as its row records) with `ai-env vm terminate`, as `creds
    /// status` lists it. Neither token is in any output (the one-shot
    /// command prints nothing) or under the world's root.
    #[test]
    fn a_stopped_warm_names_a_vm_its_row_records_a_one_shot_for() {
        let (tf, t0) = (setup_token("Gwy"), setup_token("Gwz"));
        let w = World::platform(None);
        w.seed_credentials(&tf, "1.0");
        let file = w.root.join("other.env");
        std::fs::copy(creds_dir(&w).join("setup-token.env"), &file).unwrap();
        let f = seal_tag(&file).unwrap();
        let o = seal(&w, &t0, true);
        assert_output_clean(&o, &[&tf, &t0], &[]);
        assert!(o.status.success(), "the seal of t0: {}", text(&o.stderr));
        let ws = project(&w);
        let o = run(w.sealed_cmd(&["vm", "warm", &ws]), None);
        assert_output_clean(&o, &[&tf, &t0], &[]);
        assert_eq!(code(&o), 0, "the first warm: {}", text(&o.stderr));
        let id = w.fake().vms.keys().next().cloned().expect("the workspace's VM");
        let path = file.display().to_string();
        let o = run(w.sealed_cmd(&["vm", "exec", &id, "--credential-file", &path, "--", "true"]), None);
        assert_output_clean(&o, &[&tf, &t0], &[]);
        assert_eq!(code(&o), 0, "the one-shot: {}", text(&o.stderr));
        let row = ai_env_cli::bridge::vm::registry::read_row(&Paths::from_root_and_env(w.root.join("bridge"), None), &id).unwrap().unwrap();
        assert_eq!(row.credential_tag.as_deref(), Some(f.as_str()), "the one-shot's record names its file's seal");
        assert!(w.shim.spawns.credential().has(), "the VM's cache still holds S0");
        let (exit, err) = stopped_warm(&w, &ws, &t0);
        assert_token_off_disk(&w, &tf);
        assert_eq!(exit, Some(130), "{err}");
        assert!(holders(&w).contains(&id), "creds status lists the VM");
        assert!(err.contains(&format!("nothing was delivered by this run, but {id} may hold a token sent to it earlier (seal {f}, as its row records): `ai-env vm terminate {id}` clears it")), "{err}");
    }

    /// `c` started as a session leader whose controlling terminal, stdout and
    /// stderr are a fresh pty (stdin null; SIGINT, SIGTERM and SIGHUP at
    /// their defaults): the child and the pty's master, which only the test
    /// holds (both ends close on exec), non-blocking.
    fn on_a_terminal(mut c: Command) -> (Child, libc::c_int) {
        use std::os::unix::process::CommandExt as _;
        let (mut master, mut slave) = (0, 0);
        // SAFETY: openpty fills the two fds it is given; no name, termios or window size.
        assert_eq!(unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) }, 0);
        // SAFETY: fcntl on the two fds openpty just returned.
        unsafe {
            assert_eq!(libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC), 0);
            assert_eq!(libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC), 0);
            assert_eq!(libc::fcntl(master, libc::F_SETFL, libc::O_NONBLOCK), 0);
        }
        c.stdin(Stdio::null());
        // SAFETY: in the forked child before exec: setsid, ioctl, dup2 and signal are async-signal-safe.
        unsafe {
            c.pre_exec(move || {
                if libc::setsid() == -1 || libc::ioctl(slave, libc::c_ulong::from(libc::TIOCSCTTY), 0) == -1 || libc::dup2(slave, 1) == -1 || libc::dup2(slave, 2) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                    libc::signal(sig, libc::SIG_DFL);
                }
                Ok(())
            });
        }
        let child = c.spawn().unwrap();
        // SAFETY: our own copy of the slave.
        unsafe { libc::close(slave) };
        (child, master)
    }

    /// F3: the terminal closes (its pty's master: SIGHUP to its session, and
    /// every later write to it fails with EIO) while `vm smoke`'s VM starts.
    /// The smoke ends its VM and exits 143, as after SIGTERM: none of its
    /// lines after the stop panics on the dead terminal (the first one did,
    /// and the exit was 101).
    #[test]
    fn a_smoke_whose_terminal_closes_ends_its_vm_with_143() {
        let w = World::bare(None);
        // The VM stays PENDING: the smoke waits for RUNNING.
        w.update_fake(|s| s.auto_advance = false);
        let (mut child, master) = on_a_terminal(w.cmd(&["vm", "smoke"]));
        wait_for("RunMicrovm", || !w.fake().vms.is_empty());
        std::thread::sleep(Duration::from_millis(500));
        // What the terminal shows so far, read so its buffer never holds the smoke up.
        let mut buf = [0u8; 4096];
        // SAFETY: reads into our buffer from the non-blocking master we hold.
        while unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        // SAFETY: the only master: closing it hangs the terminal up.
        unsafe { libc::close(master) };
        let status = wait_bounded(&mut child);
        let alive: Vec<String> = w.fake().vms.values().filter(|v| !v.state.is_terminal()).map(|v| v.id.clone()).collect();
        assert_eq!((status.code(), alive), (Some(143), Vec::<String>::new()), "143, and its VM ended");
    }
}

// ---- S7 fix wave 2: probes ----

/// oauth-t1's process tests of the fix wave (F1), in a module of their own:
/// their stand-in stays theirs.
mod fix_wave_2_probes {
    use super::*;

    /// A `claude` for oauth-t1 that asks for a refresh only when offered it as
    /// the real CLI must be ([`OAUTH_CLAUDE`]'s condition) and notes each run
    /// as a line of `oauth-runs` beside itself: its entrypoint, the refresh
    /// flag, the 401 wait and the auth-fail exit (`-` when unset), whether its
    /// environment's token is the sealed one (`WANT`, the sealed token's
    /// sha256) and what came back for its request: `null`, `token` (the
    /// sealed token, by its sha256), `other-token`, `other`, `none` (its
    /// stdin ended first), or `not-offered`. Never a token itself. The reply
    /// is read in the background, on fd 3 (an asynchronous list's own stdin
    /// is /dev/null), so a run that is never answered still ends at once:
    /// its line comes when the harness closes its stdin.
    const RECORDING_CLAUDE: &str = r#"#!/bin/sh
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }
case "$1" in --version) echo '2.1.290 (Claude Code)'; exit 0 ;; esac
while IFS= read -r line; do
  case "$line" in *'"type":"user"'*) break ;; esac
done
if [ "$(printf %s "${CLAUDE_CODE_OAUTH_TOKEN:-}" | sha)" = WANT ]; then env_token=sealed; else env_token=other; fi
run="${CLAUDE_CODE_ENTRYPOINT:--} ${CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH:--} ${CLAUDE_CODE_OAUTH_401_WAIT_MS:--} ${CLAUDE_CODE_AUTH_FAIL_EXIT_MS:--} $env_token"
log="$(dirname "$0")/oauth-runs"
case "${CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH:-}:${CLAUDE_CODE_ENTRYPOINT:-}" in
  1:claude-desktop|1:local-agent|1:claude-vscode)
    printf '%s\n' '{"type":"control_request","request_id":"r1","request":{"subtype":"oauth_token_refresh"}}'
    exec 3<&0
    ( if IFS= read -r answer <&3; then
        case "$answer" in
          *'"request_id":"r1"'*'"accessToken":null'*) r=null ;;
          *'"request_id":"r1"'*'"accessToken":"'*)
            if [ "$(printf %s "$answer" | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p' | sha)" = WANT ]; then r=token; else r=other-token; fi ;;
          *) r=other ;;
        esac
      else
        r=none
      fi
      printf '%s %s\n' "$run" "$r" >>"$log" ) >/dev/null 2>&1 & ;;
  *) printf '%s not-offered\n' "$run" >>"$log" ;;
esac
printf '%s\n' '{"type":"result","subtype":"error_during_execution","is_error":true}'
exit 1
"#;

    /// A bare world with `token` sealed and `script` as the `claude` on PATH.
    fn oauth_world(token: &str, script: &str) -> World {
        use std::os::unix::fs::PermissionsExt as _;
        let w = World::bare(None);
        w.seed_credentials(token, "1.0");
        let claude = w.bin().join("claude");
        std::fs::write(&claude, script).unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        w
    }

    /// F1: oauth-t1 offers the CLI the host's refresh with the extension's
    /// entrypoint (`CLAUDE_CODE_ENTRYPOINT=claude-vscode` beside
    /// `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH=1`; without the entrypoint the CLI
    /// never asks, and no reply was ever sent), so each run's reply reaches
    /// the CLI as planned: none, null, null again with
    /// `CLAUDE_CODE_OAUTH_401_WAIT_MS=5000` alone (never
    /// `CLAUDE_CODE_AUTH_FAIL_EXIT_MS`, which acts only for a remote child),
    /// then the sealed token (one Touch ID). Every run's environment holds the
    /// refused token, never the sealed one; the opening line plans the fourth
    /// run only if one of the first three asks ([`PLANNED`]); the note names
    /// the entrypoint; the token is nowhere in the output or under the
    /// world's root.
    #[test]
    fn lab_oauth_t1_offers_the_refresh_with_the_extensions_entrypoint_and_answers_each_run() {
        let token = setup_token("Op7");
        let w = oauth_world(&token, &RECORDING_CLAUDE.replace("WANT", &sha256(token.as_bytes())));
        let before = w.decrypts();
        let o = run(w.sealed_cmd(&["lab", "run", "oauth-t1"]), None);
        assert_token_nowhere(&w, &o, &token);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 0, "{err}");
        assert!(err.contains(&format!("as claude-vscode: {PLANNED}")), "{err}");
        assert_eq!(w.decrypts() - before, 1, "the valid reply's Touch ID");
        // A line per run; the unanswered run's comes once its stdin closed, so they are compared sorted.
        let t = Instant::now();
        let runs = loop {
            let runs = std::fs::read_to_string(w.bin().join("oauth-runs")).unwrap_or_default();
            if runs.lines().count() >= 4 || t.elapsed() > Duration::from_secs(10) {
                break runs;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut runs: Vec<&str> = runs.lines().collect();
        runs.sort_unstable();
        assert_eq!(
            runs,
            ["claude-vscode 1 - - other none", "claude-vscode 1 - - other null", "claude-vscode 1 - - other token", "claude-vscode 1 5000 - other null"],
            "per run: entrypoint, refresh flag, 401 wait, auth-fail exit, the environment's token, the reply"
        );
        let row = probe_row(&w, "oauth-t1").expect("an oauth-t1 row");
        let note = row["note"].as_str().unwrap_or_default().to_string();
        assert_eq!(row["verdict"], "refresh-requested", "{note}");
        assert!(note.contains("(2.1.290 (Claude Code)) as claude-vscode with CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH=1; none: refresh@"), "{note}");
        assert!(note.contains("; null, CLAUDE_CODE_OAUTH_401_WAIT_MS=5000: refresh@") && note.contains("; valid: refresh@"), "{note}");
        // Once every run's line is in: still nowhere on disk.
        assert_token_off_disk(&w, &token);
    }

    /// What oauth-t1's opening line plans with a usable sealed token: three
    /// runs, and the fourth (the valid reply) only if one of them asks, so
    /// it never promises a run it then skips.
    const PLANNED: &str = "three runs with a refused token, then a fourth with the valid reply if one of them asks for a refresh, at most 150 s each";

    /// oauth-t1 skips the valid reply, with no Touch ID, when none of its
    /// first three runs asked for a refresh: the harness answers only a
    /// request, so the sealed token could never be sent, and it is not
    /// unsealed for nothing. Its opening line promised no fourth run (it
    /// used to say "four runs" here, then made three); stderr and the note
    /// say why it was skipped; the verdict is no-refresh-request. The token
    /// is nowhere in the output or under the world's root.
    #[test]
    fn lab_oauth_t1_skips_the_valid_reply_when_no_run_asked() {
        let token = setup_token("Oq7");
        let never = OAUTH_CLAUDE.replace("1:claude-desktop|1:local-agent|1:claude-vscode)", "1:no-such-entrypoint)");
        assert_ne!(never, OAUTH_CLAUDE, "the stand-in never asks");
        let w = oauth_world(&token, &never);
        let before = w.decrypts();
        let o = run(w.sealed_cmd(&["lab", "run", "oauth-t1"]), None);
        assert_token_nowhere(&w, &o, &token);
        let err = text(&o.stderr);
        assert_eq!(code(&o), 0, "{err}");
        assert_eq!(w.decrypts(), before, "no Touch ID for a reply that could never be sent");
        assert!(err.contains(&format!("as claude-vscode: {PLANNED}")) && !err.contains("four runs"), "{err}");
        assert!(err.contains("ai-env: oauth-t1: the valid reply is skipped: no run asked for a refresh"), "{err}");
        let row = probe_row(&w, "oauth-t1").expect("an oauth-t1 row");
        let note = row["note"].as_str().unwrap_or_default().to_string();
        assert_eq!(row["verdict"], "no-refresh-request", "{note}");
        assert!(note.ends_with("; valid: skipped (no run asked for a refresh)"), "{note}");
    }
}

// ---- S7 fix wave 2: exec ----

/// F5 through the binary: a credentialed `claude` (stream-json) whose
/// requests each meet one transient retry 401 and then answer with a reply
/// that is only a Write of an 80 KB file (one `assistant` line over the
/// watch's 64 KiB, as claude prints a reply with no text before its tool
/// call) is never stopped: its own status (0) and every line pass through,
/// nothing is audited or recorded, and the next credentialed command is not
/// refused. The token is nowhere in either's output or under the world's root.
#[test]
fn transient_401s_around_long_replies_never_stop_it() {
    const CLAUDE: &str = r#"#!/bin/sh
big=$(/usr/bin/head -c 80000 /dev/zero | /usr/bin/tr '\0' x)
for turn in 1 2 3; do
  printf '{"type":"system","subtype":"api_retry","attempt":1,"error_status":401,"error":"authentication_failed"}\n'
  printf '{"type":"assistant","message":{"id":"msg_%s","type":"message","role":"assistant","model":"claude-x","content":[{"type":"tool_use","id":"t%s","name":"Write","input":{"file_path":"/w/f%s","content":"%s"}}]}}\n' "$turn" "$turn" "$turn" "$big"
  printf '{"type":"user","message":{"role":"user","content":[{"tool_use_id":"t%s","type":"tool_result","content":"File created successfully"}]}}\n' "$turn"
done
printf '{"type":"result","subtype":"success","is_error":false,"result":"done"}\n'
"#;
    let token = setup_token("E5a");
    let w = World::credentialed_with(&token, Some(CLAUDE));
    let o = run(w.cred_exec(&["--with-credential", "--", "claude", "-p", "write the fixture files", "--output-format", "stream-json", "--verbose"]), None);
    assert_token_nowhere(&w, &o, &token);
    let err = text(&o.stderr);
    assert_eq!(code(&o), 0, "{err}");
    assert_eq!(text(&o.stdout).lines().filter(|l| l.len() > 80_000 && l.contains("\"name\":\"Write\"")).count(), 3, "every long reply passed through");
    assert!(!err.contains("Anthropic refused"), "{err}");
    assert!(w.audit("credential_rejected").is_empty());
    let o = run(w.cred_exec(&["--with-credential", "--", "/bin/sh", "-c", "cat <&3 >/dev/null; echo read"]), None);
    assert_token_nowhere(&w, &o, &token);
    assert_eq!((code(&o), text(&o.stdout).as_str()), (0, "read\n"), "not refused: {}", text(&o.stderr));
}

/// F17: SIGTERM and then SIGHUP, both sent during a refused command's 3 s
/// of TERM, wait until its child-gone check, which they end together: none
/// is left to cut the last flush short, so `vm exec` still exits 5 with its
/// line, which claims no stop it did not see (the check was cut short, and
/// the final detach ended the session before any exit came back). The KILL
/// reached the group, the rejection is recorded once, and the token is
/// nowhere in the output or under the world's root.
#[test]
fn sigterm_and_sighup_during_a_refusals_stop_keep_exit_5_and_its_line() {
    let token = setup_token("E17a");
    let m = marker(171);
    let w = World::credentialed_with(&token, Some(&refused_claude(&m)));
    let live = Live::start(w.cred_exec(&["--with-credential", "--", "claude", "stubborn", "--output-format", "stream-json"]));
    let mut out: Vec<String> = (0..3).map(|_| live.line()).collect();
    let t3 = Instant::now();
    live.signal(libc::SIGTERM);
    std::thread::sleep(Duration::from_millis(100));
    live.signal(libc::SIGHUP);
    let (status, rest, err) = live.finish();
    let took = t3.elapsed();
    out.extend(rest);
    assert_token_nowhere(&w, &Output { status, stdout: out.join("\n").into_bytes(), stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "neither signal undoes the refusal: {err}");
    let vm = &w.id;
    assert!(err.contains(&format!(" was not seen gone from {vm} before a signal ended the check (it holds the refused token)")), "{err}");
    assert!(err.contains("ai-env: Anthropic refused the delivered setup-token (HTTP 401): the stop was sent, but the command was not seen to end (see above); it is not started again") && !err.contains("was stopped"), "{err}");
    assert!(took < Duration::from_millis(4500), "the KILL at 3 s, then no wait for the check: {took:?}");
    assert!(gone(&format!("^sleep {m}$")), "the KILL reached the group");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
}

/// `vm exec` with stdout and stderr piped and nothing read yet, as a
/// started child.
fn spawn_unread(mut cmd: Command) -> Child {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
}

/// Wait until `vm exec`'s session has ended with its output unconfirmed
/// (its log says so; the pump's last flush follows at once), then a margin.
fn wait_for_the_last_flush(w: &World) {
    wait_for("the session's end, its output unconfirmed", || w.cli_log().contains("the consumer did not confirm its output"));
    std::thread::sleep(Duration::from_millis(500));
}

/// F17: a refused command's last flush cut short by a signal. The command
/// prints 300 KB nobody reads, then claude's 401 on stderr, and exits 1:
/// `vm exec` waits for its stdout (a refusal is no stop of the operator's,
/// so that wait has no bound) until a SIGINT ends the wait. It still exits
/// 5, with its line, which stderr's writer wrote out (stderr is read). The
/// rejection is recorded, and the token is nowhere in the output or under
/// the world's root.
#[test]
fn a_signal_that_cuts_a_refusals_flush_short_keeps_exit_5_and_its_line() {
    const CLAUDE: &str = "#!/bin/sh\necho start >> \"$HOME/starts\"\n/bin/dd if=/dev/zero bs=1000 count=300 2>/dev/null | /usr/bin/tr '\\0' 'x'\necho\necho 'API Error: 401 {\"type\":\"error\",\"error\":{\"type\":\"authentication_error\"}}' >&2\nexit 1\n";
    let token = setup_token("E17b");
    let w = World::credentialed_with(&token, Some(CLAUDE));
    let mut child = spawn_unread(w.cred_exec(&["--with-credential", "--", "claude", "-p", "hi"]));
    let held = child.stdout.take().unwrap();
    let err = read_all(child.stderr.take().unwrap());
    wait_for_the_last_flush(&w);
    assert!(child.try_wait().unwrap().is_none(), "vm exec waits for its stdout");
    // SAFETY: kill(2) on our own child's pid.
    unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGINT) };
    let status = wait_bounded(&mut child);
    let (out, err) = (read_all(held).join().unwrap(), text(&err.join().unwrap()));
    assert_token_nowhere(&w, &Output { status, stdout: out, stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "the signal does not undo the refusal: {err}");
    assert!(err.contains("ai-env: Anthropic refused the delivered setup-token (HTTP 401): the command exited and is not started again"), "{err}");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("text")));
}

/// F17's other side: when a stderr nobody reads holds a refused command's
/// last flush, a signal still ends `vm exec` within a second (what stderr's
/// writer gets for the line, which it cannot write), with exit 5. The
/// command prints claude's 401 on stderr, then 300 KB more there, and
/// exits 1. The rejection is recorded, and the token is nowhere in the
/// output or under the world's root.
#[test]
fn a_signal_ends_a_refusals_flush_stuck_on_stderr_promptly_with_exit_5() {
    const CLAUDE: &str = "#!/bin/sh\necho start >> \"$HOME/starts\"\necho 'API Error: 401 {\"type\":\"error\",\"error\":{\"type\":\"authentication_error\"}}' >&2\n/bin/dd if=/dev/zero bs=1000 count=300 2>/dev/null | /usr/bin/tr '\\0' 'y' >&2\necho >&2\nexit 1\n";
    let token = setup_token("E17c");
    let w = World::credentialed_with(&token, Some(CLAUDE));
    let mut child = spawn_unread(w.cred_exec(&["--with-credential", "--", "claude", "-p", "hi"]));
    let out = read_all(child.stdout.take().unwrap());
    let held = child.stderr.take().unwrap();
    wait_for_the_last_flush(&w);
    assert!(child.try_wait().unwrap().is_none(), "vm exec waits for its stderr");
    let t = Instant::now();
    // SAFETY: kill(2) on our own child's pid.
    unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGINT) };
    let mut ended = None;
    while ended.is_none() && t.elapsed() < Duration::from_secs(5) {
        ended = child.try_wait().unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    let err = read_all(held);
    let status = ended.unwrap_or_else(|| wait_bounded(&mut child));
    let (out, err) = (out.join().unwrap(), text(&err.join().unwrap()));
    assert_token_nowhere(&w, &Output { status, stdout: out, stderr: err.into_bytes() }, &token);
    assert!(ended.is_some(), "the signal ended vm exec within 5 s, without waiting on the stderr nobody read");
    assert_eq!(status.code(), Some(5), "the signal does not undo the refusal");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("text")));
}

/// F22: a VM terminated during a refused command's stop (from another
/// terminal, or its max duration) leaves the child-gone check no token to
/// read `/health/detail` with: the `vm terminate` hint says the check made
/// no read and why, never that it looked for 5 s, and `vm exec` ends at
/// once with exit 5. The rejection is recorded, and the token is nowhere in
/// the output or under the world's root.
#[test]
fn a_child_gone_check_that_cannot_mint_says_it_made_no_read() {
    let token = setup_token("E22a");
    let m = marker(221);
    let w = World::credentialed_with(&token, Some(&refused_claude(&m)));
    let live = Live::start(w.cred_exec(&["--with-credential", "--", "claude", "stubborn", "--output-format", "stream-json"]));
    let mut out: Vec<String> = (0..3).map(|_| live.line()).collect();
    let t3 = Instant::now();
    let id = w.id.clone();
    w.update_fake(|s| s.vms.get_mut(&id).unwrap().state = VmState::Terminated);
    let (mints, reads) = (w.mints(), detail_reads(&w));
    let (status, rest, err) = live.finish();
    let took = t3.elapsed();
    out.extend(rest);
    assert_token_nowhere(&w, &Output { status, stdout: out.join("\n").into_bytes(), stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "{err}");
    assert!(w.mints() > mints && detail_reads(&w) == reads, "the check tried to mint, and read nothing");
    let vm = &w.id;
    assert!(err.contains(&format!(" was not seen gone from {vm}: the check made no read (its token could not be minted: ")) && !err.contains("within 5 s"), "{err}");
    assert!(took < Duration::from_millis(4500), "the KILL at 3 s, then no 5 s wait: {took:?}");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
}

/// F27 (a): a refused `claude` that ends on TERM, whose exit comes back, but
/// whose `/health/detail` cannot be read (every read fails, scripted after
/// the delivery's reads): the child-gone check never sees it gone, so the
/// `vm terminate` hint names the check's 5 s, and the exit-5 line says the
/// command was stopped (its exit came back), never that the stop was not
/// seen to end. One start, the rejection recorded as `retries`, and the
/// token nowhere in the output or under the world's root.
#[test]
fn a_refused_command_whose_exit_came_back_unseen_by_the_check_reads_as_stopped() {
    let token = setup_token("E27a");
    let m = marker(271);
    let w = World::credentialed_with(&token, Some(&refused_claude(&m)));
    let live = Live::start(w.cred_exec(&["--with-credential", "--", "claude", "gated", "-p", "hi", "--output-format", "stream-json"]));
    let mut out: Vec<String> = (0..2).map(|_| live.line()).collect();
    w.update_fake(|s| s.failures.extend((0..64).map(|_| FakeFailure { kind: "endpoint".into(), message: "the endpoint did not answer".into(), on: Some("health_detail".into()), after_effect: false })));
    let reads = detail_reads(&w);
    std::fs::write(w.root.join("home").join("go"), "").unwrap();
    out.push(live.line());
    let t3 = Instant::now();
    let (status, rest, err) = live.finish();
    let took = t3.elapsed();
    out.extend(rest);
    assert_token_nowhere(&w, &Output { status, stdout: out.join("\n").into_bytes(), stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "{err}");
    assert!(gone(&format!("^sleep {m}$")), "TERM reached its group");
    let (vm, spawn) = (&w.id, w.audit("vm_exec")[0]["detail"]["spawn"].as_str().unwrap().to_string());
    assert!(err.contains(&format!("ai-env: spawn {spawn} was not seen gone from {vm} within 5 s (it holds the refused token): `ai-env vm terminate {vm}` ends it")), "{err}");
    assert!(err.contains("ai-env: Anthropic refused the delivered setup-token (HTTP 401): the command was stopped and is not started again") && !err.contains("the stop was sent"), "its exit came back: {err}");
    assert!(!err.contains("the stop could not reach"), "{err}");
    assert!(took >= Duration::from_secs(5) && took < Duration::from_secs(10), "TERM ended it, then the check read for its 5 s: {took:?}");
    assert!(detail_reads(&w) >= reads + 2, "the check read /health/detail until its time was up");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
}

/// F27 (b): a refused `claude` whose third retry 401 is its last line,
/// without a newline, then exit 1: the watch reads that line only at the
/// exit, so no stop was due: exit 5 saying the command exited, and the
/// refusal audited as `retries`, not `text`. One start, and the token
/// nowhere in the output or under the world's root.
#[test]
fn retries_read_only_at_the_exit_are_audited_as_retries() {
    const CLAUDE: &str = r#"#!/bin/sh
echo start >> "$HOME/starts"
for i in 1 2; do
  printf '{"type":"system","subtype":"api_retry","attempt":%s,"error_status":401,"error":"authentication_failed"}\n' "$i"
done
printf '{"type":"system","subtype":"api_retry","attempt":3,"error_status":401,"error":"authentication_failed"}'
exit 1
"#;
    let token = setup_token("E27b");
    let w = World::credentialed_with(&token, Some(CLAUDE));
    let o = run(w.cred_exec(&["--with-credential", "--", "claude", "-p", "hi", "--output-format", "stream-json"]), None);
    assert_token_nowhere(&w, &o, &token);
    let err = text(&o.stderr);
    assert_eq!(code(&o), 5, "{err}");
    assert_eq!(text(&o.stdout).matches("\"subtype\":\"api_retry\"").count(), 3, "every line passed through");
    assert!(err.contains("Anthropic refused the delivered setup-token (HTTP 401): the command exited and is not started again") && !err.contains("was stopped") && !err.contains("stopping the command"), "{err}");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
    assert_eq!(starts(&w), 1, "claude started once");
}

/// F17, round 2: stdout and stderr on one pipe nobody reads (`2>&1` into a
/// reader that stalled). The command prints claude's 401 on stderr, then
/// 300 KB on stdout, which fills the pipe, and exits 1. A SIGINT during `vm
/// exec`'s last flush ends it within 5 s with exit 5: the exiting thread
/// writes nothing on that pipe (the exit-5 line is stderr's last piece, and
/// waits behind the full pipe like the rest). The rejection is recorded, and
/// the token is nowhere in the output or under the world's root.
#[test]
fn a_signal_ends_a_refusals_flush_on_one_full_pipe_promptly_with_exit_5() {
    const CLAUDE: &str = "#!/bin/sh\necho start >> \"$HOME/starts\"\necho 'API Error: 401 {\"type\":\"error\",\"error\":{\"type\":\"authentication_error\"}}' >&2\nsleep 0.5\n/bin/dd if=/dev/zero bs=1000 count=300 2>/dev/null | /usr/bin/tr '\\0' 'x'\necho\nexit 1\n";
    let token = setup_token("E17d");
    let w = World::credentialed_with(&token, Some(CLAUDE));
    let (reader, writer) = std::io::pipe().unwrap();
    let mut cmd = w.cred_exec(&["--with-credential", "--", "claude", "-p", "hi"]);
    cmd.stdout(writer.try_clone().unwrap()).stderr(writer);
    let mut child = cmd.spawn().unwrap();
    // This process's copies of the write end closed: the pipe ends with vm exec.
    drop(cmd);
    wait_for_the_last_flush(&w);
    assert!(child.try_wait().unwrap().is_none(), "vm exec waits for the pipe");
    let t = Instant::now();
    // SAFETY: kill(2) on our own child's pid.
    unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGINT) };
    let mut ended = None;
    while ended.is_none() && t.elapsed() < Duration::from_secs(5) {
        ended = child.try_wait().unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    let both = read_all(reader);
    let status = ended.unwrap_or_else(|| wait_bounded(&mut child));
    assert_token_nowhere(&w, &Output { status, stdout: both.join().unwrap(), stderr: Vec::new() }, &token);
    assert!(ended.is_some(), "the SIGINT ended vm exec within 5 s, not once the pipe was read");
    assert_eq!(status.code(), Some(5), "the signal does not undo the refusal");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("text")));
}

/// F17, round 2: a refused command's stderr that is read only after the
/// SIGINT that cut the last flush short (300 ms later) still gets the exit-5
/// line: stderr's writer has a second more to write it out. The command
/// prints claude's 401 on stderr, then 300 KB more there, and exits 1. The
/// rejection is recorded, and the token is nowhere in the output or under
/// the world's root.
#[test]
fn a_stderr_read_soon_after_the_cut_still_gets_the_refusals_line() {
    const CLAUDE: &str = "#!/bin/sh\necho start >> \"$HOME/starts\"\necho 'API Error: 401 {\"type\":\"error\",\"error\":{\"type\":\"authentication_error\"}}' >&2\n/bin/dd if=/dev/zero bs=1000 count=300 2>/dev/null | /usr/bin/tr '\\0' 'y' >&2\necho >&2\nexit 1\n";
    let token = setup_token("E17f");
    let w = World::credentialed_with(&token, Some(CLAUDE));
    let mut child = spawn_unread(w.cred_exec(&["--with-credential", "--", "claude", "-p", "hi"]));
    let out = read_all(child.stdout.take().unwrap());
    let held = child.stderr.take().unwrap();
    wait_for_the_last_flush(&w);
    assert!(child.try_wait().unwrap().is_none(), "vm exec waits for its stderr");
    let t = Instant::now();
    // SAFETY: kill(2) on our own child's pid.
    unsafe { libc::kill(i32::try_from(child.id()).unwrap(), libc::SIGINT) };
    std::thread::sleep(Duration::from_millis(300));
    let err = read_all(held);
    let status = wait_bounded(&mut child);
    let took = t.elapsed();
    let (out, err) = (out.join().unwrap(), text(&err.join().unwrap()));
    assert_token_nowhere(&w, &Output { status, stdout: out, stderr: err.clone().into_bytes() }, &token);
    assert_eq!(status.code(), Some(5), "the signal does not undo the refusal");
    let ours: Vec<&str> = err.lines().filter(|l| l.starts_with("ai-env: ")).collect();
    assert!(ours.last().is_some_and(|l| l.starts_with("ai-env: Anthropic refused the delivered setup-token (HTTP 401): the command exited and is not started again")), "the exit-5 line is stderr's last ai-env line: {ours:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("text")));
}

/// F17, round 2: SIGTERM and then SIGHUP during a refused command's 3 s of
/// TERM end its child-gone check together, and that leaves no signal to end
/// the last flush: it is bounded as an operator's stop is (3 s), so a stderr
/// nobody reads (300 KB of the command's, the hint and the exit-5 line
/// behind them) no longer holds `vm exec` until a third signal. It exits 5
/// by itself once that bound is up (the KILL at 3 s, the bound 3 s later).
/// The KILL reached the group, the rejection is recorded once, and the
/// token is nowhere in the output or under the world's root.
#[test]
fn signals_that_end_a_refusals_check_bound_its_last_flush() {
    let m = marker(172);
    let claude = format!(
        "#!/bin/sh\necho start >> \"$HOME/starts\"\ntrap '' TERM\nsleep {m} &\n/bin/dd if=/dev/zero bs=1000 count=300 2>/dev/null | /usr/bin/tr '\\0' 'y' >&2\nfor i in 1 2 3; do\n  printf '{{\"type\":\"system\",\"subtype\":\"api_retry\",\"attempt\":%s,\"error_status\":401,\"error\":\"authentication_failed\"}}\\n' \"$i\"\n  sleep 0.2\ndone\nwait\n"
    );
    let token = setup_token("E17e");
    let w = World::credentialed_with(&token, Some(&claude));
    let mut child = spawn_unread(w.cred_exec(&["--with-credential", "--", "claude", "stubborn", "--output-format", "stream-json"]));
    let held = child.stderr.take().unwrap();
    let (tx, lines) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines().map_while(std::result::Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let mut out: Vec<String> = (0..3).map(|_| lines.recv_timeout(LIMIT).expect("a retry line in time")).collect();
    let pid = i32::try_from(child.id()).unwrap();
    let t3 = Instant::now();
    // SAFETY: kill(2) on our own child's pid.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    std::thread::sleep(Duration::from_millis(100));
    // SAFETY: as above.
    unsafe { libc::kill(pid, libc::SIGHUP) };
    let mut ended = None;
    while ended.is_none() && t3.elapsed() < Duration::from_secs(10) {
        ended = child.try_wait().unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    let took = t3.elapsed();
    if ended.is_none() {
        // A third signal ends what the bound did not (the test fails below).
        // SAFETY: as above.
        unsafe { libc::kill(pid, libc::SIGINT) };
    }
    let err = read_all(held);
    let status = ended.unwrap_or_else(|| wait_bounded(&mut child));
    out.extend(lines.iter());
    assert_token_nowhere(&w, &Output { status, stdout: out.join("\n").into_bytes(), stderr: err.join().unwrap() }, &token);
    assert!(ended.is_some(), "vm exec ended by itself within 10 s of the signals");
    assert!(took >= Duration::from_secs(5), "the KILL at 3 s, then the flush's 3 s: {took:?}");
    assert_eq!(status.code(), Some(5), "neither signal undoes the refusal");
    assert!(gone(&format!("^sleep {m}$")), "the KILL reached the group");
    assert_eq!(starts(&w), 1, "claude started once");
    let rows = w.audit("credential_rejected");
    assert_eq!((rows.len(), rows[0]["detail"]["how"].as_str()), (1, Some("retries")));
}
