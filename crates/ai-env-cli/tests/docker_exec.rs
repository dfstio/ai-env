//! Opt-in Docker test of the real Mac client against the real image (plan S6
//! T6.7 offline), run by `make test-docker` after the shim-only suite
//! (`AI_ENV_DOCKER_TESTS=1`, every test `#[ignore]`d so `cargo test` never
//! needs Docker). With the variable set, a missing daemon or local image is a
//! FAILURE, never a skip. Every docker call and every process is bounded;
//! every container is named `ai-env-s6-…` (S6 and S7's) or `ai-env-s8-…`
//! (S8's, their internal networks `ai-env-s8-…-net`) and removed on drop.
//!
//! L2, the locally built image (`make image-build-local`), runs its shipped
//! ENTRYPOINT (the shim as root with the agent guard as shipped: its default
//! `on`, or tree B's fallback `log`; the pinned claude) with its ports
//! published on 127.0.0.1. `ai-env vm run` starts a VM on the
//! file-backed fake API, and the payload RunMicrovm carried goes to the
//! container's `/run` (the platform's run hook). The real `ai-env vm exec`
//! then dials `/agent` through the fake endpoint of `common/fake_endpoint.rs`
//! (the debug-build knob AI_ENV_BRIDGE_LAB_AGENT_ADDR), which checks the
//! endpoint token and forwards to the container's published app port, from
//! outside its network namespace as the platform's proxy does. The `ai-env`
//! processes get a temp HOME, PATH /usr/bin:/bin and none of the developer's
//! AWS or ai-env variables. The only claude ever executed is the pinned Linux
//! binary inside L2.
//!
//! S7: `ai-env vm exec --with-credential` on L2, in a world seeded as
//! `tests/shim_bridge_local.rs` seeds its own (the gate's facts, the fake age
//! and keystore, the runtime key and a dummy setup-token sealed by the real
//! `creds` commands): the agent reads the token on fd 3; the dummies are in
//! no Mac file, container file, command line, environment, output or log;
//! nothing in the container opened a connection out or sent a datagram in
//! its life (it only accepted the forwarder's); the shim's one spawn is the
//! `sh` asked for. The image's claude answers `auth status --json` logged
//! out on `--network none` (a pinned fixture).
//!
//! S8 (wave 2, W6): the workspace data plane and the remote session on L2
//! with no route out. The image runs as shipped on `--network none`, its
//! loopback alone, so the pinned claude never has a way out; the Mac reaches
//! its three ports through `common/docker_tunnel.rs` (a `docker exec` per
//! connection), and the routed endpoint of `common/fake_endpoint.rs` sends
//! 8080 and 9418 there and plays the platform's hooks through the third, as
//! the remote rig (`tests/common/remote.rs`) does for its in-process shim.
//! No `--fs-root`: the agent is uid 1000 with its home `/Users/mike`, and a
//! workspace's VM path is its Mac path, so the test's workspace lies under
//! `CARGO_TARGET_TMPDIR` (under the Mac's `/Users/mike`) and the helper
//! makes every directory to it as the agent. The real `ai-env box seed`,
//! `box fetch` and `ai-env-claude` (remote mode) run in the green vpc world
//! (`common/green_world.rs`): the seed at the identical path, the `/suspend`
//! snapshot, a planted symlink, the code-out round trip, the helper's git
//! environment, and a session whose `initialize` the pinned claude answers.
#[path = "common/docker_tunnel.rs"]
mod docker_tunnel;
#[path = "common/fake_endpoint.rs"]
mod fake_endpoint;
#[path = "common/green_world.rs"]
mod green_world;

use ai_env_cli::bridge::api::{FakeState, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::config::Paths;
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use ai_env_cli::bridge::vm::registry::VmRow;
use docker_tunnel::Tunnel;
use fake_endpoint::FakeEndpoint;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const PREFIX: &str = "/aws/lambda-microvms/runtime/v1";
const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// Every docker call's bound: a stuck daemon fails the test, never hangs it.
const DOCKER_LIMIT: Duration = Duration::from_secs(120);
/// Every `ai-env` process's bound (killed and failed past it).
const LIMIT: Duration = Duration::from_secs(120);

/// `docker <args>`, killed past `limit`.
fn docker_within(args: &[&str], limit: Duration) -> Result<Output, String> {
    let child = Command::new("docker").args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("docker CLI: {e}"))?;
    finish_within(child, limit).ok_or_else(|| format!("docker {args:?} did not finish within {limit:?}"))
}

fn docker(args: &[&str]) -> Output {
    docker_within(args, DOCKER_LIMIT).unwrap_or_else(|e| panic!("{e}"))
}

/// `child` to its end, stdout and stderr read meanwhile; `None` (and the
/// child killed) once `limit` passed.
fn finish_within(mut child: std::process::Child, limit: Duration) -> Option<Output> {
    let drain = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.read_to_end(&mut buf);
            buf
        })
    };
    let (out, err) = (drain(Box::new(child.stdout.take().expect("piped"))), drain(Box::new(child.stderr.take().expect("piped"))));
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    Some(Output { status, stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default() })
}

/// Every test starts here: panics unless explicitly enabled (the tests are
/// `#[ignore]`d, so reaching this without the variable is a mistake).
fn require_enabled() {
    assert_eq!(std::env::var("AI_ENV_DOCKER_TESTS").as_deref(), Ok("1"), "run through `make test-docker` (AI_ENV_DOCKER_TESTS=1)");
    let out = docker(&["version", "--format", "{{.Server.Version}}"]);
    assert!(out.status.success(), "the Docker daemon is not running: {}", String::from_utf8_lossy(&out.stderr));
}

fn local_image() -> String {
    std::env::var("AI_ENV_DOCKER_IMAGE").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "ai-env-agent:local".into())
}

fn lock_version() -> String {
    let lock = std::fs::read_to_string(Path::new(REPO).join("image/claude.lock")).unwrap();
    ai_env_cli::wire::pin::parse_lock(&lock).unwrap().version
}

/// The agent guard the image's ENTRYPOINT (image/Dockerfile's exec-form
/// line) runs: its `--agent-guard` value, or `on` (the default as root on
/// Linux) when it passes none. Plan S6 ships only these: the default, or tree
/// B's fallback `log` (the endpoint reaches 8080 as a local peer), never
/// `off`; the hooks guard is `--hook-source peer` either way.
fn shipped_agent_guard() -> &'static str {
    let df = std::fs::read_to_string(Path::new(REPO).join("image/Dockerfile")).unwrap();
    let line = df.lines().find_map(|l| l.strip_prefix("ENTRYPOINT ")).expect("an ENTRYPOINT line");
    let argv: Vec<String> = serde_json::from_str(line).unwrap_or_else(|e| panic!("ENTRYPOINT is not exec form ({e}): {line}"));
    assert!(!argv.iter().any(|a| a.starts_with("--") && a.contains('=')), "a `--flag=value` word in the ENTRYPOINT: {argv:?}");
    let value = |flag: &str| argv.iter().position(|a| a == flag).map(|at| argv.get(at + 1).map_or("", String::as_str));
    assert_eq!(value("--hook-source"), Some("peer"), "the hooks guard ships as `--hook-source peer`: {argv:?}");
    match value("--agent-guard") {
        None | Some("on") => "on",
        Some("log") => "log",
        Some(other) => panic!("the image never runs `--agent-guard {other}` (plan S6: the default on, or tree B's log): {argv:?}"),
    }
}

fn ok_stdout(args: &[&str]) -> String {
    let out = docker(args);
    assert!(out.status.success(), "docker {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `ai-env-s6-<pid>-<n>-<ms>`: unique per run and container.
fn container_name() -> String {
    container_name_for("s6")
}

/// `ai-env-<stage>-<pid>-<n>-<ms>`: S6 and S7's containers say `s6`, S8's `s8`.
fn container_name_for(stage: &str) -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!("ai-env-{stage}-{}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst), ai_env_cli::wire::time::unix_now_ms() % 1_000_000)
}

/// A detached L2 container, removed on drop.
struct Container {
    id: String,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = docker_within(&["rm", "-f", &self.id], DOCKER_LIMIT);
    }
}

impl Container {
    /// `image` with its shipped ENTRYPOINT, its three ports published on 127.0.0.1.
    fn start(image: &str) -> Container {
        // The guard exists before `docker run`: a container created but not started goes too.
        let c = Container { id: container_name() };
        ok_stdout(&["run", "-d", "--name", &c.id, "--platform", "linux/arm64", "-p", "127.0.0.1::9000", "-p", "127.0.0.1::8080", "-p", "127.0.0.1::9418", image]);
        c
    }

    fn port(&self, inner: u16) -> SocketAddr {
        let out = ok_stdout(&["port", &self.id, &format!("{inner}/tcp")]);
        out.lines().next().unwrap().trim().parse().unwrap_or_else(|e| panic!("{e}: {out:?}"))
    }

    fn logs(&self) -> String {
        let out = docker(&["logs", &self.id]);
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    }

    /// The log once it holds `n` lines starting with `prefix` (Docker copies
    /// the shim's stderr on its own time), within `secs`.
    fn wait_lines(&self, secs: u64, prefix: &str, n: usize) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let logs = self.logs();
            if logs.lines().filter(|l| l.starts_with(prefix)).count() >= n {
                return logs;
            }
            assert!(Instant::now() < deadline, "{n} lines starting {prefix:?} not in the log within {secs} s:\n{logs}");
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The log once `ok` holds for it, within `secs`, as [`Self::wait_lines`];
    /// a timeout names `what` and the log's length, never its text (it may be
    /// a credential test's).
    fn wait_for(&self, secs: u64, what: &str, ok: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let logs = self.logs();
            if ok(&logs) {
                return logs;
            }
            assert!(Instant::now() < deadline, "{what} not in the log within {secs} s ({} lines)", logs.lines().count());
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// The shim's spawn lines in `logs` (it logs a spawn's program and word
/// count, never its words): (spawn id, argv0, argc, secret delivery).
fn spawns(logs: &str) -> Vec<(String, String, usize, String)> {
    logs.lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("ai-env: spawn ")?;
            let field = |key: &str| rest.split(' ').find_map(|f| f.strip_prefix(key));
            Some((rest.split(' ').next()?.to_string(), field("argv0=")?.to_string(), field("argc=")?.parse().ok()?, field("secret=")?.to_string()))
        })
        .collect()
}

/// POST/GET through the published port; (status, body). Retries while the
/// port forwarder accepts but the shim is not listening yet.
fn http(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, String) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match try_http(addr, method, path, body) {
            Ok(r) => return r,
            Err(e) => {
                assert!(Instant::now() < deadline, "{method} {path}: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn try_http(addr: SocketAddr, method: &str, path: &str, body: &str) -> std::io::Result<(u16, String)> {
    let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, rest) = text.split_once("\r\n\r\n").ok_or_else(|| std::io::Error::other(format!("no response: {text:?}")))?;
    let status = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| std::io::Error::other(text.clone()))?;
    Ok((status, rest.to_string()))
}

/// `/ready` until 200 (503 while the claude probe runs), within `secs`.
fn wait_ready(c: &Container, secs: u64) {
    let hooks = c.port(9000);
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let (s, body) = http(hooks, "POST", &format!("{PREFIX}/ready"), "");
        if s == 200 {
            return;
        }
        assert_eq!(s, 503, "{body}");
        assert!(Instant::now() < deadline, "/ready never answered 200: {body}\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// One L2 world: the container, a temp root (`bridge/` with its bridge.toml,
/// `keys/`, `ws/`), the file-backed fake (`fake.json`, PENDING → RUNNING on
/// the first GetMicrovm) and the fake endpoint in front of the container's
/// published app port; `id` is the VM `ai-env vm run` started, whose payload
/// went to the container's `/run`.
struct World {
    root: PathBuf,
    c: Container,
    endpoint: FakeEndpoint,
    id: String,
    _tmp: tempfile::TempDir,
}

impl World {
    fn new() -> World {
        require_enabled();
        let image = local_image();
        let out = docker(&["image", "inspect", &image]);
        assert!(out.status.success(), "{image} is missing: run make image-build-local");
        let c = Container::start(&image);
        wait_ready(&c, 120);
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in ["bridge", "keys", "ws"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let toml = format!("[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\n\n[workspaces]\nroots = [{:?}]\n", root.join("ws").display().to_string());
        std::fs::write(root.join("bridge").join("bridge.toml"), toml).unwrap();
        let state = FakeState { auto_advance: true, ..FakeState::new() };
        std::fs::write(root.join("fake.json"), serde_json::to_string_pretty(&state).unwrap()).unwrap();
        let endpoint = FakeEndpoint::start(&root.join("fake.json"), c.port(8080));
        let mut w = World { root, c, endpoint, id: String::new(), _tmp: tmp };
        let mut cmd = w.cmd(&["vm", "run", "--egress", "internet", "--json"]);
        cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1");
        let o = bounded(cmd);
        assert!(o.status.success(), "vm run: {}", text(&o.stderr));
        w.id = serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap()["id"].as_str().unwrap().to_string();
        assert_eq!(w.post_run(), 200, "{}", w.c.logs());
        w
    }

    fn fake_path(&self) -> PathBuf {
        self.root.join("fake.json")
    }

    /// `ai-env <args>`: the fake API, `/agent` through the fake endpoint; the
    /// developer's AWS and ai-env variables removed, PATH pinned. No backoff
    /// knob: the session keeps its real timers across Docker's port forwarder.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ai-env"));
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
            .env("AI_ENV_BRIDGE_LAB_AGENT_ADDR", self.endpoint.addr.to_string())
            .stdin(Stdio::null());
        c
    }

    /// `ai-env vm exec <id> -- <argv>`, to its end.
    fn exec(&self, argv: &[&str]) -> Output {
        let mut args = vec!["vm", "exec", self.id.as_str(), "--"];
        args.extend_from_slice(argv);
        bounded(self.cmd(&args))
    }

    /// POST the payload RunMicrovm carried for the VM to the container's `/run` (the platform's run hook).
    fn post_run(&self) -> u16 {
        let st = FileFakeMicrovmApi::open(&self.fake_path()).unwrap().snapshot().unwrap();
        let token = st.tokens.iter().find(|(_, v)| **v == self.id).map(|(k, _)| k.clone()).expect("the VM's client token");
        let payload = st.specs.iter().find(|s| s.client_token == token).expect("the VM's run spec").run_hook_payload.clone();
        let body = serde_json::json!({ "microvmId": self.id, "runHookPayload": payload }).to_string();
        http(self.c.port(9000), "POST", &format!("{PREFIX}/run"), &body).0
    }

    /// The session token `vm run` kept in the VM's row.
    fn session_token(&self) -> String {
        let path = self.root.join("bridge").join("state").join("vms").join(format!("{}.toml", self.id));
        let row: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        row["session_token"].as_str().expect("a session token in the row").to_string()
    }

    fn audit(&self, event: &str) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(self.root.join("bridge").join("audit.jsonl")).unwrap_or_default();
        text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).collect()
    }
}

/// `cmd` to its end, stdout and stderr read meanwhile; killed and failed past [`LIMIT`].
fn bounded(mut cmd: Command) -> Output {
    let what = format!("ai-env {:?}", cmd.get_args().collect::<Vec<_>>());
    let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
    finish_within(child, LIMIT).unwrap_or_else(|| panic!("{what} ran past {LIMIT:?}"))
}

/// T6.7 offline: the real `ai-env vm exec` runs the pinned claude in the real
/// image as the agent — `claude --version` prints exactly the lock's version
/// line, `id -u` is 1000 — and a remote `exit 3` is its own exit 3. Each
/// exec is one `/agent` upgrade, checked and forwarded by the fake endpoint
/// and admitted by the shim's 8080 agent guard (as shipped: on, or tree B's
/// `log`), one `vm_exec` audit row and one spawn line (the one claude being
/// the two-word `--version`, never `claude -p`); the session token never
/// reaches the container's log.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_vm_exec_runs_the_pinned_claude_as_the_agent_and_exits_with_the_remote_code() {
    let w = World::new();
    let o = w.exec(&["claude", "--version"]);
    assert_eq!(o.status.code(), Some(0), "{}\n{}", text(&o.stderr), w.c.logs());
    assert_eq!(text(&o.stdout), format!("{} (Claude Code)\n", lock_version()), "{}", text(&o.stderr));
    let o = w.exec(&["id", "-u"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout), "1000\n");
    let o = w.exec(&["sh", "-c", "exit 3"]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout), "");
    let attempts: Vec<(u16, String)> = w.endpoint.attempts().into_iter().map(|a| (a.status, a.path)).collect();
    assert_eq!(attempts, vec![(101, "/agent".to_string()); 3], "one upgrade per exec, each through the endpoint");
    // The shim runs as shipped: the agent guard on, or tree B's `log`. Each
    // upgrade passed the 8080 guard first: the n-th guard line carries the
    // n-th upgrade's peer (the execs ran one after another). Docker's
    // forwarder, like the platform's proxy, connects from outside the
    // container's network namespace: no row there and not the container's
    // address, so both modes log the same admitted line (`log` differs only
    // in a refusal, which it logs as `would-refuse:` and lets through).
    let mode = shipped_agent_guard();
    let logs = w.c.wait_lines(10, "ai-env: agent upgrade ", 3);
    assert!(logs.lines().any(|l| l.starts_with("ai-env: shim ") && l.ends_with(&format!(" hook-source peer agent-guard {mode}"))), "the shipped ENTRYPOINT's policies (agent guard {mode}):\n{logs}");
    let lines = |prefix: &str| logs.lines().filter(|l| l.starts_with(prefix)).collect::<Vec<_>>();
    let (guard, upgrades) = (lines("ai-env: guard "), lines("ai-env: agent upgrade "));
    assert_eq!((guard.len(), upgrades.len()), (3, 3), "one guarded request per exec, its upgrade:\n{logs}");
    for (g, u) in guard.iter().zip(&upgrades) {
        let peer = u.split(' ').find_map(|f| f.strip_prefix("peer=")).unwrap_or("?");
        assert!(u.contains(" status=101 ") && g.starts_with(&format!("ai-env: guard port=8080 peer={peer} ")) && g.contains(" peer_uid=- ") && g.ends_with(" decision=admit"), "the 8080 guard admitted the upgrade's connection:\n{g}\n{u}");
    }
    let audit = w.audit("vm_exec");
    let rows: Vec<(&str, &str)> = audit.iter().map(|r| (r["detail"]["argv0"].as_str().unwrap_or_default(), r["detail"]["status"].as_str().unwrap_or_default())).collect();
    assert_eq!(rows, [("claude", "0"), ("id", "0"), ("sh", "3")]);
    // The spawn lines carry each program and its word count: the one claude
    // is the two words whose stdout was the version line above.
    let spawn_log = w.c.wait_for(10, "three spawn lines", |l| spawns(l).len() >= 3);
    let spawned = spawns(&spawn_log);
    let spawned: Vec<(&str, usize, &str)> = spawned.iter().map(|(_, argv0, argc, secret)| (argv0.as_str(), *argc, secret.as_str())).collect();
    assert_eq!(spawned, [("claude", 2, "none"), ("id", 2, "none"), ("sh", 3, "none")], "the shim's spawns, in order");
    assert!(!w.c.logs().contains(&w.session_token()), "the session token reached the container's log");
}

// ---- S7: `ai-env vm exec --with-credential` on the real image --------------------------
//
// The real Mac client delivers a sealed setup-token through the gate and the
// fake endpoint, and the real shim caches it and hands it to the agent on fd 3.
// The world mirrors `tests/shim_bridge_local.rs`'s `World::seed_credentials`
// (the green vpc facts, the fake age and keystore, the sealed runtime key and
// token) but against the real container, not an in-process shim. The
// credentialed command reads fd 3 with `wc`, never `claude -p`. The L2
// container is on Docker's default bridge (its ports are published), so it
// has a route out, and the shim's start-up probe runs the image's claude
// there (`--version`, before any token), as in every L2 test: the credential
// test reads the container's own network counters at its end, and nothing
// from inside opened a TCP connection, sent a UDP datagram or an ICMP echo
// in the container's life. `claude auth status --json` runs on
// `--network none`.

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

/// What a credentialed world seals, built at run time with a per-test tail:
/// a setup-token of the real shape and the runtime key's id and secret.
struct Dummies {
    token: String,
    key_id: String,
    secret_key: String,
}

impl Dummies {
    /// `tail`: two ASCII letters (the key id takes them upper-cased).
    fn new(tail: &str) -> Dummies {
        Dummies { token: setup_token(tail), key_id: format!("AKIA{}ID{}", "CRED".repeat(3), tail.to_ascii_uppercase()), secret_key: format!("{}cr{tail}", "Tq8+".repeat(9)) }
    }

    /// What must be nowhere in the clear: the token past the kind marker
    /// `creds` records (`sk-ant-oat01-`), the key id and its secret.
    fn needles(&self) -> [&str; 3] {
        [&self.token[13..], &self.key_id, &self.secret_key]
    }
}

/// `text` with every needle replaced by its length: what a failure message
/// may print of a buffer a dummy could have reached.
fn masked(text: &str, needles: &[&str]) -> String {
    needles.iter().fold(text.to_string(), |t, n| t.replace(n, &format!("<{} bytes>", n.len())))
}

/// `cmd` with `input` on its stdin (then EOF) to its end, stdout and stderr
/// read meanwhile; `None` (and the child killed) once `limit` passed.
fn fed_within(mut cmd: Command, input: &[u8], limit: Duration) -> Option<Output> {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn the child");
    let (mut sink, bytes) = (child.stdin.take().expect("piped stdin"), input.to_vec());
    // A killed child closes the pipe: the feeder's write fails and it ends.
    let feeder = std::thread::spawn(move || {
        let _ = sink.write_all(&bytes);
    });
    let out = finish_within(child, limit);
    let _ = feeder.join();
    out
}

/// `cmd` to its end with `stdin` piped, bounded by [`LIMIT`]; stdout/stderr read meanwhile.
fn run_in(cmd: Command, stdin: &[u8]) -> Output {
    fed_within(cmd, stdin, LIMIT).unwrap_or_else(|| panic!("ai-env ran past {LIMIT:?}"))
}

/// Every file under `root` (relative, links not followed), and those whose
/// bytes hold one of `needles`, each with the length of the needle it holds.
fn files_holding(root: &Path, needles: &[&str]) -> (Vec<String>, Vec<(String, usize)>) {
    let (mut seen, mut hits, mut dirs) = (Vec::new(), Vec::new(), vec![root.to_path_buf()]);
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let (path, kind) = (entry.path(), entry.file_type().unwrap());
            if kind.is_dir() {
                dirs.push(path);
            } else if kind.is_file() {
                let rel = path.strip_prefix(root).unwrap().display().to_string();
                let bytes = std::fs::read(&path).unwrap();
                hits.extend(needles.iter().filter(|n| bytes.windows(n.len()).any(|w| w == n.as_bytes())).map(|n| (rel.clone(), n.len())));
                seen.push(rel);
            }
        }
    }
    (seen, hits)
}

/// What [`Container::disk_hits`] runs as root, its needles on stdin: a
/// recursive `grep -rlF` over every top-level entry but the kernel trees
/// /proc, /sys and /dev, and over the tmpfs /dev/shm, then grep's status.
/// Links are not followed (the top-level ones lead into /usr), devices, FIFOs
/// and sockets are skipped, and a binary file is searched like any other (no
/// `-I`; `LC_ALL=C` reads bytes as bytes).
const DISK_SCAN: &str = "for p in /* /.[!.]*; do case \"$p\" in /proc|/sys|/dev) continue ;; esac; \
                         if [ -L \"$p\" ] || [ ! -e \"$p\" ]; then continue; fi; set -- \"$@\" \"$p\"; done; \
                         LC_ALL=C timeout 90 grep -rlF -f - -- \"$@\" /dev/shm; echo \"rc=$?\"";

/// Where [`Container::disk_hits`] plants its canary.
const CANARY_PATH: &str = "/tmp/ai-env-scan-canary";

/// What [`Container::proc_hits`] runs: every process's command line and
/// environment, an entry a line, and `refused <file>` for a read that failed
/// on a live process. A zombie has no memory left to read (the kernel answers
/// ESRCH: a spawn's leader waits as one until the shim reaps it), and a
/// process gone meanwhile has none either: neither is a refusal.
const PROC_DUMP: &str = "for d in /proc/[0-9]*; do for f in cmdline environ; do \
                         tr '\\0' '\\n' 2>/dev/null < \"$d/$f\" || { grep -qsE '^State:[[:space:]]+[^ZX[:space:]]' \"$d/status\" && echo \"refused $d/$f\"; }; echo; done; done; true";

impl Container {
    /// `sh -c <script>` as root in the container: its stdout, trimmed, after a clean exit.
    fn sh(&self, script: &str) -> String {
        let out = docker(&["exec", "-u", "0", &self.id, "sh", "-c", script]);
        assert!(out.status.success(), "{script}: {}", text(&out.stderr));
        text(&out.stdout).trim().to_string()
    }

    /// Every file of the container holding one of `needles`, as
    /// [`DISK_SCAN`] lists them (paths only). A canary, planted NUL-framed at
    /// [`CANARY_PATH`] and looked for with them, must be the one extra hit and
    /// grep's status 0: a scan that skipped binary files, lost its patterns,
    /// failed or ran out of time never passes for "found nothing".
    fn disk_hits(&self, needles: &[&str]) -> Vec<String> {
        let canary = format!("ai-env-scan-canary-{}", ai_env_cli::wire::frame::SpawnId::new_v7());
        self.sh(&format!("printf '\\0%s\\0' {canary} > {CANARY_PATH}"));
        let mut patterns = String::new();
        for n in needles.iter().copied().chain([canary.as_str()]) {
            patterns.push_str(n);
            patterns.push('\n');
        }
        let mut cmd = Command::new("docker");
        cmd.args(["exec", "-i", "-u", "0", &self.id, "sh", "-c", DISK_SCAN]);
        let out = fed_within(cmd, patterns.as_bytes(), DOCKER_LIMIT).unwrap_or_else(|| panic!("the disk scan ran past {DOCKER_LIMIT:?}"));
        self.sh(&format!("rm -f {CANARY_PATH}"));
        let mut hits: Vec<String> = text(&out.stdout).lines().map(str::to_string).collect();
        let status = hits.pop().unwrap_or_default();
        let canaries = hits.iter().filter(|h| *h == CANARY_PATH).count();
        assert!(status == "rc=0" && canaries == 1, "the scan did not finish clean with its canary found once ({status}, {canaries}; hits {hits:?}): {}", text(&out.stderr));
        hits.retain(|h| h != CANARY_PATH);
        hits
    }

    /// How many lines of the container's command lines and environments hold
    /// one of `needles`. [`PROC_DUMP`] runs in a privileged exec: an agent
    /// process's environ asks its reader for CAP_SYS_PTRACE, which root under
    /// Docker's default capabilities lacks (`Permission denied`). The lines
    /// are matched here, so no needle rides an argv in the container. No read
    /// may be refused, and the dump must hold PID 1's program and a `PATH=`.
    fn proc_hits(&self, needles: &[&str]) -> usize {
        let out = docker(&["exec", "--privileged", "-u", "0", &self.id, "sh", "-c", PROC_DUMP]);
        assert!(out.status.success(), "the process dump: {}", text(&out.stderr));
        let dump = text(&out.stdout);
        let refused: Vec<&str> = dump.lines().filter(|l| l.starts_with("refused /proc/")).collect();
        assert!(refused.is_empty(), "the dump was refused {refused:?}");
        let read = dump.lines().any(|l| l == "/usr/local/bin/ai-env") && dump.lines().any(|l| l.starts_with("PATH="));
        assert!(read, "the dump read no command line or no environment ({} lines)", dump.lines().count());
        dump.lines().filter(|l| needles.iter().any(|n| l.contains(n))).count()
    }

    /// The container's own network counters, by name (`Tcp:ActiveOpens`,
    /// `Udp6OutDatagrams`, …): /proc/net/snmp and snmp6 as read inside, where
    /// they count its network namespace alone, from its start.
    fn net_counters(&self) -> std::collections::BTreeMap<String, u64> {
        let dump = self.sh("cat /proc/net/snmp /proc/net/snmp6");
        let lines: Vec<&str> = dump.lines().collect();
        let mut counters = std::collections::BTreeMap::new();
        let mut at = 0;
        while at < lines.len() {
            let words: Vec<&str> = lines[at].split_whitespace().collect();
            match words[..] {
                // snmp: a `Proto: names…` line, then its `Proto: values…` line.
                [proto, ..] if proto.ends_with(':') => {
                    let values: Vec<&str> = lines.get(at + 1).map(|l| l.split_whitespace().collect()).unwrap_or_default();
                    for (name, value) in words.iter().zip(&values).skip(1) {
                        if let Ok(v) = value.parse() {
                            counters.insert(format!("{proto}{name}"), v);
                        }
                    }
                    at += 2;
                }
                // snmp6: `Name value`.
                [name, value] => {
                    if let Ok(v) = value.parse() {
                        counters.insert(name.to_string(), v);
                    }
                    at += 1;
                }
                _ => at += 1,
            }
        }
        counters
    }
}

impl World {
    fn bin(&self) -> PathBuf {
        self.root.join("bin")
    }

    fn age_log(&self) -> PathBuf {
        self.root.join("age.log")
    }

    /// [`World::cmd`] with the fake age first on PATH and its log, the runtime
    /// key unsealable under the fake API, a hidden paste reading stdin, a
    /// TMPDIR under the root (the leak walk covers it), and the developer's
    /// CLAUDE_CODE_*/FAKE_* removed so no real token reaches it.
    fn sealed_cmd(&self, args: &[&str]) -> Command {
        let mut c = self.cmd(args);
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().to_string();
            if k.starts_with("CLAUDE_CODE_") || k.starts_with("FAKE_") {
                c.env_remove(&k);
            }
        }
        c.env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("TMPDIR", self.root.join("tmp"))
            .env("FAKE_AGE_LOG", self.age_log())
            .env("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1")
            .env("AI_ENV_PASTE_STDIN", "1");
        c
    }

    /// `ai-env vm exec <id> <args>` as [`Self::sealed_cmd`] (args carry their own `--`).
    fn cred_exec(&self, args: &[&str]) -> Command {
        let mut all = vec!["vm", "exec", self.id.as_str()];
        all.extend_from_slice(args);
        self.sealed_cmd(&all)
    }

    fn row(&self) -> VmRow {
        ai_env_cli::bridge::vm::registry::read_row(&Paths::from_root_and_env(self.root.join("bridge"), None), &self.id).unwrap().unwrap()
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

    fn edit_row(&self, f: impl FnOnce(&mut toml::Table)) {
        let path = self.root.join("bridge").join("state").join("vms").join(format!("{}.toml", self.id));
        let mut row: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        f(&mut row);
        std::fs::write(&path, toml::to_string(&row).unwrap()).unwrap();
    }

    /// Decrypts (Touch IDs) the fake age served so far.
    fn decrypts(&self) -> usize {
        std::fs::read_to_string(self.age_log()).unwrap_or_default().lines().filter(|l| l.starts_with("age -d ")).count()
    }

    /// A world whose VM may receive a credential: everything
    /// `shim_bridge_local`'s `World::seed_credentials` seeds (the connector
    /// fixture and its answer, an egress-verified record bound to the VM's
    /// image version, the fake's facts and build, a no-dns dns-path row, the
    /// fake keystore key, and the runtime key and token of `d` sealed by the
    /// real `creds` commands with the fake age — no combined.env), then a vpc
    /// row whose echo gate passed and the fake VM's matching egress echo.
    fn credentialed(d: &Dummies) -> World {
        let w = World::new();
        w.seed_credentials(d);
        w.edit_row(|row| {
            row.insert("egress".into(), "vpc".into());
            row.insert("egress_gate".into(), "passed".into());
            row.insert("egress_connectors".into(), toml::Value::Array(vec![CONNECTOR.into()]));
        });
        let id = w.id.clone();
        w.update_fake(|s| s.vms.get_mut(&id).unwrap().egress = vec![CONNECTOR.to_string()]);
        w
    }

    /// Everything but the vpc row a credential needs (see [`Self::credentialed`]).
    /// Neither `creds` command prints a dummy.
    fn seed_credentials(&self, d: &Dummies) {
        use ai_env_cli::bridge::egress::{ConnectorFacts, EgressVerified, VerifiedRecord, DNS_NONE, DNS_RULE};
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::create_dir_all(self.bin()).unwrap();
        std::fs::create_dir_all(self.root.join("tmp")).unwrap();
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
        let version = self.row().image_version;
        self.update_fake(|s| {
            s.connectors.insert(CONNECTOR.to_string(), connector_doc());
            // The fake answers `/health/detail`, which `vm exec` reads before the token's own unseal (its caps
            // decide, S7 M11): it says what the image's real shim offers.
            s.health_caps = vec![ai_env_cli::wire::frame::CAP_CREDENTIAL_CACHE.to_string()];
        });
        let now = ai_env_cli::wire::time::unix_now();
        let record = VerifiedRecord {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: version,
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
        let aws = format!("{{\"AccessKey\": {{\"UserName\": \"ai-env-runtime\", \"AccessKeyId\": \"{}\", \"Status\": \"Active\", \"SecretAccessKey\": \"{}\"}}}}", d.key_id, d.secret_key);
        let needles = d.needles();
        for (what, args, input) in [("creds aws-set", &["creds", "aws-set"][..], aws), ("creds setup-token", &["creds", "setup-token", "--stdin", "--no-combined"][..], format!("{}\n", d.token))] {
            let o = run_in(self.sealed_cmd(args), input.as_bytes());
            assert!(o.status.success(), "{what}: {}", masked(&text(&o.stderr), &needles));
            let printed: Vec<usize> = needles.iter().filter(|n| text(&o.stdout).contains(*n) || text(&o.stderr).contains(*n)).map(|n| n.len()).collect();
            assert!(printed.is_empty(), "{what} printed dummies of {printed:?} bytes");
        }
    }
}

/// S7 T7.3 on the real image: `ai-env vm exec <id> --with-credential -- sh -c
/// 'wc -c <&3'` passes the credential gate in the fake world, unseals the
/// runtime key and the token with the fake age (two Touch IDs, no
/// combined.env), delivers the token through the fake endpoint to the real
/// shim, and the agent reads its byte count on fd 3. Then, before anything
/// prints a buffer a dummy could reach: the token and the key's id and secret
/// are in neither output nor the container's log, in no file under the Mac
/// side's root (HOME, the bridge and keys dirs, TMPDIR; the sealed files hold
/// them hex-encoded only), in no file of the container ([`Container::disk_hits`])
/// and on no command line or environment there; and nothing in the container
/// opened a TCP connection, sent a UDP datagram or an ICMP echo in its whole
/// life — the shim's start-up `claude --version` probe included. The exec is
/// one `/agent` upgrade, one `vm_exec` row and the shim's one spawn, that
/// row's `sh` of three words with the secret on fd 3 (no claude ran); one
/// `credential_deliver` row (source `sealed`) and a `credential_unseal` row
/// with source `setup-token`.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_vm_exec_with_credential_delivers_the_token_and_the_agent_reads_its_byte_count() {
    let d = Dummies::new("Ll");
    let needles = d.needles();
    let w = World::credentialed(&d);
    let before = w.decrypts();
    let o = bounded(w.cred_exec(&["--with-credential", "--", "sh", "-c", "wc -c <&3"]));
    assert_eq!(o.status.code(), Some(0), "{}\n{}", masked(&text(&o.stderr), &needles), masked(&w.c.logs(), &needles));
    let rows = w.audit("vm_exec");
    assert_eq!(rows.len(), 1, "one vm_exec row");
    let spawn = rows[0]["detail"]["spawn"].as_str().unwrap_or_default().to_string();
    let logs = w.c.wait_for(10, "the spawn's release", |l| l.contains(&format!("ai-env: spawn {spawn} released")));
    for (what, hay) in [("the exec stdout", text(&o.stdout)), ("the exec stderr", text(&o.stderr)), ("the container log", logs.clone())] {
        let held: Vec<usize> = needles.iter().filter(|n| hay.contains(*n)).map(|n| n.len()).collect();
        assert!(held.is_empty(), "{what} holds dummies of {held:?} bytes");
    }
    let (seen, on_mac) = files_holding(&w.root, &needles);
    for sealed in ["bridge/credentials/aws.env", "bridge/credentials/setup-token.env"] {
        assert!(seen.iter().any(|f| f == sealed), "the walk never reached {sealed}: {seen:?}");
    }
    assert!(on_mac.is_empty(), "the Mac side holds dummies in the clear: {on_mac:?}");
    let on_disk = w.c.disk_hits(&needles);
    assert!(on_disk.is_empty(), "the container's disk holds a dummy in {on_disk:?}");
    let in_procs = w.c.proc_hits(&needles);
    assert_eq!(in_procs, 0, "a dummy is on {in_procs} command line or environment line(s) in the container");
    // No request left the container: its own counters, from its start.
    let net = w.c.net_counters();
    let counter = |name: &str| net.get(name).copied().unwrap_or_else(|| panic!("no {name} among the container's counters: {:?}", net.keys().collect::<Vec<_>>()));
    let reached: Vec<(&str, u64)> = ["Tcp:ActiveOpens", "Udp:OutDatagrams", "Udp6OutDatagrams", "Icmp:OutEchos", "Icmp6OutEchos"].into_iter().map(|k| (k, counter(k))).collect();
    assert!(reached.iter().all(|(_, n)| *n == 0), "the container reached out: {reached:?}");
    let inbound = counter("Tcp:PassiveOpens");
    assert!(inbound >= 3, "the counters are the container's own: /ready, /run and /agent came in, yet {inbound} passive opens");
    let count: usize = text(&o.stdout).trim().parse().unwrap_or_else(|e| panic!("{e}: {:?}", text(&o.stdout)));
    assert_eq!(count, d.token.len(), "fd 3 carried the token's {} bytes", d.token.len());
    assert_eq!(w.decrypts() - before, 2, "the runtime key and the token, no combined.env");
    let attempts: Vec<(u16, String)> = w.endpoint.attempts().into_iter().map(|a| (a.status, a.path)).collect();
    assert!(attempts.iter().all(|(_, p)| p == "/agent"), "the endpoint mediated only /agent: {attempts:?}");
    assert_eq!(attempts.iter().filter(|(s, _)| *s == 101).count(), 1, "one /agent upgrade: {attempts:?}");
    let deliver = w.audit("credential_deliver");
    assert_eq!((deliver.len(), deliver.first().and_then(|r| r["detail"]["source"].as_str())), (1, Some("sealed")), "one delivery of a freshly unsealed credential: {deliver:?}");
    assert!(w.audit("credential_unseal").iter().any(|r| r["detail"]["source"] == "setup-token" && r["detail"]["outcome"] == "ok"), "the token was unsealed");
    assert!(w.audit("credential_gate").iter().any(|r| r["detail"]["result"] == "passed"), "the gate passed");
    // The shim logs a spawn's program and word count: its one spawn is this
    // exec's `sh -c 'wc -c <&3'`, the secret on fd 3. No claude ran.
    let spawned = spawns(&logs);
    let spawned: Vec<(&str, &str, usize, &str)> = spawned.iter().map(|(id, argv0, argc, secret)| (id.as_str(), argv0.as_str(), *argc, secret.as_str())).collect();
    assert_eq!(spawned, [(spawn.as_str(), "sh", 3, "fd3")], "the vm_exec row's spawn is the shim's only one");
    assert_eq!(rows[0]["detail"]["argv0"].as_str(), Some("sh"), "{:?}", rows[0]);
    eprintln!("L2 credential: fd 3 carried {count} bytes; {} Mac files and the container's disk clean; {reached:?}, {inbound} passive opens; endpoint {attempts:?}", seen.len());
}

/// The pinned image's `claude auth status --json`, run with no token and no
/// network (`--network none`; the builder-only claude exception, never `claude
/// -p`), reports a logged-out shape: the fixture pins its top-level key set and
/// `loggedIn` false (no email, org or account value). This is the shape part B
/// confirms for the recorded CLAUDE_VERSION.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_claude_auth_status_json_is_logged_out_with_no_network() {
    require_enabled();
    let image = local_image();
    assert!(docker(&["image", "inspect", &image]).status.success(), "{image} is missing: run make image-build-local");
    // Named and removed on drop like every container here (`--rm` removes it at its exit).
    let c = Container { id: container_name() };
    let out = docker(&["run", "--rm", "--name", &c.id, "--platform", "linux/arm64", "--network", "none", "-u", "1000", "-e", "HOME=/Users/mike", "--entrypoint", "/usr/local/bin/claude", &image, "auth", "status", "--json"]);
    let answer: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}\n{}", text(&out.stdout), text(&out.stderr)));
    let fixture: serde_json::Value = serde_json::from_str(include_str!("fixtures/claude/auth-status-logged-out.json")).unwrap();
    let keys = |v: &serde_json::Value| {
        let mut k: Vec<String> = v.as_object().expect("a JSON object").keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&answer), keys(&fixture), "the auth status --json key set changed; re-pin tests/fixtures/claude/auth-status-logged-out.json");
    assert_eq!(answer["loggedIn"], serde_json::json!(false), "no token: logged out: {answer}");
    assert_eq!(fixture["loggedIn"], serde_json::json!(false), "the fixture pins logged out");
    for k in ["email", "orgId", "organizationId", "organizationName", "account", "accountUuid", "userId", "oauthAccount"] {
        assert!(fixture.get(k).is_none(), "the fixture must carry no account identity ({k})");
    }
    eprintln!("L2 claude auth status --json keys: {:?}", keys(&answer));
}

// ---- S8: the workspace and the remote session on L2, no route out ------------------------
//
// The image runs as shipped with no route out ([`Container::offline`]): on
// `--network none`, or, for a session's claude, on an internal network whose
// one address is the egress proxy's, the container's own, where a decoy
// proxy logs and refuses each request. The pinned claude never has a way
// out, nor has the shim's own probe of it. The Mac reaches the three ports
// through [`Tunnel`]s (a `docker exec` per connection, as root), and the
// routed endpoint plays the platform through them ([`DockerRig`]). The
// container's own counters show what tried a way out: a packet with no
// route, a datagram, an echo must be none, and every connection made in it
// taken by a listener in it (the shim's for a tunnel's, or the decoy's), or
// reset at the decoy's closing listener ([`DockerRig::assert_no_way_out`]).

/// The image's agent (the Dockerfile's `useradd`): its uid, and its home,
/// under which every workspace path lies.
const AGENT_UID: &str = "1000";
const AGENT_HOME: &str = "/Users/mike";
/// The shim's runtime hooks port (the ENTRYPOINT's `--hooks-port`).
const HOOKS_PORT: u16 = 9000;
/// The image version the green world's egress check is recorded for (the fake's one version).
const IMAGE_VERSION: &str = "1.0";
/// The fixture repository's one commit: its author and date (the same id on every run).
const FIXTURE_AUTHOR: (&str, &str) = ("ai-env fixture", "fixture@ai-env.invalid");
const FIXTURE_DATE: &str = "2026-10-12T08:00:00+00:00";
/// The session argv of extension 2.1.282's chat spawn (`tests/common/mod.rs`'s).
const SESSION_ARGV: [&str; 16] = [
    "--output-format",
    "stream-json",
    "--verbose",
    "--input-format",
    "stream-json",
    "--permission-prompt-tool",
    "stdio",
    "--setting-sources=user,project,local",
    "--permission-mode",
    "default",
    "--include-partial-messages",
    "--debug",
    "--debug-to-stderr",
    "--enable-auth-status",
    "--no-chrome",
    "--replay-user-messages",
];
/// The phase-0 fake git (a logging passthrough to the real git, its knobs
/// from `<path>.knobs`), mounted as the shim's `--git`.
const FAKE_GIT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/git.sh");

/// Every path under the agent's home, links not followed, as `<mode>
/// <uid>:<gid> <path>`, sorted by path.
const HOME_TREE: &str = "find /Users/mike -mindepth 1 -printf '%m %U:%G %p\\n' | LC_ALL=C sort -k3";

/// `git <args>` in `dir` by the Mac's git (`/usr/bin/git`, the one the rig's
/// commands find on their `PATH`), with neither the system's nor a global
/// config and the fixture's author and dates: its stdout, trimmed; a
/// failure panics with its stderr.
fn mac_git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("/usr/bin/git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", FIXTURE_AUTHOR.0)
        .env("GIT_AUTHOR_EMAIL", FIXTURE_AUTHOR.1)
        .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
        .env("GIT_COMMITTER_NAME", FIXTURE_AUTHOR.0)
        .env("GIT_COMMITTER_EMAIL", FIXTURE_AUTHOR.1)
        .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
        .stdin(Stdio::null())
        .output()
        .expect("run the Mac's git");
    assert!(o.status.success(), "git {args:?} in {}: {}", dir.display(), text(&o.stderr));
    text(&o.stdout).trim().to_string()
}

/// `work` a git repository with one commit on `main` (`README.md`): the commit.
fn fixture_repo(work: &Path) -> String {
    mac_git(work, &["init", "-q", "-b", "main"]);
    std::fs::write(work.join("README.md"), "fixture\n").expect("write README.md");
    mac_git(work, &["add", "README.md"]);
    mac_git(work, &["commit", "-q", "-m", "fixture"]);
    mac_git(work, &["rev-parse", "HEAD"])
}

/// The Mac's uncommitted work a seed carries (D2): an edit, a staged file, an untracked one.
fn dirty_the_mac(work: &Path) {
    std::fs::write(work.join("README.md"), "fixture, edited on the Mac\n").expect("edit README.md");
    std::fs::write(work.join("staged.txt"), "staged on the Mac\n").expect("write staged.txt");
    mac_git(work, &["add", "staged.txt"]);
    std::fs::write(work.join("notes.txt"), "untracked on the Mac\n").expect("write notes.txt");
}

/// What a code-out leaves alone on the Mac (`tests/workspace/e2e.rs`'s
/// view): HEAD, the branches and tags, the index and the worktree
/// (untracked and ignored files too), the stash; read without optional locks.
fn mac_view(work: &Path) -> Vec<String> {
    [
        &["rev-parse", "HEAD"][..],
        &["for-each-ref", "refs/heads", "refs/tags"],
        &["--no-optional-locks", "status", "--porcelain=v2", "--untracked-files=all", "--ignored"],
        &["--no-optional-locks", "diff", "--cached"],
        &["--no-optional-locks", "diff"],
        &["stash", "list"],
    ]
    .iter()
    .map(|args| mac_git(work, args))
    .collect()
}

/// The part `name` of a census note (`name:value`, parts joined by `; `).
fn note_part(note: &str, name: &str) -> Option<String> {
    note.split("; ").find_map(|p| p.strip_prefix(name)?.strip_prefix(':')).map(str::to_string)
}

/// An internal Docker network of S8's (`ai-env-s8-…-net`): no gateway route
/// out of it, no published port; removed on drop, so declare it before the
/// containers on it (they go first).
struct Network {
    name: String,
}

impl Network {
    /// `--internal` with `subnet` (a `/24`) and its gateway `gateway`.
    fn internal(subnet: &str, gateway: &str) -> Network {
        // The guard exists before `docker network create`, as for a container.
        let n = Network { name: format!("{}-net", container_name_for("s8")) };
        ok_stdout(&["network", "create", "--internal", "--subnet", subnet, "--gateway", gateway, &n.name]);
        n
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = docker_within(&["network", "rm", &self.name], DOCKER_LIMIT);
    }
}

impl Container {
    /// `image` with its shipped ENTRYPOINT, `flags` appended to its argv, on
    /// `network`: `none` (its loopback alone) or an internal one, so no port
    /// is published and nothing in it has a route out ([`Tunnel`]s reach in).
    fn offline(image: &str, network: &str, docker_args: &[&str], flags: &[&str]) -> Container {
        // The guard exists before `docker run`: a container created but not started goes too.
        let c = Container { id: container_name_for("s8") };
        let mut args = vec!["run", "-d", "--name", &c.id, "--platform", "linux/arm64", "--network", network];
        args.extend_from_slice(docker_args);
        args.push(image);
        args.extend_from_slice(flags);
        ok_stdout(&args);
        c
    }

    /// `sh -c <script>` as the agent (uid 1000, its home): its stdout,
    /// trimmed, after a clean exit.
    fn agent_sh(&self, script: &str) -> String {
        let out = docker(&["exec", "-u", AGENT_UID, "-e", "HOME=/Users/mike", &self.id, "sh", "-c", script]);
        assert!(out.status.success(), "{script} as the agent: {}", text(&out.stderr));
        text(&out.stdout).trim().to_string()
    }

    /// `git <args>` in `dir` as the agent (the image's git and its system
    /// config): its stdout, trimmed, after a clean exit.
    fn agent_git(&self, dir: &str, args: &[&str]) -> String {
        let mut all = vec!["exec", "-u", AGENT_UID, "-e", "HOME=/Users/mike", "-w", dir, &self.id, "git"];
        all.extend_from_slice(args);
        let out = docker(&all);
        assert!(out.status.success(), "git {args:?} in the VM: {}", text(&out.stderr));
        text(&out.stdout).trim().to_string()
    }

    /// `sh -c <script>` as root in a privileged exec (an agent process's
    /// environ asks its reader for CAP_SYS_PTRACE, which root lacks under
    /// Docker's default capabilities): its stdout, trimmed, after a clean exit.
    fn privileged_sh(&self, script: &str) -> String {
        let out = docker(&["exec", "--privileged", "-u", "0", &self.id, "sh", "-c", script]);
        assert!(out.status.success(), "{script}: {}", text(&out.stderr));
        text(&out.stdout).trim().to_string()
    }

    /// `pid` is a live process of the container's (not a zombie).
    fn alive(&self, pid: u32) -> bool {
        let out = docker(&["exec", &self.id, "cat", &format!("/proc/{pid}/stat")]);
        out.status.success() && text(&out.stdout).rsplit_once(") ").is_some_and(|(_, rest)| !rest.starts_with('Z'))
    }

    /// The paths under the agent's home that are not the agent's (`<uid>:<gid> <path>`).
    fn not_the_agents(&self) -> Vec<String> {
        self.sh(HOME_TREE).lines().filter(|l| l.split(' ').nth(1) != Some("1000:1000")).map(str::to_string).collect()
    }
}

/// `/ready` through the hooks tunnel until 200 (503 while the claude probe
/// runs, no answer while nothing listens yet), within `secs`.
fn ready_through(c: &Container, hooks: SocketAddr, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match try_http(hooks, "POST", &format!("{PREFIX}/ready"), "") {
            Ok((200, _)) => return,
            Ok((503, _)) | Err(_) => {}
            Ok((status, body)) => panic!("/ready answered {status}: {body}\n{}", c.logs()),
        }
        assert!(Instant::now() < deadline, "/ready never answered 200 within {secs} s:\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Where the decoy proxy of [`DockerRig::behind_a_decoy_proxy`] logs each
/// request line it got (one line per connection it took).
const DECOY_LOG: &str = "/tmp/ai-env-s8-proxy.log";

/// The decoy proxy, gawk run as root in the container (gawk can listen on
/// TCP; the image has no other listener): on the egress proxy's port, one
/// connection at a time, it logs the request line, reads the head away and
/// refuses with 403, as the egress proxy refuses a host off its allowlist
/// (`-v out=` its log, `-v port=` its port). gawk listens with a backlog of
/// one and closes its listener once it took a connection, listening again
/// for the next: a connection that comes while it is busy with another is
/// refused, and one queued or still in its handshake when the listener
/// closes is reset; the CLI tries again later.
const DECOY: &str = r#"BEGIN {
  srv = "/inet4/tcp/" port "/0/0"
  while (1) {
    line = "(nothing)"
    if ((srv |& getline first) > 0) {
      sub(/\r$/, "", first); line = first
      while ((srv |& getline h) > 0) { sub(/\r$/, "", h); if (h == "") break }
      printf "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" |& srv
    }
    print line >> out; fflush(out)
    close(srv)
  }
}"#;

/// One S8 world on L2 (the section's doc), the remote rig of
/// `tests/common/remote.rs` with the real image in place of the in-process
/// shim: the container on `--network none` (the shipped ENTRYPOINT, a test's
/// flags appended), a tunnel per port, the routed endpoint in front of them
/// as the platform (it runs a VM on the shim at the VM's first request), the
/// file-backed fake API (`auto_advance`; its `/health` names the credential
/// cache and `workspace_v1`), the green vpc world with combined.env (one
/// Touch ID per credentialed command), and `<root>/work` a repository with
/// one commit. `<root>` is a tempdir under `CARGO_TARGET_TMPDIR`, a Mac path
/// under the image's `/Users/mike`: the workspace's VM path is its own.
/// Dropped in field order: the endpoint (its connections end), the container
/// (what runs inside goes with it), its network, the tunnels.
struct DockerRig {
    endpoint: FakeEndpoint,
    c: Container,
    /// The internal network of [`DockerRig::behind_a_decoy_proxy`]; `None` on `--network none`.
    net: Option<Network>,
    hooks: Tunnel,
    app: Tunnel,
    code: Tunnel,
    root: PathBuf,
    /// The dummy setup-token the green world sealed (built at run time).
    token: String,
    /// The fixture's one commit.
    head: String,
    _tmp: tempfile::TempDir,
}

impl DockerRig {
    /// The rig on `--network none`, `docker_args` added to its `docker run`.
    fn new(docker_args: &[&str], flags: &[&str]) -> DockerRig {
        DockerRig::build(None, docker_args, flags)
    }

    /// The rig for a session's claude, with a route to the egress proxy's
    /// address alone: an internal network on the proxy's `/24` (no gateway
    /// route, so a packet for anywhere else has no route), the container at
    /// the proxy's own address (`egress::PROXY_IP`, what the session's proxy
    /// variables name), and on its port the [`DECOY`] proxy. A request the CLI
    /// sends through the proxy stays inside the container and is logged
    /// ([`DockerRig::decoy_requests`]); a packet that leaves it crosses
    /// `eth0` ([`DockerRig::tx_packets`]).
    fn behind_a_decoy_proxy() -> DockerRig {
        use ai_env_cli::bridge::egress::{PROXY_IP, PROXY_PORT};
        let (net, last) = PROXY_IP.rsplit_once('.').expect("an IPv4 proxy address");
        let gateway = if last == "1" { format!("{net}.2") } else { format!("{net}.1") };
        let network = Network::internal(&format!("{net}.0/24"), &gateway);
        let rig = DockerRig::build(Some(network), &["--ip", PROXY_IP], &[]);
        let port = PROXY_PORT.to_string();
        let started = docker(&["exec", "-d", "-u", "0", &rig.c.id, "gawk", "-v", &format!("out={DECOY_LOG}"), "-v", &format!("port={port}"), DECOY]);
        assert!(started.status.success(), "the decoy proxy: {}", text(&started.stderr));
        // Listening: its LISTEN row (state 0A) on the port, in hex, in /proc/net/tcp.
        let row = format!(":{:04X} 00000000:0000 0A", PROXY_PORT);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !rig.c.sh("cat /proc/net/tcp").contains(&row) {
            assert!(Instant::now() < deadline, "the decoy proxy is not listening on {port}");
            std::thread::sleep(Duration::from_millis(100));
        }
        rig
    }

    fn build(net: Option<Network>, docker_args: &[&str], flags: &[&str]) -> DockerRig {
        use ai_env_cli::wire::workspace::{APP_PORT, CODE_PORT};
        require_enabled();
        let image = local_image();
        assert!(docker(&["image", "inspect", &image]).status.success(), "{image} is missing: run make image-build-local");
        let tmp = tempfile::Builder::new().prefix("ai-env-s8-").tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("a tempdir under CARGO_TARGET_TMPDIR");
        let root = std::fs::canonicalize(tmp.path()).expect("the tempdir's canonical path");
        assert!(root.starts_with(AGENT_HOME), "the identical path needs the workspace under the image's {AGENT_HOME}: {} (CARGO_TARGET_TMPDIR) is not", root.display());
        for d in ["bridge", "keys", "bin", "work"] {
            std::fs::create_dir_all(root.join(d)).expect("the rig's directories");
        }
        let head = fixture_repo(&root.join("work"));
        let fake = root.join("fake.json");
        std::fs::write(&fake, serde_json::to_string_pretty(&FakeState { auto_advance: true, ..FakeState::new() }).expect("the fake's state")).expect("write fake.json");
        let c = Container::offline(&image, net.as_ref().map_or("none", |n| n.name.as_str()), docker_args, flags);
        let (hooks, app, code) = (Tunnel::open(&c.id, HOOKS_PORT), Tunnel::open(&c.id, APP_PORT), Tunnel::open(&c.id, CODE_PORT));
        ready_through(&c, hooks.addr, 120);
        let endpoint = FakeEndpoint::start_routed(&fake, &[(APP_PORT, app.addr), (CODE_PORT, code.addr)], Some(hooks.addr));
        let rig = DockerRig { endpoint, c, net, hooks, app, code, root, token: green_world::setup_token("Dk"), head, _tmp: tmp };
        let roots = [rig.work()];
        green_world::Green { root: &rig.root, fake: &fake, roots: &roots }.seed(&rig.token, IMAGE_VERSION, true, &|args| rig.ai_env(args));
        // An S8 image's VM: its `/health` also names the workspace routes' capability.
        rig.update_fake(|s| s.health_caps.push(ai_env_cli::wire::frame::CAP_WORKSPACE_V1.to_string()));
        rig
    }

    /// The Mac's workspace: the fixture repository, the wrapper's cwd.
    fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    /// The workspace's VM path (`wire::workspace::vm_path_of`): its Mac path, the identical path.
    fn vm_dir(&self) -> String {
        ai_env_cli::wire::workspace::vm_path_of(&self.work()).unwrap_or_else(|e| panic!("the workspace's VM path: {e}"))
    }

    fn update_fake(&self, f: impl FnOnce(&mut FakeState)) {
        FileFakeMicrovmApi::open(&self.root.join("fake.json"))
            .and_then(|api| {
                api.with(|s| {
                    f(s);
                    Ok(())
                })
            })
            .expect("update the fake's state");
    }

    /// What every `ai-env` and `ai-env-claude` of the rig gets: `HOME` the
    /// root, `PATH` the fake age first, then `/usr/bin:/bin`; the bridge and
    /// key dirs, no AWS profile, the fake API (its runtime key unsealed with
    /// the fake age), the agent address at the endpoint and the fake age's
    /// log; a developer's AWS, ai-env, claude, fake and git variables removed
    /// first. No backoff knob: the commands keep their real timers across the tunnels.
    fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().into_owned();
            if ["AWS_", "AI_ENV_", "PULUMI_", "CLAUDE_", "FAKE_", "GIT_"].iter().any(|p| k.starts_with(p)) || k == "RUST_LOG" {
                cmd.env_remove(&k);
            }
        }
        cmd.env("HOME", &self.root)
            .env("PATH", format!("{}:/usr/bin:/bin", self.root.join("bin").display()))
            .env("AI_ENV_BRIDGE_DIR", self.root.join("bridge"))
            .env("AI_ENV_DIR", self.root.join("keys"))
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AI_ENV_BRIDGE_LAB_FAKE_API", self.root.join("fake.json"))
            .env("AI_ENV_BRIDGE_LAB_FAKE_API_UNSEAL", "1")
            .env("AI_ENV_BRIDGE_LAB_AGENT_ADDR", self.endpoint.addr.to_string())
            .env("FAKE_AGE_LOG", self.root.join("age.log"))
            .stdin(Stdio::null());
        cmd
    }

    /// `ai-env <args>` of the rig (the hidden paste read from stdin).
    fn ai_env(&self, args: &[&str]) -> Command {
        let mut cmd = self.command(env!("CARGO_BIN_EXE_ai-env"));
        cmd.args(args).env("AI_ENV_PASTE_STDIN", "1");
        cmd
    }

    /// `ai-env <args>` to its end, bounded.
    fn run(&self, args: &[&str]) -> Output {
        bounded(self.ai_env(args))
    }

    /// `vm run --egress vpc --workspace <work> --json`: the workspace's VM,
    /// run on the container at its first request through the endpoint; its id.
    fn start_vm(&self) -> String {
        let work = self.work().display().to_string();
        let mut cmd = self.ai_env(&["vm", "run", "--egress", "vpc", "--workspace", &work, "--json"]);
        cmd.env("AI_ENV_BRIDGE_LAB_BACKOFF_MS", "1");
        let o = bounded(cmd);
        assert!(o.status.success(), "vm run: {}", text(&o.stderr));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("vm run --json ({e}): {}", text(&o.stdout)));
        v["id"].as_str().unwrap_or_else(|| panic!("no id in {v}")).to_string()
    }

    /// `ai-env box <args> --json` (one Touch ID): its JSON, after a clean exit.
    fn box_json(&self, args: &[&str]) -> serde_json::Value {
        let mut all = vec!["box"];
        all.extend_from_slice(args);
        all.push("--json");
        let o = self.run(&all);
        assert!(o.status.success(), "box {args:?}: {}\n{}", text(&o.stderr), self.c.logs());
        serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("box {args:?} --json ({e}): {}", text(&o.stdout)))
    }

    /// Cursor's chat spawn of the wrapper in remote mode: `ai-env-claude
    /// <a path no claude is at> SESSION_ARGV` in the workspace. The remote
    /// route needs no claude on the Mac, and none ever runs there.
    fn wrapper(&self) -> Command {
        let mut cmd = self.command(env!("CARGO_BIN_EXE_ai-env-claude"));
        cmd.arg(self.root.join("no-claude-here")).args(SESSION_ARGV).current_dir(self.work()).env("AI_ENV_BRIDGE_MODE", "remote");
        cmd
    }

    /// Decrypts (Touch IDs) the fake age served so far.
    fn decrypts(&self) -> usize {
        green_world::decrypts(&self.root.join("age.log"))
    }

    fn audit(&self, event: &str) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(self.root.join("bridge").join("audit.jsonl")).unwrap_or_default();
        text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).collect()
    }

    /// The census end row's note (exactly one row has `end`).
    fn end_note(&self) -> String {
        let text = std::fs::read_to_string(self.root.join("bridge").join("logs").join("census.jsonl")).unwrap_or_default();
        let ends: Vec<serde_json::Value> = text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r.get("end").is_some()).collect();
        assert_eq!(ends.len(), 1, "one census end row: {text}");
        ends[0]["note"].as_str().unwrap_or_default().to_string()
    }

    /// The connections the tunnels made inside the container so far.
    fn tunnel_connects(&self) -> u64 {
        u64::from(self.hooks.connects() + self.app.connects() + self.code.connects())
    }

    /// The request lines the decoy proxy got so far, one per connection it took.
    fn decoy_requests(&self) -> Vec<String> {
        self.c.sh(&format!("cat {DECOY_LOG} 2>/dev/null; true")).lines().map(str::to_string).collect()
    }

    /// The packets the container sent on `eth0` (its one interface besides
    /// loopback) so far.
    fn tx_packets(&self) -> u64 {
        let dev = self.c.sh("cat /proc/net/dev");
        let counters = dev.lines().find_map(|l| l.trim_start().strip_prefix("eth0:")).unwrap_or_else(|| panic!("no eth0 in /proc/net/dev:\n{dev}"));
        // Received: bytes, packets and six more; then transmitted: bytes, packets.
        counters.split_whitespace().nth(9).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("eth0's transmitted packets: {counters}"))
    }

    /// [`DockerRig::tx_packets`] once it held still for 1.5 s (at most 15 s):
    /// Docker announces a container's address on its network with gratuitous
    /// ARP, a frame a second for its first seconds, and nothing after.
    fn settled_tx_packets(&self) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(15);
        let (mut last, mut since) = (self.tx_packets(), Instant::now());
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let now = self.tx_packets();
            if now != last {
                (last, since) = (now, Instant::now());
            } else if since.elapsed() >= Duration::from_millis(1500) {
                return now;
            }
            assert!(Instant::now() < deadline, "eth0 never held still: {now} packets sent");
        }
    }

    /// The neighbours the container resolved (`/proc/net/arp` past its header):
    /// a packet for another host on its network needs one.
    fn neighbours(&self) -> Vec<String> {
        self.c.sh("cat /proc/net/arp").lines().skip(1).map(str::to_string).collect()
    }

    /// The container's own counters over its whole life: nothing in it
    /// tried an address it has no route to, sent a datagram (no name was
    /// looked up) or an echo, IPv4 or IPv6. Every connection made in it (its
    /// opens less those refused: a tunnel's before the shim listened, one
    /// that came while the decoy had no listener) was taken by a listener in
    /// it, or reset at the decoy's closing listener. On `--network none` each
    /// was taken, and each was a tunnel's. Behind the decoy the listeners
    /// took at least the tunnels' and the decoy's logged ones (one that came
    /// while the decoy was busy may have been taken by its listener and reset
    /// unlogged), and a connection may have gone untaken: gawk closes the
    /// decoy's listener once it took one, so one whose handshake was still
    /// under way is reset with no listener to take it, its client having seen
    /// it established. No more went untaken than established connections
    /// were reset (`Tcp:EstabResets`). A connection a tunnel has in flight is
    /// waited for, a few seconds at most. The counters, for the record.
    fn assert_no_way_out(&self) -> Vec<(&'static str, u64)> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let net = self.c.net_counters();
            let counter = |name: &str| net.get(name).copied().unwrap_or_else(|| panic!("no {name} among the container's counters: {:?}", net.keys().collect::<Vec<_>>()));
            let out: Vec<(&'static str, u64)> = ["Ip:OutNoRoutes", "Ip6OutNoRoutes", "Udp:OutDatagrams", "Udp6OutDatagrams", "Icmp:OutEchos", "Icmp6OutEchos"].into_iter().map(|k| (k, counter(k))).collect();
            assert!(out.iter().all(|(_, n)| *n == 0), "something in the container tried a way out: {out:?}");
            let (opens, refused, taken, resets) = (counter("Tcp:ActiveOpens"), counter("Tcp:AttemptFails"), counter("Tcp:PassiveOpens"), counter("Tcp:EstabResets"));
            let (made, tunnels, decoy) = (opens.saturating_sub(refused), self.tunnel_connects(), self.decoy_requests().len() as u64);
            // Behind the decoy one reset at its closing listener was taken by none; its client saw it established, so it is among the resets.
            let untaken = if self.net.is_some() { resets } else { 0 };
            let accounted = taken <= made && made - taken <= untaken;
            let ours = if self.net.is_some() { taken >= tunnels + decoy } else { made == tunnels };
            if (accounted && ours) || Instant::now() >= deadline {
                if self.net.is_some() {
                    assert!(accounted, "every connection made in the container was taken by a listener in it, or reset at the decoy's closing listener ({opens} opens, {refused} refused, {taken} taken, {resets} reset)");
                    assert!(taken >= tunnels + decoy, "{taken} connections taken, fewer than the tunnels' {tunnels} and the decoy's {decoy}");
                } else {
                    assert_eq!(made, taken, "every connection made in the container was taken by a listener in it ({opens} opens, {refused} refused)");
                    assert_eq!(made, tunnels, "every connection made in the container is a tunnel's");
                }
                return out.into_iter().chain([("Tcp:ActiveOpens", opens), ("Tcp:AttemptFails", refused), ("Tcp:PassiveOpens", taken), ("Tcp:EstabResets", resets), ("tunnels", tunnels), ("decoy", decoy)]).collect();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The real `ai-env-claude` as Cursor runs it: stdin piped, each stdout
/// line taken as it comes, stderr kept as it comes; killed on drop if it
/// still runs.
struct Session {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: std::sync::mpsc::Receiver<String>,
    seen: Vec<String>,
    err: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Session {
    fn start(mut cmd: Command) -> Session {
        use std::io::BufRead as _;
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env-claude");
        let stdin = child.stdin.take();
        let (out, mut stderr) = (child.stdout.take().expect("piped stdout"), child.stderr.take().expect("piped stderr"));
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let err = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = err.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                kept.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Session { child, stdin, lines, seen: Vec::new(), err }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        stdin.write_all(line.as_bytes()).and_then(|()| stdin.write_all(b"\n")).and_then(|()| stdin.flush()).unwrap_or_else(|e| panic!("write to the wrapper: {e}"));
    }

    /// The first stdout line that parses as JSON and satisfies `pred`, seen
    /// before or within `limit`; panics naming `what` with what came.
    fn expect(&mut self, what: &str, limit: Duration, pred: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let deadline = Instant::now() + limit;
        let mut at = 0;
        loop {
            while at < self.seen.len() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&self.seen[at]) {
                    if pred(&v) {
                        return v;
                    }
                }
                at += 1;
            }
            match self.lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line) => self.seen.push(line),
                Err(_) => panic!("{what}: not within {limit:?}\n--- stdout: {:?}\n--- stderr:\n{}", self.seen, self.err_text()),
            }
        }
    }

    /// Close stdin (the extension's `stdin.end()`): when.
    fn close_stdin(&mut self) -> Instant {
        self.stdin = None;
        Instant::now()
    }

    /// The exit within `limit` (killed and failed past it), and when it was seen.
    fn wait(&mut self, limit: Duration) -> (std::process::ExitStatus, Instant) {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return (status, Instant::now());
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("the wrapper did not exit within {limit:?}\n{}", self.err_text());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Every stdout line so far (what already came taken).
    fn out_lines(&mut self) -> Vec<String> {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.clone()
    }

    fn err_text(&self) -> String {
        String::from_utf8_lossy(&self.err.lock().unwrap()).into_owned()
    }
}

/// T8.1 on the real image (plan Part A, wave 2: W6): `ai-env box seed`
/// through the endpoint and the code tunnel clones the Mac's dirty
/// workspace into the container at the identical path, as the agent. The
/// test made nothing in the container: the image's `/Users/mike` is all
/// there was, and the helper made each directory down to the workspace
/// (0700, the agent's). Afterwards nothing under the agent's home is
/// anyone's but the agent's (1000:1000: no root-owned path); the VM's HEAD
/// is the Mac's, shallow at it, with no origin, and the Mac's edit, staged
/// file and untracked file are uncommitted there, the same bytes. The
/// shim's helper answered GET and PUT `/seed` (200, 201).
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_seed_clones_as_the_agent_at_the_identical_path() {
    let rig = DockerRig::new(&[], &[]);
    let work = rig.work();
    dirty_the_mac(&work);
    let vm = rig.vm_dir();
    assert_eq!(vm, work.display().to_string(), "the VM path is the Mac's own");
    let below: Vec<String> = Path::new(&vm).strip_prefix(AGENT_HOME).expect("under the agent's home").iter().map(|c| c.to_string_lossy().into_owned()).collect();
    let first = format!("{AGENT_HOME}/{}", below[0]);
    assert_eq!(rig.c.sh(&format!("test -e '{first}' && echo there || echo absent")), "absent", "the test made nothing in the container");
    let before = rig.c.sh(HOME_TREE);
    let id = rig.start_vm();
    let seeded = rig.box_json(&["seed", &vm]);
    assert_eq!((seeded["outcome"].as_str(), seeded["vm"].as_str(), seeded["detail"]["head"].as_str()), (Some("seeded"), Some(id.as_str()), Some(rig.head.as_str())), "{seeded}");
    assert!(seeded["detail"]["wip"].is_string(), "the uncommitted work went with the seed: {seeded}");
    // Ownership: every path under the home is the agent's; the walk made each directory down to the workspace 0700.
    let after = rig.c.sh(HOME_TREE);
    let not_agents: Vec<&str> = after.lines().filter(|l| l.split(' ').nth(1) != Some("1000:1000")).collect();
    assert!(not_agents.is_empty(), "paths under {AGENT_HOME} that are not the agent's: {not_agents:#?}");
    let known: std::collections::BTreeSet<&str> = before.lines().filter_map(|l| l.split(' ').nth(2)).collect();
    let created: Vec<&str> = after.lines().filter(|l| l.split(' ').nth(2).is_some_and(|p| !known.contains(p))).collect();
    let mut dir = AGENT_HOME.to_string();
    for name in &below {
        dir = format!("{dir}/{name}");
        assert!(created.contains(&format!("700 1000:1000 {dir}").as_str()), "{dir} made 0700 by the agent: {created:#?}");
    }
    // The clone: HEAD the Mac's, shallow at it, no origin, the Mac's uncommitted work uncommitted here.
    assert_eq!(rig.c.agent_git(&vm, &["rev-parse", "HEAD"]), rig.head, "the VM's HEAD is the Mac's");
    assert_eq!(rig.c.agent_git(&vm, &["remote"]), "", "no origin in the VM");
    assert_eq!(rig.c.agent_sh(&format!("cat '{vm}/.git/shallow'")), rig.head, "shallow at the seeded commit: no history crossed");
    let status = ["--no-optional-locks", "status", "--porcelain", "--untracked-files=all"];
    assert_eq!(rig.c.agent_git(&vm, &status), mac_git(&work, &status), "the Mac's uncommitted work is uncommitted in the VM");
    let kinds = (rig.c.agent_git(&vm, &["diff", "--name-only"]), rig.c.agent_git(&vm, &["diff", "--cached", "--name-only"]), rig.c.agent_git(&vm, &["ls-files", "--others", "--exclude-standard"]));
    assert_eq!(kinds, ("README.md".to_string(), "staged.txt".to_string(), "notes.txt".to_string()), "an edit, a staged file, an untracked one");
    for file in ["README.md", "staged.txt", "notes.txt"] {
        let mac = std::fs::read_to_string(work.join(file)).expect("the Mac's file");
        assert_eq!(rig.c.agent_sh(&format!("cat '{vm}/{file}'")), mac.trim_end(), "{file}");
    }
    let logs = rig.c.logs();
    for line in ["ai-env: workspace seed-state status=200 ", "ai-env: workspace seed-apply status=201 "] {
        assert!(logs.lines().any(|l| l.starts_with(line)), "{line}…:\n{logs}");
    }
    let counters = rig.assert_no_way_out();
    eprintln!("L2 seed: {} paths made under {AGENT_HOME}, all the agent's; container counters {counters:?}", created.len());
}

/// L6 on the real image: the platform's `/suspend` (posted through the
/// hooks tunnel, as root from inside: the guard admits it as the platform)
/// snapshots a seeded workspace's uncommitted work as the agent. The edit
/// and the new file the agent left are in a new `refs/wip/*` commit by
/// `ai-env snapshot`, on the seeded head; the agent's checkout and index
/// are as it left them; every path under its home is still its own.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_wip_snapshot_on_suspend_is_made_by_the_agent() {
    let rig = DockerRig::new(&[], &[]);
    let vm = rig.vm_dir();
    rig.start_vm();
    assert_eq!(rig.box_json(&["seed", &vm])["outcome"].as_str(), Some("seeded"));
    rig.c.agent_sh(&format!("printf 'edited in the VM\\n' > '{vm}/README.md' && printf 'new in the VM\\n' > '{vm}/late.txt'"));
    let status = ["--no-optional-locks", "status", "--porcelain", "--untracked-files=all"];
    let (checkout, index) = (rig.c.agent_git(&vm, &status), rig.c.agent_git(&vm, &["ls-files", "--stage"]));
    assert_eq!(checkout, "M README.md\n?? late.txt", "an edit and a new file, uncommitted");
    let (s, body) = http(rig.hooks.addr, "POST", &format!("{PREFIX}/suspend"), "{}");
    assert_eq!(s, 200, "{body}\n{}", rig.c.logs());
    let logs = rig.c.wait_for(15, "the wip_snapshot line", |l| l.lines().any(|l| l.starts_with("ai-env: wip_snapshot ")));
    let line = logs.lines().find(|l| l.starts_with("ai-env: wip_snapshot ")).unwrap_or_default();
    let name = line.strip_prefix("ai-env: wip_snapshot ref=").and_then(|r| r.split(' ').next()).unwrap_or_else(|| panic!("a snapshot made: {line}"));
    assert_eq!(rig.c.agent_git(&vm, &["for-each-ref", "--format=%(refname)", "refs/wip/"]), name, "the one snapshot, named in the log");
    assert_eq!(rig.c.agent_git(&vm, &["show", &format!("{name}:README.md")]), "edited in the VM");
    assert_eq!(rig.c.agent_git(&vm, &["show", &format!("{name}:late.txt")]), "new in the VM");
    assert_eq!(rig.c.agent_git(&vm, &["log", "-1", "--format=%an <%ae>", name]), "ai-env snapshot <snapshot@ai-env.invalid>");
    assert_eq!(rig.c.agent_git(&vm, &["rev-parse", &format!("{name}^")]), rig.head, "on the seeded head");
    assert_eq!((rig.c.agent_git(&vm, &status), rig.c.agent_git(&vm, &["ls-files", "--stage"])), (checkout, index), "the agent's checkout and index as it left them");
    let not_agents = rig.c.not_the_agents();
    assert!(not_agents.is_empty(), "paths under {AGENT_HOME} that are not the agent's after the snapshot: {not_agents:#?}");
}

/// T8.6 on the real image: the agent planted a symlink at the workspace
/// path's first component under its home (to a directory of its own in
/// /tmp) before any seed. `box seed` reaches the VM and is refused there:
/// the helper's walk meets the link (409 `symlink_component`, the exit 9
/// and its line naming the VM path), nothing went through the link, and
/// nothing under the agent's home changed.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_seed_into_an_agent_planted_symlink_is_409() {
    use ai_env_cli::wire::workspace::CODE_PORT;
    let rig = DockerRig::new(&[], &[]);
    let vm = rig.vm_dir();
    let first = Path::new(&vm).strip_prefix(AGENT_HOME).ok().and_then(|r| r.iter().next()).expect("a component under the home").to_string_lossy().into_owned();
    let link = format!("{AGENT_HOME}/{first}");
    rig.c.agent_sh(&format!("mkdir /tmp/ai-env-s8-elsewhere && ln -s /tmp/ai-env-s8-elsewhere '{link}'"));
    let before = rig.c.sh(HOME_TREE);
    rig.start_vm();
    let o = rig.run(&["box", "seed", &vm, "--json"]);
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(9), "{err}");
    assert!(err.contains("symlink") && err.contains(&link), "the line names the planted component: {err}");
    let code: Vec<(String, u16)> = rig.endpoint.attempts().iter().filter(|a| a.port == CODE_PORT).map(|a| (a.path.clone(), a.status)).collect();
    assert!(code.iter().any(|(path, status)| path.starts_with("/seed") && *status == 409), "the VM refused: {code:?}");
    assert!(!code.iter().any(|(_, status)| *status == 201), "no seed went in: {code:?}");
    let logs = rig.c.logs();
    assert!(logs.lines().any(|l| l.starts_with("ai-env: workspace ") && l.contains(" status=409 code=symlink_component ")), "{logs}");
    assert_eq!(rig.c.sh("ls -A /tmp/ai-env-s8-elsewhere"), "", "nothing went through the link");
    assert_eq!(rig.c.sh(&format!("readlink '{link}'")), "/tmp/ai-env-s8-elsewhere", "the link is as the agent left it");
    assert_eq!(rig.c.sh(HOME_TREE), before, "nothing under the agent's home changed");
}

/// D7's code-out on the real image: after a seed the agent commits in the
/// VM (as claude does, the image's git and its system identity) and edits
/// on without committing. `box fetch --wip` brings the commit into
/// `refs/remotes/box/main`, on the seeded head, and the edit into exactly
/// one `box/wip/*` snapshot on the commit, through the code tunnel; the
/// Mac's branches, index, worktree and stash are untouched, and so is the
/// agent's checkout in the VM, every path there its own.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_codeout_round_trip() {
    let rig = DockerRig::new(&[], &[]);
    let work = rig.work();
    let vm = rig.vm_dir();
    let id = rig.start_vm();
    assert_eq!(rig.box_json(&["seed", &vm])["outcome"].as_str(), Some("seeded"));
    rig.c.agent_sh(&format!("printf 'from the VM\\n' > '{vm}/agent.txt'"));
    rig.c.agent_git(&vm, &["add", "-A"]);
    rig.c.agent_git(&vm, &["commit", "-q", "-m", "the agent's commit"]);
    let vm_commit = rig.c.agent_git(&vm, &["rev-parse", "HEAD"]);
    rig.c.agent_sh(&format!("printf 'from the VM, not committed yet\\n' > '{vm}/agent.txt'"));
    let mac = mac_view(&work);
    let fetched = rig.box_json(&["fetch", &vm, "--wip"]);
    let report = &fetched["report"];
    assert_eq!((fetched["vm"].as_str(), report["ok"].as_bool()), (Some(id.as_str()), Some(true)), "{fetched}");
    let promoted = report["promoted"].as_object().unwrap_or_else(|| panic!("promoted refs: {fetched}"));
    assert_eq!(promoted.get("refs/remotes/box/main").and_then(serde_json::Value::as_str), Some(vm_commit.as_str()), "{fetched}");
    let wips: Vec<&String> = promoted.keys().filter(|r| r.starts_with("refs/remotes/box/wip/")).collect();
    assert_eq!(wips.len(), 1, "one snapshot of the uncommitted edit: {fetched}");
    let wip = wips[0];
    assert_eq!((mac_git(&work, &["rev-parse", "refs/remotes/box/main"]), mac_git(&work, &["rev-parse", "refs/remotes/box/main^"])), (vm_commit.clone(), rig.head.clone()), "the agent's commit on the seeded head");
    assert_eq!(mac_git(&work, &["show", "refs/remotes/box/main:agent.txt"]), "from the VM");
    assert_eq!((mac_git(&work, &["rev-parse", &format!("{wip}^")]), mac_git(&work, &["show", &format!("{wip}:agent.txt")])), (vm_commit, "from the VM, not committed yet".to_string()), "the snapshot holds the edit, on the commit");
    assert_eq!(mac_view(&work), mac, "the Mac's branches, index, worktree and stash untouched");
    assert_eq!(rig.c.agent_git(&vm, &["--no-optional-locks", "status", "--porcelain"]), "M agent.txt", "the agent's edit is still uncommitted in the VM");
    let not_agents = rig.c.not_the_agents();
    assert!(not_agents.is_empty(), "paths under {AGENT_HOME} that are not the agent's after the code-out: {not_agents:#?}");
    rig.assert_no_way_out();
}

/// The shim's git children in the real image: its `--git` is the phase-0
/// fake git (mounted read-only; a logging passthrough to the image's git),
/// whose knobs file also logs every name a call inherited (the fake logs
/// git's own), and the shim's own environment carries two canaries. While
/// a credentialed spawn lives (`vm exec --with-credential`: the shim holds
/// the dummy token, the spawn read it on fd 3), a dirty seed, the agent's
/// commit and a `box fetch --wip` (its snapshot and its pack) run every git
/// of the helper's ops. Each git call started with no descriptor past
/// stderr (never the token's fd 3), and with only GitRun's VM environment:
/// `HOME`, `PATH`, `LC_ALL` and git's own names (the config, prompt and
/// lock rules, an index copy, the snapshot's identity), no canary; none of
/// them clones, fetches, pushes or names a remote.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_the_shim_git_child_env_is_clean_and_has_no_fd_3() {
    use std::os::unix::fs::PermissionsExt as _;
    let fake = tempfile::tempdir().expect("a tempdir for the fake git");
    std::fs::copy(FAKE_GIT, fake.path().join("git")).expect("copy the fake git");
    std::fs::set_permissions(fake.path().join("git"), std::fs::Permissions::from_mode(0o755)).expect("chmod the fake git");
    let knobs = "env | sed -n 's/=.*//p' | LC_ALL=C sort | tr '\\n' ' ' >> /tmp/ai-env-s8-git-env.log; echo >> /tmp/ai-env-s8-git-env.log\n\
                 export GIT_REAL='/usr/bin/git'\nexport GIT_ARGV_LOG='/tmp/ai-env-s8-git.log'\n";
    std::fs::write(fake.path().join("git.knobs"), knobs).expect("write the fake git's knobs");
    std::fs::set_permissions(fake.path(), std::fs::Permissions::from_mode(0o755)).expect("chmod the fake's directory");
    let mount = format!("{}:/opt/fakegit:ro", fake.path().display());
    let rig = DockerRig::new(&["-v", &mount, "-e", "GIT_AI_ENV_CANARY=1", "-e", "AI_ENV_CANARY=1"], &["--git", "/opt/fakegit/git"]);
    let work = rig.work();
    let vm = rig.vm_dir();
    dirty_the_mac(&work);
    let id = rig.start_vm();
    // The holder: a credentialed spawn living through the helper's runs.
    let mut holder = Session::start(rig.ai_env(&["vm", "exec", &id, "--with-credential", "--", "sh", "-c", "cat <&3 >/dev/null; sleep 120"]));
    let logs = rig.c.wait_for(60, "the credentialed spawn", |l| spawns(l).iter().any(|(_, argv0, _, secret)| argv0 == "sh" && secret == "fd3"));
    assert!(!logs.contains(&rig.token[13..]), "the token reached the container's log");
    assert_eq!(rig.box_json(&["seed", &vm])["outcome"].as_str(), Some("seeded"));
    rig.c.agent_sh(&format!("printf 'from the VM\\n' > '{vm}/agent.txt'"));
    rig.c.agent_git(&vm, &["add", "-A"]);
    rig.c.agent_git(&vm, &["commit", "-q", "-m", "the agent's commit"]);
    rig.c.agent_sh(&format!("printf 'from the VM, not committed yet\\n' > '{vm}/agent.txt'"));
    assert_eq!(rig.box_json(&["fetch", &vm, "--wip"])["report"]["ok"].as_bool(), Some(true));
    assert!(matches!(holder.child.try_wait(), Ok(None)), "the holder lived through the helper's runs:\n{}", holder.err_text());
    // The calls: (git's own names, the descriptors from 3, the arguments).
    let calls: Vec<(Vec<String>, String, Vec<String>)> = rig
        .c
        .sh("cat /tmp/ai-env-s8-git.log")
        .lines()
        .map(|l| {
            let mut fields = l.split('\t');
            let names = fields.next().and_then(|f| f.strip_prefix("env=")).unwrap_or_else(|| panic!("an env field: {l:?}"));
            let fds = fields.next().and_then(|f| f.strip_prefix("fds=")).unwrap_or_else(|| panic!("an fds field: {l:?}")).to_string();
            let names = if names == "-" { Vec::new() } else { names.split(',').map(str::to_string).collect() };
            (names, fds, fields.map(str::to_string).collect())
        })
        .collect();
    let subs: std::collections::BTreeSet<&str> = calls.iter().filter_map(|(_, _, args)| args.iter().skip_while(|a| *a == "-c" || a.contains('=')).find(|a| !a.starts_with('-')).map(String::as_str)).collect();
    for sub in ["init", "index-pack", "update-ref", "reset", "read-tree", "commit-tree", "pack-objects"] {
        assert!(subs.contains(sub), "the helper's {sub} ran through the shim's --git: {subs:?}");
    }
    let git_names = ["GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS", "GIT_INDEX_FILE", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"];
    for (names, fds, args) in &calls {
        assert_eq!(fds, "-", "a git started with a descriptor past stderr: {args:?}");
        assert!(names.iter().all(|n| git_names.contains(&n.as_str())), "git names beyond GitRun's: {names:?} in {args:?}");
        for must in ["GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS"] {
            assert!(names.iter().any(|n| n == must), "{must} missing: {names:?} in {args:?}");
        }
        assert!(!args.iter().any(|a| ["clone", "fetch", "push", "remote", "ls-remote"].contains(&a.as_str()) || a.contains("://")), "no git reaches a remote: {args:?}");
    }
    let shell = ["PWD", "SHLVL", "_", "OLDPWD"];
    let inherited: Vec<String> = rig.c.sh("cat /tmp/ai-env-s8-git-env.log").lines().map(str::to_string).collect();
    assert_eq!(inherited.len(), calls.len(), "one name list per call");
    for names in &inherited {
        let names: Vec<&str> = names.split_whitespace().collect();
        assert!(names.iter().all(|n| ["HOME", "PATH", "LC_ALL"].contains(n) || git_names.contains(n) || shell.contains(n)), "a git inherited more than GitRun's VM environment: {names:?}");
        assert!(["HOME", "PATH", "LC_ALL"].iter().all(|n| names.contains(n)), "{names:?}");
    }
    eprintln!("L2 git children: {} calls, {} subcommands, each with fds 0-2 and GitRun's environment alone", calls.len(), subs.len());
}

/// W3's open point 6: the image's git is 2.29 or later, the features the
/// helper's seed takes (`init --initial-branch` 2.28, `--object-format`
/// 2.29, `update-ref --stdin` transactions 2.27, `add
/// --pathspec-from-file` 2.25), and it runs those commands, with GitRun's
/// overrides, as the agent in a container of the image with no shim, no
/// claude and no network: a clone made as the helper makes it, then a thin
/// pack of a second commit indexed into it with `--fix-thin` and checked
/// out two-way. The image's system config turns automatic maintenance off
/// (`maintenance.auto false`, W6's finding 2): no commit of the agent's
/// starts a background `gc --auto` that a helper's object write could meet.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_the_images_git_is_2_29_or_later_and_runs_the_helpers_commands() {
    require_enabled();
    let image = local_image();
    assert!(docker(&["image", "inspect", &image]).status.success(), "{image} is missing: run make image-build-local");
    let overrides: String = ai_env_cli::gitrun::OVERRIDES.iter().map(|o| format!(" -c {o}")).collect();
    let script = format!(
        "set -eu; git --version; printf 'maintenance.auto=%s\\n' \"$(git config --system --get maintenance.auto || echo unset)\"; \
         g() {{ git{overrides} \"$@\"; }}; d=$(mktemp -d); cd \"$d\"; \
         g init --quiet --template= --initial-branch=main --object-format=sha1 mac; cd mac; \
         printf 'one\\n' > f; printf 'f\\0' | g --literal-pathspecs add --pathspec-from-file=- --pathspec-file-nul; \
         c1=$(g commit-tree -m one \"$(g write-tree)\"); printf 'start\\ncreate refs/heads/main %s\\nprepare\\ncommit\\n' \"$c1\" | g update-ref --stdin >/dev/null; \
         printf 'two\\n' > f; g add f; c2=$(g commit-tree -p \"$c1\" -m two \"$(g write-tree)\"); \
         cd \"$d\"; g init --quiet --template= --initial-branch=main --object-format=sha1 vm; cd vm; \
         (cd ../mac && printf '%s\\n' \"$c1\" | g pack-objects --revs --stdout -q) | g index-pack --stdin >/dev/null; \
         printf 'start\\ncreate refs/heads/main %s\\nprepare\\ncommit\\n' \"$c1\" | g update-ref --stdin >/dev/null; g reset -q --hard; \
         (cd ../mac && printf '%s\\n^%s\\n' \"$c2\" \"$c1\" | g pack-objects --revs --thin --stdout -q) | g index-pack --stdin --fix-thin >/dev/null; \
         g read-tree -m -u \"$c1\" \"$c2\"; g update-ref refs/heads/main \"$c2\" \"$c1\"; test \"$(cat f)\" = two; \
         test -z \"$(g --no-optional-locks status --porcelain)\"; echo ok"
    );
    let c = Container { id: container_name_for("s8") };
    let out = docker(&["run", "--rm", "--name", &c.id, "--platform", "linux/arm64", "--network", "none", "-u", AGENT_UID, "-e", "HOME=/Users/mike", "--entrypoint", "/bin/sh", &image, "-c", &script]);
    let said = text(&out.stdout);
    assert!(out.status.success(), "{said}\n{}", text(&out.stderr));
    let lines: Vec<&str> = said.lines().collect();
    assert_eq!(lines.last().copied(), Some("ok"), "every command ran, the checkout clean: {said}");
    assert!(lines.contains(&"maintenance.auto=false"), "the image's system git config turns automatic maintenance off: {said}");
    let version = lines.first().and_then(|l| l.strip_prefix("git version ")).unwrap_or_else(|| panic!("a version line: {said}"));
    let parts: Vec<u32> = version.split(['.', ' ']).take(2).map(|p| p.parse().unwrap_or_else(|_| panic!("a version: {version}"))).collect();
    assert!(parts.as_slice() >= [2, 29].as_slice(), "the image's git {version} is older than 2.29");
    eprintln!("L2 image git: {version}");
}

/// S8 T8.2 on the real image (plan Part A, wave 2: W6): the real
/// `ai-env-claude` in remote mode on the Mac (its cwd the workspace under the
/// roots) starts a VM on the fake API, seeds it through the tunnels, delivers
/// the dummy setup-token and spawns the session on the container's shim,
/// whose `--claude` is the pinned claude. The extension's `initialize` is
/// answered by that claude, its pid rewritten to the wrapper's (the census
/// says `pid_rewrite:ok`, and names the VM's pid, the claude's version and
/// the seed); the CLI runs as the agent at the workspace's VM path with the
/// token on fd 3, its environment holding the wrapper's names (L4: the
/// telemetry, error reports, autoupdater and nonessential traffic off) and
/// no token. The host's EOF ends the session, exit 0, within the 1.5 s
/// budget; the CLI is gone, and the closing suspend reached the shim. One
/// Touch ID (D1).
///
/// No way out, and no model request: the container's one route is to the
/// egress proxy's address, its own here, where the decoy refuses every
/// request ([`DockerRig::behind_a_decoy_proxy`]). The session closes before
/// any turn. With the telemetry environment set, the CLI asked the proxy
/// for no host off its allowlist (`infra/proxy/allow.txt`: no third-party
/// telemetry host; claude 2.1.296 fetches its remote managed settings and
/// policy limits from api.anthropic.com at start, retrying each five times
/// when refused), sent nothing direct and looked no name up; what it asked
/// an allowlisted host for is not visible here (the decoy refuses the
/// CONNECT). No packet left the container during the session (past
/// Docker's own address announcements) and it resolved no neighbour, and
/// its own counters show that nothing in it, in its whole life (the claude,
/// the shim's probe of it, the seed's and the suspend's helpers), tried an
/// address with no route, looked a name up or sent an echo, and that a
/// listener in it (the shim's or the decoy's) took every connection made in
/// it, or the decoy's closing listener reset it.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_wrapper_remote_session_initializes_the_pinned_claude() {
    use ai_env_cli::bridge::remote::env::{NONESSENTIAL, WRAPPER_NAMES};
    use ai_env_cli::bridge::remote::CLOSE_BUDGET_MS;
    let rig = DockerRig::behind_a_decoy_proxy();
    let touch = rig.decrypts();
    let vm = rig.vm_dir();
    let tx = rig.settled_tx_packets();
    let mut s = Session::start(rig.wrapper());
    let asked = Instant::now();
    s.send(r#"{"request_id":"init0001","type":"control_request","request":{"subtype":"initialize","hooks":{},"jsonSchema":null}}"#);
    let answer = s.expect("the initialize answer", Duration::from_secs(90), |v| v["type"] == "control_response" && v["response"]["request_id"] == "init0001");
    let answered = asked.elapsed();
    assert_eq!(answer["response"]["subtype"].as_str(), Some("success"), "{answer}");
    assert_eq!(answer["response"]["response"]["pid"].as_u64(), Some(u64::from(s.pid())), "initialize is answered with the wrapper's pid");
    assert!(answer["response"]["response"]["commands"].is_array(), "the pinned claude's own answer: {answer}");
    // The CLI in the container: the shim's spawn line, its environment.
    let logs = rig.c.wait_for(10, "the claude's spawn line", |l| spawns(l).iter().any(|(_, argv0, _, _)| argv0 == "claude"));
    let line = logs.lines().find(|l| l.starts_with("ai-env: spawn ") && l.contains(" argv0=claude ")).unwrap_or_default().to_string();
    let field = |key: &str| line.split(' ').find_map(|f| f.strip_prefix(key)).unwrap_or_else(|| panic!("{key} in {line}")).trim_matches('"').to_string();
    let vm_pid: u32 = field("pid=").parse().unwrap_or_else(|e| panic!("{e}: {line}"));
    assert_eq!((field("cwd="), field("uid="), field("secret=")), (vm.clone(), AGENT_UID.to_string(), "fd3".to_string()), "the agent, at the workspace's VM path, the token on fd 3: {line}");
    assert_ne!(vm_pid, s.pid(), "the VM's CLI is another process");
    let environ = rig.c.privileged_sh(&format!("tr '\\0' '\\n' < /proc/{vm_pid}/environ"));
    let names: Vec<&str> = environ.lines().filter_map(|l| l.split_once('=').map(|(k, _)| k)).collect();
    for (k, v) in WRAPPER_NAMES.into_iter().chain([NONESSENTIAL, ("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "3")]) {
        assert!(environ.lines().any(|l| l == format!("{k}={v}")), "{k}={v} in the VM claude's environment: {names:?}");
    }
    assert!(!names.contains(&"CLAUDE_CODE_OAUTH_TOKEN") && !environ.contains(&rig.token[13..]), "the token is in the VM claude's environment: {names:?}");
    // The host's EOF: the CLI's own exit, then the wrapper's, within the budget.
    let eof = s.close_stdin();
    let (status, at) = s.wait(Duration::from_secs(30));
    let took = at.saturating_duration_since(eof);
    assert_eq!(status.code(), Some(0), "{}", s.err_text());
    assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "the host's EOF to the exit: {took:?} (budget {CLOSE_BUDGET_MS} ms)\n{}", s.err_text());
    let deadline = Instant::now() + Duration::from_secs(10);
    while rig.c.alive(vm_pid) {
        assert!(Instant::now() < deadline, "the VM's CLI {vm_pid} outlived the session:\n{}", rig.c.logs());
        std::thread::sleep(Duration::from_millis(100));
    }
    // No turn: no frame of one (an echo, a reply, a result, a stream event) came back.
    let frames: Vec<serde_json::Value> = s.out_lines().iter().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let kinds: Vec<&str> = frames.iter().map(|f| f["type"].as_str().unwrap_or_default()).collect();
    assert!(!kinds.iter().any(|k| matches!(*k, "user" | "assistant" | "result" | "stream_event")), "the session closed before any turn: {kinds:?}");
    // The census end row: the pid rewritten, the VM's own CLI, the seed, one Touch ID.
    let note = rig.end_note();
    let part = |name: &str| note_part(&note, name).unwrap_or_else(|| panic!("{name}: {note}"));
    let (vm_pid_text, claude) = (vm_pid.to_string(), lock_version());
    let words = ["pid_rewrite", "vm_pid", "claude", "vm_how", "seed", "credential"].map(part);
    assert_eq!(words, ["ok", vm_pid_text.as_str(), claude.as_str(), "started", "seeded", "combined"].map(str::to_string), "{note}");
    assert!(part("close_ms").parse::<u64>().is_ok_and(|ms| ms < CLOSE_BUDGET_MS), "{note}");
    assert_eq!((rig.audit("session_remote_start").len(), rig.audit("session_remote_end").len(), rig.audit("session_remote_failed").len()), (1, 1, 0));
    assert_eq!(rig.decrypts() - touch, 1, "one Touch ID for the process (D1)");
    // The closing suspend reached the shim (no other spawn lived).
    let deadline = Instant::now() + Duration::from_secs(20);
    while !rig.endpoint.hooks().iter().any(|k| k.name == "suspend" && k.status != 0) {
        assert!(Instant::now() < deadline, "no /suspend answered: {:?}", rig.endpoint.hooks());
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(rig.endpoint.hooks().iter().any(|k| k.name == "suspend" && k.status == 200), "{:?}", rig.endpoint.hooks());
    // The proxy was asked only for allowlisted hosts; nothing left the container; nothing in it tried a way out.
    let allow = std::fs::read_to_string(Path::new(REPO).join("infra/proxy/allow.txt")).expect("the egress allowlist");
    let allowed: Vec<&str> = allow.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let requests = rig.decoy_requests();
    assert!(!requests.is_empty(), "the CLI goes out through the egress proxy alone, and it did ask it");
    for r in &requests {
        let host = r.strip_prefix("CONNECT ").and_then(|t| t.strip_suffix(":443 HTTP/1.1")).unwrap_or_else(|| panic!("a request the egress proxy never takes: {r:?}"));
        assert!(allowed.contains(&host), "the CLI asked the egress proxy for {host}, off its allowlist {allowed:?}");
    }
    assert_eq!(rig.tx_packets(), tx, "a packet left the container during the session");
    assert_eq!(rig.neighbours(), Vec::<String>::new(), "something in the container tried to reach another host on its network");
    let counters = rig.assert_no_way_out();
    let logs = rig.c.logs();
    assert!(!logs.contains(&rig.token[13..]), "the token reached the container's log");
    let hosts: std::collections::BTreeSet<&str> = requests.iter().map(String::as_str).collect();
    eprintln!("L2 remote session: initialize answered in {answered:?}, EOF to exit {took:?}; proxy requests {} ({hosts:?}); {note}; container counters {counters:?}", requests.len());
}
