//! Opt-in Docker test of the real Mac client against the real image (plan S6
//! T6.7 offline), run by `make test-docker` after the shim-only suite
//! (`AI_ENV_DOCKER_TESTS=1`, every test `#[ignore]`d so `cargo test` never
//! needs Docker). With the variable set, a missing daemon or local image is a
//! FAILURE, never a skip. Every docker call and every process is bounded;
//! every container is named `ai-env-s6-…` and removed on drop.
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
#[path = "common/fake_endpoint.rs"]
mod fake_endpoint;

use ai_env_cli::bridge::api::{FakeState, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::config::Paths;
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
use ai_env_cli::bridge::vm::registry::VmRow;
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
    static N: AtomicU32 = AtomicU32::new(0);
    format!("ai-env-s6-{}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst), ai_env_cli::wire::time::unix_now_ms() % 1_000_000)
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
