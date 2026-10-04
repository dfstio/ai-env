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
#[path = "common/fake_endpoint.rs"]
mod fake_endpoint;

use ai_env_cli::bridge::api::{FakeState, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::vm::fake_file::FileFakeMicrovmApi;
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
/// `log`), and one `vm_exec` audit row; the session token never reaches the
/// container's log.
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
    assert!(!w.c.logs().contains(&w.session_token()), "the session token reached the container's log");
}
