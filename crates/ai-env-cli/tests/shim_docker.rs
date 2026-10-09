//! Opt-in Docker tests of the shim (S3 T3.1; S6 T6.2, T6.6, T6.7), run by
//! `make test-docker` (`AI_ENV_DOCKER_TESTS=1`, every test `#[ignore]`d so
//! `cargo test` never needs Docker). With the variable set, a missing daemon,
//! base image, shim binary or local image is a FAILURE, never a skip. Every
//! docker call is bounded; every container is named `ai-env-s6-…` and removed
//! on drop.
//!
//! L1: the digest-pinned AL2023 base image with the cross-built shim
//! (`image/ai-env`, from `make vm-build`) mounted as the ENTRYPOINT and a fake
//! `claude` — PID 1, hooks from the host and from inside, clock and entropy
//! reports, orphan reaping, a graceful `docker stop`, the probe's uid/gid. The
//! shipped ENTRYPOINT runs as is (peer mode; the agent guard as shipped: its
//! default `on`, the shim being root on Linux, or tree B's fallback `log`); a
//! test may replace one of its flags, and the agent guard's own tests set
//! `--agent-guard on`. Requests from the host arrive through Docker's port
//! publishing from outside the container's network namespace: the guard
//! finds no row of theirs and their address is not the container's, so it
//! admits them.
//! S6 agent L1 (`docker exec -u 0` stands for the platform, `-u 1000` for the
//! agent; the image's agent tree is seeded from image/): the hooks guard, the
//! side-port guard, a client on an AF_INET6 socket (its row is in tcp6), the
//! orphan rule (as root, so only the inode rule can refuse), the
//! close-before-lookup trick, an RST abort (refused `no_row`), also through
//! an address the container gains after boot;
//! through a raw wire v1 client of `/agent` (the shim-only world has no Mac
//! transport; `tests/docker_exec.rs` drives L2 with the real Mac client,
//! `ai-env vm exec`): uid and groups, NO_NEW_PRIVS, the child's fds (one the
//! shim inherited never reaches it), the dummy secret on fd 3, process groups
//! and zombies, the idle sweep, the cwd rule under a symlink swap, the detach
//! grace frozen across a suspend (a socket lost before it, or closed by it);
//! `/validate`'s V6 self-test (before `/run`: after it, 409).
//! S7 agent L1, the credential cache (through the same raw client): a
//! `credential` frame the root shim caches, read byte-exact on fd 3 by a
//! uid-1000 spawn and shown by name, tag and holders in `/health/detail`;
//! the shim's environ, mem and maps closed to a spawn; `/suspend` dropping
//! the cache before its 200 and `/resume` reopening it empty; the value on no
//! file (binary ones included), command line or environment.
//! L2: the locally built image (`make image-build-local`) with the real,
//! pinned claude — the version gate, `/validate` (from the host and from
//! inside), no build-time state, modes, and (S6) `claude --version` and a
//! `setsid` escaper through `/agent`.
//! The only claude ever executed is the pinned Linux binary inside L2.
use ai_env_cli::wire::chunk::{decode, Chunker};
use ai_env_cli::wire::frame::{ClientInfo, CredentialErrCode, Deliver, EventKind, ExitInfo, Frame, Health, HealthDetail, HealthStatus, RunHookPayload, Scope, Sig, SpawnErrCode, SpawnId};
use ai_env_cli::wire::redact::Secret;
use futures_util::{SinkExt, StreamExt};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

const PREFIX: &str = "/aws/lambda-microvms/runtime/v1";
const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const FAKE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/claude-version.sh");

/// Every docker call's bound: a stuck daemon fails the test, never hangs it.
const DOCKER_LIMIT: Duration = Duration::from_secs(120);

/// `docker <args>`, killed past `limit`.
fn docker_within(args: &[&str], limit: Duration) -> Result<Output, String> {
    docker_fed(args, None, limit)
}

/// [`docker_within`] with `input`, when given, on its stdin (then EOF): what
/// a scan looks for goes in this way, never on an argv `/proc` would show.
fn docker_fed(args: &[&str], input: Option<&[u8]>, limit: Duration) -> Result<Output, String> {
    let stdin = if input.is_some() { Stdio::piped() } else { Stdio::null() };
    let mut child = Command::new("docker").args(args).stdin(stdin).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("docker CLI: {e}"))?;
    // A killed child closes the pipe: the feeder's write fails and it ends.
    let _feeder = input.map(|bytes| {
        let (mut sink, bytes) = (child.stdin.take().expect("piped"), bytes.to_vec());
        std::thread::spawn(move || {
            let _ = sink.write_all(&bytes);
        })
    });
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
                return Err(format!("docker {args:?} did not finish within {limit:?}"));
            }
        }
    };
    Ok(Output { status, stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default() })
}

fn docker(args: &[&str]) -> Output {
    docker_within(args, DOCKER_LIMIT).unwrap_or_else(|e| panic!("{e}"))
}

/// Every test starts here: panics unless explicitly enabled (the tests are
/// `#[ignore]`d, so reaching this without the variable is a mistake).
fn require_enabled() {
    assert_eq!(std::env::var("AI_ENV_DOCKER_TESTS").as_deref(), Ok("1"), "run through `make test-docker` (AI_ENV_DOCKER_TESTS=1)");
    let out = docker(&["version", "--format", "{{.Server.Version}}"]);
    assert!(out.status.success(), "the Docker daemon is not running: {}", String::from_utf8_lossy(&out.stderr));
}

fn base_image() -> String {
    std::env::var("AI_ENV_DOCKER_BASE").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| {
        let df = std::fs::read_to_string(Path::new(REPO).join("image/Dockerfile")).unwrap();
        df.lines().find_map(|l| l.strip_prefix("FROM ")).expect("FROM line").trim().to_string()
    })
}

fn local_image() -> String {
    std::env::var("AI_ENV_DOCKER_IMAGE").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "ai-env-agent:local".into())
}

fn shim_binary() -> PathBuf {
    let p = std::env::var_os("AI_ENV_DOCKER_SHIM").map_or_else(|| Path::new(REPO).join("image/ai-env"), PathBuf::from);
    assert!(p.is_file(), "{} is missing: run make vm-build", p.display());
    p
}

fn lock_version() -> String {
    let lock = std::fs::read_to_string(Path::new(REPO).join("image/claude.lock")).unwrap();
    ai_env_cli::wire::pin::parse_lock(&lock).unwrap().version
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

/// A detached container, removed on drop.
struct Container {
    id: String,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = docker_within(&["rm", "-f", &self.id], DOCKER_LIMIT);
    }
}

impl Container {
    fn start(docker_args: &[&str], image: &str, cmd: &[&str]) -> Container {
        // The guard exists before `docker run`: a container created but not started goes too.
        let c = Container { id: container_name() };
        let mut args = vec!["run", "-d", "--name", &c.id, "--platform", "linux/arm64", "-p", "127.0.0.1::9000", "-p", "127.0.0.1::8080", "-p", "127.0.0.1::9418"];
        args.extend_from_slice(docker_args);
        args.push(image);
        args.extend_from_slice(cmd);
        ok_stdout(&args);
        c
    }

    fn port(&self, inner: u16) -> SocketAddr {
        let out = ok_stdout(&["port", &self.id, &format!("{inner}/tcp")]);
        out.lines().next().unwrap().trim().parse().unwrap_or_else(|e| panic!("{e}: {out:?}"))
    }

    /// The container's own address on its network.
    fn ip(&self) -> String {
        let ip = ok_stdout(&["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", &self.id]);
        assert!(!ip.is_empty(), "no address for {}", self.id);
        ip
    }

    fn logs(&self) -> String {
        let out = docker(&["logs", &self.id]);
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    }

    /// The shim's log lines with the time Docker read each one: (seconds since the epoch, line).
    fn timed_logs(&self) -> Vec<(f64, String)> {
        let out = docker(&["logs", "--timestamps", &self.id]);
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter_map(|l| {
                let (ts, line) = l.split_once(' ')?;
                let secs = ai_env_cli::wire::time::parse_rfc3339_utc(ts)?;
                let frac: f64 = ts.split_once('.').and_then(|(_, f)| format!("0.{}", f.trim_end_matches('Z')).parse().ok()).unwrap_or(0.0);
                Some((secs as f64 + frac, line.to_string()))
            })
            .collect()
    }

    fn exec(&self, cmd: &[&str]) -> Output {
        self.exec_as("0", cmd)
    }

    /// `docker exec -u <user>`: `0` stands for the platform, `1000` for the agent.
    fn exec_as(&self, user: &str, cmd: &[&str]) -> Output {
        let mut args = vec!["exec", "-u", user, &self.id[..]];
        args.extend_from_slice(cmd);
        docker(&args)
    }

    /// [`Self::exec_as`] with `input` on the command's stdin (`docker exec -i`).
    fn exec_input(&self, user: &str, cmd: &[&str], input: &[u8]) -> Output {
        let mut args = vec!["exec", "-i", "-u", user, &self.id[..]];
        args.extend_from_slice(cmd);
        docker_fed(&args, Some(input), DOCKER_LIMIT).unwrap_or_else(|e| panic!("{e}"))
    }

    fn sh(&self, script: &str) -> String {
        self.sh_as("0", script)
    }

    fn sh_as(&self, user: &str, script: &str) -> String {
        let out = self.exec_as(user, &["sh", "-c", script]);
        assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// `curl -s` inside as `user`: (status, body).
    fn curl(&self, user: &str, args: &[&str]) -> (u16, String) {
        let mut cmd = vec!["curl", "-s", "-m", "10", "-w", "\n%{http_code}"];
        cmd.extend_from_slice(args);
        let out = self.exec_as(user, &cmd);
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
        let status = code.trim().parse().unwrap_or_else(|_| panic!("curl {args:?} as {user}: {text:?} {}", String::from_utf8_lossy(&out.stderr)));
        (status, body.to_string())
    }

    fn wait_log(&self, secs: u64, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let logs = self.logs();
            if logs.contains(needle) {
                return logs;
            }
            assert!(Instant::now() < deadline, "{needle:?} not in the logs within {secs} s:\n{logs}");
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn zombies(&self) -> String {
        self.sh("for s in /proc/[0-9]*/stat; do set -- $(cat \"$s\" 2>/dev/null); [ \"$3\" = Z ] && echo \"$1 $2\"; done; true")
    }

    /// The pids of live (not zombie) processes named `comm` (the base image has no pgrep).
    fn pids(&self, comm: &str) -> Vec<u32> {
        let script = format!("for s in /proc/[0-9]*/stat; do set -- $(cat \"$s\" 2>/dev/null); [ \"$2\" = '({comm})' ] && [ \"$3\" != Z ] && echo \"$1\"; done; true");
        self.sh(&script).lines().filter_map(|l| l.trim().parse().ok()).collect()
    }

    /// `pid` exists and is not a zombie.
    fn alive(&self, pid: u32) -> bool {
        let out = self.exec(&["cat", &format!("/proc/{pid}/stat")]);
        out.status.success() && String::from_utf8_lossy(&out.stdout).rsplit_once(") ").is_some_and(|(_, rest)| !rest.starts_with('Z'))
    }

    /// Wait (at most `secs`) until no live process is named `comm`.
    fn wait_gone(&self, secs: u64, comm: &str) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !self.pids(comm).is_empty() {
            assert!(Instant::now() < deadline, "{comm} still running after {secs} s:\n{}", self.logs());
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// A Docker network (`<container name>-net`), removed on drop: declare it
/// before the containers on it, so they go first.
struct Network {
    name: String,
}

impl Network {
    fn create() -> Network {
        // The guard exists before `docker network create`, as for a container.
        let n = Network { name: format!("{}-net", container_name()) };
        ok_stdout(&["network", "create", &n.name]);
        n
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = docker_within(&["network", "rm", &self.name], DOCKER_LIMIT);
    }
}

/// POST/GET through the published port; (status, body). Retries while the
/// port forwarder accepts but the shim is not listening yet.
fn http(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, String) {
    http_with(addr, method, path, "", body)
}

/// [`http`] with extra header lines (each ending in CRLF).
fn http_with(addr: SocketAddr, method: &str, path: &str, extra: &str, body: &str) -> (u16, String) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match try_http(addr, method, path, extra, body) {
            Ok(r) => return r,
            Err(e) => {
                assert!(Instant::now() < deadline, "{method} {path}: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn try_http(addr: SocketAddr, method: &str, path: &str, extra: &str, body: &str) -> std::io::Result<(u16, String)> {
    let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, rest) = text.split_once("\r\n\r\n").ok_or_else(|| std::io::Error::other(format!("no response: {text:?}")))?;
    let status = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| std::io::Error::other(text.clone()))?;
    Ok((status, rest.to_string()))
}

fn wait_ready(c: &Container, secs: u64) -> Vec<u16> {
    let hooks = c.port(9000);
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut seen = Vec::new();
    loop {
        let (s, body) = http(hooks, "POST", &format!("{PREFIX}/ready"), "");
        if seen.last() != Some(&s) {
            seen.push(s);
        }
        if s == 200 {
            return seen;
        }
        assert_eq!(s, 503, "{body}");
        assert!(Instant::now() < deadline, "/ready never answered 200: {body}\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn payload_for(token: &str, owner: &str) -> String {
    RunHookPayload::new(&Secret::new(token.to_string()), owner, "2026-09-29T08:00:00Z").to_json().unwrap()
}

fn payload(owner: &str) -> String {
    payload_for("test-token", owner)
}

fn run_body(microvm: &str, p: Option<&str>) -> String {
    let mut m = serde_json::Map::new();
    m.insert("microvmId".into(), microvm.into());
    if let Some(p) = p {
        m.insert("runHookPayload".into(), p.into());
    }
    serde_json::Value::Object(m).to_string()
}

// ---- L1: base image + the cross-built shim + a fake claude ----------------------------

/// The fake in a world-readable dir (the probe runs as uid 1000).
fn fake_dir(conf: &str) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    std::fs::copy(FAKE, d.path().join("claude")).unwrap();
    std::fs::set_permissions(d.path().join("claude"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(d.path().join("claude-version.conf"), conf).unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    d
}

/// The image ENTRYPOINT's argv, from image/Dockerfile's exec-form line (each
/// flag and its value two words: [`with_flags`] and [`shipped_agent_guard`]
/// rely on it).
fn entrypoint() -> Vec<String> {
    let df = std::fs::read_to_string(Path::new(REPO).join("image/Dockerfile")).unwrap();
    let line = df.lines().find_map(|l| l.strip_prefix("ENTRYPOINT ")).expect("an ENTRYPOINT line");
    let argv: Vec<String> = serde_json::from_str(line).unwrap_or_else(|e| panic!("ENTRYPOINT is not exec form ({e}): {line}"));
    assert!(!argv.iter().any(|a| a.starts_with("--") && a.contains('=')), "a `--flag=value` word in the ENTRYPOINT: {argv:?}");
    argv
}

/// The agent guard the shipped ENTRYPOINT runs: its `--agent-guard` value,
/// or `on` (the default as root on Linux) when it passes none. Plan S6 ships
/// only these: the default, or tree B's fallback `log` (the endpoint reaches
/// 8080 as a local peer), never `off`; the hooks guard is `--hook-source
/// peer` either way.
fn shipped_agent_guard() -> &'static str {
    let argv = entrypoint();
    let value = |flag: &str| argv.iter().position(|a| a == flag).map(|at| argv.get(at + 1).map_or("", String::as_str));
    assert_eq!(value("--hook-source"), Some("peer"), "the hooks guard ships as `--hook-source peer`: {argv:?}");
    match value("--agent-guard") {
        None | Some("on") => "on",
        Some("log") => "log",
        Some(other) => panic!("the image never runs `--agent-guard {other}` (plan S6: the default on, or tree B's log): {argv:?}"),
    }
}

/// `argv` with each `(flag, value)` set: a flag the ENTRYPOINT already
/// passes gets the new value in place (clap refuses a repeated flag), any
/// other is appended.
fn with_flags(mut argv: Vec<String>, flags: &[(&str, &str)]) -> Vec<String> {
    for (flag, value) in flags {
        match argv.iter().position(|a| a == flag) {
            Some(at) if at + 1 < argv.len() => argv[at + 1] = (*value).to_string(),
            _ => argv.extend([(*flag).to_string(), (*value).to_string()]),
        }
    }
    argv
}

/// The shipped ENTRYPOINT argv (defaults it relies on included, e.g. no
/// `--gid`), `--claude` set to the fake, then `flags` set (replaced or
/// appended).
fn l1(conf: &str, docker_args: &[&str], flags: &[(&str, &str)]) -> (Container, tempfile::TempDir) {
    require_enabled();
    let fake = fake_dir(conf);
    let shipped = entrypoint();
    assert_eq!(shipped.first().map(String::as_str), Some("/usr/local/bin/ai-env"), "the shim is mounted where the ENTRYPOINT runs it: {shipped:?}");
    assert!(shipped.iter().any(|a| a == "--claude"), "--claude in the ENTRYPOINT: {shipped:?}");
    let argv = with_flags(with_flags(shipped, &[("--claude", "/opt/fake/claude")]), flags);
    let shim_mount = format!("{}:/usr/local/bin/ai-env:ro", shim_binary().display());
    let fake_mount = format!("{}:/opt/fake:ro", fake.path().display());
    let mut args = vec!["-v", &shim_mount[..], "-v", &fake_mount[..], "--entrypoint", &argv[0][..]];
    args.extend_from_slice(docker_args);
    let cmd: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    (Container::start(&args, &base_image(), &cmd), fake)
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_ready_503_then_200() {
    let (c, _f) = l1("SLEEP=3\n", &[], &[]);
    let seen = wait_ready(&c, 20);
    assert_eq!(seen, vec![503, 200], "503 while the probe sleeps, then 200");
    c.wait_log(5, "claude probe ok");
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_run_first_wins_and_health() {
    let (c, _f) = l1("", &[], &[]);
    wait_ready(&c, 20);
    let hooks = c.port(9000);
    let body = run_body("mvm-l1", Some(&payload("mike@mbp")));
    assert_eq!(http(hooks, "POST", &format!("{PREFIX}/run"), &body).0, 200);
    assert_eq!(http(hooks, "POST", &format!("{PREFIX}/run"), &body).0, 200, "replay");
    assert_eq!(http(hooks, "POST", &format!("{PREFIX}/run"), &run_body("mvm-l1", Some(&payload("x@y")))).0, 409);
    let (s, h) = http(c.port(8080), "GET", "/health", "");
    assert_eq!(s, 200);
    let h: Health = serde_json::from_str(&h).unwrap();
    assert!(h.run_hook_seen);
    assert_eq!(h.owner.as_deref(), Some("mike@mbp"));
    assert_eq!(h.claude_version.as_deref(), Some("2.1.283"));
    assert_eq!(h.boot_nonce.map(|n| n.len()), Some(32));
    let logs = c.logs();
    assert!(logs.contains("ai-env: hook run peer=") && logs.contains("origin=remote"), "a request from the host is remote:\n{logs}");
}

/// Plan S4 D19: the Linux run report as PID 1 — one after the accepted /run
/// (not after the replay), one at /terminate, both with the VM id, the boot
/// id of the boot line, a real disk, PID 1's environment names (no AWS
/// credential variables) and no zombies.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_run_report_as_pid1() {
    let (c, _f) = l1("", &[], &[]);
    wait_ready(&c, 20);
    let hooks = c.port(9000);
    let body = run_body("mvm-l1", Some(&payload("mike@mbp")));
    assert_eq!(http(hooks, "POST", &format!("{PREFIX}/run"), &body).0, 200);
    assert_eq!(http(hooks, "POST", &format!("{PREFIX}/run"), &body).0, 200, "replay: no second report");
    assert_eq!(http(hooks, "POST", &format!("{PREFIX}/terminate"), "{}").0, 200);
    let logs = c.wait_log(5, "\"hook\":\"terminate\"");
    let boot: serde_json::Value = logs.lines().find_map(|l| l.split_once("ai-env: boot ").and_then(|(_, j)| serde_json::from_str(j).ok())).expect("a boot line");
    let reports: Vec<serde_json::Value> = logs.lines().filter_map(|l| l.split_once("ai-env: run-report ").and_then(|(_, j)| serde_json::from_str(j).ok())).collect();
    let hooks_seen: Vec<&str> = reports.iter().map(|r| r["hook"].as_str().unwrap()).collect();
    assert_eq!(hooks_seen, ["run", "terminate"], "{logs}");
    for r in &reports {
        assert_eq!(r["microvm_id"], "mvm-l1", "{r}");
        assert!(r.get("unsupported").is_none(), "{r}");
        let id = r["boot_id"].as_str().unwrap_or_default();
        assert_eq!(id.len(), 36, "{r}");
        assert_eq!(boot["boot_id"].as_str(), Some(id), "the boot line's boot id");
        let (total, used) = (r["disk_total_bytes"].as_u64().unwrap(), r["disk_used_bytes"].as_u64().unwrap());
        assert!(total > 0 && used <= total, "{r}");
        assert_eq!(r["env"]["values"]["HOME"], "/root", "{r}");
        let names: Vec<&str> = r["env"]["names"].as_array().unwrap().iter().filter_map(|n| n.as_str()).collect();
        assert!(names.contains(&"HOME") && names.contains(&"PATH"), "{names:?}");
        assert_eq!(r["aws_credential_env"], serde_json::json!([]), "{r}");
        assert_eq!(r["zombies"], 0, "{r}");
        assert_eq!((r["uid"].as_u64(), r["gid"].as_u64()), (Some(0), Some(0)), "{r}");
    }
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_enforce_rejects_loopback_and_container_ip() {
    let (c, _f) = l1("", &[], &[("--hook-source", "enforce")]);
    wait_ready(&c, 20);
    let code = |url: &str| c.sh(&format!("curl -s -o /dev/null -w '%{{http_code}}' -X POST -d '{{}}' {url}"));
    assert_eq!(code(&format!("http://127.0.0.1:9000{PREFIX}/resume")), "403", "loopback");
    let ip = c.ip();
    assert_eq!(code(&format!("http://{ip}:9000{PREFIX}/suspend")), "403", "our own address");
    assert_eq!(code(&format!("http://127.0.0.1:9000{PREFIX}/ready")), "200", "ready is never filtered");
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/run"), &run_body("mvm-e", None)).0, 200, "the host is remote");
    let logs = c.logs();
    let refused = |origin: &str| logs.lines().any(|l| l.starts_with("ai-env: hook ") && l.contains(&format!(" origin={origin} ")) && l.contains(" status=403 "));
    assert!(refused("loopback") && refused("self"), "{logs}");
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_delay_run_5() {
    let (c, _f) = l1("", &[], &[("--delay-run", "5")]);
    wait_ready(&c, 20);
    let hooks = c.port(9000);
    let app = c.port(8080);
    let started = Instant::now();
    let t = std::thread::spawn(move || http(hooks, "POST", &format!("{PREFIX}/run"), &run_body("mvm-d", None)));
    std::thread::sleep(Duration::from_secs(2));
    let (_, h) = http(app, "GET", "/health", "");
    assert!(h.contains("\"run_hook_seen\":false"), "held: {h}");
    assert_eq!(t.join().unwrap().0, 200);
    assert!(started.elapsed() >= Duration::from_secs(5), "{:?}", started.elapsed());
    let (_, h) = http(app, "GET", "/health", "");
    assert!(h.contains("\"run_hook_seen\":true"), "{h}");
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_orphans_are_reaped() {
    let (c, _f) = l1("ORPHAN=1\n", &[], &[]);
    wait_ready(&c, 20);
    c.wait_log(10, "init: reaped orphan");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(c.zombies(), "", "no defunct process:\n{}", c.logs());
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_pid1_is_ai_env_and_vm_help_exits_2() {
    let (c, _f) = l1("", &[], &[]);
    wait_ready(&c, 20);
    assert_eq!(c.sh("cat /proc/1/comm"), "ai-env");
    assert!(c.sh("tr '\\0' ' ' < /proc/1/cmdline").starts_with("/usr/local/bin/ai-env shim "));
    let logs = c.logs();
    assert!(logs.contains("ai-env: init pid 1 supervising worker pid"), "{logs}");
    let out = c.exec(&["/usr/local/bin/ai-env", "vm", "--help"]);
    assert_eq!(out.status.code(), Some(2), "the image binary has no bridge commands");
    let out = c.exec(&["/usr/local/bin/ai-env", "--version"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), format!("ai-env {}", env!("CARGO_PKG_VERSION")));
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_clock_and_entropy_report_without_caps() {
    let (c, _f) = l1("", &[], &[]);
    wait_ready(&c, 20);
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/run"), &run_body("mvm-c", Some(&payload("mike@mbp")))).0, 200);
    let logs = c.wait_log(5, "ai-env: clock {");
    let clock = logs.lines().find(|l| l.starts_with("ai-env: clock {")).unwrap();
    assert!(clock.contains("\"mode\":\"measure\"") && clock.contains("\"settable\":false") && clock.contains("\"stepped_to\":null"), "{clock}");
    assert!(clock.contains("\"created_s\":1790668800"), "the payload's created is measured: {clock}");
    assert!(logs.contains("entropy: mixed, reseed failed") && logs.contains("cap_sys_admin=false"), "{logs}");
    let boot = logs.lines().find(|l| l.starts_with("ai-env: boot {")).unwrap();
    assert!(boot.contains("\"cap_sys_time\":false") && boot.contains("\"pid\":"), "{boot}");
    eprintln!("L1 boot report: {boot}\nL1 clock report: {clock}");
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_reseed_succeeds_with_cap_sys_admin() {
    let (c, _f) = l1("", &["--cap-add", "SYS_ADMIN"], &[]);
    wait_ready(&c, 20);
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/run"), &run_body("mvm-r", None)).0, 200);
    let logs = c.wait_log(5, "entropy: ");
    assert!(logs.contains("entropy: mixed, reseeded, cap_sys_admin=true"), "{logs}");
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_stop_is_graceful() {
    let (c, _f) = l1("", &[], &[]);
    wait_ready(&c, 20);
    let started = Instant::now();
    ok_stdout(&["stop", "-t", "30", &c.id]);
    let took = started.elapsed();
    assert!(took < Duration::from_secs(3), "docker stop took {took:?} (30 s means SIGTERM was not handled):\n{}", c.logs());
    assert_eq!(ok_stdout(&["inspect", "-f", "{{.State.ExitCode}}", &c.id]), "0");
    let logs = c.logs();
    assert!(logs.contains("init: forwarding SIGTERM") && logs.contains("ai-env: shim stopped") && logs.contains("worker exited"), "{logs}");
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l1_probe_child_is_uid_gid_1000() {
    let (c, _f) = l1("ID_FILE=/tmp/claude-ids\nSIG_FILE=/tmp/claude-sigs\n", &[], &[]);
    wait_ready(&c, 20);
    assert_eq!(c.sh("head -1 /tmp/claude-ids"), "1000 1000", "the ENTRYPOINT's --uid and the --gid default");
    // Neither init's blocked mask nor the worker's early SIG_IGN of
    // HUP/USR1/USR2 reaches claude. (Signal 32, glibc's internal SIGCANCEL,
    // is ignored in the multi-threaded worker and inherited; not ours.)
    let sigs = c.sh("head -1 /tmp/claude-sigs");
    let mask = |name: &str| sigs.split_whitespace().skip_while(|w| *w != name).nth(1).and_then(|h| u64::from_str_radix(h, 16).ok()).unwrap_or_else(|| panic!("{name} in {sigs:?}"));
    assert_eq!(mask("SigBlk:"), 0, "no blocked signal: {sigs}");
    let ours: u64 = [1u32, 2, 3, 10, 12, 15].iter().map(|s| 1u64 << (s - 1)).sum(); // HUP INT QUIT USR1 USR2 TERM
    assert_eq!(mask("SigIgn:") & ours, 0, "none of the worker's six is ignored in claude: {sigs}");
    assert_eq!(c.sh("id -u"), "0", "the shim itself is root");
    let boot = c.logs().lines().find(|l| l.starts_with("ai-env: boot {")).unwrap().to_string();
    assert!(boot.contains("\"cap_chown\":true") && boot.contains("\"cap_setuid\":true") && boot.contains("\"cap_setgid\":true"), "{boot}");
}

/// Without the privilege drop's capabilities `/ready` never flips; the
/// probe's error names what the effective set lacks, and so does the boot
/// report.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_missing_drop_caps_are_named() {
    for (cap, needle) in [("CHOWN", "probe HOME chown: "), ("SETUID", "cannot run /opt/fake/claude: ")] {
        let (c, _f) = l1("", &["--cap-drop", cap], &[]);
        let logs = c.wait_log(15, &format!("the effective capabilities lack CAP_{cap}"));
        let failed = logs.lines().find(|l| l.contains("claude probe failed")).unwrap_or_default().to_string();
        assert!(failed.contains(needle) && failed.contains(&format!("CAP_{cap}")), "{failed}");
        let boot = logs.lines().find(|l| l.starts_with("ai-env: boot {")).unwrap().to_string();
        assert!(boot.contains(&format!("\"cap_{}\":false", cap.to_ascii_lowercase())), "{boot}");
        let (s, body) = http(c.port(9000), "POST", &format!("{PREFIX}/ready"), "");
        assert_eq!(s, 503, "{body}");
    }
}

// ---- S6 agent L1: the guard, `/agent` spawns, V6 ----------------------------------------

/// What the Dockerfile bakes for the agent, from the repo's image/ (mounted
/// at /opt/image): the lock, the managed settings, `/Users/mike` 0700 with
/// the claude config subset, all owned by 1000:1000 — and, as in the image, a
/// root-owned `/usr/local/bin/claude` (here a copy of the fake).
const SEED: &str = "set -eu; \
    mkdir -p /etc/ai-env /etc/claude-code /Users/mike/.claude/agents /Users/mike/.claude/skills /Users/mike/.claude/commands; \
    cp /opt/image/claude.lock /etc/ai-env/claude.lock; \
    cp /opt/image/managed-settings.json /etc/claude-code/managed-settings.json; \
    cp /opt/image/claude/settings.json /opt/image/claude/CLAUDE.md /Users/mike/.claude/; \
    cp /opt/image/claude/claude.json /Users/mike/.claude/.claude.json; \
    cp /opt/image/claude/claude.json /Users/mike/.claude.json; \
    cp /opt/fake/claude /usr/local/bin/claude; \
    chmod 0644 /etc/ai-env/claude.lock /etc/claude-code/managed-settings.json /Users/mike/.claude/settings.json /Users/mike/.claude/CLAUDE.md; \
    chmod 0600 /Users/mike/.claude/.claude.json /Users/mike/.claude.json; \
    chmod 0755 /Users/mike/.claude/agents /Users/mike/.claude/skills /Users/mike/.claude/commands /usr/local/bin/claude; \
    chmod 0700 /Users/mike/.claude /Users/mike; \
    chown -R 1000:1000 /Users/mike";

/// A VM ready for the agent tests: `/run` from the host committed to `token`
/// (built at runtime).
struct Vm {
    c: Container,
    token: String,
    _fake: Option<tempfile::TempDir>,
}

/// A session token built at runtime, never a credential-looking literal.
fn session_token() -> String {
    format!("s6-docker-{}", SpawnId::new_v7())
}

impl Vm {
    fn started(c: Container, fake: Option<tempfile::TempDir>, ready_s: u64) -> Vm {
        wait_ready(&c, ready_s);
        let token = session_token();
        assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/run"), &run_body("mvm-agent", Some(&payload_for(&token, "mike@mbp")))).0, 200);
        Vm { c, token, _fake: fake }
    }

    /// A socket to `/agent` past `hello`.
    fn agent(&self) -> Agent {
        Agent::connect(self.c.port(8080), &self.token)
    }

    /// `argv` with `stdin` (then EOF) through a fresh socket: (stdout, stderr, exit).
    fn run(&self, argv: &[&str], stdin: &[u8]) -> (Vec<u8>, Vec<u8>, ExitInfo) {
        let r = self.agent().run(&Spec::argv(argv), stdin);
        (r.stdout, r.stderr, r.exit)
    }

    /// `GET /health/detail` from the host with the session bearer.
    fn detail(&self) -> HealthDetail {
        let (s, body) = http_with(self.c.port(8080), "GET", "/health/detail", &format!("Authorization: Bearer {}\r\n", self.token), "");
        assert_eq!(s, 200, "{body}");
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"))
    }

    fn status(&self) -> HealthStatus {
        let (s, h) = http(self.c.port(8080), "GET", "/health", "");
        assert_eq!(s, 200, "{h}");
        serde_json::from_str::<Health>(&h).unwrap_or_else(|e| panic!("{e}: {h}")).status
    }
}

/// L1 for the agent tests: the shipped ENTRYPOINT with `flags` set, the fake
/// printing the lock's version line, the agent tree seeded.
fn agent_l1(flags: &[(&str, &str)]) -> Vm {
    let (c, fake) = agent_l1_ready(flags);
    Vm::started(c, Some(fake), 20)
}

/// [`agent_l1`] up to `/ready`, before any `/run`: the build VM the
/// platform's `/validate` runs on (it answers 409 once `/run` was accepted).
fn agent_l1_ready(flags: &[(&str, &str)]) -> (Container, tempfile::TempDir) {
    let image = std::fs::canonicalize(Path::new(REPO).join("image")).unwrap();
    let image_mount = format!("{}:/opt/image:ro", image.display());
    let (c, fake) = l1(&format!("VERSION={}\n", lock_version()), &["-v", &image_mount], flags);
    c.sh(SEED);
    wait_ready(&c, 20);
    (c, fake)
}

type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// Every frame read and send of the raw client.
const FRAME_WAIT: Duration = Duration::from_secs(30);
/// A spawn's whole answer (its frames until `spawned`, or until its exit).
const SPAWN_WAIT: Duration = Duration::from_secs(120);

/// A raw wire v1 client of `/agent` through the published app port (the
/// shim-only world has no Mac transport; `tests/docker_exec.rs` drives L2
/// with the real one, `ai-env vm exec`), on its own current-thread runtime:
/// the tests stay synchronous, and the socket is served only inside its calls.
struct Agent {
    rt: tokio::runtime::Runtime,
    ws: Ws,
}

/// A `spawn` frame's fields (defaults: no cwd, env or secret; the exec grace).
/// No `Debug`: it may hold the dummy secret.
#[derive(Default)]
struct Spec {
    argv: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    secret: Option<(String, String)>,
    /// S7: names a credential the shim cached (`spawn.credential`); its value
    /// comes from the cache, never from this frame.
    credential: Option<String>,
    grace: Option<u32>,
}

impl Spec {
    fn argv(argv: &[&str]) -> Spec {
        Spec { argv: argv.iter().map(|a| (*a).to_string()).collect(), ..Spec::default() }
    }
}

/// What one spawn sent back. No `Debug`: it holds the stdio.
struct Ran {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: ExitInfo,
}

impl Ran {
    /// stdout as text, after asserting a clean exit 0.
    fn ok(self, what: &str) -> String {
        assert_eq!(self.exit, ExitInfo { code: Some(0), signal: None }, "{what}: {}", String::from_utf8_lossy(&self.stderr));
        String::from_utf8(self.stdout).unwrap_or_else(|e| panic!("{what}: {e}"))
    }
}

impl Agent {
    /// The upgrade (with the endpoint's `x-aws-proxy-port: 8080`), then `hello` with `token`.
    fn connect(app: SocketAddr, token: &str) -> Agent {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let ws = rt.block_on(async {
            let mut req = format!("ws://{app}/agent").into_client_request().unwrap();
            req.headers_mut().insert("x-aws-proxy-port", tokio_tungstenite::tungstenite::http::HeaderValue::from_static("8080"));
            let tcp = tokio::time::timeout(FRAME_WAIT, tokio::net::TcpStream::connect(app)).await.expect("a connect in time").expect("connect");
            let dial = tokio_tungstenite::client_async_with_config(req, tcp, Some(ai_env_cli::wire::frame::ws_config()));
            let (ws, resp) = tokio::time::timeout(FRAME_WAIT, dial).await.expect("an upgrade answer in time").unwrap_or_else(|e| panic!("the /agent upgrade: {e}"));
            assert!(resp.headers().get("sec-websocket-protocol").is_none(), "{resp:?}");
            ws
        });
        let mut a = Agent { rt, ws };
        let client = ClientInfo { name: "shim_docker".into(), version: env!("CARGO_PKG_VERSION").into(), host: "test@docker".into() };
        a.send(&Frame::Hello { session_token: Secret::new(token.to_string()), client, resume: vec![], idle_s: None });
        match a.next() {
            Ok(Frame::HelloOk { wire, run_hook_seen, has_credentials, .. }) => assert_eq!((wire, run_hook_seen, has_credentials), (1, true, false)),
            other => panic!("hello_ok, got {other:?}"),
        }
        a
    }

    fn send(&mut self, f: &Frame) {
        let (rt, ws) = (&self.rt, &mut self.ws);
        rt.block_on(async { tokio::time::timeout(FRAME_WAIT, ws.send(Message::from(f))).await.expect("a send in time").unwrap_or_else(|e| panic!("send {}: {e}", f.kind())) });
    }

    /// The next frame, or the close code (`Err(None)`: the socket ended without one).
    fn next(&mut self) -> Result<Frame, Option<u16>> {
        let (rt, ws) = (&self.rt, &mut self.ws);
        rt.block_on(async {
            loop {
                match tokio::time::timeout(FRAME_WAIT, ws.next()).await.expect("a frame within 30 s") {
                    Some(Ok(Message::Text(t))) => return Ok(Frame::from_json(t.as_str()).unwrap_or_else(|e| panic!("{e}"))),
                    Some(Ok(Message::Close(f))) => return Err(f.map(|f| u16::from(f.code))),
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => return Err(None),
                }
            }
        })
    }

    /// `spawn` (a fresh uuid v7, the secret delivered on fd 3): its id and
    /// pid, or the shim's refusal. Frames about other spawns, pongs and
    /// events are skipped.
    fn spawn(&mut self, spec: &Spec) -> Result<(SpawnId, u32), (SpawnErrCode, String)> {
        let id = SpawnId::new_v7();
        let secrets = spec.secret.iter().map(|(k, v)| (k.clone(), Secret::new(v.clone()))).collect();
        self.send(&Frame::Spawn { spawn_id: id.clone(), argv: spec.argv.clone(), cwd: spec.cwd.clone(), env: spec.env.clone(), secrets, deliver_secret: Deliver::Fd, detach_grace_s: spec.grace, credential: spec.credential.clone() });
        let deadline = Instant::now() + SPAWN_WAIT;
        loop {
            assert!(Instant::now() < deadline, "no answer to spawn {id} within {SPAWN_WAIT:?}");
            match self.next() {
                Ok(Frame::Spawned { spawn_id, pid, .. }) if spawn_id == id => return Ok((id, pid)),
                Ok(Frame::SpawnErr { spawn_id, code, message }) if spawn_id == id => return Err((code, message)),
                Ok(f @ Frame::Error { .. }) => panic!("{f:?} while spawning {id}"),
                Ok(f) if f.spawn_id() != Some(&id) => {}
                other => panic!("spawned or spawn_err for {id}, got {other:?}"),
            }
        }
    }

    /// `bytes` as stdin chunks (seq from 1), then EOF; no `stdin_ack` is
    /// awaited, so `bytes` stays within the shim's stdin window.
    fn feed(&mut self, id: &SpawnId, bytes: &[u8]) {
        let mut chunker = Chunker::new();
        let mut chunks = chunker.push(bytes);
        chunks.extend(chunker.finish());
        let mut seq = 0;
        for data in chunks {
            seq += 1;
            self.send(&Frame::Stdin { spawn_id: id.clone(), seq, data });
        }
        self.send(&Frame::StdinEof { spawn_id: id.clone(), seq });
    }

    fn ack(&mut self, id: &SpawnId, seq: u64, err_seq: u64) {
        self.send(&Frame::Ack { spawn_id: id.clone(), seq, err_seq });
    }

    fn signal(&mut self, id: &SpawnId, sig: Sig) {
        self.send(&Frame::Signal { spawn_id: id.clone(), sig, scope: Scope::Group });
    }

    /// `detach`: `final` runs the shim's TERM/KILL ladder at once; nobody collects that exit.
    fn detach(&mut self, id: &SpawnId, is_final: bool) {
        self.send(&Frame::Detach { spawn_id: id.clone(), is_final });
    }

    /// Everything `id` sends until its exit: every stdout and stderr seq is
    /// acked as it arrives, and the exit's seq (which releases the spawn).
    fn collect(&mut self, id: &SpawnId) -> Ran {
        let (mut stdout, mut stderr, mut seq, mut err_seq) = (Vec::new(), Vec::new(), 0, 0);
        let deadline = Instant::now() + SPAWN_WAIT;
        loop {
            assert!(Instant::now() < deadline, "{id} did not exit within {SPAWN_WAIT:?}");
            match self.next() {
                Ok(Frame::Stdout { spawn_id, seq: s, data }) if spawn_id == *id => {
                    stdout.extend(decode(&data).unwrap());
                    seq = s;
                    self.ack(id, seq, err_seq);
                }
                Ok(Frame::Stderr { spawn_id, seq: s, data, .. }) if spawn_id == *id => {
                    stderr.extend(decode(&data).unwrap());
                    err_seq = s;
                    self.ack(id, seq, err_seq);
                }
                Ok(Frame::Exit { spawn_id, seq: s, code, signal, .. }) if spawn_id == *id => {
                    self.ack(id, s, err_seq);
                    return Ran { stdout, stderr, exit: ExitInfo { code, signal } };
                }
                Ok(Frame::Error { code, spawn_id: Some(s), .. }) if s == *id => panic!("error {code:?} for {id}"),
                // stdin_ack, another spawn's frames, a pong, an event.
                Ok(_) => {}
                Err(close) => panic!("the socket ended ({close:?}) before {id} exited"),
            }
        }
    }

    /// `spec` with `stdin`, to its exit.
    fn run(&mut self, spec: &Spec, stdin: &[u8]) -> Ran {
        let (id, _) = self.spawn(spec).unwrap_or_else(|(code, m)| panic!("{:?}: spawn_err {code:?}: {m}", spec.argv.first()));
        self.feed(&id, stdin);
        self.collect(&id)
    }

    /// `spec` without stdin: its stdout, after a clean exit 0.
    fn out(&mut self, spec: &Spec) -> String {
        self.run(spec, b"").ok(&spec.argv.join(" "))
    }

    /// S7: deliver `value` under `name` (a `credential` frame, as the Mac
    /// would); panics unless the shim answers `credential_ok` cached with `tag`.
    /// A mismatch prints the frame's kind, a refusal its code and the length
    /// of its message: never a buffer the value could have reached.
    fn deliver(&mut self, name: &str, value: &str, tag: Option<&str>) {
        self.send(&Frame::Credential { name: name.to_string(), secret: Secret::new(value.to_string()), tag: tag.map(str::to_string) });
        match self.next() {
            Ok(Frame::CredentialOk { name: n, cached: true, tag: t }) => assert_eq!((n.as_str(), t.as_deref()), (name, tag), "credential_ok's name and tag"),
            Ok(Frame::CredentialErr { code, message, .. }) => panic!("credential_ok (cached), got credential_err {code:?} (a message of {} bytes)", message.len()),
            Ok(f) => panic!("credential_ok (cached), got {}", f.kind()),
            Err(close) => panic!("credential_ok (cached), the socket ended ({close:?})"),
        }
    }

    /// S7: send a `credential` frame expecting a refusal; its code and message
    /// (which must never carry the value).
    fn credential_refused(&mut self, name: &str, value: &str) -> (CredentialErrCode, String) {
        self.send(&Frame::Credential { name: name.to_string(), secret: Secret::new(value.to_string()), tag: None });
        match self.next() {
            Ok(Frame::CredentialErr { code, message, .. }) => (code, message),
            Ok(f) => panic!("credential_err, got {}", f.kind()),
            Err(close) => panic!("credential_err, the socket ended ({close:?})"),
        }
    }
}

/// The hook lines of `hook` (`ai-env: hook <hook> peer=… decision=…`).
fn hook_lines(logs: &str, hook: &str) -> Vec<String> {
    logs.lines().filter(|l| l.starts_with(&format!("ai-env: hook {hook} "))).map(str::to_string).collect()
}

/// A forged runtime hook from the agent: 403 `forbidden_peer` through
/// 127.0.0.1 and through the container's own address, and nothing drains; the
/// platform (root, a live socket) and the host (through the published port,
/// no row here) are admitted. Every line carries the row's facts. The guards
/// are the shipped ENTRYPOINT's, as `/health/detail` reports them.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_agent_uid_cannot_drive_the_runtime_hooks() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let post = |user: &str, host: &str, hook: &str| c.curl(user, &["-X", "POST", "-d", "{}", &format!("http://{host}:9000{PREFIX}/{hook}")]);
    for host in ["127.0.0.1".to_string(), c.ip()] {
        let (s, body) = post("1000", &host, "terminate");
        assert_eq!(s, 403, "via {host}: {body}");
        assert!(body.contains("\"forbidden_peer\"") && body.contains("agent_uid"), "{body}");
    }
    assert_eq!(vm.status(), HealthStatus::Ok, "the forged /terminate drained nothing");
    assert_eq!(post("0", "127.0.0.1", "resume").0, 200, "root: the platform");
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/resume"), "{}").0, 200, "the host, through the published port");
    let logs = c.logs();
    let terms = hook_lines(&logs, "terminate");
    assert_eq!(terms.len(), 2, "{logs}");
    assert!(terms.iter().all(|l| l.contains(" status=403 ") && l.contains(" peer_uid=1000 ") && l.ends_with(" decision=refuse:agent_uid")), "{terms:#?}");
    let resumes = hook_lines(&logs, "resume");
    assert!(resumes.iter().any(|l| l.contains(" origin=loopback ") && l.contains(" peer_uid=0 ") && !l.contains(" ino=0 ") && l.ends_with(" decision=admit")), "root's live socket: {resumes:#?}");
    assert!(resumes.iter().any(|l| l.contains(" origin=remote ") && l.contains(" peer_uid=- ") && l.ends_with(" decision=admit")), "the host: no row here and not the container's address, admitted: {resumes:#?}");
    let d = vm.detail();
    assert_eq!((d.agent_guard.as_str(), d.hook_source.as_str()), (shipped_agent_guard(), "peer"), "the shipped ENTRYPOINT's policies");
    assert!(!d.hook_peers.contains_key("terminate"), "{:?}", d.hook_peers);
    assert_eq!((d.hook_refusals["terminate"].uid, d.hook_refusals["terminate"].decision.as_str()), (Some(1000), "refused"));
    assert_eq!(d.refused_peers.get("9000"), Some(&2), "{:?}", d.refused_peers);
}

/// The side ports under `--agent-guard on` (set here, whatever the
/// ENTRYPOINT ships): the agent gets 403 `forbidden_peer` on 8080 (`/health`
/// and the `/agent` upgrade) and on 9418, before any bearer check; root
/// passes the guard (200 on `/health`, 401 without the bearer on 9418).
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_side_ports_refuse_the_agent_uid() {
    let vm = agent_l1(&[("--agent-guard", "on")]);
    let c = &vm.c;
    let upgrade = ["-H", "Connection: Upgrade", "-H", "Upgrade: websocket", "-H", "Sec-WebSocket-Version: 13", "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "http://127.0.0.1:8080/agent"];
    for (what, args) in [("8080 /health", &["http://127.0.0.1:8080/health"][..]), ("8080 /agent", &upgrade[..]), ("9418", &["http://127.0.0.1:9418/seed"][..])] {
        let (s, body) = c.curl("1000", args);
        assert_eq!(s, 403, "{what}: {body}");
        assert!(body.contains("\"forbidden_peer\"") && body.contains("agent_uid"), "{what}: {body}");
    }
    assert_eq!(c.curl("0", &["http://127.0.0.1:8080/health"]).0, 200, "root passes the guard");
    assert_eq!(c.curl("0", &["http://127.0.0.1:9418/seed"]).0, 401, "root passes the guard; no bearer");
    let d = vm.detail();
    assert_eq!((d.agent_guard.as_str(), d.hook_source.as_str()), ("on", "peer"), "the agent guard this test sets; the hooks guard as shipped");
    assert_eq!((d.refused_peers.get("8080"), d.refused_peers.get("9418")), (Some(&2), Some(&1)), "{:?}", d.refused_peers);
    let logs = c.logs();
    let refused = |port: &str| logs.lines().filter(|l| l.starts_with(&format!("ai-env: guard port={port} ")) && l.contains(" peer_uid=1000 ") && l.ends_with(" decision=refuse:agent_uid")).count();
    assert_eq!((refused("8080"), refused("9418")), (2, 1), "{logs}");
}

/// A client whose own socket is AF_INET6 (curl given the v4-mapped literal
/// `[::ffff:127.0.0.1]`) reaches the 0.0.0.0 listeners as 127.0.0.1, but its
/// row is listed only in /proc/net/tcp6, in the v4-mapped form: the lookup
/// must read tcp6 to find it. On 8080 (the agent guard, set on here) and on
/// 9000 (the hooks guard) root is admitted on its live row (`fam=6`), and the
/// agent is refused for its uid, never for a missing row (`no_row`).
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_a_v4_mapped_client_is_found_in_tcp6() {
    let vm = agent_l1(&[("--agent-guard", "on")]);
    let c = &vm.c;
    let resume = format!("http://[::ffff:127.0.0.1]:9000{PREFIX}/resume");
    let routes = [("8080 /health", vec!["-g", "http://[::ffff:127.0.0.1]:8080/health"]), ("9000 /resume", vec!["-g", "-X", "POST", "-d", "{}", resume.as_str()])];
    for (what, args) in &routes {
        let (s, body) = c.curl("0", args);
        assert_eq!(s, 200, "{what}: root through an AF_INET6 socket is the platform: {body}");
        let (s, body) = c.curl("1000", args);
        assert_eq!(s, 403, "{what}: {body}");
        assert!(body.contains("\"forbidden_peer\"") && body.contains("\"agent_uid\""), "{what}: found in tcp6, refused for its uid: {body}");
    }
    let logs = c.logs();
    for (what, prefix) in [("8080", "ai-env: guard port=8080 peer=127.0.0.1:"), ("9000", "ai-env: hook resume peer=127.0.0.1:")] {
        let lines: Vec<&str> = logs.lines().filter(|l| l.starts_with(prefix)).collect();
        assert_eq!(lines.len(), 2, "{what}: {lines:#?}");
        assert!(lines.iter().any(|l| l.contains(" peer_uid=0 ") && l.contains(" fam=6 ") && l.ends_with(" decision=admit")), "{what}: root's row, in tcp6: {lines:#?}");
        assert!(lines.iter().any(|l| l.contains(" peer_uid=1000 ") && l.contains(" fam=6 ") && l.ends_with(" decision=refuse:agent_uid")), "{what}: the agent's row, in tcp6: {lines:#?}");
    }
    let d = vm.detail();
    let (admitted, refused) = (&d.hook_peers["resume"], &d.hook_refusals["resume"]);
    assert_eq!((admitted.family, admitted.uid, refused.family, refused.uid), (Some(6), Some(0), Some(6), Some(1000)), "{:?} {:?}", d.hook_peers, d.hook_refusals);
}

/// The orphan rule on Docker's kernel: a ROOT client that sent a runtime
/// hook's head and 2 of its 100 body bytes, then closed at once (hyper
/// dispatches on the head; the lookup comes after the close), owns no socket
/// file any more: its row shows inode 0, and only the inode rule refuses it
/// (`orphaned`; its uid is not the agent's). A batch may lose the race
/// (looked up before the close: admitted, then 400 on the cut body), so
/// batches are sent until one is refused.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_an_orphaned_root_client_is_refused() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let script = format!("for i in 1 2 3 4 5; do exec 3<>/dev/tcp/127.0.0.1/9000; printf 'POST {PREFIX}/resume HTTP/1.1\\r\\nHost: vm\\r\\nContent-Length: 100\\r\\n\\r\\n{{}}' >&3; exec 3>&-; done");
    let orphaned = |logs: &str| hook_lines(logs, "resume").into_iter().filter(|l| l.ends_with(" decision=refuse:orphaned")).collect::<Vec<_>>();
    let mut batches = 0;
    let logs = loop {
        batches += 1;
        assert!(c.exec_as("0", &["bash", "-c", &script]).status.success());
        std::thread::sleep(Duration::from_millis(500));
        let logs = c.logs();
        if !orphaned(&logs).is_empty() || batches == 4 {
            break logs;
        }
    };
    let refused = orphaned(&logs);
    assert!(!refused.is_empty(), "no orphaned refusal in {batches} batches of 5:\n{logs}");
    for l in &refused {
        assert!(l.contains(" status=403 ") && l.contains(" origin=loopback ") && l.contains(" peer_uid=0 ") && l.contains(" ino=0 "), "{l}");
    }
    for l in hook_lines(&logs, "resume") {
        assert!(!l.contains(" status=200 "), "a cut /resume never ran: {l}");
    }
    let d = vm.detail();
    let seen = &d.hook_refusals["resume"];
    assert_eq!((seen.uid, seen.inode, seen.decision.as_str()), (Some(0), Some(0), "refused"), "{seen:?}");
    eprintln!("orphan rule: {} of {} cut requests refused orphaned", refused.len(), 5 * batches);
}

/// The close-before-lookup trick as the agent: 50 whole `/terminate`s, each
/// followed by an immediate close. Each is dropped unseen (hyper at EOF) or
/// refused (an orphaned row, or the agent's own): the VM never drains.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_close_before_lookup_never_drains() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let script = format!("for i in $(seq 1 50); do exec 3<>/dev/tcp/127.0.0.1/9000; printf 'POST {PREFIX}/terminate HTTP/1.1\\r\\nHost: vm\\r\\nContent-Length: 2\\r\\n\\r\\n{{}}' >&3; exec 3>&-; done");
    assert!(c.exec_as("1000", &["bash", "-c", &script]).status.success());
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(vm.status(), HealthStatus::Ok, "never draining:\n{}", c.logs());
    let d = vm.detail();
    assert!(!d.hook_peers.contains_key("terminate"), "no /terminate was admitted: {:?}", d.hook_peers);
    let lines = hook_lines(&c.logs(), "terminate");
    assert!(lines.iter().all(|l| l.contains(" status=403 ")), "{lines:#?}");
    eprintln!("close-before-lookup: {} of 50 seen, all refused", lines.len());
}

/// T6.6's RST abort as the agent, through 127.0.0.1 and through the
/// container's own address, on 8080 and 9418. Without SO_LINGER (bash cannot
/// set it) a close with data unread is an RST (`TCPAbortOnClose` counts
/// them): each connection's first request is refused for the agent's live
/// row and its answer left unread; the second goes out in ONE write by `dd`,
/// the socket's only holder, whose exit resets the connection at once. hyper
/// still reads the queued request and dispatches it, and the guard, finding
/// no row for a local address, refuses it `no_row` (a lookup that beats the
/// reset sees the agent's row). bash's own `printf` writes line by line:
/// Nagle would hold the tail, the RST discard it, and an incomplete head is
/// never dispatched. 9000 cannot be driven so (every hook answer carries
/// `Connection: close`: nothing is unread before the first request is
/// decided); the hooks share `peer::facts` and `decide`. The agent guard is
/// set on here.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_an_rst_aborted_agent_request_is_refused() {
    const CONNS: usize = 5;
    let vm = agent_l1(&[("--agent-guard", "on")]);
    let c = &vm.c;
    let ip = c.ip();
    let resets = || {
        let text = c.sh("cat /proc/net/netstat");
        let mut ext = text.lines().filter(|l| l.starts_with("TcpExt:"));
        let (names, values) = (ext.next().unwrap_or_default(), ext.next().unwrap_or_default());
        names.split_whitespace().zip(values.split_whitespace()).find(|(n, _)| *n == "TCPAbortOnClose").and_then(|(_, v)| v.parse::<u64>().ok()).unwrap_or_else(|| panic!("no TcpExt TCPAbortOnClose:\n{text}"))
    };
    let before = resets();
    let routes = [("127.0.0.1", 8080, "/health"), ("127.0.0.1", 9418, "/seed"), (ip.as_str(), 8080, "/health"), (ip.as_str(), 9418, "/seed")];
    for (host, port, path) in routes {
        let out = c.exec_as("1000", &["bash", "-c", &rst_abort(host, port, path, CONNS)]);
        assert!(out.status.success(), "{host}:{port}: {}", String::from_utf8_lossy(&out.stderr));
    }
    std::thread::sleep(Duration::from_millis(500));
    let aborted = resets() - before;
    assert!(aborted >= (routes.len() * CONNS) as u64, "every close was an RST: TCPAbortOnClose rose by {aborted}");
    let logs = c.logs();
    for (host, port, _) in routes {
        let no_row = assert_rst_refused(&logs, host, port, CONNS);
        eprintln!("RST abort via {host}:{port}: {no_row} of {CONNS} refused no_row");
    }
    let d = vm.detail();
    // Per port: two routes of CONNS connections, two requests each.
    let refused = (2 * CONNS * 2) as u64;
    assert_eq!((d.refused_peers.get("8080"), d.refused_peers.get("9418")), (Some(&refused), Some(&refused)), "{:?}", d.refused_peers);
}

/// The RST abort of [`l1_an_rst_aborted_agent_request_is_refused`] as a bash
/// script for the agent: `conns` connections to `host:port`, each a first
/// request for `path` whose answer is left unread, then a second in one `dd`
/// write whose exit resets the connection.
fn rst_abort(host: &str, port: u16, path: &str, conns: usize) -> String {
    format!(
        "for i in $(seq 1 {conns}); do ( exec 3<>/dev/tcp/{host}/{port}; printf 'GET {path} HTTP/1.1\\r\\nHost: vm\\r\\n\\r\\n' >&3; sleep 0.3; \
         printf -v req 'POST {path} HTTP/1.1\\r\\nHost: vm\\r\\nContent-Length: 100\\r\\n\\r\\n{{}}'; exec dd bs=4096 status=none <<<\"$req\" >&3 3>&- ); done"
    )
}

/// The guard lines of [`rst_abort`]'s `conns` connections through
/// `host:port` in `logs`: both requests of each decided, every one refused
/// (for the agent's live row, or for no row once the reset beat the lookup),
/// at least one `no_row`. How many were.
fn assert_rst_refused(logs: &str, host: &str, port: u16, conns: usize) -> usize {
    let lines: Vec<&str> = logs.lines().filter(|l| l.starts_with(&format!("ai-env: guard port={port} peer={host}:"))).collect();
    assert_eq!(lines.len(), 2 * conns, "both requests of every connection were decided, via {host}:{port}: {lines:#?}");
    let live = lines.iter().filter(|l| l.contains(" peer_uid=1000 ") && l.ends_with(" decision=refuse:agent_uid")).count();
    let no_row = lines.iter().filter(|l| l.contains(" peer_uid=- ") && l.ends_with(" decision=refuse:no_row")).count();
    assert_eq!(live + no_row, 2 * conns, "every request refused, via {host}:{port}: {lines:#?}");
    assert!(no_row >= 1, "no aborted request reached the guard without a row, via {host}:{port}: {lines:#?}");
    no_row
}

/// Locality is read per request: an address the VM gains after the shim
/// served its first requests (on the platform the VM's own address appears
/// only once the snapshot is restored; here a second Docker network is
/// connected to the running container) is one of ours at once. The agent's
/// RST aborts through it on 8080 and 9418 (the agent guard set on here)
/// reach the guard without a row and are refused `no_row`, never admitted as
/// remote.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_an_address_gained_after_boot_is_local() {
    const CONNS: usize = 5;
    // Declared first: dropped after the container on it.
    let net = Network::create();
    let vm = agent_l1(&[("--agent-guard", "on")]);
    let c = &vm.c;
    let first = c.ip();
    ok_stdout(&["network", "connect", &net.name, &c.id]);
    // Not `Container::ip`: with two networks its template joins both addresses.
    let ip = ok_stdout(&["inspect", "-f", &format!("{{{{(index .NetworkSettings.Networks \"{}\").IPAddress}}}}", net.name), &c.id]);
    assert!(ip.parse::<std::net::Ipv4Addr>().is_ok() && ip != first, "the new network's address: {ip:?} (the first network's: {first})");
    for (port, path) in [(8080, "/health"), (9418, "/seed")] {
        let out = c.exec_as("1000", &["bash", "-c", &rst_abort(&ip, port, path, CONNS)]);
        assert!(out.status.success(), "{ip}:{port}: {}", String::from_utf8_lossy(&out.stderr));
    }
    std::thread::sleep(Duration::from_millis(500));
    let logs = c.logs();
    for port in [8080, 9418] {
        let no_row = assert_rst_refused(&logs, &ip, port, CONNS);
        eprintln!("RST abort via the gained address {ip}:{port}: {no_row} of {CONNS} refused no_row");
    }
}

/// A spawn runs as the agent: uid and gid 1000 with no supplementary group,
/// NO_NEW_PRIVS, the default cwd `--home`, and only the shim's environment
/// plus the frame's; its open fds are exactly 0–2, and 3 with a secret, whose
/// value is on fd 3 and named by `<NAME>_FILE_DESCRIPTOR=3`. Neither the
/// secret nor the session token is ever logged.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_spawns_run_as_the_agent_with_no_new_privs_and_clean_fds() {
    let vm = agent_l1(&[]);
    let mut a = vm.agent();
    assert_eq!(a.out(&Spec::argv(&["id", "-u"])), "1000\n");
    assert_eq!(a.out(&Spec::argv(&["id", "-G"])), "1000\n", "the gid only: no supplementary group");
    assert_eq!(a.out(&Spec::argv(&["grep", "NoNewPrivs", "/proc/self/status"])), "NoNewPrivs:\t1\n");
    assert_eq!(a.out(&Spec::argv(&["sh", "-c", "pwd"])), "/Users/mike\n");
    let env = a.out(&Spec { env: BTreeMap::from([("S6_DOCKER".to_string(), "on".to_string())]), ..Spec::argv(&["env"]) });
    let mut env: Vec<&str> = env.lines().collect();
    env.sort_unstable();
    assert_eq!(env, ["CLAUDE_CONFIG_DIR=/Users/mike/.claude", "DISABLE_AUTOUPDATER=1", "HOME=/Users/mike", "PATH=/usr/local/bin:/usr/bin:/bin", "S6_DOCKER=on"]);
    // The shell's own fds, listed by a child: `; true` keeps sh from exec'ing
    // ls, which would list its own directory fd.
    let fds = |text: String| text.split_whitespace().map(str::to_string).collect::<Vec<_>>();
    let listing = ["sh", "-c", "ls /proc/$$/fd; true"];
    assert_eq!(fds(a.out(&Spec::argv(&listing))), ["0", "1", "2"]);
    let secret = format!("dummy-{}", SpawnId::new_v7());
    let with_secret = |argv: &[&str]| Spec { secret: Some(("DUMMY_SECRET".into(), secret.clone())), ..Spec::argv(argv) };
    assert_eq!(fds(a.out(&with_secret(&listing))), ["0", "1", "2", "3"]);
    let got = a.out(&with_secret(&["sh", "-c", "cat <&3; echo; echo $DUMMY_SECRET_FILE_DESCRIPTOR"]));
    assert!(got == format!("{secret}\n3\n"), "the secret is not what fd 3 carried, or DUMMY_SECRET_FILE_DESCRIPTOR is not 3");
    // stdin and stdout byte-exact as the agent: non-UTF-8, chunks of 64 KiB, an unterminated last line.
    let mut input = b"line\n\x00\xff\xfe\n".to_vec();
    input.extend(std::iter::repeat_n(b'x', 200_000));
    input.extend_from_slice("€ unterminated".as_bytes());
    let echoed = a.run(&Spec::argv(&["cat"]), &input);
    assert_eq!(echoed.exit, ExitInfo { code: Some(0), signal: None });
    assert!(echoed.stdout == input, "cat gave back {} bytes, not the {} it was fed", echoed.stdout.len(), input.len());
    let logs = vm.c.logs();
    assert!(logs.contains(" secret=fd3"), "the spawn line names the delivery, not the value:\n{logs}");
    assert!(!logs.contains(&secret), "the secret reached the log");
    assert!(!logs.contains(&vm.token), "the session token reached the log");
}

/// What the shim inherited never reaches a spawn: started by a bash wrapper
/// that holds fd 5000 open WITHOUT close-on-exec (past the fallback `fcntl`
/// walk's end, 4096: only `close_range` covers it) and execs the shipped
/// ENTRYPOINT, init and the worker both hold it, yet a spawn's open fds are
/// exactly 0–2 (0–3 with a secret).
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_an_inherited_fd_never_reaches_a_spawn() {
    require_enabled();
    let fake = fake_dir(&format!("VERSION={}\n", lock_version()));
    let argv = with_flags(entrypoint(), &[("--claude", "/opt/fake/claude")]);
    assert!(argv.iter().all(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))), "a plain argv for bash -c: {argv:?}");
    let script = format!("exec 5000</etc/hostname; exec {}", argv.join(" "));
    let image = std::fs::canonicalize(Path::new(REPO).join("image")).unwrap();
    let mounts = [format!("{}:/usr/local/bin/ai-env:ro", shim_binary().display()), format!("{}:/opt/fake:ro", fake.path().display()), format!("{}:/opt/image:ro", image.display())];
    let c = Container::start(&["-v", &mounts[0], "-v", &mounts[1], "-v", &mounts[2], "--entrypoint", "/bin/bash"], &base_image(), &["-c", &script]);
    c.sh(SEED);
    let vm = Vm::started(c, Some(fake), 20);
    let logs = vm.c.logs();
    let worker: u32 = logs.lines().find_map(|l| l.strip_prefix("ai-env: shim worker pid ")).and_then(|r| r.split(' ').next()).and_then(|p| p.parse().ok()).unwrap_or_else(|| panic!("no worker pid line:\n{logs}"));
    for pid in [1, worker] {
        let target = vm.c.sh(&format!("readlink /proc/{pid}/fd/5000; true"));
        assert!(target.ends_with("hostname"), "pid {pid} holds the inherited fd 5000: {target:?}");
    }
    let fds = |text: String| text.split_whitespace().map(str::to_string).collect::<Vec<_>>();
    let listing = ["sh", "-c", "ls /proc/$$/fd; true"];
    let mut a = vm.agent();
    assert_eq!(fds(a.out(&Spec::argv(&listing))), ["0", "1", "2"], "the inherited fd 5000 reached the spawn");
    let with_secret = Spec { secret: Some(("DUMMY_SECRET".into(), format!("dummy-{}", SpawnId::new_v7()))), ..Spec::argv(&listing) };
    assert_eq!(fds(a.out(&with_secret)), ["0", "1", "2", "3"], "with a secret: fd 3 only");
}

/// Process groups, each half told apart from the idle sweep (it SIGKILLs
/// every leftover agent-uid process a second after the last leader died, so
/// "the job is gone" alone proves nothing). The leader's death TERMs its
/// group at once: `sleep 300 &` dies by SIGTERM (reaped by init, its parent
/// being dead) and the sweep that follows finds nothing. A `signal` reaches
/// the whole group: a leader that traps TERM runs on (the trap prints `t`)
/// while its background job dies; KILL then ends it. No zombie is left.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_a_spawns_group_dies_with_it_and_leaves_no_zombie() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let mut a = vm.agent();
    let swept = sweeps(&c.logs()).len();
    let out = a.run(&Spec::argv(&["sh", "-c", "sleep 300 & echo $!; exit 0"]), b"").ok("the leader that exits");
    let job: u32 = out.trim().parse().unwrap_or_else(|e| panic!("{e}: {out:?}"));
    let logs = c.wait_log(10, &format!("ai-env: init: reaped orphan {job} "));
    assert!(logs.contains(&format!("ai-env: init: reaped orphan {job} (Signaled(Pid({job}), SIGTERM")), "the leader's death TERMs its group (a SIGKILL is the sweep's):\n{logs}");
    let deadline = Instant::now() + Duration::from_secs(10);
    let killed = loop {
        if let Some(k) = sweeps(&c.logs()).get(swept) {
            break *k;
        }
        assert!(Instant::now() < deadline, "no idle sweep after the leader's death:\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(killed, 0, "the group's TERM left nothing for the sweep after the leader's death:\n{}", c.logs());
    let trapper = "trap 'echo t' TERM; sleep 300 & echo $! > /tmp/ai-env-s6-job; while :; do sleep 0.2; done";
    let (id, leader) = a.spawn(&Spec::argv(&["bash", "-c", trapper])).unwrap_or_else(|e| panic!("{e:?}"));
    let deadline = Instant::now() + Duration::from_secs(10);
    let job: u32 = loop {
        if let Ok(pid) = c.sh("cat /tmp/ai-env-s6-job 2>/dev/null; true").parse() {
            break pid;
        }
        assert!(Instant::now() < deadline, "the background job never started:\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(100));
    };
    a.signal(&id, Sig::Term);
    let deadline = Instant::now() + Duration::from_secs(3);
    while c.alive(job) {
        assert!(Instant::now() < deadline, "the background job {job} outlived the group's TERM:\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(c.alive(leader), "the leader traps TERM and runs on");
    a.signal(&id, Sig::Kill);
    let r = a.collect(&id);
    assert_eq!(r.exit, ExitInfo { code: None, signal: Some(9) }, "{}", String::from_utf8_lossy(&r.stderr));
    assert_eq!(String::from_utf8_lossy(&r.stdout), "t\n", "the TERM reached the leader too: its trap ran once");
    c.wait_gone(5, "sleep");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !c.zombies().is_empty() {
        assert!(Instant::now() < deadline, "defunct processes: {}", c.zombies());
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The killed count of every `idle sweep` line in `logs`, in order.
fn sweeps(logs: &str) -> Vec<u32> {
    logs.lines().filter_map(|l| l.strip_prefix("ai-env: idle sweep: ")).filter_map(|r| r.split(' ').next()?.parse().ok()).collect()
}

/// The idle sweep: a job that left the spawn's process group (bash job
/// control, whose setpgid is done before the shell goes on; the base image
/// has no setsid — L2 runs the setsid escaper) outlives the group's TERM and
/// KILL, and is killed once no spawn is left.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_the_idle_sweep_kills_a_group_escaper() {
    let vm = agent_l1(&[]);
    let (out, err, exit) = vm.run(&["bash", "-c", "set -m; sleep 300 & echo $!; exit 0"], b"");
    assert_eq!(exit, ExitInfo { code: Some(0), signal: None }, "{}", String::from_utf8_lossy(&err));
    assert_swept(&vm.c, &out);
}

/// The escaper whose pid `out` printed is gone within 10 s, killed by the
/// idle sweep: SIGKILL (the group ladder's first signal is TERM), reaped by
/// init, and a sweep line that killed at least one process.
fn assert_swept(c: &Container, out: &[u8]) {
    let pid: u32 = String::from_utf8_lossy(out).trim().parse().unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(out)));
    let deadline = Instant::now() + Duration::from_secs(10);
    while c.alive(pid) {
        assert!(Instant::now() < deadline, "the escaper {pid} outlived the sweep:\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(200));
    }
    let logs = c.wait_log(10, &format!("ai-env: init: reaped orphan {pid} "));
    assert!(logs.contains(&format!("ai-env: init: reaped orphan {pid} (Signaled(Pid({pid}), SIGKILL")), "{logs}");
    let killed = sweeps(&logs);
    assert!(killed.iter().any(|n| *n >= 1), "no sweep killed the escaper: {killed:?}\n{logs}");
}

/// Every path under `/Users/mike` (links not followed) whose owner is not the
/// agent: the agent's tree is all 1000's, whatever spawns and the agent did.
const NOT_THE_AGENTS: &str = "walk() { for p in \"$1\"/* \"$1\"/.[!.]*; do [ -e \"$p\" ] || [ -L \"$p\" ] || continue; \
                              [ \"$(stat -c %u \"$p\")\" = 1000 ] || echo \"$p\"; [ -d \"$p\" ] && [ ! -L \"$p\" ] && walk \"$p\"; done; }; walk /Users/mike; true";

/// The cwd rule: while an agent loop swaps `/Users/mike/w` between a
/// directory and a symlink to /etc (removing what it can, renaming away what
/// it cannot), 30 spawns ask for the fresh cwd `/Users/mike/w/a/b` (each
/// runs, or gets `spawn_err cwd`: the agent may not write /etc). No root
/// filesystem operation touches the agent's paths: nothing under
/// `/Users/mike` is anyone's but the agent's; /etc, `/usr/local/bin/claude`
/// and `/usr/local/bin/ai-env` keep their owner and mode, and nothing new is
/// in /etc. A long spawn stays alive meanwhile: the idle sweep (on the last
/// spawn's exit) would kill the loop.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_cwd_rule_holds_under_a_symlink_swap() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let stat = || c.sh("stat -c '%a %u:%g %n' /etc /usr/local/bin/claude /usr/local/bin/ai-env");
    let etc = || c.sh("ls -A /etc");
    let (stat0, etc0) = (stat(), etc());
    assert!(stat0.starts_with("755 0:0 /etc\n755 0:0 /usr/local/bin/claude\n"), "{stat0}");
    let mut a = vm.agent();
    let (anchor, anchor_pid) = a.spawn(&Spec { grace: Some(60), ..Spec::argv(&["sleep", "300"]) }).unwrap_or_else(|e| panic!("{e:?}"));
    let swap = "echo $$ > /tmp/ai-env-s6-swap.pid; cd /Users/mike || exit 1; n=0; \
                while [ ! -e /tmp/ai-env-s6-stop ]; do n=$((n+1)); rm -rf w 2>/dev/null || mv w w.$n; mkdir w 2>/dev/null; \
                rm -rf w 2>/dev/null || mv w w.$n.d; ln -s /etc w 2>/dev/null; done";
    assert!(docker(&["exec", "-d", "-u", "1000", &c.id, "timeout", "120", "sh", "-c", swap]).status.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    while c.exec(&["test", "-s", "/tmp/ai-env-s6-swap.pid"]).status.code() != Some(0) {
        assert!(Instant::now() < deadline, "the swap loop never started");
        std::thread::sleep(Duration::from_millis(100));
    }
    let looping: u32 = c.sh("cat /tmp/ai-env-s6-swap.pid").parse().unwrap();
    let (mut ran, mut refused) = (0, 0);
    for _ in 0..30 {
        match a.spawn(&Spec { cwd: Some("/Users/mike/w/a/b".into()), ..Spec::argv(&["sh", "-c", "pwd"]) }) {
            Ok((id, _)) => {
                a.feed(&id, b"");
                a.collect(&id);
                ran += 1;
            }
            Err((SpawnErrCode::Cwd, _)) => refused += 1,
            Err(other) => panic!("a spawn neither ran nor was refused for its cwd: {other:?}"),
        }
    }
    assert!(c.alive(looping), "the swap loop ran through all 30 spawns");
    c.sh("touch /tmp/ai-env-s6-stop");
    a.detach(&anchor, true);
    let deadline = Instant::now() + Duration::from_secs(5);
    while c.alive(anchor_pid) || c.alive(looping) {
        assert!(Instant::now() < deadline, "the anchor (final detach) or the loop (stop file) did not end:\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(100));
    }
    let stray = c.exec_as("0", &["bash", "-c", NOT_THE_AGENTS]);
    assert!(stray.status.success() && stray.stdout.is_empty(), "paths under /Users/mike that are not the agent's:\n{}", String::from_utf8_lossy(&stray.stdout));
    assert_eq!(stat(), stat0, "owner and mode unchanged");
    assert_eq!(etc(), etc0, "nothing new in /etc");
    eprintln!("cwd swap: {ran} spawns ran, {refused} refused (cwd)");
}

/// `/suspend` freezes a lost socket's detach grace: `sleep 30` with a 2 s
/// grace outlives 4 s suspended, and is TERMed once the grace left at the
/// freeze has run after `/resume`. The grace left is 2 s less the time from
/// the loss to the freeze (a `docker port` call and a POST through Docker's
/// proxy); every time is measured on the shim's own log lines.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_suspend_freezes_the_detach_grace() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let mut a = vm.agent();
    let (id, pid) = a.spawn(&Spec { grace: Some(2), ..Spec::argv(&["sleep", "30"]) }).unwrap_or_else(|e| panic!("{e:?}"));
    // No detach frame: a lost socket, whose grace starts.
    drop(a);
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/suspend"), "{}").0, 200);
    std::thread::sleep(Duration::from_secs(4));
    let timed = c.timed_logs();
    let (lost, frozen) = (logged_at(&timed, &format!("ai-env: spawn {id} lost connection")), logged_at(&timed, "ai-env: spawns frozen"));
    // A loss noticed after the freeze starts its grace frozen: all 2 s are left.
    let left = 2.0 - (frozen - lost).max(0.0);
    assert!(left > 0.5, "the freeze came {:.2} s after the loss: too little of the 2 s grace was left to measure", frozen - lost);
    assert!(c.alive(pid), "the grace ran while suspended:\n{}", c.logs());
    let d = vm.detail();
    let sp = d.spawns.iter().find(|s| s.status.spawn_id == id).unwrap_or_else(|| panic!("{id} in {:?}", d.spawns));
    assert!(sp.frozen && sp.detach_left_s.is_some_and(|s| s <= 2), "{sp:?}");
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/resume"), "{}").0, 200);
    c.wait_log(10, &format!("ai-env: spawn {id} detach grace over"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while c.alive(pid) {
        assert!(Instant::now() < deadline, "the sleep outlived its grace:\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(200));
    }
    let timed = c.timed_logs();
    let (thawed, over) = (logged_at(&timed, "ai-env: spawns thawed"), logged_at(&timed, &format!("ai-env: spawn {id} detach grace over")));
    assert!(((over - thawed) - left).abs() < 0.5, "TERM {:.2} s after /resume, {left:.2} s of the grace were left at the freeze", over - thawed);
    assert!(over - lost >= 5.5, "TERM {:.2} s after the socket was lost: the 4 s suspended must not count against the 2 s grace", over - lost);
}

/// When the first line holding `needle` was logged, from [`Container::timed_logs`].
fn logged_at(timed: &[(f64, String)], needle: &str) -> f64 {
    timed.iter().find(|(_, l)| l.contains(needle)).map(|(t, _)| *t).unwrap_or_else(|| panic!("{needle:?} not logged"))
}

/// `/suspend` with the socket still attached (the usual case): the shim
/// freezes first, then closes the socket itself (event `hook_suspend`, close
/// 1001), so the loss comes AFTER the freeze and its grace starts frozen: the
/// lost line says `(frozen)`, `sleep 30` with a 2 s grace outlives 4 s
/// suspended with all 2 s left, and is TERMed 2 s after `/resume`. The client
/// reads meanwhile and goes at the close: its socket ends at once, well
/// within the second the hook waits for it (a silent client's ends only as
/// that wait runs out, and a close-then-freeze order could pass unseen).
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_suspend_freezes_the_grace_of_the_socket_it_closes() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let mut a = vm.agent();
    let (id, pid) = a.spawn(&Spec { grace: Some(2), ..Spec::argv(&["sleep", "30"]) }).unwrap_or_else(|e| panic!("{e:?}"));
    let reader = std::thread::spawn(move || {
        let mut told = false;
        loop {
            match a.next() {
                Ok(Frame::Event { kind: EventKind::HookSuspend, .. }) => told = true,
                Ok(_) => {}
                // `a` goes here: its end of the socket closes with it.
                Err(code) => return (told, code),
            }
        }
    });
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/suspend"), "{}").0, 200);
    assert_eq!(reader.join().expect("the client's reader"), (true, Some(1001)), "the suspend's event, then its close");
    let needle = format!("ai-env: spawn {id} lost connection");
    let logs = c.wait_log(5, &needle);
    let lost = logs.lines().find(|l| l.starts_with(&needle)).unwrap_or_default();
    assert!(lost.ends_with(" (frozen)"), "the suspend's own close came after the freeze: {lost}");
    std::thread::sleep(Duration::from_secs(4));
    assert!(c.alive(pid), "the grace ran while suspended:\n{}", c.logs());
    let d = vm.detail();
    let sp = d.spawns.iter().find(|s| s.status.spawn_id == id).unwrap_or_else(|| panic!("{id} in {:?}", d.spawns));
    assert!(sp.frozen && sp.detach_left_s == Some(2), "the whole grace is left: {sp:?}");
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/resume"), "{}").0, 200);
    c.wait_log(10, &format!("ai-env: spawn {id} detach grace over"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while c.alive(pid) {
        assert!(Instant::now() < deadline, "the sleep outlived its grace:\n{}", c.logs());
        std::thread::sleep(Duration::from_millis(200));
    }
    let timed = c.timed_logs();
    let (thawed, over) = (logged_at(&timed, "ai-env: spawns thawed"), logged_at(&timed, &format!("ai-env: spawn {id} detach grace over")));
    assert!(((over - thawed) - 2.0).abs() < 0.5, "TERM {:.2} s after /resume, not the whole 2 s grace", over - thawed);
}

/// V6 tested from inside, before `/run` (the build VM): the platform's
/// `/validate` (root, a live socket) passes, and the V6 line names the
/// self-test's two refused `hook resume` lines (curl as uid 1000 through
/// 127.0.0.1 and through the VM's own address); a uid-1000 `/validate`
/// fails V6 alone. Once `/run` was accepted, `/validate` answers 409 at once
/// to anyone, and no check runs (no `validate` line follows).
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_validate_self_tests_the_guard() {
    let (c, _fake) = agent_l1_ready(&[]);
    let url = format!("http://127.0.0.1:9000{PREFIX}/validate");
    let (s, body) = c.curl("0", &["-X", "POST", &url]);
    assert_eq!(s, 200, "{body}\n{}", c.logs());
    assert_v6_named(&c.logs(), &c.ip(), "the platform's /validate socket is uid 0 inode ");
    let (s, body) = c.curl("1000", &["-X", "POST", &url]);
    assert_eq!(s, 503, "{body}");
    assert!(body.contains("V6: the /validate request's socket is owned by the agent uid 1000"), "{body}");
    for v in ["V1:", "V2:", "V3:", "V4:"] {
        assert!(!body.contains(v), "only V6 fails: {body}");
    }
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/run"), &run_body("mvm-agent", Some(&payload_for(&session_token(), "mike@mbp")))).0, 200);
    let checks = |logs: &str| logs.lines().filter(|l| l.starts_with("ai-env: validate ")).count();
    let before = checks(&c.logs());
    for user in ["1000", "0"] {
        let (s, body) = c.curl(user, &["-X", "POST", &url]);
        assert_eq!((s, body.as_str()), (409, "{\"status\":\"already run\"}"), "uid {user} after /run");
    }
    let logs = c.logs();
    assert_eq!(checks(&logs), before, "no check ran after /run:\n{logs}");
    assert_eq!(hook_lines(&logs, "validate").iter().filter(|l| l.contains(" status=409 ")).count(), 2, "{logs}");
}

/// The last `validate V6 ok` line starts its detail with `platform`, and
/// names two `hook resume` lines — 127.0.0.1 and `vm_ip` — each refused 403
/// as the agent's.
fn assert_v6_named(logs: &str, vm_ip: &str, platform: &str) {
    let v6 = logs.lines().filter_map(|l| l.strip_prefix("ai-env: validate V6 ok ")).next_back().unwrap_or_else(|| panic!("no V6 ok line:\n{logs}"));
    assert!(v6.starts_with(platform), "{v6}");
    let peers: Vec<&str> = v6.split("(its hook line: peer=").skip(1).filter_map(|r| r.split(')').next()).collect();
    assert_eq!(peers.len(), 2, "{v6}");
    assert!(peers[0].starts_with("127.0.0.1:") && peers[1].starts_with(&format!("{vm_ip}:")), "{peers:?}");
    for p in peers {
        let line = logs.lines().find(|l| l.starts_with(&format!("ai-env: hook resume peer={p} "))).unwrap_or_else(|| panic!("no hook line for {p}:\n{logs}"));
        assert!(line.contains(" status=403 ") && line.contains(" peer_uid=1000 ") && line.ends_with(" decision=refuse:agent_uid"), "{line}");
    }
}

/// With the hooks guard replaced by `--hook-source log`, `/validate` (on the
/// build VM: before `/run`) fails V6 alone, so such an image never becomes
/// ACTIVE.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_validate_fails_with_the_hooks_guard_off() {
    let (c, _fake) = agent_l1_ready(&[("--hook-source", "log")]);
    let cmdline = c.sh("tr '\\0' ' ' < /proc/1/cmdline");
    let args: Vec<&str> = cmdline.split_whitespace().collect();
    assert_eq!(args.iter().filter(|a| **a == "--hook-source").count(), 1, "replaced, not repeated: {cmdline}");
    assert!(args.windows(2).any(|w| w == ["--hook-source", "log"]), "{cmdline}");
    let (s, body) = http(c.port(9000), "POST", &format!("{PREFIX}/validate"), "");
    assert_eq!(s, 503, "{body}");
    assert!(body.contains("V6: the hooks guard is off (--hook-source log)"), "{body}");
    for v in ["V1:", "V2:", "V3:", "V4:"] {
        assert!(!body.contains(v), "only V6 fails: {body}");
    }
}

// ---- S7 agent L1: the credential cache -------------------------------------------------
//
// The root shim caches a `credential` frame and delivers it to a uid-1000
// spawn on fd 3; a spawn cannot read the shim's memory, environ or maps;
// `/suspend` drops the cache before it answers; and the value is on no file,
// command line or environment. The raw wire client ([`Agent`]) stands in for
// the Mac here (the shim-only world has no Mac transport);
// `tests/docker_exec.rs` drives the real `ai-env vm exec --with-credential`
// on L2.

/// The name the Mac delivers the setup-token under (the shim's env-name rule).
const CRED: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// A stand-in credential built at run time with a per-test tail: no token
/// shape, nothing real, and unique enough for a leak scan to look for.
fn dummy_credential(test: &str) -> String {
    format!("dummy-credential-{test}-{}", SpawnId::new_v7())
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
    /// Every file of the container holding one of `needles`, as
    /// [`DISK_SCAN`] lists them (paths only). A canary, planted NUL-framed at
    /// [`CANARY_PATH`] and looked for with them, must be the one extra hit and
    /// grep's status 0: a scan that skipped binary files, lost its patterns,
    /// failed or ran out of time never passes for "found nothing".
    fn disk_hits(&self, needles: &[&str]) -> Vec<String> {
        let canary = format!("ai-env-scan-canary-{}", SpawnId::new_v7());
        self.sh(&format!("printf '\\0%s\\0' {canary} > {CANARY_PATH}"));
        let mut patterns = String::new();
        for n in needles.iter().copied().chain([canary.as_str()]) {
            patterns.push_str(n);
            patterns.push('\n');
        }
        let out = self.exec_input("0", &["sh", "-c", DISK_SCAN], patterns.as_bytes());
        self.sh(&format!("rm -f {CANARY_PATH}"));
        let mut hits: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect();
        let status = hits.pop().unwrap_or_default();
        let canaries = hits.iter().filter(|h| *h == CANARY_PATH).count();
        assert!(status == "rc=0" && canaries == 1, "the scan did not finish clean with its canary found once ({status}, {canaries}; hits {hits:?}): {}", String::from_utf8_lossy(&out.stderr));
        hits.retain(|h| h != CANARY_PATH);
        hits
    }

    /// How many lines of the container's command lines and environments hold
    /// one of `needles`. [`PROC_DUMP`] runs in a privileged exec: an agent
    /// process's environ asks its reader for CAP_SYS_PTRACE, which root under
    /// Docker's default capabilities lacks (`Permission denied`). The lines
    /// are matched here, so no needle rides an argv in the container. No read
    /// may be refused, and the dump must hold PID 1's program, a `PATH=` and
    /// each line of `expect` (what shows it read the processes meant).
    fn proc_hits(&self, needles: &[&str], expect: &[&str]) -> usize {
        let out = docker(&["exec", "--privileged", "-u", "0", &self.id, "sh", "-c", PROC_DUMP]);
        assert!(out.status.success(), "the process dump: {}", String::from_utf8_lossy(&out.stderr));
        let dump = String::from_utf8_lossy(&out.stdout);
        let refused: Vec<&str> = dump.lines().filter(|l| l.starts_with("refused /proc/")).collect();
        assert!(refused.is_empty(), "the dump was refused {refused:?}");
        for line in ["/usr/local/bin/ai-env"].iter().chain(expect) {
            assert!(dump.lines().any(|l| l == *line), "the dump has no line {line:?} ({} lines)", dump.lines().count());
        }
        assert!(dump.lines().any(|l| l.starts_with("PATH=")), "the dump read no environment ({} lines)", dump.lines().count());
        dump.lines().filter(|l| needles.iter().any(|n| l.contains(n))).count()
    }
}

/// S7 T7.3 shape in Docker: the root shim caches a `credential` frame, and a
/// spawn as uid 1000 (the image's agent) that names it reads the value on fd 3
/// byte-exact — `<NAME>_FILE_DESCRIPTOR=3`, and nothing named
/// CLAUDE_CODE_OAUTH_TOKEN in its environment. `/health/detail` shows
/// has_credentials, the name and the tag, and counts a live credentialed spawn
/// as a holder, and no longer once it has exited. The value never reaches the
/// shim's log.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_credential_cached_by_root_is_delivered_to_the_uid_1000_spawn_on_fd_3() {
    let vm = agent_l1(&[]);
    let mut a = vm.agent();
    let value = dummy_credential("fd3");
    a.deliver(CRED, &value, Some("seal-dl1"));
    let d = vm.detail();
    assert!(d.has_credentials, "the root shim cached it");
    assert_eq!(
        (d.credential.credential_name.as_deref(), d.credential.credential_tag.as_deref(), d.credential.credential_holders),
        (Some(CRED), Some("seal-dl1"), 0),
        "the view names the credential, not its value: {:?}",
        d.credential
    );
    assert!(d.credential.credential_at.is_some(), "{:?}", d.credential);
    // A spawn (uid 1000) names the cached credential: the value is on fd 3
    // only, delivery is named by <NAME>_FILE_DESCRIPTOR, and the variable
    // itself is not in the environment.
    let script = "id -u; cat <&3; echo; echo \"$CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR\"; env | grep -c '^CLAUDE_CODE_OAUTH_TOKEN=' || true";
    let out = a.out(&Spec { credential: Some(CRED.to_string()), ..Spec::argv(&["sh", "-c", script]) });
    assert!(out == format!("1000\n{value}\n3\n0\n"), "the uid-1000 spawn read the {} value bytes on fd 3 with the var absent from its environ", value.len());
    // A long-lived credentialed spawn is a holder while it lives.
    let (hid, _) = a.spawn(&Spec { credential: Some(CRED.to_string()), ..Spec::argv(&["cat"]) }).unwrap_or_else(|e| panic!("holder spawn: {e:?}"));
    let d = vm.detail();
    assert_eq!((d.has_credentials, d.credential.credential_name.as_deref(), d.credential.credential_holders), (true, Some(CRED), 1), "one live holder: {:?}", d.credential);
    a.feed(&hid, b"");
    assert_eq!(a.collect(&hid).exit, ExitInfo { code: Some(0), signal: None });
    // The exit still counts until the shim takes collect's ack, which a new
    // HTTP request may overtake: its zombie leader keeps the group alive
    // until it is reaped, a second after its death. Polled, as in shim_local.
    let t = Instant::now();
    let mut holders = vm.detail().credential.credential_holders;
    while holders != 0 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
        holders = vm.detail().credential.credential_holders;
    }
    assert_eq!(holders, 0, "the exited holder is off the count within 5 s");
    assert!(!vm.c.logs().contains(&value), "the credential reached the shim's log");
}

/// S7: the cached credential lives in the shim's memory (the worker's, a
/// child of the PID 1 supervisor). A spawn — the agent as the shim makes it,
/// uid and gid 1000 under NO_NEW_PRIVS — cannot open either process's
/// `/proc/<pid>/environ` or `/proc/<pid>/mem`: both are root's, 0400 and
/// 0600, so their file mode refuses the agent before any other check. Nor
/// its `/proc/<pid>/maps`: 0444 passes the file mode, and the kernel's ptrace
/// access check (read mode) refuses the agent's uid, the uid rule an attach
/// meets too. The same spawn reads its own environ and maps, so each refusal
/// is the target's. No PTRACE_ATTACH is made (the base image has no
/// debugger, tracer or interpreter to make one): an attach is not tested.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_agent_uid_cannot_read_the_shims_memory_or_environ() {
    let vm = agent_l1(&[]);
    let mut a = vm.agent();
    let value = dummy_credential("proc");
    a.deliver(CRED, &value, Some("seal-proc"));
    assert!(vm.detail().has_credentials, "the worker holds the value in memory");
    let logs = vm.c.logs();
    let worker: u32 = logs
        .lines()
        .find_map(|l| l.strip_prefix("ai-env: shim worker pid "))
        .and_then(|r| r.split(' ').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no worker pid line:\n{}", logs.replace(&value, &format!("<{} bytes>", value.len()))));
    assert!(worker != 1, "the worker is a child of the PID 1 supervisor, got {worker}");
    assert_eq!(vm.c.sh("cat /proc/1/comm"), "ai-env", "PID 1 is the root shim");
    let nodes: Vec<String> = [1, worker].iter().flat_map(|p| ["environ", "mem", "maps"].map(|n| format!("/proc/{p}/{n}"))).collect();
    let modes = vm.c.sh(&format!("stat -c '%a %u' {}", nodes.join(" ")));
    assert_eq!(modes.lines().collect::<Vec<_>>(), ["400 0", "600 0", "444 0", "400 0", "600 0", "444 0"], "mode and owner of {}", nodes.join(" "));
    // One byte of each through a spawn: dd's status, then its complaint if any.
    let probe = format!("for n in {} /proc/self/environ /proc/self/maps; do err=$(dd if=$n of=/dev/null bs=1 count=1 status=none 2>&1); echo \"$n rc=$?${{err:+ $err}}\"; done", nodes.join(" "));
    let out = a.out(&Spec::argv(&["sh", "-c", &probe]));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), nodes.len() + 2, "{out}");
    for (node, line) in nodes.iter().zip(&lines) {
        assert!(line.starts_with(&format!("{node} rc=1 ")) && line.ends_with(": Permission denied"), "the agent opened {node}: {line}");
    }
    assert_eq!(lines[nodes.len()..], ["/proc/self/environ rc=0", "/proc/self/maps rc=0"], "the agent reads its own");
    assert!(vm.detail().has_credentials, "the shim kept the value");
}

/// S7 D3 in Docker: `/suspend` (POSTed through the published hooks port, the
/// way the platform's proxy reaches it from outside the VM's netns — the peer
/// guard admits a remote caller with no row) drops the cached credential before
/// its 200, so `/health/detail` reads has_credentials false; a `credential`
/// frame sent while suspended is refused `suspended` and never carries the
/// value; `/resume` reopens the cache empty, and it accepts a credential again.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_suspend_drops_the_cache_before_answering_and_resume_reopens_empty() {
    let vm = agent_l1(&[]);
    let mut a = vm.agent();
    let value = dummy_credential("suspend");
    a.deliver(CRED, &value, Some("seal-susp"));
    assert!(vm.detail().has_credentials, "cached before the suspend");
    assert_eq!(http(vm.c.port(9000), "POST", &format!("{PREFIX}/suspend"), "{}").0, 200);
    assert!(!vm.detail().has_credentials, "the cache was dropped before /suspend answered 200");
    // A fresh socket (the suspend closed the first): a delivery is refused `suspended`.
    let mut b = vm.agent();
    let (code, message) = b.credential_refused(CRED, &value);
    assert_eq!(code, CredentialErrCode::Suspended, "a delivery while suspended");
    assert!(!message.contains(&value), "the refusal's message ({} bytes) holds the value", message.len());
    assert_eq!(http(vm.c.port(9000), "POST", &format!("{PREFIX}/resume"), "{}").0, 200);
    assert!(!vm.detail().has_credentials, "resume reopens the cache empty");
    let mut c = vm.agent();
    c.deliver(CRED, &value, None);
    assert!(vm.detail().has_credentials, "a delivery after resume caches again");
    assert!(!vm.c.logs().contains(&value), "no suspend/resume path logged the value");
    drop((a, b, c));
}

/// S7: after a delivery and a credentialed spawn, with a credentialed holder
/// still live, the dummy is on no file of the container — binary files
/// included, and /dev/shm ([`Container::disk_hits`], its canary found) — and
/// on no process's command line or environment, the live holder's own
/// included ([`Container::proc_hits`] must read its
/// `<NAME>_FILE_DESCRIPTOR=3`): the custody path keeps the value in the
/// shim's memory and the fd-3 pipe alone. No scan puts the value on an argv
/// in the container: the disk scan reads it on stdin, the process dump is
/// matched here.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_no_scan_finds_the_cached_credential_on_disk_or_in_a_cmdline() {
    let vm = agent_l1(&[]);
    let mut a = vm.agent();
    let value = dummy_credential("scan");
    a.deliver(CRED, &value, Some("seal-scan"));
    let read = a.out(&Spec { credential: Some(CRED.to_string()), ..Spec::argv(&["sh", "-c", "cat <&3"]) });
    assert!(read == value, "the fd-3 read returned {} bytes, not the value's {}", read.len(), value.len());
    let (hid, _) = a.spawn(&Spec { credential: Some(CRED.to_string()), ..Spec::argv(&["cat"]) }).unwrap_or_else(|e| panic!("holder spawn: {e:?}"));
    assert_eq!(vm.detail().credential.credential_holders, 1, "a credentialed spawn is live during the scan");
    let on_disk = vm.c.disk_hits(&[&value]);
    assert!(on_disk.is_empty(), "the credential is on disk in {on_disk:?}");
    let in_procs = vm.c.proc_hits(&[&value], &[&format!("{CRED}_FILE_DESCRIPTOR=3")]);
    assert_eq!(in_procs, 0, "the credential is on {in_procs} command line or environment line(s)");
    eprintln!("L1 credential scan: disk 0 (canary found), command lines and environments 0 (the live holder's read)");
    a.feed(&hid, b"");
    a.collect(&hid);
}

// ---- L2: the locally built image ---------------------------------------------------------

fn l2() -> Container {
    require_enabled();
    let image = local_image();
    let out = docker(&["image", "inspect", &image]);
    assert!(out.status.success(), "{image} is missing: run make image-build-local");
    Container::start(&[], &image, &[])
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l2_claude_version_matches_the_lock() {
    let c = l2();
    let started = Instant::now();
    wait_ready(&c, 120);
    let probe = c.wait_log(5, "claude probe ok");
    let line = probe.lines().find(|l| l.contains("claude probe ok")).unwrap().to_string();
    let (_, h) = http(c.port(8080), "GET", "/health", "");
    let h: Health = serde_json::from_str(&h).unwrap();
    assert_eq!(h.claude_version, Some(lock_version()));
    eprintln!("L2 ready after {:?}; {line}", started.elapsed());
}

/// `/validate` passes from the host (outside the VM: admitted without a
/// lookup, noted) and from inside as root (a live root socket); both V6
/// lines name the self-test's two refused hook lines.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_validate_200() {
    let c = l2();
    wait_ready(&c, 120);
    let (s, body) = http(c.port(9000), "POST", &format!("{PREFIX}/validate"), "");
    assert_eq!(s, 200, "{body}\n{}", c.logs());
    let logs = c.logs();
    for v in ["V1 ok", "V2 ok", "V3 ok", "V4 ok", "V5 ok", "V6 ok"] {
        assert!(logs.contains(&format!("ai-env: validate {v}")), "{v}:\n{logs}");
    }
    assert!(logs.contains("ai-env: validate V3 ok 2 settings files parse and are readable by 1000:1000;"), "the agent is 1000:1000 (the --gid default):\n{logs}");
    let ip = c.ip();
    assert_v6_named(&logs, &ip, "the platform's /validate request came from outside this VM (admitted without a lookup); ");
    let (s, body) = c.curl("0", &["-X", "POST", &format!("http://127.0.0.1:9000{PREFIX}/validate")]);
    assert_eq!(s, 200, "{body}\n{}", c.logs());
    assert_v6_named(&c.logs(), &ip, "the platform's /validate socket is uid 0 inode ");
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l2_no_build_time_state() {
    let c = l2();
    wait_ready(&c, 120);
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/validate"), "").0, 200);
    let diff = ok_stdout(&["diff", &c.id]);
    let unexpected: Vec<&str> = diff.lines().filter(|l| !matches!(*l, "C /tmp")).collect();
    assert!(unexpected.is_empty(), "the running shim changed the image filesystem: {unexpected:?}");
    assert_eq!(c.sh("ls -A /root | grep -c '^\\.claude' || true"), "0", "no /root/.claude*");
    assert_eq!(c.sh("test ! -s /etc/machine-id && echo empty-or-absent"), "empty-or-absent");
    assert_eq!(
        c.sh("cd /Users/mike/.claude && find . -mindepth 1 | LC_ALL=C sort | tr '\\n' ' '"),
        "./.claude.json ./CLAUDE.md ./agents ./commands ./settings.json ./skills",
        "the whole baked tree: the three directories are empty"
    );
    assert_eq!(c.sh("cat /Users/mike/.claude.json"), "{\"hasCompletedOnboarding\":true,\"projects\":{}}");
    assert_eq!(c.sh("git config --system --get user.name"), "claude-agent");
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l2_modes_and_owner() {
    let c = l2();
    wait_ready(&c, 120);
    let got = c.sh(
        "stat -c '%a %u:%g %n' /Users/mike /Users/mike/.claude /Users/mike/.claude/.claude.json /Users/mike/.claude.json \
         /Users/mike/.claude/settings.json /Users/mike/.claude/CLAUDE.md /Users/mike/.claude/agents \
         /etc/claude-code/managed-settings.json /etc/ai-env/claude.lock /usr/local/bin/claude /usr/local/bin/ai-env",
    );
    let want = "700 1000:1000 /Users/mike\n700 1000:1000 /Users/mike/.claude\n600 1000:1000 /Users/mike/.claude/.claude.json\n\
                600 1000:1000 /Users/mike/.claude.json\n644 1000:1000 /Users/mike/.claude/settings.json\n\
                644 1000:1000 /Users/mike/.claude/CLAUDE.md\n755 1000:1000 /Users/mike/.claude/agents\n\
                644 0:0 /etc/claude-code/managed-settings.json\n644 0:0 /etc/ai-env/claude.lock\n755 0:0 /usr/local/bin/claude\n755 0:0 /usr/local/bin/ai-env";
    let norm = |s: &str| s.lines().map(str::trim).collect::<Vec<_>>().join("\n");
    assert_eq!(norm(&got), norm(want));
    // D6 in the built image, not only in the repo file.
    let managed: serde_json::Value = serde_json::from_str(&c.sh("cat /etc/claude-code/managed-settings.json")).unwrap();
    assert_eq!(ai_env_cli::wire::managed::hardening_gaps(&managed), Vec::<String>::new(), "{managed}");
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l2_dig_for_the_egress_check() {
    // S5: `ai-env egress check` and the dns-path probe run dig (bind-utils) in the VM.
    let c = l2();
    let v = c.sh("dig -v 2>&1");
    assert!(v.starts_with("DiG 9."), "{v}");
    assert_eq!(c.sh("command -v curl"), "/usr/bin/curl", "curl too");
}

/// The hooks' children (the probes, `/validate`'s claude and curl) are all
/// reaped. `/validate` runs before `/run`, as on the build VM: after it the
/// hook answers 409 and starts nothing.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_no_defunct() {
    let c = l2();
    wait_ready(&c, 120);
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/validate"), "").0, 200);
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/run"), &run_body("mvm-z", Some(&payload("mike@mbp")))).0, 200);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(c.zombies(), "", "{}", c.logs());
}

/// T6.7 offline: the real, pinned claude through `/agent` (as uid 1000, HOME
/// and the config dir the image's) prints exactly the lock's version line.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_claude_version_through_the_agent() {
    let vm = Vm::started(l2(), None, 120);
    let (out, err, exit) = vm.run(&["claude", "--version"], b"");
    assert_eq!(exit, ExitInfo { code: Some(0), signal: None }, "{}", String::from_utf8_lossy(&err));
    assert_eq!(String::from_utf8_lossy(&out), format!("{} (Claude Code)\n", lock_version()));
    assert!(!vm.c.logs().contains(&vm.token), "the session token reached the log");
}

/// The idle sweep in the real image: a `setsid` escaper leaves the spawn's
/// session and group, outlives the group's TERM and KILL, and is killed once
/// no spawn is left. The leader waits a second before it exits: setsid(1)
/// leaves the group only once it runs, and an escaper still in the group
/// when the leader dies goes with the group's TERM.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_a_setsid_escaper_is_swept() {
    let vm = Vm::started(l2(), None, 120);
    let (out, err, exit) = vm.run(&["sh", "-c", "setsid sleep 300 & echo $!; sleep 1"], b"");
    assert_eq!(exit, ExitInfo { code: Some(0), signal: None }, "{}", String::from_utf8_lossy(&err));
    assert_swept(&vm.c, &out);
    assert_eq!(vm.c.exec(&["pgrep", "-x", "sleep"]).status.code(), Some(1), "no sleep is left");
}
