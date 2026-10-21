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
//! S8 L1, the workspace helper as the agent on Linux: a transcript `PUT
//! /transcript` writes (0600, the agent's, in 0700 directories it made), a
//! symlink the agent planted refused with 409; and with a script standing
//! for the helper (`--helper`), a helper past its budget has its session
//! ended (`/proc` and pidfds), and one running holds the idle sweep off.
//! S10 agent L1 (image 12.0's VM side, through the same raw client): the
//! park (`park_v1`) as root on Linux with the agent's spawn — refused `busy`
//! while a process of the spawn's session runs, and on the session's CPU
//! alone while its leader spins, `parked` once it is quiet (a process of the
//! session alive and asleep), `unpark`, and a parked spawn whose socket is
//! lost living its park grace;
//! R1, a tail's URL kept by the root shim after curl got no status or S3 a
//! 5xx (the S9 fake curl as the shim's `--curl`) and pushed again at the
//! next hook; the guest's memory (`MemTotal`) in `/health` and the run report.
//! L2: the locally built image (`make image-build-local`) with the real,
//! pinned claude — the version gate, `/validate` (from the host and from
//! inside), no build-time state, modes, and (S6) `claude --version` and a
//! `setsid` escaper through `/agent`; (S10) such an escaper makes a park
//! `busy` while it spins and nothing once it sleeps (V-6), and
//! `/var/lib/ai-env` is root's, 0700 and empty.
//! The only claude ever executed is the pinned Linux binary inside L2.
#[path = "common/curl.rs"]
mod curl;

use ai_env_cli::wire::chunk::{decode, Chunker};
use ai_env_cli::wire::frame::{ClientInfo, CredentialErrCode, Deliver, EventKind, ExitInfo, Frame, Health, HealthDetail, HealthStatus, RunHookPayload, Scope, Sig, SpawnErrCode, SpawnId};
use ai_env_cli::wire::frame::{ParkOwner, ParkRefusal, SpawnDetail, CAP_PARK_V1};
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
    l1_with(fake_dir(conf), docker_args, flags)
}

/// [`l1`] with its fake dir made by the test (which may add to it before
/// the container mounts it at /opt/fake).
fn l1_with(fake: tempfile::TempDir, docker_args: &[&str], flags: &[(&str, &str)]) -> (Container, tempfile::TempDir) {
    require_enabled();
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
    agent_l1_ready_with(fake_dir(&format!("VERSION={}\n", lock_version())), flags)
}

/// [`agent_l1_ready`] with its fake dir made by the test ([`l1_with`]).
fn agent_l1_ready_with(fake: tempfile::TempDir, flags: &[(&str, &str)]) -> (Container, tempfile::TempDir) {
    let image = std::fs::canonicalize(Path::new(REPO).join("image")).unwrap();
    let image_mount = format!("{}:/opt/image:ro", image.display());
    let (c, fake) = l1_with(fake, &["-v", &image_mount], flags);
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
    /// `hello_ok.caps`: what the shim can do beyond wire v1's core.
    caps: Vec<String>,
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
        let mut a = Agent { rt, ws, caps: Vec::new() };
        let client = ClientInfo { name: "shim_docker".into(), version: env!("CARGO_PKG_VERSION").into(), host: "test@docker".into() };
        a.send(&Frame::Hello { session_token: Secret::new(token.to_string()), client, resume: vec![], idle_s: None });
        match a.next() {
            Ok(Frame::HelloOk { wire, run_hook_seen, has_credentials, caps, .. }) => {
                assert_eq!((wire, run_hook_seen, has_credentials), (1, true, false));
                a.caps = caps;
            }
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

    /// S10 (`park_v1`): `park` the spawn `id` with the park grace `grace_s`
    /// and the busy check's window `min_quiet_s` ([`CPU_BUSY_MS`],
    /// [`PARK_OWNER`], stdout not held), as the Mac's session would: the
    /// shim's answer, `parked` or `park_refused`. Frames about other spawns,
    /// pongs and events are skipped.
    fn park(&mut self, id: &SpawnId, grace_s: u32, min_quiet_s: u32) -> Frame {
        self.send(&Frame::Park { spawn_id: id.clone(), grace_s, min_quiet_s, cpu_busy_ms: CPU_BUSY_MS, hold_output: false, owner: PARK_OWNER });
        loop {
            match self.next() {
                Ok(f @ (Frame::Parked { .. } | Frame::ParkRefused { .. })) if f.spawn_id() == Some(id) => return f,
                Ok(f @ Frame::Error { .. }) => panic!("{f:?} while parking {id}"),
                Ok(f) if f.spawn_id() != Some(id) => {}
                other => panic!("parked or park_refused for {id}, got {other:?}"),
            }
        }
    }

    /// [`Agent::park`] (a window of 0: the look at the park alone) once a
    /// second until the shim parks `id`, within `within`; every answer before
    /// it must be a `busy` refusal. The `parked` answer, and how many
    /// refusals came first.
    fn park_when_quiet(&mut self, id: &SpawnId, grace_s: u32, within: Duration) -> (Frame, usize) {
        let deadline = Instant::now() + within;
        let mut refused = 0;
        loop {
            match self.park(id, grace_s, 0) {
                f @ Frame::Parked { .. } => return (f, refused),
                Frame::ParkRefused { reason: ParkRefusal::Busy, .. } if Instant::now() < deadline => refused += 1,
                other => panic!("parked within {within:?} ({refused} busy refusal(s) before), got {other:?}"),
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// S10: `unpark` the spawn `id` (it has no answer), then a `ping`: its
    /// `pong` shows the shim took the `unpark` (one socket's frames are
    /// handled in order).
    fn unpark(&mut self, id: &SpawnId) {
        self.send(&Frame::Unpark { spawn_id: id.clone() });
        let ts = ai_env_cli::wire::time::unix_now_ms();
        self.send(&Frame::Ping { ts });
        loop {
            match self.next() {
                Ok(Frame::Pong { ts: t }) if t == ts => return,
                Ok(_) => {}
                Err(close) => panic!("the socket ended ({close:?}) before the unpark's pong"),
            }
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

// ---- S8 agent L1: the workspace helper as the agent ---------------------------------------
//
// The shim's helper is this very binary (`ai-env shim-io`, `current_exe` of
// the mounted shim), started as the agent for each workspace route; the
// app port's routes run it behind the session bearer. Two tests replace it
// with a script (`--helper`, mounted with the fake claude) to drive what
// the real helper never does on purpose: overstay its budget, and run long
// while a spawn ends. (S8's `PUT /transcript` tests went with the route at
// S9's S3 cut-over; the transcript's S9 forms are G8's L1 tests.)

/// A refusal's code (a 4xx or 5xx body of the workspace routes).
fn refusal_code(body: &str) -> String {
    serde_json::from_str::<ai_env_cli::wire::workspace::WsRefusal>(body).unwrap_or_else(|e| panic!("a refusal ({e}): {body}")).code
}

/// A script standing for `ai-env shim-io` that never answers and ignores
/// TERM: it leaves a `sleep` in its own group (the helper leads it: the
/// shim's `setsid`) and one leading a group of its own in its session
/// (bash job control: the image has no perl for W3's `setpgrp`), as a git
/// run does (`gitrun` gives each its own group), each pid in /tmp.
const OVERSTAYING_HELPER: &str = "#!/bin/bash
sleep 300 &
echo $! > /tmp/ai-env-s8-group.pid
set -m
sleep 300 &
echo $! > /tmp/ai-env-s8-own.pid
set +m
trap '' TERM
wait
";

/// A script standing for `ai-env shim-io` that writes its pid, waits for
/// /tmp/ai-env-s8-go, then answers its settings capture.
const WAITING_HELPER: &str = "#!/bin/bash
echo $$ > /tmp/ai-env-s8-helper.pid
while [ ! -e /tmp/ai-env-s8-go ]; do sleep 0.1; done
printf '%s\\n' '{\"ok\":true,\"reply\":{\"path\":\"/Users/mike/w\",\"files\":[],\"at\":\"2026-10-12T00:00:00Z\"}}'
";

/// [`agent_l1`] with `script` as the shim's helper (`--helper`, beside the fake claude).
fn helper_vm(script: &str) -> Vm {
    use std::os::unix::fs::PermissionsExt;
    let fake = fake_dir(&format!("VERSION={}\n", lock_version()));
    let helper = fake.path().join("helper");
    std::fs::write(&helper, script).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (c, fake) = agent_l1_ready_with(fake, &[("--helper", "/opt/fake/helper")]);
    Vm::started(c, Some(fake), 20)
}

impl Container {
    /// The number in `file` once it holds one (written by the agent), within 10 s.
    fn pid_in(&self, file: &str) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(pid) = self.sh(&format!("cat {file} 2>/dev/null; true")).parse() {
                return pid;
            }
            assert!(Instant::now() < deadline, "{file} never held a pid:\n{}", self.logs());
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `pid`'s process group and session (`/proc/<pid>/stat`).
    fn group_and_session(&self, pid: u32) -> (u32, u32) {
        let stat = self.sh(&format!("cat /proc/{pid}/stat"));
        let fields: Vec<u32> = stat.rsplit_once(") ").map(|(_, rest)| rest.split_whitespace().skip(2).take(2).filter_map(|f| f.parse().ok()).collect()).unwrap_or_default();
        match fields[..] {
            [group, session] => (group, session),
            _ => panic!("no group and session in {stat:?}"),
        }
    }
}

/// W3's open point 9 on Linux: a helper past its budget has its group and
/// what it left of its session ended, the session found through `/proc` and
/// each process signalled through a pidfd. The helper ([`OVERSTAYING_HELPER`],
/// as in W3's native test) left two sleeps: one in its group, one leading a
/// group of its own in its session. `GET /settings` (its budget 10 s) answers
/// 504 `timeout` once the shim has TERMed the helper's group, KILLed it 2 s
/// later, then ended the one process left in the session. Both sleeps are
/// gone: the one in the group dies of the group's TERM and bash reaps it;
/// the one leading its own group, orphaned by the helper's KILL, is ended
/// with the session and reaped by init.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_a_helper_past_its_budget_has_its_session_ended() {
    use ai_env_cli::shim::asagent::KILL_AFTER;
    use ai_env_cli::wire::workspace::budget;
    let vm = helper_vm(OVERSTAYING_HELPER);
    let (app, bearer) = (vm.c.port(8080), format!("Authorization: Bearer {}\r\n", vm.token));
    let started = Instant::now();
    let asked = std::thread::spawn(move || http_with(app, "GET", "/settings?path=/Users/mike/w", &bearer, ""));
    let (in_group, own) = (vm.c.pid_in("/tmp/ai-env-s8-group.pid"), vm.c.pid_in("/tmp/ai-env-s8-own.pid"));
    let ((group, session), (own_group, own_session)) = (vm.c.group_and_session(in_group), vm.c.group_and_session(own));
    assert_eq!((group, own_session), (session, session), "the first sleep is in the helper's group, the helper leading its session; the second in that session");
    assert_eq!(own_group, own, "the second sleep leads a group of its own");
    let (s, body) = asked.join().expect("the request's thread");
    let took = started.elapsed();
    assert_eq!((s, refusal_code(&body).as_str()), (504, "timeout"), "{body}");
    assert!(took < budget::SETTINGS + 2 * KILL_AFTER + Duration::from_secs(3), "the helper's end took {took:?}");
    let logs = vm.c.wait_log(10, "process(es) in its session: TERM, KILL");
    let line = |needle: &str| logs.lines().find(|l| l.starts_with("ai-env: workspace helper settings pid=") && l.ends_with(needle)).map(str::to_string);
    assert!(line("outlived its budget: TERM, KILL").is_some(), "the group ended past the budget:\n{logs}");
    assert!(line("left 1 process(es) in its session: TERM, KILL").is_some(), "the session's one process ended:\n{logs}");
    for pid in [in_group, own] {
        let deadline = Instant::now() + Duration::from_secs(5);
        while vm.c.alive(pid) {
            assert!(Instant::now() < deadline, "{pid} outlived the helper:\n{}", vm.c.logs());
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    vm.c.wait_log(5, &format!("ai-env: init: reaped orphan {own} "));
}

/// The idle sweep on Linux (root): a helper running as the agent when a
/// spawn ends holds the sweep off and lives on; once it ends, the sweep that
/// was due runs. The helper ([`WAITING_HELPER`]) runs `GET /settings`
/// meanwhile a spawn leaves a job in a group of its own (bash job control)
/// and exits: the shim logs the sweep held off by one helper, and the job
/// and the helper are alive. The helper is let go: its answer reaches the
/// client (200), and a sweep then kills the job (SIGKILL, reaped by init).
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_a_running_helper_holds_off_the_idle_sweep() {
    let vm = helper_vm(WAITING_HELPER);
    let (app, bearer) = (vm.c.port(8080), format!("Authorization: Bearer {}\r\n", vm.token));
    let asked = std::thread::spawn(move || http_with(app, "GET", "/settings?path=/Users/mike/w", &bearer, ""));
    let helper = vm.c.pid_in("/tmp/ai-env-s8-helper.pid");
    let swept = sweeps(&vm.c.logs()).len();
    let (out, err, exit) = vm.run(&["bash", "-c", "set -m; sleep 300 & echo $!; exit 0"], b"");
    assert_eq!(exit, ExitInfo { code: Some(0), signal: None }, "{}", String::from_utf8_lossy(&err));
    let job: u32 = String::from_utf8_lossy(&out).trim().parse().unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&out)));
    let logs = vm.c.wait_log(10, "ai-env: idle sweep held off: 1 workspace helper(s) running");
    assert_eq!(sweeps(&logs).len(), swept, "no sweep while the helper runs:\n{logs}");
    assert!(vm.c.alive(job) && vm.c.alive(helper), "the job and the helper live on:\n{logs}");
    vm.c.sh("touch /tmp/ai-env-s8-go");
    let (s, body) = asked.join().expect("the request's thread");
    assert_eq!(s, 200, "the helper's answer reached the client: {body}");
    assert_swept(&vm.c, &out);
    assert!(sweeps(&vm.c.logs()).len() > swept, "a sweep ran once no helper lived:\n{}", vm.c.logs());
}

// ---- S9 agent L1: the transcript's curl (G8) ------------------------------------------------
//
// The root shim pushes a range of the agent's transcript to S3 with curl as
// uid 999 (`ai-env-net`; the base image has no such user, the uid is enough),
// its presigned URL on fd 3 only. A decoy proxy on the container's own
// address (gawk as root: an RFC 1918 proxy, as squid's is) takes curl's
// CONNECT and holds it until the test lets it go, so curl lives with the URL
// in its memory while the agent and root look for it.

/// The decoy's port, its log of the request lines it took, and the file whose
/// existence lets it answer.
const HOLDING_PORT: u16 = 3128;
const HOLDING_LOG: &str = "/tmp/ai-env-s9-decoy.log";
const HOLDING_GO: &str = "/tmp/ai-env-s9-go";

/// The holding decoy (gawk, `-v port= -v out= -v go=`): one connection, its
/// request line logged once its head is read, then no answer until `go`
/// exists, then 403, as squid refuses a host off its allowlist.
const HOLDING_DECOY: &str = r#"BEGIN {
  srv = "/inet4/tcp/" port "/0/0"
  if ((srv |& getline first) > 0) {
    sub(/\r$/, "", first)
    while ((srv |& getline h) > 0) { sub(/\r$/, "", h); if (h == "") break }
    print first >> out; fflush(out)
    while (system("test -e " go) != 0) system("sleep 0.2")
    printf "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" |& srv
  }
  close(srv)
}"#;

/// Every command line and environment uid 1000 can read, an entry a line
/// (another uid's environ is refused it: skipped).
const AGENT_PROC_DUMP: &str = "for d in /proc/[0-9]*; do for f in cmdline environ; do tr '\\0' '\\n' 2>/dev/null < \"$d/$f\"; echo; done; done; true";

/// The slug a transcript's rel starts with (the picker's, of `/Users/mike/w`).
const SLUG: &str = "-Users-mike-w";

/// M3 on Linux (S9 plan §5: the URL is never in an argv, an environment or
/// on disk, and uid 1000 cannot read uid 999's descriptors): while a push's
/// curl holds its presigned URL (the decoy holds its CONNECT), curl runs as
/// 999:999 with NO_NEW_PRIVS and the argv `-q -K /dev/fd/3`; the URL's
/// signature (made at run time) is in no command line or environment the
/// agent can read, nor in any process's (root's privileged dump), and the
/// agent cannot open curl's environ, memory or fd 3. Once the decoy refuses
/// the CONNECT, curl reports no HTTP status: the push is 500
/// `transfer_failed`; the CONNECT named the bucket's host, and the shim's
/// log never held the signature.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_curl_url_invisible_to_uid_1000() {
    use ai_env_cli::wire::s3::{bucket_host, PresignedUrl, S3Key, SIGNED_HEADERS_PUT};
    use ai_env_cli::wire::workspace::TranscriptPush;
    use sha2::Digest as _;
    let vm = agent_l1(&[]);
    let ip = vm.c.ip();
    let (port, out, go) = (format!("port={HOLDING_PORT}"), format!("out={HOLDING_LOG}"), format!("go={HOLDING_GO}"));
    let started = docker(&["exec", "-d", "-u", "0", &vm.c.id, "gawk", "-v", &port, "-v", &out, "-v", &go, HOLDING_DECOY]);
    assert!(started.status.success(), "the decoy: {}", String::from_utf8_lossy(&started.stderr));
    let row = format!(":{HOLDING_PORT:04X} 00000000:0000 0A");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !vm.c.sh("cat /proc/net/tcp").contains(&row) {
        assert!(Instant::now() < deadline, "the decoy is not listening on {HOLDING_PORT}");
        std::thread::sleep(Duration::from_millis(100));
    }
    // The agent's transcript, and a push of it through the decoy.
    let (session, owner) = ("0199d2a0-0000-7000-8000-000000000009", "123456789012");
    let rel = format!("{SLUG}/{session}.jsonl");
    let body = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"a turn\"}}\n";
    vm.c.sh_as("1000", &format!("mkdir -p /Users/mike/.claude/projects/{SLUG} && printf '%s\\n' '{}' > /Users/mike/.claude/projects/{rel}", body.trim_end()));
    let signature = hex::encode(sha2::Sha256::digest(SpawnId::new_v7().to_string().as_bytes()));
    let bucket = format!("ai-env-transcripts-{owner}");
    let key = S3Key::Base { session: session.into(), gen: 1 }.render();
    let query = format!("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261018%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261018T080000Z&X-Amz-Expires=300&X-Amz-SignedHeaders={}&X-Amz-Signature={signature}", SIGNED_HEADERS_PUT.replace(';', "%3B"));
    let url = PresignedUrl::new(format!("https://{}/{key}?{query}", bucket_host(&bucket))).expect("a presigned URL of the store");
    let push = TranscriptPush { rel, from: 0, len: body.len() as u64, sha256: hex::encode(sha2::Sha256::digest(body.as_bytes())), url, owner: owner.into(), proxy: Some(format!("http://{ip}:{HOLDING_PORT}")) };
    let (app, bearer, json) = (vm.c.port(8080), format!("Authorization: Bearer {}\r\n", vm.token), serde_json::to_string(&push).unwrap());
    let pushed = std::thread::spawn(move || http_with(app, "POST", "/transcript/push", &bearer, &json));
    let deadline = Instant::now() + Duration::from_secs(30);
    let connect = loop {
        let seen = vm.c.sh(&format!("cat {HOLDING_LOG} 2>/dev/null; true"));
        if !seen.is_empty() {
            break seen;
        }
        assert!(Instant::now() < deadline, "curl never reached the decoy:\n{}", vm.c.logs());
        std::thread::sleep(Duration::from_millis(100));
    };
    // curl now waits on the decoy, the URL in its memory.
    let curls = vm.c.pids("curl");
    assert_eq!(curls.len(), 1, "one curl: {curls:?}");
    let pid = curls[0];
    let status = vm.c.sh(&format!("grep -E '^(Uid|Gid|NoNewPrivs):' /proc/{pid}/status"));
    assert_eq!(status.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).collect::<Vec<_>>(), ["Uid: 999 999 999 999", "Gid: 999 999 999 999", "NoNewPrivs: 1"], "curl runs as ai-env-net, no new privileges");
    let argv = vm.c.sh(&format!("tr '\\0' '\\n' < /proc/{pid}/cmdline"));
    let argv: Vec<&str> = argv.lines().collect();
    assert!(argv.len() == 4 && argv[0].ends_with("curl") && argv[1..] == ["-q", "-K", "/dev/fd/3"], "curl's argv: {argv:?}");
    // What the agent can read: every command line, its own environments; never the signature.
    let seen = vm.c.exec_as("1000", &["sh", "-c", AGENT_PROC_DUMP]);
    let seen = String::from_utf8_lossy(&seen.stdout);
    assert!(seen.lines().any(|l| l == "/dev/fd/3"), "the agent's dump read curl's command line ({} lines)", seen.lines().count());
    assert_eq!(seen.lines().filter(|l| l.contains(&signature)).count(), 0, "the URL is in a command line or an environment the agent reads");
    let probe = format!("for n in environ mem fd/3; do err=$(dd if=/proc/{pid}/$n of=/dev/null bs=1 count=1 status=none 2>&1); echo \"$n rc=$?${{err:+ $err}}\"; done");
    let denied = vm.c.sh_as("1000", &probe);
    for (node, line) in ["environ", "mem", "fd/3"].iter().zip(denied.lines()) {
        assert!(line.starts_with(&format!("{node} rc=1 ")) && line.ends_with("Permission denied"), "the agent opened curl's {node}: {line}");
    }
    assert_eq!(denied.lines().count(), 3, "{denied}");
    // Root's privileged dump of every process: the URL is in no argv and no environment at all.
    assert_eq!(vm.c.proc_hits(&[&signature], &["-q", "-K", "/dev/fd/3"]), 0, "the URL is in a command line or an environment");
    vm.c.sh(&format!("touch {HOLDING_GO}"));
    let (s, reply) = pushed.join().expect("the push's thread");
    assert_eq!((s, refusal_code(&reply).as_str()), (500, "transfer_failed"), "curl reported no HTTP status: {reply}");
    assert_eq!(connect.trim(), format!("CONNECT {}:443 HTTP/1.1", bucket_host(&bucket)), "curl went to the bucket's host through the proxy");
    let logs = vm.c.wait_log(10, "ai-env: workspace transcript-push status=500 ");
    assert!(!logs.contains(&signature) && !reply.contains(&signature), "the signature reached the shim's log or the reply");
    vm.c.wait_gone(10, "curl");
}

// ---- S10 agent L1: the park, the tail's URL, the guest's memory -----------------------------
//
// The park (`park_v1`, plans/s10-contracts.md §1.2) through the raw client,
// its frames sent as the Mac's session sends them: the root shim's busy
// check reads the session of the agent's spawn in `/proc` on Linux (its CPU
// per sample, its processes but the leader), and a parked spawn whose
// socket goes lives its park grace. R1 (§1.4): the root shim keeps a tail's
// URL until S3 gave its push a final answer; curl runs as `ai-env-net`, the
// S9 fake curl (`tests/fakes/s3-curl.sh`) standing in for curl and S3. The
// guest's memory (§1.5) in `/health` and the run report.

/// S10: the busy check's threshold these parks send (`park.cpu_busy_ms`,
/// CPU ms per 10 s sample): B0's (plans/s10-measurements.md, 20 Oct), which
/// the Mac sends from I2 on. An idle `sleep` uses next to none of it, a busy
/// loop a whole CPU.
const CPU_BUSY_MS: u32 = 300;

/// S10: the wrapper these parks name (`park.owner`); the shim only reports it back.
const PARK_OWNER: ParkOwner = ParkOwner { pid: 51_234, started: 1_792_483_200 };

/// Where the setsid escaper of [`l2_a_setsid_escaper_makes_a_park_busy`]
/// writes its pid (as the agent).
const ESCAPER_PID: &str = "/tmp/ai-env-s10-escaper.pid";

/// Touched (by root) to end that escaper's busy loop: it then sleeps.
const ESCAPER_STOP: &str = "/tmp/ai-env-s10-escaper.stop";

/// Where the fake curl of [`l1_a_tail_url_is_kept_on_no_status_or_a_5xx_and_pushed_at_the_next_hook`]
/// logs, in a directory only `ai-env-net` (999) enters: the calls'
/// configurations hold the URL.
const TAIL_CURL_DIR: &str = "/tmp/ai-env-s10-curl";

impl Vm {
    /// The spawn `id` as `/health/detail` reports it.
    fn spawn_detail(&self, id: &SpawnId) -> SpawnDetail {
        self.detail().spawns.into_iter().find(|s| s.status.spawn_id == *id).unwrap_or_else(|| panic!("{id} is not in /health/detail"))
    }
}

impl Container {
    /// The live processes (not zombies) of the session `leader` leads, the
    /// leader left out (`/proc/<pid>/stat`'s sixth field).
    fn session_members(&self, leader: u32) -> Vec<u32> {
        let script = format!("for s in /proc/[0-9]*/stat; do set -- $(cat \"$s\" 2>/dev/null); [ \"$6\" = {leader} ] && [ \"$1\" != {leader} ] && [ \"$3\" != Z ] && echo \"$1\"; done; true");
        self.sh(&script).lines().filter_map(|l| l.trim().parse().ok()).collect()
    }

    /// [`Container::session_members`] once there are `n` of them, within 10 s.
    fn wait_session_members(&self, leader: u32, n: usize) -> Vec<u32> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let members = self.session_members(leader);
            if members.len() == n {
                return members;
            }
            assert!(Instant::now() < deadline, "{n} process(es) in the session of {leader} within 10 s, not {members:?}:\n{}", self.logs());
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait (at most `secs`) until `pid` is gone or a zombie.
    fn wait_dead(&self, secs: u64, pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while self.alive(pid) {
            assert!(Instant::now() < deadline, "{pid} still runs after {secs} s:\n{}", self.logs());
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait (at most `secs`) until `pid` runs `comm` (`/proc/<pid>/comm`:
    /// a busy loop that stopped and exec'd a `sleep`).
    fn wait_comm(&self, secs: u64, pid: u32, comm: &str) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while self.sh(&format!("cat /proc/{pid}/comm 2>/dev/null; true")) != comm {
            assert!(Instant::now() < deadline, "{pid} does not run {comm} after {secs} s:\n{}", self.logs());
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The fake curl's knobs, `curl.knobs` beside it in the fake dir `fake`
/// (mounted at /opt/fake): its log in [`TAIL_CURL_DIR`], then `knobs`.
/// Written on the Mac; returns once the container reads them too.
fn set_curl_knobs(c: &Container, fake: &Path, knobs: &[(&str, &str)]) {
    let mut text = format!("export S3CURL_LOG='{TAIL_CURL_DIR}/curl.log'\n");
    for (name, value) in knobs {
        text.push_str(&format!("export {name}='{value}'\n"));
    }
    std::fs::write(fake.join("curl.knobs"), &text).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while c.sh("cat /opt/fake/curl.knobs") != text.trim_end() {
        assert!(Instant::now() < deadline, "the container never read the fake curl's new knobs:\n{text}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// S10 (§1.2) as root on Linux, the spawn the agent's: the shim names
/// `park_v1`. A spawn whose session runs a busy loop (a process but the
/// leader, running) is refused `busy` on that running process, the loop its
/// one process (`procs`), and is not parked. Once the loop stops (it execs a
/// `sleep`: alive, asleep, no more CPU, as claude's background shell or a
/// stdio MCP server at rest) the spawn parks within a sample's time (once a
/// sample took the loop's last CPU in, the look at the park sees none), that
/// process still alive: `parked` with one process but the leader,
/// `/health/detail` naming its owner, its socket kept (no grace runs). An
/// `unpark` (no answer: the ping's pong follows it) takes the park away.
/// The shim logs the refusal, the park and the unpark.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_a_park_is_refused_busy_while_the_session_runs_then_parked_and_unparked() {
    use ai_env_cli::shim::spawn::ACTIVITY_SAMPLE;
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let mut a = vm.agent();
    assert!(a.caps.iter().any(|cap| cap == CAP_PARK_V1), "the shim names {CAP_PARK_V1}: {:?}", a.caps);
    let stop = "/tmp/ai-env-s10-loop.stop";
    let script = format!("sh -c 'while [ ! -e {stop} ]; do :; done; exec sleep 300' & exec sleep 300");
    let (id, leader) = a.spawn(&Spec { grace: Some(60), ..Spec::argv(&["sh", "-c", &script]) }).unwrap_or_else(|e| panic!("{e:?}"));
    let busy = c.wait_session_members(leader, 1)[0];
    // The loop runs (R): the refusal is that running process's, whatever its CPU.
    std::thread::sleep(Duration::from_millis(1500));
    match a.park(&id, 600, 0) {
        Frame::ParkRefused { reason: ParkRefusal::Busy, procs: 1, .. } => {}
        other => panic!("park_refused busy, the loop the session's one process, got {other:?}"),
    }
    assert_eq!(vm.spawn_detail(&id).parked, None, "a refused park parks nothing");
    c.sh(&format!("touch {stop}"));
    c.wait_comm(5, busy, "sleep");
    let (answer, refusals) = a.park_when_quiet(&id, 600, ACTIVITY_SAMPLE + Duration::from_secs(5));
    match answer {
        Frame::Parked { procs: 1, quiet_s, .. } => assert!(quiet_s < 120, "no stdio since the spawn: {quiet_s} s"),
        other => panic!("parked with the loop's process alive and asleep, got {other:?}"),
    }
    assert_eq!(c.session_members(leader), vec![busy], "the sleeping process is still the session's");
    let d = vm.spawn_detail(&id);
    assert!(d.status.alive && d.parked == Some(PARK_OWNER) && d.detach_left_s.is_none(), "parked, its owner named, its socket kept: {d:?}");
    a.unpark(&id);
    let d = vm.spawn_detail(&id);
    assert!(d.status.alive && d.parked.is_none(), "unparked: {d:?}");
    let logs = c.wait_log(5, &format!("ai-env: spawn {id} unparked by unpark"));
    assert!(logs.lines().any(|l| l.starts_with("ai-env: spawn ") && l.contains(" park refused (busy): ") && l.contains(", procs 1, cpu ")), "the refusal:\n{logs}");
    let parked = format!("ai-env: spawn {id} parked: park grace 600 s, ");
    assert!(logs.lines().any(|l| l.starts_with(&parked) && l.ends_with(", procs 1, owner pid 51234 started 1792483200")), "the park:\n{logs}");
    eprintln!("L1 park: parked after {refusals} busy refusal(s) once the loop slept");
}

/// S10 (§1.2) on Linux: the busy check's CPU half, the only one that sees
/// the leader (claude itself: `running` never counts it). The leader spins
/// on its own (`[` and `:` are the shell's builtins: no child), so no
/// process but the leader runs (`procs` 0, none running), and a `park`
/// whose window (11 s) holds a whole sample (one per `ACTIVITY_SAMPLE`) is
/// refused `busy` on the session's CPU alone: the busiest sample's CPU is
/// over the threshold sent, and no more than one CPU could use since the
/// spawn (the kernel's clock ticks read at their rate). The spawn is 12 s
/// old with no stdio, so the window is quiet (not `output`). Once the loop
/// stops (the leader execs a `sleep`) the spawn parks within a sample's
/// time, with no process but the leader.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_a_park_is_refused_busy_on_the_leaders_cpu_alone() {
    use ai_env_cli::shim::spawn::ACTIVITY_SAMPLE;
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let mut a = vm.agent();
    let stop = "/tmp/ai-env-s10-spin.stop";
    let script = format!("while [ ! -e {stop} ]; do :; done; exec sleep 300");
    let t0 = Instant::now();
    let (id, leader) = a.spawn(&Spec { grace: Some(60), ..Spec::argv(&["sh", "-c", &script]) }).unwrap_or_else(|e| panic!("{e:?}"));
    std::thread::sleep(ACTIVITY_SAMPLE + Duration::from_secs(2));
    assert_eq!(c.session_members(leader), Vec::<u32>::new(), "the leader spins alone");
    let (quiet_s, cpu_ms) = match a.park(&id, 600, 11) {
        Frame::ParkRefused { reason: ParkRefusal::Busy, procs: 0, quiet_s, cpu_ms, .. } => (quiet_s, cpu_ms),
        other => panic!("park_refused busy on the leader's CPU alone, got {other:?}"),
    };
    let age_ms = u64::try_from(t0.elapsed().as_millis()).unwrap();
    assert!(quiet_s >= 11, "no stdio since the spawn: {quiet_s} s");
    assert!(cpu_ms > u64::from(CPU_BUSY_MS) && cpu_ms <= age_ms + 50, "the busiest sample's CPU, {cpu_ms} ms: over {CPU_BUSY_MS} ms, and at most one CPU's {age_ms} ms since the spawn");
    assert_eq!(vm.spawn_detail(&id).parked, None, "a refused park parks nothing");
    c.sh(&format!("touch {stop}"));
    c.wait_comm(5, leader, "sleep");
    let (answer, refusals) = a.park_when_quiet(&id, 600, ACTIVITY_SAMPLE + Duration::from_secs(5));
    assert!(matches!(answer, Frame::Parked { procs: 0, .. }), "parked once the leader slept, got {answer:?}");
    let logs = c.logs();
    let refused = format!(", procs 0, cpu {cpu_ms} ms");
    assert!(logs.lines().any(|l| l.starts_with("ai-env: spawn ") && l.contains(" park refused (busy): ") && l.ends_with(&refused)), "the refusal:\n{logs}");
    eprintln!("L1 park on CPU: refused busy at {cpu_ms} ms of CPU in a sample ({age_ms} ms since the spawn); parked after {refusals} busy refusal(s) once the leader slept");
}

/// S10 V-6 (phase 4, BUSY-1) on Linux: two chats on one VM, each its spawn
/// on a socket of its own, each spawn its own session as the agent. One
/// spawn's session runs a busy loop (a process but its leader, running):
/// it is never the other's escaper, as every look takes every live spawn's
/// leader (the escapers are only the agent's processes in no live spawn's
/// session), so the quiet spawn beside it parks, with no process but its
/// leader. The busy spawn's own park is refused `busy`, its loop the one
/// process. (Before: the quiet spawn's look took the loop for its escaper,
/// and neither chat ever parked.)
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_a_busy_chat_beside_never_keeps_a_quiet_one_from_parking() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let (mut busy_chat, mut quiet_chat) = (vm.agent(), vm.agent());
    let (busy, leader) = busy_chat.spawn(&Spec { grace: Some(60), ..Spec::argv(&["sh", "-c", "sh -c 'while :; do :; done' & exec sleep 300"]) }).unwrap_or_else(|e| panic!("{e:?}"));
    let (quiet, _) = quiet_chat.spawn(&Spec { grace: Some(60), ..Spec::argv(&["sleep", "300"]) }).unwrap_or_else(|e| panic!("{e:?}"));
    c.wait_session_members(leader, 1);
    // The loop runs (R) in the busy spawn's session, and has used some CPU by now.
    std::thread::sleep(Duration::from_millis(1500));
    match quiet_chat.park(&quiet, 600, 0) {
        Frame::Parked { procs: 0, .. } => {}
        other => panic!("the quiet spawn parked beside the busy one, got {other:?}:\n{}", c.logs()),
    }
    match busy_chat.park(&busy, 600, 0) {
        Frame::ParkRefused { reason: ParkRefusal::Busy, procs: 1, .. } => {}
        other => panic!("the busy spawn's own park refused busy, its loop the one process, got {other:?}"),
    }
    assert_eq!(vm.spawn_detail(&quiet).parked, Some(PARK_OWNER), "parked");
    assert_eq!(vm.spawn_detail(&busy).parked, None, "not parked");
}

/// S10 (§1.2): a parked spawn whose socket is lost lives its park grace,
/// not its detach grace. `sleep 300` with a 60 s detach grace, parked with a
/// 5 s park grace, loses its socket: the shim says the park grace starts
/// (`lost connection …: park grace 5 s`); `/health/detail` shows it still
/// parked (its owner named), detached, its 5 s running; and TERM ends it once
/// those 5 s ran (`park grace over`), timed on the shim's own log lines.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_a_lost_parked_socket_lives_its_park_grace() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let mut a = vm.agent();
    let (id, pid) = a.spawn(&Spec { grace: Some(60), ..Spec::argv(&["sleep", "300"]) }).unwrap_or_else(|e| panic!("{e:?}"));
    match a.park(&id, 5, 0) {
        Frame::Parked { procs: 0, .. } => {}
        other => panic!("parked, got {other:?}"),
    }
    // No detach frame: a lost socket.
    drop(a);
    let lost = format!("ai-env: spawn {id} lost connection");
    let logs = c.wait_log(5, &lost);
    let line = logs.lines().find(|l| l.starts_with(&lost)).unwrap_or_default();
    assert!(line.ends_with(": park grace 5 s"), "the park grace, not the 60 s detach grace: {line}");
    let d = vm.spawn_detail(&id);
    assert!(d.parked == Some(PARK_OWNER) && !d.status.attached && !d.frozen && d.detach_left_s.is_some_and(|s| s <= 5), "parked with no socket, its park grace running: {d:?}");
    let over = format!("ai-env: spawn {id} park grace over");
    c.wait_log(15, &over);
    c.wait_dead(5, pid);
    let timed = c.timed_logs();
    let took = logged_at(&timed, &over) - logged_at(&timed, &lost);
    assert!((took - 5.0).abs() < 1.0, "TERM {took:.2} s after the socket was lost: the 5 s park grace");
}

/// S10 (R1, §1.4) on Linux: a tail's URL goes only once S3 gave its push a
/// final answer. The agent's transcript grows past the tail's `from`, and at
/// each `/suspend` the root shim pushes `[from, size)` to the tail's key with
/// curl as `ai-env-net` (the S9 fake curl as the shim's `--curl`; its knobs,
/// rewritten before each hook, pick the answer). curl with no HTTP status
/// keeps the URL (`; kept`), and so does S3's 503 (`SlowDown`): the next
/// `/suspend` (after a `/resume`) pushes the same key again, with the bytes
/// past `from` as the file holds them then; S3's 200 spends it, and the next
/// hook (`/terminate`, the file grown once more) pushes nothing. Each push
/// is the same PUT (no checksum, `If-None-Match: *`, the proxy) through fd 3
/// alone; the URL's signature never reaches the shim's log.
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_a_tail_url_is_kept_on_no_status_or_a_5xx_and_pushed_at_the_next_hook() {
    use ai_env_cli::wire::s3::{bucket_host, PresignedUrl, S3Key, SIGNED_HEADERS_TAIL};
    use ai_env_cli::wire::workspace::TranscriptTail;
    use sha2::Digest as _;
    use std::os::unix::fs::PermissionsExt as _;
    let fake = fake_dir(&format!("VERSION={}\n", lock_version()));
    std::fs::copy(curl::FAKE_CURL, fake.path().join("curl")).unwrap();
    std::fs::set_permissions(fake.path().join("curl"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let host = fake.path().to_path_buf();
    std::fs::write(host.join("curl.knobs"), "").unwrap();
    let (c, fake) = agent_l1_ready_with(fake, &[("--curl", "/opt/fake/curl")]);
    let vm = Vm::started(c, Some(fake), 20);
    let c = &vm.c;
    c.sh(&format!("mkdir -m 0700 {TAIL_CURL_DIR} && chown 999:999 {TAIL_CURL_DIR}"));
    // The agent's transcript, S3 holding it up to `from`.
    let (session, owner) = ("0199d2a0-0000-7000-8000-00000000000b", "123456789012");
    let rel = format!("{SLUG}/{session}.jsonl");
    let file = format!("/Users/mike/.claude/projects/{rel}");
    let append = |line: &str| c.sh_as("1000", &format!("printf '%s\\n' '{line}' >> {file}"));
    let size = || -> u64 { c.sh(&format!("stat -c %s {file}")).parse().unwrap() };
    c.sh_as("1000", &format!("mkdir -p /Users/mike/.claude/projects/{SLUG}"));
    append("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"a turn\"}}");
    let from = size();
    let signature = hex::encode(sha2::Sha256::digest(SpawnId::new_v7().to_string().as_bytes()));
    let key = S3Key::Tail { session: session.into(), gen: 1, offset: from }.render();
    let query = format!("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261020%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261020T080000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders={}&X-Amz-Signature={signature}", SIGNED_HEADERS_TAIL.replace(';', "%3B"));
    let url = PresignedUrl::new(format!("https://{}/{key}?{query}", bucket_host(&format!("ai-env-transcripts-{owner}")))).expect("a tail URL of the store");
    let proxy = format!("http://{}:3128", c.ip());
    let tail = TranscriptTail { rel: rel.clone(), from, url: url.clone(), owner: owner.into(), proxy: Some(proxy.clone()), expires_at: ai_env_cli::wire::time::unix_now() + 3600 };
    let bearer = format!("Authorization: Bearer {}\r\n", vm.token);
    let (s, body) = http_with(c.port(8080), "POST", "/transcript/tail", &bearer, &serde_json::to_string(&tail).unwrap());
    assert_eq!(s, 204, "the tail kept: {body}");
    let hook = |name: &str| assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/{name}"), "{}").0, 200, "/{name}");
    let tails = |logs: &str| logs.lines().filter(|l| l.starts_with("ai-env: transcript_tail ")).map(str::to_string).collect::<Vec<_>>();
    let prefix = format!("ai-env: transcript_tail suspend rel={rel} from={from} ");
    let saved = format!("{TAIL_CURL_DIR}/saved");
    let answers: [&[(&str, &str)]; 3] = [&[("S3CURL_FAIL", "7")], &[("S3CURL_STATUS", "503"), ("S3CURL_CODE", "SlowDown")], &[("S3CURL_SAVE", saved.as_str())]];
    for (n, knobs) in answers.into_iter().enumerate() {
        set_curl_knobs(c, &host, knobs);
        append(&format!("{{\"type\":\"assistant\",\"n\":{n}}}"));
        let len = size() - from;
        hook("suspend");
        let deadline = Instant::now() + Duration::from_secs(10);
        let logged = loop {
            let logged = tails(&c.logs());
            if logged.len() > n {
                break logged;
            }
            assert!(Instant::now() < deadline, "no transcript_tail line for /suspend {}:\n{}", n + 1, c.logs());
            std::thread::sleep(Duration::from_millis(200));
        };
        assert_eq!(logged.len(), n + 1, "one push per /suspend: {logged:#?}");
        let line = &logged[n];
        match n {
            0 => assert!(line.starts_with(&format!("{prefix}failed: ")) && line.ends_with("; kept"), "curl without a status keeps the URL: {line}"),
            1 => assert_eq!(*line, format!("{prefix}len={len} status=503; kept"), "S3's 503 keeps the URL"),
            _ => assert_eq!(*line, format!("{prefix}len={len} status=200"), "S3's 200 spends it"),
        }
        hook("resume");
    }
    // What curl was given: the fake's log, copied out (root reads the 0700 directory).
    let copied = tempfile::tempdir().unwrap();
    std::fs::write(copied.path().join("curl.log"), c.sh(&format!("cat {TAIL_CURL_DIR}/curl.log"))).unwrap();
    let calls = curl::curl_calls(&copied.path().join("curl.log"));
    assert_eq!(calls.len(), 3, "the three pushes");
    for call in &calls {
        assert_eq!((call.uid, call.fds.as_slice(), call.args.as_slice()), (999, &[3][..], &["-q".to_string(), "-K".to_string(), "/dev/fd/3".to_string()][..]), "curl as ai-env-net, fd 3 alone, its argv");
        assert_eq!(call.conf("url"), [url.expose()], "the same tail key each time");
        assert_eq!((call.conf("request"), call.conf("proxy")), (vec!["PUT".to_string()], vec![proxy.clone()]));
        let headers = call.conf("header");
        assert!(headers.iter().any(|h| h == "If-None-Match: *") && !headers.iter().any(|h| h.starts_with("x-amz-checksum-sha256")), "a tail's PUT: {headers:?}");
    }
    let pushed = c.sh(&format!("cat {saved}/3.put"));
    assert_eq!(pushed, c.sh(&format!("tail -c +{} {file}", from + 1)), "the third push: the bytes past from as the file held them");
    assert_eq!(pushed.lines().count(), 3, "the three lines the agent wrote past from: {pushed}");
    // Spent: the file grows, /terminate pushes nothing.
    append("{\"type\":\"summary\"}");
    hook("terminate");
    let logs = c.wait_log(10, "\"hook\":\"terminate\"");
    assert_eq!(tails(&logs).len(), 3, "a spent URL is never pushed again:\n{logs}");
    assert!(!logs.contains(&signature), "the URL's signature reached the shim's log");
}

/// S10 (§1.5): the guest's memory on Linux. `/health` (and the bearer's
/// `/health/detail`) carry `mem_total_mib`, `/proc/meminfo`'s `MemTotal`
/// read once at start, in MiB; the run report after `/run` carries
/// `mem_total_kb` (that `MemTotal`) and `mem_available_kb` (at most it).
#[test]
#[ignore = "Docker: make test-docker"]
fn l1_mem_total_in_the_run_report_and_health() {
    let vm = agent_l1(&[]);
    let c = &vm.c;
    let kb: u64 = c.sh("sed -n 's/^MemTotal: *\\([0-9]*\\) kB$/\\1/p' /proc/meminfo").parse().expect("MemTotal in kB");
    let mib = u32::try_from(kb / 1024).unwrap();
    let (s, body) = http(c.port(8080), "GET", "/health", "");
    assert_eq!(s, 200, "{body}");
    assert_eq!(serde_json::from_str::<Health>(&body).unwrap().mem_total_mib, Some(mib), "{body}");
    assert_eq!(vm.detail().health.mem_total_mib, Some(mib), "/health/detail");
    let logs = c.wait_log(10, "ai-env: run-report ");
    let report: serde_json::Value = logs.lines().find_map(|l| l.strip_prefix("ai-env: run-report ").and_then(|j| serde_json::from_str(j).ok())).expect("a run report");
    assert_eq!((report["hook"].as_str(), report["mem_total_kb"].as_u64()), (Some("run"), Some(kb)), "{report}");
    let available = report["mem_available_kb"].as_u64().unwrap_or_else(|| panic!("mem_available_kb: {report}"));
    assert!(available > 0 && available <= kb, "{report}");
    eprintln!("L1 memory: MemTotal {kb} kB ({mib} MiB), MemAvailable {available} kB at /run");
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

/// S10 V-6 in the real image (plans/s10-contracts.md §1.2's amendment): the
/// busy check counts the agent's escapers. A child of the spawn leaves its
/// session with the image's setsid(1) and spins: its own session's leader,
/// uid 1000, no spawn's and no helper's. A `park` of the spawn, whose own
/// session holds nothing but its quiet leader (`procs` 0), is refused `busy`
/// all the same (the escaper runs), as a backgrounded build must keep its VM
/// up. Once the escaper's loop stops (it execs a `sleep`: alive, asleep, no
/// more CPU, as an escaper waiting on its next job) it adds nothing: the
/// spawn parks within a sample's time, with no process but the leader, and
/// the escaper lives on.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_a_setsid_escaper_makes_a_park_busy() {
    use ai_env_cli::shim::spawn::ACTIVITY_SAMPLE;
    let vm = Vm::started(l2(), None, 120);
    let c = &vm.c;
    let mut a = vm.agent();
    assert!(a.caps.iter().any(|cap| cap == CAP_PARK_V1), "the image's shim names {CAP_PARK_V1}: {:?}", a.caps);
    let script = format!("setsid sh -c 'echo $$ > {ESCAPER_PID}; while [ ! -e {ESCAPER_STOP} ]; do :; done; exec sleep 300' & exec sleep 300");
    let (id, leader) = a.spawn(&Spec { grace: Some(60), ..Spec::argv(&["sh", "-c", &script]) }).unwrap_or_else(|e| panic!("{e:?}"));
    let escaper = c.pid_in(ESCAPER_PID);
    assert_eq!(c.group_and_session(escaper), (escaper, escaper), "the escaper leads a group and a session of its own");
    assert_eq!(c.group_and_session(leader), (leader, leader), "the spawn's leader leads its own");
    assert_eq!(c.session_members(leader), Vec::<u32>::new(), "nothing but the leader in the spawn's session");
    // The escaper runs (R): the refusal is that running escaper's, whatever its CPU.
    std::thread::sleep(Duration::from_millis(1500));
    match a.park(&id, 600, 0) {
        Frame::ParkRefused { reason: ParkRefusal::Busy, procs: 0, .. } => {}
        other => panic!("park_refused busy, the spawn's own session quiet, got {other:?}"),
    }
    assert_eq!(vm.spawn_detail(&id).parked, None, "a refused park parks nothing");
    c.sh(&format!("touch {ESCAPER_STOP}"));
    c.wait_comm(5, escaper, "sleep");
    let (answer, refusals) = a.park_when_quiet(&id, 600, ACTIVITY_SAMPLE + Duration::from_secs(5));
    assert!(matches!(answer, Frame::Parked { procs: 0, .. }), "parked once the escaper slept, got {answer:?}");
    assert_eq!(vm.spawn_detail(&id).parked, Some(PARK_OWNER));
    assert!(c.alive(escaper), "the escaper lives on, asleep:\n{}", c.logs());
    let logs = c.logs();
    assert!(logs.lines().any(|l| l.starts_with("ai-env: spawn ") && l.contains(" park refused (busy): ") && l.contains(", procs 0, cpu ")), "the refusal:\n{logs}");
    eprintln!("L2 escaper: parked after {refusals} busy refusal(s) once the escaper slept");
}

/// S10 (W3 #2, plans/s10-contracts.md §6.4) in the real image: the
/// directory a VM's shim keeps its last seed's record in, /var/lib/ai-env,
/// is root's, 0700 and empty, as every VM starts from the image (a record
/// baked in would be every VM's), and a shim that started and took `/run`
/// (no seed came) wrote nothing there: the container's diff names nothing
/// under /var/lib. The agent cannot list it.
#[test]
#[ignore = "Docker: make test-docker"]
fn l2_the_seed_record_dir_is_roots_0700_and_empty() {
    let c = l2();
    wait_ready(&c, 120);
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/run"), &run_body("mvm-s10", Some(&payload("mike@mbp")))).0, 200);
    assert_eq!(c.sh("stat -c '%a %u:%g %F' /var/lib/ai-env"), "700 0:0 directory");
    assert_eq!(c.sh("ls -A /var/lib/ai-env"), "", "no record in the image or written since");
    let diff = ok_stdout(&["diff", &c.id]);
    assert!(!diff.lines().any(|l| l.contains("/var/lib")), "the running shim changed /var/lib: {diff}");
    let out = c.exec_as("1000", &["ls", "-A", "/var/lib/ai-env"]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("Permission denied"), "the agent listed it: {}", String::from_utf8_lossy(&out.stdout));
}
