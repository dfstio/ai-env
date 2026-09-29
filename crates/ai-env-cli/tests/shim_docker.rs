//! Opt-in Docker tests of the shim (S3 T3.1), run by `make test-docker`
//! (`AI_ENV_DOCKER_TESTS=1`, every test `#[ignore]`d so `cargo test` never
//! needs Docker). With the variable set, a missing daemon, base image, shim
//! binary or local image is a FAILURE, never a skip.
//!
//! L1: the digest-pinned AL2023 base image with the cross-built shim
//! (`image/ai-env`, from `make vm-build`) mounted as the ENTRYPOINT and a fake
//! `claude` — PID 1, hooks from the host and from inside, clock and entropy
//! reports, orphan reaping, a graceful `docker stop`, the probe's uid/gid.
//! L2: the locally built image (`make image-build-local`) with the real,
//! pinned claude — the version gate, `/validate`, no build-time state, modes.
//! The only claude ever executed is the pinned Linux binary inside L2.
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const PREFIX: &str = "/aws/lambda-microvms/runtime/v1";
const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const FAKE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/claude-version.sh");

/// Every test starts here: panics unless explicitly enabled (the tests are
/// `#[ignore]`d, so reaching this without the variable is a mistake).
fn require_enabled() {
    assert_eq!(std::env::var("AI_ENV_DOCKER_TESTS").as_deref(), Ok("1"), "run through `make test-docker` (AI_ENV_DOCKER_TESTS=1)");
    let out = Command::new("docker").args(["version", "--format", "{{.Server.Version}}"]).output().expect("docker CLI on PATH");
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

fn docker(args: &[&str]) -> Output {
    Command::new("docker").args(args).output().expect("docker")
}

fn ok_stdout(args: &[&str]) -> String {
    let out = docker(args);
    assert!(out.status.success(), "docker {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A detached container, removed on drop.
struct Container {
    id: String,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.id]);
    }
}

impl Container {
    fn start(docker_args: &[&str], image: &str, cmd: &[&str]) -> Container {
        let mut args = vec!["run", "-d", "--platform", "linux/arm64", "-p", "127.0.0.1::9000", "-p", "127.0.0.1::8080", "-p", "127.0.0.1::9418"];
        args.extend_from_slice(docker_args);
        args.push(image);
        args.extend_from_slice(cmd);
        Container { id: ok_stdout(&args) }
    }

    fn port(&self, inner: u16) -> SocketAddr {
        let out = ok_stdout(&["port", &self.id, &format!("{inner}/tcp")]);
        out.lines().next().unwrap().trim().parse().unwrap_or_else(|e| panic!("{e}: {out:?}"))
    }

    fn logs(&self) -> String {
        let out = docker(&["logs", &self.id]);
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    }

    fn exec(&self, cmd: &[&str]) -> Output {
        let mut args = vec!["exec", &self.id[..]];
        args.extend_from_slice(cmd);
        docker(&args)
    }

    fn sh(&self, script: &str) -> String {
        let out = self.exec(&["sh", "-c", script]);
        assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
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

fn payload(owner: &str) -> String {
    use ai_env_cli::wire::frame::RunHookPayload;
    use ai_env_cli::wire::redact::Secret;
    RunHookPayload::new(&Secret::new("test-token".into()), owner, "2026-09-29T08:00:00Z").to_json().unwrap()
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

/// The image ENTRYPOINT's argv, from image/Dockerfile's exec-form line.
fn entrypoint() -> Vec<String> {
    let df = std::fs::read_to_string(Path::new(REPO).join("image/Dockerfile")).unwrap();
    let line = df.lines().find_map(|l| l.strip_prefix("ENTRYPOINT ")).expect("an ENTRYPOINT line");
    serde_json::from_str(line).unwrap_or_else(|e| panic!("ENTRYPOINT is not exec form ({e}): {line}"))
}

/// The shipped ENTRYPOINT argv (defaults it relies on included, e.g. no
/// `--gid`), with only the `--claude` value swapped for the fake, then
/// `shim_args`.
fn l1(conf: &str, docker_args: &[&str], shim_args: &[&str]) -> (Container, tempfile::TempDir) {
    require_enabled();
    let fake = fake_dir(conf);
    let mut argv = entrypoint();
    assert_eq!(argv.first().map(String::as_str), Some("/usr/local/bin/ai-env"), "the shim is mounted where the ENTRYPOINT runs it: {argv:?}");
    let at = argv.iter().position(|a| a == "--claude").expect("--claude in the ENTRYPOINT") + 1;
    argv[at] = "/opt/fake/claude".into();
    let shim_mount = format!("{}:/usr/local/bin/ai-env:ro", shim_binary().display());
    let fake_mount = format!("{}:/opt/fake:ro", fake.path().display());
    let mut args = vec!["-v", &shim_mount[..], "-v", &fake_mount[..], "--entrypoint", &argv[0][..]];
    args.extend_from_slice(docker_args);
    let mut cmd: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    cmd.extend_from_slice(shim_args);
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
    let h: ai_env_cli::wire::frame::Health = serde_json::from_str(&h).unwrap();
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
    let (c, _f) = l1("", &[], &["--hook-source", "enforce"]);
    wait_ready(&c, 20);
    let code = |url: &str| c.sh(&format!("curl -s -o /dev/null -w '%{{http_code}}' -X POST -d '{{}}' {url}"));
    assert_eq!(code(&format!("http://127.0.0.1:9000{PREFIX}/resume")), "403", "loopback");
    let ip = ok_stdout(&["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", &c.id]);
    assert!(!ip.is_empty());
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
    let (c, _f) = l1("", &[], &["--delay-run", "5"]);
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
    let h: ai_env_cli::wire::frame::Health = serde_json::from_str(&h).unwrap();
    assert_eq!(h.claude_version, Some(lock_version()));
    eprintln!("L2 ready after {:?}; {line}", started.elapsed());
}

#[test]
#[ignore = "Docker: make test-docker"]
fn l2_validate_200() {
    let c = l2();
    wait_ready(&c, 120);
    let (s, body) = http(c.port(9000), "POST", &format!("{PREFIX}/validate"), "");
    assert_eq!(s, 200, "{body}\n{}", c.logs());
    let logs = c.logs();
    for v in ["V1 ok", "V2 ok", "V3 ok", "V4 ok", "V5 ok"] {
        assert!(logs.contains(&format!("ai-env: validate {v}")), "{v}:\n{logs}");
    }
    assert!(logs.contains("ai-env: validate V3 ok 2 settings files parse and are readable by 1000:1000;"), "the agent is 1000:1000 (the --gid default):\n{logs}");
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
fn l2_no_defunct() {
    let c = l2();
    wait_ready(&c, 120);
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/run"), &run_body("mvm-z", Some(&payload("mike@mbp")))).0, 200);
    assert_eq!(http(c.port(9000), "POST", &format!("{PREFIX}/validate"), "").0, 200);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(c.zombies(), "", "{}", c.logs());
}
