//! Native shim tests (`--features shim`): the hooks, `/validate`, `/health`,
//! the code placeholder and the two-process init, in-process (the routers on
//! 127.0.0.1) and through the real binary. No reqwest here — the shim graph
//! has no HTTP client — so requests are written by hand on a TcpStream. No
//! test runs the real `claude` (a fake answers `--version`), steps the clock
//! or needs root.
use ai_env_cli::shim::health::{router, ProbeSpec, ShimOpts, ShimState};
use ai_env_cli::shim::hooks::{self, HookPeer, HookSource, PREFIX};
use ai_env_cli::shim::sys::{ClockMode, SysOps};
use ai_env_cli::wire::frame::{Health, HealthStatus, RunHookPayload};
use ai_env_cli::wire::pin::{render_lock, ClaudePin};
use ai_env_cli::wire::redact::Secret;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---- fakes ------------------------------------------------------------------

const FAKE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/claude-version.sh");

/// One 0755 copy of the fake under CARGO_TARGET_TMPDIR, hard-linked into
/// every test directory (macOS assesses the first exec of every NEW file,
/// ≈200 ms each, serialised; a hard link shares the inode).
fn fake_master() -> &'static Path {
    static MASTER: OnceLock<PathBuf> = OnceLock::new();
    MASTER.get_or_init(|| {
        use sha2::Digest;
        use std::os::unix::fs::PermissionsExt;
        let bytes = std::fs::read(FAKE).unwrap();
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fake-claude-version");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("claude-{}", &digest[..16]));
        if !path.exists() {
            let tmp = dir.join(format!(".claude-{}.{}.tmp", &digest[..16], std::process::id()));
            std::fs::write(&tmp, &bytes).unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::rename(&tmp, &path).unwrap();
        }
        path
    })
}

/// `<dir>/claude` (the fake) with its knobs in `<dir>/claude-version.conf`.
fn fake_claude(dir: &Path, conf: &str) -> PathBuf {
    let dest = dir.join("claude");
    if std::fs::hard_link(fake_master(), &dest).is_err() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::copy(FAKE, &dest).unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(dir.join("claude-version.conf"), conf).unwrap();
    dest
}

/// A machine for in-process tests: fixed clocks, nothing written anywhere.
struct TestSys;

impl SysOps for TestSys {
    fn now(&self) -> (u64, u128) {
        (1_790_000_000, 1_790_000_000_123_456_789)
    }
    fn rtc(&self) -> Option<u64> {
        Some(1_790_000_100)
    }
    fn kernel_random(&self) -> [u8; 32] {
        [7; 32]
    }
    fn mix(&self, _: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn reseed(&self) -> Result<(), String> {
        Err("not in tests".into())
    }
    fn cap_eff(&self) -> Option<u64> {
        None
    }
    fn set_clock(&self, _: u64) -> Result<(), String> {
        panic!("a test must never step the clock")
    }
}

fn uid_gid() -> (u32, u32) {
    (nix::unistd::geteuid().as_raw(), nix::unistd::getegid().as_raw())
}

/// The image's real managed-settings.json: the clean tree carries it, so a
/// weakened repo file fails `validate_passes_on_a_clean_tree` (V3).
const MANAGED: &str = include_str!("../../../image/managed-settings.json");

/// A VM-shaped tree under `root`: the lock (2.1.283), managed settings, the
/// baked `/Users/mike/.claude` subset — what the image holds.
fn plant_vm_tree(root: &Path) {
    let pin = ClaudePin {
        version: "2.1.283".into(),
        platform: "linux-arm64".into(),
        sha256: "ab".repeat(32),
        size: 240_902_136,
        build_date: "2026-09-25T01:39:37Z".into(),
    };
    let w = |rel: &str, text: &str| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    };
    w("etc/ai-env/claude.lock", &render_lock(&pin).unwrap());
    w("etc/claude-code/managed-settings.json", MANAGED);
    w("Users/mike/.claude/settings.json", r#"{"permissions":{"defaultMode":"default","allow":[]}}"#);
    w("Users/mike/.claude/CLAUDE.md", "# VM\n");
    w("Users/mike/.claude/.claude.json", r#"{"hasCompletedOnboarding":true,"projects":{}}"#);
    w("Users/mike/.claude.json", r#"{"hasCompletedOnboarding":true,"projects":{}}"#);
    for d in ["agents", "skills", "commands"] {
        std::fs::create_dir_all(root.join("Users/mike/.claude").join(d)).unwrap();
    }
}

fn opts(root: Option<&Path>, source: HookSource, delay: u64) -> ShimOpts {
    let (uid, gid) = uid_gid();
    ShimOpts { hook_source: source, clock: ClockMode::Measure, delay_run: delay, fs_root: root.map(Path::to_path_buf), home: PathBuf::from("/Users/mike"), uid, gid }
}

/// In-process state: listeners "bound", the fake claude probed once.
async fn state_with(claude: PathBuf, o: ShimOpts) -> Arc<ShimState> {
    let s = Arc::new(ShimState::with(claude, o, ProbeSpec::default(), Arc::new(TestSys)));
    s.set_bound();
    let _ = s.probe_once().await;
    s
}

async fn serve_hooks(state: Arc<ShimState>) -> SocketAddr {
    let l = tokio::net::TcpListener::bind(("0.0.0.0", 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(l, hooks::router(state).into_make_service_with_connect_info::<HookPeer>()).await.unwrap();
    });
    SocketAddr::from(([127, 0, 0, 1], port))
}

async fn serve_app(state: Arc<ShimState>) -> SocketAddr {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(l, router(state)).await.unwrap();
    });
    addr
}

/// One HTTP/1.1 request, `Connection: close`; (status, headers, body).
async fn http(addr: SocketAddr, method: &str, path: &str, body: &[u8], content_type: Option<&str>) -> (u16, String, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let ct = content_type.map_or(String::new(), |c| format!("Content-Type: {c}\r\n"));
    let head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{ct}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), s.read_to_end(&mut buf)).await.expect("response within 20 s").unwrap();
    split_response(&buf)
}

fn split_response(buf: &[u8]) -> (u16, String, String) {
    let text = String::from_utf8_lossy(buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or_else(|| panic!("no status in {text:?}"));
    (status, head.to_string(), body.to_string())
}

async fn hook(addr: SocketAddr, name: &str, body: &[u8]) -> (u16, String) {
    let (s, _, b) = http(addr, "POST", &format!("{PREFIX}/{name}"), body, Some("application/json")).await;
    (s, b)
}

fn payload_json(owner: &str) -> String {
    RunHookPayload::new(&Secret::new("test-token".into()), owner, "2026-09-29T08:00:00Z").to_json().unwrap()
}

fn run_body(microvm: &str, payload: Option<&str>) -> Vec<u8> {
    let mut m = serde_json::Map::new();
    m.insert("microvmId".into(), microvm.into());
    if let Some(p) = payload {
        m.insert("runHookPayload".into(), p.into());
    }
    serde_json::to_vec(&m).unwrap()
}

// ---- /health (S0) -------------------------------------------------------------

#[tokio::test]
async fn health_reports_shim_version() {
    let state = Arc::new(ShimState::new("/nonexistent/claude".into()));
    let addr = serve_app(state).await;
    let (status, _, body) = http(addr, "GET", "/health", b"", None).await;
    assert_eq!(status, 200, "{body}");
    let h: Health = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"));
    assert_eq!(h.status, HealthStatus::Ok);
    assert_eq!(h.shim_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(h.claude_version, None, "no claude at the configured path");
    assert!(!h.run_hook_seen);
    assert!(h.microvm_id.is_none());
}

// ---- hooks ----------------------------------------------------------------------

#[tokio::test]
async fn hooks_run_first_wins_replay_ok_other_409() {
    let t = tempfile::tempdir().unwrap();
    let addr = serve_hooks(state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await).await;
    let a = run_body("mvm-a", Some(&payload_json("mike@mbp")));
    assert_eq!(hook(addr, "run", &a).await.0, 200);
    let (s, b) = hook(addr, "run", &a).await;
    assert_eq!(s, 200, "a byte-identical replay is a retried delivery: {b}");
    assert!(b.contains("\"replay\":true"), "{b}");
    let (s, b) = hook(addr, "run", &run_body("mvm-a", Some(&payload_json("someone@else")))).await;
    assert_eq!(s, 409, "{b}");
    assert!(b.contains("already run"), "{b}");
    assert_eq!(hook(addr, "run", &run_body("mvm-a", None)).await.0, 409, "a later fail-closed body does not replace the record");
}

#[tokio::test]
async fn hooks_run_without_payload_is_fail_closed_200() {
    let t = tempfile::tempdir().unwrap();
    let state = state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await;
    let addr = serve_hooks(state.clone()).await;
    assert_eq!(hook(addr, "run", &run_body("mvm-b", None)).await.0, 200);
    let h = state.health().await;
    assert!(h.run_hook_seen);
    assert_eq!(h.microvm_id.as_deref(), Some("mvm-b"));
    assert!(h.owner.is_none() && h.created.is_none(), "no payload, no owner");
    assert_eq!(h.boot_nonce.as_deref().map(str::len), Some(32), "the nonce is minted anyway");
    assert!(state.run.payload().is_none(), "no commitment: every later hello is refused");
    // An empty body is the same fail-closed case.
    let t2 = tempfile::tempdir().unwrap();
    let s2 = state_with(fake_claude(t2.path(), ""), opts(None, HookSource::Log, 0)).await;
    let addr2 = serve_hooks(s2.clone()).await;
    assert_eq!(hook(addr2, "run", b"").await.0, 200);
    assert!(s2.health().await.run_hook_seen);
}

/// D13's fail-closed 200 covers every way the platform may say "no
/// payload" (missing, null, empty, blank), and `microvmId` is advisory: an
/// id outside `[A-Za-z0-9._-]{1,128}` (the platform's model allows an ARN
/// of up to 256 characters) is dropped, never a reason to refuse.
#[tokio::test]
async fn hooks_run_tolerates_blank_payloads_and_odd_ids() {
    let long = "a".repeat(129);
    let cases: [(Vec<u8>, Option<&str>); 11] = [
        (br#"{"microvmId":"mvm-1","runHookPayload":""}"#.to_vec(), Some("mvm-1")),
        (br#"{"microvmId":"mvm-1","runHookPayload":"   "}"#.to_vec(), Some("mvm-1")),
        (br#"{"microvmId":"mvm-1","runHookPayload":null}"#.to_vec(), Some("mvm-1")),
        (br#"{"microvmId":""}"#.to_vec(), None),
        (br#"{"microvmId":"01J9ZK3Q7V:abc"}"#.to_vec(), None),
        (run_body("arn:aws:lambda:eu-central-1:123456789012:microvm/mvm-1", None), None),
        (run_body(&long, None), None),
        (run_body("mvm c", None), None),
        (br#"{"microvmId":42}"#.to_vec(), None),
        (br#"{"microvmId":{"a":1}}"#.to_vec(), None),
        (br#"{"microvmId":null,"runHookPayload":null}"#.to_vec(), None),
    ];
    for (body, id) in cases {
        let shown = String::from_utf8_lossy(&body).to_string();
        let t = tempfile::tempdir().unwrap();
        let state = state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await;
        let addr = serve_hooks(state.clone()).await;
        let (s, b) = hook(addr, "run", &body).await;
        assert_eq!(s, 200, "{shown}: {b}");
        let h = state.health().await;
        assert!(h.run_hook_seen, "{shown}");
        assert_eq!(h.microvm_id.as_deref(), id, "{shown}");
        assert!(state.run.payload().is_none(), "fail-closed: {shown}");
    }
    // An odd id next to a valid payload: the payload is still the commitment.
    let t = tempfile::tempdir().unwrap();
    let state = state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await;
    let addr = serve_hooks(state.clone()).await;
    assert_eq!(hook(addr, "run", &run_body("a:b/c", Some(&payload_json("mike@mbp")))).await.0, 200);
    assert_eq!(state.health().await.microvm_id, None);
    assert_eq!(state.run.payload().map(|p| p.owner).as_deref(), Some("mike@mbp"));
}

#[tokio::test]
async fn hooks_run_bad_payload_is_400() {
    let t = tempfile::tempdir().unwrap();
    let state = state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await;
    let addr = serve_hooks(state.clone()).await;
    let bad_commit = payload_json("mike@mbp").replace("\"commit\":\"", "\"commit\":\"x");
    // 'é' straddles byte 19 of `created`: a 400, not a panicked connection.
    let multibyte = RunHookPayload::new(&Secret::new("test-token".into()), "mike@mbp", "2026-09-25T01:39:3\u{e9}Z").to_json().unwrap();
    for (body, want) in [
        (run_body("mvm-c", Some("not json")), "bad_payload"),
        (run_body("mvm-c", Some(&bad_commit)), "bad_payload"),
        (run_body("mvm-c", Some("{\"v\":1}")), "bad_payload"),
        (run_body("mvm-c", Some(&multibyte)), "bad_payload"),
        (br#"{"microvmId":"mvm-c","runHookPayload":{"v":1}}"#.to_vec(), "bad_payload"),
        (br#"{"microvmId":"mvm-c","runHookPayload":7}"#.to_vec(), "bad_payload"),
        (b"{not json".to_vec(), "bad_body"),
        (b"[1,2]".to_vec(), "bad_body"),
    ] {
        let (s, b) = hook(addr, "run", &body).await;
        assert_eq!(s, 400, "{}: {b}", String::from_utf8_lossy(&body));
        assert!(b.contains(want), "{b}");
    }
    assert!(!state.health().await.run_hook_seen, "a refused /run claims nothing");
    assert_eq!(hook(addr, "run", &run_body("mvm-c", Some(&payload_json("mike@mbp")))).await.0, 200, "a valid /run still wins");
}

#[tokio::test]
async fn hooks_run_4096_byte_payload_ok_4097_is_413() {
    let base = payload_json("mike@mbp");
    let at_cap = format!("{base}{}", " ".repeat(RunHookPayload::MAX_BYTES - base.len()));
    let over = format!("{at_cap} ");
    assert_eq!((at_cap.len(), over.len()), (4096, 4097));
    let t = tempfile::tempdir().unwrap();
    let addr = serve_hooks(state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await).await;
    let (s, b) = hook(addr, "run", &run_body("mvm-d", Some(&over))).await;
    assert_eq!(s, 413, "{b}");
    assert!(b.contains("payload_too_large"), "{b}");
    assert_eq!(hook(addr, "run", &run_body("mvm-d", Some(&at_cap))).await.0, 200, "exactly 4096 bytes is accepted");
    // The whole body is capped too (32 KiB).
    let t2 = tempfile::tempdir().unwrap();
    let addr2 = serve_hooks(state_with(fake_claude(t2.path(), ""), opts(None, HookSource::Log, 0)).await).await;
    let huge = format!("{{\"microvmId\":\"mvm-e\",\"pad\":\"{}\"}}", "x".repeat(33 * 1024));
    assert_eq!(hook(addr2, "run", huge.as_bytes()).await.0, 413);
}

#[tokio::test]
async fn hooks_log_policy_never_rejects_self_origin() {
    let t = tempfile::tempdir().unwrap();
    let addr = serve_hooks(state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await).await;
    assert_eq!(hook(addr, "run", &run_body("mvm-f", None)).await.0, 200);
    for h in ["resume", "suspend", "terminate"] {
        assert_eq!(hook(addr, h, b"{}").await.0, 200, "{h} from loopback under log");
    }
}

/// A non-loopback address of this machine (the default route's), without
/// sending anything; `None` offline.
fn lan_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

#[tokio::test]
async fn hooks_enforce_policy_rejects_self_origin_on_runtime_hooks() {
    let t = tempfile::tempdir().unwrap();
    let state = state_with(fake_claude(t.path(), ""), opts(None, HookSource::Enforce, 0)).await;
    let addr = serve_hooks(state.clone()).await;
    for h in ["run", "resume", "suspend", "terminate"] {
        let (s, b) = hook(addr, h, &run_body("mvm-g", None)).await;
        assert_eq!(s, 403, "{h}: {b}");
        assert!(b.contains("forbidden_origin") && b.contains("loopback"), "{b}");
    }
    assert!(!state.health().await.run_hook_seen, "a refused /run claims nothing");
    match lan_ip() {
        Some(ip) => {
            let own = SocketAddr::new(ip, addr.port());
            let (s, b) = hook(own, "run", &run_body("mvm-g", None)).await;
            assert_eq!(s, 403, "our own address counts as self: {b}");
            assert!(b.contains("\"origin\":\"self\""), "{b}");
        }
        None => eprintln!("no non-loopback address: the self-address case is covered by the unit tests only"),
    }
}

#[tokio::test]
async fn hooks_ready_and_validate_are_never_filtered() {
    let t = tempfile::tempdir().unwrap();
    let addr = serve_hooks(state_with(fake_claude(t.path(), ""), opts(Some(t.path()), HookSource::Enforce, 0)).await).await;
    let (s, b) = hook(addr, "ready", b"").await;
    assert_eq!(s, 200, "ready from loopback under enforce: {b}");
    let (s, b) = hook(addr, "validate", b"").await;
    assert_ne!(s, 403, "validate is never filtered: {b}");
}

#[tokio::test]
async fn hooks_accept_a_body_without_content_type() {
    let t = tempfile::tempdir().unwrap();
    let addr = serve_hooks(state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await).await;
    let body = run_body("mvm-h", Some(&payload_json("mike@mbp")));
    let (s, head, b) = http(addr, "POST", &format!("{PREFIX}/run"), &body, None).await;
    assert_eq!(s, 200, "no Content-Type is not a 415: {b}");
    assert!(head.to_ascii_lowercase().contains("connection: close"), "{head}");
    let (s, _, _) = http(addr, "POST", &format!("{PREFIX}/resume"), b"x", Some("text/plain")).await;
    assert_eq!(s, 200);
}

/// One hook request WITHOUT `Connection: close` (HTTP/1.1 keep-alive by
/// default); (status, head). Panics unless the server closes the socket.
async fn keep_alive_hook(addr: SocketAddr, name: &str, body: &[u8]) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("POST {PREFIX}/{name} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await.unwrap_or_else(|_| panic!("{name}: the server kept a keep-alive hook socket open")).unwrap();
    let (status, head, _) = split_response(&buf);
    (status, head)
}

/// Every hook response closes its connection, whatever the caller asked
/// for: no keep-alive socket survives a suspend. (`http` sends
/// `Connection: close` itself and hyper echoes it, so it cannot show this.)
#[tokio::test]
async fn hooks_close_a_keep_alive_connection() {
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    let addr = serve_hooks(state_with(fake_claude(t.path(), ""), opts(Some(t.path()), HookSource::Log, 0)).await).await;
    let u = tempfile::tempdir().unwrap();
    let enforce = serve_hooks(state_with(fake_claude(u.path(), ""), opts(None, HookSource::Enforce, 0)).await).await;
    let huge = format!("{{\"microvmId\":\"mvm-k\",\"pad\":\"{}\"}}", "x".repeat(33 * 1024));
    let cases: [(SocketAddr, &str, &[u8], u16); 8] = [
        (addr, "ready", b"", 200),
        (addr, "validate", b"", 200),
        (addr, "run", br#"{"microvmId":"mvm-k"}"#, 200),
        (addr, "resume", b"{}", 200),
        (addr, "suspend", b"{}", 200),
        (addr, "terminate", b"{}", 200),
        (enforce, "suspend", b"{}", 403),
        (addr, "run", huge.as_bytes(), 413),
    ];
    for (a, name, body, want) in cases {
        let (s, head) = keep_alive_hook(a, name, body).await;
        assert_eq!(s, want, "{name}: {head}");
        assert!(head.to_ascii_lowercase().contains("\r\nconnection: close"), "{name} ({s}): {head}");
    }
}

#[tokio::test]
async fn hooks_get_is_405_unknown_is_404() {
    let t = tempfile::tempdir().unwrap();
    let addr = serve_hooks(state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await).await;
    for h in ["ready", "validate", "run", "resume", "suspend", "terminate"] {
        let (s, _, _) = http(addr, "GET", &format!("{PREFIX}/{h}"), b"", None).await;
        assert_eq!(s, 405, "GET {h}");
    }
    assert_eq!(http(addr, "POST", &format!("{PREFIX}/nope"), b"", None).await.0, 404);
    assert_eq!(http(addr, "POST", "/health", b"", None).await.0, 404, "/health is on the app port only");
}

#[tokio::test]
async fn hooks_ready_is_503_until_the_probe_succeeds() {
    let t = tempfile::tempdir().unwrap();
    let state = Arc::new(ShimState::with(fake_claude(t.path(), "FAIL_FIRST=1\n"), opts(None, HookSource::Log, 0), ProbeSpec::default(), Arc::new(TestSys)));
    let addr = serve_hooks(state.clone()).await;
    let (s, b) = hook(addr, "ready", b"").await;
    assert_eq!(s, 503, "{b}");
    assert!(b.contains("listeners") && b.contains("claude"), "{b}");
    state.set_bound();
    assert!(state.probe_once().await.is_err(), "the first probe fails");
    let (s, b) = hook(addr, "ready", b"").await;
    assert_eq!(s, 503, "{b}");
    assert!(!b.contains("listeners") && b.contains("claude"), "{b}");
    state.probe_once().await.unwrap();
    assert_eq!(hook(addr, "ready", b"").await.0, 200);
}

// ---- /validate ------------------------------------------------------------------

async fn validate_in(root: &Path, conf: &str) -> (u16, String) {
    let claude = fake_claude(root, conf);
    let addr = serve_hooks(state_with(claude, opts(Some(root), HookSource::Log, 0)).await).await;
    hook(addr, "validate", b"").await
}

#[tokio::test]
async fn validate_passes_on_a_clean_tree() {
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    let (s, b) = validate_in(t.path(), "").await;
    assert_eq!(s, 200, "{b}");
    assert!(b.contains("valid"), "{b}");
}

#[tokio::test]
async fn validate_fails_on_version_mismatch() {
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    let (s, b) = validate_in(t.path(), "VERSION=2.1.282\n").await;
    assert_eq!(s, 503, "{b}");
    assert!(b.contains("V2") && b.contains("2.1.282") && b.contains("2.1.283"), "{b}");
    assert!(!b.contains("V3") && !b.contains("V4"), "only V2 fails: {b}");
    let u = tempfile::tempdir().unwrap();
    plant_vm_tree(u.path());
    std::fs::remove_file(u.path().join("etc/ai-env/claude.lock")).unwrap();
    let (s, b) = validate_in(u.path(), "").await;
    assert_eq!(s, 503);
    assert!(b.contains("V2") && b.contains("lock"), "a missing lock fails V2: {b}");
}

#[tokio::test]
async fn validate_fails_on_unparseable_settings() {
    for (rel, text) in [("etc/claude-code/managed-settings.json", "{"), ("Users/mike/.claude/settings.json", "[]")] {
        let t = tempfile::tempdir().unwrap();
        plant_vm_tree(t.path());
        std::fs::write(t.path().join(rel), text).unwrap();
        let (s, b) = validate_in(t.path(), "").await;
        assert_eq!(s, 503, "{rel}: {b}");
        assert!(b.contains("V3") && b.contains(rel.rsplit('/').next().unwrap()), "{rel}: {b}");
    }
    if uid_gid().0 != 0 {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        plant_vm_tree(t.path());
        std::fs::set_permissions(t.path().join("etc/claude-code/managed-settings.json"), std::fs::Permissions::from_mode(0o200)).unwrap();
        let (s, b) = validate_in(t.path(), "").await;
        assert_eq!(s, 503);
        assert!(b.contains("V3"), "an unparseable (here: unreadable by the shim itself) managed-settings file fails V3: {b}");
    }
}

/// V3's permission half: the shim (root in the VM, the owner here) reads the
/// file fine, but the agent's uid:gid could not, so claude would refuse to
/// start. The agent here is a foreign uid:gid; the check is computed from
/// the mode bits, so it holds under root too.
#[tokio::test]
async fn validate_fails_when_settings_are_closed_to_the_agent() {
    use std::os::unix::fs::PermissionsExt;
    async fn validate_as_foreign(root: &Path) -> (u16, String) {
        let (uid, gid) = uid_gid();
        let o = ShimOpts { uid: uid + 1, gid: gid + 1, ..opts(Some(root), HookSource::Log, 0) };
        let addr = serve_hooks(state_with(fake_claude(root, ""), o).await).await;
        hook(addr, "validate", b"").await
    }
    let (uid, gid) = uid_gid();
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    let (s, b) = validate_as_foreign(t.path()).await;
    assert_eq!(s, 200, "the planted tree is world-readable: {b}");
    let cases: [(&str, u32, &str); 3] = [
        ("etc/claude-code/managed-settings.json", 0o600, "not readable by"),
        ("Users/mike/.claude/settings.json", 0o600, "not readable by"),
        ("etc/claude-code", 0o700, "not searchable by"),
    ];
    for (rel, mode, want) in cases {
        let t = tempfile::tempdir().unwrap();
        plant_vm_tree(t.path());
        std::fs::set_permissions(t.path().join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
        let (s, b) = validate_as_foreign(t.path()).await;
        assert_eq!(s, 503, "{rel} {mode:o}: {b}");
        assert!(b.contains("V3") && b.contains(&format!("{want} {}:{}", uid + 1, gid + 1)), "{rel} {mode:o}: {b}");
    }
}

/// D6 in the file V3 reads: every missing or weakened hardening value is
/// named, and fails the build.
#[tokio::test]
async fn validate_fails_on_weakened_managed_settings() {
    let all = ["permissions.disableBypassPermissionsMode", "permissions.disableAutoMode", "env.DISABLE_AUTOUPDATER", "env.DISABLE_UPDATES"];
    let cases: [(&str, &[&str]); 3] = [
        (r#"{"permissions":{"disableBypassPermissionsMode":"enable","disableAutoMode":"disable"},"env":{"DISABLE_AUTOUPDATER":"1","DISABLE_UPDATES":"1"}}"#, &all[..1]),
        (r#"{"permissions":{"disableAutoMode":"disable"},"env":{"DISABLE_UPDATES":"1"}}"#, &[all[0], all[2]]),
        ("{}", &all),
    ];
    for (text, gaps) in cases {
        let t = tempfile::tempdir().unwrap();
        plant_vm_tree(t.path());
        std::fs::write(t.path().join("etc/claude-code/managed-settings.json"), text).unwrap();
        let (s, b) = validate_in(t.path(), "").await;
        assert_eq!(s, 503, "{text}: {b}");
        assert!(b.contains("V3") && b.contains("managed-settings.json"), "{text}: {b}");
        for g in all {
            assert_eq!(b.contains(g), gaps.contains(&g), "{g} in {text}: {b}");
        }
    }
}

/// V1 failing is answered at once: no fresh `claude --version` (up to 30 s)
/// before the 503; V2 is reported skipped, V3–V5 still run and are named.
#[tokio::test]
async fn validate_answers_at_once_while_not_ready() {
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    std::fs::create_dir_all(t.path().join("root/.claude")).unwrap();
    let runs = t.path().join("claude-runs");
    let claude = fake_claude(t.path(), &format!("SLEEP=5\nID_FILE={}\n", runs.display()));
    let state = Arc::new(ShimState::with(claude, opts(Some(t.path()), HookSource::Log, 0), ProbeSpec::default(), Arc::new(TestSys)));
    state.set_bound();
    let addr = serve_hooks(state).await;
    let started = Instant::now();
    let (s, b) = hook(addr, "validate", b"").await;
    let took = started.elapsed();
    assert_eq!(s, 503, "{b}");
    assert!(b.contains("V1: not ready") && b.contains("V2: skipped: not ready"), "{b}");
    assert!(b.contains("V4") && b.contains("/root/.claude"), "V4 still runs while not ready: {b}");
    assert!(took < Duration::from_millis(900), "a not-ready 503 is immediate, not after a probe: {took:?}");
    assert!(!runs.exists(), "no claude was started");
}

#[tokio::test]
async fn validate_fails_on_hygiene_hit() {
    type Plant = fn(&Path);
    let cases: [(&str, Plant); 14] = [
        ("/root/.claude", |r| std::fs::create_dir_all(r.join("root/.claude")).unwrap()),
        ("machine-id", |r| {
            std::fs::create_dir_all(r.join("etc")).unwrap();
            std::fs::write(r.join("etc/machine-id"), "0123456789abcdef0123456789abcdef\n").unwrap();
        }),
        ("identity key userID", |r| std::fs::write(r.join("Users/mike/.claude.json"), r#"{"hasCompletedOnboarding":true,"userID":"u"}"#).unwrap()),
        // D5: .claude.json is baked without project entries, in both places.
        ("Users/mike/.claude.json has project entries", |r| {
            let project = r#"{"hasCompletedOnboarding":true,"projects":{"/w":{"hasTrustDialogAccepted":true,"allowedTools":["Bash(*)"]}}}"#;
            std::fs::write(r.join("Users/mike/.claude.json"), project).unwrap();
        }),
        (".claude/.claude.json has project entries", |r| std::fs::write(r.join("Users/mike/.claude/.claude.json"), r#"{"projects":{"/w":{}}}"#).unwrap()),
        (".claude.json has project entries", |r| std::fs::write(r.join("Users/mike/.claude.json"), r#"{"projects":["/w"]}"#).unwrap()),
        (".config.json", |r| std::fs::write(r.join("Users/mike/.claude/.config.json"), "{}").unwrap()),
        ("unexpected entries in the claude config dir: projects", |r| std::fs::create_dir_all(r.join("Users/mike/.claude/projects")).unwrap()),
        // Below the baked (empty) directories: the whole tree is walked.
        ("unexpected entries in the claude config dir: skills/x, skills/x/SKILL.md", |r| {
            std::fs::create_dir_all(r.join("Users/mike/.claude/skills/x")).unwrap();
            std::fs::write(r.join("Users/mike/.claude/skills/x/SKILL.md"), "# x\n").unwrap();
        }),
        ("unexpected entries in the claude config dir: agents/foo.md", |r| std::fs::write(r.join("Users/mike/.claude/agents/foo.md"), "# foo\n").unwrap()),
        ("unexpected entries in the claude config dir: commands/projects", |r| std::fs::create_dir_all(r.join("Users/mike/.claude/commands/projects")).unwrap()),
        ("symlinks in the claude config dir: agents", |r| {
            std::fs::remove_dir(r.join("Users/mike/.claude/agents")).unwrap();
            std::fs::create_dir_all(r.join("elsewhere")).unwrap();
            std::fs::write(r.join("elsewhere/unreviewed.md"), "# x\n").unwrap();
            std::os::unix::fs::symlink(r.join("elsewhere"), r.join("Users/mike/.claude/agents")).unwrap();
        }),
        ("CLAUDE.md is not a regular file", |r| {
            std::fs::remove_file(r.join("Users/mike/.claude/CLAUDE.md")).unwrap();
            std::fs::create_dir(r.join("Users/mike/.claude/CLAUDE.md")).unwrap();
        }),
        ("commands is not a directory", |r| {
            std::fs::remove_dir(r.join("Users/mike/.claude/commands")).unwrap();
            std::fs::write(r.join("Users/mike/.claude/commands"), "").unwrap();
        }),
    ];
    for (want, plant) in cases {
        let t = tempfile::tempdir().unwrap();
        plant_vm_tree(t.path());
        plant(t.path());
        let (s, b) = validate_in(t.path(), "").await;
        assert_eq!(s, 503, "{want}: {b}");
        assert!(b.contains("V4") && b.contains(want), "{want}: {b}");
    }
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    std::fs::create_dir_all(t.path().join("etc")).unwrap();
    std::fs::write(t.path().join("etc/machine-id"), "").unwrap();
    assert_eq!(validate_in(t.path(), "").await.0, 200, "an EMPTY machine-id is fine");
}

#[tokio::test]
async fn validate_is_single_flight() {
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    let claude = fake_claude(t.path(), "");
    let state = state_with(claude, opts(Some(t.path()), HookSource::Log, 0)).await;
    std::fs::write(t.path().join("claude-version.conf"), "SLEEP=2\n").unwrap();
    let addr = serve_hooks(state).await;
    let first = tokio::spawn(async move { hook(addr, "validate", b"").await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (s, b) = hook(addr, "validate", b"").await;
    assert_eq!(s, 503, "{b}");
    assert!(b.contains("busy"), "{b}");
    let (s, b) = first.await.unwrap();
    assert_eq!(s, 200, "the first validate completes: {b}");
}

// ---- /health after /run -----------------------------------------------------------

#[tokio::test]
async fn health_after_run_has_nonce_owner_and_no_payload() {
    let t = tempfile::tempdir().unwrap();
    let state = state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await;
    let hooks_addr = serve_hooks(state.clone()).await;
    let app_addr = serve_app(state.clone()).await;
    let payload = payload_json("mike@mbp");
    assert_eq!(hook(hooks_addr, "run", &run_body("mvm-i", Some(&payload))).await.0, 200);
    let (s, _, body) = http(app_addr, "GET", "/health", b"", None).await;
    assert_eq!(s, 200);
    let h: Health = serde_json::from_str(&body).unwrap();
    assert!(h.run_hook_seen);
    assert_eq!(h.microvm_id.as_deref(), Some("mvm-i"));
    assert_eq!(h.owner.as_deref(), Some("mike@mbp"));
    assert_eq!(h.created.as_deref(), Some("2026-09-29T08:00:00Z"));
    assert_eq!(h.claude_version.as_deref(), Some("2.1.283"));
    let nonce = h.boot_nonce.unwrap();
    assert!(nonce.len() == 32 && nonce.bytes().all(|c| c.is_ascii_hexdigit()), "{nonce}");
    let commit = RunHookPayload::from_json(&payload).unwrap().commit;
    assert!(!body.contains(&commit) && !body.contains("commit"), "the payload never reaches /health: {body}");
}

#[tokio::test]
async fn delay_run_holds_run_hook_seen() {
    let t = tempfile::tempdir().unwrap();
    let state = state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 2)).await;
    let addr = serve_hooks(state.clone()).await;
    let started = Instant::now();
    let pending = tokio::spawn(async move { hook(addr, "run", &run_body("mvm-j", None)).await });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!state.health().await.run_hook_seen, "not seen while /run is held");
    assert_eq!(hook(addr, "run", &run_body("mvm-other", None)).await.0, 409, "the record is claimed at once");
    assert_eq!(pending.await.unwrap().0, 200);
    assert!(started.elapsed() >= Duration::from_secs(2), "{:?}", started.elapsed());
    assert!(state.health().await.run_hook_seen);
}

#[tokio::test]
async fn terminate_drains() {
    let t = tempfile::tempdir().unwrap();
    let state = state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await;
    let addr = serve_hooks(state.clone()).await;
    assert_eq!(hook(addr, "terminate", b"{}").await.0, 200);
    assert_eq!(state.health().await.status, HealthStatus::Draining);
}

#[tokio::test]
async fn code_port_answers_404() {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, ai_env_cli::shim::code::router()).await.unwrap() });
    for (m, p) in [("GET", "/"), ("PUT", "/seed"), ("GET", "/bundle?since=x")] {
        let (s, _, b) = http(addr, m, p, b"", None).await;
        assert_eq!(s, 404, "{m} {p}: {b}");
        assert!(b.contains("not implemented"), "{b}");
    }
}

// ---- the real binary: `ai-env shim` as the image ENTRYPOINT runs it ---------------

/// The `ai-env` built for this test run (same feature set as the tests).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env")
}

/// `ai-env <args>` with an EMPTY environment (`env -i`): PID 1 in the VM has
/// no HOME, no PATH, no keystore, and the shim must not need any of them.
fn ai_env(args: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env_clear().args(args).stdin(Stdio::null());
    cmd
}

#[test]
fn shim_help_lists_the_entrypoint_surface() {
    let out = ai_env(&["shim", "--help"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    for flag in ["--app-port", "--hooks-port", "--code-port", "--claude", "--home", "--uid", "--gid", "--echo", "--delay-run", "--hook-source", "--clock"] {
        assert!(text.contains(flag), "{flag} missing from:\n{text}");
    }
    // Per flag: the image ENTRYPOINT passes --uid but relies on --gid's default.
    for (head, default) in [
        ("--app-port <APP_PORT>", "8080"),
        ("--hooks-port <HOOKS_PORT>", "9000"),
        ("--code-port <CODE_PORT>", "9418"),
        ("--home <HOME>", "/Users/mike"),
        ("--uid <UID>", "1000"),
        ("--gid <GID>", "1000"),
        ("--hook-source <HOOK_SOURCE>", "log"),
        ("--clock <CLOCK>", "measure"),
    ] {
        let block = flag_block(&text, head);
        assert!(block.contains(&format!("[default: {default}]")), "{head}: [default: {default}] missing from {block:?}");
    }
    for hidden in ["--fs-root", "--init-pid", "--supervise", "--kill-after-s"] {
        assert!(!text.contains(hidden), "{hidden} is a hidden test/role flag:\n{text}");
    }
}

/// The help text of one flag: from `head` up to the next flag.
fn flag_block<'a>(help: &'a str, head: &str) -> &'a str {
    let start = help.find(head).unwrap_or_else(|| panic!("{head} missing from:\n{help}"));
    let tail = &help[start + head.len()..];
    let end = ["\n      -", "\n  -"].iter().filter_map(|m| tail.find(m)).min().unwrap_or(tail.len());
    &tail[..end]
}

/// The image ENTRYPOINT's argv, from image/Dockerfile's exec-form line.
fn entrypoint() -> Vec<String> {
    let df = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../image/Dockerfile")).unwrap();
    let line = df.lines().find_map(|l| l.strip_prefix("ENTRYPOINT ")).expect("an ENTRYPOINT line");
    serde_json::from_str(line).unwrap_or_else(|e| panic!("ENTRYPOINT is not exec form ({e}): {line}"))
}

/// What the shipped argv resolves to, defaults included (the gid is not on
/// the line: a changed default would run claude as 1000:<other>).
#[test]
fn the_image_entrypoint_runs_the_agent_as_1000_1000() {
    #[derive(clap::Parser)]
    struct Entry {
        #[command(flatten)]
        shim: ai_env_cli::shim::ShimArgs,
    }
    let argv = entrypoint();
    assert_eq!(argv[..2], ["/usr/local/bin/ai-env", "shim"], "{argv:?}");
    // argv[1] ("shim") stands in for the program name.
    let a = <Entry as clap::Parser>::try_parse_from(&argv[1..]).unwrap_or_else(|e| panic!("{e}: {argv:?}")).shim;
    assert_eq!((a.uid, a.gid), (1000, 1000));
    assert_eq!(a.home, PathBuf::from("/Users/mike"));
    assert_eq!(a.claude, PathBuf::from("/usr/local/bin/claude"));
    assert_eq!((a.app_port, a.hooks_port, a.code_port), (8080, 9000, 9418));
    assert_eq!((a.hook_source, a.clock), (HookSource::Log, ClockMode::Measure));
    assert!(!a.supervise && a.init_pid.is_none() && a.fs_root.is_none() && a.delay_run.is_none(), "PID 1 is init by its pid, not by a flag");
    assert_eq!(a.kill_after_s, 70);
}

#[test]
fn shim_without_claude_is_a_usage_error() {
    let out = ai_env(&["shim"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--claude"), "{err}");
}

#[test]
fn delay_run_above_25_is_a_usage_error() {
    let out = ai_env(&["shim", "--claude", "/x", "--delay-run", "26"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

/// A running `ai-env shim` whose stderr is collected on a thread; killed on
/// drop (process group included, via the supervisor's own forwarding when
/// `--supervise` is used, else directly).
struct Shim {
    child: std::process::Child,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Drop for Shim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What the stderr reader does besides collecting lines.
#[derive(Default, Clone, Copy)]
struct Watch {
    /// Send this signal to the shim process the moment a line containing
    /// the text is read (no polling delay: the startup window is short).
    signal_on: Option<(&'static str, nix::sys::signal::Signal)>,
    /// Stop reading and CLOSE stderr after a line containing the text; the
    /// reader then records [`STDERR_CLOSED`].
    close_after: Option<&'static str>,
}

const STDERR_CLOSED: &str = "<test: stderr reader closed>";

impl Shim {
    fn start(claude: &Path, extra: &[&str]) -> Shim {
        Shim::start_watching(claude, extra, Watch::default())
    }

    fn start_watching(claude: &Path, extra: &[&str], watch: Watch) -> Shim {
        let c = claude.to_str().unwrap();
        let mut args = vec!["shim", "--claude", c, "--app-port", "0", "--hooks-port", "0", "--code-port", "0"];
        args.extend_from_slice(extra);
        let mut child = ai_env(&args).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let pid = nix::unistd::Pid::from_raw(child.id() as i32);
        let stderr = child.stderr.take().unwrap();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        std::thread::spawn(move || {
            let mut signal_on = watch.signal_on;
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                let l = line.trim_end_matches('\n').to_string();
                line.clear();
                if let Some((needle, sig)) = signal_on.filter(|(n, _)| l.contains(n)) {
                    nix::sys::signal::kill(pid, sig).unwrap_or_else(|e| panic!("{sig} after {needle:?}: {e}"));
                    signal_on = None;
                }
                let close = watch.close_after.is_some_and(|n| l.contains(n));
                sink.lock().unwrap().push(l);
                if close {
                    drop(reader);
                    sink.lock().unwrap().push(STDERR_CLOSED.to_string());
                    return;
                }
            }
        });
        Shim { child, lines }
    }

    /// The first stderr line satisfying `f`, within `secs`.
    fn wait_line(&self, secs: u64, f: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if let Some(l) = self.lines.lock().unwrap().iter().find(|l| f(l)) {
                return l.clone();
            }
            assert!(Instant::now() < deadline, "no matching stderr line within {secs} s; got {:?}", self.lines.lock().unwrap());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn addr(&self, role: &str) -> SocketAddr {
        let needle = format!(" {role} listening on ");
        let line = self.wait_line(10, |l| l.starts_with("ai-env: shim ") && l.contains(&needle));
        let a: SocketAddr = line.split(&needle).nth(1).unwrap().trim().parse().unwrap_or_else(|e| panic!("{e}: {line:?}"));
        assert!(a.ip().is_unspecified(), "bound on all interfaces: {a}");
        assert_ne!(a.port(), 0, "the ACTUALLY bound port, not the requested 0");
        SocketAddr::from(([127, 0, 0, 1], a.port()))
    }

    fn worker_pid(&self) -> i32 {
        let line = self.wait_line(10, |l| l.starts_with("ai-env: shim worker pid "));
        line.trim_start_matches("ai-env: shim worker pid ").split_whitespace().next().unwrap().parse().unwrap()
    }
}

/// Blocking HTTP/1.1 for the binary tests; (status, body).
fn http_sync(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let (st, _, body) = split_response(&buf);
    (st, body)
}

#[test]
fn binary_binds_three_ports() {
    let t = tempfile::tempdir().unwrap();
    let shim = Shim::start(&fake_claude(t.path(), ""), &[]);
    let (hooks_addr, app, code) = (shim.addr("hooks"), shim.addr("app"), shim.addr("code"));
    assert!(hooks_addr.port() != app.port() && app.port() != code.port() && hooks_addr.port() != code.port());
    let (s, body) = http_sync(app, "GET", "/health");
    assert_eq!(s, 200, "{body}");
    let h: Health = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"));
    assert_eq!(h.shim_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(http_sync(code, "GET", "/").0, 404);
    let (s, _) = http_sync(hooks_addr, "POST", &format!("{PREFIX}/suspend"));
    assert_eq!(s, 200);
    shim.wait_line(5, |l| l.starts_with("ai-env: hook suspend peer=127.0.0.1:") && l.contains("origin=loopback") && l.contains("status=200"));
    shim.wait_line(5, |l| l.starts_with("ai-env: boot {\"pid\":"));
}

#[test]
fn binary_ready_flips_after_the_claude_probe() {
    let t = tempfile::tempdir().unwrap();
    let shim = Shim::start(&fake_claude(t.path(), "FAIL_FIRST=1\n"), &[]);
    let hooks_addr = shim.addr("hooks");
    shim.wait_line(10, |l| l.contains("claude probe failed"));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_503 = false;
    loop {
        let (s, body) = http_sync(hooks_addr, "POST", &format!("{PREFIX}/ready"));
        match s {
            503 => {
                assert!(body.contains("claude"), "{body}");
                saw_503 = true;
            }
            200 => break,
            other => panic!("unexpected {other}: {body}"),
        }
        assert!(Instant::now() < deadline, "/ready never flipped: {:?}", shim.lines.lock().unwrap());
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(saw_503, "the first probe failed, so /ready answered 503 before 200");
    shim.wait_line(5, |l| l.contains("claude probe ok") && l.contains("2.1.283 (Claude Code)"));
}

#[test]
fn shim_binary_stops_gracefully_on_sigterm() {
    let t = tempfile::tempdir().unwrap();
    let mut shim = Shim::start(&fake_claude(t.path(), ""), &[]);
    let _ = shim.addr("app");
    let started = Instant::now();
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(shim.child.id() as i32), nix::sys::signal::Signal::SIGTERM).unwrap();
    let status = wait_exit(&mut shim.child, 5);
    assert_eq!(status.code(), Some(0), "{:?}", shim.lines.lock().unwrap());
    assert!(started.elapsed() < Duration::from_secs(3));
    shim.wait_line(2, |l| l == "ai-env: shim stopped");
}

/// A startup error keeps its documented exit code (1) when nobody reads
/// stderr: `exit_on_error` must not panic on a closed pipe (exit 101), alone
/// or under the init, which passes the worker's status through.
#[test]
fn a_bind_failure_with_a_closed_stderr_still_exits_1() {
    let t = tempfile::tempdir().unwrap();
    let claude = fake_claude(t.path(), "");
    let taken = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    for extra in [&[][..], &["--supervise"][..]] {
        let mut args = vec!["shim", "--claude", claude.to_str().unwrap(), "--app-port", "0", "--code-port", "0", "--hooks-port", port.as_str()];
        args.extend_from_slice(extra);
        let out = ai_env(&args).stdout(Stdio::null()).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "{extra:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stderr).contains(&format!("cannot bind hooks port {port}")), "{extra:?}");
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut child = ai_env(&args).stdout(Stdio::null()).stderr(Stdio::from(writer)).spawn().unwrap();
        assert_eq!(wait_exit(&mut child, 10).code(), Some(1), "{extra:?}: a closed stderr must not turn exit 1 into a panic");
    }
    drop(taken);
}

fn wait_exit(child: &mut std::process::Child, secs: u64) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        assert!(Instant::now() < deadline, "did not exit within {secs} s");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn alive(pid: i32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
}

#[test]
fn supervise_forwards_sigterm_and_returns_the_worker_status() {
    let t = tempfile::tempdir().unwrap();
    let mut shim = Shim::start(&fake_claude(t.path(), ""), &["--supervise"]);
    let worker = shim.worker_pid();
    assert_ne!(worker, shim.child.id() as i32, "init and worker are two processes");
    shim.wait_line(10, |l| l.starts_with("ai-env: init pid "));
    let _ = shim.addr("app");
    let started = Instant::now();
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(shim.child.id() as i32), nix::sys::signal::Signal::SIGTERM).unwrap();
    let status = wait_exit(&mut shim.child, 5);
    assert_eq!(status.code(), Some(0), "the worker's graceful exit is init's status: {:?}", shim.lines.lock().unwrap());
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    shim.wait_line(2, |l| l.contains("init: forwarding SIGTERM"));
    shim.wait_line(2, |l| l.contains("init: worker exited"));
    assert!(!alive(worker), "the worker is gone and reaped");
}

#[test]
fn supervise_reports_a_signalled_worker_as_128_plus_signal() {
    let t = tempfile::tempdir().unwrap();
    let mut shim = Shim::start(&fake_claude(t.path(), ""), &["--supervise"]);
    let worker = shim.worker_pid();
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(worker), nix::sys::signal::Signal::SIGKILL).unwrap();
    let status = wait_exit(&mut shim.child, 5);
    assert_eq!(status.code(), Some(137), "{:?}", shim.lines.lock().unwrap());
}

#[test]
fn worker_exits_when_its_supervisor_dies() {
    let t = tempfile::tempdir().unwrap();
    let mut shim = Shim::start(&fake_claude(t.path(), ""), &["--supervise"]);
    let worker = shim.worker_pid();
    let _ = shim.addr("app");
    shim.child.kill().unwrap();
    let _ = shim.child.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(worker) {
        assert!(Instant::now() < deadline, "the orphaned worker is still running: {:?}", shim.lines.lock().unwrap());
        std::thread::sleep(Duration::from_millis(50));
    }
    shim.wait_line(2, |l| l.contains("shim stopping (init is gone)") || l.contains("shim stopping (SIGTERM)"));
}

fn signal(pid: u32, sig: nix::sys::signal::Signal) {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), sig).unwrap();
}

/// HUP/USR1/USR2 are forwarded by init and ignored by the worker (their
/// default action would end the worker, and PID 1 with it).
#[test]
fn supervise_forwards_hup_usr1_usr2_and_the_worker_ignores_them() {
    use nix::sys::signal::Signal;
    let t = tempfile::tempdir().unwrap();
    let mut shim = Shim::start(&fake_claude(t.path(), ""), &["--supervise"]);
    let worker = shim.worker_pid();
    let app = shim.addr("app");
    for sig in [Signal::SIGHUP, Signal::SIGUSR1, Signal::SIGUSR2] {
        signal(shim.child.id(), sig);
        shim.wait_line(5, |l| l == format!("ai-env: init: forwarding {sig} to the worker"));
        shim.wait_line(5, |l| l == format!("ai-env: {sig} ignored"));
        assert!(alive(worker), "{sig} ended the worker: {:?}", shim.lines.lock().unwrap());
        assert!(shim.child.try_wait().unwrap().is_none(), "{sig} ended init");
        assert_eq!(http_sync(app, "GET", "/health").0, 200, "{sig}");
    }
    signal(shim.child.id(), Signal::SIGTERM);
    assert_eq!(wait_exit(&mut shim.child, 5).code(), Some(0), "{:?}", shim.lines.lock().unwrap());
}

/// A signal init forwards while the worker is still starting — before tokio
/// has a handler, when the default action would apply — is ignored
/// (HUP/USR1/USR2) or stops the worker gracefully once it has bound
/// (TERM), never kills it. The signal goes to init the moment init prints
/// its "supervising" line, right after the worker's exec.
#[test]
fn supervise_worker_survives_signals_during_its_startup() {
    use nix::sys::signal::Signal;
    for sig in [Signal::SIGUSR1, Signal::SIGHUP, Signal::SIGUSR2] {
        let t = tempfile::tempdir().unwrap();
        let watch = Watch { signal_on: Some(("supervising worker pid", sig)), close_after: None };
        let mut shim = Shim::start_watching(&fake_claude(t.path(), ""), &["--supervise"], watch);
        shim.wait_line(5, |l| l == format!("ai-env: init: forwarding {sig} to the worker"));
        let app = shim.addr("app");
        let worker = shim.worker_pid();
        assert_eq!(http_sync(app, "GET", "/health").0, 200, "{sig}");
        assert!(alive(worker), "{sig} during startup ended the worker: {:?}", shim.lines.lock().unwrap());
        assert!(shim.child.try_wait().unwrap().is_none(), "{sig} during startup ended init: {:?}", shim.lines.lock().unwrap());
        signal(shim.child.id(), Signal::SIGTERM);
        assert_eq!(wait_exit(&mut shim.child, 5).code(), Some(0), "{sig}: {:?}", shim.lines.lock().unwrap());
    }
    let t = tempfile::tempdir().unwrap();
    let watch = Watch { signal_on: Some(("supervising worker pid", Signal::SIGTERM)), close_after: None };
    let mut shim = Shim::start_watching(&fake_claude(t.path(), ""), &["--supervise"], watch);
    let status = wait_exit(&mut shim.child, 10);
    assert_eq!(status.code(), Some(0), "a TERM during startup is a graceful stop: {:?}", shim.lines.lock().unwrap());
    shim.wait_line(2, |l| l == "ai-env: shim stopping (SIGTERM during startup)" || l == "ai-env: shim stopping (SIGTERM)");
    shim.wait_line(2, |l| l == "ai-env: shim stopped");
}

/// The kill timer: a worker whose graceful stop is held (here by an
/// in-flight `--delay-run` /run, which graceful shutdown waits for) is
/// SIGKILLed `--kill-after-s` after the stop signal, and init reports 137.
#[test]
fn supervise_sigkills_a_worker_that_outlives_the_kill_timer() {
    use nix::sys::signal::Signal;
    let t = tempfile::tempdir().unwrap();
    let mut shim = Shim::start(&fake_claude(t.path(), ""), &["--supervise", "--kill-after-s", "1", "--delay-run", "20"]);
    let worker = shim.worker_pid();
    let hooks_addr = shim.addr("hooks");
    let pending = std::thread::spawn(move || {
        let mut s = std::net::TcpStream::connect_timeout(&hooks_addr, Duration::from_secs(5)).unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = s.write_all(format!("POST {PREFIX}/run HTTP/1.1\r\nHost: {hooks_addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
    });
    shim.wait_line(5, |l| l == "ai-env: run delayed 20 s (--delay-run)");
    let started = Instant::now();
    signal(shim.child.id(), Signal::SIGTERM);
    let status = wait_exit(&mut shim.child, 6);
    assert_eq!(status.code(), Some(137), "{:?}", shim.lines.lock().unwrap());
    assert!(started.elapsed() >= Duration::from_secs(1), "not before the timer: {:?}", started.elapsed());
    shim.wait_line(2, |l| l == "ai-env: init: worker still alive 1 s after the stop signal; SIGKILL");
    assert!(!alive(worker), "the worker is gone and reaped");
    pending.join().unwrap();
}

/// Nobody reads stderr any more (every log line is EPIPE): lines are lost,
/// hooks are not, and SIGTERM still ends the shim with 0 — alone and under
/// init (which also keeps forwarding: SIGHUP must not end it).
#[test]
fn a_closed_stderr_loses_log_lines_not_hooks() {
    use nix::sys::signal::Signal;
    for extra in [&[][..], &["--supervise"][..]] {
        let t = tempfile::tempdir().unwrap();
        let watch = Watch { signal_on: None, close_after: Some("claude probe ok") };
        let mut shim = Shim::start_watching(&fake_claude(t.path(), ""), extra, watch);
        let hooks_addr = shim.addr("hooks");
        let app = shim.addr("app");
        shim.wait_line(10, |l| l == STDERR_CLOSED);
        for hook_name in ["ready", "suspend", "ready"] {
            let (s, body) = http_sync(hooks_addr, "POST", &format!("{PREFIX}/{hook_name}"));
            assert_eq!(s, 200, "{extra:?} {hook_name}: {body}");
        }
        if !extra.is_empty() {
            signal(shim.child.id(), Signal::SIGHUP);
            std::thread::sleep(Duration::from_millis(300));
            assert!(shim.child.try_wait().unwrap().is_none(), "init survives logging its forward of SIGHUP");
            assert_eq!(http_sync(app, "GET", "/health").0, 200, "and so does the worker");
        }
        signal(shim.child.id(), Signal::SIGTERM);
        assert_eq!(wait_exit(&mut shim.child, 5).code(), Some(0), "{extra:?}: {:?}", shim.lines.lock().unwrap());
    }
}
