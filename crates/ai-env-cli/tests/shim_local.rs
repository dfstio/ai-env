//! Native shim tests (`--features shim`): the hooks, `/validate`, `/health`,
//! the code placeholder, the two-process init, and (S6) the `/agent`
//! WebSocket, the session bearer and the peer guard, in-process (the routers
//! on 127.0.0.1) and through the real binary. No reqwest here — the shim
//! graph has no HTTP client — so requests are written by hand on a TcpStream
//! and the WebSocket client is tokio-tungstenite over a plain TcpStream. No
//! test runs the real `claude` (a fake answers `--version`), steps the clock
//! or needs root.
use ai_env_cli::shim::health::{router, ProbeSpec, ShimOpts, ShimState};
use ai_env_cli::shim::hooks::{self, HookPeer, HookSource, PREFIX};
use ai_env_cli::shim::peer::{AgentGuard, Peer, DRAIN_MAX};
use ai_env_cli::shim::sys::{ClockMode, SysOps};
use ai_env_cli::wire::frame::{
    ClientInfo, CredentialErrCode, CredentialView, Deliver, ErrorCode, EventKind, ExitInfo, Frame, Health, HealthDetail, HealthStatus, HelloErrCode, ResumePoint, ResumeStatus, Resumed, RunHookPayload, SpawnErrCode, SpawnId,
    CAP_CREDENTIAL_CACHE, CLOSE_GOING_AWAY, CLOSE_HELLO_REFUSED, CLOSE_PROTOCOL, CLOSE_TOO_BIG, MAX_UNAUTHENTICATED, WS_MAX_MESSAGE,
};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use ai_env_cli::wire::pin::{render_lock, ClaudePin};
use ai_env_cli::wire::redact::Secret;
use std::collections::BTreeMap;
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
    ShimOpts { hook_source: source, clock: ClockMode::Measure, delay_run: delay, fs_root: root.map(Path::to_path_buf), home: PathBuf::from("/Users/mike"), uid, gid, ..ShimOpts::default() }
}

/// In-process state: listeners "bound", the fake claude probed once.
async fn state_with(claude: PathBuf, o: ShimOpts) -> Arc<ShimState> {
    let s = Arc::new(ShimState::with(claude, o, ProbeSpec::default(), Arc::new(TestSys)));
    s.set_bound();
    let _ = s.probe_once().await;
    s
}

async fn serve_hooks(state: Arc<ShimState>) -> SocketAddr {
    serve_hooks_at(state, "0.0.0.0").await
}

/// The hooks router on `ip` (`0.0.0.0` where a test needs our own address too).
async fn serve_hooks_at(state: Arc<ShimState>, ip: &str) -> SocketAddr {
    let l = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
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
        axum::serve(l, router(state).into_make_service_with_connect_info::<Peer>()).await.unwrap();
    });
    addr
}

async fn serve_code(state: Arc<ShimState>) -> SocketAddr {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(l, ai_env_cli::shim::code::router(state).into_make_service_with_connect_info::<Peer>()).await.unwrap();
    });
    addr
}

/// One HTTP/1.1 request, `Connection: close`; (status, headers, body).
async fn http(addr: SocketAddr, method: &str, path: &str, body: &[u8], content_type: Option<&str>) -> (u16, String, String) {
    let ct = content_type.map_or(String::new(), |c| format!("Content-Type: {c}\r\n"));
    http_with(addr, method, path, &ct, body).await
}

/// [`http`] with extra header lines (each ending in CRLF).
async fn http_with(addr: SocketAddr, method: &str, path: &str, extra: &str, body: &[u8]) -> (u16, String, String) {
    try_http_with(addr, method, path, extra, body).await.unwrap_or_else(|e| panic!("{method} {path}: {e}"))
}

/// [`http_with`], with a reset (or a refused write) as the error.
async fn try_http_with(addr: SocketAddr, method: &str, path: &str, extra: &str, body: &[u8]) -> std::io::Result<(u16, String, String)> {
    let mut s = tokio::net::TcpStream::connect(addr).await?;
    let head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    s.write_all(head.as_bytes()).await?;
    s.write_all(body).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), s.read_to_end(&mut buf)).await.expect("response within 20 s")?;
    Ok(split_response(&buf))
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

/// The session token every `/run` payload here commits to.
const TOKEN: &str = "test-token";

fn payload_json(owner: &str) -> String {
    RunHookPayload::new(&Secret::new(TOKEN.into()), owner, "2026-09-29T08:00:00Z").to_json().unwrap()
}

fn bearer_header(token: &str) -> String {
    format!("Authorization: Bearer {token}\r\n")
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

/// Once `/run` was accepted `/validate` answers 409 at once and checks
/// nothing: the agent exists from then on, and V3 and V4 read its paths as
/// root. Here a FIFO at `<home>/.claude/settings.json` would hold V3's read
/// (and the single-flight lock) forever, and the fake claude records any
/// fresh `--version`. A check stuck on the FIFO blocks one of the two
/// workers and starves the runtime's timers, so the client is a blocking
/// socket with its own read timeout, and the test fails instead of hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validate_after_run_is_409_at_once_and_checks_nothing() {
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    let settings = t.path().join("Users/mike/.claude/settings.json");
    std::fs::remove_file(&settings).unwrap();
    nix::unistd::mkfifo(&settings, nix::sys::stat::Mode::S_IRWXU).unwrap();
    let _release = ReleaseFifo(settings);
    let runs = t.path().join("claude-runs");
    let state = state_with(fake_claude(t.path(), &format!("ID_FILE={}\n", runs.display())), opts(Some(t.path()), HookSource::Log, 0)).await;
    let addr = serve_hooks(state).await;
    assert_eq!(hook(addr, "run", &run_body("mvm-v", Some(&payload_json("mike@mbp")))).await.0, 200);
    let probes = std::fs::read_to_string(&runs).unwrap().lines().count();
    let started = Instant::now();
    let (s, b) = tokio::task::spawn_blocking(move || http_sync(addr, "POST", &format!("{PREFIX}/validate"))).await.expect("an answer within the read timeout, not a check stuck on the FIFO");
    assert_eq!(s, 409, "{b}");
    assert!(b.contains("\"already run\"") && started.elapsed() < Duration::from_secs(2), "{b} after {:?}", started.elapsed());
    assert_eq!(std::fs::read_to_string(&runs).unwrap().lines().count(), probes, "no fresh claude --version");
}

/// Opens a FIFO's write end without waiting, and closes it, on drop: a
/// reader stuck in open(2) on it (a check the test failed to stop) reads
/// EOF and lets the runtime end.
struct ReleaseFifo(PathBuf);

impl Drop for ReleaseFifo {
    fn drop(&mut self) {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(&self.0);
    }
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

/// The code port puts the session bearer in front of every path (S6): 401
/// before `/run`, without the bearer or with a wrong one; 404 "not
/// implemented" behind it.
#[tokio::test]
async fn code_port_answers_401_then_404_with_the_bearer() {
    let t = tempfile::tempdir().unwrap();
    let state = state_with(fake_claude(t.path(), ""), opts(None, HookSource::Log, 0)).await;
    let code = serve_code(state.clone()).await;
    let hooks_addr = serve_hooks(state).await;
    let paths = [("GET", "/"), ("PUT", "/seed"), ("GET", "/bundle?since=x")];
    for (m, p) in paths {
        let (s, head, b) = http_with(code, m, p, &bearer_header(TOKEN), b"").await;
        assert_eq!(s, 401, "before /run, no commitment: {m} {p}: {b}");
        assert!(head.to_ascii_lowercase().contains("www-authenticate: bearer"), "{head}");
    }
    assert_eq!(hook(hooks_addr, "run", &run_body("mvm-code", Some(&payload_json("mike@mbp")))).await.0, 200);
    for (m, p) in paths {
        let (s, _, b) = http(code, m, p, b"x", Some("text/plain")).await;
        assert_eq!(s, 401, "{m} {p}: {b}");
        assert!(b.contains("unauthorized"), "{b}");
        assert_eq!(http_with(code, m, p, &bearer_header("not-the-token"), b"").await.0, 401, "{m} {p}: a wrong token");
        let (s, _, b) = http_with(code, m, p, &bearer_header(TOKEN), b"").await;
        assert_eq!(s, 404, "{m} {p}: {b}");
        assert!(b.contains("not implemented (S8/S9)"), "{b}");
    }
}

// ---- S6: /agent, the session bearer, the peer guard ---------------------------------

/// One in-process shim on 127.0.0.1 with OS-chosen ports: hooks, app, code.
struct Stack {
    state: Arc<ShimState>,
    hooks: SocketAddr,
    app: SocketAddr,
    code: SocketAddr,
    _dir: tempfile::TempDir,
}

async fn stack(o: ShimOpts) -> Stack {
    let dir = tempfile::tempdir().unwrap();
    let state = state_with(fake_claude(dir.path(), ""), o).await;
    let (hooks, app, code) = (serve_hooks_at(state.clone(), "127.0.0.1").await, serve_app(state.clone()).await, serve_code(state.clone()).await);
    Stack { state, hooks, app, code, _dir: dir }
}

impl Stack {
    async fn log() -> Stack {
        stack(opts(None, HookSource::Log, 0)).await
    }

    /// `/run` committing to [`TOKEN`], or fail-closed (no payload).
    async fn run(&self, commit: bool) {
        let payload = commit.then(|| payload_json("mike@mbp"));
        assert_eq!(hook(self.hooks, "run", &run_body("mvm-agent", payload.as_deref())).await.0, 200);
    }

    /// `GET /health/detail` with the bearer.
    async fn detail(&self) -> (HealthDetail, String) {
        let (st, _, body) = http_with(self.app, "GET", "/health/detail", &bearer_header(TOKEN), b"").await;
        assert_eq!(st, 200, "{body}");
        (serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}")), body)
    }

    /// Wait (at most 5 s) until the registry counts (open, past hello) are `want`.
    async fn wait_sockets(&self, want: (u32, u32)) {
        let until = Instant::now() + Duration::from_secs(5);
        while self.state.agents.counts() != want {
            assert!(Instant::now() < until, "sockets {:?}, want {want:?}", self.state.agents.counts());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_no_sockets(&self) {
        self.wait_sockets((0, 0)).await;
    }
}

type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// A WebSocket to `/agent` over a plain TcpStream; the 101 carries no subprotocol.
async fn ws(app: SocketAddr) -> Ws {
    let tcp = tokio::net::TcpStream::connect(app).await.unwrap();
    let dial = tokio_tungstenite::client_async_with_config(format!("ws://{app}/agent"), tcp, Some(ai_env_cli::wire::frame::ws_config()));
    let (ws, resp) = tokio::time::timeout(Duration::from_secs(10), dial).await.expect("an upgrade answer within 10 s").expect("101");
    assert!(resp.headers().get("sec-websocket-protocol").is_none(), "{resp:?}");
    ws
}

fn hello(token: &str) -> Frame {
    hello_resuming(token, vec![])
}

fn hello_resuming(token: &str, resume: Vec<ResumePoint>) -> Frame {
    Frame::Hello { session_token: Secret::new(token.to_string()), client: ClientInfo { name: "shim_local".into(), version: env!("CARGO_PKG_VERSION").into(), host: "test@host".into() }, resume, idle_s: None }
}

/// Send one message within 20 s; `false` when the socket refused it (a reset).
async fn send_msg(w: &mut Ws, m: Message) -> bool {
    tokio::time::timeout(Duration::from_secs(20), w.send(m)).await.expect("a send within 20 s").is_ok()
}

async fn send_frame(w: &mut Ws, f: &Frame) {
    assert!(send_msg(w, Message::from(f)).await, "the socket took {}", f.kind());
}

/// The next frame, or how the socket ended: `Err(Some(code))` after a Close
/// (read on to the end, so the client's answer goes out), `Err(None)` after a
/// reset or an end without one.
async fn next_frame(w: &mut Ws) -> Result<Frame, Option<u16>> {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), w.next()).await.expect("a message within 10 s") {
            Some(Ok(Message::Text(t))) => return Ok(Frame::from_json(t.as_str()).unwrap_or_else(|e| panic!("{e}"))),
            Some(Ok(Message::Close(f))) => {
                let _ = tokio::time::timeout(Duration::from_secs(5), async { while let Some(Ok(_)) = w.next().await {} }).await;
                return Err(f.map(|f| u16::from(f.code)));
            }
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return Err(None),
        }
    }
}

/// A socket past `hello`.
async fn ws_hello_ok(app: SocketAddr) -> Ws {
    let mut w = ws(app).await;
    send_frame(&mut w, &hello(TOKEN)).await;
    match next_frame(&mut w).await {
        Ok(Frame::HelloOk { wire, run_hook_seen, has_credentials, owner, .. }) => assert_eq!((wire, run_hook_seen, has_credentials, owner.as_deref()), (1, true, false, Some("mike@mbp"))),
        other => panic!("hello_ok, got {other:?}"),
    }
    w
}

async fn ping(w: &mut Ws, ts: u64) {
    send_frame(w, &Frame::Ping { ts }).await;
    assert_eq!(next_frame(w).await, Ok(Frame::Pong { ts }), "the socket is up");
}

/// An upgrade request's head (no blank line): the four WebSocket headers but
/// those named in `skip` (`connection`, `upgrade`, `version`, `key`), then `extra`.
fn upgrade_head(addr: SocketAddr, method: &str, http: &str, skip: &[&str], extra: &[&str]) -> String {
    let mut lines = vec![format!("{method} /agent {http}"), format!("Host: {addr}")];
    for (name, line) in [("connection", "Connection: Upgrade"), ("upgrade", "Upgrade: websocket"), ("version", "Sec-WebSocket-Version: 13"), ("key", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==")] {
        if !skip.contains(&name) {
            lines.push(line.to_string());
        }
    }
    lines.extend(extra.iter().map(|l| (*l).to_string()));
    lines.join("\r\n")
}

/// One raw request; (status, head, body), the body read by its
/// Content-Length (the server may keep the connection open).
async fn raw(addr: SocketAddr, head: &str) -> (u16, String, String) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("{head}\r\n\r\n").as_bytes()).await.unwrap();
    let complete = |buf: &[u8]| {
        let text = String::from_utf8_lossy(buf);
        let Some((head, body)) = text.split_once("\r\n\r\n") else { return false };
        let len = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
        body.len() >= len
    };
    let (mut buf, mut chunk) = (Vec::new(), [0u8; 4096]);
    while !complete(&buf) {
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut chunk)).await.expect("a response within 10 s").unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    split_response(&buf)
}

#[tokio::test]
async fn agent_before_run_is_503_not_run_with_retry_after() {
    let s = Stack::log().await;
    let (st, head, body) = raw(s.app, &upgrade_head(s.app, "GET", "HTTP/1.1", &[], &[])).await;
    assert_eq!(st, 503, "{head}{body}");
    assert!(head.to_ascii_lowercase().contains("\r\nretry-after: 1"), "{head}");
    assert!(body.contains("\"not_run\""), "{body}");
    assert_eq!(s.state.agents.counts(), (0, 0), "nothing is reserved for a refused upgrade");
}

#[tokio::test]
async fn agent_hello_after_a_fail_closed_run_is_no_commitment_4403() {
    let s = Stack::log().await;
    s.run(false).await;
    let mut w = ws(s.app).await;
    send_frame(&mut w, &hello(TOKEN)).await;
    assert!(matches!(next_frame(&mut w).await, Ok(Frame::HelloErr { code: HelloErrCode::NoCommitment, .. })));
    assert_eq!(next_frame(&mut w).await, Err(Some(CLOSE_HELLO_REFUSED)));
    s.wait_no_sockets().await;
}

#[tokio::test]
async fn agent_hello_with_another_token_is_bad_token_4403() {
    let s = Stack::log().await;
    s.run(true).await;
    let mut w = ws(s.app).await;
    send_frame(&mut w, &hello("not-the-token")).await;
    assert!(matches!(next_frame(&mut w).await, Ok(Frame::HelloErr { code: HelloErrCode::BadToken, .. })));
    assert_eq!(next_frame(&mut w).await, Err(Some(CLOSE_HELLO_REFUSED)));
    let mut ok = ws_hello_ok(s.app).await;
    ping(&mut ok, 1).await;
}

/// Binary messages and unknown kinds are answered and the socket stays up;
/// `/health` and `/health/detail` answer while it is open; malformed JSON
/// ends it with `bad_frame` and 1008.
#[tokio::test]
async fn agent_socket_answers_binary_unknown_and_malformed_frames() {
    let s = Stack::log().await;
    s.run(true).await;
    let mut w = ws_hello_ok(s.app).await;
    assert!(send_msg(&mut w, Message::binary(vec![0u8, 1, 2])).await);
    assert!(matches!(next_frame(&mut w).await, Ok(Frame::Error { code: ErrorCode::BinaryRejected, .. })));
    ping(&mut w, 1).await;
    assert!(send_msg(&mut w, Message::text("{\"v\":1,\"t\":\"from_a_later_wire\",\"x\":1}")).await);
    assert!(matches!(next_frame(&mut w).await, Ok(Frame::Error { code: ErrorCode::UnknownFrame, .. })));
    ping(&mut w, 2).await;
    let (st, _, body) = http(s.app, "GET", "/health", b"", None).await;
    assert_eq!(st, 200, "/health while a socket is open: {body}");
    let (d, _) = s.detail().await;
    assert_eq!((d.sockets_open, d.sockets_authenticated), (1, 1));
    assert!(send_msg(&mut w, Message::text("{\"v\":1,\"t\":\"ping\",")).await);
    assert!(matches!(next_frame(&mut w).await, Ok(Frame::Error { code: ErrorCode::BadFrame, .. })));
    assert_eq!(next_frame(&mut w).await, Err(Some(CLOSE_PROTOCOL)));
    s.wait_no_sockets().await;
}

/// A message over the 16 MiB cap closes its socket (1009, or a reset when
/// the close loses the race); the shim serves the next socket.
#[tokio::test]
async fn agent_message_over_16_mib_closes_1009_and_the_shim_serves_on() {
    let s = Stack::log().await;
    s.run(true).await;
    let mut w = ws_hello_ok(s.app).await;
    let end = if send_msg(&mut w, Message::text("x".repeat(WS_MAX_MESSAGE + 1))).await { next_frame(&mut w).await } else { Err(None) };
    assert!(matches!(end, Err(Some(CLOSE_TOO_BIG) | None)), "{end:?}");
    drop(w);
    let mut again = ws_hello_ok(s.app).await;
    ping(&mut again, 3).await;
}

/// T6.1 strict: a message over the cap ends only its socket, never the
/// spawn attached to it. For a text and a binary message of
/// `WS_MAX_MESSAGE + 1` bytes, each on the socket the spawn is attached to,
/// the end is 1009 (or a reset when the close loses the race), and a new
/// socket's hello resumes the spawn: alive, the same pid, no grace running.
#[tokio::test]
async fn a_spawn_survives_a_1009_close_and_resumes_on_a_new_socket() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    let (pid, _) = start(&mut w, &id, &["/bin/sleep", "30"], Some(60)).await;
    for big in [Message::text("x".repeat(WS_MAX_MESSAGE + 1)), Message::binary(vec![b'x'; WS_MAX_MESSAGE + 1])] {
        let what = if big.is_text() { "text" } else { "binary" };
        let end = if send_msg(&mut w, big).await { next_frame(&mut w).await } else { Err(None) };
        assert!(matches!(end, Err(Some(CLOSE_TOO_BIG) | None)), "{what}: {end:?}");
        drop(w);
        w = ws(s.app).await;
        send_frame(&mut w, &hello_resuming(TOKEN, vec![ResumePoint { spawn_id: id.clone(), from_seq: None, err_from_seq: None }])).await;
        match next_frame(&mut w).await {
            Ok(Frame::HelloOk { resumed, spawns, .. }) => {
                assert_eq!(resumed, vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }], "{what}");
                let st = spawns.iter().find(|x| x.spawn_id == id).unwrap_or_else(|| panic!("{what}: {id} listed: {spawns:?}"));
                assert!(st.alive && st.pid == pid, "{what}: {st:?}");
            }
            other => panic!("{what}: hello_ok, got {other:?}"),
        }
        let (d, _) = s.detail().await;
        assert_eq!(d.spawns.iter().find(|x| x.status.spawn_id == id).map(|x| x.detach_left_s), Some(None), "{what}: attached to the new socket: {:?}", d.spawns);
    }
    send_frame(&mut w, &Frame::Detach { spawn_id: id, is_final: true }).await;
    ping(&mut w, 11).await;
    s.state.spawns.shutdown("test").await;
}

/// The upgrade checks (axum 0.8.9's order, `Connection` as a token list):
/// 400 for each missing or wrong header and for `Connection: close`, 405 for
/// another method, 426 for HTTP/1.0 (hyper offers no upgrade); all four
/// right: 101 with the RFC 6455 accept key and no subprotocol.
#[tokio::test]
async fn agent_upgrade_negatives() {
    let s = Stack::log().await;
    s.run(true).await;
    let a = s.app;
    for (what, head) in [
        ("no Upgrade", upgrade_head(a, "GET", "HTTP/1.1", &["upgrade"], &[])),
        ("no Connection", upgrade_head(a, "GET", "HTTP/1.1", &["connection"], &[])),
        ("Connection: close", upgrade_head(a, "GET", "HTTP/1.1", &["connection"], &["Connection: Upgrade, close"])),
        ("version 8", upgrade_head(a, "GET", "HTTP/1.1", &["version"], &["Sec-WebSocket-Version: 8"])),
        ("no key", upgrade_head(a, "GET", "HTTP/1.1", &["key"], &[])),
    ] {
        let (st, _, body) = raw(a, &head).await;
        assert_eq!(st, 400, "{what}: {body}");
    }
    let (st, head, _) = raw(a, &upgrade_head(a, "POST", "HTTP/1.1", &[], &["Content-Length: 0"])).await;
    assert_eq!(st, 405, "{head}");
    assert!(head.to_ascii_lowercase().contains("\r\nallow: get"), "{head}");
    let (st, _, body) = raw(a, &upgrade_head(a, "GET", "HTTP/1.0", &[], &[])).await;
    assert_eq!(st, 426, "{body}");
    let (st, head, _) = raw(a, &upgrade_head(a, "GET", "HTTP/1.1", &[], &[])).await;
    assert_eq!(st, 101, "{head}");
    let h = head.to_ascii_lowercase();
    assert!(h.contains("\r\nconnection: upgrade") && h.contains("\r\nupgrade: websocket") && h.contains("\r\nsec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="), "{head}");
    assert!(!h.contains("sec-websocket-protocol"), "{head}");
}

/// At most MAX_UNAUTHENTICATED sockets may wait for their hello: the next
/// upgrade gets 503 `busy`, and `busy` comes before axum's checks (agent.rs's
/// order), so a malformed upgrade, a POST or an HTTP/1.0 one gets it too,
/// never a 400, 405 or 426; a socket past hello frees its slot.
#[tokio::test]
async fn agent_upgrade_is_busy_after_max_unauthenticated() {
    let s = Stack::log().await;
    s.run(true).await;
    let mut held = Vec::new();
    for _ in 0..MAX_UNAUTHENTICATED {
        let mut t = tokio::net::TcpStream::connect(s.app).await.unwrap();
        t.write_all(format!("{}\r\n\r\n", upgrade_head(s.app, "GET", "HTTP/1.1", &[], &[])).as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            assert_eq!(tokio::time::timeout(Duration::from_secs(10), t.read(&mut b)).await.expect("a 101 within 10 s").unwrap(), 1);
            head.push(b[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
        held.push(t);
    }
    s.wait_sockets((u32::try_from(MAX_UNAUTHENTICATED).unwrap(), 0)).await;
    let a = s.app;
    for (what, head) in [
        ("well-formed", upgrade_head(a, "GET", "HTTP/1.1", &[], &[])),
        ("no key", upgrade_head(a, "GET", "HTTP/1.1", &["key"], &[])),
        ("version 8", upgrade_head(a, "GET", "HTTP/1.1", &["version"], &["Sec-WebSocket-Version: 8"])),
        ("POST", upgrade_head(a, "POST", "HTTP/1.1", &[], &["Content-Length: 0"])),
        ("HTTP/1.0", upgrade_head(a, "GET", "HTTP/1.0", &[], &[])),
    ] {
        let (st, _, body) = raw(a, &head).await;
        assert_eq!(st, 503, "{what}: {body}");
        assert!(body.contains("\"busy\""), "{what}: {body}");
    }
    drop(held);
    s.wait_no_sockets().await;
    let mut w = ws_hello_ok(s.app).await;
    ping(&mut w, 10).await;
}

/// The app port: `/health` and `/agent` are public; `/health/detail` and
/// every other path need the session bearer (401 without, and before any
/// commitment exists); an unknown path is 404 behind it.
#[tokio::test]
async fn app_port_bearer() {
    let s = Stack::log().await;
    assert_eq!(http_with(s.app, "GET", "/health/detail", &bearer_header(TOKEN), b"").await.0, 401, "no commitment before /run");
    s.run(true).await;
    assert_eq!(http(s.app, "GET", "/health", b"", None).await.0, 200);
    for (m, p, body) in [("PUT", "/transcript", &b"{}"[..]), ("GET", "/health/detail", b""), ("POST", "/seed", b"x")] {
        let (st, head, b) = http(s.app, m, p, body, Some("application/json")).await;
        assert_eq!(st, 401, "{m} {p}: {b}");
        assert!(b.contains("\"unauthorized\"") && head.to_ascii_lowercase().contains("www-authenticate: bearer"), "{head}{b}");
        assert_eq!(http_with(s.app, m, p, &bearer_header("not-the-token"), body).await.0, 401, "{m} {p}: a wrong token");
    }
    let (st, _, b) = http_with(s.app, "PUT", "/transcript", &bearer_header(TOKEN), b"{}").await;
    assert_eq!(st, 404, "{b}");
    assert!(b.contains("not implemented (S8/S9)"), "{b}");
    let (d, body) = s.detail().await;
    for key in ["\"hook_source\":\"log\"", "\"agent_guard\":\"off\"", "\"listeners\":", "\"refused_peers\":", "\"hook_peers\":", "\"wire\":1"] {
        assert!(body.contains(key), "{key} in {body}");
    }
    assert!(d.health.run_hook_seen && !d.has_credentials && d.spawns.is_empty());
    assert_eq!(d.listeners.is_empty(), !cfg!(target_os = "linux"), "the LISTEN inventory exists on Linux only: {:?}", d.listeners);
    assert!(!body.contains(TOKEN) && !body.contains("commit"), "{body}");
}

/// Every answer of the side ports reads the request body first (at most
/// `DRAIN_MAX`): an answer over unread request bytes makes the kernel reset
/// the connection, and the client loses the answer. A body just under the
/// bound, a few times each: the 404 behind the bearer on both ports, the
/// 405s, and an `/agent` refusal.
#[tokio::test]
async fn side_port_answers_read_the_body_first() {
    let s = Stack::log().await;
    s.run(true).await;
    let body = vec![b'x'; DRAIN_MAX - 1024];
    let bearer = bearer_header(TOKEN);
    let mut lost = Vec::new();
    for (addr, method, path, extra, want) in [
        (s.app, "PUT", "/transcript", bearer.as_str(), 404),
        (s.code, "PUT", "/seed", bearer.as_str(), 404),
        (s.app, "POST", "/health", "", 405),
        (s.app, "POST", "/health/detail", bearer.as_str(), 405),
        (s.app, "POST", "/agent", "", 405),
    ] {
        for i in 0..5 {
            match try_http_with(addr, method, path, extra, &body).await {
                Ok((st, _, b)) => assert_eq!(st, want, "{method} {path} #{i}: {b}"),
                Err(e) => lost.push(format!("{method} {path} #{i}: {e}")),
            }
        }
    }
    assert!(lost.is_empty(), "answers lost to a reset: {lost:#?}");
}

/// `--agent-guard on` refuses a local client first, on both side ports and
/// on `/agent`, counting every refusal. Natively the client has no row
/// (macOS) or is this test's own uid, the agent's here (Linux).
#[tokio::test]
async fn guard_on_refuses_a_local_agent_client_before_the_bearer() {
    let s = stack(ShimOpts { agent_guard: AgentGuard::On, ..opts(None, HookSource::Log, 0) }).await;
    s.run(true).await;
    let want = if cfg!(target_os = "linux") { "agent_uid" } else { "no_row" };
    for (addr, path) in [(s.app, "/health"), (s.app, "/health/detail"), (s.code, "/seed")] {
        let (st, _, b) = http_with(addr, "GET", path, &bearer_header(TOKEN), b"").await;
        assert_eq!(st, 403, "{path}: {b}");
        assert!(b.contains("\"forbidden_peer\"") && b.contains(want), "{b}");
    }
    let (st, _, b) = raw(s.app, &upgrade_head(s.app, "GET", "HTTP/1.1", &[], &[])).await;
    assert_eq!(st, 403, "{b}");
    let refused = s.state.detail().await.refused_peers;
    assert_eq!(refused.get(&s.app.port().to_string()), Some(&3), "{refused:?}");
    assert_eq!(refused.get(&s.code.port().to_string()), Some(&1), "{refused:?}");
}

#[tokio::test]
async fn guard_log_refuses_nothing() {
    let s = stack(ShimOpts { agent_guard: AgentGuard::Log, ..opts(None, HookSource::Log, 0) }).await;
    s.run(true).await;
    assert_eq!(http(s.app, "GET", "/health", b"", None).await.0, 200);
    assert_eq!(http(s.code, "GET", "/", b"", None).await.0, 401, "past the guard, the bearer");
    let mut w = ws_hello_ok(s.app).await;
    ping(&mut w, 5).await;
    assert!(s.state.detail().await.refused_peers.is_empty());
}

/// `--hook-source peer`: local clients are refused 403 `forbidden_peer` on
/// the runtime hooks — a forged `/terminate` drains nothing — counted and
/// recorded as each hook's last peer; `/ready` is never filtered.
#[tokio::test]
async fn hooks_peer_mode_refuses_local_runtime_hooks() {
    let s = stack(opts(None, HookSource::Peer, 0)).await;
    let want = if cfg!(target_os = "linux") { "agent_uid" } else { "no_row" };
    for h in ["run", "resume", "suspend", "terminate"] {
        let (st, b) = hook(s.hooks, h, &run_body("mvm-peer", None)).await;
        assert_eq!(st, 403, "{h}: {b}");
        assert!(b.contains("\"forbidden_peer\"") && b.contains(want), "{h}: {b}");
    }
    assert_eq!(hook(s.hooks, "ready", b"").await.0, 200, "ready is never filtered");
    let d = s.state.detail().await;
    assert!(!d.health.run_hook_seen && d.health.status == HealthStatus::Ok, "nothing ran and nothing drains: {:?}", d.health);
    assert_eq!(d.refused_peers.get(&s.hooks.port().to_string()), Some(&4), "{:?}", d.refused_peers);
    for h in ["run", "resume", "suspend", "terminate"] {
        let seen = &d.hook_refusals[h];
        assert_eq!(seen.decision, "refused", "{h}: {seen:?}");
        assert!(seen.peer.starts_with("127.0.0.1:"), "{seen:?}");
        assert_eq!(seen.uid.is_some(), cfg!(target_os = "linux"), "{seen:?}");
    }
    assert!(d.hook_peers.is_empty(), "a refusal never stands as the platform's record: {:?}", d.hook_peers);
    assert!(!d.hook_refusals.contains_key("ready"), "only runtime hooks are recorded");
}

/// The orphan rule on a live kernel (Linux): a client that sent a runtime
/// hook's head and part of its body, then closed — all before the shim read
/// a byte (blocking calls on this test's one runtime thread hold the server)
/// — owns no socket file any more: its row shows inode 0 (and uid 0 on some
/// kernels), and it is refused `orphaned` although its uid is not the
/// agent's. hyper dispatches on the head, so the guard sees it; a whole
/// request then close is dropped at EOF, unseen, and cannot test the rule.
#[tokio::test]
async fn hooks_peer_mode_refuses_a_client_gone_before_the_lookup() {
    if !cfg!(target_os = "linux") {
        eprintln!("no /proc/net/tcp off Linux");
        return;
    }
    // This test's uid is not the agent's: its live sockets are admitted.
    let s = stack(ShimOpts { uid: uid_gid().0.wrapping_add(1), ..opts(None, HookSource::Peer, 0) }).await;
    {
        let mut c = std::net::TcpStream::connect(s.hooks).unwrap();
        c.write_all(format!("POST {PREFIX}/resume HTTP/1.1\r\nHost: {}\r\nContent-Length: 100\r\n\r\n{{}}", s.hooks).as_bytes()).unwrap();
    }
    let until = Instant::now() + Duration::from_secs(5);
    let seen = loop {
        if let Some(seen) = s.state.hook_refusals.lock().unwrap().get("resume").cloned() {
            break seen;
        }
        assert!(Instant::now() < until, "the half-sent /resume never reached the guard");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!((seen.decision.as_str(), seen.inode), ("refused", Some(0)), "{seen:?}");
    assert_eq!(s.state.detail().await.refused_peers.get(&s.hooks.port().to_string()), Some(&1));
    assert!(s.state.hook_peers.lock().unwrap().get("resume").is_none(), "the refusal is kept apart");
    assert_eq!(hook(s.hooks, "resume", b"{}").await.0, 200, "the same uid with its socket open");
    assert_eq!(s.state.hook_peers.lock().unwrap()["resume"].decision, "admitted");
    assert_eq!(s.state.hook_refusals.lock().unwrap()["resume"].inode, Some(0), "and stays");
}

/// `log` records each runtime hook's last peer as `logged`; `/run` and
/// `/resume` leave their clock report for `/health/detail`.
#[tokio::test]
async fn hooks_record_the_last_peer_and_the_clock() {
    let s = Stack::log().await;
    s.run(true).await;
    assert_eq!(s.state.detail().await.clock.as_ref().and_then(|c| c["hook"].as_str()), Some("run"));
    assert_eq!(hook(s.hooks, "resume", b"{}").await.0, 200);
    let (d, _) = s.detail().await;
    assert_eq!(d.clock.as_ref().and_then(|c| c["hook"].as_str()), Some("resume"));
    for h in ["run", "resume"] {
        assert_eq!(d.hook_peers[h].decision, "logged", "{h}: {:?}", d.hook_peers[h]);
        assert!(d.hook_peers[h].peer.starts_with("127.0.0.1:"), "{:?}", d.hook_peers[h]);
    }
    assert!(d.refused_peers.is_empty());
}

/// `/suspend` tells every socket past hello, closes it 1001, then answers;
/// the next socket is served.
#[tokio::test]
async fn suspend_sends_hook_suspend_then_closes_every_socket() {
    let s = Stack::log().await;
    s.run(true).await;
    let mut w = ws_hello_ok(s.app).await;
    let started = Instant::now();
    let (answer, (ev, end)) = tokio::join!(hook(s.hooks, "suspend", b"{}"), async { (next_frame(&mut w).await, next_frame(&mut w).await) });
    assert_eq!(answer.0, 200, "{}", answer.1);
    assert!(matches!(ev, Ok(Frame::Event { kind: EventKind::HookSuspend, .. })), "{ev:?}");
    assert_eq!(end, Err(Some(CLOSE_GOING_AWAY)));
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    s.wait_no_sockets().await;
    let mut again = ws_hello_ok(s.app).await;
    ping(&mut again, 4).await;
}

/// `/terminate` drains: every socket gets `event hook_terminate` and 1001,
/// and a new upgrade gets 503 `draining`.
#[tokio::test]
async fn terminate_closes_the_sockets_and_refuses_new_ones() {
    let s = Stack::log().await;
    s.run(true).await;
    let mut w = ws_hello_ok(s.app).await;
    let (answer, (ev, end)) = tokio::join!(hook(s.hooks, "terminate", b"{}"), async { (next_frame(&mut w).await, next_frame(&mut w).await) });
    assert_eq!(answer.0, 200, "{}", answer.1);
    assert!(matches!(ev, Ok(Frame::Event { kind: EventKind::HookTerminate, .. })), "{ev:?}");
    assert_eq!(end, Err(Some(CLOSE_GOING_AWAY)));
    let (st, _, body) = raw(s.app, &upgrade_head(s.app, "GET", "HTTP/1.1", &[], &[])).await;
    assert_eq!(st, 503, "{body}");
    assert!(body.contains("\"draining\""), "{body}");
}

/// `/terminate` stops the spawns with the plan's ladder before it answers:
/// TERM every group, at most 5 s for the leaders, then KILL only the
/// groups whose leader still runs. A leader that traps TERM and needs 4 s
/// exits on its own (0); one that ignores TERM is KILLed at 5 s.
#[tokio::test]
async fn terminate_gives_the_leaders_5_s_then_kills_the_rest() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let (slow, deaf) = (SpawnId::new_v7(), SpawnId::new_v7());
    start(&mut w, &slow, &["/bin/sh", "-c", "trap 'sleep 4; exit 0' TERM; echo ready; while :; do sleep 0.1; done"], None).await;
    let (_, early) = start(&mut w, &deaf, &["/bin/sh", "-c", "trap '' TERM; echo ready; while :; do sleep 0.1; done"], None).await;
    // Both traps are set before the TERM (`slow`'s ready may come before `deaf`'s spawned).
    let mut ready: std::collections::BTreeSet<SpawnId> = early.iter().filter(|f| f.kind() == "stdout").filter_map(Frame::spawn_id).cloned().collect();
    while ready.len() < 2 {
        match next_frame(&mut w).await {
            Ok(Frame::Stdout { spawn_id, .. }) => _ = ready.insert(spawn_id),
            Ok(_) => {}
            Err(e) => panic!("the socket ended ({e:?}) before both traps were set"),
        }
    }
    let t = Instant::now();
    let (st, b) = hook(s.hooks, "terminate", b"{}").await;
    let took = t.elapsed();
    assert_eq!(st, 200, "{b}");
    assert!(took >= Duration::from_millis(4900) && took < Duration::from_secs(8), "{took:?}");
    let exits: BTreeMap<SpawnId, Option<ExitInfo>> = s.state.spawns.status(None).into_iter().map(|x| (x.spawn_id, x.exit)).collect();
    assert_eq!(exits.get(&slow), Some(&Some(ExitInfo { code: Some(0), signal: None })), "the trap ran to its end: {exits:?}");
    assert_eq!(exits.get(&deaf), Some(&Some(ExitInfo { code: None, signal: Some(9) })), "KILLed once the 5 s were out: {exits:?}");
}

/// A `spawn` is answered by the spawn manager: `spawned`, naming the spawn
/// and its pid, before anything else (spawning works natively: see `start`).
#[tokio::test]
async fn agent_spawn_is_answered_by_the_spawn_manager() {
    let home = tempfile::tempdir().unwrap();
    let s = stack(ShimOpts { home: std::fs::canonicalize(home.path()).unwrap(), ..opts(None, HookSource::Log, 0) }).await;
    s.run(true).await;
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    let spawn = Frame::Spawn { spawn_id: id.clone(), argv: vec!["/bin/echo".into(), "hi".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: None, credential: None };
    send_frame(&mut w, &spawn).await;
    match next_frame(&mut w).await {
        Ok(Frame::Spawned { spawn_id, pid, .. }) => assert!(spawn_id == id && pid != 0, "{spawn_id} {pid}"),
        other => panic!("spawned for the spawn, got {other:?}"),
    }
    send_frame(&mut w, &Frame::Detach { spawn_id: id, is_final: true }).await;
    w.close(None).await.unwrap();
}

/// A stack whose spawns run in a fresh home (canonical: no symlink in the path).
async fn spawning_stack() -> (Stack, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let s = stack(ShimOpts { home: std::fs::canonicalize(home.path()).unwrap(), ..opts(None, HookSource::Log, 0) }).await;
    s.run(true).await;
    (s, home)
}

/// Start `argv` on `w`: its pid, and the frames of the socket's other spawns
/// read before its `spawned` (only a spawn's own frames wait for its answer:
/// another's output may come first). Spawning works natively wherever these
/// tests run (the agent is this process's own uid, the home a canonical
/// tempdir), so anything else before its `spawned` fails the test.
async fn start(w: &mut Ws, id: &SpawnId, argv: &[&str], detach_grace_s: Option<u32>) -> (u32, Vec<Frame>) {
    let spawn = Frame::Spawn { spawn_id: id.clone(), argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s, credential: None };
    start_frame(w, &spawn).await
}

/// [`start`] for a `spawn` frame the caller built.
async fn start_frame(w: &mut Ws, spawn: &Frame) -> (u32, Vec<Frame>) {
    let id = spawn.spawn_id().expect("a spawn frame").clone();
    send_frame(w, spawn).await;
    let mut others = Vec::new();
    loop {
        match next_frame(w).await {
            Ok(Frame::Spawned { spawn_id, pid, .. }) if spawn_id == id && pid != 0 => return (pid, others),
            Ok(f) if f.spawn_id().is_some_and(|s| *s != id) => others.push(f),
            other => panic!("spawned for {id}, got {other:?}"),
        }
    }
}

/// `cat` round-trips raw bytes through the socket: stdin frames in, stdout
/// frames and `exit` out through the writer's outbox, byte-exact (non-UTF-8
/// and an unterminated last line included); acking the exit's seq releases
/// the spawn and the socket stays up.
#[tokio::test]
async fn agent_cat_round_trips_raw_bytes() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/cat"], None).await;
    let input = b"hello\n\x00\xff\n\xe2\x82\xac done".to_vec();
    let mut chunker = ai_env_cli::wire::chunk::Chunker::new();
    let mut chunks = chunker.push(&input);
    chunks.extend(chunker.finish());
    let last = chunks.len() as u64;
    for (seq, data) in (1..).zip(chunks) {
        send_frame(&mut w, &Frame::Stdin { spawn_id: id.clone(), seq, data }).await;
    }
    send_frame(&mut w, &Frame::StdinEof { spawn_id: id.clone(), seq: last }).await;
    let mut out = Vec::new();
    let (exit_seq, code) = loop {
        match next_frame(&mut w).await {
            Ok(Frame::Stdout { spawn_id, data, .. }) if spawn_id == id => out.extend(ai_env_cli::wire::chunk::decode(&data).unwrap()),
            Ok(Frame::Exit { spawn_id, seq, code, .. }) if spawn_id == id => break (seq, code),
            Ok(Frame::StdinAck { spawn_id, .. } | Frame::Stderr { spawn_id, .. }) if spawn_id == id => {}
            other => panic!("cat's frames, got {other:?}"),
        }
    };
    assert_eq!(out, input, "byte-exact");
    assert_eq!(code, Some(0));
    send_frame(&mut w, &Frame::Ack { spawn_id: id, seq: exit_seq, err_seq: 0 }).await;
    ping(&mut w, 6).await;
}

/// A socket that ends without `detach` hands its spawns to the detach
/// grace (`connection_lost`): `/health/detail` shows the grace running.
#[tokio::test]
async fn a_lost_socket_starts_the_detach_grace() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/sleep", "30"], Some(60)).await;
    let (d, _) = s.detail().await;
    assert_eq!(d.spawns.iter().find(|sp| sp.status.spawn_id == id).map(|sp| sp.detach_left_s), Some(None), "attached: no grace yet");
    drop(w);
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let (d, _) = s.detail().await;
        let left = d.spawns.iter().find(|sp| sp.status.spawn_id == id).and_then(|sp| sp.detach_left_s);
        if let Some(left) = left {
            assert!(left <= 60, "{left}");
            break;
        }
        assert!(Instant::now() < until, "no detach grace after the socket was lost: {:?}", d.spawns);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    s.state.spawns.shutdown("test").await;
}

/// The newest attachment wins: a second socket's hello resuming a spawn
/// supersedes the first (`error superseded` there; `resumed ok` and the spawn
/// listed as attached to no other socket here), and the first socket's later
/// end detaches nothing.
#[tokio::test]
async fn a_resuming_hello_supersedes_and_the_old_socket_end_detaches_nothing() {
    let (s, _home) = spawning_stack().await;
    let mut a = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    start(&mut a, &id, &["/bin/sleep", "30"], Some(60)).await;
    let mut b = ws(s.app).await;
    send_frame(&mut b, &hello_resuming(TOKEN, vec![ResumePoint { spawn_id: id.clone(), from_seq: None, err_from_seq: None }])).await;
    match next_frame(&mut b).await {
        Ok(Frame::HelloOk { resumed, spawns, .. }) => {
            assert_eq!(resumed, vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }]);
            let st = spawns.iter().find(|x| x.spawn_id == id).unwrap_or_else(|| panic!("{id} listed: {spawns:?}"));
            assert!(st.alive && !st.attached, "attached to this socket, not another: {st:?}");
        }
        other => panic!("hello_ok, got {other:?}"),
    }
    loop {
        match next_frame(&mut a).await {
            Ok(Frame::Error { code: ErrorCode::Superseded, spawn_id: Some(sid), .. }) if sid == id => break,
            Ok(_) => {}
            Err(e) => panic!("the old socket ended before hearing it was superseded: {e:?}"),
        }
    }
    drop(a);
    s.wait_sockets((1, 1)).await;
    let (d, _) = s.detail().await;
    assert_eq!(d.spawns.iter().find(|x| x.status.spawn_id == id).map(|x| x.detach_left_s), Some(None), "still attached to the new socket: {:?}", d.spawns);
    send_frame(&mut b, &Frame::Detach { spawn_id: id, is_final: true }).await;
    ping(&mut b, 9).await;
    s.state.spawns.shutdown("test").await;
}

/// V6 runs only under `--hook-source peer` (V1–V5 pass on a clean tree), and
/// natively — not root — fails closed: the guard cannot be self-tested
/// without dropping to the agent uid.
#[tokio::test]
async fn validate_v6_fails_closed_natively_under_peer_mode() {
    if uid_gid().0 == 0 {
        eprintln!("as root V6 runs its curl self-test: covered in Docker");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    plant_vm_tree(t.path());
    let addr = serve_hooks(state_with(fake_claude(t.path(), ""), opts(Some(t.path()), HookSource::Peer, 0)).await).await;
    let (st, b) = hook(addr, "validate", b"").await;
    assert_eq!(st, 503, "{b}");
    assert!(b.contains("V6: ") && b.contains("needs root"), "{b}");
    for v in ["V1:", "V2:", "V3:", "V4:"] {
        assert!(!b.contains(v), "only V6 fails on a clean tree: {b}");
    }
}

// ---- the credential cache (S7) --------------------------------------------------

/// The name the Mac delivers the setup-token under.
const CRED: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// A stand-in credential built at run time with a per-test tail: no token
/// shape, nothing real, and unique enough for a leak scan to look for.
fn dummy_value(test: &str) -> String {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    format!("dummy-credential-{test}-{}-{nanos}", std::process::id())
}

fn credential(value: &str, tag: Option<&str>) -> Frame {
    Frame::Credential { name: CRED.into(), secret: Secret::new(value.to_string()), tag: tag.map(str::to_string) }
}

/// Deliver `value` on `w`: answered `credential_ok`, cached, with the tag.
async fn deliver(w: &mut Ws, value: &str, tag: Option<&str>) {
    send_frame(w, &credential(value, tag)).await;
    match next_frame(w).await {
        Ok(Frame::CredentialOk { name, cached: true, tag: t }) => assert_eq!((name.as_str(), t.as_deref()), (CRED, tag)),
        other => panic!("credential_ok, got {other:?}"),
    }
}

/// A new socket past hello, and what its `hello_ok` says of the cache:
/// `has_credentials`, the caps and the view.
async fn hello_view(app: SocketAddr) -> (Ws, bool, Vec<String>, CredentialView) {
    let mut w = ws(app).await;
    send_frame(&mut w, &hello(TOKEN)).await;
    match next_frame(&mut w).await {
        Ok(Frame::HelloOk { has_credentials, caps, credential, .. }) => (w, has_credentials, caps, credential),
        other => panic!("hello_ok, got {other:?}"),
    }
}

/// A `spawn` of `argv` naming `credential` and carrying `secrets` (fd delivery).
fn spawn_with(id: &SpawnId, argv: &[&str], credential: Option<&str>, secrets: BTreeMap<String, Secret<String>>) -> Frame {
    Frame::Spawn { spawn_id: id.clone(), argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: BTreeMap::new(), secrets, deliver_secret: Deliver::Fd, detach_grace_s: None, credential: credential.map(str::to_string) }
}

/// The spawn's answer when it is refused: its code and message.
async fn spawn_refused(w: &mut Ws, spawn: &Frame) -> (SpawnErrCode, String) {
    send_frame(w, spawn).await;
    match next_frame(w).await {
        Ok(Frame::SpawnErr { spawn_id, code, message }) if Some(&spawn_id) == spawn.spawn_id() => (code, message),
        other => panic!("spawn_err, got {other:?}"),
    }
}

/// `id`'s stdout up to its exit, and the exit code; the exit is acked.
async fn run_to_exit(w: &mut Ws, id: &SpawnId) -> (Vec<u8>, Option<i32>) {
    let mut out = Vec::new();
    let (seq, code) = loop {
        match next_frame(w).await {
            Ok(Frame::Stdout { spawn_id, data, .. }) if spawn_id == *id => out.extend(ai_env_cli::wire::chunk::decode(&data).unwrap()),
            Ok(Frame::Exit { spawn_id, seq, code, .. }) if spawn_id == *id => break (seq, code),
            Ok(f) if f.spawn_id().is_some() => {}
            other => panic!("{id}'s frames, got {other:?}"),
        }
    };
    send_frame(w, &Frame::Ack { spawn_id: id.clone(), seq, err_seq: 0 }).await;
    (out, code)
}

/// `hello_ok` and `/health` advertise the cache; a delivered credential is
/// cached and shown by name, tag and time — never its value — on a new
/// socket's `hello_ok` and on `/health/detail`; a second delivery replaces
/// it; `credential_forget` drops it.
#[tokio::test]
async fn a_delivered_credential_is_cached_and_shown_by_name_only() {
    let s = Stack::log().await;
    s.run(true).await;
    let (mut w, has, caps, view) = hello_view(s.app).await;
    assert!(!has && view == CredentialView::default(), "nothing cached yet: {view:?}");
    assert_eq!(caps, [CAP_CREDENTIAL_CACHE]);
    let (st, _, body) = http(s.app, "GET", "/health", b"", None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(serde_json::from_str::<Health>(&body).unwrap().caps, [CAP_CREDENTIAL_CACHE], "{body}");
    let value = dummy_value("cached");
    deliver(&mut w, &value, Some("seal-1")).await;
    let (_second, has, _, view) = hello_view(s.app).await;
    assert!(has, "a new socket sees the cached copy");
    assert_eq!((view.credential_name.as_deref(), view.credential_tag.as_deref(), view.credential_holders), (Some(CRED), Some("seal-1"), 0));
    assert!(view.credential_at.is_some(), "{view:?}");
    let (d, body) = s.detail().await;
    assert!(d.has_credentials && d.credential.credential_name.as_deref() == Some(CRED) && d.credential.credential_tag.as_deref() == Some("seal-1"), "{:?}", d.credential);
    assert!(!body.contains(&value), "/health/detail ({} bytes) holds the value", body.len());
    let newer = dummy_value("newer");
    deliver(&mut w, &newer, None).await;
    assert_eq!(s.state.spawns.credential().copy(CRED).map(|v| v.expose().len()), Some(newer.len()), "the second delivery replaced the first");
    assert_eq!(s.detail().await.0.credential.credential_tag, None);
    send_frame(&mut w, &Frame::CredentialForget { name: None }).await;
    assert_eq!(next_frame(&mut w).await, Ok(Frame::CredentialOk { name: CRED.into(), cached: false, tag: None }));
    let (_third, has, _, view) = hello_view(s.app).await;
    assert!(!has && view == CredentialView::default(), "{view:?}");
}

/// A spawn naming the cached credential reads it on fd 3, byte-exact, with
/// `<NAME>_FILE_DESCRIPTOR=3`, nothing under the name in its environment and
/// the value under no other name either (fd-delivery's scan, and the
/// runbook's reading of it, rest on that); named before any delivery it is
/// `no_credential`; named together with an inline secret, `bad_request`.
/// The cache keeps its copy for the next spawn.
#[tokio::test]
async fn a_spawn_naming_the_credential_reads_it_on_fd_3() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    // `$(…)` drops trailing newlines: an `x` after fd 3's bytes, cut off
    // again, keeps them, so the value printed back is byte-exact (a stray
    // newline would also make the scan's `grep -F` count every line).
    let script = ["/bin/sh", "-c", "echo \"$CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR\"; env | grep -c '^CLAUDE_CODE_OAUTH_TOKEN='; v=$(cat <&3; printf x); v=${v%x}; env | grep -c -F -- \"$v\"; printf %s \"$v\""];
    let (code, message) = spawn_refused(&mut w, &spawn_with(&SpawnId::new_v7(), &script, Some(CRED), BTreeMap::new())).await;
    assert!(code == SpawnErrCode::NoCredential && message.contains(CRED), "{code:?}: {message}");
    let value = dummy_value("fd3");
    deliver(&mut w, &value, None).await;
    let inline = BTreeMap::from([("OTHER".to_string(), Secret::new(dummy_value("inline")))]);
    let (code, message) = spawn_refused(&mut w, &spawn_with(&SpawnId::new_v7(), &script, Some(CRED), inline)).await;
    assert_eq!(code, SpawnErrCode::BadRequest, "{message}");
    for round in 0..2 {
        let id = SpawnId::new_v7();
        start_frame(&mut w, &spawn_with(&id, &script, Some(CRED), BTreeMap::new())).await;
        let (out, code) = run_to_exit(&mut w, &id).await;
        assert_eq!(code, Some(0), "round {round}");
        assert!(out == format!("3\n0\n0\n{value}").into_bytes(), "round {round}: stdout of {} bytes, want the fd number, two zero counts and the {} value bytes", out.len(), value.len());
    }
    assert!(s.state.spawns.credential().has(), "the cache keeps its copy");
}

/// D3: `/suspend` drops the cached copy before it answers and refuses a
/// delivery until `/resume` (`credential_err suspended`); a spawn naming the
/// credential meanwhile is `no_credential`; `/resume` reopens the cache and
/// drops anything there (a suspend whose hook never ran).
#[tokio::test]
async fn suspend_drops_the_credential_before_answering_and_resume_reopens_empty() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let value = dummy_value("suspend");
    deliver(&mut w, &value, Some("seal-2")).await;
    let (st, b) = hook(s.hooks, "suspend", b"{}").await;
    assert_eq!(st, 200, "{b}");
    assert!(!s.state.spawns.credential().has(), "gone by the time /suspend answered");
    let (mut w, has, _, view) = hello_view(s.app).await;
    assert!(!has && view.credential_name.is_none(), "{view:?}");
    send_frame(&mut w, &credential(&value, None)).await;
    match next_frame(&mut w).await {
        Ok(Frame::CredentialErr { name, code: CredentialErrCode::Suspended, message }) => assert!(name == CRED && !message.contains(&value), "{message}"),
        other => panic!("credential_err suspended, got {other:?}"),
    }
    let (code, _) = spawn_refused(&mut w, &spawn_with(&SpawnId::new_v7(), &["/bin/echo", "hi"], Some(CRED), BTreeMap::new())).await;
    assert_eq!(code, SpawnErrCode::NoCredential);
    assert!(!s.state.spawns.credential().has(), "the refused delivery cached nothing");
    assert_eq!(hook(s.hooks, "resume", b"{}").await.0, 200);
    deliver(&mut w, &value, None).await;
    assert_eq!(hook(s.hooks, "resume", b"{}").await.0, 200, "a resume with no suspend before it");
    assert!(!s.state.spawns.credential().has(), "a resume never keeps a copy");
    ping(&mut w, 12).await;
}

/// `credential_holders` counts the live spawns handed a secret, from the
/// cache or inline, on `/health/detail` and a new `hello_ok`; an exit takes
/// its spawn off once its process group is gone (a group outliving its
/// leader still counts, and a zombie leader may pin it until it is reaped);
/// a spawn without a secret never counts.
#[tokio::test]
async fn holders_count_the_live_spawns_handed_a_secret() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    deliver(&mut w, &dummy_value("holders"), None).await;
    let cached = SpawnId::new_v7();
    start_frame(&mut w, &spawn_with(&cached, &["/bin/cat"], Some(CRED), BTreeMap::new())).await;
    let inline = SpawnId::new_v7();
    start_frame(&mut w, &spawn_with(&inline, &["/bin/cat"], None, BTreeMap::from([("X".to_string(), Secret::new(dummy_value("inline")))]))).await;
    start(&mut w, &SpawnId::new_v7(), &["/bin/cat"], None).await;
    assert_eq!(s.detail().await.0.credential.credential_holders, 2);
    let (_other, _, _, view) = hello_view(s.app).await;
    assert_eq!(view.credential_holders, 2);
    send_frame(&mut w, &Frame::StdinEof { spawn_id: cached.clone(), seq: 0 }).await;
    assert_eq!(run_to_exit(&mut w, &cached).await.1, Some(0));
    let t = Instant::now();
    let mut holders = s.detail().await.0.credential.credential_holders;
    while holders != 1 && t.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        holders = s.detail().await.0.credential.credential_holders;
    }
    assert_eq!(holders, 1, "the exited spawn's group is gone within 5 s");
    s.state.spawns.shutdown("test").await;
}

/// A malformed delivery is `credential_err bad_request` naming the field,
/// never the value, and the socket stays up; a `credential_ok` or
/// `credential_err` from the Mac is a protocol violation.
#[tokio::test]
async fn a_bad_delivery_is_refused_and_only_the_vm_answers_credentials() {
    let s = Stack::log().await;
    s.run(true).await;
    let mut w = ws_hello_ok(s.app).await;
    let value = dummy_value("bad");
    for (frame, says) in [
        (Frame::Credential { name: "1BAD".into(), secret: Secret::new(value.clone()), tag: None }, "environment name"),
        (credential(&value, Some("not a tag")), "tag"),
        (credential(&format!("{value}\0"), None), "NUL"),
    ] {
        send_frame(&mut w, &frame).await;
        match next_frame(&mut w).await {
            Ok(Frame::CredentialErr { code: CredentialErrCode::BadRequest, message, .. }) => assert!(message.contains(says) && !message.contains(&value), "{message}"),
            other => panic!("credential_err bad_request, got {other:?}"),
        }
    }
    ping(&mut w, 13).await;
    assert!(!s.state.spawns.credential().has());
    send_frame(&mut w, &Frame::CredentialOk { name: CRED.into(), cached: true, tag: None }).await;
    assert!(matches!(next_frame(&mut w).await, Ok(Frame::Error { code: ErrorCode::BadFrame, .. })));
    assert_eq!(next_frame(&mut w).await, Err(Some(CLOSE_PROTOCOL)));
}

/// `/terminate` drops the cached copy before it answers (`/health/detail`
/// shows none) and closes the cache for good: after a late `/suspend` and
/// `/resume`, which never reopen a stopping shim's cache, a copy is still
/// refused as `draining`. (No socket can carry one any more: the cache's own
/// refusal is the backstop, so it is checked on the cache.) The shutdown on
/// a stop signal starts with the same `hooks::begin_stop`, so this checks its
/// refusal too; `binary_stops_drop_the_cached_credential_first` shows it
/// runs it.
#[tokio::test]
async fn terminate_drops_the_credential_before_answering_and_closes_for_good() {
    let s = Stack::log().await;
    s.run(true).await;
    let mut w = ws_hello_ok(s.app).await;
    let value = dummy_value("terminate");
    deliver(&mut w, &value, Some("seal-4")).await;
    let (answer, ()) = tokio::join!(hook(s.hooks, "terminate", b"{}"), async { while next_frame(&mut w).await.is_ok() {} });
    assert_eq!(answer.0, 200, "{}", answer.1);
    assert!(!s.state.spawns.credential().has(), "gone by the time /terminate answered");
    let (d, body) = s.detail().await;
    assert!(!d.has_credentials && d.credential.credential_name.is_none(), "{:?}", d.credential);
    assert!(!body.contains(&value), "/health/detail ({} bytes) holds the value", body.len());
    for h in ["suspend", "resume"] {
        assert_eq!(hook(s.hooks, h, b"{}").await.0, 200, "{h}");
        let (code, message) = s.state.spawns.credential().put(CRED, Secret::new(value.clone()), None).unwrap_err();
        assert_eq!(code, CredentialErrCode::Draining, "after /{h}");
        assert!(!message.contains(&value), "after /{h}: the refusal ({} bytes) holds the value", message.len());
    }
    assert!(!s.state.spawns.credential().has(), "nothing was cached once stopping");
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
    for flag in ["--app-port", "--hooks-port", "--code-port", "--claude", "--home", "--uid", "--gid", "--delay-run", "--hook-source", "--agent-guard", "--clock"] {
        assert!(text.contains(flag), "{flag} missing from:\n{text}");
    }
    assert!(!text.contains("--echo"), "--echo is gone (S6: plain argv spawns cover it):\n{text}");
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
    for hidden in ["--fs-root", "--init-pid", "--supervise", "--kill-after-s", "--agent-window-bytes"] {
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
/// the line: a changed default would run claude as 1000:<other>). The hooks
/// guard is always `peer`; the agent guard is its default (on as root on
/// Linux) or tree B's fallback `--agent-guard log` (plan S6: the endpoint
/// reaches 8080 as a local peer), never `off`.
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
    assert_eq!((a.hook_source, a.clock), (HookSource::Peer, ClockMode::Measure), "S6: the peer guard on the hooks; the clock is measured (D7)");
    assert!(matches!(a.agent_guard, None | Some(AgentGuard::On | AgentGuard::Log)), "the image never runs --agent-guard off: {:?}", a.agent_guard);
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
    http_sync_body(addr, method, path, b"")
}

/// [`http_sync`] with a request body (no Content-Type: the hooks take any).
fn http_sync_body(addr: SocketAddr, method: &str, path: &str, body: &[u8]) -> (u16, String) {
    let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).unwrap();
    s.write_all(body).unwrap();
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
    assert_eq!(http_sync(code, "GET", "/").0, 401, "the code port needs the session bearer");
    let (s, _) = http_sync(hooks_addr, "POST", &format!("{PREFIX}/suspend"));
    assert_eq!(s, 200);
    let line = shim.wait_line(5, |l| l.starts_with("ai-env: hook suspend peer=127.0.0.1:") && l.contains("origin=loopback") && l.contains("status=200"));
    // S6: the row's facts and the decision ride every hook line, after the S3/S4 fields.
    let fields: Vec<&str> = line.split_whitespace().skip(3).filter_map(|w| w.split_once('=').map(|(k, _)| k)).collect();
    assert_eq!(fields, ["peer", "local", "origin", "len", "status", "ms", "peer_uid", "ino", "st", "fam", "decision"], "{line}");
    shim.wait_line(5, |l| l.starts_with("ai-env: boot {\"pid\":"));
}

/// Plan S4 D19: one `ai-env: run-report <json>` line after the first `/run`
/// that answers 200 — none for its byte-identical replay or for a 409 —
/// and one at `/terminate`, each a whole JSON document on one line carrying
/// the accepted `/run`'s microvm id. On Linux the body is the report; here
/// (the Mac) it is the portable twin, so only the portable fields are
/// asserted everywhere.
#[test]
fn run_report_logged_once_after_run_and_at_terminate() {
    let t = tempfile::tempdir().unwrap();
    let shim = Shim::start(&fake_claude(t.path(), ""), &[]);
    let hooks_addr = shim.addr("hooks");
    let id = "microvm-00000000-0000-4000-8000-000000000042";
    let payload = payload_json("mike@mbp");
    let body = run_body(id, Some(&payload));
    let run = format!("{PREFIX}/run");
    assert_eq!(http_sync_body(hooks_addr, "POST", &run, &body).0, 200);
    let (s, b) = http_sync_body(hooks_addr, "POST", &run, &body);
    assert!(s == 200 && b.contains("\"replay\":true"), "{s}: {b}");
    let (s, b) = http_sync_body(hooks_addr, "POST", &run, &run_body("microvm-00000000-0000-4000-8000-000000000043", None));
    assert_eq!(s, 409, "{b}");
    // The /run report is written off the hook's path: wait for it.
    shim.wait_line(10, |l| l.starts_with("ai-env: run-report ") && l.contains("\"hook\":\"run\""));
    assert_eq!(http_sync_body(hooks_addr, "POST", &format!("{PREFIX}/terminate"), b"{}").0, 200);
    shim.wait_line(10, |l| l.starts_with("ai-env: hook terminate ") && l.contains("status=200"));
    // A report a replay or a refusal had (wrongly) spawned would be in by now.
    std::thread::sleep(Duration::from_millis(300));
    let lines = shim.lines.lock().unwrap().clone();
    let hook_lines = |status: &str| lines.iter().filter(|l| l.starts_with("ai-env: hook run ") && l.contains(&format!(" status={status} "))).count();
    assert_eq!((hook_lines("200"), hook_lines("409")), (2, 1), "the first /run, its replay, the conflict: {lines:?}");
    let reports: Vec<serde_json::Value> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("ai-env: run-report "))
        .map(|j| serde_json::from_str(j).unwrap_or_else(|e| panic!("a run report is one JSON document ({e}): {j}")))
        .collect();
    let hooks: Vec<&str> = reports.iter().map(|r| r["hook"].as_str().unwrap_or("?")).collect();
    assert_eq!(hooks, ["run", "terminate"], "exactly one per hook, in order: {lines:?}");
    let commit = RunHookPayload::from_json(&payload).unwrap().commit;
    // The shim runs as this uid, so it may read PID 1's environ exactly when the test may.
    let environ_readable = std::fs::read("/proc/1/environ").is_ok();
    for r in &reports {
        assert_eq!(r["microvm_id"], id, "the accepted /run's id: {r}");
        assert!(!r.to_string().contains(&commit), "no payload material: {r}");
        if cfg!(target_os = "linux") {
            // Values, not key presence: the report emits every key, null when unread.
            assert!(r["boot_id"].as_str().is_some_and(|b| b.len() == 36 && b.matches('-').count() == 4), "a uuid boot_id: {r}");
            let (total, used) = (r["disk_total_bytes"].as_u64(), r["disk_used_bytes"].as_u64());
            assert!(total.is_some_and(|t| t > 0) && used.is_some_and(|u| Some(u) <= total), "statvfs(/): {r}");
            assert!(r["zombies"].is_u64(), "/proc is listable: {r}");
            assert_eq!((r["env"].is_object(), r["aws_credential_env"].is_array()), (environ_readable, environ_readable), "PID 1's environ exactly when readable: {r}");
            assert_eq!((r["uid"].as_u64(), r["gid"].as_u64()), (Some(u64::from(uid_gid().0)), Some(u64::from(uid_gid().1))), "{r}");
            assert!(r.get("unsupported").is_none(), "{r}");
        } else {
            assert_eq!(r["unsupported"], true, "the portable twin: {r}");
        }
    }
    if cfg!(target_os = "linux") {
        assert_eq!(reports[0]["boot_id"], reports[1]["boot_id"], "one boot: {reports:?}");
    }
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

/// `--agent-guard log`: one `ai-env: guard` line per request on the app and
/// code ports, with the row's facts and the decision; nothing is refused.
#[test]
fn binary_agent_guard_log_logs_every_side_port_request() {
    let t = tempfile::tempdir().unwrap();
    let shim = Shim::start(&fake_claude(t.path(), ""), &["--agent-guard", "log"]);
    let (app, code) = (shim.addr("app"), shim.addr("code"));
    shim.wait_line(5, |l| l.ends_with(" hook-source log agent-guard log"));
    assert_eq!(http_sync(app, "GET", "/health").0, 200);
    assert_eq!(http_sync(code, "GET", "/").0, 401, "logged, then the bearer");
    for port in [app.port(), code.port()] {
        let line = shim.wait_line(5, |l| l.starts_with(&format!("ai-env: guard port={port} peer=127.0.0.1:")));
        assert!(line.contains(" peer_uid=") && line.contains(" ino=") && line.contains(" st=") && line.contains(" fam="), "{line}");
        assert!(line.contains(" decision=admit") || line.contains(" decision=would-refuse:"), "log never refuses: {line}");
    }
}

/// Off Linux there is no `/proc/net/tcp`: peer mode and `--agent-guard on`
/// are startup errors (fail closed), never silently off.
#[test]
fn guard_modes_fail_closed_off_linux() {
    if cfg!(target_os = "linux") {
        return;
    }
    for flags in [["--hook-source", "peer"], ["--agent-guard", "on"]] {
        let mut args = vec!["shim", "--claude", "/nonexistent/claude", "--app-port", "0", "--hooks-port", "0", "--code-port", "0"];
        args.extend_from_slice(&flags);
        let out = ai_env(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{flags:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stderr).contains("needs Linux"), "{flags:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
}


/// S7 through the real binary: a delivery, a spawn reading fd 3, `/suspend`,
/// `/resume`, `/terminate`. The stderr log names the credential, its byte
/// count and tag, and its drop on suspend; no line ever holds the value.
#[tokio::test]
async fn binary_credential_log_names_it_and_never_holds_the_value() {
    let t = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(home.path()).unwrap();
    let shim = Shim::start(&fake_claude(t.path(), ""), &["--home", home.to_str().unwrap()]);
    let (hooks_addr, app) = (shim.addr("hooks"), shim.addr("app"));
    assert_eq!(hook(hooks_addr, "run", &run_body("mvm-cred", Some(&payload_json("mike@mbp")))).await.0, 200);
    let mut w = ws_hello_ok(app).await;
    let value = dummy_value("binary");
    deliver(&mut w, &value, Some("seal-3")).await;
    let id = SpawnId::new_v7();
    start_frame(&mut w, &spawn_with(&id, &["/bin/sh", "-c", "wc -c <&3"], Some(CRED), BTreeMap::new())).await;
    let (out, code) = run_to_exit(&mut w, &id).await;
    assert_eq!((String::from_utf8_lossy(&out).trim().to_string(), code), (value.len().to_string(), Some(0)), "fd 3's byte count");
    for h in ["suspend", "resume", "terminate"] {
        assert_eq!(hook(hooks_addr, h, b"{}").await.0, 200, "{h}");
    }
    shim.wait_line(10, |l| l.starts_with("ai-env: hook terminate ") && l.contains("status=200"));
    let lines = shim.lines.lock().unwrap().clone();
    let cached = format!("ai-env: credential cached name={CRED} bytes={} tag=seal-3", value.len());
    assert!(lines.contains(&cached), "{cached:?} missing from {} lines", lines.len());
    assert!(lines.contains(&format!("ai-env: credential forgotten name={CRED} (suspend)")), "the drop on /suspend is logged");
    let leaks = lines.iter().filter(|l| l.contains(&value)).count();
    assert_eq!(leaks, 0, "{leaks} stderr line(s) hold the value");
}

/// Both stops drop a cached credential first, through the real binary:
/// `/terminate` logs `credential forgotten … (terminate)` and SIGTERM
/// `… (stop)` (the shared `hooks::begin_stop`, whose refusal the in-process
/// `/terminate` test checks), each before the spawns are stopped (and
/// SIGTERM still exits 0); no stderr line ever holds the value.
#[tokio::test]
async fn binary_stops_drop_the_cached_credential_first() {
    for why in ["terminate", "stop"] {
        let t = tempfile::tempdir().unwrap();
        let mut shim = Shim::start(&fake_claude(t.path(), ""), &[]);
        let (hooks_addr, app) = (shim.addr("hooks"), shim.addr("app"));
        assert_eq!(hook(hooks_addr, "run", &run_body("mvm-stop", Some(&payload_json("mike@mbp")))).await.0, 200);
        let mut w = ws_hello_ok(app).await;
        let value = dummy_value(why);
        deliver(&mut w, &value, Some("seal-5")).await;
        let end = if why == "terminate" {
            let (answer, ()) = tokio::join!(hook(hooks_addr, "terminate", b"{}"), async { while next_frame(&mut w).await.is_ok() {} });
            assert_eq!(answer.0, 200, "{}", answer.1);
            "ai-env: hook terminate "
        } else {
            signal(shim.child.id(), nix::sys::signal::Signal::SIGTERM);
            while next_frame(&mut w).await.is_ok() {}
            assert_eq!(wait_exit(&mut shim.child, 10).code(), Some(0), "SIGTERM is a graceful stop");
            "ai-env: shim stopped"
        };
        shim.wait_line(10, |l| l.starts_with(end));
        let lines = shim.lines.lock().unwrap().clone();
        let forgotten = format!("ai-env: credential forgotten name={CRED} ({why})");
        let (forgot, stopping) = (lines.iter().position(|l| *l == forgotten), lines.iter().position(|l| l.starts_with(&format!("ai-env: spawns stopping ({why}): "))));
        assert!(forgot.is_some() && forgot < stopping, "{why}: the copy is dropped before the spawns are stopped (lines {forgot:?} and {stopping:?} of {})", lines.len());
        let leaks = lines.iter().filter(|l| l.contains(&value)).count();
        assert_eq!(leaks, 0, "{why}: {leaks} stderr line(s) hold the value");
    }
}
