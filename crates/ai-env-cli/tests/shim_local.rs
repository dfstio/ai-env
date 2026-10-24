//! Native shim tests (`--features shim`): the hooks, `/validate`, `/health`,
//! the code placeholder, the two-process init, and (S6) the `/agent`
//! WebSocket, the session bearer and the peer guard, in-process (the routers
//! on 127.0.0.1) and through the real binary. No reqwest here — the shim
//! graph has no HTTP client — so requests are written by hand on a TcpStream
//! and the WebSocket client is tokio-tungstenite over a plain TcpStream. No
//! test runs the real `claude` (a fake answers `--version`), steps the clock
//! or needs root.
// S9: the fake curl (`tests/common/curl.rs`, self-contained: `mod common` needs the bridge) and G5's transfers.
#[path = "common/curl.rs"]
mod curl;
#[path = "shim_local/transcript_s3.rs"]
mod transcript_s3;
// S11 (wave 1): A1's claude cache, C1's code-out manifest, view parent and gzip pull.
#[path = "shim_local/claude_stage.rs"]
mod claude_stage;
#[path = "shim_local/s11.rs"]
mod s11;

use ai_env_cli::shim::health::{router, ProbeSpec, ShimOpts, ShimState};
use ai_env_cli::shim::hooks::{self, HookPeer, HookSource, PREFIX};
use ai_env_cli::shim::peer::{AgentGuard, Peer, DRAIN_MAX};
use ai_env_cli::shim::sys::{ClockMode, SysOps};
use ai_env_cli::wire::frame::{
    ClientInfo, CredentialErrCode, CredentialView, Deliver, ErrorCode, EventKind, ExitInfo, Frame, Health, HealthDetail, HealthStatus, HelloErrCode, ResumePoint, ResumeStatus, Resumed, RunHookPayload, SpawnErrCode, SpawnId,
    CAP_CREDENTIAL_CACHE, CAP_GIT_HTTP_V1, CAP_TRANSCRIPT_S3_V1, CAP_WORKSPACE_V1, CLOSE_GOING_AWAY, CLOSE_HELLO_REFUSED, CLOSE_PROTOCOL, CLOSE_TOO_BIG, MAX_UNAUTHENTICATED, WS_MAX_MESSAGE,
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
    /// S10: a guest of 7852 MiB (the platform's 2048 MiB image minimum,
    /// as S9 measured, is not what the guest sees).
    fn meminfo(&self) -> Option<String> {
        Some(MEMINFO.to_string())
    }
}

/// [`TestSys`]'s `/proc/meminfo` (S10).
const MEMINFO: &str = "MemTotal:        8040964 kB\nMemFree:         7612048 kB\nMemAvailable:    7703512 kB\n";

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
    // S11: the image's empty claude cache (V4).
    let cache = root.join("opt/ai-env/claude");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::set_permissions(&cache, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
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
    let spawn = Frame::Spawn { spawn_id: id.clone(), argv: vec!["/bin/echo".into(), "hi".into()], cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: None, credential: None, claude: Vec::new() };
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
    let spawn = Frame::Spawn { spawn_id: id.clone(), argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s, credential: None, claude: Vec::new() };
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
    Frame::Spawn { spawn_id: id.clone(), argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: BTreeMap::new(), secrets, deliver_secret: Deliver::Fd, detach_grace_s: None, credential: credential.map(str::to_string), claude: Vec::new() }
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
    assert_eq!(caps, bare_caps());
    let (st, _, body) = http(s.app, "GET", "/health", b"", None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(serde_json::from_str::<Health>(&body).unwrap().caps, bare_caps(), "{body}");
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

/// A spawn names the cached credential or carries an inline secret, never
/// both: `bad_request` whatever the cache holds and whatever the names. Not
/// `no_credential` before any delivery; and once the credential is cached,
/// an inline secret under its own name (which the spawn manager's
/// one-secret rule cannot see once the cached copy took its place) is
/// refused, never run with the cached value instead.
#[tokio::test]
async fn a_spawn_naming_the_credential_never_carries_a_secret_too() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let both = || spawn_with(&SpawnId::new_v7(), &["/bin/echo", "hi"], Some(CRED), BTreeMap::from([(CRED.to_string(), Secret::new(dummy_value("both-inline")))]));
    let (code, message) = spawn_refused(&mut w, &both()).await;
    assert_eq!(code, SpawnErrCode::BadRequest, "nothing cached: {message}");
    deliver(&mut w, &dummy_value("both-cached"), None).await;
    let (code, message) = spawn_refused(&mut w, &both()).await;
    assert_eq!(code, SpawnErrCode::BadRequest, "cached: {message}");
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
    for hidden in ["--fs-root", "--init-pid", "--supervise", "--kill-after-s", "--agent-window-bytes", "--helper", "--git", "--curl"] {
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
    // S8: the workspace helper is the shim's own binary and the image's git; S9: and the image's curl; the
    // ENTRYPOINT names none of them.
    assert!(a.helper.is_none() && !argv.iter().any(|w| w == "--helper" || w == "--git" || w == "--curl"), "{argv:?}");
    assert_eq!(a.git, PathBuf::from("/usr/bin/git"));
    assert_eq!(a.curl, PathBuf::from("/usr/bin/curl"));
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

// ---- S8: the workspace data plane through the routes ---------------------------------------
//
// An in-process shim whose helper is this build's `ai-env` (`shim-io`, as the
// image runs it, here as this test's uid), its VM disk `<tmp>/vm` (the
// hidden `--fs-root`), the agent's home `/Users/agent` there, and the real
// git (or tests/fakes/git.sh logging to `<tmp>/git.log`); seeds are built
// from `<tmp>/mac` with the git CLI as the Mac's data plane builds them
// (D2's WIP commits, D7's shallow pack and its manifest line).

use ai_env_cli::wire::workspace::{
    head_line, CodeoutManifest, HelperHead, ObjectFormat, SeedManifest, SeedRecord, SeedReply, SeedState, SettingsCapture, TranscriptStat, WorkspaceView, WsRefusal, SEED_REF, SEED_WIP_REF,
};

const VM_HOME: &str = "/Users/agent";
const WS: &str = "/Users/agent/ws";
const S8_SLUG: &str = "-Users-agent-ws";
const S8_ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

/// The real git: the first in an absolute `PATH` entry, else `/usr/bin/git`.
fn git_real() -> &'static Path {
    static REAL: OnceLock<PathBuf> = OnceLock::new();
    REAL.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .filter(|d| d.is_absolute())
            .map(|d| d.join("git"))
            .chain(std::iter::once(PathBuf::from("/usr/bin/git")))
            .find(|g| std::fs::metadata(g).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
            .expect("a real git")
    })
}

/// `git <args>` in `dir` (no user or system config, one author at one date,
/// `env` on top, `input` on stdin): stdout. A failure panics with stderr.
fn git_with(dir: &Path, args: &[&str], env: &[(&str, &Path)], input: Option<&[u8]>) -> Vec<u8> {
    let mut cmd = Command::new(git_real());
    cmd.args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .env("GIT_AUTHOR_DATE", "2026-10-12T08:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-10-12T08:00:00Z")
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("run git");
    if let Some(bytes) = input {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

fn git(dir: &Path, args: &[&str]) -> String {
    String::from_utf8_lossy(&git_with(dir, args, &[], None)).trim().to_string()
}

/// `git status --porcelain=v1`'s lines, as they are.
fn git_status(dir: &Path) -> Vec<String> {
    String::from_utf8_lossy(&git_with(dir, &["status", "--porcelain=v1", "--untracked-files=all"], &[], None)).lines().map(str::to_string).collect()
}

fn write_file(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

/// tests/fakes/git.sh as `dest` (a hard link of one cached 0755 master: macOS
/// assesses every new executable's first exec) with its knobs file beside it:
/// the real git, and its log.
fn fake_git(dest: &Path, log: &Path) {
    static MASTER: OnceLock<PathBuf> = OnceLock::new();
    let master = MASTER.get_or_init(|| {
        use sha2::Digest;
        use std::os::unix::fs::PermissionsExt;
        let bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/git.sh")).unwrap();
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fake-git");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("git-{}", &digest[..16]));
        if !path.exists() {
            let tmp = dir.join(format!(".git-{}.{}.tmp", &digest[..16], std::process::id()));
            std::fs::write(&tmp, &bytes).unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::rename(&tmp, &path).unwrap();
        }
        path
    });
    std::fs::hard_link(master, dest).unwrap();
    let knobs = format!("export GIT_REAL='{}'\nexport GIT_ARGV_LOG='{}'\n", git_real().display(), log.display());
    std::fs::write(format!("{}.knobs", dest.display()), knobs).unwrap();
}

/// `<root>/slow-git`: the real git, `secs` late when its arguments name
/// `sub`; run once first (macOS assesses a new executable at its first exec).
fn slow_git(root: &Path, sub: &str, secs: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("slow-git");
    std::fs::write(&path, format!("#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = {sub} ]; then sleep {secs}; fi\ndone\nexec '{}' \"$@\"\n", git_real().display())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Command::new(&path).arg("--version").stdout(Stdio::null()).status().unwrap().success());
    path
}

/// The fake git's log: per call, the `GIT_*` names set, the fds open, the arguments.
fn git_log(log: &Path) -> Vec<(Vec<String>, String, Vec<String>)> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            let mut f = l.split('\t');
            let env = f.next().unwrap().trim_start_matches("env=");
            let fds = f.next().unwrap().trim_start_matches("fds=").to_string();
            let names = if env == "-" { Vec::new() } else { env.split(',').map(str::to_string).collect() };
            (names, fds, f.map(str::to_string).collect())
        })
        .collect()
}

/// The Mac's dirty state as D2's WIP commits (index commit, WIP commit), `None` when clean.
fn mac_wip(mac: &Path) -> Option<(String, Option<String>)> {
    let head = git(mac, &["rev-parse", "HEAD"]);
    let head_tree = git(mac, &["rev-parse", "HEAD^{tree}"]);
    let index_tree = git(mac, &["write-tree"]);
    let scratch = mac.join(".git/test-index.w");
    std::fs::copy(mac.join(".git/index"), &scratch).unwrap();
    git_with(mac, &["add", "-A"], &[("GIT_INDEX_FILE", &scratch)], None);
    let work_tree = String::from_utf8_lossy(&git_with(mac, &["write-tree"], &[("GIT_INDEX_FILE", &scratch)], None)).trim().to_string();
    std::fs::remove_file(&scratch).unwrap();
    if work_tree == head_tree && index_tree == head_tree {
        return None;
    }
    let index = (index_tree != head_tree).then(|| git(mac, &["commit-tree", &index_tree, "-p", &head, "-m", "index"]));
    let mut args = vec!["commit-tree", work_tree.as_str(), "-p", head.as_str()];
    if let Some(i) = &index {
        args.extend(["-p", i.as_str()]);
    }
    args.extend(["-m", "wip"]);
    Some((git(mac, &args), index))
}

/// A first seed's `PUT /seed` body of the Mac's head and WIP (D7): the
/// manifest line, then the pack of exactly the head's commit and tree and
/// the WIP commits.
fn clone_body(mac: &Path, branch: Option<&str>) -> (SeedManifest, Vec<u8>) {
    let head = git(mac, &["rev-parse", "HEAD"]);
    let wip = mac_wip(mac);
    let mut m = SeedManifest {
        v: SeedManifest::V,
        object_format: ObjectFormat::Sha1,
        branch: branch.map(str::to_string),
        detached: branch.is_none(),
        head: head.clone(),
        wip: wip.as_ref().map(|w| w.0.clone()),
        index: wip.as_ref().and_then(|w| w.1.clone()),
        shallow: vec![head.clone()],
        refs: BTreeMap::new(),
    };
    m.refs = m.expected_refs();
    let mut args = vec!["rev-list", "--objects", "--no-walk", head.as_str()];
    args.extend(m.wip.as_deref());
    args.extend(m.index.as_deref());
    let objects: String = git(mac, &args).lines().map(|l| format!("{}\n", l.split(' ').next().unwrap())).collect();
    let mut body = head_line(&m).unwrap();
    body.extend(git_with(mac, &["pack-objects", "--stdout", "-q"], &[], Some(objects.as_bytes())));
    (m, body)
}

/// An update's body (D3): the thin pack of `head` (and the WIP) less what
/// the VM's `tip` reaches within its shallow boundary `seeded`.
fn update_body(mac: &Path, base: &SeedManifest, tip: &str, seeded: &str) -> (SeedManifest, Vec<u8>) {
    let head = git(mac, &["rev-parse", "HEAD"]);
    let wip = mac_wip(mac);
    let mut m = SeedManifest { head: head.clone(), wip: wip.as_ref().map(|w| w.0.clone()), index: wip.as_ref().and_then(|w| w.1.clone()), shallow: Vec::new(), refs: BTreeMap::new(), ..base.clone() };
    m.refs = m.expected_refs();
    let shallow_file = mac.join(".git/test-vm-shallow");
    std::fs::write(&shallow_file, format!("{seeded}\n")).unwrap();
    let mut revs = format!("{head}\n");
    if let Some(w) = &m.wip {
        revs.push_str(&format!("{w}\n"));
    }
    revs.push_str(&format!("^{tip}\n"));
    let mut body = head_line(&m).unwrap();
    body.extend(git_with(mac, &["--shallow-file", shallow_file.to_str().unwrap(), "pack-objects", "--revs", "--thin", "--stdout", "-q"], &[], Some(revs.as_bytes())));
    (m, body)
}

/// One request with the session bearer (`Connection: close`; `body` with its
/// `Content-Length`): status, head, the body's bytes.
async fn request(addr: SocketAddr, method: &str, path: &str, extra: &str, body: Option<&[u8]>) -> (u16, String, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let len = body.map_or(String::new(), |b| format!("Content-Length: {}\r\n", b.len()));
    let head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{}{extra}{len}Connection: close\r\n\r\n", bearer_header(TOKEN));
    s.write_all(head.as_bytes()).await.unwrap();
    if let Some(b) = body {
        // A refusal may come before the whole body was read; what came back is still read.
        let _ = s.write_all(b).await;
    }
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), s.read_to_end(&mut buf)).await.expect("an answer within 60 s").unwrap();
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| panic!("no head in {:?}", String::from_utf8_lossy(&buf)));
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let status = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap();
    (status, head, buf[end + 4..].to_vec())
}

fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(body)))
}

fn refusal_of(body: &[u8]) -> WsRefusal {
    serde_json::from_slice(body).unwrap_or_else(|e| panic!("not a refusal ({e}): {}", String::from_utf8_lossy(body)))
}

/// The S8 world (the section's doc), `/run` done.
struct Vm {
    s: Stack,
    root: PathBuf,
    _tmp: tempfile::TempDir,
}

impl Vm {
    async fn new() -> Vm {
        Vm::with(|_| git_real().to_path_buf()).await
    }

    /// With the fake git as the helper's, logging to `<tmp>/git.log`.
    async fn with_fake_git() -> Vm {
        Vm::with(|root| {
            fake_git(&root.join("vm-git"), &root.join("git.log"));
            root.join("vm-git")
        })
        .await
    }

    /// With the git `make` puts in the test's root as the helper's.
    async fn with(make: impl FnOnce(&Path) -> PathBuf) -> Vm {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        // The agent's home exists, as the image's does.
        std::fs::create_dir_all(root.join("vm/Users/agent")).unwrap();
        let git_path = make(&root);
        let o = ShimOpts { fs_root: Some(root.join("vm")), home: root.join("vm/Users/agent"), helper: Some(PathBuf::from(bin())), git: git_path, ..opts(None, HookSource::Log, 0) };
        let s = stack(o).await;
        s.run(true).await;
        let mac = root.join("mac");
        std::fs::create_dir_all(&mac).unwrap();
        git(&mac, &["init", "-q", "-b", "main"]);
        write_file(&mac.join("a.txt"), "one\n");
        write_file(&mac.join("d/b.txt"), "two\n");
        git(&mac, &["add", "-A"]);
        git(&mac, &["commit", "-q", "-m", "c1"]);
        write_file(&mac.join("a.txt"), "three\n");
        git(&mac, &["commit", "-q", "-am", "c2"]);
        Vm { s, root, _tmp: tmp }
    }

    fn mac(&self) -> PathBuf {
        self.root.join("mac")
    }

    /// Where the VM path `vm` is on this disk.
    fn disk(&self, vm: &str) -> PathBuf {
        self.s.state.at(Path::new(vm))
    }

    fn ws(&self) -> PathBuf {
        self.disk(WS)
    }

    fn inbox_is_empty(&self) -> bool {
        std::fs::read_dir(self.disk(&format!("{VM_HOME}/.cache/ai-env/inbox"))).map_or(true, |mut d| d.next().is_none())
    }

    async fn code(&self, method: &str, path: &str, body: Option<&[u8]>) -> (u16, String, Vec<u8>) {
        request(self.s.code, method, path, "", body).await
    }

    async fn app(&self, method: &str, path: &str, body: Option<&[u8]>) -> (u16, String, Vec<u8>) {
        request(self.s.app, method, path, "", body).await
    }

    /// `PUT /seed?<query>` of `body`: the status and the JSON answer.
    async fn seed(&self, query: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let (st, _, b) = self.code("PUT", &format!("/seed?{query}"), Some(body)).await;
        (st, b)
    }

    /// A first seed of the Mac as it is now (201).
    async fn clone_mac(&self) -> SeedManifest {
        let (m, body) = clone_body(&self.mac(), Some("main"));
        let (st, b) = self.seed(&format!("path={WS}&mode=clone&branch=main"), &body).await;
        assert_eq!(st, 201, "{}", String::from_utf8_lossy(&b));
        m
    }

    async fn state(&self) -> SeedState {
        let (st, _, b) = self.code("GET", &format!("/seed?path={WS}"), None).await;
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
        serde_json::from_slice(&b).unwrap()
    }

    async fn workspace_view(&self) -> WorkspaceView {
        self.s.detail().await.0.workspace.expect("a shim with a helper reports its workspace")
    }
}

/// The caps of a shim that serves the workspace (S9): `credential_cache`,
/// `workspace_v1`, then `git_http_v1` and `transcript_s3_v1` once their
/// routes are served (`shim::gitcgi::SERVED`, `shim::s3xfer::SERVED`); S10:
/// then `park_v1` once the park is (`shim::agent::PARK_SERVED`). S11, each
/// under its flag: `codeout_manifest_v1`, `view_parent_v1` and
/// `transcript_gzip_v1` (the two transfer caps also under
/// `s3xfer::SERVED`), then `claude_stage_v1` (`shim::claudebin::SERVED`:
/// these shims run with an fs root, so the claude cache has a store).
fn shim_caps() -> Vec<&'static str> {
    use ai_env_cli::wire::frame::{CAP_CLAUDE_STAGE_V1, CAP_CODEOUT_MANIFEST_V1, CAP_TRANSCRIPT_GZIP_V1, CAP_VIEW_PARENT_V1};
    let mut caps = vec![CAP_CREDENTIAL_CACHE, CAP_WORKSPACE_V1];
    if ai_env_cli::shim::gitcgi::SERVED {
        caps.push(CAP_GIT_HTTP_V1);
    }
    if ai_env_cli::shim::s3xfer::SERVED {
        caps.push(CAP_TRANSCRIPT_S3_V1);
    }
    if ai_env_cli::shim::agent::PARK_SERVED {
        caps.push(ai_env_cli::wire::frame::CAP_PARK_V1);
    }
    if ai_env_cli::shim::code::MANIFEST_SERVED {
        caps.push(CAP_CODEOUT_MANIFEST_V1);
    }
    if ai_env_cli::shim::s3xfer::SERVED && ai_env_cli::shim::s3xfer::VIEW_PARENT_SERVED {
        caps.push(CAP_VIEW_PARENT_V1);
    }
    if ai_env_cli::shim::s3xfer::SERVED && ai_env_cli::shim::s3xfer::GZIP_SERVED {
        caps.push(CAP_TRANSCRIPT_GZIP_V1);
    }
    if ai_env_cli::shim::claudebin::SERVED {
        caps.push(CAP_CLAUDE_STAGE_V1);
    }
    caps
}

/// The caps of a shim without a helper: `credential_cache`, and S10's
/// `park_v1` once the park is served (with or without a helper). S11: no
/// helper, so none of part C's caps; and these shims run with no fs root and
/// not as root, so the claude cache has no store and `claude_stage_v1` is
/// never named.
fn bare_caps() -> Vec<&'static str> {
    let mut caps = vec![CAP_CREDENTIAL_CACHE];
    if ai_env_cli::shim::agent::PARK_SERVED {
        caps.push(ai_env_cli::wire::frame::CAP_PARK_V1);
    }
    caps
}

/// The code port: 401 before `/run`, without the bearer or with a wrong
/// one; behind it the workspace routes (S8) and, once their cap is named,
/// S9's git routes answer, and any other path is 404 `NO_SUCH_ROUTE`. A
/// shim without a helper serves none of them: 404, as an older shim, and
/// its caps name neither `workspace_v1` nor `git_http_v1`.
#[tokio::test]
async fn code_port_answers_401_then_the_seed_routes_with_the_bearer() {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    std::fs::create_dir_all(root.join("vm/Users/agent")).unwrap();
    let o = ShimOpts { fs_root: Some(root.join("vm")), home: root.join("vm/Users/agent"), helper: Some(PathBuf::from(bin())), git: git_real().to_path_buf(), ..opts(None, HookSource::Log, 0) };
    let s = stack(o).await;
    let seed = format!("/seed?path={WS}");
    let paths = [("GET", seed.as_str()), ("PUT", "/seed"), ("POST", "/codeout"), ("GET", "/bundle?since=x"), ("GET", GIT_ADVERTISE), ("POST", GIT_RECEIVE_PACK_ROUTE)];
    for (m, p) in paths {
        let (st, head, b) = http_with(s.code, m, p, &bearer_header(TOKEN), b"").await;
        assert_eq!(st, 401, "before /run, no commitment: {m} {p}: {b}");
        assert!(head.to_ascii_lowercase().contains("www-authenticate: bearer"), "{head}");
    }
    s.run(true).await;
    for (m, p) in paths {
        let (st, _, b) = http(s.code, m, p, b"x", Some("text/plain")).await;
        assert!(st == 401 && b.contains("unauthorized"), "{m} {p}: {st} {b}");
        assert_eq!(http_with(s.code, m, p, &bearer_header("not-the-token"), b"").await.0, 401, "{m} {p}: a wrong token");
    }
    let (st, _, b) = http_with(s.code, "GET", &seed, &bearer_header(TOKEN), b"").await;
    assert_eq!(st, 200, "{b}");
    assert_eq!(serde_json::from_str::<SeedState>(&b).unwrap(), SeedState::default(), "never seeded");
    let (st, _, b) = http_with(s.code, "GET", "/seed?path=relative", &bearer_header(TOKEN), b"").await;
    assert!(st == 400 && b.contains("\"bad_request\""), "{st} {b}");
    for p in ["/", "/bundle?since=x", "/workspace.git/HEAD"] {
        let (st, _, b) = http_with(s.code, "GET", p, &bearer_header(TOKEN), b"").await;
        assert!(st == 404 && b == NO_SUCH_ROUTE, "{p}: {st} {b}");
    }
    let (st, _, _) = http_with(s.code, "DELETE", &seed, &bearer_header(TOKEN), b"").await;
    assert_eq!(st, 405);
    let health: Health = serde_json::from_str(&http(s.app, "GET", "/health", b"", None).await.2).unwrap();
    assert_eq!(health.caps, shim_caps());
    let (_, has, caps, _) = hello_view(s.app).await;
    assert!(!has && caps == shim_caps(), "{caps:?}");
    // No helper program: none of it.
    let old = Stack::log().await;
    old.run(true).await;
    for p in [seed.as_str(), GIT_ADVERTISE] {
        let (st, _, b) = http_with(old.code, "GET", p, &bearer_header(TOKEN), b"").await;
        assert!(st == 404 && b == NO_SUCH_ROUTE, "{p}: {st} {b}");
    }
    assert_eq!(serde_json::from_str::<Health>(&http(old.app, "GET", "/health", b"", None).await.2).unwrap().caps, bare_caps());
    assert!(old.detail().await.0.workspace.is_none());
}

/// The app port: `/health` and `/agent` are public; `/health/detail` and
/// every other path need the session bearer (401 without, and before any
/// commitment exists); behind it the transcript route answers (S8's stat;
/// S8's `PUT` went at the S3 cut-over: 405), and an unknown path is 404.
#[tokio::test]
async fn app_port_bearer() {
    let vm = Vm::new().await;
    let s = &vm.s;
    let rel = format!("{S8_SLUG}/{S8_ID}.jsonl");
    let stat = format!("/transcript?rel={rel}");
    for (m, p, body) in [("GET", stat.as_str(), &b""[..]), ("PUT", stat.as_str(), b"{}"), ("GET", "/health/detail", b""), ("POST", "/seed", b"x"), ("GET", "/settings?path=/Users/agent/ws", b"")] {
        let (st, head, b) = http(s.app, m, p, body, Some("application/json")).await;
        assert_eq!(st, 401, "{m} {p}: {b}");
        assert!(b.contains("\"unauthorized\"") && head.to_ascii_lowercase().contains("www-authenticate: bearer"), "{head}{b}");
        assert_eq!(http_with(s.app, m, p, &bearer_header("not-the-token"), body).await.0, 401, "{m} {p}: a wrong token");
    }
    let (st, _, b) = http_with(s.app, "GET", &stat, &bearer_header(TOKEN), b"").await;
    assert_eq!(st, 200, "{b}");
    assert!(!serde_json::from_str::<TranscriptStat>(&b).unwrap().present, "{b}");
    let (st, _, b) = http_with(s.app, "PUT", &stat, &bearer_header(TOKEN), b"{}\n").await;
    assert_eq!(st, 405, "S8's upload is gone: {b}");
    assert!(!vm.disk(&format!("{VM_HOME}/.claude/projects/{rel}")).exists(), "nothing written");
    let (st, _, b) = http_with(s.app, "PUT", "/nope", &bearer_header(TOKEN), b"{}").await;
    assert!(st == 404 && b == NO_SUCH_ROUTE, "{b}");
    let (d, body) = s.detail().await;
    for key in ["\"hook_source\":\"log\"", "\"agent_guard\":\"off\"", "\"listeners\":", "\"refused_peers\":", "\"hook_peers\":", "\"wire\":1", "\"workspace\":{"] {
        assert!(body.contains(key), "{key} in {body}");
    }
    assert!(d.health.run_hook_seen && !d.has_credentials && d.spawns.is_empty());
    assert_eq!(d.listeners.is_empty(), !cfg!(target_os = "linux"), "the LISTEN inventory exists on Linux only: {:?}", d.listeners);
    assert!(!body.contains(TOKEN) && !body.contains("commit"), "{body}");
}

/// T8.1 on the shim's side: a first seed of a dirty Mac through `PUT
/// /seed` (201): the VM's HEAD is the Mac's, shallow at it, no origin and
/// no history, the WIP uncommitted (the staged change staged, the unstaged
/// unstaged, the untracked file untracked); `GET /seed` then reports it
/// pristine and not clean, `/health/detail` its record. Every git the
/// helper ran is the VM's (no global config, no prompt; nothing but those
/// and its own index or lock names), with no descriptor past stderr, and
/// none fetched, cloned or named a remote.
#[tokio::test]
async fn a_seed_round_trips_through_the_code_port() {
    let vm = Vm::with_fake_git().await;
    let mac = vm.mac();
    write_file(&mac.join("d/b.txt"), "staged\n");
    git(&mac, &["add", "d/b.txt"]);
    write_file(&mac.join("a.txt"), "unstaged\n");
    write_file(&mac.join("new.txt"), "untracked\n");
    let (m, body) = clone_body(&mac, Some("main"));
    let (st, b) = vm.seed(&format!("path={WS}&mode=clone&branch=main"), &body).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&b));
    let reply: SeedReply = serde_json::from_slice(&b).unwrap();
    assert_eq!((reply.head.as_str(), reply.branch.as_deref(), reply.wip.as_deref()), (m.head.as_str(), Some("main"), m.wip.as_deref()));
    let ws = vm.ws();
    assert_eq!(git(&ws, &["rev-parse", "HEAD"]), git(&mac, &["rev-parse", "HEAD"]), "HEAD equal");
    assert_eq!(git(&ws, &["remote"]), "", "no origin");
    assert_eq!(std::fs::read_to_string(ws.join(".git/shallow")).unwrap(), format!("{}\n", m.head), "shallow at the seeded commit");
    assert_eq!(git(&ws, &["rev-list", "--count", "HEAD"]), "1");
    assert_eq!(git_status(&ws), [" M a.txt", "M  d/b.txt", "?? new.txt"], "the WIP, uncommitted");
    assert_eq!(git(&ws, &["rev-parse", SEED_REF]), m.head);
    assert_eq!(Some(git(&ws, &["rev-parse", SEED_WIP_REF])), m.wip);
    assert!(vm.inbox_is_empty());
    let st = vm.state().await;
    assert!(st.pristine && !st.clean && st.tip.as_deref() == Some(m.head.as_str()) && st.branch.as_deref() == Some("main"), "{st:?}");
    let view = vm.workspace_view().await;
    assert_eq!(view.seed.as_ref().map(|r| r.path.as_str()), Some(WS));
    assert_eq!((view.busy, view.helpers), (None, 0));
    let calls = git_log(&vm.root.join("git.log"));
    assert!(calls.len() > 8, "{calls:?}");
    let allowed = ["GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS", "GIT_INDEX_FILE"];
    for (env, fds, args) in &calls {
        assert!(env.iter().all(|n| allowed.contains(&n.as_str())) && env.iter().any(|n| n == "GIT_CONFIG_GLOBAL"), "{env:?} {args:?}");
        assert_eq!(fds, "-", "no descriptor past stderr: {args:?}");
        assert!(!args.iter().any(|a| ["clone", "fetch", "remote", "push"].contains(&a.as_str())), "{args:?}");
    }
    assert!(calls.iter().any(|(_, _, a)| a.iter().any(|x| x == "index-pack")) && calls.iter().any(|(_, _, a)| a.iter().any(|x| x == "--template=")), "{calls:?}");
}

/// A bad seed is refused before anything stays behind: a pack that does not
/// index (422 `bad_pack`), a manifest naming a commit the pack lacks (422
/// `bad_refs`), a bad query (400), no `Content-Length` (411), a body over
/// `SEED_BODY_MAX` (413); then the good seed goes in.
#[tokio::test]
async fn a_bad_seed_is_refused_and_leaves_nothing_behind() {
    let vm = Vm::new().await;
    let (m, body) = clone_body(&vm.mac(), Some("main"));
    let line = head_line(&m).unwrap().len();
    let q = format!("path={WS}&mode=clone&branch=main");
    let mut garbage = head_line(&m).unwrap();
    garbage.extend_from_slice(b"PACK nothing like a pack");
    let (st, b) = vm.seed(&q, &garbage).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (422, "bad_pack"));
    let mut other = m.clone();
    other.head = "1".repeat(40);
    other.shallow = vec![other.head.clone()];
    other.refs = other.expected_refs();
    let mut lacking = head_line(&other).unwrap();
    lacking.extend_from_slice(&body[line..]);
    let (st, b) = vm.seed(&q, &lacking).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (422, "bad_refs"));
    for bad in [format!("path={WS}&mode=merge&branch=main"), format!("path={WS}&mode=clone"), format!("path={WS}&mode=update&branch=main"), "path=relative&mode=clone&branch=main".to_string()] {
        let (st, b) = vm.seed(&bad, &body).await;
        assert_eq!((st, refusal_of(&b).code.as_str()), (400, "bad_request"), "{bad}");
    }
    // Chunked: no length.
    let mut s = tokio::net::TcpStream::connect(vm.s.code).await.unwrap();
    let head = format!("PUT /seed?{q} HTTP/1.1\r\nHost: x\r\n{}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n", bearer_header(TOKEN));
    s.write_all(head.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let (st, _, b) = split_response(&buf);
    assert!(st == 411 && b.contains("\"bad_request\""), "{st} {b}");
    // A length over the cap: refused on its head (the body read up to the drain's bound, not the cap).
    let mut s = tokio::net::TcpStream::connect(vm.s.code).await.unwrap();
    let head = format!("PUT /seed?{q} HTTP/1.1\r\nHost: x\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n", bearer_header(TOKEN), (1u64 << 30) + 1);
    s.write_all(head.as_bytes()).await.unwrap();
    let _ = s.write_all(&vec![b'z'; DRAIN_MAX + 1]).await;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let (st, _, b) = split_response(&buf);
    assert!(st == 413 && b.contains("\"too_large\""), "{st} {b}");
    assert!(!vm.ws().exists(), "no workspace left behind");
    assert!(vm.inbox_is_empty());
    assert!(vm.state().await.record.is_none(), "nothing recorded");
    let (st, b) = vm.seed(&q, &body).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&b));
}

/// T8.6 and one workspace per VM: a symlink the agent planted on the path is
/// 409 `symlink_component` (both routes), a non-empty directory 409
/// `path_occupied`, a path outside the agent's home 409 `not_creatable`;
/// once seeded, another path is 409 `other_workspace` with the record, and
/// a clone of the seeded path 409 `changed`.
#[tokio::test]
async fn seed_paths_are_refused_as_the_agent() {
    let vm = Vm::new().await;
    let (_, body) = clone_body(&vm.mac(), Some("main"));
    let outside = vm.root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, vm.disk("/Users/agent/linked")).unwrap();
    let (st, b) = vm.seed("path=/Users/agent/linked/ws&mode=clone&branch=main", &body).await;
    let r = refusal_of(&b);
    assert!(st == 409 && r.code == "symlink_component" && r.message.contains("/Users/agent/linked"), "{st} {r:?}");
    let (st, _, b) = vm.code("GET", "/seed?path=/Users/agent/linked/ws", None).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "symlink_component"));
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none(), "nothing written through the link");
    write_file(&vm.disk("/Users/agent/full/x"), "x");
    let (st, b) = vm.seed("path=/Users/agent/full&mode=clone&branch=main", &body).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "path_occupied"));
    let (st, b) = vm.seed("path=/srv/ws&mode=clone&branch=main", &body).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "not_creatable"));
    vm.clone_mac().await;
    for (method, path) in [("PUT", "/seed?path=/Users/agent/ws2&mode=clone&branch=main"), ("GET", "/seed?path=/Users/agent/ws2")] {
        let (st, _, b) = vm.code(method, path, (method == "PUT").then_some(body.as_slice())).await;
        let r = refusal_of(&b);
        assert!(st == 409 && r.code == "other_workspace" && r.state.as_ref().and_then(|s| s.record.as_ref()).is_some_and(|rec| rec.path == WS), "{method}: {st} {r:?}");
    }
    let (st, b) = vm.seed(&format!("path={WS}&mode=clone&branch=main"), &body).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "changed"));
}

/// D3 through the route: a clean VM behind the Mac is fast-forwarded by a
/// thin update (201 `updated`, the new WIP uncommitted); a VM with changes
/// of its own is kept (409 `dirty`), a stale `expect` is 409 `changed`, a VM
/// commit makes it 409 `diverged`. A replace of a VM that changed is 409
/// `not_pristine`; of a pristine one, 201 `replaced`.
#[tokio::test]
async fn updates_fast_forward_a_clean_vm_and_keep_the_rest() {
    let vm = Vm::new().await;
    let mac = vm.mac();
    let seed = vm.clone_mac().await;
    let tip = seed.head.clone();
    write_file(&mac.join("a.txt"), "four\n");
    git(&mac, &["commit", "-q", "-am", "c3"]);
    write_file(&mac.join("wip.txt"), "the Mac's uncommitted file\n");
    let (m, body) = update_body(&mac, &seed, &tip, &tip);
    let q = format!("path={WS}&mode=update&branch=main&expect={tip}");
    let ws = vm.ws();
    write_file(&ws.join("agent.txt"), "the agent's\n");
    let (st, b) = vm.seed(&q, &body).await;
    let r = refusal_of(&b);
    assert!(st == 409 && r.code == "dirty" && r.state.as_ref().is_some_and(|s| !s.clean), "{st} {r:?}");
    std::fs::remove_file(ws.join("agent.txt")).unwrap();
    let (st, b) = vm.seed(&format!("path={WS}&mode=update&branch=main&expect={}", m.head), &body).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "changed"));
    let (st, b) = vm.seed(&q, &body).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&b));
    assert_eq!(json(&b)["outcome"], "updated");
    assert_eq!(git(&ws, &["rev-parse", "HEAD"]), m.head);
    assert_eq!(git_status(&ws), ["?? wip.txt"]);
    let st = vm.state().await;
    assert!(st.pristine && st.record.as_ref().is_some_and(|r| r.head == m.head), "{st:?}");
    // The agent commits on its own: the next update is diverged, and a replace is refused.
    std::fs::remove_file(ws.join("wip.txt")).unwrap();
    write_file(&ws.join("vm.txt"), "the agent's commit\n");
    git(&ws, &["add", "vm.txt"]);
    git(&ws, &["commit", "-q", "-m", "vm"]);
    let vm_tip = git(&ws, &["rev-parse", "HEAD"]);
    write_file(&mac.join("a.txt"), "five\n");
    std::fs::remove_file(mac.join("wip.txt")).unwrap();
    git(&mac, &["commit", "-q", "-am", "c4"]);
    let (_, body) = update_body(&mac, &seed, &m.head, &tip);
    let (st, b) = vm.seed(&format!("path={WS}&mode=update&branch=main&expect={vm_tip}"), &body).await;
    let r = refusal_of(&b);
    assert!(st == 409 && r.code == "diverged", "{st} {r:?}");
    let (_, body) = clone_body(&mac, Some("main"));
    let (st, b) = vm.seed(&format!("path={WS}&mode=replace&branch=main&expect={vm_tip}"), &body).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "not_pristine"));
    assert_eq!(git(&ws, &["rev-parse", "HEAD"]), vm_tip, "the VM keeps its commit");
}

/// `replace` on a VM unchanged since its seed: the new head checked out anew
/// (201 `replaced`), the old seed's WIP gone, the new one applied.
#[tokio::test]
async fn a_replace_checks_out_a_pristine_vm_anew() {
    let vm = Vm::new().await;
    let mac = vm.mac();
    write_file(&mac.join("old.txt"), "the first seed's untracked file\n");
    let seed = vm.clone_mac().await;
    std::fs::remove_file(mac.join("old.txt")).unwrap();
    write_file(&mac.join("a.txt"), "replaced\n");
    git(&mac, &["commit", "-q", "-am", "c3"]);
    let (m, body) = clone_body(&mac, Some("main"));
    let (st, b) = vm.seed(&format!("path={WS}&mode=replace&branch=main&expect={}", seed.head), &body).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&b));
    assert_eq!(json(&b)["outcome"], "replaced");
    let ws = vm.ws();
    assert_eq!(git(&ws, &["rev-parse", "HEAD"]), m.head);
    assert!(!ws.join("old.txt").exists());
    assert!(git_status(&ws).is_empty(), "{:?}", git_status(&ws));
    assert_eq!(vm.state().await.record.map(|r| r.mode), Some(ai_env_cli::wire::workspace::SeedMode::Replace));
}

/// Code-out (§7): a VM commit and an uncommitted edit come back through
/// `POST /codeout`: the manifest line names the branch at the VM's commit
/// and a `refs/wip/*` snapshot holding the edit, then the pack (its length
/// the answer's), which the Mac's repository indexes; with every tip had,
/// 204; past `max_bytes` 413 with the size; an unseeded VM 409 `not_seeded`.
#[tokio::test]
async fn a_codeout_brings_back_a_vm_commit_and_the_uncommitted_edit() {
    let vm = Vm::new().await;
    let (st, _, b) = vm.code("POST", "/codeout", Some(format!("{{\"path\":\"{WS}\",\"max_bytes\":1000}}").as_bytes())).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "not_seeded"));
    let seed = vm.clone_mac().await;
    let ws = vm.ws();
    write_file(&ws.join("vm.txt"), "committed in the VM\n");
    git(&ws, &["add", "vm.txt"]);
    git(&ws, &["commit", "-q", "-m", "vm"]);
    let vm_head = git(&ws, &["rev-parse", "HEAD"]);
    write_file(&ws.join("a.txt"), "edited in the VM\n");
    let req = serde_json::json!({"path": WS, "haves": [seed.head], "wip": true, "max_bytes": 1 << 20});
    let (st, head, b) = vm.code("POST", "/codeout", Some(req.to_string().as_bytes())).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let declared: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").map(|v| v.trim().parse().unwrap())).unwrap();
    assert_eq!(declared, b.len());
    let nl = b.iter().position(|c| *c == b'\n').unwrap();
    let manifest: CodeoutManifest = serde_json::from_slice(&b[..nl]).unwrap();
    manifest.check().unwrap();
    assert_eq!((manifest.head.as_str(), manifest.branch.as_deref()), (vm_head.as_str(), Some("main")));
    assert_eq!(manifest.refs["refs/heads/main"], vm_head);
    let wip = manifest.wip_ref.clone().expect("a snapshot");
    let mac = vm.mac();
    git_with(&mac, &["index-pack", "--stdin", "--fix-thin"], &[], Some(&b[nl + 1..]));
    assert_eq!(git(&mac, &["show", &format!("{}:vm.txt", vm_head)]), "committed in the VM");
    assert_eq!(git(&mac, &["show", &format!("{}:a.txt", manifest.refs[&wip])]), "edited in the VM");
    assert_eq!(git_status(&ws), [" M a.txt"], "the agent's checkout as it was");
    assert_eq!(vm.workspace_view().await.last_wip.as_deref(), Some(wip.as_str()));
    let had: Vec<&String> = manifest.refs.values().collect();
    let req = serde_json::json!({"path": WS, "haves": had, "wip": true, "max_bytes": 1 << 20});
    let (st, _, b) = vm.code("POST", "/codeout", Some(req.to_string().as_bytes())).await;
    assert!(st == 204 && b.is_empty(), "{st}: {}", String::from_utf8_lossy(&b));
    let req = serde_json::json!({"path": WS, "haves": [], "wip": false, "max_bytes": 64});
    let (st, _, b) = vm.code("POST", "/codeout", Some(req.to_string().as_bytes())).await;
    let r = refusal_of(&b);
    assert!(st == 413 && r.code == "too_large" && r.size.is_some_and(|s| s > 64), "{st} {r:?}");
    let (st, _, b) = vm.code("POST", "/codeout", Some(b"{\"path\":\"relative\",\"max_bytes\":1}")).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (400, "bad_request"));
    assert!(vm.inbox_is_empty());
}

/// The app port's transcript route after the S3 cut-over: `GET` states the
/// agent's file (absent, then present with its size and sha256; a pull
/// writes it, `tests/shim_local/transcript_s3.rs`); S8's `PUT` (the Mac's
/// mirror sent up) is gone, 405 whatever its body, nothing written, the
/// VM's copy unchanged; a traversal rel or none is 400.
#[tokio::test]
async fn the_transcript_route_states_and_takes_no_upload() {
    use sha2::Digest as _;
    let vm = Vm::new().await;
    let rel = format!("{S8_SLUG}/{S8_ID}.jsonl");
    let path = format!("/transcript?rel={rel}");
    let (st, _, b) = vm.app("GET", &path, None).await;
    assert_eq!(st, 200);
    assert!(!serde_json::from_slice::<TranscriptStat>(&b).unwrap().present);
    let (st, _, _) = vm.app("PUT", &path, Some(b"{\"type\":\"user\"}\n")).await;
    assert_eq!(st, 405, "S8's upload is gone");
    let file = vm.disk(&format!("{VM_HOME}/.claude/projects/{rel}"));
    assert!(!file.exists(), "nothing written");
    let text = b"{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n";
    write_file(&file, std::str::from_utf8(text).unwrap());
    let stat: TranscriptStat = serde_json::from_slice(&vm.app("GET", &path, None).await.2).unwrap();
    let sha = hex::encode(sha2::Sha256::digest(text));
    assert!(stat.present && stat.size == text.len() as u64 && stat.sha256.as_deref() == Some(sha.as_str()), "{stat:?}");
    assert_eq!(vm.app("PUT", &path, Some(b"{}\n")).await.0, 405);
    assert_eq!(std::fs::read(&file).unwrap(), text, "the VM's copy unchanged");
    for bad in [format!("/transcript?rel=../{S8_ID}.jsonl"), format!("/transcript?rel={S8_SLUG}/../{S8_ID}.jsonl"), "/transcript".to_string()] {
        let (st, _, b) = vm.app("GET", &bad, None).await;
        assert_eq!((st, refusal_of(&b).code.as_str()), (400, "bad_request"), "{bad}");
    }
}

/// A transcript write (a pull's `transcript-write`) the helper does not
/// end itself (the shim's TERM at the pull's budget, or at a stop: the
/// helper has no handler, no drop runs) leaves its 0600 temp file beside
/// the transcript; the next write into that directory removes it, so none
/// outlives it. The real helper, as the shim starts it.
#[test]
fn a_write_ended_by_term_leaves_no_temp_file_past_the_next_write() {
    use std::os::unix::process::ExitStatusExt;
    let tmp = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(tmp.path()).unwrap();
    let projects = home.join(".claude/projects");
    let dir = projects.join(S8_SLUG);
    let rel = format!("{S8_SLUG}/{S8_ID}.jsonl");
    let write = |len: usize| {
        let args = [format!("--home={}", home.display()), "transcript-write".into(), format!("--projects={}", projects.display()), format!("--rel={rel}"), format!("--len={len}"), "--budget-ms=90000".into()];
        Command::new(bin()).env_clear().arg("shim-io").args(&args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
    };
    let temps = || -> Vec<(String, u64)> {
        let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
        entries.flatten().map(|e| (e.file_name().to_string_lossy().into_owned(), e.metadata().map_or(0, |m| m.len()))).filter(|(n, _)| n.starts_with(".ai-env-")).collect()
    };
    let mut cut = write(1000);
    cut.stdin.as_mut().unwrap().write_all(&[b'x'; 25]).unwrap();
    let until = Instant::now() + Duration::from_secs(30);
    while !temps().iter().any(|(_, n)| *n == 25) {
        assert!(Instant::now() < until, "no temp file holding the 25 bytes: {:?}", temps());
        std::thread::sleep(Duration::from_millis(10));
    }
    signal(cut.id(), nix::sys::signal::Signal::SIGTERM);
    assert_eq!(cut.wait().unwrap().signal(), Some(libc::SIGTERM));
    let left = temps();
    assert!(left.len() == 1 && left[0].1 == 25, "the ended write left its temp file: {left:?}");
    let text = b"{\"type\":\"user\"}\n";
    let mut full = write(text.len());
    let mut stdin = full.stdin.take().unwrap();
    stdin.write_all(text).unwrap();
    stdin.write_all(b"commit\n").unwrap();
    drop(stdin);
    let out = full.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let head = json(&out.stdout);
    assert_eq!(head["reply"]["size"].as_u64(), Some(text.len() as u64), "{head}");
    assert!(temps().is_empty(), "no temp file outlives the next write: {:?}", temps());
    assert_eq!(std::fs::read(dir.join(format!("{S8_ID}.jsonl"))).unwrap(), text);
}

/// T8.7's capture through `GET /settings`: the agent's and the workspace's
/// settings files with their text, and the workspace's allowlisted keys.
#[tokio::test]
async fn settings_are_captured_on_the_app_port() {
    let vm = Vm::new().await;
    vm.clone_mac().await;
    write_file(&vm.disk(&format!("{VM_HOME}/.claude/settings.json")), "{\"permissions\":{\"allow\":[\"Bash(ls)\"]}}");
    write_file(&vm.ws().join(".claude/settings.local.json"), "{\"permissions\":{\"allow\":[\"Bash(git status)\"]}}");
    let doc = serde_json::json!({"projects": {WS: {"allowedTools": ["Bash(ls)"], "hasTrustDialogAccepted": true, "lastCost": 1}}});
    write_file(&vm.disk(&format!("{VM_HOME}/.claude/.claude.json")), &doc.to_string());
    let (st, _, b) = vm.app("GET", &format!("/settings?path={WS}"), None).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let c: SettingsCapture = serde_json::from_slice(&b).unwrap();
    c.check().unwrap();
    assert!(c.files[0].text.as_deref().is_some_and(|t| t.contains("Bash(ls)")) && c.files[0].path == format!("{VM_HOME}/.claude/settings.json"), "{:?}", c.files[0]);
    assert!(!c.files[1].present, "no project settings");
    assert!(c.files[2].text.as_deref().is_some_and(|t| t.contains("git status")), "{:?}", c.files[2]);
    assert_eq!(c.project.keys().collect::<Vec<_>>(), ["allowedTools", "hasTrustDialogAccepted"]);
    let (st, _, b) = vm.app("GET", "/settings?path=nope", None).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (400, "bad_request"));
}

/// A seed whose body is still arriving is a helper: it counts in the
/// workspace view and holds off the idle sweep (the spawn manager's own
/// tests prove the gate; natively the sweep never runs), and a spawn that
/// ends meanwhile does not end it: the seed completes once its body does.
#[tokio::test]
async fn a_helper_outlives_a_spawn_that_ends_meanwhile() {
    let vm = Vm::new().await;
    let (_, body) = clone_body(&vm.mac(), Some("main"));
    let mut s = tokio::net::TcpStream::connect(vm.s.code).await.unwrap();
    let head = format!("PUT /seed?path={WS}&mode=clone&branch=main HTTP/1.1\r\nHost: x\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n", bearer_header(TOKEN), body.len());
    s.write_all(head.as_bytes()).await.unwrap();
    let half = body.len() / 2;
    s.write_all(&body[..half]).await.unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    while vm.workspace_view().await.helpers == 0 {
        assert!(Instant::now() < until, "the seed's helper never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(vm.workspace_view().await.busy.as_deref(), Some("seed-apply"));
    let mut w = ws_hello_ok(vm.s.app).await;
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/echo", "done"], None).await;
    let (_, code) = run_to_exit(&mut w, &id).await;
    assert_eq!(code, Some(0));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(vm.workspace_view().await.helpers, 1, "the helper lives on past the spawn's end");
    s.write_all(&body[half..]).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let (st, _, b) = split_response(&buf);
    assert_eq!(st, 201, "{b}");
    assert_eq!(vm.workspace_view().await.helpers, 0);
}

/// `/suspend` snapshots the uncommitted work (L6) before it closes the
/// sockets: a `refs/wip/*` ref in the VM, the workspace view's `last_wip`;
/// while a seed or a code-out holds the workspace it is skipped, and the
/// hook still answers at once.
#[tokio::test]
async fn suspend_snapshots_the_workspace_unless_it_is_busy() {
    let vm = Vm::new().await;
    assert_eq!(hook(vm.s.hooks, "suspend", b"{}").await.0, 200, "nothing seeded: no snapshot");
    assert_eq!(hook(vm.s.hooks, "resume", b"{}").await.0, 200);
    vm.clone_mac().await;
    let ws = vm.ws();
    write_file(&ws.join("a.txt"), "uncommitted at suspend\n");
    assert_eq!(hook(vm.s.hooks, "suspend", b"{}").await.0, 200);
    let refs = git(&ws, &["for-each-ref", "--format=%(refname)", "refs/wip/"]);
    assert_eq!(refs.lines().count(), 1, "{refs}");
    assert_eq!(git(&ws, &["show", &format!("{}:a.txt", refs.trim())]), "uncommitted at suspend");
    assert_eq!(hook(vm.s.hooks, "resume", b"{}").await.0, 200);
    assert_eq!(vm.workspace_view().await.last_wip.as_deref(), Some(refs.trim()));
    write_file(&ws.join("a.txt"), "changed again\n");
    let held = vm.s.state.workspace.try_acquire("codeout").expect("the workspace is free");
    let t = Instant::now();
    assert_eq!(hook(vm.s.hooks, "suspend", b"{}").await.0, 200);
    assert!(t.elapsed() < Duration::from_secs(3), "skipped, not waited for: {:?}", t.elapsed());
    drop(held);
    assert_eq!(git(&ws, &["for-each-ref", "--format=%(refname)", "refs/wip/"]).lines().count(), 1, "busy: no snapshot");
}

/// One seed, code-out or snapshot at a time: a request finding the
/// workspace held past the wait is 409 `busy` with `Retry-After`.
#[tokio::test]
async fn a_held_workspace_answers_busy() {
    let vm = Vm::new().await;
    vm.s.state.workspace.set_busy_wait(Duration::from_millis(200));
    let held = vm.s.state.workspace.try_acquire("seed-apply").unwrap();
    let (st, head, b) = vm.code("GET", &format!("/seed?path={WS}"), None).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "busy"));
    assert!(head.to_ascii_lowercase().contains("\r\nretry-after: 5"), "{head}");
    let (_, body) = clone_body(&vm.mac(), Some("main"));
    let (st, b) = vm.seed(&format!("path={WS}&mode=clone&branch=main"), &body).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "busy"), "the body read, then refused");
    drop(held);
    assert_eq!(vm.seed(&format!("path={WS}&mode=clone&branch=main"), &body).await.0, 201);
}

/// The workspace routes' refusals read the request body first (at most
/// `DRAIN_MAX` before the length is trusted), so the client gets the
/// answer, not a reset; S8's `PUT /transcript`, gone at the S3 cut-over, is
/// a 405 that reads it too.
#[tokio::test]
async fn workspace_refusals_read_the_body_first() {
    let vm = Vm::new().await;
    let body = vec![b'x'; DRAIN_MAX - 1024];
    let mut lost = Vec::new();
    for (addr, path, want) in [(vm.s.code, "/seed?path=relative&mode=clone&branch=main", 400), (vm.s.app, "/transcript?rel=nope", 405), (vm.s.code, "/seed?path=/Users/agent/ws&mode=update&branch=main&expect=0123456789abcdef0123456789abcdef01234567", 409)] {
        for i in 0..5 {
            match try_http_with(addr, "PUT", path, &bearer_header(TOKEN), &body).await {
                Ok((st, _, b)) => assert_eq!(st, want, "{path} #{i}: {b}"),
                Err(e) => lost.push(format!("{path} #{i}: {e}")),
            }
        }
    }
    assert!(lost.is_empty(), "answers lost to a reset: {lost:#?}");
}

/// Until the workspace is free again and no helper runs (at most 30 s).
async fn wait_workspace_idle(vm: &Vm) {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let view = vm.workspace_view().await;
        if view.helpers == 0 && view.busy.is_none() {
            return;
        }
        assert!(Instant::now() < until, "the workspace is still held: {view:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A client gone while its seed is applied does not end the seed (it runs
/// as a task of its own): the helper finishes, the shim keeps the record,
/// `GET /seed` reads the VM seeded and pristine, nothing is left in the
/// inbox, and a new clone is 409 `changed` (seeded), not `path_occupied`.
#[tokio::test]
async fn a_seed_whose_client_goes_away_still_goes_in() {
    let vm = Vm::with(|root| slow_git(root, "reset", 2)).await;
    let (m, body) = clone_body(&vm.mac(), Some("main"));
    let q = format!("path={WS}&mode=clone&branch=main");
    let mut s = tokio::net::TcpStream::connect(vm.s.code).await.unwrap();
    let head = format!("PUT /seed?{q} HTTP/1.1\r\nHost: x\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n", bearer_header(TOKEN), body.len());
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(&body).await.unwrap();
    // The clone is under way (its git dir is there, its checkout waits): the client goes.
    let until = Instant::now() + Duration::from_secs(20);
    while !vm.ws().join(".git/HEAD").exists() {
        assert!(Instant::now() < until, "the clone never started");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(s);
    wait_workspace_idle(&vm).await;
    let st = vm.state().await;
    assert!(st.record.as_ref().is_some_and(|r| r.head == m.head) && st.pristine, "{st:?}");
    assert_eq!(git(&vm.ws(), &["rev-parse", "HEAD"]), m.head);
    assert!(vm.inbox_is_empty());
    let (st, b) = vm.seed(&q, &body).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "changed"));
}

/// A code-out client that reads only the head of a large pack, then goes:
/// the helper is ended mid-payload, and its pack had left the inbox before
/// the head went out, so nothing stays behind.
#[tokio::test]
async fn a_codeout_read_only_to_its_head_leaves_nothing_behind() {
    let vm = Vm::new().await;
    vm.clone_mac().await;
    // 16 MiB that does not compress, untracked in the VM: the snapshot carries it, far past every buffer.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let noise: Vec<u8> = (0..16 << 20)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    std::fs::write(vm.ws().join("noise.bin"), &noise).unwrap();
    let req = serde_json::json!({"path": WS, "haves": [], "wip": true, "max_bytes": 64 << 20}).to_string();
    let mut s = tokio::net::TcpStream::connect(vm.s.code).await.unwrap();
    s.write_all(format!("POST /codeout HTTP/1.1\r\nHost: x\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{req}", bearer_header(TOKEN), req.len()).as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(60), s.read(&mut buf)).await.expect("a head within 60 s").unwrap();
        assert!(n > 0, "closed before the head: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..n]);
    }
    assert!(got.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&got));
    drop(s);
    wait_workspace_idle(&vm).await;
    let inbox = vm.disk(&format!("{VM_HOME}/.cache/ai-env/inbox"));
    assert!(vm.inbox_is_empty(), "{:?}", std::fs::read_dir(&inbox).map(|d| d.flatten().map(|e| e.file_name()).collect::<Vec<_>>()));
}

/// A refusal the helper gives before it read the pack (a clone into a
/// directory that is not empty: 409 `path_occupied`) still reaches the
/// client of a body larger than the socket buffers: the shim reads the
/// rest of the body past the helper's exit (five rounds, none lost).
#[tokio::test]
async fn a_helper_refusal_still_reads_the_rest_of_the_body() {
    let vm = Vm::new().await;
    write_file(&vm.ws().join("the-agents.txt"), "the agent's\n");
    let (m, _) = clone_body(&vm.mac(), Some("main"));
    let mut body = head_line(&m).unwrap();
    body.resize(body.len() + (8 << 20), b'P');
    let path = format!("/seed?path={WS}&mode=clone&branch=main");
    let mut lost = Vec::new();
    for i in 0..5 {
        match try_http_with(vm.s.code, "PUT", &path, &bearer_header(TOKEN), &body).await {
            Ok((st, _, b)) => assert!(st == 409 && b.contains("\"path_occupied\""), "#{i}: {st} {b}"),
            Err(e) => lost.push(format!("#{i}: {e}")),
        }
    }
    assert!(lost.is_empty(), "answers lost to a reset: {lost:#?}");
}

/// A helper that cannot start (no such program) is a 500 `git_failed` the
/// client of a body larger than the socket buffers still reads: the shim
/// reads the body first (five rounds, none lost). The seed is the one route
/// that takes such a body since the S3 cut-over took S8's `PUT
/// /transcript`: S9's transfers take JSON of at most
/// `TRANSFER_REQUEST_MAX`, read whole before any helper starts.
#[tokio::test]
async fn a_helper_that_cannot_start_still_reads_the_body() {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    std::fs::create_dir_all(root.join("vm/Users/agent")).unwrap();
    let o = ShimOpts { fs_root: Some(root.join("vm")), home: root.join("vm/Users/agent"), helper: Some(root.join("no-such-helper")), git: git_real().to_path_buf(), ..opts(None, HookSource::Log, 0) };
    let s = stack(o).await;
    s.run(true).await;
    let body = vec![b'x'; 8 << 20];
    let mut lost = Vec::new();
    for (addr, path) in [(s.code, format!("/seed?path={WS}&mode=clone&branch=main"))] {
        for i in 0..5 {
            match try_http_with(addr, "PUT", &path, &bearer_header(TOKEN), &body).await {
                Ok((st, _, b)) => assert!(st == 500 && b.contains("\"git_failed\""), "{path} #{i}: {st} {b}"),
                Err(e) => lost.push(format!("{path} #{i}: {e}")),
            }
        }
    }
    assert!(lost.is_empty(), "answers lost to a reset: {lost:#?}");
}

/// The transcript route checks a rel itself, before any helper starts (the
/// helper's own check is a second guard, `wshelper`'s): a traversal is 400
/// `bad_request` even from a shim whose helper cannot start, where a rel the
/// route passes on is 500 `git_failed` (phase 4's mutation check, M53).
#[tokio::test]
async fn a_traversal_rel_is_refused_before_any_helper_starts() {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    std::fs::create_dir_all(root.join("vm/Users/agent")).unwrap();
    let o = ShimOpts { fs_root: Some(root.join("vm")), home: root.join("vm/Users/agent"), helper: Some(root.join("no-such-helper")), git: git_real().to_path_buf(), ..opts(None, HookSource::Log, 0) };
    let s = stack(o).await;
    s.run(true).await;
    for rel in [format!("../{S8_ID}.jsonl"), format!("{S8_SLUG}/../{S8_ID}.jsonl"), format!("{S8_SLUG}/{S8_ID}/../../x/{S8_ID}.jsonl")] {
        let (st, _, b) = request(s.app, "GET", &format!("/transcript?rel={rel}"), "", None).await;
        assert_eq!((st, refusal_of(&b).code.as_str()), (400, "bad_request"), "{rel}: the route's own refusal");
    }
    // A rel the route passes on meets the missing helper: the 400s above were the route's.
    let (st, _, b) = request(s.app, "GET", &format!("/transcript?rel={S8_SLUG}/{S8_ID}.jsonl"), "", None).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (500, "git_failed"));
}

/// The helper runs as the agent: a code-out head announcing more than the
/// request's `max_bytes` is refused, 413 `too_large` with its size, and
/// never streamed; the helper is ended and the workspace free again.
#[tokio::test]
async fn a_codeout_longer_than_asked_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    std::fs::create_dir_all(root.join("vm/Users/agent")).unwrap();
    let head = "a".repeat(40);
    let manifest = CodeoutManifest { v: SeedManifest::V, object_format: ObjectFormat::Sha1, refs: BTreeMap::from([("refs/heads/main".to_string(), head.clone())]), head: head.clone(), branch: Some("main".into()), wip_ref: None, wip_skipped: None };
    let line = String::from_utf8(head_line(&HelperHead::ok(manifest, Some(5000))).unwrap()).unwrap();
    let helper = root.join("helper");
    std::fs::write(&helper, format!("#!/bin/sh\n[ \"$1\" = warm ] && exit 0\nprintf '%s' '{line}'\nhead -c 5000 /dev/zero\n")).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Command::new(&helper).arg("warm").status().unwrap().success());
    let o = ShimOpts { fs_root: Some(root.join("vm")), home: root.join("vm/Users/agent"), helper: Some(helper), git: git_real().to_path_buf(), ..opts(None, HookSource::Log, 0) };
    let s = stack(o).await;
    s.run(true).await;
    let record = SeedRecord { path: WS.into(), mode: ai_env_cli::wire::workspace::SeedMode::Clone, branch: Some("main".into()), head, wip: None, wip_tree: None, index_tree: None, object_format: ObjectFormat::Sha1, at: "2026-10-12T08:00:00Z".into() };
    s.state.workspace.set_record(record);
    let req = serde_json::json!({"path": WS, "haves": [], "wip": false, "max_bytes": 1000}).to_string();
    let (st, _, b) = request(s.code, "POST", "/codeout", "", Some(req.as_bytes())).await;
    let r = refusal_of(&b);
    assert!(st == 413 && r.code == "too_large" && r.size == Some(5000), "{st} {r:?}");
    let view = s.detail().await.0.workspace.expect("a workspace view");
    assert_eq!((view.helpers, view.busy), (0, None));
}

/// The record a seed leaves is the one `GET /seed` and the detail report,
/// and it is shaped as the wire freezes it.
#[tokio::test]
async fn the_seed_record_is_kept_in_memory() {
    let vm = Vm::new().await;
    let m = vm.clone_mac().await;
    let record: SeedRecord = vm.s.state.workspace.record().expect("recorded");
    assert_eq!((record.path.as_str(), record.head.as_str(), record.branch.as_deref(), record.object_format), (WS, m.head.as_str(), Some("main"), ObjectFormat::Sha1));
    assert_eq!(vm.state().await.record, Some(record.clone()));
    assert_eq!(vm.workspace_view().await.seed, Some(record));
}

// ---- phase 4 F9 ----
//
// S8 phase 4's review, FIDELITY-2: an update never resets the VM's checkout
// (the design's T8.1 `reseed_never_resets_hard`). Plan §6: "a CAS ref update
// and a two-way checkout, rolling back on failure"; git's two-way merge
// refuses to overwrite a change of the agent's, a reset discards it.

/// `<root>/editing-git`: the real git, and once armed ([`arm_edit`]) the
/// agent's edit, once: right after the first `update-ref --stdin` that
/// succeeds (an update's or a replace's compare-and-swap, past the shim's
/// clean check and before the checkout moves), `<root>/edit.body` is written
/// over the VM's file `<root>/edit.path` names, as another session's CLI on
/// the VM may write while an update runs (D5: the probe and the chat share
/// one VM). Absolute paths only: the helper runs git with no environment.
/// Run once first (macOS assesses a new executable at its first exec).
fn editing_git(root: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("editing-git");
    let q = |p: PathBuf| format!("'{}'", p.display());
    let (arm, done, target, body) = (q(root.join("edit.arm")), q(root.join("edit.done")), q(root.join("edit.path")), q(root.join("edit.body")));
    let script = format!(
        "#!/bin/sh\n'{}' \"$@\"\nrc=$?\nref=0\nfed=0\nfor a in \"$@\"; do\n  case \"$a\" in\n    update-ref) ref=1 ;;\n    --stdin) fed=1 ;;\n  esac\ndone\nif [ \"$rc\" = 0 ] && [ \"$ref$fed\" = 11 ] && [ -e {arm} ] && [ ! -e {done} ]; then\n  : > {done}\n  /bin/cat {body} > \"$(/bin/cat {target})\"\nfi\nexit \"$rc\"\n",
        git_real().display()
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Command::new(&path).arg("--version").stdout(Stdio::null()).status().unwrap().success());
    path
}

/// Arm [`editing_git`] of `root`: its one edit writes `body` over `file`.
fn arm_edit(root: &Path, file: &Path, body: &str) {
    std::fs::write(root.join("edit.path"), file.display().to_string()).unwrap();
    std::fs::write(root.join("edit.body"), body).unwrap();
    std::fs::write(root.join("edit.arm"), "").unwrap();
}

/// Whether a git argv overwrites what the worktree holds: a hard reset,
/// `read-tree --reset -u`, a forced checkout, `restore`, `clean`.
fn discards(args: &[String]) -> bool {
    let has = |a: &str| args.iter().any(|x| x == a);
    (has("reset") && (has("--hard") || has("--merge")))
        || (has("read-tree") && has("--reset") && has("-u"))
        || ((has("checkout") || has("checkout-index")) && (has("-f") || has("--force")))
        || has("restore")
        || has("clean")
}

/// The design's `reseed_never_resets_hard`, from the shim's git argv: an
/// update (D3's fast-forward, the new WIP applied) and a replace of the
/// pristine VM it left move the checkout by two-way merges (`read-tree -m
/// -u`), never by anything that discards a change of the agent's. Only the
/// clone, into an empty directory, resets.
#[tokio::test]
async fn an_update_and_a_replace_never_reset_the_checkout() {
    let vm = Vm::with_fake_git().await;
    let mac = vm.mac();
    let seed = vm.clone_mac().await;
    let log = vm.root.join("git.log");
    let cloned = git_log(&log).len();
    assert!(git_log(&log).iter().any(|(_, _, a)| discards(a)), "the clone resets its new checkout: the check sees a reset");
    write_file(&mac.join("a.txt"), "four\n");
    git(&mac, &["commit", "-q", "-am", "c3"]);
    write_file(&mac.join("wip.txt"), "the Mac's uncommitted file\n");
    let (m, body) = update_body(&mac, &seed, &seed.head, &seed.head);
    let (st, b) = vm.seed(&format!("path={WS}&mode=update&branch=main&expect={}", seed.head), &body).await;
    assert_eq!((st, json(&b)["outcome"].as_str()), (201, Some("updated")), "{}", String::from_utf8_lossy(&b));
    let updated = git_log(&log).len();
    std::fs::remove_file(mac.join("wip.txt")).unwrap();
    write_file(&mac.join("a.txt"), "five\n");
    git(&mac, &["commit", "-q", "-am", "c4"]);
    let (_, body) = clone_body(&mac, Some("main"));
    let (st, b) = vm.seed(&format!("path={WS}&mode=replace&branch=main&expect={}", m.head), &body).await;
    assert_eq!((st, json(&b)["outcome"].as_str()), (201, Some("replaced")), "{}", String::from_utf8_lossy(&b));
    let calls: Vec<Vec<String>> = git_log(&log).into_iter().map(|(_, _, a)| a).collect();
    let resets: Vec<&Vec<String>> = calls[cloned..].iter().filter(|a| discards(a)).collect();
    assert!(resets.is_empty(), "an update or a replace reset the checkout: {resets:?}");
    let two_way = |calls: &[Vec<String>]| calls.iter().any(|a| ["read-tree", "-m", "-u"].iter().all(|w| a.iter().any(|x| x == w)));
    assert!(two_way(&calls[cloned..updated]) && two_way(&calls[updated..]), "each moved the checkout by a two-way merge: {:?}", &calls[cloned..]);
}

/// D3's update never discards the agent's work: an edit made in the VM's
/// checkout while an update runs (past the shim's clean check and its
/// compare-and-swap), to a file the update changes, makes git's two-way
/// checkout refuse: 409 `dirty`, the edit kept, the refs and the shallow
/// boundary back where they were. A replace of a pristine VM alike (409
/// `not_pristine`).
#[tokio::test]
async fn an_edit_made_while_an_update_runs_is_never_discarded() {
    for (mode, code) in [("update", "dirty"), ("replace", "not_pristine")] {
        let vm = Vm::with(editing_git).await;
        let mac = vm.mac();
        let seed = vm.clone_mac().await;
        let ws = vm.ws();
        let shallow = std::fs::read_to_string(ws.join(".git/shallow")).unwrap();
        write_file(&mac.join("a.txt"), "four\n");
        git(&mac, &["commit", "-q", "-am", "c3"]);
        let body = if mode == "update" { update_body(&mac, &seed, &seed.head, &seed.head).1 } else { clone_body(&mac, Some("main")).1 };
        arm_edit(&vm.root, &ws.join("a.txt"), "the agent's edit\n");
        let (st, b) = vm.seed(&format!("path={WS}&mode={mode}&branch=main&expect={}", seed.head), &body).await;
        assert!(vm.root.join("edit.done").exists(), "{mode}: the agent's edit landed while it ran");
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "the agent's edit\n", "{mode}: the agent's edit, made while it ran, was discarded ({st}: {})", String::from_utf8_lossy(&b));
        assert_eq!((st, refusal_of(&b).code.as_str()), (409, code), "{mode}");
        assert_eq!((git(&ws, &["rev-parse", "HEAD"]), git(&ws, &["rev-parse", SEED_REF])), (seed.head.clone(), seed.head.clone()), "{mode}: the refs back");
        assert_eq!(std::fs::read_to_string(ws.join(".git/shallow")).unwrap(), shallow, "{mode}: the shallow boundary back");
        assert_eq!(git_status(&ws), [" M a.txt"], "{mode}");
        assert!(vm.inbox_is_empty(), "{mode}");
    }
}

/// The same on the WIP's step: an update whose own move leaves a file alone
/// but whose new WIP changes it meets the agent's edit there. The WIP does
/// not apply (409 `dirty`); the rollback puts back what the update moved
/// (the refs, the head's checkout), never the agent's file.
#[tokio::test]
async fn an_edit_the_new_wip_meets_is_never_discarded_either() {
    let vm = Vm::with(editing_git).await;
    let mac = vm.mac();
    let seed = vm.clone_mac().await;
    let ws = vm.ws();
    write_file(&mac.join("a.txt"), "four\n");
    git(&mac, &["commit", "-q", "-am", "c3"]);
    write_file(&mac.join("d/b.txt"), "the Mac's uncommitted change\n");
    let (_, body) = update_body(&mac, &seed, &seed.head, &seed.head);
    arm_edit(&vm.root, &ws.join("d/b.txt"), "the agent's edit\n");
    let (st, b) = vm.seed(&format!("path={WS}&mode=update&branch=main&expect={}", seed.head), &body).await;
    assert!(vm.root.join("edit.done").exists(), "the agent's edit landed while it ran");
    assert_eq!(std::fs::read_to_string(ws.join("d/b.txt")).unwrap(), "the agent's edit\n", "the agent's edit, made while it ran, was discarded ({st}: {})", String::from_utf8_lossy(&b));
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "dirty"));
    assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "three\n", "the update's own move put back");
    assert_eq!((git(&ws, &["rev-parse", "HEAD"]), git(&ws, &["rev-parse", SEED_REF])), (seed.head.clone(), seed.head.clone()), "the refs back");
    assert_eq!(git_status(&ws), [" M d/b.txt"]);
}

// ---- S9: git smart-HTTP on the code port (G1) ------------------------------------------------
//
// `shim::gitcgi`'s routes through the S8 section's in-process shim: its
// helper this build's `ai-env shim-io git-cgi`, the real `git http-backend`
// behind it (through tests/fakes/git.sh where a test reads the log), §1.3's
// checks in their order. `shim::gitcgi`'s own tests drive the router with a
// scripted helper.

use ai_env_cli::wire::workspace::{GIT_RECEIVE_PACK_REFUSAL, GIT_RECEIVE_PACK_ROUTE, GIT_UPLOAD_PACK_ROUTE, NO_SUCH_ROUTE};

/// The advertisement's literal route and query (S9 §1.2).
const GIT_ADVERTISE: &str = "/workspace.git/info/refs?service=git-upload-pack";
/// A v2 `ls-refs` request: its command, the delimiter, the flush.
const LS_REFS: &[u8] = b"0014command=ls-refs\n00010000";
const UPLOAD_PACK_TYPE: &str = "Content-Type: application/x-git-upload-pack-request\r\n";

/// A chunked body's bytes, and whether it ended with its last chunk.
fn dechunk(raw: &[u8]) -> (Vec<u8>, bool) {
    let (mut rest, mut body) = (raw, Vec::new());
    loop {
        let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") else { return (body, false) };
        let size = usize::from_str_radix(std::str::from_utf8(&rest[..nl]).unwrap().trim(), 16).unwrap();
        rest = &rest[nl + 2..];
        if size == 0 {
            return (body, rest == b"\r\n");
        }
        if rest.len() < size + 2 {
            return (body, false);
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

/// The fake git's log under `FAKE_GIT_ENV_ALL=1`: per call, its uid, every
/// name it started with, its arguments.
fn git_log_all(log: &Path) -> Vec<(u32, Vec<String>, Vec<String>)> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            let mut f = l.split('\t');
            let uid = f.next().and_then(|u| u.strip_prefix("uid=")).and_then(|u| u.parse().ok()).unwrap_or_else(|| panic!("no uid in {l}"));
            let env = f.next().and_then(|e| e.strip_prefix("env=")).unwrap_or_else(|| panic!("no env in {l}"));
            let _fds = f.next();
            (uid, env.split(',').filter(|n| *n != "-").map(str::to_string).collect(), f.map(str::to_string).collect())
        })
        .collect()
}

/// On a seeded VM, an upload-pack `POST` whose body is chunked, or that
/// names no length at all, is 411 `bad_request` before any helper starts
/// (no git runs); the same request with its length is answered.
#[tokio::test]
async fn a_chunked_upload_pack_post_is_411() {
    let vm = Vm::with_fake_git().await;
    vm.clone_mac().await;
    let log = vm.root.join("git.log");
    let before = git_log(&log).len();
    let bearer = bearer_header(TOKEN);
    let chunked = format!("POST {GIT_UPLOAD_PACK_ROUTE} HTTP/1.1\r\nHost: x\r\n{bearer}{UPLOAD_PACK_TYPE}Git-Protocol: version=2\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n14\r\n0014command=ls-refs\n\r\n8\r\n00010000\r\n0\r\n\r\n");
    let lengthless = format!("POST {GIT_UPLOAD_PACK_ROUTE} HTTP/1.1\r\nHost: x\r\n{bearer}{UPLOAD_PACK_TYPE}Git-Protocol: version=2\r\nConnection: close\r\n\r\n");
    for raw in [chunked, lengthless] {
        let mut s = tokio::net::TcpStream::connect(vm.s.code).await.unwrap();
        s.write_all(raw.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), s.read_to_end(&mut buf)).await.expect("an answer within 20 s").unwrap();
        let (st, _, b) = split_response(&buf);
        assert_eq!((st, refusal_of(b.as_bytes()).code.as_str()), (411, "bad_request"), "{raw}");
    }
    assert_eq!(git_log(&log).len(), before, "no helper started: no git ran");
    let (st, head, raw) = request(vm.s.code, "POST", GIT_UPLOAD_PACK_ROUTE, &format!("{UPLOAD_PACK_TYPE}Git-Protocol: version=2\r\n"), Some(LS_REFS)).await;
    assert_eq!(st, 200, "{head}");
    let (body, complete) = dechunk(&raw);
    assert!(complete && String::from_utf8_lossy(&body).contains(" refs/heads/main"), "{}", String::from_utf8_lossy(&body));
}

/// On a VM never seeded both git routes are 409 `not_seeded` (a POST's
/// body read first) and start no helper (no git runs); receive-pack is 403
/// whatever the state; once seeded, the advertisement answers.
#[tokio::test]
async fn git_routes_on_an_unseeded_vm_are_409() {
    let vm = Vm::with_fake_git().await;
    let log = vm.root.join("git.log");
    let v2 = "Git-Protocol: version=2\r\n".to_string();
    for (method, path, extra, body) in [("GET", GIT_ADVERTISE, v2.clone(), None), ("POST", GIT_UPLOAD_PACK_ROUTE, format!("{UPLOAD_PACK_TYPE}{v2}"), Some(LS_REFS))] {
        let (st, _, b) = request(vm.s.code, method, path, &extra, body).await;
        assert_eq!((st, refusal_of(&b).code.as_str()), (409, "not_seeded"), "{method} {path}");
    }
    let receive = [("POST", GIT_RECEIVE_PACK_ROUTE), ("GET", "/workspace.git/info/refs?service=git-receive-pack")];
    for (method, path) in receive {
        let (st, _, b) = request(vm.s.code, method, path, "", Some(b"0000")).await;
        assert_eq!((st, b.as_slice()), (403, GIT_RECEIVE_PACK_REFUSAL.as_bytes()), "{method} {path}");
    }
    assert!(git_log(&log).is_empty(), "no helper started: {:?}", git_log(&log));
    vm.clone_mac().await;
    let (st, head, raw) = request(vm.s.code, "GET", GIT_ADVERTISE, &v2, None).await;
    assert_eq!(st, 200, "{head}");
    let (body, complete) = dechunk(&raw);
    assert!(complete && body.starts_with(b"000eversion 2\n"), "{}", String::from_utf8_lossy(&body));
    for (method, path) in receive {
        let (st, _, b) = request(vm.s.code, method, path, "", Some(b"0000")).await;
        assert_eq!((st, b.as_slice()), (403, GIT_RECEIVE_PACK_REFUSAL.as_bytes()), "seeded: {method} {path}");
    }
}

/// End to end through this build's helper and the real http-backend: the
/// advertisement (v2 and v0) and an `ls-refs` answer 200, chunked, with the
/// CGI's four headers only; a real git client clones the VM's workspace
/// through the code port, the bearer its one credential (a header of its
/// own); every http-backend run started with exactly `GitRun::vm`'s names
/// and its request's CGI names, as the helper's uid, behind the CGI's
/// overrides, and no git saw a bearer, a credential carrier or a URL.
#[tokio::test]
async fn a_real_git_clones_the_workspace_through_the_code_port() {
    let vm = Vm::with_fake_git().await;
    let knobs = vm.root.join("vm-git.knobs");
    let all = std::fs::read_to_string(&knobs).unwrap() + "export FAKE_GIT_ENV_ALL='1'\n";
    std::fs::write(&knobs, all).unwrap();
    let seed = vm.clone_mac().await;
    let v2 = "Git-Protocol: version=2\r\n";
    let (st, head, raw) = request(vm.s.code, "GET", GIT_ADVERTISE, v2, None).await;
    assert_eq!(st, 200, "{head}");
    let head = head.to_ascii_lowercase();
    for want in ["\r\ncontent-type: application/x-git-upload-pack-advertisement\r\n", "\r\ncache-control: no-cache", "\r\nexpires: ", "\r\npragma: no-cache\r\n", "\r\ntransfer-encoding: chunked\r\n"] {
        assert!(head.contains(want), "{want:?} in {head}");
    }
    assert!(!head.contains("content-length"), "{head}");
    let (body, complete) = dechunk(&raw);
    assert!(complete && body.starts_with(b"000eversion 2\n"), "{}", String::from_utf8_lossy(&body));
    let (st, _, raw) = request(vm.s.code, "GET", GIT_ADVERTISE, "", None).await;
    assert!(st == 200 && dechunk(&raw).0.starts_with(b"001e# service=git-upload-pack\n0000"), "v0: {st} {}", String::from_utf8_lossy(&raw));
    let (st, _, raw) = request(vm.s.code, "POST", GIT_UPLOAD_PACK_ROUTE, &format!("{UPLOAD_PACK_TYPE}{v2}"), Some(LS_REFS)).await;
    let listed = String::from_utf8_lossy(&dechunk(&raw).0).into_owned();
    assert!(st == 200 && listed.contains(&format!("{} refs/heads/main", seed.head)), "{st} {listed}");
    let dest = vm.root.join("cloned");
    let out = tokio::process::Command::new(git_real())
        .args(["-c", &format!("http.extraHeader=Authorization: Bearer {TOKEN}"), "clone", "-q", &format!("http://{}/workspace.git", vm.s.code)])
        .arg(&dest)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &vm.root)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .await
        .unwrap();
    assert!(out.status.success(), "the clone: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(git(&dest, &["rev-parse", "HEAD"]), seed.head, "the VM's commit came out");
    let calls = git_log_all(&vm.root.join("git.log"));
    let backend: Vec<&(u32, Vec<String>, Vec<String>)> = calls.iter().filter(|(_, _, args)| args.last().map(String::as_str) == Some("http-backend")).collect();
    assert!(backend.len() >= 6, "three requests here, three or more for the clone: {}", backend.len());
    let overrides = ["-c", "http.receivepack=false", "-c", "http.getanyfile=false", "-c", "http.uploadpack=true", "http-backend"];
    let (uid, _) = uid_gid();
    for (u, names, args) in &backend {
        let mut want = vec!["GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "HOME", "LC_ALL", "PATH", "GIT_HTTP_EXPORT_ALL", "GIT_PROJECT_ROOT", "PATH_INFO", "QUERY_STRING", "REMOTE_ADDR", "REQUEST_METHOD"];
        if names.iter().any(|n| n == "CONTENT_LENGTH") {
            want.extend(["CONTENT_LENGTH", "CONTENT_TYPE"]);
        }
        want.extend(["HTTP_GIT_PROTOCOL", "HTTP_CONTENT_ENCODING"].into_iter().filter(|o| names.iter().any(|n| n == o)));
        want.sort_unstable();
        assert_eq!(names, &want, "{args:?}");
        assert_eq!(*u, uid, "the helper's uid");
        assert_eq!(args[args.len() - overrides.len()..], overrides, "{args:?}");
    }
    assert!(backend.iter().any(|(_, n, _)| !n.iter().any(|x| x == "HTTP_GIT_PROTOCOL")) && backend.iter().any(|(_, n, _)| n.iter().any(|x| x == "CONTENT_LENGTH")), "a v0 GET and a POST among them");
    for (_, names, args) in &calls {
        let carrier = |n: &String| ["HTTP_AUTHORIZATION", "REMOTE_USER", "HTTP_COOKIE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"].contains(&n.as_str()) || n.starts_with("GIT_CONFIG_KEY_") || n.starts_with("GIT_CONFIG_VALUE_") || n.starts_with("HTTP_X_AWS");
        assert!(!names.iter().any(carrier), "{names:?}");
        assert!(!args.iter().any(|a| a.contains(TOKEN) || a.contains("Bearer") || a.contains("://")), "{args:?}");
    }
}

/// A gzip upload-pack request cut inside its request passes every check of
/// the route (gzip is an allowed encoding), and the real http-backend's own
/// die exits 0 once its head is out: the helper fails such a run, so the
/// 200's chunked body ends without its last chunk and never looks complete.
#[tokio::test]
async fn a_gzip_request_cut_short_never_looks_complete() {
    let vm = Vm::new().await;
    vm.clone_mac().await;
    // A final stored block that announces 110 bytes and holds the request's first 10.
    let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 1];
    gz.extend(110u16.to_le_bytes().into_iter().chain((!110u16).to_le_bytes()));
    gz.extend_from_slice(&LS_REFS[..10]);
    let (st, head, raw) = request(vm.s.code, "POST", GIT_UPLOAD_PACK_ROUTE, &format!("{UPLOAD_PACK_TYPE}Content-Encoding: gzip\r\nGit-Protocol: version=2\r\n"), Some(&gz)).await;
    assert_eq!(st, 200, "{head}");
    let (body, complete) = dechunk(&raw);
    assert!(body.is_empty() && !complete, "{}", String::from_utf8_lossy(&raw));
}

// ---- S10: the park (`park_v1`), the persisted seed record, the suspend's work, the guest's memory ----
//
// plans/s10-contracts.md §1.2, §1.5, §6.4. The park's spawns run in a fresh
// home (`spawning_stack`). Natively the busy check is its stdio part (the
// CPU sampler is Linux's), so a park here asks a window of 0 unless the
// window is what the test is about.

use ai_env_cli::wire::frame::{Chunk, ParkOwner, ParkRefusal, SpawnDetail, CAP_PARK_V1, PARK_GRACE_MAX_S};

/// The wrapper every park here names (the golden's: a pid and a start in October 2026).
const PARK_OWNER: ParkOwner = ParkOwner { pid: 51_234, started: 1_792_483_200 };

/// A `park` of `id`: its grace, its busy-check window, 500 ms of CPU a sample, stdout not held.
fn park_frame(id: &SpawnId, grace_s: u32, min_quiet_s: u32) -> Frame {
    Frame::Park { spawn_id: id.clone(), grace_s, min_quiet_s, cpu_busy_ms: 500, hold_output: false, owner: PARK_OWNER }
}

/// Send `frame` (a `park`) and read its answer; the socket's spawns' frames before it are passed over.
async fn park(w: &mut Ws, frame: &Frame) -> Frame {
    send_frame(w, frame).await;
    loop {
        match next_frame(w).await {
            Ok(f @ (Frame::Parked { .. } | Frame::ParkRefused { .. })) => return f,
            Ok(f) if f.spawn_id().is_some() => {}
            other => panic!("the park's answer, got {other:?}"),
        }
    }
}

/// A `ping` and its `pong`; the socket's spawns' frames before it are passed over.
async fn pong_past(w: &mut Ws, ts: u64) {
    send_frame(w, &Frame::Ping { ts }).await;
    loop {
        match next_frame(w).await {
            Ok(Frame::Pong { ts: got }) if got == ts => return,
            Ok(f) if f.spawn_id().is_some() => {}
            other => panic!("the pong of {ts}, got {other:?}"),
        }
    }
}

/// Is `frame` the `parked` of `id`?
fn parked(frame: &Frame, id: &SpawnId) -> bool {
    matches!(frame, Frame::Parked { spawn_id, .. } if spawn_id == id)
}

/// A refusal's reason.
fn refusal(frame: Frame) -> ParkRefusal {
    match frame {
        Frame::ParkRefused { reason, .. } => reason,
        other => panic!("park_refused, got {other:?}"),
    }
}

/// `id`'s `/health/detail` entry.
async fn spawn_detail(s: &Stack, id: &SpawnId) -> SpawnDetail {
    let (d, _) = s.detail().await;
    d.spawns.into_iter().find(|sp| sp.status.spawn_id == *id).unwrap_or_else(|| panic!("{id} is not in /health/detail"))
}

/// `id`'s detail once it satisfies `done`, within `secs`.
async fn wait_detail(s: &Stack, id: &SpawnId, secs: u64, what: &str, done: impl Fn(&SpawnDetail) -> bool) -> SpawnDetail {
    let until = Instant::now() + Duration::from_secs(secs);
    loop {
        let d = spawn_detail(s, id).await;
        if done(&d) {
            return d;
        }
        assert!(Instant::now() < until, "{what}: not within {secs} s: {d:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Until `cond` holds, within `secs`.
async fn wait_for(secs: u64, what: &str, mut cond: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(secs);
    while !cond() {
        assert!(Instant::now() < until, "{what}: not within {secs} s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// tests/fixtures/wire/park-golden.jsonl against the shim (S10 §1.6): the
/// Mac's lines are sent as written but for the session token (this rig's)
/// and the busy-check window of every park after the first (0 here, so the
/// replay waits no 30 s), each `hello` on a socket of its own; each VM line
/// is matched with the newest socket's next frame by its kind and its
/// spawn, and by what the shim cannot vary: `park_v1` named, the resume
/// `ok`, the acks' seqs and the bytes, the pong's ts, `procs` 0 (`cat` runs
/// alone), the exit's seq and code. The first park is refused by the busy
/// check: the golden's `busy` is what Linux's sampler says of a busy
/// session; the check takes the stdio part first, and the turn's a moment
/// ago makes it `output` here. The shim's re-ack of the written stdin on the
/// new socket (a reattach acks again what was written, S6) is no golden
/// line: taken and passed over. The spawn's detail names the park's owner
/// exactly while it is parked: the unpark (which has no answer) and the
/// resuming hello unpark it.
#[tokio::test]
async fn the_park_golden_replays_against_the_shim() {
    let (s, _home) = spawning_stack().await;
    let id = SpawnId("0192f1e0-2b7c-7c3a-9a1b-4d5e6f708196".into());
    let mut sockets: Vec<Ws> = Vec::new();
    let (mut parks, mut acked) = (0, 0);
    for (i, line) in include_str!("fixtures/wire/park-golden.jsonl").lines().enumerate() {
        let n = i + 1;
        let raw = line.split_once(",\"frame\":").and_then(|(_, f)| f.strip_suffix('}')).unwrap_or_else(|| panic!("line {n}: no frame"));
        let golden = Frame::from_json(raw).unwrap_or_else(|e| panic!("line {n}: {e}"));
        if line.starts_with("{\"dir\":\"mac\"") {
            let frame = match golden {
                Frame::Hello { client, resume, idle_s, .. } => {
                    sockets.push(ws(s.app).await);
                    Frame::Hello { session_token: Secret::new(TOKEN.into()), client, resume, idle_s }
                }
                Frame::Park { spawn_id, grace_s, min_quiet_s, cpu_busy_ms, hold_output, owner } => {
                    parks += 1;
                    Frame::Park { spawn_id, grace_s, min_quiet_s: if parks == 1 { min_quiet_s } else { 0 }, cpu_busy_ms, hold_output, owner }
                }
                other => other,
            };
            send_frame(sockets.last_mut().expect("a hello first"), &frame).await;
            continue;
        }
        let w = sockets.last_mut().expect("a socket");
        let got = loop {
            match next_frame(w).await.unwrap_or_else(|e| panic!("line {n}: the socket ended ({e:?})")) {
                // The re-ack of a new attachment, no golden line.
                Frame::StdinAck { seq, .. } if !matches!(golden, Frame::StdinAck { .. }) && seq == acked => {}
                f => break f,
            }
        };
        assert_eq!((got.kind(), got.spawn_id()), (golden.kind(), golden.spawn_id()), "line {n}: {got:?}");
        match (&golden, &got) {
            (Frame::HelloOk { resumed: want, .. }, Frame::HelloOk { caps, resumed, .. }) => {
                assert!(caps.iter().any(|c| c == CAP_PARK_V1), "line {n}: {caps:?}");
                assert_eq!(resumed, want, "line {n}");
                if !resumed.is_empty() {
                    assert_eq!(spawn_detail(&s, &id).await.parked, None, "line {n}: the resuming hello unparked it");
                }
            }
            (Frame::Spawned { .. }, Frame::Spawned { .. }) => {}
            (Frame::StdinAck { seq: want, .. }, Frame::StdinAck { seq, .. }) => {
                assert_eq!(seq, want, "line {n}");
                acked = *seq;
            }
            (Frame::Stdout { seq: want, data: bytes, .. }, Frame::Stdout { seq, data, .. }) => {
                assert_eq!((seq, ai_env_cli::wire::chunk::decode(data).unwrap()), (want, ai_env_cli::wire::chunk::decode(bytes).unwrap()), "line {n}");
            }
            (Frame::ParkRefused { reason: ParkRefusal::Busy, .. }, Frame::ParkRefused { reason, procs, .. }) => {
                assert_eq!((*reason, *procs), (ParkRefusal::Output, 0), "line {n}: the turn's stdio a moment ago");
            }
            (Frame::Parked { .. }, Frame::Parked { procs, .. }) => {
                assert_eq!(*procs, 0, "line {n}: cat runs alone");
                assert_eq!(spawn_detail(&s, &id).await.parked, Some(PARK_OWNER), "line {n}: its owner named");
            }
            (Frame::Pong { ts: want }, Frame::Pong { ts }) => {
                assert_eq!(ts, want, "line {n}");
                assert_eq!(spawn_detail(&s, &id).await.parked, None, "line {n}: the unpark before the ping");
            }
            (Frame::Exit { seq: want, code: c, .. }, Frame::Exit { seq, code, .. }) => assert_eq!((seq, code), (want, c), "line {n}"),
            (want, got) => panic!("line {n}: no check of {} for {got:?}", want.kind()),
        }
    }
    assert_eq!(parks, 3, "the golden's three parks");
    wait_for(5, "the exit's ack releases the spawn", || s.state.spawns.status(None).is_empty()).await;
}

/// A park answers `parked` (its quiet, the processes but the leader) and
/// sets the park grace: the spawn keeps its socket (no grace runs while it
/// is attached; its owner is named), and when that socket goes the grace is
/// the park's, not the detach grace; a park again takes the new grace. The
/// Mac's own `detach` unparks first: its detach grace is the spawn's own.
#[tokio::test]
async fn a_park_sets_the_park_grace() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/sleep", "60"], Some(60)).await;
    match park(&mut w, &park_frame(&id, 1200, 0)).await {
        Frame::Parked { spawn_id, quiet_s, procs: 0 } if spawn_id == id => assert!(quiet_s < 5, "{quiet_s}"),
        other => panic!("parked, got {other:?}"),
    }
    let d = spawn_detail(&s, &id).await;
    assert!(d.status.alive && d.detach_left_s.is_none() && d.parked == Some(PARK_OWNER), "parked, its socket kept: {d:?}");
    assert!(parked(&park(&mut w, &park_frame(&id, 2400, 0)).await, &id), "parked again, on new terms");
    drop(w);
    let d = wait_detail(&s, &id, 5, "the park grace", |d| d.detach_left_s.is_some()).await;
    let left = d.detach_left_s.unwrap_or_default();
    assert!((2390..=2400).contains(&left) && d.parked == Some(PARK_OWNER) && !d.frozen, "the park grace, not the 60 s detach grace: {d:?}");
    let mut w = ws_hello_ok(s.app).await;
    let mine = SpawnId::new_v7();
    start(&mut w, &mine, &["/bin/sleep", "60"], Some(60)).await;
    assert!(parked(&park(&mut w, &park_frame(&mine, 1200, 0)).await, &mine));
    send_frame(&mut w, &Frame::Detach { spawn_id: mine.clone(), is_final: false }).await;
    let d = wait_detail(&s, &mine, 5, "the detach grace", |d| d.detach_left_s.is_some()).await;
    assert!(d.detach_left_s.is_some_and(|left| left <= 60) && d.parked.is_none(), "the Mac's detach unparked it first: {d:?}");
    s.state.spawns.shutdown("test").await;
}

/// The busy check's refusals, each named (S10 §1.2), and none of them
/// parks: a grace of 0 or past `PARK_GRACE_MAX_S`, a window past an hour,
/// or a spawn whose leader exited, `other`; another socket's spawn (or
/// none at all), `not_attached`; stdout not acked, `unacked`; stdio within
/// the window, `output`, with the quiet so far.
#[tokio::test]
async fn park_refusals_name_their_reason() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/cat"], Some(60)).await;
    for (grace_s, min_quiet_s) in [(0, 0), (PARK_GRACE_MAX_S + 1, 0), (600, 3601)] {
        assert_eq!(refusal(park(&mut w, &park_frame(&id, grace_s, min_quiet_s)).await), ParkRefusal::Other, "grace {grace_s}, window {min_quiet_s}");
    }
    let mut other = ws_hello_ok(s.app).await;
    assert_eq!(refusal(park(&mut other, &park_frame(&id, 600, 0)).await), ParkRefusal::NotAttached, "another socket's");
    assert_eq!(refusal(park(&mut other, &park_frame(&SpawnId::new_v7(), 600, 0)).await), ParkRefusal::NotAttached, "no such spawn");
    send_frame(&mut w, &Frame::Stdin { spawn_id: id.clone(), seq: 1, data: Chunk { text: Some("x\n".into()), b64: None } }).await;
    let out = loop {
        match next_frame(&mut w).await {
            Ok(Frame::Stdout { seq, .. }) => break seq,
            Ok(_) => {}
            Err(e) => panic!("cat's line: {e:?}"),
        }
    };
    assert_eq!(refusal(park(&mut w, &park_frame(&id, 600, 0)).await), ParkRefusal::Unacked, "its line not acked");
    send_frame(&mut w, &Frame::Ack { spawn_id: id.clone(), seq: out, err_seq: 0 }).await;
    match park(&mut w, &park_frame(&id, 600, 30)).await {
        Frame::ParkRefused { reason: ParkRefusal::Output, quiet_s, procs: 0, .. } => assert!(quiet_s < 30, "{quiet_s}"),
        other => panic!("output, got {other:?}"),
    }
    assert_eq!(spawn_detail(&s, &id).await.parked, None, "no refusal parks");
    let gone = SpawnId::new_v7();
    start(&mut w, &gone, &["/bin/echo", "gone"], Some(60)).await;
    wait_for(5, "echo's exit", || s.state.spawns.status(None).iter().any(|st| st.spawn_id == gone && !st.alive)).await;
    assert_eq!(refusal(park(&mut w, &park_frame(&gone, 600, 0)).await), ParkRefusal::Other, "a leader gone");
    s.state.spawns.shutdown("test").await;
}

/// `/health/detail` names a parked spawn's owner (`SpawnDetail.parked`:
/// the wrapper's pid and start) and leaves the key out for one not parked.
/// An `unpark` takes it away (no answer: the ping's pong is the next
/// frame), and so does any frame for the spawn on its socket (`stdin`).
#[tokio::test]
async fn health_detail_names_a_parked_spawns_owner() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let (a, b) = (SpawnId::new_v7(), SpawnId::new_v7());
    start(&mut w, &a, &["/bin/cat"], Some(60)).await;
    start(&mut w, &b, &["/bin/sleep", "60"], Some(60)).await;
    assert!(parked(&park(&mut w, &park_frame(&a, 1200, 0)).await, &a));
    let (d, body) = s.detail().await;
    let of = |id: &SpawnId| d.spawns.iter().find(|sp| sp.status.spawn_id == *id).map(|sp| sp.parked);
    assert_eq!((of(&a), of(&b)), (Some(Some(PARK_OWNER)), Some(None)));
    assert!(body.contains("\"parked\":{\"pid\":51234,\"started\":1792483200}") && body.matches("\"parked\"").count() == 1, "{body}");
    send_frame(&mut w, &Frame::Unpark { spawn_id: a.clone() }).await;
    ping(&mut w, 1).await;
    assert_eq!(spawn_detail(&s, &a).await.parked, None, "unparked");
    assert!(parked(&park(&mut w, &park_frame(&a, 1200, 0)).await, &a));
    send_frame(&mut w, &Frame::Stdin { spawn_id: a.clone(), seq: 1, data: Chunk { text: Some("x\n".into()), b64: None } }).await;
    // Its stdin_ack (and cat's line) may come first.
    pong_past(&mut w, 2).await;
    assert_eq!(spawn_detail(&s, &a).await.parked, None, "a frame for it unparks it");
    s.state.spawns.shutdown("test").await;
}

/// `hold_output` (B0's fallback): while parked, the spawn's stdout waits in
/// its window, read but not sent (and its exit after it); the unpark sends both.
#[tokio::test]
async fn a_park_holding_output_sends_it_at_the_unpark() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/sh", "-c", "sleep 1; echo held"], Some(60)).await;
    let hold = Frame::Park { spawn_id: id.clone(), grace_s: 600, min_quiet_s: 0, cpu_busy_ms: 500, hold_output: true, owner: PARK_OWNER };
    assert!(parked(&park(&mut w, &hold).await, &id));
    wait_detail(&s, &id, 10, "the line read and the leader gone", |d| d.status.out_seq == 1 && !d.status.alive).await;
    ping(&mut w, 1).await;
    send_frame(&mut w, &Frame::Unpark { spawn_id: id.clone() }).await;
    match next_frame(&mut w).await {
        Ok(Frame::Stdout { spawn_id, seq: 1, data }) if spawn_id == id => assert_eq!(ai_env_cli::wire::chunk::decode(&data).unwrap(), b"held\n"),
        other => panic!("the held line at the unpark, got {other:?}"),
    }
    assert!(matches!(next_frame(&mut w).await, Ok(Frame::Exit { spawn_id, code: Some(0), .. }) if spawn_id == id), "then its exit");
}

/// A parked spawn whose socket goes lives its park grace, not its detach
/// grace, and stays parked (its owner named) with no socket; a hello
/// resuming it unparks it and attaches it again (no grace runs), and when
/// that socket goes too its grace is its detach grace again.
#[tokio::test]
async fn a_lost_parked_socket_uses_the_park_grace() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/sleep", "60"], Some(30)).await;
    assert!(parked(&park(&mut w, &park_frame(&id, 900, 0)).await, &id));
    drop(w);
    let d = wait_detail(&s, &id, 5, "the park grace", |d| d.detach_left_s.is_some()).await;
    assert!(d.detach_left_s.is_some_and(|left| (890..=900).contains(&left)) && d.parked == Some(PARK_OWNER) && !d.status.attached, "{d:?}");
    let mut b = ws(s.app).await;
    send_frame(&mut b, &hello_resuming(TOKEN, vec![ResumePoint { spawn_id: id.clone(), from_seq: None, err_from_seq: None }])).await;
    match next_frame(&mut b).await {
        Ok(Frame::HelloOk { resumed, .. }) => assert_eq!(resumed, [Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }]),
        other => panic!("hello_ok, got {other:?}"),
    }
    let d = spawn_detail(&s, &id).await;
    assert!(d.detach_left_s.is_none() && d.parked.is_none(), "unparked, attached: {d:?}");
    drop(b);
    let d = wait_detail(&s, &id, 5, "the detach grace", |d| d.detach_left_s.is_some()).await;
    assert!(d.detach_left_s.is_some_and(|left| left <= 30) && d.parked.is_none(), "{d:?}");
    s.state.spawns.shutdown("test").await;
}

/// The park grace freezes and thaws as every grace does: parked with 2 s,
/// `/suspend` closes the socket and the grace starts frozen, so nothing
/// ends the spawn while the VM is suspended; `/resume` thaws it and the
/// whole grace then runs out (TERM).
#[tokio::test]
async fn the_park_grace_freezes_and_thaws() {
    let (s, _home) = spawning_stack().await;
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/sleep", "60"], Some(60)).await;
    assert!(parked(&park(&mut w, &park_frame(&id, 2, 0)).await, &id));
    let (answer, ()) = tokio::join!(hook(s.hooks, "suspend", b"{}"), async { while next_frame(&mut w).await.is_ok() {} });
    assert_eq!(answer.0, 200, "{}", answer.1);
    let d = wait_detail(&s, &id, 5, "the frozen park grace", |d| d.detach_left_s.is_some()).await;
    assert!(d.frozen && d.detach_left_s == Some(2) && d.parked == Some(PARK_OWNER), "{d:?}");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(s.state.spawns.live(), 1, "frozen: alive past its 2 s");
    let t = Instant::now();
    assert_eq!(hook(s.hooks, "resume", b"{}").await.0, 200);
    wait_for(6, "the TERM after the thawed grace", || s.state.spawns.live() == 0).await;
    let took = t.elapsed();
    assert!(took >= Duration::from_millis(1800) && took < Duration::from_millis(3800), "the whole grace after /resume, then TERM: {took:?}");
}

/// A park grace that runs out with no socket ends the spawn as a detach
/// grace does: TERM to its group (its trap leaves the mark), KILL 2 s
/// later; its record goes (its exit is nobody's).
#[tokio::test]
async fn an_expired_park_grace_sends_term() {
    let (s, home) = spawning_stack().await;
    let mark = std::fs::canonicalize(home.path()).unwrap().join("term");
    let script = format!("trap \"echo term > '{}'; exit 0\" TERM; sleep 600 & wait", mark.display());
    let mut w = ws_hello_ok(s.app).await;
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/sh", "-c", &script], Some(600)).await;
    assert!(parked(&park(&mut w, &park_frame(&id, 1, 0)).await, &id));
    let t = Instant::now();
    drop(w);
    wait_for(6, "the TERM's mark", || mark.exists()).await;
    let took = t.elapsed();
    assert!(took >= Duration::from_millis(900) && took < Duration::from_millis(3500), "its 1 s park grace, then TERM: {took:?}");
    wait_for(6, "the spawn's end", || s.state.spawns.live() == 0).await;
    wait_for(6, "its record released", || s.state.spawns.status(None).is_empty()).await;
}

/// A parked socket's idle timer is off: after `parked` its idle deadline
/// is `PARKED_IDLE_MAX`, so it outlives several of its `idle_s`, and any
/// inbound frame brings `idle_s` back (1001 then). The spawn, still parked
/// (a ping is no frame for it), then lives its park grace. One `idle_s`
/// second is 20 ms here (`AgentRegistry::set_idle_unit`): 30 are 600 ms.
#[tokio::test]
async fn a_parked_sockets_idle_timer_is_off() {
    let (s, _home) = spawning_stack().await;
    s.state.agents.set_idle_unit(Duration::from_millis(20));
    let mut w = ws(s.app).await;
    send_frame(&mut w, &Frame::Hello { session_token: Secret::new(TOKEN.into()), client: ClientInfo { name: "shim_local".into(), version: "0.0.1".into(), host: "test@host".into() }, resume: vec![], idle_s: Some(30) }).await;
    assert!(matches!(next_frame(&mut w).await, Ok(Frame::HelloOk { .. })));
    let id = SpawnId::new_v7();
    start(&mut w, &id, &["/bin/sleep", "60"], Some(60)).await;
    assert!(parked(&park(&mut w, &park_frame(&id, 600, 0)).await, &id));
    tokio::time::sleep(Duration::from_millis(2000)).await;
    ping(&mut w, 1).await;
    let quiet = Instant::now();
    assert_eq!(next_frame(&mut w).await, Err(Some(CLOSE_GOING_AWAY)), "idle_s again since the ping");
    assert!(quiet.elapsed() < Duration::from_millis(1800), "{:?}", quiet.elapsed());
    let d = wait_detail(&s, &id, 5, "the park grace", |d| d.detach_left_s.is_some()).await;
    assert!(d.parked == Some(PARK_OWNER) && d.detach_left_s.is_some_and(|left| (590..=600).contains(&left)), "{d:?}");
    s.state.spawns.shutdown("test").await;
}

impl Vm {
    /// The same VM's shim started again (S10, W3 #2): a new state and new
    /// listeners on the same disk, `/run` done.
    async fn restarted(&self) -> Stack {
        let o = ShimOpts { fs_root: Some(self.root.join("vm")), home: self.root.join("vm/Users/agent"), helper: Some(PathBuf::from(bin())), git: self.s.state.opts.git.clone(), ..opts(None, HookSource::Log, 0) };
        let s = stack(o).await;
        s.run(true).await;
        s
    }
}

/// S10 (W3 #2): the record a seed leaves is kept in the VM's
/// `/var/lib/ai-env/seed-record.json` (under the fs root here), 0600 in a
/// 0700 directory, `{"v":1,"record":…}`. A shim started again on the same
/// disk (a restart: a new state, new listeners) has it from the start:
/// `GET /seed` reads the VM seeded and pristine, `/health/detail` names
/// it, and the Mac's next commit goes in as an update, its record kept in
/// the file in place of the first.
#[tokio::test]
async fn the_seed_record_survives_a_shim_restart() {
    use std::os::unix::fs::PermissionsExt as _;
    let vm = Vm::new().await;
    let seed = vm.clone_mac().await;
    let record = vm.s.state.workspace.record().expect("recorded");
    let file = vm.disk(ai_env_cli::shim::asagent::SEED_RECORD_PATH);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{{\"v\":1,\"record\":{}}}\n", serde_json::to_string(&record).unwrap()));
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(file.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    let again = vm.restarted().await;
    assert_eq!(again.state.workspace.record(), Some(record.clone()), "the restarted shim's record");
    let (st, _, b) = request(again.code, "GET", &format!("/seed?path={WS}"), "", None).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let state: SeedState = serde_json::from_slice(&b).unwrap();
    assert!(state.pristine && state.record.as_ref() == Some(&record) && state.tip.as_deref() == Some(seed.head.as_str()), "{state:?}");
    assert_eq!(again.detail().await.0.workspace.and_then(|w| w.seed), Some(record));
    let mac = vm.mac();
    write_file(&mac.join("a.txt"), "after the restart\n");
    git(&mac, &["commit", "-q", "-am", "c3"]);
    let (m, body) = update_body(&mac, &seed, &seed.head, &seed.head);
    let (st, _, b) = request(again.code, "PUT", &format!("/seed?path={WS}&mode=update&branch=main&expect={}", seed.head), "", Some(&body)).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&b));
    let kept = again.state.workspace.record().expect("the update's record");
    assert_eq!((kept.head.as_str(), kept.mode), (m.head.as_str(), ai_env_cli::wire::workspace::SeedMode::Update));
    assert!(std::fs::read_to_string(&file).unwrap().contains(&m.head), "the file holds the update's record");
}

/// S10 (W3 #2): after a shim restart a clone into the workspace, whose
/// `.git` holds this VM's seed (the record kept on disk names it), counts as
/// seeded: 409 `changed` with that record's state (the Mac reads the state
/// again and updates), never S8's 409 `path_occupied`, and nothing in the
/// checkout moves. A record file that fails its checks is ignored: such a
/// restarted shim knows no seed, and the clone is `path_occupied` as before.
#[tokio::test]
async fn a_clone_into_a_matching_git_counts_as_seeded() {
    let vm = Vm::new().await;
    let seed = vm.clone_mac().await;
    let record = vm.s.state.workspace.record().expect("recorded");
    let again = vm.restarted().await;
    let (_, body) = clone_body(&vm.mac(), Some("main"));
    let clone = format!("/seed?path={WS}&mode=clone&branch=main");
    let (st, _, b) = request(again.code, "PUT", &clone, "", Some(&body)).await;
    let r = refusal_of(&b);
    assert!(st == 409 && r.code == "changed" && r.state.as_ref().and_then(|s| s.record.as_ref()) == Some(&record), "{st} {r:?}");
    assert_eq!(git(&vm.ws(), &["rev-parse", "HEAD"]), seed.head, "nothing moved");
    let file = vm.disk(ai_env_cli::shim::asagent::SEED_RECORD_PATH);
    let text = std::fs::read_to_string(&file).unwrap().replacen("{\"v\":1,", "{\"v\":2,", 1);
    std::fs::write(&file, text).unwrap();
    let blind = vm.restarted().await;
    assert_eq!(blind.state.workspace.record(), None, "a file of another version is ignored");
    let (st, _, b) = request(blind.code, "PUT", &clone, "", Some(&body)).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (409, "path_occupied"));
}

/// S10: `GET /seed` reports the VM's `.git/shallow` (`SeedState.shallow`):
/// after a first seed its one boundary, the head; at most
/// `SHALLOW_REPORT_MAX` ids; past the cap none (the Mac then takes its
/// row's list).
#[tokio::test]
async fn seed_state_reports_shallow_capped() {
    use ai_env_cli::wire::workspace::SHALLOW_REPORT_MAX;
    let vm = Vm::new().await;
    let seed = vm.clone_mac().await;
    assert_eq!(vm.state().await.shallow, Some(vec![seed.head.clone()]));
    let shallow = vm.ws().join(".git/shallow");
    let mut ids: Vec<String> = (1..SHALLOW_REPORT_MAX).map(|n| format!("{n:040x}")).collect();
    ids.push(seed.head.clone());
    ids.sort();
    std::fs::write(&shallow, ids.iter().map(|id| format!("{id}\n")).collect::<String>()).unwrap();
    assert_eq!(vm.state().await.shallow, Some(ids.clone()), "the cap itself");
    std::fs::write(&shallow, format!("{}{:040x}\n", ids.iter().map(|id| format!("{id}\n")).collect::<String>(), SHALLOW_REPORT_MAX)).unwrap();
    assert_eq!(vm.state().await.shallow, None, "past the cap");
}

/// S10 (W3 #11): `/suspend`'s snapshot is a task of its own the hook
/// awaits: a hook client that goes while it runs (its request dropped, as
/// S8's snapshot was with it, its helper killed before its ref) leaves it
/// running, and the `refs/wip/*` ref is made all the same. The helper's git
/// is slowed at the snapshot's `write-tree`, so the client goes mid-run.
#[tokio::test]
async fn the_suspend_work_finishes_when_the_hook_client_goes() {
    let vm = Vm::with(|root| slow_git(root, "write-tree", 2)).await;
    vm.clone_mac().await;
    let ws = vm.ws();
    write_file(&ws.join("a.txt"), "uncommitted at suspend\n");
    let mut c = tokio::net::TcpStream::connect(vm.s.hooks).await.unwrap();
    c.write_all(format!("POST {PREFIX}/suspend HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}").as_bytes()).await.unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    while vm.workspace_view().await.busy.as_deref() != Some("snapshot") {
        assert!(Instant::now() < until, "the snapshot never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(c);
    let until = Instant::now() + Duration::from_secs(30);
    let wip = loop {
        let refs = git(&ws, &["for-each-ref", "--format=%(refname)", "refs/wip/"]);
        if !refs.is_empty() {
            break refs;
        }
        assert!(Instant::now() < until, "no refs/wip/* after the hook client went");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(git(&ws, &["show", &format!("{}:a.txt", wip.trim())]), "uncommitted at suspend");
    wait_workspace_idle(&vm).await;
}

/// S10 (W3 #11), the order of `/suspend`: the sockets hear of it and close
/// only once its snapshot and tail push are done (or past their bound):
/// the `hook_suspend` event a socket gets comes after the `refs/wip/*` ref
/// exists, the helper's git slowed 2 s at the snapshot's `write-tree`. (A
/// socket closed first would let the Mac's suspend go on while the VM's
/// snapshot still runs.)
#[tokio::test]
async fn suspend_closes_the_sockets_after_its_snapshot() {
    let vm = Vm::with(|root| slow_git(root, "write-tree", 2)).await;
    vm.clone_mac().await;
    let ws = vm.ws();
    write_file(&ws.join("a.txt"), "uncommitted at suspend\n");
    let mut w = ws_hello_ok(vm.s.app).await;
    let started = Instant::now();
    let (answer, (event, heard, wip)) = tokio::join!(hook(vm.s.hooks, "suspend", b"{}"), async {
        let event = loop {
            match tokio::time::timeout(Duration::from_secs(30), w.next()).await.expect("the suspend's event within 30 s") {
                Some(Ok(Message::Text(t))) => break Frame::from_json(t.as_str()).unwrap_or_else(|e| panic!("{e}")),
                Some(Ok(_)) => {}
                other => panic!("the socket ended before the suspend's event: {other:?}"),
            }
        };
        (event, started.elapsed(), git(&ws, &["for-each-ref", "--format=%(refname)", "refs/wip/"]))
    });
    assert_eq!(answer.0, 200, "{}", answer.1);
    assert!(matches!(event, Frame::Event { kind: EventKind::HookSuspend, .. }), "{event:?}");
    assert_eq!(wip.lines().count(), 1, "the snapshot's ref was there when the socket heard of the suspend ({heard:?} in): {wip:?}");
    assert!(heard >= Duration::from_secs(2), "heard of only after the slowed snapshot: {heard:?}");
    wait_workspace_idle(&vm).await;
}

/// S10: the guest's memory (§1.5). `/health` and `/health/detail` carry
/// `mem_total_mib`, `MemTotal` read once at start (`TestSys`'s
/// `/proc/meminfo`: 8040964 kB, 7852 MiB, last in the document); a machine
/// without the file leaves it out. The run report carries `mem_total_kb`
/// and `mem_available_kb` from `<root>/proc/meminfo` (a planted tree: the
/// binary's report on the Mac is the portable twin), `null` when unreadable.
#[tokio::test]
async fn the_run_report_and_health_carry_mem_total() {
    let s = Stack::log().await;
    let (st, _, body) = http(s.app, "GET", "/health", b"", None).await;
    assert_eq!(st, 200, "{body}");
    assert!(serde_json::from_str::<Health>(&body).unwrap().mem_total_mib == Some(7852) && body.ends_with(",\"mem_total_mib\":7852}"), "{body}");
    s.run(true).await;
    let (d, body) = s.detail().await;
    assert!(d.health.mem_total_mib == Some(7852) && body.contains("\"mem_total_mib\":7852"), "{body}");
    let machine = ShimState::new("/nonexistent/claude".into());
    assert_eq!(machine.health().await.mem_total_mib.is_some(), cfg!(target_os = "linux"), "this machine's own /proc/meminfo");
    let t = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(t.path().join("proc")).unwrap();
    std::fs::write(t.path().join("proc/meminfo"), MEMINFO).unwrap();
    let id = "microvm-00000000-0000-4000-8000-000000000010";
    let r = ai_env_cli::shim::sys::read_report(t.path(), "run", Some(id));
    assert_eq!((r["mem_total_kb"].as_u64(), r["mem_available_kb"].as_u64(), r["microvm_id"].as_str()), (Some(8_040_964), Some(7_703_512), Some(id)), "{r}");
    std::fs::remove_file(t.path().join("proc/meminfo")).unwrap();
    let r = ai_env_cli::shim::sys::read_report(t.path(), "terminate", None);
    assert!(r["mem_total_kb"].is_null() && r["mem_available_kb"].is_null(), "{r}");
}

/// S10 (§13): `--cold-warm read` reads the claude binary through once, in
/// the background, right after the first `/run` it accepts (its size and
/// path logged); without the flag (`off`, the image's ENTRYPOINT) nothing
/// is read.
#[test]
fn the_cold_warm_read_reads_the_claude_binary_after_run() {
    let t = tempfile::tempdir().unwrap();
    let claude = fake_claude(t.path(), "");
    let size = std::fs::metadata(&claude).unwrap().len();
    let run = format!("{PREFIX}/run");
    for (extra, warms) in [(&["--cold-warm", "read"][..], true), (&[][..], false)] {
        let shim = Shim::start(&claude, extra);
        let hooks_addr = shim.addr("hooks");
        assert_eq!(http_sync_body(hooks_addr, "POST", &run, &run_body("microvm-00000000-0000-4000-8000-000000000011", Some(&payload_json("mike@mbp")))).0, 200);
        shim.wait_line(10, |l| l.starts_with("ai-env: run-report "));
        if warms {
            let line = shim.wait_line(10, |l| l.starts_with("ai-env: cold-warm read "));
            assert!(line.starts_with(&format!("ai-env: cold-warm read {size} bytes of {} in ", claude.display())), "{line}");
        } else {
            std::thread::sleep(Duration::from_millis(300));
            assert!(!shim.lines.lock().unwrap().iter().any(|l| l.contains("cold-warm")), "off: no warm");
        }
    }
}

/// S10's gates in image/Dockerfile (§1.7, §6.4): right after the claude
/// binary's hash, every string the moved chat relies on (the cut's flag and
/// its miss, `wire::claude::CUT_MISS_MARKER`; a fresh chat's flag and its
/// refusal), each a build failure naming it; after the shim, the seed
/// record's directory, root's and 0700, and the gate that the image bakes
/// no record in. The ENTRYPOINT passes no `--cold-warm` (off). S11 (A §2.7):
/// after the record's gate and before the ENTRYPOINT, the claude cache's:
/// `/opt/ai-env/claude` root's, 0755 and empty (no claude baked into the
/// cache; its index lives under the record's directory, which stays empty).
#[test]
fn the_image_gates_the_claude_strings_and_bakes_no_seed_record() {
    let df = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../image/Dockerfile")).unwrap();
    let at = |what: &str| df.find(what).unwrap_or_else(|| panic!("{what} missing from image/Dockerfile"));
    let (hash, gate, chmod) = (at("sha256sum --check --strict;"), at("for want in "), at("chmod 0755 /usr/local/bin/claude;"));
    assert!(hash < gate && gate < chmod, "the strings gate right after the hash");
    let line = df[gate..].lines().next().unwrap_or_default();
    for want in ["--resume-session-at", ai_env_cli::wire::claude::CUT_MISS_MARKER, "--session-id", "is already in use"] {
        assert!(line.contains(&format!(" '{want}'")), "{want} in {line}");
    }
    assert!(df[gate..chmod].contains("grep -qaF -e \"$want\" /usr/local/bin/claude || { echo \"claude ${CLAUDE_VERSION} lacks the string S10 relies on: $want\"; exit 1; }"));
    let (shim, dir, empty) = (at("COPY ai-env /usr/local/bin/ai-env"), at("install -d -m 0700 -o 0 -g 0 /var/lib/ai-env;"), at("test -z \"$(find /var/lib/ai-env -mindepth 1 -print -quit)\""));
    assert!(shim < dir && dir < empty && at("ENTRYPOINT ") > empty, "the record's gate after the shim");
    assert!(ai_env_cli::shim::asagent::SEED_RECORD_PATH.starts_with("/var/lib/ai-env/"));
    assert!(!entrypoint().iter().any(|w| w.starts_with("--cold-warm")), "the warm is off in the image");
    let (cache, owned, baked, said) = (
        at("install -d -m 0755 -o 0 -g 0 /opt/ai-env /opt/ai-env/claude;"),
        at("test \"$(stat -c '%u:%g %a' /opt/ai-env/claude)\" = \"0:0 755\""),
        at("test -z \"$(find /opt/ai-env/claude -mindepth 1 -print -quit)\" || { echo \"a claude is baked into the cache: $(ls -A /opt/ai-env/claude)\"; exit 1; }"),
        at("echo \"claude-cache gate: /opt/ai-env/claude root 0755, empty\""),
    );
    assert!(empty < cache && cache < owned && owned < baked && baked < said && said < at("ENTRYPOINT "), "the cache's gate after the record's, before the ENTRYPOINT");
    assert!(!df[empty..cache].contains("\nENTRYPOINT ") && !df[cache..said].contains("\nRUN "), "one RUN of its own after the record's");
    assert_eq!(ai_env_cli::shim::claudebin::CACHE_DIR, "/opt/ai-env/claude");
    assert!(ai_env_cli::shim::claudebin::INDEX_PATH.starts_with("/var/lib/ai-env/"), "the cache's index under the record's directory, which the image keeps empty");
}

// ---- S11 phase 0 (part C): curl decodes gzip, the fake curl's encoding, the encoded-part refusal ----

/// S11 (C.3.8): the curl gate in the block that makes `ai-env-net` also
/// requires libz (a gzip-staged transcript is pulled with curl's
/// `compressed`): after the 7.84 check, the `Features:` line read and its
/// `libz` case, then the gate's echo; the fake curl's `--version` lists it.
#[test]
fn the_image_gates_curl_on_libz() {
    let df = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../image/Dockerfile")).unwrap();
    let at = |what: &str| df.find(what).unwrap_or_else(|| panic!("{what} missing from image/Dockerfile"));
    let user = at("useradd --system --uid 999 --gid 999");
    let run = df[..user].rfind("\nRUN ").expect("the RUN that makes ai-env-net");
    let check = at("the transcript transfers need 7.84 or later");
    let features = at("features=$(curl --version | while IFS= read -r line; do case $line in (Features:*) echo \"${line#Features:}\";; esac; done);");
    let libz = at("case \" $features \" in *\" libz \"*) ;; *) echo \"curl lists no libz:$features (a gzip-staged transcript is pulled with curl's compressed)\"; exit 1;; esac;");
    let said = at("echo \"ai-env-net 999:999; curl $2 with https and libz\"");
    assert!(run < user && user < check && check < features && features < libz && libz < said, "the libz gate after the 7.84 check, before the echo");
    assert!(!df[run + 1..said].contains("\nRUN "), "in the block that makes ai-env-net");
    let fake = std::fs::read_to_string(curl::FAKE_CURL).unwrap();
    assert!(fake.lines().any(|l| l.contains("echo \"Features:") && l.split_whitespace().any(|w| w == "libz")), "the fake curl's --version lists libz");
}

/// S11 (C.3.9): the fake curl's `S3CURL_ENCODING=gzip` serves its GET bodies
/// as gzip streams stored with `Content-Encoding: gzip`: a configuration
/// with a `compressed` line gets them decoded, one without as stored, as
/// curl does; unset, the bodies go as they are, `compressed` or not.
#[test]
fn the_fake_curl_decodes_gzip_only_with_compressed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let (fake, log) = (root.join("curl"), root.join("curl.log"));
    let plain = b"{\"n\":1}\n{\"n\":2}\n".to_vec();
    std::fs::write(root.join("plain"), &plain).unwrap();
    let gz = Command::new("/usr/bin/gzip").args(["-n", "-6", "-c"]).arg(root.join("plain")).output().unwrap();
    assert!(gz.status.success() && gz.stdout.starts_with(&[0x1f, 0x8b]), "gzip: {}", String::from_utf8_lossy(&gz.stderr));
    let stored = root.join("stored.gz");
    std::fs::write(&stored, &gz.stdout).unwrap();
    // The shim's call: the configuration on fd 3 alone, an environment of PATH and LC_ALL.
    let run = |compressed: bool| {
        let config = root.join("config.in");
        let mut lines = vec!["url = \"https://example.invalid/v1/k\"".to_string(), "request = \"GET\"".to_string()];
        if compressed {
            lines.push("compressed".to_string());
        }
        lines.extend(["fail".to_string(), "output = \"-\"".to_string()]);
        std::fs::write(&config, lines.join("\n") + "\n").unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("exec \"$0\" -q -K /dev/fd/3 3<\"$1\"").arg(&fake).arg(&config).env_clear().env("PATH", "/usr/bin:/bin").env("LC_ALL", "C").stdin(Stdio::null());
        curl::without_stray_fds(&mut cmd);
        let o = cmd.output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
        o.stdout
    };
    let body = stored.to_str().unwrap();
    curl::install_fake_curl(&fake, &log, &[("S3CURL_BODY", body), ("S3CURL_ENCODING", "gzip")]);
    assert_eq!(run(true), plain, "compressed: decoded");
    assert_eq!(run(false), gz.stdout, "without compressed: as stored");
    curl::install_fake_curl(&fake, &log, &[("S3CURL_BODY", body)]);
    assert_eq!(run(true), gz.stdout, "no encoding: as it is, compressed or not");
    assert_eq!(run(false), gz.stdout);
    let calls = curl::curl_calls(&log);
    assert_eq!(calls.iter().map(|c| c.conf("compressed").len()).collect::<Vec<_>>(), [1, 0, 1, 0], "{calls:?}");
}

/// S11 (C.3.2): while `shim::s3xfer::GZIP_SERVED` is false, a pull naming an
/// encoded part (a Mac object with its sha256, which `check()` lets through)
/// is refused before any curl runs: 400 `bad_request`, nothing written. Once
/// C1 serves gzip it returns at once (C1's own tests take over), so the flag's
/// flip needs no edit here.
#[tokio::test]
async fn a_shim_that_does_not_decode_refuses_an_encoded_part() {
    use ai_env_cli::wire::s3::{S3Key, SIGNED_HEADERS_GET};
    use ai_env_cli::wire::workspace::{PartEncoding, PullPart, TranscriptPull};
    if ai_env_cli::shim::s3xfer::GZIP_SERVED || !ai_env_cli::shim::s3xfer::SERVED {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    std::fs::create_dir_all(root.join("vm/Users/agent")).unwrap();
    let (fake, log) = (root.join("vm-curl"), root.join("curl-vm.log"));
    curl::install_fake_curl(&fake, &log, &[]);
    let o = ShimOpts { fs_root: Some(root.join("vm")), home: root.join("vm/Users/agent"), helper: Some(PathBuf::from(bin())), git: git_real().to_path_buf(), curl: fake.clone(), ..opts(None, HookSource::Log, 0) };
    let s = stack(o).await;
    s.run(true).await;
    let decoded = b"{\"n\":1}\n".to_vec();
    let digest = |b: &[u8]| {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(b))
    };
    let (sha, stored_sha) = (digest(decoded.as_slice()), digest(&b"the stored gzip bytes"[..]));
    let key = S3Key::Mac { session: S8_ID.into(), sha256: stored_sha.clone() }.render();
    let query = format!(
        "versionId=fv3&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261017%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261017T101530Z&X-Amz-Expires=300&X-Amz-SignedHeaders={}&X-Amz-Signature={}",
        SIGNED_HEADERS_GET.replace(';', "%3B"),
        digest(key.as_bytes())
    );
    // The store's bucket of S9's example account (transcript_s3's).
    let owner = transcript_s3::OWNER.to_string();
    let url = ai_env_cli::wire::s3::PresignedUrl::new(format!("https://ai-env-transcripts-{owner}.s3.eu-central-1.amazonaws.com/{key}?{query}")).unwrap();
    let rel = format!("{S8_SLUG}/{S8_ID}.jsonl");
    let pull = TranscriptPull { rel: rel.clone(), parts: vec![PullPart { url, len: decoded.len() as u64, sha256: Some(sha), encoding: Some(PartEncoding::Gzip) }], sha256: None, owner, proxy: None, share: 1 };
    pull.check().unwrap_or_else(|e| panic!("the pull itself is well formed: {e}"));
    let json = serde_json::to_vec(&pull).unwrap();
    let (st, _, body) = request(s.app, "POST", "/transcript/pull", "Content-Type: application/json\r\n", Some(&json)).await;
    assert_eq!(st, 400, "{}", String::from_utf8_lossy(&body));
    let refusal = refusal_of(&body);
    assert_eq!(refusal.code, "bad_request", "{refusal:?}");
    assert!(refusal.message.contains("the pull names an encoded part this shim does not decode"), "{refusal:?}");
    assert!(curl::curl_calls(&log).is_empty(), "no curl ran");
    assert!(!root.join("vm/Users/agent/.claude/projects").join(&rel).exists(), "nothing written");
}
