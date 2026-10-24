//! S11 part A (wave 1, A1): the VM's claude cache (`shim::claudebin`): `POST`
//! and `GET /claude/stage`, `POST /claude/relay`, a spawn's pick, `/validate`
//! V4, `/health/detail` and the run report, on native shims with an fs root
//! and S9's fake curl (`tests/fakes/s3-curl.sh`, which plays S3 and the
//! release alike). A staged binary is `fake_claude_bytes` (claude-v2.sh
//! reporting its version), or a small script ([`script`]) that prints its
//! PATH and then waits on stdin. The shim is not root here: the files keep
//! their modes, not their owners, and curl runs as the tests' own uid.
use super::curl::{curl_calls, fake_claude_bytes, install_fake_curl, CurlCall};
use super::transcript_s3::OWNER;
use super::{bin, deliver, dummy_value, fake_claude, git_real, http_sync_body, next_frame, opts, payload_json, plant_vm_tree, refusal_of, request, run_body, run_to_exit, send_frame, stack, validate_in, ws_hello_ok, HookSource, Shim, ShimOpts, Stack, Ws, PREFIX};
use ai_env_cli::wire::frame::{Deliver, Frame, SpawnId};
use ai_env_cli::wire::pin::{render_lock, ClaudePin};
use ai_env_cli::wire::s3::{sha256_b64, PresignedUrl, S3Key, SIGNED_HEADERS_GET, SIGNED_HEADERS_PUT};
use ai_env_cli::wire::workspace::{ClaudeCacheEntry, ClaudeRef, ClaudeRelay, ClaudeRelayReply, ClaudeSrc, ClaudeStage, ClaudeStageReply, ClaudeStageState, SeedRecord, TranscriptPush};
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const PROXY: &str = "http://10.42.0.10:3128";
/// The image's claude in these tests: `fake_claude` (claude-version.sh) prints it.
const IMAGE_VERSION: &str = "2.1.283";

fn sha(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// A presigned URL of the store for `key`, signed over `signed` (its signature made at run time).
fn url(key: &S3Key, signed: &str) -> PresignedUrl {
    let key = key.render();
    let sig = sha(key.as_bytes());
    let query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261023%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261023T101530Z&X-Amz-Expires=900&X-Amz-SignedHeaders={}&X-Amz-Signature={sig}",
        signed.replace(';', "%3B")
    );
    PresignedUrl::new(format!("https://ai-env-transcripts-{OWNER}.s3.eu-central-1.amazonaws.com/{key}?{query}")).unwrap()
}

/// A stage of `bytes` as claude `version` (their sha256 and length), through the proxy, waiting `wait_s`.
fn stage_of(version: &str, bytes: &[u8], wait_s: u32) -> ClaudeStage {
    let sha256 = sha(bytes);
    let url = url(&S3Key::Claude { version: version.into(), sha256: sha256.clone() }, SIGNED_HEADERS_GET);
    ClaudeStage { version: version.into(), sha256, size: bytes.len() as u64, url, owner: OWNER.into(), proxy: Some(PROXY.into()), wait_s }
}

fn of(s: &ClaudeStage) -> ClaudeRef {
    ClaudeRef { version: s.version.clone(), sha256: s.sha256.clone() }
}

/// A relay of `bytes` (the release of `version`) into its key.
fn relay_of(version: &str, bytes: &[u8]) -> ClaudeRelay {
    let sha256 = sha(bytes);
    let put = url(&S3Key::Claude { version: version.into(), sha256: sha256.clone() }, SIGNED_HEADERS_PUT);
    ClaudeRelay { version: version.into(), sha256, size: bytes.len() as u64, put, owner: OWNER.into() }
}

/// A claude that prints `<version> (Claude Code)` for `--version`, else its PATH and the `claude` a nested
/// call would run, then waits on stdin (`cat`).
fn script(version: &str) -> Vec<u8> {
    format!("#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{version} (Claude Code)'; exit 0; fi\necho \"path=$PATH\"\necho \"claude=$(command -v claude)\"\nexec cat\n").into_bytes()
}

fn reply(body: &[u8]) -> ClaudeStageReply {
    serde_json::from_slice(body).unwrap_or_else(|e| panic!("not a stage reply ({e}): {}", String::from_utf8_lossy(body)))
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())).permissions().mode() & 0o7777
}

/// The image's lock for `version` and `sha256`.
fn lock_of(version: &str, sha256: &str) -> String {
    render_lock(&ClaudePin { version: version.into(), platform: "linux-arm64".into(), sha256: sha256.into(), size: 240_902_136, build_date: "2026-09-25T01:39:37Z".into() }).unwrap()
}

/// The VM of these tests: the in-process shim (`/run` done) with an fs root (`<tmp>/vm`, so the cache has a
/// store), the image's empty `CACHE_DIR` (root 0755 in the image; here this user's), S9's fake curl.
struct Rig {
    s: Stack,
    o: ShimOpts,
    root: PathBuf,
    vm: PathBuf,
    curl: PathBuf,
    log: PathBuf,
    _tmp: tempfile::TempDir,
}

impl Rig {
    async fn new() -> Rig {
        Rig::with(None, false).await
    }

    /// With the image's lock (`version`, `sha256`) planted first, and the workspace helper when `helper`.
    async fn with(lock: Option<(&str, &str)>, helper: bool) -> Rig {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let vm = root.join("vm");
        std::fs::create_dir_all(vm.join("Users/agent")).unwrap();
        let cache = vm.join("opt/ai-env/claude");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap();
        if let Some((version, sha256)) = lock {
            std::fs::create_dir_all(vm.join("etc/ai-env")).unwrap();
            std::fs::write(vm.join("etc/ai-env/claude.lock"), lock_of(version, sha256)).unwrap();
        }
        let (curl, log) = (root.join("vm-curl"), root.join("curl-vm.log"));
        install_fake_curl(&curl, &log, &[]);
        let o = ShimOpts { fs_root: Some(vm.clone()), home: vm.join("Users/agent"), helper: helper.then(|| PathBuf::from(bin())), git: git_real().to_path_buf(), curl: curl.clone(), ..opts(None, HookSource::Log, 0) };
        let s = stack(o.clone()).await;
        s.run(true).await;
        Rig { s, o, root, vm, curl, log, _tmp: tmp }
    }

    /// The fake curl's knobs from now on (its log kept).
    fn knobs(&self, knobs: &[(&str, &str)]) {
        install_fake_curl(&self.curl, &self.log, knobs);
    }

    /// `bytes` as every GET's body from now on, with `more` knobs.
    fn serve(&self, bytes: &[u8], more: &[(&str, &str)]) {
        let object = self.root.join(format!("object-{}", &sha(bytes)[..12]));
        std::fs::write(&object, bytes).unwrap();
        let object = object.display().to_string();
        let mut knobs = vec![("S3CURL_BODY", object.as_str())];
        knobs.extend_from_slice(more);
        self.knobs(&knobs);
    }

    fn calls(&self) -> Vec<CurlCall> {
        curl_calls(&self.log)
    }

    async fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> (u16, Vec<u8>) {
        let json = serde_json::to_vec(body).unwrap();
        let (st, _, b) = request(self.s.app, "POST", path, "Content-Type: application/json\r\n", Some(&json)).await;
        (st, b)
    }

    async fn stage(&self, s: &ClaudeStage) -> (u16, Vec<u8>) {
        self.post("/claude/stage", s).await
    }

    /// `GET /claude/stage?sha256=`: 200 and its state.
    async fn state_of(&self, sha256: &str) -> ClaudeStageReply {
        let (st, _, b) = request(self.s.app, "GET", &format!("/claude/stage?sha256={sha256}"), "", None).await;
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
        reply(&b)
    }

    /// `bytes` staged as `version` (201): its ref.
    async fn fetch(&self, version: &str, bytes: &[u8]) -> ClaudeRef {
        self.serve(bytes, &[]);
        let s = stage_of(version, bytes, 30);
        let (st, b) = self.stage(&s).await;
        assert_eq!(st, 201, "{version}: {}", String::from_utf8_lossy(&b));
        of(&s)
    }

    fn cache(&self) -> PathBuf {
        self.vm.join("opt/ai-env/claude")
    }

    fn binary(&self, sha256: &str) -> PathBuf {
        self.cache().join(sha256).join("claude")
    }

    fn index(&self) -> PathBuf {
        self.vm.join("var/lib/ai-env/claude-index.json")
    }

    /// The index file's entries, in its order (most recently used first).
    fn indexed(&self) -> Vec<ClaudeCacheEntry> {
        let text = std::fs::read(self.index()).unwrap_or_else(|e| panic!("the index: {e}"));
        let v: serde_json::Value = serde_json::from_slice(&text).unwrap();
        assert_eq!(v["v"], 1, "{v}");
        serde_json::from_value(v["entries"].clone()).unwrap()
    }

    fn versions(&self) -> Vec<String> {
        self.indexed().into_iter().map(|e| e.version).collect()
    }

    /// What `.partial` holds.
    fn partials(&self) -> Vec<String> {
        std::fs::read_dir(self.cache().join(".partial")).map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default()
    }

    /// `script` as the VM's curl from now on, in place of S9's fake (written aside, then renamed in).
    fn own_curl(&self, script: &str) {
        let new = self.root.join("vm-curl.new");
        std::fs::write(&new, script).unwrap();
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&new, &self.curl).unwrap();
    }

    /// A shim restarted on the same VM disk (its cache's start-up runs), `/run` done.
    async fn restart(&self) -> Stack {
        let s = stack(self.o.clone()).await;
        s.run(true).await;
        s
    }
}

/// Spawn `argv` naming `refs` on `w`: its id and its `spawned`'s claude version and sha256.
async fn spawn_claude(w: &mut Ws, argv: &[&str], refs: Vec<ClaudeRef>) -> (SpawnId, Option<String>, Option<String>) {
    let id = SpawnId::new_v7();
    let spawn = Frame::Spawn { spawn_id: id.clone(), argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver_secret: Deliver::Fd, detach_grace_s: None, credential: None, claude: refs };
    send_frame(w, &spawn).await;
    match next_frame(w).await {
        Ok(Frame::Spawned { spawn_id, claude_version, claude_sha256, .. }) if spawn_id == id => (id, claude_version, claude_sha256),
        other => panic!("spawned, got {other:?}"),
    }
}

/// `id`'s stdout until it holds `want` (the spawn still runs).
async fn stdout_until(w: &mut Ws, id: &SpawnId, want: &str) -> String {
    let mut out = Vec::new();
    while !String::from_utf8_lossy(&out).contains(want) {
        match next_frame(w).await {
            Ok(Frame::Stdout { spawn_id, data, .. }) if spawn_id == *id => out.extend(ai_env_cli::wire::chunk::decode(&data).unwrap()),
            Ok(f) if f.spawn_id().is_some() => {}
            other => panic!("{id}'s stdout, got {other:?}"),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A fetch (§2.2): 201 ready from the cache with the bytes and the time; the
/// binary root-style 0555 in its 0755 directory, nothing left in `.partial`
/// (0700); the index names it; curl's configuration is S9's GET with the
/// proxy, the owner, `max-filesize` and `limit-rate` (no `compressed`). Asked
/// again: 200 from the cache, and no second curl; `GET` says ready.
#[tokio::test]
async fn claude_stage_fetches_then_answers_cached() {
    let rig = Rig::new().await;
    let bytes = fake_claude_bytes("2.1.399", None, &[]);
    rig.serve(&bytes, &[]);
    let s = stage_of("2.1.399", &bytes, 30);
    let (st, b) = rig.stage(&s).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&b));
    let r = reply(&b);
    assert_eq!((r.state, r.src, r.got_len, r.why.as_deref()), (ClaudeStageState::Ready, Some(ClaudeSrc::Cache), Some(bytes.len() as u64), None));
    assert!(r.ms.is_some(), "{r:?}");
    let binary = rig.binary(&s.sha256);
    assert_eq!(std::fs::read(&binary).unwrap(), bytes);
    assert_eq!((mode(&binary), mode(binary.parent().unwrap()), mode(&rig.cache().join(".partial"))), (0o555, 0o755, 0o700));
    assert!(rig.partials().is_empty(), "{:?}", rig.partials());
    let indexed = rig.indexed();
    assert_eq!(indexed.iter().map(|e| (e.version.as_str(), e.sha256.as_str(), e.size)).collect::<Vec<_>>(), [("2.1.399", s.sha256.as_str(), bytes.len() as u64)]);
    assert_eq!(mode(&rig.index()), 0o600);
    let calls = rig.calls();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!((call.conf("url"), call.conf("proxy"), call.conf("request")), (vec![s.url.expose().to_string()], vec![PROXY.to_string()], vec!["GET".to_string()]));
    assert_eq!((call.conf("max-filesize"), call.conf("limit-rate")), (vec![bytes.len().to_string()], vec!["32M".to_string()]));
    assert_eq!(call.conf("header"), [format!("x-amz-expected-bucket-owner: {OWNER}")]);
    assert!(call.conf("compressed").is_empty() && !call.conf("fail").is_empty(), "{}", call.config);
    assert_eq!(call.args, ["-q", "-K", "/dev/fd/3"], "the URL is on fd 3 only");
    let (st, b) = rig.stage(&s).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    assert_eq!(reply(&b), ClaudeStageReply { state: ClaudeStageState::Ready, src: Some(ClaudeSrc::Cache), why: None, got_len: None, got_sha256: None, ms: None });
    assert_eq!(rig.calls().len(), 1, "cached: no second curl");
    assert_eq!((rig.state_of(&s.sha256).await.state, rig.state_of(&"ef".repeat(32)).await.state), (ClaudeStageState::Ready, ClaudeStageState::Absent));
    let (st, _, b) = request(rig.s.app, "GET", "/claude/stage?sha256=AB", "", None).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (400, "bad_request"));
}

/// The image's own claude (LD-40): a stage naming the lock's version and
/// sha256 is 200 `image` at once, with no curl; `GET` says so too.
#[tokio::test]
async fn claude_stage_answers_image_for_the_locks_sha256() {
    let lock_sha = "cd".repeat(32);
    let rig = Rig::with(Some((IMAGE_VERSION, &lock_sha)), false).await;
    let url = url(&S3Key::Claude { version: IMAGE_VERSION.into(), sha256: lock_sha.clone() }, SIGNED_HEADERS_GET);
    let s = ClaudeStage { version: IMAGE_VERSION.into(), sha256: lock_sha.clone(), size: 240_902_136, url, owner: OWNER.into(), proxy: None, wait_s: 30 };
    let (st, b) = rig.stage(&s).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    assert_eq!((reply(&b).state, reply(&b).src), (ClaudeStageState::Ready, Some(ClaudeSrc::Image)));
    let r = rig.state_of(&lock_sha).await;
    assert_eq!((r.state, r.src), (ClaudeStageState::Ready, Some(ClaudeSrc::Image)));
    assert!(rig.calls().is_empty(), "nothing fetched");
    assert!(!rig.index().exists(), "nothing indexed");
}

/// A body with one byte flipped (S3 answered 200, curl ended cleanly): 422
/// `checksum_mismatch` with the length that came; nothing renamed, nothing
/// left in `.partial`; `GET` names the refusal and the sha256 of what came.
#[tokio::test]
async fn claude_stage_flipped_byte_is_422_nothing_renamed() {
    let rig = Rig::new().await;
    let bytes = fake_claude_bytes("2.1.399", None, &[]);
    let mut flipped = bytes.clone();
    let at = flipped.len() / 2;
    flipped[at] ^= 0x20;
    rig.serve(&flipped, &[]);
    let s = stage_of("2.1.399", &bytes, 30);
    let (st, b) = rig.stage(&s).await;
    let r = refusal_of(&b);
    assert_eq!((st, r.code.as_str(), r.size), (422, "checksum_mismatch", Some(bytes.len() as u64)), "{}", r.message);
    assert!(!rig.cache().join(&s.sha256).exists() && rig.partials().is_empty() && !rig.index().exists(), "nothing renamed: {:?}", rig.partials());
    let g = rig.state_of(&s.sha256).await;
    assert_eq!((g.state, g.why.as_deref(), g.got_len, g.got_sha256), (ClaudeStageState::Failed, Some("checksum_mismatch"), Some(bytes.len() as u64), Some(sha(&flipped))));
}

/// A body longer than the signed size: curl, told `max-filesize`, refuses it
/// on S3's Content-Length before the transfer (exit 63, nothing written: the
/// fake does as the real curl); 422 `checksum_mismatch` with 0 bytes come and
/// the sha256 of nothing, nothing installed.
#[tokio::test]
async fn claude_stage_cuts_an_oversized_body() {
    let rig = Rig::new().await;
    let bytes = fake_claude_bytes("2.1.399", None, &[]);
    let longer = [&bytes[..], &vec![b'#'; 70_000][..]].concat();
    rig.serve(&longer, &[]);
    let s = stage_of("2.1.399", &bytes, 30);
    let (st, b) = rig.stage(&s).await;
    let r = refusal_of(&b);
    assert_eq!((st, r.code.as_str(), r.size), (422, "checksum_mismatch", Some(0)), "{}", r.message);
    assert!(r.message.contains("stopped it at max-filesize"), "{}", r.message);
    assert!(!rig.cache().join(&s.sha256).exists() && rig.partials().is_empty(), "nothing installed");
    assert_eq!(rig.calls()[0].conf("max-filesize"), [bytes.len().to_string()]);
    let g = rig.state_of(&s.sha256).await;
    assert_eq!((g.state, g.why.as_deref(), g.got_len, g.got_sha256), (ClaudeStageState::Failed, Some("checksum_mismatch"), Some(0), Some(sha(b""))));
}

/// The right bytes of a binary that says another version: 422
/// `version_mismatch` after the probe, its directory removed, nothing indexed.
#[tokio::test]
async fn claude_stage_version_mismatch_removes_the_binary() {
    let rig = Rig::new().await;
    let bytes = fake_claude_bytes("2.1.398", None, &[]);
    rig.serve(&bytes, &[]);
    let s = stage_of("2.1.399", &bytes, 30);
    let (st, b) = rig.stage(&s).await;
    let r = refusal_of(&b);
    assert_eq!((st, r.code.as_str()), (422, "version_mismatch"), "{}", r.message);
    assert!(r.message.contains("2.1.398 (Claude Code)") && r.message.contains("removed"), "{}", r.message);
    assert!(!rig.cache().join(&s.sha256).exists() && rig.partials().is_empty() && !rig.index().exists());
    assert_eq!(rig.state_of(&s.sha256).await.why.as_deref(), Some("version_mismatch"));
}

/// Two requests for one binary at once join one fetch: one curl, both 201.
#[tokio::test]
async fn claude_stage_two_requests_one_curl() {
    let rig = Rig::new().await;
    let bytes = fake_claude_bytes("2.1.399", None, &[]);
    rig.serve(&bytes, &[("S3CURL_SLOW_MS", "1000")]);
    let s = stage_of("2.1.399", &bytes, 30);
    let ((a, ab), (b, bb)) = tokio::join!(rig.stage(&s), rig.stage(&s));
    assert_eq!((a, b), (201, 201), "{} | {}", String::from_utf8_lossy(&ab), String::from_utf8_lossy(&bb));
    assert_eq!(rig.calls().len(), 1, "one curl");
}

/// A wait shorter than the fetch: 202 `fetching`; the fetch goes on without
/// its client and `GET` turns `ready`; a second request then is 200 cached.
#[tokio::test]
async fn claude_stage_expired_wait_is_202_then_ready() {
    let rig = Rig::new().await;
    let bytes = fake_claude_bytes("2.1.399", None, &[]);
    rig.serve(&bytes, &[("S3CURL_SLOW_MS", "1500")]);
    let s = stage_of("2.1.399", &bytes, 0);
    let (st, b) = rig.stage(&s).await;
    assert_eq!(st, 202, "{}", String::from_utf8_lossy(&b));
    let r = reply(&b);
    assert_eq!((r.state, r.src), (ClaudeStageState::Fetching, None));
    assert!(r.got_len.is_some() && r.ms.is_some(), "{r:?}");
    assert_eq!(rig.state_of(&s.sha256).await.state, ClaudeStageState::Fetching);
    let until = Instant::now() + Duration::from_secs(20);
    while rig.state_of(&s.sha256).await.state != ClaudeStageState::Ready {
        assert!(Instant::now() < until, "never ready");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(rig.stage(&s).await.0, 200);
    assert_eq!(rig.calls().len(), 1);
}

/// LD-42: S3 answered 200 but curl was cut (its exit 18, half the body):
/// 500 `transfer_failed`, never `checksum_mismatch` (on a 422 the Mac
/// deletes the object); only curl's exit 63 (stopped at `max-filesize`) of
/// such a body is 422 `checksum_mismatch`. Either way nothing in `.partial`,
/// no directory, no index, and `GET` reads `failed` with that code.
#[tokio::test]
async fn claude_stage_cut_transfer_is_never_checksum_mismatch() {
    let rig = Rig::new().await;
    for (version, exit, status, code) in [("2.1.399", 18, 500, "transfer_failed"), ("2.1.398", 63, 422, "checksum_mismatch")] {
        let bytes = fake_claude_bytes(version, None, &[]);
        let object = rig.root.join(format!("object-{version}"));
        std::fs::write(&object, &bytes).unwrap();
        rig.own_curl(&format!("#!/bin/sh\ncat <&3 >/dev/null\nhead -c {} '{}'\nprintf 'ai-env-curl status=200 version= checksum= etag=\"x\"\\n' >&2\nexit {exit}\n", bytes.len() / 2, object.display()));
        let s = stage_of(version, &bytes, 30);
        let (st, b) = rig.stage(&s).await;
        let r = refusal_of(&b);
        assert_eq!((st, r.code.as_str()), (status, code), "curl exit {exit}: {}", r.message);
        assert!(rig.partials().is_empty() && !rig.cache().join(&s.sha256).exists() && !rig.index().exists(), "curl exit {exit}: nothing kept");
        let g = rig.state_of(&s.sha256).await;
        assert_eq!((g.state, g.why.as_deref()), (ClaudeStageState::Failed, Some(code)), "curl exit {exit}");
    }
}

/// A probe that never judged the binary is no `version_mismatch` (which
/// fails its version on the Mac for good): a binary killed from outside
/// (SIGKILL: the OOM killer, a chat's own `pkill claude`) is 500
/// `transfer_failed`; one that exits 3 of itself is 422 `version_mismatch`.
/// Either way its directory is removed and nothing indexed.
#[tokio::test]
async fn claude_stage_probe_not_run_is_not_version_mismatch() {
    let rig = Rig::new().await;
    for (body, status, code) in [("kill -KILL $$", 500, "transfer_failed"), ("exit 3", 422, "version_mismatch")] {
        let bytes = format!("#!/bin/sh\n{body}\n").into_bytes();
        rig.serve(&bytes, &[]);
        let s = stage_of("2.1.399", &bytes, 30);
        let (st, b) = rig.stage(&s).await;
        let r = refusal_of(&b);
        assert_eq!((st, r.code.as_str()), (status, code), "{body}: {}", r.message);
        assert!(r.message.contains("removed"), "{body}: {}", r.message);
        assert!(rig.partials().is_empty() && !rig.cache().join(&s.sha256).exists() && !rig.index().exists(), "{body}: nothing kept");
        assert_eq!(rig.state_of(&s.sha256).await.why.as_deref(), Some(code), "{body}");
    }
}

/// S3's 404 is `not_staged` (404): nothing written.
#[tokio::test]
async fn claude_stage_404_is_not_staged() {
    let rig = Rig::new().await;
    let bytes = fake_claude_bytes("2.1.399", None, &[]);
    rig.serve(&bytes, &[("S3CURL_STATUS", "404"), ("S3CURL_CODE", "NoSuchKey")]);
    let s = stage_of("2.1.399", &bytes, 30);
    let (st, b) = rig.stage(&s).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (404, "not_staged"), "{}", String::from_utf8_lossy(&b));
    assert!(!rig.cache().join(&s.sha256).exists() && rig.partials().is_empty() && !rig.index().exists());
}

/// A refusal is remembered (§2.2, LD-42): `version_mismatch` is answered at
/// once (no curl); `not_staged` and `checksum_mismatch` never are: the next
/// request fetches again (and a fixed object then stages).
#[tokio::test]
async fn claude_stage_remembers_a_refusal() {
    let rig = Rig::new().await;
    let other = fake_claude_bytes("2.1.398", None, &[]);
    rig.serve(&other, &[]);
    let wrong = stage_of("2.1.399", &other, 30);
    assert_eq!(rig.stage(&wrong).await.0, 422);
    let (st, b) = rig.stage(&wrong).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (422, "version_mismatch"));
    assert_eq!(rig.calls().len(), 1, "answered from memory");
    let bytes = fake_claude_bytes("2.1.400", None, &[]);
    let s = stage_of("2.1.400", &bytes, 30);
    rig.serve(&bytes, &[("S3CURL_STATUS", "404")]);
    assert_eq!(rig.stage(&s).await.0, 404);
    assert_eq!(rig.stage(&s).await.0, 404);
    assert_eq!(rig.calls().len(), 3, "not_staged is fetched again");
    let mut flipped = bytes.clone();
    flipped[10] ^= 1;
    rig.serve(&flipped, &[]);
    assert_eq!(rig.stage(&s).await.0, 422);
    assert_eq!(rig.state_of(&s.sha256).await.why.as_deref(), Some("checksum_mismatch"));
    rig.serve(&bytes, &[]);
    assert_eq!(rig.stage(&s).await.0, 201, "checksum_mismatch is fetched again: the Mac restaged the key");
    assert_eq!(rig.calls().len(), 5);
}

/// Two binaries stay (§2.2 step 6): the least recently used goes, but never
/// one a live spawn runs (the count stays over meanwhile); once it ended, the
/// next fetch evicts it and the other one past the keep.
#[tokio::test]
async fn claude_stage_keeps_two_never_a_running_one() {
    let rig = Rig::new().await;
    let a = rig.fetch("2.1.401", &script("2.1.401")).await;
    let mut w = ws_hello_ok(rig.s.app).await;
    let (id, version, sha256) = spawn_claude(&mut w, &["claude"], vec![a.clone()]).await;
    assert_eq!((version.as_deref(), sha256.as_deref()), (Some("2.1.401"), Some(a.sha256.as_str())));
    stdout_until(&mut w, &id, "claude=").await;
    let b = rig.fetch("2.1.402", &script("2.1.402")).await;
    let c = rig.fetch("2.1.403", &script("2.1.403")).await;
    assert_eq!(rig.versions(), ["2.1.403", "2.1.402", "2.1.401"], "2.1.401 runs: kept past the keep");
    assert!(rig.binary(&a.sha256).exists());
    send_frame(&mut w, &Frame::StdinEof { spawn_id: id.clone(), seq: 0 }).await;
    assert_eq!(run_to_exit(&mut w, &id).await.1, Some(0));
    let d = rig.fetch("2.1.404", &script("2.1.404")).await;
    assert_eq!(rig.versions(), ["2.1.404", "2.1.403"]);
    assert!(!rig.cache().join(&a.sha256).exists() && !rig.cache().join(&b.sha256).exists(), "both past the keep are gone");
    assert!(rig.binary(&c.sha256).exists() && rig.binary(&d.sha256).exists());
}

/// The index survives a restart: a new shim on the same disk answers 200
/// from its cache without a curl, and runs the binary.
#[tokio::test]
async fn claude_stage_index_survives_a_restart() {
    let rig = Rig::new().await;
    let bytes = fake_claude_bytes("2.1.399", None, &[]);
    let a = rig.fetch("2.1.399", &bytes).await;
    let again = rig.restart().await;
    let view = again.detail().await.0.claude_cache.expect("a cache with a store");
    assert_eq!(view.entries.iter().map(|e| e.sha256.as_str()).collect::<Vec<_>>(), [a.sha256.as_str()]);
    let json = serde_json::to_vec(&stage_of("2.1.399", &bytes, 30)).unwrap();
    let (st, _, b) = request(again.app, "POST", "/claude/stage", "Content-Type: application/json\r\n", Some(&json)).await;
    assert_eq!((st, reply(&b).src), (200, Some(ClaudeSrc::Cache)));
    assert_eq!(rig.calls().len(), 1);
    let mut w = ws_hello_ok(again.app).await;
    let (id, version, _) = spawn_claude(&mut w, &["claude", "--version"], vec![a]).await;
    assert_eq!(version.as_deref(), Some("2.1.399"));
    assert_eq!(run_to_exit(&mut w, &id).await, (b"2.1.399 (Claude Code)\n".to_vec(), Some(0)));
}

/// At start (§2.1, §2.1's index rules): an entry whose binary is of another
/// size, one whose binary is missing, one of a bad sha256 and a second of one
/// sha256 are dropped, the index rewritten; every unindexed directory and
/// every partial file removed; a stray file kept (V4's to name).
#[tokio::test]
async fn claude_stage_drops_a_bad_index_entry_at_start() {
    let rig = Rig::new().await;
    let a = rig.fetch("2.1.401", &script("2.1.401")).await;
    let b = rig.fetch("2.1.402", &script("2.1.402")).await;
    let mut entries = rig.indexed();
    std::fs::set_permissions(rig.binary(&b.sha256), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(rig.binary(&b.sha256), b"short").unwrap();
    let missing = ClaudeCacheEntry { version: "2.1.405".into(), sha256: "ee".repeat(32), size: 9, fetched_at: 1, last_used: 1 };
    let bad = ClaudeCacheEntry { version: "2.1.406".into(), sha256: "EE".repeat(32), size: 9, fetched_at: 1, last_used: 1 };
    let twice = entries.iter().find(|e| e.sha256 == a.sha256).unwrap().clone();
    entries.extend([missing, bad, twice]);
    std::fs::write(rig.index(), serde_json::to_vec(&serde_json::json!({"v": 1, "entries": entries})).unwrap()).unwrap();
    let stray_dir = rig.cache().join("ff".repeat(32));
    std::fs::create_dir_all(&stray_dir).unwrap();
    std::fs::write(stray_dir.join("claude"), b"x").unwrap();
    std::fs::write(rig.cache().join(".partial").join("dd".repeat(32)), b"partial").unwrap();
    std::fs::write(rig.cache().join("note.txt"), b"x").unwrap();
    let again = rig.restart().await;
    let view = again.detail().await.0.claude_cache.unwrap();
    assert_eq!(view.entries.iter().map(|e| e.version.as_str()).collect::<Vec<_>>(), ["2.1.401"]);
    assert_eq!(rig.versions(), ["2.1.401"], "the index rewritten");
    assert!(!stray_dir.exists() && !rig.cache().join(&b.sha256).exists(), "unindexed directories removed");
    assert!(rig.partials().is_empty() && rig.cache().join("note.txt").exists());
    assert!(rig.binary(&a.sha256).exists());
}

/// A fetch takes no transcript-transfer slot and not the workspace lock:
/// with four slow pushes holding every slot and the workspace held as it
/// starts, a stage still answers 201 (with a 10 ms busy wait, asking for
/// either would have been 409 at once).
#[tokio::test]
async fn claude_stage_takes_no_transfer_slot() {
    let rig = Rig::with(None, true).await;
    let bytes = script("2.1.399");
    let object = rig.root.join("object");
    std::fs::write(&object, &bytes).unwrap();
    let object = object.display().to_string();
    rig.knobs(&[("S3CURL_BODY", object.as_str()), ("S3CURL_SLOW_MS", "6000")]);
    let slug = "-Users-agent-ws";
    let mut pushes = Vec::new();
    for n in 0..ai_env_cli::wire::workspace::TRANSFERS_MAX {
        let session = format!("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5{n}");
        let rel = format!("{slug}/{session}.jsonl");
        let line = format!("{{\"type\":\"user\",\"n\":{n}}}\n").into_bytes();
        let file = rig.vm.join("Users/agent/.claude/projects").join(&rel);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, &line).unwrap();
        let push = TranscriptPush { rel, from: 0, len: line.len() as u64, sha256: sha(&line), url: url(&S3Key::Base { session, gen: 1 }, SIGNED_HEADERS_PUT), owner: OWNER.into(), proxy: Some(PROXY.into()) };
        let app = rig.s.app;
        pushes.push(tokio::spawn(async move {
            let json = serde_json::to_vec(&push).unwrap();
            request(app, "POST", "/transcript/push", "Content-Type: application/json\r\n", Some(&json)).await.0
        }));
    }
    let until = Instant::now() + Duration::from_secs(20);
    while rig.calls().len() < pushes.len() {
        assert!(Instant::now() < until, "the pushes never reached curl: {}", rig.calls().len());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    rig.knobs(&[("S3CURL_BODY", object.as_str())]);
    rig.s.state.workspace.set_busy_wait(Duration::from_millis(10));
    let held = rig.s.state.workspace.try_acquire("test").expect("the workspace is free");
    assert!(pushes.iter().all(|p| !p.is_finished()), "the four pushes hold every slot as the stage starts");
    let (st, b) = rig.stage(&stage_of("2.1.399", &bytes, 30)).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&b));
    drop(held);
    for p in pushes {
        assert_eq!(p.await.unwrap(), 200);
    }
}

/// No URL in any log line (§2.2 step 8, §2.3 step 6): the shim binary relays
/// and stages through the fake curl; its whole stderr names neither the
/// store's nor the release's URL, nor any part of a signature.
#[tokio::test]
async fn claude_stage_never_logs_a_url() {
    let tmp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let vm = root.join("vm");
    std::fs::create_dir_all(vm.join("opt/ai-env/claude")).unwrap();
    let bodies = root.join("bodies");
    std::fs::create_dir_all(&bodies).unwrap();
    let bytes = fake_claude_bytes("2.1.430", None, &[]);
    std::fs::write(bodies.join("1"), &bytes).unwrap();
    std::fs::write(bodies.join("3"), &bytes).unwrap();
    let (curl, log) = (root.join("vm-curl"), root.join("curl-vm.log"));
    install_fake_curl(&curl, &log, &[("S3CURL_BODIES", bodies.to_str().unwrap()), ("S3CURL_SAVE", root.join("saved").to_str().unwrap())]);
    let claude_dir = root.join("image");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let shim = Shim::start(&fake_claude(&claude_dir, ""), &["--fs-root", vm.to_str().unwrap(), "--curl", curl.to_str().unwrap()]);
    let (hooks, app) = (shim.addr("hooks"), shim.addr("app"));
    assert_eq!(http_sync_body(hooks, "POST", &format!("{PREFIX}/run"), &run_body("mvm-agent", Some(&payload_json("mike@mbp")))).0, 200);
    let relay = relay_of("2.1.430", &bytes);
    let (st, _, b) = request(app, "POST", "/claude/relay", "Content-Type: application/json\r\n", Some(&serde_json::to_vec(&relay).unwrap())).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let stage = stage_of("2.1.430", &bytes, 30);
    let (st, _, b) = request(app, "POST", "/claude/stage", "Content-Type: application/json\r\n", Some(&serde_json::to_vec(&stage).unwrap())).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&b));
    shim.wait_line(10, |l| l.starts_with("ai-env: claude_stage version=2.1.430 ") && l.contains(" outcome=fetched "));
    // LD-19's evidence: the redirects the release's GET followed, from its write-out.
    shim.wait_line(10, |l| l.starts_with("ai-env: claude_relay version=2.1.430 ") && l.contains(" outcome=stored ") && l.contains(" redirects=0 "));
    let lines = shim.lines.lock().unwrap().clone();
    let sigs = [stage.url.expose().to_string(), relay.put.expose().to_string()].map(|u| u.rsplit("X-Amz-Signature=").next().unwrap().to_string());
    for line in &lines {
        for needle in ["X-Amz-", "amazonaws.com", "downloads.claude.ai", "https://", sigs[0].as_str(), sigs[1].as_str()] {
            assert!(!line.contains(needle), "{needle} in {line:?}");
        }
    }
    assert_eq!(curl_calls(&log).len(), 3, "the release's GET, S3's PUT, the stage's GET");
}

/// A relay (§2.3) on a fresh VM: the release's GET first (its own
/// configuration: https only, 3 redirects, no proxy), then S3's PUT of
/// exactly the signed key, size and checksum, fed the release's bytes
/// through the shim; 200 with S3's answer and what was streamed. It writes
/// nothing on the VM's disk and marks nothing used: a second relay runs too.
#[tokio::test]
async fn claude_relay_streams_the_release_into_the_put() {
    let rig = Rig::new().await;
    let bytes = fake_claude_bytes("2.1.431", None, &[]);
    let (bodies, saved) = (rig.root.join("bodies"), rig.root.join("saved"));
    std::fs::create_dir_all(&bodies).unwrap();
    std::fs::write(bodies.join("1"), &bytes).unwrap();
    std::fs::write(bodies.join("3"), &bytes).unwrap();
    rig.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap()), ("S3CURL_SAVE", saved.to_str().unwrap())]);
    let r = relay_of("2.1.431", &bytes);
    let (st, b) = rig.post("/claude/relay", &r).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let reply: ClaudeRelayReply = serde_json::from_slice(&b).unwrap();
    assert_eq!(reply, ClaudeRelayReply { s3_status: 200, s3_code: None, version_id: Some("fake-version-2".into()), len: bytes.len() as u64, sha256: sha(&bytes) });
    assert_eq!(std::fs::read(saved.join("2.put")).unwrap(), bytes, "the release's bytes went to S3");
    let calls = rig.calls();
    assert_eq!(calls.len(), 2, "the GET 1, the PUT 2");
    let (get, put) = (&calls[0], &calls[1]);
    assert_eq!(get.conf("url"), ["https://downloads.claude.ai/claude-code-releases/2.1.431/linux-arm64/claude"]);
    for (name, want) in [("proto", "=https"), ("proto-redir", "=https"), ("max-redirs", "3"), ("request", "GET")] {
        assert_eq!(get.conf(name), [want], "{name}: {}", get.config);
    }
    assert_eq!(get.conf("max-filesize"), [bytes.len().to_string()]);
    assert!(!get.conf("location").is_empty() && !get.conf("tlsv1.2").is_empty() && get.conf("proxy").is_empty(), "{}", get.config);
    assert_eq!((put.conf("url"), put.conf("request"), put.conf("proxy")), (vec![r.put.expose().to_string()], vec!["PUT".to_string()], Vec::<String>::new()));
    let headers = put.conf("header");
    for h in [format!("Content-Length: {}", bytes.len()), format!("x-amz-checksum-sha256: {}", sha256_b64(&r.sha256).unwrap()), "If-None-Match: *".into(), format!("x-amz-expected-bucket-owner: {OWNER}")] {
        assert!(headers.contains(&h), "{h}: {headers:?}");
    }
    assert_eq!(std::fs::read_dir(rig.cache()).unwrap().count(), 0, "nothing written on the VM");
    assert!(!rig.index().exists());
    assert!(rig.s.state.fresh(), "a relay marks nothing used");
    assert_eq!(rig.post("/claude/relay", &r).await.0, 200, "a second relay runs too");
}

/// `not_fresh` (409, LD-24): a VM that ran a spawn, took a credential or
/// holds a seed record relays nothing, and no curl runs.
#[tokio::test]
async fn claude_relay_is_refused_on_a_used_vm() {
    let bytes = fake_claude_bytes("2.1.432", None, &[]);
    let r = relay_of("2.1.432", &bytes);
    let spawned = Rig::new().await;
    let mut w = ws_hello_ok(spawned.s.app).await;
    let (id, _, _) = spawn_claude(&mut w, &["/bin/echo", "hi"], Vec::new()).await;
    run_to_exit(&mut w, &id).await;
    let credential = Rig::new().await;
    let mut w = ws_hello_ok(credential.s.app).await;
    deliver(&mut w, &dummy_value("claude_relay_is_refused_on_a_used_vm"), None).await;
    let seeded = Rig::new().await;
    let record: SeedRecord = serde_json::from_value(serde_json::json!({"path": "/Users/agent/ws", "mode": "clone", "head": "ab".repeat(20), "object_format": "sha1", "at": "2026-10-23T08:00:00Z"})).unwrap();
    seeded.s.state.workspace.set_record(record);
    for (what, rig) in [("a spawn", &spawned), ("a credential", &credential), ("a seed record", &seeded)] {
        assert!(!rig.s.state.fresh(), "{what}");
        let (st, b) = rig.post("/claude/relay", &r).await;
        assert_eq!((st, refusal_of(&b).code.as_str()), (409, "not_fresh"), "{what}: {}", String::from_utf8_lossy(&b));
        assert!(rig.calls().is_empty(), "{what}: no curl");
    }
}

/// A release whose bytes stop short of the signed size (curl ended cleanly):
/// the PUT it opened is killed and the relay is 500 `transfer_failed` naming
/// the counts; a release that answers 404 opens no PUT at all. (Two VMs: the
/// killed PUT's fake curl may die holding its log's lock.)
#[tokio::test]
async fn claude_relay_cuts_a_short_release() {
    let bytes = fake_claude_bytes("2.1.433", None, &[]);
    let r = relay_of("2.1.433", &bytes);
    let short = Rig::new().await;
    let bodies = short.root.join("bodies");
    std::fs::create_dir_all(&bodies).unwrap();
    std::fs::write(bodies.join("1"), &bytes[..1000]).unwrap();
    short.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap()), ("S3CURL_SAVE", short.root.join("saved").to_str().unwrap())]);
    let (st, b) = short.post("/claude/relay", &r).await;
    let refused = refusal_of(&b);
    assert_eq!((st, refused.code.as_str()), (500, "transfer_failed"), "{}", refused.message);
    assert!(refused.message.contains(&format!("the release's bytes stopped after 1000 of {}", bytes.len())), "{}", refused.message);
    assert_eq!(short.calls().first().map(|c| c.conf("request")), Some(vec!["GET".to_string()]), "the release's GET first");
    let missing = Rig::new().await;
    missing.knobs(&[("S3CURL_STATUS", "404")]);
    let (st, b) = missing.post("/claude/relay", &r).await;
    let refused = refusal_of(&b);
    assert_eq!((st, refused.code.as_str()), (500, "transfer_failed"));
    assert!(refused.message.contains("the release answered HTTP 404"), "{}", refused.message);
    assert_eq!(missing.calls().len(), 1, "no PUT for a release that sent nothing");
}

/// A release longer than the signed size: its GET's curl, told
/// `max-filesize`, refuses it on the Content-Length before the transfer
/// (exit 63, nothing written, as the real curl): the relay is 500
/// `transfer_failed` with nothing come, and no PUT is opened.
#[tokio::test]
async fn claude_relay_opens_no_put_for_an_oversized_release() {
    let bytes = fake_claude_bytes("2.1.434", None, &[]);
    let r = relay_of("2.1.434", &bytes);
    let rig = Rig::new().await;
    let (bodies, saved) = (rig.root.join("bodies"), rig.root.join("saved"));
    std::fs::create_dir_all(&bodies).unwrap();
    std::fs::write(bodies.join("1"), [&bytes[..], &b"#"[..]].concat()).unwrap();
    rig.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap()), ("S3CURL_SAVE", saved.to_str().unwrap())]);
    let (st, b) = rig.post("/claude/relay", &r).await;
    let refused = refusal_of(&b);
    assert_eq!((st, refused.code.as_str()), (500, "transfer_failed"), "{}", refused.message);
    assert!(refused.message.contains(&format!("the release's bytes stopped after 0 of {}", bytes.len())), "{}", refused.message);
    let calls = rig.calls();
    assert_eq!(calls.len(), 1, "the release's GET only, no PUT");
    assert_eq!(calls[0].conf("max-filesize"), [bytes.len().to_string()]);
    assert!(!saved.exists(), "nothing sent to S3");
}

/// A spawn runs the first ref the cache holds (A.4, L2): `spawned` names its
/// version and sha256, the cached binary prints its version, and the pick
/// makes it the most recently used.
#[tokio::test]
async fn a_spawn_runs_the_first_cached_claude_it_names() {
    let rig = Rig::new().await;
    let a = rig.fetch("2.1.410", &fake_claude_bytes("2.1.410", None, &[])).await;
    let b = rig.fetch("2.1.411", &fake_claude_bytes("2.1.411", None, &[])).await;
    assert_eq!(rig.versions(), ["2.1.411", "2.1.410"]);
    let absent = ClaudeRef { version: "2.1.412".into(), sha256: "ee".repeat(32) };
    let mut w = ws_hello_ok(rig.s.app).await;
    let (id, version, sha256) = spawn_claude(&mut w, &["claude", "--version"], vec![absent, a.clone(), b]).await;
    assert_eq!((version.as_deref(), sha256.as_deref()), (Some("2.1.410"), Some(a.sha256.as_str())));
    assert_eq!(run_to_exit(&mut w, &id).await, (b"2.1.410 (Claude Code)\n".to_vec(), Some(0)));
    // The pick's last_used reaches the index in the background, off the spawn's path.
    let until = Instant::now() + Duration::from_secs(10);
    while rig.versions() != ["2.1.410", "2.1.411"] {
        assert!(Instant::now() < until, "the pick never wrote its last_used: {:?}", rig.versions());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A spawn naming nothing the cache holds runs the image's claude: `spawned`
/// names the image's version and no sha256; a ref that is the lock's is the
/// image's own; a program other than `claude` picks nothing.
#[tokio::test]
async fn a_spawn_naming_nothing_cached_runs_the_image_claude() {
    let lock_sha = "cd".repeat(32);
    let rig = Rig::with(Some((IMAGE_VERSION, &lock_sha)), false).await;
    let absent = ClaudeRef { version: "2.1.412".into(), sha256: "ee".repeat(32) };
    let mut w = ws_hello_ok(rig.s.app).await;
    let (id, version, sha256) = spawn_claude(&mut w, &["claude", "--version"], vec![absent.clone()]).await;
    assert_eq!((version.as_deref(), sha256), (Some(IMAGE_VERSION), None));
    assert_eq!(run_to_exit(&mut w, &id).await, (format!("{IMAGE_VERSION} (Claude Code)\n").into_bytes(), Some(0)));
    let image = ClaudeRef { version: IMAGE_VERSION.into(), sha256: lock_sha };
    let (id, version, sha256) = spawn_claude(&mut w, &["claude", "--version"], vec![absent.clone(), image]).await;
    assert_eq!((version.as_deref(), sha256), (Some(IMAGE_VERSION), None));
    run_to_exit(&mut w, &id).await;
    let (id, version, sha256) = spawn_claude(&mut w, &["/bin/echo", "hi"], vec![absent]).await;
    assert_eq!((version, sha256), (None, None));
    run_to_exit(&mut w, &id).await;
    assert!(rig.calls().is_empty());
}

/// A ref is an index entry's sha256 and version both (A.4, §2.2's index): a
/// ref naming a cached version under another sha256 (the Mac restaged that
/// version) picks nothing, and the image's claude runs; the cached binary's
/// own ref still runs it.
#[tokio::test]
async fn a_spawn_naming_a_cached_version_under_another_sha256_runs_the_image_claude() {
    let rig = Rig::new().await;
    let a = rig.fetch("2.1.430", &fake_claude_bytes("2.1.430", None, &[])).await;
    let other = ClaudeRef { version: a.version.clone(), sha256: "ee".repeat(32) };
    assert_ne!(other.sha256, a.sha256);
    let mut w = ws_hello_ok(rig.s.app).await;
    let (id, version, sha256) = spawn_claude(&mut w, &["claude", "--version"], vec![other]).await;
    assert_eq!((version.as_deref(), sha256), (Some(IMAGE_VERSION), None), "2.1.430 is cached under another sha256: not this ref's binary");
    assert_eq!(run_to_exit(&mut w, &id).await, (format!("{IMAGE_VERSION} (Claude Code)\n").into_bytes(), Some(0)));
    let (id, version, sha256) = spawn_claude(&mut w, &["claude", "--version"], vec![a.clone()]).await;
    assert_eq!((version.as_deref(), sha256.as_deref()), (Some("2.1.430"), Some(a.sha256.as_str())));
    assert_eq!(run_to_exit(&mut w, &id).await, (b"2.1.430 (Claude Code)\n".to_vec(), Some(0)));
}

/// A cached claude's directory leads the spawn's PATH, so a nested `claude`
/// runs it too.
#[tokio::test]
async fn a_cached_claudes_directory_leads_path() {
    let rig = Rig::new().await;
    let a = rig.fetch("2.1.420", &script("2.1.420")).await;
    let mut w = ws_hello_ok(rig.s.app).await;
    let (id, _, _) = spawn_claude(&mut w, &["claude"], vec![a.clone()]).await;
    let out = stdout_until(&mut w, &id, "claude=").await;
    let dir = rig.cache().join(&a.sha256);
    assert!(out.contains(&format!("path={}:/usr/local/bin:/usr/bin:/bin\n", dir.display())), "{out}");
    assert!(out.contains(&format!("claude={}\n", dir.join("claude").display())), "{out}");
    send_frame(&mut w, &Frame::StdinEof { spawn_id: id.clone(), seq: 0 }).await;
    assert_eq!(run_to_exit(&mut w, &id).await.1, Some(0));
}

/// V4 (§2.6): the image's cache is a directory, empty, 0755, and has no
/// index; each departure is named.
#[tokio::test]
async fn validate_v4_names_a_dirty_claude_cache() {
    let t = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(t.path()).unwrap();
    plant_vm_tree(&root);
    let cache = root.join("opt/ai-env/claude");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (st, b) = validate_in(&root, "").await;
    assert_eq!(st, 200, "a clean tree: {b}");
    std::fs::write(cache.join("junk"), b"x").unwrap();
    let (st, b) = validate_in(&root, "").await;
    assert!(st == 503 && b.contains("V4") && b.contains("/opt/ai-env/claude is not empty: junk"), "{b}");
    std::fs::remove_file(cache.join("junk")).unwrap();
    let index = root.join("var/lib/ai-env/claude-index.json");
    std::fs::create_dir_all(index.parent().unwrap()).unwrap();
    std::fs::write(&index, "{\"v\":1,\"entries\":[]}\n").unwrap();
    let (st, b) = validate_in(&root, "").await;
    assert!(st == 503 && b.contains("/var/lib/ai-env/claude-index.json exists"), "{b}");
    std::fs::remove_file(&index).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (st, b) = validate_in(&root, "").await;
    assert!(st == 503 && b.contains("/opt/ai-env/claude is mode 0700, not 0755"), "{b}");
    std::fs::remove_dir(&cache).unwrap();
    let (st, b) = validate_in(&root, "").await;
    assert!(st == 503 && b.contains("/opt/ai-env/claude is missing"), "{b}");
    assert!(!b.contains("V1") && !b.contains("V2") && !b.contains("V3"), "only V4: {b}");
}

/// `/health/detail` lists the cache: its entries, the image's ref (the
/// lock's), and a remembered refusal.
#[tokio::test]
async fn health_detail_lists_the_cache() {
    let lock_sha = "cd".repeat(32);
    let rig = Rig::with(Some((IMAGE_VERSION, &lock_sha)), false).await;
    let empty = rig.s.detail().await.0.claude_cache.expect("a store");
    assert!(empty.entries.is_empty() && empty.fetching.is_none() && empty.failed.is_empty(), "{empty:?}");
    let (_, body) = rig.s.detail().await;
    assert!(body.contains("\"claude_cache\":{\"entries\":[]"), "entries always written: {body}");
    let a = rig.fetch("2.1.399", &fake_claude_bytes("2.1.399", None, &[])).await;
    let missing = fake_claude_bytes("2.1.398", None, &[]);
    rig.serve(&missing, &[("S3CURL_STATUS", "404")]);
    assert_eq!(rig.stage(&stage_of("2.1.398", &missing, 30)).await.0, 404);
    let view = rig.s.detail().await.0.claude_cache.unwrap();
    assert_eq!(view.entries.iter().map(|e| (e.version.as_str(), e.sha256.as_str())).collect::<Vec<_>>(), [("2.1.399", a.sha256.as_str())]);
    assert_eq!(view.image, Some(ClaudeRef { version: IMAGE_VERSION.into(), sha256: lock_sha }));
    assert_eq!(view.failed, BTreeMap::from([(sha(&missing), "not_staged".to_string())]));
    assert_eq!(view.fetching, None);
}

/// The run report (§2.6, LD-23) lists the cache's binaries from the index
/// under its root: version, sha256 and size, most recently used first; `[]`
/// without an index and `null` when it cannot be read.
#[tokio::test]
async fn the_run_report_lists_the_cache() {
    let rig = Rig::new().await;
    let a = rig.fetch("2.1.401", &script("2.1.401")).await;
    let b = rig.fetch("2.1.402", &script("2.1.402")).await;
    let report = ai_env_cli::shim::sys::read_report(&rig.vm, "terminate", None);
    let size = |r: &ClaudeRef| std::fs::metadata(rig.binary(&r.sha256)).unwrap().len();
    assert_eq!(
        report["claude_cache"],
        serde_json::json!([{"version": "2.1.402", "sha256": b.sha256, "size": size(&b)}, {"version": "2.1.401", "sha256": a.sha256, "size": size(&a)}]),
        "{report}"
    );
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(ai_env_cli::shim::sys::read_report(empty.path(), "terminate", None)["claude_cache"], serde_json::json!([]));
    std::fs::write(rig.index(), b"not json").unwrap();
    assert!(ai_env_cli::shim::sys::read_report(&rig.vm, "terminate", None)["claude_cache"].is_null());
}
