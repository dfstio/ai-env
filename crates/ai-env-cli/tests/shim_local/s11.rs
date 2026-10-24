//! S11 part C (wave 1, C1): the code-out that answers its manifest
//! (`codeout_manifest_v1`), the view's `first_parent` (`view_parent_v1`) and
//! the gzip pull (`transcript_gzip_v1`), on native shims: the in-process
//! shim with this binary's real helper (`ai-env shim-io`) as the agent and,
//! for the transfers, the fake curl (`tests/common/curl.rs`, declared beside
//! this module as `curl`), which plays S3 (its `S3CURL_ENCODING=gzip` stores
//! a body with `Content-Encoding: gzip` and decodes it only for a
//! configuration holding `compressed`, as curl does).
use super::curl::{curl_calls, install_fake_curl, CurlCall};
use super::transcript_s3::OWNER;
use super::{bin, git, git_real, opts, refusal_of, request, stack, write_file, HookSource, ShimOpts, Stack, Vm, S8_ID, S8_SLUG, WS};
use ai_env_cli::wire::s3::{PresignedUrl, S3Key, SIGNED_HEADERS_GET};
use ai_env_cli::wire::view::TranscriptViewReply;
use ai_env_cli::wire::workspace::{head_line, CodeoutManifest, PartEncoding, PullPart, PullPartReport, TranscriptPull, TranscriptPullReply};
use sha2::Digest as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ---- C.1: the code-out's manifest-only 200 -------------------------------------------------

/// A code-out request of the Mac's shape: `haves`, a snapshot asked, and the flag when `Some`.
fn codeout_request(haves: &[&str], flag: Option<bool>) -> Vec<u8> {
    let mut req = serde_json::json!({"path": WS, "haves": haves, "wip": true, "max_bytes": 1 << 20});
    if let Some(f) = flag {
        req["manifest_when_empty"] = serde_json::Value::Bool(f);
    }
    req.to_string().into_bytes()
}

/// The answer head's `Content-Length`.
fn content_length(head: &str) -> usize {
    head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").map(|v| v.trim().parse().unwrap())).expect("a Content-Length")
}

/// S11 (C.1.2): after `git checkout -b topic` in the VM's copy (no new
/// object, every tip a have) a code-out that sets `manifest_when_empty` is
/// 200 whose body is exactly the manifest's framed line (`Content-Length`
/// its length, `application/octet-stream`, no pack byte), naming `topic` at
/// the seeded HEAD; the run ended and the workspace lock went with it (the
/// next request is served, the inbox empty). A real pack still follows its
/// line, flag or not.
#[tokio::test]
async fn a_codeout_asked_for_its_manifest_answers_200_with_the_line_alone() {
    let vm = Vm::new().await;
    let seed = vm.clone_mac().await;
    let ws = vm.ws();
    git(&ws, &["checkout", "-q", "-b", "topic"]);
    let (st, head, b) = vm.code("POST", "/codeout", Some(&codeout_request(&[seed.head.as_str()], Some(true)))).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    assert_eq!(content_length(&head), b.len(), "{head}");
    assert!(head.to_ascii_lowercase().contains("content-type: application/octet-stream"), "{head}");
    assert!(b.ends_with(b"\n") && b.iter().filter(|c| **c == b'\n').count() == 1, "the line alone: {}", String::from_utf8_lossy(&b));
    let manifest: CodeoutManifest = serde_json::from_slice(&b[..b.len() - 1]).unwrap();
    manifest.check().unwrap();
    assert_eq!(b, head_line(&manifest).unwrap(), "the framed line, byte for byte");
    assert_eq!((manifest.head.as_str(), manifest.branch.as_deref(), manifest.wip_ref.as_deref()), (seed.head.as_str(), Some("topic"), None));
    assert_eq!((manifest.refs.get("refs/heads/topic"), manifest.refs.get("refs/heads/main")), (Some(&seed.head), Some(&seed.head)));
    let state = vm.state().await;
    assert!(state.record.is_some(), "the workspace lock went with the run: {state:?}");
    assert!(vm.inbox_is_empty());
    // A VM commit: its pack follows the line, as without the flag.
    write_file(&ws.join("vm.txt"), "committed in the VM\n");
    git(&ws, &["add", "vm.txt"]);
    git(&ws, &["commit", "-q", "-m", "vm"]);
    let vm_head = git(&ws, &["rev-parse", "HEAD"]);
    let (st, head, b) = vm.code("POST", "/codeout", Some(&codeout_request(&[seed.head.as_str()], Some(true)))).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    assert_eq!(content_length(&head), b.len());
    let nl = b.iter().position(|c| *c == b'\n').unwrap();
    let manifest: CodeoutManifest = serde_json::from_slice(&b[..nl]).unwrap();
    assert_eq!((manifest.head.as_str(), manifest.branch.as_deref()), (vm_head.as_str(), Some("topic")));
    assert!(b[nl + 1..].starts_with(b"PACK") && b[nl + 1..].len() >= 32, "a pack after the line");
    assert!(vm.inbox_is_empty());
}

/// S11 (C.1.2, C.1.4): without the flag (an S10 request: no key, or
/// `false`) nothing new is still a bare 204, as a 12.0 shim answers.
#[tokio::test]
async fn without_the_flag_nothing_new_stays_204() {
    let vm = Vm::new().await;
    let seed = vm.clone_mac().await;
    git(&vm.ws(), &["checkout", "-q", "-b", "topic"]);
    for flag in [None, Some(false)] {
        let (st, head, b) = vm.code("POST", "/codeout", Some(&codeout_request(&[seed.head.as_str()], flag))).await;
        assert!(st == 204 && b.is_empty(), "{flag:?}: {st} {head}: {}", String::from_utf8_lossy(&b));
    }
    assert!(vm.inbox_is_empty());
}

// ---- the transfers' VM ---------------------------------------------------------------------

/// The VM of the transfer tests (as `transcript_s3`'s): the in-process shim
/// (`/run` done) with the real helper and the fake curl, the agent's home
/// under its fs root.
struct Rig {
    s: Stack,
    root: PathBuf,
    curl: PathBuf,
    log: PathBuf,
    _tmp: tempfile::TempDir,
}

impl Rig {
    async fn new() -> Rig {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir_all(root.join("vm/Users/agent")).unwrap();
        let (curl, log) = (root.join("vm-curl"), root.join("curl-vm.log"));
        install_fake_curl(&curl, &log, &[]);
        let o = ShimOpts { fs_root: Some(root.join("vm")), home: root.join("vm/Users/agent"), helper: Some(PathBuf::from(bin())), git: git_real().to_path_buf(), curl: curl.clone(), ..opts(None, HookSource::Log, 0) };
        let s = stack(o).await;
        s.run(true).await;
        Rig { s, root, curl, log, _tmp: tmp }
    }

    /// The fake curl's knobs from now on (its log kept).
    fn knobs(&self, knobs: &[(&str, &str)]) {
        install_fake_curl(&self.curl, &self.log, knobs);
    }

    fn calls(&self) -> Vec<CurlCall> {
        curl_calls(&self.log)
    }

    /// The session's main transcript on the VM's disk.
    fn file(&self) -> PathBuf {
        self.root.join("vm/Users/agent/.claude/projects").join(rel())
    }

    /// The temp files left in the transcript's directory.
    fn temps(&self) -> Vec<String> {
        let Ok(d) = std::fs::read_dir(self.root.join("vm/Users/agent/.claude/projects").join(S8_SLUG)) else { return Vec::new() };
        d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".tmp")).collect()
    }

    async fn pull(&self, p: &TranscriptPull) -> (u16, Vec<u8>) {
        let json = serde_json::to_vec(p).unwrap();
        let (st, _, b) = request(self.s.app, "POST", "/transcript/pull", "Content-Type: application/json\r\n", Some(&json)).await;
        (st, b)
    }

    async fn get(&self, path: &str) -> (u16, Vec<u8>) {
        let (st, _, b) = request(self.s.app, "GET", path, "", None).await;
        (st, b)
    }
}

/// The session's main transcript rel.
fn rel() -> String {
    format!("{S8_SLUG}/{S8_ID}.jsonl")
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

fn put(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// `/usr/bin/gzip -n -6` of `bytes`, as the Mac's stage stores them (C.3.4).
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut child = Command::new("/usr/bin/gzip").args(["-n", "-6", "-c"]).env_clear().env("LC_ALL", "C").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = bytes.to_vec();
    let feeder = std::thread::spawn(move || stdin.write_all(&input).unwrap());
    let out = child.wait_with_output().unwrap();
    feeder.join().unwrap();
    assert!(out.status.success() && out.stdout.starts_with(&[0x1f, 0x8b]), "gzip: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

/// A part of a pull: the Mac object of the `stored` bytes (its key the
/// stored bytes' sha256, by its version `version`), whose `len` and sha256
/// are `decoded`'s; `encoding` as the manifest says. The URL's signature is
/// made at run time: nothing credential-shaped is written here.
fn mac_part(stored: &[u8], decoded: &[u8], version: &str, encoding: Option<PartEncoding>) -> PullPart {
    let key = S3Key::Mac { session: S8_ID.into(), sha256: sha(stored) }.render();
    let query = format!(
        "versionId={version}&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261023%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261023T101530Z&X-Amz-Expires=300&X-Amz-SignedHeaders={}&X-Amz-Signature={}",
        SIGNED_HEADERS_GET.replace(';', "%3B"),
        sha(key.as_bytes())
    );
    let url = PresignedUrl::new(format!("https://ai-env-transcripts-{OWNER}.s3.eu-central-1.amazonaws.com/{key}?{query}")).unwrap();
    PullPart { url, len: decoded.len() as u64, sha256: Some(sha(decoded)), encoding }
}

fn pull_of(parts: Vec<PullPart>, whole: Option<&[u8]>) -> TranscriptPull {
    let p = TranscriptPull { rel: rel(), parts, sha256: whole.map(sha), owner: OWNER.into(), proxy: None, share: 1 };
    p.check().unwrap_or_else(|e| panic!("the pull itself is well formed: {e}"));
    p
}

/// A transcript of `n` lines.
fn lines(n: usize, tag: &str) -> Vec<u8> {
    (0..n).map(|i| format!("{{\"type\":\"user\",\"tag\":\"{tag}\",\"n\":{i}}}\n")).collect::<String>().into_bytes()
}

// ---- C.2: the view's first_parent ----------------------------------------------------------

/// S11 (C.2.3): the view answers `first_parent` only when the query asks
/// (`parent=true`): without the pair, or with `parent=false`, the key is
/// absent (an S10 Mac, which refuses unknown fields, never meets it); asked,
/// a compacted chat's first turn names its summary, and a chain root names
/// none. `parent=1` is no bool: 400, as the query pins `true`.
#[tokio::test]
async fn the_view_leaves_first_parent_out_unless_asked() {
    const SUMMARY: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4c11";
    const U: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4c12";
    let rig = Rig::new().await;
    put(&rig.file(), include_bytes!("../fixtures/view/tails/compacted-first-turn.jsonl"));
    let view = format!("/transcript/view?rel={}&n=10", rel());
    for path in [view.clone(), format!("{view}&parent=false")] {
        let (st, b) = rig.get(&path).await;
        assert_eq!(st, 200, "{path}: {}", String::from_utf8_lossy(&b));
        let text = String::from_utf8(b).unwrap();
        assert!(!text.contains("first_parent"), "{path}: {text}");
        let reply: TranscriptViewReply = serde_json::from_str(&text).unwrap();
        assert_eq!((reply.entries.len(), reply.entries[0].uuid.as_str(), reply.first_parent), (2, U, None), "{path}");
    }
    let (st, b) = rig.get(&format!("{view}&parent=true")).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let text = String::from_utf8(b).unwrap();
    assert!(text.ends_with(&format!(",\"first_parent\":\"{SUMMARY}\"}}")), "last: {text}");
    let reply: TranscriptViewReply = serde_json::from_str(&text).unwrap();
    assert_eq!((reply.entries[0].uuid.as_str(), reply.first_parent.as_deref()), (U, Some(SUMMARY)));
    assert_eq!(reply.check(10), Ok(()));
    let (st, b) = rig.get(&format!("{view}&parent=1")).await;
    assert_eq!((st, refusal_of(&b).code.as_str()), (400, "bad_request"));
    // A chain root names none, asked or not.
    put(&rig.file(), include_bytes!("../fixtures/view/tails/example.jsonl"));
    let (st, b) = rig.get(&format!("{view}&parent=true")).await;
    let text = String::from_utf8(b).unwrap();
    assert!(st == 200 && !text.contains("first_parent"), "{st}: {text}");
    assert!(rig.calls().is_empty(), "the view runs no curl");
}

// ---- C.3: the gzip pull --------------------------------------------------------------------

/// S11 (C.3.2): a part stored gzip (`encoding` `gzip`) is fetched with
/// curl's `compressed` line and checked on its decoded bytes (status,
/// length, the part's and the whole file's sha256), beside an identity part
/// whose configuration has no `compressed`, its lines S10's: 201, the file
/// the decoded bytes, 0600, no temp left.
#[tokio::test]
async fn a_gzip_part_pulls_decoded_with_compressed() {
    use std::os::unix::fs::PermissionsExt as _;
    let rig = Rig::new().await;
    let bodies = rig.root.join("bodies");
    let (a, b) = (lines(4000, "a"), lines(50, "b"));
    let gz = gzip(&a);
    assert!(gz.len() * 4 < a.len(), "compressible: {} of {}", gz.len(), a.len());
    put(&bodies.join("1"), &gz);
    put(&bodies.join("2"), &b);
    rig.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap()), ("S3CURL_ENCODING", "gzip")]);
    let whole = [&a[..], &b[..]].concat();
    let pull = pull_of(vec![mac_part(&gz, &a, "fv1", Some(PartEncoding::Gzip)), mac_part(&b, &b, "fv2", None)], Some(&whole));
    let (st, body) = rig.pull(&pull).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&body));
    let reply: TranscriptPullReply = serde_json::from_slice(&body).unwrap();
    let report = |bytes: &[u8]| PullPartReport { s3_status: 200, len: bytes.len() as u64, sha256: sha(bytes), ok: true };
    assert_eq!(reply, TranscriptPullReply { written: true, size: whole.len() as u64, sha256: Some(sha(&whole)), parts: vec![report(&a), report(&b)] });
    assert_eq!(std::fs::read(rig.file()).unwrap(), whole, "the decoded bytes");
    assert_eq!(std::fs::metadata(rig.file()).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(rig.temps().is_empty(), "{:?}", rig.temps());
    let calls = rig.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls.iter().map(|c| c.conf("compressed").len()).collect::<Vec<_>>(), [1, 0], "compressed for the gzip part only");
    for (call, part) in calls.iter().zip(&pull.parts) {
        assert_eq!((call.conf("request"), call.conf("fail"), call.conf("header")), (vec!["GET".to_string()], vec![String::new()], vec![format!("x-amz-expected-bucket-owner: {OWNER}")]));
        assert_eq!(call.conf("url"), [part.url.expose()]);
    }
    let tail = |c: &CurlCall| c.config.split_once("request = ").map(|(_, t)| t.to_string()).unwrap();
    assert_eq!(tail(&calls[0]), format!("\"GET\"\nheader = \"x-amz-expected-bucket-owner: {OWNER}\"\ncompressed\nfail\noutput = \"-\"\n"));
    assert_eq!(tail(&calls[1]), tail(&calls[0]).replace("compressed\n", ""), "the identity GET's lines are S10's");
}

/// S11 (C.3.2): a gzip part S3 serves without `Content-Encoding` (here the
/// fake curl without `S3CURL_ENCODING`) is not decoded: its stored bytes
/// fail the part's length and sha256 check, 200 `written: false` with the
/// old copy's size, nothing renamed, no temp left.
#[tokio::test]
async fn a_gzip_part_without_content_encoding_fails_its_check_nothing_renamed() {
    let rig = Rig::new().await;
    let own = b"the VM's own copy\n".to_vec();
    put(&rig.file(), &own);
    let bodies = rig.root.join("bodies");
    let a = lines(400, "a");
    let gz = gzip(&a);
    put(&bodies.join("1"), &gz);
    rig.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap())]);
    let (st, body) = rig.pull(&pull_of(vec![mac_part(&gz, &a, "fv1", Some(PartEncoding::Gzip))], Some(&a))).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let reply: TranscriptPullReply = serde_json::from_slice(&body).unwrap();
    assert_eq!(reply, TranscriptPullReply { written: false, size: own.len() as u64, sha256: None, parts: vec![PullPartReport { s3_status: 200, len: gz.len() as u64, sha256: sha(&gz), ok: false }] });
    assert_eq!(std::fs::read(rig.file()).unwrap(), own, "the VM's copy kept");
    assert!(rig.temps().is_empty(), "{:?}", rig.temps());
    assert_eq!(rig.calls()[0].conf("compressed"), [String::new()], "asked to decode; nothing to decode");
}

/// S11 (C.3.2): a decoded stream longer than its part's `len` is cut there,
/// as any part is: the bytes past `len` never reach the helper, the report
/// (S3's 200, its `len` counting the chunk that passed it) is not ok, 200
/// `written: false`, nothing renamed. A bomb (8 MiB of zeros in a few KiB of
/// gzip, `len` 100) ends the same way, never written: the fake curl dies on
/// the pipe the shim closed before its status line (500 `transfer_failed`),
/// where curl would say its 200 (`written: false`).
#[tokio::test]
async fn a_decoded_stream_past_len_is_cut_there() {
    let rig = Rig::new().await;
    let own = b"the VM's own copy\n".to_vec();
    put(&rig.file(), &own);
    let bodies = rig.root.join("bodies");
    rig.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap()), ("S3CURL_ENCODING", "gzip")]);
    let a = lines(50, "a");
    let longer = [&a[..], b"more"].concat();
    let gz = gzip(&longer);
    put(&bodies.join("1"), &gz);
    let (st, body) = rig.pull(&pull_of(vec![mac_part(&gz, &a, "fv1", Some(PartEncoding::Gzip))], None)).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let reply: TranscriptPullReply = serde_json::from_slice(&body).unwrap();
    assert_eq!((reply.written, reply.size, reply.sha256.as_deref(), reply.parts.len()), (false, own.len() as u64, None, 1), "{reply:?}");
    let part = &reply.parts[0];
    assert!(part.s3_status == 200 && !part.ok && part.len > a.len() as u64 && part.len <= longer.len() as u64, "{part:?}");
    assert_eq!(std::fs::read(rig.file()).unwrap(), own, "the VM's copy kept");
    assert!(rig.temps().is_empty(), "{:?}", rig.temps());
    // A bomb.
    let zeros = vec![0u8; 8 << 20];
    let bomb = gzip(&zeros);
    assert!(bomb.len() < 64 << 10, "{}", bomb.len());
    put(&bodies.join("2"), &bomb);
    let started = std::time::Instant::now();
    let (st, body) = rig.pull(&pull_of(vec![mac_part(&bomb, &zeros[..100], "fv2", Some(PartEncoding::Gzip))], None)).await;
    match st {
        200 => {
            let reply: TranscriptPullReply = serde_json::from_slice(&body).unwrap();
            assert!(!reply.written && reply.parts.len() == 1 && !reply.parts[0].ok && reply.parts[0].len > 100, "{reply:?}");
        }
        500 => assert_eq!(refusal_of(&body).code, "transfer_failed", "{}", String::from_utf8_lossy(&body)),
        _ => panic!("{st}: {}", String::from_utf8_lossy(&body)),
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(30), "cut at once: {:?}", started.elapsed());
    assert_eq!(std::fs::read(rig.file()).unwrap(), own, "the VM's copy kept");
    assert!(rig.temps().is_empty(), "{:?}", rig.temps());
}
