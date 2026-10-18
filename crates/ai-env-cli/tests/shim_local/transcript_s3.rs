//! S9 wave 1 (G5): the shim's S3 transfers (`shim::s3xfer`: push, pull, the
//! view and the tail) and the helper's transcript ops, through the fake curl
//! (`tests/common/curl.rs`, declared beside this module as `curl`), which
//! plays S3 itself. The in-process shim runs the real helper (this binary's
//! `ai-env shim-io`) as the agent and the fake curl as `ai-env-net` (here
//! the tests' own uid: the shim is not root); the fake logs every
//! configuration it got on fd 3, which is where the presigned URL goes.
use super::curl::{curl_calls, install_fake_curl, CurlCall};
use super::{bin, git_real, hook, opts, refusal_of, request, stack, HookSource, ShimOpts, Stack, S8_ID, S8_SLUG};
use ai_env_cli::wire::s3::{sha256_b64, PresignedUrl, S3Key, SIGNED_HEADERS_GET, SIGNED_HEADERS_PUT, SIGNED_HEADERS_TAIL};
use ai_env_cli::wire::view::TranscriptViewReply;
use ai_env_cli::wire::workspace::{PullPart, PullPartReport, TranscriptPull, TranscriptPullReply, TranscriptPush, TranscriptPushReply, TranscriptStat, TranscriptTail};
use sha2::Digest as _;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

const OWNER: &str = "123456789012";
const PROXY: &str = "http://10.42.0.10:3128";
/// curl's write-out line, as S9 §3.4 pins it.
const WRITE_OUT: &str = r#"write-out = "%{stderr}ai-env-curl status=%{http_code} version=%header{x-amz-version-id} checksum=%header{x-amz-checksum-sha256} etag=%header{etag}\n""#;

/// The VM of these tests: the in-process shim (`/run` done) with the real
/// helper and the fake curl, the agent's home under its fs root.
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

    fn projects(&self) -> PathBuf {
        self.root.join("vm/Users/agent/.claude/projects")
    }

    /// The session's transcript on the VM's disk.
    fn file(&self) -> PathBuf {
        self.projects().join(rel())
    }

    fn calls(&self) -> Vec<CurlCall> {
        curl_calls(&self.log)
    }

    /// `POST path` of `body` as JSON, with the bearer.
    async fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> (u16, String, Vec<u8>) {
        let json = serde_json::to_vec(body).unwrap();
        request(self.s.app, "POST", path, "Content-Type: application/json\r\n", Some(&json)).await
    }

    async fn get(&self, path: &str) -> (u16, String, Vec<u8>) {
        request(self.s.app, "GET", path, "", None).await
    }

    /// The temp files left in the transcript's directory.
    fn temps(&self) -> Vec<String> {
        let Ok(d) = std::fs::read_dir(self.projects().join(S8_SLUG)) else { return Vec::new() };
        d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".tmp")).collect()
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

/// A presigned URL of the store for `key`, signed over `signed` (its
/// signature made at run time: nothing credential-shaped is written here);
/// `lab` makes it the tests' path-style loopback form (debug builds).
fn url_at(key: &S3Key, signed: &str, version: Option<&str>, lab: bool) -> PresignedUrl {
    let key = key.render();
    let sig = sha(key.as_bytes());
    let version = version.map(|v| format!("versionId={v}&")).unwrap_or_default();
    let base = if lab { format!("http://127.0.0.1:9/ai-env-transcripts-{OWNER}") } else { format!("https://ai-env-transcripts-{OWNER}.s3.eu-central-1.amazonaws.com") };
    let query = format!("{version}X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261017%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261017T101530Z&X-Amz-Expires=300&X-Amz-SignedHeaders={}&X-Amz-Signature={sig}", signed.replace(';', "%3B"));
    PresignedUrl::new(format!("{base}/{key}?{query}")).unwrap()
}

fn url(key: &S3Key, signed: &str, version: Option<&str>) -> PresignedUrl {
    url_at(key, signed, version, false)
}

fn base(gen: u32) -> S3Key {
    S3Key::Base { session: S8_ID.into(), gen }
}

fn segment(gen: u32, offset: u64) -> S3Key {
    S3Key::Segment { session: S8_ID.into(), gen, offset }
}

/// A push of `bytes` (the file's from `from`) to `key`, through the proxy.
fn push_of(from: u64, bytes: &[u8], key: &S3Key) -> TranscriptPush {
    TranscriptPush { rel: rel(), from, len: bytes.len() as u64, sha256: sha(bytes), url: url(key, SIGNED_HEADERS_PUT, None), owner: OWNER.into(), proxy: Some(PROXY.into()) }
}

/// A part of a pull: `bytes` at `key`'s version `version`.
fn part_of(key: &S3Key, version: &str, bytes: &[u8]) -> PullPart {
    PullPart { url: url(key, SIGNED_HEADERS_GET, Some(version)), len: bytes.len() as u64, sha256: Some(sha(bytes)) }
}

fn pull_of(parts: Vec<PullPart>, whole: Option<&[u8]>) -> TranscriptPull {
    TranscriptPull { rel: rel(), parts, sha256: whole.map(sha), owner: OWNER.into(), proxy: Some(PROXY.into()) }
}

/// `body`'s refusal code and message.
fn refused(body: &[u8]) -> (String, String) {
    let r = refusal_of(body);
    (r.code, r.message)
}

/// The request lines of a push's configuration (S9 §3.4), `checksum` with a push's, none for a tail.
fn put_lines(len: usize, checksum: Option<&str>) -> String {
    let mut lines = format!("request = \"PUT\"\nupload-file = \"-\"\nheader = \"Content-Length: {len}\"\nheader = \"Transfer-Encoding:\"\nheader = \"Expect:\"\n");
    if let Some(sum) = checksum {
        lines.push_str(&format!("header = \"x-amz-checksum-sha256: {sum}\"\n"));
    }
    lines.push_str(&format!("header = \"If-None-Match: *\"\nheader = \"x-amz-expected-bucket-owner: {OWNER}\"\noutput = \"-\"\n"));
    lines
}

/// A whole configuration: its common lines, then `tail`.
fn config(url: &PresignedUrl, proto: &str, max_time: &str, proxy: Option<&str>, tail: &str) -> String {
    let proxy = proxy.map(|p| format!("proxy = \"{p}\"\n")).unwrap_or_default();
    format!("url = \"{}\"\nsilent\nshow-error\nproto = \"={proto}\"\nconnect-timeout = 20\nmax-time = {max_time}\n{WRITE_OUT}\n{proxy}{tail}", url.expose())
}

/// A call's configuration with its `max-time` value as `<t>`, and that value.
fn timed(call: &CurlCall) -> (String, u64) {
    let secs = call.conf("max-time").first().and_then(|v| v.parse().ok()).expect("a max-time line");
    (call.config.replace(&format!("max-time = {secs}\n"), "max-time = <t>\n"), secs)
}

/// A push streams the delta (S9 §1.4, §3.4): the extended stat names its
/// sha256 (and no whole-file one); the push sends exactly those bytes to
/// curl's stdin and answers S3's status and version id with what it
/// streamed. S3 refusing a full copy (412) is still a 200 carrying S3's
/// status and code; curl without an HTTP status is 500 `transfer_failed`
/// naming its exit; a range the file no longer holds is 409 `changed`
/// before curl starts; the body's own refusals come first (a key that does
/// not fit its bytes, a size over `PUSH_MAX`, a body that is no JSON, no
/// bearer).
#[tokio::test]
async fn push_streams_the_delta() {
    let rig = Rig::new().await;
    let saved = rig.root.join("saved");
    rig.knobs(&[("S3CURL_SAVE", saved.to_str().unwrap())]);
    let first = b"{\"type\":\"user\",\"n\":1}\n".repeat(100);
    let delta = b"{\"type\":\"assistant\",\"n\":2}\n".repeat(10);
    put(&rig.file(), &[&first[..], &delta[..]].concat());
    let from = first.len() as u64;
    let (st, _, b) = rig.get(&format!("/transcript?rel={}&from={from}", rel())).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let stat: TranscriptStat = serde_json::from_slice(&b).unwrap();
    assert_eq!((stat.size, stat.sha256.as_deref(), stat.delta_sha256.as_deref(), stat.ino.is_some()), (from + delta.len() as u64, None, Some(sha(&delta).as_str()), true));
    let push = push_of(from, &delta, &segment(1, from));
    let (st, _, b) = rig.post("/transcript/push", &push).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let reply: TranscriptPushReply = serde_json::from_slice(&b).unwrap();
    assert_eq!(reply, TranscriptPushReply { s3_status: 200, s3_code: None, version_id: Some("fake-version-1".into()), len: delta.len() as u64, sha256: sha(&delta) });
    assert_eq!(std::fs::read(saved.join("1.put")).unwrap(), delta, "exactly the delta went to curl");
    let calls = rig.calls();
    assert_eq!(calls.len(), 1);
    let checksum = sha256_b64(&sha(&delta)).unwrap();
    assert_eq!((calls[0].conf("url"), calls[0].conf("proxy")), (vec![push.url.expose().to_string()], vec![PROXY.to_string()]));
    let headers = calls[0].conf("header");
    for h in [format!("Content-Length: {}", delta.len()), format!("x-amz-checksum-sha256: {checksum}"), "If-None-Match: *".into(), format!("x-amz-expected-bucket-owner: {OWNER}")] {
        assert!(headers.contains(&h), "{h}: {headers:?}");
    }
    // A full copy S3 refuses (the key holds an object already): S3's answer, in a 200.
    rig.knobs(&[("S3CURL_STATUS", "412"), ("S3CURL_CODE", "PreconditionFailed")]);
    let whole = std::fs::read(rig.file()).unwrap();
    let (st, _, b) = rig.post("/transcript/push", &push_of(0, &whole, &base(2))).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let reply: TranscriptPushReply = serde_json::from_slice(&b).unwrap();
    assert_eq!(reply, TranscriptPushReply { s3_status: 412, s3_code: Some("PreconditionFailed".into()), version_id: None, len: whole.len() as u64, sha256: sha(&whole) });
    // curl without an HTTP status (the proxy refused the connection).
    rig.knobs(&[("S3CURL_FAIL", "7")]);
    let (st, _, b) = rig.post("/transcript/push", &push_of(from, &delta, &segment(1, from))).await;
    let (code, message) = refused(&b);
    assert_eq!((st, code.as_str()), (500, "transfer_failed"), "{message}");
    assert!(message.starts_with("curl exited 7 before an HTTP status"), "{message}");
    // A range past the file's end: refused by the helper, no curl.
    rig.knobs(&[]);
    let n = rig.calls().len();
    let longer = [&whole[..], b"x"].concat();
    let (st, _, b) = rig.post("/transcript/push", &push_of(0, &longer, &base(3))).await;
    assert_eq!((st, refused(&b).0.as_str()), (409, "changed"));
    assert_eq!(rig.calls().len(), n, "no curl for a refused range");
    // The body's own refusals.
    let mut misfit = push_of(from, &delta, &segment(1, from + 1));
    let (st, _, b) = rig.post("/transcript/push", &misfit).await;
    assert_eq!((st, refused(&b).0.as_str()), (400, "bad_request"), "a segment key at another offset");
    misfit.len = (4 << 30) + 1;
    let (st, _, b) = rig.post("/transcript/push", &misfit).await;
    assert_eq!((st, refused(&b).0.as_str()), (413, "too_large"));
    let json = serde_json::to_vec(&push).unwrap();
    let (st, _, b) = request(rig.s.app, "POST", "/transcript/push", "Content-Type: text/plain\r\n", Some(&json)).await;
    assert_eq!((st, refused(&b).0.as_str()), (400, "bad_request"), "not application/json");
    let (st, _, _) = super::http(rig.s.app, "POST", "/transcript/push", &json, Some("application/json")).await;
    assert_eq!(st, 401, "behind the bearer");
    assert_eq!(rig.calls().len(), n, "none of them started curl");
}

/// A pull rebuilds the VM's copy part by part (S9 §1.4, §3.4): each part's
/// GET (by its version) streamed into the helper, checked, then the
/// rename: 201 with the file's size and sha256 and one report per part,
/// the file 0600; a tail part, whose sha256 the Mac never knew, is taken
/// by its length.
#[tokio::test]
async fn pull_verifies_each_part() {
    let rig = Rig::new().await;
    let bodies = rig.root.join("bodies");
    let (a, b) = (b"{\"n\":1}\n".repeat(50), b"{\"n\":2}\n".repeat(5));
    put(&bodies.join("1"), &a);
    put(&bodies.join("2"), &b);
    rig.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap())]);
    let whole = [&a[..], &b[..]].concat();
    let pull = pull_of(vec![part_of(&base(1), "fv1", &a), part_of(&segment(1, a.len() as u64), "fv2", &b)], Some(&whole));
    let (st, _, body) = rig.post("/transcript/pull", &pull).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&body));
    let reply: TranscriptPullReply = serde_json::from_slice(&body).unwrap();
    let report = |bytes: &[u8]| PullPartReport { s3_status: 200, len: bytes.len() as u64, sha256: sha(bytes), ok: true };
    assert_eq!(reply, TranscriptPullReply { written: true, size: whole.len() as u64, sha256: Some(sha(&whole)), parts: vec![report(&a), report(&b)] });
    assert_eq!(std::fs::read(rig.file()).unwrap(), whole);
    assert_eq!(std::fs::metadata(rig.file()).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(rig.temps().is_empty(), "{:?}", rig.temps());
    let calls = rig.calls();
    assert_eq!(calls.len(), 2);
    for (call, part) in calls.iter().zip(&pull.parts) {
        assert_eq!((call.conf("request"), call.conf("fail"), call.conf("header")), (vec!["GET".to_string()], vec![String::new()], vec![format!("x-amz-expected-bucket-owner: {OWNER}")]));
        assert_eq!(call.conf("url"), [part.url.expose()]);
        assert!(call.conf("url")[0].contains("versionId=fv"), "by its version");
    }
    // The tail S3 holds past the committed bytes: no sha256 to check, its length is.
    let tail = b"{\"n\":3}\n".to_vec();
    put(&bodies.join("3"), &whole);
    put(&bodies.join("4"), &tail);
    let tail_part = PullPart { url: url(&S3Key::Tail { session: S8_ID.into(), gen: 1, offset: whole.len() as u64 }, SIGNED_HEADERS_GET, None), len: tail.len() as u64, sha256: None };
    let (st, _, body) = rig.post("/transcript/pull", &pull_of(vec![part_of(&base(1), "fv1", &whole), tail_part], None)).await;
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(std::fs::read(rig.file()).unwrap(), [&whole[..], &tail[..]].concat());
}

/// A part that is not what the Mac signed keeps the VM's copy (S9 §1.4,
/// X10): another sha256, another length, S3's 403 or a body longer than the
/// part's: 200 with `written: false`, the old copy's size, the reports up to
/// the bad part (its own last), nothing renamed and no temp file left; the
/// whole file's sha256 is checked too; curl without an HTTP status is 500
/// `transfer_failed`, nothing renamed either.
#[tokio::test]
async fn bad_part_keeps_old_copy() {
    let rig = Rig::new().await;
    let own = b"the VM's own copy\n".to_vec();
    put(&rig.file(), &own);
    let bodies = rig.root.join("bodies");
    rig.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap())]);
    let (a, b) = (b"{\"n\":1}\n".repeat(50), b"{\"n\":2}\n".repeat(5));
    let parts = || vec![part_of(&base(1), "fv1", &a), part_of(&segment(1, a.len() as u64), "fv2", &b)];
    let not_b = b"{\"n\":9}\n".repeat(5);
    let mut n = 0;
    for (second, why) in [(not_b.clone(), "another sha256"), (b[..10].to_vec(), "a short part"), ([&b[..], b"more"].concat(), "a part longer than its len")] {
        put(&bodies.join((n + 1).to_string()), &a);
        put(&bodies.join((n + 2).to_string()), &second);
        n += 2;
        let (st, _, body) = rig.post("/transcript/pull", &pull_of(parts(), None)).await;
        assert_eq!(st, 200, "{why}: {}", String::from_utf8_lossy(&body));
        let reply: TranscriptPullReply = serde_json::from_slice(&body).unwrap();
        assert_eq!((reply.written, reply.size, reply.sha256.as_deref(), reply.parts.len()), (false, own.len() as u64, None, 2), "{why}: {reply:?}");
        assert!(reply.parts[0].ok && !reply.parts[1].ok && reply.parts[1].s3_status == 200, "{why}: {reply:?}");
        assert_eq!(std::fs::read(rig.file()).unwrap(), own, "{why}: the VM's copy kept");
        assert!(rig.temps().is_empty(), "{why}: {:?}", rig.temps());
    }
    // Every part right, but not the whole file the Mac knows.
    put(&bodies.join((n + 1).to_string()), &a);
    put(&bodies.join((n + 2).to_string()), &b);
    let (st, _, body) = rig.post("/transcript/pull", &pull_of(parts(), Some(b"another whole file"))).await;
    let reply: TranscriptPullReply = serde_json::from_slice(&body).unwrap();
    assert_eq!((st, reply.written, reply.parts.iter().all(|p| p.ok)), (200, false, true), "{reply:?}");
    assert_eq!(std::fs::read(rig.file()).unwrap(), own);
    // S3 refuses the first part: one report, nothing streamed.
    rig.knobs(&[("S3CURL_STATUS", "403")]);
    let (st, _, body) = rig.post("/transcript/pull", &pull_of(parts(), None)).await;
    let reply: TranscriptPullReply = serde_json::from_slice(&body).unwrap();
    assert_eq!((st, reply.written, reply.size), (200, false, own.len() as u64));
    assert_eq!(reply.parts, [PullPartReport { s3_status: 403, len: 0, sha256: sha(b""), ok: false }]);
    // No HTTP status at all.
    rig.knobs(&[("S3CURL_FAIL", "56")]);
    let (st, _, body) = rig.post("/transcript/pull", &pull_of(parts(), None)).await;
    let (code, message) = refused(&body);
    assert_eq!((st, code.as_str()), (500, "transfer_failed"), "{message}");
    assert!(message.starts_with("curl exited 56 before an HTTP status"), "{message}");
    assert_eq!(std::fs::read(rig.file()).unwrap(), own);
    assert!(rig.temps().is_empty(), "{:?}", rig.temps());
}

/// The helper walks as the agent (invariant 17): a transcript that is a
/// symlink, or under a symlinked directory, is refused 409
/// `symlink_component`, and nothing is read or written through the link.
/// A push is refused before any curl starts. A pull's first part's GET (at
/// most one curl call) may already have started when the helper refuses:
/// the refusal ends it (curl is killed with the stream).
#[tokio::test]
async fn push_refuses_symlinked_transcript() {
    let rig = Rig::new().await;
    let elsewhere = rig.root.join("elsewhere");
    let target = elsewhere.join("secret.jsonl");
    put(&target, b"not the agent's transcript\n");
    std::fs::create_dir_all(rig.projects().join(S8_SLUG)).unwrap();
    std::os::unix::fs::symlink(&target, rig.file()).unwrap();
    let body = std::fs::read(&target).unwrap();
    let (st, _, b) = rig.post("/transcript/push", &push_of(0, &body, &base(1))).await;
    assert_eq!((st, refused(&b).0.as_str()), (409, "symlink_component"));
    let bodies = rig.root.join("bodies");
    put(&bodies.join("1"), b"{}\n");
    rig.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap())]);
    let (st, _, b) = rig.post("/transcript/pull", &pull_of(vec![part_of(&base(1), "fv1", b"{}\n")], None)).await;
    assert_eq!((st, refused(&b).0.as_str()), (409, "symlink_component"));
    assert_eq!(std::fs::read(&target).unwrap(), body, "nothing written through the link");
    // A symlinked project directory.
    std::fs::remove_file(rig.file()).unwrap();
    std::fs::remove_dir(rig.projects().join(S8_SLUG)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, rig.projects().join(S8_SLUG)).unwrap();
    put(&elsewhere.join(format!("{S8_ID}.jsonl")), &body);
    let (st, _, b) = rig.post("/transcript/push", &push_of(0, &body, &base(1))).await;
    assert_eq!((st, refused(&b).0.as_str()), (409, "symlink_component"));
    assert!(rig.calls().iter().all(|c| c.conf("request") != ["PUT"]), "no push ever reached curl: {:?}", rig.calls());
    assert!(rig.calls().is_empty() || rig.calls().len() == 1, "at most the pull's GET, which the helper's refusal ended: {:?}", rig.calls());
}

/// curl's configuration is pinned line by line (S9 §3.4): a push through
/// the proxy, a pull part, a tail at `/suspend`, a lab URL (plain http);
/// every call's argv is exactly `-q -K /dev/fd/3`, its only descriptor past
/// stderr is fd 3, it runs as the shim's uid when the shim is not root (as
/// `ai-env-net` when it is), and `max-time` is the budget left.
#[tokio::test]
async fn the_curl_config_is_pinned() {
    let rig = Rig::new().await;
    let bodies = rig.root.join("bodies");
    rig.knobs(&[("S3CURL_BODIES", bodies.to_str().unwrap())]);
    let text = b"{\"type\":\"user\"}\n".to_vec();
    put(&rig.file(), &text);
    let push = push_of(0, &text, &base(1));
    assert_eq!(rig.post("/transcript/push", &push).await.0, 200);
    put(&bodies.join("2"), &text);
    let part = part_of(&base(1), "fv1", &text);
    let mut pull = pull_of(vec![part], None);
    pull.proxy = None;
    assert_eq!(rig.post("/transcript/pull", &pull).await.0, 201);
    let lab = TranscriptPush { url: url_at(&base(2), SIGNED_HEADERS_PUT, None, true), proxy: None, ..push_of(0, &text, &base(2)) };
    assert_eq!(rig.post("/transcript/push", &lab).await.0, 200);
    let tail_url = url(&S3Key::Tail { session: S8_ID.into(), gen: 1, offset: text.len() as u64 }, SIGNED_HEADERS_TAIL, None);
    let tail = TranscriptTail { rel: rel(), from: text.len() as u64, url: tail_url, owner: OWNER.into(), proxy: Some(PROXY.into()), expires_at: ai_env_cli::wire::time::unix_now() + 3600 };
    assert_eq!(rig.post("/transcript/tail", &tail).await.0, 204);
    std::fs::OpenOptions::new().append(true).open(rig.file()).unwrap().write_all(b"{\"late\":1}\n").unwrap();
    assert_eq!(hook(rig.s.hooks, "suspend", b"").await.0, 200);
    let calls = rig.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    let checksum = sha256_b64(&sha(&text)).unwrap();
    let want = [
        config(&push.url, "https", "<t>", Some(PROXY), &put_lines(text.len(), Some(&checksum))),
        config(&pull.parts[0].url, "https", "<t>", None, &format!("request = \"GET\"\nheader = \"x-amz-expected-bucket-owner: {OWNER}\"\nfail\noutput = \"-\"\n")),
        config(&lab.url, "http", "<t>", None, &put_lines(text.len(), Some(&checksum))),
        config(&tail.url, "https", "<t>", Some(PROXY), &put_lines(11, None)),
    ];
    let budgets = [60 + 30, 60 + 30, 60 + 30, 8];
    // SAFETY: geteuid cannot fail.
    let uid = unsafe { libc::geteuid() };
    for ((call, want), most) in calls.iter().zip(&want).zip(budgets) {
        let (got, secs) = timed(call);
        assert_eq!(&got, want);
        assert!((1..=most).contains(&secs), "max-time {secs}: the budget left, at most {most}");
        assert_eq!((call.args.as_slice(), call.fds.as_slice(), call.uid), (&["-q".to_string(), "-K".to_string(), "/dev/fd/3".to_string()][..], &[3][..], uid), "{call:?}");
        assert!(!call.args.iter().any(|a| a.contains("X-Amz")), "no URL in an argv");
    }
}

/// The tail (S9 §1.4, X8): kept by `POST /transcript/tail` (204), pushed
/// by `/suspend` only once the file grew past its `from`, at most once;
/// one kept for another session's transcript waits for `/terminate`, which
/// pushes it while the shim stops; an expired one is never pushed. Each
/// push is the bytes past `from` alone, with no checksum.
#[tokio::test]
async fn the_tail_is_pushed_at_suspend_and_terminate() {
    let rig = Rig::new().await;
    let saved = rig.root.join("saved");
    rig.knobs(&[("S3CURL_SAVE", saved.to_str().unwrap())]);
    let first = b"{\"type\":\"user\"}\n".repeat(6);
    put(&rig.file(), &first);
    let now = ai_env_cli::wire::time::unix_now();
    let tail_of = |rel: String, session: &str, from: u64, expires_at: u64| TranscriptTail {
        rel,
        from,
        url: url(&S3Key::Tail { session: session.into(), gen: 1, offset: from }, SIGNED_HEADERS_TAIL, None),
        owner: OWNER.into(),
        proxy: Some(PROXY.into()),
        expires_at,
    };
    assert_eq!(rig.post("/transcript/tail", &tail_of(rel(), S8_ID, first.len() as u64, now + 3600)).await.0, 204);
    assert_eq!(hook(rig.s.hooks, "suspend", b"").await.0, 200);
    assert!(rig.calls().is_empty(), "the file did not grow: nothing pushed");
    let late = b"{\"type\":\"summary\"}\n".to_vec();
    std::fs::OpenOptions::new().append(true).open(rig.file()).unwrap().write_all(&late).unwrap();
    assert_eq!(hook(rig.s.hooks, "suspend", b"").await.0, 200);
    let calls = rig.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(std::fs::read(saved.join("1.put")).unwrap(), late, "the bytes past from alone");
    assert!(calls[0].conf("header").iter().all(|h| !h.starts_with("x-amz-checksum-sha256")), "no checksum on a tail: {:?}", calls[0].conf("header"));
    assert_eq!(hook(rig.s.hooks, "suspend", b"").await.0, 200);
    assert_eq!(rig.calls().len(), 1, "at most once");
    // Another session's tail waits for /terminate; an expired one is dropped.
    let (next, other) = ("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d", "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c");
    put(&rig.projects().join(format!("{S8_SLUG}/{next}.jsonl")), b"{\"next\":1}\n");
    assert_eq!(rig.post("/transcript/tail", &tail_of(format!("{S8_SLUG}/{next}.jsonl"), next, 0, now + 3600)).await.0, 204);
    put(&rig.projects().join(format!("{S8_SLUG}/{other}.jsonl")), b"{\"other\":1}\n");
    assert_eq!(rig.post("/transcript/tail", &tail_of(format!("{S8_SLUG}/{other}.jsonl"), other, 0, now.saturating_sub(1))).await.0, 204);
    assert_eq!(hook(rig.s.hooks, "terminate", b"").await.0, 200);
    let calls = rig.calls();
    assert_eq!(calls.len(), 2, "the next session's tail alone: {calls:?}");
    assert_eq!(std::fs::read(saved.join("2.put")).unwrap(), b"{\"next\":1}\n");
    assert!(calls[1].conf("url")[0].contains(&format!("/v1/{next}/vm/g1/t/0000000000000000?")), "{:?}", calls[1].conf("url"));
}

/// A tail is only ever a session's main transcript's (S9 §13, I2): its key
/// names no file, so `POST /transcript/tail` of a subtree file is 400
/// `bad_request` and kept nowhere (`/suspend` and `/terminate` push nothing
/// for it however the file grew), and a pull that would append a tail to a
/// subtree file is 400 too; no curl runs.
#[tokio::test]
async fn a_tail_of_a_subtree_file_is_refused() {
    let rig = Rig::new().await;
    let sub = format!("{S8_SLUG}/{S8_ID}/subagents/agent-a1.jsonl");
    let agent = b"{\"agent\":1}\n".to_vec();
    put(&rig.projects().join(&sub), &agent);
    let at = agent.len() as u64;
    let tail_key = S3Key::Tail { session: S8_ID.into(), gen: 1, offset: at };
    let tail = TranscriptTail { rel: sub.clone(), from: at, url: url(&tail_key, SIGNED_HEADERS_TAIL, None), owner: OWNER.into(), proxy: Some(PROXY.into()), expires_at: ai_env_cli::wire::time::unix_now() + 3600 };
    let (st, _, b) = rig.post("/transcript/tail", &tail).await;
    let (code, message) = refused(&b);
    assert_eq!((st, code.as_str()), (400, "bad_request"), "{message}");
    assert!(message.contains("a tail is only ever the session's main transcript"), "{message}");
    std::fs::OpenOptions::new().append(true).open(rig.projects().join(&sub)).unwrap().write_all(b"{\"agent\":2}\n").unwrap();
    assert_eq!(hook(rig.s.hooks, "suspend", b"").await.0, 200);
    let file = S3Key::File { session: S8_ID.into(), sha256: sha(&agent) };
    let pull = TranscriptPull { rel: sub, parts: vec![part_of(&file, "fv1", &agent), PullPart { url: url(&tail_key, SIGNED_HEADERS_GET, None), len: 12, sha256: None }], sha256: None, owner: OWNER.into(), proxy: Some(PROXY.into()) };
    let (st, _, b) = rig.post("/transcript/pull", &pull).await;
    let (code, message) = refused(&b);
    assert_eq!((st, code.as_str()), (400, "bad_request"), "{message}");
    assert!(message.contains("a tail (part number 1)"), "{message}");
    assert_eq!(hook(rig.s.hooks, "terminate", b"").await.0, 200);
    assert!(rig.calls().is_empty(), "no curl ever ran: {:?}", rig.calls());
}

/// One transfer per rel at a time (S9 §1.4): a second push of the rel waits
/// for the shim's busy wait, then 409 `busy` with `Retry-After: 5`; the
/// first goes on to its answer.
#[tokio::test]
async fn a_second_transfer_of_a_rel_waits_then_is_busy() {
    let rig = Rig::new().await;
    rig.s.state.workspace.set_busy_wait(Duration::from_millis(300));
    rig.knobs(&[("S3CURL_SLOW_MS", "2500")]);
    let text = b"{\"type\":\"user\"}\n".to_vec();
    put(&rig.file(), &text);
    let first = tokio::spawn({
        let (app, json) = (rig.s.app, serde_json::to_vec(&push_of(0, &text, &base(1))).unwrap());
        async move { request(app, "POST", "/transcript/push", "Content-Type: application/json\r\n", Some(&json)).await }
    });
    let until = std::time::Instant::now() + Duration::from_secs(20);
    while rig.calls().is_empty() {
        assert!(std::time::Instant::now() < until, "the first push never reached curl");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (st, head, b) = rig.post("/transcript/push", &push_of(0, &text, &base(2))).await;
    assert_eq!((st, refused(&b).0.as_str()), (409, "busy"));
    assert!(head.to_ascii_lowercase().contains("retry-after: 5"), "{head}");
    assert_eq!(first.await.unwrap().0, 200);
}

/// The view (S9 §1.4, §6.1): an absent transcript answers `present:
/// false`; the example tail answers §6.1's example, through the helper's
/// payload; a query the Mac never sends is 400.
#[tokio::test]
async fn the_view_answers_the_last_messages() {
    let rig = Rig::new().await;
    let path = format!("/transcript/view?rel={}&n=10", rel());
    let (st, _, b) = rig.get(&path).await;
    assert_eq!((st, String::from_utf8_lossy(&b).into_owned()), (200, r#"{"v":1,"present":false,"entries":[]}"#.to_string()));
    put(&rig.file(), include_bytes!("../fixtures/view/tails/example.jsonl"));
    let (st, _, b) = rig.get(&path).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let reply: TranscriptViewReply = serde_json::from_slice(&b).unwrap();
    let golden = r#"{"v":1,"present":true,"title":"Fix the seed's shallow boundary","version":"2.1.302","git_branch":"dev","entries":[{"role":"user","uuid":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60","timestamp":"2026-10-17T10:15:30.123Z","blocks":["Why does the update fail?"]},{"role":"assistant","uuid":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61","timestamp":"2026-10-17T10:15:41.456Z","blocks":["The boundary list was empty.","[tool: Bash]","Fixed in snapshot.rs."]}]}"#;
    assert_eq!(serde_json::to_string(&reply).unwrap(), golden);
    for bad in [format!("/transcript/view?rel={}&n=0", rel()), format!("/transcript/view?rel={}&n=51", rel()), format!("/transcript/view?rel={S8_SLUG}/{S8_ID}/subagents/a.jsonl&n=1"), "/transcript/view?n=1".to_string()] {
        let (st, _, b) = rig.get(&bad).await;
        assert_eq!((st, refused(&b).0.as_str()), (400, "bad_request"), "{bad}");
    }
}

/// The extended stat through the route (S9 §1.4): with `subtree`, the
/// session's files come back by rel with their sha256 (the helper's payload
/// form); without any S9 parameter it is S8's stat; a fingerprint without
/// `from` is 400.
#[tokio::test]
async fn the_extended_stat_lists_the_subtree() {
    let rig = Rig::new().await;
    let text = b"{\"type\":\"user\"}\n".to_vec();
    put(&rig.file(), &text);
    let agent = b"{\"agent\":1}\n".to_vec();
    put(&rig.projects().join(format!("{S8_SLUG}/{S8_ID}/subagents/agent-a1.jsonl")), &agent);
    let fp = sha(&text);
    let (st, _, b) = rig.get(&format!("/transcript?rel={}&from={}&fp={fp}&subtree=true", rel(), text.len())).await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let stat: TranscriptStat = serde_json::from_slice(&b).unwrap();
    assert_eq!((stat.fp_ok, stat.end_fp.as_deref(), stat.subtree.len()), (Some(true), Some(fp.as_str()), 1), "{stat:?}");
    assert_eq!((stat.subtree[0].rel.as_str(), stat.subtree[0].size, stat.subtree[0].sha256.as_str()), (format!("{S8_SLUG}/{S8_ID}/subagents/agent-a1.jsonl").as_str(), agent.len() as u64, sha(&agent).as_str()));
    let (st, _, b) = rig.get(&format!("/transcript?rel={}", rel())).await;
    let s8: TranscriptStat = serde_json::from_slice(&b).unwrap();
    assert_eq!((st, s8.sha256.as_deref(), s8.ino, s8.subtree.len()), (200, Some(sha(&text).as_str()), None, 0), "S8's stat, unchanged");
    let (st, _, b) = rig.get(&format!("/transcript?rel={}&fp={fp}", rel())).await;
    assert_eq!((st, refused(&b).0.as_str()), (400, "bad_request"));
}

