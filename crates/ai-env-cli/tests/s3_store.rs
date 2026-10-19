//! S9 wave 1 (G4): the S3 transcript store on the Mac — the presigns, the
//! multipart upload of a Mac-begun chat ([`stage`]), the manifest, the
//! per-turn sync, the restore, `session gc --remote` and `forget --purge`,
//! and the data plane's five transfer requests — against the tests' S3
//! (`common::fake_s3`), the fake API (its lab-key presigner) and a VM in
//! miniature ([`FakeVm`]: G5's shim as the Mac sees it, its pushes and
//! pulls going to the tests' S3 through the presigned URLs as curl sends
//! them), offline. The lead's S3 round trip (§11, after the cut-over) ends
//! the file: the real `ai-env-claude` in remote mode through the remote rig
//! (`common::remote`), its VM's real helper and curl moving the bytes.
#![cfg(all(feature = "bridge", feature = "shim"))]

mod common;

use common::fake_s3;

use ai_env_cli::bridge::agent::AgentTarget;
use ai_env_cli::bridge::api::{AuthToken, FakeMicrovmApi, TOKEN_HEADER};
use ai_env_cli::bridge::config::{BridgeConfig, Paths};
use ai_env_cli::bridge::dataplane::{verdict_cap, CodeoutBody, DataPlane, DpReply, HttpsEndpoint, TokenSource, Verdict};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::lab::VmKnobs;
use ai_env_cli::bridge::s3::client::{Body, S3Client, Written};
use ai_env_cli::bridge::s3::manifest::{self, Manifest};
use ai_env_cli::bridge::s3::stage::{self as s3stage, MacChat};
use ai_env_cli::bridge::s3::sync::{SyncCtx, SyncReport};
use ai_env_cli::bridge::s3::{PresignReq, S3Endpoint, S3Sign, S3Target, TranscriptSync, LAB_BUCKET, LAB_OWNER};
use ai_env_cli::bridge::scan::Rules;
use ai_env_cli::bridge::view::ViewOutcome;
use ai_env_cli::bridge::workspace::transcript::digest_file;
use ai_env_cli::bridge::workspace::{EnsureCtx, Head, SeedLimits, TranscriptOutcome, WorkspaceRef, WsKind};
use ai_env_cli::wire::frame::CAP_TRANSCRIPT_S3_V1;
use ai_env_cli::wire::redact::Secret;
use ai_env_cli::wire::s3::{sha256_b64, PresignedUrl, S3Key, FP_SPAN, MULTIPART_PART};
use ai_env_cli::wire::view::{TranscriptViewReply, VIEW_MARK_PREFIX};
use ai_env_cli::wire::workspace::{
    CodeoutRequest, ObjectFormat, PullPartReport, SeedQuery, SeedReply, SeedState, SettingsCapture, StatQuery, SubtreeFile, TranscriptPull, TranscriptPullReply, TranscriptPush,
    TranscriptPushReply, TranscriptStat, TranscriptTail, ViewQuery, APP_PORT,
};
use fake_s3::{FakeS3, S3Action};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
const SLUG: &str = "-Users-mike-Documents-DeFi-ai-env";
const VM: &str = "microvm-0123456789abcdef";

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A bridge root under a tempdir, with the lab S3 as its transcripts bucket.
struct World {
    _tmp: tempfile::TempDir,
    paths: Paths,
    cfg: BridgeConfig,
    projects: std::path::PathBuf,
    target: S3Target,
    s3: FakeS3,
}

impl World {
    fn new(s3: FakeS3) -> World {
        let tmp = tempfile::tempdir().unwrap();
        let target = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(s3.addr()) };
        World { paths: Paths::from_root_and_env(tmp.path().join("bridge"), None), cfg: BridgeConfig::default(), projects: tmp.path().join("projects"), target, s3, _tmp: tmp }
    }

    /// Plant `<SLUG>/<rel>` holding `bytes`.
    fn plant(&self, rel: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = self.projects.join(SLUG).join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn client(&self) -> S3Client<'_, FakeMicrovmApi> {
        // The fake API presigns with the lab key, which the fake S3 verifies.
        let api: &'static FakeMicrovmApi = Box::leak(Box::new(FakeMicrovmApi::new()));
        S3Client::new(api, &self.target).unwrap()
    }

    fn rt(&self) -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    /// The audit's rows of `event`.
    fn rows(&self, event: &str) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(self.paths.audit()).unwrap_or_default();
        text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).collect()
    }

    /// The view's path in the projects directory.
    fn view_path(&self) -> PathBuf {
        self.projects.join(SLUG).join(format!("{SID}.jsonl"))
    }

    fn manifest(&self) -> Option<Manifest> {
        manifest::read(&self.paths, SID).unwrap()
    }

    /// This world with a git repository under `[workspaces].roots`, the cwd
    /// a chat of this Mac records (the stage refuses a chat that could
    /// never reopen remote): the world and the repository, canonical.
    fn with_workspace(mut self) -> (World, PathBuf) {
        let work = self._tmp.path().join("work");
        let repo = work.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        for args in [&["init", "-q"][..], &["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "i"]] {
            let o = std::process::Command::new("git").args(args).current_dir(&repo).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
            assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        }
        self.cfg = BridgeConfig::parse(&format!("[workspaces]\nroots = [{:?}]\n", std::fs::canonicalize(&work).unwrap())).unwrap();
        let repo = std::fs::canonicalize(&repo).unwrap();
        (self, repo)
    }
}

/// A transcript's first line naming `cwd`, where the chat began.
fn cwd_line(cwd: &Path) -> Vec<u8> {
    let mut l = serde_json::json!({"type": "user", "cwd": cwd, "sessionId": SID, "message": {"role": "user", "content": "start"}}).to_string().into_bytes();
    l.push(b'\n');
    l
}

/// A transcript line of `n` bytes (a plausible jsonl entry, padded).
fn line(tag: &str, n: usize) -> Vec<u8> {
    let mut l = format!("{{\"type\":\"user\",\"message\":{{\"content\":\"{tag}\"}},\"pad\":\"");
    while l.len() < n - 3 {
        l.push('x');
    }
    l.push_str("\"}\n");
    l.into_bytes()
}

/// plans/s9-contracts.md §6.1's example view reply (tests/fixtures/view/reply.json).
fn example() -> TranscriptViewReply {
    serde_json::from_str(include_str!("fixtures/view/reply.json")).unwrap()
}

/// A view builder for the Mac-side builds (G5 builds `wire::view::build_view`): the example, whatever the tail.
fn builder(_tail: &[u8], _n: u32) -> Result<TranscriptViewReply, String> {
    Ok(example())
}

/// A builder that cannot build (a tail the builder refuses).
fn no_builder(_tail: &[u8], _n: u32) -> Result<TranscriptViewReply, String> {
    Err("no view in this tail".into())
}

/// One HTTP/1.1 exchange with a loopback server that answers one request per
/// connection and closes (the fake S3): the status, the headers (lowercase
/// names) and the body.
async fn http(method: &str, url: &str, headers: &[(&str, String)], body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let rest = url.strip_prefix("http://").expect("a lab URL");
    let (host, path) = rest.split_at(rest.find('/').expect("a path"));
    let mut s = tokio::net::TcpStream::connect(host).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("an answer's head");
    let text = String::from_utf8_lossy(&resp[..end]).into_owned();
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let hs = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    (status, hs, resp[end + 4..].to_vec())
}

/// S3's `<Code>` in an error body.
fn code_of(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let (_, rest) = text.split_once("<Code>")?;
    rest.split_once("</Code>").map(|(c, _)| c.to_string())
}

// ---- session stage: the multipart upload, the scan, bounded memory (§11's stage::…) ----

mod stage {
    use super::*;

    /// A staging upload resumes after a cut: the first run's part 3 is
    /// refused (500) at each of its three tries, so the upload fails with
    /// `stage.toml` holding its upload id and the parts it saw land; a part
    /// S3 lists with another size (one written there since) is sent again
    /// on the resume, the parts S3 lists as they should be are not, the
    /// resume asks ListParts before any UploadPart, never creates a second
    /// upload, and the object S3 ends with is the chat's bytes, by its
    /// sha256 key.
    #[test]
    fn multipart_resumes_after_cut() {
        let w = World::new(FakeS3::start());
        let part = 1usize << 20; // 1 MiB parts in the test
        let mut bytes = Vec::new();
        for i in 0..5 {
            bytes.extend_from_slice(&line(&format!("turn {i}"), part));
        }
        let path = w.plant(&format!("{SID}.jsonl"), &bytes);
        let d = digest_file(&Rules::defaults(), &path, bytes.len() as u64, part as u64).unwrap();
        assert_eq!(d.parts.len(), 5, "five parts");
        let key = S3Key::Mac { session: SID.into(), sha256: d.sha256.clone() }.render();
        // A 500 is tried again (client::PART_TRIES): part 3 gets one at each of its tries.
        w.s3.script_part(3, vec![S3Action::Status { status: 500, code: "InternalError" }; 3]);
        let client = w.client();
        let first = w.rt().block_on(s3stage::upload_file(&client, &w.paths, SID, &key, &path, &d, part as u64));
        assert!(matches!(first, Err(BridgeError::S3 { status: 500, .. })), "the refused part fails the upload: {first:?}");
        assert_eq!(w.s3.requests().iter().filter(|r| r.part == Some(3)).map(|r| r.status).collect::<Vec<_>>(), [500; 3], "three tries of part 3");
        let saved = s3stage::read_stage(&w.paths, SID).unwrap().expect("a stage file after the failure");
        assert_eq!((saved.key.as_str(), saved.part_len), (key.as_str(), part as u64));
        // The parts in flight when the failure ended the run land (or not) on the fake's own thread: wait until it is quiet.
        let mut quiet = (w.s3.requests().len(), std::time::Instant::now());
        while quiet.1.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let n = w.s3.requests().len();
            if n == quiet.0 {
                break;
            }
            quiet.0 = n;
        }
        let run1 = w.s3.requests().len();
        let put_part = |r: &fake_s3::S3Request| r.method == "PUT" && r.query_names.iter().any(|n| n == "partNumber");
        let landed_1 = w.s3.requests().iter().filter(|r| put_part(r) && r.status == 200).count();
        // A part 5 of another size lands in the upload (whether or not part 5 landed before): S3 lists it, wrong.
        let before = w.rt().block_on(client.list_parts(&key, &saved.upload_id)).unwrap().unwrap();
        let had_5 = before.iter().any(|p| p.number == 5);
        let junk = b"not the fifth part".to_vec();
        let (junk_len, junk_sum) = (junk.len().to_string(), sha256_b64(&sha(&junk)).unwrap());
        let url = w.s3.presign("PUT", &key, &[("partNumber", "5"), ("uploadId", saved.upload_id.as_str())], &[("content-length", junk_len.as_str()), ("x-amz-checksum-sha256", junk_sum.as_str())], std::time::Duration::from_secs(300));
        let (status, _, _) = w.rt().block_on(http("PUT", &url, &[("content-length", junk.len().to_string()), ("x-amz-checksum-sha256", sha256_b64(&sha(&junk)).unwrap()), ("x-amz-expected-bucket-owner", LAB_OWNER.into())], &junk));
        assert_eq!(status, 200, "the junk part lands");
        let listed = w.rt().block_on(client.list_parts(&key, &saved.upload_id)).unwrap().unwrap();
        let good = listed.iter().filter(|p| p.number < 5 && p.size == part as u64 && p.checksum.as_deref() == sha256_b64(&d.parts[p.number as usize - 1]).as_deref()).count();
        assert!(listed.iter().any(|p| p.number == 5 && p.size == junk.len() as u64), "{listed:?}");
        let run2_from = w.s3.requests().len();
        // The resume: the same upload id, the missing and the wrong parts sent, the upload completes.
        let up = w.rt().block_on(s3stage::upload_file(&client, &w.paths, SID, &key, &path, &d, part as u64)).unwrap();
        assert!(up.resumed && !up.existed && up.parts == 5, "{up:?}");
        assert!(s3stage::read_stage(&w.paths, SID).unwrap().is_none(), "the stage file is gone once complete");
        let run2: Vec<fake_s3::S3Request> = w.s3.requests()[run2_from..].to_vec();
        let list_at = run2.iter().position(|r| r.method == "GET" && r.query_names.iter().any(|n| n == "uploadId")).expect("ListParts on the resume");
        let first_put = run2.iter().position(put_part).expect("UploadParts on the resume");
        assert!(list_at < first_put, "ListParts before any UploadPart: {run2:?}");
        let sent_2 = run2.iter().filter(|r| put_part(r) && r.status == 200).count();
        assert_eq!(sent_2, 5 - good, "only the parts S3 does not hold as they should be go again (part 5 among them): {listed:?}");
        // Each part number landed once from the Mac across both runs, but part 5, which the junk replaced after it landed.
        assert_eq!(landed_1 + sent_2, 5 + usize::from(had_5), "{run1} requests in run 1");
        assert!(run2.iter().any(|r| r.method == "POST" && r.query_names.iter().any(|n| n == "uploadId") && r.status == 200), "a CompleteMultipartUpload of the resumed id");
        assert_eq!(w.s3.get(&key).as_deref(), Some(bytes.as_slice()), "S3 holds the chat's bytes");
        assert!(w.s3.objects().iter().any(|o| o.key == key && o.current && o.sha256 == d.sha256));
        assert_eq!(w.s3.requests().iter().filter(|r| r.method == "POST" && r.query_names.iter().any(|n| n == "uploads")).count(), 1, "one CreateMultipartUpload across both runs");
    }

    /// The fake API's presigner, keeping the part number of each UploadPart it presigned.
    struct Counting {
        api: FakeMicrovmApi,
        parts: std::sync::Arc<Mutex<Vec<u32>>>,
    }

    impl S3Sign for Counting {
        async fn presign(&self, req: &PresignReq) -> Result<PresignedUrl, BridgeError> {
            if let Some((_, n)) = req.query.iter().find(|(k, _)| k == "partNumber") {
                self.parts.lock().unwrap().push(n.parse().unwrap());
            }
            self.api.presign(req).await
        }
    }

    /// A chat of four 1 MiB parts (the last a few bytes) whose transcript
    /// records the world's repository; its sha256 key.
    fn four_parts(w: &World, repo: &Path) -> (Vec<u8>, String) {
        let bytes = [cwd_line(repo), line("turn 0", 1 << 20), line("turn 1", 1 << 20), line("turn 2", 1 << 20)].concat();
        w.plant(&format!("{SID}.jsonl"), &bytes);
        let key = S3Key::Mac { session: SID.into(), sha256: sha(&bytes) }.render();
        (bytes, key)
    }

    /// B6 (a): a part that gets no answer (its connection closed unanswered,
    /// as a timeout or a reset leaves it) is sent again, presigned anew, and
    /// so is one S3 answers 503 `SlowDown`; `session stage` completes and S3
    /// holds the chat's bytes.
    #[test]
    fn a_part_with_no_answer_is_sent_again_and_the_stage_completes() {
        let (w, repo) = World::new(FakeS3::start()).with_workspace();
        let (bytes, key) = four_parts(&w, &repo);
        w.s3.script_part(2, vec![S3Action::CutAfter { bytes: 0 }]);
        w.s3.script_part(3, vec![S3Action::Status { status: 503, code: "SlowDown" }]);
        let presigned = std::sync::Arc::new(Mutex::new(Vec::new()));
        let signer = Counting { api: FakeMicrovmApi::new(), parts: presigned.clone() };
        let report = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, 1 << 20, &builder, move || async move { Ok(signer) })).unwrap();
        assert_eq!((report.outcome, report.parts, report.key.as_str()), ("staged", 4, key.as_str()));
        assert_eq!(w.s3.get(&key).as_deref(), Some(bytes.as_slice()), "S3 holds the chat's bytes");
        let tries = |n: u32| w.s3.requests().iter().filter(|r| r.part == Some(n)).map(|r| r.status).collect::<Vec<_>>();
        assert_eq!((tries(1), tries(2), tries(3), tries(4)), (vec![200], vec![0, 200], vec![503, 200], vec![200]), "{:?}", w.s3.requests());
        let mut signed = presigned.lock().unwrap().clone();
        signed.sort_unstable();
        assert_eq!(signed, [1, 2, 2, 3, 3, 4], "each try presigned anew");
    }

    /// B6 (a): a part with no answer at each of its three tries ends the
    /// stage, exit 7, naming the part, the tries and the cause (reqwest's
    /// error and its source chain), never the URL (no scheme, address,
    /// bucket or signature, nothing scrubbed out of it). The stage file
    /// keeps the parts that landed, no manifest is written, the original
    /// stays in place; a rerun resumes and sends that part alone.
    #[test]
    fn a_part_with_no_answer_at_every_try_ends_the_stage_naming_the_cause() {
        let (w, repo) = World::new(FakeS3::start()).with_workspace();
        let (bytes, key) = four_parts(&w, &repo);
        w.s3.script_part(2, vec![S3Action::CutAfter { bytes: 0 }; 3]);
        let presigned = std::sync::Arc::new(Mutex::new(Vec::new()));
        let signer = Counting { api: FakeMicrovmApi::new(), parts: presigned.clone() };
        let err = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, 1 << 20, &builder, move || async move { Ok(signer) })).unwrap_err();
        let text = err.to_string();
        let head = format!("aws s3 upload part: part 2 of {key}: no answer in 3 tries: error sending request: ");
        assert!(text.starts_with(&head) && text.len() > head.len(), "the cause after reqwest's own words: {text}");
        for never in ["http", &w.s3.addr().to_string(), LAB_BUCKET, "X-Amz", "redacted"] {
            assert!(!text.contains(never), "{never:?} in {text}");
        }
        assert_eq!(ai_env_cli::errors::CliError::from(err).exit_code(), 7);
        assert_eq!(w.s3.requests().iter().filter(|r| r.part == Some(2)).map(|r| r.status).collect::<Vec<_>>(), [0; 3], "three tries, none answered");
        assert_eq!(presigned.lock().unwrap().iter().filter(|n| **n == 2).count(), 3, "each try presigned anew");
        let saved = s3stage::read_stage(&w.paths, SID).unwrap().expect("the stage file stays");
        assert_eq!(saved.parts.iter().map(|p| p.number).collect::<Vec<_>>(), [1, 3, 4]);
        assert!(w.manifest().is_none(), "no manifest");
        assert_eq!(std::fs::read(w.view_path()).unwrap(), bytes, "the original stays in place");
        // The rerun: part 2 alone, the upload completed.
        let from = w.s3.requests().len();
        let again = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, 1 << 20, &builder, || async { Ok(FakeMicrovmApi::new()) })).unwrap();
        assert_eq!(again.outcome, "resumed");
        assert_eq!(w.s3.requests()[from..].iter().filter_map(|r| r.part).collect::<Vec<_>>(), [2]);
        assert_eq!(w.s3.get(&key).as_deref(), Some(bytes.as_slice()));
    }

    /// A part S3 answers 503 `SlowDown` and then not at all (two connections
    /// closed unanswered) ends the stage, exit 7, naming both: no answer at
    /// the last of its three tries, and the 503 before it (S3 did answer).
    #[test]
    fn a_part_answered_503_and_then_not_at_all_names_both() {
        let (w, repo) = World::new(FakeS3::start()).with_workspace();
        let (_, key) = four_parts(&w, &repo);
        w.s3.script_part(2, vec![S3Action::Status { status: 503, code: "SlowDown" }, S3Action::CutAfter { bytes: 0 }, S3Action::CutAfter { bytes: 0 }]);
        let err = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, 1 << 20, &builder, || async { Ok(FakeMicrovmApi::new()) })).unwrap_err();
        let text = err.to_string();
        let head = format!("aws s3 upload part: part 2 of {key}: no answer at the last of 3 tries (S3 answered HTTP 503 (SlowDown) before): error sending request: ");
        assert!(text.starts_with(&head) && text.len() > head.len(), "the 503, then the cause: {text}");
        assert_eq!(ai_env_cli::errors::CliError::from(err).exit_code(), 7);
        assert_eq!(w.s3.requests().iter().filter(|r| r.part == Some(2)).map(|r| r.status).collect::<Vec<_>>(), [503, 0, 0], "one answer, then two tries unanswered");
    }

    /// A chat whose subagent file trips a tripwire is refused before any
    /// request and before the runtime key is unsealed: `session stage`'s
    /// whole path (`stage::stage`) errors with the finding (exit 9) naming
    /// the file, the line and the rule, never the value; the tests' S3 saw
    /// nothing, no stage file or manifest exists, the original stays.
    #[test]
    fn finding_refuses_before_any_request() {
        let (w, repo) = World::new(FakeS3::start()).with_workspace();
        let key = format!("{}{}", "AKIA", "Q".repeat(16));
        let original = [cwd_line(&repo), line("hello", 200)].concat();
        let main = w.plant(&format!("{SID}.jsonl"), &original);
        w.plant(&format!("{SID}/subagents/agent-a1.jsonl"), format!("aws_access_key_id = {key}\n").as_bytes());
        let unsealed = std::cell::Cell::new(false);
        let unseal = || async {
            unsealed.set(true);
            Ok(FakeMicrovmApi::new())
        };
        let err = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, MULTIPART_PART, &|_, _| panic!("no view is built"), unseal)).unwrap_err();
        let msg = match &err {
            BridgeError::WorkspaceRefused { code: "finding", message } => message.clone(),
            other => panic!("not a finding: {other:?}"),
        };
        assert!(msg.contains(&format!("transcript:{SID}/subagents/agent-a1.jsonl line 1: rule aws-access-key-id")), "{msg}");
        assert!(!msg.contains(&key), "no value in the finding");
        assert_eq!(ai_env_cli::errors::CliError::from(err).exit_code(), 9);
        assert!(!unsealed.get(), "the runtime key is never unsealed for a chat with a finding");
        assert!(w.s3.requests().is_empty(), "nothing was sent");
        assert!(!w.paths.transcript_stage(SID).exists() && w.manifest().is_none(), "no stage file, no manifest");
        assert_eq!(std::fs::read(&main).unwrap(), original, "the original stays in place");
        // The clean transcript alone scans without error.
        let chat = s3stage::locate(&w.projects, &[SLUG], SID, s3stage::STAGE_MAX).unwrap().expect("the chat");
        let clean = MacChat { files: vec![(format!("{SID}.jsonl"), original.len() as u64)], ..chat };
        assert!(s3stage::scan_chat(&Rules::defaults(), &clean, MULTIPART_PART).is_ok());
    }

    /// The streaming scan and digest hold bounded memory whatever the
    /// length: over 2 GiB of transcript (lines of 12 MiB, so each is
    /// scanned first in windows, then whole at its newline) the most bytes
    /// held at once is exactly what 16 MiB of the same lines hold — a chunk,
    /// the scan's window and carry, the fingerprint's tail — and the
    /// process's resident set stays far under the stream. The upload of such
    /// a file is a stream of `MULTIPART_PART` ranges (`client::file_range`);
    /// the live round trip is part B's. The slowest test of the binary: a
    /// debug build hashes in software (about 23 MB/s, twice per byte), so
    /// the 2 GiB take some minutes.
    #[test]
    fn two_gib_in_bounded_memory() {
        use ai_env_cli::bridge::workspace::transcript::digest_stream;
        /// `left` bytes of lines of `line` bytes (`.`s, which start no tripwire's literal, then a newline), never
        /// allocated whole.
        struct Lines {
            left: u64,
            at: u64,
            line: u64,
        }
        impl std::io::Read for Lines {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = (buf.len() as u64).min(self.left) as usize;
                buf[..n].fill(b'.');
                // The newlines in this read: positions p (1-based in the stream) with p % line == 0.
                let mut next = (self.at / self.line + 1) * self.line;
                while next <= self.at + n as u64 {
                    buf[(next - self.at - 1) as usize] = b'\n';
                    next += self.line;
                }
                self.at += n as u64;
                self.left -= n as u64;
                Ok(n)
            }
        }
        let rules = Rules::defaults();
        let (part, len) = (MULTIPART_PART, 12u64 << 20);
        let short = digest_stream(&rules, &mut Lines { left: 16 << 20, at: 0, line: len }, part).unwrap();
        let big = digest_stream(&rules, &mut Lines { left: 2 << 30, at: 0, line: len }, part).unwrap();
        assert_eq!((big.len, big.parts.len() as u64, big.hits.len()), (2 << 30, (2u64 << 30) / part, 0), "a sha256 per part, no finding");
        assert_eq!(big.peak, short.peak, "the working set does not grow with the stream (16 MiB to 2 GiB alike)");
        assert!((big.peak as u64) < (16 << 20), "bounded near one 8 MiB window: {} bytes held at once", big.peak);
        // What the process holds, measured: far under the 2 GiB it read.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
        let max_rss = u64::try_from(usage.ru_maxrss).unwrap(); // bytes on macOS, KiB on Linux
        let bytes = if cfg!(target_os = "macos") { max_rss } else { max_rss * 1024 };
        assert!(bytes < 1 << 30, "the process's resident set peaked at {bytes} bytes");
    }
}

// ---- session stage, end to end ----

/// `session stage`'s path against the tests' S3: the chat (its transcript
/// and a subagent file) goes up by its sha256 keys, the manifest says
/// `origin = "mac"` and gen 0 with one part, the original moves to
/// `origin/`, its view takes its place (masked, the mark on every line),
/// audited `transcript_stage`; a second stage is `already`.
#[test]
fn stage_uploads_the_chat_and_leaves_its_view() {
    let (w, repo) = World::new(FakeS3::start()).with_workspace();
    let main_bytes = [cwd_line(&repo), line("turn 0", 300), line("turn 1", 300)].concat();
    w.plant(&format!("{SID}.jsonl"), &main_bytes);
    let sub = line("subagent", 500);
    w.plant(&format!("{SID}/subagents/agent-a1.jsonl"), &sub);
    let unseal = || async { Ok(FakeMicrovmApi::new()) };
    let report = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, MULTIPART_PART, &builder, unseal)).unwrap();
    let main_key = S3Key::Mac { session: SID.into(), sha256: sha(&main_bytes) }.render();
    assert_eq!((report.outcome, report.key.as_str(), report.bytes, report.parts), ("staged", main_key.as_str(), (main_bytes.len() + sub.len()) as u64, 1));
    assert_eq!(w.s3.get(&main_key).as_deref(), Some(main_bytes.as_slice()));
    let sub_key = S3Key::Mac { session: SID.into(), sha256: sha(&sub) }.render();
    assert_eq!(w.s3.get(&sub_key).as_deref(), Some(sub.as_slice()), "the subagent file by its own sha256");
    let m = w.manifest().expect("the manifest");
    assert_eq!((m.origin.as_str(), m.gen, m.committed, m.parts.len(), m.files.len()), (manifest::ORIGIN_MAC, 0, main_bytes.len() as u64, 1, 1));
    assert_eq!((m.parts[0].key.as_str(), m.fp.as_str()), (main_key.as_str(), sha(&main_bytes).as_str()), "a file under FP_SPAN: its fingerprint is its sha256");
    assert_eq!(m.files[0].rel, format!("{SLUG}/{SID}/subagents/agent-a1.jsonl"));
    let origin = w.paths.transcript_origin(SID);
    assert_eq!(report.origin.as_deref(), Some(origin.as_path()));
    assert_eq!(std::fs::read(origin.join(format!("{SID}.jsonl"))).unwrap(), main_bytes, "the original kept under origin/");
    assert_eq!(std::fs::read(origin.join(SID).join("subagents/agent-a1.jsonl")).unwrap(), sub);
    assert!(!w.projects.join(SLUG).join(SID).exists(), "the subtree left the projects directory");
    let view = std::fs::read_to_string(w.view_path()).unwrap();
    assert!(view.lines().all(|l| l.starts_with(VIEW_MARK_PREFIX)), "{view}");
    let cwd = repo.display().to_string();
    assert!(view.lines().filter(|l| l.contains("\"type\":\"user\"")).all(|l| l.contains(&format!("\"cwd\":{}", serde_json::json!(cwd)))), "no row: the cwd the transcript recorded: {view}");
    assert_eq!(report.view.as_deref(), Some(format!("{SLUG}/{SID}.jsonl").as_str()));
    let rows = w.rows("transcript_stage");
    assert_eq!((rows.len(), rows[0]["detail"]["outcome"].as_str()), (1, Some("staged")));
    assert_eq!(w.rows("transcript_view")[0]["detail"]["outcome"], "written");
    // Staged already: the manifest holds it.
    let again = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, MULTIPART_PART, &builder, || async { Ok(FakeMicrovmApi::new()) })).unwrap();
    assert_eq!(again.outcome, "already");
}

/// The lead's phase-4 items (T7): `session stage` refuses, before any
/// request or Touch ID and before anything moves, a chat that could never
/// reopen once its original is a view: the cwd its transcript records
/// outside `bridge.toml`'s roots, or in no git repository (exit 9, as P0
/// refuses a remote session there), or none recorded (exit 1).
#[test]
fn a_chat_that_could_never_reopen_is_never_staged() {
    let (w, repo) = World::new(FakeS3::start()).with_workspace();
    let elsewhere = std::fs::canonicalize(w._tmp.path()).unwrap().join("elsewhere");
    let notes = repo.parent().unwrap().join("notes");
    for d in [&elsewhere, &notes] {
        std::fs::create_dir_all(d).unwrap();
    }
    for (cwd, code, exit) in [(Some(elsewhere.as_path()), Some("outside_roots"), 9), (Some(notes.as_path()), Some("not_a_git_repo"), 9), (None, None, 1)] {
        let original = [cwd.map(cwd_line).unwrap_or_default(), line("hello", 200)].concat();
        let main = w.plant(&format!("{SID}.jsonl"), &original);
        let unsealed = std::cell::Cell::new(false);
        let unseal = || async {
            unsealed.set(true);
            Ok(FakeMicrovmApi::new())
        };
        let err = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, MULTIPART_PART, &builder, unseal)).unwrap_err();
        match (&err, code) {
            (BridgeError::WorkspaceRefused { code: c, message }, Some(want)) => assert!(*c == want && message.contains("nothing was staged"), "{err:?}"),
            (BridgeError::Config(message), None) => assert!(message.contains("records no cwd"), "{err:?}"),
            _ => panic!("{cwd:?}: {err:?}"),
        }
        assert_eq!(ai_env_cli::errors::CliError::from(err).exit_code(), exit, "{cwd:?}");
        assert!(!unsealed.get() && w.s3.requests().is_empty() && w.manifest().is_none(), "{cwd:?}: nothing asked, nothing sent");
        assert_eq!(std::fs::read(&main).unwrap(), original, "{cwd:?}: the original stays");
    }
}

/// T8: a stage cut before its view, then the chat went on here: staged
/// again, the original is no longer the copy S3 holds, so it is refused
/// (exit 1), never moved behind a view of S3's older copy, naming the way
/// out; the copy S3 holds still gets its view.
#[test]
fn an_original_that_went_on_after_a_cut_stage_is_never_moved() {
    let (w, repo) = World::new(FakeS3::start()).with_workspace();
    let staged = [cwd_line(&repo), line("turn 0", 300)].concat();
    let main = w.plant(&format!("{SID}.jsonl"), &staged);
    let report = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, MULTIPART_PART, &no_builder, || async { Ok(FakeMicrovmApi::new()) })).unwrap();
    assert_eq!((report.outcome, report.view.is_none()), ("staged", true), "cut before its view: the original stays");
    let went_on = [staged.clone(), line("a local turn", 200)].concat();
    std::fs::write(&main, &went_on).unwrap();
    let err = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, MULTIPART_PART, &builder, || async { Ok(FakeMicrovmApi::new()) })).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("is not the copy S3 holds") && text.contains(&format!("ai-env session forget {SID} --purge")), "{text}");
    assert_eq!(ai_env_cli::errors::CliError::from(err).exit_code(), 1);
    assert_eq!(std::fs::read(&main).unwrap(), went_on, "left in place, every local turn");
    assert!(!w.paths.transcript_origin(SID).exists());
    // The copy S3 holds back in place: its view now.
    std::fs::write(&main, &staged).unwrap();
    let again = w.rt().block_on(s3stage::stage(&w.paths, &w.cfg, &w.target, &w.projects, SID, MULTIPART_PART, &builder, || async { Ok(FakeMicrovmApi::new()) })).unwrap();
    assert_eq!(again.outcome, "already");
    assert!(std::fs::read_to_string(&main).unwrap().starts_with(VIEW_MARK_PREFIX));
    assert_eq!(std::fs::read(w.paths.transcript_origin(SID).join(format!("{SID}.jsonl"))).unwrap(), staged);
}

/// T11 and T6: an upload leaves its trace before its first request
/// (`state/transcripts/<sid>/`), and one cut after an object completed
/// sends that object no more: the rerun lists `v1/<sid>/mac/` and skips
/// every key S3 holds at its length.
#[test]
fn an_upload_cut_after_an_object_never_sends_it_again() {
    let w = World::new(FakeS3::start());
    w.plant(&format!("{SID}.jsonl"), &line("main", 4000));
    w.plant(&format!("{SID}/subagents/a.jsonl"), &line("sub", 300));
    let chat = s3stage::locate(&w.projects, &[SLUG], SID, s3stage::STAGE_MAX).unwrap().unwrap();
    let digests = s3stage::scan_chat(&Rules::defaults(), &chat, MULTIPART_PART).unwrap();
    // The main object went up before the cut.
    let main_key = S3Key::Mac { session: SID.into(), sha256: digests[0].sha256.clone() }.render();
    w.s3.put(&main_key, &std::fs::read(chat.main_path(SID)).unwrap());
    let client = w.client();
    let up = w.rt().block_on(s3stage::upload_chat(&client, &w.paths, SID, &chat, &digests, MULTIPART_PART, "2026-10-18T09:00:00.000Z")).unwrap();
    assert!(up.existed && w.paths.transcript_dir(SID).is_dir(), "{up:?}");
    let puts: Vec<String> = w.s3.requests().iter().filter(|r| r.method == "PUT").map(|r| r.key.clone()).collect();
    assert_eq!(puts, vec![S3Key::Mac { session: SID.into(), sha256: digests[1].sha256.clone() }.render()], "only the subtree file went up");
    assert_eq!((up.manifest.parts[0].key.as_str(), up.manifest.parts[0].version_id.as_str()), (main_key.as_str(), ""), "its version unknown, as after a 412");
}

/// A subtree file larger than the part length goes up in exactly the parts
/// its digest was computed with, each with its signed sha256 (S3 takes
/// them), and S3 ends with its bytes.
#[test]
fn a_subtree_file_over_the_part_length_goes_up_in_its_digested_parts() {
    let w = World::new(FakeS3::start());
    let part = 1u64 << 20;
    w.plant(&format!("{SID}.jsonl"), &line("main", 100));
    let mut big = Vec::new();
    for i in 0..3 {
        big.extend_from_slice(&line(&format!("tool output {i}"), 1 << 20));
    }
    big.extend_from_slice(&line("tail", 1000));
    w.plant(&format!("{SID}/tool-results/out.txt"), &big);
    let chat = s3stage::locate(&w.projects, &[SLUG], SID, s3stage::STAGE_MAX).unwrap().unwrap();
    let digests = s3stage::scan_chat(&Rules::defaults(), &chat, part).unwrap();
    assert_eq!(digests[1].parts.len(), 4, "four parts of at most 1 MiB");
    let client = w.client();
    let up = w.rt().block_on(s3stage::upload_chat(&client, &w.paths, SID, &chat, &digests, part, "2026-10-18T09:00:00.000Z")).unwrap();
    let key = S3Key::Mac { session: SID.into(), sha256: sha(&big) }.render();
    assert_eq!(w.s3.get(&key).as_deref(), Some(big.as_slice()), "the big file's bytes, whole");
    assert_eq!(up.manifest.files[0].key, key);
    assert!(w.s3.requests().iter().all(|r| r.status == 200 || r.status == 204), "no BadDigest: {:?}", w.s3.requests());
}

// ---- session gc --remote and forget --purge ----

/// A manifest of a Mac-begun chat whose object is in the tests' S3, written long ago.
fn closed_mac_chat(w: &World) -> String {
    let key = S3Key::Mac { session: SID.into(), sha256: "a".repeat(64) }.render();
    w.s3.put(&key, b"the chat");
    let mut m = Manifest::new(SID, &w.target, manifest::ORIGIN_MAC, &format!("{SLUG}/{SID}.jsonl"), "2026-01-01T00:00:00Z");
    m.parts.push(manifest::ManifestPart { key: key.clone(), version_id: "fv1".into(), from: 0, len: 8, sha256: "a".repeat(64) });
    m.committed = 8;
    w.rt().block_on(async {
        let _h = manifest::lock(&w.paths, SID).await.unwrap();
        manifest::write(&w.paths, &m).unwrap();
    });
    std::fs::create_dir_all(w.paths.transcript_origin(SID)).unwrap();
    std::fs::write(w.paths.transcript_origin(SID).join(format!("{SID}.jsonl")), b"original").unwrap();
    let mut f = std::fs::File::create({
        std::fs::create_dir_all(w.projects.join(SLUG)).unwrap();
        w.view_path()
    })
    .unwrap();
    f.write_all(b"{\"aiEnvView\":1,\"type\":\"ai-title\",\"aiTitle\":\"t\"}\n").unwrap();
    key
}

/// `session gc --remote --yes`'s removal: a closed session's objects under
/// `v1/<sid>/` get delete markers, its manifest and state go but the
/// Mac-begun chat's `origin/`, and its view (only a view) leaves the
/// projects directory; a transcript at the view's path is never removed.
#[test]
fn gc_removes_objects_state_and_view_but_keeps_origin() {
    use ai_env_cli::bridge::s3::commands;
    let w = World::new(FakeS3::start());
    let key = closed_mac_chat(&w);
    let candidates = commands::gc_candidates(&w.paths, 90, ai_env_cli::wire::time::unix_now()).unwrap();
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert_eq!((candidates[0].session.as_str(), candidates[0].objects), (SID, 1));
    assert!(commands::gc_candidates(&w.paths, 3650, ai_env_cli::wire::time::unix_now()).unwrap().is_empty(), "not older than ten years");
    let client = w.client();
    let removed = w.rt().block_on(commands::gc_remove(&client, &w.paths, &candidates, Some(&w.projects))).unwrap();
    assert_eq!(removed, 1);
    assert!(w.s3.get(&key).is_none(), "a delete marker hides the current version");
    assert!(w.s3.objects().iter().any(|o| o.key == key && o.delete_marker && o.current));
    assert!(w.manifest().is_none() && !w.paths.transcript_lock(SID).exists(), "the manifest and the lock went");
    assert!(w.paths.transcript_origin(SID).join(format!("{SID}.jsonl")).exists(), "the Mac-begun chat's original is kept");
    assert!(!w.view_path().exists(), "the view went");
    // A transcript (not a view) at the path is never removed.
    std::fs::write(w.view_path(), b"{\"type\":\"user\"}\n").unwrap();
    assert!(!commands::remove_view(&w.projects, &format!("{SLUG}/{SID}.jsonl")), "a transcript is not a view");
    assert!(w.view_path().exists());
}

/// `forget --purge`'s S3 half: every current object under `v1/<sid>/` gets
/// a delete marker (another session's stays), then `state/transcripts/<sid>/`
/// whole, `origin/` included, and the lock file.
#[test]
fn forget_purge_deletes_the_sessions_objects_and_its_state() {
    use ai_env_cli::bridge::s3::commands;
    let w = World::new(FakeS3::start());
    let key = closed_mac_chat(&w);
    let segment = S3Key::Segment { session: SID.into(), gen: 1, offset: 8 }.render();
    w.s3.put(&segment, b"more");
    let other = S3Key::Base { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c".into(), gen: 1 }.render();
    w.s3.put(&other, b"another session");
    let client = w.client();
    assert!(w.rt().block_on(commands::purge_with(&client, &w.paths, SID)).unwrap());
    assert!(w.s3.get(&key).is_none() && w.s3.get(&segment).is_none(), "the session's objects are gone");
    assert_eq!(w.s3.get(&other).as_deref(), Some(&b"another session"[..]), "another session's stay");
    assert!(!w.paths.transcript_dir(SID).exists() && !w.paths.transcript_lock(SID).exists(), "origin/ included");
    assert!(!w.rt().block_on(commands::purge_with(&client, &w.paths, SID)).unwrap(), "nothing left to remove");
    assert!(w.rt().block_on(commands::purge_with(&client, &w.paths, "../x")).is_err());
}

/// T6: S3 may hold a session's objects with no manifest here (an upload, or
/// a first sync, cut before it): `forget --purge` asks S3 whenever this Mac
/// keeps any trace of it (its state directory, its lock file, a row naming
/// where its transcript is kept), and `gc --remote` takes such a session
/// once that trace is older than its horizon, never a directory a gc
/// already left with only a Mac-begun chat's `origin/`.
#[test]
fn a_session_without_a_manifest_is_still_purged_and_collected() {
    use ai_env_cli::bridge::s3::commands;
    let w = World::new(FakeS3::start());
    assert!(!commands::s3_traces(&w.paths, SID), "nothing here");
    std::fs::create_dir_all(w.paths.transcript_lock(SID).parent().unwrap()).unwrap();
    std::fs::write(w.paths.transcript_lock(SID), b"").unwrap();
    assert!(commands::s3_traces(&w.paths, SID), "the lock file a sync or an upload took");
    std::fs::remove_file(w.paths.transcript_lock(SID)).unwrap();
    let row = ai_env_cli::bridge::registry::SessionRow { session_id: SID.into(), mode: "remote".into(), status: "closed".into(), transcript_home: Some(manifest::HOME_S3.into()), ..ai_env_cli::bridge::registry::SessionRow::default() };
    ai_env_cli::bridge::registry::write(&w.paths, &row).unwrap();
    assert!(commands::s3_traces(&w.paths, SID), "a row naming S3");
    // gc: a cut upload's directory (its stage file), dated by itself; a later horizon takes it.
    std::fs::create_dir_all(w.paths.transcript_dir(SID)).unwrap();
    std::fs::write(w.paths.transcript_stage(SID), b"v = 1\n").unwrap();
    let now = ai_env_cli::wire::time::unix_now();
    assert!(commands::gc_candidates(&w.paths, 1, now).unwrap().is_empty(), "younger than the horizon");
    let later = commands::gc_candidates(&w.paths, 1, now + 10 * 86_400).unwrap();
    assert_eq!((later.len(), later[0].session.as_str(), later[0].objects), (1, SID, 0), "{later:?}");
    let key = S3Key::Mac { session: SID.into(), sha256: "b".repeat(64) }.render();
    w.s3.put(&key, b"a cut upload's object");
    let client = w.client();
    assert_eq!(w.rt().block_on(commands::gc_remove(&client, &w.paths, &later, Some(&w.projects))).unwrap(), 1);
    assert!(w.s3.get(&key).is_none(), "its object went");
    // What a gc leaves of a Mac-begun chat (origin/ alone) is no candidate again.
    std::fs::create_dir_all(w.paths.transcript_origin(SID)).unwrap();
    assert!(commands::gc_candidates(&w.paths, 1, now + 10 * 86_400).unwrap().is_empty());
}

/// T5: `migrate-s9` takes only S8's mirrors (`origin_of`'s `s8_mirror`: a
/// remote row with no manifest and no `transcript_home`). An S9 chat whose
/// Mac file is no view (its view could not be built) is no mirror, and
/// `migrate_one` refuses one with a manifest: failed, nothing sent, its
/// manifest and its file as they were.
#[test]
fn migrate_s9_never_takes_an_s9_chat_for_a_mirror() {
    use ai_env_cli::bridge::s3::commands::{migrate_one, mirrors, Mirror};
    use ai_env_cli::bridge::vm::cmd::Ctx;
    let w = World::new(FakeS3::start());
    let row = |home: Option<&str>| ai_env_cli::bridge::registry::SessionRow { session_id: SID.into(), mode: "remote".into(), slug: Some(SLUG.into()), transcript_home: home.map(str::to_string), ..ai_env_cli::bridge::registry::SessionRow::default() };
    let file = line("a chat", 300);
    let main = w.plant(&format!("{SID}.jsonl"), &file);
    ai_env_cli::bridge::registry::write(&w.paths, &row(Some(manifest::HOME_S3))).unwrap();
    assert!(mirrors(&w.paths, &w.projects).unwrap().is_empty(), "S3 keeps its transcript");
    ai_env_cli::bridge::registry::write(&w.paths, &row(None)).unwrap();
    assert_eq!(mirrors(&w.paths, &w.projects).unwrap().len(), 1, "an S8 mirror");
    // A manifest of a Mac-begun chat (staged, its view not built): no mirror, and never migrated.
    let mut m = Manifest::new(SID, &w.target, manifest::ORIGIN_MAC, &format!("{SLUG}/{SID}.jsonl"), "2026-10-18T09:00:00.000Z");
    m.parts.push(manifest::ManifestPart { key: S3Key::Mac { session: SID.into(), sha256: sha(&file) }.render(), version_id: "fv1".into(), from: 0, len: file.len() as u64, sha256: sha(&file) });
    m.committed = file.len() as u64;
    manifest::write(&w.paths, &m).unwrap();
    assert!(mirrors(&w.paths, &w.projects).unwrap().is_empty(), "a manifest: not a mirror");
    let ctx = Ctx { paths: w.paths.clone(), cfg: w.cfg.clone(), knobs: VmKnobs::default() };
    let chat = s3stage::locate(&w.projects, &[SLUG], SID, s3stage::STAGE_MAX).unwrap().unwrap();
    let done = w.rt().block_on(migrate_one(&ctx, &FakeMicrovmApi::new(), &w.target, &Mirror { row: row(None), chat, vm: None }, &w.projects, &Rules::defaults(), &builder));
    assert_eq!(done.outcome, "failed", "{done:?}");
    assert!(done.why.as_deref().is_some_and(|w| w.contains("not an S8 mirror")), "{done:?}");
    assert_eq!(w.manifest().unwrap(), m, "its manifest as it was");
    assert_eq!(std::fs::read(&main).unwrap(), file, "its file in place");
    assert!(w.s3.requests().is_empty(), "nothing sent");
}

/// A PutObject round-trips our bucket with its checksum and `If-None-Match`:
/// the key holds the bytes, a second new-only PUT of the same key is
/// `Exists` (412), and a wrong checksum is `BadDigest` (the fake S3 checks it).
#[test]
fn put_object_is_immutable_and_checked() {
    let w = World::new(FakeS3::start());
    let bytes = line("one turn", 4096);
    let sha = sha(&bytes);
    let key = S3Key::Base { session: SID.into(), gen: 1 }.render();
    let tmp = w._tmp.path().join("body");
    std::fs::write(&tmp, &bytes).unwrap();
    let client = w.client();
    let body = || Body::File { path: tmp.clone(), offset: 0, len: bytes.len() as u64 };
    let w1 = w.rt().block_on(client.put_object(&key, body(), bytes.len() as u64, &sha)).unwrap();
    assert!(matches!(w1, Written::Stored(ref v) if !v.is_empty()), "{w1:?}");
    assert_eq!(w.s3.get(&key).as_deref(), Some(bytes.as_slice()));
    let again = w.rt().block_on(client.put_object(&key, body(), bytes.len() as u64, &sha)).unwrap();
    assert_eq!(again, Written::Exists, "If-None-Match: * over a current version is 412");
    let bad = S3Key::Base { session: SID.into(), gen: 2 }.render();
    let err = w.rt().block_on(client.put_object(&bad, body(), bytes.len() as u64, &"b".repeat(64))).unwrap_err();
    match err {
        BridgeError::S3 { op: "put", status: 400, code } => assert_eq!(code.as_deref(), Some("BadDigest")),
        other => panic!("not a BadDigest: {other:?}"),
    }
    // The requests the fake S3 recorded carry the signed owner header, never a credential value.
    assert!(w.s3.requests().iter().all(|r| r.signed_headers.iter().any(|h| h == "x-amz-expected-bucket-owner")));
}

// ---- the VM in miniature: the transcript routes as G5's shim answers them ----

#[derive(Default)]
struct VmSt {
    /// The transcript at the main rel (`None`: absent).
    file: Option<Vec<u8>>,
    ino: u64,
    /// The `<slug>/<sid>/` subtree, by rel.
    subtree: Vec<(String, Vec<u8>)>,
    /// What `GET /transcript/view` answers (`None`: the example).
    view: Option<TranscriptViewReply>,
    /// The view's answer does not parse (`reply_of`'s error for a 200).
    view_unparseable: bool,
    /// Answers a push gives instead of PUTting (taken first).
    replies: VecDeque<TranscriptPushReply>,
    /// An edit of every stat's answer.
    stat_edit: Option<fn(&mut TranscriptStat)>,
    routes: Vec<String>,
    /// `POST /transcript/tail`: the URL's key and `from`.
    tails: Vec<(String, u64)>,
    /// `POST /transcript/pull`: the rel and its parts.
    pulls: Vec<(String, usize)>,
    /// A stat with the subtree answers 413 `too_large`, as the helper does past `SUBTREE_FILES_MAX` files.
    subtree_too_large: bool,
    /// A push of this rel is refused by S3 (403 AccessDenied), as a file push that fails.
    refused_rel: Option<String>,
}

/// G5's shim as the Mac sees it: every request checked as the shim checks
/// it; a push PUTs the asked range to its presigned URL as curl does (its
/// length, its signed checksum, `If-None-Match: *`, the owner) and relays
/// S3's status, `<Code>` and version; a pull GETs each part (the owner),
/// checks its length and sha256 and writes nothing unless all passed.
struct FakeVm {
    rel: String,
    st: Mutex<VmSt>,
}

fn unreached() -> BridgeError {
    BridgeError::Endpoint("unreached in this test".into())
}

impl FakeVm {
    fn new() -> FakeVm {
        FakeVm { rel: format!("{SLUG}/{SID}.jsonl"), st: Mutex::new(VmSt { ino: 1000, ..VmSt::default() }) }
    }

    fn set(&self, f: impl FnOnce(&mut VmSt)) {
        f(&mut self.st.lock().unwrap());
    }

    fn file(&self) -> Option<Vec<u8>> {
        self.st.lock().unwrap().file.clone()
    }
}

impl DataPlane for FakeVm {
    async fn seed_state(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SeedState>, BridgeError> {
        Err(unreached())
    }

    async fn put_seed(&self, _: &AgentTarget, _: &AuthToken, _: &SeedQuery, _: &Path, _: u64) -> Result<DpReply<SeedReply>, BridgeError> {
        Err(unreached())
    }

    async fn post_codeout(&self, _: &AgentTarget, _: &AuthToken, _: &CodeoutRequest, _: &Path, _: u64) -> Result<DpReply<CodeoutBody>, BridgeError> {
        Err(unreached())
    }

    async fn transcript_stat(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<TranscriptStat>, BridgeError> {
        Err(unreached())
    }

    async fn get_settings(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> Result<DpReply<SettingsCapture>, BridgeError> {
        Err(unreached())
    }

    async fn transcript_stat_from(&self, _: &AgentTarget, _: &AuthToken, q: &StatQuery) -> Result<DpReply<TranscriptStat>, BridgeError> {
        q.check().map_err(BridgeError::Config)?;
        let mut st = self.st.lock().unwrap();
        st.routes.push(format!("GET /transcript {}", q.from.map_or_else(|| "-".into(), |f| f.to_string())));
        let bytes = if q.rel == self.rel { st.file.clone() } else { st.subtree.iter().find(|(r, _)| *r == q.rel).map(|(_, b)| b.clone()) };
        let Some(bytes) = bytes else { return Ok(DpReply::ok(200, TranscriptStat::default())) };
        if q.subtree && st.subtree_too_large {
            return Ok(DpReply { refusal: Some(ai_env_cli::wire::workspace::WsRefusal::new("too_large", "the subtree holds more than 256 files")), ..DpReply::status(413) });
        }
        let size = bytes.len() as u64;
        let mut stat = TranscriptStat { present: true, size, ino: Some(st.ino), ..TranscriptStat::default() };
        if q.from.is_none() {
            // S8's stat: the whole file's sha256.
            stat.sha256 = Some(sha(&bytes));
        }
        if let Some(from) = q.from {
            if from <= size {
                stat.delta_sha256 = Some(sha(&bytes[from as usize..]));
            }
            stat.end_fp = Some(sha(&bytes[size.saturating_sub(FP_SPAN) as usize..]));
            if let Some(fp) = &q.fp {
                stat.fp_ok = Some(from <= size && sha(&bytes[from.saturating_sub(FP_SPAN) as usize..from as usize]) == *fp);
            }
        }
        if q.subtree {
            stat.subtree = st.subtree.iter().map(|(rel, b)| SubtreeFile { rel: rel.clone(), size: b.len() as u64, sha256: sha(b) }).collect();
        }
        if let Some(edit) = st.stat_edit {
            edit(&mut stat);
        }
        Ok(DpReply::ok(200, stat))
    }

    async fn transcript_push(&self, _: &AgentTarget, _: &AuthToken, req: &TranscriptPush) -> Result<DpReply<TranscriptPushReply>, BridgeError> {
        req.check().map_err(BridgeError::Config)?;
        let (bytes, scripted) = {
            let mut st = self.st.lock().unwrap();
            st.routes.push(format!("POST /transcript/push {} {}", req.url.key(), req.from));
            let src = if req.rel == self.rel { st.file.clone() } else { st.subtree.iter().find(|(r, _)| *r == req.rel).map(|(_, b)| b.clone()) };
            let src = src.ok_or_else(|| BridgeError::Config(format!("{}: no such file in the VM", req.rel)))?;
            if st.refused_rel.as_deref() == Some(req.rel.as_str()) {
                let refused = TranscriptPushReply { s3_status: 403, s3_code: Some("AccessDenied".into()), version_id: None, len: req.len, sha256: req.sha256.clone() };
                return Ok(DpReply::ok(200, refused));
            }
            (src[req.from as usize..(req.from + req.len) as usize].to_vec(), st.replies.pop_front())
        };
        if let Some(r) = scripted {
            return Ok(DpReply::ok(200, r));
        }
        let headers = [
            ("content-length", bytes.len().to_string()),
            ("x-amz-checksum-sha256", sha256_b64(&req.sha256).unwrap()),
            ("if-none-match", "*".to_string()),
            ("x-amz-expected-bucket-owner", req.owner.clone()),
        ];
        let (status, hs, body) = http("PUT", req.url.expose(), &headers, &bytes).await;
        let version = hs.iter().find(|(k, _)| k == "x-amz-version-id").map(|(_, v)| v.clone()).filter(|_| status == 200);
        Ok(DpReply::ok(200, TranscriptPushReply { s3_status: status, s3_code: code_of(&body), version_id: version, len: bytes.len() as u64, sha256: sha(&bytes) }))
    }

    async fn transcript_pull(&self, _: &AgentTarget, _: &AuthToken, req: &TranscriptPull) -> Result<DpReply<TranscriptPullReply>, BridgeError> {
        req.check().map_err(BridgeError::Config)?;
        let old = {
            let st = self.st.lock().unwrap();
            if req.rel == self.rel { st.file.clone() } else { st.subtree.iter().find(|(r, _)| *r == req.rel).map(|(_, b)| b.clone()) }
        };
        let old_size = old.as_ref().map_or(0, |b| b.len() as u64);
        let (mut out, mut reports) = (Vec::new(), Vec::new());
        for p in &req.parts {
            let (status, _, body) = http("GET", p.url.expose(), &[("x-amz-expected-bucket-owner", req.owner.clone())], &[]).await;
            let got = sha(&body);
            let ok = status == 200 && body.len() as u64 == p.len && p.sha256.as_ref().is_none_or(|s| *s == got);
            reports.push(PullPartReport { s3_status: status, len: body.len() as u64, sha256: got, ok });
            if !ok {
                return Ok(DpReply::ok(200, TranscriptPullReply { written: false, size: old_size, sha256: None, parts: reports }));
            }
            out.extend_from_slice(&body);
        }
        if req.sha256.as_ref().is_some_and(|s| *s != sha(&out)) {
            return Ok(DpReply::ok(200, TranscriptPullReply { written: false, size: old_size, sha256: None, parts: reports }));
        }
        let mut st = self.st.lock().unwrap();
        st.routes.push(format!("POST /transcript/pull {}", req.rel));
        st.pulls.push((req.rel.clone(), req.parts.len()));
        let size = out.len() as u64;
        let digest = sha(&out);
        if req.rel == self.rel {
            st.file = Some(out);
            st.ino += 1;
        } else {
            st.subtree.retain(|(r, _)| *r != req.rel);
            st.subtree.push((req.rel.clone(), out));
        }
        Ok(DpReply::ok(201, TranscriptPullReply { written: true, size, sha256: Some(digest), parts: reports }))
    }

    async fn transcript_view(&self, _: &AgentTarget, _: &AuthToken, q: &ViewQuery) -> Result<DpReply<TranscriptViewReply>, BridgeError> {
        q.check().map_err(BridgeError::Config)?;
        let mut st = self.st.lock().unwrap();
        st.routes.push("GET /transcript/view".into());
        if st.view_unparseable {
            return Err(BridgeError::Http { status: 200, body: "GET http://x/transcript/view: unparseable answer: unknown field `isMeta`".into() });
        }
        Ok(DpReply::ok(200, st.view.clone().unwrap_or_else(example)))
    }

    async fn transcript_tail(&self, _: &AgentTarget, _: &AuthToken, req: &TranscriptTail) -> Result<DpReply<()>, BridgeError> {
        req.check().map_err(BridgeError::Config)?;
        let mut st = self.st.lock().unwrap();
        st.routes.push("POST /transcript/tail".into());
        st.tails.push((req.url.key().to_string(), req.from));
        Ok(DpReply::status(204))
    }
}

/// Tokens that are always there (the endpoint is the fake VM itself).
struct Tokens;

impl TokenSource for Tokens {
    async fn token(&self, port: u16) -> Result<AuthToken, BridgeError> {
        Ok(AuthToken { headers: std::collections::BTreeMap::new(), port, expires_at_unix: u64::MAX })
    }
}

/// A session on the VM in miniature with the tests' S3 as its bucket.
struct Remote {
    w: World,
    vm: FakeVm,
    api: FakeMicrovmApi,
    sync: TranscriptSync,
    agent: AgentTarget,
    rules: Rules,
    ws: WorkspaceRef,
}

impl Remote {
    fn new() -> Remote {
        let w = World::new(FakeS3::start());
        let sync = TranscriptSync { target: w.target.clone(), slug: SLUG.into(), mac_cwd: "/Users/mike/Documents/DeFi/ai-env".into(), mac_projects: w.projects.clone(), proxy: None, view_messages: 10 };
        let agent = AgentTarget { vm_id: VM.into(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false };
        let ws = WorkspaceRef {
            cwd: "/Users/mike/Documents/DeFi/ai-env".into(),
            root: "/Users/mike/Documents/DeFi/ai-env".into(),
            vm_cwd: "/Users/mike/Documents/DeFi/ai-env".into(),
            vm_root: "/Users/mike/Documents/DeFi/ai-env".into(),
            slug: SLUG.into(),
            kind: WsKind::Git { git_dir: "/w/.git".into(), common_dir: "/w/.git".into(), object_format: ObjectFormat::Sha1 },
            head: Head::Detached { sha: "a".repeat(40) },
            seed_branch: None,
        };
        Remote { w, vm: FakeVm::new(), api: FakeMicrovmApi::new(), sync, agent, rules: Rules::defaults(), ws }
    }

    fn sync(&self) -> Result<SyncReport, BridgeError> {
        let ctx = SyncCtx { api: &self.api, dp: &self.vm, tokens: &Tokens, paths: &self.w.paths, target: &self.agent, sync: &self.sync, rules: &self.rules, deadline: None };
        self.w.rt().block_on(ctx.sync_session(SID))
    }

    fn restore(&self, build: s3stage::ViewBuilder<'_>) -> Result<TranscriptOutcome, BridgeError> {
        self.restore_within(build, None)
    }

    /// [`Remote::restore`] under `deadline`: generation 1's P3 has one (T0 + 50 s), a resume miss's retry and
    /// `session stage --warm` none.
    fn restore_within(&self, build: s3stage::ViewBuilder<'_>, deadline: Option<tokio::time::Instant>) -> Result<TranscriptOutcome, BridgeError> {
        let caps = vec![CAP_TRANSCRIPT_S3_V1.to_string()];
        let progress = |_| {};
        let ctx = EnsureCtx {
            api: &self.api,
            dp: &self.vm,
            tokens: &Tokens,
            paths: &self.w.paths,
            cfg: &self.w.cfg,
            target: &self.agent,
            caps: &caps,
            ws: &self.ws,
            lim: SeedLimits::wrapper(&self.w.cfg),
            deadline,
            progress: &progress,
        };
        self.w.rt().block_on(ai_env_cli::bridge::workspace::transcript::restore(&ctx, &self.sync, Some(&self.w.projects), &[SLUG], SID, build))
    }

    fn key_of(&self, k: S3Key) -> String {
        k.render()
    }

    fn ctx(&self) -> SyncCtx<'_, FakeMicrovmApi, FakeVm, Tokens> {
        SyncCtx { api: &self.api, dp: &self.vm, tokens: &Tokens, paths: &self.w.paths, target: &self.agent, sync: &self.sync, rules: &self.rules, deadline: None }
    }

    /// The code-out trigger's first step's subtree restore (S9 phase 4).
    fn restore_subtree(&self) -> Result<ai_env_cli::bridge::workspace::transcript::SubtreeRestore, BridgeError> {
        self.w.rt().block_on(ai_env_cli::bridge::workspace::transcript::restore_subtree(&self.ctx(), SID))
    }

    /// A tail URL handed before any sync or turn (S9 phase 4).
    fn hand_fresh_tail(&self) {
        self.w.rt().block_on(self.ctx().hand_fresh_tail(SID));
    }

    /// The registry row of a remote chat whose transcript S3 keeps (begun on a VM).
    fn remote_row(&self) {
        let row = ai_env_cli::bridge::registry::SessionRow {
            session_id: SID.into(),
            mode: "remote".into(),
            slug: Some(SLUG.into()),
            transcript_home: Some(manifest::HOME_S3.into()),
            ..ai_env_cli::bridge::registry::SessionRow::default()
        };
        ai_env_cli::bridge::registry::write(&self.w.paths, &row).unwrap();
    }
}

// ---- the per-turn sync ----

/// The first sync pushes generation 1's base (its key holds the VM's bytes
/// in S3), commits the manifest (its fingerprint the stat's end
/// fingerprint, the VM and inode recorded), hands the shim a tail URL at
/// the committed length and writes the view, audited `transcript_push`
/// (kind, status, version) and `transcript_view`; the next turn's bytes are
/// a segment at the committed length; a sync with nothing new pushes
/// nothing.
#[test]
fn sync_commits_a_base_then_segments_and_hands_the_tail() {
    let r = Remote::new();
    let turn0 = line("turn 0", 300);
    r.vm.set(|s| s.file = Some(turn0.clone()));
    let rep = r.sync().unwrap();
    let base = r.key_of(S3Key::Base { session: SID.into(), gen: 1 });
    assert_eq!(rep.pushed.as_ref().map(|p| (p.kind, p.from, p.len, p.key.as_str())), Some(("base", 0, 300, base.as_str())));
    assert_eq!((rep.outcome(), rep.committed), ("synced", 300));
    assert_eq!(r.w.s3.get(&base).as_deref(), Some(turn0.as_slice()));
    let m = r.w.manifest().unwrap();
    assert_eq!((m.origin.as_str(), m.gen, m.committed, m.fp.as_str(), m.ino, m.vm.as_deref()), (manifest::ORIGIN_VM, 1, 300, sha(&turn0).as_str(), Some(1000), Some(VM)));
    assert!(m.parts[0].version_id.starts_with("fv"), "the version S3 named: {m:?}");
    assert_eq!(r.vm.st.lock().unwrap().tails, vec![(r.key_of(S3Key::Tail { session: SID.into(), gen: 1, offset: 300 }), 300)], "the tail URL at the committed length");
    assert!(matches!(rep.view, Some(ViewOutcome::Written { messages: 2, .. })), "{:?}", rep.view);
    assert!(std::fs::read_to_string(r.w.view_path()).unwrap().starts_with(VIEW_MARK_PREFIX));
    let push = r.w.rows("transcript_push");
    assert_eq!((push[0]["detail"]["kind"].as_str(), push[0]["detail"]["s3_status"].as_str(), push[0]["detail"]["version_id"].as_str()), (Some("base"), Some("200"), Some(m.parts[0].version_id.as_str())));
    assert_eq!(r.w.rows("transcript_view")[0]["detail"]["outcome"], "written");
    // The next turn: a segment at the committed length.
    let turn1 = line("turn 1", 200);
    r.vm.set(|s| s.file.as_mut().unwrap().extend_from_slice(&turn1));
    let rep = r.sync().unwrap();
    let seg = r.key_of(S3Key::Segment { session: SID.into(), gen: 1, offset: 300 });
    assert_eq!(rep.pushed.as_ref().map(|p| (p.kind, p.from, p.len, p.key.as_str())), Some(("segment", 300, 200, seg.as_str())));
    assert_eq!(r.w.s3.get(&seg).as_deref(), Some(turn1.as_slice()));
    let m = r.w.manifest().unwrap();
    assert_eq!((m.parts.len(), m.committed, m.fp.clone()), (2, 500, sha(&r.vm.file().unwrap())));
    // Nothing new: nothing pushed, the view unchanged.
    let rep = r.sync().unwrap();
    assert_eq!((rep.outcome(), rep.pushed.is_none()), ("up_to_date", true));
    assert!(matches!(rep.view, Some(ViewOutcome::Unchanged { .. })));
    assert_eq!(r.w.rows("transcript_push").len(), 2);
}

/// A rewritten file (shorter than committed) is generation 2's base, the
/// old keys superseded; the next sync deletes them (delete markers) and the
/// manifest forgets them.
#[test]
fn a_rewritten_file_starts_a_generation_and_supersedes_the_old_keys() {
    let r = Remote::new();
    r.vm.set(|s| s.file = Some([line("a", 300), line("b", 300)].concat()));
    r.sync().unwrap();
    r.vm.set(|s| s.file.as_mut().unwrap().extend_from_slice(&line("c", 100)));
    r.sync().unwrap();
    let old: Vec<String> = r.w.manifest().unwrap().parts.iter().map(|p| p.key.clone()).collect();
    assert_eq!(old.len(), 2);
    let rewritten = line("compacted", 250);
    r.vm.set(|s| s.file = Some(rewritten.clone()));
    let rep = r.sync().unwrap();
    let g2 = r.key_of(S3Key::Base { session: SID.into(), gen: 2 });
    assert_eq!(rep.pushed.as_ref().map(|p| (p.kind, p.key.clone())), Some(("base", g2.clone())));
    let m = r.w.manifest().unwrap();
    assert_eq!((m.gen, m.committed, m.superseded.clone()), (2, 250, old.clone()));
    assert_eq!(r.w.s3.get(&g2).as_deref(), Some(rewritten.as_slice()));
    r.sync().unwrap();
    assert!(r.w.manifest().unwrap().superseded.is_empty(), "deleted at the next sync");
    for k in &old {
        assert!(r.w.s3.get(k).is_none() && r.w.s3.objects().iter().any(|o| o.key == *k && o.delete_marker && o.current), "{k}");
    }
}

/// A segment S3 refuses — 412 (its key holds an object of a generation the
/// manifest does not know) or 400 `BadDigest` (the VM's bytes changed under
/// the stat) — starts a new generation: a full copy, the old keys
/// superseded.
#[test]
fn a_refused_segment_starts_a_generation() {
    let r = Remote::new();
    r.vm.set(|s| s.file = Some(line("a", 300)));
    r.sync().unwrap();
    r.vm.set(|s| s.file.as_mut().unwrap().extend_from_slice(&line("b", 100)));
    let seg = r.key_of(S3Key::Segment { session: SID.into(), gen: 1, offset: 300 });
    r.w.s3.put(&seg, b"a cut sync's segment");
    let rep = r.sync().unwrap();
    assert_eq!(rep.pushed.as_ref().map(|p| (p.kind, p.len)), Some(("base", 400)), "412: a new generation");
    let m = r.w.manifest().unwrap();
    assert_eq!((m.gen, m.committed, m.superseded.clone()), (2, 400, vec![seg.clone(), r.key_of(S3Key::Base { session: SID.into(), gen: 1 })]), "the refused segment's key and the old base go");
    assert!(r.w.rows("transcript_push").iter().any(|row| row["detail"]["s3_status"] == "412"));
    // BadDigest on the next segment (the superseded key's delete goes first, then the segment's PUT).
    r.sync().unwrap();
    r.vm.set(|s| s.file.as_mut().unwrap().extend_from_slice(&line("c", 100)));
    r.w.s3.script(vec![S3Action::Status { status: 400, code: "BadDigest" }]);
    let rep = r.sync().unwrap();
    assert_eq!(rep.pushed.as_ref().map(|p| (p.kind, p.key.clone())), Some(("base", r.key_of(S3Key::Base { session: SID.into(), gen: 3 }))));
    assert_eq!(r.w.manifest().unwrap().gen, 3);
}

/// Subtree files go up by their bytes' sha256; a 412 there commits, the
/// version another entry holds for that key (two identical files) or none
/// (the key held it before the manifest knew it).
#[test]
fn a_file_412_commits_with_the_version_it_knows() {
    let r = Remote::new();
    let same = line("identical subagent", 400);
    let planted = line("planted before", 200);
    r.vm.set(|s| {
        s.file = Some(line("main", 300));
        s.subtree = vec![(format!("{SLUG}/{SID}/subagents/a.jsonl"), same.clone()), (format!("{SLUG}/{SID}/subagents/b.jsonl"), same.clone()), (format!("{SLUG}/{SID}/subagents/c.jsonl"), planted.clone())];
    });
    let planted_key = r.key_of(S3Key::File { session: SID.into(), sha256: sha(&planted) });
    r.w.s3.put(&planted_key, &planted);
    let rep = r.sync().unwrap();
    assert_eq!(rep.files, 3);
    let m = r.w.manifest().unwrap();
    let key = r.key_of(S3Key::File { session: SID.into(), sha256: sha(&same) });
    assert_eq!((m.files[0].key.as_str(), m.files[1].key.as_str()), (key.as_str(), key.as_str()));
    assert!(m.files[0].version_id.is_some() && m.files[1].version_id == m.files[0].version_id, "{m:?}");
    assert_eq!((m.files[2].key.as_str(), m.files[2].version_id.as_ref()), (planted_key.as_str(), None), "a 412 on a key the manifest did not know: version unknown");
    assert_eq!(r.w.s3.get(&key).as_deref(), Some(same.as_slice()));
    // The next sync sends none of them again.
    assert_eq!(r.sync().unwrap().files, 0);
}

/// The view is refused whole when the reply fails its check (a reply
/// first) or does not parse (an unknown key): the old view stays, the
/// `transcript_view` row says `refused`.
#[test]
fn the_view_is_refused_whole_and_audited() {
    let r = Remote::new();
    r.vm.set(|s| s.file = Some(line("a", 300)));
    r.sync().unwrap();
    let before = std::fs::read(r.w.view_path()).unwrap();
    let mut reply_first = example();
    reply_first.entries.reverse();
    r.vm.set(|s| {
        s.view = Some(reply_first);
        s.file.as_mut().unwrap().extend_from_slice(&line("b", 100));
    });
    let rep = r.sync().unwrap();
    assert!(matches!(&rep.view, Some(ViewOutcome::Refused(why)) if why.contains("user's message")), "{:?}", rep.view);
    assert_eq!(std::fs::read(r.w.view_path()).unwrap(), before, "the old view stays");
    r.vm.set(|s| {
        s.view = None;
        s.view_unparseable = true;
    });
    let rep = r.sync().unwrap();
    assert!(matches!(&rep.view, Some(ViewOutcome::Refused(why)) if why.contains("unparseable")), "{:?}", rep.view);
    assert_eq!(std::fs::read(r.w.view_path()).unwrap(), before);
    let outcomes: Vec<String> = r.w.rows("transcript_view").iter().map(|row| row["detail"]["outcome"].as_str().unwrap().to_string()).collect();
    assert_eq!(outcomes, ["written", "refused", "refused"]);
}

/// What the VM relays is checked before anything is committed from it: a
/// stat's delta sha256, end fingerprint or subtree sha256 that is no
/// digest, a stat without the end fingerprint a commit records, and a 200's
/// version id with a space are each `Protocol` with nothing committed (no
/// manifest, nothing pushed for a bad stat); S3's `<Code>` outside
/// `[A-Za-z0-9]{1,64}` is dropped from the error.
#[test]
fn vm_authored_fields_are_checked_before_any_commit() {
    let protocol = |r: &Remote, what: &str| match r.sync() {
        Err(BridgeError::Protocol(m)) => assert!(m.contains(what), "{what}: {m}"),
        other => panic!("{what}: expected Protocol, got {other:?}"),
    };
    type Edit = fn(&mut TranscriptStat);
    let edits: [(Edit, &str); 4] = [
        (|s| s.end_fp = Some("not-a-digest".into()), "an end fingerprint"),
        (|s| s.delta_sha256 = Some("Z".repeat(64)), "a delta sha256"),
        (|s| s.subtree = vec![SubtreeFile { rel: format!("{SLUG}/{SID}/subagents/a.jsonl"), size: 1, sha256: "x".into() }], "a subtree file's sha256"),
        (|s| s.end_fp = None, "without the end fingerprint"),
    ];
    for (edit, what) in edits {
        let r = Remote::new();
        r.vm.set(|s| {
            s.file = Some(line("a", 300));
            s.stat_edit = Some(edit);
        });
        protocol(&r, what);
        assert!(r.w.manifest().is_none(), "{what}: nothing committed");
        assert!(r.w.s3.requests().is_empty(), "{what}: nothing pushed");
    }
    let r = Remote::new();
    r.vm.set(|s| {
        s.file = Some(line("a", 300));
        s.replies.push_back(TranscriptPushReply { s3_status: 200, s3_code: None, version_id: Some("fv 1".into()), len: 300, sha256: sha(&line("a", 300)) });
    });
    protocol(&r, "version id");
    assert!(r.w.manifest().is_none());
    assert!(r.w.rows("transcript_push")[0]["detail"].get("version_id").is_none(), "the row names no version it refused");
    r.vm.set(|s| s.replies.push_back(TranscriptPushReply { s3_status: 403, s3_code: Some("Access Denied<script>".into()), version_id: None, len: 300, sha256: sha(&line("a", 300)) }));
    match r.sync() {
        Err(BridgeError::S3 { status: 403, code: None, .. }) => {}
        other => panic!("expected S3 403 without a code, got {other:?}"),
    }
}

/// An empty transcript (a sync before the first turn) commits nothing:
/// no manifest is written, no view.
#[test]
fn an_empty_transcript_writes_no_manifest() {
    let r = Remote::new();
    r.vm.set(|s| s.file = Some(Vec::new()));
    let rep = r.sync().unwrap();
    assert_eq!((rep.outcome(), rep.view.is_none()), ("up_to_date", true));
    assert!(r.w.manifest().is_none() && !r.w.view_path().exists());
    r.vm.set(|s| s.file = None);
    assert!(r.sync().unwrap().view.is_none(), "no transcript at all: nothing");
}

// ---- the restore (P3) ----

/// The row's VM holds the committed prefix (and more): kept, nothing pulled.
#[test]
fn restore_keeps_the_vms_copy_when_it_holds_the_committed_prefix() {
    let r = Remote::new();
    r.vm.set(|s| s.file = Some(line("a", 300)));
    r.sync().unwrap();
    r.vm.set(|s| s.file.as_mut().unwrap().extend_from_slice(&line("unsynced", 50)));
    assert_eq!(r.restore(&builder).unwrap(), TranscriptOutcome::KeptOnVm);
    assert!(r.vm.st.lock().unwrap().pulls.is_empty());
}

/// A new VM (no copy): the parts are pulled by version, the tail `/suspend`
/// pushed past the committed length appended (found by listing), each
/// subtree file pulled too; audited `transcript_pull`; the manifest takes
/// the new VM's inode. A manifest fingerprint that is no digest counts as
/// none: the VM's copy is not kept.
#[test]
fn restore_pulls_the_parts_and_the_tail_into_a_new_vm() {
    let r = Remote::new();
    let sub = line("subagent", 120);
    r.vm.set(|s| {
        s.file = Some(line("a", 300));
        s.subtree = vec![(format!("{SLUG}/{SID}/subagents/a.jsonl"), sub.clone())];
    });
    r.sync().unwrap();
    r.vm.set(|s| s.file.as_mut().unwrap().extend_from_slice(&line("b", 200)));
    r.sync().unwrap();
    let synced = r.vm.file().unwrap();
    let tail = line("after the last result", 80);
    r.w.s3.put(&r.key_of(S3Key::Tail { session: SID.into(), gen: 1, offset: 500 }), &tail);
    r.vm.set(|s| {
        s.file = None;
        s.subtree.clear();
    });
    let out = r.restore(&builder).unwrap();
    assert_eq!(out, TranscriptOutcome::Restored { parts: 3, bytes: 580 });
    assert_eq!(r.vm.file().unwrap(), [synced.clone(), tail.clone()].concat(), "the parts, then the tail");
    assert!(r.vm.st.lock().unwrap().subtree.is_empty(), "P3 restores the main transcript alone, within its deadline");
    // The trigger's first step, after the spawn: the subtree.
    let done = r.restore_subtree().unwrap();
    assert_eq!((done.pulled, done.kept), (1, 0));
    assert_eq!(r.vm.st.lock().unwrap().subtree, vec![(format!("{SLUG}/{SID}/subagents/a.jsonl"), sub)]);
    let rows = r.w.rows("transcript_pull");
    assert_eq!((rows.len(), rows[0]["detail"]["outcome"].as_str(), rows[0]["detail"]["parts"].as_str()), (2, Some("written"), Some("3")));
    assert_eq!(r.w.manifest().unwrap().ino, Some(1001), "the new copy's inode, for the next sync's rewrite check");
    // A fingerprint that is no digest: not kept, pulled again.
    let mut m = r.w.manifest().unwrap();
    m.fp = "bogus".into();
    manifest::write(&r.w.paths, &m).unwrap();
    assert!(matches!(r.restore(&builder).unwrap(), TranscriptOutcome::Restored { .. }));
}

/// A tail is only ever the main transcript's (S9 §13, I2): the restore
/// appends the one S3 holds past the committed length to the main
/// transcript alone, and each subtree file comes back from its own key, one
/// part, as last synced (one changed after that sync was never in S3). The
/// fake VM checks each pull as the shim does, which refuses a tail part in
/// another file's pull.
#[test]
fn restore_never_appends_a_tail_to_another_file() {
    let r = Remote::new();
    let (sub_rel, sub) = (format!("{SLUG}/{SID}/subagents/a.jsonl"), line("subagent", 120));
    r.vm.set(|s| {
        s.file = Some(line("a", 300));
        s.subtree = vec![(sub_rel.clone(), sub.clone())];
    });
    r.sync().unwrap();
    let synced = r.vm.file().unwrap();
    let tail = line("after the last result", 80);
    r.w.s3.put(&r.key_of(S3Key::Tail { session: SID.into(), gen: 1, offset: 300 }), &tail);
    r.vm.set(|s| {
        s.file = None;
        s.subtree.clear();
    });
    assert_eq!(r.restore(&builder).unwrap(), TranscriptOutcome::Restored { parts: 2, bytes: 380 });
    assert_eq!(r.vm.file().unwrap(), [synced, tail].concat(), "the tail goes to the main transcript");
    r.restore_subtree().unwrap();
    let st = r.vm.st.lock().unwrap();
    assert_eq!(st.subtree, vec![(sub_rel.clone(), sub)], "the subagent file as synced, nothing appended");
    assert_eq!(st.pulls, vec![(format!("{SLUG}/{SID}.jsonl"), 2), (sub_rel, 1)], "the subtree file from its own key alone");
}

/// A Mac-begun chat S3 does not hold goes up inline at its reopen (scanned,
/// by its sha256 keys), its manifest says `mac`, the original moves to
/// `origin/` behind its view, audited `transcript_stage`; the VM gets it
/// (its subtree file into the VM's project directory), and a tail the shim
/// pushes past it later is found under generation 1, where the sync signs it.
#[test]
fn restore_sends_a_mac_begun_chat_up_inline() {
    let r = Remote::new();
    let chat = [line("mac 0", 300), line("mac 1", 300)].concat();
    let sub = line("mac subagent", 100);
    r.w.plant(&format!("{SID}.jsonl"), &chat);
    r.w.plant(&format!("{SID}/subagents/a.jsonl"), &sub);
    let out = r.restore(&builder).unwrap();
    assert_eq!(out, TranscriptOutcome::Staged { bytes: (chat.len() + sub.len()) as u64 });
    let m = r.w.manifest().unwrap();
    assert_eq!((m.origin.as_str(), m.gen, m.parts.len()), (manifest::ORIGIN_MAC, 0, 1));
    assert_eq!(r.w.s3.get(&m.parts[0].key).as_deref(), Some(chat.as_slice()));
    assert_eq!(std::fs::read(r.w.paths.transcript_origin(SID).join(format!("{SID}.jsonl"))).unwrap(), chat, "the original under origin/");
    assert!(std::fs::read_to_string(r.w.view_path()).unwrap().starts_with(VIEW_MARK_PREFIX), "its view in its place");
    assert_eq!(r.vm.file().unwrap(), chat);
    assert!(r.vm.st.lock().unwrap().subtree.is_empty(), "the subtree follows after the spawn");
    assert_eq!(r.restore_subtree().unwrap().pulled, 1);
    assert_eq!(r.vm.st.lock().unwrap().subtree, vec![(format!("{SLUG}/{SID}/subagents/a.jsonl"), sub)]);
    assert_eq!(r.w.rows("transcript_stage")[0]["detail"]["outcome"], "staged");
    // A gen-0 manifest's tail: the shim pushed it under g1 (the sync hands it so), the restore finds it there.
    let tail = line("suspended", 60);
    r.w.s3.put(&r.key_of(S3Key::Tail { session: SID.into(), gen: 1, offset: chat.len() as u64 }), &tail);
    r.vm.set(|s| s.file = None);
    assert_eq!(r.restore(&builder).unwrap(), TranscriptOutcome::Restored { parts: 2, bytes: (chat.len() + tail.len()) as u64 });
    assert_eq!(r.vm.file().unwrap(), [chat, tail].concat());
}

/// An S8 mirror (a remote row without `transcript_home`) at or under the
/// inline cap goes up in `migrate-s9`'s gone-VM form: the manifest says
/// `vm` (where the chat began), the mirror is deleted (nothing of it under
/// `origin/`), its view takes its place, audited `transcript_migrate`.
#[test]
fn restore_sends_an_s8_mirror_up_in_migrate_s9s_gone_vm_form() {
    let r = Remote::new();
    let row = ai_env_cli::bridge::registry::SessionRow { session_id: SID.into(), mode: "remote".into(), slug: Some(SLUG.into()), ..ai_env_cli::bridge::registry::SessionRow::default() };
    ai_env_cli::bridge::registry::write(&r.w.paths, &row).unwrap();
    assert_eq!(manifest::origin_of(&r.w.paths, SID), Some(manifest::ORIGIN_S8_MIRROR));
    let mirror = line("vm-begun", 400);
    r.w.plant(&format!("{SID}.jsonl"), &mirror);
    assert_eq!(r.restore(&builder).unwrap(), TranscriptOutcome::Staged { bytes: 400 });
    let m = r.w.manifest().unwrap();
    assert_eq!(m.origin, manifest::ORIGIN_VM, "the chat began on a VM");
    assert!(!r.w.paths.transcript_origin(SID).exists(), "no remote transcript kept on this Mac");
    assert!(std::fs::read_to_string(r.w.view_path()).unwrap().starts_with(VIEW_MARK_PREFIX), "the view replaced the mirror");
    assert_eq!(r.vm.file().unwrap(), mirror);
    let rows = r.w.rows("transcript_migrate");
    assert_eq!((rows[0]["detail"]["from"].as_str(), rows[0]["detail"]["outcome"].as_str()), (Some("gone_vm"), Some("migrated")));
    assert!(r.w.rows("transcript_stage").is_empty());
}

/// A stage cut after its manifest and before its view (here: no view could
/// be built) leaves the original in place; the next restore finishes it
/// (the copy S3 holds moves to `origin/` behind its view), then restores. A
/// copy that is not the one S3 holds is left alone.
#[test]
fn restore_finishes_a_stage_cut_before_its_view() {
    let r = Remote::new();
    let chat = line("mac", 500);
    let main = r.w.plant(&format!("{SID}.jsonl"), &chat);
    assert_eq!(r.restore(&no_builder).unwrap(), TranscriptOutcome::Staged { bytes: 500 });
    assert_eq!(std::fs::read(&main).unwrap(), chat, "no view: the original stays");
    // The next reopen, a builder at hand: the original goes behind its view first.
    r.vm.set(|s| s.file = None);
    assert!(matches!(r.restore(&builder).unwrap(), TranscriptOutcome::Restored { .. }));
    assert_eq!(std::fs::read(r.w.paths.transcript_origin(SID).join(format!("{SID}.jsonl"))).unwrap(), chat);
    assert!(std::fs::read_to_string(&main).unwrap().starts_with(VIEW_MARK_PREFIX));
    // Another copy at the path (not the bytes S3 holds) is never moved.
    std::fs::remove_file(&main).unwrap();
    std::fs::write(&main, line("another chat", 500)).unwrap();
    r.restore(&builder).unwrap();
    assert_eq!(std::fs::read(&main).unwrap(), line("another chat", 500));
}

/// A manifest that commits nothing (an older build wrote one) restores
/// nothing: no pull of zero parts.
#[test]
fn a_manifest_that_commits_nothing_restores_nothing() {
    let r = Remote::new();
    let m = Manifest::new(SID, &r.w.target, manifest::ORIGIN_VM, &format!("{SLUG}/{SID}.jsonl"), "2026-10-18T09:00:00.000Z");
    manifest::write(&r.w.paths, &m).unwrap();
    assert_eq!(r.restore(&builder).unwrap(), TranscriptOutcome::NothingToRestore);
    assert!(r.vm.st.lock().unwrap().routes.is_empty(), "nothing asked of the VM");
}

/// S9 R5-AWS-1, P3's half of the reopen's pull cap. Under the init deadline
/// (generation 1's P3) a restore pulls at most `INLINE_MAX` in all, the
/// manifest's parts and the tail S3 lists together. At the cap the pull
/// starts (here it fails at once: S3 holds no such part). A chat one tail
/// past it (a 64 MiB base and a 100-byte tail) is `TranscriptPullTooLarge`
/// before any pull starts: no part asked of S3, no `POST /transcript/pull`,
/// nothing written in the VM, no `transcript_pull` row; Cursor's line names
/// `ai-env session stage UUID --warm` (exit 9). Without a deadline (a resume
/// miss's retry, `session stage --warm`) the same chat is pulled whole and
/// audited. A debug build hashes 64 MiB in some seconds.
#[test]
fn a_reopen_pulls_at_most_the_inline_cap_and_the_retry_any_size() {
    use ai_env_cli::bridge::remote::{link::StartStep, Failure};
    use ai_env_cli::wire::s3::INLINE_MAX;
    let r = Remote::new();
    let within = || Some(tokio::time::Instant::now() + std::time::Duration::from_secs(50));
    let base_key = r.key_of(S3Key::Base { session: SID.into(), gen: 1 });
    let manifest = |len: u64, version: &str, sha256: &str, fp: &str| {
        let mut m = Manifest::new(SID, &r.w.target, manifest::ORIGIN_VM, &format!("{SLUG}/{SID}.jsonl"), "2026-10-18T09:00:00.000Z");
        m.parts.push(manifest::ManifestPart { key: base_key.clone(), version_id: version.into(), from: 0, len, sha256: sha256.into() });
        (m.gen, m.committed, m.fp) = (1, len, fp.into());
        manifest::write(&r.w.paths, &m).unwrap();
    };
    let gets = |key: &str| r.w.s3.requests().iter().filter(|q| q.method == "GET" && q.key == key).count();
    // At the cap the pull starts.
    manifest(INLINE_MAX, "fv9", &"a".repeat(64), &"b".repeat(64));
    match r.restore_within(&builder, within()) {
        Err(BridgeError::S3 { status: 404, .. }) => {}
        other => panic!("at the cap the pull starts (and finds no such part): {other:?}"),
    }
    assert_eq!(gets(&base_key), 1, "the VM asked S3 for the part");
    let pulled = || r.w.rows("transcript_pull").iter().map(|row| row["detail"]["outcome"].as_str().unwrap_or_default().to_string()).collect::<Vec<_>>();
    assert_eq!(pulled(), ["failed"], "the pull that started");
    // The chat in S3: a base of INLINE_MAX bytes (lines of 1 MiB), then a tail of 100 bytes past it.
    let mut base = vec![b'x'; usize::try_from(INLINE_MAX).unwrap()];
    for end in (1..=64).map(|i| i * (1 << 20) - 1) {
        base[end] = b'\n';
    }
    let version = r.w.s3.put(&base_key, &base);
    let sha256 = r.w.s3.objects().into_iter().find(|o| o.key == base_key && o.version_id == version).expect("the base in S3").sha256;
    manifest(INLINE_MAX, &version, &sha256, &sha(&base[base.len() - FP_SPAN as usize..]));
    let tail = line("after the last sync", 100);
    let tail_key = r.key_of(S3Key::Tail { session: SID.into(), gen: 1, offset: INLINE_MAX });
    r.w.s3.put(&tail_key, &tail);
    let e = r.restore_within(&builder, within()).unwrap_err();
    match &e {
        BridgeError::TranscriptPullTooLarge { session, bytes } => assert_eq!((session.as_str(), *bytes), (SID, INLINE_MAX + 100)),
        other => panic!("expected TranscriptPullTooLarge, got {other:?}"),
    }
    let f = Failure::from_error(StartStep::Workspace, e, Some(VM));
    assert_eq!((f.word(), f.exit_code()), ("transcript_pull_too_large", 9));
    assert!(f.line().ends_with(&format!("run ai-env session stage {SID} --warm in a terminal, then reopen the chat")), "{}", f.line());
    assert_eq!((gets(&base_key), gets(&tail_key)), (1, 0), "no part asked of S3 since");
    {
        let st = r.vm.st.lock().unwrap();
        assert!(st.file.is_none() && st.pulls.is_empty() && !st.routes.iter().any(|q| q.starts_with("POST /transcript/pull")), "nothing pulled: {:?}", st.routes);
    }
    assert_eq!(pulled(), ["failed"], "no pull audited since");
    // No deadline: the same chat, pulled whole.
    assert_eq!(r.restore_within(&builder, None).unwrap(), TranscriptOutcome::Restored { parts: 2, bytes: INLINE_MAX + 100 });
    assert!(r.vm.file().unwrap() == [base.as_slice(), tail.as_slice()].concat(), "the base, then the tail");
    assert_eq!(pulled(), ["failed", "written"]);
    let rows = r.w.rows("transcript_pull");
    let d = &rows[1]["detail"];
    assert_eq!((d["outcome"].as_str(), d["bytes"].as_str(), d["parts"].as_str()), (Some("written"), Some((INLINE_MAX + 100).to_string().as_str()), Some("2")));
    assert!(d["ms"].as_str().is_some_and(|ms| ms.parse::<u64>().is_ok()), "{d}");
}

// ---- phase 4: the transcript store's findings (T1 to T4) ----

/// T1: a subtree past the helper's caps (its stat 413 `too_large`) never
/// holds the transcript back: the main transcript is stat'ed without it,
/// pushed, committed, its tail handed and its view written; the files the
/// manifest holds stay; once the subtree is under the caps again, its
/// files go up.
#[test]
fn a_subtree_over_the_helpers_caps_never_holds_the_transcript_back() {
    let r = Remote::new();
    let sub = (format!("{SLUG}/{SID}/subagents/a.jsonl"), line("subagent", 120));
    r.vm.set(|s| {
        s.file = Some(line("a", 300));
        s.subtree = vec![sub.clone()];
    });
    assert_eq!(r.sync().unwrap().files, 1);
    r.vm.set(|s| {
        s.file.as_mut().unwrap().extend_from_slice(&line("b", 100));
        s.subtree_too_large = true;
    });
    let rep = r.sync().unwrap();
    assert_eq!((rep.pushed.as_ref().map(|p| p.kind), rep.files, rep.committed), (Some("segment"), 0, 400));
    let m = r.w.manifest().unwrap();
    assert_eq!((m.committed, m.files.len()), (400, 1), "the committed file stays: {m:?}");
    assert_eq!(r.vm.st.lock().unwrap().tails.last().map(|t| t.1), Some(400), "the tail at the new length");
    assert!(matches!(rep.view, Some(ViewOutcome::Written { .. } | ViewOutcome::Unchanged { .. })), "the view step ran: {:?}", rep.view);
    r.vm.set(|s| {
        s.subtree_too_large = false;
        s.subtree.push((format!("{SLUG}/{SID}/subagents/b.jsonl"), line("another", 80)));
    });
    assert_eq!(r.sync().unwrap().files, 1, "under the caps again: the new file goes up");
    assert_eq!(r.w.manifest().unwrap().files.len(), 2);
}

/// T2: a tail URL is handed before any sync, from 0 under generation 1
/// when S3 holds nothing of the session (`g1/t/0000000000000000`: the whole
/// transcript), at the committed length once it holds some. A chat closed
/// before its first sync (no manifest, begun on a VM) reopens from what is
/// left: the VM's own copy is kept; on a new VM the tail the shim pushed
/// from 0 is pulled. Its first sync's base then supersedes that tail, and
/// the sync after it deletes it.
#[test]
fn a_chat_closed_before_its_first_sync_is_kept_or_restored_from_its_tail() {
    let r = Remote::new();
    r.remote_row();
    let tail0 = r.key_of(S3Key::Tail { session: SID.into(), gen: 1, offset: 0 });
    r.hand_fresh_tail();
    assert_eq!(r.vm.st.lock().unwrap().tails, vec![(tail0.clone(), 0)], "from 0, before any sync");
    let chat = line("before the first sync", 300);
    r.vm.set(|s| s.file = Some(chat.clone()));
    assert_eq!(r.restore(&builder).unwrap(), TranscriptOutcome::KeptOnVm, "the VM holds it");
    // A new VM: the tail the shim pushed at /terminate.
    r.w.s3.put(&tail0, &chat);
    r.vm.set(|s| s.file = None);
    assert_eq!(r.restore(&builder).unwrap(), TranscriptOutcome::Restored { parts: 1, bytes: 300 });
    assert_eq!(r.vm.file().unwrap(), chat);
    // The first sync: generation 1's base, the tail superseded; the next sync deletes it.
    let rep = r.sync().unwrap();
    assert_eq!(rep.pushed.as_ref().map(|p| p.kind), Some("base"));
    assert_eq!(r.w.manifest().unwrap().superseded, vec![tail0.clone()]);
    r.sync().unwrap();
    assert!(r.w.manifest().unwrap().superseded.is_empty() && r.w.s3.get(&tail0).is_none(), "deleted at the next sync");
    r.hand_fresh_tail();
    assert_eq!(r.vm.st.lock().unwrap().tails.last().cloned(), Some((r.key_of(S3Key::Tail { session: SID.into(), gen: 1, offset: 300 }), 300)), "at the committed length once S3 holds it");
    // Nothing anywhere: nothing to restore.
    let empty = Remote::new();
    empty.remote_row();
    assert_eq!(empty.restore(&builder).unwrap(), TranscriptOutcome::NothingToRestore);
}

/// T2: the placeholder view a session gets when it is first named (no file
/// at its path yet): marked, listed by its title, one user line to reopen
/// from; never over a file already there, and replaced by the first view.
#[test]
fn a_placeholder_view_stands_until_the_first_sync() {
    use ai_env_cli::bridge::s3::sync::{write_placeholder_view, PLACEHOLDER_TEXT, PLACEHOLDER_TITLE};
    let r = Remote::new();
    let o = write_placeholder_view(&r.sync, SID, &r.rules).unwrap();
    assert!(matches!(o, Some(ViewOutcome::Written { messages: 1, .. })), "{o:?}");
    let text = std::fs::read_to_string(r.w.view_path()).unwrap();
    let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert!(text.lines().all(|l| l.starts_with(VIEW_MARK_PREFIX)), "{text}");
    assert_eq!((lines[0]["type"].as_str(), lines[0]["aiTitle"].as_str()), (Some("ai-title"), Some(PLACEHOLDER_TITLE)));
    assert_eq!((lines[1]["type"].as_str(), lines[1]["message"]["content"][0]["text"].as_str()), (Some("user"), Some(PLACEHOLDER_TEXT)));
    assert_eq!(write_placeholder_view(&r.sync, SID, &r.rules).unwrap(), None, "never over a file");
    r.vm.set(|s| s.file = Some(line("a", 300)));
    r.sync().unwrap();
    assert!(!std::fs::read_to_string(r.w.view_path()).unwrap().contains(PLACEHOLDER_TEXT), "the first view replaced it");
}

/// T3: a sync never drops a committed subtree file: one the VM no longer
/// lists stays in the manifest (its object is never orphaned), and the
/// subtree restore puts it back, with a file the VM holds shorter (an older
/// copy); one the VM holds longer is newer than the commit and kept (the
/// next sync pushes it). Past the helper's caps the restore reads each
/// file's own stat.
#[test]
fn a_sync_never_drops_a_committed_file_and_the_subtree_comes_back() {
    let r = Remote::new();
    let (a, b, c) = (format!("{SLUG}/{SID}/subagents/a.jsonl"), format!("{SLUG}/{SID}/subagents/b.jsonl"), format!("{SLUG}/{SID}/subagents/c.jsonl"));
    let (a_bytes, b_bytes, c_bytes) = (line("a", 100), line("b", 200), line("c", 300));
    r.vm.set(|s| {
        s.file = Some(line("main", 300));
        s.subtree = vec![(a.clone(), a_bytes.clone()), (b.clone(), b_bytes.clone()), (c.clone(), c_bytes.clone())];
    });
    assert_eq!(r.sync().unwrap().files, 3);
    // The VM lost b, holds an older (shorter) a, and a newer (longer) c.
    let newer_c = [c_bytes.clone(), line("c more", 50)].concat();
    r.vm.set(|s| s.subtree = vec![(a.clone(), a_bytes[..40].to_vec()), (c.clone(), newer_c.clone())]);
    let rep = r.sync().unwrap();
    let m = r.w.manifest().unwrap();
    let rels: Vec<&str> = m.files.iter().map(|f| f.rel.as_str()).collect();
    assert!(rels.contains(&b.as_str()) && rels.len() == 3, "b stays: {rels:?}");
    assert_eq!(rep.files, 2, "a's and c's new bytes go up");
    let held = |rel: &str| r.vm.st.lock().unwrap().subtree.iter().find(|(r, _)| r == rel).map(|(_, b)| b.clone());
    // Commit a's shorter copy as it is now, then restore: b comes back; a and c are as committed.
    let done = r.restore_subtree().unwrap();
    assert_eq!((done.pulled, done.kept), (1, 2), "{done:?}");
    assert_eq!(held(&b), Some(b_bytes.clone()));
    // The VM holds a shorter c than committed (an older copy), past the caps: each file's own stat decides.
    r.vm.set(|s| {
        s.subtree.retain(|(rel, _)| *rel != c);
        s.subtree.push((c.clone(), c_bytes[..10].to_vec()));
        s.subtree_too_large = true;
    });
    let done = r.restore_subtree().unwrap();
    assert_eq!(done.pulled, 1, "{done:?}");
    assert_eq!(held(&c), Some(newer_c));
}

/// T4: syncs cut after their push (here three in a row: a segment, then two
/// generations' bases, stored outside the manifest) never wedge the next:
/// its first 412 lists the VM's keys once, its base goes past the highest
/// generation S3 holds, and the stray keys are superseded, deleted at the
/// sync after. A failure after the main push (a subtree file S3 refuses)
/// leaves the main push committed in the manifest.
#[test]
fn syncs_cut_after_their_push_never_wedge_the_next() {
    let r = Remote::new();
    r.vm.set(|s| s.file = Some(line("a", 300)));
    r.sync().unwrap();
    r.vm.set(|s| s.file.as_mut().unwrap().extend_from_slice(&line("b", 100)));
    let strays = [S3Key::Segment { session: SID.into(), gen: 1, offset: 300 }, S3Key::Base { session: SID.into(), gen: 2 }, S3Key::Base { session: SID.into(), gen: 3 }].map(|k| r.key_of(k));
    for k in &strays {
        r.w.s3.put(k, b"a cut sync's push");
    }
    let rep = r.sync().unwrap();
    let g4 = r.key_of(S3Key::Base { session: SID.into(), gen: 4 });
    assert_eq!(rep.pushed.as_ref().map(|p| (p.kind, p.key.clone())), Some(("base", g4.clone())), "past the highest generation S3 holds");
    let m = r.w.manifest().unwrap();
    for k in &strays {
        assert!(m.superseded.contains(k), "{k} superseded: {:?}", m.superseded);
    }
    r.sync().unwrap();
    for k in &strays {
        assert!(r.w.s3.get(k).is_none(), "{k} deleted");
    }
    // A subtree file S3 refuses after the main push: the sync fails, the main push is committed already.
    r.vm.set(|s| {
        s.file.as_mut().unwrap().extend_from_slice(&line("c", 100));
        s.subtree = vec![(format!("{SLUG}/{SID}/subagents/a.jsonl"), line("sub", 50))];
        s.refused_rel = Some(format!("{SLUG}/{SID}/subagents/a.jsonl"));
    });
    assert!(matches!(r.sync(), Err(BridgeError::S3 { status: 403, .. })));
    let m = r.w.manifest().unwrap();
    assert_eq!((m.committed, m.parts.last().map(|p| p.len)), (500, Some(100)), "the segment committed before the files: {m:?}");
    r.vm.set(|s| s.refused_rel = None);
    let rep = r.sync().unwrap();
    assert_eq!((rep.pushed.is_none(), rep.files), (true, 1), "nothing of the transcript to push again");
}

// ---- the data plane's five transfer requests (HttpsEndpoint) ----

/// One request as the in-test server read it.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// A loopback server answering `script` in order (status, body), one request per connection.
async fn server(script: Vec<(u16, Vec<u8>)>) -> (std::net::SocketAddr, std::sync::Arc<Mutex<Vec<Seen>>>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    let script = std::sync::Arc::new(Mutex::new(VecDeque::from(script)));
    let s = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let (seen, script) = (s.clone(), script.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 65536];
                let end = loop {
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break end;
                    }
                    let n = conn.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                };
                let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                let mut lines = head.split("\r\n");
                let mut first = lines.next().unwrap().split(' ');
                let (method, target) = (first.next().unwrap().to_string(), first.next().unwrap().to_string());
                let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
                let len: usize = headers.iter().find(|(k, _)| k == "content-length").map_or(0, |(_, v)| v.parse().unwrap());
                let mut body = buf[end + 4..].to_vec();
                while body.len() < len {
                    let n = conn.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                seen.lock().unwrap().push(Seen { method, target, headers, body });
                let (status, answer) = script.lock().unwrap().pop_front().unwrap_or((500, b"no script left".to_vec()));
                let out = format!("HTTP/1.1 {status} X\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n", answer.len());
                let _ = conn.write_all(out.as_bytes()).await;
                let _ = conn.write_all(&answer).await;
                let _ = conn.shutdown().await;
            });
        }
    });
    (addr, seen)
}

/// `HttpsEndpoint`'s five transfer requests in the lab (plain http to the
/// in-test server): each its method and route on the app port, the stat's
/// and the view's query, a push's, a pull's and a tail's JSON body (the
/// presigned URLs in the body only, never the request line), 200 and 201
/// carrying their reply, the tail's 204 none; a 404 is a VM without
/// `transcript_s3_v1` (exit 7, `make deploy`).
#[tokio::test]
async fn the_five_transfer_requests_go_as_the_shim_reads_them() {
    let fake = FakeS3::start();
    let target = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(fake.addr()) };
    let rel = format!("{SLUG}/{SID}.jsonl");
    let stat = TranscriptStat { present: true, size: 52000, ino: Some(7), delta_sha256: Some("b".repeat(64)), end_fp: Some("c".repeat(64)), fp_ok: Some(true), ..TranscriptStat::default() };
    let push_reply = TranscriptPushReply { s3_status: 200, s3_code: None, version_id: Some("fv2".into()), len: 3787, sha256: "b".repeat(64) };
    let pull_reply = TranscriptPullReply { written: true, size: 3787, sha256: Some("b".repeat(64)), parts: vec![PullPartReport { s3_status: 200, len: 3787, sha256: "b".repeat(64), ok: true }] };
    let (addr, seen) = server(vec![
        (200, serde_json::to_vec(&stat).unwrap()),
        (200, serde_json::to_vec(&push_reply).unwrap()),
        (201, serde_json::to_vec(&pull_reply).unwrap()),
        (200, serde_json::to_vec(&example()).unwrap()),
        (204, Vec::new()),
        (404, b"ai-env: no such route\n".to_vec()),
    ])
    .await;
    let dp = HttpsEndpoint::new(&VmKnobs { fake_api: Some("/nonexistent/fake.json".into()), agent_addr: Some(addr.to_string()), ..VmKnobs::default() }).unwrap();
    let agent = AgentTarget { vm_id: VM.into(), endpoint: format!("bed07657-5d0f-abe5-1e5e-6bc7bcb0b637{}", ai_env_cli::bridge::api::ENDPOINT_SUFFIX), session_token: Secret::new("s".repeat(64)), vpc: true, shell: false };
    let token = AuthToken { headers: std::collections::BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new("proxy-token-value".into()))]), port: APP_PORT, expires_at_unix: u64::MAX };
    let presign = |method, key: String, headers: Vec<(String, String)>| {
        let req = ai_env_cli::bridge::s3::presign::request(method, &target, Some(key), Vec::new(), headers, ai_env_cli::wire::s3::PRESIGN_EXPIRY);
        ai_env_cli::bridge::s3::presign::sign(ai_env_cli::bridge::s3::presign::lab_credentials(), &req, std::time::SystemTime::now()).unwrap()
    };
    // GET /transcript?rel=&from=&fp=&subtree=true
    let q = StatQuery { rel: rel.clone(), from: Some(48213), fp: Some("a".repeat(64)), subtree: true };
    let got = dp.transcript_stat_from(&agent, &token, &q).await.unwrap();
    assert_eq!((got.status, got.body), (200, Some(stat)));
    // POST /transcript/push
    let seg = S3Key::Segment { session: SID.into(), gen: 1, offset: 48213 }.render();
    let url = presign(ai_env_cli::bridge::s3::S3Method::Put, seg, ai_env_cli::bridge::s3::presign::write_headers(3787, &"b".repeat(64), true).unwrap());
    let push = TranscriptPush { rel: rel.clone(), from: 48213, len: 3787, sha256: "b".repeat(64), url: url.clone(), owner: LAB_OWNER.into(), proxy: None };
    let got = dp.transcript_push(&agent, &token, &push).await.unwrap();
    assert_eq!((got.status, got.body), (200, Some(push_reply)));
    // POST /transcript/pull (201)
    let get = presign(ai_env_cli::bridge::s3::S3Method::Get, S3Key::Base { session: SID.into(), gen: 1 }.render(), Vec::new());
    let pull = TranscriptPull { rel: rel.clone(), parts: vec![ai_env_cli::wire::workspace::PullPart { url: get, len: 3787, sha256: Some("b".repeat(64)) }], sha256: None, owner: LAB_OWNER.into(), proxy: None };
    let got = dp.transcript_pull(&agent, &token, &pull).await.unwrap();
    assert_eq!((got.status, got.body), (201, Some(pull_reply)));
    // GET /transcript/view?rel=&n=
    let got = dp.transcript_view(&agent, &token, &ViewQuery { rel: rel.clone(), n: 10 }).await.unwrap();
    assert_eq!((got.status, got.body), (200, Some(example())));
    // POST /transcript/tail: 204, nothing to parse.
    let tail_key = S3Key::Tail { session: SID.into(), gen: 1, offset: 52000 }.render();
    let tail_url = presign(ai_env_cli::bridge::s3::S3Method::Put, tail_key, vec![("if-none-match".into(), "*".into())]);
    let tail = TranscriptTail { rel: rel.clone(), from: 52000, url: tail_url, owner: LAB_OWNER.into(), proxy: None, expires_at: ai_env_cli::wire::time::unix_now() + 3600 };
    let got = dp.transcript_tail(&agent, &token, &tail).await.unwrap();
    assert_eq!((got.status, got.body), (204, None));
    // A 404: the image lacks transcript_s3_v1 (exit 7).
    let got = dp.transcript_view(&agent, &token, &ViewQuery { rel: rel.clone(), n: 10 }).await.unwrap();
    assert_eq!(got.status, 404);
    match verdict_cap("GET /transcript/view", APP_PORT, CAP_TRANSCRIPT_S3_V1, &got) {
        Verdict::Fail(e @ BridgeError::NoCapability { .. }) => assert_eq!(ai_env_cli::errors::CliError::from(e).exit_code(), 7),
        other => panic!("expected NoCapability, got {other:?}"),
    }
    let seen = seen.lock().unwrap().clone();
    let lines: Vec<(String, String)> = seen.iter().map(|s| (s.method.clone(), s.target.split('?').next().unwrap().to_string())).collect();
    assert_eq!(
        lines,
        [("GET", "/transcript"), ("POST", "/transcript/push"), ("POST", "/transcript/pull"), ("GET", "/transcript/view"), ("POST", "/transcript/tail"), ("GET", "/transcript/view")].map(|(m, p)| (m.to_string(), p.to_string()))
    );
    let query = |i: usize| seen[i].target.split_once('?').map(|(_, q)| q.to_string()).unwrap_or_default();
    assert!(query(0).contains("rel=") && query(0).contains("from=48213") && query(0).contains(&format!("fp={}", "a".repeat(64))) && query(0).contains("subtree=true"), "{}", query(0));
    assert!(query(3).contains("n=10") && query(3).contains("rel="), "{}", query(3));
    for s in &seen {
        assert!(!s.target.contains("X-Amz"), "a presigned URL never in the request line: {}", s.target);
        assert_eq!(s.headers.iter().find(|(k, _)| k == "x-aws-proxy-port").map(|(_, v)| v.as_str()), Some("8080"), "the app port");
    }
    for i in [1, 2, 4] {
        assert_eq!(seen[i].headers.iter().find(|(k, _)| k == "content-type").map(|(_, v)| v.as_str()), Some("application/json"));
        let body: serde_json::Value = serde_json::from_slice(&seen[i].body).unwrap();
        assert!(body["rel"] == rel.as_str() && serde_json::to_string(&body).unwrap().contains("X-Amz-Signature"), "the URL travels in the body: {body}");
    }
    let sent: TranscriptPush = serde_json::from_slice(&seen[1].body).unwrap();
    assert_eq!(sent, push, "the push as the Mac built it");
}

/// A tail is only ever the main transcript's (S9 §13, I2): `HttpsEndpoint`
/// refuses a tail of a subtree file, and a pull that would append a tail to
/// one, before any request (`Config`, exit 1): nothing reaches the VM.
#[tokio::test]
async fn a_subtree_files_tail_is_refused_before_any_request() {
    use ai_env_cli::bridge::s3::S3Method;
    use ai_env_cli::wire::workspace::PullPart;
    let fake = FakeS3::start();
    let target = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab(fake.addr()) };
    let (addr, seen) = server(vec![(204, Vec::new()), (201, Vec::new())]).await;
    let dp = HttpsEndpoint::new(&VmKnobs { fake_api: Some("/nonexistent/fake.json".into()), agent_addr: Some(addr.to_string()), ..VmKnobs::default() }).unwrap();
    let agent = AgentTarget { vm_id: VM.into(), endpoint: format!("bed07657-5d0f-abe5-1e5e-6bc7bcb0b637{}", ai_env_cli::bridge::api::ENDPOINT_SUFFIX), session_token: Secret::new("s".repeat(64)), vpc: true, shell: false };
    let token = AuthToken { headers: std::collections::BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new("proxy-token-value".into()))]), port: APP_PORT, expires_at_unix: u64::MAX };
    let presign = |method, key: S3Key, headers: Vec<(String, String)>| {
        let req = ai_env_cli::bridge::s3::presign::request(method, &target, Some(key.render()), Vec::new(), headers, ai_env_cli::wire::s3::PRESIGN_EXPIRY);
        ai_env_cli::bridge::s3::presign::sign(ai_env_cli::bridge::s3::presign::lab_credentials(), &req, std::time::SystemTime::now()).unwrap()
    };
    let config = |e: Option<BridgeError>| match e {
        Some(BridgeError::Config(m)) => {
            assert_eq!(ai_env_cli::errors::CliError::from(BridgeError::Config(m.clone())).exit_code(), 1);
            m
        }
        other => panic!("expected Config, got {other:?}"),
    };
    let sub = format!("{SLUG}/{SID}/subagents/agent-a1.jsonl");
    let tail_key = S3Key::Tail { session: SID.into(), gen: 1, offset: 4096 };
    let tail = TranscriptTail { rel: sub.clone(), from: 4096, url: presign(S3Method::Put, tail_key.clone(), vec![("if-none-match".into(), "*".into())]), owner: LAB_OWNER.into(), proxy: None, expires_at: ai_env_cli::wire::time::unix_now() + 3600 };
    let m = config(dp.transcript_tail(&agent, &token, &tail).await.err());
    assert!(m.starts_with("POST /transcript/tail: the request") && m.contains("a tail is only ever the session's main transcript"), "{m}");
    let file = S3Key::File { session: SID.into(), sha256: "d".repeat(64) };
    let parts = vec![PullPart { url: presign(S3Method::Get, file, Vec::new()), len: 4096, sha256: Some("d".repeat(64)) }, PullPart { url: presign(S3Method::Get, tail_key, Vec::new()), len: 10, sha256: None }];
    let pull = TranscriptPull { rel: sub, parts, sha256: None, owner: LAB_OWNER.into(), proxy: None };
    let m = config(dp.transcript_pull(&agent, &token, &pull).await.err());
    assert!(m.starts_with("POST /transcript/pull: the request") && m.contains("a tail (part number 1)"), "{m}");
    assert!(seen.lock().unwrap().is_empty(), "nothing reached the VM");
}

// ---- session migrate-s9: a gone VM's S8 mirror ----

/// `session migrate-s9 --yes` of a gone VM's mirror: uploaded by its sha256
/// key, a manifest of a VM-begun chat (`origin = "vm"`), its view built here
/// in its place, the mirror deleted (nothing of it kept), audited
/// `transcript_migrate`. A mirror with a finding is not uploaded: its view
/// still replaces it and the mirror moves to `origin/` (`skipped`, naming
/// the finding and `forget --purge`), nothing sent.
#[test]
fn migrate_s9_sends_a_gone_vms_mirror_to_s3_and_leaves_its_view() {
    use ai_env_cli::bridge::s3::commands::{migrate_one, Mirror};
    use ai_env_cli::bridge::vm::cmd::Ctx;
    let w = World::new(FakeS3::start());
    let ctx = Ctx { paths: w.paths.clone(), cfg: w.cfg.clone(), knobs: VmKnobs::default() };
    let row = ai_env_cli::bridge::registry::SessionRow { session_id: SID.into(), mode: "remote".into(), slug: Some(SLUG.into()), cwd: Some("/Users/mike/Documents/DeFi/ai-env".into()), ..ai_env_cli::bridge::registry::SessionRow::default() };
    let mirror = [line("vm turn 0", 300), line("vm turn 1", 300)].concat();
    w.plant(&format!("{SID}.jsonl"), &mirror);
    let chat = s3stage::locate(&w.projects, &[SLUG], SID, s3stage::STAGE_MAX).unwrap().unwrap();
    let api = FakeMicrovmApi::new();
    let m = Mirror { row: row.clone(), chat, vm: None };
    let done = w.rt().block_on(migrate_one(&ctx, &api, &w.target, &m, &w.projects, &Rules::defaults(), &builder));
    assert_eq!((done.from, done.outcome, done.why.as_deref()), ("gone_vm", "migrated", None), "{done:?}");
    let man = w.manifest().unwrap();
    assert_eq!((man.origin.as_str(), man.parts.len()), (manifest::ORIGIN_VM, 1));
    assert_eq!(w.s3.get(&man.parts[0].key).as_deref(), Some(mirror.as_slice()));
    assert!(std::fs::read_to_string(w.view_path()).unwrap().starts_with(VIEW_MARK_PREFIX), "the view replaced the mirror");
    assert!(!w.paths.transcript_origin(SID).exists(), "the mirror is not kept");
    assert_eq!(w.rows("transcript_migrate")[0]["detail"]["outcome"], "migrated");
    // A mirror with a finding: not uploaded; its view replaces it, the mirror goes to origin/.
    let w2 = World::new(FakeS3::start());
    let ctx2 = Ctx { paths: w2.paths.clone(), cfg: w2.cfg.clone(), knobs: VmKnobs::default() };
    let leaked = format!("{}aws_access_key_id = {}{}\n", String::from_utf8(line("before", 200)).unwrap(), "AKIA", "Q".repeat(16));
    w2.plant(&format!("{SID}.jsonl"), leaked.as_bytes());
    let chat = s3stage::locate(&w2.projects, &[SLUG], SID, s3stage::STAGE_MAX).unwrap().unwrap();
    let done = w2.rt().block_on(migrate_one(&ctx2, &api, &w2.target, &Mirror { row, chat, vm: None }, &w2.projects, &Rules::defaults(), &builder));
    assert_eq!((done.from, done.outcome), ("gone_vm", "skipped"), "{done:?}");
    let why = done.why.unwrap();
    assert!(why.contains("rule aws-access-key-id") && why.contains(&format!("ai-env session forget {SID} --purge")) && !why.contains("AKIAQ"), "{why}");
    assert!(w2.s3.requests().is_empty() && w2.manifest().is_none(), "nothing sent, no manifest");
    assert_eq!(std::fs::read(w2.paths.transcript_origin(SID).join(format!("{SID}.jsonl"))).unwrap(), leaked.as_bytes(), "the mirror kept under origin/");
    assert!(std::fs::read_to_string(w2.view_path()).unwrap().starts_with(VIEW_MARK_PREFIX));
}

// ---- the lead's S3 round trip (plans/s9-contracts.md §10 step 8, §11) ----------------------

/// The S3 round trip end to end, offline: the real `ai-env-claude` in remote
/// mode through the remote rig (`common::remote::RemoteRig`). Its VM is the
/// rig's in-process shim, which runs the real helper (`ai-env shim-io`) and
/// the fake curl in front of the real one (`S3CURL_REAL`, the rig's default
/// since the cut-over), so the transcript's bytes move between the VM's
/// disk and the tests' S3 as the image's curl moves them, on URLs the
/// Mac presigned with the fake API's lab key. The Mac never holds a remote
/// chat's transcript: its projects directory keeps the chat's view.
mod round_trip {
    use super::common::{is_init, is_response_to, is_result_for, Harness, Link};
    use ai_env_cli::bridge::config::Paths;
    use ai_env_cli::bridge::s3::manifest::{self, Manifest};
    use ai_env_cli::wire::s3::S3Key;
    use ai_env_cli::wire::view::VIEW_MARK_PREFIX;
    use serde_json::Value;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    /// Upper bound for a step of a session (the rig's commands are bounded the same way).
    const T: Duration = Duration::from_secs(30);

    /// The session's first `system/init` after `initialize` was answered: its session id.
    fn open(h: &mut Harness) -> String {
        let init = h.send_initialize();
        h.expect_out(|v| is_response_to(v, &init), T);
        let started = h.expect_out(is_init, T);
        started["session_id"].as_str().unwrap_or_else(|| panic!("no session id: {started}")).to_string()
    }

    /// One turn: the prompt, its result.
    fn turn(h: &mut Harness, text: &str) {
        let u = h.send_user(text);
        h.expect_out(|v| is_result_for(v, &u), T);
    }

    /// Until the turn's transcript step wrote the session's view (`transcript_view`, `written`): the
    /// code-out trigger syncs the transcript to S3 after the turn's fetch, then rewrites the view.
    fn synced(h: &mut Harness, sid: &str, views: usize) {
        h.wait_until("the turn's transcript synced to S3 and its view written", T, |h| {
            h.audit_events("transcript_view").iter().filter(|r| r["detail"]["session"] == sid && r["detail"]["outcome"] == "written").count() >= views
        });
    }

    /// The host's EOF ends the session: exit 0.
    fn closed(h: &mut Harness) {
        h.close_stdin();
        let (status, _) = h.wait(T);
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
    }

    /// The bridge root's manifest of `sid` (`state/transcripts/<sid>/manifest.toml`).
    fn manifest_of(h: &Harness, sid: &str) -> Manifest {
        manifest::read(&Paths::from_root_and_env(h.bridge(), None), sid).unwrap().unwrap_or_else(|| panic!("no manifest of {sid}"))
    }

    /// `<root>`'s regular files, by path below it.
    fn files_under(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = e.path();
                match e.file_type() {
                    Ok(t) if t.is_dir() => dirs.push(path),
                    Ok(t) if t.is_file() => out.push(path.strip_prefix(root).unwrap().to_path_buf()),
                    _ => {}
                }
            }
        }
        out.sort();
        out
    }

    /// What the Mac keeps of the chat: exactly one file under its projects
    /// directory, the view at `<slug>/<sid>.jsonl` (every line the view's
    /// mark, its user and assistant entries); no line of the VM's
    /// `transcript` anywhere under it. The view's entries.
    fn only_the_view(h: &Harness, sid: &str, transcript: &[u8]) -> Vec<Value> {
        let mac = h.prepared.mac_projects();
        let view = PathBuf::from(h.slug()).join(format!("{sid}.jsonl"));
        assert_eq!(files_under(&mac), std::slice::from_ref(&view), "the Mac keeps the view, nothing else of the chat");
        let text = std::fs::read_to_string(mac.join(&view)).unwrap();
        assert!(!text.is_empty() && text.lines().all(|l| l.starts_with(VIEW_MARK_PREFIX)), "every line the view's: {text}");
        for line in String::from_utf8_lossy(transcript).lines() {
            assert!(!text.contains(line), "a line of the VM's transcript on the Mac: {line}");
        }
        let entries: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).filter(|v: &Value| v["type"] != "ai-title").collect();
        assert!(entries.first().is_some_and(|e| e["type"] == "user") && entries.iter().all(|e| e["sessionId"] == sid), "{entries:?}");
        entries
    }

    /// A presigned URL never reaches the Mac's records: the census, the
    /// audit, the registry, the manifests, the wrapper's log.
    fn no_url_on_the_mac(h: &Harness) {
        let bridge = h.bridge();
        for rel in files_under(&bridge) {
            let text = String::from_utf8_lossy(&std::fs::read(bridge.join(&rel)).unwrap_or_default()).into_owned();
            assert!(!text.contains("X-Amz-Signature") && !text.contains("X-Amz-Credential"), "a presigned URL in {}", rel.display());
        }
    }

    /// The VM's copy of the transcript of `sid`.
    fn vm_transcript(h: &Harness, sid: &str) -> PathBuf {
        h.vm_projects().join(h.slug()).join(format!("{sid}.jsonl"))
    }

    /// S9 M2 to M4, offline: a remote chat's turn lands in S3 and the Mac
    /// keeps only its view. The VM's CLI runs without `--session-mirror`
    /// and writes its transcript (the turn's entries and 2.1.302's
    /// api-request lines) on the VM's disk. After the turn's code-out, the
    /// trigger syncs it: the VM's curl PUTs the whole file as generation 1's
    /// base (`-q -K /dev/fd/3`, the URL on its fd 3 only) and the tests' S3
    /// holds exactly the VM's bytes; the manifest commits them (origin `vm`,
    /// the base's version, its sha256, the VM); the view is rewritten. The
    /// Mac's projects directory holds that view and nothing else, no line of
    /// the transcript; the registry row says the transcript is kept in S3;
    /// no presigned URL is in any of the Mac's records; the end row says
    /// nothing was mirrored.
    #[test]
    fn s3_a_turn_lands_in_the_fake_s3_and_the_mac_keeps_only_the_view() {
        let mut h = Harness::prepare().spawn_on(Link::Remote, "", &[], &[("FAKE_WRITE_TRANSCRIPT", "1")]);
        let sid = open(&mut h);
        turn(&mut h, "hello");
        synced(&mut h, &sid, 1);
        let vm_bytes = std::fs::read(vm_transcript(&h, &sid)).expect("the VM's transcript");
        assert!(String::from_utf8_lossy(&vm_bytes).lines().any(|l| l.contains("\"type\":\"api-request\"")), "the file holds 2.1.302's api-request lines");
        let m = manifest_of(&h, &sid);
        let base = S3Key::Base { session: sid.clone(), gen: 1 }.render();
        let vm = h.audit_events("session_remote_start")[0]["detail"]["id"].as_str().expect("the VM").to_string();
        assert_eq!((m.origin.as_str(), m.gen, m.committed, m.parts.len(), m.vm.as_deref()), (manifest::ORIGIN_VM, 1, vm_bytes.len() as u64, 1, Some(vm.as_str())), "{m:?}");
        assert_eq!((m.parts[0].key.as_str(), m.parts[0].sha256.as_str()), (base.as_str(), super::sha(&vm_bytes).as_str()));
        assert_eq!(h.rig().s3().get(&base).as_deref(), Some(vm_bytes.as_slice()), "the tests' S3 holds the VM's transcript, byte for byte");
        let held = h.rig().s3().objects();
        assert!(held.iter().any(|o| o.key == base && o.version_id == m.parts[0].version_id), "the version S3 named is the manifest's: {held:?}");
        let puts: Vec<_> = h.rig().vm_curl_calls().into_iter().filter(|c| c.conf("request") == ["PUT"]).collect();
        assert!(!puts.is_empty() && puts.iter().all(|c| c.args == ["-q", "-K", "/dev/fd/3"]), "curl in the VM, its config on fd 3: {puts:?}");
        assert!(puts.iter().any(|c| c.conf("url").first().is_some_and(|u| u.contains(&format!("/{base}?")))), "the base went up from the VM: {puts:?}");
        let push = h.audit_events("transcript_push");
        assert!(push.iter().any(|r| r["detail"]["kind"] == "base" && r["detail"]["s3_status"] == "200" && r["detail"]["session"] == sid.as_str()), "{push:?}");
        let entries = only_the_view(&h, &sid, &vm_bytes);
        assert_eq!(entries.iter().map(|e| e["type"].as_str().unwrap_or_default()).collect::<Vec<_>>(), ["user", "assistant"], "the turn, as the view shows it");
        closed(&mut h);
        let argv = h.argv_log().into_iter().next().expect("the VM's argv");
        assert!(!argv.iter().any(|a| a == "--session-mirror"), "{argv:?}");
        let note = h.end_note();
        assert!(note.contains("; mirror:0/0; "), "nothing mirrored: {note}");
        let rows = h.registry_rows();
        let row = rows.iter().find(|r| r.get("session_id").and_then(toml::Value::as_str) == Some(sid.as_str())).unwrap_or_else(|| panic!("{rows:?}"));
        let field = |k: &str| row.get(k).and_then(toml::Value::as_str);
        assert_eq!((field("transcript_home"), field("origin"), field("view")), (Some("s3"), Some("vm"), Some(format!("{}/{sid}.jsonl", h.slug()).as_str())), "{row:?}");
        only_the_view(&h, &sid, &std::fs::read(vm_transcript(&h, &sid)).unwrap());
        no_url_on_the_mac(&h);
    }

    /// S9's reopen into a new VM, offline: a chat's transcript comes back
    /// from S3, every byte the first VM wrote. A first session (rig A) runs
    /// a turn: the sync commits the VM's file as generation 1's base; after
    /// the host's EOF the CLI writes one more line, which the closing
    /// suspend's `/suspend` pushes as the tail (`g1/t/<committed>`). The chat
    /// is then reopened (`--resume`) on a new VM (rig B: a fresh shim and
    /// disk, the same Mac's manifest and registry row, the same S3): its
    /// row's VM is unknown there, so a VM starts (`vm_how:started`), and
    /// before the spawn the restore pulls the base and the tail into the new
    /// VM (`transcript:restored`, `transcript_pull` written: two parts, every
    /// byte, before `session_remote_start`), from which the CLI resumes. Its
    /// turn then goes up as generation 1's segment at the committed length
    /// (the restored prefix's fingerprint matched: no new generation), so S3
    /// holds the whole conversation; each Mac keeps only the view.
    #[test]
    fn s3_a_reopen_in_a_new_vm_restores_from_the_fake_s3() {
        let knobs = [("FAKE_WRITE_TRANSCRIPT", "1"), ("FAKE_FINAL_MIRROR_MS", "200"), ("FAKE_EXIT_DELAY_MS", "400")];
        let mut a = Harness::prepare().spawn_on(Link::Remote, "", &[], &knobs);
        let sid = open(&mut a);
        turn(&mut a, "remember the word lantern");
        synced(&mut a, &sid, 1);
        let committed = manifest_of(&a, &sid).committed;
        closed(&mut a);
        let vm1 = a.audit_events("session_remote_start")[0]["detail"]["id"].as_str().expect("the first VM").to_string();
        let first = std::fs::read(vm_transcript(&a, &sid)).expect("the first VM's transcript");
        assert!(first.len() as u64 > committed, "the CLI wrote on after the last sync");
        // The closing suspend's /suspend pushes the tail past the committed length.
        let tail = S3Key::Tail { session: sid.clone(), gen: 1, offset: committed }.render();
        let until = Instant::now() + T;
        while a.rig().s3().get(&tail).is_none() {
            assert!(Instant::now() < until, "no tail {tail} in S3: hooks {:?}\n{}", a.rig().endpoint.hooks(), a.wrapper_log());
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(a.rig().s3().get(&tail).as_deref(), Some(&first[committed as usize..]), "the tail is what the CLI wrote after the sync");
        // The same Mac's records of the chat, a new VM (rig B, its fake API past rig A's first id), the same S3 (rig A's).
        let mut b = Harness::prepare();
        b.rig().update_fake(|st| st.next += 1);
        let rig_b_bridge = b.rig().bridge();
        let copy = |rel: PathBuf| {
            use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
            let to = rig_b_bridge.join(&rel);
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(to.parent().unwrap()).unwrap();
            std::fs::copy(a.bridge().join(&rel), &to).unwrap();
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        copy(PathBuf::from("state/transcripts").join(&sid).join("manifest.toml"));
        copy(PathBuf::from("state/sessions").join(format!("{sid}.toml")));
        let s3 = a.rig().s3().addr().to_string();
        let resume = format!("--resume={sid}");
        let mut h = b.spawn_on(Link::Remote, "", &[&resume], &[("FAKE_RESUME_NEEDS_FILE", "1"), ("FAKE_WRITE_TRANSCRIPT", "1"), ("AI_ENV_BRIDGE_LAB_S3_ADDR", &s3)]);
        assert_eq!(open(&mut h), sid, "the same session");
        let restored = std::fs::read(vm_transcript(&h, &sid)).expect("the new VM's copy");
        assert_eq!(restored, first, "the new VM holds every byte the first one wrote: the base and the tail");
        let lines = String::from_utf8_lossy(&first).lines().count();
        assert!(h.env_log().iter().any(|l| *l == format!("gen 1 resumed lines={lines}")), "the CLI resumed from the restored copy: {:?}", h.env_log());
        turn(&mut h, "which word?");
        synced(&mut h, &sid, 1);
        closed(&mut h);
        let note = h.end_note();
        let part = |name: &str| note.split("; ").find_map(|p| p.strip_prefix(name)?.strip_prefix(':')).map(str::to_string);
        let vm2 = part("vm").expect("the new VM");
        assert_ne!(vm2, vm1, "a new VM");
        assert_eq!((part("vm_how").as_deref(), part("transcript").as_deref()), (Some("started"), Some("restored")), "{note}");
        let events: Vec<Value> = h.audit_rows();
        let at = |pred: &dyn Fn(&Value) -> bool| events.iter().position(pred);
        let pull = at(&|r: &Value| r["event"] == "transcript_pull").unwrap_or_else(|| panic!("no transcript_pull: {events:?}"));
        let d = &events[pull]["detail"];
        assert_eq!((d["outcome"].as_str(), d["parts"].as_str(), d["bytes"].as_str(), d["vm"].as_str()), (Some("written"), Some("2"), Some(first.len().to_string().as_str()), Some(vm2.as_str())), "the base and the tail into the new VM: {d}");
        assert!(at(&|r: &Value| r["event"] == "session_remote_start").is_some_and(|start| pull < start), "restored before the spawn: {events:?}");
        // The turn on the new VM went up as a segment after the committed prefix: the restored bytes are S3's.
        let now = std::fs::read(vm_transcript(&h, &sid)).unwrap();
        assert!(now.starts_with(&first) && now.len() > first.len(), "the conversation goes on from the restored copy");
        let segment = S3Key::Segment { session: sid.clone(), gen: 1, offset: committed }.render();
        assert_eq!(a.rig().s3().get(&segment).as_deref(), Some(&now[committed as usize..]), "the tail's bytes and the new turn, as generation 1's segment");
        let m = manifest_of(&h, &sid);
        assert_eq!((m.gen, m.committed, m.parts.iter().map(|p| p.key.as_str()).collect::<Vec<_>>(), m.vm.as_deref()), (1, now.len() as u64, vec![S3Key::Base { session: sid.clone(), gen: 1 }.render().as_str(), segment.as_str()], Some(vm2.as_str())), "{m:?}");
        only_the_view(&a, &sid, &first);
        only_the_view(&h, &sid, &now);
        no_url_on_the_mac(&a);
        no_url_on_the_mac(&h);
    }
}

/// `session migrate-s9` lists and migrates a mirror by one rule
/// (`Mirror::live_vm`): the VM of an S8 image (no `transcript_s3_v1`) that
/// still runs is `gone_vm` in the dry run's list and in the migration (its
/// mirror goes up from this Mac, no GetMicrovm asked), while the same row
/// with the cap is listed `live_vm`.
#[test]
fn migrate_s9_lists_and_migrates_a_running_s8_image_vm_alike() {
    use ai_env_cli::bridge::api::{Call, VmInfo, VmState, FAKE_IMAGE_ARN};
    use ai_env_cli::bridge::s3::commands::{migrate_one, mirrors, would_migrate};
    use ai_env_cli::bridge::vm::cmd::Ctx;
    use ai_env_cli::bridge::vm::registry::{self as vm_registry, RowStatus, VmRow};
    let w = World::new(FakeS3::start());
    let ctx = Ctx { paths: w.paths.clone(), cfg: w.cfg.clone(), knobs: VmKnobs::default() };
    let row = ai_env_cli::bridge::registry::SessionRow {
        session_id: SID.into(),
        mode: "remote".into(),
        slug: Some(SLUG.into()),
        cwd: Some("/Users/mike/Documents/DeFi/ai-env".into()),
        microvm_id: Some(VM.into()),
        ..ai_env_cli::bridge::registry::SessionRow::default()
    };
    ai_env_cli::bridge::registry::write(&w.paths, &row).unwrap();
    vm_registry::write_row(&w.paths, &VmRow { id: VM.into(), status: RowStatus::Running, caps: Some(vec!["credential_cache".into(), "workspace_v1".into()]), ..VmRow::default() }).unwrap();
    let api = FakeMicrovmApi::new();
    api.insert_vm(VmInfo {
        id: VM.into(),
        state: VmState::Running,
        endpoint: "vm.example.invalid".into(),
        image_arn: FAKE_IMAGE_ARN.into(),
        image_version: "1".into(),
        started_at_unix: Some(1_760_000_000),
        max_duration_s: 3600,
        state_reason: None,
        execution_role_arn: None,
        idle: None,
        ingress: Vec::new(),
        egress: Vec::new(),
        terminated_at_unix: None,
    });
    let mirror = [line("vm turn 0", 300), line("vm turn 1", 300)].concat();
    w.plant(&format!("{SID}.jsonl"), &mirror);
    let found = mirrors(&w.paths, &w.projects).unwrap();
    assert_eq!((found.len(), found[0].vm.as_ref().map(|v| v.id.as_str())), (1, Some(VM)), "its row says it runs");
    let listed = would_migrate(&found[0]);
    assert_eq!((listed.from, listed.outcome, listed.vm.as_deref()), ("gone_vm", "would_migrate", Some(VM)));
    let done = w.rt().block_on(migrate_one(&ctx, &api, &w.target, &found[0], &w.projects, &Rules::defaults(), &builder));
    assert_eq!((done.from, done.outcome, done.vm.as_deref()), (listed.from, "migrated", Some(VM)), "{done:?}");
    assert!(!api.calls().iter().any(|c| matches!(c, Call::Get(_))), "its caps decide, as in the dry run: {:?}", api.calls());
    let man = w.manifest().unwrap();
    assert_eq!((man.origin.as_str(), w.s3.get(&man.parts[0].key).as_deref()), (manifest::ORIGIN_VM, Some(mirror.as_slice())), "the mirror went up from this Mac");
    assert_eq!(w.rows("transcript_migrate")[0]["detail"]["from"], "gone_vm");
    let mut with_cap = found[0].clone();
    with_cap.vm.as_mut().and_then(|v| v.caps.as_mut()).unwrap().push(CAP_TRANSCRIPT_S3_V1.into());
    assert_eq!(would_migrate(&with_cap).from, "live_vm", "the same rule names a VM with the cap");
}
