//! The per-turn sync (S9 plan §5, G4): what the VM's transcript gained since
//! the last commit goes from the VM to S3, through presigned URLs this Mac
//! signs, and the Mac keeps only the manifest and the view. One sync of a
//! session, under its manifest lock:
//!
//! 1. the keys a compaction replaced are deleted (the Mac's DeleteObject;
//!    delete markers);
//! 2. `GET /transcript?rel=&from=<committed>&fp=<fp>&subtree=true`: the VM's
//!    size, inode, the sha256 of what it holds past `committed`, its end
//!    fingerprint, whether its prefix still hashes to the manifest's, and the
//!    session's subtree files;
//! 3. the push `manifest::plan_push` decides: a segment at `committed`, or a
//!    full copy as the next generation's base (a rewritten file, a
//!    compaction), presigned PUT (`Content-Length`, `x-amz-checksum-sha256`,
//!    `If-None-Match: *`, the owner) and sent as `POST /transcript/push`
//!    (helper, then curl as `ai-env-net`, then S3); a 400 `BadDigest` on a
//!    segment or a base starts a new generation; the first 412 lists
//!    `v1/<sid>/vm/` once and starts the generation after the highest one
//!    S3 holds, the keys a cut sync left above the manifest's generation
//!    (and the refused segment's) superseded; the main push stored, the
//!    manifest is committed at once (a failure after it never strands its
//!    key); each subtree file the manifest lacks goes up as
//!    `v1/<sid>/vm/f/<sha256>` (a 412 there commits: the key is its bytes'
//!    sha256), and a committed file the VM no longer lists stays; a subtree
//!    over the helper's caps (413 `too_large`) is stat'ed without it, the
//!    main transcript synced alone (warned once per session);
//! 4. the manifest committed atomically, audited `transcript_push`; S10
//!    (R1): every tail the manifest records below the new committed length,
//!    or of an older generation, superseded with it
//!    (`Manifest::supersede_tails`);
//! 5. a fresh tail URL handed to the shim (`POST /transcript/tail`, for
//!    `/suspend` and `/terminate`), best effort, and recorded in the
//!    manifest's `tails`: the main transcript's only (its key names no
//!    file); a subtree file goes up whole at a sync, and one changed after
//!    the last sync is lost at `/suspend` or `/terminate`. The code-out
//!    trigger hands one too before any sync (from 0 when nothing is
//!    committed: `g1/t/0000000000000000`), before each turn's fetch and,
//!    S10, at every unpark ([`SyncCtx::hand_fresh_tail`]), so a chat closed
//!    before its sync still has its bytes pushed at `/suspend` or
//!    `/terminate`. S10 (R1): the shim drops a URL only once S3 answered
//!    its push, and those hands follow the chain of tails S3 holds from the
//!    committed length ([`tail_chain`]), so a line written after a
//!    `/suspend`'s push goes up through the next tail, and a restore
//!    follows the chain (`workspace::transcript::restore`); a move that
//!    restarts the file drops the chain ([`SyncCtx::drop_chain`]);
//! 6. `GET /transcript/view?rel=&n=`: the view written by `bridge::view`
//!    (audited `transcript_view`, `refused` included).
//!
//! Every request names `transcript_s3_v1` (a 404 is a VM without it, exit 7)
//! and answers by the session's deadline when it has one.
use super::client::{Listed, S3Client};
use super::manifest::{self, Manifest, ManifestFile, ManifestPart, ManifestTail, PushPlan};
use super::presign::{request, write_headers};
use super::{S3Method, S3Sign, TranscriptSync, TAIL_CHAIN_MAX};
use crate::bridge::agent::AgentTarget;
use crate::bridge::api::MicrovmApi;
use crate::bridge::config::Paths;
use crate::bridge::dataplane::{exchange, DataPlane, Exchange, TokenSource, Verdict};
use crate::bridge::errors::BridgeError;
use crate::bridge::remote::audit_event;
use crate::bridge::scan::Rules;
use crate::bridge::view::{ViewOutcome, ViewTarget};
use crate::wire::frame::CAP_TRANSCRIPT_S3_V1;
use crate::wire::s3::{PresignedUrl, S3Key, PRESIGN_EXPIRY, PUSH_MAX, TAIL_EXPIRY};
use crate::wire::workspace::{StatQuery, TranscriptPush, TranscriptStat, TranscriptTail, ViewQuery, APP_PORT};
use std::time::Instant;

/// S10 (R1): the longest the listing of a session's tails may take before
/// a turn's fetch or at an unpark ([`SyncCtx::hand_fresh_tail`]); past it
/// the tail at the committed length is handed, as when S3 cannot be listed.
const TAIL_LIST_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
/// S10 (R1): the longest such a hand waits for the manifest's lock to record
/// its tail; past it the tail stays handed, unrecorded (logged).
const TAIL_RECORD_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// What one sync works with: the control plane (GetMicrovm, and the
/// presigner), the data plane and its tokens, the VM, the session's
/// [`TranscriptSync`], the view's tripwires (the workspace's `ScanSet`).
pub struct SyncCtx<'a, A, D, T> {
    pub api: &'a A,
    pub dp: &'a D,
    pub tokens: &'a T,
    pub paths: &'a Paths,
    pub target: &'a AgentTarget,
    pub sync: &'a TranscriptSync,
    pub rules: &'a Rules,
    /// Back by then (none: the requests' own budgets). Only a reopen's
    /// restore sets one (generation 1's P3), and under it a pull carries at
    /// most `wire::s3::INLINE_MAX` (`workspace::transcript`'s `pull_one`).
    pub deadline: Option<tokio::time::Instant>,
}

/// The one push a sync made of the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pushed {
    /// `base` or `segment`.
    pub kind: &'static str,
    pub from: u64,
    pub len: u64,
    pub key: String,
}

/// What one sync did (`session sync --json`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub session: String,
    pub vm: String,
    pub pushed: Option<Pushed>,
    /// Subtree files pushed.
    pub files: u32,
    pub view: Option<ViewOutcome>,
    /// The committed length after the sync.
    pub committed: u64,
}

impl SyncReport {
    /// `synced` when anything went up, else `up_to_date`.
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        if self.pushed.is_some() || self.files > 0 {
            "synced"
        } else {
            "up_to_date"
        }
    }
}

/// The main transcript's rel: `<slug>/<sid>.jsonl`.
#[must_use]
pub fn main_rel(slug: &str, sid: &str) -> String {
    format!("{slug}/{sid}.jsonl")
}

/// A sha256 as the store records it: 64 lowercase hex digits.
#[must_use]
pub fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// An `x-amz-version-id` this Mac records (in the manifest, a presigned GET's
/// query and the `transcript_push` audit row): 1 to 1024 bytes of printable
/// ASCII without a space, `"` or `\`. The VM relays it: anything else is no
/// version S3 gave.
#[must_use]
pub fn is_version_id(v: &str) -> bool {
    (1..=1024).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// The extended stat's VM-authored digests, checked before anything is
/// committed from them: `delta_sha256`, `end_fp` and each subtree file's
/// sha256 are 64 lowercase hex digits when present.
fn check_stat(rel: &str, stat: &TranscriptStat) -> Result<(), BridgeError> {
    let bad = |what: &str| Err(BridgeError::Protocol(format!("GET /transcript of {rel} answered {what} that is not 64 lowercase hex digits")));
    if stat.delta_sha256.as_deref().is_some_and(|s| !is_digest(s)) {
        return bad("a delta sha256");
    }
    if stat.end_fp.as_deref().is_some_and(|s| !is_digest(s)) {
        return bad("an end fingerprint");
    }
    if stat.subtree.iter().any(|f| !is_digest(&f.sha256)) {
        return bad("a subtree file's sha256");
    }
    Ok(())
}

/// What a push's answer means for the store.
enum PushOutcome {
    /// S3 stored it (its version, empty when S3 named none).
    Stored(String),
    /// 412: the key holds an object already.
    Exists,
    /// 400 `BadDigest`: the VM's bytes changed under the stat.
    BadDigest,
}

impl<A: MicrovmApi + S3Sign, D: DataPlane, T: TokenSource> SyncCtx<'_, A, D, T> {
    fn x(&self, route: &'static str, idempotent: bool) -> Exchange<'_, A, T> {
        Exchange { api: self.api, tokens: self.tokens, vm_id: &self.target.vm_id, port: APP_PORT, cap: CAP_TRANSCRIPT_S3_V1, route, deadline: self.deadline, idempotent }
    }

    /// The extended stat of `q`, its digests checked ([`check_stat`]).
    pub async fn stat(&self, q: &StatQuery) -> Result<TranscriptStat, BridgeError> {
        let stat = match exchange(&self.x("GET /transcript", true), |t| async move { self.dp.transcript_stat_from(self.target, &t, q).await }).await? {
            (reply, Verdict::Done) => reply.body.ok_or_else(|| BridgeError::Protocol("GET /transcript answered without a stat".into()))?,
            (reply, _) => return Err(BridgeError::Protocol(format!("GET /transcript answered HTTP {} where a stat was due", reply.status))),
        };
        check_stat(&q.rel, &stat)?;
        Ok(stat)
    }

    /// A presigned request of `key` in the session's bucket.
    async fn presign(&self, method: S3Method, key: &S3Key, query: Vec<(String, String)>, headers: Vec<(String, String)>, expires: std::time::Duration) -> Result<PresignedUrl, BridgeError> {
        self.api.presign(&request(method, &self.sync.target, Some(key.render()), query, headers, expires)).await
    }

    /// Push `len` bytes of `rel` from `from` (their sha256 `sha256`) to
    /// `key`: presigned, sent, S3's answer read, audited `transcript_push`.
    /// What the VM relays is checked before anything is committed from it: a
    /// 200 with another length or sha256 than asked, or with a version id
    /// [`is_version_id`] refuses, is `Protocol` (the row then names no
    /// version); an S3 `<Code>` outside `[A-Za-z0-9]{1,64}` is dropped.
    #[allow(clippy::too_many_arguments)]
    async fn push(&self, sid: &str, kind: &'static str, rel: &str, key: &S3Key, from: u64, len: u64, sha256: &str) -> Result<PushOutcome, BridgeError> {
        if len == 0 || len > PUSH_MAX {
            return Err(BridgeError::Config(format!("{rel}: a push of {len} bytes (1 to {PUSH_MAX}: one PUT from the VM; a larger transcript cannot be pushed)")));
        }
        let t0 = Instant::now();
        let url = self.presign(S3Method::Put, key, Vec::new(), write_headers(len, sha256, true)?, PRESIGN_EXPIRY).await?;
        let req = TranscriptPush { rel: rel.to_string(), from, len, sha256: sha256.to_string(), url, owner: self.sync.target.owner.clone(), proxy: self.sync.proxy.clone() };
        let reply = match exchange(&self.x("POST /transcript/push", false), |t| {
            let req = &req;
            async move { self.dp.transcript_push(self.target, &t, req).await }
        })
        .await?
        {
            (reply, Verdict::Done) => reply.body.ok_or_else(|| BridgeError::Protocol("POST /transcript/push answered without a reply".into()))?,
            (reply, _) => return Err(BridgeError::Protocol(format!("POST /transcript/push answered HTTP {} where a push's answer was due", reply.status))),
        };
        let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let code = reply.s3_code.filter(|c| (1..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric()));
        let version = match reply.version_id.as_deref() {
            Some(v) if !is_version_id(v) => Err(()),
            v => Ok(v.unwrap_or_default().to_string()),
        };
        let mut pairs = vec![("session", sid.to_string()), ("vm", self.target.vm_id.clone()), ("kind", kind.to_string()), ("from", from.to_string()), ("len", len.to_string()), ("s3_status", reply.s3_status.to_string())];
        if let (200, Ok(v)) = (reply.s3_status, &version) {
            pairs.push(("version_id", v.clone()));
        }
        pairs.push(("ms", ms.to_string()));
        crate::bridge::workspace::audit(self.paths, audit_event::TRANSCRIPT_PUSH, &pairs);
        match reply.s3_status {
            200 if reply.len != len || reply.sha256 != sha256 => Err(BridgeError::Protocol(format!("{rel}: the VM pushed {} bytes (sha256 {}…) where {len} (sha256 {}…) were signed", reply.len, short(&reply.sha256), short(sha256)))),
            200 => version.map(PushOutcome::Stored).map_err(|()| BridgeError::Protocol(format!("{rel}: the VM relayed a version id that is not 1 to 1024 printable characters (no space, quote or backslash): nothing committed"))),
            412 => Ok(PushOutcome::Exists),
            400 if code.as_deref() == Some("BadDigest") => Ok(PushOutcome::BadDigest),
            status => Err(BridgeError::S3 { op: "transcript push", status, code }),
        }
    }

    /// One sync of `sid` (the module doc). A session the VM holds no
    /// transcript of commits nothing and writes no view; nor does one whose
    /// transcript is still empty while S3 holds nothing of it (no manifest
    /// that commits nothing is ever written). A commit takes the stat's end
    /// fingerprint, which the next sync's prefix check needs: a stat without
    /// one is `Protocol`. The first base of a session that committed nothing
    /// before supersedes the tail a chat closed before its first sync may
    /// have left (`g1/t/0000000000000000`): its bytes are in the base. S10
    /// (R1): a commit supersedes every recorded tail below the new committed
    /// length or of an older generation (`Manifest::supersede_tails`), and
    /// the tail handed after it is recorded.
    pub async fn sync_session(&self, sid: &str) -> Result<SyncReport, BridgeError> {
        let _held = manifest::lock(self.paths, sid).await?;
        let rel = main_rel(&self.sync.slug, sid);
        let vm = self.target.vm_id.clone();
        let mut m = manifest::read(self.paths, sid)?;
        let had_manifest = m.is_some();
        let end_fp = |stat: &TranscriptStat| stat.end_fp.clone().ok_or_else(|| BridgeError::Protocol(format!("GET /transcript of {rel} answered without the end fingerprint a commit records")));
        let mut report = SyncReport { session: sid.to_string(), vm: vm.clone(), pushed: None, files: 0, view: None, committed: m.as_ref().map_or(0, |m| m.committed) };
        if let Some(man) = m.as_mut() {
            if self.delete_superseded(man).await {
                manifest::write(self.paths, man)?;
            }
        }
        let committed = m.as_ref().map_or(0, |m| m.committed);
        let q = StatQuery { rel: rel.clone(), from: Some(committed), fp: (committed > 0).then(|| m.as_ref().map(|m| m.fp.clone()).unwrap_or_default()).filter(|f| !f.is_empty()), subtree: true };
        // A subtree over the helper's caps (SUBTREE_FILES_MAX files or SUBTREE_BYTES_MAX bytes) is refused whole:
        // the main transcript is synced without it, never left behind with it.
        let (stat, subtree_ok) = match self.stat(&q).await {
            Ok(stat) => (stat, true),
            Err(BridgeError::WorkspaceRefused { code, .. }) if code == crate::wire::workspace::refusal::TOO_LARGE => {
                subtree_too_large(sid);
                (self.stat(&StatQuery { subtree: false, ..q.clone() }).await?, false)
            }
            Err(e) => return Err(e),
        };
        if !stat.present {
            tracing::info!(session = sid, "transcript sync: the VM holds no transcript at {rel}");
            return Ok(report);
        }
        let at = crate::wire::time::rfc3339_utc_ms(crate::wire::time::unix_now_ms());
        let man = m.get_or_insert_with(|| Manifest::new(sid, &self.sync.target, manifest::ORIGIN_VM, &rel, &at));
        if man.bucket != self.sync.target.bucket || man.owner != self.sync.target.owner {
            return Err(BridgeError::Config(format!("the transcript manifest of {sid} names the bucket {} of {}, not this stack's {}: ai-env session forget {sid} --purge, or make infra-status WRITE=1", man.bucket, man.owner, self.sync.target.bucket)));
        }
        let mut plan = manifest::plan_push(Some(man), &stat, &vm);
        let first_commit = man.committed == 0;
        let mut stat_now = stat.clone();
        // A 412 lists the session's VM keys once: the next generation is past the highest S3 holds.
        let mut listed = false;
        for _ in 0..3 {
            match plan {
                PushPlan::Absent | PushPlan::UpToDate => break,
                PushPlan::Segment { gen, from, len } => {
                    let key = S3Key::Segment { session: sid.to_string(), gen, offset: from };
                    let sha = stat_now.delta_sha256.clone().ok_or_else(|| BridgeError::Protocol(format!("GET /transcript of {rel} answered without the sha256 past {from}")))?;
                    let fp = end_fp(&stat_now)?;
                    match self.push(sid, "segment", &rel, &key, from, len, &sha).await? {
                        PushOutcome::Stored(version) => {
                            man.commit_segment(ManifestPart { key: key.render(), version_id: version, from, len, sha256: sha, encoding: None, stored_len: None, stored_sha256: None }, &fp, stat_now.ino, &vm, &at);
                            report.pushed = Some(Pushed { kind: "segment", from, len, key: key.render() });
                            break;
                        }
                        PushOutcome::Exists => {
                            // A cut sync stored this key outside the manifest: it goes once a base commits.
                            supersede(man, key.render());
                            let next = if listed { man.gen + 1 } else { self.next_generation(sid, man).await? };
                            listed = true;
                            plan = PushPlan::Base { gen: next, len: stat_now.size, why: "refused" };
                        }
                        // S10 (R1): past the generation the tails were handed under (a Mac-begun chat's: 1), as `plan_push`'s.
                        PushOutcome::BadDigest => plan = PushPlan::Base { gen: man.tail_gen() + 1, len: stat_now.size, why: "refused" },
                    }
                }
                PushPlan::Base { gen, .. } => {
                    // A full copy needs the whole file's sha256: the stat from 0.
                    if q.from != Some(0) || stat_now.delta_sha256.is_none() {
                        stat_now = self.stat(&StatQuery { rel: rel.clone(), from: Some(0), fp: None, subtree: false }).await?;
                    }
                    let (len, sha) = (stat_now.size, stat_now.delta_sha256.clone().unwrap_or_default());
                    if !stat_now.present || len == 0 {
                        break;
                    }
                    let fp = end_fp(&stat_now)?;
                    let key = S3Key::Base { session: sid.to_string(), gen };
                    match self.push(sid, "base", &rel, &key, 0, len, &sha).await? {
                        PushOutcome::Stored(version) => {
                            man.commit_base(gen, ManifestPart { key: key.render(), version_id: version, from: 0, len, sha256: sha, encoding: None, stored_len: None, stored_sha256: None }, &fp, stat_now.ino, &vm, &at);
                            if first_commit {
                                // A chat closed before its first sync left its whole transcript as a tail from 0, if any.
                                supersede(man, S3Key::Tail { session: sid.to_string(), gen: 1, offset: 0 }.render());
                            }
                            report.pushed = Some(Pushed { kind: "base", from: 0, len, key: key.render() });
                            break;
                        }
                        // A generation this manifest does not know holds that key (a sync cut after its push): past the
                        // highest generation S3 holds (listed once), its keys superseded.
                        PushOutcome::Exists => {
                            let next = if listed { gen + 1 } else { self.next_generation(sid, man).await?.max(gen + 1) };
                            listed = true;
                            plan = PushPlan::Base { gen: next, len, why: "refused" };
                        }
                        PushOutcome::BadDigest => {
                            stat_now.delta_sha256 = None;
                            plan = PushPlan::Base { gen, len, why: "refused" };
                        }
                    }
                }
            }
        }
        if matches!(plan, PushPlan::Segment { .. } | PushPlan::Base { .. }) && report.pushed.is_none() {
            return Err(BridgeError::S3 { op: "transcript push", status: 412, code: Some("PreconditionFailed".into()) });
        }
        if report.pushed.is_some() {
            // S10 (R1): the tails this commit covers, or a rewritten file left behind, go with it.
            man.supersede_tails();
            // Committed at once: a failure among the files, or a sync cut there, never strands the stored key.
            man.at = at.clone();
            manifest::write(self.paths, man)?;
        }
        if subtree_ok {
            report.files = self.push_files(sid, man, &stat.subtree).await?;
        }
        if !had_manifest && man.parts.is_empty() && man.files.is_empty() {
            // An empty transcript (a sync before the first turn): S3 holds nothing of it yet, so no manifest says so.
            tracing::info!(session = sid, "transcript sync: {rel} is empty: nothing to commit yet");
            return Ok(report);
        }
        man.at = at.clone();
        manifest::write(self.paths, man)?;
        report.committed = man.committed;
        if let Some(tail) = self.hand_tail(sid, man, &rel).await {
            // S10 (R1): recorded, so the commit that covers it supersedes it.
            man.record_tail(tail);
            if let Err(e) = manifest::write(self.paths, man) {
                tracing::info!(session = sid, "transcript tail not recorded: {e}");
            }
        }
        report.view = Some(self.write_view(sid, &rel).await?);
        Ok(report)
    }

    /// Push the subtree files `listed` that the manifest lacks (by rel and
    /// sha256) as `v1/<sid>/vm/f/<sha256>`; the manifest's files become
    /// `listed`'s, and every committed entry whose rel none of them
    /// replaced stays (a file the VM no longer lists, a restore not yet
    /// done, bytes that changed under the stat or became empty): a sync
    /// never drops a committed file. A 412 commits (the key is the bytes'
    /// sha256: the object is those bytes), its version another entry's (one
    /// pushed earlier in this sync, else the manifest's) or none; a file
    /// whose bytes changed under the stat (`BadDigest`) waits for the next
    /// sync; an empty file is not pushed (S3 holds no empty part). The
    /// files pushed.
    async fn push_files(&self, sid: &str, man: &mut Manifest, listed: &[crate::wire::workspace::SubtreeFile]) -> Result<u32, BridgeError> {
        let mut files = Vec::with_capacity(listed.len());
        let mut pushed = 0u32;
        for f in listed {
            if let Some(kept) = man.files.iter().find(|e| e.rel == f.rel && e.sha256 == f.sha256) {
                files.push(kept.clone());
                continue;
            }
            if f.size == 0 {
                continue;
            }
            let key = S3Key::File { session: sid.to_string(), sha256: f.sha256.clone() };
            let version = match self.push(sid, "file", &f.rel, &key, 0, f.size, &f.sha256).await? {
                PushOutcome::Stored(v) => Some(v).filter(|v| !v.is_empty()),
                // The version an entry holds for that key: one this sync pushed first (two identical files), else the manifest's.
                PushOutcome::Exists => files.iter().find(|e: &&ManifestFile| e.key == key.render()).and_then(|e| e.version_id.clone()).or_else(|| man.file_version(&key.render())),
                PushOutcome::BadDigest => {
                    tracing::info!(session = sid, "transcript sync: {} changed under its stat; pushed at the next sync", f.rel);
                    continue;
                }
            };
            pushed += 1;
            files.push(ManifestFile { rel: f.rel.clone(), key: key.render(), version_id: version, len: f.size, sha256: f.sha256.clone(), encoding: None, stored_len: None, stored_sha256: None });
        }
        for kept in &man.files {
            if !files.iter().any(|f| f.rel == kept.rel) {
                files.push(kept.clone());
            }
        }
        man.files = files;
        Ok(pushed)
    }

    /// The generation after the highest one S3 holds of `sid`'s VM keys (one
    /// ListObjectsV2 of `v1/<sid>/vm/`), at least the manifest's next; every
    /// listed key of a generation above the manifest's (a base, a segment
    /// or a tail a cut sync, or the shim, left there) is superseded, so the
    /// sync after the next commit deletes it.
    async fn next_generation(&self, sid: &str, man: &mut Manifest) -> Result<u32, BridgeError> {
        let client = S3Client::new(self.api, &self.sync.target)?;
        let listed = client.list(&format!("{}{sid}/vm/", crate::wire::s3::KEY_PREFIX)).await?;
        let mut highest = man.gen;
        for o in listed {
            let gen = match S3Key::parse(&o.key) {
                Some(S3Key::Base { gen, .. } | S3Key::Segment { gen, .. } | S3Key::Tail { gen, .. }) => gen,
                _ => continue,
            };
            if gen > man.gen {
                highest = highest.max(gen);
                supersede(man, o.key);
            }
        }
        Ok(highest.saturating_add(1))
    }

    /// Delete the keys a compaction replaced (each once; a failure is kept for
    /// the next sync, logged): whether the manifest changed.
    async fn delete_superseded(&self, man: &mut Manifest) -> bool {
        if man.superseded.is_empty() {
            return false;
        }
        let Ok(client) = S3Client::new(self.api, &self.sync.target) else { return false };
        let before = man.superseded.len();
        let mut kept = Vec::new();
        for key in std::mem::take(&mut man.superseded) {
            if let Err(e) = client.delete(&key).await {
                tracing::warn!("transcript sync: {key} not deleted ({e}); tried again at the next sync");
                kept.push(key);
            }
        }
        man.superseded = kept;
        man.superseded.len() != before
    }

    /// Hand the shim a fresh tail URL for `/suspend` and `/terminate` right
    /// after a commit (`v1/<sid>/vm/g<gen>/t/<committed:016x>`,
    /// `TAIL_EXPIRY`; nothing is pushed past a length committed this
    /// instant): best effort, a failure logged (the next sync hands
    /// another). `rel` is the main transcript's ([`main_rel`]): the key names
    /// no file, so a tail is never another's (`TranscriptTail::check`
    /// refuses one before it is sent). The tail handed, for the manifest's
    /// `tails` (S10, R1).
    async fn hand_tail(&self, sid: &str, man: &Manifest, rel: &str) -> Option<ManifestTail> {
        self.hand_tail_at(sid, man.tail_gen(), man.committed, rel).await
    }

    /// A tail URL handed before the work it covers (the code-out trigger:
    /// once the session is named, before each turn's fetch, and, S10, at
    /// every unpark: `CodeoutTrigger::retail`), so the bytes between a result
    /// and the sync that commits them always have a fresh one. S10 (R1,
    /// plans/s10-contracts.md §1.4): one ListObjectsV2 of
    /// `v1/<sid>/vm/g<gen>/t/`, and the chain of tails S3 holds followed from
    /// the manifest's committed length by each one's size ([`tail_chain`]),
    /// from 0 under generation 1 when S3 holds nothing of the session (the
    /// whole transcript: a chat closed before its first sync): the tail at
    /// the chain's end is handed, so what is written after a `/suspend`'s
    /// push goes up through the next tail, never to a key S3 holds already
    /// (a 412). A chain of `TAIL_CHAIN_MAX` links already, or one S3 holds a
    /// key at the end of, gets none (logged): no restore follows more. A
    /// listing that fails, or that S3 does not answer within
    /// [`TAIL_LIST_WAIT`], hands the tail at the committed length, as S9 did:
    /// a turn's fetch waits for this hand, which S9 made with no request to
    /// S3. Without a manifest the chain is listed only for a chat begun on a VM
    /// (`manifest::origin_of`'s `vm`, the chat whose restore follows its
    /// chain from 0): any other has no tail in S3 yet (a chat begun on this
    /// Mac goes up inline, its manifest written, before its spawn), and gets
    /// the tail from 0 with no request to S3, as in S9.
    /// The tail handed is recorded in the manifest's `tails` (a session S3
    /// holds nothing of has no manifest to record it in), and the listed
    /// tails off the chain below the committed length (no restore starts
    /// there: a chat closed before its first sync left them, or a hand this
    /// Mac never recorded) are superseded with it. The manifest is read as
    /// written (it is replaced atomically), the record written under its
    /// lock, waited for at most [`TAIL_RECORD_WAIT`] (past it the tail stays
    /// unrecorded, logged: a later hand finds it off the chain once a commit
    /// covers it); best effort, as [`Self::hand_tail`].
    pub async fn hand_fresh_tail(&self, sid: &str) {
        let (gen, committed, chained) = match manifest::read(self.paths, sid) {
            Ok(Some(m)) => (m.tail_gen(), m.committed, true),
            Ok(None) => (1, 0, manifest::origin_of(self.paths, sid) == Some(manifest::ORIGIN_VM)),
            Err(e) => {
                tracing::info!(session = sid, "transcript tail not handed: {e}");
                return;
            }
        };
        let unanswered = || BridgeError::Sdk { op: "s3 list", message: format!("no answer within {} s", TAIL_LIST_WAIT.as_secs()) };
        let listed = match chained.then(|| S3Client::new(self.api, &self.sync.target)) {
            Some(Ok(client)) => Some(tokio::time::timeout(TAIL_LIST_WAIT, client.list(&tail_prefix(sid, gen))).await.unwrap_or_else(|_| Err(unanswered()))),
            Some(Err(e)) => Some(Err(e)),
            None => None,
        };
        let (from, off) = match listed {
            Some(Ok(listed)) => {
                let chain = tail_chain(&listed, sid, gen, committed, TAIL_CHAIN_MAX);
                if chain.blocked() {
                    tracing::info!(session = sid, links = chain.links.len(), "transcript tail not handed: the chain from {committed} holds {TAIL_CHAIN_MAX} links, or S3 holds a tail at its end {}", chain.end);
                    return;
                }
                (chain.end, chain.off)
            }
            Some(Err(e)) => {
                tracing::info!(session = sid, "transcript tails not listed ({e}): the tail at the committed length");
                (committed, Vec::new())
            }
            None => (committed, Vec::new()),
        };
        let Some(tail) = self.hand_tail_at(sid, gen, from, &main_rel(&self.sync.slug, sid)).await else { return };
        if let Err(e) = self.record_tail(sid, tail, &off).await {
            tracing::info!(session = sid, "transcript tail not recorded: {e}");
        }
    }

    /// The tail at `from` of generation `gen` (`v1/<sid>/vm/g<gen>/t/<from:016x>`, `If-None-Match: *`, `TAIL_EXPIRY`)
    /// handed the shim for `rel`: its record once the shim took it, `None` when it did not (logged).
    async fn hand_tail_at(&self, sid: &str, gen: u32, from: u64, rel: &str) -> Option<ManifestTail> {
        let key = S3Key::Tail { session: sid.to_string(), gen, offset: from };
        let headers = vec![("if-none-match".to_string(), "*".to_string())];
        let url = match self.presign(S3Method::Put, &key, Vec::new(), headers, TAIL_EXPIRY).await {
            Ok(u) => u,
            Err(e) => {
                tracing::info!(session = sid, "transcript tail not handed: {e}");
                return None;
            }
        };
        let req = TranscriptTail { rel: rel.to_string(), from, url, owner: self.sync.target.owner.clone(), proxy: self.sync.proxy.clone(), expires_at: crate::wire::time::unix_now() + TAIL_EXPIRY.as_secs() };
        let sent = exchange(&self.x("POST /transcript/tail", false), |t| {
            let req = &req;
            async move { self.dp.transcript_tail(self.target, &t, req).await }
        })
        .await;
        match sent {
            Ok((_, Verdict::Done)) => Some(ManifestTail { key: key.render(), gen, from, at: crate::wire::time::rfc3339_utc_ms(crate::wire::time::unix_now_ms()) }),
            Ok((reply, _)) => {
                tracing::info!(session = sid, "transcript tail not handed: POST /transcript/tail answered HTTP {}", reply.status);
                None
            }
            Err(e) => {
                tracing::info!(session = sid, "transcript tail not handed: {e}");
                None
            }
        }
    }

    /// `tail` recorded in the manifest of `sid` under its lock (waited for at
    /// most [`TAIL_RECORD_WAIT`]: `Busy` past it), and each of the listed
    /// tails `off` (key, start; of `tail`'s generation) that starts below the
    /// committed length, or whose generation is older than the manifest's
    /// now, superseded (out of `tails`, deleted at the next sync). Without a
    /// manifest there is nothing to record it in.
    async fn record_tail(&self, sid: &str, tail: ManifestTail, off: &[(String, u64)]) -> Result<(), BridgeError> {
        let _held = manifest::lock_within(self.paths, sid, TAIL_RECORD_WAIT).await?;
        let Some(mut m) = manifest::read(self.paths, sid)? else { return Ok(()) };
        for (key, from) in off {
            if tail.gen < m.tail_gen() || *from < m.committed {
                m.tails.retain(|t| t.key != *key);
                m.supersede(key.clone());
            }
        }
        m.record_tail(tail);
        manifest::write(self.paths, &m)
    }

    /// S10 (R1): drop the chain of tails S3 holds of `sid` from the committed
    /// length (from 0 without a manifest), for a move that restarts the
    /// transcript: a fresh chat's `Fresh` cut (plans/s10-contracts.md §2.9)
    /// restores nothing and starts a new file on the new VM, which no tail of
    /// the old one continues. Every listed tail of the hand's generation that
    /// starts at or past the committed length is deleted at once (a key only
    /// superseded would still be listed, and followed, by the next hand and
    /// by a restore) and leaves the manifest's `tails`, as does every such
    /// tail recorded there that S3 does not hold (a URL the old VM never
    /// pushed). The new VM's first tail then starts at the committed length
    /// again. Without a manifest, a restore then follows the new file's chain
    /// alone. With one, a restore still pulls the committed parts (the old
    /// file's bytes) before that chain, so no move restarts the file of a
    /// chat S3 holds anything committed of: `cut_before` never answers
    /// `Fresh` over a manifest, read after M1's best-effort sync. A tail
    /// below the committed length is the sync's to supersede. Under the
    /// manifest's lock. The caller runs it once the old VM pushes no more
    /// (TERMINATED: its `/terminate` tail landed), before the new VM's spawn,
    /// and bounds it (each request has the S3 client's waits). A delete that
    /// fails is the error, its record kept; the others are still deleted.
    pub async fn drop_chain(&self, sid: &str) -> Result<(), BridgeError> {
        let _held = manifest::lock(self.paths, sid).await?;
        let mut m = manifest::read(self.paths, sid)?;
        let (gen, committed) = m.as_ref().map_or((1, 0), |m| (m.tail_gen(), m.committed));
        let client = S3Client::new(self.api, &self.sync.target)?;
        let chained = |key: &str| matches!(S3Key::parse(key), Some(S3Key::Tail { session, gen: g, offset }) if session == sid && g == gen && offset >= committed);
        let (mut dropped, mut failed) = (0u32, Vec::new());
        let mut first_error = None;
        for o in client.list(&tail_prefix(sid, gen)).await?.into_iter().filter(|o| chained(&o.key)) {
            match client.delete(&o.key).await {
                Ok(()) => dropped += 1,
                Err(e) => {
                    tracing::warn!(session = sid, "transcript: the tail {} not deleted ({e})", o.key);
                    failed.push(o.key);
                    first_error.get_or_insert(e);
                }
            }
        }
        if let Some(m) = m.as_mut() {
            let before = m.tails.len();
            m.tails.retain(|t| !chained(&t.key) || failed.contains(&t.key));
            if m.tails.len() != before {
                manifest::write(self.paths, m)?;
            }
        }
        tracing::info!(session = sid, dropped, "transcript: the chain of tails from {committed} dropped (the move restarts the file)");
        first_error.map_or(Ok(()), Err)
    }

    /// `GET /transcript/view`, then the view written (`bridge::view`), audited
    /// `transcript_view` (`written`, `unchanged` or `refused`). A 200 whose
    /// answer does not parse as a view (an unknown key: the reply's types
    /// deny them; more than a JSON answer may hold) is refused whole as one
    /// that fails its check is (plans/s9-contracts.md §6.3 rule 1): the old
    /// view stays, the row says `refused`.
    pub async fn write_view(&self, sid: &str, rel: &str) -> Result<ViewOutcome, BridgeError> {
        self.write_view_carrying(sid, rel, &[]).await
    }

    /// S12 (T): [`SyncCtx::write_view`] carrying `renames` (`view::renames_of`'s, read before the mirror went:
    /// `session migrate-s9`'s live-VM path) through `view::write_view_carrying`; audited as `write_view` is.
    ///
    /// §T3 S4, Bug 2: the VM's view builder skips `custom-title` lines, so a mirror's renames reach the view only
    /// from the Mac's copy, read before it is deleted. With none it is [`SyncCtx::write_view`], byte for byte.
    /// Since phase 4 (§T3 S4 as amended) it is [`SyncCtx::view_reply`], then `SyncCtx::write_view_reply`, and the
    /// live-VM path calls the two itself (`commands::migrate_live`), the view in hand before the mirror goes.
    pub async fn write_view_carrying(&self, sid: &str, rel: &str, renames: &[Vec<u8>]) -> Result<ViewOutcome, BridgeError> {
        match self.view_reply(sid, rel).await? {
            Ok(reply) => self.write_view_reply(sid, &reply, renames),
            Err(why) => Ok(ViewOutcome::Refused(why)),
        }
    }

    /// S12 (T, phase 4): [`SyncCtx::write_view`]'s `GET /transcript/view` of `rel` and its checks, nothing written:
    /// the VM's reply; `Ok(Err(why))` for a 200 whose answer does not parse as a view, refused whole and audited
    /// `transcript_view` `refused` as `write_view` audits it; a transport error, a timeout, another status or an
    /// answer with no view is the error. `session migrate-s9`'s live-VM path has the reply in hand (and its render
    /// checked) before it deletes the mirror (§T3 S4 as amended in phase 4).
    pub async fn view_reply(&self, sid: &str, rel: &str) -> Result<Result<crate::wire::view::TranscriptViewReply, String>, BridgeError> {
        let q = ViewQuery { rel: rel.to_string(), n: self.sync.view_messages, parent: false };
        let sent = exchange(&self.x("GET /transcript/view", true), |t| {
            let q = &q;
            async move { self.dp.transcript_view(self.target, &t, q).await }
        })
        .await;
        match sent {
            Ok((reply, Verdict::Done)) => reply.body.map(Ok).ok_or_else(|| BridgeError::Protocol("GET /transcript/view answered without a view".into())),
            Ok((reply, _)) => Err(BridgeError::Protocol(format!("GET /transcript/view answered HTTP {} where a view was due", reply.status))),
            Err(BridgeError::Http { status: 200, body }) => {
                let first = crate::wire::redact::scrub(body.lines().next().unwrap_or_default()).into_owned();
                let why = format!("the view's answer is not one the Mac takes: {first}");
                audit_view(self.paths, sid, &self.target.vm_id, &ViewOutcome::Refused(why.clone()));
                tracing::warn!(session = sid, "transcript view refused: {why}");
                Ok(Err(why))
            }
            Err(e) => Err(e),
        }
    }

    /// S12 (T, phase 4): `reply`'s view of `sid` written carrying `renames` (`view::write_view_carrying`), audited
    /// `transcript_view` (`written`, `unchanged` or `refused`, a refusal warned) as [`SyncCtx::write_view`] audits
    /// it: the write that follows [`SyncCtx::view_reply`].
    pub(crate) fn write_view_reply(&self, sid: &str, reply: &crate::wire::view::TranscriptViewReply, renames: &[Vec<u8>]) -> Result<ViewOutcome, BridgeError> {
        let target = ViewTarget { mac_projects: &self.sync.mac_projects, slug: &self.sync.slug, session_id: sid, mac_cwd: &self.sync.mac_cwd };
        let outcome = crate::bridge::view::write_view_carrying(&target, reply, self.sync.view_messages, self.rules, renames)?;
        audit_view(self.paths, sid, &self.target.vm_id, &outcome);
        if let ViewOutcome::Refused(why) = &outcome {
            tracing::warn!(session = sid, "transcript view refused: {why}");
        }
        Ok(outcome)
    }
}

/// The placeholder view's title.
pub const PLACEHOLDER_TITLE: &str = "Remote chat";
/// The placeholder view's one message.
pub const PLACEHOLDER_TEXT: &str = "[ai-env: this chat runs on a VM; its last messages show here once a turn of it has synced]";

/// A marked placeholder view of `sid`, written when its session is first
/// named and nothing is at the view's path yet (S9 phase 4: a chat closed
/// before its first sync completes is still listed): Cursor's picker lists
/// a file with a title, and a reopen's precheck needs a `"type":"user"`
/// line, so it holds [`PLACEHOLDER_TITLE`] and one user line of
/// [`PLACEHOLDER_TEXT`], as `bridge::view` writes any view. The first sync's
/// view replaces it. Never over a file (a view, a transcript, a link):
/// `Ok(None)` then.
pub fn write_placeholder_view(sync: &TranscriptSync, sid: &str, rules: &Rules) -> Result<Option<ViewOutcome>, BridgeError> {
    use crate::wire::view::{TranscriptViewReply, ViewEntry, ViewRole, VIEW_V};
    let target = ViewTarget { mac_projects: &sync.mac_projects, slug: &sync.slug, session_id: sid, mac_cwd: &sync.mac_cwd };
    if std::fs::symlink_metadata(target.path()).is_ok() {
        return Ok(None);
    }
    let now = crate::wire::time::rfc3339_utc_ms(crate::wire::time::unix_now_ms());
    let entry = ViewEntry { role: ViewRole::User, uuid: String::new(), timestamp: now, blocks: vec![PLACEHOLDER_TEXT.to_string()] };
    let reply = TranscriptViewReply { v: VIEW_V, present: true, title: Some(PLACEHOLDER_TITLE.to_string()), version: None, git_branch: None, entries: vec![entry], first_parent: None };
    crate::bridge::view::write_view(&target, &reply, sync.view_messages, rules).map(Some)
}

/// `key` among the manifest's superseded keys (once; never one of its parts).
fn supersede(man: &mut Manifest, key: String) {
    man.supersede(key);
}

// ---- S10 (R1): the chain of tails --------------------------------------------------------------

/// The prefix the tails of `sid`'s generation `gen` are listed under: `v1/<sid>/vm/g<gen>/t/`.
#[must_use]
pub fn tail_prefix(sid: &str, gen: u32) -> String {
    format!("{}{sid}/vm/g{gen}/t/", crate::wire::s3::KEY_PREFIX)
}

/// A chat's chain of tails as one listing shows it ([`tail_chain`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailChain {
    /// The links from the start, in order: each tail's key and bytes, each
    /// starting where the one before ended.
    pub links: Vec<(String, u64)>,
    /// Where the last link ends (the start without one): the next tail's start.
    pub end: u64,
    /// The chain holds the most links it was followed through.
    pub full: bool,
    /// S3 holds a tail at `end` the chain did not take: one past the most
    /// links, or an empty object.
    pub more: bool,
    /// The listed tails off the chain (key, start): one below the start, one
    /// beyond a gap, one inside a link.
    pub off: Vec<(String, u64)>,
}

impl TailChain {
    /// No tail can be handed at `end`: no restore would follow it
    /// ([`TailChain::full`]), or S3 holds that key already (a 412 at its push).
    #[must_use]
    pub fn blocked(&self) -> bool {
        self.full || self.more
    }
}

/// The chain of `sid`'s tails of generation `gen` in `listed` (one
/// ListObjectsV2 of [`tail_prefix`]) from `start` (S10 R1,
/// plans/s10-contracts.md §1.4): the tail at `start`, then the one where it
/// ends, by each object's size, at most `max` links. Each link went up from a
/// URL the Mac handed at the end of the chain before it: the shim pushes
/// `[from, size)` and keeps a URL until S3 answered, so a link is that file's
/// bytes from its start. A link of no bytes ends the chain, blocked (the
/// shim never pushes one). Keys of another session or generation are no
/// tails of it.
#[must_use]
pub fn tail_chain(listed: &[Listed], sid: &str, gen: u32, start: u64, max: usize) -> TailChain {
    let tails: std::collections::BTreeMap<u64, (&str, u64)> = listed
        .iter()
        .filter_map(|o| match S3Key::parse(&o.key) {
            Some(S3Key::Tail { session, gen: g, offset }) if session == sid && g == gen => Some((offset, (o.key.as_str(), o.size))),
            _ => None,
        })
        .collect();
    let mut chain = TailChain { end: start, ..TailChain::default() };
    while let Some((key, size)) = tails.get(&chain.end) {
        if *size == 0 || chain.links.len() >= max {
            break;
        }
        chain.links.push(((*key).to_string(), *size));
        chain.end = chain.end.saturating_add(*size);
    }
    chain.full = chain.links.len() >= max;
    chain.more = tails.contains_key(&chain.end);
    chain.off = tails.iter().filter(|(_, (key, _))| !chain.links.iter().any(|(k, _)| k == key)).map(|(from, (key, _))| ((*key).to_string(), *from)).collect();
    chain
}

/// The subtree of `sid` is over the helper's caps: said once per session in
/// this process (each sync would say it again), logged every time.
fn subtree_too_large(sid: &str) {
    use crate::wire::workspace::{SUBTREE_BYTES_MAX, SUBTREE_FILES_MAX};
    static SAID: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeSet<String>>> = std::sync::OnceLock::new();
    tracing::warn!(session = sid, "transcript sync: the subtree is over the helper's caps: the main transcript is synced alone");
    let first = SAID.get_or_init(Default::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(sid.to_string());
    if first {
        crate::bridge::voice::warn(&format!(
            "the session {sid}'s subagent and tool files are over {SUBTREE_FILES_MAX} files or {} MiB: they are not synced to S3 (its transcript is)",
            SUBTREE_BYTES_MAX >> 20
        ));
    }
}

/// The `transcript_view` audit row of `outcome`.
pub fn audit_view(paths: &Paths, sid: &str, vm: &str, outcome: &ViewOutcome) {
    let (messages, masked, bytes) = outcome.counts();
    let pairs = [("session", sid.to_string()), ("vm", vm.to_string()), ("messages", messages.to_string()), ("masked", masked.to_string()), ("bytes", bytes.to_string()), ("outcome", outcome.word().to_string())];
    crate::bridge::workspace::audit(paths, audit_event::TRANSCRIPT_VIEW, &pairs);
}

/// The first 12 characters of a digest, for a message.
fn short(s: &str) -> &str {
    s.get(..12).unwrap_or(s)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod c2_tests {
    use super::*;

    const S: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    fn listed(gen: u32, from: u64, size: u64) -> Listed {
        Listed { key: S3Key::Tail { session: S.into(), gen, offset: from }.render(), size }
    }

    fn key(gen: u32, from: u64) -> String {
        S3Key::Tail { session: S.into(), gen, offset: from }.render()
    }

    /// S10 (R1, §1.4): the chain from the start follows each tail by its
    /// size, in order whatever the listing's; it ends where no tail starts
    /// (the next one's start), or at an empty one (blocked: S3 holds that
    /// key); the tails off it (below the start, past a gap, inside a link)
    /// and those of another generation or session, or another key kind,
    /// are none of its links; at most `max` links (then full, with or
    /// without one more); `tail_prefix` names where the hand and the restore
    /// list.
    #[test]
    fn the_chain_follows_each_tail_by_its_size_from_the_start() {
        assert_eq!(tail_prefix(S, 3), format!("v1/{S}/vm/g3/t/"));
        let other = Listed { key: S3Key::Tail { session: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c".into(), gen: 1, offset: 300 }.render(), size: 7 };
        let base = Listed { key: S3Key::Base { session: S.into(), gen: 1 }.render(), size: 300 };
        let objects = vec![listed(1, 420, 80), base, other, listed(1, 300, 120), listed(2, 500, 9), listed(1, 100, 5), listed(1, 350, 10), listed(1, 900, 4)];
        let chain = tail_chain(&objects, S, 1, 300, TAIL_CHAIN_MAX);
        assert_eq!(chain.links, [(key(1, 300), 120), (key(1, 420), 80)]);
        assert_eq!((chain.end, chain.full, chain.more, chain.blocked()), (500, false, false, false));
        assert_eq!(chain.off, [(key(1, 100), 100), (key(1, 350), 350), (key(1, 900), 900)], "below the start, inside a link, past a gap");
        // Nothing at the start: no link, the next tail starts there.
        let none = tail_chain(&objects, S, 1, 200, TAIL_CHAIN_MAX);
        assert_eq!((none.links.len(), none.end, none.blocked()), (0, 200, false));
        // An empty tail ends the chain, blocked: S3 holds that key.
        let empty = vec![listed(1, 0, 50), listed(1, 50, 0)];
        let chain = tail_chain(&empty, S, 1, 0, TAIL_CHAIN_MAX);
        assert_eq!((chain.links.len(), chain.end, chain.full, chain.more, chain.blocked()), (1, 50, false, true, true));
        // At most `max` links: full, and one more listed past them.
        let long: Vec<Listed> = (0..5).map(|i| listed(1, 10 * i, 10)).collect();
        let chain = tail_chain(&long, S, 1, 0, 3);
        assert_eq!((chain.links.len(), chain.end, chain.full, chain.more), (3, 30, true, true));
        assert_eq!(chain.off.iter().map(|(_, from)| *from).collect::<Vec<_>>(), [30, 40]);
        let chain = tail_chain(&long, S, 1, 0, 5);
        assert_eq!((chain.links.len(), chain.end, chain.full, chain.more, chain.blocked()), (5, 50, true, false, true), "full: no restore follows a sixth");
        assert!(!tail_chain(&long, S, 1, 0, 6).blocked(), "five links of six: the sixth may be handed");
    }
}
