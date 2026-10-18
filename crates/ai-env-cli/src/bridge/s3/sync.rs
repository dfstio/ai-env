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
//! 4. the manifest committed atomically, audited `transcript_push`;
//! 5. a fresh tail URL handed to the shim (`POST /transcript/tail`, for
//!    `/suspend` and `/terminate`), best effort: the main transcript's only
//!    (its key names no file); a subtree file goes up whole at a sync, and
//!    one changed after the last sync is lost at `/suspend` or `/terminate`.
//!    The code-out trigger hands one too before any sync (from 0 when
//!    nothing is committed: `g1/t/0000000000000000`) and before each turn's
//!    fetch ([`SyncCtx::hand_fresh_tail`]), so a chat closed before its
//!    sync still has its bytes pushed at `/suspend` or `/terminate`;
//! 6. `GET /transcript/view?rel=&n=`: the view written by `bridge::view`
//!    (audited `transcript_view`, `refused` included).
//!
//! Every request names `transcript_s3_v1` (a 404 is a VM without it, exit 7)
//! and answers by the session's deadline when it has one.
use super::client::S3Client;
use super::manifest::{self, Manifest, ManifestFile, ManifestPart, PushPlan};
use super::presign::{request, write_headers};
use super::{S3Method, S3Sign, TranscriptSync};
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
    /// have left (`g1/t/0000000000000000`): its bytes are in the base.
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
                            man.commit_segment(ManifestPart { key: key.render(), version_id: version, from, len, sha256: sha }, &fp, stat_now.ino, &vm, &at);
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
                        PushOutcome::BadDigest => plan = PushPlan::Base { gen: man.gen + 1, len: stat_now.size, why: "refused" },
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
                            man.commit_base(gen, ManifestPart { key: key.render(), version_id: version, from: 0, len, sha256: sha }, &fp, stat_now.ino, &vm, &at);
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
        self.hand_tail(sid, man, &rel).await;
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
            files.push(ManifestFile { rel: f.rel.clone(), key: key.render(), version_id: version, len: f.size, sha256: f.sha256.clone() });
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

    /// Hand the shim a fresh tail URL for `/suspend` and `/terminate`
    /// (`v1/<sid>/vm/g<gen>/t/<committed:016x>`, `TAIL_EXPIRY`): best effort,
    /// a failure logged (the next sync hands another). `rel` is the main
    /// transcript's ([`main_rel`]): the key names no file, so a tail is never
    /// another's (`TranscriptTail::check` refuses one before it is sent).
    async fn hand_tail(&self, sid: &str, man: &Manifest, rel: &str) {
        self.hand_tail_at(sid, man.gen, man.committed, rel).await;
    }

    /// A tail URL handed before the work it covers (the code-out trigger:
    /// once the session is named, and before each turn's fetch), so the
    /// bytes between a result and the sync that commits them always have a
    /// fresh one: at the manifest's committed length, or from 0 under
    /// generation 1 when S3 holds nothing of the session yet
    /// (`g1/t/0000000000000000`, the whole transcript: a chat closed before
    /// its first sync). The manifest is read as written (it is replaced
    /// atomically); best effort, as [`Self::hand_tail`].
    pub async fn hand_fresh_tail(&self, sid: &str) {
        let (gen, committed) = match manifest::read(self.paths, sid) {
            Ok(Some(m)) => (m.gen, m.committed),
            Ok(None) => (0, 0),
            Err(e) => {
                tracing::info!(session = sid, "transcript tail not handed: {e}");
                return;
            }
        };
        self.hand_tail_at(sid, gen, committed, &main_rel(&self.sync.slug, sid)).await;
    }

    /// [`Self::hand_tail`] at `committed` of generation `gen` (`max(gen, 1)`: a Mac-begun chat's first VM bytes, and
    /// a session that committed nothing, open generation 1).
    async fn hand_tail_at(&self, sid: &str, gen: u32, committed: u64, rel: &str) {
        let key = S3Key::Tail { session: sid.to_string(), gen: gen.max(1), offset: committed };
        let headers = vec![("if-none-match".to_string(), "*".to_string())];
        let url = match self.presign(S3Method::Put, &key, Vec::new(), headers, TAIL_EXPIRY).await {
            Ok(u) => u,
            Err(e) => {
                tracing::info!(session = sid, "transcript tail not handed: {e}");
                return;
            }
        };
        let req = TranscriptTail { rel: rel.to_string(), from: committed, url, owner: self.sync.target.owner.clone(), proxy: self.sync.proxy.clone(), expires_at: crate::wire::time::unix_now() + TAIL_EXPIRY.as_secs() };
        let sent = exchange(&self.x("POST /transcript/tail", false), |t| {
            let req = &req;
            async move { self.dp.transcript_tail(self.target, &t, req).await }
        })
        .await;
        if let Err(e) = sent {
            tracing::info!(session = sid, "transcript tail not handed: {e}");
        }
    }

    /// `GET /transcript/view`, then the view written (`bridge::view`), audited
    /// `transcript_view` (`written`, `unchanged` or `refused`). A 200 whose
    /// answer does not parse as a view (an unknown key: the reply's types
    /// deny them; more than a JSON answer may hold) is refused whole as one
    /// that fails its check is (plans/s9-contracts.md §6.3 rule 1): the old
    /// view stays, the row says `refused`.
    pub async fn write_view(&self, sid: &str, rel: &str) -> Result<ViewOutcome, BridgeError> {
        let q = ViewQuery { rel: rel.to_string(), n: self.sync.view_messages };
        let refuse = |why: String| {
            let outcome = ViewOutcome::Refused(why);
            audit_view(self.paths, sid, &self.target.vm_id, &outcome);
            if let ViewOutcome::Refused(why) = &outcome {
                tracing::warn!(session = sid, "transcript view refused: {why}");
            }
            outcome
        };
        let sent = exchange(&self.x("GET /transcript/view", true), |t| {
            let q = &q;
            async move { self.dp.transcript_view(self.target, &t, q).await }
        })
        .await;
        let reply = match sent {
            Ok((reply, Verdict::Done)) => reply.body.ok_or_else(|| BridgeError::Protocol("GET /transcript/view answered without a view".into()))?,
            Ok((reply, _)) => return Err(BridgeError::Protocol(format!("GET /transcript/view answered HTTP {} where a view was due", reply.status))),
            Err(BridgeError::Http { status: 200, body }) => {
                let first = crate::wire::redact::scrub(body.lines().next().unwrap_or_default()).into_owned();
                return Ok(refuse(format!("the view's answer is not one the Mac takes: {first}")));
            }
            Err(e) => return Err(e),
        };
        let target = ViewTarget { mac_projects: &self.sync.mac_projects, slug: &self.sync.slug, session_id: sid, mac_cwd: &self.sync.mac_cwd };
        match crate::bridge::view::write_view(&target, &reply, self.sync.view_messages, self.rules)? {
            ViewOutcome::Refused(why) => Ok(refuse(why)),
            outcome => {
                audit_view(self.paths, sid, &self.target.vm_id, &outcome);
                Ok(outcome)
            }
        }
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
    let reply = TranscriptViewReply { v: VIEW_V, present: true, title: Some(PLACEHOLDER_TITLE.to_string()), version: None, git_branch: None, entries: vec![entry] };
    crate::bridge::view::write_view(&target, &reply, sync.view_messages, rules).map(Some)
}

/// `key` among the manifest's superseded keys (once; never one of its parts).
fn supersede(man: &mut Manifest, key: String) {
    if !man.superseded.contains(&key) && !man.parts.iter().any(|p| p.key == key) {
        man.superseded.push(key);
    }
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
