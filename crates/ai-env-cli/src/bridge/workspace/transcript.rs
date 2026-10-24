//! The resume's transcript (S9, after the S3 cut-over): a chat's transcript
//! is kept in S3, never on this Mac, and P3 restores it into the VM
//! ([`restore`]: kept when the VM holds the committed prefix, else pulled,
//! at most `wire::s3::INLINE_MAX` within Cursor's window; a chat begun on
//! this Mac sent up inline first, at most `INLINE_MAX` too). `session stage
//! UUID --warm` restores a larger one into the workspace's VM ahead, with no
//! deadline. S8's upload of the Mac's mirror (`GET`/`PUT /transcript`,
//! `remote::TRANSCRIPT_MAX`) went at the cut-over.
//!
//! What goes up from this Mac is scanned first, as the seed is (S8 phase 4,
//! review CUSTODY-2): a chat begun here holds whatever its tools printed.
//! The wrapper's P1 runs [`scan_mac_copy`] beside the Touch ID on the chat
//! P3 will send up inline (a chat begun here, an S8 mirror): every file the
//! inline upload sends (`s3::stage::locate`'s), read once through the seed's
//! tripwires (`blobscan::ScanSet`) as the upload's own scan reads it
//! (`s3::stage::scan_chat`), its name too, so a finding starts no VM. The
//! refusal is `WorkspaceRefused { finding }` (exit 9) naming
//! `transcript:REL`, the line and the rule, never a value, audited
//! `seed_refused` (step `transcript`). [`restore`] scans again what it sends
//! (a finding refuses before any request), and a chat S3 holds is never read
//! on this Mac.
use super::blobscan::ScanSet;
use super::{audit, blocking, EnsureCtx, TranscriptOutcome, WorkspaceRef};
use crate::bridge::api::MicrovmApi;
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::dataplane::{exchange, DataPlane, Exchange, TokenSource, Verdict};
use crate::bridge::errors::BridgeError;
use crate::bridge::remote::audit_event;
use crate::wire::workspace::{transcript_rel_check, APP_PORT};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// `e`, a refusal of the transcript, audited `seed_refused` (step
/// `transcript`, the VM once one was chosen) on its way out.
fn audited(paths: &Paths, ws: &WorkspaceRef, vm: Option<&str>, e: BridgeError) -> BridgeError {
    if let BridgeError::WorkspaceRefused { code, .. } = &e {
        let mut pairs = vec![("workspace", ws.cwd.display().to_string()), ("code", (*code).to_string()), ("step", "transcript".to_string())];
        pairs.extend(vm.map(|v| ("vm", v.to_string())));
        audit(paths, audit_event::SEED_REFUSED, &pairs);
    }
    e
}

/// P1's scan of a `--resume`'s transcript (the wrapper's, on the snapshot's
/// blocking thread beside the Touch ID, for a chat P3 sends up inline: one
/// begun on this Mac, or an S8 mirror): the chat under `mirror_root` for
/// `slugs` as the inline upload takes it (`s3::stage::locate`, at most
/// `wire::s3::INLINE_MAX`; a view in its place is no chat), every file and
/// name through the seed's tripwires (`ScanSet::load`: the built-ins, and
/// `[review].tripwires` when that file exists) as that upload's own scan
/// reads them (`s3::stage::scan_chat`), nothing copied, nothing sent. Any
/// finding refuses the session before any VM is chosen (`WorkspaceRefused
/// { finding }`, exit 9, audited `seed_refused`); no Mac copy, or a clean
/// one, is `Ok`.
pub(crate) fn scan_mac_copy(paths: &Paths, cfg: &BridgeConfig, ws: &WorkspaceRef, mirror_root: &Path, slugs: &[&str], session_id: &str) -> Result<(), BridgeError> {
    use crate::bridge::s3::stage;
    let set = ScanSet::load(paths, cfg, ws)?;
    let found = stage::locate(mirror_root, slugs, session_id, crate::wire::s3::INLINE_MAX).map_err(|e| audited(paths, ws, None, e))?;
    let Some(chat) = found.filter(|c| !crate::bridge::view::is_view_file(&c.main_path(session_id))) else { return Ok(()) };
    stage::scan_chat(&set.rules, &chat, crate::wire::s3::MULTIPART_PART).map(drop).map_err(|e| audited(paths, ws, None, e))
}

// ---- S9 (G4): the streaming scan, the S3 restore, the upload of a Mac-begun chat ----------------

/// The longest stretch of one line the streaming scan holds: past it the
/// line is scanned in windows ([`LineScan`]).
pub const LINE_WINDOW: usize = 8 << 20;
/// What a window keeps of its end for the next, so a match across the
/// boundary shorter than this is found whole (the built-in rules' are all
/// far shorter).
pub const WINDOW_OVERLAP: usize = 64 << 10;
/// The chunk a file is read in.
pub const SCAN_CHUNK: usize = 1 << 20;

/// The tripwires over a byte stream, line by line, in bounded memory: the
/// complete lines of each chunk are scanned at once with the bytes carried
/// from the chunk before (the start of their first line), the rest carried;
/// a line longer than [`LINE_WINDOW`] is scanned in windows that overlap by
/// [`WINDOW_OVERLAP`]. The hits, `(line, rule)`, are those `Rules::scan_bytes`
/// gives over the whole stream (each once), never a value. At most about
/// `LINE_WINDOW` plus one chunk is held at a time, whatever the stream's size.
pub struct LineScan<'r> {
    rules: &'r crate::bridge::scan::Rules,
    carry: Vec<u8>,
    /// Lines completed before `carry`.
    lines: usize,
    hits: std::collections::BTreeSet<(usize, String)>,
    peak: usize,
}

impl<'r> LineScan<'r> {
    #[must_use]
    pub fn new(rules: &'r crate::bridge::scan::Rules) -> LineScan<'r> {
        LineScan { rules, carry: Vec::new(), lines: 0, hits: std::collections::BTreeSet::new(), peak: 0 }
    }

    /// Scan `hay`, whose first line is line `self.lines + 1`.
    fn scan(&mut self, hay: &[u8]) {
        let base = self.lines;
        self.hits.extend(self.rules.scan_bytes(hay).into_iter().map(|(line, rule)| (base + line, rule)));
    }

    /// The next bytes of the stream.
    pub fn feed(&mut self, chunk: &[u8]) {
        match chunk.iter().rposition(|b| *b == b'\n') {
            Some(nl) => {
                let mut batch = std::mem::take(&mut self.carry);
                batch.extend_from_slice(&chunk[..=nl]);
                self.peak = self.peak.max(batch.len());
                self.scan(&batch);
                self.lines += batch.iter().filter(|b| **b == b'\n').count();
                self.carry = chunk[nl + 1..].to_vec();
            }
            None => {
                self.carry.extend_from_slice(chunk);
                self.peak = self.peak.max(self.carry.len());
                if self.carry.len() > LINE_WINDOW {
                    let window = std::mem::take(&mut self.carry);
                    self.scan(&window);
                    self.carry = window[window.len() - WINDOW_OVERLAP..].to_vec();
                }
            }
        }
    }

    /// The most bytes held at once.
    #[must_use]
    pub fn peak(&self) -> usize {
        self.peak
    }

    /// The hits, sorted by line, then rule (the last line scanned too, newline or not).
    #[must_use]
    pub fn finish(mut self) -> Vec<(usize, String)> {
        let rest = std::mem::take(&mut self.carry);
        if !rest.is_empty() {
            self.scan(&rest);
        }
        self.hits.into_iter().collect()
    }
}

/// What one read of a file found: its length, sha256, fingerprint (the
/// sha256 of its last `FP_SPAN` bytes), the sha256 of each `part_len`
/// stretch (a multipart upload's parts), the tripwires' hits, and the most
/// bytes held at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {
    pub len: u64,
    pub sha256: String,
    pub fp: String,
    pub parts: Vec<String>,
    pub hits: Vec<(usize, String)>,
    pub peak: usize,
}

/// One pass over `input` in [`SCAN_CHUNK`]s ([`FileDigest`]): every byte
/// through the tripwires ([`LineScan`]), the whole sha256, the parts' and
/// the fingerprint; nothing is kept but a chunk, the scan's carry and the
/// last `FP_SPAN` bytes.
pub fn digest_stream(rules: &crate::bridge::scan::Rules, input: &mut dyn Read, part_len: u64) -> Result<FileDigest, BridgeError> {
    use sha2::{Digest, Sha256};
    let span = usize::try_from(crate::wire::s3::FP_SPAN).unwrap_or(usize::MAX);
    let part_len = part_len.max(1);
    let (mut whole, mut part, mut in_part) = (Sha256::new(), Sha256::new(), 0u64);
    let (mut parts, mut tail, mut len) = (Vec::new(), Vec::with_capacity(2 * span), 0u64);
    let mut scan = LineScan::new(rules);
    let mut buf = vec![0u8; SCAN_CHUNK];
    loop {
        let n = input.read(&mut buf).map_err(BridgeError::Io)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        whole.update(chunk);
        scan.feed(chunk);
        let mut rest = chunk;
        while !rest.is_empty() {
            let take = usize::try_from((part_len - in_part).min(rest.len() as u64)).unwrap_or(rest.len());
            part.update(&rest[..take]);
            in_part += take as u64;
            rest = &rest[take..];
            if in_part == part_len {
                parts.push(hex::encode(std::mem::replace(&mut part, Sha256::new()).finalize()));
                in_part = 0;
            }
        }
        tail.extend_from_slice(chunk);
        if tail.len() > 2 * span {
            tail.drain(..tail.len() - span);
        }
        len += n as u64;
    }
    if in_part > 0 {
        parts.push(hex::encode(part.finalize()));
    }
    let peak = scan.peak() + buf.len() + tail.capacity();
    Ok(FileDigest { len, sha256: hex::encode(whole.finalize()), fp: crate::bridge::s3::manifest::fp_of(&tail), parts, hits: scan.finish(), peak })
}

/// P3's restore of a `--resume`'s transcript from S3 (S9; `remote::pipeline`
/// calls it, the resume miss's retry again, and `session stage --warm` into
/// the VM it warmed): nothing goes
/// to a VM without `transcript_s3_v1` (exit 7), and S11 (L5) nothing of a
/// chat stored encoded to one without `transcript_gzip_v1` (exit 7, before
/// the stat and any presign); P3's inline upload stores gzip only on a VM
/// naming it. A chat S3 does not hold yet
/// (no manifest) whose copy is on this Mac goes up first, inline (at most
/// `wire::s3::INLINE_MAX`: P0 refused a larger one), scanned through the
/// session's tripwires (a finding refuses before any request, audited
/// `seed_refused`): one begun here (`s3::manifest::origin_of` none) as
/// `session stage` uploads it (the manifest's origin `mac`, its view built
/// here and left in the original's place, the original moved to `origin/`,
/// audited `transcript_stage`); an S8 mirror (`s8_mirror`, a chat begun on a
/// VM) in `session migrate-s9`'s gone-VM form (the manifest's origin `vm`,
/// the view built here, the mirror deleted, audited `transcript_migrate`).
/// A stage cut after its manifest and before its view is finished first
/// ([`finish_cut_stage`]). Then: a manifest that commits nothing restores
/// nothing; when the VM holds the committed prefix (its size at least
/// `committed`, its bytes before it hashing to the manifest's fingerprint)
/// it is kept; else the parts are presigned (GETs by version, expiring
/// after the pull's budget), with the tails `/suspend` and `/terminate`
/// pushed from `committed` (S10, R1: one listing of `g<max(gen, 1)>/t/`,
/// where the Mac signs them, and the chain followed from `committed`, each
/// tail where the one before ended, at most `TAIL_CHAIN_MAX` links and as
/// many as one pull's `PULL_PARTS_MAX` parts take; a tail off that chain is
/// left out, logged), and pulled (`POST /transcript/pull`: each part
/// checked in the VM, renamed only when all passed): a tail is only ever
/// the main transcript's (its key names no file); audited
/// `transcript_pull`, the manifest's inode and VM updated for the next
/// sync's rewrite check. A
/// part that did not check is `BridgeError::S3` (exit 7), the VM's copy
/// unchanged. Only the main transcript is restored here, all `--resume`
/// needs, within P3's deadline: the subtree's files follow after the spawn
/// ([`restore_subtree`], the code-out trigger's first step, no deadline).
/// Under a deadline (generation 1's P3: `ctx.deadline`) the pull, its parts
/// and its tails together, is at most `wire::s3::INLINE_MAX`: more is
/// `TranscriptPullTooLarge` (exit 9) before any pull starts ([`pull_one`]),
/// naming `session stage UUID --warm`. Without one (a resume miss's retry,
/// `session stage --warm`) it pulls whatever the size.
/// A chat begun on a VM that S3 holds nothing committed of (no manifest:
/// closed before its first sync) is kept on a VM that holds its file, else
/// restored from the tail the shim pushed from 0 (`g1/t/0000000000000000`,
/// the URL handed before any sync) and the chain after it, when S3 holds it.
pub async fn restore<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(
    ctx: &EnsureCtx<'_, A, D, T>,
    sync: &crate::bridge::s3::TranscriptSync,
    mac_projects: Option<&Path>,
    slugs: &[&str],
    sid: &str,
    build: crate::bridge::s3::stage::ViewBuilder<'_>,
) -> Result<TranscriptOutcome, BridgeError> {
    use crate::bridge::s3::{manifest, stage};
    super::require_cap(ctx.caps, &ctx.target.vm_id, crate::wire::frame::CAP_TRANSCRIPT_S3_V1)?;
    let set = ScanSet::load(ctx.paths, ctx.cfg, ctx.ws)?;
    let rules = std::sync::Arc::new(set.rules);
    let sctx = crate::bridge::s3::sync::SyncCtx { api: ctx.api, dp: ctx.dp, tokens: ctx.tokens, paths: ctx.paths, target: ctx.target, sync, rules: &rules, deadline: ctx.deadline };
    let rel = crate::bridge::s3::sync::main_rel(&sync.slug, sid);
    let mut staged: Option<u64> = None;
    match manifest::read(ctx.paths, sid)? {
        Some(m) => {
            if let Some(projects) = mac_projects {
                finish_cut_stage(ctx.paths, sync, &rules, projects, slugs, sid, &m, &ctx.target.vm_id, build)?;
            }
        }
        None => {
            let origin = manifest::origin_of(ctx.paths, sid);
            if origin == Some(manifest::ORIGIN_VM) {
                return restore_unsynced(&sctx, sid, &rel).await;
            }
            let s8 = origin == Some(manifest::ORIGIN_S8_MIRROR);
            let found = match mac_projects {
                Some(p) => stage::locate(p, slugs, sid, crate::wire::s3::INLINE_MAX)?,
                None => None,
            };
            let (Some(chat), Some(projects)) = (found.filter(|c| !crate::bridge::view::is_view_file(&c.main_path(sid))), mac_projects) else {
                return Ok(TranscriptOutcome::NothingToRestore);
            };
            let t0 = std::time::Instant::now();
            let digests = {
                let (rules, chat) = (std::sync::Arc::clone(&rules), chat.clone());
                blocking(move || stage::scan_chat(&rules, &chat, crate::wire::s3::MULTIPART_PART)).await?.map_err(|e| audited(ctx.paths, ctx.ws, Some(&ctx.target.vm_id), e))?
            };
            let client = crate::bridge::s3::client::S3Client::new(ctx.api, &sync.target)?;
            let at = crate::wire::time::rfc3339_utc_ms(crate::wire::time::unix_now_ms());
            // S11 (L5, C.3.7): stored gzip only on a VM that decodes it.
            let encoding = ctx.caps.iter().any(|c| c == crate::wire::frame::CAP_TRANSCRIPT_GZIP_V1).then_some(crate::wire::workspace::PartEncoding::Gzip);
            let mut up = stage::upload_chat(&client, ctx.paths, sid, &chat, &digests, crate::wire::s3::MULTIPART_PART, &at, encoding).await?;
            if s8 {
                // S8's mirror is the remote chat's transcript: the chat began on a VM, whatever copy this Mac sent up.
                up.manifest.origin = manifest::ORIGIN_VM.to_string();
            }
            {
                let _held = manifest::lock(ctx.paths, sid).await?;
                manifest::write(ctx.paths, &up.manifest)?;
            }
            let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
            if s8 {
                stage::replace_mirror(ctx.paths, sid, &chat, projects, &sync.mac_cwd, sync.view_messages, &rules, build, &ctx.target.vm_id)?;
                audit(ctx.paths, audit_event::TRANSCRIPT_MIGRATE, &[("session", sid.to_string()), ("from", "gone_vm".to_string()), ("outcome", "migrated".to_string()), ("bytes", up.bytes.to_string())]);
            } else {
                // GZ-1: a chat that went on while it went up keeps its original (S3 holds the scanned bytes).
                stage::unchanged_since_scan(&chat, &digests, sid)?;
                stage::leave_view(ctx.paths, sid, &chat, projects, &sync.mac_cwd, sync.view_messages, &rules, build)?;
                // `rate` only when something went up, as `session stage` writes it (S10 F5).
                let mut pairs = vec![("session", sid.to_string()), ("bytes", up.bytes.to_string()), ("parts", up.parts.to_string()), ("outcome", "staged".to_string()), ("ms", ms.to_string())];
                if up.sent > 0 {
                    pairs.push(("rate", up.rate().to_string()));
                }
                // S11 (C.3.7): the stored bytes, when the upload encoded.
                if up.encoding.is_some() {
                    pairs.push(("stored", up.stored.to_string()));
                }
                audit(ctx.paths, audit_event::TRANSCRIPT_STAGE, &pairs);
            }
            staged = Some(up.bytes);
        }
    }
    let _held = manifest::lock(ctx.paths, sid).await?;
    let Some(mut m) = manifest::read(ctx.paths, sid)? else { return Ok(TranscriptOutcome::NothingToRestore) };
    // S11 (L5, C.3.6): the backstop. A chat stored encoded restores only on a VM that decodes it, before the stat,
    // the kept-on-VM answer and any presign (an unknown-caps row, a pinned older image; `restore_subtree` after it).
    if m.encoded() {
        super::require_cap(ctx.caps, &ctx.target.vm_id, crate::wire::frame::CAP_TRANSCRIPT_GZIP_V1)?;
    }
    if m.parts.is_empty() {
        tracing::info!(session = sid, "transcript: the manifest commits nothing: nothing to restore");
        return Ok(TranscriptOutcome::NothingToRestore);
    }
    // A fingerprint that is no sha256 (never one this Mac committed) counts as none: the VM's copy is then not kept.
    let fp = (m.committed > 0 && crate::bridge::s3::sync::is_digest(&m.fp)).then(|| m.fp.clone());
    let prefix = crate::wire::workspace::StatQuery { rel: rel.clone(), from: Some(m.committed), fp: fp.clone(), subtree: false };
    let now = sctx.stat(&prefix).await?;
    if staged.is_none() && fp.is_some() && now.present && now.size >= m.committed && now.fp_ok == Some(true) {
        return Ok(TranscriptOutcome::KeptOnVm);
    }
    let t0 = std::time::Instant::now();
    let client = crate::bridge::s3::client::S3Client::new(ctx.api, &sync.target)?;
    // The tails are handed under g<max(gen, 1)> (a Mac-begun chat's first VM bytes open generation 1). S10 (R1): the
    // chain from the committed length, each tail where the one before ended, as many as one pull takes.
    let tail_gen = m.tail_gen();
    let room = crate::wire::s3::PULL_PARTS_MAX.saturating_sub(m.parts.len()).min(crate::bridge::s3::TAIL_CHAIN_MAX);
    let listed = client.list(&crate::bridge::s3::sync::tail_prefix(sid, tail_gen)).await?;
    let chain = crate::bridge::s3::sync::tail_chain(&listed, sid, tail_gen, m.committed, room);
    left_out(sid, &chain);
    let mut pieces: Vec<Piece> = m.parts.iter().map(|p| (p.key.clone(), p.version_id.clone(), p.len, Some(p.sha256.clone()), p.encoding)).collect();
    pieces.extend(chain.links.iter().map(|(key, size)| (key.clone(), String::new(), *size, None, None)));
    let whole = (m.parts.len() == 1 && chain.links.is_empty()).then(|| m.parts[0].sha256.clone());
    let (parts, bytes) = pull_one(&sctx, sid, &rel, &pieces, whole, 1).await?;
    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::info!(session = sid, parts, bytes, ms, "transcript restored from S3");
    if let Ok(after) = sctx.stat(&prefix).await {
        m.ino = after.ino;
        m.vm = Some(ctx.target.vm_id.clone());
        manifest::write(ctx.paths, &m)?;
    }
    Ok(match staged {
        Some(bytes) => TranscriptOutcome::Staged { bytes },
        None => TranscriptOutcome::Restored { parts, bytes },
    })
}

/// [`restore`] of a chat begun on a VM that S3 holds nothing committed of
/// (no manifest: it closed before its first sync completed): a VM holding
/// its file keeps it; else the tail the shim pushed from 0 at `/suspend` or
/// `/terminate` (`v1/<sid>/vm/g1/t/0000000000000000`, the transcript from
/// its start, no sha256 to check, as any tail), found by listing `g1/t/`,
/// and, S10 (R1), the chain of tails after it (each where the one before
/// ended: a URL handed after a `/suspend`'s push), are pulled; else nothing
/// is there to restore. The next sync pushes it as generation 1's base and
/// supersedes those tails.
async fn restore_unsynced<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(
    sctx: &crate::bridge::s3::sync::SyncCtx<'_, A, D, T>,
    sid: &str,
    rel: &str,
) -> Result<TranscriptOutcome, BridgeError> {
    let held = sctx.stat(&crate::wire::workspace::StatQuery { rel: rel.to_string(), from: None, fp: None, subtree: false }).await?;
    if held.present && held.size > 0 {
        tracing::info!(session = sid, "transcript: a VM-begun chat S3 holds nothing committed of: the VM's copy is kept");
        return Ok(TranscriptOutcome::KeptOnVm);
    }
    let client = crate::bridge::s3::client::S3Client::new(sctx.api, &sctx.sync.target)?;
    let listed = client.list(&crate::bridge::s3::sync::tail_prefix(sid, 1)).await?;
    let room = crate::wire::s3::PULL_PARTS_MAX.min(crate::bridge::s3::TAIL_CHAIN_MAX);
    let chain = crate::bridge::s3::sync::tail_chain(&listed, sid, 1, 0, room);
    left_out(sid, &chain);
    if chain.links.is_empty() {
        tracing::info!(session = sid, "transcript: a VM-begun chat that never reached S3: nothing to restore");
        return Ok(TranscriptOutcome::NothingToRestore);
    }
    let pieces: Vec<Piece> = chain.links.iter().map(|(key, size)| (key.clone(), String::new(), *size, None, None)).collect();
    let (parts, bytes) = pull_one(sctx, sid, rel, &pieces, None, 1).await?;
    tracing::info!(session = sid, bytes, tails = parts, "transcript restored from its tails (closed before its first sync)");
    Ok(TranscriptOutcome::Restored { parts, bytes })
}

/// S10 (R1): the tails a restore leaves out, logged: those off the chain it
/// follows (below the committed length: superseded at the next hand or
/// sync; past a gap or inside a link: no restore reaches them), and a chain
/// longer than one pull takes.
fn left_out(sid: &str, chain: &crate::bridge::s3::sync::TailChain) {
    if !chain.off.is_empty() {
        let starts: Vec<String> = chain.off.iter().map(|(_, from)| from.to_string()).collect();
        tracing::info!(session = sid, links = chain.links.len(), "transcript: tail(s) off the chain left out, starting at {}", starts.join(", "));
    }
    if chain.more {
        tracing::info!(session = sid, links = chain.links.len(), "transcript: S3 holds a tail at {} past the chain followed: left out", chain.end);
    }
}

/// What [`restore_subtree`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubtreeRestore {
    /// Files pulled into the VM.
    pub pulled: u32,
    /// Files the VM holds as committed, or newer (kept).
    pub kept: u32,
    /// Files no transcript rel names (a Mac-begun chat's tool output: S3 and `origin/` keep them).
    pub unnamed: u32,
}

/// The session's subtree files back into the VM (S9 phase 4: out of P3's
/// init deadline, the code-out trigger's first step after the spawn, with
/// no deadline of its own): one stat of the VM with its subtree, then each
/// manifest file (into the VM's project directory: a Mac-begun chat's
/// carry this Mac's slug) the VM lacks, holds shorter, or holds at the same
/// length with another sha256, pulled from its own key, at most
/// `TRANSFERS_MAX` at once; one the VM holds longer is newer than the
/// commit (kept: the next sync pushes it). A subtree over the helper's caps
/// (`too_large`) is read one stat per file instead (its whole-file
/// sha256). Nothing to do without a manifest. A pull that fails is the
/// error (the files pulled before it stay).
pub async fn restore_subtree<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(sctx: &crate::bridge::s3::sync::SyncCtx<'_, A, D, T>, sid: &str) -> Result<SubtreeRestore, BridgeError> {
    use futures_util::{StreamExt as _, TryStreamExt as _};
    let mut done = SubtreeRestore::default();
    let Some(m) = crate::bridge::s3::manifest::read(sctx.paths, sid)? else { return Ok(done) };
    let mut due: Vec<(String, &crate::bridge::s3::manifest::ManifestFile)> = Vec::new();
    for f in &m.files {
        let frel = f.rel.split_once('/').map_or_else(|| f.rel.clone(), |(_, rest)| format!("{}/{rest}", sctx.sync.slug));
        if transcript_rel_check(&frel).is_err() {
            done.unnamed += 1;
            continue;
        }
        if !due.iter().any(|(r, _)| *r == frel) {
            due.push((frel, f));
        }
    }
    if due.is_empty() {
        return Ok(done);
    }
    let rel = crate::bridge::s3::sync::main_rel(&sctx.sync.slug, sid);
    // What the VM holds: (size, sha256) by rel. From the committed length, as a sync stats: the main transcript's
    // whole-file sha256 (a stat without `from`) is never asked for.
    let held: Vec<(String, u64, String)> = match sctx.stat(&crate::wire::workspace::StatQuery { rel: rel.clone(), from: Some(m.committed), fp: None, subtree: true }).await {
        Ok(stat) => stat.subtree.into_iter().map(|f| (f.rel, f.size, f.sha256)).collect(),
        Err(BridgeError::WorkspaceRefused { code, .. }) if code == crate::wire::workspace::refusal::TOO_LARGE => {
            let mut held = Vec::new();
            for (frel, _) in &due {
                let st = sctx.stat(&crate::wire::workspace::StatQuery { rel: frel.clone(), from: None, fp: None, subtree: false }).await?;
                if let (true, Some(sha)) = (st.present, st.sha256) {
                    held.push((frel.clone(), st.size, sha));
                }
            }
            held
        }
        Err(e) => return Err(e),
    };
    let mut todo = Vec::new();
    for (frel, f) in due {
        match held.iter().find(|(r, _, _)| *r == frel) {
            Some((_, size, sha)) if *size > f.len || (*size == f.len && *sha == f.sha256) => done.kept += 1,
            _ => todo.push((frel, f.clone())),
        }
    }
    // S10 §1.3: up to TRANSFERS_MAX pulls share the VM's link at once, so each one's budget (and its presigned
    // GETs' life) is its bytes times the pulls sharing it.
    let share = u32::try_from(todo.len().min(crate::wire::workspace::TRANSFERS_MAX)).unwrap_or(1).max(1);
    let pulls: Vec<_> = todo.into_iter().map(|(frel, f)| pull_file(sctx, sid, frel, f, share)).collect();
    let pulled: Vec<(u32, u64)> = futures_util::stream::iter(pulls).buffer_unordered(crate::wire::workspace::TRANSFERS_MAX).try_collect().await?;
    done.pulled = u32::try_from(pulled.len()).unwrap_or(u32::MAX);
    if done.unnamed > 0 {
        tracing::info!(session = sid, unnamed = done.unnamed, "transcript: file(s) no transcript rel names kept in S3, not written in the VM");
    }
    Ok(done)
}

/// One subtree file of the manifest pulled into the VM at `frel`, from its own key alone ([`restore_subtree`]).
async fn pull_file<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(
    sctx: &crate::bridge::s3::sync::SyncCtx<'_, A, D, T>,
    sid: &str,
    frel: String,
    f: crate::bridge::s3::manifest::ManifestFile,
    share: u32,
) -> Result<(u32, u64), BridgeError> {
    let sha = Some(f.sha256.clone());
    pull_one(sctx, sid, &frel, &[(f.key, f.version_id.unwrap_or_default(), f.len, sha.clone(), f.encoding)], sha, share).await
}

/// A stage cut after its manifest and before its view (`session stage`,
/// P3's inline upload, `migrate-s9`'s gone-VM form: the step stopped, or
/// its view could not be built): the copy still in place under `projects`
/// (not a view) whose length and sha256 are the manifest's first part, a
/// `v1/<sid>/mac/<sha256>` object, leaves now as that step would have left
/// it. A Mac-begun chat's (origin `mac`) moves to `origin/` behind its view
/// (`stage::leave_view`); an S8 mirror (origin `vm`) is deleted behind its
/// view (`stage::replace_mirror`). Any other copy is left alone: it is not
/// the one S3 holds.
#[allow(clippy::too_many_arguments)]
fn finish_cut_stage(
    paths: &Paths,
    sync: &crate::bridge::s3::TranscriptSync,
    rules: &crate::bridge::scan::Rules,
    projects: &Path,
    slugs: &[&str],
    sid: &str,
    m: &crate::bridge::s3::manifest::Manifest,
    vm: &str,
    build: crate::bridge::s3::stage::ViewBuilder<'_>,
) -> Result<(), BridgeError> {
    use crate::bridge::s3::{manifest, stage};
    let Some(first) = m.parts.first() else { return Ok(()) };
    if !matches!(crate::wire::s3::S3Key::parse(&first.key), Some(crate::wire::s3::S3Key::Mac { .. })) || !matches!(m.origin.as_str(), manifest::ORIGIN_MAC | manifest::ORIGIN_VM) {
        return Ok(());
    }
    let Ok(Some(chat)) = stage::locate(projects, slugs, sid, stage::STAGE_MAX) else { return Ok(()) };
    let main = chat.main_path(sid);
    if crate::bridge::view::is_view_file(&main) || chat.files.first().map(|(_, n)| *n) != Some(first.len) || stage::sha256_if_len(&main, first.len)?.as_deref() != Some(first.sha256.as_str()) {
        return Ok(());
    }
    tracing::info!(session = sid, origin = %m.origin, "transcript: a stage cut before its view: the copy S3 holds leaves this Mac's projects now");
    if m.origin == manifest::ORIGIN_MAC {
        stage::leave_view(paths, sid, &chat, projects, &sync.mac_cwd, sync.view_messages, rules, build)?;
    } else {
        stage::replace_mirror(paths, sid, &chat, projects, &sync.mac_cwd, sync.view_messages, rules, build, vm)?;
    }
    Ok(())
}

/// One piece of a pull ([`pull_one`]): its key, its version (empty: the
/// current one), its decoded length, its decoded sha256 (none: a tail), and
/// S11 (L5) how its object is stored (none: identity; the tails' always).
type Piece = (String, String, u64, Option<String>, Option<crate::wire::workspace::PartEncoding>);

/// One `POST /transcript/pull` of `rel` from `pieces` ([`Piece`]: key,
/// version or empty, length, sha256 or none, encoding), presigned GETs
/// expiring after the pull's budget, `whole` the file's sha256 when known;
/// each part's `encoding` its piece's (only to a VM naming
/// `transcript_gzip_v1`: [`restore`]'s backstop); audited
/// `transcript_pull`. Parts and bytes written; not written is `S3` (exit 7)
/// naming the first part that failed its status, length or sha256. Under a
/// deadline (a reopen's P3, inside Cursor's window: at the proxy's 4 to 16
/// MB/s a GiB takes minutes) a pull of more than `wire::s3::INLINE_MAX` is
/// `TranscriptPullTooLarge` (exit 9) before any presign or request.
async fn pull_one<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(
    sctx: &crate::bridge::s3::sync::SyncCtx<'_, A, D, T>,
    sid: &str,
    rel: &str,
    pieces: &[Piece],
    whole: Option<String>,
    share: u32,
) -> Result<(u32, u64), BridgeError> {
    use crate::bridge::s3::{presign, S3Method};
    let t0 = std::time::Instant::now();
    let bytes: u64 = pieces.iter().map(|p| p.2).sum();
    if sctx.deadline.is_some() && bytes > crate::wire::s3::INLINE_MAX {
        return Err(BridgeError::TranscriptPullTooLarge { session: sid.to_string(), bytes });
    }
    // One pull alone (S10: C sends the share of the pulls that run at once).
    let expires = presign::pull_expiry(bytes, share);
    let mut parts = Vec::with_capacity(pieces.len());
    for (key, version, len, sha, encoding) in pieces {
        let query = if version.is_empty() { Vec::new() } else { vec![("versionId".to_string(), version.clone())] };
        let url = sctx.api.presign(&presign::request(S3Method::Get, &sctx.sync.target, Some(key.clone()), query, Vec::new(), expires)).await?;
        parts.push(crate::wire::workspace::PullPart { url, len: *len, sha256: sha.clone(), encoding: *encoding });
    }
    let req = crate::wire::workspace::TranscriptPull { rel: rel.to_string(), parts, sha256: whole, owner: sctx.sync.target.owner.clone(), proxy: sctx.sync.proxy.clone(), share };
    let x = Exchange { api: sctx.api, tokens: sctx.tokens, vm_id: &sctx.target.vm_id, port: APP_PORT, cap: crate::wire::frame::CAP_TRANSCRIPT_S3_V1, route: "POST /transcript/pull", deadline: sctx.deadline, idempotent: false };
    let reply = match exchange(&x, |t| {
        let req = &req;
        async move { sctx.dp.transcript_pull(sctx.target, &t, req).await }
    })
    .await?
    {
        (reply, Verdict::Done) => reply.body.ok_or_else(|| BridgeError::Protocol("POST /transcript/pull answered without a reply".into()))?,
        (reply, _) => return Err(BridgeError::Protocol(format!("POST /transcript/pull answered HTTP {} where a pull's answer was due", reply.status))),
    };
    let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    let n = u32::try_from(pieces.len()).unwrap_or(u32::MAX);
    let outcome = if reply.written { "written" } else { "failed" };
    audit(sctx.paths, audit_event::TRANSCRIPT_PULL, &[("session", sid.to_string()), ("vm", sctx.target.vm_id.clone()), ("parts", n.to_string()), ("bytes", bytes.to_string()), ("outcome", outcome.to_string()), ("ms", ms.to_string())]);
    if !reply.written {
        let bad = reply.parts.iter().find(|p| !p.ok);
        return Err(BridgeError::S3 { op: "transcript pull", status: bad.map_or(0, |p| p.s3_status), code: None });
    }
    Ok((n, bytes))
}

/// [`digest_stream`] over the first `len` bytes of `path` (a regular file,
/// opened without following a symlink, never blocking); a file shorter than
/// `len` now is an error.
pub fn digest_file(rules: &crate::bridge::scan::Rules, path: &Path, len: u64, part_len: u64) -> Result<FileDigest, BridgeError> {
    let at = |what: &str, e: std::io::Error| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot {what} {}: {e}", path.display())));
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path).map_err(|e| at("open", e))?;
    if !file.metadata().map_err(|e| at("stat", e))?.is_file() {
        return Err(BridgeError::Io(std::io::Error::other(format!("{} is not a regular file", path.display()))));
    }
    let d = digest_stream(rules, &mut file.take(len), part_len)?;
    if d.len != len {
        return Err(BridgeError::Io(std::io::Error::other(format!("{} is shorter than its {len} bytes now", path.display()))));
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::agent::AgentTarget;
    use crate::bridge::api::FakeMicrovmApi;
    use crate::bridge::dataplane::Unreached;
    use crate::bridge::workspace::{code, Head, SeedLimits, SeedProgress, WsKind};
    use crate::wire::frame::{CAP_TRANSCRIPT_S3_V1, CAP_WORKSPACE_V1};
    use crate::wire::redact::Secret;
    use crate::wire::workspace::ObjectFormat;
    use std::path::PathBuf;

    const ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    /// An AWS access key id's shape, built at run time.
    fn key() -> String {
        format!("{}{}", "AKIA", "Q".repeat(16))
    }

    /// A local chat's two lines: a prompt, then what a tool printed.
    fn lines(printed: &str) -> String {
        format!("{{\"type\":\"user\",\"message\":{{\"content\":\"show the deploy config\"}}}}\n{{\"type\":\"user\",\"message\":{{\"content\":[{{\"type\":\"tool_result\",\"content\":\"{printed}\"}}]}}}}\n")
    }

    /// A bridge under a tempdir, a workspace at `/w`, and the Mac's projects
    /// root (`<tmp>/projects`), the session's project `-mac`.
    struct World {
        _tmp: tempfile::TempDir,
        paths: Paths,
        cfg: BridgeConfig,
        ws: WorkspaceRef,
        projects: PathBuf,
    }

    impl World {
        fn new() -> World {
            let tmp = tempfile::tempdir().unwrap();
            let ws = WorkspaceRef {
                cwd: "/w".into(),
                root: "/w".into(),
                vm_cwd: "/w".into(),
                vm_root: "/w".into(),
                slug: "-w".into(),
                kind: WsKind::Git { git_dir: "/w/.git".into(), common_dir: "/w/.git".into(), object_format: ObjectFormat::Sha1 },
                head: Head::Detached { sha: "a".repeat(40) },
                seed_branch: None,
            };
            World { paths: Paths::from_root_and_env(tmp.path().join("bridge"), None), cfg: BridgeConfig::default(), ws, projects: tmp.path().join("projects"), _tmp: tmp }
        }

        /// `rel` below the session's project, holding `text`.
        fn plant(&self, rel: &str, text: &str) -> PathBuf {
            let path = self.projects.join("-mac").join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        }

        /// The audit's rows of `event`.
        fn rows(&self, event: &str) -> Vec<serde_json::Value> {
            let text = std::fs::read_to_string(self.paths.audit()).unwrap_or_default();
            text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == event).collect()
        }
    }

    fn target() -> AgentTarget {
        AgentTarget { vm_id: "microvm-1".into(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false }
    }

    /// The finding a refusal names (its message), or a panic naming what came instead.
    fn finding(e: BridgeError) -> String {
        match e {
            BridgeError::WorkspaceRefused { code: code::FINDING, message } => message,
            other => panic!("not a finding: {other:?}"),
        }
    }

    /// CUSTODY-2, after the S3 cut-over: a hit in a subagent's file alone
    /// of a chat begun on this Mac refuses its inline upload before any
    /// request ([`restore`]: no presign, no S3 call, nothing to the VM: the
    /// data plane and the API are never reached), exit 9 naming
    /// `transcript:REL`, the line and the rule, never the value;
    /// `seed_refused` audited with the VM, no manifest written, the chat left
    /// in place. P1's scan of the same copy refuses the same way, before any
    /// VM (its row names none).
    #[tokio::test]
    async fn a_tripwire_in_a_subagent_file_refuses_the_inline_upload_before_any_request() {
        let w = World::new();
        let main = w.plant(&format!("{ID}.jsonl"), &lines("nothing to see"));
        w.plant(&format!("{ID}/subagents/agent-a1.jsonl"), &lines(&format!("aws_access_key_id = {}", key())));
        let (api, target, caps) = (FakeMicrovmApi::new(), target(), vec![CAP_WORKSPACE_V1.to_string(), CAP_TRANSCRIPT_S3_V1.to_string()]);
        let ctx = EnsureCtx { api: &api, dp: &Unreached, tokens: &Unreached, paths: &w.paths, cfg: &w.cfg, target: &target, caps: &caps, ws: &w.ws, lim: SeedLimits::wrapper(&w.cfg), deadline: None, progress: &|_: SeedProgress| {} };
        // A lab bucket nobody listens at: a request would fail, never pass.
        let lab = crate::bridge::s3::S3Target { bucket: crate::bridge::s3::LAB_BUCKET.into(), owner: crate::bridge::s3::LAB_OWNER.into(), endpoint: crate::bridge::s3::S3Endpoint::Lab(([127, 0, 0, 1], 9).into()) };
        let sync = crate::bridge::s3::TranscriptSync { target: lab, slug: "-vm".into(), mac_cwd: "/w".into(), mac_projects: w.projects.clone(), proxy: None, view_messages: 10 };
        let want = format!("transcript:{ID}/subagents/agent-a1.jsonl line 2: rule aws-access-key-id");
        let e = restore(&ctx, &sync, Some(&w.projects), &["-mac"], ID, &crate::wire::view::build_view).await.unwrap_err();
        assert_eq!(finding(e), want);
        assert!(api.calls().is_empty(), "no AWS call: {:?}", api.calls());
        assert!(!w.paths.transcript_manifest(ID).exists() && !w.paths.transcript_stage(ID).exists(), "nothing staged");
        assert_eq!(std::fs::read_to_string(&main).unwrap(), lines("nothing to see"), "the chat left in place");
        let rows = w.rows("seed_refused");
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!((rows[0]["detail"]["step"].as_str(), rows[0]["detail"]["code"].as_str(), rows[0]["detail"]["vm"].as_str()), (Some("transcript"), Some("finding"), Some("microvm-1")));
        assert!(w.rows("transcript_stage").is_empty() && w.rows("transcript_pull").is_empty(), "nothing went up");
        assert_eq!(finding(scan_mac_copy(&w.paths, &w.cfg, &w.ws, &w.projects, &["-mac"], ID).unwrap_err()), want);
        let rows = w.rows("seed_refused");
        assert_eq!((rows.len(), rows[1]["detail"].get("vm")), (2, None), "P1's: no VM chosen yet");
        assert!(!std::fs::read_to_string(w.paths.audit()).unwrap().contains(&key()), "no value in the audit");
    }

    /// P1's scan reads what the inline upload sends to S3, every file of the
    /// chat (a file no transcript rel names goes up too, and stays in S3
    /// and `origin/`): a clean chat passes, and so do a session the Mac
    /// holds no copy of and a view in the chat's place (never a Mac copy); a
    /// hit in the transcript's second line refuses, so does one in a file
    /// directly below the session, and a subagent file whose name trips a
    /// rule (the name shown as `a path name`). Each audited `seed_refused`
    /// with no VM; nothing written to `state/tmp/`.
    #[test]
    fn p1s_scan_refuses_what_the_inline_upload_would_send() {
        let w = World::new();
        let scan = |id: &str| scan_mac_copy(&w.paths, &w.cfg, &w.ws, &w.projects, &["-mac"], id);
        let main = w.plant(&format!("{ID}.jsonl"), &lines("nothing to see"));
        scan(ID).unwrap();
        scan("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c").unwrap();
        std::fs::write(&main, lines(&format!("aws_access_key_id = {}", key()))).unwrap();
        assert_eq!(finding(scan(ID).unwrap_err()), format!("transcript:{ID}.jsonl line 2: rule aws-access-key-id"));
        std::fs::write(&main, lines("nothing to see")).unwrap();
        // Directly below the session: no transcript rel names it, but the inline upload sends it to S3.
        let stray = w.plant(&format!("{ID}/stray.jsonl"), &lines(&format!("aws_access_key_id = {}", key())));
        assert_eq!(finding(scan(ID).unwrap_err()), format!("transcript:{ID}/stray.jsonl line 2: rule aws-access-key-id"));
        std::fs::remove_file(stray).unwrap();
        w.plant(&format!("{ID}/subagents/agent-{}.jsonl", key()), &lines("nothing to see"));
        assert_eq!(finding(scan(ID).unwrap_err()), "transcript:a path name: rule aws-access-key-id");
        // A view in the chat's place is no Mac copy: nothing to scan, whatever lies beside it.
        std::fs::write(&main, format!("{}\"type\":\"ai-title\",\"aiTitle\":\"t\",\"sessionId\":\"{ID}\"}}\n", crate::wire::view::VIEW_MARK_PREFIX)).unwrap();
        scan(ID).unwrap();
        let rows = w.rows("seed_refused");
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert!(rows.iter().all(|r| r["detail"]["step"] == "transcript" && r["detail"].get("vm").is_none()), "{rows:?}");
        assert!(!w.paths.tmp().exists(), "P1 copies nothing");
        assert!(!std::fs::read_to_string(w.paths.audit()).unwrap().contains(&key()), "no value in the audit");
    }

    /// S11 (L5, C.3.6): the restore's backstop. A manifest stored encoded (its
    /// main object gzip) restores only on a VM naming `transcript_gzip_v1`:
    /// without it, `NoCapability` (exit 7) naming the cap and the VM, before
    /// any stat of the VM, kept-on-VM answer or presign (the data plane is
    /// never reached, the API never called). With the cap the restore goes
    /// on to its stat (here the unreached data plane's error). An identity
    /// manifest needs no such cap.
    #[tokio::test]
    async fn restore_refuses_an_encoded_manifest_on_a_vm_without_the_cap() {
        use crate::bridge::s3::manifest::{self, Manifest, ManifestPart, ORIGIN_MAC};
        use crate::wire::frame::CAP_TRANSCRIPT_GZIP_V1;
        let w = World::new();
        let lab = crate::bridge::s3::S3Target { bucket: crate::bridge::s3::LAB_BUCKET.into(), owner: crate::bridge::s3::LAB_OWNER.into(), endpoint: crate::bridge::s3::S3Endpoint::Lab(([127, 0, 0, 1], 9).into()) };
        let sync = crate::bridge::s3::TranscriptSync { target: lab.clone(), slug: "-w".into(), mac_cwd: "/w".into(), mac_projects: w.projects.clone(), proxy: None, view_messages: 10 };
        let mut m = Manifest::new(ID, &lab, ORIGIN_MAC, &format!("-w/{ID}.jsonl"), "2026-10-23T10:00:00.000Z");
        let key = crate::wire::s3::S3Key::Mac { session: ID.into(), sha256: "d".repeat(64) }.render();
        m.parts.push(ManifestPart { key, version_id: "fv1".into(), from: 0, len: 500, sha256: "b".repeat(64), encoding: Some(crate::wire::workspace::PartEncoding::Gzip), stored_len: Some(120), stored_sha256: Some("d".repeat(64)) });
        (m.committed, m.fp) = (500, "f".repeat(64));
        manifest::write(&w.paths, &m).unwrap();
        let (api, target) = (FakeMicrovmApi::new(), target());
        let restore_on = |caps: Vec<String>| {
            let (w, sync, api, target) = (&w, &sync, &api, &target);
            async move {
                let ctx = EnsureCtx { api, dp: &Unreached, tokens: &Unreached, paths: &w.paths, cfg: &w.cfg, target, caps: &caps, ws: &w.ws, lim: SeedLimits::wrapper(&w.cfg), deadline: None, progress: &|_: SeedProgress| {} };
                restore(&ctx, sync, Some(&w.projects), &["-mac"], ID, &crate::wire::view::build_view).await
            }
        };
        let e = restore_on(vec![CAP_WORKSPACE_V1.to_string(), CAP_TRANSCRIPT_S3_V1.to_string()]).await.unwrap_err();
        match &e {
            BridgeError::NoCapability { cap, message } => assert!(*cap == CAP_TRANSCRIPT_GZIP_V1 && message.contains("microvm-1"), "{e:?}"),
            other => panic!("not the backstop: {other:?}"),
        }
        assert_eq!(crate::errors::CliError::from(e).exit_code(), 7);
        assert!(api.calls().is_empty(), "no presign, no AWS call: {:?}", api.calls());
        assert_eq!(manifest::read(&w.paths, ID).unwrap().as_ref(), Some(&m), "the manifest as it was");
        // The cap named: past the backstop, to the stat (the data plane this test never reaches).
        let e = restore_on(vec![CAP_WORKSPACE_V1.to_string(), CAP_TRANSCRIPT_S3_V1.to_string(), CAP_TRANSCRIPT_GZIP_V1.to_string()]).await.unwrap_err();
        assert!(!matches!(e, BridgeError::NoCapability { .. }), "{e:?}");
        // An identity manifest: no such cap asked.
        let mut plain = m.clone();
        (plain.parts[0].encoding, plain.parts[0].stored_len, plain.parts[0].stored_sha256) = (None, None, None);
        manifest::write(&w.paths, &plain).unwrap();
        let e = restore_on(vec![CAP_WORKSPACE_V1.to_string(), CAP_TRANSCRIPT_S3_V1.to_string()]).await.unwrap_err();
        assert!(!matches!(e, BridgeError::NoCapability { .. }), "{e:?}");
    }
}
