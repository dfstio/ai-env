//! Code-out (S8 §7): the VM's commits and snapshots of its uncommitted work
//! (`refs/wip/*`), fetched after every result and by `box fetch` through
//! `POST /codeout`, imported into a scratch repository, scanned, and promoted
//! in one `update-ref` transaction to `refs/remotes/box/*` (a ref with a
//! finding to `refs/remotes/box-quarantine/*`) under the workspace's fetch
//! lock. The user's branches and working tree are never touched. Also the
//! pump's per-result trigger: non-blocking, coalescing, at most 300 ms at
//! close. Built in S8 wave 1 (W4).
//!
//! The trigger's API ([`CodeoutTrigger`], [`CodeoutCtx`]), what a fetch
//! reports ([`FetchReport`]), the Mac's ref namespaces and the names the VM's
//! refs take there ([`box_ref_of`], [`box_refs`]) were frozen in S8 phase 0;
//! [`fetch`] is one code-out, [`import`] its Mac half after the transfer.
//!
//! The names the VM chose are the VM's output, which the Mac does not trust:
//! the agent can read the setup-token there and name a branch or a snapshot
//! after it. A ref whose name looks like a credential ([`credential_shaped`])
//! is counted and goes no further: no git argument, ref, reflog, note,
//! workspace row or registry row of the Mac's holds its name (S8 phase 4).
use crate::bridge::agent::AgentTarget;
use crate::bridge::api::MicrovmApi;
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::dataplane::{exchange, DataPlane, Exchange, TokenSource, Verdict};
use crate::bridge::errors::BridgeError;
use crate::bridge::remote::audit_event;
use crate::bridge::scan::Rules;
use crate::bridge::voice;
use crate::bridge::workspace::blobscan::ScanSet;
use crate::bridge::workspace::snapshot::Scratch;
use crate::bridge::workspace::{audit, blocking, git_failed, rows, WorkspaceRef, WsKind};
use crate::gitrun::GitRun;
use crate::wire::redact::scrub;
use crate::wire::time::{rfc3339_utc, unix_now};
use crate::wire::workspace::{branch_check, is_ref_name, nfc, refusal, CodeoutManifest, CodeoutRequest, CODE_PORT, HAVES_MAX, HEADS_PREFIX, SEED_WIP_REF, WIP_REF_PREFIX};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use unicode_normalization::UnicodeNormalization;

/// Where a fetch promotes the VM's clean refs, each by its box name
/// ([`box_ref_of`]): a branch `refs/heads/<b>` as `refs/remotes/box/<b>`, a
/// snapshot `refs/wip/<x>` as `box/wip/<x>`, the seeded WIP as
/// `box/seed-wip`, a detached HEAD as `box/HEAD`. Never pushed anywhere;
/// reviewed and merged by hand.
pub const BOX_REFS: &str = "refs/remotes/box/";
/// Where a ref with a scan finding goes instead (`box fetch` exits 9), under
/// the same name past the prefix.
pub const BOX_QUARANTINE_REFS: &str = "refs/remotes/box-quarantine/";
/// Where a fetch puts the VM's refs before the scans (`<pid>-<n>/<box name>`);
/// removed once the promotion ran, or failed. Those of a process that exited
/// in between go at the next import's start ([`import`]).
pub const INCOMING_REFS: &str = "refs/ai-env/incoming/";
/// At the wrapper's close, the longest it waits for a running fetch: then
/// the fetch is abandoned. The box refs move in one transaction or not at
/// all; the incoming refs and scratch directories of an import the
/// process's exit cut short stay until the next import and the next
/// scratch repository remove them.
pub const CLOSE_WAIT: Duration = Duration::from_millis(300);
/// The wrapper's background fetch says at most one line per this: a
/// failure, refs quarantined, refs kept out ([`hidden_note`]).
pub const FAILURE_LINE_EVERY: Duration = Duration::from_secs(600);

/// The first components of a VM branch the box namespace keeps for itself,
/// compared as the Mac's disk compares names ([`disk_key`]): a branch `wip`
/// or `wip/…` would collide with the snapshots' `box/wip/*`, `seed-wip` with
/// the seeded WIP's `box/seed-wip`, `HEAD/…` with a detached HEAD's `box/HEAD`.
pub const BOX_RESERVED: [&str; 3] = ["wip", "seed-wip", "HEAD"];

/// A name as the Mac's disk (APFS) compares names: Unicode's case folding,
/// not ASCII's alone (É and é, `ſ` U+017F and s, ß and ss, ς and σ, `K`
/// U+212A and k), and canonically equivalent spellings as one (NFC and NFD
/// `café`): decomposed, each character lowercased, uppercased and lowercased
/// again, decomposed again. Two names APFS takes for one always get one key;
/// the odd pair it keeps apart may too (ı and i), which only skips a ref,
/// never fails a transaction.
fn disk_key(name: &str) -> String {
    let folded: String = name.nfd().flat_map(char::to_lowercase).flat_map(char::to_uppercase).flat_map(char::to_lowercase).collect();
    folded.nfd().collect()
}

/// The name a VM ref takes under [`BOX_REFS`] (pure): `refs/heads/<b>` is
/// `refs/remotes/box/<b>`, `refs/wip/<x>` is `box/wip/<x>`, `refs/ai-env/seed-wip`
/// is `box/seed-wip`, `HEAD` is `box/HEAD`, each in NFC (as git on macOS lists
/// refs, `core.precomposeUnicode`: a box ref reads back as it was written).
/// `None` for a branch whose first component is one of [`BOX_RESERVED`], and
/// for any ref `CodeoutManifest::check` refuses. So two refs one VM repository
/// holds never take one box name, nor one whose name is a directory of the
/// other's, unless they are one name in NFC ([`box_refs`] skips the second);
/// W4 names each `None` in [`FetchReport::note`].
#[must_use]
pub fn box_ref_of(vm_ref: &str) -> Option<String> {
    let name = if vm_ref == "HEAD" {
        "HEAD".to_string()
    } else if vm_ref == SEED_WIP_REF {
        "seed-wip".to_string()
    } else if let Some(snapshot) = vm_ref.strip_prefix(WIP_REF_PREFIX).filter(|_| is_ref_name(vm_ref)) {
        format!("wip/{snapshot}")
    } else {
        let branch = vm_ref.strip_prefix(HEADS_PREFIX).filter(|b| branch_check(b).is_ok())?;
        let first = disk_key(branch.split('/').next().unwrap_or(branch));
        if BOX_RESERVED.iter().any(|r| disk_key(r) == first) {
            return None;
        }
        branch.to_string()
    };
    Some(format!("{BOX_REFS}{}", nfc(&name))).filter(|n| is_ref_name(n))
}

/// What a code-out promotes of a manifest's refs (`CodeoutManifest::refs`):
/// each box name ([`box_ref_of`]) to its VM ref, then the VM refs skipped, in
/// byte order. A ref is skipped when it has no box name, or when its box name,
/// compared as the Mac's disk compares names ([`disk_key`]: case beyond ASCII,
/// NFC and NFD as one), equals one taken before it or is a directory of one
/// (or one a directory of it): the Mac's disk cannot hold both as loose refs,
/// and one ref that cannot be written fails the whole `update-ref --stdin`
/// transaction, and every code-out after it. W4 names the skipped refs in
/// [`FetchReport::note`].
#[must_use]
pub fn box_refs(refs: &BTreeMap<String, String>) -> (BTreeMap<String, String>, Vec<String>) {
    let mut taken = BTreeMap::new();
    // The box names taken so far, folded.
    let mut folded: BTreeSet<String> = BTreeSet::new();
    let mut skipped = Vec::new();
    for vm_ref in refs.keys() {
        let Some(name) = box_ref_of(vm_ref) else {
            skipped.push(vm_ref.clone());
            continue;
        };
        let key = disk_key(&name);
        let dir = format!("{key}/");
        let below = folded.range(dir.clone()..).next().is_some_and(|t| t.starts_with(&dir));
        let above = key.match_indices('/').any(|(i, _)| folded.contains(&key[..i]));
        if folded.contains(&key) || below || above {
            skipped.push(vm_ref.clone());
            continue;
        }
        folded.insert(key);
        taken.insert(name, vm_ref.clone());
    }
    (taken, skipped)
}

/// Whether `name`, one the VM chose (a ref, the branch it has checked out),
/// looks like a credential: `wire::redact::scrub` masks part of it, or a
/// tripwire of `rules` matches it (the tests a path name of a code-out's
/// trees takes). [`import`] fetches, promotes and names no such ref, and
/// `box fetch --dry-run` prints none: both only count them
/// ([`hidden_note`]). A tripwire, not a proof: an encoded token passes.
#[must_use]
pub fn credential_shaped(name: &str, rules: &Rules) -> bool {
    scrub(name) != name || !rules.scan_bytes(name.as_bytes()).is_empty()
}

/// What a code-out says of the `n` VM refs [`credential_shaped`] kept out,
/// never naming one.
#[must_use]
pub fn hidden_note(n: usize) -> String {
    format!("{n} {HIDDEN_TAIL}")
}

/// What a code-out says of the `n` VM refs [`import`] left out because
/// their object is no commit (a tree, a blob, a tag: what the helper never
/// lists), never naming one.
#[must_use]
pub fn not_commit_note(n: usize) -> String {
    format!("{n} VM ref(s) skipped: an object that is no commit (a tree, a blob or a tag; not shown)")
}

/// [`hidden_note`] past its count: how the trigger tells a report whose
/// fetch kept refs out, which it says as it says a failure.
const HIDDEN_TAIL: &str = "VM ref(s) skipped: a name that looks like a credential (not shown)";

/// What one code-out fetch did: the wrapper's census `fetch:<ok>/<n>`, the
/// session row's `last_wip_fetch`, `box fetch --json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FetchReport {
    /// When the fetch ended (RFC 3339 UTC).
    pub at: String,
    /// The promotion ran, or nothing was new (204); `false`: `note` says why.
    pub ok: bool,
    /// The refs moved under [`BOX_REFS`], by full name, to their commits.
    pub promoted: BTreeMap<String, String>,
    /// The refs with a scan finding, moved under [`BOX_QUARANTINE_REFS`].
    pub quarantined: BTreeMap<String, String>,
    /// The snapshot this fetch asked for (the VM's `refs/wip/*`), when one was
    /// made, its name does not look like a credential ([`credential_shaped`])
    /// and the import found no tree, blob or tag there ([`Imported::wip_ref`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wip_ref: Option<String>,
    /// The pack's bytes (0 when nothing was new).
    pub bytes: u64,
    pub ms: u64,
    /// Why it failed, or what it noted: each VM ref [`box_refs`] skipped (a
    /// branch under a [`BOX_RESERVED`] name, one whose box name another
    /// takes), by name; how many [`credential_shaped`] kept out, never by
    /// name ([`hidden_note`]); how many name no commit (a tree, a blob or a
    /// tag), never by name ([`not_commit_note`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// What the per-result trigger fetches with, held for the session: the
/// wrapper's own API object and tokens (D1: minted in memory), the VM, the
/// workspace.
pub struct CodeoutCtx<A, D, T> {
    pub api: Arc<A>,
    pub dp: Arc<D>,
    pub tokens: Arc<T>,
    pub paths: Paths,
    pub cfg: Arc<BridgeConfig>,
    pub target: AgentTarget,
    pub ws: WorkspaceRef,
    /// Capture the VM's settings after each fetch (T8.7, `settings_capture`).
    pub capture_settings: bool,
    /// S9: sync the transcript to S3 and rewrite the view after each fetch
    /// (`s3::TranscriptSync`, built at the session's P0); `None` for `box
    /// fetch` and a session that keeps no transcript
    /// (`--no-session-persistence`): P0 refuses one that cannot sync it.
    pub transcript: Option<crate::bridge::s3::TranscriptSync>,
}

/// How long a code-out waits for the workspace's fetch lock.
pub const FETCH_LOCK_BUDGET: Duration = Duration::from_secs(120);

const MIB: u64 = 1024 * 1024;

/// One fetch's request: a snapshot of the VM's uncommitted work first
/// (`wip`), and the largest pack it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchOpts {
    pub wip: bool,
    pub max_bytes: u64,
}

impl FetchOpts {
    /// The per-result fetch of a session: with a snapshot, `[seed].max_fetch_mib`.
    #[must_use]
    pub fn per_result(cfg: &BridgeConfig) -> FetchOpts {
        FetchOpts { wip: true, max_bytes: u64::from(cfg.seed.max_fetch_mib) * MIB }
    }
}

/// The haves of a code-out (`CodeoutRequest::haves`' order rule): the Mac's
/// HEAD and the seeded head first, then the box tips, the branches before
/// the snapshots, the newest snapshots first, while they fit `HAVES_MAX`;
/// each once.
#[must_use]
pub fn haves_of(head: Option<&str>, seeded: Option<&str>, box_tips: &BTreeMap<String, String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |id: &str| {
        if out.len() < HAVES_MAX && !out.iter().any(|h| h == id) {
            out.push(id.to_string());
        }
    };
    for id in [head, seeded].into_iter().flatten() {
        push(id);
    }
    let wip_prefix = format!("{BOX_REFS}wip/");
    for id in box_tips.iter().filter(|(n, _)| !n.starts_with(&wip_prefix)).map(|(_, id)| id) {
        push(id);
    }
    for (_, id) in box_tips.iter().rev().filter(|(n, _)| n.starts_with(&wip_prefix)) {
        push(id);
    }
    out
}

/// What [`import`] did with one code-out pack.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Imported {
    /// Box names to commits: under [`BOX_REFS`], or under [`BOX_QUARANTINE_REFS`].
    pub promoted: BTreeMap<String, String>,
    pub quarantined: BTreeMap<String, String>,
    /// VM refs not promoted, and why (a reserved name, a clash).
    pub skipped: Vec<String>,
    /// How many VM refs [`credential_shaped`] kept out (never in `skipped`).
    pub hidden: usize,
    /// How many VM refs past [`box_refs`] and the clash check name a tree, a
    /// blob or a tag (as the pack shows), left out (never in `skipped`, never
    /// named; [`not_commit_note`]). One skipped before that is in `skipped`,
    /// whatever its object.
    pub not_commits: usize,
    /// The manifest's `wip_ref`, unless [`credential_shaped`] kept it out, or
    /// its object is a tree, a blob or a tag (known once the pack is read:
    /// [`import`]).
    pub wip_ref: Option<String>,
    /// The findings of the quarantined refs.
    pub findings: Vec<crate::bridge::workspace::blobscan::Finding>,
    /// Every ref under [`BOX_REFS`] and [`BOX_QUARANTINE_REFS`] as the import
    /// left them, to their commits (the workspace row's `fetched`).
    pub tips: BTreeMap<String, String>,
}

/// One import's inputs.
pub struct Import<'a> {
    pub paths: &'a Paths,
    pub cfg: &'a BridgeConfig,
    pub ws: &'a WorkspaceRef,
    /// The code-out's manifest (checked) and its pack, a file.
    pub manifest: &'a CodeoutManifest,
    pub pack: &'a Path,
    /// What the request named as the Mac's: what the VM's thin pack leaves out.
    pub haves: &'a [String],
    pub max_blob: u64,
    /// How many `box/wip/*` refs the Mac keeps (`[seed].keep_wip_refs`): the
    /// newest by name, the manifest's `wip_ref` always among them.
    pub keep_wip: usize,
}

/// The incoming namespace of one import: `refs/ai-env/incoming/<pid>-<n>/`.
fn incoming_prefix() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!("{INCOMING_REFS}{}-{}/", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
}

/// The refs below `prefix` in `git`'s repository, to their ids.
fn refs_under(git: &GitRun, prefix: &str) -> Result<BTreeMap<String, String>, BridgeError> {
    let out = git.output(["for-each-ref", "--format=%(objectname) %(refname)", prefix]).map_err(git_failed("git for-each-ref"))?;
    Ok(String::from_utf8_lossy(&out).lines().filter_map(|l| l.split_once(' ')).map(|(id, name)| (name.to_string(), id.to_string())).collect())
}

/// Delete, in one transaction, the incoming refs of imports whose process
/// is gone (`<pid>-<n>/` with a pid neither this process nor a running one):
/// an import the process's exit cut short between its fetch and its
/// promotion (the wrapper's close abandons a running fetch, and
/// `process::exit` ends the import's thread; git, in its own process group,
/// may even finish the fetch after it). Best effort: a failure is logged.
fn sweep_incoming(user: &GitRun) {
    let Ok(left) = refs_under(user, INCOMING_REFS) else { return };
    let own = std::process::id();
    let gone = |r: &str| r.strip_prefix(INCOMING_REFS).and_then(|rest| rest.split_once('-')).and_then(|(pid, _)| pid.parse::<u32>().ok()).is_some_and(|pid| pid != own && !crate::bridge::registry::pid_alive(pid));
    let delete: String = left.keys().filter(|r| gone(r)).map(|r| format!("delete {r}\n")).collect();
    if delete.is_empty() {
        return;
    }
    if let Err(e) = user.output_stdin(["update-ref", "--stdin"], delete.as_bytes()) {
        tracing::warn!("code-out: the incoming refs of a process that is gone were not removed: {e}");
    }
}

/// Whether `name` meets one of `existing` on the Mac's disk ([`disk_key`]):
/// the same name in another case or spelling, or one a directory of the
/// other. The same name in NFC is the same ref (an update).
fn clashes(name: &str, existing: &BTreeMap<String, String>) -> bool {
    let key = disk_key(name);
    existing.keys().any(|e| {
        let other = disk_key(e);
        (other == key && nfc(e) != nfc(name)) || other.starts_with(&format!("{key}/")) || key.starts_with(&format!("{other}/"))
    })
}

/// Import one code-out (plan §7, the Mac's side): the pack indexed into a
/// scratch repository whose alternates read the user's store (`index-pack
/// --fix-thin`: a thin pack's bases are the Mac's), the manifest's refs
/// written there under their box names; `git fetch --no-tags --no-prune
/// --no-recurse-submodules` with fsck on, from that repository into
/// [`INCOMING_REFS`]; each ref's new objects scanned (the tripwires, and D8's
/// repo mode on the `.claude/settings*.json` it changed against the Mac's
/// HEAD unless the workspace trusts its repo settings); one `update-ref
/// --stdin` transaction then moves the clean refs to [`BOX_REFS`], the
/// flagged ones to [`BOX_QUARANTINE_REFS`], drops the incoming refs and the
/// snapshots past `keep_wip` (an older one the VM sent again is not
/// promoted, so not in `promoted`). A ref [`box_refs`] skips, or one whose box
/// name meets an existing ref in another case or as a directory, is skipped
/// and named. A ref whose name looks like a credential ([`credential_shaped`],
/// the scans' rules) is kept out before all of that, counted in `hidden`,
/// never named: no git argument, ref or note holds its name, and `wip_ref`
/// is `None` when the manifest's is one. Once the pack is indexed, the
/// helper's rule that a ref names a commit (its listing's `%(objecttype)`)
/// holds whoever made the manifest (S9, the lead's integration of G2's R2: a
/// hostile `/codeout` manifest, or a smart-HTTP fetch's, whose `ls-refs`
/// shows no type but a tag's), on the refs that pass [`credential_shaped`],
/// [`box_refs`] and the clash check: one whose object is a tree, a blob or
/// a tag is left out, counted in `not_commits`, never named or promoted. One
/// skipped before is named as skipped, as any skipped ref is, whatever its
/// object; so a ref to a tree or a blob that [`box_refs`] takes first
/// leaves a commit's ref whose name folds to the same skipped. A `wip_ref`
/// whose object is a tree, a blob or a tag is then `None`, its own ref
/// passed or skipped, and a manifest whose HEAD names one is `not_seeded`
/// (exit 9), as the helper answers. With no ref passing all three, the pack
/// is not read and none of this runs. The user's branches, index and
/// working tree are never touched. First, the incoming refs a process that
/// is gone left are deleted (`sweep_incoming`). S10 (F4): the refs' new
/// objects are listed and scanned as one, their settings read from one walk
/// of their trees, and a ref's own listing and scan run only once that scan
/// found something ([`scan_batch`]); the clean cache is saved once.
pub fn import(i: &Import<'_>) -> Result<Imported, BridgeError> {
    import_with(i, ScanMode::Batch)
}

/// [`import`] with S9's scans: each ref's own listing, scan and tree
/// listing, one ref after another ([`scan_per_ref`]). What the batch is held
/// equal to (S10 F4, the equivalence fixture of `tests/workspace/codeout.rs`);
/// nothing else runs it.
pub fn import_per_ref(i: &Import<'_>) -> Result<Imported, BridgeError> {
    import_with(i, ScanMode::PerRef)
}

/// How [`import`] scans the refs it takes (S10 F4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    /// [`scan_batch`].
    Batch,
    /// [`scan_per_ref`], S9's.
    PerRef,
}

/// [`import`], its refs scanned by `mode`.
fn import_with(i: &Import<'_>, mode: ScanMode) -> Result<Imported, BridgeError> {
    let WsKind::Git { common_dir, object_format, .. } = &i.ws.kind;
    let user = GitRun::mac(&i.ws.root);
    sweep_incoming(&user);
    let set = ScanSet::load(i.paths, i.cfg, i.ws)?;
    let scratch = Scratch::new(i.paths, "codeout", &common_dir.join("objects"), *object_format)?;
    let shown: BTreeMap<String, String> = i.manifest.refs.iter().filter(|(r, _)| !credential_shaped(r, &set.rules)).map(|(r, id)| (r.clone(), id.clone())).collect();
    let (taken, skipped_refs) = box_refs(&shown);
    let mut out = Imported {
        skipped: skipped_refs.iter().map(|r| format!("{r} (a name the box namespace keeps, or one another ref takes)")).collect(),
        hidden: i.manifest.refs.len() - shown.len(),
        wip_ref: i.manifest.wip_ref.clone().filter(|w| shown.contains_key(w)),
        ..Imported::default()
    };
    let existing: BTreeMap<String, String> = refs_under(&user, BOX_REFS)?.into_iter().chain(refs_under(&user, BOX_QUARANTINE_REFS)?).collect();
    let mut wanted: BTreeMap<String, String> = BTreeMap::new();
    for (name, vm_ref) in &taken {
        let suffix = name.strip_prefix(BOX_REFS).unwrap_or(name);
        let id = i.manifest.refs.get(vm_ref).cloned().unwrap_or_default();
        let quarantine_name = format!("{BOX_QUARANTINE_REFS}{suffix}");
        if clashes(name, &existing) || clashes(&quarantine_name, &existing) {
            out.skipped.push(format!("{vm_ref} (its box name meets an existing ref in another case)"));
            continue;
        }
        wanted.insert(suffix.to_string(), id);
    }
    if wanted.is_empty() {
        out.tips = existing;
        return Ok(out);
    }
    // S11 (C.1.3): a code-out without a pack (its file absent or 0 bytes: the shim's manifest-only 200, a
    // smart-HTTP fetch whose tips the haves hold) indexes nothing, so every commit it wants must be one the
    // Mac named, before any ref is written; the type check then reads them through the alternates.
    if std::fs::metadata(i.pack).is_ok_and(|m| m.len() > 0) {
        index_pack(&scratch, i.pack)?;
    } else if wanted.values().any(|id| !i.haves.contains(id)) {
        return Err(BridgeError::WorkspaceFailed { code: refusal::BAD_PACK, message: "the code-out sent no pack for a tip the Mac did not name".into() });
    }
    // Only commits go on (the helper lists nothing else): an object that is not there at all is no
    // type's, and `update-ref` below refuses its ref (`bad_refs`), as it always did. The `wip_ref`'s
    // object is read too, its ref wanted or skipped.
    let ids: BTreeSet<&String> = wanted.values().chain([&i.manifest.head]).chain(out.wip_ref.as_ref().and_then(|w| i.manifest.refs.get(w))).collect();
    let types = object_types(&scratch.git(), &ids)?;
    if let Some(other) = types.get(&i.manifest.head).filter(|t| *t != "commit") {
        return Err(BridgeError::WorkspaceRefused { code: refusal::NOT_SEEDED, message: format!("the code-out's manifest: the VM's repository has no commit checked out (its HEAD names a {other})") });
    }
    let is_commit = |id: &String| types.get(id).is_none_or(|t| t == "commit");
    let listed = wanted.len();
    wanted.retain(|_, id| is_commit(id));
    out.not_commits = listed - wanted.len();
    out.wip_ref = out.wip_ref.take().filter(|w| i.manifest.refs.get(w).is_some_and(is_commit));
    if wanted.is_empty() {
        out.tips = existing;
        return Ok(out);
    }
    let mut stdin = String::new();
    for (suffix, id) in &wanted {
        stdin.push_str(&format!("create refs/box/{suffix} {id}\n"));
    }
    scratch.git().output_stdin(["update-ref", "--stdin"], stdin.as_bytes()).map_err(|e| BridgeError::WorkspaceFailed { code: refusal::BAD_REFS, message: format!("the code-out's refs: {e}") })?;
    // Fetch, fsck on, into this import's own incoming namespace.
    let incoming = incoming_prefix();
    let mut args: Vec<String> = ["-c", "fetch.fsckObjects=true", "-c", "transfer.fsckObjects=true", "fetch", "--no-tags", "--no-prune", "--no-recurse-submodules", "--no-write-fetch-head", "--no-auto-gc", "--no-auto-maintenance", "--quiet"].iter().map(|s| (*s).to_string()).collect();
    args.push(scratch.repo().to_string_lossy().into_owned());
    for suffix in wanted.keys() {
        args.push(format!("+refs/box/{suffix}:{incoming}{suffix}"));
    }
    let fetched = user.output(&args);
    let result = fetched.map_err(git_failed("git fetch of the code-out")).and_then(|_| promote(i, &set, &user, &incoming, &wanted, &existing, out, mode));
    if result.is_err() {
        // Nothing of this import is left behind: its incoming refs go.
        if let Ok(left) = refs_under(&user, &incoming) {
            let delete: String = left.keys().map(|r| format!("delete {r}\n")).collect();
            let _ = user.output_stdin(["update-ref", "--stdin"], delete.as_bytes());
        }
    }
    result
}

/// The code-out's pack (the file `pack`) into the scratch repository
/// (`index-pack --stdin --fix-thin`), its thin bases from the user's store:
/// a pack that does not index is `bad_pack`.
fn index_pack(scratch: &Scratch, pack: &Path) -> Result<(), BridgeError> {
    let mut child = scratch.git().spawn_piped(["index-pack", "--stdin", "--fix-thin"]).map_err(git_failed("git index-pack of the code-out"))?;
    let feeder = child.take_stdin().map(|mut stdin| {
        let pack = pack.to_path_buf();
        std::thread::spawn(move || -> std::io::Result<()> {
            let mut f = std::fs::File::open(pack)?;
            std::io::copy(&mut f, &mut stdin)?;
            Ok(())
        })
    });
    if let Some(mut stdout) = child.take_stdout() {
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
    }
    let fed = feeder.map(|f| f.join());
    child.finish().map_err(|e| BridgeError::WorkspaceFailed { code: refusal::BAD_PACK, message: format!("the code-out pack does not index: {e}") })?;
    if let Some(Ok(Err(e))) = fed {
        return Err(BridgeError::Io(e));
    }
    Ok(())
}

/// [`import`] after the fetch: the scans (`set`'s, by `mode`; the clean
/// cache saved once, after the last), then the one transaction.
#[allow(clippy::too_many_arguments)]
fn promote(i: &Import<'_>, set: &ScanSet, user: &GitRun, incoming: &str, wanted: &BTreeMap<String, String>, existing: &BTreeMap<String, String>, mut out: Imported, mode: ScanMode) -> Result<Imported, BridgeError> {
    use crate::bridge::workspace::blobscan::CleanCache;
    let WsKind::Git { object_format, .. } = &i.ws.kind;
    let mut cache = CleanCache::open(i.paths, &set.digest, *object_format);
    let haves = held_commits(user, *object_format, i.haves);
    let refs: Vec<(String, String)> = wanted.iter().map(|(suffix, id)| (format!("{BOX_REFS}{suffix}"), id.clone())).collect();
    let found = match mode {
        ScanMode::Batch => scan_batch(user, set, &mut cache, &refs, &haves, i.max_blob, *object_format)?,
        ScanMode::PerRef => scan_per_ref(user, set, &mut cache, &refs, &haves, i.max_blob, *object_format)?,
    };
    // Once, every scan having run to its end (S9 wrote the whole file after each ref's).
    if let Err(e) = cache.save() {
        tracing::warn!("scan: the clean-object cache was not written: {e}");
    }
    let mut moves: Vec<(String, String)> = Vec::new();
    for ((suffix, id), findings) in wanted.iter().zip(found) {
        let box_name = format!("{BOX_REFS}{suffix}");
        if findings.is_empty() {
            out.promoted.insert(box_name.clone(), id.clone());
            moves.push((box_name, id.clone()));
        } else {
            let name = format!("{BOX_QUARANTINE_REFS}{suffix}");
            out.quarantined.insert(name.clone(), id.clone());
            moves.push((name, id.clone()));
            out.findings.extend(findings);
        }
    }
    // The newest `keep_wip` snapshots stay, this fetch's own always among them. An older one
    // goes; one this fetch sent again is then not moved (one ref, one command in a transaction).
    let wip_prefix = format!("{BOX_REFS}wip/");
    let current = out.wip_ref.as_deref().and_then(box_ref_of);
    let mut snapshots: BTreeSet<String> = existing.keys().filter(|n| n.starts_with(&wip_prefix)).cloned().collect();
    snapshots.extend(moves.iter().map(|(n, _)| n.clone()).filter(|n| n.starts_with(&wip_prefix)));
    let excess = snapshots.len().saturating_sub(i.keep_wip);
    let gone: BTreeSet<String> = snapshots.into_iter().filter(|n| current.as_ref() != Some(n)).take(excess).collect();
    moves.retain(|(n, _)| !gone.contains(n));
    out.promoted.retain(|n, _| !gone.contains(n));
    // One transaction: the moves, the incoming refs and the snapshots past the cap gone.
    let mut stdin = String::from("start\n");
    for (name, id) in &moves {
        stdin.push_str(&format!("update {name} {id}\n"));
    }
    for r in refs_under(user, incoming)?.keys().chain(gone.iter().filter(|n| existing.contains_key(*n))) {
        stdin.push_str(&format!("delete {r}\n"));
    }
    stdin.push_str("prepare\ncommit\n");
    user.output_stdin(["update-ref", "--stdin"], stdin.as_bytes()).map_err(git_failed("git update-ref of the box refs"))?;
    out.tips = existing.clone();
    out.tips.extend(moves);
    out.tips.retain(|n, _| !gone.contains(n));
    Ok(out)
}

/// The haves `git`'s repository holds as commits (a tag of one counts), in
/// their order, by one `cat-file --batch-check` of each `<id>^{commit}` (S10
/// F4; S9 ran `workspace::holds_commit` once per have, up to `HAVES_MAX`). An
/// id of another format is no have; when the check cannot run, none is (the
/// listings then take the refs' whole history, as S9's did on a failed check).
fn held_commits(git: &GitRun, format: crate::wire::workspace::ObjectFormat, haves: &[String]) -> Vec<String> {
    let asked: Vec<&String> = haves.iter().filter(|h| format.is_id(h)).collect();
    if asked.is_empty() {
        return Vec::new();
    }
    let input: String = asked.iter().map(|h| format!("{h}^{{commit}}\n")).collect();
    let held = git.output_stdin(["cat-file", "--batch-check=%(objectname)"], input.as_bytes()).map(|out| String::from_utf8_lossy(&out).lines().map(|l| format.is_id(l)).collect::<Vec<bool>>());
    match held {
        Ok(held) if held.len() == asked.len() => asked.into_iter().zip(held).filter(|(_, h)| *h).map(|(id, _)| id.clone()).collect(),
        Ok(_) => {
            tracing::warn!("code-out: git cat-file answered another count of lines than haves asked: no haves");
            Vec::new()
        }
        Err(e) => {
            tracing::warn!("code-out: the haves could not be checked ({e}): no haves");
            Vec::new()
        }
    }
}

/// `rev-list --objects`' lines as listed objects: an id of `format`, and
/// the path after its first space when the line has one (a commit has none,
/// a root tree an empty one).
fn listing(bytes: &[u8], format: crate::wire::workspace::ObjectFormat) -> Vec<crate::bridge::workspace::pack::Listed> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|l| {
            let (oid, path) = match l.split_once(' ') {
                Some((o, p)) => (o, Some(p.to_string())),
                None => (l, None),
            };
            format.is_id(oid).then(|| crate::bridge::workspace::pack::Listed { id: oid.to_string(), path })
        })
        .collect()
}

/// One ref's own listing, S9's: `rev-list --objects <id> --not <haves…>`.
fn ref_listing(git: &GitRun, id: &str, haves: &[String], format: crate::wire::workspace::ObjectFormat) -> Result<Vec<crate::bridge::workspace::pack::Listed>, BridgeError> {
    let mut args = vec!["rev-list".to_string(), "--objects".into(), id.to_string(), "--not".into()];
    args.extend(haves.iter().cloned());
    let listed = git.output(&args).map_err(git_failed("git rev-list of a fetched ref"))?;
    Ok(listing(&listed, format))
}

/// The tree of each of `refs`' commits, in their order, and the Mac's
/// HEAD's (`None`: an unborn branch), by one `cat-file --batch-check`.
fn tip_trees(git: &GitRun, refs: &[(String, String)], format: crate::wire::workspace::ObjectFormat) -> Result<(Vec<String>, Option<String>), BridgeError> {
    let mut input: String = refs.iter().map(|(_, id)| format!("{id}^{{tree}}\n")).collect();
    input.push_str("HEAD^{tree}\n");
    let out = git.output_stdin(["cat-file", "--batch-check=%(objectname)"], input.as_bytes()).map_err(git_failed("git cat-file of the fetched refs' trees"))?;
    let text = String::from_utf8_lossy(&out);
    let lines: Vec<&str> = text.lines().collect();
    let unread = || BridgeError::WorkspaceFailed { code: refusal::GIT_FAILED, message: "git cat-file could not read the tree of a fetched ref".into() };
    let Some((head, trees)) = lines.split_last().filter(|(_, trees)| trees.len() == refs.len()) else { return Err(unread()) };
    if !trees.iter().all(|t| format.is_id(t)) {
        return Err(unread());
    }
    Ok((trees.iter().map(|t| (*t).to_string()).collect(), Some(*head).filter(|h| format.is_id(h)).map(str::to_string)))
}

/// S10 F4: the findings of each of `refs` (`(box name, commit)`), the new
/// objects of all of them scanned as one. One `rev-list --objects --stdin`
/// lists every tip's objects the Mac lacks (`haves` excluded), and one scan
/// reads that union ([`scan_listed`]: the cache not saved here, no finding's
/// place looked up). D8 reads each ref's settings from one walk of the tips'
/// trees ([`settings_of_trees`]): tree-based, never from the union, which
/// leaves out a blob the Mac holds (a permissive fixture of its history) that
/// the VM copied to `.claude/settings.json`. A union with no finding needs no
/// git run per ref. Only on one, S9's exact per-ref pass decides which refs
/// it concerns and where it is: each ref's own listing, then S9's scan of it
/// (its tree the label `locate` names a place by) wherever that listing
/// holds an object the union found dirty, one the union did not list (a
/// boundary of another ref's walk hid it there: the Mac holds it), or a path
/// that trips a rule. Each ref's findings: its objects', then its settings',
/// S9's order. So a ref is quarantined, with the same findings, wherever
/// S9's scan quarantined it, but for two cases S9 decided by its own walk
/// alone: an object the Mac holds already that the union left out, and a
/// whole path tripping a rule across its `/` at a path other than the one
/// the union listed its object at (each name of it is read either way).
/// S10 phase 4: the settings within the import's bounds (a walk past its
/// caps refuses the import; a settings blob over `max_blob` is
/// `blob-too-large`, never read; a tip's settings findings capped), and
/// appended as the per-ref pass appends them ([`extend_settings`]).
///
/// [`extend_settings`]: crate::bridge::workspace::blobscan::extend_settings
fn scan_batch(user: &GitRun, set: &ScanSet, cache: &mut crate::bridge::workspace::blobscan::CleanCache, refs: &[(String, String)], haves: &[String], max_blob: u64, format: crate::wire::workspace::ObjectFormat) -> Result<Vec<Vec<crate::bridge::workspace::blobscan::Finding>>, BridgeError> {
    use crate::bridge::workspace::blobscan::{extend_settings, scan_listed, settings_of_trees};
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    let tips: BTreeSet<&String> = refs.iter().map(|(_, id)| id).collect();
    let mut input = String::new();
    for id in tips {
        input.push_str(id);
        input.push('\n');
    }
    for h in haves {
        input.push('^');
        input.push_str(h);
        input.push('\n');
    }
    let listed = user.output_stdin(["rev-list", "--objects", "--stdin"], input.as_bytes()).map_err(git_failed("git rev-list of the fetched refs"))?;
    let union = listing(&listed, format);
    let scanned = scan_listed(user, &union, set, cache, max_blob, None)?;
    let (trees, head) = tip_trees(user, refs, format)?;
    let labelled: Vec<(String, String)> = refs.iter().zip(trees).map(|((name, _), tree)| (name.clone(), tree)).collect();
    let settings = settings_of_trees(user, set, &labelled, head.as_deref(), max_blob)?;
    let mut found = vec![Vec::new(); refs.len()];
    if !scanned.report.findings.is_empty() {
        let in_union: std::collections::HashSet<&str> = union.iter().map(|o| o.id.as_str()).collect();
        let trips = |p: &str| !p.is_empty() && !set.rules.scan_bytes(p.as_bytes()).is_empty();
        for ((name, id), at) in refs.iter().zip(found.iter_mut()) {
            let list = ref_listing(user, id, haves, format)?;
            if list.iter().any(|o| scanned.dirty.contains(&o.id) || !in_union.contains(o.id.as_str()) || o.path.as_deref().is_some_and(trips)) {
                *at = scan_listed(user, &list, set, cache, max_blob, Some(&[(name.clone(), format!("{id}^{{tree}}"))]))?.report.findings;
            }
        }
    }
    for (at, of_settings) in found.iter_mut().zip(settings) {
        extend_settings(at, of_settings);
    }
    Ok(found)
}

/// S9's scan of `refs`, one after another ([`import_per_ref`]): the Mac's
/// HEAD tree listed whole; then each ref's own listing, its scan (its tree
/// the label `locate` names a place by), its tree listed whole (`ls-tree
/// -r`) and D8 on its settings files, skipping a file whose blob HEAD holds
/// at that path: S10 phase 4, within the import's bounds as the batch reads
/// them ([`scan_settings_within`]: a blob over `max_blob` never read, a
/// ref's settings findings capped), appended alike ([`extend_settings`]).
/// The cache is not saved here.
///
/// [`scan_settings_within`]: crate::bridge::workspace::blobscan::scan_settings_within
/// [`extend_settings`]: crate::bridge::workspace::blobscan::extend_settings
fn scan_per_ref(user: &GitRun, set: &ScanSet, cache: &mut crate::bridge::workspace::blobscan::CleanCache, refs: &[(String, String)], haves: &[String], max_blob: u64, format: crate::wire::workspace::ObjectFormat) -> Result<Vec<Vec<crate::bridge::workspace::blobscan::Finding>>, BridgeError> {
    use crate::bridge::workspace::blobscan::{extend_settings, scan_listed, scan_settings_within, tree_entries, ScanReport, TreeEntry};
    // The Mac's HEAD tree: a settings file the VM did not change is not read again.
    let head_entries: BTreeMap<String, String> = match user.output(["rev-parse", "--verify", "--quiet", "HEAD^{tree}"]) {
        Ok(tree) => tree_entries(user, String::from_utf8_lossy(&tree).trim())?.into_iter().map(|e| (e.path, e.id)).collect(),
        Err(_) => BTreeMap::new(),
    };
    let unchanged = |e: &TreeEntry| head_entries.get(&e.path) == Some(&e.id);
    let mut found = Vec::with_capacity(refs.len());
    for (name, id) in refs {
        let list = ref_listing(user, id, haves, format)?;
        let tree = format!("{id}^{{tree}}");
        let mut findings = scan_listed(user, &list, set, cache, max_blob, Some(&[(name.clone(), tree.clone())]))?.report.findings;
        let entries = tree_entries(user, &tree)?;
        let mut d8 = ScanReport::default();
        scan_settings_within(user, &[(name.clone(), entries)], set, &unchanged, max_blob, &mut d8)?;
        extend_settings(&mut findings, d8.findings);
        found.push(findings);
    }
    Ok(found)
}

/// One code-out fetch (plan §7): `begin_fetch` (the workspace's fetch
/// lock, a real remote named `box` refused, the haves, the scratch); `POST
/// /codeout` with the haves ([`haves_of`]) into the scratch's file; then
/// `finish_fetch` ([`import`], the report, the workspace row and the
/// audit: `codeout_fetch` with `via` `codeout` and how many refs
/// [`credential_shaped`] kept out, never a name; `box_fetch_finding` per
/// quarantined ref). A 204 is nothing new. `box fetch --smart-http` is
/// [`fetch_smart_http`], between the same two. S11 (C.1.3): to a VM whose
/// recorded caps name `codeout_manifest_v1` ([`wants_manifest`]) the
/// request asks for the manifest when nothing is new
/// (`manifest_when_empty`); a 200 without a pack (the manifest line alone)
/// is then [`manifest_only`]'s, so the VM's fetch record follows its HEAD
/// and branch. A 204 stays nothing new (a 12.0 shim's answer to the flag).
pub async fn fetch<A: MicrovmApi, D: DataPlane, T: TokenSource>(ctx: &CodeoutCtx<A, D, T>, opts: FetchOpts) -> Result<FetchReport, BridgeError> {
    let begun = begin_fetch(ctx).await?;
    let (paths, vm) = (ctx.paths.clone(), ctx.target.vm_id.clone());
    let manifest_when_empty = blocking(move || wants_manifest(&paths, &vm)).await.unwrap_or(false);
    let req = CodeoutRequest { path: ctx.ws.vm_root.clone(), haves: begun.haves.clone(), wip: opts.wip, max_bytes: opts.max_bytes, manifest_when_empty };
    let dest = begun.pack();
    let x = Exchange { api: &*ctx.api, tokens: &*ctx.tokens, vm_id: &ctx.target.vm_id, port: CODE_PORT, cap: crate::wire::frame::CAP_WORKSPACE_V1, route: "POST /codeout", deadline: None, idempotent: false };
    let (reply, verdict) = exchange(&x, |t| {
        let (req, dest) = (&req, &dest);
        async move { ctx.dp.post_codeout(&ctx.target, &t, req, dest, opts.max_bytes).await }
    })
    .await?;
    let body = match (reply.status, verdict, reply.body) {
        (204, _, _) => return Ok(nothing_new(ctx, begun, Via::Codeout).await),
        (_, Verdict::Done, Some(body)) if body.pack_bytes == 0 => return manifest_only(ctx, begun, body.manifest, opts.wip, Via::Codeout).await,
        (_, Verdict::Done, Some(body)) => body,
        (status, _, _) => return Err(BridgeError::Protocol(format!("POST /codeout answered HTTP {status} where a pack was due"))),
    };
    finish_fetch(ctx, begun, Received { manifest: body.manifest, pack_bytes: body.pack_bytes, snapshot: opts.wip, head_held: false }, Via::Codeout).await
}

/// S11 (C.1.3): whether `vm`'s recorded caps (its `state/vms` row, as
/// `/health` last wrote them) name `codeout_manifest_v1`, so a code-out may
/// ask it for the manifest when nothing is new. An unreadable row, no row,
/// or no recorded caps: `false` (no flag, S10's request).
fn wants_manifest(paths: &Paths, vm: &str) -> bool {
    let row = crate::bridge::vm::registry::read_row(paths, vm).ok().flatten();
    row.and_then(|r| r.caps).is_some_and(|caps| caps.iter().any(|c| c == crate::wire::frame::CAP_CODEOUT_MANIFEST_V1))
}

/// S11 (C.1.3): a code-out whose answer holds the manifest and no pack (the
/// shim's manifest-only 200 to `manifest_when_empty`; a smart-HTTP fetch
/// whose listed tips the haves hold). Its tips must all be haves (the
/// helper's own rule, `all_had`), else `Protocol` (exit 8). When every ref
/// the import would take (past [`credential_shaped`], then [`box_refs`])
/// already sits at its commit in the workspace row's `fetched` and the VM's
/// fetch record holds the manifest's HEAD and branch
/// ([`rows::fetch_unchanged`]) and the snapshot the import would record, or
/// the import could not record that HEAD at all ([`no_pack_unchanged`]),
/// nothing is new: [`nothing_new`], no git run.
/// Otherwise [`finish_fetch`] imports it without a pack ([`import`] takes a
/// 0-byte or absent pack file when every wanted commit is a have), and the
/// record moves through the refs it promoted, as after any import; a box
/// tip another VM's fetch left there is not moved back or aside by it
/// ([`held_back`]), and with nothing else to move that is nothing new too,
/// unless the VM's record must still take a HEAD that box tip holds
/// already (F1-1: imported without a ref, the record moved).
/// The scratch directory and the lock go with `begun`.
async fn manifest_only<A, D, T>(ctx: &CodeoutCtx<A, D, T>, begun: Begun, mut manifest: CodeoutManifest, snapshot: bool, via: Via) -> Result<FetchReport, BridgeError> {
    if !all_had(&manifest, &begun.haves) {
        return Err(BridgeError::Protocol("POST /codeout: a code-out without a pack names a tip the Mac did not name".into()));
    }
    let (paths, cfg, ws, vm) = (ctx.paths.clone(), ctx.cfg.clone(), ctx.ws.clone(), ctx.target.vm_id.clone());
    let seen = manifest.clone();
    // Off the runtime's thread: the tripwires and the row are files, and only a fetch that is not nothing new runs
    // git. Anything unreadable is no shortcut and holds nothing back: the import decides.
    let plan = blocking(move || -> Option<Held> {
        let Ok(set) = ScanSet::load(&paths, &cfg, &ws) else { return Some(Held::default()) };
        let Ok(Some(row)) = rows::row_of(&paths, &ws) else { return Some(Held::default()) };
        let (checkout, by_name) = (Checkout::of(&seen), taken_refs_of(&seen.refs, &set.rules));
        let taken = |held: &BTreeSet<String>| -> BTreeMap<String, String> { by_name.iter().filter(|(_, (r, _))| !held.contains(r)).map(|(name, (_, id))| (name.clone(), id.clone())).collect() };
        if no_pack_unchanged(&row, &vm, &taken(&BTreeSet::new()), &checkout, snapshot) {
            return None;
        }
        let held = held_back(&GitRun::mac(&ws.root), &row, &vm, &by_name, &checkout, snapshot);
        // A HEAD held back where the box has it already still moves the record (F1-1): never nothing new.
        (held.refs.is_empty() || held.head || !no_pack_unchanged(&row, &vm, &taken(&held.refs), &checkout, snapshot)).then_some(held)
    })
    .await
    .unwrap_or_else(|_| Some(Held::default()));
    let Some(held) = plan else { return Ok(nothing_new(ctx, begun, via).await) };
    manifest.refs.retain(|r, _| !held.refs.contains(r));
    finish_fetch(ctx, begun, Received { manifest, pack_bytes: 0, snapshot, head_held: held.head }, via).await
}

/// What [`held_back`] keeps out of an import without a pack: the VM refs, and
/// whether the ref that checks out the VM's HEAD is among them because the
/// box tip there holds that HEAD already (F1-1), so the VM's fetch record
/// still takes the HEAD ([`Received::head_held`]).
#[derive(Debug, Default)]
struct Held {
    refs: BTreeSet<String>,
    head: bool,
}

/// S11 (C.1.3; the review's C2-R2 and C2-R3): whether an import of a
/// manifest without a pack would change nothing the row keeps, so the fetch
/// is nothing new (pure, no git run): every ref it takes (`taken`: box name
/// to commit) already sits at its commit among the row's box tips
/// (`WsRow::fetched`), and either the import cannot record the VM's HEAD
/// (the ref that checks it out is not taken at it: a branch under a name
/// the box namespace keeps, or one that looks like a credential: only the
/// record's `at` would move), or `vm`'s record holds the HEAD and branch
/// ([`rows::fetch_unchanged`]) and the snapshot the import would leave
/// there ([`record_holds`]).
fn no_pack_unchanged(row: &rows::WsRow, vm: &str, taken: &BTreeMap<String, String>, checkout: &Checkout, snapshot: bool) -> bool {
    if !taken_at(taken, &checkout.head_ref(), &checkout.head) {
        return taken.iter().all(|(name, id)| row.fetched.get(name) == Some(id));
    }
    rows::fetch_unchanged(row, vm, taken, &checkout.head, checkout.branch.as_deref()) && record_holds(row, vm, taken, checkout, snapshot)
}

/// Whether `taken` (box name to commit) takes `vm_ref` at `id`.
fn taken_at(taken: &BTreeMap<String, String>, vm_ref: &str, id: &str) -> bool {
    box_ref_of(vm_ref).is_some_and(|name| taken.get(&name).is_some_and(|got| got == id))
}

/// Whether `vm`'s fetch record in `row` already holds what an import of
/// `checkout` taking `taken` would write there ([`fetch_record`],
/// [`rows::note_fetch`]): its HEAD and branch, and its snapshot: the
/// manifest's when the import takes it (none: a clean worktree, or one kept
/// out), when the fetch asked for one (`snapshot`) or the manifest names
/// one; else the record's own, which a fetch that said nothing of the
/// worktree keeps at the same HEAD.
fn record_holds(row: &rows::WsRow, vm: &str, taken: &BTreeMap<String, String>, checkout: &Checkout, snapshot: bool) -> bool {
    let wip = checkout.wip.as_ref().filter(|(r, id)| taken_at(taken, r, id)).map(|(_, id)| id);
    let record = row.vm.get(vm).and_then(|e| e.fetched.as_ref());
    record.is_some_and(|f| f.head == checkout.head && f.branch == checkout.branch && ((!snapshot && wip.is_none()) || f.wip.as_ref() == wip))
}

/// S11 (the review's C2-R1): the VM refs of a manifest without a pack whose
/// import would move a box tip that another VM's fetch left there back or
/// aside: their box tip (`WsRow::fetched`) is another commit, not an
/// ancestor of theirs (`merge-base --is-ancestor`, in the Mac's repository,
/// `user`). S10's 204 moved nothing, and moving it would make the other
/// VM's next code-out send again what the box held. Never held back: this
/// fetch's snapshot; a ref whose box tip the VM's own record names on that
/// branch (its own earlier promotion, moved back since); and the ref that
/// checks out the VM's HEAD when its record does not hold what the import
/// would write there ([`record_holds`]), so the record still follows the
/// VM, unless that box tip holds the HEAD already (F1-1: another VM's
/// commits on it, a VM with no record yet idle at the seeded commit): then
/// it is held back too, nothing of this VM is lost, and `Held::head` says
/// so, for the record to take the HEAD all the same. A ref git cannot tell
/// of is not held back: the import decides.
fn held_back(user: &GitRun, row: &rows::WsRow, vm: &str, by_name: &BTreeMap<String, (String, String)>, checkout: &Checkout, snapshot: bool) -> Held {
    let all: BTreeMap<String, String> = by_name.iter().map(|(name, (_, id))| (name.clone(), id.clone())).collect();
    let record = row.vm.get(vm).and_then(|e| e.fetched.as_ref());
    let own = record.and_then(|f| box_ref_of(&Checkout { head: f.head.clone(), branch: f.branch.clone(), wip: None }.head_ref()).map(|name| (name, f.head.as_str())));
    let follows = !record_holds(row, vm, &all, checkout, snapshot);
    let mut held = Held::default();
    for (name, (vm_ref, id)) in by_name {
        let Some(tip) = row.fetched.get(name).filter(|tip| *tip != id) else { continue };
        let snapshot_ref = checkout.wip.as_ref().is_some_and(|(w, _)| w == vm_ref);
        let own_earlier = own.as_ref().is_some_and(|(n, head)| n == name && head == tip);
        if snapshot_ref || own_earlier {
            continue;
        }
        if follows && *vm_ref == checkout.head_ref() && *id == checkout.head {
            if user.output(["merge-base", "--is-ancestor", id.as_str(), tip.as_str()]).is_ok() {
                held.refs.insert(vm_ref.clone());
                held.head = true;
            }
            continue;
        }
        if let Err(crate::gitrun::GitError::Failed { code: Some(1), .. }) = user.output(["merge-base", "--is-ancestor", tip.as_str(), id.as_str()]) {
            held.refs.insert(vm_ref.clone());
        }
    }
    held
}

/// `box fetch --smart-http` (S9 plan §2, §4.3): [`fetch`] through git
/// smart-HTTP v2 (`gitsmart::Client`) in place of `POST /codeout`, between
/// the same `begin_fetch` and `finish_fetch`. The advertisement (v2, the
/// Mac's object format) and `ls-refs` (the four prefixes) give the VM's refs
/// as a code-out manifest (`gitsmart::manifest_of`, the helper's rules); a
/// ref [`credential_shaped`] keeps out, or one without a box name
/// ([`box_refs`]), is never wanted ([`wants_of`]). Every listed tip among
/// the haves, the helper's rule for its 204 (`all_had`), asks for no pack:
/// S11 (C.1.3) takes that listing as a manifest without one
/// ([`manifest_only`]: nothing new, or the record moved by an import
/// without a pack); a ref kept out counts there too (its tip is never a
/// have), so [`import`] then counts or names it, as after a code-out. Else `fetch` brings the
/// wants' pack (thin against the haves, at most `opts.max_bytes`), and
/// [`import`] takes it as it takes a code-out's, its commit-only rule
/// leaving out (counted) a ref it takes whose object the pack shows to be a
/// tree or a blob, which `ls-refs` cannot tell from a commit. No `fetch`
/// ever wants nothing: with every ref kept out, the import reads no pack,
/// so none is asked for (the VM's http-backend answers a fetch without a
/// want with its head alone, a cut answer: G1). No snapshot: the VM's
/// uncommitted work comes through `POST /codeout` only (`--wip`, refused
/// here). The audit's `via` is `smart-http`.
pub async fn fetch_smart_http<A: MicrovmApi, D: crate::bridge::gitsmart::GitHttp, T: TokenSource>(ctx: &CodeoutCtx<A, D, T>, opts: FetchOpts) -> Result<FetchReport, BridgeError> {
    use crate::bridge::gitsmart::{manifest_of, Client};
    if opts.wip {
        return Err(BridgeError::Config("a smart-HTTP fetch takes no snapshot of the VM's uncommitted work: box fetch --wip goes through POST /codeout".into()));
    }
    let begun = begin_fetch(ctx).await?;
    let WsKind::Git { object_format, .. } = &ctx.ws.kind;
    let client = Client { api: &*ctx.api, tokens: &*ctx.tokens, git: &*ctx.dp, target: &ctx.target };
    let advert = client.advertise(*object_format).await?;
    let manifest = manifest_of(&client.ls_refs(&advert).await?, advert.object_format)?;
    let wants = wants_of(&manifest, &ScanSet::load(&ctx.paths, &ctx.cfg, &ctx.ws)?.rules);
    if all_had(&manifest, &begun.haves) {
        // S11 (C.1.3): the listing is the manifest, so the record follows the VM's HEAD and branch.
        return manifest_only(ctx, begun, manifest, false, Via::SmartHttp).await;
    }
    if wants.is_empty() {
        // Every ref kept out: the import takes none and reads no pack, so none is asked for.
        return finish_fetch(ctx, begun, Received { manifest, pack_bytes: 0, snapshot: false, head_held: false }, Via::SmartHttp).await;
    }
    let pack_bytes = client.fetch_pack(&advert, &wants, &begun.haves, &begun.pack(), opts.max_bytes).await?;
    finish_fetch(ctx, begun, Received { manifest, pack_bytes, snapshot: false, head_held: false }, Via::SmartHttp).await
}

/// Whether every tip `manifest` lists is one of `haves`: the helper's rule
/// for nothing new (its 204: every tip among the haves it holds, so its pack
/// would hold no object). A ref [`import`] keeps out counts too.
fn all_had(manifest: &CodeoutManifest, haves: &[String]) -> bool {
    manifest.refs.values().all(|id| haves.contains(id))
}

/// The types of `ids` in `git`'s repository (`cat-file --batch-check`: the
/// pack [`import`] indexed, and through the alternates the Mac's store),
/// each by its id; an object not there is left out.
fn object_types(git: &GitRun, ids: &BTreeSet<&String>) -> Result<BTreeMap<String, String>, BridgeError> {
    let asked: String = ids.iter().map(|id| format!("{id}\n")).collect();
    let listed = git.output_stdin(["cat-file", "--batch-check=%(objectname) %(objecttype)"], asked.as_bytes()).map_err(git_failed("git cat-file of the code-out's refs"))?;
    Ok(String::from_utf8_lossy(&listed).lines().filter_map(|l| l.split_once(' ')).filter(|(_, t)| *t != "missing").map(|(id, t)| (id.to_string(), t.to_string())).collect())
}

/// The commits a smart-HTTP fetch asks the VM for: the ids of `manifest`'s
/// refs that [`import`] takes, once each in byte order. Never one of a ref
/// whose name [`credential_shaped`] finds (`rules`), nor of one without a
/// box name or whose box name another takes ([`box_refs`]): none of their
/// objects crosses.
#[must_use]
pub fn wants_of(manifest: &CodeoutManifest, rules: &Rules) -> Vec<String> {
    let ids: BTreeSet<String> = taken_of(&manifest.refs, rules).into_values().collect();
    ids.into_iter().collect()
}

/// The refs of a manifest (`refs`: VM ref to commit) that [`import`] takes
/// before it reads any object, as `import_with` takes them: past
/// [`credential_shaped`] (`rules`), then [`box_refs`]; each box name to its
/// commit.
fn taken_of(refs: &BTreeMap<String, String>, rules: &Rules) -> BTreeMap<String, String> {
    taken_refs_of(refs, rules).into_iter().map(|(name, (_, id))| (name, id)).collect()
}

/// [`taken_of`], each box name to its VM ref and commit.
fn taken_refs_of(refs: &BTreeMap<String, String>, rules: &Rules) -> BTreeMap<String, (String, String)> {
    let shown: BTreeMap<String, String> = refs.iter().filter(|(r, _)| !credential_shaped(r, rules)).map(|(r, id)| (r.clone(), id.clone())).collect();
    let (taken, _) = box_refs(&shown);
    taken.into_iter().filter_map(|(name, vm_ref)| shown.get(&vm_ref).map(|id| (name, (vm_ref, id.clone())))).collect()
}

/// How a fetch reached the VM: the `codeout_fetch` audit row's `via`, and
/// `box fetch --json`'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// `POST /codeout` (S8): the per-result trigger's and plain `box fetch`'s.
    Codeout,
    /// Git smart-HTTP v2 (S9): `box fetch --smart-http` ([`fetch_smart_http`]).
    SmartHttp,
}

impl Via {
    /// `codeout` or `smart-http`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Via::Codeout => "codeout",
            Via::SmartHttp => "smart-http",
        }
    }
}

/// A fetch begun ([`begin_fetch`]): the workspace's fetch lock, held to its
/// end; when it began; the haves; the scratch directory its pack lands in
/// ([`Begun::pack`]), which goes with it.
pub(crate) struct Begun {
    lock: crate::bridge::vm::lock::FlockGuard,
    started: std::time::Instant,
    haves: Vec<String>,
    scratch: Scratch,
}

impl Begun {
    /// Where the VM's pack is written, in the scratch directory.
    fn pack(&self) -> std::path::PathBuf {
        self.scratch.dir().join("codeout.pack")
    }
}

/// What the VM sent a fetch: its manifest (checked) and the pack's bytes in [`Begun::pack`].
pub(crate) struct Received {
    pub manifest: CodeoutManifest,
    pub pack_bytes: u64,
    /// S10 (L7): the fetch asked for a snapshot of the VM's uncommitted work
    /// (`--wip`), so the manifest's snapshot, or none, is what its worktree
    /// held; without one (`box fetch` without `--wip`, a smart-HTTP fetch)
    /// the fetch said nothing of the worktree ([`rows::note_fetch`]).
    pub snapshot: bool,
    /// S11 (F1-1): an import without a pack held back the ref that checks out
    /// the manifest's HEAD because its box tip holds that commit already
    /// ([`held_back`]): the record takes the HEAD, branch and snapshot as if
    /// that ref were promoted.
    pub head_held: bool,
}

/// Milliseconds since `started`.
fn ms_since(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// A fetch's start, either mode's (S9 §4.3): the workspace's fetch lock
/// (at most [`FETCH_LOCK_BUDGET`]); a real remote named `box` refused (its
/// `refs/remotes/box/*` would be the code-out's); the haves ([`haves_of`]:
/// the Mac's HEAD, the VM's seeded head, the box tips); a scratch directory
/// under `state/tmp` for the pack.
pub(crate) async fn begin_fetch<A, D, T>(ctx: &CodeoutCtx<A, D, T>) -> Result<Begun, BridgeError> {
    let started = std::time::Instant::now();
    let lock = crate::bridge::vm::lock::lock_exclusive(&ctx.paths.workspace_fetch_lock(&ctx.ws.slug), FETCH_LOCK_BUDGET, "the workspace's fetch lock").await?;
    let (paths, ws) = (ctx.paths.clone(), ctx.ws.clone());
    let vm = ctx.target.vm_id.clone();
    let (haves, scratch) = blocking(move || -> Result<(Vec<String>, Scratch), BridgeError> {
        let user = GitRun::mac(&ws.root);
        if !refs_or_none(&user, &["config", "--get-regexp", r"^remote\.box\."])?.is_empty() {
            return Err(BridgeError::Config(format!("{} has a git remote named box: its refs/remotes/box/* would be the code-out's (git remote rename box <other>)", ws.root.display())));
        }
        let head = user.output(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]).ok().map(|o| String::from_utf8_lossy(&o).trim().to_string());
        let seeded = rows::seeded_head(&paths, &ws, &vm);
        let tips = refs_under(&user, BOX_REFS)?;
        let WsKind::Git { common_dir, object_format, .. } = &ws.kind;
        let scratch = Scratch::new(&paths, "fetch", &common_dir.join("objects"), *object_format)?;
        Ok((haves_of(head.as_deref(), seeded.as_deref(), &tips), scratch))
    })
    .await??;
    Ok(Begun { lock, started, haves, scratch })
}

/// A fetch's end, either mode's (S9 §4.3): the pack [`import`]ed off the
/// runtime's thread (the scratch directory then removed); the report, which
/// names what was skipped, kept out, not snapshotted or quarantined; the
/// workspace row and the audit ([`record_fetch`], `via`); then the fetch
/// lock let go. S10 (L7): the manifest's HEAD, branch and snapshot go to
/// the VM's fetch record ([`fetch_record`]), the snapshot's first parent
/// read in the Mac's repository right after the import, when it was
/// promoted; a fetch that asked for no snapshot keeps the record's snapshot
/// at the same HEAD (`Received::snapshot`).
pub(crate) async fn finish_fetch<A, D, T>(ctx: &CodeoutCtx<A, D, T>, begun: Begun, received: Received, via: Via) -> Result<FetchReport, BridgeError> {
    let dest = begun.pack();
    let Begun { lock, started, haves, scratch } = begun;
    let Received { manifest, pack_bytes, snapshot, head_held } = received;
    let wip_skipped = manifest.wip_skipped.clone();
    let checkout = Checkout::of(&manifest);
    let (paths, cfg, ws) = (ctx.paths.clone(), ctx.cfg.clone(), ctx.ws.clone());
    let keep = cfg.seed.keep_wip_refs as usize;
    let max_blob = u64::from(cfg.seed.max_blob_mib) * MIB;
    let seen = checkout.clone();
    let (imported, wip_parent) = blocking(move || -> Result<(Imported, Option<String>), BridgeError> {
        let imported = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &dest, haves: &haves, max_blob, keep_wip: keep });
        drop(scratch);
        let imported = imported?;
        let parent = seen.promoted_wip(&imported).and_then(|wip| first_parent(&GitRun::mac(&ws.root), wip));
        Ok((imported, parent))
    })
    .await??;
    let mut notes: Vec<String> = imported.skipped.iter().map(|s| format!("skipped {s}")).collect();
    if imported.hidden > 0 {
        notes.push(hidden_note(imported.hidden));
    }
    if imported.not_commits > 0 {
        notes.push(not_commit_note(imported.not_commits));
    }
    if let Some(why) = &wip_skipped {
        notes.push(format!("no snapshot of the VM's uncommitted work: {why}"));
    }
    if !imported.findings.is_empty() {
        notes.push(format!("quarantined: {}", crate::bridge::workspace::blobscan::finding_lines(&imported.findings).replace('\n', "; ")));
    }
    let report = FetchReport {
        at: rfc3339_utc(unix_now()),
        ok: true,
        promoted: imported.promoted.clone(),
        quarantined: imported.quarantined.clone(),
        wip_ref: imported.wip_ref.clone(),
        bytes: pack_bytes,
        ms: ms_since(started),
        note: (!notes.is_empty()).then(|| notes.join("; ")),
    };
    let fetched = fetch_record(&checkout, &imported, wip_parent.as_deref(), unix_now(), head_held);
    record_fetch(ctx, &report, &imported, via, fetched, snapshot).await;
    drop(lock);
    Ok(report)
}

/// A fetch with nothing new (the code-out's 204; a smart-HTTP fetch whose
/// listed tips the haves hold): its report and its `codeout_fetch` row; S10
/// (L7): the VM's fetch record says when it ended, when it has one
/// (`rows::refresh_fetch`, off the runtime's thread, best effort); the
/// scratch directory and the lock go with `begun`.
async fn nothing_new<A, D, T>(ctx: &CodeoutCtx<A, D, T>, begun: Begun, via: Via) -> FetchReport {
    let report = FetchReport { at: rfc3339_utc(unix_now()), ok: true, ms: ms_since(begun.started), ..FetchReport::default() };
    let (paths, ws, vm, now) = (ctx.paths.clone(), ctx.ws.clone(), ctx.target.vm_id.clone(), unix_now());
    if let Err(e) = rows::write_off_thread(move || rows::refresh_fetch(&paths, &ws, &vm, now)).await {
        tracing::info!(vm = %ctx.target.vm_id, "code-out: the VM's fetch record not refreshed: {e}");
    }
    audit(&ctx.paths, audit_event::CODEOUT_FETCH, &[("vm", ctx.target.vm_id.clone()), ("via", via.word().into()), ("outcome", "nothing_new".into()), ("ms", report.ms.to_string())]);
    report
}

/// What a code-out's manifest says of the VM's checkout (S10 L7), for its
/// fetch record: its HEAD, the branch checked out (`None`: detached), and
/// the snapshot this fetch asked for, by its ref and commit. VM-chosen
/// names, which the record takes only through refs the import promoted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Checkout {
    head: String,
    branch: Option<String>,
    wip: Option<(String, String)>,
}

impl Checkout {
    fn of(manifest: &CodeoutManifest) -> Checkout {
        let wip = manifest.wip_ref.as_ref().and_then(|w| manifest.refs.get(w).map(|id| (w.clone(), id.clone())));
        Checkout { head: manifest.head.clone(), branch: manifest.branch.clone(), wip }
    }

    /// The ref that checks the HEAD out: the branch's, or `HEAD` when detached.
    fn head_ref(&self) -> String {
        self.branch.as_ref().map_or_else(|| "HEAD".to_string(), |b| format!("{HEADS_PREFIX}{b}"))
    }

    /// Whether `imported` promoted `vm_ref` at `id`: its box name moved
    /// there (a name the import took, so never one [`credential_shaped`]
    /// keeps out), not quarantined.
    fn promoted(imported: &Imported, vm_ref: &str, id: &str) -> bool {
        box_ref_of(vm_ref).is_some_and(|name| imported.promoted.get(&name).is_some_and(|got| got == id))
    }

    /// The snapshot's commit, when `imported` promoted it under the ref the
    /// import kept ([`Imported::wip_ref`]).
    fn promoted_wip<'a>(&'a self, imported: &Imported) -> Option<&'a str> {
        let (wip_ref, id) = self.wip.as_ref()?;
        (imported.wip_ref.as_deref() == Some(wip_ref.as_str()) && Checkout::promoted(imported, wip_ref, id)).then_some(id.as_str())
    }
}

/// The first parent of `commit` in `git`'s repository (`rev-parse
/// <commit>^1`); `None` for a root commit, or when git cannot tell.
fn first_parent(git: &GitRun, commit: &str) -> Option<String> {
    let out = git.output(["rev-parse", "--verify", "--quiet", &format!("{commit}^1")]).ok()?;
    Some(String::from_utf8_lossy(&out).trim().to_string()).filter(|p| !p.is_empty())
}

/// The fetch record of the VM a fetch reached (S10 L7, plans/s10-contracts.md
/// §6.3): ids the import promoted, never refs (another VM's fetch can move
/// `box/*`). Its HEAD, only when this fetch promoted the ref that checks it
/// out there (the branch's box ref, or `box/HEAD` when detached), with that
/// branch; the snapshot this fetch made, only when it was promoted too and
/// its first parent (`wip_parent`, read in the Mac's repository) is that
/// HEAD (tree the worktree, parents the HEAD and the index commit: what a
/// seed carries uncommitted), with its ref for the logs. `None` when the
/// HEAD was not promoted (quarantined, kept out, skipped): the VM's record
/// then says only when this fetch ended ([`rows::note_fetch`]).
///
/// S11 (F1-1): with `head_held` (an import without a pack held the HEAD's
/// ref back because its box tip holds that commit, a have, already) the
/// HEAD and branch are recorded as if that ref were promoted.
fn fetch_record(checkout: &Checkout, imported: &Imported, wip_parent: Option<&str>, at: u64, head_held: bool) -> Option<rows::VmFetchRow> {
    if !head_held && !Checkout::promoted(imported, &checkout.head_ref(), &checkout.head) {
        return None;
    }
    let wip = checkout.promoted_wip(imported).filter(|_| wip_parent == Some(checkout.head.as_str()));
    let wip_ref = wip.and(checkout.wip.as_ref().map(|(r, _)| r.clone()));
    Some(rows::VmFetchRow { at, head: checkout.head.clone(), branch: checkout.branch.clone(), wip: wip.map(str::to_string), wip_ref })
}

/// `git <args>`' lines, none when it exits 1 (`config --get-regexp` without a match).
fn refs_or_none(git: &GitRun, args: &[&str]) -> Result<Vec<String>, BridgeError> {
    match git.output(args) {
        Ok(out) => Ok(String::from_utf8_lossy(&out).lines().map(str::to_string).collect()),
        Err(crate::gitrun::GitError::Failed { code: Some(1), .. }) => Ok(Vec::new()),
        Err(e) => Err(git_failed("git config")(e)),
    }
}

/// The workspace row (off the runtime's thread, within `rows::ROWS_WAIT`)
/// and the audit of one fetch (best effort), `via` the way it reached the VM.
/// S10 (L7): the VM's own fetch record in the row (`WsRow.vm[<vm>].fetched`,
/// [`rows::note_fetch`]): `fetched` ([`fetch_record`]), else only when it
/// ended; `snapshot`: the fetch asked for one (`Received::snapshot`).
async fn record_fetch<A, D, T>(ctx: &CodeoutCtx<A, D, T>, report: &FetchReport, imported: &Imported, via: Via, fetched: Option<rows::VmFetchRow>, snapshot: bool) {
    let now = unix_now();
    let newest_wip = report.promoted.keys().filter(|n| n.starts_with(&format!("{BOX_REFS}wip/"))).max().cloned();
    let (paths, ws, vm, tips) = (ctx.paths.clone(), ctx.ws.clone(), ctx.target.vm_id.clone(), imported.tips.clone());
    let found: Vec<rows::FindingRow> = imported.findings.iter().map(|f| rows::FindingRow { location: f.location.clone(), object: f.object.clone(), rule: f.rule.clone(), key: f.key.clone(), at: now }).collect();
    let result = rows::write_off_thread(move || {
        rows::update(&paths, &ws, |row| {
            row.last_fetch_at = Some(now);
            rows::note_fetch(row, &vm, fetched, now, snapshot);
            row.last_fetch_vm = Some(vm);
            if newest_wip.is_some() {
                row.last_wip = newest_wip;
            }
            row.fetched = tips;
            row.finding.extend(found);
        })
    })
    .await;
    if let Err(e) = result {
        voice::warn(&format!("the workspace row of {} was not written: {e}", ctx.ws.cwd.display()));
    }
    audit(
        &ctx.paths,
        audit_event::CODEOUT_FETCH,
        &[
            ("vm", ctx.target.vm_id.clone()),
            ("via", via.word().into()),
            ("outcome", if report.quarantined.is_empty() { "promoted" } else { "quarantined" }.into()),
            ("promoted", report.promoted.len().to_string()),
            ("quarantined", report.quarantined.len().to_string()),
            ("hidden", imported.hidden.to_string()),
            ("bytes", report.bytes.to_string()),
            ("ms", report.ms.to_string()),
        ],
    );
    let rules: BTreeSet<&str> = imported.findings.iter().map(|f| f.rule.as_str()).collect();
    let rules = rules.into_iter().collect::<Vec<_>>().join(",");
    for name in report.quarantined.keys() {
        audit(&ctx.paths, audit_event::BOX_FETCH_FINDING, &[("vm", ctx.target.vm_id.clone()), ("ref", name.clone()), ("rules", rules.clone())]);
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod g2_tests {
    use super::*;
    use crate::wire::workspace::ObjectFormat;

    /// A smart-HTTP fetch wants what the import would take, each commit
    /// once: never a ref whose name looks like a credential (the
    /// setup-token's shape, built here), nor a branch the box namespace
    /// keeps (`wip`), so none of their objects crosses; `via`'s two words.
    #[test]
    fn wants_are_the_commits_of_the_refs_the_import_takes() {
        let rules = Rules::with_extras("", "tripwires").unwrap();
        let token = format!("{}-{}-oat01-{}", "sk", "ant", "Kq4_".repeat(20));
        let id = |n: u32| format!("{n:040x}");
        let refs = BTreeMap::from([
            ("refs/heads/main".to_string(), id(1)),
            ("refs/heads/dev".to_string(), id(1)),
            ("refs/heads/wip".to_string(), id(2)),
            (format!("refs/heads/x-{token}"), id(3)),
            ("refs/wip/20261018T080000Z-1".to_string(), id(4)),
            ("refs/ai-env/seed-wip".to_string(), id(5)),
        ]);
        let manifest = CodeoutManifest { v: 1, object_format: ObjectFormat::Sha1, refs, head: id(1), branch: Some("main".into()), wip_ref: None, wip_skipped: None };
        assert_eq!(manifest.check(), Ok(()));
        assert_eq!(wants_of(&manifest, &rules), [id(1), id(4), id(5)]);
        assert_eq!((Via::Codeout.word(), Via::SmartHttp.word()), ("codeout", "smart-http"));
    }
}

/// The pump's per-result code-out (§7), owned by the remote link
/// (`LinkFactory::on_result`): [`Self::request`] never blocks and coalesces
/// (one fetch running, at most one queued); fetches run as a task on the
/// runtime the trigger was spawned on (with a snapshot, `[seed].max_fetch_mib`),
/// their failures logged and audited, never fatal (at most one warning
/// every [`FAILURE_LINE_EVERY`]). With `capture_settings` the same task
/// keeps the session's settings (T8.7, `settings_capture`, never fatal):
/// the start capture once [`Self::set_session`] names a session (before any
/// fetch still queued), a turn's after each fetch of each session named when
/// it was asked for; a capture running as the trigger closes is given up at
/// once, never waited for inside the close budget. [`Self::watch`] hands
/// out what the session's closing suspend waits on ([`TriggerWatch`]). S10
/// (R1): [`Self::retail`] hands the VM the chain's next tail, as
/// non-blocking and coalescing as a fetch's request.
#[derive(Debug)]
pub struct CodeoutTrigger {
    shared: Arc<TriggerShared>,
    task: Option<tokio::task::JoinHandle<()>>,
}

/// What the trigger and its task share.
#[derive(Debug, Default)]
struct TriggerShared {
    state: std::sync::Mutex<TriggerState>,
    wake: tokio::sync::Notify,
    /// Every waiter woken once the trigger closes (a running capture gives up).
    closing: tokio::sync::Notify,
    /// Every waiter woken when the trigger may be done ([`TriggerWatch`]): it
    /// closed, its task ended a piece of work, or its task went.
    changed: tokio::sync::Notify,
}

#[derive(Debug, Default)]
struct TriggerState {
    /// A fetch was asked for since the last one started.
    pending: bool,
    /// The sessions named when that fetch was asked for, each once (a
    /// `/clear` may name another before it starts): each gets its turn's
    /// capture after it.
    pending_sessions: Vec<String>,
    closed: bool,
    session: Option<String>,
    /// The session named last has no start capture taken by this trigger yet.
    start_due: bool,
    /// The session named last has had no transcript step of its own yet (S9
    /// phase 4): its placeholder view, a tail URL, its subtree restored.
    begin_due: bool,
    /// S10 (R1): a tail was asked for ([`CodeoutTrigger::retail`]) since the
    /// task last handed one.
    retail_due: bool,
    /// The task runs a piece of work: a fetch and its turn's captures, or a
    /// start capture.
    busy: bool,
    /// The task's future is gone (it returned, or the close aborted it), or
    /// there never was one.
    over: bool,
    last: Option<FetchReport>,
    /// When the last failure was said.
    said_at: Option<std::time::Instant>,
}

impl TriggerShared {
    fn state(&self) -> std::sync::MutexGuard<'_, TriggerState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The task ended a piece of work (`over`: the task is gone).
    fn idle(&self, over: bool) {
        {
            let mut st = self.state();
            st.busy = false;
            st.over |= over;
        }
        self.changed.notify_waiters();
    }
}

/// What the session's closing suspend waits on (plan §11's close: the
/// code-out trigger's last fetch, or its [`CLOSE_WAIT`], then the suspend):
/// a fetch that reached the endpoint after SuspendMicrovm would wake the VM
/// again (the platform's auto-resume). Handed out by
/// [`CodeoutTrigger::watch`]; it holds the trigger's state, not its task.
#[derive(Debug, Clone)]
pub struct TriggerWatch {
    shared: Arc<TriggerShared>,
}

impl TriggerWatch {
    /// No fetch of the trigger's starts any more: it closed and its task
    /// runs nothing (a fetch running at the close ended, or was given up at
    /// `CLOSE_WAIT`; a queued one never starts), or its task is gone. One
    /// given up with its request already on its way may still reach the VM.
    /// A trigger that is merely idle is not done: a result the pump has still
    /// to see may ask for a fetch after the session's exit arrived.
    #[must_use]
    pub fn done(&self) -> bool {
        let st = self.shared.state();
        st.over || (st.closed && !st.busy)
    }

    /// S10 §D: no fetch is pending and none runs (nor a capture or a
    /// transcript step: the task is idle). A parking session parks only then,
    /// so no fetch reaches a parked VM.
    #[must_use]
    pub fn quiet(&self) -> bool {
        let st = self.shared.state();
        !st.pending && !st.busy
    }

    /// Until [`TriggerWatch::done`] (cancel-safe); the caller bounds it.
    pub async fn wait_done(&self) {
        loop {
            let changed = self.shared.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.done() {
                return;
            }
            changed.await;
        }
    }
}

/// The trigger's task's mark: its future gone (it returned, or the close
/// aborted it), the watch's wait is over.
struct TaskGone(Arc<TriggerShared>);

impl Drop for TaskGone {
    fn drop(&mut self) {
        self.0.idle(true);
    }
}

impl CodeoutTrigger {
    /// The trigger of one session, its task on the current runtime (none
    /// outside a runtime: every report then says so). With
    /// `ctx.transcript` (S9) the same task syncs the session's transcript to
    /// S3 after each fetch, `ctx.api` presigning.
    #[must_use]
    pub fn spawn<A: MicrovmApi + crate::bridge::s3::S3Sign + 'static, D: DataPlane + 'static, T: TokenSource + 'static>(ctx: CodeoutCtx<A, D, T>) -> CodeoutTrigger {
        let shared = Arc::new(TriggerShared::default());
        let task = match tokio::runtime::Handle::try_current() {
            Ok(rt) => Some(rt.spawn(run(ctx, shared.clone()))),
            Err(_) => {
                tracing::warn!("code-out: no runtime to fetch on; results fetch nothing");
                shared.state().over = true;
                None
            }
        };
        CodeoutTrigger { shared, task }
    }

    /// What the session's closing suspend waits on ([`TriggerWatch`]).
    #[must_use]
    pub fn watch(&self) -> TriggerWatch {
        TriggerWatch { shared: Arc::clone(&self.shared) }
    }

    /// Ask for a fetch (with a snapshot of the uncommitted work): returns at
    /// once; a request while one runs is queued, further ones coalesce. The
    /// session named now gets the turn's capture after that fetch.
    pub fn request(&self) {
        let mut st = self.shared.state();
        if self.task.is_none() {
            st.last = Some(FetchReport { at: rfc3339_utc(unix_now()), ok: false, note: Some("code-out: no runtime to fetch on".into()), ..FetchReport::default() });
            return;
        }
        st.pending = true;
        if let Some(id) = st.session.clone().filter(|id| !st.pending_sessions.contains(id)) {
            st.pending_sessions.push(id);
        }
        drop(st);
        self.shared.wake.notify_one();
    }

    /// The session's id (a `--resume`'s as its spawn goes out, the one the
    /// pump adopted from a `system/init` otherwise): the settings captures'
    /// quarantine directory. A session named for the first time, or another
    /// one (`/clear`), gets its start capture before any fetch still queued
    /// (`settings_capture::capture` keeps a start capture already on disk).
    pub fn set_session(&self, session_id: &str) {
        let mut st = self.shared.state();
        if st.session.as_deref() == Some(session_id) {
            return;
        }
        st.session = Some(session_id.to_string());
        st.start_due = true;
        st.begin_due = true;
        drop(st);
        self.shared.wake.notify_one();
    }

    /// The last fetch's report; `None` before any ended.
    #[must_use]
    pub fn last(&self) -> Option<FetchReport> {
        self.shared.state().last.clone()
    }

    /// S10 (R1): hand the VM the chain's next tail URL (the link calls it at
    /// every unpark, plans/s10-contracts.md §3.3): returns at once, as
    /// [`Self::request`] does, and coalesces (asked again before the task
    /// took it, it is one). The task lists the named session's tails and
    /// hands the one at the end of their chain (`SyncCtx::hand_fresh_tail`),
    /// before any fetch still queued, given up at once at the close. Nothing
    /// without a transcript sync (`ctx.transcript`), or before a session is
    /// named; the session's first transcript step hands one anyway.
    pub fn retail(&self) {
        if self.task.is_none() {
            return;
        }
        self.shared.state().retail_due = true;
        self.shared.wake.notify_one();
    }

    /// At the wrapper's close: no new fetch starts; a running one is waited
    /// for at most `within` ([`CLOSE_WAIT`]), then abandoned (logged): left to
    /// run to its end, which the process's exit may cut (its promotion is one
    /// transaction, so the box refs never move half-way, and what an import
    /// cut short leaves, its incoming refs and its scratch directories, the
    /// next import removes). S10 (D5): an abandoned fetch is no longer
    /// aborted, so the trigger is done ([`TriggerWatch`]) only once it ended:
    /// the closing suspend waits for it (within its bound), and no
    /// SuspendMicrovm goes out while its request may still reach the VM. The
    /// last report.
    pub async fn close(mut self, within: Duration) -> Option<FetchReport> {
        self.shared.state().closed = true;
        self.shared.wake.notify_one();
        self.shared.closing.notify_waiters();
        self.shared.changed.notify_waiters();
        if let Some(mut task) = self.task.take() {
            if tokio::time::timeout(within, &mut task).await.is_err() {
                tracing::info!(within_ms = u64::try_from(within.as_millis()).unwrap_or(u64::MAX), "code-out: the fetch still running at the close was given up (left to its end)");
            }
        }
        self.last()
    }
}

impl Drop for CodeoutTrigger {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// What the trigger's task does next.
enum Work {
    /// The start capture of this session (T8.7).
    Start(String),
    /// The first transcript step of this session (S9 phase 4,
    /// [`transcript_begin`]).
    Begin(String),
    /// S10 (R1): the next tail of this session's chain ([`CodeoutTrigger::retail`]).
    Retail(String),
    /// A fetch, then a turn's capture of each session it was asked for.
    Fetch(Vec<String>),
}

/// Until the trigger closes (at once when it already has).
async fn until_closed(shared: &TriggerShared) {
    loop {
        let notified = shared.closing.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if shared.state().closed {
            return;
        }
        notified.await;
    }
}

/// One settings capture of `session` (T8.7): never fatal (logged), and
/// given up at once when the trigger closes, so none ever runs inside the
/// wrapper's close budget.
async fn capture_session_settings<A, D: DataPlane, T: TokenSource>(ctx: &CodeoutCtx<A, D, T>, shared: &TriggerShared, session: &str, phase: crate::bridge::settings_capture::CapturePhase) {
    let capture = crate::bridge::settings_capture::capture(&*ctx.dp, &*ctx.tokens, &ctx.target, &ctx.paths, session, &ctx.ws.vm_root, phase);
    tokio::select! {
        biased;
        () = until_closed(shared) => tracing::info!(phase = phase.word(), "settings capture given up: the session closes"),
        got = capture => match got {
            Ok(written) => tracing::info!(phase = phase.word(), written, "settings captured"),
            Err(e) => tracing::info!(phase = phase.word(), "settings not captured: {e}"),
        },
    }
}

/// The first transcript step of a session the trigger is told of (S9 phase
/// 4), before any fetch still queued: a placeholder view when nothing is at
/// its path (`s3::sync::write_placeholder_view`: a chat closed before its
/// first sync is still listed), its subtree's files restored into the VM
/// (`workspace::transcript::restore_subtree`, out of P3's deadline), then a
/// tail URL (`hand_fresh_tail`: from 0 when S3 holds nothing of it, so
/// `/suspend` and `/terminate` push its bytes even before a sync). The
/// subtree goes first: the tail's listing of S3 (S10 R1) may wait up to its
/// own bound, and a short session would close before the subtree came.
/// Never fatal (logged), given up at once when the trigger closes.
async fn transcript_begin<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(ctx: &CodeoutCtx<A, D, T>, shared: &TriggerShared, sync: &crate::bridge::s3::TranscriptSync, rules: &crate::bridge::scan::Rules, session: &str) {
    let sctx = crate::bridge::s3::sync::SyncCtx { api: &*ctx.api, dp: &*ctx.dp, tokens: &*ctx.tokens, paths: &ctx.paths, target: &ctx.target, sync, rules, deadline: None };
    let begin = async {
        match crate::bridge::s3::sync::write_placeholder_view(sync, session, rules) {
            Ok(Some(outcome)) => tracing::info!(session, outcome = outcome.word(), "placeholder view"),
            Ok(None) => {}
            Err(e) => tracing::info!(session, "placeholder view not written: {e}"),
        }
        match crate::bridge::workspace::transcript::restore_subtree(&sctx, session).await {
            Ok(r) => tracing::info!(session, pulled = r.pulled, kept = r.kept, unnamed = r.unnamed, "transcript subtree restored"),
            Err(e) => {
                tracing::warn!(session, "transcript subtree not restored: {e}");
                voice::warn(&format!("the subagent and tool files of {session} were not restored into the VM: {e}"));
            }
        }
        sctx.hand_fresh_tail(session).await;
    };
    tokio::select! {
        biased;
        () = until_closed(shared) => tracing::info!(session, "transcript begin given up: the session closes"),
        () = begin => {}
    }
}

/// A fresh tail URL for `session` before its turn's fetch (S9 phase 4:
/// the bytes between a result and the sync that commits them always have
/// one), and at an unpark (S10 R1, [`CodeoutTrigger::retail`]): the chain's
/// next; given up at once when the trigger closes.
async fn tail_before_turn<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(ctx: &CodeoutCtx<A, D, T>, shared: &TriggerShared, sync: &crate::bridge::s3::TranscriptSync, rules: &crate::bridge::scan::Rules, session: &str) {
    let sctx = crate::bridge::s3::sync::SyncCtx { api: &*ctx.api, dp: &*ctx.dp, tokens: &*ctx.tokens, paths: &ctx.paths, target: &ctx.target, sync, rules, deadline: None };
    tokio::select! {
        biased;
        () = until_closed(shared) => {}
        () = sctx.hand_fresh_tail(session) => {}
    }
}

/// The transcript step of one session (S9), after its turn's fetch and
/// capture: one sync to S3 and its view (`s3::sync`), never fatal (logged),
/// given up at once when the trigger closes (what the last turn left is the
/// tail the shim pushes at `/suspend` or `/terminate`); each of its requests
/// keeps its own budget. Without its tripwires (`rules`) nothing is synced:
/// a view is never written unmasked.
async fn sync_transcript<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(ctx: &CodeoutCtx<A, D, T>, shared: &TriggerShared, sync: &crate::bridge::s3::TranscriptSync, rules: &crate::bridge::scan::Rules, session: &str) {
    let sctx = crate::bridge::s3::sync::SyncCtx { api: &*ctx.api, dp: &*ctx.dp, tokens: &*ctx.tokens, paths: &ctx.paths, target: &ctx.target, sync, rules, deadline: None };
    tokio::select! {
        biased;
        () = until_closed(shared) => tracing::info!(session, "transcript sync given up: the session closes"),
        got = sctx.sync_session(session) => match got {
            Ok(r) => tracing::info!(session, outcome = r.outcome(), committed = r.committed, files = r.files, "transcript synced"),
            Err(e) => {
                tracing::warn!(session, "transcript not synced: {e}");
                voice::warn(&format!("the transcript of {session} did not reach S3 this turn: {e}"));
            }
        },
    }
}

/// The trigger's task: a session's start capture once it is named, one
/// fetch per wake while asked (then a turn's capture, then with
/// `ctx.transcript` the transcript's sync), until closed; S10 (R1), with
/// `ctx.transcript`, the chain's next tail when [`CodeoutTrigger::retail`]
/// asked, before a fetch. Each piece of work
/// is `busy` from its taking (under the state's lock, so a close sees it or
/// none starts) to its end.
async fn run<A: MicrovmApi + crate::bridge::s3::S3Sign, D: DataPlane, T: TokenSource>(ctx: CodeoutCtx<A, D, T>, shared: Arc<TriggerShared>) {
    use crate::bridge::settings_capture::CapturePhase;
    let _gone = TaskGone(Arc::clone(&shared));
    // The view's tripwires, read once: without them no sync runs (a view is never written unmasked).
    let rules = match &ctx.transcript {
        Some(_) => match ScanSet::load(&ctx.paths, &ctx.cfg, &ctx.ws) {
            Ok(set) => Some(set.rules),
            Err(e) => {
                voice::warn(&format!("the session's transcript is not synced to S3: its tripwires do not load ({e})"));
                None
            }
        },
        None => None,
    };
    loop {
        let work = loop {
            {
                let mut st = shared.state();
                if st.closed {
                    return;
                }
                if std::mem::take(&mut st.start_due) && ctx.capture_settings {
                    if let Some(id) = st.session.clone() {
                        st.busy = true;
                        break Work::Start(id);
                    }
                }
                if std::mem::take(&mut st.begin_due) && ctx.transcript.is_some() && rules.is_some() {
                    if let Some(id) = st.session.clone() {
                        st.busy = true;
                        // S10 (R1): its tail is the chain's next already.
                        st.retail_due = false;
                        break Work::Begin(id);
                    }
                }
                // S10 (R1): an unpark's tail before any fetch still queued.
                if std::mem::take(&mut st.retail_due) && ctx.transcript.is_some() && rules.is_some() {
                    if let Some(id) = st.session.clone() {
                        st.busy = true;
                        break Work::Retail(id);
                    }
                }
                if st.pending {
                    st.pending = false;
                    st.busy = true;
                    // Asked for before any session was named: the session named now.
                    let mut asked = std::mem::take(&mut st.pending_sessions);
                    if asked.is_empty() {
                        asked.extend(st.session.clone());
                    }
                    break Work::Fetch(asked);
                }
            }
            shared.wake.notified().await;
        };
        let asked = match work {
            Work::Start(id) => {
                capture_session_settings(&ctx, &shared, &id, CapturePhase::Start).await;
                shared.idle(false);
                continue;
            }
            Work::Begin(id) => {
                if let (Some(sync), Some(rules)) = (&ctx.transcript, &rules) {
                    transcript_begin(&ctx, &shared, sync, rules, &id).await;
                }
                shared.idle(false);
                continue;
            }
            Work::Retail(id) => {
                if let (Some(sync), Some(rules)) = (&ctx.transcript, &rules) {
                    tail_before_turn(&ctx, &shared, sync, rules, &id).await;
                }
                shared.idle(false);
                continue;
            }
            Work::Fetch(asked) => asked,
        };
        // S9: a fresh tail URL for each asking session before the fetch, so the turn's bytes have one until its sync.
        if let (Some(sync), Some(rules)) = (&ctx.transcript, &rules) {
            for id in asked.iter().filter(|_| !shared.state().closed) {
                tail_before_turn(&ctx, &shared, sync, rules, id).await;
            }
        }
        // No fetch starts after the close: a close that came while the tails went (each given up at once) ends the
        // task here. S8's task started its fetch as it took the work, with nothing to wait for between.
        if shared.state().closed {
            return;
        }
        let report = match fetch(&ctx, FetchOpts::per_result(&ctx.cfg)).await {
            Ok(r) => r,
            Err(e) => {
                audit(&ctx.paths, audit_event::CODEOUT_FETCH, &[("vm", ctx.target.vm_id.clone()), ("outcome", "failed".into()), ("why", e.to_string())]);
                FetchReport { at: rfc3339_utc(unix_now()), ok: false, note: Some(format!("code-out: {e}")), ..FetchReport::default() }
            }
        };
        let closed = {
            let mut st = shared.state();
            let say = !report.ok || !report.quarantined.is_empty() || report.note.as_deref().is_some_and(|n| n.contains(HIDDEN_TAIL));
            if say && st.said_at.is_none_or(|t| t.elapsed() >= FAILURE_LINE_EVERY) {
                st.said_at = Some(std::time::Instant::now());
                voice::warn(&format!("code-out of {}: {}", ctx.target.vm_id, report.note.as_deref().unwrap_or("refs quarantined")));
            }
            tracing::info!(vm = %ctx.target.vm_id, ok = report.ok, promoted = report.promoted.len(), quarantined = report.quarantined.len(), "code-out fetch");
            st.last = Some(report);
            st.closed
        };
        // Each session whose result asked for this fetch, a queued one's too: a `/clear` before it started named the next session, whose start capture ran first.
        for id in asked.iter().filter(|_| ctx.capture_settings && !closed) {
            capture_session_settings(&ctx, &shared, id, CapturePhase::Turn).await;
        }
        // S9: then each such session's transcript to S3, and its view.
        if let (Some(sync), Some(rules)) = (&ctx.transcript, &rules) {
            for id in asked.iter().filter(|_| !shared.state().closed) {
                sync_transcript(&ctx, &shared, sync, rules, id).await;
            }
        }
        shared.idle(false);
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod c2_tests {
    use super::*;
    use crate::bridge::api::FakeMicrovmApi;
    use crate::bridge::dataplane::Unreached;
    use crate::bridge::workspace::Head;
    use crate::wire::redact::Secret;
    use crate::wire::workspace::ObjectFormat;

    const SESSION: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const VM1: &str = "microvm-00000000-0000-4000-8000-000000000001";
    const VM2: &str = "microvm-00000000-0000-4000-8000-000000000002";

    fn ws() -> WorkspaceRef {
        WorkspaceRef {
            cwd: "/w".into(),
            root: "/w".into(),
            vm_cwd: "/w".into(),
            vm_root: "/w".into(),
            slug: "-w".into(),
            kind: WsKind::Git { git_dir: "/w/.git".into(), common_dir: "/w/.git".into(), object_format: ObjectFormat::Sha1 },
            head: Head::Detached { sha: "a".repeat(40) },
            seed_branch: None,
        }
    }

    fn target(vm: &str) -> AgentTarget {
        AgentTarget { vm_id: vm.into(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false }
    }

    /// A fetch's context on `dir`'s bridge root, against `vm` (no request reaches it).
    fn ctx_of(dir: &Path, vm: &str) -> CodeoutCtx<FakeMicrovmApi, Unreached, Unreached> {
        CodeoutCtx {
            api: Arc::new(FakeMicrovmApi::new()),
            dp: Arc::new(Unreached),
            tokens: Arc::new(Unreached),
            paths: Paths::from_root_and_env(dir.to_path_buf(), None),
            cfg: Arc::new(BridgeConfig::default()),
            target: target(vm),
            ws: ws(),
            capture_settings: false,
            transcript: None,
        }
    }

    fn id(n: u32) -> String {
        format!("{n:040x}")
    }

    /// Box names (past `BOX_REFS`) to their commits.
    fn promoted(refs: &[(&str, String)]) -> BTreeMap<String, String> {
        refs.iter().map(|(name, id)| (format!("{BOX_REFS}{name}"), id.clone())).collect()
    }

    /// S10 (L7, plans/s10-contracts.md §6.3): each VM a fetch reaches keeps
    /// its own record in the workspace row (`WsRow.vm[<vm>].fetched`), of
    /// ids the import promoted only: the HEAD when the ref that checks it
    /// out was promoted at it (the branch's box ref, `box/HEAD` when
    /// detached), with that branch; the snapshot this fetch made when it was
    /// promoted too and its first parent is that HEAD, with its ref. A fetch
    /// whose HEAD was not promoted (quarantined) leaves the record's ids and
    /// dates it; a snapshot made before the HEAD moved, or one the import
    /// kept out, is no wip; a branch whose name looks like a credential is
    /// kept out by the import, so its HEAD is no promoted id and its name
    /// never reaches the row. A fetch that asked for no snapshot (`box
    /// fetch` without `--wip`, a smart-HTTP fetch) keeps the record's
    /// snapshot at the same HEAD; one that asked and got none (a clean
    /// worktree) records none.
    #[tokio::test]
    async fn record_fetch_keeps_promoted_ids_per_vm() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let report = FetchReport { at: rfc3339_utc(unix_now()), ok: true, ..FetchReport::default() };
        let record = |vm: &str| rows::row_of(&paths, &ws()).unwrap().and_then(|r| r.vm.get(vm).and_then(|e| e.fetched.clone()));
        let snapshot = "refs/wip/20261020T100000Z-1";
        // VM 1 on main: its HEAD and this fetch's snapshot (first parent the HEAD) promoted.
        let on_main = Checkout { head: id(1), branch: Some("main".into()), wip: Some((snapshot.into(), id(2))) };
        let imported = Imported { promoted: promoted(&[("main", id(1)), ("wip/20261020T100000Z-1", id(2))]), wip_ref: Some(snapshot.into()), ..Imported::default() };
        record_fetch(&ctx_of(dir.path(), VM1), &report, &imported, Via::Codeout, fetch_record(&on_main, &imported, Some(&id(1)), 100, false), true).await;
        let first = rows::VmFetchRow { at: 100, head: id(1), branch: Some("main".into()), wip: Some(id(2)), wip_ref: Some(snapshot.into()) };
        assert_eq!(record(VM1), Some(first.clone()));
        // VM 2, detached: its HEAD promoted as box/HEAD, its snapshot quarantined.
        let detached = Checkout { head: id(3), branch: None, wip: Some(("refs/wip/y".into(), id(4))) };
        let imported = Imported {
            promoted: promoted(&[("HEAD", id(3))]),
            quarantined: BTreeMap::from([(format!("{BOX_QUARANTINE_REFS}wip/y"), id(4))]),
            wip_ref: Some("refs/wip/y".into()),
            ..Imported::default()
        };
        record_fetch(&ctx_of(dir.path(), VM2), &report, &imported, Via::Codeout, fetch_record(&detached, &imported, Some(&id(3)), 200, false), true).await;
        assert_eq!(record(VM2), Some(rows::VmFetchRow { at: 200, head: id(3), branch: None, wip: None, wip_ref: None }));
        assert_eq!(record(VM1), Some(first.clone()), "each VM its own record");
        // VM 1's next HEAD quarantined: the ids it promoted before stay, dated by this fetch.
        let moved = Checkout { head: id(5), branch: Some("main".into()), wip: None };
        let imported = Imported { quarantined: BTreeMap::from([(format!("{BOX_QUARANTINE_REFS}main"), id(5))]), ..Imported::default() };
        assert_eq!(fetch_record(&moved, &imported, None, 300, false), None);
        record_fetch(&ctx_of(dir.path(), VM1), &report, &imported, Via::Codeout, None, true).await;
        let kept = record(VM1).expect("VM 1's record");
        assert_eq!((kept.head.as_str(), kept.wip.as_deref(), kept.branch.as_deref()), (id(1).as_str(), Some(id(2).as_str()), Some("main")));
        assert!(kept.at > 300, "dated by the last fetch: {}", kept.at);
        // A snapshot whose first parent is not the HEAD (made before a commit, sent again): the HEAD alone.
        let stale = Checkout { head: id(6), branch: Some("main".into()), wip: Some(("refs/wip/old".into(), id(7))) };
        let imported = Imported { promoted: promoted(&[("main", id(6)), ("wip/old", id(7))]), wip_ref: Some("refs/wip/old".into()), ..Imported::default() };
        assert_eq!(fetch_record(&stale, &imported, Some(&id(1)), 400, false), Some(rows::VmFetchRow { at: 400, head: id(6), branch: Some("main".into()), wip: None, wip_ref: None }));
        assert_eq!(fetch_record(&stale, &imported, None, 400, false).and_then(|f| f.wip), None, "no first parent read");
        // A branch whose name looks like a credential (the setup-token's shape, built here): the import kept it out.
        let token = format!("{}-{}-oat01-{}", "sk", "ant", "Kq4_".repeat(20));
        let hidden = Checkout { head: id(8), branch: Some(format!("x-{token}")), wip: None };
        let imported = Imported { promoted: promoted(&[("dev", id(8))]), hidden: 1, ..Imported::default() };
        let fetched = fetch_record(&hidden, &imported, None, 500, false);
        assert_eq!(fetched, None, "the ref that checks the HEAD out was not promoted");
        record_fetch(&ctx_of(dir.path(), VM2), &report, &imported, Via::Codeout, fetched, true).await;
        assert_eq!(record(VM2).map(|f| f.head), Some(id(3)), "VM 2's ids stay");
        let text = std::fs::read_to_string(paths.workspace_row("-w")).unwrap();
        assert!(!text.contains(&token), "no credential-shaped name in the row");
        // A snapshot ref the import kept out: no wip, no ref.
        let wip_hidden = Checkout { head: id(9), branch: Some("main".into()), wip: Some((format!("refs/wip/{token}"), id(10))) };
        let imported = Imported { promoted: promoted(&[("main", id(9))]), hidden: 1, ..Imported::default() };
        assert_eq!(fetch_record(&wip_hidden, &imported, Some(&id(9)), 600, false).map(|f| (f.head, f.wip, f.wip_ref)), Some((id(9), None, None)));
        // VM 1 fetched with no snapshot asked, its HEAD promoted at the same commit (another branch moved): it said
        // nothing of the worktree, so the record's snapshot stays; a snapshot asked and none made: none.
        let no_wip = Checkout { head: id(1), branch: Some("main".into()), wip: None };
        let imported = Imported { promoted: promoted(&[("main", id(1)), ("topic", id(11))]), ..Imported::default() };
        record_fetch(&ctx_of(dir.path(), VM1), &report, &imported, Via::SmartHttp, fetch_record(&no_wip, &imported, None, 700, false), false).await;
        assert_eq!(record(VM1), Some(rows::VmFetchRow { at: 700, ..first }), "the snapshot kept");
        record_fetch(&ctx_of(dir.path(), VM1), &report, &imported, Via::Codeout, fetch_record(&no_wip, &imported, None, 800, false), true).await;
        assert_eq!(record(VM1), Some(rows::VmFetchRow { at: 800, head: id(1), branch: Some("main".into()), wip: None, wip_ref: None }), "a clean worktree");
    }

    /// The snapshot's first parent, as the Mac's repository reads it after
    /// the import: none for a root commit, or an id the repository lacks.
    #[test]
    fn a_snapshots_first_parent_is_read_in_the_macs_repository() {
        let dir = tempfile::tempdir().unwrap();
        let git = GitRun::mac(dir.path());
        let run = |args: &[&str]| String::from_utf8_lossy(&git.output(args).unwrap_or_else(|e| panic!("git {args:?}: {e}"))).trim().to_string();
        run(&["init", "-q"]);
        let tree = run(&["write-tree"]);
        let commit = |parents: &[&str], msg: &str| {
            let mut args = vec!["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgSign=false", "commit-tree", tree.as_str()];
            for p in parents {
                args.extend(["-p", p]);
            }
            args.extend(["-m", msg]);
            run(&args)
        };
        let head = commit(&[], "head");
        let index = commit(&[&head], "index");
        let wip = commit(&[&head, &index], "wip");
        assert_eq!(first_parent(&git, &wip).as_deref(), Some(head.as_str()), "a snapshot's first parent: the HEAD it was made on");
        assert_eq!(first_parent(&git, &index).as_deref(), Some(head.as_str()));
        assert_eq!(first_parent(&git, &head), None, "a root commit");
        assert_eq!(first_parent(&git, &"0".repeat(40)), None, "an id the repository lacks");
    }

    /// S11 (F1-1): an import without a pack never moves a box tip back to a
    /// VM's HEAD that tip holds already, even when the VM's record does not
    /// hold that HEAD yet (no record: a VM idle at the seeded commit after
    /// another VM's commit moved `box/main`; or a record whose snapshot alone
    /// differs): the ref is held back with `Held::head`, and the record takes
    /// the HEAD all the same. A HEAD the tip lacks is still promoted for the
    /// record; one the record holds is held back as any other ref.
    #[test]
    fn a_head_the_box_tip_holds_already_is_held_back_and_still_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let git = GitRun::mac(dir.path());
        let run = |args: &[&str]| String::from_utf8_lossy(&git.output(args).unwrap_or_else(|e| panic!("git {args:?}: {e}"))).trim().to_string();
        run(&["init", "-q"]);
        let tree = run(&["write-tree"]);
        let commit = |parents: &[&str], msg: &str| {
            let mut args = vec!["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgSign=false", "commit-tree", tree.as_str()];
            for p in parents {
                args.extend(["-p", p]);
            }
            args.extend(["-m", msg]);
            run(&args)
        };
        let seeded = commit(&[], "seeded");
        let b_work = commit(&[&seeded], "B's work");
        let a_work = commit(&[&seeded], "A's own work");
        let main = format!("{BOX_REFS}main");
        let row = |record: Option<rows::VmFetchRow>| rows::WsRow {
            fetched: BTreeMap::from([(main.clone(), b_work.clone())]),
            vm: BTreeMap::from([(VM1.to_string(), rows::VmSeedRow { fetched: record, ..rows::VmSeedRow::default() })]),
            ..rows::WsRow::default()
        };
        let by_name = |id: &str| BTreeMap::from([(main.clone(), ("refs/heads/main".to_string(), id.to_string()))]);
        let at_seeded = Checkout { head: seeded.clone(), branch: Some("main".into()), wip: None };
        let on_main = |wip: Option<String>| rows::VmFetchRow { at: 1, head: seeded.clone(), branch: Some("main".into()), wip_ref: wip.as_ref().map(|_| "refs/wip/x".to_string()), wip };
        // No record yet, or one whose snapshot alone differs (a reverted edit): held back, the record follows.
        for record in [None, Some(on_main(Some(id(7))))] {
            let held = held_back(&git, &row(record.clone()), VM1, &by_name(&seeded), &at_seeded, true);
            assert_eq!((held.refs.into_iter().collect::<Vec<_>>(), held.head), (vec!["refs/heads/main".to_string()], true), "{record:?}");
        }
        // A record that holds it: held back as any other ref, nothing for the record.
        let held = held_back(&git, &row(Some(on_main(None))), VM1, &by_name(&seeded), &at_seeded, true);
        assert_eq!((held.refs.len(), held.head), (1, false));
        // A HEAD the box tip lacks (the VM's own commit beside B's): promoted, so the record follows, as before.
        let at_own = Checkout { head: a_work.clone(), branch: Some("main".into()), wip: None };
        let held = held_back(&git, &row(None), VM1, &by_name(&a_work), &at_own, true);
        assert!(held.refs.is_empty() && !held.head, "{held:?}");
        // The record of a HEAD held back so: its HEAD and branch, no ref promoted.
        assert_eq!(fetch_record(&at_seeded, &Imported::default(), None, 9, false), None);
        assert_eq!(fetch_record(&at_seeded, &Imported::default(), None, 9, true), Some(rows::VmFetchRow { at: 9, head: seeded.clone(), branch: Some("main".into()), wip: None, wip_ref: None }));
    }

    /// A VM that takes every tail URL it is handed (`POST /transcript/tail`,
    /// 204) and records its key and start; nothing else is served.
    #[derive(Default)]
    struct TailVm {
        handed: std::sync::Mutex<Vec<(String, u64)>>,
    }

    impl TailVm {
        fn handed(&self) -> Vec<(String, u64)> {
            self.handed.lock().unwrap().clone()
        }
    }

    impl TokenSource for TailVm {
        async fn token(&self, port: u16) -> Result<crate::bridge::api::AuthToken, BridgeError> {
            Ok(crate::bridge::api::AuthToken { headers: BTreeMap::new(), port, expires_at_unix: u64::MAX })
        }
    }

    impl DataPlane for TailVm {
        async fn seed_state(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &str) -> Result<crate::bridge::dataplane::DpReply<crate::wire::workspace::SeedState>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn put_seed(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &crate::wire::workspace::SeedQuery, _: &Path, _: u64) -> Result<crate::bridge::dataplane::DpReply<crate::wire::workspace::SeedReply>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn post_codeout(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &CodeoutRequest, _: &Path, _: u64) -> Result<crate::bridge::dataplane::DpReply<crate::bridge::dataplane::CodeoutBody>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn transcript_stat(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &str) -> Result<crate::bridge::dataplane::DpReply<crate::wire::workspace::TranscriptStat>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn get_settings(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &str) -> Result<crate::bridge::dataplane::DpReply<crate::wire::workspace::SettingsCapture>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn transcript_tail(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, req: &crate::wire::workspace::TranscriptTail) -> Result<crate::bridge::dataplane::DpReply<()>, BridgeError> {
            req.check().map_err(BridgeError::Config)?;
            self.handed.lock().unwrap().push((req.url.key().to_string(), req.from));
            Ok(crate::bridge::dataplane::DpReply::status(204))
        }
    }

    /// The trigger's context on `dir`'s bridge root with a transcript sync
    /// whose S3 nobody listens at (a request to it fails), the tails going
    /// to `vm`.
    fn tail_ctx(dir: &Path, vm: Arc<TailVm>) -> CodeoutCtx<FakeMicrovmApi, TailVm, TailVm> {
        use crate::bridge::s3::{S3Endpoint, S3Target, TranscriptSync, LAB_BUCKET, LAB_OWNER};
        let s3 = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab("127.0.0.1:9".parse().unwrap()) };
        CodeoutCtx {
            api: Arc::new(FakeMicrovmApi::new()),
            dp: vm.clone(),
            tokens: vm,
            paths: Paths::from_root_and_env(dir.to_path_buf(), None),
            cfg: Arc::new(BridgeConfig::default()),
            target: target(VM1),
            ws: ws(),
            capture_settings: false,
            transcript: Some(TranscriptSync { target: s3, slug: "-w".into(), mac_cwd: "/w".into(), mac_projects: dir.join("projects"), proxy: None, view_messages: 10 }),
        }
    }

    /// Until `done`, at most 20 s.
    async fn until(mut done: impl FnMut() -> bool) {
        let end = std::time::Instant::now() + Duration::from_secs(20);
        while !done() && std::time::Instant::now() < end {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// S10 (R1, §1.4, §3.3): `retail` returns at once and coalesces as a
    /// fetch's request does: three unparks before the task looked hand one
    /// tail of the named session (here the one from 0: S3 holds nothing of
    /// it, and no row says S3 keeps it, so no chain is listed), and the
    /// session's first transcript step's tail stands for a retail asked
    /// before it ran. Before any session is named, and without a transcript
    /// sync, nothing is handed; the watch is quiet again once it was. No
    /// fetch runs for it.
    #[tokio::test]
    async fn retail_hands_the_named_sessions_next_tail_once_however_often_asked() {
        let dir = tempfile::tempdir().unwrap();
        let vm = Arc::new(TailVm::default());
        let trigger = CodeoutTrigger::spawn(tail_ctx(dir.path(), vm.clone()));
        let watch = trigger.watch();
        trigger.retail();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(vm.handed().is_empty() && watch.quiet(), "no session named: nothing to tail");
        trigger.set_session(SESSION);
        trigger.retail();
        until(|| !vm.handed().is_empty() && watch.quiet()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let tail0 = crate::wire::s3::S3Key::Tail { session: SESSION.into(), gen: 1, offset: 0 }.render();
        assert_eq!(vm.handed(), [(tail0.clone(), 0)], "the first step's tail, which the retail asked meanwhile is");
        for _ in 0..3 {
            trigger.retail();
        }
        until(|| vm.handed().len() >= 2 && watch.quiet()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(vm.handed(), [(tail0.clone(), 0), (tail0, 0)], "three unparks, one tail");
        assert!(trigger.last().is_none(), "no fetch ran");
        let _ = trigger.close(CLOSE_WAIT).await;
        // Without a transcript sync: nothing to hand, whatever is asked.
        let plain = Arc::new(TailVm::default());
        let mut ctx = tail_ctx(dir.path(), plain.clone());
        ctx.transcript = None;
        let trigger = CodeoutTrigger::spawn(ctx);
        trigger.set_session(SESSION);
        trigger.retail();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(plain.handed().is_empty() && trigger.watch().quiet());
        let _ = trigger.close(CLOSE_WAIT).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::FakeMicrovmApi;
    use crate::bridge::dataplane::Unreached;
    use crate::bridge::workspace::Head;
    use crate::wire::redact::Secret;
    use crate::wire::workspace::ObjectFormat;

    /// The trigger: never asked, it closes at once with no report; asked
    /// twice before its task first ran, it runs once (here: a fetch that
    /// fails, its workspace gone; each failure is one `codeout_fetch` audit
    /// row) and keeps the last report, a failure a report, never a panic or
    /// an error; closing waits at most its budget. Outside a runtime it runs
    /// nothing and says so.
    #[tokio::test]
    async fn the_trigger_coalesces_reports_and_closes_within_its_budget() {
        let dir = tempfile::tempdir().unwrap();
        let ws = WorkspaceRef {
            cwd: "/nonexistent/w".into(),
            root: "/nonexistent/w".into(),
            vm_cwd: "/nonexistent/w".into(),
            vm_root: "/nonexistent/w".into(),
            slug: "-nonexistent-w".into(),
            kind: WsKind::Git { git_dir: "/nonexistent/w/.git".into(), common_dir: "/nonexistent/w/.git".into(), object_format: ObjectFormat::Sha1 },
            head: Head::Detached { sha: "a".repeat(40) },
            seed_branch: None,
        };
        let ctx = || CodeoutCtx {
            api: Arc::new(FakeMicrovmApi::new()),
            dp: Arc::new(Unreached),
            tokens: Arc::new(Unreached),
            paths: Paths::from_root_and_env(dir.path().to_path_buf(), None),
            cfg: Arc::new(BridgeConfig::default()),
            target: AgentTarget { vm_id: "microvm-1".into(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false },
            ws: ws.clone(),
            capture_settings: true,
            transcript: None,
        };
        let quiet = CodeoutTrigger::spawn(ctx());
        let t = std::time::Instant::now();
        assert_eq!(quiet.close(CLOSE_WAIT).await, None, "never asked: no report");
        assert!(t.elapsed() < CLOSE_WAIT);
        let trigger = CodeoutTrigger::spawn(ctx());
        assert_eq!(trigger.last(), None);
        trigger.request();
        trigger.request();
        trigger.set_session("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b");
        let until = std::time::Instant::now() + Duration::from_secs(20);
        while trigger.last().is_none() && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let report = trigger.last().expect("a report once a fetch ran");
        assert!(!report.ok && report.promoted.is_empty() && report.bytes == 0 && report.at.ends_with('Z'), "{report:?}");
        assert!(report.note.as_deref().is_some_and(|n| n.starts_with("code-out: ")), "{report:?}");
        // A quiet while: the two requests were one fetch, and none follows it.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let audit = std::fs::read_to_string(Paths::from_root_and_env(dir.path().to_path_buf(), None).audit()).unwrap_or_default();
        assert_eq!(audit.lines().filter(|l| l.contains("\"event\":\"codeout_fetch\"")).count(), 1, "{audit}");
        let t = std::time::Instant::now();
        assert!(trigger.close(CLOSE_WAIT).await.is_some_and(|r| !r.ok));
        assert!(t.elapsed() < CLOSE_WAIT + Duration::from_millis(200), "{:?}", t.elapsed());
        // Outside any runtime: nothing runs, and the report says so.
        let lone = ctx();
        let outside = std::thread::spawn(move || {
            let trigger = CodeoutTrigger::spawn(lone);
            trigger.request();
            trigger.last()
        })
        .join()
        .unwrap();
        assert_eq!(outside.and_then(|r| r.note).as_deref(), Some("code-out: no runtime to fetch on"));
    }

    /// The settings route of a VM whose every other route is unreached:
    /// `get_settings` answers a capture of the trigger's workspace, or holds
    /// forever (`hold`), and counts its requests. With a `gate`, each answer
    /// waits for a permit; `changing`, each answer's project keys differ
    /// from the one before (every capture is written). `POST
    /// /transcript/tail` is counted (`tails`) and unserved, but from the
    /// `hold_tail`-th one on (0 the first) it holds forever.
    struct SettingsVm {
        hold: bool,
        gets: std::sync::atomic::AtomicUsize,
        gate: Option<tokio::sync::Semaphore>,
        changing: bool,
        tails: std::sync::atomic::AtomicUsize,
        hold_tail: Option<usize>,
    }

    fn settings_vm(hold: bool) -> SettingsVm {
        SettingsVm { hold, gets: std::sync::atomic::AtomicUsize::new(0), gate: None, changing: false, tails: std::sync::atomic::AtomicUsize::new(0), hold_tail: None }
    }

    impl TokenSource for SettingsVm {
        async fn token(&self, port: u16) -> Result<crate::bridge::api::AuthToken, BridgeError> {
            Ok(crate::bridge::api::AuthToken { headers: BTreeMap::new(), port, expires_at_unix: u64::MAX })
        }
    }

    impl DataPlane for SettingsVm {
        async fn seed_state(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &str) -> Result<crate::bridge::dataplane::DpReply<crate::wire::workspace::SeedState>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn put_seed(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &crate::wire::workspace::SeedQuery, _: &Path, _: u64) -> Result<crate::bridge::dataplane::DpReply<crate::wire::workspace::SeedReply>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn post_codeout(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &CodeoutRequest, _: &Path, _: u64) -> Result<crate::bridge::dataplane::DpReply<crate::bridge::dataplane::CodeoutBody>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn transcript_stat(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &str) -> Result<crate::bridge::dataplane::DpReply<crate::wire::workspace::TranscriptStat>, BridgeError> {
            Err(BridgeError::Endpoint("unreached".into()))
        }

        async fn get_settings(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, path: &str) -> Result<crate::bridge::dataplane::DpReply<crate::wire::workspace::SettingsCapture>, BridgeError> {
            let n = self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.hold {
                std::future::pending::<()>().await;
            }
            if let Some(gate) = &self.gate {
                gate.acquire().await.expect("the gate is never closed").forget();
            }
            let mut project = BTreeMap::new();
            if self.changing {
                project.insert("allowedTools".to_string(), serde_json::json!([format!("Bash(echo {n})")]));
            }
            Ok(crate::bridge::dataplane::DpReply::ok(200, crate::wire::workspace::SettingsCapture { path: path.to_string(), files: Vec::new(), project, at: "2026-10-12T10:00:00Z".into() }))
        }

        async fn transcript_tail(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &crate::wire::workspace::TranscriptTail) -> Result<crate::bridge::dataplane::DpReply<()>, BridgeError> {
            let n = self.tails.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.hold_tail.is_some_and(|from| n >= from) {
                std::future::pending::<()>().await;
            }
            Err(BridgeError::Config("POST /transcript/tail: this VM does not serve it".into()))
        }
    }

    /// The trigger's context on `dir`'s bridge root, a workspace that does not
    /// exist (each fetch fails at once), the settings captured through `vm`.
    fn settings_ctx(dir: &Path, vm: Arc<SettingsVm>) -> CodeoutCtx<FakeMicrovmApi, SettingsVm, SettingsVm> {
        CodeoutCtx {
            api: Arc::new(FakeMicrovmApi::new()),
            dp: vm.clone(),
            tokens: vm,
            paths: Paths::from_root_and_env(dir.to_path_buf(), None),
            cfg: Arc::new(BridgeConfig::default()),
            target: AgentTarget { vm_id: "microvm-1".into(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false },
            ws: WorkspaceRef {
                cwd: "/nonexistent/w".into(),
                root: "/nonexistent/w".into(),
                vm_cwd: "/nonexistent/w".into(),
                vm_root: "/nonexistent/w".into(),
                slug: "-nonexistent-w".into(),
                kind: WsKind::Git { git_dir: "/nonexistent/w/.git".into(), common_dir: "/nonexistent/w/.git".into(), object_format: ObjectFormat::Sha1 },
                head: Head::Detached { sha: "a".repeat(40) },
                seed_branch: None,
            },
            capture_settings: true,
            transcript: None,
        }
    }

    /// The audit events of `dir`'s bridge root, in order.
    fn events(dir: &Path) -> Vec<String> {
        let text = std::fs::read_to_string(Paths::from_root_and_env(dir.to_path_buf(), None).audit()).unwrap_or_default();
        text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).map(|r| format!("{}:{}", r["event"].as_str().unwrap_or("?"), r["detail"]["phase"].as_str().or(r["detail"]["outcome"].as_str()).unwrap_or("?"))).collect()
    }

    /// T8.7: a session the trigger is told of gets its start capture before
    /// a fetch already queued, then the fetch, then a turn's capture (here
    /// the same settings: nothing written); a session named again is not
    /// captured again, another one is.
    #[tokio::test]
    async fn a_named_session_is_captured_before_the_queued_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let vm = Arc::new(settings_vm(false));
        let trigger = CodeoutTrigger::spawn(settings_ctx(dir.path(), vm.clone()));
        trigger.request();
        trigger.set_session(SESSION);
        let until = std::time::Instant::now() + Duration::from_secs(20);
        while (trigger.last().is_none() || vm.gets.load(std::sync::atomic::Ordering::SeqCst) < 2) && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(events(dir.path()), ["settings_capture:start", "codeout_fetch:failed"], "the start capture first, then the fetch; the turn's capture changed nothing");
        assert_eq!(vm.gets.load(std::sync::atomic::Ordering::SeqCst), 2, "the start capture and the turn's");
        let start = crate::bridge::settings_capture::capture_path(&Paths::from_root_and_env(dir.path().to_path_buf(), None), SESSION, crate::bridge::settings_capture::CapturePhase::Start).unwrap();
        assert!(start.is_file(), "{}", start.display());
        trigger.set_session(SESSION);
        let other = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";
        trigger.set_session(other);
        let until = std::time::Instant::now() + Duration::from_secs(20);
        while vm.gets.load(std::sync::atomic::Ordering::SeqCst) < 3 && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(vm.gets.load(std::sync::atomic::Ordering::SeqCst), 3, "the same session once, the other one once");
        let _ = trigger.close(CLOSE_WAIT).await;
    }

    /// S9 phase 4 (T2): a session the trigger is told of gets its
    /// placeholder view at once, before any fetch (none is asked here), so a
    /// chat closed before its first sync is still listed in Cursor's
    /// picker; its tail is offered (this VM serves no transcript route: it
    /// fails, logged, never fatal) and its subtree has nothing to restore
    /// (no manifest). A file already at the view's path is never replaced.
    #[tokio::test]
    async fn a_named_session_gets_its_placeholder_view_before_any_fetch() {
        use crate::bridge::s3::{S3Endpoint, S3Target, TranscriptSync, LAB_BUCKET, LAB_OWNER};
        let dir = tempfile::tempdir().unwrap();
        let projects = dir.path().join("projects");
        let ctx = |vm: Arc<SettingsVm>| {
            let mut ctx = settings_ctx(dir.path(), vm);
            ctx.capture_settings = false;
            let target = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab("127.0.0.1:9".parse().unwrap()) };
            ctx.transcript = Some(TranscriptSync { target, slug: "-w".into(), mac_cwd: "/w".into(), mac_projects: projects.clone(), proxy: None, view_messages: 10 });
            ctx
        };
        let trigger = CodeoutTrigger::spawn(ctx(Arc::new(settings_vm(false))));
        trigger.set_session(SESSION);
        let view = projects.join("-w").join(format!("{SESSION}.jsonl"));
        let until = std::time::Instant::now() + Duration::from_secs(20);
        while !view.exists() && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(crate::bridge::view::is_view_file(&view), "the placeholder view, marked");
        assert!(std::fs::read_to_string(&view).unwrap().contains(crate::bridge::s3::sync::PLACEHOLDER_TEXT));
        assert!(trigger.last().is_none(), "no fetch was asked");
        let _ = trigger.close(CLOSE_WAIT).await;
        // A file there already (a view, or a transcript): left as it is.
        std::fs::write(&view, b"{\"type\":\"user\"}\n").unwrap();
        let trigger = CodeoutTrigger::spawn(ctx(Arc::new(settings_vm(false))));
        trigger.set_session(SESSION);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = trigger.close(CLOSE_WAIT).await;
        assert_eq!(std::fs::read(&view).unwrap(), b"{\"type\":\"user\"}\n");
    }

    /// Never inside the close budget: a capture still waiting for the VM as
    /// the trigger closes is given up at once (not after `CLOSE_WAIT`), and
    /// nothing of it is written.
    #[tokio::test]
    async fn a_capture_running_at_close_is_given_up_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let vm = Arc::new(settings_vm(true));
        let trigger = CodeoutTrigger::spawn(settings_ctx(dir.path(), vm.clone()));
        trigger.set_session(SESSION);
        let until = std::time::Instant::now() + Duration::from_secs(20);
        while vm.gets.load(std::sync::atomic::Ordering::SeqCst) == 0 && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(vm.gets.load(std::sync::atomic::Ordering::SeqCst), 1, "the start capture is waiting for the VM");
        let t = std::time::Instant::now();
        assert_eq!(trigger.close(CLOSE_WAIT).await, None);
        assert!(t.elapsed() < CLOSE_WAIT, "given up at once, not waited for: {:?}", t.elapsed());
        assert!(!Paths::from_root_and_env(dir.path().to_path_buf(), None).quarantine().exists(), "nothing written");
        assert!(events(dir.path()).is_empty(), "{:?}", events(dir.path()));
    }

    /// S9 round 5 (R3): no fetch starts after the close. A turn's fresh
    /// tail goes to the VM before its fetch (S9); a close while that tail
    /// waits at the VM gives it up at once, and the fetch never starts: the
    /// close finds no report and the task ended, and no `codeout_fetch` row
    /// is written. S8's task went from the work to its fetch with nothing
    /// to wait for between.
    #[tokio::test]
    async fn a_close_while_the_turns_tail_waits_starts_no_fetch() {
        use crate::bridge::s3::{S3Endpoint, S3Target, TranscriptSync, LAB_BUCKET, LAB_OWNER};
        use std::sync::atomic::Ordering::SeqCst;
        let dir = tempfile::tempdir().unwrap();
        // The session's first tail (its naming's) is refused at once; the turn's waits at the VM.
        let vm = Arc::new(SettingsVm { hold_tail: Some(1), ..settings_vm(false) });
        let mut ctx = settings_ctx(dir.path(), vm.clone());
        ctx.capture_settings = false;
        let target = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab("127.0.0.1:9".parse().unwrap()) };
        ctx.transcript = Some(TranscriptSync { target, slug: "-w".into(), mac_cwd: "/w".into(), mac_projects: dir.path().join("projects"), proxy: None, view_messages: 10 });
        let trigger = CodeoutTrigger::spawn(ctx);
        let watch = trigger.watch();
        trigger.set_session(SESSION);
        trigger.request();
        let until = std::time::Instant::now() + Duration::from_secs(20);
        while vm.tails.load(SeqCst) < 2 && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(vm.tails.load(SeqCst), 2, "the turn's tail waits at the VM");
        let t = std::time::Instant::now();
        assert_eq!(trigger.close(CLOSE_WAIT).await, None, "no fetch ran");
        assert!(t.elapsed() < CLOSE_WAIT, "the tail given up at once: {:?}", t.elapsed());
        assert!(watch.done());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!events(dir.path()).iter().any(|e| e.starts_with("codeout_fetch")), "{:?}", events(dir.path()));
    }

    /// A fetch queued by a session's result keeps that session's turn
    /// capture when a `/clear` names the next session before it starts:
    /// the next one's start capture runs first, then the fetch, then the
    /// asking session's capture, never the next one's.
    #[tokio::test]
    async fn a_queued_fetchs_turn_capture_is_the_asking_sessions() {
        use std::sync::atomic::Ordering::SeqCst;
        let dir = tempfile::tempdir().unwrap();
        let vm = Arc::new(SettingsVm { gate: Some(tokio::sync::Semaphore::new(1)), changing: true, ..settings_vm(false) });
        let trigger = CodeoutTrigger::spawn(settings_ctx(dir.path(), vm.clone()));
        let captures = || -> Vec<(String, String)> {
            let text = std::fs::read_to_string(Paths::from_root_and_env(dir.path().to_path_buf(), None).audit()).unwrap_or_default();
            let rows = text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|r| r["event"] == "settings_capture");
            rows.map(|r| (r["session_id"].as_str().unwrap_or("?").to_string(), r["detail"]["phase"].as_str().unwrap_or("?").to_string())).collect()
        };
        let until = std::time::Instant::now() + Duration::from_secs(20);
        trigger.set_session(SESSION);
        while captures().is_empty() && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The session's result: a fetch, then its turn's capture, held at the VM.
        trigger.request();
        while vm.gets.load(SeqCst) < 2 && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(vm.gets.load(SeqCst), 2, "the turn's capture waits at the VM");
        // Its last result queues a fetch; a `/clear` then names the next session.
        trigger.request();
        let next = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";
        trigger.set_session(next);
        vm.gate.as_ref().unwrap().add_permits(3);
        while captures().len() < 4 && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let want: Vec<(String, String)> = [(SESSION, "start"), (SESSION, "turn"), (next, "start"), (SESSION, "turn")].iter().map(|(s, p)| ((*s).to_string(), (*p).to_string())).collect();
        assert_eq!(captures(), want, "the queued fetch's capture is the asking session's");
        assert_eq!(vm.gets.load(SeqCst), 4);
        let _ = trigger.close(CLOSE_WAIT).await;
    }

    /// The closing suspend's watch (plan §11): a trigger is done only once
    /// it closed and nothing of it runs. Idle but open it is not (a result
    /// still on its way may ask for a fetch), nor while a fetch runs (here
    /// held at the workspace's fetch lock, which the test holds); closed with
    /// the fetch running, it is done once the fetch ends, also one the close
    /// gave up at `CLOSE_WAIT` (S10 D5: left to its end, so the closing
    /// suspend waits for it). Without a runtime it is done from the start.
    #[tokio::test]
    async fn the_watch_is_done_once_the_trigger_closed_and_its_fetch_ended_or_was_given_up() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = settings_ctx(dir.path(), Arc::new(settings_vm(false)));
        let lock = ctx.paths.workspace_fetch_lock(&ctx.ws.slug);
        let (quick, bound) = (Duration::from_millis(150), Duration::from_secs(10));
        // Open and idle: not done.
        let idle = CodeoutTrigger::spawn(settings_ctx(dir.path(), Arc::new(settings_vm(false))));
        let watch = idle.watch();
        assert!(!watch.done() && tokio::time::timeout(quick, watch.wait_done()).await.is_err(), "an open trigger is not done");
        let t = std::time::Instant::now();
        let _ = idle.close(CLOSE_WAIT).await;
        tokio::time::timeout(quick, watch.wait_done()).await.expect("closed with nothing running: done at once");
        assert!(t.elapsed() < CLOSE_WAIT);
        // A fetch held at the lock, given up at the close's bound: S10 (D5) it runs on, so the watch is done only at
        // its end (the closing suspend waits for it), here once the test lets the lock go.
        let held = crate::bridge::vm::lock::try_lock_exclusive(&lock).unwrap().expect("the test holds the fetch lock");
        let trigger = CodeoutTrigger::spawn(ctx);
        let watch = trigger.watch();
        trigger.request();
        assert!(tokio::time::timeout(quick, watch.wait_done()).await.is_err(), "a fetch runs: not done");
        let t = std::time::Instant::now();
        let report = trigger.close(CLOSE_WAIT).await;
        assert!(report.is_none() && t.elapsed() >= CLOSE_WAIT && t.elapsed() < CLOSE_WAIT + Duration::from_secs(2), "the close gives the fetch up at its bound: {:?}", t.elapsed());
        assert!(tokio::time::timeout(quick, watch.wait_done()).await.is_err(), "the abandoned fetch runs on: not done");
        drop(held);
        tokio::time::timeout(bound, watch.wait_done()).await.expect("the abandoned fetch ended: done");
        assert!(watch.done());
        let held = crate::bridge::vm::lock::try_lock_exclusive(&lock).unwrap().expect("the test holds the fetch lock again");
        // A fetch held at the lock that ends once the lock goes: done at its end, before `CLOSE_WAIT`.
        let trigger = CodeoutTrigger::spawn(settings_ctx(dir.path(), Arc::new(settings_vm(false))));
        let watch = trigger.watch();
        trigger.request();
        assert!(tokio::time::timeout(quick, watch.wait_done()).await.is_err(), "a fetch runs: not done");
        let t = std::time::Instant::now();
        let close = trigger.close(CLOSE_WAIT * 20);
        let release = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!watch.done(), "closed, the fetch still running: not done");
            drop(held);
            tokio::time::timeout(bound, watch.wait_done()).await.expect("the fetch ended: done");
        };
        let (report, ()) = tokio::join!(close, release);
        assert!(report.is_some_and(|r| !r.ok), "the fetch ended (its workspace is gone): a report");
        assert!(t.elapsed() < CLOSE_WAIT * 10, "done at the fetch's end, not the close's bound: {:?}", t.elapsed());
        // No runtime: nothing ever runs.
        let lone = settings_ctx(dir.path(), Arc::new(settings_vm(false)));
        assert!(std::thread::spawn(move || CodeoutTrigger::spawn(lone).watch().done()).join().unwrap());
    }

    /// S10 §D: the watch is quiet while no fetch is pending or running (a
    /// park waits for it): an idle trigger is; one whose fetch is held at the
    /// workspace's fetch lock is not, until that fetch ended. `retail`
    /// without a transcript sync hands nothing.
    #[tokio::test]
    async fn the_watch_is_quiet_while_no_fetch_is_pending_or_running() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = settings_ctx(dir.path(), Arc::new(settings_vm(false)));
        let lock = ctx.paths.workspace_fetch_lock(&ctx.ws.slug);
        let trigger = CodeoutTrigger::spawn(ctx);
        let watch = trigger.watch();
        assert!(watch.quiet(), "idle");
        trigger.retail();
        assert!(watch.quiet(), "no transcript sync: retail hands nothing");
        let held = crate::bridge::vm::lock::try_lock_exclusive(&lock).unwrap().expect("the test holds the fetch lock");
        trigger.request();
        assert!(!watch.quiet(), "a fetch asked for");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!watch.quiet(), "a fetch running (held at the lock)");
        drop(held);
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while !watch.quiet() && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(watch.quiet(), "the fetch ended");
        let _ = trigger.close(CLOSE_WAIT).await;
    }

    const SESSION: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    /// The haves: the Mac's HEAD and the seeded head first, then the box
    /// branches, then the snapshots newest first, each once, at most
    /// `HAVES_MAX`; a request with them passes the wire's check.
    #[test]
    fn haves_follow_the_wires_order_rule() {
        let id = |n: u32| format!("{n:040x}");
        let mut tips = BTreeMap::new();
        tips.insert(format!("{BOX_REFS}dev"), id(3));
        tips.insert(format!("{BOX_REFS}wip/20261012T101530Z-1"), id(4));
        tips.insert(format!("{BOX_REFS}wip/20261012T111530Z-2"), id(5));
        tips.insert(format!("{BOX_REFS}main"), id(1));
        assert_eq!(haves_of(Some(&id(1)), Some(&id(2)), &tips), vec![id(1), id(2), id(3), id(5), id(4)], "HEAD, seeded, branches (main's tip is HEAD's), newest snapshot first");
        let many: BTreeMap<String, String> = (0..400).map(|n| (format!("{BOX_REFS}wip/{n:04}"), id(1000 + n))).collect();
        let haves = haves_of(Some(&id(1)), None, &many);
        assert_eq!((haves.len(), haves[1].clone()), (HAVES_MAX, id(1399)), "capped, the newest kept");
        let req = CodeoutRequest { path: "/w".into(), haves, wip: true, max_bytes: 1, manifest_when_empty: false };
        assert_eq!(req.check(), Ok(()));
    }

    /// A box name meets an existing ref on a case-folding filesystem: the
    /// same name in another case, or one a directory of the other.
    #[test]
    fn clashes_fold_case_and_directories() {
        let existing: BTreeMap<String, String> = [format!("{BOX_REFS}Dev"), format!("{BOX_REFS}feature/a")].into_iter().map(|n| (n, H.to_string())).collect();
        assert!(clashes(&format!("{BOX_REFS}dev"), &existing));
        assert!(!clashes(&format!("{BOX_REFS}Dev"), &existing), "the same ref is an update");
        assert!(clashes(&format!("{BOX_REFS}feature"), &existing));
        assert!(clashes(&format!("{BOX_REFS}feature/a/b"), &existing));
        assert!(!clashes(&format!("{BOX_REFS}feature/b"), &existing));
    }

    /// The Mac's disk folds names beyond ASCII (each pair checked on this
    /// Mac: APFS opens the second name as the first): `box_refs` takes the
    /// first of a pair (byte order) and skips the second; `clashes` meets an
    /// existing ref in the other spelling, or under it as a directory, while
    /// the same name, and its NFC twin, is the same ref; a box name is NFC; a
    /// reserved name in `ſ` is reserved. Dotless ı, which APFS keeps apart
    /// from i, folds too: a skip, never a failed transaction.
    #[test]
    fn box_names_fold_as_the_macs_disk_does() {
        let pairs = [
            ("\u{c9}t\u{e9}", "\u{e9}t\u{e9}"),
            ("cafe\u{301}", "caf\u{e9}"),
            ("fix-sort", "fix-\u{17f}ort"),
            ("strasse", "stra\u{df}e"),
            ("\u{3c2}x", "\u{3c3}x"),
            ("Kelvin", "\u{212a}elvin"),
            ("\u{424}\u{438}\u{447}\u{430}", "\u{444}\u{438}\u{447}\u{430}"),
            ("SS-up", "\u{1e9e}-up"),
            ("\u{13a0}", "\u{ab70}"),
            ("\u{1c5}x", "\u{1c6}x"),
            ("i\u{307}x", "\u{130}x"),
            ("\u{b5}", "\u{3bc}"),
            ("fix", "\u{fb01}x"),
        ];
        for (first, second) in pairs {
            assert!(first < second, "{first} sorts first");
            let refs: BTreeMap<String, String> = [first, second].iter().map(|b| (format!("refs/heads/{b}"), H.to_string())).collect();
            let (taken, skipped) = box_refs(&refs);
            assert_eq!(taken, BTreeMap::from([(format!("{BOX_REFS}{}", nfc(first)), format!("refs/heads/{first}"))]), "{first} and {second}");
            assert_eq!(skipped, [format!("refs/heads/{second}")], "{first} and {second}");
            assert_no_clash(&taken);
            let existing = BTreeMap::from([(format!("{BOX_REFS}{}", nfc(first)), H.to_string())]);
            assert_eq!(clashes(&format!("{BOX_REFS}{second}"), &existing), nfc(first) != nfc(second), "{second} beside box/{first}");
            assert!(clashes(&format!("{BOX_REFS}{second}/x"), &existing), "{second}/x under box/{first}");
            assert!(!clashes(&format!("{BOX_REFS}{}", nfc(first)), &existing), "{first} is the same ref");
        }
        assert_eq!(box_ref_of("refs/heads/cafe\u{301}").as_deref(), Some("refs/remotes/box/caf\u{e9}"), "a box name is NFC");
        assert_eq!(box_ref_of("refs/heads/\u{17f}eed-wip"), None, "seed-wip in a long s is reserved");
        let (taken, skipped) = box_refs(&BTreeMap::from([("refs/heads/i".to_string(), H.to_string()), ("refs/heads/\u{131}".to_string(), H.to_string())]));
        assert_eq!((taken.len(), skipped), (1, vec!["refs/heads/\u{131}".to_string()]), "dotless i folds too: one is skipped");
    }

    const H: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";

    /// The collisions a flat `refs/remotes/box/` met: a VM branch `wip`,
    /// `wip/…`, `seed-wip` or `HEAD/…` (in any ASCII case) has no box name, so
    /// it never meets the snapshots, the seeded WIP or a detached HEAD.
    #[test]
    fn a_vm_ref_takes_its_box_name_and_reserved_branches_none() {
        for (vm, boxed) in [
            ("refs/heads/dev", "refs/remotes/box/dev"),
            ("refs/heads/feature/x-1", "refs/remotes/box/feature/x-1"),
            ("refs/heads/wipe", "refs/remotes/box/wipe"),
            ("refs/heads/dev/wip", "refs/remotes/box/dev/wip"),
            ("refs/heads/header", "refs/remotes/box/header"),
            ("refs/wip/20261012T101530Z-1", "refs/remotes/box/wip/20261012T101530Z-1"),
            ("refs/ai-env/seed-wip", "refs/remotes/box/seed-wip"),
            ("HEAD", "refs/remotes/box/HEAD"),
        ] {
            assert_eq!(box_ref_of(vm).as_deref(), Some(boxed), "{vm}");
        }
        for vm in [
            "refs/heads/wip",
            "refs/heads/WIP",
            "refs/heads/wip/20261012T101530Z-1",
            "refs/heads/seed-wip",
            "refs/heads/Seed-Wip",
            "refs/heads/seed-wip/x",
            "refs/heads/HEAD/x",
            "refs/heads/head",
            "refs/heads/HEAD",
            "refs/heads/a..b",
            "refs/tags/v1",
            "refs/ai-env/seed",
            "refs/remotes/origin/main",
            "refs/wip/a b",
        ] {
            assert_eq!(box_ref_of(vm), None, "{vm}");
        }
        // The three sets the review found accepted by the manifest check, and failing one update-ref transaction whole.
        for set in [
            &["refs/heads/dev", "refs/heads/wip", "refs/wip/20261012T101530Z-1"][..],
            &["refs/heads/seed-wip", "refs/ai-env/seed-wip"],
            &["refs/heads/wip/20261012T101530Z-1", "refs/wip/20261012T101530Z-1"],
        ] {
            let refs: BTreeMap<String, String> = set.iter().map(|r| ((*r).to_string(), H.to_string())).collect();
            let m = CodeoutManifest { v: 1, object_format: ObjectFormat::Sha1, refs: refs.clone(), head: H.into(), branch: Some("dev".into()), wip_ref: None, wip_skipped: None };
            assert_eq!(m.check(), Ok(()), "{set:?}");
            let (taken, skipped) = box_refs(&refs);
            assert_eq!(skipped.len(), 1, "{set:?}: {taken:?}");
            assert!(skipped[0].starts_with("refs/heads/"), "the VM branch is the one skipped: {skipped:?}");
            assert_no_clash(&taken);
        }
    }

    /// No two box names are equal, or one a directory of the other, as the
    /// Mac's disk compares names.
    fn assert_no_clash(taken: &BTreeMap<String, String>) {
        let names: Vec<String> = taken.keys().map(|n| disk_key(n)).collect();
        for (i, a) in names.iter().enumerate() {
            assert!(a.starts_with(BOX_REFS) && is_ref_name(a), "{a}");
            for b in &names[i + 1..] {
                assert!(a != b && !b.starts_with(&format!("{a}/")) && !a.starts_with(&format!("{b}/")), "{a} and {b} in {taken:?}");
            }
        }
    }

    /// The VM refs of the property below: the reserved names, case and
    /// directory variants of ordinary branches, snapshots, the seeded WIP
    /// and a detached HEAD; then names the Mac's disk folds beyond ASCII
    /// (É and é, NFC and NFD, `ſ` and s, ß and ss, a reserved name in `ſ`).
    const UNIVERSE: [&str; 29] = [
        "HEAD",
        "refs/ai-env/seed-wip",
        "refs/heads/Dev",
        "refs/heads/HEAD/x",
        "refs/heads/Seed-Wip",
        "refs/heads/WIP",
        "refs/heads/dev",
        "refs/heads/dev/x",
        "refs/heads/feature",
        "refs/heads/feature/a",
        "refs/heads/head",
        "refs/heads/seed-wip",
        "refs/heads/seed-wip/x",
        "refs/heads/wip",
        "refs/heads/wip/20261012T101530Z-1",
        "refs/heads/wipe",
        "refs/wip/20261012T101530Z-1",
        "refs/wip/x",
        "refs/wip/x/y",
        "refs/wip/X",
        "refs/heads/\u{e9}t\u{e9}",
        "refs/heads/\u{c9}t\u{e9}/x",
        "refs/heads/caf\u{e9}",
        "refs/heads/cafe\u{301}",
        "refs/heads/fix-\u{17f}ort",
        "refs/heads/fix-sort",
        "refs/heads/stra\u{df}e",
        "refs/heads/strasse",
        "refs/heads/\u{17f}eed-wip",
    ];

    /// Two refs one VM repository can hold (neither a directory of the
    /// other, in git's case-sensitive namespace) never take one box name, nor
    /// one a directory of the other's: the mapper alone keeps git's own rule,
    /// but for one name in NFC and NFD, which takes one box name (git on
    /// macOS lists the two as one): [`box_refs`] skips the second.
    #[test]
    fn box_names_keep_gits_rule_for_any_two_refs_a_vm_holds() {
        let dir_of = |a: &str, b: &str| b.starts_with(&format!("{a}/"));
        for (i, a) in UNIVERSE.iter().enumerate() {
            for b in &UNIVERSE[i + 1..] {
                if dir_of(a, b) || dir_of(b, a) || nfc(a) == nfc(b) {
                    continue;
                }
                if let (Some(x), Some(y)) = (box_ref_of(a), box_ref_of(b)) {
                    assert!(x != y && !dir_of(&x, &y) && !dir_of(&y, &x), "{a} as {x}, {b} as {y}");
                }
            }
        }
    }

    proptest::proptest! {
        /// Any manifest the check passes promotes refs that one `update-ref`
        /// transaction on a case-folding filesystem can write: no two box
        /// names equal, or one a directory of the other, case ignored; every
        /// VM ref is promoted or skipped, each once, and the box names are
        /// [`box_ref_of`]'s.
        #[test]
        fn any_checked_manifest_promotes_refs_one_transaction_can_write(mask in 0u32..(1 << 29)) {
            let refs: BTreeMap<String, String> = UNIVERSE.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, r)| ((*r).to_string(), H.to_string())).collect();
            let detached = refs.contains_key("HEAD");
            let m = CodeoutManifest { v: 1, object_format: ObjectFormat::Sha1, refs: refs.clone(), head: H.into(), branch: (!detached).then(|| "dev".to_string()), wip_ref: None, wip_skipped: None };
            proptest::prop_assert_eq!(m.check(), Ok(()));
            let (taken, skipped) = box_refs(&refs);
            assert_no_clash(&taken);
            proptest::prop_assert_eq!(taken.len() + skipped.len(), refs.len());
            for (name, vm) in &taken {
                let mapped = box_ref_of(vm);
                proptest::prop_assert_eq!(mapped.as_deref(), Some(name.as_str()));
            }
            for r in UNIVERSE.iter().filter(|r| refs.contains_key(**r) && box_ref_of(r).is_none()) {
                proptest::prop_assert!(skipped.iter().any(|s| s == r), "{} is skipped", r);
            }
        }
    }

    /// A name the VM chose looks like a credential when the scrubber masks
    /// part of it or a tripwire matches it (each built at run time: the
    /// setup-token's shape, an AWS key id, a `token=` assignment, a custom
    /// tripwire); a branch, a snapshot, the seeded WIP and a detached HEAD
    /// named as ai-env and people name them do not. The two notes that count
    /// refs, naming none, read as the contracts pin them (S9 §13, I1).
    #[test]
    fn credential_shaped_names_are_the_scrubbers_and_the_tripwires() {
        let rules = Rules::with_extras("internal-[0-9]{6}\n", "tripwires").unwrap();
        let token = format!("{}-{}-oat01-{}", "sk", "ant", "Kq4_".repeat(20));
        let key = format!("{}{}", "AKIA", "Z3".repeat(8));
        for name in [format!("refs/heads/x-{token}"), format!("refs/wip/zz-{token}-9"), format!("refs/heads/{key}"), "refs/heads/fix/token=abc".into(), "refs/heads/internal-123456".into()] {
            assert!(credential_shaped(&name, &rules), "{}", name.replace(&token, "<TOKEN>"));
        }
        for name in ["refs/heads/main", "refs/heads/feature/x-1", "refs/heads/tokenizer", "refs/heads/secret-santa", "refs/wip/20261012T101530Z-1", "refs/ai-env/seed-wip", "HEAD"] {
            assert!(!credential_shaped(name, &rules), "{name}");
        }
        assert_eq!(hidden_note(2), "2 VM ref(s) skipped: a name that looks like a credential (not shown)");
        assert_eq!(not_commit_note(2), "2 VM ref(s) skipped: an object that is no commit (a tree, a blob or a tag; not shown)");
    }

    #[test]
    fn the_namespaces_and_budgets_are_the_plans() {
        for prefix in [BOX_REFS, BOX_QUARANTINE_REFS, INCOMING_REFS] {
            assert!(prefix.starts_with("refs/") && prefix.ends_with('/') && crate::wire::workspace::is_ref_name(prefix.trim_end_matches('/')), "{prefix}");
        }
        assert!(!BOX_QUARANTINE_REFS.starts_with(BOX_REFS), "a quarantined ref is never under box/");
        assert_eq!((CLOSE_WAIT, FAILURE_LINE_EVERY), (Duration::from_millis(300), Duration::from_secs(600)));
        let json = serde_json::to_string(&FetchReport { at: "2026-10-12T10:15:30Z".into(), ok: true, ..FetchReport::default() }).unwrap();
        assert_eq!(json, r#"{"at":"2026-10-12T10:15:30Z","ok":true,"promoted":{},"quarantined":{},"bytes":0,"ms":0}"#);
    }
}
