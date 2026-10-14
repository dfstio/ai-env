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
    /// made and its name does not look like a credential ([`credential_shaped`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wip_ref: Option<String>,
    /// The pack's bytes (0 when nothing was new).
    pub bytes: u64,
    pub ms: u64,
    /// Why it failed, or what it noted: each VM ref [`box_refs`] skipped (a
    /// branch under a [`BOX_RESERVED`] name, one whose box name another
    /// takes), by name; how many [`credential_shaped`] kept out, never by
    /// name ([`hidden_note`]).
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
    /// The manifest's `wip_ref`, unless [`credential_shaped`] kept it out.
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
/// is `None` when the manifest's is one. The user's branches, index and
/// working tree are never touched. First, the incoming refs a process that
/// is gone left are deleted (`sweep_incoming`).
pub fn import(i: &Import<'_>) -> Result<Imported, BridgeError> {
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
    // The pack into the scratch repository, its thin bases from the user's store.
    let mut child = scratch.git().spawn_piped(["index-pack", "--stdin", "--fix-thin"]).map_err(git_failed("git index-pack of the code-out"))?;
    let feeder = child.take_stdin().map(|mut stdin| {
        let pack = i.pack.to_path_buf();
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
    let result = fetched.map_err(git_failed("git fetch of the code-out")).and_then(|_| promote(i, &set, &user, &incoming, &wanted, &existing, out));
    if result.is_err() {
        // Nothing of this import is left behind: its incoming refs go.
        if let Ok(left) = refs_under(&user, &incoming) {
            let delete: String = left.keys().map(|r| format!("delete {r}\n")).collect();
            let _ = user.output_stdin(["update-ref", "--stdin"], delete.as_bytes());
        }
    }
    result
}

/// [`import`] after the fetch: the scans per ref (`set`'s), then the one transaction.
fn promote(i: &Import<'_>, set: &ScanSet, user: &GitRun, incoming: &str, wanted: &BTreeMap<String, String>, existing: &BTreeMap<String, String>, mut out: Imported) -> Result<Imported, BridgeError> {
    use crate::bridge::workspace::blobscan::{scan_objects, scan_settings, tree_entries, CleanCache};
    let WsKind::Git { object_format, .. } = &i.ws.kind;
    let mut cache = CleanCache::open(i.paths, &set.digest, *object_format);
    let haves: Vec<&String> = i.haves.iter().filter(|h| crate::bridge::workspace::holds_commit(user, h).unwrap_or(false)).collect();
    // The Mac's HEAD tree: a settings file the VM did not change is not read again.
    let head_entries: BTreeMap<String, String> = match user.output(["rev-parse", "--verify", "--quiet", "HEAD^{tree}"]) {
        Ok(tree) => tree_entries(user, String::from_utf8_lossy(&tree).trim())?.into_iter().map(|e| (e.path, e.id)).collect(),
        Err(_) => BTreeMap::new(),
    };
    let unchanged = |e: &crate::bridge::workspace::blobscan::TreeEntry| head_entries.get(&e.path) == Some(&e.id);
    let mut moves: Vec<(String, String)> = Vec::new();
    for (suffix, id) in wanted {
        let mut args = vec!["rev-list".to_string(), "--objects".into(), id.clone(), "--not".into()];
        args.extend(haves.iter().map(|h| (*h).clone()));
        let listed = user.output(&args).map_err(git_failed("git rev-list of a fetched ref"))?;
        let list: Vec<crate::bridge::workspace::pack::Listed> = String::from_utf8_lossy(&listed)
            .lines()
            .filter_map(|l| {
                let (oid, path) = match l.split_once(' ') {
                    Some((o, p)) => (o, Some(p.to_string())),
                    None => (l, None),
                };
                object_format.is_id(oid).then(|| crate::bridge::workspace::pack::Listed { id: oid.to_string(), path })
            })
            .collect();
        let box_name = format!("{BOX_REFS}{suffix}");
        let tree = format!("{id}^{{tree}}");
        let mut report = scan_objects(user, &list, set, &mut cache, i.max_blob, &[(box_name.clone(), tree.clone())])?;
        let entries = tree_entries(user, &tree)?;
        scan_settings(user, &[(box_name.clone(), entries)], set, &unchanged, &mut report)?;
        if report.findings.is_empty() {
            out.promoted.insert(box_name.clone(), id.clone());
            moves.push((box_name, id.clone()));
        } else {
            let name = format!("{BOX_QUARANTINE_REFS}{suffix}");
            out.quarantined.insert(name.clone(), id.clone());
            moves.push((name, id.clone()));
            out.findings.extend(report.findings);
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

/// One code-out fetch (plan §7): under the workspace's fetch lock; a real
/// remote named `box` refused; `POST /codeout` with the haves
/// ([`haves_of`]) into a scratch file; then [`import`]. A 204 is nothing
/// new. The workspace row and the audit (`codeout_fetch`, with how many refs
/// [`credential_shaped`] kept out, never a name; `box_fetch_finding` per
/// quarantined ref) record it.
pub async fn fetch<A: MicrovmApi, D: DataPlane, T: TokenSource>(ctx: &CodeoutCtx<A, D, T>, opts: FetchOpts) -> Result<FetchReport, BridgeError> {
    let started = std::time::Instant::now();
    let _lock = crate::bridge::vm::lock::lock_exclusive(&ctx.paths.workspace_fetch_lock(&ctx.ws.slug), FETCH_LOCK_BUDGET, "the workspace's fetch lock").await?;
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
    let req = CodeoutRequest { path: ctx.ws.vm_root.clone(), haves: haves.clone(), wip: opts.wip, max_bytes: opts.max_bytes };
    let dest = scratch.dir().join("codeout.pack");
    let x = Exchange { api: &*ctx.api, tokens: &*ctx.tokens, vm_id: &ctx.target.vm_id, port: CODE_PORT, route: "POST /codeout", deadline: None, idempotent: false };
    let (reply, verdict) = exchange(&x, |t| {
        let (req, dest) = (&req, &dest);
        async move { ctx.dp.post_codeout(&ctx.target, &t, req, dest, opts.max_bytes).await }
    })
    .await?;
    let ms = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let body = match (reply.status, verdict, reply.body) {
        (204, _, _) => {
            let report = FetchReport { at: rfc3339_utc(unix_now()), ok: true, ms: ms(), ..FetchReport::default() };
            audit(&ctx.paths, audit_event::CODEOUT_FETCH, &[("vm", ctx.target.vm_id.clone()), ("outcome", "nothing_new".into()), ("ms", report.ms.to_string())]);
            return Ok(report);
        }
        (_, Verdict::Done, Some(body)) => body,
        (status, _, _) => return Err(BridgeError::Protocol(format!("POST /codeout answered HTTP {status} where a pack was due"))),
    };
    let (paths, cfg, ws, manifest) = (ctx.paths.clone(), ctx.cfg.clone(), ctx.ws.clone(), body.manifest.clone());
    let keep = cfg.seed.keep_wip_refs as usize;
    let max_blob = u64::from(cfg.seed.max_blob_mib) * MIB;
    let imported = blocking(move || {
        let imported = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &dest, haves: &haves, max_blob, keep_wip: keep });
        drop(scratch);
        imported
    })
    .await??;
    let mut notes: Vec<String> = imported.skipped.iter().map(|s| format!("skipped {s}")).collect();
    if imported.hidden > 0 {
        notes.push(hidden_note(imported.hidden));
    }
    if let Some(why) = &body.manifest.wip_skipped {
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
        bytes: body.pack_bytes,
        ms: ms(),
        note: (!notes.is_empty()).then(|| notes.join("; ")),
    };
    record_fetch(ctx, &report, &imported).await;
    Ok(report)
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
/// and the audit of one fetch (best effort).
async fn record_fetch<A, D, T>(ctx: &CodeoutCtx<A, D, T>, report: &FetchReport, imported: &Imported) {
    let now = unix_now();
    let newest_wip = report.promoted.keys().filter(|n| n.starts_with(&format!("{BOX_REFS}wip/"))).max().cloned();
    let (paths, ws, vm, tips) = (ctx.paths.clone(), ctx.ws.clone(), ctx.target.vm_id.clone(), imported.tips.clone());
    let found: Vec<rows::FindingRow> = imported.findings.iter().map(|f| rows::FindingRow { location: f.location.clone(), object: f.object.clone(), rule: f.rule.clone(), key: f.key.clone(), at: now }).collect();
    let result = rows::write_off_thread(move || {
        rows::update(&paths, &ws, |row| {
            row.last_fetch_at = Some(now);
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
/// out what the session's closing suspend waits on ([`TriggerWatch`]).
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
    /// outside a runtime: every report then says so).
    #[must_use]
    pub fn spawn<A: MicrovmApi + 'static, D: DataPlane + 'static, T: TokenSource + 'static>(ctx: CodeoutCtx<A, D, T>) -> CodeoutTrigger {
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
        drop(st);
        self.shared.wake.notify_one();
    }

    /// The last fetch's report; `None` before any ended.
    #[must_use]
    pub fn last(&self) -> Option<FetchReport> {
        self.shared.state().last.clone()
    }

    /// At the wrapper's close: no new fetch starts; a running one gets at
    /// most `within` ([`CLOSE_WAIT`]), then is abandoned (logged): its
    /// promotion is one transaction, so the box refs never move half-way,
    /// and what an import cut short by the process's exit leaves (its
    /// incoming refs, its scratch directories) the next import removes. Once
    /// it ended, or is abandoned, the trigger is done ([`TriggerWatch`]). The
    /// last report.
    pub async fn close(mut self, within: Duration) -> Option<FetchReport> {
        self.shared.state().closed = true;
        self.shared.wake.notify_one();
        self.shared.closing.notify_waiters();
        self.shared.changed.notify_waiters();
        if let Some(mut task) = self.task.take() {
            if tokio::time::timeout(within, &mut task).await.is_err() {
                tracing::info!(within_ms = u64::try_from(within.as_millis()).unwrap_or(u64::MAX), "code-out: the fetch still running at the close was given up");
                task.abort();
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

/// The trigger's task: a session's start capture once it is named, one
/// fetch per wake while asked (then a turn's capture), until closed. Each
/// piece of work is `busy` from its taking (under the state's lock, so a
/// close sees it or none starts) to its end.
async fn run<A: MicrovmApi, D: DataPlane, T: TokenSource>(ctx: CodeoutCtx<A, D, T>, shared: Arc<TriggerShared>) {
    use crate::bridge::settings_capture::CapturePhase;
    let _gone = TaskGone(Arc::clone(&shared));
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
            Work::Fetch(asked) => asked,
        };
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
        shared.idle(false);
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
    /// from the one before (every capture is written).
    struct SettingsVm {
        hold: bool,
        gets: std::sync::atomic::AtomicUsize,
        gate: Option<tokio::sync::Semaphore>,
        changing: bool,
    }

    fn settings_vm(hold: bool) -> SettingsVm {
        SettingsVm { hold, gets: std::sync::atomic::AtomicUsize::new(0), gate: None, changing: false }
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

        async fn put_transcript(&self, _: &AgentTarget, _: &crate::bridge::api::AuthToken, _: &str, _: &Path, _: u64) -> Result<crate::bridge::dataplane::DpReply<crate::wire::workspace::TranscriptReply>, BridgeError> {
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
    /// the fetch running, it is done once the fetch ends, or at `CLOSE_WAIT`
    /// when the fetch is given up. Without a runtime it is done from the start.
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
        // A fetch held at the lock, given up at the close's bound.
        let held = crate::bridge::vm::lock::try_lock_exclusive(&lock).unwrap().expect("the test holds the fetch lock");
        let trigger = CodeoutTrigger::spawn(ctx);
        let watch = trigger.watch();
        trigger.request();
        assert!(tokio::time::timeout(quick, watch.wait_done()).await.is_err(), "a fetch runs: not done");
        let t = std::time::Instant::now();
        let (done, _) = tokio::join!(tokio::time::timeout(bound, watch.wait_done()), trigger.close(CLOSE_WAIT));
        assert!(done.is_ok(), "the fetch given up: done (a task gone marks it)");
        assert!(t.elapsed() >= CLOSE_WAIT && t.elapsed() < CLOSE_WAIT + Duration::from_secs(2), "done once the fetch was given up: {:?}", t.elapsed());
        assert!(watch.done());
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
        let req = CodeoutRequest { path: "/w".into(), haves, wip: true, max_bytes: 1 };
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
    /// named as ai-env and people name them do not.
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
