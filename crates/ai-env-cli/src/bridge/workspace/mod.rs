//! The S8 workspace data plane, the Mac's side (plan §5): `resolve` (the git
//! repository under the roots, its NFC VM path, its slug and HEAD; D6 refuses
//! a workspace that is not a git repository), `prepare` (the WIP snapshot and
//! the scan's warm-up, local only) and `ensure_workspace` (the seed, D3's
//! fast-forward or keep, through the data plane), plus the resume's
//! transcript upload. The module is `workspace` because `bridge::seed` is S2's
//! transcript seeder. Built in S8 wave 1 (W4).
//!
//! The API the remote session (W2), `vm warm` and `box` call was frozen in
//! S8 phase 0: the types below, [`resolve`], [`prepare`] (and the wrapper's
//! [`prepare_cancellable`]), [`ensure_workspace`] and [`ensure_transcript`].
//! D3's decision is the pure [`decide`]. The Mac's own refusal and failure
//! codes are [`code`]'s (the VM's are `wire::workspace::refusal`'s); the
//! pieces are [`snapshot`] (the WIP), [`pack`] (the shallow transport),
//! [`blobscan`] (the scans), [`rows`] (`state/workspaces/`) and
//! [`transcript`] (the resume's upload). Every function keeps to the
//! session's contract: nothing on stderr but through the voice, git and the
//! scans off the runtime's thread (`blocking`), cancel-safe (a dropped
//! future leaves nothing that breaks the next call: the scratch
//! repositories go with what holds them, the locks with their descriptors),
//! its own seed lock and never `<slug>.lock`, back by the deadline.
pub mod blobscan;
pub mod pack;
pub mod rows;
pub mod snapshot;
pub mod transcript;

use crate::bridge::agent::AgentTarget;
use crate::bridge::api::MicrovmApi;
use crate::bridge::config::{BridgeConfig, Paths, WorkspaceCfg};
use crate::bridge::dataplane::{exchange, DataPlane, Exchange, TokenSource, Verdict};
use crate::bridge::errors::BridgeError;
use crate::bridge::remote::audit_event;
use crate::bridge::route::cwd_under_roots;
use crate::bridge::vm::registry::VmRow;
use crate::bridge::voice;
use crate::gitrun::{GitError, GitRun};
use crate::wire::frame::CAP_WORKSPACE_V1;
use crate::wire::slug::project_dir_name;
use crate::wire::workspace::{branch_check, refusal, vm_path_of, ObjectFormat, SeedApplied, SeedManifest, SeedMode, SeedQuery, SeedState, CODE_PORT, HEADS_PREFIX};
use serde::Serialize;
use snapshot::line;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The codes of the Mac's own workspace errors: `BridgeError::WorkspaceRefused`
/// (exit 9) and `WorkspaceFailed` (exit 1). The VM's refusals carry the
/// shim's codes (`wire::workspace::refusal`), never one of these; a Mac git
/// run that fails carries the wire's `git_failed` or `timeout`. W2 turns
/// [`NOT_A_GIT_REPO`](code::NOT_A_GIT_REPO) and [`FINDING`](code::FINDING) into
/// their `remote::Failure` kinds (`Failure::from_error`).
pub mod code {
    /// Refused: the workspace is not a git repository (D6; nothing leaves the Mac).
    pub const NOT_A_GIT_REPO: &str = "not_a_git_repo";
    /// Refused: the repository's top level is not under `[workspaces].roots`.
    pub const OUTSIDE_ROOTS: &str = "outside_roots";
    /// Failed: a repository the seed cannot carry: shallow, bare, an unborn
    /// HEAD, a partial clone, a sparse checkout.
    pub const UNSUPPORTED_REPO: &str = "unsupported_repo";
    /// Refused: a scan finding in what the seed would carry (a tripwire, D8's
    /// repo settings, L9's dotenv rule). The message's first line is the
    /// finding `remote::Failure::Finding` shows (the location, the rule, the
    /// key; never a value), the next lines the others (at most 20 in all).
    pub const FINDING: &str = "finding";
    /// Refused: the uncommitted changes are over a `[seed]` cap (their new
    /// bytes, one file, the untracked files): the message names the five largest.
    pub const WIP_TOO_LARGE: &str = "wip_too_large";
    /// Failed: the wrapper's seed cannot be done by its deadline (T0 + 50 s):
    /// the message names `ai-env vm warm` and `ai-env box seed`.
    pub const TOO_SLOW_FOR_INIT: &str = "too_slow_for_init";
    /// Failed: a phase-0 stub (`<what>: not built yet (<wave>)`; S8 wave 2
    /// built the last one, the settings capture).
    pub const NOT_BUILT: &str = "not_built";
    /// Every code above.
    pub const ALL: [&str; 7] = [NOT_A_GIT_REPO, OUTSIDE_ROOTS, UNSUPPORTED_REPO, FINDING, WIP_TOO_LARGE, TOO_SLOW_FOR_INIT, NOT_BUILT];
}

// ---- the workspace -----------------------------------------------------------------------

/// A workspace as the Mac resolved it: where it is on the Mac and in the VM
/// (the identical path, Design A), and what to seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRef {
    /// The canonical cwd (SELECT_VM's key, the spawn's cwd on the Mac's side).
    pub cwd: PathBuf,
    /// The repository's top level (what is seeded).
    pub root: PathBuf,
    /// `cwd` and `root` in their VM form (`wire::workspace::vm_path_of`: UTF-8,
    /// NFC, absolute): the only form sent to the VM, as the seed's path and as
    /// the spawn's cwd.
    pub vm_cwd: String,
    pub vm_root: String,
    /// The extension's slug of `cwd` (`wire::slug::project_dir_name`): S4's
    /// lock name, the row's name, the transcript's directory.
    pub slug: String,
    pub kind: WsKind,
    /// HEAD on the Mac now.
    pub head: Head,
    /// `--branch` (or `[[workspace]].branch`) when it is not the checked-out
    /// branch: its committed state only, never a WIP.
    pub seed_branch: Option<String>,
}

/// What kind of workspace (D6: a git repository only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsKind {
    /// A git repository: its git dir (a worktree's own), its common dir (the
    /// object store the scratch repository's alternates point at), its format.
    Git { git_dir: PathBuf, common_dir: PathBuf, object_format: ObjectFormat },
}

/// HEAD on the Mac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    /// On `name` at `sha`.
    Branch { name: String, sha: String },
    /// Detached at `sha`.
    Detached { sha: String },
}

impl Head {
    /// The commit.
    #[must_use]
    pub fn sha(&self) -> &str {
        match self {
            Head::Branch { sha, .. } | Head::Detached { sha } => sha,
        }
    }

    /// The branch; `None` when detached.
    #[must_use]
    pub fn branch(&self) -> Option<&str> {
        match self {
            Head::Branch { name, .. } => Some(name),
            Head::Detached { .. } => None,
        }
    }
}

/// The caps one seed runs under (`[seed]`, D2, D7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedLimits {
    /// The most the seed's body (the manifest line and the pack) may hold.
    pub max_bytes: u64,
    /// The largest object it carries (a larger blob is a finding).
    pub max_blob_bytes: u64,
    /// The most new bytes the uncommitted changes add (more: exit 9, the
    /// five largest files named).
    pub max_wip_bytes: u64,
    /// The most untracked files the uncommitted changes carry.
    pub max_untracked_files: u32,
}

const MIB: u64 = 1024 * 1024;

impl SeedLimits {
    /// The wrapper's own seed, inside Cursor's 60 s initialize window:
    /// `[seed].wrapper_inline_mib` (a larger one is left to `box seed`, `vm
    /// warm` and the prewarm).
    #[must_use]
    pub fn wrapper(cfg: &BridgeConfig) -> SeedLimits {
        SeedLimits::with_max(cfg, cfg.seed.wrapper_inline_mib)
    }

    /// `box seed`, `vm warm` and the prewarm: `--max-mib` when given, else
    /// `[seed].max_mib`.
    #[must_use]
    pub fn cli(cfg: &BridgeConfig, max_mib: Option<u32>) -> SeedLimits {
        SeedLimits::with_max(cfg, max_mib.unwrap_or(cfg.seed.max_mib))
    }

    fn with_max(cfg: &BridgeConfig, max_mib: u32) -> SeedLimits {
        let s = &cfg.seed;
        SeedLimits { max_bytes: u64::from(max_mib) * MIB, max_blob_bytes: u64::from(s.max_blob_mib) * MIB, max_wip_bytes: u64::from(s.max_wip_mib) * MIB, max_untracked_files: s.max_untracked_files }
    }
}

/// The workspace at `cwd` as the remote path sees it: the canonical cwd and
/// the repository's top level, its VM form, its slug and HEAD, `branch`
/// (`--branch`) when given. Refused: not a git repository (D6, exit 9 at
/// once: `WorkspaceRefused { code::NOT_A_GIT_REPO }`); a top level outside
/// `[workspaces].roots` (`WorkspaceRefused { code::OUTSIDE_ROOTS }`, exit 9);
/// shallow, bare, an unborn HEAD, a partial clone, a sparse checkout
/// (`WorkspaceFailed { code::UNSUPPORTED_REPO }`, exit 1, one line). An
/// operation in progress, submodules, nested repositories and LFS pointers
/// are noted, not carried. Local only: no AWS call, no Touch ID.
pub fn resolve(cfg: &BridgeConfig, cwd: &Path, branch: Option<&str>) -> Result<WorkspaceRef, BridgeError> {
    let cwd = std::fs::canonicalize(cwd).map_err(|e| BridgeError::Config(format!("the workspace {}: {e}", cwd.display())))?;
    if !cwd.is_dir() {
        return Err(BridgeError::Config(format!("the workspace {} is not a directory", cwd.display())));
    }
    let roots = cfg.roots();
    if !cwd_under_roots(&cwd, &roots) {
        return Err(BridgeError::WorkspaceRefused { code: code::OUTSIDE_ROOTS, message: format!("{} is outside [workspaces].roots", cwd.display()) });
    }
    // git never looks above the outermost root that holds the workspace: a repository higher up is not this
    // workspace's. Its messages in English: D6 is told by what git says.
    let mut git = GitRun::mac(&cwd).env("LC_ALL", "C");
    if let Some(ceiling) = ceiling_of(&cwd, &roots) {
        git = git.env("GIT_CEILING_DIRECTORIES", ceiling);
    }
    let inside = match git.output(["rev-parse", "--is-inside-work-tree"]) {
        Ok(out) => line(&out),
        Err(GitError::Failed { stderr, .. }) if stderr.contains("not a git repository") => {
            return Err(BridgeError::WorkspaceRefused { code: code::NOT_A_GIT_REPO, message: format!("{}: {NOT_A_GIT_REPO_HINT}", cwd.display()) });
        }
        Err(e) => return Err(git_failed("git rev-parse of the workspace")(e)),
    };
    if inside != "true" {
        let bare = git.output(["rev-parse", "--is-bare-repository"]).map(|o| line(&o) == "true").unwrap_or(false);
        let why = if bare { "is a bare repository: seed a clone with a working tree" } else { "is inside a .git directory: open the working tree instead" };
        return Err(unsupported(&cwd, why));
    }
    let out = git
        .output(["rev-parse", "--path-format=absolute", "--show-toplevel", "--git-dir", "--git-common-dir", "--is-shallow-repository", "--show-object-format"])
        .map_err(git_failed("git rev-parse of the repository"))?;
    let text = String::from_utf8_lossy(&out).into_owned();
    let lines: Vec<&str> = text.lines().collect();
    let [toplevel, git_dir, common_dir, shallow, format] = lines.as_slice() else {
        return Err(BridgeError::WorkspaceFailed { code: refusal::GIT_FAILED, message: format!("git rev-parse of {} answered {} lines, not 5", cwd.display(), lines.len()) });
    };
    let root = std::fs::canonicalize(toplevel).map_err(|e| BridgeError::Config(format!("the repository of {}: {e}", cwd.display())))?;
    if !cwd_under_roots(&root, &roots) {
        return Err(BridgeError::WorkspaceRefused { code: code::OUTSIDE_ROOTS, message: format!("the repository's top level {} is outside [workspaces].roots", root.display()) });
    }
    let object_format = match *format {
        "sha1" => ObjectFormat::Sha1,
        "sha256" => ObjectFormat::Sha256,
        other => return Err(unsupported(&root, &format!("uses the object format {other:?}, which ai-env does not carry"))),
    };
    if *shallow == "true" {
        return Err(unsupported(&root, "is a shallow clone: git fetch --unshallow first"));
    }
    let root_git = GitRun::mac(&root);
    if config_get(&root_git, &["--get", "extensions.partialclone"])?.is_some() || config_get(&root_git, &["--get-regexp", r"^remote\..*\.promisor$"])?.is_some_and(|v| v.lines().any(|l| l.ends_with(" true"))) {
        return Err(unsupported(&root, "is a partial clone (objects are missing): git fetch --refetch first"));
    }
    if config_get(&root_git, &["--bool", "--get", "core.sparsecheckout"])?.as_deref() == Some("true") {
        return Err(unsupported(&root, "has a sparse checkout: git sparse-checkout disable first"));
    }
    let sha = match root_git.output(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]) {
        Ok(out) => line(&out),
        Err(GitError::Failed { code: Some(1), .. }) => return Err(unsupported(&root, "has no commit yet (an unborn HEAD): commit first")),
        Err(e) => return Err(git_failed("git rev-parse of HEAD")(e)),
    };
    let head = match root_git.output(["symbolic-ref", "--quiet", "HEAD"]) {
        Ok(out) => match line(&out).strip_prefix(HEADS_PREFIX) {
            Some(name) => Head::Branch { name: name.to_string(), sha },
            None => Head::Detached { sha },
        },
        Err(GitError::Failed { code: Some(1), .. }) => Head::Detached { sha },
        Err(e) => return Err(git_failed("git symbolic-ref of HEAD")(e)),
    };
    let wanted = branch.map(str::to_string).or_else(|| workspace_cfg_at(cfg, &cwd, &root).and_then(|w| w.branch.clone()));
    let seed_branch = match wanted {
        Some(b) if Some(b.as_str()) != head.branch() => {
            branch_check(&b).map_err(|why| BridgeError::Config(format!("--branch {b:?} {why}")))?;
            if !root_git.succeeds(["show-ref", "--verify", "--quiet", &format!("{HEADS_PREFIX}{b}")]).map_err(git_failed("git show-ref of the branch"))? {
                return Err(BridgeError::Config(format!("--branch {b}: {} has no such branch", root.display())));
            }
            Some(b)
        }
        _ => None,
    };
    let vm_cwd = vm_path_of(&cwd).map_err(|why| unsupported(&cwd, &format!("has a path that {why}")))?;
    let vm_root = vm_path_of(&root).map_err(|why| unsupported(&root, &format!("has a path that {why}")))?;
    let slug = project_dir_name(&cwd).map_err(|e| BridgeError::Config(format!("the workspace {}: {e}", cwd.display())))?;
    for note in repo_notes(Path::new(git_dir), &root) {
        voice::note(&note);
    }
    Ok(WorkspaceRef {
        cwd,
        root,
        vm_cwd,
        vm_root,
        slug,
        kind: WsKind::Git { git_dir: PathBuf::from(git_dir), common_dir: PathBuf::from(common_dir), object_format },
        head,
        seed_branch,
    })
}

/// D6's refusal after the workspace's path: the plan's hint, word for word.
pub const NOT_A_GIT_REPO_HINT: &str = "not a git repository: ai-env seeds git workspaces only; AI_ENV_BRIDGE_LOCAL=1 runs Cursor locally";

/// `WorkspaceFailed { unsupported_repo }` (exit 1): `<path> <why>`.
fn unsupported(path: &Path, why: &str) -> BridgeError {
    BridgeError::WorkspaceFailed { code: code::UNSUPPORTED_REPO, message: format!("{} {why}", path.display()) }
}

/// The parent of the outermost root that holds `cwd` (git's ceiling: a
/// repository above every root is never the workspace's); `None` for `/`.
fn ceiling_of(cwd: &Path, roots: &[&Path]) -> Option<PathBuf> {
    roots.iter().filter_map(|r| std::fs::canonicalize(r).ok()).filter(|r| cwd.starts_with(r)).min_by_key(|r| r.components().count()).and_then(|r| r.parent().map(Path::to_path_buf))
}

/// `git config <args>`: its value, `None` when the key is not set (exit 1).
fn config_get(git: &GitRun, args: &[&str]) -> Result<Option<String>, BridgeError> {
    let mut all = vec!["config"];
    all.extend_from_slice(args);
    match git.output(&all) {
        Ok(out) => Ok(Some(line(&out))),
        Err(GitError::Failed { code: Some(1), .. }) => Ok(None),
        Err(e) => Err(git_failed("git config")(e)),
    }
}

/// Whether `git`'s repository holds the commit `id` (a tag of one counts):
/// `rev-parse --verify --quiet --end-of-options <id>^{commit}` exits 0, and 1
/// for an object the store lacks or one that is no commit. Not `cat-file -e
/// <id>^{commit}`: git (2.54, 2.56) exits 128 there for an object it lacks,
/// which [`GitRun::succeeds`] takes for a failure.
pub(crate) fn holds_commit(git: &GitRun, id: &str) -> Result<bool, GitError> {
    git.succeeds(["rev-parse", "--verify", "--quiet", "--end-of-options", &format!("{id}^{{commit}}")])
}

/// What a seed of this repository leaves behind, said once: an operation in
/// progress (its state stays on the Mac; the files are carried), submodules
/// (never carried), LFS files (carried as their pointers).
fn repo_notes(git_dir: &Path, root: &Path) -> Vec<String> {
    let mut notes = Vec::new();
    let ops = [("MERGE_HEAD", "a merge"), ("CHERRY_PICK_HEAD", "a cherry-pick"), ("REVERT_HEAD", "a revert"), ("rebase-merge", "a rebase"), ("rebase-apply", "a rebase or git am"), ("BISECT_LOG", "a bisect")];
    if let Some((_, what)) = ops.iter().find(|(f, _)| git_dir.join(f).exists()) {
        notes.push(format!("{} has {what} in progress: its files are carried, the operation stays on this Mac", root.display()));
    }
    if root.join(".gitmodules").is_file() {
        notes.push(format!("{} has submodules: they are not carried", root.display()));
    }
    if std::fs::read_to_string(root.join(".gitattributes")).is_ok_and(|t| t.contains("filter=lfs")) {
        notes.push(format!("{} uses Git LFS: LFS files are carried as their pointers", root.display()));
    }
    notes
}

/// The `[[workspace]]` table of `ws`: the deepest one whose path holds its
/// cwd (its root's when none does), as `seed_wip`, `branch` and
/// `trust_repo_settings` read it.
#[must_use]
pub fn workspace_cfg<'a>(cfg: &'a BridgeConfig, ws: &WorkspaceRef) -> Option<&'a WorkspaceCfg> {
    workspace_cfg_at(cfg, &ws.cwd, &ws.root)
}

fn workspace_cfg_at<'a>(cfg: &'a BridgeConfig, cwd: &Path, root: &Path) -> Option<&'a WorkspaceCfg> {
    let deepest = |p: &Path| {
        cfg.workspace_overrides
            .iter()
            .filter_map(|w| std::fs::canonicalize(&w.path).ok().map(|c| (c, w)))
            .filter(|(c, _)| p.starts_with(c))
            .max_by_key(|(c, _)| c.components().count())
            .map(|(_, w)| w)
    };
    deepest(cwd).or_else(|| deepest(root))
}

/// A git failure as the data plane's error: `WorkspaceFailed` with the
/// wire's `timeout` for a run past its budget, else `git_failed`, naming `what`.
pub(crate) fn git_failed(what: &str) -> impl FnOnce(GitError) -> BridgeError + '_ {
    move |e| {
        let code = if matches!(e, GitError::Timeout { .. }) { refusal::TIMEOUT } else { refusal::GIT_FAILED };
        BridgeError::WorkspaceFailed { code, message: format!("{what}: {e}") }
    }
}

/// Run `f` on a blocking thread (git and the scans never run on the runtime's).
pub(crate) async fn blocking<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> Result<R, BridgeError> {
    tokio::task::spawn_blocking(f).await.map_err(|e| BridgeError::Io(std::io::Error::other(format!("a blocking workspace step failed: {e}"))))
}

/// One audit row of the data plane (`remote::audit_event`), its actor this
/// process's voice; one that cannot be written is a warning, never fatal.
pub(crate) fn audit(paths: &Paths, event: &str, pairs: &[(&str, String)]) {
    let mut detail = crate::bridge::audit::detail(pairs);
    let actor = match voice::voice() {
        voice::Voice::Cli => "cli",
        voice::Voice::Wrapper => "wrapper",
    };
    detail.insert("actor".into(), actor.into());
    if let Err(e) = crate::bridge::audit::append(&paths.audit(), &crate::bridge::audit::AuditRow::new(event, None, detail)) {
        voice::warn(&format!("audit row {event} not written: {e}"));
    }
}

/// Nothing goes to a VM whose caps lack `workspace_v1` (L5).
pub(crate) fn require_capability(caps: &[String], vm: &str) -> Result<(), BridgeError> {
    if caps.iter().any(|c| c == CAP_WORKSPACE_V1) {
        Ok(())
    } else {
        Err(BridgeError::NoCapability { cap: CAP_WORKSPACE_V1, message: format!("{vm} names no {CAP_WORKSPACE_V1} in its caps") })
    }
}

/// What [`prepare`] built for [`ensure_workspace`]: the WIP snapshot (D2) in
/// its scratch repository under `state/tmp/` and the first seed's objects,
/// listed and scanned. Opaque; dropping it removes the scratch repository.
#[derive(Debug)]
pub struct PreparedSeed {
    scratch: snapshot::Scratch,
    /// The commit the VM checks out: HEAD, or `--branch`'s tip.
    head: String,
    /// The branch it checks out; `None`: detached.
    branch: Option<String>,
    wip: Option<snapshot::Wip>,
    /// The first seed's objects (D7), every one scanned.
    list: pack::ObjectList,
    set: blobscan::ScanSet,
    scan: blobscan::ScanReport,
    /// What the snapshot and the scans left behind.
    notes: Vec<String>,
    /// `HEAD`, `wip` and `index` as a finding names them, with their trees.
    labels: Vec<(String, String)>,
}

/// What [`PreparedSeed::summary`] shows (`box seed --dry-run --json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreparedSummary {
    pub head: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub detached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wip: Option<WipSummary>,
    /// The first seed's objects, of them found clean in the cache, the bytes read.
    pub objects: u64,
    pub cached: u64,
    pub scanned_bytes: u64,
    pub settings_files: u32,
    pub trust_repo_settings: bool,
    pub notes: Vec<String>,
}

/// The WIP as [`PreparedSummary`] shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WipSummary {
    pub commit: String,
    pub tree: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_commit: Option<String>,
    pub index_tree: String,
    pub changed: u32,
    pub untracked: u32,
    pub new_bytes: u64,
}

impl PreparedSeed {
    /// What the seed carries, for the CLI.
    #[must_use]
    pub fn summary(&self) -> PreparedSummary {
        PreparedSummary {
            head: self.head.clone(),
            branch: self.branch.clone(),
            detached: self.branch.is_none(),
            wip: self.wip.as_ref().map(|w| WipSummary {
                commit: w.commit.clone(),
                tree: w.tree.clone(),
                index_commit: w.index_commit.clone(),
                index_tree: w.index_tree.clone(),
                changed: w.changed,
                untracked: w.untracked,
                new_bytes: w.new_bytes,
            }),
            objects: self.scan.objects,
            cached: self.scan.cached,
            scanned_bytes: self.scan.bytes,
            settings_files: self.scan.settings_files,
            trust_repo_settings: !self.set.repo_settings,
            notes: self.notes.clone(),
        }
    }

    /// The first seed's manifest (D7: the head shallow, no history).
    fn first_manifest(&self) -> SeedManifest {
        let mut m = SeedManifest {
            v: SeedManifest::V,
            object_format: self.scratch.format(),
            branch: self.branch.clone(),
            detached: self.branch.is_none(),
            head: self.head.clone(),
            wip: self.wip.as_ref().map(|w| w.commit.clone()),
            index: self.wip.as_ref().and_then(|w| w.index_commit.clone()),
            shallow: vec![self.head.clone()],
            refs: BTreeMap::new(),
        };
        m.refs = m.expected_refs();
        m
    }

    /// The first seed's body (a clone or a replace) into the scratch
    /// directory, at most `max` bytes (`None` past it).
    pub(crate) fn first_body(&self, max: u64) -> Result<Option<pack::SeedBody>, BridgeError> {
        pack::write_body(&self.scratch, &self.first_manifest(), &self.list, max)
    }

    /// D3's ancestry of the VM's tip `tip` and seeded commit `seeded` in the
    /// Mac's repository (through the scratch repository's alternates), over
    /// the whole graph. A commit the Mac lacks (the agent's, until a code-out
    /// brings it) is not known, never a failure ([`holds_commit`]).
    fn ancestry(&self, tip: &str, seeded: &str) -> Result<Ancestry, BridgeError> {
        let git = self.scratch.git();
        let format = self.scratch.format();
        let known = |id: &str| -> Result<bool, BridgeError> { Ok(format.is_id(id) && holds_commit(&git, id).map_err(git_failed("git rev-parse of a commit"))?) };
        let ancestor = |a: &str, b: &str| -> Result<bool, BridgeError> { git.succeeds(["merge-base", "--is-ancestor", a, b]).map_err(git_failed("git merge-base --is-ancestor")) };
        let tip_known = known(tip)?;
        let seeded_known = known(seeded)?;
        let (tip_in_head, head_in_tip) = if tip_known { (ancestor(tip, &self.head)?, ancestor(&self.head, tip)?) } else { (false, false) };
        Ok(Ancestry { tip_known, tip_in_head, head_in_tip, seeded_known })
    }

    /// An update's body (D3): what the VM at `tip`, seeded at `seeded` and
    /// shallow at `boundary`, lacks, every object of it scanned before the
    /// pack is written.
    fn update_body(&self, paths: &Paths, tip: &str, seeded: &str, boundary: &[String], lim: &SeedLimits) -> Result<Built, BridgeError> {
        let Some(plan) = pack::update_objects(&self.scratch, &self.head, self.wip.as_ref(), tip, seeded, boundary)? else {
            return Ok(Built::NoUpdate);
        };
        let mut cache = blobscan::CleanCache::open(paths, &self.set.digest, self.scratch.format());
        let report = blobscan::scan_objects(&self.scratch.git(), &plan.list.objects, &self.set, &mut cache, lim.max_blob_bytes, &self.labels)?;
        if let Some(refused) = report.refusal() {
            return Ok(Built::Refused(refused));
        }
        let mut m = self.first_manifest();
        m.shallow = plan.shallow;
        Ok(match pack::write_body(&self.scratch, &m, &plan.list, lim.max_bytes)? {
            Some(body) => Built::Body(body),
            None => Built::OverCap,
        })
    }
}

/// What building a seed's body came to.
#[derive(Debug)]
enum Built {
    Body(pack::SeedBody),
    /// Past the seed's cap (`SeedLimits::max_bytes`).
    OverCap,
    /// An update's own objects (its history) hold a finding.
    Refused(BridgeError),
    /// No update fits the wire (more shallow commits than it carries): the VM keeps its state.
    NoUpdate,
}

/// The local half of a seed, run beside the Touch ID and SELECT_VM: the WIP
/// snapshot in a scratch repository whose alternates point at the user's
/// object store (the user's index, worktree, stash, refs and objects never
/// touched), the outgoing objects listed and the clean-object cache read.
/// No AWS call. Refused: uncommitted changes over a cap
/// (`WorkspaceRefused { code::WIP_TOO_LARGE }`, exit 9), a scan finding
/// (`WorkspaceRefused { code::FINDING }`, exit 9); a git run that fails is
/// `WorkspaceFailed` with the wire's `git_failed` or `timeout` (exit 1). The
/// WIP is carried unless the workspace's `[[workspace]] seed_wip` is false.
pub fn prepare(paths: &Paths, cfg: &BridgeConfig, ws: &WorkspaceRef, lim: &SeedLimits) -> Result<PreparedSeed, BridgeError> {
    let with_wip = workspace_cfg(cfg, ws).is_none_or(|w| w.seed_wip);
    prepare_checked(paths, cfg, ws, lim, with_wip, None)
}

/// [`prepare`], given up once `cancel` is set: its git runs end (their
/// groups killed) and it returns `Io` of kind `Interrupted`, its scratch
/// repository removed. The wrapper's P1 runs it on a blocking thread beside
/// the Touch ID and sets the flag when the start is dropped or fails, so
/// nothing of it runs on into the process's exit. The flag covers this call
/// only: the seed it returns sends without it.
pub fn prepare_cancellable(paths: &Paths, cfg: &BridgeConfig, ws: &WorkspaceRef, lim: &SeedLimits, cancel: Arc<AtomicBool>) -> Result<PreparedSeed, BridgeError> {
    let with_wip = workspace_cfg(cfg, ws).is_none_or(|w| w.seed_wip);
    prepare_checked(paths, cfg, ws, lim, with_wip, Some(cancel))
}

/// [`prepare`] with the WIP carried or not (`box seed --no-wip` overrides
/// `seed_wip`; a `--branch` other than the checked-out one never carries one).
pub(crate) fn prepare_with(paths: &Paths, cfg: &BridgeConfig, ws: &WorkspaceRef, lim: &SeedLimits, with_wip: bool) -> Result<PreparedSeed, BridgeError> {
    prepare_checked(paths, cfg, ws, lim, with_wip, None)
}

/// [`prepare_with`], given up once `cancel` is set ([`prepare_cancellable`]).
fn prepare_checked(paths: &Paths, cfg: &BridgeConfig, ws: &WorkspaceRef, lim: &SeedLimits, with_wip: bool, cancel: Option<Arc<AtomicBool>>) -> Result<PreparedSeed, BridgeError> {
    if let Some(note) = workspace_cfg(cfg, ws).and_then(WorkspaceCfg::deprecation) {
        voice::warn(&note);
    }
    let result = prepare_inner(paths, cfg, ws, lim, with_wip, cancel);
    if let Err(BridgeError::WorkspaceRefused { code, .. }) = &result {
        let mut pairs = vec![("workspace", ws.cwd.display().to_string()), ("code", (*code).to_string()), ("step", "prepare".into())];
        // The process's purpose (`prewarm`, `session`), as on a prewarm's refusal at `resolve` (`vm::cmd`).
        if let Some(purpose) = crate::bridge::vm::cmd::audit_purpose() {
            pairs.push(("purpose", purpose.into()));
        }
        audit(paths, audit_event::SEED_REFUSED, &pairs);
    }
    result
}

fn prepare_inner(paths: &Paths, cfg: &BridgeConfig, ws: &WorkspaceRef, lim: &SeedLimits, with_wip: bool, cancel: Option<Arc<AtomicBool>>) -> Result<PreparedSeed, BridgeError> {
    let WsKind::Git { common_dir, object_format, .. } = &ws.kind;
    if cancel.as_ref().is_some_and(|c| c.load(Ordering::SeqCst)) {
        return Err(BridgeError::Io(std::io::Error::new(std::io::ErrorKind::Interrupted, "the seed's preparation was cancelled")));
    }
    let mut scratch = snapshot::Scratch::new(paths, "seed", &common_dir.join("objects"), *object_format)?;
    scratch.cancel_on(cancel);
    let (head, branch) = match &ws.seed_branch {
        Some(b) => {
            let tip = GitRun::mac(&ws.root).output(["rev-parse", "--verify", &format!("{HEADS_PREFIX}{b}^{{commit}}")]).map_err(git_failed("git rev-parse of the branch"))?;
            (line(&tip), Some(b.clone()))
        }
        None => (ws.head.sha().to_string(), ws.head.branch().map(str::to_string)),
    };
    // The rules before the snapshot: a cap's refusal shows a path they match as a finding does.
    let set = blobscan::ScanSet::load(paths, cfg, ws)?;
    let wip = if with_wip && ws.seed_branch.is_none() { snapshot::snapshot(ws, &scratch, lim, &set)? } else { None };
    let git = scratch.git();
    let head_tree = line(&git.output(["rev-parse", "--verify", &format!("{head}^{{tree}}")]).map_err(git_failed("git rev-parse of the head's tree"))?);
    let list = pack::first_seed_objects(&scratch, &head, wip.as_ref())?;
    let mut labels = vec![("HEAD".to_string(), head_tree.clone())];
    if let Some(w) = &wip {
        if w.tree != head_tree {
            labels.push(("wip".into(), w.tree.clone()));
        }
        if w.index_tree != head_tree && w.index_tree != w.tree {
            labels.push(("index".into(), w.index_tree.clone()));
        }
    }
    let mut cache = blobscan::CleanCache::open(paths, &set.digest, *object_format);
    let mut scan = blobscan::scan_objects(&git, &list.objects, &set, &mut cache, lim.max_blob_bytes, &labels)?;
    let mut trees = Vec::new();
    for (label, tree) in &labels {
        trees.push((label.clone(), blobscan::tree_entries(&git, tree)?));
    }
    blobscan::scan_settings(&git, &trees, &set, &|_| false, &mut scan)?;
    if let Some(w) = &wip {
        for (label, entries) in trees.iter().filter(|(l, _)| l != "HEAD") {
            blobscan::scan_dotenv(&git, &set, label, entries, &w.added, &mut scan)?;
        }
    }
    // One finding per object, rule, line and key (a file both staged and in the worktree is one).
    let mut seen = std::collections::BTreeSet::new();
    scan.findings.retain(|f| f.object.is_none() || seen.insert((f.object.clone(), f.rule.clone(), f.line, f.key.clone())));
    if let Some(refused) = scan.refusal() {
        return Err(refused);
    }
    let mut notes = wip.as_ref().map(|w| w.notes.clone()).unwrap_or_default();
    notes.extend(scan.notes.iter().cloned());
    // The cancel covered the preparation; the sends that follow are the caller's to bound.
    scratch.cancel_on(None);
    Ok(PreparedSeed { scratch, head, branch, wip, list, set, scan, notes, labels })
}

// `prepare` runs on a blocking thread and its seed comes back to the runtime (the wrapper's P1, `vm warm`).
const _: fn() = || {
    fn send<T: Send>() {}
    send::<PreparedSeed>();
};

/// What [`ensure_workspace`] and [`ensure_transcript`] work with.
pub struct EnsureCtx<'a, A, D, T> {
    /// GetMicrovm (a 502 or 503 asks whether the VM is gone).
    pub api: &'a A,
    pub dp: &'a D,
    pub tokens: &'a T,
    pub paths: &'a Paths,
    pub cfg: &'a BridgeConfig,
    pub target: &'a AgentTarget,
    /// The VM's caps (its row's, or its `hello_ok`'s): without
    /// `workspace_v1` nothing is sent (`NoCapability`, exit 7).
    pub caps: &'a [String],
    pub ws: &'a WorkspaceRef,
    /// [`SeedLimits::wrapper`] in the wrapper, [`SeedLimits::cli`] elsewhere.
    pub lim: SeedLimits,
    /// Back by then (the wrapper's T0 + 50 s): a seed that cannot make it is
    /// `WorkspaceFailed { code::TOO_SLOW_FOR_INIT }`, naming `vm warm` and `box seed`.
    pub deadline: Option<tokio::time::Instant>,
    /// Where each step is reported (the CLI prints, the wrapper logs).
    pub progress: &'a (dyn Fn(SeedProgress) + Sync),
}

/// What [`ensure_workspace`] is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedWant {
    /// D3: seed a VM never seeded, fast-forward one that is clean, on the same branch and at or behind the commit seeded; keep any other.
    Auto,
    /// `box seed --replace`: check the VM out anew (a pristine VM only, else 409 `not_pristine`).
    Replace,
}

/// A step of a seed, as it happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedProgress {
    /// The WIP snapshot: changed tracked files, untracked files, new bytes.
    Snapshot { changed: u32, untracked: u32, new_bytes: u64 },
    /// The scans: objects scanned, of them found clean in the cache.
    Scanned { objects: u64, cached: u64 },
    /// The pack, built.
    Packed { bytes: u64 },
    /// The body, sent so far.
    Sending { sent: u64, total: u64 },
    /// The VM checked it out.
    Applied,
}

/// What [`ensure_workspace`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// A first seed (or a replace) went in.
    Seeded { head: String, wip: Option<String>, bytes: u64, ms: u64 },
    /// D3: a clean VM fast-forwarded from `from`.
    Updated { from: String, head: String, wip: Option<String>, bytes: u64 },
    /// The VM held this head and WIP already.
    UpToDate { head: String },
    /// D3: the VM keeps its state (`note`: what the operator sees).
    Kept { reason: KeptReason, vm_head: String, note: String },
}

impl EnsureOutcome {
    /// The census's `seed:` word and the `seed` audit row's outcome.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            EnsureOutcome::Seeded { .. } => "seeded",
            EnsureOutcome::Updated { .. } => "updated",
            EnsureOutcome::UpToDate { .. } => "up_to_date",
            EnsureOutcome::Kept { .. } => "kept",
        }
    }
}

/// Why D3 kept the VM's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeptReason {
    /// The VM's checkout has changes of its own (a VM seeded dirty is dirty).
    Dirty,
    /// The VM's tip is ahead of the Mac's head.
    Ahead,
    /// Neither is an ancestor of the other.
    Diverged,
}

impl KeptReason {
    /// The note's and the workspace row's word (`kept`).
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            KeptReason::Dirty => "dirty",
            KeptReason::Ahead => "ahead",
            KeptReason::Diverged => "diverged",
        }
    }
}

/// The rate a seed is estimated at against the wrapper's deadline (plan
/// §5: 4 MB/s, about 16 s for the wrapper's 64 MiB).
pub const SEED_RATE: u64 = 4_000_000;
/// How long a seed waits for the workspace's seed lock when no deadline bounds it.
pub const SEED_LOCK_BUDGET: Duration = Duration::from_secs(600);

/// The note D3's kept state shows (plan §5), naming why.
#[must_use]
pub fn kept_note(reason: KeptReason) -> String {
    format!("the VM keeps its state ({}): ai-env box fetch shows what changed", reason.word())
}

/// The Mac's side of D3: what a seed would check out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacSeed<'a> {
    /// The workspace's root in its VM form.
    pub vm_root: &'a str,
    /// M: the commit to check out.
    pub head: &'a str,
    /// Its branch; `None`: detached.
    pub branch: Option<&'a str>,
    /// The worktree's and the index's trees when they are not M's (the WIP).
    pub wip_tree: Option<&'a str>,
    pub index_tree: Option<&'a str>,
}

/// What the Mac's repository says of the VM's tip (T) and seeded commit (S).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ancestry {
    /// The Mac holds T (a commit the VM made is not known until `box fetch`).
    pub tip_known: bool,
    /// T is M or an ancestor of it; M is an ancestor of T.
    pub tip_in_head: bool,
    pub head_in_tip: bool,
    /// The Mac holds S (an update's negative).
    pub seeded_known: bool,
}

/// D3's verdict on one `GET /seed` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Never seeded: a first seed.
    Clone,
    /// A clean VM at `tip`, an ancestor of M: a thin pack of what it lacks
    /// (it was seeded at `seeded`), then the new WIP applied uncommitted.
    Update { tip: String, seeded: String },
    /// `--replace` of a pristine VM at `tip`.
    Replace { tip: String },
    /// The VM holds this head and WIP: nothing is sent.
    UpToDate,
    /// The VM keeps its state.
    Kept(KeptReason),
    /// Nothing is sent: `WorkspaceRefused { code }` (exit 9).
    Refuse { code: &'static str, message: String },
}

/// D3 (plan §5), pure: the VM never seeded gets a first seed; one seeded at
/// another path is refused (one workspace per VM); the same head, WIP and
/// index trees and branch is up to date; `--replace` needs a pristine VM
/// (409 `not_pristine` otherwise); a clean VM on the same branch whose tip T
/// is M or an ancestor of it gets an update (none when T is M and the Mac has
/// nothing uncommitted: up to date); anything else is kept: a VM with changes
/// of its own (a VM seeded with a WIP is one) is `dirty`, one whose tip the
/// Mac lacks or that M is an ancestor of is `ahead`, any other (another
/// branch, no common line) `diverged`.
#[must_use]
pub fn decide(state: &SeedState, mac: &MacSeed<'_>, ancestry: &Ancestry, want: SeedWant) -> Decision {
    let Some(record) = &state.record else {
        return Decision::Clone;
    };
    if record.path != mac.vm_root {
        return Decision::Refuse { code: refusal::OTHER_WORKSPACE, message: format!("the VM was seeded at {} (one workspace per VM): {} needs a VM of its own", record.path, mac.vm_root) };
    }
    let same = record.head == mac.head && record.wip_tree.as_deref() == mac.wip_tree && record.index_tree.as_deref() == mac.index_tree && record.branch.as_deref() == mac.branch;
    let tip = state.tip.clone();
    if want == SeedWant::Replace {
        return match tip {
            Some(_) if same && state.pristine => Decision::UpToDate,
            Some(tip) if state.pristine => Decision::Replace { tip },
            _ => Decision::Refuse { code: refusal::NOT_PRISTINE, message: "the VM's checkout changed since its seed: --replace takes only a VM unchanged since then (ai-env box fetch shows what changed)".into() },
        };
    }
    if same {
        return Decision::UpToDate;
    }
    let Some(tip) = tip else {
        return Decision::Kept(KeptReason::Diverged);
    };
    if !state.clean {
        return Decision::Kept(KeptReason::Dirty);
    }
    if state.branch.as_deref() != mac.branch {
        return Decision::Kept(KeptReason::Diverged);
    }
    if !ancestry.tip_known {
        return Decision::Kept(KeptReason::Ahead);
    }
    if !ancestry.tip_in_head {
        return Decision::Kept(if ancestry.head_in_tip { KeptReason::Ahead } else { KeptReason::Diverged });
    }
    if tip == mac.head && mac.wip_tree.is_none() && mac.index_tree.is_none() {
        return Decision::UpToDate;
    }
    if !ancestry.seeded_known {
        return Decision::Kept(KeptReason::Diverged);
    }
    Decision::Update { tip, seeded: record.head.clone() }
}

/// Make the VM's checkout the workspace's (after SELECT_VM, beside the gate
/// and the token; before any spawn whose cwd is in the workspace): `GET
/// /seed`, then D3 (a first seed, a fast-forward, up to date, or kept),
/// `PUT /seed` of the shallow pack (D7) with its scanned WIP (D2). Every scan
/// runs before a byte leaves the Mac. Refused: a finding
/// (`WorkspaceRefused { code::FINDING }`, exit 9), uncommitted changes over a
/// cap (`code::WIP_TOO_LARGE`, exit 9), the VM's refusals by the shim's code
/// (`dataplane::verdict`); failed: a seed the deadline cannot fit
/// (`WorkspaceFailed { code::TOO_SLOW_FOR_INIT }`, exit 1), a git run (the
/// wire's `git_failed` or `timeout`, exit 1). Held under the workspace's
/// seed lock (never `<slug>.lock`); a 409 `changed` reads the state once
/// more and decides again; nothing goes to a VM without `workspace_v1`.
pub async fn ensure_workspace<A: MicrovmApi, D: DataPlane, T: TokenSource>(ctx: &EnsureCtx<'_, A, D, T>, prepared: Option<PreparedSeed>, want: SeedWant) -> Result<EnsureOutcome, BridgeError> {
    require_capability(ctx.caps, &ctx.target.vm_id)?;
    let started = std::time::Instant::now();
    let budget = ctx.deadline.map_or(SEED_LOCK_BUDGET, |d| d.saturating_duration_since(tokio::time::Instant::now()).max(Duration::from_millis(1)));
    let _lock = crate::bridge::vm::lock::lock_exclusive(&ctx.paths.workspace_seed_lock(&ctx.ws.slug), budget, "the workspace's seed lock").await?;
    let mut prepared = match prepared {
        Some(p) => p,
        None => {
            let (paths, cfg, ws, lim) = (ctx.paths.clone(), ctx.cfg.clone(), ctx.ws.clone(), ctx.lim);
            blocking(move || prepare(&paths, &cfg, &ws, &lim)).await??
        }
    };
    if let Some(w) = &prepared.wip {
        (ctx.progress)(SeedProgress::Snapshot { changed: w.changed, untracked: w.untracked, new_bytes: w.new_bytes });
    }
    (ctx.progress)(SeedProgress::Scanned { objects: prepared.scan.objects, cached: prepared.scan.cached });
    let mut reread = false;
    loop {
        let state = seed_state(ctx).await?;
        let tip = state.tip.clone();
        let ancestry = match (&state.record, &tip) {
            (Some(r), Some(t)) if r.path == ctx.ws.vm_root => {
                let (t, s) = (t.clone(), r.head.clone());
                let (p, a) = blocking(move || {
                    let a = prepared.ancestry(&t, &s);
                    (prepared, a)
                })
                .await?;
                prepared = p;
                a?
            }
            _ => Ancestry::default(),
        };
        let wip = prepared.wip.as_ref();
        let mac = MacSeed { vm_root: &ctx.ws.vm_root, head: &prepared.head, branch: prepared.branch.as_deref(), wip_tree: wip.and_then(snapshot::Wip::wip_tree), index_tree: wip.and_then(snapshot::Wip::staged_tree) };
        let decision = decide(&state, &mac, &ancestry, want);
        let (mode, expect) = match &decision {
            Decision::UpToDate => {
                let event = seed_event(ctx, &prepared, "up_to_date", 0, &state, None);
                record(ctx, event).await;
                return Ok(EnsureOutcome::UpToDate { head: prepared.head.clone() });
            }
            Decision::Kept(reason) => {
                let event = seed_event(ctx, &prepared, "kept", 0, &state, Some(*reason));
                return Ok(kept(ctx, event, *reason).await);
            }
            Decision::Refuse { code, message } => return Err(refused(ctx, BridgeError::WorkspaceRefused { code, message: message.clone() })),
            Decision::Clone => (SeedMode::Clone, None),
            Decision::Replace { tip } => (SeedMode::Replace, Some(tip.clone())),
            Decision::Update { tip, .. } => (SeedMode::Update, Some(tip.clone())),
        };
        let (paths, lim, ws, vm) = (ctx.paths.clone(), ctx.lim, ctx.ws.clone(), ctx.target.vm_id.clone());
        let d = decision.clone();
        let (p, built) = blocking(move || {
            let built = match &d {
                Decision::Update { tip, seeded } => prepared.update_body(&paths, tip, seeded, &rows::boundary(&paths, &ws, &vm, tip, seeded), &lim),
                _ => prepared.first_body(lim.max_bytes).map(|b| b.map_or(Built::OverCap, Built::Body)),
            };
            (prepared, built)
        })
        .await?;
        prepared = p;
        let body = match built? {
            Built::Body(b) => b,
            Built::OverCap => return Err(refused(ctx, over_cap(ctx))),
            Built::Refused(e) => return Err(refused(ctx, e)),
            Built::NoUpdate => {
                let event = seed_event(ctx, &prepared, "kept", 0, &state, Some(KeptReason::Diverged));
                return Ok(kept(ctx, event, KeptReason::Diverged).await);
            }
        };
        (ctx.progress)(SeedProgress::Packed { bytes: body.len });
        if let Some(deadline) = ctx.deadline {
            let need = Duration::from_millis(body.len.saturating_mul(1000) / SEED_RATE);
            if tokio::time::Instant::now() + need > deadline {
                return Err(too_slow(ctx, body.len));
            }
        }
        let query = SeedQuery { path: ctx.ws.vm_root.clone(), mode, branch: prepared.branch.clone(), detached: prepared.branch.is_none(), expect: expect.clone() };
        (ctx.progress)(SeedProgress::Sending { sent: 0, total: body.len });
        let x = Exchange { api: ctx.api, tokens: ctx.tokens, vm_id: &ctx.target.vm_id, port: CODE_PORT, route: "PUT /seed", deadline: ctx.deadline, idempotent: false };
        let (path, len) = (body.path.clone(), body.len);
        let answer = exchange(&x, |t| {
            let (query, path) = (&query, &path);
            async move { ctx.dp.put_seed(ctx.target, &t, query, path, len).await }
        })
        .await;
        let _ = std::fs::remove_file(&body.path);
        match answer {
            Ok((reply, Verdict::Done)) => {
                (ctx.progress)(SeedProgress::Sending { sent: len, total: len });
                (ctx.progress)(SeedProgress::Applied);
                let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let wip = reply.body.as_ref().and_then(|r| r.wip.clone()).or_else(|| prepared.wip.as_ref().map(|w| w.commit.clone()));
                let outcome = match reply.body.as_ref().map(|r| r.outcome) {
                    Some(SeedApplied::UpToDate) => EnsureOutcome::UpToDate { head: prepared.head.clone() },
                    Some(SeedApplied::Updated) => EnsureOutcome::Updated { from: expect.clone().unwrap_or_default(), head: prepared.head.clone(), wip, bytes: len },
                    _ => EnsureOutcome::Seeded { head: prepared.head.clone(), wip, bytes: len, ms },
                };
                // The boundary the VM's `.git/shallow` gained, and the seed it was planned on: the next update walks its graph.
                let event = rows::SeedEvent { shallow: body.manifest.shallow.clone(), base: state.record.as_ref().map(|r| r.head.clone()), ..seed_event(ctx, &prepared, mode.name(), len, &state, None) };
                record(ctx, event).await;
                audit(ctx.paths, audit_event::SEED, &[("vm", ctx.target.vm_id.clone()), ("outcome", outcome.word().into()), ("mode", mode.name().into()), ("bytes", len.to_string()), ("ms", ms.to_string()), ("workspace", ctx.ws.cwd.display().to_string())]);
                return Ok(outcome);
            }
            Ok((reply, Verdict::Kept { reason, state: vm })) => {
                let _ = reply;
                let event = seed_event(ctx, &prepared, "kept", 0, &vm.unwrap_or(state), Some(reason));
                return Ok(kept(ctx, event, reason).await);
            }
            Ok((_, Verdict::Reread { error })) if !reread => {
                tracing::info!("PUT /seed: {error}; reading the VM's state again");
                reread = true;
            }
            Ok((_, Verdict::Reread { error })) => return Err(refused(ctx, error)),
            Ok((reply, _)) => return Err(BridgeError::Protocol(format!("PUT /seed answered HTTP {} where no seed answer was due", reply.status))),
            Err(e) => return Err(refused(ctx, e)),
        }
    }
}

/// `GET /seed` of the workspace (a 200 with the VM's state, else its error).
async fn seed_state<A: MicrovmApi, D: DataPlane, T: TokenSource>(ctx: &EnsureCtx<'_, A, D, T>) -> Result<SeedState, BridgeError> {
    let x = Exchange { api: ctx.api, tokens: ctx.tokens, vm_id: &ctx.target.vm_id, port: CODE_PORT, route: "GET /seed", deadline: ctx.deadline, idempotent: true };
    match exchange(&x, |t| async move { ctx.dp.seed_state(ctx.target, &t, &ctx.ws.vm_root).await }).await {
        Ok((reply, Verdict::Done)) => reply.body.ok_or_else(|| BridgeError::Protocol("GET /seed answered without a state".into())),
        Ok((reply, _)) => Err(BridgeError::Protocol(format!("GET /seed answered HTTP {} where a state was due", reply.status))),
        Err(e) => Err(refused(ctx, e)),
    }
}

/// D3's kept outcome: recorded (`event`, the VM's state's), audited, its note.
async fn kept<A, D, T>(ctx: &EnsureCtx<'_, A, D, T>, event: rows::SeedEvent, reason: KeptReason) -> EnsureOutcome {
    let vm_head = event.vm_head.clone().unwrap_or_default();
    record(ctx, event).await;
    audit(ctx.paths, audit_event::SEED, &[("vm", ctx.target.vm_id.clone()), ("outcome", "kept".into()), ("kept", reason.word().into()), ("workspace", ctx.ws.cwd.display().to_string())]);
    EnsureOutcome::Kept { reason, vm_head, note: kept_note(reason) }
}

/// `e`, a workspace refusal audited (`seed_refused`) on its way out.
fn refused<A, D, T>(ctx: &EnsureCtx<'_, A, D, T>, e: BridgeError) -> BridgeError {
    if let BridgeError::WorkspaceRefused { code, .. } = &e {
        audit(ctx.paths, audit_event::SEED_REFUSED, &[("vm", ctx.target.vm_id.clone()), ("code", (*code).to_string()), ("workspace", ctx.ws.cwd.display().to_string())]);
    }
    e
}

/// A seed body over its cap: the wrapper's (a deadline bounds it) is left to
/// `vm warm` and `box seed`; the CLI's names its flag.
fn over_cap<A, D, T>(ctx: &EnsureCtx<'_, A, D, T>) -> BridgeError {
    let cap = snapshot::human_bytes(ctx.lim.max_bytes);
    let ws = ctx.ws.cwd.display();
    if ctx.deadline.is_some() {
        BridgeError::WorkspaceFailed { code: code::TOO_SLOW_FOR_INIT, message: format!("the seed is over {cap} ([seed].wrapper_inline_mib): `ai-env vm warm {ws}` or `ai-env box seed {ws}` from a terminal seeds it") }
    } else {
        BridgeError::WorkspaceRefused { code: refusal::TOO_LARGE, message: format!("the seed is over {cap} (box seed --max-mib, [seed].max_mib)") }
    }
}

/// A seed the wrapper's deadline cannot fit at [`SEED_RATE`].
fn too_slow<A, D, T>(ctx: &EnsureCtx<'_, A, D, T>, bytes: u64) -> BridgeError {
    let ws = ctx.ws.cwd.display();
    BridgeError::WorkspaceFailed {
        code: code::TOO_SLOW_FOR_INIT,
        message: format!("the seed of {} does not fit Cursor's 60 s window at 4 MB/s: `ai-env vm warm {ws}` or `ai-env box seed {ws}` from a terminal seeds it", snapshot::human_bytes(bytes)),
    }
}

/// What the workspace row records of a seed's decision.
fn seed_event<A, D, T>(ctx: &EnsureCtx<'_, A, D, T>, prepared: &PreparedSeed, mode: &str, bytes: u64, state: &SeedState, kept: Option<KeptReason>) -> rows::SeedEvent {
    let wip = prepared.wip.as_ref();
    rows::SeedEvent {
        vm: ctx.target.vm_id.clone(),
        mode: mode.to_string(),
        head: prepared.head.clone(),
        branch: prepared.branch.clone(),
        wip: wip.map(|w| w.commit.clone()),
        wip_tree: wip.and_then(snapshot::Wip::wip_tree).map(str::to_string),
        index_tree: wip.and_then(snapshot::Wip::staged_tree).map(str::to_string),
        bytes,
        objects: prepared.scan.objects,
        cached: prepared.scan.cached,
        digest: prepared.set.digest.clone(),
        vm_head: state.tip.clone(),
        vm_clean: state.clean,
        kept: kept.map(|k| k.word().to_string()),
        shallow: Vec::new(),
        base: None,
    }
}

/// The workspace row after a seed's decision, written off the runtime's
/// thread within `rows::ROWS_WAIT` (best effort: a row that cannot be
/// written is a warning).
async fn record<A, D, T>(ctx: &EnsureCtx<'_, A, D, T>, event: rows::SeedEvent) {
    let (paths, ws) = (ctx.paths.clone(), ctx.ws.clone());
    if let Err(e) = rows::write_off_thread(move || rows::record_seed(&paths, &ws, &event)).await {
        voice::warn(&format!("the workspace row of {} was not written: {e}", ctx.ws.cwd.display()));
    }
}

/// What [`ensure_transcript`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptOutcome {
    /// The Mac's mirror went up (`files`: the transcript and its subtree).
    Uploaded { files: u32, bytes: u64 },
    /// The VM's copy is the Mac's.
    AlreadyThere,
    /// The VM's copy is longer: it wins (409 `vm_longer`).
    VmLonger { vm: u64, mac: u64 },
    /// The Mac holds no copy of the session.
    NoMacCopy,
}

impl TranscriptOutcome {
    /// The census's `transcript:` word and the `transcript_put` audit row's.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            TranscriptOutcome::Uploaded { .. } => "uploaded",
            TranscriptOutcome::AlreadyThere => "already_there",
            TranscriptOutcome::VmLonger { .. } => "vm_longer",
            TranscriptOutcome::NoMacCopy => "no_mac_copy",
        }
    }
}

/// Before a `--resume <session_id>` spawn (plan §8, in the workspace's
/// branch of P3): the Mac's mirror of the session (`seed::candidates` under
/// `mirror_root` for `slugs`, walked by the S2 seeder's rules: symlinks
/// skipped, at most `seed::MAX_SUBTREE_DEPTH` levels, `remote::TRANSCRIPT_MAX`
/// in all) goes to the VM's projects directory under `vm_slug` (the one the
/// VM's claude reads: the slug of the workspace's VM cwd, or a
/// `CLAUDE_CODE_PROJECT_DIR_NAME` the session forwards), each file stat'ed
/// first and put only when the VM's copy is absent, shorter, or different at
/// equal length. A file whose rel `wire::workspace::transcript_rel_check`
/// refuses (one directly below `<uuid>/`, or one not `.jsonl` or `.json`) is
/// skipped, never sent; the skips are logged with their count. A 409
/// `vm_longer` is the VM's copy winning (`dataplane::Verdict::VmLonger`),
/// never an error. As every data-plane call: nothing goes to a VM whose
/// `ctx.caps` lack `workspace_v1`, a 502 or 503 asks `ctx.api`'s GetMicrovm,
/// and the call is back by `ctx.deadline`. Every file and its name go
/// through the seed's tripwires first (`transcript::scan_copy`: the
/// built-ins plus `[review].tripwires`). A name's finding refuses before any
/// request; a finding in a file the VM lacks, or holds shorter or
/// different, refuses before the first `PUT` (a file the VM holds already is
/// never sent, so what it holds is no finding). Either is
/// `WorkspaceRefused { finding }` (exit 9, audited `seed_refused` with step
/// `transcript` and the VM), and none of the transcript is sent. A `PUT`
/// sends a private copy of exactly the bytes scanned
/// (`state/tmp/transcript-<pid>-*`, removed with the upload).
pub async fn ensure_transcript<A: MicrovmApi, D: DataPlane, T: TokenSource>(ctx: &EnsureCtx<'_, A, D, T>, mirror_root: &Path, slugs: &[&str], session_id: &str, vm_slug: &str) -> Result<TranscriptOutcome, BridgeError> {
    transcript::ensure(ctx, mirror_root, slugs, session_id, vm_slug).await
}

// ---- the VM's capability -----------------------------------------------------------------

/// Whether a VM serves the workspace routes, as its row last recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Its caps name `workspace_v1`.
    Yes,
    /// Its caps were read and lack it (an S6 or S7 image): SELECT_VM skips
    /// the row before any Touch ID; a pinned VM is exit 7 naming `make deploy`.
    No,
    /// Never read (`vm run` reads no `/health`): `hello_ok` decides, and every
    /// data-plane call checks again before it sends anything.
    Unknown,
}

/// `row`'s [`Capability`], from `VmRow.caps` (L5).
#[must_use]
pub fn vm_capability(row: &VmRow) -> Capability {
    match &row.caps {
        None => Capability::Unknown,
        Some(caps) if caps.iter().any(|c| c == CAP_WORKSPACE_V1) => Capability::Yes,
        Some(_) => Capability::No,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::FakeMicrovmApi;
    use crate::bridge::config::SeedCfg;
    use crate::bridge::dataplane::Unreached;
    use crate::errors::CliError;
    use crate::wire::frame::CAP_CREDENTIAL_CACHE;
    use crate::wire::redact::Secret;

    #[test]
    fn the_vm_capability_comes_from_the_rows_caps() {
        let with = |caps: Option<&[&str]>| VmRow { caps: caps.map(|c| c.iter().map(|s| (*s).to_string()).collect()), ..VmRow::default() };
        assert_eq!(vm_capability(&with(None)), Capability::Unknown, "never read");
        assert_eq!(vm_capability(&with(Some(&[]))), Capability::No, "an S6 shim");
        assert_eq!(vm_capability(&with(Some(&[CAP_CREDENTIAL_CACHE]))), Capability::No, "an S7 shim (image 7.0)");
        assert_eq!(vm_capability(&with(Some(&[CAP_CREDENTIAL_CACHE, CAP_WORKSPACE_V1]))), Capability::Yes);
        assert_eq!(vm_capability(&with(Some(&["workspace_v2"]))), Capability::No, "only the exact cap");
    }

    /// D3's `known` and the code-out's haves: a commit, or a tag of one, is
    /// held; a tree, a blob and an id the store lacks are not, and none of
    /// them is an error (git exits 128 on `cat-file -e ID^{commit}` for each).
    #[test]
    fn holds_commit_is_no_for_what_the_store_lacks_and_never_an_error() {
        let d = tempfile::tempdir().unwrap();
        let git = GitRun::mac(d.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid");
        git.output(["init", "-q", "-b", "main"]).unwrap();
        git.output(["commit", "-q", "--allow-empty", "-m", "one"]).unwrap();
        git.output(["tag", "-a", "-m", "a tag", "v1"]).unwrap();
        let id = |rev: &str| line(&git.output(["rev-parse", "--verify", rev]).unwrap());
        let blob = line(&git.output_stdin(["hash-object", "-w", "--stdin"], b"a blob\n").unwrap());
        for (what, object, held) in [("a commit", id("HEAD"), true), ("a tag of one", id("v1"), true), ("a tree", id("HEAD^{tree}"), false), ("a blob", blob, false), ("an id the store lacks", "e".repeat(40), false)] {
            assert_eq!(holds_commit(&git, &object).unwrap_or_else(|e| panic!("{what}: {e}")), held, "{what}");
        }
    }

    #[test]
    fn seed_limits_follow_the_seed_table_and_the_flag() {
        let mut cfg = BridgeConfig::default();
        assert_eq!(SeedLimits::wrapper(&cfg), SeedLimits { max_bytes: 64 * MIB, max_blob_bytes: 64 * MIB, max_wip_bytes: 64 * MIB, max_untracked_files: 5000 });
        assert_eq!(SeedLimits::cli(&cfg, None).max_bytes, 512 * MIB);
        assert_eq!(SeedLimits::cli(&cfg, Some(1024)).max_bytes, 1024 * MIB);
        cfg.seed = SeedCfg { wrapper_inline_mib: 8, max_mib: 100, max_blob_mib: 2, max_wip_mib: 3, max_untracked_files: 10, ..SeedCfg::default() };
        assert_eq!(SeedLimits::wrapper(&cfg), SeedLimits { max_bytes: 8 * MIB, max_blob_bytes: 2 * MIB, max_wip_bytes: 3 * MIB, max_untracked_files: 10 });
        assert_eq!(SeedLimits::cli(&cfg, None).max_bytes, 100 * MIB);
    }

    /// The wire's caps are the config's and the S2 seeder's: a seed body of
    /// at most `[seed]`'s largest, a transcript of the seeder's cap at its
    /// depth, a session id checked the registry's way.
    #[test]
    fn the_wires_limits_are_the_configs_and_the_seeders() {
        use crate::wire::workspace as w;
        assert_eq!(w::SEED_BODY_MAX, u64::from(SeedCfg::MIB_MAX) * MIB);
        assert_eq!(w::TRANSCRIPT_MAX, crate::bridge::seed::MAX_SEED_BYTES);
        assert_eq!(w::TRANSCRIPT_DIRS_MAX, crate::bridge::seed::MAX_SUBTREE_DEPTH);
        assert_eq!(w::HAVES_MAX, 256);
        for id in ["0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", "0199A1B2-C3D4-7E5F-8A9B-0C1D2E3F4A5B", "not-a-uuid", ""] {
            assert_eq!(crate::bridge::registry::is_uuid(id), w::is_uuid(id), "{id:?}");
        }
    }

    #[test]
    fn the_words_are_stable() {
        let outcomes = [
            EnsureOutcome::Seeded { head: "h".into(), wip: None, bytes: 1, ms: 1 },
            EnsureOutcome::Updated { from: "f".into(), head: "h".into(), wip: None, bytes: 1 },
            EnsureOutcome::UpToDate { head: "h".into() },
            EnsureOutcome::Kept { reason: KeptReason::Dirty, vm_head: "h".into(), note: String::new() },
        ];
        assert_eq!(outcomes.iter().map(EnsureOutcome::word).collect::<Vec<_>>(), ["seeded", "updated", "up_to_date", "kept"]);
        assert_eq!([KeptReason::Dirty, KeptReason::Ahead, KeptReason::Diverged].map(KeptReason::word), ["dirty", "ahead", "diverged"]);
        let uploads = [TranscriptOutcome::Uploaded { files: 1, bytes: 1 }, TranscriptOutcome::AlreadyThere, TranscriptOutcome::VmLonger { vm: 2, mac: 1 }, TranscriptOutcome::NoMacCopy];
        assert_eq!(uploads.iter().map(TranscriptOutcome::word).collect::<Vec<_>>(), ["uploaded", "already_there", "vm_longer", "no_mac_copy"]);
        let head = Head::Branch { name: "dev".into(), sha: "s".into() };
        assert_eq!((head.sha(), head.branch()), ("s", Some("dev")));
        assert_eq!((Head::Detached { sha: "d".into() }.branch(), Head::Detached { sha: "d".into() }.sha()), (None, "d"));
    }

    fn ws_at(path: &str) -> WorkspaceRef {
        WorkspaceRef {
            cwd: path.into(),
            root: path.into(),
            vm_cwd: path.into(),
            vm_root: path.into(),
            slug: "-w".into(),
            kind: WsKind::Git { git_dir: format!("{path}/.git").into(), common_dir: format!("{path}/.git").into(), object_format: ObjectFormat::Sha1 },
            head: Head::Detached { sha: "a".repeat(40) },
            seed_branch: None,
        }
    }

    /// A VM without `workspace_v1` is sent nothing (exit 7, naming `make
    /// deploy`), before any lock, scan or request; a missing workspace is
    /// exit 1 before git runs.
    #[tokio::test]
    async fn nothing_goes_to_a_vm_without_the_capability() {
        let cfg = BridgeConfig::default();
        let paths = Paths::from_root_and_env(PathBuf::from("/nonexistent/bridge"), None);
        let e = resolve(&cfg, Path::new("/nonexistent"), None).unwrap_err();
        assert!(matches!(e, BridgeError::Config(_)) && e.to_string().contains("/nonexistent"), "{e}");
        let ws = ws_at("/w");
        let api = FakeMicrovmApi::new();
        let target = AgentTarget { vm_id: "microvm-1".into(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false };
        let caps = vec![CAP_CREDENTIAL_CACHE.to_string()];
        let ctx = EnsureCtx { api: &api, dp: &Unreached, tokens: &Unreached, paths: &paths, cfg: &cfg, target: &target, caps: &caps, ws: &ws, lim: SeedLimits::wrapper(&cfg), deadline: None, progress: &|_: SeedProgress| {} };
        for e in [ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap_err(), ensure_transcript(&ctx, Path::new("/nonexistent"), &["-w"], "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", "-w").await.unwrap_err()] {
            assert!(matches!(e, BridgeError::NoCapability { cap: CAP_WORKSPACE_V1, .. }), "{e:?}");
            let text = e.to_string();
            assert!(text.contains("microvm-1") && text.contains("make deploy"), "{text}");
            assert_eq!(CliError::from(e).exit_code(), 7);
        }
        assert!(api.calls().is_empty(), "no control-plane call");
        assert!(matches!(Unreached.token(9418).await, Err(BridgeError::Endpoint(_))));
    }

    /// The Mac's own codes: unique, snake_case, and never one of the shim's
    /// refusal codes, so a code names one thing whichever side said it; the
    /// two the remote session turns into their own failure kinds.
    #[test]
    fn the_macs_workspace_codes_are_unique_and_apart_from_the_shims() {
        use crate::wire::workspace::refusal;
        let codes: std::collections::BTreeSet<&str> = code::ALL.iter().copied().collect();
        assert_eq!(codes.len(), code::ALL.len(), "unique codes");
        for c in code::ALL {
            assert!(!c.is_empty() && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{c}");
            assert!(!refusal::ALL.contains(&c), "{c} is a shim refusal code");
        }
        use crate::bridge::remote::link::StartStep;
        use crate::bridge::remote::Failure;
        let git = BridgeError::WorkspaceRefused { code: code::NOT_A_GIT_REPO, message: "/Users/mike/notes".into() };
        assert_eq!(Failure::from_error(StartStep::Precheck, git, None), Failure::NotGitRepo);
        let found = BridgeError::WorkspaceRefused { code: code::FINDING, message: "untracked .env: rule env-file-plaintext\nrefs/heads/dev:cfg/a.yaml line 3: rule aws-key".into() };
        assert_eq!(Failure::from_error(StartStep::Workspace, found, None).line(), Failure::Finding { finding: "untracked .env: rule env-file-plaintext".into() }.line(), "the first line is the finding");
    }
}
