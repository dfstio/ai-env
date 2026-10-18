//! The workspace rows (S8 §12): `state/workspaces/<slug>.toml`, a map keyed by
//! canonical cwd (the slug is lossy) holding the root, the VM path, the
//! branch, the last fetch and, per VM, what was seeded (head, WIP and index
//! trees, mode, scan counts, the last state, why a VM was kept, findings).
//! Written atomically under `Paths::workspaces_rows_lock`. Built in S8 wave 1
//! (W4).
//!
//! A row is the Mac's memory of what it sent and fetched, never a source of
//! truth about a VM (the shim's `GET /seed` is): a VM entry whose
//! `state/vms` row is gone or terminated is pruned at the next write.
//!
//! A write waits on `.rows.lock` without a budget, so async code never runs
//! one on the runtime's thread: `write_off_thread` runs it on a blocking
//! thread and waits at most [`ROWS_WAIT`] for it.
use super::WorkspaceRef;
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::registry::{ensure_private_dir, read_regular_file};
use crate::bridge::vm::lock::lock_blocking;
use crate::bridge::vm::registry::{read_row, RowStatus};
use crate::wire::time::unix_now;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// The rows' schema version.
pub const ROWS_V: u8 = 1;
/// How many findings a workspace's row keeps (the newest).
pub const FINDINGS_KEPT: usize = 20;
/// The longest an async caller waits for a row write (`write_off_thread`).
pub const ROWS_WAIT: Duration = Duration::from_secs(2);

/// One `<slug>.toml`: every workspace of that slug, by canonical cwd.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceRows {
    pub v: u8,
    pub ws: BTreeMap<String, WsRow>,
}

/// One workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WsRow {
    pub root: String,
    pub vm_root: String,
    pub branch: Option<String>,
    pub updated_at: u64,
    /// The last code-out: when, from which VM, its newest `box/wip/*`.
    pub last_fetch_at: Option<u64>,
    pub last_fetch_vm: Option<String>,
    pub last_wip: Option<String>,
    /// S9: when (unix seconds) `box fetch` said that the workspace's
    /// repository has no ai-env pre-push hook: it says so once.
    pub hook_noted_at: Option<u64>,
    /// `refs/remotes/box/*` and `refs/remotes/box-quarantine/*` as the last
    /// fetch left them, to their commits (a snapshot past the cap gone).
    pub fetched: BTreeMap<String, String>,
    /// Per VM, what it was seeded with.
    pub vm: BTreeMap<String, VmSeedRow>,
    /// The newest findings of the seeds and code-outs (at most [`FINDINGS_KEPT`]).
    pub finding: Vec<FindingRow>,
}

/// What one VM was seeded with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VmSeedRow {
    pub seeded_at: u64,
    /// `clone`, `update`, `replace`, or the decision that sent nothing (`up_to_date`, `kept`).
    pub mode: String,
    pub seeded_head: Option<String>,
    pub seeded_wip: Option<String>,
    pub seeded_wip_tree: Option<String>,
    pub seeded_index_tree: Option<String>,
    pub bytes: u64,
    pub scan: ScanCounts,
    pub last_state: Option<LastState>,
    /// Why D3 kept the VM's state, when it did.
    pub kept: Option<String>,
    /// The VM's shallow boundary as this Mac sent it (D7): the first seed's
    /// head, a replace's, and every update's new boundary commits
    /// (`SeedManifest::shallow`), as the helper adds them to its
    /// `.git/shallow`. The next update walks the VM's graph cut there.
    /// Emptied by an update or a replace planned on a seed the row did not
    /// see (that seed's row write lost): the list would lack part of the
    /// VM's, so it stays empty for that VM, whose updates then walk from
    /// [`boundary`]'s fallback.
    pub shallow: Vec<String>,
}

/// A seed's scan in numbers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanCounts {
    pub objects: u64,
    pub cached: u64,
    /// The rules' digest (16 hex digits).
    pub digest: String,
}

/// The VM's checkout as the last `GET /seed` read it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LastState {
    pub head: Option<String>,
    pub clean: bool,
    pub at: u64,
}

/// One finding, as the row keeps it (never a value).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FindingRow {
    pub location: String,
    pub object: Option<String>,
    pub rule: String,
    pub key: Option<String>,
    pub at: u64,
}

/// What [`record_seed`] writes (owned: it goes to a blocking thread).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedEvent {
    pub vm: String,
    pub mode: String,
    pub head: String,
    pub branch: Option<String>,
    pub wip: Option<String>,
    pub wip_tree: Option<String>,
    pub index_tree: Option<String>,
    pub bytes: u64,
    pub objects: u64,
    pub cached: u64,
    pub digest: String,
    pub vm_head: Option<String>,
    pub vm_clean: bool,
    pub kept: Option<String>,
    /// The manifest's boundary the VM took (`SeedManifest::shallow`); empty
    /// when nothing was sent.
    pub shallow: Vec<String>,
    /// The VM's seeded head an update or a replace was planned on (`GET
    /// /seed`'s record): the row's boundary grows only when it is that seed's.
    pub base: Option<String>,
}

/// `state/workspaces/<slug>.toml`; `Config` for a slug that is not one plain name.
fn path_of(paths: &Paths, slug: &str) -> Result<PathBuf, BridgeError> {
    if slug.is_empty() || slug.len() > crate::wire::workspace::SLUG_MAX || !slug.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(BridgeError::Config(format!("not a workspace slug: {slug:?}")));
    }
    Ok(paths.workspace_row(slug))
}

/// The rows of `slug` (empty when the file does not exist).
pub fn read(paths: &Paths, slug: &str) -> Result<WorkspaceRows, BridgeError> {
    let path = path_of(paths, slug)?;
    let Some(text) = read_regular_file(&path)? else {
        return Ok(WorkspaceRows::default());
    };
    toml::from_str(&text).map_err(|e| BridgeError::Config(format!("{}: {}", path.display(), e.to_string().lines().next().unwrap_or("unparseable"))))
}

/// The row of `ws`, when one was written.
pub fn row_of(paths: &Paths, ws: &WorkspaceRef) -> Result<Option<WsRow>, BridgeError> {
    Ok(read(paths, &ws.slug)?.ws.remove(&key(ws)))
}

fn key(ws: &WorkspaceRef) -> String {
    ws.cwd.to_string_lossy().into_owned()
}

/// Run `write` (a row write, which waits on `.rows.lock` without a budget)
/// on a blocking thread, waiting at most [`ROWS_WAIT`] for it: a holder that
/// never lets go (a process stopped while it held the lock) costs the caller
/// that long, never the runtime's thread (the wrapper's relay, its close);
/// the write still lands once the lock is free. Past the wait: `Busy`.
pub(crate) async fn write_off_thread(write: impl FnOnce() -> Result<(), BridgeError> + Send + 'static) -> Result<(), BridgeError> {
    match tokio::time::timeout(ROWS_WAIT, super::blocking(write)).await {
        Ok(done) => done?,
        Err(_) => Err(BridgeError::Busy(format!("the workspace rows' lock was not free within {} s", ROWS_WAIT.as_secs()))),
    }
}

/// Read-modify-write of `ws`'s row (created when absent) under the rows'
/// lock: `f` changes it, then the file is replaced atomically (0600 in the
/// 0700 `state/workspaces`). Blocking, the lock without a budget: async code
/// calls it through `write_off_thread`.
pub fn update(paths: &Paths, ws: &WorkspaceRef, f: impl FnOnce(&mut WsRow)) -> Result<(), BridgeError> {
    let path = path_of(paths, &ws.slug)?;
    ensure_private_dir(&paths.workspaces())?;
    let _guard = lock_blocking(&paths.workspaces_rows_lock())?;
    let mut rows = read(paths, &ws.slug)?;
    rows.v = ROWS_V;
    let row = rows.ws.entry(key(ws)).or_default();
    row.root = ws.root.to_string_lossy().into_owned();
    row.vm_root.clone_from(&ws.vm_root);
    f(row);
    row.updated_at = unix_now();
    if row.finding.len() > FINDINGS_KEPT {
        let drop = row.finding.len() - FINDINGS_KEPT;
        row.finding.drain(..drop);
    }
    let text = toml::to_string_pretty(&rows).map_err(|e| BridgeError::Config(format!("{}: cannot serialise the workspace row: {e}", path.display())))?;
    crate::bridge::infra::write_atomic_mode(&path, text.as_bytes(), 0o600)
}

/// Record a seed's decision for `ev.vm`.
pub fn record_seed(paths: &Paths, ws: &WorkspaceRef, ev: &SeedEvent) -> Result<(), BridgeError> {
    let now = unix_now();
    update(paths, ws, |row| {
        row.branch.clone_from(&ev.branch);
        let entry = row.vm.entry(ev.vm.clone()).or_default();
        // The row's boundary is the VM's only when the row saw the seed this one was planned on.
        let known = ev.base.is_some() && entry.seeded_head == ev.base && !entry.shallow.is_empty();
        if !matches!(ev.mode.as_str(), "kept" | "up_to_date") || entry.seeded_head.is_none() {
            entry.seeded_at = now;
            entry.seeded_head = Some(ev.head.clone());
            entry.seeded_wip.clone_from(&ev.wip);
            entry.seeded_wip_tree.clone_from(&ev.wip_tree);
            entry.seeded_index_tree.clone_from(&ev.index_tree);
            entry.bytes = ev.bytes;
        }
        match ev.mode.as_str() {
            // A first seed's `.git/shallow` is its manifest's list; an update or a replace adds to it.
            "clone" => entry.shallow.clone_from(&ev.shallow),
            "update" | "replace" if known => {
                for id in &ev.shallow {
                    if !entry.shallow.contains(id) {
                        entry.shallow.push(id.clone());
                    }
                }
            }
            // A seed the row never saw went in before this one: what it added is unknown, so no list.
            "update" | "replace" => entry.shallow.clear(),
            _ => {}
        }
        entry.mode.clone_from(&ev.mode);
        entry.scan = ScanCounts { objects: ev.objects, cached: ev.cached, digest: ev.digest.chars().take(16).collect() };
        entry.last_state = Some(LastState { head: ev.vm_head.clone(), clean: ev.vm_clean, at: now });
        entry.kept.clone_from(&ev.kept);
        // The other VMs whose `state/vms` row is gone or terminated: nothing of theirs is reused.
        row.vm.retain(|id, _| *id == ev.vm || read_row(paths, id).ok().flatten().is_some_and(|r| r.status != RowStatus::Terminated));
    })
}

/// `vm`'s shallow boundary for an update of the VM at `tip`, seeded at
/// `seeded` (its checkout's commit and its last seed's head, as `GET /seed`
/// read them): the row's, when the row saw that seed; else `seeded` and
/// `tip` alone (logged), which the VM holds with their trees. A walk cut at
/// both never takes a commit below them for the VM's, which a walk from
/// `tip` cut at `seeded` alone can (a commit the agent made on an earlier
/// boundary commit, F1 of a merged fork, reaches F1's parent): the pack may
/// carry what the VM holds and mark a commit shallow whose parent it holds,
/// never lack what it lacks.
#[must_use]
pub fn boundary(paths: &Paths, ws: &WorkspaceRef, vm: &str, tip: &str, seeded: &str) -> Vec<String> {
    let entry = row_of(paths, ws).ok().flatten().and_then(|r| r.vm.get(vm).cloned());
    match entry {
        Some(e) if !e.shallow.is_empty() && e.seeded_head.as_deref() == Some(seeded) => e.shallow,
        _ => {
            tracing::info!(vm, "the workspace row holds no shallow boundary for this seed of the VM: its seeded head and its tip alone");
            let mut cut = vec![seeded.to_string()];
            if tip != seeded {
                cut.push(tip.to_string());
            }
            cut
        }
    }
}

/// The commit `vm` was last seeded at, as the row of `ws` remembers it.
#[must_use]
pub fn seeded_head(paths: &Paths, ws: &WorkspaceRef, vm: &str) -> Option<String> {
    row_of(paths, ws).ok().flatten().and_then(|r| r.vm.get(vm).and_then(|v| v.seeded_head.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::workspace::{Head, WsKind};
    use crate::wire::workspace::ObjectFormat;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A row write never holds the runtime's thread: while another holder
    /// keeps `.rows.lock` (a process stopped while it held it), the caller
    /// gets `Busy` after `ROWS_WAIT` and the runtime ran on meanwhile; the
    /// write lands once the lock is free.
    #[tokio::test]
    async fn a_held_rows_lock_costs_the_caller_rows_wait_never_the_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let kind = WsKind::Git { git_dir: "/w/.git".into(), common_dir: "/w/.git".into(), object_format: ObjectFormat::Sha1 };
        let ws = WorkspaceRef { cwd: "/w".into(), root: "/w".into(), vm_cwd: "/w".into(), vm_root: "/w".into(), slug: "-w".into(), kind, head: Head::Detached { sha: "a".repeat(40) }, seed_branch: None };
        let held = lock_blocking(&paths.workspaces_rows_lock()).unwrap();
        let ticks = Arc::new(AtomicU32::new(0));
        let ticker = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    ticks.fetch_add(1, Ordering::SeqCst);
                }
            })
        };
        let started = std::time::Instant::now();
        let (p, w) = (paths.clone(), ws.clone());
        let e = write_off_thread(move || update(&p, &w, |row| row.branch = Some("dev".into()))).await.unwrap_err();
        let waited = started.elapsed();
        assert!(matches!(e, BridgeError::Busy(_)), "{e:?}");
        assert!(waited >= ROWS_WAIT && waited < ROWS_WAIT + Duration::from_secs(1), "{waited:?}");
        assert!(ticks.load(Ordering::SeqCst) >= 5, "the runtime's thread ran on meanwhile");
        ticker.abort();
        drop(held);
        let branch = || row_of(&paths, &ws).unwrap().and_then(|r| r.branch);
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while branch().is_none() && std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(branch().as_deref(), Some("dev"), "the write landed once the lock was free");
    }
}
