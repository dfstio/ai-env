//! S11 (A.3, A.4): the VM's claude cache. A staged Claude Code binary
//! (`wire::s3::S3Key::Claude`, put by a stager VM's `POST /claude/relay`)
//! is fetched once into `CACHE_DIR/<sha256>/claude` by `POST /claude/stage`,
//! read back by `GET /claude/stage?sha256=`, and run by a spawn that names
//! it (`spawn.claude`, resolved by the `/agent` connection into
//! `SpawnRequest.picked` before the manager sees the spawn). The routes are
//! mounted (`health::router`) and `CAP_CLAUDE_STAGE_V1` named
//! (`ShimState::caps`) exactly when [`SERVED`] holds and the cache has a
//! store ([`ClaudeCache::enabled`]: the shim is root, or runs with
//! `--fs-root`).
//!
//! A fetch (plans/s11-contracts-A.md §2.2) is a task of its own, one curl
//! at a time (a semaphore of 1; another sha256 waits its turn), never a
//! transcript transfer's slot and never the workspace lock: curl (as
//! `ai-env-net` when root, its presigned GET on fd 3 only) streams into
//! `PARTIAL_DIR/<sha256>` (root 0600 in a root 0700 directory: the agent
//! never sees partial bytes), counted, hashed and cut at the signed size;
//! only a complete 200 of exactly the size and sha256 is installed (0555,
//! renamed into its 0755 directory, everything fsynced), and only a binary
//! whose `--version` (run as the agent, `ShimState::probe_version`) prints
//! exactly `<version> (Claude Code)` is indexed. The index
//! ([`INDEX_PATH`], written atomically) is the only thing [`ClaudeCache::pick`]
//! trusts; at most [`CACHE_KEEP`] binaries stay, never one a live spawn
//! runs nor one a spawn picked and the manager does not hold yet
//! ([`PickHold`]). The index is written off the runtime's threads, outside
//! the cache's lock, in order (a newer snapshot is never overwritten by an
//! older one). A refusal is remembered [`FAILED_KEEP`], but `not_staged` and
//! `checksum_mismatch` are never answered from memory (LD-42). A relay
//! (§2.3) streams the release's linux-arm64 binary through the root shim
//! into a presigned PUT, on a fresh VM only (`ShimState::fresh`). No URL
//! ever reaches an argv, an environment, a file or a log line.
use crate::shim::asagent::{self, AgentProcError};
use crate::shim::health::{ProbeError, ShimOpts, ShimState};
use crate::shim::s3xfer::{checked, curl_config, json_body, no_status, parse_status, read_capped, s3_code, seconds_left, timed_out, transfer_failed, Curl, Kind, Refused};
use crate::shim::s3xfer::{CHUNK, CONNECT_TIMEOUT_S, CURL_STDOUT_MAX, SPEED_LIMIT, SPEED_TIME_S};
use crate::wire::s3::{sha256_b64, CLAUDE_MAX};
use crate::wire::workspace::{budget, refusal, ClaudeCacheEntry, ClaudeCacheView, ClaudeRef, WsRefusal};
use crate::wire::workspace::{ClaudeRelay, ClaudeRelayReply, ClaudeSrc, ClaudeStage, ClaudeStageQuery, ClaudeStageReply, ClaudeStageState};
use axum::extract::{Request, State};
use axum::response::Response;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{watch, Semaphore};

/// Whether this build serves the claude routes and runs a spawn's refs (and names `claude_stage_v1`).
pub const SERVED: bool = true;
/// Fetched binaries: `<CACHE_DIR>/<sha256>/claude`, the file root 0555, the directories root 0755.
pub const CACHE_DIR: &str = "/opt/ai-env/claude";
/// Where a fetch writes until its checks pass (root 0700): the agent never sees partial bytes.
pub const PARTIAL_DIR: &str = "/opt/ai-env/claude/.partial";
/// The index, the only thing `pick` trusts (root 0600, written as `asagent::RecordStore::save` writes).
pub const INDEX_PATH: &str = "/var/lib/ai-env/claude-index.json";
/// The index file's version: `{"v":1,"entries":[<ClaudeCacheEntry>…]}`.
pub const INDEX_V: u32 = 1;
/// Binaries kept: the least recently used evicted, never one a live spawn runs.
pub const CACHE_KEEP: usize = 2;
/// A refused fetch is remembered (sha256 to code) this long: a `GET` meanwhile reads it as `failed`, and a `POST`
/// gets it at once but for `not_staged` and `checksum_mismatch`, which a `POST` fetches again (§2.2, LD-42).
pub const FAILED_KEEP: Duration = Duration::from_secs(600);
/// A fetch's receive rate: curl's `limit-rate` (LD-2).
pub const FETCH_RATE: &str = "32M";

/// The routes' names in the workspace log lines (`asagent::log`).
const OP_STAGE: &str = "claude-stage";
const OP_STATE: &str = "claude-stage-state";
const OP_RELAY: &str = "claude-relay";
/// The largest index file read (an entry is about 200 bytes).
const INDEX_MAX: u64 = 256 * 1024;
/// What a binary's `--version` prints after its version.
const VERSION_SUFFIX: &str = " (Claude Code)";
/// The binary's file name in its sha256's directory.
const BINARY: &str = "claude";

/// What a spawn runs, as the `/agent` connection resolved it (`resolve_claude`) before the manager saw the spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickedClaude {
    /// A cached binary; `None`: the image's (`--claude`).
    pub path: Option<PathBuf>,
    /// What `spawned` reports.
    pub version: Option<String>,
    pub sha256: Option<String>,
}

/// The cache: the index, the one fetch under way, the refusals of the last `FAILED_KEEP`, the image's own ref.
/// Disabled (no store) for a shim with neither root nor `--fs-root`: an in-process test never touches this
/// machine's `/opt` or `/var/lib`.
pub struct ClaudeCache {
    store: Option<Store>,
}

/// The cache's files, under the shim's root (`/`, or `--fs-root`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Paths {
    cache: PathBuf,
    partial: PathBuf,
    index: PathBuf,
}

impl Paths {
    fn under(root: &Path) -> Paths {
        let at = |p: &str| root.join(p.trim_start_matches('/'));
        Paths { cache: at(CACHE_DIR), partial: at(PARTIAL_DIR), index: at(INDEX_PATH) }
    }

    /// An indexed sha256's directory (a checked 64-hex name: never a ref's text).
    fn dir(&self, sha256: &str) -> PathBuf {
        self.cache.join(sha256)
    }

    fn binary(&self, sha256: &str) -> PathBuf {
        self.dir(sha256).join(BINARY)
    }

    fn partial_file(&self, sha256: &str) -> PathBuf {
        self.partial.join(sha256)
    }
}

/// A store: its paths, the image's own ref, the state behind one lock, the index's writes in order, and the
/// two turns.
struct Store {
    paths: Paths,
    image: Option<ClaudeRef>,
    /// Shared with each pick's hold ([`PickHold`]).
    inner: Arc<Mutex<Inner>>,
    /// The generation of the snapshot the index file holds: a write of an older one is skipped.
    written: Arc<Mutex<u64>>,
    /// One fetch's curl at a time.
    fetch_turn: Arc<Semaphore>,
    /// One relay at a time.
    relay_turn: Arc<Semaphore>,
}

#[derive(Default)]
struct Inner {
    /// The index: most recently used first.
    entries: Vec<ClaudeCacheEntry>,
    /// The index's generation: one more at each change of `entries` ([`Inner::changed`]).
    gen: u64,
    /// The sha256s a spawn picked that the manager does not hold yet, each with its count: eviction skips them as
    /// it skips one a live spawn runs.
    picking: BTreeMap<String, usize>,
    /// The fetches under way or waiting their turn, by sha256.
    fetches: BTreeMap<String, Fetch>,
    /// The sha256 whose curl runs now.
    active: Option<String>,
    /// The refusals of the last `FAILED_KEEP`, by sha256.
    failed: BTreeMap<String, Failure>,
}

/// A fetch under way: whom a second request joins.
struct Fetch {
    version: String,
    began: Instant,
    got: Arc<AtomicU64>,
    done: watch::Receiver<Option<Outcome>>,
}

/// A refused fetch, remembered.
struct Failure {
    version: String,
    refusal: WsRefusal,
    at: Instant,
    got_len: u64,
    got_sha256: Option<String>,
}

/// The index's entries as one write takes them, and their generation.
struct Snapshot {
    gen: u64,
    entries: Vec<ClaudeCacheEntry>,
}

/// A pick's hold on its cached binary ([`ClaudeCache::pick`]): eviction skips it until the hold is dropped,
/// which the `/agent` connection does once the manager holds the spawn (its record then names the sha256 to
/// `running_claudes`) or refused it. The image's own claude needs none.
#[must_use]
pub struct PickHold(Option<(Arc<Mutex<Inner>>, String)>);

impl Drop for PickHold {
    fn drop(&mut self) {
        let Some((inner, sha256)) = self.0.take() else { return };
        let mut inner = inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = inner.picking.get_mut(&sha256) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                inner.picking.remove(&sha256);
            }
        }
    }
}

/// How a fetch ended.
#[derive(Debug, Clone)]
enum Outcome {
    Ready { got_len: u64, ms: u64 },
    Refused(Box<WsRefusal>),
}

/// Why a fetch failed: the refusal (boxed: a `WsRefusal` is large), and (a checksum mismatch) the sha256 of what
/// came.
struct Failed {
    refusal: Refused,
    got_sha256: Option<String>,
}

impl Failed {
    fn new(code: &str, message: &str) -> Failed {
        Failed { refusal: Box::new(WsRefusal::new(code, message)), got_sha256: None }
    }
}

impl From<Refused> for Failed {
    fn from(refusal: Refused) -> Failed {
        Failed { refusal, got_sha256: None }
    }
}

impl Inner {
    /// The refusals older than `FAILED_KEEP` go.
    fn prune(&mut self) {
        self.failed.retain(|_, f| f.at.elapsed() < FAILED_KEEP);
    }

    fn holds(&self, sha256: &str) -> Option<&ClaudeCacheEntry> {
        self.entries.iter().find(|e| e.sha256 == sha256)
    }

    /// A live spawn runs `sha256` (`running`, read under this lock), or a spawn picked it and the manager does not
    /// hold it yet.
    fn in_use(&self, running: &BTreeSet<String>, sha256: &str) -> bool {
        running.contains(sha256) || self.picking.contains_key(sha256)
    }

    /// The entries past `CACHE_KEEP`, least recently used first, but never one in use (the count may stay over
    /// until the next eviction).
    fn evict_past_keep(&mut self, running: &BTreeSet<String>) -> Vec<ClaudeCacheEntry> {
        let mut gone = Vec::new();
        let mut i = self.entries.len();
        while i > CACHE_KEEP {
            i -= 1;
            if !self.in_use(running, &self.entries[i].sha256) {
                gone.push(self.entries.remove(i));
            }
        }
        gone
    }

    /// The least recently used entry not in use, but `keep`: the one eviction a full disk gets.
    fn evict_one(&mut self, running: &BTreeSet<String>, keep: &str) -> Option<ClaudeCacheEntry> {
        let i = self.entries.iter().rposition(|e| !self.in_use(running, &e.sha256) && e.sha256 != keep)?;
        Some(self.entries.remove(i))
    }

    /// `entries` changed: the snapshot to write.
    fn changed(&mut self) -> Snapshot {
        self.gen += 1;
        Snapshot { gen: self.gen, entries: self.entries.clone() }
    }
}

impl ClaudeCache {
    /// The shim's: the three paths under `--fs-root` when set, as they are when the shim is root, none otherwise
    /// (an in-process test: disabled). The image's ref read once from `validate::LOCK` (under `--fs-root`). At
    /// start: entries whose file is missing or of another size dropped, `.partial/*` and unindexed directories
    /// removed, each logged. It creates nothing (V4 needs the image's empty `CACHE_DIR`): the first fetch makes
    /// `PARTIAL_DIR`.
    #[must_use]
    pub fn for_shim(opts: &ShimOpts) -> ClaudeCache {
        let root = match &opts.fs_root {
            Some(root) => root.clone(),
            None if nix::unistd::geteuid().is_root() => PathBuf::from("/"),
            None => return ClaudeCache { store: None },
        };
        let paths = Paths::under(&root);
        let image = image_ref(&root);
        let entries = start_up(&paths);
        let inner = Inner { entries, ..Inner::default() };
        ClaudeCache { store: Some(Store { paths, image, inner: Arc::new(Mutex::new(inner)), written: Arc::new(Mutex::new(0)), fetch_turn: Arc::new(Semaphore::new(1)), relay_turn: Arc::new(Semaphore::new(1)) }) }
    }

    /// A store exists: the routes are mounted and the cap named only then.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.store.is_some()
    }

    /// The first of `refs` whose sha256 and version an index entry holds (its `last_used` now, the index written in
    /// the background: the spawn never waits for its fsync), with the hold that keeps it from eviction until the
    /// manager holds the spawn; or the image's own when a ref's sha256 and version are the lock's; `None`: none,
    /// the image's claude runs. A ref is only ever compared, never joined into a path: the path is the entry's.
    #[must_use]
    pub fn pick(&self, refs: &[ClaudeRef]) -> Option<(PickedClaude, PickHold)> {
        let store = self.store.as_ref()?;
        let mut inner = store.lock();
        for r in refs {
            if let Some(i) = inner.entries.iter().position(|e| e.sha256 == r.sha256 && e.version == r.version) {
                let mut entry = inner.entries.remove(i);
                entry.last_used = crate::wire::time::unix_now();
                inner.entries.insert(0, entry.clone());
                *inner.picking.entry(entry.sha256.clone()).or_default() += 1;
                let snap = inner.changed();
                drop(inner);
                store.save_soon(snap);
                let hold = PickHold(Some((Arc::clone(&store.inner), entry.sha256.clone())));
                return Some((PickedClaude { path: Some(store.paths.binary(&entry.sha256)), version: Some(entry.version), sha256: Some(entry.sha256) }, hold));
            }
            if store.image.as_ref() == Some(r) {
                return Some((PickedClaude { path: None, version: Some(r.version.clone()), sha256: None }, PickHold(None)));
            }
        }
        None
    }

    /// `/health/detail`'s view; `None` when disabled.
    #[must_use]
    pub fn view(&self) -> Option<ClaudeCacheView> {
        let store = self.store.as_ref()?;
        let mut inner = store.lock();
        inner.prune();
        Some(ClaudeCacheView {
            entries: inner.entries.clone(),
            fetching: inner.active.clone(),
            failed: inner.failed.iter().map(|(sha, f)| (sha.clone(), f.refusal.code.clone())).collect(),
            image: store.image.clone(),
        })
    }
}

/// The index's entries under `root` (`sys::read_report`): `Some(vec![])` when the index is absent, `None` when unreadable.
#[must_use]
pub fn index_at(root: &Path) -> Option<Vec<ClaudeCacheEntry>> {
    match read_index(&Paths::under(root)) {
        IndexRead::Absent => Some(Vec::new()),
        IndexRead::Unreadable(_) => None,
        IndexRead::Read { kept, .. } => Some(kept),
    }
}

// ---- the index ----------------------------------------------------------------------------

/// The index file as it is read: no key but these two.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexIn {
    v: u32,
    entries: Vec<serde_json::Value>,
}

/// The index file as it is written.
#[derive(serde::Serialize)]
struct IndexOut<'a> {
    v: u32,
    entries: &'a [ClaudeCacheEntry],
}

/// What reading the index found.
enum IndexRead {
    Absent,
    Unreadable(String),
    /// The entries that passed (most recently used first), and why the others were dropped.
    Read { kept: Vec<ClaudeCacheEntry>, dropped: Vec<String> },
}

/// The index read strictly: `v` 1, each entry's version `N.N.N`, sha256 64 lowercase hex, size 1 to
/// `CLAUDE_MAX`, its file a regular file of that size in a real directory; another entry (or a second of one
/// sha256) is dropped with its reason, a file that does not parse is unreadable.
fn read_index(paths: &Paths) -> IndexRead {
    let md = match std::fs::symlink_metadata(&paths.index) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return IndexRead::Absent,
        Err(e) => return IndexRead::Unreadable(e.to_string()),
        Ok(md) => md,
    };
    if !md.is_file() {
        return IndexRead::Unreadable("it is not a regular file".into());
    }
    if md.len() > INDEX_MAX {
        return IndexRead::Unreadable(format!("it is over {INDEX_MAX} bytes"));
    }
    let bytes = match std::fs::read(&paths.index) {
        Ok(b) => b,
        Err(e) => return IndexRead::Unreadable(e.to_string()),
    };
    let file: IndexIn = match serde_json::from_slice(&bytes) {
        Ok(f) => f,
        Err(e) => return IndexRead::Unreadable(format!("it does not parse ({})", crate::shim::s3xfer::parse_error(&e))),
    };
    if file.v != INDEX_V {
        return IndexRead::Unreadable(format!("its v is {}, not {INDEX_V}", file.v));
    }
    let (mut kept, mut dropped): (Vec<ClaudeCacheEntry>, Vec<String>) = (Vec::new(), Vec::new());
    for (i, value) in file.entries.into_iter().enumerate() {
        let entry: ClaudeCacheEntry = match serde_json::from_value(value) {
            Ok(e) => e,
            Err(e) => {
                dropped.push(format!("entry {i} does not parse ({})", crate::shim::s3xfer::parse_error(&e)));
                continue;
            }
        };
        if let Some(why) = entry_problem(paths, &entry) {
            dropped.push(format!("entry {i} {why}"));
        } else if kept.iter().any(|k| k.sha256 == entry.sha256) {
            dropped.push(format!("entry {i} names sha {} a second time", short_sha(&entry.sha256)));
        } else {
            kept.push(entry);
        }
    }
    kept.sort_by_key(|e| std::cmp::Reverse(e.last_used));
    IndexRead::Read { kept, dropped }
}

/// Why an index entry cannot stand, if it cannot.
fn entry_problem(paths: &Paths, e: &ClaudeCacheEntry) -> Option<String> {
    if let Err(why) = (ClaudeRef { version: e.version.clone(), sha256: e.sha256.clone() }).check() {
        return Some(why);
    }
    if !(1..=CLAUDE_MAX).contains(&e.size) {
        return Some(format!("names a size of {} bytes (1 to {CLAUDE_MAX})", e.size));
    }
    let sha = short_sha(&e.sha256);
    match std::fs::symlink_metadata(paths.dir(&e.sha256)) {
        Ok(md) if md.is_dir() => {}
        _ => return Some(format!("(claude {} sha {sha}) has no directory", e.version)),
    }
    match std::fs::symlink_metadata(paths.binary(&e.sha256)) {
        Ok(md) if md.is_file() && md.len() == e.size => None,
        Ok(md) if md.is_file() => Some(format!("(claude {} sha {sha}) is {} bytes, not {}", e.version, md.len(), e.size)),
        _ => Some(format!("(claude {} sha {sha}) has no binary", e.version)),
    }
}

/// Write the index atomically: a temp file (0600) in its directory (made 0700 when missing, and kept 0700, as
/// the seed record's), fsynced, renamed over it, the directory fsynced after.
fn save_index(index: &Path, entries: &[ClaudeCacheEntry]) -> Result<(), String> {
    let dir = index.parent().ok_or("the index has no directory")?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("cannot keep {} 0700: {e}", dir.display()))?;
    let mut text = serde_json::to_vec(&IndexOut { v: INDEX_V, entries }).map_err(|e| e.to_string())?;
    text.push(b'\n');
    let mut tmp = tempfile::Builder::new().prefix(".claude-index-").tempfile_in(dir).map_err(|e| format!("cannot make a temp file in {}: {e}", dir.display()))?;
    tmp.write_all(&text).map_err(|e| e.to_string())?;
    tmp.as_file().sync_all().map_err(|e| e.to_string())?;
    tmp.persist(index).map_err(|e| e.error.to_string())?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The image's own claude: the lock's version and sha256 (`None` without a lock that parses).
fn image_ref(root: &Path) -> Option<ClaudeRef> {
    let lock = root.join(crate::shim::validate::LOCK.trim_start_matches('/'));
    let text = std::fs::read_to_string(&lock).ok()?;
    match crate::wire::pin::parse_lock(&text) {
        Ok(pin) => Some(ClaudeRef { version: pin.version, sha256: pin.sha256 }),
        Err(why) => {
            errln!("ai-env: claude cache: the lock {} does not parse ({why}): no image ref", lock.display());
            None
        }
    }
}

/// The cache as a shim finds it at start: the index's entries that stand; every partial file and every
/// directory no entry names removed; the index rewritten when it dropped something. Each step logged.
fn start_up(paths: &Paths) -> Vec<ClaudeCacheEntry> {
    let (entries, rewrite) = match read_index(paths) {
        IndexRead::Absent => (Vec::new(), false),
        IndexRead::Unreadable(why) => {
            errln!("ai-env: claude cache index {} ignored ({why}): an empty cache", paths.index.display());
            (Vec::new(), true)
        }
        IndexRead::Read { kept, dropped } => {
            for why in &dropped {
                errln!("ai-env: claude cache index: {why}: dropped");
            }
            (kept, !dropped.is_empty())
        }
    };
    if let Ok(rd) = std::fs::read_dir(&paths.partial) {
        for e in rd.flatten() {
            let path = e.path();
            let gone = if e.file_type().is_ok_and(|t| t.is_dir()) { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
            errln!("ai-env: claude cache: partial {} removed{}", e.file_name().to_string_lossy(), gone.err().map(|e| format!(" (failed: {e})")).unwrap_or_default());
        }
    }
    if let Ok(rd) = std::fs::read_dir(&paths.cache) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.path() == paths.partial || !e.file_type().is_ok_and(|t| t.is_dir()) || entries.iter().any(|k| k.sha256 == name) {
                continue;
            }
            let gone = std::fs::remove_dir_all(e.path());
            errln!("ai-env: claude cache: unindexed directory {} removed{}", name.chars().take(80).collect::<String>(), gone.err().map(|e| format!(" (failed: {e})")).unwrap_or_default());
        }
    }
    if rewrite {
        if let Err(why) = save_index(&paths.index, &entries) {
            errln!("ai-env: claude cache index not rewritten: {why}");
        }
    }
    entries
}

// ---- the store --------------------------------------------------------------------------

impl Store {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A snapshot's write, for a blocking thread (never the cache's lock): skipped when the file holds a newer one,
    /// so writes keep their order; a failure is logged: the cache goes on in memory, and a restarted shim drops
    /// what its index lacks.
    fn writer(&self, snap: Snapshot) -> impl FnOnce() + Send + 'static {
        let (index, written) = (self.paths.index.clone(), Arc::clone(&self.written));
        move || {
            let mut at = written.lock().unwrap_or_else(PoisonError::into_inner);
            if *at >= snap.gen {
                return;
            }
            match save_index(&index, &snap.entries) {
                Ok(()) => *at = snap.gen,
                Err(why) => errln!("ai-env: claude cache index not written: {why}"),
            }
        }
    }

    /// The snapshot written in the background (a pick, an eviction for space): nobody waits for it.
    fn save_soon(&self, snap: Snapshot) {
        let write = self.writer(snap);
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => drop(rt.spawn_blocking(write)),
            Err(_) => write(),
        }
    }

    /// The snapshot written, awaited (a fetch's end: its 201 means the index file names the binary).
    async fn save_now(&self, snap: Snapshot) {
        let _ = tokio::task::spawn_blocking(self.writer(snap)).await;
    }

    /// The directories of `entries` removed, each logged (the cache's own line: a fetch's is its one
    /// `claude_stage` line).
    fn remove_dirs(&self, entries: &[ClaudeCacheEntry], why: &str) {
        for e in entries {
            let gone = std::fs::remove_dir_all(self.paths.dir(&e.sha256));
            errln!("ai-env: claude cache: {why} version={} sha={}{}", e.version, short_sha(&e.sha256), gone.err().map(|e| format!(" (not removed: {e})")).unwrap_or_default());
        }
    }

    /// A full disk's one eviction: the least recently used binary not in use (the running ones read under the
    /// cache's lock), its directory removed first, then the index written.
    fn evict_for_space(&self, state: &ShimState, fetching: &str) {
        let mut inner = self.lock();
        let Some(gone) = inner.evict_one(&state.spawns.running_claudes(), fetching) else { return };
        let snap = inner.changed();
        drop(inner);
        self.remove_dirs(&[gone], "evicted for space");
        self.save_soon(snap);
    }

    /// What a `POST` gets at once, or the fetch it waits for (joined, or started here).
    fn begin(&self, state: &Arc<ShimState>, s: &ClaudeStage) -> Begin {
        let mut inner = self.lock();
        if let Some(e) = inner.holds(&s.sha256) {
            if e.version == s.version {
                return Begin::Answer(ready(ClaudeSrc::Cache));
            }
            return Begin::Refuse(Box::new(WsRefusal::new(refusal::VERSION_MISMATCH, &format!("the cache holds this sha256 as claude {}, not {}", e.version, s.version))));
        }
        if self.image.as_ref().is_some_and(|i| i.sha256 == s.sha256 && i.version == s.version) {
            return Begin::Answer(ready(ClaudeSrc::Image));
        }
        inner.prune();
        if let Some(f) = inner.failed.get(&s.sha256) {
            // LD-42: the Mac restages the same key after either of these, so neither outlives the object it judged.
            let fetch_again = f.version != s.version || matches!(f.refusal.code.as_str(), refusal::NOT_STAGED | refusal::CHECKSUM_MISMATCH);
            if !fetch_again {
                return Begin::Refuse(Box::new(f.refusal.clone()));
            }
            inner.failed.remove(&s.sha256);
        }
        if let Some(f) = inner.fetches.get(&s.sha256) {
            if f.version != s.version {
                return Begin::Refuse(Box::new(asagent::busy(OP_STAGE, "a fetch of this sha256 as another claude version is under way", Duration::ZERO)));
            }
            return Begin::Wait(Waiter { done: f.done.clone(), got: Arc::clone(&f.got), began: f.began });
        }
        let (tx, rx) = watch::channel(None);
        let (got, began) = (Arc::new(AtomicU64::new(0)), Instant::now());
        inner.fetches.insert(s.sha256.clone(), Fetch { version: s.version.clone(), began, got: Arc::clone(&got), done: rx.clone() });
        drop(inner);
        // A task of its own: a client gone (or a wait over) never ends the fetch.
        tokio::spawn(fetch_task(Arc::clone(state), s.clone(), Arc::clone(&got), tx));
        Begin::Wait(Waiter { done: rx, got, began })
    }

    /// `GET /claude/stage`'s answer for `sha256`.
    fn state_of(&self, sha256: &str) -> ClaudeStageReply {
        let mut inner = self.lock();
        inner.prune();
        if inner.holds(sha256).is_some() {
            return ready(ClaudeSrc::Cache);
        }
        if self.image.as_ref().is_some_and(|i| i.sha256 == sha256) {
            return ready(ClaudeSrc::Image);
        }
        if let Some(f) = inner.fetches.get(sha256) {
            return fetching(f.got.load(Ordering::Relaxed), f.began);
        }
        if let Some(f) = inner.failed.get(sha256) {
            let got_sha256 = (f.refusal.code == refusal::CHECKSUM_MISMATCH).then(|| f.got_sha256.clone()).flatten();
            return ClaudeStageReply { state: ClaudeStageState::Failed, src: None, why: Some(f.refusal.code.clone()), got_len: Some(f.got_len), got_sha256, ms: None };
        }
        ClaudeStageReply { state: ClaudeStageState::Absent, src: None, why: None, got_len: None, got_sha256: None, ms: None }
    }

    /// A fetch's end, under the lock: indexed (then the entries past the keep evicted, the running ones read under
    /// this lock), or its refusal remembered. The index's snapshot to write and the evicted entries' directories
    /// are the caller's.
    fn finish(&self, state: &ShimState, s: &ClaudeStage, result: Result<(), Failed>, got_len: u64, ms: u64) -> (Outcome, Vec<ClaudeCacheEntry>, Option<Snapshot>) {
        let mut inner = self.lock();
        inner.fetches.remove(&s.sha256);
        if inner.active.as_deref() == Some(s.sha256.as_str()) {
            inner.active = None;
        }
        match result {
            Ok(()) => {
                let now = crate::wire::time::unix_now();
                inner.entries.retain(|e| e.sha256 != s.sha256);
                inner.entries.insert(0, ClaudeCacheEntry { version: s.version.clone(), sha256: s.sha256.clone(), size: s.size, fetched_at: now, last_used: now });
                let gone = inner.evict_past_keep(&state.spawns.running_claudes());
                let snap = inner.changed();
                (Outcome::Ready { got_len, ms }, gone, Some(snap))
            }
            Err(f) => {
                inner.failed.insert(s.sha256.clone(), Failure { version: s.version.clone(), refusal: (*f.refusal).clone(), at: Instant::now(), got_len, got_sha256: f.got_sha256 });
                (Outcome::Refused(f.refusal), Vec::new(), None)
            }
        }
    }

    /// A failed fetch's leftovers: its partial file, and its directory unless the index names it.
    fn discard(&self, sha256: &str) {
        let _ = std::fs::remove_file(self.paths.partial_file(sha256));
        if self.lock().holds(sha256).is_none() {
            let _ = std::fs::remove_dir_all(self.paths.dir(sha256));
        }
    }
}

/// What `begin` decided.
enum Begin {
    Answer(ClaudeStageReply),
    Refuse(Refused),
    Wait(Waiter),
}

/// A request's hold on a fetch: its outcome, its bytes so far, when it began.
struct Waiter {
    done: watch::Receiver<Option<Outcome>>,
    got: Arc<AtomicU64>,
    began: Instant,
}

fn ready(src: ClaudeSrc) -> ClaudeStageReply {
    ClaudeStageReply { state: ClaudeStageState::Ready, src: Some(src), why: None, got_len: None, got_sha256: None, ms: None }
}

fn fetching(got_len: u64, began: Instant) -> ClaudeStageReply {
    ClaudeStageReply { state: ClaudeStageState::Fetching, src: None, why: None, got_len: Some(got_len), got_sha256: None, ms: Some(millis(began)) }
}

fn millis(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The first 12 hex digits of a sha256 (log lines).
fn short_sha(sha256: &str) -> &str {
    sha256.get(..12).unwrap_or(sha256)
}

/// At most 120 characters of a text a binary printed.
fn clip(text: &str) -> String {
    text.chars().take(120).collect()
}

/// A fetch's outcome, once it has one (`None`: its task ended without one).
async fn outcome_of(mut rx: watch::Receiver<Option<Outcome>>) -> Option<Outcome> {
    loop {
        if let Some(o) = rx.borrow_and_update().clone() {
            return Some(o);
        }
        if rx.changed().await.is_err() {
            return rx.borrow().clone();
        }
    }
}

/// The refusal of a route that has no store (never mounted so: `health::router`).
fn no_store() -> WsRefusal {
    WsRefusal::new(refusal::BAD_REQUEST, "this shim has no claude cache (neither root nor --fs-root)")
}

// ---- the routes ---------------------------------------------------------------------------

/// `POST /claude/stage` (§2.2): 200 when the cache holds it (`cache`) or it is the image's own (`image`); else
/// the fetch of it (joined, or started), waited for at most `wait_s`: 201 ready, the refusal, or 202 fetching. A
/// remembered `version_mismatch`, `transfer_failed`, `timeout` or `disk_full` is answered at once.
pub async fn stage(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = (OP_STAGE, Instant::now());
    let s: ClaudeStage = match json_body(op, started, req).await {
        Ok(s) => s,
        Err(res) => return *res,
    };
    if let Err(e) = s.check() {
        return asagent::refuse(op, started, &checked("claude stage", e));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &AgentProcError::Draining.refusal(op));
    }
    let Some(store) = state.claude_cache.store.as_ref() else { return asagent::refuse(op, started, &no_store()) };
    let waiter = match store.begin(&state, &s) {
        Begin::Answer(reply) => {
            asagent::log(op, 200, None, started);
            return asagent::answered(200, &reply);
        }
        Begin::Refuse(r) => return asagent::refuse(op, started, &r),
        Begin::Wait(w) => w,
    };
    match tokio::time::timeout(Duration::from_secs(u64::from(s.wait_s)), outcome_of(waiter.done.clone())).await {
        Ok(Some(Outcome::Ready { got_len, ms })) => {
            asagent::log(op, 201, None, started);
            asagent::answered(201, &ClaudeStageReply { state: ClaudeStageState::Ready, src: Some(ClaudeSrc::Cache), why: None, got_len: Some(got_len), got_sha256: None, ms: Some(ms) })
        }
        Ok(Some(Outcome::Refused(r))) => asagent::refuse(op, started, &r),
        Ok(None) => asagent::refuse(op, started, &transfer_failed("the claude fetch ended without an outcome")),
        Err(_) => {
            asagent::log(op, 202, None, started);
            asagent::answered(202, &fetching(waiter.got.load(Ordering::Relaxed), waiter.began))
        }
    }
}

/// `GET /claude/stage?sha256=` (§2.2): 200 with `ready` (`cache` or `image`), `fetching`, `failed` or `absent`
/// for every query that passes its check (LD-22); 400 otherwise.
pub async fn stage_state(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = (OP_STATE, Instant::now());
    let q: ClaudeStageQuery = match crate::shim::code::query(&req) {
        Ok(q) => q,
        Err(r) => return asagent::refuse(op, started, &r),
    };
    if let Err(e) = q.check() {
        return asagent::refuse(op, started, &checked("claude stage query", e));
    }
    let Some(store) = state.claude_cache.store.as_ref() else { return asagent::refuse(op, started, &no_store()) };
    let reply = store.state_of(&q.sha256);
    asagent::log(op, 200, None, started);
    asagent::answered(200, &reply)
}

/// `POST /claude/relay` (§2.3): on a fresh VM only, one at a time, the release's binary streamed through the
/// root shim into S3's PUT; 200 with S3's answer whenever the PUT's curl reported a status.
pub async fn relay(State(state): State<Arc<ShimState>>, req: Request) -> Response {
    let (op, started) = (OP_RELAY, Instant::now());
    let r: ClaudeRelay = match json_body(op, started, req).await {
        Ok(r) => r,
        Err(res) => return *res,
    };
    if let Err(e) = r.check() {
        return asagent::refuse(op, started, &checked("claude relay", e));
    }
    if !state.fresh() {
        return asagent::refuse(op, started, &WsRefusal::new(refusal::NOT_FRESH, "this VM ran a spawn, took a credential or holds a seed record: only a fresh stager VM relays"));
    }
    if state.is_draining() {
        return asagent::refuse(op, started, &AgentProcError::Draining.refusal(op));
    }
    let Some(store) = state.claude_cache.store.as_ref() else { return asagent::refuse(op, started, &no_store()) };
    let wait = state.workspace.busy_wait();
    let Ok(Ok(_turn)) = tokio::time::timeout(wait, Arc::clone(&store.relay_turn).acquire_owned()).await else {
        return asagent::refuse(op, started, &asagent::busy(op, "another claude relay is under way", wait));
    };
    let sent = AtomicU64::new(0);
    // LD-19's evidence: the redirects the release's GET followed (`u64::MAX` while its write-out has not said).
    let redirects = AtomicU64::new(u64::MAX);
    let deadline = tokio::time::Instant::now() + budget::CLAUDE_RELAY;
    let result = tokio::time::timeout_at(deadline, relay_run(&state, &r, deadline, &sent, &redirects)).await.unwrap_or_else(|_| Err(timed_out(op)));
    let word = match &result {
        Ok(reply) => match reply.s3_status {
            200 => "stored".to_string(),
            412 => "exists".to_string(),
            n => format!("s3_{n}"),
        },
        Err(refused) => refused.code.clone(),
    };
    let redirects = match redirects.load(Ordering::Relaxed) {
        u64::MAX => "-".to_string(),
        n => n.to_string(),
    };
    errln!("ai-env: claude_relay version={} sha={} outcome={word} bytes={} redirects={redirects} ms={}", r.version, short_sha(&r.sha256), sent.load(Ordering::Relaxed), millis(started));
    match result {
        Ok(reply) => {
            asagent::log(op, 200, None, started);
            asagent::answered(200, &reply)
        }
        Err(refused) => asagent::refuse(op, started, &refused),
    }
}

// ---- the fetch ----------------------------------------------------------------------------

/// The fetch's curl configuration (§2.4): S9's GET exactly (identity: the object is stored raw), then
/// `max-filesize` (the signed size) and `limit-rate`.
pub(crate) fn fetch_config(s: &ClaudeStage, max_time: u64) -> String {
    let mut text = curl_config(&s.url, s.proxy.as_deref(), max_time, &Kind::Get { owner: &s.owner, compressed: false });
    text.push_str(&format!("max-filesize = {}\nlimit-rate = {FETCH_RATE}\n", s.size));
    text
}

/// A fetch from its turn to its end (§2.2's steps), within `budget::CLAUDE_FETCH` (504 past it); its leftovers
/// removed on a failure; one log line, never the URL; its outcome to every request that waits.
async fn fetch_task(state: Arc<ShimState>, s: ClaudeStage, got: Arc<AtomicU64>, tx: watch::Sender<Option<Outcome>>) {
    let Some(store) = state.claude_cache.store.as_ref() else { return };
    let began = Instant::now();
    let turn = Arc::clone(&store.fetch_turn).acquire_owned().await.ok();
    store.lock().active = Some(s.sha256.clone());
    let deadline = tokio::time::Instant::now() + budget::CLAUDE_FETCH;
    let result = tokio::time::timeout_at(deadline, fetch_into(&state, store, &s, &got, deadline)).await.unwrap_or_else(|_| Err(Failed::from(timed_out(OP_STAGE))));
    if result.is_err() {
        store.discard(&s.sha256);
    }
    let (n, ms) = (got.load(Ordering::Relaxed), millis(began));
    let (outcome, gone, snap) = store.finish(&state, &s, result, n, ms);
    if let Some(snap) = snap {
        store.save_now(snap).await;
    }
    store.remove_dirs(&gone, "evicted");
    drop(turn);
    let word = match &outcome {
        Outcome::Ready { .. } => "fetched",
        Outcome::Refused(r) => r.code.as_str(),
    };
    errln!("ai-env: claude_stage version={} sha={} outcome={word} bytes={n} ms={ms}", s.version, short_sha(&s.sha256));
    let _ = tx.send(Some(outcome));
}

fn is_enospc(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOSPC)
}

fn disk_full() -> Failed {
    Failed::new(refusal::DISK_FULL, "the VM's disk cannot take the claude binary (after one eviction and one more try)")
}

/// A local file step that failed: `disk_full` for a full disk, else `transfer_failed` naming the step.
fn io_failed(what: &str, e: &io::Error) -> Failed {
    if is_enospc(e) {
        disk_full()
    } else {
        Failed::from(transfer_failed(&format!("{what}: {e}")))
    }
}

/// `PARTIAL_DIR/<sha256>`, new (0600, `O_EXCL`; a leftover of the same name removed first), its directory made
/// root 0700 (and `CACHE_DIR` 0755 when the image did not make it).
fn open_partial(paths: &Paths, sha256: &str) -> io::Result<std::fs::File> {
    if std::fs::symlink_metadata(&paths.cache).is_err() {
        std::fs::DirBuilder::new().recursive(true).mode(0o755).create(&paths.cache)?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(&paths.partial) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    if !std::fs::symlink_metadata(&paths.partial)?.is_dir() {
        return Err(io::Error::other("the partial directory is not a directory"));
    }
    std::fs::set_permissions(&paths.partial, std::fs::Permissions::from_mode(0o700))?;
    let file = paths.partial_file(sha256);
    match std::fs::remove_file(&file) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file)
}

/// `bytes` into the partial file; a full disk gets the fetch's one eviction (`evicted`) and one more try.
fn write_or_evict(state: &ShimState, store: &Store, sha256: &str, file: &mut std::fs::File, bytes: &[u8], evicted: &mut bool) -> Result<(), Failed> {
    let mut off = 0;
    while off < bytes.len() {
        match file.write(&bytes[off..]) {
            Ok(0) => return Err(io_failed("writing the partial binary", &io::Error::from(io::ErrorKind::WriteZero))),
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if is_enospc(&e) && !*evicted => {
                *evicted = true;
                store.evict_for_space(state, sha256);
            }
            Err(e) => return Err(io_failed("writing the partial binary", &e)),
        }
    }
    Ok(())
}

/// The checked partial binary into its place: 0555, a fresh `CACHE_DIR/<sha256>` (0755), renamed into it as
/// `claude`; the file and both directories fsynced.
fn install(paths: &Paths, sha256: &str) -> io::Result<()> {
    let partial = paths.partial_file(sha256);
    std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o555))?;
    let dir = paths.dir(sha256);
    match std::fs::symlink_metadata(&dir) {
        Ok(md) if md.is_dir() => std::fs::remove_dir_all(&dir)?,
        Ok(_) => std::fs::remove_file(&dir)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::DirBuilder::new().mode(0o755).create(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
    let binary = paths.binary(sha256);
    std::fs::rename(&partial, &binary)?;
    std::fs::File::open(&binary)?.sync_all()?;
    for d in [&dir, &paths.cache] {
        if let Ok(f) = std::fs::File::open(d) {
            let _ = f.sync_all();
        }
    }
    Ok(())
}

/// [`install`] off the runtime's threads.
async fn install_off_thread(paths: &Paths, sha256: &str) -> io::Result<()> {
    let (paths, sha256) = (paths.clone(), sha256.to_string());
    tokio::task::spawn_blocking(move || install(&paths, &sha256)).await.unwrap_or_else(|e| Err(io::Error::other(e.to_string())))
}

/// §2.2's fetch steps 1 to 5 and 7: curl's GET into the partial file (counted, hashed, cut at the size);
/// S3's answer judged (404 `not_staged`; a cut transfer `transfer_failed`; only a complete 200, or one curl
/// stopped at `max-filesize`, of other bytes is `checksum_mismatch`); installed; its `--version` probed as the
/// agent (else removed: `version_mismatch`). A full disk at the write or the install: one eviction, one more try.
async fn fetch_into(state: &ShimState, store: &Store, s: &ClaudeStage, got: &AtomicU64, deadline: tokio::time::Instant) -> Result<(), Failed> {
    let paths = &store.paths;
    let mut evicted = false;
    let mut file = match open_partial(paths, &s.sha256) {
        Ok(f) => f,
        Err(e) if is_enospc(&e) => {
            evicted = true;
            store.evict_for_space(state, &s.sha256);
            open_partial(paths, &s.sha256).map_err(|e| io_failed("cannot make the partial file", &e))?
        }
        Err(e) => return Err(io_failed("cannot make the partial file", &e)),
    };
    let mut curl = Curl::start(state, OP_STAGE, &fetch_config(s, seconds_left(deadline)))?;
    drop(curl.stdin.take());
    let mut out = curl.stdout.take();
    let mut h = Sha256::new();
    let (mut n, mut kept) = (0u64, 0u64);
    let mut buf = vec![0u8; CHUNK];
    let mut stopped = None;
    while let Some(o) = out.as_mut() {
        let k = match o.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(k) => k,
        };
        h.update(&buf[..k]);
        n += k as u64;
        got.store(n, Ordering::Relaxed);
        // Anything past the signed size is counted (what came) but never written.
        let take = usize::try_from(s.size.saturating_sub(kept)).unwrap_or(usize::MAX).min(k);
        if take > 0 {
            if let Err(f) = write_or_evict(state, store, &s.sha256, &mut file, &buf[..take], &mut evicted) {
                stopped = Some(f);
                break;
            }
            kept += take as u64;
        }
    }
    drop(out);
    if let Some(f) = stopped {
        curl.kill().await;
        return Err(f);
    }
    let (code, said) = curl.finish().await;
    let Some(status) = said.status.as_deref().and_then(parse_status).filter(|st| st.http != 0) else { return Err(transfer_failed(&no_status(code, &said)).into()) };
    match status.http {
        200 => {}
        404 => return Err(Failed::new(refusal::NOT_STAGED, "S3 holds no claude binary at its key (404)")),
        other => return Err(transfer_failed(&format!("S3 answered HTTP {other} to the claude binary's GET")).into()),
    }
    // curl's exit 63: stopped at `max-filesize` (a body over the signed size).
    let over = code == Some(63);
    if code != Some(0) && !over {
        let how = code.map_or_else(|| "curl was ended by a signal".to_string(), |c| format!("curl exited {c}"));
        return Err(transfer_failed(&format!("the claude binary's transfer was cut after {n} of {} bytes ({how})", s.size)).into());
    }
    let came = hex::encode(h.finalize());
    if over || n != s.size || came != s.sha256 {
        let past = if over { " (curl stopped it at max-filesize)" } else { "" };
        let message = format!("what came is {n} bytes{past} that are not the {} bytes of its sha256: nothing installed", s.size);
        return Err(Failed { refusal: Box::new(WsRefusal::new(refusal::CHECKSUM_MISMATCH, &message).with_size(n)), got_sha256: Some(came) });
    }
    match tokio::task::spawn_blocking(move || file.sync_all()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(io_failed("cannot sync the partial binary", &e)),
        Err(e) => return Err(io_failed("cannot sync the partial binary", &io::Error::other(e.to_string()))),
    }
    let mut installed = install_off_thread(paths, &s.sha256).await;
    if installed.as_ref().is_err_and(is_enospc) && !evicted {
        store.evict_for_space(state, &s.sha256);
        installed = install_off_thread(paths, &s.sha256).await;
    }
    installed.map_err(|e| io_failed("cannot install the claude binary", &e))?;
    let want = format!("{}{VERSION_SUFFIX}", s.version);
    let not = |why: String| Failed::new(refusal::VERSION_MISMATCH, &format!("the binary is not claude {}: {why}; removed", s.version));
    let refused = match state.probe_claude(&paths.binary(&s.sha256)).await {
        Ok(line) if line == want => return Ok(()),
        Ok(line) => not(format!("its --version printed {:?}", clip(&line))),
        Err(ProbeError::Ran(why)) => not(format!("its --version failed ({})", clip(&why))),
        // Nothing judged the binary (a 422 would fail its version on the Mac for good): another stage tries again.
        Err(ProbeError::NotRun { why, enospc }) => {
            let message = format!("the claude binary's --version could not be run ({}): removed, not judged", clip(&why));
            if enospc { Failed::new(refusal::DISK_FULL, &message) } else { Failed::from(transfer_failed(&message)) }
        }
    };
    let _ = std::fs::remove_dir_all(paths.dir(&s.sha256));
    Err(refused)
}

// ---- the relay ----------------------------------------------------------------------------

/// The release GET's write-out: the store's transfers' fields (`s3xfer::WRITE_OUT`), then how many redirects curl
/// followed (LD-19's evidence, the relay's log line's `redirects=`).
const RELEASE_WRITE_OUT: &str = r#"write-out = "%{stderr}ai-env-curl status=%{http_code} version=%header{x-amz-version-id} checksum=%header{x-amz-checksum-sha256} etag=%header{etag} redirects=%{num_redirects}\n""#;

/// The `redirects=` field of the release GET's status line ([`RELEASE_WRITE_OUT`]).
fn redirects_of(fields: &str) -> Option<u64> {
    fields.split(' ').find_map(|f| f.strip_prefix("redirects=")).and_then(|n| n.parse().ok())
}

/// The release's GET (§2.4, claudebin's own; pinned line by line): `binary_url(version)`, https only, TLS 1.2
/// or newer, the stall limit, at most 3 https-only redirects (LD-19), how many it followed in its write-out,
/// `max-filesize` the signed size. No proxy: a stager is an internet VM.
pub(crate) fn release_config(version: &str, size: u64, max_time: u64) -> String {
    let lines = [
        format!("url = \"{}\"", crate::wire::pin::binary_url(version)),
        "silent".to_string(),
        "show-error".to_string(),
        "proto = \"=https\"".to_string(),
        "tlsv1.2".to_string(),
        format!("connect-timeout = {CONNECT_TIMEOUT_S}"),
        format!("max-time = {max_time}"),
        format!("speed-limit = {SPEED_LIMIT}"),
        format!("speed-time = {SPEED_TIME_S}"),
        RELEASE_WRITE_OUT.to_string(),
        "request = \"GET\"".to_string(),
        "fail".to_string(),
        "location".to_string(),
        "proto-redir = \"=https\"".to_string(),
        "max-redirs = 3".to_string(),
        format!("max-filesize = {size}"),
        "output = \"-\"".to_string(),
    ];
    lines.join("\n") + "\n"
}

/// The relay's PUT: its curl, its stdin, and its stdout read off (capped) by a task of its own.
struct Put {
    curl: Curl,
    stdin: Option<tokio::process::ChildStdin>,
    body: tokio::task::JoinHandle<Vec<u8>>,
}

impl Put {
    /// S3's PUT of exactly the relay's key (§2.4): `size` bytes, its checksum, `If-None-Match: *`, the owner.
    fn start(state: &ShimState, r: &ClaudeRelay, deadline: tokio::time::Instant) -> Result<Put, Refused> {
        let checksum = sha256_b64(&r.sha256);
        let kind = Kind::Put { len: r.size, checksum: checksum.as_deref(), owner: &r.owner };
        let mut curl = Curl::start(state, OP_RELAY, &curl_config(&r.put, None, seconds_left(deadline), &kind))?;
        let stdin = curl.stdin.take();
        let mut stdout = curl.stdout.take();
        let body = tokio::spawn(async move { read_capped(stdout.as_mut(), CURL_STDOUT_MAX).await });
        Ok(Put { curl, stdin, body })
    }

    async fn feed(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self.stdin.as_mut() {
            Some(w) => w.write_all(bytes).await,
            None => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        }
    }

    /// Its stdin closed and S3's answer read: the reply, or `transfer_failed` without a status.
    async fn answer(mut self, len: u64, sha256: String) -> Result<ClaudeRelayReply, Refused> {
        drop(self.stdin.take());
        let (code, said) = self.curl.finish().await;
        let body = self.body.await.unwrap_or_default();
        let Some(status) = said.status.as_deref().and_then(parse_status).filter(|st| st.http != 0) else { return Err(transfer_failed(&no_status(code, &said))) };
        let s3_code = (!(200..300).contains(&status.http)).then(|| s3_code(&body)).flatten();
        let version_id = (status.http == 200).then_some(status.version).flatten();
        Ok(ClaudeRelayReply { s3_status: status.http, s3_code, version_id, len, sha256 })
    }
}

/// §2.3 steps 3 to 5: the release's GET first; the PUT once its first bytes came; the bytes through the root
/// shim (counted, hashed, cut at `size`). S3 stopping the PUT early: its answer. Else the GET judged when it
/// ended (another status than 200, or bytes short of `size`: the PUT killed, `transfer_failed`), then the PUT's
/// stdin closed and S3's answer read. `sent` counts what went to the PUT.
async fn relay_run(state: &ShimState, r: &ClaudeRelay, deadline: tokio::time::Instant, sent_n: &AtomicU64, redirects_n: &AtomicU64) -> Result<ClaudeRelayReply, Refused> {
    let mut get = Curl::start(state, OP_RELAY, &release_config(&r.version, r.size, seconds_left(deadline)))?;
    drop(get.stdin.take());
    let mut from = get.stdout.take();
    let mut put: Option<Put> = None;
    let mut h = Sha256::new();
    let (mut got, mut sent) = (0u64, 0u64);
    let mut s3_stopped = false;
    let mut buf = vec![0u8; CHUNK];
    while let Some(o) = from.as_mut() {
        let k = match o.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(k) => k,
        };
        got += k as u64;
        if put.is_none() {
            match Put::start(state, r, deadline) {
                Ok(p) => put = Some(p),
                Err(e) => {
                    get.kill().await;
                    return Err(e);
                }
            }
        }
        let take = usize::try_from(r.size.saturating_sub(sent)).unwrap_or(usize::MAX).min(k);
        if take == 0 {
            continue;
        }
        let Some(p) = put.as_mut() else { break };
        if p.feed(&buf[..take]).await.is_err() {
            // S3 answered already (its status says what): the rest is not sent.
            s3_stopped = true;
            break;
        }
        h.update(&buf[..take]);
        sent += take as u64;
        sent_n.store(sent, Ordering::Relaxed);
    }
    drop(from);
    if s3_stopped {
        get.kill().await;
        let _ = get.finish().await;
        return match put {
            Some(p) => p.answer(sent, hex::encode(h.finalize())).await,
            None => Err(transfer_failed("the PUT ended before it started")),
        };
    }
    let (code, said) = get.finish().await;
    if let Some(n) = said.status.as_deref().and_then(redirects_of) {
        redirects_n.store(n, Ordering::Relaxed);
    }
    let status = said.status.as_deref().and_then(parse_status).map(|st| st.http).filter(|http| *http != 0);
    let refused = match status {
        None => Some(transfer_failed(&format!("the release: {}", no_status(code, &said)))),
        Some(200) if got < r.size => Some(transfer_failed(&format!("the release's bytes stopped after {got} of {}", r.size))),
        Some(200) => None,
        Some(other) => Some(transfer_failed(&format!("the release answered HTTP {other}"))),
    };
    if let Some(refused) = refused {
        if let Some(mut p) = put {
            p.curl.kill().await;
        }
        return Err(refused);
    }
    match put {
        Some(p) => p.answer(sent, hex::encode(h.finalize())).await,
        None => Err(transfer_failed("the release sent no bytes")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shim::s3xfer::WRITE_OUT;
    use crate::wire::s3::{S3Key, SIGNED_HEADERS_GET, SIGNED_HEADERS_PUT};

    const OWNER: &str = "123456789012";

    /// A presigned URL of the store at `key` (its signature made at run time), signed over `signed`.
    fn url(key: &str, signed: &str) -> crate::wire::s3::PresignedUrl {
        let sig = hex::encode(Sha256::digest(key.as_bytes()));
        let query = format!("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ai-env-fake-s3%2F20261023%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20261023T101530Z&X-Amz-Expires=900&X-Amz-SignedHeaders={}&X-Amz-Signature={sig}", signed.replace(';', "%3B"));
        crate::wire::s3::PresignedUrl::new(format!("https://ai-env-transcripts-{OWNER}.s3.eu-central-1.amazonaws.com/{key}?{query}")).unwrap()
    }

    /// The three curl configurations, line by line (§2.4): the fetch is S9's GET exactly (identity) and then
    /// `max-filesize` and `limit-rate`; the relay's PUT is S9's PUT exactly (the signed size, its checksum, the
    /// owner, no proxy); the release's GET is claudebin's own (https only, 3 redirects at most, no proxy).
    #[test]
    fn the_claude_curl_configs_are_pinned() {
        let (version, sha) = ("2.1.308", "ab".repeat(32));
        let key = S3Key::Claude { version: version.into(), sha256: sha.clone() }.render();
        let get = url(&key, SIGNED_HEADERS_GET);
        let stage = ClaudeStage { version: version.into(), sha256: sha.clone(), size: 290_000_000, url: get.clone(), owner: OWNER.into(), proxy: Some("http://10.42.0.10:3128".into()), wait_s: 0 };
        stage.check().unwrap();
        let common = |u: &crate::wire::s3::PresignedUrl, t: u64| format!("url = \"{}\"\nsilent\nshow-error\nproto = \"=https\"\nconnect-timeout = 20\nmax-time = {t}\nspeed-limit = 1024\nspeed-time = 60\n{WRITE_OUT}\n", u.expose());
        assert_eq!(
            fetch_config(&stage, 600),
            format!("{}proxy = \"http://10.42.0.10:3128\"\nrequest = \"GET\"\nheader = \"x-amz-expected-bucket-owner: {OWNER}\"\nfail\noutput = \"-\"\nmax-filesize = 290000000\nlimit-rate = 32M\n", common(&get, 600))
        );
        assert!(!fetch_config(&stage, 600).contains("\ncompressed\n"), "the claude object is stored raw");
        let put = url(&key, SIGNED_HEADERS_PUT);
        let relay = ClaudeRelay { version: version.into(), sha256: sha.clone(), size: 290_000_000, put: put.clone(), owner: OWNER.into() };
        relay.check().unwrap();
        let sum = sha256_b64(&sha).unwrap();
        assert_eq!(
            curl_config(&relay.put, None, 599, &Kind::Put { len: relay.size, checksum: Some(&sum), owner: &relay.owner }),
            format!("{}request = \"PUT\"\nupload-file = \"-\"\nheader = \"Content-Length: 290000000\"\nheader = \"Transfer-Encoding:\"\nheader = \"Expect:\"\nheader = \"x-amz-checksum-sha256: {sum}\"\nheader = \"If-None-Match: *\"\nheader = \"x-amz-expected-bucket-owner: {OWNER}\"\noutput = \"-\"\n", common(&put, 599))
        );
        assert_eq!(
            release_config(version, 290_000_000, 598),
            format!("url = \"https://downloads.claude.ai/claude-code-releases/2.1.308/linux-arm64/claude\"\nsilent\nshow-error\nproto = \"=https\"\ntlsv1.2\nconnect-timeout = 20\nmax-time = 598\nspeed-limit = 1024\nspeed-time = 60\n{RELEASE_WRITE_OUT}\nrequest = \"GET\"\nfail\nlocation\nproto-redir = \"=https\"\nmax-redirs = 3\nmax-filesize = 290000000\noutput = \"-\"\n")
        );
        assert!(!release_config(version, 1, 1).contains("proxy"), "an internet VM: no proxy");
        // LD-19's evidence: the store's write-out fields, then the redirects followed, which the log line names.
        assert_eq!(RELEASE_WRITE_OUT, WRITE_OUT.replace("etag=%header{etag}\\n", "etag=%header{etag} redirects=%{num_redirects}\\n"));
        assert_eq!(redirects_of("status=200 version= checksum= etag=\"x\" redirects=2"), Some(2));
        assert_eq!((redirects_of("status=200 version= checksum= etag=\"x\""), redirects_of("status=200 redirects=%{num_redirects}")), (None, None));
    }

    /// The eviction rules (§2.2 step 6): past the keep, least recently used first, never a running one (the count
    /// may stay over); a full disk's one eviction takes the least recently used one no spawn runs, never the
    /// fetch's own.
    #[test]
    fn eviction_keeps_two_and_never_a_running_one() {
        let e = |n: u8| ClaudeCacheEntry { version: format!("2.1.{n}"), sha256: format!("{n:02x}").repeat(32), size: 1, fetched_at: 0, last_used: 0 };
        let shas = |inner: &Inner| inner.entries.iter().map(|e| e.version.clone()).collect::<Vec<_>>();
        let mut inner = Inner { entries: vec![e(4), e(3), e(2), e(1)], ..Inner::default() };
        let running: BTreeSet<String> = [e(1).sha256].into();
        let gone = inner.evict_past_keep(&running);
        assert_eq!(gone.iter().map(|e| e.version.as_str()).collect::<Vec<_>>(), ["2.1.2"], "2.1.1 runs: kept");
        assert_eq!(shas(&inner), ["2.1.4", "2.1.3", "2.1.1"]);
        assert_eq!(inner.evict_past_keep(&BTreeSet::new()).len(), 1);
        assert_eq!(shas(&inner), ["2.1.4", "2.1.3"]);
        assert!(inner.evict_past_keep(&BTreeSet::new()).is_empty(), "at the keep: nothing");
        let one = inner.evict_one(&[e(3).sha256].into(), &e(9).sha256).unwrap();
        assert_eq!((one.version.as_str(), shas(&inner)), ("2.1.4", vec!["2.1.3".to_string()]));
        assert!(inner.evict_one(&BTreeSet::new(), &e(3).sha256).is_none(), "never the fetch's own");
        let mut inner = Inner { entries: vec![e(3), e(2), e(1)], ..Inner::default() };
        inner.picking.insert(e(1).sha256, 1);
        assert_eq!(inner.evict_past_keep(&BTreeSet::new()).len(), 0, "2.1.1 was picked for a spawn the manager does not hold yet");
        assert_eq!(inner.evict_one(&BTreeSet::new(), &e(9).sha256).map(|e| e.version), Some("2.1.2".to_string()), "nor the one eviction for space");
    }

    /// A pick's hold keeps its entry from eviction until it is dropped; the image's own ref needs none.
    #[test]
    fn a_pick_holds_its_binary_until_dropped() {
        let e = ClaudeCacheEntry { version: "2.1.1".into(), sha256: "01".repeat(32), size: 1, fetched_at: 0, last_used: 0 };
        let inner = Arc::new(Mutex::new(Inner { entries: vec![e.clone()], ..Inner::default() }));
        let hold = |sha: &str| {
            *inner.lock().unwrap().picking.entry(sha.to_string()).or_default() += 1;
            PickHold(Some((Arc::clone(&inner), sha.to_string())))
        };
        let (a, b) = (hold(&e.sha256), hold(&e.sha256));
        assert!(inner.lock().unwrap().evict_one(&BTreeSet::new(), "").is_none(), "held twice");
        drop(a);
        assert!(inner.lock().unwrap().evict_one(&BTreeSet::new(), "").is_none(), "still held once");
        drop(b);
        assert!(inner.lock().unwrap().picking.is_empty());
        assert_eq!(inner.lock().unwrap().evict_one(&BTreeSet::new(), "").map(|e| e.version), Some("2.1.1".to_string()));
        drop(PickHold(None));
    }

    /// A probe judges a fetched binary only by what it did itself (`version_mismatch` fails its version for good):
    /// an exit status and its own faults; a kill, a termination or an abort may come from outside.
    #[test]
    fn a_probe_judges_only_what_the_binary_did() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::ExitStatus;
        let judged = crate::shim::health::ended_of_itself;
        assert!(judged(ExitStatus::from_raw(3 << 8)), "an exit status");
        for sig in [libc::SIGSEGV, libc::SIGILL, libc::SIGBUS] {
            assert!(judged(ExitStatus::from_raw(sig)), "signal {sig}");
        }
        for sig in [libc::SIGKILL, libc::SIGTERM, libc::SIGABRT, libc::SIGINT] {
            assert!(!judged(ExitStatus::from_raw(sig)), "signal {sig}");
        }
    }
}
