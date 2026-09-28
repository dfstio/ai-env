//! Local resume seeder (stage S2, `AI_ENV_BRIDGE_MODE=local-scratch`).
//!
//! In `local-scratch` mode the child `claude` runs with `CLAUDE_CONFIG_DIR`
//! set to a private scratch directory, so it cannot see the Mac's
//! transcripts. The CLI resolves `--resume=<uuid>` by opening
//! `<config dir>/projects/<slug>/<uuid>.jsonl`; before such a child is
//! spawned the wrapper therefore copies the Mac's transcript and its subtree
//! `<slug>/<uuid>/**` (subagent transcripts and their `.meta.json`
//! companions) into `<scratch>/projects/<dst slug>/`.
//!
//! [`candidates`] lists the Mac project directories that hold the transcript,
//! best guess first; [`seed_local`] copies from one of them. Both check the
//! session id with [`is_uuid`] before any path is built from it, neither
//! follows a symlink out of the source tree, and the seeder never chmods a
//! directory that already exists. Every file is streamed through a
//! per-process temp name and renamed into place, so a seed is idempotent and
//! the child never reads a torn file. The whole copy is bounded by
//! [`MAX_SEED_BYTES`], checked before the first byte is written.
use crate::bridge::errors::BridgeError;
use crate::bridge::registry::is_uuid;
use std::ffi::OsString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Upper bound on the bytes one seed copies: `<uuid>.jsonl` plus every file of
/// the `<uuid>/` subtree, summed before anything is copied.
pub const MAX_SEED_BYTES: u64 = 64 * 1024 * 1024;

/// How many directory levels below `<uuid>/` the subtree walk enters
/// (`<uuid>/subagents` is level 1). Deeper directories are skipped with a warning.
pub const MAX_SUBTREE_DEPTH: usize = 8;

/// What one [`seed_local`] call did. `Default` is the empty report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeedReport {
    /// The Mac project directory the transcript was copied from.
    pub source: Option<PathBuf>,
    /// `<uuid>.jsonl` existed and was copied.
    pub copied_jsonl: bool,
    /// Regular files copied from the `<uuid>/` subtree.
    pub subtree_files: u32,
    /// Bytes copied in total (the transcript plus the subtree files).
    pub bytes: u64,
    /// Symlinks met in the subtree (to files or directories, the subtree root
    /// included) that were skipped rather than followed.
    pub skipped_symlinks: u32,
}

/// The Mac project directories `D = mac_projects/<slug>` that hold
/// `<session_id>.jsonl` as a regular file (checked with `symlink_metadata`: a
/// symlinked transcript does not count), in order and without duplicates.
///
/// First the given `slugs` in order (the cwd's slug, then the one the
/// session registry recorded), then every direct subdirectory of
/// `mac_projects` in name order (one `read_dir`, no recursion). A symlinked
/// project directory is skipped in both passes; so is a slug that is not a
/// single normal path component (empty, `.`, `..`, or containing `/` or NUL).
/// Empty when `session_id` is not a uuid or `mac_projects` cannot be listed
/// and no slug matched.
#[must_use]
pub fn candidates(mac_projects: &Path, slugs: &[&str], session_id: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    if !is_uuid(session_id) {
        return found;
    }
    let file = jsonl_name(session_id);
    let mut consider = |dir: PathBuf| {
        if !found.contains(&dir) && is_real_dir(&dir) && is_regular_file(&dir.join(&file)) {
            found.push(dir);
        }
    };
    for slug in slugs.iter().filter(|s| is_single_component(s)) {
        consider(mac_projects.join(slug));
    }
    for name in subdirectory_names(mac_projects) {
        consider(mac_projects.join(name));
    }
    found
}

/// Copy the transcript of `session_id` from the Mac project directory
/// `src_dir` into `dst_projects/dst_slug/`, bounded by [`MAX_SEED_BYTES`].
///
/// - Refuses (`Err(Config)`) a non-uuid `session_id` and a `dst_slug` that is
///   not a single normal path component — before touching the filesystem.
/// - `<src_dir>/<uuid>.jsonl` must be a regular file when present (a symlink or
///   any other file type is refused). `<src_dir>/<uuid>/`, when it is a real
///   directory, is walked up to [`MAX_SUBTREE_DEPTH`] levels: directories are
///   recreated, regular files copied, symlinks skipped and counted, other file
///   types (FIFOs, sockets) skipped.
/// - The sizes of everything to be copied are summed first; above the cap the
///   call fails with `transcript too large to seed: <n> bytes` and copies nothing.
/// - Missing directories on the destination side (`dst_projects` included) are
///   created 0700; existing ones are used as they are, never chmod'ed, but a
///   symlink where a directory belongs is refused.
/// - Each file is streamed into `.<name>.<pid>.tmp` beside its destination
///   (`create_new`, 0600, `O_NOFOLLOW`), fsync'ed, then renamed over the
///   destination, so a second call overwrites the first one's copies.
/// - A missing `<uuid>.jsonl` is not an error: the subtree is still copied and
///   the report says `copied_jsonl: false`. When both are missing nothing is
///   created and the report is empty apart from `source`.
pub fn seed_local(src_dir: &Path, session_id: &str, dst_projects: &Path, dst_slug: &str) -> Result<SeedReport, BridgeError> {
    seed_local_capped(src_dir, session_id, dst_projects, dst_slug, MAX_SEED_BYTES)
}

/// [`seed_local`] with the byte cap as a parameter (tests use a tiny one).
fn seed_local_capped(src_dir: &Path, session_id: &str, dst_projects: &Path, dst_slug: &str, cap: u64) -> Result<SeedReport, BridgeError> {
    if !is_uuid(session_id) {
        return Err(BridgeError::Config(format!("not a session id: {session_id:?}")));
    }
    if !is_single_component(dst_slug) {
        return Err(BridgeError::Config(format!("not a project directory name: {dst_slug:?}")));
    }
    let plan = plan(src_dir, session_id)?;
    let total = plan.total_bytes();
    if total > cap {
        return Err(BridgeError::Config(format!("transcript too large to seed: {total} bytes")));
    }
    let mut report = SeedReport { source: Some(src_dir.to_path_buf()), skipped_symlinks: plan.skipped_symlinks, ..SeedReport::default() };
    if plan.jsonl.is_none() && plan.subtree.is_none() {
        return Ok(report);
    }
    let dst = dst_projects.join(dst_slug);
    create_private_tree(&dst)?;
    let mut budget = cap;
    if plan.jsonl.is_some() {
        let name = jsonl_name(session_id);
        report.bytes += copy_file(&src_dir.join(&name), &dst.join(&name), &mut budget)?;
        report.copied_jsonl = true;
    }
    if let Some(entries) = &plan.subtree {
        let (src_root, dst_root) = (src_dir.join(session_id), dst.join(session_id));
        ensure_private_dir(&dst_root)?;
        for entry in entries {
            match entry {
                Entry::Dir(rel) => ensure_private_dir(&dst_root.join(rel))?,
                Entry::File(rel, _) => {
                    report.bytes += copy_file(&src_root.join(rel), &dst_root.join(rel), &mut budget)?;
                    report.subtree_files += 1;
                }
            }
        }
    }
    Ok(report)
}

// ---- planning --------------------------------------------------------------------------

/// Everything one seed will copy, gathered before the first byte moves.
#[derive(Debug, Default)]
struct Plan {
    /// Size of `<uuid>.jsonl` when it exists.
    jsonl: Option<u64>,
    /// The `<uuid>/` subtree when it is a real directory, parents before children.
    subtree: Option<Vec<Entry>>,
    /// Symlinks met (and skipped) while planning.
    skipped_symlinks: u32,
}

impl Plan {
    /// The bytes the plan copies.
    fn total_bytes(&self) -> u64 {
        let files = self.subtree.iter().flatten().map(|e| if let Entry::File(_, len) = e { *len } else { 0 });
        files.fold(self.jsonl.unwrap_or(0), u64::saturating_add)
    }
}

/// One item of the subtree, relative to `<uuid>/`.
#[derive(Debug)]
enum Entry {
    Dir(PathBuf),
    File(PathBuf, u64),
}

/// Inspect `<src_dir>/<uuid>.jsonl` and `<src_dir>/<uuid>/` without following symlinks.
fn plan(src_dir: &Path, session_id: &str) -> Result<Plan, BridgeError> {
    let mut plan = Plan::default();
    let jsonl = src_dir.join(jsonl_name(session_id));
    match std::fs::symlink_metadata(&jsonl) {
        Ok(m) if m.file_type().is_symlink() => return Err(BridgeError::Config(format!("{} is a symlink; refusing to seed from it", jsonl.display()))),
        Ok(m) if m.is_file() => plan.jsonl = Some(m.len()),
        Ok(_) => return Err(BridgeError::Config(format!("{} is not a regular file", jsonl.display()))),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(io_at("cannot stat", &jsonl)(e)),
    }
    let root = src_dir.join(session_id);
    match std::fs::symlink_metadata(&root) {
        Ok(m) if m.file_type().is_symlink() => plan.skipped_symlinks += 1,
        Ok(m) if m.is_dir() => {
            let mut entries = Vec::new();
            walk(&root, Path::new(""), 0, &mut entries, &mut plan.skipped_symlinks)?;
            plan.subtree = Some(entries);
        }
        Ok(_) => tracing::debug!("seed: {} is not a directory; no subtree", root.display()),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(io_at("cannot stat", &root)(e)),
    }
    Ok(plan)
}

/// Append the contents of the directory `dir` (whose path below `<uuid>/` is
/// `rel` and whose level is `depth`, the root being 0) to `out` in name order,
/// each directory before its own contents. Symlinks are counted in `skipped`,
/// never followed; directories below [`MAX_SUBTREE_DEPTH`] are not entered.
fn walk(dir: &Path, rel: &Path, depth: usize, out: &mut Vec<Entry>, skipped: &mut u32) -> Result<(), BridgeError> {
    let listing = std::fs::read_dir(dir).map_err(io_at("cannot list", dir))?;
    let mut entries = listing.collect::<Result<Vec<_>, _>>().map_err(io_at("cannot list", dir))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let (path, child) = (entry.path(), rel.join(entry.file_name()));
        let kind = entry.file_type().map_err(io_at("cannot stat", &path))?;
        if kind.is_symlink() {
            *skipped += 1;
        } else if kind.is_file() {
            let len = entry.metadata().map_err(io_at("cannot stat", &path))?.len();
            out.push(Entry::File(child, len));
        } else if kind.is_dir() && depth < MAX_SUBTREE_DEPTH {
            out.push(Entry::Dir(child.clone()));
            walk(&path, &child, depth + 1, out, skipped)?;
        } else if kind.is_dir() {
            tracing::warn!("seed: {} is nested deeper than {MAX_SUBTREE_DEPTH} levels; not copied", path.display());
        } else {
            tracing::debug!("seed: {} is not a regular file or directory; not copied", path.display());
        }
    }
    Ok(())
}

// ---- copying ---------------------------------------------------------------------------

/// Stream the regular file `src` into `dst` through a temp file beside `dst`
/// (see [`temp_path`]), fsync it and rename it over `dst`. At most `*budget`
/// bytes: a source that grew past the remaining budget since planning is
/// refused and leaves nothing behind. Returns the bytes copied and takes them
/// off the budget.
fn copy_file(src: &Path, dst: &Path, budget: &mut u64) -> Result<u64, BridgeError> {
    let input = open_source(src)?;
    let tmp = temp_path(dst);
    remove_if_present(&tmp)?;
    let result = stream_into(input, &tmp, dst, *budget);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    let copied = result?;
    *budget -= copied;
    Ok(copied)
}

/// Open `path` for reading only if it is a regular file: `O_NOFOLLOW` refuses a
/// symlink swapped in since planning, `O_NONBLOCK` keeps a FIFO from blocking
/// the open, and the descriptor's own metadata is checked.
fn open_source(path: &Path) -> Result<File, BridgeError> {
    let opened = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path);
    let file = match opened {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(BridgeError::Config(format!("{} is a symlink; refusing to seed from it", path.display()))),
        Err(e) => return Err(io_at("cannot open", path)(e)),
    };
    if !file.metadata().map_err(io_at("cannot stat", path))?.is_file() {
        return Err(BridgeError::Config(format!("{} is not a regular file", path.display())));
    }
    Ok(file)
}

/// The body of [`copy_file`] between opening the source and the rename.
fn stream_into(input: File, tmp: &Path, dst: &Path, budget: u64) -> Result<u64, BridgeError> {
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(tmp)
        .map_err(io_at("cannot create", tmp))?;
    let copied = std::io::copy(&mut input.take(budget.saturating_add(1)), &mut out).map_err(io_at("cannot copy into", tmp))?;
    if copied > budget {
        return Err(BridgeError::Config(format!("transcript too large to seed: more than {budget} bytes left for {}", dst.display())));
    }
    out.sync_all().map_err(io_at("cannot fsync", tmp))?;
    drop(out);
    std::fs::rename(tmp, dst).map_err(io_at("cannot rename onto", dst))?;
    Ok(copied)
}

/// `.<file name>.<pid>.tmp` in `dst`'s directory: one name per process, so
/// concurrent wrappers never share a temp file.
fn temp_path(dst: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(dst.file_name().unwrap_or_default());
    name.push(format!(".{}.tmp", std::process::id()));
    dst.with_file_name(name)
}

/// Remove `path` (a leftover temp file of this pid); a missing file is fine.
fn remove_if_present(path: &Path) -> Result<(), BridgeError> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(io_at("cannot remove", path)(e)),
        _ => Ok(()),
    }
}

// ---- directories -----------------------------------------------------------------------

/// Create `dir` and its missing parents 0700 (existing ones are left as they
/// are), then insist that `dir` itself is a real directory, not a symlink to one.
fn create_private_tree(dir: &Path) -> Result<(), BridgeError> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(io_at("cannot create", dir))?;
    require_real_dir(dir)
}

/// Create the single directory `dir` 0700, or accept it when it already is a
/// real directory (never chmod'ed); a symlink or a file there is refused.
fn ensure_private_dir(dir: &Path) -> Result<(), BridgeError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => require_real_dir(dir),
        Err(e) => Err(io_at("cannot create", dir)(e)),
    }
}

/// `Ok` when `dir` is a directory and not a symlink.
fn require_real_dir(dir: &Path) -> Result<(), BridgeError> {
    if is_real_dir(dir) {
        Ok(())
    } else {
        Err(BridgeError::Config(format!("{} is not a real directory; refusing to seed into it", dir.display())))
    }
}

// ---- small predicates ------------------------------------------------------------------

/// `<session_id>.jsonl`.
fn jsonl_name(session_id: &str) -> String {
    format!("{session_id}.jsonl")
}

/// Is `slug` usable as one directory name: non-empty, not `.` or `..`, no `/` or NUL?
fn is_single_component(slug: &str) -> bool {
    !slug.is_empty() && slug != "." && slug != ".." && !slug.contains(['/', '\0'])
}

/// `path` is a directory itself (a symlink to one does not count).
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// `path` is a regular file itself (a symlink to one does not count).
fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// Names of the real (non-symlinked) subdirectories of `dir`, sorted; empty
/// when `dir` cannot be listed.
fn subdirectory_names(dir: &Path) -> Vec<OsString> {
    let Ok(listing) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<OsString> = listing.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.file_name()).collect();
    names.sort();
    names
}

/// Wrap an I/O error with what was being done and to which path, keeping its kind.
fn io_at<'a>(what: &'static str, path: &'a Path) -> impl FnOnce(std::io::Error) -> BridgeError + 'a {
    move |e| BridgeError::Io(std::io::Error::new(e.kind(), format!("{what} {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const OTHER_ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";

    /// Write `bytes` to `path`, creating its parents.
    fn put(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn config_msg(r: Result<SeedReport, BridgeError>) -> String {
        match r {
            Err(BridgeError::Config(m)) => m,
            other => panic!("expected Err(Config), got {other:?}"),
        }
    }

    /// Every name below `dir`, relative, sorted (for leftover checks).
    fn tree(dir: &Path) -> Vec<String> {
        fn go(base: &Path, dir: &Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                out.push(e.path().strip_prefix(base).unwrap().display().to_string());
                if e.file_type().unwrap().is_dir() {
                    go(base, &e.path(), out);
                }
            }
        }
        let mut out = Vec::new();
        go(dir, dir, &mut out);
        out.sort();
        out
    }

    /// A Mac project dir `<tmp>/mac/projects/<slug>` with a transcript, two
    /// subagent files (one nested) and a `.meta.json` companion.
    fn fake_source(tmp: &Path, slug: &str) -> PathBuf {
        let src = tmp.join("mac/projects").join(slug);
        put(&src.join(format!("{ID}.jsonl")), b"{\"type\":\"user\",\"n\":1e21}\r\n{\"s\":\"\\u00e9\"}\n\xff\xfe no newline");
        put(&src.join(ID).join("subagents/agent-a1.jsonl"), b"{\"type\":\"assistant\"}\n");
        put(&src.join(ID).join("subagents/agent-a1.meta.json"), b"{\"agentType\":\"x\"}");
        put(&src.join(ID).join("subagents/workflows/x.jsonl"), b"{\"k\":2}\n{\"k\":3}\n");
        src
    }

    // ---- candidates ----

    #[test]
    fn candidates_order_given_slugs_then_scan_deduplicated() {
        let tmp = tempfile::tempdir().unwrap();
        let projects = tmp.path().join("projects");
        for slug in ["a-other", "m-cwd", "z-registry", "c-scan"] {
            put(&projects.join(slug).join(format!("{ID}.jsonl")), b"{}\n");
        }
        put(&projects.join("b-none").join(format!("{OTHER_ID}.jsonl")), b"{}\n");
        let got = candidates(&projects, &["m-cwd", "z-registry", "m-cwd", "missing"], ID);
        let want: Vec<PathBuf> = ["m-cwd", "z-registry", "a-other", "c-scan"].iter().map(|s| projects.join(s)).collect();
        assert_eq!(got, want);
        // No slugs: pure scan order.
        let scan: Vec<PathBuf> = ["a-other", "c-scan", "m-cwd", "z-registry"].iter().map(|s| projects.join(s)).collect();
        assert_eq!(candidates(&projects, &[], ID), scan);
        // A missing projects dir is no candidates, not a panic.
        assert!(candidates(&tmp.path().join("nope"), &["m-cwd"], ID).is_empty());
    }

    #[test]
    fn candidates_skip_a_symlinked_jsonl_and_a_non_file_jsonl() {
        let tmp = tempfile::tempdir().unwrap();
        let projects = tmp.path().join("projects");
        let elsewhere = tmp.path().join("elsewhere.jsonl");
        put(&elsewhere, b"{}\n");
        std::fs::create_dir_all(projects.join("linked")).unwrap();
        symlink(&elsewhere, projects.join("linked").join(format!("{ID}.jsonl"))).unwrap();
        std::fs::create_dir_all(projects.join("dir-named").join(format!("{ID}.jsonl"))).unwrap();
        put(&projects.join("real").join(format!("{ID}.jsonl")), b"{}\n");
        assert_eq!(candidates(&projects, &["linked", "dir-named"], ID), vec![projects.join("real")]);
    }

    #[test]
    fn candidates_skip_a_symlinked_project_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let projects = tmp.path().join("projects");
        let outside = tmp.path().join("outside");
        put(&outside.join(format!("{ID}.jsonl")), b"{}\n");
        std::fs::create_dir_all(&projects).unwrap();
        symlink(&outside, projects.join("a-link")).unwrap();
        assert!(candidates(&projects, &[], ID).is_empty(), "scan skips a symlinked subdirectory");
        assert!(candidates(&projects, &["a-link"], ID).is_empty(), "a given slug naming a symlink is skipped too");
    }

    #[test]
    fn candidates_empty_for_non_uuid_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let projects = tmp.path().join("projects");
        put(&projects.join("p/not-a-uuid.jsonl"), b"{}\n");
        put(&projects.join("p/.jsonl"), b"{}\n");
        put(&projects.join(format!("p/{ID}.jsonl")), b"{}\n");
        for bad in ["not-a-uuid", "", "../p/x", &ID[..35], &format!("{ID}x")] {
            assert!(candidates(&projects, &["p"], bad).is_empty(), "{bad:?}");
        }
        assert_eq!(candidates(&projects, &["p"], ID), vec![projects.join("p")]);
    }

    #[test]
    fn candidates_skip_bad_slugs() {
        let tmp = tempfile::tempdir().unwrap();
        let projects = tmp.path().join("projects");
        let file = format!("{ID}.jsonl");
        put(&tmp.path().join(&file), b"{}\n"); // reachable via ".."
        put(&projects.join(&file), b"{}\n"); // reachable via "" and "."
        put(&projects.join("a/b").join(&file), b"{}\n"); // reachable via "a/b"
        let abs = tmp.path().to_str().unwrap(); // an absolute slug replaces the whole path in `join`
        assert!(candidates(&projects, &["..", "a/b", "", ".", "a/", abs, "a\0"], ID).is_empty());
    }

    // ---- seed_local ----

    #[test]
    fn seed_copies_jsonl_and_subtree_byte_for_byte() {
        let tmp = tempfile::tempdir().unwrap();
        let src = fake_source(tmp.path(), "-Users-mike-proj");
        let dst_projects = tmp.path().join("scratch/projects");
        let report = seed_local(&src, ID, &dst_projects, "-Users-mike-proj").unwrap();
        let dst = dst_projects.join("-Users-mike-proj");
        let rels = [".jsonl", "/subagents/agent-a1.jsonl", "/subagents/agent-a1.meta.json", "/subagents/workflows/x.jsonl"].map(|tail| format!("{ID}{tail}"));
        for rel in &rels {
            assert_eq!(std::fs::read(dst.join(rel)).unwrap(), std::fs::read(src.join(rel)).unwrap(), "{rel}");
        }
        let total: u64 = rels.iter().map(|r| std::fs::metadata(src.join(r)).unwrap().len()).sum();
        assert_eq!(report, SeedReport { source: Some(src.clone()), copied_jsonl: true, subtree_files: 3, bytes: total, skipped_symlinks: 0 });
        assert!(!tree(&dst).iter().any(|n| n.ends_with(".tmp")), "no temp leftovers: {:?}", tree(&dst));
    }

    #[test]
    fn seed_modes_are_private_and_existing_dirs_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let src = fake_source(tmp.path(), "p");
        for f in [src.join(format!("{ID}.jsonl")), src.join(ID).join("subagents/agent-a1.jsonl")] {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        // Fresh destination: every created directory 0700, every file 0600.
        let fresh = tmp.path().join("fresh/projects");
        seed_local(&src, ID, &fresh, "p").unwrap();
        let sub = fresh.join("p").join(ID);
        for d in [fresh.clone(), fresh.join("p"), sub.clone(), sub.join("subagents"), sub.join("subagents/workflows")] {
            assert_eq!(mode_of(&d), 0o700, "{}", d.display());
        }
        for f in [fresh.join(format!("p/{ID}.jsonl")), sub.join("subagents/agent-a1.jsonl"), sub.join("subagents/workflows/x.jsonl")] {
            assert_eq!(mode_of(&f), 0o600, "{}", f.display());
        }
        // Pre-existing 0755 directories are used, never chmod'ed.
        let existing = tmp.path().join("existing/projects");
        std::fs::create_dir_all(existing.join("p").join(ID)).unwrap();
        for d in [existing.clone(), existing.join("p"), existing.join("p").join(ID)] {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        seed_local(&src, ID, &existing, "p").unwrap();
        for d in [existing.clone(), existing.join("p"), existing.join("p").join(ID)] {
            assert_eq!(mode_of(&d), 0o755, "{}", d.display());
        }
        assert_eq!(mode_of(&existing.join("p").join(ID).join("subagents")), 0o700);
    }

    #[test]
    fn seed_skips_and_counts_symlinks_in_the_subtree() {
        let tmp = tempfile::tempdir().unwrap();
        let src = fake_source(tmp.path(), "p");
        let outside_file = tmp.path().join("outside.jsonl");
        put(&outside_file, b"TARGET-FILE\n");
        let outside_dir = tmp.path().join("outside-dir");
        put(&outside_dir.join("inner.jsonl"), b"TARGET-DIR\n");
        symlink(&outside_file, src.join(ID).join("subagents/link.jsonl")).unwrap();
        symlink(&outside_dir, src.join(ID).join("linkdir")).unwrap();
        let dst_projects = tmp.path().join("dst");
        let report = seed_local(&src, ID, &dst_projects, "p").unwrap();
        assert_eq!(report.skipped_symlinks, 2);
        assert_eq!(report.subtree_files, 3);
        let dst = dst_projects.join("p").join(ID);
        assert!(std::fs::symlink_metadata(dst.join("subagents/link.jsonl")).is_err());
        assert!(std::fs::symlink_metadata(dst.join("linkdir")).is_err());
        assert!(std::fs::symlink_metadata(dst.join("inner.jsonl")).is_err());
        assert_eq!(tree(&dst), vec!["subagents", "subagents/agent-a1.jsonl", "subagents/agent-a1.meta.json", "subagents/workflows", "subagents/workflows/x.jsonl"]);
    }

    #[test]
    fn seed_skips_a_symlinked_subtree_root_and_a_fifo() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        put(&src.join(format!("{ID}.jsonl")), b"{}\n");
        let outside = tmp.path().join("outside");
        put(&outside.join("subagents/a.jsonl"), b"{}\n");
        symlink(&outside, src.join(ID)).unwrap();
        let report = seed_local(&src, ID, &tmp.path().join("dst"), "p").unwrap();
        assert_eq!((report.copied_jsonl, report.subtree_files, report.skipped_symlinks), (true, 0, 1));
        assert!(std::fs::symlink_metadata(tmp.path().join("dst/p").join(ID)).is_err());

        let src2 = tmp.path().join("src2");
        put(&src2.join(ID).join("a.jsonl"), b"{}\n");
        let fifo = std::ffi::CString::new(src2.join(ID).join("pipe").into_os_string().into_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let report = seed_local(&src2, ID, &tmp.path().join("dst2"), "p").unwrap();
        assert_eq!((report.copied_jsonl, report.subtree_files, report.skipped_symlinks), (false, 1, 0));
        assert!(std::fs::symlink_metadata(tmp.path().join("dst2/p").join(ID).join("pipe")).is_err());
    }

    #[test]
    fn seed_is_idempotent_and_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let src = fake_source(tmp.path(), "p");
        let dst_projects = tmp.path().join("dst");
        let first = seed_local(&src, ID, &dst_projects, "p").unwrap();
        let jsonl = dst_projects.join("p").join(format!("{ID}.jsonl"));
        std::fs::write(&jsonl, b"stale").unwrap();
        std::fs::write(dst_projects.join("p").join(ID).join("subagents/agent-a1.jsonl"), b"stale").unwrap();
        // A leftover temp file of this very pid does not block the copy.
        std::fs::write(dst_projects.join("p").join(format!(".{ID}.jsonl.{}.tmp", std::process::id())), b"junk").unwrap();
        let second = seed_local(&src, ID, &dst_projects, "p").unwrap();
        assert_eq!(first, second);
        assert_eq!(std::fs::read(&jsonl).unwrap(), std::fs::read(src.join(format!("{ID}.jsonl"))).unwrap());
        assert_eq!(std::fs::read(dst_projects.join("p").join(ID).join("subagents/agent-a1.jsonl")).unwrap(), b"{\"type\":\"assistant\"}\n");
        assert!(!tree(&dst_projects).iter().any(|n| n.ends_with(".tmp")), "{:?}", tree(&dst_projects));
    }

    #[test]
    fn seed_byte_cap_is_checked_before_copying() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        put(&src.join(format!("{ID}.jsonl")), &[b'x'; 20]);
        let dst_projects = tmp.path().join("dst");
        assert_eq!(config_msg(seed_local_capped(&src, ID, &dst_projects, "p", 10)), "transcript too large to seed: 20 bytes");
        assert!(!dst_projects.exists(), "nothing created when over the cap");
        // The subtree counts toward the cap too: 6 + 6 > 10.
        let src2 = tmp.path().join("src2");
        put(&src2.join(format!("{ID}.jsonl")), b"abcdef");
        put(&src2.join(ID).join("subagents/a.jsonl"), b"ghijkl");
        assert_eq!(config_msg(seed_local_capped(&src2, ID, &dst_projects, "p", 10)), "transcript too large to seed: 12 bytes");
        assert!(!dst_projects.exists());
        // Exactly at the cap is fine.
        let src3 = tmp.path().join("src3");
        put(&src3.join(format!("{ID}.jsonl")), b"abcde");
        put(&src3.join(ID).join("subagents/a.jsonl"), b"fghij");
        let report = seed_local_capped(&src3, ID, &dst_projects, "p", 10).unwrap();
        assert_eq!((report.bytes, report.subtree_files), (10, 1));
    }

    #[test]
    fn copy_refuses_a_source_that_outgrew_the_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let (src, dst) = (tmp.path().join("src.jsonl"), tmp.path().join("dst.jsonl"));
        put(&src, b"0123456789");
        let mut budget = 4;
        assert!(matches!(copy_file(&src, &dst, &mut budget), Err(BridgeError::Config(m)) if m.contains("too large")));
        assert_eq!(budget, 4);
        assert_eq!(tree(tmp.path()), vec!["src.jsonl"], "neither the target nor a temp file is left");
        let mut budget = 12;
        assert_eq!(copy_file(&src, &dst, &mut budget).unwrap(), 10);
        assert_eq!(budget, 2);
    }

    #[test]
    fn seed_refuses_a_symlinked_or_non_file_source_jsonl() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let elsewhere = tmp.path().join("elsewhere.jsonl");
        put(&elsewhere, b"{}\n");
        std::fs::create_dir_all(&src).unwrap();
        symlink(&elsewhere, src.join(format!("{ID}.jsonl"))).unwrap();
        let dst_projects = tmp.path().join("dst");
        assert!(config_msg(seed_local(&src, ID, &dst_projects, "p")).contains("symlink"));
        assert!(!dst_projects.exists());
        let src2 = tmp.path().join("src2");
        std::fs::create_dir_all(src2.join(format!("{ID}.jsonl"))).unwrap();
        assert!(config_msg(seed_local(&src2, ID, &dst_projects, "p")).contains("not a regular file"));
        assert!(!dst_projects.exists());
    }

    #[test]
    fn seed_refuses_a_symlinked_destination_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let src = fake_source(tmp.path(), "p");
        let dst_projects = tmp.path().join("dst");
        let target = tmp.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&dst_projects).unwrap();
        symlink(&target, dst_projects.join("p")).unwrap();
        assert!(config_msg(seed_local(&src, ID, &dst_projects, "p")).contains("not a real directory"));
        assert!(tree(&target).is_empty(), "nothing written through the symlink");
        // A symlink where the subtree root `<dst>/<uuid>` belongs is refused as well.
        let dst2 = tmp.path().join("dst2");
        std::fs::create_dir_all(dst2.join("p")).unwrap();
        symlink(&target, dst2.join("p").join(ID)).unwrap();
        assert!(config_msg(seed_local(&src, ID, &dst2, "p")).contains("not a real directory"));
        assert!(tree(&target).is_empty(), "nothing written through the subtree-root symlink");
    }

    #[test]
    fn copy_refuses_a_symlink_or_fifo_swapped_in_after_planning() {
        let tmp = tempfile::tempdir().unwrap();
        let (real, link, dst) = (tmp.path().join("real.jsonl"), tmp.path().join("link.jsonl"), tmp.path().join("dst.jsonl"));
        put(&real, b"{}\n");
        symlink(&real, &link).unwrap();
        let mut budget = 100;
        assert!(matches!(copy_file(&link, &dst, &mut budget), Err(BridgeError::Config(m)) if m.contains("is a symlink")));
        let pipe = tmp.path().join("pipe");
        let fifo = std::ffi::CString::new(pipe.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        // On a thread with a deadline: without O_NONBLOCK the open would block forever.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(copy_file(&pipe, &dst, &mut 100)).unwrap());
        let got = rx.recv_timeout(std::time::Duration::from_secs(10)).expect("opening a FIFO must not block");
        assert!(matches!(got, Err(BridgeError::Config(m)) if m.contains("not a regular file")));
        assert_eq!(budget, 100);
        assert_eq!(tree(tmp.path()), vec!["link.jsonl", "pipe", "real.jsonl"], "neither the target nor a temp file is left");
    }

    #[test]
    fn seed_refuses_non_uuid_ids_and_bad_dst_slugs() {
        let tmp = tempfile::tempdir().unwrap();
        let src = fake_source(tmp.path(), "p");
        let dst_projects = tmp.path().join("dst");
        for bad in ["not-a-uuid", "", "../../etc/x", &format!("{ID}/..")] {
            assert!(config_msg(seed_local(&src, bad, &dst_projects, "p")).starts_with("not a session id"), "{bad:?}");
        }
        for bad in ["..", ".", "a/b", "", "/abs", "p/", "a\0b"] {
            assert!(config_msg(seed_local(&src, ID, &dst_projects, bad)).starts_with("not a project directory name"), "{bad:?}");
        }
        assert!(!dst_projects.exists(), "refusals touch nothing");
    }

    #[test]
    fn seed_missing_jsonl_still_copies_the_subtree() {
        let tmp = tempfile::tempdir().unwrap();
        let src = fake_source(tmp.path(), "p");
        std::fs::remove_file(src.join(format!("{ID}.jsonl"))).unwrap();
        let dst_projects = tmp.path().join("dst");
        let report = seed_local(&src, ID, &dst_projects, "q").unwrap();
        assert!(!report.copied_jsonl);
        assert_eq!(report.subtree_files, 3);
        assert!(!dst_projects.join("q").join(format!("{ID}.jsonl")).exists());
        assert!(dst_projects.join("q").join(ID).join("subagents/workflows/x.jsonl").is_file());
    }

    #[test]
    fn seed_with_nothing_to_copy_creates_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        let dst_projects = tmp.path().join("dst");
        let report = seed_local(&src, ID, &dst_projects, "p").unwrap();
        assert_eq!(report, SeedReport { source: Some(src), ..SeedReport::default() });
        assert!(!dst_projects.exists());
    }

    #[test]
    fn seed_stops_at_the_depth_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let mut deep = src.join(ID);
        for level in 1..=MAX_SUBTREE_DEPTH + 1 {
            deep = deep.join(format!("d{level}"));
            put(&deep.join("f.jsonl"), b"{}\n");
        }
        let report = seed_local(&src, ID, &tmp.path().join("dst"), "p").unwrap();
        assert_eq!(report.subtree_files as usize, MAX_SUBTREE_DEPTH);
        let mut last_ok = tmp.path().join("dst/p").join(ID);
        for level in 1..=MAX_SUBTREE_DEPTH {
            last_ok = last_ok.join(format!("d{level}"));
        }
        assert!(last_ok.join("f.jsonl").is_file());
        assert!(!last_ok.join(format!("d{}", MAX_SUBTREE_DEPTH + 1)).exists());
    }

    #[test]
    fn temp_path_is_hidden_and_pid_suffixed() {
        let p = temp_path(Path::new("/x/p").join(format!("{ID}.jsonl")).as_path());
        assert_eq!(p, Path::new("/x/p").join(format!(".{ID}.jsonl.{}.tmp", std::process::id())));
    }
}
