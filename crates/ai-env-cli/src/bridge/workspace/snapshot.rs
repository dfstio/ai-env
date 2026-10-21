//! The WIP (S8 D2): the uncommitted changes — tracked, and untracked files
//! that are not ignored, vetted and capped by `[seed]` — as deterministic
//! commits built in a scratch bare repository under `state/tmp/` whose
//! alternates point at the user's object store, from copies of the index:
//! the user's index, working tree, stash, refs and objects are never
//! touched. Built in S8 wave 1 (W4).
//!
//! Every run reads the user's repository as it is configured (its git dir,
//! so `.git/info/exclude`, the user's global excludes, `core.autocrlf` and
//! the clean filters apply exactly as to a `git add` there), with three
//! things moved aside: the index (`GIT_INDEX_FILE`, a copy in the scratch
//! directory), the object store new objects go to (`GIT_OBJECT_DIRECTORY`,
//! the scratch repository's, whose alternates read the user's) and the
//! author (`ai-env seed`, HEAD's committer date, so one dirty state always
//! gives one pair of commit ids).
use super::blobscan::{shown_path, ScanSet, PATH_NAME};
use super::{git_failed, SeedLimits, WorkspaceRef, WsKind};
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::registry::{ensure_private_dir, pid_alive};
use crate::gitrun::{GitError, GitRun};
use crate::wire::workspace::ObjectFormat;
use std::collections::BTreeSet;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The author and committer of a WIP commit.
pub const SEED_AUTHOR: (&str, &str) = ("ai-env seed", "seed@ai-env.invalid");
/// The WIP commit's message (the worktree to leave).
pub const WIP_MESSAGE: &str = "ai-env seed: uncommitted changes";
/// The index commit's message (the index to leave).
pub const INDEX_MESSAGE: &str = "ai-env seed: staged changes";
/// How many files a `wip_too_large` refusal names.
pub const LARGEST_NAMED: usize = 5;

/// A scratch bare repository under `state/tmp/` (`<prefix>-<pid>-XXXX/repo.git`,
/// the directory 0700): new objects go to its store, whose
/// `objects/info/alternates` reads the user's. Removed, with everything in
/// it, when dropped; one a process left when it exited under it (no
/// destructor runs at `process::exit`: the wrapper's close abandons a
/// running fetch) goes when the next one is made (`sweep_tmp`), and the
/// wrapper removes its own once its close's waits are over (S9:
/// [`remove_own_scratch`]).
#[derive(Debug)]
pub struct Scratch {
    dir: tempfile::TempDir,
    repo: PathBuf,
    format: ObjectFormat,
    /// Every git run in it (and the user's index copies') given up once set
    /// ([`Scratch::cancel_on`]).
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// Remove the scratch directories of `tmp` whose process is gone: each
/// `<prefix>-<pid>-*` directory whose pid is neither this process nor a
/// running one. Best effort: a failure is logged.
fn sweep_tmp(tmp: &Path) {
    let Ok(entries) = std::fs::read_dir(tmp) else { return };
    let own = std::process::id();
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.rsplit('-').nth(1)).and_then(|p| p.parse::<u32>().ok()) else { continue };
        if pid == own || pid_alive(pid) || !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            // Another process's sweep took it first.
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => tracing::warn!("the scratch directory {} of a process that is gone was not removed: {e}", entry.path().display()),
            _ => {}
        }
    }
}

/// Remove this process's own scratch directories under `state/tmp/` (each
/// `<prefix>-<pid>-*` directory of its pid: a code-out's, a seed's, any
/// other's), as the wrapper exits (S9: after its close's waits,
/// a fetch given up at `codeout::CLOSE_WAIT` leaves its scratch repository,
/// whose alternates name the user's object store, and perhaps a pack never
/// scanned, until another process's sweep). A run still at work in one
/// fails, which nothing waits for any more. Best effort: a failure is logged.
pub fn remove_own_scratch(paths: &Paths) {
    let Ok(entries) = std::fs::read_dir(paths.tmp()) else { return };
    let own = std::process::id();
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        let pid = name.to_str().and_then(|n| n.rsplit('-').nth(1)).and_then(|p| p.parse::<u32>().ok());
        if pid != Some(own) || !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => tracing::warn!("this process's scratch directory {} was not removed: {e}", entry.path().display()),
            _ => {}
        }
    }
}

impl Scratch {
    /// A new scratch repository of `format` borrowing the object store
    /// `objects` (the user's `<common dir>/objects`); the scratch
    /// directories of processes that are gone are removed first.
    pub fn new(paths: &Paths, prefix: &str, objects: &Path, format: ObjectFormat) -> Result<Scratch, BridgeError> {
        let tmp = paths.tmp();
        ensure_private_dir(&tmp)?;
        sweep_tmp(&tmp);
        let dir = tempfile::Builder::new().prefix(&format!("{prefix}-{}-", std::process::id())).tempdir_in(&tmp).map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot create a scratch directory in {}: {e}", tmp.display()))))?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let repo = dir.path().join("repo.git");
        GitRun::mac(dir.path())
            .output([std::ffi::OsStr::new("init"), "--bare".as_ref(), "--quiet".as_ref(), "--template=".as_ref(), format!("--object-format={}", format.name()).as_ref(), repo.as_os_str()])
            .map_err(git_failed("git init of the scratch repository"))?;
        let info = repo.join("objects").join("info");
        std::fs::create_dir_all(&info)?;
        let objects = objects.to_str().ok_or_else(|| BridgeError::WorkspaceFailed { code: super::code::UNSUPPORTED_REPO, message: format!("{} is not UTF-8", objects.display()) })?;
        write_private(&info.join("alternates"), format!("{objects}\n").as_bytes())?;
        Ok(Scratch { dir, repo, format, cancel: None })
    }

    /// Give up its git runs once `flag` is set (`gitrun::GitRun::cancel_on`);
    /// `None`: never (what a prepared seed keeps for its sends).
    pub(crate) fn cancel_on(&mut self, flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>) {
        self.cancel = flag;
    }

    /// The scratch directory (the bodies, the packs and the index copies live here).
    #[must_use]
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// The bare repository.
    #[must_use]
    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// Its object format.
    #[must_use]
    pub fn format(&self) -> ObjectFormat {
        self.format
    }

    /// git in the scratch repository (its objects, the user's through the alternates).
    #[must_use]
    pub fn git(&self) -> GitRun {
        self.cancellable(GitRun::mac(self.dir.path()).env("GIT_DIR", &self.repo))
    }

    /// `git` given up with the scratch's runs ([`Scratch::cancel_on`]).
    fn cancellable(&self, git: GitRun) -> GitRun {
        match &self.cancel {
            Some(flag) => git.cancel_on(std::sync::Arc::clone(flag)),
            None => git,
        }
    }
}

/// A new file `path` (0600, never through a symlink) holding `bytes`.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), BridgeError> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// A copy of the user's index (`bytes`, read from `src`) at `dst` with the
/// original's mtime: git trusts an entry's cached stat only when the file is
/// older than the index, so a copy with a newer mtime would take a file
/// edited in the index's own second, at the same size, for clean (the racy
/// case git guards against by that comparison).
fn copy_index(src: &Path, bytes: &[u8], dst: &Path) -> Result<(), BridgeError> {
    write_private(dst, bytes)?;
    let modified = std::fs::metadata(src)?.modified()?;
    std::fs::OpenOptions::new().write(true).open(dst)?.set_modified(modified)?;
    Ok(())
}

/// The uncommitted changes as two commits on HEAD (or one: no staged change).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wip {
    /// The commit it sits on (the Mac's HEAD) and its tree.
    pub head: String,
    pub head_tree: String,
    /// The WIP commit: its tree is the worktree to leave in the VM (tracked
    /// changes and the vetted untracked files).
    pub commit: String,
    pub tree: String,
    /// The index commit when the staged tree is not HEAD's (its tree the index to leave).
    pub index_commit: Option<String>,
    /// The staged tree (HEAD's when nothing is staged, or the index has conflicts).
    pub index_tree: String,
    /// Paths the WIP or the index changes, adds or deletes against HEAD (the
    /// untracked ones included), and of them the untracked files carried.
    pub changed: u32,
    pub untracked: u32,
    /// The bytes of the blobs the two trees add to HEAD's.
    pub new_bytes: u64,
    /// Paths the two trees add to HEAD's (L9's dotenv rule reads these), in byte order.
    pub added: Vec<String>,
    /// What was left behind, and why (a nested repository, a FIFO, a conflicted index).
    pub notes: Vec<String>,
}

impl Wip {
    /// The worktree's tree as the VM records it: `None` when it is HEAD's.
    #[must_use]
    pub fn wip_tree(&self) -> Option<&str> {
        (self.tree != self.head_tree).then_some(self.tree.as_str())
    }

    /// The index's tree as the VM records it: `None` when it is HEAD's.
    #[must_use]
    pub fn staged_tree(&self) -> Option<&str> {
        (self.index_tree != self.head_tree).then_some(self.index_tree.as_str())
    }
}

/// The text of git's stdout, its trailing newline taken off.
pub(crate) fn line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches(['\n', '\r']).to_string()
}

/// git reading the user's repository of `ws` with the scratch store for new
/// objects and `index` for the index (both moved aside, see the module doc).
fn user_git(ws: &WorkspaceRef, scratch: &Scratch, index: &Path) -> Result<GitRun, BridgeError> {
    let WsKind::Git { git_dir, .. } = &ws.kind;
    Ok(scratch.cancellable(
        GitRun::mac(&ws.root).env("GIT_DIR", git_dir).env("GIT_WORK_TREE", &ws.root).env("GIT_INDEX_FILE", index).env("GIT_OBJECT_DIRECTORY", scratch.repo().join("objects")),
    ))
}

/// HEAD's committer date in git's internal form (`<unix> <+zone>`), for a WIP
/// commit that is the same commit whenever the dirty state is the same.
fn head_date(git: &GitRun, head: &str) -> Result<String, BridgeError> {
    let out = git.output(["log", "-1", "--format=%cd", "--date=raw", head]).map_err(git_failed("git log of HEAD's date"))?;
    let date = line(&out);
    if date.split(' ').count() != 2 || !date.split(' ').next().is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())) {
        return Err(BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: "git log printed no date for HEAD".into() });
    }
    Ok(date)
}

/// One untracked file the WIP would carry: its path and size (a symlink's is its target's length).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Untracked {
    path: String,
    size: u64,
}

/// `(path, size)` pairs over a cap, as a refusal names them: the
/// [`LARGEST_NAMED`] largest, largest first, ties by path; a path one of
/// `set`'s rules matches is `a path name`, as a finding shows it
/// ([`shown_path`]: a custom tripwire's match is never scrubbed).
fn largest(set: &ScanSet, mut files: Vec<(String, u64)>) -> String {
    files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    files.iter().take(LARGEST_NAMED).map(|(p, s)| format!("{} ({})", noted(set, p), human_bytes(*s))).collect::<Vec<_>>().join(", ")
}

/// `path` as a note or a refusal names it: a path one of `set`'s rules
/// matches is `a path name` ([`shown_path`]), and what is left is scrubbed
/// (S9: a seed's notes of what it does not carry name their paths this way,
/// as [`largest`] does).
fn noted(set: &ScanSet, path: &str) -> String {
    crate::wire::redact::scrub(&shown_path(set, path)).into_owned()
}

/// [`git_failed`] for a git run whose text names the user's files: when one
/// of `set`'s rules matches that text, it is left out (`{what}: git failed
/// on a path name`), as [`largest`] leaves such a path out.
fn git_failed_shown<'a>(set: &'a ScanSet, what: &'a str) -> impl FnOnce(GitError) -> BridgeError + 'a {
    move |e| match git_failed(what)(e) {
        BridgeError::WorkspaceFailed { code, message } if !set.rules.scan_bytes(message.as_bytes()).is_empty() => BridgeError::WorkspaceFailed { code, message: format!("{what}: git failed on {PATH_NAME}") },
        other => other,
    }
}

/// `12.3 MiB`, `4.0 KiB`, `17 B`.
#[must_use]
pub fn human_bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    let f = n as f64;
    if f >= KIB * KIB {
        format!("{:.1} MiB", f / (KIB * KIB))
    } else if f >= KIB {
        format!("{:.1} KiB", f / KIB)
    } else {
        format!("{n} B")
    }
}

/// The untracked, not ignored files of the worktree (`ls-files --others
/// --exclude-standard` against `git`'s index), vetted: regular files and
/// symlinks are kept; a nested repository (listed as `dir/`), a FIFO, a
/// socket or a device is noted and left out, its path named as `set`'s
/// rules let it be shown ([`noted`]: the note reaches stderr). Then the
/// caps: at most `max_untracked_files` files, none over `max_blob_bytes`, at
/// most `max_wip_bytes` in all, else `wip_too_large` naming the largest (the
/// same way, [`largest`]). A file it cannot stat fails, named the same way.
fn untracked(ws: &WorkspaceRef, git: &GitRun, lim: &SeedLimits, set: &ScanSet, notes: &mut Vec<String>) -> Result<Vec<Untracked>, BridgeError> {
    let out = git.output(["ls-files", "-z", "--others", "--exclude-standard"]).map_err(git_failed("git ls-files of the untracked files"))?;
    let mut kept = Vec::new();
    for raw in out.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let Ok(path) = std::str::from_utf8(raw) else {
            notes.push(format!("an untracked file whose name is not UTF-8 is not carried ({})", noted(set, &String::from_utf8_lossy(raw))));
            continue;
        };
        if path.ends_with('/') {
            notes.push(format!("{} is a nested repository: not carried", noted(set, path)));
            continue;
        }
        let meta = match std::fs::symlink_metadata(ws.root.join(path)) {
            Ok(m) => m,
            // Gone since it was listed: nothing to carry.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot stat {}: {e}", noted(set, path))))),
        };
        let kind = meta.file_type();
        if kind.is_file() || kind.is_symlink() {
            kept.push(Untracked { path: path.to_string(), size: meta.size() });
        } else {
            let what = if kind.is_dir() { "a directory" } else { "not a regular file (a FIFO, a socket or a device)" };
            notes.push(format!("{} is {what}: not carried", noted(set, path)));
        }
    }
    let all = || kept.iter().map(|u| (u.path.clone(), u.size)).collect::<Vec<_>>();
    let cap = |what: String| BridgeError::WorkspaceRefused { code: super::code::WIP_TOO_LARGE, message: what };
    if kept.len() > lim.max_untracked_files as usize {
        return Err(cap(format!(
            "{} carries {} untracked files, over [seed].max_untracked_files ({}): ignore them (.gitignore) or commit them; the largest: {}",
            ws.root.display(),
            kept.len(),
            lim.max_untracked_files,
            largest(set, all())
        )));
    }
    let over: Vec<(String, u64)> = kept.iter().filter(|u| u.size > lim.max_blob_bytes).map(|u| (u.path.clone(), u.size)).collect();
    if !over.is_empty() {
        return Err(cap(format!("untracked files over [seed].max_blob_mib ({}): {}", human_bytes(lim.max_blob_bytes), largest(set, over))));
    }
    let total: u64 = kept.iter().map(|u| u.size).sum();
    if total > lim.max_wip_bytes {
        return Err(cap(format!("the untracked files hold {}, over [seed].max_wip_mib ({}); the largest: {}", human_bytes(total), human_bytes(lim.max_wip_bytes), largest(set, all()))));
    }
    Ok(kept)
}

/// The paths `from` to `to` changes (`diff-tree -r --raw --no-renames`):
/// for each, whether it is added, and the new blob (none for a deletion).
fn changes(git: &GitRun, from: &str, to: &str) -> Result<Vec<(String, bool, Option<String>)>, BridgeError> {
    if from == to {
        return Ok(Vec::new());
    }
    let out = git.output(["diff-tree", "-r", "-z", "--raw", "--no-renames", from, to]).map_err(git_failed("git diff-tree of the WIP"))?;
    let mut parts = out.split(|b| *b == 0).filter(|p| !p.is_empty());
    let mut found = Vec::new();
    while let (Some(head), Some(path)) = (parts.next(), parts.next()) {
        // `:<old mode> <new mode> <old id> <new id> <status>`
        let head = String::from_utf8_lossy(head);
        let fields: Vec<&str> = head.trim_start_matches(':').split(' ').collect();
        let (Some(new_mode), Some(new_id), Some(status)) = (fields.get(1), fields.get(3), fields.get(4)) else { continue };
        let path = String::from_utf8_lossy(path).into_owned();
        // A file or a symlink carries a blob; a deletion none, a gitlink (160000) a commit id.
        let blob_mode = new_mode.starts_with("100") || new_mode.starts_with("120");
        let blob = (blob_mode && !status.starts_with('D')).then(|| (*new_id).to_string());
        found.push((path, status.starts_with('A'), blob));
    }
    Ok(found)
}

/// Sizes of `ids` (`cat-file --batch-check`), in order.
pub(crate) fn sizes(git: &GitRun, ids: &[String]) -> Result<Vec<u64>, BridgeError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = ids.join("\n");
    input.push('\n');
    let out = git.output_stdin(["cat-file", "--batch-check=%(objectsize)"], input.as_bytes()).map_err(git_failed("git cat-file of the WIP's blobs"))?;
    let text = String::from_utf8_lossy(&out);
    let sizes: Vec<u64> = text.lines().map(|l| l.trim().parse().unwrap_or(0)).collect();
    if sizes.len() != ids.len() {
        return Err(BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: format!("git cat-file answered {} sizes for {} objects", sizes.len(), ids.len()) });
    }
    Ok(sizes)
}

/// `commit-tree` of `tree` on `parents` as the seed's author at `date`, never signed.
fn commit(git: &GitRun, tree: &str, parents: &[&str], message: &str, date: &str) -> Result<String, BridgeError> {
    let mut args = vec!["commit-tree".to_string(), "--no-gpg-sign".to_string(), tree.to_string()];
    for p in parents {
        args.push("-p".into());
        args.push((*p).to_string());
    }
    args.push("-m".into());
    args.push(message.into());
    let git = git
        .clone()
        .env("GIT_AUTHOR_NAME", SEED_AUTHOR.0)
        .env("GIT_AUTHOR_EMAIL", SEED_AUTHOR.1)
        .env("GIT_AUTHOR_DATE", date)
        .env("GIT_COMMITTER_NAME", SEED_AUTHOR.0)
        .env("GIT_COMMITTER_EMAIL", SEED_AUTHOR.1)
        .env("GIT_COMMITTER_DATE", date);
    Ok(line(&git.output(&args).map_err(git_failed("git commit-tree of the WIP"))?))
}

/// The WIP of `ws` (D2) in `scratch`: `None` when the worktree and the index
/// are HEAD's (nothing uncommitted to carry). The index is copied twice (the
/// user's is never written): one copy is written as the staged tree (I),
/// the other gets `add -u` and the vetted untracked files and is written as
/// the worktree's tree (W); then the caps on what the two add to HEAD
/// (`[seed]`: each blob, all of them), and the commits I (on HEAD) and W (on
/// HEAD and I). Refused: over a cap, `wip_too_large` naming the largest
/// files (exit 9). A path the seed's rules (`set`) match is `a path name`
/// there and in a failure's text (a stat, git's `add` of the files).
pub fn snapshot(ws: &WorkspaceRef, scratch: &Scratch, lim: &SeedLimits, set: &ScanSet) -> Result<Option<Wip>, BridgeError> {
    let WsKind::Git { git_dir, .. } = &ws.kind;
    let head = ws.head.sha().to_string();
    let (index_i, index_w) = (scratch.dir().join("index.i"), scratch.dir().join("index.w"));
    for copy in [&index_i, &index_w] {
        match std::fs::read(git_dir.join("index")) {
            Ok(bytes) => copy_index(&git_dir.join("index"), &bytes, copy)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                user_git(ws, scratch, copy)?.output(["read-tree", head.as_str()]).map_err(git_failed("git read-tree of HEAD"))?;
            }
            Err(e) => return Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot read {}: {e}", git_dir.join("index").display())))),
        }
    }
    let git_i = user_git(ws, scratch, &index_i)?;
    let git_w = user_git(ws, scratch, &index_w)?;
    let head_tree = line(&git_w.output(["rev-parse", "--verify", &format!("{head}^{{tree}}")]).map_err(git_failed("git rev-parse of HEAD's tree"))?);
    let mut notes = Vec::new();
    let index_tree = match git_i.output(["write-tree"]) {
        Ok(out) => line(&out),
        Err(e) => {
            let unmerged = git_i.output(["ls-files", "--unmerged"]).map(|o| !o.is_empty()).unwrap_or(false);
            if !unmerged {
                return Err(git_failed("git write-tree of the index")(e));
            }
            notes.push("the index has unresolved conflicts: the VM's index is HEAD's (the worktree's files are carried)".to_string());
            head_tree.clone()
        }
    };
    git_w.output(["add", "-u"]).map_err(git_failed_shown(set, "git add -u of the tracked changes"))?;
    let carried = untracked(ws, &git_w, lim, set, &mut notes)?;
    if !carried.is_empty() {
        let mut list = Vec::new();
        for u in &carried {
            list.extend_from_slice(u.path.as_bytes());
            list.push(0);
        }
        git_w.output_stdin(["--literal-pathspecs", "add", "--pathspec-from-file=-", "--pathspec-file-nul"], &list).map_err(git_failed_shown(set, "git add of the untracked files"))?;
    }
    let tree = line(&git_w.output(["write-tree"]).map_err(git_failed("git write-tree of the worktree"))?);
    if tree == head_tree && index_tree == head_tree {
        return Ok(None);
    }
    // What the two trees add to HEAD's: the caps, the paths the dotenv rule reads.
    let mut paths = BTreeSet::new();
    let mut added = BTreeSet::new();
    let mut blobs: Vec<(String, String)> = Vec::new();
    for to in [&tree, &index_tree] {
        for (path, is_added, blob) in changes(&git_w, &head_tree, to)? {
            if is_added {
                added.insert(path.clone());
            }
            if let Some(id) = blob {
                if !blobs.iter().any(|(b, _)| *b == id) {
                    blobs.push((id, path.clone()));
                }
            }
            paths.insert(path);
        }
    }
    let ids: Vec<String> = blobs.iter().map(|(id, _)| id.clone()).collect();
    let blob_sizes = sizes(&git_w, &ids)?;
    let with_size: Vec<(String, u64)> = blobs.iter().zip(&blob_sizes).map(|((_, p), s)| (p.clone(), *s)).collect();
    let over: Vec<(String, u64)> = with_size.iter().filter(|(_, s)| *s > lim.max_blob_bytes).cloned().collect();
    if !over.is_empty() {
        return Err(BridgeError::WorkspaceRefused { code: super::code::WIP_TOO_LARGE, message: format!("uncommitted files over [seed].max_blob_mib ({}): {}", human_bytes(lim.max_blob_bytes), largest(set, over)) });
    }
    let new_bytes: u64 = blob_sizes.iter().sum();
    if new_bytes > lim.max_wip_bytes {
        return Err(BridgeError::WorkspaceRefused {
            code: super::code::WIP_TOO_LARGE,
            message: format!("the uncommitted changes add {}, over [seed].max_wip_mib ({}); the largest: {}", human_bytes(new_bytes), human_bytes(lim.max_wip_bytes), largest(set, with_size)),
        });
    }
    let date = head_date(&git_w, &head)?;
    let index_commit = if index_tree == head_tree { None } else { Some(commit(&git_w, &index_tree, &[&head], INDEX_MESSAGE, &date)?) };
    let parents: Vec<&str> = std::iter::once(head.as_str()).chain(index_commit.as_deref()).collect();
    let wip = commit(&git_w, &tree, &parents, WIP_MESSAGE, &date)?;
    let untracked_count = u32::try_from(carried.len()).unwrap_or(u32::MAX);
    Ok(Some(Wip {
        head,
        head_tree,
        commit: wip,
        tree,
        index_commit,
        index_tree,
        changed: u32::try_from(paths.len()).unwrap_or(u32::MAX),
        untracked: untracked_count,
        new_bytes,
        added: added.into_iter().collect(),
        notes,
    }))
}

/// S10 (L7): the WIP of a dead VM's last fetch, its `refs/wip/*` snapshot
/// `wip` on `head` (both promoted into the user's store by the code-out,
/// which `scratch` reads through its alternates). The VM's helper makes it in
/// [`snapshot`]'s shape: its tree the VM's worktree, its parents `head` and,
/// when the index differed from `head`'s tree, the index commit; so it is
/// carried as this Mac's WIP is (the worktree uncommitted, the index from
/// the second parent), under the same caps (`[seed]`: each blob, all of them)
/// and with the paths it adds for the dotenv rule. `None` when it changes
/// nothing of `head`'s tree. Refused: over a cap (`wip_too_large`, exit 9,
/// naming the largest as a path the rules match shows); a snapshot that is
/// not on `head`, or not a commit this store holds, fails (`git_failed`).
pub(crate) fn box_wip(scratch: &Scratch, head: &str, wip: &str, lim: &SeedLimits, set: &ScanSet) -> Result<Option<Wip>, BridgeError> {
    let git = scratch.git();
    let tree_of = |c: &str| -> Result<String, BridgeError> { Ok(line(&git.output(["rev-parse", "--verify", "--end-of-options", &format!("{c}^{{tree}}")]).map_err(git_failed("git rev-parse of the VM's snapshot"))?)) };
    let head_tree = tree_of(head)?;
    let shown = line(&git.output(["show", "-s", "--format=%T %P", "--end-of-options", &format!("{wip}^{{commit}}")]).map_err(git_failed("git show of the VM's snapshot"))?);
    let mut words = shown.split(' ');
    let tree = words.next().unwrap_or_default().to_string();
    let parents: Vec<&str> = words.collect();
    if parents.first() != Some(&head) || parents.len() > 2 {
        return Err(BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: "the dead VM's snapshot is not on the head its fetch recorded".into() });
    }
    let index_commit = parents.get(1).map(|i| (*i).to_string());
    let index_tree = match &index_commit {
        Some(i) => tree_of(i)?,
        None => head_tree.clone(),
    };
    if tree == head_tree && index_tree == head_tree {
        return Ok(None);
    }
    let mut paths = BTreeSet::new();
    let mut added = BTreeSet::new();
    let mut blobs: Vec<(String, String)> = Vec::new();
    for to in [&tree, &index_tree] {
        for (path, is_added, blob) in changes(&git, &head_tree, to)? {
            if is_added {
                added.insert(path.clone());
            }
            if let Some(id) = blob {
                if !blobs.iter().any(|(b, _)| *b == id) {
                    blobs.push((id, path.clone()));
                }
            }
            paths.insert(path);
        }
    }
    let ids: Vec<String> = blobs.iter().map(|(id, _)| id.clone()).collect();
    let blob_sizes = sizes(&git, &ids)?;
    let with_size: Vec<(String, u64)> = blobs.iter().zip(&blob_sizes).map(|((_, p), s)| (p.clone(), *s)).collect();
    let over: Vec<(String, u64)> = with_size.iter().filter(|(_, s)| *s > lim.max_blob_bytes).cloned().collect();
    if !over.is_empty() {
        return Err(BridgeError::WorkspaceRefused { code: super::code::WIP_TOO_LARGE, message: format!("the dead VM's uncommitted files over [seed].max_blob_mib ({}): {}", human_bytes(lim.max_blob_bytes), largest(set, over)) });
    }
    let new_bytes: u64 = blob_sizes.iter().sum();
    if new_bytes > lim.max_wip_bytes {
        return Err(BridgeError::WorkspaceRefused {
            code: super::code::WIP_TOO_LARGE,
            message: format!("the dead VM's uncommitted changes add {}, over [seed].max_wip_mib ({}); the largest: {}", human_bytes(new_bytes), human_bytes(lim.max_wip_bytes), largest(set, with_size)),
        });
    }
    Ok(Some(Wip {
        head: head.to_string(),
        head_tree,
        commit: wip.to_string(),
        tree,
        index_commit,
        index_tree,
        changed: u32::try_from(paths.len()).unwrap_or(u32::MAX),
        // The VM's snapshot does not say which of its files were untracked there.
        untracked: 0,
        new_bytes,
        added: added.into_iter().collect(),
        notes: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S9: as the wrapper exits, its own scratch directories under
    /// `state/tmp/` go with what is in them (a fetch's, a seed's, any other
    /// prefix's); another process's (pid 1 runs), a file named
    /// as one of this pid's and a name without a pid stay; with no
    /// `state/tmp/` there is nothing to do.
    #[test]
    fn a_process_removes_its_own_scratch_directories_only() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let tmp = paths.tmp();
        let own = std::process::id();
        let mine = [format!("fetch-{own}-a1b2c3"), format!("seed-{own}-d4e5f6"), format!("transcript-{own}-g7h8i9")];
        let theirs = ["fetch-1-j0k1l2".to_string(), format!("codeout-{}-m3n4o5", own + 1)];
        for name in mine.iter().chain(&theirs) {
            std::fs::create_dir_all(tmp.join(name).join("repo.git/objects/pack")).unwrap();
            std::fs::write(tmp.join(name).join("repo.git/objects/pack/pack-x.pack"), b"PACK").unwrap();
        }
        let stray = format!("stray-{own}-p6q7r8");
        std::fs::write(tmp.join(&stray), b"a file, not a scratch directory").unwrap();
        std::fs::create_dir_all(tmp.join("no-pid-here")).unwrap();
        remove_own_scratch(&paths);
        let mut left: Vec<String> = std::fs::read_dir(&tmp).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        let mut want: Vec<String> = theirs.to_vec();
        want.extend([stray, "no-pid-here".to_string()]);
        want.sort();
        assert_eq!(left, want);
        remove_own_scratch(&Paths::from_root_and_env(dir.path().join("none"), None));
    }
}
