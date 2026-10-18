//! `ai-env box review` and the pre-push hook (S9 plan §3, §4, M6): what a
//! push would carry, reviewed before it leaves this Mac — the tripwires
//! (`blobscan::scan_objects`: blobs, whole commits, path names), the
//! settings files new in the range (D8's repo mode, and an allow entry
//! beyond `settings-policy.txt`: [`RULE_ALLOW_NOT_IN_POLICY`]), L9's dotenv
//! rule and L8's Cargo.lock checks ([`RULE_CARGO_LOCK_REMOVED`],
//! [`RULE_CARGO_LOCK_SOURCE`], [`RULE_CARGO_LOCK_CHECKSUM`],
//! [`RULE_CARGO_CONFIG_SOURCE`]), each file read through the links the
//! merge bases and the head hold too, and any change on the way to the
//! pre-push hook where git reaches it through the work tree
//! ([`RULE_PRE_PUSH_HOOK_CHANGED`]) — over
//! `rev-list --objects REV --not BASES`, with no AWS call and no Touch ID.
//! `box hook-install` writes the pre-push hook (marked [`PRE_PUSH_MARK`])
//! where git runs hooks (`git::hook_path`, `core.hooksPath` honoured), never
//! over another hook; the hook runs `ai-env box review --pre-push REMOTE
//! URL` on every push and fails closed without its binary. [`hook_state`]
//! tells doctor and `box fetch` whether a repository has it. Frozen in S9
//! phase 0 (the mark, the rule ids, [`HookState`] and [`hook_state`],
//! built); G3 builds the review, the installer and the hook's refusals; the
//! lead's integration (I2) the links and the hook's own path.
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// The hook's second line: what marks a pre-push hook as ai-env's.
pub const PRE_PUSH_MARK: &str = "# ai-env pre-push review";
/// A commit deleting a `Cargo.lock` (first-parent, no renames), or a net removal against the base.
pub const RULE_CARGO_LOCK_REMOVED: &str = "cargo-lock-removed";
/// A new `source =` in a `Cargo.lock` that is not crates.io.
pub const RULE_CARGO_LOCK_SOURCE: &str = "cargo-lock-source";
/// A checksum changed for an unchanged version.
pub const RULE_CARGO_LOCK_CHECKSUM: &str = "cargo-lock-checksum";
/// In cargo's configuration at any depth (`.cargo/config.toml`, or the older `.cargo/config`): a source replacement,
/// a `[patch]`, a `paths` override or an `include` that no known version holds (bytes the `toml` crate cannot read
/// fail closed), or a new link at `.cargo` or at one of those files.
pub const RULE_CARGO_CONFIG_SOURCE: &str = "cargo-config-source";
/// An allow entry new against the merge base and absent from `settings-policy.txt`.
pub const RULE_ALLOW_NOT_IN_POLICY: &str = "allow-not-in-policy";
/// A change on the way to the pre-push hook where git reaches it through the work tree (S9 §13, I2): at its path
/// as git names it, a link passed on the way or the file it ends at, or a directory above one of them.
pub const RULE_PRE_PUSH_HOOK_CHANGED: &str = "pre-push-hook-changed";

/// How much of a hook file is read for the mark.
const HOOK_HEAD_READ: u64 = 4096;

/// Whether a repository has the pre-push hook, where git runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookState {
    /// The file there carries [`PRE_PUSH_MARK`] in its first 4 KiB.
    Installed(PathBuf),
    /// Nothing is there.
    Missing(PathBuf),
    /// Something else is there (a file without the mark, a directory, a dangling link): never written over.
    Foreign(PathBuf),
    /// Not a repository, or git or the file could not be read: why.
    Unknown(String),
}

/// The pre-push hook of the repository at `repo_root`: where git runs it
/// (`git::hook_path`, through the plain `git`: `core.hooksPath` honoured),
/// and what is there.
#[must_use]
pub fn hook_state(repo_root: &Path) -> HookState {
    if let Err(e) = crate::gitrun::GitRun::mac(repo_root).output(["rev-parse", "--git-dir"]) {
        return HookState::Unknown(format!("{} is not a git repository ({e})", repo_root.display()));
    }
    let path = crate::git::hook_path(repo_root, "pre-push");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HookState::Missing(path),
        Err(e) => return HookState::Unknown(format!("{}: {e}", path.display())),
        Ok(_) => {}
    }
    let file = match std::fs::metadata(&path) {
        Ok(md) if md.is_file() => std::fs::File::open(&path),
        _ => return HookState::Foreign(path),
    };
    let mut head = Vec::new();
    match file.and_then(|f| f.take(HOOK_HEAD_READ).read_to_end(&mut head)) {
        Ok(_) if String::from_utf8_lossy(&head).lines().any(|l| l.trim_end() == PRE_PUSH_MARK) => HookState::Installed(path),
        Ok(_) => HookState::Foreign(path),
        Err(e) => HookState::Unknown(format!("{}: {e}", path.display())),
    }
}

// ---- the review and the hook (G3) ----

use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::remote::audit_event;
use crate::bridge::scan::allow_beyond_policy;
use crate::bridge::scan::{settings_findings_mode, SettingsMode};
use crate::bridge::workspace::blobscan::{finding_lines, folds_to, has_marker, is_claude_dir, is_dotenv_name, read_objects, scan_objects, scan_settings, settings_name, shown_path, CleanCache, Finding, ScanReport, ScanSet, TreeEntry, FINDINGS_MAX, ID_SHOWN};
use crate::bridge::workspace::blobscan::{SETTINGS_NAMES, SETTINGS_SYMLINK};
use crate::bridge::workspace::pack::Listed;
use crate::errors::CliError;
use crate::gitrun::{GitError, GitRun};
use crate::outln;
use crate::wire::redact::scrub;
use crate::wire::workspace::ObjectFormat;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};
use unicode_normalization::UnicodeNormalization as _;

/// The commits the text report names, the newest first (`--json` lists every one).
pub const COMMITS_SHOWN: usize = 50;
/// The most the hook's stdin may hold: one line per pushed ref (a
/// `--mirror` push of every ref fits); more is exit 1.
pub const PRE_PUSH_INPUT_MAX: u64 = 16 << 20;
/// What a push never names as its local or its remote ref (compared as the
/// Mac's disk compares names): ai-env's box refs and incoming refs, and
/// everything a `--mirror` push carries.
pub const NEVER_PUSHED: [&str; 2] = ["refs/remotes/", "refs/ai-env/"];
/// The remotes whose tracking refs are ai-env's own (`codeout::BOX_REFS`,
/// `codeout::BOX_QUARANTINE_REFS`): never a default base, never pushed to
/// (compared ignoring ASCII case: one directory on the Mac's disk).
pub const BOX_REMOTES: [&str; 2] = ["box", "box-quarantine"];
/// crates.io as a `Cargo.lock`'s `source` names it (its git index, its sparse one).
pub const CRATES_IO: [&str; 2] = ["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"];
/// What one git run of a review may take (a whole history is long).
const GIT_BUDGET: Duration = Duration::from_secs(600);
const MIB: u64 = 1024 * 1024;
/// The locks' pathspec: git's `icase` folds ASCII only, and the Mac's disk
/// also takes a `k` written U+212A KELVIN SIGN for `Cargo.lock`, so every
/// `Cargo.loc*` is listed and [`is_cargo_lock`] decides.
const LOCKS: &str = ":(icase,glob)**/Cargo.loc*";
/// The paths whose changes the settings, dotenv and Cargo rules read
/// (`git log --raw`), wide on purpose (names folded as the Mac's disk folds
/// them where claude or cargo reads them): each change is then judged by its
/// own name (`settings_name`, `is_claude_dir`, `is_dotenv_name`,
/// [`is_cargo_lock`], [`is_cargo_config`], [`is_cargo_dir`]). `.claude`
/// and `.cargo` themselves are watched too: either may be a link.
const WATCHED: [&str; 9] = [
    ":(icase,glob)**/.claude",
    ":(icase,glob)**/.claude/*",
    ":(glob)**/.env",
    ":(glob)**/.env.*",
    ":(glob)**/*.env",
    LOCKS,
    ":(icase,glob)**/.cargo",
    ":(icase,glob)**/.cargo/config",
    ":(icase,glob)**/.cargo/config.toml",
];

/// A `Cargo.lock` (its name compared as the Mac's disk compares names,
/// `blobscan::folds_to`).
fn is_cargo_lock(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|n| folds_to(n, "cargo.lock"))
}

/// cargo's configuration at any depth (cargo reads every parent's):
/// `.cargo/config.toml`, or the older `.cargo/config`.
fn is_cargo_config(path: &str) -> bool {
    let mut parts = path.rsplit('/');
    match (parts.next(), parts.next()) {
        (Some(name), Some(dir)) => folds_to(dir, ".cargo") && (folds_to(name, "config.toml") || folds_to(name, "config")),
        _ => false,
    }
}

/// A `.cargo` directory's own path: a link there moves all of cargo's
/// configuration below it.
fn is_cargo_dir(path: &str) -> bool {
    folds_to(path.rsplit('/').next().unwrap_or(path), ".cargo")
}

/// L9's dotenv name (`blobscan::is_dotenv_name`) of a path's last component.
fn is_dotenv(path: &str) -> bool {
    is_dotenv_name(path.rsplit('/').next().unwrap_or(path))
}

/// A path the settings, dotenv or Cargo rules read by its own name.
fn is_watched(path: &str) -> bool {
    settings_name(path).is_some() || is_claude_dir(path) || is_dotenv(path) || is_cargo_lock(path) || is_cargo_config(path) || is_cargo_dir(path)
}

// ---- the links on the way to a watched file, and the pre-push hook's own path (I2) ----

/// The most links one path is followed through, in a tree or on this disk:
/// macOS's `MAXSYMLINKS`, so the review gives up only where the Mac's disk
/// does (a longer chain is `ELOOP` there, and nothing is read through it).
const LINK_HOPS: usize = 32;
/// The longest link target followed (macOS's `PATH_MAX`).
const LINK_TARGET_MAX: u64 = 1024;

/// A path as the Mac's disk compares names: NFC, case folded (U+017F LONG
/// S as `s`; U+212A KELVIN SIGN lowercases to `k`).
fn folded(path: &str) -> String {
    path.nfc().flat_map(|c| if c == '\u{17f}' { 's'.to_lowercase() } else { c.to_lowercase() }).collect()
}

/// Two tree paths the Mac's disk takes for one ([`folded`]).
fn same_path(a: &str, b: &str) -> bool {
    folded(a) == folded(b)
}

/// Is `dir` a directory above `path` (as the Mac's disk compares names)?
fn is_above(dir: &str, path: &str) -> bool {
    let (dir, path) = (folded(dir), folded(path));
    path.len() > dir.len() && path.starts_with(&dir) && path.as_bytes()[dir.len()] == b'/'
}

/// The directories above `path` (a tree path), the nearest last: `a/b/c` gives `a`, `a/b`.
fn dirs_above(path: &str) -> Vec<&str> {
    path.match_indices('/').map(|(i, _)| &path[..i]).collect()
}

/// A pathspec listing the tree entry at `rel` (from the top level) under
/// every name the Mac's disk takes for it, and some more ([`same_path`]
/// decides): `icase` glob magic, one `*` for each run of characters git's
/// ASCII-only folding could miss (`s` and `k`, which U+017F and U+212A fold
/// into; anything beyond ASCII: its other cases, its decomposed forms) or
/// glob would read; a pattern left without a wildcard ends in `?`, so it
/// names the entry alone, never what lies below it.
fn folded_spec(rel: &str) -> String {
    let mut pattern = String::new();
    for c in rel.chars() {
        let plain = c == '/' || ((c.is_ascii_graphic() || c == ' ') && !matches!(c, '*' | '?' | '[' | ']' | '\\' | 's' | 'S' | 'k' | 'K'));
        if plain {
            pattern.push(c);
        } else if !pattern.ends_with('*') {
            pattern.push('*');
        }
    }
    if !pattern.contains(['*', '?']) {
        pattern.pop();
        pattern.push('?');
    }
    format!(":(icase,glob){pattern}")
}

/// The pre-push hook's paths from the top level of the repository at `root`
/// (its canonical top level) where git reaches it through the work tree
/// ([`work_tree_rels`] of `git::hook_path`: a `core.hooksPath` such as
/// `.githooks` or Husky's `.husky/_`, a link there to shared hooks outside
/// the repository); none when no entry on its way lies there (the git
/// directory, outside the repository, a bare repository).
fn hook_rels(root: &Path) -> Vec<String> {
    work_tree_rels(root, &crate::git::hook_path(root, "pre-push"))
}

/// The top level of the repository at `repo_root` and the work-tree rule
/// [`work_tree_rels`] and [`config_rels`] share: a path from the top level
/// lies in the work tree when it is not empty, holds no `.git` component and
/// is no git directory nor below one. None in a bare repository.
fn work_tree_of(repo_root: &Path) -> Option<(PathBuf, Vec<String>)> {
    let out = GitRun::mac(repo_root).output(["rev-parse", "--path-format=absolute", "--show-toplevel", "--git-common-dir", "--git-dir"]).ok()?;
    let text = String::from_utf8_lossy(&out).into_owned();
    let dirs: Vec<PathBuf> = text.lines().map(|l| resolved(Path::new(l))).collect();
    let [top, common, git_dir] = dirs.as_slice() else { return None };
    let gits: Vec<String> = [common, git_dir].into_iter().filter_map(|g| g.strip_prefix(top).ok().and_then(Path::to_str).map(str::to_string)).collect();
    Some((top.clone(), gits))
}

/// [`work_tree_of`]'s rule on `r` (a path from the top level).
fn in_work_tree(gits: &[String], r: &str) -> bool {
    !r.is_empty() && !r.split('/').any(|c| same_path(c, ".git")) && !gits.iter().any(|g| g.is_empty() || same_path(r, g) || is_above(g, r))
}

/// The git configuration files of the repository at `repo_root` that lie in
/// its work tree ([`in_work_tree`]), as paths from the top level (S9 phase
/// 4): each file `git config --list --show-origin --includes` read (a
/// `file:` origin, relative to the top level where git runs), and the
/// target of each `include.path` and `includeIf.<condition>.path`, resolved
/// against the directory of the file that holds it, whether it exists or
/// not (an absent target lists no origin, and a condition can change with a
/// checkout). A merged or checked-out commit can replace such a file, and
/// with it `core.hooksPath` (or `core.fsmonitor`): a change there is
/// [`RULE_PRE_PUSH_HOOK_CHANGED`]. None in a bare repository.
fn config_rels(repo_root: &Path) -> Vec<String> {
    let Some((top, gits)) = work_tree_of(repo_root) else { return Vec::new() };
    let Ok(listed) = GitRun::mac(&top).output(["config", "--list", "--show-origin", "--includes", "-z"]) else { return Vec::new() };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let at = |p: &str| if Path::new(p).is_absolute() { PathBuf::from(p) } else { top.join(p) };
    let mut files: Vec<PathBuf> = Vec::new();
    let mut fields = listed.split(|b| *b == 0);
    while let (Some(origin), Some(entry)) = (fields.next(), fields.next()) {
        let origin = String::from_utf8_lossy(origin);
        let Some(file) = origin.strip_prefix("file:").map(at) else { continue };
        let entry = String::from_utf8_lossy(entry);
        let (key, value) = entry.split_once('\n').unwrap_or((entry.as_ref(), ""));
        let key = key.to_ascii_lowercase();
        if key == "include.path" || (key.starts_with("includeif.") && key.ends_with(".path")) {
            let target = match (value.strip_prefix("~/"), &home) {
                (Some(rest), Some(h)) => h.join(rest),
                _ => file.parent().map_or_else(|| PathBuf::from(value), |d| d.join(value)),
            };
            files.push(target);
        }
        files.push(file);
    }
    let mut kept: Vec<String> = Vec::new();
    for f in files {
        let Some(r) = resolved(&lexical(&f)).strip_prefix(&top).ok().and_then(Path::to_str).map(str::to_string) else { continue };
        if in_work_tree(&gits, &r) && !kept.iter().any(|k| same_path(k, &r)) {
            kept.push(r);
        }
    }
    kept
}

/// The entries a checkout can replace on the way to the hook git runs at
/// `hook` (absolute), as paths from the top level of the repository at
/// `repo_root` (S9 §13, I2), each judged on its own: `hook` as git names it
/// (`.` and `..` taken lexically, its links left as they are: each is a
/// work-tree entry), each link this disk passes on the way, and where that
/// walk ends ([`walk_disk`]). Each is kept when it lies in the work tree
/// (under the top level, outside the git directories, no `.git` on it: git
/// checks out none there) and is neither one kept before nor a directory
/// above one. None in a bare repository.
fn work_tree_rels(repo_root: &Path, hook: &Path) -> Vec<String> {
    let Some((top, gits)) = work_tree_of(repo_root) else { return Vec::new() };
    let rel = |p: &Path| p.strip_prefix(&top).ok().and_then(Path::to_str).map(str::to_string);
    let (passed, end) = walk_disk(hook);
    let mut kept: Vec<String> = Vec::new();
    for r in std::iter::once(lexical(hook)).chain(passed).chain([end]).filter_map(|p| rel(p.as_path())).filter(|r| in_work_tree(&gits, r)) {
        if !is_hook(&kept, &r) {
            kept.push(r);
        }
    }
    kept
}

/// `path` (absolute) as this disk resolves it, one component at a time as
/// the kernel walks it: a link replaced by its target (relative to the
/// link's own directory), `..` the directory above the one reached (after
/// the link before it), each directory made canonical (its name as the disk
/// holds it), at most [`LINK_HOPS`] links. The links passed (each its own
/// path) and where the walk ends: the whole path, or the first entry that is
/// no directory (a file, nothing there, a link past the hops) with the rest
/// after it taken lexically, as a checkout making directories there would
/// take it.
fn walk_disk(path: &Path) -> (Vec<PathBuf>, PathBuf) {
    use std::ffi::OsString;
    use std::path::Component;
    let parts = |p: &Path| -> Vec<OsString> {
        p.components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_os_string()),
                Component::ParentDir => Some(OsString::from("..")),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
            })
            .collect()
    };
    if !path.is_absolute() {
        return (Vec::new(), path.to_path_buf());
    }
    let mut pending: std::collections::VecDeque<OsString> = parts(path).into();
    let mut at = PathBuf::from("/");
    let mut passed: Vec<PathBuf> = Vec::new();
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            at.pop();
            continue;
        }
        let next = at.join(&part);
        let kind = std::fs::symlink_metadata(&next).map(|m| m.file_type());
        let target = match kind {
            Ok(k) if k.is_symlink() && hops < LINK_HOPS => std::fs::read_link(&next).ok(),
            Ok(k) if k.is_dir() => {
                at = std::fs::canonicalize(&next).unwrap_or(next);
                continue;
            }
            _ => None,
        };
        let Some(target) = target else {
            let rest: PathBuf = pending.iter().collect();
            return (passed, lexical(&next.join(rest)));
        };
        hops += 1;
        passed.push(next);
        if target.is_absolute() {
            at = PathBuf::from("/");
        }
        for p in parts(&target).into_iter().rev() {
            pending.push_front(p);
        }
    }
    (passed, at)
}

/// `path` with its `.` and `..` components taken lexically.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

/// Is `path` (a tree path) one of the pre-push hook's paths through the work tree, or a directory above one
/// (`hook`: [`hook_rels`])?
fn is_hook(hook: &[String], path: &str) -> bool {
    hook.iter().any(|h| same_path(path, h) || is_above(path, h))
}

/// A tree path the rules read under a watched path's name: where a link the
/// merge bases or the head hold makes cargo, claude or git read that file
/// ([`link_aliases`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Alias {
    /// The tree path, as that tree names it.
    path: String,
    /// The watched path whose rules it takes: a link's own path, a file below a linked `.claude` or `.cargo`, or
    /// the pre-push hook's.
    name: String,
    /// A link passed on the way (or the entry a walk stopped at, when the rest leaves it), or a directory above
    /// the file reached: only its own replacement counts (a link in its place, or anything there in a lock's or
    /// the hook's case), never a content.
    via: bool,
}

/// The entry `commit`'s tree holds at `path` (one `ls-tree`, the path taken
/// literally): its mode and id; none for a path the tree does not hold (or
/// holds only below a link or a file).
fn tree_entry(git: &GitRun, commit: &str, path: &str) -> Result<Option<(String, String)>, CliError> {
    let out = git.output(["--literal-pathspecs", "ls-tree", "-z", "--full-tree", commit, "--", path]).map_err(failed("git ls-tree"))?;
    for raw in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let text = String::from_utf8_lossy(raw);
        let Some((meta, name)) = text.split_once('\t') else { continue };
        let mut f = meta.split(' ');
        if let (Some(mode), Some(_), Some(id), true) = (f.next(), f.next(), f.next(), name == path) {
            return Ok(Some((mode.to_string(), id.to_string())));
        }
    }
    Ok(None)
}

/// A link's target (its blob `id`): none when it is over [`LINK_TARGET_MAX`]
/// bytes, holds a NUL or is no UTF-8 (no path git checks out).
fn link_target(git: &GitRun, id: &str) -> Result<Option<String>, CliError> {
    if objects(git, &[id.to_string()])?.get(id).is_none_or(|o| o.kind != "blob" || o.size > LINK_TARGET_MAX) {
        return Ok(None);
    }
    let mut target = None;
    read_objects(git, &[id.to_string()], |_, b| target = String::from_utf8(b.to_vec()).ok().filter(|t| !t.contains('\0')))?;
    Ok(target)
}

/// The entries of the tree `tree` names (a commit's tree, or a tree's id),
/// not recursive (one `ls-tree`): each `(mode, id, name)`.
fn tree_entries(git: &GitRun, tree: &str) -> Result<Vec<(String, String, String)>, CliError> {
    let out = git.output(["ls-tree", "-z", "--full-tree", tree]).map_err(failed("git ls-tree"))?;
    let mut entries = Vec::new();
    for raw in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let text = String::from_utf8_lossy(raw);
        let Some((meta, name)) = text.split_once('\t') else { continue };
        let mut f = meta.split(' ');
        if let (Some(mode), Some(_), Some(id)) = (f.next(), f.next(), f.next()) {
            entries.push((mode.to_string(), id.to_string(), name.to_string()));
        }
    }
    Ok(entries)
}

/// `path` (a tree path) resolved in `commit`'s tree as a checkout of it
/// resolves on the Mac's disk, one component at a time as the kernel walks
/// it: each name looked up in its directory's tree (the exact name first,
/// else one the Mac's disk takes for it, [`same_path`]); a link (mode
/// 120000) replaced by its target, relative to the link's own directory;
/// `..` the directory above the one reached (after the link before it,
/// never lexically); at most [`LINK_HOPS`] links. A file, a submodule or
/// nothing there ends the walk: the rest after it is taken lexically, as a
/// checkout making directories there would take it (a path that leaves the
/// tree that way adds nothing, and none holds `.` or `..`, which git's
/// pathspecs would read), and that entry counts as passed when the rest
/// leaves it by `..` (a link put there moves the end). The entries passed
/// (each as its tree names it) and the path it ends at; none when a link
/// leaves the tree (an absolute target, `..` above the top level), names no
/// path ([`link_target`]), the hops run out (a loop), or the walk ends at
/// the top level.
fn resolve_in_tree(git: &GitRun, commit: &str, path: &str) -> Result<Option<(Vec<String>, String)>, CliError> {
    use std::collections::hash_map::Entry;
    let joined = |dirs: &[(String, String)], name: &str| dirs.iter().map(|(d, _)| d.as_str()).chain([name]).collect::<Vec<&str>>().join("/");
    let mut pending: std::collections::VecDeque<String> = path.split('/').map(str::to_string).collect();
    // The directories reached (real ones only), each as its tree names it, with that tree's id.
    let mut dirs: Vec<(String, String)> = Vec::new();
    let mut listed: HashMap<String, Vec<(String, String, String)>> = HashMap::new();
    let mut passed: Vec<String> = Vec::new();
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        match part.as_str() {
            "" | "." => continue,
            ".." => {
                if dirs.pop().is_none() {
                    return Ok(None);
                }
                continue;
            }
            _ => {}
        }
        let tree = dirs.last().map_or_else(|| commit.to_string(), |(_, id)| id.clone());
        let entries = match listed.entry(tree) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let listing = tree_entries(git, e.key())?;
                e.insert(listing)
            }
        };
        let found = entries.iter().find(|e| e.2 == part).or_else(|| entries.iter().find(|e| same_path(&e.2, &part))).cloned();
        match found {
            Some((mode, id, name)) if mode == "040000" => dirs.push((name, id)),
            Some((mode, id, name)) if mode == "120000" => {
                hops += 1;
                if hops > LINK_HOPS {
                    return Ok(None);
                }
                let Some(target) = link_target(git, &id)?.filter(|t| !t.starts_with('/')) else { return Ok(None) };
                passed.push(joined(&dirs, &name));
                for p in target.split('/').rev() {
                    pending.push_front(p.to_string());
                }
            }
            // A file, a submodule or nothing there: no link lies below it in this tree.
            found => {
                let stop = joined(&dirs, found.as_ref().map_or(part.as_str(), |e| e.2.as_str()));
                let mut end: Vec<&str> = stop.split('/').collect();
                for p in &pending {
                    match p.as_str() {
                        "" | "." => {}
                        ".." => {
                            if end.pop().is_none() {
                                return Ok(None);
                            }
                        }
                        p => end.push(p),
                    }
                }
                let end = end.join("/");
                if end.is_empty() {
                    return Ok(None);
                }
                if !same_path(&stop, &end) && !is_above(&stop, &end) {
                    passed.push(stop);
                }
                return Ok(Some((passed, end)));
            }
        }
    }
    let end = dirs.iter().map(|(d, _)| d.as_str()).collect::<Vec<&str>>().join("/");
    Ok((!end.is_empty()).then_some((passed, end)))
}

/// The watched paths a link at `link` stands on the way to: itself for a
/// watched file (a settings file, a dotenv, a `Cargo.lock`, cargo's
/// configuration), the files below it for `.claude` and `.cargo`, the
/// pre-push hook's path for a link on it (`hook`).
fn watched_through(link: &str, hook: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if settings_name(link).is_some() || is_dotenv(link) || is_cargo_lock(link) || is_cargo_config(link) {
        out.push(link.to_string());
    }
    if is_claude_dir(link) {
        out.extend(SETTINGS_NAMES.iter().map(|n| format!("{link}/{n}")));
    }
    if is_cargo_dir(link) {
        out.extend(["config.toml", "config"].iter().map(|n| format!("{link}/{n}")));
    }
    for h in hook {
        if same_path(link, h) {
            out.push(link.to_string());
        } else if is_above(link, h) {
            // The hook's path below the link, as git names it.
            let below = h.split('/').skip(link.split('/').count()).collect::<Vec<_>>().join("/");
            out.push(format!("{link}/{below}"));
        }
    }
    out
}

/// Where the links the merge bases and `head` hold make cargo, claude or git
/// read a watched file under another path (S9 §13, I2): each link (mode
/// 120000) at a watched path or on the pre-push hook's ([`watched_through`]),
/// the watched paths behind it resolved in that tree ([`resolve_in_tree`]):
/// the path each ends at, read under the watched path's name, and the
/// entries passed and the directories above that path (`via`). A link that
/// leaves the tree, or a chain past [`LINK_HOPS`], adds nothing. Then the
/// files cargo's configuration includes ([`include_aliases`]), read under
/// the including configuration's name.
fn link_aliases(cx: &Cx<'_>, head: &str, mbs: &[String]) -> Result<Vec<Alias>, CliError> {
    let git = &cx.repo.git;
    let empty = git.output_stdin(["hash-object", "-t", "tree", "--stdin"], b"").map_err(failed("git hash-object of the empty tree"))?;
    let empty = String::from_utf8_lossy(&empty).trim().to_string();
    let mut specs: Vec<String> = WATCHED.iter().map(|s| (*s).to_string()).collect();
    for h in &cx.hook {
        specs.extend(dirs_above(h).into_iter().chain([h.as_str()]).map(folded_spec));
    }
    let mut commits: Vec<&str> = Vec::new();
    for c in mbs.iter().map(String::as_str).chain([head]) {
        if !commits.contains(&c) {
            commits.push(c);
        }
    }
    let mut out: Vec<Alias> = Vec::new();
    let mut add = |a: Alias| {
        if !out.contains(&a) {
            out.push(a);
        }
    };
    for commit in commits {
        let mut args = vec!["diff", "--raw", "-z", "--no-renames", "--no-abbrev", "--no-relative", empty.as_str(), commit, "--"];
        args.extend(specs.iter().map(String::as_str));
        let listed = git.output(&args).map_err(failed("git diff of the links"))?;
        let entries = parse_raw(&listed, commit);
        let mut here: Vec<Alias> = Vec::new();
        for link in entries.iter().filter(|c| c.new_mode == "120000") {
            for name in watched_through(&link.path, &cx.hook) {
                let Some((passed, end)) = resolve_in_tree(git, commit, &name)? else { continue };
                for dir in dirs_above(&end) {
                    here.push(Alias { path: dir.to_string(), name: name.clone(), via: true });
                }
                for p in passed {
                    here.push(Alias { path: p, name: name.clone(), via: true });
                }
                here.push(Alias { path: end, name: name.clone(), via: false });
            }
        }
        // cargo's configuration in this tree, its own or reached through a link: what it includes.
        let mut configs: Vec<(String, String)> = entries.iter().filter(|c| c.new_mode.starts_with("100") && is_cargo_config(&c.path)).map(|c| (c.path.clone(), c.path.clone())).collect();
        configs.extend(here.iter().filter(|a| !a.via && is_cargo_config(&a.name)).map(|a| (a.path.clone(), a.name.clone())));
        here.extend(include_aliases(git, commit, configs, cx.max_blob)?);
        for a in here {
            add(a);
        }
    }
    Ok(out)
}

/// The files cargo reads as configuration through an `include` of the
/// configurations `configs` (`(path in commit's tree, the watched name it
/// is read under)`), nested includes too, in `commit`'s tree (I2's rule
/// for links, S9 phase 4): each relative entry resolved against the
/// including file's directory ([`resolve_in_tree`]), the path it ends at
/// read under the including configuration's name (a change there is
/// reviewed as a change of that configuration), the entries passed and the
/// directories above it `via`. An absolute or home-relative entry, or one
/// that leaves the tree, is never followed (its `include` entry is a source
/// of its own, [`config_sources`]); a file over `max_blob` is not read; at
/// most [`LINK_HOPS`] files are read.
fn include_aliases(git: &GitRun, commit: &str, configs: Vec<(String, String)>, max_blob: u64) -> Result<Vec<Alias>, CliError> {
    let mut out: Vec<Alias> = Vec::new();
    let mut queue: std::collections::VecDeque<(String, String)> = configs.into();
    let mut read: HashSet<String> = HashSet::new();
    while let Some((file, name)) = queue.pop_front() {
        if read.len() >= LINK_HOPS || !read.insert(folded(&file)) {
            continue;
        }
        let spec = format!("{commit}:{file}");
        let Some(id) = objects(git, std::slice::from_ref(&spec))?.get(&spec).filter(|o| o.kind == "blob" && o.size <= max_blob).map(|o| o.id.clone()) else { continue };
        let mut bytes = Vec::new();
        read_objects(git, &[id], |_, b| bytes = b.to_vec())?;
        let dir = file.rsplit_once('/').map_or("", |(d, _)| d);
        for entry in config_includes(&bytes) {
            if entry.starts_with('/') || entry.starts_with('~') {
                continue;
            }
            let joined = if dir.is_empty() { entry } else { format!("{dir}/{entry}") };
            let Some((passed, end)) = resolve_in_tree(git, commit, &joined)? else { continue };
            for d in dirs_above(&end) {
                out.push(Alias { path: d.to_string(), name: name.clone(), via: true });
            }
            for p in passed {
                out.push(Alias { path: p, name: name.clone(), via: true });
            }
            out.push(Alias { path: end.clone(), name: name.clone(), via: false });
            queue.push_back((end, name.clone()));
        }
    }
    Ok(out)
}

/// The pathspecs the rules read besides [`WATCHED`]: the pre-push hook's
/// path and the directories above it, and every alias's path (each entry
/// alone, [`folded_spec`]).
fn watch_specs(hook: &[String], aliases: &[Alias]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let paths = hook.iter().flat_map(|h| dirs_above(h).into_iter().chain([h.as_str()])).chain(aliases.iter().map(|a| a.path.as_str()));
    for spec in paths.map(folded_spec) {
        if !out.contains(&spec) {
            out.push(spec);
        }
    }
    out
}

/// A text as a report shows it: scrubbed, control characters as `?`.
fn shown(text: &str) -> String {
    scrub(text).chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// An object id's first [`ID_SHOWN`] digits.
fn short(id: &str) -> &str {
    &id[..id.len().min(ID_SHOWN)]
}

/// `s` single-quoted for `sh`, its own `'` written `'\''`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A git failure of a review: exit 1, naming the step.
fn failed(what: &'static str) -> impl FnOnce(GitError) -> CliError {
    move |e| CliError::Msg(format!("box review: {what}: {e}"))
}

/// The directory a command acts on: `--repo`/`REPO`, else the current one.
fn workdir(repo: Option<&Path>) -> Result<PathBuf, CliError> {
    match repo {
        Some(p) => Ok(p.to_path_buf()),
        None => std::env::current_dir().map_err(|e| CliError::Msg(format!("cannot read the current directory: {e}"))),
    }
}

/// The repository a review or an install acts on: its top level (a bare
/// repository's git dir), its object format, and its git (the Mac's
/// `GitRun`: no hook runs, no inherited `GIT_*`, git's messages in English).
struct Repo {
    root: PathBuf,
    format: ObjectFormat,
    git: GitRun,
}

impl Repo {
    /// The repository holding `dir`: exit 1 when there is none.
    fn open(dir: &Path) -> Result<Repo, CliError> {
        // `refs/replace/*` never stands in for an object: the review reads what a push sends (`git replace` redirects
        // only local reads; a graft or a replaced blob would otherwise hide a commit or a blob the remote receives).
        let git = GitRun::mac(dir).env("LC_ALL", "C").env("GIT_NO_REPLACE_OBJECTS", "1").timeout(GIT_BUDGET);
        let out = git
            .output(["rev-parse", "--path-format=absolute", "--git-dir", "--show-object-format", "--is-bare-repository"])
            .map_err(|e| CliError::Msg(format!("{} is not a git repository ({e})", dir.display())))?;
        let text = String::from_utf8_lossy(&out).into_owned();
        let lines: Vec<&str> = text.lines().collect();
        let [git_dir, format, bare] = lines.as_slice() else {
            return Err(CliError::Msg(format!("git rev-parse in {} answered {} lines, not 3", dir.display(), lines.len())));
        };
        let format = match *format {
            "sha1" => ObjectFormat::Sha1,
            "sha256" => ObjectFormat::Sha256,
            other => return Err(CliError::Msg(format!("{} uses the object format {other:?}, which ai-env does not read", dir.display()))),
        };
        // A bare repository, or a directory inside `.git`, has no top level: its git dir stands for it.
        let top = if *bare == "true" { None } else { git.output(["rev-parse", "--show-toplevel"]).ok().map(|o| String::from_utf8_lossy(&o).trim().to_string()) };
        let root = std::fs::canonicalize(top.as_deref().unwrap_or(git_dir)).map_err(|e| CliError::Msg(format!("the repository of {}: {e}", dir.display())))?;
        Ok(Repo { git: GitRun::mac(&root).env("LC_ALL", "C").env("GIT_NO_REPLACE_OBJECTS", "1").timeout(GIT_BUDGET), root, format })
    }
}

/// What every range of one review shares.
struct Cx<'a> {
    repo: Repo,
    paths: Paths,
    set: &'a ScanSet,
    /// `settings-policy.txt`'s allow entries.
    policy: &'a [String],
    cache: CleanCache,
    /// `[seed].max_blob_mib` in bytes: a larger blob is `blob-too-large`, never read.
    max_blob: u64,
    json: bool,
    started: Instant,
    /// Said before the commits (the repo mode off, the whole history).
    notes: Vec<String>,
    /// The pre-push hook's paths from the top level where git reaches it through the work tree ([`hook_rels`]):
    /// a change there is [`RULE_PRE_PUSH_HOOK_CHANGED`].
    hook: Vec<String>,
}

/// One reviewed commit: its subject with control characters stripped, or
/// the rule that withholds it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Commit {
    id: String,
    subject: Option<String>,
    withheld: Option<String>,
}

/// One finding, with what `--json` names: the commit that brought it (a
/// finding naming none is its range's head's) and its path as the finding
/// shows it (empty for the commit's own text: its message and headers).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    finding: Finding,
    commit: String,
    path: String,
}

/// What a review read and found: one range, or several merged.
#[derive(Debug, Default)]
struct Review {
    /// The newest first, each once.
    commits: Vec<Commit>,
    found: Vec<Found>,
    /// A range had no base: the whole history up to its head was read.
    whole_history: bool,
    /// The bases' names (a ref, or the id itself), each once.
    bases: Vec<String>,
}

impl Review {
    /// `other`'s commits, findings and bases added, each once, in order.
    fn merge(&mut self, other: Review) {
        for c in other.commits {
            if !self.commits.iter().any(|k| k.id == c.id) {
                self.commits.push(c);
            }
        }
        for f in other.found {
            if !self.found.iter().any(|k| k.finding == f.finding) {
                self.found.push(f);
            }
        }
        for b in other.bases {
            if !self.bases.contains(&b) {
                self.bases.push(b);
            }
        }
        self.whole_history |= other.whole_history;
    }

    fn verdict(&self) -> &'static str {
        if self.found.is_empty() {
            "pass"
        } else {
            "findings"
        }
    }
}

/// `ai-env box review REV [--base REV]… [--repo DIR] [--json]`, and the
/// hook's `--pre-push REMOTE URL` (plans/s9-contracts.md §4.1): every rule
/// over `rev-list --objects REV --not BASES`, where BASES is `--base`, else
/// every remote-tracking ref but ai-env's (`refs/remotes/box/*`,
/// `box-quarantine/*`), else nothing (the whole history, said in a note).
/// The tripwires over every object (blobs, whole commits, path names, a
/// blob over `[seed].max_blob_mib` a finding of its own); then, per change
/// that brings a file no merge base holds at its path, at the commit that
/// made it (`log --raw --full-history --diff-merges=first-parent`): D8's
/// repo mode and its links on the settings files
/// (`blobscan::scan_settings`, unless the workspace trusts its settings:
/// such a link is then a policy finding), an allow entry beyond the policy
/// ([`RULE_ALLOW_NOT_IN_POLICY`]: new against the merge base and the
/// commits reviewed before it), L9's dotenv rule, and the Cargo rules (a
/// lock deleted, by a commit or net against the merge base or the tip a
/// push replaces; a new source that is not crates.io; a checksum changed
/// for an unchanged version; a new source replacement, patch or path
/// override in cargo's configuration; a new link where cargo reads its
/// lock or its configuration), each file read through the links the merge
/// bases and the head hold too (`link_aliases`); and any change on the way
/// to the pre-push hook where git reaches it through the work tree
/// ([`RULE_PRE_PUSH_HOOK_CHANGED`], `hook_rels`). Prints the commits'
/// subjects, at most [`FINDINGS_MAX`] finding lines, then the verdict;
/// audited (`box_review`). Exits 0 clean, 9 a finding or a refused push, 1 no
/// repository, a REV or base naming no commit, a git failure. No AWS call,
/// no Touch ID, no workspace needed.
pub fn cmd_review(rev: Option<&str>, base: &[String], repo: Option<&Path>, json: bool, pre_push: Option<&[String]>) -> crate::errors::Result<()> {
    let started = Instant::now();
    let dir = workdir(repo)?;
    let repo = Repo::open(&dir)?;
    let paths = Paths::resolve()?;
    let cfg = BridgeConfig::load(&paths)?;
    let seed = cfg.as_ref().map(|c| c.seed.clone()).unwrap_or_default();
    seed.validate()?;
    let here = std::fs::canonicalize(&dir).unwrap_or_else(|_| repo.root.clone());
    let (set, policy) = ScanSet::for_review(&paths, cfg.as_ref(), &here, &repo.root)?;
    let mut notes = Vec::new();
    if !set.repo_settings {
        notes.push("the workspace trusts its repo settings (trust_repo_settings): D8's repo mode is off, the policy rule is not".to_string());
    }
    let mut hook = hook_rels(&repo.root);
    if let Some(h) = hook.first() {
        notes.push(format!("git runs the pre-push hook from the work tree ({}): a change there is a finding ({RULE_PRE_PUSH_HOOK_CHANGED})", shown(h)));
    }
    // The configuration files git reads from the work tree: one can move the hook (core.hooksPath).
    let configs = config_rels(&repo.root);
    if let Some(c) = configs.first() {
        notes.push(format!("git reads its configuration from the work tree ({}): a change there can move the pre-push hook and is a finding ({RULE_PRE_PUSH_HOOK_CHANGED})", shown(c)));
    }
    for c in configs {
        if !is_hook(&hook, &c) {
            hook.push(c);
        }
    }
    let cache = CleanCache::open(&paths, &set.digest, repo.format);
    let mut cx = Cx { repo, paths, set: &set, policy: &policy, cache, max_blob: u64::from(seed.max_blob_mib) * MIB, json, started, notes, hook };
    match (pre_push, rev) {
        (Some([remote, url]), _) => review_push(&mut cx, remote, url),
        (None, Some(rev)) => review_rev(&mut cx, rev, base),
        _ => Err(CliError::Usage("box review takes REV, or the hook's --pre-push REMOTE URL".into())),
    }
}

/// `box review REV [--base REV]…`.
fn review_rev(cx: &mut Cx<'_>, rev: &str, base: &[String]) -> Result<(), CliError> {
    let head = resolve_commit(&cx.repo.git, rev)?.ok_or_else(|| CliError::Msg(format!("box review: {} names no commit in {}", shown(rev), cx.repo.root.display())))?;
    // The range's tip is the object REV names, unpeeled: a push of an annotated tag carries the tag object too.
    let tip = rev_parse(&cx.repo.git, rev)?.unwrap_or_else(|| head.clone());
    let bases: Vec<(String, String)> = if base.is_empty() {
        tracking_refs(&cx.repo.git, "refs/remotes/")?.into_iter().filter(|(name, _)| !is_box_ref(name)).collect()
    } else {
        let mut out = Vec::new();
        for b in base {
            let id = resolve_commit(&cx.repo.git, b)?.ok_or_else(|| CliError::Msg(format!("box review: --base {} names no commit in {}", shown(b), cx.repo.root.display())))?;
            out.push((b.clone(), id));
        }
        out
    };
    if bases.is_empty() {
        cx.notes.push("no base and no remote-tracking ref (but ai-env's): the whole history is reviewed".into());
    }
    let review = review_range(cx, &tip, &head, &bases, &[])?;
    let verdict = review.verdict();
    let header = if bases.is_empty() {
        format!("box review: {}: {} ({}), the whole history: {} commit(s)", cx.repo.root.display(), shown(rev), short(&head), review.commits.len())
    } else {
        format!("box review: {}: {} ({}) against {}: {} commit(s) they lack", cx.repo.root.display(), shown(rev), short(&head), names(&review.bases), review.commits.len())
    };
    // The verdict decides the exit, never the report's write: a closed stdout (`| head`, a pipe already gone) is
    // `BrokenPipe`, exit 0, which must never pass a finding.
    let printed = report(cx, &header, Some(rev), Some(&head), &review, verdict);
    audit_review(cx, None, &review, verdict);
    match review.found.len() {
        0 => printed,
        n => Err(CliError::Policy(format!("box review: {n} finding(s) in the commits a push of {} would carry (named above, never a value): take them out of those commits before any push", shown(rev)))),
    }
}

/// The hook's `box review --pre-push REMOTE URL`, the pushed refs on stdin
/// (§4.1): a remote named `box` or `box-quarantine`, or a local or remote
/// ref under [`NEVER_PUSHED`], refuses the push before anything is read;
/// deletions are skipped; each pushed range is reviewed against its remote
/// id (when this repository holds it) and, when REMOTE is a remote's name
/// ([`remote_name`]), its `refs/remotes/<REMOTE>/*`; a lock the remote id
/// holds and the pushed head lacks is a net removal too (a forced push
/// replaces that tip). A REMOTE that is no remote's name (a push to a bare
/// URL, credentials and all) is never printed, audited (`remote` is then
/// `url`) or made part of a ref name.
fn review_push(cx: &mut Cx<'_>, remote: &str, url: &str) -> Result<(), CliError> {
    let mut input = Vec::new();
    std::io::stdin().lock().take(PRE_PUSH_INPUT_MAX + 1).read_to_end(&mut input).map_err(|e| CliError::Msg(format!("box review: the pushed refs on stdin: {e}")))?;
    if input.len() as u64 > PRE_PUSH_INPUT_MAX {
        return Err(CliError::Msg(format!("box review: more than {} MiB of pushed refs on stdin", PRE_PUSH_INPUT_MAX / MIB)));
    }
    let pushed = pushed_refs(&input, cx.repo.format)?;
    let name = remote_name(&cx.repo.git, remote, url);
    let audited = name.clone().unwrap_or_else(|| "url".to_string());
    let to = name.as_deref().map_or_else(|| "a URL (not shown)".to_string(), |n| format!("the remote {n}"));
    let refusal = match BOX_REMOTES.iter().find(|b| remote.eq_ignore_ascii_case(b)) {
        Some(b) => Some(format!("the remote is named {b}, and refs/remotes/{b}/* are ai-env's (git remote rename {b} <other>)")),
        None => pushed
            .iter()
            .flat_map(|p| [p.local_ref.as_str(), p.remote_ref.as_str()])
            .find(|r| never_pushed(r))
            .map(|r| format!("it names {}, and refs under refs/remotes/ and refs/ai-env/ are never pushed (ai-env's box refs, a --mirror push)", shown(r))),
    };
    if let Some(why) = refusal {
        let review = Review::default();
        // Refused whatever the report's write gave (a closed stdout must never let the push through).
        let _ = report(cx, &format!("box review --pre-push: {}: a push to {to}", cx.repo.root.display()), None, None, &review, "refused");
        audit_review(cx, Some(&audited), &review, "refused");
        return Err(CliError::Policy(format!("box review: the push is refused: {why}; nothing was reviewed")));
    }
    let tracking = match &name {
        // git moves refs/remotes/<REMOTE>/* after the push to each URL: with two or more push URLs they describe
        // none of the URLs after the first, so no pushed range is reviewed against them.
        Some(n) if push_urls(&cx.repo.git, n) >= 2 => {
            cx.notes.push(format!("the remote {n} has several push URLs: its remote-tracking refs are no base (each pushed ref is reviewed against its remote id, else its whole history)"));
            Vec::new()
        }
        Some(n) => tracking_refs(&cx.repo.git, &format!("refs/remotes/{n}/"))?,
        None => Vec::new(),
    };
    let mut review = Review::default();
    let mut heads: Vec<String> = Vec::new();
    for p in pushed.iter().filter(|p| !is_zero(&p.local)) {
        let mut bases = Vec::new();
        // The tip this push replaces, for the net removal only: a forced push may drop a lock no commit deletes.
        let mut olds = Vec::new();
        if !is_zero(&p.remote) && crate::bridge::workspace::holds_commit(&cx.repo.git, &p.remote).map_err(failed("git rev-parse of the remote's tip"))? {
            bases.push((p.remote.clone(), p.remote.clone()));
            olds.push(p.remote.clone());
        }
        bases.extend(tracking.iter().cloned());
        if bases.is_empty() {
            let note = "a pushed ref has no base (a new ref, no remote-tracking ref): its whole history is reviewed".to_string();
            if !cx.notes.contains(&note) {
                cx.notes.push(note);
            }
        }
        // A pushed annotated tag is reviewed whole; its commit names the head's findings.
        let head = resolve_commit(&cx.repo.git, &p.local)?.unwrap_or_else(|| p.local.clone());
        heads.push(head.clone());
        let range = review_range(cx, &p.local, &head, &bases, &olds)?;
        review.merge(range);
    }
    let verdict = review.verdict();
    let header = format!("box review --pre-push: {}: {} ref(s) to {to}: {} commit(s) it lacks", cx.repo.root.display(), heads.len(), review.commits.len());
    let printed = report(cx, &header, None, heads.first().map(String::as_str), &review, verdict);
    audit_review(cx, Some(&audited), &review, verdict);
    match review.found.len() {
        0 => printed,
        n => Err(CliError::Policy(format!("box review: {n} finding(s) in the commits this push carries (named above, never a value): the push is refused"))),
    }
}

/// One line git hands the pre-push hook (githooks(5)): `<local ref> <local
/// id> <remote ref> <remote id>`; a local ref given as an expression may
/// hold spaces, so the three fields that cannot are taken from the right.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pushed {
    local_ref: String,
    local: String,
    remote_ref: String,
    remote: String,
}

/// The pushed refs on stdin: exit 1 for anything that is not git's lines.
fn pushed_refs(input: &[u8], format: ObjectFormat) -> Result<Vec<Pushed>, CliError> {
    let bad = || CliError::Msg("box review: the pushed refs on stdin are not git's pre-push lines (<local ref> <local id> <remote ref> <remote id>)".into());
    let text = std::str::from_utf8(input).map_err(|_| bad())?;
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let fields: Vec<&str> = line.rsplitn(4, ' ').collect();
        let [remote, remote_ref, local, local_ref] = fields.as_slice() else { return Err(bad()) };
        if !format.is_id(local) || !format.is_id(remote) || local_ref.is_empty() || remote_ref.is_empty() {
            return Err(bad());
        }
        out.push(Pushed { local_ref: (*local_ref).to_string(), local: (*local).to_string(), remote_ref: (*remote_ref).to_string(), remote: (*remote).to_string() });
    }
    Ok(out)
}

/// An id of zeros: a deletion's local id, a new ref's remote id.
fn is_zero(id: &str) -> bool {
    id.bytes().all(|b| b == b'0')
}

/// A ref under [`NEVER_PUSHED`], compared as the Mac's disk compares names.
fn never_pushed(name: &str) -> bool {
    NEVER_PUSHED.iter().any(|p| name.len() >= p.len() && name.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes()))
}

/// A ref under `refs/remotes/box/` or `refs/remotes/box-quarantine/`
/// (ignoring ASCII case: one directory on the Mac's disk).
fn is_box_ref(name: &str) -> bool {
    let remote = name.strip_prefix("refs/remotes/").and_then(|rest| rest.split('/').next()).unwrap_or_default();
    BOX_REMOTES.iter().any(|b| remote.eq_ignore_ascii_case(b))
}

/// REMOTE as a remote's name (§4.1): only when it differs from URL, is a
/// plain name (`[A-Za-z0-9._-]{1,64}`) and `git config --get
/// remote.<REMOTE>.url` succeeds. Anything else is a push to a bare URL,
/// which git passes as REMOTE too, credentials included: never shown, and
/// never part of a git argument.
fn remote_name(git: &GitRun, remote: &str, url: &str) -> Option<String> {
    let plain = (1..=64).contains(&remote.len()) && remote.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if remote == url || !plain {
        return None;
    }
    git.output(["config", "--get", &format!("remote.{remote}.url")]).ok().map(|_| remote.to_string())
}

/// How many push URLs the remote `remote` (a name [`remote_name`] took) has
/// (`git config --get-all remote.<REMOTE>.pushurl`; none set: 0).
fn push_urls(git: &GitRun, remote: &str) -> usize {
    git.output(["config", "--get-all", &format!("remote.{remote}.pushurl")]).map_or(0, |out| String::from_utf8_lossy(&out).lines().filter(|l| !l.trim().is_empty()).count())
}

/// The object `spec` names (`None` when it names none: no such name, or
/// nothing of the kind a `^{…}` asks behind it).
fn rev_parse(git: &GitRun, spec: &str) -> Result<Option<String>, CliError> {
    match git.output(["rev-parse", "--verify", "--quiet", "--end-of-options", spec]) {
        Ok(out) => Ok(Some(String::from_utf8_lossy(&out).trim().to_string())),
        Err(GitError::Failed { .. }) => Ok(None),
        Err(e) => Err(failed("git rev-parse")(e)),
    }
}

/// The commit `rev` names (`None` when it names none: no such name, no
/// commit behind it).
fn resolve_commit(git: &GitRun, rev: &str) -> Result<Option<String>, CliError> {
    rev_parse(git, &format!("{rev}^{{commit}}"))
}

/// The refs under `prefix` that name a commit, `(ref, id)`, in ref order.
fn tracking_refs(git: &GitRun, prefix: &str) -> Result<Vec<(String, String)>, CliError> {
    let out = git.output(["for-each-ref", "--format=%(objectname)%00%(objecttype)%00%(refname)", prefix]).map_err(failed("git for-each-ref"))?;
    Ok(String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| {
            let mut f = l.split('\0');
            match (f.next(), f.next(), f.next()) {
                (Some(id), Some("commit"), Some(name)) => Some((name.to_string(), id.to_string())),
                _ => None,
            }
        })
        .collect())
}

/// The bases' names as the header shows them: the first five, then how many more.
fn names(bases: &[String]) -> String {
    let mut out: Vec<String> = bases.iter().take(5).map(|b| shown(b)).collect();
    if bases.len() > 5 {
        out.push(format!("{} more", bases.len() - 5));
    }
    out.join(", ")
}

/// One change `git log --raw` (or `git diff --raw`) reported.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Change {
    commit: String,
    new_mode: String,
    old_id: String,
    new_id: String,
    /// `A`, `M`, `D`, `T`.
    status: char,
    path: String,
}

/// `--raw -z` output: `\x01<id>` headers (`--format=%x01%H`), each change
/// a `:<modes> <ids> <status>` field and its path; changes before any
/// header are `commit`'s.
fn parse_raw(out: &[u8], commit: &str) -> Vec<Change> {
    let mut changes = Vec::new();
    let mut at = commit.to_string();
    let mut fields = out.split(|b| *b == 0).map(|f| f.strip_prefix(b"\n").unwrap_or(f));
    while let Some(field) = fields.next() {
        if let Some(id) = field.strip_prefix(b"\x01") {
            at = String::from_utf8_lossy(id).into_owned();
            continue;
        }
        let Some(meta) = field.strip_prefix(b":") else { continue };
        let Some(path) = fields.next() else { break };
        let meta = String::from_utf8_lossy(meta);
        let m: Vec<&str> = meta.split(' ').collect();
        let [_, new_mode, old_id, new_id, status] = m.as_slice() else { continue };
        changes.push(Change { commit: at.clone(), new_mode: (*new_mode).to_string(), old_id: (*old_id).to_string(), new_id: (*new_id).to_string(), status: status.chars().next().unwrap_or('?'), path: String::from_utf8_lossy(path).into_owned() });
    }
    changes
}

/// The rules' changes of the range `revs` names, the oldest commit first:
/// every commit not TREESAME to all its parents for [`WATCHED`] and `extra`
/// ([`watch_specs`]), a merge's against its first parent.
fn changes_of(git: &GitRun, revs: &[u8], extra: &[String]) -> Result<Vec<Change>, CliError> {
    let mut args = vec!["log", "--stdin", "--full-history", "--no-renames", "--diff-merges=first-parent", "--root", "--raw", "-z", "--no-abbrev", "--no-relative", "--no-show-signature", "--reverse", "--format=%x01%H", "--"];
    args.extend(WATCHED);
    args.extend(extra.iter().map(String::as_str));
    let out = git.output_stdin(&args, revs).map_err(failed("git log of the reviewed changes"))?;
    Ok(parse_raw(&out, ""))
}

/// The merge bases of `head` and the bases (`merge-base --all`): what a
/// change is new against; none without a base or a common ancestor.
fn merge_bases(git: &GitRun, head: &str, bases: &[(String, String)]) -> Result<Vec<String>, CliError> {
    if bases.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = vec!["merge-base".to_string(), "--all".into(), head.to_string()];
    args.extend(bases.iter().map(|(_, id)| id.clone()));
    match git.output(&args) {
        Ok(out) => Ok(String::from_utf8_lossy(&out).lines().map(str::to_string).collect()),
        Err(GitError::Failed { code: Some(1), .. }) => Ok(Vec::new()),
        Err(e) => Err(failed("git merge-base")(e)),
    }
}

/// One object `cat-file --batch-check` named: its id, its type, its size.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Object {
    id: String,
    kind: String,
    size: u64,
}

/// `specs` (object ids, `<commit>:<path>`) to the objects they name (one
/// `cat-file --batch-check`); a spec naming none, or holding a newline (no
/// batch line can carry it), is absent.
fn objects(git: &GitRun, specs: &[String]) -> Result<HashMap<String, Object>, CliError> {
    let specs: Vec<&String> = specs.iter().filter(|s| !s.contains('\n')).collect();
    if specs.is_empty() {
        return Ok(HashMap::new());
    }
    let input: String = specs.iter().map(|s| format!("{s}\n")).collect();
    let out = git.output_stdin(["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], input.as_bytes()).map_err(failed("git cat-file --batch-check"))?;
    let text = String::from_utf8_lossy(&out);
    Ok(specs
        .into_iter()
        .zip(text.lines())
        .filter_map(|(spec, line)| {
            let mut f = line.split(' ');
            match (f.next(), f.next(), f.next().and_then(|n| n.parse::<u64>().ok())) {
                (Some(id), Some(kind), Some(size)) => Some((spec.clone(), Object { id: id.to_string(), kind: kind.to_string(), size })),
                _ => None,
            }
        })
        .collect())
}

/// One range, `rev-list --objects <tip> --not <bases>` (`tip` the object
/// pushed or named, an annotated tag unpeeled; `head` its commit, which
/// names the head's findings): its commits, the tripwires over its objects
/// (a tag's own among them), then the rules over its changes (those behind
/// the links its merge bases and its head hold too, [`link_aliases`], and
/// the pre-push hook's own path); `olds` are
/// tips the push replaces, against which a lock the head lacks is a net
/// removal as against a merge base.
fn review_range(cx: &mut Cx<'_>, tip: &str, head: &str, bases: &[(String, String)], olds: &[String]) -> Result<Review, CliError> {
    let mut revs = format!("{tip}\n");
    for (_, id) in bases {
        revs.push_str(&format!("^{id}\n"));
    }
    let revs = revs.into_bytes();
    let log = cx.repo.git.output_stdin(["log", "--stdin", "-z", "--no-show-signature", "--format=%H %s"], &revs).map_err(failed("git log of the reviewed commits"))?;
    let commits: Vec<Commit> = log
        .split(|b| *b == 0)
        .filter(|r| !r.is_empty())
        .map(|r| {
            let r = String::from_utf8_lossy(r.strip_prefix(b"\n").unwrap_or(r)).into_owned();
            let (id, subject) = r.split_once(' ').unwrap_or((r.as_str(), ""));
            subject_of(cx.set, id, subject)
        })
        .collect();
    let listed = cx.repo.git.output_stdin(["rev-list", "--objects", "--stdin"], &revs).map_err(failed("git rev-list of the reviewed commits"))?;
    let list: Vec<Listed> = String::from_utf8_lossy(&listed)
        .lines()
        .filter_map(|l| {
            let (id, path) = match l.split_once(' ') {
                Some((o, p)) => (o, Some(p.to_string())),
                None => (l, None),
            };
            cx.repo.format.is_id(id).then(|| Listed { id: id.to_string(), path })
        })
        .collect();
    let mut findings = scan_objects(&cx.repo.git, &list, cx.set, &mut cx.cache, cx.max_blob, &[])?.findings;
    let mbs = merge_bases(&cx.repo.git, head, bases)?;
    let aliases = link_aliases(cx, head, &mbs)?;
    let changes = changes_of(&cx.repo.git, &revs, &watch_specs(&cx.hook, &aliases))?;
    findings.extend(rule_findings(cx, &changes, head, &mbs, olds, &aliases)?);
    let ids: Vec<String> = commits.iter().map(|c| c.id.clone()).collect();
    let mut found: Vec<Found> = Vec::new();
    for f in findings {
        if found.iter().any(|k| k.finding == f) {
            continue;
        }
        let (commit, path) = attribute(&f.location, &ids, head);
        found.push(Found { finding: f, commit, path });
    }
    Ok(Review { commits, found, whole_history: bases.is_empty(), bases: bases.iter().map(|(n, _)| n.clone()).collect() })
}

/// A commit's subject as the report shows it: control characters stripped
/// and scrubbed, or withheld when a tripwire trips on it (the rule named).
fn subject_of(set: &ScanSet, id: &str, raw: &str) -> Commit {
    let stripped: String = raw.chars().filter(|c| !c.is_control()).collect();
    let rule = set.rules.scan_bytes(raw.as_bytes()).into_iter().chain(set.rules.scan_bytes(stripped.as_bytes())).map(|(_, r)| r).next();
    match rule {
        Some(rule) => Commit { id: id.to_string(), subject: None, withheld: Some(rule) },
        None => Commit { id: id.to_string(), subject: Some(scrub(&stripped).into_owned()), withheld: None },
    }
}

/// The commit a finding names (`commit <id12>…`, its full id from `ids`)
/// and the path after it (empty for the commit's own text); a finding that
/// names no commit (a path name, an object) is `head`'s, its location the path.
fn attribute(location: &str, ids: &[String], head: &str) -> (String, String) {
    if let Some(rest) = location.strip_prefix("commit ") {
        let (id, path) = rest.split_once(':').unwrap_or((rest, ""));
        if id.len() == ID_SHOWN && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            let full = ids.iter().chain(std::iter::once(&head.to_string())).find(|i| i.starts_with(id)).cloned().unwrap_or_else(|| id.to_string());
            return (full, path.to_string());
        }
    }
    (head.to_string(), location.to_string())
}

/// Where a finding of `commit`'s change at `path` is: `commit <id12>:<path>`
/// (the path withheld when it trips a rule).
fn place(set: &ScanSet, commit: &str, path: &str) -> String {
    format!("commit {}:{}", short(commit), shown_path(set, path))
}

/// The rules over `changes` (the oldest first), each change at the commit
/// that made it, `mbs` the merge bases, `olds` the tips a push replaces. A
/// change counts when it brings a blob to a watched path that no merge base
/// holds at that path (a file copied there from one the remote has
/// elsewhere counts too): D8's repo mode and its links (`scan_settings`);
/// an allow entry beyond the policy; a plaintext dotenv; a `Cargo.lock`'s
/// new sources and changed checksums; cargo configuration's new source
/// replacement and patches. A link where cargo reads its files is a
/// finding of its own, since cargo reads through it and these rules never
/// do: at a `Cargo.lock` [`RULE_CARGO_LOCK_REMOVED`] (the lock is no file
/// there any more), at `.cargo` or its configuration
/// [`RULE_CARGO_CONFIG_SOURCE`] (key `source`); so is one where claude
/// reads its settings while the workspace trusts its repo settings
/// ([`RULE_ALLOW_NOT_IN_POLICY`], key `permissions.allow`: D8's
/// `settings-symlink` is off then). Whatever it brings, a `Cargo.lock` a
/// commit deletes, or that the head lacks (or holds as a link) against a
/// merge base or a replaced tip, is [`RULE_CARGO_LOCK_REMOVED`]. "New"
/// inside a file is against the merge bases' file at that path and the
/// versions reviewed before it, so each entry is named once, where it first
/// came. A blob over `max_blob` is never read (`scan_objects` names it
/// `blob-too-large` when the range brought it). A key that trips a rule
/// itself (a registry named by a credentialed URL) is left out.
///
/// A path an alias stands on ([`link_aliases`]: a link the merge bases or
/// the head hold makes cargo or claude read it under a watched path's name)
/// is judged under that name, at its own path: the file reached by the
/// rules above (D8's repo mode too, which blobscan's scan applies by own
/// names only, and a link there is `settings-symlink`); a link passed, or a
/// directory above that file, as a link at the watched path (a lock's:
/// anything in its place, or its deletion). Any change at one of the
/// pre-push hook's paths through the work tree ([`hook_rels`]: as git
/// names it, a link passed, where it ends), at a directory above one, or
/// at an alias of one is [`RULE_PRE_PUSH_HOOK_CHANGED`], unless a merge
/// base holds that very entry there (its mode too: a hook git cannot
/// execute, or a link in its place, never runs) or, for a deletion, none.
fn rule_findings(cx: &Cx<'_>, changes: &[Change], head: &str, mbs: &[String], olds: &[String], aliases: &[Alias]) -> Result<Vec<Finding>, CliError> {
    let git = &cx.repo.git;
    // Whether a change stands on an alias, and on a link or a directory on the way to the file (`name_of`).
    let aliased = |c: &Change| alias_of(aliases, &c.path).is_some();
    let via = |c: &Change| alias_of(aliases, &c.path).is_some_and(|a| a.via);
    let watched = |c: &Change| c.status != 'D' && is_watched(name_of(aliases, c));
    // What the merge bases hold at each watched path, what the changes bring, and the first parents' locks.
    let paths: BTreeSet<&str> = changes.iter().filter(|c| watched(c)).map(|c| c.path.as_str()).collect();
    let mut specs: Vec<String> = mbs.iter().flat_map(|m| paths.iter().map(move |p| format!("{m}:{p}"))).collect();
    specs.extend(changes.iter().filter(|c| watched(c)).map(|c| c.new_id.clone()));
    specs.extend(changes.iter().filter(|c| watched(c) && is_cargo_lock(name_of(aliases, c)) && !is_zero(&c.old_id)).map(|c| c.old_id.clone()));
    let objs = objects(git, &specs)?;
    let held = |c: &Change| mbs.iter().any(|m| objs.get(&format!("{m}:{}", c.path)).is_some_and(|o| o.id == c.new_id));
    let fresh = |c: &Change| watched(c) && !held(c);
    let mut out = Vec::new();
    // D8 and the settings links, through blobscan's own scan (a blob read once per path).
    let mut trees: Vec<(String, Vec<TreeEntry>)> = Vec::new();
    for c in changes.iter().filter(|c| fresh(c) && (settings_name(&c.path).is_some() || (c.new_mode == "120000" && is_claude_dir(&c.path)))) {
        let label = format!("commit {}", short(&c.commit));
        let entry = TreeEntry { mode: c.new_mode.clone(), id: c.new_id.clone(), path: c.path.clone() };
        match trees.last_mut() {
            Some((l, entries)) if *l == label => entries.push(entry),
            _ => trees.push((label, vec![entry])),
        }
    }
    let mut d8 = ScanReport::default();
    scan_settings(git, &trees, cx.set, &|_| false, &mut d8)?;
    out.extend(d8.findings);
    // The documents the other rules read, the merge bases' versions of their paths, and the first parents' locks.
    let doc = |c: &Change| {
        let name = name_of(aliases, c);
        fresh(c) && !via(c) && c.new_mode.starts_with("100") && (settings_name(name).is_some() || is_dotenv(name) || is_cargo_lock(name) || is_cargo_config(name))
    };
    let docs: Vec<&Change> = changes.iter().filter(|c| doc(c)).collect();
    let mut reads: Vec<String> = docs.iter().map(|c| c.new_id.clone()).collect();
    reads.extend(docs.iter().filter(|c| is_cargo_lock(name_of(aliases, c)) && !is_zero(&c.old_id)).map(|c| c.old_id.clone()));
    let compared: BTreeSet<&str> = docs.iter().filter(|c| !is_dotenv(name_of(aliases, c))).map(|c| c.path.as_str()).collect();
    for m in mbs {
        reads.extend(compared.iter().map(|p| format!("{m}:{p}")));
    }
    let readable = |spec: &str| objs.get(spec).filter(|o| o.kind == "blob" && o.size <= cx.max_blob).map(|o| o.id.as_str());
    let wanted: Vec<String> = reads.iter().filter_map(|s| readable(s)).map(str::to_string).collect::<BTreeSet<String>>().into_iter().collect();
    let mut bytes: HashMap<String, Vec<u8>> = HashMap::new();
    read_objects(git, &wanted, |id, b| {
        bytes.insert(id.to_string(), b.to_vec());
    })?;
    let blob = |spec: &str| readable(spec).and_then(|id| bytes.get(id)).map(Vec::as_slice);
    // Per path: the merge bases' versions, then each version reviewed (the newest last).
    let mut known: HashMap<&str, Vec<&[u8]>> = HashMap::new();
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let mut removed: BTreeSet<String> = BTreeSet::new();
    for c in changes {
        let name = name_of(aliases, c);
        if c.status == 'D' && is_cargo_lock(name) {
            removed.insert(c.path.clone());
            out.push(Finding { location: place(cx.set, &c.commit, &c.path), object: None, line: 0, rule: RULE_CARGO_LOCK_REMOVED.into(), key: None });
            continue;
        }
        // A new link where cargo or claude reads a file (on the way to a lock reached through one, anything in a
        // directory's place): what it points at is never read here.
        if fresh(c) && (c.new_mode == "120000" || via(c)) {
            let rule = if is_cargo_lock(name) {
                removed.insert(c.path.clone());
                Some((RULE_CARGO_LOCK_REMOVED, None))
            } else if c.new_mode != "120000" {
                // A file in the place of a directory on the way: cargo and claude read nothing there.
                None
            } else if is_cargo_config(name) || is_cargo_dir(name) {
                Some((RULE_CARGO_CONFIG_SOURCE, Some("source".to_string())))
            } else if settings_name(name).is_some() || is_claude_dir(name) {
                if !cx.set.repo_settings {
                    Some((RULE_ALLOW_NOT_IN_POLICY, Some("permissions.allow".to_string())))
                } else if aliased(c) {
                    // D8's own scan names a link by its own name only.
                    Some((SETTINGS_SYMLINK, None))
                } else {
                    None
                }
            } else {
                None
            };
            let first = seen.insert((c.path.as_str(), c.new_id.as_str()));
            if let Some((rule, key)) = rule.filter(|_| first) {
                out.push(Finding { location: place(cx.set, &c.commit, &c.path), object: Some(short(&c.new_id).to_string()), line: 0, rule: rule.into(), key });
            }
            continue;
        }
        if !doc(c) || !seen.insert((c.path.as_str(), c.new_id.as_str())) {
            continue;
        }
        // Over `max_blob`: never read (`blob-too-large` when the range brought it).
        let Some(text) = blob(&c.new_id) else { continue };
        let versions = known.entry(c.path.as_str()).or_insert_with(|| mbs.iter().filter_map(|m| blob(&format!("{m}:{}", c.path))).collect());
        let hits: Vec<(usize, &'static str, Option<String>)> = if let Some(file) = settings_name(name) {
            let mut hits = Vec::new();
            // D8's repo mode on a settings file reached through a link: blobscan's scan reads own names only.
            if cx.set.repo_settings && aliased(c) {
                hits.extend(settings_findings_mode(file, text, &[], SettingsMode::Repo).into_iter().map(|f| (f.line, f.rule, Some(f.key).filter(|k| !k.is_empty()))));
            }
            hits.extend(allow_beyond_policy(file, text, versions, cx.policy).into_iter().map(|f| (f.line, f.rule, Some(f.key))));
            hits
        } else if is_dotenv(name) {
            if has_marker(text) {
                Vec::new()
            } else {
                vec![(0, "env-file-plaintext", None)]
            }
        } else if is_cargo_lock(name) {
            cargo_lock_findings(text, versions, blob(&c.old_id))
        } else {
            cargo_config_findings(text, versions)
        };
        for (line, rule, key) in hits {
            // Never a key that trips a tripwire, nor one cut short (part of a token may no longer match).
            let key = key.filter(|k| !k.ends_with('\u{2026}') && cx.set.rules.scan_bytes(k.as_bytes()).is_empty());
            out.push(Finding { location: place(cx.set, &c.commit, &c.path), object: Some(short(&c.new_id).to_string()), line, rule: rule.into(), key });
        }
        versions.push(text);
    }
    // The pre-push hook through the work tree: any change at one of its paths, above one or on an alias of one,
    // unless a merge base holds that very entry there (mode and id: a merge bringing the remote's own change) or,
    // for a deletion, none.
    let hooked = |c: &Change| is_hook(&cx.hook, &c.path) || aliases.iter().any(|a| same_path(&a.path, &c.path) && is_hook(&cx.hook, &a.name));
    let mut hook_seen: HashSet<(&str, &str, &str)> = HashSet::new();
    for c in changes.iter().filter(|c| hooked(c)) {
        if !hook_seen.insert((c.path.as_str(), c.new_mode.as_str(), c.new_id.as_str())) {
            continue;
        }
        let mut held_there = false;
        for m in mbs {
            let entry = tree_entry(git, m, &c.path)?;
            held_there |= if c.status == 'D' { entry.is_none() } else { entry.is_some_and(|(mode, id)| mode == c.new_mode && id == c.new_id) };
        }
        if !held_there {
            out.push(Finding { location: place(cx.set, &c.commit, &c.path), object: (!is_zero(&c.new_id)).then(|| short(&c.new_id).to_string()), line: 0, rule: RULE_PRE_PUSH_HOOK_CHANGED.into(), key: None });
        }
    }
    // A lock the head lacks, or holds as a link, against a merge base or a tip the push replaces (a forced push's
    // old tip need not be an ancestor), which no commit of the range was seen removing; a lock reached through a
    // link too, when a link or a directory on its way is gone or replaced.
    let mut lock_specs: Vec<String> = vec![LOCKS.to_string()];
    for spec in aliases.iter().filter(|a| is_cargo_lock(&a.name)).map(|a| folded_spec(&a.path)) {
        if !lock_specs.contains(&spec) {
            lock_specs.push(spec);
        }
    }
    let mut against: Vec<&str> = Vec::new();
    for b in mbs.iter().chain(olds) {
        if !against.contains(&b.as_str()) {
            against.push(b);
        }
    }
    for b in against {
        let mut args = vec!["diff", "--raw", "-z", "--no-renames", "--no-abbrev", "--no-relative", b, head, "--"];
        args.extend(lock_specs.iter().map(String::as_str));
        let out_diff = git.output(&args).map_err(failed("git diff of the locks"))?;
        for c in parse_raw(&out_diff, head) {
            if is_cargo_lock(name_of(aliases, &c)) && (c.status == 'D' || c.new_mode == "120000" || via(&c)) && removed.insert(c.path.clone()) {
                out.push(Finding { location: place(cx.set, head, &c.path), object: None, line: 0, rule: RULE_CARGO_LOCK_REMOVED.into(), key: None });
            }
        }
    }
    Ok(out)
}

/// The alias `path` stands on ([`link_aliases`]), when its own name is no watched one.
fn alias_of<'a>(aliases: &'a [Alias], path: &str) -> Option<&'a Alias> {
    if is_watched(path) {
        None
    } else {
        aliases.iter().find(|a| same_path(&a.path, path))
    }
}

/// The name a change's rules go by: its own path's, else the watched path its alias stands for.
fn name_of<'a>(aliases: &'a [Alias], c: &'a Change) -> &'a str {
    alias_of(aliases, &c.path).map_or(c.path.as_str(), |a| a.name.as_str())
}

/// One package of a `Cargo.lock` as cargo reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

/// The packages of a `Cargo.lock` parsed as the TOML it is (`[[package]]`
/// tables, whatever their layout), a v1 lock's `[metadata]` checksums
/// (`"checksum NAME VERSION (SOURCE)" = "…"`) joined to theirs; `None` for
/// bytes the `toml` crate (TOML 1.0) does not read. cargo reads TOML 1.1,
/// which takes more (a newline or a trailing comma inside an inline
/// table): the rules fail closed on `None` ([`cargo_lock_findings`]).
fn lock_packages(bytes: &[u8]) -> Option<Vec<LockPackage>> {
    let root: toml::Table = toml::from_str(std::str::from_utf8(bytes).ok()?).ok()?;
    let mut out: Vec<LockPackage> = Vec::new();
    for p in root.get("package").and_then(toml::Value::as_array).into_iter().flatten().filter_map(toml::Value::as_table) {
        let s = |k: &str| p.get(k).and_then(toml::Value::as_str).map(str::to_string);
        if let (Some(name), Some(version)) = (s("name"), s("version")) {
            out.push(LockPackage { name, version, source: s("source"), checksum: s("checksum") });
        }
    }
    for (key, value) in root.get("metadata").and_then(toml::Value::as_table).into_iter().flatten() {
        let (Some(rest), Some(sum)) = (key.strip_prefix("checksum "), value.as_str()) else { continue };
        let mut f = rest.splitn(3, ' ');
        let (Some(name), Some(version)) = (f.next(), f.next()) else { continue };
        let source = f.next().and_then(|s| s.strip_prefix('(')).and_then(|s| s.strip_suffix(')')).map(str::to_string);
        match out.iter_mut().find(|p| p.name == name && p.version == version && p.checksum.is_none()) {
            Some(p) => p.checksum = Some(sum.to_string()),
            None => out.push(LockPackage { name: name.to_string(), version: version.to_string(), source, checksum: Some(sum.to_string()) }),
        }
    }
    Some(out)
}

/// The first line (1-based) of `text` holding `needle` quoted, else bare; 0 when none does.
fn line_of(text: &[u8], needle: &str) -> usize {
    let text = String::from_utf8_lossy(text);
    let quoted = format!("\"{needle}\"");
    let find = |n: &str| text.lines().position(|l| l.contains(n)).map(|i| i + 1);
    find(&quoted).or_else(|| find(needle)).unwrap_or(0)
}

/// The Cargo rules on one `Cargo.lock` against `known` (the merge bases'
/// and the earlier reviewed versions at its path) and its first parent's:
/// a source no known version names that is not crates.io
/// ([`RULE_CARGO_LOCK_SOURCE`]); a checksum no known version records for
/// that package and version where one of them, or the first parent,
/// records another ([`RULE_CARGO_LOCK_CHECKSUM`]); a lock emptied of every
/// package with a source that the first parent or a known version held, by
/// `(name, source)`, which drops their pins and checksums as a deletion
/// does ([`RULE_CARGO_LOCK_REMOVED`]). Keyed `NAME VERSION`, never the
/// source or the checksum. Bytes [`lock_packages`] does not read fail
/// closed: one [`RULE_CARGO_LOCK_SOURCE`] at the file (cargo may read them:
/// TOML 1.1), unless a known version holds the very same bytes.
fn cargo_lock_findings(text: &[u8], known: &[&[u8]], parent: Option<&[u8]>) -> Vec<(usize, &'static str, Option<String>)> {
    let Some(pkgs) = lock_packages(text) else {
        return if known.contains(&text) { Vec::new() } else { vec![(0, RULE_CARGO_LOCK_SOURCE, None)] };
    };
    let held: Vec<LockPackage> = known.iter().filter_map(|k| lock_packages(k)).flatten().collect();
    let before: Vec<LockPackage> = parent.and_then(lock_packages).unwrap_or_default();
    let mut out = Vec::new();
    // Emptied: no `(name, source)` the first parent or a known version held is left (a `version = 4` header alone).
    let pinned: Vec<(&str, &str)> = held.iter().chain(&before).filter_map(|h| h.source.as_deref().map(|s| (h.name.as_str(), s))).collect();
    if !pinned.is_empty() && !pkgs.iter().any(|p| p.source.as_deref().is_some_and(|s| pinned.contains(&(p.name.as_str(), s)))) {
        out.push((0, RULE_CARGO_LOCK_REMOVED, None));
    }
    for p in &pkgs {
        let key = Some(format!("{} {}", p.name, p.version));
        if let Some(src) = p.source.as_deref().filter(|s| !CRATES_IO.contains(s)) {
            if !held.iter().any(|h| h.source.as_deref() == Some(src)) {
                out.push((line_of(text, src), RULE_CARGO_LOCK_SOURCE, key.clone()));
            }
        }
        if let Some(sum) = p.checksum.as_deref() {
            let same = |h: &LockPackage| h.name == p.name && h.version == p.version;
            let recorded = held.iter().any(|h| same(h) && h.checksum.as_deref() == Some(sum));
            let other = held.iter().chain(&before).any(|h| same(h) && h.checksum.as_deref().is_some_and(|c| c != sum));
            if !recorded && other {
                out.push((line_of(text, sum), RULE_CARGO_LOCK_CHECKSUM, key));
            }
        }
    }
    out
}

/// What in a cargo configuration file takes crates from elsewhere, `(KEY,
/// LEAF, VALUE)` (the value as TOML writes it): each key of each
/// `[source.NAME]` table (source replacement, `source.NAME.KEY`), each key
/// of each `[patch.REGISTRY.CRATE]` table (a patch, read from configuration
/// since cargo 1.56: `patch.REGISTRY.CRATE.KEY`), a top-level `paths`
/// (path overrides: `paths`), and each entry of a top-level `include`
/// (another file cargo reads as configuration, a string or `{ path = … }`:
/// `include`; [`link_aliases`] reviews that file under the including one's
/// name); `None` for bytes the `toml` crate (TOML 1.0) does not read, which
/// cargo may (TOML 1.1): [`cargo_config_findings`] fails closed on them.
fn config_sources(bytes: &[u8]) -> Option<Vec<(String, String, String)>> {
    let root: toml::Table = toml::from_str(std::str::from_utf8(bytes).ok()?).ok()?;
    let written = |v: &toml::Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
    let mut out = Vec::new();
    for (name, table) in root.get("source").and_then(toml::Value::as_table).into_iter().flatten() {
        for (key, value) in table.as_table().into_iter().flatten() {
            out.push((format!("source.{name}.{key}"), key.clone(), written(value)));
        }
    }
    for (registry, crates) in root.get("patch").and_then(toml::Value::as_table).into_iter().flatten() {
        for (krate, patch) in crates.as_table().into_iter().flatten() {
            match patch.as_table() {
                Some(table) => out.extend(table.iter().map(|(key, value)| (format!("patch.{registry}.{krate}.{key}"), key.clone(), written(value)))),
                None => out.push((format!("patch.{registry}.{krate}"), krate.clone(), written(patch))),
            }
        }
    }
    if let Some(paths) = root.get("paths") {
        out.push(("paths".to_string(), "paths".to_string(), written(paths)));
    }
    match root.get("include") {
        Some(toml::Value::Array(entries)) => out.extend(entries.iter().map(|e| ("include".to_string(), "include".to_string(), written(e)))),
        Some(other) => out.push(("include".to_string(), "include".to_string(), written(other))),
        None => {}
    }
    Some(out)
}

/// The files a cargo configuration includes (its top-level `include`: each
/// string entry, each table's `path`), as written; none for bytes that are
/// no TOML.
fn config_includes(bytes: &[u8]) -> Vec<String> {
    let Some(root) = std::str::from_utf8(bytes).ok().and_then(|t| toml::from_str::<toml::Table>(t).ok()) else { return Vec::new() };
    let entry = |v: &toml::Value| match v {
        toml::Value::String(p) => Some(p.clone()),
        toml::Value::Table(t) => t.get("path").and_then(toml::Value::as_str).map(str::to_string),
        _ => None,
    };
    match root.get("include") {
        Some(toml::Value::Array(entries)) => entries.iter().filter_map(entry).collect(),
        Some(other) => entry(other).into_iter().collect(),
        None => Vec::new(),
    }
}

/// [`RULE_CARGO_CONFIG_SOURCE`] on one cargo configuration against `known`
/// (the merge bases' and the earlier reviewed versions at its path): each
/// source replacement, patch, path override or include ([`config_sources`])
/// no known version holds with that value, keyed (`source.NAME.KEY`,
/// `patch.REGISTRY.CRATE.KEY`, `paths`, `include`), never the value. Bytes
/// [`config_sources`] does not read fail closed: one finding keyed
/// `source` at the file (cargo may read them: TOML 1.1), unless a known
/// version holds the very same bytes.
fn cargo_config_findings(text: &[u8], known: &[&[u8]]) -> Vec<(usize, &'static str, Option<String>)> {
    let Some(entries) = config_sources(text) else {
        return if known.contains(&text) { Vec::new() } else { vec![(0, RULE_CARGO_CONFIG_SOURCE, Some("source".into()))] };
    };
    let held: Vec<(String, String, String)> = known.iter().filter_map(|k| config_sources(k)).flatten().collect();
    entries
        .into_iter()
        .filter(|e| !held.contains(e))
        .map(|(key, leaf, value)| {
            let line = Some(line_of(text, &value)).filter(|l| *l > 0).unwrap_or_else(|| line_of(text, &leaf));
            (line, RULE_CARGO_CONFIG_SOURCE, Some(key))
        })
        .collect()
}

/// The report: `--json`'s one document, or the header, the notes, the
/// commits (at most [`COMMITS_SHOWN`]), at most [`FINDINGS_MAX`] finding
/// lines, then the verdict.
fn report(cx: &Cx<'_>, header: &str, rev: Option<&str>, head: Option<&str>, review: &Review, verdict: &str) -> Result<(), CliError> {
    if cx.json {
        let findings: Vec<serde_json::Value> = review
            .found
            .iter()
            .take(FINDINGS_MAX)
            .map(|f| serde_json::json!({ "rule": f.finding.rule, "path": shown(&f.path), "line": (f.finding.line > 0).then_some(f.finding.line), "commit": f.commit }))
            .collect();
        let commits: Vec<serde_json::Value> = review.commits.iter().map(|c| serde_json::json!({ "id": c.id, "subject": c.subject, "withheld": c.withheld })).collect();
        let v = serde_json::json!({
            "repo": cx.repo.root.display().to_string(),
            "rev": rev.map(shown),
            "head": head,
            "bases": review.bases.iter().map(|b| shown(b)).collect::<Vec<_>>(),
            "whole_history": review.whole_history,
            "commits": commits,
            "findings": findings,
            "more_findings": review.found.len().saturating_sub(FINDINGS_MAX),
            "verdict": verdict,
        });
        outln!("{}", serde_json::to_string_pretty(&v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
        return Ok(());
    }
    outln!("{header}");
    for note in &cx.notes {
        outln!("  note: {note}");
    }
    for c in review.commits.iter().take(COMMITS_SHOWN) {
        match (&c.subject, &c.withheld) {
            (_, Some(rule)) => outln!("  {} (subject withheld: rule {rule})", short(&c.id)),
            (subject, None) => outln!("{}", format!("  {} {}", short(&c.id), subject.as_deref().unwrap_or_default()).trim_end()),
        }
    }
    if review.commits.len() > COMMITS_SHOWN {
        outln!("  and {} more commit(s) (box review --json lists them all)", review.commits.len() - COMMITS_SHOWN);
    }
    if !review.found.is_empty() {
        outln!("{} finding(s):", review.found.len());
        let findings: Vec<Finding> = review.found.iter().map(|f| f.finding.clone()).collect();
        for line in finding_lines(&findings).lines() {
            outln!("  {line}");
        }
    }
    outln!("box review: {verdict}");
    Ok(())
}

/// The `box_review` audit row (§5.1); `remote` is the pre-push's (a
/// remote's name, else `url`), `None` from the command line.
fn audit_review(cx: &Cx<'_>, remote: Option<&str>, review: &Review, verdict: &str) {
    let mut pairs = vec![("repo", cx.repo.root.display().to_string()), ("mode", if remote.is_some() { "pre_push" } else { "cli" }.to_string())];
    if let Some(r) = remote {
        pairs.push(("remote", r.to_string()));
    }
    pairs.extend([
        ("commits", review.commits.len().to_string()),
        ("findings", review.found.len().to_string()),
        ("whole_history", review.whole_history.to_string()),
        ("verdict", verdict.to_string()),
        ("ms", u64::try_from(cx.started.elapsed().as_millis()).unwrap_or(u64::MAX).to_string()),
    ]);
    crate::bridge::workspace::audit(&cx.paths, audit_event::BOX_REVIEW, &pairs);
}

/// The pre-push hook (§4.2) that runs `ai_env` (an absolute path) on every
/// push, [`PRE_PUSH_MARK`] on its second line; without its binary it
/// refuses the push.
#[must_use]
pub fn hook_body(ai_env: &str) -> String {
    format!(
        "#!/bin/sh\n{PRE_PUSH_MARK}\n# Installed by `ai-env box hook-install`: every push is reviewed first.\nai_env={}\nif [ ! -x \"$ai_env\" ]; then\n  echo \"ai-env pre-push: $ai_env is missing: the push is refused (ai-env box hook-install reinstalls the hook)\" >&2\n  exit 1\nfi\nexec \"$ai_env\" box review --pre-push \"$1\" \"$2\"\n",
        sh_quote(ai_env)
    )
}

/// The review's call in a hook, after the binary's quoted path.
const REVIEW_CALL: &str = "box review --pre-push \"$1\" \"$2\"";
/// The chain's first line: the pushed refs read from the hook's stdin once,
/// byte for byte (a trailing newline kept), for the review and the hook's
/// own readers. git runs pre-push with an empty stdin when nothing is
/// pushed, so the review cannot tell a stdin another reader drained from no
/// push: the refs are read first, and shared.
const CHAIN_READ: &str = "ai_env_refs=$(cat; echo .); ai_env_refs=${ai_env_refs%.}";
/// What feeds the review, and each of the hook's own stdin readers, the refs [`CHAIN_READ`] kept.
pub const CHAIN_FEED: &str = "printf '%s' \"$ai_env_refs\" |";
/// How much of another hook [`calls_review`] reads.
const HOOK_CALL_READ: u64 = 64 * 1024;

/// The two lines another pre-push hook needs to run the review, first
/// (before any `exit` of its own and any read of its stdin; `box
/// hook-install` never writes over it): the refs read once
/// ([`CHAIN_READ`]), then the review fed from them ([`CHAIN_FEED`]). The
/// hook's own readers take the refs the same way (`printf '%s'
/// "$ai_env_refs" | git lfs pre-push "$@"`).
#[must_use]
pub fn chain_line(ai_env: &str) -> String {
    format!("{CHAIN_READ}\n{CHAIN_FEED} {} {REVIEW_CALL} || exit 1", sh_quote(ai_env))
}

/// Whether another pre-push hook (a regular file at `path`) calls the
/// review as [`chain_line`] does, in its first 64 KiB: the refs read once
/// ([`CHAIN_READ`]) and a line feeding them to `box review --pre-push "$1"
/// "$2"` ([`CHAIN_FEED`]). Whether those run before an `exit` or another
/// read of its own is not checked.
#[must_use]
pub fn calls_review(path: &Path) -> bool {
    if !std::fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return false;
    }
    let mut head = Vec::new();
    if std::fs::File::open(path).and_then(|f| f.take(HOOK_CALL_READ).read_to_end(&mut head)).is_err() {
        return false;
    }
    let text = String::from_utf8_lossy(&head);
    text.contains(CHAIN_READ) && text.lines().any(|l| l.contains(CHAIN_FEED) && l.contains(REVIEW_CALL))
}

/// Whether a checkout can change the hook git runs from `hook` through the
/// work tree of the repository at `repo_root` (S9 §13, I2; phase 4): the
/// hook's path as git names it, a link this disk passes on the way, or the
/// file it ends at, lies under the top level and outside the git
/// directories, where a `core.hooksPath` such as `.githooks` or Husky's
/// `.husky/_` puts it, or a link there to shared hooks outside the
/// repository; or git reads a configuration file there ([`config_rels`]: an
/// `include.path` to a tracked `.gitconfig`), which can move
/// `core.hooksPath`. A merged or checked-out commit can replace an entry
/// there, tracked or ignored (git treats an ignored file as expendable),
/// and with it the review of every later push. A bare repository has no
/// work tree.
#[must_use]
pub fn hook_in_work_tree(repo_root: &Path, hook: &Path) -> bool {
    !work_tree_rels(repo_root, hook).is_empty() || !config_rels(repo_root).is_empty()
}

/// `path` with its deepest existing ancestor made canonical (links and
/// `..` resolved up to there), the rest appended as it is.
fn resolved(path: &Path) -> PathBuf {
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    let mut at = path;
    loop {
        if let Ok(real) = std::fs::canonicalize(at) {
            return rest.iter().rev().fold(real, |p, name| p.join(name));
        }
        match (at.parent(), at.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                at = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// The running `ai-env`, canonical, as the hook names it; why not when it
/// cannot be named (a path that is no UTF-8, or holds a newline).
pub fn running_ai_env() -> Result<String, String> {
    let exe = std::env::current_exe().and_then(std::fs::canonicalize).map_err(|e| format!("cannot find the running ai-env: {e}"))?;
    let path = exe.to_str().ok_or_else(|| format!("the path of ai-env is no UTF-8: {}", exe.display()))?;
    if path.contains('\n') {
        return Err(format!("the path of ai-env holds a newline, which a hook cannot name: {}", shown(path)));
    }
    Ok(path.to_string())
}

/// `ai-env box hook-install [REPO] [--dry-run] [--json]` (§4.2): the
/// pre-push hook ([`hook_body`], 0755) where git runs it (`git::hook_path`,
/// `core.hooksPath` honoured, [`hook_state`]), naming this `ai-env`. Never
/// over another hook: that is exit 1, printing the one line it needs
/// ([`chain_line`]); a hook of ours naming another binary, or no longer
/// 0755 (git skips it), is rewritten. A hook in the work tree
/// ([`hook_in_work_tree`]) is installed with a warning on stderr. A dry run
/// prints the path and the body and writes nothing (exit 0, no audit row).
/// Exits 0 installed or up to date, 1 a foreign hook, no repository, a
/// write that failed. Audited (`hook_install`).
pub fn cmd_hook_install(repo: Option<&Path>, dry_run: bool, json: bool) -> crate::errors::Result<()> {
    let dir = workdir(repo)?;
    let repo = Repo::open(&dir)?;
    let (hook, ours) = match hook_state(&repo.root) {
        HookState::Installed(p) => (p, Some(true)),
        HookState::Missing(p) => (p, Some(false)),
        HookState::Foreign(p) => (p, None),
        HookState::Unknown(why) => return Err(CliError::Msg(format!("box hook-install: {why}"))),
    };
    let ai_env = running_ai_env().map_err(|e| CliError::Msg(format!("box hook-install: {e}")))?;
    let body = hook_body(&ai_env);
    let outcome = match ours {
        None => "foreign",
        // Its mode too: git skips a hook it cannot execute, and the push goes out unreviewed.
        Some(true) if std::fs::read(&hook).is_ok_and(|b| b == body.as_bytes()) && crate::git::is_mode_0755(&hook).unwrap_or(false) => "up_to_date",
        Some(_) if dry_run => "would_install",
        Some(_) => match crate::git::install_hook(&hook, &body, PRE_PUSH_MARK, true) {
            Ok(crate::git::HookInstall::Foreign) => "foreign",
            Ok(crate::git::HookInstall::Marked { rewritten: false }) => "up_to_date",
            Ok(_) => "installed",
            Err(e) => return Err(CliError::Msg(format!("box hook-install: cannot write {}: {e}", hook.display()))),
        },
    };
    // Worded to stay true once that hook calls the review: it may still exit before the call.
    let calls = if outcome == "foreign" && calls_review(&hook) { ", which calls box review --pre-push" } else { "" };
    let foreign = format!(
        "{} is another pre-push hook{calls}: it is never written over; its pushes are reviewed only if it runs these two lines first, before any exit or read of its stdin, and feeds its own stdin readers from them ({CHAIN_FEED} git lfs pre-push \"$@\"):\n{}",
        hook.display(),
        chain_line(&ai_env)
    );
    if json {
        let v = serde_json::json!({ "repo": repo.root.display().to_string(), "hook": hook.display().to_string(), "outcome": outcome });
        outln!("{}", serde_json::to_string_pretty(&v).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else if dry_run {
        let what = match outcome {
            "foreign" => "another hook is there",
            "up_to_date" => "up to date",
            _ => "would install (0755)",
        };
        outln!("box hook-install --dry-run: {}: {what}", hook.display());
        if outcome == "foreign" {
            outln!("{foreign}");
        } else {
            for line in body.lines() {
                outln!("{line}");
            }
        }
        outln!("nothing was written");
    } else {
        match outcome {
            "installed" => outln!("installed the pre-push review hook: {} (every push from {} is reviewed first)", hook.display(), repo.root.display()),
            "up_to_date" => outln!("the pre-push review hook is up to date: {}", hook.display()),
            _ => {}
        }
    }
    if outcome != "foreign" && hook_in_work_tree(&repo.root, &hook) {
        eprintln!("ai-env: warning: {} lies in the work tree (core.hooksPath), or git reads a configuration file there that can move it (an include): a merged or checked-out commit can replace either, tracked or ignored, and no push after that is reviewed", hook.display());
    }
    if dry_run {
        return Ok(());
    }
    if let Ok(paths) = Paths::resolve() {
        crate::bridge::workspace::audit(&paths, audit_event::HOOK_INSTALL, &[("repo", repo.root.display().to_string()), ("hook", hook.display().to_string()), ("outcome", outcome.to_string())]);
    }
    if outcome == "foreign" {
        return Err(CliError::Msg(format!("box hook-install: {foreign}")));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod review_tests {
    use super::*;

    /// The hook is §4.2's body, byte for byte: the mark on its second line,
    /// the binary single-quoted (its own `'` written `'\''`), a missing
    /// binary refusing the push; the chain line for another hook names the
    /// same call and fails that hook.
    #[test]
    fn the_hook_body_is_the_contracts() {
        assert_eq!(
            hook_body("/opt/ai-env/bin/ai-env"),
            "#!/bin/sh\n# ai-env pre-push review\n# Installed by `ai-env box hook-install`: every push is reviewed first.\nai_env='/opt/ai-env/bin/ai-env'\nif [ ! -x \"$ai_env\" ]; then\n  echo \"ai-env pre-push: $ai_env is missing: the push is refused (ai-env box hook-install reinstalls the hook)\" >&2\n  exit 1\nfi\nexec \"$ai_env\" box review --pre-push \"$1\" \"$2\"\n"
        );
        assert!(hook_body("/Users/o'neil/bin/ai-env").contains("\nai_env='/Users/o'\\''neil/bin/ai-env'\n"));
        assert_eq!(hook_body("/x").lines().nth(1), Some(PRE_PUSH_MARK));
        assert_eq!(chain_line("/Users/o'neil/bin/ai-env"), "ai_env_refs=$(cat; echo .); ai_env_refs=${ai_env_refs%.}\nprintf '%s' \"$ai_env_refs\" | '/Users/o'\\''neil/bin/ai-env' box review --pre-push \"$1\" \"$2\" || exit 1");
    }

    /// git's pre-push lines: a deletion, a local ref given as an expression
    /// with spaces; anything else (three fields, an id that is not the
    /// repository's format, no UTF-8) refused as a whole.
    #[test]
    fn pushed_refs_are_gits_lines() {
        let (a, z) = ("a".repeat(40), "0".repeat(40));
        let input = format!("refs/heads/main {a} refs/heads/main {z}\n(delete) {z} refs/heads/old {a}\nHEAD^{{/fix the bug}} {a} refs/heads/fix {z}\n");
        let p = pushed_refs(input.as_bytes(), ObjectFormat::Sha1).unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!((p[0].local_ref.as_str(), p[0].local.as_str(), p[0].remote_ref.as_str(), p[0].remote.as_str()), ("refs/heads/main", a.as_str(), "refs/heads/main", z.as_str()));
        assert!(is_zero(&p[1].local) && !is_zero(&p[1].remote));
        assert_eq!(p[2].local_ref, "HEAD^{/fix the bug}");
        assert!(pushed_refs(b"", ObjectFormat::Sha1).unwrap().is_empty());
        for bad in [format!("refs/heads/main {a} refs/heads/main\n"), format!("refs/heads/main {} refs/heads/main {z}\n", "A".repeat(40)), format!("refs/heads/main {a} refs/heads/main {z}\n").replace(&a, &"a".repeat(64))] {
            assert!(pushed_refs(bad.as_bytes(), ObjectFormat::Sha1).is_err(), "{bad}");
        }
        assert!(pushed_refs(b"\xff\n", ObjectFormat::Sha1).is_err());
        assert_eq!(pushed_refs(format!("refs/heads/m {} refs/heads/m {}\n", "b".repeat(64), "0".repeat(64)).as_bytes(), ObjectFormat::Sha256).unwrap().len(), 1);
    }

    /// The refs a push never names and the remotes that are ai-env's, as the
    /// Mac's disk compares names (ASCII case).
    #[test]
    fn box_refs_and_never_pushed_fold_case() {
        for r in ["refs/remotes/box/main", "refs/REMOTES/origin/x", "refs/ai-env/incoming/1-0/main", "refs/AI-ENV/seed-wip"] {
            assert!(never_pushed(r), "{r}");
        }
        for r in ["refs/heads/main", "refs/tags/v1", "refs/remote/x", "(delete)", "HEAD", "refs/ai-envx/y"] {
            assert!(!never_pushed(r), "{r}");
        }
        for r in ["refs/remotes/box/main", "refs/remotes/Box/x", "refs/remotes/box-quarantine/a/b", "refs/remotes/BOX-QUARANTINE/c"] {
            assert!(is_box_ref(r), "{r}");
        }
        for r in ["refs/remotes/origin/main", "refs/remotes/boxer/x", "refs/remotes/origin/box", "refs/heads/box/x"] {
            assert!(!is_box_ref(r), "{r}");
        }
    }

    /// `--raw -z`: each change at the header before it (or the given commit
    /// when none came), its new mode, both ids, its status, its path.
    #[test]
    fn raw_changes_parse_with_their_commits() {
        let (c1, c2, x, y, z) = ("1".repeat(40), "2".repeat(40), "a".repeat(40), "b".repeat(40), "0".repeat(40));
        let out = format!("\x01{c1}\0\n:000000 100644 {z} {x} A\0.claude/settings.json\0:100644 000000 {x} {z} D\0Cargo.lock\0\x01{c2}\0\x01{}\0\n:100644 100755 {x} {y} M\0a b/.env\0", "3".repeat(40));
        let changes = parse_raw(out.as_bytes(), "");
        assert_eq!(changes.len(), 3);
        assert_eq!((changes[0].commit.as_str(), changes[0].new_mode.as_str(), changes[0].new_id.as_str(), changes[0].status, changes[0].path.as_str()), (c1.as_str(), "100644", x.as_str(), 'A', ".claude/settings.json"));
        assert_eq!((changes[1].status, changes[1].old_id.as_str(), changes[1].path.as_str()), ('D', x.as_str(), "Cargo.lock"));
        assert_eq!((changes[2].commit.as_str(), changes[2].status, changes[2].path.as_str()), ("3".repeat(40).as_str(), 'M', "a b/.env"));
        let diff = format!(":100644 000000 {x} {z} D\0sub/Cargo.lock\0");
        assert_eq!(parse_raw(diff.as_bytes(), &c2)[0].commit, c2);
    }

    /// A subject that trips a tripwire is withheld naming the rule (raw, or
    /// once its control characters are gone); others lose their control
    /// characters and are scrubbed.
    #[test]
    fn subjects_are_stripped_or_withheld() {
        let set = ScanSet { rules: crate::bridge::scan::Rules::defaults(), digest: String::new(), repo_settings: true };
        let key = format!("{}{}", "AKIA", "Q7".repeat(8));
        let c = subject_of(&set, "abc", &format!("deploy with {key}"));
        assert_eq!((c.subject, c.withheld.as_deref()), (None, Some("aws-access-key-id")));
        let split = format!("{}\u{1b}{}", &key[..10], &key[10..]);
        assert_eq!(subject_of(&set, "abc", &split).withheld.as_deref(), Some("aws-access-key-id"), "a control byte inside the key hides nothing");
        let c = subject_of(&set, "abc", "fix\u{7}the \u{1b}[31mseed");
        assert_eq!((c.subject.as_deref(), c.withheld), (Some("fixthe [31mseed"), None));
    }

    /// A finding's commit and path: `commit <id12>:<path>` to the full id it
    /// abbreviates (a path holding `:` kept whole), `commit <id12>` to that
    /// commit with no path, anything else the head's with its location.
    #[test]
    fn findings_are_attributed_to_their_commits() {
        let ids = vec!["3f2a91c0e4b1aaaa".to_string() + &"0".repeat(24), "9".repeat(40)];
        let head = "h".repeat(40);
        assert_eq!(attribute("commit 3f2a91c0e4b1:cfg/a:b.yaml", &ids, &head), (ids[0].clone(), "cfg/a:b.yaml".to_string()));
        assert_eq!(attribute("commit 999999999999", &ids, &head), (ids[1].clone(), String::new()));
        assert_eq!(attribute("a path name (tree 3f2a91c0e4b1)", &ids, &head), (head.clone(), "a path name (tree 3f2a91c0e4b1)".to_string()));
        assert_eq!(attribute("commit abcabcabcabc:x", &ids, &head), ("abcabcabcabc".to_string(), "x".to_string()), "an id the range does not list stays abbreviated");
    }

    fn lock(packages: &[(&str, &str, Option<&str>, Option<&str>)]) -> Vec<u8> {
        let mut out = String::from("# This file is automatically @generated by Cargo.\nversion = 4\n");
        for (name, version, source, sum) in packages {
            out.push_str(&format!("\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n"));
            if let Some(s) = source {
                out.push_str(&format!("source = \"{s}\"\n"));
            }
            if let Some(c) = sum {
                out.push_str(&format!("checksum = \"{c}\"\n"));
            }
        }
        out.into_bytes()
    }

    fn rules_of(found: Vec<(usize, &'static str, Option<String>)>) -> Vec<(usize, &'static str, String)> {
        found.into_iter().map(|(l, r, k)| (l, r, k.unwrap_or_default())).collect()
    }

    /// The Cargo rules: a source that is not crates.io and no known version
    /// names is a finding (a known one, crates.io's two forms, a path
    /// dependency are not); a checksum changed for an unchanged version
    /// against a known version or the first parent is one, a new version's
    /// is not, nor one a known version records; a v1 lock's metadata
    /// checksums count; a lock emptied of every held package with a source
    /// is removed; bytes the toml crate does not read fail closed.
    #[test]
    fn cargo_lock_rules_name_new_sources_and_changed_checksums() {
        let crates = Some(CRATES_IO[0]);
        let git = "git+https://example.invalid/fork/serde?rev=1#0123456789abcdef";
        let (sum_a, sum_b) = ("a".repeat(64), "b".repeat(64));
        let base = lock(&[("app", "0.1.0", None, None), ("serde", "1.0.200", crates, Some(&sum_a))]);
        let new = lock(&[("app", "0.1.0", None, None), ("serde", "1.0.200", crates, Some(&sum_b)), ("evil", "0.1.0", Some(git), None), ("rand", "0.9.0", Some(CRATES_IO[1]), Some(&sum_a))]);
        let text = String::from_utf8(new.clone()).unwrap();
        let line = |needle: &str| text.lines().position(|l| l.contains(needle)).unwrap() + 1;
        assert_eq!(
            rules_of(cargo_lock_findings(&new, &[&base], None)),
            [(line(&sum_b), RULE_CARGO_LOCK_CHECKSUM, "serde 1.0.200".to_string()), (line(git), RULE_CARGO_LOCK_SOURCE, "evil 0.1.0".to_string())]
        );
        assert_eq!(rules_of(cargo_lock_findings(&new, &[], Some(&base))), [(line(&sum_b), RULE_CARGO_LOCK_CHECKSUM, "serde 1.0.200".to_string()), (line(git), RULE_CARGO_LOCK_SOURCE, "evil 0.1.0".to_string())], "the first parent's checksum counts");
        assert_eq!(rules_of(cargo_lock_findings(&new, &[&base, &new], None)), [], "what a known version holds is not new");
        assert_eq!(rules_of(cargo_lock_findings(&new, &[], None)), [(line(git), RULE_CARGO_LOCK_SOURCE, "evil 0.1.0".to_string())], "a new version's checksum is no change");
        let v1 = format!("[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"{}\"\n\n[metadata]\n\"checksum serde 1.0.200 ({})\" = \"{sum_b}\"\n", CRATES_IO[0], CRATES_IO[0]);
        assert_eq!(rules_of(cargo_lock_findings(v1.as_bytes(), &[&base], None)), [(7, RULE_CARGO_LOCK_CHECKSUM, "serde 1.0.200".to_string())]);
        let inline = format!("version = 4\npackage = [{{ name = \"x\", version = \"1.0.0\", source = \"{git}\" }}]\n");
        assert_eq!(rules_of(cargo_lock_findings(inline.as_bytes(), &[], None)), [(2, RULE_CARGO_LOCK_SOURCE, "x 1.0.0".to_string())], "any TOML layout cargo reads");
        // Bytes the toml crate does not read fail closed, unless a known version holds the very same bytes; TOML
        // 1.1's trailing comma inside an inline table is read by cargo, not by toml 0.8.
        assert_eq!(cargo_lock_findings(b"<<<<<<< HEAD\n", &[], None), [(0, RULE_CARGO_LOCK_SOURCE, None)]);
        assert!(cargo_lock_findings(b"<<<<<<< HEAD\n", &[b"<<<<<<< HEAD\n"], None).is_empty());
        let toml11 = format!("version = 4\npackage = [\n  {{ name = \"evil\", version = \"0.1.0\", source = \"{git}\", }},\n]\n");
        assert_eq!(cargo_lock_findings(toml11.as_bytes(), &[&base], None), [(0, RULE_CARGO_LOCK_SOURCE, None)], "TOML 1.1");
        // A lock emptied of every package with a source the first parent or a known version held: removed, as a deletion is.
        assert_eq!(cargo_lock_findings(b"version = 4\n", &[&base], None), [(0, RULE_CARGO_LOCK_REMOVED, None)]);
        assert_eq!(cargo_lock_findings(b"version = 4\n", &[], Some(&base)), [(0, RULE_CARGO_LOCK_REMOVED, None)], "the first parent's packages count");
        let only_app = lock(&[("app", "0.1.0", None, None)]);
        assert_eq!(cargo_lock_findings(&only_app, &[&base], None), [(0, RULE_CARGO_LOCK_REMOVED, None)], "a package without a source pins nothing");
        assert!(cargo_lock_findings(b"version = 4\n", &[&only_app], None).is_empty(), "nothing with a source was held");
        let kept = lock(&[("serde", "1.0.200", crates, Some(&sum_a))]);
        assert!(cargo_lock_findings(&kept, &[&base], None).is_empty(), "one held package with its source kept");
    }

    /// Crates from elsewhere in cargo's configuration: each `[source.NAME]`
    /// key, each `[patch.REGISTRY.CRATE]` key and a top-level `paths` that no
    /// known version holds with that value, keyed, never the value; an
    /// include too; the rest of the file gives none, and bytes the toml crate
    /// does not read (TOML 1.1 that cargo reads among them) fail closed.
    /// cargo's file names fold as the Mac's disk folds them (a KELVIN SIGN
    /// `k` too).
    #[test]
    fn cargo_config_source_replacement_is_named_once_new() {
        let vendored = b"[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"vendor\"\n\n[build]\nrustflags = [\"-Dwarnings\"]\n";
        assert_eq!(
            rules_of(cargo_config_findings(vendored, &[])),
            [(2, RULE_CARGO_CONFIG_SOURCE, "source.crates-io.replace-with".to_string()), (5, RULE_CARGO_CONFIG_SOURCE, "source.vendored-sources.directory".to_string())]
        );
        assert_eq!(rules_of(cargo_config_findings(vendored, &[vendored])), []);
        let moved = b"[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+https://mirror.example.invalid/index/\"\n";
        assert_eq!(rules_of(cargo_config_findings(moved, &[vendored])).iter().map(|f| f.2.as_str()).collect::<Vec<_>>(), ["source.crates-io.replace-with", "source.mirror.registry"]);
        // A patch (inline, a table of its own, a bare version) and path overrides take crates from elsewhere too.
        let patched = b"paths = [\"../overrides/regex\"]\n\n[build]\njobs = 2\n\n[patch.crates-io]\nserde = { git = \"https://example.invalid/serde\", branch = \"main\" }\nrand = \"0.9\"\n\n[patch.crates-io.log]\npath = \"../log\"\n";
        assert_eq!(
            rules_of(cargo_config_findings(patched, &[])),
            [
                (11, RULE_CARGO_CONFIG_SOURCE, "patch.crates-io.log.path".to_string()),
                (8, RULE_CARGO_CONFIG_SOURCE, "patch.crates-io.rand".to_string()),
                (7, RULE_CARGO_CONFIG_SOURCE, "patch.crates-io.serde.branch".to_string()),
                (7, RULE_CARGO_CONFIG_SOURCE, "patch.crates-io.serde.git".to_string()),
                (1, RULE_CARGO_CONFIG_SOURCE, "paths".to_string()),
            ]
        );
        let held = b"[patch.crates-io]\nserde = { git = \"https://example.invalid/serde\", branch = \"main\" }\nrand = \"0.9\"\n[patch.crates-io.log]\npath = \"../log\"\n";
        assert_eq!(rules_of(cargo_config_findings(patched, &[held])), [(1, RULE_CARGO_CONFIG_SOURCE, "paths".to_string())], "what a known version holds is not new");
        assert!(cargo_config_findings(b"[build]\njobs = 2\n", &[]).is_empty());
        assert_eq!(cargo_config_findings(b"[source\n", &[]), [(0, RULE_CARGO_CONFIG_SOURCE, Some("source".to_string()))], "bytes the toml crate does not read fail closed");
        assert!(cargo_config_findings(b"[source\n", &[b"[source\n"]).is_empty(), "unless a known version holds the same bytes");
        let toml11 = b"source = {\n  crates-io = { replace-with = \"mirror\", },\n  mirror = { registry = \"sparse+https://mirror.example.invalid/index/\", },\n}\n";
        assert_eq!(cargo_config_findings(toml11, &[]), [(0, RULE_CARGO_CONFIG_SOURCE, Some("source".to_string()))], "TOML 1.1, which cargo reads");
        // An include is a source of its own (the file it names is read under this one's name: `include_aliases`).
        for include in [&b"include = [\"mirror.toml\"]\n"[..], b"include = [{ path = \"mirror.toml\" }]\n", b"include = \"mirror.toml\"\n"] {
            assert_eq!(rules_of(cargo_config_findings(include, &[])), [(1, RULE_CARGO_CONFIG_SOURCE, "include".to_string())], "{}", String::from_utf8_lossy(include));
            assert!(cargo_config_findings(include, &[include]).is_empty());
            assert_eq!(config_includes(include), ["mirror.toml"]);
        }
        assert_eq!(config_includes(b"include = [\"a.toml\", { path = \"b.toml\", optional = true }, 7]\n"), ["a.toml", "b.toml"]);
        assert_eq!(config_includes(b"[include]\npath = \"a.toml\"\n"), ["a.toml"], "a table alone is followed too (read more, never less)");
        assert!(config_includes(b"include = [\n").is_empty() && config_includes(b"[build]\njobs = 2\n").is_empty());
        assert!(is_cargo_config("a/.cargo/config.toml") && is_cargo_config(".Cargo/Config") && !is_cargo_config("cargo/config.toml") && !is_cargo_config("config.toml"));
        assert!(is_cargo_lock("Cargo.lock") && is_cargo_lock("sub/cargo.LOCK") && is_cargo_lock("sub/Cargo.loc\u{212a}") && !is_cargo_lock("Cargo.lock.bak") && !is_cargo_lock("Cargo.loc"));
        assert!(is_cargo_dir(".cargo") && is_cargo_dir("a/.CARGO") && !is_cargo_dir(".cargo/config.toml") && !is_cargo_dir("cargo"));
    }

    fn git_in(dir: &Path, args: &[&str]) {
        let o = std::process::Command::new("git").args(args).current_dir(dir).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    }

    /// Where a hook lies: in the git directory (the default), in the work
    /// tree (`core.hooksPath` there, or a link from the git directory into
    /// it, or a path through `..` that ends there), reached through it (a
    /// link there to a hook or a directory outside the repository: a
    /// checkout replaces the link), or outside the repository; a bare
    /// repository has no work tree. Another hook calls the review when it
    /// holds the chain line's call; a directory never does.
    /// A git configuration file the repository reads from its work tree
    /// (S9 phase 4, RVH-7) puts the hook within a checkout's reach: an
    /// `include.path` to a tracked `.gitconfig`, whether it exists yet or
    /// not, and what an `includeIf` there names, whatever its condition;
    /// one outside the repository does not.
    #[test]
    fn a_config_file_read_from_the_work_tree_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_in(&repo, &["init", "-q"]);
        let hook = repo.join(".git/hooks/pre-push");
        assert!(!hook_in_work_tree(&repo, &hook) && config_rels(&repo).is_empty(), "the git directory's own config");
        git_in(&repo, &["config", "include.path", "../.gitconfig"]);
        assert!(hook_in_work_tree(&repo, &hook), "the include's target, not there yet");
        assert_eq!(config_rels(&repo), [".gitconfig"]);
        std::fs::write(repo.join(".gitconfig"), "[includeIf \"gitdir:/nowhere/\"]\n\tpath = team/extra.cfg\n").unwrap();
        assert_eq!(config_rels(&repo), [".gitconfig", "team/extra.cfg"], "there, and what it names");
        git_in(&repo, &["config", "--unset", "include.path"]);
        git_in(&repo, &["config", "include.path", base.join("outside.cfg").to_str().unwrap()]);
        std::fs::write(base.join("outside.cfg"), "[user]\n\tname = x\n").unwrap();
        assert!(!hook_in_work_tree(&repo, &hook) && config_rels(&repo).is_empty(), "outside the repository");
    }

    #[test]
    fn a_hook_in_the_work_tree_and_a_hook_calling_the_review_are_told() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_in(&repo, &["init", "-q"]);
        assert!(!hook_in_work_tree(&repo, &repo.join(".git/hooks/pre-push")), "the default: the git directory");
        assert!(hook_in_work_tree(&repo, &repo.join(".githooks/pre-push")), "core.hooksPath in the work tree, not made yet");
        assert!(hook_in_work_tree(&repo, &repo.join(".husky/_/pre-push")));
        assert!(!hook_in_work_tree(&repo, &base.join("shared-hooks/pre-push")), "outside the repository");
        assert!(!hook_in_work_tree(&repo, &repo.join("../shared-hooks/pre-push")), "`..` leaves it");
        assert!(hook_in_work_tree(&repo, &repo.join(".git/../tools/hooks/pre-push")), "`..` back into it");
        std::fs::create_dir_all(repo.join("tools")).unwrap();
        std::fs::write(repo.join("tools/pre-push"), hook_body("/x")).unwrap();
        std::fs::create_dir_all(repo.join(".git/hooks")).unwrap();
        std::os::unix::fs::symlink(repo.join("tools/pre-push"), repo.join(".git/hooks/pre-push")).unwrap();
        assert!(hook_in_work_tree(&repo, &repo.join(".git/hooks/pre-push")), "a link from the git directory into the work tree");
        std::fs::create_dir_all(base.join("shared-hooks")).unwrap();
        std::fs::write(base.join("shared-hooks/pre-push"), hook_body("/x")).unwrap();
        std::fs::create_dir_all(repo.join(".githooks")).unwrap();
        std::os::unix::fs::symlink("../../shared-hooks/pre-push", repo.join(".githooks/pre-push")).unwrap();
        assert!(hook_in_work_tree(&repo, &repo.join(".githooks/pre-push")), "a link in the work tree to a hook outside the repository");
        std::os::unix::fs::symlink("../shared-hooks", repo.join("shared")).unwrap();
        assert!(hook_in_work_tree(&repo, &repo.join("shared/pre-push")), "below a link in the work tree to a directory outside it");
        assert!(!hook_in_work_tree(&repo, &base.join("shared-hooks/pre-push")), "still outside the repository");
        let bare = base.join("bare.git");
        git_in(&base, &["init", "-q", "--bare", bare.to_str().unwrap()]);
        assert!(!hook_in_work_tree(&bare, &bare.join("hooks/pre-push")), "a bare repository has no work tree");
        let theirs = base.join("theirs");
        std::fs::write(&theirs, format!("#!/bin/sh\nnpm test || exit 1\n{}\n", chain_line("/opt/ai-env/bin/ai-env"))).unwrap();
        assert!(calls_review(&theirs));
        let one_line = chain_line("/opt/ai-env/bin/ai-env").replace('\n', "; ");
        std::fs::write(&theirs, format!("#!/bin/sh\n{one_line}\nnpm test || exit 1\n")).unwrap();
        assert!(calls_review(&theirs), "the two lines joined by `; `");
        std::fs::write(&theirs, "#!/bin/sh\nexec ai-env box review HEAD\n").unwrap();
        assert!(!calls_review(&theirs), "another call of box review is not the hook's");
        std::fs::write(&theirs, "#!/bin/sh\n'/opt/ai-env/bin/ai-env' box review --pre-push \"$1\" \"$2\" || exit 1\n").unwrap();
        assert!(!calls_review(&theirs), "a call that reads the refs itself, unshared: another reader may have drained them");
        assert!(!calls_review(&base.join("nothing")) && !calls_review(&repo));
    }

    /// Names as the Mac's disk compares them (NFC, case, U+017F and U+212A
    /// folded into ASCII), and the pathspec that lists one entry under all of
    /// them: a `*` for each run git's ASCII-only `icase` could miss or glob
    /// would read, a pattern without a wildcard ending in `?` (never the
    /// directory's contents).
    #[test]
    fn paths_fold_as_the_macs_disk_and_their_pathspecs_name_one_entry() {
        assert!(same_path("Cargo.loc\u{212a}", "cargo.lock") && same_path(".claude/\u{17f}ettings.json", ".CLAUDE/Settings.json") && same_path("caf\u{e9}", "CAFE\u{301}"));
        assert!(!same_path("a/b", "a/b/c") && !same_path("a/b", "a-b"));
        assert!(is_above(".githooks", ".GitHooks/pre-push") && is_above("a", "a/b/c") && !is_above(".githooks/pre", ".githooks/pre-push") && !is_above("a/b", "a/b"));
        assert_eq!(dirs_above("a/b/c"), ["a", "a/b"]);
        assert!(dirs_above("c").is_empty());
        assert_eq!(folded_spec(".githooks/pre-push"), ":(icase,glob).githoo*/pre-pu*h");
        assert_eq!(folded_spec("Cargo.lock"), ":(icase,glob)Cargo.loc*");
        assert_eq!(folded_spec("caf\u{e9}/x[1]"), ":(icase,glob)caf*/x*1*");
        assert_eq!(folded_spec("bin/run"), ":(icase,glob)bin/ru?", "a wildcard, so git never lists what lies below it");
        assert!(is_hook(&[".githooks/pre-push".to_string()], ".GITHOOKS") && is_hook(&[".githooks/pre-push".to_string()], ".githooks/Pre-Push") && !is_hook(&[".githooks/pre-push".to_string()], ".githooks/pre-commit"));
    }

    /// A tree path resolved through the links on its way in one commit, one
    /// component at a time as the Mac's kernel walks it: a link to a link to
    /// a directory, `..` from a link's own directory, no link at all; a
    /// link's target named in another case than the tree's entry (the Mac's
    /// disk folds it, and a link there is followed too); `..` after the
    /// link before it (taken on what that link reached, never lexically);
    /// chains of 9 and 32 links (macOS follows 32); the rest after a missing
    /// entry taken lexically, that entry passed when the rest leaves it. A
    /// link that leaves the tree (an absolute target, one above the top
    /// level), a rest leaving it, a loop and a 33rd link resolve to nothing.
    /// A link's own entry is in the tree, nothing below it is.
    #[test]
    fn links_resolve_within_the_tree_and_never_out_of_it() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = std::fs::canonicalize(tmp.path()).unwrap().join("repo");
        let file = |at: &str| {
            std::fs::create_dir_all(repo.join(at).parent().unwrap()).unwrap();
            std::fs::write(repo.join(at), "{}\n").unwrap();
        };
        file("real/cfg/settings.json");
        let link = |target: &str, at: &str| {
            std::fs::create_dir_all(repo.join(at).parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, repo.join(at)).unwrap();
        };
        link("cfg-link", ".claude");
        link("real/cfg", "cfg-link");
        link("../../locks.toml", "sub/x/Cargo.lock");
        link("/etc", "abs");
        link("../outside", "up");
        link("loop", "loop");
        // `.claude -> CFG` where the tree holds the link `cfg`.
        file("fold/real/settings.json");
        link("CFG", "fold/.claude");
        link("real", "fold/cfg");
        // `a -> x/y`, so `a/..` is `x`, not the directory holding `a`.
        file("dots/x/y/keep");
        file("dots/x/settings.json");
        file("dots/settings.json");
        link("x/y", "dots/a");
        link("a/..", "dots/.claude");
        for n in [9, 32, 33] {
            file(&format!("chain{n}/real/settings.json"));
            for i in 0..n {
                let target = if i + 1 == n { "real".to_string() } else { format!("l{}", i + 1) };
                link(&target, &format!("chain{n}/l{i}"));
            }
        }
        file("gone/cfg/settings.json");
        link("nothing/../cfg", "gone/.claude");
        link("nothing/../../../x", "gone/out");
        git_in(&repo, &["init", "-q"]);
        git_in(&repo, &["add", "-A"]);
        git_in(&repo, &["-c", "user.name=ai-env fixture", "-c", "user.email=fixture@ai-env.invalid", "commit", "-q", "-m", "links"]);
        let git = GitRun::mac(&repo);
        let r = |p: &str| resolve_in_tree(&git, "HEAD", p).unwrap();
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_string()).collect::<Vec<String>>();
        assert_eq!(r(".claude/settings.json"), Some((s(&[".claude", "cfg-link"]), "real/cfg/settings.json".to_string())));
        assert_eq!(r("sub/x/Cargo.lock"), Some((s(&["sub/x/Cargo.lock"]), "locks.toml".to_string())), "`..` from the link's own directory");
        assert_eq!(r("real/cfg/settings.json"), Some((Vec::new(), "real/cfg/settings.json".to_string())), "no link on the way");
        assert_eq!(r("no/such/file"), Some((Vec::new(), "no/such/file".to_string())));
        assert_eq!(r("abs/hosts"), None, "an absolute target leaves the tree");
        assert_eq!(r("up/x"), None, "above the top level");
        assert_eq!(r("loop"), None, "a loop runs out of hops");
        assert_eq!(r("fold/.claude/settings.json"), Some((s(&["fold/.claude", "fold/cfg"]), "fold/real/settings.json".to_string())), "the Mac's disk folds the target's case, and the link there is followed");
        assert_eq!(r("dots/.claude/settings.json"), Some((s(&["dots/.claude", "dots/a"]), "dots/x/settings.json".to_string())), "`..` after the link before it");
        let chain = |n: usize| (0..n).map(|i| format!("chain{n}/l{i}")).collect::<Vec<String>>();
        assert_eq!(r("chain9/l0/settings.json"), Some((chain(9), "chain9/real/settings.json".to_string())));
        assert_eq!(r("chain32/l0/settings.json"), Some((chain(32), "chain32/real/settings.json".to_string())), "macOS follows 32 links");
        assert_eq!(r("chain33/l0/settings.json"), None, "and no more");
        assert_eq!(r("gone/.claude/settings.json"), Some((s(&["gone/.claude", "gone/nothing"]), "gone/cfg/settings.json".to_string())), "a missing entry's rest, taken lexically");
        assert_eq!(r("gone/out/x"), None, "a rest that leaves the tree");
        assert_eq!(tree_entry(&git, "HEAD", ".claude").unwrap().map(|e| e.0), Some("120000".to_string()));
        assert_eq!(tree_entry(&git, "HEAD", "real").unwrap().map(|e| e.0), Some("040000".to_string()));
        assert_eq!(tree_entry(&git, "HEAD", "real/cfg/settings.json").unwrap().map(|e| e.0), Some("100644".to_string()));
        assert_eq!(tree_entry(&git, "HEAD", ".claude/settings.json").unwrap(), None, "below a link: not in the tree");
    }

    /// The pre-push hook's paths where git reaches it through the work tree:
    /// none from the git directory or outside the repository; as git names
    /// it (`core.hooksPath` relative, or through `..`), whatever its links
    /// reach (a hook or a directory outside the repository, the git
    /// directory); each link this disk passes in the work tree, and where it
    /// ends there (a dangling link's target too).
    #[test]
    fn the_hook_is_watched_where_git_runs_it_from_the_work_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_in(&repo, &["init", "-q"]);
        // The repository's own setting first: the plain git reads this user's global config too.
        git_in(&repo, &["config", "core.hooksPath", ".git/hooks"]);
        assert!(hook_rels(&repo).is_empty(), "the git directory");
        git_in(&repo, &["config", "core.hooksPath", ".githooks"]);
        assert_eq!(hook_rels(&repo), [".githooks/pre-push"]);
        git_in(&repo, &["config", "core.hooksPath", ".git/../tools/hooks"]);
        assert_eq!(hook_rels(&repo), ["tools/hooks/pre-push"]);
        std::fs::create_dir_all(repo.join("tools/hooks")).unwrap();
        std::os::unix::fs::symlink("tools/hooks", repo.join(".githooks")).unwrap();
        git_in(&repo, &["config", "core.hooksPath", ".githooks"]);
        assert_eq!(hook_rels(&repo), [".githooks/pre-push", "tools/hooks/pre-push"], "as git names it, then on this disk");
        std::fs::create_dir_all(base.join("shared-hooks")).unwrap();
        std::fs::write(base.join("shared-hooks/pre-push"), "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::remove_file(repo.join(".githooks")).unwrap();
        std::fs::create_dir_all(repo.join(".githooks")).unwrap();
        std::os::unix::fs::symlink("../../shared-hooks/pre-push", repo.join(".githooks/pre-push")).unwrap();
        assert_eq!(hook_rels(&repo), [".githooks/pre-push"], "a link at the hook's path to a hook outside the repository");
        std::fs::remove_dir_all(repo.join(".githooks")).unwrap();
        std::os::unix::fs::symlink("../shared-hooks", repo.join(".githooks")).unwrap();
        assert_eq!(hook_rels(&repo), [".githooks/pre-push"], "a link on its way to a directory outside the repository");
        std::fs::remove_file(repo.join(".githooks")).unwrap();
        std::os::unix::fs::symlink(".git/hooks", repo.join(".githooks")).unwrap();
        assert_eq!(hook_rels(&repo), [".githooks/pre-push"], "a link into the git directory: the link's way only");
        std::fs::remove_file(repo.join(".githooks")).unwrap();
        std::os::unix::fs::symlink("a", repo.join(".githooks")).unwrap();
        std::os::unix::fs::symlink("tools/hooks", repo.join("a")).unwrap();
        assert_eq!(hook_rels(&repo), [".githooks/pre-push", "a", "tools/hooks/pre-push"], "each link passed in the work tree");
        std::fs::remove_file(repo.join(".githooks")).unwrap();
        std::fs::create_dir_all(repo.join(".githooks")).unwrap();
        std::os::unix::fs::symlink("../nowhere/pre-push", repo.join(".githooks/pre-push")).unwrap();
        assert_eq!(hook_rels(&repo), [".githooks/pre-push", "nowhere/pre-push"], "a dangling link's target: a checkout can make it");
        git_in(&repo, &["config", "core.hooksPath", base.join("shared-hooks").to_str().unwrap()]);
        assert!(hook_rels(&repo).is_empty(), "outside the repository");
    }
}

#[cfg(test)]
mod hook_state_tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let o = Command::new("git").args(args).current_dir(dir).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    }

    /// Where git runs the hook (`.git/hooks`, or `core.hooksPath`), and what
    /// is there: the mark (on its own line, in the first 4 KiB), another
    /// file, a directory, nothing; a directory that is no repository is unknown.
    #[test]
    fn the_hook_state_reads_the_hook_git_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = std::fs::canonicalize(tmp.path()).unwrap().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(matches!(hook_state(&repo), HookState::Unknown(why) if why.contains("is not a git repository")));
        git(&repo, &["init", "-q", "-b", "main"]);
        // The repository's own setting first: the plain git reads this user's global config too, and a global
        // core.hooksPath would otherwise decide.
        git(&repo, &["config", "core.hooksPath", ".git/hooks"]);
        let default = repo.join(".git/hooks/pre-push");
        assert_eq!(hook_state(&repo), HookState::Missing(default.clone()));
        std::fs::create_dir_all(default.parent().unwrap()).unwrap();
        std::fs::write(&default, format!("#!/bin/sh\n{PRE_PUSH_MARK}\nexec true\n")).unwrap();
        assert_eq!(hook_state(&repo), HookState::Installed(default.clone()));
        std::fs::write(&default, "#!/bin/sh\n# someone's own hook\nexit 0\n").unwrap();
        assert_eq!(hook_state(&repo), HookState::Foreign(default.clone()));
        std::fs::write(&default, format!("#!/bin/sh\n{}\n{PRE_PUSH_MARK}\n", "#".repeat(5000))).unwrap();
        assert_eq!(hook_state(&repo), HookState::Foreign(default.clone()), "the mark past the first 4 KiB does not count");
        git(&repo, &["config", "core.hooksPath", "githooks"]);
        let custom = repo.join("githooks/pre-push");
        assert_eq!(hook_state(&repo), HookState::Missing(custom.clone()), "core.hooksPath is honoured");
        std::fs::create_dir_all(&custom).unwrap();
        assert_eq!(hook_state(&repo), HookState::Foreign(custom), "a directory is no hook of ours");
    }
}
