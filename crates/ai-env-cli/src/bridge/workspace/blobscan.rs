//! The scans of everything a seed or a code-out carries (S8 §5): every object
//! of the outgoing pack through the tripwires (commit messages too), with a
//! clean-object cache under `state/scan-cache/` keyed by the rules' digest;
//! D8's repo mode on every `.claude/settings.json` and
//! `.claude/settings.local.json` the VM checks out; L9's plaintext dotenv rule
//! on carried untracked files. A finding names the location, the object, the
//! line, the rule and the key, never a value. Built in S8 wave 1 (W4).
//!
//! What is scanned is what is sent: the objects come from the same listing
//! `pack-objects` packs (`pack::ObjectList`), blobs by their bytes, commits
//! whole (headers and message), and every path name: each object's path as
//! the listing gives it (its first), and every entry name of every listed
//! tree (an object at a second path is listed once, so only its tree holds
//! that name). A path that trips a rule is never shown: a finding names it
//! `a path name`. A blob larger than `[seed].max_blob_mib` is a finding of its own
//! (`blob-too-large`, its text naming that key), never read. Only clean
//! verdicts are cached, by object id, and only once a scan ran to its end;
//! the cache's file name is the rules' digest, so a changed tripwire list
//! starts a new cache.
//!
//! D8's names are compared as the Mac's disk compares them (APFS folds case):
//! a code-out's `.CLAUDE/Settings.Local.json` is the settings file the Mac's
//! claude reads after a merge, so the repo mode reads it; harmless on a seed,
//! whose VM compares names exactly. A `.claude` that is a symlink is a
//! finding wherever it points (the settings read through it are elsewhere).
//!
//! S10 (F4): the code-out's import scans every fetched ref's new objects as
//! one ([`scan_listed`], which leaves the cache's save to its caller: once
//! per import) and reads D8's settings files of every tip from one walk of
//! the trees ([`settings_of_trees`]: each tree read once, level by level),
//! with the findings, and their order, that [`scan_settings_within`], the
//! per-ref twin, gives per tree. Phase 4 bounds that walk and what it makes:
//! its nodes and its paths' bytes, a settings blob over the cap (never read:
//! `blob-too-large`), and the settings findings a tip keeps (the twin bounds
//! the last two alike).
use super::pack::Listed;
use super::{git_failed, workspace_cfg, WorkspaceRef};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::errors::BridgeError;
use crate::bridge::registry::ensure_private_dir;
use crate::bridge::scan::{load_lists, settings_findings_mode, Rules, SettingsMode};
use crate::gitrun::GitRun;
use crate::wire::redact::scrub;
use crate::wire::workspace::ObjectFormat;
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

/// The settings files D8 reads, as the last component below a `.claude/` directory.
pub const SETTINGS_NAMES: [&str; 2] = ["settings.json", "settings.local.json"];
/// L9: suffixes that make a dotenv-named file a template (exempt).
pub const DOTENV_EXEMPT: [&str; 4] = [".example", ".sample", ".template", ".dist"];
/// L9: how many leading lines may carry the `AI_ENV=1` marker (the pre-commit guard's `head -32`).
pub const MARKER_LINES: usize = 32;
/// The most lines a finding refusal holds ([`finding_lines`]): up to this
/// many findings, one line each; past it, the first `FINDINGS_MAX - 1` and a
/// last line counting the others (`and N more finding(s)`).
pub const FINDINGS_MAX: usize = 20;
/// The most object ids one rule set's cache file holds; past it the file starts over with the last scan's.
pub const CACHE_MAX: usize = 500_000;
/// How many hex digits of an object id a finding names.
pub const ID_SHOWN: usize = 12;
/// What a finding shows for a path that itself trips a rule.
pub const PATH_NAME: &str = "a path name";
/// The rule of a blob over `[seed].max_blob_mib`, never read; its finding's
/// text names that key ([`Finding::text`]).
pub const BLOB_TOO_LARGE: &str = "blob-too-large";
/// D8's rule for a link where the repo mode would read a settings file: one
/// at a settings file's name, or a `.claude` directory that is one.
pub const SETTINGS_SYMLINK: &str = "settings-symlink";
/// S10 phase 4 (F4-WALK-1): the most kept nodes one walk of the settings
/// visits ([`each_setting`]: a subtree entered, an entry reached, one it
/// skips among them). Past it the import is refused: 41 trees whose every
/// level names the one below twice route 2^40 paths to one settings file.
pub const SETTINGS_WALK_MAX: usize = 1 << 16;
/// ... and the most bytes of paths one walk builds: each subtree's name it
/// enters, each whole path it hands on (300 levels of 3000-byte names over
/// a `.claude` of names that fold to `settings.json` would build gigabytes
/// from a pack of kilobytes).
pub const SETTINGS_WALK_BYTES: usize = 1 << 22;
/// S10 phase 4 (F4-WALK-1): the settings findings one tip of the import
/// keeps (one label of [`scan_settings_within`]): the first this many, and
/// past them the first of each rule not among them, so every rule still
/// reaches the report and the audit. Nothing shows or keeps more of them
/// ([`finding_lines`], `rows::FINDINGS_KEPT`), while a blob's findings
/// copied to every path that names it would grow without bound.
pub const SETTINGS_FINDINGS_MAX: usize = FINDINGS_MAX;

/// The rules one scan runs with (`Debug` names the rule ids only).
#[derive(Debug)]
pub struct ScanSet {
    pub rules: Rules,
    /// [`Rules::digest`]: the clean cache's key.
    pub digest: String,
    /// D8's repo mode applies (no `trust_repo_settings` for the workspace).
    pub repo_settings: bool,
}

impl ScanSet {
    /// The scan of `ws`: the tripwires `ai-env infra scan` reads (the
    /// built-ins, plus `[review].tripwires` when that file exists), and D8's
    /// repo mode unless the workspace's `[[workspace]]` sets
    /// `trust_repo_settings` (the tripwires apply whatever it says). A bad
    /// tripwires file is exit 1 naming its line.
    pub fn load(paths: &Paths, cfg: &BridgeConfig, ws: &WorkspaceRef) -> Result<ScanSet, BridgeError> {
        let (rules, _) = load_lists(Some((paths, &cfg.review)), None, None, false).map_err(BridgeError::Config)?;
        let digest = rules.digest();
        let repo_settings = !workspace_cfg(cfg, ws).is_some_and(|w| w.trust_repo_settings);
        Ok(ScanSet { rules, digest, repo_settings })
    }

    /// `box review`'s scan (S9 §3), and the settings policy it judges allow
    /// entries by (`scan::allow_beyond_policy`): the tripwires
    /// [`ScanSet::load`] reads (so the clean cache is the seeds' and the
    /// code-outs'), the policy `[review].settings_policy` names (empty when
    /// that file does not exist: every new allow entry is then beyond it),
    /// and D8's repo mode unless the deepest `[[workspace]]` whose path holds
    /// `dir`, else `root`, sets `trust_repo_settings`. A review needs no
    /// workspace: a repository outside the roots, or no bridge.toml at all
    /// (`cfg` `None`: the empty `[review]`), is reviewed with the repo mode
    /// on. A bad tripwires or policy file is exit 1 naming its line.
    pub fn for_review(paths: &Paths, cfg: Option<&BridgeConfig>, dir: &std::path::Path, root: &std::path::Path) -> Result<(ScanSet, Vec<String>), BridgeError> {
        let review = cfg.map(|c| c.review.clone()).unwrap_or_default();
        let (rules, policy) = load_lists(Some((paths, &review)), None, None, true).map_err(BridgeError::Config)?;
        let digest = rules.digest();
        let deepest = |cfg: &BridgeConfig, p: &std::path::Path| {
            cfg.workspace_overrides
                .iter()
                .filter_map(|w| std::fs::canonicalize(&w.path).ok().map(|c| (c, w.trust_repo_settings)))
                .filter(|(c, _)| p.starts_with(c))
                .max_by_key(|(c, _)| c.components().count())
                .map(|(_, trust)| trust)
        };
        let trusted = cfg.and_then(|c| deepest(c, dir).or_else(|| deepest(c, root))).unwrap_or(false);
        Ok((ScanSet { rules, digest, repo_settings: !trusted }, policy))
    }
}

/// One finding: where (`HEAD:cfg/prod.yaml`, `wip:.env`, `index:a.txt`,
/// `commit 3f2a91c0e4b1`, `refs/remotes/box/dev:x`), the object's id prefix,
/// the line (0: the object as a whole), the rule and the JSON key, never a value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    pub line: usize,
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl Finding {
    /// The one line a refusal shows: `HEAD:cfg/prod.yaml (blob 3f2a91c0e4b1) line 3: rule aws-access-key-id`,
    /// `wip:.claude/settings.local.json (blob …) line 5: rule broad-allow, key permissions.allow[2]`,
    /// `HEAD:assets/model.bin (blob …): rule blob-too-large (over [seed].max_blob_mib)`.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = shown(&self.location);
        if let Some(o) = &self.object {
            out.push_str(&format!(" (blob {o})"));
        }
        if self.line > 0 {
            out.push_str(&format!(" line {}", self.line));
        }
        out.push_str(&format!(": rule {}", self.rule));
        if self.rule == BLOB_TOO_LARGE {
            // The cap it is over, which `box seed` and Cursor's line then point at.
            out.push_str(" (over [seed].max_blob_mib)");
        }
        if let Some(k) = self.key.as_deref().filter(|k| !k.is_empty()) {
            out.push_str(&format!(", key {}", shown(k)));
        }
        out
    }
}

/// A location or key as a finding shows it: scrubbed, control characters as `?`.
fn shown(text: &str) -> String {
    scrub(text).chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// `id`'s first [`ID_SHOWN`] digits.
fn short(id: &str) -> String {
    id.chars().take(ID_SHOWN).collect()
}

/// What one scan read and found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    /// Objects scanned, of them found clean in the cache, and the bytes read.
    pub objects: u64,
    pub cached: u64,
    pub bytes: u64,
    /// Settings files the repo mode read.
    pub settings_files: u32,
    pub findings: Vec<Finding>,
    /// What was not scanned and why (a gitlink: a submodule is not carried).
    pub notes: Vec<String>,
}

impl ScanReport {
    /// `other`'s counts and findings added to this one (findings deduplicated, in order).
    pub fn merge(&mut self, other: ScanReport) {
        self.objects += other.objects;
        self.cached += other.cached;
        self.bytes += other.bytes;
        self.settings_files += other.settings_files;
        for f in other.findings {
            if !self.findings.contains(&f) {
                self.findings.push(f);
            }
        }
        for n in other.notes {
            if !self.notes.contains(&n) {
                self.notes.push(n);
            }
        }
    }

    /// The refusal the findings make: `WorkspaceRefused { finding }` (exit
    /// 9), its first line the first finding, at most [`FINDINGS_MAX`] lines
    /// ([`finding_lines`]: past that many findings, the last line counts the
    /// rest); `None` when clean.
    #[must_use]
    pub fn refusal(&self) -> Option<BridgeError> {
        if self.findings.is_empty() {
            return None;
        }
        Some(BridgeError::WorkspaceRefused { code: super::code::FINDING, message: finding_lines(&self.findings) })
    }
}

/// [`ScanReport::refusal`]'s message (and `box review`'s): one line per
/// finding while they are at most [`FINDINGS_MAX`]; past that, the first
/// `FINDINGS_MAX - 1` and `and N more finding(s)`, so never more than
/// [`FINDINGS_MAX`] lines.
#[must_use]
pub fn finding_lines(findings: &[Finding]) -> String {
    let mut lines: Vec<String> = Vec::new();
    if findings.len() <= FINDINGS_MAX {
        lines.extend(findings.iter().map(Finding::text));
    } else {
        lines.extend(findings[..FINDINGS_MAX - 1].iter().map(Finding::text));
        lines.push(format!("and {} more finding(s)", findings.len() - (FINDINGS_MAX - 1)));
    }
    lines.join("\n")
}

/// Object ids a complete scan under one rule set found clean
/// (`state/scan-cache/<digest's first 16>-<format>.ids`, 0600, one id per
/// line). Missing or unreadable: empty (the scan reads everything).
#[derive(Debug)]
pub struct CleanCache {
    path: PathBuf,
    known: HashSet<String>,
    added: Vec<String>,
}

impl CleanCache {
    /// The cache of `digest` for `format`'s ids.
    #[must_use]
    pub fn open(paths: &Paths, digest: &str, format: ObjectFormat) -> CleanCache {
        let name: String = digest.chars().take(16).collect();
        let path = paths.scan_cache().join(format!("{name}-{}.ids", format.name()));
        let known = crate::bridge::registry::read_regular_file(&path)
            .ok()
            .flatten()
            .map(|text| text.lines().filter(|l| format.is_id(l)).map(str::to_string).collect())
            .unwrap_or_default();
        CleanCache { path, known, added: Vec::new() }
    }

    /// Was `id` found clean under these rules?
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.known.contains(id)
    }

    /// How many ids it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.known.len()
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }

    /// Record `id` clean (kept once [`CleanCache::save`] runs).
    pub fn insert(&mut self, id: &str) {
        if self.known.insert(id.to_string()) {
            self.added.push(id.to_string());
        }
    }

    /// Write what was added (atomically, 0600 in a 0700 directory), after a
    /// scan that ran to its end; a cache over [`CACHE_MAX`] ids starts over.
    pub fn save(&mut self) -> Result<(), BridgeError> {
        if self.added.is_empty() {
            return Ok(());
        }
        ensure_private_dir(&self.path.parent().map(PathBuf::from).unwrap_or_default())?;
        let ids: Vec<&String> = if self.known.len() > CACHE_MAX { self.added.iter().collect() } else { self.known.iter().collect() };
        let mut sorted: Vec<&String> = ids;
        sorted.sort_unstable();
        let mut text = String::with_capacity(sorted.len() * 41);
        for id in sorted {
            text.push_str(id);
            text.push('\n');
        }
        crate::bridge::infra::write_atomic_mode(&self.path, text.as_bytes(), 0o600)?;
        self.added.clear();
        Ok(())
    }
}

/// One entry of a tree (`ls-tree -r`): its mode, id and path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: String,
    pub id: String,
    pub path: String,
}

/// Every entry of `tree` (`ls-tree -r -z --full-tree`), in tree order.
pub fn tree_entries(git: &GitRun, tree: &str) -> Result<Vec<TreeEntry>, BridgeError> {
    let out = git.output(["ls-tree", "-r", "-z", "--full-tree", tree]).map_err(git_failed("git ls-tree"))?;
    let mut entries = Vec::new();
    for raw in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let text = String::from_utf8_lossy(raw);
        let Some((head, path)) = text.split_once('\t') else { continue };
        let mut fields = head.split(' ');
        let (Some(mode), Some(_kind), Some(id)) = (fields.next(), fields.next(), fields.next()) else { continue };
        entries.push(TreeEntry { mode: mode.to_string(), id: id.to_string(), path: path.to_string() });
    }
    Ok(entries)
}

/// Whether `name` is `want` (lowercase ASCII) as the Mac's disk compares
/// names: APFS folds case, ASCII's and the two letters outside it that fold
/// into it (U+017F LONG S as `s`, U+212A KELVIN SIGN as `k`). `box review`
/// names cargo's files by it too.
pub(crate) fn folds_to(name: &str, want: &str) -> bool {
    let fold = |c: char| match c {
        '\u{17f}' => 's',
        '\u{212a}' => 'k',
        c => c.to_ascii_lowercase(),
    };
    name.chars().map(fold).eq(want.chars())
}

/// The settings file D8 reads at `path`, by its own name (`settings.json`,
/// `settings.local.json`): one below a `.claude` directory at any depth, both
/// names compared as the Mac's disk compares them (`folds_to`).
#[must_use]
pub fn settings_name(path: &str) -> Option<&'static str> {
    let mut parts = path.rsplit('/');
    let (Some(name), Some(dir)) = (parts.next(), parts.next()) else { return None };
    if !folds_to(dir, ".claude") {
        return None;
    }
    SETTINGS_NAMES.into_iter().find(|s| folds_to(name, s))
}

/// Is `path` a settings file D8 reads ([`settings_name`]).
#[must_use]
pub fn is_settings_path(path: &str) -> bool {
    settings_name(path).is_some()
}

/// Is `path`'s last component a `.claude` directory's name (compared as the Mac's disk does).
#[must_use]
pub fn is_claude_dir(path: &str) -> bool {
    folds_to(path.rsplit('/').next().unwrap_or(path), ".claude")
}

/// L9: is `name` (a file name) a dotenv's: `.env`, `.env.*` or `*.env`, but
/// not a template (`*.example`, `*.sample`, `*.template`, `*.dist`).
#[must_use]
pub fn is_dotenv_name(name: &str) -> bool {
    if DOTENV_EXEMPT.iter().any(|s| name.ends_with(s)) {
        return false;
    }
    name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
}

/// L9: does `bytes` carry the ai-env container marker (`AI_ENV=1` at the
/// start of one of its first [`MARKER_LINES`] lines, as the pre-commit guard reads it)?
#[must_use]
pub fn has_marker(bytes: &[u8]) -> bool {
    bytes.split(|b| *b == b'\n').take(MARKER_LINES).any(|l| l.starts_with(b"AI_ENV=1"))
}

/// One object's type and size, as `cat-file --batch-check` saw it.
struct Checked {
    kind: String,
    size: u64,
}

/// `cat-file --batch-check` of `ids`, in order (`missing` objects error).
fn check(git: &GitRun, ids: &[String]) -> Result<Vec<Checked>, BridgeError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = ids.join("\n");
    input.push('\n');
    let out = git.output_stdin(["cat-file", "--batch-check=%(objecttype) %(objectsize)"], input.as_bytes()).map_err(git_failed("git cat-file --batch-check"))?;
    let text = String::from_utf8_lossy(&out);
    let checked: Vec<Checked> = text
        .lines()
        .map(|l| {
            let (kind, size) = l.split_once(' ').unwrap_or((l, "0"));
            Checked { kind: kind.to_string(), size: size.trim().parse().unwrap_or(0) }
        })
        .collect();
    if checked.len() != ids.len() || checked.iter().any(|c| c.kind.is_empty() || c.kind.ends_with("missing")) {
        return Err(BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: "git cat-file could not read an object the scan lists".into() });
    }
    Ok(checked)
}

/// Read each of `ids` whole through one `cat-file --batch`, calling `seen`
/// with its id and bytes, in order.
pub(crate) fn read_objects(git: &GitRun, ids: &[String], mut seen: impl FnMut(&str, &[u8])) -> Result<(), BridgeError> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut child = git.spawn_piped(["cat-file", "--batch"]).map_err(git_failed("git cat-file --batch"))?;
    let feeder = child.take_stdin().map(|mut stdin| {
        let mut input = ids.join("\n");
        input.push('\n');
        // A cat-file that stopped reading fails this write: its end says why.
        std::thread::spawn(move || {
            let _ = stdin.write_all(input.as_bytes());
        })
    });
    let result = (|| -> Result<(), BridgeError> {
        let out = child.take_stdout().ok_or_else(|| BridgeError::Io(std::io::Error::other("git cat-file has no stdout")))?;
        let mut out = BufReader::new(out);
        let mut head = String::new();
        let mut body = Vec::new();
        for id in ids {
            head.clear();
            out.read_line(&mut head)?;
            let mut fields = head.trim_end().split(' ');
            let (Some(got), Some(_kind), Some(size)) = (fields.next(), fields.next(), fields.next()) else {
                return Err(BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: format!("git cat-file could not read {}", short(id)) });
            };
            let size: usize = size.parse().map_err(|_| BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: "git cat-file printed a bad size".into() })?;
            if got != id {
                return Err(BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: format!("git cat-file answered another object than {}", short(id)) });
            }
            body.clear();
            body.resize(size, 0);
            out.read_exact(&mut body)?;
            let mut nl = [0u8; 1];
            out.read_exact(&mut nl)?;
            seen(id, &body);
        }
        Ok(())
    })();
    if result.is_err() {
        drop(child);
        if let Some(f) = feeder {
            let _ = f.join();
        }
        return result;
    }
    if let Some(f) = feeder {
        let _ = f.join();
    }
    child.finish().map_err(git_failed("git cat-file --batch"))?;
    result
}

/// `path` as a finding shows it: [`PATH_NAME`] when the path itself trips a
/// rule (a custom tripwire's match is never scrubbed), else the path.
pub(crate) fn shown_path(set: &ScanSet, path: &str) -> String {
    if set.rules.scan_bytes(path.as_bytes()).is_empty() {
        path.to_string()
    } else {
        PATH_NAME.to_string()
    }
}

/// Where a finding of an object of `list` is: the first of `labels`
/// (`(label, tree)`, `HEAD`, `wip`, `index`, a box ref) whose tree holds the
/// blob at the path it was listed at (`label:path`), else the listed commit
/// that brought it (`commit <id12>:path`: the last listed of those whose
/// tree holds it at that path, as `rev-list` lists the newest first; with
/// none, the newest that adds or removes it), else its path; the path as
/// `shown` ([`shown_path`]).
fn locate(git: &GitRun, labels: &[(String, String)], commits: &[String], id: &str, path: &str, shown: &str) -> String {
    for (label, tree) in labels {
        let at = git.output(["rev-parse", "--verify", "--quiet", &format!("{tree}:{path}")]).ok().map(|o| String::from_utf8_lossy(&o).trim().to_string());
        if at.as_deref() == Some(id) {
            return format!("{label}:{shown}");
        }
    }
    if !commits.is_empty() {
        // What each listed commit holds there, one line each (a newline in the path breaks the count: unused).
        let input: String = commits.iter().map(|c| format!("{c}:{path}\n")).collect();
        if let Ok(out) = git.output_stdin(["cat-file", "--batch-check=%(objectname)"], input.as_bytes()) {
            let text = String::from_utf8_lossy(&out);
            let held: Vec<&str> = text.lines().collect();
            if held.len() == commits.len() {
                if let Some((c, _)) = commits.iter().zip(held).rev().find(|(_, at)| *at == id) {
                    return format!("commit {}:{shown}", short(c));
                }
            }
        }
        let mut args = vec!["log".to_string(), "--no-walk".into(), "--format=%H".into(), format!("--find-object={id}")];
        args.extend(commits.iter().cloned());
        if let Ok(out) = git.output(&args) {
            if let Some(c) = String::from_utf8_lossy(&out).lines().next().filter(|c| !c.is_empty()) {
                return format!("commit {}:{shown}", short(c));
            }
        }
    }
    shown.to_string()
}

/// The entry names a tree object's bytes hold (`<mode> <name>\0<id>` each,
/// the id `raw` bytes); a malformed tail is left out.
fn tree_names(bytes: &[u8], raw: usize) -> Vec<&[u8]> {
    let mut names = Vec::new();
    let mut rest = bytes;
    while let Some(sp) = rest.iter().position(|b| *b == b' ') {
        let entry = &rest[sp + 1..];
        let Some(nul) = entry.iter().position(|b| *b == 0) else { break };
        names.push(&entry[..nul]);
        rest = entry.get(nul + 1 + raw..).unwrap_or_default();
    }
    names
}

/// The tripwires over every object of `list` (read in `git`'s repository):
/// blobs by their bytes (one over `max_blob` is `blob-too-large`, never
/// read; one found clean before under these rules is not read again),
/// commits whole, every path name: each object's listed path, and every
/// entry name of each listed tree (a name tripping a rule is [`PATH_NAME`],
/// with the tree's id when only a tree holds it). `labels` and the listed
/// commits name a finding's place ([`Finding::location`]). Clean objects go
/// into `cache`, which is saved once the scan ran to its end.
pub fn scan_objects(git: &GitRun, list: &[Listed], set: &ScanSet, cache: &mut CleanCache, max_blob: u64, labels: &[(String, String)]) -> Result<ScanReport, BridgeError> {
    let scanned = scan_listed(git, list, set, cache, max_blob, Some(labels))?;
    if let Err(e) = cache.save() {
        tracing::warn!("scan: the clean-object cache was not written: {e}");
    }
    Ok(scanned.report)
}

/// What [`scan_listed`] read and found: its report, and the ids it found
/// dirty (a hit in a blob's or a commit's bytes or in a tree's entry names,
/// or a blob over the cap), which no cache ever holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scanned {
    pub report: ScanReport,
    pub dirty: BTreeSet<String>,
}

/// [`scan_objects`] without saving `cache` (S10 F4: a caller that runs
/// several scans saves it once, after the last ran to its end), with the ids
/// it found dirty. `labels` `None`: no finding's place is looked up (no git
/// run for it): a finding names its listed path as [`shown_path`] shows it,
/// else `an object`, which serves where only whether there is one counts
/// (the import's one scan of every fetched ref's objects at once).
pub fn scan_listed(git: &GitRun, list: &[Listed], set: &ScanSet, cache: &mut CleanCache, max_blob: u64, labels: Option<&[(String, String)]>) -> Result<Scanned, BridgeError> {
    let mut report = ScanReport::default();
    let ids: Vec<String> = list.iter().map(|o| o.id.clone()).collect();
    let checked = check(git, &ids)?;
    let commits: Vec<String> = list.iter().zip(&checked).filter(|(_, c)| c.kind == "commit").map(|(o, _)| o.id.clone()).collect();
    let trees: HashSet<&str> = list.iter().zip(&checked).filter(|(_, c)| c.kind == "tree").map(|(o, _)| o.id.as_str()).collect();
    let mut to_read: Vec<String> = Vec::new();
    let mut path_of: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut found: Vec<(String, Option<String>, usize, String)> = Vec::new();
    // The names (a listed path's last component) whose path tripped a rule, with the rule: shown once.
    let mut named: HashSet<(Vec<u8>, String)> = HashSet::new();
    for (o, c) in list.iter().zip(&checked) {
        report.objects += 1;
        // The path names a tree records: never shown when they trip a rule.
        if let Some(p) = o.path.as_deref().filter(|p| !p.is_empty()) {
            if let Some((_, rule)) = set.rules.scan_bytes(p.as_bytes()).into_iter().next() {
                named.insert((p.rsplit('/').next().unwrap_or(p).as_bytes().to_vec(), rule.clone()));
                report.findings.push(Finding { location: PATH_NAME.into(), object: Some(short(&o.id)), line: 0, rule, key: None });
            }
        }
        match c.kind.as_str() {
            "blob" if c.size > max_blob => {
                found.push((o.id.clone(), o.path.clone(), 0, BLOB_TOO_LARGE.into()));
            }
            _ if cache.contains(&o.id) => report.cached += 1,
            _ => {
                if let Some(p) = &o.path {
                    path_of.insert(o.id.clone(), p.clone());
                }
                to_read.push(o.id.clone());
            }
        }
    }
    let mut dirty: BTreeSet<String> = BTreeSet::new();
    let mut commit_findings: Vec<Finding> = Vec::new();
    let mut clean_names: HashSet<Vec<u8>> = HashSet::new();
    read_objects(git, &to_read, |id, bytes| {
        report.bytes += bytes.len() as u64;
        if trees.contains(id) {
            // Every name the tree records: `rev-list` lists an object at its first path only.
            for name in tree_names(bytes, id.len() / 2) {
                if clean_names.contains(name) {
                    continue;
                }
                let Some((_, rule)) = set.rules.scan_bytes(name).into_iter().next() else {
                    clean_names.insert(name.to_vec());
                    continue;
                };
                dirty.insert(id.to_string());
                let f = Finding { location: format!("{PATH_NAME} (tree {})", short(id)), object: None, line: 0, rule: rule.clone(), key: None };
                if named.insert((name.to_vec(), rule)) && !report.findings.contains(&f) {
                    report.findings.push(f);
                }
            }
            return;
        }
        let hits = set.rules.scan_bytes(bytes);
        if hits.is_empty() {
            return;
        }
        dirty.insert(id.to_string());
        for (line, rule) in hits {
            if commits.iter().any(|c| c == id) {
                commit_findings.push(Finding { location: format!("commit {}", short(id)), object: None, line, rule, key: None });
            } else {
                found.push((id.to_string(), path_of.get(id).cloned(), line, rule));
            }
        }
    })?;
    for (id, path, line, rule) in found {
        let location = match (&path, labels) {
            (Some(p), Some(labels)) => locate(git, labels, &commits, &id, p, &shown_path(set, p)),
            (Some(p), None) => shown_path(set, p),
            (None, _) => "an object".to_string(),
        };
        // A blob over the cap is never read, so never cached: dirty as one with a hit.
        dirty.insert(id.clone());
        report.findings.push(Finding { location, object: Some(short(&id)), line, rule, key: None });
    }
    report.findings.extend(commit_findings);
    for id in &to_read {
        if !dirty.contains(id) {
            cache.insert(id);
        }
    }
    Ok(Scanned { report, dirty })
}

/// D8 on the settings files of the trees the VM checks out (`trees`:
/// `(label, entries)`), within the import's bounds (S10 phase 4) as
/// [`settings_of_trees`] reads each tip: each `.claude/settings.json` and
/// `.claude/settings.local.json` ([`settings_name`]: any depth, names
/// compared as the Mac's disk does) through the repo mode (a blob read once
/// however many trees hold it), a symlink at either name
/// [`SETTINGS_SYMLINK`]; a file whose blob `unchanged` says the Mac already
/// holds at that path is skipped (the code-out reads only what changed). A
/// `.claude` that is a symlink is [`SETTINGS_SYMLINK`] changed or not: the
/// settings read through it are not at a path this scan reads. A gitlink is
/// noted (a submodule is never carried), its path as [`shown_path`] shows
/// it, scrubbed. Nothing when the workspace trusts its repo settings, but
/// the notes. A settings file whose blob is over `max_blob` is never read, a
/// [`BLOB_TOO_LARGE`] finding at its path instead (F4-WALK-2: one the Mac
/// already holds, which no scan of the objects lists, among them), and each
/// label keeps at most [`SETTINGS_FINDINGS_MAX`] settings findings, past
/// them the first of each rule not among them (F4-WALK-1). The seed, `box
/// review` and the per-ref import all take it; S9's unbounded
/// `scan_settings` (every blob read whole, every finding kept) is gone, so
/// no caller can pick it (phase 4b follow-up, VF-3).
pub fn scan_settings_within(git: &GitRun, trees: &[(String, Vec<TreeEntry>)], set: &ScanSet, unchanged: &dyn Fn(&TreeEntry) -> bool, max_blob: u64, report: &mut ScanReport) -> Result<(), BridgeError> {
    let mut read: BTreeSet<(String, String)> = BTreeSet::new();
    for (label, entries) in trees {
        // What this label keeps of its findings.
        let mut keep = SettingsKept::default();
        let mut push = |report: &mut ScanReport, f: Finding| {
            if keep.admit(&f.rule) {
                report.findings.push(f);
            }
        };
        for e in entries {
            if e.mode == "160000" {
                // The path as the other notes name theirs: shown, then scrubbed alone (a bare k=v value runs to the
                // line's end, so a scrub of the whole note would mask the rest of it).
                let note = format!("{} is a submodule: not carried", scrub(&shown_path(set, &e.path)));
                if !report.notes.contains(&note) {
                    report.notes.push(note);
                }
                continue;
            }
            if !set.repo_settings {
                continue;
            }
            let at = || format!("{label}:{}", shown_path(set, &e.path));
            if e.mode == "120000" && is_claude_dir(&e.path) {
                if read.insert((e.id.clone(), e.path.clone())) {
                    push(report, Finding { location: at(), object: Some(short(&e.id)), line: 0, rule: SETTINGS_SYMLINK.into(), key: None });
                }
                continue;
            }
            let Some(name) = settings_name(&e.path) else { continue };
            if unchanged(e) || !read.insert((e.id.clone(), e.path.clone())) {
                continue;
            }
            if e.mode == "120000" {
                push(report, Finding { location: at(), object: Some(short(&e.id)), line: 0, rule: SETTINGS_SYMLINK.into(), key: None });
                continue;
            }
            // F4-WALK-2: sized first, never read past the cap (a miss here must never pass for a clean file).
            if check(git, std::slice::from_ref(&e.id))?.iter().any(|c| c.size > max_blob) {
                push(report, Finding { location: at(), object: Some(short(&e.id)), line: 0, rule: BLOB_TOO_LARGE.into(), key: None });
                continue;
            }
            report.settings_files += 1;
            let mut findings = Vec::new();
            read_objects(git, std::slice::from_ref(&e.id), |_, bytes| findings = settings_findings_mode(name, bytes, &[], SettingsMode::Repo))?;
            for f in findings {
                push(report, settings_finding(set, at(), &e.id, f));
            }
        }
    }
    Ok(())
}

/// What one tip (one label) keeps of its settings findings, in their order
/// ([`SETTINGS_FINDINGS_MAX`]): whether the next one, of `rule`, is kept.
#[derive(Debug, Default)]
struct SettingsKept {
    kept: usize,
    rules: HashSet<String>,
}

impl SettingsKept {
    /// Keep the next finding, of `rule`: while fewer than the cap are kept,
    /// and past it when no kept one has its rule.
    fn admit(&mut self, rule: &str) -> bool {
        let new = !self.rules.contains(rule);
        if self.kept >= SETTINGS_FINDINGS_MAX && !new {
            return false;
        }
        self.kept += 1;
        if new {
            self.rules.insert(rule.to_string());
        }
        true
    }

    /// One file's findings cut to what a fresh tip keeps of them: no tip,
    /// whatever it kept before, keeps another of them (once one is passed
    /// over, its rule is kept and the cap reached).
    fn kept_of(all: Vec<crate::bridge::scan::SettingsFinding>) -> Vec<crate::bridge::scan::SettingsFinding> {
        let mut fresh = SettingsKept::default();
        all.into_iter().filter(|f| fresh.admit(f.rule)).collect()
    }
}

/// `settings` (one ref's settings findings) after `findings` (its
/// objects'), S10 phase 4 (F4-WALK-2): a blob over the cap the objects'
/// scan named at the same place (`blob-too-large`) is not named again. The
/// import's two modes append so alike.
pub fn extend_settings(findings: &mut Vec<Finding>, settings: Vec<Finding>) {
    for f in settings {
        if f.rule != BLOB_TOO_LARGE || !findings.contains(&f) {
            findings.push(f);
        }
    }
}

/// One finding of D8's repo mode in the settings file `id` at `at`. A key
/// path that trips a tripwire (a token as a JSON key) is never shown, nor one
/// cut short (a cut can leave part of a token that no longer matches): the
/// seed's, the code-out's and the review's reports.
fn settings_finding(set: &ScanSet, at: String, id: &str, f: crate::bridge::scan::SettingsFinding) -> Finding {
    let key = Some(f.key).filter(|k| !k.is_empty() && !k.ends_with('\u{2026}') && set.rules.scan_bytes(k.as_bytes()).is_empty());
    Finding { location: at, object: Some(short(id)), line: f.line, rule: f.rule.to_string(), key }
}

/// One entry of a tree object as git wrote it: its mode as `ls-tree` shows
/// it ([`canon_mode`]), its name, its id.
struct RawEntry {
    mode: &'static str,
    name: Vec<u8>,
    id: String,
}

/// The mode of a tree entry as git's tree walk makes it (`canon_mode`), so
/// as `ls-tree` shows it: a regular file `100644` or `100755` by its owner's
/// execute bit, a link `120000`, a tree `40000`, anything else a gitlink
/// `160000`. Read as git's `get_mode` reads it: octal digits summed in an
/// unsigned int that wraps, so `40000100644` is a regular file (a mode past
/// 32 bits, which fsck lets through, never hides an entry). `None` for an
/// empty mode or a byte that is no octal digit, which git refuses too.
fn canon_mode(text: &[u8]) -> Option<&'static str> {
    if text.is_empty() || !text.iter().all(|b| (b'0'..=b'7').contains(b)) {
        return None;
    }
    let mode = text.iter().fold(0u32, |m, b| (m << 3) | u32::from(b - b'0'));
    Some(match mode & 0o170_000 {
        0o100_000 if mode & 0o100 != 0 => "100755",
        0o100_000 => "100644",
        0o120_000 => "120000",
        0o040_000 => "40000",
        _ => "160000",
    })
}

/// The entries of a tree object's bytes (`<mode> <name>\0<id>` each, the id
/// `raw` bytes), in their order. `None` for a tree git refuses to walk (its
/// `ls-tree` dies on it): an entry whose mode `canon_mode` cannot read, an
/// empty name, a cut entry or a tail that is no entry. Never one entry left
/// out: the walk of the settings reads every entry git reads, or none.
fn raw_entries(bytes: &[u8], raw: usize) -> Option<Vec<RawEntry>> {
    let mut entries = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let sp = rest.iter().position(|b| *b == b' ')?;
        let mode = canon_mode(&rest[..sp])?;
        let entry = &rest[sp + 1..];
        let nul = entry.iter().position(|b| *b == 0).filter(|n| *n > 0)?;
        let id = entry.get(nul + 1..nul + 1 + raw)?;
        entries.push(RawEntry { mode, name: entry[..nul].to_vec(), id: hex::encode(id) });
        rest = &entry[nul + 1 + raw..];
    }
    Some(entries)
}

/// What a settings entry of a tree is to D8 ([`scan_settings_within`]'s cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingsKind {
    /// A link whose name is `.claude` ([`is_claude_dir`]): `settings-symlink`, changed or not.
    ClaudeLink,
    /// A settings file D8 reads ([`settings_name`]'s name).
    File(&'static str),
    /// An entry of this very tree named as a settings file: D8's only where this tree is a `.claude` directory,
    /// which the tree that names it decides.
    Named(&'static str),
}

/// What the walk of the settings keeps of one tree (S10 F4), in its order:
/// each subtree below which D8 reads an entry, by its name and what that
/// subtree keeps, and each entry of this very tree D8 may read. What a
/// subtree keeps is shared, never copied into the trees above it with its
/// paths: a tree keeps its own entries' names alone, so the walk holds what
/// the trees it read hold, whatever their depth (a copy per level grows with
/// the depth's square: 300 levels of 100-character names over 100 settings
/// files, a pack of some 60 KB, would hold some 450 MB of paths).
#[derive(Debug)]
enum Kept {
    /// A subtree and what it keeps.
    Tree { name: String, below: std::rc::Rc<Vec<Kept>> },
    /// A `.claude` link ([`SettingsKind::ClaudeLink`]), or a file or a link named as a settings file ([`SettingsKind::Named`]).
    Entry { name: String, mode: &'static str, id: String, kind: SettingsKind },
}

/// What the tree `id` keeps ([`Kept`]; `trees`: every tree read, by id),
/// each tree's computed once (`memo`), its subtrees' first: children first
/// through an explicit stack, so no depth of nesting recurses. A tree not in
/// `trees` keeps nothing; a subtree is kept only when D8 reads an entry below
/// it there (a settings-named one only right below a `.claude` directory).
fn kept_of(id: &str, trees: &std::collections::HashMap<String, Vec<RawEntry>>, memo: &mut std::collections::HashMap<String, std::rc::Rc<Vec<Kept>>>) {
    let mut stack: Vec<(String, usize)> = vec![(id.to_string(), 0)];
    while let Some(top) = stack.len().checked_sub(1) {
        let (tree, at) = stack[top].clone();
        if memo.contains_key(&tree) {
            stack.pop();
            continue;
        }
        let entries = trees.get(&tree).map_or(&[][..], Vec::as_slice);
        // The next subtree whose own is not known yet: it goes first.
        if let Some(skip) = entries[at..].iter().position(|e| e.mode == "40000" && !memo.contains_key(&e.id) && !stack.iter().any(|(t, _)| *t == e.id)) {
            stack[top].1 = at + skip + 1;
            stack.push((entries[at + skip].id.clone(), 0));
            continue;
        }
        let mut kept = Vec::new();
        for e in entries {
            let name = String::from_utf8_lossy(&e.name);
            match e.mode {
                "40000" => {
                    let claude = folds_to(&name, ".claude");
                    if let Some(below) = memo.get(&e.id).filter(|b| b.iter().any(|k| claude || !matches!(k, Kept::Entry { kind: SettingsKind::Named(_), .. }))) {
                        kept.push(Kept::Tree { name: name.into_owned(), below: std::rc::Rc::clone(below) });
                    }
                }
                // A gitlink makes a note only, which the import does not keep.
                "160000" => {}
                "120000" if folds_to(&name, ".claude") => kept.push(Kept::Entry { name: name.into_owned(), mode: e.mode, id: e.id.clone(), kind: SettingsKind::ClaudeLink }),
                _ => {
                    if let Some(n) = SETTINGS_NAMES.into_iter().find(|s| folds_to(&name, s)) {
                        kept.push(Kept::Entry { name: name.into_owned(), mode: e.mode, id: e.id.clone(), kind: SettingsKind::Named(n) });
                    }
                }
            }
        }
        memo.insert(tree, std::rc::Rc::new(kept));
        stack.pop();
    }
}

/// Each entry D8 reads below a tree that keeps `kept` ([`kept_of`]), in
/// `ls-tree -r`'s order: its path from that tree, its mode, its id and what
/// it is ([`SettingsKind::ClaudeLink`], or [`SettingsKind::File`]: a
/// settings-named entry right below a `.claude` directory), handed to
/// `seen`. One path is built at a time, on one string; none is kept.
/// Whether the walk ran whole: S10 phase 4 (F4-WALK-1), what each tree
/// keeps is shared, but a tree that `k` routes reach is walked `k` times,
/// so the walk stops at once, `false`, past [`SETTINGS_WALK_MAX`] nodes
/// (each subtree entered, each entry reached) or [`SETTINGS_WALK_BYTES`]
/// of paths (each name entered, each whole path handed on).
fn each_setting<'k>(kept: &'k [Kept], mut seen: impl FnMut(&str, &'static str, &'k str, SettingsKind)) -> bool {
    let mut path = String::new();
    let (mut nodes, mut bytes) = (0usize, 0usize);
    // Each tree being walked: what it keeps, the next of it, whether it is a `.claude` directory, and the length
    // of `path` before its name.
    let mut stack: Vec<(&'k [Kept], usize, bool, usize)> = vec![(kept, 0, false, 0)];
    while let Some(top) = stack.last_mut() {
        let (list, at, claude, len) = *top;
        let Some(k) = list.get(at) else {
            path.truncate(len);
            stack.pop();
            continue;
        };
        top.1 += 1;
        nodes += 1;
        if nodes > SETTINGS_WALK_MAX {
            return false;
        }
        match k {
            Kept::Tree { name, below } => {
                bytes += name.len() + 1;
                if bytes > SETTINGS_WALK_BYTES {
                    return false;
                }
                let len = path.len();
                path.push_str(name);
                path.push('/');
                stack.push((below.as_slice(), 0, folds_to(name, ".claude"), len));
            }
            Kept::Entry { name, mode, id, kind } => {
                let kind = match kind {
                    SettingsKind::Named(n) if claude => SettingsKind::File(n),
                    SettingsKind::Named(_) => continue,
                    other => *other,
                };
                bytes += path.len() + name.len();
                if bytes > SETTINGS_WALK_BYTES {
                    return false;
                }
                let len = path.len();
                path.push_str(name);
                seen(&path, mode, id.as_str(), kind);
                path.truncate(len);
            }
        }
    }
    true
}

/// What one tip reads of the settings below its tree (`kept`), as
/// [`scan_settings_within`] walks its listing: each `.claude` link, and
/// each settings file whose blob the Mac's HEAD does not hold at its path
/// (`held`, path to blob), once per blob and path, handed to `step` with its
/// path and blob: the name D8 reads it by, or `None` for a link (a
/// `settings-symlink` finding at once). Whether the walk ran whole
/// ([`each_setting`]).
fn tip_settings<'k>(kept: &'k [Kept], held: &std::collections::HashMap<String, String>, mut step: impl FnMut(&str, &'k str, Option<&'static str>)) -> bool {
    let mut read: HashSet<(&'k str, String)> = HashSet::new();
    each_setting(kept, |path, mode, id, kind| match kind {
        SettingsKind::ClaudeLink => {
            if read.insert((id, path.to_string())) {
                step(path, id, None);
            }
        }
        SettingsKind::File(name) => {
            if held.get(path).is_some_and(|h| h == id) || !read.insert((id, path.to_string())) {
                return;
            }
            step(path, id, (mode != "120000").then_some(name));
        }
        SettingsKind::Named(_) => {}
    })
}

/// D8 on the settings files of the trees the VM checks out, exactly as
/// [`scan_settings_within`] reads each one's `ls-tree -r` (the same findings
/// in the same order, per tip; S10 F4), without listing any: every distinct
/// tree reachable from `tips` (`(label, tree id)`) and from `head` (the
/// Mac's HEAD tree: a settings file whose blob it holds at that path is
/// skipped, [`scan_settings_within`]'s `unchanged`) is read once, one
/// `cat-file --batch` per depth, and parsed as git parses it
/// ([`raw_entries`]: a tree git cannot walk refuses the import,
/// `GIT_FAILED`); what each tree keeps is computed once however many tips
/// hold it ([`kept_of`]). Then each distinct settings blob a tip reads is
/// read once, and each tip's findings are made by a second walk of its own:
/// no tip's paths are held beside another's. Tree-based, never taken from a
/// listing of what is new: a blob the Mac already holds (a permissive
/// fixture of its history) copied into `.claude/settings.json` is read
/// there. Nothing when the workspace trusts its repo settings; no gitlink's
/// note (the import keeps none).
///
/// S10 phase 4, within [`scan_settings_within`]'s bounds: a walk (HEAD's,
/// or a tip's) past [`SETTINGS_WALK_MAX`] nodes or [`SETTINGS_WALK_BYTES`]
/// of paths refuses the import (`GIT_FAILED`, F4-WALK-1); the settings
/// blobs are sized first (one `cat-file --batch-check`) and one over
/// `max_blob` is never read, [`BLOB_TOO_LARGE`] at each path a tip reads it
/// at (F4-WALK-2); a tip keeps at most [`SETTINGS_FINDINGS_MAX`] settings
/// findings, and past them the first of each rule not among them.
pub fn settings_of_trees(git: &GitRun, set: &ScanSet, tips: &[(String, String)], head: Option<&str>, max_blob: u64) -> Result<Vec<Vec<Finding>>, BridgeError> {
    use std::collections::HashMap;
    if !set.repo_settings || tips.is_empty() {
        return Ok(vec![Vec::new(); tips.len()]);
    }
    let roots: BTreeSet<&str> = tips.iter().map(|(_, t)| t.as_str()).chain(head).collect();
    // Each tree as its subtrees and the entries D8 may read: a repository's other files are never held.
    let wanted_entry = |e: &RawEntry| {
        let name = String::from_utf8_lossy(&e.name);
        e.mode == "40000" || (e.mode != "160000" && (folds_to(&name, ".claude") || SETTINGS_NAMES.iter().any(|s| folds_to(&name, s))))
    };
    let mut trees: HashMap<String, Vec<RawEntry>> = HashMap::new();
    let mut level: Vec<String> = roots.iter().map(|t| (*t).to_string()).collect();
    while !level.is_empty() {
        let mut malformed: Option<String> = None;
        read_objects(git, &level, |id, bytes| match raw_entries(bytes, id.len() / 2) {
            Some(entries) => {
                trees.insert(id.to_string(), entries.into_iter().filter(wanted_entry).collect());
            }
            None => {
                malformed.get_or_insert_with(|| short(id));
            }
        })?;
        if let Some(id) = malformed {
            return Err(BridgeError::WorkspaceFailed { code: crate::wire::workspace::refusal::GIT_FAILED, message: format!("the tree {id} is malformed: git cannot walk it") });
        }
        let next: BTreeSet<String> = level.iter().filter_map(|t| trees.get(t)).flatten().filter(|e| e.mode == "40000" && !trees.contains_key(&e.id)).map(|e| e.id.clone()).collect();
        level = next.into_iter().collect();
    }
    let mut memo: HashMap<String, std::rc::Rc<Vec<Kept>>> = HashMap::new();
    for root in &roots {
        kept_of(root, &trees, &mut memo);
    }
    drop(trees);
    let kept = |tree: &str| memo.get(tree).map_or(&[][..], |k| k.as_slice());
    let too_many = |tree: &str| BridgeError::WorkspaceFailed {
        code: crate::wire::workspace::refusal::GIT_FAILED,
        message: format!("the tree {} routes more settings paths than the import walks ({SETTINGS_WALK_MAX} entries, {} MiB of paths): refused", short(tree), SETTINGS_WALK_BYTES >> 20),
    };
    let mut held: HashMap<String, String> = HashMap::new();
    if let Some(h) = head {
        let whole = each_setting(kept(h), |path, _, id, kind| {
            if matches!(kind, SettingsKind::File(_)) {
                held.insert(path.to_string(), id.to_string());
            }
        });
        if !whole {
            return Err(too_many(h));
        }
    }
    // The blobs the tips read, each by the names it is read as.
    let mut wanted: HashMap<String, BTreeSet<&'static str>> = HashMap::new();
    for (_, tree) in tips {
        let whole = tip_settings(kept(tree), &held, |_, id, name| {
            if let Some(name) = name {
                wanted.entry(id.to_string()).or_default().insert(name);
            }
        });
        if !whole {
            return Err(too_many(tree));
        }
    }
    let ids: Vec<String> = wanted.keys().cloned().collect();
    // Sized first: a blob over the cap is never read (F4-WALK-2), and never passes for a clean file either.
    let large: HashSet<&str> = ids.iter().zip(check(git, &ids)?).filter(|(_, c)| c.size > max_blob).map(|(id, _)| id.as_str()).collect();
    let small: Vec<String> = ids.iter().filter(|id| !large.contains(id.as_str())).cloned().collect();
    let mut found: HashMap<(String, &'static str), Vec<crate::bridge::scan::SettingsFinding>> = HashMap::new();
    read_objects(git, &small, |id, bytes| {
        for name in wanted.get(id).into_iter().flatten() {
            // What any tip keeps of them (F4-WALK-1): a blob at many paths is many copies.
            found.insert((id.to_string(), name), SettingsKept::kept_of(settings_findings_mode(name, bytes, &[], SettingsMode::Repo)));
        }
    })?;
    Ok(tips
        .iter()
        .map(|(label, tree)| {
            let mut findings = Vec::new();
            let mut keep = SettingsKept::default();
            let whole = tip_settings(kept(tree), &held, |path, id, name| {
                let at = || format!("{label}:{}", shown_path(set, path));
                let object = || Some(short(id));
                match name {
                    None => {
                        if keep.admit(SETTINGS_SYMLINK) {
                            findings.push(Finding { location: at(), object: object(), line: 0, rule: SETTINGS_SYMLINK.into(), key: None });
                        }
                    }
                    Some(_) if large.contains(id) => {
                        if keep.admit(BLOB_TOO_LARGE) {
                            findings.push(Finding { location: at(), object: object(), line: 0, rule: BLOB_TOO_LARGE.into(), key: None });
                        }
                    }
                    Some(name) => {
                        for f in found.get(&(id.to_string(), name)).map_or(&[][..], Vec::as_slice) {
                            if keep.admit(f.rule) {
                                findings.push(settings_finding(set, at(), id, f.clone()));
                            }
                        }
                    }
                }
            });
            // The same walk ran whole for the reads above.
            debug_assert!(whole, "the walk of {label} stopped");
            findings
        })
        .collect())
}

/// L9 on the files the WIP adds (`added`, paths of `entries`, the WIP's
/// tree labelled `label`): a dotenv-named regular file without the ai-env
/// marker is `env-file-plaintext` (ai-env encrypt it, or ignore it).
pub fn scan_dotenv(git: &GitRun, set: &ScanSet, label: &str, entries: &[TreeEntry], added: &[String], report: &mut ScanReport) -> Result<(), BridgeError> {
    let added: BTreeSet<&str> = added.iter().map(String::as_str).collect();
    for e in entries.iter().filter(|e| e.mode.starts_with("100") && added.contains(e.path.as_str())) {
        let name = e.path.rsplit('/').next().unwrap_or_default();
        if !is_dotenv_name(name) {
            continue;
        }
        let mut plain = false;
        read_objects(git, std::slice::from_ref(&e.id), |_, bytes| plain = !has_marker(bytes))?;
        if plain {
            report.findings.push(Finding { location: format!("{label}:{}", shown_path(set, &e.path)), object: Some(short(&e.id)), line: 0, rule: "env-file-plaintext".into(), key: None });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D8's names as the Mac's disk compares them: ASCII case, and the two
    /// letters outside ASCII that fold into it; the file directly below a
    /// `.claude` at any depth, nothing else.
    #[test]
    fn settings_names_fold_as_the_macs_disk_does() {
        for (path, name) in [
            (".claude/settings.json", "settings.json"),
            ("pkg/.claude/settings.local.json", "settings.local.json"),
            (".CLAUDE/Settings.Local.json", "settings.local.json"),
            (".Claude/SETTINGS.JSON", "settings.json"),
            (".claude/\u{17f}ettings.json", "settings.json"),
            (".claude/settings.j\u{17f}on", "settings.json"),
        ] {
            assert_eq!(settings_name(path), Some(name), "{path}");
        }
        for path in ["settings.json", "claude/settings.json", ".claudex/settings.json", ".claude/sub/settings.json", ".claude/settings.json.bak", ".claude/settings\u{200b}.json", ".claude/settings.jso"] {
            assert_eq!(settings_name(path), None, "{path}");
        }
        assert!(is_claude_dir(".claude") && is_claude_dir("a/b/.CLAUDE") && !is_claude_dir(".claude/x") && !is_claude_dir("claude"));
    }

    /// A finding's line: where, the object, the line, the rule, the key; a
    /// blob over the cap names the cap's key (`box seed` and Cursor's line
    /// show it), no other rule does.
    #[test]
    fn a_finding_names_its_rule_and_a_blob_too_large_its_cap() {
        let f = |location: &str, line: usize, rule: &str, key: Option<&str>| Finding { location: location.into(), object: Some("3f2a91c0e4b1".into()), line, rule: rule.into(), key: key.map(str::to_string) };
        assert_eq!(f("HEAD:assets/model.bin", 0, BLOB_TOO_LARGE, None).text(), "HEAD:assets/model.bin (blob 3f2a91c0e4b1): rule blob-too-large (over [seed].max_blob_mib)");
        assert_eq!(f("HEAD:cfg/prod.yaml", 3, "aws-access-key-id", None).text(), "HEAD:cfg/prod.yaml (blob 3f2a91c0e4b1) line 3: rule aws-access-key-id");
        assert_eq!(f("wip:.claude/settings.local.json", 5, "broad-allow", Some("permissions.allow[2]")).text(), "wip:.claude/settings.local.json (blob 3f2a91c0e4b1) line 5: rule broad-allow, key permissions.allow[2]");
    }

    /// A tree's entry names, spaces and all, each id skipped by its length
    /// (an id may hold a space or a NUL); a cut tail is left out.
    #[test]
    fn tree_names_reads_every_entry() {
        let id: Vec<u8> = (0..20).map(|i| if i % 2 == 0 { b' ' } else { 0 }).collect();
        let mut bytes = Vec::new();
        for (mode, name) in [("100644", "a b.txt"), ("40000", "dir"), ("120000", ".claude")] {
            bytes.extend_from_slice(format!("{mode} {name}\0").as_bytes());
            bytes.extend_from_slice(&id);
        }
        let all = [&b"a b.txt"[..], &b"dir"[..], &b".claude"[..]];
        assert_eq!(tree_names(&bytes, 20), all);
        assert_eq!(tree_names(&bytes[..bytes.len() - 5], 20), all, "the last id cut: its name was read");
        assert!(tree_names(b"100644 x", 20).is_empty());
    }

    /// S10 F4: a tree object's entries as the walk of the settings reads
    /// them: each mode as `ls-tree` shows it, by git's own rule (a regular
    /// file by its owner's execute bit, `100664` as `100644`; a link; a
    /// tree's `40000`; anything else, a bare `644` too, a gitlink), read as
    /// git's `get_mode` reads it, in an unsigned int that wraps (so a mode
    /// past 32 bits, which fsck lets through, is the entry git checks out:
    /// `40000100644` a file, `40000040000` a tree), its name bytes and its id
    /// in hex. A tree git refuses to walk is none: a mode with a byte that is
    /// no octal digit, an empty mode, an empty name, a cut entry, a tail.
    #[test]
    fn a_trees_entries_read_with_ls_trees_modes() {
        let tree = |named: &[(&str, &str)]| {
            let mut bytes = Vec::new();
            for (i, (mode, name)) in (1u8..).zip(named) {
                bytes.extend_from_slice(format!("{mode} {name}\0").as_bytes());
                bytes.extend_from_slice(&[i; 20]);
            }
            bytes
        };
        let named = [("100644", "a b.txt"), ("100664", "group.txt"), ("100755", "run.sh"), ("644", "bare.txt"), ("120000", ".claude"), ("40000", "dir"), ("160000", "sub"), ("40000100644", "wrapped.json"), ("40000040000", "wrapped-dir")];
        let bytes = tree(&named);
        let got: Vec<(&str, String, String)> = raw_entries(&bytes, 20).unwrap().into_iter().map(|e| (e.mode, String::from_utf8(e.name).unwrap(), e.id)).collect();
        let want: Vec<(&str, String, String)> = [("100644", "a b.txt", 1u8), ("100644", "group.txt", 2), ("100755", "run.sh", 3), ("160000", "bare.txt", 4), ("120000", ".claude", 5), ("40000", "dir", 6), ("160000", "sub", 7), ("100644", "wrapped.json", 8), ("40000", "wrapped-dir", 9)]
            .into_iter()
            .map(|(m, n, i)| (m, n.to_string(), hex::encode([i; 20])))
            .collect();
        assert_eq!(got, want);
        assert_eq!(raw_entries(b"", 20).map(|e| e.len()), Some(0), "an empty tree");
        assert!(raw_entries(&bytes[..bytes.len() - 5], 20).is_none(), "the last id cut");
        let mut tail = bytes.clone();
        tail.extend_from_slice(b"zz");
        assert!(raw_entries(&tail, 20).is_none(), "a tail that is no entry");
        for bad in [[("100644", "a"), ("x1", "bad")], [("100644", "a"), ("", "no-mode")], [("100644", "a"), ("+100644", "signed")], [("100644", "a"), ("100644", "")]] {
            assert!(raw_entries(&tree(&bad), 20).is_none(), "{bad:?}");
        }
        assert_eq!((canon_mode(b"100600"), canon_mode(b"040000"), canon_mode(b"")), (Some("100644"), Some("40000"), None));
        assert_eq!((canon_mode(b"77777777777100644"), canon_mode(b"40000100644"), canon_mode(b"40000040000"), canon_mode(b"40000120000")), (Some("100644"), Some("100644"), Some("40000"), Some("120000")));
        assert_eq!((canon_mode(b"+100644"), canon_mode(b"100644 "), canon_mode(b"10064x")), (None, None, None));
    }

    /// S10 F4: what the walk keeps of a deep tree is each tree's own names,
    /// never a copy of the paths below it per level, and every settings path
    /// comes out whole, in `ls-tree -r`'s order. 300 levels of 100-character
    /// names over 100 directories with a `.claude/settings.json` each (a pack
    /// of some 60 KB from a VM): the walk keeps under 64 KiB of names, where
    /// a copy per level would hold some 450 MB of paths; each of the 100
    /// paths is 30 KB long. A directory whose only settings-named file is
    /// outside a `.claude` is not kept, and that file never comes out; a
    /// `.claude` link comes out as one.
    #[test]
    fn a_deep_walk_keeps_each_trees_own_names_and_builds_each_path_once() {
        use std::collections::HashMap;
        let id = |n: usize| format!("{n:040x}");
        let entry = |mode: &'static str, name: &str, of: usize| RawEntry { mode, name: name.as_bytes().to_vec(), id: id(of) };
        let mut trees: HashMap<String, Vec<RawEntry>> = HashMap::new();
        // The bottom (tree 1): 100 directories (trees 1000…), each holding a `.claude` (trees 2000…) with its settings
        // file (blobs 3000…); a `settings.json` beside them and a `cfg` (tree 4) holding one, outside any `.claude`.
        let mut bottom: Vec<RawEntry> = (0..100).map(|i| entry("40000", &format!("d{i:02}"), 1000 + i)).collect();
        bottom.push(entry("40000", "cfg", 4));
        bottom.push(entry("100644", "settings.json", 9));
        trees.insert(id(1), bottom);
        trees.insert(id(4), vec![entry("100644", "settings.json", 10)]);
        for i in 0..100 {
            trees.insert(id(1000 + i), vec![entry("40000", ".claude", 2000 + i)]);
            trees.insert(id(2000 + i), vec![entry("100644", "settings.json", 3000 + i)]);
        }
        let name = |level: usize| format!("{level:03}{}", "n".repeat(97));
        // Levels 300 (the root, tree 10300) down to 1 (tree 10001), each the next one's only entry; level 1 names
        // the bottom; the root holds a `.claude` link too.
        for level in 1..=300 {
            let below = if level == 1 { 1 } else { 10_000 + level - 1 };
            let mut entries = vec![entry("40000", &name(level), below)];
            if level == 300 {
                entries.insert(0, entry("120000", ".Claude", 8));
            }
            trees.insert(id(10_000 + level), entries);
        }
        let mut memo = HashMap::new();
        kept_of(&id(10_300), &trees, &mut memo);
        let names: usize = memo.values().flat_map(|k| k.iter()).map(|k| match k {
            Kept::Tree { name, .. } | Kept::Entry { name, .. } => name.len(),
        }).sum();
        assert!(names < 64 << 10, "{names} bytes of names kept");
        assert!(!memo[&id(1)].iter().any(|k| matches!(k, Kept::Tree { name, .. } if name == "cfg")), "cfg's settings.json is outside a .claude: cfg is not kept");
        let mut got: Vec<(String, &str, String, SettingsKind)> = Vec::new();
        assert!(each_setting(&memo[&id(10_300)], |path, mode, id, kind| got.push((path.to_string(), mode, id.to_string(), kind))), "some 600 nodes and 3 MB of paths: within the caps");
        let prefix: String = (1..=300).rev().map(|level| format!("{}/", name(level))).collect();
        let mut want = vec![(".Claude".to_string(), "120000", id(8), SettingsKind::ClaudeLink)];
        want.extend((0..100).map(|i| (format!("{prefix}d{i:02}/.claude/settings.json"), "100644", id(3000 + i), SettingsKind::File("settings.json"))));
        assert_eq!(got.len(), want.len());
        assert!(got == want, "the paths, whole, in order");
        assert!(got[1].0.len() > 30_000);
        // One tip's reads: each file once, the link a finding; a file HEAD holds at its path is skipped.
        let held: HashMap<String, String> = [(want[1].0.clone(), id(3000)), (want[2].0.clone(), id(7))].into_iter().collect();
        let mut steps: Vec<(String, Option<&str>)> = Vec::new();
        assert!(tip_settings(&memo[&id(10_300)], &held, |path, _, name| steps.push((path.to_string(), name))));
        assert_eq!(steps.len(), 100, "the link, and 99 files: d00's blob is HEAD's at its path, d01's is not");
        assert_eq!((steps[0].1, steps[1].0.ends_with("/d01/.claude/settings.json"), steps[1].1), (None, true, Some("settings.json")));
    }

    /// Every name the Mac's disk folds to `name` (lowercase ASCII,
    /// [`folds_to`]): each letter in either case, an `s` also U+017F, a `k`
    /// also U+212A.
    fn folded(name: &str) -> Vec<String> {
        let mut out = vec![String::new()];
        for c in name.chars() {
            let forms: Vec<char> = match c {
                's' => vec!['s', 'S', '\u{17f}'],
                'k' => vec!['k', 'K', '\u{212a}'],
                c if c.is_ascii_alphabetic() => vec![c, c.to_ascii_uppercase()],
                c => vec![c],
            };
            out = out.into_iter().flat_map(|p| forms.iter().map(move |f| format!("{p}{f}"))).collect();
        }
        out
    }

    /// S10 phase 4 (F4-WALK-1): a walk stops at once past its caps, and says
    /// so. 41 trees whose every level names the one below twice (`a`, `b`)
    /// over one `.claude/settings.json` route 2^40 paths to it (git's own
    /// `ls-tree -r` would list them all): each path costs the walk four
    /// nodes, so it hands on about a quarter of [`SETTINGS_WALK_MAX`] of
    /// them (65 536 nodes: never four times that, phase 4b V-5) and returns
    /// false, and a tip's reads stop at the same path. 300 levels of 3000-byte names over a `.claude`
    /// of 2000 names that fold to `settings.json` (of 13 824; each path some
    /// 900 KB) stop on the bytes, after a few paths, far below the node cap.
    #[test]
    fn a_walk_past_its_caps_stops_at_once() {
        use std::collections::HashMap;
        let id = |n: usize| format!("{n:040x}");
        let entry = |mode: &'static str, name: &str, of: usize| RawEntry { mode, name: name.as_bytes().to_vec(), id: id(of) };
        // Tree 1 holds `.claude` (tree 2), which holds settings.json (blob 3); level k (1..=40, tree 100 + k) names
        // level k - 1 (level 0 is tree 1) as `a` and as `b`.
        let level = |k: usize| if k == 0 { 1 } else { 100 + k };
        let mut trees: HashMap<String, Vec<RawEntry>> = HashMap::new();
        trees.insert(id(1), vec![entry("40000", ".claude", 2)]);
        trees.insert(id(2), vec![entry("100644", "settings.json", 3)]);
        for k in 1..=40 {
            trees.insert(id(level(k)), vec![entry("40000", "a", level(k - 1)), entry("40000", "b", level(k - 1))]);
        }
        let mut memo = HashMap::new();
        kept_of(&id(level(40)), &trees, &mut memo);
        assert_eq!(memo.len(), 42, "41 trees and .claude's, each kept once");
        let root = &memo[&id(level(40))];
        let mut seen = 0usize;
        let whole = each_setting(root, |path, _, _, kind| {
            assert!(path.len() == 40 * 2 + ".claude/settings.json".len() && kind == SettingsKind::File("settings.json"), "{path}");
            seen += 1;
        });
        // Four nodes a path (a level's `a` or `b`, amortized over its two, then `.claude` and `settings.json`): the
        // walk stops at the cap itself, never at a multiple of it.
        assert!(!whole && seen > SETTINGS_WALK_MAX / 8 && seen <= SETTINGS_WALK_MAX / 4, "{seen} paths handed on of 2^40 (four nodes a path), whole: {whole}");
        assert_eq!(SETTINGS_WALK_MAX, 1 << 16, "S10 §14: one walk visits at most 65 536 kept nodes");
        let mut steps = 0usize;
        assert!(!tip_settings(root, &HashMap::new(), |_, _, _| steps += 1));
        assert_eq!(steps, seen, "each path read once, up to the same stop");
        let variants = folded("settings.json");
        assert_eq!(variants.len(), 13_824);
        assert!(variants.iter().all(|v| folds_to(v, "settings.json")) && variants.iter().collect::<HashSet<_>>().len() == variants.len());
        let mut trees: HashMap<String, Vec<RawEntry>> = HashMap::new();
        trees.insert(id(2000), variants.iter().take(2000).enumerate().map(|(i, n)| entry("100644", n, 3000 + i)).collect());
        trees.insert(id(1000), vec![entry("40000", ".claude", 2000)]);
        for k in 1..=300 {
            trees.insert(id(1000 + k), vec![entry("40000", &format!("{k:03}{}", "n".repeat(2997)), 1000 + k - 1)]);
        }
        let mut memo = HashMap::new();
        kept_of(&id(1300), &trees, &mut memo);
        let mut seen = 0usize;
        assert!(!each_setting(&memo[&id(1300)], |path, _, _, _| {
            assert!(path.len() > 900_000, "{}", path.len());
            seen += 1;
        }), "past the byte cap");
        assert!((1..5).contains(&seen), "{seen} paths of some 900 KB each, of 2000");
    }

    /// S10 phase 4 (F4-WALK-1): what a tip keeps of its settings findings:
    /// the first [`SETTINGS_FINDINGS_MAX`], and past them the first of each
    /// rule not among them. A file's findings cut to what a fresh tip keeps
    /// ([`SettingsKept::kept_of`]) lose nothing any tip keeps of them,
    /// whatever it kept before.
    #[test]
    fn a_tip_keeps_its_first_settings_findings_and_each_rule() {
        use crate::bridge::scan::SettingsFinding;
        let f = |line: usize, rule: &'static str| SettingsFinding { line, rule, key: format!("k{line}") };
        let mut file: Vec<SettingsFinding> = (1..=30).map(|i| f(i, "bypass-permissions")).collect();
        file.insert(25, f(99, "repo-hooks"));
        file.push(f(100, "repo-hooks"));
        let cut = SettingsKept::kept_of(file.clone());
        assert_eq!(cut.iter().map(|f| f.line).collect::<Vec<_>>(), (1..=20).chain([99]).collect::<Vec<_>>(), "the first 20, then repo-hooks' first");
        for before in [vec![], vec!["broad-allow"; 3], vec!["bypass-permissions"; 25], vec!["repo-hooks"; 20], vec!["broad-allow"; 19]] {
            let kept = |of: &[SettingsFinding]| {
                let mut k = SettingsKept::default();
                for rule in &before {
                    k.admit(rule);
                }
                of.iter().filter(|f| k.admit(f.rule)).map(|f| f.line).collect::<Vec<_>>()
            };
            assert_eq!(kept(&cut), kept(&file), "after {before:?}");
        }
    }

    /// S10 phase 4 (F4-WALK-2): a ref's settings findings after its
    /// objects': a `blob-too-large` the objects' scan named at the same
    /// place is not named twice; any other finding is appended as it is.
    #[test]
    fn a_settings_blob_too_large_is_named_once() {
        let at = |location: &str, rule: &str| Finding { location: location.into(), object: Some("3f2a91c0e4b1".into()), line: 0, rule: rule.into(), key: None };
        let mut findings = vec![at("box/x:.claude/settings.json", BLOB_TOO_LARGE)];
        extend_settings(&mut findings, vec![at("box/x:.claude/settings.json", BLOB_TOO_LARGE), at("box/x:.claude/Settings.json", BLOB_TOO_LARGE), at("box/x:.claude", SETTINGS_SYMLINK), at("box/x:.claude", SETTINGS_SYMLINK)]);
        let got: Vec<(&str, &str)> = findings.iter().map(|f| (f.location.as_str(), f.rule.as_str())).collect();
        assert_eq!(got, [("box/x:.claude/settings.json", BLOB_TOO_LARGE), ("box/x:.claude/Settings.json", BLOB_TOO_LARGE), ("box/x:.claude", SETTINGS_SYMLINK), ("box/x:.claude", SETTINGS_SYMLINK)]);
    }

    /// F6: a refusal holds at most 20 lines. Twenty findings are all named;
    /// past twenty, the first 19 and a last line counting the others.
    #[test]
    fn findings_max_is_twenty_lines_the_last_counting_the_rest() {
        assert_eq!(FINDINGS_MAX, 20);
        let found = |n: usize| -> Vec<Finding> { (1..=n).map(|i| Finding { location: format!("HEAD:f{i}.txt"), object: None, line: i, rule: "aws-access-key-id".into(), key: None }).collect() };
        let twenty = finding_lines(&found(20));
        assert_eq!(twenty.lines().count(), 20);
        assert_eq!(twenty.lines().last(), Some("HEAD:f20.txt line 20: rule aws-access-key-id"), "twenty: every one named");
        let more = finding_lines(&found(25));
        let lines: Vec<&str> = more.lines().collect();
        assert_eq!(lines.len(), 20);
        assert_eq!(lines[18], "HEAD:f19.txt line 19: rule aws-access-key-id");
        assert_eq!(lines[19], "and 6 more finding(s)");
        assert_eq!(finding_lines(&found(21)).lines().last(), Some("and 2 more finding(s)"));
        assert_eq!(finding_lines(&[]), "");
        let refusal = ScanReport { findings: found(25), ..ScanReport::default() }.refusal().unwrap().to_string();
        assert_eq!(refusal.lines().count(), 20, "{refusal}");
    }

    /// `box review`'s set: the policy file's allow lines, the tripwires the
    /// seeds read, and the repo mode unless the deepest `[[workspace]]`
    /// holding the repository trusts its settings (none, or no bridge.toml:
    /// on); a bad policy line is an error naming the file and the line.
    #[test]
    fn the_review_set_loads_the_policy_and_honours_a_trusting_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let paths = Paths::from_root_and_env(root.join("bridge"), None);
        std::fs::create_dir_all(&paths.root).unwrap();
        let (repo, other) = (root.join("work/app"), root.join("elsewhere/app"));
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let (set, policy) = ScanSet::for_review(&paths, None, &repo, &repo).unwrap();
        assert!(set.repo_settings && policy.is_empty());
        assert_eq!(set.digest, Rules::defaults().digest(), "the built-ins alone without the files");
        std::fs::write(paths.root.join("settings-policy.txt"), "# reviewed\nallow Bash(npm test:*)\n").unwrap();
        std::fs::write(paths.root.join("tripwires.txt"), "INTERNAL-[0-9]{4}\n").unwrap();
        let s = |p: &std::path::Path| format!("{:?}", p.display().to_string());
        let text = format!("[workspaces]\nroots = [{}]\n\n[[workspace]]\npath = {}\ntrust_repo_settings = true\n\n[[workspace]]\npath = {}\n", s(&root.join("work")), s(&repo), s(&repo.join("sub")));
        let cfg = BridgeConfig::parse(&text).unwrap();
        let (set, policy) = ScanSet::for_review(&paths, Some(&cfg), &repo, &repo).unwrap();
        assert!(!set.repo_settings, "the workspace trusts its repo settings");
        assert_eq!(policy, ["Bash(npm test:*)"]);
        assert_eq!(set.rules.ids().last(), Some("tripwire:1"));
        assert_eq!(set.digest, set.rules.digest());
        let (set, _) = ScanSet::for_review(&paths, Some(&cfg), &repo.join("sub"), &repo).unwrap();
        assert!(set.repo_settings, "the deepest [[workspace]] decides");
        let (set, _) = ScanSet::for_review(&paths, Some(&cfg), &other, &other).unwrap();
        assert!(set.repo_settings, "outside every [[workspace]]");
        std::fs::write(paths.root.join("settings-policy.txt"), "alow x\n").unwrap();
        let e = ScanSet::for_review(&paths, Some(&cfg), &repo, &repo).unwrap_err().to_string();
        assert!(e.contains("settings-policy.txt:1: expected `allow <entry>`"), "{e}");
    }
}
