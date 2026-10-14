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
/// The most lines a finding refusal holds (the last counts what it left out).
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
    /// (the last one then counting the rest); `None` when clean.
    #[must_use]
    pub fn refusal(&self) -> Option<BridgeError> {
        if self.findings.is_empty() {
            return None;
        }
        Some(BridgeError::WorkspaceRefused { code: super::code::FINDING, message: finding_lines(&self.findings) })
    }
}

/// [`ScanReport::refusal`]'s message: one line per finding, at most [`FINDINGS_MAX`].
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
/// into it (U+017F LONG S as `s`, U+212A KELVIN SIGN as `k`).
fn folds_to(name: &str, want: &str) -> bool {
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
        let location = match &path {
            Some(p) => locate(git, labels, &commits, &id, p, &shown_path(set, p)),
            None => "an object".to_string(),
        };
        report.findings.push(Finding { location, object: Some(short(&id)), line, rule, key: None });
    }
    report.findings.extend(commit_findings);
    for id in &to_read {
        if !dirty.contains(id) {
            cache.insert(id);
        }
    }
    if let Err(e) = cache.save() {
        tracing::warn!("scan: the clean-object cache was not written: {e}");
    }
    Ok(report)
}

/// D8 on the settings files of the trees the VM checks out (`trees`:
/// `(label, entries)`): each `.claude/settings.json` and
/// `.claude/settings.local.json` ([`settings_name`]: any depth, names
/// compared as the Mac's disk does) through the repo mode (a blob read once
/// however many trees hold it), a symlink at either name
/// [`SETTINGS_SYMLINK`]; a file whose blob `unchanged` says the Mac already
/// holds at that path is skipped (the code-out reads only what changed). A
/// `.claude` that is a symlink is [`SETTINGS_SYMLINK`] changed or not: the
/// settings read through it are not at a path this scan reads. A gitlink is
/// noted (a submodule is never carried). Nothing when the workspace trusts
/// its repo settings, but the notes.
pub fn scan_settings(git: &GitRun, trees: &[(String, Vec<TreeEntry>)], set: &ScanSet, unchanged: &dyn Fn(&TreeEntry) -> bool, report: &mut ScanReport) -> Result<(), BridgeError> {
    let mut read: BTreeSet<(String, String)> = BTreeSet::new();
    for (label, entries) in trees {
        for e in entries {
            if e.mode == "160000" {
                let note = format!("{} is a submodule: not carried", e.path);
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
                    report.findings.push(Finding { location: at(), object: Some(short(&e.id)), line: 0, rule: SETTINGS_SYMLINK.into(), key: None });
                }
                continue;
            }
            let Some(name) = settings_name(&e.path) else { continue };
            if unchanged(e) || !read.insert((e.id.clone(), e.path.clone())) {
                continue;
            }
            if e.mode == "120000" {
                report.findings.push(Finding { location: at(), object: Some(short(&e.id)), line: 0, rule: SETTINGS_SYMLINK.into(), key: None });
                continue;
            }
            report.settings_files += 1;
            let mut findings = Vec::new();
            read_objects(git, std::slice::from_ref(&e.id), |_, bytes| findings = settings_findings_mode(name, bytes, &[], SettingsMode::Repo))?;
            for f in findings {
                report.findings.push(Finding { location: at(), object: Some(short(&e.id)), line: f.line, rule: f.rule.to_string(), key: Some(f.key).filter(|k| !k.is_empty()) });
            }
        }
    }
    Ok(())
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
}
