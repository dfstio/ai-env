//! A remote chat's view on this Mac (S9 plan §5, M3; G4 builds it): after
//! each turn the VM's `GET /transcript/view` answer (`wire::view::TranscriptViewReply`)
//! is taken only in the shape its `check` allows, then written as the file
//! Cursor's picker lists, `<CLAUDE_CONFIG_DIR, else ~/.claude>/projects/<slug>/<sid>.jsonl`:
//! the title line, one `wire::view::ViewLine` per message (a `parentUuid`
//! chain, uuids and timestamps re-minted when invalid, `cwd`, `sessionId`
//! and `entrypoint` the Mac's), every text block and the title through the
//! session's tripwires (a hit masked, `wire::view::masked_text`), then
//! Cursor's own `custom-title` lines carried over byte for byte. Written
//! atomically (a 0600 temp file, fsync, rename), never through a symlink;
//! unchanged bytes are not rewritten. Never a transcript: the wrapper
//! refuses a local resume of it (`wire::view::local_view_target`).
//!
//! The file a view replaces is a view (`wire::view::is_view_head`), or
//! nothing: a transcript at the path (a chat begun on this Mac, an S8
//! mirror) is left alone and the write refused, so only the callers that
//! moved it first (`session stage`, the reopen's inline upload,
//! `session migrate-s9`) ever put a view in its place.
//!
//! S12: ai-env's own `custom-title` line, in the extension's shape, unmarked, once the CLI announced a rename
//! (`ensure_custom_title`); a staged chat's renames carried from its transcript (`write_view_carrying`).
use crate::bridge::errors::BridgeError;
use crate::bridge::scan::Rules;
use crate::bridge::title::{self, Ensure, SessionTitle, TitleSource};
use crate::wire::view::{
    is_view_head, masked_text, TranscriptViewReply, ViewLine, ViewMessage, ViewText, ViewTextKind, ViewTitleLine, CUSTOM_TITLES_MAX, CUSTOM_TITLE_LINE_MAX, VIEW_ENTRYPOINT, VIEW_HEAD_READ,
    VIEW_MARK_PREFIX, VIEW_TAIL_MAX, VIEW_USER_TYPE, VIEW_V,
};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The largest existing view file read for its `custom-title` lines (a view
/// is at most `VIEW_FILE_MAX` of text and its fields, escaped): anything
/// larger is no view of ours, and is left alone.
pub const EXISTING_MAX: u64 = 4 << 20;
/// The title line's `type`.
pub const TITLE_KIND: &str = "ai-title";
/// The `type` of the lines Cursor appends to a session file when it renames one.
pub const CUSTOM_TITLE_KIND: &str = "custom-title";
/// S12 (T): how far into a transcript's head [`renames_of`] reads when its tail holds no rename (the picker's head).
pub const RENAME_HEAD_READ: usize = 64 << 10;

/// Where a session's view goes, and what its lines say of this Mac.
#[derive(Debug, Clone, Copy)]
pub struct ViewTarget<'a> {
    /// `<CLAUDE_CONFIG_DIR, else ~/.claude>/projects`.
    pub mac_projects: &'a Path,
    /// The session's project directory name (one path component).
    pub slug: &'a str,
    /// The session's id: the file's name and every line's `sessionId`.
    pub session_id: &'a str,
    /// The lines' `cwd`: the workspace's Mac path.
    pub mac_cwd: &'a str,
}

impl ViewTarget<'_> {
    /// `<mac_projects>/<slug>/<session_id>.jsonl`.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.mac_projects.join(self.slug).join(format!("{}.jsonl", self.session_id))
    }

    /// The view's rel under the projects directory (`SessionRow::view`).
    #[must_use]
    pub fn rel(&self) -> String {
        format!("{}/{}.jsonl", self.slug, self.session_id)
    }
}

/// What one view write did (`transcript_view`'s audit `outcome`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewOutcome {
    /// The file now holds the view: its messages, the blocks masked, its bytes.
    Written { messages: usize, masked: usize, bytes: u64 },
    /// The file held these very bytes already: not rewritten.
    Unchanged { messages: usize, masked: usize, bytes: u64 },
    /// Refused whole (the reply's shape, a symlink, a transcript at the path): the old file stays.
    Refused(String),
}

impl ViewOutcome {
    /// The audit's word.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            ViewOutcome::Written { .. } => "written",
            ViewOutcome::Unchanged { .. } => "unchanged",
            ViewOutcome::Refused(_) => "refused",
        }
    }

    /// Messages, masked blocks and bytes (zero for a refusal).
    #[must_use]
    pub fn counts(&self) -> (usize, usize, u64) {
        match self {
            ViewOutcome::Written { messages, masked, bytes } | ViewOutcome::Unchanged { messages, masked, bytes } => (*messages, *masked, *bytes),
            ViewOutcome::Refused(_) => (0, 0, 0),
        }
    }
}

/// S12 (T): what [`ensure_custom_title`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ensured {
    /// ai-env's line was added and the view rewritten.
    Appended,
    /// Nothing to write: the newest `custom-title` line says it already, or (`only_if_none`) the view holds one.
    Already,
    /// No marked view at the path (nothing there, Cursor's lines alone, a transcript, a symlink, a file over
    /// `EXISTING_MAX`, a bad slug or id): nothing written.
    NoView,
}

/// `N.N.N` (three dot-separated groups of digits): the only `version` a line carries.
fn is_version(v: &str) -> bool {
    let groups: Vec<&str> = v.split('.').collect();
    groups.len() == 3 && groups.iter().all(|g| (1..=9).contains(&g.len()) && g.bytes().all(|b| b.is_ascii_digit()))
}

/// The first rule `rules` finds in `text`, if any.
fn hit(rules: &Rules, text: &str) -> Option<String> {
    rules.scan_bytes(text.as_bytes()).into_iter().next().map(|(_, rule)| rule)
}

/// The view's lines for `reply` (the Mac's rules 1 to 3): refused (`Err`,
/// why) unless the reply passes `check(n)`; one [`ViewLine`] per entry, its
/// `parentUuid` the previous line's `uuid` (null first), the entry's uuid
/// when `registry::is_uuid` takes it and no earlier line has it (else
/// `mint()`, which the chain then uses: a repeated uuid would make a line
/// its own parent, a cycle in the chain the extension walks back from the
/// leaf), its timestamp when `parse_rfc3339_utc` takes it (else `now`),
/// `cwd` and `sessionId` the target's, `version` the reply's when `N.N.N`,
/// `gitBranch` when `branch_check` passes it and the tripwires find nothing
/// in it (the one free-text field every line carries), the constants for
/// `entrypoint`, `userType` and `isSidechain`; every block with a tripwire
/// hit is `masked_text(rule)`, a title with one is dropped. The lines (each
/// with its newline), the messages and the blocks masked.
pub fn render(reply: &TranscriptViewReply, n: u32, rules: &Rules, t: &ViewTarget<'_>, now: &str, mint: &mut dyn FnMut() -> String) -> Result<(Vec<u8>, usize, usize), String> {
    reply.check(n).map_err(|e| format!("the view {e}"))?;
    let mut out: Vec<u8> = Vec::new();
    let push = |out: &mut Vec<u8>, line: &dyn erased::Line| -> Result<(), String> {
        let text = line.json().map_err(|e| format!("the view: {e}"))?;
        debug_assert!(text.starts_with(VIEW_MARK_PREFIX));
        out.extend_from_slice(text.as_bytes());
        out.push(b'\n');
        Ok(())
    };
    if let Some(title) = reply.title.as_deref().filter(|t| !t.is_empty() && hit(rules, t).is_none()) {
        let line = ViewTitleLine { ai_env_view: VIEW_V, kind: TITLE_KIND.to_string(), ai_title: title.to_string(), session_id: t.session_id.to_string() };
        push(&mut out, &line)?;
    }
    let version = reply.version.as_deref().filter(|v| is_version(v)).unwrap_or_default().to_string();
    let branch = reply.git_branch.as_deref().filter(|b| crate::wire::workspace::branch_check(b).is_ok() && hit(rules, b).is_none()).unwrap_or_default().to_string();
    let (mut parent, mut masked) = (None::<String>, 0usize);
    let mut written = std::collections::HashSet::new();
    for e in &reply.entries {
        let own = crate::bridge::registry::is_uuid(&e.uuid).then(|| e.uuid.to_ascii_lowercase()).filter(|u| !written.contains(u));
        let uuid = match own {
            Some(u) => u,
            None => mint(),
        };
        if !written.insert(uuid.clone()) {
            return Err("the view: an entry's minted uuid repeats one already written".into());
        }
        let timestamp = if crate::wire::time::parse_rfc3339_utc(&e.timestamp).is_some() { e.timestamp.clone() } else { now.to_string() };
        let content = e
            .blocks
            .iter()
            .map(|b| {
                let text = match hit(rules, b) {
                    Some(rule) => {
                        masked += 1;
                        masked_text(&rule)
                    }
                    None => b.clone(),
                };
                ViewText { kind: ViewTextKind::Text, text }
            })
            .collect();
        let line = ViewLine {
            ai_env_view: VIEW_V,
            parent_uuid: parent.clone(),
            is_sidechain: false,
            user_type: VIEW_USER_TYPE.to_string(),
            cwd: t.mac_cwd.to_string(),
            session_id: t.session_id.to_string(),
            version: version.clone(),
            git_branch: branch.clone(),
            entrypoint: VIEW_ENTRYPOINT.to_string(),
            kind: e.role,
            message: ViewMessage { role: e.role, content },
            uuid: uuid.clone(),
            timestamp,
        };
        push(&mut out, &line)?;
        parent = Some(uuid);
    }
    Ok((out, reply.entries.len(), masked))
}

/// Serialising either kind of line through one closure.
mod erased {
    pub trait Line {
        fn json(&self) -> serde_json::Result<String>;
    }
    impl Line for crate::wire::view::ViewLine {
        fn json(&self) -> serde_json::Result<String> {
            serde_json::to_string(self)
        }
    }
    impl Line for crate::wire::view::ViewTitleLine {
        fn json(&self) -> serde_json::Result<String> {
            serde_json::to_string(self)
        }
    }
}

/// What a session file holds now, read without following a symlink and
/// never blocking: `Ok(None)` when absent; `Err` (why it is left alone)
/// for a symlink, something not a regular file, more than [`EXISTING_MAX`]
/// bytes, or a transcript (a non-empty file whose head is no view). A file
/// whose non-empty lines are all Cursor's `custom-title` lines (a rename
/// before the first view: `renameSession` appends one) is a view to be:
/// its lines are carried into the view ([`custom_titles`]).
pub fn existing(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let file = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(format!("{} is a symlink: never written through", path.display())),
        Err(e) => return Err(format!("cannot open {}: {e}", path.display())),
    };
    let md = file.metadata().map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if md.len() > EXISTING_MAX {
        return Err(format!("{} is {} bytes: not a view of ai-env's, left alone", path.display(), md.len()));
    }
    let mut bytes = Vec::new();
    file.take(EXISTING_MAX + 1).read_to_end(&mut bytes).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !bytes.is_empty() && !is_view_head(&bytes[..bytes.len().min(VIEW_HEAD_READ)]) && !only_custom_titles(&bytes) {
        return Err(format!("{} holds a transcript, not a view: left alone", path.display()));
    }
    Ok(Some(bytes))
}

/// Whether every non-empty line of `file` is a top-level `custom-title`
/// line, none of them ai-env's, and there is one at least.
fn only_custom_titles(file: &[u8]) -> bool {
    let mut any = false;
    for line in file.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        if line.starts_with(VIEW_MARK_PREFIX.as_bytes()) {
            return false;
        }
        let kind = serde_json::from_slice::<serde_json::Value>(line).ok().and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string));
        if kind.as_deref() != Some(CUSTOM_TITLE_KIND) {
            return false;
        }
        any = true;
    }
    any
}

/// Whether `path` is a view: its first `VIEW_HEAD_READ` bytes (one regular
/// file, read without following a symlink, never blocking) begin with the mark.
#[must_use]
pub fn is_view_file(path: &Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path) else { return false };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return false;
    }
    let mut head = Vec::with_capacity(VIEW_HEAD_READ);
    file.take(VIEW_HEAD_READ as u64).read_to_end(&mut head).is_ok() && is_view_head(&head)
}

/// The `custom-title` lines of `file` (top-level `type` `custom-title`;
/// none of ai-env's own lines), the newest [`CUSTOM_TITLES_MAX`], each at
/// most [`CUSTOM_TITLE_LINE_MAX`] bytes, byte for byte with their newline.
#[must_use]
pub fn custom_titles(file: &[u8]) -> Vec<Vec<u8>> {
    let mut found: Vec<Vec<u8>> = Vec::new();
    for line in file.split(|b| *b == b'\n') {
        if is_carried_title(line) {
            let mut l = line.to_vec();
            l.push(b'\n');
            found.push(l);
        }
    }
    let skip = found.len().saturating_sub(CUSTOM_TITLES_MAX);
    found.split_off(skip)
}

/// [`custom_titles`]' test of one line (without its newline): a top-level
/// `custom-title` line of at most [`CUSTOM_TITLE_LINE_MAX`] bytes, none of
/// ai-env's own (marked) lines. S12's [`renames_of`] takes the same lines.
fn is_carried_title(line: &[u8]) -> bool {
    if line.is_empty() || line.len() > CUSTOM_TITLE_LINE_MAX || line.starts_with(VIEW_MARK_PREFIX.as_bytes()) {
        return false;
    }
    let kind = serde_json::from_slice::<serde_json::Value>(line).ok().and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string));
    kind.as_deref() == Some(CUSTOM_TITLE_KIND)
}

/// The project directory of `t`, a real directory made 0700 when missing
/// (its parent created as needed); a symlink or a slug that is not one path
/// component is refused.
fn project_dir(t: &ViewTarget<'_>) -> Result<PathBuf, String> {
    if let Some(dir) = existing_project_dir(t)? {
        return Ok(dir);
    }
    let dir = t.mac_projects.join(t.slug);
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

/// [`project_dir`]'s checks without its create: the project directory of
/// `t` when it is a real directory (`Ok(Some)`), `Ok(None)` when nothing is
/// there; a symlink, something not a directory, a slug that is not one path
/// component or an id that is no uuid is refused. S12 (§T3 V1): the title's
/// ensure never makes a directory.
fn existing_project_dir(t: &ViewTarget<'_>) -> Result<Option<PathBuf>, String> {
    let ok = !t.slug.is_empty() && t.slug != "." && t.slug != ".." && !t.slug.contains('/') && !t.slug.contains('\0');
    if !ok || !crate::bridge::registry::is_uuid(t.session_id) {
        return Err(format!("{:?}/{:?} is not a project directory and a session id", t.slug, t.session_id));
    }
    let dir = t.mac_projects.join(t.slug);
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.file_type().is_symlink() => Err(format!("{} is a symlink: never written through", dir.display())),
        Ok(m) if !m.is_dir() => Err(format!("{} is not a directory", dir.display())),
        Ok(_) => Ok(Some(dir)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot stat {}: {e}", dir.display())),
    }
}

/// Write `reply`'s view for `t` (the module doc; rules 1 to 4 of
/// plans/s9-contracts.md §6.3): [`render`]ed, the existing file's
/// [`custom_titles`] appended, then written atomically unless the file holds
/// exactly those bytes. A refusal (`ViewOutcome::Refused`, the old file
/// kept) is the reply's shape, a symlink on the way, or a transcript at the
/// path; an I/O failure of the write itself is the error. A render of no
/// line at all (no title in the tail, no message left: `view_messages = 1`
/// after a turn) never replaces a view (`Unchanged`, the old one kept) and
/// never writes a file of Cursor's lines alone, which would read as a
/// transcript (`Refused`): a view file always starts with a marked line.
pub fn write_view(t: &ViewTarget<'_>, reply: &TranscriptViewReply, n: u32, rules: &Rules) -> Result<ViewOutcome, BridgeError> {
    write_view_carrying(t, reply, n, rules, &[])
}

/// [`write_view`] with the time and the uuid minter given (tests).
pub fn write_view_with(t: &ViewTarget<'_>, reply: &TranscriptViewReply, n: u32, rules: &Rules, now: &str, mint: &mut dyn FnMut() -> String) -> Result<ViewOutcome, BridgeError> {
    write_view_carrying_with(t, reply, n, rules, &[], now, mint)
}

/// S12 (T, Bug 2): [`write_view`] carrying `renames` (§T3 S6). With no renames it is [`write_view`], byte for byte.
///
/// `renames` are a staged chat's own `custom-title` lines ([`renames_of`]'s), read before its original went:
/// after the rendered lines, `renames`, then the existing file's own [`custom_titles`], an identical line once
/// at its newest place, the newest [`CUSTOM_TITLES_MAX`]. A render of no line is still never written over a view.
pub fn write_view_carrying(t: &ViewTarget<'_>, reply: &TranscriptViewReply, n: u32, rules: &Rules, renames: &[Vec<u8>]) -> Result<ViewOutcome, BridgeError> {
    let now = crate::wire::time::rfc3339_utc_ms(crate::wire::time::unix_now_ms());
    write_view_carrying_with(t, reply, n, rules, renames, &now, &mut || uuid::Uuid::now_v7().to_string())
}

/// [`write_view_carrying`] with the time and the uuid minter given (tests).
///
/// With `renames` empty the carry is S9's, byte for byte (D8: no dedup), so `view_keeps_mac_custom_title` and the
/// golden view are unchanged.
pub fn write_view_carrying_with(t: &ViewTarget<'_>, reply: &TranscriptViewReply, n: u32, rules: &Rules, renames: &[Vec<u8>], now: &str, mint: &mut dyn FnMut() -> String) -> Result<ViewOutcome, BridgeError> {
    let dir = match project_dir(t) {
        Ok(d) => d,
        Err(why) => return Ok(ViewOutcome::Refused(why)),
    };
    let path = dir.join(format!("{}.jsonl", t.session_id));
    let old = match existing(&path) {
        Ok(old) => old,
        Err(why) => return Ok(ViewOutcome::Refused(why)),
    };
    let (mut bytes, messages, masked) = match render(reply, n, rules, t, now, mint) {
        Ok(r) => r,
        Err(why) => return Ok(ViewOutcome::Refused(why)),
    };
    if bytes.is_empty() {
        return Ok(match old {
            Some(view) if is_view_head(&view[..view.len().min(VIEW_HEAD_READ)]) => ViewOutcome::Unchanged { messages: 0, masked: 0, bytes: view.len() as u64 },
            _ => ViewOutcome::Refused("the view has no message and no title".into()),
        });
    }
    let carried = custom_titles(old.as_deref().unwrap_or_default());
    // S12 (T, §T3 S6): a staged chat's renames, then the file's own lines, each once at its newest place.
    let carried = if renames.is_empty() { carried } else { newest_once(renames.iter().cloned().chain(carried).collect()) };
    for line in carried {
        bytes.extend_from_slice(&line);
    }
    let len = bytes.len() as u64;
    if old.as_deref() == Some(bytes.as_slice()) {
        return Ok(ViewOutcome::Unchanged { messages, masked, bytes: len });
    }
    crate::bridge::infra::write_atomic_mode(&path, &bytes, 0o600)?;
    Ok(ViewOutcome::Written { messages, masked, bytes: len })
}

// ---- S12 (T): the chat's name in its view (plans/s12-contracts.md §T1.5, §T3 V1 to V6, S5, S6) ----------------

/// `lines` with an identical line kept once, at its newest (last) place, then the newest [`CUSTOM_TITLES_MAX`] of
/// them, in their order (§T3 S5, S6: the picker shows the last rename, so a dedup keeping the first place would
/// show an older one).
fn newest_once(lines: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut seen = std::collections::HashSet::new();
    let mut kept: Vec<Vec<u8>> = lines.into_iter().rev().filter(|l| seen.insert(l.clone())).collect();
    kept.truncate(CUSTOM_TITLES_MAX);
    kept.reverse();
    kept
}

/// The `customTitle` of one `custom-title` line (without its newline), as written; `None` when it holds no string.
fn custom_title_of(line: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(line).ok()?;
    v.get("customTitle")?.as_str().map(str::to_string)
}

/// S12 (T): the newest `custom-title` line's `customTitle` of `file` (the last of [`custom_titles`]), as written.
#[must_use]
pub fn newest_custom_title(file: &[u8]) -> Option<String> {
    let last = custom_titles(file).pop()?;
    custom_title_of(last.strip_suffix(b"\n").unwrap_or(&last))
}

/// S12 (T): the title the picker shows for a view's bytes, through `title::clean`: the newest `custom-title`
/// line's (`Custom`; `None` when `clean` drops it), else the first line's `aiTitle` when it is the marked
/// `ai-title` line (`Ai`), never `s3::sync::PLACEHOLDER_TITLE`.
///
/// §T3 V5: the picker's order (§T0.2 item 5), the newest rename before any AI title; a rename `clean` drops shows no
/// title rather than an older one. The placeholder's title is no chat's name.
#[must_use]
pub fn shown_title(file: &[u8], rules: &Rules) -> Option<SessionTitle> {
    if let Some(rename) = newest_custom_title(file) {
        return title::clean(&rename, rules).ok().map(|text| SessionTitle { text, source: TitleSource::Custom });
    }
    let first = file.split(|b| *b == b'\n').next().filter(|l| l.starts_with(VIEW_MARK_PREFIX.as_bytes()))?;
    let line: ViewTitleLine = serde_json::from_slice(first).ok()?;
    if line.ai_env_view != VIEW_V || line.kind != TITLE_KIND || line.ai_title == crate::bridge::s3::sync::PLACEHOLDER_TITLE {
        return None;
    }
    title::clean(&line.ai_title, rules).ok().map(|text| SessionTitle { text, source: TitleSource::Ai })
}

/// S12 (T): [`newest_custom_title`] of the file at `path` as [`existing`] reads it (a view, or Cursor's lines
/// alone), raw; `None` for anything else.
///
/// §T3 V6, L1: a startup frame's answer, a rename made in Cursor while the chat was closed; the pump cleans it (P4).
#[must_use]
pub fn view_rename(path: &Path) -> Option<String> {
    existing(path).ok().flatten().as_deref().and_then(newest_custom_title)
}

/// S12 (T): `t`'s view ends with `e`'s title (§T3 V1 to V4), and the view's [`shown_title`] after the step
/// (`None` with `NoView`). An I/O failure of the write is the error.
///
/// Only a marked view (V1), past [`project_dir`]'s checks without its create: nothing there, a missing project
/// directory, Cursor's lines alone, a transcript, a symlink or a file over [`EXISTING_MAX`] is `NoView`, nothing
/// created or written. `Already` (V2): the newest `custom-title` line says `e.text` (normalized), or `e` is a
/// startup's (`only_if_none`) and the view holds any. `Appended` (V3, D3): the file rebuilt as its marked lines in
/// order, then its [`custom_titles`] with `title::custom_title_line(e.session, e.text)` appended, the newest
/// [`CUSTOM_TITLES_MAX`] of them, written atomically 0600; a burst of names never grows the view past
/// [`EXISTING_MAX`]. The line is unmarked and in the extension's shape (V4): every later write carries it as one of
/// Cursor's, the kill switch reads only the marked head, and the picker shows it as the newest rename.
pub fn ensure_custom_title(t: &ViewTarget<'_>, e: &Ensure, rules: &Rules) -> Result<(Ensured, Option<SessionTitle>), BridgeError> {
    let Ok(Some(dir)) = existing_project_dir(t) else { return Ok((Ensured::NoView, None)) };
    let path = dir.join(format!("{}.jsonl", t.session_id));
    let bytes = match existing(&path) {
        Ok(Some(bytes)) if is_view_head(&bytes[..bytes.len().min(VIEW_HEAD_READ)]) => bytes,
        _ => return Ok((Ensured::NoView, None)),
    };
    let titles = custom_titles(&bytes);
    let newest_says_it = newest_custom_title(&bytes).is_some_and(|newest| title::normalize(&newest) == e.text);
    if newest_says_it || (e.only_if_none && !titles.is_empty()) {
        return Ok((Ensured::Already, shown_title(&bytes, rules)));
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 1024);
    for line in bytes.split(|b| *b == b'\n').filter(|l| l.starts_with(VIEW_MARK_PREFIX.as_bytes())) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    let mut titles = titles;
    titles.push(title::custom_title_line(&e.session, &e.text));
    let skip = titles.len().saturating_sub(CUSTOM_TITLES_MAX);
    for line in &titles[skip..] {
        out.extend_from_slice(line);
    }
    crate::bridge::infra::write_atomic_mode(&path, &out, 0o600)?;
    Ok((Ensured::Appended, shown_title(&out, rules)))
}

/// S12 (T, Bug 2): the `custom-title` lines a staged chat's view carries, read before its original goes
/// (§T3 S5): those of `tail` (`s3::stage::tail_of`'s), else, when it holds none and `main` is longer than
/// `VIEW_TAIL_MAX`, those of `main`'s first `RENAME_HEAD_READ` bytes; byte for byte.
///
/// Each a line [`custom_titles`] would carry (uncapped), less a line a tripwire hits (its bytes, or its
/// `customTitle` unescaped) and one whose `customTitle` `wire::redact::scrub` would change; an identical line once,
/// at its newest place; the newest
/// [`CUSTOM_TITLES_MAX`]; each with its newline. A line is never rewritten: the CLI's and Cursor's key orders both
/// stay as they were written (§T0.2 item 4). The head is the picker's second place to look (§T0.2 item 5).
#[must_use]
pub fn renames_of(main: &Path, tail: &[u8], rules: &Rules) -> Vec<Vec<u8>> {
    let found = kept_renames(tail, rules);
    if !found.is_empty() {
        return found;
    }
    head_past_the_tail(main).map(|head| kept_renames(&head, rules)).unwrap_or_default()
}

/// [`renames_of`]'s lines of `bytes`. The tripwires judge both the line's bytes and its `customTitle` unescaped
/// (wave 1's fix round, §T3 S5 as amended): a term with one letter spelled as a JSON escape (a backslash, `u` and
/// `0066` for an `f`) passes the bytes' scan, yet the picker shows the term, since a line is carried byte for byte.
fn kept_renames(bytes: &[u8], rules: &Rules) -> Vec<Vec<u8>> {
    let clean = |line: &[u8]| rules.scan_bytes(line).is_empty() && custom_title_of(line).is_none_or(|t| rules.scan_bytes(t.as_bytes()).is_empty() && crate::wire::redact::scrub(&t) == t.as_str());
    let lines = bytes.split(|b| *b == b'\n').filter(|l| is_carried_title(l) && clean(l)).map(|l| [l, b"\n".as_slice()].concat()).collect();
    newest_once(lines)
}

/// `main`'s first [`RENAME_HEAD_READ`] bytes when it is a regular file (opened without following a symlink, never
/// blocking) longer than `VIEW_TAIL_MAX`: the head a view's tail left out.
fn head_past_the_tail(main: &Path) -> Option<Vec<u8>> {
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(main).ok()?;
    let md = file.metadata().ok()?;
    if !md.is_file() || md.len() <= VIEW_TAIL_MAX {
        return None;
    }
    let mut head = Vec::with_capacity(RENAME_HEAD_READ);
    file.take(RENAME_HEAD_READ as u64).read_to_end(&mut head).ok()?;
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::view::{ViewEntry, ViewRole};

    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const NOW: &str = "2026-10-18T09:00:00.000Z";

    /// plans/s9-contracts.md §6.1's example.
    fn example() -> TranscriptViewReply {
        serde_json::from_str(include_str!("../../tests/fixtures/view/reply.json")).unwrap()
    }

    fn target(projects: &Path) -> ViewTarget<'_> {
        ViewTarget { mac_projects: projects, slug: "-Users-mike-Documents-DeFi-ai-env", session_id: SID, mac_cwd: "/Users/mike/Documents/DeFi/ai-env" }
    }

    /// A minter of fixed v7-shaped uuids, counted.
    fn minter() -> impl FnMut() -> String {
        let mut n = 0u32;
        move || {
            n += 1;
            format!("0199a1b2-0000-7000-8000-{n:012x}")
        }
    }

    fn lines(bytes: &[u8]) -> Vec<serde_json::Value> {
        bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect()
    }

    fn render_of(reply: &TranscriptViewReply, rules: &Rules) -> (Vec<u8>, usize, usize) {
        let tmp = Path::new("/nonexistent");
        render(reply, 10, rules, &target(tmp), NOW, &mut minter()).unwrap()
    }

    /// The first message's `parentUuid` is null (written), every other's the
    /// line before it; the title line comes first and carries no chain; every
    /// line starts with the mark, its `cwd`, `sessionId` and `entrypoint` the
    /// Mac's.
    #[test]
    fn view_chain_first_parent_null() {
        let (bytes, messages, masked) = render_of(&example(), &Rules::defaults());
        assert_eq!((messages, masked), (2, 0));
        assert!(bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()).all(|l| l.starts_with(VIEW_MARK_PREFIX.as_bytes())), "{}", String::from_utf8_lossy(&bytes));
        let l = lines(&bytes);
        assert_eq!((l[0]["type"].as_str(), l[0]["aiTitle"].as_str(), l[0].get("parentUuid")), (Some("ai-title"), Some("Fix the seed's shallow boundary"), None));
        assert!(l[1].get("parentUuid").is_some_and(serde_json::Value::is_null), "written, null: {}", l[1]);
        assert_eq!(l[2]["parentUuid"], l[1]["uuid"]);
        for e in &l[1..] {
            assert_eq!((e["cwd"].as_str(), e["sessionId"].as_str(), e["entrypoint"].as_str(), e["isSidechain"].as_bool(), e["userType"].as_str()), (Some("/Users/mike/Documents/DeFi/ai-env"), Some(SID), Some("claude-vscode"), Some(false), Some("external")));
        }
        // Three messages chain through each other; none chains to the title.
        let mut three = example();
        three.entries.push(ViewEntry { role: ViewRole::User, uuid: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a62".into(), timestamp: "2026-10-17T10:16:00.000Z".into(), blocks: vec!["thanks".into()] });
        let l = lines(&render_of(&three, &Rules::defaults()).0);
        assert_eq!((l[3]["parentUuid"].as_str(), l[3]["type"].as_str()), (Some("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61"), Some("user")));
    }

    /// A block with a tripwire hit becomes `[ai-env: masked, rule R]`, the
    /// rest of its message kept; a title with one is dropped (no title line);
    /// the counts say how many were masked; no value reaches the file.
    #[test]
    fn view_masks_tripwires() {
        let key = format!("{}{}", "AKIA", "Q".repeat(16));
        let mut r = example();
        r.entries[1].blocks[0] = format!("the key is {key}");
        r.title = Some(format!("leak {key}"));
        let (bytes, messages, masked) = render_of(&r, &Rules::defaults());
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!((messages, masked), (2, 1));
        assert!(!text.contains(&key) && !text.contains("ai-title"), "{text}");
        let l = lines(text.as_bytes());
        assert_eq!(l[1]["message"]["content"][0]["text"].as_str(), Some(masked_text("aws-access-key-id").as_str()));
        assert_eq!(l[1]["message"]["content"][1]["text"].as_str(), Some("[tool: Bash]"), "the other blocks stay");
        // A rule of [review].tripwires masks too.
        let extra = Rules::with_extras("swordfish\n", "tripwires.txt").unwrap();
        r.entries[0].blocks[0] = "the password is swordfish".into();
        let (bytes, _, masked) = render_of(&r, &extra);
        assert_eq!(masked, 2);
        assert!(!String::from_utf8_lossy(&bytes).contains("swordfish"));
        // The branch is the one free-text field on every line: one git would take but a tripwire hits is written empty.
        let mut b = example();
        b.git_branch = Some(key.clone());
        assert!(crate::wire::workspace::branch_check(&key).is_ok(), "a name git takes");
        let text = String::from_utf8(render_of(&b, &Rules::defaults()).0).unwrap();
        assert!(!text.contains(&key), "{text}");
        assert!(lines(text.as_bytes())[1..].iter().all(|l| l["gitBranch"] == ""), "{text}");
        b.git_branch = Some("swordfish-fix".into());
        assert!(lines(&render_of(&b, &extra).0)[1..].iter().all(|l| l["gitBranch"] == ""));
        assert!(lines(&render_of(&b, &Rules::defaults()).0)[1..].iter().all(|l| l["gitBranch"] == "swordfish-fix"), "kept without a hit");
    }

    /// The reply is refused whole when its shape is not one `check` takes (an
    /// unknown key never parses; more messages than asked; a reply first);
    /// uuids and timestamps that are no uuid or no RFC 3339 time are minted
    /// anew (the chain then uses the new uuid), a version that is not N.N.N
    /// and a branch git would not take are written empty.
    #[test]
    fn view_rejects_extra_keys_bad_uuids() {
        let text = include_str!("../../tests/fixtures/view/reply.json");
        assert!(serde_json::from_str::<TranscriptViewReply>(&text.replacen("\"present\":true,", "\"present\":true,\"isMeta\":true,", 1)).is_err(), "an unknown key is refused");
        assert!(serde_json::from_str::<TranscriptViewReply>(&text.replacen("\"role\":\"assistant\",", "\"role\":\"assistant\",\"teamName\":\"x\",", 1)).is_err());
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        let refuse = |r: &TranscriptViewReply, n: u32| render(r, n, &Rules::defaults(), &t, NOW, &mut minter()).unwrap_err();
        assert!(refuse(&example(), 1).contains("2 messages (at most 1)"));
        let mut reply_first = example();
        reply_first.entries.reverse();
        assert!(refuse(&reply_first, 10).contains("user's message"));
        let mut bad = example();
        bad.entries[0].uuid = "not-a-uuid".into();
        bad.entries[0].timestamp = "yesterday".into();
        bad.version = Some("2.1.302-beta; rm -rf".into());
        bad.git_branch = Some("dev..x".into());
        let l = lines(&render(&bad, 10, &Rules::defaults(), &t, NOW, &mut minter()).unwrap().0);
        assert_eq!((l[1]["uuid"].as_str(), l[1]["timestamp"].as_str()), (Some("0199a1b2-0000-7000-8000-000000000001"), Some(NOW)));
        assert_eq!(l[2]["parentUuid"].as_str(), Some("0199a1b2-0000-7000-8000-000000000001"), "the chain uses the minted uuid");
        assert_eq!((l[1]["version"].as_str(), l[1]["gitBranch"].as_str()), (Some(""), Some("")));
        // A uuid that repeats an earlier line's is minted anew: no line is its own parent, no uuid is written twice.
        let mut twice = example();
        twice.entries[1].uuid = twice.entries[0].uuid.to_ascii_uppercase();
        twice.entries.push(ViewEntry { role: ViewRole::User, uuid: twice.entries[0].uuid.clone(), timestamp: "2026-10-17T10:16:00.000Z".into(), blocks: vec!["again".into()] });
        let l = lines(&render(&twice, 10, &Rules::defaults(), &t, NOW, &mut minter()).unwrap().0);
        let uuids: Vec<&str> = l[1..].iter().map(|e| e["uuid"].as_str().unwrap()).collect();
        assert_eq!(uuids, ["0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60", "0199a1b2-0000-7000-8000-000000000001", "0199a1b2-0000-7000-8000-000000000002"]);
        assert!(l[1..].iter().all(|e| e["parentUuid"] != e["uuid"]), "never its own parent");
        assert_eq!((l[2]["parentUuid"].as_str(), l[3]["parentUuid"].as_str()), (Some(uuids[0]), Some(uuids[1])), "the chain uses the minted uuids");
        // A minter that repeats itself is refused rather than written into a cycle.
        let mut same = || "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60".to_string();
        assert!(render(&twice, 10, &Rules::defaults(), &t, NOW, &mut same).unwrap_err().contains("repeats"));
        // A refused reply leaves the old view in place, and says why.
        let first = write_view_with(&t, &example(), 10, &Rules::defaults(), NOW, &mut minter()).unwrap();
        assert!(matches!(first, ViewOutcome::Written { messages: 2, masked: 0, .. }), "{first:?}");
        let before = std::fs::read(t.path()).unwrap();
        let refused = write_view_with(&t, &reply_first, 10, &Rules::defaults(), NOW, &mut minter()).unwrap();
        assert!(matches!(&refused, ViewOutcome::Refused(why) if why.contains("user's message")), "{refused:?}");
        assert_eq!((refused.word(), std::fs::read(t.path()).unwrap()), ("refused", before));
    }

    /// Cursor's own `custom-title` lines (a rename) survive every rewrite,
    /// byte for byte, after the view's lines, the newest 16 only; the
    /// view's own lines are never carried twice; unchanged bytes are not
    /// rewritten; a transcript or a symlink at the path is left alone.
    #[test]
    fn view_keeps_mac_custom_title() {
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        assert!(matches!(write_view_with(&t, &example(), 10, &Rules::defaults(), NOW, &mut minter()).unwrap(), ViewOutcome::Written { .. }));
        let rename = format!("{{\"type\":\"custom-title\",\"customTitle\":\"My \\u2028title\",\"sessionId\":\"{SID}\"}}");
        let mut file = std::fs::OpenOptions::new().append(true).open(t.path()).unwrap();
        std::io::Write::write_all(&mut file, format!("{rename}\n").as_bytes()).unwrap();
        drop(file);
        let mut longer = example();
        longer.entries[1].blocks.push("And the test.".into());
        assert!(matches!(write_view_with(&t, &longer, 10, &Rules::defaults(), NOW, &mut minter()).unwrap(), ViewOutcome::Written { .. }));
        let text = std::fs::read_to_string(t.path()).unwrap();
        assert!(text.ends_with(&format!("{rename}\n")), "carried last, byte for byte: {text}");
        assert_eq!(text.matches("custom-title").count(), 1);
        assert_eq!(text.matches("\"ai-title\"").count(), 1, "the view's own title line is rewritten, never carried");
        assert!(text.contains("And the test."));
        // The same reply again: unchanged, not rewritten.
        let mtime = std::fs::metadata(t.path()).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let again = write_view_with(&t, &longer, 10, &Rules::defaults(), NOW, &mut minter()).unwrap();
        assert!(matches!(again, ViewOutcome::Unchanged { messages: 2, .. }), "{again:?}");
        assert_eq!(std::fs::metadata(t.path()).unwrap().modified().unwrap(), mtime);
        // The newest 16 of 20 renames.
        let mut file = std::fs::OpenOptions::new().append(true).open(t.path()).unwrap();
        for i in 0..20 {
            std::io::Write::write_all(&mut file, format!("{{\"type\":\"custom-title\",\"customTitle\":\"t{i}\"}}\n").as_bytes()).unwrap();
        }
        drop(file);
        write_view_with(&t, &example(), 10, &Rules::defaults(), NOW, &mut minter()).unwrap();
        let text = std::fs::read_to_string(t.path()).unwrap();
        assert_eq!(text.matches("custom-title").count(), CUSTOM_TITLES_MAX);
        assert!(text.contains("\"t19\"") && text.contains("\"t4\"") && !text.contains("\"t3\"") && !text.contains("My "), "{text}");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(t.path()).unwrap().permissions().mode() & 0o777, 0o600);
        // A transcript at the path (a chat begun on this Mac) is never replaced.
        std::fs::write(t.path(), "{\"type\":\"user\",\"message\":{\"content\":\"hi\"}}\n").unwrap();
        let o = write_view_with(&t, &example(), 10, &Rules::defaults(), NOW, &mut minter()).unwrap();
        assert!(matches!(&o, ViewOutcome::Refused(why) if why.contains("holds a transcript")), "{o:?}");
        // Nor a symlink.
        std::fs::remove_file(t.path()).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("elsewhere.jsonl"), t.path()).unwrap();
        let o = write_view_with(&t, &example(), 10, &Rules::defaults(), NOW, &mut minter()).unwrap();
        assert!(matches!(&o, ViewOutcome::Refused(why) if why.contains("symlink")), "{o:?}");
        assert!(!tmp.path().join("elsewhere.jsonl").exists());
    }

    /// S9 phase 4 (T9): a render of no line (no title in the tail, no
    /// message left, as `view_messages = 1` gives after a turn) never
    /// replaces a view (unchanged, the old one kept) and never writes a
    /// file of Cursor's lines alone, which would read as a transcript from
    /// then on (refused, nothing written). A file of Cursor's
    /// `custom-title` lines alone (a rename before the first view) is a
    /// view to be: the next view replaces it, carrying them.
    #[test]
    fn an_empty_render_never_writes_a_file_without_the_mark() {
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        let empty = TranscriptViewReply { title: None, entries: Vec::new(), ..example() };
        let o = write_view_with(&t, &empty, 10, &Rules::defaults(), NOW, &mut minter()).unwrap();
        assert!(matches!(&o, ViewOutcome::Refused(why) if why == "the view has no message and no title"), "{o:?}");
        assert!(!t.path().exists(), "nothing written");
        assert!(matches!(write_view_with(&t, &example(), 10, &Rules::defaults(), NOW, &mut minter()).unwrap(), ViewOutcome::Written { .. }));
        let view = std::fs::read(t.path()).unwrap();
        let rename = format!("{{\"type\":\"custom-title\",\"customTitle\":\"Mine\",\"sessionId\":\"{SID}\"}}\n");
        let mut with_rename = view.clone();
        with_rename.extend_from_slice(rename.as_bytes());
        std::fs::write(t.path(), &with_rename).unwrap();
        let o = write_view_with(&t, &empty, 10, &Rules::defaults(), NOW, &mut minter()).unwrap();
        assert!(matches!(o, ViewOutcome::Unchanged { .. }), "{o:?}");
        assert_eq!(std::fs::read(t.path()).unwrap(), with_rename, "the old view stays, its rename too");
        assert!(is_view_file(&t.path()));
        // Cursor's lines alone: refused by an empty render (never written without the mark), replaced by a view.
        std::fs::write(t.path(), &rename).unwrap();
        assert!(matches!(existing(&t.path()), Ok(Some(_))), "a view to be");
        let o = write_view_with(&t, &empty, 10, &Rules::defaults(), NOW, &mut minter()).unwrap();
        assert!(matches!(&o, ViewOutcome::Refused(_)), "{o:?}");
        assert_eq!(std::fs::read_to_string(t.path()).unwrap(), rename);
        assert!(matches!(write_view_with(&t, &example(), 10, &Rules::defaults(), NOW, &mut minter()).unwrap(), ViewOutcome::Written { .. }));
        let text = std::fs::read_to_string(t.path()).unwrap();
        assert!(text.starts_with(VIEW_MARK_PREFIX) && text.ends_with(&rename), "{text}");
        // A file with any other line is still a transcript.
        std::fs::write(t.path(), format!("{rename}{{\"type\":\"user\",\"message\":{{\"content\":\"hi\"}}}}\n")).unwrap();
        assert!(existing(&t.path()).is_err());
    }

    /// The golden view (extension 2.1.302): tests/fixtures/view/reply.json
    /// (§6.1's example) rendered for the session at the Mac's cwd is
    /// tests/fixtures/view/golden.jsonl byte for byte, and its lines have
    /// the shape the extension's readers take (plans/s9-design-s3.md): the
    /// picker's `aiTitle` in the head, no sidechain line, no `sdk-*`
    /// entrypoint; a reopen's chain from the leaf (the last line no line
    /// names as its parent) back to a null parent through `user` and
    /// `assistant` entries with a string uuid, none `isMeta`, none with a
    /// `teamName`, each message's role its type and its content text blocks.
    #[test]
    fn view_golden_matches_extension_reader_shape() {
        let golden = include_bytes!("../../tests/fixtures/view/golden.jsonl");
        let (bytes, _, _) = render_of(&example(), &Rules::defaults());
        assert_eq!(String::from_utf8_lossy(&bytes), String::from_utf8_lossy(golden), "the golden view");
        let text = std::str::from_utf8(golden).unwrap();
        assert!(!text.contains("\"isSidechain\":true") && !text.contains("\"entrypoint\":\"sdk-"), "the picker drops neither");
        assert!(text[..text.len().min(65536)].contains("\"aiTitle\":\"Fix the seed's shallow boundary\""), "the picker's title in the head");
        let l = lines(golden);
        let entries: Vec<&serde_json::Value> = l.iter().filter(|e| e["type"] == "user" || e["type"] == "assistant").collect();
        let named: std::collections::BTreeSet<&str> = entries.iter().filter_map(|e| e["parentUuid"].as_str()).collect();
        let leaf = entries.iter().rev().find(|e| !named.contains(e["uuid"].as_str().unwrap())).unwrap();
        let mut at = Some(*leaf);
        let mut walked = 0;
        while let Some(e) = at {
            assert!(e["uuid"].is_string() && e.get("isMeta").is_none() && e.get("teamName").is_none() && e["isSidechain"] == false, "{e}");
            assert_eq!(e["message"]["role"], e["type"]);
            assert!(e["message"]["content"].as_array().unwrap().iter().all(|b| b["type"] == "text" && b["text"].is_string()), "{e}");
            walked += 1;
            at = e["parentUuid"].as_str().and_then(|p| entries.iter().find(|x| x["uuid"] == p).copied());
        }
        assert_eq!(walked, entries.len(), "the chain from the leaf reaches every message, back to a null parent");
        assert!(text.lines().all(|line| line.starts_with(VIEW_MARK_PREFIX)), "the kill switch's prefix on every line");
    }

    // ---- S12 (T): the chat's name in its view (plans/s12-contracts.md §T8.1) ----

    /// Cursor's rename line of `name` (the extension's key order: `sessionId` first).
    fn cursor_line(name: &str) -> Vec<u8> {
        format!("{{\"type\":\"custom-title\",\"sessionId\":\"{SID}\",\"customTitle\":{}}}\n", serde_json::to_string(name).unwrap()).into_bytes()
    }

    /// The CLI's rename line of `name` (its key order: `customTitle` first).
    fn cli_line(name: &str) -> Vec<u8> {
        format!("{{\"type\":\"custom-title\",\"customTitle\":{},\"sessionId\":\"{SID}\"}}\n", serde_json::to_string(name).unwrap()).into_bytes()
    }

    /// `bytes` appended to the file at `path`.
    fn append(path: &Path, bytes: &[u8]) {
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        std::io::Write::write_all(&mut f, bytes).unwrap();
    }

    /// The marked view of [`example`] at `t`: its bytes.
    fn marked_view(t: &ViewTarget<'_>) -> Vec<u8> {
        assert!(matches!(write_view_with(t, &example(), 10, &Rules::defaults(), NOW, &mut minter()).unwrap(), ViewOutcome::Written { .. }));
        std::fs::read(t.path()).unwrap()
    }

    fn ensure(text: &str, only_if_none: bool) -> Ensure {
        Ensure { session: SID.into(), text: text.into(), only_if_none }
    }

    fn custom(text: &str) -> Option<SessionTitle> {
        Some(SessionTitle { text: text.into(), source: TitleSource::Custom })
    }

    /// §T3 V1, V3: over a marked view holding Cursor's rename `A`, an ensure of `B` rebuilds the file as its marked
    /// lines, `A`'s line, then ai-env's line of `B` (the extension's shape, unmarked), 0600; the view then shows `B`.
    #[test]
    fn ensure_appends_ai_envs_line_after_the_carried_ones() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        let marked = marked_view(&t);
        append(&t.path(), &cursor_line("A"));
        let got = ensure_custom_title(&t, &ensure("B", false), &Rules::defaults()).unwrap();
        assert_eq!(got, (Ensured::Appended, custom("B")));
        assert_eq!(String::from_utf8(std::fs::read(t.path()).unwrap()).unwrap(), String::from_utf8([marked, cursor_line("A"), title::custom_title_line(SID, "B")].concat()).unwrap(), "the marked lines, A's line, then ai-env's");
        assert_eq!(std::fs::metadata(t.path()).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(is_view_file(&t.path()), "still a view");
    }

    /// §T3 V2: the newest `custom-title` line saying the name already (normalized: Cursor's `My  name` for `My name`)
    /// is `Already`: the file's bytes and its mtime unchanged.
    #[test]
    fn ensure_writes_nothing_when_the_newest_already_says_it() {
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        marked_view(&t);
        append(&t.path(), &cursor_line("Older"));
        append(&t.path(), &cursor_line("My  name"));
        let (before, mtime) = (std::fs::read(t.path()).unwrap(), std::fs::metadata(t.path()).unwrap().modified().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(20));
        let got = ensure_custom_title(&t, &ensure("My name", false), &Rules::defaults()).unwrap();
        assert_eq!(got, (Ensured::Already, custom("My name")));
        assert_eq!((std::fs::read(t.path()).unwrap(), std::fs::metadata(t.path()).unwrap().modified().unwrap()), (before, mtime), "nothing written");
        // An older line saying it is not the newest: written.
        assert_eq!(ensure_custom_title(&t, &ensure("Older", false), &Rules::defaults()).unwrap().0, Ensured::Appended);
    }

    /// §T3 V2, P7: a startup's ensure (`only_if_none`) over a view holding any rename is `Already` (a rename made in
    /// Cursor while the chat was closed stays the newest); over one holding none it is written.
    #[test]
    fn a_startup_ensure_never_follows_a_rename() {
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        marked_view(&t);
        append(&t.path(), &cursor_line("Picked in Cursor"));
        let before = std::fs::read(t.path()).unwrap();
        let got = ensure_custom_title(&t, &ensure("From the CLI", true), &Rules::defaults()).unwrap();
        assert_eq!(got, (Ensured::Already, custom("Picked in Cursor")));
        assert_eq!(std::fs::read(t.path()).unwrap(), before);
        // A view holding no rename (one lost before S12): the startup's name goes in.
        let fresh = tempfile::tempdir().unwrap();
        let t = target(fresh.path());
        let marked = marked_view(&t);
        assert!(custom_titles(&marked).is_empty(), "a fresh view");
        assert_eq!(ensure_custom_title(&t, &ensure("From the CLI", true), &Rules::defaults()).unwrap(), (Ensured::Appended, custom("From the CLI")));
        assert_eq!(std::fs::read(t.path()).unwrap(), [marked, title::custom_title_line(SID, "From the CLI")].concat());
    }

    /// §T3 V1: no marked view, no write: a missing project directory (none is made), a missing file (none is
    /// created), a transcript, a symlink (its target untouched), a symlinked project directory, Cursor's lines alone
    /// (a view to be) and a bad id are each `NoView`, nothing created or changed.
    #[test]
    fn ensure_never_touches_a_missing_file_a_transcript_a_symlink_or_cursors_lines_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = Rules::defaults();
        let e = ensure("Harbour-s12 named", false);
        let projects = tmp.path().join("projects");
        let t = target(&projects);
        assert_eq!(ensure_custom_title(&t, &e, &rules).unwrap(), (Ensured::NoView, None));
        assert!(!projects.exists(), "no project directory made");
        std::fs::create_dir_all(t.path().parent().unwrap()).unwrap();
        assert_eq!(ensure_custom_title(&t, &e, &rules).unwrap(), (Ensured::NoView, None));
        assert!(!t.path().exists(), "no file created");
        let transcript = b"{\"type\":\"user\",\"message\":{\"content\":\"hi\"}}\n".to_vec();
        let alone = cursor_line("Mine");
        for bytes in [&transcript, &alone] {
            std::fs::write(t.path(), bytes).unwrap();
            assert_eq!(ensure_custom_title(&t, &e, &rules).unwrap(), (Ensured::NoView, None));
            assert_eq!(&std::fs::read(t.path()).unwrap(), bytes, "left as it was");
        }
        // A symlink at the path, to a marked view elsewhere: never written through.
        std::fs::remove_file(t.path()).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        let other = target(&elsewhere);
        let view = marked_view(&other);
        std::os::unix::fs::symlink(other.path(), t.path()).unwrap();
        assert_eq!(ensure_custom_title(&t, &e, &rules).unwrap(), (Ensured::NoView, None));
        assert_eq!(std::fs::read(other.path()).unwrap(), view, "the symlink's target untouched");
        // A symlinked project directory holding a marked view.
        let linked = tmp.path().join("linked");
        std::fs::create_dir_all(&linked).unwrap();
        std::os::unix::fs::symlink(other.path().parent().unwrap(), linked.join(other.slug)).unwrap();
        assert_eq!(ensure_custom_title(&target(&linked), &e, &rules).unwrap(), (Ensured::NoView, None));
        assert_eq!(std::fs::read(other.path()).unwrap(), view, "never written through the directory's link");
        // An id that is no uuid names no file.
        let bad = ViewTarget { session_id: "../x", ..other };
        assert_eq!(ensure_custom_title(&bad, &e, &rules).unwrap(), (Ensured::NoView, None));
    }

    /// §T3 V3, D3: 20 ensures of distinct names leave the newest 16 `custom-title` lines, the last the 20th name,
    /// and the view's marked lines byte for byte: an append-only ensure would grow the view toward `EXISTING_MAX`.
    #[test]
    fn ensure_keeps_the_newest_sixteen() {
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        let marked = marked_view(&t);
        for i in 1..=20 {
            assert_eq!(ensure_custom_title(&t, &ensure(&format!("name {i}"), false), &Rules::defaults()).unwrap().0, Ensured::Appended, "{i}");
        }
        let bytes = std::fs::read(t.path()).unwrap();
        let titles = custom_titles(&bytes);
        assert_eq!(titles.len(), CUSTOM_TITLES_MAX);
        assert_eq!((titles.first().cloned(), titles.last().cloned()), (Some(title::custom_title_line(SID, "name 5")), Some(title::custom_title_line(SID, "name 20"))));
        assert!(bytes.starts_with(&marked), "the marked lines as before");
        assert_eq!(bytes.len(), marked.len() + titles.iter().map(Vec::len).sum::<usize>(), "nothing else");
    }

    /// §T3 V5: the picker's title: the newest rename over the `ai-title` line, else the marked `ai-title` line's,
    /// never the placeholder's; a newest rename a tripwire hits shows none (never an older one).
    #[test]
    fn the_shown_title_is_the_pickers_and_never_the_placeholder() {
        use crate::bridge::s3::{S3Endpoint, S3Target, TranscriptSync, LAB_BUCKET, LAB_OWNER};
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        let rules = Rules::defaults();
        let marked = marked_view(&t);
        let ai = Some(SessionTitle { text: "Fix the seed's shallow boundary".into(), source: TitleSource::Ai });
        assert_eq!(shown_title(&marked, &rules), ai, "the ai-title line alone");
        assert_eq!(shown_title(&[marked.clone(), cursor_line("Mine")].concat(), &rules), custom("Mine"), "the newest rename over it");
        let extra = Rules::with_extras("swordfish\n", "tripwires.txt").unwrap();
        let hit = [marked.clone(), cursor_line("Mine"), cursor_line("the swordfish plan")].concat();
        assert_eq!(shown_title(&hit, &extra), None, "a newest rename a tripwire hits: none, never the older one");
        assert_eq!(shown_title(&hit, &rules), custom("the swordfish plan"));
        // The placeholder view: its title is no chat's name.
        let p = tmp.path().join("p");
        let placeholder = target(&p);
        let s3 = S3Target { bucket: LAB_BUCKET.into(), owner: LAB_OWNER.into(), endpoint: S3Endpoint::Lab("127.0.0.1:9".parse().unwrap()) };
        let sync = TranscriptSync { target: s3, slug: placeholder.slug.into(), mac_cwd: placeholder.mac_cwd.into(), mac_projects: placeholder.mac_projects.to_path_buf(), proxy: None, view_messages: 10 };
        crate::bridge::s3::sync::write_placeholder_view(&sync, SID, &rules).unwrap().expect("the placeholder written");
        let bytes = std::fs::read(placeholder.path()).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains(crate::bridge::s3::sync::PLACEHOLDER_TITLE));
        assert_eq!(shown_title(&bytes, &rules), None);
        assert_eq!(shown_title(&[bytes, cursor_line("Named")].concat(), &rules), custom("Named"), "a rename over the placeholder");
        assert_eq!(shown_title(b"", &rules), None);
    }

    /// §T3 V6: a startup's answer is the newest `custom-title` line's `customTitle`, as written (the pump cleans
    /// it), of a view or of Cursor's lines alone; none for nothing there or a transcript.
    #[test]
    fn view_rename_reads_the_newest_custom_title() {
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        marked_view(&t);
        append(&t.path(), &cursor_line("First"));
        append(&t.path(), &cli_line("Second  one"));
        assert_eq!(view_rename(&t.path()).as_deref(), Some("Second  one"), "the second, as written");
        assert_eq!(newest_custom_title(&std::fs::read(t.path()).unwrap()).as_deref(), Some("Second  one"));
        std::fs::write(t.path(), [cursor_line("First"), cursor_line("Second")].concat()).unwrap();
        assert_eq!(view_rename(&t.path()).as_deref(), Some("Second"), "Cursor's lines alone");
        std::fs::remove_file(t.path()).unwrap();
        assert_eq!(view_rename(&t.path()), None, "nothing there");
        std::fs::write(t.path(), [b"{\"type\":\"user\",\"message\":{\"content\":\"hi\"}}\n".to_vec(), cursor_line("In a transcript")].concat()).unwrap();
        assert_eq!(view_rename(&t.path()), None, "a transcript");
    }

    /// §T3 S6: a staged chat's renames go after the rendered lines, then the file's own, each identical line once
    /// at its newest place (`[A, B, A]` is `[B, A]`: the picker shows `A`, the last one); with no renames the bytes
    /// are S9's `write_view_with`'s, duplicates and all.
    #[test]
    fn write_view_carrying_puts_the_renames_last_once_at_their_newest_place() {
        let (a, b, c) = (cli_line("A"), cursor_line("B"), cursor_line("C"));
        let rules = Rules::defaults();
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        let rendered = render(&example(), 10, &rules, &t, NOW, &mut minter()).unwrap().0;
        let renames = [a.clone(), b.clone(), a.clone()];
        let o = write_view_carrying_with(&t, &example(), 10, &rules, &renames, NOW, &mut minter()).unwrap();
        assert!(matches!(o, ViewOutcome::Written { messages: 2, .. }), "{o:?}");
        assert_eq!(std::fs::read(t.path()).unwrap(), [rendered.clone(), b.clone(), a.clone()].concat(), "[B, A] after the rendered lines");
        assert_eq!(view_rename(&t.path()).as_deref(), Some("A"));
        append(&t.path(), &c);
        write_view_carrying_with(&t, &example(), 10, &rules, &renames, NOW, &mut minter()).unwrap();
        assert_eq!(std::fs::read(t.path()).unwrap(), [rendered.clone(), b.clone(), a.clone(), c.clone()].concat(), "[B, A, C]");
        // No renames: S9's carry, byte for byte (no dedup).
        let (carrying, s9) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (u, v) = (target(carrying.path()), target(s9.path()));
        for at in [&u, &v] {
            marked_view(at);
            append(&at.path(), &[a.clone(), b.clone(), a.clone()].concat());
        }
        write_view_with(&v, &example(), 10, &rules, NOW, &mut minter()).unwrap();
        write_view_carrying_with(&u, &example(), 10, &rules, &[], NOW, &mut minter()).unwrap();
        assert_eq!(std::fs::read(u.path()).unwrap(), std::fs::read(v.path()).unwrap());
        assert_eq!(std::fs::read(u.path()).unwrap(), [rendered, a.clone(), b, a].concat(), "duplicates kept, as S9 carries them");
    }

    /// §T3 S5: the tail's `custom-title` lines (the CLI's and Cursor's), byte for byte and in order; a line a
    /// tripwire hits, one whose `customTitle` the scrub would change and one over `CUSTOM_TITLE_LINE_MAX` left out;
    /// a tripwire's term with a letter written as a JSON escape (its bytes pass the scan, its `customTitle` holds the
    /// term: wave 1's fix round, M-T56) left out; a transcript of 65 MiB whose only rename is in its first 64 KiB
    /// (no rename in its tail) gives that one.
    #[test]
    fn renames_of_reads_the_tail_then_the_head_and_leaves_out_tripwire_hits() {
        use std::io::Write as _;
        let tmp = tempfile::tempdir().unwrap();
        let rules = Rules::defaults();
        let key = format!("{}{}", "AKIA", "Q".repeat(16));
        let session = format!("{}{}", "ASIA", "Q".repeat(16));
        assert!(rules.scan_bytes(session.as_bytes()).is_empty() && crate::wire::redact::scrub(&session) != session.as_str(), "the scrub's alone");
        let user = b"{\"type\":\"user\",\"message\":{\"content\":\"turn 1\"}}\n".to_vec();
        let (cli, cursor) = (cli_line("Harbour-s11 word memory"), cursor_line("Harbour-s11 word memory"));
        let tail = [user.clone(), cli_line(&format!("leak {key}")), cli.clone(), cursor_line(&format!("leak {session}")), cursor.clone(), cli_line(&"x".repeat(CUSTOM_TITLE_LINE_MAX))].concat();
        let main = tmp.path().join("small.jsonl");
        std::fs::write(&main, &tail).unwrap();
        assert_eq!(renames_of(&main, &tail, &rules), [cli.clone(), cursor.clone()], "byte for byte, in order");
        assert_eq!(renames_of(&main, &[cli.clone(), cursor.clone(), cli.clone()].concat(), &rules), [cursor.clone(), cli.clone()], "once, at the newest place");
        assert!(renames_of(&main, &user, &rules).is_empty(), "no rename, and a file under the tail's size has no head to read");
        // A tripwire's term with its `f` a JSON escape (the backslash built here): the line's bytes pass the scan,
        // its `customTitle` unescaped holds the term, so the picker would show it.
        let extra = Rules::with_extras("swordfish\n", "tripwires.txt").unwrap();
        let escaped = format!("{{\"type\":\"custom-title\",\"customTitle\":\"the sword{}u0066ish plan\",\"sessionId\":\"{SID}\"}}\n", '\\').into_bytes();
        assert!(extra.scan_bytes(&escaped).is_empty(), "the line's bytes pass the tripwires");
        assert_eq!(custom_title_of(escaped.strip_suffix(b"\n").unwrap()).as_deref(), Some("the swordfish plan"), "its text holds the term");
        assert_eq!(renames_of(&main, &[escaped, cli.clone()].concat(), &extra), std::slice::from_ref(&cli), "the escaped term left out, the clean line kept");
        // A 65 MiB transcript: its rename in the head alone.
        let big = tmp.path().join("big.jsonl");
        let early = cli_line("Early name");
        let mut f = std::io::BufWriter::new(std::fs::File::create(&big).unwrap());
        f.write_all(&user).unwrap();
        f.write_all(&early).unwrap();
        let filler = format!("{{\"type\":\"assistant\",\"pad\":\"{}\"}}\n", "y".repeat(1000));
        let mut written = (user.len() + early.len()) as u64;
        while written <= VIEW_TAIL_MAX + (1 << 20) {
            f.write_all(filler.as_bytes()).unwrap();
            written += filler.len() as u64;
        }
        drop(f);
        let tail = crate::bridge::s3::stage::tail_of(&big).unwrap();
        assert!(kept_renames(&tail, &rules).is_empty(), "the tail holds no rename");
        assert_eq!(renames_of(&big, &tail, &rules), [early], "the head's");
    }

    /// §T0.2 item 5: the picker reads the last `"customTitle":"` of a session file's last 64 KiB: after Cursor's
    /// rename and an ensure of another name, that is ai-env's line.
    #[test]
    fn the_pickers_last_custom_title_is_ai_envs_line() {
        let tmp = tempfile::tempdir().unwrap();
        let t = target(tmp.path());
        marked_view(&t);
        append(&t.path(), &cursor_line("Cursor's name"));
        assert_eq!(ensure_custom_title(&t, &ensure("Harbour-s12 renamed", false), &Rules::defaults()).unwrap().0, Ensured::Appended);
        let bytes = std::fs::read(t.path()).unwrap();
        let tail = &bytes[bytes.len().saturating_sub(64 << 10)..];
        let text = std::str::from_utf8(tail).unwrap();
        let at = text.rfind("\"customTitle\":\"").expect("a customTitle in the tail");
        let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
        let end = at + text[at..].find('\n').expect("the line's end") + 1;
        assert_eq!(&text.as_bytes()[start..end], title::custom_title_line(SID, "Harbour-s12 renamed").as_slice(), "the picker's last one starts ai-env's line");
    }
}
