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
use crate::bridge::errors::BridgeError;
use crate::bridge::scan::Rules;
use crate::wire::view::{
    is_view_head, masked_text, TranscriptViewReply, ViewLine, ViewMessage, ViewText, ViewTextKind, ViewTitleLine, CUSTOM_TITLES_MAX, CUSTOM_TITLE_LINE_MAX, VIEW_ENTRYPOINT, VIEW_HEAD_READ,
    VIEW_MARK_PREFIX, VIEW_USER_TYPE, VIEW_V,
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
        if line.is_empty() || line.len() > CUSTOM_TITLE_LINE_MAX || line.starts_with(VIEW_MARK_PREFIX.as_bytes()) {
            continue;
        }
        let kind = serde_json::from_slice::<serde_json::Value>(line).ok().and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string));
        if kind.as_deref() == Some(CUSTOM_TITLE_KIND) {
            let mut l = line.to_vec();
            l.push(b'\n');
            found.push(l);
        }
    }
    let skip = found.len().saturating_sub(CUSTOM_TITLES_MAX);
    found.split_off(skip)
}

/// The project directory of `t`, a real directory made 0700 when missing
/// (its parent created as needed); a symlink or a slug that is not one path
/// component is refused.
fn project_dir(t: &ViewTarget<'_>) -> Result<PathBuf, String> {
    let ok = !t.slug.is_empty() && t.slug != "." && t.slug != ".." && !t.slug.contains('/') && !t.slug.contains('\0');
    if !ok || !crate::bridge::registry::is_uuid(t.session_id) {
        return Err(format!("{:?}/{:?} is not a project directory and a session id", t.slug, t.session_id));
    }
    let dir = t.mac_projects.join(t.slug);
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.file_type().is_symlink() => Err(format!("{} is a symlink: never written through", dir.display())),
        Ok(m) if !m.is_dir() => Err(format!("{} is not a directory", dir.display())),
        Ok(_) => Ok(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            Ok(dir)
        }
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
    let now = crate::wire::time::rfc3339_utc_ms(crate::wire::time::unix_now_ms());
    write_view_with(t, reply, n, rules, &now, &mut || uuid::Uuid::now_v7().to_string())
}

/// [`write_view`] with the time and the uuid minter given (tests).
pub fn write_view_with(t: &ViewTarget<'_>, reply: &TranscriptViewReply, n: u32, rules: &Rules, now: &str, mint: &mut dyn FnMut() -> String) -> Result<ViewOutcome, BridgeError> {
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
    for line in custom_titles(old.as_deref().unwrap_or_default()) {
        bytes.extend_from_slice(&line);
    }
    let len = bytes.len() as u64;
    if old.as_deref() == Some(bytes.as_slice()) {
        return Ok(ViewOutcome::Unchanged { messages, masked, bytes: len });
    }
    crate::bridge::infra::write_atomic_mode(&path, &bytes, 0o600)?;
    Ok(ViewOutcome::Written { messages, masked, bytes: len })
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
}
