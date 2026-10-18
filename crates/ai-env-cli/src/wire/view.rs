//! A remote chat's view on the Mac (S9 plan §5, M3; every feature set): the
//! last messages of a transcript the VM keeps in S3, built in the VM by the
//! agent's helper (`shim-io transcript-view`, [`build_view`]) and answered as
//! a [`TranscriptViewReply`], which the Mac takes only in the shape
//! [`TranscriptViewReply::check`] allows before it writes the file Cursor's
//! picker lists (`bridge::view`: one [`ViewLine`] per message, each starting
//! with [`VIEW_MARK_PREFIX`], the title line first, Cursor's own
//! `custom-title` lines last). A view is never a transcript: a local resume
//! of one is refused ([`local_view_target`], [`LOCAL_RESUME_REFUSAL`]). The
//! format is the one the 2.1.302 extension reads (`fetchSessionsInDir` for
//! the list, the SDK reader's filter for a reopen), pinned by a golden test.
//! Frozen in S9 phase 0; G5 builds [`build_view`], G4 the Mac's writer.
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The view format's version.
pub const VIEW_V: u8 = 1;
/// `[transcript] view_messages`' default, and its largest value.
pub const VIEW_MESSAGES_DEFAULT: u32 = 10;
pub const VIEW_MESSAGES_MAX: u32 = 50;
/// Bytes of one text block.
pub const VIEW_BLOCK_MAX: usize = 16 << 10;
/// Blocks of one message.
pub const VIEW_BLOCKS_MAX: usize = 64;
/// Every block of a view, summed.
pub const VIEW_FILE_MAX: usize = 256 << 10;
/// Characters of the title.
pub const VIEW_TITLE_MAX: usize = 120;
/// Bytes of an entry's uuid or timestamp.
pub const VIEW_ID_MAX: usize = 64;
/// Bytes of `version` or `git_branch`.
pub const VIEW_META_MAX: usize = 255;
/// Bytes of the transcript's tail the builder reads.
pub const VIEW_TAIL_MAX: u64 = 64 << 20;
/// Bytes the kill switch reads of a session file to tell a view.
pub const VIEW_HEAD_READ: usize = 4096;
/// The first bytes of every line of a view file (the kill switch's prefix test).
pub const VIEW_MARK_PREFIX: &str = "{\"aiEnvView\":1,";
/// A view line's `entrypoint` (the extension's own: its picker lists the session).
pub const VIEW_ENTRYPOINT: &str = "claude-vscode";
/// A view line's `userType`.
pub const VIEW_USER_TYPE: &str = "external";
/// What an image block becomes.
pub const IMAGE_TEXT: &str = "[image]";
/// Cursor's `custom-title` lines a rewrite carries over: the newest this many, each at most `CUSTOM_TITLE_LINE_MAX` bytes.
pub const CUSTOM_TITLES_MAX: usize = 16;
pub const CUSTOM_TITLE_LINE_MAX: usize = 4096;

/// `[tool: NAME]` for a NAME of `[A-Za-z0-9_.:-]{1,64}`, else `[tool]`.
#[must_use]
pub fn tool_text(name: &str) -> String {
    let ok = (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'));
    if ok {
        format!("[tool: {name}]")
    } else {
        "[tool]".to_string()
    }
}

/// What a text block with a tripwire hit becomes on the Mac.
#[must_use]
pub fn masked_text(rule: &str) -> String {
    format!("[ai-env: masked, rule {rule}]")
}

/// The block before the last `VIEW_BLOCKS_MAX - 1` of a long message: how many earlier ones were left out.
#[must_use]
pub fn elided_text(n: usize) -> String {
    format!("[\u{2026} {n} earlier blocks]")
}

/// `GET /transcript/view`'s answer, built in the VM: at most n messages, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptViewReply {
    /// [`VIEW_V`].
    pub v: u8,
    /// The transcript is there (none: no entries).
    pub present: bool,
    /// The newest `ai-title` line's title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The newest kept entry's claude version and git branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    #[serde(default)]
    pub entries: Vec<ViewEntry>,
}

/// One message of a view: a user prompt, or one assistant reply collapsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewEntry {
    pub role: ViewRole,
    /// The entry's uuid (a collapsed reply's last entry's).
    pub uuid: String,
    pub timestamp: String,
    pub blocks: Vec<String>,
}

/// Who wrote a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViewRole {
    User,
    Assistant,
}

impl TranscriptViewReply {
    /// The shape the Mac takes: `v` is [`VIEW_V`]; no entries when not
    /// present; at most `n` (and [`VIEW_MESSAGES_MAX`]) entries, the first a
    /// user's; 1 to [`VIEW_BLOCKS_MAX`] non-empty blocks of at most
    /// [`VIEW_BLOCK_MAX`] bytes each, [`VIEW_FILE_MAX`] in all; a title of at
    /// most [`VIEW_TITLE_MAX`] characters; a uuid and a timestamp of at most
    /// [`VIEW_ID_MAX`] bytes each, a version and a git branch of at most
    /// [`VIEW_META_MAX`]; no NUL anywhere. uuids and timestamps are not
    /// judged otherwise (the Mac re-mints them). So its compact JSON stays
    /// under `wire::workspace::JSON_PAYLOAD_MAX`.
    pub fn check(&self, n: u32) -> Result<(), String> {
        if self.v != VIEW_V {
            return Err(format!("is view v{} (this side reads v{VIEW_V})", self.v));
        }
        if !self.present && !self.entries.is_empty() {
            return Err("has entries but no transcript".into());
        }
        let most = n.min(VIEW_MESSAGES_MAX) as usize;
        if self.entries.len() > most {
            return Err(format!("has {} messages (at most {most})", self.entries.len()));
        }
        if self.entries.first().is_some_and(|e| e.role != ViewRole::User) {
            return Err("does not start with a user's message".into());
        }
        let nul = |s: &str| s.contains('\0');
        if let Some(t) = &self.title {
            if t.chars().count() > VIEW_TITLE_MAX || nul(t) {
                return Err(format!("has a title of more than {VIEW_TITLE_MAX} characters, or a NUL"));
            }
        }
        for (what, value) in [("version", &self.version), ("git branch", &self.git_branch)] {
            if value.as_deref().is_some_and(|v| v.len() > VIEW_META_MAX || nul(v)) {
                return Err(format!("has a {what} of more than {VIEW_META_MAX} bytes, or a NUL"));
            }
        }
        let mut total = 0usize;
        for (i, e) in self.entries.iter().enumerate() {
            if e.uuid.len() > VIEW_ID_MAX || e.timestamp.len() > VIEW_ID_MAX || nul(&e.uuid) || nul(&e.timestamp) {
                return Err(format!("has a message (number {i}) whose uuid or timestamp is over {VIEW_ID_MAX} bytes, or holds a NUL"));
            }
            if e.blocks.is_empty() || e.blocks.len() > VIEW_BLOCKS_MAX {
                return Err(format!("has a message (number {i}) of {} blocks (1 to {VIEW_BLOCKS_MAX})", e.blocks.len()));
            }
            for b in &e.blocks {
                if b.is_empty() || b.len() > VIEW_BLOCK_MAX || nul(b) {
                    return Err(format!("has a message (number {i}) with an empty block, one over {VIEW_BLOCK_MAX} bytes, or a NUL"));
                }
                total += b.len();
            }
        }
        if total > VIEW_FILE_MAX {
            return Err(format!("holds {total} bytes of text (at most {VIEW_FILE_MAX})"));
        }
        Ok(())
    }
}

// ---- the file's lines ----------------------------------------------------------------------

/// One message as a line of the view file, in the extension's own shape
/// (its fields in this order; `parentUuid` written even when null).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ViewLine {
    /// [`VIEW_V`]: first, so every line starts with [`VIEW_MARK_PREFIX`].
    pub ai_env_view: u8,
    /// The previous line's uuid; null for the first entry (written).
    pub parent_uuid: Option<String>,
    /// Always false.
    pub is_sidechain: bool,
    /// [`VIEW_USER_TYPE`].
    pub user_type: String,
    /// The Mac's workspace path.
    pub cwd: String,
    /// The Mac's session id.
    pub session_id: String,
    pub version: String,
    pub git_branch: String,
    /// [`VIEW_ENTRYPOINT`].
    pub entrypoint: String,
    #[serde(rename = "type")]
    pub kind: ViewRole,
    pub message: ViewMessage,
    pub uuid: String,
    pub timestamp: String,
}

/// A view line's message: its role and its text blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewMessage {
    pub role: ViewRole,
    pub content: Vec<ViewText>,
}

/// One text block of a view line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewText {
    /// `"text"` only.
    #[serde(rename = "type")]
    pub kind: ViewTextKind,
    pub text: String,
}

/// The only kind of block a view carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViewTextKind {
    Text,
}

/// The view's title line (first, when there is a title).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ViewTitleLine {
    /// [`VIEW_V`].
    pub ai_env_view: u8,
    /// `"ai-title"`.
    #[serde(rename = "type")]
    pub kind: String,
    pub ai_title: String,
    pub session_id: String,
}

/// The first bytes of a view file (`head`: at most [`VIEW_HEAD_READ`] of
/// them) begin with [`VIEW_MARK_PREFIX`].
#[must_use]
pub fn is_view_head(head: &[u8]) -> bool {
    head.starts_with(VIEW_MARK_PREFIX.as_bytes())
}

// ---- the local resume of a view ------------------------------------------------------------

/// What a refused local resume names, for the census note `view_refused:<word>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewHit {
    /// `--resume ID`, `--resume=ID` or `-r ID` named a view.
    Resume,
    /// `--continue` or `-c`: the newest session file is a view.
    Continue,
}

impl ViewHit {
    /// The census note's word.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            ViewHit::Resume => "resume",
            ViewHit::Continue => "continue",
        }
    }
}

/// What the wrapper prints (after `ai-env-claude: `) when it refuses a local resume of a view (exit 9).
pub const LOCAL_RESUME_REFUSAL: &str = "this chat's transcript is kept in S3; the file here is its view (the last messages only) and cannot be resumed on this Mac: reopen it with remote mode on, or start a new chat";

/// The first [`VIEW_HEAD_READ`] bytes of `path` when it is a regular file
/// (opened without following a symlink, never blocking on a fifo).
fn head_of(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut head = Vec::with_capacity(VIEW_HEAD_READ);
    file.take(VIEW_HEAD_READ as u64).read_to_end(&mut head).ok()?;
    Some(head)
}

/// The newest `*.jsonl` (by mtime) of `dir`, regular files only.
fn newest_session_file(dir: &Path) -> Option<PathBuf> {
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else { continue };
        if !md.is_file() || path.extension().is_none_or(|e| e != "jsonl") {
            continue;
        }
        let Ok(mtime) = md.modified() else { continue };
        if newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
            newest = Some((mtime, path));
        }
    }
    newest.map(|(_, p)| p)
}

/// The session file a local claude run with `args` would resume, when it is a view: `--resume=ID`, `--resume ID`
/// or `-r ID` names `<projects>/<dir>/<ID>.jsonl`; `--continue` or `-c` the newest `*.jsonl` (by mtime) of
/// `<projects>/<dir>/`. `projects` is `$CLAUDE_CONFIG_DIR/projects`, else `$HOME/.claude/projects` (from `env`);
/// `dir` `slug::override_dir_name` when it applies, else `slug::project_dir_name(cwd)`. Only the first
/// VIEW_HEAD_READ bytes of one regular file are read (O_NOFOLLOW, O_NONBLOCK). None: no such flag, no file, no view.
/// The first such flag decides; flag handling stops at a bare `--`, and a value-taking flag's value is
/// never read as a flag (`wire::argv::takes_value`); an ID that is no session id names nothing.
#[must_use]
pub fn local_view_target(args: &[OsString], cwd: Option<&Path>, env: &dyn Fn(&str) -> Option<OsString>) -> Option<(ViewHit, PathBuf)> {
    let mut hit: Option<(ViewHit, Option<String>)> = None;
    let mut i = 0;
    while i < args.len() {
        let Some(tok) = args[i].to_str() else {
            i += 1;
            continue;
        };
        if tok == "--" {
            break;
        }
        if let Some(id) = tok.strip_prefix("--resume=") {
            hit = Some((ViewHit::Resume, Some(id.to_string())));
        } else if tok == "--resume" || tok == "-r" {
            hit = Some((ViewHit::Resume, args.get(i + 1).and_then(|a| a.to_str()).map(str::to_string)));
        } else if tok == "--continue" || tok == "-c" {
            hit = Some((ViewHit::Continue, None));
        }
        if hit.is_some() {
            break;
        }
        i += if crate::wire::argv::takes_value(tok) { 2 } else { 1 };
    }
    let (kind, id) = hit?;
    let nonempty = |k: &str| env(k).filter(|v| !v.is_empty());
    let config_dir = nonempty("CLAUDE_CONFIG_DIR");
    let projects = match &config_dir {
        Some(d) => PathBuf::from(d).join("projects"),
        None => PathBuf::from(nonempty("HOME")?).join(".claude").join("projects"),
    };
    let name = env("CLAUDE_CODE_PROJECT_DIR_NAME").map(|v| v.to_string_lossy().into_owned());
    let dir = match crate::wire::slug::override_dir_name(config_dir.is_some(), name.as_deref()) {
        Some(d) => d,
        None => crate::wire::slug::project_dir_name(cwd?).ok()?,
    };
    let file = match kind {
        ViewHit::Resume => {
            let id = id.filter(|id| crate::wire::workspace::is_uuid(id))?;
            projects.join(&dir).join(format!("{id}.jsonl"))
        }
        ViewHit::Continue => newest_session_file(&projects.join(&dir))?,
    };
    is_view_head(&head_of(&file)?).then_some((kind, file))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    /// §6.1's example: the golden document `transcript_view_reply`.
    const EXAMPLE: &str = r#"{"v":1,"present":true,"title":"Fix the seed's shallow boundary","version":"2.1.302","git_branch":"dev","entries":[{"role":"user","uuid":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60","timestamp":"2026-10-17T10:15:30.123Z","blocks":["Why does the update fail?"]},{"role":"assistant","uuid":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61","timestamp":"2026-10-17T10:15:41.456Z","blocks":["The boundary list was empty.","[tool: Bash]","Fixed in snapshot.rs."]}]}"#;

    /// Every line of a view starts with the mark (the title line too), so
    /// the kill switch's 4 KiB check is a prefix test; a transcript's own
    /// line, a BOM or a space first, or a mark of another version is no view.
    #[test]
    fn a_view_head_is_the_mark_prefix() {
        let sid = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
        let title = ViewTitleLine { ai_env_view: VIEW_V, kind: "ai-title".into(), ai_title: "Fix the seed's shallow boundary".into(), session_id: sid.into() };
        let title_line = serde_json::to_string(&title).unwrap();
        assert_eq!(title_line, format!(r#"{{"aiEnvView":1,"type":"ai-title","aiTitle":"Fix the seed's shallow boundary","sessionId":"{sid}"}}"#));
        let line = ViewLine {
            ai_env_view: VIEW_V,
            parent_uuid: None,
            is_sidechain: false,
            user_type: VIEW_USER_TYPE.into(),
            cwd: "/Users/mike/Documents/DeFi/ai-env".into(),
            session_id: sid.into(),
            version: "2.1.302".into(),
            git_branch: "dev".into(),
            entrypoint: VIEW_ENTRYPOINT.into(),
            kind: ViewRole::User,
            message: ViewMessage { role: ViewRole::User, content: vec![ViewText { kind: ViewTextKind::Text, text: "Why does the update fail?".into() }] },
            uuid: "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60".into(),
            timestamp: "2026-10-17T10:15:30.123Z".into(),
        };
        let entry_line = serde_json::to_string(&line).unwrap();
        assert_eq!(
            entry_line,
            format!(r#"{{"aiEnvView":1,"parentUuid":null,"isSidechain":false,"userType":"external","cwd":"/Users/mike/Documents/DeFi/ai-env","sessionId":"{sid}","version":"2.1.302","gitBranch":"dev","entrypoint":"claude-vscode","type":"user","message":{{"role":"user","content":[{{"type":"text","text":"Why does the update fail?"}}]}},"uuid":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60","timestamp":"2026-10-17T10:15:30.123Z"}}"#)
        );
        assert_eq!(serde_json::from_str::<ViewLine>(&entry_line).unwrap(), line);
        for head in [title_line.as_bytes(), entry_line.as_bytes(), VIEW_MARK_PREFIX.as_bytes()] {
            assert!(is_view_head(head), "{}", String::from_utf8_lossy(head));
        }
        let transcript = br#"{"parentUuid":null,"isSidechain":false,"type":"user","message":{"role":"user","content":"hi"}}"#;
        for head in [&transcript[..], b"", b" {\"aiEnvView\":1,", b"\xef\xbb\xbf{\"aiEnvView\":1,", b"{\"aiEnvView\":2,", b"{\"aiEnvView\":1}"] {
            assert!(!is_view_head(head), "{}", String::from_utf8_lossy(head));
        }
        assert!(serde_json::from_str::<ViewLine>(&entry_line.replacen(r#""isSidechain":false,"#, r#""isSidechain":false,"isMeta":true,"#, 1)).is_err(), "unknown keys are refused");
        assert_eq!((tool_text("Bash"), tool_text("mcp__x:y.z-1"), tool_text(""), tool_text("a b"), tool_text(&"t".repeat(65))), ("[tool: Bash]".into(), "[tool: mcp__x:y.z-1]".into(), "[tool]".into(), "[tool]".into(), "[tool]".into()));
        assert_eq!((masked_text("aws-key"), elided_text(3)), ("[ai-env: masked, rule aws-key]".to_string(), "[\u{2026} 3 earlier blocks]".to_string()));
    }

    /// The Mac takes §6.1's example and refuses each shape the builder
    /// never makes: another version, entries of an absent transcript, more
    /// messages than asked, a reply first, an empty or oversized block or
    /// message, too much text in all, a long title, uuid or branch, a NUL,
    /// an unknown key.
    #[test]
    fn the_view_reply_check_refuses_shapes_the_mac_never_takes() {
        let good: TranscriptViewReply = serde_json::from_str(EXAMPLE).unwrap();
        assert_eq!(serde_json::to_string(&good).unwrap(), EXAMPLE, "round-trips byte for byte");
        assert_eq!(good.check(10), Ok(()));
        assert_eq!(good.check(2), Ok(()));
        let absent = TranscriptViewReply { v: VIEW_V, present: false, title: None, version: None, git_branch: None, entries: Vec::new() };
        assert_eq!(serde_json::to_string(&absent).unwrap(), r#"{"v":1,"present":false,"entries":[]}"#);
        assert_eq!(absent.check(10), Ok(()));
        let with = |f: &dyn Fn(&mut TranscriptViewReply)| {
            let mut r = good.clone();
            f(&mut r);
            r
        };
        let user = good.entries[0].clone();
        let big = "x".repeat(VIEW_BLOCK_MAX);
        let cases: Vec<(TranscriptViewReply, u32, &str)> = vec![
            (with(&|r| r.v = 2), 10, "view v2"),
            (with(&|r| r.present = false), 10, "no transcript"),
            (good.clone(), 1, "2 messages (at most 1)"),
            (with(&|r| r.entries = vec![user.clone(); 51]), 60, "51 messages (at most 50)"),
            (with(&|r| r.entries.reverse()), 10, "user's message"),
            (with(&|r| r.entries[1].blocks.clear()), 10, "of 0 blocks"),
            (with(&|r| r.entries[1].blocks = vec!["b".into(); VIEW_BLOCKS_MAX + 1]), 10, "of 65 blocks"),
            (with(&|r| r.entries[1].blocks[1] = String::new()), 10, "an empty block"),
            (with(&|r| r.entries[1].blocks[1] = format!("{big}y")), 10, "over 16384 bytes"),
            (with(&|r| r.entries[1].blocks = vec![big.clone(); 17]), 10, "bytes of text"),
            (with(&|r| r.title = Some("t".repeat(VIEW_TITLE_MAX + 1))), 10, "title"),
            (with(&|r| r.title = Some("a\0b".into())), 10, "title"),
            (with(&|r| r.version = Some("v".repeat(VIEW_META_MAX + 1))), 10, "a version"),
            (with(&|r| r.git_branch = Some("de\0v".into())), 10, "a git branch"),
            (with(&|r| r.entries[0].uuid = "u".repeat(VIEW_ID_MAX + 1)), 10, "uuid or timestamp"),
            (with(&|r| r.entries[1].timestamp = "t\0".into()), 10, "uuid or timestamp"),
            (with(&|r| r.entries[0].blocks[0] = "a\0b".into()), 10, "a NUL"),
        ];
        for (bad, n, why) in cases {
            let e = bad.check(n).unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
        }
        // A title of 120 characters (not bytes) passes; uuids and timestamps are re-minted by the Mac, not judged here.
        assert_eq!(with(&|r| r.title = Some("\u{e9}".repeat(VIEW_TITLE_MAX))).check(10), Ok(()));
        assert_eq!(with(&|r| r.entries[0].uuid = "not-a-uuid".into()).check(10), Ok(()));
        for extra in [r#""v":1,"x":0,"#, r#""role":"user","x":0,"#] {
            let text = EXAMPLE.replacen(&extra.replace(r#""x":0,"#, ""), extra, 1);
            assert!(serde_json::from_str::<TranscriptViewReply>(&text).is_err(), "unknown keys are refused: {text}");
        }
        assert!(serde_json::from_str::<TranscriptViewReply>(&EXAMPLE.replace(r#""role":"user""#, r#""role":"system""#)).is_err());
    }

    /// The local resume of a view: `--resume=ID`, `--resume ID` and `-r ID`
    /// name `<projects>/<slug>/<ID>.jsonl`; `--continue` and `-c` the newest
    /// session file; a file that is no view, an ID that is no session id, a
    /// symlink, a flag after `--` or as another flag's value is none.
    #[test]
    fn a_local_resume_finds_a_view_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let cwd = root.join("work");
        std::fs::create_dir_all(&cwd).unwrap();
        let slug = crate::wire::slug::project_dir_name(&cwd).unwrap();
        let dir = root.join(".claude").join("projects").join(&slug);
        std::fs::create_dir_all(&dir).unwrap();
        let (view, plain) = ("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c");
        std::fs::write(dir.join(format!("{plain}.jsonl")), "{\"type\":\"user\"}\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(dir.join(format!("{view}.jsonl")), format!("{VIEW_MARK_PREFIX}\"type\":\"ai-title\"}}\n")).unwrap();
        let home = root.clone().into_os_string();
        let env = move |k: &str| (k == "HOME").then(|| home.clone());
        let run = |args: &[&str]| local_view_target(&args.iter().map(OsString::from).collect::<Vec<_>>(), Some(&cwd), &env);
        let at = |id: &str| dir.join(format!("{id}.jsonl"));
        assert_eq!(run(&["--resume", view]), Some((ViewHit::Resume, at(view))));
        assert_eq!(run(&[&format!("--resume={view}")]), Some((ViewHit::Resume, at(view))));
        assert_eq!(run(&["--print", "-r", view]), Some((ViewHit::Resume, at(view))));
        assert_eq!(run(&["--continue"]), Some((ViewHit::Continue, at(view))), "the newest file is the view");
        assert_eq!(run(&["-c", "--model", "x"]), Some((ViewHit::Continue, at(view))));
        for none in [&["--resume", plain][..], &["--resume", "../x"], &["--", "--resume", view], &["--model", "--continue"], &["-p"], &[]] {
            assert_eq!(run(none), None, "{none:?}");
        }
        assert_eq!(ViewHit::Continue.word(), "continue");
        // A symlink to a view is not read.
        std::os::unix::fs::symlink(at(view), dir.join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d.jsonl")).unwrap();
        assert_eq!(run(&["--resume", "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d"]), None);
        // CLAUDE_CONFIG_DIR's projects, and CLAUDE_CODE_PROJECT_DIR_NAME with it.
        let config = root.join("cfg");
        std::fs::create_dir_all(config.join("projects").join("named")).unwrap();
        std::fs::copy(at(view), config.join("projects").join("named").join(format!("{view}.jsonl"))).unwrap();
        let config_os = config.clone().into_os_string();
        let named = move |k: &str| match k {
            "CLAUDE_CONFIG_DIR" => Some(config_os.clone()),
            "CLAUDE_CODE_PROJECT_DIR_NAME" => Some(OsString::from("named")),
            _ => None,
        };
        assert_eq!(local_view_target(&[OsString::from("-r"), OsString::from(view)], None, &named), Some((ViewHit::Resume, config.join("projects").join("named").join(format!("{view}.jsonl")))));
    }
}

// ---- the builder (G5) ----

use serde_json::value::RawValue;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};

/// The builder (G5; shared by the helper's `transcript-view` and the Mac's `migrate-s9` of a gone VM):
/// `tail` is the transcript's last bytes, its first line possibly partial. Whatever the tail holds, nothing
/// [`TranscriptViewReply::check`] refuses comes out (plans/s9-contracts.md §6.1's rules).
///
/// The rules, in order: a line that does not parse (a partial first or last one) or that
/// `wire::mirror::is_unmirrored` takes is skipped; the parent chain is the
/// extension reader's: its entries are the `user`, `assistant`, `system`,
/// `progress` and `attachment` lines with a string uuid, its leaf the last
/// non-sidechain one no entry names as its `parentUuid` (so a `system` line
/// after the last reply leaves that reply in the view), walked back within
/// the tail; of the chain only the candidates are shown (rule 2: `user` and
/// `assistant` entries not `isSidechain`, `isMeta`, `isCompactSummary`, with
/// no `teamName`); a user entry of `tool_result` blocks only is dropped, and
/// the assistant entries between two user prompts collapse into one message
/// (rule 4); the blocks of rule 5; the last `n` messages, the first a user's,
/// the oldest dropped until the blocks fit `VIEW_FILE_MAX` (rule 6); the
/// title, version, branch, uuids and timestamps of rule 7. The reply is
/// checked before it is returned: an `Err` is a builder bug, never a tail's.
pub fn build_view(tail: &[u8], n: u32) -> Result<TranscriptViewReply, String> {
    let most = n.min(VIEW_MESSAGES_MAX) as usize;
    let (nodes, title) = index_lines(tail);
    let mut kept: VecDeque<Kept> = VecDeque::new();
    let mut open: Option<Gathered<'_, '_>> = None;
    for &i in &chain_of(&nodes) {
        let node = &nodes[i];
        let Some(role) = node.role else { continue };
        let (blocks, results_only) = blocks_of(node.line.message);
        match role {
            ViewRole::User => {
                if results_only {
                    continue;
                }
                if let Some(reply) = open.take() {
                    keep(&mut kept, most, reply);
                }
                let mut prompt = Gathered::new(role, node);
                prompt.extend(blocks);
                keep(&mut kept, most, prompt);
            }
            ViewRole::Assistant => {
                let reply = open.get_or_insert_with(|| Gathered::new(role, node));
                reply.last = node;
                reply.extend(blocks);
            }
        }
    }
    if let Some(reply) = open.take() {
        keep(&mut kept, most, reply);
    }
    // Rule 6: the first message is a user's, and the blocks fit the file's budget.
    loop {
        while kept.front().is_some_and(|m| m.role == ViewRole::Assistant) {
            kept.pop_front();
        }
        if kept.iter().map(|m| m.bytes).sum::<usize>() <= VIEW_FILE_MAX {
            break;
        }
        kept.pop_front();
    }
    let newest = kept.back();
    let reply = TranscriptViewReply {
        v: VIEW_V,
        present: true,
        title,
        version: newest.and_then(|m| m.version.clone()),
        git_branch: newest.and_then(|m| m.git_branch.clone()),
        entries: kept.into_iter().map(|m| ViewEntry { role: m.role, uuid: m.uuid, timestamp: m.timestamp, blocks: m.blocks }).collect(),
    };
    reply.check(n).map_err(|e| format!("build_view made a view that {e}"))?;
    Ok(reply)
}

/// One transcript line as the builder reads it: the fields it needs,
/// borrowed from the tail (nothing else is built; a field of another type
/// than its rule takes is as good as absent).
#[derive(Deserialize)]
struct Line<'a> {
    #[serde(rename = "type", borrow, default)]
    kind: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    uuid: Option<&'a RawValue>,
    #[serde(rename = "parentUuid", borrow, default)]
    parent: Option<&'a RawValue>,
    #[serde(rename = "isSidechain", borrow, default)]
    sidechain: Option<&'a RawValue>,
    #[serde(rename = "isMeta", borrow, default)]
    meta: Option<&'a RawValue>,
    #[serde(rename = "isCompactSummary", borrow, default)]
    compact: Option<&'a RawValue>,
    #[serde(rename = "teamName", borrow, default)]
    team: Option<&'a RawValue>,
    #[serde(borrow, default)]
    timestamp: Option<&'a RawValue>,
    #[serde(borrow, default)]
    version: Option<&'a RawValue>,
    #[serde(rename = "gitBranch", borrow, default)]
    git_branch: Option<&'a RawValue>,
    #[serde(borrow, default)]
    message: Option<&'a RawValue>,
    #[serde(rename = "aiTitle", borrow, default)]
    ai_title: Option<&'a RawValue>,
}

/// One entry of the parent chain.
struct Node<'a> {
    uuid: String,
    parent: Option<String>,
    sidechain: bool,
    /// A candidate's role (rule 2); `None` for every other entry of the chain.
    role: Option<ViewRole>,
    line: Line<'a>,
}

/// The text of a JSON string (`None` for any other value).
fn text_of(raw: Option<&RawValue>) -> Option<String> {
    raw.and_then(|r| serde_json::from_str::<String>(r.get()).ok())
}

/// A flag set to exactly `true`.
fn is_true(raw: Option<&RawValue>) -> bool {
    raw.is_some_and(|r| r.get() == "true")
}

/// `text` without its NULs.
fn without_nul(text: String) -> String {
    if text.contains('\0') {
        text.replace('\0', "")
    } else {
        text
    }
}

/// The chain's entries and the newest `ai-title` line's title (rule 7: its
/// NULs removed, cut to `VIEW_TITLE_MAX` characters; none when empty).
fn index_lines(tail: &[u8]) -> (Vec<Node<'_>>, Option<String>) {
    let mut nodes = Vec::new();
    let mut title = None;
    for raw in tail.split(|b| *b == b'\n') {
        if raw.is_empty() || crate::wire::mirror::is_unmirrored(raw) {
            continue;
        }
        let Ok(line) = serde_json::from_slice::<Line<'_>>(raw) else { continue };
        let (is_title, in_chain, role) = match line.kind.as_deref() {
            Some("ai-title") => (true, false, None),
            Some("user") => (false, true, Some(ViewRole::User)),
            Some("assistant") => (false, true, Some(ViewRole::Assistant)),
            Some("system" | "progress" | "attachment") => (false, true, None),
            _ => (false, false, None),
        };
        if is_title {
            if let Some(t) = text_of(line.ai_title) {
                title = Some(t);
            }
            continue;
        }
        if !in_chain {
            continue;
        }
        let Some(uuid) = text_of(line.uuid) else { continue };
        let sidechain = is_true(line.sidechain);
        let role = role.filter(|_| !sidechain && !is_true(line.meta) && !is_true(line.compact) && line.team.is_none());
        nodes.push(Node { uuid, parent: text_of(line.parent), sidechain, role, line });
    }
    let title = title.map(without_nul).map(|t| t.chars().take(VIEW_TITLE_MAX).collect::<String>()).filter(|t| !t.is_empty());
    (nodes, title)
}

/// The chain, oldest first: from the leaf (the last non-sidechain entry no
/// entry names as its parent) back through each `parentUuid` found in the
/// tail, an entry met twice ending it.
fn chain_of(nodes: &[Node<'_>]) -> Vec<usize> {
    let named: HashSet<&str> = nodes.iter().filter_map(|n| n.parent.as_deref()).collect();
    let by_uuid: HashMap<&str, usize> = nodes.iter().enumerate().map(|(i, n)| (n.uuid.as_str(), i)).collect();
    let mut at = nodes.iter().rposition(|n| !n.sidechain && !named.contains(n.uuid.as_str()));
    let (mut chain, mut seen) = (Vec::new(), HashSet::new());
    while let Some(i) = at {
        if !seen.insert(i) {
            break;
        }
        chain.push(i);
        at = nodes[i].parent.as_deref().and_then(|p| by_uuid.get(p).copied());
    }
    chain.reverse();
    chain
}

/// Rule 5's blocks of an entry's `message.content`, and whether it holds
/// `tool_result` blocks only (rule 4: such a user entry is dropped).
fn blocks_of(message: Option<&RawValue>) -> (Vec<String>, bool) {
    #[derive(Deserialize)]
    struct Message<'a> {
        #[serde(borrow, default)]
        content: Option<&'a RawValue>,
    }
    #[derive(Deserialize)]
    struct Block<'a> {
        #[serde(rename = "type", borrow, default)]
        kind: Option<Cow<'a, str>>,
        #[serde(borrow, default)]
        text: Option<&'a RawValue>,
        #[serde(borrow, default)]
        name: Option<&'a RawValue>,
    }
    let Some(content) = message.and_then(|m| serde_json::from_str::<Message<'_>>(m.get()).ok()).and_then(|m| m.content) else { return (Vec::new(), false) };
    // A typed prompt is stored as a string.
    if let Some(text) = text_of(Some(content)) {
        return (text_block(text).into_iter().collect(), false);
    }
    let Ok(items) = serde_json::from_str::<Vec<&RawValue>>(content.get()) else { return (Vec::new(), false) };
    let mut blocks = Vec::new();
    let mut results = 0usize;
    for item in &items {
        let Ok(block) = serde_json::from_str::<Block<'_>>(item.get()) else { continue };
        match block.kind.as_deref() {
            Some("text") => blocks.extend(text_of(block.text).and_then(text_block)),
            Some("image") => blocks.push(IMAGE_TEXT.to_string()),
            Some("tool_use") => blocks.push(tool_text(&text_of(block.name).unwrap_or_default())),
            Some("tool_result") => results += 1,
            // thinking, redacted_thinking and every other kind.
            _ => {}
        }
    }
    (blocks, !items.is_empty() && results == items.len())
}

/// A `text` block: its NULs removed, cut at a character boundary so that it
/// is at most `VIEW_BLOCK_MAX` bytes with its `…` (last, when cut); none when empty.
fn text_block(text: String) -> Option<String> {
    let text = without_nul(text);
    if text.is_empty() {
        return None;
    }
    if text.len() <= VIEW_BLOCK_MAX {
        return Some(text);
    }
    let mut cut = VIEW_BLOCK_MAX - '\u{2026}'.len_utf8();
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    Some(format!("{}\u{2026}", &text[..cut]))
}

/// A string field of rule 7's `version` or `git_branch`: its NULs removed;
/// none when it is no string, empty or over `VIEW_META_MAX` bytes.
fn meta_of(raw: Option<&RawValue>) -> Option<String> {
    text_of(raw).map(without_nul).filter(|v| !v.is_empty() && v.len() <= VIEW_META_MAX)
}

/// A uuid or a timestamp (rule 7): its NULs removed; empty when it is no
/// string or over `VIEW_ID_MAX` bytes (the Mac re-mints it).
fn id_of(text: Option<String>) -> String {
    text.map(without_nul).filter(|t| t.len() <= VIEW_ID_MAX).unwrap_or_default()
}

/// A message being gathered: a prompt, or the reply collapsing the assistant
/// entries up to the next prompt, its last entry its uuid's and timestamp's;
/// its last `VIEW_BLOCKS_MAX` blocks kept, the earlier ones counted.
struct Gathered<'n, 'a> {
    role: ViewRole,
    last: &'n Node<'a>,
    blocks: VecDeque<String>,
    earlier: usize,
}

impl<'n, 'a> Gathered<'n, 'a> {
    fn new(role: ViewRole, first: &'n Node<'a>) -> Self {
        Gathered { role, last: first, blocks: VecDeque::new(), earlier: 0 }
    }

    fn extend(&mut self, blocks: Vec<String>) {
        for b in blocks {
            self.blocks.push_back(b);
            if self.blocks.len() > VIEW_BLOCKS_MAX {
                self.blocks.pop_front();
                self.earlier += 1;
            }
        }
    }
}

/// A message the view may hold, as it will be written.
struct Kept {
    role: ViewRole,
    uuid: String,
    timestamp: String,
    version: Option<String>,
    git_branch: Option<String>,
    blocks: Vec<String>,
    /// Its blocks' bytes, summed.
    bytes: usize,
}

/// Keep `m` among the last `most` messages: a message left without a block
/// is dropped; one of more than `VIEW_BLOCKS_MAX` blocks keeps its last
/// `VIEW_BLOCKS_MAX - 1` after one `elided_text` block.
fn keep(kept: &mut VecDeque<Kept>, most: usize, m: Gathered<'_, '_>) {
    let mut blocks: Vec<String> = m.blocks.into();
    if blocks.is_empty() {
        return;
    }
    if m.earlier > 0 {
        let drop = blocks.len() - (VIEW_BLOCKS_MAX - 1);
        blocks.drain(..drop);
        blocks.insert(0, elided_text(m.earlier + drop));
    }
    let line = &m.last.line;
    let bytes = blocks.iter().map(String::len).sum();
    kept.push_back(Kept {
        role: m.role,
        uuid: id_of(Some(m.last.uuid.clone())),
        timestamp: id_of(text_of(line.timestamp)),
        version: meta_of(line.version),
        git_branch: meta_of(line.git_branch),
        blocks,
        bytes,
    });
    if kept.len() > most {
        kept.pop_front();
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;
    use serde_json::{json, Value};

    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    /// A transcript tail whose view is §6.1's example (the golden document `transcript_view_reply`).
    const EXAMPLE_TAIL: &[u8] = include_bytes!("../../tests/fixtures/view/tails/example.jsonl");
    /// A compacted chat with a rewound question.
    const BRANCHED_TAIL: &[u8] = include_bytes!("../../tests/fixtures/view/tails/branched.jsonl");

    /// The uuid of entry `n`.
    fn id(n: u32) -> String {
        format!("0199a1b2-c3d4-7e5f-8a9b-{n:012x}")
    }

    /// One transcript line of the session as the CLI writes it: `kind`, its
    /// uuid and parent, its message's `content`, `extra` fields on top.
    fn entry(kind: &str, uuid: &str, parent: Option<&str>, content: Value, extra: Value) -> String {
        let role = if kind == "user" { "user" } else { "assistant" };
        let mut line = json!({
            "parentUuid": parent,
            "isSidechain": false,
            "userType": "external",
            "cwd": "/Users/mike/Documents/DeFi/ai-env",
            "sessionId": SID,
            "version": "2.1.302",
            "gitBranch": "dev",
            "type": kind,
            "message": {"role": role, "content": content},
            "uuid": uuid,
            "timestamp": "2026-10-17T10:15:30.123Z",
        });
        if let (Some(obj), Some(more)) = (line.as_object_mut(), extra.as_object()) {
            for (k, v) in more {
                obj.insert(k.clone(), v.clone());
            }
        }
        line.to_string()
    }

    /// `turns` turns of a chat with every kind of block, one line each, plus
    /// what a transcript holds besides (the api-request records, the titles):
    /// turn k's prompt is `question k` (turn 11's with an image), its reply
    /// thinks, says `answer k`, runs Bash, gets the result and says `done k`.
    fn chat(turns: u32) -> String {
        let mut lines = Vec::new();
        let mut parent: Option<String> = None;
        for k in 1..=turns {
            let base = k * 16;
            let prompt = if k == 11 { json!([{"type": "text", "text": format!("question {k}")}, {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}]) } else { json!(format!("question {k}")) };
            lines.push(entry("user", &id(base), parent.as_deref(), prompt, json!({})));
            lines.push(format!(r#"{{"type":"api-request","requestId":"req_fake_{k}_1","sessionId":"{SID}","timestamp":"2026-10-17T00:00:00.000Z"}}"#));
            lines.push(format!(r#"{{"type":"api-request-blob","requestId":"req_fake_{k}_1","blob":"ZmFrZQ=="}}"#));
            lines.push(entry("assistant", &id(base + 1), Some(&id(base)), json!([{"type": "thinking", "thinking": format!("thinking {k}"), "signature": "c2ln"}]), json!({})));
            lines.push(entry("assistant", &id(base + 2), Some(&id(base + 1)), json!([{"type": "text", "text": format!("answer {k}")}]), json!({})));
            lines.push(entry("assistant", &id(base + 3), Some(&id(base + 2)), json!([{"type": "tool_use", "id": format!("toolu_{k}"), "name": "Bash", "input": {"command": "ls"}}]), json!({})));
            lines.push(entry("user", &id(base + 4), Some(&id(base + 3)), json!([{"type": "tool_result", "tool_use_id": format!("toolu_{k}"), "content": format!("tool output {k}")}]), json!({})));
            let gitbranch = if k == turns { "main" } else { "dev" };
            lines.push(entry("assistant", &id(base + 5), Some(&id(base + 4)), json!([{"type": "text", "text": format!("done {k}")}]), json!({"gitBranch": gitbranch, "timestamp": format!("2026-10-17T10:{k:02}:00.000Z")})));
            parent = Some(id(base + 5));
            lines.push(format!(r#"{{"type":"ai-title","aiTitle":"title after turn {k}","sessionId":"{SID}"}}"#));
        }
        lines.join("\n") + "\n"
    }

    /// Every block of `reply`, with its message's role.
    fn texts(reply: &TranscriptViewReply) -> Vec<(ViewRole, Vec<&str>)> {
        reply.entries.iter().map(|e| (e.role, e.blocks.iter().map(String::as_str).collect())).collect()
    }

    /// The example tail (a torn first and last line, an older title, an
    /// api-request pair, thinking, a tool call and its result, a sidechain
    /// reply, a meta entry, a `system` entry after the last reply) is §6.1's
    /// example; a compacted chat shows the live branch after its boundary
    /// only: neither the summary, the rewound question nor what came before.
    #[test]
    fn the_example_tail_builds_the_golden_view() {
        let golden: TranscriptViewReply = serde_json::from_str(tests_example()).unwrap();
        assert_eq!(build_view(EXAMPLE_TAIL, 10).unwrap(), golden);
        let branched = build_view(BRANCHED_TAIL, 10).unwrap();
        assert_eq!(
            texts(&branched),
            [
                (ViewRole::User, vec!["First question after the compact"]),
                (ViewRole::Assistant, vec!["First answer"]),
                (ViewRole::User, vec!["The question asked instead"]),
                (ViewRole::Assistant, vec!["The answer on the live branch"]),
            ]
        );
        assert_eq!(branched.title, None, "no ai-title line");
        // Any prefix of the tail (a file cut anywhere) builds a view the Mac takes.
        for cut in 0..=EXAMPLE_TAIL.len() {
            for tail in [&EXAMPLE_TAIL[..cut], &EXAMPLE_TAIL[cut..]] {
                let reply = build_view(tail, 10).unwrap_or_else(|e| panic!("cut at {cut}: {e}"));
                assert_eq!(reply.check(10), Ok(()));
            }
        }
    }

    /// §6.1's example, as the phase-0 tests hold it.
    fn tests_example() -> &'static str {
        r#"{"v":1,"present":true,"title":"Fix the seed's shallow boundary","version":"2.1.302","git_branch":"dev","entries":[{"role":"user","uuid":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60","timestamp":"2026-10-17T10:15:30.123Z","blocks":["Why does the update fail?"]},{"role":"assistant","uuid":"0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61","timestamp":"2026-10-17T10:15:41.456Z","blocks":["The boundary list was empty.","[tool: Bash]","Fixed in snapshot.rs."]}]}"#
    }

    /// The last 10 messages of a 12-turn chat, text only: each prompt, each
    /// reply collapsed (its thinking gone, its tool call `[tool: Bash]`, its
    /// tool result dropped), an image `[image]`, no api-request record; the
    /// newest title, the newest entry's version and branch. Asked for 9, the
    /// leading reply is dropped so the first message is a prompt.
    #[test]
    fn view_last_10_text_only() {
        let tail = chat(12);
        let reply = build_view(tail.as_bytes(), 10).unwrap();
        assert_eq!(reply.check(10), Ok(()));
        let mut want = Vec::new();
        for k in 8..=12 {
            let prompt = format!("question {k}");
            want.push((ViewRole::User, if k == 11 { vec![prompt, IMAGE_TEXT.to_string()] } else { vec![prompt] }));
            want.push((ViewRole::Assistant, vec![format!("answer {k}"), "[tool: Bash]".to_string(), format!("done {k}")]));
        }
        let got: Vec<(ViewRole, Vec<String>)> = reply.entries.iter().map(|e| (e.role, e.blocks.clone())).collect();
        assert_eq!(got, want);
        let text = serde_json::to_string(&reply).unwrap();
        for absent in ["thinking", "tool output", "api-request", "req_fake", "iVBORw0KGgo"] {
            assert!(!text.contains(absent), "{absent} in {text}");
        }
        assert_eq!((reply.title.as_deref(), reply.version.as_deref(), reply.git_branch.as_deref()), (Some("title after turn 12"), Some("2.1.302"), Some("main")));
        let last = reply.entries.last().unwrap();
        assert_eq!((last.uuid.as_str(), last.timestamp.as_str()), (id(12 * 16 + 5).as_str(), "2026-10-17T10:12:00.000Z"), "a collapsed reply carries its last entry's uuid and timestamp");
        assert_eq!(reply.entries[0].uuid, id(8 * 16));
        let nine = build_view(tail.as_bytes(), 9).unwrap();
        assert_eq!(nine.entries.len(), 8, "the last 9 begin with a reply, which goes");
        assert_eq!((nine.entries[0].role, nine.entries[0].blocks[0].as_str()), (ViewRole::User, "question 9"));
        assert_eq!(build_view(tail.as_bytes(), 1).unwrap().entries.len(), 0, "the last message is a reply: nothing begins with a prompt");
        assert_eq!(build_view(tail.as_bytes(), 2).unwrap().entries.len(), 2);
        assert_eq!(build_view(tail.as_bytes(), 500).unwrap().entries.len(), 24, "every message, VIEW_MESSAGES_MAX at most");
        let empty = build_view(b"", 10).unwrap();
        assert_eq!((empty.present, empty.entries.len(), empty.title), (true, 0, None));
    }

    /// The caps: a text block past `VIEW_BLOCK_MAX` is cut at a character
    /// boundary with its `…`; a turn of 100 tool calls keeps its last 63
    /// blocks after one elided block; replies of 64 KiB each fit
    /// `VIEW_FILE_MAX` by dropping the oldest messages (a prompt first).
    #[test]
    fn view_caps_bytes() {
        let long = "\u{e9}".repeat(VIEW_BLOCK_MAX);
        let lines = [entry("user", &id(1), None, json!(long), json!({})), entry("assistant", &id(2), Some(&id(1)), json!([{"type": "text", "text": "ok"}]), json!({}))];
        let reply = build_view(lines.join("\n").as_bytes(), 10).unwrap();
        let block = &reply.entries[0].blocks[0];
        assert!(block.len() <= VIEW_BLOCK_MAX && block.len() > VIEW_BLOCK_MAX - 8 && block.ends_with('\u{2026}'), "{}", block.len());
        assert!(block.trim_end_matches('\u{2026}').chars().all(|c| c == '\u{e9}'), "cut at a character boundary");
        // 100 tool calls and a text: 101 blocks.
        let mut lines = vec![entry("user", &id(1), None, json!("run them"), json!({}))];
        for k in 0..100u32 {
            lines.push(entry("assistant", &id(10 + k), Some(&if k == 0 { id(1) } else { id(9 + k) }), json!([{"type": "tool_use", "id": format!("t{k}"), "name": format!("Tool{k}"), "input": {}}]), json!({})));
        }
        lines.push(entry("assistant", &id(200), Some(&id(109)), json!([{"type": "text", "text": "all done"}]), json!({})));
        let reply = build_view(lines.join("\n").as_bytes(), 10).unwrap();
        let blocks = &reply.entries[1].blocks;
        assert_eq!(blocks.len(), VIEW_BLOCKS_MAX);
        assert_eq!((blocks[0].as_str(), blocks[1].as_str(), blocks[63].as_str()), (elided_text(38).as_str(), "[tool: Tool38]", "all done"));
        // Five turns whose replies are four full blocks each (64 KiB): the last 10 messages hold 320 KiB.
        let big = "r".repeat(VIEW_BLOCK_MAX);
        let mut lines = Vec::new();
        let mut parent: Option<String> = None;
        for k in 0..6u32 {
            lines.push(entry("user", &id(k * 4), parent.as_deref(), json!(format!("prompt {k}")), json!({})));
            lines.push(entry("assistant", &id(k * 4 + 1), Some(&id(k * 4)), json!([{"type": "text", "text": big}, {"type": "text", "text": big}, {"type": "text", "text": big}, {"type": "text", "text": big}]), json!({})));
            parent = Some(id(k * 4 + 1));
        }
        let reply = build_view(lines.join("\n").as_bytes(), 10).unwrap();
        assert_eq!(reply.check(10), Ok(()));
        let total: usize = reply.entries.iter().flat_map(|e| &e.blocks).map(String::len).sum();
        assert!(total <= VIEW_FILE_MAX, "{total}");
        assert_eq!(reply.entries.len(), 6, "the three newest turns: four would pass 256 KiB with their prompts");
        assert_eq!((reply.entries[0].role, reply.entries[0].blocks[0].as_str()), (ViewRole::User, "prompt 3"));
    }

    /// Nothing the Mac refuses comes out, whatever the tail holds: a turn
    /// of 200 tool calls, a string prompt, an empty text block, NULs in a
    /// text, a title, a version, a branch and a uuid, a block cut at the
    /// cap, an oversized uuid and timestamp, a version over its cap, a title
    /// over its, a uuid that is no string, entries flagged sidechain, meta,
    /// compact summary or team, a team name of null, garbage lines.
    #[test]
    fn view_never_builds_what_check_refuses() {
        let long_id = "u".repeat(VIEW_ID_MAX + 1);
        let nul_id = format!("{}\0", id(3));
        let lines = [
            "not json at all".to_string(),
            "{\"type\":\"user\",\"uuid\":".to_string(),
            "[1,2,3]".to_string(),
            format!(r#"{{"type":"ai-title","aiTitle":"{}\u0000x","sessionId":"{SID}"}}"#, "T".repeat(VIEW_TITLE_MAX + 30)),
            entry("user", &id(1), None, json!("a typed prompt\u{0}with a NUL"), json!({"version": "v".repeat(VIEW_META_MAX + 1), "gitBranch": "de\u{0}v"})),
            entry("assistant", &id(2), Some(&id(1)), json!([{"type": "text", "text": ""}, {"type": "text", "text": "\u{0}\u{0}"}, {"type": "redacted_thinking", "data": "x"}, {"type": "text", "text": "x".repeat(3 * VIEW_BLOCK_MAX)}]), json!({"timestamp": "t".repeat(VIEW_ID_MAX + 1)})),
            entry("user", &nul_id, Some(&id(2)), json!("a prompt whose uuid holds a NUL"), json!({})),
            entry("assistant", &long_id, Some(&nul_id), json!([{"type": "text", "text": "a reply with a long uuid"}]), json!({"timestamp": 7})),
            entry("user", &id(5), Some(&long_id), json!("sidechain"), json!({"isSidechain": true})),
            entry("user", &id(6), Some(&long_id), json!("meta"), json!({"isMeta": true})),
            entry("user", &id(7), Some(&id(6)), json!("compact"), json!({"isCompactSummary": true})),
            entry("user", &id(8), Some(&id(7)), json!("team"), json!({"teamName": "t"})),
            entry("user", &id(9), Some(&id(8)), json!("a team name of null is none"), json!({"teamName": null})),
            entry("assistant", "", Some(&id(9)), json!([{"type": "text", "text": "an empty uuid is a string"}]), json!({})),
            r#"{"type":"assistant","uuid":42,"parentUuid":"x","message":{"content":"a uuid that is no string"}}"#.to_string(),
        ];
        // A chain of its own after them: the 200-call turn is the tail's leaf.
        let mut turn = vec![entry("user", &id(100), None, json!("go"), json!({}))];
        for k in 0..200u32 {
            let name = if k % 2 == 0 { "Bash" } else { "a bad name" };
            turn.push(entry("assistant", &id(101 + k), Some(&id(100 + k)), json!([{"type": "tool_use", "id": "x", "name": name, "input": {}}]), json!({})));
        }
        let tail = lines.join("\n") + "\n" + &turn.join("\n");
        for n in [0, 1, 2, 3, 10, 50, 51, u32::MAX] {
            let reply = build_view(tail.as_bytes(), n).unwrap_or_else(|e| panic!("n {n}: {e}"));
            assert_eq!(reply.check(n), Ok(()), "n {n}");
        }
        let reply = build_view(tail.as_bytes(), 50).unwrap();
        let title = reply.title.clone().unwrap();
        assert_eq!((title.chars().count(), title.contains('\0')), (VIEW_TITLE_MAX, false));
        assert_eq!(reply.entries.len(), 2, "the 200-call turn's chain alone: {:?}", texts(&reply));
        let blocks = &reply.entries[1].blocks;
        assert_eq!((blocks.len(), blocks[0].as_str(), blocks[63].as_str(), blocks[62].as_str()), (VIEW_BLOCKS_MAX, elided_text(137).as_str(), "[tool]", "[tool: Bash]"));
        // The first chain, alone: the NULs gone, the caps kept, the flagged entries never shown.
        let first = lines.join("\n");
        let reply = build_view(first.as_bytes(), 50).unwrap();
        assert_eq!(reply.check(50), Ok(()));
        let got = texts(&reply);
        assert_eq!(got[0], (ViewRole::User, vec!["a typed promptwith a NUL"]));
        assert_eq!(got[1].1.len(), 1, "two empty texts and the thinking dropped, the long text kept: {got:?}");
        assert!(got[1].1[0].len() <= VIEW_BLOCK_MAX && got[1].1[0].ends_with('\u{2026}'));
        assert_eq!(reply.entries[1].timestamp, "", "a timestamp over VIEW_ID_MAX is written empty");
        assert_eq!(reply.entries[2].uuid, id(3), "the NUL removed");
        assert_eq!((reply.entries[3].uuid.as_str(), reply.entries[3].timestamp.as_str()), ("", ""), "a long uuid and a number for a timestamp: empty");
        assert_eq!(got[4], (ViewRole::User, vec!["a team name of null is none"]));
        assert_eq!(got[5], (ViewRole::Assistant, vec!["an empty uuid is a string"]));
        assert_eq!(got.len(), 6, "{got:?}");
        assert!(!serde_json::to_string(&reply).unwrap().contains("sidechain\""), "flagged entries never shown");
        assert_eq!((reply.version.as_deref(), reply.git_branch.as_deref()), (Some("2.1.302"), Some("dev")));
        let first_only = build_view(lines[..5].join("\n").as_bytes(), 50).unwrap();
        assert_eq!((first_only.version, first_only.git_branch.as_deref()), (None, Some("dev")), "a version over VIEW_META_MAX is none; a branch's NUL removed");
    }
}
