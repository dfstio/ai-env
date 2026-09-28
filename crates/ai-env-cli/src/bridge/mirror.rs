//! The transcript-mirror writer of the S2 pump.
//!
//! The child claude runs with `--session-mirror` and, after every transcript
//! append, emits `{"type":"transcript_mirror","filePath":<abs path under the
//! CHILD's projects root>,"entries":[<transcript objects>]}` on stdout. The
//! pump peels those frames (they never reach the extension) and hands
//! `(filePath, raw entries)` to [`Writer::append`], which appends each
//! entry's raw JSON text + `\n` — byte-for-byte, never re-serialised — to the
//! SAME relative path under a destination root.
//!
//! Where: the path is validated with `wire::mirror::mirror_key` (the
//! extension's own rule: `..`/absolute/outside → rejected, 3 segments →
//! rejected, `<project>/<session>.jsonl` or `<project>/<session>/<sub…>`),
//! and the destination is `dest_root/<the validated relative path itself>` —
//! a `…/subagents/agent-a1.meta.json` companion keeps its name. Directories
//! below the root are created 0700 one level at a time and a symlink at any
//! level is refused; files are opened `O_APPEND|O_CREAT|O_NOFOLLOW`, 0600,
//! regular files only. Existing directories and files are never chmod'ed:
//! the destination is often the user's own `~/.claude/projects/<slug>`.
//!
//! What: every entry is appended as the CLI's own file line — the raw slice,
//! with the two escapes the stdout serializer adds (`\u2028`, `\u2029`,
//! which `JSON.stringify` leaves raw in the file) turned back into the raw
//! characters. On a subagent path, `{"type":"agent_metadata",…}` entries are
//! not transcript lines: like the SDK's own session store, the last one of a
//! frame replaces `<subpath>.meta.json` (the entry without its `type`,
//! 0600), and only the other entries are appended to the `.jsonl`.
//!
//! When: [`decide`] enables the writer iff the route is remote, the child's
//! config dir differs from the Mac's, or `AI_ENV_BRIDGE_MIRROR_ROOT` is set —
//! except that a LOCAL child whose projects root IS the destination never
//! gets a second writer (no double append).
use crate::wire::mirror::{mirror_key, node_relative};
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// Open files kept per writer (least recently used closed first).
pub const MAX_OPEN_FILES: usize = 8;

/// The writer's configuration, decided once per session by [`decide`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorCfg {
    /// `<child CLAUDE_CONFIG_DIR>/projects`: the root the frames' `filePath`s are relative to.
    pub child_projects_root: PathBuf,
    /// `AI_ENV_BRIDGE_MIRROR_ROOT`, else `<Mac config dir>/projects`.
    pub dest_root: PathBuf,
    pub enabled: bool,
    /// One human line for the log: `mirror writer enabled: …` / `mirror writer disabled: …`.
    pub reason: String,
}

/// The Mac's Claude config dir as the wrapper's own environment has it:
/// `CLAUDE_CONFIG_DIR` when set and non-empty, else `$HOME/.claude`.
#[must_use]
pub fn mac_config_dir() -> Option<PathBuf> {
    match std::env::var_os("CLAUDE_CONFIG_DIR").filter(|v| !v.is_empty()) {
        Some(d) => Some(PathBuf::from(d)),
        None => std::env::var_os("HOME").filter(|v| !v.is_empty()).map(|h| PathBuf::from(h).join(".claude")),
    }
}

/// `p` without trailing separators and `.` components (lexical only).
fn lexical(p: &Path) -> PathBuf {
    p.components().filter(|c| !matches!(c, Component::CurDir)).collect()
}

/// Do `a` and `b` name the same directory? Canonical paths when both exist,
/// else the lexically normalised paths.
fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => lexical(a) == lexical(b),
    }
}

/// The enable rule (module doc). `child_local`: the child runs on this Mac
/// (every S2 mode); a remote child (S8) writes a VM disk, never ours.
#[must_use]
pub fn decide(route_remote: bool, child_local: bool, child_config_dir: &Path, mac_config_dir: &Path, mirror_root: Option<&Path>) -> MirrorCfg {
    let child_projects_root = child_config_dir.join("projects");
    let dest_root = mirror_root.map_or_else(|| mac_config_dir.join("projects"), Path::to_path_buf);
    let base = route_remote || !same_dir(child_config_dir, mac_config_dir) || mirror_root.is_some();
    let (enabled, reason) = if !base {
        (false, format!("mirror writer disabled: local child writes {} itself (no AI_ENV_BRIDGE_MIRROR_ROOT)", child_projects_root.display()))
    } else if child_local && same_dir(&child_projects_root, &dest_root) {
        (false, format!("mirror writer disabled: child projects root {} is the destination (no double append)", child_projects_root.display()))
    } else {
        (true, format!("mirror writer enabled: {} -> {}", child_projects_root.display(), dest_root.display()))
    };
    MirrorCfg { child_projects_root, dest_root, enabled, reason }
}

/// Why a frame was not appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// The writer is disabled (counted as `skipped`).
    Disabled,
    /// No `filePath`, or one `mirror_key` refuses.
    BadKey,
    /// A symlink or a non-directory/non-regular file on the way.
    Unconfined(String),
    /// A directory or the file could not be created or opened.
    NotCreatable(String),
    /// The append itself failed.
    Io(String),
}

/// The appender. Counters feed the census end row (`mirror:<frames>/<rejected>`) and the log.
#[derive(Debug)]
pub struct Writer {
    cfg: MirrorCfg,
    /// Most recently used first.
    open: Vec<(PathBuf, File)>,
    /// Destinations whose failed append could not be rolled back: never appended to again.
    poisoned: BTreeSet<PathBuf>,
    pub appended_frames: u64,
    pub appended_lines: u64,
    pub appended_bytes: u64,
    /// `.meta.json` files written from `agent_metadata` entries.
    pub meta_files: u64,
    pub rejected: u64,
    pub errors: u64,
    pub skipped: u64,
}

/// `raw` as the CLI's file line: the stdout serializer escapes U+2028/U+2029
/// (`\u2028`, `\u2029`) where `JSON.stringify` — the file writer — leaves
/// them raw. Escape pairs are consumed whole, so `\\u2028` (an escaped
/// backslash followed by text) stays as it is.
#[must_use]
pub fn file_line(raw: &str) -> Cow<'_, str> {
    if !raw.contains("\\u202") {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let rest = &raw[i + 1..];
        let sep = if rest.starts_with("u2028") { Some('\u{2028}') } else if rest.starts_with("u2029") { Some('\u{2029}') } else { None };
        match sep {
            Some(ch) => {
                out.push(ch);
                for _ in 0..5 {
                    chars.next();
                }
            }
            None => {
                out.push('\\');
                if let Some((_, next)) = chars.next() {
                    out.push(next);
                }
            }
        }
    }
    Cow::Owned(out)
}

/// Is this entry the CLI's synthetic subagent metadata?
fn is_agent_metadata(raw: &RawValue) -> bool {
    #[derive(serde::Deserialize)]
    struct Ty<'a> {
        #[serde(rename = "type", borrow, default)]
        ty: Option<Cow<'a, str>>,
    }
    raw.get().contains("agent_metadata") && serde_json::from_str::<Ty<'_>>(raw.get()).ok().and_then(|t| t.ty).as_deref() == Some("agent_metadata")
}

/// The `.meta.json` body for an `agent_metadata` entry: the entry without its
/// `type` member (textually when `type` is the first member, as the CLI
/// builds it; else through a JSON round trip).
fn meta_body(raw: &RawValue) -> Option<String> {
    let text = raw.get();
    if let Some(rest) = text.strip_prefix(r#"{"type":"agent_metadata","#) {
        return Some(format!("{{{rest}"));
    }
    if text == r#"{"type":"agent_metadata"}"# {
        return Some("{}".to_string());
    }
    let mut v: serde_json::Map<String, serde_json::Value> = serde_json::from_str(text).ok()?;
    v.remove("type");
    serde_json::to_string(&v).ok()
}

impl Writer {
    #[must_use]
    pub fn new(cfg: MirrorCfg) -> Writer {
        Writer { cfg, open: Vec::new(), poisoned: BTreeSet::new(), appended_frames: 0, appended_lines: 0, appended_bytes: 0, meta_files: 0, rejected: 0, errors: 0, skipped: 0 }
    }

    #[must_use]
    pub fn cfg(&self) -> &MirrorCfg {
        &self.cfg
    }

    /// The relative path a frame's `filePath` maps to, validated: `mirror_key`
    /// must accept it and every segment must be a normal name.
    fn rel_for(&self, file_path: &str) -> Result<PathBuf, Reject> {
        let root = self.cfg.child_projects_root.to_str().ok_or(Reject::BadKey)?;
        mirror_key(root, file_path).ok_or(Reject::BadKey)?;
        let rel = node_relative(root, file_path);
        if rel.is_empty() || rel.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
            return Err(Reject::BadKey);
        }
        Ok(PathBuf::from(rel))
    }

    /// Where `file_path`'s entries would be appended (validation only).
    pub fn dest_for(&self, file_path: &str) -> Result<PathBuf, Reject> {
        Ok(self.cfg.dest_root.join(self.rel_for(file_path)?))
    }

    /// Append one frame's entries (each as its file line + `\n`, in one
    /// `write_all`); on a subagent path the last `agent_metadata` entry
    /// replaces the `.meta.json` companion instead. Returns the bytes
    /// written. Never panics, never logs entry text.
    pub fn append(&mut self, file_path: Option<&str>, entries: &[&RawValue]) -> Result<usize, Reject> {
        if !self.cfg.enabled {
            self.skipped += 1;
            return Err(Reject::Disabled);
        }
        let rel = match file_path.ok_or(Reject::BadKey).and_then(|p| self.rel_for(p)) {
            Ok(rel) => rel,
            Err(e) => {
                self.rejected += 1;
                tracing::debug!("mirror frame rejected: {e:?}");
                return Err(e);
            }
        };
        // Subagent metadata: only on a subagent transcript (`<project>/<session>/<sub…>.jsonl`),
        // where the CLI mirrors its `.meta.json` writes.
        let subagent = rel.components().count() >= 4 && rel.extension().is_some_and(|e| e == "jsonl");
        let (meta, lines): (Vec<&RawValue>, Vec<&RawValue>) = if subagent { entries.iter().partition(|e| is_agent_metadata(e)) } else { (Vec::new(), entries.to_vec()) };
        let mut written = 0;
        if let Some(last) = meta.last() {
            written += self.write_meta(&rel, last)?;
        }
        if lines.is_empty() {
            self.appended_frames += 1;
            return Ok(written);
        }
        let mut buf = Vec::with_capacity(lines.iter().map(|e| e.get().len() + 1).sum());
        for e in &lines {
            buf.extend_from_slice(file_line(e.get()).as_bytes());
            buf.push(b'\n');
        }
        let dest = self.cfg.dest_root.join(&rel);
        if self.poisoned.contains(&dest) {
            self.errors += 1;
            return Err(Reject::Io(format!("{}: an earlier append could not be rolled back", rel.display())));
        }
        let idx = match self.open.iter().position(|(p, _)| *p == dest) {
            Some(i) => i,
            None => match confine_and_open(&self.cfg.dest_root, &rel) {
                Ok(f) => {
                    self.open.insert(0, (dest.clone(), f));
                    while self.open.len() > MAX_OPEN_FILES {
                        // Leaving the cache: fsync first, so the per-result fsync rule holds for it too.
                        if let Some((p, f)) = self.open.pop() {
                            if let Err(e) = f.sync_data() {
                                tracing::warn!("mirror: fsync of {} on eviction: {e}", p.display());
                            }
                        }
                    }
                    0
                }
                Err(e) => {
                    self.rejected += 1;
                    tracing::warn!("mirror: {} not appended: {e:?}", rel.display());
                    return Err(e);
                }
            },
        };
        let entry = self.open.remove(idx);
        self.open.insert(0, entry);
        let before = self.open[0].1.metadata().map(|m| m.len()).ok();
        if let Err(e) = self.open[0].1.write_all(&buf) {
            self.errors += 1;
            let (_, file) = self.open.remove(0);
            // Roll a partial line back, so the next frame does not land glued to it.
            let rolled_back = before.is_some_and(|len| file.set_len(len).is_ok());
            if !rolled_back {
                self.poisoned.insert(dest);
            }
            tracing::warn!("mirror: append to {} failed: {e} (rolled back: {rolled_back})", rel.display());
            return Err(Reject::Io(e.to_string()));
        }
        self.appended_frames += 1;
        self.appended_lines += lines.len() as u64;
        self.appended_bytes += buf.len() as u64;
        tracing::debug!(path = %rel.display(), entries = lines.len(), bytes = buf.len(), "mirror appended");
        Ok(written + buf.len())
    }

    /// Replace `<rel without .jsonl>.meta.json` with the entry's body (0600,
    /// temp file + rename in the same confined directory).
    fn write_meta(&mut self, rel: &Path, entry: &RawValue) -> Result<usize, Reject> {
        let Some(name) = rel.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".jsonl")) else {
            self.rejected += 1;
            return Err(Reject::BadKey);
        };
        let Some(body) = meta_body(entry) else {
            self.rejected += 1;
            return Err(Reject::BadKey);
        };
        let meta_rel = rel.with_file_name(format!("{name}.meta.json"));
        match replace_file(&self.cfg.dest_root, &meta_rel, body.as_bytes()) {
            Ok(()) => {
                self.meta_files += 1;
                Ok(body.len())
            }
            Err(e) => {
                self.rejected += 1;
                tracing::warn!("mirror: {} not written: {e:?}", meta_rel.display());
                Err(e)
            }
        }
    }

    /// `sync_data` every open file; the first error is returned after trying all.
    pub fn sync_all(&mut self) -> std::io::Result<()> {
        let mut first = None;
        for (_, f) in &self.open {
            if let Err(e) = f.sync_data() {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }
}

/// Open `root/rel` for appending under the rules of the module doc. `root`
/// is created (0700 for the directories created) when missing and trusted
/// as given (it may sit behind a symlink such as `/tmp` → `/private/tmp`);
/// everything below it is checked level by level.
pub fn confine_and_open(root: &Path, rel: &Path) -> Result<File, Reject> {
    if !root.exists() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(root).map_err(|e| Reject::NotCreatable(format!("{}: {e}", root.display())))?;
    }
    let root = std::fs::canonicalize(root).map_err(|e| Reject::NotCreatable(format!("{}: {e}", root.display())))?;
    let parts: Vec<&std::ffi::OsStr> = rel
        .components()
        .map(|c| match c {
            Component::Normal(n) => Ok(n),
            other => Err(Reject::Unconfined(format!("{}: {other:?} component", rel.display()))),
        })
        .collect::<Result<_, _>>()?;
    let Some((file_name, dirs)) = parts.split_last() else {
        return Err(Reject::Unconfined("empty path".into()));
    };
    let mut dir = root;
    for name in dirs {
        dir.push(name);
        ensure_dir_level(&dir)?;
    }
    let path = dir.join(file_name);
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|e| if e.raw_os_error() == Some(libc::ELOOP) { Reject::Unconfined(format!("{} is a symlink", path.display())) } else { Reject::NotCreatable(format!("{}: {e}", path.display())) })?;
    let meta = file.metadata().map_err(|e| Reject::NotCreatable(format!("{}: {e}", path.display())))?;
    if !meta.file_type().is_file() {
        return Err(Reject::Unconfined(format!("{} is not a regular file", path.display())));
    }
    Ok(file)
}

/// Replace `root/rel` with `data`: the directories are walked like
/// [`confine_and_open`]; the data goes to `.<name>.<pid>.tmp` (created
/// exclusively, 0600, `O_NOFOLLOW`), is fsync'ed and renamed over the target
/// — refused when the target is a symlink or not a regular file.
pub fn replace_file(root: &Path, rel: &Path, data: &[u8]) -> Result<(), Reject> {
    if !root.exists() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(root).map_err(|e| Reject::NotCreatable(format!("{}: {e}", root.display())))?;
    }
    let mut dir = std::fs::canonicalize(root).map_err(|e| Reject::NotCreatable(format!("{}: {e}", root.display())))?;
    let parts: Vec<&std::ffi::OsStr> = rel
        .components()
        .map(|c| match c {
            Component::Normal(n) => Ok(n),
            other => Err(Reject::Unconfined(format!("{}: {other:?} component", rel.display()))),
        })
        .collect::<Result<_, _>>()?;
    let Some((file_name, dirs)) = parts.split_last() else {
        return Err(Reject::Unconfined("empty path".into()));
    };
    for name in dirs {
        dir.push(name);
        ensure_dir_level(&dir)?;
    }
    let target = dir.join(file_name);
    match std::fs::symlink_metadata(&target) {
        Ok(m) if !m.file_type().is_file() => return Err(Reject::Unconfined(format!("{} is not a regular file", target.display()))),
        _ => {}
    }
    let tmp = dir.join(format!(".{}.{}.tmp", file_name.to_string_lossy(), std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp)?;
        f.write_all(data)?;
        f.sync_data()?;
        std::fs::rename(&tmp, &target)
    })();
    result.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Reject::NotCreatable(format!("{}: {e}", target.display()))
    })
}

/// One directory level below the root: a real directory (created 0700 when
/// missing), never a symlink, never chmod'ed.
fn ensure_dir_level(dir: &Path) -> Result<(), Reject> {
    for _ in 0..2 {
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.file_type().is_symlink() => return Err(Reject::Unconfined(format!("{} is a symlink", dir.display()))),
            Ok(m) if !m.is_dir() => return Err(Reject::Unconfined(format!("{} is not a directory", dir.display()))),
            Ok(m) => {
                if m.permissions().mode() & 0o077 != 0 {
                    tracing::debug!("mirror: {} is group/other accessible (left as is)", dir.display());
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(Reject::NotCreatable(format!("{}: {e}", dir.display()))),
            },
            Err(e) => return Err(Reject::NotCreatable(format!("{}: {e}", dir.display()))),
        }
    }
    Err(Reject::NotCreatable(format!("{}: raced", dir.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLUG: &str = "-Users-mike-Documents-DeFi-ai-env";
    const SID: &str = "0fc50cce-c5c3-418e-980e-ff1861ab423d";

    struct Fx {
        _d: tempfile::TempDir,
        child: PathBuf,
        dest: PathBuf,
    }

    fn fx() -> Fx {
        let d = tempfile::tempdir().unwrap();
        let child = d.path().join("child").join("projects");
        let dest = d.path().join("dest");
        Fx { child, dest, _d: d }
    }

    fn writer(f: &Fx) -> Writer {
        Writer::new(MirrorCfg { child_projects_root: f.child.clone(), dest_root: f.dest.clone(), enabled: true, reason: String::new() })
    }

    fn raw(s: &str) -> Box<RawValue> {
        RawValue::from_string(s.to_string()).unwrap()
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn fp(f: &Fx, rel: &str) -> String {
        format!("{}/{rel}", f.child.display())
    }

    #[test]
    fn two_segment_append_is_byte_equal_and_appends() {
        let f = fx();
        let mut w = writer(&f);
        let e1 = raw(r#"{"z":1,"a":1e21,"n":2.50,"s":"q\"\tr","u":"é"}"#);
        let e2 = raw(r#"{"type":"user","message":{"content":[1, 2]}}"#);
        let path = fp(&f, &format!("{SLUG}/{SID}.jsonl"));
        assert_eq!(w.append(Some(&path), &[&e1, &e2]).unwrap(), e1.get().len() + e2.get().len() + 2);
        let e3 = raw(r#"{"type":"relocated"}"#);
        w.append(Some(&path), &[&e3]).unwrap();
        let file = f.dest.join(SLUG).join(format!("{SID}.jsonl"));
        let want = format!("{}\n{}\n{}\n", e1.get(), e2.get(), e3.get());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), want, "raw bytes, appended, never truncated");
        assert_eq!((w.appended_frames, w.appended_lines, w.rejected), (2, 3, 0));
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&f.dest.join(SLUG)), 0o700);
        w.sync_all().unwrap();
    }

    #[test]
    fn subagent_paths_and_meta_companions_keep_their_names() {
        let f = fx();
        let mut w = writer(&f);
        let e = raw(r#"{"k":"v"}"#);
        w.append(Some(&fp(&f, &format!("{SLUG}/{SID}/subagents/agent-a1.jsonl"))), &[&e]).unwrap();
        w.append(Some(&fp(&f, &format!("{SLUG}/{SID}/subagents/agent-a1.meta.json"))), &[&e]).unwrap();
        assert_eq!(std::fs::read_to_string(f.dest.join(SLUG).join(SID).join("subagents").join("agent-a1.jsonl")).unwrap(), "{\"k\":\"v\"}\n");
        assert!(f.dest.join(SLUG).join(SID).join("subagents").join("agent-a1.meta.json").is_file());
        assert_eq!(w.dest_for(&fp(&f, &format!("{SLUG}/{SID}/subagents/agent-a1.meta.json"))).unwrap(), f.dest.join(SLUG).join(SID).join("subagents").join("agent-a1.meta.json"));
        assert_eq!(mode(&f.dest.join(SLUG).join(SID).join("subagents")), 0o700);
    }

    #[test]
    fn bad_keys_are_rejected_and_counted() {
        let f = fx();
        let mut w = writer(&f);
        let e = raw("{}");
        let bad = [
            fp(&f, &format!("{SLUG}/{SID}/x.jsonl")),
            fp(&f, &format!("../{SLUG}/{SID}.jsonl")),
            format!("/elsewhere/{SLUG}/{SID}.jsonl"),
            format!("{}2/{SLUG}/{SID}.jsonl", f.child.display()),
            fp(&f, SLUG),
        ];
        for p in &bad {
            assert_eq!(w.append(Some(p), &[&e]), Err(Reject::BadKey), "{p}");
        }
        assert_eq!(w.append(None, &[&e]), Err(Reject::BadKey));
        assert_eq!(w.rejected, bad.len() as u64 + 1);
        assert_eq!(w.appended_frames, 0);
        assert!(!f.dest.exists(), "nothing was created for a rejected frame");
    }

    #[test]
    fn empty_entries_count_without_touching_the_disk() {
        let f = fx();
        let mut w = writer(&f);
        assert_eq!(w.append(Some(&fp(&f, &format!("{SLUG}/{SID}.jsonl"))), &[]), Ok(0));
        assert_eq!(w.appended_frames, 1);
        assert!(!f.dest.exists());
    }

    #[test]
    fn existing_directories_keep_their_mode() {
        let f = fx();
        std::fs::create_dir_all(f.dest.join(SLUG)).unwrap();
        std::fs::set_permissions(f.dest.join(SLUG), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut w = writer(&f);
        w.append(Some(&fp(&f, &format!("{SLUG}/{SID}.jsonl"))), &[&raw("{}")]).unwrap();
        assert_eq!(mode(&f.dest.join(SLUG)), 0o755, "the user's own directory is never chmod'ed");
    }

    #[test]
    fn symlinks_below_the_root_are_refused() {
        let f = fx();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(&f.dest).unwrap();
        std::os::unix::fs::symlink(outside.path(), f.dest.join(SLUG)).unwrap();
        let mut w = writer(&f);
        let r = w.append(Some(&fp(&f, &format!("{SLUG}/{SID}.jsonl"))), &[&raw("{}")]);
        assert!(matches!(r, Err(Reject::Unconfined(_))), "{r:?}");
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0, "nothing written through the link");
        // A symlinked target file is refused too.
        let slug2 = "-other";
        std::fs::create_dir_all(f.dest.join(slug2)).unwrap();
        let target = outside.path().join("t.jsonl");
        std::fs::write(&target, "x").unwrap();
        std::os::unix::fs::symlink(&target, f.dest.join(slug2).join(format!("{SID}.jsonl"))).unwrap();
        let r = w.append(Some(&fp(&f, &format!("{slug2}/{SID}.jsonl"))), &[&raw("{}")]);
        assert!(matches!(r, Err(Reject::Unconfined(_))), "{r:?}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");
        assert_eq!(w.rejected, 2);
    }

    #[test]
    fn the_lru_keeps_at_most_eight_files_open_yet_every_append_lands() {
        let f = fx();
        let mut w = writer(&f);
        let sids: Vec<String> = (0..10).map(|i| format!("{i:08x}-0000-4000-8000-000000000000")).collect();
        for s in &sids {
            w.append(Some(&fp(&f, &format!("{SLUG}/{s}.jsonl"))), &[&raw("{\"a\":1}")]).unwrap();
        }
        assert_eq!(w.open.len(), MAX_OPEN_FILES);
        w.append(Some(&fp(&f, &format!("{SLUG}/{}.jsonl", sids[0]))), &[&raw("{\"a\":2}")]).unwrap();
        assert_eq!(std::fs::read_to_string(f.dest.join(SLUG).join(format!("{}.jsonl", sids[0]))).unwrap(), "{\"a\":1}\n{\"a\":2}\n");
        assert_eq!(w.appended_frames, 11);
    }

    #[test]
    fn agent_metadata_goes_to_the_meta_json_companion() {
        let f = fx();
        let mut w = writer(&f);
        let path = fp(&f, &format!("{SLUG}/{SID}/subagents/agent-a1.jsonl"));
        let line = raw(r#"{"type":"user","n":1}"#);
        let meta1 = raw(r#"{"type":"agent_metadata","agentType":"general-purpose","isFork":false}"#);
        let meta2 = raw(r#"{"type":"agent_metadata","agentType":"general-purpose","description":"d"}"#);
        w.append(Some(&path), &[&meta1, &line, &meta2]).unwrap();
        let dir = f.dest.join(SLUG).join(SID).join("subagents");
        assert_eq!(std::fs::read_to_string(dir.join("agent-a1.jsonl")).unwrap(), "{\"type\":\"user\",\"n\":1}\n", "metadata is not a transcript line");
        assert_eq!(std::fs::read_to_string(dir.join("agent-a1.meta.json")).unwrap(), r#"{"agentType":"general-purpose","description":"d"}"#, "the last one, without its type");
        assert_eq!(mode(&dir.join("agent-a1.meta.json")), 0o600);
        // A metadata-only frame replaces the companion and appends nothing.
        w.append(Some(&path), &[&raw(r#"{"type":"agent_metadata"}"#)]).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("agent-a1.meta.json")).unwrap(), "{}");
        assert_eq!(std::fs::read_to_string(dir.join("agent-a1.jsonl")).unwrap().lines().count(), 1);
        assert_eq!(w.meta_files, 2);
        // On the main transcript an entry of that type is just a line.
        let main = fp(&f, &format!("{SLUG}/{SID}.jsonl"));
        w.append(Some(&main), &[&meta1]).unwrap();
        assert_eq!(std::fs::read_to_string(f.dest.join(SLUG).join(format!("{SID}.jsonl"))).unwrap().trim_end(), meta1.get());
        // A type member that is not first goes through a JSON round trip.
        assert_eq!(meta_body(&raw(r#"{"agentType":"x","type":"agent_metadata"}"#)).unwrap(), r#"{"agentType":"x"}"#);
    }

    #[test]
    fn line_separator_escapes_become_the_files_raw_characters() {
        assert_eq!(file_line(r#"{"s":"a\u2028b\u2029c"}"#), "{\"s\":\"a\u{2028}b\u{2029}c\"}");
        assert_eq!(file_line(r#"{"s":"\\u2028"}"#), r#"{"s":"\\u2028"}"#, "an escaped backslash followed by text stays");
        assert_eq!(file_line(r#"{"s":"\\\u2028"}"#), "{\"s\":\"\\\\\u{2028}\"}", "an escaped backslash, then a real escape");
        assert_eq!(file_line(r#"{"s":"\u00e9\n"}"#), r#"{"s":"\u00e9\n"}"#, "other escapes are the file's too");
        assert!(matches!(file_line(r#"{"plain":1}"#), Cow::Borrowed(_)));
        let f = fx();
        let mut w = writer(&f);
        w.append(Some(&fp(&f, &format!("{SLUG}/{SID}.jsonl"))), &[&raw(r#"{"s":"x\u2028y"}"#)]).unwrap();
        assert_eq!(std::fs::read_to_string(f.dest.join(SLUG).join(format!("{SID}.jsonl"))).unwrap(), "{\"s\":\"x\u{2028}y\"}\n");
    }

    #[test]
    fn a_disabled_writer_skips() {
        let f = fx();
        let mut w = Writer::new(MirrorCfg { enabled: false, ..writer(&f).cfg.clone() });
        assert_eq!(w.append(Some(&fp(&f, &format!("{SLUG}/{SID}.jsonl"))), &[&raw("{}")]), Err(Reject::Disabled));
        assert_eq!((w.skipped, w.rejected), (1, 0));
    }

    #[test]
    fn decide_matrix() {
        let d = tempfile::tempdir().unwrap();
        let mac = d.path().join("mac");
        let other = d.path().join("scratch");
        std::fs::create_dir_all(&mac).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let c = decide(false, true, &mac, &mac, None);
        assert!(!c.enabled);
        assert!(c.reason.starts_with("mirror writer disabled: local child writes") && c.reason.contains("itself"), "{}", c.reason);
        let c = decide(false, true, &other, &mac, None);
        assert!(c.enabled, "{}", c.reason);
        assert_eq!((c.child_projects_root, c.dest_root), (other.join("projects"), mac.join("projects")));
        let root = d.path().join("mirror");
        let c = decide(false, true, &mac, &mac, Some(&root));
        assert!(c.enabled && c.dest_root == root, "{}", c.reason);
        let c = decide(false, true, &mac, &mac, Some(&mac.join("projects")));
        assert!(!c.enabled && c.reason.contains("is the destination"), "{}", c.reason);
        let c = decide(true, true, &mac, &mac, None);
        assert!(!c.enabled && c.reason.contains("is the destination"), "a remote route with a local child still never double-appends: {}", c.reason);
        let c = decide(true, false, &mac, &mac, None);
        assert!(c.enabled, "a remote child writes a VM disk: {}", c.reason);
        // Trailing separators and "." do not defeat the comparison.
        let c = decide(false, true, &d.path().join("x/./"), &d.path().join("x"), None);
        assert!(!c.enabled, "{}", c.reason);
    }
}
