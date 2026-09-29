//! The session registry: `<bridge root>/state/sessions/<uuid>.toml`, one row
//! per session the wrapper piped (S2), later extended by S8/S10 (VM ids,
//! spawn ids, acked sequence numbers, seeded heads). The wrapper that owns a
//! session is the only writer of its row (no lock in S2 — the per-workspace
//! flock of §2.4 guards VM placement from S4 on, not this file); every write
//! is atomic (temp file named after the writer's pid, fsync, rename, dir
//! fsync), so a wrapper killed mid-write never blocks a later one.
//!
//! A row never holds a request body: `host_state` carries digests and an
//! allowlisted summary (`mcp_set_servers` and `apply_flag_settings` bodies
//! can carry API keys the scrubber does not recognise; the full requests live
//! in the pump's memory only).
//!
//! Every path is built from a session id only after [`is_uuid`] accepted it,
//! so no id can traverse out of `state/sessions` or `state/scratch`. The
//! operator commands `ai-env session list|show|forget` live at the bottom
//! ([`cmd_list`], [`cmd_show`], [`cmd_forget`]).
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::errors::CliError;
use crate::wire::time;
use crate::{bail, outln};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Schema version written into every row's `v` field.
pub const REGISTRY_SCHEMA_V: u8 = 1;

/// What the registry records of the host's state requests: digests plus a
/// summary of allowlisted fields, never request bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostStateSnapshot {
    /// `sha256` hex of the recorded `initialize` request object.
    pub initialize_sha256: Option<String>,
    /// Its length in bytes.
    pub initialize_bytes: Option<u64>,
    /// From the last `set_permission_mode.mode`.
    pub permission_mode: Option<String>,
    /// From the last `apply_flag_settings.settings.model` or `set_model.model`
    /// (whichever came last).
    pub model: Option<String>,
    /// From the last `set_max_thinking_tokens.max_thinking_tokens`.
    pub max_thinking_tokens: Option<u64>,
    /// The server names of the last `mcp_set_servers.servers` (keys only).
    pub mcp_server_names: Vec<String>,
    /// The union of top-level keys of every `apply_flag_settings.settings`
    /// (sorted, deduplicated; values never).
    pub flag_keys: Vec<String>,
    /// Per recorded subtype: `sha256:<hex>:<len>` of its last request object.
    pub recorded: BTreeMap<String, String>,
}

/// One `<uuid>.toml`. Every field has a default so rows written by an older
/// or newer wrapper still read.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionRow {
    pub v: u8,
    /// From the first forwarded `system/init`.
    pub session_id: String,
    /// The child's projects subdirectory (`pump::child_slug`).
    pub slug: Option<String>,
    pub cwd: Option<String>,
    /// `<slug>/<session_id>.jsonl`, relative to a projects root.
    pub transcript_rel: Option<String>,
    /// RFC 3339 UTC.
    pub created: String,
    /// RFC 3339 UTC; rewritten on each forwarded `result` and at exit.
    pub last_seen: String,
    /// `active` | `closed` (S8/S10 add `detached` | `migrating`).
    pub status: String,
    /// `local-child` | `local-scratch` | `remote`.
    pub mode: String,
    /// `remote` | `local:outside_roots` | `local:unconfigured`.
    pub route: String,
    /// Bundle version from argv[1]'s path.
    pub ext: Option<String>,
    /// The wrapper's pid.
    pub pid: u32,
    pub child_pid: Option<u32>,
    /// Absent while active.
    pub exit: Option<i32>,
    /// sha256 hex of the redacted argv joined by NUL.
    pub argv_hash: String,
    pub respawns: u32,
    pub child_config_dir: Option<String>,
    pub mirror_root: Option<String>,
    /// `local-scratch` only; informational (`forget` derives the path from the uuid).
    pub scratch_dir: Option<String>,
    pub host_state: HostStateSnapshot,
    // Reserved by plan §2.4, filled by S8/S10.
    pub microvm_id: Option<String>,
    pub spawn_id: Option<String>,
    pub last_acked_seq: Option<u64>,
    pub seeded_head: Option<String>,
    pub last_wip_fetch: Option<String>,
    pub vms: Vec<toml::Value>,
}

/// What [`forget`] removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForgetReport {
    /// `state/sessions/<uuid>.toml` existed and was deleted.
    pub removed_row: bool,
    /// `state/scratch/<uuid>` was a real directory and was deleted with its contents.
    pub removed_scratch: bool,
}

// ---- ids and paths ---------------------------------------------------------------------

/// Is `s` a canonical uuid: 36 characters, hex digits (either case) in the
/// 8-4-4-4-12 groups, `-` at offsets 8, 13, 18 and 23? The same shape as the
/// session picker's regex. Checked before ANY path is built from an id, so
/// `..`, `/` and empty strings never reach the filesystem.
#[must_use]
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// `<root>/state/sessions/<session_id>.toml`; `Err(Config)` for anything that
/// is not a uuid (no traversal is possible through an accepted id).
pub fn path_for(paths: &Paths, session_id: &str) -> Result<PathBuf, BridgeError> {
    if !is_uuid(session_id) {
        return Err(BridgeError::Config(format!("not a session id: {session_id:?}")));
    }
    Ok(paths.sessions().join(format!("{session_id}.toml")))
}

/// Wrap an I/O error with what was being done and to which path, keeping its
/// kind (a broken pipe still maps to exit 0 upstream).
fn io_at<'a>(what: &'static str, path: &'a Path) -> impl FnOnce(std::io::Error) -> BridgeError + 'a {
    move |e| BridgeError::Io(std::io::Error::new(e.kind(), format!("{what} {}: {e}", path.display())))
}

/// Make `dir` a real 0700 directory: created (with missing parents, 0700) when
/// absent, refused when it is a symlink or not a directory, chmod'ed to 0700
/// when it exists wider (it is the bridge's own state directory).
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<(), BridgeError> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(BridgeError::Config(format!("{} is a symlink; refusing to write sessions through it", dir.display()))),
        Ok(meta) if !meta.is_dir() => Err(BridgeError::Config(format!("{} is not a directory", dir.display()))),
        Ok(meta) => {
            if meta.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io_at("cannot chmod", dir))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(io_at("cannot create", dir)),
        Err(e) => Err(io_at("cannot stat", dir)(e)),
    }
}

/// `true` when `path` exists as a symlink (the link itself, not followed).
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// Remove `path` if it exists; a missing file is not an error.
pub(crate) fn remove_if_present(path: &Path) -> Result<bool, BridgeError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_at("cannot remove", path)(e)),
    }
}

// ---- write / read / list ---------------------------------------------------------------

/// Atomically replace `<root>/state/sessions/<row.session_id>.toml` with `row`.
///
/// Refuses a non-uuid `session_id`. Makes the sessions directory a real 0700
/// directory first (see `ensure_private_dir`). The TOML goes to
/// `.<id>.toml.<pid>.tmp` in the same directory — a leftover with exactly that
/// name (this pid, killed mid-write) is removed first; another pid's leftover
/// is never touched and never blocks — created `create_new`, 0600,
/// `O_NOFOLLOW|O_CLOEXEC`, written, fsync'ed, then renamed over the target
/// (refused when the target is a symlink) and the directory fsync'ed
/// (best effort). The temp file is removed on any error.
pub fn write(paths: &Paths, row: &SessionRow) -> Result<(), BridgeError> {
    let target = path_for(paths, &row.session_id)?;
    let dir = paths.sessions();
    ensure_private_dir(&dir)?;
    let text = toml::to_string_pretty(row).map_err(|e| BridgeError::Config(format!("session {}: cannot serialise the row: {e}", row.session_id)))?;
    let tmp = dir.join(format!(".{}.toml.{}.tmp", row.session_id, std::process::id()));
    remove_if_present(&tmp)?;
    let result = write_and_rename(&tmp, &target, text.as_bytes());
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The body of [`write`] between the temp file's creation and the rename.
fn write_and_rename(tmp: &Path, target: &Path, data: &[u8]) -> Result<(), BridgeError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(tmp)
        .map_err(io_at("cannot create", tmp))?;
    file.write_all(data).map_err(io_at("cannot write", tmp))?;
    file.sync_all().map_err(io_at("cannot fsync", tmp))?;
    drop(file);
    if is_symlink(target) {
        return Err(BridgeError::Config(format!("{} is a symlink; refusing to replace it", target.display())));
    }
    std::fs::rename(tmp, target).map_err(io_at("cannot rename onto", target))
}

/// The row of `session_id`: `Ok(None)` when its file does not exist; `Err`
/// for a non-uuid, a symlink, a non-regular file, or TOML that does not parse
/// (the message names the file and carries only the first line of the parser
/// error, never file content). A row without a `session_id` takes the file
/// name's. The open is `O_NOFOLLOW|O_NONBLOCK`, so neither a swapped-in
/// symlink nor a FIFO can redirect or block it.
pub fn read(paths: &Paths, session_id: &str) -> Result<Option<SessionRow>, BridgeError> {
    let path = path_for(paths, session_id)?;
    let Some(text) = read_regular_file(&path)? else {
        return Ok(None);
    };
    let mut row = parse_row(&path, &text)?;
    if row.session_id.is_empty() {
        row.session_id = session_id.to_string();
    }
    Ok(Some(row))
}

/// The contents of `path` when it is a regular file; `None` when it is missing.
pub(crate) fn read_regular_file(path: &Path) -> Result<Option<String>, BridgeError> {
    let opened = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(path);
    let mut file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(BridgeError::Config(format!("{} is a symlink; refusing to read it", path.display()))),
        Err(e) => return Err(io_at("cannot open", path)(e)),
    };
    if !file.metadata().map_err(io_at("cannot stat", path))?.is_file() {
        return Err(BridgeError::Config(format!("{} is not a regular file", path.display())));
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(io_at("cannot read", path))?;
    Ok(Some(text))
}

/// Parse one row; the error names `path` and keeps the parser's first line only.
fn parse_row(path: &Path, text: &str) -> Result<SessionRow, BridgeError> {
    toml::from_str(text).map_err(|e| {
        let msg = e.to_string();
        BridgeError::Config(format!("{}: {}", path.display(), msg.lines().next().unwrap_or("unparseable")))
    })
}

/// The session id named by a directory entry `<uuid>.toml`, else `None`
/// (dotfiles, `*.tmp`, other suffixes and non-uuid stems included).
fn row_file_id(name: &std::ffi::OsStr) -> Option<&str> {
    name.to_str().and_then(|n| n.strip_suffix(".toml")).filter(|id| is_uuid(id))
}

/// Every row in `state/sessions`, newest `last_seen` first, ties by
/// `session_id` ascending. A missing directory is an empty list; only regular
/// files named `<uuid>.toml` are read (symlinks, dotfiles, temp files and
/// other names are ignored); a row that fails to read or parse is skipped
/// with a `warn!`.
pub fn list(paths: &Paths) -> Result<Vec<SessionRow>, BridgeError> {
    let dir = paths.sessions();
    let entries = match std::fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_at("cannot list", &dir)(e)),
    };
    let mut rows = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io_at("cannot list", &dir))?;
        let name = entry.file_name();
        let Some(id) = row_file_id(&name) else { continue };
        // The dirent type never follows a symlink.
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        match read(paths, id) {
            Ok(Some(row)) => rows.push(row),
            Ok(None) => {}
            Err(e) => tracing::warn!("session registry: skipping {id}: {e}"),
        }
    }
    sort_rows(&mut rows);
    Ok(rows)
}

/// `last_seen` descending (RFC 3339 UTC sorts lexically), then `session_id` ascending.
fn sort_rows(rows: &mut [SessionRow]) {
    rows.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| a.session_id.cmp(&b.session_id)));
}

// ---- forget ------------------------------------------------------------------------------

/// Delete a session's row and its scratch config dir.
///
/// Refuses a non-uuid, and a row whose `status` is `active` while its wrapper
/// pid is alive. The scratch dir is DERIVED from the id
/// (`<root>/state/scratch/<id>`), never taken from the row's `scratch_dir`, and
/// is removed only when `symlink_metadata` says it is a real directory — a
/// symlink there is left alone, and so is its target. A row that exists but
/// does not parse (or is a symlink / not a regular file) is still removed
/// (with a `warn!`): a corrupt row cannot belong to a live wrapper, whose
/// writes are atomic. An I/O error reading the row is returned instead — the
/// active check could not run, so nothing is removed.
pub fn forget(paths: &Paths, session_id: &str) -> Result<ForgetReport, BridgeError> {
    let row_path = path_for(paths, session_id)?;
    match read(paths, session_id) {
        Ok(Some(row)) if row.status == "active" && pid_alive(row.pid) => {
            return Err(BridgeError::Config(format!("session {session_id} is still active (wrapper pid {}); close it first", row.pid)));
        }
        Ok(_) => {}
        Err(e @ BridgeError::Config(_)) => tracing::warn!("session registry: forgetting an unreadable row: {e}"),
        Err(e) => return Err(e),
    }
    let scratch = paths.scratch().join(session_id);
    if let Some(owner) = scratch_owner(&scratch).filter(|pid| pid_alive(*pid)) {
        return Err(BridgeError::Config(format!("the scratch config dir of session {session_id} is in use by wrapper pid {owner}; close that session first")));
    }
    let removed_scratch = remove_scratch_dir(&scratch)?;
    let removed_row = remove_if_present(&row_path)?;
    Ok(ForgetReport { removed_row, removed_scratch })
}

/// The file a pump writes into a scratch config dir while its child uses it
/// (the pump's pid, decimal); removed when the pump ends.
pub const SCRATCH_OWNER_FILE: &str = ".ai-env-owner";

/// The pid recorded in `<dir>/.ai-env-owner`, if the file is a regular file
/// holding a number (never follows a symlink).
#[must_use]
pub fn scratch_owner(dir: &Path) -> Option<u32> {
    let path = dir.join(SCRATCH_OWNER_FILE);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() || meta.len() > 32 {
        return None;
    }
    std::fs::read_to_string(&path).ok()?.trim().parse().ok()
}

/// `remove_dir_all(dir)` when `dir` itself is a real directory; `Ok(false)`
/// when it is missing, a symlink (left alone) or anything else.
fn remove_scratch_dir(dir: &Path) -> Result<bool, BridgeError> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_dir() => {
            std::fs::remove_dir_all(dir).map_err(io_at("cannot remove", dir))?;
            Ok(true)
        }
        Ok(meta) => {
            let kind = if meta.file_type().is_symlink() { "a symlink" } else { "not a directory" };
            tracing::warn!("session registry: {} is {kind}; left alone", dir.display());
            Ok(false)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_at("cannot stat", dir)(e)),
    }
}

// ---- small helpers used by the pump ------------------------------------------------------

/// Does a process with this pid exist? `kill(pid, 0)` succeeding, or failing
/// with `EPERM` (it exists but belongs to someone else), means yes. Pid 0 and
/// pids above `i32::MAX` (process groups / invalid as `pid_t`) are never alive.
#[must_use]
pub fn pid_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill(2) with signal 0 sends nothing; it only checks that the pid exists and may be signalled.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Lowercase hex sha256 of the (already redacted) argv joined by `\0` — the
/// row's `argv_hash`, comparable across rows without storing the argv.
#[must_use]
pub fn argv_hash(redacted_argv: &[String]) -> String {
    let mut h = Sha256::new();
    for (i, arg) in redacted_argv.iter().enumerate() {
        if i > 0 {
            h.update([0u8]);
        }
        h.update(arg.as_bytes());
    }
    hex::encode(h.finalize())
}

/// The current time as `YYYY-MM-DDTHH:MM:SSZ` (the row's `created`/`last_seen`).
#[must_use]
pub fn now_rfc3339() -> String {
    time::rfc3339_utc(time::unix_now())
}

// ---- `ai-env session …` ------------------------------------------------------------------

/// One text line of `session list`: id, status, mode, last_seen, slug (`-` when unset).
fn list_line(row: &SessionRow) -> String {
    format!("{}  {:<6}  {:<13}  {}  {}", row.session_id, row.status, row.mode, row.last_seen, row.slug.as_deref().unwrap_or("-"))
}

/// The suffix of `forgot <uuid>…`, or `None` when nothing was removed.
fn forget_suffix(r: ForgetReport) -> Option<&'static str> {
    match (r.removed_row, r.removed_scratch) {
        (true, false) => Some(" (row)"),
        (true, true) => Some(" (row, scratch dir)"),
        (false, true) => Some(" (scratch dir)"),
        (false, false) => None,
    }
}

/// Pretty JSON of any row(s), mapped into the CLI error type.
fn to_json<T: Serialize + ?Sized>(value: &T) -> crate::errors::Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))
}

/// `ai-env session list [--json]`: every registered session, newest first.
/// Text: one line per row (`<id>  <status>  <mode>  <last_seen>  <slug>`), or
/// `no sessions yet`; JSON: a pretty array (`[]` when empty).
pub fn cmd_list(json: bool) -> crate::errors::Result<()> {
    let paths = Paths::resolve()?;
    let rows = list(&paths)?;
    if json {
        outln!("{}", to_json(&rows)?);
    } else if rows.is_empty() {
        outln!("no sessions yet");
    } else {
        for row in &rows {
            outln!("{}", list_line(row));
        }
    }
    Ok(())
}

/// `ai-env session show UUID [--json]`: the row as TOML (or pretty JSON).
/// A non-uuid is a usage error (exit 2); an unknown session exits 1.
pub fn cmd_show(uuid: &str, json: bool) -> crate::errors::Result<()> {
    if !is_uuid(uuid) {
        return Err(CliError::Usage(format!("not a session id: {uuid}")));
    }
    let paths = Paths::resolve()?;
    let Some(row) = read(&paths, uuid)? else {
        bail!("no session {uuid}");
    };
    if json {
        outln!("{}", to_json(&row)?);
    } else {
        let text = toml::to_string_pretty(&row).map_err(|e| CliError::Msg(format!("cannot render TOML: {e}")))?;
        outln!("{}", text.trim_end_matches('\n'));
    }
    Ok(())
}

/// `ai-env session forget UUID`: delete the row and the derived scratch dir
/// (refused while the session is active). A non-uuid is a usage error (exit
/// 2); nothing to remove exits 1 with `no session <uuid>`.
pub fn cmd_forget(uuid: &str) -> crate::errors::Result<()> {
    if !is_uuid(uuid) {
        return Err(CliError::Usage(format!("not a session id: {uuid}")));
    }
    let paths = Paths::resolve()?;
    let Some(what) = forget_suffix(forget(&paths, uuid)?) else {
        bail!("no session {uuid}");
    };
    outln!("forgot {uuid}{what}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A deterministic uuid-shaped id for test row `n`.
    fn id(n: u32) -> String {
        format!("{n:08x}-0000-7000-8000-{n:012x}")
    }

    fn paths_in(dir: &tempfile::TempDir) -> Paths {
        Paths::from_root_and_env(dir.path().to_path_buf(), None)
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn row(n: u32, last_seen: &str) -> SessionRow {
        SessionRow { v: REGISTRY_SCHEMA_V, session_id: id(n), last_seen: last_seen.into(), status: "closed".into(), mode: "local-child".into(), ..SessionRow::default() }
    }

    fn digest(label: &str) -> String {
        hex::encode(Sha256::digest(label.as_bytes()))
    }

    /// Every field set, including every `host_state` field and the recorded map.
    fn full_row() -> SessionRow {
        let sid = id(7);
        let mut recorded = BTreeMap::new();
        recorded.insert("set_permission_mode".to_string(), format!("sha256:{}:41", digest("perm")));
        recorded.insert("apply_flag_settings".to_string(), format!("sha256:{}:63", digest("flags")));
        SessionRow {
            v: REGISTRY_SCHEMA_V,
            session_id: sid.clone(),
            slug: Some("-Users-mike-Documents-DeFi-ai-env".into()),
            cwd: Some("/Users/mike/Documents/DeFi/ai-env".into()),
            transcript_rel: Some(format!("-Users-mike-Documents-DeFi-ai-env/{sid}.jsonl")),
            created: "2026-09-25T10:00:00Z".into(),
            last_seen: "2026-09-25T10:03:12Z".into(),
            status: "closed".into(),
            mode: "local-scratch".into(),
            route: "local:outside_roots".into(),
            ext: Some("2.1.278".into()),
            pid: 4242,
            child_pid: Some(4250),
            exit: Some(-15),
            argv_hash: argv_hash(&["--output-format".to_string(), "stream-json".to_string()]),
            respawns: 1,
            child_config_dir: Some("/tmp/scratch".into()),
            mirror_root: Some("/tmp/mirror".into()),
            scratch_dir: Some(format!("/tmp/state/scratch/{sid}")),
            host_state: HostStateSnapshot {
                initialize_sha256: Some(digest("init")),
                initialize_bytes: Some(18_342),
                permission_mode: Some("default".into()),
                model: Some("claude-test-model".into()),
                max_thinking_tokens: Some(8000),
                mcp_server_names: vec!["github".into(), "linear".into()],
                flag_keys: vec!["model".into(), "viewMode".into()],
                recorded,
            },
            microvm_id: Some("vm-1".into()),
            spawn_id: Some("spawn-1".into()),
            last_acked_seq: Some(99),
            seeded_head: Some("head-1".into()),
            last_wip_fetch: Some("2026-09-25T10:01:00Z".into()),
            vms: Vec::new(),
        }
    }

    #[test]
    fn is_uuid_accepts_both_cases_and_rejects_malformed() {
        assert!(is_uuid("b1e6c0de-0000-4000-8000-00000000abcd"));
        assert!(is_uuid("B1E6C0DE-0000-4000-8000-00000000ABCD"));
        assert!(is_uuid(&id(1)));
        for bad in [
            "",
            "../x",
            "b1e6c0de-0000-4000-8000-00000000abc",          // 35
            "b1e6c0de-0000-4000-8000-00000000abcde",        // 37
            "b1e6c0de00000-4000-8000-00000000abcd",         // missing dash
            "b1e6c0de-0000-4000-8000_00000000abcd",         // wrong separator
            "b1e6c0dex0000-4000-8000-00000000abcd",
            "g1e6c0de-0000-4000-8000-00000000abcd",         // non-hex
            "b1e6c0de-0000-4000-8000-00000000abc/",
            "../../../../../../../../../../etc/pw",         // 36 chars, not a uuid
            "b1e6c0de-0000-4000-8000-00000000abcd\n",
        ] {
            assert!(!is_uuid(bad), "{bad:?}");
        }
    }

    #[test]
    fn path_for_refuses_traversal() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        assert_eq!(path_for(&p, &id(3)).unwrap(), p.sessions().join(format!("{}.toml", id(3))));
        for bad in ["../x", "..", "", "a/b", "/etc/passwd"] {
            let e = path_for(&p, bad).unwrap_err();
            assert!(matches!(e, BridgeError::Config(_)), "{bad:?}: {e}");
        }
    }

    #[test]
    fn write_read_round_trip_full_row() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        let r = full_row();
        write(&p, &r).unwrap();
        assert_eq!(read(&p, &r.session_id).unwrap(), Some(r.clone()));
        let text = std::fs::read_to_string(path_for(&p, &r.session_id).unwrap()).unwrap();
        assert!(text.contains("[host_state.recorded]"), "{text}");
        // Rewriting the same row is idempotent and leaves no temp file behind.
        write(&p, &r).unwrap();
        assert_eq!(read(&p, &r.session_id).unwrap(), Some(r));
        let names: Vec<String> = std::fs::read_dir(p.sessions()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(names, vec![format!("{}.toml", id(7))]);
    }

    #[test]
    fn write_read_round_trip_default_row() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        let r = SessionRow { session_id: id(8), ..SessionRow::default() };
        write(&p, &r).unwrap();
        assert_eq!(read(&p, &id(8)).unwrap(), Some(r));
    }

    #[test]
    fn write_refuses_a_non_uuid_row() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        let r = SessionRow { session_id: "../escape".into(), ..SessionRow::default() };
        assert!(matches!(write(&p, &r), Err(BridgeError::Config(_))));
        assert!(!p.root.join("state").exists(), "nothing created for a refused id");
    }

    #[test]
    fn modes_are_0600_and_0700_and_a_wide_dir_is_tightened() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        write(&p, &row(1, "2026-09-25T10:00:00Z")).unwrap();
        assert_eq!(mode_of(&p.sessions()), 0o700);
        assert_eq!(mode_of(&path_for(&p, &id(1)).unwrap()), 0o600);

        let e = tempfile::tempdir().unwrap();
        let q = paths_in(&e);
        std::fs::create_dir_all(q.sessions()).unwrap();
        std::fs::set_permissions(q.sessions(), std::fs::Permissions::from_mode(0o755)).unwrap();
        write(&q, &row(2, "2026-09-25T10:00:00Z")).unwrap();
        assert_eq!(mode_of(&q.sessions()), 0o700, "a pre-existing 0755 sessions dir is tightened");
        assert_eq!(mode_of(&path_for(&q, &id(2)).unwrap()), 0o600);
    }

    #[test]
    fn write_refuses_a_symlinked_or_non_dir_sessions_path() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(p.root.join("state")).unwrap();
        symlink(&elsewhere, p.sessions()).unwrap();
        let e = write(&p, &row(1, "")).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);

        std::fs::remove_file(p.sessions()).unwrap();
        std::fs::write(p.sessions(), "x").unwrap();
        let e = write(&p, &row(1, "")).unwrap_err();
        assert!(e.to_string().contains("not a directory"), "{e}");
    }

    #[test]
    fn leftover_temp_files_never_block_a_write() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        std::fs::create_dir_all(p.sessions()).unwrap();
        let other_pid = std::process::id().wrapping_add(1);
        let other = p.sessions().join(format!(".{}.toml.{other_pid}.tmp", id(4)));
        let own = p.sessions().join(format!(".{}.toml.{}.tmp", id(4), std::process::id()));
        std::fs::write(&other, "stale other").unwrap();
        std::fs::write(&own, "stale own").unwrap();
        let r = row(4, "2026-09-25T10:00:00Z");
        write(&p, &r).unwrap();
        assert_eq!(read(&p, &id(4)).unwrap(), Some(r));
        assert!(!own.exists(), "our own leftover is replaced and renamed away");
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "stale other", "another pid's leftover is not touched");
    }

    #[test]
    fn write_refuses_a_symlinked_target_and_cleans_its_temp_file() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        std::fs::create_dir_all(p.sessions()).unwrap();
        let outside = d.path().join("outside.toml");
        std::fs::write(&outside, "original").unwrap();
        symlink(&outside, path_for(&p, &id(5)).unwrap()).unwrap();
        let e = write(&p, &row(5, "")).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "original");
        assert!(is_symlink(&path_for(&p, &id(5)).unwrap()), "the link itself is left in place");
        assert!(!p.sessions().join(format!(".{}.toml.{}.tmp", id(5), std::process::id())).exists());
    }

    #[test]
    fn read_missing_symlink_and_unparseable() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        assert_eq!(read(&p, &id(1)).unwrap(), None, "no sessions dir at all");
        std::fs::create_dir_all(p.sessions()).unwrap();
        assert_eq!(read(&p, &id(1)).unwrap(), None);
        assert!(matches!(read(&p, "../x"), Err(BridgeError::Config(_))));

        let outside = d.path().join("outside.toml");
        std::fs::write(&outside, toml::to_string_pretty(&row(2, "")).unwrap()).unwrap();
        symlink(&outside, path_for(&p, &id(2)).unwrap()).unwrap();
        let e = read(&p, &id(2)).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");

        let bad = path_for(&p, &id(3)).unwrap();
        std::fs::write(&bad, "v = 1\npid = \"not a number\"\n").unwrap();
        let e = read(&p, &id(3)).unwrap_err().to_string();
        assert!(e.contains(&format!("{}.toml", id(3))), "names the file: {e}");
        assert!(!e.contains('\n'), "first line only: {e}");
        assert!(!e.contains("not a number"), "no file content: {e}");

        std::fs::create_dir(path_for(&p, &id(4)).unwrap()).unwrap();
        let e = read(&p, &id(4)).unwrap_err();
        assert!(e.to_string().contains("not a regular file"), "{e}");
    }

    #[test]
    fn old_row_with_unknown_keys_and_missing_fields_parses() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        std::fs::create_dir_all(p.sessions()).unwrap();
        let text = "v = 0\nstatus = \"closed\"\nfuture_key = \"x\"\n\n[host_state]\nmodel = \"m\"\nfuture_nested = 3\n\n[future_table]\na = 1\n";
        std::fs::write(path_for(&p, &id(9)).unwrap(), text).unwrap();
        let r = read(&p, &id(9)).unwrap().unwrap();
        assert_eq!(r.session_id, id(9), "a row without session_id takes the file name's");
        assert_eq!(r.status, "closed");
        assert_eq!(r.v, 0);
        assert_eq!(r.pid, 0);
        assert_eq!(r.host_state.model.as_deref(), Some("m"));
        assert!(r.host_state.recorded.is_empty() && r.vms.is_empty() && r.slug.is_none());
    }

    #[test]
    fn list_orders_rows_and_skips_junk() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        assert!(list(&p).unwrap().is_empty(), "a missing dir is an empty list");
        let a = row(0xa, "2026-09-25T10:00:00Z");
        let b = row(0xb, "2026-09-25T11:00:00Z");
        let c = row(0x3, "2026-09-25T10:00:00Z");
        for r in [&a, &b, &c] {
            write(&p, r).unwrap();
        }
        let s = p.sessions();
        let valid = toml::to_string_pretty(&row(0x20, "2026-09-25T12:00:00Z")).unwrap();
        std::fs::write(s.join("notes.txt"), &valid).unwrap();
        std::fs::write(s.join("not-a-uuid.toml"), &valid).unwrap();
        std::fs::write(s.join(format!(".{}.toml", id(0x21))), &valid).unwrap();
        std::fs::write(s.join(format!(".{}.toml.123.tmp", id(0x22))), &valid).unwrap();
        std::fs::write(s.join(format!("{}.toml.tmp", id(0x23))), &valid).unwrap();
        let outside = d.path().join("outside.toml");
        std::fs::write(&outside, &valid).unwrap();
        symlink(&outside, s.join(format!("{}.toml", id(0x24)))).unwrap();
        std::fs::write(s.join(format!("{}.toml", id(0x25))), "this = = not toml").unwrap();
        std::fs::create_dir(s.join(format!("{}.toml", id(0x26)))).unwrap();
        let ids: Vec<String> = list(&p).unwrap().into_iter().map(|r| r.session_id).collect();
        assert_eq!(ids, vec![id(0xb), id(0x3), id(0xa)], "last_seen desc, then id asc; junk skipped");
    }

    #[test]
    fn forget_removes_the_row_and_the_derived_scratch_dir() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        let mut r = row(1, "2026-09-25T10:00:00Z");
        // The stored scratch_dir is never used: it points at something that must survive.
        let decoy = d.path().join("decoy");
        std::fs::create_dir_all(&decoy).unwrap();
        r.scratch_dir = Some(decoy.display().to_string());
        write(&p, &r).unwrap();
        let scratch = p.scratch().join(id(1));
        std::fs::create_dir_all(scratch.join("projects").join("slug")).unwrap();
        std::fs::write(scratch.join("projects").join("slug").join("x.jsonl"), "{}\n").unwrap();
        assert_eq!(forget(&p, &id(1)).unwrap(), ForgetReport { removed_row: true, removed_scratch: true });
        assert!(!scratch.exists() && !path_for(&p, &id(1)).unwrap().exists());
        assert!(decoy.is_dir());
        assert_eq!(forget(&p, &id(1)).unwrap(), ForgetReport::default(), "nothing left");

        write(&p, &row(2, "")).unwrap();
        assert_eq!(forget(&p, &id(2)).unwrap(), ForgetReport { removed_row: true, removed_scratch: false });
        std::fs::create_dir_all(p.scratch().join(id(3))).unwrap();
        assert_eq!(forget(&p, &id(3)).unwrap(), ForgetReport { removed_row: false, removed_scratch: true });
    }

    #[test]
    fn forget_leaves_a_symlinked_scratch_path_alone() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        write(&p, &row(1, "")).unwrap();
        let target = d.path().join("precious");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("keep.txt"), "keep").unwrap();
        std::fs::create_dir_all(p.scratch()).unwrap();
        let link = p.scratch().join(id(1));
        symlink(&target, &link).unwrap();
        assert_eq!(forget(&p, &id(1)).unwrap(), ForgetReport { removed_row: true, removed_scratch: false });
        assert!(is_symlink(&link), "the link stays");
        assert_eq!(std::fs::read_to_string(target.join("keep.txt")).unwrap(), "keep");
    }

    #[test]
    fn forget_refuses_an_active_row_with_a_live_pid() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        let mut r = row(1, "");
        r.status = "active".into();
        r.pid = std::process::id();
        write(&p, &r).unwrap();
        std::fs::create_dir_all(p.scratch().join(id(1))).unwrap();
        let e = forget(&p, &id(1)).unwrap_err().to_string();
        assert!(e.contains(&format!("session {} is still active (wrapper pid {})", id(1), std::process::id())), "{e}");
        assert!(path_for(&p, &id(1)).unwrap().exists() && p.scratch().join(id(1)).is_dir(), "nothing removed");
    }

    #[test]
    fn forget_fails_closed_when_the_row_cannot_be_read() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        let mut r = row(1, "");
        r.status = "active".into();
        r.pid = std::process::id();
        write(&p, &r).unwrap();
        std::fs::create_dir_all(p.scratch().join(id(1))).unwrap();
        let row_path = path_for(&p, &id(1)).unwrap();
        // EACCES on open (as root the read succeeds and the active check refuses instead).
        std::fs::set_permissions(&row_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(forget(&p, &id(1)).is_err());
        assert!(row_path.exists() && p.scratch().join(id(1)).is_dir(), "nothing removed");
    }

    #[test]
    fn forget_allows_an_active_row_whose_pid_is_dead() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        let mut r = row(1, "");
        r.status = "active".into();
        r.pid = i32::MAX as u32;
        write(&p, &r).unwrap();
        assert_eq!(forget(&p, &id(1)).unwrap(), ForgetReport { removed_row: true, removed_scratch: false });
    }

    #[test]
    fn forget_refuses_non_uuids_and_removes_an_unparseable_row() {
        let d = tempfile::tempdir().unwrap();
        let p = paths_in(&d);
        std::fs::create_dir_all(p.scratch().join("x")).unwrap();
        for bad in ["../x", "x", "", "../../state"] {
            assert!(matches!(forget(&p, bad), Err(BridgeError::Config(_))), "{bad:?}");
        }
        assert!(p.scratch().join("x").is_dir());
        std::fs::create_dir_all(p.sessions()).unwrap();
        std::fs::write(path_for(&p, &id(6)).unwrap(), "not = = toml").unwrap();
        assert_eq!(forget(&p, &id(6)).unwrap(), ForgetReport { removed_row: true, removed_scratch: false });
    }

    #[test]
    fn forget_refuses_a_scratch_dir_owned_by_a_live_pump() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().to_path_buf(), None);
        let id = "44444444-0000-4000-8000-000000000004";
        let scratch = paths.scratch().join(id);
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(scratch.join(SCRATCH_OWNER_FILE), std::process::id().to_string()).unwrap();
        assert_eq!(scratch_owner(&scratch), Some(std::process::id()));
        let e = forget(&paths, id).unwrap_err();
        assert!(e.to_string().contains("in use by wrapper pid"), "{e}");
        assert!(scratch.exists());
        // A dead owner does not block.
        std::fs::write(scratch.join(SCRATCH_OWNER_FILE), (i32::MAX as u32).to_string()).unwrap();
        assert!(forget(&paths, id).unwrap().removed_scratch);
        assert!(!scratch.exists());
        // Junk in the owner file reads as no owner.
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(scratch.join(SCRATCH_OWNER_FILE), "not a pid").unwrap();
        assert_eq!(scratch_owner(&scratch), None);
    }

    #[test]
    fn pid_alive_edges() {
        assert!(pid_alive(std::process::id()));
        // Pid 1 (launchd / init) always exists and, for a non-root test run, answers EPERM.
        assert!(pid_alive(1), "EPERM means alive");
        assert!(!pid_alive(0));
        assert!(!pid_alive(i32::MAX as u32));
        assert!(!pid_alive(u32::MAX));
        assert!(!pid_alive(i32::MAX as u32 + 1));
    }

    #[test]
    fn argv_hash_kat() {
        let expected = hex::encode(Sha256::digest(b"a\0b"));
        assert_eq!(argv_hash(&["a".to_string(), "b".to_string()]), expected);
        assert_eq!(argv_hash(&[]), hex::encode(Sha256::digest(b"")));
        assert_ne!(argv_hash(&["ab".to_string()]), argv_hash(&["a".to_string(), "b".to_string()]));
        assert!(expected.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    }

    #[test]
    fn now_rfc3339_shape() {
        let now = now_rfc3339();
        assert_eq!(now.len(), 20, "{now}");
        assert!(now.starts_with("20") && now.ends_with('Z') && now.as_bytes()[10] == b'T', "{now}");
    }

    #[test]
    fn list_line_and_forget_suffix() {
        let mut r = row(1, "2026-09-25T10:00:00Z");
        assert_eq!(list_line(&r), format!("{}  closed  local-child    2026-09-25T10:00:00Z  -", id(1)));
        r.slug = Some("-tmp-x".into());
        r.status = "active".into();
        r.mode = "local-scratch".into();
        assert_eq!(list_line(&r), format!("{}  active  local-scratch  2026-09-25T10:00:00Z  -tmp-x", id(1)));
        assert_eq!(forget_suffix(ForgetReport { removed_row: true, removed_scratch: false }), Some(" (row)"));
        assert_eq!(forget_suffix(ForgetReport { removed_row: true, removed_scratch: true }), Some(" (row, scratch dir)"));
        assert_eq!(forget_suffix(ForgetReport { removed_row: false, removed_scratch: true }), Some(" (scratch dir)"));
        assert_eq!(forget_suffix(ForgetReport::default()), None);
    }

    #[test]
    fn json_rendering_of_rows() {
        assert_eq!(to_json::<[SessionRow]>(&[]).unwrap(), "[]");
        let j: serde_json::Value = serde_json::from_str(&to_json(&full_row()).unwrap()).unwrap();
        assert_eq!(j["session_id"], id(7));
        assert_eq!(j["host_state"]["max_thinking_tokens"], 8000);
    }
}
