//! `<bridge root>/audit.jsonl`: one JSON line per audited event (plan §2.4:
//! fsync per line; the prewarm's row alone is not synced: [`append_unsynced`]).
//! S2 writes `resume_seed_retry`, `resume_seed_miss`, `replay_timeout` and
//! `oauth_refresh_answered`; S8/S10 and the operator CLI add theirs through
//! the same writer, so every surface emits identical rows. Every string in
//! a row passes `wire::redact::scrub`.
//!
//! S11 (schema v2): every row names its writer (`detail.actor`, set here from
//! [`actor`], never by a writer), every event is registered in [`schema`]
//! (strict mode, `AI_ENV_AUDIT_STRICT=1` in `make test`, refuses one that is
//! not), the events written as literals before have constants ([`event`]),
//! and [`read`] is the reader the views share.
pub mod read;
pub mod schema;

pub use schema::event;

use crate::bridge::census;
use crate::bridge::errors::BridgeError;
use crate::bridge::logging::open_log_file;
use crate::bridge::voice::Voice;
use crate::wire::redact::scrub;
use crate::wire::time::{rfc3339_utc, unix_now};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;

/// S11: 2 (`actor` on every row, the registry). A row strict mode found
/// unregistered outside `make test` is written as 1, so readers take it best effort.
pub const AUDIT_SCHEMA_V: u8 = 2;

/// A row larger than this is refused (never written piecemeal).
pub const MAX_AUDIT_ROW_BYTES: usize = 64 * 1024;

/// Set by `make test` (and inherited by every child that keeps its environment): `1` makes a violation panic.
pub const STRICT_ENV: &str = "AI_ENV_AUDIT_STRICT";

/// Who wrote a row (S11 schema v2): `detail.actor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    Cli,
    Wrapper,
    Panel,
}

impl Actor {
    /// `cli`, `wrapper`, `panel`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Actor::Cli => "cli",
            Actor::Wrapper => "wrapper",
            Actor::Panel => "panel",
        }
    }
}

/// The actor [`set_actor`] set.
static ACTOR: OnceLock<Actor> = OnceLock::new();

/// Set this process's actor, once, before its first row (`panel serve` sets `Panel`). A second call with
/// another actor panics in debug builds and is ignored in release builds.
pub fn set_actor(actor: Actor) {
    if ACTOR.set(actor).is_err() {
        let was = ACTOR.get().copied();
        debug_assert!(was == Some(actor), "audit::set_actor({actor:?}) after {was:?}");
    }
}

/// The set actor, else the process's voice (`voice::Voice::Cli` is `Cli`, `Voice::Wrapper` is `Wrapper`).
#[must_use]
pub fn actor() -> Actor {
    actor_of(ACTOR.get().copied(), crate::bridge::voice::voice())
}

/// [`actor`]'s rule, pure (its test's).
#[must_use]
pub(crate) fn actor_of(set: Option<Actor>, voice: Voice) -> Actor {
    set.unwrap_or(match voice {
        Voice::Cli => Actor::Cli,
        Voice::Wrapper => Actor::Wrapper,
    })
}

/// Debug builds: the variable is exactly `1` (read once). Release builds: false.
#[cfg(debug_assertions)]
#[must_use]
pub fn strict() -> bool {
    static STRICT: OnceLock<bool> = OnceLock::new();
    *STRICT.get_or_init(|| std::env::var(STRICT_ENV).is_ok_and(|v| v == "1"))
}

/// Release builds: never strict (no check on the wrapper's path).
#[cfg(not(debug_assertions))]
#[must_use]
pub fn strict() -> bool {
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRow {
    pub v: u8,
    /// RFC 3339 UTC.
    pub ts: String,
    pub event: String,
    pub session_id: Option<String>,
    /// The writing process.
    pub pid: u32,
    pub detail: BTreeMap<String, String>,
}

impl AuditRow {
    /// A row stamped now by this process; `event`, `session_id` and every
    /// detail key and value are scrubbed. `detail.actor` is [`actor`]'s word,
    /// over whatever the writer passed. Without a `session_id`, an event whose
    /// spec takes its session from a detail key copies that key's value into
    /// the envelope when it is a uuid.
    #[must_use]
    pub fn new(event: &str, session_id: Option<&str>, detail: BTreeMap<String, String>) -> AuditRow {
        let event = scrub(event).into_owned();
        let mut detail: BTreeMap<String, String> = detail.into_iter().map(|(k, v)| (scrub(&k).into_owned(), scrub(&v).into_owned())).collect();
        detail.insert("actor".into(), actor().word().into());
        let session_id = session_id.map(|s| scrub(s).into_owned()).or_else(|| match schema::spec(&event)?.session {
            schema::SessionFrom::Detail(key) => detail.get(key).filter(|s| crate::bridge::registry::is_uuid(s)).cloned(),
            schema::SessionFrom::Envelope | schema::SessionFrom::None => None,
        });
        AuditRow { v: AUDIT_SCHEMA_V, ts: rfc3339_utc(unix_now()), event, session_id, pid: std::process::id(), detail }
    }
}

/// `detail` from `(key, value)` pairs.
#[must_use]
pub fn detail(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect()
}

/// Append one row as `<json>\n` with a single `write` on the file
/// `logging::open_log_file` opens (0700 dir, 0600 file, `O_APPEND`,
/// `O_NOFOLLOW`), then `sync_data`. A short write is an error (never
/// completed by a second write that could interleave with another writer);
/// a row over [`MAX_AUDIT_ROW_BYTES`] is refused before the file is touched.
pub fn append(path: &Path, row: &AuditRow) -> Result<(), BridgeError> {
    write_row(path, row)?.sync_data()?;
    Ok(())
}

/// [`append`] without its `sync_data` (`F_FULLFSYNC` on macOS: milliseconds,
/// more on a busy disk), as the census writes its rows: only for the
/// `prewarm` row, which `auth status` waits for (T1.2's 10 ms over a bare
/// exec). A crash may lose it, as it may that run's census row, which
/// names the same spawn.
pub fn append_unsynced(path: &Path, row: &AuditRow) -> Result<(), BridgeError> {
    write_row(path, row)?;
    Ok(())
}

/// The one `write` of [`append`] and [`append_unsynced`]: the file, for the caller to sync or not.
fn write_row(path: &Path, row: &AuditRow) -> Result<std::fs::File, BridgeError> {
    write_row_with(path, row, strict())
}

/// [`write_row`] with strictness given (the seam of its test: [`strict`] is read once per process).
/// In debug builds a v2 row is checked against the registry first: a violation panics when `strict`,
/// else it is logged and the row written as v1. Then the serialization, the size refusal and the one `write`.
fn write_row_with(path: &Path, row: &AuditRow, strict: bool) -> Result<std::fs::File, BridgeError> {
    let downgraded;
    let row = match (cfg!(debug_assertions) && row.v == AUDIT_SCHEMA_V).then(|| schema::check(row)) {
        Some(Err(violation)) if strict => panic!("audit row {}: {violation} ({STRICT_ENV}=1: register it in src/bridge/audit/schema.rs)", row.event),
        Some(Err(violation)) => {
            tracing::error!(event = %row.event, "audit row {}: {violation}: written as v1 (register it in src/bridge/audit/schema.rs)", row.event);
            downgraded = AuditRow { v: 1, ..row.clone() };
            &downgraded
        }
        Some(Ok(())) | None => row,
    };
    let mut line = serde_json::to_vec(row).map_err(|e| BridgeError::Config(format!("audit row: {e}")))?;
    line.push(b'\n');
    if line.len() > MAX_AUDIT_ROW_BYTES {
        return Err(BridgeError::Config(format!("audit row too large: {} bytes", line.len())));
    }
    let mut file = open_log_file(path)?;
    let written = file.write(&line)?;
    if written != line.len() {
        return Err(BridgeError::Io(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            format!("short audit write: {written} of {} bytes", line.len()),
        )));
    }
    Ok(file)
}

/// Every parseable row (oldest first), or the last `last` of them; a missing
/// file is empty, unparseable lines are skipped.
pub fn read_rows(path: &Path, last: Option<usize>) -> Result<Vec<serde_json::Value>, BridgeError> {
    census::read_rows(path, last)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "11111111-2222-4333-8444-555555555555";

    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn rows_append_one_per_line_with_private_modes() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("root").join("audit.jsonl");
        append(&path, &AuditRow::new("resume_seed_retry", Some(SID), detail(&[("session_id", SID.into()), ("source", "s3".into()), ("files", "2".into()), ("bytes", "42".into())]))).unwrap();
        append(&path, &AuditRow::new("replay_timeout", None, detail(&[("failed", "0".into()), ("gen", "2".into())]))).unwrap();
        let rows = read_rows(&path, None).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["event"], "resume_seed_retry");
        assert_eq!(rows[0]["detail"]["files"], "2");
        assert_eq!(rows[0]["v"], 2);
        assert_eq!(rows[0]["pid"], std::process::id());
        for r in &rows {
            assert_eq!(r["detail"]["actor"], actor().word(), "{r}");
        }
        assert!(rows[1]["session_id"].is_null());
        assert_eq!(read_rows(&path, Some(1)).unwrap()[0]["event"], "replay_timeout");
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(path.parent().unwrap()), 0o700);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    /// A complete `prewarm` row, `workspace` holding `len` bytes.
    fn prewarm(len: usize) -> AuditRow {
        AuditRow::new("prewarm", None, detail(&[("workspace", "y".repeat(len)), ("pid", "4242".into()), ("setting", "auto".into())]))
    }

    /// The prewarm's unsynced row is the synced one's line, in the same file
    /// under the same rules.
    #[test]
    fn an_unsynced_row_is_the_same_line() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("root").join("audit.jsonl");
        let row = prewarm(4);
        append_unsynced(&path, &row).unwrap();
        append(&path, &row).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], lines[1]);
        assert_eq!(serde_json::from_str::<AuditRow>(lines[0]).unwrap(), row);
        assert_eq!((mode_of(&path), mode_of(path.parent().unwrap())), (0o600, 0o700));
        assert!(append_unsynced(&path, &prewarm(MAX_AUDIT_ROW_BYTES)).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text, "an oversized row is refused before the file is touched");
    }

    #[test]
    fn every_string_is_scrubbed() {
        let token = format!("sk-ant-oat01-{}", "Q".repeat(24));
        let row = AuditRow::new("oauth_refresh_answered", Some(&token), detail(&[("subtype", format!("/x/{token}")), ("gen", "1".into())]));
        let text = serde_json::to_string(&row).unwrap();
        assert!(!text.contains(&token), "{text}");
        assert!(text.contains("sk-ant-[redacted:len="), "{text}");
    }

    #[test]
    fn oversized_rows_are_refused_before_touching_the_file() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let row = prewarm(MAX_AUDIT_ROW_BYTES);
        assert_eq!(schema::check(&row), Ok(()), "registered: the size refusal is what fails it");
        assert!(append(&path, &row).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn missing_file_reads_empty() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_rows(&d.path().join("none.jsonl"), None).unwrap().is_empty());
    }

    /// Strict mode: an unregistered event, a missing or an unregistered key panics before anything is
    /// written; without it the row is written as v1 (debug builds, where the check runs).
    #[test]
    fn strict_mode_refuses_an_unregistered_event_or_key() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let unknown = AuditRow::new("vm_test", None, BTreeMap::new());
        let missing = AuditRow::new("replay_timeout", None, detail(&[("failed", "0".into())]));
        let extra = AuditRow::new("replay_timeout", None, detail(&[("failed", "0".into()), ("gen", "1".into()), ("why", "x".into())]));
        assert_eq!(schema::check(&unknown), Err(schema::Violation::UnknownEvent("vm_test".into())));
        assert_eq!(schema::check(&missing), Err(schema::Violation::MissingKey { event: "replay_timeout".into(), key: "gen" }));
        assert_eq!(schema::check(&extra), Err(schema::Violation::UnknownKey { event: "replay_timeout".into(), key: "why".into() }));
        if !cfg!(debug_assertions) {
            return;
        }
        for bad in [&unknown, &missing, &extra] {
            let refused = std::panic::catch_unwind(|| write_row_with(&path, bad, true));
            let message = refused.expect_err("strict: a panic").downcast::<String>().map(|m| *m).unwrap_or_default();
            assert!(message.contains(&format!("audit row {}:", bad.event)) && message.contains("AI_ENV_AUDIT_STRICT=1: register it in src/bridge/audit/schema.rs"), "{message}");
            assert!(!path.exists(), "nothing written before the check");
        }
        for bad in [&unknown, &missing, &extra] {
            write_row_with(&path, bad, false).unwrap();
        }
        let rows = read_rows(&path, None).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r["v"] == 1), "{rows:?}");
        let good = AuditRow::new("replay_timeout", None, detail(&[("failed", "0".into()), ("gen", "1".into())]));
        write_row_with(&path, &good, true).unwrap();
        assert_eq!(read_rows(&path, Some(1)).unwrap()[0]["v"], 2);
    }

    #[test]
    fn the_actor_is_the_voice_unless_set() {
        assert_eq!(actor_of(None, Voice::Cli), Actor::Cli);
        assert_eq!(actor_of(None, Voice::Wrapper), Actor::Wrapper);
        assert_eq!(actor_of(Some(Actor::Panel), Voice::Cli), Actor::Panel);
        assert_eq!(actor_of(Some(Actor::Cli), Voice::Wrapper), Actor::Cli);
        assert_eq!([Actor::Cli, Actor::Wrapper, Actor::Panel].map(Actor::word), schema::ACTORS);
        let row = AuditRow::new("replay_timeout", None, detail(&[("failed", "0".into()), ("gen", "1".into()), ("actor", "panel".into())]));
        assert_eq!(row.detail["actor"], actor().word(), "a writer's actor is overwritten");
    }

    #[test]
    fn the_envelope_takes_a_detail_sessions_uuid() {
        let other = "22222222-3333-4444-8555-666666666666";
        let pull = |s: &str| AuditRow::new("transcript_pull", None, detail(&[("session", s.into()), ("vm", "microvm-a".into()), ("parts", "1".into()), ("bytes", "2".into()), ("outcome", "restored".into()), ("ms", "3".into())]));
        assert_eq!(pull(SID).session_id.as_deref(), Some(SID));
        assert_eq!(pull("-").session_id, None, "a `-` is no session");
        assert_eq!(pull("not-a-uuid").session_id, None);
        let given = AuditRow::new("drop_transport", Some(other), detail(&[("session", SID.into()), ("wrapper_pid", "1".into())]));
        assert_eq!(given.session_id.as_deref(), Some(other), "the writer's envelope wins");
        let seed = AuditRow::new("resume_seed_miss", None, detail(&[("session_id", SID.into()), ("reason", "x".into())]));
        assert_eq!(seed.session_id.as_deref(), Some(SID), "session_id is resume_seed_*'s key");
        let envelope_only = AuditRow::new("replay_timeout", None, detail(&[("failed", "0".into()), ("gen", "1".into()), ("session", SID.into())]));
        assert_eq!(envelope_only.session_id, None, "an envelope event takes nothing from its detail");
    }
}
