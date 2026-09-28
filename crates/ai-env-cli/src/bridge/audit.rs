//! `<bridge root>/audit.jsonl`: one JSON line per audited event (plan §2.4:
//! fsync per line). S2 writes `resume_seed_retry`, `resume_seed_miss`,
//! `replay_timeout` and `oauth_refresh_answered`; S8/S10 and the operator
//! CLI add theirs through the same writer, so every surface emits identical
//! rows. Every string in a row passes `wire::redact::scrub`.
use crate::bridge::census;
use crate::bridge::errors::BridgeError;
use crate::bridge::logging::open_log_file;
use crate::wire::redact::scrub;
use crate::wire::time::{rfc3339_utc, unix_now};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

pub const AUDIT_SCHEMA_V: u8 = 1;

/// A row larger than this is refused (never written piecemeal).
pub const MAX_AUDIT_ROW_BYTES: usize = 64 * 1024;

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
    /// detail key and value are scrubbed.
    #[must_use]
    pub fn new(event: &str, session_id: Option<&str>, detail: BTreeMap<String, String>) -> AuditRow {
        AuditRow {
            v: AUDIT_SCHEMA_V,
            ts: rfc3339_utc(unix_now()),
            event: scrub(event).into_owned(),
            session_id: session_id.map(|s| scrub(s).into_owned()),
            pid: std::process::id(),
            detail: detail.into_iter().map(|(k, v)| (scrub(&k).into_owned(), scrub(&v).into_owned())).collect(),
        }
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
    file.sync_data()?;
    Ok(())
}

/// Every parseable row (oldest first), or the last `last` of them; a missing
/// file is empty, unparseable lines are skipped.
pub fn read_rows(path: &Path, last: Option<usize>) -> Result<Vec<serde_json::Value>, BridgeError> {
    census::read_rows(path, last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn rows_append_one_per_line_with_private_modes() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("root").join("audit.jsonl");
        append(&path, &AuditRow::new("resume_seed_retry", Some("11111111-2222-4333-8444-555555555555"), detail(&[("files", "2".into()), ("bytes", "42".into())]))).unwrap();
        append(&path, &AuditRow::new("replay_timeout", None, BTreeMap::new())).unwrap();
        let rows = read_rows(&path, None).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["event"], "resume_seed_retry");
        assert_eq!(rows[0]["detail"]["files"], "2");
        assert_eq!(rows[0]["v"], 1);
        assert_eq!(rows[0]["pid"], std::process::id());
        assert!(rows[1]["session_id"].is_null());
        assert_eq!(read_rows(&path, Some(1)).unwrap()[0]["event"], "replay_timeout");
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(path.parent().unwrap()), 0o700);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn every_string_is_scrubbed() {
        let token = format!("sk-ant-oat01-{}", "Q".repeat(24));
        let row = AuditRow::new("oauth_refresh_answered", Some(&token), detail(&[("source", format!("/x/{token}"))]));
        let text = serde_json::to_string(&row).unwrap();
        assert!(!text.contains(&token), "{text}");
        assert!(text.contains("sk-ant-[redacted:len="), "{text}");
    }

    #[test]
    fn oversized_rows_are_refused_before_touching_the_file() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let row = AuditRow::new("big", None, detail(&[("x", "y".repeat(MAX_AUDIT_ROW_BYTES))]));
        assert!(append(&path, &row).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn missing_file_reads_empty() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_rows(&d.path().join("none.jsonl"), None).unwrap().is_empty());
    }
}
