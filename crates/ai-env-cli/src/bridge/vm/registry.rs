//! The VM registry (plan §2.4, S4 §7): `state/vms/<microvm id>.toml`, one row
//! per VM `ai-env vm` started, and `state/vms/pending-<client_token>.toml`,
//! written under the placement lock BEFORE `RunMicrovm` so a crash between
//! the call and the answer leaves a trace gc can adopt (by the `/health`
//! `owner` + `created` pair) or clear.
//!
//! Rows are 0600 in a 0700 directory, written atomically
//! (`infra::write_atomic_mode`). A row holds the VM's session token (plan
//! §2.4: the S6 transport presents it to the shim); nothing else ever prints
//! it — [`view`] is the projection every `--json` output uses.
//!
//! Every path is built from an id only after [`is_vm_id`] / `is_uuid`
//! accepted it, so no id traverses out of `state/vms`.
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::infra::write_atomic_mode;
use crate::bridge::registry::{ensure_private_dir, is_uuid, read_regular_file, remove_if_present};
use crate::bridge::vm::lock::lock_blocking;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::PathBuf;

/// Schema version written into every row's `v`.
pub const VM_SCHEMA_V: u8 = 1;

/// [`VmRow::egress_gate`] until the echo gate ran.
pub const GATE_PENDING: &str = "pending";
/// [`VmRow::egress_gate`] once the VM echoed exactly its required egress.
pub const GATE_PASSED: &str = "passed";
/// [`VmRow::egress_gate`] of a VM that echoed anything else (terminate it).
pub const GATE_MISMATCH: &str = "mismatch";

/// File-name prefix of a pending row.
pub const PENDING_PREFIX: &str = "pending-";

/// A pending row older than this, with no VM to adopt it, is stale.
pub const PENDING_STALE_S: u64 = 300;

/// Terminated rows are kept this long (the `cloudtrail-payload` probe needs
/// the `client_token` and the session token of a finished run).
pub const TERMINATED_KEEP_S: u64 = 7 * 86_400;

/// What the registry believes about a VM (refreshed from `GetMicrovm`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RowStatus {
    /// Written before `RunMicrovm`, or RunMicrovm returned and the VM is not RUNNING yet.
    #[default]
    Pending,
    Running,
    Suspended,
    Terminated,
    /// Anything else (a state this build does not know, a failed refresh).
    #[serde(other)]
    Unknown,
}

impl RowStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RowStatus::Pending => "pending",
            RowStatus::Running => "running",
            RowStatus::Suspended => "suspended",
            RowStatus::Terminated => "terminated",
            RowStatus::Unknown => "unknown",
        }
    }
}

/// The idle policy as the service echoed it (or as sent, before the echo).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdleRow {
    pub max_idle_s: u32,
    pub suspended_s: u32,
    pub auto_resume: bool,
}

/// One row. Every field has a default so rows written by an older or newer
/// build still read. Times are Unix seconds except `created` (the payload's
/// RFC 3339 milliseconds, part of the adoption key). `Debug` is written by
/// hand: it never prints `session_token` (a token read back from disk is not
/// registered with the scrubber).
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VmRow {
    pub v: u8,
    pub status: RowStatus,
    /// `microvm-<uuid>`; empty in a pending row.
    pub id: String,
    /// The uuid v7 passed as `RunMicrovm.clientToken`.
    pub client_token: String,
    pub label: Option<String>,
    /// The canonical workspace path (`--workspace`), if any.
    pub workspace: Option<String>,
    /// Its project dir name (the lock's name).
    pub slug: Option<String>,
    pub image_arn: String,
    /// The resolved version passed to `RunMicrovm` (`N.0`).
    pub image_version: String,
    /// Bare host `<uuid>.lambda-microvm.eu-central-1.on.aws`.
    pub endpoint: Option<String>,
    /// `<user>@<short host>`, as in the payload.
    pub owner: String,
    /// The payload's `created` (RFC 3339 UTC, milliseconds).
    pub created: String,
    /// `hex(sha256(session_token))`, as in the payload.
    pub commit: String,
    /// 64 hex; never printed, never in `--json`, logs or audit.
    pub session_token: Option<String>,
    /// When the service says the VM started.
    pub started_at: Option<u64>,
    /// `started_at` + the echoed maximum duration.
    pub wall_deadline: Option<u64>,
    pub max_duration_s: u32,
    pub idle: Option<IdleRow>,
    /// `internet` | `vpc`.
    pub egress: String,
    /// The ingress connector ARNs as echoed (the platform default when none was sent).
    pub ingress: Vec<String>,
    /// The egress connector ARNs (S5): as planned in a pending row (empty for
    /// `internet`: nothing is sent), as echoed once the egress echo gate
    /// passed. A `vpc` row without them (written before S5) fails the gate.
    pub egress_connectors: Vec<String>,
    /// The S5 egress echo gate's verdict on this VM: [`GATE_PENDING`] from
    /// the pending row until the gate ran, [`GATE_PASSED`], or
    /// [`GATE_MISMATCH`] (written before the terminate is tried). `None` in a
    /// row written before S5. gc gates again every live id row that is not
    /// [`GATE_PASSED`], so a VM whose terminate failed, or whose `ai-env`
    /// died between RunMicrovm and the gate, cannot outlive the next gc.
    pub egress_gate: Option<String>,
    /// Whether `SHELL_INGRESS` was requested (`vm run --shell`).
    pub shell: bool,
    pub execution_role: Option<String>,
    /// The last state `GetMicrovm`/`ListMicrovms` reported, and when.
    pub state_seen: Option<String>,
    pub state_seen_at: Option<u64>,
    pub state_reason: Option<String>,
    pub last_health_at: Option<u64>,
    pub boot_nonce: Option<String>,
    pub claude_version: Option<String>,
    pub shim_version: Option<String>,
    /// The shim's public capabilities as its last `/health` showed them (S7):
    /// `None` until one was read, empty for an S6 shim (which cannot hold a
    /// credential).
    pub caps: Option<Vec<String>>,
    /// When the setup-token was last sent to this VM (Unix seconds, S7), and
    /// the seal id it carried. Set before the value leaves the Mac, whatever
    /// answer comes back, and on any hit seen while it is unset: the VM's
    /// memory, its running children and any snapshot may hold the token
    /// until it is TERMINATED, whatever the shim's cache says now, so
    /// `creds status` and `creds forget` list it.
    pub credential_at: Option<u64>,
    pub credential_tag: Option<String>,
    /// Port → expiry (Unix seconds) of the tokens minted for this VM.
    pub token_expiries: BTreeMap<String, u64>,
    /// S6.
    pub spawns: Vec<toml::Value>,
    pub terminated_at: Option<u64>,
    /// `operator` | `gc-expired` | `gc-orphan` | `smoke` | `test` | `probe` | `timeout` | `platform` | `policy` (the S5 egress gate).
    pub terminated_by: Option<String>,
}

impl std::fmt::Debug for VmRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut v = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(map) = v.as_object_mut() {
            if map.get("session_token").is_some_and(|t| !t.is_null()) {
                map.insert("session_token".into(), serde_json::Value::String("[redacted]".into()));
            }
        }
        write!(f, "VmRow {v}")
    }
}

impl VmRow {
    /// A pending row (no id yet).
    #[must_use]
    pub fn is_pending_row(&self) -> bool {
        self.id.is_empty()
    }

    /// Seconds of wall time left (negative once passed); `None` before the
    /// service reported a start.
    #[must_use]
    pub fn wall_left(&self, now: u64) -> Option<i64> {
        self.wall_deadline.map(|d| i64::try_from(d).unwrap_or(i64::MAX) - i64::try_from(now).unwrap_or(i64::MAX))
    }

    /// The row's file name stem: the VM id, or `pending-<client_token>`.
    #[must_use]
    pub fn stem(&self) -> String {
        if self.is_pending_row() {
            format!("{PENDING_PREFIX}{}", self.client_token)
        } else {
            self.id.clone()
        }
    }
}

// ---- ids and paths ---------------------------------------------------------------------

/// Is `s` usable as a MicroVM id in a file name? The live shape is
/// `microvm-<uuid>`; any 1–128 characters of `[A-Za-z0-9-]` not starting with
/// `-` or the pending prefix (in any case: APFS is case-insensitive, so
/// `Pending-<uuid>.toml` names the file of `pending-<uuid>.toml`) are
/// accepted, so a service-side format change does not strand VMs, while `.`,
/// `/` and empty strings never reach the filesystem.
#[must_use]
pub fn is_vm_id(s: &str) -> bool {
    let pending = s.get(..PENDING_PREFIX.len()).is_some_and(|p| p.eq_ignore_ascii_case(PENDING_PREFIX));
    !s.is_empty() && s.len() <= 128 && !s.starts_with('-') && !pending && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

/// `state/vms/.rows.lock`: held (briefly, `flock`) around every
/// read-modify-write of an existing row ([`update_row`],
/// [`adopt_pending_locked`]) so two processes never lose each other's
/// update. Not a `.toml`, so [`list_rows`] never reads it.
#[must_use]
pub fn rows_lock_path(paths: &Paths) -> PathBuf {
    paths.vms().join(".rows.lock")
}

/// `state/vms/<id>.toml`.
pub fn row_path(paths: &Paths, id: &str) -> Result<PathBuf, BridgeError> {
    if !is_vm_id(id) {
        return Err(BridgeError::Config(format!("not a microvm id: {id:?}")));
    }
    Ok(paths.vms().join(format!("{id}.toml")))
}

/// `state/vms/pending-<client_token>.toml`.
pub fn pending_path(paths: &Paths, client_token: &str) -> Result<PathBuf, BridgeError> {
    if !is_uuid(client_token) {
        return Err(BridgeError::Config(format!("not a client token: {client_token:?}")));
    }
    Ok(paths.vms().join(format!("{PENDING_PREFIX}{client_token}.toml")))
}

/// The path of `row` (its id row, or its pending row when it has no id).
pub fn path_of(paths: &Paths, row: &VmRow) -> Result<PathBuf, BridgeError> {
    if row.is_pending_row() {
        pending_path(paths, &row.client_token)
    } else {
        row_path(paths, &row.id)
    }
}

// ---- write / read / list ---------------------------------------------------------------

fn render(row: &VmRow) -> Result<String, BridgeError> {
    let mut row = row.clone();
    row.v = VM_SCHEMA_V;
    toml::to_string_pretty(&row).map_err(|e| BridgeError::Config(format!("vm row {}: cannot serialise: {e}", row.stem())))
}

/// Atomically write `row` to its path ([`path_of`]): 0600 in a 0700 `state/vms`.
pub fn write_row(paths: &Paths, row: &VmRow) -> Result<(), BridgeError> {
    let target = path_of(paths, row)?;
    ensure_private_dir(&paths.vms())?;
    write_atomic_mode(&target, render(row)?.as_bytes(), 0o600)
}

/// Write the pending row (`row.id` must be empty, `client_token` a uuid).
pub fn write_pending(paths: &Paths, row: &VmRow) -> Result<(), BridgeError> {
    if !row.is_pending_row() {
        return Err(BridgeError::Config(format!("write_pending with an id ({})", row.id)));
    }
    write_row(paths, row)
}

/// `RunMicrovm` answered: write `<id>.toml` (the row now carries the id),
/// then remove `pending-<client_token>.toml`. A crash between the two leaves
/// both; [`list_rows`] prefers the id row.
pub fn promote_pending(paths: &Paths, row: &VmRow) -> Result<(), BridgeError> {
    if row.is_pending_row() {
        return Err(BridgeError::Config("promote_pending without an id".into()));
    }
    write_row(paths, row)?;
    if is_uuid(&row.client_token) {
        remove_if_present(&pending_path(paths, &row.client_token)?)?;
    }
    Ok(())
}

/// Remove the row's file; `Ok(false)` when it was already gone.
pub fn remove_row(paths: &Paths, row: &VmRow) -> Result<bool, BridgeError> {
    remove_if_present(&path_of(paths, row)?)
}

fn parse_row(path: &std::path::Path, text: &str) -> Result<VmRow, BridgeError> {
    toml::from_str(text).map_err(|e| {
        let msg = e.to_string();
        BridgeError::Config(format!("{}: {}", path.display(), msg.lines().next().unwrap_or("unparseable")))
    })
}

/// The id row of `id`; `Ok(None)` when absent.
pub fn read_row(paths: &Paths, id: &str) -> Result<Option<VmRow>, BridgeError> {
    let path = row_path(paths, id)?;
    let Some(text) = read_regular_file(&path)? else {
        return Ok(None);
    };
    let mut row = parse_row(&path, &text)?;
    if row.id.is_empty() {
        row.id = id.to_string();
    }
    Ok(Some(row))
}

/// Read-modify-write of the existing row of `id` under a short `flock` on
/// [`rows_lock_path`] (read → `f` → atomic write), so concurrent `ai-env`
/// processes never lose each other's updates. `Ok(None)` when there is no
/// row (nothing is written and, when `state/vms` is absent, nothing is
/// created); otherwise the row as written. `f` may not change the row's id.
/// Rows are created with [`write_row`] / [`write_pending`], not here. The
/// lock is blocking and held for microseconds; `f` must not take it again.
pub fn update_row(paths: &Paths, id: &str, f: impl FnOnce(&mut VmRow)) -> Result<Option<VmRow>, BridgeError> {
    // No row, no lock file: a mint or a /health for a row-less VM writes nothing.
    if read_row(paths, id)?.is_none() {
        return Ok(None);
    }
    let _guard = lock_blocking(&rows_lock_path(paths))?;
    let Some(mut row) = read_row(paths, id)? else {
        return Ok(None);
    };
    f(&mut row);
    if row.id != id {
        return Err(BridgeError::Config(format!("update_row {id}: the update changed the id to {:?}", row.id)));
    }
    write_row(paths, &row)?;
    Ok(Some(row))
}

/// Adoption (gc's `adopt` class, the sweep after an ambiguous `RunMicrovm`)
/// under the [`rows_lock_path`] lock: the pending row of `client_token` is
/// read again from disk; `Ok(None)` when it is gone (another process adopted
/// or cleared it); else `f` turns it into the id row (it must set the id),
/// which is written before the pending row is removed ([`promote_pending`]).
pub fn adopt_pending_locked(paths: &Paths, client_token: &str, f: impl FnOnce(&mut VmRow)) -> Result<Option<VmRow>, BridgeError> {
    let path = pending_path(paths, client_token)?;
    let _guard = lock_blocking(&rows_lock_path(paths))?;
    let Some(text) = read_regular_file(&path)? else {
        return Ok(None);
    };
    let mut row = parse_row(&path, &text)?;
    row.id.clear();
    row.client_token = client_token.to_string();
    f(&mut row);
    promote_pending(paths, &row)?;
    Ok(Some(row))
}

/// Every row in `state/vms` (id rows and pending rows), newest `created`
/// first. Only regular files named `<id>.toml` / `pending-<uuid>.toml` are
/// read; a row's name that is not a regular file (a link, a directory), or a
/// row that fails to parse, is skipped with a `warn!`. A pending row
/// whose `client_token` also has an id row (a crash inside
/// [`promote_pending`]) is dropped in favour of the id row.
pub fn list_rows(paths: &Paths) -> Result<Vec<VmRow>, BridgeError> {
    let (rows, skipped) = list_rows_reporting(paths)?;
    for s in skipped {
        tracing::warn!("vm registry: skipping {s}");
    }
    Ok(rows)
}

/// [`list_rows`], and the rows it skipped as unreadable or unparseable, each
/// as the error that names its path once (`<path>: <parser message>`, `<path>
/// is a symlink; …`, `<path> is not a regular file`, `cannot open <path>:
/// …`), for a caller that must not take a row it could not read for no row
/// at all (S7: the VMs that may hold the setup-token). A row's name that is
/// not a regular file is such a row too: `read_row` refuses it, so it is
/// named here, never dropped unsaid.
pub fn list_rows_reporting(paths: &Paths) -> Result<(Vec<VmRow>, Vec<String>), BridgeError> {
    let dir = paths.vms();
    let entries = match std::fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot list {}: {e}", dir.display())))),
    };
    let (mut rows, mut skipped) = (Vec::new(), Vec::new());
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".toml")) else { continue };
        let pending = stem.strip_prefix(PENDING_PREFIX);
        let valid = match pending {
            Some(token) => is_uuid(token),
            None => is_vm_id(stem),
        };
        if !valid {
            continue;
        }
        let path = dir.join(&name);
        // A link, a directory or a FIFO under a row's name is a row `read_row` refuses (F13): named in
        // `read_regular_file`'s words and never opened (the entry's type does not follow a link).
        match entry.file_type() {
            Ok(t) if t.is_file() => {}
            Ok(t) if t.is_symlink() => {
                skipped.push(format!("{} is a symlink; refusing to read it", path.display()));
                continue;
            }
            Ok(_) => {
                skipped.push(format!("{} is not a regular file", path.display()));
                continue;
            }
            // Gone since the listing: no row, as `read_regular_file` says of a file that is not there.
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => {
                skipped.push(format!("cannot stat {}: {e}", path.display()));
                continue;
            }
        }
        match read_regular_file(&path).and_then(|t| t.map(|t| parse_row(&path, &t)).transpose()) {
            Ok(Some(mut row)) => {
                match pending {
                    Some(token) => {
                        row.id.clear();
                        row.client_token = token.to_string();
                    }
                    None if row.id.is_empty() => row.id = stem.to_string(),
                    None => {}
                }
                rows.push(row);
            }
            Ok(None) => {}
            // Each error names the path already: said once, without its class's `config:`.
            Err(BridgeError::Config(m)) => skipped.push(m),
            Err(e) => skipped.push(e.to_string()),
        }
    }
    let promoted: std::collections::HashSet<String> = rows.iter().filter(|r| !r.is_pending_row()).map(|r| r.client_token.clone()).collect();
    rows.retain(|r| !(r.is_pending_row() && promoted.contains(&r.client_token)));
    rows.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.stem().cmp(&b.stem())));
    skipped.sort();
    Ok((rows, skipped))
}

/// The `--json` projection of a row: every field except `session_token`.
#[must_use]
pub fn view(row: &VmRow) -> serde_json::Value {
    let mut v = serde_json::to_value(row).unwrap_or(serde_json::Value::Null);
    if let Some(map) = v.as_object_mut() {
        map.remove("session_token");
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const TOKEN: &str = "01926f2e-0000-7000-8000-000000000001";

    fn paths(dir: &std::path::Path) -> Paths {
        Paths::from_root_and_env(dir.to_path_buf(), None)
    }

    fn row(id: &str, created: &str) -> VmRow {
        VmRow {
            id: id.into(),
            client_token: TOKEN.into(),
            created: created.into(),
            owner: "mike@host".into(),
            session_token: Some("ab".repeat(32)),
            image_arn: "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent".into(),
            image_version: "1.0".into(),
            ..VmRow::default()
        }
    }

    #[test]
    fn ids_are_path_safe() {
        assert!(is_vm_id("microvm-8448b786-57b0-3fd2-9e06-b107353bc6ec"));
        for bad in ["", "..", "a/b", "-x", "pending-x", "a.toml", &"a".repeat(129)] {
            assert!(!is_vm_id(bad), "{bad}");
        }
        assert!(row_path(&paths(std::path::Path::new("/r")), "../x").is_err());
        assert!(pending_path(&paths(std::path::Path::new("/r")), "nope").is_err());
    }

    #[test]
    fn the_pending_prefix_is_refused_in_any_case() {
        // APFS is case-insensitive: `Pending-<uuid>.toml` is the file of `pending-<uuid>.toml`.
        for alias in [format!("Pending-{TOKEN}"), format!("PENDING-{TOKEN}"), format!("pEnDiNg-{TOKEN}"), "PENDING-".to_string()] {
            assert!(!is_vm_id(&alias), "{alias}");
            assert!(row_path(&paths(std::path::Path::new("/r")), &alias).is_err(), "{alias}");
        }
        assert!(is_vm_id("pendin"), "shorter than the prefix: an id like any other");
        assert!(is_vm_id("pendingx"), "no dash: not the prefix");
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write_pending(&p, &row("", "2026-09-29T10:00:00.000Z")).unwrap();
        let alias = p.vms().join(format!("Pending-{TOKEN}.toml"));
        if alias.exists() {
            // Case-insensitive volume: the alias must not be read as an id row.
            assert!(read_row(&p, &format!("Pending-{TOKEN}")).is_err());
        } else {
            std::fs::copy(pending_path(&p, TOKEN).unwrap(), &alias).unwrap();
        }
        let listed = list_rows(&p).unwrap();
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert!(listed[0].is_pending_row());
    }

    #[test]
    fn update_row_writes_only_existing_rows_and_keeps_concurrent_updates() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert_eq!(update_row(&p, "microvm-1", |r| r.status = RowStatus::Running).unwrap(), None);
        assert!(!p.vms().exists(), "no row: nothing created, not even the lock");
        write_row(&p, &row("microvm-1", "2026-09-29T10:00:00.000Z")).unwrap();
        let back = update_row(&p, "microvm-1", |r| r.status = RowStatus::Suspended).unwrap().unwrap();
        assert_eq!(back.status, RowStatus::Suspended);
        assert_eq!(read_row(&p, "microvm-1").unwrap().unwrap(), back);
        assert!(rows_lock_path(&p).exists());
        assert_eq!(list_rows(&p).unwrap().len(), 1, "the lock file is not a row");
        assert!(update_row(&p, "microvm-1", |r| r.id = "microvm-2".into()).is_err(), "the id is fixed");
        // Eight writers, one field each: every update survives.
        std::thread::scope(|s| {
            for port in 0..8u16 {
                let p = &p;
                s.spawn(move || {
                    update_row(p, "microvm-1", |r| {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        r.token_expiries.insert(port.to_string(), u64::from(port));
                    })
                    .unwrap();
                });
            }
        });
        assert_eq!(read_row(&p, "microvm-1").unwrap().unwrap().token_expiries.len(), 8);
    }

    #[test]
    fn adopt_pending_locked_promotes_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write_pending(&p, &row("", "2026-09-29T10:00:00.000Z")).unwrap();
        let adopted = adopt_pending_locked(&p, TOKEN, |r| {
            r.id = "microvm-1".into();
            r.status = RowStatus::Running;
        })
        .unwrap()
        .unwrap();
        assert_eq!((adopted.id.as_str(), adopted.client_token.as_str()), ("microvm-1", TOKEN));
        assert!(!pending_path(&p, TOKEN).unwrap().exists());
        assert_eq!(read_row(&p, "microvm-1").unwrap().unwrap(), adopted);
        assert_eq!(adopt_pending_locked(&p, TOKEN, |r| r.id = "microvm-9".into()).unwrap(), None, "already adopted");
        assert!(read_row(&p, "microvm-9").unwrap().is_none());
    }

    #[test]
    fn pending_then_promote_round_trip_with_modes() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let mut r = row("", "2026-09-29T10:00:00.000Z");
        write_pending(&p, &r).unwrap();
        let pend = pending_path(&p, TOKEN).unwrap();
        assert_eq!(std::fs::metadata(&pend).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(p.vms()).unwrap().permissions().mode() & 0o777, 0o700);
        let listed = list_rows(&p).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].is_pending_row());
        r.id = "microvm-1".into();
        r.status = RowStatus::Running;
        promote_pending(&p, &r).unwrap();
        assert!(!pend.exists());
        let back = read_row(&p, "microvm-1").unwrap().unwrap();
        assert_eq!(back.status, RowStatus::Running);
        assert_eq!(back.v, VM_SCHEMA_V);
        assert_eq!(back.session_token.as_deref(), Some("ab".repeat(32).as_str()));
    }

    #[test]
    fn a_crash_inside_promote_keeps_only_the_id_row() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write_pending(&p, &row("", "2026-09-29T10:00:00.000Z")).unwrap();
        write_row(&p, &row("microvm-1", "2026-09-29T10:00:00.000Z")).unwrap();
        let listed = list_rows(&p).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "microvm-1");
    }

    #[test]
    fn list_skips_junk_and_sorts_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let mut a = row("microvm-a", "2026-09-29T10:00:00.000Z");
        a.client_token = "01926f2e-0000-7000-8000-00000000000a".into();
        let mut b = row("microvm-b", "2026-09-29T11:00:00.000Z");
        b.client_token = "01926f2e-0000-7000-8000-00000000000b".into();
        write_row(&p, &a).unwrap();
        write_row(&p, &b).unwrap();
        std::fs::write(p.vms().join("garbage.toml"), "not = [toml").unwrap();
        std::fs::write(p.vms().join(".x.toml.1.tmp"), "").unwrap();
        std::fs::write(p.vms().join("notes.txt"), "").unwrap();
        std::os::unix::fs::symlink(p.vms().join("microvm-a.toml"), p.vms().join("microvm-c.toml")).unwrap();
        let ids: Vec<String> = list_rows(&p).unwrap().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, ["microvm-b", "microvm-a"]);
    }

    /// A row that cannot be parsed is skipped by `list_rows` and named by
    /// `list_rows_reporting`, which the holder list reads (S7): a VM whose
    /// row is unreadable is never taken for no VM. It is named once, as
    /// `<path>: <parser message>`, with no error class (`creds status` shows
    /// it as it is).
    #[test]
    fn a_row_that_cannot_be_read_is_reported_not_only_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write_row(&p, &row("microvm-a", "2026-09-29T10:00:00.000Z")).unwrap();
        std::fs::write(p.vms().join("microvm-b.toml"), "status = [broken").unwrap();
        std::fs::write(p.vms().join("notes.txt"), "").unwrap();
        let (rows, skipped) = list_rows_reporting(&p).unwrap();
        assert_eq!(rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["microvm-a"]);
        assert!(skipped.len() == 1 && skipped[0].starts_with(&format!("{}: TOML parse error", p.vms().join("microvm-b.toml").display())), "{skipped:?}");
        assert!(skipped[0].matches("microvm-b.toml").count() == 1 && !skipped[0].contains("config:"), "named once, no class: {skipped:?}");
        assert_eq!(list_rows(&p).unwrap(), rows, "list_rows skips it");
    }

    /// F13: a row's name that is not a regular file (a symlink to a copy of
    /// the row, which `read_row` refuses; a directory; a FIFO) is named by
    /// `list_rows_reporting` in `read_row`'s words, each once, never dropped
    /// unsaid (the holder list would read none for its VM); `list_rows`
    /// still skips them, and nothing reads through the link or blocks on the
    /// FIFO.
    #[test]
    fn a_row_that_is_not_a_regular_file_is_reported_not_only_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let mut a = row("microvm-a", "2026-09-29T10:00:00.000Z");
        a.credential_at = Some(1_790_000_000);
        write_row(&p, &a).unwrap();
        let (link, copy) = (p.vms().join("microvm-a.toml"), dir.path().join("microvm-a.copy.toml"));
        std::fs::rename(&link, &copy).unwrap();
        std::os::unix::fs::symlink(&copy, &link).unwrap();
        assert!(read_row(&p, "microvm-a").unwrap_err().to_string().ends_with("microvm-a.toml is a symlink; refusing to read it"), "read_row refuses the link");
        std::fs::create_dir(p.vms().join("microvm-b.toml")).unwrap();
        let fifo = std::ffi::CString::new(p.vms().join("microvm-c.toml").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: mkfifo(3) with a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        std::fs::write(p.vms().join("notes.txt"), "").unwrap();
        let (rows, skipped) = list_rows_reporting(&p).unwrap();
        assert!(rows.is_empty(), "{rows:?}");
        let vms = p.vms();
        let want = [
            format!("{} is a symlink; refusing to read it", vms.join("microvm-a.toml").display()),
            format!("{} is not a regular file", vms.join("microvm-b.toml").display()),
            format!("{} is not a regular file", vms.join("microvm-c.toml").display()),
        ];
        assert_eq!(skipped, want, "each named once, in read_row's words");
        assert!(list_rows(&p).unwrap().is_empty(), "list_rows skips them");
    }

    #[test]
    fn debug_never_prints_the_session_token() {
        let r = row("microvm-1", "2026-09-29T10:00:00.000Z");
        for text in [format!("{r:?}"), format!("{r:#?}"), format!("{:?}", vec![r.clone()])] {
            assert!(!text.contains(&"ab".repeat(32)), "{text}");
            assert!(text.contains("[redacted]") && text.contains("microvm-1"), "{text}");
        }
    }

    #[test]
    fn json_view_never_carries_the_session_token() {
        let r = row("microvm-1", "2026-09-29T10:00:00.000Z");
        let v = view(&r);
        assert!(v.get("session_token").is_none());
        assert!(!v.to_string().contains(&"ab".repeat(32)));
        assert_eq!(v["id"], "microvm-1");
    }

    #[test]
    fn unknown_status_reads_as_unknown() {
        let r: VmRow = toml::from_str("status = \"migrating\"\nid = \"microvm-1\"\n").unwrap();
        assert_eq!(r.status, RowStatus::Unknown);
    }

    #[test]
    fn wall_left_counts_down() {
        let mut r = row("microvm-1", "x");
        assert_eq!(r.wall_left(100), None);
        r.wall_deadline = Some(1000);
        assert_eq!(r.wall_left(900), Some(100));
        assert_eq!(r.wall_left(1100), Some(-100));
    }
}
