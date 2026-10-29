//! S12 (C1): the live tests' cost rows. A live test's bridge root is a temporary directory, gone at
//! its end, so `ai-env cost` never saw the VMs it ran (22 Oct: 44.8 % under the bill). Its guard
//! (`tests/aws.rs` `Live`) keeps, under the real root's `state/test-runs/<name>/`, the audit rows
//! naming a VM, as stored, and the VM rows through `strip`: a miniature bridge root that
//! `audit::read::read_all` and `vm::registry::list_rows_reporting` read unchanged.
//! `cost::estimate_with` merges the runs, labelled; nothing else reads them.
//! Phase 0 declared it; S12 wave 1's C builds it.
use crate::bridge::audit::read::Read;
use crate::bridge::config::Paths;
use crate::bridge::errors::BridgeError;
use crate::bridge::vm::registry::VmRow;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// The most characters of a test's name a run's name keeps.
pub const RUN_TEST_MAX: usize = 96;
/// The most further runs one process names in one second (`.<k>`, `k` 1 to 9, after the pid).
pub const RUN_SEQ_MAX: u32 = 9;
/// A run being written: `.tmp-<name>`, renamed to `<name>` once whole (readers skip every `.` entry).
pub const RUN_TMP_PREFIX: &str = ".tmp-";

/// One kept run, as `read_runs` read it.
#[derive(Debug, Clone, PartialEq)]
pub struct TestRun {
    /// Its directory's name, `<YYYYMMDDTHHMMSSZ>-<test>-<pid>[.<k>]`.
    pub name: String,
    /// The test's name as `name` spells it ([`test_part`]).
    pub test: String,
    /// Its audit's rows: registered events (`Read.known`) naming a VM, in file order.
    pub rows: Vec<Read>,
    /// Its VM rows (id rows only), as stripped.
    pub vm_rows: Vec<VmRow>,
}

/// A character a run's test part keeps as it is (LD-C3); every other becomes `_`.
fn test_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// `test` as a run name spells it: each character outside `[A-Za-z0-9_-]` becomes `_`, then the
/// first `RUN_TEST_MAX` characters; `unnamed` for an empty name.
#[must_use]
pub fn test_part(test: &str) -> String {
    if test.is_empty() {
        return "unnamed".to_string();
    }
    test.chars().map(|c| if test_char(c) { c } else { '_' }).take(RUN_TEST_MAX).collect()
}

/// `<YYYYMMDDTHHMMSSZ>-<test_part(test)>-<pid>`, with `.<seq>` after the pid when `seq` > 0.
#[must_use]
pub fn run_name(test: &str, now: u64, pid: u32, seq: u32) -> String {
    let stamp: String = crate::wire::time::rfc3339_utc(now).chars().filter(|c| *c != '-' && *c != ':').collect();
    let name = format!("{stamp}-{}-{pid}", test_part(test));
    if seq > 0 {
        format!("{name}.{seq}")
    } else {
        name
    }
}

/// `YYYYMMDDTHHMMSSZ` of a real UTC time at or after 1970, as `run_name` stamps it: its RFC 3339 form
/// is one `wire::time::parse_rfc3339_utc` takes.
fn is_stamp(stamp: &str) -> bool {
    let shape = stamp.len() == 16
        && stamp.bytes().enumerate().all(|(i, c)| match i {
            8 => c == b'T',
            15 => c == b'Z',
            _ => c.is_ascii_digit(),
        });
    // The shape is ASCII, so the slices below cut at character boundaries.
    shape && crate::wire::time::parse_rfc3339_utc(&format!("{}-{}-{}T{}:{}:{}Z", &stamp[..4], &stamp[4..6], &stamp[6..8], &stamp[9..11], &stamp[11..13], &stamp[13..15])).is_some()
}

/// The test of a run's name; `None` for a name `run_name` cannot make.
///
/// The name is read from both ends, since a test part may hold `-` and digits: the stamp before the
/// first `-`, the pid after the last (decimal, as `run_name` prints a `u32`: no sign, no leading
/// zero), then at most one `.<k>` with `k` 1 to [`RUN_SEQ_MAX`] as `run_name` prints it (`.0` and
/// `.10` are none); the test part between is 1 to [`RUN_TEST_MAX`] characters of `[A-Za-z0-9_-]`
/// (LD-C3). A dot-name (`.tmp-…`) has no stamp.
#[must_use]
pub fn parse_run_name(name: &str) -> Option<String> {
    let (base, seq) = match name.split_once('.') {
        Some((base, seq)) => (base, Some(seq)),
        None => (name, None),
    };
    if let Some(seq) = seq {
        seq.parse::<u32>().ok().filter(|k| (1..=RUN_SEQ_MAX).contains(k) && k.to_string() == seq)?;
    }
    let (stamp, rest) = base.split_once('-')?;
    if !is_stamp(stamp) {
        return None;
    }
    let (test, pid) = rest.rsplit_once('-')?;
    pid.parse::<u32>().ok().filter(|p| p.to_string() == pid)?;
    let valid = !test.is_empty() && test.chars().count() <= RUN_TEST_MAX && test.chars().all(test_char);
    valid.then(|| test.to_string())
}

/// The row with only what the cost timeline reads, and a few words and numbers (§C1.3).
///
/// An allowlist (LD-C4): the kept fields are copied and every other takes its default, so a field
/// `VmRow` gains later is dropped unless it is named here. Kept: the identity (`v`, `status`, `id`),
/// the start, the wall and the idle policy (`started_at`, `wall_deadline`, `max_duration_s`, `idle`),
/// the end (`terminated_at`, `terminated_by`) and `label`, `image_version`, `egress`, `state_seen`,
/// `state_seen_at`, `mem_total_mib`. Dropped: the VM's credential and its hash (`session_token`,
/// `commit`), the run's tokens, what credential reached the VM, where the VM and its user are, the
/// ARNs naming the account, and everything else that prices nothing. Written by
/// `vm::registry::write_row`, a stripped row holds no `session_token` key at all.
#[must_use]
pub fn strip(row: &VmRow) -> VmRow {
    VmRow {
        v: row.v,
        status: row.status,
        id: row.id.clone(),
        started_at: row.started_at,
        wall_deadline: row.wall_deadline,
        max_duration_s: row.max_duration_s,
        idle: row.idle,
        terminated_at: row.terminated_at,
        terminated_by: row.terminated_by.clone(),
        label: row.label.clone(),
        image_version: row.image_version.clone(),
        egress: row.egress.clone(),
        state_seen: row.state_seen.clone(),
        state_seen_at: row.state_seen_at,
        mem_total_mib: row.mem_total_mib,
        ..VmRow::default()
    }
}

/// An audit row a run keeps (LD-C1, §C1.4 rule 2, §C1.5 rule 4): a registered event that names a
/// VM. A row naming none (`proxy_start`, `proxy_stop`, `creds_*`, `transcript_stage`) or an unknown
/// event never is: a test's own proxy rows would move the real proxy's spans at the merge.
fn kept(r: &Read) -> bool {
    r.known && !r.vms.is_empty()
}

/// An I/O error that names what was being done and to which path, keeping its kind.
fn io_at(what: &str, path: &Path, e: std::io::Error) -> BridgeError {
    BridgeError::Io(std::io::Error::new(e.kind(), format!("{what} {}: {e}", path.display())))
}

/// Whether `root`'s VM rows are there to list (§C1.4 rule 3, §C1.5 rule 3): `state`, then `state/vms`,
/// each a real directory, its own type read and never followed (`list_rows_reporting`'s `read_dir`
/// would follow a link at either, to another root's rows: a run's `state` linked to the real root's
/// would price the root's own VMs as a test's). `Ok(false)` when either is missing: no VM rows. A
/// symlink, anything but a directory, or a type that cannot be read is the `Err`, naming its path.
fn vms_listable(root: &Paths) -> Result<bool, String> {
    for path in [root.root.join("state"), root.vms()] {
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => return Err(format!("{} is a symlink; refusing to read it", path.display())),
            Ok(m) if !m.is_dir() => return Err(format!("{} is not a directory", path.display())),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(format!("cannot stat {}: {e}", path.display())),
        }
    }
    Ok(true)
}

/// Keep `test`'s cost rows under `real` (§C1.4): `Ok(Some(dir))` the run written, `Ok(None)` nothing
/// to keep (no row names a VM); never panics.
///
/// The rules, in order (plans/s12-contracts.md §C1.4):
/// 1. `test.root` and `real.root` may not be one directory (both canonicalized, as given when either
///    cannot be): a live test keeps rows only from a root of its own (§C1.4 rule 1).
/// 2. The test's audit (`read_all`; an error, a symlink or a FIFO included, is the `Err`): the rows
///    [`kept`] keeps, their stored lines in file order, each with its newline.
/// 3. The test's VM rows (`list_rows_reporting`): its `state` and `state/vms` each a real directory
///    or missing ([`vms_listable`]: a symlink at either, which the listing would follow, or a
///    non-directory is the `Err`); an error, or any row it skipped, is the `Err`; pending rows are left
///    out and each id row goes through [`strip`]. Nothing is written yet.
/// 4. With no kept audit row and no id row: `Ok(None)`, and nothing is created, not even
///    `state/test-runs`.
/// 5. `state/test-runs` is made a real 0700 directory (`registry::ensure_private_dir`), then the
///    first `seq` from 0 to [`RUN_SEQ_MAX`] whose [`run_name`] (this process's pid) nothing holds.
/// 6. The run is written whole under `.tmp-<name>` (removed first when a dead attempt left it): the
///    audit lines through `infra::write_atomic_mode` (0600, an empty file when no row was kept), each
///    stripped row through `vm::registry::write_row` (0600 in a 0700 `state/vms`), then renamed to
///    `<name>`, so a reader sees it whole or not at all; `state/test-runs` is fsync'ed (best
///    effort). A failure from here on removes `.tmp-<name>` (best effort) and is the `Err`.
///
/// It never panics (the guard calls it while a failed test unwinds, where a second panic aborts),
/// logs nothing, and its errors name paths and the readers' messages only, never a row's value.
pub fn archive(test: &Paths, real: &Paths, test_name: &str, now: u64) -> Result<Option<PathBuf>, BridgeError> {
    let same = match (std::fs::canonicalize(&test.root), std::fs::canonicalize(&real.root)) {
        (Ok(a), Ok(b)) => a == b,
        _ => test.root == real.root,
    };
    if same {
        return Err(BridgeError::Config(format!("{} is the real root: a live test keeps its rows only from a root of its own", test.root.display())));
    }
    let mut audit = String::new();
    for r in crate::bridge::audit::read::read_all(&test.audit())?.iter().filter(|r| kept(r)) {
        audit.push_str(&r.raw);
        audit.push('\n');
    }
    let (rows, skipped) = if vms_listable(test).map_err(BridgeError::Config)? { crate::bridge::vm::registry::list_rows_reporting(test)? } else { (Vec::new(), Vec::new()) };
    if !skipped.is_empty() {
        return Err(BridgeError::Config(format!("the test's VM rows could not all be read: {}", skipped.join("; "))));
    }
    let rows: Vec<VmRow> = rows.iter().filter(|r| !r.is_pending_row()).map(strip).collect();
    if audit.is_empty() && rows.is_empty() {
        return Ok(None);
    }
    let runs = real.test_runs();
    crate::bridge::registry::ensure_private_dir(&runs)?;
    let pid = std::process::id();
    let mut free = None;
    for seq in 0..=RUN_SEQ_MAX {
        let name = run_name(test_name, now, pid, seq);
        let path = runs.join(&name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {
                free = Some(name);
                break;
            }
            Err(e) => return Err(io_at("cannot stat", &path, e)),
        }
    }
    let Some(name) = free else {
        return Err(BridgeError::Config(format!("no free run name for {} (.1 to .{RUN_SEQ_MAX} taken)", run_name(test_name, now, pid, 0))));
    };
    let tmp = runs.join(format!("{RUN_TMP_PREFIX}{name}"));
    let dir = runs.join(&name);
    let written = write_run(&tmp, &dir, &audit, &rows);
    if written.is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    written?;
    if let Ok(d) = std::fs::File::open(&runs) {
        let _ = d.sync_all();
    }
    Ok(Some(dir))
}

/// [`archive`]'s rule 6 up to the rename: `tmp` made afresh and filled, then renamed to `dir`.
fn write_run(tmp: &Path, dir: &Path, audit: &str, rows: &[VmRow]) -> Result<(), BridgeError> {
    match std::fs::remove_dir_all(tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(io_at("cannot remove", tmp, e)),
    }
    crate::bridge::registry::ensure_private_dir(tmp)?;
    let run = Paths::from_root_and_env(tmp.to_path_buf(), None);
    crate::bridge::infra::write_atomic_mode(&run.audit(), audit.as_bytes(), 0o600)?;
    for row in rows {
        crate::bridge::vm::registry::write_row(&run, row)?;
    }
    std::fs::rename(tmp, dir).map_err(|e| io_at("cannot rename onto", dir, e))
}

/// Every readable run under `real` by name, and each unreadable one as `<name>: <why>` (§C1.5);
/// reads only.
///
/// `state/test-runs` missing is no run and nothing unreadable; a symlink there, a non-directory or a
/// listing that fails is one entry naming it, and no run; a listing that fails part way is that entry
/// too, beside the runs read before it, so no run drops out unnamed (§C1.5 rule 1). Of its entries, a
/// name that is not UTF-8, starts with `.` (a run being written, [`RUN_TMP_PREFIX`]) or
/// [`parse_run_name`] refuses is skipped silently (§C1.5 rule 2); a run's name on a symlink or on
/// anything but a directory (the entry's own type, never followed) is unreadable. A run is read whole
/// or not at all (LD-C2, §C1.5 rule 3): its audit (`read_all`, a missing file no rows) and its VM rows
/// (`list_rows_reporting`, a missing `state` or `state/vms` none; a symlink at either, which the
/// listing would follow, or a non-directory refused by [`vms_listable`]); an error, or any VM row
/// skipped, leaves the whole run out as `<name>: <message>` (a `Config` error's own text, else the
/// error's display; skipped rows joined by `; `). Kept: the rows [`kept`] keeps (a hand-made run's
/// proxy row is dropped here too) and the id rows; a run with neither is skipped silently. Runs come
/// back sorted by name, the unreadable entries sorted. It writes, creates, chmods and locks nothing,
/// and logs nothing.
#[must_use]
pub fn read_runs(real: &Paths) -> (Vec<TestRun>, Vec<String>) {
    let dir = real.test_runs();
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == ErrorKind::NotFound => return (Vec::new(), Vec::new()),
        Err(e) => return (Vec::new(), vec![format!("cannot stat {}: {e}", dir.display())]),
        Ok(m) if m.file_type().is_symlink() => return (Vec::new(), vec![format!("{} is a symlink; refusing to read it", dir.display())]),
        Ok(m) if !m.is_dir() => return (Vec::new(), vec![format!("{} is not a directory", dir.display())]),
        Ok(_) => {}
    }
    let entries = match std::fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) => return (Vec::new(), vec![format!("cannot list {}: {e}", dir.display())]),
    };
    let (mut runs, mut unreadable) = (Vec::new(), Vec::new());
    for entry in entries {
        // A listing that fails part way (an I/O error) is named once and ends there, never a silent gap: std's
        // listing ends at its first error but in one path (an error after it skipped `.` or `..`), which could
        // otherwise repeat the error without end.
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                unreadable.push(format!("cannot list {}: {e}", dir.display()));
                break;
            }
        };
        let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
        if name.starts_with('.') {
            continue;
        }
        let Some(test) = parse_run_name(&name) else { continue };
        let path = dir.join(&name);
        match entry.file_type() {
            Ok(t) if t.is_dir() => {}
            Ok(t) if t.is_symlink() => {
                unreadable.push(format!("{name}: {} is a symlink; refusing to read it", path.display()));
                continue;
            }
            Ok(_) => {
                unreadable.push(format!("{name}: {} is not a directory", path.display()));
                continue;
            }
            // Gone since the listing: no run.
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => {
                unreadable.push(format!("{name}: cannot stat {}: {e}", path.display()));
                continue;
            }
        }
        match read_run(&path) {
            Ok((rows, vm_rows)) if rows.is_empty() && vm_rows.is_empty() => {}
            Ok((rows, vm_rows)) => runs.push(TestRun { name, test, rows, vm_rows }),
            Err(why) => unreadable.push(format!("{name}: {why}")),
        }
    }
    runs.sort_by(|a, b| a.name.cmp(&b.name));
    unreadable.sort();
    (runs, unreadable)
}

/// One run's kept rows and id rows, whole, or why it cannot be read ([`read_runs`]).
fn read_run(path: &Path) -> Result<(Vec<Read>, Vec<VmRow>), String> {
    let run = Paths::from_root_and_env(path.to_path_buf(), None);
    // Each error names its path already: said once, without its class's `config:`.
    let message = |e: BridgeError| match e {
        BridgeError::Config(m) => m,
        e => e.to_string(),
    };
    let rows = crate::bridge::audit::read::read_all(&run.audit()).map_err(message)?;
    let (vm_rows, skipped) = if vms_listable(&run)? { crate::bridge::vm::registry::list_rows_reporting(&run).map_err(message)? } else { (Vec::new(), Vec::new()) };
    if !skipped.is_empty() {
        return Err(skipped.join("; "));
    }
    Ok((rows.into_iter().filter(kept).collect(), vm_rows.into_iter().filter(|r| !r.is_pending_row()).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::vm::registry::{list_rows_reporting, write_pending, write_row, IdleRow, RowStatus};
    use std::os::unix::fs::PermissionsExt as _;

    /// 2026-10-25T10:15:00Z.
    const AT: u64 = 1_792_923_300;
    const X: &str = "microvm-0c570000-0000-4000-8000-00000000000c";

    /// A v2 audit line of `event` at `t`, its detail `actor` and `detail`.
    fn line(t: u64, event: &str, detail: &[(&str, &str)]) -> String {
        line_of(2, t, event, detail)
    }

    /// [`line`] in schema version `version`.
    fn line_of(version: u64, t: u64, event: &str, detail: &[(&str, &str)]) -> String {
        let mut d = serde_json::Map::new();
        d.insert("actor".into(), "cli".into());
        for (k, v) in detail {
            d.insert((*k).into(), (*v).into());
        }
        serde_json::json!({ "v": version, "ts": crate::wire::time::rfc3339_utc(t), "event": event, "session_id": null, "pid": 4242, "detail": d }).to_string()
    }

    /// The three lines a run keeps of [`test_root`]'s audit, as a live test's root holds them: X's
    /// `vm_run` with `row`'s own client token (`vm::run` writes it), the delivery of `row`'s seal to X
    /// (its `credential_tag`), and X's `vm_terminate`.
    fn x_lines(row: &VmRow) -> [String; 3] {
        let tag = row.credential_tag.as_deref().unwrap_or("-");
        [
            line(AT, "vm_run", &[("id", X), ("purpose", "test"), ("image_version", "13.0"), ("egress", "internet"), ("shell", "false"), ("client_token", row.client_token.as_str())]),
            line(AT + 40, "credential_deliver", &[("id", X), ("spawn", "s1"), ("name", "CLAUDE_CODE_OAUTH_TOKEN"), ("tag", tag), ("source", "combined"), ("deliver", "fd")]),
            line(AT + 600, "vm_terminate", &[("id", X), ("by", "test")]),
        ]
    }

    /// A test root: X's three lines ([`x_lines`] of `row`), a `proxy_stop`, a `creds_setup_token`, an
    /// unknown event naming X, a `vm_run` of a later schema (`v` 3) naming X, X's row (`row`) and a
    /// pending row.
    fn test_root(dir: &Path, row: &VmRow) -> Paths {
        let p = Paths::from_root_and_env(dir.to_path_buf(), None);
        let [run, deliver, terminate] = x_lines(row);
        let lines = [
            run,
            line(AT + 10, "proxy_stop", &[("instance", "i-0test"), ("vpc_vms", "0")]),
            line(AT + 20, "creds_setup_token", &[("key", "k"), ("prefix", "p"), ("chars", "1"), ("source", "stdin"), ("rotated", "false"), ("combined", "false"), ("account", "a"), ("installed", "true")]),
            line(AT + 30, "not_an_event", &[("vm", X)]),
            deliver,
            line_of(3, AT + 50, "vm_run", &[("id", X), ("purpose", "test"), ("image_version", "13.0"), ("egress", "internet"), ("shell", "false"), ("client_token", "0199eff0-0000-7000-8000-0000000000c3")]),
            terminate,
        ];
        std::fs::write(p.audit(), lines.iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
        write_row(&p, row).unwrap();
        write_pending(&p, &VmRow { client_token: uuid::Uuid::now_v7().to_string(), status: RowStatus::Pending, ..VmRow::default() }).unwrap();
        p
    }

    /// X's row as the live test's root holds it: every field set, each value a test must never find in a
    /// run's VM row built at run time (`planted`; two of them, the client token and the seal tag, are
    /// also the ids of the audit rows [`x_lines`] makes).
    fn x_row(planted: &mut Vec<String>) -> VmRow {
        let mut plant = |v: String| {
            planted.push(v.clone());
            v
        };
        let nonce = uuid::Uuid::now_v7().simple().to_string();
        let account = "7".repeat(12);
        let arn = |what: &str| format!("arn:aws:lambda:eu-central-1:{account}:{what}");
        VmRow {
            v: 1,
            status: RowStatus::Terminated,
            id: X.into(),
            client_token: plant(uuid::Uuid::now_v7().to_string()),
            label: Some("test".into()),
            workspace: Some(plant(format!("/w/workspace-{nonce}"))),
            slug: Some(plant(format!("-w-slug-{nonce}"))),
            image_arn: plant(arn("microvm-image:ai-env-agent")),
            image_version: "13.0".into(),
            endpoint: Some(plant(format!("{nonce}.lambda-microvm.eu-central-1.on.aws"))),
            owner: plant(format!("owner-{nonce}@host")),
            created: plant("2026-10-25T10:14:58.321Z".into()),
            commit: plant(format!("{}{nonce}", "c0".repeat(16))),
            session_token: Some(plant(format!("{}{nonce}", "5e".repeat(16)))),
            started_at: Some(AT),
            wall_deadline: Some(AT + 3600),
            max_duration_s: 3600,
            idle: Some(IdleRow { max_idle_s: 300, suspended_s: 3600, auto_resume: true }),
            egress: "internet".into(),
            ingress: vec![plant(arn("network-connector:ingress-planted"))],
            egress_connectors: vec![plant(arn("network-connector:egress-planted"))],
            egress_gate: Some("passed".into()),
            shell: true,
            execution_role: Some(plant(format!("arn:aws:iam::{account}:role/role-{nonce}"))),
            state_seen: Some("TERMINATED".into()),
            state_seen_at: Some(AT + 600),
            state_reason: Some(plant(format!("reason-{nonce}"))),
            last_health_at: Some(AT + 5),
            boot_nonce: Some(plant(format!("boot-{nonce}"))),
            claude_version: Some(plant("2.1.399".into())),
            shim_version: Some(plant("0.99.7".into())),
            caps: Some(vec![plant(format!("cap-{nonce}"))]),
            credential_at: Some(AT + 7),
            credential_tag: Some(plant(format!("tag-{nonce}"))),
            credential_tags: vec![plant(format!("tags-{nonce}"))],
            token_expiries: [("8080".to_string(), plant("4000000123".into()).parse().unwrap())].into_iter().collect(),
            spawns: vec![toml::Value::String(plant(format!("spawn-{nonce}")))],
            terminated_at: Some(AT + 600),
            terminated_by: Some("test".into()),
            leaving_for: Some(plant(format!("microvm-leaving-{nonce}"))),
            leaving_since: Some(AT + 8),
            mem_total_mib: Some(1980),
            claude_bad: vec![plant(format!("bad-{nonce}"))],
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Every entry under `root`, links not followed: its path, its kind and mode, a file's bytes, a link's target.
    fn tree(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let mut entries: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).collect();
            entries.sort();
            for p in entries {
                let m = std::fs::symlink_metadata(&p).unwrap();
                let what = if m.file_type().is_symlink() {
                    format!("link {}", std::fs::read_link(&p).unwrap().display())
                } else if m.is_dir() {
                    stack.push(p.clone());
                    "dir".to_string()
                } else {
                    format!("file {:?}", std::fs::read(&p).unwrap())
                };
                out.push(format!("{} {:o} {what}", p.display(), m.permissions().mode() & 0o7777));
            }
        }
        out
    }

    /// LD-C3: a run's name is the stamp, the test as it spells it and the pid, then `.<k>` for a further
    /// run of one process in one second; `parse_run_name` gives the test back and takes no other name.
    #[test]
    fn run_names_round_trip_and_other_names_are_no_runs() {
        let at = crate::wire::time::parse_rfc3339_utc("2026-10-25T10:15:00Z").unwrap();
        assert_eq!(at, AT);
        assert_eq!(run_name("live_vm_lifecycle", at, 4242, 0), "20261025T101500Z-live_vm_lifecycle-4242");
        assert_eq!(run_name("live_vm_lifecycle", at, 4242, 3), "20261025T101500Z-live_vm_lifecycle-4242.3");
        assert_eq!(test_part("s12::live x"), "s12__live_x");
        assert_eq!(test_part(""), "unnamed");
        assert_eq!(test_part("é-ü"), "_-_", "one `_` a character, never a byte");
        assert_eq!(test_part(&"a".repeat(200)), "a".repeat(RUN_TEST_MAX));
        for (test, seq) in [("live_vm_lifecycle", 0), ("live_vm_lifecycle", 3), ("s12::live x", 9), ("", 1), ("x-1", 0), ("123", 2), ("-", 0)] {
            let name = run_name(test, at, 4242, seq);
            assert_eq!(parse_run_name(&name), Some(test_part(test)), "{name}");
        }
        assert_eq!(parse_run_name(&run_name(&"b".repeat(200), at, u32::MAX, 0)), Some("b".repeat(RUN_TEST_MAX)));
        assert_eq!(parse_run_name(&run_name("t", 0, 0, 0)).as_deref(), Some("t"), "1970 and pid 0");
        for bad in [
            "20261325T101500Z-live_vm_lifecycle-4242",
            "20261025T241500Z-live_vm_lifecycle-4242",
            "20261025T101500-live_vm_lifecycle-4242",
            "2026-10-25T10:15:00Z-live_vm_lifecycle-4242",
            "20261025t101500Z-live_vm_lifecycle-4242",
            "19691231T235959Z-live_vm_lifecycle-4242",
            "20261025T101500Z-live_vm_lifecycle",
            "20261025T101500Z-live_vm_lifecycle-",
            "20261025T101500Z-4242",
            "20261025T101500Z--4242",
            "20261025T101500Z-live_vm_lifecycle-04242",
            "20261025T101500Z-live_vm_lifecycle-+4242",
            "20261025T101500Z-live_vm_lifecycle-4294967296",
            "20261025T101500Z-live_vm_lifecycle-4242.0",
            "20261025T101500Z-live_vm_lifecycle-4242.10",
            "20261025T101500Z-live_vm_lifecycle-4242.",
            "20261025T101500Z-live_vm_lifecycle-4242.1.1",
            "20261025T101500Z-live_vm_lifecycle-4242.+1",
            "20261025T101500Z-live vm-4242",
            "20261025T101500Z-livé-4242",
            ".tmp-20261025T101500Z-live_vm_lifecycle-4242",
            ".20261025T101500Z-live_vm_lifecycle-4242",
            "notarun",
            "",
        ] {
            assert_eq!(parse_run_name(bad), None, "{bad:?}");
        }
        assert_eq!(parse_run_name(&format!("20261025T101500Z-{}-4242", "c".repeat(RUN_TEST_MAX + 1))), None, "longer than run_name keeps");
    }

    /// §C1.3: a row with every field set strips to exactly the kept fields; its TOML holds none of the
    /// planted values and no `session_token` key (M-C1).
    #[test]
    fn strip_keeps_only_what_the_timeline_reads() {
        let mut planted = Vec::new();
        let row = x_row(&mut planted);
        let s = strip(&row);
        let want = VmRow {
            v: 1,
            status: RowStatus::Terminated,
            id: X.into(),
            started_at: Some(AT),
            wall_deadline: Some(AT + 3600),
            max_duration_s: 3600,
            idle: Some(IdleRow { max_idle_s: 300, suspended_s: 3600, auto_resume: true }),
            terminated_at: Some(AT + 600),
            terminated_by: Some("test".into()),
            label: Some("test".into()),
            image_version: "13.0".into(),
            egress: "internet".into(),
            state_seen: Some("TERMINATED".into()),
            state_seen_at: Some(AT + 600),
            mem_total_mib: Some(1980),
            ..VmRow::default()
        };
        assert!(s == want, "{s:?}");
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(!text.contains("session_token"), "{text}");
        for v in &planted {
            assert!(!text.contains(v.as_str()), "{v} in {text}");
        }
        // The control: the row as it was holds every planted value.
        let full = toml::to_string_pretty(&row).unwrap();
        assert!(planted.iter().all(|v| full.contains(v.as_str())), "{planted:?}");
    }

    /// §C1.4: a run keeps the three rows naming X as stored (not the `v` 3 one: a registered event of a
    /// later schema is no `known` row) and X's stripped row alone, in a private miniature root named by
    /// `run_name`, renamed into place whole; a second run of the process in the same second is `.1`
    /// (M-C2, M-C2b). The stripped row holds none of the row's planted values; the audit holds its kept
    /// lines as stored, `vm_run`'s client token and the delivery's seal tag among them (ids, under the
    /// audit's custody rule, §C5 item 1), and none of the row's other values.
    #[test]
    fn archive_keeps_the_vm_rows_alone_in_a_private_run() {
        let (t, r) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut planted = Vec::new();
        let x = x_row(&mut planted);
        let test = test_root(t.path(), &x);
        let real = Paths::from_root_and_env(r.path().to_path_buf(), None);
        let name = run_name("archive_test", AT + 3600, std::process::id(), 0);
        let dir = archive(&test, &real, "archive_test", AT + 3600).unwrap().expect("a run");
        assert_eq!(dir, real.test_runs().join(&name));
        let [run, deliver, terminate] = x_lines(&x);
        assert_eq!(std::fs::read_to_string(dir.join("audit.jsonl")).unwrap(), format!("{run}\n{deliver}\n{terminate}\n"), "the three v2 lines naming X, as stored");
        let run_paths = Paths::from_root_and_env(dir.clone(), None);
        let (rows, skipped) = list_rows_reporting(&run_paths).unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(rows == vec![strip(&x)], "{rows:?}");
        let names: Vec<String> = std::fs::read_dir(run_paths.vms()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, [format!("{X}.toml")], "X's row alone: no pending row");
        for d in [real.test_runs(), dir.clone(), dir.join("state"), run_paths.vms()] {
            assert_eq!(mode(&d), 0o700, "{}", d.display());
        }
        for f in [dir.join("audit.jsonl"), run_paths.vms().join(format!("{X}.toml"))] {
            assert_eq!(mode(&f), 0o600, "{}", f.display());
        }
        let row_text = std::fs::read_to_string(run_paths.vms().join(format!("{X}.toml"))).unwrap();
        assert!(!row_text.contains("session_token") && planted.iter().all(|v| !row_text.contains(v.as_str())), "{row_text}");
        let audit_text = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        let ids = [x.client_token.as_str(), x.credential_tag.as_deref().unwrap_or_default()];
        assert!(ids.iter().all(|id| planted.iter().any(|v| v == id)), "{ids:?} are planted values");
        for v in &planted {
            assert_eq!(audit_text.contains(v.as_str()), ids.contains(&v.as_str()), "{v}: only the rows' own ids, as stored");
        }
        let again = archive(&test, &real, "archive_test", AT + 3600).unwrap().expect("a second run");
        assert_eq!(again, real.test_runs().join(format!("{name}.1")));
        let mut entries: Vec<String> = std::fs::read_dir(real.test_runs()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        entries.sort();
        assert_eq!(entries, [name.clone(), format!("{name}.1")], "no .tmp- entry left");
        // A dead attempt's `.tmp-` directory is taken over, and every further name of the second taken is refused.
        std::fs::create_dir(real.test_runs().join(format!("{RUN_TMP_PREFIX}{name}.2"))).unwrap();
        std::fs::write(real.test_runs().join(format!("{RUN_TMP_PREFIX}{name}.2")).join("junk"), "x").unwrap();
        let third = archive(&test, &real, "archive_test", AT + 3600).unwrap().unwrap();
        assert_eq!(third, real.test_runs().join(format!("{name}.2")));
        assert!(!third.join("junk").exists(), "the dead attempt's files are gone");
        for k in 3..=RUN_SEQ_MAX {
            std::fs::create_dir(real.test_runs().join(format!("{name}.{k}"))).unwrap();
        }
        let e = archive(&test, &real, "archive_test", AT + 3600).unwrap_err();
        assert_eq!(e.to_string(), format!("config: no free run name for {name} (.1 to .9 taken)"));
    }

    /// §C1.4 rules 1 to 4: nothing naming a VM keeps nothing (not even `state/test-runs`); the real root is
    /// refused (M-C23); a symlinked audit, a symlinked VM row and a symlinked `state` or `state/vms` (which
    /// the listing would follow) fail it, nothing written (M-C28).
    #[test]
    fn archive_writes_nothing_without_a_vm_and_refuses_the_real_root() {
        let r = tempfile::tempdir().unwrap();
        let real = Paths::from_root_and_env(r.path().to_path_buf(), None);
        let quiet = tempfile::tempdir().unwrap();
        let q = Paths::from_root_and_env(quiet.path().to_path_buf(), None);
        let rows = [line(AT, "proxy_start", &[("instance", "i-0test")]), line(AT + 5, "creds_combined", &[("by", "cli"), ("outcome", "ok"), ("removed", "0")])];
        std::fs::write(q.audit(), rows.iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
        write_pending(&q, &VmRow { client_token: uuid::Uuid::now_v7().to_string(), ..VmRow::default() }).unwrap();
        assert!(archive(&q, &real, "quiet", AT).unwrap().is_none(), "no row names a VM");
        assert!(!real.root.join("state").exists(), "nothing created");
        // The real root itself, as given and through another spelling of it.
        let t = tempfile::tempdir().unwrap();
        let mut planted = Vec::new();
        let p = test_root(t.path(), &x_row(&mut planted));
        let before = tree(&p.root);
        for other in [p.clone(), Paths::from_root_and_env(p.root.join("."), None)] {
            let e = archive(&p, &other, "self", AT).unwrap_err();
            assert!(matches!(&e, BridgeError::Config(m) if m == &format!("{} is the real root: a live test keeps its rows only from a root of its own", p.root.display())), "{e}");
        }
        assert_eq!(tree(&p.root), before, "nothing written");
        // A symlinked audit: refused by the reader.
        let s = tempfile::tempdir().unwrap();
        let linked = test_root(s.path(), &x_row(&mut planted));
        std::fs::rename(linked.audit(), s.path().join("elsewhere.jsonl")).unwrap();
        std::os::unix::fs::symlink(s.path().join("elsewhere.jsonl"), linked.audit()).unwrap();
        let e = archive(&linked, &real, "linked", AT).unwrap_err();
        assert!(e.to_string().contains("is a symlink"), "{e}");
        assert!(!real.root.join("state").exists(), "nothing written");
        // A symlinked VM row: named, nothing written.
        let v = tempfile::tempdir().unwrap();
        let row_linked = test_root(v.path(), &x_row(&mut planted));
        let row = row_linked.vms().join(format!("{X}.toml"));
        std::fs::rename(&row, v.path().join("row.toml")).unwrap();
        std::os::unix::fs::symlink(v.path().join("row.toml"), &row).unwrap();
        let e = archive(&row_linked, &real, "row_linked", AT).unwrap_err();
        assert_eq!(e.to_string(), format!("config: the test's VM rows could not all be read: {} is a symlink; refusing to read it", row.display()));
        assert!(!real.root.join("state").exists(), "nothing written");
        // A symlinked `state` or `state/vms`, whose rows the listing would read through the link: named, nothing written.
        for part in ["state", "state/vms"] {
            let d = tempfile::tempdir().unwrap();
            test_root(d.path(), &x_row(&mut planted));
            let (at, elsewhere) = (d.path().join(part), d.path().join("elsewhere"));
            std::fs::rename(&at, &elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &at).unwrap();
            let e = archive(&Paths::from_root_and_env(d.path().to_path_buf(), None), &real, "state_linked", AT).unwrap_err();
            assert!(matches!(&e, BridgeError::Config(m) if m == &format!("{} is a symlink; refusing to read it", at.display())), "{part}: {e}");
            assert!(!real.root.join("state").exists(), "{part}: nothing written");
        }
    }

    /// §C1.5: dot entries and other names are skipped silently (M-C3); a symlinked run, a run with a
    /// symlinked audit and one with a symlinked VM row are named and none of their rows is used (M-C4), and
    /// so are a run whose `state` links to the real root's own (whose VM rows the listing would read as the
    /// run's), one whose `state/vms` is a symlink and one whose `state` is a file (M-C27); a hand-made run's
    /// proxy row and its row of a later schema are dropped (M-C2b); a missing `state/test-runs` is nothing,
    /// a symlinked one an entry; the tree is as it was.
    #[test]
    fn read_runs_skips_dot_dirs_and_names_unreadable_runs() {
        let r = tempfile::tempdir().unwrap();
        let real = Paths::from_root_and_env(r.path().to_path_buf(), None);
        let mut planted = Vec::new();
        let x = x_row(&mut planted);
        let make = |test: &str| {
            let t = tempfile::tempdir().unwrap();
            let dir = archive(&test_root(t.path(), &x), &real, test, AT).unwrap().unwrap();
            (dir.file_name().unwrap().to_string_lossy().into_owned(), dir)
        };
        let (good, good_dir) = make("good");
        let (audit_link, audit_link_dir) = make("audit_link");
        let (row_link, row_link_dir) = make("row_link");
        std::fs::rename(audit_link_dir.join("audit.jsonl"), r.path().join("audit-elsewhere.jsonl")).unwrap();
        std::os::unix::fs::symlink(r.path().join("audit-elsewhere.jsonl"), audit_link_dir.join("audit.jsonl")).unwrap();
        let linked_row = row_link_dir.join("state/vms").join(format!("{X}.toml"));
        std::fs::rename(&linked_row, r.path().join("row-elsewhere.toml")).unwrap();
        std::os::unix::fs::symlink(r.path().join("row-elsewhere.toml"), &linked_row).unwrap();
        // The real root's own VM, which a run's linked `state` would hand the run.
        write_row(&real, &VmRow { id: "microvm-0b000000-0000-4000-8000-00000000000b".into(), status: RowStatus::Running, started_at: Some(AT), ..VmRow::default() }).unwrap();
        let (state_link, state_link_dir) = make("state_link");
        std::fs::remove_dir_all(state_link_dir.join("state")).unwrap();
        std::os::unix::fs::symlink(real.root.join("state"), state_link_dir.join("state")).unwrap();
        let (vms_link, vms_link_dir) = make("vms_link");
        std::fs::remove_dir_all(vms_link_dir.join("state/vms")).unwrap();
        std::os::unix::fs::symlink(real.vms(), vms_link_dir.join("state/vms")).unwrap();
        let (state_file, state_file_dir) = make("state_file");
        std::fs::remove_dir_all(state_file_dir.join("state")).unwrap();
        std::fs::write(state_file_dir.join("state"), "x").unwrap();
        let dir_link = run_name("dir_link", AT, 77, 0);
        std::os::unix::fs::symlink(&good_dir, real.test_runs().join(&dir_link)).unwrap();
        let file_run = run_name("file_run", AT, 78, 0);
        std::fs::write(real.test_runs().join(&file_run), "x").unwrap();
        // A run being written, a name that is no run's, an empty run, and a hand-made run with a proxy row.
        for skipped in [format!("{RUN_TMP_PREFIX}{}", run_name("tmp", AT, 79, 0)), "notarun".to_string(), run_name("empty", AT, 80, 0)] {
            std::fs::create_dir(real.test_runs().join(&skipped)).unwrap();
            if skipped != run_name("empty", AT, 80, 0) {
                std::fs::copy(good_dir.join("audit.jsonl"), real.test_runs().join(&skipped).join("audit.jsonl")).unwrap();
            }
        }
        let hand = run_name("hand", AT, 81, 0);
        std::fs::create_dir(real.test_runs().join(&hand)).unwrap();
        let [run, ..] = x_lines(&x);
        let later = line_of(3, AT + 5, "vm_terminate", &[("id", X), ("by", "test")]);
        std::fs::write(real.test_runs().join(&hand).join("audit.jsonl"), format!("{}\n{run}\n{later}\n", line(AT - 60, "proxy_start", &[("instance", "i-0test")]))).unwrap();
        let before = tree(&real.root);
        let (runs, unreadable) = read_runs(&real);
        assert_eq!(tree(&real.root), before, "reading writes, creates and chmods nothing");
        let names: Vec<&str> = runs.iter().map(|r| r.name.as_str()).collect();
        let mut want = vec![good.as_str(), hand.as_str()];
        want.sort_unstable();
        assert_eq!(names, want, "{unreadable:?}");
        let g = runs.iter().find(|r| r.name == good).unwrap();
        assert_eq!((g.test.as_str(), g.rows.iter().map(|r| r.raw.as_str()).collect::<Vec<_>>()), ("good", x_lines(&x).iter().map(String::as_str).collect::<Vec<_>>()));
        assert!(g.vm_rows == vec![strip(&x)], "{:?}", g.vm_rows);
        let h = runs.iter().find(|r| r.name == hand).unwrap();
        assert_eq!((h.test.as_str(), h.rows.iter().map(|r| r.event.as_str()).collect::<Vec<_>>(), h.vm_rows.len()), ("hand", vec!["vm_run"], 0), "its proxy row and its v3 row dropped");
        let mut want = vec![
            format!("{audit_link}: {} is a symlink; refusing to read it", audit_link_dir.join("audit.jsonl").display()),
            format!("{row_link}: {} is a symlink; refusing to read it", linked_row.display()),
            format!("{dir_link}: {} is a symlink; refusing to read it", real.test_runs().join(&dir_link).display()),
            format!("{file_run}: {} is not a directory", real.test_runs().join(&file_run).display()),
            format!("{state_link}: {} is a symlink; refusing to read it", state_link_dir.join("state").display()),
            format!("{vms_link}: {} is a symlink; refusing to read it", vms_link_dir.join("state/vms").display()),
            format!("{state_file}: {} is not a directory", state_file_dir.join("state").display()),
        ];
        want.sort();
        assert_eq!(unreadable, want);
        // No state/test-runs: nothing, nothing created; a symlinked one: one entry, no run.
        let empty = tempfile::tempdir().unwrap();
        let none = Paths::from_root_and_env(empty.path().to_path_buf(), None);
        assert_eq!(read_runs(&none), (Vec::new(), Vec::new()));
        assert_eq!(tree(empty.path()), Vec::<String>::new());
        std::fs::create_dir(empty.path().join("state")).unwrap();
        std::os::unix::fs::symlink(real.test_runs(), none.test_runs()).unwrap();
        assert_eq!(read_runs(&none), (Vec::new(), vec![format!("{} is a symlink; refusing to read it", none.test_runs().display())]));
        std::fs::remove_file(none.test_runs()).unwrap();
        std::fs::write(none.test_runs(), "").unwrap();
        assert_eq!(read_runs(&none), (Vec::new(), vec![format!("{} is not a directory", none.test_runs().display())]));
    }
}
