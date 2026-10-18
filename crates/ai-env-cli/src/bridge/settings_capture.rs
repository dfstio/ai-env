//! Settings persistence (S8 T8.7, plan section 9): what the VM's claude holds
//! for the workspace — the agent's `settings.json` (user), the workspace's
//! `.claude/settings.json` (project) and `.claude/settings.local.json` (local:
//! where "don't ask again" lands), and the allowlisted keys of
//! `projects[path]` in the agent's `.claude.json` — read through `GET
//! /settings` (8080, the data plane's `get_settings`) into the session's
//! quarantine, `quarantine/<session>/settings/` (0700 directories, 0600
//! files), each capture with the VM it was read in ([`KeptCapture`]):
//! - `start.json`, the session's baseline: taken once its id is known (a
//!   `--resume`'s as its spawn goes out, a fresh session's at its first
//!   `system/init`, both through `codeout::CodeoutTrigger::set_session`) and
//!   never moved after, so a resumed session keeps its first baseline;
//! - `latest.json`, after each code-out fetch: the last capture of the VM
//!   the session ran on last, written only when a file's digest or a
//!   project key changed since that VM's newest capture;
//! - `latest-<VM id>.json`, the last capture of each VM the session left: a
//!   turn's capture from another VM than `latest.json`'s renames that file
//!   to its VM's name first (the VM id as the VM row writes it, checked:
//!   never a path). A resume on a new VM (the old one terminated) is seeded
//!   from the Mac, so its captures lack what the old VM approved; kept per
//!   VM, a rule approved on a VM the session left stays in the diff, and
//!   among `settings-sync`'s candidates (`already in the image` once
//!   promoted), until the session is forgotten (`session forget` removes the
//!   whole quarantine directory);
//! - `checked.json` (S9, L9): `{at, vm}` of the last turn's capture that
//!   equalled its VM's newest one (none is written then), so the diff says
//!   the settings were checked unchanged, not never compared; a written
//!   turn's capture removes it.
//!
//! The quarantine keeps no secret (`at_rest`, every file): each file's text
//! is kept re-written from its document with every `env` value replaced by
//! a digest, and every string a tripwire or the scrubber matches masked (a
//! text that is no JSON is not kept); the VM file's presence, size and
//! digest stay, so a change is still seen.
//!
//! Nothing runs inside the close budget: the trigger gives a running capture
//! up as the wrapper closes, so a rule approved after the last result's
//! capture (or in a turn the close cut short) is missed until the session
//! runs another turn. A capture never fails the session: a failure is
//! logged and audited (`settings_capture`), and the next code-out tries
//! again.
//!
//! `session show UUID --settings-diff [--json]` ([`cmd_settings_diff`])
//! compares each VM's last capture with the start, per scope ([`diff`]): the
//! `allow`, `deny` and `ask` entries added and removed, `defaultMode`'s
//! change, every other key by name only, `env` by name with its values
//! masked. The rules added in any of them are shown once, their union (the
//! scopes and VMs that added each), then each VM's other changes. The diff
//! is written to [`DIFF_FILE`] beside the captures, `diff.json` of
//! [`DIFF_V`] 3: `{v, session, path, start, start_vm, added: [{kind, rule,
//! scopes, vms}], vms: [{vm, current, at, scopes, project}], checked: {at,
//! vm}}`, the union first, then each VM's whole diff ([`VmDiff`]), the
//! session's last VM (`current`, `latest.json`'s) before the VMs it left (by
//! id); a VM not recorded leaves `vm` out, as `start_vm`, and no
//! `checked.json` leaves `checked` out. Version 1 held one comparison's
//! `latest`, `scopes` and `project` at the top; version 2 had no `checked`.
//! A rule a tripwire matches is never shown, and every rule and key is shown
//! scrubbed ([`SettingsDiff::shown`]). `wrapper settings-sync` promotes the safe
//! added rules into the image (`bridge::wrapper::settings_sync`,
//! [`SettingsDiff::added_rules`], [`rule_refusal`]).
use crate::bridge::agent::AgentTarget;
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::dataplane::{verdict, DataPlane, TokenSource, Verdict};
use crate::bridge::errors::BridgeError;
use crate::bridge::infra::write_atomic_mode;
use crate::bridge::registry::{is_uuid, read_regular_file};
use crate::bridge::remote::audit_event;
use crate::bridge::scan::{load_lists, settings_findings_mode, Rules, SettingsMode};
use crate::bridge::vm::registry::is_vm_id;
use crate::errors::{CliError, Result};
use crate::wire::redact::scrub;
use crate::wire::time::parse_rfc3339_utc;
use crate::wire::workspace::{SettingsCapture, SettingsFile, SettingsScope, APP_PORT, SETTINGS_ROUTE};
use crate::{bail, outln};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The diff `session show --settings-diff` writes beside the captures.
pub const DIFF_FILE: &str = "diff.json";

/// The longest one capture may take, its token's mint included; past it the
/// capture is given up (logged and audited) and the next code-out tries again.
pub const CAPTURE_WAIT: Duration = Duration::from_secs(20);

/// The schema version of [`SettingsDiff`] (`diff.json`'s `v`): 3 since it
/// carries the last check (`checked`, S9); 2 kept and compared each VM's
/// last capture (1 compared one capture).
pub const DIFF_V: u8 = 3;

/// The last turn's capture that equalled its VM's newest one, beside the
/// captures (S9, L9: [`SettingsChecked`]).
pub const CHECKED_FILE: &str = "checked.json";

/// A kept capture of a VM the session left is named `latest-<VM id>.json`.
const LEFT_PREFIX: &str = "latest-";
const LEFT_SUFFIX: &str = ".json";

/// When a capture is taken: nothing runs inside the close budget, so a rule
/// approved after the last result is missed (documented).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePhase {
    /// Once the session's id is known (a `--resume`'s at its spawn, a fresh
    /// session's at its first `system/init`); a session's first is kept.
    Start,
    /// After each code-out fetch (written when the settings changed since
    /// its VM's newest capture; another VM's `latest.json` is kept first as
    /// `latest-<VM id>.json`).
    Turn,
}

impl CapturePhase {
    /// The file it writes under `quarantine/<session>/settings/`.
    #[must_use]
    pub fn file_name(self) -> &'static str {
        match self {
            CapturePhase::Start => "start.json",
            CapturePhase::Turn => "latest.json",
        }
    }

    /// The word the audit row and the log name it by.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            CapturePhase::Start => "start",
            CapturePhase::Turn => "turn",
        }
    }
}

/// `quarantine/<session>/settings/<phase's file>` (0600 under 0700
/// directories); `Config` for anything that is not a session id, before
/// any path is built from it.
pub fn capture_path(paths: &Paths, session_id: &str, phase: CapturePhase) -> std::result::Result<PathBuf, BridgeError> {
    if !is_uuid(session_id) {
        return Err(BridgeError::Config(format!("not a session id: {session_id:?}")));
    }
    Ok(settings_dir(paths, session_id).join(phase.file_name()))
}

/// `quarantine/<session>/settings` (`session_id` already a session id).
fn settings_dir(paths: &Paths, session_id: &str) -> PathBuf {
    paths.quarantine_session(session_id).join("settings")
}

/// `quarantine/<session>/settings/latest-<vm>.json`: the last capture of a
/// VM the session left; `Config` for a session id or a VM id that is none
/// (`vm::registry::is_vm_id`), before any path is built from either.
pub fn left_capture_path(paths: &Paths, session_id: &str, vm: &str) -> std::result::Result<PathBuf, BridgeError> {
    if !is_uuid(session_id) {
        return Err(BridgeError::Config(format!("not a session id: {session_id:?}")));
    }
    if !is_vm_id(vm) {
        return Err(BridgeError::Config(format!("not a VM id: {vm:?}")));
    }
    Ok(settings_dir(paths, session_id).join(format!("{LEFT_PREFIX}{vm}{LEFT_SUFFIX}")))
}

/// The VM a `latest-<VM id>.json` name is of, when it is one.
fn left_vm(name: &str) -> Option<&str> {
    name.strip_prefix(LEFT_PREFIX).and_then(|n| n.strip_suffix(LEFT_SUFFIX)).filter(|vm| is_vm_id(vm))
}

/// The VMs of the `latest-<VM id>.json` files in `dir`, sorted; none when
/// `dir` does not exist.
fn left_vms(dir: &Path) -> std::result::Result<Vec<String>, BridgeError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot list {}: {e}", dir.display())))),
    };
    let mut vms: Vec<String> = entries.filter_map(std::result::Result::ok).filter_map(|e| e.file_name().to_str().and_then(left_vm).map(str::to_string)).collect();
    vms.sort();
    Ok(vms)
}

/// `dir` a real directory of this user's, 0700: created (0700) when absent,
/// tightened when wider, refused when it is a symlink or not a directory
/// (the quarantine is the bridge's own, never written through a link).
fn private_dir(dir: &Path) -> std::result::Result<(), BridgeError> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => Err(BridgeError::Config(format!("{} is a symlink; refusing to write the quarantine through it", dir.display()))),
        Ok(m) if !m.is_dir() => Err(BridgeError::Config(format!("{} is not a directory", dir.display()))),
        Ok(m) => {
            if m.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => std::fs::DirBuilder::new().mode(0o700).create(dir).map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot create {}: {e}", dir.display())))),
        Err(e) => Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot stat {}: {e}", dir.display())))),
    }
}

/// `quarantine/<session>/settings`, each level made a private directory
/// ([`private_dir`]); the session id must already be one.
pub(crate) fn private_settings_dir(paths: &Paths, session_id: &str) -> std::result::Result<PathBuf, BridgeError> {
    if !is_uuid(session_id) {
        return Err(BridgeError::Config(format!("not a session id: {session_id:?}")));
    }
    let dir = settings_dir(paths, session_id);
    for level in [paths.quarantine(), paths.quarantine_session(session_id), dir.clone()] {
        private_dir(&level)?;
    }
    Ok(dir)
}

/// One capture as the quarantine keeps it (`start.json`, `latest.json`,
/// `latest-<VM id>.json`): `GET /settings`' answer as `at_rest` left it,
/// one JSON document with the VM it was read in beside the capture's own
/// keys. `vm` is `None` for a capture that names none (W8's first build
/// wrote them so), which is taken as any VM's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptCapture {
    /// The VM, as its row names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<String>,
    #[serde(flatten)]
    pub capture: SettingsCapture,
}

impl KeptCapture {
    /// Read in `vm`, as far as it says: one that names no VM is anyone's.
    fn of_vm(&self, vm: &str) -> bool {
        self.vm.as_deref().is_none_or(|v| v == vm)
    }
}

/// `checked.json` (S9, L9): when the last turn's capture that equalled its
/// VM's newest one was read in the VM, and which VM; written only for a
/// capture that names its VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsChecked {
    /// The capture's own time (RFC 3339 UTC, as `GET /settings` answered it).
    pub at: String,
    /// The VM it was read in.
    pub vm: String,
}

/// `quarantine/<session>/settings/checked.json`; `Config` for anything that
/// is not a session id, before any path is built from it.
fn checked_path(paths: &Paths, session_id: &str) -> std::result::Result<PathBuf, BridgeError> {
    if !is_uuid(session_id) {
        return Err(BridgeError::Config(format!("not a session id: {session_id:?}")));
    }
    Ok(settings_dir(paths, session_id).join(CHECKED_FILE))
}

/// A turn's capture (`kept`) equalled its VM's newest one: `checked.json`
/// says when and in which VM (0600, in the session's private directory).
/// Best effort: one that cannot be written is logged, the capture itself
/// stays unwritten as it should.
fn note_checked(paths: &Paths, session_id: &str, kept: &KeptCapture) {
    let Some(vm) = kept.vm.clone() else { return };
    let checked = SettingsChecked { at: kept.capture.at.clone(), vm };
    let written = checked_path(paths, session_id).and_then(|path| {
        private_settings_dir(paths, session_id)?;
        let mut text = serde_json::to_string_pretty(&checked).map_err(|e| BridgeError::Config(format!("cannot render {CHECKED_FILE}: {e}")))?;
        text.push('\n');
        write_atomic_mode(&path, text.as_bytes(), 0o600)
    });
    if let Err(e) = written {
        tracing::warn!("settings capture: {CHECKED_FILE} not written: {e}");
    }
}

/// A turn's capture was written: the last check no longer stands for the
/// newest capture, so `checked.json` goes (best effort, never through a
/// link: `remove_file` takes the link itself).
fn forget_checked(paths: &Paths, session_id: &str) {
    let Ok(path) = checked_path(paths, session_id) else { return };
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("settings capture: {} not removed: {e}", path.display()),
    }
}

/// `checked.json` of `session_id` (a regular file, never followed through a
/// symlink); `None` when there is none, or (logged) when it does not read
/// as one: the diff goes on without it.
fn read_checked(paths: &Paths, session_id: &str) -> std::result::Result<Option<SettingsChecked>, BridgeError> {
    let path = checked_path(paths, session_id)?;
    let Some(text) = read_regular_file(&path)? else {
        return Ok(None);
    };
    match serde_json::from_str(&text) {
        Ok(checked) => Ok(Some(checked)),
        Err(e) => {
            tracing::warn!("settings capture: {} is not a check: {}", path.display(), e.to_string().lines().next().unwrap_or("unparseable"));
            Ok(None)
        }
    }
}

/// The capture at `path` (a regular file, never followed through a
/// symlink); `None` when there is none.
pub fn read_capture(path: &Path) -> std::result::Result<Option<KeptCapture>, BridgeError> {
    let Some(text) = read_regular_file(path)? else {
        return Ok(None);
    };
    let kept: KeptCapture = serde_json::from_str(&text).map_err(|e| BridgeError::Config(format!("{} is not a settings capture: {}", path.display(), e.to_string().lines().next().unwrap_or("unparseable"))))?;
    Ok(Some(kept))
}

/// The two captures hold the same settings: every file's presence, size,
/// digest and skip reason, and the project keys (`at` aside).
fn same_settings(a: &SettingsCapture, b: &SettingsCapture) -> bool {
    let same_file = |x: &SettingsFile, y: &SettingsFile| (x.scope, x.present, x.size, &x.sha256, &x.skipped) == (y.scope, y.present, y.size, &y.sha256, &y.skipped);
    a.files.len() == b.files.len() && a.files.iter().zip(&b.files).all(|(x, y)| same_file(x, y)) && a.project == b.project
}

/// `GET /settings?path=<vm_root>` on 8080: a 401 or 403 forgets the port's
/// token and asks once more ([`verdict`]'s re-mint); any other refusal is
/// the error. The answer must be a capture of `vm_root` that passes the
/// wire's check, read at an RFC 3339 UTC time, each file's path and skip
/// reason free of control characters and its digest 64 lowercase hex
/// digits (the helper's words reach the operator's terminal).
async fn fetch_settings<D: DataPlane, T: TokenSource>(dp: &D, tokens: &T, target: &AgentTarget, vm_root: &str) -> std::result::Result<SettingsCapture, BridgeError> {
    let route = "GET /settings";
    let mut reminted = false;
    let capture = loop {
        let token = tokens.token(APP_PORT).await?;
        let reply = dp.get_settings(target, &token, vm_root).await?;
        match verdict(route, APP_PORT, &reply) {
            Verdict::Done => break reply.body.ok_or_else(|| BridgeError::Protocol(format!("{route} answered HTTP {} without a capture", reply.status)))?,
            Verdict::Remint { error } => {
                if reminted {
                    return Err(error);
                }
                reminted = true;
                tokens.forget(APP_PORT);
            }
            Verdict::Fail(e) | Verdict::Busy { error: e } | Verdict::Reread { error: e } | Verdict::Throttled { error: e, .. } | Verdict::CheckVm { error: e } => return Err(e),
            Verdict::Kept { .. } => return Err(BridgeError::Protocol(format!("{route} answered HTTP {}, which no settings route answers", reply.status))),
        }
    };
    capture.check().map_err(|e| BridgeError::Protocol(format!("{SETTINGS_ROUTE}: the capture {e}")))?;
    if capture.path != vm_root {
        return Err(BridgeError::Protocol(format!("{SETTINGS_ROUTE}: the VM answered for another workspace path than {vm_root}")));
    }
    if parse_rfc3339_utc(&capture.at).is_none() {
        return Err(BridgeError::Protocol(format!("{SETTINGS_ROUTE}: the capture's time is not RFC 3339 UTC")));
    }
    let hex64 = |h: &str| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let control = |s: &str| s.chars().any(char::is_control);
    if let Some(f) = capture.files.iter().find(|f| control(&f.path) || f.skipped.as_deref().is_some_and(control) || f.sha256.as_deref().is_some_and(|h| !hex64(h))) {
        return Err(BridgeError::Protocol(format!("{SETTINGS_ROUTE}: the {} file's path, skip reason or digest is malformed", f.scope.name())));
    }
    Ok(capture)
}

// ---- at rest -----------------------------------------------------------------------------

/// How a string the quarantine does not keep starts ([`masked`]); settings-sync
/// never promotes such a rule ([`rule_refusal`]).
const MASKED: &str = "(masked: ";

/// `sha256:` and the first 16 hex digits of the digest of `bytes`: tells two
/// values apart without keeping either.
fn short_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hex = hex::encode(Sha256::digest(bytes));
    format!("sha256:{}", &hex[..16])
}

/// A string of the VM's as the quarantine keeps it: `(masked: RULES,
/// sha256:…)` when a tripwire matches it or the scrubber would change it
/// (the digest keeps two such strings apart, so the diff still sees a
/// change), else as it is.
fn masked(text: &str, rules: &Rules) -> String {
    let mut why: BTreeSet<String> = rules.scan_bytes(text.as_bytes()).into_iter().map(|(_, id)| id).collect();
    if why.is_empty() && scrub(text) != text {
        why.insert("secret-shaped".into());
    }
    if why.is_empty() {
        return text.to_string();
    }
    format!("{MASKED}{}, {})", why.into_iter().collect::<Vec<_>>().join(", "), short_digest(text.as_bytes()))
}

/// `value` with every string and every key through [`masked`].
fn mask_value(value: Value, rules: &Rules) -> Value {
    match value {
        Value::String(s) => Value::String(masked(&s, rules)),
        Value::Array(a) => Value::Array(a.into_iter().map(|v| mask_value(v, rules)).collect()),
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, v)| (masked(&k, rules), mask_value(v, rules))).collect()),
        other => other,
    }
}

/// A settings file's text as the quarantine keeps it: its document with
/// every `env` value replaced by its [`short_digest`] (the diff names a
/// changed one, never its value), then every string and key [`masked`],
/// written compact; `Err` says why a text that is no JSON is not kept.
fn kept_text(text: &str, rules: &Rules) -> std::result::Result<String, String> {
    let mut doc: Value = serde_json::from_str(text).map_err(|e| format!("not JSON (line {})", e.line()))?;
    match doc.get_mut("env") {
        Some(Value::Object(env)) => env.values_mut().for_each(|v| *v = Value::String(short_digest(v.to_string().as_bytes()))),
        Some(other) => *other = Value::String(short_digest(other.to_string().as_bytes())),
        None => {}
    }
    serde_json::to_string(&mask_value(doc, rules)).map_err(|e| format!("cannot be written again: {e}"))
}

/// What the quarantine keeps of a capture (custody: no secret at rest):
/// each file's text as [`kept_text`] writes it (one that is no JSON is
/// dropped, `skipped` saying why), its path and skip reason [`masked`], its
/// presence, size and digest the VM file's, so a change is still seen; the
/// project values masked. A kept text is no longer its file's bytes: a kept
/// capture is never checked against the wire's rules again.
fn at_rest(capture: SettingsCapture, rules: &Rules) -> SettingsCapture {
    let files = capture
        .files
        .into_iter()
        .map(|f| {
            let (text, skipped) = match f.text.as_deref().map(|t| kept_text(t, rules)) {
                Some(Ok(text)) => (Some(text), f.skipped.as_deref().map(|s| masked(s, rules))),
                Some(Err(why)) => (None, Some(why)),
                None => (None, f.skipped.as_deref().map(|s| masked(s, rules))),
            };
            SettingsFile { path: masked(&f.path, rules), text, skipped, ..f }
        })
        .collect();
    let project = capture.project.into_iter().map(|(k, v)| (k, mask_value(v, rules))).collect();
    SettingsCapture { files, project, ..capture }
}

/// Write `kept` as `phase`'s file of `session_id`; `true` when written. A
/// turn's (the module doc): a `latest.json` read in another VM is kept as
/// that VM's last capture ([`leave`]) and `kept` takes its place; else
/// `kept` is written only when it differs from its VM's newest capture on
/// disk (`latest.json`, else its `latest-<VM id>.json`, else `start.json`
/// when read in that VM; one that cannot be read counts as different); an
/// unwritten one leaves `checked.json` (S9, [`note_checked`]), a written one
/// takes it away. Once `latest.json` is `kept`'s, that VM's older
/// `latest-<VM id>.json` goes.
fn store(paths: &Paths, session_id: &str, phase: CapturePhase, kept: &KeptCapture) -> std::result::Result<bool, BridgeError> {
    let path = capture_path(paths, session_id, phase)?;
    let vm = kept.vm.as_deref().filter(|_| phase == CapturePhase::Turn);
    // The VM's own older capture, under the name a VM the session left has.
    let older = vm.map(|vm| left_capture_path(paths, session_id, vm)).transpose()?;
    if phase == CapturePhase::Turn {
        let newest = match read_capture(&path) {
            Ok(Some(latest)) => match (latest.vm.as_deref(), vm) {
                // The session moved: the VM it left keeps its last capture.
                (Some(left), Some(now)) if left != now => {
                    leave(paths, session_id, &path, left)?;
                    None
                }
                _ => Some(latest),
            },
            Ok(None) => match older.as_deref().map(read_capture) {
                Some(Ok(Some(own))) => Some(own),
                _ => read_capture(&capture_path(paths, session_id, CapturePhase::Start)?).ok().flatten().filter(|start| vm.is_none_or(|v| start.of_vm(v))),
            },
            Err(_) => None,
        };
        if newest.is_some_and(|n| same_settings(&n.capture, &kept.capture)) {
            note_checked(paths, session_id, kept);
            return Ok(false);
        }
    }
    private_settings_dir(paths, session_id)?;
    let mut text = serde_json::to_string_pretty(kept).map_err(|e| BridgeError::Config(format!("cannot render the settings capture: {e}")))?;
    text.push('\n');
    write_atomic_mode(&path, text.as_bytes(), 0o600)?;
    if phase == CapturePhase::Turn {
        forget_checked(paths, session_id);
    }
    if let Some(older) = &older {
        match std::fs::remove_file(older) {
            Ok(()) => tracing::info!("settings capture: {} went (latest.json is that VM's now)", older.display()),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("settings capture: {} not removed: {e}", older.display()),
        }
    }
    Ok(true)
}

/// `latest.json` (at `latest`), read in `vm`, kept as the last capture of a
/// VM the session left: renamed `latest-<vm>.json`, over that VM's older one
/// (in the session's private directory, never through a link). A `vm` that
/// is no VM id (a capture edited by hand) names no file: that capture is
/// replaced, as one that cannot be read.
fn leave(paths: &Paths, session_id: &str, latest: &Path, vm: &str) -> std::result::Result<(), BridgeError> {
    let Ok(to) = left_capture_path(paths, session_id, vm) else {
        tracing::warn!("settings capture: latest.json names {vm:?}, no VM id: replaced");
        return Ok(());
    };
    private_settings_dir(paths, session_id)?;
    std::fs::rename(latest, &to).map_err(|e| BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot rename {} to {}: {e}", latest.display(), to.display()))))?;
    tracing::info!(vm, "settings capture: latest.json kept as {} (the session moved to another VM)", to.display());
    Ok(())
}

/// One `settings_capture` audit row of `session_id` (best effort: a row
/// that cannot be written is logged).
fn audit_capture(paths: &Paths, session_id: &str, pairs: &[(&str, String)]) {
    let row = AuditRow::new(audit_event::SETTINGS_CAPTURE, Some(session_id), audit::detail(pairs));
    if let Err(e) = audit::append(&paths.audit(), &row) {
        tracing::warn!("audit row settings_capture not written: {e}");
    }
}

/// Capture the VM's settings for `session_id` (`GET /settings?path=<vm_root>`
/// on 8080) into its quarantine, as `at_rest` keeps them, with
/// `target`'s VM: `Ok(true)` when a file was written. A start capture is
/// taken once: with a `start.json` already there nothing is asked and
/// `Ok(false)` comes back (a resumed session keeps its first baseline). A
/// turn's is written only when the settings changed since that VM's newest
/// capture; the first on another VM than `latest.json`'s keeps that file as
/// the last capture of the VM the session left (`latest-<VM id>.json`).
/// Bounded by [`CAPTURE_WAIT`]; never inside the close budget (the caller
/// gives it up as the wrapper closes); a written or failed capture is
/// audited (`settings_capture`), never fatal to the caller.
pub async fn capture<D: DataPlane, T: TokenSource>(dp: &D, tokens: &T, target: &AgentTarget, paths: &Paths, session_id: &str, vm_root: &str, phase: CapturePhase) -> std::result::Result<bool, BridgeError> {
    capture_within(dp, tokens, target, paths, session_id, vm_root, phase, CAPTURE_WAIT).await
}

/// [`capture`] bounded by `wait`.
#[allow(clippy::too_many_arguments)]
async fn capture_within<D: DataPlane, T: TokenSource>(dp: &D, tokens: &T, target: &AgentTarget, paths: &Paths, session_id: &str, vm_root: &str, phase: CapturePhase, wait: Duration) -> std::result::Result<bool, BridgeError> {
    let path = capture_path(paths, session_id, phase)?;
    if phase == CapturePhase::Start {
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => return Err(BridgeError::Config(format!("{} is a symlink; refusing to write the quarantine through it", path.display()))),
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot stat {}: {e}", path.display())))),
        }
    }
    let fetched = match tokio::time::timeout(wait, fetch_settings(dp, tokens, target, vm_root)).await {
        Ok(r) => r,
        Err(_) => Err(BridgeError::Endpoint(format!("GET /settings did not answer within {} ms", wait.as_millis()))),
    };
    // What is kept: masked with the bridge's tripwires (a failure to load them writes nothing), and its VM.
    let kept = fetched.and_then(|c| tripwires(paths).map(|rules| KeptCapture { vm: Some(target.vm_id.clone()), capture: at_rest(c, &rules) }).map_err(|e| BridgeError::Config(format!("the tripwires: {e}"))));
    let result = kept.and_then(|k| store(paths, session_id, phase, &k).map(|written| (written, k.capture.files.iter().filter(|f| f.present).count())));
    match &result {
        Ok((true, present)) => audit_capture(paths, session_id, &[("phase", phase.word().into()), ("outcome", "written".into()), ("vm", target.vm_id.clone()), ("files", present.to_string())]),
        Ok((false, _)) => {}
        Err(e) => {
            let why = scrub(e.to_string().lines().next().unwrap_or("failed")).chars().take(300).collect::<String>();
            audit_capture(paths, session_id, &[("phase", phase.word().into()), ("outcome", "failed".into()), ("vm", target.vm_id.clone()), ("why", why)]);
        }
    }
    result.map(|(written, _)| written)
}

// ---- the diff ----------------------------------------------------------------------------

/// One list of rules (`permissions.allow`, `deny`, `ask`, or a project
/// key's list): the entries added, in the newer document's order, and the
/// entries removed, in the older one's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ListDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl ListDiff {
    fn of(old: &[String], new: &[String]) -> ListDiff {
        let (o, n): (BTreeSet<&String>, BTreeSet<&String>) = (old.iter().collect(), new.iter().collect());
        let mut seen = BTreeSet::new();
        let added = new.iter().filter(|r| !o.contains(r) && seen.insert(*r)).cloned().collect();
        let mut seen = BTreeSet::new();
        let removed = old.iter().filter(|r| !n.contains(r) && seen.insert(*r)).cloned().collect();
        ListDiff { added, removed }
    }

    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Keys by name only: added, removed, or holding another value (the
/// values never shown).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NameDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

impl NameDiff {
    fn of<'a>(old: impl IntoIterator<Item = (&'a String, &'a Value)>, new: impl IntoIterator<Item = (&'a String, &'a Value)>, prefix: &str) -> NameDiff {
        let (old, new): (BTreeMap<&String, &Value>, BTreeMap<&String, &Value>) = (old.into_iter().collect(), new.into_iter().collect());
        let name = |k: &String| format!("{prefix}{k}");
        NameDiff {
            added: new.keys().filter(|k| !old.contains_key(*k)).map(|k| name(k)).collect(),
            removed: old.keys().filter(|k| !new.contains_key(*k)).map(|k| name(k)).collect(),
            changed: new.iter().filter(|(k, v)| old.get(*k).is_some_and(|o| o != *v)).map(|(k, _)| name(k)).collect(),
        }
    }

    fn extend(&mut self, other: NameDiff) {
        self.added.extend(other.added);
        self.removed.extend(other.removed);
        self.changed.extend(other.changed);
    }

    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// `permissions.defaultMode` from one value to another (`None`: unset).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModeChange {
    pub from: Option<String>,
    pub to: Option<String>,
}

/// What changed in one scope's settings file between the two captures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeDiff {
    pub scope: SettingsScope,
    /// The file's path in the VM.
    pub path: String,
    pub allow: ListDiff,
    pub deny: ListDiff,
    pub ask: ListDiff,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<ModeChange>,
    /// Every other key that changed, by its path (`model`, `hooks`,
    /// `permissions.additionalDirectories`), never its value.
    pub keys: NameDiff,
    /// The `env` names that changed: their values are never shown (masked).
    pub env: NameDiff,
    /// Why the two could not be compared (a file the helper skipped, a
    /// document that is no JSON object): no entry is listed then.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl ScopeDiff {
    /// Nothing changed (and nothing kept it from being compared).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && self.ask.is_empty() && self.default_mode.is_none() && self.keys.is_empty() && self.env.is_empty() && self.note.is_none()
    }

    fn list(&self, kind: RuleKind) -> &ListDiff {
        match kind {
            RuleKind::Allow => &self.allow,
            RuleKind::Deny => &self.deny,
            RuleKind::Ask => &self.ask,
        }
    }
}

/// What changed in the allowlisted keys of `projects[path]` in the agent's
/// `.claude.json`: the lists (`allowedTools`, the MCP server lists) entry
/// by entry, the rest by name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProjectDiff {
    pub lists: BTreeMap<String, ListDiff>,
    pub keys: NameDiff,
}

/// One VM's last capture against the session's start (`diff.json`'s `vms`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmDiff {
    /// The VM the capture was read in (left out: a capture that names none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm: Option<String>,
    /// `latest.json`'s: the VM the session ran on last; else one it left
    /// (`latest-<VM id>.json`).
    pub current: bool,
    /// When the capture was read in the VM.
    pub at: String,
    /// One per scope, in `SettingsScope::ALL`'s order.
    pub scopes: Vec<ScopeDiff>,
    pub project: ProjectDiff,
}

/// `session show --settings-diff`: the session's VM settings, each VM's
/// last capture against the start, and the last check (`diff.json`,
/// [`DIFF_V`] 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsDiff {
    pub v: u8,
    pub session: String,
    /// The workspace's VM path.
    pub path: String,
    /// When the start capture was read in the VM, and in which (left out:
    /// a capture that names none).
    pub start: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_vm: Option<String>,
    /// Every rule added in any VM's last capture: their union, once per
    /// list and rule, by list then rule (what settings-sync offers).
    pub added: Vec<AddedRule>,
    /// Each VM's last capture against the start: the session's last VM
    /// first, then each VM it left, by id; none before any capture after a
    /// result.
    pub vms: Vec<VmDiff>,
    /// S9 (L9): the last turn's capture that equalled its VM's newest one
    /// (`checked.json`); left out when there is none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked: Option<SettingsChecked>,
}

/// The three rule lists of `permissions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Allow,
    Deny,
    Ask,
}

impl RuleKind {
    pub const ALL: [RuleKind; 3] = [RuleKind::Allow, RuleKind::Deny, RuleKind::Ask];

    /// The key in `permissions`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            RuleKind::Allow => "allow",
            RuleKind::Deny => "deny",
            RuleKind::Ask => "ask",
        }
    }
}

/// A rule the session's VMs added to one of the `permissions` lists: the
/// scopes it was added in, and the VMs whose last capture holds it (a
/// capture that names no VM adds none).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct AddedRule {
    pub kind: RuleKind,
    pub rule: String,
    pub scopes: Vec<SettingsScope>,
    pub vms: Vec<String>,
}

impl AddedRule {
    /// Where it was added, as printed: the scopes, then the VMs (`local;
    /// microvm-a, microvm-b`).
    #[must_use]
    pub fn place(&self) -> String {
        place(&self.scopes, &self.vms)
    }
}

/// `scopes` then `vms` as one place (`local; microvm-a`), the VMs left out
/// when none is known.
fn place(scopes: &[SettingsScope], vms: &[String]) -> String {
    let scopes = scopes.iter().map(|s| s.name()).collect::<Vec<_>>().join(", ");
    if vms.is_empty() {
        scopes
    } else {
        format!("{scopes}; {}", vms.join(", "))
    }
}

impl SettingsDiff {
    /// Every rule added to `allow`, `deny` or `ask` in any scope of any
    /// VM's last capture, once per list, by list then rule.
    #[must_use]
    pub fn added_rules(&self) -> &[AddedRule] {
        &self.added
    }

    /// The diff as it may be shown or written: each rule through
    /// [`shown_rule`]; each key, `env` name and mode, the VMs, the paths, the
    /// times and the notes (the helper's words) scrubbed, control characters
    /// as `?`.
    #[must_use]
    pub fn shown(&self, rules: &Rules) -> SettingsDiff {
        let list = |l: &ListDiff| ListDiff { added: l.added.iter().map(|r| shown_rule(r, rules)).collect(), removed: l.removed.iter().map(|r| shown_rule(r, rules)).collect() };
        let names = |n: &NameDiff| NameDiff { added: n.added.iter().map(|k| shown_name(k)).collect(), removed: n.removed.iter().map(|k| shown_name(k)).collect(), changed: n.changed.iter().map(|k| shown_name(k)).collect() };
        let mode = |m: &Option<String>| m.as_deref().map(shown_name);
        let scope = |s: &ScopeDiff| ScopeDiff {
            path: shown_name(&s.path),
            allow: list(&s.allow),
            deny: list(&s.deny),
            ask: list(&s.ask),
            default_mode: s.default_mode.as_ref().map(|m| ModeChange { from: mode(&m.from), to: mode(&m.to) }),
            keys: names(&s.keys),
            env: names(&s.env),
            note: s.note.as_deref().map(shown_name),
            ..s.clone()
        };
        SettingsDiff {
            path: shown_name(&self.path),
            start: shown_name(&self.start),
            start_vm: self.start_vm.as_deref().map(shown_name),
            added: self.added.iter().map(|a| AddedRule { rule: shown_rule(&a.rule, rules), vms: a.vms.iter().map(|v| shown_name(v)).collect(), ..a.clone() }).collect(),
            vms: self
                .vms
                .iter()
                .map(|v| VmDiff {
                    vm: v.vm.as_deref().map(shown_name),
                    at: shown_name(&v.at),
                    scopes: v.scopes.iter().map(scope).collect(),
                    project: ProjectDiff { lists: v.project.lists.iter().map(|(k, l)| (shown_name(k), list(l))).collect(), keys: names(&v.project.keys) },
                    ..v.clone()
                })
                .collect(),
            checked: self.checked.as_ref().map(|c| SettingsChecked { at: shown_name(&c.at), vm: shown_name(&c.vm) }),
            ..self.clone()
        }
    }
}

/// A rule as `session show --settings-diff` and `settings-sync` print it:
/// never one a tripwire matches (allow rules have been seen carrying
/// credentials), otherwise scrubbed, control characters as `?`.
#[must_use]
pub fn shown_rule(rule: &str, rules: &Rules) -> String {
    let hits: BTreeSet<String> = rules.scan_bytes(rule.as_bytes()).into_iter().map(|(_, id)| id).collect();
    if hits.is_empty() {
        shown_name(rule)
    } else {
        format!("(a rule the tripwire {} matches: not shown)", hits.into_iter().collect::<Vec<_>>().join(", "))
    }
}

/// A key, an `env` name or a value word as shown: scrubbed, control characters as `?`.
fn shown_name(text: &str) -> String {
    scrub(text).chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// Why `wrapper settings-sync` never promotes `rule` into the image's
/// `kind` list, or `None`: not a one-line rule (empty, space at either end
/// — the policy file trims its lines —, a control character), masked in
/// the quarantine (`at_rest`: it carried a secret), a tripwire matches
/// it, it carries a secret shape the scrubber knows, or the repo mode (D8)
/// refuses it in a committed settings file (`broad-allow`: the `Bash(*)`
/// family, bare `Write`, `Edit`, `WebFetch`, any `mcp__` entry;
/// `bypass-permissions`). `defaultMode` is never a rule: no change of it is
/// ever promoted.
#[must_use]
pub fn rule_refusal(kind: RuleKind, rule: &str, rules: &Rules) -> Option<String> {
    if rule.is_empty() || rule.trim() != rule || rule.chars().any(char::is_control) {
        return Some("not a one-line rule".into());
    }
    if rule.starts_with(MASKED) {
        return Some("masked in the quarantine: it carried a secret".into());
    }
    let hits: BTreeSet<String> = rules.scan_bytes(rule.as_bytes()).into_iter().map(|(_, id)| id).collect();
    if !hits.is_empty() {
        return Some(format!("the tripwire {} matches it", hits.into_iter().collect::<Vec<_>>().join(", ")));
    }
    if scrub(rule) != rule {
        return Some("it carries a secret-shaped value".into());
    }
    let doc = serde_json::json!({ "permissions": { kind.name(): [rule] } }).to_string();
    settings_findings_mode("settings.json", doc.as_bytes(), &[], SettingsMode::Repo).into_iter().next().map(|f| format!("{} (the repo mode refuses it, D8)", f.rule))
}

/// One scope's document: an absent file is an empty object; `Err` says why
/// a present one cannot be compared (no text: the helper skipped it, or the
/// quarantine did not keep it).
fn document(file: Option<&SettingsFile>) -> std::result::Result<Map<String, Value>, String> {
    let Some(f) = file.filter(|f| f.present) else {
        return Ok(Map::new());
    };
    let Some(text) = &f.text else {
        return Err(format!("no text ({})", f.skipped.as_deref().unwrap_or("no reason given")));
    };
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err("not a JSON object".into()),
        Err(e) => Err(format!("not JSON (line {})", e.line())),
    }
}

/// The string entries of `permissions.<kind>` (anything else in the list is
/// no rule the CLI reads).
fn rules_of(doc: &Map<String, Value>, kind: RuleKind) -> Vec<String> {
    doc.get("permissions").and_then(|p| p.get(kind.name())).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
}

/// `permissions.defaultMode` as a word (`None`: unset; a non-string value is named as such).
fn default_mode_of(doc: &Map<String, Value>) -> Option<String> {
    doc.get("permissions").and_then(|p| p.get("defaultMode")).map(|m| m.as_str().map_or_else(|| "(not a string)".to_string(), str::to_string))
}

/// What changed in one scope between `old` and `new`.
fn scope_diff(scope: SettingsScope, old: Option<&SettingsFile>, new: Option<&SettingsFile>) -> ScopeDiff {
    let path = new.or(old).map(|f| f.path.clone()).unwrap_or_default();
    let mut d = ScopeDiff { scope, path, allow: ListDiff::default(), deny: ListDiff::default(), ask: ListDiff::default(), default_mode: None, keys: NameDiff::default(), env: NameDiff::default(), note: None };
    let (a, b) = match (document(old), document(new)) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            let notes: Vec<String> = [("start", a.err()), ("latest", b.err())].into_iter().filter_map(|(w, e)| e.map(|e| format!("{w}: {e}"))).collect();
            d.note = Some(notes.join("; "));
            return d;
        }
    };
    d.allow = ListDiff::of(&rules_of(&a, RuleKind::Allow), &rules_of(&b, RuleKind::Allow));
    d.deny = ListDiff::of(&rules_of(&a, RuleKind::Deny), &rules_of(&b, RuleKind::Deny));
    d.ask = ListDiff::of(&rules_of(&a, RuleKind::Ask), &rules_of(&b, RuleKind::Ask));
    let (from, to) = (default_mode_of(&a), default_mode_of(&b));
    if from != to {
        d.default_mode = Some(ModeChange { from, to });
    }
    let others = |m: &Map<String, Value>| -> Vec<(String, Value)> { m.iter().filter(|(k, _)| k.as_str() != "permissions" && k.as_str() != "env").map(|(k, v)| (k.clone(), v.clone())).collect() };
    let (oa, ob) = (others(&a), others(&b));
    d.keys = NameDiff::of(oa.iter().map(|(k, v)| (k, v)), ob.iter().map(|(k, v)| (k, v)), "");
    let empty = Map::new();
    match (a.get("permissions"), b.get("permissions")) {
        (pa, pb) if pa.is_none_or(Value::is_object) && pb.is_none_or(Value::is_object) => {
            let (pa, pb) = (pa.and_then(Value::as_object).unwrap_or(&empty), pb.and_then(Value::as_object).unwrap_or(&empty));
            let rest = |p: &Map<String, Value>| -> Vec<(String, Value)> { p.iter().filter(|(k, _)| !["allow", "deny", "ask", "defaultMode"].contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect() };
            let (ra, rb) = (rest(pa), rest(pb));
            d.keys.extend(NameDiff::of(ra.iter().map(|(k, v)| (k, v)), rb.iter().map(|(k, v)| (k, v)), "permissions."));
        }
        (pa, pb) if pa != pb => d.keys.changed.push("permissions".into()),
        _ => {}
    }
    match (a.get("env"), b.get("env")) {
        (ea, eb) if ea.is_none_or(Value::is_object) && eb.is_none_or(Value::is_object) => {
            let (ea, eb) = (ea.and_then(Value::as_object).unwrap_or(&empty), eb.and_then(Value::as_object).unwrap_or(&empty));
            d.env = NameDiff::of(ea, eb, "");
        }
        (ea, eb) if ea != eb => d.keys.changed.push("env".into()),
        _ => {}
    }
    d
}

/// What changed in the project keys: a key holding a list on either side
/// entry by entry (string entries), any other by name.
fn project_diff(old: &BTreeMap<String, Value>, new: &BTreeMap<String, Value>) -> ProjectDiff {
    let strings = |v: Option<&Value>| -> Vec<String> { v.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default() };
    let listed = |k: &String| old.get(k).is_some_and(Value::is_array) || new.get(k).is_some_and(Value::is_array);
    let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    let mut d = ProjectDiff::default();
    for k in keys.iter().filter(|k| listed(k)) {
        let l = ListDiff::of(&strings(old.get(*k)), &strings(new.get(*k)));
        if !l.is_empty() {
            d.lists.insert((*k).clone(), l);
        }
    }
    d.keys = NameDiff::of(old.iter().filter(|(k, _)| !listed(k)), new.iter().filter(|(k, _)| !listed(k)), "");
    d
}

/// One VM's last capture `last` against the session's `start`.
fn vm_diff(start: &SettingsCapture, last: &KeptCapture, current: bool) -> VmDiff {
    let scopes = SettingsScope::ALL
        .iter()
        .map(|scope| {
            let of = |c: &SettingsCapture| c.files.iter().find(|f| f.scope == *scope).cloned();
            scope_diff(*scope, of(start).as_ref(), of(&last.capture).as_ref())
        })
        .collect();
    VmDiff { vm: last.vm.clone(), current, at: last.capture.at.clone(), scopes, project: project_diff(&start.project, &last.capture.project) }
}

/// The rules `vms` added, once per list and rule (by list, then rule), each
/// with every scope and every VM that added it.
fn union_of(vms: &[VmDiff]) -> Vec<AddedRule> {
    let mut out: BTreeMap<(RuleKind, String), (BTreeSet<SettingsScope>, BTreeSet<String>)> = BTreeMap::new();
    for v in vms {
        for s in &v.scopes {
            for kind in RuleKind::ALL {
                for rule in &s.list(kind).added {
                    let (scopes, by) = out.entry((kind, rule.clone())).or_default();
                    scopes.insert(s.scope);
                    by.extend(v.vm.clone());
                }
            }
        }
    }
    out.into_iter().map(|((kind, rule), (scopes, vms))| AddedRule { kind, rule, scopes: scopes.into_iter().collect(), vms: vms.into_iter().collect() }).collect()
}

/// The diff of `session_id`'s settings: each VM's last capture against the
/// start (the session's last VM first), and the union of the rules they
/// added (pure; the rules and names as they are: [`SettingsDiff::shown`]
/// before anything is printed or written).
#[must_use]
pub fn diff(session_id: &str, captures: &Captures) -> SettingsDiff {
    let start = &captures.start.capture;
    let vms: Vec<VmDiff> = captures.latest.iter().map(|c| vm_diff(start, c, true)).chain(captures.left.iter().map(|c| vm_diff(start, c, false))).collect();
    let path = captures.latest.as_ref().map_or(&start.path, |l| &l.capture.path).clone();
    SettingsDiff { v: DIFF_V, session: session_id.to_string(), path, start: start.at.clone(), start_vm: captures.start.vm.clone(), added: union_of(&vms), vms, checked: captures.checked.clone() }
}

/// A session's captures ([`read_captures`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captures {
    /// `start.json`: the baseline.
    pub start: KeptCapture,
    /// `latest.json`: the last capture of the VM the session ran on last
    /// (`None` before any capture after a result).
    pub latest: Option<KeptCapture>,
    /// `latest-<VM id>.json`: the last capture of each VM the session left,
    /// by VM id, each named its file's VM.
    pub left: Vec<KeptCapture>,
    /// `checked.json` (S9): the last turn's capture that equalled its VM's
    /// newest one.
    pub checked: Option<SettingsChecked>,
}

/// The captures of `session_id` under `paths`: `start.json` (required),
/// `latest.json`, each `latest-<VM id>.json` but one of `latest.json`'s own
/// VM (older: a write cut short left it), and `checked.json` (S9).
pub fn read_captures(paths: &Paths, session_id: &str) -> Result<Captures> {
    let start_path = capture_path(paths, session_id, CapturePhase::Start)?;
    let Some(start) = read_capture(&start_path)? else {
        bail!("no settings captured for session {session_id} ({} is missing): a remote session captures them once its id is known", start_path.display());
    };
    let latest = read_capture(&capture_path(paths, session_id, CapturePhase::Turn)?)?;
    let mut left = Vec::new();
    for vm in left_vms(&settings_dir(paths, session_id))? {
        if latest.as_ref().is_some_and(|l| l.vm.as_deref() == Some(vm.as_str())) {
            continue;
        }
        if let Some(kept) = read_capture(&left_capture_path(paths, session_id, &vm)?)? {
            left.push(KeptCapture { vm: Some(vm), ..kept });
        }
    }
    Ok(Captures { start, latest, left, checked: read_checked(paths, session_id)? })
}

/// The tripwires (`[review].tripwires` with the built-ins) of the bridge at `paths`.
pub(crate) fn tripwires(paths: &Paths) -> Result<Rules> {
    let review = BridgeConfig::load(paths)?.map(|c| c.review).unwrap_or_default();
    load_lists(Some((paths, &review)), None, None, false).map(|(rules, _)| rules).map_err(CliError::Msg)
}

/// The text lines of one list's change, indented `pad`: `+ allow R`, `- deny R`.
fn list_lines(pad: &str, kind: &str, l: &ListDiff) -> Vec<String> {
    l.added.iter().map(|r| format!("{pad}+ {kind} {r}")).chain(l.removed.iter().map(|r| format!("{pad}- {kind} {r}"))).collect()
}

/// The text lines of a change of names: `keys added: a, b`.
fn name_lines(what: &str, n: &NameDiff, masked: bool) -> Vec<String> {
    let shown = |ks: &[String]| ks.iter().map(|k| if masked { format!("{k}=***") } else { k.clone() }).collect::<Vec<_>>().join(", ");
    [("added", &n.added), ("removed", &n.removed), ("changed", &n.changed)].into_iter().filter(|(_, ks)| !ks.is_empty()).map(|(how, ks)| format!("    {what} {how}: {}", shown(ks))).collect()
}

/// `head`'s line and its change lines: `head: no other change` without any.
fn section(out: &mut Vec<String>, head: String, lines: Vec<String>) {
    if lines.is_empty() {
        out.push(format!("{head}: no other change"));
    } else {
        out.push(format!("{head}:"));
        out.extend(lines);
    }
}

/// The text rendering of a shown diff, one line per change: the union of
/// the rules added, then each VM's other changes, per scope.
fn diff_lines(d: &SettingsDiff) -> Vec<String> {
    let start_vm = d.start_vm.as_deref().map(|vm| format!(" in {vm}")).unwrap_or_default();
    let mut out = vec![format!("settings of session {} in its VMs ({}): start {}{start_vm}", d.session, d.path, d.start)];
    if d.vms.is_empty() {
        out.push(match &d.checked {
            // S9 (L9): turns ran and their captures equalled the start's, so nothing was written to compare.
            Some(c) => format!("no change since the start capture (last checked {} in VM {})", c.at, c.vm),
            None => "no capture after a result yet: nothing to compare (a capture follows each code-out)".into(),
        });
        return out;
    }
    if d.added.is_empty() {
        out.push("rules added: none".into());
    } else {
        out.push("rules added, in any VM's last capture:".into());
        out.extend(d.added.iter().map(|a| format!("  + {} {}  ({})", a.kind.name(), a.rule, a.place())));
    }
    for v in &d.vms {
        let which = if v.current { "the session's last" } else { "left" };
        out.push(format!("VM {}, {which} (captured {}):", v.vm.as_deref().unwrap_or("(not recorded)"), v.at));
        for s in &v.scopes {
            let mut lines: Vec<String> = s.note.iter().map(|note| format!("    not compared: {note}")).collect();
            for kind in RuleKind::ALL {
                lines.extend(list_lines("    ", kind.name(), &ListDiff { added: Vec::new(), ..s.list(kind).clone() }));
            }
            if let Some(m) = &s.default_mode {
                lines.push(format!("    defaultMode: {} -> {}", m.from.as_deref().unwrap_or("unset"), m.to.as_deref().unwrap_or("unset")));
            }
            lines.extend(name_lines("keys", &s.keys, false));
            lines.extend(name_lines("env", &s.env, true));
            section(&mut out, format!("  {} ({})", s.scope.name(), if s.path.is_empty() { "no file" } else { s.path.as_str() }), lines);
        }
        let mut lines: Vec<String> = Vec::new();
        for (k, l) in &v.project.lists {
            lines.extend(list_lines("    ", k, l));
        }
        lines.extend(name_lines("keys", &v.project.keys, false));
        section(&mut out, format!("  .claude.json projects[{}]", d.path), lines);
    }
    out
}

/// `ai-env session show UUID --settings-diff [--json]` (T8.7): each VM's
/// last capture against the session's start, the rules they added first
/// (their union), then each VM's other changes per scope, as text or one
/// JSON document; written to `quarantine/UUID/settings/diff.json` (0600).
/// Exit 2 for a non-uuid, 1 without a start capture.
pub fn cmd_settings_diff(uuid: &str, json: bool) -> Result<()> {
    if !is_uuid(uuid) {
        return Err(CliError::Usage(format!("not a session id: {uuid}")));
    }
    let paths = Paths::resolve()?;
    let rules = tripwires(&paths)?;
    let shown = diff(uuid, &read_captures(&paths, uuid)?).shown(&rules);
    let mut text = serde_json::to_string_pretty(&shown).map_err(|e| CliError::Msg(format!("cannot render JSON: {e}")))?;
    let dir = private_settings_dir(&paths, uuid)?;
    let file = dir.join(DIFF_FILE);
    text.push('\n');
    write_atomic_mode(&file, text.as_bytes(), 0o600)?;
    if json {
        outln!("{}", text.trim_end());
    } else {
        for line in diff_lines(&shown) {
            outln!("{line}");
        }
        outln!("written: {}", file.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::AuthToken;
    use crate::bridge::dataplane::{CodeoutBody, DpReply};
    use crate::wire::redact::Secret;
    use crate::wire::workspace::{CodeoutRequest, SeedQuery, SeedReply, SeedState, TranscriptStat, WsRefusal};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    const ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const VM_ROOT: &str = "/Users/mike/w";

    /// A settings file of `scope` holding `text` (absent: `None`).
    fn file(scope: SettingsScope, text: Option<&str>) -> SettingsFile {
        let path = match scope {
            SettingsScope::User => "/Users/mike/.claude/settings.json".to_string(),
            SettingsScope::Project => format!("{VM_ROOT}/.claude/settings.json"),
            SettingsScope::Local => format!("{VM_ROOT}/.claude/settings.local.json"),
        };
        let sha256 = text.map(|t| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(t.as_bytes())));
        SettingsFile { scope, path, present: text.is_some(), size: text.map_or(0, |t| t.len() as u64), sha256, text: text.map(str::to_string), skipped: None }
    }

    /// A capture of the three scopes at `at`.
    fn capture_of(user: Option<&str>, project: Option<&str>, local: Option<&str>, at: &str) -> SettingsCapture {
        SettingsCapture { path: VM_ROOT.into(), files: vec![file(SettingsScope::User, user), file(SettingsScope::Project, project), file(SettingsScope::Local, local)], project: BTreeMap::new(), at: at.into() }
    }

    /// `get_settings` answers from a queue (the last answer repeats); every
    /// other route is unreached. Counts the requests and the tokens forgotten.
    struct Vm {
        answers: Mutex<Vec<DpReply<SettingsCapture>>>,
        gets: AtomicUsize,
        forgotten: AtomicUsize,
        hold: bool,
    }

    impl Vm {
        fn answering(answers: Vec<DpReply<SettingsCapture>>) -> Vm {
            Vm { answers: Mutex::new(answers), gets: AtomicUsize::new(0), forgotten: AtomicUsize::new(0), hold: false }
        }
    }

    fn unreached<T>() -> std::result::Result<T, BridgeError> {
        Err(BridgeError::Endpoint("unreached".into()))
    }

    impl TokenSource for Vm {
        async fn token(&self, port: u16) -> std::result::Result<AuthToken, BridgeError> {
            assert_eq!(port, APP_PORT, "the settings route is the app port's");
            Ok(AuthToken { headers: BTreeMap::new(), port, expires_at_unix: u64::MAX })
        }

        fn forget(&self, _port: u16) {
            self.forgotten.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl DataPlane for Vm {
        async fn seed_state(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> std::result::Result<DpReply<SeedState>, BridgeError> {
            unreached()
        }

        async fn put_seed(&self, _: &AgentTarget, _: &AuthToken, _: &SeedQuery, _: &Path, _: u64) -> std::result::Result<DpReply<SeedReply>, BridgeError> {
            unreached()
        }

        async fn post_codeout(&self, _: &AgentTarget, _: &AuthToken, _: &CodeoutRequest, _: &Path, _: u64) -> std::result::Result<DpReply<CodeoutBody>, BridgeError> {
            unreached()
        }

        async fn transcript_stat(&self, _: &AgentTarget, _: &AuthToken, _: &str) -> std::result::Result<DpReply<TranscriptStat>, BridgeError> {
            unreached()
        }

        async fn get_settings(&self, _: &AgentTarget, _: &AuthToken, path: &str) -> std::result::Result<DpReply<SettingsCapture>, BridgeError> {
            assert_eq!(path, VM_ROOT, "the workspace's VM path is asked for");
            self.gets.fetch_add(1, Ordering::SeqCst);
            if self.hold {
                std::future::pending::<()>().await;
            }
            let mut answers = self.answers.lock().unwrap();
            Ok(if answers.len() > 1 { answers.remove(0) } else { answers[0].clone() })
        }
    }

    fn target() -> AgentTarget {
        target_on("microvm-1")
    }

    fn target_on(vm: &str) -> AgentTarget {
        AgentTarget { vm_id: vm.into(), endpoint: "x".into(), session_token: Secret::new("t".into()), vpc: true, shell: false }
    }

    /// `start` and `latest` as captures kept with no VM named (W8's first
    /// build's, or planted by hand).
    fn two(start: &SettingsCapture, latest: &SettingsCapture) -> Captures {
        Captures { start: KeptCapture { vm: None, capture: start.clone() }, latest: Some(KeptCapture { vm: None, capture: latest.clone() }), left: Vec::new(), checked: None }
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn audit_rows(paths: &Paths) -> Vec<Value> {
        std::fs::read_to_string(paths.audit()).unwrap_or_default().lines().map(|l| serde_json::from_str(l).unwrap()).filter(|r: &Value| r["event"] == "settings_capture").collect()
    }

    /// The file names in the session's settings directory, sorted.
    fn names(paths: &Paths) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(settings_dir(paths, ID)).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        out.sort();
        out
    }

    #[test]
    fn captures_go_to_the_sessions_quarantine() {
        let paths = Paths::from_root_and_env("/b".into(), None);
        assert_eq!(capture_path(&paths, ID, CapturePhase::Start).unwrap(), PathBuf::from(format!("/b/quarantine/{ID}/settings/start.json")));
        assert_eq!(capture_path(&paths, ID, CapturePhase::Turn).unwrap(), PathBuf::from(format!("/b/quarantine/{ID}/settings/latest.json")));
        assert_eq!(left_capture_path(&paths, ID, "microvm-0a1b").unwrap(), PathBuf::from(format!("/b/quarantine/{ID}/settings/latest-microvm-0a1b.json")));
        for bad in ["../../etc", "", "not-a-uuid"] {
            assert!(matches!(capture_path(&paths, bad, CapturePhase::Start), Err(BridgeError::Config(_))), "{bad:?}");
            assert!(matches!(left_capture_path(&paths, bad, "microvm-1"), Err(BridgeError::Config(_))), "{bad:?}");
        }
        // A VM id names a file, never a path: no `/`, no `.`, no pending row's id.
        let long = "v".repeat(129);
        for bad in ["../x", "a/b", "", "-v", "pending-0199a1b2", "micro.vm", long.as_str()] {
            assert!(matches!(left_capture_path(&paths, ID, bad), Err(BridgeError::Config(_))), "{bad:?}");
        }
        assert_eq!([left_vm("latest-microvm-1.json"), left_vm("latest.json"), left_vm("latest-.json"), left_vm("latest-a.b.json"), left_vm(".latest-microvm-1.json.7.tmp")], [Some("microvm-1"), None, None, None, None]);
        assert_eq!((DIFF_FILE, DIFF_V, CHECKED_FILE, CapturePhase::Start.word(), CapturePhase::Turn.word()), ("diff.json", 3, "checked.json", "start", "turn"));
        assert_eq!(checked_path(&paths, ID).unwrap(), PathBuf::from(format!("/b/quarantine/{ID}/settings/checked.json")));
        assert!(matches!(checked_path(&paths, "../../etc"), Err(BridgeError::Config(_))));
    }

    /// The session's start capture is written once (0600 in 0700
    /// directories, audited) and never asked again: a resumed session keeps
    /// its first baseline. A turn's is written only when a digest or a
    /// project key changed since the newest capture on disk.
    #[tokio::test]
    async fn the_start_capture_is_kept_and_a_turns_is_written_when_the_settings_changed() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let start = capture_of(Some("{}"), None, None, "2026-10-12T10:00:00Z");
        let vm = Vm::answering(vec![DpReply::ok(200, start.clone())]);
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap(), "written");
        let file = capture_path(&paths, ID, CapturePhase::Start).unwrap();
        assert_eq!(read_capture(&file).unwrap(), Some(KeptCapture { vm: Some("microvm-1".into()), capture: start.clone() }), "kept with the VM it was read in");
        assert_eq!((mode_of(&file), mode_of(&paths.quarantine()), mode_of(&paths.quarantine_session(ID)), mode_of(file.parent().unwrap())), (0o600, 0o700, 0o700, 0o700));
        assert!(!capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap(), "kept");
        assert_eq!(vm.gets.load(Ordering::SeqCst), 1, "a kept baseline asks nothing");
        // The same settings after a turn: nothing written.
        let same = SettingsCapture { at: "2026-10-12T10:05:00Z".into(), ..start.clone() };
        let vm = Vm::answering(vec![DpReply::ok(200, same), DpReply::ok(200, capture_of(Some("{}"), None, Some("{\"permissions\":{\"allow\":[\"Bash(git status)\"]}}"), "2026-10-12T10:06:00Z"))]);
        assert!(!capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap());
        let latest = capture_path(&paths, ID, CapturePhase::Turn).unwrap();
        assert!(!latest.exists(), "unchanged settings write no latest.json");
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap(), "a rule approved");
        assert_eq!(mode_of(&latest), 0o600);
        assert!(!capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap(), "the same again: compared with latest.json");
        // A project key changing is a change too.
        let mut keyed = read_capture(&latest).unwrap().unwrap().capture;
        keyed.project.insert("hasTrustDialogAccepted".into(), Value::Bool(true));
        let vm = Vm::answering(vec![DpReply::ok(200, keyed.clone())]);
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap());
        // A latest.json that cannot be read counts as different: written again, never compared with the start.
        std::fs::write(&latest, "not json").unwrap();
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap());
        assert_eq!(read_capture(&latest).unwrap().map(|k| k.capture), Some(keyed));
        assert_eq!(names(&paths), ["latest.json", "start.json"], "one VM: nothing kept for another");
        let rows = audit_rows(&paths);
        assert_eq!(rows.len(), 4, "four written: {rows:?}");
        assert!(rows.iter().all(|r| r["session_id"] == ID && r["detail"]["outcome"] == "written" && r["detail"]["vm"] == "microvm-1"), "{rows:?}");
        assert_eq!(rows[0]["detail"]["phase"], "start");
    }

    /// S9 (L9): turns whose captures equal the start's write no
    /// `latest.json`, so the diff had nothing to compare and said none was
    /// taken. Each such turn now leaves `checked.json` (`{at, vm}`, 0600 in
    /// the 0700 directory, no audit row: nothing was captured), and the diff
    /// says the settings are unchanged since the start, last checked then
    /// and there (`diff.json` v3 carries it). A turn that changes them writes
    /// `latest.json` and takes the check away; a capture that names no VM
    /// leaves none.
    #[tokio::test]
    async fn a_turn_capture_equal_to_the_start_leaves_a_check_and_the_diff_says_no_change() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let start = capture_of(Some("{}"), None, None, "2026-10-12T10:00:00Z");
        let same = |at: &str| SettingsCapture { at: at.into(), ..start.clone() };
        let vm = Vm::answering(vec![DpReply::ok(200, start.clone()), DpReply::ok(200, same("2026-10-12T10:05:00Z")), DpReply::ok(200, same("2026-10-12T10:09:00Z"))]);
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap());
        assert!(!capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap(), "nothing captured");
        let checked = checked_path(&paths, ID).unwrap();
        assert_eq!(names(&paths), ["checked.json", "start.json"]);
        assert_eq!((mode_of(&checked), mode_of(checked.parent().unwrap())), (0o600, 0o700));
        let text = std::fs::read_to_string(&checked).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), serde_json::json!({"at": "2026-10-12T10:05:00Z", "vm": "microvm-1"}));
        assert!(!capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap());
        assert_eq!(read_checked(&paths, ID).unwrap(), Some(SettingsChecked { at: "2026-10-12T10:09:00Z".into(), vm: "microvm-1".into() }), "the last check");
        assert_eq!(audit_rows(&paths).len(), 1, "the start's row only: a check captures nothing");
        assert_eq!(left_vms(&settings_dir(&paths, ID)).unwrap(), Vec::<String>::new(), "checked.json is no VM's capture");
        let captures = read_captures(&paths, ID).unwrap();
        assert!(captures.latest.is_none() && captures.left.is_empty(), "{captures:?}");
        let d = diff(ID, &captures).shown(&Rules::defaults());
        assert_eq!((d.v, d.vms.len(), d.checked.clone()), (3, 0, Some(SettingsChecked { at: "2026-10-12T10:09:00Z".into(), vm: "microvm-1".into() })));
        let lines = diff_lines(&d);
        assert_eq!(lines, [format!("settings of session {ID} in its VMs ({VM_ROOT}): start 2026-10-12T10:00:00Z in microvm-1"), "no change since the start capture (last checked 2026-10-12T10:09:00Z in VM microvm-1)".to_string()]);
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!((json["v"].as_u64(), json["checked"]["at"].as_str(), json["checked"]["vm"].as_str()), (Some(3), Some("2026-10-12T10:09:00Z"), Some("microvm-1")), "{json}");
        // A turn that changes the settings: latest.json written, the check gone, the diff compares.
        let vm = Vm::answering(vec![DpReply::ok(200, capture_of(Some("{}"), None, Some("{\"permissions\":{\"allow\":[\"Read\"]}}"), "2026-10-12T10:15:00Z"))]);
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap());
        assert_eq!(names(&paths), ["latest.json", "start.json"]);
        let d = diff(ID, &read_captures(&paths, ID).unwrap());
        assert!(d.checked.is_none() && d.vms.len() == 1, "{d:?}");
        assert!(serde_json::to_value(&d).unwrap().get("checked").is_none(), "left out when there is none");
        // A check that does not read as one is ignored (logged), never fatal to the diff.
        std::fs::write(&checked, "not json").unwrap();
        assert_eq!(read_checked(&paths, ID).unwrap(), None);
        assert!(read_captures(&paths, ID).unwrap().checked.is_none());
        // A capture that names no VM (by hand) leaves no check.
        std::fs::remove_file(&checked).unwrap();
        note_checked(&paths, ID, &KeptCapture { vm: None, capture: start });
        assert!(!checked.exists());
    }

    /// A refused token is minted again once, then the refusal is the
    /// capture's error; a refusal, an answer for another path or a bad
    /// capture writes nothing and is audited as failed, never a value in it.
    #[tokio::test]
    async fn a_capture_that_fails_writes_nothing_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let denied = DpReply::<SettingsCapture>::status(401);
        let vm = Vm::answering(vec![denied]);
        let e = capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap_err();
        assert!(matches!(e, BridgeError::TokenRejected { port: APP_PORT, .. }), "{e}");
        assert_eq!((vm.gets.load(Ordering::SeqCst), vm.forgotten.load(Ordering::SeqCst)), (2, 1), "re-minted once");
        let busy = DpReply::<SettingsCapture>::refused(WsRefusal::new("busy", "another op holds it"));
        let vm = Vm::answering(vec![busy]);
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.is_err());
        let elsewhere = SettingsCapture { path: "/Users/mike/other".into(), ..capture_of(None, None, None, "2026-10-12T10:00:00Z") };
        let vm = Vm::answering(vec![DpReply::ok(200, elsewhere)]);
        let e = capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap_err();
        assert!(e.to_string().contains("another workspace path"), "{e}");
        let mut bad = capture_of(Some("{}"), None, None, "2026-10-12T10:00:00Z");
        bad.project.insert("mcpServers".into(), Value::Null);
        let vm = Vm::answering(vec![DpReply::ok(200, bad)]);
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap_err().to_string().contains("not allowlisted"));
        assert!(!paths.quarantine().exists(), "nothing written");
        let rows = audit_rows(&paths);
        assert_eq!(rows.len(), 4, "{rows:?}");
        assert!(rows.iter().all(|r| r["detail"]["outcome"] == "failed" && r["detail"]["why"].as_str().is_some_and(|w| !w.is_empty())), "{rows:?}");
        assert!(matches!(capture(&vm, &vm, &target(), &paths, "x/../y", VM_ROOT, CapturePhase::Turn).await, Err(BridgeError::Config(_))));
    }

    /// The quarantine is never written through a link: a symlinked session
    /// directory or start file refuses, its target untouched.
    #[tokio::test]
    async fn a_symlinked_quarantine_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().join("bridge"), None);
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(paths.quarantine()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, paths.quarantine_session(ID)).unwrap();
        let vm = Vm::answering(vec![DpReply::ok(200, capture_of(None, None, None, "2026-10-12T10:00:00Z"))]);
        let e = capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap_err();
        assert!(e.to_string().contains("is a symlink"), "{e}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0, "nothing through the link");
        std::fs::remove_file(paths.quarantine_session(ID)).unwrap();
        std::fs::create_dir_all(settings_dir(&paths, ID)).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("start.json"), capture_path(&paths, ID, CapturePhase::Start).unwrap()).unwrap();
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap_err().to_string().contains("is a symlink"));
        assert!(!elsewhere.join("start.json").exists());
    }

    /// A capture that does not answer within its bound is given up and
    /// audited ([`CAPTURE_WAIT`] in the wrapper; 50 ms here).
    #[tokio::test]
    async fn a_capture_that_never_answers_is_given_up_at_its_bound() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let vm = Vm { hold: true, ..Vm::answering(vec![DpReply::status(204)]) };
        let t = std::time::Instant::now();
        let e = capture_within(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn, Duration::from_millis(50)).await.unwrap_err();
        assert!(e.to_string().contains("did not answer within 50 ms") && t.elapsed() < Duration::from_secs(5), "{e}");
        let rows = audit_rows(&paths);
        assert!(rows.len() == 1 && rows[0]["detail"]["outcome"] == "failed", "{rows:?}");
        assert!(CAPTURE_WAIT >= Duration::from_secs(10), "the helper's own budget fits");
    }

    /// The semantic diff per scope: allow, deny and ask entries added and
    /// removed, `defaultMode`'s change, every other key by name, `env` by
    /// name only; a scope the helper skipped is noted, never guessed; the
    /// project keys' lists entry by entry. Nothing of a value reaches the
    /// shown diff but the rules, and a rule a tripwire matches is masked.
    #[test]
    fn the_diff_names_rules_modes_keys_and_env_names_never_values() {
        let secret = format!("{}{}", "sk-ant-api03-", "Q".repeat(24));
        let start_local = r#"{"permissions":{"allow":["Read","Bash(ls)"],"deny":["Bash(rm:*)"],"defaultMode":"default"},"env":{"KEEP":"same","OLD":"gone"},"model":"x"}"#;
        let latest_local = format!(r#"{{"permissions":{{"allow":["Read","Bash(git status)","Bash(curl -H {secret})"],"ask":["WebFetch(domain:example.com)"],"defaultMode":"acceptEdits","additionalDirectories":["/tmp"]}},"env":{{"KEEP":"same","NEW":"value-never-shown"}},"model":"y","hooks":{{}}}}"#);
        let start = capture_of(Some("{}"), None, Some(start_local), "2026-10-12T10:00:00Z");
        let mut latest = capture_of(Some("{}"), Some("{\"permissions\":{\"allow\":[\"Edit\"]}}"), Some(&latest_local), "2026-10-12T10:09:00Z");
        latest.project.insert("allowedTools".into(), serde_json::json!(["Bash(npm test)"]));
        latest.project.insert("hasTrustDialogAccepted".into(), Value::Bool(true));
        let d = diff(ID, &two(&start, &latest));
        assert_eq!((d.v, d.vms.len(), d.vms[0].current, d.vms[0].vm.as_deref(), d.start_vm.as_deref(), d.checked.as_ref()), (3, 1, true, None, None, None), "one VM, not recorded, never checked");
        let local = &d.vms[0].scopes[2];
        assert_eq!(local.allow, ListDiff { added: vec!["Bash(git status)".into(), format!("Bash(curl -H {secret})")], removed: vec!["Bash(ls)".into()] });
        assert_eq!(local.deny, ListDiff { added: vec![], removed: vec!["Bash(rm:*)".into()] });
        assert_eq!(local.ask.added, ["WebFetch(domain:example.com)"]);
        assert_eq!(local.default_mode, Some(ModeChange { from: Some("default".into()), to: Some("acceptEdits".into()) }));
        assert_eq!(local.keys, NameDiff { added: vec!["hooks".into(), "permissions.additionalDirectories".into()], removed: vec![], changed: vec!["model".into()] });
        assert_eq!(local.env, NameDiff { added: vec!["NEW".into()], removed: vec!["OLD".into()], changed: vec![] });
        assert_eq!(d.vms[0].scopes[1].allow.added, ["Edit"], "a file absent at the start: its entries are added");
        assert!(d.vms[0].scopes[0].is_empty());
        assert_eq!(d.vms[0].project.lists["allowedTools"].added, ["Bash(npm test)"]);
        assert_eq!(d.vms[0].project.keys.added, ["hasTrustDialogAccepted"]);
        let rules_added = d.added_rules();
        let added: Vec<(RuleKind, &str)> = rules_added.iter().map(|a| (a.kind, a.rule.as_str())).collect();
        assert_eq!(added.len(), 4, "{added:?}");
        assert_eq!((added[1], added[2], added[3]), ((RuleKind::Allow, "Bash(git status)"), (RuleKind::Allow, "Edit"), (RuleKind::Ask, "WebFetch(domain:example.com)")), "by list, then rule");
        assert!(rules_added.iter().all(|a| a.vms.is_empty()), "no VM named: none listed");
        let shown = d.shown(&Rules::defaults());
        let json = serde_json::to_string(&shown).unwrap();
        assert!(!json.contains(&secret) && !json.contains("value-never-shown") && !json.contains("\"same\""), "{json}");
        assert!(shown.vms[0].scopes[2].allow.added.iter().any(|r| r == "(a rule the tripwire anthropic-key matches: not shown)"), "{:?}", shown.vms[0].scopes[2].allow);
        assert!(shown.added.iter().any(|a| a.rule == "(a rule the tripwire anthropic-key matches: not shown)"), "{:?}", shown.added);
        let text = diff_lines(&shown).join("\n");
        for want in [
            "rules added, in any VM's last capture:",
            "  + allow Bash(git status)  (local)",
            "  + allow Edit  (project)",
            "  + ask WebFetch(domain:example.com)  (local)",
            "VM (not recorded), the session's last (captured 2026-10-12T10:09:00Z):",
            "  local (/Users/mike/w/.claude/settings.local.json):",
            "    - allow Bash(ls)",
            "    - deny Bash(rm:*)",
            "    defaultMode: default -> acceptEdits",
            "    keys added: hooks, permissions.additionalDirectories",
            "    env added: NEW=***",
            "    env removed: OLD=***",
            "  user (/Users/mike/.claude/settings.json): no other change",
            "  project (/Users/mike/w/.claude/settings.json): no other change",
            "    + allowedTools Bash(npm test)",
        ] {
            assert!(text.lines().any(|l| l == want), "{want}: {text}");
        }
        assert!(!text.lines().any(|l| l.starts_with("    + allow ") || l.starts_with("    + ask ")), "an added rule is the union's, not the VM's: {text}");
        // A skipped file is noted, nothing guessed from it.
        let mut skipped = latest.clone();
        skipped.files[2].text = None;
        skipped.files[2].skipped = Some("300000 bytes (at most 262144)".into());
        let s = &diff(ID, &two(&start, &skipped)).vms[0].scopes[2];
        assert!(s.allow.is_empty() && s.note.as_deref() == Some("latest: no text (300000 bytes (at most 262144))"), "{s:?}");
        // Before any capture after a result: nothing to compare.
        let only = Captures { latest: None, ..two(&start, &latest) };
        let d = diff(ID, &only);
        assert!(d.vms.is_empty() && d.added.is_empty(), "{d:?}");
        assert_eq!(diff_lines(&d.shown(&Rules::defaults()))[1], "no capture after a result yet: nothing to compare (a capture follows each code-out)");
    }

    /// What settings-sync never promotes: the repo mode's set (D8), a rule a
    /// tripwire matches or one with a secret shape, and anything that is no
    /// one-line rule; a narrow allow, deny or ask passes.
    #[test]
    fn rule_refusal_follows_the_repo_mode_and_the_tripwires() {
        let rules = Rules::defaults();
        for (kind, rule) in [(RuleKind::Allow, "Bash(git status)"), (RuleKind::Allow, "Read"), (RuleKind::Allow, "WebFetch(domain:docs.rs)"), (RuleKind::Deny, "Write"), (RuleKind::Ask, "Bash(*)"), (RuleKind::Deny, "mcp__github")] {
            assert_eq!(rule_refusal(kind, rule, &rules), None, "{kind:?} {rule}");
        }
        let token = format!("{}{}", "AKIA", "Q".repeat(16));
        for (kind, rule, why) in [
            (RuleKind::Allow, "Bash(*)", "broad-allow"),
            (RuleKind::Allow, "Bash", "broad-allow"),
            (RuleKind::Allow, "Write", "broad-allow"),
            (RuleKind::Allow, "Edit(*)", "broad-allow"),
            (RuleKind::Allow, "mcp__github__create_issue", "broad-allow"),
            (RuleKind::Allow, "bypassPermissions", "bypass-permissions"),
            (RuleKind::Allow, " Read", "not a one-line rule"),
            (RuleKind::Allow, "Bash(a\nb)", "not a one-line rule"),
            (RuleKind::Allow, "", "not a one-line rule"),
            (RuleKind::Allow, &format!("Bash(aws --key {token})"), "aws-access-key-id"),
            (RuleKind::Allow, "Bash(curl -H authorization=abc)", "secret-shaped"),
            (RuleKind::Allow, "(masked: anthropic-key, sha256:0123456789abcdef)", "masked in the quarantine"),
        ] {
            let got = rule_refusal(kind, rule, &rules).unwrap_or_else(|| panic!("{rule:?} passed"));
            assert!(got.contains(why), "{rule:?}: {got}");
            assert!(!got.contains(&token), "never the value: {got}");
        }
    }

    /// Custody: the quarantine keeps no secret of the VM's settings. Every
    /// `env` value is kept as a digest (a changed one still shows as
    /// changed), a rule or project entry a tripwire matches is masked (two
    /// such stay apart, and settings-sync never promotes one), a text that
    /// is no JSON is not kept; the VM file's size and digest stay.
    #[tokio::test]
    async fn the_quarantine_keeps_no_secret_of_the_vms_settings() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let (key, key2) = (format!("{}{}", "AKIA", "Q".repeat(16)), format!("{}{}", "AKIA", "R".repeat(16)));
        let token = format!("{}{}", "sk-ant-api03-", "Q".repeat(24));
        // An env value of no secret shape is a secret all the same (the plan masks every one).
        let plain = "plain-value-never-kept";
        let start_local = format!(r#"{{"env":{{"AWS_ACCESS_KEY_ID":"{key}","PLAIN":"{plain}"}},"permissions":{{"allow":["Read"]}}}}"#);
        let latest_local = format!("{{\n  \"env\": {{\"AWS_ACCESS_KEY_ID\": \"{key2}\", \"PLAIN\": \"{plain}\"}},\n  \"permissions\": {{\"allow\": [\"Read\", \"Bash(git status)\", \"Bash(curl -H {token})\"]}}\n}}\n");
        let not_json = format!("{{\"env\": {{\"K\": \"{key}\"}},}}");
        let start = capture_of(Some("{}"), None, Some(&start_local), "2026-10-12T10:00:00Z");
        let mut latest = capture_of(Some(&not_json), None, Some(&latest_local), "2026-10-12T10:09:00Z");
        latest.project.insert("allowedTools".into(), serde_json::json!([format!("Bash(curl -H {token})"), "Bash(npm test)"]));
        let vm = Vm::answering(vec![DpReply::ok(200, start), DpReply::ok(200, latest.clone())]);
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap());
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap());
        for phase in [CapturePhase::Start, CapturePhase::Turn] {
            let bytes = std::fs::read_to_string(capture_path(&paths, ID, phase).unwrap()).unwrap();
            for secret in [key.as_str(), key2.as_str(), token.as_str(), plain] {
                assert!(!bytes.contains(secret), "{phase:?}: {bytes}");
            }
        }
        let captures = read_captures(&paths, ID).unwrap();
        let kept = &captures.latest.as_ref().expect("latest.json").capture;
        assert_eq!((kept.files[2].size, &kept.files[2].sha256), (latest.files[2].size, &latest.files[2].sha256), "the VM file's size and digest");
        assert_eq!((kept.files[0].text.as_deref(), kept.files[0].skipped.as_deref()), (None, Some("not JSON (line 1)")), "a text that is no JSON is not kept");
        let d = diff(ID, &captures);
        let local = &d.vms[0].scopes[2];
        assert_eq!(local.env, NameDiff { added: vec![], removed: vec![], changed: vec!["AWS_ACCESS_KEY_ID".into()] }, "a changed value, never its value");
        assert_eq!(local.allow.added.len(), 2, "{:?}", local.allow);
        assert_eq!(local.allow.added[0], "Bash(git status)");
        let masked_rule = &local.allow.added[1];
        assert!(masked_rule.starts_with("(masked: anthropic-key, sha256:") && masked_rule.len() == "(masked: anthropic-key, sha256:)".len() + 16, "{masked_rule}");
        assert!(rule_refusal(RuleKind::Allow, masked_rule, &Rules::defaults()).is_some_and(|why| why.contains("masked in the quarantine")));
        let tools = d.vms[0].project.lists["allowedTools"].added.clone();
        assert!(tools.len() == 2 && tools.contains(&"Bash(npm test)".to_string()) && tools.iter().any(|t| t.starts_with("(masked: anthropic-key")), "{tools:?}");
        assert!(d.vms[0].scopes[0].note.as_deref().is_some_and(|n| n.contains("latest: no text (not JSON (line 1))")), "{:?}", d.vms[0].scopes[0]);
        // Two secrets a tripwire matches stay apart; the same one masks the same.
        let rules = Rules::defaults();
        assert_ne!(masked(&format!("Bash(x {key})"), &rules), masked(&format!("Bash(x {key2})"), &rules));
        assert_eq!(masked(&format!("Bash(x {key})"), &rules), masked(&format!("Bash(x {key})"), &rules));
        assert_eq!(masked("Bash(git status)", &rules), "Bash(git status)");
    }

    /// The helper's words reach the operator's terminal: a capture whose
    /// time is no RFC 3339 UTC, or a file whose path or skip reason holds a
    /// control character or whose digest is no hex, is refused (nothing
    /// written, audited as failed); a diff of such captures planted on disk
    /// is shown with every control character as `?`, one line per change.
    #[tokio::test]
    async fn the_helpers_words_never_carry_a_control_character_to_the_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let ok = capture_of(Some("{}"), None, Some("{\"permissions\":{\"allow\":[\"Read\"]}}"), "2026-10-12T10:00:00Z");
        let mut forged_at = ok.clone();
        forged_at.at = "2026-10-12T10:00:00Z\nai-env: forged line from the VM".into();
        let mut escaped_path = ok.clone();
        escaped_path.files[2].path = format!("{VM_ROOT}/.claude/\u{1b}[2Ksettings.local.json");
        let mut skipped = ok.clone();
        skipped.files[1] = SettingsFile { present: true, skipped: Some("a symlink\u{1b}[1A".into()), ..file(SettingsScope::Project, None) };
        let mut digest = ok.clone();
        digest.files[0].sha256 = Some("not hex".into());
        for bad in [forged_at.clone(), escaped_path.clone(), skipped.clone(), digest] {
            let vm = Vm::answering(vec![DpReply::ok(200, bad)]);
            let e = capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap_err();
            assert!(e.to_string().contains("not RFC 3339 UTC") || e.to_string().contains("path, skip reason or digest is malformed"), "{e}");
        }
        assert!(!paths.quarantine().exists(), "nothing written");
        assert_eq!(audit_rows(&paths).len(), 4);
        let latest = SettingsCapture { files: vec![escaped_path.files[0].clone(), skipped.files[1].clone(), escaped_path.files[2].clone()], ..forged_at };
        // The VM a hand-edited latest.json names: shown by the same rule.
        let captures = Captures { latest: Some(KeptCapture { vm: Some("microvm-1\u{1b}[2J".into()), capture: latest }), ..two(&ok, &ok) };
        let lines = diff_lines(&diff(ID, &captures).shown(&Rules::defaults()));
        assert_eq!(lines.len(), 8, "a head, the rules' line, the VM's, a line per scope and the project keys', the note its own: {lines:#?}");
        assert!(lines.iter().all(|l| !l.chars().any(char::is_control)), "{lines:#?}");
        assert_eq!((lines[1].as_str(), lines[2].as_str()), ("rules added: none", "VM microvm-1?[2J, the session's last (captured 2026-10-12T10:00:00Z?ai-env: forged line from the VM):"), "{lines:#?}");
        assert_eq!((lines[5].as_str(), lines[6].as_str()), ("    not compared: latest: no text (a symlink?[1A)", "  local (/Users/mike/w/.claude/?[2Ksettings.local.json): no other change"), "{lines:#?}");
    }

    /// W8-R3's P2 sequence (T8.7 with T8.5): a session starts on one VM and
    /// a turn there approves a rule; the chat is reopened on a second VM
    /// (the first gone), whose start is the kept baseline and whose turn
    /// lacks the rule. The first VM's last capture is kept beside the
    /// second's (`latest-<VM id>.json`), so the rule stays in the diff, the
    /// first VM named, and among settings-sync's candidates. A VM that comes
    /// back takes `latest.json` again (its older capture goes): its last
    /// capture, without the rule now, is what counts.
    #[tokio::test]
    async fn a_rule_approved_on_a_vm_the_session_left_stays_in_the_diff() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let rule = "Bash(git status)";
        let approved = format!(r#"{{"permissions":{{"allow":["{rule}"]}}}}"#);
        let (a, b) = (target_on("microvm-a1"), target_on("microvm-b2"));
        let seeded = capture_of(Some("{}"), None, None, "2026-10-12T10:00:00Z");
        let vm = Vm::answering(vec![DpReply::ok(200, seeded.clone()), DpReply::ok(200, capture_of(Some("{}"), None, Some(&approved), "2026-10-12T10:05:00Z"))]);
        assert!(capture(&vm, &vm, &a, &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap(), "the start, on the first VM");
        assert!(capture(&vm, &vm, &a, &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap(), "the turn approving the rule");
        // The second VM: seeded from the Mac, so no rule.
        let vm = Vm::answering(vec![DpReply::ok(200, SettingsCapture { at: "2026-10-12T11:00:00Z".into(), ..seeded.clone() })]);
        assert!(!capture(&vm, &vm, &b, &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap(), "the baseline kept: nothing asked");
        assert_eq!(vm.gets.load(Ordering::SeqCst), 0);
        assert!(capture(&vm, &vm, &b, &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap(), "another VM's latest.json: its capture written, whatever it holds");
        assert_eq!(names(&paths), ["latest-microvm-a1.json", "latest.json", "start.json"]);
        for name in ["latest-microvm-a1.json", "latest.json"] {
            assert_eq!(mode_of(&settings_dir(&paths, ID).join(name)), 0o600, "{name}");
        }
        let captures = read_captures(&paths, ID).unwrap();
        assert_eq!((captures.start.vm.as_deref(), captures.latest.as_ref().and_then(|l| l.vm.as_deref())), (Some("microvm-a1"), Some("microvm-b2")));
        assert_eq!(captures.left.iter().map(|l| l.vm.as_deref()).collect::<Vec<_>>(), [Some("microvm-a1")]);
        let d = diff(ID, &captures);
        assert_eq!(d.added_rules(), [AddedRule { kind: RuleKind::Allow, rule: rule.into(), scopes: vec![SettingsScope::Local], vms: vec!["microvm-a1".into()] }], "the rule the first VM approved: settings-sync's candidate");
        assert_eq!(d.vms.iter().map(|v| (v.vm.as_deref(), v.current)).collect::<Vec<_>>(), [(Some("microvm-b2"), true), (Some("microvm-a1"), false)]);
        let text = diff_lines(&d.shown(&Rules::defaults()));
        for want in ["  + allow Bash(git status)  (local; microvm-a1)", "VM microvm-b2, the session's last (captured 2026-10-12T11:00:00Z):", "VM microvm-a1, left (captured 2026-10-12T10:05:00Z):"] {
            assert!(text.iter().any(|l| l == want), "{want}: {text:#?}");
        }
        let json: Value = serde_json::to_value(d.shown(&Rules::defaults())).unwrap();
        assert_eq!((json["v"].as_u64(), json["start_vm"].as_str(), json["added"][0]["vms"][0].as_str(), json["vms"][1]["vm"].as_str()), (Some(3), Some("microvm-a1"), Some("microvm-a1"), Some("microvm-a1")), "{json}");
        assert!(json.get("checked").is_none(), "no turn equalled its VM's newest capture yet: {json}");
        // Unchanged on the second VM: nothing written, nothing moved; the check noted (S9), gone again at the next write.
        assert!(!capture(&vm, &vm, &b, &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap());
        assert_eq!(read_checked(&paths, ID).unwrap(), Some(SettingsChecked { at: "2026-10-12T11:00:00Z".into(), vm: "microvm-b2".into() }));
        // The first VM back (a pin), the rule gone there: it takes latest.json, the second's kept, its own older one gone.
        let vm = Vm::answering(vec![DpReply::ok(200, SettingsCapture { at: "2026-10-12T12:00:00Z".into(), ..seeded })]);
        assert!(capture(&vm, &vm, &a, &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap());
        assert_eq!(names(&paths), ["latest-microvm-b2.json", "latest.json", "start.json"]);
        let d = diff(ID, &read_captures(&paths, ID).unwrap());
        assert!(d.added_rules().is_empty(), "each VM's last capture lacks it: {:?}", d.added_rules());
        assert_eq!(d.vms.iter().map(|v| (v.vm.as_deref(), v.current)).collect::<Vec<_>>(), [(Some("microvm-a1"), true), (Some("microvm-b2"), false)]);
        let rows = audit_rows(&paths);
        assert_eq!(rows.iter().map(|r| (r["detail"]["phase"].as_str().unwrap(), r["detail"]["vm"].as_str().unwrap())).collect::<Vec<_>>(), [("start", "microvm-a1"), ("turn", "microvm-a1"), ("turn", "microvm-b2"), ("turn", "microvm-a1")]);
    }

    /// What names a kept capture's file is checked: a `latest.json` naming a
    /// VM that is no VM id (edited by hand) is replaced, never renamed into a
    /// path; files whose names hold no VM id are not read; a `latest-<VM
    /// id>.json` of `latest.json`'s own VM (left by a write cut short) is not
    /// a VM the session left.
    #[tokio::test]
    async fn a_kept_capture_is_named_by_a_vm_id_never_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let start = capture_of(Some("{}"), None, None, "2026-10-12T10:00:00Z");
        let vm = Vm::answering(vec![DpReply::ok(200, start.clone()), DpReply::ok(200, capture_of(Some("{}"), None, Some("{}"), "2026-10-12T10:05:00Z"))]);
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Start).await.unwrap());
        let latest = capture_path(&paths, ID, CapturePhase::Turn).unwrap();
        let forged = KeptCapture { vm: Some("../../../escaped".into()), capture: SettingsCapture { at: "2026-10-12T10:01:00Z".into(), ..start.clone() } };
        std::fs::write(&latest, serde_json::to_string(&forged).unwrap()).unwrap();
        assert!(capture(&vm, &vm, &target(), &paths, ID, VM_ROOT, CapturePhase::Turn).await.unwrap(), "replaced");
        assert_eq!(names(&paths), ["latest.json", "start.json"], "nothing renamed");
        assert!(!dir.path().join("escaped").exists() && !paths.quarantine().join("escaped").exists());
        assert_eq!(read_capture(&latest).unwrap().and_then(|k| k.vm).as_deref(), Some("microvm-1"));
        for name in ["latest-.json", "latest-pending-0199.json", "latest-micro.vm.json", "latest-microvm-1.json"] {
            std::fs::write(settings_dir(&paths, ID).join(name), serde_json::to_string(&KeptCapture { vm: None, capture: start.clone() }).unwrap()).unwrap();
        }
        let captures = read_captures(&paths, ID).unwrap();
        assert!(captures.left.is_empty(), "no VM id, or latest.json's own VM: {:?}", captures.left);
    }
}
