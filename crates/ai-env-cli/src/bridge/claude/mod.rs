//! S11 part A: the Claude Code versions this Mac knows and the VMs follow
//! (plan §A). Each version's record (`state/claude/<v>.toml`, written only
//! through [`Record::update`] under `state/claude/records.lock`), its phase
//! (seen, signed, admitted, failed, staged, stale), P0's plan of the claudes a
//! session's spawn may name ([`plan_for`]), the census word `claude_src`
//! ([`claude_src_of`]) and D5's automatic admission ([`maybe_auto_admit`]).
//! The release's trust (`release`), the admission (`admit`), the stager
//! (`stage`) and gc (`gc`) are A2's; the fetch into a VM (`fetch`) and the
//! doctor and `wrapper status` rows (`rows`) are A3's, as are P0's plan, the
//! census word, D5's trigger and `ai-env claude status` here. Whatever fails
//! fails closed: a chat runs the image's claude.
pub mod admit;
pub mod fetch;
pub mod gc;
pub mod release;
pub mod rows;
pub mod stage;

use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::errors::BridgeError;
use crate::wire::workspace::ClaudeRef;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// D5 (LD-11): an automatic admission of a version is tried again only this long after the last one ended.
pub const ADMIT_COOLDOWN: Duration = Duration::from_secs(15 * 60);
/// D5 as Mike amended it on 24 Oct (a Docker run failed once under load on a busy Mac, then passed three times):
/// the automatic admission runs a version whose Docker tests failed (`failed(docker)`) again while fewer than this
/// many Docker failures are recorded for it ([`Record::docker_failures`]), each try [`ADMIT_COOLDOWN`] after the
/// last one ended; every other failed step stays final for it, and `--redo` admits again whatever the count.
pub const ADMIT_DOCKER_TRIES: u32 = 3;
/// The admission's Docker run (`make claude-admit-docker`) is ended past this.
pub const ADMIT_MAKE_BOUND: Duration = Duration::from_secs(30 * 60);
/// `ai-env claude gc` keeps this many newest staged versions' objects (beside the bundle's and every live window's).
pub const CLAUDE_GC_KEEP_STAGED: usize = 3;
/// This Mac keeps this many newest admitted binaries (LD-31).
pub const CLAUDE_GC_KEEP_LOCAL: usize = 2;
/// The stager VM's `max_duration_s`.
pub const STAGER_MAX_DURATION_S: u32 = 900;
/// The record's schema version (`Record.v`).
pub const RECORD_V: u32 = 1;

/// How long [`Record::update`] waits for `state/claude/records.lock`.
const RECORDS_LOCK_WAIT: Duration = Duration::from_secs(2);

/// What this Mac knows of one Claude Code version. Strict: an unknown key, or `v` other than 1, is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Record {
    /// 1.
    pub v: u32,
    /// `N.N.N`.
    pub version: String,
    /// When this Mac first wrote it (RFC 3339 UTC).
    pub created: String,
    pub signature: Option<SignatureRow>,
    pub download: Option<DownloadRow>,
    pub admission: Option<AdmissionRow>,
    pub staging: Option<StagingRow>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SignatureRow {
    /// `ok` or `failed`.
    pub outcome: String,
    /// `failed`: `manifest`, `version` or one of `status_ok`'s words (a failed fetch or a missing gpgv records
    /// nothing).
    pub why: Option<String>,
    pub manifest_sha256: Option<String>,
    /// `ok`: VALIDSIG's primary fingerprint.
    pub signer: Option<String>,
    /// `ok`: the linux-arm64 pin the signed manifest names.
    pub linux_sha256: Option<String>,
    pub linux_size: Option<u64>,
    pub build_date: Option<String>,
    /// Recorded only.
    pub darwin_sha256: Option<String>,
    pub at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DownloadRow {
    /// `state/claude/<v>/claude`, checked against the signature's pin.
    pub sha256: String,
    pub size: u64,
    pub at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdmissionRow {
    /// `admitted` or `failed`.
    pub outcome: String,
    /// `failed`: `download`, `markers`, `docker`, `version` (a VM's 422) or `stage` (two bad stages in a row).
    pub step: Option<String>,
    /// `ok`, or `missing:<name>`.
    pub markers: Option<String>,
    /// The Docker run's last line.
    pub docker: Option<String>,
    /// `failed(docker)`: the first failing test's name (cargo's `test NAME ... FAILED`, else libtest's closing
    /// `failures:` list), when the log names one that is an id (at most 200 characters, none the scrubber changes).
    pub docker_test: Option<String>,
    /// How many Docker runs of this version failed since it was last admitted, the last one included (`--auto` or
    /// by hand; [`ADMIT_DOCKER_TRIES`]); 0, and absent from the file, once admitted. A record from before the count
    /// reads 0 ([`Record::docker_failures`] counts its own failure).
    #[serde(skip_serializing_if = "is_zero")]
    pub docker_failures: u32,
    /// `failed(docker)`: the make log's excerpt (`admit::docker_excerpt`): each failing test's line and each
    /// thread's first panic, else the log's last lines; scrubbed, at most 300 characters a line, 12 lines and 4 KiB.
    /// The next run writes the log anew; the record keeps what failed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub docker_excerpt: Vec<String>,
    /// The local image's id the tests ran on.
    pub docker_image: Option<String>,
    /// The ai-env version that ran it.
    pub ai_env: String,
    /// The wrapper's `--auto` child ran it.
    pub auto: bool,
    pub at: String,
}

/// A count left out of the record while it is 0, so a record that never failed at Docker (an admitted one too) holds
/// no key an older ai-env, whose records refuse unknown keys, would not read.
fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StagingRow {
    /// `staged`, `stale` or `absent`.
    pub state: String,
    /// `v1/_claude/mac/<v>/<sha>`.
    pub s3_key: String,
    pub s3_version_id: Option<String>,
    /// The stager VM of the last stage.
    pub stager_vm: Option<String>,
    /// VMs that answered 422 `checksum_mismatch` since the last good stage.
    pub bad_reports: u32,
    /// Stages in a row a VM then refused: at 2 the admission becomes `failed(stage)`.
    pub bad_stages: u32,
    pub at: String,
}

/// A version's phase, as every view says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// No record (the version is the bundle's, a window's or a census row's), or one with no signature yet.
    Seen,
    /// Signed, not admitted (an admission that stopped before its Docker run).
    Signed,
    /// `admission.outcome = admitted`, `staging` none or `absent`.
    Admitted,
    /// `signature.outcome = failed` (`signature`) or `admission.outcome = failed` (its step).
    Failed(String),
    /// `staging.state = staged`.
    Staged,
    /// `staging.state = stale`: a VM refused the object; it was deleted; a restage is due.
    Stale,
}

impl Phase {
    /// `seen`, `signed`, `admitted`, `failed(<step>)`, `staged`, `stale`.
    #[must_use]
    pub fn word(&self) -> String {
        match self {
            Phase::Seen => "seen".into(),
            Phase::Signed => "signed".into(),
            Phase::Admitted => "admitted".into(),
            Phase::Failed(step) => format!("failed({step})"),
            Phase::Staged => "staged".into(),
            Phase::Stale => "stale".into(),
        }
    }
}

/// A version every record path takes: `N.N.N` (`wire::pin::is_version`), so a path only joins.
fn checked_version(version: &str) -> Result<(), BridgeError> {
    if crate::wire::pin::is_version(version) {
        Ok(())
    } else {
        Err(BridgeError::Config(format!("not a claude version (N.N.N): {version:?}")))
    }
}

/// Parse one record's TOML: strict (an unknown key, `v` other than [`RECORD_V`], or another version's record is
/// refused); the error names `path` and the parser's message (never its snippet of the file).
fn parse_record(path: &std::path::Path, version: &str, text: &str) -> Result<Record, BridgeError> {
    let record: Record = toml::from_str(text).map_err(|e| BridgeError::Config(format!("{}: {}", path.display(), e.message())))?;
    if record.v != RECORD_V {
        return Err(BridgeError::Config(format!("{}: a claude record of schema {} (this ai-env reads {RECORD_V})", path.display(), record.v)));
    }
    if record.version != version {
        return Err(BridgeError::Config(format!("{}: names claude {:?}, not {version}", path.display(), record.version)));
    }
    Ok(record)
}

/// `state/claude/records.lock`, polled for at most [`RECORDS_LOCK_WAIT`].
fn lock_records(paths: &Paths) -> Result<crate::bridge::vm::lock::FlockGuard, BridgeError> {
    let path = paths.claude_records_lock();
    let start = std::time::Instant::now();
    loop {
        if let Some(guard) = crate::bridge::vm::lock::try_lock_exclusive(&path)? {
            return Ok(guard);
        }
        if start.elapsed() >= RECORDS_LOCK_WAIT {
            return Err(BridgeError::Busy(format!("{} still held after {} s", path.display(), RECORDS_LOCK_WAIT.as_secs())));
        }
        std::thread::sleep(crate::bridge::vm::lock::POLL);
    }
}

impl Record {
    /// `state/claude/<v>.toml`: `Ok(None)` when absent.
    pub fn load(paths: &Paths, version: &str) -> Result<Option<Record>, BridgeError> {
        checked_version(version)?;
        let path = paths.claude_record(version);
        let Some(text) = crate::bridge::registry::read_regular_file(&path)? else {
            return Ok(None);
        };
        parse_record(&path, version, &text).map(Some)
    }

    /// Read, changed by `f`, written, under `claude_records_lock` (2 s; a new record when absent).
    pub fn update(paths: &Paths, version: &str, f: impl FnOnce(&mut Record)) -> Result<Record, BridgeError> {
        checked_version(version)?;
        crate::bridge::registry::ensure_private_dir(&paths.claude_dir())?;
        let _held = lock_records(paths)?;
        let mut record = Record::load(paths, version)?.unwrap_or_else(|| Record { v: RECORD_V, version: version.to_string(), created: crate::bridge::registry::now_rfc3339(), ..Record::default() });
        f(&mut record);
        // The record stays this version's, of this schema, whatever `f` did.
        record.v = RECORD_V;
        record.version = version.to_string();
        let text = toml::to_string_pretty(&record).map_err(|e| BridgeError::Config(format!("claude {version}: cannot serialise the record: {e}")))?;
        crate::bridge::infra::write_atomic_mode(&paths.claude_record(version), text.as_bytes(), 0o600)?;
        Ok(record)
    }

    /// `claude forget`'s delete (A3's review): the record removed under `claude_records_lock`, so a verdict written
    /// through [`Record::update_existing`] meanwhile never writes a forgotten version back. Whether there was one.
    pub fn remove(paths: &Paths, version: &str) -> Result<bool, BridgeError> {
        checked_version(version)?;
        let path = paths.claude_record(version);
        if std::fs::symlink_metadata(&path).is_err() {
            return Ok(false);
        }
        let _held = lock_records(paths)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(BridgeError::Config(format!("cannot remove {}: {e}", path.display()))),
        }
    }

    /// [`Record::update`] of a record that exists, never a new one: `f` sees it under `claude_records_lock` and says
    /// whether it changed it; nothing is written when it is absent (forgotten meanwhile: it stays forgotten) or
    /// unchanged. `Ok(None)` when absent.
    pub fn update_existing(paths: &Paths, version: &str, f: impl FnOnce(&mut Record) -> bool) -> Result<Option<Record>, BridgeError> {
        if Record::load(paths, version)?.is_none() {
            return Ok(None);
        }
        let _held = lock_records(paths)?;
        let Some(mut record) = Record::load(paths, version)? else {
            return Ok(None);
        };
        if !f(&mut record) {
            return Ok(Some(record));
        }
        record.v = RECORD_V;
        record.version = version.to_string();
        let text = toml::to_string_pretty(&record).map_err(|e| BridgeError::Config(format!("claude {version}: cannot serialise the record: {e}")))?;
        crate::bridge::infra::write_atomic_mode(&paths.claude_record(version), text.as_bytes(), 0o600)?;
        Ok(Some(record))
    }

    /// The phase: a failed signature or admission before any staging state, so a failed version is never
    /// nameable, whatever S3 holds.
    #[must_use]
    pub fn phase(&self) -> Phase {
        if let Some(sig) = &self.signature {
            if sig.outcome == "failed" {
                return Phase::Failed("signature".into());
            }
        }
        if let Some(adm) = &self.admission {
            match adm.outcome.as_str() {
                "failed" => return Phase::Failed(adm.step.clone().unwrap_or_else(|| "admission".into())),
                "admitted" => {
                    return match self.staging.as_ref().map(|s| s.state.as_str()) {
                        Some("staged") => Phase::Staged,
                        Some("stale") => Phase::Stale,
                        _ => Phase::Admitted,
                    };
                }
                _ => {}
            }
        }
        match &self.signature {
            Some(sig) if sig.outcome == "ok" => Phase::Signed,
            _ => Phase::Seen,
        }
    }

    /// A spawn may name it (A.1's rule): admitted and its object present, `phase() == Staged`.
    #[must_use]
    pub fn nameable(&self) -> bool {
        self.phase() == Phase::Staged
    }

    /// Its ref, once signed: the version and the linux-arm64 pin's sha256.
    #[must_use]
    pub fn claude_ref(&self) -> Option<ClaudeRef> {
        let sig = self.signature.as_ref().filter(|s| s.outcome == "ok")?;
        let sha256 = sig.linux_sha256.clone()?;
        Some(ClaudeRef { version: self.version.clone(), sha256 })
    }

    /// Its Docker failures since it was last admitted (`admission.docker_failures`); a `failed(docker)` record
    /// written before the count (which reads 0) counts its own failure, 1.
    #[must_use]
    pub fn docker_failures(&self) -> u32 {
        let n = self.admission.as_ref().map_or(0, |a| a.docker_failures);
        if self.failed_at_docker() {
            n.max(1)
        } else {
            n
        }
    }

    /// `phase() == failed(docker)`: the Docker tests' make failed (its time bound included); a stop by a signal or
    /// an image changed under the run records nothing.
    fn failed_at_docker(&self) -> bool {
        matches!(self.phase(), Phase::Failed(step) if step == "docker")
    }

    /// D5's retry (Mike's rule, 24 Oct): the automatic admission runs it again, as for a missing or `signed` record,
    /// once its cooldown is over ([`Record::auto_retry_from`]): its admission failed at `docker` with fewer than
    /// [`ADMIT_DOCKER_TRIES`] Docker failures recorded. Every other failed step stays final until `--redo`: the
    /// signature, the download's size or sha256 (`failed(download)`), the markers, and a VM's `version` or two bad
    /// `stage`s.
    #[must_use]
    pub fn auto_retry(&self) -> bool {
        self.failed_at_docker() && self.docker_failures() < ADMIT_DOCKER_TRIES
    }

    /// When [`Record::auto_retry`] holds: the Unix time its retry may start, [`ADMIT_COOLDOWN`] after the failure's
    /// `at` (a failure by hand writes no `finished_at` into the lock, so its own time counts too); `None` when it does
    /// not hold or that time does not read (then the lock's `finished_at` alone spaces the tries). S12 (V2): the
    /// trigger's and `--auto`'s own check; the views use [`Record::retry_from`], which also counts the lock's
    /// `finished_at`.
    #[must_use]
    pub fn auto_retry_from(&self) -> Option<u64> {
        let at = self.admission.as_ref().filter(|_| self.auto_retry()).and_then(|a| crate::wire::time::parse_rfc3339_utc(&a.at))?;
        Some(at.saturating_add(ADMIT_COOLDOWN.as_secs()))
    }

    /// S12 (V2): when [`Record::auto_retry`] holds, the Unix time the views name for its retry: [`ADMIT_COOLDOWN`]
    /// after the later of the failure's `at` and the version lock's `finished_at` (`clock.finished`), or after
    /// whichever of the two reads. That is the first second D5's trigger lets the retry start, both its gates past
    /// (plans/s12-contracts.md §V2.4 rules 1 and 2: `auto_retry_from() <= now`, and `cooldown_lock`'s `now - F` of at
    /// least the cooldown). `None` when it does not hold, or neither reads. The trigger keeps
    /// [`Record::auto_retry_from`] and the lock's own read (`prewarm::cooldown_lock`).
    #[must_use]
    pub fn retry_from(&self, clock: &RetryClock) -> Option<u64> {
        if !self.auto_retry() {
            return None;
        }
        let failed = self.admission.as_ref().and_then(|a| crate::wire::time::parse_rfc3339_utc(&a.at));
        let finished = clock.finished.get(&self.version).copied();
        // The later of the two that read; with one, that one.
        let from = failed.into_iter().chain(finished).max()?;
        Some(from.saturating_add(ADMIT_COOLDOWN.as_secs()))
    }
}

/// A Docker failure's count as every view says it: `attempt N of ADMIT_DOCKER_TRIES` (past them, by `--redo`:
/// `attempt N`).
#[must_use]
pub fn attempt_words(n: u32) -> String {
    if n <= ADMIT_DOCKER_TRIES {
        format!("attempt {n} of {ADMIT_DOCKER_TRIES}")
    } else {
        format!("attempt {n}")
    }
}

/// S12 (V2): what the views judge an automatic retry's time by (plain data, so the views stay pure): now, and the
/// `finished_at=` of `state/claude/<v>.lock` for each record whose Docker failure the automatic admission runs
/// again ([`Record::auto_retry`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetryClock {
    /// Unix seconds.
    pub now: u64,
    /// [`lock_finished_at`] by version, for those records only; a lock that does not read is absent.
    pub finished: std::collections::BTreeMap<String, u64>,
}

impl RetryClock {
    /// [`crate::wire::time::unix_now`], and the lock of each of `records` that [`Record::auto_retry`] holds for:
    /// file reads only, no lock taken, nothing written, never a wait. Now is read first, so a lock's end written
    /// meanwhile is later than it and the view says ` from` (plans/s12-contracts.md §V2.4 rules 10 and 12: one clock
    /// a command run, one open and at most 4 KiB per such record, no other lock opened, LD-V9).
    #[must_use]
    pub fn read(paths: &Paths, records: &[Record]) -> RetryClock {
        let now = crate::wire::time::unix_now();
        let finished = records.iter().filter(|r| r.auto_retry()).filter_map(|r| lock_finished_at(paths, &r.version).map(|f| (r.version.clone(), f))).collect();
        RetryClock { now, finished }
    }

    /// `now`, and no lock read: the tests, and [`rows::rows_claude`] (S11's text).
    #[must_use]
    pub fn at(now: u64) -> RetryClock {
        RetryClock { now, finished: std::collections::BTreeMap::new() }
    }
}

/// S12 (V2): `state/claude/<v>.lock`'s `finished_at=` as the views read it
/// ([`crate::bridge::remote::prewarm::finished_at_in`]): opened read-only with `O_NOFOLLOW`, `O_NONBLOCK` and
/// `O_CLOEXEC`, a regular file only, at most [`crate::bridge::remote::prewarm::FINISHED_AT_READ_MAX`] bytes as
/// UTF-8. Never created, written or locked: an admission holding the flock is read past, never waited for. `None`
/// for a version that is not `N.N.N`, a missing, symlinked, non-regular or unreadable file, text that is not
/// UTF-8, or no such line. It opens the file itself, `registry::read_regular_file`'s flags with the bound (LD-V11):
/// every failure is `None`, never an error or a log line, so a view never fails over a lock (§V2.4 rule 13).
#[must_use]
pub(crate) fn lock_finished_at(paths: &Paths, version: &str) -> Option<u64> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if !crate::wire::pin::is_version(version) {
        return None;
    }
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(paths.claude_lock(version)).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(crate::bridge::remote::prewarm::FINISHED_AT_READ_MAX).read_to_string(&mut text).ok()?;
    crate::bridge::remote::prewarm::finished_at_in(&text)
}

/// When an automatic retry of `r` may start, as the views say it: ` from <T>` (RFC 3339 UTC) while
/// [`Record::retry_from`] is after `clock.now`, ` is due now` once it is not (at that second too: the trigger's first,
/// LD-V5), empty when it does not read (S12, V2: plans/s12-contracts.md §V2.4 rule 3, the words §12.1's Q-V4).
fn retry_when(r: &Record, clock: &RetryClock) -> String {
    match r.retry_from(clock) {
        Some(t) if t > clock.now => format!(" from {}", crate::wire::time::rfc3339_utc(t)),
        Some(_) => " is due now".into(),
        None => String::new(),
    }
}

/// `N.N.N` as numbers, for ordering versions part by part.
#[must_use]
pub fn version_key(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.').map(|p| p.parse::<u64>().ok());
    let key = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(key)
}

/// S12 (V1): the `N.N.N` ones of `versions` (`wire::pin::is_version`), newest first (numbers part by part,
/// [`version_key`]; equal numbers by text, so the order is total and a repeat sits next to its twin), each once:
/// how the views list versions (gc's kept line and its JSON `windows`, `status`' `windows`: LD-V1, LD-V2).
#[must_use]
pub fn newest_first_once<'a>(versions: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<&str> = versions.into_iter().filter(|v| crate::wire::pin::is_version(v)).collect();
    out.sort_by_key(|v| std::cmp::Reverse((version_key(v), *v)));
    out.dedup();
    out.into_iter().map(str::to_string).collect()
}

/// Every record that reads (others logged and skipped), by version, oldest first.
pub fn load_all(paths: &Paths) -> Vec<Record> {
    let Ok(dir) = std::fs::read_dir(paths.claude_dir()) else {
        return Vec::new();
    };
    let mut records: Vec<Record> = dir
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".toml")).filter(|v| crate::wire::pin::is_version(v)).map(str::to_string))
        .filter_map(|v| match Record::load(paths, &v) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(version = %v, error = %e, "a claude record that does not read is skipped");
                None
            }
        })
        .collect();
    records.sort_by_key(|r| version_key(&r.version));
    records
}

/// P0's claude for one session (A.4, L2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaudePlan {
    /// V, when argv[1]'s bundle names an `N.N.N` one.
    pub ext: Option<String>,
    /// V's phase word (`seen` without a record); `None` without V.
    pub phase: Option<String>,
    /// Why V is not first in `prefs`: `no_ext`, `seen`, `failed`, `not_staged`; `None` when it is.
    pub why_not: Option<&'static str>,
    /// L2: V when nameable, then the other nameable versions newest first, at most `CLAUDE_REFS_MAX` in all.
    pub prefs: Vec<ClaudeRef>,
    /// The signed sizes of `prefs`' binaries, by sha256 (a fetch's `size`).
    pub sizes: std::collections::BTreeMap<String, u64>,
}

/// From the records (local reads only, no AWS, a few ms): V (`ext`, when `N.N.N`), its phase word (`seen` without a
/// record), why V does not lead (`no_ext`, `seen` for a version not admitted yet, `failed`, `not_staged` for an
/// admitted one whose object is not present), and L2's preferences: V when nameable, then every other nameable
/// version newest first (versions compared as numbers part by part), at most `CLAUDE_REFS_MAX` in all, a sha256
/// named once; their signed sizes by sha256.
#[must_use]
pub fn plan_for(paths: &Paths, ext: Option<&str>) -> ClaudePlan {
    plan_of(&load_all(paths), ext)
}

/// [`plan_for`] on `records` (pure).
#[must_use]
pub fn plan_of(records: &[Record], ext: Option<&str>) -> ClaudePlan {
    let ext = ext.filter(|v| crate::wire::pin::is_version(v));
    let mine = ext.and_then(|v| records.iter().find(|r| r.version == v));
    let phase = ext.map(|_| mine.map_or_else(|| Phase::Seen.word(), |r| r.phase().word()));
    let why_not = match (ext, mine.map(Record::phase)) {
        (None, _) => Some("no_ext"),
        (Some(_), None | Some(Phase::Seen | Phase::Signed)) => Some("seen"),
        (Some(_), Some(Phase::Failed(_))) => Some("failed"),
        (Some(_), Some(Phase::Admitted | Phase::Stale)) => Some("not_staged"),
        (Some(_), Some(Phase::Staged)) => None,
    };
    let mut newest: Vec<&Record> = records.iter().filter(|r| r.nameable() && Some(r.version.as_str()) != ext).collect();
    newest.sort_by_key(|r| std::cmp::Reverse(version_key(&r.version)));
    let lead = mine.filter(|r| r.nameable());
    let mut plan = ClaudePlan { ext: ext.map(str::to_string), phase, why_not, ..ClaudePlan::default() };
    for r in lead.into_iter().chain(newest) {
        if plan.prefs.len() >= crate::wire::workspace::CLAUDE_REFS_MAX {
            break;
        }
        let Some(cref) = r.claude_ref().filter(|c| c.check().is_ok() && !plan.prefs.iter().any(|p| p.sha256 == c.sha256)) else { continue };
        if let Some(size) = r.signature.as_ref().and_then(|s| s.linux_size).filter(|s| (1..=crate::wire::s3::CLAUDE_MAX).contains(s)) {
            plan.sizes.insert(cref.sha256.clone(), size);
        }
        plan.prefs.push(cref);
    }
    plan
}

/// What P4 asked of a generation's VM, for the link's `claude_src` (`PipelineEnd.claude`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaudeAsk {
    pub plan: ClaudePlan,
    /// The VM's recorded caps name `claude_stage_v1`.
    pub cap: bool,
    /// The refs `spawn.claude` carried (`plan.prefs` minus the VM row's `claude_bad`; empty without the cap).
    pub sent: Vec<ClaudeRef>,
    /// This generation follows a `ClaudeRetry` of this chat.
    pub after_start_failed: bool,
}

/// The census word (pure, §5.1): what ran (`Spawned`'s version and sha256) against what was asked and the image's
/// version (`hello_ok`'s, else the VM row's). `cached`: V ran from the VM's cache; `image`: the image's claude ran
/// and it is V; `older(<why>)`: another cached version ran (a newer one too, for an older window); `image(<why>)`:
/// the image's claude ran and it is not V. `<why>` says why V did not run, the first that holds: `no_ext`,
/// `start_failed` (this chat's cached claude died before its init), V's own (`seen`, `failed`, `not_staged`),
/// `no_cap`, `bad` (V nameable but in the VM row's `claude_bad`), `not_cached` (named, the cache lacked it).
#[must_use]
pub fn claude_src_of(ask: &ClaudeAsk, image: Option<&str>, ran_version: Option<&str>, ran_sha256: Option<&str>) -> String {
    let v = ask.plan.ext.as_deref();
    let v_ref = v.and_then(|v| ask.plan.prefs.iter().find(|r| r.version == v));
    match ran_sha256 {
        Some(sha) if v_ref.is_some_and(|r| r.sha256 == sha) || (v.is_some() && ran_version == v) => return "cached".into(),
        None if v.is_some() && ran_version.or(image) == v => return "image".into(),
        _ => {}
    }
    let why = match v {
        None => "no_ext",
        Some(_) if ask.after_start_failed => "start_failed",
        Some(_) => match (ask.plan.why_not, v_ref) {
            (Some(why), _) => why,
            (None, _) if !ask.cap => "no_cap",
            (None, Some(r)) if !ask.sent.contains(r) => "bad",
            (None, _) => "not_cached",
        },
    };
    match ran_sha256 {
        Some(_) => format!("older({why})"),
        None => format!("image({why})"),
    }
}

/// V admitted and its object not present (`admitted` or `stale`): an `auto` prewarm does not skip (§4.6). A record
/// that does not read, or no record, is no such version.
#[must_use]
pub fn needs_staging(paths: &Paths, version: &str) -> bool {
    matches!(Record::load(paths, version), Ok(Some(r)) if matches!(r.phase(), Phase::Admitted | Phase::Stale))
}

/// D5 (§4.7): when V's record is missing or `signed`, or (Mike's rule, 24 Oct) `failed(docker)` with tries left
/// ([`Record::auto_retry`]), the cooldown is over and its lock is free, `ai-env claude admit <v> --auto` started
/// detached. File reads, at most one double fork; never a wait. In order: `[claude].auto_admit` (`off`); under the
/// fake API, the three admission knobs (`lab`); V's record (`has_record` for any phase past `signed` but a Docker
/// failure with tries left, or a record that does not read; `recent` while that failure is younger than
/// [`ADMIT_COOLDOWN`]); `state/claude/<v>.lock` taken without waiting (`admitting` while held) and its
/// `finished_at=` line (`recent` within [`ADMIT_COOLDOWN`]); the sibling `ai-env` next to the wrapper
/// (`no_sibling`); then the prewarm's double fork (`spawn_failed`), the lock's open file on fd 3, stdio on
/// `/dev/null`, the prewarm's environment.
pub fn maybe_auto_admit(paths: &Paths, cfg: &BridgeConfig, version: &str) -> AutoAdmit {
    let sibling = || match crate::bridge::sibling::find_sibling("ai-env") {
        crate::bridge::sibling::Sibling::Next(p) => Some(p),
        _ => None,
    };
    auto_admit_with(paths, cfg, &crate::bridge::lab::vm_knobs(), version, &sibling)
}

/// [`maybe_auto_admit`] with the knobs and the sibling given (tests).
fn auto_admit_with(paths: &Paths, cfg: &BridgeConfig, knobs: &crate::bridge::lab::VmKnobs, version: &str, sibling: &dyn Fn() -> Option<std::path::PathBuf>) -> AutoAdmit {
    if !cfg.claude.auto_admit {
        return AutoAdmit::Skipped("off");
    }
    let set = |k: Result<Option<std::path::PathBuf>, String>| matches!(k, Ok(Some(_)));
    if knobs.fake_api.is_some() && !(set(knobs.release_curl()) && set(knobs.gpgv()) && set(knobs.admit_make())) {
        return AutoAdmit::Skipped("lab");
    }
    match Record::load(paths, version) {
        Ok(None) => {}
        Ok(Some(r)) if matches!(r.phase(), Phase::Seen | Phase::Signed) => {}
        // A Docker failure with tries left: again, once its own cooldown is over too (a run by hand ends without a
        // `finished_at`). The child reads the record again under the lock.
        Ok(Some(r)) if r.auto_retry() => {
            if r.auto_retry_from().is_some_and(|from| crate::wire::time::unix_now() < from) {
                return AutoAdmit::Skipped("recent");
            }
        }
        _ => return AutoAdmit::Skipped("has_record"),
    }
    let lock = match crate::bridge::remote::prewarm::cooldown_lock(&paths.claude_lock(version), ADMIT_COOLDOWN, "admitting") {
        Ok(lock) => lock,
        Err(why) => return AutoAdmit::Skipped(why),
    };
    let Some(program) = sibling() else {
        return AutoAdmit::Skipped("no_sibling");
    };
    let args: [&std::ffi::OsStr; 4] = ["claude".as_ref(), "admit".as_ref(), version.as_ref(), "--auto".as_ref()];
    match crate::bridge::remote::prewarm::spawn_detached(&program, &args, &lock) {
        Ok(pid) => AutoAdmit::Spawned(pid),
        Err(e) => {
            tracing::warn!(version, "claude admit --auto: {e}");
            AutoAdmit::Skipped("spawn_failed")
        }
    }
}

/// What `maybe_auto_admit` did (logged; no census part, no audit row: LD-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoAdmit {
    Spawned(u32),
    Skipped(&'static str),
}

/// The phase words (`Phase::word`, as `ClaudePlan.phase` holds them) a remote P0 hands to [`maybe_auto_admit`]:
/// `seen`, `signed` and `failed(docker)`, whose tries and cooldown the trigger judges itself.
#[must_use]
pub fn auto_admit_phase(word: &str) -> bool {
    matches!(word, "seen" | "signed" | "failed(docker)")
}

/// The installed Cursor bundle's Claude Code version (`doctor::pick_bundle` of `~/.cursor/extensions`, as
/// `infra pin --bundle-version` reads it), `N.N.N` only.
#[must_use]
pub fn installed_bundle() -> Option<String> {
    let dir = std::path::PathBuf::from(std::env::var_os("HOME")?).join(".cursor").join("extensions");
    crate::bridge::doctor::pick_bundle(&crate::bridge::doctor::installed_extension_names(&dir)).map(|(v, _)| v).filter(|v| crate::wire::pin::is_version(v))
}

/// Why a failed version failed, as `status` and the doctor rows say it: the signature's word, the markers' missing
/// one, the first failing Docker test (`test NAME failed`), else the Docker run's last line, or the step's own words.
#[must_use]
pub fn failed_why(r: &Record) -> Option<String> {
    if let Some(sig) = r.signature.as_ref().filter(|s| s.outcome == "failed") {
        return Some(sig.why.clone().unwrap_or_else(|| "signature".into()));
    }
    let adm = r.admission.as_ref().filter(|a| a.outcome == "failed")?;
    Some(match adm.step.as_deref() {
        Some("markers") => adm.markers.clone().unwrap_or_else(|| "a marker is missing".into()),
        Some("docker") => adm.docker_test.as_ref().map(|t| format!("test {t} failed")).or_else(|| adm.docker.clone()).unwrap_or_else(|| "the Docker tests failed".into()),
        Some("download") => "the binary is not the signed manifest's".into(),
        Some("version") => "a VM found another version in it".into(),
        Some("stage") => "VMs refused two stages in a row".into(),
        other => other.unwrap_or("admission").to_string(),
    })
}

/// `status --json`'s document (pure): every version the records, the installed bundle and the live windows name,
/// newest first, with its phase, ref, size, staging state, admission time and why it failed (absent values `null`),
/// its Docker failures since it was last admitted (`docker_failures`, 0 without one) and, for a Docker failure the
/// automatic admission runs again (`auto_admit` on and the wrapper's mode `remote`, doctor's T6: in passthrough no
/// wrapper starts it; tries left), the time that retry may start (`retry_from`, RFC 3339 UTC, else `null`). S12
/// (V2): that time is [`Record::retry_from`] by `clock` (the later of the failure and the lock's `finished_at`, plus
/// the cooldown), even when it is past (§V2.4 rule 4, LD-V6: [`status_lines`] says `is due now` from it); the
/// windows are each `N.N.N` one once, newest first ([`newest_first_once`]).
#[must_use]
pub fn status_doc(records: &[Record], bundle: Option<&str>, windows: &[String], image: Option<&str>, auto_admit: bool, remote: bool, clock: &RetryClock) -> serde_json::Value {
    let mut versions: Vec<String> = records.iter().map(|r| r.version.clone()).chain(bundle.map(str::to_string)).chain(windows.iter().cloned()).filter(|v| crate::wire::pin::is_version(v)).collect();
    versions.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
    versions.dedup();
    let rows: Vec<serde_json::Value> = versions
        .iter()
        .map(|v| {
            let r = records.iter().find(|r| &r.version == v);
            serde_json::json!({
                "version": v,
                "phase": r.map_or_else(|| Phase::Seen.word(), |r| r.phase().word()),
                "sha256": r.and_then(Record::claude_ref).map(|c| c.sha256),
                "size": r.and_then(|r| r.signature.as_ref()).and_then(|s| s.linux_size),
                "staged": r.and_then(|r| r.staging.as_ref()).map(|s| s.state.clone()),
                "admitted_at": r.and_then(|r| r.admission.as_ref()).filter(|a| a.outcome == "admitted").map(|a| a.at.clone()),
                "why": r.and_then(failed_why),
                "docker_failures": r.map_or(0, Record::docker_failures),
                "retry_from": r.filter(|_| auto_admit && remote).and_then(|r| r.retry_from(clock)).map(crate::wire::time::rfc3339_utc),
            })
        })
        .collect();
    let win = newest_first_once(windows.iter().map(String::as_str));
    serde_json::json!({ "versions": rows, "bundle": bundle, "windows": win, "image": image, "auto_admit": auto_admit })
}

/// `status`'s text lines from its document: one per version (its phase, who runs it, why it failed; a Docker
/// failure's attempt and whether an automatic retry follows, from when, or that its tries are spent), then the
/// image's fallback and the automatic admission's setting. S12 (V2): a retry whose `retry_from` is at or before
/// `now` (Unix seconds: the `now` of the clock `status_doc` was given) is said to be due now, its time kept in the
/// document only (LD-V6).
#[must_use]
pub fn status_lines(doc: &serde_json::Value, now: u64) -> Vec<String> {
    let s = |v: &serde_json::Value| v.as_str().map(str::to_string);
    let bundle = s(&doc["bundle"]);
    let windows: Vec<String> = doc["windows"].as_array().map(|a| a.iter().filter_map(s).collect()).unwrap_or_default();
    let auto_admit = doc["auto_admit"].as_bool() == Some(true);
    let mut lines = Vec::new();
    for v in doc["versions"].as_array().into_iter().flatten() {
        let version = s(&v["version"]).unwrap_or_default();
        let mut runs = Vec::new();
        if bundle.as_deref() == Some(version.as_str()) {
            runs.push("the Cursor bundle");
        }
        if windows.contains(&version) {
            runs.push("a live Cursor window");
        }
        let phase = s(&v["phase"]).unwrap_or_default();
        let mut line = format!("claude {version}: {phase}");
        if let Some(why) = s(&v["why"]) {
            let docker = if phase == "failed(docker)" { docker_status(&version, v, now) } else { String::new() };
            line.push_str(&format!(" ({why}{docker})"));
        }
        if !runs.is_empty() {
            line.push_str(&format!("; run by {}", runs.join(" and ")));
        }
        lines.push(line);
    }
    if lines.is_empty() {
        lines.push("no Claude Code version known yet (no record, no Cursor bundle, no live window)".into());
    }
    lines.push(format!("the image's claude {} runs where no staged version can", s(&doc["image"]).unwrap_or_else(|| "unknown".into())));
    let auto = if auto_admit { "on: a wrapper starts ai-env claude admit <v> --auto while Docker answers" } else { "off: only ai-env claude admit or update admits" };
    lines.push(format!("automatic admission ([claude].auto_admit): {auto}"));
    lines
}

/// A Docker failure's part of `status`' parenthetical, from its row: `; attempt N of 3`, then whether the automatic
/// admission runs it again (`; an automatic retry from <T> (the next remote wrapper starts it)`, the row's
/// `retry_from`: `auto_admit` on in remote mode; S12, V2: `; an automatic retry is due now (the next remote wrapper
/// starts it)` once that time is at or before `now`, §V2.4 rule 5) or its tries are spent (`, no automatic retry
/// left: fix it, then ai-env claude admit <v> --redo`). A `retry_from` that does not parse keeps S11's ` from` form
/// (`status_doc` writes none).
fn docker_status(version: &str, row: &serde_json::Value, now: u64) -> String {
    let n = row["docker_failures"].as_u64().and_then(|n| u32::try_from(n).ok()).unwrap_or(0);
    let attempt = attempt_words(n);
    if n >= ADMIT_DOCKER_TRIES {
        format!("; {attempt}, no automatic retry left: fix it, then ai-env claude admit {version} --redo")
    } else if let Some(from) = row["retry_from"].as_str() {
        if crate::wire::time::parse_rfc3339_utc(from).is_some_and(|t| t <= now) {
            format!("; {attempt}; an automatic retry is due now (the next remote wrapper starts it)")
        } else {
            format!("; {attempt}; an automatic retry from {from} (the next remote wrapper starts it)")
        }
    } else {
        format!("; {attempt}")
    }
}

/// `ai-env claude status [--json]` (§7.1): local reads only, no Touch ID: the records, the installed bundle, the live
/// windows (the census), the deployed image's claude (`state/infra.toml`), `[claude].auto_admit` and `[wrapper].mode`
/// (a Docker failure's retry promised only in remote mode, as doctor's T6 rule). S12 (V2): one [`RetryClock`] a run,
/// read after the records (now, and the locks of the Docker failures the automatic admission runs again), so every
/// row is judged against one now (§V2.4 rule 10).
pub fn cmd_status(json: bool) -> crate::errors::Result<()> {
    let paths = Paths::resolve()?;
    let cfg = BridgeConfig::load(&paths).ok().flatten().unwrap_or_default();
    let remote = matches!(cfg.wrapper.wrapper_mode(), Ok(crate::bridge::config::WrapperMode::Remote));
    let records = load_all(&paths);
    let clock = RetryClock::read(&paths, &records);
    let windows: Vec<String> = crate::bridge::doctor::running_windows().into_iter().map(|w| w.ext).filter(|e| crate::wire::pin::is_version(e)).collect();
    let image = crate::bridge::infra::read_infra_state(&paths).ok().flatten().and_then(|s| s.claude_version);
    let doc = status_doc(&records, installed_bundle().as_deref(), &windows, image.as_deref(), cfg.claude.auto_admit, remote, &clock);
    if json {
        crate::outln!("{}", serde_json::to_string_pretty(&doc).map_err(|e| crate::errors::CliError::Msg(format!("cannot render JSON: {e}")))?);
    } else {
        for line in status_lines(&doc, clock.now) {
            crate::outln!("{line}");
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn paths(dir: &std::path::Path) -> Paths {
        Paths::from_root_and_env(dir.join("bridge"), None)
    }

    #[test]
    fn records_round_trip_and_name_their_phase() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert_eq!(Record::load(&p, "2.1.308").unwrap(), None);
        assert!(load_all(&p).is_empty());
        let seen = Record::update(&p, "2.1.308", |_| {}).unwrap();
        assert_eq!((seen.v, seen.version.as_str(), seen.phase(), seen.phase().word()), (1, "2.1.308", Phase::Seen, "seen".to_string()));
        assert_eq!(seen.claude_ref(), None);
        assert!(!seen.created.is_empty());
        let sha = "a".repeat(64);
        let signed = Record::update(&p, "2.1.308", |r| {
            r.signature = Some(SignatureRow { outcome: "ok".into(), signer: Some("F".into()), linux_sha256: Some(sha.clone()), linux_size: Some(290), at: "t".into(), ..SignatureRow::default() });
        })
        .unwrap();
        assert_eq!((signed.phase(), signed.created.as_str()), (Phase::Signed, seen.created.as_str()));
        assert_eq!(signed.claude_ref(), Some(ClaudeRef { version: "2.1.308".into(), sha256: sha.clone() }));
        let admitted = Record::update(&p, "2.1.308", |r| r.admission = Some(AdmissionRow { outcome: "admitted".into(), markers: Some("ok".into()), ai_env: "0.1.0".into(), at: "t".into(), ..AdmissionRow::default() })).unwrap();
        assert_eq!((admitted.phase(), admitted.nameable()), (Phase::Admitted, false));
        let staged = Record::update(&p, "2.1.308", |r| r.staging = Some(StagingRow { state: "staged".into(), s3_key: format!("v1/_claude/mac/2.1.308/{sha}"), at: "t".into(), ..StagingRow::default() })).unwrap();
        assert_eq!((staged.phase(), staged.nameable(), staged.phase().word()), (Phase::Staged, true, "staged".to_string()));
        // What was written reads back the same, 0600 in a 0700 directory.
        assert_eq!(Record::load(&p, "2.1.308").unwrap(), Some(staged.clone()));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(p.claude_record("2.1.308")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(p.claude_dir()).unwrap().permissions().mode() & 0o777, 0o700);
        let stale = Record::update(&p, "2.1.308", |r| r.staging.as_mut().unwrap().state = "stale".into()).unwrap();
        assert_eq!(stale.phase(), Phase::Stale);
        let absent = Record::update(&p, "2.1.308", |r| r.staging.as_mut().unwrap().state = "absent".into()).unwrap();
        assert_eq!(absent.phase(), Phase::Admitted);
        // A failed admission or signature is read before any staging state: never nameable.
        let failed = Record::update(&p, "2.1.308", |r| {
            r.staging.as_mut().unwrap().state = "staged".into();
            let a = r.admission.as_mut().unwrap();
            a.outcome = "failed".into();
            a.step = Some("version".into());
        })
        .unwrap();
        assert_eq!((failed.phase().word(), failed.nameable()), ("failed(version)".to_string(), false));
        let bad_sig = Record::update(&p, "2.1.309", |r| r.signature = Some(SignatureRow { outcome: "failed".into(), why: Some("wrong_key".into()), at: "t".into(), ..SignatureRow::default() })).unwrap();
        assert_eq!((bad_sig.phase().word(), bad_sig.claude_ref()), ("failed(signature)".to_string(), None));
        // Every record, oldest first; a file that is no version's is not read.
        Record::update(&p, "2.1.10", |_| {}).unwrap();
        std::fs::write(p.claude_dir().join("notes.toml"), "x = 1\n").unwrap();
        let versions: Vec<String> = load_all(&p).into_iter().map(|r| r.version).collect();
        assert_eq!(versions, ["2.1.10", "2.1.308", "2.1.309"]);
        assert!(Record::update(&p, "2.1", |_| {}).is_err());
        assert!(Record::load(&p, "../x").is_err());
    }

    #[test]
    fn a_record_of_another_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        Record::update(&p, "2.1.308", |_| {}).unwrap();
        let path = p.claude_record("2.1.308");
        let good = std::fs::read_to_string(&path).unwrap();
        for (bad, says) in [
            (good.replace("v = 1", "v = 2"), "schema 2"),
            (format!("{good}surprise = true\n"), "surprise"),
            (good.replace("version = \"2.1.308\"", "version = \"2.1.309\""), "not 2.1.308"),
            (format!("{good}\n[signature]\noutcome = \"ok\"\nextra = 1\n"), "extra"),
        ] {
            std::fs::write(&path, &bad).unwrap();
            let e = Record::load(&p, "2.1.308").unwrap_err().to_string();
            assert!(e.contains(says), "{e}");
            // load_all skips it; update refuses to write over it.
            assert!(load_all(&p).is_empty());
            assert!(Record::update(&p, "2.1.308", |_| {}).is_err());
        }
    }

    /// A record of `v` in `phase` (`seen`, `signed`, `admitted`, `staged`, `stale`, `absent`, `failed`), its linux
    /// pin `c` repeated 64 times, 290 bytes.
    pub(crate) fn put(p: &Paths, v: &str, c: char, phase: &str) -> Record {
        let sha = c.to_string().repeat(64);
        Record::update(p, v, |r| {
            if phase == "seen" {
                return;
            }
            r.signature = Some(SignatureRow { outcome: "ok".into(), signer: Some(crate::wire::pin::RELEASE_KEY_FPR.into()), linux_sha256: Some(sha.clone()), linux_size: Some(290), at: "2026-10-23T10:00:00Z".into(), ..SignatureRow::default() });
            if phase == "signed" {
                return;
            }
            let failed = phase == "failed";
            r.admission = Some(AdmissionRow {
                outcome: if failed { "failed" } else { "admitted" }.into(),
                step: failed.then(|| "markers".into()),
                markers: Some(if failed { "missing:auto_mode" } else { "ok" }.into()),
                ai_env: "0.1.0".into(),
                at: "2026-10-23T10:05:00Z".into(),
                ..AdmissionRow::default()
            });
            if matches!(phase, "staged" | "stale" | "absent" | "failed") {
                let state = if failed { "staged" } else { phase };
                r.staging = Some(StagingRow { state: state.into(), s3_key: format!("v1/_claude/mac/{v}/{sha}"), at: "2026-10-23T10:10:00Z".into(), ..StagingRow::default() });
            }
        })
        .unwrap()
    }

    fn cref(v: &str, c: char) -> ClaudeRef {
        ClaudeRef { version: v.into(), sha256: c.to_string().repeat(64) }
    }

    /// A3's review: forget's delete under the records lock; a verdict after it writes nothing back.
    #[test]
    fn a_removed_record_stays_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert!(!Record::remove(&p, "2.1.306").unwrap(), "none to remove");
        Record::update(&p, "2.1.306", |_| {}).unwrap();
        assert!(Record::remove(&p, "2.1.306").unwrap());
        assert_eq!(Record::update_existing(&p, "2.1.306", |_| true).unwrap(), None, "not written back");
        assert!(Record::load(&p, "2.1.306").unwrap().is_none());
    }

    /// L2: V first when nameable, then every other nameable version newest first (2.1.9 before 2.1.306 as text,
    /// after it as numbers), at most four, a sha256 once; a failed version is never named whatever its staging
    /// says; V's phase and why it does not lead.
    #[test]
    fn plan_for_names_admitted_staged_versions_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        for (v, c, phase) in [("2.1.306", 'a', "staged"), ("2.1.310", 'b', "staged"), ("2.1.9", 'c', "staged"), ("2.1.311", 'a', "staged"), ("2.1.312", 'f', "staged"), ("2.1.308", 'd', "admitted"), ("2.1.307", 'e', "failed"), ("2.1.309", '9', "stale")] {
            put(&p, v, c, phase);
        }
        let plan = plan_for(&p, Some("2.1.310"));
        assert_eq!((plan.ext.as_deref(), plan.phase.as_deref(), plan.why_not), (Some("2.1.310"), Some("staged"), None));
        assert_eq!(plan.prefs, [cref("2.1.310", 'b'), cref("2.1.312", 'f'), cref("2.1.311", 'a'), cref("2.1.9", 'c')]);
        assert_eq!(plan.sizes.len(), 4);
        assert!(plan.sizes.values().all(|s| *s == 290));
        for (v, phase, why) in [("2.1.308", "admitted", "not_staged"), ("2.1.309", "stale", "not_staged"), ("2.1.307", "failed(markers)", "failed"), ("2.1.400", "seen", "seen")] {
            let plan = plan_for(&p, Some(v));
            assert_eq!((plan.phase.as_deref(), plan.why_not), (Some(phase), Some(why)), "{v}");
            assert_eq!(plan.prefs, [cref("2.1.312", 'f'), cref("2.1.311", 'a'), cref("2.1.310", 'b'), cref("2.1.9", 'c')], "{v}: the others newest first");
        }
        put(&p, "2.1.401", '1', "signed");
        assert_eq!(plan_for(&p, Some("2.1.401")).why_not, Some("seen"), "signed is not admitted yet");
        for ext in [None, Some("2.1"), Some("x"), Some("2.1.310-beta")] {
            let plan = plan_for(&p, ext);
            assert_eq!((plan.ext.as_deref(), plan.phase.as_deref(), plan.why_not), (None, None, Some("no_ext")), "{ext:?}");
            assert_eq!(plan.prefs.len(), 4);
        }
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(plan_for(&paths(empty.path()), Some("2.1.310")), ClaudePlan { ext: Some("2.1.310".into()), phase: Some("seen".into()), why_not: Some("seen"), ..ClaudePlan::default() });
    }

    /// §5.1's words, each from what ran (`Spawned`) against what P4 asked.
    #[test]
    fn census_words_of_claude_src() {
        let v = cref("2.1.310", 'b');
        let older = cref("2.1.309", 'c');
        let staged = ClaudePlan { ext: Some("2.1.310".into()), phase: Some("staged".into()), why_not: None, prefs: vec![v.clone(), older.clone()], ..ClaudePlan::default() };
        let asked = |plan: &ClaudePlan, cap: bool, sent: Vec<ClaudeRef>, after: bool| ClaudeAsk { plan: plan.clone(), cap, sent, after_start_failed: after };
        let both = asked(&staged, true, vec![v.clone(), older.clone()], false);
        let sha = |r: &ClaudeRef| r.sha256.clone();
        type Case<'a> = (ClaudeAsk, Option<&'a str>, Option<&'a str>, Option<String>, &'a str);
        let cases: Vec<Case<'_>> = vec![
            (both.clone(), Some("2.1.305"), Some("2.1.310"), Some(sha(&v)), "cached"),
            (both.clone(), Some("2.1.305"), Some("2.1.309"), Some(sha(&older)), "older(not_cached)"),
            (both.clone(), Some("2.1.305"), Some("2.1.305"), None, "image(not_cached)"),
            (both.clone(), Some("2.1.310"), Some("2.1.310"), None, "image"),
            (both.clone(), Some("2.1.310"), None, None, "image"),
            (asked(&staged, false, Vec::new(), false), Some("2.1.305"), Some("2.1.305"), None, "image(no_cap)"),
            (asked(&staged, true, vec![older.clone()], false), Some("2.1.305"), Some("2.1.309"), Some(sha(&older)), "older(bad)"),
            (asked(&staged, true, vec![older.clone()], true), Some("2.1.305"), Some("2.1.309"), Some(sha(&older)), "older(start_failed)"),
            (asked(&staged, true, Vec::new(), true), Some("2.1.305"), Some("2.1.305"), None, "image(start_failed)"),
        ];
        for (ask, image, ran, ran_sha, want) in cases {
            assert_eq!(claude_src_of(&ask, image, ran, ran_sha.as_deref()), want, "{ask:?} ran {ran:?}");
        }
        for (why, phase) in [("seen", "seen"), ("failed", "failed(markers)"), ("not_staged", "admitted")] {
            let plan = ClaudePlan { ext: Some("2.1.310".into()), phase: Some(phase.into()), why_not: Some(why), prefs: vec![older.clone()], ..ClaudePlan::default() };
            let ask = asked(&plan, true, vec![older.clone()], false);
            assert_eq!(claude_src_of(&ask, Some("2.1.305"), Some("2.1.305"), None), format!("image({why})"));
            assert_eq!(claude_src_of(&ask, Some("2.1.305"), Some("2.1.309"), Some(&sha(&older))), format!("older({why})"));
            assert_eq!(claude_src_of(&ask, Some("2.1.310"), Some("2.1.310"), None), "image", "the image's own is V");
        }
        let no_v = ClaudeAsk { plan: ClaudePlan { why_not: Some("no_ext"), prefs: vec![older.clone()], ..ClaudePlan::default() }, cap: true, sent: vec![older.clone()], after_start_failed: false };
        assert_eq!(claude_src_of(&no_v, Some("2.1.305"), Some("2.1.305"), None), "image(no_ext)");
        assert_eq!(claude_src_of(&no_v, Some("2.1.305"), Some("2.1.309"), Some(&sha(&older))), "older(no_ext)");
        for word in crate::bridge::remote::CLAUDE_SRC_WHYS {
            assert!(word.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{word}");
        }
    }

    /// `status` names every phase, the bundle's and the windows' versions (seen without a record), the image's
    /// fallback and the automatic admission.
    #[test]
    fn status_lists_seen_signed_admitted_failed_staged_stale() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        for (v, c, phase) in [("2.1.306", 'a', "seen"), ("2.1.307", 'b', "signed"), ("2.1.308", 'c', "admitted"), ("2.1.309", 'd', "failed"), ("2.1.310", 'e', "staged"), ("2.1.311", 'f', "stale")] {
            put(&p, v, c, phase);
        }
        let doc = status_doc(&load_all(&p), Some("2.1.320"), &["2.1.310".to_string(), "2.1.310".to_string()], Some("2.1.305"), true, true, &RetryClock::at(0));
        let phases: Vec<(String, String)> = doc["versions"].as_array().unwrap().iter().map(|v| (v["version"].as_str().unwrap().to_string(), v["phase"].as_str().unwrap().to_string())).collect();
        let want = [("2.1.320", "seen"), ("2.1.311", "stale"), ("2.1.310", "staged"), ("2.1.309", "failed(markers)"), ("2.1.308", "admitted"), ("2.1.307", "signed"), ("2.1.306", "seen")];
        assert_eq!(phases, want.map(|(v, p)| (v.to_string(), p.to_string())));
        let row = |v: &str| doc["versions"].as_array().unwrap().iter().find(|r| r["version"] == v).unwrap().clone();
        assert_eq!(row("2.1.310"), serde_json::json!({"version": "2.1.310", "phase": "staged", "sha256": "e".repeat(64), "size": 290, "staged": "staged", "admitted_at": "2026-10-23T10:05:00Z", "why": null, "docker_failures": 0, "retry_from": null}));
        assert_eq!(row("2.1.320"), serde_json::json!({"version": "2.1.320", "phase": "seen", "sha256": null, "size": null, "staged": null, "admitted_at": null, "why": null, "docker_failures": 0, "retry_from": null}));
        assert_eq!(row("2.1.309")["why"], "missing:auto_mode");
        assert_eq!((doc["bundle"].as_str(), doc["image"].as_str(), doc["auto_admit"].as_bool()), (Some("2.1.320"), Some("2.1.305"), Some(true)));
        assert_eq!(doc["windows"], serde_json::json!(["2.1.310"]));
        let lines = status_lines(&doc, 0);
        for want in ["claude 2.1.320: seen; run by the Cursor bundle", "claude 2.1.310: staged; run by a live Cursor window", "claude 2.1.309: failed(markers) (missing:auto_mode)", "claude 2.1.311: stale", "the image's claude 2.1.305 runs where no staged version can"] {
            assert!(lines.iter().any(|l| l == want), "{want}: {lines:?}");
        }
        assert!(lines.last().unwrap().starts_with("automatic admission ([claude].auto_admit): on"), "{lines:?}");
        let none = status_lines(&status_doc(&[], None, &[], None, false, false, &RetryClock::at(0)), 0);
        assert_eq!(none.len(), 3, "{none:?}");
        assert!(none[1].contains("unknown") && none[2].contains(": off"), "{none:?}");
    }

    /// D5: one detached `ai-env claude admit <v> --auto` per version while its lock is held, none again within the
    /// cooldown its child writes, one more once it passed; never for an admitted record, with the switch off, under
    /// the fake API without the three admission knobs, or without the sibling.
    #[test]
    fn auto_admit_forks_once_per_version_and_cooldown() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let cfg = BridgeConfig::default();
        let knobs = crate::bridge::lab::VmKnobs::default();
        // The child: what `claude admit --auto` writes at its end, on fd 3 (its lock's open file), then its exit.
        let child = dir.path().join("admit.sh");
        let log = dir.path().join("admit.log");
        std::fs::write(&child, format!("#!/bin/sh\necho \"$@\" >> '{}'\nprintf 'finished_at=%s\\noutcome=skipped(no_docker)\\n' \"$(date +%s)\" >&3\n", log.display())).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sibling = || Some(child.clone());
        let settled = |v: &str| {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let r = auto_admit_with(&p, &cfg, &knobs, v, &sibling);
                if r != AutoAdmit::Skipped("admitting") || std::time::Instant::now() > until {
                    return r;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        assert!(matches!(auto_admit_with(&p, &cfg, &knobs, "2.1.310", &sibling), AutoAdmit::Spawned(pid) if pid > 0));
        assert_eq!(settled("2.1.310"), AutoAdmit::Skipped("recent"), "its end within the cooldown");
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "claude admit 2.1.310 --auto\n");
        let lock = p.claude_lock("2.1.310");
        assert_eq!(std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777, 0o600);
        // Past the cooldown: once more.
        let old = crate::wire::time::unix_now() - ADMIT_COOLDOWN.as_secs() - 60;
        std::fs::write(&lock, format!("finished_at={old}\noutcome=error(fetch)\n")).unwrap();
        assert!(matches!(auto_admit_with(&p, &cfg, &knobs, "2.1.310", &sibling), AutoAdmit::Spawned(_)));
        assert_eq!(settled("2.1.310"), AutoAdmit::Skipped("recent"));
        assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
        // Another holds the lock (an admission or a stage of it runs): never a second.
        let held = crate::bridge::vm::lock::try_lock_exclusive(&p.claude_lock("2.1.311")).unwrap().expect("the lock is free");
        assert_eq!(auto_admit_with(&p, &cfg, &knobs, "2.1.311", &sibling), AutoAdmit::Skipped("admitting"));
        drop(held);
        // A version past `signed`: never; a signed one: yes.
        put(&p, "2.1.312", 'a', "admitted");
        assert_eq!(auto_admit_with(&p, &cfg, &knobs, "2.1.312", &sibling), AutoAdmit::Skipped("has_record"));
        put(&p, "2.1.313", 'b', "failed");
        assert_eq!(auto_admit_with(&p, &cfg, &knobs, "2.1.313", &sibling), AutoAdmit::Skipped("has_record"));
        put(&p, "2.1.314", 'c', "signed");
        assert!(matches!(auto_admit_with(&p, &cfg, &knobs, "2.1.314", &sibling), AutoAdmit::Spawned(_)));
        // The switch, the lab, the sibling.
        let off = BridgeConfig { claude: crate::bridge::config::ClaudeCfg { auto_admit: false }, ..BridgeConfig::default() };
        assert_eq!(auto_admit_with(&p, &off, &knobs, "2.1.315", &sibling), AutoAdmit::Skipped("off"));
        let lab = crate::bridge::lab::VmKnobs { fake_api: Some(dir.path().join("fake.json")), ..crate::bridge::lab::VmKnobs::default() };
        assert_eq!(auto_admit_with(&p, &cfg, &lab, "2.1.315", &sibling), AutoAdmit::Skipped("lab"));
        assert_eq!(auto_admit_with(&p, &cfg, &knobs, "2.1.315", &|| None), AutoAdmit::Skipped("no_sibling"));
        assert_eq!(maybe_auto_admit(&p, &off, "2.1.315"), AutoAdmit::Skipped("off"));
        assert_eq!(settled("2.1.314"), AutoAdmit::Skipped("recent"));
        assert!(!needs_staging(&p, "2.1.314") && needs_staging(&p, "2.1.312") && !needs_staging(&p, "2.1.316"));
        put(&p, "2.1.316", 'd', "stale");
        put(&p, "2.1.317", 'e', "staged");
        assert!(needs_staging(&p, "2.1.316") && !needs_staging(&p, "2.1.317"));
    }

    /// A record of `v` whose admission failed at `docker` (the make log's `l2_x` failed), `failures` recorded (0: a
    /// record from before the count), at `at` (RFC 3339 UTC).
    pub(crate) fn put_docker(p: &Paths, v: &str, c: char, failures: u32, at: &str) -> Record {
        put(p, v, c, "signed");
        Record::update(p, v, |r| {
            r.admission = Some(AdmissionRow {
                outcome: "failed".into(),
                step: Some("docker".into()),
                markers: Some("ok".into()),
                docker: Some("make: *** [claude-admit-docker] Error 101".into()),
                docker_test: Some("l2_x".into()),
                docker_failures: failures,
                docker_excerpt: vec!["test l2_x ... FAILED".into()],
                ai_env: "0.1.0".into(),
                auto: true,
                at: at.into(),
                ..AdmissionRow::default()
            });
        })
        .unwrap()
    }

    /// Mike's rule (24 Oct): D5's trigger forks for a Docker failure with 0 (a record from before the count), 1 or 2
    /// failures recorded once its cooldown is over, as for a missing or signed record; never within the cooldown
    /// (the lock's `finished_at`, or the failure's own time: a run by hand writes no `finished_at`), while the lock
    /// is held, at 3, nor for any other failed step (the signature; the download's size or sha256, recorded as
    /// `failed(download)`; the markers; a VM's version or two bad stages). P0 hands it `failed(docker)` too.
    #[test]
    fn auto_admit_retries_a_docker_failure_with_tries_left_after_its_cooldown() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let cfg = BridgeConfig::default();
        let knobs = crate::bridge::lab::VmKnobs::default();
        let child = dir.path().join("admit.sh");
        let log = dir.path().join("admit.log");
        std::fs::write(&child, format!("#!/bin/sh\necho \"$@\" >> '{}'\nprintf 'finished_at=%s\\noutcome=failed(docker)\\n' \"$(date +%s)\" >&3\n", log.display())).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sibling = || Some(child.clone());
        let now = crate::wire::time::unix_now();
        let old = crate::wire::time::rfc3339_utc(now - ADMIT_COOLDOWN.as_secs() - 60);
        let trigger = |v: &str| auto_admit_with(&p, &cfg, &knobs, v, &sibling);
        let settled = |v: &str| {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let r = trigger(v);
                if r != AutoAdmit::Skipped("admitting") || std::time::Instant::now() > until {
                    return r;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        for (v, failures) in [("2.1.320", 0), ("2.1.321", 1), ("2.1.322", 2)] {
            let r = put_docker(&p, v, 'a', failures, &old);
            assert!(r.auto_retry() && auto_admit_phase(&r.phase().word()), "{v}");
            assert!(matches!(trigger(v), AutoAdmit::Spawned(pid) if pid > 0), "{v}: {failures} recorded");
            assert_eq!(settled(v), AutoAdmit::Skipped("recent"), "{v}: the child's end starts the cooldown");
        }
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "claude admit 2.1.320 --auto\nclaude admit 2.1.321 --auto\nclaude admit 2.1.322 --auto\n");
        // The tries spent: the record stands until --redo.
        for failures in [3, 4] {
            let r = put_docker(&p, "2.1.323", 'b', failures, &old);
            assert!(!r.auto_retry());
            assert_eq!(trigger("2.1.323"), AutoAdmit::Skipped("has_record"), "{failures} recorded");
        }
        // Within the cooldown of the failure's own time (a run by hand): no lock taken, no fork.
        put_docker(&p, "2.1.324", 'c', 1, &crate::wire::time::rfc3339_utc(now - 60));
        assert_eq!(trigger("2.1.324"), AutoAdmit::Skipped("recent"));
        assert!(!p.claude_lock("2.1.324").exists(), "decided from the record alone");
        // Within the lock's `finished_at` cooldown; while another holds the lock.
        put_docker(&p, "2.1.325", 'd', 1, &old);
        std::fs::write(p.claude_lock("2.1.325"), format!("finished_at={}\noutcome=skipped(no_docker)\n", now - 60)).unwrap();
        assert_eq!(trigger("2.1.325"), AutoAdmit::Skipped("recent"));
        put_docker(&p, "2.1.326", 'e', 2, &old);
        let held = crate::bridge::vm::lock::try_lock_exclusive(&p.claude_lock("2.1.326")).unwrap().expect("the lock is free");
        assert_eq!(trigger("2.1.326"), AutoAdmit::Skipped("admitting"));
        drop(held);
        // Every other failed step stays final for the automatic path, whatever its time.
        let failed_sig = Record::update(&p, "2.1.330", |r| r.signature = Some(SignatureRow { outcome: "failed".into(), why: Some("bad".into()), at: old.clone(), ..SignatureRow::default() })).unwrap();
        assert_eq!(failed_sig.phase().word(), "failed(signature)");
        for (v, step) in [("2.1.331", "download"), ("2.1.332", "markers"), ("2.1.333", "version"), ("2.1.334", "stage")] {
            put_docker(&p, v, 'f', 1, &old);
            let r = Record::update(&p, v, |r| r.admission.as_mut().unwrap().step = Some(step.into())).unwrap();
            assert_eq!((r.phase().word(), r.auto_retry(), auto_admit_phase(&r.phase().word())), (format!("failed({step})"), false, false));
        }
        for v in ["2.1.330", "2.1.331", "2.1.332", "2.1.333", "2.1.334"] {
            assert_eq!(trigger(v), AutoAdmit::Skipped("has_record"), "{v}");
        }
        assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 3, "no other fork");
        for (word, handed) in [("seen", true), ("signed", true), ("failed(docker)", true), ("failed(markers)", false), ("admitted", false), ("staged", false), ("stale", false)] {
            assert_eq!(auto_admit_phase(word), handed, "{word}");
        }
    }

    /// A record written before the count (an older ai-env's `failed(docker)`) reads, and counts its failure as 1;
    /// a record that never failed at Docker holds none of the new keys, so an older ai-env still reads it.
    #[test]
    fn a_record_from_before_the_count_reads_and_counts_its_docker_failure() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        std::fs::create_dir_all(p.claude_dir()).unwrap();
        let sha = "a".repeat(64);
        let old = format!(
            "v = 1\nversion = \"2.1.309\"\ncreated = \"2026-10-23T10:00:00Z\"\n\n[signature]\noutcome = \"ok\"\nlinux_sha256 = \"{sha}\"\nlinux_size = 290\nat = \"2026-10-23T10:00:00Z\"\n\n[admission]\noutcome = \"failed\"\nstep = \"docker\"\nmarkers = \"ok\"\ndocker = \"make: *** [claude-admit-docker] Error 101\"\nai_env = \"0.1.0\"\nauto = true\nat = \"2026-10-23T10:05:00Z\"\n"
        );
        std::fs::write(p.claude_record("2.1.309"), old).unwrap();
        let r = Record::load(&p, "2.1.309").unwrap().expect("it reads");
        let adm = r.admission.clone().unwrap();
        assert_eq!((adm.docker_failures, adm.docker_test.as_deref(), adm.docker_excerpt.len()), (0, None, 0), "absent keys read as their defaults");
        assert_eq!((r.phase().word(), r.docker_failures(), r.auto_retry()), ("failed(docker)".to_string(), 1, true));
        assert_eq!(r.auto_retry_from(), crate::wire::time::parse_rfc3339_utc("2026-10-23T10:20:00Z"), "its own time plus the cooldown");
        assert_eq!(failed_why(&r).as_deref(), Some("make: *** [claude-admit-docker] Error 101"), "no test named: the last line");
        // Written again (a verdict of the stage, say): still none of the new keys.
        Record::update(&p, "2.1.309", |_| {}).unwrap();
        let text = std::fs::read_to_string(p.claude_record("2.1.309")).unwrap();
        assert!(!text.contains("docker_failures") && !text.contains("docker_excerpt") && !text.contains("docker_test"), "{text}");
        // A count, a test and an excerpt round-trip; an admission clears them from the file.
        let counted = put_docker(&p, "2.1.310", 'b', 2, "2026-10-23T10:05:00Z");
        assert_eq!(Record::load(&p, "2.1.310").unwrap(), Some(counted.clone()));
        assert_eq!((counted.docker_failures(), counted.auto_retry(), failed_why(&counted).as_deref()), (2, true, Some("test l2_x failed")));
        let admitted = Record::update(&p, "2.1.310", |r| r.admission = Some(AdmissionRow { outcome: "admitted".into(), markers: Some("ok".into()), ai_env: "0.1.0".into(), at: "t".into(), ..AdmissionRow::default() })).unwrap();
        assert_eq!((admitted.docker_failures(), admitted.auto_retry(), admitted.auto_retry_from()), (0, false, None));
        let text = std::fs::read_to_string(p.claude_record("2.1.310")).unwrap();
        assert!(!text.contains("docker_failures") && !text.contains("docker_excerpt") && !text.contains("docker_test"), "{text}");
        // A failure's time that does not read: due at once (the lock's `finished_at` still spaces the tries).
        let odd = put_docker(&p, "2.1.311", 'c', 1, "t");
        assert_eq!((odd.auto_retry(), odd.auto_retry_from()), (true, None));
    }

    /// `status` names a Docker failure's first failing test and its attempt, then the automatic retry and from when
    /// (`[claude].auto_admit` on in remote mode: in passthrough no wrapper starts it, doctor's T6), or the tries spent
    /// and the `--redo`; `--json` carries the count and the time.
    #[test]
    fn status_says_a_docker_failures_attempt_and_its_retry() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        put_docker(&p, "2.1.320", 'a', 1, "2026-10-24T13:50:00Z");
        put_docker(&p, "2.1.321", 'b', 3, "2026-10-24T13:50:00Z");
        put_docker(&p, "2.1.322", 'c', 0, "2026-10-24T13:50:00Z");
        put(&p, "2.1.323", 'd', "failed");
        let doc = status_doc(&load_all(&p), None, &[], Some("2.1.305"), true, true, &RetryClock::at(0));
        let row = |v: &str| doc["versions"].as_array().unwrap().iter().find(|r| r["version"] == v).unwrap().clone();
        assert_eq!((row("2.1.320")["why"].as_str(), row("2.1.320")["docker_failures"].as_u64(), row("2.1.320")["retry_from"].as_str()), (Some("test l2_x failed"), Some(1), Some("2026-10-24T14:05:00Z")));
        assert_eq!((row("2.1.321")["docker_failures"].as_u64(), row("2.1.321")["retry_from"].clone()), (Some(3), serde_json::Value::Null), "spent: no retry");
        assert_eq!((row("2.1.322")["docker_failures"].as_u64(), row("2.1.322")["retry_from"].as_str()), (Some(1), Some("2026-10-24T14:05:00Z")), "a record from before the count");
        assert_eq!((row("2.1.323")["docker_failures"].as_u64(), row("2.1.323")["retry_from"].clone()), (Some(0), serde_json::Value::Null), "markers: final");
        let lines = status_lines(&doc, 0);
        for want in [
            "claude 2.1.320: failed(docker) (test l2_x failed; attempt 1 of 3; an automatic retry from 2026-10-24T14:05:00Z (the next remote wrapper starts it))",
            "claude 2.1.321: failed(docker) (test l2_x failed; attempt 3 of 3, no automatic retry left: fix it, then ai-env claude admit 2.1.321 --redo)",
            "claude 2.1.322: failed(docker) (test l2_x failed; attempt 1 of 3; an automatic retry from 2026-10-24T14:05:00Z (the next remote wrapper starts it))",
            "claude 2.1.323: failed(markers) (missing:auto_mode)",
        ] {
            assert!(lines.iter().any(|l| l == want), "{want}: {lines:?}");
        }
        // The automatic admission off, or on in passthrough: the attempt only, no retry promised.
        for (auto_admit, remote) in [(false, true), (true, false)] {
            let off = status_doc(&load_all(&p), None, &[], Some("2.1.305"), auto_admit, remote, &RetryClock::at(0));
            assert_eq!(off["versions"].as_array().unwrap().iter().find(|r| r["version"] == "2.1.320").unwrap()["retry_from"], serde_json::Value::Null, "{auto_admit} {remote}");
            let lines = status_lines(&off, 0);
            assert!(lines.iter().any(|l| l == "claude 2.1.320: failed(docker) (test l2_x failed; attempt 1 of 3)"), "{lines:?}");
            assert!(lines.iter().any(|l| l.starts_with("claude 2.1.321: failed(docker) (test l2_x failed; attempt 3 of 3, no automatic retry left: ")), "{lines:?}");
        }
        // Past the tries by --redo: the attempt alone.
        put_docker(&p, "2.1.321", 'b', 4, "2026-10-24T13:50:00Z");
        let lines = status_lines(&status_doc(&load_all(&p), None, &[], None, true, true, &RetryClock::at(0)), 0);
        assert!(lines.iter().any(|l| l.starts_with("claude 2.1.321: failed(docker) (test l2_x failed; attempt 4, no automatic retry left: ")), "{lines:?}");
    }

    /// S12 (V1, LD-V1): how the views list versions: the `N.N.N` ones only, newest first by number part by part
    /// (2.1.10 after 2.1.302 and before 2.1.9, which a text sort would put first), each once.
    #[test]
    fn newest_first_once_orders_by_number_and_names_each_once() {
        assert_eq!(newest_first_once(["2.1.302", "2.1.310", "2.1.9", "2.1.302", "unrecognised", "2.1.10", ""]), ["2.1.310", "2.1.302", "2.1.10", "2.1.9"]);
        assert!(newest_first_once(Vec::<&str>::new()).is_empty());
    }

    /// S12 (V2, §V2.4 rules 1 to 3): the views' retry time is the cooldown after the later of the failure's `at` and
    /// the version lock's `finished_at` (the last automatic try's end), after either alone when the other does not
    /// read, and none when neither reads or the automatic admission does not run the record again (its tries spent,
    /// another failed step, admitted), whatever its lock says. It is ` from <T>` until `T`, then ` is due now`, from
    /// that very second (LD-V5, the words §12.1's Q-V4). `RetryClock::read` opens the locks of the records the
    /// automatic admission runs again and no other, though each holds an end (rule 12, LD-V9).
    #[test]
    fn the_retry_counts_from_the_later_of_the_failure_and_the_last_auto_end() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let a = crate::wire::time::parse_rfc3339_utc("2026-10-24T13:50:00Z").unwrap();
        let cooldown = ADMIT_COOLDOWN.as_secs();
        let r = put_docker(&p, "2.1.320", 'a', 1, "2026-10-24T13:50:00Z");
        let clock = |v: &str, now: u64, finished: Option<u64>| RetryClock { now, finished: finished.map(|f| (v.to_string(), f)).into_iter().collect() };
        // The last automatic try ended after the failure: its end counts.
        let later = clock("2.1.320", a + 60, Some(a + 600));
        assert_eq!(r.retry_from(&later), Some(a + 1500));
        assert_eq!(retry_when(&r, &later), " from 2026-10-24T14:15:00Z");
        // It ended before the failure: the failure's own time.
        let earlier = clock("2.1.320", a + 60, Some(a - 600));
        assert_eq!((r.retry_from(&earlier), retry_when(&r, &earlier).as_str()), (Some(a + cooldown), " from 2026-10-24T14:05:00Z"));
        // No end in the lock, or only another version's: S11's time.
        assert_eq!((r.retry_from(&clock("2.1.320", a + 60, None)), r.auto_retry_from()), (Some(a + cooldown), Some(a + cooldown)));
        assert_eq!(r.retry_from(&clock("2.1.399", a + 60, Some(a + 600))), Some(a + cooldown));
        // A failure's time that does not read: the lock's end alone; neither: no time, and nothing said.
        let odd = put_docker(&p, "2.1.321", 'b', 1, "t");
        assert_eq!(odd.retry_from(&clock("2.1.321", a + 60, Some(a + 600))), Some(a + 600 + cooldown));
        assert_eq!((odd.retry_from(&RetryClock::at(a + 60)), retry_when(&odd, &RetryClock::at(a + 60))), (None, String::new()));
        // Due at `T` itself and after it; one second before, still from `T`.
        let t = a + 1500;
        assert_eq!(retry_when(&r, &clock("2.1.320", t, Some(a + 600))), " is due now");
        assert_eq!(retry_when(&r, &clock("2.1.320", t + 3600, Some(a + 600))), " is due now");
        assert_eq!(retry_when(&r, &clock("2.1.320", t - 1, Some(a + 600))), " from 2026-10-24T14:15:00Z");
        // No automatic retry, so no time, whatever the lock says: 3 failures, a failed marker, an admitted version.
        let spent = put_docker(&p, "2.1.322", 'c', 3, "2026-10-24T13:50:00Z");
        let markers = put(&p, "2.1.323", 'd', "failed");
        let admitted = put(&p, "2.1.324", 'e', "admitted");
        for rec in [spent, markers, admitted] {
            let c = clock(&rec.version, a + 60, Some(a + 600));
            assert_eq!((rec.retry_from(&c), retry_when(&rec, &c)), (None, String::new()), "{}", rec.version);
        }
        // Every one of the five holds an end; the clock reads those of the two Docker failures with tries left (the
        // one whose time does not read too), never the spent, the markers' or the admitted version's.
        for v in ["2.1.320", "2.1.321", "2.1.322", "2.1.323", "2.1.324"] {
            std::fs::write(p.claude_lock(v), format!("finished_at={}\n", a + 600)).unwrap();
        }
        assert_eq!(RetryClock::read(&p, &load_all(&p)).finished, std::collections::BTreeMap::from([("2.1.320".to_string(), a + 600), ("2.1.321".to_string(), a + 600)]), "only the locks of Docker failures with tries left are read");
    }

    /// S12 (V2, §V4 items 1 and 2, LD-V11): the views read a lock's `finished_at=` past an admission's flock, never
    /// wait (a FIFO opens at once), never create the file, and take only a regular file's first
    /// `FINISHED_AT_READ_MAX` bytes as UTF-8: the prewarm's form reads, and a line ending right at the bound; a
    /// missing file (which stays missing), a symlink (its target holding a time), a directory, a FIFO, a line whose
    /// last digit lies one byte past the bound, bytes that are no UTF-8 and a name that is no version (`../x` would
    /// name a file holding a time) read as none. Every case on a thread bounded at 5 s: a wait fails the test, never
    /// hangs it.
    #[test]
    fn lock_finished_at_reads_without_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        std::fs::create_dir_all(p.claude_dir()).unwrap();
        let lock = |v: &str| p.claude_lock(v);
        std::fs::write(lock("2.1.301"), "finished_at=123\noutcome=failed(docker)\n").unwrap();
        std::fs::write(lock("2.1.302"), "pid=1\nstarted_at=5\nfinished_at=7\n").unwrap();
        let elsewhere = dir.path().join("elsewhere.lock");
        std::fs::write(&elsewhere, "finished_at=5\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, lock("2.1.304")).unwrap();
        std::fs::create_dir(lock("2.1.305")).unwrap();
        let fifo = std::ffi::CString::new(lock("2.1.306").into_os_string().into_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        // The line's last byte one past the bound (4097 bytes), then right at it (4096): only a bound of exactly 4096
        // bytes (`FINISHED_AT_READ_MAX`) cuts the one's digit and reads the other's. No newline at the end: `lines()`
        // still yields the last line.
        std::fs::write(lock("2.1.307"), format!("{}\nfinished_at=9", "x".repeat(4083))).unwrap();
        std::fs::write(lock("2.1.308"), format!("{}\nfinished_at=9", "x".repeat(4082))).unwrap();
        assert_eq!([lock("2.1.307"), lock("2.1.308")].map(|l| std::fs::metadata(l).unwrap().len()), [4097, 4096]);
        std::fs::write(lock("2.1.309"), [b"finished_at=9\n".as_slice(), &[0xff, 0xfe, b'\n']].concat()).unwrap();
        std::fs::write(p.claude_dir().join("..").join("x.lock"), "finished_at=5\n").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let q = p.clone();
        std::thread::spawn(move || {
            // An admission of 2.1.301 holds its lock while the views read.
            let held = admit::VersionLock::take(&q, "2.1.301").unwrap().expect("the lock is free");
            let got: Vec<(&str, Option<u64>)> = ["2.1.301", "2.1.302", "2.1.303", "2.1.304", "2.1.305", "2.1.306", "2.1.307", "2.1.308", "2.1.309", "../x", "2.1"].into_iter().map(|v| (v, lock_finished_at(&q, v))).collect();
            drop(held);
            let _ = tx.send(got);
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("lock_finished_at waited (on the flock, or on a FIFO without a writer)");
        let want: [(&str, Option<u64>); 11] = [
            ("2.1.301", Some(123)),
            ("2.1.302", Some(7)),
            ("2.1.303", None),
            ("2.1.304", None),
            ("2.1.305", None),
            ("2.1.306", None),
            ("2.1.307", None),
            ("2.1.308", Some(9)),
            ("2.1.309", None),
            ("../x", None),
            ("2.1", None),
        ];
        assert_eq!(got, want);
        assert!(std::fs::symlink_metadata(lock("2.1.303")).is_err(), "a missing lock stays missing");
        assert_eq!(std::fs::read_to_string(lock("2.1.301")).unwrap(), "finished_at=123\noutcome=failed(docker)\n", "read, never written");
    }

    /// S12 (V2, §V2.5): `status` names the retry from the later time, and says it is due now once that has passed
    /// (judged by the `now` its lines are given, at that second too), while `--json` keeps the time itself; in
    /// passthrough no retry is promised, whatever the lock says.
    #[test]
    fn status_says_the_retry_from_the_later_time_or_due_now() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let a = crate::wire::time::parse_rfc3339_utc("2026-10-24T13:50:00Z").unwrap();
        put_docker(&p, "2.1.320", 'a', 1, "2026-10-24T13:50:00Z");
        let clock = RetryClock { now: a + 60, finished: [("2.1.320".to_string(), a + 600)].into() };
        let doc = status_doc(&load_all(&p), None, &[], Some("2.1.305"), true, true, &clock);
        let row = |doc: &serde_json::Value| doc["versions"].as_array().unwrap().iter().find(|r| r["version"] == "2.1.320").unwrap().clone();
        let line = |doc: &serde_json::Value, now: u64| status_lines(doc, now).into_iter().find(|l| l.starts_with("claude 2.1.320: ")).unwrap_or_default();
        assert_eq!(row(&doc)["retry_from"].as_str(), Some("2026-10-24T14:15:00Z"));
        assert_eq!(line(&doc, a + 60), "claude 2.1.320: failed(docker) (test l2_x failed; attempt 1 of 3; an automatic retry from 2026-10-24T14:15:00Z (the next remote wrapper starts it))");
        assert_eq!(line(&doc, a + 1500), "claude 2.1.320: failed(docker) (test l2_x failed; attempt 1 of 3; an automatic retry is due now (the next remote wrapper starts it))");
        assert_eq!(row(&doc)["retry_from"].as_str(), Some("2026-10-24T14:15:00Z"), "the document keeps the time, past or not");
        // Passthrough: no wrapper starts it.
        let off = status_doc(&load_all(&p), None, &[], Some("2.1.305"), true, false, &clock);
        assert_eq!(row(&off)["retry_from"], serde_json::Value::Null);
        assert_eq!(line(&off, a + 1500), "claude 2.1.320: failed(docker) (test l2_x failed; attempt 1 of 3)");
    }
}
