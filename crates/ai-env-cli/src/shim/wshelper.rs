//! `ai-env shim-io` (hidden, feature `shim`; S8 §6): the helper the shim
//! starts as the agent (uid 1000) for every workspace, transcript and
//! settings operation in the VM, so the root shim only authenticates,
//! routes, locks, times out and pipes bodies (invariant 17): every path the
//! agent can write is touched by the agent alone.
//!
//! Each op prints one JSON head line (`wire::workspace::HelperHead`), then
//! an optional payload, and exits 0: a refusal is a head `{"ok":false,
//! "code","message"}` the route answers with its code's status; a non-zero
//! exit is an internal failure (the route answers 500). Every git run is
//! `gitrun::GitRun::vm` with the shim's `--git`; every workspace path is a VM
//! path (absolute, NFC: `vm_path_check`, else 400 `bad_request`), mapped by
//! `--fs-root` as the shim maps it (`ShimState::at`), strictly under
//! `--home` (else 409 `not_creatable`), and reached from `--home` one
//! component at a time, never through a symlink (409 `symlink_component`),
//! each directory it makes created 0700 by the agent. `--home` and
//! `--projects` are the shim's own paths, already on this disk.
//!
//! The shim passes the run's whole budget (`--budget-ms`, from the start;
//! past it the shim ends the helper): every git run is cut to end
//! `reserve` before it (a tenth, at least 3 s), so a run that takes too
//! long is ended by the helper itself and its rollback (whose own git runs
//! may use what is left but `UNDO_MARGIN`, 1 s) comes before the shim's
//! TERM. Only the ops that hold the shim's workspace lock (seed-state,
//! seed-apply, codeout, snapshot) use the inbox, one at a time: each first
//! removes what a run that never ended left in it. A staged pack leaves the
//! inbox once it is open again, before it is indexed or sent.
//!
//! The ops (D7: a manifest line and a shallow pack each way, never a bundle):
//! * `seed-state`: the workspace as D3 decides on it (`SeedState`), given the
//!   shim's record of the last seed (`--record`);
//! * `seed-apply`: stdin is the `PUT /seed` body, a `SeedManifest` line then
//!   the pack, staged under the agent's `HOME/.cache/ai-env/inbox` first.
//!   `clone`: `git init` (no template, the branch, the object format), the
//!   pack indexed, `.git/shallow` the manifest's list (exactly the head),
//!   the refs (the branch or a detached HEAD, `SEED_REF`, `SEED_WIP_REF`),
//!   `reset --hard`, then the WIP applied uncommitted (`read-tree -m -u HEAD
//!   SEED_WIP_REF`, `read-tree` of the index tree, `update-index --refresh`);
//!   no origin ever exists, and a clone that fails leaves nothing behind.
//!   `update` (D3): only a clean checkout whose tip is `--expect` and an
//!   ancestor of the head; the thin pack indexed (`--fix-thin`), the
//!   manifest's boundary commits appended to `.git/shallow`, every new
//!   object checked present, a compare-and-swap ref transaction against the
//!   tip it checked, a two-way checkout, the new WIP applied; a failure
//!   after the transaction rolls it all back, the refs first, then the
//!   files the move wrote. `replace`: only a checkout unchanged since its seed
//!   (pristine), checked out anew the same way. The success head's `state`
//!   carries the new `SeedRecord` the shim keeps;
//! * `codeout`: with `--wip` a snapshot first (below), then a thin pack of the
//!   branches, `refs/wip/*`, `SEED_WIP_REF` (and HEAD when detached) less
//!   what the Mac has (stdin: its haves as JSON): the head's `reply` is the
//!   `CodeoutManifest`, its `len` the pack's size, the pack follows; no
//!   payload when nothing is new (204); over `--max-bytes` 413 `too_large`;
//! * `snapshot` (`/suspend`): the uncommitted work as a `refs/wip/<UTC>-<n>`
//!   commit, built in copies of the index (the agent's own is never
//!   written), regular files and symlinks only, within the caps below (else
//!   skipped with the reason); none when the tree and parents equal the
//!   newest snapshot's or the checkout matches its head; the newest
//!   [`WIP_KEEP`] kept;
//! * `transcript-stat`, `transcript-put`: a transcript under `--projects`
//!   (`transcript_rel_check`'s rel): written 0700 directories, a 0600 temp
//!   file beside it, fsync, the length checked, renamed; a longer VM copy
//!   (also one grown longer while the body came in) is 409 `vm_longer` with
//!   its size, the same bytes 200 `unchanged`;
//! * `settings`: the agent's `settings.json`, the workspace's
//!   `.claude/settings.json` and `.claude/settings.local.json` (each at most
//!   `SETTINGS_FILE_MAX` of text, with its sha256), and the `PROJECT_KEYS` of
//!   the workspace's entry in the agent's `.claude/.claude.json`.
use crate::errors::{CliError, Result};
use crate::gitrun::{GitError, GitRun};
use crate::wire::workspace::{
    budget, head_line, read_head_line, refusal, transcript_rel_check, vm_path_check, CodeoutManifest, HelperHead, ObjectFormat, SeedApplied, SeedManifest, SeedMode, SeedQuery, SeedRecord, SeedReply, SeedState,
    SettingsCapture, SettingsFile, SettingsScope, SnapshotReply, TranscriptReply, TranscriptStat, TranscriptWrite, WsRefusal, HAVES_MAX, HEADS_PREFIX, HEAD_LINE_MAX, PROJECT_KEYS, SEED_BODY_MAX, SEED_REF, SEED_WIP_REF,
    SETTINGS_FILE_MAX, TRANSCRIPT_MAX, WIP_REF_PREFIX,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

/// The ops, as their subcommands are spelled.
pub const OPS: [&str; 7] = ["seed-state", "seed-apply", "codeout", "snapshot", "transcript-stat", "transcript-put", "settings"];

/// Where a body is staged, under the agent's `HOME`.
pub const INBOX: &str = ".cache/ai-env/inbox";
/// A snapshot's caps in the VM, `[seed]`'s defaults on the Mac (the VM gets
/// no config): untracked files carried, bytes hashed in all, bytes of one
/// file. Over any of them the snapshot is skipped and the reason given.
pub const SNAPSHOT_MAX_FILES: usize = 5000;
pub const SNAPSHOT_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const SNAPSHOT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// The `refs/wip/*` snapshots the VM keeps, the newest first (`[seed].keep_wip_refs`' default).
pub const WIP_KEEP: usize = 64;
/// The author and committer of a VM snapshot.
pub const SNAPSHOT_AUTHOR: (&str, &str) = ("ai-env snapshot", "snapshot@ai-env.invalid");
/// The largest `.claude.json` a settings capture reads for its project keys.
const CLAUDE_JSON_MAX: u64 = 16 * 1024 * 1024;
/// What a rollback's git runs leave of the run's budget: the head and the exit.
const UNDO_MARGIN: Duration = Duration::from_secs(1);

/// Of the run's budget, what its forward git runs leave: for a run cut at
/// its end (`gitrun::KILL_AFTER`), the rollback and the head, all before
/// the shim ends the run. A tenth, at least 3 s.
fn reserve(budget: Duration) -> Duration {
    (budget / 10).max(Duration::from_secs(3))
}

/// `ai-env shim-io [--home H] [--fs-root R] [--git G] <op> …`.
#[derive(clap::Args, Debug, Clone)]
pub struct ShimIoArgs {
    /// HOME of the agent: every workspace path must lie under it
    #[arg(long, global = true, value_name = "DIR", default_value = "/Users/mike")]
    pub home: PathBuf,
    /// Prefix for every VM path (native tests)
    #[arg(long, global = true, value_name = "DIR")]
    pub fs_root: Option<PathBuf>,
    /// The git program (absolute; the shim's own `--git`)
    #[arg(long, global = true, value_name = "PATH", default_value = crate::shim::health::GIT_DEFAULT)]
    pub git: PathBuf,
    /// The run's whole budget in milliseconds (the shim ends the helper past it): every git run is cut to end before it
    #[arg(long, global = true, value_name = "MS")]
    pub budget_ms: Option<u64>,
    #[command(subcommand)]
    pub op: ShimIoOp,
}

/// One helper operation; the route that starts it in parentheses.
#[derive(clap::Subcommand, Debug, Clone)]
pub enum ShimIoOp {
    /// The workspace at PATH: seeded or not, its tip, clean or not, unchanged since its seed or not (GET /seed)
    SeedState {
        /// The workspace's path in the VM (absolute, NFC)
        #[arg(long)]
        path: String,
        /// The shim's record of the last seed (JSON), when the VM was seeded
        #[arg(long, value_name = "JSON")]
        record: Option<String>,
    },
    /// Clone, update or replace the workspace at PATH from stdin: one manifest line, then the pack (PUT /seed)
    SeedApply {
        /// The workspace's path in the VM (absolute, NFC)
        #[arg(long)]
        path: String,
        /// clone (the first seed), update (a fast-forward of a clean VM) or replace (a VM unchanged since its seed)
        #[arg(long, value_parser = ["clone", "update", "replace"])]
        mode: String,
        /// The branch to check out
        #[arg(long, value_name = "B", required_unless_present = "detached", conflicts_with = "detached")]
        branch: Option<String>,
        /// Check the seeded commit out detached
        #[arg(long)]
        detached: bool,
        /// The VM's tip an update or a replace expects (compare and swap)
        #[arg(long, value_name = "SHA")]
        expect: Option<String>,
        /// The body's length in bytes
        #[arg(long, value_name = "N")]
        len: u64,
        /// The shim's record of the last seed (JSON): an update's and a replace's
        #[arg(long, value_name = "JSON")]
        record: Option<String>,
    },
    /// With --wip, snapshot the uncommitted changes into refs/wip/*; then pack what the Mac lacks (stdin: its haves as JSON; stdout: a manifest line, then the pack) (POST /codeout)
    Codeout {
        /// The workspace's path in the VM (absolute, NFC)
        #[arg(long)]
        path: String,
        /// Snapshot the uncommitted changes first
        #[arg(long)]
        wip: bool,
        /// The largest pack the reply may carry (more is refused)
        #[arg(long, value_name = "N")]
        max_bytes: u64,
    },
    /// Snapshot the uncommitted changes into a refs/wip/* ref (the /suspend hook)
    Snapshot {
        /// The workspace's path in the VM (absolute, NFC)
        #[arg(long)]
        path: String,
        /// The budget in seconds
        #[arg(long, value_name = "S", default_value_t = 8)]
        budget_s: u64,
    },
    /// Presence, size and sha256 of the transcript REL under PROJECTS (GET /transcript)
    TranscriptStat {
        /// The agent's projects directory
        #[arg(long, value_name = "DIR")]
        projects: PathBuf,
        /// The transcript's path under it (slug/uuid.jsonl, or slug/uuid/…)
        #[arg(long)]
        rel: String,
    },
    /// Write the transcript REL under PROJECTS from stdin, N bytes (PUT /transcript)
    TranscriptPut {
        /// The agent's projects directory
        #[arg(long, value_name = "DIR")]
        projects: PathBuf,
        /// The transcript's path under it (slug/uuid.jsonl, or slug/uuid/…)
        #[arg(long)]
        rel: String,
        /// The body's length in bytes
        #[arg(long, value_name = "N")]
        len: u64,
    },
    /// The agent's settings.json, the workspace's .claude/settings.json and settings.local.json, and the allowlisted keys of PATH's entry under projects in .claude.json (GET /settings)
    Settings {
        /// The workspace's path in the VM (absolute, NFC)
        #[arg(long)]
        path: String,
    },
}

impl ShimIoOp {
    /// The op's name, one of [`OPS`].
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            ShimIoOp::SeedState { .. } => OPS[0],
            ShimIoOp::SeedApply { .. } => OPS[1],
            ShimIoOp::Codeout { .. } => OPS[2],
            ShimIoOp::Snapshot { .. } => OPS[3],
            ShimIoOp::TranscriptStat { .. } => OPS[4],
            ShimIoOp::TranscriptPut { .. } => OPS[5],
            ShimIoOp::Settings { .. } => OPS[6],
        }
    }
}

/// `ai-env shim-io …` (dispatched before the keystore: the helper runs with
/// the environment the shim gives it). The head goes to stdout, then the
/// payload; an internal failure is exit 1 with one `ai-env:` line.
pub fn run(args: ShimIoArgs) -> Result<()> {
    let ctx = Ctx::new(&args);
    let stdin = io::stdin();
    let mut input = io::BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut out = stdout.lock();
    dispatch(&ctx, &args.op, &mut input, &mut out)
}

/// Run `op`, writing its head (and payload) to `out`.
fn dispatch(ctx: &Ctx, op: &ShimIoOp, input: &mut dyn BufRead, out: &mut dyn Write) -> Result<()> {
    if matches!(op, ShimIoOp::SeedState { .. } | ShimIoOp::SeedApply { .. } | ShimIoOp::Codeout { .. } | ShimIoOp::Snapshot { .. }) {
        ctx.clear_inbox();
    }
    match op {
        ShimIoOp::SeedState { path, record } => {
            let record = parse_record(record.as_deref())?;
            answer(out, ctx.seed_state(path, record.as_ref()))
        }
        ShimIoOp::SeedApply { path, mode, branch, detached, expect, len, record } => {
            let mode = match mode.as_str() {
                "clone" => SeedMode::Clone,
                "update" => SeedMode::Update,
                _ => SeedMode::Replace,
            };
            let q = SeedQuery { path: path.clone(), mode, branch: branch.clone(), detached: *detached, expect: expect.clone() };
            let record = parse_record(record.as_deref())?;
            match ctx.seed_apply(&q, *len, record.as_ref(), input) {
                Ok((reply, state)) => emit(out, &HelperHead { state: Some(state), ..HelperHead::ok(reply, None) }),
                Err(stop) => refused::<SeedReply>(out, stop),
            }
        }
        ShimIoOp::Codeout { path, wip, max_bytes } => match ctx.codeout(path, *wip, *max_bytes, input) {
            Ok(Codeout { manifest, pack: None }) => emit(out, &HelperHead::ok(manifest, None)),
            Ok(Codeout { manifest, pack: Some((file, len)) }) => {
                // The pack leaves the inbox before a byte goes out: a helper ended mid-payload leaves nothing.
                let mut f = file.reopen()?;
                drop(file);
                emit(out, &HelperHead::ok(manifest, Some(len)))?;
                let copied = io::copy(&mut (&mut f).take(len), out)?;
                out.flush()?;
                if copied != len {
                    return Err(CliError::Msg(format!("the staged pack is {copied} bytes, not {len}")));
                }
                Ok(())
            }
            Err(stop) => refused::<CodeoutManifest>(out, stop),
        },
        ShimIoOp::Snapshot { path, budget_s } => answer(out, ctx.snapshot(path, Duration::from_secs(*budget_s))),
        ShimIoOp::TranscriptStat { projects, rel } => answer(out, ctx.transcript_stat(projects, rel)),
        ShimIoOp::TranscriptPut { projects, rel, len } => answer(out, ctx.transcript_put(projects, rel, *len, input)),
        ShimIoOp::Settings { path } => answer(out, ctx.settings(path)),
    }
}

fn parse_record(text: Option<&str>) -> Result<Option<SeedRecord>> {
    text.map(|t| serde_json::from_str(t).map_err(|e| CliError::Usage(format!("--record is not a seed record: {e}")))).transpose()
}

/// The head of `step`: its reply, or its refusal; a failure is the helper's exit 1.
fn answer<T: Serialize>(out: &mut dyn Write, step: Step<T>) -> Result<()> {
    match step {
        Ok(reply) => emit(out, &HelperHead::ok(reply, None)),
        Err(stop) => refused::<T>(out, stop),
    }
}

fn refused<T: Serialize>(out: &mut dyn Write, stop: Stop) -> Result<()> {
    match stop {
        Stop::Refused(r) => emit(out, &HelperHead::<T>::refused(*r)),
        Stop::Failed(e) => Err(e),
    }
}

fn emit<T: Serialize>(out: &mut dyn Write, head: &HelperHead<T>) -> Result<()> {
    out.write_all(&head_line(head)?)?;
    out.flush()?;
    Ok(())
}

// ---- refusals and failures ---------------------------------------------------------------

/// Why an op gave no reply: a refusal (its head says so, exit 0) or an
/// internal failure (exit 1).
#[derive(Debug)]
enum Stop {
    Refused(Box<WsRefusal>),
    Failed(CliError),
}

impl Stop {
    fn refused(r: WsRefusal) -> Stop {
        Stop::Refused(Box::new(r))
    }
}

type Step<T> = std::result::Result<T, Stop>;

fn refuse<T>(code: &str, message: &str) -> Step<T> {
    Err(Stop::refused(WsRefusal::new(code, message)))
}

impl From<io::Error> for Stop {
    fn from(e: io::Error) -> Stop {
        Stop::Failed(CliError::Msg(e.to_string()))
    }
}

/// A git run that failed at `step`: 504 `timeout` when it outlived its
/// budget, else 500 `git_failed` naming the step and git's last lines.
fn git_stop(step: &str) -> impl FnOnce(GitError) -> Stop + '_ {
    move |e| match e {
        GitError::Timeout { .. } => Stop::refused(WsRefusal::new(refusal::TIMEOUT, &format!("git {step} did not finish within its budget"))),
        other => Stop::refused(WsRefusal::new(refusal::GIT_FAILED, &format!("git {step}: {other}"))),
    }
}

/// A failed run's refusal: 504 `timeout` ([`git_stop`]) when it was cut at
/// its budget, else what `other` makes of the failure.
fn cut_or(step: &str, e: GitError, other: impl FnOnce(&GitError) -> Stop) -> Stop {
    if matches!(e, GitError::Timeout { .. }) {
        git_stop(step)(e)
    } else {
        other(&e)
    }
}

/// git's last stderr lines of a failure, for a refusal of another code.
fn git_said(e: &GitError) -> String {
    match e {
        GitError::Failed { stderr, .. } if !stderr.is_empty() => stderr.replace('\n', " | "),
        other => other.to_string(),
    }
}

/// `Ok(None)` for a run that answered "no" with exit 1 (`rev-parse --verify -q`, `symbolic-ref -q`).
fn no_on_1(r: std::result::Result<Vec<u8>, GitError>) -> std::result::Result<Option<Vec<u8>>, GitError> {
    match r {
        Ok(out) => Ok(Some(out)),
        Err(GitError::Failed { code: Some(1), .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

// ---- the context ---------------------------------------------------------------------------

struct Ctx {
    home: PathBuf,
    fs_root: Option<PathBuf>,
    git: PathBuf,
    started: Instant,
    /// The run's whole budget from `started` (`--budget-ms`); `None`: each git run its step's only.
    budget: Option<Duration>,
}

impl Ctx {
    fn new(args: &ShimIoArgs) -> Ctx {
        Ctx { home: args.home.clone(), fs_root: args.fs_root.clone(), git: args.git.clone(), started: Instant::now(), budget: args.budget_ms.map(Duration::from_millis) }
    }

    /// `step`, cut to what is left of the run's budget with `keep` of it held back.
    fn cut(&self, step: Duration, keep: Duration) -> Duration {
        match self.budget {
            Some(b) => step.min(b.saturating_sub(keep).saturating_sub(self.started.elapsed())),
            None => step,
        }
    }

    fn ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// A VM path on this disk: under `--fs-root` when set (`ShimState::at`).
    fn at(&self, vm: &str) -> PathBuf {
        let path = Path::new(vm);
        match &self.fs_root {
            Some(root) => root.join(path.strip_prefix("/").unwrap_or(path)),
            None => path.to_path_buf(),
        }
    }

    /// A path on this disk as the VM names it (for a message).
    fn shown(&self, disk: &Path) -> String {
        match self.fs_root.as_deref().and_then(|r| disk.strip_prefix(r).ok()) {
            Some(rest) => format!("/{}", rest.display()),
            None => disk.display().to_string(),
        }
    }

    /// A git run in `cwd` as the agent: the VM's rules, the shim's `--git`,
    /// no optional lock taken (a `status` never rewrites the agent's index),
    /// its timeout `step` cut to end [`reserve`] before the run's budget.
    fn git_in(&self, cwd: &Path, step: Duration) -> GitRun {
        let keep = self.budget.map_or(Duration::ZERO, reserve);
        self.vm_git(cwd).timeout(self.cut(step, keep))
    }

    /// A rollback's git run in `cwd`: it may use what the forward runs
    /// left of the budget, all but [`UNDO_MARGIN`].
    fn undo_in(&self, cwd: &Path, step: Duration) -> GitRun {
        self.vm_git(cwd).timeout(self.cut(step, UNDO_MARGIN))
    }

    fn vm_git(&self, cwd: &Path) -> GitRun {
        GitRun::vm(cwd, &self.home).with_program(&self.git).env("GIT_OPTIONAL_LOCKS", "0")
    }

    /// The workspace at the VM path `vm`: [`vm_path_check`] (400), strictly
    /// under `--home` (409 `not_creatable`), walked without following a
    /// symlink and, with `create`, made. `None`: absent (without `create`).
    fn workspace(&self, vm: &str, create: bool) -> Step<Option<Walked>> {
        if let Err(e) = vm_path_check(vm) {
            return refuse(refusal::BAD_REQUEST, &format!("the workspace path {e}"));
        }
        let disk = self.at(vm);
        self.walk(&disk, create, "the workspace path")
    }

    /// `target` (on this disk) strictly under `--home`, reached from it one
    /// component at a time ([`walk_under`]).
    fn walk(&self, target: &Path, create: bool, what: &str) -> Step<Option<Walked>> {
        let Some(rest) = target.strip_prefix(&self.home).ok().filter(|r| r.components().next().is_some()) else {
            return refuse(refusal::NOT_CREATABLE, &format!("{what} {} is not under the agent's home {}: the agent cannot create it", self.shown(target), self.shown(&self.home)));
        };
        walk_under(&self.home, rest, create).map_err(|w| w.stop(self, what))
    }

    /// The inbox, made when missing.
    fn inbox(&self) -> Step<Walked> {
        let inbox = self.home.join(INBOX);
        self.walk(&inbox, true, "the inbox")?.ok_or_else(|| Stop::Failed(CliError::Msg("the inbox was not made".into())))
    }

    /// A 0600 file in the inbox, removed when dropped.
    fn staged(&self, prefix: &str) -> Step<tempfile::NamedTempFile> {
        let inbox = self.inbox()?;
        Ok(tempfile::Builder::new().prefix(prefix).tempfile_in(&inbox.path)?)
    }

    /// Remove what a run that never ended (ended by the shim, its client
    /// gone) left in the inbox: only the ops holding the shim's workspace
    /// lock use it, one at a time, so at their start nothing in it is anyone's.
    fn clear_inbox(&self) {
        let Ok(Some(inbox)) = self.walk(&self.home.join(INBOX), false, "the inbox") else { return };
        let Ok(entries) = std::fs::read_dir(&inbox.path) else { return };
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| !t.is_dir()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

// ---- walking paths as the agent ------------------------------------------------------------

/// A directory reached without following a symlink, and the directories
/// the walk made on the way (top down).
struct Walked {
    fd: OwnedFd,
    path: PathBuf,
    created: Vec<PathBuf>,
}

/// Why a walk stopped.
enum WalkStop {
    /// A component is a symlink (the agent planted it).
    Symlink(PathBuf),
    /// Something that is not a directory is where one is needed.
    NotDir(PathBuf),
    /// The agent may not open or create it.
    Denied(PathBuf, io::Error),
    Io(PathBuf, io::Error),
}

impl WalkStop {
    fn stop(self, ctx: &Ctx, what: &str) -> Stop {
        match self {
            WalkStop::Symlink(p) => Stop::refused(WsRefusal::new(
                refusal::SYMLINK_COMPONENT,
                // The remedy before the path: a line cut short (Cursor's) keeps it.
                &format!("a component of {what} is a symlink, which the VM never follows: remove it in the VM, or terminate the VM and seed a new one ({})", ctx.shown(&p)),
            )),
            WalkStop::NotDir(p) => Stop::refused(WsRefusal::new(refusal::PATH_OCCUPIED, &format!("{what}'s component {} is not a directory", ctx.shown(&p)))),
            WalkStop::Denied(p, e) => Stop::refused(WsRefusal::new(refusal::NOT_CREATABLE, &format!("the agent cannot create or enter {} ({e})", ctx.shown(&p)))),
            WalkStop::Io(p, e) => Stop::Failed(CliError::Msg(format!("{}: {e}", ctx.shown(&p)))),
        }
    }
}

fn cstr(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path component holds a NUL byte"))
}

/// `open(2)` of `base` (followed: the shim's own `--home`) as a directory.
fn open_base(base: &Path) -> io::Result<OwnedFd> {
    let c = cstr(base.as_os_str())?;
    // SAFETY: a NUL-terminated path and plain flags; a non-negative result is a new fd we own.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just opened, owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `openat(2)` of the directory `name` under `dir`, never following a symlink.
fn open_dir_at(dir: &OwnedFd, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: a valid directory fd, a NUL-terminated name, plain flags.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just opened, owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The file type bits of `name` under `dir` itself (`AT_SYMLINK_NOFOLLOW`).
fn kind_at(dir: &OwnedFd, name: &CStr) -> io::Result<libc::mode_t> {
    // SAFETY: an all-zero stat is a valid value for fstatat to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid directory fd, a NUL-terminated name, a stat to fill.
    if unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.st_mode & libc::S_IFMT)
}

/// From the directory `base` (opened as it is), each component of the
/// relative `rest` opened with `O_NOFOLLOW`: a symlink or a non-directory
/// stops the walk; a missing one is made 0700 by this process (the agent)
/// with `create`, else the walk answers `None`.
fn walk_under(base: &Path, rest: &Path, create: bool) -> std::result::Result<Option<Walked>, WalkStop> {
    let mut fd = open_base(base).map_err(|e| classify(base.to_path_buf(), e))?;
    let mut path = base.to_path_buf();
    let mut created = Vec::new();
    for comp in rest.components() {
        let Component::Normal(name) = comp else {
            return Err(WalkStop::Io(path, io::Error::new(io::ErrorKind::InvalidInput, "a path component is not a plain name")));
        };
        path.push(name);
        let c = cstr(name).map_err(|e| WalkStop::Io(path.clone(), e))?;
        let next = match open_dir_at(&fd, &c) {
            Ok(next) => next,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                if !create {
                    return Ok(None);
                }
                // SAFETY: a valid directory fd, a NUL-terminated name, a mode.
                if unsafe { libc::mkdirat(fd.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::EEXIST) {
                        return Err(classify(path, e));
                    }
                } else {
                    created.push(path.clone());
                }
                open_dir_at(&fd, &c).map_err(|e| why_not_dir(&fd, &c, path.clone(), e))?
            }
            Err(e) => return Err(why_not_dir(&fd, &c, path, e)),
        };
        fd = next;
    }
    Ok(Some(Walked { fd, path, created }))
}

/// Why `name` under `dir` did not open as a directory.
fn why_not_dir(dir: &OwnedFd, name: &CStr, path: PathBuf, e: io::Error) -> WalkStop {
    match kind_at(dir, name) {
        Ok(libc::S_IFLNK) => WalkStop::Symlink(path),
        Ok(libc::S_IFDIR) => classify(path, e),
        Ok(_) => WalkStop::NotDir(path),
        Err(_) => classify(path, e),
    }
}

fn classify(path: PathBuf, e: io::Error) -> WalkStop {
    match e.raw_os_error() {
        Some(libc::EACCES | libc::EPERM | libc::EROFS) => WalkStop::Denied(path, e),
        Some(libc::ENOTDIR) => WalkStop::NotDir(path),
        Some(libc::ELOOP) => WalkStop::Symlink(path),
        _ => WalkStop::Io(path, e),
    }
}

/// Remove what a failed clone made: the target's content, the target and
/// the parents when the walk made them (the deepest first).
fn undo_clone(w: &Walked) {
    if w.created.last() == Some(&w.path) {
        let _ = std::fs::remove_dir_all(&w.path);
    } else if let Ok(entries) = std::fs::read_dir(&w.path) {
        for e in entries.flatten() {
            let p = e.path();
            let _ = if e.file_type().is_ok_and(|t| t.is_dir()) { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
        }
    }
    for dir in w.created.iter().rev().filter(|d| **d != w.path) {
        let _ = std::fs::remove_dir(dir);
    }
}

// ---- the repository ------------------------------------------------------------------------

/// The checkout's state now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Facts {
    tip: Option<String>,
    branch: Option<String>,
    clean: bool,
}

/// The trees of a snapshot: the head, the index (`None`: unmerged), the worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Trees {
    head: String,
    head_tree: String,
    index: Option<String>,
    worktree: String,
}

/// One workspace's repository, its git runs within one budget.
struct Repo<'a> {
    ctx: &'a Ctx,
    dir: PathBuf,
    budget: Duration,
}

impl Repo<'_> {
    /// A forward run (each run its own: its timeout is cut when it starts).
    fn git(&self) -> GitRun {
        self.ctx.git_in(&self.dir, self.budget)
    }

    /// A rollback's run ([`Ctx::undo_in`]).
    fn undo(&self) -> GitRun {
        self.ctx.undo_in(&self.dir, self.budget)
    }

    /// A run on another index file (a copy: the agent's index is never written).
    fn git_on(&self, index: &Path) -> GitRun {
        self.git().env("GIT_INDEX_FILE", index)
    }

    /// Is there a repository here (a `.git` directory, as a seed makes it)?
    fn exists(&self) -> bool {
        std::fs::symlink_metadata(self.dir.join(".git")).is_ok_and(|m| m.is_dir())
    }

    /// The commit `spec` names; `None` when it names none.
    fn commit(&self, spec: &str) -> Step<Option<String>> {
        let out = no_on_1(self.git().output(["rev-parse", "--verify", "-q", &format!("{spec}^{{commit}}")])).map_err(git_stop("rev-parse"))?;
        Ok(out.map(|o| text(&o)).filter(|t| !t.is_empty()))
    }

    fn tree_of(&self, commit: &str) -> Step<String> {
        Ok(text(&self.git().output(["rev-parse", "--verify", &format!("{commit}^{{tree}}")]).map_err(git_stop("rev-parse"))?))
    }

    /// The branch checked out; `None` when detached (or HEAD names no branch).
    fn branch(&self) -> Step<Option<String>> {
        let out = no_on_1(self.git().output(["symbolic-ref", "-q", "HEAD"])).map_err(git_stop("symbolic-ref"))?;
        Ok(out.and_then(|o| text(&o).strip_prefix(HEADS_PREFIX).map(str::to_string)))
    }

    /// Nothing to commit: no change to a tracked file, staged or not, and no
    /// untracked file that is not ignored (whatever the repository's config says).
    fn clean(&self) -> Step<bool> {
        let out = self.git().output(["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]).map_err(git_stop("status"))?;
        Ok(out.is_empty())
    }

    fn facts(&self) -> Step<Facts> {
        if !self.exists() {
            return Ok(Facts::default());
        }
        let tip = self.commit("HEAD")?;
        let branch = self.branch()?;
        let clean = tip.is_some() && self.clean()?;
        Ok(Facts { tip, branch, clean })
    }

    /// A file of the git dir (`rev-parse --git-path`), absolute.
    fn git_path(&self, name: &str) -> Step<PathBuf> {
        let p = PathBuf::from(text(&self.git().output(["rev-parse", "--git-path", name]).map_err(git_stop("rev-parse"))?));
        Ok(if p.is_absolute() { p } else { self.dir.join(p) })
    }

    /// A copy of the agent's index in the inbox (empty when it has none).
    fn index_copy(&self) -> Step<tempfile::NamedTempFile> {
        let copy = self.ctx.staged("index-")?;
        let index = self.git_path("index")?;
        match std::fs::read(&index) {
            Ok(bytes) => std::fs::write(copy.path(), bytes)?,
            // No index: an empty one (git reads a missing or empty file as none).
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(copy)
    }

    /// The snapshot trees ([`Trees`]), each built in a copy of the index:
    /// the tracked changes (`add -u`) and the untracked files that are not
    /// ignored, regular files and symlinks only (a nested repository, a fifo
    /// or a socket stays out), within the snapshot caps. `Err(why)` when it
    /// is skipped (over a cap, no commit checked out).
    fn trees(&self) -> Step<std::result::Result<Trees, String>> {
        let Some(head) = self.commit("HEAD")? else { return Ok(Err("the checkout has no commit (HEAD)".into())) };
        let head_tree = self.tree_of(&head)?;
        let staged = self.index_copy()?;
        let index = match self.git_on(staged.path()).output(["write-tree"]) {
            Ok(t) => Some(text(&t)),
            Err(GitError::Failed { .. }) => None,
            Err(e) => return Err(git_stop("write-tree")(e)),
        };
        let work = self.index_copy()?;
        let git = || self.git_on(work.path());
        let listed = git().output(["ls-files", "-z", "--others", "--exclude-standard"]).map_err(git_stop("ls-files"))?;
        let changed = git().output(["diff", "--name-only", "-z", "--no-renames"]).map_err(git_stop("diff"))?;
        let mut carried: Vec<&[u8]> = Vec::new();
        let mut bytes = 0u64;
        for path in listed.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            if path.ends_with(b"/") {
                // A nested repository: never carried.
                continue;
            }
            let Ok(md) = std::fs::symlink_metadata(self.dir.join(OsStr::from_bytes(path))) else { continue };
            if !(md.is_file() || md.file_type().is_symlink()) {
                continue;
            }
            if md.is_file() && md.len() > SNAPSHOT_MAX_FILE_BYTES {
                return Ok(Err(format!("an untracked file is {} MiB (at most {} MiB)", md.len() >> 20, SNAPSHOT_MAX_FILE_BYTES >> 20)));
            }
            bytes = bytes.saturating_add(md.len());
            carried.push(path);
        }
        if carried.len() > SNAPSHOT_MAX_FILES {
            return Ok(Err(format!("{} untracked files (at most {SNAPSHOT_MAX_FILES})", carried.len())));
        }
        for path in changed.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            if let Ok(md) = std::fs::symlink_metadata(self.dir.join(OsStr::from_bytes(path))) {
                bytes = bytes.saturating_add(md.len());
            }
        }
        if bytes > SNAPSHOT_MAX_BYTES {
            return Ok(Err(format!("the uncommitted changes are {} MiB (at most {} MiB)", bytes >> 20, SNAPSHOT_MAX_BYTES >> 20)));
        }
        git().output(["add", "-u"]).map_err(git_stop("add -u"))?;
        if !carried.is_empty() {
            let mut list = Vec::new();
            for p in &carried {
                list.extend_from_slice(p);
                list.push(0);
            }
            // The names as they are, never pathspec magic (`:!x`, `:(top)`, `:w`), as the Mac's snapshot takes them.
            git().output_stdin(["--literal-pathspecs", "add", "--pathspec-from-file=-", "--pathspec-file-nul"], &list).map_err(git_stop("add"))?;
        }
        let worktree = text(&git().output(["write-tree"]).map_err(git_stop("write-tree"))?);
        Ok(Ok(Trees { head, head_tree, index, worktree }))
    }

    /// The pack read from `pack` indexed into the repository (`--fix-thin`
    /// for a thin one): 422 `missing_prerequisites` when a delta's base is
    /// missing, else 422 `bad_pack` for anything git cannot index.
    fn index_pack(&self, mut pack: std::fs::File, thin: bool) -> Step<()> {
        let mut args = vec!["index-pack", "--stdin"];
        if thin {
            args.push("--fix-thin");
        }
        let mut child = self.git().spawn_piped(args).map_err(git_stop("index-pack"))?;
        let mut stdin = child.take_stdin().ok_or_else(|| Stop::Failed(CliError::Msg("index-pack has no stdin".into())))?;
        let feeder = std::thread::Builder::new().name("index-pack stdin".into()).spawn(move || {
            // A run that stops reading closes the pipe: its exit says why.
            let _ = io::copy(&mut pack, &mut stdin);
        })?;
        let done = child.finish();
        let _ = feeder.join();
        match done {
            Ok(()) => Ok(()),
            Err(GitError::Timeout { .. }) => refuse(refusal::TIMEOUT, "git index-pack did not finish within its budget"),
            Err(e) => {
                let said = git_said(&e);
                // "pack has N unresolved deltas"; a cut pack's "bytes missing" is a bad pack.
                if said.contains("unresolved delta") {
                    refuse(refusal::MISSING_PREREQUISITES, &format!("the pack needs objects the VM lacks: {said}"))
                } else {
                    refuse(refusal::BAD_PACK, &format!("the pack does not index: {said}"))
                }
            }
        }
    }

    /// Every id in `ids` a commit of the repository: 422 `bad_refs` otherwise.
    fn all_commits(&self, ids: &BTreeSet<&str>) -> Step<()> {
        let mut input = Vec::new();
        for id in ids {
            input.extend_from_slice(id.as_bytes());
            input.push(b'\n');
        }
        let out = self.git().output_stdin(["cat-file", "--batch-check=%(objectname) %(objecttype)"], &input).map_err(git_stop("cat-file"))?;
        let found: BTreeMap<String, String> = String::from_utf8_lossy(&out).lines().filter_map(|l| l.split_once(' ')).map(|(a, b)| (a.to_string(), b.to_string())).collect();
        if let Some(id) = ids.iter().find(|id| found.get(**id).map(String::as_str) != Some("commit")) {
            return refuse(refusal::BAD_REFS, &format!("the manifest names {id}, which is no commit of the pack or the VM"));
        }
        Ok(())
    }

    /// Every object the new `tips` reach, less what `have` reaches, is in the
    /// repository (`rev-list --objects` reads every commit and tree on the
    /// way and stops at a missing one; each listed id is then checked
    /// present): otherwise 422, `missing_prerequisites` for an update's thin
    /// pack (`have` its base), `bad_pack` for a first seed's.
    fn all_present(&self, tips: &[&str], have: Option<&str>) -> Step<()> {
        let code = if have.is_some() { refusal::MISSING_PREREQUISITES } else { refusal::BAD_PACK };
        let mut args: Vec<String> = vec!["rev-list".into(), "--objects".into()];
        args.extend(tips.iter().map(|t| (*t).to_string()));
        if let Some(h) = have {
            args.push("--not".into());
            args.push(h.to_string());
        }
        let listed = match self.git().output(&args) {
            Ok(out) => out,
            Err(GitError::Timeout { .. }) => return refuse(refusal::TIMEOUT, "git rev-list did not finish within its budget"),
            Err(e) => return refuse(code, &format!("the seed's objects are incomplete in the VM: {}", git_said(&e))),
        };
        let mut ids = Vec::new();
        for line in listed.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            ids.extend_from_slice(line.split(|b| *b == b' ').next().unwrap_or(line));
            ids.push(b'\n');
        }
        if ids.is_empty() {
            return Ok(());
        }
        let out = self.git().output_stdin(["cat-file", "--batch-check=%(objectname) %(objecttype)"], &ids).map_err(git_stop("cat-file"))?;
        if let Some(line) = String::from_utf8_lossy(&out).lines().find(|l| l.ends_with(" missing")) {
            return refuse(code, &format!("the pack lacks object {}", line.split(' ').next().unwrap_or("?")));
        }
        Ok(())
    }

    fn read_shallow(&self) -> Step<(PathBuf, Option<Vec<u8>>)> {
        let path = self.git_path("shallow")?;
        match std::fs::read(&path) {
            Ok(b) => Ok((path, Some(b))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((path, None)),
            Err(e) => Err(e.into()),
        }
    }

    /// `.git/shallow` as `old` plus `add` (sorted, one id a line), written
    /// beside it and renamed into place.
    fn add_shallow(&self, path: &Path, old: Option<&[u8]>, add: &[String]) -> Step<()> {
        let mut ids: BTreeSet<String> = old.map(|b| String::from_utf8_lossy(b).lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect()).unwrap_or_default();
        ids.extend(add.iter().cloned());
        let body: String = ids.iter().map(|i| format!("{i}\n")).collect();
        write_beside(path, body.as_bytes())?;
        Ok(())
    }

    /// Put `.git/shallow` back as it was.
    fn restore_shallow(&self, path: &Path, old: Option<&[u8]>) {
        let _ = match old {
            Some(b) => write_beside(path, b),
            None => std::fs::remove_file(path).or_else(|e| if e.kind() == io::ErrorKind::NotFound { Ok(()) } else { Err(e) }),
        };
    }

    /// One `update-ref --stdin` transaction of `lines` (all or nothing).
    fn refs(&self, lines: &[String]) -> std::result::Result<(), GitError> {
        transaction(&self.git(), lines)
    }

    /// The ref `name`'s commit, `None` when absent.
    fn ref_target(&self, name: &str) -> Step<Option<String>> {
        let out = no_on_1(self.git().output(["rev-parse", "--verify", "-q", name])).map_err(git_stop("rev-parse"))?;
        Ok(out.map(|o| text(&o)).filter(|t| !t.is_empty()))
    }

    /// The WIP applied uncommitted over the head checked out: the worktree
    /// becomes the WIP's tree, the index the index commit's (else the
    /// head's), the stat info refreshed. Untracked files stay untracked.
    fn apply_wip(&self, head: &str, wip: Option<&str>, index: Option<&str>) -> std::result::Result<(), GitError> {
        let Some(wip) = wip else { return Ok(()) };
        self.git().output(["read-tree", "-m", "-u", head, wip])?;
        self.git().output(["read-tree", index.unwrap_or(head)])?;
        self.git().output(["update-index", "-q", "--refresh"]).map(|_| ())
    }

    /// Put the checkout back at `from` after a move that stopped part way
    /// (its two-way checkout failed or was cut at the budget, or a WIP did
    /// not apply after it): the index becomes `from`'s; of the paths `from`
    /// and a tree the move wrote (`wrote`) differ in, each whose file is
    /// that tree's version (the move wrote it) or is gone is put back as
    /// `from` has it, or removed when `from` lacks it. Any other file stays
    /// as it is, so an edit the agent made meanwhile is never lost (nor is
    /// one git left half written, nor a directory with files in it where
    /// `from` has a file): the VM then reads dirty, never as a moved tip.
    /// Only an edit of the agent's that made a file that tree's version, or
    /// removed it, cannot be told from the move's and goes back too. Unlike
    /// `read-tree --reset -u`, no other path is touched. Best effort, with
    /// the rollback's runs ([`Repo::undo`]).
    fn restore_checkout(&self, from: &str, wrote: &[&str]) {
        // Per path: whether `from` has it, and whether the move wrote it.
        let mut paths: BTreeMap<Vec<u8>, (bool, bool)> = BTreeMap::new();
        for tree in wrote {
            let Ok(raw) = self.undo().output(["diff-tree", "-r", "-z", "--no-renames", from, tree]) else { continue };
            // Per path ":<from's mode> <tree's mode> <from's id> <tree's id> <status>", NUL, the path, NUL.
            let mut entries = Vec::new();
            let mut fields = raw.split(|b| *b == 0);
            while let (Some(head), Some(path)) = (fields.next(), fields.next()) {
                let words: Vec<&[u8]> = head.split(|b| *b == b' ').collect();
                let [from_mode, mode, _, id, _] = words[..] else { continue };
                paths.entry(path.to_vec()).or_insert((from_mode != b":000000", false));
                if mode != b"000000" {
                    for part in [mode, b" ", id, b"\t", path, b"\0"] {
                        entries.extend_from_slice(part);
                    }
                }
            }
            for path in self.files_as_in(&entries) {
                if let Some(seen) = paths.get_mut(&path) {
                    seen.1 = true;
                }
            }
        }
        // A one-way merge without `-u`: an entry it keeps keeps its stat data,
        // so the refresh below hashes only the files that changed (a plain
        // `read-tree` drops it all: the whole worktree hashed again within
        // the rollback's time, and no stat data left if that refresh is cut).
        let _ = self.undo().output(["read-tree", "--reset", from]);
        // What `from` lacks first: a directory the move made where `from` has a file may then be empty.
        for (path, _) in paths.iter().filter(|(_, (in_from, wrote))| !*in_from && *wrote) {
            self.remove_written(path);
        }
        let mut back = Vec::new();
        for (path, (_, wrote)) in paths.iter().filter(|(_, (in_from, _))| *in_from) {
            let disk = self.dir.join(OsStr::from_bytes(path));
            let put_back = match std::fs::symlink_metadata(&disk) {
                Err(_) => true,
                // checkout-index -f would remove the directory with all in it: only an empty one goes.
                Ok(md) if md.is_dir() => std::fs::remove_dir(&disk).is_ok(),
                Ok(_) => *wrote,
            };
            if put_back {
                back.extend_from_slice(path);
                back.push(0);
            }
        }
        if !back.is_empty() {
            let _ = self.undo().output_stdin(["checkout-index", "-f", "-z", "--stdin"], &back);
        }
        let _ = self.undo().output(["update-index", "-q", "--refresh"]);
    }

    /// Of the index `entries` (`update-index -z --index-info` records), the
    /// paths whose file holds that entry's version, as git compares them (its
    /// filters applied): a scratch index of them in the inbox, refreshed, then
    /// `diff-files`. None when a run fails.
    fn files_as_in(&self, entries: &[u8]) -> BTreeSet<Vec<u8>> {
        let mut same = BTreeSet::new();
        if entries.is_empty() {
            return same;
        }
        let Ok(scratch) = self.ctx.staged("index-") else { return same };
        // git makes the index itself: an empty file is no index of its.
        if std::fs::remove_file(scratch.path()).is_err() {
            return same;
        }
        let git = || self.undo().env("GIT_INDEX_FILE", scratch.path());
        if git().output_stdin(["update-index", "-z", "--index-info"], entries).is_err() {
            return same;
        }
        let _ = git().output(["update-index", "-q", "--refresh"]);
        let Ok(differ) = git().output(["diff-files", "--name-only", "-z"]) else { return same };
        let differ: BTreeSet<&[u8]> = differ.split(|b| *b == 0).filter(|p| !p.is_empty()).collect();
        for record in entries.split(|b| *b == 0) {
            let Some(tab) = record.iter().position(|b| *b == b'\t') else { continue };
            if !differ.contains(&record[tab + 1..]) {
                same.insert(record[tab + 1..].to_vec());
            }
        }
        same
    }

    /// Remove the file at the tree path `path` the move wrote: its
    /// directories walked without following a symlink ([`walk_under`]), the
    /// file unlinked (never followed), then its directories while empty.
    fn remove_written(&self, path: &[u8]) {
        let rel = Path::new(OsStr::from_bytes(path));
        let (Some(parent), Some(name)) = (rel.parent(), rel.file_name()) else { return };
        let Ok(Some(dir)) = walk_under(&self.dir, parent, false) else { return };
        let Ok(c) = cstr(name) else { return };
        // SAFETY: a valid directory fd and a NUL-terminated name.
        if unsafe { libc::unlinkat(dir.fd.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            return;
        }
        for up in parent.ancestors().filter(|a| !a.as_os_str().is_empty()) {
            if std::fs::remove_dir(self.dir.join(up)).is_err() {
                break;
            }
        }
    }
}

/// One `update-ref --stdin` transaction of `lines` by `git` (all or nothing).
fn transaction(git: &GitRun, lines: &[String]) -> std::result::Result<(), GitError> {
    let mut input = String::from("start\n");
    for l in lines {
        input.push_str(l);
        input.push('\n');
    }
    input.push_str("prepare\ncommit\n");
    git.output_stdin(["update-ref", "--stdin"], input.as_bytes()).map(|_| ())
}

/// Write `bytes` to `path` through a temp file beside it, renamed into place.
fn write_beside(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::Builder::new().prefix(".ai-env-").tempfile_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map(|_| ()).map_err(|e| e.error)
}

/// The all-zero id of `format` ("must not exist" in a ref transaction).
fn zero(format: ObjectFormat) -> String {
    "0".repeat(format.hex_len())
}

/// The format of the repository's ids, read off one of them.
fn format_of(id: &str) -> Option<ObjectFormat> {
    ObjectFormat::of_id(id)
}

// ---- the seed ------------------------------------------------------------------------------

/// What a code-out answers: the manifest, and the staged pack with its size
/// unless nothing is new.
#[derive(Debug)]
struct Codeout {
    manifest: CodeoutManifest,
    pack: Option<(tempfile::NamedTempFile, u64)>,
}

impl Ctx {
    fn seed_state(&self, path: &str, record: Option<&SeedRecord>) -> Step<SeedState> {
        let walked = self.workspace(path, false)?;
        let Some(record) = record else { return Ok(SeedState::default()) };
        if record.path != path {
            return Err(Stop::refused(
                WsRefusal::new(refusal::OTHER_WORKSPACE, &format!("the VM was seeded at {} (one workspace per VM)", record.path)).with_state(SeedState { record: Some(record.clone()), ..SeedState::default() }),
            ));
        }
        let Some(walked) = walked else { return Ok(SeedState { record: Some(record.clone()), ..SeedState::default() }) };
        let repo = Repo { ctx: self, dir: walked.path, budget: budget::SEED_STATE };
        let facts = repo.facts()?;
        let pristine = facts.tip.as_deref() == Some(record.head.as_str()) && facts.branch == record.branch && repo.unchanged_since(record)?;
        Ok(SeedState { record: Some(record.clone()), tip: facts.tip, branch: facts.branch, clean: facts.clean, pristine })
    }

    /// `PUT /seed`'s work (module doc): the reply and the workspace's state after it.
    fn seed_apply(&self, q: &SeedQuery, len: u64, record: Option<&SeedRecord>, input: &mut dyn BufRead) -> Step<(SeedReply, SeedState)> {
        if let Err(e) = q.check() {
            return refuse(refusal::BAD_REQUEST, &format!("the seed query {e}"));
        }
        if len > SEED_BODY_MAX {
            return Err(Stop::refused(WsRefusal::new(refusal::TOO_LARGE, &format!("the seed body is {len} bytes (at most {SEED_BODY_MAX})")).with_size(len)));
        }
        let line = match read_head_line(input, HEAD_LINE_MAX) {
            Ok(l) => l,
            Err(e) => return refuse(refusal::BAD_PACK, &format!("the seed body has no manifest line: {e}")),
        };
        let manifest: SeedManifest = match crate::wire::workspace::parse_head(&line) {
            Ok(m) => m,
            Err(e) => return refuse(refusal::BAD_PACK, &format!("the manifest line {e}")),
        };
        if let Err(e) = manifest.check_for(q) {
            return refuse(refusal::BAD_REFS, &format!("the manifest {e}"));
        }
        let Some(pack_len) = len.checked_sub(line.len() as u64 + 1) else {
            return refuse(refusal::BAD_REQUEST, "the seed body is shorter than its manifest line");
        };
        match q.mode {
            SeedMode::Clone => self.clone_seed(q, &manifest, pack_len, input),
            SeedMode::Update | SeedMode::Replace => {
                let Some(record) = record else { return refuse(refusal::NOT_SEEDED, "the VM was never seeded: nothing to update or replace") };
                if record.path != q.path {
                    return Err(Stop::refused(
                        WsRefusal::new(refusal::OTHER_WORKSPACE, &format!("the VM was seeded at {} (one workspace per VM)", record.path)).with_state(SeedState { record: Some(record.clone()), ..SeedState::default() }),
                    ));
                }
                self.move_seed(q, &manifest, pack_len, record, input)
            }
        }
    }

    /// Copy the pack (`len` bytes of `input`) into a 0600 file in the inbox,
    /// then open it again and let its name go: it is indexed from the open
    /// file, and nothing stays whatever ends the helper (no fsync).
    fn stage_pack(&self, len: u64, input: &mut dyn BufRead) -> Step<std::fs::File> {
        let mut staged = self.staged("seed-")?;
        let copied = io::copy(&mut input.take(len), staged.as_file_mut())?;
        if copied != len {
            return refuse(refusal::BAD_REQUEST, &format!("the seed body ended after {copied} of the pack's {len} bytes"));
        }
        Ok(staged.reopen()?)
    }

    fn clone_seed(&self, q: &SeedQuery, m: &SeedManifest, pack_len: u64, input: &mut dyn BufRead) -> Step<(SeedReply, SeedState)> {
        // The path's own refusals first, before the body is staged.
        if let Some(w) = self.workspace(&q.path, false)? {
            if std::fs::read_dir(&w.path)?.next().is_some() {
                return refuse(refusal::PATH_OCCUPIED, &format!("{} is not empty and holds no seed of this VM's", q.path));
            }
        }
        let pack = self.stage_pack(pack_len, input)?;
        let walked = self.workspace(&q.path, true)?.ok_or_else(|| Stop::Failed(CliError::Msg("the workspace was not made".into())))?;
        // Made or emptied between the two walks: still refused, as above.
        if std::fs::read_dir(&walked.path)?.next().is_some() && walked.created.last() != Some(&walked.path) {
            return refuse(refusal::PATH_OCCUPIED, &format!("{} is not empty and holds no seed of this VM's", q.path));
        }
        let repo = Repo { ctx: self, dir: walked.path.clone(), budget: SeedMode::Clone.budget() };
        let done = self.clone_into(&repo, q, m, pack);
        if done.is_err() {
            undo_clone(&walked);
        }
        done
    }

    fn clone_into(&self, repo: &Repo<'_>, q: &SeedQuery, m: &SeedManifest, pack: std::fs::File) -> Step<(SeedReply, SeedState)> {
        let branch = format!("--initial-branch={}", q.branch.as_deref().unwrap_or("main"));
        let format = format!("--object-format={}", m.object_format.name());
        repo.git().output(["init", "--quiet", "--template=", branch.as_str(), format.as_str()]).map_err(git_stop("init"))?;
        repo.index_pack(pack, false)?;
        let (shallow, _) = repo.read_shallow()?;
        repo.add_shallow(&shallow, None, &m.shallow)?;
        let wanted: BTreeSet<&str> = m.refs.values().map(String::as_str).chain(m.index.as_deref()).collect();
        repo.all_commits(&wanted)?;
        let tips: Vec<&str> = std::iter::once(m.head.as_str()).chain(m.wip.as_deref()).chain(m.index.as_deref()).collect();
        repo.all_present(&tips, None)?;
        let mut lines: Vec<String> = m.refs.iter().map(|(name, id)| format!("create {name} {id}")).collect();
        if q.detached {
            lines.push("option no-deref".into());
            lines.push(format!("update HEAD {}", m.head));
        }
        repo.refs(&lines).map_err(|e| cut_or("update-ref", e, |e| Stop::refused(WsRefusal::new(refusal::BAD_REFS, &format!("the seed's refs did not set: {}", git_said(e))))))?;
        if let Some(b) = &q.branch {
            repo.git().output(["symbolic-ref", "HEAD", &format!("{HEADS_PREFIX}{b}")]).map_err(git_stop("symbolic-ref"))?;
        }
        repo.git().output(["reset", "--quiet", "--hard"]).map_err(git_stop("reset --hard"))?;
        repo.apply_wip(&m.head, m.wip.as_deref(), m.index.as_deref()).map_err(git_stop("read-tree (the WIP)"))?;
        self.applied(repo, q, m, SeedApplied::Cloned)
    }

    /// An update's or a replace's work (module doc).
    fn move_seed(&self, q: &SeedQuery, m: &SeedManifest, pack_len: u64, record: &SeedRecord, input: &mut dyn BufRead) -> Step<(SeedReply, SeedState)> {
        let Some(walked) = self.workspace(&q.path, false)? else {
            return Err(Stop::refused(WsRefusal::new(refusal::CHANGED, &format!("{} is gone from the VM", q.path)).with_state(SeedState { record: Some(record.clone()), ..SeedState::default() })));
        };
        let repo = Repo { ctx: self, dir: walked.path, budget: q.mode.budget() };
        let facts = repo.facts()?;
        let state = |pristine: bool| SeedState { record: Some(record.clone()), tip: facts.tip.clone(), branch: facts.branch.clone(), clean: facts.clean, pristine };
        let Some(tip) = facts.tip.clone() else {
            return Err(Stop::refused(WsRefusal::new(refusal::CHANGED, "the VM's checkout has no commit any more").with_state(state(false))));
        };
        if q.expect.as_deref() != Some(tip.as_str()) {
            return Err(Stop::refused(WsRefusal::new(refusal::CHANGED, "the VM's tip moved since the Mac read it: read the state again").with_state(state(false))));
        }
        if format_of(&tip) != Some(m.object_format) {
            return refuse(refusal::BAD_REFS, &format!("the manifest's object format is {}, the VM's repository another", m.object_format.name()));
        }
        let old_head = if facts.branch.is_some() { None } else { Some(tip.clone()) };
        match q.mode {
            SeedMode::Update => {
                if !facts.clean {
                    return Err(Stop::refused(WsRefusal::new(refusal::DIRTY, "the VM's checkout has changes of its own (committed or not): it keeps them").with_state(state(false))));
                }
                if facts.branch != q.branch {
                    return Err(Stop::refused(WsRefusal::new(refusal::DIVERGED, "the VM has another branch checked out than the seed's: it keeps it").with_state(state(false))));
                }
            }
            SeedMode::Replace | SeedMode::Clone => {
                let pristine = facts.tip.as_deref() == Some(record.head.as_str()) && facts.branch == record.branch && repo.unchanged_since(record)?;
                if !pristine {
                    return Err(Stop::refused(WsRefusal::new(refusal::NOT_PRISTINE, "the VM changed since its seed: replace only a VM unchanged since then").with_state(state(false))));
                }
                // A branch of the agent's own under the new name: a replace never moves it.
                if let Some(b) = q.branch.as_ref().filter(|b| record.branch.as_ref() != Some(*b)) {
                    if repo.ref_target(&format!("{HEADS_PREFIX}{b}"))?.is_some() {
                        return Err(Stop::refused(WsRefusal::new(refusal::NOT_PRISTINE, &format!("the VM has a branch {b} of its own: a replace never moves it")).with_state(state(false))));
                    }
                }
            }
        }
        repo.index_pack(self.stage_pack(pack_len, input)?, true)?;
        let (shallow, old_shallow) = repo.read_shallow()?;
        let extra: Vec<String> = if q.mode == SeedMode::Replace { vec![m.head.clone()] } else { m.shallow.clone() };
        repo.add_shallow(&shallow, old_shallow.as_deref(), &extra)?;
        let checked = self.check_moved(&repo, q, m, &tip, &state);
        if let Err(stop) = checked {
            repo.restore_shallow(&shallow, old_shallow.as_deref());
            return Err(stop);
        }
        let moved = self.move_refs_and_tree(&repo, q, m, record, &tip, old_head.as_deref());
        if let Err(stop) = moved {
            repo.restore_shallow(&shallow, old_shallow.as_deref());
            return Err(stop);
        }
        let outcome = match q.mode {
            SeedMode::Update if m.head == tip && m.wip.is_none() => SeedApplied::UpToDate,
            SeedMode::Update => SeedApplied::Updated,
            _ => SeedApplied::Replaced,
        };
        self.applied(&repo, q, m, outcome)
    }

    /// An update's or a replace's checks once the pack is in: the manifest's
    /// commits, every new object, and (an update) the tip an ancestor of the head.
    fn check_moved(&self, repo: &Repo<'_>, q: &SeedQuery, m: &SeedManifest, tip: &str, state: &dyn Fn(bool) -> SeedState) -> Step<()> {
        let wanted: BTreeSet<&str> = m.refs.values().map(String::as_str).chain(m.index.as_deref()).collect();
        repo.all_commits(&wanted)?;
        let tips: Vec<&str> = std::iter::once(m.head.as_str()).chain(m.wip.as_deref()).chain(m.index.as_deref()).collect();
        repo.all_present(&tips, Some(tip))?;
        if q.mode == SeedMode::Update && !repo.git().succeeds(["merge-base", "--is-ancestor", tip, &m.head]).map_err(git_stop("merge-base"))? {
            return Err(Stop::refused(WsRefusal::new(refusal::DIVERGED, "the VM's tip is not an ancestor of the Mac's head: the VM keeps its state").with_state(state(false))));
        }
        Ok(())
    }

    /// The refs moved in one compare-and-swap transaction (against what the
    /// checks saw), then the checkout moved by a two-way merge, then the WIP
    /// applied; a failure after the transaction puts the refs back first,
    /// then the checkout ([`Repo::restore_checkout`]).
    fn move_refs_and_tree(&self, repo: &Repo<'_>, q: &SeedQuery, m: &SeedManifest, record: &SeedRecord, tip: &str, old_detached: Option<&str>) -> Step<()> {
        let none = zero(m.object_format);
        let old_seed = repo.ref_target(SEED_REF)?;
        let old_wip = repo.ref_target(SEED_WIP_REF)?;
        // The branches' old values are what the checks saw, never a read made
        // since: a commit of the agent's made while the pack came in then
        // fails the transaction (409 `changed`) and stays where the agent
        // made it (D3). The branch checked out (an update's, a replace's onto
        // its own branch) was at the tip; a replace's new branch did not exist.
        let checked_out = old_detached.is_none() && (q.mode == SeedMode::Update || record.branch == q.branch);
        let old_branch = q.branch.as_ref().filter(|_| checked_out).map(|_| tip.to_string());
        // The seed's own branch, at the tip when the replace found the VM
        // pristine, is removed by a replace onto another branch (one
        // detaching HEAD keeps it: HEAD still names it until the transaction
        // commits).
        let stale = match (&record.branch, &q.branch) {
            (Some(old), Some(new)) if q.mode == SeedMode::Replace && new != old => Some((format!("{HEADS_PREFIX}{old}"), tip.to_string())),
            _ => None,
        };
        let mut forward = Vec::new();
        let mut back = Vec::new();
        match &q.branch {
            Some(b) => {
                let name = format!("{HEADS_PREFIX}{b}");
                let old = old_branch.clone().unwrap_or_else(|| none.clone());
                forward.push(format!("update {name} {} {old}", m.head));
                back.push(match &old_branch {
                    Some(o) => format!("update {name} {o} {}", m.head),
                    None => format!("delete {name} {}", m.head),
                });
            }
            None => {
                forward.push("option no-deref".into());
                forward.push(format!("update HEAD {} {tip}", m.head));
                back.push("option no-deref".into());
                back.push(format!("update HEAD {tip} {}", m.head));
            }
        }
        if let Some((name, at)) = &stale {
            forward.push(format!("delete {name} {at}"));
            back.push(format!("create {name} {at}"));
        }
        forward.push(format!("update {SEED_REF} {} {}", m.head, old_seed.clone().unwrap_or_else(|| none.clone())));
        back.push(match &old_seed {
            Some(o) => format!("update {SEED_REF} {o} {}", m.head),
            None => format!("delete {SEED_REF} {}", m.head),
        });
        match (&m.wip, &old_wip) {
            (Some(w), Some(o)) => {
                forward.push(format!("update {SEED_WIP_REF} {w} {o}"));
                back.push(format!("update {SEED_WIP_REF} {o} {w}"));
            }
            (Some(w), None) => {
                forward.push(format!("create {SEED_WIP_REF} {w}"));
                back.push(format!("delete {SEED_WIP_REF} {w}"));
            }
            (None, Some(o)) => {
                forward.push(format!("delete {SEED_WIP_REF} {o}"));
                back.push(format!("create {SEED_WIP_REF} {o}"));
            }
            (None, None) => {}
        }
        // The checkout: an update's index is its tip's (it is clean); a
        // replace's worktree is what the seed left, which becomes the index
        // first so the two-way merge sees no change of the agent's.
        let from = match q.mode {
            SeedMode::Update => tip.to_string(),
            _ => match &record.wip_tree {
                Some(t) => t.clone(),
                None => repo.tree_of(&record.head)?,
            },
        };
        if let Err(e) = repo.refs(&forward) {
            return Err(cut_or("update-ref", e, |e| Stop::refused(WsRefusal::new(refusal::CHANGED, &format!("the VM's refs moved meanwhile: {}", git_said(e))))));
        }
        // From here a failure rolls back with runs of their own (`Repo::undo`): they may use what the forward runs left.
        let old_head_ref = record.branch.as_ref().map(|b| format!("{HEADS_PREFIX}{b}"));
        let undo_refs = |repo: &Repo<'_>| {
            let _ = transaction(&repo.undo(), &back);
            match (&old_head_ref, old_detached) {
                (Some(r), _) if q.mode == SeedMode::Replace => {
                    let _ = repo.undo().output(["symbolic-ref", "HEAD", r]);
                }
                (None, Some(at)) if q.mode == SeedMode::Replace => {
                    let _ = repo.undo().output(["update-ref", "--no-deref", "HEAD", at]);
                }
                _ => {}
            }
        };
        if q.mode == SeedMode::Replace {
            if let Some(b) = &q.branch {
                if let Err(e) = repo.git().output(["symbolic-ref", "HEAD", &format!("{HEADS_PREFIX}{b}")]) {
                    undo_refs(repo);
                    return Err(git_stop("symbolic-ref")(e));
                }
            }
        }
        if q.mode != SeedMode::Update {
            let refreshed = repo.git().output(["read-tree", &from]).and_then(|_| repo.git().output(["update-index", "-q", "--refresh"]));
            if let Err(e) = refreshed {
                undo_refs(repo);
                let _ = repo.undo().output(["read-tree", "--reset", record.index_tree.as_deref().unwrap_or(&record.head)]);
                return Err(git_stop("read-tree")(e));
            }
        }
        // A replace's index back to the one its seed left (after the files:
        // their restore resets it), the stat data of what it keeps kept, as
        // in `Repo::restore_checkout`.
        let old_index = |repo: &Repo<'_>| {
            if q.mode != SeedMode::Update {
                let _ = repo.undo().output(["read-tree", "--reset", record.index_tree.as_deref().unwrap_or(&record.head)]);
                let _ = repo.undo().output(["update-index", "-q", "--refresh"]);
            }
        };
        let code = if q.mode == SeedMode::Update { refusal::DIRTY } else { refusal::NOT_PRISTINE };
        if let Err(e) = repo.git().output(["read-tree", "-m", "-u", &from, &m.head]) {
            // The refs first (one quick transaction), whatever the files take.
            undo_refs(repo);
            // Cut at its budget, or failed while writing (a full disk, a
            // directory the agent made read-only), it may have written part
            // of the head. Refused in its checks, it wrote nothing: the
            // restore then meets only what the agent itself made the head's
            // version, or removed, meanwhile (the WIP path's edge too).
            repo.restore_checkout(&from, &[&m.head]);
            old_index(repo);
            return Err(cut_or("read-tree", e, |e| Stop::refused(WsRefusal::new(code, &format!("a file in the VM's checkout is in the way: the VM keeps its state ({})", git_said(e))))));
        }
        if let Err(e) = repo.apply_wip(&m.head, m.wip.as_deref(), m.index.as_deref()) {
            // Back to where the move started: the refs first, then the files
            // the two-way checkout and the WIP wrote, then a replace's index.
            undo_refs(repo);
            let wrote: Vec<&str> = std::iter::once(m.head.as_str()).chain(m.wip.as_deref()).collect();
            repo.restore_checkout(&from, &wrote);
            old_index(repo);
            return Err(cut_or("read-tree (the WIP)", e, |e| Stop::refused(WsRefusal::new(code, &format!("the new WIP does not apply in the VM: it keeps its state ({})", git_said(e))))));
        }
        Ok(())
    }

    /// The reply and the state after a seed went in.
    fn applied(&self, repo: &Repo<'_>, q: &SeedQuery, m: &SeedManifest, outcome: SeedApplied) -> Step<(SeedReply, SeedState)> {
        let wip_tree = match &m.wip {
            Some(w) => Some(repo.tree_of(w)?),
            None => None,
        };
        let index_tree = match (&m.wip, &m.index) {
            (Some(_), Some(i)) => Some(repo.tree_of(i)?),
            (Some(_), None) => Some(repo.tree_of(&m.head)?),
            (None, _) => None,
        };
        let head_tree = repo.tree_of(&m.head)?;
        let record = SeedRecord {
            path: q.path.clone(),
            mode: q.mode,
            branch: q.branch.clone(),
            head: m.head.clone(),
            wip: m.wip.clone(),
            wip_tree: wip_tree.filter(|t| *t != head_tree),
            index_tree: index_tree.filter(|t| *t != head_tree),
            object_format: m.object_format,
            at: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()),
        };
        let clean = record.wip_tree.is_none() && record.index_tree.is_none() && repo.clean()?;
        let state = SeedState { record: Some(record), tip: Some(m.head.clone()), branch: q.branch.clone(), clean, pristine: true };
        let reply = SeedReply { outcome, head: m.head.clone(), branch: q.branch.clone(), wip: m.wip.clone(), index: m.index.clone(), ms: self.ms() };
        Ok((reply, state))
    }
}

impl Repo<'_> {
    /// The worktree and index trees are those the seed left (`record`): the
    /// part of "pristine" the tip and branch do not tell.
    fn unchanged_since(&self, record: &SeedRecord) -> Step<bool> {
        let Ok(trees) = self.trees()? else { return Ok(false) };
        let head_tree = self.tree_of(&record.head)?;
        let want_work = record.wip_tree.as_deref().unwrap_or(&head_tree);
        let want_index = record.index_tree.as_deref().unwrap_or(&head_tree);
        Ok(trees.worktree == want_work && trees.index.as_deref() == Some(want_index))
    }
}

// ---- snapshots and code-out ----------------------------------------------------------------

/// A `refs/wip/<UTC>-<n>` name's sort key: its time, then its number.
fn wip_key(name: &str) -> Option<(String, u64)> {
    let rest = name.strip_prefix(WIP_REF_PREFIX)?;
    let (time, n) = rest.rsplit_once('-')?;
    Some((time.to_string(), n.parse().ok()?))
}

/// `YYYYMMDDTHHMMSSZ` of `secs`.
fn compact_utc(secs: u64) -> String {
    crate::wire::time::rfc3339_utc(secs).chars().filter(|c| *c != '-' && *c != ':').collect()
}

impl Ctx {
    /// The seeded workspace's repository, or 409 `not_seeded` when the path holds none.
    fn seeded_repo(&self, path: &str, budget: Duration) -> Step<Repo<'_>> {
        let Some(walked) = self.workspace(path, false)? else { return refuse(refusal::NOT_SEEDED, &format!("{path} holds no seed")) };
        let repo = Repo { ctx: self, dir: walked.path, budget };
        if !repo.exists() {
            return refuse(refusal::NOT_SEEDED, &format!("{path} holds no repository"));
        }
        Ok(repo)
    }

    fn snapshot(&self, path: &str, budget: Duration) -> Step<SnapshotReply> {
        let repo = self.seeded_repo(path, budget)?;
        let (wip_ref, wip_skipped) = self.take_snapshot(&repo)?;
        Ok(SnapshotReply { wip_ref, wip_skipped, ms: self.ms() })
    }

    /// Snapshot the uncommitted work (module doc): the `refs/wip/*` made or
    /// kept (`None` when the checkout matches its head), or why none was made.
    fn take_snapshot(&self, repo: &Repo<'_>) -> Step<(Option<String>, Option<String>)> {
        let trees = match repo.trees()? {
            Ok(t) => t,
            Err(why) => return Ok((None, Some(why))),
        };
        let index_tree = trees.index.clone().unwrap_or_else(|| trees.head_tree.clone());
        if trees.worktree == trees.head_tree && index_tree == trees.head_tree {
            return Ok((None, None));
        }
        let listed = repo.git().output(["for-each-ref", "--format=%(refname)", "refs/wip/"]).map_err(git_stop("for-each-ref"))?;
        let mut wips: Vec<(String, u64, String)> = String::from_utf8_lossy(&listed).lines().filter_map(|n| wip_key(n).map(|(t, k)| (t, k, n.to_string()))).collect();
        wips.sort();
        // Unchanged since the newest snapshot: the same tree on the same parents.
        if let Some((_, _, newest)) = wips.last() {
            let shown = repo.git().output(["show", "-s", "--format=%T %P", newest]).map_err(git_stop("show"))?;
            let shown = text(&shown);
            let mut words = shown.split(' ');
            let (tree, first) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
            let second = words.next();
            let index_same = match second {
                None => index_tree == trees.head_tree,
                Some(i) => repo.tree_of(i)? == index_tree && index_tree != trees.head_tree,
            };
            if tree == trees.worktree && first == trees.head && index_same {
                return Ok((Some(newest.clone()), None));
            }
        }
        let author = |g: GitRun| {
            g.env("GIT_AUTHOR_NAME", SNAPSHOT_AUTHOR.0).env("GIT_AUTHOR_EMAIL", SNAPSHOT_AUTHOR.1).env("GIT_COMMITTER_NAME", SNAPSHOT_AUTHOR.0).env("GIT_COMMITTER_EMAIL", SNAPSHOT_AUTHOR.1)
        };
        let now = crate::wire::time::unix_now();
        let mut parents = vec!["-p".to_string(), trees.head.clone()];
        if index_tree != trees.head_tree {
            let msg = format!("ai-env snapshot index {}", crate::wire::time::rfc3339_utc(now));
            let index_commit = text(&author(repo.git()).output(["commit-tree", &index_tree, "-p", &trees.head, "-m", &msg]).map_err(git_stop("commit-tree"))?);
            parents.extend(["-p".to_string(), index_commit]);
        }
        let msg = format!("ai-env snapshot {}", crate::wire::time::rfc3339_utc(now));
        let mut args = vec!["commit-tree".to_string(), trees.worktree.clone()];
        args.extend(parents);
        args.extend(["-m".to_string(), msg]);
        let commit = text(&author(repo.git()).output(&args).map_err(git_stop("commit-tree"))?);
        let stamp = compact_utc(now);
        let n = wips.iter().filter(|(t, _, _)| *t == stamp).map(|(_, k, _)| *k).max().unwrap_or(0) + 1;
        let name = format!("{WIP_REF_PREFIX}{stamp}-{n}");
        repo.refs(&[format!("create {name} {commit}")]).map_err(git_stop("update-ref"))?;
        wips.push((stamp, n, name.clone()));
        // The newest WIP_KEEP stay.
        if wips.len() > WIP_KEEP {
            let old: Vec<String> = wips[..wips.len() - WIP_KEEP].iter().map(|(_, _, n)| format!("delete {n}")).collect();
            repo.refs(&old).map_err(git_stop("update-ref"))?;
        }
        Ok((Some(name), None))
    }

    fn codeout(&self, path: &str, wip: bool, max_bytes: u64, input: &mut dyn BufRead) -> Step<Codeout> {
        let mut haves_json = Vec::new();
        input.take(crate::wire::workspace::CODEOUT_REQUEST_MAX as u64 + 1).read_to_end(&mut haves_json)?;
        let haves: Vec<String> = if haves_json.iter().all(u8::is_ascii_whitespace) {
            Vec::new()
        } else {
            match serde_json::from_slice(&haves_json) {
                Ok(h) => h,
                Err(e) => return refuse(refusal::BAD_REQUEST, &format!("the haves are not a JSON list of object ids: {e}")),
            }
        };
        if haves.len() > HAVES_MAX || haves.iter().any(|h| ObjectFormat::of_id(h).is_none()) {
            return refuse(refusal::BAD_REQUEST, &format!("the haves are not at most {HAVES_MAX} object ids"));
        }
        let repo = self.seeded_repo(path, budget::CODEOUT)?;
        // A snapshot that fails (an untracked file the agent cannot read, one
        // gone meanwhile) is skipped with why: the commits still come back.
        let (wip_ref, wip_skipped) = match wip.then(|| self.take_snapshot(&repo)) {
            None => (None, None),
            Some(Ok(made)) => made,
            Some(Err(Stop::Refused(r))) if r.code != refusal::TIMEOUT => (None, Some(format!("the snapshot failed: {}", r.message))),
            Some(Err(e)) => return Err(e),
        };
        let Some(head) = repo.commit("HEAD")? else { return refuse(refusal::NOT_SEEDED, &format!("{path} has no commit checked out")) };
        let Some(format) = format_of(&head) else { return Err(Stop::Failed(CliError::Msg("HEAD is no object id".into()))) };
        let branch = repo.branch()?.filter(|b| crate::wire::workspace::branch_check(b).is_ok());
        let listed = repo.git().output(["for-each-ref", "--format=%(refname)%00%(objectname)%00%(objecttype)", "refs/heads/", "refs/wip/", SEED_WIP_REF]).map_err(git_stop("for-each-ref"))?;
        let mut refs = BTreeMap::new();
        for line in String::from_utf8_lossy(&listed).lines() {
            let mut f = line.split('\0');
            let (Some(name), Some(id), Some("commit")) = (f.next(), f.next(), f.next()) else { continue };
            refs.insert(name.to_string(), id.to_string());
        }
        if branch.is_none() {
            refs.insert("HEAD".to_string(), head.clone());
        }
        let mut manifest = CodeoutManifest { v: SeedManifest::V, object_format: format, refs, head: head.clone(), branch, wip_ref, wip_skipped };
        // A ref the Mac's check would refuse (a name the agent made) stays in the VM.
        let names: Vec<String> = manifest.refs.keys().cloned().collect();
        for name in names {
            let mut one = CodeoutManifest { refs: BTreeMap::new(), wip_ref: None, wip_skipped: None, ..manifest.clone() };
            one.refs.insert(name.clone(), manifest.refs[&name].clone());
            if one.check().is_err() {
                manifest.refs.remove(&name);
            }
        }
        if manifest.wip_ref.as_ref().is_some_and(|w| !manifest.refs.contains_key(w)) {
            manifest.wip_ref = None;
        }
        if let Err(e) = manifest.check() {
            return Err(Stop::Failed(CliError::Msg(format!("the code-out manifest {e}"))));
        }
        // The Mac's haves the VM holds: the pack leaves out what they reach.
        let mut ask = Vec::new();
        for h in &haves {
            ask.extend_from_slice(h.as_bytes());
            ask.push(b'\n');
        }
        let present: BTreeSet<String> = if ask.is_empty() {
            BTreeSet::new()
        } else {
            let out = repo.git().output_stdin(["cat-file", "--batch-check=%(objectname) %(objecttype)"], &ask).map_err(git_stop("cat-file"))?;
            String::from_utf8_lossy(&out).lines().filter_map(|l| l.strip_suffix(" commit")).map(str::to_string).collect()
        };
        let tips: BTreeSet<&String> = manifest.refs.values().collect();
        let mut revs = String::new();
        for t in &tips {
            revs.push_str(t);
            revs.push('\n');
        }
        for h in &present {
            revs.push('^');
            revs.push_str(h);
            revs.push('\n');
        }
        let staged = self.staged("codeout-")?;
        let len = self.pack_objects(&repo, revs.as_bytes(), staged.path(), max_bytes)?;
        let mut header = [0u8; 12];
        std::fs::File::open(staged.path())?.read_exact(&mut header)?;
        let objects = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        if objects == 0 && tips.iter().all(|t| present.contains(*t)) {
            return Ok(Codeout { manifest, pack: None });
        }
        Ok(Codeout { manifest, pack: Some((staged, len)) })
    }

    /// `pack-objects --revs --thin --stdout` of `revs` into `dest`: its size;
    /// 413 `too_large` past `max_bytes` (with the size, when the pack ended
    /// within `SEED_BODY_MAX`).
    fn pack_objects(&self, repo: &Repo<'_>, revs: &[u8], dest: &Path, max_bytes: u64) -> Step<u64> {
        let mut child = repo.git().spawn_piped(["pack-objects", "--revs", "--thin", "--stdout", "--delta-base-offset", "-q"]).map_err(git_stop("pack-objects"))?;
        let mut stdin = child.take_stdin().ok_or_else(|| Stop::Failed(CliError::Msg("pack-objects has no stdin".into())))?;
        let revs = revs.to_vec();
        let feeder = std::thread::Builder::new().name("pack-objects stdin".into()).spawn(move || {
            let _ = stdin.write_all(&revs);
        })?;
        let mut out = child.take_stdout().ok_or_else(|| Stop::Failed(CliError::Msg("pack-objects has no stdout".into())))?;
        let mut file = std::fs::OpenOptions::new().write(true).truncate(true).open(dest)?;
        let copied = io::copy(&mut (&mut out).take(SEED_BODY_MAX + 1), &mut file)?;
        let _ = feeder.join();
        if copied > SEED_BODY_MAX {
            drop(out);
            drop(child);
            return Err(Stop::refused(WsRefusal::new(refusal::TOO_LARGE, &format!("the code-out pack is over {} MiB (at most {} MiB asked)", SEED_BODY_MAX >> 20, max_bytes >> 20))));
        }
        drop(out);
        child.finish().map_err(git_stop("pack-objects"))?;
        if copied > max_bytes {
            return Err(Stop::refused(WsRefusal::new(refusal::TOO_LARGE, &format!("the code-out pack is {copied} bytes (at most {max_bytes} asked)")).with_size(copied)));
        }
        file.sync_all()?;
        Ok(copied)
    }
}

// ---- transcripts ---------------------------------------------------------------------------

/// A file under a directory reached by a walk: its open directory and its name.
struct InDir {
    dir: OwnedFd,
    dir_path: PathBuf,
    name: CString,
}

/// What is at a file's name.
enum AtName {
    Absent,
    /// A regular file, open for reading.
    File(std::fs::File),
}

impl InDir {
    /// What is at the name: a regular file (opened without following a
    /// symlink, never blocking on a fifo), nothing, or a refusal.
    fn open(&self, ctx: &Ctx, what: &str) -> Step<AtName> {
        // SAFETY: a valid directory fd, a NUL-terminated name, plain flags.
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), self.name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        let shown = || ctx.shown(&self.dir_path.join(OsStr::from_bytes(self.name.as_bytes())));
        if fd < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::ENOENT) => Ok(AtName::Absent),
                _ => match kind_at(&self.dir, &self.name) {
                    Ok(libc::S_IFLNK) => refuse(refusal::SYMLINK_COMPONENT, &format!("{what} {} is a symlink, which the VM never follows", shown())),
                    Ok(_) => refuse(refusal::PATH_OCCUPIED, &format!("{what} {} cannot be opened ({e})", shown())),
                    Err(_) => Err(e.into()),
                },
            };
        }
        // SAFETY: just opened, owned by nobody else.
        let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        if !file.metadata()?.is_file() {
            return refuse(refusal::PATH_OCCUPIED, &format!("{what} {} is not a regular file", shown()));
        }
        Ok(AtName::File(file))
    }

    /// Remove the temp files of puts ended before their own end (the shim's
    /// TERM at a put's budget or at a stop: the helper has no handler, so no
    /// drop of [`TempIn`] ran): the directory's regular files named as
    /// [`TempIn`] names them, through its fd. Only a put calls it, under the
    /// shim's transcripts lock, which a put's helper holds until it is
    /// reaped: none of these is anyone's now.
    fn sweep_temps(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir_path) else { return };
        for name in entries.flatten().map(|e| e.file_name()).filter(|n| is_put_temp(n.as_bytes())) {
            let Ok(c) = cstr(&name) else { continue };
            if kind_at(&self.dir, &c).is_ok_and(|k| k == libc::S_IFREG) {
                // SAFETY: a valid directory fd and a NUL-terminated name.
                unsafe { libc::unlinkat(self.dir.as_raw_fd(), c.as_ptr(), 0) };
            }
        }
    }
}

/// A transcript put's temp file name, as [`TempIn`] makes it: `.ai-env-`, 16 lowercase hex digits, `.tmp`.
fn is_put_temp(name: &[u8]) -> bool {
    name.len() == 28 && name.starts_with(b".ai-env-") && name.ends_with(b".tmp") && name[8..24].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// sha256 (lowercase hex) and the size of everything `r` gives.
fn digest(mut r: impl Read) -> io::Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut n = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => return Ok((hex::encode(h.finalize()), n)),
            Ok(k) => {
                h.update(&buf[..k]);
                n += k as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// A file's mtime as RFC 3339 UTC.
fn mtime_of(md: &std::fs::Metadata) -> Option<String> {
    let secs = md.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(crate::wire::time::rfc3339_utc(secs))
}

impl Ctx {
    /// The transcript `rel` under `projects`: its directory walked (and with
    /// `create`, made), its file name.
    fn transcript_at(&self, projects: &Path, rel: &str, create: bool) -> Step<Option<InDir>> {
        if let Err(e) = transcript_rel_check(rel) {
            return refuse(refusal::BAD_REQUEST, &format!("the transcript's rel {e}"));
        }
        let target = projects.join(rel);
        let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else { return refuse(refusal::BAD_REQUEST, "the transcript's rel names no file") };
        let Some(walked) = self.walk(parent, create, "the transcript's directory")? else { return Ok(None) };
        Ok(Some(InDir { dir: walked.fd, dir_path: walked.path, name: cstr(name)? }))
    }

    fn transcript_stat(&self, projects: &Path, rel: &str) -> Step<TranscriptStat> {
        let absent = TranscriptStat { present: false, size: 0, sha256: None, mtime: None };
        let Some(at) = self.transcript_at(projects, rel, false)? else { return Ok(absent) };
        match at.open(self, "the transcript")? {
            AtName::Absent => Ok(absent),
            AtName::File(f) => {
                let md = f.metadata()?;
                let (sha, size) = digest(f)?;
                Ok(TranscriptStat { present: true, size, sha256: Some(sha), mtime: mtime_of(&md) })
            }
        }
    }

    /// `len` bytes of `input` as the transcript `rel` (module doc).
    fn transcript_put(&self, projects: &Path, rel: &str, len: u64, input: &mut dyn BufRead) -> Step<TranscriptReply> {
        if len > TRANSCRIPT_MAX {
            return Err(Stop::refused(WsRefusal::new(refusal::TOO_LARGE, &format!("the transcript is {len} bytes (at most {TRANSCRIPT_MAX})")).with_size(len)));
        }
        let at = self.transcript_at(projects, rel, true)?.ok_or_else(|| Stop::Failed(CliError::Msg("the transcript's directory was not made".into())))?;
        at.sweep_temps();
        let current = match at.open(self, "the transcript")? {
            AtName::Absent => None,
            AtName::File(f) => Some(digest(f)?),
        };
        let tmp = TempIn::create(&at)?;
        let mut file = std::fs::File::from(tmp.fd.try_clone()?);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0u64;
        let mut body = input.take(len);
        loop {
            let k = match body.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            hasher.update(&buf[..k]);
            file.write_all(&buf[..k])?;
            got += k as u64;
        }
        if got != len {
            return refuse(refusal::BAD_REQUEST, &format!("the transcript body ended after {got} of {len} bytes"));
        }
        let sha = hex::encode(hasher.finalize());
        match &current {
            Some((_, size)) if *size > len => {
                return Err(Stop::refused(WsRefusal::new(refusal::VM_LONGER, &format!("the VM's copy is longer ({size} bytes, the upload {len}): the VM's copy wins")).with_size(*size)));
            }
            Some((vm_sha, size)) if *size == len && *vm_sha == sha => return Ok(TranscriptReply { outcome: TranscriptWrite::Unchanged, size: len, sha256: sha }),
            _ => {}
        }
        file.sync_all()?;
        let written = file.metadata()?.len();
        if written != len {
            return Err(Stop::Failed(CliError::Msg(format!("the transcript's temp file holds {written} of {len} bytes"))));
        }
        // The VM's claude may have written on while the body came in: a copy
        // longer than the upload now still wins (a window of the rename's
        // own remains: nothing locks the VM's claude out).
        if let AtName::File(f) = at.open(self, "the transcript")? {
            let now = f.metadata()?.len();
            if now > len {
                return Err(Stop::refused(WsRefusal::new(refusal::VM_LONGER, &format!("the VM's copy is longer ({now} bytes, the upload {len}): the VM's copy wins")).with_size(now)));
            }
        }
        tmp.rename_over(&at)?;
        Ok(TranscriptReply { outcome: TranscriptWrite::Written, size: len, sha256: sha })
    }
}

/// A 0600 temp file beside a transcript (`.ai-env-<random>.tmp`), created
/// without following a symlink and removed unless renamed over it; one a
/// helper ended by a signal left goes at the next put into its directory
/// ([`InDir::sweep_temps`]).
struct TempIn {
    dir: libc::c_int,
    name: CString,
    fd: OwnedFd,
    renamed: bool,
}

impl TempIn {
    fn create(at: &InDir) -> io::Result<TempIn> {
        let mut rand = [0u8; 8];
        getrandom::fill(&mut rand).map_err(|e| io::Error::other(e.to_string()))?;
        // A name of its own length, whatever the transcript's (a segment may be NAME_MAX long).
        let name = CString::new(format!(".ai-env-{}.tmp", hex::encode(rand))).map_err(|_| io::Error::other("a temp name holds a NUL byte"))?;
        // SAFETY: a valid directory fd, a NUL-terminated name, plain flags and a mode.
        let fd = unsafe { libc::openat(at.dir.as_raw_fd(), name.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600 as libc::c_uint) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: just opened, owned by nobody else.
        Ok(TempIn { dir: at.dir.as_raw_fd(), name, fd: unsafe { OwnedFd::from_raw_fd(fd) }, renamed: false })
    }

    /// Rename over the transcript, then fsync the directory.
    fn rename_over(mut self, at: &InDir) -> io::Result<()> {
        // SAFETY: valid directory fds and NUL-terminated names.
        if unsafe { libc::renameat(self.dir, self.name.as_ptr(), at.dir.as_raw_fd(), at.name.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.renamed = true;
        // SAFETY: a valid directory fd.
        if unsafe { libc::fsync(at.dir.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for TempIn {
    fn drop(&mut self) {
        if !self.renamed {
            // SAFETY: a valid directory fd and a NUL-terminated name.
            unsafe { libc::unlinkat(self.dir, self.name.as_ptr(), 0) };
        }
    }
}

// ---- settings ------------------------------------------------------------------------------

impl Ctx {
    fn settings(&self, path: &str) -> Step<SettingsCapture> {
        if let Err(e) = vm_path_check(path) {
            return refuse(refusal::BAD_REQUEST, &format!("the workspace path {e}"));
        }
        let disk = self.at(path);
        let mut files = Vec::new();
        for scope in SettingsScope::ALL {
            let (dir, name, vm) = match scope {
                SettingsScope::User => (self.home.join(".claude"), "settings.json", format!("{}/.claude/settings.json", self.shown(&self.home))),
                SettingsScope::Project => (disk.join(".claude"), "settings.json", format!("{path}/.claude/settings.json")),
                SettingsScope::Local => (disk.join(".claude"), "settings.local.json", format!("{path}/.claude/settings.local.json")),
            };
            files.push(self.settings_file(scope, &dir, name, vm)?);
        }
        let project = self.project_keys(path)?;
        let capture = SettingsCapture { path: path.to_string(), files, project, at: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()) };
        if let Err(e) = capture.check() {
            return Err(Stop::Failed(CliError::Msg(format!("the settings capture {e}"))));
        }
        Ok(capture)
    }

    /// One settings file as the agent reads it (`SettingsFile`).
    fn settings_file(&self, scope: SettingsScope, dir: &Path, name: &str, vm: String) -> Step<SettingsFile> {
        let none = SettingsFile { scope, path: vm, present: false, size: 0, sha256: None, text: None, skipped: None };
        let walked = match self.walk(dir, false, "a settings directory") {
            Ok(Some(w)) => w,
            Ok(None) => return Ok(none),
            // Its directory is the agent's symlink, or outside the home: never looked at.
            Err(Stop::Refused(r)) => return Ok(SettingsFile { skipped: Some(format!("not read: {}", r.code)), ..none }),
            Err(e) => return Err(e),
        };
        let at = InDir { dir: walked.fd, dir_path: walked.path, name: cstr(OsStr::new(name))? };
        let file = match at.open(self, "a settings file") {
            Ok(AtName::Absent) => return Ok(none),
            Ok(AtName::File(f)) => f,
            Err(Stop::Refused(r)) => {
                let why = if r.code == refusal::SYMLINK_COMPONENT { "a symlink" } else { "not a regular file" };
                return Ok(SettingsFile { present: true, skipped: Some(why.into()), ..none });
            }
            Err(e) => return Err(e),
        };
        let mut file = file;
        let mut bytes = Vec::new();
        (&mut file).take(SETTINGS_FILE_MAX as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > SETTINGS_FILE_MAX {
            // Over the cap: no text, the digest of the whole file.
            io::Seek::seek(&mut file, io::SeekFrom::Start(0))?;
            let (sha, size) = digest(&mut file)?;
            return Ok(SettingsFile { present: true, size, sha256: Some(sha), skipped: Some(format!("larger than {} KiB", SETTINGS_FILE_MAX / 1024)), ..none });
        }
        let (sha, size) = digest(bytes.as_slice())?;
        let (text, skipped) = match String::from_utf8(bytes) {
            Ok(t) => (Some(t), None),
            Err(_) => (None, Some("not UTF-8".to_string())),
        };
        Ok(SettingsFile { present: true, size, sha256: Some(sha), text, skipped, ..none })
    }

    /// The `PROJECT_KEYS` of `projects[path]` in the agent's `.claude/.claude.json`.
    fn project_keys(&self, path: &str) -> Step<BTreeMap<String, serde_json::Value>> {
        let mut keys = BTreeMap::new();
        let Ok(Some(walked)) = self.walk(&self.home.join(".claude"), false, "the agent's config directory") else { return Ok(keys) };
        let at = InDir { dir: walked.fd, dir_path: walked.path, name: cstr(OsStr::new(".claude.json"))? };
        let Ok(AtName::File(file)) = at.open(self, "the agent's .claude.json") else { return Ok(keys) };
        let mut bytes = Vec::new();
        (&file).take(CLAUDE_JSON_MAX + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > CLAUDE_JSON_MAX {
            return Ok(keys);
        }
        let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return Ok(keys) };
        if let Some(entry) = doc.get("projects").and_then(|p| p.get(path)).and_then(serde_json::Value::as_object) {
            for k in PROJECT_KEYS {
                if let Some(v) = entry.get(k) {
                    keys.insert(k.to_string(), v.clone());
                }
            }
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    /// The real git these tests run: the first in an absolute `PATH` entry, else `/usr/bin/git`.
    fn real_git() -> PathBuf {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .filter(|d| d.is_absolute())
            .map(|d| d.join("git"))
            .chain(std::iter::once(PathBuf::from("/usr/bin/git")))
            .find(|g| std::fs::metadata(g).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
            .expect("a git")
    }

    /// `git <args>` in `dir` with no user or system config, one author at one
    /// date, `env` on top; stdout. A failure panics with stderr.
    fn git_env(dir: &Path, args: &[&str], env: &[(&str, &OsStr)], input: Option<&[u8]>) -> Vec<u8> {
        let mut cmd = Command::new(real_git());
        cmd.args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", dir)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .env("GIT_AUTHOR_DATE", "2026-10-12T08:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-10-12T08:00:00Z");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = {
            let _fork = crate::test_locks::forking();
            cmd.spawn().expect("run git")
        };
        if let Some(bytes) = input {
            child.stdin.take().expect("stdin").write_all(bytes).expect("feed git");
        }
        let out = child.wait_with_output().expect("git's output");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        out.stdout
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        text(&git_env(dir, args, &[], None))
    }

    /// `git status --porcelain=v1`'s lines, as they are.
    fn status(dir: &Path) -> Vec<String> {
        String::from_utf8_lossy(&git_env(dir, &["status", "--porcelain=v1", "--untracked-files=all"], &[], None)).lines().map(str::to_string).collect()
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// A test world: `<tmp>/vm/home` the agent's home under the fs root
    /// `<tmp>/vm` (its VM path `/home`), and the Mac's repository `<tmp>/mac`
    /// with two commits on `main`.
    struct World {
        tmp: tempfile::TempDir,
        ctx: Ctx,
    }

    impl World {
        fn new() -> World {
            let tmp = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(tmp.path()).unwrap();
            let home = root.join("vm/home");
            std::fs::create_dir_all(&home).unwrap();
            let mac = root.join("mac");
            std::fs::create_dir_all(&mac).unwrap();
            git(&mac, &["init", "-q", "-b", "main"]);
            write(&mac.join("a.txt"), "one\n");
            write(&mac.join("d/b.txt"), "two\n");
            git(&mac, &["add", "-A"]);
            git(&mac, &["commit", "-q", "-m", "c1"]);
            write(&mac.join("a.txt"), "three\n");
            git(&mac, &["commit", "-q", "-am", "c2"]);
            let ctx = Ctx { home, fs_root: Some(root.join("vm")), git: real_git(), started: Instant::now(), budget: None };
            World { tmp, ctx }
        }

        fn root(&self) -> PathBuf {
            std::fs::canonicalize(self.tmp.path()).unwrap()
        }

        fn mac(&self) -> PathBuf {
            self.root().join("mac")
        }

        /// The workspace's disk copy (`/home/ws` in the VM).
        fn ws(&self) -> PathBuf {
            self.ctx.home.join("ws")
        }

        fn inbox_is_empty(&self) -> bool {
            std::fs::read_dir(self.ctx.home.join(INBOX)).map_or(true, |mut d| d.next().is_none())
        }
    }

    const WS: &str = "/home/ws";

    /// The Mac's dirty state as one WIP commit (D2, as W4 builds it): the
    /// index commit when the index differs from HEAD, the WIP commit of the
    /// tracked changes and the untracked files; `None` when clean.
    fn wip_of(mac: &Path) -> Option<(String, Option<String>)> {
        let head = git(mac, &["rev-parse", "HEAD"]);
        let head_tree = git(mac, &["rev-parse", "HEAD^{tree}"]);
        let index_tree = git(mac, &["write-tree"]);
        let scratch = mac.join(".git/test-index.w");
        std::fs::copy(mac.join(".git/index"), &scratch).unwrap();
        let idx = [("GIT_INDEX_FILE", scratch.as_os_str())];
        git_env(mac, &["add", "-A"], &idx, None);
        let work_tree = text(&git_env(mac, &["write-tree"], &idx, None));
        std::fs::remove_file(&scratch).unwrap();
        if work_tree == head_tree && index_tree == head_tree {
            return None;
        }
        let index = (index_tree != head_tree).then(|| git(mac, &["commit-tree", &index_tree, "-p", &head, "-m", "index"]));
        let mut args = vec!["commit-tree", work_tree.as_str(), "-p", head.as_str()];
        if let Some(i) = &index {
            args.extend(["-p", i.as_str()]);
        }
        args.extend(["-m", "wip"]);
        Some((git(mac, &args), index))
    }

    /// A `PUT /seed` body: the manifest line, then `pack-objects` of `objects`' ids.
    fn body_of(m: &SeedManifest, mac: &Path, revs: &str, shallow_file: Option<&Path>) -> Vec<u8> {
        let mut body = head_line(m).unwrap();
        let pack = match shallow_file {
            Some(f) => git_env(mac, &["--shallow-file", f.to_str().unwrap(), "pack-objects", "--revs", "--thin", "--stdout", "-q"], &[], Some(revs.as_bytes())),
            None => git_env(mac, &["pack-objects", "--stdout", "-q"], &[], Some(revs.as_bytes())),
        };
        body.extend(pack);
        body
    }

    /// A first seed of the Mac's head (and its WIP): the manifest and the body (D7's shallow pack).
    fn clone_body(mac: &Path, branch: Option<&str>) -> (SeedManifest, Vec<u8>) {
        let head = git(mac, &["rev-parse", "HEAD"]);
        let wip = wip_of(mac);
        let mut m = SeedManifest {
            v: SeedManifest::V,
            object_format: ObjectFormat::Sha1,
            branch: branch.map(str::to_string),
            detached: branch.is_none(),
            head: head.clone(),
            wip: wip.as_ref().map(|w| w.0.clone()),
            index: wip.as_ref().and_then(|w| w.1.clone()),
            shallow: vec![head.clone()],
            refs: BTreeMap::new(),
        };
        m.refs = m.expected_refs();
        let mut tips = vec![head];
        tips.extend(m.wip.clone());
        tips.extend(m.index.clone());
        let mut args = vec!["rev-list", "--objects", "--no-walk"];
        args.extend(tips.iter().map(String::as_str));
        let objects: String = git(mac, &args).lines().map(|l| format!("{}\n", l.split(' ').next().unwrap())).collect();
        let body = body_of(&m, mac, &objects, None);
        (m, body)
    }

    fn query(mode: SeedMode, branch: Option<&str>, expect: Option<&str>) -> SeedQuery {
        SeedQuery { path: WS.to_string(), mode, branch: branch.map(str::to_string), detached: branch.is_none(), expect: expect.map(str::to_string) }
    }

    fn apply(w: &World, q: &SeedQuery, body: &[u8], record: Option<&SeedRecord>) -> Step<(SeedReply, SeedState)> {
        w.ctx.seed_apply(q, body.len() as u64, record, &mut Cursor::new(body.to_vec()))
    }

    fn refused<T: std::fmt::Debug>(step: Step<T>) -> WsRefusal {
        match step {
            Err(Stop::Refused(r)) => *r,
            other => panic!("not a refusal: {other:?}"),
        }
    }

    /// A first seed of a dirty Mac: the clone's HEAD is the Mac's, shallow at
    /// it, with no origin and no history; the staged change staged, the
    /// unstaged one unstaged, the untracked file untracked, the ignored one
    /// absent; the record names the trees it left; the inbox is empty.
    #[test]
    fn a_clone_checks_out_the_head_shallow_with_the_wip_uncommitted() {
        let w = World::new();
        let mac = w.mac();
        write(&mac.join(".gitignore"), "*.log\n");
        git(&mac, &["add", ".gitignore"]);
        git(&mac, &["commit", "-q", "-m", "ignore"]);
        write(&mac.join("d/b.txt"), "staged\n");
        git(&mac, &["add", "d/b.txt"]);
        write(&mac.join("a.txt"), "unstaged\n");
        write(&mac.join("new.txt"), "untracked\n");
        write(&mac.join("x.log"), "ignored\n");
        let (m, body) = clone_body(&mac, Some("main"));
        assert!(m.wip.is_some() && m.index.is_some());
        let (reply, state) = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap();
        assert_eq!((reply.outcome, reply.head.as_str(), reply.branch.as_deref()), (SeedApplied::Cloned, m.head.as_str(), Some("main")));
        let ws = w.ws();
        assert_eq!(git(&ws, &["rev-parse", "HEAD"]), m.head);
        assert_eq!(git(&ws, &["symbolic-ref", "HEAD"]), "refs/heads/main");
        assert_eq!(std::fs::read_to_string(ws.join(".git/shallow")).unwrap(), format!("{}\n", m.head), "shallow at the seeded commit");
        assert_eq!(git(&ws, &["rev-list", "--count", "HEAD"]), "1", "no history crossed");
        assert_eq!(git(&ws, &["remote"]), "", "no origin");
        assert_eq!(status(&ws), [" M a.txt", "M  d/b.txt", "?? new.txt"]);
        assert!(!ws.join("x.log").exists(), "an ignored file never crossed");
        assert_eq!(git(&ws, &["rev-parse", SEED_REF]), m.head);
        assert_eq!(git(&ws, &["rev-parse", SEED_WIP_REF]), *m.wip.as_ref().unwrap());
        let record = state.record.unwrap();
        assert_eq!(record.wip_tree.as_deref(), Some(git(&mac, &["rev-parse", &format!("{}^{{tree}}", m.wip.as_ref().unwrap())]).as_str()));
        assert_eq!(record.index_tree.as_deref(), Some(git(&mac, &["write-tree"]).as_str()));
        assert!(state.pristine && !state.clean);
        assert_eq!(std::fs::metadata(&ws).unwrap().permissions().mode() & 0o777, 0o700, "made 0700 by the agent");
        assert!(w.inbox_is_empty(), "the staged pack is gone");
        // GET /seed's view of it: pristine until the agent changes something.
        let st = w.ctx.seed_state(WS, Some(&record)).unwrap();
        assert!(st.pristine && !st.clean && st.tip.as_deref() == Some(m.head.as_str()), "{st:?}");
        write(&ws.join("agent.txt"), "the agent's\n");
        assert!(!w.ctx.seed_state(WS, Some(&record)).unwrap().pristine, "an untracked file of the agent's");
    }

    /// A clean, detached seed: HEAD detached at the head, clean and pristine.
    #[test]
    fn a_detached_clean_clone_is_clean_and_pristine() {
        let w = World::new();
        let (m, body) = clone_body(&w.mac(), None);
        assert!(m.wip.is_none());
        let (_, state) = apply(&w, &query(SeedMode::Clone, None, None), &body, None).unwrap();
        assert!(state.clean && state.pristine && state.branch.is_none(), "{state:?}");
        let ws = w.ws();
        assert!(Command::new(real_git()).args(["symbolic-ref", "-q", "HEAD"]).current_dir(&ws).status().unwrap().code() == Some(1), "detached");
        assert_eq!(git(&ws, &["rev-parse", "HEAD"]), m.head);
        let record = state.record.unwrap();
        assert!(record.wip_tree.is_none() && record.index_tree.is_none());
        let st = w.ctx.seed_state(WS, Some(&record)).unwrap();
        assert!(st.clean && st.pristine && st.branch.is_none(), "{st:?}");
    }

    /// A bad pack, refs the pack lacks, a manifest that does not parse or does
    /// not match its query: each refused with its code before anything stays
    /// behind (no workspace directory, an empty inbox).
    #[test]
    fn a_bad_seed_is_refused_and_leaves_nothing_behind() {
        let w = World::new();
        let (m, body) = clone_body(&w.mac(), Some("main"));
        let line_len = head_line(&m).unwrap().len();
        let q = query(SeedMode::Clone, Some("main"), None);
        let mut garbage = head_line(&m).unwrap();
        garbage.extend_from_slice(b"PACK this is no pack at all");
        assert_eq!(refused(apply(&w, &q, &garbage, None)).code, refusal::BAD_PACK);
        let mut other = m.clone();
        other.head = "1".repeat(40);
        other.shallow = vec![other.head.clone()];
        other.refs = other.expected_refs();
        let mut lacking = head_line(&other).unwrap();
        lacking.extend_from_slice(&body[line_len..]);
        assert_eq!(refused(apply(&w, &q, &lacking, None)).code, refusal::BAD_REFS);
        assert_eq!(refused(apply(&w, &q, b"not json\nPACK", None)).code, refusal::BAD_PACK);
        let mut wrong_shallow = m.clone();
        wrong_shallow.shallow = Vec::new();
        let mut shallowless = head_line(&wrong_shallow).unwrap();
        shallowless.extend_from_slice(&body[line_len..]);
        let r = refused(apply(&w, &q, &shallowless, None));
        assert!(r.code == refusal::BAD_REFS && r.message.contains("shallow"), "{r:?}");
        let r = refused(w.ctx.seed_apply(&q, body.len() as u64 + 10, None, &mut Cursor::new(body.clone())));
        assert_eq!(r.code, refusal::BAD_REQUEST, "a body shorter than its length: {r:?}");
        assert!(!w.ws().exists(), "no workspace left behind");
        assert!(w.inbox_is_empty());
        // And the good one still goes in afterwards.
        assert_eq!(apply(&w, &q, &body, None).unwrap().0.outcome, SeedApplied::Cloned);
    }

    /// Paths: not NFC or with a `..` is 400; outside the agent's home 409
    /// `not_creatable`; through a symlink 409 `symlink_component`; a
    /// non-empty directory 409 `path_occupied`; a file in the way too.
    #[test]
    fn workspace_paths_are_checked_as_the_agent() {
        let w = World::new();
        let (_, body) = clone_body(&w.mac(), Some("main"));
        let mut q = query(SeedMode::Clone, Some("main"), None);
        for (path, code) in [("/home/\u{0418}\u{0306}", refusal::BAD_REQUEST), ("/home/../etc", refusal::BAD_REQUEST), ("/elsewhere/ws", refusal::NOT_CREATABLE), ("/home", refusal::NOT_CREATABLE)] {
            q.path = path.to_string();
            let r = refused(w.ctx.seed_apply(&q, body.len() as u64, None, &mut Cursor::new(body.clone())));
            assert_eq!(r.code, code, "{path}: {r:?}");
        }
        let outside = w.root().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, w.ctx.home.join("link")).unwrap();
        q.path = "/home/link/ws".into();
        let r = refused(w.ctx.seed_apply(&q, body.len() as u64, None, &mut Cursor::new(body.clone())));
        assert_eq!(r.code, refusal::SYMLINK_COMPONENT, "{r:?}");
        assert!(r.message.contains("/home/link") && !r.message.contains(&w.root().display().to_string()), "the VM's path, not the disk's: {r:?}");
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none(), "nothing written through the link");
        write(&w.ctx.home.join("full/x"), "x");
        q.path = "/home/full".into();
        assert_eq!(refused(w.ctx.seed_apply(&q, body.len() as u64, None, &mut Cursor::new(body.clone()))).code, refusal::PATH_OCCUPIED);
        write(&w.ctx.home.join("file"), "x");
        q.path = "/home/file/ws".into();
        assert_eq!(refused(w.ctx.seed_apply(&q, body.len() as u64, None, &mut Cursor::new(body.clone()))).code, refusal::PATH_OCCUPIED);
        // GET /seed refuses the symlink too.
        assert_eq!(refused(w.ctx.seed_state("/home/link/ws", None)).code, refusal::SYMLINK_COMPONENT);
        assert_eq!(w.ctx.seed_state("/home/nothing-yet", None).unwrap(), SeedState::default(), "never seeded");
    }

    /// Seed clean at c2, then the Mac moves on (a commit and a merge of a
    /// branch older than the seed): the thin update pack (shallow-aware,
    /// with the merged branch's commit as a boundary) fast-forwards the VM,
    /// whose new WIP lands uncommitted.
    #[test]
    fn an_update_fast_forwards_a_clean_vm_and_applies_the_new_wip() {
        let w = World::new();
        let mac = w.mac();
        let (seed, body) = clone_body(&mac, Some("main"));
        let (_, state) = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap();
        let record = state.record.unwrap();
        let tip = seed.head.clone();
        let c1 = git(&mac, &["rev-parse", "HEAD~1"]);
        git(&mac, &["checkout", "-q", "-b", "side", &c1]);
        write(&mac.join("side.txt"), "side\n");
        git(&mac, &["add", "side.txt"]);
        git(&mac, &["commit", "-q", "-m", "side"]);
        let side = git(&mac, &["rev-parse", "HEAD"]);
        git(&mac, &["checkout", "-q", "main"]);
        write(&mac.join("a.txt"), "four\n");
        git(&mac, &["commit", "-q", "-am", "c3"]);
        git(&mac, &["merge", "-q", "--no-ff", "-m", "merge", "side"]);
        write(&mac.join("wip.txt"), "uncommitted on the Mac\n");
        let head = git(&mac, &["rev-parse", "HEAD"]);
        let wip = wip_of(&mac).unwrap();
        let mut m = SeedManifest { head: head.clone(), wip: Some(wip.0.clone()), index: wip.1.clone(), shallow: vec![side.clone()], refs: BTreeMap::new(), ..seed.clone() };
        m.refs = m.expected_refs();
        // The Mac's walk stops at the VM's boundary and at the merged branch's
        // commit (the history below it never crosses), which the manifest
        // then lists as the VM's new boundary.
        let shallow_file = w.root().join("vm-shallow");
        std::fs::write(&shallow_file, format!("{tip}\n{side}\n")).unwrap();
        let revs = format!("{head}\n{}\n^{tip}\n", wip.0);
        let q = query(SeedMode::Update, Some("main"), Some(&tip));
        let ws = w.ws();
        // A thin pack that takes the VM for a full clone (no shallow boundary on the Mac's side) lacks
        // what lies below the seed: refused, and the VM as it was.
        let naive = {
            let mut b = head_line(&m).unwrap();
            b.extend(git_env(&mac, &["pack-objects", "--revs", "--thin", "--stdout", "-q"], &[], Some(revs.as_bytes())));
            b
        };
        let r = refused(apply(&w, &q, &naive, Some(&record)));
        assert_eq!(r.code, refusal::MISSING_PREREQUISITES, "{r:?}");
        // So does a manifest whose boundary leaves out the merged branch's commit (its parent never crossed).
        let unbounded = SeedManifest { shallow: Vec::new(), ..m.clone() };
        let r = refused(apply(&w, &q, &body_of(&unbounded, &mac, &revs, Some(&shallow_file)), Some(&record)));
        assert_eq!(r.code, refusal::MISSING_PREREQUISITES, "{r:?}");
        assert_eq!((git(&ws, &["rev-parse", "HEAD"]), std::fs::read_to_string(ws.join(".git/shallow")).unwrap()), (tip.clone(), format!("{tip}\n")), "the VM as it was");
        let body = body_of(&m, &mac, &revs, Some(&shallow_file));
        let (reply, state) = apply(&w, &q, &body, Some(&record)).unwrap();
        assert_eq!(reply.outcome, SeedApplied::Updated);
        assert_eq!(git(&ws, &["rev-parse", "HEAD"]), head);
        assert_eq!(git(&ws, &["rev-parse", SEED_REF]), head);
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "four\n");
        assert_eq!(std::fs::read_to_string(ws.join("side.txt")).unwrap(), "side\n");
        let c1_there = Command::new(real_git()).args(["cat-file", "-e", &c1]).current_dir(&ws).status().unwrap();
        assert!(!c1_there.success(), "no history below the boundary crossed");
        assert_eq!(status(&ws), ["?? wip.txt"]);
        let shallow = std::fs::read_to_string(ws.join(".git/shallow")).unwrap();
        assert!(shallow.contains(&tip) && shallow.contains(&m.shallow[0]), "{shallow}");
        assert_eq!(state.record.as_ref().unwrap().mode, SeedMode::Update);
        assert!(w.inbox_is_empty());
    }

    /// D3's refusals under the helper's own check: a dirty VM (`dirty`), a
    /// tip the Mac did not read (`changed`), another branch (`diverged`),
    /// and a tip that is no ancestor of the head (`diverged`); each with the
    /// state, and the VM unchanged.
    #[test]
    fn an_update_keeps_a_dirty_moved_or_diverged_vm() {
        let w = World::new();
        let mac = w.mac();
        let (seed, body) = clone_body(&mac, Some("main"));
        let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
        let tip = seed.head.clone();
        write(&mac.join("a.txt"), "four\n");
        git(&mac, &["commit", "-q", "-am", "c3"]);
        let head = git(&mac, &["rev-parse", "HEAD"]);
        let mut m = SeedManifest { head: head.clone(), wip: None, index: None, shallow: Vec::new(), refs: BTreeMap::new(), ..seed.clone() };
        m.refs = m.expected_refs();
        let shallow_file = w.root().join("vm-shallow");
        std::fs::write(&shallow_file, format!("{tip}\n")).unwrap();
        let body = body_of(&m, &mac, &format!("{head}\n^{tip}\n"), Some(&shallow_file));
        let ws = w.ws();
        write(&ws.join("agent.txt"), "uncommitted\n");
        let r = refused(apply(&w, &query(SeedMode::Update, Some("main"), Some(&tip)), &body, Some(&record)));
        assert!(r.code == refusal::DIRTY && r.state.as_ref().is_some_and(|s| !s.clean), "{r:?}");
        std::fs::remove_file(ws.join("agent.txt")).unwrap();
        let r = refused(apply(&w, &query(SeedMode::Update, Some("main"), Some(&head)), &body, Some(&record)));
        assert_eq!(r.code, refusal::CHANGED, "{r:?}");
        git(&ws, &["checkout", "-q", "-b", "other"]);
        let r = refused(apply(&w, &query(SeedMode::Update, Some("main"), Some(&tip)), &body, Some(&record)));
        assert_eq!(r.code, refusal::DIVERGED, "{r:?}");
        git(&ws, &["checkout", "-q", "main"]);
        // The VM commits on its own: its tip is no ancestor of the Mac's head.
        write(&ws.join("vm.txt"), "the agent's commit\n");
        git(&ws, &["add", "vm.txt"]);
        git(&ws, &["commit", "-q", "-m", "vm"]);
        let vm_tip = git(&ws, &["rev-parse", "HEAD"]);
        let r = refused(apply(&w, &query(SeedMode::Update, Some("main"), Some(&vm_tip)), &body, Some(&record)));
        assert!(r.code == refusal::DIVERGED && r.message.contains("ancestor"), "{r:?}");
        assert_eq!(git(&ws, &["rev-parse", "HEAD"]), vm_tip, "the VM keeps its commit");
        assert_eq!(git(&ws, &["rev-parse", SEED_REF]), tip, "and its seed ref");
        let shallow = std::fs::read_to_string(ws.join(".git/shallow")).unwrap();
        assert_eq!(shallow, format!("{tip}\n"), "the shallow file restored");
    }

    /// `replace` only on a pristine VM: refused once the agent changed a
    /// file; on a pristine one, the new head checked out, the old seed's
    /// untracked file gone, the new WIP applied.
    #[test]
    fn replace_needs_a_vm_unchanged_since_its_seed() {
        let w = World::new();
        let mac = w.mac();
        write(&mac.join("old-untracked.txt"), "old\n");
        let (seed, body) = clone_body(&mac, Some("main"));
        let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
        let ws = w.ws();
        std::fs::remove_file(mac.join("old-untracked.txt")).unwrap();
        write(&mac.join("a.txt"), "replaced\n");
        git(&mac, &["commit", "-q", "-am", "c3"]);
        write(&mac.join("fresh.txt"), "fresh\n");
        let (m, body) = clone_body(&mac, Some("main"));
        let q = query(SeedMode::Replace, Some("main"), Some(&seed.head));
        write(&ws.join("a.txt"), "the agent's edit\n");
        let r = refused(apply(&w, &q, &body, Some(&record)));
        assert!(r.code == refusal::NOT_PRISTINE && r.state.as_ref().is_some_and(|s| !s.pristine), "{r:?}");
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "the agent's edit\n", "kept");
        write(&ws.join("a.txt"), "three\n");
        let (reply, state) = apply(&w, &q, &body, Some(&record)).unwrap();
        assert_eq!(reply.outcome, SeedApplied::Replaced);
        assert_eq!(git(&ws, &["rev-parse", "HEAD"]), m.head);
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "replaced\n");
        assert!(!ws.join("old-untracked.txt").exists(), "the old seed's WIP went");
        assert_eq!(status(&ws), ["?? fresh.txt"]);
        assert!(state.pristine && state.record.as_ref().unwrap().mode == SeedMode::Replace);
        let shallow = std::fs::read_to_string(ws.join(".git/shallow")).unwrap();
        assert!(shallow.contains(&m.head), "{shallow}");
    }

    /// A replace onto another branch: the new branch checked out at the new
    /// head, the seed's old branch (still at the seeded head) removed; never
    /// onto a branch the agent made itself; and a replace to a detached head.
    #[test]
    fn a_replace_moves_to_another_branch_but_never_an_agents_own() {
        let w = World::new();
        let mac = w.mac();
        let (seed, body) = clone_body(&mac, Some("main"));
        let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
        let ws = w.ws();
        git(&ws, &["branch", "mine"]);
        git(&mac, &["checkout", "-q", "-b", "mine"]);
        write(&mac.join("a.txt"), "on mine\n");
        git(&mac, &["commit", "-q", "-am", "mine"]);
        let (_, onto_mine) = clone_body(&mac, Some("mine"));
        let r = refused(apply(&w, &query(SeedMode::Replace, Some("mine"), Some(&seed.head)), &onto_mine, Some(&record)));
        assert!(r.code == refusal::NOT_PRISTINE && r.message.contains("mine"), "{r:?}");
        assert_eq!(git(&ws, &["rev-parse", "mine"]), seed.head, "the agent's branch is untouched");
        git(&mac, &["checkout", "-q", "-b", "feature"]);
        let (m, onto_feature) = clone_body(&mac, Some("feature"));
        let (reply, state) = apply(&w, &query(SeedMode::Replace, Some("feature"), Some(&seed.head)), &onto_feature, Some(&record)).unwrap();
        assert_eq!(reply.outcome, SeedApplied::Replaced);
        assert_eq!(git(&ws, &["symbolic-ref", "HEAD"]), "refs/heads/feature");
        assert_eq!(git(&ws, &["rev-parse", "HEAD"]), m.head);
        assert!(git(&ws, &["for-each-ref", "--format=%(refname)", "refs/heads/"]).lines().all(|l| l != "refs/heads/main"), "the seed's old branch went");
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "on mine\n");
        let record = state.record.unwrap();
        let (d, detached) = clone_body(&mac, None);
        let (_, state) = apply(&w, &query(SeedMode::Replace, None, Some(&m.head)), &detached, Some(&record)).unwrap();
        assert!(state.branch.is_none() && state.tip.as_deref() == Some(d.head.as_str()));
        assert!(Command::new(real_git()).args(["symbolic-ref", "-q", "HEAD"]).current_dir(&ws).status().unwrap().code() == Some(1), "detached");
        assert_eq!(git(&ws, &["rev-parse", "refs/heads/feature"]), m.head, "a branch left at the head: kept only when it is the seed's own");
    }

    /// Seed, then a VM commit and an uncommitted edit: a code-out with the
    /// WIP snapshot names the branch and a `refs/wip/*` ref; its thin pack
    /// indexes into the Mac's repository; the agent's own index is not
    /// written; the same request again reuses the snapshot, and with every
    /// tip had, nothing is new; past `max_bytes` 413 with the size.
    #[test]
    fn a_codeout_snapshots_then_packs_what_the_mac_lacks() {
        let w = World::new();
        let mac = w.mac();
        let (seed, body) = clone_body(&mac, Some("main"));
        apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap();
        let ws = w.ws();
        write(&ws.join("vm.txt"), "committed in the VM\n");
        git(&ws, &["add", "vm.txt"]);
        git(&ws, &["commit", "-q", "-m", "vm"]);
        let vm_head = git(&ws, &["rev-parse", "HEAD"]);
        write(&ws.join("a.txt"), "edited, uncommitted\n");
        write(&ws.join("new.txt"), "untracked\n");
        let index_before = std::fs::read(ws.join(".git/index")).unwrap();
        let haves = format!("[\"{}\"]", seed.head);
        let out = w.ctx.codeout(WS, true, 1 << 20, &mut Cursor::new(haves.clone().into_bytes())).unwrap();
        assert_eq!(std::fs::read(ws.join(".git/index")).unwrap(), index_before, "the agent's index is never written");
        let m = &out.manifest;
        assert_eq!((m.head.as_str(), m.branch.as_deref()), (vm_head.as_str(), Some("main")));
        let wip_ref = m.wip_ref.clone().expect("a snapshot");
        assert!(wip_ref.starts_with(WIP_REF_PREFIX) && m.refs.contains_key(&wip_ref) && m.refs["refs/heads/main"] == vm_head, "{m:?}");
        m.check().unwrap();
        let (file, len) = out.pack.expect("a pack");
        let pack = std::fs::read(file.path()).unwrap();
        assert_eq!(pack.len() as u64, len);
        drop(file);
        git_env(&mac, &["index-pack", "--stdin", "--fix-thin"], &[], Some(&pack));
        let snap = &m.refs[&wip_ref];
        assert_eq!(git(&mac, &["show", &format!("{snap}:a.txt")]), "edited, uncommitted");
        assert_eq!(git(&mac, &["show", &format!("{snap}:new.txt")]), "untracked");
        assert_eq!(git(&mac, &["rev-parse", &format!("{snap}^1")]), vm_head);
        assert_eq!(status(&ws), [" M a.txt", "?? new.txt"], "the checkout as the agent left it");
        let again = w.ctx.codeout(WS, true, 1 << 20, &mut Cursor::new(haves.into_bytes())).unwrap();
        assert_eq!(again.manifest.wip_ref.as_deref(), Some(wip_ref.as_str()), "unchanged since: the same snapshot");
        drop(again.pack);
        let all: Vec<String> = again.manifest.refs.values().cloned().collect();
        let had = serde_json::to_vec(&all).unwrap();
        assert!(w.ctx.codeout(WS, true, 1 << 20, &mut Cursor::new(had)).unwrap().pack.is_none(), "every tip had: nothing new");
        let r = refused(w.ctx.codeout(WS, false, 10, &mut Cursor::new(b"[]".to_vec())));
        assert!(r.code == refusal::TOO_LARGE && r.size.is_some_and(|s| s > 10), "{r:?}");
        assert!(w.inbox_is_empty());
    }

    /// A snapshot that fails (here an untracked file the agent cannot read)
    /// is skipped with why: the code-out still brings back the VM's commit.
    #[test]
    fn a_codeout_whose_snapshot_fails_still_brings_back_the_commits() {
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("root reads a mode-000 file: skipped");
            return;
        }
        let w = World::new();
        let (seed, body) = clone_body(&w.mac(), Some("main"));
        apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap();
        let ws = w.ws();
        write(&ws.join("vm.txt"), "committed in the VM\n");
        git(&ws, &["add", "vm.txt"]);
        git(&ws, &["commit", "-q", "-m", "vm"]);
        let vm_head = git(&ws, &["rev-parse", "HEAD"]);
        write(&ws.join("locked.txt"), "the agent's, unreadable\n");
        std::fs::set_permissions(ws.join("locked.txt"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let out = w.ctx.codeout(WS, true, 1 << 20, &mut Cursor::new(format!("[\"{}\"]", seed.head).into_bytes())).unwrap();
        let m = &out.manifest;
        assert!(m.wip_ref.is_none() && m.wip_skipped.as_deref().is_some_and(|s| s.starts_with("the snapshot failed: ") && s.contains("locked.txt")), "{m:?}");
        assert_eq!(m.refs["refs/heads/main"], vm_head);
        m.check().unwrap();
        assert!(out.pack.is_some(), "the VM's commit comes back");
        std::fs::set_permissions(ws.join("locked.txt"), std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// The run's budget (`--budget-ms`) cuts every git run: a clone whose
    /// checkout would outlive it is ended by the helper itself, which
    /// removes what the clone made and answers 504 `timeout` before the
    /// shim would end it (a second before the budget).
    #[test]
    fn a_clone_cut_at_its_budget_is_undone_by_the_helper() {
        let w = World::new();
        let (_, body) = clone_body(&w.mac(), Some("main"));
        let slow = w.root().join("slow-git");
        std::fs::write(&slow, format!("#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = reset ]; then sleep 30; fi\ndone\nexec '{}' \"$@\"\n", real_git().display())).unwrap();
        std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A first exec, outside the budget (macOS assesses a new executable then).
        let warmed = {
            let _fork = crate::test_locks::forking();
            Command::new(&slow).arg("--version").stdout(Stdio::null()).status().unwrap()
        };
        assert!(warmed.success());
        // Cut at 5 s (8 less the 3 s reserve): the steps before the checkout take far less.
        let budget = Duration::from_secs(8);
        let ctx = Ctx { home: w.ctx.home.clone(), fs_root: w.ctx.fs_root.clone(), git: slow, started: Instant::now(), budget: Some(budget) };
        let r = refused(ctx.seed_apply(&query(SeedMode::Clone, Some("main"), None), body.len() as u64, None, &mut Cursor::new(body.clone())));
        assert!(r.code == refusal::TIMEOUT && r.message.contains("reset"), "{r:?}");
        assert!(ctx.started.elapsed() < budget - UNDO_MARGIN, "before the shim's end: {:?}", ctx.started.elapsed());
        assert!(!w.ws().exists(), "the clone undone");
        assert!(w.inbox_is_empty());
        assert_eq!(apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().0.outcome, SeedApplied::Cloned, "and the VM can be seeded");
    }

    /// Only the ops that hold the shim's workspace lock use the inbox: each
    /// first removes what a run that never ended left there; the others
    /// never touch it.
    #[test]
    fn the_ops_that_hold_the_workspace_clear_the_inbox_first() {
        let w = World::new();
        let inbox = w.ctx.home.join(INBOX);
        let left = |names: &[&str]| {
            for n in names {
                write(&inbox.join(n), "left by a run that never ended");
            }
        };
        left(&["seed-1a2b3c", "index-4d5e6f", "index-4d5e6f.lock"]);
        let op = ShimIoOp::TranscriptStat { projects: w.ctx.home.join(".claude/projects"), rel: format!("{SLUG}/{ID}.jsonl") };
        dispatch(&w.ctx, &op, &mut Cursor::new(Vec::new()), &mut Vec::new()).unwrap();
        assert!(!w.inbox_is_empty(), "a transcript op leaves the inbox alone");
        dispatch(&w.ctx, &ShimIoOp::SeedState { path: WS.into(), record: None }, &mut Cursor::new(Vec::new()), &mut Vec::new()).unwrap();
        assert!(w.inbox_is_empty());
        left(&["codeout-7a8b9c"]);
        dispatch(&w.ctx, &ShimIoOp::Snapshot { path: WS.into(), budget_s: 8 }, &mut Cursor::new(Vec::new()), &mut Vec::new()).unwrap();
        assert!(w.inbox_is_empty());
    }

    /// The snapshot's caps: an untracked file past the per-file cap skips
    /// the snapshot with the reason (a sparse file: nothing is hashed); a
    /// clean checkout makes none; only the newest WIP_KEEP stay.
    #[test]
    fn snapshots_respect_the_caps_and_keep_the_newest() {
        let w = World::new();
        let (_, body) = clone_body(&w.mac(), Some("main"));
        apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap();
        let ws = w.ws();
        let clean = w.ctx.snapshot(WS, Duration::from_secs(30)).unwrap();
        assert_eq!((clean.wip_ref, clean.wip_skipped), (None, None), "nothing uncommitted");
        let big = std::fs::File::create(ws.join("big.bin")).unwrap();
        big.set_len(SNAPSHOT_MAX_FILE_BYTES + 1).unwrap();
        let skipped = w.ctx.snapshot(WS, Duration::from_secs(30)).unwrap();
        assert!(skipped.wip_ref.is_none() && skipped.wip_skipped.as_deref().is_some_and(|s| s.contains("MiB")), "{skipped:?}");
        std::fs::remove_file(ws.join("big.bin")).unwrap();
        let head = git(&ws, &["rev-parse", "HEAD"]);
        let mut lines = String::new();
        for n in 1..=(WIP_KEEP + 5) {
            lines.push_str(&format!("create refs/wip/20200101T000000Z-{n} {head}\n"));
        }
        git_env(&ws, &["update-ref", "--stdin"], &[], Some(lines.as_bytes()));
        write(&ws.join("a.txt"), "changed\n");
        let made = w.ctx.snapshot(WS, Duration::from_secs(30)).unwrap().wip_ref.expect("a snapshot");
        let left = git(&ws, &["for-each-ref", "--format=%(refname)", "refs/wip/"]);
        assert_eq!(left.lines().count(), WIP_KEEP);
        assert!(left.lines().any(|l| l == made), "the newest is kept");
        assert!(!left.lines().any(|l| l == "refs/wip/20200101T000000Z-1") && left.lines().any(|l| l == "refs/wip/20200101T000000Z-10"), "by time, then number");
    }

    const SLUG: &str = "-Users-mike-ws";
    const ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    /// A transcript: absent, then written (0600, 0700 directories), the same
    /// bytes unchanged, a longer VM copy 409 `vm_longer` with its size, a
    /// longer upload written; a traversal 400; a symlink 409; no temp file
    /// left on any path.
    #[test]
    fn transcripts_are_written_as_the_agent_and_the_longer_vm_copy_wins() {
        let w = World::new();
        let projects = w.ctx.home.join(".claude/projects");
        let rel = format!("{SLUG}/{ID}.jsonl");
        assert!(!w.ctx.transcript_stat(&projects, &rel).unwrap().present);
        let put = |body: &[u8]| w.ctx.transcript_put(&projects, &rel, body.len() as u64, &mut Cursor::new(body.to_vec()));
        let one = put(b"{\"a\":1}\n").unwrap();
        assert_eq!((one.outcome, one.size), (TranscriptWrite::Written, 8));
        let file = projects.join(&rel);
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(projects.join(SLUG)).unwrap().permissions().mode() & 0o777, 0o700);
        let stat = w.ctx.transcript_stat(&projects, &rel).unwrap();
        assert!(stat.present && stat.size == 8 && stat.sha256.as_deref() == Some(one.sha256.as_str()) && stat.mtime.is_some(), "{stat:?}");
        assert_eq!(put(b"{\"a\":1}\n").unwrap().outcome, TranscriptWrite::Unchanged);
        let r = refused(put(b"{}\n"));
        assert!(r.code == refusal::VM_LONGER && r.size == Some(8), "{r:?}");
        assert_eq!(std::fs::read(&file).unwrap(), b"{\"a\":1}\n", "the VM's copy wins");
        assert_eq!(put(b"{\"a\":1}\n{\"b\":2}\n").unwrap().outcome, TranscriptWrite::Written);
        let r = refused(w.ctx.transcript_put(&projects, &rel, 5, &mut Cursor::new(b"abc".to_vec())));
        assert_eq!(r.code, refusal::BAD_REQUEST, "a short body: {r:?}");
        for bad in [format!("../{ID}.jsonl"), format!("{SLUG}/../{ID}.jsonl"), format!("{SLUG}/{ID}/../../x/{ID}.jsonl")] {
            assert_eq!(refused(w.ctx.transcript_stat(&projects, &bad)).code, refusal::BAD_REQUEST, "{bad}");
        }
        let elsewhere = w.root().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, projects.join("-linked")).unwrap();
        let linked = format!("-linked/{ID}.jsonl");
        assert_eq!(refused(w.ctx.transcript_put(&projects, &linked, 2, &mut Cursor::new(b"{}".to_vec()))).code, refusal::SYMLINK_COMPONENT);
        std::os::unix::fs::symlink(&file, projects.join(SLUG).join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c.jsonl")).unwrap();
        assert_eq!(refused(w.ctx.transcript_stat(&projects, &format!("{SLUG}/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c.jsonl"))).code, refusal::SYMLINK_COMPONENT);
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none(), "nothing written through a link");
        let names: Vec<String> = std::fs::read_dir(projects.join(SLUG)).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "no temp file left: {names:?}");
        // A component as long as a name may be: its temp name is its own length.
        let long = format!("{SLUG}/{ID}/subagents/{}.jsonl", "a".repeat(crate::wire::workspace::SEGMENT_MAX - 6));
        assert_eq!(w.ctx.transcript_put(&projects, &long, 3, &mut Cursor::new(b"{}\n".to_vec())).unwrap().outcome, TranscriptWrite::Written);
    }

    /// The settings capture: the three files with their text and sha256, a
    /// symlinked one and an oversized one present but skipped, and only the
    /// allowlisted keys of the workspace's project entry.
    #[test]
    fn settings_capture_reads_the_files_and_the_allowlisted_keys() {
        let w = World::new();
        let ws = w.ws();
        write(&w.ctx.home.join(".claude/settings.json"), "{\"permissions\":{\"allow\":[\"Bash(ls)\"]}}");
        write(&ws.join(".claude/settings.local.json"), "{\"permissions\":{\"allow\":[\"Bash(git status)\"]}}");
        std::os::unix::fs::symlink(w.ctx.home.join(".claude/settings.json"), ws.join(".claude/settings.json")).unwrap();
        let doc = serde_json::json!({"projects": {WS: {"allowedTools": ["Bash(ls)"], "hasTrustDialogAccepted": true, "history": ["secret-looking text"]}, "/other": {"allowedTools": ["x"]}}});
        write(&w.ctx.home.join(".claude/.claude.json"), &doc.to_string());
        let c = w.ctx.settings(WS).unwrap();
        c.check().unwrap();
        assert_eq!(c.files.iter().map(|f| f.scope).collect::<Vec<_>>(), SettingsScope::ALL);
        let user = &c.files[0];
        assert!(user.present && user.text.as_deref().is_some_and(|t| t.contains("Bash(ls)")) && user.sha256.is_some() && user.path == "/home/.claude/settings.json", "{user:?}");
        let project = &c.files[1];
        assert!(project.present && project.text.is_none() && project.skipped.as_deref() == Some("a symlink"), "{project:?}");
        let local = &c.files[2];
        assert!(local.present && local.text.as_deref().is_some_and(|t| t.contains("git status")), "{local:?}");
        assert_eq!(c.project.keys().collect::<Vec<_>>(), ["allowedTools", "hasTrustDialogAccepted"]);
        std::fs::write(ws.join(".claude/settings.local.json"), "x".repeat(SETTINGS_FILE_MAX + 1)).unwrap();
        let big = &w.ctx.settings(WS).unwrap().files[2];
        assert!(big.present && big.text.is_none() && big.size == SETTINGS_FILE_MAX as u64 + 1 && big.sha256.is_some() && big.skipped.as_deref().is_some_and(|s| s.starts_with("larger than")), "{big:?}");
        let none = w.ctx.settings("/home/nothing").unwrap();
        assert!(none.files[1..].iter().all(|f| !f.present) && none.project.is_empty());
        let elsewhere = w.root().join("elsewhere");
        write(&elsewhere.join("settings.json"), "{}");
        std::fs::create_dir_all(w.ctx.home.join("linked")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, w.ctx.home.join("linked/.claude")).unwrap();
        let linked = w.ctx.settings("/home/linked").unwrap();
        assert!(!linked.files[1].present && linked.files[1].text.is_none() && linked.files[1].skipped.as_deref() == Some("not read: symlink_component"), "{:?}", linked.files[1]);
    }

    /// The dispatcher's heads: a reply, a refusal (exit 0), and a seed's
    /// success head carrying the new state for the shim's record.
    #[test]
    fn the_helper_answers_one_head_line() {
        let w = World::new();
        let mut out = Vec::new();
        dispatch(&w.ctx, &ShimIoOp::SeedState { path: "relative".into(), record: None }, &mut Cursor::new(Vec::new()), &mut out).unwrap();
        let head: HelperHead<SeedState> = crate::wire::workspace::parse_head(out.strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(head.outcome().unwrap().unwrap_err().code, refusal::BAD_REQUEST);
        let (_, body) = clone_body(&w.mac(), Some("main"));
        let op = ShimIoOp::SeedApply { path: WS.into(), mode: "clone".into(), branch: Some("main".into()), detached: false, expect: None, len: body.len() as u64, record: None };
        let mut out = Vec::new();
        dispatch(&w.ctx, &op, &mut Cursor::new(body), &mut out).unwrap();
        let head: HelperHead<SeedReply> = crate::wire::workspace::parse_head(out.strip_suffix(b"\n").unwrap()).unwrap();
        assert!(head.ok && head.state.as_ref().and_then(|s| s.record.as_ref()).is_some_and(|r| r.path == WS), "{head:?}");
        assert!(dispatch(&w.ctx, &ShimIoOp::SeedState { path: WS.into(), record: Some("not json".into()) }, &mut Cursor::new(Vec::new()), &mut Vec::new()).is_err(), "a bad record is the helper's own failure");
    }

    /// The shim passes every valued flag as `--name=value` (`asagent::flag`):
    /// a transcript rel starts with its slug's `-`, which clap would read as
    /// a flag of its own after `--rel `.
    #[test]
    fn a_value_starting_with_a_dash_parses_only_after_an_equals_sign() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Line {
            #[command(flatten)]
            io: ShimIoArgs,
        }
        let rel = format!("{SLUG}/{ID}.jsonl");
        let joined = crate::shim::asagent::flag("rel", &rel);
        let parsed = Line::try_parse_from([OsStr::new("ai-env"), OsStr::new("--home=/h"), OsStr::new("transcript-stat"), OsStr::new("--projects=/p"), joined.as_os_str()]).unwrap();
        assert!(matches!(&parsed.io.op, ShimIoOp::TranscriptStat { rel: r, .. } if *r == rel));
        assert_eq!(parsed.io.home, PathBuf::from("/h"));
        assert!(Line::try_parse_from(["ai-env", "transcript-stat", "--projects", "/p", "--rel", &rel]).is_err(), "the split form is a flag clap does not know");
    }

    #[test]
    fn wip_names_sort_by_time_then_number() {
        assert_eq!(wip_key("refs/wip/20261012T101530Z-10"), Some(("20261012T101530Z".into(), 10)));
        assert!(wip_key("refs/wip/20261012T101530Z-2") < wip_key("refs/wip/20261012T101530Z-10"));
        assert_eq!(wip_key("refs/wip/nope"), None);
        assert_eq!(compact_utc(0), "19700101T000000Z");
    }

    /// A body that runs `hook` once, at its first read at or past byte `at`:
    /// the agent at work in the VM while the body comes in (for a seed's
    /// pack, past every check the helper made before it staged the pack).
    struct MidBody<F: FnOnce()> {
        inner: Cursor<Vec<u8>>,
        at: u64,
        hook: Option<F>,
    }

    impl<F: FnOnce()> MidBody<F> {
        fn new(body: &[u8], at: usize, hook: F) -> MidBody<F> {
            MidBody { inner: Cursor::new(body.to_vec()), at: at as u64, hook: Some(hook) }
        }

        fn fire(&mut self) {
            if self.inner.position() >= self.at {
                if let Some(hook) = self.hook.take() {
                    hook();
                }
            }
        }
    }

    impl<F: FnOnce()> Read for MidBody<F> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.fire();
            self.inner.read(buf)
        }
    }

    impl<F: FnOnce()> BufRead for MidBody<F> {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            self.fire();
            self.inner.fill_buf()
        }

        fn consume(&mut self, n: usize) {
            self.inner.consume(n);
        }
    }

    /// The agent's commit in the VM's checkout `ws`: `files` written, all added, committed. Its id.
    fn agent_commit(ws: &Path, files: &[(&str, &str)]) -> String {
        for (name, body) in files {
            write(&ws.join(name), body);
        }
        git(ws, &["add", "-A"]);
        git(ws, &["commit", "-q", "-m", "the agent's commit"]);
        git(ws, &["rev-parse", "HEAD"])
    }

    /// An update of the VM's `tip` (seeded by `seed`) to the Mac's head and
    /// WIP now: the manifest and the body, its thin pack within the VM's
    /// shallow boundary (the tip).
    fn update_of(w: &World, seed: &SeedManifest, tip: &str) -> (SeedManifest, Vec<u8>) {
        let mac = w.mac();
        let head = git(&mac, &["rev-parse", "HEAD"]);
        let wip = wip_of(&mac);
        let mut m = SeedManifest { head: head.clone(), wip: wip.as_ref().map(|x| x.0.clone()), index: wip.as_ref().and_then(|x| x.1.clone()), shallow: Vec::new(), refs: BTreeMap::new(), ..seed.clone() };
        m.refs = m.expected_refs();
        let shallow_file = w.root().join("vm-shallow");
        std::fs::write(&shallow_file, format!("{tip}\n")).unwrap();
        let mut revs = format!("{head}\n");
        if let Some(x) = &m.wip {
            revs.push_str(&format!("{x}\n"));
        }
        revs.push_str(&format!("^{tip}\n"));
        let body = body_of(&m, &mac, &revs, Some(&shallow_file));
        (m, body)
    }

    /// The VM's own smudge filter on `*.txt`: 30 s on a `*b.txt` checkout,
    /// once (`marker` made then) or every time (`None`); otherwise as it is.
    fn slow_smudge(ws: &Path, marker: Option<&Path>) {
        let slow = match marker {
            Some(m) => format!("if [ ! -e '{0}' ]; then : > '{0}'; sleep 30; fi", m.display()),
            None => "sleep 30".to_string(),
        };
        git(ws, &["config", "filter.slow.smudge", &format!("case %f in *b.txt) {slow};; esac; cat")]);
        write(&ws.join(".git/info/attributes"), "*.txt filter=slow\n");
    }

    /// D3 against a commit the agent makes while an update's pack comes in,
    /// past the helper's checks (over a fast-forward, a WIP alone, a WIP
    /// over a file the agent edits, a detached HEAD): the compare-and-swap is
    /// against the tip the checks saw, so the transaction fails, 409
    /// `changed`, and the agent's commit stays where it made it, the checkout
    /// and the seed's refs as the agent left them, `.git/shallow` restored.
    #[test]
    fn an_update_never_moves_a_branch_the_agent_committed_on_meanwhile() {
        for case in ["a fast-forward", "a WIP alone", "a WIP over the agent's edit", "a detached HEAD"] {
            let w = World::new();
            let mac = w.mac();
            let branch = (case != "a detached HEAD").then_some("main");
            let (seed, body) = clone_body(&mac, branch);
            let record = apply(&w, &query(SeedMode::Clone, branch, None), &body, None).unwrap().1.record.unwrap();
            let tip = seed.head.clone();
            match case {
                "a WIP alone" => write(&mac.join("mac-wip.txt"), "uncommitted on the Mac\n"),
                "a WIP over the agent's edit" => write(&mac.join("a.txt"), "the Mac's edit\n"),
                _ => {
                    write(&mac.join("a.txt"), "four\n");
                    git(&mac, &["commit", "-q", "-am", "c3"]);
                }
            }
            let (m, body) = update_of(&w, &seed, &tip);
            let ws = w.ws();
            let edits: &[(&str, &str)] = if case == "a WIP over the agent's edit" { &[("a.txt", "the agent's edit\n"), ("agent.txt", "the agent's\n")] } else { &[("agent.txt", "the agent's\n")] };
            let made = std::cell::OnceCell::new();
            let mut input = MidBody::new(&body, head_line(&m).unwrap().len(), || {
                made.set(agent_commit(&ws, edits)).unwrap();
            });
            let r = refused(w.ctx.seed_apply(&query(SeedMode::Update, branch, Some(&tip)), body.len() as u64, Some(&record), &mut input));
            let x = made.get().expect("the agent committed while the pack came in");
            assert_eq!(r.code, refusal::CHANGED, "{case}: {r:?}");
            assert_eq!(git(&ws, &["rev-parse", "HEAD"]), *x, "{case}: the agent's commit stays");
            if branch.is_some() {
                assert_eq!(git(&ws, &["symbolic-ref", "HEAD"]), "refs/heads/main", "{case}");
            }
            assert!(status(&ws).is_empty(), "{case}: the checkout as the agent left it: {:?}", status(&ws));
            let a = if case == "a WIP over the agent's edit" { "the agent's edit\n" } else { "three\n" };
            assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), a, "{case}");
            assert_eq!(git(&ws, &["rev-parse", SEED_REF]), tip, "{case}");
            assert_eq!(std::fs::read_to_string(ws.join(".git/shallow")).unwrap(), format!("{tip}\n"), "{case}: the shallow file restored");
            assert!(w.inbox_is_empty(), "{case}");
        }
    }

    /// A replace against the agent at work while its pack comes in: a
    /// commit on the seed's branch (a replace onto that branch; onto another,
    /// which removes the seed's branch only where the check saw it), and a
    /// branch of the agent's own made under the replace's new name: each
    /// fails the transaction, 409 `changed`, and the agent's branch keeps its
    /// commit, the checkout as the agent left it.
    #[test]
    fn a_replace_never_moves_a_branch_the_agent_committed_on_meanwhile() {
        for (case, onto) in [("onto its own branch", "main"), ("onto another branch", "feature"), ("onto a branch the agent makes meanwhile", "feature")] {
            let w = World::new();
            let mac = w.mac();
            let (seed, body) = clone_body(&mac, Some("main"));
            let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
            if onto != "main" {
                git(&mac, &["checkout", "-q", "-b", onto]);
            }
            write(&mac.join("a.txt"), "replaced\n");
            git(&mac, &["commit", "-q", "-am", "c3"]);
            let (m, body) = clone_body(&mac, Some(onto));
            let ws = w.ws();
            let agents = if case == "onto a branch the agent makes meanwhile" { onto } else { "main" };
            let made = std::cell::OnceCell::new();
            let mut input = MidBody::new(&body, head_line(&m).unwrap().len(), || {
                // On `main`, or on a branch of its own it then leaves.
                if agents != "main" {
                    git(&ws, &["checkout", "-q", "-b", agents]);
                }
                made.set(agent_commit(&ws, &[("agent.txt", "the agent's\n")])).unwrap();
                if agents != "main" {
                    git(&ws, &["checkout", "-q", "main"]);
                }
            });
            let r = refused(w.ctx.seed_apply(&query(SeedMode::Replace, Some(onto), Some(&seed.head)), body.len() as u64, Some(&record), &mut input));
            let x = made.get().expect("the agent committed while the pack came in");
            assert_eq!(r.code, refusal::CHANGED, "{case}: {r:?}");
            assert_eq!(git(&ws, &["rev-parse", &format!("refs/heads/{agents}")]), *x, "{case}: the agent's branch keeps its commit");
            assert_eq!(git(&ws, &["symbolic-ref", "HEAD"]), "refs/heads/main", "{case}");
            assert_eq!(git(&ws, &["rev-parse", "HEAD"]), if agents == "main" { x.clone() } else { seed.head.clone() }, "{case}");
            assert!(status(&ws).is_empty(), "{case}: the checkout as the agent left it: {:?}", status(&ws));
            assert_eq!(git(&ws, &["rev-parse", SEED_REF]), seed.head, "{case}");
        }
    }

    /// An update's or a replace's two-way checkout cut at the run's budget
    /// (the VM's smudge filter sleeps on `d/b.txt`, once): the refs go back
    /// first, then exactly what the cut checkout wrote or removed (`a.txt`
    /// back, the new `c.txt` gone, `d/b.txt` back), nothing else: an edit the
    /// agent made meanwhile to a file the move never touched stays (`read-tree
    /// --reset -u` would lose it). 504 `timeout` before the shim's end; with the
    /// agent's edit undone, `GET /seed` reads the VM clean and pristine.
    #[test]
    fn a_cut_checkout_puts_back_what_it_wrote_and_nothing_else() {
        for mode in [SeedMode::Update, SeedMode::Replace] {
            let w = World::new();
            let mac = w.mac();
            write(&mac.join("e.txt"), "e\n");
            git(&mac, &["add", "e.txt"]);
            git(&mac, &["commit", "-q", "-m", "e"]);
            let (seed, body) = clone_body(&mac, Some("main"));
            let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
            let tip = seed.head.clone();
            write(&mac.join("a.txt"), "four\n");
            write(&mac.join("c.txt"), "new\n");
            write(&mac.join("d/b.txt"), "changed\n");
            git(&mac, &["add", "-A"]);
            git(&mac, &["commit", "-q", "-m", "c3"]);
            let (m, body) = if mode == SeedMode::Update { update_of(&w, &seed, &tip) } else { clone_body(&mac, Some("main")) };
            let ws = w.ws();
            slow_smudge(&ws, Some(&w.root().join("smudged-once")));
            // Cut at 5 s (8 less the 3 s reserve): the steps before the checkout take far less.
            let budget = Duration::from_secs(8);
            let ctx = Ctx { home: w.ctx.home.clone(), fs_root: w.ctx.fs_root.clone(), git: real_git(), started: Instant::now(), budget: Some(budget) };
            let mut input = MidBody::new(&body, head_line(&m).unwrap().len(), || write(&ws.join("e.txt"), "the agent's edit\n"));
            let r = refused(ctx.seed_apply(&query(mode, Some("main"), Some(&tip)), body.len() as u64, Some(&record), &mut input));
            assert!(r.code == refusal::TIMEOUT && r.message.contains("read-tree"), "{mode:?}: {r:?}");
            assert!(ctx.started.elapsed() < budget - UNDO_MARGIN, "{mode:?}: before the shim's end: {:?}", ctx.started.elapsed());
            for name in ["HEAD", "refs/heads/main", SEED_REF] {
                assert_eq!(git(&ws, &["rev-parse", name]), tip, "{mode:?}: {name}");
            }
            assert_eq!(status(&ws), [" M e.txt"], "{mode:?}: the agent's edit, and nothing of the move's");
            let read = |p: &str| std::fs::read_to_string(ws.join(p)).unwrap();
            assert_eq!((read("a.txt"), read("d/b.txt"), read("e.txt")), ("three\n".into(), "two\n".into(), "the agent's edit\n".into()), "{mode:?}");
            assert!(!ws.join("c.txt").exists(), "{mode:?}: the file the cut checkout added is gone");
            assert_eq!(read(".git/shallow"), format!("{tip}\n"), "{mode:?}");
            git(&ws, &["checkout", "--", "e.txt"]);
            let st = w.ctx.seed_state(WS, Some(&record)).unwrap();
            assert!(st.clean && st.pristine, "{mode:?}: {st:?}");
            assert!(w.inbox_is_empty(), "{mode:?}");
        }
    }

    /// The new WIP cut at the run's budget after the two-way checkout went
    /// through, with a restore as slow (the smudge sleeps on every
    /// `d/b.txt`): the refs go back first, so the VM never reads as a moved
    /// tip whatever the files' restore had time for; what the two-way
    /// checkout wrote is put back before the slow file.
    #[test]
    fn a_wip_cut_at_its_budget_puts_the_refs_back_first() {
        let w = World::new();
        let mac = w.mac();
        let (seed, body) = clone_body(&mac, Some("main"));
        let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
        let tip = seed.head.clone();
        write(&mac.join("a.txt"), "four\n");
        git(&mac, &["commit", "-q", "-am", "c3"]);
        write(&mac.join("d/b.txt"), "uncommitted on the Mac\n");
        let (m, body) = update_of(&w, &seed, &tip);
        assert!(m.wip.is_some());
        let ws = w.ws();
        slow_smudge(&ws, None);
        let budget = Duration::from_secs(8);
        let ctx = Ctx { home: w.ctx.home.clone(), fs_root: w.ctx.fs_root.clone(), git: real_git(), started: Instant::now(), budget: Some(budget) };
        let r = refused(ctx.seed_apply(&query(SeedMode::Update, Some("main"), Some(&tip)), body.len() as u64, Some(&record), &mut Cursor::new(body.clone())));
        assert!(r.code == refusal::TIMEOUT && r.message.contains("the WIP"), "{r:?}");
        assert!(ctx.started.elapsed() < budget, "before the shim's end: {:?}", ctx.started.elapsed());
        for name in ["HEAD", "refs/heads/main", SEED_REF] {
            assert_eq!(git(&ws, &["rev-parse", name]), tip, "{name}: the VM never reads as a moved tip");
        }
        let wip_ref = Command::new(real_git()).args(["rev-parse", "--verify", "-q", SEED_WIP_REF]).current_dir(&ws).stdout(Stdio::null()).status().unwrap();
        assert_eq!(wip_ref.code(), Some(1), "the new WIP's ref is gone");
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "three\n", "what the two-way checkout wrote is put back");
    }

    /// While the cut two-way checkout runs (inside `d/b.txt`'s smudge, once),
    /// the agent edits `e.txt` (the move changes it; git has not reached it)
    /// and writes its own `c.txt` (the move adds it; git wrote it first):
    /// `a.txt` and `d/b.txt` go back, both of the agent's files stay as it
    /// left them.
    #[test]
    fn a_cut_checkout_leaves_the_agents_files_the_move_touches() {
        let w = World::new();
        let mac = w.mac();
        write(&mac.join("e.txt"), "e\n");
        git(&mac, &["add", "e.txt"]);
        git(&mac, &["commit", "-q", "-m", "e"]);
        let (seed, body) = clone_body(&mac, Some("main"));
        let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
        let tip = seed.head.clone();
        for (p, t) in [("a.txt", "four\n"), ("c.txt", "new\n"), ("d/b.txt", "changed\n"), ("e.txt", "the Mac's e\n")] {
            write(&mac.join(p), t);
        }
        git(&mac, &["add", "-A"]);
        git(&mac, &["commit", "-q", "-m", "c3"]);
        let (_, body) = update_of(&w, &seed, &tip);
        let ws = w.ws();
        // `slow_smudge`'s filter, with the agent's writes before its sleep.
        let marker = w.root().join("smudged-once");
        let edits = format!("printf 'the agent edit\\n' > '{}'; printf 'the agent c\\n' > '{}'", ws.join("e.txt").display(), ws.join("c.txt").display());
        git(&ws, &["config", "filter.slow.smudge", &format!("case %f in *b.txt) if [ ! -e '{0}' ]; then : > '{0}'; {edits}; sleep 30; fi;; esac; cat", marker.display())]);
        write(&ws.join(".git/info/attributes"), "*.txt filter=slow\n");
        let ctx = Ctx { home: w.ctx.home.clone(), fs_root: w.ctx.fs_root.clone(), git: real_git(), started: Instant::now(), budget: Some(Duration::from_secs(8)) };
        let r = refused(ctx.seed_apply(&query(SeedMode::Update, Some("main"), Some(&tip)), body.len() as u64, Some(&record), &mut Cursor::new(body.clone())));
        assert_eq!(r.code, refusal::TIMEOUT, "{r:?}");
        let read = |p: &str| std::fs::read_to_string(ws.join(p)).unwrap_or_else(|e| format!("({e})"));
        assert_eq!((read("a.txt"), read("d/b.txt"), read("c.txt"), read("e.txt")), ("three\n".into(), "two\n".into(), "the agent c\n".into(), "the agent edit\n".into()));
        assert_eq!(status(&ws), [" M e.txt", "?? c.txt"]);
    }

    /// A two-way checkout that fails while writing (here a directory the
    /// agent made read-only; a full disk or a required filter that fails
    /// alike): git wrote `a.txt`, then could not replace `d/b.txt`. The refs
    /// go back, then what it wrote: 409 `dirty`, and the VM reads clean and
    /// pristine again.
    #[test]
    fn a_checkout_that_fails_while_writing_puts_back_what_it_wrote() {
        // SAFETY: a plain getter.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("root writes into a mode-555 directory: skipped");
            return;
        }
        let w = World::new();
        let mac = w.mac();
        let (seed, body) = clone_body(&mac, Some("main"));
        let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
        let tip = seed.head.clone();
        write(&mac.join("a.txt"), "four\n");
        write(&mac.join("d/b.txt"), "changed\n");
        git(&mac, &["commit", "-q", "-am", "c3"]);
        let (_, body) = update_of(&w, &seed, &tip);
        let ws = w.ws();
        std::fs::set_permissions(ws.join("d"), std::fs::Permissions::from_mode(0o555)).unwrap();
        let got = apply(&w, &query(SeedMode::Update, Some("main"), Some(&tip)), &body, Some(&record));
        std::fs::set_permissions(ws.join("d"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = refused(got);
        assert!(r.code == refusal::DIRTY && r.message.contains("'d/b.txt'"), "{r:?}");
        for name in ["HEAD", "refs/heads/main", SEED_REF] {
            assert_eq!(git(&ws, &["rev-parse", name]), tip, "{name}");
        }
        assert!(status(&ws).is_empty(), "what git wrote is put back: {:?}", status(&ws));
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "three\n");
        let st = w.ctx.seed_state(WS, Some(&record)).unwrap();
        assert!(st.clean && st.pristine, "{st:?}");
    }

    /// The VM's claude writing on while an upload comes in: a copy longer
    /// than the upload by the time it would be renamed over still wins (409
    /// `vm_longer` with its size now, the VM's bytes kept, no temp file
    /// left); one that grew but stays shorter is replaced (the longer wins).
    #[test]
    fn a_vm_copy_grown_while_the_upload_came_in_still_wins() {
        let w = World::new();
        let projects = w.ctx.home.join(".claude/projects");
        let rel = format!("{SLUG}/{ID}.jsonl");
        let file = projects.join(&rel);
        let first = b"{\"a\":1}\n";
        let entry = b"{\"type\":\"assistant\",\"n\":2}\n";
        let grown = [&first[..], &entry[..]].concat();
        for upload in [b"{\"a\":1}\n{\"b\":2}\n".to_vec(), vec![b'x'; 64]] {
            let _ = std::fs::remove_file(&file);
            assert_eq!(w.ctx.transcript_put(&projects, &rel, first.len() as u64, &mut Cursor::new(first.to_vec())).unwrap().outcome, TranscriptWrite::Written);
            let mut input = MidBody::new(&upload, 0, || std::fs::OpenOptions::new().append(true).open(&file).unwrap().write_all(entry).unwrap());
            let got = w.ctx.transcript_put(&projects, &rel, upload.len() as u64, &mut input);
            if grown.len() > upload.len() {
                let r = refused(got);
                assert!(r.code == refusal::VM_LONGER && r.size == Some(grown.len() as u64), "{r:?}");
                assert_eq!(std::fs::read(&file).unwrap(), grown, "the VM's copy wins");
            } else {
                assert_eq!(got.unwrap().outcome, TranscriptWrite::Written);
                assert_eq!(std::fs::read(&file).unwrap(), upload, "a copy still shorter is replaced");
            }
            let names: Vec<String> = std::fs::read_dir(projects.join(SLUG)).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            assert!(names.iter().all(|n| !n.ends_with(".tmp")), "no temp file left: {names:?}");
        }
    }

    /// A put a helper ended by a signal left its temp file (no drop ran):
    /// the next put into that directory removes it; only names a put makes,
    /// and only regular files (a look-alike name, a symlink, a longer name stay).
    #[test]
    fn the_next_put_sweeps_what_an_ended_put_left() {
        let w = World::new();
        let projects = w.ctx.home.join(".claude/projects");
        let dir = projects.join(SLUG);
        write(&dir.join(".ai-env-0123456789abcdef.tmp"), "half a transcript");
        write(&dir.join(".ai-env-ABCDEF0123456789.tmp"), "not a put's");
        write(&dir.join(".ai-env-0123456789abcdef.tmp.keep"), "not a put's");
        std::os::unix::fs::symlink(dir.join(".ai-env-ABCDEF0123456789.tmp"), dir.join(".ai-env-fedcba9876543210.tmp")).unwrap();
        let put = w.ctx.transcript_put(&projects, &format!("{SLUG}/{ID}.jsonl"), 3, &mut Cursor::new(b"{}\n".to_vec())).unwrap();
        assert_eq!(put.outcome, TranscriptWrite::Written);
        let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, [".ai-env-0123456789abcdef.tmp.keep", ".ai-env-ABCDEF0123456789.tmp", ".ai-env-fedcba9876543210.tmp", &format!("{ID}.jsonl")]);
        assert!(is_put_temp(b".ai-env-0123456789abcdef.tmp") && !is_put_temp(b".ai-env-0123456789abcde.tmp") && !is_put_temp(format!("{ID}.jsonl").as_bytes()));
    }

    /// The snapshot adds the vetted untracked files by name, never as
    /// pathspec magic (`--literal-pathspecs`, as the Mac's snapshot): files
    /// named like exclusions are carried, not left out; one whose name would
    /// be a pathspec matching nothing (`:w`) fails neither `GET /seed`'s
    /// pristine check nor the snapshot, nor the code-out's WIP.
    #[test]
    fn a_snapshot_takes_untracked_names_literally() {
        let w = World::new();
        let (seed, body) = clone_body(&w.mac(), Some("main"));
        let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
        let ws = w.ws();
        write(&ws.join(":w"), "a stray write\n");
        let st = w.ctx.seed_state(WS, Some(&record)).unwrap();
        assert!(!st.clean && !st.pristine, "{st:?}");
        for name in [":!todo.txt", ":(exclude)notes.txt", "plain.txt"] {
            write(&ws.join(name), "untracked\n");
        }
        let wip = w.ctx.snapshot(WS, Duration::from_secs(30)).unwrap().wip_ref.expect("a snapshot");
        assert_eq!(git(&ws, &["ls-tree", "--name-only", &wip]).lines().collect::<Vec<_>>(), [":!todo.txt", ":(exclude)notes.txt", ":w", "a.txt", "d", "plain.txt"]);
        let out = w.ctx.codeout(WS, true, 1 << 20, &mut Cursor::new(format!("[\"{}\"]", seed.head).into_bytes())).unwrap();
        assert!(out.manifest.wip_skipped.is_none() && out.manifest.wip_ref.as_deref() == Some(wip.as_str()), "{:?}", out.manifest);
    }
}
