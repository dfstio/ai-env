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
//! * `transcript-stat`: a transcript under `--projects`
//!   (`transcript_rel_check`'s rel): its presence, size, sha256 and mtime;
//! * `settings`: the agent's `settings.json`, the workspace's
//!   `.claude/settings.json` and `.claude/settings.local.json` (each at most
//!   `SETTINGS_FILE_MAX` of text, with its sha256), and the `PROJECT_KEYS` of
//!   the workspace's entry in the agent's `.claude/.claude.json`.
//!
//! S9 (plans/s9-contracts.md §3) adds, none of them using the inbox:
//! `transcript-stat --from/--fp/--subtree` (the extended stat),
//! `transcript-read` (a range of the transcript after the head, for a push),
//! `transcript-write` (a pull's bytes, then the line `commit`, then the
//! rename), `transcript-view` (the Mac's view, `wire::view::build_view`) and
//! `git-cgi` (`git http-backend` for the seeded workspace, upload-pack only).
//! An op whose reply can pass `HEAD_LINE_MAX` (the view, a subtree stat)
//! answers through [`answer_payload`]: a `JsonPayloadReply` head, then the
//! reply's JSON. S8's `transcript-put` (the Mac's mirror written into the
//! VM) went at the S3 cut-over: `transcript-write` writes what a pull brings.
use crate::errors::{CliError, Result};
use crate::gitrun::{GitError, GitRun};
use crate::wire::view::TranscriptViewReply;
use crate::wire::workspace::{
    budget, head_line, read_head_line, refusal, transcript_rel_check, vm_path_check, CodeoutManifest, HelperHead, ObjectFormat, SeedApplied, SeedManifest, SeedMode, SeedQuery, SeedRecord, SeedReply, SeedState,
    SettingsCapture, SettingsFile, SettingsScope, SnapshotReply, TranscriptStat, WsRefusal, HAVES_MAX, HEADS_PREFIX, HEAD_LINE_MAX, PROJECT_KEYS, SEED_BODY_MAX, SEED_REF, SEED_WIP_REF, SETTINGS_FILE_MAX,
    WIP_REF_PREFIX,
};
use crate::wire::workspace::{GitCgiReply, JsonPayloadReply, TranscriptWriteReply, JSON_PAYLOAD_MAX};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

/// The ops, as their subcommands are spelled (S8's `transcript-put` went at the S3 cut-over).
pub const OPS: [&str; 10] = ["seed-state", "seed-apply", "codeout", "snapshot", "transcript-stat", "transcript-read", "transcript-write", "transcript-view", "settings", "git-cgi"];

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
    /// Presence, size and sha256 of the transcript REL under PROJECTS; with --from the delta's sha256 and the fingerprints a sync needs, with --subtree the session's files (GET /transcript)
    TranscriptStat {
        /// The agent's projects directory
        #[arg(long, value_name = "DIR")]
        projects: PathBuf,
        /// The transcript's path under it (slug/uuid.jsonl, or slug/uuid/…)
        #[arg(long)]
        rel: String,
        /// The length S3 holds: hash [FROM, size) and the fingerprint at the end, never the whole file (S9)
        #[arg(long, value_name = "N")]
        from: Option<u64>,
        /// The fingerprint at FROM the Mac recorded (64 hex), checked against the file (S9)
        #[arg(long, value_name = "HEX", requires = "from")]
        fp: Option<String>,
        /// Also list the session's subtree, each file with its sha256 (S9)
        #[arg(long)]
        subtree: bool,
    },
    /// LEN bytes of the transcript REL under PROJECTS from FROM, after the head (POST /transcript/push)
    TranscriptRead {
        /// The agent's projects directory
        #[arg(long, value_name = "DIR")]
        projects: PathBuf,
        /// The transcript's path under it (slug/uuid.jsonl, or slug/uuid/…)
        #[arg(long)]
        rel: String,
        /// The first byte
        #[arg(long, value_name = "N")]
        from: u64,
        /// How many bytes
        #[arg(long, value_name = "N")]
        len: u64,
    },
    /// Write the transcript REL under PROJECTS from stdin: LEN bytes, then the line commit; renamed into place only then (POST /transcript/pull)
    TranscriptWrite {
        /// The agent's projects directory
        #[arg(long, value_name = "DIR")]
        projects: PathBuf,
        /// The transcript's path under it (slug/uuid.jsonl, or slug/uuid/…)
        #[arg(long)]
        rel: String,
        /// The file's length in bytes
        #[arg(long, value_name = "N")]
        len: u64,
        /// The bytes' sha256 (64 hex), when known: anything else is refused
        #[arg(long, value_name = "HEX")]
        sha256: Option<String>,
    },
    /// The last N messages of the transcript REL under PROJECTS, as the Mac's view takes them (GET /transcript/view)
    TranscriptView {
        /// The agent's projects directory
        #[arg(long, value_name = "DIR")]
        projects: PathBuf,
        /// The transcript's path under it (slug/uuid.jsonl)
        #[arg(long)]
        rel: String,
        /// How many messages
        #[arg(long, value_name = "N")]
        n: u32,
    },
    /// The agent's settings.json, the workspace's .claude/settings.json and settings.local.json, and the allowlisted keys of PATH's entry under projects in .claude.json (GET /settings)
    Settings {
        /// The workspace's path in the VM (absolute, NFC)
        #[arg(long)]
        path: String,
    },
    /// git http-backend for the seeded workspace at PATH, upload-pack only: the head, then the CGI's output (the code port's git routes)
    GitCgi(GitCgiArgs),
}

/// `git-cgi`'s flags (S9 §3.3): none of them secret (uid 1000 can read
/// them); the router passes only the literal routes' values.
#[derive(clap::Args, Debug, Clone)]
pub struct GitCgiArgs {
    /// The seeded workspace's path in the VM (absolute, NFC)
    #[arg(long)]
    pub path: String,
    /// GET (the advertisement) or POST (an upload-pack request)
    #[arg(long, value_parser = ["GET", "POST"])]
    pub method: String,
    /// The CGI's PATH_INFO: /info/refs or /git-upload-pack (never the URL's)
    #[arg(long, value_parser = ["/info/refs", "/git-upload-pack"])]
    pub path_info: String,
    /// The request's query (GET: exactly service=git-upload-pack)
    #[arg(long, value_name = "Q")]
    pub query: Option<String>,
    /// The request's Content-Type (POST)
    #[arg(long, value_name = "T")]
    pub content_type: Option<String>,
    /// The request body's length (POST): exactly that many bytes come on stdin
    #[arg(long, value_name = "N")]
    pub content_length: Option<u64>,
    /// The request's Content-Encoding
    #[arg(long, value_parser = ["gzip", "x-gzip"])]
    pub content_encoding: Option<String>,
    /// The request's Git-Protocol header
    #[arg(long, value_parser = ["version=0", "version=1", "version=2"])]
    pub git_protocol: Option<String>,
    /// The client's address (the CGI's REMOTE_ADDR)
    #[arg(long, value_name = "A")]
    pub remote_addr: String,
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
            ShimIoOp::TranscriptRead { .. } => OPS[5],
            ShimIoOp::TranscriptWrite { .. } => OPS[6],
            ShimIoOp::TranscriptView { .. } => OPS[7],
            ShimIoOp::Settings { .. } => OPS[8],
            ShimIoOp::GitCgi(_) => OPS[9],
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
        ShimIoOp::TranscriptStat { projects, rel, from: None, fp: None, subtree: false } => answer(out, ctx.transcript_stat(projects, rel)),
        ShimIoOp::TranscriptStat { projects, rel, from, fp, subtree: true } => answer_payload(out, ctx.transcript_stat_from(projects, rel, *from, fp.as_deref(), true)),
        ShimIoOp::TranscriptStat { projects, rel, from, fp, subtree: false } => answer(out, ctx.transcript_stat_from(projects, rel, *from, fp.as_deref(), false)),
        ShimIoOp::TranscriptRead { projects, rel, from, len } => ctx.transcript_read(projects, rel, *from, *len, out),
        ShimIoOp::TranscriptWrite { projects, rel, len, sha256 } => answer(out, ctx.transcript_write(projects, rel, *len, sha256.as_deref(), input)),
        ShimIoOp::TranscriptView { projects, rel, n } => answer_payload(out, ctx.transcript_view(projects, rel, *n)),
        ShimIoOp::Settings { path } => answer(out, ctx.settings(path)),
        ShimIoOp::GitCgi(a) => ctx.git_cgi(a, input, out),
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

/// [`answer`] for an op whose reply can pass `HEAD_LINE_MAX` (S9: the view,
/// a subtree stat): the head is a [`JsonPayloadReply`] (the reply's compact
/// JSON's sha256) with its `len`, then exactly those bytes, at most
/// [`JSON_PAYLOAD_MAX`] (more is the helper's exit 1); a refusal is an
/// ordinary refusal head.
fn answer_payload<T: Serialize>(out: &mut dyn Write, step: Step<T>) -> Result<()> {
    let reply = match step {
        Ok(reply) => reply,
        Err(stop) => return refused::<JsonPayloadReply>(out, stop),
    };
    let json = serde_json::to_vec(&reply).map_err(|e| CliError::Msg(format!("the reply does not serialise: {e}")))?;
    if json.len() > JSON_PAYLOAD_MAX {
        return Err(CliError::Msg(format!("the reply is {} bytes of JSON (at most {JSON_PAYLOAD_MAX})", json.len())));
    }
    let sha256 = hex::encode(Sha256::digest(&json));
    emit(out, &HelperHead::ok(JsonPayloadReply { sha256 }, Some(json.len() as u64)))?;
    out.write_all(&json)?;
    out.flush()?;
    Ok(())
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

    /// A copy of the agent's index in the inbox (empty when it has none),
    /// with the index's own mtime (S9): git trusts an entry's cached stat
    /// only when the file is older than the index, so a copy with a newer
    /// mtime would take a file edited at the same size in the index's own
    /// second for clean, and the snapshot would leave the edit out (the Mac's
    /// copies keep the mtime too, `bridge::workspace::snapshot::copy_index`).
    /// The mtime is read before the bytes: an index rewritten in between
    /// leaves the copy older than its bytes, which only makes git re-read
    /// more files.
    fn index_copy(&self) -> Step<tempfile::NamedTempFile> {
        let copy = self.ctx.staged("index-")?;
        let index = self.git_path("index")?;
        let modified = std::fs::metadata(&index).and_then(|m| m.modified());
        match std::fs::read(&index) {
            Ok(bytes) => {
                std::fs::write(copy.path(), bytes)?;
                // An index made between the two reads had no mtime yet: the copy keeps its own.
                if let Ok(at) = modified {
                    copy.as_file().set_modified(at)?;
                }
            }
            // No index: an empty one (git reads a missing or empty file as none).
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(copy)
    }

    /// The snapshot trees ([`Trees`]), each built in a copy of the index:
    /// the tracked changes (`add -u`) and the untracked files that are not
    /// ignored, regular files and symlinks only (a nested repository, a fifo
    /// or a socket stays out), within the snapshot caps; an untracked file
    /// gone since its listing (the agent removed it meanwhile) is left out,
    /// never a failed snapshot (S9, W3 #10). `Err(why)` when it is skipped
    /// (over a cap, no commit checked out).
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
            // The names as they are: update-index takes paths, never pathspec magic (`:!x`, `:(top)`, `:w`), as
            // the Mac's snapshot takes them; `--remove` drops one gone since the listing from the copy (W3 #10),
            // where `add` failed the whole snapshot on it.
            git().output_stdin(["update-index", "--add", "--remove", "-z", "--stdin"], &list).map_err(git_stop("update-index"))?;
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

/// The oldest git a seed's update or replace takes (F8): `update-ref
/// --stdin` learned `symref-verify` in 2.46 (the image has 2.50.1).
const GIT_FLOOR: (u32, u32) = (2, 46);

impl Ctx {
    /// F8 (S9): the helper's git is [`GIT_FLOOR`] or later, so a move can
    /// check that HEAD still names the branch its checks saw
    /// ([`verified_transaction`]); an older one is a `git_failed` refusal
    /// naming its version, before anything moves.
    fn git_floor(&self) -> Step<()> {
        let out = self.git_in(&self.home, Duration::from_secs(10)).output(["version"]).map_err(git_stop("version"))?;
        let said = text(&out);
        if git_version(&said).is_some_and(|v| v >= GIT_FLOOR) {
            return Ok(());
        }
        refuse(refusal::GIT_FAILED, &format!("the VM's git is {said:?}: a seed's update or replace needs git {}.{} or later (update-ref's symref-verify)", GIT_FLOOR.0, GIT_FLOOR.1))
    }
}

/// `(major, minor)` of a `git version` line (`git version 2.50.1`, `git
/// version 2.54.0 (Apple Git-157)`); `None` for anything else.
fn git_version(line: &str) -> Option<(u32, u32)> {
    let v = line.strip_prefix("git version ")?.split_whitespace().next()?;
    let mut parts = v.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
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

/// [`transaction`] of `lines`, after `verify`'s own transaction in the same
/// `update-ref --stdin` run (F8: its `symref-verify HEAD …`): git's files
/// backend refuses HEAD and its branch in one transaction ("multiple
/// updates for 'HEAD' (including one via its referent …)"), so the check
/// commits first, and when it fails git stops there: `lines` never run.
fn verified_transaction(git: &GitRun, verify: &[String], lines: &[String]) -> std::result::Result<(), GitError> {
    if verify.is_empty() {
        return transaction(git, lines);
    }
    let mut input = String::new();
    for block in [verify, lines] {
        input.push_str("start\n");
        for l in block {
            input.push_str(l);
            input.push('\n');
        }
        input.push_str("prepare\ncommit\n");
    }
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
    /// then the checkout ([`Repo::restore_checkout`]). F8 (S9): git
    /// [`GIT_FLOOR`] or later first, and a HEAD on a branch must still name
    /// it (`symref-verify`, [`verified_transaction`]): an agent that switched
    /// to another branch at the same commit while the pack came in keeps its
    /// checkout (409 `changed`), where the move went on under its new HEAD.
    fn move_refs_and_tree(&self, repo: &Repo<'_>, q: &SeedQuery, m: &SeedManifest, record: &SeedRecord, tip: &str, old_detached: Option<&str>) -> Step<()> {
        self.git_floor()?;
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
        // The branch HEAD named at the checks (an update's, which the checks
        // compared with the query's; a pristine replace's, the seed's): it must
        // still. A detached HEAD has no name to verify (`symref-verify` with no
        // target asks that HEAD not exist); its update is against the tip.
        let head_branch = match (old_detached, q.mode) {
            (Some(_), _) => None,
            (None, SeedMode::Update) => q.branch.as_ref(),
            (None, _) => record.branch.as_ref(),
        };
        let verify: Vec<String> = head_branch.map(|b| vec!["option no-deref".into(), format!("symref-verify HEAD {HEADS_PREFIX}{b}")]).unwrap_or_default();
        if let Err(e) = verified_transaction(&repo.git(), &verify, &forward) {
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
            // A one-way merge without `-u` (F8, as `Repo::restore_checkout`'s):
            // an entry it keeps keeps its stat data, so the refresh hashes only
            // what the seed's index and worktree differ in (a plain `read-tree`
            // dropped it all: the whole checkout hashed again on every replace).
            let refreshed = repo.git().output(["read-tree", "--reset", &from]).and_then(|_| repo.git().output(["update-index", "-q", "--refresh"]));
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

/// The stand-in a code-out lists a credential-shaped VM ref under (F4): the
/// ref's own namespace, then this and a number. The scrubber masks a
/// `token=` value, so the Mac's screen (`codeout::credential_shaped`) takes
/// the stand-in for what it stands for: hidden and counted, never fetched.
const HIDDEN_STAND_IN: &str = "token=hidden-";

/// F4 (S9): the refs of `m` whose name the scrubber masks part of (the
/// setup-token's shape, an AWS key id, a `token=` value: the agent can name
/// a branch or a snapshot after what it reads in the VM) never leave the VM
/// by name. Each is listed under a stand-in ([`HIDDEN_STAND_IN`], numbered
/// in name order) at its commit, and so are the branch checked out and the
/// snapshot (`wip_ref`) when they are among them, so the Mac still counts
/// them (`box fetch`'s note, the dry run's "a branch whose name looks like a
/// credential") with no change to the wire. A tripwire, not a proof, as on
/// the Mac, whose custom tripwires this side never sees.
fn hide_credential_shaped(m: &mut CodeoutManifest) {
    use crate::wire::redact::scrub;
    let names: Vec<String> = m.refs.keys().filter(|n| scrub(n) != n.as_str()).cloned().collect();
    // Every hidden ref out first: a stand-in may spell a hidden ref's own name.
    let hidden: Vec<(String, String)> = names.into_iter().filter_map(|n| m.refs.remove(&n).map(|id| (n, id))).collect();
    let mut stand_ins = BTreeMap::new();
    for (i, (name, id)) in hidden.into_iter().enumerate() {
        let space = if name.starts_with(WIP_REF_PREFIX) { WIP_REF_PREFIX } else { HEADS_PREFIX };
        let stand_in = format!("{space}{HIDDEN_STAND_IN}{}", i + 1);
        m.refs.insert(stand_in.clone(), id);
        stand_ins.insert(name, stand_in);
    }
    if let Some(w) = m.wip_ref.take() {
        m.wip_ref = Some(stand_ins.get(&w).cloned().unwrap_or(w));
    }
    if let Some(b) = m.branch.take() {
        let hidden = scrub(&b) != b.as_str();
        m.branch = Some(match stand_ins.get(&format!("{HEADS_PREFIX}{b}")) {
            Some(s) => s.strip_prefix(HEADS_PREFIX).unwrap_or(s).to_string(),
            None if hidden => format!("{HIDDEN_STAND_IN}{}", stand_ins.len() + 1),
            None => b,
        });
    }
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
        let (wip_ref, wip_skipped) = self.take_snapshot(&repo, true)?;
        Ok(SnapshotReply { wip_ref, wip_skipped, ms: self.ms() })
    }

    /// Snapshot the uncommitted work (module doc): the `refs/wip/*` made or
    /// kept (`None` when the checkout matches its head), or why none was made.
    /// S9 (F4): `by_name` when the reply names it as it is (`/suspend`'s,
    /// whose name the shim logs and keeps for its health): a snapshot kept
    /// then never has a name the scrubber masks part of. The agent can make
    /// such a ref at the checkout's tree and parents, and `zz-<token>-<n>`
    /// sorts after every time: the newest of the other snapshots is the one
    /// compared, and with none the helper makes its own. The code-out keeps
    /// S8's choice, which its manifest names through a stand-in
    /// ([`hide_credential_shaped`]) that the Mac hides.
    fn take_snapshot(&self, repo: &Repo<'_>, by_name: bool) -> Step<(Option<String>, Option<String>)> {
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
        // Unchanged since the newest snapshot (with `by_name`, the newest whose name may leave the VM: F4): the same
        // tree on the same parents.
        if let Some((_, _, newest)) = wips.iter().rev().find(|(_, _, n)| !by_name || crate::wire::redact::scrub(n) == n.as_str()) {
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
        let (wip_ref, wip_skipped) = match wip.then(|| self.take_snapshot(&repo, false)) {
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
        // F4 (S9): nor does a name that looks like a credential leave it (a stand-in in its place).
        hide_credential_shaped(&mut manifest);
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

// ---- git smart-HTTP (G1) ----

/// `git version`'s and the object format's runs: a moment's work each.
const CGI_PROBE: Duration = Duration::from_secs(10);

/// http-backend's arguments after `gitrun::OVERRIDES`: `GIT_CGI_OVERRIDES`
/// on its command line, which beats the agent's repository config
/// (receive-pack and the dumb files off, upload-pack on).
fn cgi_args() -> Vec<&'static str> {
    let mut args: Vec<&'static str> = crate::wire::workspace::GIT_CGI_OVERRIDES.iter().flat_map(|o| ["-c", *o]).collect();
    args.push("http-backend");
    args
}

/// §3.3's pairs, the only requests the code port's git routes make: `GET`
/// of `/info/refs` with the query exactly `GIT_UPLOAD_PACK_QUERY` and no
/// body; `POST` of `/git-upload-pack` of exactly
/// `GIT_UPLOAD_PACK_REQUEST_TYPE` with its length (at most
/// `GIT_REQUEST_MAX`) and no query; the client's address an IP address.
/// Anything else is 400 `bad_request`, before any git run. The POST's length.
fn cgi_check(a: &GitCgiArgs) -> Step<Option<u64>> {
    use crate::wire::workspace::{GIT_PATH_INFO_REFS, GIT_PATH_INFO_UPLOAD_PACK, GIT_REQUEST_MAX, GIT_UPLOAD_PACK_QUERY, GIT_UPLOAD_PACK_REQUEST_TYPE};
    if a.remote_addr.parse::<std::net::IpAddr>().is_err() {
        return refuse(refusal::BAD_REQUEST, "the client's address is no IP address");
    }
    let body = (a.content_type.as_deref(), a.content_length, a.content_encoding.as_deref());
    match (a.method.as_str(), a.path_info.as_str(), a.query.as_deref()) {
        ("GET", GIT_PATH_INFO_REFS, Some(GIT_UPLOAD_PACK_QUERY)) if body == (None, None, None) => Ok(None),
        ("POST", GIT_PATH_INFO_UPLOAD_PACK, None) if body.0 == Some(GIT_UPLOAD_PACK_REQUEST_TYPE) => match body.1 {
            Some(len) if len <= GIT_REQUEST_MAX => Ok(Some(len)),
            Some(len) => refuse(refusal::BAD_REQUEST, &format!("the request body is {len} bytes (at most {GIT_REQUEST_MAX})")),
            None => refuse(refusal::BAD_REQUEST, "an upload-pack request names its body's length"),
        },
        _ => refuse(refusal::BAD_REQUEST, "not a request of the code port's git routes (GET /info/refs?service=git-upload-pack, or POST /git-upload-pack of an upload-pack request with its length)"),
    }
}

/// The request's CGI environment beside `GitRun::vm`'s own (S9 §3.3): the
/// `GIT_CGI_ENV` names this request sets, and no other: `PATH_INFO` the
/// route's (never the URL's), `QUERY_STRING` the literal query of the `GET`
/// and empty for the `POST`; never a bearer, a cookie, an `x-aws-*` header,
/// a remote user or a config carrier. `project_root` is the walked
/// `<path>/.git`. Called on a request [`cgi_check`] passed.
pub(crate) fn cgi_env(a: &GitCgiArgs, project_root: &Path) -> Vec<(&'static str, std::ffi::OsString)> {
    use crate::wire::workspace::{GIT_UPLOAD_PACK_QUERY, GIT_UPLOAD_PACK_REQUEST_TYPE};
    let post = a.method == "POST";
    let mut env: Vec<(&'static str, std::ffi::OsString)> = vec![
        ("GIT_PROJECT_ROOT", project_root.into()),
        ("GIT_HTTP_EXPORT_ALL", "1".into()),
        ("PATH_INFO", a.path_info.as_str().into()),
        ("REQUEST_METHOD", a.method.as_str().into()),
        ("QUERY_STRING", if post { "".into() } else { GIT_UPLOAD_PACK_QUERY.into() }),
    ];
    if post {
        env.push(("CONTENT_TYPE", GIT_UPLOAD_PACK_REQUEST_TYPE.into()));
        env.push(("CONTENT_LENGTH", a.content_length.unwrap_or(0).to_string().into()));
    }
    if let Some(e) = &a.content_encoding {
        env.push(("HTTP_CONTENT_ENCODING", e.as_str().into()));
    }
    if let Some(p) = &a.git_protocol {
        env.push(("HTTP_GIT_PROTOCOL", p.as_str().into()));
    }
    env.push(("REMOTE_ADDR", a.remote_addr.as_str().into()));
    env
}

impl Ctx {
    /// `git-cgi` (S9 §3.3): the request checked ([`cgi_check`]), the seeded
    /// workspace walked (`seeded_repo`), a `POST`'s body read (exactly its
    /// length), git's version and the repository's object format read, and
    /// `git http-backend` started as the agent with [`cgi_env`] only; then
    /// the head (`GitCgiReply`), the body piped into http-backend and its
    /// output (the CGI's header block, then its body) copied out to its end.
    /// A refusal before the head is its head; http-backend failing after it
    /// is the helper's own failure (exit 1), which ends the root shim's
    /// stream with an error. No inbox, no lock: the CGI only reads.
    fn git_cgi(&self, a: &GitCgiArgs, input: &mut dyn BufRead, out: &mut dyn Write) -> Result<()> {
        let (child, body, reply) = match self.cgi_start(a, input) {
            Ok(started) => started,
            Err(stop) => return refused::<GitCgiReply>(out, stop),
        };
        emit(out, &HelperHead::ok(reply, None))?;
        cgi_pipe(child, body, out)
    }

    /// Everything before `git-cgi`'s head, http-backend started last.
    fn cgi_start(&self, a: &GitCgiArgs, input: &mut dyn BufRead) -> Step<(crate::gitrun::GitChild, Vec<u8>, GitCgiReply)> {
        let len = cgi_check(a)?;
        let repo = self.seeded_repo(&a.path, CGI_PROBE)?;
        let mut body = Vec::new();
        if let Some(len) = len {
            input.take(len).read_to_end(&mut body)?;
            if body.len() as u64 != len {
                return refuse(refusal::BAD_REQUEST, &format!("the request body ended after {} of {len} bytes", body.len()));
            }
        }
        let reply = self.cgi_reply(&repo)?;
        let step = if len.is_some() { budget::GIT_UPLOAD_PACK } else { budget::GIT_ADVERTISE };
        let env = cgi_env(a, &repo.dir.join(".git"));
        let child = self.cgi_git(&repo.dir, step, &env).spawn_piped(cgi_args()).map_err(git_stop("http-backend"))?;
        Ok((child, body, reply))
    }

    /// `git-cgi`'s head reply: git's version (the first word after `git
    /// version `) and the repository's object format.
    fn cgi_reply(&self, repo: &Repo<'_>) -> Step<GitCgiReply> {
        let said = text(&repo.git().output(["version"]).map_err(git_stop("version"))?);
        let version = said.strip_prefix("git version ").and_then(|v| v.split_whitespace().next()).filter(|v| v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)));
        let Some(version) = version else { return refuse(refusal::GIT_FAILED, "git version printed no version") };
        let format = text(&repo.git().output(["rev-parse", "--show-object-format"]).map_err(git_stop("rev-parse"))?);
        let object_format = match format.as_str() {
            "sha1" => ObjectFormat::Sha1,
            "sha256" => ObjectFormat::Sha256,
            _ => return refuse(refusal::GIT_FAILED, "the repository's object format is none this build knows"),
        };
        Ok(GitCgiReply { object_format, git_version: version.to_string() })
    }

    /// http-backend's run in `dir`: `GitRun::vm`'s environment and `env`
    /// only (not `vm_git`'s optional-locks name: the CGI's environment is
    /// exactly §3.3's), the shim's `--git`; it streams for what is left of
    /// the run's budget but the margin of its exit, having nothing to roll back.
    fn cgi_git(&self, dir: &Path, step: Duration, env: &[(&'static str, std::ffi::OsString)]) -> GitRun {
        let git = GitRun::vm(dir, &self.home).with_program(&self.git).timeout(self.cut(step, UNDO_MARGIN));
        env.iter().fold(git, |git, (name, value)| git.env(name, value))
    }
}

/// `body` into http-backend (a thread of its own; then its stdin closed),
/// its whole output to `out` ([`cgi_copy`]); `Err` (the helper's exit 1)
/// when the copy or http-backend failed, or when http-backend exited 0
/// with its header block and no body: its own die exits 0 once the head is
/// out (a gzip request cut short or corrupt), and every answer the routes
/// serve has a body (an advertisement, an ls-refs or a fetch result).
fn cgi_pipe(mut child: crate::gitrun::GitChild, body: Vec<u8>, out: &mut dyn Write) -> Result<()> {
    let stdin = child.take_stdin();
    let feeder = std::thread::Builder::new().name("http-backend stdin".into()).spawn(move || {
        if let Some(mut w) = stdin {
            // A run that stops reading closes the pipe: its exit says why.
            let _ = w.write_all(&body);
        }
    })?;
    let copied = match child.take_stdout() {
        Some(mut stdout) => cgi_copy(&mut stdout, out),
        None => Err(io::Error::other("http-backend has no stdout")),
    };
    let _ = feeder.join();
    let done = child.finish();
    let answered = copied?;
    done?;
    if !answered {
        return Err(CliError::Msg("http-backend wrote its head and no body: a request it could not read (its own die exits 0)".into()));
    }
    Ok(())
}

/// Where [`cgi_copy`] is in the CGI's output. Its header block ends at the
/// first blank line, LF or CRLF, as the root shim's `parse_cgi_head` reads it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CgiAt {
    /// At a line's start in the block.
    LineStart,
    /// After a CR at a line's start.
    Cr,
    /// Inside a line of the block.
    Line,
    /// Right after the block's blank line.
    Blank,
    /// Past a byte of the body.
    Body,
}

impl CgiAt {
    /// Where the output is once `b` followed.
    fn after(self, b: u8) -> CgiAt {
        match (self, b) {
            (CgiAt::LineStart | CgiAt::Cr, b'\n') => CgiAt::Blank,
            (CgiAt::LineStart, b'\r') => CgiAt::Cr,
            (CgiAt::Line, b'\n') => CgiAt::LineStart,
            (CgiAt::Blank | CgiAt::Body, _) => CgiAt::Body,
            _ => CgiAt::Line,
        }
    }
}

/// `from` copied to `out` to its end, `out` flushed: whether a byte of a
/// body followed the CGI's header block.
fn cgi_copy(from: &mut dyn Read, out: &mut dyn Write) -> io::Result<bool> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = CgiAt::LineStart;
    loop {
        let k = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        out.write_all(&buf[..k])?;
        if at != CgiAt::Body {
            at = buf[..k].iter().fold(at, |at, b| at.after(*b));
        }
    }
    out.flush()?;
    Ok(at == CgiAt::Body)
}

/// `shim-io git-cgi` in this process with `input` for its stdin: what it
/// printed and how it ended (the code port's unit tests drive the helper's
/// side so, without its binary).
#[cfg(test)]
pub(crate) fn git_cgi_here(home: &Path, git: &Path, a: &GitCgiArgs, input: &[u8]) -> (Vec<u8>, Result<()>) {
    let ctx = Ctx { home: home.to_path_buf(), fs_root: None, git: git.to_path_buf(), started: Instant::now(), budget: None };
    let mut out = Vec::new();
    let done = ctx.git_cgi(a, &mut io::Cursor::new(input.to_vec()), &mut out);
    (out, done)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod git_cgi_tests {
    use super::*;
    use crate::wire::workspace::{parse_head, GIT_RECEIVE_PACK_QUERY, GIT_UPLOAD_PACK_QUERY, GIT_UPLOAD_PACK_REQUEST_TYPE};
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    /// The real git: the first in an absolute `PATH` entry, else `/usr/bin/git`.
    fn real_git() -> PathBuf {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .filter(|d| d.is_absolute())
            .map(|d| d.join("git"))
            .chain(std::iter::once(PathBuf::from("/usr/bin/git")))
            .find(|g| std::fs::metadata(g).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
            .expect("a git")
    }

    /// `git <args>` in `dir` with no user or system config, one author at one date: stdout.
    fn git(dir: &Path, args: &[&str]) -> String {
        let out = {
            let _fork = crate::test_locks::forking();
            Command::new(real_git())
                .args(args)
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
                .env("GIT_COMMITTER_DATE", "2026-10-12T08:00:00Z")
                .output()
                .unwrap()
        };
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        text(&out.stdout)
    }

    /// The agent's home `<tmp>/home` and its workspace `<home>/ws`, a
    /// repository with one commit on `main` (as a seed leaves one).
    struct Home {
        _tmp: tempfile::TempDir,
        ctx: Ctx,
        ws: PathBuf,
    }

    fn home() -> Home {
        let tmp = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(tmp.path()).unwrap().join("home");
        let ws = home.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        git(&ws, &["init", "-q", "-b", "main"]);
        std::fs::write(ws.join("a.txt"), "one\n").unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "c1"]);
        let ctx = Ctx { home, fs_root: None, git: real_git(), started: Instant::now(), budget: None };
        Home { _tmp: tmp, ctx, ws }
    }

    /// A `GET` of the advertisement for the workspace at `ws` (protocol v2).
    fn get(ws: &Path) -> GitCgiArgs {
        GitCgiArgs {
            path: ws.to_str().unwrap().into(),
            method: "GET".into(),
            path_info: "/info/refs".into(),
            query: Some(GIT_UPLOAD_PACK_QUERY.into()),
            content_type: None,
            content_length: None,
            content_encoding: None,
            git_protocol: Some("version=2".into()),
            remote_addr: "10.0.0.1".into(),
        }
    }

    /// A `POST` of `body` (an upload-pack request, protocol v2).
    fn post(ws: &Path, body: &[u8]) -> GitCgiArgs {
        GitCgiArgs { method: "POST".into(), path_info: "/git-upload-pack".into(), query: None, content_type: Some(GIT_UPLOAD_PACK_REQUEST_TYPE.into()), content_length: Some(body.len() as u64), ..get(ws) }
    }

    /// `git-cgi` through the dispatcher: its head, what followed it, and how it ended.
    fn run(ctx: &Ctx, a: &GitCgiArgs, body: &[u8]) -> (HelperHead<GitCgiReply>, Vec<u8>, Result<()>) {
        let mut out = Vec::new();
        let done = dispatch(ctx, &ShimIoOp::GitCgi(a.clone()), &mut Cursor::new(body.to_vec()), &mut out);
        let nl = out.iter().position(|b| *b == b'\n').unwrap_or_else(|| panic!("no head: {}", String::from_utf8_lossy(&out)));
        (parse_head(&out[..nl]).unwrap(), out[nl + 1..].to_vec(), done)
    }

    /// What http-backend prints for a request of its own CGI environment in
    /// the workspace (stdin closed), through the helper's own run with `args`.
    fn backend(h: &Home, args: &[&str], method: &str, path_info: &str, query: &str) -> String {
        let env: Vec<(&'static str, std::ffi::OsString)> = vec![
            ("GIT_PROJECT_ROOT", h.ws.join(".git").into()),
            ("GIT_HTTP_EXPORT_ALL", "1".into()),
            ("PATH_INFO", path_info.into()),
            ("REQUEST_METHOD", method.into()),
            ("QUERY_STRING", query.into()),
            ("REMOTE_ADDR", "127.0.0.1".into()),
        ];
        let mut child = h.ctx.cgi_git(&h.ws, Duration::from_secs(30), &env).spawn_piped(args).unwrap();
        drop(child.take_stdin());
        let mut out = Vec::new();
        child.take_stdout().unwrap().read_to_end(&mut out).unwrap();
        child.finish().unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The command line's overrides beat whatever the agent writes in its
    /// repository's config: with `http.receivepack` and `http.getanyfile`
    /// on there (which, plain, would serve a push's advertisement), the
    /// helper's http-backend answers 403 to receive-pack in either form and
    /// to the dumb files, and keeps upload-pack on although the config turns
    /// it off; the op itself never asks for receive-pack (its check refuses
    /// the query before any git run).
    #[test]
    fn git_cgi_receivepack_stays_off_whatever_the_repo_config_says() {
        let h = home();
        for (key, value) in [("http.receivepack", "true"), ("http.getanyfile", "true"), ("http.uploadpack", "false")] {
            git(&h.ws, &["config", key, value]);
        }
        let plain = backend(&h, &["http-backend"], "GET", "/info/refs", GIT_RECEIVE_PACK_QUERY);
        assert!(plain.contains("Content-Type: application/x-git-receive-pack-advertisement") && !plain.contains("Status:"), "the agent's config alone opens receive-pack: {plain}");
        let args = cgi_args();
        assert_eq!(args, ["-c", "http.receivepack=false", "-c", "http.getanyfile=false", "-c", "http.uploadpack=true", "http-backend"]);
        for (method, path_info, query) in [("GET", "/info/refs", GIT_RECEIVE_PACK_QUERY), ("POST", "/git-receive-pack", ""), ("GET", "/HEAD", ""), ("GET", "/objects/info/packs", "")] {
            let out = backend(&h, &args, method, path_info, query);
            let head = out.split("\r\n\r\n").next().unwrap_or_default();
            assert!(head.split("\r\n").any(|l| l == "Status: 403 Forbidden") && !out.contains("receive-pack-advertisement"), "{method} {path_info}: {out}");
        }
        let up = backend(&h, &args, "GET", "/info/refs", GIT_UPLOAD_PACK_QUERY);
        assert!(up.contains("Content-Type: application/x-git-upload-pack-advertisement") && !up.contains("Status:"), "{up}");
        let (head, cgi, done) = run(&h.ctx, &get(&h.ws), b"");
        done.unwrap();
        let cgi = String::from_utf8_lossy(&cgi);
        assert!(head.ok && cgi.contains("application/x-git-upload-pack-advertisement") && cgi.contains("version 2") && !cgi.contains("Status:"), "{head:?} {cgi}");
        let receive = GitCgiArgs { query: Some(GIT_RECEIVE_PACK_QUERY.into()), ..get(&h.ws) };
        let (head, rest, done) = run(&h.ctx, &receive, b"");
        done.unwrap();
        assert!(head.code.as_deref() == Some(refusal::BAD_REQUEST) && rest.is_empty(), "{head:?}");
    }

    /// `git-cgi` never touches the inbox: what a seed or a code-out staged
    /// there stays (the dispatcher clears it for the four ops that hold the
    /// workspace only), and a run never makes it either.
    #[test]
    fn git_cgi_keeps_the_inbox() {
        let h = home();
        let inbox = h.ctx.home.join(INBOX);
        std::fs::create_dir_all(&inbox).unwrap();
        for name in ["seed-1a2b3c", "codeout-4d5e6f", "index-7a8b9c.lock"] {
            std::fs::write(inbox.join(name), "staged by a run that holds the workspace").unwrap();
        }
        let ls_refs = b"0014command=ls-refs\n00010000";
        for (a, body) in [(get(&h.ws), &b""[..]), (post(&h.ws, ls_refs), &ls_refs[..])] {
            let (head, cgi, done) = run(&h.ctx, &a, body);
            done.unwrap();
            assert!(head.ok && !cgi.is_empty(), "{head:?}");
            let mut left: Vec<String> = std::fs::read_dir(&inbox).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            left.sort();
            assert_eq!(left, ["codeout-4d5e6f", "index-7a8b9c.lock", "seed-1a2b3c"], "{} kept the inbox", a.method);
        }
        std::fs::remove_dir_all(h.ctx.home.join(".cache")).unwrap();
        let (head, _, done) = run(&h.ctx, &get(&h.ws), b"");
        done.unwrap();
        assert!(head.ok && !h.ctx.home.join(".cache").exists(), "no inbox made");
    }

    /// The op's answers: its head (the object format, git's version), then
    /// the CGI's output to its end, a v2 or a v0 advertisement as asked and
    /// an upload-pack result; http-backend failing after the head is the
    /// helper's failure, and so is its exit 0 after a head and no body (its
    /// own die, on a gzip request cut short). Its refusals come before any
    /// git run or before the head: a path that holds no repository (or
    /// nothing) 409 `not_seeded`, a symlinked one 409 `symlink_component`, a
    /// request outside §3.3's pairs, a body shorter than its length or a
    /// client address that is no address 400 `bad_request`.
    #[test]
    fn git_cgi_answers_its_head_then_the_cgi_output() {
        let h = home();
        let (head, cgi, done) = run(&h.ctx, &get(&h.ws), b"");
        done.unwrap();
        let reply = head.reply.clone().expect("a reply");
        assert!(reply.object_format == ObjectFormat::Sha1 && reply.git_version.chars().next().is_some_and(|c| c.is_ascii_digit()), "{reply:?}");
        let end = cgi.windows(4).position(|w| w == b"\r\n\r\n").expect("the CGI's header block") + 4;
        assert!(cgi[end..].starts_with(b"000eversion 2\n"), "a v2 advertisement: {}", String::from_utf8_lossy(&cgi));
        let (_, cgi, done) = run(&h.ctx, &GitCgiArgs { git_protocol: None, ..get(&h.ws) }, b"");
        done.unwrap();
        let end = cgi.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(cgi[end..].starts_with(b"001e# service=git-upload-pack\n0000"), "v0: {}", String::from_utf8_lossy(&cgi));
        let head_id = git(&h.ws, &["rev-parse", "HEAD"]);
        let ls_refs = b"0014command=ls-refs\n00010000";
        let (_, cgi, done) = run(&h.ctx, &post(&h.ws, ls_refs), ls_refs);
        done.unwrap();
        let cgi = String::from_utf8_lossy(&cgi);
        assert!(cgi.contains("Content-Type: application/x-git-upload-pack-result") && cgi.contains(&format!("{head_id} refs/heads/main")), "{cgi}");
        let (head, cgi, done) = run(&h.ctx, &post(&h.ws, b"zzzz"), b"zzzz");
        assert!(head.ok && done.is_err(), "a request upload-pack cannot read: the head, then the helper's failure: {}", String::from_utf8_lossy(&cgi));
        // A gzip member cut inside its request: a final stored block that
        // announces 110 bytes and holds the request's first 10.
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 1];
        gz.extend(110u16.to_le_bytes().into_iter().chain((!110u16).to_le_bytes()));
        gz.extend_from_slice(&ls_refs[..10]);
        let (head, cgi, done) = run(&h.ctx, &GitCgiArgs { content_encoding: Some("gzip".into()), ..post(&h.ws, &gz) }, &gz);
        assert!(head.ok && done.is_err(), "a gzip request cut short: the head, then the helper's failure: {}", String::from_utf8_lossy(&cgi));
        std::fs::create_dir_all(h.ctx.home.join("empty")).unwrap();
        std::os::unix::fs::symlink(&h.ws, h.ctx.home.join("linked")).unwrap();
        let at = |name: &str| GitCgiArgs { path: h.ctx.home.join(name).to_str().unwrap().into(), ..get(&h.ws) };
        let cases = [
            (at("empty"), &b""[..], refusal::NOT_SEEDED),
            (at("nothing"), b"", refusal::NOT_SEEDED),
            (at("linked"), b"", refusal::SYMLINK_COMPONENT),
            (GitCgiArgs { content_type: Some(GIT_UPLOAD_PACK_REQUEST_TYPE.into()), ..get(&h.ws) }, b"", refusal::BAD_REQUEST),
            (GitCgiArgs { query: None, ..get(&h.ws) }, b"", refusal::BAD_REQUEST),
            (GitCgiArgs { path_info: "/git-upload-pack".into(), ..get(&h.ws) }, b"", refusal::BAD_REQUEST),
            (GitCgiArgs { method: "POST".into(), ..get(&h.ws) }, b"", refusal::BAD_REQUEST),
            (GitCgiArgs { query: Some(GIT_UPLOAD_PACK_QUERY.into()), ..post(&h.ws, ls_refs) }, &ls_refs[..], refusal::BAD_REQUEST),
            (GitCgiArgs { content_length: None, ..post(&h.ws, ls_refs) }, &ls_refs[..], refusal::BAD_REQUEST),
            (GitCgiArgs { content_length: Some(crate::wire::workspace::GIT_REQUEST_MAX + 1), ..post(&h.ws, ls_refs) }, &ls_refs[..], refusal::BAD_REQUEST),
            (GitCgiArgs { content_type: Some("application/x-git-receive-pack-request".into()), ..post(&h.ws, ls_refs) }, &ls_refs[..], refusal::BAD_REQUEST),
            (post(&h.ws, ls_refs), &ls_refs[..10], refusal::BAD_REQUEST),
            (GitCgiArgs { remote_addr: "10.0.0.1; x".into(), ..get(&h.ws) }, b"", refusal::BAD_REQUEST),
        ];
        for (a, body, code) in cases {
            let (head, rest, done) = run(&h.ctx, &a, body);
            done.unwrap();
            assert!(!head.ok && head.code.as_deref() == Some(code) && rest.is_empty(), "{a:?}: {head:?}");
        }
    }

    /// The copy passes every byte on and sees a body exactly when a byte
    /// follows the header block's first blank line (LF or CRLF, as the root
    /// shim reads the block), the output whole or a byte per read.
    #[test]
    fn the_cgi_copy_sees_a_body_only_past_the_blank_line() {
        /// A reader that gives one byte per read.
        struct Trickle<'a>(&'a [u8]);
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let (Some((first, rest)), Some(slot)) = (self.0.split_first(), buf.first_mut()) else { return Ok(0) };
                *slot = *first;
                self.0 = rest;
                Ok(1)
            }
        }
        let cases: [(&[u8], bool); 8] = [
            (b"Content-Type: t\r\n\r\n0000", true),
            (b"Content-Type: t\n\n0000", true),
            (b"Content-Type: t\n\r\n0000", true),
            (b"\r\n0000", true),
            (b"Content-Type: t\r\n\r\n", false),
            (b"Content-Type: t\r\r\n0000", false),
            (b"Content-Type: t\r\n", false),
            (b"", false),
        ];
        for (output, body) in cases {
            for trickle in [false, true] {
                let mut out = Vec::new();
                let seen = if trickle { cgi_copy(&mut Trickle(output), &mut out) } else { cgi_copy(&mut Cursor::new(output), &mut out) };
                assert_eq!((seen.unwrap(), out.as_slice()), (body, output), "{:?}, a byte per read: {trickle}", String::from_utf8_lossy(output));
            }
        }
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

    /// Remove the temp files of writes ended before their own end (the
    /// shim's TERM at a pull's budget or at a stop: the helper has no
    /// handler, so no drop of [`TempIn`] ran): the directory's regular files
    /// named as [`TempIn`] names them, through its fd. A pull's
    /// `transcript-write` calls it under no lock another writer shares: a
    /// temp file whose writer still lives holds its flock
    /// ([`TempIn::create`]) and is left alone, whoever swept.
    fn sweep_temps(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir_path) else { return };
        for name in entries.flatten().map(|e| e.file_name()).filter(|n| is_transcript_temp(n.as_bytes())) {
            let Ok(c) = cstr(&name) else { continue };
            if kind_at(&self.dir, &c).is_ok_and(|k| k == libc::S_IFREG) && !temp_in_use(&self.dir, &c) {
                // SAFETY: a valid directory fd and a NUL-terminated name.
                unsafe { libc::unlinkat(self.dir.as_raw_fd(), c.as_ptr(), 0) };
            }
        }
    }
}

/// A transcript write's temp file name, as [`TempIn`] makes it: `.ai-env-`, 16 lowercase hex digits, `.tmp`.
fn is_transcript_temp(name: &[u8]) -> bool {
    name.len() == 28 && name.starts_with(b".ai-env-") && name.ends_with(b".tmp") && name[8..24].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether a live writer holds the temp file `name` under `dir`: its
/// [`TempIn`] keeps an exclusive flock on it until it ends (the lock goes
/// with the writer's last descriptor, however it ended).
fn temp_in_use(dir: &OwnedFd, name: &CStr) -> bool {
    // SAFETY: a valid directory fd, a NUL-terminated name, plain flags.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }
    // SAFETY: just opened, owned by nobody else.
    let probe = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: a valid fd; the lock, when taken, goes with `probe`.
    unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) != 0 }
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
        let absent = TranscriptStat { present: false, size: 0, sha256: None, mtime: None, ..TranscriptStat::default() };
        let Some(at) = self.transcript_at(projects, rel, false)? else { return Ok(absent) };
        match at.open(self, "the transcript")? {
            AtName::Absent => Ok(absent),
            AtName::File(f) => {
                let md = f.metadata()?;
                let (sha, size) = digest(f)?;
                Ok(TranscriptStat { present: true, size, sha256: Some(sha), mtime: mtime_of(&md), ..TranscriptStat::default() })
            }
        }
    }
}

/// A 0600 temp file beside a transcript (`.ai-env-<random>.tmp`), created
/// without following a symlink, flocked while it lives and removed unless
/// renamed over it; one a helper ended by a signal left goes at the next
/// write into its directory ([`InDir::sweep_temps`]).
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
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // A sweep in the same directory leaves it alone while this writer
        // lives (`temp_in_use`). One that met it in the instant before the
        // lock removes it: the rename then fails, the write with it, whole.
        // SAFETY: a valid fd we own.
        unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        Ok(TempIn { dir: at.dir.as_raw_fd(), name, fd, renamed: false })
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

// S9 (plans/s9-contracts.md §3.2, G5): the transcript store's ops. None
// uses the inbox or the workspace lock; the root shim pipes them to curl
// (`shim::s3xfer`) and checks what crosses.

/// The line a pull's root shim sends once every part checked
/// (`shim::s3xfer`): only then does `transcript-write` rename into place.
pub const COMMIT: &str = "commit";

/// The `len` bytes of `f` from `start` to `sink`, a chunk at a time (pread:
/// the file's offset never moves); a file that ends before them is an error.
fn read_range(f: &std::fs::File, start: u64, len: u64, sink: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
    use std::os::unix::fs::FileExt as _;
    let mut buf = vec![0u8; 64 * 1024];
    let mut done = 0u64;
    while done < len {
        let want = usize::try_from(len - done).map_or(buf.len(), |left| left.min(buf.len()));
        let k = match f.read_at(&mut buf[..want], start + done) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("the transcript ended at byte {} of {}", start + done, start + len))),
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        sink(&buf[..k])?;
        done += k as u64;
    }
    Ok(())
}

/// sha256 (lowercase hex) of the `len` bytes of `f` from `start`.
fn range_sha256(f: &std::fs::File, start: u64, len: u64) -> io::Result<String> {
    let mut h = Sha256::new();
    read_range(f, start, len, &mut |chunk| {
        h.update(chunk);
        Ok(())
    })?;
    Ok(hex::encode(h.finalize()))
}

/// A path segment of a session's subtree as a rel takes it: `[A-Za-z0-9._-]`,
/// at most `SEGMENT_MAX` bytes, no leading `.`.
fn subtree_segment(name: &str) -> bool {
    !name.is_empty() && name.len() <= crate::wire::workspace::SEGMENT_MAX && !name.starts_with('.') && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A stat query's refusal text (its own rel's message is already whole).
fn stat_message(e: String) -> String {
    if e.starts_with("the ") {
        e
    } else {
        format!("the stat query {e}")
    }
}

impl Ctx {
    /// `transcript-stat` with `--from`, `--fp` or `--subtree` (S9 §1.7;
    /// through [`answer_payload`] with `--subtree`, else [`answer`]): the
    /// file's size, mtime and inode; with `from`, the sha256 of
    /// `[from, size)` (when `from` is at most `size`) and of the `FP_SPAN`
    /// bytes before `size`, and never the whole file's (without `from`,
    /// S8's whole-file sha256); with `fp`, whether the `FP_SPAN` bytes
    /// before `from` hash to it (false past `size`, or for an absent file);
    /// with `subtree`, the session's files ([`Ctx::subtree`]). Without any
    /// of them the arm runs S8's [`Ctx::transcript_stat`].
    fn transcript_stat_from(&self, projects: &Path, rel: &str, from: Option<u64>, fp: Option<&str>, subtree: bool) -> Step<TranscriptStat> {
        use crate::wire::s3::FP_SPAN;
        use std::os::unix::fs::MetadataExt as _;
        let q = crate::wire::workspace::StatQuery { rel: rel.to_string(), from, fp: fp.map(str::to_string), subtree };
        if let Err(e) = q.check() {
            return refuse(refusal::BAD_REQUEST, &stat_message(e));
        }
        let mut stat = TranscriptStat::default();
        let file = match self.transcript_at(projects, rel, false)? {
            Some(at) => match at.open(self, "the transcript")? {
                AtName::File(f) => Some(f),
                AtName::Absent => None,
            },
            None => None,
        };
        match &file {
            Some(f) => {
                let md = f.metadata()?;
                let size = md.len();
                (stat.present, stat.size, stat.mtime, stat.ino) = (true, size, mtime_of(&md), Some(md.ino()));
                match from {
                    None => stat.sha256 = Some(range_sha256(f, 0, size)?),
                    Some(from) => {
                        if from <= size {
                            stat.delta_sha256 = Some(range_sha256(f, from, size - from)?);
                        }
                        let tail = size.min(FP_SPAN);
                        stat.end_fp = Some(range_sha256(f, size - tail, tail)?);
                        if let Some(fp) = fp {
                            let span = from.min(FP_SPAN);
                            stat.fp_ok = Some(from <= size && range_sha256(f, from - span, span)? == fp);
                        }
                    }
                }
            }
            None => stat.fp_ok = fp.map(|_| false),
        }
        if subtree {
            stat.subtree = self.subtree(projects, rel)?;
        }
        Ok(stat)
    }

    /// The subtree of `rel`'s session (`<slug>/<uuid>/` beside
    /// `<slug>/<uuid>.jsonl`): every regular file whose rel
    /// `transcript_rel_check` takes, by rel, with its size and sha256,
    /// walked as the agent one component at a time (a symlink at any level,
    /// `<uuid>` itself included, is skipped, never followed; a `<uuid>`
    /// that is no directory, or one the agent cannot enter, is no subtree);
    /// past `SUBTREE_FILES_MAX` files or `SUBTREE_BYTES_MAX` bytes, 413
    /// `too_large`.
    fn subtree(&self, projects: &Path, rel: &str) -> Step<Vec<crate::wire::workspace::SubtreeFile>> {
        let base = rel.strip_suffix(".jsonl").unwrap_or(rel);
        // The stat walked to `<slug>` first and refused a symlink, a non-directory or a directory the agent
        // cannot enter on the way: one this walk meets is at `<uuid>` (or was put there since), skipped as at
        // any level below (the lead, S9 integration: `not_creatable` is no code GET /transcript lists).
        let top = match self.walk(&projects.join(base), false, "the session's subtree") {
            Ok(top) => top,
            Err(Stop::Refused(r)) if r.code == refusal::SYMLINK_COMPONENT || r.code == refusal::PATH_OCCUPIED || r.code == refusal::NOT_CREATABLE => None,
            Err(stop) => return Err(stop),
        };
        let mut files = Vec::new();
        if let Some(top) = top {
            let mut bytes = 0u64;
            Self::subtree_dir(&top.fd, &top.path, base, 0, &mut files, &mut bytes)?;
        }
        files.sort_by(|a, b| a.rel.cmp(&b.rel));
        Ok(files)
    }

    /// One directory of a subtree ([`Ctx::subtree`]), `depth` below the session.
    fn subtree_dir(dir: &OwnedFd, path: &Path, rel: &str, depth: usize, files: &mut Vec<crate::wire::workspace::SubtreeFile>, bytes: &mut u64) -> Step<()> {
        use crate::wire::workspace::{SubtreeFile, SUBTREE_BYTES_MAX, SUBTREE_FILES_MAX, TRANSCRIPT_DIRS_MAX};
        let Ok(entries) = std::fs::read_dir(path) else { return Ok(()) };
        let mut names: Vec<std::ffi::OsString> = entries.flatten().map(|e| e.file_name()).collect();
        names.sort();
        for name in names {
            let Some(text) = name.to_str().filter(|t| subtree_segment(t)) else { continue };
            let Ok(c) = cstr(&name) else { continue };
            let child = format!("{rel}/{text}");
            match kind_at(dir, &c) {
                Ok(libc::S_IFDIR) if depth < TRANSCRIPT_DIRS_MAX => {
                    let Ok(sub) = open_dir_at(dir, &c) else { continue };
                    Self::subtree_dir(&sub, &path.join(&name), &child, depth + 1, files, bytes)?;
                }
                Ok(libc::S_IFREG) if transcript_rel_check(&child).is_ok() => {
                    // SAFETY: a valid directory fd, a NUL-terminated name, plain flags.
                    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
                    if fd < 0 {
                        continue;
                    }
                    // SAFETY: just opened, owned by nobody else.
                    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
                    let md = file.metadata()?;
                    if !md.is_file() {
                        continue;
                    }
                    if files.len() >= SUBTREE_FILES_MAX {
                        return refuse(refusal::TOO_LARGE, &format!("the session's subtree holds more than {SUBTREE_FILES_MAX} files"));
                    }
                    *bytes += md.len();
                    if *bytes > SUBTREE_BYTES_MAX {
                        return Err(Stop::refused(WsRefusal::new(refusal::TOO_LARGE, &format!("the session's subtree holds more than {SUBTREE_BYTES_MAX} bytes")).with_size(*bytes)));
                    }
                    let sha256 = range_sha256(&file, 0, md.len())?;
                    files.push(SubtreeFile { rel: child, size: md.len(), sha256 });
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// `transcript-read` (a push's bytes): its own head
    /// (`TranscriptReadReply`: the file's size and inode, `len` N), then
    /// exactly N bytes of the file from `from`. A file that is absent or
    /// shorter than `from + len` is 409 `changed` (with its size), one that
    /// is no regular file 409 `path_occupied`, a symlink 409
    /// `symlink_component`; a file cut short after the head is the helper's
    /// failure (exit 1: the root shim's payload ends early).
    fn transcript_read(&self, projects: &Path, rel: &str, from: u64, len: u64, out: &mut dyn Write) -> Result<()> {
        use crate::wire::workspace::TranscriptReadReply;
        use std::os::unix::fs::MetadataExt as _;
        let opened = (|| -> Step<(std::fs::File, TranscriptReadReply)> {
            let Some(end) = from.checked_add(len) else { return refuse(refusal::BAD_REQUEST, "--from and --len pass the largest offset") };
            let file = match self.transcript_at(projects, rel, false)? {
                Some(at) => match at.open(self, "the transcript")? {
                    AtName::File(f) => Some(f),
                    AtName::Absent => None,
                },
                None => None,
            };
            let Some(file) = file else { return Err(Stop::refused(WsRefusal::new(refusal::CHANGED, "the transcript is absent: nothing to read").with_size(0))) };
            let md = file.metadata()?;
            if end > md.len() {
                return Err(Stop::refused(WsRefusal::new(refusal::CHANGED, &format!("the transcript is {} bytes, shorter than {from} + {len}", md.len())).with_size(md.len())));
            }
            Ok((file, TranscriptReadReply { size: md.len(), ino: md.ino() }))
        })();
        let (file, reply) = match opened {
            Ok(o) => o,
            Err(stop) => return refused::<TranscriptReadReply>(out, stop),
        };
        emit(out, &HelperHead::ok(reply, Some(len)))?;
        read_range(&file, from, len, &mut |chunk| out.write_all(chunk))?;
        out.flush()?;
        Ok(())
    }

    /// `transcript-write` (a pull's bytes, §3.2, X10): the target checked
    /// first (a symlink 409 `symlink_component`, no regular file 409
    /// `path_occupied`; its directories made 0700); then exactly `len` bytes
    /// of `input` into a 0600 temp file beside it ([`TempIn`], flocked, the
    /// directory's leftovers swept first), then the line `commit`, then,
    /// once `sha256` (when given) is the bytes', fsync and the rename over
    /// it. Before the commit nothing is renamed: an input that ends early or
    /// without the line is 500 `transfer_failed`, other bytes than `sha256`
    /// 409 `changed`, each with the old copy's size; the temp file goes on
    /// every refusal.
    fn transcript_write(&self, projects: &Path, rel: &str, len: u64, sha256: Option<&str>, input: &mut dyn BufRead) -> Step<TranscriptWriteReply> {
        if sha256.is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
            return refuse(refusal::BAD_REQUEST, "--sha256 is not 64 lowercase hex digits");
        }
        if len > crate::wire::workspace::PULL_MAX {
            return refuse(refusal::BAD_REQUEST, &format!("--len is over {} bytes", crate::wire::workspace::PULL_MAX));
        }
        let at = self.transcript_at(projects, rel, true)?.ok_or_else(|| Stop::Failed(CliError::Msg("the transcript's directory was not made".into())))?;
        let old = match at.open(self, "the transcript")? {
            AtName::Absent => 0,
            AtName::File(f) => f.metadata()?.len(),
        };
        at.sweep_temps();
        let tmp = TempIn::create(&at)?;
        let mut file = std::fs::File::from(tmp.fd.try_clone()?);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0u64;
        let mut body = (&mut *input).take(len);
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
        let failed = |why: String| Err(Stop::refused(WsRefusal::new(refusal::TRANSFER_FAILED, &why).with_size(old)));
        if got != len {
            return failed(format!("the transcript's bytes ended after {got} of {len}: nothing renamed"));
        }
        let mut line = Vec::new();
        (&mut *input).take(COMMIT.len() as u64 + 1).read_until(b'\n', &mut line)?;
        if line.strip_suffix(b"\n") != Some(COMMIT.as_bytes()) {
            return failed(format!("no {COMMIT} line after the transcript's {len} bytes: nothing renamed"));
        }
        let sha = hex::encode(hasher.finalize());
        if sha256.is_some_and(|want| want != sha) {
            return Err(Stop::refused(WsRefusal::new(refusal::CHANGED, "the transcript's bytes are not the sha256 asked: nothing renamed").with_size(old)));
        }
        file.sync_all()?;
        let written = file.metadata()?.len();
        if written != len {
            return Err(Stop::Failed(CliError::Msg(format!("the transcript's temp file holds {written} of {len} bytes"))));
        }
        tmp.rename_over(&at)?;
        Ok(TranscriptWriteReply { size: len, sha256: sha })
    }

    /// `transcript-view` (through [`answer_payload`]): the last `n` messages
    /// of the transcript as `wire::view::build_view` makes them from at most
    /// `VIEW_TAIL_MAX` bytes of its end, the first line dropped when the
    /// read starts past the file's first byte (it is partial); an absent
    /// file answers `present: false`.
    fn transcript_view(&self, projects: &Path, rel: &str, n: u32) -> Step<TranscriptViewReply> {
        use crate::wire::view::{build_view, VIEW_TAIL_MAX, VIEW_V};
        let q = crate::wire::workspace::ViewQuery { rel: rel.to_string(), n };
        if let Err(e) = q.check() {
            return refuse(refusal::BAD_REQUEST, &if e.starts_with("the ") { e } else { format!("the view query {e}") });
        }
        let absent = TranscriptViewReply { v: VIEW_V, present: false, title: None, version: None, git_branch: None, entries: Vec::new() };
        let Some(at) = self.transcript_at(projects, rel, false)? else { return Ok(absent) };
        let AtName::File(file) = at.open(self, "the transcript")? else { return Ok(absent) };
        let size = file.metadata()?.len();
        let start = size.saturating_sub(VIEW_TAIL_MAX);
        let mut tail = Vec::with_capacity(usize::try_from(size - start).unwrap_or(0));
        read_range(&file, start, size - start, &mut |chunk| {
            tail.extend_from_slice(chunk);
            Ok(())
        })?;
        if start > 0 {
            let first = tail.iter().position(|b| *b == b'\n').map_or(tail.len(), |nl| nl + 1);
            tail.drain(..first);
        }
        build_view(&tail, n).map_err(|e| Stop::Failed(CliError::Msg(e)))
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod transcript_s3_tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const SLUG: &str = "-Users-mike-ws";
    const ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    /// The agent's home `<tmp>/vm/home` under the fs root `<tmp>/vm`, its
    /// projects directory and the session's transcript rel.
    struct Home {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        ctx: Ctx,
        projects: PathBuf,
        rel: String,
    }

    fn home() -> Home {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let home = root.join("vm/home");
        std::fs::create_dir_all(&home).unwrap();
        let ctx = Ctx { home: home.clone(), fs_root: Some(root.join("vm")), git: PathBuf::from(crate::shim::health::GIT_DEFAULT), started: Instant::now(), budget: None };
        Home { _tmp: tmp, root, ctx, projects: home.join(".claude/projects"), rel: format!("{SLUG}/{ID}.jsonl") }
    }

    impl Home {
        fn file(&self) -> PathBuf {
            self.projects.join(&self.rel)
        }
    }

    fn put(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn refused<T: std::fmt::Debug>(step: Step<T>) -> WsRefusal {
        match step {
            Err(Stop::Refused(r)) => *r,
            other => panic!("not a refusal: {other:?}"),
        }
    }

    /// `n` bytes no two 64 KiB windows of which hash alike.
    fn bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| u8::try_from((i * 7 + i / 251) % 251).unwrap()).collect()
    }

    /// One head line and what follows it.
    fn head_of(out: &[u8]) -> (serde_json::Value, &[u8]) {
        let nl = out.iter().position(|b| *b == b'\n').expect("a head line");
        (serde_json::from_slice(&out[..nl]).unwrap(), &out[nl + 1..])
    }

    /// The extended stat: no whole-file sha256 with `from`, the delta's,
    /// the end's fingerprint and the inode; `fp_ok` true for the bytes the
    /// Mac recorded, false for others, for an offset past the end and for an
    /// absent file; the S8 sha256 without `from`; its query's refusals; a
    /// symlinked transcript 409.
    #[test]
    fn the_extended_stat_hashes_the_delta_and_the_fingerprints() {
        use crate::wire::s3::FP_SPAN;
        let h = home();
        let span = usize::try_from(FP_SPAN).unwrap();
        let absent = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(0), Some(&sha(b"")), false).unwrap();
        assert_eq!((absent.present, absent.size, absent.fp_ok, absent.delta_sha256), (false, 0, Some(false), None));
        let body = bytes(100_000);
        put(&h.file(), &body);
        let from = 70_000usize;
        let fp = sha(&body[from - span..from]);
        let stat = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(from as u64), Some(&fp), false).unwrap();
        let ino = std::fs::metadata(h.file()).unwrap().ino();
        assert_eq!((stat.present, stat.size, stat.sha256.as_deref(), stat.ino), (true, 100_000, None, Some(ino)), "{stat:?}");
        assert_eq!(stat.delta_sha256, Some(sha(&body[from..])));
        assert_eq!(stat.end_fp, Some(sha(&body[body.len() - span..])));
        assert_eq!((stat.fp_ok, stat.mtime.is_some(), stat.subtree.len()), (Some(true), true, 0));
        assert_eq!(h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(from as u64), Some(&sha(b"other")), false).unwrap().fp_ok, Some(false));
        let past = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(100_001), Some(&fp), false).unwrap();
        assert_eq!((past.delta_sha256, past.fp_ok), (None, Some(false)), "from past the end: no delta, not ok");
        let at_end = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(100_000), None, false).unwrap();
        assert_eq!((at_end.delta_sha256, at_end.fp_ok), (Some(sha(b"")), None));
        let start = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(10), Some(&sha(&body[..10])), false).unwrap();
        assert_eq!(start.fp_ok, Some(true), "a fingerprint near the start covers what there is");
        let whole = h.ctx.transcript_stat_from(&h.projects, &h.rel, None, None, true).unwrap();
        assert_eq!((whole.sha256, whole.delta_sha256, whole.end_fp), (Some(sha(&body)), None, None), "S8's sha256 without from");
        put(&h.file(), b"short\n");
        assert_eq!(h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(0), None, false).unwrap().end_fp, Some(sha(b"short\n")), "a file under FP_SPAN: its whole bytes");
        let queries = [
            (None, Some(sha(b"")), false, h.rel.clone()),
            (Some(0), Some("AB".repeat(32)), false, h.rel.clone()),
            (Some(0), None, true, format!("{SLUG}/{ID}/subagents/a1.jsonl")),
            (Some(0), None, false, format!("../{ID}.jsonl")),
        ];
        for (from, fp, subtree, rel) in queries {
            let r = refused(h.ctx.transcript_stat_from(&h.projects, &rel, from, fp.as_deref(), subtree));
            assert_eq!(r.code, refusal::BAD_REQUEST, "{from:?} {fp:?} {subtree} {rel}: {r:?}");
        }
        std::fs::remove_file(h.file()).unwrap();
        std::os::unix::fs::symlink(h.root.join("elsewhere"), h.file()).unwrap();
        assert_eq!(refused(h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(0), None, false)).code, refusal::SYMLINK_COMPONENT);
    }

    /// The subtree: the session's regular files whose rel the store takes,
    /// sorted, each with its size and sha256; a file one level below the
    /// session, a hidden one, one of another kind, a symlinked file and a
    /// symlinked directory are not listed; past the file cap, 413. Through
    /// `dispatch` it answers in the payload form. A `<uuid>` that is itself
    /// a symlink (never followed) or no directory is no subtree: the stat
    /// still answers, its subtree empty.
    #[test]
    fn the_subtree_lists_regular_files_by_rel_and_skips_links() {
        let h = home();
        put(&h.file(), b"{}\n");
        let sub = h.projects.join(SLUG).join(ID);
        put(&sub.join("subagents/agent-a1.jsonl"), b"{\"a\":1}\n");
        put(&sub.join("subagents/agent-a1.meta.json"), b"{\"agentType\":\"x\"}");
        put(&sub.join("subagents/deeper/agent-b2.jsonl"), b"{\"b\":2}\n");
        put(&sub.join("one-level.jsonl"), b"not a rel the store takes");
        put(&sub.join("subagents/.hidden.jsonl"), b"hidden");
        put(&sub.join("subagents/notes.txt"), b"another kind");
        std::os::unix::fs::symlink(sub.join("subagents/agent-a1.jsonl"), sub.join("subagents/link.jsonl")).unwrap();
        let elsewhere = h.root.join("elsewhere");
        put(&elsewhere.join("leak.jsonl"), b"outside");
        std::os::unix::fs::symlink(&elsewhere, sub.join("linked")).unwrap();
        let stat = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(0), None, true).unwrap();
        let got: Vec<(String, u64, String)> = stat.subtree.iter().map(|f| (f.rel.clone(), f.size, f.sha256.clone())).collect();
        let entry = |rel: &str, body: &[u8]| (format!("{SLUG}/{ID}/{rel}"), body.len() as u64, sha(body));
        assert_eq!(got, [entry("subagents/agent-a1.jsonl", b"{\"a\":1}\n"), entry("subagents/agent-a1.meta.json", b"{\"agentType\":\"x\"}"), entry("subagents/deeper/agent-b2.jsonl", b"{\"b\":2}\n")]);
        let mut out = Vec::new();
        let op = ShimIoOp::TranscriptStat { projects: h.projects.clone(), rel: h.rel.clone(), from: Some(0), fp: None, subtree: true };
        dispatch(&h.ctx, &op, &mut Cursor::new(Vec::new()), &mut out).unwrap();
        let (head, payload) = head_of(&out);
        assert_eq!((head["ok"].as_bool(), head["len"].as_u64(), head["reply"]["sha256"].as_str()), (Some(true), Some(payload.len() as u64), Some(sha(payload).as_str())), "{head}");
        assert_eq!(serde_json::from_slice::<TranscriptStat>(payload).unwrap(), stat, "the payload is the stat");
        for i in 0..=crate::wire::workspace::SUBTREE_FILES_MAX {
            put(&sub.join(format!("many/f{i:04}.jsonl")), b"x");
        }
        assert_eq!(refused(h.ctx.transcript_stat_from(&h.projects, &h.rel, None, None, true)).code, refusal::TOO_LARGE);
        // `<uuid>` itself a symlink to a directory holding a session's files, then a file.
        std::fs::remove_dir_all(&sub).unwrap();
        let planted = h.root.join("planted");
        put(&planted.join("subagents/agent-a1.jsonl"), b"{\"a\":1}\n");
        std::os::unix::fs::symlink(&planted, &sub).unwrap();
        let linked = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(0), None, true).unwrap();
        assert_eq!((linked.present, linked.subtree.len()), (true, 0), "a linked subtree is skipped: {linked:?}");
        let mut out = Vec::new();
        dispatch(&h.ctx, &op, &mut Cursor::new(Vec::new()), &mut out).unwrap();
        let (head, payload) = head_of(&out);
        assert_eq!(head["ok"].as_bool(), Some(true), "{head}");
        assert_eq!(serde_json::from_slice::<TranscriptStat>(payload).unwrap(), linked, "through dispatch too");
        std::fs::remove_file(&sub).unwrap();
        put(&sub, b"not a directory");
        let occupied = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(0), None, true).unwrap();
        assert_eq!((occupied.present, occupied.subtree.len()), (true, 0), "a file at <uuid> is no subtree: {occupied:?}");
    }

    /// The lead (S9 integration, G5's open point): a `<uuid>` the agent made
    /// unenterable (mode 000) is no subtree, as one deeper down is skipped:
    /// the stat answers, its subtree empty, directly and through `dispatch`
    /// (never 409 `not_creatable`, a code `GET /transcript` does not list);
    /// an unenterable directory below it is skipped, its siblings listed.
    #[test]
    fn an_unenterable_subtree_is_no_subtree() {
        /// Gives the directories back their 0700 when dropped (before the tempdir goes), a failed assert included.
        struct Unlock(Vec<PathBuf>);
        impl Drop for Unlock {
            fn drop(&mut self) {
                for p in &self.0 {
                    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
                }
            }
        }
        let h = home();
        put(&h.file(), b"{}\n");
        let sub = h.projects.join(SLUG).join(ID);
        put(&sub.join("subagents/agent-a1.jsonl"), b"{\"a\":1}\n");
        put(&sub.join("locked/agent-b2.jsonl"), b"{\"b\":2}\n");
        let _unlock = Unlock(vec![sub.clone(), sub.join("locked")]);
        let mode = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        mode(&sub.join("locked"), 0o000);
        if std::fs::read_dir(sub.join("locked")).is_ok() {
            eprintln!("root enters a mode-000 directory: skipped");
            return;
        }
        let stat = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(0), None, true).unwrap();
        let rels: Vec<&str> = stat.subtree.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, [format!("{SLUG}/{ID}/subagents/agent-a1.jsonl")], "an unenterable directory below <uuid> is skipped");
        mode(&sub, 0o000);
        let locked = h.ctx.transcript_stat_from(&h.projects, &h.rel, Some(0), None, true).unwrap();
        assert_eq!((locked.present, locked.size, locked.subtree.len()), (true, 3, 0), "an unenterable <uuid> is no subtree: {locked:?}");
        let mut out = Vec::new();
        let op = ShimIoOp::TranscriptStat { projects: h.projects.clone(), rel: h.rel.clone(), from: Some(0), fp: None, subtree: true };
        dispatch(&h.ctx, &op, &mut Cursor::new(Vec::new()), &mut out).unwrap();
        let (head, payload) = head_of(&out);
        assert_eq!(head["ok"].as_bool(), Some(true), "{head}");
        assert_eq!(serde_json::from_slice::<TranscriptStat>(payload).unwrap(), locked, "through dispatch too");
    }

    /// `transcript-read`: its head (the size, the inode, `len`), then
    /// exactly those bytes; absent or too short 409 `changed` with the size;
    /// a symlink 409 `symlink_component`; no regular file 409 `path_occupied`;
    /// the inbox untouched.
    #[test]
    fn transcript_read_answers_its_head_then_exactly_the_range() {
        let h = home();
        let read = |from: u64, len: u64| {
            let mut out = Vec::new();
            let op = ShimIoOp::TranscriptRead { projects: h.projects.clone(), rel: h.rel.clone(), from, len };
            dispatch(&h.ctx, &op, &mut Cursor::new(Vec::new()), &mut out).unwrap();
            out
        };
        let out = read(0, 1);
        let (head, rest) = head_of(&out);
        assert_eq!((head["ok"].as_bool(), head["code"].as_str(), head["size"].as_u64(), rest.len()), (Some(false), Some("changed"), Some(0), 0), "{head}");
        let body = bytes(200_000);
        put(&h.file(), &body);
        let out = read(150_000, 40_000);
        let (head, rest) = head_of(&out);
        assert_eq!((head["reply"]["size"].as_u64(), head["reply"]["ino"].as_u64(), head["len"].as_u64()), (Some(200_000), Some(std::fs::metadata(h.file()).unwrap().ino()), Some(40_000)), "{head}");
        assert_eq!(rest, &body[150_000..190_000]);
        let out = read(199_000, 1001);
        let (head, rest) = head_of(&out);
        assert_eq!((head["code"].as_str(), head["size"].as_u64(), rest.len()), (Some("changed"), Some(200_000), 0), "shorter than from + len");
        std::fs::remove_file(h.file()).unwrap();
        std::fs::create_dir(h.file()).unwrap();
        assert_eq!(head_of(&read(0, 1)).0["code"].as_str(), Some("path_occupied"));
        std::fs::remove_dir(h.file()).unwrap();
        std::os::unix::fs::symlink(h.root.join("elsewhere"), h.file()).unwrap();
        assert_eq!(head_of(&read(0, 1)).0["code"].as_str(), Some("symlink_component"));
        assert!(!h.ctx.home.join(INBOX).exists(), "the S9 ops never make the inbox");
    }

    /// `transcript-write`: N bytes, then the line `commit`, then the rename
    /// (0600 in 0700 directories); without the line, cut short, or with
    /// other bytes than its sha256, nothing is renamed, the old copy and its
    /// size kept, no temp file left; a symlinked target is refused before
    /// a byte is read; the sweep removes an ended writer's temp file and
    /// leaves a live one's (it holds its flock).
    #[test]
    fn transcript_write_renames_only_after_the_commit_line() {
        let h = home();
        let write = |input: Vec<u8>, len: u64, sum: Option<String>| {
            let mut out = Vec::new();
            let op = ShimIoOp::TranscriptWrite { projects: h.projects.clone(), rel: h.rel.clone(), len, sha256: sum };
            let mut cursor = Cursor::new(input);
            dispatch(&h.ctx, &op, &mut cursor, &mut out).unwrap();
            (head_of(&out).0, cursor.position())
        };
        let temps = || -> Vec<String> {
            let Ok(d) = std::fs::read_dir(h.projects.join(SLUG)) else { return Vec::new() };
            d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".tmp")).collect()
        };
        let body = b"{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n".to_vec();
        let with_commit = |b: &[u8]| [b, &format!("{COMMIT}\n").into_bytes()].concat();
        let (head, _) = write(with_commit(&body), body.len() as u64, Some(sha(&body)));
        assert_eq!((head["ok"].as_bool(), head["reply"]["size"].as_u64(), head["reply"]["sha256"].as_str()), (Some(true), Some(body.len() as u64), Some(sha(&body).as_str())), "{head}");
        assert_eq!(std::fs::read(h.file()).unwrap(), body);
        assert_eq!(std::fs::metadata(h.file()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(h.projects.join(SLUG)).unwrap().permissions().mode() & 0o777, 0o700);
        let new = b"{\"type\":\"user\",\"n\":2}\n".to_vec();
        for (input, sum, code) in [
            (new.clone(), None, "transfer_failed"),
            (new[..5].to_vec(), None, "transfer_failed"),
            ([&new[..], b"comm"].concat(), None, "transfer_failed"),
            ([&new[..], b"rollback\n"].concat(), None, "transfer_failed"),
            (with_commit(&new), Some(sha(b"other bytes")), "changed"),
        ] {
            let (head, _) = write(input, new.len() as u64, sum);
            assert_eq!((head["code"].as_str(), head["size"].as_u64()), (Some(code), Some(body.len() as u64)), "{head}");
            assert_eq!(std::fs::read(h.file()).unwrap(), body, "nothing renamed: the old copy kept");
            assert!(temps().is_empty(), "no temp file left: {:?}", temps());
        }
        let (head, _) = write(with_commit(&new), new.len() as u64, None);
        assert_eq!(head["ok"].as_bool(), Some(true), "{head}");
        assert_eq!(std::fs::read(h.file()).unwrap(), new);
        // The sweep: an ended writer's temp file goes, a live one's (its flock held) stays.
        let dir = h.projects.join(SLUG);
        put(&dir.join(".ai-env-0123456789abcdef.tmp"), b"an ended write");
        put(&dir.join(".ai-env-fedcba9876543210.tmp"), b"a live write");
        let live = std::fs::File::open(dir.join(".ai-env-fedcba9876543210.tmp")).unwrap();
        // SAFETY: a valid fd; the lock goes with `live`.
        assert_eq!(unsafe { libc::flock(live.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        let (head, _) = write(with_commit(&body), body.len() as u64, None);
        assert_eq!(head["ok"].as_bool(), Some(true));
        assert_eq!(temps(), [".ai-env-fedcba9876543210.tmp"], "the live one stays");
        drop(live);
        // A symlinked target: refused before any byte is read.
        std::fs::remove_file(h.file()).unwrap();
        std::os::unix::fs::symlink(h.root.join("elsewhere"), h.file()).unwrap();
        let (head, read) = write(with_commit(&body), body.len() as u64, None);
        assert_eq!((head["code"].as_str(), read), (Some("symlink_component"), 0), "{head}");
        assert!(!h.root.join("elsewhere").exists(), "nothing written through the link");
    }

    /// `transcript-view` (the payload form): an absent file answers
    /// `present: false`; the example tail answers §6.1's example; a file
    /// longer than `VIEW_TAIL_MAX` loses the line its read starts in, even
    /// one whose rest would parse (here an entry naming as its parent the
    /// newest one's).
    #[test]
    fn transcript_view_builds_from_the_tail_and_drops_a_partial_first_line() {
        use crate::wire::view::VIEW_TAIL_MAX;
        let h = home();
        let view = |n: u32| -> TranscriptViewReply {
            let mut out = Vec::new();
            let op = ShimIoOp::TranscriptView { projects: h.projects.clone(), rel: h.rel.clone(), n };
            dispatch(&h.ctx, &op, &mut Cursor::new(Vec::new()), &mut out).unwrap();
            let (head, payload) = head_of(&out);
            assert_eq!((head["len"].as_u64(), head["reply"]["sha256"].as_str()), (Some(payload.len() as u64), Some(sha(payload).as_str())), "{head}");
            serde_json::from_slice(payload).unwrap()
        };
        assert_eq!(serde_json::to_string(&view(10)).unwrap(), r#"{"v":1,"present":false,"entries":[]}"#);
        put(&h.file(), include_bytes!("../../tests/fixtures/view/tails/example.jsonl"));
        let reply = view(10);
        assert_eq!((reply.title.as_deref(), reply.entries.len(), reply.entries[1].blocks.len()), (Some("Fix the seed's shallow boundary"), 2, 3));
        let mut out = Vec::new();
        let op = ShimIoOp::TranscriptView { projects: h.projects.clone(), rel: h.rel.clone(), n: 0 };
        dispatch(&h.ctx, &op, &mut Cursor::new(Vec::new()), &mut out).unwrap();
        assert_eq!(head_of(&out).0["code"].as_str(), Some("bad_request"), "n 0");
        // The read starts at the hidden entry's `{`: its line's garbage start is before the read.
        let user = |uuid: &str, parent: Option<&str>, text: &str, pad: usize| {
            let parent = parent.map_or("null".to_string(), |p| format!("\"{p}\""));
            format!(r#"{{"parentUuid":{parent},"isSidechain":false,"type":"user","message":{{"role":"user","content":"{text}"}},"uuid":"{uuid}","pad":"{}"}}"#, "x".repeat(pad))
        };
        let (hidden, kept) = ("0199a1b2-c3d4-7e5f-8a9b-000000000001", "0199a1b2-c3d4-7e5f-8a9b-000000000002");
        let last = user(kept, Some(hidden), "kept", 0);
        let bare = user(hidden, None, "hidden", 0).len();
        let pad = usize::try_from(VIEW_TAIL_MAX).unwrap() - bare - 1 - last.len() - 1;
        let text = format!("garbage{}\n{last}\n", user(hidden, None, "hidden", pad));
        put(&h.file(), text.as_bytes());
        let reply = view(10);
        let shown: Vec<&str> = reply.entries.iter().flat_map(|e| e.blocks.iter().map(String::as_str)).collect();
        assert_eq!(shown, ["kept"], "the partial first line is dropped");
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
        let op = ShimIoOp::TranscriptStat { projects: w.ctx.home.join(".claude/projects"), rel: format!("{SLUG}/{ID}.jsonl"), from: None, fp: None, subtree: false };
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

    /// `transcript-write` of `body` as `rel`: its bytes, then the commit line.
    fn write_transcript(w: &World, projects: &Path, rel: &str, body: &[u8]) -> Step<TranscriptWriteReply> {
        let input = [body, format!("{COMMIT}\n").as_bytes()].concat();
        w.ctx.transcript_write(projects, rel, body.len() as u64, None, &mut Cursor::new(input))
    }

    /// A transcript as a pull writes it (S9; S8's put went at the cut-over):
    /// absent, then written (0600, 0700 directories) and stated; another
    /// write replaces it whatever its length (the VM's copy never outranks
    /// what S3 holds: the Mac pulls only when the VM lacks the committed
    /// prefix); a traversal 400; a symlinked directory or file 409; no temp
    /// file left on any path.
    #[test]
    fn transcripts_are_written_as_the_agent_and_stated() {
        let w = World::new();
        let projects = w.ctx.home.join(".claude/projects");
        let rel = format!("{SLUG}/{ID}.jsonl");
        assert!(!w.ctx.transcript_stat(&projects, &rel).unwrap().present);
        let one = write_transcript(&w, &projects, &rel, b"{\"a\":1}\n").unwrap();
        assert_eq!(one.size, 8);
        let file = projects.join(&rel);
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(projects.join(SLUG)).unwrap().permissions().mode() & 0o777, 0o700);
        let stat = w.ctx.transcript_stat(&projects, &rel).unwrap();
        assert!(stat.present && stat.size == 8 && stat.sha256.as_deref() == Some(one.sha256.as_str()) && stat.mtime.is_some(), "{stat:?}");
        assert_eq!(write_transcript(&w, &projects, &rel, b"{}\n").unwrap().size, 3, "a shorter pull replaces it");
        assert_eq!(std::fs::read(&file).unwrap(), b"{}\n");
        let r = refused(w.ctx.transcript_write(&projects, &rel, 5, None, &mut Cursor::new(b"abc".to_vec())));
        assert_eq!(r.code, refusal::TRANSFER_FAILED, "a short input: {r:?}");
        assert_eq!(std::fs::read(&file).unwrap(), b"{}\n", "nothing renamed");
        for bad in [format!("../{ID}.jsonl"), format!("{SLUG}/../{ID}.jsonl"), format!("{SLUG}/{ID}/../../x/{ID}.jsonl")] {
            assert_eq!(refused(w.ctx.transcript_stat(&projects, &bad)).code, refusal::BAD_REQUEST, "{bad}");
            assert_eq!(refused(write_transcript(&w, &projects, &bad, b"{}\n")).code, refusal::BAD_REQUEST, "{bad}");
        }
        let elsewhere = w.root().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, projects.join("-linked")).unwrap();
        let linked = format!("-linked/{ID}.jsonl");
        assert_eq!(refused(write_transcript(&w, &projects, &linked, b"{}")).code, refusal::SYMLINK_COMPONENT);
        std::os::unix::fs::symlink(&file, projects.join(SLUG).join("0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c.jsonl")).unwrap();
        assert_eq!(refused(w.ctx.transcript_stat(&projects, &format!("{SLUG}/0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c.jsonl"))).code, refusal::SYMLINK_COMPONENT);
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none(), "nothing written through a link");
        let names: Vec<String> = std::fs::read_dir(projects.join(SLUG)).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "no temp file left: {names:?}");
        // A component as long as a name may be: its temp name is its own length.
        let long = format!("{SLUG}/{ID}/subagents/{}.jsonl", "a".repeat(crate::wire::workspace::SEGMENT_MAX - 6));
        assert_eq!(write_transcript(&w, &projects, &long, b"{}\n").unwrap().size, 3);
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

    /// A write a helper ended by a signal left its temp file (no drop ran):
    /// the next write into that directory removes it; only names a write
    /// makes, and only regular files (a look-alike name, a symlink, a longer
    /// name stay).
    #[test]
    fn the_next_write_sweeps_what_an_ended_write_left() {
        let w = World::new();
        let projects = w.ctx.home.join(".claude/projects");
        let dir = projects.join(SLUG);
        write(&dir.join(".ai-env-0123456789abcdef.tmp"), "half a transcript");
        write(&dir.join(".ai-env-ABCDEF0123456789.tmp"), "not a write's");
        write(&dir.join(".ai-env-0123456789abcdef.tmp.keep"), "not a write's");
        std::os::unix::fs::symlink(dir.join(".ai-env-ABCDEF0123456789.tmp"), dir.join(".ai-env-fedcba9876543210.tmp")).unwrap();
        assert_eq!(write_transcript(&w, &projects, &format!("{SLUG}/{ID}.jsonl"), b"{}\n").unwrap().size, 3);
        let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, [".ai-env-0123456789abcdef.tmp.keep", ".ai-env-ABCDEF0123456789.tmp", ".ai-env-fedcba9876543210.tmp", &format!("{ID}.jsonl")]);
        assert!(is_transcript_temp(b".ai-env-0123456789abcdef.tmp") && !is_transcript_temp(b".ai-env-0123456789abcde.tmp") && !is_transcript_temp(format!("{ID}.jsonl").as_bytes()));
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

    /// S9 (§3.2): a reply that would pass `HEAD_LINE_MAX` goes after a small
    /// head: `JsonPayloadReply` with the payload's sha256 and `len`, then
    /// exactly `len` bytes of the reply's compact JSON; a refusal stays an
    /// ordinary head; a reply over `JSON_PAYLOAD_MAX` is the helper's failure.
    #[test]
    fn a_payload_reply_is_a_small_head_then_its_json() {
        let reply = TranscriptStat { present: true, size: 1, subtree: (0..200).map(|i| crate::wire::workspace::SubtreeFile { rel: format!("{SLUG}/{ID}/subagents/agent-{i:04}-{}.jsonl", "a".repeat(990)), size: 7, sha256: "0".repeat(64) }).collect(), ..TranscriptStat::default() };
        let mut out = Vec::new();
        answer_payload(&mut out, Ok(reply.clone())).unwrap();
        let nl = out.iter().position(|b| *b == b'\n').expect("a head line");
        assert!(nl < 1024, "a small head: {nl} bytes");
        let head: HelperHead<JsonPayloadReply> = serde_json::from_slice(&out[..nl]).unwrap();
        let (sums, len) = head.outcome().expect("a reply").expect("not a refusal");
        let payload = &out[nl + 1..];
        assert!(payload.len() > 200 << 10, "a 200 KiB reply: {}", payload.len());
        assert_eq!(Some(payload.len() as u64), len);
        assert_eq!(sums.sha256, hex::encode(Sha256::digest(payload)));
        assert_eq!(serde_json::from_slice::<TranscriptStat>(payload).unwrap(), reply, "the payload is the reply");
        let mut refused_out = Vec::new();
        answer_payload::<TranscriptStat>(&mut refused_out, refuse(refusal::PATH_OCCUPIED, "not a regular file")).unwrap();
        let head: HelperHead<JsonPayloadReply> = serde_json::from_slice(refused_out.strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(head.outcome().map(|o| o.map(|_| ()).map_err(|r| r.code)), Some(Err(refusal::PATH_OCCUPIED.to_string())));
        let huge = "x".repeat(JSON_PAYLOAD_MAX);
        assert!(answer_payload(&mut Vec::new(), Ok(huge)).is_err(), "over the payload cap: the helper fails");
    }

    /// `script` as the helper's `--git`: a 0755 shell script in `w`'s root
    /// named `name`, run once outside any budget (macOS assesses a new
    /// executable's first exec).
    fn git_script(w: &World, name: &str, script: &str) -> PathBuf {
        let path = w.root().join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let warmed = {
            let _fork = crate::test_locks::forking();
            Command::new(&path).arg("--help").stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap()
        };
        assert!(warmed.code().is_some(), "{name} ran");
        path
    }

    /// S9, W3 #10: an untracked file the agent removes while a snapshot
    /// adds the untracked files (here at that very step, by the helper's
    /// git) is left out of the snapshot, never a failed one (`add
    /// --pathspec-from-file` failed it: "did not match any files"); the
    /// other files ride as before.
    #[test]
    fn a_snapshot_drops_an_untracked_file_gone_since_its_listing() {
        let w = World::new();
        let (_, body) = clone_body(&w.mac(), Some("main"));
        apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap();
        let ws = w.ws();
        write(&ws.join("a.txt"), "edited\n");
        write(&ws.join("kept.txt"), "the agent's\n");
        write(&ws.join("gone.txt"), "removed while the snapshot runs\n");
        let script = format!("#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in --add|--pathspec-from-file=-) rm -f '{}' ;; esac\ndone\nexec '{}' \"$@\"\n", ws.join("gone.txt").display(), real_git().display());
        let racing = git_script(&w, "racing-git", &script);
        let ctx = Ctx { home: w.ctx.home.clone(), fs_root: w.ctx.fs_root.clone(), git: racing, started: Instant::now(), budget: None };
        let snap = ctx.snapshot(WS, Duration::from_secs(30)).unwrap();
        let wip = snap.wip_ref.clone().unwrap_or_else(|| panic!("a snapshot: {snap:?}"));
        assert!(!ws.join("gone.txt").exists(), "the agent removed it as the snapshot added the untracked files");
        assert_eq!(git(&ws, &["ls-tree", "--name-only", &wip]).lines().collect::<Vec<_>>(), ["a.txt", "d", "kept.txt"]);
        assert_eq!((git(&ws, &["show", &format!("{wip}:a.txt")]), git(&ws, &["show", &format!("{wip}:kept.txt")])), ("edited".to_string(), "the agent's".to_string()));
        assert_eq!(status(&ws), [" M a.txt", "?? kept.txt"], "the agent's index is never written");
        assert!(w.inbox_is_empty());
    }

    /// S9, F4: a VM ref whose name the scrubber masks part of (the
    /// setup-token's shape, built at run time: a branch, a snapshot ref, the
    /// branch checked out) never leaves the VM by name. The code-out lists
    /// each at its commit under a stand-in of its namespace, numbered in name
    /// order, as it names the branch checked out; the Mac's scrubber masks
    /// every stand-in, so its screen hides and counts them as before. The
    /// helper's own snapshot and `main` pass as they are; the agent's snapshot
    /// ref the helper takes for the newest goes as its stand-in (`/suspend`'s
    /// snapshot takes none such: its reply names it as it is).
    #[test]
    fn a_codeout_lists_credential_shaped_ref_names_under_stand_ins() {
        let w = World::new();
        let (seed, body) = clone_body(&w.mac(), Some("main"));
        apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap();
        let ws = w.ws();
        let token = format!("{}-{}-oat01-{}", "sk", "ant", "Kq4_".repeat(20));
        let masked = |text: &str| text.replace(&token, "<TOKEN>");
        let commit = agent_commit(&ws, &[("agent.txt", "the agent's\n")]);
        git(&ws, &["branch", &format!("x-{token}")]);
        git(&ws, &["update-ref", &format!("refs/wip/zz-{token}"), "HEAD"]);
        git(&ws, &["checkout", "-q", "-b", &format!("y-{token}")]);
        write(&ws.join("agent.txt"), "uncommitted\n");
        let haves = format!("[\"{}\"]", seed.head);
        let out = w.ctx.codeout(WS, true, 1 << 20, &mut Cursor::new(haves.clone().into_bytes())).unwrap();
        let m = &out.manifest;
        m.check().unwrap();
        let json = serde_json::to_string(m).unwrap();
        assert!(!json.contains(&token[7..]), "a name that looks like a credential left the VM: {}", masked(&json));
        let snapshot = m.wip_ref.clone().expect("the helper's own snapshot");
        assert!(wip_key(&snapshot).is_some_and(|(t, _)| t.starts_with("20")), "{snapshot}");
        let listed: BTreeMap<String, String> = m.refs.iter().map(|(k, v)| (masked(k), v.clone())).collect();
        let want: BTreeMap<String, String> = [
            ("refs/heads/main".to_string(), commit.clone()),
            ("refs/heads/token=hidden-1".to_string(), commit.clone()),
            ("refs/heads/token=hidden-2".to_string(), commit.clone()),
            (snapshot.clone(), m.refs[&snapshot].clone()),
            ("refs/wip/token=hidden-3".to_string(), commit.clone()),
        ]
        .into();
        assert_eq!(listed, want);
        assert_eq!(m.branch.as_deref().map(masked).as_deref(), Some("token=hidden-2"), "the branch checked out, by its stand-in");
        for name in m.refs.keys().filter(|n| n.contains(HIDDEN_STAND_IN)).chain(m.branch.as_ref()) {
            assert_ne!(crate::wire::redact::scrub(name), name.as_str(), "the Mac's screen takes {name} for what it stands for");
        }
        assert!(out.pack.is_some(), "the commits still come back");
        drop(out);
        // The agent's own snapshot ref of the unchanged checkout, the newest by its name: the helper takes it.
        let tree = git(&ws, &["rev-parse", &format!("{snapshot}^{{tree}}")]);
        let theirs = git(&ws, &["commit-tree", &tree, "-p", "HEAD", "-m", "the agent's snapshot"]);
        git(&ws, &["update-ref", &format!("refs/wip/zz-{token}-9"), &theirs]);
        let again = w.ctx.codeout(WS, true, 1 << 20, &mut Cursor::new(haves.into_bytes())).unwrap();
        let m = &again.manifest;
        m.check().unwrap();
        assert!(!serde_json::to_string(m).unwrap().contains(&token[7..]), "the snapshot taken goes by its stand-in");
        assert_eq!((m.wip_ref.as_deref().map(masked).as_deref(), m.refs.get("refs/wip/token=hidden-4")), (Some("refs/wip/token=hidden-4"), Some(&theirs)));
        assert_eq!(git(&ws, &["for-each-ref", "--format=%(refname)", "refs/wip/"]).lines().count(), 3, "the helper made no snapshot of its own");
    }

    /// S9, F4: `/suspend`'s snapshot never names an agent's `refs/wip/*`
    /// whose name the scrubber masks part of (the setup-token's shape, built
    /// at run time), though it sorts newest and holds the checkout's tree on
    /// its parents: the reply leaves the VM by name (the shim logs it and
    /// keeps it for its health). With no other snapshot of that state the
    /// helper makes its own, which a second snapshot of the unchanged
    /// checkout keeps.
    #[test]
    fn a_snapshot_never_keeps_a_credential_shaped_ref_name() {
        let w = World::new();
        let (_, body) = clone_body(&w.mac(), Some("main"));
        apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap();
        let ws = w.ws();
        write(&ws.join("a.txt"), "edited\n");
        write(&ws.join("new.txt"), "the agent's\n");
        let token = format!("{}-{}-oat01-{}", "sk", "ant", "Kq4_".repeat(20));
        // The checkout's state as the helper commits it: its worktree's tree on HEAD (the index is HEAD's).
        let (theirs, index) = wip_of(&ws).expect("a dirty checkout");
        assert_eq!(index, None);
        git(&ws, &["update-ref", &format!("refs/wip/zz-{token}-9"), &theirs]);
        let snap = w.ctx.snapshot(WS, Duration::from_secs(30)).unwrap();
        let made = snap.wip_ref.clone().unwrap_or_else(|| panic!("a snapshot: {snap:?}"));
        assert!(!made.contains(&token[7..]), "a name that looks like a credential left the VM: {}", made.replace(&token, "<TOKEN>"));
        assert!(wip_key(&made).is_some_and(|(t, _)| t.starts_with("20")), "the helper's own: {made}");
        assert_eq!(git(&ws, &["rev-parse", &format!("{made}^{{tree}}")]), git(&ws, &["rev-parse", &format!("{theirs}^{{tree}}")]));
        let again = w.ctx.snapshot(WS, Duration::from_secs(30)).unwrap();
        assert_eq!((again.wip_ref.as_deref(), again.wip_skipped), (Some(made.as_str()), None), "the checkout unchanged: the helper's own kept");
        assert_eq!(git(&ws, &["for-each-ref", "--format=%(refname)", "refs/wip/"]).lines().count(), 2, "one snapshot made");
        assert_eq!(status(&ws), [" M a.txt", "?? new.txt"], "the agent's index is never written");
    }

    /// S9, F8: `git version` against the floor: the image's, this Mac's
    /// (Apple's suffix), a build's suffix; anything else is no version.
    #[test]
    fn git_versions_are_read_against_the_floor() {
        for (line, want, passes) in [
            ("git version 2.50.1", Some((2, 50)), true),
            ("git version 2.54.0 (Apple Git-157)", Some((2, 54)), true),
            ("git version 2.46.0.windows.1", Some((2, 46)), true),
            ("git version 3.0.0", Some((3, 0)), true),
            ("git version 2.45.2", Some((2, 45)), false),
            ("git version 1.99.9", Some((1, 99)), false),
            ("version 2.50.1", None, false),
            ("git version two", None, false),
        ] {
            assert_eq!(git_version(line), want, "{line}");
            assert_eq!(git_version(line).is_some_and(|v| v >= GIT_FLOOR), passes, "{line}");
        }
    }

    /// S9, F8: a git older than [`GIT_FLOOR`] (it has no `symref-verify`)
    /// refuses an update before anything moves: 500 `git_failed` naming its
    /// version and the floor, the refs, the checkout and `.git/shallow` as
    /// they were; with this Mac's git the same update goes in.
    #[test]
    fn a_move_refuses_a_git_older_than_its_floor() {
        let w = World::new();
        let mac = w.mac();
        let (seed, body) = clone_body(&mac, Some("main"));
        let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
        let tip = seed.head.clone();
        write(&mac.join("a.txt"), "four\n");
        git(&mac, &["commit", "-q", "-am", "c3"]);
        let (_, body) = update_of(&w, &seed, &tip);
        let script = format!("#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = version ]; then echo 'git version 2.45.2'; exit 0; fi\ndone\nexec '{}' \"$@\"\n", real_git().display());
        let old = git_script(&w, "old-git", &script);
        let ctx = Ctx { home: w.ctx.home.clone(), fs_root: w.ctx.fs_root.clone(), git: old, started: Instant::now(), budget: None };
        let q = query(SeedMode::Update, Some("main"), Some(&tip));
        let r = refused(ctx.seed_apply(&q, body.len() as u64, Some(&record), &mut Cursor::new(body.clone())));
        assert!(r.code == refusal::GIT_FAILED && r.message.contains("git version 2.45.2") && r.message.contains("2.46 or later"), "{r:?}");
        let ws = w.ws();
        for name in ["HEAD", "refs/heads/main", SEED_REF] {
            assert_eq!(git(&ws, &["rev-parse", name]), tip, "{name}");
        }
        assert!(status(&ws).is_empty(), "{:?}", status(&ws));
        assert_eq!(std::fs::read_to_string(ws.join(".git/shallow")).unwrap(), format!("{tip}\n"), "the shallow file restored");
        assert_eq!(apply(&w, &q, &body, Some(&record)).unwrap().0.outcome, SeedApplied::Updated, "a git at the floor or later");
    }

    /// S9, F8: an agent that checks out another branch at the same commit
    /// while an update's or a replace's pack comes in (past every check)
    /// keeps its checkout: HEAD no longer names the branch the checks saw,
    /// so `symref-verify` fails before the move's transaction, 409
    /// `changed`; nothing of the Mac's is written under the agent's HEAD,
    /// `main`, the seed ref and `.git/shallow` stay at the tip.
    #[test]
    fn a_move_never_follows_a_head_switched_to_another_branch_meanwhile() {
        for mode in [SeedMode::Update, SeedMode::Replace] {
            let w = World::new();
            let mac = w.mac();
            let (seed, body) = clone_body(&mac, Some("main"));
            let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
            let tip = seed.head.clone();
            write(&mac.join("a.txt"), "four\n");
            git(&mac, &["commit", "-q", "-am", "c3"]);
            let (m, body) = if mode == SeedMode::Update { update_of(&w, &seed, &tip) } else { clone_body(&mac, Some("main")) };
            let ws = w.ws();
            let mut input = MidBody::new(&body, head_line(&m).unwrap().len(), || {
                git(&ws, &["checkout", "-q", "-b", "other"]);
            });
            let r = refused(w.ctx.seed_apply(&query(mode, Some("main"), Some(&tip)), body.len() as u64, Some(&record), &mut input));
            assert!(r.code == refusal::CHANGED && r.message.contains("refs/heads/other"), "{mode:?}: {r:?}");
            assert_eq!(git(&ws, &["symbolic-ref", "HEAD"]), "refs/heads/other", "{mode:?}: the agent's HEAD stays");
            for name in ["HEAD", "refs/heads/main", "refs/heads/other", SEED_REF] {
                assert_eq!(git(&ws, &["rev-parse", name]), tip, "{mode:?}: {name}");
            }
            assert!(status(&ws).is_empty(), "{mode:?}: nothing written under the agent's HEAD: {:?}", status(&ws));
            assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "three\n", "{mode:?}");
            assert_eq!(std::fs::read_to_string(ws.join(".git/shallow")).unwrap(), format!("{tip}\n"), "{mode:?}: the shallow file restored");
            assert!(w.inbox_is_empty(), "{mode:?}");
        }
    }

    /// S9, F8: a replace's forward step resets the index to the worktree
    /// its seed left keeping the stat data of every entry it keeps (`read-tree
    /// --reset`), so its refresh hashes none of the files the replace leaves
    /// as they are (a VM clean filter logs every file git hashes; each file
    /// older than the index, so none is racily clean): a plain `read-tree`
    /// hashed the whole checkout again on every replace.
    #[test]
    fn a_replace_keeps_the_stat_data_of_the_files_it_leaves() {
        let w = World::new();
        let mac = w.mac();
        for i in 0..20 {
            write(&mac.join(format!("f{i:02}.txt")), &format!("file {i}\n"));
        }
        git(&mac, &["add", "-A"]);
        git(&mac, &["commit", "-q", "-m", "files"]);
        let (seed, body) = clone_body(&mac, Some("main"));
        let record = apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap().1.record.unwrap();
        write(&mac.join("a.txt"), "replaced\n");
        git(&mac, &["commit", "-q", "-am", "c4"]);
        let (_, body) = clone_body(&mac, Some("main"));
        let ws = w.ws();
        let old = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        for rel in (0..20).map(|i| format!("f{i:02}.txt")).chain(["a.txt".to_string(), "d/b.txt".to_string()]) {
            std::fs::OpenOptions::new().write(true).open(ws.join(&rel)).unwrap().set_modified(old).unwrap();
        }
        git(&ws, &["update-index", "-q", "--refresh"]);
        let log = w.root().join("hashed.log");
        git(&ws, &["config", "filter.log.clean", &format!("echo %f >> '{}'; cat", log.display())]);
        write(&ws.join(".git/info/attributes"), "* filter=log\n");
        let (reply, state) = apply(&w, &query(SeedMode::Replace, Some("main"), Some(&seed.head)), &body, Some(&record)).unwrap();
        assert_eq!(reply.outcome, SeedApplied::Replaced);
        let hashed = std::fs::read_to_string(&log).unwrap_or_default();
        let left: Vec<&str> = hashed.lines().filter(|l| l.starts_with('f')).collect();
        assert!(left.is_empty(), "the replace hashed files it left as they were: {left:?}");
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "replaced\n");
        assert!(state.clean && state.pristine && status(&ws).is_empty(), "{state:?} {:?}", status(&ws));
    }

    /// S9: an edit at the same size in the index's own second rides in the
    /// snapshot. The helper's copies of the index keep its mtime, so git
    /// re-reads a file whose cached stat still matches; a copy written later
    /// took that stat on trust, and the snapshot left the edit out. The
    /// index, the file's entry and the edit all in one past second (an
    /// agent's tool writing within its commit's second); the copies made now.
    #[test]
    fn a_same_size_edit_in_the_indexs_own_second_rides_in_the_snapshot() {
        let w = World::new();
        let (_, body) = clone_body(&w.mac(), Some("main"));
        apply(&w, &query(SeedMode::Clone, Some("main"), None), &body, None).unwrap();
        let ws = w.ws();
        let then = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        let touch = |p: &Path| std::fs::OpenOptions::new().write(true).open(p).unwrap().set_modified(then).unwrap();
        touch(&ws.join("a.txt"));
        git(&ws, &["update-index", "-q", "--refresh"]);
        touch(&ws.join(".git/index"));
        // "three\n" to "seven\n": the same size, in the same inode, at the same mtime.
        std::fs::write(ws.join("a.txt"), "seven\n").unwrap();
        touch(&ws.join("a.txt"));
        let snap = w.ctx.snapshot(WS, Duration::from_secs(30)).unwrap();
        let wip = snap.wip_ref.clone().unwrap_or_else(|| panic!("the edit taken for clean: {snap:?}"));
        assert_eq!(git(&ws, &["show", &format!("{wip}:a.txt")]), "seven");
        assert_eq!(status(&ws), [" M a.txt"], "the agent's index is never written");
    }
}
