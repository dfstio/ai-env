//! The S2 NDJSON pump: with `AI_ENV_BRIDGE_MODE=local-child|local-scratch` a
//! stream-json session is no longer exec'd — the wrapper spawns the real
//! binary as a piped child and stands between it and the extension.
//!
//! What it does, per line:
//! * host stdin → child stdin, byte-for-byte, recorded by
//!   `bridge::hoststate` (initialize, state requests, pending ids,
//!   outstanding user lines);
//! * child stdout → host stdout, classified by `wire::claude`:
//!   `transcript_mirror` frames go to `bridge::mirror` and are NEVER
//!   forwarded; `oauth_token_refresh` / `host_auth_token_refresh` requests
//!   are answered locally with a null token and never forwarded (the
//!   extension would throw); a gen-1 resume-miss `result` is held until the
//!   child's exit decides between a seed retry (dropped) and propagation;
//!   everything else is forwarded or, after a respawn, rewritten/swallowed as
//!   `hoststate` decides;
//! * child stderr → the wrapper's stderr as a raw byte copy (never re-framed:
//!   the extension shows its last 2048 bytes on a non-zero exit).
//!
//! Concurrency (one current-thread tokio runtime, built only here): every
//! I/O direction is its own task behind a bounded channel — host stdin
//! reader, host stdout writer, child stdin writer, child stdout reader, child
//! stderr copy, child waiter/signaller. The supervisor never awaits a send:
//! it keeps a small queue per direction and offers the head through a
//! `reserve()` future inside its `select!`, and it stops reading a source
//! while the queue towards its sink is not empty. Backpressure therefore
//! propagates end to end (a stalled host stops the child's stdout, a child
//! that does not read stops the host's stdin), and neither stall can block
//! the other direction, the signals or the deadlines.
//!
//! The child is reached through a [`ChildLink`] (an input sender, a signal
//! sender, an event receiver) that a `remote::link::LinkFactory` hands the
//! pump for each generation: `LocalLinks` over a local process
//! ([`spawn_local`], S2), `RemoteLinks` over the MicroVM's agent transport
//! (S8 `remote`). The supervisor runs on a `LocalSet` in every mode, where a
//! remote generation's pipeline and adapter run as local tasks. A remote
//! start returns its link at once and is pending until its first event,
//! `Started` or `SpawnFailed` (never `Exit(None)`, so the [`EndReason`]s keep
//! their meaning): a pending start is a live child, so the ladders run, the
//! host is still read (until the pump's own queue holds `PENDING_IN_LINES`
//! lines or `PENDING_IN_BYTES`; the link's channel holds its [`CHANNEL_CAP`]
//! lines more, of any size, as in every state: S8's TIMING-4, as designed),
//! and a host EOF or a signal cancels it at once. A remote session
//! fails closed: whatever ends it before or after the pump started is an
//! exit with one `ai-env-claude:` line, printed last through `bridge::voice`,
//! never a local run.
//!
//! Timing (plan D22): host stdin EOF → child stdin closed → SIGTERM at
//! +800 ms → SIGKILL at +1200 ms → hard stop at +1400 ms → exit ≤ 1500 ms;
//! SIGTERM to the wrapper → SIGTERM the child now → SIGKILL at +600 ms →
//! hard stop at +900 ms → exit ≤ 1000 ms. The rungs are the link's
//! (`CloseTimings`): a remote CLI is never sent TERM after EOF, its own exit
//! is awaited until `detach{final}` at +1200 ms (L2). The queued lines' flush
//! to the host never outlives the hard stop. When the child ends on its own
//! while the host still reads, its remaining output is drained eagerly and
//! the host gets up to 5 s to take it. At the end the mirror is fsync'ed, the
//! registry row closed and a second census row (the start row + `end`,
//! `exit`, a note) appended; a remote link then gets what is left of the hard
//! stop to close (`LinkFactory::close`) before `process::exit`.
//!
//! The forwarded answer to the host's `initialize` carries the wrapper's pid
//! in every piped mode (`wire::claude::rewrite_initialize_pid`): the
//! extension's pid is the process it spawned, never a CLI in a VM or a
//! respawned generation.
//!
//! Lines are split at the CLI's own limit (256 MiB, `CLI_LINE_BYTES`): a user
//! message with pasted images or a transcript entry holding them passes as
//! the CLI would take it (the agent transport carries byte chunks, S6).
//!
//! `local-scratch` logs its child in with the sealed setup-token (S7,
//! [`scratch_login`]): when `CLAUDE_CODE_OAUTH_TOKEN` is not in the
//! environment, `credentials/setup-token.env` is unsealed before the spawn
//! (one Touch ID, the countdown on stderr, `[creds].unseal_timeout_s` — but
//! never past T−10 s of Cursor's 60 s initialize window, which runs while the
//! child does not exist yet: [`scratch_unseal_budget`]) and handed to the
//! child on fd 3 — or in its environment only, with `[creds] deliver =
//! "env"` — never in argv or on disk; the wrapper's copy is dropped once no
//! child generation can need it. Anything that keeps the token from the
//! child (none sealed, a refused seal, a dismissed dialog, the deadline) is
//! one note line, and the child runs logged out: the session is never
//! blocked or failed for it. SIGINT (130), SIGTERM and SIGHUP (143) during
//! the wait close the dialog (age runs in its own process group) and end the
//! wrapper. Every piped invocation pays its own Touch ID: Cursor's config
//! probe, whose argv is a chat's, included.
//!
//! A debug-build lab knob, [`SYNTHETIC_OAUTH_KNOB`], probes the extension's
//! side of Tier B: once the session is initialized the pump sends the host one
//! `oauth_token_refresh` request of its own and records the class of the
//! answer in the end row (`synthetic_oauth:<class>`); the answer is never
//! forwarded to the child.
use crate::age_cmd::{AgeKill, AgeTool};
use crate::bridge::agent::credential::{read_rejection, tag_of};
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::census::{self, CensusRow};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::creds::{aws_env_state, AwsEnvState};
use crate::bridge::hoststate::{ChildVerdict, DupCounts, HostState, HostVerdict};
use crate::bridge::lab::{self, PumpKnobs};
use crate::bridge::logging::{self, LogOpts};
use crate::bridge::mirror::{self, MirrorCfg, Writer};
use crate::bridge::registry::{self, SessionRow};
use crate::bridge::remote::link::{CloseTimings, LinkFactory, LinkKind, LinkLoss, LocalLinks, MoveFailure, MoveReady, RemoteLinks, RemoteStarted, SpawnFailure, StartReq, StartStep, StartWhy, PENDING_IN_BYTES, PENDING_IN_LINES, STEP_PART};
use crate::bridge::remote::{audit_event, census_part, pipeline, Failure};
use crate::bridge::remote::link::{LossCause, MoveKind, MoveWhy, RemoteSnapshot};
use crate::bridge::remote::{note_continues, note_move_at_next, note_moving, note_restart_at_next, note_restarting};
use crate::bridge::park::QuietState;
use crate::bridge::remote::link::{request_of, MigrateTrigger};
use crate::bridge::remote::{note_migrating, note_stayed, StayedThen, MIGRATE_PREP_TRIES};
use crate::bridge::route::Mode;
use crate::bridge::voice;
use crate::bridge::seed;
use crate::bridge::workspace::TranscriptOutcome;
use crate::bridge::setup_token::{parse_token_env, sealed_text, SetupToken, TOKEN_VAR};
use crate::bridge::unseal::UnsealJob;
use crate::errors::CliError;
use crate::store::{validate_key_name, Keystore};
use crate::wire::argv::{self, Route, SanitiseOpts, SessionArgs};
use crate::wire::claude::{self, ChildFrame, HostFrame};
use crate::wire::frame::Deliver;
use crate::wire::ndjson::{encode_line, LineError, LineSplitter, CLI_LINE_BYTES};
use crate::wire::redact::{self, Secret};
use crate::wire::slug;
use crate::wire::time::unix_now_ms;
use bytes::Bytes;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// Capacity of every channel between the supervisor and an I/O task.
pub const CHANNEL_CAP: usize = 64;
/// After host stdin EOF (the child's stdin is closed at once): SIGTERM the child.
pub const EOF_TERM_AFTER: Duration = Duration::from_millis(800);
/// After host stdin EOF: SIGKILL the child.
pub const EOF_KILL_AFTER: Duration = Duration::from_millis(1200);
/// After SIGTERM to the wrapper (forwarded at once): SIGKILL the child.
pub const SIGTERM_KILL_AFTER: Duration = Duration::from_millis(600);
/// After the child's exit: how long its stdout/stderr may still drain.
pub const EXIT_DRAIN: Duration = Duration::from_millis(200);
/// A respawned child must answer the replayed requests within this.
pub const REPLAY_DEADLINE: Duration = Duration::from_secs(15);
/// At the end of a closing session: how long queued lines may take to reach the host.
pub const FLUSH_DEADLINE: Duration = Duration::from_millis(250);
/// When the child ended on its own and the host still reads: how long the
/// host may take to read the rest (a host EOF or SIGTERM shortens it).
pub const FLUSH_OPEN_DEADLINE: Duration = Duration::from_secs(5);
/// After host stdin EOF: finish no matter what (exit budget 1500 ms).
pub const EOF_HARD_STOP: Duration = Duration::from_millis(1400);
/// After SIGTERM to the wrapper: finish no matter what (exit budget 1000 ms).
pub const SIGTERM_HARD_STOP: Duration = Duration::from_millis(900);
/// Longest line the pump passes (the CLI's own stream-json limit).
pub const PUMP_LINE_CAP: usize = CLI_LINE_BYTES;
/// While closing, lines queued for a host that stopped reading beyond this
/// many are dropped (counted), so the child's exit is still observed.
pub const CLOSING_QUEUE_CAP: usize = 1024;
/// The environment variable that points the mirror writer elsewhere.
pub const MIRROR_ROOT_ENV: &str = "AI_ENV_BRIDGE_MIRROR_ROOT";
/// Removed from a scratch child's environment: it would re-point the scratch
/// child's secure storage at the host's keychain entry.
pub const SECURE_STORAGE_ENV: &str = "CLAUDE_SECURESTORAGE_CONFIG_DIR";
/// Names the child's token descriptor under fd delivery
/// (`<TOKEN_VAR>_FILE_DESCRIPTOR`, as the shim sets it in a VM).
pub const TOKEN_FD_VAR: &str = "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR";
/// The descriptor a `local-scratch` child reads the token from.
const TOKEN_FD: libc::c_int = 3;
/// `AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS=<n>` (debug builds only): once the
/// session is initialized, send the extension one `oauth_token_refresh`
/// request and wait at most `n` ms for its answer (`10000` from Cursor). Its
/// value is not allowlisted in the census (the name holds `AUTH`): the
/// name shows in `env_names`, the answer's class in the end row.
pub const SYNTHETIC_OAUTH_KNOB: &str = "AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS";
/// `AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS=<n>` (debug builds only): the budget of
/// the `local-scratch` unseal in ms, in place of `[creds].unseal_timeout_s`
/// (whose range starts at 10 s), so a test reaches the deadline at once.
/// `bridge::lab::vm_knobs` reads the same knob as the budget of every unseal
/// a credentialed `vm` or `lab` command makes.
pub const UNSEAL_TIMEOUT_KNOB: &str = "AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS";
/// How often the wrapper looks for a signal while Touch ID is awaited.
const UNSEAL_POLL: Duration = Duration::from_millis(25);
/// A signal while Touch ID is awaited: how long after it the wrapper waits,
/// at most, for the decrypt to be over before it exits. The decrypt answers
/// only once it gave up before spawning `age`, or killed and reaped it: a stop
/// that came while `age` was being spawned, before the kill could reach its
/// group, would otherwise exit first and leave the dialog up with nobody to
/// close it (`AgeKill` kills such a child as it adopts it, which needs the
/// process alive). The answer normally takes tens of ms; the bound keeps the
/// stop within the 1 s a SIGTERM may take.
const STOP_SETTLE: Duration = Duration::from_millis(800);
/// Cursor closes the channel when `initialize` is not answered within this
/// much of the wrapper's spawn (v6 §3.1).
pub const INITIALIZE_WINDOW: Duration = Duration::from_secs(60);
/// The `local-scratch` unseal gives up this long before [`INITIALIZE_WINDOW`]
/// closes (v6 §2.8, "fail fast at T−10 s"), so a logged-out child still has
/// the rest to start and answer `initialize`.
pub const INIT_FAIL_FAST: Duration = Duration::from_secs(10);
/// How long after generation 1 of a `--resume` answered `initialize` the
/// token copy is kept for the seed retry. The CLI reports a resume miss
/// synchronously at startup, while its first `system/init` comes with the
/// first turn: holding the copy until that init would keep it for as long as
/// a resumed chat sits idle.
const RESUME_MISS_GRACE: Duration = Duration::from_secs(2);
/// The most of an error text the end row keeps from the extension's answer.
const SYNTHETIC_ERROR_CHARS: usize = 160;
/// The wrapper's exit once Anthropic refused a remote session's token (S7
/// D6's, as `vm exec`'s).
const REJECTED_STATUS: i32 = 5;
/// After that refusal, how long the session's stop (`Signal(Term)` plus
/// `detach{final}`) may take before the wrapper finishes anyway.
const REJECT_HARD_STOP: Duration = Duration::from_secs(2);

const READ_CHUNK: usize = 64 * 1024;

/// A `_MS` lab knob's value: a positive number of milliseconds; unset, `0`
/// and anything unparseable are off (a lab knob never breaks a session).
#[must_use]
pub fn parse_ms_knob(value: Option<&str>) -> Option<Duration> {
    value.and_then(|v| v.trim().parse::<u64>().ok()).filter(|ms| *ms > 0).map(Duration::from_millis)
}

/// A `_MS` lab knob from the environment (debug builds only, as `bridge::lab`'s).
#[cfg(debug_assertions)]
fn ms_knob(name: &str) -> Option<Duration> {
    parse_ms_knob(std::env::var(name).ok().as_deref())
}

/// Release builds: every knob off, whatever the environment says.
#[cfg(not(debug_assertions))]
fn ms_knob(_name: &str) -> Option<Duration> {
    None
}

/// Everything `ai-env-claude` knew when it decided to pipe this invocation.
#[derive(Debug, Clone)]
pub struct Session {
    pub real_binary: PathBuf,
    /// The CLI arguments after argv[1], verbatim.
    pub args: Vec<String>,
    pub route: Route,
    pub session: SessionArgs,
    pub cwd: Option<PathBuf>,
    pub paths: Paths,
    /// Unused by the local modes; S8 reads the VM settings from it.
    pub cfg: Option<BridgeConfig>,
    pub mode: Mode,
    /// This invocation's census row (the end row clones it): written by
    /// `main`, or for a remote session by [`run`] once it listens for a stop
    /// (S8 phase 4).
    pub start_row: CensusRow,
}

/// How the child is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildPlan {
    pub program: PathBuf,
    /// `argv::sanitise` with nothing stripped: the host's argv + one `--session-mirror` (a
    /// remote session's VM argv is the pipeline's, without it: S9 keeps the transcript in S3).
    pub argv: Vec<String>,
    pub env_set: Vec<(String, OsString)>,
    pub env_remove: Vec<String>,
    /// The child's `CLAUDE_CONFIG_DIR` (inherited for local-child).
    pub child_config_dir: PathBuf,
    /// `local-scratch`: the scratch config dir to create before the spawn.
    pub scratch: Option<PathBuf>,
    /// The `--resume=<uuid>` value, when it is a uuid.
    pub resume: Option<String>,
    /// The child's projects subdirectory for this cwd.
    pub slug: Option<String>,
    pub mirror: MirrorCfg,
}

/// `CLAUDE_CODE_PROJECT_DIR_NAME` when the CLI would honour it (only with
/// `CLAUDE_CONFIG_DIR` set), else the slug of the canonical cwd — the
/// directory under `<config dir>/projects` the child writes its transcript to.
#[must_use]
pub fn child_slug(cwd: Option<&Path>, config_dir_set: bool, override_name: Option<&str>) -> Option<String> {
    slug::override_dir_name(config_dir_set, override_name).or_else(|| cwd.and_then(|c| slug::project_dir_name(c).ok()))
}

/// `remote` | `local:<reason>` for the registry row.
#[must_use]
pub fn route_label(route: &Route) -> String {
    match route {
        Route::Remote(_) => "remote".to_string(),
        Route::Local(r) => format!("local:{}", r.name()),
    }
}

/// The child plan, from the session and an environment lookup (the wrapper's
/// own environment in production). Pure apart from `canonicalize` inside the
/// slug and mirror decisions; the scratch dir is only named here. A remote
/// session's (S8) child is the CLI in the VM, run by the agent whose HOME is
/// the Mac's (Design A): its config dir is the Mac HOME's `.claude`; it gets
/// no mirror writer (S9 D9: its transcript is kept in S3, never on this
/// Mac, `MirrorCfg::kept_in_s3`: a frame it prints anyway is dropped and
/// counted, [`MIRROR_DROPPED_PART`]); no scratch dir, no environment of the
/// wrapper's (the pipeline builds the VM's), and the slug is the cwd's (no
/// `CLAUDE_CODE_PROJECT_DIR_NAME`: the shim sets the VM's
/// `CLAUDE_CONFIG_DIR`, the wrapper forwards no override).
pub fn child_plan(sess: &Session, env: &dyn Fn(&str) -> Option<OsString>, fresh_id: &mut dyn FnMut() -> String) -> Result<ChildPlan, String> {
    let argv = argv::sanitise(&sess.args, SanitiseOpts { strip_add_dir: false, strip_debug: false, mirror: true }).map_err(|e| e.to_string())?;
    let nonempty = |k: &str| env(k).filter(|v| !v.is_empty());
    let mac_config_dir = match nonempty("CLAUDE_CONFIG_DIR") {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(nonempty("HOME").ok_or("HOME is not set")?).join(".claude"),
    };
    let resume = sess.session.resume.clone().filter(|r| registry::is_uuid(r));
    let override_name = env("CLAUDE_CODE_PROJECT_DIR_NAME").map(|v| v.to_string_lossy().into_owned());
    let mirror_root = nonempty(MIRROR_ROOT_ENV).map(PathBuf::from);
    let (child_config_dir, scratch, env_set, env_remove, config_dir_set) = match sess.mode {
        Mode::LocalScratch => {
            let name = resume.clone().unwrap_or_else(fresh_id);
            let dir = sess.paths.scratch().join(name);
            // The scratch child's login is the wrapper's to decide (S7): an inherited descriptor
            // number names nothing this wrapper set up, so only `spawn_local`'s fd delivery sets one.
            (dir.clone(), Some(dir.clone()), vec![("CLAUDE_CONFIG_DIR".to_string(), dir.into_os_string())], vec![SECURE_STORAGE_ENV.to_string(), TOKEN_FD_VAR.to_string()], true)
        }
        Mode::LocalChild => (mac_config_dir.clone(), None, Vec::new(), Vec::new(), nonempty("CLAUDE_CONFIG_DIR").is_some()),
        Mode::Remote => (PathBuf::from(nonempty("HOME").ok_or("HOME is not set")?).join(".claude"), None, Vec::new(), Vec::new(), false),
        Mode::Passthrough => return Err(format!("mode {} does not pipe", sess.mode.name())),
    };
    let slug = child_slug(sess.cwd.as_deref(), config_dir_set, override_name.as_deref());
    let mut mirror = mirror::decide(matches!(sess.route, Route::Remote(_)), sess.mode != Mode::Remote, &child_config_dir, &mac_config_dir, mirror_root.as_deref());
    if sess.mode == Mode::Remote {
        // A remote chat's transcript is kept in S3 (S9): none of its frames is written here.
        mirror = mirror.kept_in_s3();
    }
    Ok(ChildPlan { program: sess.real_binary.clone(), argv, env_set, env_remove, child_config_dir, scratch, resume, slug, mirror })
}

/// Why the pump ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// The child exited on its own.
    ChildExit,
    /// Host stdin closed; the child ended within the ladder (by itself or by our SIGTERM).
    EofTerm,
    /// Host stdin closed; the child needed SIGKILL.
    EofKill,
    /// The wrapper got SIGTERM/SIGINT.
    SigTerm,
    /// The host stopped reading stdout.
    HostGone,
    /// `AI_ENV_BRIDGE_LAB_EXIT=…:after-init`.
    LabExit,
    /// The child could not be spawned (S8: a remote start that ended before
    /// `spawned`, `ChildEvent::SpawnFailed`).
    SpawnFailed,
    /// S8: the remote link stayed lost past its budget after the spawn
    /// started (`ChildEvent::Lost`).
    LinkLost,
    /// S8: Anthropic refused the token delivered to the remote session (the
    /// AuthWatch verdict, `ChildEvent::Rejected`).
    CredentialRejected,
    /// S10: a move's start failed (its `ChildEvent::SpawnFailed`); the exit is
    /// the failure's, the end row carries `step:<step>`.
    MoveFailed,
}

impl EndReason {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            EndReason::ChildExit => "child_exit",
            EndReason::EofTerm => "eof",
            EndReason::EofKill => "eof_kill",
            EndReason::SigTerm => "sigterm",
            EndReason::HostGone => "host_gone",
            EndReason::LabExit => "lab_exit",
            EndReason::SpawnFailed => "spawn_failed",
            EndReason::LinkLost => "link_lost",
            EndReason::CredentialRejected => "credential_rejected",
            EndReason::MoveFailed => "move_failed",
        }
    }
}

/// What the end row records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The wrapper's exit code; `None` only for the `IGNORE_EOF=2` row written at SIGTERM.
    pub code: Option<i32>,
    pub end: Option<EndReason>,
    pub child_pid: Option<u32>,
    pub respawns: u32,
    pub mirror_frames: u64,
    pub mirror_rejected: u64,
    /// S9: a remote session's `transcript_mirror` frames dropped, its transcript
    /// being kept in S3 ([`MIRROR_DROPPED_PART`]).
    pub mirror_dropped: u64,
    pub dropped_lines: u64,
    pub oauth_answered: u64,
    pub init_latency_ms: Option<u64>,
    pub eof_to_sigterm_ms: Option<u64>,
    pub session_id: Option<String>,
    /// `local-scratch`: how the child was logged in ([`ScratchLogin::word`]);
    /// `none` once the seed retry respawned it after the token copy was
    /// dropped, since that generation runs logged out. A remote session:
    /// where its token came from (`RemoteSnapshot::credential`), however
    /// the session ended.
    pub credential: Option<&'static str>,
    /// With [`SYNTHETIC_OAUTH_KNOB`]: the class of the extension's answer
    /// ([`synthetic_answer_class`]), `none` (no answer within the wait) or
    /// `unsent` (the session was never initialized).
    pub synthetic_oauth: Option<String>,
    /// A failed remote start (`end:spawn_failed`): the step it stopped at
    /// (`remote::link::StartStep::name`).
    pub step: Option<&'static str>,
    /// A remote session: the parts its link owns (`RemoteSnapshot::census_parts`).
    pub remote: Vec<String>,
    /// From the host's EOF or the signal that closed the session to the end row.
    pub close_ms: Option<u64>,
    /// The `initialize` answer's pid: `ok` (the wrapper's), `failed` (forwarded as the CLI gave it).
    pub pid_rewrite: Option<&'static str>,
    /// A remote session: the `system/init` session ids not adopted, each
    /// naming another session's row ([`INIT_ID_REFUSED_PART`]).
    pub init_id_refused: u64,
    /// S10: the moves started (readdress, respawn, migrate): the census's `moves`.
    pub moves: [u32; 3],
    /// S10: the last move's ms, to its generation's `Started` or its failure.
    pub move_ms: Option<u64>,
    /// S10: the last move that sent lines again: `none`, `at`, `fresh`.
    pub cut: Option<&'static str>,
    /// S10: what the swallow rules and the moves did (`HostState::counts`): a remote session's only.
    pub dups: Option<DupCounts>,
    /// S10: the host's `keep_alive` lines dropped while parked.
    pub ka_dropped: u64,
}

/// The end row's part counting a remote session's `system/init` ids that
/// named another session's row, and so were not adopted
/// (`init_id_refused:<n>`, written only when `n` > 0; S8 W1's fix).
pub const INIT_ID_REFUSED_PART: &str = "init_id_refused";

/// The end row's part counting a remote session's `transcript_mirror`
/// frames dropped, its transcript being kept in S3, never on this Mac
/// (`mirror_dropped:<n>` right after `mirror:<frames>/<rejected>`, written
/// only when `n` > 0; S9 D9).
pub const MIRROR_DROPPED_PART: &str = "mirror_dropped";

/// The census end row: a clone of `start` with `end`, `exit` and the note
/// extended by `end:<reason>; child_pid:<n>; respawns:<n>; mirror:<frames>/<rejected>;
/// dropped:<n>; oauth_refresh_answered:<n>` (S9's `mirror_dropped:<n>` right after the
/// mirror part when n > 0; then `init_ms`, `eof_to_sigterm_ms` when known;
/// `credential:<fd|env|inherited|none>` for `local-scratch`, a remote session's
/// `credential:<combined|setup-token|cached>`; `synthetic_oauth:<class>` with the lab
/// knob; `init_id_refused:<n>` when n > 0; S10's `moves`, `move_ms` and `cut` once a move started,
/// a remote session's `inits:<forwarded>/<swallowed>` and `echoes:<forwarded>/<swallowed>`,
/// `ka_dropped:<n>` when n > 0; `step:<step>` for a failed remote start; a remote link's parts
/// with `close_ms` before its `link_drops`, `remote::census_part::ALL`'s order; else
/// `close_ms` after the rest; `pid_rewrite:<ok|failed>` once an `initialize` answer went).
#[must_use]
pub fn end_row(start: &CensusRow, out: &Outcome, now_ms: u64) -> CensusRow {
    let mut row = start.clone();
    row.end = Some(now_ms);
    row.exit = out.code;
    let mut parts = vec![
        format!("end:{}", out.end.map_or("unknown", EndReason::name)),
        format!("child_pid:{}", out.child_pid.map_or_else(|| "-".to_string(), |p| p.to_string())),
        format!("respawns:{}", out.respawns),
        format!("mirror:{}/{}", out.mirror_frames, out.mirror_rejected),
    ];
    if out.mirror_dropped > 0 {
        parts.push(format!("{MIRROR_DROPPED_PART}:{}", out.mirror_dropped));
    }
    parts.push(format!("dropped:{}", out.dropped_lines));
    parts.push(format!("oauth_refresh_answered:{}", out.oauth_answered));
    if let Some(ms) = out.init_latency_ms {
        parts.push(format!("init_ms:{ms}"));
    }
    if let Some(ms) = out.eof_to_sigterm_ms {
        parts.push(format!("eof_to_sigterm_ms:{ms}"));
    }
    if let Some(how) = out.credential {
        parts.push(format!("credential:{how}"));
    }
    if let Some(class) = &out.synthetic_oauth {
        parts.push(format!("synthetic_oauth:{class}"));
    }
    if out.init_id_refused > 0 {
        parts.push(format!("{INIT_ID_REFUSED_PART}:{}", out.init_id_refused));
    }
    // S10: the moves (once one started), then the swallow rules' counts of a remote session.
    if out.moves.iter().any(|n| *n > 0) {
        let [readdress, respawn, migrate] = out.moves;
        parts.push(format!("{}:readdress={readdress},respawn={respawn},migrate={migrate}", census_part::MOVES));
        if let Some(ms) = out.move_ms {
            parts.push(format!("{}:{ms}", census_part::MOVE_MS));
        }
        if let Some(cut) = out.cut {
            parts.push(format!("{}:{cut}", census_part::CUT));
        }
    }
    if let Some(d) = out.dups {
        parts.push(format!("{}:{}/{}", census_part::INITS, d.inits_forwarded, d.inits_swallowed));
        parts.push(format!("{}:{}/{}", census_part::ECHOES, d.echoes_forwarded, d.echoes_swallowed));
    }
    if out.ka_dropped > 0 {
        parts.push(format!("{}:{}", census_part::KA_DROPPED, out.ka_dropped));
    }
    if let Some(step) = out.step {
        parts.push(format!("{STEP_PART}:{step}"));
    }
    let close = out.close_ms.map(|ms| format!("{}:{ms}", census_part::CLOSE_MS));
    let drops = format!("{}:", census_part::LINK_DROPS);
    let mut close_put = false;
    for part in &out.remote {
        if part.starts_with(&drops) {
            if let Some(c) = close.as_ref().filter(|_| !close_put) {
                parts.push(c.clone());
                close_put = true;
            }
        }
        parts.push(part.clone());
    }
    if let Some(c) = close.filter(|_| !close_put) {
        parts.push(c);
    }
    if let Some(word) = out.pid_rewrite {
        parts.push(format!("{}:{word}", census_part::PID_REWRITE));
    }
    let tail = parts.join("; ");
    row.note = Some(match row.note.take() {
        Some(n) if !n.is_empty() => format!("{n}; {tail}"),
        _ => tail,
    });
    row
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod mirror_cut_tests {
    use super::*;

    const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    fn start_row() -> CensusRow {
        CensusRow {
            v: 1,
            ts: "2026-10-18T10:00:00Z".into(),
            start: 1_000,
            pid: 42,
            ppid: 1,
            ext: Some("2.1.302".into()),
            route: "remote".into(),
            reason: "session".into(),
            argv: vec!["w".into(), "b".into(), "--output-format".into(), "stream-json".into()],
            cwd: Some("/x".into()),
            env_names: vec!["HOME".into()],
            env_selected: std::collections::BTreeMap::new(),
            note: Some("mode:remote".into()),
            end: None,
            exit: None,
        }
    }

    /// A remote session in `dir`, and its child plan with `dir` as HOME.
    fn remote(dir: &Path) -> (Session, ChildPlan) {
        let args: Vec<String> = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json"].iter().map(|s| (*s).to_string()).collect();
        let route = argv::classify(&args);
        let Route::Remote(session) = route.clone() else { panic!("not a session: {route:?}") };
        let sess = Session { real_binary: PathBuf::from("/bin/claude"), args, route, session, cwd: Some(dir.to_path_buf()), paths: Paths::from_root_and_env(dir.join("bridge"), None), cfg: None, mode: Mode::Remote, start_row: start_row() };
        let home = dir.as_os_str().to_owned();
        let plan = child_plan(&sess, &move |k: &str| (k == "HOME").then(|| home.clone()), &mut || "x".to_string()).unwrap();
        (sess, plan)
    }

    /// A `transcript_mirror` frame of the session's own project.
    fn frame(dir: &Path) -> String {
        let file = dir.join(".claude/projects").join(slug::project_dir_name(dir).unwrap()).join(format!("{SID}.jsonl"));
        format!(r#"{{"type":"transcript_mirror","filePath":"{}","entries":[{{"type":"user","message":"the VM's entry"}}]}}"#, file.display())
    }

    /// A remote session's plan has no writer (S9 D9: its transcript is kept
    /// in S3), whatever the project: none confined to its own either.
    #[test]
    fn a_remote_plan_never_mirrors() {
        let d = tempfile::tempdir().unwrap();
        let (_, plan) = remote(d.path());
        assert!(!plan.mirror.enabled && plan.mirror.project.is_none() && plan.mirror.reason.contains("kept in S3"), "{:?}", plan.mirror);
    }

    /// A remote session drops each mirror frame, its own project's too,
    /// and counts it: nothing is created on this Mac, and the end row says
    /// `mirror_dropped:<n>` right after `mirror:0/0`, only when n is above 0.
    #[test]
    fn a_remote_frame_is_dropped_and_counted_without_a_writer() {
        let d = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(d.path()).unwrap();
        let (sess, plan) = remote(&dir);
        let mut pump = Pump::new(sess, plan.clone(), None, Box::new(LocalLinks::new(plan)));
        let note = end_row(&start_row(), &pump.snapshot_outcome(), 9_000).note.unwrap();
        assert!(note.contains("; mirror:0/0; dropped:0; ") && !note.contains(MIRROR_DROPPED_PART), "only when n > 0: {note}");
        for _ in 0..2 {
            pump.on_child_line(Bytes::from(frame(&dir)));
        }
        assert_eq!(pump.out.mirror_dropped, 2);
        assert!(!dir.join(".claude").exists(), "nothing written on this Mac");
        let note = end_row(&start_row(), &pump.snapshot_outcome(), 9_000).note.unwrap();
        assert!(note.contains("; respawns:0; mirror:0/0; mirror_dropped:2; dropped:0; "), "{note}");
    }

    /// S9's row fields (§5.7): kept in S3, begun in the VM when no manifest
    /// says otherwise, its view's rel.
    #[test]
    fn the_s3_fields_of_a_remote_row() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
        let mut row = SessionRow { session_id: SID.into(), mode: "remote".into(), ..SessionRow::default() };
        Pump::s3_fields(&mut row, &paths, Some("-Users-mike-w"));
        assert_eq!((row.transcript_home.as_deref(), row.origin.as_deref(), row.view.clone()), (Some("s3"), Some("vm"), Some(format!("-Users-mike-w/{SID}.jsonl"))));
        Pump::s3_fields(&mut row, &paths, None);
        assert_eq!(row.view, None, "no slug, no view");
    }
}

// ---- the child link ----------------------------------------------------------------------

/// A line (with its `\n`) or the end of the child's stdin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildInput {
    Line(Bytes),
    Eof,
}

/// A signal for the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    Term,
    Kill,
}

/// What the child side reports. A local child sends the first five; the
/// rest are a remote link's (S8 §2; `remote::link` holds their payloads and
/// builds them). A local pump that met one would log it and change nothing.
#[derive(Debug)]
pub enum ChildEvent {
    /// One stdout line (without `\n`).
    Line(Bytes),
    /// A stdout line over the CLI's 256 MiB limit was dropped.
    TooLong(usize),
    StdoutEof,
    StderrEof,
    /// The child was reaped (`None`: waiting failed). A remote exit arrives
    /// as a status made from the shim's code or signal.
    Exit(Option<ExitStatus>),
    /// The remote spawn started (the shim's `spawned`): a pending start's
    /// first event when it succeeds.
    Started(RemoteStarted),
    /// The remote start ended before `spawned`, with its exit code and line:
    /// never `Exit(None)`.
    SpawnFailed(SpawnFailure),
    /// The remote spawn started, then its link was lost past the budget.
    Lost(LinkLoss),
    /// The remote spawn started, and the wrapper's own `detach{final}` ended
    /// the link before an exit came (0 after a host EOF, 143 after a signal).
    Detached,
    /// AuthWatch: Anthropic refused the delivered token (`how`: `retries` or
    /// `text`, as `credential_rejected` records it).
    Rejected { how: &'static str },
    /// The remote link went down (`false`) or came back (`true`): the
    /// registry row's `detached`, never an exit.
    Link(bool),
    /// A remote transport note for the wrapper's log, never its stderr.
    Note(String),
    /// S10 §B: a migration's phase A is done: the new VM is chosen, gated and holds the token.
    MoveReady(MoveReady),
    /// S10 §B: phase A failed, or its Touch ID went unanswered: the chat stays on its VM.
    MoveFailed(MoveFailure),
    /// S10 §D: the session parked (`true`) or unparked (`false`): the row says `parked`, then `active`; never an exit.
    Parked(bool),
}

impl ChildEvent {
    /// The event's kind, for logs (a `Line`'s bytes are never logged).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            ChildEvent::Line(_) => "line",
            ChildEvent::TooLong(_) => "too_long",
            ChildEvent::StdoutEof => "stdout_eof",
            ChildEvent::StderrEof => "stderr_eof",
            ChildEvent::Exit(_) => "exit",
            ChildEvent::Started(_) => "started",
            ChildEvent::SpawnFailed(_) => "spawn_failed",
            ChildEvent::Lost(_) => "lost",
            ChildEvent::Detached => "detached",
            ChildEvent::Rejected { .. } => "rejected",
            ChildEvent::Link(_) => "link",
            ChildEvent::Note(_) => "note",
            ChildEvent::MoveReady(_) => "move_ready",
            ChildEvent::MoveFailed(_) => "move_failed",
            ChildEvent::Parked(_) => "parked",
        }
    }
}

/// The pump's handle on one child: the seam S8's remote link
/// (`remote::link::LinkFactory`) reuses with a WebSocket behind it.
/// `pid` is a local child's; a remote link's is `None` (the VM's pid comes
/// with `ChildEvent::Started`).
#[derive(Debug)]
pub struct ChildLink {
    pub pid: Option<u32>,
    pub input: mpsc::Sender<ChildInput>,
    pub signal: mpsc::UnboundedSender<Sig>,
    pub events: mpsc::Receiver<ChildEvent>,
}

/// Spawn `plan` as a local child with piped stdio and start its four tasks.
/// All three pipes are taken before the waiter owns the process
/// (`Child::wait` would otherwise close stdin), and signals are delivered by
/// the waiter itself, before it has reaped the child, so a signal can never
/// reach a recycled pid.
///
/// `credential` (`local-scratch`, S7): the token goes on fd 3 — a pipe that
/// already holds it, its write end closed, with [`TOKEN_FD_VAR`]`=3` — or, for
/// [`Deliver::Env`], into the child's environment only. Either way the other
/// variable is removed after the plan's own environment is applied, so an
/// inherited empty `CLAUDE_CODE_OAUTH_TOKEN` or a stale descriptor number can
/// never shadow what was delivered.
pub fn spawn_local(plan: &ChildPlan, credential: Option<(&SetupToken, Deliver)>) -> std::io::Result<ChildLink> {
    let mut cmd = tokio::process::Command::new(&plan.program);
    cmd.args(&plan.argv).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    for (k, v) in &plan.env_set {
        cmd.env(k, v);
    }
    for k in &plan.env_remove {
        cmd.env_remove(k);
    }
    // fd delivery: the pipe holds the value before the child exists.
    let pipe = match credential {
        Some((token, Deliver::Fd)) => Some(secret_pipe(token.expose().as_bytes())?),
        _ => None,
    };
    match credential {
        Some((_, Deliver::Fd)) => {
            cmd.env(TOKEN_FD_VAR, TOKEN_FD.to_string()).env_remove(TOKEN_VAR);
        }
        Some((token, Deliver::Env)) => {
            // std keeps its own (unzeroized) copy until `cmd` is dropped below, as in the shim.
            cmd.env(TOKEN_VAR, token.expose()).env_remove(TOKEN_FD_VAR);
        }
        None => {}
    }
    if let Some(fd) = pipe.as_ref().map(|p| p.as_raw_fd()) {
        // SAFETY: the closure runs in the forked child before exec and makes
        // only async-signal-safe calls (dup2/fcntl) on an integer prepared here.
        unsafe {
            cmd.pre_exec(move || onto_fd3(fd));
        }
    }
    let spawned = cmd.spawn();
    drop(cmd);
    // The parent's read end: the child has its own on fd 3.
    drop(pipe);
    let mut child = spawned?;
    let pid = child.id();
    let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take()) else {
        return Err(std::io::Error::other("child pipes missing"));
    };
    let (in_tx, in_rx) = mpsc::channel(CHANNEL_CAP);
    let (sig_tx, sig_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::channel(CHANNEL_CAP);
    tokio::spawn(child_stdin_writer(stdin, in_rx));
    tokio::spawn(child_stdout_reader(stdout, ev_tx.clone()));
    tokio::spawn(child_stderr_copy(stderr, ev_tx.clone()));
    tokio::spawn(child_waiter(child, pid, sig_rx, ev_tx));
    Ok(ChildLink { pid, input: in_tx, signal: sig_tx, events: ev_rx })
}

/// A close-on-exec pipe already holding `value`, its write end closed: the
/// read end, for the child's fd 3 (the twin of the shim's, which this build
/// does not compile). A token is at most 4096 bytes and fits the pipe
/// buffer, so the write never waits for a reader.
fn secret_pipe(value: &[u8]) -> std::io::Result<OwnedFd> {
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `fds` is an array of two ints for pipe(2) to fill.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both fds were just created and belong to nobody else.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&read, &write] {
        // SAFETY: a valid fd we own.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    std::io::Write::write_all(&mut std::fs::File::from(write), value)?;
    Ok(read)
}

/// In the forked child: `fd` onto [`TOKEN_FD`], without close-on-exec (a
/// pipe already there only loses the flag). Async-signal-safe.
fn onto_fd3(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: plain syscalls on integers.
    let rc = unsafe {
        if fd == TOKEN_FD {
            libc::fcntl(TOKEN_FD, libc::F_SETFD, 0)
        } else {
            libc::dup2(fd, TOKEN_FD)
        }
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

async fn child_stdin_writer(mut stdin: tokio::process::ChildStdin, mut rx: mpsc::Receiver<ChildInput>) {
    while let Some(item) = rx.recv().await {
        match item {
            ChildInput::Line(line) => {
                if stdin.write_all(&line).await.is_err() {
                    break;
                }
            }
            ChildInput::Eof => break,
        }
    }
    // Dropping the handle closes the pipe: the child sees EOF.
}

async fn child_stdout_reader(mut out: tokio::process::ChildStdout, tx: mpsc::Sender<ChildEvent>) {
    let mut split = LineSplitter::with_cap(PUMP_LINE_CAP);
    let mut buf = vec![0_u8; READ_CHUNK];
    loop {
        let n = match out.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        split.push(&buf[..n]);
        while let Some(r) = split.next_line() {
            if tx.send(line_event(r)).await.is_err() {
                return;
            }
        }
    }
    if let Some(r) = split.finish() {
        let _ = tx.send(line_event(r)).await;
    }
    let _ = tx.send(ChildEvent::StdoutEof).await;
}

/// One splitter result as the child's event: a line, or a line over the cap dropped.
pub(crate) fn line_event(r: Result<Bytes, LineError>) -> ChildEvent {
    match r {
        Ok(line) => ChildEvent::Line(line),
        Err(LineError::TooLong { dropped_bytes }) => ChildEvent::TooLong(dropped_bytes),
    }
}

async fn child_stderr_copy(mut err: tokio::process::ChildStderr, tx: mpsc::Sender<ChildEvent>) {
    let mut out = tokio::io::stderr();
    let _ = tokio::io::copy(&mut err, &mut out).await;
    let _ = out.flush().await;
    let _ = tx.send(ChildEvent::StderrEof).await;
}

async fn child_waiter(mut child: tokio::process::Child, pid: Option<u32>, mut sig: mpsc::UnboundedReceiver<Sig>, tx: mpsc::Sender<ChildEvent>) {
    let status = {
        let wait = child.wait();
        tokio::pin!(wait);
        let mut sig_open = true;
        loop {
            tokio::select! {
                biased;
                st = &mut wait => break st.ok(),
                s = sig.recv(), if sig_open => match s {
                    Some(s) => send_signal(pid, s),
                    None => sig_open = false,
                },
            }
        }
    };
    let _ = tx.send(ChildEvent::Exit(status)).await;
}

fn send_signal(pid: Option<u32>, sig: Sig) {
    let Some(pid) = pid.and_then(|p| i32::try_from(p).ok()).filter(|p| *p > 0) else { return };
    let signo = match sig {
        Sig::Term => libc::SIGTERM,
        Sig::Kill => libc::SIGKILL,
    };
    // SAFETY: kill(2) with a positive pid we spawned and have not reaped yet
    // (the waiter reaps only after this select arm cannot run any more).
    unsafe {
        libc::kill(pid, signo);
    }
}

// ---- host I/O tasks ------------------------------------------------------------------------

#[derive(Debug)]
enum HostIn {
    Line(Bytes),
    TooLong(usize),
    Eof,
}

async fn host_stdin_reader(tx: mpsc::Sender<HostIn>) {
    let mut input = tokio::io::stdin();
    let mut split = LineSplitter::with_cap(PUMP_LINE_CAP);
    let mut buf = vec![0_u8; READ_CHUNK];
    loop {
        let n = match input.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        split.push(&buf[..n]);
        while let Some(r) = split.next_line() {
            let item = match r {
                Ok(line) => HostIn::Line(line),
                Err(LineError::TooLong { dropped_bytes }) => HostIn::TooLong(dropped_bytes),
            };
            if tx.send(item).await.is_err() {
                return;
            }
        }
    }
    if let Some(r) = split.finish() {
        let item = match r {
            Ok(line) => HostIn::Line(line),
            Err(LineError::TooLong { dropped_bytes }) => HostIn::TooLong(dropped_bytes),
        };
        let _ = tx.send(item).await;
    }
    let _ = tx.send(HostIn::Eof).await;
}

async fn host_stdout_writer(mut rx: mpsc::Receiver<Bytes>) {
    let mut out = tokio::io::stdout();
    while let Some(line) = rx.recv().await {
        if out.write_all(&line).await.is_err() {
            return;
        }
        if rx.is_empty() && out.flush().await.is_err() {
            return;
        }
    }
    let _ = out.flush().await;
}

async fn recv_opt<T>(rx: &mut Option<mpsc::Receiver<T>>) -> Option<Option<T>> {
    match rx {
        Some(r) => Some(r.recv().await),
        None => std::future::pending().await,
    }
}

async fn reserve_opt<T>(tx: &Option<mpsc::Sender<T>>) -> Option<mpsc::Permit<'_, T>> {
    match tx {
        Some(t) => t.reserve().await.ok(),
        None => std::future::pending().await,
    }
}

/// A signal to the wrapper, as the supervisor acts on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostSignal {
    /// SIGTERM or SIGINT (and, for a remote session, SIGHUP): close.
    Term,
    /// `registry::DROP_TRANSPORT_SIGNAL` (`session drop-transport`, T8.6).
    DropTransport,
    /// S10: `registry::MIGRATE_SIGNAL` (`session migrate`, §7.1).
    Migrate,
}

/// The wrapper's signal handlers, installed by the supervisor before the
/// first child (and so before the session's row is first written); a remote
/// session's by `run`, as soon as its runtime exists (before P0).
enum Signals {
    Os {
        term: tokio::signal::unix::Signal,
        int: tokio::signal::unix::Signal,
        /// A remote session only: a hang-up during a pending start must not
        /// leave a Touch ID dialog orphaned (S8 §3).
        hup: Option<tokio::signal::unix::Signal>,
        drop_transport: tokio::signal::unix::Signal,
        /// S10: every piped mode answers `session migrate`'s signal (its
        /// default action would end the wrapper).
        migrate: tokio::signal::unix::Signal,
    },
    /// The tests' signals.
    #[cfg(test)]
    Scripted(mpsc::UnboundedReceiver<HostSignal>),
}

impl Signals {
    /// The handlers of a pump whose child is `kind`. A remote session's
    /// SIGHUP listener is `signals::handle`'s: one ignored when the wrapper
    /// started stays ignored, as `vm exec` leaves it.
    fn install(kind: LinkKind) -> std::io::Result<Signals> {
        use tokio::signal::unix::{signal, SignalKind};
        crate::bridge::signals::note_dispositions();
        let hup = match kind {
            LinkKind::Remote => crate::bridge::signals::handle(libc::SIGHUP, SignalKind::hangup()).map_err(|e| std::io::Error::other(e.to_string()))?,
            LinkKind::Local => None,
        };
        Ok(Signals::Os {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
            hup,
            drop_transport: signal(SignalKind::from_raw(registry::DROP_TRANSPORT_SIGNAL))?,
            migrate: signal(SignalKind::from_raw(registry::MIGRATE_SIGNAL))?,
        })
    }

    /// The next signal (cancel-safe).
    async fn recv(&mut self) -> HostSignal {
        match self {
            Signals::Os { term, int, hup, drop_transport, migrate } => tokio::select! {
                biased;
                _ = term.recv() => HostSignal::Term,
                _ = int.recv() => HostSignal::Term,
                _ = async { match hup { Some(h) => h.recv().await, None => std::future::pending().await } } => HostSignal::Term,
                _ = drop_transport.recv() => HostSignal::DropTransport,
                _ = migrate.recv() => HostSignal::Migrate,
            },
            #[cfg(test)]
            Signals::Scripted(rx) => match rx.recv().await {
                Some(s) => s,
                None => std::future::pending().await,
            },
        }
    }
}

/// The supervisor's host side: the host's lines, its stdout (and the
/// writer task that drains it), the signals.
struct HostIo {
    lines: mpsc::Receiver<HostIn>,
    out: mpsc::Sender<Bytes>,
    writer: tokio::task::JoinHandle<()>,
    signals: Signals,
}

/// What woke the supervisor. The `select!` arms only touch disjoint fields
/// (its futures stay alive while an arm runs); everything else happens on
/// this value afterwards.
#[derive(Debug)]
enum Wake {
    Signal(HostSignal),
    Deadline,
    Sent,
    HostOutClosed,
    ChildInClosed,
    Child(Option<ChildEvent>),
    Host(Option<HostIn>),
}

/// The lines queued for the child, and their bytes (a pending remote start
/// reads the host until either is past its cap).
#[derive(Debug, Default)]
struct InQueue {
    items: VecDeque<ChildInput>,
    bytes: usize,
}

impl InQueue {
    fn size(item: &ChildInput) -> usize {
        match item {
            ChildInput::Line(b) => b.len(),
            ChildInput::Eof => 0,
        }
    }

    fn push_back(&mut self, item: ChildInput) {
        self.bytes += InQueue::size(&item);
        self.items.push_back(item);
    }

    fn pop_front(&mut self) -> Option<ChildInput> {
        let item = self.items.pop_front()?;
        self.bytes = self.bytes.saturating_sub(InQueue::size(&item));
        Some(item)
    }

    fn clear(&mut self) {
        self.items.clear();
        self.bytes = 0;
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

// ---- the supervisor ----------------------------------------------------------------------

/// The EOF/SIGTERM ladder in progress.
#[derive(Debug, Clone, Copy)]
struct Ladder {
    term_at: Option<Instant>,
    kill_at: Instant,
    /// Finish at this instant even if the child's exit was never observed.
    hard_stop: Instant,
    /// true: host stdin closed (a child that ends after our signal still ends with 0).
    host_initiated: bool,
    /// The ladder sent the child a signal (SIGTERM or SIGKILL).
    signalled: bool,
    killed: bool,
}

struct Pump {
    sess: Session,
    plan: ChildPlan,
    /// Where each child generation comes from (S8's seam), its kind and its close ladder.
    links: Box<dyn LinkFactory>,
    kind: LinkKind,
    timings: CloseTimings,
    knobs: PumpKnobs,
    after_init: Option<(i32, String)>,
    state: HostState,
    mirror: Writer,
    gen: u32,
    /// A remote start is pending: its link's first event has not come.
    starting: bool,
    /// How a remote link ended without an exit, what `on_child_gone` maps
    /// first: a start that ended before `Started` (its code and line), a
    /// started link lost past its budget, the wrapper's own detach.
    start_failure: Option<SpawnFailure>,
    link_loss: Option<LinkLoss>,
    detached: bool,
    /// A remote session's link is down (`ChildEvent::Link(false)`): its row says `detached`.
    link_down: bool,
    /// A respawn's replay deadline waits for the remote generation's `Started`.
    replay_at_start: bool,
    /// The remote generations' VMs and spawns (the row's `vms`, S10's `registry::VmEntry`).
    vms: Vec<registry::VmEntry>,
    /// The one `ai-env-claude:` line the wrapper ends with, printed last (a remote session's).
    final_line: Option<String>,
    /// The host's EOF (or its stdout gone) or the signal that closed the session: the census's `close_ms` counts from it.
    close_at: Option<Instant>,
    // The current child, split so the select! can borrow the parts independently.
    child_events: Option<mpsc::Receiver<ChildEvent>>,
    child_input: Option<mpsc::Sender<ChildInput>>,
    child_signal: Option<mpsc::UnboundedSender<Sig>>,
    child_pid: Option<u32>,
    spawned_at: Instant,
    child_exit: Option<Option<ExitStatus>>,
    exit_seen_at: Option<Instant>,
    stdout_eof: bool,
    stderr_eof: bool,
    held_miss: Option<Bytes>,
    retries: u32,
    /// Host EOF or SIGTERM seen: never respawn after it.
    close_requested: bool,
    /// The first session id (the scratch dir is renamed after it).
    first_session_id: Option<String>,
    /// A registry row was written at least once.
    registered: bool,
    /// The session ids whose row this wrapper wrote (a remote init may name them again).
    own_ids: Vec<String>,
    in_q: InQueue,
    out_q: VecDeque<Bytes>,
    host_open: bool,
    host_eof_at: Option<Instant>,
    host_gone: bool,
    ladder: Option<Ladder>,
    delay_until: Option<Instant>,
    replay_deadline: Option<Instant>,
    finish: Option<(i32, EndReason)>,
    /// Decided while the child still runs (the lab exit): applied once it is gone.
    finish_after_child: Option<(i32, EndReason)>,
    finish_deadline: Option<Instant>,
    lab_message: Option<String>,
    noise_done: bool,
    ignored_sigterm_row: bool,
    user_line_seen: bool,
    row: Option<SessionRow>,
    out: Outcome,
    audit_path: PathBuf,
    /// `local-scratch` (S7): the unsealed setup-token, held only until no
    /// child generation can need it ([`Pump::settle_credential`]).
    credential: Option<ChildCredential>,
    /// A `--resume`'s copy goes at this instant: [`RESUME_MISS_GRACE`] after
    /// generation 1 answered `initialize` — unless by then it reported a
    /// resume miss or exited: the copy then stays for the seed retry's
    /// respawn, which gets it, or until the session ends ([`Pump::on_deadline`]).
    credential_hold_until: Option<Instant>,
    /// The synthetic `oauth_token_refresh` probe ([`SYNTHETIC_OAUTH_KNOB`]).
    synthetic: Option<Synthetic>,
    /// S10: the last move (§A): from its start on, through its cut miss's
    /// retry; the generation it started is `gen_move`'s.
    moving: Option<Moving>,
    /// S10 (L5): a loss with no turn in flight, waiting for the next host
    /// line that is no `keep_alive` to start its move.
    waiting: Option<Pending>,
    /// S10: the last top-level `assistant` frame forwarded in the current
    /// turn, and the leaf a move cuts at: that frame's uuid once a `result`
    /// followed it (none when the turn forwarded none). A move's start drops
    /// the dead CLI's partial frame: it is cut away, never a later leaf.
    last_assistant: Option<String>,
    leaf: Option<String>,
    /// S10: the `result`s forwarded since the CLI's session id was adopted (a
    /// `/clear`'s new session counts from 0: a chat with none is fresh).
    results: u32,
    /// S10 (§6.1): the `vms` entries of the session's row as an earlier
    /// wrapper left it, kept as the prefix of this process's.
    vms_prefix: Vec<toml::Value>,
    /// S10: the current generation's start: its `vms` why (the kind that ran
    /// replaces a move's own at `Started`), the move it is, whether it
    /// forwarded a `system/init` (a moved CLI's miss comes before one).
    gen_why: String,
    gen_move: Option<MoveWhy>,
    gen_init: bool,
    /// S10: [`RESUME_MISS_GRACE`] after a moved CLI's first answer (to the
    /// replayed `initialize`): with no miss by then it resumed the session,
    /// as at its first init, whichever comes first.
    move_resumed_by: Option<Instant>,
    /// S10 §D: the session parked (`ChildEvent::Parked(true)`, no `Parked(false)` since).
    parked: bool,
    /// S10 §B: a `keep_alive` went to the parked session so a prepared
    /// migration can switch (any stdin unparks it); until its `Parked(false)`.
    unparking: bool,
    /// S10 §D: the last line forwarded either way other than a `keep_alive`
    /// (`QuietState::since`), and the last host frame's kind forwarded
    /// (`QuietState::last_host`).
    quiet_since: Instant,
    last_host: Option<&'static str>,
    /// S10 §B: the chat's migration, from its phase A to its switch's spawn.
    migration: Option<Migration>,
    /// S10 §B: no more wall migrations in this process: a phase A failed for
    /// good, or `MIGRATE_PREP_TRIES` switches fell back to the old VM.
    wall_off: bool,
    /// S10 §B: switches that fell back to the old VM.
    fallbacks: u32,
    /// S10 §2.7: generation 1 was a reopen's carry, counted in `moves` once
    /// (`Some(kind)`); a carry off a gone VM is no loss's move
    /// (`[vm].max_readdress` leaves it out).
    carried: Option<MoveKind>,
    /// S10 §B: host lines a switch held when it was called off (the old
    /// link lost meanwhile), taken as the host's next ones.
    held_host: VecDeque<Bytes>,
}

/// S10 §B: a migration as the pump runs it: what started it (the wall, or
/// `session migrate`'s request), the VM it leaves, when its phase A began,
/// where it stands.
#[derive(Debug)]
struct Migration {
    trigger: MigrateTrigger,
    from_vm: String,
    at: Instant,
    phase: MigPhase,
}

/// Where a migration stands.
#[derive(Debug)]
enum MigPhase {
    /// Phase A runs (`LinkFactory::prepare_move`).
    Preparing,
    /// Phase A ended `MoveReady`: the switch waits for a quiet point.
    Ready,
    /// The switch began at `at`: the old CLI got its EOF, and its
    /// `detach{final}` (`Sig::Kill`) is due at `detach_at`; the host's lines
    /// are held, unrecorded, until the moved generation's replay.
    Switching { at: Instant, detach_at: Option<Instant>, held: VecDeque<Bytes> },
}

/// S10: a move as the pump runs it (§A, §3.4): what it started as and the
/// kind that ran (the pipeline may make a `Respawn` a `Readdress`), when it
/// started (`move_ms`), whether it sent lines again (the census `cut`),
/// whether its cut miss's one retry ran, its `session_move_end` `done`
/// while that waits for the moved CLI to show it resumed, and the `done` it
/// wrote (a miss later than that: no second one for a retry on the same
/// VM, the values of the generation that failed for its `failed`). S10 §B:
/// a switch whose new VM never started the moved CLI fell back to the old
/// VM (`fell_back`, once per switch: the step and code of that failure, its
/// `stayed` row's, written when the fallback's generation starts).
#[derive(Debug, Clone)]
struct Moving {
    why: MoveWhy,
    ran: MoveKind,
    at: Instant,
    resent: bool,
    retried: bool,
    done: Option<MoveDoneRow>,
    written: Option<MoveDoneRow>,
    fell_back: Option<(&'static str, i32)>,
}

/// S10 (§4.2): a move's `session_move_end` `done`, its values taken at the
/// moved generation's `Started` and written once the moved CLI shows it
/// resumed: at its first init, or [`RESUME_MISS_GRACE`] after its first
/// answer (to the replayed `initialize`: a resume or cut miss comes at
/// start-up, S9's rule) with no miss by then, whichever comes first; else
/// at that generation's end with nothing failed (the host closed, the link
/// was lost again), or the wrapper's. A cut miss's retry on the same VM
/// keeps the first generation's `how`, `seed`, `transcript` and `touchid`,
/// its own `gen`, `cut` and `ms`; a miss writes `failed` in its place. A
/// miss later than the grace, still before the CLI's first init (§2.9), is
/// held all the same, after the `done`: a resume miss writes `failed` after
/// it; a cut miss's retry on that VM writes no second `done` and no second
/// note, one on another VM that VM's.
#[derive(Debug, Clone)]
struct MoveDoneRow {
    gen: u32,
    to_vm: String,
    how: Option<&'static str>,
    seed: Option<&'static str>,
    transcript: Option<&'static str>,
    cut: Option<&'static str>,
    touchid: Option<&'static str>,
    ms: u64,
}

/// S10 (L5): a lost link that moves with the next host line: the move it
/// starts, and how many of the dead CLI's requests were withdrawn.
#[derive(Debug, Clone)]
struct Pending {
    kind: MoveKind,
    cause: LossCause,
    from_vm: String,
    from_spawn: Option<crate::wire::frame::SpawnId>,
    cancelled: usize,
}

/// The census's `moves` slot of `kind`: readdress, respawn, migrate.
fn move_slot(kind: MoveKind) -> usize {
    match kind {
        MoveKind::Readdress => 0,
        MoveKind::Respawn => 1,
        MoveKind::Migrate => 2,
    }
}

/// S10 §D: a host frame's kind as `QuietState::last_host` names it (and
/// `session_unpark.by` after it): `user`, `control_response`,
/// `control_request`, `control_cancel_request`, `other`.
fn host_kind(frame: &HostFrame<'_>) -> &'static str {
    match frame {
        HostFrame::User { .. } => "user",
        HostFrame::ControlResponse { .. } => "control_response",
        HostFrame::ControlRequest { .. } => "control_request",
        HostFrame::ControlCancel { .. } => "control_cancel_request",
        HostFrame::KeepAlive | HostFrame::Other => "other",
    }
}

/// S10 §B: why a migration's phase A left the chat on its VM, as the note says it.
fn stayed_why(f: &MoveFailure) -> String {
    match f.word {
        "touchid_cancelled" => "the Touch ID was dismissed".to_string(),
        "touchid_timeout" => "no Touch ID in time".to_string(),
        "deadline" if f.step == StartStep::TouchId || f.code == 5 => "no Touch ID in time".to_string(),
        "max_concurrent" => "no VM can start: [vm].max_concurrent".to_string(),
        word => format!("preparing a new VM failed at {}: {word}", f.step.name()),
    }
}

/// The synthetic `oauth_token_refresh` the pump sends the host itself
/// ([`SYNTHETIC_OAUTH_KNOB`]): sent once, after the first success answer to
/// the host's `initialize` that reaches it, whichever generation gave it (a
/// seed retry's comes rewritten to the host's id); the answer is classified
/// and never forwarded.
#[derive(Debug)]
struct Synthetic {
    /// How long the host has to answer.
    wait: Duration,
    /// The request id, once sent: an answer to it never reaches a child,
    /// however late it comes.
    id: Option<String>,
    sent_at: Option<Instant>,
    /// The answer's class, or `none` once the wait ran out.
    class: Option<String>,
}

impl Synthetic {
    /// The probe, nothing sent yet, when [`SYNTHETIC_OAUTH_KNOB`] is set.
    fn from_knob() -> Option<Synthetic> {
        ms_knob(SYNTHETIC_OAUTH_KNOB).map(|wait| Synthetic { wait, id: None, sent_at: None, class: None })
    }

    /// When the wait runs out, while no class is decided.
    fn deadline(&self) -> Option<Instant> {
        if self.class.is_some() {
            return None;
        }
        self.sent_at.map(|t| t + self.wait)
    }

    /// The end row's class: the decided one, `none` for a request still
    /// unanswered, `unsent` when the session was never initialized.
    fn census(&self) -> String {
        self.class.clone().unwrap_or_else(|| if self.id.is_some() { "none".into() } else { "unsent".into() })
    }
}

impl Pump {
    fn new(sess: Session, plan: ChildPlan, login: Option<ScratchLogin>, links: Box<dyn LinkFactory>) -> Pump {
        let audit_path = sess.paths.audit();
        let mirror = Writer::new(plan.mirror.clone());
        let word = login.as_ref().map(ScratchLogin::word);
        let credential = match login {
            Some(ScratchLogin::Sealed(c)) => Some(c),
            _ => None,
        };
        let synthetic = Synthetic::from_knob();
        let (kind, timings) = (links.kind(), links.timings());
        Pump {
            links,
            kind,
            timings,
            knobs: lab::pump_knobs(),
            after_init: lab::exit_after_init(),
            state: HostState::new(),
            mirror,
            gen: 0,
            starting: false,
            start_failure: None,
            link_loss: None,
            detached: false,
            link_down: false,
            replay_at_start: false,
            vms: Vec::new(),
            final_line: None,
            close_at: None,
            child_events: None,
            child_input: None,
            child_signal: None,
            child_pid: None,
            spawned_at: Instant::now(),
            child_exit: None,
            exit_seen_at: None,
            stdout_eof: false,
            stderr_eof: false,
            held_miss: None,
            retries: 0,
            close_requested: false,
            first_session_id: None,
            registered: false,
            own_ids: Vec::new(),
            in_q: InQueue::default(),
            out_q: VecDeque::new(),
            host_open: true,
            host_eof_at: None,
            host_gone: false,
            ladder: None,
            delay_until: None,
            replay_deadline: None,
            finish: None,
            finish_after_child: None,
            finish_deadline: None,
            lab_message: None,
            noise_done: false,
            ignored_sigterm_row: false,
            user_line_seen: false,
            row: None,
            out: Outcome { credential: word, ..Outcome::default() },
            audit_path,
            credential,
            credential_hold_until: None,
            synthetic,
            moving: None,
            waiting: None,
            last_assistant: None,
            leaf: None,
            results: 0,
            vms_prefix: Vec::new(),
            gen_why: String::new(),
            gen_move: None,
            gen_init: false,
            move_resumed_by: None,
            parked: false,
            unparking: false,
            quiet_since: Instant::now(),
            last_host: None,
            migration: None,
            wall_off: false,
            fallbacks: 0,
            carried: None,
            held_host: VecDeque::new(),
            sess,
            plan,
        }
    }

    fn audit(&self, event: &str, detail: &[(&str, String)]) {
        let row = AuditRow::new(event, self.out.session_id.as_deref(), audit::detail(detail));
        if let Err(e) = audit::append(&self.audit_path, &row) {
            tracing::warn!("audit {event}: {e}");
        }
    }

    /// Drop (zeroize) the setup-token once no child generation can need it:
    /// right after the spawn, unless the one seed retry of a `--resume` may
    /// still respawn — until the first init, [`RESUME_MISS_GRACE`] after
    /// generation 1 answered `initialize` ([`Pump::on_deadline`]) or that
    /// respawn — and always when the session is `finishing`. `why` is logged.
    fn settle_credential(&mut self, finishing: bool, why: &str) {
        if self.credential.is_some() && (finishing || !self.retry_possible()) {
            self.drop_credential(why);
        }
    }

    /// Drop (zeroize) the setup-token now, if it is still held. A token of a
    /// shape the scrubber's rules do not mask whole is masked while its handle
    /// lives (`parse_token` registered it) and no longer: the handle's drop
    /// ends that registration, so the scrubber keeps no plain copy of it for
    /// the rest of the session (as `vm exec`'s delivery forgets its masking
    /// when it drops the value). The wrapper's own lines (its log, audit and
    /// census rows, notes) never quote the token, and the child's output
    /// passes through verbatim, never scrubbed, either way.
    fn drop_credential(&mut self, why: &str) {
        self.credential_hold_until = None;
        if self.credential.take().is_some() {
            tracing::info!(gen = self.gen, "the setup-token copy was dropped ({why})");
        }
    }

    // -- the synthetic oauth_token_refresh (lab knob) -------------------------------------

    /// Send the host the synthetic `oauth_token_refresh` (once, with the knob).
    fn send_synthetic_oauth(&mut self) {
        let Some(s) = self.synthetic.as_mut().filter(|s| s.id.is_none()) else { return };
        let Ok(request) = RawValue::from_string(r#"{"subtype":"oauth_token_refresh"}"#.to_string()) else { return };
        let id = format!("ai-env-synthetic-{}", uuid::Uuid::now_v7());
        s.id = Some(id.clone());
        s.sent_at = Some(Instant::now());
        let wait_ms = s.wait.as_millis() as u64;
        self.forward(&claude::control_request_line(&id, &request));
        tracing::info!(id = %id, wait_ms, "synthetic oauth_token_refresh sent toward the extension");
    }

    /// Is `id` the synthetic request's?
    fn is_synthetic(&self, id: &str) -> bool {
        self.synthetic.as_ref().and_then(|s| s.id.as_deref()) == Some(id)
    }

    /// The host answered the synthetic request: classify it (once) and
    /// never forward it — no child asked.
    fn on_synthetic_answer(&mut self, line: &[u8]) {
        let Some(s) = self.synthetic.as_mut() else { return };
        let ms = s.sent_at.map_or(0, |t| t.elapsed().as_millis() as u64);
        if s.class.is_some() {
            tracing::info!(ms, "synthetic oauth_token_refresh: a late answer was dropped (never forwarded)");
            return;
        }
        let class = synthetic_answer_class(line);
        s.class = Some(class.clone());
        tracing::info!(class = %class, ms, "synthetic oauth_token_refresh answered (never forwarded)");
        self.audit("synthetic_oauth", &[("class", class), ("ms", ms.to_string())]);
    }

    /// Start the next child generation (`why`: the first, or the resume
    /// miss's retry) from the link factory; `false` when the start failed
    /// (the finish is then already decided). A remote start is pending until
    /// its link's first event; its init-delay knob waits for `Started`.
    fn spawn_next(&mut self, why: StartWhy) -> bool {
        self.gen += 1;
        self.state.begin_gen(self.gen);
        // S10: what the generation is, for its `vms` entry and a moved CLI's miss; a new spawn is parked nowhere.
        self.gen_init = false;
        self.move_resumed_by = None;
        self.parked = false;
        self.unparking = false;
        (self.gen_why, self.gen_move) = match &why {
            StartWhy::First => ("first".to_string(), None),
            StartWhy::ResumeRetry { .. } => ("retry".to_string(), None),
            StartWhy::Move(m) => (m.vms_why(), Some(m.clone())),
        };
        self.child_exit = None;
        self.exit_seen_at = None;
        self.stdout_eof = false;
        self.stderr_eof = false;
        if self.gen > 1 && self.credential.is_none() && matches!(self.out.credential, Some("fd" | "env")) {
            // A resume miss later than the grace: the seed retry still runs, logged out.
            tracing::warn!(gen = self.gen, "respawned without the setup-token: the copy was already dropped");
            say(&logged_out_note("the seed retry respawned the child after the setup-token copy was dropped"));
            // The end row says how the generation that serves the session was logged in.
            self.out.credential = Some("none");
        }
        let req = StartReq { why, credential: self.credential.as_ref().map(|c| (&c.token, c.deliver)) };
        match self.links.start(self.gen, req) {
            Ok(link) => {
                tracing::info!(gen = self.gen, pid = link.pid, kind = self.kind.name(), "child spawned");
                self.child_pid = link.pid;
                self.out.child_pid = link.pid;
                self.child_events = Some(link.events);
                self.child_input = Some(link.input);
                self.child_signal = Some(link.signal);
                self.spawned_at = Instant::now();
                self.starting = self.kind == LinkKind::Remote;
                if self.gen == 1 && !self.starting {
                    self.delay_until = self.knobs.delay_init.map(|d| self.spawned_at + d);
                }
                if let Some(c) = &self.credential {
                    let detail = [
                        ("to", "local-scratch".to_string()),
                        ("gen", self.gen.to_string()),
                        ("pid", link.pid.map_or_else(|| "-".to_string(), |p| p.to_string())),
                        ("name", TOKEN_VAR.to_string()),
                        ("tag", c.tag.clone()),
                        ("source", "setup-token".to_string()),
                        ("deliver", c.word().to_string()),
                    ];
                    self.audit("credential_deliver", &detail);
                }
                self.settle_credential(false, "the child started and no retry can respawn it");
                true
            }
            Err(e) => {
                match self.kind {
                    LinkKind::Local => eprintln!("ai-env-claude: cannot spawn {}: {e}", self.plan.program.display()),
                    LinkKind::Remote => self.final_line = Some(Failure::Other { code: 1, step: StartStep::Spawn.name(), first_line: format!("the remote session could not start: {e}") }.line()),
                }
                tracing::warn!("spawn failed: {e}");
                self.child_events = None;
                self.child_input = None;
                self.child_signal = None;
                self.out.step = (self.kind == LinkKind::Remote).then_some(StartStep::Spawn.name());
                self.decide_finish(1, EndReason::SpawnFailed);
                false
            }
        }
    }

    fn signal_child(&self, sig: Sig) {
        if let Some(tx) = &self.child_signal {
            let _ = tx.send(sig);
        }
    }

    fn child_alive(&self) -> bool {
        self.child_events.is_some() && self.child_exit.is_none()
    }

    /// Decide the exit. The flush of queued lines may take up to 5 s while
    /// the host still reads and nothing asked us to close; 250 ms otherwise;
    /// never past a ladder's hard stop.
    fn decide_finish(&mut self, code: i32, end: EndReason) {
        if self.finish.is_some() {
            return;
        }
        // No child is spawned once the finish is decided.
        self.settle_credential(true, "the session is finishing");
        let now = Instant::now();
        self.finish = Some((code, end));
        let flush = if self.host_open && !self.close_requested && !self.host_gone { FLUSH_OPEN_DEADLINE } else { FLUSH_DEADLINE };
        let mut deadline = now + flush;
        if let Some(l) = &self.ladder {
            deadline = deadline.min(l.hard_stop);
        }
        self.finish_deadline = Some(deadline);
    }

    /// A close request (host EOF, SIGTERM) while finishing: flush briefly.
    fn shorten_finish(&mut self) {
        if let Some(d) = &mut self.finish_deadline {
            *d = (*d).min(Instant::now() + FLUSH_DEADLINE);
        }
    }

    fn forward(&mut self, line: &[u8]) {
        // Nobody reads a closed stdout: queueing would only stall the child side.
        if self.host_gone {
            return;
        }
        // Closing towards a host that stopped reading: keep observing the child, drop the excess.
        if self.ladder.is_some() && self.out_q.len() >= CLOSING_QUEUE_CAP {
            self.out.dropped_lines += 1;
            return;
        }
        self.out_q.push_back(encode_line(line));
    }

    /// The replay deadline (15 s, or the debug lab knob).
    fn replay_deadline_len(&self) -> Duration {
        self.knobs.replay_deadline.unwrap_or(REPLAY_DEADLINE)
    }

    // -- host → child --------------------------------------------------------------------

    fn on_host(&mut self, item: Option<HostIn>) {
        if self.finish.is_some() {
            // Finishing: host lines have nowhere to go; an EOF shortens the flush.
            if matches!(item, Some(HostIn::Eof) | None) {
                self.host_open = false;
                self.close_requested = true;
                self.shorten_finish();
            }
            return;
        }
        match item {
            Some(HostIn::Line(line)) => {
                let frame = claude::classify_host(&line);
                // The answer to the synthetic request is the pump's own: recorded, never forwarded.
                if let HostFrame::ControlResponse { request_id: Some(id) } = &frame {
                    if self.is_synthetic(id) {
                        self.on_synthetic_answer(&line);
                        return;
                    }
                }
                if let Some(Migration { phase: MigPhase::Switching { held, .. }, .. }) = self.migration.as_mut() {
                    // S10 §B: during the switch the host's lines wait, unrecorded, for the moved generation's replay; a
                    // keep_alive has no CLI to keep alive.
                    if !matches!(frame, HostFrame::KeepAlive) {
                        held.push_back(line.clone());
                    }
                    return;
                }
                if self.parked && matches!(frame, HostFrame::KeepAlive) && crate::bridge::park::DROP_HOST_KEEP_ALIVE {
                    // S10 §D (L10): a parked chat's VM is left to idle: Cursor's keep_alive never wakes it.
                    self.out.ka_dropped += 1;
                    return;
                }
                if self.waiting.is_some() {
                    // S10 (L5): the lost link's move starts with the next host line that is no keep_alive (dropped: no
                    // CLI runs); the host's late answer to a withdrawn request is dropped below, and starts nothing.
                    if matches!(frame, HostFrame::KeepAlive) {
                        tracing::debug!(gen = self.gen, "a host keep_alive while the moved chat waits for its next line: dropped");
                        return;
                    }
                    let withdrawn = matches!(&frame, HostFrame::ControlResponse { request_id: Some(id) } if self.state.child_cancelled(id));
                    if !withdrawn {
                        if let Some(pending) = self.waiting.take() {
                            self.start_move(pending, Vec::new(), true);
                        }
                    }
                }
                if let HostFrame::ControlRequest { request_id, subtype, .. } = &frame {
                    // The subtype and id only: request bodies can carry credentials.
                    tracing::debug!(subtype = subtype.as_deref().unwrap_or("-"), id = request_id.as_deref().unwrap_or("-"), "host control_request");
                }
                if self.state.on_host_frame(&frame, &line) == HostVerdict::Drop {
                    // S10: the host's answer to a CLI request withdrawn at a move: the re-run asks again.
                    tracing::info!(gen = self.gen, "a host answer to a request withdrawn at a move: dropped");
                    return;
                }
                if matches!(frame, HostFrame::User { .. }) && !self.user_line_seen {
                    self.user_line_seen = true;
                    self.maybe_register();
                }
                self.in_q.push_back(ChildInput::Line(encode_line(&line)));
                // S10 §D: the live session's park control reads the chat's quiet after each line.
                self.tell_quiet(Some(host_kind(&frame)), matches!(frame, HostFrame::KeepAlive));
            }
            Some(HostIn::TooLong(n)) => {
                self.out.dropped_lines += 1;
                tracing::warn!("host line over the CLI's 256 MiB limit dropped ({n} bytes)");
            }
            Some(HostIn::Eof) | None => self.on_host_eof(),
        }
    }

    fn on_host_eof(&mut self) {
        if !self.host_open {
            return;
        }
        self.host_open = false;
        let now = Instant::now();
        self.host_eof_at = Some(now);
        tracing::info!(ms = now.duration_since(self.spawned_at).as_millis() as u64, "host stdin EOF");
        if self.knobs.ignore_eof >= 1 {
            tracing::info!("lab: host EOF ignored");
            return;
        }
        self.close_requested = true;
        self.close_at.get_or_insert(now);
        if self.child_events.is_none() {
            self.decide_finish(0, EndReason::EofTerm);
            return;
        }
        if self.child_exit.is_some() {
            // The child already exited and is draining: its own exit decides (no respawn).
            return;
        }
        self.in_q.push_back(ChildInput::Eof);
        self.eof_ladder(now);
    }

    /// The host closed (EOF, or its stdout gone) with a child alive: the EOF
    /// ladder of the link's timings. A pending remote start is cancelled at
    /// once instead (no spawn goes out, an unseal's dialog closes), under the
    /// same hard stop.
    fn eof_ladder(&mut self, now: Instant) {
        let t = self.timings;
        if self.starting {
            self.signal_child(Sig::Term);
            self.start_ladder(None, now + t.eof_kill_after, now + t.eof_hard_stop, true, true);
        } else {
            self.start_ladder(t.eof_term_after.map(|d| now + d), now + t.eof_kill_after, now + t.eof_hard_stop, true, false);
        }
    }

    /// Start (or tighten) the ladder; `signalled`: a signal went to the child
    /// as it started (SIGTERM's at once; an EOF ladder sends none yet).
    fn start_ladder(&mut self, term_at: Option<Instant>, kill_at: Instant, hard_stop: Instant, host_initiated: bool, signalled: bool) {
        // A closing session is never held back by the init-delay knob.
        self.delay_until = None;
        match &mut self.ladder {
            Some(l) => {
                l.kill_at = l.kill_at.min(kill_at);
                l.hard_stop = l.hard_stop.min(hard_stop);
                if term_at.is_none() {
                    l.term_at = None;
                }
                l.host_initiated &= host_initiated;
                l.signalled |= signalled;
            }
            None => self.ladder = Some(Ladder { term_at, kill_at, hard_stop, host_initiated, signalled, killed: false }),
        }
    }

    fn on_sigterm(&mut self) {
        let now = Instant::now();
        if let Some(eof) = self.host_eof_at {
            self.out.eof_to_sigterm_ms = Some(now.duration_since(eof).as_millis() as u64);
        }
        tracing::info!(eof_to_sigterm_ms = self.out.eof_to_sigterm_ms, "SIGTERM");
        if self.knobs.ignore_eof >= 2 {
            if !self.ignored_sigterm_row {
                self.ignored_sigterm_row = true;
                tracing::info!("lab: SIGTERM ignored; end row written with exit null");
                let mut out = self.snapshot_outcome();
                out.code = None;
                out.end = Some(EndReason::SigTerm);
                self.write_end_row(&out);
            }
            return;
        }
        self.host_open = false;
        self.close_requested = true;
        self.close_at.get_or_insert(now);
        if self.finish.is_some() {
            self.shorten_finish();
            return;
        }
        if self.child_events.is_none() {
            self.decide_finish(143, EndReason::SigTerm);
            return;
        }
        if self.child_exit.is_some() {
            // The child already exited and is draining: its own exit decides (no respawn).
            return;
        }
        // A remote child: `Signal(Term)` plus `detach{final}`, or the pending start cancelled.
        self.signal_child(Sig::Term);
        self.start_ladder(None, now + self.timings.sigterm_kill_after, now + self.timings.sigterm_hard_stop, false, true);
    }

    /// `session drop-transport` (T8.6): the link closes its socket and
    /// reattaches (a local child is left alone).
    fn on_drop_transport(&mut self) {
        tracing::info!(gen = self.gen, kind = self.kind.name(), "drop-transport signal");
        self.links.drop_transport();
    }

    /// `session migrate` (S10 §7.1): the wrapper takes the request
    /// `state/sessions/<sid>.migrate.json` of its session (removed whatever it
    /// holds; one older than `migrate::MIGRATE_REQUEST_FRESH` goes
    /// unanswered) and moves the chat: phase A at once, whatever
    /// `migration_due` would say, the switch at its next quiet point. A
    /// request it cannot take (a migration or a move already under way, the
    /// session closing, a pinned VM, a session not remote or keeping no
    /// transcript) is answered `session_move_end` `refused`, with its nonce.
    fn on_migrate(&mut self) {
        tracing::info!(gen = self.gen, kind = self.kind.name(), "session migrate signal");
        let Some(sid) = self.out.session_id.clone().filter(|s| registry::is_uuid(s)) else {
            tracing::info!("session migrate: no session id yet: no request to take");
            return;
        };
        let request = match crate::bridge::migrate::take_request(&self.sess.paths, &sid) {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::info!(session = %sid, "session migrate: no request of this session");
                return;
            }
            Err(e) => {
                tracing::warn!(session = %sid, "session migrate: the request: {e}");
                return;
            }
        };
        if !request.fresh(crate::wire::time::unix_now()) {
            tracing::info!(session = %sid, "session migrate: a stale request removed unanswered");
            return;
        }
        let pinned = self.links.snapshot().and_then(|s| s.pinned).is_some();
        let busy = self.migration.is_some() || self.waiting.is_some() || self.starting || self.move_unconfirmed() || self.child_events.is_none();
        if self.kind != LinkKind::Remote || self.closing() || pinned || busy || self.sess.session.no_session_persistence {
            tracing::info!(session = %sid, pinned, busy, "session migrate: the request is refused");
            let from_vm = self.links.snapshot().and_then(|s| s.vm).unwrap_or_default();
            let row = crate::bridge::remote::link::MoveEndRow { session: Some(&sid), gen: self.gen, kind: Some(MoveKind::Migrate), outcome: "refused", from_vm: &from_vm, request: Some(&request.nonce), ..Default::default() };
            row.audit(&self.sess.paths);
            return;
        }
        self.start_migration(MigrateTrigger::Command { nonce: request.nonce });
    }

    /// Nothing more starts: the host closed, a signal came, the finish is decided or a ladder runs.
    fn closing(&self) -> bool {
        self.close_requested || self.host_gone || self.finish.is_some() || self.finish_after_child.is_some() || self.ladder.is_some()
    }

    // -- child → host --------------------------------------------------------------------

    fn on_child_event(&mut self, ev: Option<ChildEvent>) {
        match ev {
            Some(ChildEvent::Line(line)) => self.on_child_line(line),
            Some(ChildEvent::TooLong(n)) => {
                self.out.dropped_lines += 1;
                tracing::warn!("child line over the CLI's 256 MiB limit dropped ({n} bytes)");
            }
            Some(ChildEvent::StdoutEof) => self.stdout_eof = true,
            Some(ChildEvent::StderrEof) => self.stderr_eof = true,
            Some(ChildEvent::Exit(status)) => {
                tracing::info!(gen = self.gen, status = ?status, "child exited");
                self.child_exit = Some(status);
                self.exit_seen_at = Some(Instant::now());
            }
            // A remote link's events: no local child sends one.
            Some(ev) if self.kind == LinkKind::Local => tracing::debug!(gen = self.gen, event = ev.kind(), "a remote link's event on a local child: ignored"),
            Some(ChildEvent::Started(s)) => self.on_started(s),
            Some(ChildEvent::SpawnFailed(f)) => {
                tracing::info!(gen = self.gen, step = f.step.name(), code = f.code, cancelled = f.cancelled, "the remote start ended before the spawn ran");
                self.start_failure = Some(f);
                self.link_ended();
            }
            Some(ChildEvent::Lost(l)) => {
                tracing::warn!(gen = self.gen, code = l.code, "the remote link was lost");
                self.link_loss = Some(l);
                self.link_ended();
            }
            Some(ChildEvent::Detached) => {
                tracing::info!(gen = self.gen, "the remote spawn was detached for good");
                self.detached = true;
                self.link_ended();
            }
            Some(ChildEvent::Rejected { how }) => self.on_rejected(how),
            Some(ChildEvent::Link(up)) => self.on_link(up),
            Some(ChildEvent::Note(text)) => tracing::info!(gen = self.gen, "remote link: {text}"),
            Some(ChildEvent::MoveReady(r)) => self.on_move_ready(&r),
            Some(ChildEvent::MoveFailed(f)) => self.on_move_failed(&f),
            Some(ChildEvent::Parked(on)) => self.on_parked(on),
            None => {
                // Every task of this child ended.
                self.stdout_eof = true;
                self.stderr_eof = true;
                if self.child_exit.is_none() {
                    if self.kind == LinkKind::Remote {
                        // Fail closed: a remote link that ends without saying how is lost, never a local run.
                        tracing::warn!(gen = self.gen, starting = self.starting, "the remote link ended without its last event");
                        let vm = self.links.snapshot().and_then(|s| s.vm).unwrap_or_else(|| "the VM".to_string());
                        if self.starting {
                            self.start_failure = Some(SpawnFailure::from_failure(StartStep::Spawn, &Failure::LinkLost { vm }, None));
                        } else {
                            self.link_loss = Some(LinkLoss::from_failure(&Failure::LinkLost { vm }));
                        }
                        self.starting = false;
                    }
                    self.child_exit = Some(None);
                    self.exit_seen_at = Some(Instant::now());
                }
            }
        }
    }

    /// The remote link's last event (a failed start, a lost link, our own
    /// detach): nothing more comes from it, and `on_child_gone` maps it.
    fn link_ended(&mut self) {
        self.starting = false;
        self.stdout_eof = true;
        self.stderr_eof = true;
        if self.child_exit.is_none() {
            self.child_exit = Some(None);
            self.exit_seen_at = Some(Instant::now());
        }
    }

    /// The remote spawn runs (`spawned`): the start is no longer pending; the
    /// generation's VM and spawn go into the row's `vms`; the init-delay knob
    /// (generation 1) and a respawn's replay deadline start now.
    fn on_started(&mut self, s: RemoteStarted) {
        let now = Instant::now();
        tracing::info!(gen = self.gen, spawn = %s.spawn_id, vm_pid = s.vm_pid, ms = now.duration_since(self.spawned_at).as_millis() as u64, "the remote spawn started");
        self.starting = false;
        self.link_down = false;
        let snap = self.links.snapshot();
        let vm = snap.as_ref().and_then(|snap| snap.vm.clone()).unwrap_or_default();
        // S10 (§6.1): why it started (a move's, the kind that ran), this wrapper's pid; `end` comes with its end.
        let why = self.started_why(snap.as_ref());
        self.vms.push(registry::VmEntry { gen: self.gen, vm, spawn: Some(s.spawn_id.to_string()), from: registry::now_rfc3339(), to: None, why, end: None, pid: std::process::id() });
        if self.gen_move.is_some() {
            self.move_started(snap.as_ref());
        }
        if let Some(c) = snap.as_ref().and_then(|s| s.carried.as_ref()).filter(|_| self.gen == 1 && self.carried.is_none()) {
            // S10 §2.7: a reopen's carry counts in `moves` (once), never against `[vm].max_readdress`.
            let kind = if c.left_s.is_some() { MoveKind::Migrate } else { MoveKind::Readdress };
            self.out.moves[move_slot(kind)] += 1;
            self.carried = Some(kind);
        }
        if self.ladder.is_none() {
            if self.gen == 1 {
                self.delay_until = self.knobs.delay_init.map(|d| now + d);
            }
            if std::mem::take(&mut self.replay_at_start) && self.state.replaying() {
                self.replay_deadline = Some(now + self.replay_deadline_len());
            }
        }
        self.touch_registry();
    }

    /// The remote link went down (`false`) or came back (`true`): the row's
    /// `detached` or `active`, written when it changes; never an exit.
    fn on_link(&mut self, up: bool) {
        tracing::info!(gen = self.gen, up, "remote link");
        self.link_down = !up;
        let want = if up { "active" } else { "detached" };
        if let Some(row) = self.row.as_mut().filter(|r| r.status != want && r.status != "closed") {
            row.status = want.to_string();
            self.write_row();
        }
    }

    /// AuthWatch's verdict on the VM's claude (S7 D6): Anthropic refused the
    /// delivered setup-token. The session stops (`Signal(Term)` plus
    /// `detach{final}`) and is never started again; the wrapper exits 5 with
    /// D6's line, and the seal is recorded as refused, so no later session
    /// unseals it. The seal is the one the VM's row names (the delivered
    /// copy), else the sealed file's.
    fn on_rejected(&mut self, how: &'static str) {
        if self.finish.is_some() || self.finish_after_child.is_some() {
            return;
        }
        tracing::warn!(gen = self.gen, how, "Anthropic refused the delivered setup-token: stopping the session");
        self.final_line = Some(Failure::TokenRefused.line());
        let vm = self.links.snapshot().and_then(|s| s.vm);
        let tag = vm.as_deref().and_then(|vm| crate::bridge::vm::registry::read_row(&self.sess.paths, vm).ok().flatten()).and_then(|r| r.credential_tag).or_else(|| crate::bridge::agent::credential::seal_tag(&self.sess.paths.setup_token_env()));
        match (&vm, &tag) {
            (Some(vm), Some(tag)) => crate::bridge::agent::credential::record_rejection(&self.sess.paths, vm, tag, how),
            _ => tracing::warn!("the refusal is not recorded: no VM or no seal known"),
        }
        self.finish_after_child = Some((REJECTED_STATUS, EndReason::CredentialRejected));
        self.close_requested = true;
        self.signal_child(Sig::Term);
        let now = Instant::now();
        self.start_ladder(None, now + self.timings.sigterm_kill_after, now + REJECT_HARD_STOP, false, true);
    }

    fn on_child_line(&mut self, line: Bytes) {
        let frame = claude::classify_child(&line);
        match &frame {
            ChildFrame::Mirror { file_path, entries } => {
                // S9 (D9): a remote session without a writer (its transcript kept in S3) drops each frame and counts it.
                if self.sess.mode == Mode::Remote && !self.mirror.cfg().enabled {
                    self.out.mirror_dropped += 1;
                    tracing::debug!("mirror frame of a remote session dropped: its transcript is kept in S3");
                    return;
                }
                match self.mirror.append(file_path.as_deref(), entries) {
                    Ok(bytes) => tracing::debug!(bytes, "mirror frame appended"),
                    Err(e) => tracing::debug!(reject = ?e, "mirror frame not appended"),
                }
                return;
            }
            ChildFrame::ControlRequest { request_id, subtype } if matches!(subtype.as_deref(), Some("oauth_token_refresh" | "host_auth_token_refresh")) => {
                let sub = subtype.as_deref().unwrap_or_default().to_string();
                if let Some(id) = request_id {
                    let body = if sub == "oauth_token_refresh" { r#"{"accessToken":null}"# } else { r#"{"authToken":null}"# };
                    if let Ok(raw) = RawValue::from_string(body.to_string()) {
                        self.in_q.push_back(ChildInput::Line(encode_line(&claude::control_success_line(id, &raw))));
                    }
                }
                self.out.oauth_answered += 1;
                self.audit("oauth_refresh_answered", &[("subtype", sub.clone()), ("gen", self.gen.to_string())]);
                tracing::info!(subtype = %sub, "answered locally with a null token (never forwarded)");
                return;
            }
            _ => {}
        }
        // S10 (§2.9): a moved CLI's error result before it showed it resumed (a cut its transcript lacks, a resume it
        // does not find, any other start-up refusal) is never the host's, nor its cut or resume miss before its first
        // init however late (the grace past, its move written done): held until the child exits, then the cut miss's
        // one retry, or the move failed.
        let start_miss = self.gen_move.is_some() && !self.gen_init && (claude::is_cut_miss(&frame) || claude::is_resume_miss(&frame));
        if (start_miss || self.move_unconfirmed()) && self.held_miss.is_none() && matches!(frame, ChildFrame::Result { is_error: true, .. }) {
            tracing::info!(gen = self.gen, cut = claude::is_cut_miss(&frame), resume = claude::is_resume_miss(&frame), late = !self.move_unconfirmed(), "the moved CLI failed before it resumed; holding the result until the child exits");
            self.held_miss = Some(line.clone());
            return;
        }
        if claude::is_resume_miss(&frame) && self.retry_possible() && self.held_miss.is_none() {
            tracing::info!("resume miss reported by generation {}; holding the result until the child exits", self.gen);
            self.held_miss = Some(line.clone());
            return;
        }
        if matches!(frame, ChildFrame::Init { .. }) && !self.gen_init {
            self.gen_init = true;
            // S10: a moved CLI's first init (swallowed or not): it resumed the session, so the move is done.
            if self.gen_move.is_some() {
                self.move_resumed();
            }
        }
        if matches!(frame, ChildFrame::ControlResponse { .. }) && self.move_unconfirmed() && self.move_resumed_by.is_none() {
            // S10: a moved CLI reading its input is past its start; a miss comes within the grace after its first
            // answer (S9's rule for a resume), so with none by then the move is done, its turn or not.
            self.move_resumed_by = Some(Instant::now() + RESUME_MISS_GRACE);
        }
        // Generation 1's answer to the host's `initialize`: its latency, and the start of the token's grace.
        if let ChildFrame::ControlResponse { request_id: Some(id), .. } = &frame {
            if self.gen == 1 && self.out.init_latency_ms.is_none() && self.state.initialize_id() == Some(id.as_ref()) {
                // A remote session's runs from the census start (T0): Cursor's 60 s window covers the pipeline too.
                self.out.init_latency_ms = Some(match self.kind {
                    LinkKind::Local => self.spawned_at.elapsed().as_millis() as u64,
                    LinkKind::Remote => unix_now_ms().saturating_sub(self.sess.start_row.start),
                });
                if self.credential.is_some() {
                    // Still held: a seed retry is possible. A resume miss comes at startup, so not for long.
                    self.credential_hold_until = Some(Instant::now() + RESUME_MISS_GRACE);
                }
            }
        }
        let init_before = self.state.inits_forwarded();
        let verdict = self.state.on_child_frame(&frame, &line);
        let forwarded = !matches!(verdict, ChildVerdict::Swallow(_));
        // The session is initialized once a success answer to the host's `initialize` reaches the host, from
        // whichever generation: when generation 1 missed the resume before answering, the seed retry's answer
        // to the replayed request is the one, rewritten to the host's id.
        let initialized = match &verdict {
            ChildVerdict::Forward => self.answers_initialize(&frame),
            ChildVerdict::Rewritten(b) => self.answers_initialize(&claude::classify_child(b)),
            ChildVerdict::Swallow(_) => false,
        };
        match verdict {
            ChildVerdict::Forward if initialized => self.forward_initialize(&line),
            ChildVerdict::Rewritten(b) if initialized => self.forward_initialize(&b),
            ChildVerdict::Forward => self.forward(&line),
            ChildVerdict::Rewritten(b) => self.forward(&b),
            ChildVerdict::Swallow(why) => tracing::debug!(?why, "child frame swallowed"),
        }
        if forwarded {
            // S10 §D: the live session's park control reads the chat's quiet after each line.
            self.tell_quiet(None, matches!(frame, ChildFrame::KeepAlive));
        }
        if initialized {
            if self.kind == LinkKind::Remote && self.out.init_latency_ms.is_none() {
                // The first answer the host got, whichever generation gave it (a resume miss's retry
                // answers the replayed request under a fresh id): from T0, as generation 1's above.
                self.out.init_latency_ms = Some(unix_now_ms().saturating_sub(self.sess.start_row.start));
            }
            // Queued behind the response, so the host's handshake is complete when it arrives.
            self.send_synthetic_oauth();
        }
        match &frame {
            ChildFrame::Init { session_id, cwd } => {
                if let Some(id) = session_id.as_ref().filter(|id| self.out.session_id.as_deref() != Some(id.as_ref())) {
                    if self.may_adopt(id) {
                        if self.out.session_id.is_some() {
                            // `/clear` starts a new session in the same process: close the old row.
                            tracing::info!(session = %id, "new session id in the same process");
                            self.close_row(None);
                            self.row = None;
                            // S10: a move of the new session cuts in its own transcript, fresh until its first result.
                            self.results = 0;
                            self.leaf = None;
                            self.last_assistant = None;
                        } else {
                            tracing::info!(session = %id, cwd = ?cwd, "session id learned");
                        }
                        self.out.session_id = Some(id.to_string());
                        self.first_session_id.get_or_insert_with(|| id.to_string());
                        // A remote link's settings captures go to this session's quarantine (T8.7).
                        self.links.session_adopted(id);
                    } else {
                        // A remote CLI's output is the VM's: it never chooses which of the Mac's rows this wrapper writes.
                        self.out.init_id_refused += 1;
                        tracing::warn!(session = ?id, "the remote init named a session whose row is another's: not adopted, this session's row stays");
                    }
                }
                if init_before == 0 && self.state.inits_forwarded() == 1 {
                    self.after_first_init();
                    // The host saw an init: the seed retry, the last reason to keep the token, is over.
                    self.settle_credential(false, "the first init");
                }
                self.maybe_register();
            }
            ChildFrame::Result { .. } if forwarded => {
                // S10: the turn is over: its last top-level assistant frame is the leaf a move cuts at. A turn with
                // none (stopped before any reply) leaves none: an older leaf would cut away this turn's prompt and
                // its interruption marker, so the cut is then the view's entry just before the next turn's line.
                self.results += 1;
                self.leaf = self.last_assistant.take();
                if let Err(e) = self.mirror.sync_all() {
                    tracing::warn!("mirror fsync: {e}");
                }
                // A remote link's per-result code-out: asked for, never awaited.
                self.links.on_result();
                self.touch_registry();
                // S10 §B: the VM's wall near, a migration's phase A starts.
                self.maybe_migrate();
            }
            ChildFrame::Assistant { uuid: Some(uuid), top_level: true } if forwarded => self.last_assistant = Some(uuid.to_string()),
            _ => {}
        }
    }

    /// Forward the answer to the host's `initialize` with the wrapper's pid
    /// in it (every piped mode, S8 §4): the extension's pid is the process it
    /// spawned. A line whose pid is not found once, byte-exact, goes as it
    /// came (`pid_rewrite:failed` in the census).
    fn forward_initialize(&mut self, line: &[u8]) {
        match claude::rewrite_initialize_pid(line, std::process::id()) {
            Some((rewritten, from)) => {
                tracing::info!(from, to = std::process::id(), "the initialize answer carries the wrapper's pid");
                self.out.pid_rewrite = Some(self.out.pid_rewrite.unwrap_or("ok"));
                self.forward(&rewritten);
            }
            None => {
                tracing::warn!("the initialize answer's pid was not found once: forwarded as the CLI gave it");
                self.out.pid_rewrite = Some("failed");
                self.forward(line);
            }
        }
    }

    fn after_first_init(&mut self) {
        if self.knobs.stdout_noise && !self.noise_done {
            self.noise_done = true;
            tracing::info!("hello");
            eprintln!("ai-env-claude: hello");
        }
        if let Some((code, msg)) = self.after_init.take() {
            tracing::info!(code, "lab: exit after init");
            self.lab_message = Some(msg);
            self.host_open = false;
            self.signal_child(Sig::Term);
            let now = Instant::now();
            self.start_ladder(None, now + self.timings.sigterm_kill_after, now + self.timings.sigterm_hard_stop, false, true);
            self.finish_after_child = Some((code, EndReason::LabExit));
        }
    }

    /// Is `frame` a success answer to the host's `initialize`, under the host's own id?
    fn answers_initialize(&self, frame: &ChildFrame<'_>) -> bool {
        matches!(frame, ChildFrame::ControlResponse { request_id: Some(id), subtype: Some(s) } if s == "success" && self.state.initialize_id() == Some(id.as_ref()))
    }

    /// The resume miss's one retry is possible: a `--resume` of
    /// `local-scratch` (the scratch dir re-seeded) or of a remote session
    /// (the transcript restored into the VM from S3), generation 1, no init
    /// forwarded.
    fn retry_possible(&self) -> bool {
        matches!(self.sess.mode, Mode::LocalScratch | Mode::Remote) && self.gen == 1 && self.retries == 0 && self.plan.resume.is_some() && self.state.inits_forwarded() == 0
    }

    /// May a `system/init` naming `id` make it this session's (its registry
    /// row)? A local child's, always. A remote one's (the VM's output, which
    /// the Mac does not trust) only when no row of `id` exists, or `id` is
    /// the session's own `--resume`, or its row is one this wrapper wrote:
    /// never another session's row, whose VM, cwd and pid would become this
    /// wrapper's (and a `--resume` of it would prefer this VM). A row that
    /// cannot be read, or an id that is no uuid, is refused too.
    fn may_adopt(&self, id: &str) -> bool {
        if self.kind == LinkKind::Local || self.plan.resume.as_deref() == Some(id) || self.own_ids.iter().any(|own| own == id) {
            return true;
        }
        matches!(registry::read(&self.sess.paths, id), Ok(None))
    }

    // -- registry ------------------------------------------------------------------------

    fn maybe_register(&mut self) {
        if self.row.is_some() || !self.user_line_seen || self.sess.session.no_session_persistence {
            return;
        }
        let Some(session_id) = self.out.session_id.clone().filter(|s| registry::is_uuid(s)) else { return };
        // S10 (§6.1): an earlier wrapper's history of this session stays, the prefix of this process's entries;
        // `created` stays this wrapper's registration (`confirm_wrapper` judges a wrapper's start against it).
        self.vms_prefix = registry::read(&self.sess.paths, &session_id).ok().flatten().map(|r| r.vms).unwrap_or_default();
        let now = registry::now_rfc3339();
        let row = SessionRow {
            v: registry::REGISTRY_SCHEMA_V,
            session_id: session_id.clone(),
            slug: self.plan.slug.clone(),
            cwd: self.sess.cwd.as_ref().map(|c| c.display().to_string()),
            transcript_rel: self.plan.slug.as_ref().map(|s| format!("{s}/{session_id}.jsonl")),
            created: now.clone(),
            last_seen: now,
            status: "active".to_string(),
            mode: self.sess.mode.name().to_string(),
            route: route_label(&self.sess.route),
            ext: self.sess.start_row.ext.clone(),
            pid: std::process::id(),
            child_pid: self.child_pid,
            exit: None,
            argv_hash: registry::argv_hash(&self.sess.start_row.argv),
            respawns: self.out.respawns,
            child_config_dir: Some(self.plan.child_config_dir.display().to_string()),
            mirror_root: std::env::var_os(MIRROR_ROOT_ENV).filter(|v| !v.is_empty()).map(|v| v.to_string_lossy().into_owned()),
            scratch_dir: self.plan.scratch.as_ref().map(|p| p.display().to_string()),
            host_state: self.state.snapshot(),
            ..SessionRow::default()
        };
        self.row = Some(row);
        self.registered = true;
        if !self.own_ids.contains(&session_id) {
            self.own_ids.push(session_id);
        }
        if self.link_down {
            if let Some(row) = &mut self.row {
                row.status = "detached".to_string();
            }
        }
        self.fill_remote();
        self.write_row();
    }

    fn touch_registry(&mut self) {
        if let Some(row) = &mut self.row {
            row.last_seen = registry::now_rfc3339();
            row.host_state = self.state.snapshot();
            row.child_pid = self.child_pid;
            row.respawns = self.out.respawns;
        }
        self.fill_remote();
        self.write_row();
    }

    /// Mark the current row closed (with the exit code, when known) and write it.
    fn close_row(&mut self, exit: Option<i32>) {
        if let Some(row) = &mut self.row {
            row.status = "closed".to_string();
            row.exit = exit;
            row.last_seen = registry::now_rfc3339();
            row.host_state = self.state.snapshot();
            row.respawns = self.out.respawns;
        }
        self.fill_remote();
        self.write_row();
    }

    /// A remote session's fields of the row (plan §2.4's reserved ones),
    /// from its link: the VM, the spawn, the last stdout seq handed to the
    /// pump, the seeded head, the newest WIP ref fetched, one `vms` entry per
    /// generation (S10: after the earlier wrappers' entries, at most
    /// `registry::VMS_KEPT` in all, the oldest dropped); S9's
    /// ([`Pump::s3_fields`]).
    fn fill_remote(&mut self) {
        let Some(row) = self.row.as_mut() else { return };
        let Some(s) = self.links.snapshot() else { return };
        row.microvm_id = s.vm;
        row.spawn_id = s.spawn.as_ref().map(ToString::to_string);
        row.last_acked_seq = s.spawn.is_some().then_some(s.last_acked_seq);
        row.seeded_head = s.seeded_head;
        row.last_wip_fetch = s.last_wip_fetch;
        let own = self.vms.iter().filter_map(|v| toml::Value::try_from(v).ok());
        let mut vms: Vec<toml::Value> = self.vms_prefix.iter().cloned().chain(own).collect();
        if vms.len() > registry::VMS_KEPT {
            vms.drain(..vms.len() - registry::VMS_KEPT);
        }
        row.vms = vms;
        Self::s3_fields(row, &self.sess.paths, self.plan.slug.as_deref());
    }

    /// S9's fields of a remote session's row (§5.7): its transcript is kept
    /// in S3 (`transcript_home`); where the chat began (`origin`:
    /// `s3::manifest::origin_of`'s `vm` or `mac`, and `vm` for a chat no
    /// manifest names yet, as `origin_of` reads a row kept in S3; its
    /// `s8_mirror` is never written); the view's rel under the Mac's projects
    /// directory (`view`).
    fn s3_fields(row: &mut SessionRow, paths: &Paths, slug: Option<&str>) {
        row.transcript_home = Some("s3".to_string());
        match crate::bridge::s3::manifest::origin_of(paths, &row.session_id) {
            Some(origin @ ("vm" | "mac")) => row.origin = Some(origin.to_string()),
            Some(_) => {}
            None => row.origin = Some("vm".to_string()),
        }
        row.view = slug.map(|s| format!("{s}/{}.jsonl", row.session_id));
    }

    fn write_row(&self) {
        if let Some(row) = &self.row {
            if let Err(e) = registry::write(&self.sess.paths, row) {
                tracing::warn!("registry: {e}");
            }
        }
    }

    // -- the child's end -------------------------------------------------------------------

    /// Called once the current child is gone and drained.
    fn on_child_gone(&mut self) {
        let status = self.child_exit.flatten();
        let code = status.and_then(|s| s.code());
        let signal = status.and_then(|s| s.signal());
        self.child_events = None;
        self.child_input = None;
        self.child_signal = None;
        self.in_q.clear();
        let closing = self.close_requested || self.finish.is_some() || self.ladder.is_some();
        // S10: a moved CLI that ended on its own before it showed it resumed, with no error result held (a start-up
        // refusal on stderr alone: `--session-id`'s `is already in use`), did not resume the session either.
        let unresumed = self.move_unconfirmed()
            && self.held_miss.is_none()
            && !closing
            && !self.host_gone
            && self.link_loss.is_none()
            && self.start_failure.is_none()
            && !self.detached
            && self.finish_after_child.is_none();
        // S10 §B: the old CLI of a switch under way stopped (its exit, or the wrapper's detach): the switch goes on,
        // unless the host closed or the old link was lost meanwhile (that loss moves the chat as any loss).
        let switching = matches!(self.migration, Some(Migration { phase: MigPhase::Switching { .. }, .. }));
        let switched = switching && !closing && !self.host_gone && self.link_loss.is_none() && self.start_failure.is_none() && self.finish_after_child.is_none();
        // This generation's end, before a retry moves `gen` on (its row write closes it with it); S10: how it ended.
        let end = if unresumed {
            "failed".to_string()
        } else if switched {
            "moved".to_string()
        } else {
            self.generation_end()
        };
        if let Some(v) = self.vms.last_mut().filter(|v| v.gen == self.gen && v.to.is_none()) {
            v.to = Some(registry::now_rfc3339());
            v.end = Some(end);
        }
        if switched {
            self.detached = false;
            self.start_switch_gen();
            return;
        }
        if switching {
            if let Some(m) = self.migration.take() {
                self.migration_abandoned(&m, "the switch is off: the host closed, or the old link was lost");
                if let MigPhase::Switching { held, .. } = m.phase {
                    if !closing && !self.host_gone {
                        // Its held lines go on as the host's next ones (a loss's move waits for the next line).
                        self.held_host.extend(held);
                    }
                }
            }
        }
        if let Some(held) = self.held_miss.take() {
            if self.gen_move.is_some() {
                // S10 (§2.9): a moved CLI's miss never reaches the host: a cut miss gets its one retry on the same VM;
                // past it, a resume miss, any other start-up refusal, or the host closing meanwhile, the move failed
                // (its exit 8, or the close's).
                let frame = claude::classify_child(&held);
                let retry = claude::is_cut_miss(&frame) && code == Some(1) && !closing && self.moving.as_ref().is_some_and(|m| !m.retried);
                if retry && self.retry_cut() {
                    return;
                }
                let text = match &frame {
                    ChildFrame::Result { first_error: Some(e), .. } => e.to_string(),
                    _ => "the moved claude did not resume the session".to_string(),
                };
                let failure = self.move_failed(text);
                if !closing {
                    self.end_move_failed(&failure);
                    return;
                }
            } else {
                if code == Some(1) && self.retry_possible() && !closing && self.respawn_after_miss() {
                    return;
                }
                // No retry: the host gets the error result after all.
                let _ = self.state.on_child_frame(&claude::classify_child(&held), &held);
                self.forward(&held);
            }
        }
        if unresumed {
            let how = match (code, signal) {
                (Some(c), _) => format!("exit {c}"),
                (None, Some(s)) => format!("signal {s}"),
                (None, None) => "no exit status".to_string(),
            };
            let failure = self.move_failed(format!("the moved claude ended ({how}) before it resumed the session"));
            self.end_move_failed(&failure);
            return;
        }
        // S10: the move's one end row. A cut miss's retry whose start failed was audited `failed` by its pipeline;
        // a moved generation that ended before its CLI's init with nothing failed (the host closed, the link was lost
        // again) leaves its move done.
        if self.start_failure.is_some() && self.gen_move.is_some() {
            if let Some(m) = self.moving.as_mut() {
                m.done = None;
            }
        } else {
            self.write_move_done();
        }
        if let Some(fin) = self.finish_after_child.take() {
            self.decide_finish(fin.0, fin.1);
            return;
        }
        // A remote link's last events, ahead of the exit table (S8 §2): a start
        // that failed (its code, its line), or one the host's EOF or a signal
        // cancelled; a link lost past its budget; the wrapper's own detach.
        let host_closed = self.ladder.map_or(self.host_eof_at.is_some() || self.host_gone, |l| l.host_initiated);
        if let Some(f) = self.start_failure.take() {
            // S10 §B: a switch whose new VM never started the moved CLI falls back to the old VM (the link leaves its row
            // to the pump); one the host's EOF or a signal cancelled is given up.
            let switch = self.gen_move.as_ref().filter(|w| w.kind == MoveKind::Migrate);
            if let Some(w) = switch.filter(|w| !f.cancelled && f.vm.as_deref().is_some_and(|vm| vm != w.from_vm)) {
                tracing::info!(gen = self.gen, from = %w.from_vm, "the switch's moved claude never started on its new VM");
                if self.stay_after_failed_switch(&f, closing) {
                    return;
                }
            } else if let Some(m) = switch.and(self.moving.as_ref()).filter(|_| f.cancelled) {
                self.move_abandoned(m.why.trigger.as_ref(), &m.why.from_vm, m.at, "the switch's start was cancelled (the host closed, or a signal)");
            }
            let (exit_code, end) = match (f.cancelled, host_closed) {
                (true, true) => (0, EndReason::EofTerm),
                (true, false) => (143, EndReason::SigTerm),
                // S10: a move's start that failed (its line the move's, `Failure::Move`).
                (false, _) if self.gen_move.is_some() => (f.code, EndReason::MoveFailed),
                (false, _) => (f.code, EndReason::SpawnFailed),
            };
            if !f.cancelled {
                self.out.step = Some(f.step.name());
            }
            if let Some(m) = self.moving.as_ref().filter(|_| self.gen_move.is_some()) {
                self.out.move_ms = Some(m.at.elapsed().as_millis() as u64);
            }
            // A host that closed hears nothing; a signal or a failure ends with the line.
            if !(f.cancelled && host_closed) {
                self.final_line = f.line;
            }
            self.decide_finish(exit_code, end);
            return;
        }
        if let Some(l) = self.link_loss.take() {
            // S10 (§A): a loss that moves (L6: within `[vm].max_readdress`; 0 keeps S9's exit 8).
            if let Some(kind) = self.move_for(&l) {
                // S10 §2.7: a reopen's carry off a gone VM is counted in `moves`, but is no loss's move.
                let carried = u32::from(self.carried == Some(MoveKind::Readdress));
                let (max, done) = (self.max_readdress(), (self.out.moves[0] + self.out.moves[1]).saturating_sub(carried));
                if max > 0 && done >= max {
                    tracing::warn!(gen = self.gen, done, max, "the link was lost past [vm].max_readdress moves: no move");
                    self.final_line = Some(Failure::MovesExhausted { vm: l.vm.clone(), moves: done }.line());
                    self.decide_finish(8, EndReason::LinkLost);
                    return;
                }
                if max > 0 {
                    self.on_moving_loss(l, kind);
                    return;
                }
            }
            self.final_line = Some(l.line);
            self.decide_finish(l.code, EndReason::LinkLost);
            return;
        }
        if std::mem::take(&mut self.detached) {
            let (exit_code, end) = if host_closed { (0, EndReason::EofKill) } else { (143, EndReason::SigTerm) };
            self.decide_finish(exit_code, end);
            return;
        }
        let (exit_code, end) = match (code, signal, self.ladder) {
            // The host closed: a child that ended after our signal (whatever its code, e.g. a
            // SIGTERM handler's 143) is a clean close; one that ended on its own keeps its code.
            (Some(c), _, Some(l)) if l.host_initiated => (if l.signalled { 0 } else { c }, if l.killed { EndReason::EofKill } else { EndReason::EofTerm }),
            (Some(c), _, Some(_)) => (c, EndReason::SigTerm),
            (Some(c), _, None) => (c, if self.host_gone { EndReason::HostGone } else { EndReason::ChildExit }),
            (None, Some(_), Some(l)) if l.host_initiated => (0, if l.killed { EndReason::EofKill } else { EndReason::EofTerm }),
            (None, Some(s), Some(_)) => (128 + s, EndReason::SigTerm),
            (None, Some(s), None) => (if self.host_gone { 0 } else { 128 + s }, if self.host_gone { EndReason::HostGone } else { EndReason::ChildExit }),
            (None, None, _) => (1, EndReason::ChildExit),
        };
        self.decide_finish(exit_code, end);
    }

    /// The seed retry: re-seed the scratch dir from the Mac's transcript and
    /// spawn generation 2 with the host state replayed. `false` when there
    /// was nothing to seed from (the miss then propagates). A remote session
    /// seeds nothing here: generation 2's pipeline restores the transcript
    /// from S3 into the VM first (`StartWhy::ResumeRetry`, S9) and respawns
    /// on the same VM; its replay deadline starts at its `Started`. When
    /// generation 1's restore found nothing to restore (no manifest, no Mac
    /// copy), there is nothing for the retry either: the miss propagates, as
    /// a local one with no source does.
    fn respawn_after_miss(&mut self) -> bool {
        self.retries += 1;
        let Some(resume) = self.plan.resume.clone() else { return false };
        if self.kind == LinkKind::Remote {
            if self.links.snapshot().and_then(|s| s.transcript) == Some(TranscriptOutcome::NothingToRestore.word()) {
                tracing::warn!("resume miss for {resume}: no transcript in S3 or on this Mac to restore");
                self.audit("resume_seed_miss", &[("session_id", resume.clone()), ("reason", "nothing to restore".to_string())]);
                return false;
            }
            self.audit("resume_seed_retry", &[("session_id", resume.clone()), ("source", "s3".to_string())]);
            return self.respawn_and_replay(resume);
        }
        let detail: Vec<(&str, String)> = match seed_from_mac(&self.sess, &self.plan, &resume, true) {
            SeedOutcome::Seeded(report) => vec![
                ("session_id", resume.clone()),
                ("source", report.source.as_ref().map(|p| p.display().to_string()).unwrap_or_default()),
                ("files", (u32::from(report.copied_jsonl) + report.subtree_files).to_string()),
                ("bytes", report.bytes.to_string()),
            ],
            // The scratch dir holds a LONGER transcript than the Mac's: never
            // overwritten; the one respawn still gets its chance.
            SeedOutcome::KeptNewer(path) => vec![("session_id", resume.clone()), ("source", path.display().to_string()), ("files", "0".to_string()), ("bytes", "0".to_string()), ("kept", "scratch copy".to_string())],
            SeedOutcome::NoSource => {
                tracing::warn!("resume miss for {resume}: no local transcript to seed from");
                self.audit("resume_seed_miss", &[("session_id", resume.clone()), ("reason", "no local transcript".to_string())]);
                return false;
            }
            SeedOutcome::Failed(reason) => {
                tracing::warn!("resume miss for {resume}: seeding failed: {reason}");
                self.audit("resume_seed_failed", &[("session_id", resume.clone()), ("reason", reason)]);
                return false;
            }
        };
        self.audit("resume_seed_retry", &detail);
        self.respawn_and_replay(resume)
    }

    /// Generation 2 for the resume miss of `resume`, the host state replayed
    /// to it (`true` also when its start failed: the finish is decided). It
    /// is told whether generation 1 answered the host's `initialize` (its
    /// latency is recorded only then): while the host waits, a remote
    /// retry's start keeps Cursor's window from T0.
    fn respawn_and_replay(&mut self, resume: String) -> bool {
        let init_answered = self.out.init_latency_ms.is_some();
        if !self.spawn_next(StartWhy::ResumeRetry { session_id: resume, init_answered }) {
            return true;
        }
        self.out.respawns += 1;
        self.replay_into_new_gen(false);
        true
    }

    /// The host's state into the generation just started (a resume miss's
    /// retry, S10's move): `initialize` and the state requests under fresh
    /// ids, then every outstanding line verbatim (a move's replay sends a
    /// pending `interrupt` again, last: `HostState::replay_move`, L4); every
    /// host request no replayed one stands for failed toward the host; the
    /// replay deadline from the generation's `Started` (a remote start's) or
    /// now, an earlier generation's disarmed (S10: a move lost again within
    /// its window, a cut miss's retry); the row touched.
    fn replay_into_new_gen(&mut self, moving: bool) {
        let mut fresh = || uuid::Uuid::now_v7().to_string();
        let lines = if moving { self.state.replay_move(&mut fresh) } else { self.state.replay_lines(&mut fresh) };
        for line in lines {
            self.in_q.push_back(ChildInput::Line(encode_line(&line)));
        }
        for line in self.state.fail_in_flight() {
            self.forward(&line);
        }
        // The window just opened is this generation's: an earlier one's deadline would expire it.
        self.replay_deadline = None;
        self.replay_at_start = false;
        if self.state.replaying() {
            if self.starting {
                self.replay_at_start = true;
            } else {
                self.replay_deadline = Some(Instant::now() + self.replay_deadline_len());
            }
        }
        self.touch_registry();
    }

    // -- S10: moves (plans/s10-contracts.md §2.2, §3.4, §4) ----------------------------------

    /// How the current generation ended, its `vms` entry's `end` (§6.1):
    /// `failed` (its CLI's miss; [`Pump::on_child_gone`] says it too of a
    /// moved CLI that ended before it showed it resumed), `lost:<cause>`,
    /// `detached` (the wrapper's own detach), `close` (the session closed
    /// with it), else `exit`.
    fn generation_end(&self) -> String {
        if self.held_miss.is_some() {
            "failed".to_string()
        } else if let Some(l) = &self.link_loss {
            format!("lost:{}", l.cause.word())
        } else if self.detached {
            "detached".to_string()
        } else if self.close_requested || self.ladder.is_some() || self.host_gone {
            "close".to_string()
        } else {
            "exit".to_string()
        }
    }

    /// `[vm].max_readdress` (L6): the moves after a lost link this wrapper
    /// process makes; a session without its bridge.toml, the default.
    fn max_readdress(&self) -> u32 {
        self.sess.cfg.as_ref().map_or_else(|| crate::bridge::config::VmCfg::default().max_readdress, |c| c.vm.max_readdress)
    }

    /// The move a lost link starts, by its cause (§A): only a remote
    /// session's, nothing closing (the host's EOF, a signal, a finish or a
    /// ladder decided), its transcript kept (`--no-session-persistence`
    /// keeps S9's exit 8). A fresh chat's respawn moves as a re-address (its
    /// VM holds the dead CLI's own transcript, which `--session-id`
    /// refuses). A pinned session (`AI_ENV_BRIDGE_VM`: its VM or nothing)
    /// never re-addresses: S9's exit 8, with no note, no wait and no move;
    /// only a respawn on its VM runs.
    fn move_for(&self, l: &LinkLoss) -> Option<MoveKind> {
        let closing = self.close_requested || self.host_gone || self.finish.is_some() || self.finish_after_child.is_some() || self.ladder.is_some();
        if self.kind != LinkKind::Remote || closing || self.sess.session.no_session_persistence {
            return None;
        }
        let mut kind = l.cause.moves()?;
        if kind == MoveKind::Respawn && self.fresh_chat() && self.move_session().is_some() && !self.state.outstanding().is_empty() {
            kind = MoveKind::Readdress;
        }
        if kind == MoveKind::Readdress {
            if let Some(pin) = self.links.snapshot().and_then(|s| s.pinned) {
                tracing::warn!(gen = self.gen, vm = %pin, cause = l.cause.word(), "the pinned VM's link was lost: a pinned session never moves to another VM");
                return None;
            }
        }
        Some(kind)
    }

    /// The session id a moved CLI resumes (§2.2): the one adopted from the
    /// CLI's init (a `/clear` makes it the newest), else P0's `--resume`.
    fn move_session(&self) -> Option<String> {
        self.out.session_id.clone().or_else(|| self.plan.resume.clone())
    }

    /// A fresh chat (§2.2), per session: no `result` forwarded since its id
    /// was adopted, and not the session the CLI started with when P0 resumed
    /// or continued one (`--resume`, `--fork-session` beside it, or
    /// `--continue`: it carries an earlier conversation, which a
    /// `--session-id` start would leave behind). A `/clear`'s new session is
    /// fresh until its first result.
    fn fresh_chat(&self) -> bool {
        let carried = self.plan.resume.is_some() || self.sess.session.continue_;
        let first = self.out.session_id.is_none() || self.out.session_id == self.first_session_id;
        self.results == 0 && !(carried && first)
    }

    /// S10 L3: `text` to the host only, as an informational line (level
    /// warning, a fresh uuid v7), never to a child nor into the transcript;
    /// to the log too.
    fn note(&mut self, text: &str) {
        tracing::info!(gen = self.gen, "{text}");
        let line = claude::informational_line(text, self.out.session_id.as_deref(), &uuid::Uuid::now_v7().to_string());
        self.forward(&line);
    }

    /// The row's status (§6.1), written when it changes (never a closed row's).
    fn set_status(&mut self, want: &str) {
        if let Some(row) = self.row.as_mut().filter(|r| r.status != want && r.status != "closed") {
            row.status = want.to_string();
            self.write_row();
        }
    }

    /// A lost link that moves (§A, L4, L5): the dead CLI's open requests to
    /// the host withdrawn (`control_cancel_request` each: the extension
    /// dismisses the prompt, and a late answer is dropped); mid-turn (a line
    /// outstanding), or while the host waits for its `initialize`'s answer
    /// (Cursor sends nothing before it, and its window is T0 + 50 s), the
    /// move starts at once; with no turn in flight it waits for the next host
    /// line that is no `keep_alive` (the user is there for its Touch ID), the
    /// row `detached`, the note saying so.
    fn on_moving_loss(&mut self, l: LinkLoss, kind: MoveKind) {
        let cancels = self.state.cancel_child_requests();
        let pending = Pending { kind, cause: l.cause, from_vm: l.vm, from_spawn: l.spawn, cancelled: cancels.len() };
        let host_waits = self.state.initialize_id().is_some() && self.out.init_latency_ms.is_none();
        tracing::info!(gen = self.gen, kind = kind.word(), cause = l.cause.word(), vm = %pending.from_vm, outstanding = self.state.outstanding().len(), host_waits, "the link was lost: the chat moves");
        if !self.state.outstanding().is_empty() || host_waits {
            self.start_move(pending, cancels, false);
            return;
        }
        // L5: no turn in flight: the move waits for the next host line.
        self.set_status("detached");
        let note = match kind {
            MoveKind::Respawn => note_restart_at_next(&pending.from_vm, l.cause),
            MoveKind::Readdress | MoveKind::Migrate => note_move_at_next(&pending.from_vm, l.cause),
        };
        self.note(&note);
        for line in &cancels {
            self.forward(line);
        }
        self.waiting = Some(pending);
    }

    /// A move's start (§A, in this order): counted; the row `migrating`; the
    /// note (unless the wait said it, `noted`); the dead CLI's requests
    /// withdrawn (`cancels`); `session_move` audited; the generation started
    /// (`StartWhy::Move`: the session id the pump adopted, the outstanding
    /// lines' uuids, the leaf, whether the chat is fresh, whether the host's
    /// `initialize` was answered), then the host's state replayed into it.
    fn start_move(&mut self, p: Pending, cancels: Vec<Bytes>, noted: bool) {
        let outstanding: Vec<String> = self.state.outstanding().iter().filter_map(|l| l.uuid.clone()).collect();
        let resent = !self.state.outstanding().is_empty();
        // The dead CLI's partial reply is cut away (or never written): it is never the moved CLI's leaf.
        self.last_assistant = None;
        let why = MoveWhy {
            kind: p.kind,
            cause: Some(p.cause),
            trigger: None,
            from_vm: p.from_vm.clone(),
            from_spawn: p.from_spawn.clone(),
            session_id: self.move_session(),
            outstanding,
            leaf: self.leaf.clone(),
            fresh_chat: self.fresh_chat(),
            init_answered: self.out.init_latency_ms.is_some(),
        };
        self.out.moves[move_slot(p.kind)] += 1;
        self.set_status("migrating");
        if p.kind == MoveKind::Readdress {
            if let Some(m) = self.migration.take() {
                // S10 §B: the chat leaves the VM its migration was to leave, by this move (the link drops phase A, its
                // dialog with it, and lets the prepared VM go).
                self.migration_abandoned(&m, "the chat's VM was lost: a re-address moves it");
            }
        }
        if !noted {
            let note = match p.kind {
                MoveKind::Respawn => note_restarting(&p.from_vm, p.cause),
                MoveKind::Readdress | MoveKind::Migrate => note_moving(&p.from_vm, p.cause),
            };
            self.note(&note);
        }
        for line in &cancels {
            self.forward(line);
        }
        let detail = [
            ("session", why.session_id.clone().unwrap_or_else(|| "-".to_string())),
            ("gen", (self.gen + 1).to_string()),
            ("kind", p.kind.word().to_string()),
            ("cause", p.cause.word().to_string()),
            ("from_vm", p.from_vm.clone()),
            ("outstanding", why.outstanding.len().to_string()),
            ("cancelled", p.cancelled.to_string()),
        ];
        self.audit(audit_event::SESSION_MOVE, &detail);
        tracing::info!(gen = self.gen + 1, kind = p.kind.word(), cause = p.cause.word(), "the move starts");
        self.moving = Some(Moving { why: why.clone(), ran: p.kind, at: Instant::now(), resent, retried: false, done: None, written: None, fell_back: None });
        if !self.spawn_next(StartWhy::Move(why)) {
            return;
        }
        self.replay_into_new_gen(true);
    }

    /// The `vms` why of the generation that just started: a move's of the
    /// kind that ran (`RemoteSnapshot.moved`), generation 1's of a reopen's
    /// carry (§2.7: `migrate:reopen` off a VM near its wall, `readdress:vm_gone`
    /// off a gone one), else what it started for.
    fn started_why(&self, snap: Option<&RemoteSnapshot>) -> String {
        if let (Some(m), Some(done)) = (&self.gen_move, snap.and_then(|s| s.moved.as_ref())) {
            return MoveWhy { kind: done.kind, ..m.clone() }.vms_why();
        }
        match snap.and_then(|s| s.carried.as_ref()).filter(|_| self.gen == 1) {
            Some(c) if c.left_s.is_some() => "migrate:reopen".to_string(),
            Some(_) => "readdress:vm_gone".to_string(),
            None => self.gen_why.clone(),
        }
    }

    /// A move's generation started (§3.4, §4): the census counts the kind
    /// that ran and times the move (`move_ms`, from its start), its `cut`
    /// when it sent lines again; the row `active`. Its `session_move_end`
    /// `done` and the note that the chat goes on wait for the moved CLI to
    /// show it resumed (its first init, or the grace past its first answer:
    /// [`Pump::move_resumed`]), so a miss writes `failed` alone and a cut
    /// miss's retry one `done`: this generation's values are kept for it (a
    /// retry on the same VM keeps the first generation's `how`, `seed`,
    /// `transcript` and `touchid`). A retry after the move was written done
    /// (its cut miss later than the grace) keeps none on that VM: its CLI
    /// is past the move, so nothing more is written or said for it.
    fn move_started(&mut self, snap: Option<&RemoteSnapshot>) {
        let Some(m) = self.moving.clone() else { return };
        let done = snap.and_then(|s| s.moved.clone());
        if done.as_ref().is_some_and(|d| d.stayed) {
            self.switch_stayed(&m, snap);
            return;
        }
        let kind = done.as_ref().map_or(m.ran, |d| d.kind);
        if !m.retried && kind != m.ran {
            // The census counts the kind that ran (a respawn the pipeline made a re-address).
            self.out.moves[move_slot(m.ran)] = self.out.moves[move_slot(m.ran)].saturating_sub(1);
            self.out.moves[move_slot(kind)] += 1;
        }
        let landed = snap.and_then(|s| s.vm.as_deref());
        if let Some(mig) = self.migration.take_if(|mig| landed.is_some_and(|vm| vm != mig.from_vm)) {
            // S10 §B: the move took the chat off the VM its migration was to leave (a respawn that ran as a re-address).
            self.migration_abandoned(&mig, "a move took the chat off the VM its migration was to leave");
        }
        let ms = u64::try_from(m.at.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.out.move_ms = Some(ms);
        if m.resent {
            self.out.cut = Some(done.as_ref().map_or("none", |d| d.cut));
        }
        self.set_status("active");
        let own = MoveDoneRow {
            gen: self.gen,
            to_vm: snap.and_then(|s| s.vm.clone()).unwrap_or_default(),
            how: snap.and_then(|s| s.vm_how),
            seed: done.as_ref().map(|d| d.seed),
            transcript: snap.and_then(|s| s.transcript),
            cut: done.as_ref().map(|d| d.cut),
            touchid: done.as_ref().map(|d| d.touchid),
            ms,
        };
        if let Some(moving) = self.moving.as_mut() {
            if !m.retried {
                moving.ran = kind;
            }
            moving.done = match moving.done.take().filter(|_| m.retried) {
                // The cut miss's retry is the same move: on its VM it keeps the first generation's checkout, transcript
                // and token; on another (that VM was no longer running) that VM's, its Touch ID `asked` if either was.
                Some(first) if first.to_vm == own.to_vm => Some(MoveDoneRow { gen: own.gen, cut: own.cut, ms: own.ms, ..first }),
                Some(first) => Some(MoveDoneRow { touchid: if first.touchid == Some("asked") { first.touchid } else { own.touchid }, ..own }),
                // A cut miss later than the grace: the move is written done on this VM already (one row, one note).
                None if m.retried && moving.written.as_ref().is_some_and(|w| w.to_vm == own.to_vm) => None,
                None => Some(own),
            };
        }
    }

    /// S10 §B: a switch that fell back to a respawn on the old VM started
    /// there (`MoveDone::stayed`: its pipeline wrote `session_move_end`
    /// `stayed`, or, a fallback after the new VM never started the moved CLI
    /// ([`Pump::stay_after_failed_switch`]), it is written here, with that
    /// failure's step and code): no `done` waits for it; the move timed; the
    /// row `active`; the note that the chat stays (trying again after the
    /// next turn, or at its wall once `MIGRATE_PREP_TRIES` switches fell
    /// back; nothing more for `session migrate`, which reports itself).
    fn switch_stayed(&mut self, m: &Moving, snap: Option<&RemoteSnapshot>) {
        let ms = u64::try_from(m.at.elapsed().as_millis()).unwrap_or(u64::MAX);
        if let Some((step, code)) = m.fell_back {
            let done = snap.and_then(|s| s.moved.as_ref());
            let row = crate::bridge::remote::link::MoveEndRow {
                session: m.why.session_id.as_deref(),
                gen: self.gen,
                kind: Some(MoveKind::Migrate),
                outcome: "stayed",
                from_vm: &m.why.from_vm,
                to_vm: snap.and_then(|s| s.vm.as_deref()),
                how: snap.and_then(|s| s.vm_how),
                seed: done.map(|d| d.seed),
                cut: done.map(|d| d.cut),
                touchid: done.map(|d| d.touchid),
                ms,
                step_code: Some((step, code)),
                request: request_of(m.why.trigger.as_ref()),
                ..Default::default()
            };
            row.audit(&self.sess.paths);
        }
        self.out.move_ms = Some(ms);
        self.set_status("active");
        self.fallbacks += 1;
        self.wall_off |= self.fallbacks >= MIGRATE_PREP_TRIES;
        if let Some(moving) = self.moving.as_mut() {
            moving.done = None;
        }
        let then = match &m.why.trigger {
            Some(MigrateTrigger::Command { .. }) => StayedThen::Nothing,
            _ if self.wall_off => StayedThen::AtWall,
            _ => StayedThen::Retry,
        };
        let vm = snap.and_then(|s| s.vm.clone()).unwrap_or_else(|| m.why.from_vm.clone());
        tracing::warn!(gen = self.gen, vm = %vm, fallbacks = self.fallbacks, "the switch fell back to the old VM");
        self.note(&note_stayed(&vm, "the move to the new VM failed after the old claude stopped; it restarted here", then));
    }

    /// The current generation is a move's whose CLI has not shown yet that
    /// it resumed the session (S10): its `session_move_end` `done` waits, and
    /// a miss, a start-up error result or an end on its own fails the move.
    /// Past it, only a cut or resume miss before the CLI's first init is
    /// still held ([`Pump::on_child_line`], §2.9).
    fn move_unconfirmed(&self) -> bool {
        self.gen_move.is_some() && self.moving.as_ref().is_some_and(|m| m.done.is_some())
    }

    /// The moved CLI resumed the session (S10: its first init, or
    /// [`RESUME_MISS_GRACE`] past its first answer with no miss), so the
    /// move is done: the note that the chat goes on (L3), `session_move_end`
    /// `done` (§4.2), written once. An error result it gave before its init
    /// and held was then a turn's, no start-up refusal: the host gets it
    /// (one held after the move was written done too).
    fn move_resumed(&mut self) {
        self.move_resumed_by = None;
        if let Some(held) = self.held_miss.take() {
            let _ = self.state.on_child_frame(&claude::classify_child(&held), &held);
            self.forward(&held);
        }
        let Some(to_vm) = self.moving.as_ref().and_then(|m| m.done.as_ref()).map(|d| d.to_vm.clone()) else { return };
        self.note(&note_continues(&to_vm));
        self.write_move_done();
    }

    /// The move's `session_move_end` `done` its generation's `Started` left
    /// pending, written now (its CLI resumed, or that generation ended with
    /// nothing failed, or the wrapper did) and kept as the move's written
    /// one; nothing when none is pending.
    fn write_move_done(&mut self) {
        let Some(m) = self.moving.as_mut() else { return };
        let Some(d) = m.done.take() else { return };
        let row = crate::bridge::remote::link::MoveEndRow {
            session: m.why.session_id.as_deref(),
            gen: d.gen,
            kind: Some(m.ran),
            outcome: "done",
            from_vm: &m.why.from_vm,
            to_vm: Some(&d.to_vm),
            how: d.how,
            seed: d.seed,
            transcript: d.transcript,
            cut: d.cut,
            touchid: d.touchid,
            ms: d.ms,
            step_code: None,
            request: request_of(m.why.trigger.as_ref()),
        };
        row.audit(&self.sess.paths);
        m.written = Some(d);
    }

    /// The cut miss's one retry (§2.9): the moved generation's CLI found no
    /// message at its cut, before its init. Its VM again (the token is
    /// cached there: no Touch ID), plain `--resume` (its `MoveWhy` names no
    /// outstanding line, so its cut is `None`: `cut_before`), the host's
    /// state replayed and every outstanding line sent again. `true` once
    /// started (or its start failed: the finish is decided).
    fn retry_cut(&mut self) -> bool {
        let snap = self.links.snapshot();
        let Some(m) = self.moving.as_mut() else { return false };
        m.retried = true;
        let why = MoveWhy {
            kind: MoveKind::Respawn,
            cause: Some(LossCause::SpawnGone),
            trigger: None,
            from_vm: snap.as_ref().and_then(|s| s.vm.clone()).unwrap_or_else(|| m.why.from_vm.clone()),
            from_spawn: snap.and_then(|s| s.spawn),
            session_id: m.why.session_id.clone(),
            outstanding: Vec::new(),
            leaf: None,
            fresh_chat: false,
            init_answered: self.out.init_latency_ms.is_some(),
        };
        tracing::info!(gen = self.gen, vm = %why.from_vm, "the moved CLI missed its cut: one retry on its VM, with no cut");
        if !self.spawn_next(StartWhy::Move(why)) {
            return true;
        }
        self.replay_into_new_gen(true);
        true
    }

    /// A moved CLI that did not resume the session (§2.9: a resume miss
    /// inside a move, a cut miss past its retry, another start-up refusal,
    /// an end on its own before it showed it resumed; `text` what it said):
    /// the move failed, its failure the move's (`Failure::Move`, the inner one
    /// at the spawn, exit 8), timed (`move_ms`) and audited `session_move_end`
    /// `failed` in place of the `done` its `Started` left pending, or after
    /// the `done` written already (a miss later than the grace: the written
    /// row's values when it is this generation's). The host never gets the
    /// CLI's error result.
    fn move_failed(&mut self, text: String) -> Failure {
        let inner = Box::new(Failure::Other { code: 8, step: StartStep::Spawn.name(), first_line: text });
        let to_vm = self.links.snapshot().and_then(|s| s.vm);
        let gen = self.gen;
        let Some(m) = self.moving.as_mut() else {
            // Never: a moved generation's move is known (`start_move` sets it first). Its own `MoveWhy` then.
            let why = self.gen_move.as_ref();
            return Failure::Move { kind: why.map_or(MoveKind::Respawn, |w| w.kind), from_vm: why.map(|w| w.from_vm.clone()).or(to_vm).unwrap_or_default(), cause: why.and_then(|w| w.cause), inner };
        };
        let failure = Failure::Move { kind: m.ran, from_vm: m.why.from_vm.clone(), cause: m.why.cause, inner };
        tracing::warn!(gen = self.gen, "the moved CLI did not resume the session: the move failed");
        let ms = u64::try_from(m.at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let pending = m.done.take().or_else(|| m.written.clone().filter(|w| w.gen == gen));
        let row = crate::bridge::remote::link::MoveEndRow {
            session: m.why.session_id.as_deref(),
            gen: self.gen,
            kind: Some(m.ran),
            outcome: "failed",
            from_vm: &m.why.from_vm,
            to_vm: to_vm.as_deref(),
            how: pending.as_ref().and_then(|d| d.how),
            seed: pending.as_ref().and_then(|d| d.seed),
            transcript: pending.as_ref().and_then(|d| d.transcript),
            cut: pending.as_ref().and_then(|d| d.cut),
            touchid: pending.as_ref().and_then(|d| d.touchid),
            ms,
            step_code: Some((StartStep::Spawn.name(), failure.exit_code())),
            request: request_of(m.why.trigger.as_ref()),
        };
        row.audit(&self.sess.paths);
        self.out.move_ms = Some(ms);
        failure
    }

    /// The wrapper ends with a failed move ([`Pump::move_failed`]): its
    /// exit (8) and line, `end:move_failed` with `step:spawn`.
    fn end_move_failed(&mut self, failure: &Failure) {
        self.out.step = Some(StartStep::Spawn.name());
        self.final_line = Some(failure.line());
        self.decide_finish(failure.exit_code(), EndReason::MoveFailed);
    }

    // -- S10: parks and migrations (plans/s10-contracts.md §2.4, §3.3, §B) --------------------

    /// S10 §D: the chat's quiet after a line forwarded either way, for the
    /// live session's park control (`LinkFactory::quiet`): the verdict over
    /// the host state, since the last line other than a `keep_alive`, the
    /// last host frame's kind (`host`, a host line's; none for the CLI's).
    fn tell_quiet(&mut self, host: Option<&'static str>, keep_alive: bool) {
        if self.kind != LinkKind::Remote {
            return;
        }
        if !keep_alive {
            self.quiet_since = Instant::now();
            if host.is_some() {
                self.last_host = host;
            }
        }
        self.links.quiet(QuietState { verdict: crate::bridge::park::verdict(&self.state), since: self.quiet_since, last_host: self.last_host });
    }

    /// S10 §D: the session parked (`true`) or unparked: the row says
    /// `parked`, then `active` again; never an exit.
    fn on_parked(&mut self, on: bool) {
        tracing::info!(gen = self.gen, parked = on, "the remote session's park");
        self.parked = on;
        self.unparking &= on;
        self.set_status(if on { "parked" } else { "active" });
    }

    /// S10 §B: after a forwarded `result`, a wall migration when one is due
    /// (`LinkFactory::migration_due`), unless one runs already, wall
    /// migrations were given up in this process, the session closes, or it
    /// keeps no transcript (`--no-session-persistence`: there is nothing to
    /// resume on a new VM, as a loss's move keeps S9's exit for it).
    fn maybe_migrate(&mut self) {
        if self.kind != LinkKind::Remote || self.migration.is_some() || self.wall_off || self.closing() || self.sess.session.no_session_persistence {
            return;
        }
        if let Some(trigger) = self.links.migration_due() {
            self.start_migration(trigger);
        }
    }

    /// S10 §B: a migration's phase A starts: the note (L3), `session_move`
    /// (the live generation, its trigger, `session migrate`'s nonce), then
    /// `LinkFactory::prepare_move` (in the background: the chat goes on).
    fn start_migration(&mut self, trigger: MigrateTrigger) {
        let from_vm = self.links.snapshot().and_then(|s| s.vm).unwrap_or_default();
        tracing::info!(gen = self.gen, trigger = trigger.word(), vm = %from_vm, "a migration's phase A starts");
        self.note(&note_migrating(&from_vm, &trigger));
        let mut detail = vec![
            ("session", self.move_session().unwrap_or_else(|| "-".to_string())),
            ("gen", self.gen.to_string()),
            ("kind", MoveKind::Migrate.word().to_string()),
            ("trigger", trigger.word().to_string()),
            ("from_vm", from_vm.clone()),
            ("outstanding", self.state.outstanding().len().to_string()),
            ("cancelled", "0".to_string()),
        ];
        if let Some(nonce) = request_of(Some(&trigger)) {
            detail.push(("request", nonce.to_string()));
        }
        self.audit(audit_event::SESSION_MOVE, &detail);
        self.migration = Some(Migration { trigger: trigger.clone(), from_vm, at: Instant::now(), phase: MigPhase::Preparing });
        self.links.prepare_move(trigger);
    }

    /// S10 §B: phase A is done: the switch waits for the first quiet point.
    fn on_move_ready(&mut self, r: &MoveReady) {
        match self.migration.as_mut() {
            Some(m) if matches!(m.phase, MigPhase::Preparing) => {
                tracing::info!(gen = self.gen, to_vm = %r.to_vm, how = r.how, ms = r.ms, "a migration's VM is prepared: the switch waits for a quiet point");
                m.phase = MigPhase::Ready;
            }
            _ => tracing::info!(gen = self.gen, to_vm = %r.to_vm, "a migration's VM was prepared with no migration waiting for it: left to its hold"),
        }
    }

    /// S10 §B, M4: phase A failed: the chat stays on its VM, said (L3:
    /// trying again after the next turn for a dismissed or unanswered Touch
    /// ID; else moving at its wall, wall migrations given up in this
    /// process; nothing more for `session migrate`'s request, which reports
    /// itself) and audited `session_move_end` `stayed`.
    fn on_move_failed(&mut self, f: &MoveFailure) {
        let Some(m) = self.migration.take() else {
            tracing::info!(gen = self.gen, word = f.word, "a migration's phase A failed with no migration waiting for it");
            return;
        };
        tracing::info!(gen = self.gen, step = f.step.name(), code = f.code, word = f.word, again = f.again, "a migration's phase A failed: the chat stays on its VM");
        self.wall_off |= !f.again;
        let then = match (&m.trigger, f.again) {
            (MigrateTrigger::Command { .. }, _) => StayedThen::Nothing,
            (MigrateTrigger::Wall { .. }, true) => StayedThen::Retry,
            (MigrateTrigger::Wall { .. }, false) => StayedThen::AtWall,
        };
        self.note(&note_stayed(&m.from_vm, &stayed_why(f), then));
        let row = crate::bridge::remote::link::MoveEndRow {
            session: self.out.session_id.as_deref(),
            gen: self.gen,
            kind: Some(MoveKind::Migrate),
            outcome: "stayed",
            from_vm: &m.from_vm,
            touchid: Some("asked"),
            ms: u64::try_from(m.at.elapsed().as_millis()).unwrap_or(u64::MAX),
            step_code: Some((f.step.name(), f.code)),
            request: request_of(Some(&m.trigger)),
            ..Default::default()
        };
        row.audit(&self.sess.paths);
    }

    /// S10 §B: a migration's VM is prepared and the chat is at a quiet point.
    fn switch_due(&self) -> bool {
        matches!(self.migration, Some(Migration { phase: MigPhase::Ready, .. })) && self.quiet_point()
    }

    /// S10 §B (§2.4): a quiet point ([`Pump::settled`]), the session not
    /// parked: the switch's EOF must reach a CLI that exits at it (a session
    /// parked with no socket would close parked instead, its claude left on
    /// the old VM: [`Pump::unpark_due`] unparks it first).
    fn quiet_point(&self) -> bool {
        !self.parked && self.settled()
    }

    /// No outstanding user line, no open request either way, no replay
    /// window, no ladder; the spawn running on a link that is up, nothing
    /// queued for it, no move under way.
    fn settled(&self) -> bool {
        self.state.outstanding().is_empty()
            && self.state.pending_len() == 0
            && self.state.child_requests().is_empty()
            && !self.state.replaying()
            && !self.closing()
            && !self.starting
            && !self.link_down
            && self.child_alive()
            && self.in_q.is_empty()
            && self.waiting.is_none()
            && self.held_miss.is_none()
            && !self.move_unconfirmed()
    }

    /// S10 §B: a migration's VM is prepared and the chat is quiet but
    /// parked (an idle chat parks at `park_after`, and nothing but input
    /// unparks it): it is unparked once ([`Pump::unpark_for_switch`]).
    fn unpark_due(&self) -> bool {
        matches!(self.migration, Some(Migration { phase: MigPhase::Ready, .. })) && self.parked && !self.unparking && self.settled()
    }

    /// S10 §B, §3.3: a `keep_alive` to the parked session, which any stdin
    /// unparks (with no socket: the VM resumed, the spawn reattached; no
    /// Touch ID); the switch begins at the quiet point after its
    /// `Parked(false)`. Never recorded (no host line), and once until then.
    fn unpark_for_switch(&mut self) {
        tracing::info!(gen = self.gen, "a migration's VM is prepared while the session is parked: a keep_alive unparks it for the switch");
        self.unparking = true;
        self.in_q.push_back(ChildInput::Line(encode_line(br#"{"type":"keep_alive"}"#)));
    }

    /// S10 §B, phase B begins at a quiet point: the factory keeps the
    /// prepared VM for the next start and holds the old generation's closing
    /// suspend off (`LinkFactory::begin_switch`; `false`: its hold ended, the
    /// prepared VM released: `session_move_end` `abandoned`, and the next due
    /// migration prepares again); the move counted, the row `migrating`; EOF
    /// to the old CLI, its `detach{final}` at the remote EOF rung; the host's
    /// lines held from now ([`Pump::on_host`]).
    fn begin_switch(&mut self, now: Instant) {
        if !self.links.begin_switch() {
            if let Some(m) = self.migration.take() {
                self.migration_abandoned(&m, "its prepared VM was released (its hold ended)");
            }
            return;
        }
        let Some(m) = self.migration.as_mut() else { return };
        tracing::info!(gen = self.gen, vm = %m.from_vm, "the switch begins: the old CLI gets its EOF");
        m.phase = MigPhase::Switching { at: now, detach_at: Some(now + self.timings.eof_kill_after), held: VecDeque::new() };
        self.out.moves[move_slot(MoveKind::Migrate)] += 1;
        self.set_status("migrating");
        self.in_q.push_back(ChildInput::Eof);
    }

    /// S10 §B, §4.2: the chat's migration given up (`why`, logged), its
    /// `session_move_end` `abandoned` (with `session migrate`'s nonce): its
    /// prepared VM released at its hold's end, a loss's move took the chat
    /// off the VM it was to leave, the switch called off, or the session's end.
    fn migration_abandoned(&self, m: &Migration, why: &str) {
        self.move_abandoned(Some(&m.trigger), &m.from_vm, m.at, why);
    }

    /// [`Pump::migration_abandoned`]'s row, of a migration off `from_vm`
    /// begun `at` (its phase A's start, or its switch's).
    fn move_abandoned(&self, trigger: Option<&MigrateTrigger>, from_vm: &str, at: Instant, why: &str) {
        tracing::info!(gen = self.gen, vm = %from_vm, trigger = trigger.map_or("-", MigrateTrigger::word), "the migration is given up: {why}");
        let row = crate::bridge::remote::link::MoveEndRow {
            session: self.out.session_id.as_deref(),
            gen: self.gen,
            kind: Some(MoveKind::Migrate),
            outcome: "abandoned",
            from_vm,
            ms: u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX),
            request: request_of(trigger),
            ..Default::default()
        };
        row.audit(&self.sess.paths);
    }

    /// S10 §B: a switch whose new VM never started the moved CLI (its
    /// session refused the spawn there, or `Started` did not come by the
    /// move's deadline): the move's `session_move_end` is the pump's to
    /// write (the link leaves it). Not closing, and once per switch, the chat
    /// falls back to the old VM: the next generation is a `Migrate` start
    /// again, which finds no VM prepared and respawns on the VM the switch
    /// left (`pipeline::switch_gen`), the host's state replayed into it; its
    /// `stayed` row, with this failure's step and code, comes at its `Started`
    /// ([`Pump::switch_stayed`]). `false`: no fallback (closing, a fallback
    /// ran already): the row is `failed`, and the session ends as a failed move.
    fn stay_after_failed_switch(&mut self, f: &SpawnFailure, closing: bool) -> bool {
        let Some(m) = self.moving.as_mut() else { return false };
        if closing || self.host_gone || m.fell_back.is_some() {
            let row = crate::bridge::remote::link::MoveEndRow {
                session: m.why.session_id.as_deref(),
                gen: self.gen,
                kind: Some(MoveKind::Migrate),
                outcome: "failed",
                from_vm: &m.why.from_vm,
                to_vm: f.vm.as_deref(),
                touchid: Some("asked"),
                ms: u64::try_from(m.at.elapsed().as_millis()).unwrap_or(u64::MAX),
                step_code: Some((f.step.name(), f.code)),
                request: request_of(m.why.trigger.as_ref()),
                ..Default::default()
            };
            row.audit(&self.sess.paths);
            return false;
        }
        tracing::warn!(gen = self.gen, step = f.step.name(), code = f.code, vm = f.vm.as_deref().unwrap_or("-"), "the switch's new VM never started the moved claude: the chat falls back to the old VM");
        m.fell_back = Some((f.step.name(), f.code));
        let why = m.why.clone();
        if self.spawn_next(StartWhy::Move(why)) {
            self.replay_into_new_gen(true);
        }
        true
    }

    /// S10 §B: the switch's old CLI stopped: the moved generation starts
    /// (`StartWhy::Move`, `Migrate`: no line outstanding, so no cut), the
    /// host's state replayed into it, then the lines held during the switch
    /// (recorded now).
    fn start_switch_gen(&mut self) {
        let Some(Migration { trigger, from_vm, phase: MigPhase::Switching { at, held, .. }, .. }) = self.migration.take() else { return };
        let snap = self.links.snapshot();
        let why = MoveWhy {
            kind: MoveKind::Migrate,
            cause: None,
            trigger: Some(trigger),
            from_vm,
            from_spawn: snap.and_then(|s| s.spawn),
            session_id: self.move_session(),
            outstanding: Vec::new(),
            leaf: self.leaf.clone(),
            fresh_chat: false,
            init_answered: self.out.init_latency_ms.is_some(),
        };
        tracing::info!(gen = self.gen + 1, vm = %why.from_vm, held = held.len(), "the switch: the moved generation starts");
        self.moving = Some(Moving { why: why.clone(), ran: MoveKind::Migrate, at, resent: false, retried: false, done: None, written: None, fell_back: None });
        if !self.spawn_next(StartWhy::Move(why)) {
            return;
        }
        self.replay_into_new_gen(true);
        for line in held {
            self.on_host(Some(HostIn::Line(line)));
        }
    }

    // -- deadlines -------------------------------------------------------------------------

    fn next_deadline(&self) -> Option<Instant> {
        let mut all: Vec<Instant> = Vec::new();
        if let Some(l) = &self.ladder {
            if self.child_alive() {
                all.extend(l.term_at);
                if !l.killed {
                    all.push(l.kill_at);
                } else if self.finish.is_none() {
                    all.push(l.hard_stop);
                }
            }
        }
        all.extend(self.delay_until);
        all.extend(self.replay_deadline);
        all.extend(self.move_resumed_by);
        if let Some(Migration { phase: MigPhase::Switching { detach_at, .. }, .. }) = &self.migration {
            all.extend(detach_at.filter(|_| self.child_alive()));
        }
        all.extend(self.credential_hold_until);
        all.extend(self.synthetic.as_ref().and_then(Synthetic::deadline));
        if self.finish.is_some() {
            all.extend(self.finish_deadline);
        }
        if self.child_exit.is_some() && self.child_events.is_some() {
            all.extend(self.exit_seen_at.map(|t| t + EXIT_DRAIN));
        }
        all.into_iter().min()
    }

    fn on_deadline(&mut self, now: Instant) {
        if let Some(mut l) = self.ladder {
            if self.child_alive() {
                if l.term_at.is_some_and(|t| now >= t) {
                    l.term_at = None;
                    l.signalled = true;
                    tracing::info!("ladder: SIGTERM child");
                    self.signal_child(Sig::Term);
                }
                if !l.killed && now >= l.kill_at {
                    l.killed = true;
                    l.signalled = true;
                    tracing::info!("ladder: SIGKILL child");
                    self.signal_child(Sig::Kill);
                } else if l.killed && now >= l.hard_stop && self.finish.is_none() {
                    // Killed, yet its exit is still queued behind lines the host does not read
                    // (or a remote start that never said how it ended: a cancelled start).
                    tracing::warn!(starting = self.starting, "child killed but its exit was not observed; finishing");
                    let (code, end) = match self.finish_after_child.take() {
                        Some(f) => f,
                        None if self.starting && l.host_initiated => (0, EndReason::EofTerm),
                        None if self.starting => {
                            self.final_line = Some(Failure::Stopped.line());
                            (143, EndReason::SigTerm)
                        }
                        None if l.host_initiated => (0, EndReason::EofKill),
                        None => (143, EndReason::SigTerm),
                    };
                    self.decide_finish(code, end);
                }
            }
            self.ladder = Some(l);
        }
        if self.delay_until.is_some_and(|t| now >= t) {
            self.delay_until = None;
        }
        let detach = match self.migration.as_mut() {
            Some(Migration { phase: MigPhase::Switching { detach_at, .. }, .. }) if detach_at.is_some_and(|t| now >= t) => detach_at.take().is_some(),
            _ => false,
        };
        if detach && self.child_alive() {
            // S10 §B: the old CLI did not end at its EOF within the remote rung: `detach{final}` (the shim's ladder ends it).
            tracing::info!(gen = self.gen, "the switch: the old CLI did not exit at its EOF in time: detach{{final}}");
            self.signal_child(Sig::Kill);
        }
        if self.move_resumed_by.is_some_and(|t| now >= t) {
            self.move_resumed_by = None;
            // S10: no miss within the grace after the moved CLI's first answer: it resumed the session. A miss held,
            // or a child gone, is the child's end's to decide.
            if self.held_miss.is_none() && self.child_exit.is_none() {
                self.move_resumed();
            }
        }
        if self.credential_hold_until.is_some_and(|t| now >= t) {
            self.credential_hold_until = None;
            // A miss already held, or a child already gone, settles at the respawn or the finish.
            if self.held_miss.is_none() && self.child_exit.is_none() {
                self.drop_credential("no resume miss within the grace after initialize");
            }
        }
        if let Some(s) = self.synthetic.as_mut().filter(|s| s.deadline().is_some_and(|t| now >= t)) {
            // The id stays known: a later answer is still never forwarded.
            s.class = Some("none".into());
            let wait_ms = s.wait.as_millis() as u64;
            tracing::info!(wait_ms, "synthetic oauth_token_refresh: no answer within the wait");
            self.audit("synthetic_oauth", &[("class", "none".to_string()), ("ms", wait_ms.to_string())]);
        }
        if self.replay_deadline.is_some_and(|t| now >= t) {
            self.replay_deadline = None;
            if self.state.replaying() {
                let errors = self.state.replay_expired();
                tracing::warn!("respawned child did not answer the replay within {:?}", self.replay_deadline_len());
                self.audit("replay_timeout", &[("failed", errors.len().to_string()), ("gen", self.gen.to_string())]);
                for e in errors {
                    self.forward(&e);
                }
            }
        }
    }

    /// The child is gone for good once it exited and its output drained (or
    /// the drain window closed).
    fn child_done(&self, now: Instant) -> bool {
        self.child_events.is_some()
            && self.child_exit.is_some()
            && ((self.stdout_eof && self.stderr_eof) || self.exit_seen_at.is_some_and(|t| now >= t + EXIT_DRAIN))
    }

    fn snapshot_outcome(&self) -> Outcome {
        let mut out = self.out.clone();
        out.mirror_frames = self.mirror.appended_frames;
        out.mirror_rejected = self.mirror.rejected;
        out.synthetic_oauth = self.synthetic.as_ref().map(Synthetic::census);
        if let Some(snap) = self.links.snapshot() {
            // A remote session's S7 `credential:` part: where its token came from.
            out.credential = snap.credential;
            out.remote = snap.census_parts();
        }
        if self.kind == LinkKind::Remote {
            // S10: what the swallow rules did, the census's `inits` and `echoes`.
            out.dups = Some(self.state.counts());
        }
        out
    }

    fn write_end_row(&self, out: &Outcome) {
        let row = end_row(&self.sess.start_row, out, unix_now_ms());
        if let Err(e) = census::record(&self.sess.paths.census(), &row) {
            match self.kind {
                LinkKind::Local => eprintln!("ai-env-claude: census: {e}"),
                // A remote session's stderr ends with its one line: the log has this.
                LinkKind::Remote => voice::warn(&format!("census: {e}")),
            }
        }
    }

    /// The loop over this process's stdio and signals (`supervise_with`):
    /// the host's stdin reader and stdout writer tasks, then the handlers of
    /// SIGTERM, SIGINT, the drop-transport signal and, for a remote session,
    /// SIGHUP, all before the first child (and so before the session's row
    /// is first written). `early`: the handlers `run` installed already (a
    /// remote session's, before P0). With them the loop first waits one turn
    /// of the runtime's driver, which reads the signals: the current-thread
    /// runtime would otherwise poll the loop and generation 1's task before
    /// that turn. So a signal that came during P0 is the loop's first wake,
    /// and generation 1's pending start never runs (no countdown, no `age`,
    /// no WIP snapshot).
    async fn supervise(&mut self, early: Option<std::io::Result<Signals>>) -> i32 {
        let yield_first = early.is_some();
        let (host_tx, host_rx) = mpsc::channel::<HostIn>(CHANNEL_CAP);
        let (out_tx, out_rx) = mpsc::channel::<Bytes>(CHANNEL_CAP);
        tokio::spawn(host_stdin_reader(host_tx));
        let writer = tokio::spawn(host_stdout_writer(out_rx));
        let signals = match early.unwrap_or_else(|| Signals::install(self.kind)) {
            Ok(s) => s,
            Err(e) => {
                match self.kind {
                    LinkKind::Local => eprintln!("ai-env-claude: cannot install signal handlers: {e}"),
                    LinkKind::Remote => self.final_line = Some(Failure::Other { code: 1, step: StartStep::Precheck.name(), first_line: format!("cannot install signal handlers: {e}") }.line()),
                }
                return 1;
            }
        };
        if yield_first {
            // `yield_now` wakes this only after the driver's next turn: a signal from P0 is in `signals` by then.
            tokio::task::yield_now().await;
        }
        self.supervise_with(HostIo { lines: host_rx, out: out_tx, writer, signals }).await
    }

    /// The loop. Returns the exit code once the finish is decided and the
    /// queued lines reached the host (or the flush deadline passed).
    async fn supervise_with(&mut self, io: HostIo) -> i32 {
        let HostIo { lines: mut host_rx, out: out_tx, writer, mut signals } = io;
        let out_tx = Some(out_tx);
        self.spawn_next(StartWhy::First);
        loop {
            let now = Instant::now();
            if self.child_done(now) {
                self.on_child_gone();
                continue;
            }
            // S10 §B: a migration's switch begins at the first quiet point once its VM is prepared (a parked session
            // unparked for it first); the lines a switch held when it was called off are the host's next.
            if self.switch_due() {
                self.begin_switch(now);
            } else if self.unpark_due() {
                self.unpark_for_switch();
            }
            if let Some(line) = self.held_host.pop_front() {
                self.on_host(Some(HostIn::Line(line)));
                continue;
            }
            if let Some((code, _)) = self.finish {
                let flushed = self.out_q.is_empty();
                if flushed || self.finish_deadline.is_some_and(|t| now >= t) {
                    drop(out_tx);
                    let remaining = self.finish_deadline.map_or(FLUSH_DEADLINE, |t| t.saturating_duration_since(Instant::now()));
                    if !remaining.is_zero() {
                        let _ = tokio::time::timeout(remaining, writer).await;
                    }
                    return code;
                }
            }
            let deadline = self.next_deadline().unwrap_or_else(|| now + Duration::from_secs(3600));
            // After the child's exit its remaining output is bounded (pipe + channel): drain it eagerly.
            // While closing, keep reading too (the excess is dropped in `forward`): the exit must be seen.
            let read_child = self.child_events.is_some() && (self.out_q.len() < 2 || self.child_exit.is_some() || self.ladder.is_some()) && self.delay_until.is_none();
            // Host lines during a replay queue behind the replayed ones (the CLI takes user
            // lines before it has answered initialize); an EOF is acted on at once. While
            // finishing, host lines are read only to notice an EOF. A pending remote start
            // takes no input yet: the host is still read up to its caps, so its EOF is seen.
            // The caps count `in_q` alone (the line that crosses the bytes' cap stays whole),
            // beside the link's CHANNEL_CAP slots, which the queue fills first (TIMING-4).
            let starting_room = self.starting && self.in_q.len() < PENDING_IN_LINES && self.in_q.bytes < PENDING_IN_BYTES;
            // S10 (L5): a lost link's move waits for the next host line: the host is read with no child.
            let read_host = self.host_open && (self.finish.is_some() || self.waiting.is_some() || (self.child_input.is_some() && (self.in_q.len() < 2 || starting_room)));
            let write_out = !self.out_q.is_empty() && !self.host_gone;
            let write_in = !self.in_q.is_empty() && self.child_input.is_some();
            let wake = tokio::select! {
                biased;
                s = signals.recv() => Wake::Signal(s),
                () = tokio::time::sleep_until(deadline) => Wake::Deadline,
                permit = reserve_opt(&out_tx), if write_out => match permit {
                    Some(p) => {
                        if let Some(line) = self.out_q.pop_front() {
                            p.send(line);
                        }
                        Wake::Sent
                    }
                    None => Wake::HostOutClosed,
                },
                permit = reserve_opt(&self.child_input), if write_in => match permit {
                    Some(p) => {
                        if let Some(item) = self.in_q.pop_front() {
                            p.send(item);
                        }
                        Wake::Sent
                    }
                    None => Wake::ChildInClosed,
                },
                ev = recv_opt(&mut self.child_events), if read_child => Wake::Child(ev.flatten()),
                item = host_rx.recv(), if read_host => Wake::Host(item),
            };
            match wake {
                Wake::Signal(HostSignal::Term) => self.on_sigterm(),
                Wake::Signal(HostSignal::DropTransport) => self.on_drop_transport(),
                Wake::Signal(HostSignal::Migrate) => self.on_migrate(),
                Wake::Deadline => self.on_deadline(Instant::now()),
                Wake::Sent => {}
                Wake::HostOutClosed => {
                    tracing::info!("host stdout closed");
                    self.host_gone = true;
                    self.out_q.clear();
                    self.on_host_gone();
                }
                Wake::ChildInClosed => {
                    // The child's stdin is closed (it exited or stopped reading): drop the rest.
                    self.in_q.clear();
                    self.child_input = None;
                }
                Wake::Child(ev) => self.on_child_event(ev),
                Wake::Host(item) => self.on_host(item),
            }
        }
    }

    fn on_host_gone(&mut self) {
        self.host_open = false;
        let now = Instant::now();
        self.close_at.get_or_insert(now);
        if self.child_alive() {
            self.close_requested = true;
            self.in_q.push_back(ChildInput::Eof);
            self.eof_ladder(now);
        } else {
            self.close_requested = true;
            self.decide_finish(0, EndReason::HostGone);
            self.shorten_finish();
        }
    }

    /// After the supervisor: the token dropped, the mirror fsync'ed, the
    /// scratch dir settled, every generation's `vms` entry ended, the
    /// registry row closed and the census end row written (with `code`); the
    /// outcome recorded.
    fn conclude(&mut self, code: i32) -> Outcome {
        // `process::exit` runs no destructor: the token, if one is still held, is zeroized here.
        self.settle_credential(true, "the session ended");
        if let Err(e) = self.mirror.sync_all() {
            tracing::warn!("mirror fsync: {e}");
        }
        let mut out = self.snapshot_outcome();
        out.code = Some(code);
        out.end = self.finish.map(|f| f.1);
        out.close_ms = self.close_at.map(|t| t.elapsed().as_millis() as u64);
        let scratch = finish_scratch(&self.plan, self.registered, self.first_session_id.as_deref());
        if let (Some(row), Some(dir)) = (&mut self.row, &scratch) {
            row.scratch_dir = Some(dir.display().to_string());
        }
        // A generation whose exit never came (the hard stop with its link down) ends with the wrapper.
        let now = registry::now_rfc3339();
        for v in self.vms.iter_mut().filter(|v| v.to.is_none()) {
            v.to = Some(now.clone());
            v.end.get_or_insert_with(|| "close".to_string());
        }
        // S10: so does a move whose CLI never reached its init: nothing failed, so it was done.
        self.write_move_done();
        if let Some(m) = self.migration.take() {
            // S10 §B: a migration still preparing, prepared and never switched to, or switching, ends with the session
            // (its phase A dropped and its prepared VM released by the link's close).
            self.migration_abandoned(&m, "the session ends");
        }
        self.close_row(Some(code));
        if !self.ignored_sigterm_row {
            self.write_end_row(&out);
        }
        self.audit_remote_end(&out);
        tracing::info!(code, end = out.end.map_or("unknown", EndReason::name), "pump done");
        out
    }

    /// `session_remote_end` (C6), after the end row, once a remote spawn ran
    /// (a start that never did is `session_remote_failed`'s): the VM, the
    /// spawn and its last stdout seq handed over (the row's), the
    /// generation, the exit, how it closed. Ids and numbers only.
    fn audit_remote_end(&self, out: &Outcome) {
        if self.vms.is_empty() {
            return;
        }
        let Some(snap) = self.links.snapshot() else { return };
        let or_dash = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());
        let detail = [
            ("vm", or_dash(snap.vm)),
            ("spawn", or_dash(snap.spawn.map(|s| s.to_string()))),
            ("gen", self.gen.to_string()),
            ("exit", or_dash(out.code.map(|c| c.to_string()))),
            ("end", out.end.map_or("unknown", EndReason::name).to_string()),
            ("close_ms", or_dash(out.close_ms.map(|ms| ms.to_string()))),
            ("last_acked_seq", snap.last_acked_seq.to_string()),
        ];
        self.audit(audit_event::SESSION_REMOTE_END, &detail);
    }

    /// What is left of the hard stop, from now: the ladder's, else the one
    /// of the close request (the host's EOF or its stdout gone, or a signal)
    /// that came after the CLI had ended, else a remote EOF ladder's from
    /// now. The remote link's close budget.
    fn close_budget(&self) -> Duration {
        let hard_stop = if self.host_eof_at.is_some() || self.host_gone { self.timings.eof_hard_stop } else { self.timings.sigterm_hard_stop };
        let until = self.ladder.map(|l| l.hard_stop).or_else(|| self.close_at.map(|t| t + hard_stop)).unwrap_or_else(|| Instant::now() + self.timings.eof_hard_stop);
        until.saturating_duration_since(Instant::now())
    }

    /// A remote session lets its link go before the close: its adapter then
    /// stops waiting on the pump (its stdin ends, a running spawn is detached).
    fn release_link(&mut self) {
        self.child_events = None;
        self.child_input = None;
        self.child_signal = None;
    }
}

/// What seeding the scratch config dir from the Mac's transcript did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedOutcome {
    /// Copied (the first candidate directory that had the transcript).
    Seeded(seed::SeedReport),
    /// The scratch copy was kept (never truncated — the scratch child may hold
    /// entries a mirror gap kept from the Mac copy).
    KeptNewer(PathBuf),
    /// No candidate directory holds `<uuid>.jsonl`.
    NoSource,
    /// Seeding failed (too large, unreadable, …).
    Failed(String),
}

/// Copy the Mac's transcript for `resume` into the plan's scratch config dir
/// (`local-scratch`): the first candidate directory that seeds wins. A
/// scratch copy longer than the Mac's is never overwritten; before the spawn
/// (`retry` false) an equally long one is kept too, while the seed retry
/// re-copies it (the child just reported it missing).
fn seed_from_mac(sess: &Session, plan: &ChildPlan, resume: &str, retry: bool) -> SeedOutcome {
    let (Some(scratch), Some(dst_slug), Some(mac)) = (plan.scratch.as_ref(), plan.slug.as_deref(), mirror::mac_config_dir()) else {
        return SeedOutcome::NoSource;
    };
    let mac_projects = mac.join("projects");
    let dst_projects = scratch.join("projects");
    let cwd_slug = sess.cwd.as_deref().and_then(|c| slug::project_dir_name(c).ok());
    let registry_slug = registry::read(&sess.paths, resume).ok().flatten().and_then(|r| r.slug);
    let slugs: Vec<&str> = cwd_slug.iter().chain(registry_slug.iter()).map(String::as_str).collect();
    let dst_file = dst_projects.join(dst_slug).join(format!("{resume}.jsonl"));
    let dst_len = std::fs::symlink_metadata(&dst_file).ok().filter(|m| m.file_type().is_file()).map(|m| m.len());
    let mut failure = None;
    for dir in seed::candidates(&mac_projects, &slugs, resume) {
        let src_len = std::fs::symlink_metadata(dir.join(format!("{resume}.jsonl"))).map(|m| m.len()).unwrap_or(0);
        if dst_len.is_some_and(|d| d > src_len || (d == src_len && !retry)) {
            tracing::info!(source = %dir.display(), "scratch transcript kept: it is at least as long as the Mac copy");
            return SeedOutcome::KeptNewer(dst_file);
        }
        match seed::seed_local(&dir, resume, &dst_projects, dst_slug) {
            Ok(report) if report.copied_jsonl => {
                tracing::info!(source = %dir.display(), files = report.subtree_files, bytes = report.bytes, "seeded the scratch config dir");
                return SeedOutcome::Seeded(report);
            }
            Ok(_) => tracing::debug!(source = %dir.display(), "candidate had no transcript"),
            Err(e) => {
                tracing::warn!(source = %dir.display(), "seed failed: {e}");
                failure = Some(e.to_string());
            }
        }
    }
    failure.map_or(SeedOutcome::NoSource, SeedOutcome::Failed)
}

/// A new `local-scratch` session's scratch dir is named by a fresh id (the
/// session id is only known after the spawn). Once the child is gone, rename
/// it to the session id, so `ai-env session forget <uuid>` finds it and a
/// later `--resume=<uuid>` reuses it. Never replaces an existing directory.
fn rename_scratch(plan: &ChildPlan, session_id: Option<&str>) -> Option<PathBuf> {
    let from = plan.scratch.as_ref()?;
    let id = session_id.filter(|s| registry::is_uuid(s))?;
    if from.file_name().is_some_and(|n| n == id) {
        return None;
    }
    let to = from.parent()?.join(id);
    if std::fs::symlink_metadata(&to).is_ok() {
        tracing::info!("scratch dir {} kept: {} exists", from.display(), to.display());
        return None;
    }
    match std::fs::rename(from, &to) {
        Ok(()) => {
            tracing::info!("scratch dir renamed to {}", to.display());
            Some(to)
        }
        Err(e) => {
            tracing::warn!("scratch dir {} not renamed: {e}", from.display());
            None
        }
    }
}

/// Create the scratch config dir (0700, parents included) for `local-scratch`
/// and mark it as ours (`.ai-env-owner` = this pid) so `ai-env session forget`
/// never deletes it under a live child.
fn prepare_scratch(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => return Err(std::io::Error::other(format!("{} is not a directory", dir.display()))),
        Ok(_) => {}
        Err(_) => std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?,
    }
    let owner = dir.join(registry::SCRATCH_OWNER_FILE);
    let _ = std::fs::remove_file(&owner);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&owner)?;
    std::io::Write::write_all(&mut f, std::process::id().to_string().as_bytes())
}

/// At teardown (the child is gone): a fresh-named scratch dir of an
/// invocation that never registered a session (a config probe, a login, a
/// suggestions query, a chat closed before its first message) is removed;
/// any other scratch dir loses its owner mark and a fresh-named one is
/// renamed to the first session id. Returns the dir's final path, if kept.
fn finish_scratch(plan: &ChildPlan, registered: bool, first_session_id: Option<&str>) -> Option<PathBuf> {
    let dir = plan.scratch.as_ref()?;
    let fresh = plan.resume.is_none();
    if fresh && !registered {
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.is_dir() => match std::fs::remove_dir_all(dir) {
                Ok(()) => tracing::info!("scratch dir {} removed (no session was registered)", dir.display()),
                Err(e) => tracing::warn!("scratch dir {} not removed: {e}", dir.display()),
            },
            _ => {}
        }
        return None;
    }
    let _ = std::fs::remove_file(dir.join(registry::SCRATCH_OWNER_FILE));
    rename_scratch(plan, first_session_id).or_else(|| Some(dir.clone()))
}

// ---- local-scratch: the sealed setup-token (S7) ---------------------------------------------

/// The setup-token a `local-scratch` child is handed, and how.
#[derive(Debug)]
pub struct ChildCredential {
    token: SetupToken,
    deliver: Deliver,
    /// The seal id of the container it came from (audit rows only).
    tag: String,
}

impl ChildCredential {
    /// `fd` or `env`.
    fn word(&self) -> &'static str {
        match self.deliver {
            Deliver::Fd => "fd",
            Deliver::Env => "env",
        }
    }
}

/// How a `local-scratch` child logs in, decided once, before its first spawn.
#[derive(Debug)]
pub enum ScratchLogin {
    /// `CLAUDE_CODE_OAUTH_TOKEN` is in the wrapper's environment: the child
    /// inherits it, as before S7.
    Inherited,
    /// Unsealed for this session.
    Sealed(ChildCredential),
    /// The child runs logged out, and why (the reason in its note line).
    LoggedOut(String),
    /// A signal arrived while Touch ID was awaited: the dialog was closed and
    /// the wrapper exits with this code.
    Stopped(i32),
}

impl ScratchLogin {
    /// The end row's `credential:` word.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            ScratchLogin::Inherited => "inherited",
            ScratchLogin::Sealed(c) => c.word(),
            ScratchLogin::LoggedOut(_) | ScratchLogin::Stopped(_) => "none",
        }
    }
}

/// The one note line of a logged-out `local-scratch` child.
#[must_use]
pub fn logged_out_note(why: &str) -> String {
    format!("ai-env-claude: local-scratch without {TOKEN_VAR}: {why}, so the child is logged out")
}

/// The `local-scratch` unseal's budget and whether Cursor's initialize window
/// set it: `configured` (`[creds].unseal_timeout_s`, or the lab knob), but
/// never past T−10 s of [`INITIALIZE_WINDOW`], of which `used` is already
/// gone — the unseal runs before the child exists, so a longer wait lets the
/// window close on the session. `used` counts in whole seconds (a fraction
/// comes out of the 10 s margin), so the countdown says `50 s left`.
#[must_use]
pub fn scratch_unseal_budget(configured: Duration, used: Duration) -> (Duration, bool) {
    let room = INITIALIZE_WINDOW.saturating_sub(INIT_FAIL_FAST).saturating_sub(Duration::from_secs(used.as_secs()));
    if configured <= room {
        (configured, false)
    } else {
        (room, true)
    }
}

/// The wrapper's exit code after a signal during the unseal: 130 for Ctrl-C,
/// 143 for SIGTERM and SIGHUP, as `vm exec`'s unseal exits.
fn stop_code(sig: i32) -> i32 {
    if sig == libc::SIGINT {
        130
    } else {
        143
    }
}

/// How a `local-scratch` child logs in. A token in the environment wins.
/// Otherwise the sealed setup-token is unsealed — unless none is sealed,
/// `[creds]` does not validate, Anthropic refused this seal before (S7 D6:
/// never unsealed again, no Touch ID), or `state/creds.toml` cannot be read
/// (which seals were refused is then unknown: it fails closed, as `vm exec`
/// does) — with `[creds].key` from the keystore at `AI_ENV_DIR` (else
/// `~/.config/ai-env`), within `[creds].unseal_timeout_s` (or
/// [`UNSEAL_TIMEOUT_KNOB`]) capped by [`scratch_unseal_budget`] (`used`: how
/// much of the initialize window the wrapper spent before this call). The
/// refusal is checked, and the delivery audited, under the seal id of the
/// very bytes decrypted: the text one read of the sealed file returned (the
/// reads before that one only classify the file). Every
/// failure, a dismissed dialog and the deadline included, is a logged-out
/// child, never a failed session; the unseal is audited `credential_unseal`.
pub fn scratch_login(sess: &Session, env: &dyn Fn(&str) -> Option<OsString>, used: Duration) -> ScratchLogin {
    if env(TOKEN_VAR).is_some_and(|v| !v.is_empty()) {
        return ScratchLogin::Inherited;
    }
    let paths = &sess.paths;
    let path = paths.setup_token_env();
    match aws_env_state(&path) {
        AwsEnvState::Sealed => {}
        AwsEnvState::Absent => return ScratchLogin::LoggedOut("no setup-token is sealed (`ai-env creds setup-token` seals one)".into()),
        AwsEnvState::NotSealed(why) => return ScratchLogin::LoggedOut(format!("{} {why}", path.display())),
    }
    let creds = sess.cfg.as_ref().map(|c| c.creds.clone()).unwrap_or_default();
    if let Err(e) = creds.validate() {
        return ScratchLogin::LoggedOut(one_line(&e.to_string()));
    }
    // One read (M38, as `vm exec`): the bytes whose seal id is checked against the refusals and audited at
    // the spawn are the ones decrypted, never a second read of a file sealed anew or restored meanwhile.
    let Ok(text) = sealed_text(&path, "seal it with `ai-env creds setup-token`") else {
        return ScratchLogin::LoggedOut(format!("{} cannot be read", path.display()));
    };
    let tag = tag_of(&text);
    // Fails closed, as `vm exec` does: a store that cannot be read may hold this seal's refusal.
    match read_rejection(paths, &tag) {
        Ok(None) => {}
        Ok(Some(r)) => {
            return ScratchLogin::LoggedOut(format!("the sealed setup-token was refused by Anthropic on {} ({}) and is not unsealed again (`claude setup-token`, then `ai-env creds setup-token`)", r.at, r.vm));
        }
        Err(e) => return ScratchLogin::LoggedOut(format!("{}: which tokens Anthropic refused is unknown and the sealed setup-token is not unsealed (repair that file, or remove it to forget every recorded refusal)", one_line(&e))),
    }
    let deliver = if creds.deliver == "env" { Deliver::Env } else { Deliver::Fd };
    let (budget, capped) = scratch_unseal_budget(ms_knob(UNSEAL_TIMEOUT_KNOB).unwrap_or_else(|| creds.unseal_budget()), used);
    if budget.is_zero() {
        return ScratchLogin::LoggedOut(format!("the sealed setup-token was not unsealed (no time was left for Touch ID inside Cursor's {} s initialize window)", INITIALIZE_WINDOW.as_secs()));
    }
    if capped {
        tracing::info!(budget_s = budget.as_secs(), "the Touch ID budget ends {} s before Cursor's initialize window", INIT_FAIL_FAST.as_secs());
    }
    let started = std::time::Instant::now();
    let unsealed = Keystore::resolve(env("AI_ENV_DIR").filter(|d| !d.is_empty()).map(PathBuf::from)).and_then(|store| unseal_for_child(&store, &creds.key, &text, budget));
    let elapsed = started.elapsed();
    let outcome = match &unsealed {
        Ok(Unsealed::Token(_)) => "ok".to_string(),
        Ok(Unsealed::Stopped(sig)) => format!("signal {sig}"),
        Err(e) => format!("exit {}", e.exit_code()),
    };
    let detail = [("for", "local-scratch".to_string()), ("source", "setup-token".to_string()), ("ms", elapsed.as_millis().to_string()), ("outcome", outcome)];
    if let Err(e) = audit::append(&paths.audit(), &AuditRow::new("credential_unseal", None, audit::detail(&detail))) {
        tracing::warn!("audit credential_unseal: {e}");
    }
    match unsealed {
        Ok(Unsealed::Token(token)) => {
            tracing::info!(ms = elapsed.as_millis() as u64, len = token.len(), "setup-token unsealed for the local-scratch child");
            ScratchLogin::Sealed(ChildCredential { token, deliver, tag })
        }
        Ok(Unsealed::Stopped(sig)) => ScratchLogin::Stopped(stop_code(sig)),
        Err(e) => {
            let why = match &e {
                CliError::Cancelled => "the Touch ID dialog was dismissed".to_string(),
                CliError::AuthUnavailable(_) if elapsed >= budget && capped => format!("no Touch ID within {}: Cursor's {} s initialize window allows no more", budget_text(budget), INITIALIZE_WINDOW.as_secs()),
                CliError::AuthUnavailable(_) if elapsed >= budget => format!("no Touch ID within {}", budget_text(budget)),
                other => one_line(&other.to_string()),
            };
            ScratchLogin::LoggedOut(format!("the sealed setup-token was not unsealed ({why})"))
        }
    }
}

/// `60 s`, or `1500 ms` for a budget that is not whole seconds (the lab knob).
fn budget_text(d: Duration) -> String {
    if d.subsec_millis() == 0 {
        format!("{} s", d.as_secs())
    } else {
        format!("{} ms", d.as_millis())
    }
}

/// The first line of `text`, scrubbed and at most 300 characters: what a
/// note line carries of an error.
fn one_line(text: &str) -> String {
    redact::scrub(text.lines().next().unwrap_or_default()).chars().take(300).collect()
}

/// One line on stderr. A closed stderr is ignored, never a panic: the
/// countdown speaks from a thread of its own.
fn say(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// What the wait for Touch ID ended with.
enum Unsealed {
    Token(SetupToken),
    /// This signal arrived; the decrypt was killed, its dialog with it.
    Stopped(i32),
}

/// One killable, timed unseal of the sealed `text` with `key` (one Touch ID):
/// the countdown on stderr as `ai-env-claude`, the deadline `budget`. Signals
/// are caught before `age` exists, so from its first instant the dialog has an
/// owner that closes it ([`UnsealSignals`]); the dialog is killed while the
/// handlers still hold any further signal ([`await_unseal`]), and the
/// plaintext never leaves zeroizing memory. How the wait ends is
/// [`unseal_outcome`]'s.
fn unseal_for_child(store: &Keystore, key: &str, text: &str, budget: Duration) -> crate::errors::Result<Unsealed> {
    validate_key_name(key).map_err(|e| CliError::Msg(format!("[creds].key: {e}")))?;
    let cont = crate::container::read(text)?;
    let name = crate::select::resolve_for_decrypt(store, Some(key), &cont)?;
    let age = Arc::new(AgeTool::probe()?);
    let mut signals = UnsealSignals::catch().map_err(|e| CliError::Msg(format!("cannot catch signals for the unseal: {e}")))?;
    let job = UnsealJob::start(age, store.identity_path(&name), cont.data, budget, "the setup token").with_prefix("ai-env-claude");
    let kill = job.kill_handle();
    let (tx, rx) = std::sync::mpsc::channel();
    // A thread that cannot start drops the job, and its Drop closes the dialog.
    std::thread::Builder::new()
        .name("unseal-wait".into())
        .spawn(move || {
            let _ = tx.send(job.wait(say));
        })
        .map_err(|e| CliError::Msg(format!("cannot wait for the unseal: {e}")))?;
    let answer = await_unseal(&|| signals.caught(), &kill, &rx);
    // The decrypt is over either way: an answer came, or its group was killed above.
    unseal_outcome(signals.restore(), answer)
}

/// The wait for Touch ID: the decrypt's answer (`rx`), or `None` once
/// `caught` reports a signal. A stop kills the decrypt's group, then waits —
/// at most [`STOP_SETTLE`] after the stop — for the answer, which comes only
/// once the decrypt is over: given up before it spawned `age`, or with its
/// child adopted, killed (the kill is marked first) and reaped. So a stop
/// that came while `age` was being spawned, when the kill could not reach its
/// group yet, never lets the wrapper exit with the dialog up. That answer,
/// a plaintext included, is dropped (zeroized): the stop wins.
fn await_unseal(caught: &dyn Fn() -> Option<i32>, kill: &AgeKill, rx: &std::sync::mpsc::Receiver<crate::errors::Result<Zeroizing<Vec<u8>>>>) -> Option<crate::errors::Result<Zeroizing<Vec<u8>>>> {
    use std::sync::mpsc::RecvTimeoutError;
    loop {
        if caught().is_some() {
            let settle = std::time::Instant::now() + STOP_SETTLE;
            kill.kill_group();
            let _ = rx.recv_timeout(settle.saturating_duration_since(std::time::Instant::now()));
            return None;
        }
        match rx.recv_timeout(UNSEAL_POLL) {
            Ok(done) => return Some(done),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Some(Err(CliError::Msg("the unseal ended without an answer".into()))),
        }
    }
}

/// How the wait for Touch ID ends: a signal recorded until the dispositions
/// were restored wins over any answer — a plaintext (dropped, so zeroized), a
/// dismissed dialog, the deadline — so a wrapper told to stop never spawns;
/// otherwise the answer decides.
fn unseal_outcome(caught: Option<i32>, answer: Option<crate::errors::Result<Zeroizing<Vec<u8>>>>) -> crate::errors::Result<Unsealed> {
    match (caught, answer) {
        (Some(sig), _) => Ok(Unsealed::Stopped(sig)),
        (None, Some(done)) => Ok(Unsealed::Token(parse_token_env(&done?)?)),
        (None, None) => Err(CliError::Msg("the unseal stopped without an answer".into())),
    }
}

/// The signal caught while Touch ID was awaited (0: none).
static UNSEAL_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Only records the signal: an atomic store is async-signal-safe.
extern "C" fn record_unseal_signal(sig: libc::c_int) {
    UNSEAL_SIGNAL.store(sig, Ordering::SeqCst);
}

/// SIGINT, SIGTERM and SIGHUP caught while this lives, their previous
/// dispositions restored when it drops. `age` runs in its own process group,
/// so a terminal's Ctrl-C never reaches it, and the extension signals the
/// wrapper alone: a wrapper ended by the default action during the wait would
/// leave the Touch ID dialog behind. A signal ignored when the wrapper started
/// stays ignored. SIGKILL cannot be caught: its dialog stays until answered,
/// and the plaintext then goes nowhere (age's stdout reader is gone).
struct UnsealSignals {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl UnsealSignals {
    fn catch() -> std::io::Result<UnsealSignals> {
        UNSEAL_SIGNAL.store(0, Ordering::SeqCst);
        let mut caught = UnsealSignals { previous: Vec::new() };
        let handler: extern "C" fn(libc::c_int) = record_unseal_signal;
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: sigaction(2) on zeroed (valid) structs; the handler only
            // stores to an atomic. On an error `caught` drops and restores
            // what was already replaced.
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, std::ptr::null(), &raw mut old) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if old.sa_sigaction == libc::SIG_IGN {
                    continue;
                }
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = handler as libc::sighandler_t;
                act.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&raw mut act.sa_mask);
                if libc::sigaction(sig, &raw const act, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                caught.previous.push((sig, old));
            }
        }
        Ok(caught)
    }

    /// The signal that arrived since [`Self::catch`], if any.
    fn caught(&self) -> Option<i32> {
        let sig = UNSEAL_SIGNAL.load(Ordering::SeqCst);
        (sig != 0).then_some(sig)
    }

    /// Put the previous dispositions back, then report the signal recorded up
    /// to that instant: one that came with the answer, or between the last
    /// look and here, is never lost. A later one takes its default course.
    fn restore(&mut self) -> Option<i32> {
        for (sig, old) in self.previous.drain(..).rev() {
            // SAFETY: restores a disposition sigaction(2) itself returned.
            unsafe { libc::sigaction(sig, &raw const old, std::ptr::null_mut()) };
        }
        self.caught()
    }
}

impl Drop for UnsealSignals {
    fn drop(&mut self) {
        // Idempotent: `restore` already emptied the list.
        self.restore();
    }
}

/// A signal ended the wrapper while Touch ID was awaited (the dialog is
/// closed): nothing was spawned. The scratch dir goes as an unregistered
/// invocation's does, the census gets its end row (`end:sigterm`, and with
/// [`SYNTHETIC_OAUTH_KNOB`] `synthetic_oauth:unsent`: the session was never
/// initialized), and the wrapper exits with `code`.
fn stop_before_spawn(sess: &Session, plan: &ChildPlan, code: i32) -> ! {
    say("ai-env-claude: stopped while waiting for Touch ID: the dialog was closed and nothing was started");
    tracing::info!(code, "stopped by a signal during the unseal");
    let _ = finish_scratch(plan, false, None);
    let synthetic_oauth = Synthetic::from_knob().as_ref().map(Synthetic::census);
    let out = Outcome { code: Some(code), end: Some(EndReason::SigTerm), credential: Some("none"), synthetic_oauth, ..Outcome::default() };
    if let Err(e) = census::record(&sess.paths.census(), &end_row(&sess.start_row, &out, unix_now_ms())) {
        say(&format!("ai-env-claude: census: {e}"));
    }
    std::process::exit(code)
}

// ---- the synthetic oauth_token_refresh's answer ---------------------------------------------

/// The class of the host's answer to the synthetic request, as the end row
/// records it: `token(len=<n>)` (a success with an `accessToken` string —
/// only its length is kept; the value is read into a zeroizing `Secret` and
/// dropped), `null` (`accessToken: null`), `absent` (a success without
/// one), `malformed` (an `accessToken` that is no string), `error(<text>)`
/// (the stock extension: `getOAuthToken callback is not provided.`), or
/// `other(<subtype>)`. Texts are scrubbed and bounded ([`note_text`]). The
/// line itself, in the pump's read buffers, is freed without zeroizing: the
/// leak S7 accepts for serde and transport buffers (a stock extension sends
/// no token at all).
#[must_use]
pub fn synthetic_answer_class(line: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Line<'a> {
        #[serde(borrow, default)]
        response: Option<&'a RawValue>,
    }
    #[derive(Deserialize)]
    struct Answer<'a> {
        #[serde(default)]
        subtype: Option<String>,
        #[serde(borrow, default)]
        response: Option<&'a RawValue>,
        #[serde(borrow, default)]
        error: Option<&'a RawValue>,
    }
    let Some(answer) = serde_json::from_slice::<Line<'_>>(line).ok().and_then(|l| l.response).and_then(|r| serde_json::from_str::<Answer<'_>>(r.get()).ok()) else {
        return "other(unparseable)".into();
    };
    match answer.subtype.as_deref() {
        Some("success") => {
            let fields: BTreeMap<String, &RawValue> = answer.response.and_then(|r| serde_json::from_str(r.get()).ok()).unwrap_or_default();
            match fields.get("accessToken") {
                None => "absent".into(),
                Some(raw) if raw.get() == "null" => "null".into(),
                Some(raw) => match serde_json::from_str::<Secret<String>>(raw.get()) {
                    Ok(token) => format!("token(len={})", token.expose().len()),
                    Err(_) => "malformed".into(),
                },
            }
        }
        Some("error") => {
            let text = answer.error.and_then(|e| serde_json::from_str::<String>(e.get()).ok()).unwrap_or_default();
            format!("error({})", note_text(&text, SYNTHETIC_ERROR_CHARS))
        }
        other => format!("other({})", note_text(other.unwrap_or("-"), 32)),
    }
}

/// `text` fit for one `; `-separated note part: scrubbed, `;` made `,`,
/// control characters made spaces, at most `max` characters (`…` when cut).
fn note_text(text: &str, max: usize) -> String {
    let clean: String = redact::scrub(text).chars().map(|c| if c == ';' { ',' } else if c.is_control() { ' ' } else { c }).collect();
    if clean.chars().count() > max {
        format!("{}\u{2026}", clean.chars().take(max.saturating_sub(1)).collect::<String>())
    } else {
        clean
    }
}

/// Exec the real binary as S1 does (the pump could not start).
fn exec_unpiped(sess: &Session) -> ! {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(&sess.real_binary).args(&sess.args).exec();
    eprintln!("ai-env-claude: cannot exec {}: {err}", sess.real_binary.display());
    std::process::exit(1)
}

/// A remote session that cannot reach its pump (S8 P0, fail closed): the
/// census end row (`end:spawn_failed; step:precheck`, with the failure's
/// code) and the audit row `session_remote_failed` are written, then the
/// failure's one line is printed last (through the voice), and the wrapper
/// exits with the failure's code. Nothing ran: no AWS call, no Touch ID.
fn fail_before_pump(sess: &Session, failure: &Failure) -> ! {
    let code = record_failure_before_pump(sess, failure);
    voice::line(&failure.line());
    std::process::exit(code)
}

/// What [`fail_before_pump`] records before its line (the census end row
/// and the audit row); the exit code.
fn record_failure_before_pump(sess: &Session, failure: &Failure) -> i32 {
    let code = failure.exit_code();
    let step = match failure {
        Failure::Other { step, .. } => step,
        _ => StartStep::Precheck.name(),
    };
    tracing::warn!(why = failure.word(), code, step, "the remote session failed before the pump started");
    let out = Outcome { code: Some(code), end: Some(EndReason::SpawnFailed), step: Some(step), ..Outcome::default() };
    if let Err(e) = census::record(&sess.paths.census(), &end_row(&sess.start_row, &out, unix_now_ms())) {
        voice::warn(&format!("census: {e}"));
    }
    let detail = [("step", step.to_string()), ("code", code.to_string()), ("why", failure.word().to_string())];
    if let Err(e) = audit::append(&sess.paths.audit(), &AuditRow::new(audit_event::SESSION_REMOTE_FAILED, None, audit::detail(&detail))) {
        voice::warn(&format!("audit {}: {e}", audit_event::SESSION_REMOTE_FAILED));
    }
    code
}

/// What a remote session's pump could not get before it started: the
/// `Failure` it fails closed with (exit 1, at the precheck).
fn not_started(what: &str, e: &dyn std::fmt::Display) -> Failure {
    Failure::Other { code: 1, step: StartStep::Precheck.name(), first_line: format!("{what}: {e}") }
}

/// A remote session's census start row, which `main` leaves to the pump (S8
/// phase 4): written once the stop handlers listen, so a stop that comes
/// after it always ends as a cancelled start with its end row, never by the
/// default action. A failure is a warning in the log, as the end row's is.
fn record_start_row(sess: &Session) {
    if let Err(e) = census::record(&sess.paths.census(), &sess.start_row) {
        voice::warn(&format!("census: {e}"));
    }
}

/// What a remote session's close leaves once its waits are over (S9): the
/// registry row's `last_wip_fetch` takes a fetch that ended inside them
/// ([`wip_fetched_at_the_close`]), and this process's scratch under
/// `state/tmp/` goes (a fetch given up at `codeout::CLOSE_WAIT` leaves its
/// scratch repository: `snapshot::remove_own_scratch`). The census end row
/// and `session_remote_end` are written before the waits (plan §11's order),
/// so their `fetch:` counts never include that fetch; its `codeout_fetch`
/// row and the workspace row do.
fn after_close(pump: &mut Pump) {
    if let Some(wip) = wip_fetched_at_the_close(&pump.sess, pump.row.as_ref()) {
        if let Some(row) = pump.row.as_mut() {
            row.last_wip_fetch = Some(wip);
        }
        pump.write_row();
    }
    crate::bridge::workspace::snapshot::remove_own_scratch(&pump.sess.paths);
}

/// The newest `refs/remotes/box/wip/*` a code-out from the session's VM
/// promoted since the session started, as the workspace row of its cwd
/// records it (`codeout::record_fetch`: the last fetch's VM, time and
/// newest snapshot), when it is newer than the registry row's
/// `last_wip_fetch` (snapshots are named by time: the greatest is the
/// newest). `None` otherwise, and when either row is missing or unreadable.
fn wip_fetched_at_the_close(sess: &Session, row: Option<&SessionRow>) -> Option<String> {
    let row = row?;
    let vm = row.microvm_id.as_deref()?;
    let cwd = std::fs::canonicalize(sess.cwd.as_ref()?).ok()?;
    let slug = slug::project_dir_name(&cwd).ok()?;
    let ws = crate::bridge::workspace::rows::read(&sess.paths, &slug).ok()?.ws.remove(&*cwd.to_string_lossy())?;
    let since = sess.start_row.start / 1000;
    let wip = ws.last_wip.filter(|_| ws.last_fetch_vm.as_deref() == Some(vm) && ws.last_fetch_at.is_some_and(|at| at >= since))?;
    (row.last_wip_fetch.as_deref() < Some(wip.as_str())).then_some(wip)
}

/// Pipe `sess` through the pump and exit with the child's code. Never returns.
///
/// Order: the wrapper's voice → the runtime (before any Touch ID, so a
/// runtime that cannot start never wastes one) → remote: the stop handlers
/// (S8 phase 4: as early as the runtime allows) → logging (the first
/// production caller of `logging::init`; a failure is one stderr line,
/// never fatal) → remote: the census start row ([`record_start_row`]) →
/// register `CLAUDE_CODE_OAUTH_TOKEN` as a secret → the child plan (on
/// failure: one stderr line and S1's exec; a remote session fails closed
/// instead) → the link factory (remote: P0, `remote::pipeline::precheck`,
/// whose failure ends it before the pump) → `local-scratch`: the scratch
/// dir, the child's login ([`scratch_login`]: the sealed token, or one note
/// line), the pre-spawn seed → the supervisor on a `LocalSet` → mirror
/// fsync → registry row closed → census end row → the link's close
/// (remote: within what is left of the hard stop), then what its waits
/// left ([`after_close`]: the row's `last_wip_fetch`, this process's
/// scratch) → the lab message or the one final line → exit (which joins an
/// unseal's SIGKILL step still running: `age_cmd::join_kills`).
pub fn run(sess: Session) -> ! {
    // Only the wrapper pipes: its notes go to the log, its one final line to stderr.
    voice::set(voice::Voice::Wrapper);
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) if sess.mode == Mode::Remote => {
            record_start_row(&sess);
            fail_before_pump(&sess, &not_started("cannot start the pump runtime", &e))
        }
        Err(e) => {
            eprintln!("ai-env-claude: cannot start the pump runtime ({e}); running unpiped");
            exec_unpiped(&sess)
        }
    };
    // A remote session listens for a stop before anything else, its census start row included (S8 phase 4): a
    // SIGTERM, SIGINT or SIGHUP during the setup below or P0 is the supervisor's first wake ([`Pump::supervise`]),
    // a cancelled start (143, its line, the end row), never the default action.
    let early = (sess.mode == Mode::Remote).then(|| {
        let _rt = rt.enter();
        Signals::install(LinkKind::Remote)
    });
    let log_path = sess.paths.wrapper_log();
    if let Err(e) = logging::init(&LogOpts { path: log_path, rust_log: std::env::var("RUST_LOG").ok() }) {
        eprintln!("ai-env-claude: log: {e}");
    }
    if sess.mode == Mode::Remote {
        record_start_row(&sess);
    }
    if let Some(token) = std::env::var_os(TOKEN_VAR) {
        redact::register_secret(&token.to_string_lossy());
    }
    let env = |k: &str| std::env::var_os(k);
    let mut fresh = || uuid::Uuid::now_v7().to_string();
    let plan = match child_plan(&sess, &env, &mut fresh) {
        Ok(p) => p,
        Err(e) if sess.mode == Mode::Remote => fail_before_pump(&sess, &not_started("the session's pump cannot start", &e)),
        Err(e) => {
            eprintln!("ai-env-claude: pump unavailable ({e}); running unpiped");
            tracing::warn!("pump unavailable: {e}");
            exec_unpiped(&sess)
        }
    };
    tracing::info!(mode = sess.mode.name(), argc = plan.argv.len(), resume = plan.resume.is_some(), scratch = plan.scratch.is_some(), "piping the session");
    let links: Box<dyn LinkFactory> = match sess.mode {
        Mode::Remote => match pipeline::precheck(&sess) {
            Ok(session_plan) => Box::new(RemoteLinks::new(Rc::new(session_plan))),
            Err(failure) => fail_before_pump(&sess, &failure),
        },
        _ => Box::new(LocalLinks::new(plan.clone())),
    };
    let mut login = None;
    if let Some(dir) = &plan.scratch {
        if let Err(e) = prepare_scratch(dir) {
            eprintln!("ai-env-claude: scratch dir {}: {e}; running unpiped", dir.display());
            exec_unpiped(&sess)
        }
        // Cursor's initialize window runs from the wrapper's spawn; the start row was stamped just after it.
        let used = Duration::from_millis(unix_now_ms().saturating_sub(sess.start_row.start));
        let decided = scratch_login(&sess, &env, used);
        tracing::info!(credential = decided.word(), "local-scratch login decided");
        match &decided {
            ScratchLogin::LoggedOut(why) => say(&logged_out_note(why)),
            ScratchLogin::Stopped(code) => stop_before_spawn(&sess, &plan, *code),
            ScratchLogin::Inherited | ScratchLogin::Sealed(_) => {}
        }
        login = Some(decided);
        if let Some(resume) = &plan.resume {
            match seed_from_mac(&sess, &plan, resume, false) {
                SeedOutcome::Seeded(_) => {}
                SeedOutcome::KeptNewer(p) => tracing::info!("resume: scratch transcript {} kept", p.display()),
                SeedOutcome::NoSource => tracing::info!("resume: no local transcript for {resume}"),
                SeedOutcome::Failed(e) => tracing::warn!("resume: seeding failed: {e}"),
            }
        }
    }
    if plan.slug.is_some() && plan.slug != sess.cwd.as_deref().and_then(|c| slug::project_dir_name(c).ok()) {
        tracing::warn!("the child's projects subdirectory differs from the picker's slug of the cwd (CLAUDE_CODE_PROJECT_DIR_NAME?)");
    }
    tracing::info!("{}", plan.mirror.reason);
    let mut pump = Pump::new(sess, plan, login, links);
    // A remote generation's pipeline, session and adapter run as local tasks beside the supervisor.
    let local = tokio::task::LocalSet::new();
    let code = local.block_on(&rt, pump.supervise(early));
    pump.conclude(code);
    if pump.kind == LinkKind::Remote {
        let budget = pump.close_budget();
        pump.release_link();
        let close = pump.links.close(budget);
        local.block_on(&rt, async move {
            let _ = tokio::time::timeout(budget, close).await;
        });
        after_close(&mut pump);
    }
    if let Some(msg) = pump.lab_message.take() {
        eprintln!("{msg}");
    }
    if let Some(line) = pump.final_line.take() {
        voice::line(&line);
    }
    // Never drop the runtime: its blocking stdin reader would hold the exit.
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::agent::credential::seal_tag;
    use crate::wire::argv::LocalReason;

    fn start_row() -> CensusRow {
        CensusRow {
            v: 1,
            ts: "2026-09-25T10:00:00Z".into(),
            start: 1_000,
            pid: 42,
            ppid: 1,
            ext: Some("2.1.282".into()),
            route: "local".into(),
            reason: "unconfigured".into(),
            argv: vec!["w".into(), "b".into(), "--output-format".into(), "stream-json".into()],
            cwd: Some("/x".into()),
            env_names: vec!["HOME".into()],
            env_selected: std::collections::BTreeMap::new(),
            note: Some("mode:local-child".into()),
            end: None,
            exit: None,
        }
    }

    fn session(mode: Mode, args: &[&str], root: &Path) -> Session {
        let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let route = argv::classify(&args);
        let session = match &route {
            Route::Remote(s) => s.clone(),
            Route::Local(_) => SessionArgs::default(),
        };
        let route = if matches!(route, Route::Remote(_)) { Route::Local(LocalReason::Unconfigured) } else { route };
        Session {
            real_binary: PathBuf::from("/bin/claude"),
            args,
            route,
            session,
            cwd: Some(root.to_path_buf()),
            paths: Paths::from_root_and_env(root.join("bridge"), None),
            cfg: None,
            mode,
            start_row: start_row(),
        }
    }

    fn env_of(pairs: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())
    }

    /// A pump over a local child plan, as `run` builds one.
    fn local_pump(sess: Session, plan: ChildPlan, login: Option<ScratchLogin>) -> Pump {
        let links = Box::new(LocalLinks::new(plan.clone()));
        Pump::new(sess, plan, login, links)
    }

    #[test]
    fn end_row_clones_the_start_row_and_extends_the_note() {
        let out = Outcome {
            code: Some(3),
            end: Some(EndReason::LabExit),
            child_pid: Some(77),
            respawns: 1,
            mirror_frames: 2,
            mirror_rejected: 1,
            mirror_dropped: 0,
            dropped_lines: 0,
            oauth_answered: 1,
            init_latency_ms: Some(120),
            eof_to_sigterm_ms: None,
            session_id: None,
            credential: None,
            synthetic_oauth: None,
            step: None,
            remote: Vec::new(),
            close_ms: None,
            pid_rewrite: None,
            init_id_refused: 0,
            moves: [0; 3],
            move_ms: None,
            cut: None,
            dups: None,
            ka_dropped: 0,
        };
        let row = end_row(&start_row(), &out, 9_000);
        assert_eq!((row.end, row.exit, row.pid, row.start), (Some(9_000), Some(3), 42, 1_000), "paired with the start row on (pid, start)");
        assert_eq!(
            row.note.as_deref(),
            Some("mode:local-child; end:lab_exit; child_pid:77; respawns:1; mirror:2/1; dropped:0; oauth_refresh_answered:1; init_ms:120")
        );
        let refused = end_row(&start_row(), &Outcome { init_id_refused: 2, step: Some("spawn"), ..out.clone() }, 9_000);
        assert!(refused.note.unwrap().ends_with("; init_ms:120; init_id_refused:2; step:spawn"), "only when n > 0, before the remote parts");
        let mut bare = start_row();
        bare.note = None;
        let row = end_row(&bare, &Outcome { code: None, ..Outcome::default() }, 5);
        assert_eq!(row.exit, None);
        assert!(row.note.unwrap().starts_with("end:unknown; child_pid:-"));
        let json = serde_json::to_string(&end_row(&start_row(), &Outcome { code: None, ..Outcome::default() }, 5)).unwrap();
        assert!(json.contains("\"end\":5") && !json.contains("\"exit\""), "exit: null is omitted: {json}");
    }

    #[test]
    fn child_plan_local_child_keeps_argv_and_env() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::LocalChild, &["--output-format", "stream-json", "--add-dir", "/o", "--debug", "--replay-user-messages"], d.path());
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned())]);
        let plan = child_plan(&sess, &env, &mut || "x".to_string()).unwrap();
        assert_eq!(plan.argv, vec!["--output-format", "stream-json", "--add-dir", "/o", "--debug", "--replay-user-messages", "--session-mirror"]);
        assert!(plan.env_set.is_empty() && plan.env_remove.is_empty());
        assert_eq!(plan.child_config_dir, d.path().join(".claude"));
        assert_eq!(plan.scratch, None);
        assert!(!plan.mirror.enabled, "{}", plan.mirror.reason);
        assert!(plan.mirror.reason.starts_with("mirror writer disabled:"), "{}", plan.mirror.reason);
        assert_eq!(plan.slug, slug::project_dir_name(d.path()).ok());
        // With a mirror root the writer is on.
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned()), (MIRROR_ROOT_ENV, d.path().join("m").into_os_string())]);
        assert!(child_plan(&sess, &env, &mut || "x".to_string()).unwrap().mirror.enabled);
    }

    #[test]
    fn child_plan_local_scratch_points_the_child_at_a_scratch_dir() {
        let d = tempfile::tempdir().unwrap();
        let uuid = "11111111-2222-4333-8444-555555555555";
        let resume = format!("--resume={uuid}");
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json", &resume], d.path());
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned()), ("CLAUDE_CODE_PROJECT_DIR_NAME", OsString::from("custom-dir"))]);
        let plan = child_plan(&sess, &env, &mut || "fresh".to_string()).unwrap();
        let scratch = d.path().join("bridge").join("state").join("scratch").join(uuid);
        assert_eq!(plan.scratch.as_deref(), Some(scratch.as_path()));
        assert_eq!(plan.env_set, vec![("CLAUDE_CONFIG_DIR".to_string(), scratch.clone().into_os_string())]);
        assert_eq!(plan.env_remove, vec![SECURE_STORAGE_ENV.to_string(), TOKEN_FD_VAR.to_string()], "no inherited keychain pointer, no inherited token descriptor");
        assert_eq!(plan.resume.as_deref(), Some(uuid));
        assert_eq!(plan.slug.as_deref(), Some("custom-dir"), "the override applies because CLAUDE_CONFIG_DIR is set for the child");
        assert!(plan.mirror.enabled, "a scratch child writes elsewhere: the writer mirrors into the Mac's projects dir");
        assert_eq!(plan.mirror.dest_root, d.path().join(".claude").join("projects"));
        // Without --resume the scratch dir gets a fresh name; a non-uuid resume is not trusted.
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json", "--resume=../../etc"], d.path());
        let plan = child_plan(&sess, &env, &mut || "fresh".to_string()).unwrap();
        assert_eq!(plan.resume, None);
        assert!(plan.scratch.unwrap().ends_with("fresh"));
    }

    #[test]
    fn child_plan_refuses_non_pipe_modes_and_a_missing_home() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::Passthrough, &["--output-format", "stream-json"], d.path());
        assert!(child_plan(&sess, &env_of(vec![("HOME", OsString::from("/h"))]), &mut || "x".into()).is_err());
        let sess = session(Mode::LocalChild, &["--output-format", "stream-json"], d.path());
        assert!(child_plan(&sess, &env_of(vec![]), &mut || "x".into()).is_err(), "no HOME and no CLAUDE_CONFIG_DIR");
        let plan = child_plan(&sess, &env_of(vec![("CLAUDE_CONFIG_DIR", d.path().join("cfg").into_os_string())]), &mut || "x".into()).unwrap();
        assert_eq!(plan.child_config_dir, d.path().join("cfg"));
    }

    #[test]
    fn child_slug_prefers_a_valid_override_only_with_a_config_dir() {
        let d = tempfile::tempdir().unwrap();
        let cwd_slug = slug::project_dir_name(d.path()).ok();
        assert_eq!(child_slug(Some(d.path()), false, Some("custom")), cwd_slug, "ignored without CLAUDE_CONFIG_DIR");
        assert_eq!(child_slug(Some(d.path()), true, Some("custom")).as_deref(), Some("custom"));
        assert_eq!(child_slug(Some(d.path()), true, Some("bad/name")), cwd_slug, "an invalid override falls back");
        assert_eq!(child_slug(None, false, None), None);
    }

    #[test]
    fn scratch_dirs_are_renamed_to_the_session_id_once() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json"], d.path());
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned())]);
        let plan = child_plan(&sess, &env, &mut || "01a0d961-56d6-72c3-8573-4acdf7f8ad65".to_string()).unwrap();
        let from = plan.scratch.clone().unwrap();
        prepare_scratch(&from).unwrap();
        std::fs::write(from.join("x"), "y").unwrap();
        let sid = "33333333-0000-4000-8000-000000000003";
        assert_eq!(rename_scratch(&plan, Some("not-a-uuid")), None);
        assert_eq!(rename_scratch(&plan, None), None);
        let to = rename_scratch(&plan, Some(sid)).unwrap();
        assert_eq!(to, from.parent().unwrap().join(sid));
        assert_eq!(std::fs::read_to_string(to.join("x")).unwrap(), "y");
        // An existing target is never replaced.
        prepare_scratch(&from).unwrap();
        assert_eq!(rename_scratch(&plan, Some(sid)), None);
        assert!(from.exists());
    }

    #[test]
    fn route_labels() {
        assert_eq!(route_label(&Route::Remote(SessionArgs::default())), "remote");
        assert_eq!(route_label(&Route::Local(LocalReason::OutsideRoots)), "local:outside_roots");
    }

    #[test]
    fn end_reason_names_are_stable() {
        let all = [
            (EndReason::ChildExit, "child_exit"),
            (EndReason::EofTerm, "eof"),
            (EndReason::EofKill, "eof_kill"),
            (EndReason::SigTerm, "sigterm"),
            (EndReason::HostGone, "host_gone"),
            (EndReason::LabExit, "lab_exit"),
            (EndReason::SpawnFailed, "spawn_failed"),
            (EndReason::LinkLost, "link_lost"),
            (EndReason::CredentialRejected, "credential_rejected"),
            (EndReason::MoveFailed, "move_failed"),
        ];
        for (r, n) in all {
            assert_eq!(r.name(), n);
        }
    }

    /// S10 (§4.1): a remote end row's parts after S9's, in order: the moves
    /// (once one started) with the last one's ms and cut, the swallow rules'
    /// `inits` and `echoes`, `ka_dropped` when above 0, then `step` and the
    /// link's parts; without any of them a row is S9's.
    #[test]
    fn end_row_writes_the_s10_parts_after_s9s() {
        let dups = DupCounts { inits_forwarded: 3, inits_swallowed: 1, echoes_forwarded: 2, echoes_swallowed: 1, ..DupCounts::default() };
        let out = Outcome {
            code: Some(8),
            end: Some(EndReason::MoveFailed),
            init_id_refused: 1,
            moves: [2, 1, 0],
            move_ms: Some(4200),
            cut: Some("at"),
            dups: Some(dups),
            ka_dropped: 7,
            step: Some("spawn"),
            remote: vec!["vm:microvm-2".into(), "link_drops:0".into()],
            ..Outcome::default()
        };
        let note = end_row(&start_row(), &out, 9_000).note.unwrap();
        assert!(
            note.ends_with("; init_id_refused:1; moves:readdress=2,respawn=1,migrate=0; move_ms:4200; cut:at; inits:3/1; echoes:2/1; ka_dropped:7; step:spawn; vm:microvm-2; link_drops:0"),
            "{note}"
        );
        assert!(note.contains("; end:move_failed; "), "{note}");
        // No move, nothing dropped: a remote row's inits and echoes alone; a local row (no counts) as S9's.
        let quiet = end_row(&start_row(), &Outcome { dups: Some(DupCounts::default()), ..Outcome::default() }, 9_000).note.unwrap();
        assert!(quiet.ends_with("; oauth_refresh_answered:0; inits:0/0; echoes:0/0"), "{quiet}");
        let local = end_row(&start_row(), &Outcome::default(), 9_000).note.unwrap();
        for part in ["moves:", "move_ms:", "cut:", "inits:", "echoes:", "ka_dropped:"] {
            assert!(!local.contains(part), "{part}: {local}");
        }
    }

    /// The remote link's events reach a local pump as nothing but a log
    /// line: its exit, its streams and its finish stay as they were.
    #[test]
    fn a_remote_links_events_change_nothing_on_a_local_child() {
        use crate::bridge::remote::link::StartStep;
        use crate::bridge::remote::Failure;
        use crate::wire::frame::SpawnId;
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::LocalChild, &["--output-format", "stream-json"], d.path());
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned())]);
        let plan = child_plan(&sess, &env, &mut || "x".to_string()).unwrap();
        let mut pump = local_pump(sess, plan, None);
        let events = [
            ChildEvent::Started(RemoteStarted { spawn_id: SpawnId::new_v7(), vm_pid: 42, claude_version: None }),
            ChildEvent::SpawnFailed(SpawnFailure::from_failure(StartStep::Spawn, &Failure::OldImage { vm: "microvm-1".into(), cap: crate::wire::frame::CAP_WORKSPACE_V1 }, None)),
            ChildEvent::Lost(LinkLoss::from_failure(&Failure::LinkLost { vm: "microvm-1".into() })),
            ChildEvent::Detached,
            ChildEvent::Rejected { how: "text" },
            ChildEvent::Link(false),
            ChildEvent::Note("reattached".into()),
            // S10's three.
            ChildEvent::MoveReady(MoveReady { to_vm: "microvm-2".into(), how: "started", ms: 900 }),
            ChildEvent::MoveFailed(MoveFailure { step: StartStep::TouchId, code: 3, word: "touchid_cancelled", again: true }),
            ChildEvent::Parked(true),
        ];
        let kinds: Vec<&str> = events.iter().map(ChildEvent::kind).collect();
        assert_eq!(kinds, ["started", "spawn_failed", "lost", "detached", "rejected", "link", "note", "move_ready", "move_failed", "parked"]);
        for ev in events {
            pump.on_child_event(Some(ev));
        }
        assert!(pump.child_exit.is_none() && !pump.stdout_eof && !pump.stderr_eof && pump.finish.is_none() && pump.out_q.is_empty() && pump.in_q.is_empty());
        assert_eq!(pump.out.end, None);
    }

    /// The end row carries how a scratch child logged in and the synthetic
    /// answer's class, after the S2 parts; without them it is unchanged.
    #[test]
    fn end_row_records_the_login_and_the_synthetic_answer() {
        let out = Outcome { code: Some(0), end: Some(EndReason::EofTerm), credential: Some("fd"), synthetic_oauth: Some("error(getOAuthToken callback is not provided.)".into()), ..Outcome::default() };
        let note = end_row(&start_row(), &out, 9_000).note.unwrap();
        assert!(note.ends_with("; oauth_refresh_answered:0; credential:fd; synthetic_oauth:error(getOAuthToken callback is not provided.)"), "{note}");
        let plain = end_row(&start_row(), &Outcome::default(), 9_000).note.unwrap();
        assert!(!plain.contains("credential:") && !plain.contains("synthetic_oauth:"), "{plain}");
    }

    /// The lab knobs' `_MS` values parse as the S2 knobs do: a positive number
    /// of milliseconds, anything else off.
    #[test]
    fn ms_knobs_parse_like_the_s2_knobs() {
        assert_eq!(parse_ms_knob(None), None);
        assert_eq!(parse_ms_knob(Some("300")), Some(Duration::from_millis(300)));
        assert_eq!(parse_ms_knob(Some(" 40 ")), Some(Duration::from_millis(40)));
        for off in ["0", "-5", "x", "", "1.5"] {
            assert_eq!(parse_ms_knob(Some(off)), None, "{off:?}");
        }
        assert_eq!(TOKEN_FD_VAR, format!("{TOKEN_VAR}_FILE_DESCRIPTOR"), "the shim's name for the slot");
        assert!(!census::CENSUS_VALUE_ALLOWLIST.contains(&SYNTHETIC_OAUTH_KNOB), "its name holds AUTH: never allowlisted");
    }

    /// Each class of the extension's answer, and never the token: a returned
    /// `accessToken` is recorded as present with its length only; error texts
    /// are scrubbed, bounded and kept to one note part.
    #[test]
    fn synthetic_answers_are_classified_without_their_token() {
        let answer = |inner: &str| format!(r#"{{"type":"control_response","response":{inner}}}"#).into_bytes();
        let token = format!("{}oat01-{}", "sk-ant-", "Tk4_".repeat(12));
        let with_token = answer(&format!(r#"{{"subtype":"success","request_id":"s1","response":{{"accessToken":"{token}"}}}}"#));
        let class = synthetic_answer_class(&with_token);
        assert_eq!(class, format!("token(len={})", token.len()));
        assert!(!class.contains(&token[7..]), "only the length is kept");
        let cases = [
            (r#"{"subtype":"success","request_id":"s1","response":{"accessToken":null}}"#, "null"),
            (r#"{"subtype":"success","request_id":"s1","response":{}}"#, "absent"),
            (r#"{"subtype":"success","request_id":"s1"}"#, "absent"),
            (r#"{"subtype":"success","request_id":"s1","response":{"accessToken":42}}"#, "malformed"),
            (r#"{"subtype":"error","request_id":"s1","error":"getOAuthToken callback is not provided."}"#, "error(getOAuthToken callback is not provided.)"),
            (r#"{"subtype":"error","request_id":"s1"}"#, "error()"),
            (r#"{"subtype":"cancelled","request_id":"s1"}"#, "other(cancelled)"),
            (r#"{"request_id":"s1"}"#, "other(-)"),
        ];
        for (inner, want) in cases {
            assert_eq!(synthetic_answer_class(&answer(inner)), want, "{inner}");
        }
        assert_eq!(synthetic_answer_class(b"not json"), "other(unparseable)");
        // One note part: `;` and control characters go, the text is bounded and scrubbed.
        let long = format!("a;b\nc {} {}", token, "z".repeat(400));
        let class = synthetic_answer_class(&answer(&format!(r#"{{"subtype":"error","request_id":"s1","error":{}}}"#, serde_json::to_string(&long).unwrap())));
        assert!(class.starts_with("error(a,b c sk-ant-[redacted:len=") && class.ends_with("\u{2026})"), "{} chars", class.len());
        assert!(!class.contains(&token[7..]) && !class.contains(';') && !class.contains('\n'));
        assert_eq!(class.chars().count(), "error()".len() + SYNTHETIC_ERROR_CHARS);
    }

    /// F12 (M46): a `local-scratch` token of a shape the scrubber's rules do
    /// not mask whole is masked while the wrapper holds it (its handle's
    /// registration, `parse_token`'s) and no longer once `drop_credential`
    /// let the copy go: the scrubber keeps no plain copy of it for the rest of
    /// a session that may run for hours (no holder is left to forget).
    #[test]
    fn an_unrecognised_scratch_tokens_masking_ends_with_the_wrappers_copy() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json"], d.path());
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned())]);
        let plan = child_plan(&sess, &env, &mut || "fresh".to_string()).unwrap();
        let odd = format!("odd-shape-scratch-{}", "Q8".repeat(12));
        let masked = |v: &str| !redact::scrub(&format!("x {v} y")).contains(v);
        let token = crate::bridge::setup_token::parse_token(&odd).unwrap_or_else(|f| panic!("{}", f.message));
        let mut pump = local_pump(sess, plan, Some(ScratchLogin::Sealed(ChildCredential { token, deliver: Deliver::Fd, tag: "seal".into() })));
        assert!(masked(&odd), "masked while the wrapper holds it");
        pump.drop_credential("the test");
        assert!(pump.credential.is_none(), "the copy is gone");
        assert!(!masked(&odd), "the scrubber still holds a copy after the wrapper dropped its own");
        assert!(!redact::forget_secret(&odd), "a holder of the registration is left");
    }

    /// F9: the `initialize` grace of a `--resume` drops the copy only while
    /// no resume miss is held and generation 1 still runs. A held miss, or a
    /// child already exited (its drain may still bring one), keeps it for
    /// the seed retry's respawn (or the finish); either way the grace fires
    /// once.
    #[test]
    fn the_initialize_grace_keeps_the_copy_for_a_held_miss_or_an_exited_child() {
        let d = tempfile::tempdir().unwrap();
        let env = env_of(vec![("HOME", d.path().as_os_str().to_owned())]);
        let grace_over = |held_miss: bool, exited: bool| {
            let sess = session(Mode::LocalScratch, &["--output-format", "stream-json", "--resume=11111111-2222-4333-8444-5555aaaa5555"], d.path());
            let plan = child_plan(&sess, &env, &mut || "fresh".to_string()).unwrap();
            assert!(plan.resume.is_some(), "a --resume, so a seed retry is possible");
            let token = crate::bridge::setup_token::parse_token(&format!("{}oat01-{}", "sk-ant-", "Gr9_".repeat(12))).unwrap_or_else(|f| panic!("{}", f.message));
            let mut pump = local_pump(sess, plan, Some(ScratchLogin::Sealed(ChildCredential { token, deliver: Deliver::Fd, tag: "seal".into() })));
            pump.gen = 1;
            let now = Instant::now();
            pump.credential_hold_until = Some(now);
            if held_miss {
                pump.held_miss = Some(Bytes::from_static(br#"{"type":"result","subtype":"error_during_execution"}"#));
            }
            if exited {
                pump.child_exit = Some(None);
                pump.exit_seen_at = Some(now);
            }
            pump.on_deadline(now);
            assert!(pump.credential_hold_until.is_none(), "the grace fires once (miss {held_miss}, exited {exited})");
            pump.credential.is_some()
        };
        assert!(!grace_over(false, false), "no miss within the grace and the child running: the copy goes");
        assert!(grace_over(true, false), "a held miss: the copy is kept for the seed retry");
        assert!(grace_over(false, true), "a child already exited: kept until its drain settles");
        assert!(grace_over(true, true), "a held miss from an exited child: kept");
    }

    /// Before any unseal: a token in the environment wins; no sealed file, a
    /// file that is not a container, a `[creds]` that does not validate, a
    /// seal Anthropic refused, a `state/creds.toml` that cannot be read (M53:
    /// it may hold this seal's refusal; the note names the file) and an
    /// initialize window already spent each run the child logged out without
    /// asking for Touch ID; a key the keystore lacks fails before `age` is
    /// probed, and that unseal is audited.
    #[test]
    fn scratch_login_decides_without_touch_id_where_it_can() {
        let d = tempfile::tempdir().unwrap();
        let mut sess = session(Mode::LocalScratch, &["--output-format", "stream-json"], d.path());
        let keys = d.path().join("keys");
        let keys_os = keys.clone().into_os_string();
        let env = env_of(vec![("AI_ENV_DIR", keys_os.clone())]);
        let inherited = env_of(vec![(TOKEN_VAR, OsString::from("from-the-shell")), ("AI_ENV_DIR", keys_os.clone())]);
        let now = Duration::ZERO;
        assert!(matches!(scratch_login(&sess, &inherited, now), ScratchLogin::Inherited));
        let logged_out = |l: ScratchLogin| match l {
            ScratchLogin::LoggedOut(why) => why,
            other => panic!("{}", other.word()),
        };
        let why = logged_out(scratch_login(&sess, &env, now));
        assert!(why.starts_with("no setup-token is sealed"), "{why}");
        assert!(logged_out_note(&why).starts_with("ai-env-claude: local-scratch without CLAUDE_CODE_OAUTH_TOKEN: no setup-token is sealed"));
        // An empty variable is no token.
        let empty = env_of(vec![(TOKEN_VAR, OsString::new())]);
        assert!(logged_out(scratch_login(&sess, &empty, now)).starts_with("no setup-token is sealed"));
        let path = sess.paths.setup_token_env();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{TOKEN_VAR}=plain\n")).unwrap();
        assert!(logged_out(scratch_login(&sess, &env, now)).contains("is not an ai-env container"));
        std::fs::write(&path, crate::container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
        sess.cfg = Some(BridgeConfig::parse("[creds]\ndeliver = \"smoke\"\n").unwrap());
        assert!(logged_out(scratch_login(&sess, &env, now)).contains("[creds].deliver"));
        sess.cfg = None;
        let tag = seal_tag(&path).unwrap();
        std::fs::create_dir_all(sess.paths.creds_state().parent().unwrap()).unwrap();
        std::fs::write(sess.paths.creds_state(), format!("[[rejected]]\ntag = \"{tag}\"\nat = \"2026-10-08T09:00:00Z\"\nvm = \"microvm-test\"\n")).unwrap();
        let why = logged_out(scratch_login(&sess, &env, now));
        assert!(why.contains("refused by Anthropic on 2026-10-08T09:00:00Z (microvm-test)"), "{why}");
        std::fs::write(sess.paths.creds_state(), "[[rejected]\n").unwrap();
        let why = logged_out(scratch_login(&sess, &env, now));
        let unreadable = format!("{} cannot be parsed (", sess.paths.creds_state().display());
        assert!(why.starts_with(&unreadable) && why.contains("which tokens Anthropic refused is unknown and the sealed setup-token is not unsealed"), "{why}");
        std::fs::remove_file(sess.paths.creds_state()).unwrap();
        // 50 s of the window already gone: nothing is left for Touch ID.
        let why = logged_out(scratch_login(&sess, &env, Duration::from_secs(50)));
        assert_eq!(why, "the sealed setup-token was not unsealed (no time was left for Touch ID inside Cursor's 60 s initialize window)");
        let audit = std::fs::read_to_string(sess.paths.audit()).unwrap_or_default();
        assert!(!audit.contains("credential_unseal"), "nothing was unsealed: {audit}");
        let why = logged_out(scratch_login(&sess, &env, now));
        assert!(why.starts_with("the sealed setup-token was not unsealed (key \"ai-env-bridge\" does not exist"), "{why}");
        let audit = std::fs::read_to_string(sess.paths.audit()).unwrap();
        assert!(audit.contains("\"event\":\"credential_unseal\"") && audit.contains("\"outcome\":\"exit 4\""), "{audit}");
        assert_eq!(budget_text(Duration::from_secs(60)), "60 s");
        assert_eq!(budget_text(Duration::from_millis(1500)), "1500 ms");
    }

    /// F11: the unseal decrypts the very text whose seal id was checked
    /// against the refusals, never a second read of `setup-token.env`. The
    /// `AI_ENV_DIR` lookup comes between the check and the unseal; there the
    /// file is removed: the unseal still goes on with the text already read,
    /// to the keystore, which lacks the key (so `age` is never probed). A
    /// second read would have failed on the missing file instead.
    #[test]
    fn the_unseal_decrypts_the_text_whose_seal_was_checked() {
        let d = tempfile::tempdir().unwrap();
        let sess = session(Mode::LocalScratch, &["--output-format", "stream-json"], d.path());
        let keys = d.path().join("keys");
        let path = sess.paths.setup_token_env();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, crate::container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
        let env = |k: &str| -> Option<OsString> {
            if k == "AI_ENV_DIR" {
                let _ = std::fs::remove_file(&path);
                return Some(keys.clone().into_os_string());
            }
            None
        };
        let why = match scratch_login(&sess, &env, Duration::ZERO) {
            ScratchLogin::LoggedOut(why) => why,
            other => panic!("{}", other.word()),
        };
        assert!(!path.exists(), "the file was removed between the check and the unseal");
        assert!(why.starts_with("the sealed setup-token was not unsealed (key \"ai-env-bridge\" does not exist"), "the file was read again: {why}");
    }

    /// The unseal ends T−10 s into Cursor's 60 s initialize window, so a
    /// logged-out child can still answer in time: the default
    /// `[creds].unseal_timeout_s` (60 s) and the range's top become 50 s, a
    /// shorter budget (the lab knob's included) is kept, time already used
    /// counts in whole seconds, and a spent window leaves nothing.
    #[test]
    fn the_unseal_budget_ends_ten_seconds_before_the_initialize_window() {
        let s = Duration::from_secs;
        let default = crate::bridge::config::CredsCfg::default().unseal_budget();
        assert_eq!(default, s(60), "the default [creds].unseal_timeout_s");
        assert_eq!(scratch_unseal_budget(default, Duration::ZERO), (s(50), true));
        assert_eq!(scratch_unseal_budget(default, Duration::from_millis(900)), (s(50), true), "under a second comes out of the margin");
        assert_eq!(scratch_unseal_budget(default, Duration::from_millis(3_200)), (s(47), true));
        assert_eq!(scratch_unseal_budget(s(600), Duration::ZERO), (s(50), true));
        assert_eq!(scratch_unseal_budget(s(30), Duration::from_millis(200)), (s(30), false));
        assert_eq!(scratch_unseal_budget(Duration::from_millis(1500), Duration::ZERO), (Duration::from_millis(1500), false));
        assert_eq!(scratch_unseal_budget(default, s(55)), (Duration::ZERO, true));
    }

    /// A signal recorded before the dispositions were restored ends the wait
    /// whatever the answer — a dismissed dialog included, so the wrapper never
    /// spawns after being told to stop; without one the answer decides. Ctrl-C
    /// exits 130, SIGTERM and SIGHUP 143.
    #[test]
    fn a_signal_wins_over_any_answer_of_the_unseal() {
        let stopped = |r: crate::errors::Result<Unsealed>| match r {
            Ok(Unsealed::Stopped(sig)) => sig,
            Ok(Unsealed::Token(_)) => panic!("a token, not a stop"),
            Err(e) => panic!("an error, not a stop: {e}"),
        };
        let plain = || Zeroizing::new(format!("{TOKEN_VAR}={}oat01-{}\n", "sk-ant-", "Sw1_".repeat(12)).into_bytes());
        assert_eq!(stopped(unseal_outcome(Some(libc::SIGTERM), Some(Err(CliError::Cancelled)))), libc::SIGTERM, "a dismissed dialog and a SIGTERM: stop");
        assert_eq!(stopped(unseal_outcome(Some(libc::SIGHUP), Some(Err(CliError::AuthUnavailable("deadline".into()))))), libc::SIGHUP);
        assert_eq!(stopped(unseal_outcome(Some(libc::SIGINT), Some(Ok(plain())))), libc::SIGINT, "the plaintext is dropped");
        assert_eq!(stopped(unseal_outcome(Some(libc::SIGINT), None)), libc::SIGINT);
        assert!(matches!(unseal_outcome(None, Some(Err(CliError::Cancelled))), Err(CliError::Cancelled)));
        match unseal_outcome(None, Some(Ok(plain()))) {
            Ok(Unsealed::Token(t)) => assert_eq!(t.len(), plain().len() - TOKEN_VAR.len() - 2, "the value, without its name and newline"),
            _ => panic!("no token from a good answer"),
        }
        assert!(unseal_outcome(None, None).is_err());
        assert_eq!((stop_code(libc::SIGINT), stop_code(libc::SIGTERM), stop_code(libc::SIGHUP)), (130, 143, 143), "as vm exec's unseal");
    }

    /// F21: a stop that comes while `age` is being spawned — the decrypt past
    /// its `cancelled()` check, its child not adopted yet, so `kill_group`
    /// finds nothing to signal — waits for the decrypt's answer, which comes
    /// once the child was adopted, killed (the kill was marked first) and
    /// reaped: the wrapper never goes on to exit with the dialog's process
    /// group alive. The decrypt here stands for `AgeKill`'s: its child is a
    /// `sleep` in a group of its own, adopted 100 ms after the stop.
    #[test]
    fn a_stop_while_age_is_spawned_waits_until_its_group_is_gone() {
        use std::os::unix::process::CommandExt as _;
        let kill = Arc::new(AgeKill::new());
        let (tx, rx) = std::sync::mpsc::channel();
        let (pid_tx, pid_rx) = std::sync::mpsc::channel();
        let decrypt = Arc::clone(&kill);
        let worker = std::thread::spawn(move || {
            let mut child = std::process::Command::new("/bin/sleep").arg("30").process_group(0).spawn().expect("spawn sleep");
            let pgid = i32::try_from(child.id()).unwrap();
            pid_tx.send(pgid).unwrap();
            // The stop comes first; the adoption 100 ms later.
            let until = std::time::Instant::now() + Duration::from_secs(5);
            while !decrypt.cancelled() && std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(100));
            // What `AgeKill::adopt` does to a cancelled decrypt's child (and, were it never cancelled, the cleanup).
            // SAFETY: killpg(2) on our own unreaped child's group.
            unsafe { libc::killpg(pgid, libc::SIGKILL) };
            let _ = child.wait();
            let _ = tx.send(Err(CliError::Cancelled));
        });
        let pgid = pid_rx.recv().unwrap();
        let answer = await_unseal(&|| Some(libc::SIGTERM), &kill, &rx);
        // SAFETY: signal 0 only checks for existence.
        let alive = unsafe { libc::killpg(pgid, 0) } == 0;
        worker.join().unwrap();
        assert!(answer.is_none() && kill.cancelled(), "a stop wins, and marks the kill");
        assert!(!alive, "the wait for Touch ID ended on a stop while the decrypt's group was alive");
    }

    /// F21: the wait after a stop is bounded ([`STOP_SETTLE`]) for a decrypt
    /// that never answers; without a stop the answer decides, and a wait
    /// thread gone without one is an error, never a success.
    #[test]
    fn the_wait_after_a_stop_is_bounded_and_without_one_the_answer_decides() {
        let (tx, rx) = std::sync::mpsc::channel::<crate::errors::Result<Zeroizing<Vec<u8>>>>();
        let started = std::time::Instant::now();
        assert!(await_unseal(&|| Some(libc::SIGINT), &AgeKill::new(), &rx).is_none());
        let took = started.elapsed();
        assert!(took >= STOP_SETTLE - Duration::from_millis(20) && took < STOP_SETTLE + Duration::from_secs(2), "a stop waited {took:?} for a decrypt that never answers, not about {STOP_SETTLE:?}");
        tx.send(Err(CliError::Cancelled)).unwrap();
        assert!(matches!(await_unseal(&|| None, &AgeKill::new(), &rx), Some(Err(CliError::Cancelled))));
        drop(tx);
        assert!(matches!(await_unseal(&|| None, &AgeKill::new(), &rx), Some(Err(CliError::Msg(_)))), "no answer is no success");
    }

    /// The pipe fd delivery starts from: it holds the value and closes on exec.
    #[test]
    fn the_secret_pipe_holds_the_value_and_closes_on_exec() {
        let value = format!("pipe-dummy-{}", "p".repeat(24));
        let fd = secret_pipe(value.as_bytes()).unwrap();
        // SAFETY: F_GETFD on a valid fd we own.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC, "only the child's fd 3 survives exec");
        let mut got = String::new();
        std::io::Read::read_to_string(&mut std::fs::File::from(fd), &mut got).unwrap();
        assert!(got == value, "the pipe held {} bytes, not the {} written", got.len(), value.len());
    }

    /// Everything a `sh -c` child wrote on stdout. Its lines and its exit come
    /// from different tasks, in no fixed order, so this reads until it has
    /// seen both the end of stdout and the exit, as the pump does.
    async fn child_stdout(mut link: ChildLink) -> Vec<u8> {
        drop(link.input);
        let mut out = Vec::new();
        let (mut eof, mut exited) = (false, false);
        while !(eof && exited) {
            match link.events.recv().await {
                Some(ChildEvent::Line(l)) => {
                    out.extend_from_slice(&l);
                    out.push(b'\n');
                }
                Some(ChildEvent::StdoutEof) => eof = true,
                Some(ChildEvent::Exit(_)) => exited = true,
                Some(_) => {}
                None => break,
            }
        }
        out
    }

    /// `spawn_local` hands the token on fd 3 with the descriptor variable and
    /// no token variable, or (env) in the environment with no descriptor
    /// variable — removing what the environment already held, an empty token
    /// variable and a stale descriptor number; without a credential the
    /// child's environment is the plan's, untouched.
    #[tokio::test]
    async fn spawn_local_delivers_on_fd_3_or_in_the_environment() {
        let token = crate::bridge::setup_token::parse_token(&format!("{}oat01-{}", "sk-ant-", "Fd3_".repeat(10))).unwrap();
        // `-unset` without a colon: an empty variable prints as empty, an absent one as `unset`.
        let script = "if [ \"${CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR-}\" = 3 ]; then cat <&3; echo; fi; echo \"fd=${CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR-unset}\"; echo \"env=${CLAUDE_CODE_OAUTH_TOKEN-unset}\"";
        let plan = ChildPlan {
            program: PathBuf::from("/bin/sh"),
            argv: vec!["-c".into(), script.into()],
            // What the child would otherwise inherit: an empty token variable and a stale descriptor.
            env_set: vec![(TOKEN_VAR.to_string(), OsString::new()), (TOKEN_FD_VAR.to_string(), OsString::from("7"))],
            env_remove: Vec::new(),
            child_config_dir: PathBuf::from("/nonexistent"),
            scratch: None,
            resume: None,
            slug: None,
            mirror: mirror::decide(false, false, Path::new("/nonexistent"), Path::new("/nonexistent"), None),
        };
        let out = child_stdout(spawn_local(&plan, Some((&token, Deliver::Fd))).unwrap()).await;
        let want = format!("{}\nfd=3\nenv=unset\n", token.expose());
        assert!(out == want.as_bytes(), "fd delivery: {} bytes, expected {}", out.len(), want.len());
        let out = child_stdout(spawn_local(&plan, Some((&token, Deliver::Env))).unwrap()).await;
        let want = format!("fd=unset\nenv={}\n", token.expose());
        assert!(out == want.as_bytes(), "env delivery: {} bytes, expected {}", out.len(), want.len());
        let out = child_stdout(spawn_local(&plan, None).unwrap()).await;
        assert_eq!(out, b"fd=7\nenv=\n");
    }

    /// The wrapper's handlers by link kind: every piped mode answers
    /// `registry::DROP_TRANSPORT_SIGNAL` and (S10) `registry::MIGRATE_SIGNAL`
    /// (whose defaults would end the wrapper), a remote session alone
    /// listens to SIGHUP, as a SIGTERM, and a local one leaves SIGHUP as it
    /// found it. In a child run of this test binary, its SIGHUP, SIGUSR1 and
    /// SIGUSR2 at their defaults: tokio's handlers are never removed, and in
    /// the library's test process they would swallow the signals meant for
    /// `cargo test`.
    #[test]
    fn the_handlers_answer_drop_transport_everywhere_and_sighup_when_remote() {
        use std::os::unix::process::CommandExt as _;
        const TEST: &str = "bridge::pump::tests::the_handlers_answer_drop_transport_everywhere_and_sighup_when_remote";
        // The child's mark: its parent's pid, which no exported value matches.
        const PARENT: &str = "AI_ENV_TEST_PUMP_SIGNALS_PARENT";
        if std::env::var(PARENT).ok() == Some(std::os::unix::process::parent_id().to_string()) {
            return handlers_in_this_process();
        }
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([TEST, "--exact", "--test-threads=1"]).env(PARENT, std::process::id().to_string()).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // As from a terminal: a `nohup` above this run would hand SIGHUP down ignored.
        // SAFETY: runs in the forked child before exec; signal(2) is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGHUP, libc::SIG_DFL);
                libc::signal(registry::DROP_TRANSPORT_SIGNAL, libc::SIG_DFL);
                libc::signal(registry::MIGRATE_SIGNAL, libc::SIG_DFL);
                Ok(())
            });
        }
        let child = {
            // Held across the fork, as every fork of these tests holds it (`test_locks`).
            let _fork = crate::test_locks::forking();
            cmd.spawn().unwrap()
        };
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // A filter that matches nothing passes too: the count says it ran.
        assert!(out.status.success() && stdout.contains("test result: ok. 1 passed"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    }

    /// The child's half: each signal raised is answered (a missing handler
    /// would end this process, failing the parent's run).
    fn handlers_in_this_process() {
        // SAFETY: sigaction(2) with a null new action only reads into a zeroed (valid) struct.
        let disposition = |sig: libc::c_int| unsafe {
            let mut now: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(sig, std::ptr::null(), &raw mut now), 0);
            now.sa_sigaction
        };
        let raise = |sig: libc::c_int| {
            // SAFETY: raise(3) on this process, whose handler for `sig` tokio installed.
            assert_eq!(unsafe { libc::raise(sig) }, 0);
        };
        let hup_before = disposition(libc::SIGHUP);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let local = Signals::install(LinkKind::Local).unwrap();
            assert!(matches!(local, Signals::Os { hup: None, .. }), "a local session has no SIGHUP listener");
            assert_eq!(disposition(libc::SIGHUP), hup_before, "a local session leaves SIGHUP as it found it");
            assert_ne!(disposition(registry::DROP_TRANSPORT_SIGNAL), libc::SIG_DFL, "every piped mode answers the drop-transport signal");
            assert_ne!(disposition(registry::MIGRATE_SIGNAL), libc::SIG_DFL, "every piped mode answers session migrate's signal");
            drop(local);
            let mut remote = Signals::install(LinkKind::Remote).unwrap();
            raise(registry::DROP_TRANSPORT_SIGNAL);
            assert_eq!(tokio::time::timeout(Duration::from_secs(5), remote.recv()).await.unwrap(), HostSignal::DropTransport);
            raise(registry::MIGRATE_SIGNAL);
            assert_eq!(tokio::time::timeout(Duration::from_secs(5), remote.recv()).await.unwrap(), HostSignal::Migrate);
            if crate::bridge::signals::ignored(libc::SIGHUP) {
                eprintln!("SIGHUP was ignored when this run started: it stays ignored");
                return;
            }
            raise(libc::SIGHUP);
            assert_eq!(tokio::time::timeout(Duration::from_secs(5), remote.recv()).await.unwrap(), HostSignal::Term, "a remote session's SIGHUP is a SIGTERM");
        });
    }

    /// S8 W1, the link contract (plans/s8-design-tests.md §2.3): the pump
    /// over a remote link played by hand, as `remote::link` builds one (the
    /// first event `Started` or `SpawnFailed`; a `Sig::Term` cancelling a
    /// pending start; `Detached` after the wrapper's own detach; `Lost`;
    /// `Rejected`; `Link`), the host's stdio and signals in memory, on a
    /// `LocalSet` as `run` drives it.
    mod link_contract {
        use super::*;
        use crate::bridge::remote::link::RemoteSnapshot;
        use crate::bridge::remote::CLOSE_BUDGET_MS;
        use crate::wire::frame::SpawnId;
        use serde_json::Value;
        use std::cell::RefCell;

        /// Every wait's bound (timing is asserted where it is the point).
        const T: Duration = Duration::from_secs(5);
        const INIT: &str = r#"{"type":"control_request","request_id":"i1","request":{"subtype":"initialize"}}"#;
        const SID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

        fn on_local<F: std::future::Future>(f: F) -> F::Output {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            tokio::task::LocalSet::new().block_on(&rt, f)
        }

        /// The CLI's answer to request `id` (`body` its inner response).
        fn answer(id: &str, body: &str) -> String {
            format!(r#"{{"type":"control_response","response":{{"subtype":"success","request_id":"{id}","response":{body}}}}}"#)
        }

        fn init_frame(sid: &str) -> String {
            format!(r#"{{"type":"system","subtype":"init","session_id":"{sid}","cwd":"/w"}}"#)
        }

        fn user(n: u32) -> String {
            format!(r#"{{"type":"user","uuid":"{n:08x}-0000-4000-8000-{n:012x}","message":{{"role":"user","content":"line {n}"}}}}"#)
        }

        fn result_for(n: u32) -> String {
            format!(r#"{{"type":"result","subtype":"success","is_error":false,"session_id":"{SID}","user_message_uuid":"{n:08x}-0000-4000-8000-{n:012x}"}}"#)
        }

        /// S10: user line `n`'s uuid, its echo (`--replay-user-messages`), a
        /// top-level assistant frame, and the loss of a terminated VM.
        fn uuid_of(n: u32) -> String {
            format!("{n:08x}-0000-4000-8000-{n:012x}")
        }

        fn echo(n: u32) -> String {
            format!(r#"{{"type":"user","uuid":"{}","isReplay":true,"message":{{"role":"user","content":"line {n}"}}}}"#, uuid_of(n))
        }

        fn assistant(uuid: &str) -> String {
            format!(r#"{{"type":"assistant","uuid":"{uuid}","parent_tool_use_id":null,"message":{{"role":"assistant","content":[]}}}}"#)
        }

        fn gone(vm: &str) -> ChildEvent {
            ChildEvent::Lost(LinkLoss::of(&crate::bridge::errors::BridgeError::Terminated(format!("{vm} is TERMINATED")), vm, None))
        }

        /// One generation's far end, as the hand factory started it.
        struct Far {
            gen: u32,
            input: mpsc::Receiver<ChildInput>,
            signal: mpsc::UnboundedReceiver<Sig>,
            events: mpsc::Sender<ChildEvent>,
        }

        impl Far {
            async fn send(&self, ev: ChildEvent) {
                tokio::time::timeout(T, self.events.send(ev)).await.expect("the pump reads its link").expect("the link is open");
            }

            async fn line(&self, text: &str) {
                self.send(ChildEvent::Line(Bytes::from(text.to_string()))).await;
            }

            async fn started(&self) {
                self.send(ChildEvent::Started(RemoteStarted { spawn_id: SpawnId::new_v7(), vm_pid: 4000 + self.gen, claude_version: Some(crate::bridge::authwatch::AUTH_TIMERS.claude.into()) })).await;
            }

            async fn exit(&self, code: i32) {
                for ev in [ChildEvent::StdoutEof, ChildEvent::StderrEof, ChildEvent::Exit(Some(ExitStatus::from_raw(code << 8)))] {
                    self.send(ev).await;
                }
            }

            /// The next input line (without its newline), `None` at its EOF.
            async fn next_input(&mut self) -> Option<String> {
                match tokio::time::timeout(T, self.input.recv()).await.expect("input within the bound") {
                    Some(ChildInput::Line(b)) => Some(String::from_utf8_lossy(&b).trim_end().to_string()),
                    Some(ChildInput::Eof) | None => None,
                }
            }

            async fn next_signal(&mut self) -> Option<Sig> {
                tokio::time::timeout(T, self.signal.recv()).await.expect("a signal within the bound")
            }
        }

        /// What the hand factory saw, and the far ends it started.
        #[derive(Default)]
        struct Hand {
            fars: VecDeque<Far>,
            whys: Vec<StartWhy>,
            results: u32,
            drops: u32,
            snap: RemoteSnapshot,
            /// S10 §B: what `migration_due` answers (while set), how often it was asked, the phase A
            /// triggers asked for, what `begin_switch` answers and how often it was called.
            due: Option<MigrateTrigger>,
            asked_due: u32,
            prepares: Vec<MigrateTrigger>,
            switch: bool,
            switches: u32,
            /// S10 §D: the quiet the pump told after each line.
            quiet: Vec<QuietState>,
        }

        struct HandLinks(Rc<RefCell<Hand>>);

        impl LinkFactory for HandLinks {
            fn start(&mut self, gen: u32, req: StartReq<'_>) -> std::io::Result<ChildLink> {
                assert!(req.credential.is_none(), "a remote start carries no token");
                let (input, input_rx) = mpsc::channel(CHANNEL_CAP);
                let (signal, signal_rx) = mpsc::unbounded_channel();
                let (events_tx, events) = mpsc::channel(CHANNEL_CAP);
                let mut hand = self.0.borrow_mut();
                hand.whys.push(req.why);
                hand.fars.push_back(Far { gen, input: input_rx, signal: signal_rx, events: events_tx });
                Ok(ChildLink { pid: None, input, signal, events })
            }

            fn kind(&self) -> LinkKind {
                LinkKind::Remote
            }

            fn timings(&self) -> CloseTimings {
                CloseTimings::REMOTE
            }

            fn on_result(&mut self) {
                self.0.borrow_mut().results += 1;
            }

            fn snapshot(&self) -> Option<RemoteSnapshot> {
                Some(self.0.borrow().snap.clone())
            }

            fn drop_transport(&mut self) {
                self.0.borrow_mut().drops += 1;
            }

            fn quiet(&mut self, q: QuietState) {
                self.0.borrow_mut().quiet.push(q);
            }

            fn migration_due(&mut self) -> Option<MigrateTrigger> {
                let mut h = self.0.borrow_mut();
                h.asked_due += 1;
                h.due.clone()
            }

            fn prepare_move(&mut self, trigger: MigrateTrigger) {
                self.0.borrow_mut().prepares.push(trigger);
            }

            fn begin_switch(&mut self) -> bool {
                let mut h = self.0.borrow_mut();
                h.switches += 1;
                h.switch
            }
        }

        /// The host's side: its lines and signals into the pump, its stdout out.
        struct Host {
            lines: mpsc::Sender<HostIn>,
            signals: mpsc::UnboundedSender<HostSignal>,
            out: Rc<RefCell<Vec<Bytes>>>,
        }

        impl Host {
            async fn send(&self, line: &str) {
                tokio::time::timeout(T, self.lines.send(HostIn::Line(Bytes::from(line.to_string())))).await.expect("the pump reads the host").expect("the host channel is open");
            }

            async fn eof(&self) {
                let _ = self.lines.send(HostIn::Eof).await;
            }

            fn signal(&self, s: HostSignal) {
                let _ = self.signals.send(s);
            }

            /// Every line the host got, as written (with its newline).
            fn raw(&self) -> Vec<Vec<u8>> {
                self.out.borrow().iter().map(|b| b.to_vec()).collect()
            }

            fn json(&self) -> Vec<Value> {
                self.out.borrow().iter().filter_map(|b| serde_json::from_slice(b).ok()).collect()
            }

            /// Wait until the host got a line `pred` accepts; that line.
            async fn wait_for(&self, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
                let until = Instant::now() + T;
                loop {
                    if let Some(v) = self.json().into_iter().find(|v| pred(v)) {
                        return v;
                    }
                    assert!(Instant::now() < until, "the host never got {what}: {:?}", self.json());
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        }

        /// A remote session in `dir` (`extra` after the stream-json argv).
        fn remote_session(dir: &Path, extra: &[&str]) -> Session {
            let mut args: Vec<String> = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json"].iter().map(|s| (*s).to_string()).collect();
            args.extend(extra.iter().map(|s| (*s).to_string()));
            let route = argv::classify(&args);
            let Route::Remote(session) = route.clone() else { panic!("not a session: {route:?}") };
            let mut row = start_row();
            (row.route, row.reason, row.note, row.start) = ("remote".into(), "session".into(), Some("mode:remote".into()), unix_now_ms());
            Session { real_binary: PathBuf::from("/bin/claude"), args, route, session, cwd: Some(dir.to_path_buf()), paths: Paths::from_root_and_env(dir.join("bridge"), None), cfg: None, mode: Mode::Remote, start_row: row }
        }

        /// A remote session in `dir` (`extra` after the stream-json argv),
        /// its pump on the hand factory, its host, and the pump's host side.
        fn remote_pump(dir: &Path, extra: &[&str]) -> (Pump, Rc<RefCell<Hand>>, Host, HostIo) {
            let sess = remote_session(dir, extra);
            let plan = child_plan(&sess, &env_of(vec![("HOME", dir.as_os_str().to_owned())]), &mut || "x".to_string()).unwrap();
            let hand = Rc::new(RefCell::new(Hand::default()));
            let pump = Pump::new(sess, plan, None, Box::new(HandLinks(Rc::clone(&hand))));
            let (lines_tx, lines) = mpsc::channel(CHANNEL_CAP);
            let (signals_tx, signals) = mpsc::unbounded_channel();
            let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(CHANNEL_CAP);
            let out = Rc::new(RefCell::new(Vec::new()));
            let sink = Rc::clone(&out);
            let writer = tokio::task::spawn_local(async move {
                while let Some(b) = out_rx.recv().await {
                    sink.borrow_mut().push(b);
                }
            });
            (pump, hand, Host { lines: lines_tx, signals: signals_tx, out }, HostIo { lines, out: out_tx, writer, signals: Signals::Scripted(signals) })
        }

        fn supervise(mut pump: Pump, io: HostIo) -> tokio::task::JoinHandle<(i32, Pump)> {
            tokio::task::spawn_local(async move {
                let code = pump.supervise_with(io).await;
                (code, pump)
            })
        }

        async fn ended(task: tokio::task::JoinHandle<(i32, Pump)>) -> (i32, Pump) {
            tokio::time::timeout(T, task).await.expect("the pump finished within the bound").expect("the pump task")
        }

        /// The generation the pump started next.
        async fn far(hand: &Rc<RefCell<Hand>>) -> Far {
            let until = Instant::now() + T;
            loop {
                if let Some(f) = hand.borrow_mut().fars.pop_front() {
                    return f;
                }
                assert!(Instant::now() < until, "the pump started no generation");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        /// The census end row's note `conclude` wrote.
        fn end_note(pump: &Pump) -> String {
            let rows = census::read_rows(&pump.sess.paths.census(), None).unwrap();
            rows.last().and_then(|r| r["note"].as_str()).unwrap_or_default().to_string()
        }

        fn registry_row(pump: &Pump, sid: &str) -> SessionRow {
            registry::read(&pump.sess.paths, sid).unwrap().expect("the session's row")
        }

        /// The far end answers `initialize` (pid 4242) and starts the session `sid`.
        async fn handshake(host: &Host, far: &mut Far, sid: &str) {
            host.send(INIT).await;
            assert_eq!(far.next_input().await.as_deref(), Some(INIT));
            far.line(&answer("i1", r#"{"pid":4242}"#)).await;
            far.line(&init_frame(sid)).await;
            host.wait_for("the init", |v| v["type"] == "system").await;
        }

        /// M01, M02: a remote start that ends before `spawned` is
        /// `SpawnFailed`, never `Exit(None)`: the wrapper exits with each
        /// failure's own code, its line is the one it ends with, the census
        /// ends `spawn_failed` naming the step, and the host gets nothing.
        #[test]
        fn a_refused_spawn_is_spawn_failed_not_exit_none() {
            let cases = [
                (StartStep::TouchId, Failure::TouchIdCancelled, 3),
                (StartStep::TouchId, Failure::TouchIdTimeout { secs: 47 }, 5),
                (StartStep::SelectVm, Failure::MaxConcurrent { running: 3, parked: Vec::new() }, 9),
                (StartStep::SelectVm, Failure::Select { code: 8, first_line: "microvm not found".into() }, 8),
                (StartStep::Workspace, Failure::Finding { finding: "untracked .env: rule env-file-plaintext".into() }, 9),
                (StartStep::Spawn, Failure::OldImage { vm: "microvm-1".into(), cap: crate::wire::frame::CAP_WORKSPACE_V1 }, 7),
                (StartStep::Deadline, Failure::Deadline { code: 5, step: "touchid" }, 5),
                (StartStep::Spawn, Failure::Other { code: 1, step: "spawn", first_line: "broken pipe".into() }, 1),
            ];
            for (step, failure, code) in cases {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                    let task = supervise(pump, io);
                    host.send(INIT).await;
                    let far = far(&hand).await;
                    far.send(ChildEvent::SpawnFailed(SpawnFailure::from_failure(step, &failure, Some("microvm-1".into())))).await;
                    let (got, mut pump) = ended(task).await;
                    assert_eq!((got, pump.finish.map(|f| f.1)), (code, Some(EndReason::SpawnFailed)), "{failure:?}");
                    assert_eq!(pump.final_line.as_deref(), Some(failure.line().as_str()), "the failure's line");
                    let out = pump.conclude(got);
                    assert_eq!((out.code, out.step), (Some(code), Some(step.name())));
                    let note = end_note(&pump);
                    assert!(note.contains("end:spawn_failed") && note.contains(&format!("; step:{}", step.name())), "{note}");
                    assert!(host.raw().is_empty(), "nothing reached the host");
                });
            }
        }

        /// M05: while the start is pending (a Touch ID, a cold boot) the host
        /// is still read, past what the link's and the host's channels hold
        /// (the local rule stops at two queued lines): the lines reach the
        /// spawn in order, `initialize` first, once it started.
        #[test]
        fn a_slow_start_buffers_host_lines_in_order() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                let users: Vec<String> = (0..300).map(user).collect();
                tokio::time::timeout(Duration::from_secs(2), async {
                    host.send(INIT).await;
                    for u in &users {
                        host.send(u).await;
                    }
                })
                .await
                .expect("the host is read while the start is pending");
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert!(!task.is_finished());
                far.started().await;
                assert_eq!(far.next_input().await.as_deref(), Some(INIT), "initialize first");
                for u in &users {
                    assert_eq!(far.next_input().await.as_deref(), Some(u.as_str()));
                }
                host.eof().await;
                assert_eq!(far.next_input().await, None, "the host's EOF after its lines");
                far.exit(0).await;
                let (code, pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (0, Some(EndReason::EofTerm)));
            });
        }

        /// M06: a host EOF while the start is pending cancels it at once
        /// (`Sig::Term` now, never at the EOF ladder's +0.8 s: the spawn
        /// never goes out, a Touch ID dialog closes); the cancelled start
        /// exits 0 with no line, within the close budget. A start that never
        /// answers is ended by the remote hard stop (1.4 s), the same way.
        #[test]
        fn eof_before_the_start_resolves_sends_no_spawn_and_exits_within_budget() {
            for answers in [true, false] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                    let task = supervise(pump, io);
                    let mut far = far(&hand).await;
                    host.send(INIT).await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    let eof_at = Instant::now();
                    host.eof().await;
                    assert_eq!(far.next_signal().await, Some(Sig::Term), "answers {answers}");
                    assert!(eof_at.elapsed() < Duration::from_millis(800), "the cancel waited {:?} (the EOF ladder's TERM rung)", eof_at.elapsed());
                    if answers {
                        far.send(ChildEvent::SpawnFailed(SpawnFailure::stopped(StartStep::TouchId, None))).await;
                    }
                    let (code, pump) = ended(task).await;
                    let took = eof_at.elapsed();
                    assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "EOF to the end took {took:?}");
                    assert_eq!((code, pump.finish.map(|f| f.1)), (0, Some(EndReason::EofTerm)), "answers {answers}");
                    assert_eq!(pump.final_line, None, "a host that closed hears nothing");
                    assert!(!host.raw().iter().any(|l| l.starts_with(b"{\"type\":\"control_response\"")), "no spawn answered anything");
                });
            }
        }

        /// M07: a SIGTERM while the start is pending cancels it at once (it
        /// never waits for `spawned`): 143 within 1000 ms, the line saying
        /// nothing was started; one that never answers is ended by the
        /// SIGTERM hard stop (0.9 s), the same way.
        #[test]
        fn sigterm_before_the_start_resolves_cancels_it() {
            for answers in [true, false] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                    let task = supervise(pump, io);
                    let mut far = far(&hand).await;
                    let term_at = Instant::now();
                    host.signal(HostSignal::Term);
                    assert_eq!(far.next_signal().await, Some(Sig::Term));
                    if answers {
                        far.send(ChildEvent::SpawnFailed(SpawnFailure::stopped(StartStep::TouchId, None))).await;
                    }
                    let (code, pump) = ended(task).await;
                    let took = term_at.elapsed();
                    assert!(took < Duration::from_millis(1000), "SIGTERM to the end took {took:?}");
                    assert_eq!((code, pump.finish.map(|f| f.1)), (143, Some(EndReason::SigTerm)), "answers {answers}");
                    assert_eq!(pump.final_line.as_deref(), Some(Failure::Stopped.line().as_str()));
                });
            }
        }

        /// M08: a link that goes down is not an exit (the row says
        /// `detached`, then `active` again); one lost past its budget for a
        /// cause no move takes (`NotMovable`) ends the wrapper with the
        /// loss's code and line (`end:link_lost`). S10: one lost with its VM
        /// gone (`VmGone`) is no exit either: it starts a move.
        #[test]
        fn a_lost_link_is_not_an_exit() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                far.started().await;
                handshake(&host, &mut far, SID).await;
                host.send(&user(1)).await;
                assert!(far.next_input().await.is_some());
                far.send(ChildEvent::Link(false)).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert!(!task.is_finished(), "a link down is no exit");
                let status = |dir: &Path| registry::read(&Paths::from_root_and_env(dir.join("bridge"), None), SID).unwrap().map(|r| r.status);
                assert_eq!(status(d.path()).as_deref(), Some("detached"));
                far.send(ChildEvent::Link(true)).await;
                far.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                assert_eq!(status(d.path()).as_deref(), Some("active"));
                let loss = LinkLoss::from_failure(&Failure::LinkLost { vm: "microvm-1".into() });
                assert_eq!(loss.cause, LossCause::NotMovable);
                far.send(ChildEvent::Lost(loss.clone())).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (8, Some(EndReason::LinkLost)));
                assert_eq!(pump.final_line.as_deref(), Some(loss.line.as_str()));
                pump.conclude(code);
                assert!(end_note(&pump).contains("end:link_lost"));
                assert_eq!(registry_row(&pump, SID).status, "closed");
                assert_eq!(hand.borrow().whys, [StartWhy::First], "no move");
            });
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut far1 = far(&hand).await;
                far1.started().await;
                handshake(&host, &mut far1, SID).await;
                host.send(&user(1)).await;
                assert!(far1.next_input().await.is_some());
                far1.send(gone("microvm-1")).await;
                let mut far2 = far(&hand).await;
                assert!(matches!(&hand.borrow().whys[..], [StartWhy::First, StartWhy::Move(m)] if m.kind == MoveKind::Readdress && m.cause == Some(LossCause::VmGone)), "{:?}", hand.borrow().whys);
                assert!(!task.is_finished(), "a lost VM is no exit");
                far2.started().await;
                host.eof().await;
                while far2.next_input().await.is_some() {}
                far2.exit(0).await;
                let (code, _) = ended(task).await;
                assert_eq!(code, 0);
            });
        }

        /// With the link down at the host's EOF nothing comes back: the
        /// remote ladder still sends `detach{final}` (`Sig::Kill`) at +1.2 s
        /// and the hard stop ends the wrapper at +1.4 s, exit 0.
        #[test]
        fn with_the_link_down_at_eof_the_hard_stop_still_holds() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                far.started().await;
                handshake(&host, &mut far, SID).await;
                far.send(ChildEvent::Link(false)).await;
                let eof_at = Instant::now();
                host.eof().await;
                assert_eq!(far.next_input().await, None, "stdin_eof at once");
                assert_eq!(far.next_signal().await, Some(Sig::Kill), "no TERM from the Mac after EOF");
                let kill = eof_at.elapsed();
                assert!(kill >= Duration::from_millis(1150) && kill < Duration::from_millis(CLOSE_BUDGET_MS), "detach at {kill:?}");
                let (code, pump) = ended(task).await;
                let took = eof_at.elapsed();
                assert!(took < Duration::from_millis(CLOSE_BUDGET_MS), "EOF to the end took {took:?}");
                assert_eq!((code, pump.finish.map(|f| f.1)), (0, Some(EndReason::EofKill)));
            });
        }

        /// The wrapper's own detach ends a started link: 0 after the host's
        /// EOF (at the ladder's +1.2 s), 143 after a signal (at once, after
        /// `Sig::Term`, which is `Signal(Term)` plus the detach); either close
        /// is timed in the end row (`close_ms`, from the EOF or the signal).
        #[test]
        fn a_detached_link_ends_0_after_eof_and_143_after_a_signal() {
            for eof in [true, false] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                    let task = supervise(pump, io);
                    let mut far = far(&hand).await;
                    far.started().await;
                    handshake(&host, &mut far, SID).await;
                    if eof {
                        host.eof().await;
                        assert_eq!(far.next_input().await, None);
                        assert_eq!(far.next_signal().await, Some(Sig::Kill));
                    } else {
                        host.signal(HostSignal::Term);
                        assert_eq!(far.next_signal().await, Some(Sig::Term));
                    }
                    far.send(ChildEvent::Detached).await;
                    let (code, mut pump) = ended(task).await;
                    let want = if eof { (0, EndReason::EofKill) } else { (143, EndReason::SigTerm) };
                    assert_eq!((code, pump.finish.map(|f| f.1).unwrap()), want, "eof {eof}");
                    assert_eq!(pump.final_line, None);
                    let ms = pump.conclude(code).close_ms.expect("the close is timed");
                    assert!(end_note(&pump).split("; ").any(|p| p == format!("close_ms:{ms}")), "eof {eof}: {}", end_note(&pump));
                });
            }
        }

        /// The CLI's own exit after the host's EOF (no TERM from the Mac,
        /// L2) keeps its code: the remote EOF ladder signals nothing first.
        #[test]
        fn the_clis_own_exit_after_eof_keeps_its_code() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                far.started().await;
                handshake(&host, &mut far, SID).await;
                host.eof().await;
                assert_eq!(far.next_input().await, None);
                tokio::time::sleep(Duration::from_millis(300)).await;
                assert!(far.signal.try_recv().is_err(), "no signal before +1.2 s");
                far.exit(3).await;
                let (code, pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (3, Some(EndReason::EofTerm)));
            });
        }

        /// M28, the resume miss on the remote link: generation 1 reports the
        /// CLI's miss and exits 1; generation 2 starts as the retry of that
        /// session (its pipeline restores the transcript from S3 first), the host's
        /// state is replayed to it, its answer to the replayed `initialize`
        /// reaches the host under the host's id with the wrapper's pid (and
        /// times the session's `init_ms`), and the miss itself never reaches
        /// the host.
        #[test]
        fn the_resume_miss_path_keeps_its_meaning_on_the_remote_link() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let resume = format!("--resume={SID}");
                let (pump, hand, host, io) = remote_pump(d.path(), &[&resume]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                host.send(INIT).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(INIT));
                let miss = format!(r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"x","errors":["No conversation found with session ID: {SID}"]}}"#);
                gen1.line(&miss).await;
                gen1.exit(1).await;
                let mut gen2 = far(&hand).await;
                assert_eq!(hand.borrow().whys, [StartWhy::First, StartWhy::ResumeRetry { session_id: SID.to_string(), init_answered: false }], "the host still waits: the retry keeps Cursor's window");
                gen2.started().await;
                let replayed = gen2.next_input().await.expect("the replayed initialize");
                let v: Value = serde_json::from_str(&replayed).unwrap();
                assert_eq!(v["request"]["subtype"], "initialize");
                let fresh = v["request_id"].as_str().unwrap().to_string();
                assert_ne!(fresh, "i1", "replayed under a fresh id");
                gen2.line(&answer(&fresh, r#"{"pid":4242}"#)).await;
                gen2.line(&init_frame(SID)).await;
                host.wait_for("the init", |v| v["type"] == "system").await;
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                let answers: Vec<Value> = host.json().into_iter().filter(|v| v["type"] == "control_response").collect();
                assert_eq!(answers.len(), 1, "{answers:?}");
                assert_eq!((answers[0]["response"]["request_id"].as_str(), answers[0]["response"]["response"]["pid"].as_u64()), (Some("i1"), Some(u64::from(std::process::id()))));
                assert!(!host.json().iter().any(|v| v["type"] == "result"), "the miss never reached the host");
                let out = pump.conclude(code);
                assert_eq!(out.respawns, 1);
                assert!(out.init_latency_ms.is_some(), "the retry's answer, the first the host got, is the session's init_ms");
                assert!(end_note(&pump).split("; ").any(|p| p.starts_with("init_ms:")), "{}", end_note(&pump));
                let audit = std::fs::read_to_string(pump.sess.paths.audit()).unwrap();
                assert!(audit.contains("\"event\":\"resume_seed_retry\"") && audit.contains("\"source\":\"s3\""), "{audit}");
            });
        }

        /// S8 phase 4 (TIMING-3): a miss after generation 1 answered the
        /// host's `initialize` (the CLI read a user line first) starts the
        /// retry `init_answered`: Cursor's 60 s window is over, so its start
        /// has a window of its own (`pipeline::deadline_of`); M28's miss
        /// before the answer starts it unanswered.
        #[test]
        fn a_miss_after_the_answer_starts_the_retry_answered() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let resume = format!("--resume={SID}");
                let (pump, hand, host, io) = remote_pump(d.path(), &[&resume]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                host.send(INIT).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(INIT));
                gen1.line(&answer("i1", r#"{"pid":4242}"#)).await;
                host.wait_for("the initialize answer", |v| v["response"]["request_id"] == "i1").await;
                gen1.line(&format!(r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"x","errors":["No conversation found with session ID: {SID}"]}}"#)).await;
                gen1.exit(1).await;
                let mut gen2 = far(&hand).await;
                assert_eq!(hand.borrow().whys, [StartWhy::First, StartWhy::ResumeRetry { session_id: SID.to_string(), init_answered: true }]);
                gen2.started().await;
                host.eof().await;
                while gen2.next_input().await.is_some() {}
                gen2.exit(0).await;
                let (code, _) = ended(task).await;
                assert_eq!(code, 0);
            });
        }

        /// S8 phase 4 (RESUME-2): each generation's `vms` entry ends with its
        /// child: generation 1's before the resume miss's retry moves the
        /// session on (the retry's row write carries it closed), the
        /// retry's at its own end, so the closed row's history ends both.
        /// The host's user line before the miss lets the retry's init write
        /// the row.
        #[test]
        fn each_generations_vms_entry_ends_with_it_across_a_retry() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let resume = format!("--resume={SID}");
                let (pump, hand, host, io) = remote_pump(d.path(), &[&resume]);
                let paths = pump.sess.paths.clone();
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                host.send(INIT).await;
                host.send(&user(1)).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(INIT));
                assert!(gen1.next_input().await.is_some(), "the user line");
                gen1.line(&format!(r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"x","errors":["No conversation found with session ID: {SID}"]}}"#)).await;
                gen1.exit(1).await;
                let mut gen2 = far(&hand).await;
                gen2.started().await;
                let replayed: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                assert!(gen2.next_input().await.is_some_and(|l| l.contains("\"type\":\"user\"")), "the replayed user line");
                gen2.line(&answer(replayed["request_id"].as_str().unwrap(), r#"{"pid":4242}"#)).await;
                gen2.line(&init_frame(SID)).await;
                host.wait_for("the init", |v| v["type"] == "system").await;
                let ended_of = |vms: &[toml::Value]| vms.iter().map(|v| (v["gen"].as_integer(), v.get("to").is_some())).collect::<Vec<_>>();
                let row = registry::read(&paths, SID).unwrap().expect("the session's row");
                assert_eq!(ended_of(&row.vms), [(Some(1), true), (Some(2), false)], "generation 1 ended before the retry ran: {:?}", row.vms);
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, mut pump) = ended(task).await;
                pump.conclude(code);
                let row = registry_row(&pump, SID);
                assert_eq!((row.status.as_str(), ended_of(&row.vms)), ("closed", vec![(Some(1), true), (Some(2), true)]), "{:?}", row.vms);
            });
        }

        /// S8 phase 4 (RESUME-2, the hard stop): with the link down at the
        /// host's EOF the generation's exit never comes; the wrapper's end
        /// ends its `vms` entry, so the closed row records no generation as
        /// still running.
        #[test]
        fn the_hard_stop_ends_the_generations_vms_entry() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                far.started().await;
                handshake(&host, &mut far, SID).await;
                host.send(&user(1)).await;
                assert!(far.next_input().await.is_some());
                far.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                far.send(ChildEvent::Link(false)).await;
                host.eof().await;
                assert_eq!(far.next_input().await, None);
                assert_eq!(far.next_signal().await, Some(Sig::Kill));
                let (code, mut pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (0, Some(EndReason::EofKill)));
                pump.conclude(code);
                let row = registry_row(&pump, SID);
                assert_eq!((row.status.as_str(), row.vms.len()), ("closed", 1));
                assert!(row.vms[0].get("to").is_some(), "{:?}", row.vms);
            });
        }

        /// A spawn failure on the seed retry ends the wrapper `spawn_failed`
        /// with that failure's code, line and step.
        #[test]
        fn a_spawn_failure_on_the_seed_retry_ends_spawn_failed() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let resume = format!("--resume={SID}");
                let (pump, hand, host, io) = remote_pump(d.path(), &[&resume]);
                let task = supervise(pump, io);
                let gen1 = far(&hand).await;
                gen1.started().await;
                host.send(INIT).await;
                gen1.line(&format!(r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"errors":["No conversation found with session ID: {SID}"]}}"#)).await;
                gen1.exit(1).await;
                let gen2 = far(&hand).await;
                let failure = Failure::Workspace { code: 9, first_line: "workspace refused (symlink_component): PUT /transcript".into() };
                gen2.send(ChildEvent::SpawnFailed(SpawnFailure::from_failure(StartStep::Workspace, &failure, Some("microvm-1".into())))).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (9, Some(EndReason::SpawnFailed)));
                assert_eq!(pump.final_line.as_deref(), Some(failure.line().as_str()));
                pump.conclude(code);
                let note = end_note(&pump);
                assert!(note.contains("end:spawn_failed") && note.contains("; step:workspace") && note.contains("; respawns:1"), "{note}");
            });
        }

        /// M03, M04: the forwarded answer to the host's `initialize` carries
        /// the wrapper's pid; another answer that names a pid passes byte
        /// for byte (`pid_rewrite:ok`), one naming it once too (the rewrite
        /// would take that one: phase 4's mutation check); an `initialize`
        /// answer whose pid is not found once passes as it came
        /// (`pid_rewrite:failed`).
        #[test]
        fn only_the_initialize_answer_gets_the_wrappers_pid() {
            for once in [true, false] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                    let task = supervise(pump, io);
                    let mut far = far(&hand).await;
                    far.started().await;
                    let status = r#"{"type":"control_request","request_id":"m1","request":{"subtype":"mcp_status"}}"#;
                    let status2 = r#"{"type":"control_request","request_id":"m2","request":{"subtype":"mcp_status"}}"#;
                    host.send(INIT).await;
                    host.send(status).await;
                    host.send(status2).await;
                    assert_eq!(far.next_input().await.as_deref(), Some(INIT));
                    assert_eq!(far.next_input().await.as_deref(), Some(status));
                    assert_eq!(far.next_input().await.as_deref(), Some(status2));
                    let other = answer("m1", r#"{"mcpServers":[{"name":"x","pid":4242}],"pid":4242}"#);
                    far.line(&other).await;
                    let lone = answer("m2", r#"{"pid":4242}"#);
                    far.line(&lone).await;
                    let init_body = if once { r#"{"commands":[],"pid":4242}"# } else { r#"{"commands":[{"pid":4242}],"pid":4242}"# };
                    far.line(&answer("i1", init_body)).await;
                    host.wait_for("the initialize answer", |v| v["response"]["request_id"] == "i1").await;
                    host.eof().await;
                    far.exit(0).await;
                    let (code, mut pump) = ended(task).await;
                    let raw = host.raw();
                    assert_eq!(raw[0], format!("{other}\n").into_bytes(), "another answer passes byte for byte");
                    assert_eq!(raw[1], format!("{lone}\n").into_bytes(), "one naming its pid once too: only initialize's is rewritten");
                    let want = if once { answer("i1", &format!(r#"{{"commands":[],"pid":{}}}"#, std::process::id())) } else { answer("i1", init_body) };
                    assert_eq!(String::from_utf8_lossy(&raw[2]), format!("{want}\n"));
                    assert_eq!(pump.conclude(code).pid_rewrite, Some(if once { "ok" } else { "failed" }));
                    assert!(end_note(&pump).ends_with(&format!("; pid_rewrite:{}", if once { "ok" } else { "failed" })));
                });
            }
        }

        /// The 2.1.296 fixture's `rate_limit_event` line reaches the host byte
        /// for byte (the S7 B16 hand-off).
        #[test]
        fn a_rate_limit_event_line_passes_byte_identical() {
            let line = include_str!("../../tests/fixtures/claude/valid-stream-json-2.1.296.jsonl").lines().find(|l| l.contains("rate_limit_event")).unwrap().to_string();
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                far.started().await;
                handshake(&host, &mut far, SID).await;
                far.line(&line).await;
                host.wait_for("the rate limit line", |v| v["type"] == "rate_limit_event").await;
                host.eof().await;
                far.exit(0).await;
                ended(task).await;
                assert!(host.raw().contains(&format!("{line}\n").into_bytes()));
            });
        }

        /// S7 D6 on the remote link: AuthWatch's verdict stops the session
        /// (`Sig::Term`: `Signal(Term)` plus the detach) and the wrapper
        /// exits 5 with D6's line, `end:credential_rejected`, whatever the
        /// link's end after it; the seal the VM's row names is recorded as
        /// refused (the sealed file's when the row names none).
        #[test]
        fn a_rejected_token_stops_the_session_with_5_and_records_its_seal() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let paths = pump.sess.paths.clone();
                let token_env = paths.setup_token_env();
                std::fs::create_dir_all(token_env.parent().unwrap()).unwrap();
                std::fs::write(&token_env, "a sealed text\n").unwrap();
                let tag = crate::bridge::agent::credential::seal_tag(&token_env).unwrap();
                hand.borrow_mut().snap.vm = Some("microvm-1".into());
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                far.started().await;
                handshake(&host, &mut far, SID).await;
                far.send(ChildEvent::Rejected { how: "text" }).await;
                assert_eq!(far.next_signal().await, Some(Sig::Term));
                far.send(ChildEvent::Detached).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (5, Some(EndReason::CredentialRejected)));
                assert_eq!(pump.final_line.as_deref(), Some(Failure::TokenRefused.line().as_str()));
                let refused = crate::bridge::agent::credential::read_rejection(&paths, &tag).unwrap().expect("the seal is recorded as refused");
                assert_eq!(refused.vm, "microvm-1");
                pump.conclude(code);
                assert!(end_note(&pump).contains("end:credential_rejected"));
                assert_eq!(REJECTED_STATUS, Failure::TokenRefused.exit_code());
            });
        }

        /// A remote session's registry row and census end row come from its
        /// link: the VM, the spawn, the last stdout seq handed over, the
        /// seeded head, one `vms` entry per generation; the census's remote
        /// parts, `close_ms` before `link_drops`, `pid_rewrite`, and S7's
        /// `credential` (the pipeline's delivery). A forwarded result asks
        /// the link for a code-out; the drop-transport signal reaches the
        /// link. The audit row `session_remote_end` follows the end row.
        #[test]
        fn the_row_and_the_census_of_a_remote_session_come_from_its_link() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let spawn = SpawnId::new_v7();
                hand.borrow_mut().snap = RemoteSnapshot {
                    vm: Some("microvm-1".into()),
                    vm_how: Some("reused"),
                    spawn: Some(spawn.clone()),
                    last_acked_seq: 7,
                    seeded_head: Some("a".repeat(40)),
                    credential: Some("combined"),
                    fetch_ok: 1,
                    fetch_runs: 1,
                    link_drops: 1,
                    ..RemoteSnapshot::default()
                };
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                far.started().await;
                handshake(&host, &mut far, SID).await;
                host.send(&user(1)).await;
                assert!(far.next_input().await.is_some());
                far.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                assert_eq!(hand.borrow().results, 1, "a forwarded result asks for a code-out");
                host.signal(HostSignal::DropTransport);
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert_eq!(hand.borrow().drops, 1);
                host.eof().await;
                assert_eq!(far.next_input().await, None);
                far.exit(0).await;
                let (code, mut pump) = ended(task).await;
                pump.conclude(code);
                let row = registry_row(&pump, SID);
                assert_eq!((row.mode.as_str(), row.status.as_str(), row.child_pid), ("remote", "closed", None));
                assert_eq!((row.microvm_id.as_deref(), row.spawn_id.clone(), row.last_acked_seq), (Some("microvm-1"), Some(spawn.to_string()), Some(7)));
                assert_eq!(row.seeded_head, Some("a".repeat(40)));
                assert_eq!(row.vms.len(), 1);
                assert_eq!((row.vms[0]["gen"].as_integer(), row.vms[0]["vm"].as_str()), (Some(1), Some("microvm-1")));
                assert!(row.vms[0].get("to").is_some(), "{:?}", row.vms);
                assert_eq!(row.child_config_dir, Some(d.path().join(".claude").display().to_string()), "the VM's config dir: the Mac HOME's .claude");
                let note = end_note(&pump);
                for part in ["end:eof", "vm:microvm-1", "vm_how:reused", "fetch:1/1", "pid_rewrite:ok", "credential:combined"] {
                    assert!(note.split("; ").any(|p| p == part), "{part} in {note}");
                }
                let close = note.find("; close_ms:").expect("close_ms");
                assert!(close < note.find("; link_drops:1").expect("link_drops"), "close_ms before link_drops: {note}");
                assert!(note.split("; ").any(|p| p.starts_with("init_ms:")), "{note}");
                assert!(!note.contains(INIT_ID_REFUSED_PART), "no refusal, no part: {note}");
                let audit = std::fs::read_to_string(pump.sess.paths.audit()).unwrap();
                let ends: Vec<Value> = audit.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|v| v["event"] == "session_remote_end").collect();
                assert_eq!(ends.len(), 1, "{audit}");
                let (row, detail) = (&ends[0], &ends[0]["detail"]);
                assert_eq!(row["session_id"], SID);
                let spawn = spawn.to_string();
                for (key, want) in [("vm", "microvm-1"), ("spawn", spawn.as_str()), ("gen", "1"), ("exit", "0"), ("end", "eof"), ("last_acked_seq", "7")] {
                    assert_eq!(detail[key], want, "{key}: {detail}");
                }
                assert!(detail["close_ms"].as_str().is_some_and(|ms| ms.parse::<u64>().is_ok()), "{detail}");
            });
        }

        /// A remote session writes none of the VM's frames on this Mac (S9:
        /// its transcript is kept in S3): one naming its own project and one
        /// naming another of the Mac's (a forgery the VM can print, a
        /// subagent's `.meta.json` included) are dropped alike and counted
        /// (`mirror:0/0`, `mirror_dropped:3`), nothing created under the
        /// Mac's projects dir; none reaches the host.
        #[test]
        fn a_remote_sessions_frames_are_dropped_whatever_project_they_name() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let slug = pump.plan.slug.clone().expect("the cwd's slug");
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                far.started().await;
                handshake(&host, &mut far, SID).await;
                let projects = d.path().join(".claude").join("projects");
                let frame = |project: &str, rel: &str, entry: &str| format!(r#"{{"type":"transcript_mirror","filePath":"{}","entries":[{entry}]}}"#, projects.join(project).join(rel).display());
                let other = "-Users-someone-else-project";
                far.line(&frame(other, &format!("{SID}.jsonl"), r#"{"type":"user","message":"injected by the VM"}"#)).await;
                far.line(&frame(other, &format!("{SID}/subagents/agent-a1.jsonl"), r#"{"type":"agent_metadata","agentType":"x"}"#)).await;
                far.line(&frame(&slug, &format!("{SID}.jsonl"), r#"{"type":"user","message":"the session's own"}"#)).await;
                far.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                host.eof().await;
                assert_eq!(far.next_input().await, None);
                far.exit(0).await;
                let (code, mut pump) = ended(task).await;
                pump.conclude(code);
                assert!(!projects.exists(), "nothing was created on this Mac, its own project's frame neither");
                let note = end_note(&pump);
                assert!(note.split("; ").any(|p| p == "mirror:0/0") && note.split("; ").any(|p| p == "mirror_dropped:3"), "{note}");
                assert!(!host.json().iter().any(|v| v["type"] == "transcript_mirror"), "no mirror frame reached the host");
            });
        }

        /// A remote CLI's `system/init` never chooses which of the Mac's
        /// rows the wrapper writes: an id whose row is another session's is
        /// not adopted (that row stays as it was; `init_id_refused:1`); the
        /// session's own `--resume` id is, its row then this wrapper's.
        #[test]
        fn a_remote_init_never_takes_over_another_sessions_row() {
            const OTHER: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d";
            for resumed in [false, true] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let resume = format!("--resume={OTHER}");
                    let extra: Vec<&str> = if resumed { vec![resume.as_str()] } else { Vec::new() };
                    let (pump, hand, host, io) = remote_pump(d.path(), &extra);
                    let theirs = SessionRow { v: registry::REGISTRY_SCHEMA_V, session_id: OTHER.into(), cwd: Some("/Users/someone/other-workspace".into()), status: "closed".into(), mode: "remote".into(), pid: 1, microvm_id: Some("microvm-other".into()), ..SessionRow::default() };
                    registry::write(&pump.sess.paths, &theirs).unwrap();
                    hand.borrow_mut().snap.vm = Some("microvm-this".into());
                    let task = supervise(pump, io);
                    let mut far = far(&hand).await;
                    far.started().await;
                    handshake(&host, &mut far, OTHER).await;
                    host.send(&user(1)).await;
                    assert!(far.next_input().await.is_some());
                    host.eof().await;
                    assert_eq!(far.next_input().await, None);
                    far.exit(0).await;
                    let (code, mut pump) = ended(task).await;
                    let out = pump.conclude(code);
                    let row = registry_row(&pump, OTHER);
                    let fields = (row.pid, row.cwd.clone(), row.microvm_id.clone(), row.status.clone());
                    if resumed {
                        assert_eq!(fields, (std::process::id(), Some(d.path().display().to_string()), Some("microvm-this".into()), "closed".into()), "the session's own --resume");
                        assert_eq!(out.init_id_refused, 0);
                    } else {
                        assert_eq!(fields, (1, theirs.cwd.clone(), theirs.microvm_id.clone(), theirs.status.clone()), "another session's row is left as it was");
                        assert_eq!((out.init_id_refused, out.session_id), (1, None));
                        assert!(end_note(&pump).split("; ").any(|p| p == format!("{INIT_ID_REFUSED_PART}:1")), "{}", end_note(&pump));
                    }
                });
            }
        }

        /// M05's caps: while the start is pending the host is read until
        /// `PENDING_IN_LINES` lines wait in the pump (beside the link's and
        /// the host's channels), then no more: the host's next send waits
        /// until the start resolves, and every line reaches the spawn in order.
        #[test]
        fn a_pending_start_reads_the_host_up_to_its_caps() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                let total = PENDING_IN_LINES + 2 * CHANNEL_CAP + 8;
                let lines: Vec<String> = (0..u32::try_from(total).unwrap()).map(user).collect();
                let mut sent = 0;
                while sent < total {
                    // A send that waits a second is one the pump will not take while the start is pending.
                    match tokio::time::timeout(Duration::from_secs(1), host.lines.send(HostIn::Line(Bytes::from(lines[sent].clone())))).await {
                        Ok(r) => {
                            r.expect("the host channel is open");
                            sent += 1;
                        }
                        Err(_) => break,
                    }
                }
                assert!((PENDING_IN_LINES..total).contains(&sent), "the pending start read {sent} of {total} lines: past two, up to its cap");
                far.started().await;
                let reader = tokio::task::spawn_local(async move {
                    let mut got = Vec::new();
                    while got.len() < total {
                        got.push(far.next_input().await.expect("a line"));
                    }
                    (got, far)
                });
                for line in &lines[sent..] {
                    host.send(line).await;
                }
                let (got, mut far) = tokio::time::timeout(T, reader).await.expect("every line within the bound").unwrap();
                assert!(got == lines, "every line, in order");
                host.eof().await;
                assert_eq!(far.next_input().await, None);
                far.exit(0).await;
                let (code, pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (0, Some(EndReason::EofTerm)));
            });
        }

        /// M15: a remote link that ends without its last event (the far end
        /// gone, no exit, no loss said) fails closed: once started it is a
        /// lost link (8, `end:link_lost`, the loss's line), while pending a
        /// failed start (8, `end:spawn_failed`): never a CLI's exit 1.
        #[test]
        fn a_link_that_ends_without_its_last_event_is_lost_not_an_exit() {
            for started in [true, false] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                    hand.borrow_mut().snap.vm = Some("microvm-1".into());
                    let task = supervise(pump, io);
                    let mut far = far(&hand).await;
                    if started {
                        far.started().await;
                        handshake(&host, &mut far, SID).await;
                    }
                    drop(far);
                    let (code, pump) = ended(task).await;
                    let want = if started { EndReason::LinkLost } else { EndReason::SpawnFailed };
                    assert_eq!((code, pump.finish.map(|f| f.1)), (8, Some(want)), "started {started}");
                    assert_eq!(pump.final_line, Some(Failure::LinkLost { vm: "microvm-1".into() }.line()), "started {started}");
                });
            }
        }

        /// M23: the retry's replay deadline runs from its `Started`, never
        /// while its start is pending (the transcript's upload, a cold boot):
        /// with a 200 ms deadline (the lab knob) and the start pending 400
        /// ms, the host's `initialize` fails only once generation 2 has run
        /// 200 ms without answering the replay.
        #[test]
        fn the_retrys_replay_deadline_runs_from_its_started() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let resume = format!("--resume={SID}");
                let (mut pump, hand, host, io) = remote_pump(d.path(), &[&resume]);
                pump.knobs.replay_deadline = Some(Duration::from_millis(200));
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                host.send(INIT).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(INIT));
                gen1.line(&format!(r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"errors":["No conversation found with session ID: {SID}"]}}"#)).await;
                gen1.exit(1).await;
                let mut gen2 = far(&hand).await;
                tokio::time::sleep(Duration::from_millis(400)).await;
                assert!(host.json().is_empty(), "nothing failed while the retry's start was pending: {:?}", host.json());
                let started = Instant::now();
                gen2.started().await;
                assert!(gen2.next_input().await.is_some(), "the replayed initialize");
                let failed = host.wait_for("the replay's timeout", |v| v["response"]["request_id"] == "i1").await;
                assert_eq!(failed["response"]["subtype"], "error", "{failed}");
                assert!(started.elapsed() >= Duration::from_millis(190), "the deadline ran from Started: {:?}", started.elapsed());
                host.eof().await;
                gen2.exit(0).await;
                let (_, pump) = ended(task).await;
                let audit = std::fs::read_to_string(pump.sess.paths.audit()).unwrap();
                assert!(audit.contains("\"event\":\"replay_timeout\""), "{audit}");
            });
        }

        /// L2's bound on the remote close (M03): what is left of the hard
        /// stop, the ladder's, else that of the close request that came after
        /// the CLI had ended (a host's EOF 1.4 s, a signal 0.9 s), else a
        /// remote EOF ladder's from now.
        #[test]
        fn the_close_budget_is_what_is_left_of_the_hard_stop() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (mut pump, _hand, _host, _io) = remote_pump(d.path(), &[]);
                let ms = |p: &Pump| p.close_budget().as_millis();
                let ago = |d: u64| Some(Instant::now() - Duration::from_millis(d));
                let budget = ms(&pump);
                assert!((1300..=1400).contains(&budget), "nothing closed it yet: {budget}");
                pump.close_at = ago(300);
                let budget = ms(&pump);
                assert!((500..=600).contains(&budget), "a signal 300 ms ago: {budget}");
                pump.close_at = ago(1000);
                pump.host_eof_at = pump.close_at;
                let budget = ms(&pump);
                assert!((300..=400).contains(&budget), "the host's EOF 1 s ago: {budget}");
                pump.close_at = ago(2000);
                assert_eq!(ms(&pump), 0, "past the hard stop");
                let now = Instant::now();
                pump.ladder = Some(Ladder { term_at: None, kill_at: now, hard_stop: now + Duration::from_millis(500), host_initiated: true, signalled: false, killed: false });
                let budget = ms(&pump);
                assert!((400..=500).contains(&budget), "the ladder's: {budget}");
            });
        }

        /// A remote session's child plan: the VM's CLI runs with the Mac
        /// HOME's `.claude` (Design A: the VM path its frames name), whose
        /// frames no writer mirrors into the Mac's projects dir (S9 D9: the
        /// transcript is kept in S3), not even its own project's; no scratch
        /// dir, no environment of the wrapper's, the cwd's slug whatever
        /// `CLAUDE_CODE_PROJECT_DIR_NAME` says, a `--resume` uuid kept;
        /// without HOME no plan (fail closed).
        #[test]
        fn a_remote_child_plan_mirrors_nothing_and_spawns_nothing_here() {
            let d = tempfile::tempdir().unwrap();
            let resume = format!("--resume={SID}");
            let sess = remote_session(d.path(), &[&resume]);
            let env = env_of(vec![("HOME", d.path().as_os_str().to_owned()), ("CLAUDE_CODE_PROJECT_DIR_NAME", OsString::from("custom-dir"))]);
            let plan = child_plan(&sess, &env, &mut || "fresh".to_string()).unwrap();
            assert_eq!(plan.child_config_dir, d.path().join(".claude"));
            assert_eq!((plan.scratch.as_deref(), plan.resume.as_deref()), (None, Some(SID)));
            assert!(plan.env_set.is_empty() && plan.env_remove.is_empty());
            assert_eq!(plan.slug, slug::project_dir_name(d.path()).ok(), "the cwd's slug, no override");
            assert!(!plan.mirror.enabled && plan.mirror.project.is_none() && plan.mirror.reason.contains("kept in S3"), "{}", plan.mirror.reason);
            let projects = d.path().join(".claude").join("projects");
            assert_eq!((&plan.mirror.child_projects_root, &plan.mirror.dest_root), (&projects, &projects));
            assert!(child_plan(&sess, &env_of(vec![]), &mut || "x".into()).is_err());
        }

        /// P0's failure, before the pump: the census end row
        /// (`end:spawn_failed`, the failure's exit, its step) and the audit
        /// row `session_remote_failed` with the failure's word; the wrapper's
        /// exit is the failure's code.
        #[test]
        fn a_failure_before_the_pump_is_recorded_with_its_code_and_step() {
            for (failure, code) in [
                (Failure::NotGitRepo, 9),
                (Failure::NoToken { why: "no setup-token is sealed".into() }, 5),
                (Failure::Other { code: 1, step: "precheck", first_line: "the session's pump cannot start: HOME is not set".into() }, 1),
            ] {
                let d = tempfile::tempdir().unwrap();
                let sess = remote_session(d.path(), &[]);
                assert_eq!(record_failure_before_pump(&sess, &failure), code);
                let rows = census::read_rows(&sess.paths.census(), None).unwrap();
                assert_eq!((rows.len(), rows[0]["exit"].as_i64()), (1, Some(i64::from(code))));
                let note = rows[0]["note"].as_str().unwrap_or_default();
                assert!(note.starts_with("mode:remote; end:spawn_failed; child_pid:-") && note.ends_with("; step:precheck"), "{note}");
                let audit = std::fs::read_to_string(sess.paths.audit()).unwrap();
                assert!(audit.contains("\"event\":\"session_remote_failed\"") && audit.contains(&format!("\"why\":\"{}\"", failure.word())) && audit.contains(&format!("\"code\":\"{code}\"")), "{audit}");
            }
        }

        /// S9 (G7), TIMING-4 (W1R-08's gap): the pending start's byte cap.
        /// While the start is pending the link's channel takes its
        /// `CHANNEL_CAP` lines first, whatever their size; then the pump's own
        /// queue grows until it holds `PENDING_IN_BYTES` (here 32 lines of 2
        /// MiB, far under `PENDING_IN_LINES`) and the host is read no more:
        /// its channel fills and its next send waits until the start resolves.
        /// Then every line reaches the spawn, in order.
        #[test]
        fn a_pending_start_reads_the_host_up_to_its_byte_cap() {
            const BIG: usize = 2 << 20;
            let big_n = PENDING_IN_BYTES / BIG;
            let total = CHANNEL_CAP + big_n + CHANNEL_CAP + 16;
            let pad = "x".repeat(BIG);
            // Line i: the link's CHANNEL_CAP small ones first, then big_n of BIG bytes and more, then small ones.
            let line = |i: usize| {
                let big = (CHANNEL_CAP..CHANNEL_CAP + big_n).contains(&i);
                Bytes::from(format!(r#"{{"type":"keep_alive","n":{i:05},"pad":"{}"}}"#, if big { pad.as_str() } else { "" }))
            };
            let seq = |l: &str| l.split_once(r#""n":"#).and_then(|(_, rest)| rest.get(..5)).and_then(|n| n.parse::<usize>().ok());
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                let mut sent = 0;
                while sent < total {
                    // A send that waits a second is one the pump will not take while the start is pending.
                    match tokio::time::timeout(Duration::from_secs(1), host.lines.send(HostIn::Line(line(sent)))).await {
                        Ok(r) => {
                            r.expect("the host channel is open");
                            sent += 1;
                        }
                        Err(_) => break,
                    }
                }
                assert!((CHANNEL_CAP + big_n..total).contains(&sent), "the pending start read {sent} of {total} lines: the link's slots, then its queue up to its bytes (far under its {PENDING_IN_LINES} lines), then no more");
                far.started().await;
                let reader = tokio::task::spawn_local(async move {
                    let mut got = Vec::new();
                    while got.len() < total {
                        got.push(seq(&far.next_input().await.expect("a line")));
                    }
                    (got, far)
                });
                for i in sent..total {
                    tokio::time::timeout(T, host.lines.send(HostIn::Line(line(i)))).await.expect("the pump reads the host once started").expect("the host channel is open");
                }
                let (got, mut far) = tokio::time::timeout(T, reader).await.expect("every line within the bound").unwrap();
                assert!(got.iter().enumerate().all(|(i, n)| *n == Some(i)), "every line, in order");
                host.eof().await;
                assert_eq!(far.next_input().await, None);
                far.exit(0).await;
                let (code, pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (0, Some(EndReason::EofTerm)));
            });
        }

        /// S9 (G7): once a remote close's waits are over, the registry row
        /// takes a code-out of the session's VM that ended inside them (the
        /// end row was written before, and the trigger's report is gone with
        /// the close): its workspace row's newest snapshot, newer than the
        /// row's own; and this process's scratch under `state/tmp/` goes (a
        /// fetch given up at the close leaves its own). A workspace row of
        /// another VM's fetch, or of one before the session began, or an
        /// older snapshot, changes nothing.
        #[test]
        fn after_its_waits_the_close_records_their_fetch_and_removes_its_scratch() {
            const VM: &str = "microvm-1";
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                {
                    let mut h = hand.borrow_mut();
                    h.snap.vm = Some(VM.into());
                    h.snap.last_wip_fetch = Some(format!("{}wip/20261018T100000Z-1", crate::bridge::codeout::BOX_REFS));
                }
                let task = supervise(pump, io);
                let mut far = far(&hand).await;
                far.started().await;
                handshake(&host, &mut far, SID).await;
                host.send(&user(1)).await;
                assert!(far.next_input().await.is_some());
                far.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                host.eof().await;
                assert_eq!(far.next_input().await, None);
                far.exit(0).await;
                let (code, mut pump) = ended(task).await;
                pump.conclude(code);
                let wip = |name: &str| format!("{}wip/{name}", crate::bridge::codeout::BOX_REFS);
                assert_eq!(registry_row(&pump, SID).last_wip_fetch, Some(wip("20261018T100000Z-1")), "the end's row, before the waits");
                let paths = pump.sess.paths.clone();
                let cwd = std::fs::canonicalize(d.path()).unwrap();
                let slug = slug::project_dir_name(&cwd).unwrap();
                let fetched = |vm: &str, at: u64, newest: &str| {
                    let row = crate::bridge::workspace::rows::WsRow { root: cwd.display().to_string(), vm_root: cwd.display().to_string(), last_fetch_at: Some(at), last_fetch_vm: Some(vm.into()), last_wip: Some(wip(newest)), ..Default::default() };
                    let rows = crate::bridge::workspace::rows::WorkspaceRows { v: crate::bridge::workspace::rows::ROWS_V, ws: [(cwd.display().to_string(), row)].into() };
                    std::fs::create_dir_all(paths.workspaces()).unwrap();
                    std::fs::write(paths.workspace_row(&slug), toml::to_string(&rows).unwrap()).unwrap();
                };
                let now = crate::wire::time::unix_now();
                let own = std::process::id();
                for dir in [format!("fetch-{own}-a1b2c3/repo.git"), "fetch-1-d4e5f6/repo.git".to_string()] {
                    std::fs::create_dir_all(paths.tmp().join(dir)).unwrap();
                }
                fetched(VM, now, "20261018T100200Z-2");
                after_close(&mut pump);
                assert_eq!(registry_row(&pump, SID).last_wip_fetch, Some(wip("20261018T100200Z-2")), "the fetch that ended inside the waits");
                assert_eq!(registry_row(&pump, SID).status, "closed");
                let left: Vec<String> = std::fs::read_dir(paths.tmp()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
                assert_eq!(left, ["fetch-1-d4e5f6"], "this process's scratch went, another's stays");
                for (vm, at, newest) in [("microvm-other", now, "20261018T100300Z-3"), (VM, 1, "20261018T100400Z-4"), (VM, now, "20261018T100100Z-1")] {
                    fetched(vm, at, newest);
                    after_close(&mut pump);
                    assert_eq!(registry_row(&pump, SID).last_wip_fetch, Some(wip("20261018T100200Z-2")), "{vm} at {at}: {newest}");
                }
            });
        }

        // ---- S10 (C1): a lost VM or spawn moves the chat (plans/s10-contracts.md §A, §3.4, §6.1) ----

        /// The audit rows of `event` the pump wrote, oldest first.
        fn audit_rows(pump: &Pump, event: &str) -> Vec<Value> {
            crate::bridge::audit::read_rows(&pump.sess.paths.audit(), None).unwrap().into_iter().filter(|r| r["event"] == event).collect()
        }

        /// The informational notes the host got, their texts in order.
        fn notes(host: &Host) -> Vec<String> {
            host.json().into_iter().filter(|v| v["type"] == "system" && v["subtype"] == "informational").map(|v| v["content"].as_str().unwrap_or_default().to_string()).collect()
        }

        /// The moved generation's start, as its pipeline reports it (`RemoteSnapshot.moved`).
        fn moved_to(hand: &Rc<RefCell<Hand>>, vm: &str, kind: MoveKind, cut: &'static str) {
            let mut h = hand.borrow_mut();
            h.snap.vm = Some(vm.into());
            h.snap.moved = Some(crate::bridge::remote::link::MoveDone { kind, cut, touchid: "asked", seed: "box", stayed: false });
        }

        /// A mid-turn loss of a terminated VM moves the chat at once: the
        /// next generation starts as a re-address (`whys == [First,
        /// Move(Readdress …)]`, the adopted session id, the outstanding
        /// line's uuid, the leaf, not fresh, `initialize` answered); the host
        /// gets one note and the dead CLI's open prompt withdrawn (one
        /// `control_cancel_request`); generation 2's input is `initialize`
        /// and the mode under fresh ids, then the line verbatim; its answers,
        /// its init and its echo are swallowed, so the host sees one init and
        /// one echo per turn and one result for the line. The census counts
        /// the move, its time and its cut; `session_move` and
        /// `session_move_end` `done` are audited; the row went `migrating`,
        /// then `active`.
        #[test]
        fn a_vm_gone_loss_moves_with_the_host_state_replayed() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                hand.borrow_mut().snap.vm = Some("microvm-1".into());
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                host.send(INIT).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(INIT));
                gen1.line(&answer("i1", r#"{"pid":4242}"#)).await;
                host.wait_for("the initialize answer", |v| v["response"]["request_id"] == "i1").await;
                let mode = r#"{"type":"control_request","request_id":"m1","request":{"subtype":"set_permission_mode","mode":"plan"}}"#;
                host.send(mode).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(mode));
                gen1.line(&answer("m1", "{}")).await;
                // Turn 1, its last assistant frame the leaf; then turn 2 in flight, its prompt open.
                host.send(&user(1)).await;
                assert_eq!(gen1.next_input().await, Some(user(1)));
                for line in [init_frame(SID), echo(1), assistant("a-1"), result_for(1)] {
                    gen1.line(&line).await;
                }
                host.wait_for("turn 1's result", |v| v["type"] == "result").await;
                host.send(&user(2)).await;
                assert_eq!(gen1.next_input().await, Some(user(2)));
                let ask = r#"{"type":"control_request","request_id":"c1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{}}}"#;
                for line in [init_frame(SID), echo(2), ask.to_string()] {
                    gen1.line(&line).await;
                }
                host.wait_for("the prompt", |v| v["request_id"] == "c1").await;
                gen1.send(gone("microvm-1")).await;
                let mut gen2 = far(&hand).await;
                let want = MoveWhy {
                    kind: MoveKind::Readdress,
                    cause: Some(LossCause::VmGone),
                    trigger: None,
                    from_vm: "microvm-1".into(),
                    from_spawn: None,
                    session_id: Some(SID.into()),
                    outstanding: vec![uuid_of(2)],
                    leaf: Some("a-1".into()),
                    fresh_chat: false,
                    init_answered: true,
                };
                assert_eq!(hand.borrow().whys, [StartWhy::First, StartWhy::Move(want)]);
                host.wait_for("the withdrawn prompt", |v| v["type"] == "control_cancel_request").await;
                assert_eq!(notes(&host), [note_moving("microvm-1", LossCause::VmGone)], "one note");
                assert_eq!(registry::read(&Paths::from_root_and_env(d.path().join("bridge"), None), SID).unwrap().map(|r| r.status).as_deref(), Some("migrating"));
                moved_to(&hand, "microvm-2", MoveKind::Readdress, "at");
                gen2.started().await;
                let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                let mode2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed mode")).unwrap();
                assert_eq!((init2["request"]["subtype"].as_str(), mode2["request"]["mode"].as_str()), (Some("initialize"), Some("plan")));
                assert!(init2["request_id"] != "i1" && mode2["request_id"] != "m1", "fresh ids: {init2} {mode2}");
                assert_eq!(gen2.next_input().await, Some(user(2)), "the line again, verbatim");
                gen2.line(&answer(init2["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                gen2.line(&answer(mode2["request_id"].as_str().unwrap(), "{}")).await;
                for line in [init_frame(SID), echo(2), assistant("a-2"), result_for(2)] {
                    gen2.line(&line).await;
                }
                host.wait_for("turn 2's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()).await;
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                let out = host.json();
                let count = |pred: &dyn Fn(&Value) -> bool| out.iter().filter(|v| pred(v)).count();
                assert_eq!(count(&|v| v["type"] == "system" && v["subtype"] == "init"), 2, "one init per turn");
                assert_eq!(count(&|v| v["type"] == "user" && v["uuid"] == uuid_of(2).as_str()), 1, "one echo of the line");
                assert_eq!(count(&|v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()), 1, "one result");
                assert_eq!(count(&|v| v["type"] == "control_response"), 2, "the host's two requests, answered once");
                assert_eq!(count(&|v| v["type"] == "control_cancel_request" && v["request_id"] == "c1"), 1);
                assert_eq!(notes(&host), [note_moving("microvm-1", LossCause::VmGone), note_continues("microvm-2")]);
                pump.conclude(code);
                let note = end_note(&pump);
                for part in ["moves:readdress=1,respawn=0,migrate=0", "cut:at", "inits:2/1", "echoes:2/1"] {
                    assert!(note.split("; ").any(|p| p == part), "{part} in {note}");
                }
                assert!(note.split("; ").any(|p| p.starts_with("move_ms:")), "{note}");
                let started = audit_rows(&pump, "session_move");
                assert_eq!(started.len(), 1, "{started:?}");
                let d1 = &started[0]["detail"];
                assert_eq!((d1["gen"].as_str(), d1["kind"].as_str(), d1["cause"].as_str(), d1["from_vm"].as_str(), d1["outstanding"].as_str(), d1["cancelled"].as_str()), (Some("2"), Some("readdress"), Some("vm_gone"), Some("microvm-1"), Some("1"), Some("1")));
                let ends = audit_rows(&pump, "session_move_end");
                assert_eq!(ends.len(), 1, "{ends:?}");
                let d2 = &ends[0]["detail"];
                assert_eq!((d2["outcome"].as_str(), d2["to_vm"].as_str(), d2["cut"].as_str(), d2["touchid"].as_str(), d2["seed"].as_str()), (Some("done"), Some("microvm-2"), Some("at"), Some("asked"), Some("box")));
                let row = registry_row(&pump, SID);
                let whys: Vec<_> = row.vms.iter().map(|v| (v["gen"].as_integer(), v["why"].as_str().map(str::to_string), v.get("end").and_then(|e| e.as_str()).map(str::to_string))).collect();
                assert_eq!(whys, [(Some(1), Some("first".into()), Some("lost:vm_gone".into())), (Some(2), Some("readdress:vm_gone".into()), Some("close".into()))]);
            });
        }

        /// §2.9: the leaf moves with every result. A turn that forwarded no
        /// top-level assistant frame (stopped before any reply) leaves none,
        /// so a move in the next turn cuts just before that turn's own line
        /// (`MoveWhy.leaf` none), never at an older reply, which would cut
        /// the stopped turn and its marker away. A move's start drops the
        /// dead CLI's partial frame: the moved CLI's turn with no reply of
        /// its own leaves no leaf either.
        #[test]
        fn a_turn_with_no_reply_leaves_no_leaf() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                hand.borrow_mut().snap.vm = Some("microvm-1".into());
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                // Turn 1 replies (a-1); turn 2 is stopped before any reply: its result alone.
                host.send(&user(1)).await;
                assert_eq!(gen1.next_input().await, Some(user(1)));
                for line in [echo(1), assistant("a-1"), result_for(1)] {
                    gen1.line(&line).await;
                }
                host.wait_for("turn 1's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(1).as_str()).await;
                host.send(&user(2)).await;
                assert_eq!(gen1.next_input().await, Some(user(2)));
                for line in [echo(2), result_for(2)] {
                    gen1.line(&line).await;
                }
                host.wait_for("turn 2's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()).await;
                // Turn 3 is lost mid-turn, a partial reply forwarded.
                host.send(&user(3)).await;
                assert_eq!(gen1.next_input().await, Some(user(3)));
                for line in [echo(3), assistant("a-partial")] {
                    gen1.line(&line).await;
                }
                host.wait_for("the partial reply", |v| v["uuid"] == "a-partial").await;
                gen1.send(gone("microvm-1")).await;
                let mut gen2 = far(&hand).await;
                let moved = |n: u32, from: &str| MoveWhy {
                    kind: MoveKind::Readdress,
                    cause: Some(LossCause::VmGone),
                    trigger: None,
                    from_vm: from.into(),
                    from_spawn: None,
                    session_id: Some(SID.into()),
                    outstanding: vec![uuid_of(n)],
                    leaf: None,
                    fresh_chat: false,
                    init_answered: true,
                };
                assert_eq!(hand.borrow().whys.last(), Some(&StartWhy::Move(moved(3, "microvm-1"))), "turn 2 forwarded no reply: no leaf");
                // The moved CLI runs turn 3 again with no reply of its own; turn 4 is lost mid-turn.
                moved_to(&hand, "microvm-2", MoveKind::Readdress, "none");
                gen2.started().await;
                let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                assert_eq!(init2["request"]["subtype"], "initialize");
                assert_eq!(gen2.next_input().await, Some(user(3)), "the line again, verbatim");
                gen2.line(&answer(init2["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                for line in [init_frame(SID), echo(3), result_for(3)] {
                    gen2.line(&line).await;
                }
                host.wait_for("turn 3's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(3).as_str()).await;
                host.send(&user(4)).await;
                assert_eq!(gen2.next_input().await, Some(user(4)));
                gen2.line(&echo(4)).await;
                gen2.send(gone("microvm-2")).await;
                let mut gen3 = far(&hand).await;
                assert_eq!(hand.borrow().whys.last(), Some(&StartWhy::Move(moved(4, "microvm-2"))), "the dead CLI's partial reply is never a leaf");
                moved_to(&hand, "microvm-3", MoveKind::Readdress, "none");
                gen3.started().await;
                let init3: Value = serde_json::from_str(&gen3.next_input().await.expect("the replayed initialize")).unwrap();
                assert_eq!(gen3.next_input().await, Some(user(4)));
                gen3.line(&answer(init3["request_id"].as_str().unwrap(), r#"{"pid":4444}"#)).await;
                for line in [init_frame(SID), echo(4), assistant("a-4"), result_for(4)] {
                    gen3.line(&line).await;
                }
                host.wait_for("turn 4's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(4).as_str()).await;
                host.eof().await;
                assert_eq!(gen3.next_input().await, None);
                gen3.exit(0).await;
                let (code, _pump) = ended(task).await;
                assert_eq!(code, 0);
            });
        }

        /// L5: a loss with no turn in flight waits: no generation starts,
        /// the row says `detached`, the host gets the note that the chat moves
        /// with the next message; a host `keep_alive` starts nothing (and
        /// never reaches a CLI); the next user line starts the move, then
        /// reaches the moved CLI after the replayed `initialize` (sent once,
        /// not resent: no `cut` part), and that CLI's own init starts the
        /// turn. A host that closes while the chat waits ends it, exit 0,
        /// with no move.
        #[test]
        fn a_loss_while_idle_waits_for_the_next_line() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                hand.borrow_mut().snap.vm = Some("microvm-1".into());
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                gen1.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                gen1.send(gone("microvm-1")).await;
                host.wait_for("the note", |v| v["subtype"] == "informational").await;
                let status = || registry::read(&Paths::from_root_and_env(d.path().join("bridge"), None), SID).unwrap().map(|r| r.status);
                assert_eq!(status().as_deref(), Some("detached"));
                assert_eq!(notes(&host), [note_move_at_next("microvm-1", LossCause::VmGone)]);
                host.send(r#"{"type":"keep_alive"}"#).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert!(hand.borrow().fars.is_empty() && hand.borrow().whys == [StartWhy::First], "nothing moves before the next line");
                assert!(!task.is_finished());
                host.send(&user(2)).await;
                let mut gen2 = far(&hand).await;
                assert!(matches!(&hand.borrow().whys[..], [StartWhy::First, StartWhy::Move(m)] if m.kind == MoveKind::Readdress && m.outstanding.is_empty() && !m.fresh_chat), "{:?}", hand.borrow().whys);
                moved_to(&hand, "microvm-2", MoveKind::Readdress, "none");
                gen2.started().await;
                let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                assert_eq!(init2["request"]["subtype"], "initialize");
                assert_eq!(gen2.next_input().await, Some(user(2)), "the next line, after the replay; no keep_alive");
                gen2.line(&answer(init2["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                for line in [init_frame(SID), echo(2), result_for(2)] {
                    gen2.line(&line).await;
                }
                host.wait_for("turn 2's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()).await;
                assert_eq!(status().as_deref(), Some("active"));
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                assert_eq!(host.json().iter().filter(|v| v["type"] == "system" && v["subtype"] == "init").count(), 2, "the moved CLI's init starts turn 2");
                assert_eq!(notes(&host).len(), 2, "the wait's note, then the chat's continuing: {:?}", notes(&host));
                pump.conclude(code);
                let note = end_note(&pump);
                assert!(note.contains("moves:readdress=1,respawn=0,migrate=0") && !note.contains("cut:"), "{note}");
            });
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                gen1.send(gone("microvm-1")).await;
                host.wait_for("the note", |v| v["subtype"] == "informational").await;
                host.eof().await;
                let (code, mut pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (0, Some(EndReason::EofTerm)));
                assert_eq!(hand.borrow().whys, [StartWhy::First], "a closed chat never moves");
                pump.conclude(code);
                assert!(!end_note(&pump).contains("moves:"), "{}", end_note(&pump));
            });
        }

        /// L6: `[vm].max_readdress` moves per wrapper process; the loss past
        /// them ends the wrapper 8 with `MovesExhausted`'s line, and with 0
        /// a lost VM is S9's exit 8 with the loss's own line, no move.
        #[test]
        fn past_max_readdress_the_exit_is_8() {
            for max in [1, 0] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (mut pump, hand, host, io) = remote_pump(d.path(), &[]);
                    let mut cfg = BridgeConfig::default();
                    cfg.vm.max_readdress = max;
                    pump.sess.cfg = Some(cfg);
                    let task = supervise(pump, io);
                    let mut gen = far(&hand).await;
                    gen.started().await;
                    handshake(&host, &mut gen, SID).await;
                    host.send(&user(1)).await;
                    assert!(gen.next_input().await.is_some());
                    for n in 0..max {
                        let vm = format!("microvm-{}", n + 1);
                        gen.send(gone(&vm)).await;
                        gen = far(&hand).await;
                        moved_to(&hand, &format!("microvm-{}", n + 2), MoveKind::Readdress, "none");
                        gen.started().await;
                    }
                    let last = format!("microvm-{}", max + 1);
                    gen.send(gone(&last)).await;
                    let (code, mut pump) = ended(task).await;
                    assert_eq!((code, pump.finish.map(|f| f.1)), (8, Some(EndReason::LinkLost)), "max {max}");
                    let line = if max == 0 { Failure::LinkLost { vm: last.clone() }.line() } else { Failure::MovesExhausted { vm: last.clone(), moves: max }.line() };
                    assert_eq!(pump.final_line.as_deref(), Some(line.as_str()), "max {max}");
                    assert_eq!(hand.borrow().whys.len(), 1 + max as usize, "max {max}: one move each");
                    pump.conclude(code);
                    let note = end_note(&pump);
                    assert!(note.contains("end:link_lost"), "{note}");
                    assert_eq!(note.contains("moves:readdress=1,"), max == 1, "{note}");
                });
            }
        }

        /// A move whose start fails (here M1's Touch ID dismissed) ends the
        /// wrapper with that failure's code and line (`Failure::Move`),
        /// `end:move_failed` naming the step, the census counting the move
        /// and timing it; the row closed.
        #[test]
        fn a_failed_move_start_ends_move_failed() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                gen1.send(gone("microvm-1")).await;
                let gen2 = far(&hand).await;
                let failure = Failure::Move { kind: MoveKind::Readdress, from_vm: "microvm-1".into(), cause: Some(LossCause::VmGone), inner: Box::new(Failure::TouchIdCancelled) };
                gen2.send(ChildEvent::SpawnFailed(SpawnFailure::from_failure(StartStep::TouchId, &failure, None))).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (3, Some(EndReason::MoveFailed)));
                assert_eq!(pump.final_line.as_deref(), Some(failure.line().as_str()));
                assert!(failure.line().contains("moving the chat to a new VM failed"), "{}", failure.line());
                pump.conclude(code);
                let note = end_note(&pump);
                for part in ["end:move_failed", "step:touchid", "moves:readdress=1,respawn=0,migrate=0"] {
                    assert!(note.split("; ").any(|p| p == part), "{part} in {note}");
                }
                assert!(note.split("; ").any(|p| p.starts_with("move_ms:")), "{note}");
                assert_eq!(registry_row(&pump, SID).status, "closed");
                assert!(!host.json().iter().any(|v| v["type"] == "result"), "the host never got an error result");
            });
        }

        /// L4: the dead CLI's open prompt is withdrawn at the move
        /// (`control_cancel_request` to the host); the host's late answer to
        /// it is dropped, never sent to the moved CLI, whose own request is
        /// answered as usual. A late answer while the chat waits for its
        /// next line (L5) starts no move.
        #[test]
        fn a_late_answer_to_a_withdrawn_prompt_is_dropped() {
            let late = |id: &str| format!(r#"{{"type":"control_response","response":{{"subtype":"success","request_id":"{id}","response":{{"behavior":"allow"}}}}}}"#);
            let ask = |id: &str, sub: &str| format!(r#"{{"type":"control_request","request_id":"{id}","request":{{"subtype":"{sub}"}}}}"#);
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                gen1.line(&ask("c1", "can_use_tool")).await;
                host.wait_for("the prompt", |v| v["request_id"] == "c1").await;
                gen1.send(gone("microvm-1")).await;
                let mut gen2 = far(&hand).await;
                host.wait_for("the withdrawn prompt", |v| v["type"] == "control_cancel_request" && v["request_id"] == "c1").await;
                moved_to(&hand, "microvm-2", MoveKind::Readdress, "none");
                gen2.started().await;
                let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                assert_eq!(gen2.next_input().await, Some(user(1)));
                gen2.line(&answer(init2["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                host.send(&late("c1")).await;
                gen2.line(&ask("c2", "can_use_tool")).await;
                host.wait_for("the new prompt", |v| v["request_id"] == "c2").await;
                host.send(&late("c2")).await;
                assert_eq!(gen2.next_input().await, Some(late("c2")), "the late answer to c1 never reached the moved CLI");
                gen2.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, pump) = ended(task).await;
                assert_eq!(code, 0);
                let counts = pump.state.counts();
                assert_eq!((counts.requests_cancelled, counts.answers_dropped), (1, 1));
            });
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                gen1.line(&ask("e1", "elicitation")).await;
                host.wait_for("the request", |v| v["request_id"] == "e1").await;
                gen1.send(gone("microvm-1")).await;
                host.wait_for("the withdrawn request", |v| v["type"] == "control_cancel_request" && v["request_id"] == "e1").await;
                host.send(&late("e1")).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert_eq!(hand.borrow().whys, [StartWhy::First], "a late answer starts no move");
                host.send(&user(1)).await;
                let mut gen2 = far(&hand).await;
                assert_eq!(hand.borrow().whys.len(), 2);
                gen2.started().await;
                let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                assert_eq!(init2["request"]["subtype"], "initialize");
                assert_eq!(gen2.next_input().await, Some(user(1)), "the line, never the late answer");
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, _) = ended(task).await;
                assert_eq!(code, 0);
            });
        }

        /// §2.9: a moved CLI that misses its cut before its init gets one
        /// retry on its VM with no cut (`Respawn` for `SpawnGone`, nothing
        /// outstanding, so plain `--resume`; no new move counted, the census
        /// `cut:none`), the host's state and the line replayed again; the
        /// miss never reaches the host. The move has one `session_move_end`,
        /// `done` once the retry's CLI resumed (its init), keeping the first
        /// generation's Touch ID and seed with `cut` `none`, and one note
        /// that the chat goes on. A resume miss inside a move fails it: exit 8
        /// with the move's line, `end:move_failed` at `step:spawn`, its one
        /// `session_move_end` `failed`, no note that the chat goes on; the
        /// host never gets the error result.
        #[test]
        fn a_cut_miss_retries_once_and_a_resume_miss_fails_the_move() {
            let miss = |text: &str| format!(r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"x","errors":["{text}"]}}"#);
            for cut in [true, false] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                    hand.borrow_mut().snap.vm = Some("microvm-1".into());
                    let task = supervise(pump, io);
                    let mut gen1 = far(&hand).await;
                    gen1.started().await;
                    handshake(&host, &mut gen1, SID).await;
                    host.send(&user(1)).await;
                    assert!(gen1.next_input().await.is_some());
                    for line in [assistant("a-1"), result_for(1)] {
                        gen1.line(&line).await;
                    }
                    host.wait_for("turn 1's result", |v| v["type"] == "result").await;
                    host.send(&user(2)).await;
                    assert!(gen1.next_input().await.is_some());
                    gen1.send(gone("microvm-1")).await;
                    let mut gen2 = far(&hand).await;
                    moved_to(&hand, "microvm-2", MoveKind::Readdress, "at");
                    gen2.started().await;
                    assert!(gen2.next_input().await.is_some_and(|l| l.contains("\"initialize\"")));
                    assert_eq!(gen2.next_input().await, Some(user(2)));
                    assert_eq!(notes(&host), [note_moving("microvm-1", LossCause::VmGone)], "nothing says the chat goes on before its CLI resumed");
                    let text = if cut { format!("No message found with message.uuid of: {}", "a-1") } else { format!("No conversation found with session ID: {SID}") };
                    gen2.line(&miss(&text)).await;
                    gen2.exit(1).await;
                    if !cut {
                        let (code, mut pump) = ended(task).await;
                        assert_eq!((code, pump.finish.map(|f| f.1)), (8, Some(EndReason::MoveFailed)));
                        let line = pump.final_line.clone().unwrap_or_default();
                        assert!(line.starts_with("the chat's VM microvm-1 was lost (it was terminated); moving the chat to a new VM failed: ") && line.contains(&text), "{line}");
                        assert_eq!(hand.borrow().whys.len(), 2, "no retry");
                        pump.conclude(code);
                        assert!(end_note(&pump).contains("end:move_failed") && end_note(&pump).contains("; step:spawn"), "{}", end_note(&pump));
                        let ends = audit_rows(&pump, "session_move_end");
                        assert_eq!(ends.iter().map(|r| r["detail"]["outcome"].clone()).collect::<Vec<_>>(), [Value::from("failed")], "the move's one end row: {ends:?}");
                        assert_eq!((ends[0]["detail"]["to_vm"].as_str(), ends[0]["detail"]["cut"].as_str(), ends[0]["detail"]["code"].as_str()), (Some("microvm-2"), Some("at"), Some("8")));
                        assert!(!host.json().iter().any(|v| v["is_error"] == true), "the host never got the miss");
                        assert_eq!(notes(&host).len(), 1, "no note that the chat goes on: {:?}", notes(&host));
                        assert_eq!(registry_row(&pump, SID).vms.last().and_then(|v| v.get("end")).and_then(|e| e.as_str()), Some("failed"));
                        return;
                    }
                    let mut gen3 = far(&hand).await;
                    let want = MoveWhy {
                        kind: MoveKind::Respawn,
                        cause: Some(LossCause::SpawnGone),
                        trigger: None,
                        from_vm: "microvm-2".into(),
                        from_spawn: None,
                        session_id: Some(SID.into()),
                        outstanding: Vec::new(),
                        leaf: None,
                        fresh_chat: false,
                        init_answered: true,
                    };
                    assert_eq!(hand.borrow().whys.last(), Some(&StartWhy::Move(want)));
                    // The retry on the same VM: its own seed kept, its token the VM's copy.
                    hand.borrow_mut().snap.moved = Some(crate::bridge::remote::link::MoveDone { kind: MoveKind::Respawn, cut: "none", touchid: "cached", seed: "kept", stayed: false });
                    gen3.started().await;
                    let init3: Value = serde_json::from_str(&gen3.next_input().await.expect("the replayed initialize")).unwrap();
                    assert_eq!(gen3.next_input().await, Some(user(2)), "the line again");
                    gen3.line(&answer(init3["request_id"].as_str().unwrap(), r#"{"pid":4444}"#)).await;
                    for line in [init_frame(SID), result_for(2)] {
                        gen3.line(&line).await;
                    }
                    host.wait_for("turn 2's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()).await;
                    host.eof().await;
                    assert_eq!(gen3.next_input().await, None);
                    gen3.exit(0).await;
                    let (code, mut pump) = ended(task).await;
                    assert_eq!(code, 0);
                    assert!(!host.json().iter().any(|v| v["is_error"] == true), "the host never got the miss");
                    assert_eq!(notes(&host), [note_moving("microvm-1", LossCause::VmGone), note_continues("microvm-2")], "one note that the chat goes on");
                    pump.conclude(code);
                    let note = end_note(&pump);
                    assert!(note.contains("moves:readdress=1,respawn=0,migrate=0") && note.contains("; cut:none"), "{note}");
                    let ends = audit_rows(&pump, "session_move_end");
                    assert_eq!(ends.len(), 1, "the move's one end row: {ends:?}");
                    let d = &ends[0]["detail"];
                    let got = [&d["outcome"], &d["gen"], &d["kind"], &d["to_vm"], &d["cut"], &d["touchid"], &d["seed"]].map(|v| v.as_str().unwrap_or_default().to_string());
                    assert_eq!(got, ["done", "3", "readdress", "microvm-2", "none", "asked", "box"], "{d}");
                });
            }
        }

        /// §2.9: a moved CLI's cut or resume miss before its first init is
        /// held however late it comes. Past `RESUME_MISS_GRACE` after its
        /// answer to the replayed `initialize` (its MCP servers slow to
        /// start, say) the move is written done and the note says the chat
        /// goes on; a miss after that still never reaches the host. A cut
        /// miss gets its one retry with no cut (the census `cut:none`): on the
        /// same VM it writes no second `done` and says nothing more; on
        /// another VM (the moved one no longer running) that VM's `done` and
        /// note. A resume miss fails the move: exit 8 with the move's line,
        /// `end:move_failed` at `step:spawn`, `failed` after the `done`, with
        /// the values of the generation that failed.
        #[test]
        fn a_miss_later_than_the_grace_is_held_until_the_init() {
            let miss = |text: &str| format!(r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"x","errors":["{text}"]}}"#);
            let row_of = |r: &Value| {
                let d = &r["detail"];
                [&d["outcome"], &d["gen"], &d["to_vm"], &d["cut"], &d["touchid"], &d["seed"]].map(|v| v.as_str().unwrap_or_default().to_string())
            };
            for (cut, retry_vm) in [(true, "microvm-2"), (true, "microvm-3"), (false, "")] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                    hand.borrow_mut().snap.vm = Some("microvm-1".into());
                    let task = supervise(pump, io);
                    let mut gen1 = far(&hand).await;
                    gen1.started().await;
                    handshake(&host, &mut gen1, SID).await;
                    host.send(&user(1)).await;
                    assert!(gen1.next_input().await.is_some());
                    for line in [assistant("a-1"), result_for(1)] {
                        gen1.line(&line).await;
                    }
                    host.wait_for("turn 1's result", |v| v["type"] == "result").await;
                    host.send(&user(2)).await;
                    assert!(gen1.next_input().await.is_some());
                    gen1.send(gone("microvm-1")).await;
                    let mut gen2 = far(&hand).await;
                    moved_to(&hand, "microvm-2", MoveKind::Readdress, "at");
                    gen2.started().await;
                    let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                    assert_eq!(gen2.next_input().await, Some(user(2)));
                    gen2.line(&answer(init2["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                    let continues = note_continues("microvm-2");
                    host.wait_for("the note that the chat goes on", |v| v["content"] == continues.as_str()).await;
                    let paths = Paths::from_root_and_env(d.path().join("bridge"), None);
                    let ends_now: Vec<_> = crate::bridge::audit::read_rows(&paths.audit(), None).unwrap().iter().filter(|r| r["event"] == "session_move_end").map(row_of).collect();
                    assert_eq!(ends_now, [["done", "2", "microvm-2", "at", "asked", "box"]], "the grace wrote the move done");
                    let text = if cut { format!("No message found with message.uuid of: {}", "a-1") } else { format!("No conversation found with session ID: {SID}") };
                    gen2.line(&miss(&text)).await;
                    gen2.exit(1).await;
                    if !cut {
                        let (code, mut pump) = ended(task).await;
                        assert_eq!((code, pump.finish.map(|f| f.1)), (8, Some(EndReason::MoveFailed)));
                        let line = pump.final_line.clone().unwrap_or_default();
                        assert!(line.starts_with("the chat's VM microvm-1 was lost (it was terminated); moving the chat to a new VM failed: ") && line.contains(&text), "{line}");
                        assert_eq!(hand.borrow().whys.len(), 2, "no retry");
                        assert!(!host.json().iter().any(|v| v["is_error"] == true), "the host never got the miss");
                        pump.conclude(code);
                        let note = end_note(&pump);
                        assert!(note.contains("end:move_failed") && note.contains("; step:spawn"), "{note}");
                        let ends = audit_rows(&pump, "session_move_end");
                        assert_eq!(ends.iter().map(row_of).collect::<Vec<_>>(), [["done", "2", "microvm-2", "at", "asked", "box"], ["failed", "2", "microvm-2", "at", "asked", "box"]], "{ends:?}");
                        assert_eq!(ends[1]["detail"]["code"].as_str(), Some("8"));
                        assert_eq!(registry_row(&pump, SID).vms.last().and_then(|v| v.get("end")).and_then(|e| e.as_str()), Some("failed"));
                        return;
                    }
                    let mut gen3 = far(&hand).await;
                    assert!(matches!(hand.borrow().whys.last(), Some(StartWhy::Move(m)) if m.kind == MoveKind::Respawn && m.from_vm == "microvm-2" && m.outstanding.is_empty()), "{:?}", hand.borrow().whys);
                    if retry_vm == "microvm-2" {
                        hand.borrow_mut().snap.moved = Some(crate::bridge::remote::link::MoveDone { kind: MoveKind::Respawn, cut: "none", touchid: "cached", seed: "kept", stayed: false });
                    } else {
                        moved_to(&hand, retry_vm, MoveKind::Readdress, "none");
                    }
                    gen3.started().await;
                    let init3: Value = serde_json::from_str(&gen3.next_input().await.expect("the replayed initialize")).unwrap();
                    assert_eq!(gen3.next_input().await, Some(user(2)), "the line again");
                    gen3.line(&answer(init3["request_id"].as_str().unwrap(), r#"{"pid":4444}"#)).await;
                    for line in [init_frame(SID), result_for(2)] {
                        gen3.line(&line).await;
                    }
                    host.wait_for("turn 2's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()).await;
                    host.eof().await;
                    assert_eq!(gen3.next_input().await, None);
                    gen3.exit(0).await;
                    let (code, mut pump) = ended(task).await;
                    assert_eq!(code, 0, "{retry_vm}");
                    assert!(!host.json().iter().any(|v| v["is_error"] == true), "the host never got the miss");
                    let mut want = vec![note_moving("microvm-1", LossCause::VmGone), note_continues("microvm-2")];
                    let mut rows = vec![["done", "2", "microvm-2", "at", "asked", "box"]];
                    if retry_vm != "microvm-2" {
                        want.push(note_continues(retry_vm));
                        rows.push(["done", "3", retry_vm, "none", "asked", "box"]);
                    }
                    assert_eq!(notes(&host), want, "{retry_vm}");
                    pump.conclude(code);
                    let note = end_note(&pump);
                    assert!(note.contains("moves:readdress=1,respawn=0,migrate=0") && note.contains("; cut:none"), "{note}");
                    let ends = audit_rows(&pump, "session_move_end");
                    assert_eq!(ends.iter().map(row_of).collect::<Vec<_>>(), rows, "{retry_vm}: {ends:?}");
                });
            }
        }

        /// §2.2's fresh chat: one begun here with no result yet moves fresh
        /// (its cut `Fresh`: `--session-id`, nothing restored); a
        /// `--continue` chat never does, nor a `--resume` one whose CLI forked
        /// the session under a new id, their CLI having carried on an earlier
        /// conversation.
        #[test]
        fn only_a_chat_begun_here_moves_fresh() {
            const FORK: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";
            let resume = format!("--resume={SID}");
            for (extra, sid, fresh) in [(vec![], SID, true), (vec!["--continue"], SID, false), (vec![resume.as_str(), "--fork-session"], FORK, false)] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &extra);
                    let task = supervise(pump, io);
                    let mut gen1 = far(&hand).await;
                    gen1.started().await;
                    handshake(&host, &mut gen1, sid).await;
                    host.send(&user(1)).await;
                    assert!(gen1.next_input().await.is_some());
                    gen1.send(gone("microvm-1")).await;
                    let mut gen2 = far(&hand).await;
                    assert!(matches!(&hand.borrow().whys[..], [StartWhy::First, StartWhy::Move(m)] if m.fresh_chat == fresh && m.outstanding == [uuid_of(1)] && m.session_id.as_deref() == Some(sid)), "{extra:?}: {:?}", hand.borrow().whys);
                    host.eof().await;
                    assert_eq!(gen2.next_signal().await, Some(Sig::Term), "the host's EOF cancels the pending move");
                    gen2.send(ChildEvent::SpawnFailed(SpawnFailure::stopped(StartStep::TouchId, None))).await;
                    let (code, _) = ended(task).await;
                    assert_eq!(code, 0, "{extra:?}");
                });
            }
        }

        /// A `/clear` (a new session id from the same CLI) begins a fresh
        /// session (§2.2, per session): lost in its first turn, the chat moves
        /// fresh under the new id, with no leaf of the old session's.
        #[test]
        fn a_cleared_chats_new_session_moves_fresh() {
            const CLEARED: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d";
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                for line in [assistant("a-1"), result_for(1)] {
                    gen1.line(&line).await;
                }
                host.wait_for("turn 1's result", |v| v["type"] == "result").await;
                host.send(&user(2)).await;
                assert!(gen1.next_input().await.is_some());
                gen1.line(&init_frame(CLEARED)).await;
                host.wait_for("the new session's init", |v| v["session_id"] == CLEARED).await;
                gen1.send(gone("microvm-1")).await;
                let mut gen2 = far(&hand).await;
                assert!(matches!(&hand.borrow().whys[..], [StartWhy::First, StartWhy::Move(m)] if m.fresh_chat && m.session_id.as_deref() == Some(CLEARED) && m.outstanding == [uuid_of(2)] && m.leaf.is_none()), "{:?}", hand.borrow().whys);
                host.eof().await;
                assert_eq!(gen2.next_signal().await, Some(Sig::Term), "the host's EOF cancels the pending move");
                gen2.send(ChildEvent::SpawnFailed(SpawnFailure::stopped(StartStep::TouchId, None))).await;
                let (code, _) = ended(task).await;
                assert_eq!(code, 0);
            });
        }

        /// The VM lost while the host's `initialize` waits for its answer
        /// (Cursor sends nothing else meanwhile): the move starts at once,
        /// with no host line, its note the move's, in the host's window
        /// (`init_answered` false: T0 + 50 s); the moved CLI's answer to the
        /// replayed `initialize` reaches the host under the host's id, the
        /// wrapper's pid in it, and times the session's `init_ms`. No turn
        /// runs, so no init comes: with no miss within `RESUME_MISS_GRACE`
        /// of that answer the CLI resumed, and the move is done (its note
        /// that the chat goes on, its one `session_move_end` `done`).
        #[test]
        fn a_loss_before_the_initialize_answer_moves_at_once() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let resume = format!("--resume={SID}");
                let (pump, hand, host, io) = remote_pump(d.path(), &[&resume]);
                hand.borrow_mut().snap.vm = Some("microvm-1".into());
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                host.send(INIT).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(INIT));
                gen1.send(gone("microvm-1")).await;
                let mut gen2 = far(&hand).await;
                assert!(matches!(&hand.borrow().whys[..], [StartWhy::First, StartWhy::Move(m)] if m.kind == MoveKind::Readdress && !m.init_answered && m.outstanding.is_empty() && m.session_id.as_deref() == Some(SID)), "{:?}", hand.borrow().whys);
                assert_eq!(notes(&host), [note_moving("microvm-1", LossCause::VmGone)], "the move's note, not the wait's");
                moved_to(&hand, "microvm-2", MoveKind::Readdress, "none");
                gen2.started().await;
                let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                assert_eq!(init2["request"]["subtype"], "initialize");
                gen2.line(&answer(init2["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                let answered = host.wait_for("the initialize answer", |v| v["type"] == "control_response").await;
                assert_eq!((answered["response"]["request_id"].as_str(), answered["response"]["response"]["pid"].as_u64()), (Some("i1"), Some(u64::from(std::process::id()))));
                assert_eq!(notes(&host).len(), 1, "within the grace nothing says the chat goes on");
                let continues = note_continues("microvm-2");
                host.wait_for("the note that the chat goes on", |v| v["content"] == continues.as_str()).await;
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                let out = pump.conclude(code);
                assert!(out.init_latency_ms.is_some(), "the moved CLI's answer is the session's init_ms");
                let ends = audit_rows(&pump, "session_move_end");
                assert_eq!(ends.iter().map(|r| r["detail"]["outcome"].clone()).collect::<Vec<_>>(), [Value::from("done")], "{ends:?}");
            });
        }

        /// A moved CLI that does not resume the session fails the move, and
        /// the host never hears it: one that ends before its first init with
        /// nothing on stdout (`--session-id`'s `is already in use` is on its
        /// stderr alone), and one whose start-up error result comes before
        /// that init (held, never forwarded). Exit 8 with the move's line,
        /// `end:move_failed` at `step:spawn`, the move's one
        /// `session_move_end` `failed`, the generation's `vms` entry `failed`.
        #[test]
        fn a_moved_cli_that_never_resumes_fails_the_move() {
            for said in [None, Some("Error: a start-up refusal")] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                    hand.borrow_mut().snap.vm = Some("microvm-1".into());
                    let task = supervise(pump, io);
                    let mut gen1 = far(&hand).await;
                    gen1.started().await;
                    handshake(&host, &mut gen1, SID).await;
                    host.send(&user(1)).await;
                    assert!(gen1.next_input().await.is_some());
                    gen1.send(gone("microvm-1")).await;
                    let gen2 = far(&hand).await;
                    moved_to(&hand, "microvm-2", MoveKind::Readdress, "fresh");
                    gen2.started().await;
                    if let Some(text) = said {
                        gen2.line(&format!(r#"{{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"{SID}","errors":["{text}"]}}"#)).await;
                    }
                    gen2.exit(1).await;
                    let (code, mut pump) = ended(task).await;
                    assert_eq!((code, pump.finish.map(|f| f.1)), (8, Some(EndReason::MoveFailed)), "{said:?}");
                    let line = pump.final_line.clone().unwrap_or_default();
                    let inner = said.unwrap_or("the moved claude ended (exit 1) before it resumed the session");
                    assert!(line.starts_with("the chat's VM microvm-1 was lost (it was terminated); moving the chat to a new VM failed: ") && line.contains(inner), "{line}");
                    assert!(!host.json().iter().any(|v| v["type"] == "result"), "the host never got a result: {:?}", host.json());
                    pump.conclude(code);
                    let note = end_note(&pump);
                    assert!(note.contains("end:move_failed") && note.contains("; step:spawn"), "{note}");
                    let ends = audit_rows(&pump, "session_move_end");
                    assert_eq!(ends.iter().map(|r| r["detail"]["outcome"].clone()).collect::<Vec<_>>(), [Value::from("failed")], "{ends:?}");
                    assert_eq!(registry_row(&pump, SID).vms.last().and_then(|v| v.get("end")).and_then(|e| e.as_str()), Some("failed"));
                });
            }
        }

        /// A pinned session (`AI_ENV_BRIDGE_VM`: its VM or nothing) never
        /// moves to another VM: its VM lost mid-turn is S9's exit 8 with the
        /// loss's own line, no note, no `session_move`, no move counted; its
        /// spawn gone on the pinned VM restarts there (a respawn).
        #[test]
        fn a_pinned_session_never_moves_to_another_vm() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                hand.borrow_mut().snap.pinned = Some("microvm-1".into());
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                gen1.send(gone("microvm-1")).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!((code, pump.finish.map(|f| f.1)), (8, Some(EndReason::LinkLost)));
                assert_eq!(pump.final_line.as_deref(), Some(Failure::LinkLost { vm: "microvm-1".into() }.line().as_str()));
                assert_eq!(hand.borrow().whys, [StartWhy::First], "no move");
                assert!(notes(&host).is_empty(), "{:?}", notes(&host));
                pump.conclude(code);
                assert!(audit_rows(&pump, "session_move").is_empty());
                assert!(!end_note(&pump).contains("moves:"), "{}", end_note(&pump));
            });
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                hand.borrow_mut().snap.pinned = Some("microvm-1".into());
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                gen1.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                host.send(&user(2)).await;
                assert!(gen1.next_input().await.is_some());
                let spawn_gone = LinkLoss::of(&crate::bridge::errors::BridgeError::SpawnGone("the spawn is not on microvm-1".into()), "microvm-1", None);
                gen1.send(ChildEvent::Lost(spawn_gone)).await;
                let mut gen2 = far(&hand).await;
                assert!(matches!(&hand.borrow().whys[..], [StartWhy::First, StartWhy::Move(m)] if m.kind == MoveKind::Respawn && m.cause == Some(LossCause::SpawnGone)), "{:?}", hand.borrow().whys);
                host.eof().await;
                assert_eq!(gen2.next_signal().await, Some(Sig::Term), "the host's EOF cancels the pending move");
                gen2.send(ChildEvent::SpawnFailed(SpawnFailure::stopped(StartStep::TouchId, None))).await;
                let (code, _) = ended(task).await;
                assert_eq!(code, 0);
            });
        }

        /// A move lost again inside its replay window, a host `interrupt`
        /// pending (L4 replays it): the next move's window is its own, so
        /// no earlier generation's deadline fails the `interrupt` while
        /// generation 3's start is pending, and generation 3's answer reaches
        /// the host under the host's id; no `replay_timeout` is audited.
        #[test]
        fn a_move_lost_in_its_replay_window_leaves_the_next_its_own() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (mut pump, hand, host, io) = remote_pump(d.path(), &[]);
                pump.knobs.replay_deadline = Some(Duration::from_millis(200));
                hand.borrow_mut().snap.vm = Some("microvm-1".into());
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                let interrupt = r#"{"type":"control_request","request_id":"x1","request":{"subtype":"interrupt"}}"#;
                host.send(interrupt).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(interrupt));
                gen1.send(gone("microvm-1")).await;
                let gen2 = far(&hand).await;
                moved_to(&hand, "microvm-2", MoveKind::Readdress, "none");
                gen2.started().await;
                gen2.send(gone("microvm-2")).await;
                let mut gen3 = far(&hand).await;
                tokio::time::sleep(Duration::from_millis(400)).await;
                assert!(!host.json().iter().any(|v| v["type"] == "control_response" && v["response"]["request_id"] == "x1"), "nothing answered the interrupt while generation 3's start was pending: {:?}", host.json());
                moved_to(&hand, "microvm-3", MoveKind::Readdress, "none");
                gen3.started().await;
                let init3: Value = serde_json::from_str(&gen3.next_input().await.expect("the replayed initialize")).unwrap();
                assert_eq!(gen3.next_input().await, Some(user(1)), "the line again");
                let int3: Value = serde_json::from_str(&gen3.next_input().await.expect("the replayed interrupt, last")).unwrap();
                assert_eq!((init3["request"]["subtype"].as_str(), int3["request"]["subtype"].as_str()), (Some("initialize"), Some("interrupt")));
                gen3.line(&answer(init3["request_id"].as_str().unwrap(), r#"{"pid":4545}"#)).await;
                gen3.line(&answer(int3["request_id"].as_str().unwrap(), "{}")).await;
                let answered = host.wait_for("the interrupt's answer", |v| v["response"]["request_id"] == "x1").await;
                assert_eq!(answered["response"]["subtype"], "success", "{answered}");
                host.eof().await;
                while gen3.next_input().await.is_some() {}
                gen3.exit(0).await;
                let (code, pump) = ended(task).await;
                assert_eq!(code, 0);
                assert!(audit_rows(&pump, "replay_timeout").is_empty(), "{:?}", audit_rows(&pump, "replay_timeout"));
            });
        }

        /// §6.1's prefix rule: a reopened session's row keeps the `vms`
        /// entries an earlier wrapper left (its own after them, each with its
        /// why, its end and this wrapper's pid), at most `VMS_KEPT`, the
        /// oldest dropped; `created` is this wrapper's registration.
        #[test]
        fn the_vms_history_survives_a_reopen() {
            for earlier in [2_usize, registry::VMS_KEPT] {
                let d = tempfile::tempdir().unwrap();
                on_local(async {
                    let resume = format!("--resume={SID}");
                    let (pump, hand, host, io) = remote_pump(d.path(), &[&resume]);
                    hand.borrow_mut().snap.vm = Some("microvm-1".into());
                    let paths = pump.sess.paths.clone();
                    let old = |n: usize| registry::VmEntry { gen: 1, vm: format!("microvm-old-{n}"), spawn: None, from: "2026-10-01T00:00:00Z".into(), to: Some("2026-10-01T01:00:00Z".into()), why: "first".into(), end: Some("close".into()), pid: 1 };
                    let row = SessionRow {
                        v: registry::REGISTRY_SCHEMA_V,
                        session_id: SID.into(),
                        created: "2026-10-01T00:00:00Z".into(),
                        last_seen: "2026-10-01T01:00:00Z".into(),
                        status: "closed".into(),
                        mode: "remote".into(),
                        pid: 1,
                        vms: (0..earlier).map(|n| toml::Value::try_from(old(n)).unwrap()).collect(),
                        ..SessionRow::default()
                    };
                    registry::write(&paths, &row).unwrap();
                    let task = supervise(pump, io);
                    let mut gen1 = far(&hand).await;
                    gen1.started().await;
                    handshake(&host, &mut gen1, SID).await;
                    host.send(&user(1)).await;
                    assert!(gen1.next_input().await.is_some());
                    gen1.send(gone("microvm-1")).await;
                    let mut gen2 = far(&hand).await;
                    moved_to(&hand, "microvm-2", MoveKind::Readdress, "none");
                    gen2.started().await;
                    host.eof().await;
                    while gen2.next_input().await.is_some() {}
                    gen2.exit(0).await;
                    let (code, mut pump) = ended(task).await;
                    pump.conclude(code);
                    let row = registry_row(&pump, SID);
                    assert_ne!(row.created, "2026-10-01T00:00:00Z", "created is this wrapper's registration");
                    let vms: Vec<registry::VmEntry> = row.vms.iter().map(|v| registry::VmEntry::from_value(v).expect("a vms entry")).collect();
                    assert_eq!(vms.len(), (earlier + 2).min(registry::VMS_KEPT), "{vms:?}");
                    let own = &vms[vms.len() - 2..];
                    assert_eq!((own[0].gen, own[0].vm.as_str(), own[0].why.as_str(), own[0].end.as_deref(), own[0].pid), (1, "microvm-1", "first", Some("lost:vm_gone"), std::process::id()));
                    assert_eq!((own[1].gen, own[1].vm.as_str(), own[1].why.as_str(), own[1].end.as_deref(), own[1].pid), (2, "microvm-2", "readdress:vm_gone", Some("close"), std::process::id()));
                    let kept: Vec<&str> = vms[..vms.len() - 2].iter().map(|v| v.vm.as_str()).collect();
                    let first_kept = earlier + 2 - vms.len();
                    let want: Vec<String> = (first_kept..earlier).map(|n| format!("microvm-old-{n}")).collect();
                    assert_eq!(kept, want.iter().map(String::as_str).collect::<Vec<_>>(), "the earlier entries, the oldest dropped past VMS_KEPT");
                });
            }
        }

        // ---- S10 (C3): migrations (§B), parks (§D), `session migrate`'s request (§7.1) ----------

        const WALL: MigrateTrigger = MigrateTrigger::Wall { left_s: 600 };

        /// Until `pred` holds of the hand factory.
        async fn until_hand(hand: &Rc<RefCell<Hand>>, what: &str, pred: impl Fn(&Hand) -> bool) {
            let until = Instant::now() + T;
            while !pred(&hand.borrow()) {
                assert!(Instant::now() < until, "the hand factory never saw {what}");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        /// A started session on `microvm-1` whose wall comes near with turn 1's
        /// result: phase A asked for (the hand's `due` taken back once asked).
        async fn migrating(hand: &Rc<RefCell<Hand>>, host: &Host, gen1: &mut Far) {
            hand.borrow_mut().snap.vm = Some("microvm-1".into());
            gen1.started().await;
            handshake(host, gen1, SID).await;
            hand.borrow_mut().due = Some(WALL);
            host.send(&user(1)).await;
            assert_eq!(gen1.next_input().await, Some(user(1)));
            for line in [echo(1), assistant("a-1"), result_for(1)] {
                gen1.line(&line).await;
            }
            host.wait_for("turn 1's result", |v| v["type"] == "result").await;
            until_hand(hand, "phase A", |h| h.prepares.len() == 1).await;
            hand.borrow_mut().due = None;
            assert_eq!(hand.borrow().prepares, [WALL]);
        }

        /// §B: a due migration's phase A runs while the chat goes on, said
        /// first (`note_migrating`, `session_move` with the live generation
        /// and its trigger); its prepared VM waits for a quiet point: never
        /// while a line is outstanding. At the first quiet point the switch
        /// begins: the old CLI gets its EOF; the host's line meanwhile is
        /// held, unrecorded, until the moved generation (`Move(Migrate)`: no
        /// line outstanding, so no cut) read the replayed `initialize`, then
        /// it comes. The move is counted and done once the moved CLI resumed;
        /// the row's `vms` say `moved`, then `migrate:wall`.
        #[test]
        fn a_migration_switches_only_at_a_quiet_point() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                migrating(&hand, &host, &mut gen1).await;
                assert_eq!(notes(&host), [note_migrating("microvm-1", &WALL)], "phase A is said once");
                // Turn 2 starts; phase A ends while it runs: no switch before its result.
                host.send(&user(2)).await;
                assert_eq!(gen1.next_input().await, Some(user(2)));
                hand.borrow_mut().switch = true;
                gen1.send(ChildEvent::MoveReady(MoveReady { to_vm: "microvm-2".into(), how: "started", ms: 20 })).await;
                gen1.line(&echo(2)).await;
                tokio::time::sleep(Duration::from_millis(150)).await;
                assert_eq!(hand.borrow().switches, 0, "a line is outstanding: no quiet point");
                gen1.line(&result_for(2)).await;
                host.wait_for("turn 2's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()).await;
                // The quiet point: the switch, the old CLI's EOF; the host's next line is held meanwhile.
                assert_eq!(gen1.next_input().await, None, "the old CLI's EOF");
                assert_eq!(hand.borrow().switches, 1);
                host.send(&user(3)).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
                gen1.exit(0).await;
                let mut gen2 = far(&hand).await;
                // Turn 2 forwarded no assistant frame: no leaf (turn 1's would cut turn 2 away).
                let want = MoveWhy {
                    kind: MoveKind::Migrate,
                    cause: None,
                    trigger: Some(WALL),
                    from_vm: "microvm-1".into(),
                    from_spawn: None,
                    session_id: Some(SID.into()),
                    outstanding: Vec::new(),
                    leaf: None,
                    fresh_chat: false,
                    init_answered: true,
                };
                assert_eq!(hand.borrow().whys, [StartWhy::First, StartWhy::Move(want)]);
                assert_eq!(registry::read(&Paths::from_root_and_env(d.path().join("bridge"), None), SID).unwrap().map(|r| r.status).as_deref(), Some("migrating"));
                moved_to(&hand, "microvm-2", MoveKind::Migrate, "none");
                gen2.started().await;
                let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                assert_eq!(init2["request"]["subtype"], "initialize");
                assert_eq!(gen2.next_input().await, Some(user(3)), "the held line, after the replay");
                gen2.line(&answer(init2["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                host.wait_for("the chat goes on", |v| v["subtype"] == "informational" && v["content"] == note_continues("microvm-2").as_str()).await;
                for line in [init_frame(SID), echo(3), result_for(3)] {
                    gen2.line(&line).await;
                }
                host.wait_for("turn 3's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(3).as_str()).await;
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                assert_eq!(host.json().iter().filter(|v| v["type"] == "control_response").count(), 1, "the host's initialize answered once");
                pump.conclude(code);
                assert!(end_note(&pump).split("; ").any(|p| p == "moves:readdress=0,respawn=0,migrate=1"), "{}", end_note(&pump));
                let moved = audit_rows(&pump, "session_move");
                assert_eq!(moved.len(), 1, "{moved:?}");
                let m = &moved[0]["detail"];
                assert_eq!((m["gen"].as_str(), m["kind"].as_str(), m["trigger"].as_str(), m["from_vm"].as_str()), (Some("1"), Some("migrate"), Some("wall"), Some("microvm-1")));
                let ends = audit_rows(&pump, "session_move_end");
                assert_eq!(ends.len(), 1, "{ends:?}");
                assert_eq!((ends[0]["detail"]["outcome"].as_str(), ends[0]["detail"]["to_vm"].as_str(), ends[0]["detail"]["kind"].as_str()), (Some("done"), Some("microvm-2"), Some("migrate")));
                let row = registry_row(&pump, SID);
                let whys: Vec<_> = row.vms.iter().map(|v| (v["why"].as_str().map(str::to_string), v.get("end").and_then(|e| e.as_str()).map(str::to_string))).collect();
                assert_eq!(whys, [(Some("first".into()), Some("moved".into())), (Some("migrate:wall".into()), Some("close".into()))]);
            });
        }

        /// M4: a phase A whose Touch ID went unanswered leaves the chat on its
        /// VM: said (it tries again after the next turn), audited
        /// `session_move_end` `stayed` with its step and code, nothing
        /// started; the next turn's result asks for phase A again.
        #[test]
        fn a_failed_prepare_stays_on_the_old_vm() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                migrating(&hand, &host, &mut gen1).await;
                gen1.send(ChildEvent::MoveFailed(MoveFailure { step: StartStep::TouchId, code: 5, word: "touchid_timeout", again: true })).await;
                let stayed = note_stayed("microvm-1", "no Touch ID in time", StayedThen::Retry);
                host.wait_for("the stayed note", |v| v["subtype"] == "informational" && v["content"] == stayed.as_str()).await;
                hand.borrow_mut().switch = true;
                hand.borrow_mut().due = Some(MigrateTrigger::Wall { left_s: 500 });
                host.send(&user(2)).await;
                assert_eq!(gen1.next_input().await, Some(user(2)));
                gen1.line(&result_for(2)).await;
                host.wait_for("turn 2's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()).await;
                until_hand(&hand, "phase A again", |h| h.prepares.len() == 2).await;
                assert_eq!(hand.borrow().prepares[1], MigrateTrigger::Wall { left_s: 500 }, "asked again after the next turn (M4)");
                assert_eq!((hand.borrow().switches, hand.borrow().whys.len()), (0, 1), "nothing prepared, nothing switched");
                host.eof().await;
                assert_eq!(gen1.next_input().await, None);
                gen1.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                pump.conclude(code);
                let ends = audit_rows(&pump, "session_move_end");
                assert_eq!(ends.len(), 2, "{ends:?}");
                let e = &ends[0]["detail"];
                assert_eq!((e["outcome"].as_str(), e["kind"].as_str(), e["step"].as_str(), e["code"].as_str(), e["from_vm"].as_str()), (Some("stayed"), Some("migrate"), Some("touchid"), Some("5"), Some("microvm-1")));
                // The second phase A, still running when the session ended, is given up with it.
                assert_eq!((ends[1]["detail"]["outcome"].as_str(), ends[1]["detail"]["kind"].as_str()), (Some("abandoned"), Some("migrate")), "{ends:?}");
                assert_eq!(audit_rows(&pump, "session_move").len(), 2, "each phase A's start");
                assert!(!end_note(&pump).contains("moves:"), "no move: {}", end_note(&pump));
            });
        }

        /// §2.4: a phase A that failed for good (here SELECT_VM refused at
        /// `[vm].max_concurrent`, no Touch ID to answer) ends wall migrations
        /// in this process: said (the chat moves when the VM reaches its
        /// wall), and no later result asks for one again.
        #[test]
        fn a_prepare_refused_for_good_ends_wall_migrations() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                migrating(&hand, &host, &mut gen1).await;
                gen1.send(ChildEvent::MoveFailed(MoveFailure { step: StartStep::SelectVm, code: 9, word: "max_concurrent", again: false })).await;
                let stayed = note_stayed("microvm-1", "no VM can start: [vm].max_concurrent", StayedThen::AtWall);
                host.wait_for("the stayed note", |v| v["subtype"] == "informational" && v["content"] == stayed.as_str()).await;
                let asked = hand.borrow().asked_due;
                hand.borrow_mut().due = Some(WALL);
                for n in 2..=3 {
                    host.send(&user(n)).await;
                    assert_eq!(gen1.next_input().await, Some(user(n)));
                    gen1.line(&result_for(n)).await;
                    host.wait_for("the result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(n).as_str()).await;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert_eq!((hand.borrow().asked_due, hand.borrow().prepares.len()), (asked, 1), "no wall migration is asked for again");
                host.eof().await;
                assert_eq!(gen1.next_input().await, None);
                gen1.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                pump.conclude(code);
                let ends = audit_rows(&pump, "session_move_end");
                assert_eq!(ends.iter().map(|r| (r["detail"]["outcome"].clone(), r["detail"]["code"].clone())).collect::<Vec<_>>(), [(Value::from("stayed"), Value::from("9"))]);
            });
        }

        /// §B: a switch that fell back to a respawn on the old VM (its
        /// pipeline wrote `stayed`) writes no `done`: the chat stays, said;
        /// at the second such fallback (`MIGRATE_PREP_TRIES`) wall migrations
        /// are over in this process, so no later result asks for one.
        #[test]
        fn a_switch_that_fell_back_stays_and_counts_toward_the_tries() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen = far(&hand).await;
                migrating(&hand, &host, &mut gen).await;
                hand.borrow_mut().switch = true;
                for n in 1..=MIGRATE_PREP_TRIES {
                    gen.send(ChildEvent::MoveReady(MoveReady { to_vm: "microvm-2".into(), how: "started", ms: 20 })).await;
                    assert_eq!(gen.next_input().await, None, "the old CLI's EOF");
                    gen.exit(0).await;
                    gen = far(&hand).await;
                    hand.borrow_mut().snap.moved = Some(crate::bridge::remote::link::MoveDone { kind: MoveKind::Migrate, cut: "none", touchid: "cached", seed: "kept", stayed: true });
                    gen.started().await;
                    let init: Value = serde_json::from_str(&gen.next_input().await.expect("the replayed initialize")).unwrap();
                    gen.line(&answer(init["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                    let then = if n < MIGRATE_PREP_TRIES { StayedThen::Retry } else { StayedThen::AtWall };
                    let stayed = note_stayed("microvm-1", "the move to the new VM failed after the old claude stopped; it restarted here", then);
                    host.wait_for("the stayed note", |v| v["content"] == stayed.as_str()).await;
                    if n < MIGRATE_PREP_TRIES {
                        hand.borrow_mut().due = Some(WALL);
                        host.send(&user(10 + n)).await;
                        assert_eq!(gen.next_input().await, Some(user(10 + n)));
                        gen.line(&result_for(10 + n)).await;
                        until_hand(&hand, "phase A again", |h| h.prepares.len() == n as usize + 1).await;
                        hand.borrow_mut().due = None;
                    }
                }
                let asked = hand.borrow().asked_due;
                hand.borrow_mut().due = Some(WALL);
                host.send(&user(20)).await;
                assert_eq!(gen.next_input().await, Some(user(20)));
                gen.line(&result_for(20)).await;
                host.wait_for("the result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(20).as_str()).await;
                assert_eq!(hand.borrow().asked_due, asked, "no wall migration after MIGRATE_PREP_TRIES fallbacks");
                host.eof().await;
                while gen.next_input().await.is_some() {}
                gen.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                pump.conclude(code);
                assert!(audit_rows(&pump, "session_move_end").iter().all(|r| r["detail"]["outcome"] != "done"), "{:?}", audit_rows(&pump, "session_move_end"));
                assert!(!notes(&host).iter().any(|n| n.contains("continues on")), "{:?}", notes(&host));
            });
        }

        /// §7.1 at the pump: `session migrate`'s signal takes its session's
        /// fresh request (removed) and starts phase A at once with its nonce
        /// (`Command`), whatever `migration_due` says; a stale one is removed
        /// unanswered; one while a migration runs is answered `refused`.
        #[test]
        fn a_session_migrate_request_starts_phase_a_at_once_or_is_refused() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let paths = pump.sess.paths.clone();
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                hand.borrow_mut().snap.vm = Some("microvm-1".into());
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                gen1.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                let now = crate::wire::time::unix_now();
                let write = |age: u64, nonce: &str| {
                    std::fs::create_dir_all(paths.sessions()).unwrap();
                    let req = crate::bridge::migrate::MigrateRequest { v: 1, nonce: nonce.into(), requested_at: crate::wire::time::rfc3339_utc(now - age), by_pid: 1 };
                    std::fs::write(paths.session_migrate_request(SID), serde_json::to_string(&req).unwrap()).unwrap();
                };
                write(120, "stale-nonce");
                host.signal(HostSignal::Migrate);
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert!(!paths.session_migrate_request(SID).exists() && hand.borrow().prepares.is_empty(), "a stale request: removed, unanswered");
                write(0, "nonce-1");
                host.signal(HostSignal::Migrate);
                until_hand(&hand, "the command's phase A", |h| h.prepares.len() == 1).await;
                assert_eq!(hand.borrow().prepares, [MigrateTrigger::Command { nonce: "nonce-1".into() }]);
                assert!(!paths.session_migrate_request(SID).exists(), "taken");
                host.wait_for("the note", |v| v["content"] == note_migrating("microvm-1", &MigrateTrigger::Command { nonce: "nonce-1".into() }).as_str()).await;
                write(0, "nonce-2");
                host.signal(HostSignal::Migrate);
                let until = Instant::now() + T;
                while !crate::bridge::audit::read_rows(&paths.audit(), None).unwrap().iter().any(|r| r["event"] == "session_move_end" && r["detail"]["request"] == "nonce-2") {
                    assert!(Instant::now() < until, "the second request was never answered");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                host.eof().await;
                assert_eq!(gen1.next_input().await, None);
                gen1.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                pump.conclude(code);
                let ends = audit_rows(&pump, "session_move_end");
                // The second request refused at once; the first, its phase A still running at the session's end, given up then.
                assert_eq!(
                    ends.iter().map(|r| (r["detail"]["outcome"].clone(), r["detail"]["request"].clone())).collect::<Vec<_>>(),
                    [(Value::from("refused"), Value::from("nonce-2")), (Value::from("abandoned"), Value::from("nonce-1"))]
                );
                let moved = audit_rows(&pump, "session_move");
                assert_eq!((moved.len(), moved[0]["detail"]["trigger"].as_str(), moved[0]["detail"]["request"].as_str()), (1, Some("command"), Some("nonce-1")));
                assert_eq!(hand.borrow().prepares.len(), 1);
            });
        }

        /// §7.1, C3: a pinned session (`AI_ENV_BRIDGE_VM`: its VM or nothing,
        /// `RemoteSnapshot.pinned`) never migrates: `session migrate`'s
        /// fresh request is taken (removed) and answered `refused` with its
        /// nonce at once; no phase A starts, nothing is said to the host.
        #[test]
        fn a_pinned_sessions_migrate_request_is_refused() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let paths = pump.sess.paths.clone();
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                {
                    let mut h = hand.borrow_mut();
                    h.snap.vm = Some("microvm-1".into());
                    h.snap.pinned = Some("microvm-1".into());
                }
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                gen1.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                std::fs::create_dir_all(paths.sessions()).unwrap();
                let req = crate::bridge::migrate::MigrateRequest { v: 1, nonce: "nonce-pinned".into(), requested_at: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()), by_pid: 1 };
                std::fs::write(paths.session_migrate_request(SID), serde_json::to_string(&req).unwrap()).unwrap();
                host.signal(HostSignal::Migrate);
                let until = Instant::now() + T;
                while !crate::bridge::audit::read_rows(&paths.audit(), None).unwrap().iter().any(|r| r["event"] == "session_move_end" && r["detail"]["request"] == "nonce-pinned") {
                    assert!(Instant::now() < until, "the pinned session's request was never answered");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert!(!paths.session_migrate_request(SID).exists(), "taken");
                assert!(hand.borrow().prepares.is_empty(), "no phase A: {:?}", hand.borrow().prepares);
                host.eof().await;
                assert_eq!(gen1.next_input().await, None);
                gen1.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                pump.conclude(code);
                let ends = audit_rows(&pump, "session_move_end");
                assert_eq!(ends.iter().map(|r| (r["detail"]["outcome"].clone(), r["detail"]["request"].clone(), r["detail"]["kind"].clone())).collect::<Vec<_>>(), [(Value::from("refused"), Value::from("nonce-pinned"), Value::from("migrate"))]);
                assert!(audit_rows(&pump, "session_move").is_empty(), "no move started");
                assert!(notes(&host).is_empty(), "nothing said: {:?}", notes(&host));
            });
        }

        /// §D at the pump: after each line forwarded either way the link gets
        /// the chat's quiet (the verdict, since the last line that was no
        /// `keep_alive`, the last host frame's kind); a parked session's row
        /// says `parked`, then `active`; while parked the host's `keep_alive`
        /// is dropped and counted (`ka_dropped`), any other line forwarded.
        #[test]
        fn a_parked_session_drops_the_hosts_keep_alive_and_the_link_hears_the_quiet() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert!(gen1.next_input().await.is_some());
                {
                    let h = hand.borrow();
                    let last = h.quiet.last().expect("the quiet after the user line");
                    assert_eq!((last.verdict, last.last_host), (crate::bridge::park::Verdict::Busy, Some("user")), "a line outstanding");
                }
                gen1.line(&result_for(1)).await;
                host.wait_for("the result", |v| v["type"] == "result").await;
                until_hand(&hand, "an idle quiet", |h| h.quiet.last().is_some_and(|q| q.verdict == crate::bridge::park::Verdict::Idle)).await;
                let status = || registry::read(&Paths::from_root_and_env(d.path().join("bridge"), None), SID).unwrap().map(|r| r.status);
                gen1.send(ChildEvent::Parked(true)).await;
                let until = Instant::now() + T;
                while status().as_deref() != Some("parked") {
                    assert!(Instant::now() < until, "the row never said parked");
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                let told = hand.borrow().quiet.len();
                for _ in 0..3 {
                    host.send(r#"{"type":"keep_alive"}"#).await;
                }
                host.send(&user(2)).await;
                assert_eq!(gen1.next_input().await, Some(user(2)), "the user's line passes, the keep_alives never");
                gen1.send(ChildEvent::Parked(false)).await;
                let until = Instant::now() + T;
                while status().as_deref() != Some("active") {
                    assert!(Instant::now() < until, "the row never said active again");
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                assert_eq!(hand.borrow().quiet.len(), told + 1, "only the forwarded line told");
                host.send(r#"{"type":"keep_alive"}"#).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(r#"{"type":"keep_alive"}"#), "unparked: a keep_alive goes through");
                host.eof().await;
                assert_eq!(gen1.next_input().await, None);
                gen1.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                pump.conclude(code);
                assert!(end_note(&pump).split("; ").any(|p| p == "ka_dropped:3"), "{}", end_note(&pump));
            });
        }

        // ---- S10 (C3's review): a parked chat's switch, a loss during a migration, a switch's spawn that failed ----

        /// `session migrate`'s request of `nonce` for the session (fresh), and its signal.
        fn request(paths: &Paths, host: &Host, nonce: &str) {
            std::fs::create_dir_all(paths.sessions()).unwrap();
            let req = crate::bridge::migrate::MigrateRequest { v: 1, nonce: nonce.into(), requested_at: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()), by_pid: 1 };
            std::fs::write(paths.session_migrate_request(SID), serde_json::to_string(&req).unwrap()).unwrap();
            host.signal(HostSignal::Migrate);
        }

        /// §B, §3.3: a migration whose VM is prepared while the idle chat is
        /// parked is no quiet point yet (a switch's EOF to a session parked
        /// with no socket would close it parked, its claude left on the old
        /// VM): one `keep_alive` unparks it (any stdin does; never a second
        /// one), and the switch begins at the quiet point after its
        /// `Parked(false)`: the old CLI's EOF, the moved generation.
        #[test]
        fn a_migration_prepared_while_parked_unparks_the_chat_then_switches() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                migrating(&hand, &host, &mut gen1).await;
                gen1.send(ChildEvent::Parked(true)).await;
                hand.borrow_mut().switch = true;
                gen1.send(ChildEvent::MoveReady(MoveReady { to_vm: "microvm-2".into(), how: "started", ms: 20 })).await;
                assert_eq!(gen1.next_input().await.as_deref(), Some(r#"{"type":"keep_alive"}"#), "the unpark");
                assert!(tokio::time::timeout(Duration::from_millis(150), gen1.input.recv()).await.is_err(), "one keep_alive, no EOF while parked");
                assert_eq!(hand.borrow().switches, 0, "parked: no switch yet");
                gen1.send(ChildEvent::Parked(false)).await;
                assert_eq!(gen1.next_input().await, None, "the quiet point after the unpark: the old CLI's EOF");
                assert_eq!(hand.borrow().switches, 1);
                gen1.exit(0).await;
                let mut gen2 = far(&hand).await;
                assert!(matches!(hand.borrow().whys.last(), Some(StartWhy::Move(m)) if m.kind == MoveKind::Migrate && m.from_vm == "microvm-1"), "{:?}", hand.borrow().whys);
                moved_to(&hand, "microvm-2", MoveKind::Migrate, "none");
                gen2.started().await;
                let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                gen2.line(&answer(init2["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                host.wait_for("the chat goes on", |v| v["subtype"] == "informational" && v["content"] == note_continues("microvm-2").as_str()).await;
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                pump.conclude(code);
                let ends = audit_rows(&pump, "session_move_end");
                assert_eq!(ends.iter().map(|r| r["detail"]["outcome"].clone()).collect::<Vec<_>>(), [Value::from("done")], "{ends:?}");
            });
        }

        /// §A, §B: a lost VM's move while a migration's VM is prepared moves
        /// the chat as any loss (a re-address, at once mid-turn) and gives the
        /// migration up: `session_move_end` `abandoned` with `session
        /// migrate`'s nonce (its command answered at once); no switch comes
        /// at the next quiet point, a late `MoveReady` included.
        #[test]
        fn a_loss_while_a_migration_is_prepared_gives_the_migration_up() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let paths = pump.sess.paths.clone();
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                hand.borrow_mut().snap.vm = Some("microvm-1".into());
                gen1.started().await;
                handshake(&host, &mut gen1, SID).await;
                host.send(&user(1)).await;
                assert_eq!(gen1.next_input().await, Some(user(1)));
                gen1.line(&result_for(1)).await;
                host.wait_for("turn 1's result", |v| v["type"] == "result").await;
                request(&paths, &host, "nonce-1");
                until_hand(&hand, "the command's phase A", |h| h.prepares.len() == 1).await;
                // Turn 2 runs when the VM is prepared, then the platform ends the VM mid-turn.
                host.send(&user(2)).await;
                assert_eq!(gen1.next_input().await, Some(user(2)));
                hand.borrow_mut().switch = true;
                gen1.send(ChildEvent::MoveReady(MoveReady { to_vm: "microvm-2".into(), how: "started", ms: 20 })).await;
                gen1.send(gone("microvm-1")).await;
                let mut gen2 = far(&hand).await;
                assert!(matches!(hand.borrow().whys.last(), Some(StartWhy::Move(m)) if m.kind == MoveKind::Readdress), "{:?}", hand.borrow().whys);
                let given_up = |p: &Paths| crate::bridge::audit::read_rows(&p.audit(), None).unwrap().into_iter().filter(|r| r["event"] == "session_move_end" && r["detail"]["outcome"] == "abandoned").count();
                assert_eq!(given_up(&paths), 1, "the migration is given up as the re-address starts");
                moved_to(&hand, "microvm-2", MoveKind::Readdress, "none");
                gen2.started().await;
                let init2: Value = serde_json::from_str(&gen2.next_input().await.expect("the replayed initialize")).unwrap();
                assert_eq!(gen2.next_input().await, Some(user(2)), "the line again");
                gen2.line(&answer(init2["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                // A phase A end that comes late finds no migration: nothing switches at the quiet point.
                gen2.send(ChildEvent::MoveReady(MoveReady { to_vm: "microvm-2".into(), how: "started", ms: 20 })).await;
                for line in [init_frame(SID), echo(2), result_for(2)] {
                    gen2.line(&line).await;
                }
                host.wait_for("turn 2's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert_eq!((hand.borrow().switches, hand.borrow().whys.len()), (0, 2), "no switch, no third generation");
                host.eof().await;
                assert_eq!(gen2.next_input().await, None);
                gen2.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                pump.conclude(code);
                let ends = audit_rows(&pump, "session_move_end");
                let got: Vec<_> = ends.iter().map(|r| (r["detail"]["outcome"].clone(), r["detail"]["kind"].clone(), r["detail"]["request"].clone())).collect();
                assert_eq!(got, [(Value::from("abandoned"), Value::from("migrate"), Value::from("nonce-1")), (Value::from("done"), Value::from("readdress"), Value::Null)], "{ends:?}");
            });
        }

        /// §2.7: a switch whose new VM never started the moved CLI (its
        /// session refused the spawn there) falls back to the old VM: one
        /// more `Move(Migrate)` generation (the pipeline finds no VM prepared
        /// and respawns on the VM the switch left), the host's state replayed
        /// into it; at its `Started` the move's one end row, `stayed`, with
        /// that failure's step and code; the chat goes on there, said.
        #[test]
        fn a_switch_whose_new_vm_refuses_the_spawn_falls_back_to_the_old_vm() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                migrating(&hand, &host, &mut gen1).await;
                hand.borrow_mut().switch = true;
                gen1.send(ChildEvent::MoveReady(MoveReady { to_vm: "microvm-2".into(), how: "started", ms: 20 })).await;
                assert_eq!(gen1.next_input().await, None, "the old CLI's EOF");
                gen1.exit(0).await;
                let gen2 = far(&hand).await;
                hand.borrow_mut().snap.vm = Some("microvm-2".into());
                let refused = SpawnFailure { code: 7, step: StartStep::Spawn, line: Some("the spawn was refused".into()), cancelled: false, vm: Some("microvm-2".into()) };
                gen2.send(ChildEvent::SpawnFailed(refused)).await;
                let mut gen3 = far(&hand).await;
                let whys = hand.borrow().whys.clone();
                assert!(matches!(&whys[..], [StartWhy::First, StartWhy::Move(a), StartWhy::Move(b)] if a == b && b.kind == MoveKind::Migrate && b.from_vm == "microvm-1"), "{whys:?}");
                hand.borrow_mut().snap.vm = Some("microvm-1".into());
                hand.borrow_mut().snap.moved = Some(crate::bridge::remote::link::MoveDone { kind: MoveKind::Migrate, cut: "none", touchid: "asked", seed: "kept", stayed: true });
                gen3.started().await;
                let init3: Value = serde_json::from_str(&gen3.next_input().await.expect("the replayed initialize")).unwrap();
                gen3.line(&answer(init3["request_id"].as_str().unwrap(), r#"{"pid":4343}"#)).await;
                let stayed = note_stayed("microvm-1", "the move to the new VM failed after the old claude stopped; it restarted here", StayedThen::Retry);
                host.wait_for("the stayed note", |v| v["content"] == stayed.as_str()).await;
                host.send(&user(2)).await;
                assert_eq!(gen3.next_input().await, Some(user(2)));
                gen3.line(&result_for(2)).await;
                host.wait_for("turn 2's result", |v| v["type"] == "result" && v["user_message_uuid"] == uuid_of(2).as_str()).await;
                host.eof().await;
                assert_eq!(gen3.next_input().await, None);
                gen3.exit(0).await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0, "the chat went on");
                pump.conclude(code);
                let ends = audit_rows(&pump, "session_move_end");
                assert_eq!(ends.len(), 1, "{ends:?}");
                let e = &ends[0]["detail"];
                assert_eq!(
                    (e["outcome"].as_str(), e["kind"].as_str(), e["to_vm"].as_str(), e["step"].as_str(), e["code"].as_str(), e["touchid"].as_str()),
                    (Some("stayed"), Some("migrate"), Some("microvm-1"), Some("spawn"), Some("7"), Some("asked")),
                    "{ends:?}"
                );
            });
        }

        /// C3-E: a switch the old link's loss calls off is given up
        /// (`abandoned`), and so is a migration still preparing at the
        /// session's end: every migration's `session_move` has its end row.
        #[test]
        fn a_switch_called_off_by_a_loss_is_given_up() {
            let d = tempfile::tempdir().unwrap();
            on_local(async {
                let (pump, hand, host, io) = remote_pump(d.path(), &[]);
                let task = supervise(pump, io);
                let mut gen1 = far(&hand).await;
                migrating(&hand, &host, &mut gen1).await;
                hand.borrow_mut().switch = true;
                gen1.send(ChildEvent::MoveReady(MoveReady { to_vm: "microvm-2".into(), how: "started", ms: 20 })).await;
                assert_eq!(gen1.next_input().await, None, "the old CLI's EOF");
                // The old link is lost before the old CLI's exit: the switch is off, the loss moves the chat at its next line.
                gen1.send(gone("microvm-1")).await;
                host.wait_for("the move waits for the next line", |v| v["content"] == note_move_at_next("microvm-1", LossCause::VmGone).as_str()).await;
                host.eof().await;
                let (code, mut pump) = ended(task).await;
                assert_eq!(code, 0);
                pump.conclude(code);
                let ends = audit_rows(&pump, "session_move_end");
                assert_eq!(ends.iter().map(|r| r["detail"]["outcome"].clone()).collect::<Vec<_>>(), [Value::from("abandoned")], "{ends:?}");
                assert_eq!(hand.borrow().whys.len(), 1, "no generation after the called-off switch");
            });
        }
    }
}
