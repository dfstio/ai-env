//! The spawn manager (plan S6): the processes `/agent` starts, their stdio
//! windows, attachments, detach graces and process groups.
//!
//! CONTRACT (phase 0; W2 implements, W1's connection task calls it):
//!
//! - **spawn**: validate (uuid v7 id, single-use: an id this shim ever
//!   registered is refused `exists`, also once its record was released — the
//!   last [`USED_IDS_MAX`] are kept — so a `spawn` the Mac sends again after
//!   a lost `spawned` never runs twice, while a resume of it still answers
//!   `unknown`; argv non-empty, at most
//!   [`ARGV_MAX_BYTES`]; env keys `[A-Za-z_][A-Za-z0-9_]*`, at most
//!   [`ENV_MAX_ENTRIES`], never `HOME`/`PATH`/`CLAUDE_CONFIG_DIR`; at most one
//!   secret; at most [`MAX_SPAWNS`] live), resolve argv[0] (`claude` →
//!   `--claude`, else the child PATH), start as `--uid`/`--gid` (when root)
//!   with a cleared environment (`HOME`, `PATH=/usr/local/bin:/usr/bin:/bin`,
//!   `CLAUDE_CONFIG_DIR=<home>/.claude`, `DISABLE_AUTOUPDATER=1`, then the
//!   frame's env), piped stdio, and in `pre_exec` (`childproc`, shared with
//!   the workspace helper; async-signal-safe, nothing allocated after the
//!   fork): `setsid`, `PR_SET_NO_NEW_PRIVS` (Linux), the
//!   working directory — created (missing components, mode 0700) and entered
//!   AS THE AGENT, after std's setuid, from paths prepared before the fork;
//!   `current_dir` is never set, and no root filesystem operation ever touches
//!   an agent-writable path — and, with a secret, its pipe on fd 3 (the shim
//!   sets `<NAME>_FILE_DESCRIPTOR=3`). The child's open fds are exactly 0–2
//!   (and 3). The new spawn is attached to `conn`.
//! - **windows**: stdout is read in [`CHUNK_MAX`] reads through a
//!   `wire::chunk::Chunker` into a ring of seq-numbered chunks; at most
//!   `window_bytes` (default [`STDOUT_WINDOW_BYTES`]) or
//!   [`STDOUT_WINDOW_CHUNKS`] unacked, after which the reader stops (the child
//!   blocks): nothing is ever dropped. stderr: a [`STDERR_BUFFER_BYTES`]
//!   drop-oldest buffer with a cumulative `dropped` (what was dropped before
//!   the attachment was handed it: what it was handed, the Mac delivers or
//!   counts), never blocking. stdin: at
//!   most [`STDIN_WINDOW_BYTES`] held unacked; `stdin_ack` once written to the
//!   pipe (after every write: well within [`ACK_EVERY_BYTES`] and
//!   [`ACK_EVERY`]); a seq at or below `in_seq` is a duplicate (dropped
//!   silently), one above `in_seq + 1` is [`ErrorCode::StdinGap`], more than
//!   the window [`ErrorCode::StdinOverflow`].
//! - **attachments**: the newest wins — [`SpawnManager::attach`] moves a
//!   spawn to the new connection and the old connection's outbox yields
//!   `error superseded` for it; generations ensure a late
//!   [`SpawnManager::connection_lost`] of the old connection never detaches
//!   the new one.
//! - **ends**: `detach {final: true}` runs the D22 ladder from receipt
//!   ([`LADDER_TERM_AFTER`], [`LADDER_KILL_AFTER`]); `final: false` and a lost
//!   connection start the spawn's `detach_grace_s` (default
//!   [`DETACH_GRACE_EXEC_S`]), whatever the stdin state, then TERM, KILL 2 s
//!   later. Graces are frozen by [`SpawnManager::freeze`] (`/suspend`) and
//!   resumed by [`SpawnManager::thaw`] (`/resume`), with a jump guard: time
//!   the clock did not see is given back to the graces that ran through it,
//!   never to one started or thawed after the clock last looked.
//! - **exit**: when the leader exits, its group gets TERM, then KILL after
//!   [`GROUP_KILL_AFTER`] (only while the group is known alive). `exit.seq` is
//!   assigned only at stdout EOF (or an explicit abandon): after the leader's
//!   death the reader drains past the window by up to 1 MiB; an escaper that
//!   holds the pipe past 2 s ends the drain with `stdout_truncated`. The exit
//!   goes out after every earlier stdout and stderr chunk was sent; acking
//!   its seq releases the spawn (an unclaimed exit is kept for the grace).
//! - **shutdown** (the shim stops): TERM every group, wait at most 3 s, KILL
//!   every group still pinned, wait at most 1 s. **terminate** (`/terminate`):
//!   TERM every group, wait at most 5 s for the leaders, KILL only the groups
//!   whose leader still runs (an exited leader's group keeps its own ladder
//!   below), wait at most 1 s. Both refuse new spawns from the start.
//!   **Idle sweep** (Linux, root): on the transition to zero spawns (once
//!   that last group's KILL step is done), under the lock `spawn` takes,
//!   every remaining agent-uid process (a setsid escaper) is killed through a
//!   pidfd after re-checking its uid; `/proc` is scanned again until a scan
//!   finds none (at most five scans), so what an escaper forked during a
//!   pass dies in the next. A workspace helper (S8, `asagent`) is counted
//!   under the same lock before it is forked ([`SpawnManager::hold_helper`]):
//!   no sweep runs while one lives, the last one to go runs a sweep it held
//!   off, and both stops signal its group too. Helpers are not spawns: they
//!   never count toward [`MAX_SPAWNS`].
//! - **working directory** (S8): a spawn's `cwd` is a VM path; with the
//!   shim's `--fs-root` (native tests) it is entered under that prefix, as
//!   every VM path is.
//! - **park** (S10, `park_v1`): [`SpawnManager::park`] parks a spawn its
//!   socket carries once the busy check passes: no stdio and no unacked
//!   stdout or stdin within the window, and (Linux) no sample of its session
//!   over the Mac's CPU threshold and no process but the leader running (R
//!   or D). The samples are taken every [`ACTIVITY_SAMPLE`] from `/proc`
//!   (the CPU of every process of the session, sid = pgid = the leader's
//!   pid), and once more at the `park` (judged with them, never kept: the
//!   kept samples stay one per [`ACTIVITY_SAMPLE`]); native macOS has the
//!   stdio part only. A parked spawn keeps its socket; when that socket
//!   goes, it lives its park grace instead of its detach grace, frozen and
//!   thawed with the others and given back time by the jump guard; its end
//!   is TERM, then KILL, as a detach grace's. `unpark`, any frame for the
//!   spawn on its socket (`stdin`, `stdin_eof`, `signal`, `ack`, `detach`),
//!   a hello resuming it and a `park` refused to it (the answer says it is
//!   not parked) end the park; `hold_output` keeps its stdout (and so its
//!   exit) in its window meanwhile. `/health/detail` names a parked spawn's
//!   owner, the wrapper that parked it.
//!
//! Group signals: a group is signalled only while its leader is UNREAPED.
//! The leader's death is observed with `waitid(WNOWAIT)`, the group ladder
//! runs on the zombie, and only then is the leader reaped: while it is a
//! zombie its pid — the group id — cannot be reused, so a signal can never
//! reach someone else's group. The leader's watcher outlives its record (a
//! release aborts only the readers and the writer), so it acts only on the
//! record with its spawn id AND its pid.
//!
//! Native macOS runs skip the uid drop and NO_NEW_PRIVS and keep setsid and killpg.
use crate::shim::childproc::{child_setup, cwd_parts, fd_walk_end, CWD_ERRNO_BASE};
use crate::shim::replay::{Cursor, ErrBuffer, ExitRecord, OutWindow, StdinQueue};
use crate::shim::sys::SysOps;
use crate::wire::chunk::Chunker;
#[cfg(doc)]
use crate::wire::frame::{ACK_EVERY, ACK_EVERY_BYTES, STDOUT_WINDOW_BYTES};
use crate::wire::frame::{Deliver, ErrorCode, ExitInfo, Frame, ResumePoint, ResumeStatus, Resumed, Sig, SpawnDetail, SpawnErrCode, SpawnId, SpawnStatus};
use crate::wire::frame::{
    ARGV_MAX_BYTES, CHUNK_MAX, DETACH_GRACE_EXEC_S, ENV_MAX_ENTRIES, GROUP_KILL_AFTER, LADDER_KILL_AFTER, LADDER_TERM_AFTER, MAX_SPAWNS, STDERR_BUFFER_BYTES, STDIN_WINDOW_BYTES, STDOUT_WINDOW_CHUNKS,
};
use crate::wire::frame::{ParkOwner, ParkRefusal, PARK_GRACE_MAX_S};
use crate::shim::claudebin::PickedClaude;
use crate::wire::workspace::{ClaudeRef, CLAUDE_REFS_MAX};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::{watch, Notify};
use tokio::task::AbortHandle;
use tokio::time::Instant;

/// One connection (socket) of `/agent`, numbered by the agent registry.
pub type ConnGen = u64;

/// How spawns are started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnOpts {
    /// `--claude`: what argv[0] `claude` runs.
    pub claude: PathBuf,
    /// `--home`: HOME, the default cwd, and `CLAUDE_CONFIG_DIR=<home>/.claude`.
    pub home: PathBuf,
    /// The agent's uid/gid when the shim is root; `None` = unchanged (native tests).
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// The uid the idle sweep and the guard treat as the agent (`--uid`).
    pub agent_uid: u32,
    /// stdout window per spawn (hidden `--agent-window-bytes`; tests make it small).
    pub window_bytes: u64,
    /// Kill leftover agent-uid processes when the last spawn ends (Linux, root).
    pub sweep: bool,
    /// The shim's `--fs-root` (native tests, S8): a spawn's working directory
    /// is a VM path, entered under this prefix as every other VM path is
    /// (`ShimState::at`); the default (`home`) is the shim's own path already.
    pub fs_root: Option<PathBuf>,
}

/// A `spawn` frame's fields. `Debug` is written by hand: the id, argv[0] and
/// counts, never the arguments, environment values or the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SpawnRequest {
    pub spawn_id: SpawnId,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: std::collections::BTreeMap<String, String>,
    pub secrets: std::collections::BTreeMap<String, crate::wire::redact::Secret<String>>,
    pub deliver: crate::wire::frame::Deliver,
    pub detach_grace_s: Option<u32>,
    /// `spawn.credential` (S7): the name of a cached credential. The `/agent`
    /// connection resolves it from the shim's cache into `secrets` before the
    /// spawn manager sees the request, so delivery is the one tested path.
    pub credential: Option<String>,
    /// `spawn.claude` (S11, A.4): the staged claudes this spawn may run, in
    /// preference order (at most `CLAUDE_REFS_MAX`).
    pub claude: Vec<ClaudeRef>,
    /// What a `claude` argv[0] runs (S11): `None` until the `/agent`
    /// connection resolved it (`resolve_claude`, from the shim's cache),
    /// and for any other argv[0].
    pub picked: Option<PickedClaude>,
}

impl SpawnRequest {
    /// The request of a `spawn` frame; `None` for any other kind.
    #[must_use]
    pub fn from_frame(f: Frame) -> Option<SpawnRequest> {
        match f {
            Frame::Spawn { spawn_id, argv, cwd, env, secrets, deliver_secret, detach_grace_s, credential, claude } => Some(SpawnRequest { spawn_id, argv, cwd, env, secrets, deliver: deliver_secret, detach_grace_s, credential, claude, picked: None }),
            _ => None,
        }
    }
}

impl std::fmt::Debug for SpawnRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let argv0 = short(self.argv.first().map_or("", |a| basename(a)));
        write!(
            f,
            "SpawnRequest({}, argv0={argv0}, argc={}, cwd={}, env={}, secrets={}, deliver={:?}, detach_grace_s={:?}, credential={:?}, claude={})",
            short(&self.spawn_id.0),
            self.argv.len(),
            if self.cwd.is_some() { "set" } else { "home" },
            self.env.len(),
            self.secrets.len(),
            self.deliver,
            self.detach_grace_s,
            self.credential,
            self.claude.len()
        )
    }
}

// ---- limits and timers of this module ----------------------------------------------------

/// PATH of every spawn (the environment is otherwise cleared); also where a
/// bare argv[0] is looked up.
const CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
/// Names the shim sets itself.
const RESERVED_ENV: [&str; 3] = ["HOME", "PATH", "CLAUDE_CONFIG_DIR"];
/// Largest secret delivered on fd 3: it is written into the pipe before the
/// child exists, so it must fit the pipe buffer (≥ 16 KiB everywhere).
pub(crate) const SECRET_FD_MAX_BYTES: usize = 4096;
/// After the leader died the stdout reader may read this far past the window
/// (backpressure protects nothing any more; critic M1) ...
const DRAIN_PAST_WINDOW_BYTES: u64 = 1024 * 1024;
const DRAIN_PAST_WINDOW_CHUNKS: u64 = 1024;
/// ... and stops reading (`stdout_truncated`) when an escaper still holds a
/// pipe this long after the leader died.
const DRAIN_AFTER_DEATH: Duration = Duration::from_secs(2);
/// A detach grace that expired: TERM, then KILL this much later.
const GRACE_KILL_AFTER: Duration = Duration::from_secs(2);
/// `shutdown`: TERM, at most this for the leaders to exit, KILL, at most the second.
const SHUTDOWN_TERM_WAIT: Duration = Duration::from_secs(3);
const SHUTDOWN_KILL_WAIT: Duration = Duration::from_secs(1);
/// `terminate`: TERM, at most this for the leaders (the plan's "KILL 5 s
/// later"), KILL those still running, at most [`SHUTDOWN_KILL_WAIT`].
const TERMINATE_TERM_WAIT: Duration = Duration::from_secs(5);
/// Spawn ids kept for the single-use rule, the oldest forgotten first: far
/// more than one VM runs.
const USED_IDS_MAX: usize = 16_384;
/// The jump guard: the clock wakes at least every `TICK`; a wake that finds
/// more than `JUMP` gone (the VM was suspended without `/suspend`, or the
/// monotonic clock leapt at resume) extends every running grace by the excess.
const TICK: Duration = Duration::from_secs(1);
const JUMP: Duration = Duration::from_secs(10);
/// The idle sweep scans `/proc` until a scan finds nothing, at most this
/// often (a process forked between a scan and its parent's kill is in the
/// next scan) ...
const SWEEP_PASSES: usize = 5;
/// ... this far apart, so what one pass killed is a zombie (skipped) by the next.
const SWEEP_PAUSE: Duration = Duration::from_millis(20);
/// The busy check's sample (S10, `park_v1`): every this often, the CPU of
/// each live spawn's session and its running processes are read (Linux);
/// the Mac's `park.cpu_busy_ms` is per sample.
pub const ACTIVITY_SAMPLE: Duration = Duration::from_secs(10);
/// The longest busy-check window a `park` may name (`min_quiet_s`); the
/// samples are kept this long.
const PARK_WINDOW_MAX_S: u32 = 3600;

// ---- state -------------------------------------------------------------------------------

/// A detach grace `/suspend` can freeze: `left` from `since` (`None` = frozen).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Grace {
    left: Duration,
    since: Option<Instant>,
}

impl Grace {
    fn new(left: Duration, frozen: bool, now: Instant) -> Grace {
        Grace { left, since: (!frozen).then_some(now) }
    }

    /// `None` while frozen (or beyond what an Instant holds: never).
    fn deadline(&self) -> Option<Instant> {
        self.since.and_then(|s| s.checked_add(self.left))
    }

    fn remaining(&self, now: Instant) -> Duration {
        self.since.map_or(self.left, |s| self.left.saturating_sub(now.saturating_duration_since(s)))
    }

    fn freeze(&mut self, now: Instant) {
        self.left = self.remaining(now);
        self.since = None;
    }

    fn thaw(&mut self, now: Instant) {
        self.since.get_or_insert(now);
    }

    /// The jump guard: `by` passed unseen after `last`, the clock's previous
    /// wake. Only a grace already running then ran through it; a frozen one,
    /// or one started or thawed since (a `/resume`, or a lost socket noticed
    /// after the gap), keeps its time. Whether it was extended.
    fn extend(&mut self, last: Instant, by: Duration) -> bool {
        let through = self.since.is_some_and(|s| s <= last);
        if through {
            self.left += by;
        }
        through
    }
}

/// What a `park` asks of one spawn (S10, `park_v1`): the frame's fields but its spawn id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParkAsk {
    /// The park grace (1..=[`PARK_GRACE_MAX_S`]).
    pub grace_s: u32,
    /// The busy check's window (0..=3600).
    pub min_quiet_s: u32,
    /// CPU of the session per sample above which it is busy.
    pub cpu_busy_ms: u32,
    pub hold_output: bool,
    pub owner: ParkOwner,
}

/// A parked spawn's park (S10): the grace its socket's loss starts, the
/// wrapper that parked it, whether its stdout waits in its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParkState {
    grace: Duration,
    owner: ParkOwner,
    hold_output: bool,
}

/// One busy-check sample of a spawn's session (Linux, S10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sample {
    at: Instant,
    /// The session's CPU since the sample before it (ms).
    cpu_ms: u64,
    /// Its processes but the leader running or in uninterruptible sleep (R, D).
    running: u32,
}

/// The busy check's record of one spawn: the samples of the last
/// [`PARK_WINDOW_MAX_S`], and its session's CPU at the newest (0 at the start).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Activity {
    samples: VecDeque<Sample>,
    cpu_total_ms: u64,
}

impl Activity {
    /// A look at the session at `at`: its CPU since the last becomes a
    /// sample; the samples older than the longest window go.
    fn record(&mut self, at: Instant, now: &SessionNow) {
        if let Some(total) = now.cpu_ms {
            self.samples.push_back(Sample { at, cpu_ms: total.saturating_sub(self.cpu_total_ms), running: now.running });
            self.cpu_total_ms = total;
        }
        let keep = Duration::from_secs(u64::from(PARK_WINDOW_MAX_S));
        while self.samples.front().is_some_and(|s| at.saturating_duration_since(s.at) > keep) {
            self.samples.pop_front();
        }
    }

    /// The samples within `window` before `now` (inclusive): the busiest
    /// one's CPU, and whether one ran over `cpu_busy_ms` or saw a process
    /// but the leader running.
    fn busy(&self, now: Instant, window: Duration, cpu_busy_ms: u32) -> (bool, u64) {
        let within = self.samples.iter().filter(|s| now.saturating_duration_since(s.at) <= window);
        within.fold((false, 0), |(busy, max), s| (busy || s.cpu_ms > u64::from(cpu_busy_ms) || s.running > 0, max.max(s.cpu_ms)))
    }
}

/// One look at a spawn's session (S10's busy check): its CPU so far (ms;
/// `None` where it cannot be read: native macOS), its processes but the
/// leader that run (R or D), and those alive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SessionNow {
    cpu_ms: Option<u64>,
    running: u32,
    procs: u32,
}

/// How a spawn's attachment ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// On a connection, or re-attached within its grace: no clock.
    Attached,
    /// Detached (`final: false`, or the socket was lost): the grace runs.
    Grace(Grace),
    /// The grace ran out: TERM was sent and KILL is due; nobody will collect the exit.
    Expired,
    /// `detach {final: true}`: the D22 ladder is due; nobody will collect the exit.
    Final,
}

struct Spawn {
    /// The basename of argv[0].
    argv0: String,
    /// It was handed a secret (S7): while its leader, or a process of its
    /// group, lives, its memory may hold that value
    /// ([`SpawnManager::credential_holders`]).
    holds_secret: bool,
    /// S11: the sha256 of the cached claude it runs (`SpawnRequest.picked`
    /// with a path): [`SpawnManager::running_claudes`] keeps that binary.
    claude_sha256: Option<String>,
    /// The leader's pid, which is also the group id (setsid).
    pid: u32,
    started_at: String,
    /// `detach_grace_s` of the request.
    grace: Duration,
    attached: Option<ConnGen>,
    ending: Ending,
    /// The current attachment's send position.
    cursor: Cursor,
    out: OutWindow,
    err: ErrBuffer,
    stdin: StdinQueue,
    /// The written stdin seq last handed to the attachment as `stdin_ack`.
    stdin_acked: u64,
    /// The pipe is closed (EOF written) or gone (the child closed it).
    stdin_closed: bool,
    /// The child closed its stdin: later chunks are acked unwritten.
    stdin_broken: bool,
    /// The leader's status once it died.
    leader: Option<ExitInfo>,
    /// The leader is reaped: its pid (the group id) may be reused, so the
    /// group is never signalled again.
    reaped: bool,
    out_done: bool,
    err_done: bool,
    truncated: bool,
    exit: Option<ExitRecord>,
    /// Signals due at an instant (the detach ladders); dropped once the leader died.
    due: Vec<(Instant, i32)>,
    /// The stdout reader waits here for window credit.
    credit: Arc<Notify>,
    /// The stdin writer waits here for data or EOF.
    ready: Arc<Notify>,
    /// The leader's watcher waits here for both readers.
    drained: Arc<Notify>,
    readers: Vec<AbortHandle>,
    writer: Option<AbortHandle>,
    /// S10: the park, while parked (module doc).
    park: Option<ParkState>,
    /// S10: its last stdio (a stdin frame taken, a stdout or stderr chunk
    /// read; its start before any): the busy check's quiet.
    last_io: Instant,
    /// S10: the busy check's samples of its session (Linux).
    activity: Activity,
}

impl Spawn {
    /// killpg, only while the leader is unreaped (its zombie pins the group id).
    fn signal_group(&self, sig: i32) {
        if !self.reaped {
            killpg(self.pid, sig);
        }
    }

    /// Bytes the stdout reader may read now.
    fn stdout_room(&self, window: u64) -> u64 {
        if self.leader.is_some() {
            self.out.room(window.saturating_add(DRAIN_PAST_WINDOW_BYTES), STDOUT_WINDOW_CHUNKS + DRAIN_PAST_WINDOW_CHUNKS)
        } else {
            self.out.room(window, STDOUT_WINDOW_CHUNKS)
        }
    }

    fn status(&self, id: &SpawnId, conn: Option<ConnGen>) -> SpawnStatus {
        SpawnStatus {
            spawn_id: id.clone(),
            argv0: self.argv0.clone(),
            pid: self.pid,
            pgid: self.pid,
            alive: self.leader.is_none(),
            attached: self.attached.is_some_and(|a| Some(a) != conn),
            out_seq: self.out.last(),
            out_from: self.out.first(),
            err_seq: self.err.last(),
            in_seq: self.stdin.in_seq(),
            stdin_closed: self.stdin_closed,
            exit: self.leader,
        }
    }

    /// Detached now: the grace starts (frozen while the VM is suspended),
    /// unless a ladder already ends the spawn. A parked spawn's is its park
    /// grace (S10): only a lost socket meets one, as every frame of the Mac's
    /// for it, a `detach` among them, unparks it first.
    fn detached(&mut self, frozen: bool, now: Instant) {
        self.attached = None;
        if self.ending == Ending::Attached {
            let grace = self.park.map_or(self.grace, |p| p.grace);
            self.ending = Ending::Grace(Grace::new(grace, frozen, now));
        }
    }

    /// The Mac took the spawn back (`unpark`, a frame for it on its socket,
    /// a resuming hello: `by`): it is parked no more. Whether it was.
    fn unpark(&mut self, id: &SpawnId, by: &str) -> bool {
        let was = self.park.take().is_some();
        if was {
            log(&format!("ai-env: spawn {id} unparked by {by}"));
        }
        was
    }

    /// Whole seconds since its last stdio.
    fn quiet_s(&self, now: Instant) -> u32 {
        u32::try_from(now.saturating_duration_since(self.last_io).as_secs()).unwrap_or(u32::MAX)
    }

    /// The busy check (S10) at `now`, judged on `activity` (its samples and
    /// the session's look then): why it may not park, in this order (`not_attached` is the caller's):
    /// a grace or a window out of range, or a leader gone (`other`); stdout
    /// or stdin not acked (`unacked`); stdio within the window (`output`);
    /// a sample within it over `cpu_busy_ms`, or one that saw a process but
    /// the leader running (`busy`). With the busiest sample's CPU in the window.
    fn park_check(&self, activity: &Activity, ask: &ParkAsk, now: Instant) -> (Option<ParkRefusal>, u64) {
        let window = Duration::from_secs(u64::from(ask.min_quiet_s));
        let (busy, cpu_ms) = activity.busy(now, window, ask.cpu_busy_ms);
        let refusal = if !(1..=PARK_GRACE_MAX_S).contains(&ask.grace_s) || ask.min_quiet_s > PARK_WINDOW_MAX_S || self.leader.is_some() {
            Some(ParkRefusal::Other)
        } else if self.out.unacked().1 > 0 || self.stdin.in_seq() > self.stdin_acked {
            Some(ParkRefusal::Unacked)
        } else if now.saturating_duration_since(self.last_io) < window {
            Some(ParkRefusal::Output)
        } else if busy {
            Some(ParkRefusal::Busy)
        } else {
            None
        };
        (refusal, cpu_ms)
    }

    fn abort_tasks(self) {
        for t in self.readers.into_iter().chain(self.writer) {
            t.abort();
        }
    }
}

/// What one connection's outbox keeps between pulls.
#[derive(Default)]
struct ConnQueue {
    /// Live `Outbox`es of the connection (the entry goes with the last).
    outboxes: usize,
    /// Spawns a newer connection took: one `error superseded` each.
    superseded: VecDeque<SpawnId>,
    /// The spawn whose stdout (stderr) went last: round-robin.
    rr_out: Option<SpawnId>,
    rr_err: Option<SpawnId>,
}

/// Every spawn id `start` registered, oldest first, at most
/// [`USED_IDS_MAX`]: an id is single-use for the shim's lifetime.
#[derive(Default)]
struct UsedIds {
    order: VecDeque<SpawnId>,
    set: HashSet<SpawnId>,
}

impl UsedIds {
    fn contains(&self, id: &SpawnId) -> bool {
        self.set.contains(id)
    }

    /// Keep `id`; past the cap the oldest is forgotten.
    fn insert(&mut self, id: SpawnId) {
        if self.set.insert(id.clone()) {
            self.order.push_back(id);
        }
        if self.order.len() > USED_IDS_MAX {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
    }
}

#[derive(Default)]
struct State {
    spawns: BTreeMap<SpawnId, Spawn>,
    conns: HashMap<ConnGen, ConnQueue>,
    /// Every id ever registered: `spawn` answers `exists` for each.
    used: UsedIds,
    /// `shutdown` or `terminate` began: `spawn` answers `draining`.
    stopping: bool,
    /// Between `/suspend` and `/resume`: new graces start frozen.
    frozen: bool,
    /// The workspace helpers running now (S8), by hold, with the process
    /// group of each once it was forked and until it is about to be reaped
    /// ([`HelperHold`]): a group is signalled only while its leader is unreaped.
    helpers: BTreeMap<u64, Option<u32>>,
    next_helper: u64,
    /// An idle sweep was held off by a helper: the last hold to go runs it.
    sweep_due: bool,
}

impl State {
    fn live(&self) -> usize {
        self.spawns.values().filter(|s| s.leader.is_none()).count()
    }

    /// The live spawns' leaders, each with its spawn (S10 V-6): every look
    /// of the busy check takes them all, as each session one of them leads
    /// is its own spawn's and never another's escaper ([`sample_sessions`]'
    /// `leaders`): the sampler's looks and a `park`'s alike.
    fn live_leaders(&self) -> Vec<(SpawnId, u32)> {
        self.spawns.iter().filter(|(_, s)| s.leader.is_none()).map(|(id, s)| (id.clone(), s.pid)).collect()
    }

    /// The groups of the helpers running now.
    fn helper_groups(&self) -> Vec<u32> {
        self.helpers.values().filter_map(|g| *g).collect()
    }

    /// After any change to `id`: assign its exit once the leader died and both
    /// readers are done, and release it when nobody will collect that exit.
    /// The released record's tasks are the caller's to abort.
    fn settle(&mut self, id: &SpawnId) -> Option<Spawn> {
        let s = self.spawns.get_mut(id)?;
        if s.exit.is_none() && s.out_done && s.err_done {
            if let Some(info) = s.leader {
                let rec = ExitRecord::assign(&s.out, &s.err, info, s.truncated);
                s.exit = Some(rec);
                log(&format!(
                    "ai-env: exit {id} code={} signal={} stderr_dropped={} out_seq={} stdout_truncated={}",
                    opt(info.code),
                    opt(info.signal),
                    rec.stderr_dropped,
                    rec.seq - 1,
                    rec.stdout_truncated
                ));
            }
        }
        if s.exit.is_some() && s.attached.is_none() && matches!(s.ending, Ending::Expired | Ending::Final) {
            log(&format!("ai-env: spawn {id} released (its exit is nobody's)"));
            return self.spawns.remove(id);
        }
        None
    }

    /// One reader reached EOF (in the same critical section as its last
    /// chunk): settle, and wake the leader's watcher.
    fn reader_finished(&mut self, id: &SpawnId, stdout: bool) -> Option<Spawn> {
        let s = self.spawns.get_mut(id)?;
        if stdout {
            s.out_done = true;
        } else {
            s.err_done = true;
        }
        s.drained.notify_one();
        self.settle(id)
    }

    /// The earliest grace expiry or due signal.
    fn next_deadline(&self) -> Option<Instant> {
        self.spawns
            .values()
            .flat_map(|s| {
                let grace = match s.ending {
                    Ending::Grace(g) => g.deadline(),
                    _ => None,
                };
                grace.into_iter().chain(s.due.iter().map(|(at, _)| *at))
            })
            .min()
    }

    /// The next frame `conn` is owed, by priority.
    fn next_frame(&mut self, conn: ConnGen) -> Option<Frame> {
        let State { spawns, conns, .. } = self;
        let q = conns.get_mut(&conn)?;
        if let Some(id) = q.superseded.pop_front() {
            return Some(Frame::error(ErrorCode::Superseded, "a newer connection attached this spawn", Some(id)));
        }
        let mine: Vec<SpawnId> = spawns.iter().filter(|(_, s)| s.attached == Some(conn)).map(|(id, _)| id.clone()).collect();
        for id in &mine {
            let s = spawns.get_mut(id)?;
            let written = s.stdin.written();
            if written > s.stdin_acked {
                s.stdin_acked = written;
                return Some(Frame::StdinAck { spawn_id: id.clone(), seq: written });
            }
            if let Some(rec) = s.cursor.take_exit(&s.out, &s.err, s.exit.as_ref()) {
                return Some(Frame::Exit { spawn_id: id.clone(), seq: rec.seq, code: rec.info.code, signal: rec.info.signal, stderr_dropped: rec.stderr_dropped, stdout_truncated: rec.stdout_truncated });
            }
        }
        let last = q.rr_out.clone();
        for id in round_robin(&mine, last.as_ref()) {
            let s = spawns.get_mut(id)?;
            // S10: a park that holds its output keeps the stdout (and so the exit) in its window.
            if s.park.is_some_and(|p| p.hold_output) {
                continue;
            }
            if let Some((seq, chunk)) = s.cursor.next_out(&s.out) {
                let frame = Frame::Stdout { spawn_id: id.clone(), seq, data: chunk.clone() };
                q.rr_out = Some(id.clone());
                return Some(frame);
            }
        }
        let last = q.rr_err.clone();
        for id in round_robin(&mine, last.as_ref()) {
            let s = spawns.get_mut(id)?;
            let dropped = s.err.dropped();
            if let Some((seq, chunk)) = s.cursor.next_err(&s.err) {
                let frame = Frame::Stderr { spawn_id: id.clone(), seq, data: chunk.clone(), dropped };
                q.rr_err = Some(id.clone());
                return Some(frame);
            }
        }
        None
    }
}

/// `ids` (sorted) starting after `last`, wrapping around.
fn round_robin<'a>(ids: &'a [SpawnId], last: Option<&SpawnId>) -> impl Iterator<Item = &'a SpawnId> {
    let start = last.map_or(0, |l| ids.partition_point(|i| i <= l));
    ids[start..].iter().chain(&ids[..start])
}

struct Inner {
    opts: SpawnOpts,
    state: Mutex<State>,
    /// Held by `spawn` from its checks until the new spawn is registered, by
    /// the idle sweep and by the first step of `shutdown` and `terminate`: a
    /// child between fork and registration is never swept, and nothing
    /// starts once stopping.
    spawn_lock: tokio::sync::Mutex<()>,
    /// Bumped on every change an outbox may care about.
    changed: watch::Sender<u64>,
    /// Wakes the clock task (a grace or ladder was scheduled, frozen or thawed).
    clock_wake: Arc<Notify>,
    clock_started: AtomicBool,
    /// `shutdown` or `terminate` finished: outboxes never wake again.
    shut: AtomicBool,
    /// The shim's one-slot credential cache (S7): here so the clock's jump
    /// guard reaches it (the clock runs from the first hello: a copy is
    /// cached only over a connection past it).
    credential: crate::shim::credential::CredentialCache,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What the busy check counts beyond the sessions (S10 V-6): the agent's
    /// uid and the sessions its workspace helpers lead, when the shim owns
    /// that uid as the idle sweep does (`sweep`, Linux and root, and an agent
    /// uid that is not root's); `None` otherwise (native tests: the test's
    /// own uid runs everything else on the machine).
    fn escapers(&self) -> Option<(u32, Vec<u32>)> {
        (self.opts.sweep && self.opts.agent_uid != 0).then(|| (self.opts.agent_uid, self.lock().helper_groups()))
    }

    fn bump(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// A reader without a pipe: done at once.
    fn reader_done(&self, id: &SpawnId, stdout: bool) {
        let released = self.lock().reader_finished(id, stdout);
        self.bump();
        if let Some(r) = released {
            r.abort_tasks();
        }
    }

    /// The stdin pipe closed (EOF written, or the child closed it: `broken`).
    fn stdin_ended(&self, id: &SpawnId, broken: bool) {
        if let Some(s) = self.lock().spawns.get_mut(id) {
            s.stdin_closed = true;
            if broken {
                s.stdin_broken = true;
                s.stdin.discard();
            }
        }
        self.bump();
    }

    /// The clock: fire due graces and ladder steps.
    fn tick(&self, now: Instant) {
        let mut released = Vec::new();
        {
            let mut st = self.lock();
            let ids: Vec<SpawnId> = st.spawns.keys().cloned().collect();
            for id in ids {
                let Some(s) = st.spawns.get_mut(&id) else { continue };
                if let Ending::Grace(g) = s.ending {
                    if g.deadline().is_some_and(|d| d <= now) {
                        s.ending = Ending::Expired;
                        // S10: a parked spawn's grace is its park grace; it ends the park too.
                        let which = if s.park.take().is_some() { "park" } else { "detach" };
                        if s.leader.is_none() {
                            s.signal_group(libc::SIGTERM);
                            s.due.push((now + GRACE_KILL_AFTER, libc::SIGKILL));
                            log(&format!("ai-env: spawn {id} {which} grace over: TERM, KILL in {} s", GRACE_KILL_AFTER.as_secs()));
                        }
                    }
                }
                let due = std::mem::take(&mut s.due);
                for (at, sig) in due {
                    if at > now {
                        s.due.push((at, sig));
                    } else if s.leader.is_none() {
                        s.signal_group(sig);
                    }
                }
                released.extend(st.settle(&id));
            }
        }
        for r in released {
            r.abort_tasks();
        }
    }

    /// One wake of the clock at `now`, the previous one at `last`: more than
    /// [`JUMP`] between them went unseen (the VM was suspended without
    /// `/suspend`, or the monotonic clock leapt at resume), so the cached
    /// credential goes (S7; `/resume` is the main backstop) and the graces
    /// that ran through it get the excess back; then what is due fires.
    fn woke(&self, last: Instant, now: Instant) {
        let gap = now.saturating_duration_since(last);
        if gap > JUMP {
            self.credential.forget(None, "clock jump");
            self.extend_graces(last, gap.saturating_sub(TICK));
        }
        self.tick(now);
    }

    /// The jump guard: `by` passed unseen after `last`.
    fn extend_graces(&self, last: Instant, by: Duration) {
        let mut st = self.lock();
        let mut n = 0;
        for s in st.spawns.values_mut() {
            if let Ending::Grace(g) = &mut s.ending {
                if g.extend(last, by) {
                    n += 1;
                }
            }
        }
        log(&format!("ai-env: spawns: {} s passed unseen (suspended without /suspend?): {n} detach grace(s) extended", by.as_secs()));
    }

    /// After the last leader died: kill every leftover agent-uid process, under
    /// the spawn lock, if still nothing runs: no spawn and no workspace
    /// helper (S8; a helper is the agent's too, and its git with it). A sweep
    /// a helper held off is due once the last helper is gone.
    async fn sweep_if_idle(&self) {
        let _held = self.spawn_lock.lock().await;
        let uid = self.opts.agent_uid;
        {
            let mut st = self.lock();
            if st.live() != 0 || uid == 0 {
                return;
            }
            if !st.helpers.is_empty() {
                st.sweep_due = true;
                log(&format!("ai-env: idle sweep held off: {} workspace helper(s) running", st.helpers.len()));
                return;
            }
            st.sweep_due = false;
        }
        // /proc reads and the pauses between scans block: off the runtime's workers.
        let (killed, scans) = tokio::task::spawn_blocking(move || sweep(uid)).await.unwrap_or_default();
        log(&format!("ai-env: idle sweep: {killed} leftover agent-uid process(es) killed ({scans} scan(s))"));
    }

    /// The leader `pid` died: wait for both readers until the deadline, then
    /// abandon them (an escaper holds a pipe). Only that leader's record.
    async fn drain_or_abandon(&self, id: &SpawnId, pid: u32, deadline: Instant) {
        loop {
            let drained = match self.lock().spawns.get(id).filter(|s| s.pid == pid) {
                None => return,
                Some(s) if s.out_done && s.err_done => return,
                Some(s) => s.drained.clone(),
            };
            if tokio::time::timeout_at(deadline, drained.notified()).await.is_err() {
                break;
            }
        }
        let (readers, released) = {
            let mut st = self.lock();
            let Some(s) = st.spawns.get_mut(id).filter(|s| s.pid == pid) else { return };
            if s.out_done && s.err_done {
                return;
            }
            s.truncated = !s.out_done;
            s.out_done = true;
            s.err_done = true;
            log(&format!(
                "ai-env: spawn {id} pipes still open {} s after the leader died (an escaper holds them): stopped reading{}",
                DRAIN_AFTER_DEATH.as_secs(),
                if s.truncated { ", stdout_truncated" } else { "" }
            ));
            (std::mem::take(&mut s.readers), st.settle(id))
        };
        for r in readers {
            r.abort();
        }
        if let Some(r) = released {
            r.abort_tasks();
        }
        self.bump();
    }
}

// ---- the manager -------------------------------------------------------------------------

/// The frames one connection is owed by its attached spawns, pulled by the
/// connection's writer: `try_next` never blocks; `changed` waits (cancel-safe)
/// until `try_next` may have something. Priority: `stdin_ack`, `exit` and
/// `error superseded` first, then stdout round-robin over the attached spawns,
/// then stderr.
pub struct Outbox {
    conn: ConnGen,
    inner: Arc<Inner>,
    rx: watch::Receiver<u64>,
}

impl Outbox {
    /// The next frame for this connection, without waiting.
    pub fn try_next(&mut self) -> Option<Frame> {
        self.inner.lock().next_frame(self.conn)
    }

    /// Resolves when new output may be available (cancel-safe: dropping the
    /// future loses nothing). Never resolves after the manager shut down.
    pub async fn changed(&mut self) {
        if !self.inner.shut.load(Ordering::SeqCst) && self.rx.changed().await.is_ok() && !self.inner.shut.load(Ordering::SeqCst) {
            return;
        }
        std::future::pending().await
    }
}

impl Drop for Outbox {
    fn drop(&mut self) {
        let mut st = self.inner.lock();
        if let Some(q) = st.conns.get_mut(&self.conn) {
            q.outboxes = q.outboxes.saturating_sub(1);
            if q.outboxes == 0 {
                st.conns.remove(&self.conn);
            }
        }
    }
}

/// Every spawn of this shim.
pub struct SpawnManager {
    inner: Arc<Inner>,
}

impl SpawnManager {
    /// No task starts here (a runtime may not exist yet): the clock starts
    /// with the first hello ([`Self::attach`]) or spawn.
    #[must_use]
    pub fn new(opts: SpawnOpts) -> SpawnManager {
        SpawnManager {
            inner: Arc::new(Inner {
                opts,
                state: Mutex::new(State::default()),
                spawn_lock: tokio::sync::Mutex::new(()),
                changed: watch::channel(0).0,
                clock_wake: Arc::new(Notify::new()),
                clock_started: AtomicBool::new(false),
                shut: AtomicBool::new(false),
                credential: crate::shim::credential::CredentialCache::new(),
            }),
        }
    }

    #[must_use]
    pub fn opts(&self) -> &SpawnOpts {
        &self.inner.opts
    }

    /// Start `req` attached to `conn`: the `spawned` or `spawn_err` frame.
    pub async fn spawn(&self, conn: ConnGen, req: SpawnRequest) -> Frame {
        let id = req.spawn_id.clone();
        match self.start(conn, req).await {
            Ok(frame) => frame,
            Err((code, message)) => {
                let name = serde_json::to_value(code).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                log(&format!("ai-env: spawn {} refused ({name}): {message}", short(&id.0)));
                Frame::SpawnErr { spawn_id: id, code, message }
            }
        }
    }

    async fn start(&self, conn: ConnGen, mut req: SpawnRequest) -> Result<Frame, (SpawnErrCode, String)> {
        let inner = &self.inner;
        let opts = &inner.opts;
        let held = inner.spawn_lock.lock().await;
        if inner.lock().stopping {
            return Err((SpawnErrCode::Draining, "the shim is stopping".into()));
        }
        check_request(&req).map_err(|m| (SpawnErrCode::BadRequest, m))?;
        {
            let st = inner.lock();
            // Single-use: a record released since (its exit collected, or its grace over) still counts.
            if st.spawns.contains_key(&req.spawn_id) || st.used.contains(&req.spawn_id) {
                return Err((SpawnErrCode::Exists, format!("spawn {} already ran on this VM: not starting it again", req.spawn_id)));
            }
            if st.live() >= MAX_SPAWNS {
                return Err((SpawnErrCode::Limit, format!("{MAX_SPAWNS} spawns are running (at most {MAX_SPAWNS})")));
            }
        }
        let cwd_text = short(&req.cwd.clone().unwrap_or_else(|| opts.home.to_string_lossy().into_owned()));
        let cwd = match &req.cwd {
            Some(c) => vm_cwd_parts(opts.fs_root.as_deref(), c),
            None => cwd_parts(opts.home.as_os_str().as_bytes()),
        }
        .map_err(|m| (SpawnErrCode::Cwd, format!("working directory \"{cwd_text}\": {m}")))?;
        // S11: a `claude` argv[0] runs the cached binary the connection picked, else `--claude`.
        let cached = if req.argv[0] == "claude" { req.picked.as_ref().and_then(|p| p.path.clone()) } else { None };
        let program = resolve(&req.argv[0], &opts.claude, cached.as_deref()).map_err(|m| (SpawnErrCode::NotFound, m))?;
        let secrets = std::mem::take(&mut req.secrets);
        let secret = secrets.iter().next();
        let secret_kind = match (secret, req.deliver) {
            (None, _) => "none",
            (Some(_), Deliver::Fd) => "fd3",
            (Some(_), Deliver::Env) => "env",
        };
        // fd delivery: the pipe already holds the value, its write end closed,
        // before the child exists.
        let pipe = match secret {
            Some((_, value)) if req.deliver == Deliver::Fd => Some(secret_pipe(value.expose().as_bytes()).map_err(|e| (SpawnErrCode::Exec, format!("cannot make the secret's pipe: {e}")))?),
            _ => None,
        };
        let mut cmd = tokio::process::Command::new(&program);
        cmd.arg0(&req.argv[0])
            .args(&req.argv[1..])
            .env_clear()
            .env("HOME", &opts.home)
            .env("PATH", child_path(cached.as_deref()))
            .env("CLAUDE_CONFIG_DIR", opts.home.join(".claude"))
            .env("DISABLE_AUTOUPDATER", "1")
            .envs(&req.env);
        if let Some((name, value)) = secret {
            match req.deliver {
                // std keeps its own (unzeroized) copy until `cmd` is dropped below.
                Deliver::Env => cmd.env(name, value.expose()),
                Deliver::Fd => cmd.env(format!("{name}_FILE_DESCRIPTOR"), "3"),
            };
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        if let Some(gid) = opts.gid {
            cmd.gid(gid);
        }
        if let Some(uid) = opts.uid {
            cmd.uid(uid);
        }
        let secret_fd = pipe.as_ref().map(AsRawFd::as_raw_fd);
        let fd_walk = fd_walk_end();
        // SAFETY: the closure runs in the forked child, after std applied the
        // stdio and the uid/gid, before exec; it makes only async-signal-safe
        // calls on data prepared here (no allocation, no lock).
        unsafe {
            cmd.pre_exec(move || child_setup(&cwd, secret_fd, fd_walk));
        }
        let spawned = {
            #[cfg(test)]
            let _fork = crate::test_locks::forking();
            cmd.spawn()
        };
        drop(cmd);
        // The parent's read end: the child has its own on fd 3.
        drop(pipe);
        let holds_secret = !secrets.is_empty();
        // The shim's copy of the secret (zeroized on drop).
        drop(secrets);
        let mut child = spawned.map_err(|e| spawn_error(&e, &req.argv[0], &cwd_text, opts))?;
        let argv0 = short(basename(&req.argv[0]));
        let Some(pid) = child.id() else {
            return Err((SpawnErrCode::Exec, format!("{argv0} exited before it was registered")));
        };
        let id = req.spawn_id.clone();
        let (stdin, stdout, stderr) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
        let record = Spawn {
            argv0: argv0.clone(),
            holds_secret,
            claude_sha256: req.picked.as_ref().filter(|p| p.path.is_some()).and_then(|p| p.sha256.clone()),
            pid,
            started_at: crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()),
            grace: Duration::from_secs(u64::from(req.detach_grace_s.unwrap_or(DETACH_GRACE_EXEC_S))),
            attached: Some(conn),
            ending: Ending::Attached,
            cursor: Cursor { out: 1, err: 1, exit_sent: false },
            out: OutWindow::default(),
            err: ErrBuffer::new(STDERR_BUFFER_BYTES),
            stdin: StdinQueue::new(STDIN_WINDOW_BYTES),
            stdin_acked: 0,
            stdin_closed: false,
            stdin_broken: false,
            leader: None,
            reaped: false,
            out_done: false,
            err_done: false,
            truncated: false,
            exit: None,
            due: Vec::new(),
            credit: Arc::new(Notify::new()),
            ready: Arc::new(Notify::new()),
            drained: Arc::new(Notify::new()),
            readers: Vec::new(),
            writer: None,
            park: None,
            last_io: Instant::now(),
            activity: Activity::default(),
        };
        let (credit, ready) = (record.credit.clone(), record.ready.clone());
        {
            let mut st = inner.lock();
            st.used.insert(id.clone());
            st.spawns.insert(id.clone(), record);
        }
        let readers = vec![tokio::spawn(read_stdout(inner.clone(), id.clone(), stdout, credit)).abort_handle(), tokio::spawn(read_stderr(inner.clone(), id.clone(), stderr)).abort_handle()];
        let writer = tokio::spawn(write_stdin(inner.clone(), id.clone(), stdin, ready)).abort_handle();
        tokio::spawn(watch_leader(inner.clone(), id.clone(), child, pid));
        if let Some(s) = inner.lock().spawns.get_mut(&id) {
            s.readers = readers;
            s.writer = Some(writer);
        }
        drop(held);
        self.start_clock();
        // S11: which claude ran, when the connection picked one (argv[0] `claude`).
        let ran = req.picked.as_ref().map_or(String::new(), |p| format!(" claude={} src={}", p.version.as_deref().unwrap_or("-"), if p.path.is_some() { "cache" } else { "image" }));
        log(&format!(
            "ai-env: spawn {id} pid={pid} pgid={pid} argv0={argv0} argc={} cwd=\"{cwd_text}\" uid={} secret={secret_kind}{ran}",
            req.argv.len(),
            opts.uid.map_or("-".to_string(), |u| u.to_string())
        ));
        inner.bump();
        let (claude_version, claude_sha256) = req.picked.map_or((None, None), |p| (p.version, p.sha256));
        Ok(Frame::Spawned { spawn_id: id, pid, pgid: pid, claude_version, claude_sha256 })
    }

    /// The clock task, once a runtime exists (the first hello or spawn); on
    /// Linux the busy check's sampler with it (S10).
    fn start_clock(&self) {
        if !self.inner.clock_started.swap(true, Ordering::SeqCst) {
            tokio::spawn(run_clock(Arc::downgrade(&self.inner), self.inner.clock_wake.clone()));
            #[cfg(target_os = "linux")]
            tokio::spawn(run_sampler(Arc::downgrade(&self.inner)));
        }
    }

    /// `hello.resume`: attach each spawn to `conn` (newest wins); one entry per point.
    pub fn attach(&self, conn: ConnGen, resume: &[ResumePoint]) -> Vec<Resumed> {
        let mut out = Vec::with_capacity(resume.len());
        {
            let mut st = self.inner.lock();
            let State { spawns, conns, .. } = &mut *st;
            for p in resume {
                let status = match spawns.get_mut(&p.spawn_id) {
                    None => ResumeStatus::Unknown,
                    Some(s) => match Cursor::resume(&s.out, &s.err, p.from_seq, p.err_from_seq) {
                        Err(_) => ResumeStatus::Gap,
                        Ok(cursor) => {
                            s.cursor = cursor;
                            s.stdin_acked = 0;
                            if let Ending::Grace(_) = s.ending {
                                s.ending = Ending::Attached;
                            }
                            // S10: a hello resuming a parked spawn unparks it (its grace went above).
                            s.unpark(&p.spawn_id, "a resuming hello");
                            if let Some(old) = s.attached.replace(conn).filter(|old| *old != conn) {
                                if let Some(q) = conns.get_mut(&old) {
                                    q.superseded.push_back(p.spawn_id.clone());
                                }
                                log(&format!("ai-env: spawn {} superseded: connection {old} -> {conn}", p.spawn_id));
                            }
                            ResumeStatus::Ok
                        }
                    },
                };
                out.push(Resumed { spawn_id: p.spawn_id.clone(), status });
            }
        }
        self.inner.bump();
        // From the first hello, not the first spawn (S7): a credential is
        // cached only over a connection past hello (`vm warm`'s with no spawn
        // at all), and the jump guard must reach it. Until a spawn the clock
        // costs one idle wake a second.
        self.start_clock();
        self.inner.clock_wake.notify_one();
        out
    }

    /// Live spawns that were handed a secret (S7: `credential_holders`): their
    /// memory, and any snapshot taken while they live, still holds it. A spawn
    /// whose leader died counts while a process of its group lives on
    /// ([`group_alive`], as `/health/detail` shows it): that process may hold
    /// what the leader was handed.
    #[must_use]
    pub fn credential_holders(&self) -> u32 {
        let n = self.inner.lock().spawns.values().filter(|s| s.holds_secret && (s.leader.is_none() || group_alive(s.pid))).count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// S11: the sha256s of the cached claudes live spawns run (a spawn whose
    /// leader died counts while a process of its group lives on: it may start
    /// a nested `claude` from the binary's directory). The cache never evicts
    /// one of them.
    #[must_use]
    pub fn running_claudes(&self) -> std::collections::BTreeSet<String> {
        self.inner.lock().spawns.values().filter(|s| s.leader.is_none() || group_alive(s.pid)).filter_map(|s| s.claude_sha256.clone()).collect()
    }

    /// The shim's credential cache (S7).
    #[must_use]
    pub fn credential(&self) -> &crate::shim::credential::CredentialCache {
        &self.inner.credential
    }

    /// What `hello_ok` and `/health/detail` show of the cache and its holders.
    #[must_use]
    pub fn credential_view(&self) -> crate::wire::frame::CredentialView {
        self.inner.credential.view(self.credential_holders())
    }

    /// Every spawn, as seen from `conn` (`attached` = to another connection).
    pub fn status(&self, conn: Option<ConnGen>) -> Vec<SpawnStatus> {
        self.inner.lock().spawns.iter().map(|(id, s)| s.status(id, conn)).collect()
    }

    /// Every spawn for `/health/detail`.
    pub fn detail(&self) -> Vec<SpawnDetail> {
        let now = Instant::now();
        self.inner
            .lock()
            .spawns
            .iter()
            .map(|(id, s)| {
                let (detach_left_s, frozen) = match s.ending {
                    Ending::Attached => (None, false),
                    Ending::Grace(g) => (Some(g.remaining(now).as_secs()), g.since.is_none()),
                    Ending::Expired | Ending::Final => (Some(0), false),
                };
                // S10: a parked spawn names the wrapper that parked it (the reaper's owner check).
                SpawnDetail { status: s.status(id, None), started_at: s.started_at.clone(), detach_left_s, frozen, group_alive: group_alive(s.pid), parked: s.park.map(|p| p.owner) }
            })
            .collect()
    }

    /// The spawn `id` if it is attached to `conn`. A frame for a parked
    /// spawn on its socket unparks it first (S10; `by` names the frame), and
    /// the outbox is woken for what the park held.
    fn with_attached<T>(&self, conn: ConnGen, id: &SpawnId, by: &str, f: impl FnOnce(&mut Spawn) -> Result<T, ErrorCode>) -> Result<T, ErrorCode> {
        let (out, unparked) = {
            let mut st = self.inner.lock();
            let s = st.spawns.get_mut(id).filter(|s| s.attached == Some(conn)).ok_or(ErrorCode::NotAttached)?;
            let unparked = s.unpark(id, by);
            (f(s), unparked)
        };
        if unparked {
            self.inner.bump();
        }
        out
    }

    pub fn stdin(&self, conn: ConnGen, id: &SpawnId, seq: u64, bytes: Vec<u8>) -> Result<(), ErrorCode> {
        let discarded = self.with_attached(conn, id, "stdin", |s| {
            if !s.stdin.offer(seq, bytes)? {
                return Ok(false);
            }
            // S10: stdin is the spawn's I/O (the busy check's quiet).
            s.last_io = Instant::now();
            if s.stdin_broken {
                s.stdin.discard();
                return Ok(true);
            }
            s.ready.notify_one();
            Ok(false)
        })?;
        if discarded {
            self.inner.bump();
        }
        Ok(())
    }

    pub fn stdin_eof(&self, conn: ConnGen, id: &SpawnId, seq: u64) -> Result<(), ErrorCode> {
        self.with_attached(conn, id, "stdin_eof", |s| {
            s.stdin.eof(seq);
            s.ready.notify_one();
            Ok(())
        })
    }

    pub fn signal(&self, conn: ConnGen, id: &SpawnId, sig: Sig) -> Result<(), ErrorCode> {
        self.with_attached(conn, id, "signal", |s| {
            s.signal_group(sig.number());
            Ok(())
        })?;
        log(&format!("ai-env: spawn {id} signal {sig:?}"));
        Ok(())
    }

    pub fn ack(&self, conn: ConnGen, id: &SpawnId, seq: u64, err_seq: u64) -> Result<(), ErrorCode> {
        let released = {
            let mut st = self.inner.lock();
            let s = st.spawns.get_mut(id).filter(|s| s.attached == Some(conn)).ok_or(ErrorCode::NotAttached)?;
            // S10: an ack (the Mac took VM output) unparks; the bump below wakes the outbox for what it held.
            s.unpark(id, "ack");
            s.out.ack(seq);
            s.err.ack(err_seq);
            s.credit.notify_one();
            if s.exit.is_some_and(|e| seq >= e.seq) {
                log(&format!("ai-env: spawn {id} released (exit collected)"));
                st.spawns.remove(id)
            } else {
                None
            }
        };
        if let Some(r) = released {
            r.abort_tasks();
        }
        self.inner.bump();
        Ok(())
    }

    pub fn detach(&self, conn: ConnGen, id: &SpawnId, is_final: bool) -> Result<(), ErrorCode> {
        let released = {
            let mut st = self.inner.lock();
            let frozen = st.frozen;
            let s = st.spawns.get_mut(id).filter(|s| s.attached == Some(conn)).ok_or(ErrorCode::NotAttached)?;
            let now = Instant::now();
            // S10: a detach unparks first: the Mac's own detach takes its detach grace.
            s.unpark(id, "detach");
            s.detached(frozen, now);
            if is_final {
                s.ending = Ending::Final;
                if s.leader.is_none() {
                    s.due.push((now + LADDER_TERM_AFTER, libc::SIGTERM));
                    s.due.push((now + LADDER_KILL_AFTER, libc::SIGKILL));
                    log(&format!("ai-env: spawn {id} detached (final): TERM in {} ms, KILL in {} ms", LADDER_TERM_AFTER.as_millis(), LADDER_KILL_AFTER.as_millis()));
                } else {
                    log(&format!("ai-env: spawn {id} detached (final) after its exit"));
                }
            } else {
                log(&format!("ai-env: spawn {id} detached: grace {} s", s.grace.as_secs()));
            }
            st.settle(id)
        };
        if let Some(r) = released {
            r.abort_tasks();
        }
        self.inner.clock_wake.notify_one();
        Ok(())
    }

    /// The socket of `conn` ended without `detach`: every spawn still attached
    /// to it (not superseded since) starts its grace.
    pub fn connection_lost(&self, conn: ConnGen) {
        let released: Vec<Spawn> = {
            let mut st = self.inner.lock();
            let frozen = st.frozen;
            let now = Instant::now();
            let mut lost = Vec::new();
            for (id, s) in st.spawns.iter_mut().filter(|(_, s)| s.attached == Some(conn)) {
                // S10: a parked spawn stays parked, under its park grace.
                let (which, grace) = s.park.map_or(("grace", s.grace), |p| ("park grace", p.grace));
                s.detached(frozen, now);
                log(&format!("ai-env: spawn {id} lost connection {conn}: {which} {} s{}", grace.as_secs(), if frozen { " (frozen)" } else { "" }));
                lost.push(id.clone());
            }
            lost.iter().filter_map(|id| st.settle(id)).collect()
        };
        for r in released {
            r.abort_tasks();
        }
        self.inner.clock_wake.notify_one();
    }

    /// `park` (S10, `park_v1`; the module doc): park the spawn `id` that
    /// `conn` carries, or say why not. Its session is looked at once more
    /// first (off the runtime's workers; with every live spawn's leader, as
    /// the sampler looks: another live spawn's session is never this one's
    /// escaper, V-6), then the busy check
    /// ([`Spawn::park_check`], on its samples and that look, which is not
    /// kept) and the park itself run under one lock: a
    /// spawn not this socket's (or no longer) is `not_attached`. The answer
    /// is `parked` (the quiet in whole seconds, the processes but the
    /// leader) or `park_refused` (its reason, the same two, and the busiest
    /// sample's CPU in the window). A parked spawn parked again takes the
    /// new terms; refused, it is parked no more (what its park held goes out).
    pub async fn park(&self, conn: ConnGen, id: &SpawnId, ask: ParkAsk) -> Frame {
        let refused = |reason: ParkRefusal, quiet_s: u32, procs: u32, cpu_ms: u64| {
            log(&format!("ai-env: spawn {} park refused ({}): quiet {quiet_s} s, procs {procs}, cpu {cpu_ms} ms", short(&id.0), refusal_word(reason)));
            Frame::ParkRefused { spawn_id: id.clone(), reason, quiet_s, procs, cpu_ms }
        };
        // Its leader and every live one, under one lock (BUSY-1: a look with this leader alone took the other
        // spawns' sessions for its escapers). `escapers` takes the same lock: after this guard went.
        let looked = {
            let st = self.inner.lock();
            st.spawns.get(id).filter(|s| s.attached == Some(conn)).map(|s| (s.pid, st.live_leaders().into_iter().map(|(_, pid)| pid).collect::<Vec<u32>>()))
        };
        let Some((pid, leaders)) = looked else { return refused(ParkRefusal::NotAttached, 0, 0, 0) };
        let away = self.inner.escapers();
        let session = tokio::task::spawn_blocking(move || session_now(pid, &leaders, away)).await.unwrap_or_default();
        let now = Instant::now();
        let mut st = self.inner.lock();
        let Some(s) = st.spawns.get_mut(id).filter(|s| s.attached == Some(conn) && s.pid == pid) else { return refused(ParkRefusal::NotAttached, 0, 0, 0) };
        let mut seen = s.activity.clone();
        seen.record(now, &session);
        let quiet_s = s.quiet_s(now);
        let (refusal, cpu_ms) = s.park_check(&seen, &ask, now);
        if let Some(reason) = refusal {
            let was = s.unpark(id, "a refused park");
            drop(st);
            if was {
                self.inner.bump();
            }
            return refused(reason, quiet_s, session.procs, cpu_ms);
        }
        s.park = Some(ParkState { grace: Duration::from_secs(u64::from(ask.grace_s)), owner: ask.owner, hold_output: ask.hold_output });
        log(&format!(
            "ai-env: spawn {id} parked: park grace {} s, quiet {quiet_s} s, procs {}, owner pid {} started {}{}",
            ask.grace_s,
            session.procs,
            ask.owner.pid,
            ask.owner.started,
            if ask.hold_output { ", stdout held" } else { "" }
        ));
        Frame::Parked { spawn_id: id.clone(), quiet_s, procs: session.procs }
    }

    /// `unpark` (S10): the spawn `id` that `conn` carries is the Mac's
    /// again, and what its park held goes out. No answer either way: a spawn
    /// not attached to `conn` is left as it is.
    pub fn unpark(&self, conn: ConnGen, id: &SpawnId) {
        let was = self.inner.lock().spawns.get_mut(id).filter(|s| s.attached == Some(conn)).is_some_and(|s| s.unpark(id, "unpark"));
        if was {
            self.inner.bump();
        }
    }

    /// The frames `conn` is owed.
    #[must_use]
    pub fn outbox(&self, conn: ConnGen) -> Outbox {
        self.inner.lock().conns.entry(conn).or_default().outboxes += 1;
        let mut rx = self.inner.changed.subscribe();
        rx.mark_changed();
        Outbox { conn, inner: self.inner.clone(), rx }
    }

    /// `/suspend`: freeze every detach grace.
    pub fn freeze(&self) {
        let n = {
            let mut st = self.inner.lock();
            st.frozen = true;
            let now = Instant::now();
            let mut n = 0;
            for s in st.spawns.values_mut() {
                if let Ending::Grace(g) = &mut s.ending {
                    g.freeze(now);
                    n += 1;
                }
            }
            n
        };
        log(&format!("ai-env: spawns frozen ({n} detach grace(s))"));
        self.inner.clock_wake.notify_one();
    }

    /// `/resume`: resume the frozen graces.
    pub fn thaw(&self) {
        let n = {
            let mut st = self.inner.lock();
            st.frozen = false;
            let now = Instant::now();
            let mut n = 0;
            for s in st.spawns.values_mut() {
                if let Ending::Grace(g) = &mut s.ending {
                    g.thaw(now);
                    n += 1;
                }
            }
            n
        };
        log(&format!("ai-env: spawns thawed ({n} detach grace(s))"));
        self.inner.clock_wake.notify_one();
    }

    /// Live spawns (not yet exited).
    #[must_use]
    pub fn live(&self) -> usize {
        self.inner.lock().live()
    }

    /// Count one workspace helper (S8 §6, `asagent`) before it is forked,
    /// under the lock the idle sweep holds, so a sweep never runs while a
    /// helper lives and a helper is never forked into a sweep. `None` once
    /// the shim is stopping, unless `during_stop`. Helpers do not count
    /// toward [`MAX_SPAWNS`].
    pub async fn hold_helper(&self, during_stop: bool) -> Option<HelperHold> {
        let _held = self.inner.spawn_lock.lock().await;
        let mut st = self.inner.lock();
        if st.stopping && !during_stop {
            return None;
        }
        st.next_helper += 1;
        let id = st.next_helper;
        st.helpers.insert(id, None);
        Some(HelperHold { inner: self.inner.clone(), id })
    }

    /// Workspace helpers running now (`/health/detail`'s workspace view).
    #[must_use]
    pub fn helpers(&self) -> usize {
        self.inner.lock().helpers.len()
    }

    /// The stop ladder (the shim exits next): TERM every group, at most 3 s
    /// for the leaders, then KILL every group still pinned — an exited
    /// leader's too, whose watcher would not see its 1 s out — at most 1 s.
    pub async fn shutdown(&self, why: &str) {
        self.end_all(why, SHUTDOWN_TERM_WAIT, true).await;
    }

    /// `/terminate`'s ladder (plan S6: TERM every group, KILL 5 s later):
    /// TERM every group, at most 5 s for the leaders, then KILL only the
    /// groups whose leader still runs (an exited leader's group keeps its
    /// watcher's ladder: TERM at the death, KILL 1 s later), at most 1 s.
    pub async fn terminate(&self) {
        self.end_all("terminate", TERMINATE_TERM_WAIT, false).await;
    }

    /// Refuse new spawns and TERM every live group; at most `term_wait` for
    /// the leaders; KILL the groups whose leader still runs, and with
    /// `kill_pinned` every group an exited leader still pins; at most
    /// [`SHUTDOWN_KILL_WAIT`]. Outboxes never wake again.
    async fn end_all(&self, why: &str, term_wait: Duration, kill_pinned: bool) {
        let (terms, helpers) = {
            let _held = self.inner.spawn_lock.lock().await;
            let mut st = self.inner.lock();
            st.stopping = true;
            let live: Vec<&Spawn> = st.spawns.values().filter(|s| s.leader.is_none()).collect();
            for s in &live {
                s.signal_group(libc::SIGTERM);
            }
            // The workspace helpers too (S8): each one's owner reaps it.
            let helpers = st.helper_groups();
            for g in &helpers {
                killpg(*g, libc::SIGTERM);
            }
            (live.len(), helpers.len())
        };
        log(&format!("ai-env: spawns stopping ({why}): TERM to {terms} group(s) and {helpers} workspace helper(s)"));
        self.wait_idle(term_wait).await;
        let kills = {
            let st = self.inner.lock();
            let due: Vec<&Spawn> = st.spawns.values().filter(|s| !s.reaped && (kill_pinned || s.leader.is_none())).collect();
            for s in &due {
                s.signal_group(libc::SIGKILL);
            }
            for g in st.helper_groups() {
                killpg(g, libc::SIGKILL);
            }
            due.len()
        };
        self.wait_idle(SHUTDOWN_KILL_WAIT).await;
        let left = self.live();
        log(&format!("ai-env: spawns stopped ({why}): KILL to {kills} group(s), {left} still running"));
        self.inner.shut.store(true, Ordering::SeqCst);
        self.inner.bump();
    }

    /// Until no leader runs and no workspace helper's group is left to
    /// signal (each one's owner reaps it), or `limit`.
    async fn wait_idle(&self, limit: Duration) {
        let until = Instant::now() + limit;
        let busy = || {
            let st = self.inner.lock();
            st.live() > 0 || st.helpers.values().any(Option::is_some)
        };
        while busy() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// One workspace helper counted by [`SpawnManager::hold_helper`]: the idle
/// sweep waits while it exists, and a stop signals its process group once
/// [`HelperHold::set_group`] named it. Its owner clears the group
/// ([`HelperHold::clear_group`]) before it reaps the leader, so no stop ever
/// signals a reused group id. Dropping it runs a sweep a helper held off.
pub struct HelperHold {
    inner: Arc<Inner>,
    id: u64,
}

impl HelperHold {
    /// The helper was forked: its group (its pid) may be signalled by a stop.
    pub fn set_group(&self, pgid: u32) {
        if let Some(g) = self.inner.lock().helpers.get_mut(&self.id) {
            *g = Some(pgid);
        }
    }

    /// The helper's leader is about to be reaped: no stop signals it from here.
    pub fn clear_group(&self) {
        if let Some(g) = self.inner.lock().helpers.get_mut(&self.id) {
            *g = None;
        }
    }
}

impl Drop for HelperHold {
    fn drop(&mut self) {
        let sweep = {
            let mut st = self.inner.lock();
            st.helpers.remove(&self.id);
            st.sweep_due && st.helpers.is_empty() && st.live() == 0 && !st.stopping
        };
        if sweep && self.inner.opts.sweep {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let inner = self.inner.clone();
                rt.spawn(async move { inner.sweep_if_idle().await });
            }
        }
    }
}

impl Drop for SpawnManager {
    /// No group outlives the manager (tests drop it; the shim stops through `shutdown`).
    fn drop(&mut self) {
        for s in self.inner.lock().spawns.values() {
            s.signal_group(libc::SIGKILL);
        }
    }
}

// ---- the four tasks of a spawn -----------------------------------------------------------

/// stdout → Chunker → the window; waits for credit when the window is full.
async fn read_stdout(inner: Arc<Inner>, id: SpawnId, pipe: Option<ChildStdout>, credit: Arc<Notify>) {
    let Some(mut pipe) = pipe else { return inner.reader_done(&id, true) };
    let window = inner.opts.window_bytes;
    let mut chunker = Chunker::new();
    let mut buf = vec![0u8; CHUNK_MAX];
    loop {
        let room = match inner.lock().spawns.get(&id) {
            Some(s) if !s.out_done => s.stdout_room(window),
            _ => return,
        };
        if room == 0 {
            credit.notified().await;
            continue;
        }
        let want = usize::try_from(room).unwrap_or(CHUNK_MAX).min(CHUNK_MAX);
        let n = match pipe.read(&mut buf[..want]).await {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => 0,
        };
        let (eof, released) = {
            let mut st = inner.lock();
            let Some(s) = st.spawns.get_mut(&id) else { return };
            if s.out_done {
                return;
            }
            if n > 0 {
                // S10: stdout is the spawn's I/O (the busy check's quiet).
                s.last_io = Instant::now();
            }
            let chunks = if n == 0 { chunker.finish().into_iter().collect() } else { chunker.push(&buf[..n]) };
            for c in chunks {
                s.out.push(c);
            }
            if n == 0 { (true, st.reader_finished(&id, true)) } else { (false, None) }
        };
        inner.bump();
        if let Some(r) = released {
            r.abort_tasks();
        }
        if eof {
            return;
        }
    }
}

/// stderr → Chunker → the drop-oldest buffer; never waits.
async fn read_stderr(inner: Arc<Inner>, id: SpawnId, pipe: Option<ChildStderr>) {
    let Some(mut pipe) = pipe else { return inner.reader_done(&id, false) };
    let mut chunker = Chunker::new();
    let mut buf = vec![0u8; CHUNK_MAX];
    loop {
        let n = match pipe.read(&mut buf).await {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => 0,
        };
        let (eof, released) = {
            let mut st = inner.lock();
            let Some(s) = st.spawns.get_mut(&id) else { return };
            if s.err_done {
                return;
            }
            if n > 0 {
                // S10: so is stderr.
                s.last_io = Instant::now();
            }
            let chunks = if n == 0 { chunker.finish().into_iter().collect() } else { chunker.push(&buf[..n]) };
            for c in chunks {
                // What the attachment was handed already is not counted as dropped again.
                s.err.push(c, s.cursor.err);
            }
            if n == 0 { (true, st.reader_finished(&id, false)) } else { (false, None) }
        };
        inner.bump();
        if let Some(r) = released {
            r.abort_tasks();
        }
        if eof {
            return;
        }
    }
}

/// The stdin queue → the pipe; closes it at the EOF seq. Every write is acked.
async fn write_stdin(inner: Arc<Inner>, id: SpawnId, pipe: Option<ChildStdin>, ready: Arc<Notify>) {
    enum Step {
        Write(u64, Vec<u8>),
        Close,
        Wait,
    }
    let Some(mut pipe) = pipe else { return inner.stdin_ended(&id, true) };
    loop {
        let step = {
            let mut st = inner.lock();
            let Some(s) = st.spawns.get_mut(&id) else { return };
            match s.stdin.to_write() {
                Some((seq, bytes)) => Step::Write(seq, bytes),
                None if s.stdin.close_due() => Step::Close,
                None => Step::Wait,
            }
        };
        match step {
            Step::Wait => ready.notified().await,
            Step::Close => {
                drop(pipe);
                return inner.stdin_ended(&id, false);
            }
            Step::Write(seq, bytes) => {
                if pipe.write_all(&bytes).await.is_err() {
                    drop(pipe);
                    return inner.stdin_ended(&id, true);
                }
                if let Some(s) = inner.lock().spawns.get_mut(&id) {
                    s.stdin.wrote(seq, bytes.len() as u64);
                }
                inner.bump();
            }
        }
    }
}

/// The leader: observe its death without reaping it, TERM the group at once
/// and KILL it after [`GROUP_KILL_AFTER`] (the zombie pins the group id), then
/// reap; sweep when it was the last; give an escaper's pipes 2 s. Every step
/// touches only this leader's record (the id and `pid`): the record may be
/// released meanwhile, and another may hold the id.
async fn watch_leader(inner: Arc<Inner>, id: SpawnId, mut child: Child, pid: u32) {
    let nowait = match libc::pid_t::try_from(pid) {
        Ok(p) => tokio::task::spawn_blocking(move || wait_exited(p)).await.ok().flatten(),
        Err(_) => None,
    };
    let pinned = nowait.is_some();
    let info = match nowait {
        Some(info) => info,
        None => child.wait().await.map_or(ExitInfo { code: None, signal: None }, |s| ExitInfo { code: s.code(), signal: s.signal() }),
    };
    let died = Instant::now();
    let (idle, released) = {
        let mut st = inner.lock();
        if pinned {
            killpg(pid, libc::SIGTERM);
        }
        let mine = match st.spawns.get_mut(&id).filter(|s| s.pid == pid) {
            Some(s) => {
                s.leader = Some(info);
                s.reaped = !pinned;
                s.due.clear();
                s.credit.notify_one();
                true
            }
            None => false,
        };
        let released = if mine { st.settle(&id) } else { None };
        (st.live() == 0, released)
    };
    if let Some(r) = released {
        r.abort_tasks();
    }
    inner.bump();
    if pinned {
        tokio::time::sleep_until(died + GROUP_KILL_AFTER).await;
        {
            let mut st = inner.lock();
            killpg(pid, libc::SIGKILL);
            if let Some(s) = st.spawns.get_mut(&id).filter(|s| s.pid == pid) {
                s.reaped = true;
            }
        }
        // From here the pid, and so the group id, may name someone else.
        let _ = child.wait().await;
    }
    if idle && inner.opts.sweep {
        inner.sweep_if_idle().await;
    }
    inner.drain_or_abandon(&id, pid, died + DRAIN_AFTER_DEATH).await;
}

/// Graces and ladders, and the jump guard. Holds the manager only while it
/// works, so dropping the manager ends it at the next wake.
async fn run_clock(inner: Weak<Inner>, wake: Arc<Notify>) {
    let mut last = Instant::now();
    loop {
        let next = match inner.upgrade() {
            Some(i) => i.lock().next_deadline(),
            None => return,
        };
        let tick = last + TICK;
        tokio::select! {
            () = tokio::time::sleep_until(next.map_or(tick, |d| d.min(tick))) => {}
            () = wake.notified() => {}
        }
        let Some(i) = inner.upgrade() else { return };
        let now = Instant::now();
        i.woke(last, now);
        last = now;
    }
}

// ---- the park's busy check (S10) ---------------------------------------------------------

/// The busy check's sampler (Linux): every [`ACTIVITY_SAMPLE`], one look
/// at the session of each live spawn (`/proc`, off the runtime's workers),
/// recorded as a sample of its own. Holds the manager only while it works,
/// so dropping the manager ends it at the next wake.
#[cfg(target_os = "linux")]
async fn run_sampler(inner: Weak<Inner>) {
    let hz = clock_ticks();
    loop {
        tokio::time::sleep(ACTIVITY_SAMPLE).await;
        let leaders: Vec<(SpawnId, u32)> = match inner.upgrade() {
            Some(i) => i.lock().live_leaders(),
            None => return,
        };
        if leaders.is_empty() {
            continue;
        }
        let pids: Vec<u32> = leaders.iter().map(|(_, pid)| *pid).collect();
        let away = match inner.upgrade() {
            Some(i) => i.escapers(),
            None => return,
        };
        let Ok(looks) = tokio::task::spawn_blocking(move || sample_sessions(Path::new("/proc"), &pids, hz, away.as_ref().map(|(uid, helpers)| (*uid, helpers.as_slice())))).await else { continue };
        let Some(i) = inner.upgrade() else { return };
        let at = Instant::now();
        let mut st = i.lock();
        for (id, pid) in leaders {
            if let (Some(s), Some(look)) = (st.spawns.get_mut(&id).filter(|s| s.pid == pid), looks.get(&pid)) {
                s.activity.record(at, look);
            }
        }
    }
}

/// The kernel's clock ticks a second (`/proc/<pid>/stat`'s CPU unit).
#[cfg(target_os = "linux")]
fn clock_ticks() -> u64 {
    // SAFETY: sysconf takes a name and returns a value, or -1.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(hz).ok().filter(|h| *h > 0).unwrap_or(100)
}

/// The busy check's look at the session `leader` leads, now (Linux: from
/// `/proc`), the agent's escapers counted in it ([`Inner::escapers`]):
/// `leaders` are every live spawn's leader, `leader` among them, whose
/// sessions are their own spawns' and never an escaper's (V-6). A `leader`
/// not among them (its spawn's leader died) gets the default look.
#[cfg(target_os = "linux")]
fn session_now(leader: u32, leaders: &[u32], away: Option<(u32, Vec<u32>)>) -> SessionNow {
    sample_sessions(Path::new("/proc"), leaders, clock_ticks(), away.as_ref().map(|(uid, helpers)| (*uid, helpers.as_slice()))).remove(&leader).unwrap_or_default()
}

/// Native macOS: the busy check is the stdio part alone (no CPU, nothing
/// running counted); the session's processes are counted for the answer.
#[cfg(target_os = "macos")]
fn session_now(leader: u32, _leaders: &[u32], _away: Option<(u32, Vec<u32>)>) -> SessionNow {
    SessionNow { cpu_ms: None, running: 0, procs: u32::try_from(crate::shim::asagent::session_pids(leader).len()).unwrap_or(u32::MAX) }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn session_now(_leader: u32, _leaders: &[u32], _away: Option<(u32, Vec<u32>)>) -> SessionNow {
    SessionNow::default()
}

/// One `/proc/<pid>/stat` as the busy check reads it: its state, its
/// session, and the CPU (clock ticks) it and its reaped children used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatLine {
    state: char,
    session: u32,
    cpu_ticks: u64,
}

/// A `/proc/<pid>/stat` text's fields past the `)` that closes `comm`
/// (the last one: `comm` may hold spaces and parentheses): the state
/// (field 3), the session (6), utime, stime, cutime and cstime (14 to 17).
/// `None` for a text that does not parse.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_stat(text: &str) -> Option<StatLine> {
    let fields: Vec<&str> = text[text.rfind(')')? + 1..].split_whitespace().collect();
    let state = fields.first()?.chars().next()?;
    let session = fields.get(3)?.parse().ok()?;
    let ticks = |i: usize| fields.get(i).and_then(|f| f.parse::<i64>().ok()).map(|t| u64::try_from(t).unwrap_or(0));
    let cpu_ticks = [11, 12, 13, 14].into_iter().try_fold(0u64, |sum, i| ticks(i).map(|t| sum.saturating_add(t)))?;
    Some(StatLine { state, session, cpu_ticks })
}

/// One session's count in [`sample_sessions`].
#[derive(Debug, Clone, Copy, Default)]
struct SessionCount {
    ticks: u64,
    running: u32,
    alive: u32,
    /// The leader's own stat was read.
    leader: bool,
}

/// The sessions of `leaders` under `proc` (`/proc`; a planted tree in the
/// tests), from one pass over its numeric entries: per leader, the CPU in
/// ms (at `hz` ticks a second) of every process of its session (a
/// zombie's too: its parent's children count takes it once reaped), and
/// its processes but the leader alive, and running (R or D). A leader
/// whose own stat was not read (gone meanwhile) is missing: a count
/// without it would start the next sample's CPU from nothing.
///
/// With `away` (S10 V-6: the agent's uid and the sessions its workspace
/// helpers lead), the agent's escapers count in every leader's look too:
/// each running process (not a zombie) whose real and effective uid are
/// the agent's, in no leader's session and no helper's, such as a child of
/// claude that called `setsid` (a backgrounded build). Their CPU and those
/// running (R or D) are added; `procs` stays the session's own. A session
/// left out of `leaders` is counted so too: every look passes every live
/// spawn's leader ([`State::live_leaders`]).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sample_sessions(proc: &Path, leaders: &[u32], hz: u64, away: Option<(u32, &[u32])>) -> BTreeMap<u32, SessionNow> {
    let Ok(rd) = std::fs::read_dir(proc) else { return BTreeMap::new() };
    let mut seen: BTreeMap<u32, SessionCount> = leaders.iter().map(|l| (*l, SessionCount::default())).collect();
    let mut escaped = SessionCount::default();
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())).and_then(|n| n.parse::<u32>().ok()) else { continue };
        // Lossy: a `comm` that is not UTF-8 must not hide the process's CPU.
        let Some(line) = std::fs::read(e.path().join("stat")).ok().and_then(|b| parse_stat(&String::from_utf8_lossy(&b))) else { continue };
        let Some(count) = seen.get_mut(&line.session) else {
            if let Some((uid, helpers)) = away {
                if !helpers.contains(&line.session) && std::fs::read_to_string(e.path().join("status")).is_ok_and(|s| crate::shim::sys::is_running_as(&s, uid)) {
                    escaped.ticks = escaped.ticks.saturating_add(line.cpu_ticks);
                    if matches!(line.state, 'R' | 'D') {
                        escaped.running += 1;
                    }
                }
            }
            continue;
        };
        count.ticks = count.ticks.saturating_add(line.cpu_ticks);
        if pid == line.session {
            count.leader = true;
        } else if !matches!(line.state, 'Z' | 'X') {
            count.alive += 1;
            if matches!(line.state, 'R' | 'D') {
                count.running += 1;
            }
        }
    }
    seen.into_iter()
        .filter(|(_, c)| c.leader)
        .map(|(leader, c)| (leader, SessionNow { cpu_ms: Some(c.ticks.saturating_add(escaped.ticks).saturating_mul(1000) / hz.max(1)), running: c.running + escaped.running, procs: c.alive }))
        .collect()
}

/// `park_refused.reason`'s word, for the log.
fn refusal_word(r: ParkRefusal) -> &'static str {
    match r {
        ParkRefusal::Busy => "busy",
        ParkRefusal::Output => "output",
        ParkRefusal::Unacked => "unacked",
        ParkRefusal::NotAttached => "not_attached",
        ParkRefusal::Other => "other",
    }
}

// ---- process plumbing --------------------------------------------------------------------

fn log(line: &str) {
    #[cfg(test)]
    tests::LOG.lock().unwrap_or_else(PoisonError::into_inner).push(line.to_string());
    errln!("{line}");
}

fn opt(v: Option<i32>) -> String {
    v.map_or("-".to_string(), |v| v.to_string())
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// At most 200 characters of client text (an id, argv[0], a name, a path)
/// for a log line or a message, escaped as `{:?}` escapes a string, without
/// the quotes: a newline in it never starts a (forged) line of its own.
fn short(text: &str) -> String {
    let quoted = format!("{:?}", text.chars().take(200).collect::<String>());
    quoted.strip_prefix('"').and_then(|q| q.strip_suffix('"')).unwrap_or(&quoted).to_string()
}

/// killpg for a group id this module got from a spawn or a helper (never 0 or 1).
pub(crate) fn killpg(pgid: u32, sig: i32) {
    if let Ok(pgid) = libc::pid_t::try_from(pgid) {
        if pgid > 1 {
            // SAFETY: plain integers; the caller holds the leader unreaped, so the id is still its group.
            unsafe { libc::killpg(pgid, sig) };
        }
    }
}

/// Whether a process of group `pgid` still exists (`/health/detail`'s
/// `group_alive`, S7 D6): `kill(-pgid, 0)` succeeds, or is refused (EPERM).
/// Signal 0 delivers nothing, so unlike [`killpg`] it may ask after the
/// leader was reaped: a reused group id can then only read alive (a needless
/// `vm terminate` hint), never gone. On Linux a zombie leader counts too,
/// until its watcher reaps it (after the group's KILL, [`GROUP_KILL_AFTER`]
/// after its death).
fn group_alive(pgid: u32) -> bool {
    let Ok(pgid) = libc::pid_t::try_from(pgid) else { return false };
    if pgid <= 1 {
        return false;
    }
    // SAFETY: plain integers; signal 0 only checks that the group exists.
    let rc = unsafe { libc::killpg(pgid, 0) };
    rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Block until the leader `pid` has exited, WITHOUT reaping it: `None` when
/// it cannot be waited for (reaped by someone else: the group is not pinned).
pub(crate) fn wait_exited(pid: libc::pid_t) -> Option<ExitInfo> {
    let id = libc::id_t::try_from(pid).ok()?;
    loop {
        // SAFETY: an all-zero siginfo_t is a valid value for waitid to fill.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid fills `info`; WNOWAIT leaves the child waitable.
        if unsafe { libc::waitid(libc::P_PID, id, &mut info, libc::WEXITED | libc::WNOWAIT) } == 0 {
            return Some(exit_info(&info));
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return None;
        }
    }
}

fn exit_info(info: &libc::siginfo_t) -> ExitInfo {
    #[cfg(target_os = "linux")]
    // SAFETY: waitid filled a SIGCHLD siginfo, whose status field is valid.
    let status = unsafe { info.si_status() };
    #[cfg(not(target_os = "linux"))]
    let status = info.si_status;
    match info.si_code {
        libc::CLD_EXITED => ExitInfo { code: Some(status), signal: None },
        libc::CLD_KILLED | libc::CLD_DUMPED => ExitInfo { code: None, signal: Some(status) },
        _ => ExitInfo { code: None, signal: None },
    }
}

/// A close-on-exec pipe already holding `value`, its write end closed: the
/// read end, for the child's fd 3. `value` fits the pipe buffer, so the
/// write never waits for a reader.
fn secret_pipe(value: &[u8]) -> io::Result<OwnedFd> {
    let mut fds: [libc::c_int; 2] = [-1, -1];
    #[cfg(target_os = "linux")]
    // SAFETY: `fds` is an array of two ints for pipe2 to fill.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: as above.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both fds were just created and belong to nobody else.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    #[cfg(not(target_os = "linux"))]
    for fd in [&read, &write] {
        // SAFETY: a valid fd we own.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    io::Write::write_all(&mut std::fs::File::from(write), value)?;
    Ok(read)
}

/// The program for argv[0]: `claude` → the cached binary the connection
/// picked (S11), else `--claude`; a path (with `/`) as given; a bare name
/// looked up on the child's PATH, here, before the fork.
fn resolve(argv0: &str, claude: &Path, picked: Option<&Path>) -> Result<PathBuf, String> {
    if argv0 == "claude" {
        return Ok(picked.unwrap_or(claude).to_path_buf());
    }
    if argv0.contains('/') {
        return Ok(PathBuf::from(argv0));
    }
    CHILD_PATH
        .split(':')
        .map(|dir| Path::new(dir).join(argv0))
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
        .ok_or_else(|| format!("{}: not found on PATH={CHILD_PATH}", short(argv0)))
}

/// A spawn's PATH (S11): the cached claude's directory first when one runs,
/// so a nested `claude` runs it too; [`CHILD_PATH`] otherwise. A frame still
/// cannot set PATH ([`RESERVED_ENV`]).
fn child_path(cached: Option<&Path>) -> std::ffi::OsString {
    let mut path = std::ffi::OsString::new();
    if let Some(dir) = cached.and_then(Path::parent) {
        path.push(dir.as_os_str());
        path.push(":");
    }
    path.push(CHILD_PATH);
    path
}

/// The components of a spawn's working directory, a VM path ([`cwd_parts`]'s
/// rules), entered under `fs_root` when the shim has one (native tests: the
/// VM's disk is a directory of the Mac's).
fn vm_cwd_parts(fs_root: Option<&Path>, path: &str) -> Result<Vec<std::ffi::CString>, String> {
    let mut parts = match fs_root {
        Some(root) => cwd_parts(root.as_os_str().as_bytes()).map_err(|m| format!("the fs root {m}"))?,
        None => Vec::new(),
    };
    parts.extend(cwd_parts(path.as_bytes())?);
    Ok(parts)
}

/// The `bad_request` rules of a spawn frame; the message names a field or a
/// key, never an argument, a value or the secret.
fn check_request(req: &SpawnRequest) -> Result<(), String> {
    if !req.spawn_id.is_v7() {
        return Err("spawn_id must be a lowercase hyphenated uuid v7".into());
    }
    if req.argv.first().is_none_or(String::is_empty) {
        return Err("argv[0] is missing or empty".into());
    }
    let size: usize = req.argv.iter().map(|a| a.len() + 1).sum();
    if size > ARGV_MAX_BYTES {
        return Err(format!("argv is {size} bytes (at most {ARGV_MAX_BYTES})"));
    }
    if let Some(i) = req.argv.iter().position(|a| a.contains('\0')) {
        return Err(format!("argument {i} holds a NUL byte"));
    }
    if req.env.len() > ENV_MAX_ENTRIES {
        return Err(format!("{} environment entries (at most {ENV_MAX_ENTRIES})", req.env.len()));
    }
    for (k, v) in &req.env {
        check_name(k)?;
        if v.contains('\0') {
            return Err(format!("the value of {k} holds a NUL byte"));
        }
    }
    if req.secrets.len() > 1 {
        return Err(format!("{} secrets (at most one)", req.secrets.len()));
    }
    // S11: the staged claudes it names (compared with the cache's index only, never joined into a path).
    if req.claude.len() > CLAUDE_REFS_MAX {
        return Err(format!("claude names {} refs (at most {CLAUDE_REFS_MAX})", req.claude.len()));
    }
    for (i, r) in req.claude.iter().enumerate() {
        r.check().map_err(|e| format!("claude ref {i} {e}"))?;
        if req.claude[..i].iter().any(|before| before.sha256 == r.sha256) {
            return Err(format!("claude ref {i} names a sha256 an earlier ref names"));
        }
    }
    for (k, v) in &req.secrets {
        check_name(k)?;
        let var = match req.deliver {
            Deliver::Fd => format!("{k}_FILE_DESCRIPTOR"),
            Deliver::Env => k.clone(),
        };
        if req.env.contains_key(&var) {
            return Err(format!("{var} is set by the secret's delivery"));
        }
        let value = v.expose();
        if req.deliver == Deliver::Fd && value.len() > SECRET_FD_MAX_BYTES {
            return Err(format!("the secret {k} is {} bytes (at most {SECRET_FD_MAX_BYTES} on fd 3)", value.len()));
        }
        if value.contains('\0') {
            return Err(format!("the secret {k} holds a NUL byte"));
        }
    }
    Ok(())
}

/// An environment name: `[A-Za-z_][A-Za-z0-9_]*`, and none the shim sets itself.
pub(crate) fn check_name(k: &str) -> Result<(), String> {
    let valid = k.bytes().next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_') && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
    if !valid {
        return Err(format!("environment name \"{}\" is not [A-Za-z_][A-Za-z0-9_]*", short(k)));
    }
    if RESERVED_ENV.contains(&k) {
        return Err(format!("{k} is set by the shim"));
    }
    Ok(())
}

/// A failed `spawn()`: the working directory (the `pre_exec` marker) or the program.
fn spawn_error(e: &io::Error, argv0: &str, cwd: &str, opts: &SpawnOpts) -> (SpawnErrCode, String) {
    match e.raw_os_error() {
        Some(n) if n >= CWD_ERRNO_BASE => (SpawnErrCode::Cwd, format!("cannot create or enter the working directory \"{cwd}\": {}", io::Error::from_raw_os_error(n - CWD_ERRNO_BASE))),
        // A path that names nothing (or a missing interpreter): a shell's 127.
        Some(libc::ENOENT) => (SpawnErrCode::NotFound, format!("cannot start {}: {e}", short(argv0))),
        _ => {
            let dropping = opts.uid.is_some() || opts.gid.is_some();
            let hint = if dropping { crate::shim::sys::eperm_hint(e, crate::shim::sys::RealSys.cap_eff()) } else { String::new() };
            (SpawnErrCode::Exec, format!("cannot start {}: {e}{hint}", short(argv0)))
        }
    }
}

/// Kill every running process of `uid` but this one, scanning `/proc` until
/// a scan finds none ([`sweep_passes`]). Zombies — a pinned leader among
/// them — are skipped. How many were signalled, and how many scans it took.
#[cfg(target_os = "linux")]
fn sweep(uid: u32) -> (usize, usize) {
    let proc = Path::new("/proc");
    let me = std::process::id();
    sweep_passes(|| crate::shim::sys::pids_of_uid(proc, uid).into_iter().filter(|p| *p != me).collect(), |pid| kill_still_running_as(proc, pid, uid))
}

/// SIGKILL `pid` through a pidfd when, once the pidfd pins it, it still runs
/// as `uid` (the pid may have been reused since the scan).
#[cfg(target_os = "linux")]
fn kill_still_running_as(proc: &Path, pid: u32, uid: u32) -> bool {
    let Ok(raw) = libc::pid_t::try_from(pid) else { return false };
    // SAFETY: pidfd_open takes a pid and flags; a non-negative result is a new fd we own.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, raw, 0) };
    let Ok(fd) = libc::c_int::try_from(fd) else { return false };
    if fd < 0 {
        return false;
    }
    // SAFETY: as above.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    let still = std::fs::read_to_string(proc.join(pid.to_string()).join("status")).is_ok_and(|s| crate::shim::sys::is_running_as(&s, uid));
    // SAFETY: a pidfd we own, a signal number, no siginfo, no flags.
    still && unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), libc::SIGKILL, std::ptr::null::<libc::siginfo_t>(), 0) } == 0
}

/// Off Linux the sweep is never enabled (`SpawnOpts::sweep` is false).
#[cfg(not(target_os = "linux"))]
fn sweep(_uid: u32) -> (usize, usize) {
    (0, 0)
}

/// The sweep's scans: `kill` what `scan` finds, then scan again
/// [`SWEEP_PAUSE`] later, until a scan finds nothing or [`SWEEP_PASSES`]
/// scans were made: one snapshot misses what an escaper forks between the
/// scan and its own kill. How many distinct pids were killed, and the scans.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sweep_passes(mut scan: impl FnMut() -> Vec<u32>, mut kill: impl FnMut(u32) -> bool) -> (usize, usize) {
    let mut killed = std::collections::BTreeSet::new();
    for pass in 1..=SWEEP_PASSES {
        if pass > 1 {
            std::thread::sleep(SWEEP_PAUSE);
        }
        let found = scan();
        if found.is_empty() {
            return (killed.len(), pass);
        }
        killed.extend(found.into_iter().filter(|p| kill(*p)));
    }
    (killed.len(), SWEEP_PASSES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shim::childproc::CWD_MAX_BYTES;
    use crate::wire::chunk::decode;
    use crate::wire::frame::STDOUT_WINDOW_BYTES;
    use crate::wire::redact::Secret;

    /// Every line this module logged (tests assert what never appears).
    pub(super) static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// Held by the tests that count idle-sweep lines (they share [`LOG`]).
    static SWEEPS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    const WAIT: Duration = Duration::from_secs(10);

    fn opts(home: &Path, window_bytes: u64) -> SpawnOpts {
        SpawnOpts { claude: PathBuf::from("/nonexistent/claude"), home: home.to_path_buf(), uid: None, gid: None, agent_uid: 1000, window_bytes, sweep: false, fs_root: None }
    }

    fn manager(home: &Path) -> SpawnManager {
        SpawnManager::new(opts(home, STDOUT_WINDOW_BYTES))
    }

    fn req(argv: &[&str]) -> SpawnRequest {
        SpawnRequest { spawn_id: SpawnId::new_v7(), argv: argv.iter().map(|a| (*a).to_string()).collect(), cwd: None, env: BTreeMap::new(), secrets: BTreeMap::new(), deliver: Deliver::Fd, detach_grace_s: None, credential: None, claude: Vec::new(), picked: None }
    }

    async fn start(m: &SpawnManager, conn: ConnGen, r: SpawnRequest) -> (SpawnId, u32) {
        let id = r.spawn_id.clone();
        match m.spawn(conn, r).await {
            Frame::Spawned { spawn_id, pid, pgid, claude_version: None, claude_sha256: None } if spawn_id == id && pgid == pid => (id, pid),
            f => panic!("{f:?}"),
        }
    }

    async fn refused(m: &SpawnManager, r: SpawnRequest) -> (SpawnErrCode, String) {
        let id = r.spawn_id.clone();
        match m.spawn(1, r).await {
            Frame::SpawnErr { spawn_id, code, message } if spawn_id == id => (code, message),
            f => panic!("{f:?}"),
        }
    }

    /// Is `pid` gone (not even a zombie)?
    fn gone(pid: u32) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else { return true };
        // SAFETY: signal 0 only checks that the process exists.
        let rc = unsafe { libc::kill(pid, 0) };
        rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    async fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + limit;
        while !cond() {
            if Instant::now() >= end {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        true
    }

    /// The Mac's side of one connection: pulls the outbox, keeps the bytes,
    /// and acks what it received (stdout and stderr each when told to).
    struct Client<'a> {
        m: &'a SpawnManager,
        conn: ConnGen,
        ob: Outbox,
        ack_out: bool,
        ack_err: bool,
        out: Vec<u8>,
        err: Vec<u8>,
        out_seqs: Vec<u64>,
        err_seq: u64,
        stdin_ack: u64,
        exit: Option<Frame>,
        other: Vec<Frame>,
    }

    impl<'a> Client<'a> {
        fn new(m: &'a SpawnManager, conn: ConnGen) -> Client<'a> {
            Client { m, conn, ob: m.outbox(conn), ack_out: true, ack_err: true, out: Vec::new(), err: Vec::new(), out_seqs: Vec::new(), err_seq: 0, stdin_ack: 0, exit: None, other: Vec::new() }
        }

        fn out_seq(&self) -> u64 {
            self.out_seqs.last().copied().unwrap_or(0)
        }

        /// Ack what this client has, as far as it acks each stream.
        fn ack(&self, id: &SpawnId) {
            let (out, err) = (if self.ack_out { self.out_seq() } else { 0 }, if self.ack_err { self.err_seq } else { 0 });
            let _ = self.m.ack(self.conn, id, out, err);
        }

        /// Everything the outbox has now.
        fn take(&mut self) {
            while let Some(f) = self.ob.try_next() {
                match &f {
                    Frame::Stdout { spawn_id, seq, data } => {
                        self.out.extend(decode(data).unwrap());
                        self.out_seqs.push(*seq);
                        self.ack(spawn_id);
                    }
                    Frame::Stderr { spawn_id, seq, data, .. } => {
                        self.err.extend(decode(data).unwrap());
                        self.err_seq = *seq;
                        self.ack(spawn_id);
                    }
                    Frame::StdinAck { seq, .. } => self.stdin_ack = *seq,
                    Frame::Exit { .. } => self.exit = Some(f),
                    _ => self.other.push(f),
                }
            }
        }

        /// Pull until `done` holds or `limit` passes.
        async fn until(&mut self, limit: Duration, done: impl Fn(&Client<'_>) -> bool) -> bool {
            let end = Instant::now() + limit;
            loop {
                self.take();
                if done(self) {
                    return true;
                }
                if tokio::time::timeout_at(end, self.ob.changed()).await.is_err() {
                    self.take();
                    return done(self);
                }
            }
        }

        fn exited(&self) -> (u64, ExitInfo, u64, bool) {
            match self.exit {
                Some(Frame::Exit { seq, code, signal, stderr_dropped, stdout_truncated, .. }) => (seq, ExitInfo { code, signal }, stderr_dropped, stdout_truncated),
                ref other => panic!("no exit: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn cat_round_trips_bytes_exactly_with_stdin_acks_and_eof() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let (id, _) = start(&m, 1, req(&["cat"])).await;
        let mut input = b"hello\n\x00\xff\n".to_vec();
        input.extend((0..300_000u32).map(|i| (i.wrapping_mul(7) % 256) as u8));
        input.extend_from_slice("a last line without a newline: \u{20ac}".as_bytes());
        let mut seq = 0;
        for piece in input.chunks(CHUNK_MAX) {
            seq += 1;
            m.stdin(1, &id, seq, piece.to_vec()).unwrap();
        }
        m.stdin(1, &id, 1, b"resent".to_vec()).unwrap();
        assert_eq!(m.stdin(1, &id, seq + 2, b"x".to_vec()), Err(ErrorCode::StdinGap));
        m.stdin_eof(1, &id, seq).unwrap();
        assert!(c.until(WAIT, |c| c.exit.is_some()).await, "no exit");
        assert_eq!(c.out.len(), input.len());
        assert!(c.out == input, "byte-identical, the resent seq 1 ignored");
        assert_eq!(c.stdin_ack, seq, "every chunk was acked once written");
        assert_eq!(c.out_seqs, (1..=c.out_seq()).collect::<Vec<_>>(), "seqs from 1, no gap");
        let (exit_seq, info, dropped, truncated) = c.exited();
        assert_eq!((exit_seq, info, dropped, truncated), (c.out_seq() + 1, ExitInfo { code: Some(0), signal: None }, 0, false));
        let st = &m.status(Some(1))[0];
        assert!(!st.alive && st.stdin_closed && st.in_seq == seq && st.exit == Some(info) && st.argv0 == "cat", "{st:?}");
        m.ack(1, &id, exit_seq, 0).unwrap();
        assert!(m.status(None).is_empty(), "acking the exit seq releases the spawn");
        assert_eq!(m.ack(1, &id, exit_seq, 0), Err(ErrorCode::NotAttached));
    }

    #[tokio::test]
    async fn a_full_window_stops_the_child_until_acks_arrive() {
        const WINDOW: u64 = 32 * 1024;
        let home = tempfile::tempdir().unwrap();
        let m = SpawnManager::new(opts(home.path(), WINDOW));
        let mut c = Client::new(&m, 1);
        c.ack_out = false;
        let (id, _) = start(&m, 1, req(&["sh", "-c", "head -c 1000000 /dev/zero; echo end >&2"])).await;
        c.until(Duration::from_millis(700), |_| false).await;
        assert!(!c.out.is_empty() && c.out.len() as u64 <= WINDOW + 3, "{} bytes unacked", c.out.len());
        assert!(c.exit.is_none() && m.status(None)[0].alive, "the child blocks on its full pipe");
        c.ack_out = true;
        c.ack(&id);
        assert!(c.until(WAIT, |c| c.exit.is_some()).await, "acks resume the child");
        assert_eq!(c.out.len(), 1_000_000);
        assert!(c.out.iter().all(|b| *b == 0));
        assert_eq!(c.err, b"end\n");
    }

    /// The stdout window counts chunks as well as bytes (a child writing one
    /// byte at a time): STDOUT_WINDOW_CHUNKS unacked chunks stop the reader
    /// however few bytes they hold; an ack frees room again; only once the
    /// leader died may the drain go DRAIN_PAST_WINDOW_CHUNKS past it. A bare
    /// record: pid 0 and `reaped` signal no one.
    #[test]
    fn the_stdout_room_stops_at_the_chunk_window() {
        use crate::wire::frame::Chunk;
        let mut s = Spawn {
            argv0: "x".into(),
            holds_secret: false,
            claude_sha256: None,
            pid: 0,
            started_at: String::new(),
            grace: Duration::ZERO,
            attached: None,
            ending: Ending::Attached,
            cursor: Cursor { out: 1, err: 1, exit_sent: false },
            out: OutWindow::default(),
            err: ErrBuffer::new(STDERR_BUFFER_BYTES),
            stdin: StdinQueue::new(STDIN_WINDOW_BYTES),
            stdin_acked: 0,
            stdin_closed: false,
            stdin_broken: false,
            leader: None,
            reaped: true,
            out_done: false,
            err_done: false,
            truncated: false,
            exit: None,
            due: Vec::new(),
            credit: Arc::new(Notify::new()),
            ready: Arc::new(Notify::new()),
            drained: Arc::new(Notify::new()),
            readers: Vec::new(),
            writer: None,
            park: None,
            last_io: Instant::now(),
            activity: Activity::default(),
        };
        let one = || Chunk { text: Some("x".into()), b64: None };
        for _ in 0..STDOUT_WINDOW_CHUNKS {
            s.out.push(one());
        }
        assert_eq!(s.stdout_room(STDOUT_WINDOW_BYTES), 0, "20 000 one-byte chunks fill the window");
        s.out.ack(1);
        assert_eq!(s.stdout_room(STDOUT_WINDOW_BYTES), STDOUT_WINDOW_BYTES - (STDOUT_WINDOW_CHUNKS - 1), "one acked chunk frees room");
        s.out.push(one());
        s.leader = Some(ExitInfo { code: Some(0), signal: None });
        assert!(s.stdout_room(STDOUT_WINDOW_BYTES) > 0, "the leader died: the drain may pass the chunk window");
        for _ in 0..DRAIN_PAST_WINDOW_CHUNKS {
            s.out.push(one());
        }
        assert_eq!(s.stdout_room(STDOUT_WINDOW_BYTES), 0, "at most DRAIN_PAST_WINDOW_CHUNKS past it");
    }

    /// The client takes every frame but acks no stderr: past 2 MiB the
    /// oldest stderr goes, chunks it was handed among them. Every stderr byte
    /// is received or counted as dropped, never both.
    #[tokio::test]
    async fn a_stderr_flood_drops_the_oldest_while_stdout_stays_complete() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        c.ack_err = false;
        start(&m, 1, req(&["sh", "-c", "head -c 3000000 /dev/zero >&2; head -c 200000 /dev/zero; head -c 1000000 /dev/zero >&2; echo done"])).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        let (_, info, dropped, _) = c.exited();
        assert_eq!(info.code, Some(0));
        assert_eq!(c.out.len(), 200_005, "stdout is never dropped");
        assert!(c.out.ends_with(b"done\n"));
        assert_eq!(c.err.len() as u64 + dropped, 4_000_000, "received {} and {dropped} dropped", c.err.len());
    }

    #[tokio::test]
    async fn a_final_detach_runs_the_ladder_and_releases_the_spawn() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let (id, pid) = start(&m, 1, req(&["sleep", "100"])).await;
        let t = Instant::now();
        m.detach(1, &id, true).unwrap();
        assert_eq!(m.detach(1, &id, true), Err(ErrorCode::NotAttached), "no longer attached");
        assert!(wait_until(Duration::from_secs(3), || m.live() == 0).await);
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(700) && took < Duration::from_millis(1500), "TERM at 0.8 s: {took:?}");
        assert!(wait_until(Duration::from_secs(3), || m.status(None).is_empty()).await, "nobody collects a final detach's exit");
        assert!(wait_until(Duration::from_secs(3), || gone(pid)).await, "reaped");
    }

    #[tokio::test]
    async fn a_lost_connection_gets_the_grace_then_term() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut r = req(&["sleep", "100"]);
        r.detach_grace_s = Some(1);
        let (id, _) = start(&m, 1, r).await;
        let t = Instant::now();
        m.connection_lost(1);
        let d = &m.detail()[0];
        assert!(d.detach_left_s.is_some() && !d.frozen && !d.status.attached, "{d:?}");
        assert!(wait_until(Duration::from_secs(4), || m.live() == 0).await);
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(2), "TERM after the 1 s grace: {took:?}");
        let log = LOG.lock().unwrap().join("\n");
        assert!(log.contains(&format!("ai-env: spawn {id} detach grace over: TERM")), "{log}");
    }

    #[tokio::test]
    async fn freeze_holds_the_grace_and_thaw_resumes_it() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut r = req(&["sleep", "100"]);
        r.detach_grace_s = Some(1);
        start(&m, 1, r).await;
        m.freeze();
        m.connection_lost(1);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(m.live(), 1, "frozen: the grace does not run");
        let d = &m.detail()[0];
        assert!(d.frozen && d.detach_left_s == Some(1), "{d:?}");
        let t = Instant::now();
        m.thaw();
        assert!(wait_until(Duration::from_secs(4), || m.live() == 0).await);
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(2), "the whole grace after thaw: {took:?}");
    }

    #[tokio::test]
    async fn the_newest_attachment_wins_and_the_old_one_hears_superseded_once() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c1 = Client::new(&m, 1);
        let mut c2 = Client::new(&m, 2);
        let (id, _) = start(&m, 1, req(&["sh", "-c", "read line; echo got-$line"])).await;
        let point = ResumePoint { spawn_id: id.clone(), from_seq: None, err_from_seq: None };
        assert_eq!(m.attach(2, &[point]), [Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }]);
        assert!(m.status(Some(1))[0].attached && !m.status(Some(2))[0].attached, "attached elsewhere, as seen from each");
        assert_eq!(m.stdin(1, &id, 1, b"x\n".to_vec()), Err(ErrorCode::NotAttached));
        m.connection_lost(1);
        assert_eq!(m.detail()[0].detach_left_s, None, "the old connection's late loss does not detach the new one");
        m.stdin(2, &id, 1, b"x\n".to_vec()).unwrap();
        m.stdin_eof(2, &id, 1).unwrap();
        assert!(c2.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(c2.out, b"got-x\n");
        c1.take();
        assert!(matches!(c1.other.as_slice(), [Frame::Error { code: ErrorCode::Superseded, spawn_id: Some(s), .. }] if *s == id), "{:?}", c1.other);
        assert!(c1.out.is_empty() && c1.exit.is_none(), "nothing more for the superseded spawn");
        let unknown = ResumePoint { spawn_id: SpawnId::new_v7(), from_seq: None, err_from_seq: None };
        assert_eq!(m.attach(3, std::slice::from_ref(&unknown)), [Resumed { spawn_id: unknown.spawn_id, status: ResumeStatus::Unknown }]);
    }

    #[tokio::test]
    async fn a_reattach_from_a_trimmed_seq_is_a_gap() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let (id, _) = start(&m, 1, req(&["sh", "-c", "echo one; read x; echo two"])).await;
        assert!(c.until(WAIT, |c| c.out == b"one\n").await);
        let gap = ResumePoint { spawn_id: id.clone(), from_seq: Some(1), err_from_seq: None };
        assert_eq!(m.attach(2, &[gap]), [Resumed { spawn_id: id.clone(), status: ResumeStatus::Gap }]);
        assert!(!m.status(Some(1))[0].attached, "a gap does not take the spawn");
        let next = ResumePoint { spawn_id: id.clone(), from_seq: Some(2), err_from_seq: None };
        assert_eq!(m.attach(2, &[next]), [Resumed { spawn_id: id, status: ResumeStatus::Ok }]);
    }

    #[tokio::test]
    async fn full_window_then_kill_9_replays_everything_then_the_exit() {
        const WINDOW: u64 = 16 * 1024;
        let home = tempfile::tempdir().unwrap();
        let m = SpawnManager::new(opts(home.path(), WINDOW));
        let (id, pid) = start(&m, 1, req(&["head", "-c", "50000000", "/dev/zero"])).await;
        assert!(wait_until(WAIT, || m.status(None)[0].out_seq > 0).await);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(m.status(None)[0].alive, "blocked on the full window");
        m.connection_lost(1);
        // SAFETY: the spawn's own leader, alive and unreaped.
        unsafe { libc::kill(libc::pid_t::try_from(pid).unwrap(), libc::SIGKILL) };
        assert!(wait_until(WAIT, || !m.status(None)[0].alive).await);
        let mut c = Client::new(&m, 2);
        let point = ResumePoint { spawn_id: id.clone(), from_seq: Some(1), err_from_seq: None };
        assert_eq!(m.attach(2, &[point]), [Resumed { spawn_id: id, status: ResumeStatus::Ok }]);
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert!(c.out.len() as u64 > WINDOW, "the pipe was drained past the window: {} bytes", c.out.len());
        assert!(c.out.iter().all(|b| *b == 0));
        assert_eq!(c.out_seqs, (1..=c.out_seq()).collect::<Vec<_>>());
        let (seq, info, _, truncated) = c.exited();
        assert_eq!((seq, info, truncated), (c.out_seq() + 1, ExitInfo { code: None, signal: Some(9) }, false), "exit 137 after the replay, nothing truncated");
    }

    #[tokio::test]
    async fn the_group_dies_with_its_leader_and_no_zombie_is_left() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let (_, leader) = start(&m, 1, req(&["sh", "-c", "sleep 30 & echo $!; exit 0"])).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await, "the background sleep holds stdout until the group TERM");
        let (_, info, _, truncated) = c.exited();
        assert_eq!((info.code, truncated), (Some(0), false));
        let sleeper: u32 = String::from_utf8_lossy(&c.out).trim().parse().unwrap();
        assert!(wait_until(Duration::from_secs(5), || gone(sleeper) && gone(leader)).await, "the sleep died with the group and the leader was reaped");
    }

    /// The group gets TERM the moment its leader dies, KILL only
    /// GROUP_KILL_AFTER later: a member that traps TERM runs its trap (a
    /// KILL could not be trapped). The leader waits on stdin, so it dies
    /// when the test says, never while the member's trap is being set.
    #[tokio::test]
    async fn a_dead_leaders_group_gets_term_at_once() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let member = "trap 'echo got-term; exit 0' TERM; echo ready; while :; do sleep 0.05; done";
        let (id, _) = start(&m, 1, req(&["sh", "-c", &format!("sh -c \"{member}\" & read -r line; exit 0")])).await;
        assert!(c.until(WAIT, |c| c.out == b"ready\n").await, "the member's trap is set");
        m.stdin(1, &id, 1, b"go\n".to_vec()).unwrap();
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(String::from_utf8_lossy(&c.out), "ready\ngot-term\n", "TERM reached the group when the leader died");
        let (_, info, _, truncated) = c.exited();
        assert_eq!((info.code, truncated), (Some(0), false));
    }

    /// `/health/detail`'s `group_alive` (S7 D6) asks the group, not the
    /// leader: a member that ignores TERM keeps it true once its leader has
    /// died (`alive` false), until the group's KILL; then it reads false.
    #[tokio::test]
    async fn group_alive_outlives_the_leader_until_the_groups_kill() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let member = "trap '' TERM; echo ready; while :; do sleep 0.05; done";
        let (id, _) = start(&m, 1, req(&["sh", "-c", &format!("sh -c \"{member}\" & read -r line; exit 0")])).await;
        assert!(c.until(WAIT, |c| c.out == b"ready\n").await, "the member's trap is set");
        let d = m.detail();
        assert!(d[0].status.alive && d[0].group_alive, "{d:?}");
        m.stdin(1, &id, 1, b"go\n".to_vec()).unwrap();
        let mut first_dead = None;
        assert!(
            wait_until(WAIT, || {
                first_dead = m.detail().into_iter().next().filter(|d| !d.status.alive);
                first_dead.is_some()
            })
            .await,
            "the leader exits"
        );
        let d = first_dead.unwrap();
        assert!(d.group_alive, "the member ignored the group's TERM: the group outlives its leader: {d:?}");
        assert!(wait_until(Duration::from_secs(5), || m.detail().first().is_none_or(|d| !d.group_alive)).await, "the group's KILL ended it");
    }

    /// F15: `credential_holders` counts a spawn handed a secret while its
    /// leader lives and, once the leader died, while a process of its group
    /// lives on (here a member that ignores the group's TERM until its KILL):
    /// that process may hold the secret, as `/health/detail`'s `group_alive`
    /// says. After the group's KILL it counts no more. The secret is built at
    /// run time.
    #[tokio::test]
    async fn a_dead_leaders_live_group_still_counts_as_a_holder() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let member = "trap '' TERM; echo ready; while :; do sleep 0.05; done";
        let mut r = req(&["sh", "-c", &format!("sh -c \"{member}\" & read -r line; exit 0")]);
        r.secrets.insert("X".into(), Secret::new(format!("{}-{}", "dummy", "value-of-the-holders-test")));
        let (id, _) = start(&m, 1, r).await;
        assert!(c.until(WAIT, |c| c.out == b"ready\n").await, "the member's trap is set");
        assert_eq!(m.credential_holders(), 1, "its leader lives");
        m.stdin(1, &id, 1, b"go\n".to_vec()).unwrap();
        let mut seen = None;
        assert!(
            wait_until(WAIT, || {
                seen = m.detail().into_iter().next().filter(|d| !d.status.alive).map(|d| (d.group_alive, m.credential_holders()));
                seen.is_some()
            })
            .await,
            "the leader exits"
        );
        assert_eq!(seen, Some((true, 1)), "the leader died, its group lives on: still a holder");
        assert!(wait_until(Duration::from_secs(5), || m.credential_holders() == 0).await, "the group's KILL ended it: no holder left");
    }

    /// A leader's watcher acts only on its own record. The id is registered
    /// again (here by forgetting it, as the single-use memory does past
    /// [`USED_IDS_MAX`]) while the first leader's watcher still waits out
    /// its group's KILL (1 s) and its pipes' drain (2 s): the new spawn is
    /// never marked reaped (no signal would reach it), and its pipes are
    /// read to the end.
    #[tokio::test]
    async fn a_watcher_never_touches_a_newer_record_under_its_id() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let (id, first) = start(&m, 1, req(&["true"])).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        m.ack(1, &id, c.exited().0, 0).unwrap();
        assert!(m.status(None).is_empty(), "released: its exit was collected");
        m.inner.lock().used = UsedIds::default();
        let mut again = req(&["sh", "-c", "sleep 2.5; echo late"]);
        again.spawn_id = id.clone();
        let mut d = Client::new(&m, 2);
        let (_, second) = start(&m, 2, again).await;
        assert_ne!(first, second);
        // Past the first watcher's KILL step, 1 s after `true` died.
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(!m.inner.lock().spawns[&id].reaped, "the first leader's watcher marked the new spawn reaped");
        // Past its drain deadline too (2 s): the new spawn's stdout is still read.
        assert!(d.until(WAIT, |c| c.exit.is_some()).await);
        let (_, info, _, truncated) = d.exited();
        assert_eq!((info, truncated), (ExitInfo { code: Some(0), signal: None }, false));
        assert_eq!(d.out, b"late\n");
    }

    /// stdout has priority on the socket: a stderr chunk produced first and a
    /// stdout chunk after it, both pending, come out stdout first.
    #[tokio::test]
    async fn the_outbox_sends_stdout_before_stderr() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut ob = m.outbox(1);
        start(&m, 1, req(&["sh", "-c", "echo err >&2; sleep 0.3; echo out; sleep 5"])).await;
        assert!(wait_until(WAIT, || m.status(None).first().is_some_and(|s| s.out_seq >= 1 && s.err_seq >= 1)).await);
        let first = std::iter::from_fn(|| ob.try_next()).find(|f| matches!(f, Frame::Stdout { .. } | Frame::Stderr { .. }));
        assert!(matches!(first, Some(Frame::Stdout { .. })), "{first:?}");
        m.shutdown("test").await;
    }

    #[tokio::test]
    async fn an_escaper_holding_stdout_ends_the_drain_with_stdout_truncated() {
        // Leave the group: setsid(1) on Linux, perl's setpgrp on the Mac.
        let escape = if Path::new("/usr/bin/setsid").exists() {
            "/usr/bin/setsid sleep 20"
        } else if Path::new("/usr/bin/perl").exists() {
            "/usr/bin/perl -e 'setpgrp(0, 0); sleep 20'"
        } else {
            eprintln!("neither setsid nor perl to escape the group with: skipped");
            return;
        };
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        start(&m, 1, req(&["sh", "-c", &format!("{escape} & sleep 0.5; echo $!")])).await;
        assert!(c.until(WAIT, |c| !c.out.is_empty()).await);
        let t = Instant::now();
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        let escaper: u32 = String::from_utf8_lossy(&c.out).trim().parse().unwrap();
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(1500) && took < Duration::from_secs(4), "{took:?}");
        let (_, info, _, truncated) = c.exited();
        assert_eq!((info.code, truncated), (Some(0), true));
        // SAFETY: the escaper this test started.
        unsafe { libc::kill(libc::pid_t::try_from(escaper).unwrap(), libc::SIGKILL) };
    }

    /// As root on Linux (the image; skipped elsewhere): the child is uid and
    /// gid 1000 with no other group, under NO_NEW_PRIVS; its working
    /// directory is made by the agent (owned 1000, 0700), so a parent only
    /// root may enter refuses it; and the last exit sweeps a setsid escaper
    /// that keeps forking, with everything it forked during the sweep.
    #[tokio::test]
    async fn as_root_the_agent_is_1000_without_new_privs_and_makes_its_own_cwd() {
        use std::os::unix::fs::MetadataExt;
        if !cfg!(target_os = "linux") || !nix::unistd::geteuid().is_root() {
            eprintln!("needs root on Linux (the image): skipped");
            return;
        }
        let _sweeps = SWEEPS.lock().await;
        let home = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(home.path(), Some(1000), Some(1000)).unwrap();
        let m = SpawnManager::new(SpawnOpts { uid: Some(1000), gid: Some(1000), sweep: true, ..opts(home.path(), STDOUT_WINDOW_BYTES) });
        let cwd = home.path().join("made/by/agent");
        let mut r = req(&["sh", "-c", "id -u; id -g; id -G; grep NoNewPrivs /proc/self/status; pwd"]);
        r.cwd = Some(cwd.to_str().unwrap().to_string());
        let mut c = Client::new(&m, 1);
        start(&m, 1, r).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(String::from_utf8_lossy(&c.out), format!("1000\n1000\n1000\nNoNewPrivs:\t1\n{}\n", cwd.display()));
        for rel in ["made", "made/by", "made/by/agent"] {
            let md = std::fs::metadata(home.path().join(rel)).unwrap();
            assert_eq!((md.uid(), md.gid(), md.mode() & 0o777), (1000, 1000, 0o700), "{rel}");
        }
        // That exit's own sweep (nothing to kill) comes GROUP_KILL_AFTER later: once it is
        // done, the escaper's is the only sweep, and a straggler cannot be left to a later one.
        let sweeps = || LOG.lock().unwrap().iter().filter(|l| l.starts_with("ai-env: idle sweep: ")).cloned().collect::<Vec<_>>();
        assert!(wait_until(Duration::from_secs(3), || sweeps().len() == 1).await, "{:?}", sweeps());
        let locked = tempfile::tempdir().unwrap();
        let mut r = req(&["pwd"]);
        r.cwd = Some(locked.path().join("x").to_str().unwrap().to_string());
        let (code, message) = refused(&m, r).await;
        assert_eq!(code, SpawnErrCode::Cwd, "root could make it, the agent cannot: {message}");
        assert!(message.contains("Permission denied"), "{message}");
        assert!(!locked.path().join("x").exists());
        let mut e = Client::new(&m, 2);
        let forker = "setsid sh -c 'while :; do sleep 30 & sleep 0.001; done' </dev/null >/dev/null 2>&1 & sleep 0.5; echo $!";
        start(&m, 2, req(&["sh", "-c", forker])).await;
        assert!(e.until(WAIT, |c| c.exit.is_some()).await);
        let escaper: u32 = String::from_utf8_lossy(&e.out).trim().parse().unwrap();
        assert!(wait_until(Duration::from_secs(5), || gone(escaper)).await, "the idle sweep killed the escaper");
        assert!(wait_until(Duration::from_secs(2), || sweeps().len() == 2).await, "{:?}", sweeps());
        let killed: usize = sweeps()[1].strip_prefix("ai-env: idle sweep: ").and_then(|r| r.split(' ').next()).and_then(|n| n.parse().ok()).unwrap();
        assert!(killed > 1, "the escaper and what it forked, in one line: {:?}", sweeps());
        let agent = || crate::shim::sys::pids_of_uid(Path::new("/proc"), 1000);
        assert!(wait_until(Duration::from_secs(2), || agent().is_empty()).await, "forked during a scan and left alive: {:?}", agent());
    }

    #[tokio::test]
    async fn the_working_directory_is_made_and_entered_as_the_agent() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let cwd = home.path().join("a/b/c");
        let mut r = req(&["pwd"]);
        r.cwd = Some(cwd.to_str().unwrap().to_string());
        let mut c = Client::new(&m, 1);
        start(&m, 1, r).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(String::from_utf8_lossy(&c.out).trim_end(), std::fs::canonicalize(&cwd).unwrap().to_str().unwrap());
        for rel in ["a", "a/b", "a/b/c"] {
            assert_eq!(std::fs::metadata(home.path().join(rel)).unwrap().permissions().mode() & 0o777, 0o700, "{rel}");
        }
        let mut d = Client::new(&m, 2);
        start(&m, 2, req(&["pwd"])).await;
        assert!(d.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(String::from_utf8_lossy(&d.out).trim_end(), std::fs::canonicalize(home.path()).unwrap().to_str().unwrap(), "the default is HOME");
        let base = home.path().to_str().unwrap();
        for bad in [format!("{base}/a/../b"), format!("{base}/./a"), "relative/dir".to_string(), format!("/{}", "x".repeat(CWD_MAX_BYTES))] {
            let mut r = req(&["pwd"]);
            r.cwd = Some(bad.clone());
            let (code, _) = refused(&m, r).await;
            assert_eq!(code, SpawnErrCode::Cwd, "{bad:.60}");
        }
        std::fs::write(home.path().join("file"), "").unwrap();
        let mut r = req(&["pwd"]);
        r.cwd = Some(format!("{base}/file/x"));
        let (code, message) = refused(&m, r).await;
        assert_eq!(code, SpawnErrCode::Cwd, "refused in the child: {message}");
        assert!(message.contains("Not a directory"), "{message}");
        assert!(!home.path().join("file/x").exists());
    }

    #[tokio::test]
    async fn a_secret_arrives_on_fd_3_or_in_env_and_never_in_a_log_line() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let dummy = format!("{}-{}", "dummy", "value-of-the-test-secret");
        let mut r = req(&["sh", "-c", "cat <&3; echo; echo $X_FILE_DESCRIPTOR"]);
        r.secrets.insert("X".into(), Secret::new(dummy.clone()));
        assert!(!format!("{r:?}").contains(&dummy));
        let mut c = Client::new(&m, 1);
        let (id, _) = start(&m, 1, r).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(String::from_utf8_lossy(&c.out), format!("{dummy}\n3\n"));
        let mut r = req(&["sh", "-c", "echo \"$X\""]);
        r.deliver = Deliver::Env;
        r.secrets.insert("X".into(), Secret::new(dummy.clone()));
        let mut e = Client::new(&m, 2);
        start(&m, 2, r).await;
        assert!(e.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(String::from_utf8_lossy(&e.out), format!("{dummy}\n"));
        let log = LOG.lock().unwrap().join("\n");
        assert!(log.contains(&format!("ai-env: spawn {id} pid=")) && log.contains("secret=fd3"), "{log}");
        assert!(!log.contains(&dummy), "{log}");
    }

    #[tokio::test]
    async fn the_child_holds_only_fds_0_to_2_and_3_with_a_secret() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        // An fd this process holds WITHOUT close-on-exec: the child must not get it.
        // SAFETY: dup of our own stderr; closed below.
        let leaked = unsafe { libc::dup(2) };
        assert!(leaked > 3 && leaked < 1024, "{leaked}");
        let probe = format!("for fd in {}; do [ -e /dev/fd/$fd ] && echo $fd; done; true", (0..=leaked.max(63)).map(|i| i.to_string()).collect::<Vec<_>>().join(" "));
        let mut plain = Client::new(&m, 1);
        start(&m, 1, req(&["sh", "-c", &probe])).await;
        assert!(plain.until(WAIT, |c| c.exit.is_some()).await);
        let mut r = req(&["sh", "-c", &probe]);
        r.secrets.insert("S".into(), Secret::new("x".repeat(16)));
        let mut with = Client::new(&m, 2);
        start(&m, 2, r).await;
        assert!(with.until(WAIT, |c| c.exit.is_some()).await);
        // SAFETY: the fd dup'ed above.
        unsafe { libc::close(leaked) };
        assert_eq!(String::from_utf8_lossy(&plain.out), "0\n1\n2\n");
        assert_eq!(String::from_utf8_lossy(&with.out), "0\n1\n2\n3\n");
    }

    #[tokio::test]
    async fn a_signal_frame_reaches_the_group() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let (id, _) = start(&m, 1, req(&["sleep", "100"])).await;
        assert_eq!(m.signal(2, &id, Sig::Term), Err(ErrorCode::NotAttached));
        m.signal(1, &id, Sig::Term).unwrap();
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(c.exited().1, ExitInfo { code: None, signal: Some(15) });
    }

    /// A signal frame reaches every process of the group, not only its
    /// leader. The leader ignores TERM (`trap '' TERM`, set once its
    /// background job was started, so the job keeps TERM's default action),
    /// waits for the job, then on stdin: it outlives the TERM frame, so its
    /// death, whose group TERM would end the job as well, cannot stand in for
    /// the frame. Within 3 s of a TERM frame the job is dead (the leader's
    /// `wait` says 143: TERM) while the leader still runs; a KILL frame then
    /// ends the leader (exit signal 9) and nothing is left running.
    #[tokio::test]
    async fn a_term_frame_reaches_a_member_while_the_leader_ignores_it() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let (id, leader) = start(&m, 1, req(&["sh", "-c", "sleep 100 & trap '' TERM; echo $!; wait $!; echo $?; read -r line"])).await;
        assert!(c.until(WAIT, |c| c.out.ends_with(b"\n")).await, "the job started and the leader's trap is set");
        let job: u32 = String::from_utf8_lossy(&c.out).trim().parse().unwrap();
        m.signal(1, &id, Sig::Term).unwrap();
        let ended = c.until(Duration::from_secs(3), |c| c.out.iter().filter(|b| **b == b'\n').count() == 2).await;
        assert!(ended, "the job {job} outlived the TERM frame by 3 s: stdout {:?}", String::from_utf8_lossy(&c.out));
        assert_eq!(String::from_utf8_lossy(&c.out), format!("{job}\n143\n"), "the leader's wait: the job died of the TERM");
        assert!(gone(job), "the leader reaped the job");
        let s = &m.status(None)[0];
        assert!(s.alive && c.exit.is_none() && !gone(leader), "the leader ignores TERM and runs on: {s:?}");
        m.signal(1, &id, Sig::Kill).unwrap();
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(c.exited().1, ExitInfo { code: None, signal: Some(9) }, "the leader ran on until the KILL frame");
        assert!(wait_until(Duration::from_secs(5), || gone(leader)).await, "the KILL frame ended the group: its leader was reaped");
    }

    /// A signal the shim ignores is not ignored by its spawns: SIGUSR2,
    /// ignored in this process for the test, still kills the child.
    #[tokio::test]
    async fn an_ignored_signal_is_reset_for_the_child() {
        // SAFETY: SIG_IGN for SIGUSR2, which no other test of this binary uses; restored below.
        let old = unsafe { libc::signal(libc::SIGUSR2, libc::SIG_IGN) };
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let (_, _) = start(&m, 1, req(&["sh", "-c", "kill -USR2 $$; echo survived"])).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        // SAFETY: restores the disposition saved above.
        unsafe { libc::signal(libc::SIGUSR2, old) };
        assert_eq!(c.exited().1, ExitInfo { code: None, signal: Some(libc::SIGUSR2) }, "stdout: {:?}", String::from_utf8_lossy(&c.out));
    }

    #[tokio::test]
    async fn two_spawns_share_one_outbox() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut c = Client::new(&m, 1);
        let (a, _) = start(&m, 1, req(&["sh", "-c", "head -c 300000 /dev/zero"])).await;
        let (b, _) = start(&m, 1, req(&["sh", "-c", "head -c 300000 /dev/zero"])).await;
        let mut exits = Vec::new();
        let end = Instant::now() + WAIT;
        while exits.len() < 2 && Instant::now() < end {
            while let Some(f) = c.ob.try_next() {
                match f {
                    Frame::Stdout { spawn_id, seq, .. } => m.ack(1, &spawn_id, seq, 0).unwrap(),
                    Frame::Exit { spawn_id, .. } => exits.push(spawn_id),
                    _ => {}
                }
            }
            let _ = tokio::time::timeout(Duration::from_millis(100), c.ob.changed()).await;
        }
        exits.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(exits, want);
    }

    #[tokio::test]
    async fn shutdown_kills_every_group_then_refuses_spawns() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut leaders = Vec::new();
        for _ in 0..3 {
            leaders.push(start(&m, 1, req(&["sh", "-c", "sleep 100 & sleep 100"])).await.1);
        }
        let t = Instant::now();
        m.shutdown("test").await;
        assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
        assert_eq!(m.live(), 0);
        assert_eq!(refused(&m, req(&["true"])).await.0, SpawnErrCode::Draining);
        assert!(wait_until(Duration::from_secs(3), || leaders.iter().all(|p| gone(*p))).await);
        let mut ob = m.outbox(9);
        assert!(tokio::time::timeout(Duration::from_millis(200), ob.changed()).await.is_err(), "an outbox never wakes after shutdown");
    }

    /// `terminate` gives the leaders 5 s after its TERM: one that traps TERM
    /// and needs 4.5 s exits on its own (0), and only the one that ignores
    /// TERM is KILLed, at 5 s — not the trapper's group, which its exited
    /// leader pins until its own KILL at 5.5 s. The stop ladder KILLs the
    /// trapping leader 3 s after its TERM.
    #[tokio::test]
    async fn terminate_gives_the_leaders_5_s_and_stop_kills_at_3_s() {
        let trapper = ["sh", "-c", "trap 'sleep 4.5; exit 0' TERM; echo ready; while :; do sleep 0.1; done"];
        let deaf = ["sh", "-c", "trap '' TERM; echo ready; while :; do sleep 0.1; done"];
        let home = tempfile::tempdir().unwrap();
        let (terminated, stopped) = (manager(home.path()), manager(home.path()));
        let (mut a, mut b) = (Client::new(&terminated, 1), Client::new(&stopped, 1));
        let (slow, _) = start(&terminated, 1, req(&trapper)).await;
        let (ignores, _) = start(&terminated, 1, req(&deaf)).await;
        start(&stopped, 1, req(&trapper)).await;
        assert!(a.until(WAIT, |c| c.out == b"ready\nready\n").await && b.until(WAIT, |c| c.out == b"ready\n").await, "every trap is set before the TERM");
        let t = Instant::now();
        let (took_terminate, took_stop) = tokio::join!(
            async {
                terminated.terminate().await;
                t.elapsed()
            },
            async {
                stopped.shutdown("test").await;
                t.elapsed()
            }
        );
        let exit = |m: &SpawnManager, id: Option<&SpawnId>| m.status(None).into_iter().find(|s| id.is_none_or(|id| s.spawn_id == *id)).and_then(|s| s.exit);
        assert_eq!(exit(&terminated, Some(&slow)), Some(ExitInfo { code: Some(0), signal: None }), "the trap ran to its end");
        assert_eq!(exit(&terminated, Some(&ignores)), Some(ExitInfo { code: None, signal: Some(9) }));
        assert!(took_terminate >= Duration::from_millis(4900) && took_terminate < Duration::from_secs(6), "{took_terminate:?}");
        assert_eq!(exit(&stopped, None), Some(ExitInfo { code: None, signal: Some(9) }), "KILLed in its trap");
        assert!(took_stop >= Duration::from_millis(2900) && took_stop < Duration::from_secs(4), "{took_stop:?}");
        let log = LOG.lock().unwrap().join("\n");
        assert!(log.contains("ai-env: spawns stopped (terminate): KILL to 1 group(s), 0 still running"), "{log}");
    }

    /// S11 (A §2.5): more than `CLAUDE_REFS_MAX` refs, a ref that fails its
    /// check, or one sha256 twice is `bad_request` naming `claude`, before
    /// anything starts; a request naming good refs starts.
    #[tokio::test]
    async fn a_spawn_with_too_many_or_bad_refs_is_bad_request() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let r = |n: u8| ClaudeRef { version: format!("2.1.{n}"), sha256: format!("{n:02x}").repeat(32) };
        let with = |refs: Vec<ClaudeRef>| {
            let mut q = req(&["true"]);
            q.claude = refs;
            q
        };
        let bad_sha = ClaudeRef { version: "2.1.1".into(), sha256: "AB".repeat(32) };
        let bad_version = ClaudeRef { version: "2.1".into(), sha256: "ab".repeat(32) };
        let twice = ClaudeRef { version: "2.1.9".into(), sha256: r(1).sha256 };
        let too_many: Vec<ClaudeRef> = (1..=u8::try_from(CLAUDE_REFS_MAX).unwrap() + 1).map(r).collect();
        for (refs, needle) in [(too_many, "claude names 5 refs (at most 4)"), (vec![r(1), bad_sha], "claude ref 1 "), (vec![bad_version], "claude ref 0 "), (vec![r(1), twice], "claude ref 1 names a sha256 an earlier ref names")] {
            let (code, message) = refused(&m, with(refs)).await;
            assert_eq!(code, SpawnErrCode::BadRequest, "{message}");
            assert!(message.contains(needle), "{needle}: {message}");
        }
        let good = with((1..=u8::try_from(CLAUDE_REFS_MAX).unwrap()).map(r).collect());
        let id = good.spawn_id.clone();
        assert!(matches!(m.spawn(1, good).await, Frame::Spawned { spawn_id, claude_version: None, claude_sha256: None, .. } if spawn_id == id), "four good refs start; nothing was picked");
    }

    #[tokio::test]
    async fn bad_requests_are_refused_by_name_and_never_echo_values() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let with = |f: &dyn Fn(&mut SpawnRequest)| {
            let mut r = req(&["true", "argument-text"]);
            f(&mut r);
            r
        };
        let cases: Vec<(SpawnRequest, SpawnErrCode, &str)> = vec![
            (with(&|r| r.spawn_id = SpawnId("not-a-uuid".into())), SpawnErrCode::BadRequest, "uuid v7"),
            (with(&|r| r.argv.clear()), SpawnErrCode::BadRequest, "argv[0]"),
            (with(&|r| r.argv = vec!["x".repeat(ARGV_MAX_BYTES)]), SpawnErrCode::BadRequest, "bytes (at most"),
            (with(&|r| r.argv.push("a\0b".into())), SpawnErrCode::BadRequest, "NUL"),
            (with(&|r| _ = r.env.insert("1X".into(), "env-value-text".into())), SpawnErrCode::BadRequest, "is not [A-Za-z_]"),
            // The names the shim sets, written out (not RESERVED_ENV): a frame's env replaces none.
            (with(&|r| _ = r.env.insert("HOME".into(), "env-value-text".into())), SpawnErrCode::BadRequest, "HOME is set by the shim"),
            (with(&|r| _ = r.env.insert("PATH".into(), "env-value-text".into())), SpawnErrCode::BadRequest, "PATH is set by the shim"),
            (with(&|r| _ = r.env.insert("CLAUDE_CONFIG_DIR".into(), "env-value-text".into())), SpawnErrCode::BadRequest, "CLAUDE_CONFIG_DIR is set by the shim"),
            (with(&|r| _ = r.env.insert("V".into(), "env\0value-text".into())), SpawnErrCode::BadRequest, "NUL"),
            (with(&|r| r.env = (0..=ENV_MAX_ENTRIES).map(|i| (format!("V{i}"), "env-value-text".to_string())).collect()), SpawnErrCode::BadRequest, "entries"),
            (
                with(&|r| {
                    r.secrets.insert("A".into(), Secret::new("secret-value-text".into()));
                    r.secrets.insert("B".into(), Secret::new("secret-value-text".into()));
                }),
                SpawnErrCode::BadRequest,
                "at most one",
            ),
            (with(&|r| _ = r.secrets.insert("A".into(), Secret::new("s".repeat(SECRET_FD_MAX_BYTES + 1)))), SpawnErrCode::BadRequest, "on fd 3"),
            (
                with(&|r| {
                    r.secrets.insert("A".into(), Secret::new("secret-value-text".into()));
                    r.env.insert("A_FILE_DESCRIPTOR".into(), "7".into());
                }),
                SpawnErrCode::BadRequest,
                "set by the secret",
            ),
            (with(&|r| r.argv = vec!["no-such-program-for-ai-env-tests".into()]), SpawnErrCode::NotFound, "not found on PATH"),
            (with(&|r| r.argv = vec!["claude".into()]), SpawnErrCode::NotFound, "/nonexistent/claude"),
        ];
        for (r, want, needle) in cases {
            let (code, message) = refused(&m, r).await;
            assert_eq!(code, want, "{message}");
            assert!(message.contains(needle) || (needle == "/nonexistent/claude" && message.contains("cannot start claude")), "{needle}: {message}");
            for hidden in ["argument-text", "env-value-text", "secret-value-text"] {
                assert!(!message.contains(hidden), "{message}");
            }
        }
        let script = home.path().join("not-executable");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();
        let (code, message) = refused(&m, req(&[script.to_str().unwrap()])).await;
        assert_eq!(code, SpawnErrCode::Exec, "{message}");
        assert!(message.contains("Permission denied"), "{message}");
        let log = LOG.lock().unwrap().join("\n");
        for hidden in ["argument-text", "env-value-text", "secret-value-text"] {
            assert!(!log.contains(hidden), "{hidden} in the log");
        }
        assert_eq!(m.live(), 0);
    }

    #[tokio::test]
    async fn ids_are_unique_and_live_spawns_are_capped() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let first = req(&["sleep", "100"]);
        let again = SpawnRequest { argv: vec!["true".into()], ..first.clone() };
        start(&m, 1, first).await;
        assert_eq!(refused(&m, again).await.0, SpawnErrCode::Exists);
        for _ in 1..MAX_SPAWNS {
            start(&m, 1, req(&["sleep", "100"])).await;
        }
        assert_eq!(m.live(), MAX_SPAWNS);
        assert_eq!(refused(&m, req(&["true"])).await.0, SpawnErrCode::Limit);
        m.shutdown("test").await;
        assert_eq!(m.live(), 0);
    }

    /// A spawn id is single-use: once the grace released a spawn whose
    /// `spawned` the Mac never read (it finished meanwhile), a resume finds
    /// nothing (`unknown`), and the same `spawn` sent again is refused
    /// `exists`: the command ran once.
    #[tokio::test]
    async fn a_released_spawn_id_is_never_started_again() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut r = req(&["sh", "-c", "echo ran >> \"$HOME/runs\""]);
        r.detach_grace_s = Some(1);
        let (id, _) = start(&m, 1, r.clone()).await;
        m.connection_lost(1);
        assert!(wait_until(Duration::from_secs(5), || m.status(None).is_empty()).await, "released when the grace ran out");
        let point = ResumePoint { spawn_id: id.clone(), from_seq: Some(1), err_from_seq: Some(1) };
        assert_eq!(m.attach(2, &[point]), [Resumed { spawn_id: id.clone(), status: ResumeStatus::Unknown }]);
        let (code, message) = refused(&m, r).await;
        assert_eq!((code, message), (SpawnErrCode::Exists, format!("spawn {id} already ran on this VM: not starting it again")));
        assert_eq!(std::fs::read_to_string(home.path().join("runs")).unwrap(), "ran\n", "the command ran once");
        assert!(m.status(None).is_empty());
    }

    #[test]
    fn the_used_ids_forget_the_oldest_past_the_cap() {
        let mut used = UsedIds::default();
        let ids: Vec<SpawnId> = (0..=USED_IDS_MAX).map(|_| SpawnId::new_v7()).collect();
        for id in &ids {
            used.insert(id.clone());
        }
        used.insert(ids[1].clone());
        assert!(!used.contains(&ids[0]), "the oldest went");
        assert!(ids[1..].iter().all(|id| used.contains(id)));
        assert_eq!((used.order.len(), used.set.len()), (USED_IDS_MAX, USED_IDS_MAX), "an id kept once");
    }

    #[tokio::test]
    async fn stdin_beyond_the_window_overflows() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let (id, _) = start(&m, 1, req(&["sleep", "100"])).await;
        let chunk = vec![b'x'; CHUNK_MAX];
        let mut seq = 0;
        let fits = STDIN_WINDOW_BYTES / CHUNK_MAX as u64 + 2;
        let mut refused = None;
        while seq < fits && refused.is_none() {
            seq += 1;
            refused = m.stdin(1, &id, seq, chunk.clone()).err();
        }
        assert_eq!(refused, Some(ErrorCode::StdinOverflow), "sleep never reads: at most the window is held ({seq} chunks)");
        m.shutdown("test").await;
    }

    #[test]
    fn a_grace_freezes_thaws_and_extends() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut g = Grace::new(s(10), false, t0);
        assert_eq!(g.deadline(), Some(t0 + s(10)));
        g.freeze(t0 + s(4));
        assert_eq!((g.deadline(), g.remaining(t0 + s(100))), (None, s(6)), "frozen: 6 s left, however long");
        assert!(!g.extend(t0 + s(100), s(30)));
        assert_eq!(g.remaining(t0 + s(100)), s(6), "a frozen grace is not extended");
        g.thaw(t0 + s(50));
        g.thaw(t0 + s(51));
        assert_eq!(g.deadline(), Some(t0 + s(56)), "the first thaw counts");
        assert!(!g.extend(t0 + s(49), s(30)), "thawed after the clock last looked: it did not run through the gap");
        assert_eq!(g.deadline(), Some(t0 + s(56)));
        assert!(g.extend(t0 + s(50), s(30)));
        assert_eq!(g.deadline(), Some(t0 + s(86)), "the jump guard pushes a grace that ran through the gap");
        assert_eq!(Grace::new(s(5), true, t0).deadline(), None, "a grace started while suspended is frozen");
    }

    /// S7: a wake after a gap the clock did not see drops the cached
    /// credential (a suspend without `/suspend`); an ordinary wake keeps it.
    #[test]
    fn the_jump_guard_drops_the_cached_credential() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        m.credential().put("A_TOKEN", Secret::new("dummy-value".into()), None).unwrap();
        let last = Instant::now();
        m.inner.woke(last, last + JUMP);
        assert!(m.credential().has(), "a gap of JUMP is not a jump");
        m.inner.woke(last, last + JUMP + Duration::from_millis(1));
        assert!(!m.credential().has(), "dropped on the jump");
    }

    /// The clock's wake after a gap it did not see (more than JUMP; the
    /// instants are made up, so nothing waits): a grace running when the
    /// clock last looked gets the unseen time back; one whose socket loss was
    /// noticed after the gap, or one `/resume` thawed before the clock woke,
    /// keeps exactly what it had.
    #[tokio::test]
    async fn the_jump_guard_gives_time_back_only_to_graces_that_ran_through_the_gap() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut ids = Vec::new();
        for conn in 1..=3 {
            let mut r = req(&["sleep", "100"]);
            r.detach_grace_s = Some(60);
            ids.push(start(&m, conn, r).await.0);
        }
        let left = |id: &SpawnId, at: Instant| match m.inner.lock().spawns[id].ending {
            Ending::Grace(g) => g.remaining(at),
            other => panic!("{other:?}"),
        };
        let gap = JUMP + Duration::from_secs(5);
        // Suspended without /suspend: the clock last looked after the first loss, the second is noticed after the gap.
        m.connection_lost(1);
        let last = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        m.connection_lost(2);
        let at = Instant::now();
        let before = [left(&ids[0], at), left(&ids[1], at)];
        m.inner.woke(last, last + gap);
        assert_eq!(left(&ids[0], at), before[0] + gap - TICK, "running through the gap: the unseen time comes back");
        assert_eq!(left(&ids[1], at), before[1], "started after the clock last looked: nothing to give back");
        // /suspend froze every grace, the monotonic clock leapt, and /resume came before the clock woke.
        m.freeze();
        m.connection_lost(3);
        let last = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        m.thaw();
        let at = Instant::now();
        let before: Vec<Duration> = ids.iter().map(|id| left(id, at)).collect();
        m.inner.woke(last, last + gap);
        assert_eq!(ids.iter().map(|id| left(id, at)).collect::<Vec<_>>(), before, "thawed after the clock last looked: the suspend is not added");
        assert_eq!(m.live(), 3, "no grace ran out");
        assert!(LOG.lock().unwrap().iter().any(|l| l == "ai-env: spawns: 14 s passed unseen (suspended without /suspend?): 1 detach grace(s) extended"));
    }

    /// The clock task itself runs the jump guard (real time, no paused
    /// clock): the test blocks its runtime's only thread for more than JUMP
    /// while a 5 s grace runs, as a VM suspended without `/suspend` stops
    /// every task. The clock's first wake after it finds the jump, and the
    /// grace that ran through it gets the unseen time but one TICK back:
    /// about 4 s left, not run out.
    #[tokio::test(flavor = "current_thread")]
    async fn the_clock_task_gives_an_unseen_jump_back_to_a_running_grace() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut r = req(&["sleep", "100"]);
        r.detach_grace_s = Some(5);
        let (id, _) = start(&m, 1, r).await;
        m.connection_lost(1);
        // The clock looks once after the loss (it was woken), then sees nothing for JUMP + 2 s.
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::thread::sleep(JUMP + Duration::from_secs(2));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let ending = m.inner.lock().spawns.get(&id).map(|s| s.ending);
        let left = match ending {
            Some(Ending::Grace(g)) => g.remaining(Instant::now()),
            other => panic!("the jump was not given back: {other:?}"),
        };
        assert!(left > Duration::from_secs(2) && left <= Duration::from_secs(4), "{left:?}");
        assert_eq!(m.live(), 1);
    }

    /// S7: the clock starts with the first hello (`attach`), not the first
    /// spawn, so its jump guard drops a credential cached on a VM that never
    /// spawned (what `vm warm` leaves). Real time, as above: the test blocks
    /// its runtime's only thread for more than JUMP after the delivery.
    #[tokio::test(flavor = "current_thread")]
    async fn the_jump_guard_drops_a_credential_cached_before_any_spawn() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        assert!(m.attach(1, &[]).is_empty(), "a hello resuming nothing");
        let value = format!("dummy-before-any-spawn-{}", std::process::id());
        m.credential().put("A_TOKEN", Secret::new(value.clone()), None).unwrap();
        // The clock looks once, then sees nothing for JUMP + 2 s.
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::thread::sleep(JUMP + Duration::from_secs(2));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(m.live(), 0, "no spawn ran");
        assert!(!m.credential().has(), "the jump guard dropped the copy");
        assert!(!LOG.lock().unwrap().iter().any(|l| l.contains(&value)), "a logged line holds the value");
    }

    /// A grace longer than JUMP runs out on time: the clock wakes every
    /// TICK, so it never takes its own sleep for a jump (one that slept
    /// straight to an 11 s deadline would give the grace 10 s back).
    #[tokio::test]
    async fn a_grace_longer_than_the_jump_runs_out_on_time() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut r = req(&["sleep", "100"]);
        r.detach_grace_s = Some(11);
        start(&m, 1, r).await;
        let t = Instant::now();
        m.connection_lost(1);
        assert!(wait_until(Duration::from_secs(14), || m.live() == 0).await, "the 11 s grace ran out within 14 s");
        assert!(t.elapsed() >= Duration::from_millis(10900), "{:?}", t.elapsed());
    }

    /// The sweep re-checks each pid through its pidfd before signalling it:
    /// a pid whose status no longer shows the agent's uid (reused by another
    /// process since the scan) or shows a zombie is left alone; one still
    /// running as the uid is killed. A fake `/proc` entry stands for the
    /// reuse; the pid is a real child of this test. Linux only (pidfds): the
    /// Mac gate never runs it, nor does `make test-docker` (no unit-test
    /// step); it needs the lib's unit tests cross-built and run in the base
    /// image, as the S6 mutation check (M5a) ran it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_sweep_kills_only_a_pid_still_running_as_the_uid() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let uid = nix::unistd::getuid().as_raw();
        let proc = tempfile::tempdir().unwrap();
        let dir = proc.path().join(pid.to_string());
        std::fs::create_dir(&dir).unwrap();
        let status = |state: &str, u: u32| format!("Name:\tsleep\nState:\t{state}\nUid:\t{u}\t{u}\t{u}\t{u}\n");
        for (state, u, what) in [("S (sleeping)", uid.wrapping_add(1), "another uid"), ("Z (zombie)", uid, "a zombie")] {
            std::fs::write(dir.join("status"), status(state, u)).unwrap();
            assert!(!kill_still_running_as(proc.path(), pid, uid), "{what}: not signalled");
        }
        std::thread::sleep(Duration::from_millis(200));
        assert!(child.try_wait().unwrap().is_none(), "nothing was signalled");
        std::fs::write(dir.join("status"), status("S (sleeping)", uid)).unwrap();
        assert!(kill_still_running_as(proc.path(), pid, uid), "still running as the uid: killed");
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    }

    /// The idle sweep scans again until a scan finds nothing: what a forker
    /// made between a scan and its own kill is in the next scan; a forker
    /// that never runs out still ends at the bound.
    #[test]
    fn the_sweep_scans_until_nothing_is_left() {
        use std::cell::{Cell, RefCell};
        // 10 forks 30 and 31 just before it dies; 31 forks 40 likewise.
        let table = RefCell::new(std::collections::BTreeSet::from([10u32, 11, 20]));
        let forks = HashMap::from([(10u32, vec![30u32, 31]), (31, vec![40])]);
        let scan = || table.borrow().iter().copied().collect::<Vec<u32>>();
        let kill = |pid: u32| {
            let mut t = table.borrow_mut();
            t.extend(forks.get(&pid).into_iter().flatten());
            t.remove(&pid)
        };
        assert_eq!(sweep_passes(scan, kill), (6, 4), "10, 11 and 20; 30 and 31; 40; then a scan that finds nothing");
        assert!(table.borrow().is_empty(), "{:?}", table.borrow());
        let next = Cell::new(100u32);
        let endless = sweep_passes(
            || vec![next.get()],
            |pid| {
                next.set(pid + 1);
                true
            },
        );
        assert_eq!(endless, (SWEEP_PASSES, SWEEP_PASSES), "bounded");
        assert_eq!(sweep_passes(Vec::new, |_| panic!("nothing to kill")), (0, 1));
    }

    /// Client text reaches a log line or a message escaped: a newline in a
    /// spawn id, argv[0] or a working directory never starts a line of its
    /// own (the runbook reads `peer_uid`/`ino` lines).
    #[tokio::test]
    async fn client_text_never_forges_a_log_line() {
        let forged = "\nai-env: hook run peer_uid=0 ino=4242 st=admitted";
        let escaped = "\\nai-env: hook run peer_uid=0 ino=4242 st=admitted";
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let mut bad_id = req(&["true"]);
        bad_id.spawn_id = SpawnId(format!("x{forged}"));
        assert!(!format!("{bad_id:?}").contains('\n'));
        assert_eq!(refused(&m, bad_id.clone()).await.0, SpawnErrCode::BadRequest);
        for argv0 in [format!("nope{forged}"), format!("/nonexistent/x{forged}")] {
            assert!(!format!("{:?}", req(&[&argv0])).contains('\n'));
            let (code, message) = refused(&m, req(&[&argv0])).await;
            assert_eq!(code, SpawnErrCode::NotFound, "{message}");
            assert!(!message.contains('\n') && message.contains(escaped), "{message}");
        }
        // A program and a working directory whose names hold the line: the spawn starts, and its line stays one line.
        let program = home.path().join(format!("prog{forged}"));
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut r = req(&[program.to_str().unwrap()]);
        r.cwd = Some(home.path().join(format!("dir{forged}")).to_str().unwrap().to_string());
        let mut c = Client::new(&m, 1);
        start(&m, 1, r).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(c.exited().1.code, Some(0));
        assert_eq!(m.status(None)[0].argv0, format!("prog{escaped}"));
        let stopped = manager(home.path());
        stopped.shutdown("test").await;
        assert_eq!(refused(&stopped, bad_id).await.0, SpawnErrCode::Draining, "refused before the id is checked");
        let log = LOG.lock().unwrap();
        let lines: Vec<&String> = log.iter().filter(|l| l.contains("ai-env: hook run peer_uid=0")).collect();
        assert_eq!(lines.len(), 5, "two bad ids, two programs not started, one spawn: {lines:?}");
        for l in lines {
            assert!(!l.contains(['\n', '\r']) && l.contains(escaped), "{l}");
        }
    }

    #[test]
    fn round_robin_starts_after_the_last_served() {
        let ids: Vec<SpawnId> = ["a", "b", "c"].iter().map(|s| SpawnId((*s).to_string())).collect();
        let order = |last: Option<&str>| {
            let last = last.map(|l| SpawnId(l.to_string()));
            round_robin(&ids, last.as_ref()).map(|i| i.0.clone()).collect::<Vec<_>>()
        };
        assert_eq!(order(None), ["a", "b", "c"]);
        assert_eq!(order(Some("a")), ["b", "c", "a"]);
        assert_eq!(order(Some("c")), ["a", "b", "c"]);
        assert_eq!(order(Some("bb")), ["c", "a", "b"], "a released spawn: the next one after it");
    }

    #[test]
    fn a_request_debug_shows_no_argument_value_or_secret() {
        let mut r = req(&["/usr/local/bin/claude", "-p", "the prompt text"]);
        r.env.insert("FOO".into(), "env-value-text".into());
        r.secrets.insert("TOKEN_NAME".into(), Secret::new("secret-value-text".into()));
        r.cwd = Some("/Users/mike/private-dir".into());
        let d = format!("{r:?}");
        for hidden in ["the prompt text", "-p", "env-value-text", "secret-value-text", "private-dir", "FOO", "TOKEN_NAME"] {
            assert!(!d.contains(hidden), "{hidden}: {d}");
        }
        assert!(d.contains("argv0=claude") && d.contains("argc=3") && d.contains("env=1") && d.contains("secrets=1"), "{d}");
    }

    #[test]
    fn programs_resolve_like_a_shell_but_claude() {
        assert_eq!(resolve("claude", Path::new("/opt/c"), None).unwrap(), PathBuf::from("/opt/c"));
        // S11: a picked (cached) binary wins for `claude`, and only for it.
        let picked = Path::new("/opt/ai-env/claude/abc/claude");
        assert_eq!(resolve("claude", Path::new("/opt/c"), Some(picked)).unwrap(), picked);
        assert_eq!(resolve("./x", Path::new("/opt/c"), Some(picked)).unwrap(), PathBuf::from("./x"));
        assert_eq!(child_path(Some(picked)), std::ffi::OsString::from("/opt/ai-env/claude/abc:/usr/local/bin:/usr/bin:/bin"), "the cached binary's directory leads");
        assert_eq!(child_path(None), std::ffi::OsString::from(CHILD_PATH));
        assert_eq!(resolve("./x", Path::new("/opt/c"), None).unwrap(), PathBuf::from("./x"));
        assert!(resolve("sh", Path::new("/opt/c"), None).unwrap().starts_with("/"), "found on the child PATH");
        assert!(resolve("no-such-program-for-ai-env-tests", Path::new("/opt/c"), None).unwrap_err().contains("not found on PATH=/usr/local/bin:/usr/bin:/bin"));
    }

    /// S8: a workspace helper holds off the idle sweep. With a hold alive, a
    /// spawn's end logs the sweep held off and sweeps nothing; dropping the
    /// last hold runs the sweep that was due. The uid is one nothing runs
    /// as, so a sweep here kills nothing (and off Linux it scans nothing).
    #[tokio::test]
    async fn a_helper_holds_off_the_idle_sweep_until_it_ends() {
        let _sweeps = SWEEPS.lock().await;
        let swept = || LOG.lock().unwrap().iter().filter(|l| l.starts_with("ai-env: idle sweep: ")).count();
        let held_off = || LOG.lock().unwrap().iter().filter(|l| l.starts_with("ai-env: idle sweep held off: ")).count();
        let home = tempfile::tempdir().unwrap();
        let m = SpawnManager::new(SpawnOpts { sweep: true, agent_uid: 3_999_999_999, ..opts(home.path(), STDOUT_WINDOW_BYTES) });
        let hold = m.hold_helper(false).await.expect("a hold while running");
        assert_eq!((m.helpers(), m.live()), (1, 0), "a helper is no spawn");
        let (before, off) = (swept(), held_off());
        let mut c = Client::new(&m, 1);
        start(&m, 1, req(&["true"])).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert!(wait_until(Duration::from_secs(4), || held_off() > off).await, "the spawn's end found a helper");
        assert_eq!(swept(), before, "no sweep while the helper lives");
        drop(hold);
        assert!(wait_until(Duration::from_secs(4), || swept() > before).await, "the last hold ran the sweep that was due");
        assert_eq!(m.helpers(), 0);
        let again = m.hold_helper(false).await.expect("a hold");
        let before = swept();
        drop(again);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(swept(), before, "no sweep was due: none runs");
    }

    /// A stop TERMs every helper group it was told of (the owner reaps it:
    /// exit observed, group cleared, then reaped), and afterwards only a
    /// helper started during the stop is held.
    #[tokio::test]
    async fn a_stop_ends_the_helper_groups_and_refuses_new_helpers() {
        use std::os::unix::process::CommandExt;
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let hold = m.hold_helper(false).await.expect("a hold");
        let mut child = {
            let _fork = crate::test_locks::forking();
            std::process::Command::new("sleep").arg("100").process_group(0).spawn().unwrap()
        };
        let pid = child.id();
        hold.set_group(pid);
        let owner = tokio::spawn(async move {
            let p = libc::pid_t::try_from(pid).unwrap();
            tokio::task::spawn_blocking(move || wait_exited(p)).await.unwrap();
            hold.clear_group();
            child.wait().unwrap()
        });
        let t = Instant::now();
        m.shutdown("test").await;
        let status = tokio::time::timeout(WAIT, owner).await.unwrap().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM), "the stop's TERM reached the helper's group");
        assert!(t.elapsed() < Duration::from_secs(3), "no KILL step was needed: {:?}", t.elapsed());
        assert!(m.hold_helper(false).await.is_none(), "stopping: no new helper");
        let during = m.hold_helper(true).await.expect("a helper the stop itself starts");
        assert_eq!(m.helpers(), 1);
        drop(during);
        let log = LOG.lock().unwrap().join("\n");
        assert!(log.contains("ai-env: spawns stopping (test): TERM to 0 group(s) and 1 workspace helper(s)"), "{log}");
    }

    /// Helpers are no spawns: with helpers held, MAX_SPAWNS spawns still
    /// start, and with that many running a helper is still held.
    #[tokio::test]
    async fn helpers_never_count_toward_the_spawn_limit() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let first = m.hold_helper(false).await.expect("a hold");
        for _ in 0..MAX_SPAWNS {
            start(&m, 1, req(&["sleep", "100"])).await;
        }
        assert_eq!(refused(&m, req(&["true"])).await.0, SpawnErrCode::Limit, "the limit is the spawns'");
        let second = m.hold_helper(false).await.expect("a helper beside MAX_SPAWNS spawns");
        assert_eq!((m.live(), m.helpers()), (MAX_SPAWNS, 2));
        drop((first, second));
        m.shutdown("test").await;
    }

    /// The spawn's working directory is a VM path: with an fs root it is
    /// entered (and made) under it, as every VM path is.
    #[tokio::test]
    async fn a_spawn_cwd_is_entered_under_the_fs_root() {
        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let m = SpawnManager::new(SpawnOpts { fs_root: Some(root.clone()), ..opts(&root, STDOUT_WINDOW_BYTES) });
        let mut r = req(&["pwd"]);
        r.cwd = Some("/Users/agent/ws".into());
        let mut c = Client::new(&m, 1);
        start(&m, 1, r).await;
        assert!(c.until(WAIT, |c| c.exit.is_some()).await);
        assert_eq!(String::from_utf8_lossy(&c.out).trim_end(), root.join("Users/agent/ws").to_str().unwrap());
        let mut bad = req(&["pwd"]);
        bad.cwd = Some("/Users/../x".into());
        assert_eq!(refused(&m, bad).await.0, SpawnErrCode::Cwd, "the VM path's own rules first");
    }

    // ---- S10: the park ----

    /// A bare record (S10's busy check): pid 0 and `reaped` signal no one.
    fn bare_spawn() -> Spawn {
        Spawn {
            argv0: "x".into(),
            holds_secret: false,
            claude_sha256: None,
            pid: 0,
            started_at: String::new(),
            grace: Duration::ZERO,
            attached: None,
            ending: Ending::Attached,
            cursor: Cursor { out: 1, err: 1, exit_sent: false },
            out: OutWindow::default(),
            err: ErrBuffer::new(STDERR_BUFFER_BYTES),
            stdin: StdinQueue::new(STDIN_WINDOW_BYTES),
            stdin_acked: 0,
            stdin_closed: false,
            stdin_broken: false,
            leader: None,
            reaped: true,
            out_done: false,
            err_done: false,
            truncated: false,
            exit: None,
            due: Vec::new(),
            credit: Arc::new(Notify::new()),
            ready: Arc::new(Notify::new()),
            drained: Arc::new(Notify::new()),
            readers: Vec::new(),
            writer: None,
            park: None,
            last_io: Instant::now(),
            activity: Activity::default(),
        }
    }

    /// The park's busy check in its order: `other` (a grace of 0 or past
    /// the max, a window past an hour, a leader gone) before `unacked`
    /// (stdout or stdin) before `output` (stdio within the window) before
    /// `busy` (a sample within it over the CPU threshold, or one that saw a
    /// process but the leader running); a sample older than the window
    /// counts for nothing; the busiest's CPU is named whatever the verdict.
    #[test]
    fn the_park_check_refuses_in_its_order() {
        let ask = ParkAsk { grace_s: 600, min_quiet_s: 30, cpu_busy_ms: 500, hold_output: false, owner: ParkOwner { pid: 7, started: 8 } };
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let now = at(4000);
        let mut s = bare_spawn();
        s.last_io = t0;
        assert_eq!(s.park_check(&s.activity, &ask, now), (None, 0), "quiet, nothing sampled");
        for bad in [ParkAsk { grace_s: 0, ..ask }, ParkAsk { grace_s: PARK_GRACE_MAX_S + 1, ..ask }, ParkAsk { min_quiet_s: 3601, ..ask }] {
            assert_eq!(s.park_check(&s.activity, &bad, now).0, Some(ParkRefusal::Other), "{bad:?}");
        }
        assert_eq!(s.park_check(&s.activity, &ParkAsk { grace_s: PARK_GRACE_MAX_S, min_quiet_s: 3600, ..ask }, now).0, None, "the limits themselves");
        s.activity.record(at(3980), &SessionNow { cpu_ms: Some(600), running: 0, procs: 0 });
        assert_eq!(s.park_check(&s.activity, &ask, now), (Some(ParkRefusal::Busy), 600), "600 ms in a sample 20 s ago");
        assert_eq!(s.park_check(&s.activity, &ParkAsk { min_quiet_s: 10, ..ask }, now), (None, 0), "older than the window");
        s.activity.record(at(3995), &SessionNow { cpu_ms: Some(700), running: 1, procs: 1 });
        assert_eq!(s.park_check(&s.activity, &ParkAsk { min_quiet_s: 10, ..ask }, now), (Some(ParkRefusal::Busy), 100), "a process but the leader running");
        s.last_io = at(3995);
        assert_eq!(s.park_check(&s.activity, &ask, now), (Some(ParkRefusal::Output), 600), "stdio 5 s ago, before busy");
        s.stdin.offer(1, b"x".to_vec()).unwrap();
        assert_eq!(s.park_check(&s.activity, &ask, now).0, Some(ParkRefusal::Unacked), "stdin not acked, before output");
        s.stdin_acked = 1;
        s.out.push(crate::wire::frame::Chunk { text: Some("y".into()), b64: None });
        assert_eq!(s.park_check(&s.activity, &ask, now).0, Some(ParkRefusal::Unacked), "stdout not acked");
        s.leader = Some(ExitInfo { code: Some(0), signal: None });
        assert_eq!(s.park_check(&s.activity, &ask, now).0, Some(ParkRefusal::Other), "a leader gone, before all");
    }

    /// The busy check's samples: each the session's CPU since the one
    /// before (never below 0), the window inclusive, an hour of them kept; a
    /// look without CPU (native macOS) adds none.
    #[test]
    fn the_activity_keeps_an_hour_of_samples_and_takes_deltas() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let look = |cpu: u64, running: u32| SessionNow { cpu_ms: Some(cpu), running, procs: running };
        let mut a = Activity::default();
        a.record(t0, &look(250, 0));
        a.record(at(10), &look(1250, 0));
        a.record(at(20), &look(1200, 0));
        assert_eq!(a.samples.iter().map(|s| s.cpu_ms).collect::<Vec<_>>(), [250, 1000, 0], "the CPU since the last; a lower total is 0");
        assert_eq!(a.busy(at(20), Duration::from_secs(10), 500), (true, 1000), "the sample 10 s back is within");
        assert_eq!(a.busy(at(21), Duration::from_secs(10), 500), (false, 0));
        a.record(at(20), &SessionNow { cpu_ms: None, running: 3, procs: 3 });
        assert_eq!(a.samples.len(), 3, "no CPU read: no sample");
        a.record(at(3611), &look(1300, 0));
        assert_eq!(a.samples.iter().map(|s| s.cpu_ms).collect::<Vec<_>>(), [0, 100], "an hour of them kept");
    }

    /// `/proc/<pid>/stat` as the busy check reads it: the state and the
    /// session past the last `)` (a `comm` may hold spaces and
    /// parentheses), the CPU as utime, stime, cutime and cstime; a text cut
    /// short is none, a negative children's count is 0.
    #[test]
    fn a_proc_stat_line_gives_its_state_session_and_cpu() {
        let line = "4242 (my (odd) name) S 1 4242 4242 0 -1 4194304 100 0 0 0 7 3 2 1 20 0 1 0 100 1000 100";
        assert_eq!(parse_stat(line), Some(StatLine { state: 'S', session: 4242, cpu_ticks: 13 }));
        assert_eq!(parse_stat("7 (sh) R 1 7 4242 0 -1 0 0 0 0 0 5 5"), None, "cut before cutime");
        assert_eq!(parse_stat("no parenthesis"), None);
        assert_eq!(parse_stat("9 (x) Z 1 9 4242 0 -1 0 0 0 0 0 0 0 -1 0").map(|l| (l.state, l.cpu_ticks)), Some(('Z', 0)));
    }

    /// One pass over a (planted) `/proc` counts each leader's session: the
    /// CPU of all its processes (a zombie's too) in ms at the clock's ticks,
    /// its processes but the leader alive, and those running (R or D);
    /// another session's process counts for nothing, and a leader whose own
    /// stat is not there is missing. A `comm` that is not UTF-8 still counts.
    #[test]
    fn a_sample_counts_a_sessions_cpu_and_its_running_processes() {
        let t = tempfile::tempdir().unwrap();
        let stat = |pid: u32, state: char, session: u32, utime: u64| format!("{pid} (p {pid}) {state} 1 {session} {session} 0 -1 0 0 0 0 0 {utime} 0 0 0 20 0 1 0");
        let planted = [(100, 'S', 100, 50), (101, 'R', 100, 30), (102, 'D', 100, 10), (103, 'Z', 100, 10), (104, 'S', 100, 0), (200, 'R', 200, 5), (300, 'R', 999, 7)];
        for (pid, state, session, utime) in planted {
            std::fs::create_dir_all(t.path().join(pid.to_string())).unwrap();
            std::fs::write(t.path().join(format!("{pid}/stat")), stat(pid, state, session, utime)).unwrap();
        }
        std::fs::create_dir_all(t.path().join("105")).unwrap();
        std::fs::write(t.path().join("105/stat"), b"105 (\xff\xfe) S 1 100 100 0 -1 0 0 0 0 0 20 0 0 0 20 0 1 0").unwrap();
        std::fs::create_dir_all(t.path().join("self")).unwrap();
        let looks = sample_sessions(t.path(), &[100, 200, 400], 100, None);
        assert_eq!(looks.get(&100), Some(&SessionNow { cpu_ms: Some(1200), running: 2, procs: 4 }));
        assert_eq!(looks.get(&200), Some(&SessionNow { cpu_ms: Some(50), running: 0, procs: 0 }), "the leader is neither");
        assert_eq!(looks.get(&400), None, "a leader whose stat is not there");
        assert!(sample_sessions(&t.path().join("absent"), &[100], 100, None).is_empty());
    }

    /// S10 V-6: with the agent's uid, its escapers count in every leader's
    /// look: a process of that uid in no leader's session and no helper's
    /// (300, running: a backgrounded build that called setsid) adds its CPU
    /// and its running; one asleep adds its CPU only; a helper's session, a
    /// zombie and another uid's process add nothing; `procs` stays the session's.
    #[test]
    fn the_agents_escapers_count_in_every_look() {
        let t = tempfile::tempdir().unwrap();
        let stat = |pid: u32, state: char, session: u32, utime: u64| format!("{pid} (p {pid}) {state} 1 {session} {session} 0 -1 0 0 0 0 0 {utime} 0 0 0 20 0 1 0");
        let status = |state: char, uid: u32| format!("Name:\tp\nState:\t{state} (x)\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n");
        let planted = [(100, 'S', 100, 50, 1000), (101, 'S', 100, 10, 1000), (200, 'S', 200, 5, 1000), (300, 'R', 300, 70, 1000), (301, 'S', 300, 30, 1000), (310, 'Z', 310, 40, 1000), (500, 'R', 500, 90, 1000), (600, 'R', 600, 80, 0)];
        for (pid, state, session, utime, uid) in planted {
            std::fs::create_dir_all(t.path().join(pid.to_string())).unwrap();
            std::fs::write(t.path().join(format!("{pid}/stat")), stat(pid, state, session, utime)).unwrap();
            std::fs::write(t.path().join(format!("{pid}/status")), status(state, uid)).unwrap();
        }
        let looks = sample_sessions(t.path(), &[100, 200], 100, Some((1000, &[500])));
        assert_eq!(looks.get(&100), Some(&SessionNow { cpu_ms: Some(600 + 1000), running: 1, procs: 1 }), "300 and 301 escaped; 310 is a zombie, 500 a helper's, 600 root's");
        assert_eq!(looks.get(&200), Some(&SessionNow { cpu_ms: Some(50 + 1000), running: 1, procs: 0 }), "every leader's look");
        assert_eq!(sample_sessions(t.path(), &[100], 100, None).get(&100), Some(&SessionNow { cpu_ms: Some(600), running: 0, procs: 1 }), "without the agent's uid, the session alone");
        // BUSY-1: a session left out of `leaders` is an escaper's, so every look passes every live leader.
        let alone = sample_sessions(t.path(), &[100], 100, Some((1000, &[500])));
        assert_eq!(alone.get(&100), Some(&SessionNow { cpu_ms: Some(600 + 1000 + 50), running: 1, procs: 1 }), "200's session, not passed, counts as escaped");
    }

    /// S10 V-6: what every look of the busy check counts beyond the sessions
    /// is the agent's, and only where the shim sweeps (Linux and root:
    /// `sweep`) and the agent is not root: its uid, with the groups of the
    /// workspace helpers forked by then (a hold not forked yet names none).
    /// Otherwise none (native runs: the test's own uid runs everything else).
    #[tokio::test]
    async fn the_busy_check_counts_the_agents_escapers_only_where_it_sweeps() {
        let home = tempfile::tempdir().unwrap();
        let agent = 3_999_999_999;
        let m = SpawnManager::new(SpawnOpts { sweep: true, agent_uid: agent, ..opts(home.path(), STDOUT_WINDOW_BYTES) });
        assert_eq!(m.inner.escapers(), Some((agent, vec![])));
        let hold = m.hold_helper(false).await.expect("a hold");
        assert_eq!(m.inner.escapers(), Some((agent, vec![])), "a helper not forked yet leads no group");
        // Past every pid_max (Linux's 4 194 304, macOS's 99 998): no process's group; no stop signals it here.
        hold.set_group(4_194_305);
        assert_eq!(m.inner.escapers(), Some((agent, vec![4_194_305])), "a forked helper's group is its own");
        hold.clear_group();
        drop(hold);
        for off in [SpawnOpts { sweep: false, ..m.opts().clone() }, SpawnOpts { agent_uid: 0, ..m.opts().clone() }] {
            assert_eq!(SpawnManager::new(off.clone()).inner.escapers(), None, "sweep {}, agent uid {}", off.sweep, off.agent_uid);
        }
    }

    /// S10 V-6 (BUSY-1) as root on Linux (the image; skipped elsewhere), the
    /// shim sweeping as it does there, under a uid of this test's alone (the
    /// other root tests' sweeps kill uid 1000's processes): two chats'
    /// spawns, each its own session. One whose session runs a busy loop
    /// (a process but the leader, running) is no escaper of the other's: the
    /// quiet one parks beside it, and its own park is refused `busy`. A busy
    /// loop of the agent's that left every spawn's session (setsid) is one:
    /// the quiet spawn's next park is refused `busy`.
    #[tokio::test]
    async fn as_root_a_busy_spawn_beside_is_no_escaper_but_a_setsid_one_is() {
        const AGENT: u32 = 61_000;
        if !cfg!(target_os = "linux") || !nix::unistd::geteuid().is_root() {
            eprintln!("needs root on Linux (the image): skipped");
            return;
        }
        let _sweeps = SWEEPS.lock().await;
        let swept = || LOG.lock().unwrap().iter().filter(|l| l.starts_with("ai-env: idle sweep: ")).count();
        let home = tempfile::tempdir().unwrap();
        std::os::unix::fs::chown(home.path(), Some(AGENT), Some(AGENT)).unwrap();
        let m = SpawnManager::new(SpawnOpts { uid: Some(AGENT), gid: Some(AGENT), agent_uid: AGENT, sweep: true, ..opts(home.path(), STDOUT_WINDOW_BYTES) });
        let ask = ParkAsk { grace_s: 600, min_quiet_s: 0, cpu_busy_ms: 300, hold_output: false, owner: ParkOwner { pid: 7, started: 8 } };
        let (busy, _) = start(&m, 2, req(&["sh", "-c", "sh -c 'while :; do :; done' & exec sleep 100"])).await;
        let (quiet, _) = start(&m, 1, req(&["sleep", "100"])).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let parked = m.park(1, &quiet, ask).await;
        assert!(matches!(parked, Frame::Parked { procs: 0, .. }), "a busy spawn beside is no escaper: {parked:?}");
        let own = m.park(2, &busy, ask).await;
        assert!(matches!(own, Frame::ParkRefused { reason: ParkRefusal::Busy, procs: 1, .. }), "its own loop runs: {own:?}");
        let mut e = Client::new(&m, 3);
        // The leader waits for the loop's setsid: its death TERMs its group.
        start(&m, 3, req(&["sh", "-c", "setsid sh -c 'while :; do :; done' </dev/null >/dev/null 2>&1 & sleep 0.5; echo $!"])).await;
        assert!(e.until(WAIT, |c| c.exit.is_some()).await);
        let escaper: u32 = String::from_utf8_lossy(&e.out).trim().parse().unwrap();
        let refused = m.park(1, &quiet, ask).await;
        // SAFETY: the escaper this test started.
        unsafe { libc::kill(libc::pid_t::try_from(escaper).unwrap(), libc::SIGKILL) };
        assert!(matches!(refused, Frame::ParkRefused { reason: ParkRefusal::Busy, procs: 0, .. }), "the setsid loop is the agent's escaper: {refused:?}");
        let before = swept();
        m.shutdown("test").await;
        // Its idle sweep, before the next test that counts them may start.
        assert!(wait_until(Duration::from_secs(5), || swept() > before).await, "the idle sweep after the last leader");
    }

    /// A parked spawn whose connection goes lives its park grace (not its
    /// 60 s detach grace), parked still; at its end TERM, logged as the
    /// park grace's, and its park goes. Another one, unparked by a frame for
    /// it (`stdin`), takes its detach grace when its connection goes.
    #[tokio::test]
    async fn a_lost_parked_connection_lives_its_park_grace_then_term() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let owner = ParkOwner { pid: 7, started: 8 };
        let ask = ParkAsk { grace_s: 1, min_quiet_s: 0, cpu_busy_ms: 500, hold_output: false, owner };
        let (id, _) = start(&m, 1, req(&["sleep", "100"])).await;
        assert!(matches!(m.park(1, &id, ask).await, Frame::Parked { ref spawn_id, procs: 0, .. } if *spawn_id == id));
        let t = Instant::now();
        m.connection_lost(1);
        let d = m.detail().into_iter().find(|d| d.status.spawn_id == id).unwrap();
        assert!(d.detach_left_s.is_some_and(|left| left <= 1) && d.parked == Some(owner), "{d:?}");
        let (other, _) = start(&m, 2, req(&["sleep", "100"])).await;
        assert!(matches!(m.park(2, &other, ask).await, Frame::Parked { .. }));
        m.stdin(2, &other, 1, b"x".to_vec()).unwrap();
        m.connection_lost(2);
        let d = m.detail().into_iter().find(|d| d.status.spawn_id == other).unwrap();
        assert!(d.detach_left_s.is_some_and(|left| left > 50) && d.parked.is_none(), "unparked by its stdin: the detach grace: {d:?}");
        assert!(wait_until(Duration::from_secs(4), || m.live() == 1).await);
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(2), "TERM after the 1 s park grace: {took:?}");
        let log = LOG.lock().unwrap().join("\n");
        assert!(log.contains(&format!("ai-env: spawn {id} lost connection 1: park grace 1 s")) && log.contains(&format!("ai-env: spawn {id} park grace over: TERM")), "{log}");
        assert!(log.contains(&format!("ai-env: spawn {other} unparked by stdin")), "{log}");
        m.shutdown("test").await;
    }

    /// A `park` refused to a spawn already parked ends its park (the answer
    /// says it is not parked): `/health/detail` names no owner, the log says
    /// why, and its lost connection takes its detach grace. Another
    /// socket's `park` (`not_attached`) leaves the park as it is.
    #[tokio::test]
    async fn a_park_refused_to_a_parked_spawn_ends_its_park() {
        let home = tempfile::tempdir().unwrap();
        let m = manager(home.path());
        let owner = ParkOwner { pid: 7, started: 8 };
        let ask = ParkAsk { grace_s: 600, min_quiet_s: 0, cpu_busy_ms: 500, hold_output: true, owner };
        let (id, _) = start(&m, 1, req(&["sleep", "100"])).await;
        let detail = || m.detail().into_iter().find(|d| d.status.spawn_id == id).unwrap();
        assert!(matches!(m.park(1, &id, ask).await, Frame::Parked { .. }));
        assert!(matches!(m.park(2, &id, ask).await, Frame::ParkRefused { reason: ParkRefusal::NotAttached, .. }));
        assert_eq!(detail().parked, Some(owner), "another socket's park changes nothing");
        assert!(matches!(m.park(1, &id, ParkAsk { grace_s: 0, ..ask }).await, Frame::ParkRefused { reason: ParkRefusal::Other, .. }));
        assert_eq!(detail().parked, None, "refused: parked no more");
        m.connection_lost(1);
        let d = detail();
        assert!(d.detach_left_s.is_some_and(|left| left > 50 && left <= 60), "the detach grace, not the park grace: {d:?}");
        let log = LOG.lock().unwrap().join("\n");
        assert!(log.contains(&format!("ai-env: spawn {id} unparked by a refused park")), "{log}");
        m.shutdown("test").await;
    }
}
