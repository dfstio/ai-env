//! The root shim's side of the workspace helper (S8 §6): it starts `ai-env
//! shim-io <op>` as the agent through `childproc`'s `pre_exec` path (setsid,
//! NO_NEW_PRIVS, the agent's uid and gid, its home entered as the agent),
//! holds the spawn manager's helper count (the idle sweep never runs while a
//! helper lives, and a stop ends its group), pipes the request body to its
//! stdin, reads its JSON head line, streams the payload, and ends its
//! process group past the operation's budget (TERM, then KILL
//! [`KILL_AFTER`] later; the helper is told the budget, `--budget-ms`, and
//! ends its own git runs before it). A run ends with what it left of its
//! session too: each git run leads a process group of its own (`gitrun`),
//! which a signal to the helper's group misses, so once the leader has
//! exited every process left in its session gets TERM, then KILL
//! [`KILL_AFTER`] later. The leader is reaped only after the last signal:
//! its zombie keeps its pid, the group's and the session's id, ours. The
//! root shim never touches a path the agent can write (invariant 17).
//!
//! A route whose helper changes the workspace runs it as a task of its own
//! ([`detached`]): a request is dropped when its client goes away, and a
//! helper dropped mid-op is killed before its own rollback ran.
//!
//! Also here: [`WorkspaceSlot`], the shim's one workspace (one per VM): the
//! last seed's record (in memory, so it survives a suspend; S10, W3 #2: and
//! in [`SEED_RECORD_PATH`], root's, so it survives a shim restart:
//! [`RecordStore`]), and the lock that serialises seed, code-out and
//! snapshot (a request waits at most `budget::BUSY_WAIT`, then 409 `busy`
//! with `Retry-After`); and the answers the routes give (`refused`, `answered`). S9's git CGI (`gitcgi`) takes no
//! lock, only one of its own two slots ([`WorkspaceSlot::try_cgi`]), and
//! reads its helper's output past the head as a CGI's
//! ([`AgentProc::read_cgi_head`], [`AgentProc::into_stream`]).
use crate::shim::childproc::{child_setup, cwd_parts, fd_walk_end, CWD_ERRNO_BASE};
use crate::shim::health::{ShimOpts, ShimState};
use crate::shim::spawn::{killpg, wait_exited, HelperHold};
use crate::wire::workspace::{budget, parse_head, read_head_line_async, refusal, head_line, HelperHead, SeedRecord, SnapshotReply, WorkspaceView, WsRefusal, HEAD_LINE_MAX};
use crate::wire::workspace::{GIT_CGI_HEADERS, GIT_CGI_HEAD_MAX, GIT_CGI_MAX};
use crate::wire::workspace::{branch_check, vm_path_check, JsonPayloadReply, JSON_PAYLOAD_MAX};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// What a body's transfer may take on top of an op's budget: this much,
/// plus the bytes at [`STREAM_RATE`] (the Mac's own floor,
/// `bridge::dataplane::request_timeout`).
pub const STREAM_BASE: Duration = Duration::from_secs(30);
/// Bytes per second a body is given at least.
pub const STREAM_RATE: u64 = 1_000_000;
/// After the budget's TERM: how long a helper's group has before KILL.
pub const KILL_AFTER: Duration = Duration::from_secs(2);
/// A body's run given up (its budget passed, the feed cut, so its stdin is
/// closed): how long the helper has to end by itself before TERM. Its EOF
/// path takes milliseconds and removes what it wrote (a seed's or a
/// transcript write's temp file); a helper that ends sooner is reaped at once.
pub const EOF_GRACE: Duration = Duration::from_millis(500);
/// A 409 `busy`'s `Retry-After`, in seconds.
pub const RETRY_AFTER_S: u64 = 5;
/// The tail of a helper's stderr kept for a failure's message.
const STDERR_KEEP: usize = 16 * 1024;
/// One read of a streamed payload.
const CHUNK: usize = 64 * 1024;
/// `PATH` of the helper (its git is the shim's `--git`, by path).
const HELPER_PATH: &str = crate::gitrun::VM_PATH;

/// One argument `--name=value`: a value starting with `-` (a transcript
/// rel's slug does) is never read as a flag of its own.
#[must_use]
pub fn flag(name: &str, value: impl AsRef<std::ffi::OsStr>) -> OsString {
    let mut arg = OsString::from(format!("--{name}="));
    arg.push(value.as_ref());
    arg
}

/// The time a body of `len` bytes may take to cross: [`STREAM_BASE`] plus
/// `len` at [`STREAM_RATE`].
#[must_use]
pub fn transfer(len: u64) -> Duration {
    STREAM_BASE + Duration::from_secs(len / STREAM_RATE)
}

/// One helper run: `<helper> shim-io --home=H [--fs-root=R] --git=G <op> <args…> --budget-ms=B`.
#[derive(Debug, Clone)]
pub struct AgentCmd {
    /// The op, one of `wshelper::OPS`.
    pub op: &'static str,
    /// The op's own flags.
    pub args: Vec<OsString>,
    /// Its budget, from its start (a body's transfer included).
    pub budget: Duration,
    /// stdin piped (a body, the haves), else `/dev/null`.
    pub stdin: bool,
    /// Started while the shim stops (the spawn manager refuses others then).
    pub during_stop: bool,
}

/// Why a helper gave no head, or failed after it.
#[derive(Debug)]
pub enum AgentProcError {
    /// The shim is stopping: no helper starts.
    Draining,
    /// The helper did not start (no program, a fork or exec failure).
    Spawn(String),
    /// It outlived its budget: its group was ended.
    Timeout,
    /// Its first line was no head.
    BadHead(String),
    /// It ended without a head, or non-zero after one: its code and its stderr's last line.
    Exit { code: Option<i32>, stderr: String },
}

impl AgentProcError {
    /// The refusal a route answers with: 503 `draining`, 504 `timeout`, else 500 `git_failed`.
    #[must_use]
    pub fn refusal(&self, op: &str) -> WsRefusal {
        match self {
            AgentProcError::Draining => WsRefusal::new(refusal::DRAINING, "the shim is stopping: nothing new starts"),
            AgentProcError::Spawn(e) => WsRefusal::new(refusal::GIT_FAILED, &format!("the workspace helper ({op}) did not start: {e}")),
            AgentProcError::Timeout => WsRefusal::new(refusal::TIMEOUT, &format!("{op} did not finish within its budget: the helper was ended")),
            AgentProcError::BadHead(e) => WsRefusal::new(refusal::GIT_FAILED, &format!("the workspace helper ({op}) answered no head: {e}")),
            AgentProcError::Exit { code, stderr } => {
                let code = code.map_or("a signal".to_string(), |c| format!("exit {c}"));
                WsRefusal::new(refusal::GIT_FAILED, &format!("the workspace helper ({op}) failed ({code}): {stderr}"))
            }
        }
    }
}

/// A running helper ([`AgentProc::start`]): its pipes, its group, its
/// hold, its deadline. Dropped before it was reaped, its group and what it
/// left of its session are killed.
pub struct AgentProc {
    child: Child,
    /// The leader's pid, its group id (setsid).
    pid: u32,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    hold: HelperHold,
    deadline: Instant,
    op: &'static str,
    /// Its exit, once reaped: from then on its pid may be anyone's, and it is never signalled again.
    status: Option<ExitStatus>,
}

impl AgentProc {
    /// Start `cmd` as the agent (module doc). The program is the shim's
    /// helper (`ShimOpts.helper`), its environment only `HOME`, `PATH` and
    /// `LC_ALL`, its fds 0 to 2 (every other close-on-exec).
    pub async fn start(state: &ShimState, cmd: AgentCmd) -> Result<AgentProc, AgentProcError> {
        let Some(program) = state.opts.helper.clone() else { return Err(AgentProcError::Spawn("this shim names no helper program".into())) };
        let hold = state.spawns.hold_helper(cmd.during_stop).await.ok_or(AgentProcError::Draining)?;
        let home = &state.opts.home;
        let cwd = cwd_parts(home.as_os_str().as_bytes()).map_err(|m| AgentProcError::Spawn(format!("the agent's home {m}")))?;
        let mut c = tokio::process::Command::new(&program);
        c.arg("shim-io").arg(flag("home", home));
        if let Some(root) = &state.opts.fs_root {
            c.arg(flag("fs-root", root));
        }
        c.arg(flag("git", &state.opts.git)).arg(cmd.op).args(&cmd.args);
        // The whole run's budget, as this side counts it: the helper's git runs end before it (`wshelper`).
        c.arg(flag("budget-ms", cmd.budget.as_millis().to_string()));
        c.env_clear().env("HOME", home).env("PATH", HELPER_PATH).env("LC_ALL", "C");
        c.stdin(if cmd.stdin { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
        let opts = state.spawns.opts();
        if let Some(gid) = opts.gid {
            c.gid(gid);
        }
        if let Some(uid) = opts.uid {
            c.uid(uid);
        }
        let fd_walk = fd_walk_end();
        // SAFETY: the closure runs in the forked child, after std applied the
        // stdio and the uid/gid, before exec; it makes only async-signal-safe
        // calls on data prepared here (no allocation, no lock).
        unsafe {
            c.pre_exec(move || child_setup(&cwd, None, fd_walk));
        }
        let spawned = {
            #[cfg(test)]
            let _fork = crate::test_locks::forking();
            c.spawn()
        };
        let mut child = spawned.map_err(|e| match e.raw_os_error() {
            Some(n) if n >= CWD_ERRNO_BASE => AgentProcError::Spawn(format!("cannot enter the agent's home: {}", io::Error::from_raw_os_error(n - CWD_ERRNO_BASE))),
            _ => AgentProcError::Spawn(format!("cannot start {}: {e}", program.display())),
        })?;
        let Some(pid) = child.id() else { return Err(AgentProcError::Spawn("the helper exited before it was registered".into())) };
        hold.set_group(pid);
        let (Some(stdout), stderr) = (child.stdout.take(), child.stderr.take()) else { return Err(AgentProcError::Spawn("the helper has no stdout".into())) };
        let stderr = stderr.map(|mut err| {
            tokio::spawn(async move {
                let mut tail = Vec::new();
                let mut buf = vec![0u8; 8192];
                while let Ok(n) = err.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    tail.extend_from_slice(&buf[..n]);
                    if tail.len() > STDERR_KEEP {
                        tail.drain(..tail.len() - STDERR_KEEP);
                    }
                }
                tail
            })
        });
        Ok(AgentProc { stdin: child.stdin.take(), child, pid, stdout: BufReader::new(stdout), stderr, hold, deadline: Instant::now() + cmd.budget, op: cmd.op, status: None })
    }

    /// The deadline: past it the group is ended.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Give the run `by` more (a payload's transfer).
    pub fn extend(&mut self, by: Duration) {
        self.deadline = Instant::now().max(self.deadline) + by;
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }

    /// The first stdout line, at most `HEAD_LINE_MAX`, as a head; within the
    /// deadline. A helper that ends without one is [`AgentProcError::Exit`].
    pub async fn head<T: DeserializeOwned>(&mut self) -> Result<HelperHead<T>, AgentProcError> {
        match tokio::time::timeout_at(self.deadline, read_head_line_async(&mut self.stdout, HEAD_LINE_MAX)).await {
            Err(_) => Err(AgentProcError::Timeout),
            Ok(Ok(line)) => parse_head(&line).map_err(AgentProcError::BadHead),
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                let status = self.reap().await?;
                Err(AgentProcError::Exit { code: status.code(), stderr: self.stderr_line().await })
            }
            Ok(Err(e)) => Err(AgentProcError::BadHead(e.to_string())),
        }
    }

    /// Close stdin, read the rest of stdout away, and wait for the exit
    /// within the deadline (else the group is ended): `Ok` on exit 0.
    pub async fn finish(mut self) -> Result<(), AgentProcError> {
        drop(self.stdin.take());
        let drained = tokio::time::timeout_at(self.deadline, tokio::io::copy(&mut self.stdout, &mut tokio::io::sink())).await;
        let status = self.reap().await?;
        if drained.is_err() {
            return Err(AgentProcError::Timeout);
        }
        if status.success() {
            return Ok(());
        }
        Err(AgentProcError::Exit { code: status.code(), stderr: self.stderr_line().await })
    }

    /// End the run now (TERM, then KILL) and reap it.
    pub async fn stop(mut self) {
        self.deadline = Instant::now();
        let _ = self.reap().await;
    }

    /// [`AgentProc::stop`] `grace` from now: reaped as soon as it ends by
    /// itself, else TERM, then KILL.
    pub async fn stop_after(mut self, grace: Duration) {
        self.deadline = Instant::now() + grace;
        let _ = self.reap().await;
    }

    /// Wait for the leader's exit without reaping it until the deadline;
    /// past it TERM its group, KILL [`KILL_AFTER`] later; then what it left
    /// of its session is ended ([`end_session`]), the group leaves the
    /// manager's view and the leader is reaped. A timeout is
    /// [`AgentProcError::Timeout`]. Once reaped, its exit is answered again
    /// and nothing is signalled.
    async fn reap(&mut self) -> Result<ExitStatus, AgentProcError> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let Ok(pid) = libc::pid_t::try_from(self.pid) else { return Err(AgentProcError::Spawn("a pid out of range".into())) };
        let mut exited = tokio::task::spawn_blocking(move || wait_exited(pid));
        let mut timed_out = false;
        if tokio::time::timeout_at(self.deadline, &mut exited).await.is_err() {
            timed_out = true;
            // The leader is unreaped (exited waits WNOWAIT): its group id is still ours.
            killpg(self.pid, libc::SIGTERM);
            if tokio::time::timeout(KILL_AFTER, &mut exited).await.is_err() {
                killpg(self.pid, libc::SIGKILL);
                let _ = exited.await;
            }
            errln!("ai-env: workspace helper {} pid={} outlived its budget: TERM, KILL", self.op, self.pid);
        }
        // The leader has exited, unreaped: its zombie keeps the session's id ours.
        let sid = self.pid;
        let left = tokio::task::spawn_blocking(move || end_session(sid)).await.unwrap_or(0);
        if left > 0 {
            errln!("ai-env: workspace helper {} pid={} left {left} process(es) in its session: TERM, KILL", self.op, self.pid);
        }
        self.hold.clear_group();
        let status = self.child.wait().await.map_err(|e| AgentProcError::Spawn(format!("cannot reap the helper: {e}")))?;
        self.status = Some(status);
        if timed_out {
            return Err(AgentProcError::Timeout);
        }
        Ok(status)
    }

    /// The last line of the helper's stderr (it closed: the helper ended), scrubbed, at most 200 characters.
    async fn stderr_line(&mut self) -> String {
        let tail = match self.stderr.take() {
            Some(t) => tokio::time::timeout(Duration::from_secs(1), t).await.ok().and_then(Result::ok).unwrap_or_default(),
            None => Vec::new(),
        };
        let text = String::from_utf8_lossy(&tail);
        let last = text.lines().rev().map(str::trim).find(|l| !l.is_empty()).unwrap_or("nothing on stderr");
        crate::wire::redact::scrub(last).chars().take(200).collect()
    }

    /// The payload after the head: `prefix`, then exactly `len` bytes of
    /// stdout, as a response body. A task of its own reads the helper
    /// ([`payload_pump`]) and hands the body each chunk, so the run's
    /// deadline holds whether or not the client reads (a client that stops
    /// reading leaves the body unpolled): the run is finished (off the
    /// body's path) from the read that brings its last byte, the deadline
    /// is extended for the transfer, `keep` (the workspace's lock) is held
    /// until the run ended; a body dropped early, or a chunk the client has
    /// not taken by the deadline, ends the run.
    pub fn into_body(mut self, prefix: Vec<u8>, len: u64, keep: Option<SlotGuard>) -> Body {
        self.extend(transfer(len));
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(payload_pump(self, len, keep, tx));
        Body::from_stream(futures_util::stream::once(async move { Ok::<_, io::Error>(Bytes::from(prefix)) }).chain(piped(rx, Some(len))))
    }
}

/// What a pump hands its response body.
enum Piece {
    Data(Bytes),
    /// The body is whole: its end (a chunked body's last chunk) follows.
    End,
    /// The run was cut: the body ends in this error (a chunked body without its last chunk).
    Cut(io::Error),
}

/// A pump's pieces as a response body's stream: each chunk as it comes;
/// `End` ends it; a cut, or the channel closed without `End`, ends it in
/// error, unless `len` bytes were due and all came (a body with its
/// length is whole then, and never polled past it).
fn piped(rx: tokio::sync::mpsc::Receiver<Piece>, len: Option<u64>) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> + Send {
    futures_util::stream::unfold(Some((rx, 0u64)), move |state| async move {
        let (mut rx, got) = state?;
        match rx.recv().await {
            Some(Piece::Data(b)) => {
                let got = got + b.len() as u64;
                Some((Ok(b), Some((rx, got))))
            }
            Some(Piece::End) => None,
            Some(Piece::Cut(e)) => Some((Err(e), None)),
            None if len == Some(got) => None,
            None => Some((Err(io::Error::other("the helper's stream was cut")), None)),
        }
    })
}

/// A run's error: its deadline passed with the body's last chunk untaken or its stdout unread.
fn outlived(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("the {what} outlived its budget"))
}

/// [`AgentProc::into_body`]'s task: `len` bytes of the helper's stdout to
/// `tx`, chunk by chunk, each read and each hand-over within the deadline,
/// the body's drop watched while reading. Once the last byte is read the
/// run is finished off the body's path ([`finish_after`]), then `keep`
/// goes; anything else (an early EOF, a read error, the deadline, the body
/// dropped) ends the run now, then `keep` goes, and the body ends in error.
async fn payload_pump(mut proc: AgentProc, len: u64, keep: Option<SlotGuard>, tx: tokio::sync::mpsc::Sender<Piece>) {
    let (op, deadline) = (proc.op, proc.deadline);
    let mut left = len;
    let why = loop {
        if left == 0 {
            // No payload at all.
            finish_after(proc, keep);
            return;
        }
        let want = usize::try_from(left).unwrap_or(CHUNK).min(CHUNK);
        let mut buf = vec![0u8; want];
        let read = tokio::select! {
            biased;
            () = tx.closed() => break io::Error::other("the response body was dropped"),
            r = tokio::time::timeout_at(deadline, proc.stdout.read(&mut buf)) => r,
        };
        match read {
            Ok(Ok(n)) if n > 0 => {
                buf.truncate(n);
                left -= n as u64;
                if left == 0 {
                    // The client gets every byte whatever the run does now: it is finished off the body's path.
                    finish_after(proc, keep);
                    let _ = tokio::time::timeout_at(deadline, tx.send(Piece::Data(Bytes::from(buf)))).await;
                    return;
                }
                match tokio::time::timeout_at(deadline, tx.send(Piece::Data(Bytes::from(buf)))).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => break io::Error::other("the response body was dropped"),
                    Err(_) => break outlived("helper's payload"),
                }
            }
            Ok(Ok(_)) => break io::Error::new(io::ErrorKind::UnexpectedEof, "the helper's payload ended early"),
            Ok(Err(e)) => break e,
            Err(_) => break outlived("helper's payload"),
        }
    };
    errln!("ai-env: workspace {op} payload cut: {why}");
    proc.stop().await;
    drop(keep);
    let _ = tx.try_send(Piece::Cut(why));
}

/// Finish `proc` off the body's path (the client has every byte), then let `keep` go.
fn finish_after(proc: AgentProc, keep: Option<SlotGuard>) {
    tokio::spawn(async move {
        let op = proc.op;
        if let Err(e) = proc.finish().await {
            errln!("ai-env: workspace {op} ended badly after its payload: {}", e.refusal(op).message);
        }
        drop(keep);
    });
}

impl Drop for AgentProc {
    /// A run given up before it was reaped: its group leaves the manager's
    /// view, then it and what it left of its session are killed (the
    /// leader is unreaped: the ids are still its own); tokio reaps the orphan.
    fn drop(&mut self) {
        if self.status.is_none() {
            self.hold.clear_group();
            killpg(self.pid, libc::SIGKILL);
            for pid in session_pids(self.pid) {
                signal_in_session(pid, self.pid, libc::SIGKILL);
            }
        }
    }
}

/// Feed `body` (`len` bytes) to the helper's stdin, then close it; once the
/// helper stops reading, the rest is read and dropped, so the client gets
/// the answer rather than a reset. The bytes read.
pub async fn feed(body: Body, mut stdin: Option<ChildStdin>) -> u64 {
    let mut stream = body.into_data_stream();
    let mut n = 0u64;
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else { break };
        n += chunk.len() as u64;
        if let Some(w) = stdin.as_mut() {
            if w.write_all(&chunk).await.is_err() {
                stdin = None;
            }
        }
    }
    drop(stdin);
    n
}

/// Run `cmd` to its head: `input` written to its stdin (then closed), the
/// head read, the run finished. The head, or why there is none.
pub async fn run_op<T: DeserializeOwned>(state: &ShimState, cmd: AgentCmd, input: Option<Vec<u8>>) -> Result<HelperHead<T>, AgentProcError> {
    let mut proc = AgentProc::start(state, cmd).await?;
    if let (Some(bytes), Some(mut w)) = (input, proc.take_stdin()) {
        // A helper that stops reading closes the pipe: its head says why.
        let _ = tokio::time::timeout_at(proc.deadline(), w.write_all(&bytes)).await;
    }
    finish_head(proc).await
}

/// Run `cmd` with the request `body` streamed to its stdin. A helper that
/// does not start (a stop, a failed exec) still has the body read, within
/// the budget, so the client gets that answer rather than a reset. One
/// given up without a head (its budget passed: a body that stalled is cut
/// there, which closes its stdin) has [`EOF_GRACE`] to end by itself
/// before TERM, so its EOF path removes what it wrote.
pub async fn run_with_body<T: DeserializeOwned>(state: &ShimState, cmd: AgentCmd, body: Body) -> Result<HelperHead<T>, AgentProcError> {
    let budget = cmd.budget;
    let mut proc = match AgentProc::start(state, cmd).await {
        Ok(proc) => proc,
        Err(e) => {
            let _ = tokio::time::timeout(budget, feed(body, None)).await;
            return Err(e);
        }
    };
    let stdin = proc.take_stdin();
    let deadline = proc.deadline();
    let (_, head) = tokio::join!(tokio::time::timeout_at(deadline, feed(body, stdin)), proc.head::<T>());
    match head {
        Ok(h) => proc.finish().await.map(|()| h),
        Err(e) => {
            // The feed has ended (its body read, or cut at the deadline): the helper's stdin is closed.
            proc.stop_after(EOF_GRACE).await;
            Err(e)
        }
    }
}

/// [`run_op`] for an op that answers in the payload form (S10: `seed-state`,
/// whose shallow list can pass a head line): its head a `JsonPayloadReply`,
/// then exactly the `len` bytes it names (at most `JSON_PAYLOAD_MAX`), read
/// within the run's deadline and their sha256 checked, then the run
/// finished: as with [`run_op`], the helper is reaped before this returns,
/// so the route answers with no helper left (S9's `s3xfer::run_payload`
/// finishes the run off the reply's path instead). The reply; or the
/// refusal: the helper's own, `timeout` past the deadline, else
/// `git_failed` (a payload that is not what its head announced among them).
pub async fn run_op_payload<T: DeserializeOwned>(state: &ShimState, cmd: AgentCmd) -> Result<T, Box<WsRefusal>> {
    let op = cmd.op;
    let failed = |e: AgentProcError| Box::new(e.refusal(op));
    let mut proc = AgentProc::start(state, cmd).await.map_err(failed)?;
    let head = match proc.head::<JsonPayloadReply>().await {
        Ok(h) => h,
        Err(e) => {
            proc.stop().await;
            return Err(failed(e));
        }
    };
    let (sums, len) = match head.outcome() {
        Some(Ok((sums, Some(len)))) if len <= JSON_PAYLOAD_MAX as u64 => (sums, len),
        Some(Err(r)) => {
            if let Err(e) = proc.finish().await {
                errln!("ai-env: workspace {op} helper ended badly after its refusal: {}", e.refusal(op).message);
            }
            return Err(Box::new(r));
        }
        _ => {
            proc.stop().await;
            return Err(failed(AgentProcError::BadHead(format!("no payload of at most {JSON_PAYLOAD_MAX} bytes announced"))));
        }
    };
    let mut bytes = vec![0u8; usize::try_from(len).unwrap_or_default()];
    let why = match tokio::time::timeout_at(proc.deadline, proc.stdout.read_exact(&mut bytes)).await {
        Err(_) => Some(AgentProcError::Timeout),
        Ok(Err(e)) => Some(AgentProcError::BadHead(format!("the payload: {e}"))),
        Ok(Ok(_)) if hex::encode(Sha256::digest(&bytes)) != sums.sha256 => Some(AgentProcError::BadHead(format!("a payload of {len} bytes that is not the one announced"))),
        Ok(Ok(_)) => None,
    };
    if let Some(e) = why {
        proc.stop().await;
        return Err(failed(e));
    }
    proc.finish().await.map_err(failed)?;
    serde_json::from_slice(&bytes).map_err(|e| failed(AgentProcError::BadHead(format!("a payload that does not parse: {}", parse_error(&e)))))
}

async fn finish_head<T: DeserializeOwned>(mut proc: AgentProc) -> Result<HelperHead<T>, AgentProcError> {
    match proc.head::<T>().await {
        Ok(h) => proc.finish().await.map(|()| h),
        Err(e) => {
            proc.stop().await;
            Err(e)
        }
    }
}

// ---- the git CGI's head and stream (S9) ----------------------------------------------------

/// The longest value of a CGI header the root shim passes on (S9 §1.3).
pub const CGI_VALUE_MAX: usize = 1024;

/// What the root shim passes on of a CGI's header block (S9 §1.3): the
/// `GIT_CGI_HEADERS` it names, each as the CGI gave it, in its order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgiHead {
    pub headers: Vec<(axum::http::HeaderName, HeaderValue)>,
}

/// RFC 9110's `tchar`: what a header's name is made of.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A CGI's header block (its lines ended by LF or CRLF, up to the first
/// blank one) as the root shim takes it: every line a `name: value` whose
/// name is a token (no folded line), a `Status` that is absent or 200, and
/// each of `GIT_CGI_HEADERS` at most once with a value of at most
/// [`CGI_VALUE_MAX`] bytes and no control character. Those are kept, every
/// other header dropped. `Err` says why the block is refused: the route
/// answers 500 `git_failed`, never the CGI's own status (a CGI 403 would make
/// the Mac re-mint its token).
pub fn parse_cgi_head(block: &[u8]) -> Result<CgiHead, String> {
    let mut head = CgiHead::default();
    let mut status = false;
    for raw in block.split_inclusive(|b| *b == b'\n') {
        // What follows the last LF is no line: the block ended before its blank line.
        let Some(line) = raw.strip_suffix(b"\n") else { break };
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return Ok(head);
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else { return Err("has a line that is no header".into()) };
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        if name.is_empty() || !name.iter().all(|b| is_tchar(*b)) {
            return Err("has a header name that is no token (or a folded line)".into());
        }
        if name.eq_ignore_ascii_case(b"status") {
            if std::mem::replace(&mut status, true) {
                return Err("names its status twice".into());
            }
            if value.split(|b| *b == b' ').next() != Some(&b"200"[..]) {
                return Err(format!("answered status {}", String::from_utf8_lossy(&value[..value.len().min(64)])));
            }
            continue;
        }
        let Some(known) = GIT_CGI_HEADERS.iter().find(|h| name.eq_ignore_ascii_case(h.as_bytes())) else { continue };
        if value.len() > CGI_VALUE_MAX || value.iter().any(u8::is_ascii_control) {
            return Err(format!("gives {known} a value over {CGI_VALUE_MAX} bytes or with a control character"));
        }
        let name = axum::http::HeaderName::from_static(known);
        if head.headers.iter().any(|(n, _)| *n == name) {
            return Err(format!("names {known} twice"));
        }
        let value = HeaderValue::from_bytes(value).map_err(|_| format!("gives {known} a value that is no header value"))?;
        head.headers.push((name, value));
    }
    Err("ends before its blank line".into())
}

impl AgentProc {
    /// The CGI's header block after the head (S9 §1.3: `git-cgi` copies
    /// http-backend's output past its own head), within the deadline: at
    /// most `GIT_CGI_HEAD_MAX` bytes up to its blank line, as
    /// [`parse_cgi_head`] takes it. A block over the cap, cut short or
    /// refused is [`AgentProcError::BadHead`]; a helper that ended before its
    /// block did and failed, [`AgentProcError::Exit`]. What follows the
    /// block stays for [`AgentProc::into_stream`].
    pub async fn read_cgi_head(&mut self) -> Result<CgiHead, AgentProcError> {
        use tokio::io::AsyncBufReadExt as _;
        let deadline = self.deadline;
        let stdout = &mut self.stdout;
        let read = async move {
            let mut block = Vec::new();
            loop {
                let start = block.len();
                if start >= GIT_CGI_HEAD_MAX {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("is over {GIT_CGI_HEAD_MAX} bytes")));
                }
                let left = u64::try_from(GIT_CGI_HEAD_MAX - start).unwrap_or(0);
                if (&mut *stdout).take(left).read_until(b'\n', &mut block).await? == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ended before its blank line"));
                }
                // A line the cap cut is caught above; one cut by EOF, by the next read.
                if matches!(&block[start..], b"\n" | b"\r\n") {
                    return Ok(block);
                }
            }
        };
        match tokio::time::timeout_at(deadline, read).await {
            Err(_) => Err(AgentProcError::Timeout),
            Ok(Ok(block)) => parse_cgi_head(&block).map_err(|why| AgentProcError::BadHead(format!("the CGI's head {why}"))),
            Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                let status = self.reap().await?;
                if status.success() {
                    return Err(AgentProcError::BadHead(format!("the CGI's head {e}")));
                }
                Err(AgentProcError::Exit { code: status.code(), stderr: self.stderr_line().await })
            }
            Ok(Err(e)) => Err(AgentProcError::BadHead(format!("the CGI's head {e}"))),
        }
    }

    /// The CGI's body after its header block (S9 §1.3) as a response body:
    /// no length is known, so it goes out chunked, to the helper's EOF,
    /// within the deadline (never extended: the route's budget counts from
    /// the request) and at most `cap` bytes. A task of its own reads the
    /// helper ([`cgi_pump`]), so the deadline, the cap and the release of
    /// the run hold whether or not the client reads (one that stops reading
    /// leaves the body unpolled, and hyper only flushes then). It ends only
    /// once the helper has exited 0; past the cap or the deadline (a chunk
    /// the client has not taken by then too), or on any other exit, it ends
    /// with an error, which leaves the chunked body without its last chunk:
    /// a cut pack never looks complete. `keep` (the CGI's slot) is held
    /// until the run ended; a body dropped early ends the run at once.
    pub fn into_stream(self, cap: u64, keep: Option<CgiSlot>) -> Body {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(cgi_pump(self, cap, keep, tx));
        Body::from_stream(piped(rx, None))
    }
}

/// [`AgentProc::into_stream`]'s task: the helper's stdout to `tx` to its
/// EOF, each read and each hand-over within the deadline, at most `cap`
/// bytes, the body's drop watched while reading. At EOF the run is
/// finished: exit 0 lets `keep` go and ends the body whole, any other exit
/// ends it in error (`finish` reaped it already). Past the cap or the
/// deadline, on a read error or the body dropped, the run is ended now,
/// then `keep` goes, and the body ends in error.
async fn cgi_pump(mut proc: AgentProc, cap: u64, keep: Option<CgiSlot>, tx: tokio::sync::mpsc::Sender<Piece>) {
    let (op, deadline) = (proc.op, proc.deadline);
    let mut sent = 0u64;
    let why = loop {
        if Instant::now() >= deadline {
            break outlived("CGI's body");
        }
        let mut buf = vec![0u8; CHUNK];
        let read = tokio::select! {
            biased;
            () = tx.closed() => break io::Error::other("the response body was dropped"),
            r = tokio::time::timeout_at(deadline, proc.stdout.read(&mut buf)) => r,
        };
        match read {
            Ok(Ok(0)) => {
                let why = match proc.finish().await {
                    Ok(()) => {
                        drop(keep);
                        let _ = tokio::time::timeout_at(deadline, tx.send(Piece::End)).await;
                        return;
                    }
                    Err(e) => io::Error::other(format!("the helper failed after the CGI's head: {}", e.refusal(op).message)),
                };
                errln!("ai-env: workspace {op} stream cut: {why}");
                drop(keep);
                // A full channel loses this piece: the body then sees the channel close without its end, an error too.
                let _ = tx.try_send(Piece::Cut(why));
                return;
            }
            Ok(Ok(n)) if sent + n as u64 <= cap => {
                sent += n as u64;
                buf.truncate(n);
                match tokio::time::timeout_at(deadline, tx.send(Piece::Data(Bytes::from(buf)))).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => break io::Error::other("the response body was dropped"),
                    Err(_) => break outlived("CGI's body"),
                }
            }
            Ok(Ok(_)) => break io::Error::other(format!("the CGI's body passed {cap} bytes")),
            Ok(Err(e)) => break e,
            Err(_) => break outlived("CGI's body"),
        }
    };
    errln!("ai-env: workspace {op} stream cut: {why}");
    proc.stop().await;
    drop(keep);
    let _ = tx.try_send(Piece::Cut(why));
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod cgi_tests {
    use super::*;
    use crate::shim::health::{ProbeSpec, ShimOpts};
    use crate::shim::sys::RealSys;
    use crate::wire::workspace::GitCgiReply;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// The helper's own head, as `git-cgi` writes it before the CGI's output.
    const HEAD: &str = r#"{"ok":true,"reply":{"object_format":"sha1","git_version":"2.50.1"}}"#;

    fn home() -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let p = std::fs::canonicalize(t.path()).unwrap();
        (t, p)
    }

    /// A shim whose helper is the script `body` (run once first, as
    /// `tests::shim`'s: macOS assesses a new executable at its first exec),
    /// its home `dir`.
    fn shim(dir: &Path, name: &str, body: &str) -> Arc<ShimState> {
        let script = dir.join(name);
        std::fs::write(&script, format!("#!/bin/sh\n[ \"$1\" = warm ] && exit 0\n{body}")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let warmed = {
            let _fork = crate::test_locks::forking();
            std::process::Command::new(&script).arg("warm").status().unwrap()
        };
        assert!(warmed.success());
        let opts = ShimOpts { helper: Some(script), home: dir.to_path_buf(), ..ShimOpts::default() };
        Arc::new(ShimState::with(PathBuf::from("/nonexistent/claude"), opts, ProbeSpec::default(), Arc::new(RealSys)))
    }

    /// One `GET /` of a server whose answer is the helper's CGI body (its
    /// head and its header block read first, the four headers passed on),
    /// streamed with `cap` under `budget`, one of the shim's CGI slots held:
    /// the raw response, read to the server's close.
    async fn served(state: Arc<ShimState>, budget: Duration, cap: u64) -> Vec<u8> {
        let addr = serve_cgi(state, budget, cap).await;
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut got)).await.expect("the server closes within 30 s").unwrap();
        got
    }

    /// A server whose `GET /` answers as [`served`] reads it: its address.
    async fn serve_cgi(state: Arc<ShimState>, budget: Duration, cap: u64) -> std::net::SocketAddr {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let state = state.clone();
                async move {
                    let cmd = AgentCmd { op: "git-cgi", args: Vec::new(), budget, stdin: false, during_stop: false };
                    let mut proc = AgentProc::start(&state, cmd).await.unwrap();
                    assert!(proc.head::<GitCgiReply>().await.unwrap().ok);
                    let cgi = proc.read_cgi_head().await.unwrap();
                    let mut res = Response::new(proc.into_stream(cap, state.workspace.try_cgi()));
                    for (name, value) in cgi.headers {
                        res.headers_mut().insert(name, value);
                    }
                    res
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// A chunked response's head (lowercase), its body's bytes, and whether
    /// the body ended with its last chunk.
    fn chunked(raw: &[u8]) -> (String, Vec<u8>, bool) {
        let end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a head") + 4;
        let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
        let (mut rest, mut body) = (&raw[end..], Vec::new());
        loop {
            let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") else { return (head, body, false) };
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..nl]).unwrap().trim(), 16).unwrap();
            rest = &rest[nl + 2..];
            if size == 0 {
                return (head, body, rest == b"\r\n");
            }
            if rest.len() < size + 2 {
                body.extend_from_slice(&rest[..rest.len().min(size)]);
                return (head, body, false);
            }
            body.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
    }

    /// Until every CGI slot is free again and no helper runs (at most 10 s).
    async fn idle(state: &ShimState) {
        if let Err(why) = idle_within(state, Duration::from_secs(10)).await {
            panic!("{why}");
        }
    }

    /// Until every CGI slot is free again and no helper runs, at most `within`; else what is still held.
    async fn idle_within(state: &ShimState, within: Duration) -> Result<(), String> {
        let until = std::time::Instant::now() + within;
        loop {
            let slots: Vec<CgiSlot> = (0..GIT_CGI_MAX).filter_map(|_| state.workspace.try_cgi()).collect();
            if slots.len() == GIT_CGI_MAX && state.spawns.helpers() == 0 {
                return Ok(());
            }
            if std::time::Instant::now() >= until {
                return Err(format!("slots free {}, helpers {} after {within:?}", slots.len(), state.spawns.helpers()));
            }
            drop(slots);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// `GET /` sent to `addr`, then the response read up to its head's end
    /// and on until its bytes hold `until`: the open stream and what was read.
    async fn read_up_to(addr: std::net::SocketAddr, until: &[u8]) -> (tokio::net::TcpStream, Vec<u8>) {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        while !(got.windows(4).any(|w| w == b"\r\n\r\n") && got.windows(until.len()).any(|w| w == until)) {
            let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await.expect("the answer within 10 s").unwrap();
            assert!(n > 0, "the server closed early: {}", String::from_utf8_lossy(&got));
            got.extend_from_slice(&buf[..n]);
        }
        (s, got)
    }

    /// S9 phase 4 (CGI-1): a client that reads the head and then stops
    /// reading, its socket open (the body unpolled: hyper only flushes),
    /// never holds the run past its budget. The helper writing 16 MiB (more
    /// than any socket buffer takes) under a 2 s budget is ended, its slot
    /// and its hold freed within the budget and the kill's grace, the
    /// client still connected.
    #[tokio::test]
    async fn a_stalled_reader_never_holds_the_run_past_its_budget() {
        let (_t, dir) = home();
        let big = shim(&dir, "big", &format!("printf '%s\\n' '{HEAD}'\nprintf 'Content-Type: application/x-git-upload-pack-result\\r\\n\\r\\n'\ndd if=/dev/zero bs=65536 count=256 2>/dev/null\nexit 0\n"));
        let t = std::time::Instant::now();
        let addr = serve_cgi(big.clone(), Duration::from_secs(2), 1 << 30).await;
        let (stalled, _) = read_up_to(addr, b"\r\n\r\n").await;
        let freed = idle_within(&big, Duration::from_secs(2) + KILL_AFTER + Duration::from_secs(1)).await;
        assert!(freed.is_ok(), "{freed:?} at {:?}, the client still connected", t.elapsed());
        drop(stalled);
    }

    /// S9 phase 4 (CGI-1): a body dropped early (the client closed after the
    /// first bytes) ends the run at once, the helper still sleeping and
    /// far from its 20 s budget: its slot and its hold freed within 5 s.
    #[tokio::test]
    async fn a_dropped_body_ends_the_run_at_once() {
        let (_t, dir) = home();
        let slow = shim(&dir, "partial", &format!("printf '%s\\n' '{HEAD}'\nprintf 'Content-Type: application/x-git-upload-pack-result\\r\\n\\r\\n'\nprintf 'partial'\nsleep 30\n"));
        let addr = serve_cgi(slow.clone(), Duration::from_secs(20), 1 << 20).await;
        let (closed, _) = read_up_to(addr, b"partial").await;
        drop(closed);
        let freed = idle_within(&slow, Duration::from_secs(5)).await;
        assert!(freed.is_ok(), "{freed:?}");
    }

    /// The CGI's body streams chunked (no length) to the helper's EOF and
    /// gets its last chunk only once the helper exited 0. A helper that
    /// exits non-zero after its head and part of the body, a body past the
    /// cap and one past the deadline each end the stream with an error: the
    /// bytes sent so far, then no last chunk, so a cut pack never looks
    /// complete. The run's slot and its helper count go with it every time.
    #[tokio::test]
    async fn a_stream_after_a_failed_exit_ends_in_error() {
        let (_t, dir) = home();
        let cgi = format!("printf '%s\\n' '{HEAD}'\nprintf 'Content-Type: application/x-git-upload-pack-result\\r\\nX-Other: dropped\\r\\n\\r\\n'\nprintf 'partial pack'\n");
        let ok = shim(&dir, "ok", &format!("{cgi}exit 0\n"));
        let (head, body, complete) = chunked(&served(ok.clone(), Duration::from_secs(20), 1 << 20).await);
        assert!(complete && body == b"partial pack", "{head}{}", String::from_utf8_lossy(&body));
        assert!(head.contains("transfer-encoding: chunked") && !head.contains("content-length") && head.contains("content-type: application/x-git-upload-pack-result") && !head.contains("x-other"), "{head}");
        idle(&ok).await;
        let failed = shim(&dir, "failed", &format!("{cgi}exit 3\n"));
        let (head, body, complete) = chunked(&served(failed.clone(), Duration::from_secs(20), 1 << 20).await);
        assert!(!complete && body == b"partial pack", "a failed exit ends in error: {head}{}", String::from_utf8_lossy(&body));
        idle(&failed).await;
        let (_, body, complete) = chunked(&served(ok.clone(), Duration::from_secs(20), 4).await);
        assert!(!complete && body.is_empty(), "past the cap: {}", String::from_utf8_lossy(&body));
        idle(&ok).await;
        let slow = shim(&dir, "slow", &format!("{cgi}sleep 30\n"));
        let t = std::time::Instant::now();
        let (_, body, complete) = chunked(&served(slow.clone(), Duration::from_secs(2), 1 << 20).await);
        assert!(!complete && body == b"partial pack", "past the deadline: {}", String::from_utf8_lossy(&body));
        assert!(t.elapsed() < Duration::from_secs(2) + KILL_AFTER + Duration::from_secs(3), "{:?}", t.elapsed());
        idle(&slow).await;
    }

    /// The header blocks the root shim takes and refuses (S9 §1.3 rows 14
    /// and 15): the four headers kept in any case, every other dropped, LF
    /// or CRLF; a status other than 200, a line that is no header, a folded
    /// line, a value with a control character or over 1 KiB, a header twice
    /// and a block without its blank line refused.
    #[test]
    fn a_cgi_head_passes_its_four_headers_and_a_200_only() {
        let block = b"Expires: Fri, 01 Jan 1980 00:00:00 GMT\r\nPragma: no-cache\r\ncache-control: no-cache, max-age=0, must-revalidate\r\nCONTENT-TYPE: application/x-git-upload-pack-advertisement\r\nSet-Cookie: a=b\r\nLocation: http://example.invalid/\r\nContent-Length: 9\r\nX-Aws-Proxy-Auth: no\r\nStatus: 200 OK\r\n\r\nbody";
        let head = parse_cgi_head(block).unwrap();
        let names: Vec<&str> = head.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["expires", "pragma", "cache-control", "content-type"]);
        assert_eq!(head.headers[3].1, "application/x-git-upload-pack-advertisement");
        assert_eq!(parse_cgi_head(b"Content-Type: text/plain\nStatus: 200\n\n").unwrap().headers.len(), 1, "LF lines, a bare 200");
        assert_eq!(parse_cgi_head(b"\r\n").unwrap(), CgiHead::default(), "no header at all");
        let long = format!("Pragma: {}\r\n\r\n", "x".repeat(CGI_VALUE_MAX + 1));
        let exactly = format!("Pragma: {}\r\n\r\n", "x".repeat(CGI_VALUE_MAX));
        assert!(parse_cgi_head(exactly.as_bytes()).is_ok());
        for (bad, why) in [
            (&b"Status: 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n"[..], "status 403"),
            (b"Status: 404 Not Found\r\n\r\n", "status 404"),
            (b"Status: 500 Internal Server Error\r\n\r\n", "status 500"),
            (b"Status: 2000\r\n\r\n", "status 2000"),
            (b"Status: 200 OK\r\nStatus: 200 OK\r\n\r\n", "twice"),
            (b"Garbage\r\n\r\n", "no header"),
            (b"Content-Type: text/plain\r\n continued\r\n\r\n", "no header"),
            (b"Content-Type: text/plain\r\n X-Folded: x\r\n\r\n", "no token"),
            (b"Bad Name: x\r\n\r\n", "no token"),
            (b": x\r\n\r\n", "no token"),
            (b"Content-Type: a\x01b\r\n\r\n", "control"),
            (b"Content-Type: a\rInjected: b\r\n\r\n", "control"),
            (long.as_bytes(), "over 1024"),
            (b"Pragma: no-cache\r\nPRAGMA: no-cache\r\n\r\n", "twice"),
            (b"Content-Type: text/plain\r\n", "blank line"),
        ] {
            let e = parse_cgi_head(bad).unwrap_err();
            assert!(e.contains(why), "{}: {e}", String::from_utf8_lossy(bad));
        }
    }

    /// The header block is read within its cap: a block over
    /// `GIT_CGI_HEAD_MAX` is a bad head (500), a helper that ends before its
    /// blank line one too when it exited 0, its failure when it did not;
    /// the body's first bytes, already read past the block, stay for the stream.
    #[tokio::test]
    async fn a_cgi_head_over_its_cap_or_cut_short_is_refused() {
        let (_t, dir) = home();
        let cmd = || AgentCmd { op: "git-cgi", args: Vec::new(), budget: Duration::from_secs(20), stdin: false, during_stop: false };
        let pad = "X-Pad: ".to_string() + &"p".repeat(1000);
        let big = shim(&dir, "big", &format!("printf '%s\\n' '{HEAD}'\ni=0\nwhile [ $i -lt 17 ]; do printf '%s\\r\\n' '{pad}'; i=$((i+1)); done\nprintf '\\r\\n'\n"));
        let mut proc = AgentProc::start(&big, cmd()).await.unwrap();
        proc.head::<GitCgiReply>().await.unwrap();
        let e = proc.read_cgi_head().await.unwrap_err();
        assert!(matches!(&e, AgentProcError::BadHead(m) if m.contains("over 16384 bytes")), "{e:?}");
        proc.stop().await;
        let cut = shim(&dir, "cut", &format!("printf '%s\\n' '{HEAD}'\nprintf 'Content-Type: text/plain\\r\\n'\nexit 0\n"));
        let mut proc = AgentProc::start(&cut, cmd()).await.unwrap();
        proc.head::<GitCgiReply>().await.unwrap();
        let e = proc.read_cgi_head().await.unwrap_err();
        assert!(matches!(&e, AgentProcError::BadHead(m) if m.contains("blank line")), "{e:?}");
        assert_eq!(e.refusal("git-cgi").status(), 500);
        let failed = shim(&dir, "failed", &format!("printf '%s\\n' '{HEAD}'\necho 'fatal: http-backend broke' >&2\nexit 2\n"));
        let mut proc = AgentProc::start(&failed, cmd()).await.unwrap();
        proc.head::<GitCgiReply>().await.unwrap();
        let e = proc.read_cgi_head().await.unwrap_err();
        assert!(matches!(&e, AgentProcError::Exit { code: Some(2), stderr } if stderr.contains("http-backend broke")), "{e:?}");
        let whole = shim(&dir, "whole", &format!("printf '%s\\n' '{HEAD}'\nprintf 'Content-Type: text/plain\\n\\nthe body'\n"));
        let mut proc = AgentProc::start(&whole, cmd()).await.unwrap();
        proc.head::<GitCgiReply>().await.unwrap();
        assert_eq!(proc.read_cgi_head().await.unwrap().headers.len(), 1);
        let mut rest = Vec::new();
        proc.stdout.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"the body");
        proc.finish().await.unwrap();
    }
}

// ---- the helper's session ------------------------------------------------------------------

/// End what the helper `sid` left in its session, its leader exited and
/// unreaped (its zombie keeps the id): TERM, then KILL what is still there
/// [`KILL_AFTER`] later (a git ended by TERM removes its lock files). How
/// many processes there were. It blocks: run it off the runtime's workers.
fn end_session(sid: u32) -> usize {
    let found = session_pids(sid);
    if found.is_empty() {
        return 0;
    }
    for pid in &found {
        signal_in_session(*pid, sid, libc::SIGTERM);
    }
    let until = std::time::Instant::now() + KILL_AFTER;
    loop {
        std::thread::sleep(Duration::from_millis(20));
        let left = session_pids(sid);
        if left.is_empty() {
            break;
        }
        if std::time::Instant::now() >= until {
            for pid in left {
                signal_in_session(pid, sid, libc::SIGKILL);
            }
            break;
        }
    }
    found.len()
}

/// The session of a `/proc/<pid>/stat` text: the fourth field after the
/// `)` that closes `comm` (the last one: `comm` may hold parentheses);
/// `None` for a zombie (it holds nothing and cannot be signalled) or a
/// text that does not parse.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stat_session(stat: &str) -> Option<u32> {
    let mut fields = stat[stat.rfind(')')? + 1..].split_whitespace();
    if matches!(fields.next()?, "Z" | "X") {
        return None;
    }
    fields.nth(2)?.parse().ok()
}

/// The processes of the session `sid` but its leader, zombies left out.
#[cfg(target_os = "linux")]
pub(crate) fn session_pids(sid: u32) -> Vec<u32> {
    let Ok(rd) = std::fs::read_dir("/proc") else { return Vec::new() };
    rd.flatten().filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok()).filter(|pid| *pid != sid && in_session(*pid, sid)).collect()
}

#[cfg(target_os = "linux")]
fn in_session(pid: u32, sid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| stat_session(&s)) == Some(sid)
}

/// Signal `pid` when, once a pidfd pins it, it is still in the session
/// `sid` (the pid may have been reused since the scan).
#[cfg(target_os = "linux")]
fn signal_in_session(pid: u32, sid: u32, sig: libc::c_int) -> bool {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let Ok(raw) = libc::pid_t::try_from(pid) else { return false };
    // SAFETY: pidfd_open takes a pid and flags; a non-negative result is a new fd we own.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, raw, 0) };
    let Ok(fd) = libc::c_int::try_from(fd) else { return false };
    if fd < 0 {
        return false;
    }
    // SAFETY: as above.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: a pidfd we own, a signal number, no siginfo, no flags.
    in_session(pid, sid) && unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), sig, std::ptr::null::<libc::siginfo_t>(), 0) } == 0
}

/// The processes of the session `sid` but its leader (native tests: the
/// shim runs on Linux).
#[cfg(target_os = "macos")]
pub(crate) fn session_pids(sid: u32) -> Vec<u32> {
    // SAFETY: a null buffer of no size asks how many pids there are.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    let Ok(n) = usize::try_from(n) else { return Vec::new() };
    // Room for what starts meanwhile.
    let mut pids: Vec<libc::pid_t> = vec![0; n + 64];
    let Ok(bytes) = libc::c_int::try_from(pids.len() * std::mem::size_of::<libc::pid_t>()) else { return Vec::new() };
    // SAFETY: `pids` holds `bytes` bytes for the call to fill.
    let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(usize::try_from(got).unwrap_or(0));
    pids.into_iter().filter_map(|p| u32::try_from(p).ok()).filter(|pid| *pid != sid && in_session(*pid, sid)).collect()
}

#[cfg(target_os = "macos")]
fn in_session(pid: u32, sid: u32) -> bool {
    let (Ok(pid), Ok(sid)) = (libc::pid_t::try_from(pid), libc::pid_t::try_from(sid)) else { return false };
    // SAFETY: plain integers.
    pid > 1 && unsafe { libc::getsid(pid) } == sid
}

/// No pidfd here: the check and the signal are a moment apart (native tests only).
#[cfg(target_os = "macos")]
fn signal_in_session(pid: u32, sid: u32, sig: libc::c_int) -> bool {
    let Ok(raw) = libc::pid_t::try_from(pid) else { return false };
    // SAFETY: plain integers.
    in_session(pid, sid) && unsafe { libc::kill(raw, sig) } == 0
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn session_pids(_sid: u32) -> Vec<u32> {
    Vec::new()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn signal_in_session(_pid: u32, _sid: u32, _sig: libc::c_int) -> bool {
    false
}

// ---- the workspace slot --------------------------------------------------------------------

#[derive(Default)]
struct SlotState {
    record: Option<SeedRecord>,
    busy: Option<&'static str>,
    last_wip: Option<String>,
    last_wip_at: Option<String>,
}

struct SlotShared {
    lock: Arc<tokio::sync::Mutex<()>>,
    state: Mutex<SlotState>,
    /// How long a request waits for the workspace (`budget::BUSY_WAIT`; tests shorten it).
    wait: Mutex<Duration>,
}

impl SlotShared {
    fn state(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The VM's one workspace (module doc).
pub struct WorkspaceSlot {
    shared: Arc<SlotShared>,
    /// The git CGI's runs (S9): `GIT_CGI_MAX` at once, never waited for.
    cgi: Arc<tokio::sync::Semaphore>,
    /// S10 (W3 #2): where the record persists (`None`: in memory only).
    store: Option<RecordStore>,
}

/// One git CGI run's slot ([`WorkspaceSlot::try_cgi`]); dropped (its stream
/// ended, or its answer was a refusal), it is free again.
pub struct CgiSlot {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// The workspace held for one op; dropped, it is free again.
pub struct SlotGuard {
    _lock: tokio::sync::OwnedMutexGuard<()>,
    shared: Arc<SlotShared>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.shared.state().busy = None;
    }
}

impl Default for WorkspaceSlot {
    fn default() -> Self {
        let shared = SlotShared { lock: Arc::new(tokio::sync::Mutex::new(())), state: Mutex::new(SlotState::default()), wait: Mutex::new(budget::BUSY_WAIT) };
        WorkspaceSlot { shared: Arc::new(shared), cgi: Arc::new(tokio::sync::Semaphore::new(GIT_CGI_MAX)), store: None }
    }
}

impl WorkspaceSlot {
    /// The slot of a shim whose record persists in `store` (S10, W3 #2):
    /// what a shim before this one kept there, when it passes the load's
    /// checks ([`RecordStore::load`]), is the last seed's from the start.
    #[must_use]
    pub fn persisted(store: Option<RecordStore>) -> WorkspaceSlot {
        let slot = WorkspaceSlot { store, ..WorkspaceSlot::default() };
        if let Some(record) = slot.store.as_ref().and_then(RecordStore::load) {
            slot.shared.state().record = Some(record);
        }
        slot
    }

    /// How long a request waits for the workspace before 409 `busy`.
    #[must_use]
    pub fn busy_wait(&self) -> Duration {
        *self.shared.wait.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait `wait` instead of `budget::BUSY_WAIT` (tests).
    pub fn set_busy_wait(&self, wait: Duration) {
        *self.shared.wait.lock().unwrap_or_else(PoisonError::into_inner) = wait;
    }

    /// Hold the workspace for `op`, waiting at most [`Self::busy_wait`]; `None`: busy.
    pub async fn acquire(&self, op: &'static str) -> Option<SlotGuard> {
        let lock = tokio::time::timeout(self.busy_wait(), self.shared.lock.clone().lock_owned()).await.ok()?;
        self.shared.state().busy = Some(op);
        Some(SlotGuard { _lock: lock, shared: self.shared.clone() })
    }

    /// Hold the workspace for `op` only if it is free now.
    pub fn try_acquire(&self, op: &'static str) -> Option<SlotGuard> {
        let lock = self.shared.lock.clone().try_lock_owned().ok()?;
        self.shared.state().busy = Some(op);
        Some(SlotGuard { _lock: lock, shared: self.shared.clone() })
    }

    /// One of the git CGI's `GIT_CGI_MAX` slots, if one is free now (S9):
    /// the CGI only reads, so it takes no workspace lock, and a run past the
    /// slots is refused at once (409 `busy`), never queued.
    pub fn try_cgi(&self) -> Option<CgiSlot> {
        self.cgi.clone().try_acquire_owned().ok().map(|p| CgiSlot { _permit: p })
    }

    /// The last seed's record.
    #[must_use]
    pub fn record(&self) -> Option<SeedRecord> {
        self.shared.state().record.clone()
    }

    /// Keep `record` as the last seed's (one workspace per VM: the shim keeps
    /// its path for the VM's life), in its store too (S10, W3 #2: written
    /// atomically, [`RecordStore::save`]; a record the load would refuse, or
    /// a write that fails, is kept in memory only, with a log line, and the
    /// file an earlier seed wrote goes: a restarted shim then has no record,
    /// never an older one).
    pub fn set_record(&self, record: SeedRecord) {
        if let Some(store) = &self.store {
            if let Err(why) = store.save(&record) {
                let old = match std::fs::remove_file(&store.path) {
                    Ok(()) => "the older file removed".to_string(),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => "no older file".to_string(),
                    Err(e) => format!("the older file not removed: {e}"),
                };
                errln!("ai-env: seed record not kept in {} ({why}): in memory only, {old}", store.path.display());
            }
        }
        self.shared.state().record = Some(record);
    }

    /// A snapshot made or kept `name`, now.
    pub fn wip_made(&self, name: &str) {
        let mut st = self.shared.state();
        st.last_wip = Some(name.to_string());
        st.last_wip_at = Some(crate::wire::time::rfc3339_utc(crate::wire::time::unix_now()));
    }

    /// `/health/detail`'s workspace, with `helpers` running now.
    #[must_use]
    pub fn view(&self, helpers: usize) -> WorkspaceView {
        let st = self.shared.state();
        WorkspaceView { seed: st.record.clone(), busy: st.busy.map(str::to_string), helpers: u32::try_from(helpers).unwrap_or(u32::MAX), last_wip: st.last_wip.clone(), last_wip_at: st.last_wip_at.clone() }
    }
}

// ---- the persisted seed record (S10, W3 #2) --------------------------------------------------

/// Where the shim keeps the last seed's record: root's, 0600, in a root
/// 0700 directory the image makes (and bakes no record into); under
/// `--fs-root` in the native tests. The root shim alone reads and writes it:
/// no path the agent can write is ever touched (invariant 17).
pub const SEED_RECORD_PATH: &str = "/var/lib/ai-env/seed-record.json";
/// The record file's version: `{"v":1,"record":<SeedRecord>}`.
pub const SEED_RECORD_V: u32 = 1;
/// The largest record file read (a record is a few hundred bytes).
const SEED_RECORD_MAX: u64 = 64 * 1024;
/// The keys a `SeedRecord` writes: a record file's `record` holds no other.
const SEED_RECORD_KEYS: [&str; 9] = ["path", "mode", "branch", "head", "wip", "wip_tree", "index_tree", "object_format", "at"];

/// The record file as it is read: no key but these two.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFileIn {
    v: u32,
    record: serde_json::Map<String, serde_json::Value>,
}

/// The record file as it is written.
#[derive(Debug, Serialize)]
struct RecordFileOut<'a> {
    v: u32,
    record: &'a SeedRecord,
}

/// The persisted record (S10, W3 #2): its file, and the agent's home (with
/// the fs root) every record's path must lie under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordStore {
    path: PathBuf,
    home: PathBuf,
    fs_root: Option<PathBuf>,
}

impl RecordStore {
    /// The shim's store: [`SEED_RECORD_PATH`], under `--fs-root` when set. A
    /// shim with neither an fs root nor root's uid (an in-process test) has
    /// none: its record lives in memory only, as before S10, and it never
    /// reads or writes this machine's `/var/lib`.
    #[must_use]
    pub fn for_shim(opts: &ShimOpts) -> Option<RecordStore> {
        let path = match &opts.fs_root {
            Some(root) => root.join(SEED_RECORD_PATH.trim_start_matches('/')),
            None if nix::unistd::geteuid().is_root() => PathBuf::from(SEED_RECORD_PATH),
            None => return None,
        };
        Some(RecordStore { path, home: opts.home.clone(), fs_root: opts.fs_root.clone() })
    }

    /// The file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A record's checks, at the load and before each write: its path a VM
    /// path (absolute, NFC, no `.` or `..` component: `vm_path_check`)
    /// strictly under the agent's home; its branch one git takes; its
    /// `head`, `wip`, `wip_tree` and `index_tree` ids of its object format.
    fn check(&self, r: &SeedRecord) -> Result<(), String> {
        vm_path_check(&r.path).map_err(|e| format!("its path {e}"))?;
        let disk = match &self.fs_root {
            Some(root) => root.join(r.path.trim_start_matches('/')),
            None => PathBuf::from(&r.path),
        };
        if !disk.strip_prefix(&self.home).is_ok_and(|rest| rest.components().next().is_some()) {
            return Err(format!("its path {} is not under the agent's home", r.path));
        }
        if let Some(b) = &r.branch {
            branch_check(b).map_err(|e| format!("its branch {e}"))?;
        }
        for (what, id) in [("head", Some(&r.head)), ("wip", r.wip.as_ref()), ("wip_tree", r.wip_tree.as_ref()), ("index_tree", r.index_tree.as_ref())] {
            if id.is_some_and(|id| !r.object_format.is_id(id)) {
                return Err(format!("its {what} is no {} id", r.object_format.name()));
            }
        }
        Ok(())
    }

    /// A record file's text, checked strictly: one JSON object of `v` 1 and
    /// the record, no other key in either, and the record's checks.
    fn parse(&self, bytes: &[u8]) -> Result<SeedRecord, String> {
        let file: RecordFileIn = serde_json::from_slice(bytes).map_err(|e| format!("it does not parse ({})", parse_error(&e)))?;
        if file.v != SEED_RECORD_V {
            return Err(format!("its v is {}, not {SEED_RECORD_V}", file.v));
        }
        if let Some(key) = file.record.keys().find(|k| !SEED_RECORD_KEYS.contains(&k.as_str())) {
            return Err(format!("its record has an unknown key {:?}", key.chars().take(64).collect::<String>()));
        }
        let record: SeedRecord = serde_json::from_value(serde_json::Value::Object(file.record)).map_err(|e| format!("its record does not parse ({})", parse_error(&e)))?;
        self.check(&record)?;
        Ok(record)
    }

    /// The record the file holds when it passes every check ([`Self::parse`]):
    /// else `None`, logged with the reason (silently for a VM never seeded,
    /// which has no file).
    #[must_use]
    pub fn load(&self) -> Option<SeedRecord> {
        let shown = self.path.display();
        let read = match std::fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => Err(e.to_string()),
            Ok(md) if !md.is_file() => Err("it is not a regular file".into()),
            Ok(md) if md.len() > SEED_RECORD_MAX => Err(format!("it is over {SEED_RECORD_MAX} bytes")),
            Ok(_) => std::fs::read(&self.path).map_err(|e| e.to_string()),
        };
        match read.and_then(|bytes| self.parse(&bytes)) {
            Ok(record) => {
                errln!("ai-env: seed record loaded from {shown}: {} at {}", record.path, record.head);
                Some(record)
            }
            Err(why) => {
                errln!("ai-env: seed record {shown} ignored: {why}");
                None
            }
        }
    }

    /// Write `record` atomically (a record the load would refuse never is):
    /// a temp file (0600) beside the file, in its directory (made 0700 when
    /// missing, and kept 0700), fsynced, renamed over it, the directory
    /// fsynced after. `Err` says why not.
    fn save(&self, record: &SeedRecord) -> Result<(), String> {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        self.check(record)?;
        let dir = self.path.parent().ok_or("the file has no directory")?;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("cannot keep {} 0700: {e}", dir.display()))?;
        let mut text = serde_json::to_vec(&RecordFileOut { v: SEED_RECORD_V, record }).map_err(|e| e.to_string())?;
        text.push(b'\n');
        let mut tmp = tempfile::Builder::new().prefix(".seed-record-").tempfile_in(dir).map_err(|e| format!("cannot make a temp file in {}: {e}", dir.display()))?;
        std::io::Write::write_all(&mut tmp, &text).map_err(|e| e.to_string())?;
        tmp.as_file().sync_all().map_err(|e| e.to_string())?;
        tmp.persist(&self.path).map_err(|e| e.error.to_string())?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

/// A parse error as a log line names it: where, and what, unless the text
/// quotes a value.
fn parse_error(e: &serde_json::Error) -> String {
    let what = e.to_string();
    if what.contains('"') {
        format!("invalid at line {} column {}", e.line(), e.column())
    } else {
        what
    }
}

// ---- answers -------------------------------------------------------------------------------

/// A refusal's answer: its status, the `WsRefusal` as JSON; `busy` with `Retry-After`.
#[must_use]
pub fn refused(r: &WsRefusal) -> Response {
    let status = StatusCode::from_u16(r.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut res = (status, Json(r)).into_response();
    if r.code == refusal::BUSY {
        res.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(RETRY_AFTER_S));
    }
    res
}

/// A reply's answer: `status` and the reply as JSON.
#[must_use]
pub fn answered<T: Serialize>(status: u16, reply: &T) -> Response {
    (StatusCode::from_u16(status).unwrap_or(StatusCode::OK), Json(reply)).into_response()
}

/// What a 409 `busy` names when the workspace's lock was held.
pub const WORKSPACE_HELD: &str = "another seed, code-out or snapshot holds the workspace";

/// 409 `busy`: `held` says who held what `op` waited for, past the wait
/// ([`WORKSPACE_HELD`], or a transfer's own rel: S9's `s3xfer`).
#[must_use]
pub fn busy(op: &str, held: &str, waited: Duration) -> WsRefusal {
    WsRefusal::new(refusal::BUSY, &format!("{held} ({op} waited {} s)", waited.as_secs()))
}

/// Run `work` (a helper's run and what must follow it: the record kept,
/// the lock let go, the answer logged) as a task of its own, and await it.
/// A request is dropped when its client goes away, and a helper dropped
/// mid-op is killed before its own rollback ran (a clone's directory, a
/// staged file): as a task, the run ends as it would have, and only the
/// answer is lost.
pub async fn detached(op: &'static str, started: std::time::Instant, work: impl std::future::Future<Output = Response> + Send + 'static) -> Response {
    match tokio::spawn(work).await {
        Ok(res) => res,
        Err(e) => refuse(op, started, &WsRefusal::new(refusal::GIT_FAILED, &format!("the workspace {op} task ended: {e}"))),
    }
}

/// One log line per workspace request: the op, the status, the code of a refusal, the time.
pub fn log(op: &str, status: u16, code: Option<&str>, started: std::time::Instant) {
    errln!("ai-env: workspace {op} status={status}{} ms={}", code.map_or(String::new(), |c| format!(" code={c}")), started.elapsed().as_millis());
}

/// The answer to a helper's outcome: its reply (with `status` of it), its
/// refusal, or why it gave none; logged.
pub fn respond<T: Serialize>(op: &'static str, started: std::time::Instant, outcome: Result<HelperHead<T>, AgentProcError>, status: impl FnOnce(&T) -> u16) -> Response {
    match outcome.map(HelperHead::outcome) {
        Ok(Some(Ok((reply, _)))) => {
            let s = status(&reply);
            log(op, s, None, started);
            answered(s, &reply)
        }
        Ok(Some(Err(r))) => {
            log(op, r.status(), Some(&r.code), started);
            refused(&r)
        }
        Ok(None) => {
            let r = AgentProcError::BadHead("neither a reply nor a refusal".into()).refusal(op);
            log(op, r.status(), Some(&r.code), started);
            refused(&r)
        }
        Err(e) => {
            let r = e.refusal(op);
            log(op, r.status(), Some(&r.code), started);
            refused(&r)
        }
    }
}

/// The refusal of `r`, logged.
pub fn refuse(op: &str, started: std::time::Instant, r: &WsRefusal) -> Response {
    log(op, r.status(), Some(&r.code), started);
    refused(r)
}

/// The line a framed body starts with (a code-out's manifest).
pub fn framed_head<T: Serialize>(head: &T) -> io::Result<Vec<u8>> {
    head_line(head)
}

// ---- the /suspend snapshot -----------------------------------------------------------------

/// `/suspend`'s snapshot (L6): after `freeze()`, before the sockets close,
/// within `budget::SUSPEND_SNAPSHOT`; only for a seeded VM, and skipped
/// when the workspace is busy. Logged as `ai-env: wip_snapshot …`.
pub async fn suspend_snapshot(state: &ShimState) {
    if !state.serves_workspace() {
        return;
    }
    let Some(record) = state.workspace.record() else { return };
    let Some(_held) = state.workspace.try_acquire("snapshot") else {
        errln!("ai-env: wip_snapshot skipped: the workspace is busy");
        return;
    };
    let started = std::time::Instant::now();
    let secs = budget::SUSPEND_SNAPSHOT.as_secs().to_string();
    let cmd = AgentCmd { op: "snapshot", args: vec![flag("path", &record.path), flag("budget-s", secs)], budget: budget::SUSPEND_SNAPSHOT, stdin: false, during_stop: false };
    match run_op::<SnapshotReply>(state, cmd, None).await.map(HelperHead::outcome) {
        Ok(Some(Ok((reply, _)))) => {
            if let Some(name) = &reply.wip_ref {
                state.workspace.wip_made(name);
            }
            let what = match (&reply.wip_ref, &reply.wip_skipped) {
                (Some(name), _) => format!("ref={name}"),
                (None, Some(why)) => format!("skipped: {why}"),
                (None, None) => "nothing uncommitted".to_string(),
            };
            errln!("ai-env: wip_snapshot {what} ms={}", started.elapsed().as_millis());
        }
        Ok(Some(Err(r))) => errln!("ai-env: wip_snapshot refused code={}: {} ms={}", r.code, r.message, started.elapsed().as_millis()),
        Ok(None) => errln!("ai-env: wip_snapshot failed: the helper's head is neither a reply nor a refusal"),
        Err(e) => errln!("ai-env: wip_snapshot failed: {}", e.refusal("snapshot").message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shim::health::{ProbeSpec, ShimOpts};
    use crate::shim::sys::RealSys;
    use crate::wire::workspace::SeedState;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// A shim whose helper is the script `body` (argv: `shim-io --home=H
    /// --git=G <op> <args>… --budget-ms=B`, so `$4` is the op), its home `dir`. The script
    /// is run once first (it exits at once on `warm`): macOS assesses a new
    /// executable at its first exec, which must not eat a test's budget.
    fn shim(dir: &Path, body: &str) -> ShimState {
        let script = dir.join("helper");
        std::fs::write(&script, format!("#!/bin/sh\n[ \"$1\" = warm ] && exit 0\n{body}")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let warmed = {
            let _fork = crate::test_locks::forking();
            std::process::Command::new(&script).arg("warm").status().unwrap()
        };
        assert!(warmed.success());
        let opts = ShimOpts { helper: Some(script), home: dir.to_path_buf(), ..ShimOpts::default() };
        ShimState::with(PathBuf::from("/nonexistent/claude"), opts, ProbeSpec::default(), Arc::new(RealSys))
    }

    fn cmd(op: &'static str, budget: Duration) -> AgentCmd {
        AgentCmd { op, args: vec![flag("path", "/w")], budget, stdin: true, during_stop: false }
    }

    fn home() -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let p = std::fs::canonicalize(t.path()).unwrap();
        (t, p)
    }

    /// The helper runs in the agent's home with an environment of three
    /// names and fds 0 to 2 only; its head is read, its run finished, and
    /// it counted as a helper while it ran.
    #[tokio::test]
    async fn a_helper_runs_in_the_home_with_a_bare_environment() {
        let (_t, dir) = home();
        // The descriptors from 3 to 63 the shell itself holds (bash keeps the script on 255).
        let state = shim(&dir, "fds=''\nfor n in $(seq 3 63); do [ -e /dev/fd/$n ] && fds=\"$fds$n,\"; done\nvars=$(env | cut -d= -f1 | grep -v -e '^PWD$' -e '^SHLVL$' -e '^_$' -e '^OLDPWD$' | sort | tr '\\n' ,)\nprintf '{\"ok\":true,\"reply\":{\"tip\":\"%s|%s|%s|%s\"}}\\n' \"$(pwd)\" \"$vars\" \"$4\" \"$fds\"\n");
        let head = run_op::<SeedState>(&state, cmd("seed-state", Duration::from_secs(20)), Some(b"ignored".to_vec())).await.unwrap();
        let tip = head.reply.unwrap().tip.unwrap();
        let parts: Vec<&str> = tip.split('|').collect();
        assert_eq!(parts[0], dir.to_str().unwrap(), "entered the agent's home");
        assert_eq!(parts[1], "HOME,LC_ALL,PATH,", "only what the shim sets");
        assert_eq!(parts[2], "seed-state");
        assert_eq!(parts[3], "", "no descriptor past stderr");
        assert_eq!(state.spawns.helpers(), 0, "the hold went with the run");
    }

    /// Past its budget the helper's group is ended (TERM, then KILL) and
    /// reaped, and what it left of its session with it: a background
    /// process of its group dies, and so does one leading a group of its
    /// own in its session, as each git run does (perl's setpgrp makes one).
    #[tokio::test]
    async fn a_helper_past_its_budget_has_its_group_and_session_ended() {
        let (_t, dir) = home();
        let (bg, own) = (dir.join("bg.pid"), dir.join("own.pid"));
        let perl = Path::new("/usr/bin/perl").exists();
        let own_group = if perl {
            format!("/usr/bin/perl -e 'setpgrp(0, 0); exec @ARGV' sleep 60 &\necho $! > '{}'\n", own.display())
        } else {
            eprintln!("no /usr/bin/perl to lead a group of its own: only the helper's group is checked");
            String::new()
        };
        let state = shim(&dir, &format!("sleep 60 &\necho $! > '{}'\n{own_group}trap '' TERM\nwait\n", bg.display()));
        let t = std::time::Instant::now();
        let e = run_op::<SeedState>(&state, cmd("seed-state", Duration::from_secs(2)), None).await.unwrap_err();
        assert!(matches!(e, AgentProcError::Timeout), "{e:?}");
        assert!(t.elapsed() < Duration::from_secs(2) + KILL_AFTER + Duration::from_secs(2), "{:?}", t.elapsed());
        assert_eq!(e.refusal("seed-state").status(), 504);
        let pidfiles = if perl { vec![bg, own] } else { vec![bg] };
        for pidfile in pidfiles {
            let pid: i32 = std::fs::read_to_string(&pidfile).expect("the helper started within its budget").trim().parse().unwrap();
            let gone = (0..100).any(|_| {
                std::thread::sleep(Duration::from_millis(20));
                // SAFETY: signal 0 only checks for existence.
                let rc = unsafe { libc::kill(pid, 0) };
                rc == -1
            });
            assert!(gone, "{} went with the helper", pidfile.display());
        }
        assert_eq!(state.spawns.helpers(), 0);
    }

    /// A `/proc/<pid>/stat` line's session: past the last `)` (a `comm` may
    /// hold one), the fourth field; none for a zombie or a line cut short.
    #[test]
    fn a_stat_line_names_its_session() {
        assert_eq!(stat_session("4242 (git) S 4200 4242 4100 0 -1 4194560"), Some(4100));
        assert_eq!(stat_session("4243 (my (odd) name) R 1 4243 4100 0"), Some(4100));
        assert_eq!(stat_session("4244 (git) Z 4200 4244 4100 0"), None, "a zombie");
        assert_eq!(stat_session("4245 (git) S 4200"), None);
        assert_eq!(stat_session("no parenthesis"), None);
    }

    /// A helper that ends without a head is a 500 naming its exit and its
    /// last stderr line (scrubbed); one that prints no JSON is a bad head.
    #[tokio::test]
    async fn a_helper_without_a_head_is_a_failure_naming_its_stderr() {
        let (_t, dir) = home();
        let token = format!("{}-{}-{}-{}", "sk", "ant", "oat01", "b".repeat(40));
        let state = shim(&dir, &format!("echo 'first line' >&2\necho 'ai-env: it broke near {token}' >&2\nexit 3\n"));
        let e = run_op::<SeedState>(&state, cmd("seed-state", Duration::from_secs(20)), None).await.unwrap_err();
        let AgentProcError::Exit { code, stderr } = &e else { panic!("{e:?}") };
        assert_eq!(*code, Some(3));
        let masked = format!("ai-env: it broke near {}-{}-", "sk", "ant");
        assert!(stderr.starts_with(&masked) && !stderr.contains(&token), "the last line, scrubbed: {stderr}");
        let r = e.refusal("seed-state");
        assert!(r.code == refusal::GIT_FAILED && r.message.contains("exit 3"), "{r:?}");
        let state = shim(&dir, "echo 'not json'\n");
        assert!(matches!(run_op::<SeedState>(&state, cmd("seed-state", Duration::from_secs(20)), None).await, Err(AgentProcError::BadHead(_))));
    }

    /// The payload after the head streams as a body of exactly its length,
    /// behind the prefix, through a server that sends its `Content-Length`
    /// and never polls the body past it: the run is finished from its last
    /// read, not killed (what the helper does after its payload is done),
    /// and its hold goes with it.
    #[tokio::test]
    async fn a_payload_streams_behind_its_prefix() {
        let (_t, dir) = home();
        let after = dir.join("after-the-payload");
        let script = format!("printf '{{\"ok\":true,\"reply\":{{}},\"len\":200000}}\\n'\nhead -c 200000 /dev/zero | tr '\\0' x\nsleep 0.3\ntouch '{}'\n", after.display());
        let state = Arc::new(shim(&dir, &script));
        let serving = state.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let state = serving.clone();
                async move {
                    let mut proc = AgentProc::start(&state, cmd("codeout", Duration::from_secs(20))).await.unwrap();
                    let len = proc.head::<SeedState>().await.unwrap().len.unwrap();
                    let mut res = Response::new(proc.into_body(b"prefix\n".to_vec(), len, None));
                    res.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(7 + len));
                    res
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        let end = got.windows(4).position(|w| w == b"\r\n\r\n").expect("a head") + 4;
        let bytes = &got[end..];
        assert_eq!(bytes.len(), 7 + 200_000);
        assert!(bytes.starts_with(b"prefix\nxxx") && bytes.iter().skip(7).all(|b| *b == b'x'));
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while !(after.exists() && state.spawns.helpers() == 0) {
            assert!(std::time::Instant::now() < until, "finished, not killed: after the payload {}, helpers {}", after.exists(), state.spawns.helpers());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// S9 phase 4 (CGI-1, S8's `/codeout`): a payload body dropped early
    /// (the client closed after its first bytes) ends the run at once, the
    /// helper far from its budget, and its hold goes with it.
    #[tokio::test]
    async fn a_payload_body_dropped_early_ends_the_run() {
        let (_t, dir) = home();
        let script = "printf '{\"ok\":true,\"reply\":{},\"len\":200000}\\n'\nhead -c 1000 /dev/zero | tr '\\0' x\nsleep 30\n";
        let state = Arc::new(shim(&dir, script));
        let serving = state.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let state = serving.clone();
                async move {
                    let mut proc = AgentProc::start(&state, cmd("codeout", Duration::from_secs(20))).await.unwrap();
                    let len = proc.head::<SeedState>().await.unwrap().len.unwrap();
                    let mut res = Response::new(proc.into_body(b"prefix\n".to_vec(), len, None));
                    res.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(7 + len));
                    res
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(10).any(|w| w == b"prefix\nxxx") {
            let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await.expect("the payload's first bytes").unwrap();
            assert!(n > 0, "closed early");
            got.extend_from_slice(&buf[..n]);
        }
        drop(s);
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while state.spawns.helpers() != 0 {
            assert!(std::time::Instant::now() < until, "the helper still held 5 s after the body went");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A body the helper stops reading is still read to its end, every
    /// chunk past the helper's exit, so the client gets the answer, not a
    /// reset.
    #[tokio::test]
    async fn a_body_the_helper_stops_reading_is_drained() {
        let (_t, dir) = home();
        let state = shim(&dir, "head -c 10 >/dev/null\nprintf '{\"ok\":false,\"code\":\"bad_pack\",\"message\":\"no\"}\\n'\n");
        let chunks = || Body::from_stream(futures_util::stream::iter((0..48).map(|_| Ok::<_, io::Error>(Bytes::from(vec![b'y'; 64 * 1024])))));
        let mut proc = AgentProc::start(&state, cmd("seed-apply", Duration::from_secs(20))).await.unwrap();
        let stdin = proc.take_stdin();
        let (read, head) = tokio::join!(feed(chunks(), stdin), proc.head::<SeedState>());
        assert_eq!(read, 48 * 64 * 1024, "every chunk read");
        assert_eq!(head.unwrap().outcome().unwrap().unwrap_err().code, refusal::BAD_PACK);
        proc.finish().await.unwrap();
        let head = run_with_body::<SeedState>(&state, cmd("seed-apply", Duration::from_secs(20)), chunks()).await.unwrap();
        let r = head.outcome().unwrap().unwrap_err();
        assert_eq!((r.code.as_str(), r.status()), (refusal::BAD_PACK, 422));
    }

    /// A body that stalls is cut at the budget, which closes the helper's
    /// stdin, and the helper ends by itself on its EOF path within
    /// [`EOF_GRACE`] (here 50 ms of work after the EOF), before any TERM: what
    /// it wrote goes with it (a temp file, F8's DATAPLANE-5). The answer is
    /// still the 504.
    #[tokio::test]
    async fn a_body_cut_at_its_budget_lets_the_helper_end_by_itself() {
        let (_t, dir) = home();
        let (tmp, done) = (dir.join(".ai-env-0123456789abcdef.tmp"), dir.join("eof-path-done"));
        let script = format!(": > '{tmp}'\ncat >/dev/null\nsleep 0.05\nrm -f '{tmp}'\ntouch '{done}'\nprintf '{{\"ok\":false,\"code\":\"bad_request\",\"message\":\"the body ended early\"}}\\n'\n", tmp = tmp.display(), done = done.display());
        let state = shim(&dir, &script);
        let stalled = Body::from_stream(futures_util::stream::once(async { Ok::<_, io::Error>(Bytes::from_static(b"the first bytes")) }).chain(futures_util::stream::pending()));
        let t = std::time::Instant::now();
        let e = run_with_body::<SeedState>(&state, cmd("seed-apply", Duration::from_secs(1)), stalled).await.unwrap_err();
        assert!(matches!(e, AgentProcError::Timeout), "{e:?}");
        assert_eq!(e.refusal("seed-apply").status(), 504);
        assert!(done.exists() && !tmp.exists(), "the helper ended by itself, its temp file removed: done {}, temp file {}", done.exists(), tmp.exists());
        assert!(t.elapsed() < Duration::from_secs(1) + EOF_GRACE + Duration::from_secs(1), "{:?}", t.elapsed());
        assert_eq!(state.spawns.helpers(), 0);
    }

    /// The slot: one holder at a time; a waiter gives up after the wait;
    /// `try_acquire` does not wait; the view names the holder; the record kept.
    #[tokio::test]
    async fn the_workspace_slot_serialises_its_ops() {
        let slot = WorkspaceSlot::default();
        assert_eq!(slot.busy_wait(), budget::BUSY_WAIT);
        slot.set_busy_wait(Duration::from_millis(50));
        let held = slot.acquire("seed-apply").await.unwrap();
        assert_eq!(slot.view(2).busy.as_deref(), Some("seed-apply"));
        assert_eq!(slot.view(2).helpers, 2);
        let t = std::time::Instant::now();
        assert!(slot.acquire("codeout").await.is_none());
        assert!(t.elapsed() >= Duration::from_millis(50));
        assert!(slot.try_acquire("snapshot").is_none());
        drop(held);
        assert!(slot.view(0).busy.is_none());
        assert!(slot.try_acquire("snapshot").is_some());
        let r = busy("codeout", WORKSPACE_HELD, slot.busy_wait());
        assert_eq!(refused(&r).headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()), Some("5"));
        assert_eq!(refused(&r).status(), StatusCode::CONFLICT);
        assert!(r.message.starts_with("another seed, code-out or snapshot holds the workspace (codeout waited 0 s)"), "{r:?}");
    }

    /// No helper starts once the shim stops; without a helper program none
    /// starts at all; either way a body is read to its end first.
    #[tokio::test]
    async fn no_helper_starts_while_the_shim_stops() {
        let (_t, dir) = home();
        let state = shim(&dir, "exit 0\n");
        state.spawns.shutdown("test").await;
        let e = run_op::<SeedState>(&state, cmd("seed-state", Duration::from_secs(5)), None).await.unwrap_err();
        assert!(matches!(e, AgentProcError::Draining));
        assert_eq!(e.refusal("seed-state").status(), 503);
        let none = ShimState::with(PathBuf::from("/nonexistent/claude"), ShimOpts::default(), ProbeSpec::default(), Arc::new(RealSys));
        // S10: `park_v1` is named with or without a helper.
        assert!(!none.serves_workspace() && none.caps() == [crate::wire::frame::CAP_CREDENTIAL_CACHE, crate::wire::frame::CAP_PARK_V1]);
        assert!(matches!(run_op::<SeedState>(&none, cmd("seed-state", Duration::from_secs(5)), None).await, Err(AgentProcError::Spawn(_))));
        // A body for a helper that does not start is still read to its end (the client gets the answer, not a reset).
        for (st, want) in [(&state, "draining"), (&none, "spawn")] {
            let read = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = read.clone();
            let body = Body::from_stream(futures_util::stream::iter(0..16).map(move |_| {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, io::Error>(Bytes::from(vec![b'y'; 64 * 1024]))
            }));
            let e = run_with_body::<SeedState>(st, cmd("seed-apply", Duration::from_secs(5)), body).await.unwrap_err();
            assert!(matches!((&e, want), (AgentProcError::Draining, "draining") | (AgentProcError::Spawn(_), "spawn")), "{e:?}");
            assert_eq!(read.load(std::sync::atomic::Ordering::SeqCst), 16, "{want}: the body was read");
        }
    }

    /// S10: an op in the payload form (`seed-state`): the head names the
    /// payload's length and sha256, the reply parses from those bytes, and
    /// the helper is reaped before the run returns (no helper left, though
    /// it lingers after its last byte); a payload other than the one
    /// announced is 500 `git_failed`; a refusal is the helper's own.
    #[tokio::test]
    async fn a_payload_run_reads_its_reply_and_reaps_the_helper() {
        use sha2::Digest as _;
        let reply = r#"{"tip":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0","clean":true,"pristine":false,"shallow":["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"]}"#;
        let script = |sha: &str| format!("printf '%s\\n' '{{\"ok\":true,\"reply\":{{\"sha256\":\"{sha}\"}},\"len\":{}}}'\nprintf '%s' '{reply}'\nsleep 0.3\n", reply.len());
        let (_t, dir) = home();
        let state = shim(&dir, &script(&hex::encode(sha2::Sha256::digest(reply.as_bytes()))));
        let st = run_op_payload::<SeedState>(&state, cmd("seed-state", Duration::from_secs(20))).await.unwrap();
        assert_eq!(st.shallow, Some(vec!["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0".to_string()]));
        assert_eq!(state.spawns.helpers(), 0, "reaped before the reply");
        let (_t, dir) = home();
        let other = shim(&dir, &script(&"0".repeat(64)));
        let r = run_op_payload::<SeedState>(&other, cmd("seed-state", Duration::from_secs(20))).await.unwrap_err();
        assert!(r.code == refusal::GIT_FAILED && r.message.contains("not the one announced"), "{r:?}");
        let (_t, dir) = home();
        let refusing = shim(&dir, "printf '%s\\n' '{\"ok\":false,\"code\":\"other_workspace\",\"message\":\"the VM was seeded at /w2\"}'\n");
        assert_eq!(run_op_payload::<SeedState>(&refusing, cmd("seed-state", Duration::from_secs(20))).await.unwrap_err().code, refusal::OTHER_WORKSPACE);
    }

    /// A record of the workspace `/Users/agent/ws` (two ids of sha1).
    fn record() -> SeedRecord {
        SeedRecord {
            path: "/Users/agent/ws".into(),
            mode: crate::wire::workspace::SeedMode::Clone,
            branch: Some("main".into()),
            head: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0".into(),
            wip: Some("b".repeat(40)),
            wip_tree: Some("c".repeat(40)),
            index_tree: Some("d".repeat(40)),
            object_format: crate::wire::workspace::ObjectFormat::Sha1,
            at: "2026-10-20T08:00:00Z".into(),
        }
    }

    /// S10 (W3 #2): a store under the fs root, the agent's home beneath it.
    fn store_in(root: &Path) -> RecordStore {
        let opts = ShimOpts { fs_root: Some(root.join("vm")), home: root.join("vm/Users/agent"), ..ShimOpts::default() };
        RecordStore::for_shim(&opts).expect("a store under the fs root")
    }

    /// S10 (W3 #2): the record file is written atomically (no temp file
    /// left), 0600 in a 0700 directory, `{"v":1,"record":…}` with the
    /// record's own keys, and read back by a new slot; a shim with neither
    /// an fs root nor root's uid keeps none (it never touches this
    /// machine's `/var/lib`). The keys a record writes are the ones a file's
    /// record may hold.
    #[test]
    fn the_seed_record_is_written_atomically_and_read_back() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_t, dir) = home();
        let store = store_in(&dir);
        assert_eq!(store.path(), dir.join("vm/var/lib/ai-env/seed-record.json"));
        let slot = WorkspaceSlot::persisted(Some(store.clone()));
        assert_eq!(slot.record(), None, "no file: never seeded");
        slot.set_record(record());
        let text = std::fs::read_to_string(store.path()).unwrap();
        assert_eq!(text, format!("{{\"v\":1,\"record\":{}}}\n", serde_json::to_string(&record()).unwrap()));
        assert_eq!(std::fs::metadata(store.path()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(store.path().parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        let left: Vec<_> = std::fs::read_dir(store.path().parent().unwrap()).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, [std::ffi::OsString::from("seed-record.json")], "no temp file left");
        assert_eq!(WorkspaceSlot::persisted(Some(store.clone())).record(), Some(record()), "a restarted shim's slot");
        let mut later = record();
        later.mode = crate::wire::workspace::SeedMode::Update;
        later.head = "e".repeat(40);
        slot.set_record(later.clone());
        assert_eq!(store.load(), Some(later), "replaced whole");
        let keys: std::collections::BTreeSet<String> = serde_json::to_value(record()).unwrap().as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, SEED_RECORD_KEYS.iter().map(|k| (*k).to_string()).collect(), "every key a full record writes");
        if !nix::unistd::geteuid().is_root() {
            assert_eq!(RecordStore::for_shim(&ShimOpts::default()), None);
        }
    }

    /// S10 (W3 #2): a file failing any check is ignored, and a record the
    /// load would refuse is never written (kept in memory only, the file of
    /// the seed before it removed, so a restart finds no record): another
    /// version, an unknown key outside or inside the record, a record that
    /// does not parse, a path that is not a VM path or not under the home
    /// (or is the home itself), a bad branch, an id of another format or
    /// none; a file that is no regular file or too large.
    #[test]
    fn a_seed_record_file_failing_a_check_is_ignored() {
        let (_t, dir) = home();
        let store = store_in(&dir);
        std::fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        let good = serde_json::to_value(record()).unwrap();
        let with = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut file = serde_json::json!({"v": 1, "record": good.clone()});
            f(&mut file);
            file.to_string()
        };
        let cases: Vec<(&str, String)> = vec![
            ("v 2", with(&|f| f["v"] = 2.into())),
            ("an unknown key", with(&|f| f["extra"] = true.into())),
            ("an unknown record key", with(&|f| f["record"]["extra"] = true.into())),
            ("no record", serde_json::json!({"v": 1}).to_string()),
            ("a record without its head", with(&|f| drop(f["record"].as_object_mut().unwrap().remove("head")))),
            ("a relative path", with(&|f| f["record"]["path"] = "Users/agent/ws".into())),
            ("a dotdot path", with(&|f| f["record"]["path"] = "/Users/agent/../agent/ws".into())),
            ("a path outside the home", with(&|f| f["record"]["path"] = "/Users/other/ws".into())),
            ("the home itself", with(&|f| f["record"]["path"] = "/Users/agent".into())),
            ("a bad branch", with(&|f| f["record"]["branch"] = "-x".into())),
            ("a short head", with(&|f| f["record"]["head"] = "a1b2".into())),
            ("a sha256 wip in a sha1 record", with(&|f| f["record"]["wip"] = "b".repeat(64).into())),
            ("an index tree that is no id", with(&|f| f["record"]["index_tree"] = "HEAD".into())),
            ("not JSON", "{\"v\":1,".into()),
        ];
        for (what, text) in &cases {
            std::fs::write(store.path(), text).unwrap();
            assert_eq!(store.load(), None, "{what}: {text}");
        }
        std::fs::write(store.path(), with(&|_| {})).unwrap();
        assert_eq!(store.load(), Some(record()), "the good one reads");
        std::fs::write(store.path(), format!("{}{}", with(&|_| {}), " ".repeat(SEED_RECORD_MAX as usize))).unwrap();
        assert_eq!(store.load(), None, "too large");
        std::fs::remove_file(store.path()).unwrap();
        std::fs::create_dir(store.path()).unwrap();
        assert_eq!(store.load(), None, "a directory");
        std::fs::remove_dir(store.path()).unwrap();
        let slot = WorkspaceSlot::persisted(Some(store.clone()));
        let mut bad = record();
        bad.path = "/Users/other/ws".into();
        slot.set_record(bad.clone());
        assert_eq!((slot.record(), store.path().exists()), (Some(bad), false), "kept in memory only, never written");
        slot.set_record(record());
        assert_eq!(store.load(), Some(record()));
        let mut refused = record();
        refused.branch = Some("-x".into());
        slot.set_record(refused.clone());
        assert_eq!((slot.record(), store.path().exists()), (Some(refused), false), "in memory only, the older file removed");
        assert_eq!(WorkspaceSlot::persisted(Some(store)).record(), None, "a restarted shim has no record, not the older one");
    }
}
