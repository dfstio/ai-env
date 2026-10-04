//! Everything across sockets for one spawn (plan S6): [`run`] mints a
//! `Port(8080)` token, dials, says `hello` (resuming the spawn it already
//! has), starts or reattaches the spawn, and serves it until the exit is
//! delivered, reconnecting as often as the reconnect rules allow. A
//! `--shell` row's target is refused first, before any mint or dial
//! (`Policy`, exit 9: the platform shell's in-VM listener is outside the
//! shim's guard, D1).
//!
//! - **Stdio.** stdin is chunked (`wire::chunk::Chunker`), numbered from 1
//!   (`Start::Attach`: after the shim's `in_seq`, so no input is taken
//!   before the first `hello_ok`) and kept until `stdin_ack`; the session
//!   stops taking input while `STDIN_WINDOW_BYTES` are unacked and never has
//!   more than that in flight; after a reattach everything above
//!   `hello_ok`'s `in_seq` is sent again. A frame leaves its queue (stdin,
//!   signals, the detach) only once its send succeeded. stdout and stderr
//!   are delivered once, in order, by seq (a replay's duplicates are dropped;
//!   a stdout seq that skips one is a protocol error); acks carry only what
//!   the consumer marked in `Consumed`, at least every `ack_bytes` or
//!   `ack_every`. Each socket has a reader task that never waits on the
//!   consumer. The events hold at most the shim's stdout window and
//!   `STDERR_BUFFER_BYTES` of stderr the consumer has not marked: newer
//!   stderr is dropped meanwhile and counted in `dropped`, as the shim drops
//!   its oldest.
//! - **Liveness.** While the spawn is attached and unfinished: an app `ping`
//!   every `ping`, a WebSocket Ping every `ws_ping`, and under
//!   `Keepalive::Http` a bearer-less `GET /health` every `keepalive_every`
//!   (failures only logged). No inbound message for `dead_after`, or a wall
//!   clock that ran `dead_after` ahead of `Instant` (a laptop sleep), loses
//!   the socket.
//! - **Reconnect.** Backoff `backoff_min`..`backoff_max` ×2 ±25 % (getrandom),
//!   reset once the spawn was carried `stable_after` without a break (a
//!   rotation's socket continues the old one's time), everything within
//!   `reconnect_budget`. A mint that fails (the network still waking) is a
//!   failed attempt like a refused dial, unless the VM is gone; past the
//!   budget its own error ends the session. 401/403: one re-mint, the second is
//!   `TokenRejected` (exit 7). 429: wait max(Retry-After, backoff), never
//!   re-mint, audit `endpoint_429`. 503 `not_run`: every `backoff_min` for
//!   `not_run_budget`, then `ShimUnavailable`; `draining`: `Terminated`.
//!   404: `NoAgent`. 502 or no connection asks GetMicrovm: gone →
//!   `VmNotFound`/`Terminated`; SUSPENDED without auto-resume → one
//!   ResumeMicrovm (a Conflict is a resume already under way) and up to 60 s
//!   for RUNNING; PENDING → up to 60 s; otherwise keep backing off.
//! - **Tokens.** Wall-clock expiry (Darwin's `Instant` stops during sleep):
//!   a fresh token before any dial with less than `remint_below` left, and on
//!   any tick (the keep-alive presents it; a failed mint there never ends a
//!   live socket). `Rotation::Proactive`: at expiry minus `rotate_before` a
//!   second socket with a fresh token says `hello` with the resume; from that
//!   hello on spawn frames wait for it, the old socket's `superseded` is
//!   ignored, and the old socket is closed 1000 after the new `hello_ok`. A
//!   hello without an answer is a lost socket (the shim may have moved the
//!   spawn already): reconnect with the resume. The second socket's dial
//!   follows the reconnect rules while the old one serves: a 429 waits its
//!   Retry-After (audited), the token is kept across attempts, a 401/403
//!   spends the one re-mint and a second stops rotating on that socket.
//!   `Rotation::Lazy`: no second socket; the next reconnect uses the fresh token.
//! - **Suspend.** After `event hook_suspend` the session never dials on its
//!   own: it polls GetMicrovm every 3 s and reattaches once RUNNING, or gives
//!   up after `suspend_wait` naming `ai-env vm resume` and `ai-env vm attach`
//!   (exit 8). `event hook_terminate` is `Terminated`.
//! - **End.** `exit` is delivered as `SpawnEvent::Exit`; once the consumer
//!   marked every chunk this session delivered (at most `dead_after`) the
//!   exit's seq is acked, which releases the spawn, and the socket is closed 1000.
//! - **Records.** Audit rows `endpoint_429` (retry_after, waited_ms: the wait
//!   the 429 set; written at the 429, before that wait, so also when the 429
//!   ends the session or a detach cuts its wait short), `agent_reconnect`
//!   (reason, ms), `agent_rotate` (mode), `agent_remint` (reason);
//!   `SpawnEvent::Note` lines for the operator, each loss, reattach or spawn
//!   sent again followed by a `SpawnEvent::Link`; TRACE in `conn`.
use super::conn::{close_text, Activity, AgentConn, AgentReceiver, AgentSender, HelloOk, Trace, CLOSE_WAIT};
use super::{AgentEnv, RemoteExit, RunPolicy, SpawnEvent, SpawnInput, SpawnIo, SpawnOutcome, SpawnSpec, Start};
use crate::bridge::api::{AuthToken, EndpointClient, HealthReply, MicrovmApi, VmInfo, VmState, APP_PORT};
use crate::bridge::config::{Keepalive, Rotation};
use crate::bridge::errors::BridgeError;
use crate::bridge::transport::DialError;
use crate::bridge::vm::cmd::audit_event;
use crate::bridge::vm::token::mint;
use crate::wire::chunk::{decode, raw_len, Chunker};
use crate::wire::frame::{Chunk, Deliver, ErrorCode, EventKind, Frame, ResumePoint, ResumeStatus, Scope, Sig, SpawnErrCode, SpawnId, SpawnStatus, CLOSE_NORMAL, STDERR_BUFFER_BYTES, STDIN_WINDOW_BYTES};
use crate::wire::redact::scrub;
use futures_util::future::BoxFuture;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// [`super::run_spawn`]'s body (see the module doc).
pub async fn run<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>, start: Start, io: SpawnIo) -> Result<SpawnOutcome, BridgeError> {
    // D1, for every caller (`vm exec` and `vm attach` refuse such rows before any call too).
    if env.target.shell {
        return Err(BridgeError::Policy(format!(
            "{} was started with --shell: no command runs on it until the platform shell's in-VM listener, which the shim does not guard, is shown unreachable from the agent (ai-env lab run in-vm-firewall measures it); start a VM without --shell",
            env.target.vm_id
        )));
    }
    crate::wire::redact::register_secret(env.target.session_token.expose());
    let token = mint_token(env).await?;
    let mut session = Session { env, io, trace: Trace::from_env(env.paths), token, st: State::new(start), attached: false, paused: false, control_open: true };
    session.run().await
}

/// How one socket's service ended.
enum End {
    /// The remote exit (its seq) was delivered.
    Exited(u64, RemoteExit),
    /// The socket is gone (why); reconnect.
    Lost(String),
    /// `event hook_suspend`: wait for RUNNING without dialing.
    Suspended,
    /// The consumer's `detach` went out.
    Detached,
}

/// What a socket's reader task reports.
enum Inbound {
    Frame(Frame),
    /// The socket ended (the peer's Close, EOF, a read error): why.
    Ended(String),
    /// Input the wire forbids (binary, malformed, another version).
    Bad(String),
}

/// One socket in service: its sender, and a reader task whose frames queue
/// in `inbound` (bounded in practice by the shim's windows).
struct Link {
    n: u64,
    tx: AgentSender,
    inbound: mpsc::UnboundedReceiver<Inbound>,
    reader: tokio::task::JoinHandle<()>,
    activity: Activity,
    /// The first send that failed: the socket is lost.
    broken: Option<String>,
}

impl Link {
    fn start(conn: AgentConn) -> Link {
        let (n, activity) = (conn.number(), conn.activity());
        let (tx, rx) = conn.split();
        let (sink, inbound) = mpsc::unbounded_channel();
        Link { n, tx, inbound, reader: tokio::spawn(read_all(rx, sink)), activity, broken: None }
    }

    /// Send `frame` unless an earlier send failed (a failure lands in
    /// `broken`); whether it went out.
    async fn send(&mut self, frame: &Frame) -> bool {
        if self.broken.is_none() {
            if let Err(e) = self.tx.send(frame).await {
                self.broken = Some(e.to_string());
            }
        }
        self.broken.is_none()
    }

    async fn ws_ping(&mut self) {
        if self.broken.is_none() {
            if let Err(e) = self.tx.ping().await {
                self.broken = Some(e.to_string());
            }
        }
    }

    /// Close with `code`, give the reader [`CLOSE_WAIT`] to see the peer's Close, then stop it.
    async fn close(mut self, code: u16) {
        self.tx.close(code).await;
        let _ = tokio::time::timeout(CLOSE_WAIT, &mut self.reader).await;
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// A socket's reader: every frame into `sink` until the socket ends. A
/// dropped `sink` (a replaced socket) stops only the forwarding: reading
/// goes on, so the close handshake completes.
async fn read_all(mut rx: AgentReceiver, sink: mpsc::UnboundedSender<Inbound>) {
    loop {
        let report = match rx.recv().await {
            Ok(Some(frame)) => {
                let _ = sink.send(Inbound::Frame(frame));
                continue;
            }
            Ok(None) => Inbound::Ended(format!("the socket closed{}", close_text(rx.close_frame().as_ref()))),
            Err(BridgeError::Protocol(m)) => Inbound::Bad(m),
            Err(BridgeError::Transport(m)) => Inbound::Ended(m),
            Err(e) => Inbound::Ended(e.to_string()),
        };
        let _ = sink.send(report);
        return;
    }
}

/// Where the spawn stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// `Start::New` before any `spawn` went out.
    ToSpawn,
    /// `spawn` went out; a lost socket may or may not have started it.
    SpawnSent,
    Running,
}

/// One spawn's bookkeeping across sockets.
struct State {
    id: SpawnId,
    spec: Option<SpawnSpec>,
    phase: Phase,
    /// `spawn` went out again, on a socket whose resume the shim answered `unknown`.
    resent: bool,
    started: bool,
    /// The last stdout seq delivered; `out_known` once the stream's position
    /// is fixed (always for a new spawn; for `Start::Attach` without
    /// `from_seq`, at its first chunk).
    out: u64,
    out_known: bool,
    err: u64,
    err_known: bool,
    /// The last stdout and stderr seq this session handed to the consumer
    /// (0: none; the position `vm attach --from-seq` starts at is no delivery).
    delivered: (u64, u64),
    /// Delivered chunks not yet counted as consumed: (seq, bytes).
    out_lens: VecDeque<(u64, u64)>,
    err_lens: VecDeque<(u64, u64)>,
    /// Bytes consumed since the last ack.
    consumed_bytes: u64,
    /// stderr bytes delivered and not yet marked consumed, and the stderr
    /// bytes dropped while that stood at `STDERR_BUFFER_BYTES`.
    err_unconsumed: u64,
    err_dropped: u64,
    /// The last ack sent on this socket (stdout, stderr).
    acked: (u64, u64),
    chunker: Chunker,
    /// The stdin numbering is fixed: from 1 for a new spawn; for
    /// `Start::Attach` once the first `hello_ok` gave the shim's `in_seq`
    /// (input waits in its channel until then).
    in_base: bool,
    /// The last stdin seq assigned.
    next_in: u64,
    /// stdin not yet acked: (seq, chunk, bytes), seq order.
    pending: VecDeque<(u64, Chunk, u64)>,
    pending_bytes: u64,
    /// The highest seq sent on this socket, and the bytes of `pending` at or below it.
    sent_in: u64,
    inflight: u64,
    /// `stdin_eof`'s seq once the consumer closed stdin.
    eof: Option<u64>,
    eof_sent: bool,
    /// The remote's stdin is already closed (`vm attach` to such a spawn).
    remote_stdin_closed: bool,
    input_open: bool,
    signals: VecDeque<Sig>,
    detach: Option<bool>,
    detach_sent: bool,
}

impl State {
    fn new(start: Start) -> State {
        let base = |id: SpawnId, spec: Option<SpawnSpec>, phase: Phase| State {
            id,
            spec,
            phase,
            resent: false,
            started: false,
            out: 0,
            out_known: true,
            err: 0,
            err_known: true,
            delivered: (0, 0),
            out_lens: VecDeque::new(),
            err_lens: VecDeque::new(),
            consumed_bytes: 0,
            err_unconsumed: 0,
            err_dropped: 0,
            acked: (0, 0),
            chunker: Chunker::new(),
            in_base: true,
            next_in: 0,
            pending: VecDeque::new(),
            pending_bytes: 0,
            sent_in: 0,
            inflight: 0,
            eof: None,
            eof_sent: false,
            remote_stdin_closed: false,
            input_open: true,
            signals: VecDeque::new(),
            detach: None,
            detach_sent: false,
        };
        match start {
            Start::New(spec) => base(SpawnId::new_v7(), Some(spec), Phase::ToSpawn),
            Start::Attach { spawn_id, from_seq, err_from_seq } => State {
                out: from_seq.map_or(0, |s| s.saturating_sub(1)),
                out_known: from_seq.is_some(),
                err: err_from_seq.map_or(0, |s| s.saturating_sub(1)),
                err_known: err_from_seq.is_some(),
                in_base: false,
                ..base(spawn_id, None, Phase::Running)
            },
        }
    }

    /// The resume point of a `hello` (nothing before the first `spawn`).
    fn resume(&self) -> Vec<ResumePoint> {
        if self.phase == Phase::ToSpawn {
            return Vec::new();
        }
        vec![ResumePoint { spawn_id: self.id.clone(), from_seq: self.out_known.then_some(self.out + 1), err_from_seq: self.err_known.then_some(self.err + 1) }]
    }

    fn wants_input(&self) -> bool {
        self.input_open && self.in_base && self.pending_bytes < STDIN_WINDOW_BYTES
    }

    /// Queue one consumer input.
    fn take(&mut self, input: SpawnInput) {
        match input {
            SpawnInput::Stdin(bytes) if self.eof.is_none() && !self.remote_stdin_closed => {
                for chunk in self.chunker.push(&bytes) {
                    self.push(chunk);
                }
            }
            SpawnInput::Stdin(_) => {}
            SpawnInput::StdinEof => {
                if self.eof.is_none() {
                    if let Some(tail) = self.chunker.finish() {
                        self.push(tail);
                    }
                    self.eof = Some(self.next_in);
                }
            }
            SpawnInput::Signal(sig) => self.signals.push_back(sig),
            SpawnInput::Detach { is_final } => self.detach = Some(is_final),
        }
    }

    fn push(&mut self, chunk: Chunk) {
        let len = raw_len(&chunk).unwrap_or(0) as u64;
        self.next_in += 1;
        self.pending.push_back((self.next_in, chunk, len));
        self.pending_bytes += len;
    }

    /// The next stdin chunk to send, if the shim's window has room for it.
    fn next_stdin(&self) -> Option<(u64, Chunk, u64)> {
        let at = self.pending.partition_point(|(seq, _, _)| *seq <= self.sent_in);
        let (seq, chunk, len) = self.pending.get(at)?;
        (self.inflight + len <= STDIN_WINDOW_BYTES).then(|| (*seq, chunk.clone(), *len))
    }

    fn stdin_acked(&mut self, seq: u64) {
        while self.pending.front().is_some_and(|(s, _, _)| *s <= seq) {
            let Some((s, _, len)) = self.pending.pop_front() else { break };
            self.pending_bytes -= len;
            if s <= self.sent_in {
                self.inflight -= len;
            }
        }
    }

    /// A socket that resumed the spawn: the shim holds stdin up to `in_seq`
    /// (anything above goes again), and knows nothing of this socket's acks.
    fn reattached(&mut self, status: Option<&SpawnStatus>) {
        let in_seq = status.map_or(0, |s| s.in_seq);
        // `vm attach`: this client's stdin continues the shim's numbering
        // (none of it was numbered before: `in_base` held the input back).
        self.next_in = self.next_in.max(in_seq);
        self.in_base = true;
        self.sent_in = in_seq;
        self.inflight = self.pending.iter().take_while(|(seq, _, _)| *seq <= in_seq).map(|(_, _, len)| len).sum();
        self.remote_stdin_closed = status.is_some_and(|s| s.stdin_closed);
        self.eof_sent = self.remote_stdin_closed;
        if self.remote_stdin_closed {
            self.pending.clear();
            self.pending_bytes = 0;
            self.inflight = 0;
        }
        self.acked = (0, 0);
    }

    /// Count what the consumer marked (`out`, `err` capped at what was delivered).
    fn count_consumed(&mut self, out: u64, err: u64) {
        while let Some(&(_, len)) = self.out_lens.front().filter(|(seq, _)| *seq <= out) {
            self.out_lens.pop_front();
            self.consumed_bytes += len;
        }
        while let Some(&(_, len)) = self.err_lens.front().filter(|(seq, _)| *seq <= err) {
            self.err_lens.pop_front();
            self.consumed_bytes += len;
            self.err_unconsumed -= len;
        }
    }
}

/// The waits of one reconnect episode (from a socket's loss, or the first dial).
struct Retry {
    since: Instant,
    step: Duration,
    /// The one re-mint after a 401/403 is spent (until a hello succeeds).
    reminted: bool,
    not_run_since: Option<Instant>,
    /// The one ResumeMicrovm is spent.
    resumed: bool,
    /// The last failure, and its Retry-After when it was a 429.
    last: String,
    throttled: Option<Option<u64>>,
    /// The last failure was a mint: past the budget its error ends the session.
    no_token: Option<BridgeError>,
}

impl Retry {
    fn new(p: &RunPolicy) -> Retry {
        Retry { since: Instant::now(), step: p.backoff_min, reminted: false, not_run_since: None, resumed: false, last: String::new(), throttled: None, no_token: None }
    }

    fn failed(&mut self, why: String) {
        self.last = why;
        self.throttled = None;
        self.no_token = None;
    }

    /// The next backoff: the step ±25 %; the step then doubles, up to `backoff_max`.
    fn next(&mut self, p: &RunPolicy) -> Duration {
        let wait = jittered(self.step);
        self.step = self.step.saturating_mul(2).min(p.backoff_max);
        wait
    }
}

/// `d` × [0.75, 1.25), from getrandom.
fn jittered(d: Duration) -> Duration {
    let r = getrandom::u32().unwrap_or(u32::MAX / 2);
    d.mul_f64(0.75 + 0.5 * f64::from(r) / (f64::from(u32::MAX) + 1.0))
}

/// What a proactive rotation brings: the new token, its socket, and that socket's `hello_ok`.
struct Rotated {
    token: AuthToken,
    conn: AgentConn,
    ok: HelloOk,
}

/// How one step of a proactive rotation ended.
enum RotationStep {
    /// The second socket is up (with its token): its `hello` comes next.
    Dialed(AuthToken, AgentConn),
    /// Its `hello_ok`: it takes over.
    Answered(Box<Rotated>),
    /// No new socket; the token it used, kept for the next attempt.
    Failed(Option<AuthToken>, RotationFailed),
}

/// Why a rotation attempt failed.
enum RotationFailed {
    Mint(String),
    Dial(DialError),
    /// `hello_err` on the new socket: the shim left the spawn where it was.
    Refused(String),
    /// The `hello` went out and no `hello_ok` came: the shim may have moved the spawn.
    Unanswered(String),
}

impl std::fmt::Display for RotationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotationFailed::Mint(m) => write!(f, "mint: {m}"),
            RotationFailed::Dial(e) => write!(f, "dial: {e}"),
            RotationFailed::Refused(m) | RotationFailed::Unanswered(m) => write!(f, "hello: {m}"),
        }
    }
}

/// Proactive rotation on one socket: the step under way, when the next
/// attempt may start, the token kept for it, and the reconnect rules its
/// dials follow (backoff, the one re-mint after a 401/403).
struct Rotating<'a> {
    step: Option<BoxFuture<'a, RotationStep>>,
    after: Option<Instant>,
    /// A 429 or a failed connect never costs a fresh token.
    token: Option<AuthToken>,
    retry: Retry,
    /// The old socket heard `superseded` while the new one's `hello` was out.
    superseded: bool,
    /// A second 401/403: no more attempts on this socket (when it ends, the
    /// reconnect's own 401/403 rule applies).
    stopped: bool,
}

impl Rotating<'_> {
    fn new(p: &RunPolicy) -> Self {
        Rotating { step: None, after: None, token: None, retry: Retry::new(p), superseded: false, stopped: false }
    }

    /// An attempt may start now (once the token is within `rotate_before`).
    fn due(&self) -> bool {
        self.step.is_none() && !self.stopped && self.after.is_none_or(|t| Instant::now() >= t)
    }
}

struct Session<'e, 'a, A: MicrovmApi, E: EndpointClient> {
    env: &'e AgentEnv<'a, A, E>,
    io: SpawnIo,
    trace: Trace,
    token: AuthToken,
    st: State,
    /// The current socket carries the spawn (after `spawned`, or a `hello_ok` that resumed it).
    attached: bool,
    /// A rotation's `hello` is out (the shim may move the spawn to its
    /// socket any moment): spawn frames wait for the new socket.
    paused: bool,
    control_open: bool,
}

impl<'a, A: MicrovmApi, E: EndpointClient> Session<'_, 'a, A, E> {
    async fn run(&mut self) -> Result<SpawnOutcome, BridgeError> {
        let mut retry = Retry::new(&self.env.policy);
        let mut lost: Option<(Instant, String)> = None;
        loop {
            let mut link = self.connect(&mut retry).await?;
            // The stability clock: a rotation swaps the socket without a break, so it runs on.
            let carried = Instant::now();
            if let Some((at, why)) = lost.take() {
                let ms = at.elapsed().as_millis().to_string();
                // Still `SpawnSent`: the resume found no such spawn and `adopt` sent it again; nothing was reattached.
                if self.st.phase == Phase::SpawnSent {
                    self.note(format!("sent spawn {} again after {ms} ms (socket {}): the VM did not hold it", self.st.id, link.n));
                } else {
                    self.note(format!("reattached to spawn {} after {ms} ms (socket {})", self.st.id, link.n));
                }
                self.link(true);
                self.audit("agent_reconnect", &[("reason", why), ("ms", ms)]);
            }
            match self.serve(&mut link).await? {
                End::Exited(seq, exit) => return Ok(self.finish(link, seq, exit).await),
                End::Detached => {
                    link.close(CLOSE_NORMAL).await;
                    return Err(BridgeError::Transport(format!("detached from spawn {}", self.st.id)));
                }
                End::Lost(why) => {
                    if carried.elapsed() >= self.env.policy.stable_after {
                        retry = Retry::new(&self.env.policy);
                    }
                    drop(link);
                    retry.failed(why.clone());
                    let wait = retry.next(&self.env.policy);
                    self.note(format!("lost the connection to {} ({why}); reconnecting", self.vm()));
                    self.link(false);
                    self.give_up_past(&mut retry, wait)?;
                    lost = Some((Instant::now(), why));
                    self.pause(wait).await?;
                }
                End::Suspended => {
                    link.close(CLOSE_NORMAL).await;
                    self.wait_resumed().await?;
                    retry = Retry::new(&self.env.policy);
                    lost = Some((Instant::now(), "suspended".into()));
                }
            }
        }
    }

    // ---- connecting ---------------------------------------------------------------------

    /// Dial and `hello` until a socket carries the spawn (or the rules give up).
    async fn connect(&mut self, retry: &mut Retry) -> Result<Link, BridgeError> {
        let env = self.env;
        loop {
            // An expired token cannot dial: a mint that failed then (the
            // network still waking after a sleep) is a failed attempt.
            if let Some(e) = self.freshen().await?.filter(|_| self.token_left().is_zero()) {
                self.mint_failed(e, retry).await?;
                continue;
            }
            let token = self.token.value()?.clone();
            // A detach while the dial or the hello is under way ends the
            // session there: the spawn is never sent (signals are queued).
            let mut conn = match self.watching(AgentConn::open(&env.dial, &env.target.endpoint, &token)).await? {
                Ok(conn) => conn.with_trace(self.trace.clone()),
                Err(e) => {
                    self.dial_failed(e, retry).await?;
                    continue;
                }
            };
            let resume = self.st.resume();
            match self.watching(tokio::time::timeout(env.policy.dead_after, conn.hello(&env.target.session_token, resume, env.policy.idle_s))).await? {
                Ok(Ok(ok)) => {
                    retry.reminted = false;
                    retry.not_run_since = None;
                    let mut link = Link::start(conn);
                    // A rotation in flight when the last socket was lost died with it.
                    (self.attached, self.paused) = (false, false);
                    self.adopt(&ok, &mut link).await?;
                    match link.broken.take() {
                        None => return Ok(link),
                        Some(why) => retry.failed(why),
                    }
                }
                Ok(Err(BridgeError::HelloRefused { code, message })) if code == "busy" => retry.failed(format!("hello_err busy: {message}")),
                Ok(Err(BridgeError::Transport(m))) => retry.failed(m),
                Ok(Err(e)) => return Err(e),
                Err(_) => retry.failed(format!("no hello_ok within {}", secs(env.policy.dead_after))),
            }
            let wait = retry.next(&env.policy);
            self.give_up_past(retry, wait)?;
            self.pause(wait).await?;
        }
    }

    /// A refused or failed dial: wait, re-mint or give up, per the reconnect rules.
    async fn dial_failed(&mut self, e: DialError, retry: &mut Retry) -> Result<(), BridgeError> {
        let env = self.env;
        let p = &env.policy;
        tracing::info!("vm {}: /agent dial: {e}", self.vm());
        match e {
            DialError::TokenRejected { status, proxy_error } => {
                if retry.reminted {
                    return Err(BridgeError::TokenRejected { port: APP_PORT, status, proxy_error });
                }
                match self.remint("token_rejected").await {
                    Ok(()) => {
                        retry.reminted = true;
                        Ok(())
                    }
                    Err(e) => self.mint_failed(e, retry).await,
                }
            }
            DialError::Throttled { retry_after_s } => {
                let backoff = retry.next(p);
                let wait = retry_after_s.map_or(backoff, |s| units(p, s).max(backoff));
                // Audited before the budget and the wait: a 429 that ends the session, or whose wait a detach cuts short, has its row too.
                let retry_after = retry_after_s.map_or_else(|| "none".to_string(), |s| s.to_string());
                self.audit("endpoint_429", &[("retry_after", retry_after), ("waited_ms", wait.as_millis().to_string())]);
                retry.failed(e.to_string());
                retry.throttled = Some(retry_after_s);
                self.give_up_past(retry, wait)?;
                self.note(format!("the endpoint throttled /agent (HTTP 429); retrying in {}", secs(wait)));
                self.pause(wait).await
            }
            DialError::NotRun => {
                let since = *retry.not_run_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= p.not_run_budget {
                    return Err(BridgeError::ShimUnavailable(format!("{}: its /run hook has not returned after {} (HTTP 503 not_run)", self.vm(), secs(p.not_run_budget))));
                }
                retry.failed(e.to_string());
                self.pause(p.backoff_min).await
            }
            DialError::Draining => Err(BridgeError::Terminated(format!("{}: the shim is draining (the VM is terminating)", self.vm()))),
            DialError::NoAgent => Err(BridgeError::NoAgent(format!("{}: HTTP 404 on /agent", self.vm()))),
            DialError::Http { status, body } if status < 500 => Err(BridgeError::Http { status, body }),
            DialError::Tls(m) => Err(BridgeError::Endpoint(format!("TLS to {}: {m}", env.target.endpoint))),
            DialError::Handshake(m) => Err(BridgeError::Endpoint(format!("the /agent handshake with {} failed: {m}", env.target.endpoint))),
            DialError::Busy => {
                retry.failed(e.to_string());
                let wait = retry.next(p);
                self.give_up_past(retry, wait)?;
                self.pause(wait).await
            }
            DialError::Gateway { .. } | DialError::Connect(_) | DialError::Http { .. } => {
                retry.failed(e.to_string());
                if self.check_vm(retry).await? {
                    return Ok(());
                }
                let wait = retry.next(p);
                self.give_up_past(retry, wait)?;
                self.pause(wait).await
            }
        }
    }

    /// 502 or no connection: what GetMicrovm says. `Ok(true)`: the VM just
    /// became RUNNING (redial at once); `Ok(false)`: keep backing off.
    async fn check_vm(&mut self, retry: &mut Retry) -> Result<bool, BridgeError> {
        let vm = match self.env.api.get(self.vm()).await {
            Ok(vm) => vm,
            Err(e @ BridgeError::VmNotFound(_)) => return Err(e),
            Err(e) => {
                tracing::warn!("vm {}: GetMicrovm after a failed dial: {e}", self.vm());
                return Ok(false);
            }
        };
        match vm.state {
            ref s if s.is_terminal() => Err(terminated(&vm)),
            VmState::Suspended | VmState::Suspending if auto_resume(&vm) => Ok(false),
            VmState::Pending | VmState::Suspended | VmState::Suspending => self.wait_running(retry).await.map(|()| true),
            _ => Ok(false),
        }
    }

    /// Up to 60 s for RUNNING; a SUSPENDED VM without auto-resume gets one
    /// ResumeMicrovm (a Conflict means a resume is already under way).
    async fn wait_running(&mut self, retry: &mut Retry) -> Result<(), BridgeError> {
        let limit = units(&self.env.policy, 60);
        let start = Instant::now();
        loop {
            let seen = match self.env.api.get(self.vm()).await {
                Ok(vm) => match vm.state {
                    VmState::Running => return Ok(()),
                    ref s if s.is_terminal() => return Err(terminated(&vm)),
                    VmState::Suspended if !auto_resume(&vm) && !retry.resumed => {
                        retry.resumed = true;
                        self.note(format!("{} is suspended without auto-resume: resuming it", self.vm()));
                        match self.env.api.resume(self.vm()).await {
                            Ok(()) | Err(BridgeError::Conflict(_)) => {}
                            Err(e) => return Err(e),
                        }
                        continue;
                    }
                    ref s => s.as_str().to_string(),
                },
                Err(e @ BridgeError::VmNotFound(_)) => return Err(e),
                Err(e) => format!("unknown (GetMicrovm: {e})"),
            };
            if start.elapsed() >= limit {
                return Err(BridgeError::ShimUnavailable(format!("{} is still {seen} after {}", self.vm(), secs(limit))));
            }
            self.pause(self.env.policy.backoff_min).await?;
        }
    }

    /// Past the reconnect budget, the last failure's error.
    fn give_up_past(&self, retry: &mut Retry, wait: Duration) -> Result<(), BridgeError> {
        let spent = retry.since.elapsed();
        if spent + wait <= self.env.policy.reconnect_budget {
            return Ok(());
        }
        Err(match (retry.no_token.take(), retry.throttled) {
            (Some(e), _) => e,
            (None, Some(retry_after_s)) => BridgeError::EndpointThrottled { retry_after_s },
            (None, None) => BridgeError::ShimUnavailable(format!("{}: no lasting /agent connection for {} (last: {})", self.vm(), secs(spent), retry.last)),
        })
    }

    /// A mint that failed while reconnecting: a VM that is gone ends the
    /// session; anything else is a failed attempt like a refused dial.
    async fn mint_failed(&mut self, e: BridgeError, retry: &mut Retry) -> Result<(), BridgeError> {
        if gone(&e) {
            return Err(e);
        }
        retry.failed(format!("no endpoint token: {e}"));
        retry.no_token = Some(e);
        let wait = retry.next(&self.env.policy);
        self.give_up_past(retry, wait)?;
        self.pause(wait).await
    }

    /// After `event hook_suspend`: GetMicrovm every 3 s, never a dial, until RUNNING or `suspend_wait`.
    async fn wait_resumed(&mut self) -> Result<(), BridgeError> {
        let env = self.env;
        let id = env.target.vm_id.as_str();
        self.note(format!("{id} was suspended; not reconnecting until it runs again (up to {}; `ai-env vm resume {id}`)", secs(env.policy.suspend_wait)));
        self.link(false);
        let start = Instant::now();
        loop {
            self.pause(units(&env.policy, 3)).await?;
            match env.api.get(id).await {
                Ok(vm) if vm.state == VmState::Running => return Ok(()),
                Ok(vm) if vm.state.is_terminal() => return Err(terminated(&vm)),
                Ok(_) => {}
                Err(e @ BridgeError::VmNotFound(_)) => return Err(e),
                Err(e) => tracing::warn!("vm {id}: GetMicrovm while suspended: {e}"),
            }
            if start.elapsed() >= env.policy.suspend_wait {
                return Err(BridgeError::Transport(format!(
                    "{id} stayed suspended for {}: resume it with `ai-env vm resume {id}`, then reattach with `ai-env vm attach {id} --spawn {}`",
                    secs(env.policy.suspend_wait),
                    self.st.id
                )));
            }
        }
    }

    /// A `hello_ok`: the spawn goes out (again), or what became of it.
    async fn adopt(&mut self, ok: &HelloOk, link: &mut Link) -> Result<(), BridgeError> {
        if self.st.phase == Phase::ToSpawn {
            self.no_pending_detach()?;
            self.send_spawn(link).await;
            return Ok(());
        }
        let status = ok.resumed.iter().find(|r| r.spawn_id == self.st.id).map_or(ResumeStatus::Unknown, |r| r.status);
        match status {
            ResumeStatus::Ok => {
                let found = ok.spawns.iter().find(|s| s.spawn_id == self.st.id);
                // A resume point past the end of the stream (`vm attach --from-seq`):
                // the shim replays from its next chunk (`Cursor::resume`), and so
                // does the session — else it drops every chunk up to the point as a
                // duplicate, never acks one, and the shim's window fills. The status
                // is read after the attach, so chunks in between are duplicates, never a skip.
                if let Some(s) = found.filter(|s| self.st.out_known && self.st.out > s.out_seq) {
                    self.note(format!("stdout seq {} is past the end of spawn {}'s stdout (seq {}): showing it from seq {}", self.st.out + 1, self.st.id, s.out_seq, s.out_seq + 1));
                    self.st.out = s.out_seq;
                }
                self.st.reattached(found);
                self.st.phase = Phase::Running;
                self.attached = true;
                if !self.st.started {
                    let (pid, pgid) = found.map_or((0, 0), |s| (s.pid, s.pgid));
                    self.started(pid, pgid, None);
                }
                self.flush(link).await;
                Ok(())
            }
            ResumeStatus::Gap => Err(BridgeError::Gap { spawn_id: self.st.id.0.clone(), from_seq: self.st.resume().first().and_then(|r| r.from_seq).unwrap_or(0) }),
            // The shim does not hold the spawn: its `spawn` never arrived, the
            // shim is still starting it, or it ran and was released once its
            // detach grace ran out while no socket carried it. Sent again, it
            // starts in the first case only: the shim refuses an id it holds or
            // already used (`spawn_err exists`, see `on_frame`), so it never runs twice.
            ResumeStatus::Unknown if self.st.phase == Phase::SpawnSent => {
                self.no_pending_detach()?;
                self.st.resent = true;
                self.send_spawn(link).await;
                Ok(())
            }
            ResumeStatus::Unknown => Err(BridgeError::Transport(format!("spawn {} is not on {} (it ended, or its detach grace ran out while disconnected)", self.st.id, self.vm()))),
        }
    }

    async fn send_spawn(&mut self, link: &mut Link) {
        let Some(spec) = &self.st.spec else { return };
        let frame = Frame::Spawn {
            spawn_id: self.st.id.clone(),
            argv: spec.argv.clone(),
            cwd: spec.cwd.clone(),
            env: spec.env.clone(),
            secrets: BTreeMap::new(),
            deliver_secret: Deliver::Fd,
            detach_grace_s: spec.detach_grace_s,
        };
        link.send(&frame).await;
        self.st.phase = Phase::SpawnSent;
    }

    // ---- serving one socket ---------------------------------------------------------------

    async fn serve(&mut self, link: &mut Link) -> Result<End, BridgeError> {
        let p = self.env.policy.clone();
        let mut tick = tokio::time::interval(p.ack_every.min(p.ping).min(p.ws_ping).min(p.dead_after / 4).max(Duration::from_millis(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let (mut pinged, mut ws_pinged) = (Instant::now(), Instant::now());
        let mut keepalive_at = Instant::now() + p.keepalive_every;
        let mut keepalive: Option<BoxFuture<'a, Result<HealthReply, BridgeError>>> = None;
        let mut rot = Rotating::new(&p);
        let mut remint_after: Option<Instant> = None;
        let mut clock = (Instant::now(), wall_now());
        loop {
            if let Some(why) = link.broken.take() {
                return Ok(End::Lost(why));
            }
            if self.st.detach_sent {
                return Ok(End::Detached);
            }
            tokio::select! {
                m = link.inbound.recv() => match m {
                    Some(Inbound::Frame(frame)) => {
                        if let Some(end) = self.on_frame(frame, link, &mut rot.superseded).await? {
                            return Ok(end);
                        }
                    }
                    Some(Inbound::Ended(why)) => return Ok(End::Lost(why)),
                    Some(Inbound::Bad(m)) => return Err(BridgeError::Protocol(m)),
                    None => return Ok(End::Lost("the socket's reader stopped".into())),
                },
                r = pending_or(&mut rot.step) => {
                    rot.step = None;
                    match r {
                        RotationStep::Dialed(token, conn) => {
                            // From this hello on the shim may move the spawn: spawn frames wait for the new socket.
                            self.paused = true;
                            rot.step = Some(self.rotation_hello(token, conn));
                        }
                        RotationStep::Answered(rotated) => {
                            self.rotated(link, *rotated).await?;
                            rot = Rotating::new(&p);
                        }
                        // The shim may hold the spawn for that socket now: only a reconnect with the resume finds it for sure.
                        RotationStep::Failed(token, RotationFailed::Unanswered(why)) => {
                            if let Some(token) = token {
                                self.token = token;
                            }
                            return Ok(End::Lost(format!("the token rotation's hello got no answer: {why}")));
                        }
                        // A refused hello moved nothing: that `superseded` was another client's.
                        RotationStep::Failed(..) if rot.superseded => return Err(BridgeError::Superseded(format!("spawn {} of {}", self.st.id, self.vm()))),
                        RotationStep::Failed(token, failed) => {
                            self.paused = false;
                            rot.token = token;
                            self.rotation_failed(&mut rot, &failed, link.n);
                            self.flush(link).await;
                        }
                    }
                },
                m = self.io.control.recv(), if self.control_open => match m {
                    Some(input) => self.on_input(input, link).await,
                    None => self.control_open = false,
                },
                m = self.io.input.recv(), if self.st.wants_input() => match m {
                    Some(input) => self.on_input(input, link).await,
                    None => self.st.input_open = false,
                },
                () = self.io.consumed.changed() => self.ack(link, false).await,
                r = pending_or(&mut keepalive) => {
                    keepalive = None;
                    match r {
                        Ok(reply) if reply.status == 200 => {}
                        Ok(reply) => tracing::info!("vm {}: keep-alive /health answered {}", self.vm(), reply.status),
                        Err(e) => tracing::info!("vm {}: keep-alive /health: {e}", self.vm()),
                    }
                },
                _ = tick.tick() => {
                    // A laptop sleep stops Instant but not the wall clock: the socket did not survive it.
                    let asleep = wall_now().saturating_sub(clock.1).saturating_sub(clock.0.elapsed());
                    clock = (Instant::now(), wall_now());
                    if asleep > p.dead_after {
                        return Ok(End::Lost(format!("woke after {} asleep", secs(asleep))));
                    }
                    let idle = link.activity.idle();
                    if idle > p.dead_after {
                        return Ok(End::Lost(format!("no frame for {}", secs(idle))));
                    }
                    self.ack(link, true).await;
                    if self.attached {
                        if pinged.elapsed() >= p.ping {
                            link.send(&Frame::Ping { ts: crate::wire::time::unix_now_ms() }).await;
                            pinged = Instant::now();
                        }
                        if ws_pinged.elapsed() >= p.ws_ping {
                            link.ws_ping().await;
                            ws_pinged = Instant::now();
                        }
                        if p.keepalive == Keepalive::Http && keepalive.is_none() && Instant::now() >= keepalive_at {
                            keepalive = Some(self.keepalive());
                            keepalive_at = Instant::now() + p.keepalive_every;
                        }
                        if p.rotation == Rotation::Proactive && rot.due() && self.token_left() <= p.rotate_before {
                            tracing::info!("vm {}: rotating the endpoint token (socket {})", self.vm(), link.n);
                            rot.step = Some(self.rotation_dial(rot.token.take()));
                            rot.after = None;
                        }
                    }
                    // A failed mint never ends a live socket: the next reconnect mints again.
                    if rot.step.is_none() && remint_after.is_none_or(|t| Instant::now() >= t) && self.freshen().await?.is_some() {
                        remint_after = Some(Instant::now() + p.backoff_max);
                    }
                }
            }
        }
    }

    /// One frame from the shim; `Some` when it ends this socket's service.
    /// While a rotation's hello is out (`paused`), `superseded` and
    /// `not_attached` are that hello's doing.
    async fn on_frame(&mut self, frame: Frame, link: &mut Link, superseded: &mut bool) -> Result<Option<End>, BridgeError> {
        if frame.spawn_id().is_some_and(|id| *id != self.st.id) {
            tracing::debug!("vm {}: ignoring {frame:?} (another spawn)", self.vm());
            return Ok(None);
        }
        match frame {
            Frame::Spawned { pid, pgid, claude_version, .. } => {
                self.st.phase = Phase::Running;
                self.attached = true;
                if !self.st.started {
                    self.started(pid, pgid, claude_version);
                }
                self.flush(link).await;
            }
            Frame::SpawnErr { spawn_id, code, message } => {
                // The re-sent spawn's id is taken: the first `spawn` reached the VM
                // before its socket was lost, and the shim never starts an id twice.
                if code == SpawnErrCode::Exists && self.st.resent {
                    let vm = self.vm();
                    return Err(BridgeError::Transport(format!(
                        "spawn {spawn_id} reached {vm} before the connection was lost: it ran, or still runs, without this client and was not started again (`ai-env vm attach {vm} --spawn {spawn_id}` reattaches to it while it runs)"
                    )));
                }
                // The command itself could not start (no program, not executable, no
                // working directory): the operator's to fix, not a lost VM.
                let refused = match code {
                    SpawnErrCode::NotFound => Some("not_found"),
                    SpawnErrCode::Exec => Some("exec"),
                    SpawnErrCode::Cwd => Some("cwd"),
                    // The VM runs its most commands already: a refusal, not a lost VM.
                    SpawnErrCode::Limit => Some("limit"),
                    _ => None,
                };
                if let Some(code) = refused {
                    return Err(BridgeError::SpawnRefused { code, message: scrub(&message).into_owned() });
                }
                return Err(BridgeError::Protocol(format!("the shim refused spawn {spawn_id} ({}): {}", wire_name(&code), scrub(&message))));
            }
            Frame::Stdout { seq, data, .. } => self.deliver_out(seq, &data)?,
            Frame::Stderr { seq, data, dropped, .. } => self.deliver_err(seq, &data, dropped)?,
            Frame::StdinAck { seq, .. } => {
                self.st.stdin_acked(seq);
                self.flush(link).await;
            }
            Frame::Exit { seq, code, signal, stderr_dropped, stdout_truncated, .. } => {
                if self.st.out_known && seq > self.st.out + 1 {
                    return Err(BridgeError::Protocol(format!("spawn {} exited at stdout seq {seq} but its stdout stopped at {}", self.st.id, self.st.out)));
                }
                let exit = RemoteExit { code, signal, stderr_dropped: stderr_dropped + self.st.err_dropped, stdout_truncated };
                let _ = self.io.events.send(SpawnEvent::Exit(exit));
                return Ok(Some(End::Exited(seq, exit)));
            }
            Frame::Event { kind: EventKind::HookSuspend, .. } => return Ok(Some(End::Suspended)),
            Frame::Event { kind: EventKind::HookTerminate, .. } => return Err(BridgeError::Terminated(format!("{} is terminating (event hook_terminate)", self.vm()))),
            Frame::Error { code: ErrorCode::Superseded, .. } if self.paused => *superseded = true,
            Frame::Error { code: ErrorCode::Superseded, .. } => return Err(BridgeError::Superseded(format!("spawn {} of {}", self.st.id, self.vm()))),
            Frame::Error { code: ErrorCode::NotAttached, .. } if self.paused => {}
            Frame::Error { code: ErrorCode::NotAttached, message, .. } => return Ok(Some(End::Lost(format!("the shim does not attach the spawn to this socket: {}", scrub(&message))))),
            Frame::Error { code: ErrorCode::Draining, .. } => return Err(BridgeError::Terminated(format!("{} is draining", self.vm()))),
            Frame::Error { code: ErrorCode::UnknownFrame | ErrorCode::Other, message, .. } => tracing::info!("vm {}: the shim reported: {}", self.vm(), scrub(&message)),
            Frame::Error { code, message, .. } => return Err(BridgeError::Protocol(format!("the shim reported {}: {}", wire_name(&code), scrub(&message)))),
            other => tracing::debug!("vm {}: ignoring {other:?}", self.vm()),
        }
        Ok(None)
    }

    fn deliver_out(&mut self, seq: u64, data: &Chunk) -> Result<(), BridgeError> {
        let st = &mut self.st;
        if st.out_known && seq <= st.out {
            return Ok(());
        }
        if st.out_known && seq != st.out + 1 {
            return Err(BridgeError::Protocol(format!("stdout of spawn {} skipped from seq {} to {seq}", st.id, st.out)));
        }
        let bytes = decode(data).map_err(|e| BridgeError::Protocol(format!("stdout seq {seq} of spawn {}: {e}", st.id)))?;
        st.out = seq;
        st.out_known = true;
        st.delivered.0 = seq;
        st.out_lens.push_back((seq, bytes.len() as u64));
        let _ = self.io.events.send(SpawnEvent::Stdout { seq, bytes });
        Ok(())
    }

    /// stderr is drop-oldest on the shim: its seqs may skip (`dropped` counts
    /// the bytes). The shim sends it without credit, so the session bounds it
    /// too: while `STDERR_BUFFER_BYTES` of it wait for the consumer's mark,
    /// newer chunks are dropped and added to `dropped`.
    fn deliver_err(&mut self, seq: u64, data: &Chunk, dropped: u64) -> Result<(), BridgeError> {
        let (out_done, err_done) = self.io.consumed.seqs();
        let st = &mut self.st;
        if st.err_known && seq <= st.err {
            return Ok(());
        }
        let bytes = decode(data).map_err(|e| BridgeError::Protocol(format!("stderr seq {seq} of spawn {}: {e}", st.id)))?;
        st.err = seq;
        st.err_known = true;
        st.count_consumed(out_done.min(st.out), err_done.min(seq));
        let len = bytes.len() as u64;
        if st.err_unconsumed + len > STDERR_BUFFER_BYTES {
            st.err_dropped += len;
            return Ok(());
        }
        st.err_unconsumed += len;
        st.delivered.1 = seq;
        st.err_lens.push_back((seq, len));
        let _ = self.io.events.send(SpawnEvent::Stderr { seq, bytes, dropped: dropped + st.err_dropped });
        Ok(())
    }

    async fn on_input(&mut self, input: SpawnInput, link: &mut Link) {
        self.st.take(input);
        self.flush(link).await;
    }

    fn can_send(&self) -> bool {
        self.attached && !self.paused
    }

    /// Everything that waits for a socket carrying the spawn: stdin within
    /// the shim's window, `stdin_eof`, signals, the ack, a detach. A frame
    /// leaves its queue only once its send succeeded: after a failure the
    /// rest waits for the next socket (the broken one is replaced at once).
    async fn flush(&mut self, link: &mut Link) {
        if !self.can_send() {
            return;
        }
        while let Some((seq, data, len)) = self.st.next_stdin() {
            if !link.send(&Frame::Stdin { spawn_id: self.st.id.clone(), seq, data }).await {
                return;
            }
            self.st.sent_in = seq;
            self.st.inflight += len;
        }
        if let Some(seq) = self.st.eof.filter(|eof| !self.st.eof_sent && self.st.sent_in >= *eof) {
            if !link.send(&Frame::StdinEof { spawn_id: self.st.id.clone(), seq }).await {
                return;
            }
            self.st.eof_sent = true;
        }
        while let Some(&sig) = self.st.signals.front() {
            if !link.send(&Frame::Signal { spawn_id: self.st.id.clone(), sig, scope: Scope::Group }).await {
                return;
            }
            self.st.signals.pop_front();
        }
        self.ack(link, true).await;
        if let Some(is_final) = self.st.detach {
            if link.send(&Frame::Detach { spawn_id: self.st.id.clone(), is_final }).await {
                self.st.detach = None;
                self.st.detach_sent = true;
            }
        }
    }

    /// Ack what the consumer marked: always on the timer, otherwise once
    /// `ack_bytes` were consumed since the last ack.
    async fn ack(&mut self, link: &mut Link, timer: bool) {
        let (out, err) = self.io.consumed.seqs();
        let (out, err) = (out.min(self.st.out), err.min(self.st.err));
        self.st.count_consumed(out, err);
        if !self.can_send() || (out, err) == self.st.acked || (!timer && self.st.consumed_bytes < self.env.policy.ack_bytes) {
            return;
        }
        link.send(&Frame::Ack { spawn_id: self.st.id.clone(), seq: out, err_seq: err }).await;
        self.st.acked = (out, err);
        self.st.consumed_bytes = 0;
    }

    /// The rotation's new socket said `hello_ok`: it takes over, the old one is closed 1000.
    async fn rotated(&mut self, link: &mut Link, rotated: Rotated) -> Result<(), BridgeError> {
        // stdin acks the old socket already read still count.
        while let Ok(m) = link.inbound.try_recv() {
            if let Inbound::Frame(Frame::StdinAck { spawn_id, seq }) = m {
                if spawn_id == self.st.id {
                    self.st.stdin_acked(seq);
                }
            }
        }
        let old = std::mem::replace(link, Link::start(rotated.conn));
        tokio::spawn(old.close(CLOSE_NORMAL));
        self.token = rotated.token;
        self.paused = false;
        self.attached = false;
        self.adopt(&rotated.ok, link).await?;
        self.audit("agent_rotate", &[("mode", "proactive".into())]);
        self.note(format!("rotated to a fresh endpoint token (socket {})", link.n));
        Ok(())
    }

    /// The exit was delivered: once the consumer marked every chunk this
    /// session delivered (at most `dead_after`), ack the exit's seq (the shim
    /// then releases the spawn); close 1000.
    async fn finish(&mut self, mut link: Link, exit_seq: u64, exit: RemoteExit) -> SpawnOutcome {
        let want = self.st.delivered;
        let (consumed, events) = (self.io.consumed.clone(), self.io.events.clone());
        let caught_up = tokio::time::timeout(self.env.policy.dead_after, async {
            loop {
                let (out, err) = consumed.seqs();
                if out >= want.0 && err >= want.1 {
                    return true;
                }
                tokio::select! {
                    () = consumed.changed() => {}
                    () = events.closed() => return false,
                }
            }
        })
        .await
        .unwrap_or(false);
        if caught_up {
            link.send(&Frame::Ack { spawn_id: self.st.id.clone(), seq: exit_seq, err_seq: self.st.err }).await;
        } else {
            tracing::info!("vm {}: spawn {} exited; the consumer did not confirm its output, so the exit stays unacked (the shim keeps it for its grace)", self.vm(), self.st.id);
        }
        link.close(CLOSE_NORMAL).await;
        SpawnOutcome { spawn_id: self.st.id.clone(), exit }
    }

    // ---- waiting while disconnected -----------------------------------------------------

    /// Sleep `d`, still taking the consumer's input (queued for the next
    /// socket); a detach ends the session at once.
    async fn pause(&mut self, d: Duration) -> Result<(), BridgeError> {
        let until = tokio::time::Instant::now() + d;
        loop {
            let input = tokio::select! {
                () = tokio::time::sleep_until(until) => return Ok(()),
                m = self.io.control.recv(), if self.control_open => match m {
                    Some(input) => input,
                    None => {
                        self.control_open = false;
                        continue;
                    }
                },
                m = self.io.input.recv(), if self.st.wants_input() => match m {
                    Some(input) => input,
                    None => {
                        self.st.input_open = false;
                        continue;
                    }
                },
            };
            if matches!(input, SpawnInput::Detach { .. }) {
                return Err(self.detached_while_disconnected());
            }
            self.st.take(input);
        }
    }

    /// `fut` (a dial, a hello) while the consumer's control channel is
    /// watched: a signal is queued for the spawn, a detach ends the session
    /// at once and `fut` is dropped (a spawn not sent yet is never sent).
    async fn watching<T>(&mut self, fut: impl std::future::Future<Output = T>) -> Result<T, BridgeError> {
        tokio::pin!(fut);
        loop {
            tokio::select! {
                out = &mut fut => return Ok(out),
                m = self.io.control.recv(), if self.control_open => match m {
                    Some(SpawnInput::Detach { .. }) => return Err(self.detached_while_disconnected()),
                    Some(input) => self.st.take(input),
                    None => self.control_open = false,
                },
            }
        }
    }

    /// Before a `spawn` goes out: the control inputs that arrived meanwhile;
    /// a detach among them (or one already taken) means it never goes out.
    fn no_pending_detach(&mut self) -> Result<(), BridgeError> {
        while self.control_open {
            match self.io.control.try_recv() {
                Ok(input) => self.st.take(input),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => self.control_open = false,
            }
        }
        match self.st.detach {
            Some(_) => Err(self.detached_while_disconnected()),
            None => Ok(()),
        }
    }

    fn detached_while_disconnected(&self) -> BridgeError {
        BridgeError::Transport(format!("detached from spawn {} while disconnected from {} (its detach grace ends it)", self.st.id, self.vm()))
    }

    // ---- tokens -------------------------------------------------------------------------

    /// What is left of the endpoint token, by the wall clock.
    fn token_left(&self) -> Duration {
        left(&self.token)
    }

    async fn remint(&mut self, why: &str) -> Result<(), BridgeError> {
        self.token = mint_token(self.env).await?;
        self.audit("agent_remint", &[("reason", why.to_string())]);
        Ok(())
    }

    /// A fresh token when less than `remint_below` is left. A failed mint
    /// keeps the current token and comes back as `Ok(Some(error))` (whether
    /// an expired token is the end is the caller's call); only a VM that is
    /// gone is `Err`.
    async fn freshen(&mut self) -> Result<Option<BridgeError>, BridgeError> {
        if self.token_left() >= self.env.policy.remint_below {
            return Ok(None);
        }
        match self.remint("expiring").await {
            Ok(()) => Ok(None),
            Err(e) if gone(&e) => Err(e),
            Err(e) => {
                tracing::warn!("vm {}: the endpoint token was not re-minted ({e}); {} left on the current one", self.vm(), secs(self.token_left()));
                Ok(Some(e))
            }
        }
    }

    /// The keep-alive: one bearer-less `GET /health` (bounded by its own cadence).
    fn keepalive(&self) -> BoxFuture<'a, Result<HealthReply, BridgeError>> {
        let (ep, endpoint, token, limit) = (self.env.ep, self.env.target.endpoint.clone(), self.token.clone(), self.env.policy.keepalive_every);
        Box::pin(async move {
            match tokio::time::timeout(limit, ep.get_health(&endpoint, &token, APP_PORT)).await {
                Ok(r) => r,
                Err(_) => Err(BridgeError::Endpoint(format!("no /health answer within {}", secs(limit)))),
            }
        })
    }

    /// A rotation's first step: `kept` (while it has `remint_below` left) or
    /// a fresh token, and a second socket. The old one serves meanwhile.
    fn rotation_dial(&self, kept: Option<AuthToken>) -> BoxFuture<'a, RotationStep> {
        let env = self.env;
        let (api, paths, dial, minutes, below) = (env.api, env.paths, env.dial, env.policy.token_minutes, env.policy.remint_below);
        let (vm, endpoint, trace) = (env.target.vm_id.clone(), env.target.endpoint.clone(), self.trace.clone());
        Box::pin(async move {
            let token = match kept.filter(|t| left(t) >= below) {
                Some(token) => token,
                None => match mint(api, paths, &vm, APP_PORT, minutes).await {
                    Ok(token) => token,
                    Err(e) => return RotationStep::Failed(None, RotationFailed::Mint(e.to_string())),
                },
            };
            let value = match token.value() {
                Ok(value) => value.clone(),
                Err(e) => return RotationStep::Failed(None, RotationFailed::Mint(e.to_string())),
            };
            match AgentConn::open(&dial, &endpoint, &value).await {
                Ok(conn) => RotationStep::Dialed(token, conn.with_trace(trace)),
                Err(e) => RotationStep::Failed(Some(token), RotationFailed::Dial(e)),
            }
        })
    }

    /// A rotation's second step: `hello` on the new socket, resuming from what was delivered by now.
    fn rotation_hello(&self, token: AuthToken, mut conn: AgentConn) -> BoxFuture<'a, RotationStep> {
        let env = self.env;
        let (session_token, resume, idle_s, wait) = (env.target.session_token.clone(), self.st.resume(), env.policy.idle_s, env.policy.dead_after);
        Box::pin(async move {
            let answer = tokio::time::timeout(wait, conn.hello(&session_token, resume, idle_s)).await;
            match answer {
                Ok(Ok(ok)) => RotationStep::Answered(Box::new(Rotated { token, conn, ok })),
                Ok(Err(e @ BridgeError::HelloRefused { .. })) => RotationStep::Failed(Some(token), RotationFailed::Refused(e.to_string())),
                Ok(Err(e)) => RotationStep::Failed(Some(token), RotationFailed::Unanswered(e.to_string())),
                Err(_) => RotationStep::Failed(Some(token), RotationFailed::Unanswered(format!("no hello_ok within {}", secs(wait)))),
            }
        })
    }

    /// A rotation attempt that left the spawn on socket `n`: when the next
    /// may start, by the reconnect rules. A 429 waits max(Retry-After,
    /// backoff) and is audited; a 401/403 spends the one re-mint, and a second
    /// stops rotating on this socket; anything else backs off.
    fn rotation_failed(&self, rot: &mut Rotating<'_>, failed: &RotationFailed, n: u64) {
        let p = &self.env.policy;
        tracing::warn!("vm {}: token rotation: {failed}", self.vm());
        let wait = match failed {
            RotationFailed::Dial(DialError::TokenRejected { .. }) if rot.retry.reminted => {
                rot.stopped = true;
                self.note(format!("the token rotation failed again with a fresh token ({failed}); staying on socket {n} until it ends"));
                return;
            }
            RotationFailed::Dial(DialError::TokenRejected { .. }) => {
                rot.retry.reminted = true;
                rot.token = None;
                rot.retry.next(p)
            }
            RotationFailed::Dial(DialError::Throttled { retry_after_s }) => {
                let backoff = rot.retry.next(p);
                let wait = retry_after_s.map_or(backoff, |s| units(p, s).max(backoff));
                let retry_after = retry_after_s.map_or_else(|| "none".to_string(), |s| s.to_string());
                self.audit("endpoint_429", &[("retry_after", retry_after), ("waited_ms", wait.as_millis().to_string())]);
                wait
            }
            _ => rot.retry.next(p),
        };
        self.note(format!("the token rotation failed ({failed}); staying on socket {n} and trying again in {}", secs(wait)));
        rot.after = Some(Instant::now() + wait);
    }

    // ---- records ------------------------------------------------------------------------

    fn vm(&self) -> &str {
        &self.env.target.vm_id
    }

    fn started(&mut self, pid: u32, pgid: u32, claude_version: Option<String>) {
        self.st.started = true;
        let _ = self.io.events.send(SpawnEvent::Started { spawn_id: self.st.id.clone(), pid, pgid, claude_version });
    }

    fn note(&self, text: String) {
        tracing::info!("vm {}: {text}", self.vm());
        let _ = self.io.events.send(SpawnEvent::Note(text));
    }

    /// [`SpawnEvent::Link`]: whether a signal or a `detach` can reach the VM now.
    fn link(&self, up: bool) {
        let _ = self.io.events.send(SpawnEvent::Link(up));
    }

    fn audit(&self, event: &str, pairs: &[(&str, String)]) {
        let mut all = vec![("id", self.vm().to_string()), ("spawn", self.st.id.to_string())];
        all.extend(pairs.iter().cloned());
        audit_event(self.env.paths, event, &all);
    }
}

/// A `Port(8080)` token for the session; a mint that failed because the VM
/// is gone says so (exit 8, not the mint's own exit 7).
async fn mint_token<A: MicrovmApi, E: EndpointClient>(env: &AgentEnv<'_, A, E>) -> Result<AuthToken, BridgeError> {
    let id = &env.target.vm_id;
    match mint(env.api, env.paths, id, APP_PORT, env.policy.token_minutes).await {
        Ok(token) => Ok(token),
        Err(e @ BridgeError::VmNotFound(_)) => Err(e),
        Err(e) => match env.api.get(id).await {
            Ok(vm) if vm.state.is_terminal() => Err(terminated(&vm)),
            Err(gone @ BridgeError::VmNotFound(_)) => Err(gone),
            _ => Err(e),
        },
    }
}

/// What is left of `token`, by the wall clock.
fn left(token: &AuthToken) -> Duration {
    Duration::from_secs(token.expires_at_unix).saturating_sub(wall_now())
}

/// The wall clock, as time since the epoch (in tests it runs
/// `tests::WALL_AHEAD` ahead: a laptop sleep, which stops `Instant` only).
fn wall_now() -> Duration {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    #[cfg(test)]
    let now = now + tests::WALL_AHEAD.with(std::cell::Cell::get);
    now
}

/// A mint failure that means the VM is gone (`mint_token` asked GetMicrovm).
fn gone(e: &BridgeError) -> bool {
    matches!(e, BridgeError::Terminated(_) | BridgeError::VmNotFound(_))
}

/// The output of the future in `slot`, or never while it is empty (a select arm that stays quiet).
async fn pending_or<T>(slot: &mut Option<BoxFuture<'_, T>>) -> T {
    match slot.as_mut() {
        Some(f) => f.await,
        None => std::future::pending().await,
    }
}

fn auto_resume(vm: &VmInfo) -> bool {
    !vm.idle.is_some_and(|i| !i.auto_resume)
}

fn terminated(vm: &VmInfo) -> BridgeError {
    let reason = vm.state_reason.as_deref().map(|r| format!(" ({})", scrub(r))).unwrap_or_default();
    BridgeError::Terminated(format!("{} is {}{reason}", vm.id, vm.state.as_str()))
}

/// `n` of the policy's seconds (`backoff_min`; see `RunPolicy`).
fn units(p: &RunPolicy, n: u64) -> Duration {
    p.backoff_min.saturating_mul(u32::try_from(n).unwrap_or(u32::MAX))
}

fn secs(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

/// The wire spelling of a code (`bad_request`, …).
fn wire_name<T: serde::Serialize>(code: &T) -> String {
    serde_json::to_value(code).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::agent::{run_spawn, spawn_channels, AgentTarget, Consumed, ConsumerIo};
    use crate::bridge::api::{Call, FakeMicrovmApi, IdleSpec, RunSpec, FAKE_IMAGE_ARN, TOKEN_HEADER};
    use crate::bridge::config::Paths;
    use crate::bridge::transport::AgentDial;
    use crate::errors::CliError;
    use crate::wire::frame::{HelloErrCode, Resumed, ACK_EVERY_BYTES, CLOSE_GOING_AWAY, CLOSE_HELLO_REFUSED};
    use crate::wire::redact::Secret;
    use futures_util::{SinkExt, StreamExt};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::Message;

    type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

    const SESSION_TOKEN: &str = "test-session-token-0001";
    /// Every test ends within this.
    const LIMIT: Duration = Duration::from_secs(30);

    thread_local! {
        /// How far `wall_now` runs ahead of the real wall clock on this test's
        /// thread (a `#[tokio::test]` runs on one thread, so no other test sees it).
        pub(super) static WALL_AHEAD: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
    }

    // ---- the fake endpoint ---------------------------------------------------------------

    /// A scripted answer to one upgrade.
    struct Refusal {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: String,
    }

    fn refusal(status: u16, headers: &[(&'static str, &str)], body: &str) -> Refusal {
        Refusal { status, headers: headers.iter().map(|(k, v)| (*k, (*v).to_string())).collect(), body: body.into() }
    }

    /// One upgrade as the endpoint saw it.
    #[derive(Debug, Clone)]
    struct Attempt {
        at: Instant,
        status: u16,
    }

    /// The tests' MicroVM endpoint on loopback (the knob dials it): the
    /// scripted refusals first, then the proxy's own token and state check
    /// (`FakeState::endpoint_check`, which also auto-resumes), then the
    /// upgrade, whose socket goes to the test.
    struct Endpoint {
        addr: SocketAddr,
        refusals: Arc<Mutex<VecDeque<Refusal>>>,
        attempts: Arc<Mutex<Vec<Attempt>>>,
        sockets: tokio::sync::Mutex<mpsc::UnboundedReceiver<Ws>>,
    }

    impl Endpoint {
        async fn start(api: Arc<FakeMicrovmApi>) -> Endpoint {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let refusals: Arc<Mutex<VecDeque<Refusal>>> = Arc::default();
            let attempts: Arc<Mutex<Vec<Attempt>>> = Arc::default();
            let (tx, rx) = mpsc::unbounded_channel();
            let (scripted, seen) = (refusals.clone(), attempts.clone());
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let (scripted, seen, api, tx) = (scripted.clone(), seen.clone(), api.clone(), tx.clone());
                    tokio::spawn(async move {
                        // tungstenite's `Callback` fixes this signature.
                        #[allow(clippy::result_large_err)]
                        let check = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                            let header = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                            let refused = scripted.lock().unwrap().pop_front().or_else(|| {
                                let token = AuthToken { headers: BTreeMap::from([(TOKEN_HEADER.to_string(), Secret::new(header("x-aws-proxy-auth")))]), port: APP_PORT, expires_at_unix: 0 };
                                let proxy = api.state().endpoint_check(&header("host"), &token, header("x-aws-proxy-port").parse().unwrap_or(0));
                                proxy.err().map(|r| Refusal { status: r.status, headers: r.proxy_error.map(|e| vec![("x-aws-proxy-error", e)]).unwrap_or_default(), body: String::new() })
                            });
                            seen.lock().unwrap().push(Attempt { at: Instant::now(), status: refused.as_ref().map_or(101, |r| r.status) });
                            let Some(r) = refused else { return Ok(resp) };
                            let mut answer = http::Response::builder().status(r.status);
                            for (k, v) in r.headers {
                                answer = answer.header(k, v);
                            }
                            Err(answer.body(Some(r.body)).unwrap())
                        };
                        if let Ok(ws) = tokio_tungstenite::accept_hdr_async_with_config(tcp, check, Some(crate::wire::frame::ws_config())).await {
                            let _ = tx.send(ws);
                        }
                    });
                }
            });
            Endpoint { addr, refusals, attempts, sockets: tokio::sync::Mutex::new(rx) }
        }

        fn refuse(&self, r: Refusal) {
            self.refusals.lock().unwrap().push_back(r);
        }

        fn attempts(&self) -> Vec<Attempt> {
            self.attempts.lock().unwrap().clone()
        }

        /// The next upgraded socket.
        async fn next(&self) -> Ws {
            tokio::time::timeout(LIMIT, async { self.sockets.lock().await.recv().await }).await.expect("an upgrade in time").expect("the endpoint runs")
        }
    }

    /// A RUNNING fake VM, its endpoint and a state root.
    struct Rig {
        api: Arc<FakeMicrovmApi>,
        vm: VmInfo,
        endpoint: Endpoint,
        paths: Paths,
        _dir: tempfile::TempDir,
    }

    async fn rig(auto_resume: bool) -> Rig {
        let api = Arc::new(FakeMicrovmApi::new());
        let spec = RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: "0192f1e0-0000-7000-8000-0000000000a1".into(),
        };
        let vm = api.run(&spec).await.unwrap();
        api.advance_all();
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(dir.path().to_path_buf(), None);
        let endpoint = Endpoint::start(api.clone()).await;
        Rig { api, vm, endpoint, paths, _dir: dir }
    }

    impl Rig {
        fn env(&self, policy: RunPolicy) -> AgentEnv<'_, FakeMicrovmApi, FakeMicrovmApi> {
            AgentEnv {
                api: &self.api,
                ep: &self.api,
                paths: &self.paths,
                target: AgentTarget { vm_id: self.vm.id.clone(), endpoint: self.vm.endpoint.clone(), session_token: Secret::new(SESSION_TOKEN.into()), vpc: false, shell: false },
                policy,
                dial: AgentDial { local: Some(self.endpoint.addr) },
            }
        }

        fn calls(&self, f: impl Fn(&Call) -> bool) -> usize {
            self.api.calls().iter().filter(|c| f(c)).count()
        }

        fn audit(&self, event: &str) -> Vec<serde_json::Value> {
            crate::bridge::audit::read_rows(&self.paths.audit(), None).unwrap().into_iter().filter(|r| r["event"] == event).collect()
        }
    }

    /// Small timers; pings and keep-alives off unless a test turns them on.
    fn policy() -> RunPolicy {
        RunPolicy {
            ping: Duration::from_secs(3600),
            ws_ping: Duration::from_secs(3600),
            dead_after: Duration::from_secs(5),
            ack_bytes: ACK_EVERY_BYTES,
            ack_every: Duration::from_millis(10),
            rotation: Rotation::Lazy,
            keepalive: Keepalive::Frames,
            keepalive_every: Duration::from_secs(3600),
            suspend_wait: Duration::from_secs(5),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(100),
            stable_after: Duration::from_secs(1),
            reconnect_budget: Duration::from_secs(5),
            not_run_budget: Duration::from_secs(2),
            token_minutes: 60,
            remint_below: Duration::from_secs(60),
            rotate_before: Duration::from_secs(120),
            idle_s: Some(90),
        }
    }

    fn cat_spec() -> SpawnSpec {
        SpawnSpec { argv: vec!["cat".into()], cwd: None, env: BTreeMap::new(), detach_grace_s: None }
    }

    fn lines(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("line-{i:03}\n").into_bytes()).collect()
    }

    // ---- the consumer --------------------------------------------------------------------

    /// What the consumer saw.
    #[derive(Debug, Default)]
    struct Seen {
        stdout: Vec<u8>,
        out_seqs: Vec<u64>,
        notes: Vec<String>,
        links: Vec<bool>,
        started: Option<(u32, u32)>,
        exit: Option<RemoteExit>,
    }

    impl Seen {
        /// One event, marked consumed as soon as it is "written".
        fn add(&mut self, ev: SpawnEvent, consumed: &Consumed) {
            match ev {
                SpawnEvent::Started { pid, pgid, .. } => self.started = Some((pid, pgid)),
                SpawnEvent::Stdout { seq, bytes } => {
                    self.out_seqs.push(seq);
                    self.stdout.extend(bytes);
                    consumed.stdout_done(seq);
                }
                SpawnEvent::Stderr { seq, .. } => consumed.stderr_done(seq),
                SpawnEvent::Note(n) => self.notes.push(n),
                SpawnEvent::Link(up) => self.links.push(up),
                SpawnEvent::Exit(e) => self.exit = Some(e),
            }
        }
    }

    /// Feeds `input` (each a stdin chunk, `gap` apart, then EOF; `None`: no
    /// stdin, never closed) and reads every event until the session ends.
    async fn consume(c: ConsumerIo, input: Option<Vec<Vec<u8>>>, gap: Duration) -> Seen {
        let ConsumerIo { input: tx, control: _control, mut events, consumed } = c;
        // The sender comes back, so stdin stays open until the session ends.
        let feed = async move {
            for chunk in input.iter().flatten() {
                tokio::time::sleep(gap).await;
                let _ = tx.send(SpawnInput::Stdin(chunk.clone())).await;
            }
            if input.is_some() {
                let _ = tx.send(SpawnInput::StdinEof).await;
            }
            tx
        };
        let read = async {
            let mut seen = Seen::default();
            while let Some(ev) = events.recv().await {
                seen.add(ev, &consumed);
            }
            seen
        };
        tokio::join!(feed, read).1
    }

    // ---- a scripted shim -----------------------------------------------------------------

    /// The next frame (WebSocket Pings and Pongs and app pings skipped).
    async fn frame(ws: &mut Ws) -> Frame {
        loop {
            match tokio::time::timeout(LIMIT, ws.next()).await.expect("a frame in time").expect("open").expect("readable") {
                Message::Text(t) => match Frame::from_json(t.as_str()).unwrap() {
                    Frame::Ping { .. } => continue,
                    f => return f,
                },
                Message::Ping(_) | Message::Pong(_) => continue,
                other => panic!("{other:?}"),
            }
        }
    }

    async fn put(ws: &mut Ws, f: &Frame) {
        ws.send(Message::from(f)).await.unwrap();
    }

    fn hello_ok(spawns: Vec<SpawnStatus>, resumed: Vec<Resumed>) -> Frame {
        Frame::HelloOk {
            wire: 1,
            shim_version: "0.1.0".into(),
            claude_version: None,
            microvm_id: None,
            image_version: None,
            boot_nonce: "test-nonce".into(),
            owner: None,
            has_credentials: false,
            uptime_s: 1,
            run_hook_seen: true,
            spawns,
            resumed,
        }
    }

    fn status(id: &SpawnId, out_seq: u64, in_seq: u64) -> SpawnStatus {
        SpawnStatus { spawn_id: id.clone(), argv0: "cat".into(), pid: 4242, pgid: 4242, alive: true, attached: false, out_seq, out_from: 1, err_seq: 0, in_seq, stdin_closed: false, exit: None }
    }

    /// hello → hello_ok → spawn → spawned: the spawn's id.
    async fn start_spawn(ws: &mut Ws) -> SpawnId {
        assert!(matches!(frame(ws).await, Frame::Hello { .. }));
        put(ws, &hello_ok(vec![], vec![])).await;
        let Frame::Spawn { spawn_id, .. } = frame(ws).await else { panic!("no spawn") };
        put(ws, &Frame::Spawned { spawn_id: spawn_id.clone(), pid: 4242, pgid: 4242, claude_version: None }).await;
        spawn_id
    }

    fn exit0(id: &SpawnId, seq: u64) -> Frame {
        Frame::Exit { spawn_id: id.clone(), seq, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false }
    }

    /// A one-minute token rotated 59 s before its expiry: within a second.
    fn rotation_policy() -> RunPolicy {
        RunPolicy { rotation: Rotation::Proactive, token_minutes: 1, rotate_before: Duration::from_secs(59), remint_below: Duration::from_secs(1), ..policy() }
    }

    /// A session as `run` builds it (a fresh token), before its first socket.
    async fn session<'e, 'a>(env: &'e AgentEnv<'a, FakeMicrovmApi, FakeMicrovmApi>, io: SpawnIo, start: Start) -> Session<'e, 'a, FakeMicrovmApi, FakeMicrovmApi> {
        let token = mint_token(env).await.unwrap();
        Session { env, io, trace: Trace::default(), token, st: State::new(start), attached: false, paused: false, control_open: true }
    }

    /// A socket to the rig's endpoint with the session's token, and the endpoint's end of it.
    async fn link_to(rig: &Rig, s: &Session<'_, '_, FakeMicrovmApi, FakeMicrovmApi>) -> (Link, Ws) {
        let (conn, ws) = tokio::join!(AgentConn::open(&s.env.dial, &s.env.target.endpoint, s.token.value().unwrap()), rig.endpoint.next());
        (Link::start(conn.unwrap()), ws)
    }

    // ---- a cat shim ----------------------------------------------------------------------

    /// How the cat shim misbehaves.
    #[derive(Debug, Default, Clone, Copy)]
    struct CatScript {
        /// Socket `n` is cut (no Close) when stdin seq `m` reaches it: that
        /// chunk and everything after it on that socket are lost.
        cut: Option<(usize, u64)>,
        /// A reattach replays stdout from seq 1 (the client drops what it has).
        replay_all: bool,
        /// Socket `n` acks stdin only up to seq `m` (it holds the rest unacked).
        ack_upto: Option<(usize, u64)>,
        /// Socket `n` goes silent after `spawned`: it reads and writes nothing more.
        silent: Option<usize>,
        /// Socket `n` never answers its hello.
        mute: Option<usize>,
        /// Socket `n` is cut at its first ping after the muted socket said hello.
        cut_on_ping: Option<usize>,
    }

    enum Action {
        Go,
        Cut,
        Silent,
    }

    /// A shim running one `cat`: stdin chunks come back as stdout chunks,
    /// `stdin_eof` exits 0; the newest socket that resumes the spawn gets it
    /// (the old one is told `superseded`) and all output.
    #[derive(Default)]
    struct Cat {
        script: CatScript,
        /// Runs once, when the cut happens.
        on_cut: Option<Box<dyn FnOnce() + Send>>,
        spawn: Option<SpawnId>,
        out: Vec<Chunk>,
        in_seq: u64,
        /// (socket, seq) of every stdin frame that arrived, duplicates included.
        stdin: Vec<(usize, u64)>,
        eof: Option<u64>,
        attached: usize,
        writers: Vec<mpsc::UnboundedSender<Message>>,
        hellos: Vec<(usize, Vec<ResumePoint>)>,
        muted: bool,
        closes: Vec<(usize, Option<u16>)>,
        detach: Option<bool>,
    }

    impl Cat {
        fn new(script: CatScript) -> Arc<Mutex<Cat>> {
            Arc::new(Mutex::new(Cat { script, ..Cat::default() }))
        }

        fn send(&self, n: usize, f: &Frame) {
            let _ = self.writers[n - 1].send(Message::from(f));
        }

        fn id(&self) -> SpawnId {
            self.spawn.clone().expect("spawned")
        }

        fn on_frame(&mut self, n: usize, frame: Frame) -> Action {
            match frame {
                Frame::Hello { session_token, resume, .. } => {
                    assert_eq!(session_token.expose(), SESSION_TOKEN);
                    self.hellos.push((n, resume.clone()));
                    if self.script.mute == Some(n) {
                        self.muted = true;
                        return Action::Go;
                    }
                    let mut resumed = Vec::new();
                    let mut replay = None;
                    for r in resume {
                        if Some(&r.spawn_id) == self.spawn.as_ref() {
                            if self.attached != 0 && self.attached != n {
                                self.send(self.attached, &Frame::error(ErrorCode::Superseded, "a newer socket attached", Some(r.spawn_id.clone())));
                            }
                            self.attached = n;
                            replay = Some(if self.script.replay_all { 1 } else { r.from_seq.unwrap_or(1) });
                            resumed.push(Resumed { spawn_id: r.spawn_id, status: ResumeStatus::Ok });
                        } else {
                            resumed.push(Resumed { spawn_id: r.spawn_id, status: ResumeStatus::Unknown });
                        }
                    }
                    let spawns = self.spawn.iter().map(|id| status(id, self.out.len() as u64, self.in_seq)).collect();
                    self.send(n, &hello_ok(spawns, resumed));
                    if let Some(from) = replay {
                        if self.in_seq > 0 {
                            self.send(n, &Frame::StdinAck { spawn_id: self.id(), seq: self.in_seq });
                        }
                        for seq in from..=self.out.len() as u64 {
                            self.send(n, &Frame::Stdout { spawn_id: self.id(), seq, data: self.out[seq as usize - 1].clone() });
                        }
                        self.maybe_exit();
                    }
                    Action::Go
                }
                Frame::Spawn { spawn_id, argv, .. } => {
                    assert_eq!(argv, vec!["cat".to_string()]);
                    self.spawn = Some(spawn_id.clone());
                    self.attached = n;
                    self.send(n, &Frame::Spawned { spawn_id, pid: 4242, pgid: 4242, claude_version: None });
                    if self.script.silent == Some(n) {
                        return Action::Silent;
                    }
                    Action::Go
                }
                Frame::Stdin { spawn_id, seq, data } => {
                    self.stdin.push((n, seq));
                    if self.script.cut.is_some_and(|(s, m)| s == n && seq >= m) {
                        if let Some(hook) = self.on_cut.take() {
                            hook();
                        }
                        return Action::Cut;
                    }
                    if self.attached != n {
                        self.send(n, &Frame::error(ErrorCode::NotAttached, "not attached here", Some(spawn_id)));
                        return Action::Go;
                    }
                    if seq <= self.in_seq {
                        return Action::Go;
                    }
                    assert_eq!(seq, self.in_seq + 1, "a stdin gap");
                    self.in_seq = seq;
                    self.out.push(data.clone());
                    if self.script.ack_upto.is_none_or(|(s, m)| s != n || seq <= m) {
                        self.send(n, &Frame::StdinAck { spawn_id: spawn_id.clone(), seq });
                    }
                    self.send(n, &Frame::Stdout { spawn_id, seq: self.out.len() as u64, data });
                    self.maybe_exit();
                    Action::Go
                }
                Frame::StdinEof { seq, .. } => {
                    self.eof = Some(seq);
                    self.maybe_exit();
                    Action::Go
                }
                Frame::Ping { ts } => {
                    if self.muted && self.script.cut_on_ping == Some(n) {
                        return Action::Cut;
                    }
                    self.send(n, &Frame::Pong { ts });
                    Action::Go
                }
                Frame::Detach { is_final, .. } => {
                    self.detach = Some(is_final);
                    Action::Go
                }
                Frame::Ack { .. } => Action::Go,
                other => panic!("the cat shim got {other:?}"),
            }
        }

        fn maybe_exit(&self) {
            if self.eof.is_some_and(|e| self.in_seq >= e) {
                self.send(self.attached, &Frame::Exit { spawn_id: self.id(), seq: self.out.len() as u64 + 1, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false });
            }
        }
    }

    /// One socket of the cat shim: a writer task fed by the model, and this reader.
    async fn cat_socket(ws: Ws, cat: Arc<Mutex<Cat>>) {
        let (mut sink, mut stream) = ws.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let n = {
            let mut c = cat.lock().unwrap();
            c.writers.push(tx);
            c.writers.len()
        };
        let writer = tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                if sink.send(m).await.is_err() {
                    return;
                }
            }
        });
        while let Some(Ok(msg)) = stream.next().await {
            let frame = match msg {
                Message::Text(t) => Frame::from_json(t.as_str()).unwrap(),
                Message::Close(f) => {
                    cat.lock().unwrap().closes.push((n, f.map(|f| u16::from(f.code))));
                    break;
                }
                _ => continue,
            };
            let action = cat.lock().unwrap().on_frame(n, frame);
            match action {
                Action::Go => {}
                Action::Cut => {
                    writer.abort();
                    return;
                }
                Action::Silent => std::future::pending::<()>().await,
            }
        }
    }

    /// `work` while the cat shim serves every socket the endpoint upgrades.
    async fn with_cat<T>(rig: &Rig, cat: &Arc<Mutex<Cat>>, work: impl std::future::Future<Output = T>) -> T {
        let serve = async {
            while let Some(ws) = rig.endpoint.sockets.lock().await.recv().await {
                tokio::spawn(cat_socket(ws, cat.clone()));
            }
        };
        tokio::select! {
            out = work => out,
            () = serve => unreachable!("the endpoint stopped"),
        }
    }

    /// A whole `cat` session: `input` in, the outcome and what the consumer saw out.
    async fn cat_session(rig: &Rig, cat: &Arc<Mutex<Cat>>, policy: RunPolicy, input: Vec<Vec<u8>>, gap: Duration) -> (Result<SpawnOutcome, BridgeError>, Seen) {
        let env = rig.env(policy);
        let (sio, cio) = spawn_channels(8);
        with_cat(rig, cat, async { tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, Some(input), gap)) }).await
    }

    async fn bounded<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(LIMIT, f).await.expect("the test ran past its limit")
    }

    // ---- the tests -----------------------------------------------------------------------

    /// tests/fixtures/wire/exec-golden.jsonl from both ends: the client's
    /// frames equal the golden Mac lines (between two VM lines in any order;
    /// the spawn id and the host substituted), and the golden VM lines bring
    /// the bytes and the exit.
    #[tokio::test]
    async fn the_golden_conversation_both_directions() {
        bounded(async {
            let rig = rig(true).await;
            let mut env = rig.env(policy());
            env.target.session_token = Secret::new("golden-session-token".into());
            let (sio, cio) = spawn_channels(8);
            let golden_id = "0192f1e0-2b7c-7c3a-9a1b-4d5e6f708192";
            let host = format!("\"host\":{}", serde_json::to_string(&crate::bridge::vm::owner()).unwrap());
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let mut id = String::new();
                let mut want: Vec<String> = Vec::new();
                let check = |want: &mut Vec<String>, got: Vec<String>| {
                    let mut got = got;
                    got.sort();
                    want.sort();
                    assert_eq!(&got, want);
                    want.clear();
                };
                for line in include_str!("../../../tests/fixtures/wire/exec-golden.jsonl").lines() {
                    let raw = line.split_once(",\"frame\":").and_then(|(_, f)| f.strip_suffix('}')).unwrap();
                    if line.starts_with("{\"dir\":\"mac\"") {
                        want.push(raw.to_string());
                        continue;
                    }
                    let mut got = Vec::new();
                    while got.len() < want.len() {
                        let Message::Text(t) = ws.next().await.unwrap().unwrap() else { continue };
                        if let Ok(Frame::Spawn { spawn_id, .. }) = Frame::from_json(t.as_str()) {
                            id = spawn_id.0;
                        }
                        let mut text = t.as_str().replace(&host, "\"host\":\"mike@mbp\"");
                        if !id.is_empty() {
                            text = text.replace(&id, golden_id);
                        }
                        got.push(text);
                    }
                    check(&mut want, got);
                    ws.send(Message::text(raw.replace(golden_id, &id))).await.unwrap();
                }
                let mut got = Vec::new();
                while got.len() < want.len() {
                    if let Message::Text(t) = ws.next().await.unwrap().unwrap() {
                        got.push(t.as_str().replace(&id, golden_id));
                    }
                }
                check(&mut want, got);
                assert!(matches!(ws.next().await, Some(Ok(Message::Close(Some(f)))) if f.code == CloseCode::from(CLOSE_NORMAL)), "closed 1000 after the final ack");
            };
            let consumer = async {
                let ConsumerIo { input, control: _control, mut events, consumed } = cio;
                input.send(SpawnInput::Stdin(b"hello\n".to_vec())).await.unwrap();
                input.send(SpawnInput::Stdin(b"\x00\xff\n".to_vec())).await.unwrap();
                let mut seen = Seen::default();
                while let Some(ev) = events.recv().await {
                    match ev {
                        // Mark only once both chunks are in, after stdin's EOF (the golden order).
                        SpawnEvent::Stdout { seq, bytes } => {
                            seen.stdout.extend(bytes);
                            if seq == 2 {
                                input.send(SpawnInput::StdinEof).await.unwrap();
                                consumed.stdout_done(2);
                            }
                        }
                        other => seen.add(other, &consumed),
                    }
                }
                seen
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer, shim);
            let out = result.unwrap();
            assert_eq!((out.exit.status(), out.spawn_id.is_v7()), (0, true));
            assert_eq!(seen.stdout, b"hello\n\x00\xff\n");
            assert_eq!((seen.started, seen.exit.map(|e| e.code)), (Some((4242, 4242)), Some(Some(0))));
        })
        .await;
    }

    #[tokio::test]
    async fn a_cut_mid_stream_reattaches_resends_stdin_above_in_seq_and_dedupes_stdout() {
        bounded(async {
            let rig = rig(true).await;
            // Socket 1 holds stdin 1..8 but acks only 1..4: the resend starts above in_seq 8, not above the last ack.
            let cat = Cat::new(CatScript { cut: Some((1, 9)), replay_all: true, ack_upto: Some((1, 4)), ..CatScript::default() });
            let input = lines(30);
            let (result, seen) = cat_session(&rig, &cat, policy(), input.clone(), Duration::from_millis(2)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat(), "every byte once, in order");
            assert_eq!(seen.out_seqs, (1..=30).collect::<Vec<u64>>(), "no seq twice, none skipped");
            assert_eq!(seen.started, Some((4242, 4242)), "one spawn, one pid");
            let c = cat.lock().unwrap();
            let on_2: Vec<u64> = c.stdin.iter().filter(|(n, _)| *n == 2).map(|(_, s)| *s).collect();
            assert_eq!(on_2.first(), Some(&9), "the resend starts above in_seq 8: {on_2:?}");
            assert!(on_2.windows(2).all(|w| w[1] == w[0] + 1), "{on_2:?}");
            assert_eq!(c.hellos.len(), 2);
            assert!(c.hellos[1].1[0].from_seq.is_some_and(|f| (2..=9).contains(&f)), "{:?}", c.hellos[1].1);
            assert!(seen.notes.iter().any(|n| n.starts_with("lost the connection")) && seen.notes.iter().any(|n| n.starts_with("reattached to spawn")), "{:?}", seen.notes);
            assert_eq!(seen.links, [false, true], "the link went down, then up");
            let rows = rig.audit("agent_reconnect");
            assert_eq!(rows.len(), 1);
            assert!(rows[0]["detail"]["ms"].as_str().is_some_and(|ms| ms.parse::<u64>().is_ok()));
        })
        .await;
    }

    #[tokio::test]
    async fn token_rejected_twice_remints_once_then_exit_7() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..2 {
                rig.endpoint.refuse(refusal(403, &[("x-aws-proxy-error", "UNAUTHORIZED")], ""));
            }
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::TokenRejected { port: 8080, status: 403, proxy_error: Some(p) } if p == "UNAUTHORIZED"), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 2, "the first token and exactly one re-mint");
            assert_eq!(rig.endpoint.attempts().len(), 2);
            assert_eq!(rig.audit("agent_remint").len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn throttled_waits_its_retry_after_and_never_remints() {
        bounded(async {
            let rig = rig(true).await;
            rig.endpoint.refuse(refusal(429, &[("retry-after", "2")], ""));
            let mut p = policy();
            // One second of Retry-After is one backoff_min: 2 → 200 ms, the backoff alone ≤ 125 ms.
            p.backoff_min = Duration::from_millis(100);
            p.backoff_max = Duration::from_millis(400);
            let cat = Cat::new(CatScript::default());
            let (result, seen) = cat_session(&rig, &cat, p, lines(3), Duration::ZERO).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, lines(3).concat());
            let a = rig.endpoint.attempts();
            assert_eq!(a.iter().map(|a| a.status).collect::<Vec<_>>(), vec![429, 101]);
            assert!(a[1].at - a[0].at >= Duration::from_millis(200), "waited {:?}", a[1].at - a[0].at);
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 1, "a 429 never re-mints");
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["detail"]["retry_after"], "2");
            assert!(rows[0]["detail"]["waited_ms"].as_str().unwrap().parse::<u64>().unwrap() >= 200);
            assert!(seen.notes.iter().any(|n| n.contains("HTTP 429")), "{:?}", seen.notes);
        })
        .await;
    }

    #[tokio::test]
    async fn throttled_without_retry_after_backs_off_exponentially() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..3 {
                rig.endpoint.refuse(refusal(429, &[], ""));
            }
            let mut p = policy();
            p.backoff_min = Duration::from_millis(200);
            p.backoff_max = Duration::from_secs(4);
            let cat = Cat::new(CatScript::default());
            let (result, _) = cat_session(&rig, &cat, p, lines(2), Duration::ZERO).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            let a = rig.endpoint.attempts();
            assert_eq!(a.iter().map(|a| a.status).collect::<Vec<_>>(), vec![429, 429, 429, 101]);
            // 200, 400, 800 ms, each ±25 %: the steps double. The third wait is at
            // least twice the first (its floor 600 ms, the first's ceiling 250 ms),
            // which no constant step is, jittered or not; 100 ms of slack for load.
            let gaps: Vec<Duration> = a.windows(2).map(|w| w[1].at - w[0].at).collect();
            assert!(gaps[0] >= Duration::from_millis(150) && gaps[0] < Duration::from_millis(600) && gaps[1] >= Duration::from_millis(300) && gaps[2] >= Duration::from_millis(600) && gaps[2] >= gaps[0] * 2, "{gaps:?}");
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 1, "a 429 never re-mints");
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 3);
            assert!(rows.iter().all(|r| r["detail"]["retry_after"] == "none"));
        })
        .await;
    }

    #[tokio::test]
    async fn throttled_past_the_budget_is_exit_7() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..100 {
                rig.endpoint.refuse(refusal(429, &[("retry-after", "1")], ""));
            }
            let mut p = policy();
            p.reconnect_budget = Duration::from_millis(300);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(e, BridgeError::EndpointThrottled { retry_after_s: Some(1) }), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
        })
        .await;
    }

    /// The 429 that ends the session has its `endpoint_429` row: it is
    /// written as the 429 is classified, before the budget is checked.
    #[tokio::test]
    async fn a_429_past_the_budget_is_audited_before_exit_7() {
        bounded(async {
            let rig = rig(true).await;
            // Retry-After 1000: 10 s at this policy, past its 5 s budget at once.
            rig.endpoint.refuse(refusal(429, &[("retry-after", "1000")], ""));
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(e, BridgeError::EndpointThrottled { retry_after_s: Some(1000) }), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
            assert_eq!(rig.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![429]);
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!((rows[0]["detail"]["retry_after"].as_str(), rows[0]["detail"]["waited_ms"].as_str()), (Some("1000"), Some("10000")), "the wait it set");
        })
        .await;
    }

    /// A detach during a 429's wait ends the session there, and the 429 was audited already.
    #[tokio::test]
    async fn a_detach_during_a_429_wait_leaves_its_audit_row() {
        bounded(async {
            let rig = rig(true).await;
            // Retry-After 300: a 3 s wait at this policy, within its budget.
            rig.endpoint.refuse(refusal(429, &[("retry-after", "300")], ""));
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let consumer = async {
                let ConsumerIo { input: _input, control, mut events, consumed: _c } = cio;
                // The note comes as the wait starts.
                while let Some(ev) = events.recv().await {
                    if matches!(&ev, SpawnEvent::Note(n) if n.contains("HTTP 429")) {
                        control.send(SpawnInput::Detach { is_final: true }).unwrap();
                    }
                }
            };
            let started = Instant::now();
            let (result, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::Transport(m) if m.contains("while disconnected")), "{e}");
            assert!(started.elapsed() < Duration::from_secs(2), "the detach cut the 3 s wait short: {:?}", started.elapsed());
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0]["detail"]["retry_after"], "300");
        })
        .await;
    }

    /// A detach while the dial or the hello is under way ends the session
    /// there (`watching`): at once — not after the dial's 60 s or the hello's
    /// `dead_after` — and no `spawn` goes out.
    #[tokio::test]
    async fn a_detach_during_the_dial_or_the_hello_ends_the_session_at_once() {
        bounded(async {
            let rig = rig(true).await;
            {
                // The dial: a loopback listener takes the connection and never answers the upgrade.
                let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut env = rig.env(policy());
                env.dial = AgentDial { local: Some(silent.local_addr().unwrap()) };
                let (sio, cio) = spawn_channels(8);
                let session = run_spawn(&env, Start::New(cat_spec()), sio);
                tokio::pin!(session);
                let _held = tokio::select! {
                    tcp = silent.accept() => tcp.unwrap(),
                    r = &mut session => panic!("the session ended before its dial: {:?}", r.err()),
                };
                cio.control.send(SpawnInput::Detach { is_final: true }).unwrap();
                let e = tokio::time::timeout(Duration::from_secs(2), &mut session).await.expect("the detach ended the dial at once").unwrap_err();
                assert!(matches!(&e, BridgeError::Transport(m) if m.contains("while disconnected")), "{e}");
            }
            {
                // The hello: the endpoint upgrades; the shim reads the hello and never answers it.
                let env = rig.env(policy());
                let (sio, cio) = spawn_channels(8);
                let session = run_spawn(&env, Start::New(cat_spec()), sio);
                tokio::pin!(session);
                let mut ws = tokio::select! {
                    ws = rig.endpoint.next() => ws,
                    r = &mut session => panic!("the session ended before its hello: {:?}", r.err()),
                };
                let hello = tokio::select! {
                    f = frame(&mut ws) => f,
                    r = &mut session => panic!("the session ended before its hello: {:?}", r.err()),
                };
                assert!(matches!(hello, Frame::Hello { .. }), "{hello:?}");
                cio.control.send(SpawnInput::Detach { is_final: true }).unwrap();
                let e = tokio::time::timeout(Duration::from_secs(2), &mut session).await.expect("the detach ended the hello at once").unwrap_err();
                assert!(matches!(&e, BridgeError::Transport(m) if m.contains("while disconnected")), "{e}");
                while let Ok(Some(Ok(m))) = tokio::time::timeout(Duration::from_millis(200), ws.next()).await {
                    if let Message::Text(t) = m {
                        assert!(!matches!(Frame::from_json(t.as_str()), Ok(Frame::Spawn { .. })), "a spawn went out after the detach");
                    }
                }
            }
        })
        .await;
    }

    #[tokio::test]
    async fn not_run_is_retried_then_succeeds() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..2 {
                rig.endpoint.refuse(refusal(503, &[("retry-after", "1"), ("content-type", "application/json")], r#"{"status":"not_run"}"#));
            }
            let cat = Cat::new(CatScript::default());
            let (result, seen) = cat_session(&rig, &cat, policy(), lines(2), Duration::ZERO).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, lines(2).concat());
            assert_eq!(rig.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![503, 503, 101]);
        })
        .await;
    }

    #[tokio::test]
    async fn not_run_past_its_budget_is_exit_8() {
        bounded(async {
            let rig = rig(true).await;
            for _ in 0..200 {
                rig.endpoint.refuse(refusal(503, &[], r#"{"status":"not_run"}"#));
            }
            let mut p = policy();
            p.not_run_budget = Duration::from_millis(200);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::ShimUnavailable(m) if m.contains("not_run")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    /// The VM is suspended under the session (no hook event seen) and has no
    /// auto-resume: the redial gets 502, GetMicrovm says SUSPENDED, one
    /// ResumeMicrovm, then the spawn is reattached.
    #[tokio::test]
    async fn gateway_with_a_suspended_vm_resumes_it_once_then_reattaches() {
        bounded(async {
            let rig = rig(false).await;
            let cat = Cat::new(CatScript { cut: Some((1, 5)), ..CatScript::default() });
            let (api, id) = (rig.api.clone(), rig.vm.id.clone());
            cat.lock().unwrap().on_cut = Some(Box::new(move || api.set_state(&id, VmState::Suspended)));
            let input = lines(12);
            let (result, seen) = cat_session(&rig, &cat, policy(), input.clone(), Duration::from_millis(2)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat());
            assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 1, "exactly one ResumeMicrovm");
            let statuses: Vec<u16> = rig.endpoint.attempts().iter().map(|a| a.status).collect();
            assert!(statuses.contains(&502) && statuses.last() == Some(&101), "{statuses:?}");
            assert!(seen.notes.iter().any(|n| n.contains("resuming it")), "{:?}", seen.notes);
        })
        .await;
    }

    /// ResumeMicrovm answers Conflict (someone else is resuming it): fine; the VM turns RUNNING meanwhile.
    #[tokio::test]
    async fn a_resume_conflict_is_a_resume_under_way() {
        bounded(async {
            let rig = rig(false).await;
            rig.api.fail_on("resume", BridgeError::Conflict("resume already in progress".into()), false);
            let cat = Cat::new(CatScript { cut: Some((1, 4)), ..CatScript::default() });
            let (api, id) = (rig.api.clone(), rig.vm.id.clone());
            cat.lock().unwrap().on_cut = Some(Box::new(move || {
                api.set_state(&id, VmState::Suspended);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    api.set_state(&id, VmState::Running);
                });
            }));
            let input = lines(8);
            let (result, seen) = cat_session(&rig, &cat, policy(), input.clone(), Duration::from_millis(2)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat());
            assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 1, "one resume, its Conflict tolerated");
        })
        .await;
    }

    #[tokio::test]
    async fn hook_suspend_never_redials_until_the_vm_runs_again() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                rig.api.set_state(&rig.vm.id, VmState::Suspended);
                put(&mut ws, &Frame::Event { kind: EventKind::HookSuspend, at: "2026-10-03T12:00:00Z".into(), reference: None }).await;
                ws.close(Some(CloseFrame { code: CloseCode::from(CLOSE_GOING_AWAY), reason: "suspend".into() })).await.unwrap();
                tokio::time::sleep(Duration::from_millis(400)).await;
                assert_eq!(rig.endpoint.attempts().len(), 1, "no dial while the VM is suspended");
                assert!(rig.calls(|c| matches!(c, Call::Get(_))) >= 3, "it polls GetMicrovm instead");
                assert_eq!(rig.calls(|c| matches!(c, Call::Resume(_))), 0, "it never resumes the VM itself");
                rig.api.set_state(&rig.vm.id, VmState::Running);
                let mut ws = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws).await else { panic!("no hello") };
                assert_eq!(resume, vec![ResumePoint { spawn_id: id.clone(), from_seq: Some(1), err_from_seq: Some(1) }]);
                put(&mut ws, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws, &Frame::Exit { spawn_id: id.clone(), seq: 1, code: Some(3), signal: None, stderr_dropped: 0, stdout_truncated: false }).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 3);
            assert!(seen.notes.iter().any(|n| n.contains("was suspended")), "{:?}", seen.notes);
            assert_eq!(seen.links, [false, true], "down while suspended, up once reattached");
        })
        .await;
    }

    #[tokio::test]
    async fn hook_suspend_gives_up_after_suspend_wait_naming_resume_and_attach() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = policy();
            p.suspend_wait = Duration::from_millis(200);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                rig.api.set_state(&rig.vm.id, VmState::Suspended);
                put(&mut ws, &Frame::Event { kind: EventKind::HookSuspend, at: "2026-10-03T12:00:00Z".into(), reference: None }).await;
                ws.close(Some(CloseFrame { code: CloseCode::from(CLOSE_GOING_AWAY), reason: "suspend".into() })).await.unwrap();
                id
            };
            let (result, _, id) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            let text = e.to_string();
            let vm = &rig.vm.id;
            assert!(text.contains(&format!("ai-env vm resume {vm}")) && text.contains(&format!("ai-env vm attach {vm} --spawn {id}")), "{text}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert_eq!(rig.endpoint.attempts().len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn hook_terminate_is_terminated() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                start_spawn(&mut ws).await;
                put(&mut ws, &Frame::Event { kind: EventKind::HookTerminate, at: "2026-10-03T12:00:00Z".into(), reference: None }).await;
                ws
            };
            let (result, _, _ws) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(e, BridgeError::Terminated(_)), "{e}");
        })
        .await;
    }

    #[tokio::test]
    async fn hello_err_bad_token_is_refused_exit_8() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &Frame::HelloErr { code: HelloErrCode::BadToken, message: "the token does not match this VM".into() }).await;
                ws.close(Some(CloseFrame { code: CloseCode::from(CLOSE_HELLO_REFUSED), reason: "bad_token".into() })).await.unwrap();
                ws
            };
            let (result, _, _ws) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::HelloRefused { code, .. } if code == "bad_token"), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert_eq!(rig.endpoint.attempts().len(), 1, "a refused hello is never retried");
        })
        .await;
    }

    /// A `--shell` row's target gets no session, whoever the caller (D1):
    /// a new spawn and a reattach are refused before anything reaches the VM
    /// (no mint, no GetMicrovm, no dial) with a policy error (exit 9) naming
    /// the unguarded platform shell and in-vm-firewall.
    #[tokio::test]
    async fn a_shell_rows_target_is_refused_before_any_mint_or_dial() {
        bounded(async {
            let rig = rig(true).await;
            let mut env = rig.env(policy());
            env.target.shell = true;
            let before = rig.api.calls().len();
            for start in [Start::New(cat_spec()), Start::Attach { spawn_id: SpawnId::new_v7(), from_seq: None, err_from_seq: None }] {
                let (sio, cio) = spawn_channels(8);
                let (result, seen) = tokio::join!(run_spawn(&env, start, sio), consume(cio, None, Duration::ZERO));
                let e = result.unwrap_err();
                let says = format!("{} was started with --shell: no command runs on it until the platform shell's in-VM listener, which the shim does not guard, is shown unreachable from the agent (ai-env lab run in-vm-firewall measures it)", rig.vm.id);
                assert!(matches!(&e, BridgeError::Policy(m) if m.starts_with(&says)), "{e}");
                assert_eq!(CliError::from(e).exit_code(), 9);
                assert!(seen.notes.is_empty() && seen.started.is_none(), "{seen:?}");
            }
            assert_eq!(rig.api.calls().len(), before, "nothing reached the API: {:?}", rig.api.calls());
            assert!(rig.endpoint.attempts().is_empty(), "no dial: {:?}", rig.endpoint.attempts());
        })
        .await;
    }

    #[tokio::test]
    async fn a_silent_socket_is_dead_after_dead_after_and_replaced() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript { silent: Some(1), ..CatScript::default() });
            let mut p = policy();
            p.ping = Duration::from_millis(50);
            p.ws_ping = Duration::from_millis(50);
            p.dead_after = Duration::from_millis(300);
            let input = lines(10);
            let (result, seen) = cat_session(&rig, &cat, p, input.clone(), Duration::from_millis(20)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat());
            assert!(seen.notes.iter().any(|n| n.contains("no frame for")), "{:?}", seen.notes);
            assert_eq!(cat.lock().unwrap().hellos.len(), 2);
        })
        .await;
    }

    /// A one-minute token with rotation 59 s before its expiry: within a
    /// second a second socket says hello with the resume, the first is closed
    /// 1000, and the stream goes on without a byte lost or doubled.
    #[tokio::test]
    async fn proactive_rotation_moves_the_spawn_to_a_second_socket() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript::default());
            let input = lines(60);
            let (result, seen) = cat_session(&rig, &cat, rotation_policy(), input.clone(), Duration::from_millis(25)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat(), "no output lost or doubled");
            assert_eq!(seen.out_seqs, (1..=60).collect::<Vec<u64>>());
            let c = cat.lock().unwrap();
            assert!(c.hellos.len() >= 2, "a second socket said hello");
            assert!(c.hellos[1].1.first().is_some_and(|r| Some(&r.spawn_id) == c.spawn.as_ref()), "with the resume");
            assert!(c.closes.contains(&(1, Some(CLOSE_NORMAL))), "the first socket was closed 1000: {:?}", c.closes);
            drop(c);
            assert!(rig.audit("agent_rotate").iter().all(|r| r["detail"]["mode"] == "proactive") && !rig.audit("agent_rotate").is_empty());
            assert!(rig.calls(|c| matches!(c, Call::Token { minutes: 1, .. })) >= 2);
            assert!(rig.endpoint.attempts().iter().all(|a| a.status == 101));
            assert!(seen.notes.iter().any(|n| n.starts_with("rotated to a fresh endpoint token")), "{:?}", seen.notes);
        })
        .await;
    }

    /// The first socket is lost while the rotation's socket still waits for
    /// its hello_ok: the reconnect's socket carries the spawn at once (the
    /// stdin queued meanwhile goes out on it, before any further rotation).
    #[tokio::test]
    async fn a_socket_lost_during_a_rotation_reconnects_unpaused() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript { mute: Some(2), cut_on_ping: Some(1), ..CatScript::default() });
            let mut p = rotation_policy();
            p.ping = Duration::from_millis(100);
            let input = lines(80);
            let (result, seen) = cat_session(&rig, &cat, p, input.clone(), Duration::from_millis(25)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, input.concat());
            let c = cat.lock().unwrap();
            let sockets: Vec<usize> = c.hellos.iter().map(|(n, _)| *n).collect();
            assert!(c.muted && sockets.contains(&3), "the third socket took over: {sockets:?}");
            assert!(c.stdin.iter().any(|(n, _)| *n == 3), "stdin flowed on the reconnected socket: {:?}", c.stdin);
        })
        .await;
    }

    #[tokio::test]
    async fn acks_carry_only_what_the_consumer_marked() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let (mark_tx, mut mark_rx) = mpsc::unbounded_channel::<u64>();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                for (seq, text) in [(1, "a"), (2, "b"), (3, "c")] {
                    put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq, data: Chunk { text: Some(text.into()), b64: None } }).await;
                }
                assert!(tokio::time::timeout(Duration::from_millis(150), frame(&mut ws)).await.is_err(), "nothing is acked before the consumer marks it");
                mark_tx.send(2).unwrap();
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id.clone(), seq: 2, err_seq: 0 });
                mark_tx.send(3).unwrap();
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id.clone(), seq: 3, err_seq: 0 });
                put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq: 4, data: Chunk { text: Some("d".into()), b64: None } }).await;
                put(&mut ws, &Frame::Exit { spawn_id: id.clone(), seq: 5, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false }).await;
                assert!(tokio::time::timeout(Duration::from_millis(150), frame(&mut ws)).await.is_err(), "the exit waits for the last chunk's mark");
                mark_tx.send(4).unwrap();
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id, seq: 5, err_seq: 0 }, "the exit's seq releases the spawn");
            };
            let consumer = async {
                let ConsumerIo { input: _input, control: _control, mut events, consumed } = cio;
                let mut out = Vec::new();
                loop {
                    tokio::select! {
                        ev = events.recv() => match ev {
                            Some(SpawnEvent::Stdout { bytes, .. }) => out.extend(bytes),
                            Some(_) => {}
                            None => return out,
                        },
                        Some(seq) = mark_rx.recv() => consumed.stdout_done(seq),
                    }
                }
            };
            let (result, out, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer, shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(out, b"abcd");
        })
        .await;
    }

    /// The byte cadence: once `ack_bytes` are consumed the ack goes out at
    /// once, without waiting for the timer (an hour away here; the tick's
    /// other bounds are 15 s, and its immediate first tick is long past).
    #[tokio::test]
    async fn consuming_ack_bytes_acks_at_once_without_the_timer() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = policy();
            p.ack_bytes = 8;
            p.ack_every = Duration::from_secs(3600);
            p.dead_after = Duration::from_secs(60);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                // Past the interval's first tick (it fires at once): only the bytes can ack now.
                tokio::time::sleep(Duration::from_millis(200)).await;
                for (seq, text) in [(1, "abcd"), (2, "efgh")] {
                    put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq, data: Chunk { text: Some(text.into()), b64: None } }).await;
                }
                let ack = tokio::time::timeout(Duration::from_secs(2), frame(&mut ws)).await.expect("8 bytes consumed: acked at once, not at the next tick");
                assert_eq!(ack, Frame::Ack { spawn_id: id.clone(), seq: 2, err_seq: 0 }, "4 bytes alone are no ack");
                put(&mut ws, &exit0(&id, 3)).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id, seq: 3, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, b"abcdefgh");
        })
        .await;
    }

    /// The time cadence: what the consumer marked is acked within
    /// `ack_every` (10 ms here) however few bytes it is, not at the tick's
    /// other bounds (pings an hour away, dead_after / 4 = 15 s).
    #[tokio::test]
    async fn a_mark_below_ack_bytes_is_acked_within_ack_every() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = policy();
            p.dead_after = Duration::from_secs(60);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
                put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq: 1, data: Chunk { text: Some("a".into()), b64: None } }).await;
                let ack = tokio::time::timeout(Duration::from_secs(2), frame(&mut ws)).await.expect("acked within ack_every, not at a 15 s tick");
                assert_eq!(ack, Frame::Ack { spawn_id: id.clone(), seq: 1, err_seq: 0 });
                put(&mut ws, &exit0(&id, 2)).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id, seq: 2, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, b"a");
        })
        .await;
    }

    #[tokio::test]
    async fn keep_alive_gets_health_while_the_spawn_runs() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript::default());
            let mut p = policy();
            p.keepalive = Keepalive::Http;
            p.keepalive_every = Duration::from_millis(30);
            let (result, _) = cat_session(&rig, &cat, p, lines(20), Duration::from_millis(10)).await;
            assert_eq!(result.unwrap().exit.status(), 0);
            assert!(rig.calls(|c| matches!(c, Call::Health { port: 8080, .. })) >= 2, "{:?}", rig.api.calls());
        })
        .await;
    }

    #[tokio::test]
    async fn a_detach_goes_out_and_ends_the_session() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript::default());
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let consumer = async {
                let ConsumerIo { input, control, mut events, consumed: _c } = cio;
                input.send(SpawnInput::Stdin(b"x\n".to_vec())).await.unwrap();
                while let Some(ev) = events.recv().await {
                    if matches!(ev, SpawnEvent::Stdout { .. }) {
                        control.send(SpawnInput::Detach { is_final: true }).unwrap();
                    }
                }
            };
            let (result, ()) = with_cat(&rig, &cat, async { tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer) }).await;
            let e = result.unwrap_err();
            assert!(e.to_string().contains("detached from spawn"), "{e}");
            assert_eq!(cat.lock().unwrap().detach, Some(true));
        })
        .await;
    }

    #[tokio::test]
    async fn no_connection_to_a_running_vm_gives_up_after_the_budget() {
        bounded(async {
            let rig = rig(true).await;
            let mut env = rig.env(policy());
            env.dial = AgentDial { local: Some(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap()) };
            env.policy.reconnect_budget = Duration::from_millis(300);
            let (sio, cio) = spawn_channels(8);
            let (result, _) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO));
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::ShimUnavailable(m) if m.contains("connect")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert!(rig.calls(|c| matches!(c, Call::Get(_))) >= 2, "each failed dial asks GetMicrovm");
        })
        .await;
    }

    #[tokio::test]
    async fn a_terminated_vm_ends_the_reconnect() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript { cut: Some((1, 3)), ..CatScript::default() });
            let (api, id) = (rig.api.clone(), rig.vm.id.clone());
            cat.lock().unwrap().on_cut = Some(Box::new(move || api.set_state(&id, VmState::Terminated)));
            let (result, _) = cat_session(&rig, &cat, policy(), lines(5), Duration::from_millis(2)).await;
            let e = result.unwrap_err();
            assert!(matches!(e, BridgeError::Terminated(_)), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    /// A VM back in PENDING (502 from the proxy) gets 60 of the policy's seconds, then exit 8.
    #[tokio::test]
    async fn a_vm_that_stays_pending_is_given_up_on() {
        bounded(async {
            let rig = rig(true).await;
            let cat = Cat::new(CatScript { cut: Some((1, 3)), ..CatScript::default() });
            let (api, id) = (rig.api.clone(), rig.vm.id.clone());
            cat.lock().unwrap().on_cut = Some(Box::new(move || api.set_state(&id, VmState::Pending)));
            let started = Instant::now();
            let (result, _) = cat_session(&rig, &cat, policy(), lines(5), Duration::from_millis(2)).await;
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::ShimUnavailable(m) if m.contains("still PENDING")), "{e}");
            assert!(started.elapsed() >= Duration::from_millis(600), "60 × backoff_min");
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    #[tokio::test]
    async fn spawn_err_names_its_code() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                let Frame::Spawn { spawn_id, .. } = frame(&mut ws).await else { panic!("no spawn") };
                put(&mut ws, &Frame::SpawnErr { spawn_id, code: crate::wire::frame::SpawnErrCode::Cwd, message: "cannot create the working directory".into() }).await;
                ws
            };
            let (result, _, _ws) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::SpawnRefused { code: "cwd", message } if message.contains("working directory")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 1, "the command could not start: the operator's to fix, not a lost VM");
        })
        .await;
    }

    /// The codes the operator cannot act on stay protocol errors (exit 8).
    #[tokio::test]
    async fn spawn_err_of_the_shims_own_making_is_a_protocol_error() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                let Frame::Spawn { spawn_id, .. } = frame(&mut ws).await else { panic!("no spawn") };
                put(&mut ws, &Frame::SpawnErr { spawn_id, code: crate::wire::frame::SpawnErrCode::Exists, message: "the spawn id is in use".into() }).await;
                ws
            };
            let (result, _, _ws) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            assert!(matches!(&e, BridgeError::Protocol(m) if m.contains("(exists)")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
        })
        .await;
    }

    /// The socket is lost after `spawn` went out and before `spawned` came
    /// back, and the shim released the spawn meanwhile: the resume answers
    /// `unknown`, the spawn goes out again (the note says so, not "reattached"),
    /// and the shim refuses its used id (`spawn_err exists`). The session ends
    /// with exit 8 naming `vm attach` — it never waits for a second `spawned`,
    /// nor sends a third `spawn`.
    #[tokio::test]
    async fn a_resent_spawn_whose_id_the_shim_used_is_exit_8() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws1).await, Frame::Hello { .. }));
                put(&mut ws1, &hello_ok(vec![], vec![])).await;
                let Frame::Spawn { spawn_id: id, .. } = frame(&mut ws1).await else { panic!("no spawn") };
                // Cut (no Close) before `spawned`.
                drop(ws1);
                let mut ws2 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws2).await else { panic!("no hello") };
                assert_eq!(resume, vec![ResumePoint { spawn_id: id.clone(), from_seq: Some(1), err_from_seq: Some(1) }]);
                put(&mut ws2, &hello_ok(vec![], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Unknown }])).await;
                let Frame::Spawn { spawn_id, .. } = frame(&mut ws2).await else { panic!("the spawn did not go out again") };
                assert_eq!(spawn_id, id, "the same id");
                put(&mut ws2, &Frame::SpawnErr { spawn_id: id.clone(), code: SpawnErrCode::Exists, message: format!("spawn {id} was already started") }).await;
                while let Ok(Some(Ok(m))) = tokio::time::timeout(LIMIT, ws2.next()).await {
                    if let Message::Text(t) = m {
                        assert!(!matches!(Frame::from_json(t.as_str()), Ok(Frame::Spawn { .. })), "a third spawn");
                    }
                }
                id
            };
            let (result, seen, id) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            let e = result.unwrap_err();
            let vm = &rig.vm.id;
            let says = format!("spawn {id} reached {vm} before the connection was lost: it ran, or still runs, without this client and was not started again (`ai-env vm attach {vm} --spawn {id}` reattaches to it while it runs)");
            assert!(matches!(&e, BridgeError::Transport(m) if *m == says), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            assert_eq!(seen.started, None, "the spawn never started for this client");
            assert_eq!(rig.endpoint.attempts().len(), 2, "no third socket");
            // Socket numbers are the process's (tests run side by side): any.
            let again = format!("sent spawn {id} again after ");
            assert!(seen.notes.iter().any(|n| n.starts_with(&again) && n.contains(" ms (socket ") && n.ends_with("): the VM did not hold it")), "{:?}", seen.notes);
            assert!(!seen.notes.iter().any(|n| n.starts_with("reattached")), "nothing was reattached: {:?}", seen.notes);
            assert_eq!(seen.links, [false, true], "down at the loss, up once the spawn went out again");
            assert_eq!(rig.audit("agent_reconnect").len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn attach_continues_the_shims_stdin_numbering_and_replays_from_the_asked_seq() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let id = SpawnId::new_v7();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws).await else { panic!("no hello") };
                assert_eq!(resume, vec![ResumePoint { spawn_id: id.clone(), from_seq: Some(5), err_from_seq: None }]);
                put(&mut ws, &hello_ok(vec![status(&id, 6, 40)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                for (seq, text) in [(4, "old"), (5, "five"), (6, "six")] {
                    put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq, data: Chunk { text: Some(text.into()), b64: None } }).await;
                }
                // Acks of the replayed chunks may come first.
                let seq = loop {
                    match frame(&mut ws).await {
                        Frame::Stdin { seq, .. } => break seq,
                        Frame::Ack { .. } => {}
                        other => panic!("expected stdin, got {other:?}"),
                    }
                };
                assert_eq!(seq, 41, "a second client's stdin continues after the shim's in_seq");
                put(&mut ws, &Frame::Exit { spawn_id: id.clone(), seq: 7, code: Some(0), signal: None, stderr_dropped: 0, stdout_truncated: false }).await;
                loop {
                    if let Frame::Ack { seq: 7, .. } = frame(&mut ws).await {
                        break;
                    }
                }
            };
            let consumer = consume(cio, Some(vec![b"more\n".to_vec()]), Duration::ZERO);
            let start = Start::Attach { spawn_id: id.clone(), from_seq: Some(5), err_from_seq: None };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, start, sio), consumer, shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(seen.stdout, b"fivesix", "nothing below the asked seq");
            assert_eq!(seen.started, Some((4242, 4242)));
        })
        .await;
    }

    /// `vm attach`: input typed while the first dial is retried waits for
    /// the first hello_ok, then continues the shim's numbering (after its
    /// in_seq 40), its EOF too; nothing is numbered from 1 and then taken for
    /// stdin the shim already holds.
    #[tokio::test]
    async fn attach_takes_input_only_once_the_first_hello_ok_fixed_its_numbering() {
        bounded(async {
            let rig = rig(true).await;
            rig.endpoint.refuse(refusal(503, &[], r#"{"status":"not_run"}"#));
            let mut p = policy();
            p.backoff_min = Duration::from_millis(300);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let id = SpawnId::new_v7();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![status(&id, 0, 40)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                let Frame::Stdin { seq, data, .. } = frame(&mut ws).await else { panic!("the input typed during the retry never came") };
                assert_eq!((seq, decode(&data).unwrap()), (41, b"typed during the retry\n".to_vec()), "it continues after in_seq 40");
                assert_eq!(frame(&mut ws).await, Frame::StdinEof { spawn_id: id.clone(), seq: 41 });
                put(&mut ws, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id.clone(), seq: 1, err_seq: 0 });
            };
            let start = Start::Attach { spawn_id: id.clone(), from_seq: None, err_from_seq: None };
            let consumer = consume(cio, Some(vec![b"typed during the retry\n".to_vec()]), Duration::ZERO);
            let (result, _, ()) = tokio::join!(run_spawn(&env, start, sio), consumer, shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(rig.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![503, 101]);
        })
        .await;
    }

    /// `vm attach --from-seq 5` to a spawn that exits at seq 5: nothing was
    /// delivered, so nothing waits for marks; the exit's seq is acked at once.
    #[tokio::test]
    async fn an_attach_that_delivered_nothing_acks_the_exit_at_once() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = policy();
            p.dead_after = Duration::from_secs(3);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let id = SpawnId::new_v7();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![status(&id, 4, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws, &exit0(&id, 5)).await;
                assert_eq!(frame(&mut ws).await, Frame::Ack { spawn_id: id.clone(), seq: 5, err_seq: 0 }, "the exit's seq releases the spawn");
            };
            let started = Instant::now();
            let start = Start::Attach { spawn_id: id.clone(), from_seq: Some(5), err_from_seq: None };
            let (result, _, ()) = tokio::join!(run_spawn(&env, start, sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert!(started.elapsed() < Duration::from_secs(2), "it waited {:?} for marks of output it never delivered", started.elapsed());
        })
        .await;
    }

    /// A send that fails mid-flush leaves what is still queued (a signal, the
    /// detach) for the next socket, which sends it: nothing is popped into a
    /// dead link, and the detach is not taken for sent.
    #[tokio::test]
    async fn a_failed_send_keeps_the_signals_and_the_detach_for_the_next_socket() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            (s.st.phase, s.attached) = (Phase::Running, true);
            let (mut dead, _ws1) = link_to(&rig, &s).await;
            // After its Close every send on it fails.
            dead.tx.close(CLOSE_NORMAL).await;
            s.st.take(SpawnInput::Stdin(b"a\n".to_vec()));
            s.st.take(SpawnInput::Signal(Sig::Int));
            s.st.take(SpawnInput::Detach { is_final: true });
            s.flush(&mut dead).await;
            assert!(dead.broken.is_some());
            assert_eq!((Vec::from(s.st.signals.clone()), s.st.detach, s.st.detach_sent), (vec![Sig::Int], Some(true), false), "nothing left its queue");
            let (mut live, mut ws2) = link_to(&rig, &s).await;
            s.st.reattached(None);
            s.flush(&mut live).await;
            let id = s.st.id.clone();
            assert!(matches!(frame(&mut ws2).await, Frame::Stdin { seq: 1, .. }));
            assert_eq!(frame(&mut ws2).await, Frame::Signal { spawn_id: id.clone(), sig: Sig::Int, scope: Scope::Group });
            assert_eq!(frame(&mut ws2).await, Frame::Detach { spawn_id: id, is_final: true });
            assert!(s.st.signals.is_empty() && s.st.detach.is_none() && s.st.detach_sent);
        })
        .await;
    }

    /// The rotation's socket dies after its hello reached the shim (which
    /// moved the spawn to it), and the old socket hears `superseded` only
    /// later: the session reconnects with the resume instead of staying on a
    /// socket that no longer carries the spawn.
    #[tokio::test]
    async fn a_rotation_hello_without_an_answer_reconnects() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = rotation_policy();
            // Another attempt from the first socket would come only after this.
            p.backoff_max = Duration::from_secs(5);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                let id = start_spawn(&mut ws1).await;
                let mut ws2 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws2).await else { panic!("no hello on the rotation's socket") };
                assert_eq!(resume[0].spawn_id, id);
                drop(ws2);
                tokio::time::sleep(Duration::from_millis(300)).await;
                let _ = ws1.send(Message::from(&Frame::error(ErrorCode::Superseded, "a newer connection attached this spawn", Some(id.clone())))).await;
                let mut ws3 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws3).await else { panic!("no hello") };
                assert_eq!(resume[0].spawn_id, id, "the reconnect resumes the spawn");
                put(&mut ws3, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws3, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws3).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert!(seen.notes.iter().any(|n| n.starts_with("lost the connection") && n.contains("rotation")), "{:?}", seen.notes);
        })
        .await;
    }

    /// A rotation does not restart the stability clock: the spawn was carried
    /// without a break, so losing the rotation's socket within `stable_after`
    /// of it — with the session older than its reconnect budget — starts a
    /// fresh reconnect episode: the session redials and finishes.
    #[tokio::test]
    async fn a_loss_soon_after_a_rotation_still_redials() {
        bounded(async {
            let rig = rig(true).await;
            // The rotation comes 1–2 s in (58 s before the expiry of a token the
            // fake stamps in whole seconds), past the budget; the cut 300 ms after
            // it, when the spawn was carried past `stable_after` but the rotation's socket was not.
            let p = RunPolicy { rotate_before: Duration::from_secs(58), stable_after: Duration::from_millis(800), reconnect_budget: Duration::from_millis(900), ..rotation_policy() };
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                let id = start_spawn(&mut ws1).await;
                let mut ws2 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws2).await else { panic!("no hello on the rotation's socket") };
                assert_eq!(resume[0].spawn_id, id);
                put(&mut ws2, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                tokio::time::sleep(Duration::from_millis(300)).await;
                // Cut, no Close.
                drop(ws2);
                let mut ws3 = rig.endpoint.next().await;
                let Frame::Hello { resume, .. } = frame(&mut ws3).await else { panic!("no hello") };
                assert_eq!(resume[0].spawn_id, id, "the redial resumes the spawn");
                put(&mut ws3, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws3, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws3).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
                ws1
            };
            let (result, seen, _ws1) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            let rotated = seen.notes.iter().position(|n| n.starts_with("rotated to a fresh endpoint token"));
            let lost = seen.notes.iter().position(|n| n.starts_with("lost the connection"));
            assert!(rotated.is_some_and(|r| lost.is_some_and(|l| r < l)), "rotated, then lost: {:?}", seen.notes);
            assert_eq!(rig.endpoint.attempts().len(), 3, "the redial was the third socket");
        })
        .await;
    }

    /// The other side of the stability clock: a socket lost within
    /// `stable_after` of taking the spawn starts no fresh reconnect episode,
    /// so the budget runs on from the first dial across every such socket;
    /// once it is spent the session gives up (exit 8) instead of redialing for ever.
    #[tokio::test]
    async fn sockets_lost_within_stable_after_spend_one_reconnect_budget() {
        bounded(async {
            let rig = rig(true).await;
            let p = RunPolicy { stable_after: Duration::from_secs(1), reconnect_budget: Duration::from_millis(500), backoff_max: Duration::from_millis(40), ..policy() };
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            // Each socket is cut (no Close) 20 ms after it took the spawn; the next one resumes it.
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                loop {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    drop(ws);
                    ws = rig.endpoint.next().await;
                    let Frame::Hello { resume, .. } = frame(&mut ws).await else { panic!("no hello") };
                    assert_eq!(resume[0].spawn_id, id, "the redial resumes the spawn");
                    put(&mut ws, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                }
            };
            let started = Instant::now();
            // A session that redials for ever never ends this.
            let session = async { tokio::join!(tokio::time::timeout(Duration::from_secs(5), run_spawn(&env, Start::New(cat_spec()), sio)), consume(cio, None, Duration::ZERO)) };
            let (result, seen) = tokio::select! {
                out = session => out,
                () = shim => unreachable!("the shim serves every socket"),
            };
            let e = result.expect("the session gave up once its reconnect budget was spent").unwrap_err();
            assert!(matches!(&e, BridgeError::ShimUnavailable(m) if m.contains("no lasting /agent connection")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 8);
            // The budget less the last wait (at most 1.25 × backoff_max).
            assert!(started.elapsed() >= Duration::from_millis(450), "it gave up before the budget was spent: {:?}", started.elapsed());
            let sockets = rig.endpoint.attempts().len();
            assert!(sockets >= 3, "the lost sockets were replaced within the budget: {sockets}");
            assert_eq!(seen.notes.iter().filter(|n| n.starts_with("reattached to spawn")).count(), sockets - 1, "{:?}", seen.notes);
        })
        .await;
    }

    /// The rotation's dials follow the reconnect rules: a 429 waits its
    /// Retry-After, is audited and keeps the token; a 403 spends the one
    /// re-mint; the third dial carries the spawn on.
    #[tokio::test]
    async fn rotation_dials_follow_the_429_and_403_rules() {
        bounded(async {
            let rig = rig(true).await;
            let mut p = rotation_policy();
            // Retry-After 2 → 200 ms; the backoff alone stays below that.
            p.backoff_min = Duration::from_millis(100);
            p.backoff_max = Duration::from_millis(400);
            let env = rig.env(p);
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                rig.endpoint.refuse(refusal(429, &[("retry-after", "2")], ""));
                rig.endpoint.refuse(refusal(403, &[("x-aws-proxy-error", "UNAUTHORIZED")], ""));
                let id = start_spawn(&mut ws1).await;
                let mut ws2 = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws2).await, Frame::Hello { .. }));
                let mints = rig.calls(|c| matches!(c, Call::Token { .. }));
                put(&mut ws1, &Frame::error(ErrorCode::Superseded, "a newer connection attached this spawn", Some(id.clone()))).await;
                put(&mut ws2, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws2, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws2).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
                (mints, ws1)
            };
            let (result, _, (mints, _ws1)) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(mints, 3, "the session's token, the rotation's (kept across the 429), the one re-mint after the 403");
            let a = rig.endpoint.attempts();
            assert_eq!(a.iter().map(|a| a.status).collect::<Vec<_>>(), vec![101, 429, 403, 101]);
            assert!(a[2].at - a[1].at >= Duration::from_millis(200), "Retry-After 2 was kept: {:?}", a[2].at - a[1].at);
            let rows = rig.audit("endpoint_429");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["detail"]["retry_after"], "2");
            assert!(rows[0]["detail"]["waited_ms"].as_str().unwrap().parse::<u64>().unwrap() >= 200);
        })
        .await;
    }

    /// A second 401/403 on the rotation's dials stops rotating on that
    /// socket: the spawn carries on where it is.
    #[tokio::test]
    async fn a_rotation_refused_twice_stays_on_its_socket() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(rotation_policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                for _ in 0..2 {
                    rig.endpoint.refuse(refusal(403, &[("x-aws-proxy-error", "UNAUTHORIZED")], ""));
                }
                let id = start_spawn(&mut ws1).await;
                while rig.endpoint.attempts().len() < 3 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                // Many backoffs long: no third dial comes.
                tokio::time::sleep(Duration::from_millis(500)).await;
                put(&mut ws1, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws1).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
            };
            let (result, seen, ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert_eq!(rig.endpoint.attempts().iter().map(|a| a.status).collect::<Vec<_>>(), vec![101, 403, 403]);
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 3, "the session's token, the rotation's, its one re-mint");
            assert!(seen.notes.iter().any(|n| n.contains("staying on socket")), "{:?}", seen.notes);
        })
        .await;
    }

    /// An expired token and a mint that fails (the network still waking
    /// after a sleep): a failed attempt within the reconnect budget, not the
    /// end of the session; past the budget the mint's own error ends it.
    #[tokio::test]
    async fn an_expired_token_whose_mint_fails_is_retried() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            s.token.expires_at_unix = 1;
            let offline = || BridgeError::Endpoint("the network is not up yet".into());
            rig.api.fail_on("token", offline(), false);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                std::future::pending::<()>().await;
            };
            let mut retry = Retry::new(&env.policy);
            let link = tokio::select! {
                link = s.connect(&mut retry) => link,
                () = shim => unreachable!(),
            };
            assert!(link.is_ok(), "{:?}", link.err());
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 3, "the session's token, the failed mint, the retried one");
            assert!(!s.token_left().is_zero());

            let mut env = rig.env(policy());
            env.policy.reconnect_budget = Duration::from_millis(200);
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            s.token.expires_at_unix = 1;
            for _ in 0..100 {
                rig.api.fail_on("token", offline(), false);
            }
            let e = s.connect(&mut Retry::new(&env.policy)).await.err().unwrap();
            assert!(matches!(&e, BridgeError::Endpoint(m) if m.contains("not up yet")), "{e}");
            assert_eq!(CliError::from(e).exit_code(), 7);
        })
        .await;
    }

    /// A re-mint that fails on a tick never ends a live socket, even with
    /// the token expired: it serves on (the next reconnect mints again).
    #[tokio::test]
    async fn a_failed_remint_never_ends_a_live_socket() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            let (mut link, mut ws) = link_to(&rig, &s).await;
            (s.st.phase, s.attached) = (Phase::Running, true);
            s.token.expires_at_unix = 1;
            for _ in 0..100 {
                rig.api.fail_on("token", BridgeError::Endpoint("the network is not up yet".into()), false);
            }
            let id = s.st.id.clone();
            let shim = async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                put(&mut ws, &exit0(&id, 1)).await;
            };
            let (end, ()) = tokio::join!(s.serve(&mut link), shim);
            assert!(matches!(end, Ok(End::Exited(1, _))), "{:?}", end.err());
            assert!(rig.calls(|c| matches!(c, Call::Token { .. })) >= 3, "it kept trying: {:?}", rig.api.calls());
        })
        .await;
    }

    /// Token expiry is by the wall clock (Darwin's `Instant` stops while a
    /// laptop sleeps): a token the wall clock expired — two hours ahead of
    /// `Instant` here — is re-minted before the dial, never presented.
    #[tokio::test]
    async fn a_token_the_wall_clock_expired_is_reminted_before_the_dial() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, _cio) = spawn_channels(8);
            let mut s = session(&env, sio, Start::New(cat_spec())).await;
            assert!(s.token_left() > Duration::from_secs(3000), "a fresh 60-minute token");
            WALL_AHEAD.with(|w| w.set(Duration::from_secs(2 * 3600)));
            let expired = s.token_left().is_zero();
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                assert!(matches!(frame(&mut ws).await, Frame::Hello { .. }));
                put(&mut ws, &hello_ok(vec![], vec![])).await;
                std::future::pending::<()>().await;
            };
            let mut retry = Retry::new(&env.policy);
            let link = tokio::select! {
                link = s.connect(&mut retry) => link,
                () = shim => unreachable!(),
            };
            WALL_AHEAD.with(|w| w.set(Duration::ZERO));
            assert!(expired, "the token is expired by the wall clock");
            assert!(link.is_ok(), "{:?}", link.err());
            assert_eq!(rig.calls(|c| matches!(c, Call::Token { .. })), 2, "the session's token and the re-mint the wall clock asked for");
            let rows = rig.audit("agent_remint");
            assert!(rows.len() == 1 && rows[0]["detail"]["reason"] == "expiring", "{rows:?}");
        })
        .await;
    }

    /// A laptop sleep (the wall clock ran past `dead_after` ahead of
    /// `Instant`) loses the socket at the next tick, though it still looks
    /// open: the session redials with the resume and finishes.
    #[tokio::test]
    async fn a_wall_clock_jump_past_dead_after_loses_the_socket() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let shim = async {
                let mut ws1 = rig.endpoint.next().await;
                let id = start_spawn(&mut ws1).await;
                // dead_after is 5 s; the next tick (every 10 ms) finds 6 s asleep.
                WALL_AHEAD.with(|w| w.set(Duration::from_secs(6)));
                let mut ws2 = tokio::time::timeout(Duration::from_secs(3), rig.endpoint.next()).await.expect("the jump lost the socket: a redial");
                let Frame::Hello { resume, .. } = frame(&mut ws2).await else { panic!("no hello") };
                assert_eq!(resume[0].spawn_id, id, "the redial resumes the spawn");
                put(&mut ws2, &hello_ok(vec![status(&id, 0, 0)], vec![Resumed { spawn_id: id.clone(), status: ResumeStatus::Ok }])).await;
                put(&mut ws2, &exit0(&id, 1)).await;
                assert_eq!(frame(&mut ws2).await, Frame::Ack { spawn_id: id, seq: 1, err_seq: 0 });
                ws1
            };
            let (result, seen, _ws1) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consume(cio, None, Duration::ZERO), shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            assert!(seen.notes.iter().any(|n| n.starts_with("lost the connection") && n.contains("(woke after ") && n.contains(" asleep)")), "{:?}", seen.notes);
            assert_eq!(rig.endpoint.attempts().len(), 2);
        })
        .await;
    }

    /// A consumer that marks no stderr while the shim floods it: the session
    /// hands it at most STDERR_BUFFER_BYTES, drops the rest and says so in
    /// the next chunk's `dropped` and in the exit.
    #[tokio::test]
    async fn stderr_the_consumer_has_not_marked_stays_bounded() {
        bounded(async {
            let rig = rig(true).await;
            let env = rig.env(policy());
            let (sio, cio) = spawn_channels(8);
            let chunk = Chunk { text: Some("e".repeat(crate::wire::frame::CHUNK_MAX)), b64: None };
            let len = crate::wire::frame::CHUNK_MAX as u64;
            let (flood, kept) = (3 * STDERR_BUFFER_BYTES / len / 2, STDERR_BUFFER_BYTES / len);
            let shim = async {
                let mut ws = rig.endpoint.next().await;
                let id = start_spawn(&mut ws).await;
                for seq in 1..=flood {
                    put(&mut ws, &Frame::Stderr { spawn_id: id.clone(), seq, data: chunk.clone(), dropped: 0 }).await;
                }
                // stdout after the flood: the consumer marks once it has it.
                put(&mut ws, &Frame::Stdout { spawn_id: id.clone(), seq: 1, data: Chunk { text: Some("after\n".into()), b64: None } }).await;
                loop {
                    if let Frame::Ack { err_seq, .. } = frame(&mut ws).await {
                        if err_seq == kept {
                            break;
                        }
                    }
                }
                put(&mut ws, &Frame::Stderr { spawn_id: id.clone(), seq: flood + 1, data: Chunk { text: Some("late\n".into()), b64: None }, dropped: 0 }).await;
                put(&mut ws, &exit0(&id, 2)).await;
                loop {
                    if let Frame::Ack { seq: 2, .. } = frame(&mut ws).await {
                        break;
                    }
                }
            };
            let consumer = async {
                let ConsumerIo { input: _input, control: _control, mut events, consumed } = cio;
                let (mut got, mut exit) = (Vec::new(), None);
                while let Some(ev) = events.recv().await {
                    match ev {
                        SpawnEvent::Stderr { seq, bytes, dropped } => got.push((seq, bytes.len() as u64, dropped)),
                        SpawnEvent::Stdout { seq, .. } => {
                            consumed.stderr_done(got.last().map_or(0, |g| g.0));
                            consumed.stdout_done(seq);
                        }
                        SpawnEvent::Exit(e) => {
                            exit = Some(e);
                            consumed.stderr_done(got.last().map_or(0, |g| g.0));
                        }
                        _ => {}
                    }
                }
                (got, exit)
            };
            let (result, (got, exit), ()) = tokio::join!(run_spawn(&env, Start::New(cat_spec()), sio), consumer, shim);
            assert_eq!(result.unwrap().exit.status(), 0);
            let lost = (flood - kept) * len;
            let seqs: Vec<u64> = got.iter().map(|g| g.0).collect();
            assert_eq!(seqs, (1..=kept).chain([flood + 1]).collect::<Vec<u64>>(), "the flood past the bound was dropped");
            assert_eq!(got.iter().take(kept as usize).map(|g| g.1).sum::<u64>(), STDERR_BUFFER_BYTES);
            assert_eq!(got.last().map(|g| g.2), Some(lost), "the next chunk counts the drop");
            assert_eq!(exit.map(|e| e.stderr_dropped), Some(lost));
        })
        .await;
    }

    #[test]
    fn stdin_never_puts_more_than_the_window_in_flight() {
        let mut st = State::new(Start::New(cat_spec()));
        let big = vec![b'a'; crate::wire::frame::CHUNK_MAX];
        let chunks = (STDIN_WINDOW_BYTES / big.len() as u64) + 3;
        for _ in 0..chunks {
            st.take(SpawnInput::Stdin(big.clone()));
        }
        assert!(!st.wants_input(), "input stops once a window is pending");
        let mut sent = 0;
        while let Some((seq, _, len)) = st.next_stdin() {
            st.sent_in = seq;
            st.inflight += len;
            sent += 1;
        }
        assert_eq!(st.inflight, STDIN_WINDOW_BYTES, "exactly the window in flight");
        assert_eq!(sent, STDIN_WINDOW_BYTES / big.len() as u64);
        st.stdin_acked(4);
        assert!(st.next_stdin().is_some(), "an ack frees room");
        assert!(st.wants_input(), "less than a window pending again");
        // A reattach that holds stdin up to 6: 7.. go again, 5 and 6 still count until acked.
        st.reattached(Some(&status(&st.id.clone(), 0, 6)));
        assert_eq!((st.sent_in, st.inflight), (6, 2 * big.len() as u64));
        assert_eq!(st.next_stdin().map(|(seq, _, _)| seq), Some(7));
    }

    #[test]
    fn stdin_eof_flushes_a_held_utf8_tail_and_later_stdin_is_dropped() {
        let mut st = State::new(Start::New(cat_spec()));
        st.take(SpawnInput::Stdin(vec![b'o', b'k', 0xe2, 0x82]));
        st.take(SpawnInput::StdinEof);
        st.take(SpawnInput::Stdin(b"late".to_vec()));
        let chunks: Vec<(u64, Chunk)> = st.pending.iter().map(|(seq, c, _)| (*seq, c.clone())).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], (1, Chunk { text: Some("ok".into()), b64: None }));
        assert_eq!(chunks[1].1.b64.as_deref(), Some("4oI="), "the unfinished tail goes at EOF, as b64");
        assert_eq!(st.eof, Some(2));
    }

    #[test]
    fn resume_points_follow_what_was_delivered() {
        let mut st = State::new(Start::New(cat_spec()));
        assert!(st.resume().is_empty(), "nothing to resume before the first spawn");
        st.phase = Phase::SpawnSent;
        assert_eq!(st.resume()[0].from_seq, Some(1));
        st.out = 7;
        st.err = 2;
        assert_eq!((st.resume()[0].from_seq, st.resume()[0].err_from_seq), (Some(8), Some(3)));
        let attach = State::new(Start::Attach { spawn_id: SpawnId::new_v7(), from_seq: None, err_from_seq: None });
        assert_eq!((attach.resume()[0].from_seq, attach.resume()[0].err_from_seq), (None, None), "the oldest retained");
    }

    #[test]
    fn jitter_stays_within_a_quarter() {
        for _ in 0..200 {
            let d = jittered(Duration::from_millis(1000));
            assert!(d >= Duration::from_millis(750) && d < Duration::from_millis(1250), "{d:?}");
        }
        let p = policy();
        let mut r = Retry::new(&p);
        let steps: Vec<Duration> = (0..6).map(|_| {
            r.next(&p);
            r.step
        }).collect();
        assert_eq!(steps.last(), Some(&p.backoff_max), "the step doubles up to backoff_max: {steps:?}");
    }
}
