//! Calls (WM-R18 to WM-R30, WM-R34): admission and the queue, each call's task, and its output as chunks.
//!
//! The frame loop owns the in-flight map and the queue (no lock). Each running call is a tokio task with a
//! cancel token that is a child of the tunnel's; it sends its own chunks through the bounded outbound queue
//! inside its deadline and cancel, and exactly one final chunk (LD-WM10), then tells the loop it is done.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use ai_env_relay_proto::v1::{worker_frame, Chunk, Invoke, WorkerFrame};
use ai_env_source::{wire, Body, CallContext, CallRequest, Caller, Cancel, Code, Limits, Output, Redactor, SourceError, TextStream};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_stream::Stream;

use crate::tunnel::OUTBOUND_FRAMES;
use crate::worker::{Inner, SourceEntry};

/// The deadline a call gets is the relay's less this, so its final chunk reaches the relay first (WM-R19).
const DEADLINE_MARGIN: Duration = Duration::from_millis(100);
/// The longest request id (WM-R18).
const REQUEST_ID_MAX: usize = 64;

/// 1 to 64 printable ASCII bytes (WM-R18).
pub(crate) fn valid_request_id(id: &str) -> bool {
    (1..=REQUEST_ID_MAX).contains(&id.len()) && id.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// A refusal: one final chunk at once, `seq` 0, no data (WM-R18).
pub(crate) fn refusal(request_id: &str, code: Code, message: &str) -> WorkerFrame {
    chunk_frame(Chunk {
        request_id: request_id.to_string(),
        seq: 0,
        data: Vec::new(),
        content_type: String::new(),
        r#final: true,
        error: Some(crate::map::error(code, cut(message, ai_env_source::MESSAGE_MAX))),
        truncated: false,
    })
}

fn chunk_frame(c: Chunk) -> WorkerFrame {
    WorkerFrame { msg: Some(worker_frame::Msg::Chunk(c)) }
}

/// At most `max` bytes of `text`, cut at a character boundary.
fn cut(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// How many of `bytes` (UTF-8 text) fit in `max`: at most `max`, never ending inside a character.
fn utf8_floor(bytes: &[u8], max: usize) -> usize {
    let mut n = max.min(bytes.len());
    while n > 0 && bytes.get(n).is_some_and(|b| (b & 0xc0) == 0x80) {
        n -= 1;
    }
    n
}

/// `f` with a panic caught: `Err(())` once it panicked. The payload is dropped unread: a panic's text may
/// hold data (WM-R24).
fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    std::panic::catch_unwind(AssertUnwindSafe(f)).map_err(drop)
}

/// A call accepted and not started yet.
struct Pending {
    request_id: String,
    entry: Arc<SourceEntry>,
    op: String,
    params: serde_json::Value,
    caller: Caller,
    limits: Limits,
    deadline: Instant,
    /// The effective deadline, for the message of its passing.
    deadline_ms: u128,
    received: Instant,
}

/// A running call: its token and its task.
struct Running {
    cancel: Cancel,
    task: JoinHandle<()>,
}

/// One tunnel's calls.
pub(crate) struct Calls {
    inner: Arc<Inner>,
    tx: mpsc::Sender<WorkerFrame>,
    /// Every call's token is a child of this one (WM-R19).
    tunnel: Cancel,
    in_flight: HashMap<String, Running>,
    queue: VecDeque<Pending>,
    done_tx: mpsc::UnboundedSender<String>,
    done_rx: mpsc::UnboundedReceiver<String>,
    /// Frames that found the outbound queue full and wait for room (a pong, a refusal): at most `side_max`.
    side: JoinSet<()>,
    /// One refusal for each queued call, and 32 more (WM-R34: the frames waiting are bounded too).
    side_max: usize,
    /// A frame found no room there either: the relay reads nothing back, and the frame loop ends the tunnel.
    overflowed: bool,
}

impl Calls {
    pub(crate) fn new(inner: Arc<Inner>, tx: mpsc::Sender<WorkerFrame>) -> Calls {
        let (done_tx, done_rx) = mpsc::unbounded_channel();
        let side_max = inner.max_queued + OUTBOUND_FRAMES;
        Calls {
            inner,
            tx,
            tunnel: Cancel::new(),
            in_flight: HashMap::new(),
            queue: VecDeque::new(),
            done_tx,
            done_rx,
            side: JoinSet::new(),
            side_max,
            overflowed: false,
        }
    }

    /// The next call that sent its final chunk.
    pub(crate) async fn next_done(&mut self) -> Option<String> {
        self.done_rx.recv().await
    }

    /// One frame now, ahead of nothing the queue already holds: a full queue hands it to a task that waits
    /// for room, so the frame loop never waits. When `side_max` frames already wait, the frame is dropped
    /// and `overflowed` says so: a relay that sends while it reads nothing back never grows the worker's
    /// memory (WM-R34).
    pub(crate) fn send_now(&mut self, frame: WorkerFrame) {
        while self.side.try_join_next().is_some() {}
        match self.tx.try_send(frame) {
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(_)) if self.side.len() >= self.side_max => self.overflowed = true,
            Err(TrySendError::Full(frame)) => {
                let tx = self.tx.clone();
                self.side.spawn(async move {
                    let _ = tx.send(frame).await;
                });
            }
        }
    }

    /// Whether a frame found no room in the outbound queue nor among the frames waiting for it: the relay
    /// reads nothing back, so the tunnel ends (transient).
    pub(crate) fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// A refusal of `inv` (WM-R18), logged as its call's one line (WM-R30).
    fn refuse(&mut self, inv: &Invoke, code: Code, message: &str) {
        let caller = crate::map::caller_of(inv.caller.as_ref());
        tracing::info!(request_id = %inv.request_id, source = ?inv.source, op = ?inv.op, caller_id = %caller.caller_id, session_id = %caller.session_id,
            outcome = code.name(), bytes = 0u64, chunks = 1u64, ms = 0u64, "relay call");
        self.send_now(refusal(&inv.request_id, code, message));
    }

    /// WM-R18 to WM-R20: check, then start, queue or refuse busy. The source is never called for a refused
    /// `Invoke`.
    pub(crate) fn invoke(&mut self, inv: Invoke, received: Instant) {
        if !valid_request_id(&inv.request_id) {
            tracing::warn!("dropped an invoke without a usable request id ({} bytes)", inv.request_id.len());
            return;
        }
        if self.in_flight.contains_key(&inv.request_id) || self.queue.iter().any(|p| p.request_id == inv.request_id) {
            tracing::warn!(request_id = %inv.request_id, "dropped an invoke whose request id is already in flight or queued");
            return;
        }
        let Some(&index) = self.inner.by_name.get(&inv.source) else {
            let message = format!("no source {} on this worker", inv.source);
            return self.refuse(&inv, Code::NotFound, &message);
        };
        let entry = self.inner.sources[index].clone();
        let Some(op) = entry.descriptor.op_named(&inv.op) else {
            let message = format!("source {} has no op {}", inv.source, inv.op);
            return self.refuse(&inv, Code::NotFound, &message);
        };
        let params = if inv.params_json.len() > wire::PARAMS_MAX {
            Err(format!("params_json of {} bytes is over {}", inv.params_json.len(), wire::PARAMS_MAX))
        } else if inv.params_json.is_empty() {
            Ok(serde_json::Value::Object(serde_json::Map::new()))
        } else {
            match serde_json::from_slice::<serde_json::Value>(&inv.params_json) {
                Ok(object @ serde_json::Value::Object(_)) => Ok(object),
                Ok(_) => Err("params_json is not a JSON object".to_string()),
                Err(_) => Err("params_json is not JSON".to_string()),
            }
        };
        let params = match params {
            Ok(p) => p,
            Err(message) => return self.refuse(&inv, Code::InvalidArgument, &message),
        };
        let limits = op.effective_limits(crate::map::limits_of(inv.limits.as_ref()));
        let effective = op.effective_deadline(inv.deadline_ms);
        let deadline = (received + effective).checked_sub(DEADLINE_MARGIN).map_or(received, |d| d.max(received));
        let pending = Pending {
            request_id: inv.request_id.clone(),
            entry: entry.clone(),
            op: inv.op.clone(),
            params,
            caller: crate::map::caller_of(inv.caller.as_ref()),
            limits,
            deadline,
            deadline_ms: effective.as_millis(),
            received,
        };
        if self.in_flight.len() < self.inner.max_in_flight {
            self.start(pending);
        } else if self.queue.len() < self.inner.max_queued {
            self.queue.push_back(pending);
        } else {
            let message = format!("worker busy: {} calls in flight, {} queued", self.in_flight.len(), self.queue.len());
            self.refuse(&inv, Code::ResourceExhausted, &message);
        }
    }

    fn start(&mut self, p: Pending) {
        let cancel = self.tunnel.child();
        let id = p.request_id.clone();
        let task = tokio::spawn(run(p, cancel.clone(), self.tx.clone(), Done { id: id.clone(), tx: self.done_tx.clone() }));
        self.in_flight.insert(id, Running { cancel, task });
    }

    /// WM-R22: a running call's token trips (its task answers `CANCELLED` and drops the source's future); a
    /// queued call leaves the queue with its final chunk; an unknown id changes nothing.
    pub(crate) fn cancel(&mut self, request_id: &str) {
        if let Some(running) = self.in_flight.get(request_id) {
            running.cancel.cancel();
        } else if let Some(at) = self.queue.iter().position(|p| p.request_id == request_id) {
            if let Some(p) = self.queue.remove(at) {
                self.never_started(&p, Code::Cancelled, "cancelled before it started");
            }
        }
    }

    /// A call sent its final chunk: its slot goes to the next queued call, in order (WM-R20); a queued call
    /// whose deadline passed meanwhile never starts.
    pub(crate) fn finished(&mut self, request_id: &str) {
        self.in_flight.remove(request_id);
        self.expire_queued(Instant::now());
        while self.in_flight.len() < self.inner.max_in_flight {
            match self.queue.pop_front() {
                Some(p) => self.start(p),
                None => break,
            }
        }
    }

    /// The earliest deadline in the queue.
    pub(crate) fn next_queued_deadline(&self) -> Option<Instant> {
        self.queue.iter().map(|p| p.deadline).min()
    }

    /// Queued calls whose deadline passed leave the queue with `DEADLINE_EXCEEDED` and never start (WM-R20).
    pub(crate) fn expire_queued(&mut self, now: Instant) {
        let (gone, kept): (VecDeque<Pending>, VecDeque<Pending>) = std::mem::take(&mut self.queue).into_iter().partition(|p| p.deadline <= now);
        self.queue = kept;
        for p in gone {
            let message = format!("deadline of {} ms passed", p.deadline_ms);
            self.never_started(&p, Code::DeadlineExceeded, &message);
        }
    }

    fn never_started(&mut self, p: &Pending, code: Code, message: &str) {
        tracing::info!(request_id = %p.request_id, source = %p.entry.descriptor.name, op = %p.op, caller_id = %p.caller.caller_id,
            session_id = %p.caller.session_id, outcome = code.name(), bytes = 0u64, chunks = 1u64, ms = p.received.elapsed().as_millis() as u64, "relay call");
        self.send_now(refusal(&p.request_id, code, message));
    }

    /// WM-R23: the tunnel ended. Every call in flight and queued is cancelled before the next dial (tasks
    /// aborted, so their futures are dropped; tokens tripped, so a source's own tasks stop); nothing more is
    /// sent for them.
    pub(crate) async fn end(mut self) {
        for running in self.in_flight.values() {
            running.task.abort();
        }
        self.tunnel.cancel();
        for (_, running) in self.in_flight.drain() {
            let _ = running.task.await;
        }
        self.queue.clear();
        self.side.shutdown().await;
    }
}

/// Tells the frame loop a call is over when dropped: after its final chunk, or when its task is aborted.
struct Done {
    id: String,
    tx: mpsc::UnboundedSender<String>,
}

impl Drop for Done {
    fn drop(&mut self) {
        let _ = self.tx.send(std::mem::take(&mut self.id));
    }
}

/// How a call's output stopped short.
enum Stop {
    Cancelled,
    Deadline,
    /// The tunnel's stream is gone: nothing more can be sent.
    Closed,
}

/// One call's chunks: `seq` from 0 without a gap, the output's content type on each, one final chunk
/// (WM-R25).
struct Out {
    request_id: String,
    content_type: &'static str,
    seq: u64,
    bytes: u64,
    tx: mpsc::Sender<WorkerFrame>,
    cancel: Cancel,
    deadline: Instant,
    deadline_ms: u128,
}

impl Out {
    fn chunk(&self, data: Vec<u8>, last: bool, error: Option<(Code, String)>, truncated: bool) -> WorkerFrame {
        chunk_frame(Chunk {
            request_id: self.request_id.clone(),
            seq: self.seq,
            data,
            content_type: self.content_type.to_string(),
            r#final: last,
            error: error.map(|(code, message)| crate::map::error(code, cut(&message, ai_env_source::MESSAGE_MAX))),
            truncated: last && truncated,
        })
    }

    /// A data chunk, waiting for room inside the call's cancel and deadline (WM-R34).
    async fn data(&mut self, data: Vec<u8>) -> Result<(), Stop> {
        let len = data.len() as u64;
        let frame = self.chunk(data, false, None, false);
        let sent = tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(Stop::Cancelled),
            () = tokio::time::sleep_until(self.deadline) => Err(Stop::Deadline),
            r = self.tx.send(frame) => r.map_err(|_| Stop::Closed),
        };
        if sent.is_ok() {
            self.seq += 1;
            self.bytes += len;
        }
        sent
    }

    /// A data chunk after the call stopped (pending data goes first, A-M10): it waits for room as long as
    /// the tunnel lives.
    async fn data_unguarded(&mut self, data: Vec<u8>) -> Result<(), Stop> {
        let len = data.len() as u64;
        self.tx.send(self.chunk(data, false, None, false)).await.map_err(|_| Stop::Closed)?;
        self.seq += 1;
        self.bytes += len;
        Ok(())
    }

    /// What is pending, as data chunks of at most `CHUNK_MAX`, while a slot is left after each for the final
    /// chunk (R-39 ends a call whose `max_chunks`-th chunk is not final): only whole chunks while the stream
    /// goes on (`whole_only`), every piece at its end. `guarded` waits for room inside the call's cancel and
    /// deadline (WM-R34); otherwise as long as the tunnel lives (the call already stopped, and its pending
    /// data goes first, A-M10). What the slots cannot carry stays in `pending`.
    async fn drain(&mut self, pending: &mut Vec<u8>, max_chunks: u64, whole_only: bool, guarded: bool) -> Result<(), Stop> {
        while self.seq + 1 < max_chunks && !pending.is_empty() && (pending.len() >= wire::CHUNK_MAX || !whole_only) {
            let n = pending.len().min(wire::CHUNK_MAX);
            let piece = pending[..n].to_vec();
            if guarded {
                self.data(piece).await?;
            } else {
                self.data_unguarded(piece).await?;
            }
            pending.drain(..n);
        }
        Ok(())
    }

    /// The final chunk: it always goes out while the tunnel lives (LD-WM10). Its outcome word for the log.
    async fn last(&mut self, data: Vec<u8>, error: Option<(Code, String)>, truncated: bool) -> &'static str {
        let outcome = match (&error, truncated) {
            (Some((code, _)), _) => code.name(),
            (None, true) => "truncated",
            (None, false) => "ok",
        };
        let len = data.len() as u64;
        if self.tx.send(self.chunk(data, true, error, truncated)).await.is_ok() {
            self.seq += 1;
            self.bytes += len;
        }
        outcome
    }

    /// `INTERNAL` `the source failed`, with no panic text (WM-R24).
    async fn failed(&mut self) -> &'static str {
        self.last(Vec::new(), Some((Code::Internal, "the source failed".into())), false).await
    }

    /// The final chunk of a call that stopped short: `CANCELLED`, or `DEADLINE_EXCEEDED` with its token
    /// tripped (WM-R21, WM-R22); `truncated` when output the call made stayed unsent (WM-R30).
    async fn stopped(&mut self, stop: Stop, truncated: bool) -> &'static str {
        match stop {
            Stop::Cancelled => self.last(Vec::new(), Some((Code::Cancelled, "the call was cancelled".into())), truncated).await,
            Stop::Deadline => {
                self.cancel.cancel();
                let message = format!("deadline of {} ms passed", self.deadline_ms);
                self.last(Vec::new(), Some((Code::DeadlineExceeded, message)), truncated).await
            }
            Stop::Closed => "gone",
        }
    }

    /// A JSON or text output: `ceil(n / CHUNK_MAX)` chunks, one empty for `n = 0`, the last final (WM-R25).
    async fn whole(&mut self, bytes: Vec<u8>, truncated: bool) -> &'static str {
        let mut pieces: Vec<Vec<u8>> = bytes.chunks(wire::CHUNK_MAX).map(<[u8]>::to_vec).collect();
        let last = pieces.pop().unwrap_or_default();
        for piece in pieces {
            if let Err(stop) = self.data(piece).await {
                return self.stopped(stop, false).await;
            }
        }
        self.last(last, None, truncated).await
    }

    /// Before an error's final chunk (an `Err` item, a cancel, a deadline): what is pending goes first, in
    /// chunks within the slots the final chunk leaves (WM-R29, A-M10). Whether bytes stayed unsent: the
    /// worker cut the output, and the final chunk says `truncated` (WM-R30).
    async fn flush(&mut self, mut pending: Vec<u8>, max_chunks: u64) -> bool {
        let _ = self.drain(&mut pending, max_chunks, false, false).await;
        !pending.is_empty()
    }

    /// A stream stopped by a cancel or its deadline: a deadline trips the token, what is pending goes
    /// first, then the final chunk (WM-R21, WM-R22, WM-R29).
    async fn stop_stream(&mut self, stop: Stop, pending: Vec<u8>, max_chunks: u64) -> &'static str {
        if matches!(stop, Stop::Deadline) {
            self.cancel.cancel();
        }
        let cut = self.flush(pending, max_chunks).await;
        self.stopped(stop, cut).await
    }

    /// A stream's end, at its cap or its last item: what is pending, as data chunks within the slots, then
    /// the final chunk, which carries the last of it when it takes the call's last slot (WM-R29).
    async fn close(&mut self, mut pending: Vec<u8>, truncated: bool, max_chunks: u64) -> &'static str {
        if let Err(stop) = self.drain(&mut pending, max_chunks, false, true).await {
            return self.stop_stream(stop, pending, max_chunks).await;
        }
        // Every chunk before the last slot is a whole one, so the byte cap (`byte_cap`) leaves at most one
        // chunk for it; never more than `CHUNK_MAX`, whatever the cap.
        let keep = utf8_floor(&pending, wire::CHUNK_MAX);
        let truncated = truncated || keep < pending.len();
        pending.truncate(keep);
        self.last(pending, None, truncated).await
    }
}

/// The byte cap of a call: `max_bytes`, and never more than `max_chunks` full chunks.
fn byte_cap(l: Limits) -> usize {
    let chunks = u64::from(l.max_chunks).saturating_mul(wire::CHUNK_MAX as u64);
    usize::try_from(l.max_bytes.min(chunks)).unwrap_or(usize::MAX)
}

/// Every string of a JSON value, keys and values, through the redactor; the value stays JSON (WM-R26, A-M11).
fn redact_json(value: serde_json::Value, r: &Redactor) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(s) => Value::String(r.redact(&s).into_owned()),
        Value::Array(items) => Value::Array(items.into_iter().map(|v| redact_json(v, r)).collect()),
        Value::Object(map) => Value::Object(map.into_iter().map(|(k, v)| (r.redact(&k).into_owned(), redact_json(v, r))).collect()),
        other => other,
    }
}

/// The next poll of a source's future, a panic caught (WM-R24).
fn caught<F: Future + Unpin>(fut: &mut F) -> impl Future<Output = Result<F::Output, ()>> + '_ {
    std::future::poll_fn(move |cx| match guarded(|| Pin::new(&mut *fut).poll(cx)) {
        Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
        Ok(Poll::Pending) => Poll::Pending,
        Err(()) => Poll::Ready(Err(())),
    })
}

/// The next item of a source's stream, a panic caught (WM-R24).
fn next_item(stream: &mut TextStream) -> impl Future<Output = Result<Option<Result<String, SourceError>>, ()>> + '_ {
    std::future::poll_fn(move |cx| match guarded(|| Pin::new(&mut *stream).poll_next(cx)) {
        Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
        Ok(Poll::Pending) => Poll::Pending,
        Err(()) => Poll::Ready(Err(())),
    })
}

/// How the source's future ended, or why it was dropped.
enum Answer {
    Output(Output),
    Failed(SourceError),
    Panicked,
    Stopped(Stop),
}

/// One call, from the source's `call` to its final chunk (WM-R19 to WM-R30).
async fn run(p: Pending, cancel: Cancel, tx: mpsc::Sender<WorkerFrame>, done: Done) {
    let entry = p.entry.clone();
    let ctx = CallContext::new(p.request_id.clone(), entry.descriptor.name.clone(), p.caller.clone(), p.limits, p.deadline, cancel.clone());
    let mut out = Out { request_id: p.request_id.clone(), content_type: "", seq: 0, bytes: 0, tx, cancel: cancel.clone(), deadline: p.deadline, deadline_ms: p.deadline_ms };
    // WM-R24: `call` itself may panic before it returns its future (a hand-written impl).
    let answer = match guarded(|| entry.source.call(CallRequest::new(p.op.clone(), p.params), ctx)) {
        Err(()) => Answer::Panicked,
        Ok(mut fut) => {
            let answer = tokio::select! {
                biased;
                () = cancel.cancelled() => Answer::Stopped(Stop::Cancelled),
                () = tokio::time::sleep_until(p.deadline) => Answer::Stopped(Stop::Deadline),
                r = caught(&mut fut) => match r {
                    Ok(Ok(output)) => Answer::Output(output),
                    Ok(Err(e)) => Answer::Failed(e),
                    Err(()) => Answer::Panicked,
                },
            };
            // WM-R21, WM-R22: a cancelled or late call's future is dropped here, before its final chunk.
            drop(fut);
            answer
        }
    };
    let outcome = match answer {
        Answer::Stopped(stop) => out.stopped(stop, false).await,
        Answer::Panicked => out.failed().await,
        Answer::Failed(e) => {
            let error = match guarded(|| e.wire_message(&entry.redactor)) {
                Ok(message) => (e.code(), message),
                Err(()) => (Code::Internal, "the source failed".into()),
            };
            out.last(Vec::new(), Some(error), false).await
        }
        Answer::Output(output) => emit(&mut out, output, &entry.redactor, p.limits).await,
    };
    tracing::info!(request_id = %p.request_id, source = %entry.descriptor.name, op = %p.op, caller_id = %p.caller.caller_id, session_id = %p.caller.session_id,
        outcome, bytes = out.bytes, chunks = out.seq, ms = p.received.elapsed().as_millis() as u64, "relay call");
    drop(done);
}

/// An output, redacted and capped, as chunks (WM-R25 to WM-R29).
async fn emit(out: &mut Out, output: Output, redactor: &Redactor, limits: Limits) -> &'static str {
    out.content_type = output.content_type().as_str();
    let (body, source_cut) = output.into_parts();
    let cap = byte_cap(limits);
    match body {
        Body::Json(value) => {
            // WM-R27, LD-WM9: a JSON over its cap is refused, never cut.
            let Ok(Ok(text)) = guarded(|| serde_json::to_vec(&redact_json(value, redactor))) else {
                return out.failed().await;
            };
            if text.len() > cap {
                let message = format!("result of {} bytes is over max_bytes {cap}: page it (cursor) or ask for fewer rows", text.len());
                return out.last(Vec::new(), Some((Code::ResourceExhausted, message)), false).await;
            }
            out.whole(text, source_cut).await
        }
        Body::Text(text) => {
            // WM-R28: cut at the last character boundary under the cap, and flagged.
            let Ok(redacted) = guarded(|| redactor.redact(&text).into_owned()) else {
                return out.failed().await;
            };
            let kept = cut(&redacted, cap);
            let truncated = source_cut || kept.len() < redacted.len();
            out.whole(kept.into_bytes(), truncated).await
        }
        Body::Stream(stream) => stream_out(out, stream, redactor, limits, source_cut).await,
        _ => out.last(Vec::new(), Some((Code::Internal, "an output this worker cannot send".into())), false).await,
    }
}

/// How a stream stopped.
enum StreamEnd {
    /// Its last item, or a cap (`truncated`).
    Closed { truncated: bool },
    Failed(Code, String),
    Panicked,
    Stopped(Stop),
}

/// WM-R29: items redacted through one `StreamRedactor`, each and a `\n` appended to what is pending, one row
/// each; a full chunk goes when the buffer reaches `CHUNK_MAX`, nothing because no item is ready (A-M10); at
/// a cap the part that fits goes and the stream is dropped. However large an item, no chunk carries more
/// than `CHUNK_MAX` (P-R18): the end sends what is pending in chunks (`Out::drain`).
async fn stream_out(out: &mut Out, mut stream: TextStream, redactor: &Redactor, limits: Limits, source_cut: bool) -> &'static str {
    let cap = byte_cap(limits);
    let max_chunks = u64::from(limits.max_chunks);
    let mut pieces = redactor.stream();
    let mut pending: Vec<u8> = Vec::new();
    let (mut total, mut rows) = (0usize, 0u32);
    let cancel = out.cancel.clone();
    let deadline = out.deadline;
    let end = loop {
        let item = tokio::select! {
            biased;
            () = cancel.cancelled() => break StreamEnd::Stopped(Stop::Cancelled),
            () = tokio::time::sleep_until(deadline) => break StreamEnd::Stopped(Stop::Deadline),
            item = next_item(&mut stream) => item,
        };
        let text = match item {
            Err(()) => break StreamEnd::Panicked,
            Ok(None) => break StreamEnd::Closed { truncated: false },
            Ok(Some(Err(e))) => match guarded(|| e.wire_message(redactor)) {
                Ok(message) => break StreamEnd::Failed(e.code(), message),
                Err(()) => break StreamEnd::Panicked,
            },
            Ok(Some(Ok(text))) => text,
        };
        if rows >= limits.max_rows {
            break StreamEnd::Closed { truncated: true };
        }
        rows += 1;
        let Ok(redacted) = guarded(|| pieces.piece(&text).into_owned()) else {
            break StreamEnd::Panicked;
        };
        let mut line = redacted.into_bytes();
        line.push(b'\n');
        if total + line.len() > cap {
            // The part that fits, cut at a character boundary; `close` sends it in chunks.
            let fits = utf8_floor(&line, cap - total);
            pending.extend_from_slice(&line[..fits]);
            break StreamEnd::Closed { truncated: true };
        }
        total += line.len();
        pending.extend_from_slice(&line);
        // Whole chunks go only while a slot is left for the final one after them (the relay ends a call whose
        // `max_chunks`-th chunk is not final, R-39).
        if let Err(stop) = out.drain(&mut pending, max_chunks, true, true).await {
            break StreamEnd::Stopped(stop);
        }
    };
    // The stream is dropped before the last chunks go: that stops the source's producer.
    drop(stream);
    match end {
        StreamEnd::Closed { truncated } => out.close(pending, truncated || source_cut, max_chunks).await,
        StreamEnd::Failed(code, message) => {
            let cut = out.flush(pending, max_chunks).await;
            out.last(Vec::new(), Some((code, message)), cut).await
        }
        StreamEnd::Panicked => out.failed().await,
        StreamEnd::Stopped(stop) => out.stop_stream(stop, pending, max_chunks).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use ai_env_relay_proto::v1::Pong;

    use crate::endpoint::RelayEndpoint;
    use crate::keys::SigningKey;
    use crate::signer::FileSigner;
    use crate::worker::Tuning;

    /// A tunnel's calls over `tx`: no source, `max_queued` 0.
    fn calls_over(tx: mpsc::Sender<WorkerFrame>) -> Calls {
        let inner = Inner {
            worker_id: "worker-a".into(),
            endpoint: RelayEndpoint::new("relay.example.com").expect("an address"),
            signer: Arc::new(FileSigner::from_key(SigningKey::from_seed(&[1u8; 32]).expect("seed"))),
            sources: Vec::new(),
            by_name: HashMap::new(),
            catalog: WorkerFrame { msg: None },
            max_in_flight: 1,
            max_queued: 0,
            tuning: Tuning::default(),
            wall: Arc::new(SystemTime::now),
        };
        Calls::new(Arc::new(inner), tx)
    }

    fn pong(seq: u64) -> WorkerFrame {
        WorkerFrame { msg: Some(worker_frame::Msg::Pong(Pong { seq })) }
    }

    /// WM-R34: with the outbound queue full, at most `max_queued + 32` frames wait for room; the next one is
    /// dropped and the tunnel is told to end. The ones that waited still go once the relay reads.
    #[tokio::test]
    async fn frames_waiting_for_room_are_bounded() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut calls = calls_over(tx);
        calls.send_now(pong(0));
        for seq in 1..=OUTBOUND_FRAMES as u64 {
            calls.send_now(pong(seq));
            assert!(!calls.overflowed(), "{seq} frames wait");
        }
        calls.send_now(pong(99));
        assert!(calls.overflowed(), "one more finds no room");
        let mut seqs = Vec::new();
        while let Ok(Some(frame)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            if let Some(worker_frame::Msg::Pong(p)) = frame.msg {
                seqs.push(p.seq);
            }
        }
        seqs.sort_unstable();
        assert_eq!(seqs, (0..=OUTBOUND_FRAMES as u64).collect::<Vec<_>>(), "the dropped frame never goes");
    }
}
