//! The per-tunnel call table, chunk routing and `CallStream` (R-37 to R-46, R-106, R-109, R-111, R-112). Synchronous
//! only (R-75, a `make lint` guard): nothing in this file awaits. The tunnel's reader hands each chunk to
//! `CallTable::on_chunk`, which decides everything under the entry's lock and returns what to deliver; the reader then
//! hands it to the caller's buffer with `CallState::hand`, which never waits (R-111).
//!
//! A call's outcome is set once (`CallState::conclude`), by whoever ends it first: its final chunk, a breach, the
//! deadline, an eviction, the caller going, a fail-all or a shutdown; that same step writes its one call line (R-61)
//! and releases what the call held for its session and its connection (R-106). The relay's own permit stays with the
//! call's stream until hyper drops the stream: hyper takes a body's frame before it waits for send capacity, so a
//! last item yielded may still sit unsent in hyper's hands, and only the drop says it went.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use ai_env_relay_proto::v1::{CallChunk, Chunk, Error, RelayFrame};
use ai_env_source::wire::cancel;
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::reqlog::CallLog;
use crate::tls::{Pending as PendingRequest, StreamMark};

/// The most bytes of one chunk's data.
pub const CHUNK_MAX: usize = 65_536;
/// The most bytes of an error message.
pub const MESSAGE_MAX: usize = 1024;
/// The longest content type.
pub const CONTENT_TYPE_MAX: usize = 128;
/// R-109: a tunnel's table remembers the request ids of its last this many ended calls, whose late chunks are no fault.
pub const RECENT_CALLS: usize = 64;

/// How a call ended (R-64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Answered.
    Ok,
    /// Answered, cut.
    Truncated,
    /// The source's error, with its code.
    SourceError(i32),
    /// Cancelled.
    Cancelled,
    /// Its deadline passed.
    Deadline,
    /// Its worker went.
    WorkerGone,
    /// Evicted.
    Evicted,
    /// The worker broke the chunk rules.
    Violation,
    /// The relay stopped.
    Shutdown,
}

impl Outcome {
    /// R-64's word.
    pub fn word(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Truncated => "truncated",
            Outcome::SourceError(_) => "source_error",
            Outcome::Cancelled => "cancelled",
            Outcome::Deadline => "deadline",
            Outcome::WorkerGone => "worker_gone",
            Outcome::Evicted => "evicted",
            Outcome::Violation => "violation",
            Outcome::Shutdown => "shutdown",
        }
    }

    /// R-64's code.
    pub fn code(self) -> i32 {
        match self {
            Outcome::Ok | Outcome::Truncated => 0,
            Outcome::SourceError(code) => code,
            Outcome::Cancelled => 1,
            Outcome::Deadline => 4,
            Outcome::WorkerGone | Outcome::Shutdown => 14,
            Outcome::Evicted => 10,
            Outcome::Violation => 13,
        }
    }

    /// R-42's synthetic final's message.
    fn message(self) -> &'static str {
        match self {
            Outcome::Deadline => "the call's deadline passed",
            Outcome::WorkerGone => "the worker disconnected",
            Outcome::Evicted => "the caller read too slowly",
            Outcome::Violation => "the worker broke the protocol",
            Outcome::Shutdown => "the relay is shutting down",
            Outcome::Cancelled => "the call was cancelled",
            Outcome::Ok | Outcome::Truncated | Outcome::SourceError(_) => "the call ended",
        }
    }
}

/// A call's byte and chunk caps.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    /// The most bytes.
    pub max_bytes: u64,
    /// The most chunks.
    pub max_chunks: u32,
}

/// What a call holds until it concludes (R-106): its session's in-flight pass, its private connection's pending
/// request (R-103), and its stream's mark on that connection's watch, whose undrained clock its conclusion starts.
#[derive(Default)]
pub(crate) struct Permits {
    /// Held for its drop: the session's call slot (R-57).
    pub(crate) _session: Option<crate::limits::SessionPass>,
    /// Held for its drop: the connection's pending request (R-103).
    pub(crate) _request: Option<PendingRequest>,
    pub(crate) stream: Option<Arc<StreamMark>>,
}

impl Permits {
    /// The call concluded at `now`: the stream's undrained clock starts, then the pass and the request go.
    fn release(self, now: Instant) {
        if let Some(mark) = &self.stream {
            mark.concluded(now);
        }
    }
}

/// One call's state.
pub struct CallState {
    request_id: String,
    /// R-112: the session an eviction of this call is charged to.
    session_id: String,
    outcome: OnceLock<Outcome>,
    bytes: AtomicU64,
    chunks: AtomicU64,
    /// R-42: the worker's last chunk when it found the caller's buffer full, for the stream to yield after the buffer
    /// (`keep_final`). A last chunk the buffer took leaves nothing here: no second copy outlives it.
    final_chunk: Mutex<Option<CallChunk>>,
    /// R-106: what the call holds until it concludes.
    permits: Mutex<Option<Permits>>,
    /// R-112: when each chunk now in the caller's buffer was handed to it, oldest first.
    buffered: Mutex<VecDeque<Instant>>,
    log: Option<CallLog>,
    started: Instant,
    ended: CancellationToken,
}

impl CallState {
    /// A call of `request_id` in session `session_id`; `log` writes its call line when it ends (None in unit tests).
    pub(crate) fn new(request_id: String, session_id: String, log: Option<CallLog>) -> CallState {
        CallState {
            request_id,
            session_id,
            outcome: OnceLock::new(),
            bytes: AtomicU64::new(0),
            chunks: AtomicU64::new(0),
            final_chunk: Mutex::new(None),
            permits: Mutex::new(None),
            buffered: Mutex::new(VecDeque::new()),
            log,
            started: Instant::now(),
            ended: CancellationToken::new(),
        }
    }

    /// The call's id.
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The call's session (R-112).
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    /// How it ended, once it did.
    pub(crate) fn outcome(&self) -> Option<Outcome> {
        self.outcome.get().copied()
    }

    /// Cancelled when the call ends (its deadline timer stops).
    pub(crate) fn ended(&self) -> CancellationToken {
        self.ended.clone()
    }

    /// The data bytes and chunks forwarded so far.
    pub(crate) fn sent(&self) -> (u64, u64) {
        (self.bytes.load(Ordering::SeqCst), self.chunks.load(Ordering::SeqCst))
    }

    /// R-106: the call holds `permits` until it concludes; a call that concluded already releases them at once.
    pub(crate) fn hold(&self, permits: Permits) {
        let mut held = self.permits.lock().unwrap_or_else(PoisonError::into_inner);
        if self.outcome.get().is_some() {
            drop(held);
            permits.release(Instant::now());
        } else {
            *held = Some(permits);
        }
    }

    /// Sets the outcome if none is set, then writes the call line and releases what the call held (R-106); false
    /// when it was already set.
    pub(crate) fn conclude(&self, outcome: Outcome) -> bool {
        if self.outcome.set(outcome).is_err() {
            return false;
        }
        self.ended.cancel();
        if let Some(log) = &self.log {
            let (bytes, chunks) = self.sent();
            let millis = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            log.write(outcome, bytes, chunks, millis);
        }
        let held = self.permits.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(permits) = held {
            permits.release(Instant::now());
        }
        true
    }

    /// R-111: hands `chunk` to the caller's buffer `to` without waiting; a buffered chunk's instant is kept for R-112's
    /// charge until the stream takes it.
    pub(crate) fn hand(&self, to: &mpsc::Sender<CallChunk>, chunk: CallChunk, now: Instant) -> Handoff {
        let mut buffered = self.buffered.lock().unwrap_or_else(PoisonError::into_inner);
        buffered.push_back(now);
        match to.try_send(chunk) {
            Ok(()) => Handoff::Buffered,
            Err(e) => {
                buffered.pop_back();
                match e {
                    mpsc::error::TrySendError::Full(chunk) => Handoff::Full(chunk),
                    mpsc::error::TrySendError::Closed(_) => Handoff::Gone,
                }
            }
        }
    }

    /// R-42, R-111: the call's last chunk found the caller's buffer full (`Handoff::Full`): the call keeps it, and the
    /// stream yields it once the buffer is drained and the queue closed. A last chunk that finds the stream gone
    /// (`Handoff::Gone`) is not kept: nobody is left to read it.
    pub(crate) fn keep_final(&self, chunk: CallChunk) {
        *self.final_chunk.lock().unwrap_or_else(PoisonError::into_inner) = Some(chunk);
    }

    /// R-112: when the oldest chunk in the caller's buffer was handed to it.
    pub(crate) fn oldest_buffered(&self) -> Option<Instant> {
        self.buffered.lock().unwrap_or_else(PoisonError::into_inner).front().copied()
    }

    /// The stream took the oldest buffered chunk.
    fn unbuffered(&self) {
        self.buffered.lock().unwrap_or_else(PoisonError::into_inner).pop_front();
    }
}

/// What became of a chunk handed to its caller's buffer (R-111).
pub(crate) enum Handoff {
    /// In the buffer.
    Buffered,
    /// The buffer was full: the chunk back.
    Full(CallChunk),
    /// The caller's stream went (R-43 ran).
    Gone,
}

/// What to do with one chunk (R-37, R-39, R-40, R-109).
pub enum Delivery {
    /// Hand it to the caller.
    Forward {
        /// The caller's queue.
        to: tokio::sync::mpsc::Sender<CallChunk>,
        /// The chunk.
        chunk: CallChunk,
        /// Whether it is the call's last.
        last: bool,
        /// A `Cancel` reason to send the worker, if any.
        cancel: Option<&'static str>,
        /// The call (R-111's hand-off, R-112's charge).
        state: Arc<CallState>,
    },
    /// End the call with this outcome.
    Fail {
        /// The caller's queue.
        to: tokio::sync::mpsc::Sender<CallChunk>,
        /// The outcome.
        outcome: Outcome,
    },
    /// A chunk of one of the table's last `RECENT_CALLS` ended calls: dropped and counted (R-46's late chunks).
    Late,
    /// Not a call of this table, nor a recent one: dropped and counted, and budgeted by the tunnel (R-109).
    Unknown,
}

/// The table is full or closed (R-44).
#[derive(Debug)]
pub struct Busy;

struct Pending {
    state: Arc<CallState>,
    to: mpsc::Sender<CallChunk>,
    caps: Caps,
    next_seq: u64,
    sent: u64,
    chunks: u32,
}

/// One tunnel's calls.
pub struct CallTable {
    calls: DashMap<String, Pending>,
    /// Closed by a fail-all; held while an insert checks it, so no entry lands after the drain (R-44).
    closed: Mutex<bool>,
    /// R-109: the request ids of the last `RECENT_CALLS` ended calls, oldest first.
    recent: Mutex<VecDeque<String>>,
    limit: usize,
}

#[allow(clippy::len_without_is_empty)]
impl CallTable {
    /// A table of at most `limit` calls.
    pub fn new(limit: usize) -> CallTable {
        CallTable { calls: DashMap::new(), closed: Mutex::new(false), recent: Mutex::new(VecDeque::with_capacity(RECENT_CALLS)), limit }
    }

    /// Refused when full or closed (R-44).
    pub fn insert(&self, state: Arc<CallState>, caps: Caps, buffer: usize) -> Result<tokio::sync::mpsc::Receiver<CallChunk>, Busy> {
        let closed = self.closed.lock().unwrap_or_else(PoisonError::into_inner);
        if *closed || self.calls.len() >= self.limit || self.calls.contains_key(state.request_id()) {
            return Err(Busy);
        }
        let (to, rx) = mpsc::channel(buffer.max(1));
        self.calls.insert(state.request_id().to_string(), Pending { state, to, caps, next_seq: 0, sent: 0, chunks: 0 });
        drop(closed);
        Ok(rx)
    }

    /// R-37, R-39, R-40 and R-109, synchronously; the reader hands a `Forward` on with `CallState::hand`.
    pub fn on_chunk(&self, chunk: Chunk) -> Delivery {
        let request_id = chunk.request_id.clone();
        let mut delivery = Delivery::Unknown;
        let mut ending = None;
        // Decided and removed under the entry's one lock: no other end can slip between the check and the removal.
        let removed = self.calls.remove_if_mut(&request_id, |_, p| {
            let (d, end) = route(p, chunk);
            delivery = d;
            ending = end;
            end.is_some()
        });
        if let (Some((_, gone)), Some(outcome)) = (removed, ending) {
            // The `Forward` that ends the call carries its last chunk: the hand-off keeps it only when the caller's
            // buffer is full (`CallState::keep_final`), and the `Forward`'s sender keeps the stream's queue open
            // until then (R-42).
            gone.state.conclude(outcome);
            self.remember(&request_id);
        }
        if matches!(delivery, Delivery::Unknown) && self.is_recent(&request_id) {
            return Delivery::Late;
        }
        delivery
    }

    /// Removes the call and sets its outcome; false when it was already gone.
    pub fn finish(&self, request_id: &str, outcome: Outcome) -> bool {
        match self.calls.remove(request_id) {
            Some((_, p)) => {
                p.state.conclude(outcome);
                self.remember(request_id);
                true
            }
            None => false,
        }
    }

    /// Closes the table and ends every pending call with `outcome`; returns how many (R-44).
    pub fn fail_all(&self, outcome: Outcome) -> usize {
        *self.closed.lock().unwrap_or_else(PoisonError::into_inner) = true;
        let ids: Vec<String> = self.calls.iter().map(|e| e.key().clone()).collect();
        ids.iter().filter(|id| self.finish(id, outcome)).count()
    }

    /// LD-R53: whether `request_id` is a live call of this table. Read-only: `on_chunk` decides its chunk's fate.
    pub(crate) fn holds(&self, request_id: &str) -> bool {
        self.calls.contains_key(request_id)
    }

    /// How many calls are pending.
    pub fn len(&self) -> usize {
        self.calls.len()
    }

    /// Whether a fail-all closed it (an insert then answers `source offline`, R-44).
    pub(crate) fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Removes a call that never reached its worker, with no outcome: its refusal writes the line (R-38). Its id is
    /// not remembered: no worker was ever told of it.
    pub(crate) fn discard(&self, request_id: &str) -> bool {
        self.calls.remove(request_id).is_some()
    }

    /// R-109: one more ended call; the oldest of `RECENT_CALLS` is forgotten.
    fn remember(&self, request_id: &str) {
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        if recent.len() >= RECENT_CALLS {
            recent.pop_front();
        }
        recent.push_back(request_id.to_string());
    }

    /// R-109: whether `request_id` is one of the last `RECENT_CALLS` ended calls.
    pub(crate) fn is_recent(&self, request_id: &str) -> bool {
        self.recent.lock().unwrap_or_else(PoisonError::into_inner).iter().any(|r| r == request_id)
    }
}

/// R-39 and R-40 for one chunk of a pending call: what to deliver, and the outcome when it ends the call. What it
/// delivers holds no more capacity than its length: prost's merge keeps a repeated field's first allocation (up to the
/// frame's 256 KiB), and only its length is checked, so a chunk stays inside §RS.2's 64 KiB term.
fn route(p: &mut Pending, mut chunk: Chunk) -> (Delivery, Option<Outcome>) {
    let printable = chunk.content_type.len() <= CONTENT_TYPE_MAX && chunk.content_type.bytes().all(|b| (0x20..=0x7e).contains(&b));
    if chunk.seq != p.next_seq || chunk.data.len() > CHUNK_MAX || !printable {
        return (Delivery::Fail { to: p.to.clone(), outcome: Outcome::Violation }, Some(Outcome::Violation));
    }
    p.next_seq += 1;
    chunk.request_id.shrink_to_fit();
    chunk.data.shrink_to_fit();
    chunk.content_type.shrink_to_fit();
    let mut out = CallChunk {
        request_id: chunk.request_id,
        seq: chunk.seq,
        data: chunk.data,
        content_type: chunk.content_type,
        r#final: chunk.r#final,
        error: None,
        truncated: chunk.truncated,
    };
    let (ending, cancel) = if let Some(e) = chunk.error {
        // R-40: an error ends the call, final and with no data; its code is a gRPC code, its message cut.
        let code = if (1..=16).contains(&e.code) { e.code } else { 2 };
        out.error = Some(Error { code, message: cut(e.message, MESSAGE_MAX) });
        out.data.clear();
        out.r#final = true;
        out.truncated = false;
        (Some(Outcome::SourceError(code)), None)
    } else {
        if !out.r#final {
            out.truncated = false;
        }
        let room = p.caps.max_bytes.saturating_sub(p.sent);
        let over_bytes = out.data.len() as u64 > room;
        if over_bytes {
            out.data.truncate(usize::try_from(room).unwrap_or(usize::MAX));
        }
        let over_chunks = !out.r#final && p.chunks.saturating_add(1) >= p.caps.max_chunks;
        if over_bytes || over_chunks {
            out.r#final = true;
            out.truncated = true;
            (Some(Outcome::Truncated), Some(if over_bytes { cancel::BYTE_CAP } else { cancel::CHUNK_CAP }))
        } else if out.r#final {
            (Some(if out.truncated { Outcome::Truncated } else { Outcome::Ok }), None)
        } else {
            (None, None)
        }
    };
    p.sent += out.data.len() as u64;
    p.chunks = p.chunks.saturating_add(1);
    p.state.bytes.fetch_add(out.data.len() as u64, Ordering::SeqCst);
    p.state.chunks.fetch_add(1, Ordering::SeqCst);
    (Delivery::Forward { to: p.to.clone(), chunk: out, last: ending.is_some(), cancel, state: Arc::clone(&p.state) }, ending)
}

/// At most `max` bytes, cut at a character boundary, with no more capacity than its length.
fn cut(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut i = max;
        while !s.is_char_boundary(i) {
            i -= 1;
        }
        s.truncate(i);
    }
    s.shrink_to_fit();
    s
}

/// The response stream of one `Call`: yields the forwarded chunks, then R-42's kept or synthetic final when needed.
/// It holds the relay's in-flight permit and its mark on the connection's watch until it is dropped (R-106), so at
/// most `calls_in_flight_max` calls hold buffered chunks, and a stream nobody drains is cut with its connection
/// `UNDRAINED_GRACE` after its call concluded (R-103). Yielding its last item releases nothing: hyper takes a body's
/// frame before it waits for the client's window, so a client that grants none parks the call's last frame in hyper,
/// and hyper drops the stream only once that frame and the trailers are handed on.
pub struct CallStream {
    rx: mpsc::Receiver<CallChunk>,
    state: Arc<CallState>,
    table: Weak<CallTable>,
    tunnel: mpsc::Sender<Result<RelayFrame, tonic::Status>>,
    relay: Option<tokio::sync::OwnedSemaphorePermit>,
    mark: Option<Arc<StreamMark>>,
    within: Duration,
    yielded: u64,
    done: bool,
}

impl CallStream {
    /// The stream of a call inserted in `table`, whose `Cancel` goes to `tunnel` within `within` (R-43), holding the
    /// relay's permit `relay` and its connection's `mark`.
    pub(crate) fn new(
        rx: mpsc::Receiver<CallChunk>,
        state: Arc<CallState>,
        table: Weak<CallTable>,
        tunnel: mpsc::Sender<Result<RelayFrame, tonic::Status>>,
        relay: Option<tokio::sync::OwnedSemaphorePermit>,
        mark: Option<Arc<StreamMark>>,
        within: Duration,
    ) -> CallStream {
        CallStream { rx, state, table, tunnel, relay, mark, within, yielded: 0, done: false }
    }

    /// R-106: the stream is dropped: the relay's permit and the connection's mark go.
    fn release(&mut self) {
        self.relay = None;
        if let Some(mark) = self.mark.take() {
            mark.drained();
        }
    }

    /// R-42: the final that ends a stream whose queue closed before a final went through it.
    fn last_word(&mut self) -> CallChunk {
        if let Some(kept) = self.state.final_chunk.lock().unwrap_or_else(PoisonError::into_inner).take() {
            return kept;
        }
        // A queue that closed with no outcome lost its tunnel without a fail-all: the worker is gone.
        if self.state.outcome().is_none() {
            self.state.conclude(Outcome::WorkerGone);
        }
        let outcome = self.state.outcome().unwrap_or(Outcome::WorkerGone);
        let code = match outcome.code() {
            0 => 2,
            c => c,
        };
        CallChunk {
            request_id: self.state.request_id.clone(),
            seq: self.yielded,
            data: Vec::new(),
            content_type: String::new(),
            r#final: true,
            error: Some(Error { code, message: outcome.message().to_string() }),
            truncated: false,
        }
    }
}

impl tokio_stream::Stream for CallStream {
    type Item = Result<CallChunk, tonic::Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        // R-106: the last item yielded releases nothing; the drop does (hyper may hold that item unsent).
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                self.state.unbuffered();
                self.yielded += 1;
                if chunk.r#final {
                    self.done = true;
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(Some(Ok(self.last_word())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for CallStream {
    /// R-43: a caller gone before its final chunk ends the call `Cancelled` and tells the worker, once; then R-106's
    /// release, whether the stream was drained (hyper drops a read stream right after its trailers) or not.
    fn drop(&mut self) {
        if !self.done {
            if let Some(table) = self.table.upgrade() {
                if table.finish(&self.state.request_id, Outcome::Cancelled) {
                    let frame = crate::tunnel::cancel_frame(&self.state.request_id, cancel::CALLER_GONE);
                    if let Err(mpsc::error::TrySendError::Full(Ok(frame))) = self.tunnel.try_send(Ok(frame)) {
                        crate::tunnel::send_later(self.tunnel.clone(), frame, self.within);
                    }
                }
            }
        }
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(id: &str, seq: u64, len: usize, last: bool) -> Chunk {
        Chunk { request_id: id.into(), seq, data: vec![7; len], content_type: "application/json".into(), r#final: last, error: None, truncated: false }
    }

    fn state(id: &str) -> Arc<CallState> {
        Arc::new(CallState::new(id.into(), "0199a1b2-0000-7000-8000-000000000002".into(), None))
    }

    fn pending(table: &CallTable, id: &str, max_bytes: u64, max_chunks: u32) -> (Arc<CallState>, mpsc::Receiver<CallChunk>) {
        let state = state(id);
        let rx = table.insert(Arc::clone(&state), Caps { max_bytes, max_chunks }, 64).expect("room");
        (state, rx)
    }

    fn forwarded(d: Delivery) -> (CallChunk, bool, Option<&'static str>) {
        match d {
            Delivery::Forward { chunk, last, cancel, .. } => (chunk, last, cancel),
            Delivery::Fail { outcome, .. } => panic!("failed: {outcome:?}"),
            Delivery::Late => panic!("late"),
            Delivery::Unknown => panic!("unknown"),
        }
    }

    /// Unit 13.
    #[test]
    fn chunks_are_forwarded_in_order_under_the_byte_cap() {
        let table = CallTable::new(8);
        let (state, _rx) = pending(&table, "r1", 204_800, 256);
        for seq in 0..3 {
            let (c, last, cancel) = forwarded(table.on_chunk(chunk("r1", seq, 65_536, false)));
            assert_eq!((c.data.len(), c.r#final, c.truncated, last, cancel), (65_536, false, false, false, None));
        }
        let (c, last, cancel) = forwarded(table.on_chunk(chunk("r1", 3, 65_536, false)));
        assert_eq!(c.data.len(), 8192);
        assert!(c.r#final && c.truncated && last);
        assert_eq!(cancel, Some("byte_cap"));
        assert_eq!(state.outcome(), Some(Outcome::Truncated));
        assert_eq!(state.sent(), (204_800, 4));
        assert_eq!(table.len(), 0);
    }

    /// Unit 14.
    #[test]
    fn a_bad_chunk_fails_its_call_only() {
        let table = CallTable::new(8);
        let (other, _rx0) = pending(&table, "other", 1 << 20, 16);
        let bad = [chunk("r", 1, 10, false), chunk("r", 0, 65_537, false), Chunk { content_type: "x".repeat(129), ..chunk("r", 0, 10, false) }];
        for (i, c) in bad.into_iter().enumerate() {
            let (state, _rx) = pending(&table, "r", 1 << 20, 16);
            match table.on_chunk(c) {
                Delivery::Fail { outcome, .. } => assert_eq!(outcome, Outcome::Violation, "case {i}"),
                _ => panic!("case {i} must fail"),
            }
            assert_eq!(state.outcome(), Some(Outcome::Violation));
            assert_eq!(table.len(), 1, "only the other call is left");
        }
        assert!(matches!(table.on_chunk(chunk("nobody", 0, 1, true)), Delivery::Unknown));
        assert!(matches!(table.on_chunk(chunk("r", 1, 1, true)), Delivery::Late), "a broken call's later chunk is late");
        assert_eq!(other.outcome(), None, "the table's other call untouched");
        assert!(matches!(table.on_chunk(chunk("other", 0, 1, false)), Delivery::Forward { last: false, .. }));
        let ctl = Chunk { content_type: "text/plain\u{7f}".into(), ..chunk("other", 1, 1, false) };
        assert!(matches!(table.on_chunk(ctl), Delivery::Fail { .. }), "printable ASCII only");
    }

    /// Unit 15.
    #[test]
    fn the_chunk_cap_ends_with_a_truncated_final() {
        let table = CallTable::new(8);
        let (state, _rx) = pending(&table, "r", 1 << 20, 2);
        let (c0, last0, _) = forwarded(table.on_chunk(chunk("r", 0, 10, false)));
        assert!(!c0.r#final && !c0.truncated && !last0);
        let (c1, last1, cancel) = forwarded(table.on_chunk(chunk("r", 1, 10, false)));
        assert!(c1.r#final && c1.truncated && last1);
        assert_eq!(cancel, Some("chunk_cap"));
        assert_eq!(state.outcome(), Some(Outcome::Truncated));

        let (state, _rx) = pending(&table, "s", 1 << 20, 2);
        forwarded(table.on_chunk(chunk("s", 0, 10, false)));
        let (c1, last, cancel) = forwarded(table.on_chunk(chunk("s", 1, 10, true)));
        assert!(c1.r#final && !c1.truncated && last);
        assert_eq!(cancel, None);
        assert_eq!(state.outcome(), Some(Outcome::Ok));
    }

    /// Unit 16.
    #[test]
    fn a_worker_error_ends_the_call_as_sent() {
        let table = CallTable::new(8);
        let error = |id: &str, code: i32, message: String| Chunk { error: Some(Error { code, message }), ..chunk(id, 0, 10, false) };
        let (state, _rx) = pending(&table, "a", 1 << 20, 16);
        let (c, last, cancel) = forwarded(table.on_chunk(error("a", 5, "no such row".into())));
        assert!(c.r#final && last && c.data.is_empty() && cancel.is_none());
        assert_eq!(c.error.as_ref().map(|e| e.code), Some(5));
        assert_eq!(state.outcome(), Some(Outcome::SourceError(5)));
        for (id, code) in [("b", 0), ("c", 99)] {
            let (state, _rx) = pending(&table, id, 1 << 20, 16);
            let (c, _, _) = forwarded(table.on_chunk(error(id, code, "x".into())));
            assert_eq!(c.error.unwrap().code, 2);
            assert_eq!(state.outcome(), Some(Outcome::SourceError(2)));
        }
        let (_s, _rx) = pending(&table, "d", 1 << 20, 16);
        let long = "é".repeat(1000);
        let (c, _, _) = forwarded(table.on_chunk(error("d", 13, long)));
        let message = c.error.unwrap().message;
        assert!(message.len() <= 1024 && message.len() >= 1023, "{}", message.len());
        assert!(message.chars().all(|ch| ch == 'é'));
        let (_s, _rx) = pending(&table, "e", 1 << 20, 16);
        let (c, _, _) = forwarded(table.on_chunk(Chunk { truncated: true, ..chunk("e", 0, 10, false) }));
        assert!(!c.truncated, "a non-final chunk's truncated is cleared");
    }

    /// Unit 17.
    #[test]
    fn fail_all_empties_and_closes_the_table() {
        let table = CallTable::new(8);
        let states: Vec<_> = (0..5).map(|i| pending(&table, &format!("r{i}"), 1 << 20, 16)).collect();
        assert_eq!(table.fail_all(Outcome::WorkerGone), 5);
        assert_eq!(table.len(), 0);
        assert!(states.iter().all(|(s, _)| s.outcome() == Some(Outcome::WorkerGone)));
        assert!(table.insert(state("late"), Caps { max_bytes: 1, max_chunks: 1 }, 1).is_err());
        assert!(table.is_closed());
        assert!((0..5).all(|i| table.is_recent(&format!("r{i}"))), "a fail-all's calls ended: their late chunks are known");
    }

    #[test]
    fn a_full_table_refuses_and_outcomes_have_their_codes() {
        let table = CallTable::new(1);
        let _a = pending(&table, "a", 1, 1);
        assert!(table.insert(state("b"), Caps { max_bytes: 1, max_chunks: 1 }, 1).is_err());
        assert!(!table.is_closed());
        let pairs: Vec<(&str, i32)> =
            [Outcome::Ok, Outcome::Truncated, Outcome::SourceError(9), Outcome::Cancelled, Outcome::Deadline, Outcome::WorkerGone, Outcome::Evicted, Outcome::Violation, Outcome::Shutdown]
                .iter()
                .map(|o| (o.word(), o.code()))
                .collect();
        assert_eq!(
            pairs,
            [("ok", 0), ("truncated", 0), ("source_error", 9), ("cancelled", 1), ("deadline", 4), ("worker_gone", 14), ("evicted", 10), ("violation", 13), ("shutdown", 14)]
        );
    }

    /// Unit 43 (R-109).
    #[test]
    fn chunks_of_recently_ended_calls_are_known_late() {
        assert_eq!(RECENT_CALLS, 64);
        let table = CallTable::new(8);
        let (first, _rx) = pending(&table, "r0", 1 << 20, 16);
        forwarded(table.on_chunk(chunk("r0", 0, 10, true)));
        assert_eq!(first.outcome(), Some(Outcome::Ok));
        assert!(table.is_recent("r0"), "a finished call is in the ring");
        assert!(matches!(table.on_chunk(chunk("r0", 1, 10, true)), Delivery::Late), "its late chunk");
        assert!(matches!(table.on_chunk(chunk("never", 0, 1, true)), Delivery::Unknown), "an id never carried");
        for i in 1..RECENT_CALLS {
            let id = format!("r{i}");
            let (_s, _rx) = pending(&table, &id, 1 << 20, 16);
            assert!(table.finish(&id, if i % 2 == 0 { Outcome::Cancelled } else { Outcome::Deadline }));
        }
        assert!(table.is_recent("r0"), "64 ended calls: the first still known");
        let (_s, _rx) = pending(&table, "r64", 1 << 20, 16);
        table.finish("r64", Outcome::Evicted);
        assert!(!table.is_recent("r0"), "the 65th ended call forgets the first");
        assert!(matches!(table.on_chunk(chunk("r0", 1, 10, true)), Delivery::Unknown));
        assert!(table.is_recent("r1") && table.is_recent("r64"));
        // A call that never reached its worker is not remembered.
        let (_s, _rx) = pending(&table, "never-sent", 1 << 20, 16);
        assert!(table.discard("never-sent"));
        assert!(!table.is_recent("never-sent"));
    }

    /// Unit 50 (§RS.2's 64 KiB a chunk): a field sent twice in one frame keeps the first's allocation through prost's
    /// merge, 256 KiB under its last value's few bytes. A routed chunk holds none of it, in its data, its content type or
    /// its request id, nor an error's message, long or short.
    #[test]
    fn a_routed_chunk_keeps_no_capacity_of_a_repeated_field() {
        use ai_env_relay_proto::prost::Message as _;
        const BIG: usize = 256 * 1024;
        let twice = |first: Chunk, last: Chunk| {
            let mut wire = first.encode_to_vec();
            wire.extend_from_slice(&last.encode_to_vec());
            Chunk::decode(wire.as_slice()).expect("one chunk, its fields sent twice")
        };
        let padded = Chunk { request_id: "x".repeat(BIG), data: vec![1; BIG], content_type: "y".repeat(BIG), ..chunk("x", 0, 0, false) };
        let decoded = twice(padded, chunk("r", 0, 2, false));
        assert_eq!((decoded.request_id.as_str(), decoded.data.len(), decoded.content_type.as_str()), ("r", 2, "application/json"));
        assert!(decoded.data.capacity() >= BIG && decoded.content_type.capacity() >= BIG && decoded.request_id.capacity() >= BIG, "the case: prost kept the first allocation");
        let table = CallTable::new(8);
        let (_s, _rx) = pending(&table, "r", 1 << 20, 16);
        let (c, _, _) = forwarded(table.on_chunk(decoded));
        assert!(c.data.capacity() <= CHUNK_MAX, "{}", c.data.capacity());
        assert!(c.content_type.capacity() <= CONTENT_TYPE_MAX, "{}", c.content_type.capacity());
        assert!(c.request_id.capacity() <= 64, "{}", c.request_id.capacity());

        // An error's message, whose last value is short (no truncation), or long.
        for (id, last, len) in [("short", "m".to_string(), 1), ("long", "m".repeat(2 * MESSAGE_MAX), MESSAGE_MAX)] {
            let with = |message: String| Chunk { error: Some(Error { code: 5, message }), ..chunk(id, 0, 0, true) };
            let decoded = twice(with("z".repeat(BIG)), with(last));
            assert!(decoded.error.as_ref().unwrap().message.capacity() >= BIG, "the case: prost kept the first allocation");
            let (_s, _rx) = pending(&table, id, 1 << 20, 16);
            let (c, _, _) = forwarded(table.on_chunk(decoded));
            let message = c.error.unwrap().message;
            assert_eq!(message.len(), len);
            assert!(message.capacity() <= MESSAGE_MAX, "{id}: {}", message.capacity());
        }
    }

    /// LD-R53: the table holds a call from its insert until it ends, however it ends, and asking changes nothing: its
    /// late chunks are late, an id never carried unknown.
    #[test]
    fn a_table_holds_its_live_calls_alone() {
        let table = CallTable::new(8);
        assert!(!table.holds("r"), "before its insert");
        let (_s, _rx) = pending(&table, "r", 1 << 20, 16);
        assert!(table.holds("r") && table.holds("r"));
        assert_eq!(table.len(), 1);
        forwarded(table.on_chunk(chunk("r", 0, 10, false)));
        assert!(table.holds("r"), "a chunk that ends nothing");
        forwarded(table.on_chunk(chunk("r", 1, 10, true)));
        assert!(!table.holds("r"), "its final ended it");
        assert!(matches!(table.on_chunk(chunk("r", 2, 10, false)), Delivery::Late));
        assert!(!table.holds("r") && !table.holds("nobody"));

        let (_s, _rx) = pending(&table, "chunk-cap", 1 << 20, 1);
        forwarded(table.on_chunk(chunk("chunk-cap", 0, 10, false)));
        assert!(!table.holds("chunk-cap"), "over its chunks");
        let (_s, _rx) = pending(&table, "byte-cap", 5, 16);
        forwarded(table.on_chunk(chunk("byte-cap", 0, 10, false)));
        assert!(!table.holds("byte-cap"), "over its bytes");
        let (_s, _rx) = pending(&table, "broken", 1 << 20, 16);
        assert!(matches!(table.on_chunk(chunk("broken", 7, 10, false)), Delivery::Fail { .. }));
        assert!(!table.holds("broken"), "a seq out of order");
        let (_s, _rx) = pending(&table, "finished", 1 << 20, 16);
        assert!(table.finish("finished", Outcome::Evicted));
        assert!(!table.holds("finished"), "evicted");
        let (_s, _rx) = pending(&table, "discarded", 1 << 20, 16);
        assert!(table.discard("discarded"));
        assert!(!table.holds("discarded"), "never sent");
        let (_s, _rx) = pending(&table, "failed", 1 << 20, 16);
        assert_eq!(table.fail_all(Outcome::WorkerGone), 1);
        assert!(!table.holds("failed"), "a fail-all");
    }

    /// R-106, R-112: a call holds its session pass until it concludes, whether its stream is read or not; a call that
    /// concluded before `hold` releases at once. The hand-off never waits, and keeps each buffered chunk's instant.
    #[test]
    fn a_call_holds_its_pass_until_it_concludes_and_hands_without_waiting() {
        let l = crate::config::Limits { calls_per_session: 1, ..crate::config::Limits::default() };
        let sessions = crate::limits::Sessions::new(&l);
        let t0 = Instant::now();
        let table = CallTable::new(8);
        let call = state("r");
        let mut rx = table.insert(Arc::clone(&call), Caps { max_bytes: 1 << 20, max_chunks: 16 }, 1).expect("room");
        call.hold(Permits { _session: sessions.enter("s", "mac", true, t0).unwrap(), ..Permits::default() });
        assert!(sessions.enter("s", "mac", true, t0).is_err(), "the pass is held");
        // The buffer of one: the first chunk is handed, the second finds it full, with no wait.
        let Delivery::Forward { to, chunk: c0, state, .. } = table.on_chunk(chunk("r", 0, 10, false)) else { panic!("forward") };
        assert!(matches!(state.hand(&to, c0, t0), Handoff::Buffered));
        let Delivery::Forward { to, chunk: c1, state, .. } = table.on_chunk(chunk("r", 1, 10, false)) else { panic!("forward") };
        let later = t0 + Duration::from_millis(1200);
        assert!(matches!(state.hand(&to, c1, later), Handoff::Full(_)));
        assert_eq!(state.oldest_buffered(), Some(t0), "the full hand-off kept no instant");
        assert!(table.finish("r", Outcome::Evicted));
        assert!(sessions.enter("s", "mac", true, t0).is_ok(), "concluded: the pass went, the stream unread");
        assert!(rx.try_recv().is_ok());
        drop(rx);
        let Delivery::Late = table.on_chunk(chunk("r", 2, 10, false)) else { panic!("late") };
        let rx = table.insert(self::state("g"), Caps { max_bytes: 1 << 20, max_chunks: 16 }, 1).expect("room");
        drop(rx);
        let Delivery::Forward { to, chunk: c, state: gone, .. } = table.on_chunk(chunk("g", 0, 10, false)) else { panic!("forward") };
        assert!(matches!(gone.hand(&to, c, t0), Handoff::Gone), "its caller's stream went");
        assert_eq!(gone.oldest_buffered(), None);

        let early = state_with_outcome();
        early.hold(Permits { _session: sessions.enter("t", "mac", true, t0).unwrap(), ..Permits::default() });
        assert!(sessions.enter("t", "mac", true, t0).is_ok(), "held after its conclusion: released at once");
    }

    fn state_with_outcome() -> Arc<CallState> {
        let s = state("done");
        assert!(s.conclude(Outcome::Ok));
        s
    }

    /// The stream's next item, polled once: hyper's poll, with a waker that does nothing.
    fn next(stream: &mut CallStream, cx: &mut Context<'_>) -> Option<CallChunk> {
        use tokio_stream::Stream as _;
        match Pin::new(stream).poll_next(cx) {
            Poll::Ready(Some(Ok(c))) => Some(c),
            Poll::Ready(None) => None,
            other => panic!("an item or the end, not {other:?}"),
        }
    }

    /// R-42, R-106 (review B finding 1): a last chunk the caller's buffer takes leaves no copy behind; one that finds
    /// the buffer full is kept, and the stream yields it after the buffer. Either way the stream keeps the relay's
    /// permit and its connection's undrained clock after it yielded its last item, until it is dropped: hyper takes a
    /// body's frame before it waits for the client's window, so a yielded item may never have left.
    #[test]
    fn a_full_buffer_keeps_the_last_chunk_and_a_stream_holds_its_permit_until_dropped() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let conn = crate::tls::PrivateConns::default().insert(1, Instant::now());
        conn.verified();
        let budget = crate::tls::PrivateBudget { token: Duration::from_secs(5), idle: Duration::from_secs(600), undrained: Duration::from_secs(10), faulted: Duration::from_secs(1) };
        let undrained = || conn.next_cut(&budget).is_some_and(|(_, reason)| reason == "undrained");
        let table = Arc::new(CallTable::new(8));
        let (tunnel, _worker) = mpsc::channel::<Result<RelayFrame, tonic::Status>>(4);
        // A call with a buffer of one, its stream holding the relay's permit and its connection's mark.
        let open = |id: &str| {
            let call = state(id);
            let rx = table.insert(Arc::clone(&call), Caps { max_bytes: 1 << 20, max_chunks: 16 }, 1).expect("room");
            let mark = Arc::new(conn.stream());
            call.hold(Permits { stream: Some(Arc::clone(&mark)), ..Permits::default() });
            let permit = Arc::clone(&permits).try_acquire_owned().expect("the relay's permit");
            (Arc::clone(&call), CallStream::new(rx, call, Arc::downgrade(&table), tunnel.clone(), Some(permit), Some(mark), Duration::from_secs(1)))
        };

        // Its first chunk takes the buffer; its last finds the buffer full and is kept (R-42, R-111).
        let (call, mut stream) = open("kept");
        let Delivery::Forward { to, chunk: c, state: s, .. } = table.on_chunk(chunk("kept", 0, 10, false)) else { panic!("forward") };
        assert!(matches!(s.hand(&to, c, Instant::now()), Handoff::Buffered));
        drop((to, s));
        let Delivery::Forward { to, chunk: c, last: true, state: s, .. } = table.on_chunk(chunk("kept", 1, 20, true)) else { panic!("the last") };
        assert_eq!(call.outcome(), Some(Outcome::Ok));
        assert!(call.final_chunk.lock().unwrap().is_none(), "routing keeps no copy of the last chunk");
        let Handoff::Full(c) = s.hand(&to, c, Instant::now()) else { panic!("the buffer is full") };
        s.keep_final(c);
        drop((to, s));
        assert!(undrained(), "concluded: the undrained clock runs");
        assert_eq!(next(&mut stream, &mut cx).map(|c| c.seq), Some(0));
        let last = next(&mut stream, &mut cx).expect("the kept last chunk, after the buffer");
        assert!(last.r#final && last.error.is_none() && last.seq == 1 && last.data.len() == 20, "{last:?}");
        assert!(next(&mut stream, &mut cx).is_none());
        assert_eq!(permits.available_permits(), 0, "its last item yielded, the stream still holds the relay's permit");
        assert!(undrained(), "and its mark");
        drop(stream);
        assert_eq!(permits.available_permits(), 1, "dropped: the permit is back");
        assert!(!undrained(), "and the mark is gone");

        // A last chunk the buffer takes: no copy is kept.
        let (call, mut stream) = open("taken");
        let Delivery::Forward { to, chunk: c, state: s, .. } = table.on_chunk(chunk("taken", 0, 10, true)) else { panic!("forward") };
        assert!(matches!(s.hand(&to, c, Instant::now()), Handoff::Buffered));
        drop((to, s));
        assert!(call.final_chunk.lock().unwrap().is_none(), "no second copy of a last chunk the buffer took");
        assert!(next(&mut stream, &mut cx).is_some_and(|c| c.r#final && c.seq == 0));
        assert!(next(&mut stream, &mut cx).is_none());
        assert_eq!(permits.available_permits(), 0);
        drop(stream);
        assert_eq!(permits.available_permits(), 1);
    }
}
