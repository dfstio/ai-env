//! The per-tunnel call table, chunk routing and `CallStream` (R-37 to R-46). Synchronous only (R-75, a `make lint`
//! guard): nothing in this file awaits. The tunnel's reader hands each chunk to `CallTable::on_chunk`, which decides
//! everything under the entry's lock and returns what to deliver; the reader then waits for the caller's buffer
//! outside any guard (R-41).
//!
//! A call's outcome is set once (`CallState::conclude`), by whoever ends it first: its final chunk, a breach, the
//! deadline, an eviction, the caller going, a fail-all or a shutdown; that same step writes its one call line (R-61).

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use ai_env_relay_proto::v1::{CallChunk, Chunk, Error, RelayFrame};
use ai_env_source::wire::cancel;
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::reqlog::CallLog;

/// The most bytes of one chunk's data.
pub const CHUNK_MAX: usize = 65_536;
/// The most bytes of an error message.
pub const MESSAGE_MAX: usize = 1024;
/// The longest content type.
pub const CONTENT_TYPE_MAX: usize = 128;

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

/// One call's state.
pub struct CallState {
    request_id: String,
    outcome: OnceLock<Outcome>,
    bytes: AtomicU64,
    chunks: AtomicU64,
    /// A copy of the final chunk the worker's answer ended with, for a caller whose hand-off timed out (R-42).
    final_chunk: Mutex<Option<CallChunk>>,
    log: Option<CallLog>,
    started: tokio::time::Instant,
    ended: CancellationToken,
}

impl CallState {
    /// A call of `request_id`; `log` writes its call line when it ends (None in unit tests).
    pub(crate) fn new(request_id: String, log: Option<CallLog>) -> CallState {
        CallState {
            request_id,
            outcome: OnceLock::new(),
            bytes: AtomicU64::new(0),
            chunks: AtomicU64::new(0),
            final_chunk: Mutex::new(None),
            log,
            started: tokio::time::Instant::now(),
            ended: CancellationToken::new(),
        }
    }

    /// The call's id.
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
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

    /// Sets the outcome if none is set, and then writes the call line; false when it was already set.
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
        true
    }
}

/// What to do with one chunk (R-37, R-39, R-40).
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
    },
    /// End the call with this outcome.
    Fail {
        /// The caller's queue.
        to: tokio::sync::mpsc::Sender<CallChunk>,
        /// The outcome.
        outcome: Outcome,
    },
    /// Not a call of this table: dropped and counted.
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
    limit: usize,
}

#[allow(clippy::len_without_is_empty)]
impl CallTable {
    /// A table of at most `limit` calls.
    pub fn new(limit: usize) -> CallTable {
        CallTable { calls: DashMap::new(), closed: Mutex::new(false), limit }
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

    /// R-37, R-39 and R-40, synchronously; the caller awaits the hand-off outside any guard (R-41).
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
            if let Delivery::Forward { chunk, .. } = &delivery {
                *gone.state.final_chunk.lock().unwrap_or_else(PoisonError::into_inner) = Some(chunk.clone());
            }
            gone.state.conclude(outcome);
        }
        delivery
    }

    /// Removes the call and sets its outcome; false when it was already gone.
    pub fn finish(&self, request_id: &str, outcome: Outcome) -> bool {
        match self.calls.remove(request_id) {
            Some((_, p)) => {
                p.state.conclude(outcome);
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

    /// How many calls are pending.
    pub fn len(&self) -> usize {
        self.calls.len()
    }

    /// Whether a fail-all closed it (an insert then answers `source offline`, R-44).
    pub(crate) fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Removes a call that never reached its worker, with no outcome: its refusal writes the line (R-38).
    pub(crate) fn discard(&self, request_id: &str) -> bool {
        self.calls.remove(request_id).is_some()
    }
}

/// R-39 and R-40 for one chunk of a pending call: what to deliver, and the outcome when it ends the call.
fn route(p: &mut Pending, chunk: Chunk) -> (Delivery, Option<Outcome>) {
    let printable = chunk.content_type.len() <= CONTENT_TYPE_MAX && chunk.content_type.bytes().all(|b| (0x20..=0x7e).contains(&b));
    if chunk.seq != p.next_seq || chunk.data.len() > CHUNK_MAX || !printable {
        return (Delivery::Fail { to: p.to.clone(), outcome: Outcome::Violation }, Some(Outcome::Violation));
    }
    p.next_seq += 1;
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
    (Delivery::Forward { to: p.to.clone(), chunk: out, last: ending.is_some(), cancel }, ending)
}

/// At most `max` bytes, cut at a character boundary.
fn cut(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut i = max;
        while !s.is_char_boundary(i) {
            i -= 1;
        }
        s.truncate(i);
    }
    s
}

/// What a call holds while its stream lives: the session's in-flight permit and the relay's (R-57), each
/// released when the stream goes.
#[derive(Default)]
pub(crate) struct Permits {
    pub(crate) _session: Option<crate::limits::SessionPass>,
    pub(crate) _relay: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// The response stream of one `Call`: yields the forwarded chunks, then R-42's synthetic final when needed.
pub struct CallStream {
    rx: mpsc::Receiver<CallChunk>,
    state: Arc<CallState>,
    table: Weak<CallTable>,
    tunnel: mpsc::Sender<Result<RelayFrame, tonic::Status>>,
    _permits: Permits,
    within: Duration,
    yielded: u64,
    done: bool,
}

impl CallStream {
    /// The stream of a call inserted in `table`, whose `Cancel` goes to `tunnel` within `within` (R-43).
    pub(crate) fn new(
        rx: mpsc::Receiver<CallChunk>,
        state: Arc<CallState>,
        table: Weak<CallTable>,
        tunnel: mpsc::Sender<Result<RelayFrame, tonic::Status>>,
        permits: Permits,
        within: Duration,
    ) -> CallStream {
        CallStream { rx, state, table, tunnel, _permits: permits, within, yielded: 0, done: false }
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
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                self.yielded += 1;
                if chunk.r#final {
                    self.done = true;
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(None) => {
                self.done = true;
                let last = self.last_word();
                Poll::Ready(Some(Ok(last)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for CallStream {
    /// R-43: a caller gone before its final chunk ends the call `Cancelled` and tells the worker, once.
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let Some(table) = self.table.upgrade() else { return };
        if table.finish(&self.state.request_id, Outcome::Cancelled) {
            let frame = crate::tunnel::cancel_frame(&self.state.request_id, cancel::CALLER_GONE);
            if let Err(mpsc::error::TrySendError::Full(Ok(frame))) = self.tunnel.try_send(Ok(frame)) {
                crate::tunnel::send_later(self.tunnel.clone(), frame, self.within);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(id: &str, seq: u64, len: usize, last: bool) -> Chunk {
        Chunk { request_id: id.into(), seq, data: vec![7; len], content_type: "application/json".into(), r#final: last, error: None, truncated: false }
    }

    fn pending(table: &CallTable, id: &str, max_bytes: u64, max_chunks: u32) -> (Arc<CallState>, mpsc::Receiver<CallChunk>) {
        let state = Arc::new(CallState::new(id.into(), None));
        let rx = table.insert(Arc::clone(&state), Caps { max_bytes, max_chunks }, 64).expect("room");
        (state, rx)
    }

    fn forwarded(d: Delivery) -> (CallChunk, bool, Option<&'static str>) {
        match d {
            Delivery::Forward { chunk, last, cancel, .. } => (chunk, last, cancel),
            Delivery::Fail { outcome, .. } => panic!("failed: {outcome:?}"),
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
        assert!(table.insert(Arc::new(CallState::new("late".into(), None)), Caps { max_bytes: 1, max_chunks: 1 }, 1).is_err());
        assert!(table.is_closed());
    }

    #[test]
    fn a_full_table_refuses_and_outcomes_have_their_codes() {
        let table = CallTable::new(1);
        let _a = pending(&table, "a", 1, 1);
        assert!(table.insert(Arc::new(CallState::new("b".into(), None)), Caps { max_bytes: 1, max_chunks: 1 }, 1).is_err());
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
}
