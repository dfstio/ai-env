//! Pure replay structures of the spawn manager (plan S6, W2): the stdout
//! credit window (a ring of seq-numbered chunks trimmed by acks), the stderr
//! drop-oldest buffer with its cumulative counter, the exit slot, the send
//! cursor of each attachment and the gap rule, and the stdin queue (dedupe,
//! gap, overflow, EOF). No I/O, no clock: unit tests and proptests drive them
//! directly.
use crate::wire::chunk::raw_len;
use crate::wire::frame::{Chunk, ErrorCode, ExitInfo};
use std::collections::VecDeque;

/// One retained chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    seq: u64,
    chunk: Chunk,
    len: u64,
}

/// Chunks numbered from 1 in production order, retained until acked (or dropped).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ring {
    held: VecDeque<Held>,
    /// The seq the next chunk gets.
    next: u64,
    /// Raw bytes retained.
    bytes: u64,
}

impl Ring {
    fn new() -> Ring {
        Ring { held: VecDeque::new(), next: 1, bytes: 0 }
    }

    fn push(&mut self, chunk: Chunk) -> u64 {
        let len = raw_len(&chunk).unwrap_or(0) as u64;
        let seq = self.next;
        self.next += 1;
        self.bytes += len;
        self.held.push_back(Held { seq, chunk, len });
        seq
    }

    fn pop_front(&mut self) -> Option<Held> {
        let h = self.held.pop_front()?;
        self.bytes -= h.len;
        Some(h)
    }

    /// Drop every chunk at or below `seq`.
    fn trim(&mut self, seq: u64) {
        while self.held.front().is_some_and(|h| h.seq <= seq) {
            self.pop_front();
        }
    }

    fn last(&self) -> u64 {
        self.next - 1
    }

    /// The oldest retained seq (`last + 1` when none is).
    fn first(&self) -> u64 {
        self.held.front().map_or(self.next, |h| h.seq)
    }

    fn get(&self, seq: u64) -> Option<&Chunk> {
        let at = usize::try_from(seq.checked_sub(self.held.front()?.seq)?).ok()?;
        self.held.get(at).map(|h| &h.chunk)
    }
}

/// The stdout credit window of one spawn: every chunk stays until the Mac
/// acks it, and the reader may only read while [`OutWindow::room`] says so —
/// nothing is ever dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutWindow {
    ring: Ring,
}

impl Default for OutWindow {
    fn default() -> Self {
        OutWindow { ring: Ring::new() }
    }
}

impl OutWindow {
    /// Append one chunk; its seq.
    pub fn push(&mut self, chunk: Chunk) -> u64 {
        self.ring.push(chunk)
    }

    /// The Mac consumed stdout up to `seq`: trim it (a seq beyond the last
    /// chunk trims everything, never what is not produced yet).
    pub fn ack(&mut self, seq: u64) {
        self.ring.trim(seq);
    }

    /// The last seq produced (0 = none yet).
    #[must_use]
    pub fn last(&self) -> u64 {
        self.ring.last()
    }

    /// The oldest seq retained (`last + 1` when none is).
    #[must_use]
    pub fn first(&self) -> u64 {
        self.ring.first()
    }

    /// Unacked raw bytes and chunks.
    #[must_use]
    pub fn unacked(&self) -> (u64, u64) {
        (self.ring.bytes, self.ring.held.len() as u64)
    }

    #[must_use]
    pub fn get(&self, seq: u64) -> Option<&Chunk> {
        self.ring.get(seq)
    }

    /// Bytes the reader may read now: `limit_bytes` minus what is unacked,
    /// and 0 once `limit_chunks` chunks are unacked. A reader that reads at
    /// most this much keeps the unacked bytes within `limit_bytes` + 3 (the
    /// incomplete UTF-8 tail a Chunker holds back) and the chunks within
    /// `limit_chunks` + 1 (one read can end a held tail and start a chunk).
    #[must_use]
    pub fn room(&self, limit_bytes: u64, limit_chunks: u64) -> u64 {
        if self.ring.held.len() as u64 >= limit_chunks {
            return 0;
        }
        limit_bytes.saturating_sub(self.ring.bytes)
    }
}

/// The stderr buffer of one spawn: chunks stay until acked, but never more
/// than `cap` bytes — the oldest go first; those dropped before the
/// attachment was handed them are counted in `dropped` (one it was handed
/// is the Mac's: delivered, or counted there as its own drop; one in flight
/// on a socket that died, and dropped before the reattach, is counted by
/// neither). The reader never waits on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrBuffer {
    ring: Ring,
    cap: u64,
    dropped: u64,
}

impl ErrBuffer {
    #[must_use]
    pub fn new(cap: u64) -> ErrBuffer {
        ErrBuffer { ring: Ring::new(), cap, dropped: 0 }
    }

    /// Append one chunk, then drop the oldest until at most `cap` bytes are
    /// held; its seq. `next` is the attachment's next stderr seq
    /// ([`Cursor::err`]): a dropped chunk below it was handed out already
    /// and is not counted again.
    pub fn push(&mut self, chunk: Chunk, next: u64) -> u64 {
        let seq = self.ring.push(chunk);
        while self.ring.bytes > self.cap {
            match self.ring.pop_front() {
                Some(h) if h.seq >= next => self.dropped += h.len,
                Some(_) => {}
                None => break,
            }
        }
        seq
    }

    pub fn ack(&mut self, seq: u64) {
        self.ring.trim(seq);
    }

    #[must_use]
    pub fn last(&self) -> u64 {
        self.ring.last()
    }

    #[must_use]
    pub fn first(&self) -> u64 {
        self.ring.first()
    }

    /// Bytes dropped before they were handed out, so far (cumulative).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    #[must_use]
    pub fn held_bytes(&self) -> u64 {
        self.ring.bytes
    }

    #[must_use]
    pub fn get(&self, seq: u64) -> Option<&Chunk> {
        self.ring.get(seq)
    }
}

/// The exit slot's content, assigned once: when the leader has exited and
/// both readers are done (EOF, or abandoned while an escaper holds a pipe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitRecord {
    /// The last stdout seq + 1: every stdout chunk is below it.
    pub seq: u64,
    pub info: ExitInfo,
    pub stderr_dropped: u64,
    pub stdout_truncated: bool,
}

impl ExitRecord {
    /// The record for a spawn whose readers are done: no chunk follows it.
    #[must_use]
    pub fn assign(out: &OutWindow, err: &ErrBuffer, info: ExitInfo, stdout_truncated: bool) -> ExitRecord {
        ExitRecord { seq: out.last() + 1, info, stderr_dropped: err.dropped(), stdout_truncated }
    }
}

/// A reattach asked for stdout older than the oldest retained chunk: an
/// earlier client acked (and so released) what this one asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap;

/// Where one attachment's sends stand: the next stdout and stderr seq to
/// hand out, and whether the exit was handed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub out: u64,
    pub err: u64,
    pub exit_sent: bool,
}

impl Cursor {
    /// An attachment replaying from `from` (stdout) and `err_from` (stderr);
    /// absent = the oldest retained chunk. The gap rule: a `from` older than
    /// the oldest retained stdout chunk is a [`Gap`]; a `from` past the last
    /// chunk starts at the next one. stderr is lossy by design (drop-oldest),
    /// so an old `err_from` starts at its oldest retained chunk instead.
    pub fn resume(out: &OutWindow, err: &ErrBuffer, from: Option<u64>, err_from: Option<u64>) -> Result<Cursor, Gap> {
        // Seqs start at 1: a `from` of 0 asks for everything.
        let out_at = match from.map(|f| f.max(1)) {
            None => out.first(),
            Some(f) if f < out.first() => return Err(Gap),
            Some(f) => f.min(out.last() + 1),
        };
        let err_at = err_from.map_or(err.first(), |f| f.clamp(err.first(), err.last() + 1));
        Ok(Cursor { out: out_at, err: err_at, exit_sent: false })
    }

    /// The next stdout chunk to hand out (acked chunks are skipped).
    pub fn next_out<'a>(&mut self, out: &'a OutWindow) -> Option<(u64, &'a Chunk)> {
        self.out = self.out.max(out.first());
        let chunk = out.get(self.out)?;
        self.out += 1;
        Some((self.out - 1, chunk))
    }

    /// The next stderr chunk to hand out (acked and dropped chunks are skipped).
    pub fn next_err<'a>(&mut self, err: &'a ErrBuffer) -> Option<(u64, &'a Chunk)> {
        self.err = self.err.max(err.first());
        let chunk = err.get(self.err)?;
        self.err += 1;
        Some((self.err - 1, chunk))
    }

    /// Every retained chunk of both streams was handed out.
    #[must_use]
    pub fn drained(&self, out: &OutWindow, err: &ErrBuffer) -> bool {
        self.out.max(out.first()) > out.last() && self.err.max(err.first()) > err.last()
    }

    /// The exit, once, and only after every earlier stdout and stderr chunk
    /// was handed out.
    pub fn take_exit(&mut self, out: &OutWindow, err: &ErrBuffer, slot: Option<&ExitRecord>) -> Option<ExitRecord> {
        let rec = *slot?;
        if self.exit_sent || !self.drained(out, err) {
            return None;
        }
        self.exit_sent = true;
        Some(rec)
    }
}

/// The stdin side of one spawn: seqs from 1, queued until written to the
/// pipe; at most `window` bytes held unwritten (unacked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdinQueue {
    queue: VecDeque<(u64, Vec<u8>)>,
    /// Bytes queued or being written (not yet acked).
    pending: u64,
    window: u64,
    /// The highest seq held (written or queued): the Mac resends above it.
    in_seq: u64,
    /// The highest seq written to the pipe (what `stdin_ack` carries).
    written: u64,
    /// `stdin_eof`: close the pipe once everything up to this seq is written.
    eof: Option<u64>,
}

impl StdinQueue {
    #[must_use]
    pub fn new(window: u64) -> StdinQueue {
        StdinQueue { queue: VecDeque::new(), pending: 0, window, in_seq: 0, written: 0, eof: None }
    }

    /// One `stdin` frame: `Ok(true)` queued, `Ok(false)` a duplicate (at or
    /// below `in_seq`, dropped silently) or data past the EOF seq (ignored);
    /// a seq that skips ahead is [`ErrorCode::StdinGap`], more than the
    /// window [`ErrorCode::StdinOverflow`].
    pub fn offer(&mut self, seq: u64, bytes: Vec<u8>) -> Result<bool, ErrorCode> {
        if seq <= self.in_seq || self.eof.is_some_and(|e| seq > e) {
            return Ok(false);
        }
        if seq != self.in_seq + 1 {
            return Err(ErrorCode::StdinGap);
        }
        let len = bytes.len() as u64;
        if self.pending + len > self.window {
            return Err(ErrorCode::StdinOverflow);
        }
        self.pending += len;
        self.in_seq = seq;
        self.queue.push_back((seq, bytes));
        Ok(true)
    }

    /// `stdin_eof {seq}` (the first one counts; 0 = no stdin was sent).
    pub fn eof(&mut self, seq: u64) {
        self.eof.get_or_insert(seq);
    }

    /// The next chunk for the pipe (never one past the EOF seq).
    pub fn to_write(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.queue.front().is_some_and(|(s, _)| self.eof.is_some_and(|e| *s > e)) {
            return None;
        }
        self.queue.pop_front()
    }

    /// The chunk `seq` of `len` bytes is in the pipe.
    pub fn wrote(&mut self, seq: u64, len: u64) {
        self.written = self.written.max(seq);
        self.pending = self.pending.saturating_sub(len);
    }

    /// The pipe is gone (the child closed it): everything held counts as
    /// written, and so will every later chunk.
    pub fn discard(&mut self) {
        self.queue.clear();
        self.pending = 0;
        self.written = self.in_seq;
    }

    /// Everything up to the EOF seq is written: close the pipe.
    #[must_use]
    pub fn close_due(&self) -> bool {
        self.eof.is_some_and(|e| self.written >= e)
    }

    #[must_use]
    pub fn in_seq(&self) -> u64 {
        self.in_seq
    }

    #[must_use]
    pub fn written(&self) -> u64 {
        self.written
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::chunk::{decode, Chunker};
    use crate::wire::frame::CHUNK_MAX;
    use proptest::prelude::*;

    fn text(s: &str) -> Chunk {
        Chunk { text: Some(s.to_string()), b64: None }
    }

    fn exit0() -> ExitInfo {
        ExitInfo { code: Some(0), signal: None }
    }

    #[test]
    fn window_numbers_from_one_trims_on_ack_and_never_past_production() {
        let mut w = OutWindow::default();
        assert_eq!((w.first(), w.last()), (1, 0), "empty: first = last + 1");
        assert_eq!(w.push(text("ab")), 1);
        assert_eq!(w.push(text("cde")), 2);
        assert_eq!(w.unacked(), (5, 2));
        assert_eq!(w.get(2), Some(&text("cde")));
        assert_eq!(w.get(3), None);
        w.ack(1);
        assert_eq!((w.first(), w.last(), w.unacked()), (2, 2, (3, 1)));
        assert_eq!(w.get(1), None, "trimmed");
        w.ack(99);
        assert_eq!((w.first(), w.last(), w.unacked()), (3, 2, (0, 0)), "everything acked: first = last + 1");
        assert_eq!(w.push(text("f")), 3, "an ack past production does not skip seqs");
        w.ack(1);
        assert_eq!(w.first(), 3, "an old ack trims nothing");
    }

    #[test]
    fn room_counts_bytes_and_chunks() {
        let mut w = OutWindow::default();
        assert_eq!(w.room(10, 3), 10);
        w.push(text("1234"));
        assert_eq!(w.room(10, 3), 6);
        w.push(text("123456"));
        assert_eq!(w.room(10, 3), 0, "the byte window is full");
        assert_eq!(w.room(10 + 1024, 3), 1024, "past the window after the leader died");
        w.ack(2);
        w.push(text("a"));
        w.push(text("b"));
        w.push(text("c"));
        assert_eq!(w.room(10, 3), 0, "the chunk window is full");
    }

    /// Nothing handed out yet (the attachment's next seq is 1).
    #[test]
    fn stderr_drops_oldest_and_counts_cumulatively() {
        let mut b = ErrBuffer::new(5);
        b.push(text("abc"), 1);
        b.push(text("de"), 1);
        assert_eq!((b.first(), b.last(), b.dropped(), b.held_bytes()), (1, 2, 0, 5));
        b.push(text("f"), 1);
        assert_eq!((b.first(), b.dropped(), b.held_bytes()), (2, 3, 3), "the oldest chunk went");
        b.ack(2);
        b.push(text("ghijk"), 1);
        assert_eq!((b.first(), b.last(), b.dropped(), b.held_bytes()), (4, 4, 4, 5), "f dropped, the acked de is not counted");
        b.push(text("lmnopq"), 1);
        assert_eq!((b.first(), b.last(), b.dropped(), b.held_bytes()), (6, 5, 15, 0), "a chunk larger than the buffer goes too");
    }

    /// A dropped chunk the attachment was already handed is the Mac's to
    /// deliver or count, so `dropped` does not count it again; one dropped
    /// before it was handed out does count.
    #[test]
    fn a_dropped_chunk_counts_only_if_it_was_never_handed_out() {
        let w = OutWindow::default();
        let mut b = ErrBuffer::new(4);
        let mut c = Cursor::resume(&w, &b, None, None).unwrap();
        b.push(text("ab"), c.err);
        assert_eq!(c.next_err(&b).map(|(s, _)| s), Some(1));
        b.push(text("cde"), c.err);
        assert_eq!((b.first(), b.dropped()), (2, 0), "seq 1 was handed out before it was dropped");
        b.push(text("fg"), c.err);
        assert_eq!((b.first(), b.dropped()), (3, 3), "seq 2 was dropped before it was handed out");
        assert_eq!(c.next_err(&b).map(|(s, _)| s), Some(3), "the cursor skips what was dropped");
    }

    #[test]
    fn gap_rule_and_cursor_starts() {
        let mut w = OutWindow::default();
        let b = ErrBuffer::new(1024);
        for s in ["a", "b", "c", "d"] {
            w.push(text(s));
        }
        w.ack(2);
        assert_eq!(Cursor::resume(&w, &b, None, None).unwrap().out, 3, "absent: the oldest retained");
        assert_eq!(Cursor::resume(&w, &b, Some(3), None).unwrap().out, 3);
        assert_eq!(Cursor::resume(&w, &b, Some(4), None).unwrap().out, 4);
        assert_eq!(Cursor::resume(&w, &b, Some(2), None), Err(Gap), "older than the trimmed point");
        assert_eq!(Cursor::resume(&w, &b, Some(1), None), Err(Gap));
        assert_eq!(Cursor::resume(&w, &b, Some(50), None).unwrap().out, 5, "past production: the next chunk");
        let fresh = OutWindow::default();
        assert_eq!(Cursor::resume(&fresh, &b, Some(0), None).unwrap().out, 1, "from 0 = from 1: nothing was trimmed");
        assert_eq!(Cursor::resume(&fresh, &b, Some(1), None).unwrap().out, 1);
        let mut e = ErrBuffer::new(2);
        e.push(text("xy"), 1);
        e.push(text("z"), 1);
        assert_eq!(Cursor::resume(&w, &e, None, Some(1)).unwrap().err, 2, "stderr never gaps: the oldest retained");
    }

    #[test]
    fn cursor_skips_acked_and_dropped_chunks() {
        let mut w = OutWindow::default();
        let mut b = ErrBuffer::new(4);
        let mut c = Cursor::resume(&w, &b, None, None).unwrap();
        assert_eq!(c.next_out(&w), None);
        w.push(text("1"));
        w.push(text("2"));
        w.push(text("3"));
        assert_eq!(c.next_out(&w).map(|(s, _)| s), Some(1));
        w.ack(2);
        assert_eq!(c.next_out(&w).map(|(s, ch)| (s, ch.clone())), Some((3, text("3"))), "seq 2 was acked meanwhile");
        assert_eq!(c.next_out(&w), None);
        b.push(text("aa"), c.err);
        b.push(text("bb"), c.err);
        b.push(text("cc"), c.err);
        assert_eq!(c.next_err(&b).map(|(s, _)| s), Some(2), "seq 1 was dropped");
    }

    #[test]
    fn exit_waits_for_both_cursors_and_goes_once() {
        let mut w = OutWindow::default();
        let mut b = ErrBuffer::new(1024);
        w.push(text("out"));
        b.push(text("err"), 1);
        let slot = ExitRecord::assign(&w, &b, exit0(), false);
        assert_eq!(slot.seq, 2);
        let mut c = Cursor::resume(&w, &b, None, None).unwrap();
        assert_eq!(c.take_exit(&w, &b, Some(&slot)), None, "stdout and stderr pending");
        c.next_out(&w);
        assert_eq!(c.take_exit(&w, &b, Some(&slot)), None, "stderr pending");
        c.next_err(&b);
        assert_eq!(c.take_exit(&w, &b, None), None, "no exit yet");
        assert_eq!(c.take_exit(&w, &b, Some(&slot)), Some(slot));
        assert_eq!(c.take_exit(&w, &b, Some(&slot)), None, "once");
        let mut again = Cursor::resume(&w, &b, Some(1), None).unwrap();
        again.next_out(&w);
        again.next_err(&b);
        assert_eq!(again.take_exit(&w, &b, Some(&slot)), Some(slot), "a reattach collects it again");
    }

    #[test]
    fn acks_past_the_cursor_count_as_drained() {
        let mut w = OutWindow::default();
        let b = ErrBuffer::new(1024);
        w.push(text("a"));
        w.push(text("b"));
        let mut c = Cursor::resume(&w, &b, None, None).unwrap();
        w.ack(2);
        let slot = ExitRecord::assign(&w, &b, exit0(), false);
        assert_eq!(c.take_exit(&w, &b, Some(&slot)).map(|r| r.seq), Some(3), "the client already had both chunks");
    }

    #[test]
    fn stdin_dedupes_gaps_overflows_and_closes_at_eof() {
        let mut q = StdinQueue::new(10);
        assert_eq!(q.offer(1, b"abc".to_vec()), Ok(true));
        assert_eq!(q.offer(1, b"abc".to_vec()), Ok(false), "a resent seq is a duplicate");
        assert_eq!(q.offer(3, b"x".to_vec()), Err(ErrorCode::StdinGap));
        assert_eq!(q.offer(2, vec![0; 8]), Err(ErrorCode::StdinOverflow), "3 + 8 > 10");
        assert_eq!(q.offer(2, vec![0; 7]), Ok(true), "3 + 7 = the window");
        assert_eq!(q.in_seq(), 2);
        assert_eq!(q.to_write(), Some((1, b"abc".to_vec())));
        assert_eq!(q.offer(3, vec![1]), Err(ErrorCode::StdinOverflow), "a chunk being written still counts");
        q.wrote(1, 3);
        assert_eq!(q.offer(3, vec![1]), Ok(true));
        assert_eq!(q.written(), 1);
        q.eof(4);
        assert!(!q.close_due());
        assert_eq!(q.to_write().map(|(s, _)| s), Some(2));
        q.wrote(2, 7);
        assert_eq!(q.to_write().map(|(s, _)| s), Some(3));
        q.wrote(3, 1);
        assert!(!q.close_due(), "seq 4 is still missing");
        assert_eq!(q.offer(5, vec![9]), Ok(false), "past the EOF seq: ignored");
        q.eof(9);
        assert_eq!(q.offer(4, vec![2]), Ok(true), "the first EOF counts");
        assert_eq!(q.to_write().map(|(s, _)| s), Some(4));
        q.wrote(4, 1);
        assert!(q.close_due());
        let mut none = StdinQueue::new(10);
        none.eof(0);
        assert!(none.close_due(), "EOF 0: no stdin at all");
    }

    #[test]
    fn stdin_discard_acks_everything_held() {
        let mut q = StdinQueue::new(100);
        q.offer(1, vec![1; 10]).unwrap();
        q.offer(2, vec![1; 10]).unwrap();
        q.discard();
        assert_eq!((q.written(), q.to_write()), (2, None));
        q.offer(3, vec![1; 100]).unwrap();
        q.discard();
        assert_eq!(q.written(), 3, "the window is free again");
    }

    /// One step of the replay model below.
    #[derive(Debug, Clone)]
    enum Op {
        /// The child writes (a chunk of `n` bytes, 1..=8).
        Push(u8),
        /// The writer hands the next frame to the socket.
        Send,
        /// The socket delivers its oldest in-flight frame.
        Deliver,
        /// The Mac acks what it has (contiguously) received.
        Ack,
        /// The socket dies with its in-flight frames; the Mac reattaches.
        Cut,
        /// As `Cut`, but without `from_seq` when the Mac holds nothing unacked
        /// (the oldest retained chunk is then exactly the next it lacks).
        CutFromOldest,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (1u8..=8).prop_map(Op::Push),
            4 => Just(Op::Send),
            4 => Just(Op::Deliver),
            2 => Just(Op::Ack),
            1 => Just(Op::Cut),
            1 => Just(Op::CutFromOldest),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// No loss and no duplicate across any interleaving of push, ack and
        /// reattach-from-seq: every stdout chunk the Mac receives is exactly
        /// the next one it lacks, a reattach is never a gap, and once the
        /// child stops and the exit is assigned, the last attachment delivers
        /// everything and then the exit.
        #[test]
        fn stdout_replay_never_loses_or_duplicates(ops in proptest::collection::vec(op(), 0..300)) {
            let mut w = OutWindow::default();
            let b = ErrBuffer::new(1024);
            let mut cur = Cursor::resume(&w, &b, None, None).unwrap();
            let mut flight: VecDeque<u64> = VecDeque::new();
            let (mut have, mut acked) = (0u64, 0u64);
            let mut bytes: Vec<u8> = Vec::new();
            let mut got: Vec<u8> = Vec::new();
            for op in ops {
                match op {
                    Op::Push(n) => {
                        let s: String = (0..n).map(|i| char::from(b'a' + ((w.last() as u8).wrapping_add(i)) % 26)).collect();
                        bytes.extend_from_slice(s.as_bytes());
                        w.push(text(&s));
                    }
                    Op::Send => {
                        if let Some((seq, _)) = cur.next_out(&w) {
                            flight.push_back(seq);
                        }
                    }
                    Op::Deliver => {
                        if let Some(seq) = flight.pop_front() {
                            prop_assert_eq!(seq, have + 1, "in order, nothing skipped, nothing twice");
                            got.extend(decode(w.get(seq).expect("an unacked chunk is retained")).unwrap());
                            have = seq;
                        }
                    }
                    Op::Ack => {
                        acked = have;
                        w.ack(acked);
                    }
                    Op::Cut => {
                        flight.clear();
                        cur = Cursor::resume(&w, &b, Some(have + 1), None).map_err(|g| TestCaseError::fail(format!("{g:?} at {have}")))?;
                    }
                    Op::CutFromOldest => {
                        flight.clear();
                        let from = (have != acked).then_some(have + 1);
                        cur = Cursor::resume(&w, &b, from, None).unwrap();
                    }
                }
                prop_assert!(w.first() == acked + 1, "exactly the unacked chunks are retained");
            }
            flight.clear();
            let slot = ExitRecord::assign(&w, &b, exit0(), false);
            let mut last = Cursor::resume(&w, &b, Some(have + 1), None).unwrap();
            prop_assert_eq!(last.take_exit(&w, &b, Some(&slot)).is_some(), have == w.last(), "the exit waits for the replay");
            while let Some((seq, ch)) = last.next_out(&w) {
                prop_assert_eq!(seq, have + 1);
                got.extend(decode(ch).unwrap());
                have = seq;
            }
            prop_assert_eq!(&got, &bytes);
            prop_assert_eq!(slot.seq, have + 1);
            prop_assert!(last.exit_sent || last.take_exit(&w, &b, Some(&slot)) == Some(slot));
        }

        /// stderr: delivered seqs only increase (no duplicate), and every
        /// byte is delivered or counted as dropped, never both: delivered +
        /// dropped = produced.
        #[test]
        fn stderr_never_duplicates_and_counts_what_it_drops(sizes in proptest::collection::vec((1usize..40, any::<bool>(), any::<bool>()), 0..200), cap in 1u64..120) {
            let mut b = ErrBuffer::new(cap);
            let w = OutWindow::default();
            let mut cur = Cursor::resume(&w, &b, None, None).unwrap();
            let (mut produced, mut delivered, mut last_seq) = (0u64, 0u64, 0u64);
            for (n, send, ack) in sizes {
                b.push(text(&"e".repeat(n)), cur.err);
                produced += n as u64;
                prop_assert!(b.held_bytes() <= cap);
                if send {
                    while let Some((seq, ch)) = cur.next_err(&b) {
                        prop_assert!(seq > last_seq);
                        last_seq = seq;
                        delivered += raw_len(ch).unwrap() as u64;
                    }
                }
                if ack {
                    b.ack(last_seq);
                }
            }
            while let Some((seq, ch)) = cur.next_err(&b) {
                prop_assert!(seq > last_seq);
                last_seq = seq;
                delivered += raw_len(ch).unwrap() as u64;
            }
            prop_assert_eq!(delivered + b.dropped(), produced, "{} delivered, {} dropped", delivered, b.dropped());
        }

        /// The exit is handed out exactly when every retained stdout and
        /// stderr chunk was (whatever the order of hand-outs, acks and
        /// stderr drops), once, and nothing follows it.
        #[test]
        fn the_exit_waits_for_both_cursors(outs in proptest::collection::vec(1usize..30, 0..20), errs in proptest::collection::vec(1usize..30, 0..20), cap in 1u64..80, order in proptest::collection::vec((any::<bool>(), any::<bool>()), 0..80)) {
            let mut w = OutWindow::default();
            let mut b = ErrBuffer::new(cap);
            for n in &outs {
                w.push(text(&"o".repeat(*n)));
            }
            for n in &errs {
                b.push(text(&"e".repeat(*n)), 1);
            }
            let slot = ExitRecord::assign(&w, &b, exit0(), false);
            prop_assert_eq!(slot.seq, outs.len() as u64 + 1);
            let mut c = Cursor::resume(&w, &b, None, None).unwrap();
            let mut steps = order.into_iter().chain(std::iter::repeat((true, false)));
            loop {
                let pending = c.out.max(w.first()) <= w.last() || c.err.max(b.first()) <= b.last();
                let exit = c.take_exit(&w, &b, Some(&slot));
                prop_assert_eq!(exit.is_some(), !pending);
                if exit.is_some() {
                    break;
                }
                let (stdout_first, ack) = steps.next().unwrap_or((true, false));
                let handed = if stdout_first {
                    c.next_out(&w).is_some() || c.next_err(&b).is_some()
                } else {
                    let err = c.next_err(&b).is_some();
                    err || c.next_out(&w).is_some()
                };
                prop_assert!(handed, "pending means something to hand out");
                if ack {
                    w.ack(c.out - 1);
                    b.ack(c.err - 1);
                }
            }
            prop_assert!(c.next_out(&w).is_none() && c.next_err(&b).is_none(), "nothing after the exit");
            prop_assert_eq!(c.take_exit(&w, &b, Some(&slot)), None, "once");
        }

        /// A reader that reads at most `room` bytes per read keeps the window:
        /// unacked bytes ≤ limit + 3, chunks ≤ limit + 1, whatever the reads,
        /// the bytes (UTF-8 cut anywhere, or not UTF-8 at all) and the acks.
        #[test]
        fn the_window_bound_holds(data in proptest::collection::vec(any::<u8>(), 0..40_000), reads in proptest::collection::vec((1usize..20_000, any::<bool>()), 1..60), limit in 1u64..30_000, limit_chunks in 1u64..6) {
            let mut w = OutWindow::default();
            let mut ch = Chunker::new();
            let mut at = 0usize;
            for (want, ack) in reads {
                let room = w.room(limit, limit_chunks);
                let n = want.min(room as usize).min(CHUNK_MAX).min(data.len() - at);
                for c in ch.push(&data[at..at + n]) {
                    w.push(c);
                }
                at += n;
                let (bytes, chunks) = w.unacked();
                prop_assert!(bytes <= limit + 3, "{} > {} + 3", bytes, limit);
                prop_assert!(chunks <= limit_chunks + 1);
                if ack {
                    w.ack(w.last());
                }
            }
        }
    }

    /// Critic M1: the window is full and nobody acks, then the leader is
    /// killed. The reader drains past the window (by at most 1 MiB) what the
    /// pipe still holds, reaches EOF, and only then is the exit assigned —
    /// so a later attach replays every byte, then the exit, untruncated.
    #[test]
    fn full_window_then_kill_replays_everything_then_the_exit() {
        const WINDOW: u64 = 4096;
        const PAST: u64 = 1024 * 1024;
        let produced: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let mut w = OutWindow::default();
        let b = ErrBuffer::new(1024);
        let mut ch = Chunker::new();
        let mut at = 0usize;
        // Alive: read while there is room; the rest stays in the "pipe".
        loop {
            let n = (w.room(WINDOW, 20_000) as usize).min(CHUNK_MAX).min(produced.len() - at);
            if n == 0 {
                break;
            }
            for c in ch.push(&produced[at..at + n]) {
                w.push(c);
            }
            at += n;
        }
        assert!(at < produced.len() && w.unacked().0 <= WINDOW + 3, "the window stopped the reader");
        // The leader died: the writers are gone, the pipe drains past the window.
        loop {
            let n = (w.room(WINDOW + PAST, 20_000 + 1024) as usize).min(CHUNK_MAX).min(produced.len() - at);
            if n == 0 {
                break;
            }
            for c in ch.push(&produced[at..at + n]) {
                w.push(c);
            }
            at += n;
        }
        assert_eq!(at, produced.len(), "1 MiB past the window holds what a pipe can");
        if let Some(tail) = ch.finish() {
            w.push(tail);
        }
        let slot = ExitRecord::assign(&w, &b, ExitInfo { code: None, signal: Some(9) }, false);
        assert_eq!(slot.seq, w.last() + 1);
        let mut c = Cursor::resume(&w, &b, None, None).unwrap();
        assert_eq!(c.take_exit(&w, &b, Some(&slot)), None, "replay first");
        let mut got = Vec::new();
        let mut seqs = Vec::new();
        while let Some((seq, chunk)) = c.next_out(&w) {
            seqs.push(seq);
            got.extend(decode(chunk).unwrap());
        }
        assert_eq!(got, produced, "every byte, in order");
        assert_eq!(seqs, (1..slot.seq).collect::<Vec<_>>());
        let exit = c.take_exit(&w, &b, Some(&slot)).unwrap();
        assert_eq!((exit.info.signal, exit.stdout_truncated), (Some(9), false));
    }
}
