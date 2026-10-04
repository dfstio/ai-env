//! Incremental NDJSON line splitter with a hard per-line cap. Pure (no I/O):
//! the async pumps feed it chunks and drain complete lines. `\r` is kept so
//! forwarded lines stay byte-identical.
use bytes::{Buf, Bytes, BytesMut};

/// Longest line accepted by default: a bound for splitters that set none of
/// their own. The pumps split at [`CLI_LINE_BYTES`]; the agent transport (S6)
/// carries raw byte chunks, not lines, so no wire cap applies to a line.
pub const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// The Claude CLI's own stream-json line limit (268,435,456 characters in
/// 2.1.282): a local pump must never drop a line the CLI would accept (a user
/// message with pasted images, a transcript entry holding them).
pub const CLI_LINE_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineError {
    /// A line exceeded the splitter's cap ([`MAX_LINE_BYTES`] by default); `dropped_bytes` were discarded up
    /// to (not including) the next newline, and splitting resumes after it.
    TooLong { dropped_bytes: usize },
}

#[derive(Debug)]
pub struct LineSplitter {
    buf: BytesMut,
    discarding: bool,
    dropped: usize,
    cap: usize,
}

impl Default for LineSplitter {
    fn default() -> Self {
        Self::with_cap(MAX_LINE_BYTES)
    }
}

impl LineSplitter {
    /// A splitter with the default cap ([`MAX_LINE_BYTES`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A splitter whose longest accepted line is `cap` bytes.
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        LineSplitter { buf: BytesMut::new(), discarding: false, dropped: 0, cap }
    }

    /// Buffer a chunk. While an over-cap line is being discarded the bytes are
    /// still buffered: `next_line`/`finish` count and drop them.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Next complete line without its `\n`, or `None` when more input is needed.
    pub fn next_line(&mut self) -> Option<Result<Bytes, LineError>> {
        if self.discarding {
            return match self.buf.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    self.dropped += i;
                    self.buf.advance(i + 1);
                    self.discarding = false;
                    let dropped = std::mem::take(&mut self.dropped);
                    Some(Err(LineError::TooLong { dropped_bytes: dropped }))
                }
                None => {
                    self.dropped += self.buf.len();
                    self.buf.clear();
                    None
                }
            };
        }
        match self.buf.iter().position(|b| *b == b'\n') {
            Some(i) if i > self.cap => {
                self.buf.advance(i + 1);
                Some(Err(LineError::TooLong { dropped_bytes: i }))
            }
            Some(i) => {
                let line = self.buf.split_to(i).freeze();
                self.buf.advance(1);
                Some(Ok(line))
            }
            None => {
                if self.buf.len() > self.cap {
                    self.dropped = self.buf.len();
                    self.buf.clear();
                    self.discarding = true;
                }
                None
            }
        }
    }

    /// At EOF: the trailing unterminated line, if any.
    pub fn finish(&mut self) -> Option<Result<Bytes, LineError>> {
        if self.discarding {
            self.discarding = false;
            self.dropped += self.buf.len();
            self.buf.clear();
            let dropped = std::mem::take(&mut self.dropped);
            return Some(Err(LineError::TooLong { dropped_bytes: dropped }));
        }
        if self.buf.is_empty() {
            return None;
        }
        if self.buf.len() > self.cap {
            let dropped = self.buf.len();
            self.buf.clear();
            return Some(Err(LineError::TooLong { dropped_bytes: dropped }));
        }
        Some(Ok(self.buf.split().freeze()))
    }
}

/// `line` followed by exactly one `\n`.
#[must_use]
pub fn encode_line(line: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(line.len() + 1);
    out.extend_from_slice(line);
    out.extend_from_slice(b"\n");
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(s: &mut LineSplitter) -> Vec<Result<Vec<u8>, LineError>> {
        let mut out = Vec::new();
        while let Some(r) = s.next_line() {
            out.push(r.map(|b| b.to_vec()));
        }
        out
    }

    #[test]
    fn split_two_lines_one_chunk() {
        let mut s = LineSplitter::new();
        s.push(b"{\"a\":1}\n{\"b\":2}\n");
        assert_eq!(drain(&mut s), vec![Ok(b"{\"a\":1}".to_vec()), Ok(b"{\"b\":2}".to_vec())]);
        assert!(s.finish().is_none());
    }

    #[test]
    fn split_line_across_chunks() {
        let mut s = LineSplitter::new();
        s.push(b"{\"a\":");
        assert!(s.next_line().is_none());
        s.push(b"1}\n");
        assert_eq!(drain(&mut s), vec![Ok(b"{\"a\":1}".to_vec())]);
    }

    #[test]
    fn keeps_cr_bytes() {
        let mut s = LineSplitter::new();
        s.push(b"x\r\ny\n");
        assert_eq!(drain(&mut s), vec![Ok(b"x\r".to_vec()), Ok(b"y".to_vec())]);
    }

    #[test]
    fn exact_4mib_ok() {
        let mut s = LineSplitter::new();
        let line = vec![b'a'; MAX_LINE_BYTES];
        s.push(&line);
        s.push(b"\n");
        let got = s.next_line().unwrap().unwrap();
        assert_eq!(got.len(), MAX_LINE_BYTES);
    }

    #[test]
    fn four_mib_plus_one_too_long_then_resyncs() {
        let mut s = LineSplitter::new();
        let line = vec![b'a'; MAX_LINE_BYTES + 1];
        s.push(&line);
        assert!(s.next_line().is_none()); // now discarding
        s.push(b"tail\nnext\n");
        let first = s.next_line().unwrap();
        assert_eq!(first, Err(LineError::TooLong { dropped_bytes: MAX_LINE_BYTES + 1 + 4 }));
        assert_eq!(s.next_line().unwrap().unwrap().as_ref(), b"next");
        assert!(s.next_line().is_none());
    }

    #[test]
    fn oversized_terminated_line_in_one_chunk() {
        let mut s = LineSplitter::new();
        let mut line = vec![b'a'; MAX_LINE_BYTES + 1];
        line.extend_from_slice(b"\nok\n");
        s.push(&line);
        assert!(matches!(s.next_line().unwrap(), Err(LineError::TooLong { .. })));
        assert_eq!(s.next_line().unwrap().unwrap().as_ref(), b"ok");
    }

    #[test]
    fn finish_while_discarding_reports_drop_without_phantom_line() {
        let mut s = LineSplitter::new();
        s.push(&vec![b'a'; MAX_LINE_BYTES + 1]);
        assert!(s.next_line().is_none()); // over cap, now discarding
        s.push(b"tail"); // still the same line, no newline yet; left undrained on purpose
        assert_eq!(s.finish(), Some(Err(LineError::TooLong { dropped_bytes: MAX_LINE_BYTES + 1 + 4 })));
        assert!(s.finish().is_none()); // no phantom line, nothing left to report
        // The splitter is clean afterwards: a new line is delivered normally.
        s.push(b"ok\n");
        assert_eq!(s.next_line().unwrap().unwrap().as_ref(), b"ok");
        assert!(s.finish().is_none());
    }

    #[test]
    fn finish_after_too_long_error_is_clean() {
        // `TooLong` already returned (newline arrived), nothing buffered after it.
        let mut s = LineSplitter::new();
        let mut line = vec![b'a'; MAX_LINE_BYTES + 1];
        line.extend_from_slice(b"\n");
        s.push(&line);
        assert!(matches!(s.next_line().unwrap(), Err(LineError::TooLong { .. })));
        assert!(s.next_line().is_none());
        assert!(s.finish().is_none());
    }

    #[test]
    fn finish_returns_trailing_partial() {
        let mut s = LineSplitter::new();
        s.push(b"a\nb");
        assert_eq!(s.next_line().unwrap().unwrap().as_ref(), b"a");
        assert!(s.next_line().is_none());
        assert_eq!(s.finish().unwrap().unwrap().as_ref(), b"b");
        assert!(s.finish().is_none());
    }

    #[test]
    fn a_custom_cap_applies_everywhere() {
        let mut s = LineSplitter::with_cap(4);
        s.push(b"abcd\nabcde\nok\n");
        assert_eq!(drain(&mut s), vec![Ok(b"abcd".to_vec()), Err(LineError::TooLong { dropped_bytes: 5 }), Ok(b"ok".to_vec())]);
        s.push(b"123456");
        assert!(s.next_line().is_none(), "over the cap while unterminated: discarding");
        s.push(b"7\nz");
        assert_eq!(s.next_line(), Some(Err(LineError::TooLong { dropped_bytes: 7 })));
        assert_eq!(s.finish(), Some(Ok(Bytes::from_static(b"z"))));
        let mut big = LineSplitter::with_cap(CLI_LINE_BYTES);
        let line = vec![b'x'; MAX_LINE_BYTES + 1];
        big.push(&line);
        big.push(b"\n");
        assert_eq!(big.next_line().unwrap().unwrap().len(), MAX_LINE_BYTES + 1, "a 4 MiB+1 line passes the CLI cap");
    }

    #[test]
    fn encode_line_appends_newline() {
        assert_eq!(encode_line(b"abc").as_ref(), b"abc\n");
    }
}
