//! Incremental NDJSON line splitter with a hard per-line cap. Pure (no I/O):
//! the async pumps feed it chunks and drain complete lines. `\r` is kept so
//! forwarded lines stay byte-identical.
use bytes::{Buf, Bytes, BytesMut};

/// Longest line accepted (Claude frames are far smaller; this bounds memory).
pub const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineError {
    /// A line exceeded [`MAX_LINE_BYTES`]; `dropped_bytes` were discarded up
    /// to (not including) the next newline, and splitting resumes after it.
    TooLong { dropped_bytes: usize },
}

#[derive(Debug, Default)]
pub struct LineSplitter {
    buf: BytesMut,
    discarding: bool,
    dropped: usize,
}

impl LineSplitter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: &[u8]) {
        if self.discarding {
            self.buf.extend_from_slice(chunk);
            return;
        }
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
            Some(i) if i > MAX_LINE_BYTES => {
                self.buf.advance(i + 1);
                Some(Err(LineError::TooLong { dropped_bytes: i }))
            }
            Some(i) => {
                let line = self.buf.split_to(i).freeze();
                self.buf.advance(1);
                Some(Ok(line))
            }
            None => {
                if self.buf.len() > MAX_LINE_BYTES {
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
        if self.buf.len() > MAX_LINE_BYTES {
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
    fn finish_returns_trailing_partial() {
        let mut s = LineSplitter::new();
        s.push(b"a\nb");
        assert_eq!(s.next_line().unwrap().unwrap().as_ref(), b"a");
        assert!(s.next_line().is_none());
        assert_eq!(s.finish().unwrap().unwrap().as_ref(), b"b");
        assert!(s.finish().is_none());
    }

    #[test]
    fn encode_line_appends_newline() {
        assert_eq!(encode_line(b"abc").as_ref(), b"abc\n");
    }
}
