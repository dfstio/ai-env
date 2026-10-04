//! Raw stdio bytes ⇄ wire v1 [`Chunk`]s (plan S6 D2). Pure: the shim's
//! stdout/stderr readers and the Mac's stdin reader push whatever a read
//! returned; every chunk is at most [`CHUNK_MAX`] raw bytes, `text` when it is
//! valid UTF-8 and `b64` otherwise. A UTF-8 sequence cut by a read boundary
//! (at most 3 trailing bytes that can still become a character) is held for
//! the next push, so text stays text across reads; at EOF ([`Chunker::finish`])
//! a held tail goes out as `b64`. Nothing is ever appended or dropped:
//! concat(decode(chunks)) = the input, for any bytes and any read sizes.
use crate::wire::frame::{Chunk, WireError, CHUNK_MAX};
use base64::Engine;

/// Splits a byte stream into chunks.
#[derive(Debug, Default)]
pub struct Chunker {
    /// The incomplete UTF-8 sequence held from the previous push (≤ 3 bytes).
    tail: Vec<u8>,
}

impl Chunker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes held for the next push (an incomplete UTF-8 sequence).
    #[must_use]
    pub fn held(&self) -> usize {
        self.tail.len()
    }

    /// Chunk `bytes` (any length, including 0), after the held tail.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Chunk> {
        let mut out = Vec::new();
        let mut rest = bytes;
        loop {
            let room = CHUNK_MAX - self.tail.len();
            let take = rest.len().min(room);
            let mut piece = std::mem::take(&mut self.tail);
            piece.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if piece.is_empty() {
                break;
            }
            let (chunk, held) = encode_piece(piece);
            self.tail = held;
            if let Some(c) = chunk {
                out.push(c);
            }
            if rest.is_empty() {
                break;
            }
        }
        out
    }

    /// At EOF: the held tail, if any, as `b64`.
    pub fn finish(&mut self) -> Option<Chunk> {
        if self.tail.is_empty() {
            return None;
        }
        Some(b64_chunk(&std::mem::take(&mut self.tail)))
    }
}

fn b64_chunk(bytes: &[u8]) -> Chunk {
    Chunk { text: None, b64: Some(base64::engine::general_purpose::STANDARD.encode(bytes)) }
}

/// One piece (≤ CHUNK_MAX) → its chunk and the bytes to hold: a valid piece
/// is text; a valid prefix followed by an unfinished sequence (≤ 3 bytes) is
/// text plus the held tail (the next piece, or the next push, completes it);
/// anything else is b64.
fn encode_piece(piece: Vec<u8>) -> (Option<Chunk>, Vec<u8>) {
    let (valid, error_len) = match std::str::from_utf8(&piece) {
        Ok(_) => return (Some(Chunk { text: Some(String::from_utf8(piece).expect("checked above")), b64: None }), Vec::new()),
        Err(e) => (e.valid_up_to(), e.error_len()),
    };
    // `error_len() == None`: the input ended inside a sequence that may still complete.
    if error_len.is_some() || piece.len() - valid > 3 {
        return (Some(b64_chunk(&piece)), Vec::new());
    }
    let held = piece[valid..].to_vec();
    if valid == 0 {
        return (None, held);
    }
    let mut head = piece;
    head.truncate(valid);
    (Some(Chunk { text: Some(String::from_utf8(head).expect("valid prefix")), b64: None }), held)
}

/// The raw bytes of one chunk: exactly one of `text`/`b64`, at most
/// [`CHUNK_MAX`] bytes decoded.
pub fn decode(chunk: &Chunk) -> Result<Vec<u8>, WireError> {
    let bytes = match (&chunk.text, &chunk.b64) {
        (Some(t), None) => t.as_bytes().to_vec(),
        (None, Some(b)) => {
            // A base64 text of more than 4/3 × CHUNK_MAX (+ padding) cannot decode to ≤ CHUNK_MAX.
            if b.len() > CHUNK_MAX.div_ceil(3) * 4 {
                return Err(WireError::BadChunk("larger than 64 KiB"));
            }
            base64::engine::general_purpose::STANDARD.decode(b).map_err(|_| WireError::BadChunk("b64 is not standard base64"))?
        }
        (Some(_), Some(_)) => return Err(WireError::BadChunk("both text and b64")),
        (None, None) => return Err(WireError::BadChunk("neither text nor b64")),
    };
    if bytes.len() > CHUNK_MAX {
        return Err(WireError::BadChunk("larger than 64 KiB"));
    }
    Ok(bytes)
}

/// The decoded length of a chunk without decoding it (for windows); `None` when malformed.
#[must_use]
pub fn raw_len(chunk: &Chunk) -> Option<usize> {
    match (&chunk.text, &chunk.b64) {
        (Some(t), None) => Some(t.len()),
        (None, Some(b)) => {
            let pad = b.bytes().rev().take_while(|c| *c == b'=').count().min(2);
            (b.len() % 4 == 0).then(|| b.len() / 4 * 3 - pad)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn all(chunker: &mut Chunker, reads: &[&[u8]]) -> Vec<Chunk> {
        let mut out = Vec::new();
        for r in reads {
            out.extend(chunker.push(r));
        }
        out.extend(chunker.finish());
        out
    }

    fn join(chunks: &[Chunk]) -> Vec<u8> {
        chunks.iter().flat_map(|c| decode(c).unwrap()).collect()
    }

    #[test]
    fn text_stays_text_and_nothing_is_appended() {
        let mut c = Chunker::new();
        let chunks = all(&mut c, &[b"hello\n", b"", b"world"]);
        assert_eq!(chunks, vec![Chunk { text: Some("hello\n".into()), b64: None }, Chunk { text: Some("world".into()), b64: None }]);
        assert_eq!(join(&chunks), b"hello\nworld");
    }

    #[test]
    fn a_character_cut_by_a_read_is_held_then_joined() {
        let euro = "€".as_bytes(); // 3 bytes
        let mut c = Chunker::new();
        let first = c.push(&[b'a', euro[0], euro[1]]);
        assert_eq!(first, vec![Chunk { text: Some("a".into()), b64: None }]);
        assert_eq!(c.held(), 2);
        let second = c.push(&[euro[2], b'b']);
        assert_eq!(second, vec![Chunk { text: Some("€b".into()), b64: None }]);
        assert_eq!(c.finish(), None);
    }

    #[test]
    fn invalid_bytes_go_b64_and_a_held_tail_at_eof_too() {
        let mut c = Chunker::new();
        let chunks = all(&mut c, &[&[0xff, 0x00, b'x']]);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].b64.is_some());
        assert_eq!(join(&chunks), vec![0xff, 0x00, b'x']);
        let mut c = Chunker::new();
        let chunks = all(&mut c, &[&[b'o', b'k', 0xe2, 0x82]]);
        assert_eq!(chunks[0].text.as_deref(), Some("ok"));
        assert_eq!(chunks[1].b64.as_deref(), Some("4oI="), "the unfinished tail at EOF: b64");
        assert_eq!(join(&chunks), vec![b'o', b'k', 0xe2, 0x82]);
    }

    #[test]
    fn large_reads_split_at_chunk_max() {
        let data = vec![b'a'; CHUNK_MAX * 2 + 5];
        let mut c = Chunker::new();
        let chunks = all(&mut c, &[&data]);
        assert_eq!(chunks.iter().map(|c| decode(c).unwrap().len()).collect::<Vec<_>>(), vec![CHUNK_MAX, CHUNK_MAX, 5]);
        assert_eq!(join(&chunks), data);
    }

    #[test]
    fn decode_refuses_malformed_chunks() {
        assert!(matches!(decode(&Chunk::default()), Err(WireError::BadChunk(_))));
        assert!(matches!(decode(&Chunk { text: Some("a".into()), b64: Some("YQ==".into()) }), Err(WireError::BadChunk(_))));
        assert!(matches!(decode(&Chunk { text: None, b64: Some("!!".into()) }), Err(WireError::BadChunk(_))));
        assert!(matches!(decode(&Chunk { text: Some("a".repeat(CHUNK_MAX + 1)), b64: None }), Err(WireError::BadChunk(_))));
        let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; CHUNK_MAX + 1]);
        assert!(matches!(decode(&Chunk { text: None, b64: Some(big) }), Err(WireError::BadChunk(_))));
        let max = base64::engine::general_purpose::STANDARD.encode(vec![0u8; CHUNK_MAX]);
        assert_eq!(decode(&Chunk { text: None, b64: Some(max) }).unwrap().len(), CHUNK_MAX);
    }

    #[test]
    fn raw_len_matches_decode() {
        for bytes in [vec![], vec![1u8], vec![1, 2], vec![1, 2, 3], vec![0xff; 100]] {
            let c = b64_chunk(&bytes);
            assert_eq!(raw_len(&c), Some(bytes.len()));
        }
        assert_eq!(raw_len(&Chunk { text: Some("héllo".into()), b64: None }), Some(6));
        assert_eq!(raw_len(&Chunk::default()), None);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// concat(decode(chunks)) = input for any bytes split at any points;
        /// every chunk is non-empty, at most CHUNK_MAX bytes, and text unless
        /// it holds invalid UTF-8 (or a final unfinished sequence).
        #[test]
        fn chunks_join_to_the_input(data in proptest::collection::vec(any::<u8>(), 0..300_000), cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..12)) {
            let mut points: Vec<usize> = cuts.iter().map(|i| i.index(data.len() + 1)).collect();
            points.sort_unstable();
            let mut reads: Vec<&[u8]> = Vec::new();
            let mut at = 0;
            for p in points {
                reads.push(&data[at..p]);
                at = p;
            }
            reads.push(&data[at..]);
            let mut c = Chunker::new();
            let chunks = all(&mut c, &reads);
            for ch in &chunks {
                let raw = decode(ch).unwrap();
                prop_assert!(!raw.is_empty() && raw.len() <= CHUNK_MAX);
                prop_assert_eq!(raw_len(ch), Some(raw.len()));
            }
            prop_assert_eq!(join(&chunks), data);
        }

        /// Valid UTF-8 text never becomes b64, however it is cut.
        #[test]
        fn utf8_text_stays_text(s in "\\PC{0,4000}", cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..8)) {
            let data = s.as_bytes();
            let mut points: Vec<usize> = cuts.iter().map(|i| i.index(data.len() + 1)).collect();
            points.sort_unstable();
            let mut c = Chunker::new();
            let mut chunks = Vec::new();
            let mut at = 0;
            for p in points {
                chunks.extend(c.push(&data[at..p]));
                at = p;
            }
            chunks.extend(c.push(&data[at..]));
            chunks.extend(c.finish());
            prop_assert!(chunks.iter().all(|ch| ch.text.is_some()), "{:?}", chunks);
            prop_assert_eq!(join(&chunks), data.to_vec());
        }
    }
}
