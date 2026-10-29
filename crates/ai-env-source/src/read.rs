//! Reading under a cap (plans/s13-contracts.md §P-proto-sdk.6.6, P-R55 to P-R58).

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use futures_core::Stream;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt};

use crate::{SourceError, TextStream};

/// The longest line kept; a longer one is cut and ends with `LINE_CUT`.
pub const LINE_MAX: usize = 65_536;
/// What a cut line ends with.
pub const LINE_CUT: &str = " …[cut]";

/// How much `read_capped` asks its reader for at once (it never allocates its cap ahead).
const READ_STEP: usize = 8192;

/// A value read under a cap, and whether anything was left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capped<T> {
    /// What was kept.
    pub value: T,
    /// Whether anything was left unread or cut.
    pub truncated: bool,
}

fn read_error(e: impl fmt::Display) -> SourceError {
    SourceError::Unavailable(format!("read: {e}"))
}

/// Reads until EOF or `max_bytes`, then probes one more byte, which is discarded: `truncated` is whether it
/// existed (P-R55). It never reads further and never allocates `max_bytes` ahead; an I/O error is
/// `Unavailable("read: <error>")`.
pub async fn read_capped<R: AsyncRead + Unpin>(mut reader: R, max_bytes: u64) -> Result<Capped<Vec<u8>>, SourceError> {
    let max = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let mut value = Vec::new();
    let mut step = [0u8; READ_STEP];
    while value.len() < max {
        let want = (max - value.len()).min(READ_STEP);
        match reader.read(&mut step[..want]).await {
            Ok(0) => return Ok(Capped { value, truncated: false }),
            Ok(n) => value.extend_from_slice(&step[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(read_error(e)),
        }
    }
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe).await {
            Ok(n) => return Ok(Capped { value, truncated: n > 0 }),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(read_error(e)),
        }
    }
}

/// Appends items' bytes until the next would pass `max_bytes`; it keeps that item's first bytes up to the
/// cap, sets `truncated` and stops polling (P-R56). An item error is `Unavailable("read: <error>")`.
pub async fn collect_capped<S, B, E>(mut stream: S, max_bytes: u64) -> Result<Capped<Vec<u8>>, SourceError>
where
    S: Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
    E: fmt::Display,
{
    let max = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let mut value = Vec::new();
    while let Some(item) = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await {
        let item = item.map_err(read_error)?;
        let bytes = item.as_ref();
        let room = max - value.len();
        if bytes.len() > room {
            value.extend_from_slice(&bytes[..room]);
            return Ok(Capped { value, truncated: true });
        }
        value.extend_from_slice(bytes);
    }
    Ok(Capped { value, truncated: false })
}

/// Lines under a line and a byte cap (P-R57): split at `\n`, one trailing `\r` dropped, invalid UTF-8 as
/// U+FFFD. A line over `LINE_MAX` bytes keeps its first `LINE_MAX` and ends with `LINE_CUT` (the rest is
/// read and dropped; the result is truncated). A line costs its kept length plus 1; reading stops before a
/// line that would pass either cap, truncated when any byte was left.
pub async fn lines_capped<R: AsyncBufRead + Unpin>(mut reader: R, max_lines: u32, max_bytes: u64) -> Result<Capped<Vec<String>>, SourceError> {
    let mut value = Vec::new();
    let mut used: u64 = 0;
    let mut truncated = false;
    let mut line = LineBuf::default();
    loop {
        if value.len() >= usize::try_from(max_lines).unwrap_or(usize::MAX) {
            truncated |= !reader.fill_buf().await.map_err(read_error)?.is_empty();
            break;
        }
        let Some(next) = std::future::poll_fn(|cx| line.poll_line(&mut reader, cx)).await.map_err(read_error)? else {
            break;
        };
        let cost = u64::try_from(next.text.len()).unwrap_or(u64::MAX).saturating_add(1);
        if used.saturating_add(cost) > max_bytes {
            truncated = true;
            break;
        }
        used += cost;
        truncated |= next.cut;
        value.push(next.text);
    }
    Ok(Capped { value, truncated })
}

/// The same lines as `lines_capped`, read only as the stream is polled, as a `TextStream::lines` (P-R58);
/// an I/O error is yielded once as `Err(Unavailable("read: <error>"))` and ends the stream.
pub fn text_lines<R: AsyncBufRead + Send + Unpin + 'static>(reader: R) -> TextStream {
    TextStream::lines(Lines { reader, line: LineBuf::default(), done: false })
}

/// One line read whole: its text (U+FFFD for invalid UTF-8, `LINE_CUT` at a cut) and whether it was cut.
struct Line {
    text: String,
    cut: bool,
}

/// A line in the making (P-R57): at most `LINE_MAX` bytes kept, whether more were dropped, and a `\r` held
/// back until the next byte says whether it ends the line.
#[derive(Default)]
struct LineBuf {
    kept: Vec<u8>,
    cut: bool,
    cr: bool,
    started: bool,
}

impl LineBuf {
    /// Reads through `fill_buf` and `consume` up to the end of one line: `None` at EOF before any byte.
    fn poll_line<R: AsyncBufRead + Unpin>(&mut self, reader: &mut R, cx: &mut Context<'_>) -> Poll<io::Result<Option<Line>>> {
        loop {
            let buf = ready!(Pin::new(&mut *reader).poll_fill_buf(cx))?;
            if buf.is_empty() {
                // EOF: a final line without `\n` counts; a trailing `\n` started no line.
                return Poll::Ready(Ok(std::mem::take(&mut self.started).then(|| self.take())));
            }
            self.started = true;
            let (content, used, ends) = match buf.iter().position(|&b| b == b'\n') {
                Some(i) => (&buf[..i], i + 1, true),
                None => (buf, buf.len(), false),
            };
            self.push(content);
            Pin::new(&mut *reader).consume(used);
            if ends {
                self.started = false;
                return Poll::Ready(Ok(Some(self.take())));
            }
        }
    }

    /// Appends one run of a line's bytes; a `\r` at the run's end is held back.
    fn push(&mut self, content: &[u8]) {
        if content.is_empty() {
            return;
        }
        if std::mem::take(&mut self.cr) {
            self.keep(b"\r");
        }
        let (body, cr) = match content.split_last() {
            Some((b'\r', body)) => (body, true),
            _ => (content, false),
        };
        self.keep(body);
        self.cr = cr;
    }

    fn keep(&mut self, bytes: &[u8]) {
        let room = LINE_MAX - self.kept.len();
        if bytes.len() > room {
            self.kept.extend_from_slice(&bytes[..room]);
            self.cut = true;
        } else {
            self.kept.extend_from_slice(bytes);
        }
    }

    /// The line so far, and a fresh state (a held `\r` is the one trailing `\r` dropped).
    fn take(&mut self) -> Line {
        let kept = std::mem::take(&mut self.kept);
        let cut = std::mem::take(&mut self.cut);
        self.cr = false;
        let mut text = match String::from_utf8(kept) {
            Ok(text) => text,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        };
        if cut {
            text.push_str(LINE_CUT);
        }
        Line { text, cut }
    }
}

/// `text_lines`' stream.
struct Lines<R> {
    reader: R,
    line: LineBuf,
    done: bool,
}

impl<R: AsyncBufRead + Unpin> Stream for Lines<R> {
    type Item = Result<String, SourceError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match ready!(this.line.poll_line(&mut this.reader, cx)) {
            Ok(Some(line)) => Poll::Ready(Some(Ok(line.text))),
            Ok(None) => {
                this.done = true;
                Poll::Ready(None)
            }
            Err(e) => {
                this.done = true;
                Poll::Ready(Some(Err(read_error(e))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{BufReader, ReadBuf};

    async fn next<S: Stream + Unpin>(s: &mut S) -> Option<S::Item> {
        std::future::poll_fn(|cx| Pin::new(&mut *s).poll_next(cx)).await
    }

    fn broken() -> io::Error {
        io::Error::other("the pipe broke")
    }

    /// A reader of `len` bytes that panics when asked for more once it gave `limit` bytes.
    struct Tripwire {
        len: usize,
        limit: usize,
        given: usize,
    }

    impl AsyncRead for Tripwire {
        fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            assert!(self.given < self.limit, "read past {} bytes", self.limit);
            let n = buf.remaining().min(self.len - self.given).min(self.limit - self.given);
            buf.put_slice(&vec![b'x'; n]);
            self.given += n;
            Poll::Ready(Ok(()))
        }
    }

    /// A reader that fails at once.
    struct Failing;

    impl AsyncRead for Failing {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(broken()))
        }
    }

    /// A buffered reader handing out one chunk per `fill_buf`, counting them, then an error if `fails`.
    struct Chunks {
        chunks: Vec<Vec<u8>>,
        at: usize,
        offset: usize,
        reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        fails: bool,
    }

    impl Chunks {
        fn new(chunks: &[&str], fails: bool) -> Self {
            let chunks = chunks.iter().map(|c| c.as_bytes().to_vec()).collect();
            Chunks { chunks, at: 0, offset: 0, reads: Default::default(), fails }
        }
    }

    impl AsyncRead for Chunks {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            unreachable!("read through fill_buf and consume only")
        }
    }

    impl AsyncBufRead for Chunks {
        fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let this = self.get_mut();
            if this.offset == 0 {
                this.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            match this.chunks.get(this.at) {
                Some(chunk) => Poll::Ready(Ok(&chunk[this.offset..])),
                None if this.fails => Poll::Ready(Err(broken())),
                None => Poll::Ready(Ok(&[])),
            }
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            let this = self.get_mut();
            this.offset += amt;
            if this.chunks.get(this.at).is_some_and(|c| this.offset >= c.len()) {
                this.at += 1;
                this.offset = 0;
            }
        }
    }

    /// P-T23.
    #[tokio::test]
    async fn read_capped_reads_to_the_cap_and_flags_more() {
        for (len, kept, truncated) in [(0, 0, false), (1023, 1023, false), (1024, 1024, false), (1025, 1024, true), (10_240, 1024, true)] {
            let input = vec![b'x'; len];
            let got = read_capped(input.as_slice(), 1024).await.expect("reads");
            assert_eq!((got.value.len(), got.truncated), (kept, truncated), "{len} bytes");
        }
        assert_eq!(read_capped(&b"x"[..], 0).await, Ok(Capped { value: Vec::new(), truncated: true }));
        assert_eq!(read_capped(&b""[..], 0).await, Ok(Capped { value: Vec::new(), truncated: false }));
        // The cap is never allocated ahead: a cap of u64::MAX reads three bytes as three bytes.
        assert_eq!(read_capped(&b"abc"[..], u64::MAX).await, Ok(Capped { value: b"abc".to_vec(), truncated: false }));
        // It reads the probe byte and stops there: no drain to EOF.
        let got = read_capped(Tripwire { len: 10_240, limit: 1025, given: 0 }, 1024).await.expect("reads");
        assert_eq!((got.value.len(), got.truncated), (1024, true));
        let got = read_capped(Tripwire { len: 100_000, limit: 50_001, given: 0 }, 50_000).await.expect("reads");
        assert_eq!((got.value.len(), got.truncated), (50_000, true));
        let e = read_capped(Failing, 1024).await.expect_err("fails");
        assert_eq!(e, SourceError::Unavailable("read: the pipe broke".into()));
    }

    /// P-T24.
    #[tokio::test]
    async fn collect_capped_cuts_inside_a_chunk() {
        let mut polled = 0;
        let chunks = std::iter::from_fn(move || {
            polled += 1;
            assert!(polled <= 2, "the third chunk is never polled");
            Some(Ok::<_, io::Error>(vec![polled; 600]))
        });
        let got = collect_capped(crate::stream_iter(chunks), 1000).await.expect("collects");
        assert_eq!(got.value.len(), 1000);
        assert!(got.truncated);
        assert_eq!((&got.value[..600], &got.value[600..]), (&[1u8; 600][..], &[2u8; 400][..]));

        let whole = collect_capped(crate::stream_iter(vec![Ok::<_, io::Error>(vec![1u8; 500]), Ok(vec![2u8; 500])]), 1000).await;
        assert_eq!(whole.map(|c| (c.value.len(), c.truncated)), Ok((1000, false)));
        let failing = collect_capped(crate::stream_iter(vec![Ok(vec![1u8; 10]), Err(broken())]), 1000).await;
        assert_eq!(failing, Err(SourceError::Unavailable("read: the pipe broke".into())));
    }

    /// P-T25.
    #[tokio::test]
    async fn lines_capped_counts_lines_bytes_and_cuts_long_lines() {
        async fn lines(input: &[u8], max_lines: u32, max_bytes: u64) -> (Vec<String>, bool) {
            let got = lines_capped(BufReader::new(input), max_lines, max_bytes).await.expect("reads");
            (got.value, got.truncated)
        }
        let s = |v: &[&str]| v.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(lines(b"a\r\nb\n", 10, 1000).await, (s(&["a", "b"]), false));
        assert_eq!(lines(b"a\n\n", 10, 1000).await, (s(&["a", ""]), false));
        assert_eq!(lines(b"a", 10, 1000).await, (s(&["a"]), false));
        assert_eq!(lines(b"", 10, 1000).await, (s(&[]), false));
        assert_eq!(lines(b"a\r\r\nb\r", 10, 1000).await, (s(&["a\r", "b"]), false));
        assert_eq!(lines(b"a\xffb\n", 10, 1000).await, (s(&["a\u{fffd}b"]), false));
        assert_eq!(lines(b"aaaa\nbbbb\n", 10, 9).await, (s(&["aaaa"]), true));
        assert_eq!(lines(b"aaaa\nbbbb\n", 10, 10).await, (s(&["aaaa", "bbbb"]), false));
        assert_eq!(lines(b"a\nb\nc\n", 2, 1000).await, (s(&["a", "b"]), true));
        assert_eq!(lines(b"a\nb\n", 2, 1000).await, (s(&["a", "b"]), false));
        assert_eq!(lines(b"a\nb\n", 0, 1000).await, (s(&[]), true));

        let mut long = vec![b'y'; 100 * 1024];
        long.extend_from_slice(b"\nnext\n");
        let (got, truncated) = lines(&long, 10, 1 << 20).await;
        assert!(truncated);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], format!("{}{LINE_CUT}", "y".repeat(LINE_MAX)));
        assert_eq!(got[1], "next", "the line after a cut one is read in place");
        // A line of exactly LINE_MAX bytes and its `\r` is not cut; a character cut at LINE_MAX is U+FFFD.
        let mut exact = vec![b'z'; LINE_MAX];
        exact.extend_from_slice(b"\r\n");
        assert_eq!(lines(&exact, 10, 1 << 20).await, (vec!["z".repeat(LINE_MAX)], false));
        let mut split = vec![b'z'; LINE_MAX - 1];
        split.extend_from_slice("\u{e9}\u{e9}\n".as_bytes());
        let (got, truncated) = lines(&split, 10, 1 << 20).await;
        assert!(truncated);
        assert_eq!(got, vec![format!("{}\u{fffd}{LINE_CUT}", "z".repeat(LINE_MAX - 1))]);
        let e = lines_capped(BufReader::new(Failing), 10, 1000).await.expect_err("fails");
        assert_eq!(e, SourceError::Unavailable("read: the pipe broke".into()));
    }

    /// P-T26.
    #[tokio::test]
    async fn text_lines_streams_lazily_and_ends_on_an_error() {
        let reader = Chunks::new(&["first\n", "sec", "ond\r\n", "third"], false);
        let reads = std::sync::Arc::clone(&reader.reads);
        let mut stream = text_lines(reader);
        assert_eq!(stream.content_type(), crate::ContentType::Text);
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing read before the first poll");
        assert_eq!(next(&mut stream).await, Some(Ok("first".to_string())));
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1, "one poll reads what the first line needs");
        assert_eq!(next(&mut stream).await, Some(Ok("second".to_string())));
        assert_eq!(next(&mut stream).await, Some(Ok("third".to_string())));
        assert_eq!(next(&mut stream).await, None);
        assert_eq!(next(&mut stream).await, None);

        let mut stream = text_lines(Chunks::new(&["a\n", "b\n"], true));
        assert_eq!(next(&mut stream).await, Some(Ok("a".to_string())));
        assert_eq!(next(&mut stream).await, Some(Ok("b".to_string())));
        assert_eq!(next(&mut stream).await, Some(Err(SourceError::Unavailable("read: the pipe broke".into()))));
        assert_eq!(next(&mut stream).await, None);

        let mut long = vec![b'y'; LINE_MAX + 10];
        long.extend_from_slice(b"\nz");
        let mut stream = text_lines(BufReader::new(std::io::Cursor::new(long)));
        assert_eq!(next(&mut stream).await, Some(Ok(format!("{}{LINE_CUT}", "y".repeat(LINE_MAX)))));
        assert_eq!(next(&mut stream).await, Some(Ok("z".to_string())));
        assert_eq!(next(&mut stream).await, None);
    }
}
