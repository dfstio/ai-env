//! Outputs (plans/s13-contracts.md §P-proto-sdk.6.5, P-R50 to P-R53).

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;
use serde::Serialize;

use crate::{Cursor, OutputKind, SourceError};

/// The content type of an output's chunks (P-R18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ContentType {
    /// `application/json`.
    Json,
    /// `application/x-ndjson`.
    Ndjson,
    /// `text/plain; charset=utf-8`.
    Text,
}

impl ContentType {
    /// The MIME text: `application/json`, `application/x-ndjson`, `text/plain; charset=utf-8`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ContentType::Json => "application/json",
            ContentType::Ndjson => "application/x-ndjson",
            ContentType::Text => "text/plain; charset=utf-8",
        }
    }
}

/// A stream of text items (P-R51): lines, or NDJSON records, each without its newline.
pub struct TextStream {
    content_type: ContentType,
    items: Pin<Box<dyn Stream<Item = Result<String, SourceError>> + Send>>,
}

impl TextStream {
    /// A stream of lines (`text/plain`).
    #[must_use]
    pub fn lines<S>(items: S) -> Self
    where
        S: Stream<Item = Result<String, SourceError>> + Send + 'static,
    {
        TextStream { content_type: ContentType::Text, items: Box::pin(items) }
    }

    /// A stream of NDJSON records, each one JSON value on one line (`application/x-ndjson`).
    #[must_use]
    pub fn ndjson<S>(items: S) -> Self
    where
        S: Stream<Item = Result<String, SourceError>> + Send + 'static,
    {
        TextStream { content_type: ContentType::Ndjson, items: Box::pin(items) }
    }

    /// `Text` or `Ndjson`, never `Json`.
    #[must_use]
    pub fn content_type(&self) -> ContentType {
        self.content_type
    }
}

impl Stream for TextStream {
    type Item = Result<String, SourceError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.items.as_mut().poll_next(cx)
    }
}

impl fmt::Debug for TextStream {
    /// Its content type only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TextStream").field("content_type", &self.content_type).finish_non_exhaustive()
    }
}

/// An iterator as a stream: it yields each item on poll.
#[derive(Debug)]
pub struct IterStream<I>(I);

/// `items` as a stream.
#[must_use]
pub fn stream_iter<I: IntoIterator>(items: I) -> IterStream<I::IntoIter> {
    IterStream(items.into_iter())
}

impl<I: Iterator + Unpin> Stream for IterStream<I> {
    type Item = I::Item;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.next())
    }
}

/// An output's body.
#[derive(Debug)]
#[non_exhaustive]
pub enum Body {
    /// One JSON value.
    Json(serde_json::Value),
    /// One text.
    Text(String),
    /// A stream of text items.
    Stream(TextStream),
}

/// What a call returns: a body, and whether the source cut it (LD-P3).
#[derive(Debug)]
pub struct Output {
    body: Body,
    truncated: bool,
}

impl Output {
    /// A JSON output.
    #[must_use]
    pub fn json(value: serde_json::Value) -> Self {
        Output { body: Body::Json(value), truncated: false }
    }

    /// `value` serialized with serde_json; a failure is `Internal("output: <serde's text>")` (P-R50).
    pub fn json_of<T: Serialize>(value: &T) -> Result<Self, SourceError> {
        serde_json::to_value(value).map(Output::json).map_err(|e| SourceError::Internal(format!("output: {e}")))
    }

    /// A text output.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Output { body: Body::Text(text.into()), truncated: false }
    }

    /// A stream output.
    #[must_use]
    pub fn stream(stream: TextStream) -> Self {
        Output { body: Body::Stream(stream), truncated: false }
    }

    /// The same output, saying whether the source cut it (P-R52).
    #[must_use]
    pub fn with_truncated(mut self, yes: bool) -> Self {
        self.truncated = yes;
        self
    }

    /// Whether the source cut it.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The body's kind (P-R50).
    #[must_use]
    pub fn kind(&self) -> OutputKind {
        match self.body {
            Body::Json(_) => OutputKind::Json,
            Body::Text(_) => OutputKind::Text,
            Body::Stream(_) => OutputKind::Stream,
        }
    }

    /// The body's content type (P-R50): a stream's own, never `Json`.
    #[must_use]
    pub fn content_type(&self) -> ContentType {
        match &self.body {
            Body::Json(_) => ContentType::Json,
            Body::Text(_) => ContentType::Text,
            Body::Stream(s) => s.content_type(),
        }
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// The body and the truncation flag.
    #[must_use]
    pub fn into_parts(self) -> (Body, bool) {
        (self.body, self.truncated)
    }
}

/// One page of items and how to get the next (P-R53).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Page<T> {
    /// The items.
    pub items: Vec<T>,
    /// The next page's cursor, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    /// Whether more items exist than this page holds.
    pub truncated: bool,
}

impl<T> Page<T> {
    /// A page with no cursor, not truncated.
    #[must_use]
    pub fn new(items: Vec<T>) -> Self {
        Page { items, next_cursor: None, truncated: false }
    }

    /// The same page with its cursor set; `Some` also sets `truncated`, `None` clears both.
    #[must_use]
    pub fn with_next(mut self, cursor: Option<Cursor>) -> Self {
        self.truncated = cursor.is_some();
        self.next_cursor = cursor;
        self
    }
}

impl<T: Serialize> Page<T> {
    /// `Output::json_of(&page)` with `with_truncated(page.truncated)`.
    pub fn into_output(self) -> Result<Output, SourceError> {
        Output::json_of(&self).map(|o| o.with_truncated(self.truncated))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn next<S: Stream + Unpin>(s: &mut S) -> Option<S::Item> {
        std::future::poll_fn(|cx| Pin::new(&mut *s).poll_next(cx)).await
    }

    /// P-T21.
    #[test]
    fn page_serializes_with_its_cursor_and_truncation() {
        let page = Page::new(vec![1, 2]);
        assert_eq!(serde_json::to_string(&page).expect("serializes"), r#"{"items":[1,2],"truncated":false}"#);
        let cursor = Cursor::encode("test-page", "list", &2).expect("encodes");
        let more = page.clone().with_next(Some(cursor.clone()));
        assert_eq!(
            serde_json::to_string(&more).expect("serializes"),
            format!(r#"{{"items":[1,2],"next_cursor":"{}","truncated":true}}"#, cursor.as_str())
        );
        let out = more.clone().into_output().expect("an output");
        assert!(out.is_truncated());
        assert!(matches!(out.body(), Body::Json(v) if v["next_cursor"] == json!(cursor.as_str())), "{out:?}");
        let cleared = more.with_next(None);
        assert_eq!(cleared, page);
        assert!(!cleared.into_output().expect("an output").is_truncated());
    }

    /// P-T22.
    #[tokio::test]
    async fn outputs_report_their_kind_content_type_and_truncation() {
        type Row = (fn() -> Output, OutputKind, ContentType);
        let rows: [Row; 4] = [
            (|| Output::json(json!({"a": 1})), OutputKind::Json, ContentType::Json),
            (|| Output::text("t"), OutputKind::Text, ContentType::Text),
            (|| Output::stream(TextStream::lines(stream_iter(vec![Ok("a".to_string())]))), OutputKind::Stream, ContentType::Text),
            (|| Output::stream(TextStream::ndjson(stream_iter(vec![Ok("{}".to_string())]))), OutputKind::Stream, ContentType::Ndjson),
        ];
        for (make, kind, content_type) in rows {
            let out = make();
            assert_eq!((out.kind(), out.content_type(), out.is_truncated()), (kind, content_type, false));
            let (body, truncated) = out.into_parts();
            assert!(!truncated);
            match (kind, body) {
                (OutputKind::Json, Body::Json(v)) => assert_eq!(v, json!({"a": 1})),
                (OutputKind::Text, Body::Text(t)) => assert_eq!(t, "t"),
                (OutputKind::Stream, Body::Stream(mut s)) => {
                    assert_eq!(s.content_type(), content_type);
                    assert!(next(&mut s).await.is_some_and(|item| item.is_ok()));
                    assert!(next(&mut s).await.is_none());
                }
                (kind, body) => panic!("{kind:?} answered {body:?}"),
            }
            let cut = make().with_truncated(true);
            assert!(cut.is_truncated());
            assert_eq!((cut.kind(), cut.content_type()), (kind, content_type));
            assert!(cut.into_parts().1);
        }

        let keyed_by_pairs: std::collections::BTreeMap<(u8, u8), u8> = [((1, 2), 3)].into_iter().collect();
        let e = Output::json_of(&keyed_by_pairs).expect_err("serde_json refuses a key that is not a string");
        assert!(matches!(&e, SourceError::Internal(m) if m.starts_with("output: ")), "{e}");
        assert!(matches!(Output::json_of(&[1, 2]).expect("an output").body(), Body::Json(v) if *v == json!([1, 2])));

        let mut s = stream_iter(1..4);
        assert_eq!((next(&mut s).await, next(&mut s).await, next(&mut s).await, next(&mut s).await), (Some(1), Some(2), Some(3), None));
        let shown = format!("{:?}", TextStream::ndjson(stream_iter(Vec::new())));
        assert!(shown.contains("Ndjson"), "{shown}");
    }
}
