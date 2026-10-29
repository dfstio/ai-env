//! `EchoSource`, the generic example source (P-R81), and the secret-shaped samples (P-R82).

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::redact::Rule;
use crate::{
    stream_iter, BoxFuture, CallContext, CallRequest, DataSource, OpDescriptor, Output, OutputKind, Redactor, Sensitivity, SourceDescriptor,
    SourceError, SourceKind, TextStream, VERSION,
};

/// The description `EchoSource` advertises (P-R81).
const DESCRIPTION: &str = "A generic example source: echoes text, streams numbered lines, sleeps, fails on request and prints secret-shaped samples.";
/// The longest `echo` text.
const TEXT_MAX: usize = 4096;
/// The most `lines` items, and the widest padding.
const COUNT_MAX: u64 = 100_000;
const WIDTH_MAX: u64 = 1024;
/// The longest `sleep`, the deadlines' ceiling.
const SLEEP_MAX: u64 = 600_000;
/// The longest `fail` message.
const MESSAGE_MAX: usize = 256;

/// A generic example source: echoes text, streams numbered lines, sleeps, fails on request and prints
/// secret-shaped samples (P-R81).
#[derive(Debug, Clone)]
pub struct EchoSource {
    name: String,
}

impl EchoSource {
    /// The source named `echo`.
    #[must_use]
    pub fn new() -> Self {
        EchoSource::named("echo")
    }

    /// The source under another name.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        EchoSource { name: name.into() }
    }
}

impl Default for EchoSource {
    /// `EchoSource::new()`.
    fn default() -> Self {
        EchoSource::new()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EchoParams {
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinesParams {
    count: u64,
    #[serde(default)]
    width: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SleepParams {
    ms: u64,
}

/// The nine codes a source answers (P-R30), by their google.rpc names.
#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FailCode {
    InvalidArgument,
    NotFound,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Unavailable,
    DeadlineExceeded,
    Cancelled,
    Internal,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailParams {
    code: FailCode,
    #[serde(default)]
    message: String,
}

/// The six shapes, by their rules' names.
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Shape {
    Ansi,
    Pem,
    Jwt,
    Bearer,
    Dsn,
    Hex64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SampleParams {
    shape: Shape,
}

fn too_big(what: &str) -> SourceError {
    SourceError::InvalidArgument(format!("params: {what}"))
}

/// One of `{i:08}` and, for a width, a space and that many `x`.
fn numbered(i: u64, width: u64) -> String {
    if width == 0 {
        format!("{i:08}")
    } else {
        format!("{i:08} {}", "x".repeat(usize::try_from(width).unwrap_or(0)))
    }
}

impl DataSource for EchoSource {
    fn descriptor(&self) -> SourceDescriptor {
        let op = |name: &str, description: &str, output: OutputKind, schema: serde_json::Value, example: serde_json::Value| {
            OpDescriptor::new(name, description).params_schema(schema).output(output).read_only(true).example(example)
        };
        SourceDescriptor::new(self.name.clone(), VERSION, DESCRIPTION)
            .kind(SourceKind::Other)
            .env("test")
            .sensitivity(Sensitivity::Public)
            .op(op(
                "echo",
                "Answers its text back as JSON.",
                OutputKind::Json,
                json!({"type": "object", "properties": {"text": {"type": "string", "maxLength": TEXT_MAX}}, "required": ["text"], "additionalProperties": false}),
                json!({"text": "hello"}),
            ))
            .op(op(
                "lines",
                "Streams count numbered lines, each padded with a space and width x characters when width is above 0.",
                OutputKind::Stream,
                json!({"type": "object", "properties": {
                    "count": {"type": "integer", "minimum": 0, "maximum": COUNT_MAX},
                    "width": {"type": "integer", "minimum": 0, "maximum": WIDTH_MAX, "default": 0},
                }, "required": ["count"], "additionalProperties": false}),
                json!({"count": 3}),
            ))
            .op(op(
                "sleep",
                "Waits ms milliseconds within the call's deadline, then answers how long it slept.",
                OutputKind::Json,
                json!({"type": "object", "properties": {"ms": {"type": "integer", "minimum": 0, "maximum": SLEEP_MAX}}, "required": ["ms"], "additionalProperties": false}),
                json!({"ms": 1}),
            ))
            .op(op(
                "fail",
                "Fails with the named error code and message.",
                OutputKind::Json,
                json!({"type": "object", "properties": {
                    "code": {"type": "string", "enum": [
                        "INVALID_ARGUMENT", "NOT_FOUND", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
                        "UNAVAILABLE", "DEADLINE_EXCEEDED", "CANCELLED", "INTERNAL",
                    ]},
                    "message": {"type": "string", "maxLength": MESSAGE_MAX, "default": ""},
                }, "required": ["code"], "additionalProperties": false}),
                json!({"code": "NOT_FOUND", "message": "nothing here"}),
            ))
            .op(op(
                "sample",
                "Prints one secret-shaped sample text, unmasked: the worker's redaction masks it.",
                OutputKind::Text,
                json!({"type": "object", "properties": {
                    "shape": {"type": "string", "enum": ["ansi", "pem", "jwt", "bearer", "dsn", "hex64"]},
                }, "required": ["shape"], "additionalProperties": false}),
                json!({"shape": "jwt"}),
            ))
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        // Params are checked before anything waits (P-R35).
        let answer = match req.op.as_str() {
            "echo" => req.params_as::<EchoParams>().and_then(|p| {
                if p.text.len() > TEXT_MAX {
                    return Err(too_big("text is at most 4096 bytes"));
                }
                Ok(Answer::Now(Output::json(json!({"text": p.text}))))
            }),
            "lines" => req.params_as::<LinesParams>().and_then(|p| {
                if p.count > COUNT_MAX {
                    return Err(too_big("count is at most 100000"));
                }
                if p.width > WIDTH_MAX {
                    return Err(too_big("width is at most 1024"));
                }
                let items = stream_iter((0..p.count).map(move |i| Ok(numbered(i, p.width))));
                Ok(Answer::Now(Output::stream(TextStream::lines(items))))
            }),
            "sleep" => req.params_as::<SleepParams>().and_then(|p| {
                if p.ms > SLEEP_MAX {
                    return Err(too_big("ms is at most 600000"));
                }
                Ok(Answer::Sleep(p.ms))
            }),
            "fail" => req.params_as::<FailParams>().and_then(|p| {
                if p.message.len() > MESSAGE_MAX {
                    return Err(too_big("message is at most 256 bytes"));
                }
                Err(match p.code {
                    FailCode::InvalidArgument => SourceError::InvalidArgument(p.message),
                    FailCode::NotFound => SourceError::NotFound(p.message),
                    FailCode::PermissionDenied => SourceError::PermissionDenied(p.message),
                    FailCode::ResourceExhausted => SourceError::ResourceExhausted(p.message),
                    FailCode::FailedPrecondition => SourceError::FailedPrecondition(p.message),
                    FailCode::Unavailable => SourceError::Unavailable(p.message),
                    FailCode::DeadlineExceeded => SourceError::DeadlineExceeded,
                    FailCode::Cancelled => SourceError::Cancelled,
                    FailCode::Internal => SourceError::Internal(p.message),
                })
            }),
            "sample" => req.params_as::<SampleParams>().map(|p| {
                let rule = match p.shape {
                    Shape::Ansi => Rule::Ansi,
                    Shape::Pem => Rule::Pem,
                    Shape::Jwt => Rule::Jwt,
                    Shape::Bearer => Rule::Bearer,
                    Shape::Dsn => Rule::Dsn,
                    Shape::Hex64 => Rule::Hex64,
                };
                Answer::Now(Output::text(sample(rule).0))
            }),
            op => Err(SourceError::NotFound(format!("no op {op}"))),
        };
        Box::pin(async move {
            match answer? {
                Answer::Now(out) => Ok(out),
                Answer::Sleep(ms) => {
                    ctx.within(async {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        Ok(())
                    })
                    .await?;
                    Ok(Output::json(json!({"slept_ms": ms})))
                }
            }
        })
    }
}

/// An op's answer once its params passed: now, or after a sleep.
enum Answer {
    Now(Output),
    Sleep(u64),
}

/// `rule`'s sample text, built at run time from low-entropy parts, and that text after `Redactor::new()`
/// (P-R82).
#[must_use]
pub fn sample(rule: Rule) -> (String, String) {
    let raw = match rule {
        Rule::Ansi => ["\u{1b}", "[31mred", "\u{1b}", "[0m plain"].concat(),
        Rule::Pem => {
            let dashes = "-".repeat(5);
            format!("{dashes}BEGIN TEST KEY{dashes}\n{}\n{dashes}END TEST KEY{dashes}", "A".repeat(64))
        }
        Rule::Jwt => ["token ", "eyJ", &"a".repeat(17), ".", &"b".repeat(20), ".", &"c".repeat(20)].concat(),
        Rule::Bearer => ["Authorization: Bearer ", &"0".repeat(8), "-", &"a".repeat(8)].concat(),
        // A user and its host never sit in one literal here (P-R89): the parts are joined at run time.
        Rule::Dsn => format!("{}://{}:{}@{}", "scheme", "reader", "placeholder-1", "db.example.com:5432/app"),
        Rule::Hex64 => ["key ", &"ab".repeat(32)].concat(),
    };
    let masked = Redactor::new().redact(&raw).into_owned();
    (raw, masked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::context;
    use crate::{Body, Limits};
    use futures_core::Stream;
    use std::pin::Pin;

    async fn call(op: &str, params: serde_json::Value) -> Result<Output, SourceError> {
        EchoSource::new().call(CallRequest::new(op, params), context("echo", Limits::DEFAULT, Duration::from_secs(30))).await
    }

    async fn next<S: Stream + Unpin>(s: &mut S) -> Option<S::Item> {
        std::future::poll_fn(|cx| Pin::new(&mut *s).poll_next(cx)).await
    }

    fn invalid(e: &SourceError) -> bool {
        matches!(e, SourceError::InvalidArgument(m) if m.starts_with("params: "))
    }

    /// P-T34.
    #[tokio::test(start_paused = true)]
    async fn echo_ops_answer_as_documented() {
        let out = call("echo", json!({"text": "hi"})).await.expect("answers");
        assert!(matches!(out.body(), Body::Json(v) if *v == json!({"text": "hi"})));
        assert_eq!(call("echo", json!({"text": "x".repeat(4096)})).await.map(|o| o.kind()), Ok(OutputKind::Json));
        assert_eq!(
            call("echo", json!({"text": "x".repeat(4097)})).await.expect_err("too long"),
            SourceError::InvalidArgument("params: text is at most 4096 bytes".into())
        );
        for bad in [json!({"text": "hi", "extra": 1}), json!({}), json!({"text": 5})] {
            assert!(invalid(&call("echo", bad.clone()).await.expect_err("refused")), "{bad}");
        }

        let out = call("lines", json!({"count": 3, "width": 2})).await.expect("answers");
        assert_eq!((out.kind(), out.content_type()), (OutputKind::Stream, crate::ContentType::Text));
        let Body::Stream(mut s) = out.into_parts().0 else { panic!("a stream") };
        let mut items = Vec::new();
        while let Some(item) = next(&mut s).await {
            items.push(item.expect("an item"));
        }
        assert_eq!(items, ["00000000 xx", "00000001 xx", "00000002 xx"]);
        let Body::Stream(mut s) = call("lines", json!({"count": 100_000})).await.expect("answers").into_parts().0 else { panic!("a stream") };
        assert_eq!(next(&mut s).await, Some(Ok("00000000".to_string())), "the first item before the rest is produced");
        drop(s);
        for bad in [json!({"count": 100_001}), json!({"count": 1, "width": 1025}), json!({"count": -1}), json!({"width": 1}), json!({"count": 1, "x": 0})] {
            assert!(invalid(&call("lines", bad.clone()).await.expect_err("refused")), "{bad}");
        }

        let start = tokio::time::Instant::now();
        let out = call("sleep", json!({"ms": 50})).await.expect("answers");
        assert_eq!(start.elapsed(), Duration::from_millis(50));
        assert!(matches!(out.body(), Body::Json(v) if *v == json!({"slept_ms": 50})));
        let short = context("echo", Limits::DEFAULT, Duration::from_millis(10));
        let start = tokio::time::Instant::now();
        assert_eq!(EchoSource::new().call(CallRequest::new("sleep", json!({"ms": 50})), short).await.expect_err("deadline"), SourceError::DeadlineExceeded);
        assert_eq!(start.elapsed(), Duration::from_millis(10));
        assert!(invalid(&call("sleep", json!({"ms": 600_001})).await.expect_err("refused")));

        let codes = [
            ("INVALID_ARGUMENT", SourceError::InvalidArgument("m".into())),
            ("NOT_FOUND", SourceError::NotFound("m".into())),
            ("PERMISSION_DENIED", SourceError::PermissionDenied("m".into())),
            ("RESOURCE_EXHAUSTED", SourceError::ResourceExhausted("m".into())),
            ("FAILED_PRECONDITION", SourceError::FailedPrecondition("m".into())),
            ("UNAVAILABLE", SourceError::Unavailable("m".into())),
            ("DEADLINE_EXCEEDED", SourceError::DeadlineExceeded),
            ("CANCELLED", SourceError::Cancelled),
            ("INTERNAL", SourceError::Internal("m".into())),
        ];
        for (code, want) in codes {
            assert_eq!(call("fail", json!({"code": code, "message": "m"})).await.expect_err("fails"), want, "{code}");
            assert_eq!(call("fail", json!({"code": code})).await.expect_err("fails").message(), "", "{code}");
        }
        assert!(invalid(&call("fail", json!({"code": "OK"})).await.expect_err("refused")));
        assert!(invalid(&call("fail", json!({"code": "NOT_FOUND", "message": "m".repeat(257)})).await.expect_err("refused")));

        for (shape, rule) in [("ansi", Rule::Ansi), ("pem", Rule::Pem), ("jwt", Rule::Jwt), ("bearer", Rule::Bearer), ("dsn", Rule::Dsn), ("hex64", Rule::Hex64)] {
            let out = call("sample", json!({"shape": shape})).await.expect("answers");
            assert!(matches!(out.body(), Body::Text(t) if *t == sample(rule).0), "{shape}");
        }
        assert!(invalid(&call("sample", json!({"shape": "aws"})).await.expect_err("refused")));
        assert_eq!(call("nope", json!({})).await.expect_err("unknown op"), SourceError::NotFound("no op nope".into()));

        let d = EchoSource::named("echo-2").descriptor();
        assert_eq!((d.name.as_str(), d.version.as_str(), d.description.as_str()), ("echo-2", VERSION, DESCRIPTION));
        assert_eq!((d.kind, d.env.as_str(), d.sensitivity), (SourceKind::Other, "test", Sensitivity::Public));
        let ops: Vec<_> = d.ops.iter().map(|o| (o.name.as_str(), o.output, o.read_only)).collect();
        assert_eq!(
            ops,
            [
                ("echo", OutputKind::Json, true),
                ("lines", OutputKind::Stream, true),
                ("sleep", OutputKind::Json, true),
                ("fail", OutputKind::Json, true),
                ("sample", OutputKind::Text, true)
            ]
        );
        assert_eq!(
            d.ops[0].params_schema.to_string(),
            r#"{"additionalProperties":false,"properties":{"text":{"maxLength":4096,"type":"string"}},"required":["text"],"type":"object"}"#
        );
        assert_eq!(d.validate(), Ok(()));
        assert_eq!(EchoSource::default().descriptor().name, "echo");
    }

    /// P-T35.
    #[test]
    fn samples_are_masked_by_the_default_redactor() {
        let esc = "\u{1b}";
        let dashes = "-".repeat(5);
        let rows = [
            (Rule::Ansi, format!("{esc}[31mred{esc}[0m plain"), "red plain".to_string()),
            (Rule::Pem, format!("{dashes}BEGIN TEST KEY{dashes}\n{}\n{dashes}END TEST KEY{dashes}", "A".repeat(64)), "[redacted:pem]".to_string()),
            (Rule::Jwt, format!("token eyJ{}.{}.{}", "a".repeat(17), "b".repeat(20), "c".repeat(20)), "token [redacted:jwt]".to_string()),
            (Rule::Bearer, format!("Authorization: Bearer {}-{}", "0".repeat(8), "a".repeat(8)), "Authorization: Bearer [redacted:bearer]".to_string()),
            (Rule::Dsn, format!("scheme://{}@db.example.com:5432/app", "reader:placeholder-1"), format!("scheme://{}@db.example.com:5432/app", "reader:[redacted:dsn]")),
            (Rule::Hex64, format!("key {}", "ab".repeat(32)), "key [redacted:hex64]".to_string()),
        ];
        for (rule, raw, masked) in rows {
            let (got_raw, got_masked) = sample(rule);
            assert_eq!((&got_raw, &got_masked), (&raw, &masked), "{rule:?}");
            assert_eq!(Redactor::new().redact(&got_raw), got_masked);
            assert_eq!(Redactor::none().redact(&got_raw), got_raw);
            assert_ne!(got_raw, got_masked);
        }
    }
}
