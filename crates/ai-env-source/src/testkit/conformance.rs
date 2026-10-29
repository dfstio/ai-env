//! The conformance checks (P-R85, P-R86).

use std::any::Any;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_core::Stream;
use serde_json::json;
use tokio::task::JoinHandle;

use crate::testkit::context;
use crate::{Body, CallRequest, Code, DataSource, Limits, Output, OutputKind, Redactor, SourceError, TextStream};

/// The op `unknown-op` calls; a descriptor that has it skips the check.
const UNKNOWN_OP: &str = "conformance-unknown-op";
/// The param `unknown-params` passes to every op.
const UNKNOWN_PARAM: &str = "conformance_unknown_param";

/// One conformance check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Check {
    /// `validate()` is `Ok`.
    DescriptorValid,
    /// Two `descriptor()` calls are equal.
    DescriptorStable,
    /// An op the source lacks answers `NotFound`.
    UnknownOp,
    /// Unknown params answer `InvalidArgument`.
    UnknownParams,
    /// `health()` answers within its bound.
    Health,
    /// Each example answers `Ok`, or an error that is not INTERNAL (with examples only).
    Example,
    /// An example's output kind is the op's (with examples only).
    ExampleOutputKind,
}

impl Check {
    /// `descriptor-valid`, `descriptor-stable`, `unknown-op`, `unknown-params`, `health`, `example`,
    /// `example-output-kind`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Check::DescriptorValid => "descriptor-valid",
            Check::DescriptorStable => "descriptor-stable",
            Check::UnknownOp => "unknown-op",
            Check::UnknownParams => "unknown-params",
            Check::Health => "health",
            Check::Example => "example",
            Check::ExampleOutputKind => "example-output-kind",
        }
    }
}

/// One failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Violation {
    /// The check.
    pub check: Check,
    /// The op, where the check has one.
    pub op: Option<String>,
    /// What went wrong.
    pub detail: String,
}

impl fmt::Display for Violation {
    /// `<check> <op or ->: <detail>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.check.name(), self.op.as_deref().unwrap_or("-"), self.detail)
    }
}

/// The checks over one source (P-R85).
pub struct Conformance {
    source: Arc<dyn DataSource>,
    examples: bool,
    call_timeout: Duration,
    health_timeout: Duration,
}

impl Conformance {
    /// The offline checks only; both timeouts 5 s.
    #[must_use]
    pub fn new(source: Arc<dyn DataSource>) -> Self {
        Conformance { source, examples: false, call_timeout: Duration::from_secs(5), health_timeout: Duration::from_secs(5) }
    }

    /// Also each op's examples (needs the backend).
    #[must_use]
    pub fn with_examples(mut self) -> Self {
        self.examples = true;
        self
    }

    /// Each call's bound.
    #[must_use]
    pub fn call_timeout(mut self, d: Duration) -> Self {
        self.call_timeout = d;
        self
    }

    /// `health()`'s bound.
    #[must_use]
    pub fn health_timeout(mut self, d: Duration) -> Self {
        self.health_timeout = d;
        self
    }

    /// Every violation, in check then op order; empty when the source conforms (P-R85). Every call is spawned
    /// (a panic is a violation, `panicked: <message>`) and bounded by its timeout. A source's error and panic
    /// texts may carry what its backend said, so a violation shows them through the source's own redactor, as
    /// the worker would send them (P-R32, P-R39), never raw in a test log.
    pub async fn run(&self) -> Vec<Violation> {
        let d = self.source.descriptor();
        let redactor = self.source.redactor();
        let mut out = Vec::new();
        let mut fail = |check: Check, op: Option<&str>, detail: String| out.push(Violation { check, op: op.map(str::to_string), detail });
        if let Err(e) = d.validate() {
            fail(Check::DescriptorValid, None, e.to_string());
        }
        if self.source.descriptor() != d {
            fail(Check::DescriptorStable, None, "two descriptor() calls differ".to_string());
        }
        if d.op_named(UNKNOWN_OP).is_none() {
            match self.call(&d.name, UNKNOWN_OP, json!({}), &redactor).await {
                Ok(Err(SourceError::NotFound(_))) => {}
                answer => fail(Check::UnknownOp, Some(UNKNOWN_OP), wrong_answer(answer, Code::NotFound, &redactor)),
            }
        }
        for op in &d.ops {
            match self.call(&d.name, &op.name, json!({UNKNOWN_PARAM: true}), &redactor).await {
                Ok(Err(SourceError::InvalidArgument(_))) => {}
                answer => fail(Check::UnknownParams, Some(op.name.as_str()), wrong_answer(answer, Code::InvalidArgument, &redactor)),
            }
        }
        let source = Arc::clone(&self.source);
        if let Err(detail) = bounded(self.health_timeout, tokio::spawn(async move { source.health().await }), &redactor).await {
            fail(Check::Health, None, detail);
        }
        if self.examples {
            let mut kinds = Vec::new();
            for op in &d.ops {
                for example in &op.examples {
                    match self.example(&d.name, &op.name, example.clone(), &redactor).await {
                        Ok(Ok(kind)) if kind != op.output => {
                            kinds.push((op.name.as_str(), format!("{example} answered {}, the op declares {}", kind.name(), op.output.name())));
                        }
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) if e.code() == Code::Internal => {
                            fail(Check::Example, Some(op.name.as_str()), format!("{example} answered {}", shown(&e, &redactor)));
                        }
                        Ok(Err(_)) => {}
                        Err(detail) => fail(Check::Example, Some(op.name.as_str()), format!("{example}: {detail}")),
                    }
                }
            }
            for (op, detail) in kinds {
                fail(Check::ExampleOutputKind, Some(op), detail);
            }
        }
        out
    }

    /// One call, spawned and bounded by `call_timeout`: its answer, or why there is none.
    async fn call(&self, source_name: &str, op: &str, params: serde_json::Value, redactor: &Redactor) -> Result<Result<Output, SourceError>, String> {
        let source = Arc::clone(&self.source);
        let (req, ctx) = (CallRequest::new(op, params), context(source_name, Limits::DEFAULT, self.call_timeout));
        bounded(self.call_timeout, tokio::spawn(async move { source.call(req, ctx).await }), redactor).await
    }

    /// One example's call: its output's kind, a stream drained in the same bound.
    async fn example(&self, source_name: &str, op: &str, params: serde_json::Value, redactor: &Redactor) -> Result<Result<OutputKind, SourceError>, String> {
        let source = Arc::clone(&self.source);
        let (req, ctx) = (CallRequest::new(op, params), context(source_name, Limits::DEFAULT, self.call_timeout));
        let task = tokio::spawn(async move {
            let out = source.call(req, ctx).await?;
            let kind = out.kind();
            if let Body::Stream(items) = out.into_parts().0 {
                drain(items).await?;
            }
            Ok(kind)
        });
        bounded(self.call_timeout, task, redactor).await
    }
}

/// Polls `items` up to `Limits::DEFAULT.max_rows` items and no further (P-R85): an item's error is the answer.
async fn drain(mut items: TextStream) -> Result<(), SourceError> {
    for _ in 0..Limits::DEFAULT.max_rows {
        match std::future::poll_fn(|cx| Pin::new(&mut items).poll_next(cx)).await {
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(e),
            None => break,
        }
    }
    Ok(())
}

/// `task`'s value within `limit`; otherwise the task is aborted, and the text says why there is none (a panic's
/// message through `redactor`).
async fn bounded<T>(limit: Duration, task: JoinHandle<T>, redactor: &Redactor) -> Result<T, String> {
    let abort = task.abort_handle();
    match tokio::time::timeout(limit, task).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) if e.is_panic() => Err(format!("panicked: {}", redactor.redact(&panic_message(e.into_panic().as_ref())))),
        Ok(Err(e)) => Err(format!("its task ended: {e}")),
        Err(_) => {
            abort.abort();
            Err(format!("no answer within {limit:?}"))
        }
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    match (payload.downcast_ref::<String>(), payload.downcast_ref::<&str>()) {
        (Some(s), _) => s.clone(),
        (None, Some(s)) => (*s).to_string(),
        (None, None) => "a payload that is not text".to_string(),
    }
}

/// `e` as its Display shows it, the message as the wire carries it: redacted, then cut (P-R32).
fn shown(e: &SourceError, redactor: &Redactor) -> String {
    match e {
        SourceError::DeadlineExceeded | SourceError::Cancelled => e.code().name().to_string(),
        _ => format!("{}: {}", e.code().name(), e.wire_message(redactor)),
    }
}

/// Why a call's answer is not the error `want`.
fn wrong_answer(answer: Result<Result<Output, SourceError>, String>, want: Code, redactor: &Redactor) -> String {
    match answer {
        Ok(Ok(out)) => format!("answered a {} output, not {}", out.kind().name(), want.name()),
        Ok(Err(e)) => format!("answered {}, not {}", shown(&e, redactor), want.name()),
        Err(detail) => detail,
    }
}

/// `Conformance::new(source).run()`; panics with `<source name> does not conform:` and one violation per
/// line when any (P-R86).
pub async fn assert_conforms(source: Arc<dyn DataSource>) {
    let name = source.descriptor().name;
    let violations = Conformance::new(source).run().await;
    if !violations.is_empty() {
        let lines: Vec<String> = violations.iter().map(ToString::to_string).collect();
        panic!("{name} does not conform:\n{}", lines.join("\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Rule;
    use crate::stream_iter;
    use crate::testkit::sample;

    /// `rows` items, then an INTERNAL error.
    fn rows_then_a_fault(rows: u32) -> TextStream {
        let items = (0..rows).map(|i| Ok(i.to_string())).chain(std::iter::once(Err(SourceError::Internal("after the rows".into()))));
        TextStream::lines(stream_iter(items))
    }

    /// P-R85: an example's stream is drained up to `Limits::DEFAULT.max_rows` items, and the next is never polled.
    #[tokio::test]
    async fn an_example_stream_is_drained_up_to_the_default_rows() {
        let rows = Limits::DEFAULT.max_rows;
        assert_eq!(drain(rows_then_a_fault(rows)).await, Ok(()));
        assert_eq!(drain(rows_then_a_fault(rows - 1)).await, Err(SourceError::Internal("after the rows".into())));
        assert_eq!(drain(TextStream::lines(stream_iter(Vec::<Result<String, SourceError>>::new()))).await, Ok(()));
    }

    /// A violation shows an error as Display does, its message redacted and cut as on the wire (P-R32).
    #[test]
    fn errors_are_shown_redacted_and_cut() {
        let (raw, masked) = sample(Rule::Jwt);
        let redactor = Redactor::new();
        assert_eq!(shown(&SourceError::Unavailable(format!("backend said {raw}")), &redactor), format!("UNAVAILABLE: backend said {masked}"));
        assert_eq!(shown(&SourceError::Internal("x".repeat(2000)), &redactor), format!("INTERNAL: {}", "x".repeat(crate::MESSAGE_MAX)));
        assert_eq!(shown(&SourceError::Cancelled, &redactor), "CANCELLED");
        assert_eq!(shown(&SourceError::DeadlineExceeded, &redactor), SourceError::DeadlineExceeded.to_string());
        assert_eq!(shown(&SourceError::NotFound(raw.clone()), &Redactor::none()), format!("NOT_FOUND: {raw}"));
        let found = wrong_answer(Ok(Err(SourceError::Unavailable(raw))), Code::NotFound, &redactor);
        assert_eq!(found, format!("answered UNAVAILABLE: {masked}, not NOT_FOUND"));
    }
}
