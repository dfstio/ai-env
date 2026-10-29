//! `ScriptedSource` (P-R80).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::{
    stream_iter, BoxFuture, CallContext, CallRequest, Caller, DataSource, Health, Limits, Output, Redactor, SourceDescriptor, SourceError,
    TextStream,
};

/// One scripted answer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Scripted {
    /// Answers this JSON.
    Json(serde_json::Value),
    /// Answers this text.
    Text(String),
    /// Answers a `TextStream::lines` of these.
    Lines(Vec<String>),
    /// Answers this error.
    Fail(SourceError),
    /// Waits in `ctx.within` for the cancel or the deadline.
    Hang,
    /// Waits this long in `ctx.within`, then plays the step.
    Delay(Duration, Box<Scripted>),
    /// Panics with this message.
    Panic(String),
}

/// One call as `ScriptedSource` saw it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct RecordedCall {
    /// The context's request id.
    pub request_id: String,
    /// The context's source.
    pub source: String,
    /// The op called.
    pub op: String,
    /// Its params.
    pub params: serde_json::Value,
    /// The context's caller.
    pub caller: Caller,
    /// The context's limits.
    pub limits: Limits,
    /// `ctx.remaining()` when the call was invoked.
    pub remaining: Duration,
}

/// What every handle of one `ScriptedSource` shares.
#[derive(Default)]
struct State {
    general: VecDeque<Scripted>,
    per_op: BTreeMap<String, VecDeque<Scripted>>,
    calls: Vec<RecordedCall>,
    in_flight: usize,
    max_in_flight: usize,
    cancelled: usize,
}

/// A source that answers a script, records its calls and counts them in flight (P-R80).
pub struct ScriptedSource {
    descriptor: SourceDescriptor,
    state: Arc<Mutex<State>>,
    health: Health,
    redactor: Redactor,
}

impl ScriptedSource {
    /// A source of this descriptor with an empty script.
    #[must_use]
    pub fn new(descriptor: SourceDescriptor) -> Self {
        ScriptedSource { descriptor, state: Arc::default(), health: Health::Ok, redactor: Redactor::new() }
    }

    /// The same source with one more general step.
    #[must_use]
    pub fn then(self, step: Scripted) -> Self {
        self.push(step);
        self
    }

    /// The same source with one more step for `op` (taken before the general ones).
    #[must_use]
    pub fn then_for(self, op: &str, step: Scripted) -> Self {
        self.lock().per_op.entry(op.to_string()).or_default().push_back(step);
        self
    }

    /// Queues one more general step on a shared source.
    pub fn push(&self, step: Scripted) {
        self.lock().general.push_back(step);
    }

    /// The same source answering `health()` with `health`.
    #[must_use]
    pub fn with_health(mut self, health: Health) -> Self {
        self.health = health;
        self
    }

    /// The same source answering `redactor()` with `redactor`.
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// Every call so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.lock().calls.clone()
    }

    /// The calls running now.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.lock().in_flight
    }

    /// The most calls that ran at once.
    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.lock().max_in_flight
    }

    /// The calls that answered `Err(Cancelled)` or were dropped before answering. A call whose step panicked
    /// leaves `in_flight()` without counting here: a panic is no cancel.
    #[must_use]
    pub fn cancelled(&self) -> usize {
        self.lock().cancelled
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }
}

/// A test double's lock: a panic elsewhere (a `Panic` step) never poisons the counts.
fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One call in flight: counted from its invocation until its future completes or is dropped.
struct InFlight {
    state: Arc<Mutex<State>>,
    left: bool,
}

impl InFlight {
    fn start(state: &Arc<Mutex<State>>) -> Self {
        let mut s = lock(state);
        s.in_flight += 1;
        s.max_in_flight = s.max_in_flight.max(s.in_flight);
        InFlight { state: Arc::clone(state), left: false }
    }

    /// The call answered: it leaves the count, as cancelled when the answer is `Cancelled`.
    fn answer(mut self, answer: &Result<Output, SourceError>) {
        self.leave(matches!(answer, Err(SourceError::Cancelled)));
    }

    fn leave(&mut self, cancelled: bool) {
        if std::mem::replace(&mut self.left, true) {
            return;
        }
        let mut s = lock(&self.state);
        s.in_flight -= 1;
        if cancelled {
            s.cancelled += 1;
        }
    }
}

impl Drop for InFlight {
    /// A call dropped before it answered counts as cancelled, unless a panic is unwinding through it.
    fn drop(&mut self) {
        self.leave(!std::thread::panicking());
    }
}

/// One step's answer (P-R80).
async fn play(mut step: Scripted, ctx: &CallContext) -> Result<Output, SourceError> {
    loop {
        return match step {
            Scripted::Json(value) => Ok(Output::json(value)),
            Scripted::Text(text) => Ok(Output::text(text)),
            Scripted::Lines(lines) => Ok(Output::stream(TextStream::lines(stream_iter(lines.into_iter().map(Ok))))),
            Scripted::Fail(e) => Err(e),
            Scripted::Hang => ctx.within(std::future::pending()).await,
            Scripted::Delay(d, then) => {
                ctx.within(async {
                    tokio::time::sleep(d).await;
                    Ok(())
                })
                .await?;
                step = *then;
                continue;
            }
            Scripted::Panic(message) => panic!("{message}"),
        };
    }
}

impl DataSource for ScriptedSource {
    fn descriptor(&self) -> SourceDescriptor {
        self.descriptor.clone()
    }

    fn call<'s, 'f>(&'s self, req: CallRequest, ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f,
    {
        let known = self.descriptor.op_named(&req.op).is_some();
        let step = {
            let mut s = self.lock();
            s.calls.push(RecordedCall {
                request_id: ctx.request_id.clone(),
                source: ctx.source.clone(),
                op: req.op.clone(),
                params: req.params.clone(),
                caller: ctx.caller.clone(),
                limits: ctx.limits,
                remaining: ctx.remaining(),
            });
            if known {
                s.per_op.get_mut(&req.op).and_then(VecDeque::pop_front).or_else(|| s.general.pop_front())
            } else {
                None
            }
        };
        let guard = InFlight::start(&self.state);
        Box::pin(async move {
            let answer = match step {
                _ if !known => Err(SourceError::NotFound(format!("no op {}", req.op))),
                None => Err(SourceError::Internal(format!("ScriptedSource: no step left for {}", req.op))),
                Some(step) => play(step, &ctx).await,
            };
            guard.answer(&answer);
            answer
        })
    }

    fn health<'s, 'f>(&'s self) -> BoxFuture<'f, Health>
    where
        's: 'f,
        Self: 'f,
    {
        let health = self.health.clone();
        Box::pin(async move { health })
    }

    fn redactor(&self) -> Redactor {
        self.redactor.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{caller, context};
    use crate::{Body, OpDescriptor};
    use futures_core::Stream as _;
    use serde_json::json;

    fn descriptor() -> SourceDescriptor {
        SourceDescriptor::new("test-scripted", "0.1.0", "A scripted test source.")
            .op(OpDescriptor::new("a", "Op a."))
            .op(OpDescriptor::new("b", "Op b."))
    }

    fn ctx() -> CallContext {
        context("test-scripted", Limits::DEFAULT, Duration::from_secs(30))
    }

    async fn answer(source: &ScriptedSource, op: &str) -> Result<Output, SourceError> {
        source.call(CallRequest::new(op, json!({"op": op})), ctx()).await
    }

    async fn drain(out: Output) -> Vec<String> {
        let Body::Stream(mut s) = out.into_parts().0 else { panic!("not a stream") };
        let mut items = Vec::new();
        while let Some(item) = std::future::poll_fn(|cx| std::pin::Pin::new(&mut s).poll_next(cx)).await {
            items.push(item.expect("an item"));
        }
        items
    }

    /// P-T31.
    #[tokio::test(start_paused = true)]
    async fn scripted_source_answers_its_script_in_order_and_records_calls() {
        let source = ScriptedSource::new(descriptor())
            .then(Scripted::Json(json!({"n": 1})))
            .then(Scripted::Text("two".into()))
            .then_for("b", Scripted::Text("for b".into()));
        source.push(Scripted::Lines(vec!["x".into(), "y".into()]));
        source.push(Scripted::Fail(SourceError::Unavailable("down".into())));

        assert!(matches!(answer(&source, "b").await.expect("answers").body(), Body::Text(t) if t == "for b"));
        assert_eq!(answer(&source, "x").await.expect_err("unknown op"), SourceError::NotFound("no op x".into()));
        assert!(matches!(answer(&source, "a").await.expect("answers").body(), Body::Json(v) if *v == json!({"n": 1})));
        assert!(matches!(answer(&source, "b").await.expect("answers").body(), Body::Text(t) if t == "two"));
        assert_eq!(drain(answer(&source, "a").await.expect("answers")).await, ["x", "y"]);
        assert_eq!(answer(&source, "a").await.expect_err("fails"), SourceError::Unavailable("down".into()));
        assert_eq!(answer(&source, "a").await.expect_err("empty"), SourceError::Internal("ScriptedSource: no step left for a".into()));

        let calls = source.calls();
        let ops: Vec<_> = calls.iter().map(|c| c.op.as_str()).collect();
        assert_eq!(ops, ["b", "x", "a", "b", "a", "a", "a"]);
        let first = &calls[0];
        assert_eq!(first.request_id, "0199a1b2-0000-7000-8000-000000000001");
        assert_eq!((first.source.as_str(), &first.params, &first.caller), ("test-scripted", &json!({"op": "b"}), &caller()));
        assert_eq!((first.limits, first.remaining), (Limits::DEFAULT, Duration::from_secs(30)));

        let ctx = context("test-scripted", Limits::new(1, 2, 3), Duration::from_secs(7));
        tokio::time::advance(Duration::from_secs(2)).await;
        let _ = source.call(CallRequest::new("a", json!({})), ctx).await;
        let last = source.calls().pop().expect("recorded");
        assert_eq!((last.limits, last.remaining), (Limits::new(1, 2, 3), Duration::from_secs(5)));
        assert_eq!((source.in_flight(), source.max_in_flight(), source.cancelled()), (0, 1, 0));

        let shaped = ScriptedSource::new(descriptor()).with_health(Health::Down("off".into())).with_redactor(Redactor::none());
        assert_eq!(shaped.health().await, Health::Down("off".into()));
        assert!(shaped.redactor().rules().is_empty());
        assert_eq!(ScriptedSource::new(descriptor()).health().await, Health::Ok);
        assert_eq!(ScriptedSource::new(descriptor()).redactor().rules(), crate::redact::Rule::ALL);
        assert_eq!(shaped.descriptor(), descriptor());
    }

    /// P-T32.
    #[tokio::test(start_paused = true)]
    async fn scripted_hang_waits_for_cancel_and_counts_drops() {
        let source = ScriptedSource::new(descriptor()).then(Scripted::Hang).then(Scripted::Hang).then(Scripted::Hang);

        let ctx = context("test-scripted", Limits::DEFAULT, Duration::from_secs(30));
        let cancel = ctx.cancel.clone();
        let call = source.call(CallRequest::new("a", json!({})), ctx);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            cancel.cancel();
        });
        assert_eq!(call.await.expect_err("cancelled"), SourceError::Cancelled);
        assert_eq!(source.cancelled(), 1, "a Cancelled answer counts");

        let ctx = context("test-scripted", Limits::DEFAULT, Duration::from_secs(3));
        let start = tokio::time::Instant::now();
        assert_eq!(source.call(CallRequest::new("a", json!({})), ctx).await.expect_err("deadline"), SourceError::DeadlineExceeded);
        assert_eq!(start.elapsed(), Duration::from_secs(3));
        assert_eq!(source.cancelled(), 1, "a deadline answer does not count");

        let dropped = source.call(CallRequest::new("a", json!({})), ctx_long());
        assert_eq!(source.in_flight(), 1);
        drop(dropped);
        assert_eq!((source.in_flight(), source.cancelled()), (0, 2), "a call dropped before answering counts");

        let delayed = ScriptedSource::new(descriptor()).then(Scripted::Delay(Duration::from_secs(10), Box::new(Scripted::Json(json!(1)))));
        let start = tokio::time::Instant::now();
        let out = delayed.call(CallRequest::new("a", json!({})), ctx_long()).await.expect("answers");
        assert_eq!(start.elapsed(), Duration::from_secs(10));
        assert!(matches!(out.body(), Body::Json(v) if *v == json!(1)));

        let panicking = Arc::new(ScriptedSource::new(descriptor()).then(Scripted::Panic("boom".into())));
        let shared = Arc::clone(&panicking);
        let joined = tokio::spawn(async move { shared.call(CallRequest::new("a", json!({})), ctx_long()).await }).await;
        let e = joined.expect_err("panicked");
        assert!(e.is_panic());
        assert_eq!(e.into_panic().downcast_ref::<String>().map(String::as_str), Some("boom"));
        assert_eq!((panicking.in_flight(), panicking.cancelled()), (0, 0), "a panic leaves the count and is no cancel");
    }

    fn ctx_long() -> CallContext {
        context("test-scripted", Limits::DEFAULT, Duration::from_secs(60))
    }

    /// P-T33.
    #[tokio::test(start_paused = true)]
    async fn scripted_counts_calls_in_flight() {
        let source = Arc::new(ScriptedSource::new(descriptor()));
        for i in 0..5u64 {
            source.push(Scripted::Delay(Duration::from_secs(10 + i), Box::new(Scripted::Json(json!(i)))));
        }
        let mut calls: Vec<_> = (0..5).map(|_| source.call(CallRequest::new("a", json!({})), ctx_long())).collect();
        assert_eq!((source.in_flight(), source.max_in_flight()), (5, 5));
        let mut dropped = calls.pop().expect("five calls");
        // Polled once, so it is dropped mid-delay.
        let pending = std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(dropped.as_mut(), cx).is_pending())).await;
        assert!(pending, "the fifth call waits in its delay");
        drop(dropped);
        assert_eq!(source.in_flight(), 4, "one lower at once");
        for (i, call) in calls.into_iter().enumerate() {
            let out = call.await.expect("answers");
            assert!(matches!(out.body(), Body::Json(v) if *v == json!(i)));
        }
        assert_eq!((source.in_flight(), source.max_in_flight(), source.cancelled()), (0, 5, 1));
    }
}
