//! Calls (plans/s13-contracts.md §P-proto-sdk.6.4, P-R35 to P-R37, P-R62).

use std::future::Future;
use std::time::Duration;

use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;

use crate::{Cursor, Limits, SourceError};

/// Who calls, as the relay asserts it from the verified session token: never a credential.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Caller {
    /// The token signer's caller id.
    pub caller_id: String,
    /// The VM session's id.
    pub session_id: String,
    /// The grant the call went through.
    pub grant_id: String,
    /// The VM's id (informational: every VM reaches the relay from one address).
    pub vm_id: String,
}

impl Caller {
    /// A caller of these four ids.
    #[must_use]
    pub fn new(caller_id: impl Into<String>, session_id: impl Into<String>, grant_id: impl Into<String>, vm_id: impl Into<String>) -> Self {
        Caller { caller_id: caller_id.into(), session_id: session_id.into(), grant_id: grant_id.into(), vm_id: vm_id.into() }
    }
}

/// The call's cancellation: fired by the worker when the caller goes or the tunnel closes.
#[derive(Debug, Clone, Default)]
pub struct Cancel(CancellationToken);

impl Cancel {
    /// A cancellation not fired yet.
    #[must_use]
    pub fn new() -> Self {
        Cancel(CancellationToken::new())
    }

    /// Fires it (and every child).
    pub fn cancel(&self) {
        self.0.cancel();
    }

    /// Whether it fired.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }

    /// Resolves once it fired.
    pub async fn cancelled(&self) {
        self.0.cancelled().await;
    }

    /// A cancellation fired with this one, or on its own (for a task the source spawns, P-R37).
    #[must_use]
    pub fn child(&self) -> Cancel {
        Cancel(self.0.child_token())
    }
}

/// One call of one op: the op's name and its params, a JSON object (P-R35).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CallRequest {
    /// The op's name, one of the descriptor's.
    pub op: String,
    /// The params: a JSON object.
    pub params: serde_json::Value,
}

impl CallRequest {
    /// A request of `op` with `params`.
    #[must_use]
    pub fn new(op: impl Into<String>, params: serde_json::Value) -> Self {
        CallRequest { op: op.into(), params }
    }

    /// The params as `T` (P-R35): every serde error is `InvalidArgument("params: <serde's text>")`.
    pub fn params_as<T: DeserializeOwned>(&self) -> Result<T, SourceError> {
        serde_json::from_value(self.params.clone()).map_err(|e| SourceError::InvalidArgument(format!("params: {e}")))
    }

    /// `params["cursor"]` (P-R62): absent or null is `None`, a string is `Cursor::parse`, anything else
    /// `InvalidArgument("params: cursor is a string")`.
    pub fn cursor(&self) -> Result<Option<Cursor>, SourceError> {
        match self.params.get("cursor") {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(text)) => Cursor::parse(text).map(Some),
            Some(_) => Err(SourceError::InvalidArgument("params: cursor is a string".to_string())),
        }
    }
}

/// What the worker tells a source about one call.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CallContext {
    /// The `Invoke`'s UUIDv7.
    pub request_id: String,
    /// The source's name as invoked.
    pub source: String,
    /// Who calls, as the relay asserts it.
    pub caller: Caller,
    /// The effective limits (P-R45): no field is 0.
    pub limits: Limits,
    /// When the call's budget ends (P-R47).
    pub deadline: tokio::time::Instant,
    /// The call's cancellation.
    pub cancel: Cancel,
}

impl CallContext {
    /// A context of these values.
    #[must_use]
    pub fn new(
        request_id: impl Into<String>,
        source: impl Into<String>,
        caller: Caller,
        limits: Limits,
        deadline: tokio::time::Instant,
        cancel: Cancel,
    ) -> Self {
        CallContext { request_id: request_id.into(), source: source.into(), caller, limits, deadline, cancel }
    }

    /// The deadline less now; 0 once it passed.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(tokio::time::Instant::now())
    }

    /// Whether the call was cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// P-R36: races, in this order, the cancel (`Err(Cancelled)`), the deadline (`Err(DeadlineExceeded)`) and
    /// `fut` (its answer); a cancel already fired or a deadline already passed wins over a ready `fut`.
    pub async fn within<T, F>(&self, fut: F) -> Result<T, SourceError>
    where
        F: Future<Output = Result<T, SourceError>>,
    {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(SourceError::Cancelled),
            () = tokio::time::sleep_until(self.deadline) => Err(SourceError::DeadlineExceeded),
            answer = fut => answer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;
    use tokio::time::Instant;

    fn ctx(timeout: Duration) -> CallContext {
        CallContext::new("0199a1b2-0000-7000-8000-000000000001", "test-call", Caller::default(), Limits::DEFAULT, Instant::now() + timeout, Cancel::new())
    }

    fn pending() -> std::future::Pending<Result<u32, SourceError>> {
        std::future::pending()
    }

    /// P-T18.
    #[test]
    fn params_as_refuses_unknown_and_missing_fields_as_invalid_argument() {
        #[derive(Debug, PartialEq, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            text: String,
            n: u32,
        }
        let good = CallRequest::new("op", json!({"text": "a", "n": 1}));
        assert_eq!(good.params_as::<Params>(), Ok(Params { text: "a".into(), n: 1 }));
        for bad in [json!({"text": "a", "n": 1, "extra": true}), json!({"text": "a"}), json!({"text": "a", "n": "one"}), json!([])] {
            let e = CallRequest::new("op", bad.clone()).params_as::<Params>().expect_err("refused");
            assert!(matches!(&e, SourceError::InvalidArgument(m) if m.starts_with("params: ")), "{bad}: {e}");
        }

        assert_eq!(CallRequest::new("op", json!({})).cursor(), Ok(None));
        assert_eq!(CallRequest::new("op", json!({"cursor": null})).cursor(), Ok(None));
        let cursor = Cursor::encode("test-call", "op", &3).expect("encodes");
        assert_eq!(CallRequest::new("op", json!({"cursor": cursor.as_str()})).cursor(), Ok(Some(cursor)));
        assert_eq!(CallRequest::new("op", json!({"cursor": 5})).cursor(), Err(SourceError::InvalidArgument("params: cursor is a string".into())));
        assert_eq!(
            CallRequest::new("op", json!({"cursor": "c2.e30"})).cursor(),
            Err(SourceError::InvalidArgument("cursor: not one of this source's cursors".into()))
        );
    }

    /// P-T19.
    #[tokio::test(start_paused = true)]
    async fn within_answers_cancel_then_deadline_then_the_call() {
        let ready = || async { Ok::<u32, SourceError>(7) };
        assert_eq!(ctx(Duration::from_secs(1)).within(ready()).await, Ok(7));
        // Fifty rounds: without `biased;`, a ready call would win about two times in three in each.
        for _ in 0..50 {
            let cancelled = ctx(Duration::from_secs(1));
            cancelled.cancel.cancel();
            let passed = ctx(Duration::from_millis(10));
            let both = ctx(Duration::from_millis(10));
            both.cancel.cancel();
            tokio::time::advance(Duration::from_millis(20)).await;
            assert_eq!(cancelled.within(ready()).await, Err(SourceError::Cancelled));
            assert_eq!(passed.within(ready()).await, Err(SourceError::DeadlineExceeded));
            assert_eq!(both.within(ready()).await, Err(SourceError::Cancelled));
            assert_eq!(passed.remaining(), Duration::ZERO);
        }

        let c = ctx(Duration::from_millis(100));
        assert_eq!(c.remaining(), Duration::from_millis(100));
        let start = Instant::now();
        assert_eq!(c.within(pending()).await, Err(SourceError::DeadlineExceeded));
        assert_eq!(start.elapsed(), Duration::from_millis(100));
        assert_eq!(c.remaining(), Duration::ZERO);

        let c = ctx(Duration::from_secs(1));
        let cancel = c.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel.cancel();
        });
        let start = Instant::now();
        assert!(!c.is_cancelled());
        assert_eq!(c.within(pending()).await, Err(SourceError::Cancelled));
        assert_eq!(start.elapsed(), Duration::from_millis(50));
        assert!(c.is_cancelled());
    }

    /// P-R37: a child fires with its parent, and alone without firing the parent.
    #[test]
    fn a_child_cancel_follows_its_parent() {
        let parent = Cancel::new();
        let (a, b) = (parent.child(), parent.child());
        b.cancel();
        assert!(b.is_cancelled() && !parent.is_cancelled() && !a.is_cancelled());
        parent.cancel();
        assert!(a.is_cancelled());
    }
}
