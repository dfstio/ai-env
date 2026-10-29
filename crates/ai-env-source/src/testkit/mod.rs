//! Test doubles and the conformance checks (plans/s13-contracts.md §P-proto-sdk.6.10, P-R80 to P-R86), for
//! ai-env's own tests and a private repo's `[dev-dependencies]` only (P-R84).

use std::time::Duration;

use crate::{CallContext, Caller, Cancel, Limits};

mod conformance;
mod echo;
mod scripted;

pub use conformance::{assert_conforms, Check, Conformance, Violation};
pub use echo::{sample, EchoSource};
pub use scripted::{RecordedCall, Scripted, ScriptedSource};

/// The test caller: caller_id `test-caller`, session_id `0199a1b2-0000-7000-8000-000000000002`, grant_id
/// `test-grant`, vm_id `test-vm`.
#[must_use]
pub fn caller() -> Caller {
    Caller::new("test-caller", "0199a1b2-0000-7000-8000-000000000002", "test-grant", "test-vm")
}

/// A context: request_id `0199a1b2-0000-7000-8000-000000000001`, `source`, `caller()`, `limits`, now plus
/// `timeout`, a fresh `Cancel`.
#[must_use]
pub fn context(source: &str, limits: Limits, timeout: Duration) -> CallContext {
    CallContext::new("0199a1b2-0000-7000-8000-000000000001", source, caller(), limits, tokio::time::Instant::now() + timeout, Cancel::new())
}
