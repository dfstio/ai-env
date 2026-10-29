//! The trait (plans/s13-contracts.md §P-proto-sdk.6.1).

use std::future::Future;
use std::pin::Pin;

use crate::{CallContext, CallRequest, Output, Redactor, SourceDescriptor, SourceError};

/// A boxed future, the form `#[async_trait]` expands an `async fn` to.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One data source: what it offers (its descriptor) and how it answers a call. Implement it by hand with
/// the signatures below, or write `#[async_trait::async_trait] impl DataSource for … { async fn call(…) }`.
///
/// The two lifetimes of `call` and `health` are what async-trait expands to (LD-P2): a one-lifetime
/// form would refuse `#[async_trait]` impls (E0195).
pub trait DataSource: Send + Sync + 'static {
    /// What the catalog advertises (P-R33).
    fn descriptor(&self) -> SourceDescriptor;
    /// One call of one of its ops (P-R34 to P-R37).
    fn call<'s, 'f>(&'s self, req: CallRequest, ctx: CallContext) -> BoxFuture<'f, Result<Output, SourceError>>
    where
        's: 'f,
        Self: 'f;
    /// Whether the backend answers now (P-R38).
    fn health<'s, 'f>(&'s self) -> BoxFuture<'f, Health>
    where
        's: 'f,
        Self: 'f,
    {
        Box::pin(async { Health::Ok })
    }
    /// The masking the worker applies to everything this source returns (P-R39). The built-in rules leave some
    /// forms unmasked: hex runs of other lengths than 64, `password=` parameters, `Password=…;` pairs, DSNs
    /// without `://` and `Bearer:`. A source whose output can hold them adds a custom rule.
    fn redactor(&self) -> Redactor {
        Redactor::new()
    }
}

/// A source's health: advisory, shown by the worker's `check` (P-R38).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Health {
    /// The backend answers.
    Ok,
    /// The backend answers, with a problem worth showing.
    Degraded(String),
    /// The backend does not answer.
    Down(String),
}
