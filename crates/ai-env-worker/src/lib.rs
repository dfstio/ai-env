//! The ai-env relay worker (plans/s13-contracts.md §WM-worker-mac.3): dial the relay over pinned TLS 1.3,
//! prove a whitelisted Ed25519 key, serve `DataSource`s.
//!
//! Without the `runtime` feature (as ai-env-cli and the relay take it) the crate holds the shared formats
//! only: ids and globs, keys, session tokens, the three relay lists, the signing agent's protocol, the signers,
//! the relay's certificates (`certs`) and the mapping of ai-env-source's types to the wire (`map`, review A-M13).
//!
//! The runtime: `Worker::builder().worker_id(…).relay(…).signer(…).source(…).build()?.run_until(shutdown)`.
//! Each tunnel is one new TLS 1.3 connection under the pinned relay CA (WM-R11, LD-WM18), one
//! `WorkerTunnel.Open` stream, the handshake (WM-R13), then the calls (WM-R18 to WM-R30) until it ends
//! (WM-R15); the next dial waits the backoff (WM-R16).
#![forbid(unsafe_code)]

pub use ai_env_relay_proto::PROTOCOL;
/// This crate's version: `Hello.sdk_version`.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
/// A boxed future, as async-trait expands to (the same alias as `ai_env_source::BoxFuture`).
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub mod agent;
pub mod certs;
pub mod globs;
pub mod keys;
pub mod map;
pub mod policy;
pub mod session;
pub mod signer;

pub use ai_env_source;

#[cfg(feature = "runtime")]
mod backoff;
#[cfg(feature = "runtime")]
mod calls;
#[cfg(feature = "runtime")]
mod endpoint;
#[cfg(feature = "runtime")]
mod tunnel;
#[cfg(feature = "runtime")]
mod worker;

#[cfg(feature = "runtime")]
pub use crate::endpoint::{Dial, EndpointError, Io, RelayEndpoint};
#[cfg(feature = "runtime")]
pub use crate::worker::{BuildError, CheckReport, Tuning, Worker, WorkerBuilder, WorkerError};
