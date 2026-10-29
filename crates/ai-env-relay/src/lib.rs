//! The ai-env relay (plans/s13-contracts.md §R-relay): the always-on gRPC rendezvous between data-source
//! workers (the public face, `WorkerTunnel`) and MicroVM agents (the private face, `Relay`).
//!
//! Workers dial in over TLS 1.3, prove a whitelisted Ed25519 key and push their catalog; VM agents list the
//! catalog and call sources with a session token the Mac minted. The relay reads its whitelist, token signers,
//! grants and certificate from a live directory I's reload fills, and fails closed whenever they are missing or
//! stale. It never calls AWS, never forwards a token and logs ids and hashes only.
#![forbid(unsafe_code)]

pub mod calls;
pub mod config;
pub mod files;
pub mod handshake;
pub mod limits;
pub mod lists;
pub mod notify;
pub mod private;
pub mod registry;
pub mod reqlog;
pub mod serve;
pub mod session;
pub mod tls;
pub mod tunnel;

pub use config::{Config, Limits};
pub use serve::{Clock, Deps, RelayApp, RelayError, SystemClock};
pub use tls::{Face, PeerInfo, Peered};

/// The relay's own version: `--version`, the status line, the artifact I builds.
pub const RELAY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The run-time CA and leaves of the integration tests (`tests/common/certs.rs`), for the unit tests too.
#[cfg(test)]
#[path = "../tests/common/certs.rs"]
mod test_certs;
