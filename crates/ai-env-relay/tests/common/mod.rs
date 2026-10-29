//! The relay's test harness (§R-relay.7): an in-process relay over `tokio::io::duplex` (`rig`), a scripted
//! worker (`worker`), a manual wall clock (`clock`) and a run-time CA (`certs`). Every key, token and certificate
//! is derived from a seed at run time; every name is generic (`example.alpha`, `worker-a`, `mac`).
//!
//! Seeds: workers A `[1u8; 32]` (`worker-a`, `example.alpha*`), B `[2u8; 32]` (`worker-b`, `example.beta*`),
//! C `[5u8; 32]` (`worker-c`, `example.gamma*`); the token signer `mac` `[7u8; 32]` (WM-T6's session key). The
//! lists are rendered with W/M's `policy::render_*` and every token is minted with W/M's `session::mint`.
#![allow(dead_code)]

pub mod certs;
pub mod clock;
pub mod rig;
pub mod worker;
