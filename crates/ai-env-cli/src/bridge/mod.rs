//! Mac-side bridge (feature `bridge`): the MicroVM control-plane client, the
//! TLS policy, scrubbed logging, config, the sibling-binary lookup, doctor
//! rows, the pre-code gates, and the S2 pump with its host-state recorder,
//! transcript-mirror writer, session registry, resume seeder and audit log.
//! Nothing here is compiled into the VM image.
pub mod api;
pub mod audit;
pub mod census;
pub mod config;
pub mod doctor;
pub mod errors;
pub mod gates;
pub mod hoststate;
pub mod lab;
pub mod logging;
pub mod mirror;
pub mod pump;
pub mod registry;
pub mod route;
pub mod seed;
pub mod sibling;
pub mod tls;
pub mod transport;
pub mod wrapper;
