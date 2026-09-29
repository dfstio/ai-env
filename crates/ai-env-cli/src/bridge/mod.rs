//! Mac-side bridge (feature `bridge`): the MicroVM control-plane client, the
//! TLS policy, scrubbed logging, config, the sibling-binary lookup, doctor
//! rows, the pre-code gates, the S2 pump with its host-state recorder,
//! transcript-mirror writer, session registry, resume seeder and audit log,
//! and the S3 infrastructure helpers (image scan, claude pin, stack outputs,
//! sealed AWS credentials). Nothing here is compiled into the VM image.
pub mod api;
pub mod audit;
pub mod census;
pub mod config;
pub mod creds;
pub mod doctor;
pub mod errors;
pub mod gates;
pub mod hoststate;
pub mod imagepin;
pub mod infra;
pub mod lab;
pub mod logging;
pub mod mirror;
pub mod probes;
pub mod pump;
pub mod registry;
pub mod route;
pub mod scan;
pub mod seed;
pub mod sibling;
pub mod tls;
pub mod transport;
pub mod vm;
pub mod wrapper;
