//! ai-env library: the classic Touch ID `.env` tool (eleven modules moved
//! verbatim from the old `src/main.rs`), the network-free wire protocol
//! (`wire`), and the feature-gated halves — `bridge` (Mac operator CLI +
//! the `ai-env-claude` wrapper) and `shim` (VM PID 1).
//!
//! Feature matrix: `default = ["bridge", "shim"]`; the VM image is built with
//! `--no-default-features --features shim`. Gating happens by module, clap
//! variant and doctor row only — never `cfg(feature)` inside function bodies.
pub mod age_cmd;
pub mod ceremony;
pub mod commands;
pub mod config;
pub mod container;
pub mod dotenv;
pub mod edit;
pub mod errors;
pub mod git;
pub mod select;
pub mod store;

pub mod cli;
pub mod wire;
#[cfg(feature = "bridge")]
pub mod bridge;
#[cfg(feature = "shim")]
pub mod shim;
