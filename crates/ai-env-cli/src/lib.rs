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

/// Test-only serialisation of two operations the macOS kernel races: a
/// fork in one thread (the shim's spawns use `pre_exec`, which forces fork
/// over posix_spawn) can undo another thread's concurrent `mprotect`, and
/// the prekey's guarded page then faults (SIGBUS, seen in S6 when the spawn
/// tests ran beside `edit::cells`). Forks share the lock; a prekey's
/// protection window takes it alone. Production code never forks while a
/// prekey exists, so nothing outside `cfg(test)` holds it.
#[cfg(test)]
pub(crate) mod test_locks {
    use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

    static FORK_VS_MPROTECT: RwLock<()> = RwLock::new(());

    /// Held across a fork (only the shim forks).
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn forking() -> RwLockReadGuard<'static, ()> {
        FORK_VS_MPROTECT.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Held across an mprotect window of guarded memory.
    pub(crate) fn mprotecting() -> RwLockWriteGuard<'static, ()> {
        FORK_VS_MPROTECT.write().unwrap_or_else(PoisonError::into_inner)
    }
}
