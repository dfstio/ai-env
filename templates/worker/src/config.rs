//! `worker.toml` (see `worker.toml.example`): unknown keys are refused, so a typo never passes silently.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

/// The worker's config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The worker's id, as the deployer allowed it.
    pub worker_id: String,
    /// The relay's public address, `host:port`.
    pub relay: String,
    /// The name in the relay's certificate (else the host of `relay`).
    pub server_name: Option<String>,
    /// The relay CA's certificate (PEM): the only trust anchor.
    pub relay_ca: PathBuf,
    /// The relay id its challenge must carry, if set.
    pub expect_relay_id: Option<String>,
    /// Who signs the handshake.
    pub signer: Signer,
    /// The 0600 key file (`signer = "file"`).
    pub key_file: Option<PathBuf>,
    /// The agent's socket (`signer = "agent"`; else its default path).
    pub agent_socket: Option<PathBuf>,
    /// Calls at once (1 to 256; else the worker's default).
    pub max_in_flight: Option<usize>,
    /// The sources, `[[source]]` tables.
    #[serde(rename = "source")]
    pub sources: Vec<SourceConfig>,
}

/// Who signs the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signer {
    /// A key file (servers).
    File,
    /// The Mac's signing agent (`ai-env relay agent`).
    Agent,
}

/// One source.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceConfig {
    /// `EchoSource`.
    Echo { name: String },
    /// `HttpJsonSource`.
    HttpJson { name: String, base_url: String, paths: Vec<String>, timeout_ms: Option<u64> },
    // your own kinds here
}

impl Config {
    /// The config at `path`.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("{} does not parse", path.display()))
    }
}
