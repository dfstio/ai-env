//! my-worker: a worker behind the ai-env relay (from ai-env's `templates/worker`).
//!
//! `my-worker keygen --out <path>` makes its 0600 Ed25519 key and prints the public key, which the deployer
//! allows (`ai-env relay allow`); `check --config <path>` builds the worker and, without `--offline`, dials
//! the relay once; `run --config <path>` serves until SIGINT or SIGTERM. Logs go to stderr (`RUST_LOG`,
//! default `info`); nothing prints a private key.

mod config;
mod sources;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use ai_env_worker::keys::{self, SigningKey};
use ai_env_worker::signer::{AgentSigner, FileSigner, Signer};
use ai_env_worker::{RelayEndpoint, Worker};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "my-worker", version, about = "A worker behind the ai-env relay")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make the worker's Ed25519 key (a new 0600 file); prints only its public key
    Keygen {
        /// The key file to make
        #[arg(long)]
        out: PathBuf,
        /// Replace an existing key file
        #[arg(long)]
        force: bool,
    },
    /// Print the public key of a key file
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Build the worker from its config; without --offline, dial the relay once and report what it said
    Check {
        #[arg(long)]
        config: PathBuf,
        /// Stop once the worker is built: no network
        #[arg(long)]
        offline: bool,
    },
    /// Serve the sources until SIGINT or SIGTERM
    Run {
        #[arg(long)]
        config: PathBuf,
    },
}

fn main() -> ExitCode {
    // rustls's process default (reqwest's rustls has no provider of its own): aws-lc-rs, so no ring is built.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("my-worker: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Keygen { out, force } => {
            let key = SigningKey::generate()?;
            keys::write_key_file(&out, &key, force)?;
            println!("{}", key.public_key().text());
            Ok(())
        }
        Cmd::Pubkey { key } => {
            println!("{}", keys::read_key_file(&key)?.public_key().text());
            Ok(())
        }
        Cmd::Check { config, offline } => tokio::runtime::Runtime::new()?.block_on(check(&config, offline)),
        Cmd::Run { config } => tokio::runtime::Runtime::new()?.block_on(async {
            let worker = build(&config::Config::load(&config)?).await?;
            tracing::info!(worker_id = worker.worker_id(), key_fp = %worker.public_key().fingerprint(), "serving");
            worker.run_until(shutdown()).await?;
            Ok(())
        }),
    }
}

async fn check(path: &Path, offline: bool) -> Result<()> {
    let cfg = config::Config::load(path)?;
    let worker = build(&cfg).await?;
    if offline {
        println!("config ok: worker {}, {} source(s), key fp {}", worker.worker_id(), cfg.sources.len(), worker.public_key().fingerprint());
        return Ok(());
    }
    let r = worker.check().await?;
    println!("ok: relay {} (protocol {}), tunnel {}, whitelist {:016x}, {} source(s)", r.relay_id, r.protocol, r.tunnel_id, r.whitelist_version, r.sources);
    Ok(())
}

/// The worker of a config: the relay pinned to its CA, the signer, the sources.
async fn build(cfg: &config::Config) -> Result<Worker> {
    let ca = std::fs::read(&cfg.relay_ca).with_context(|| format!("relay_ca {}", cfg.relay_ca.display()))?;
    let mut endpoint = RelayEndpoint::new(&cfg.relay)?.ca_pem(&ca)?;
    if let Some(name) = &cfg.server_name {
        endpoint = endpoint.server_name(name)?;
    }
    if let Some(id) = &cfg.expect_relay_id {
        endpoint = endpoint.expect_relay_id(id)?;
    }
    let signer: Arc<dyn Signer> = match cfg.signer {
        config::Signer::File => Arc::new(FileSigner::open(cfg.key_file.as_ref().context("signer = \"file\" needs key_file")?)?),
        config::Signer::Agent => Arc::new(AgentSigner::connect(cfg.agent_socket.clone()).await?),
    };
    let mut builder = Worker::builder().worker_id(cfg.worker_id.clone()).relay(endpoint).signer(signer);
    if let Some(n) = cfg.max_in_flight {
        builder = builder.max_in_flight(n);
    }
    for source in sources::build_sources(&cfg.sources) {
        builder = builder.source(source);
    }
    Ok(builder.build()?)
}

/// SIGINT or SIGTERM.
async fn shutdown() {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("stopping");
}
