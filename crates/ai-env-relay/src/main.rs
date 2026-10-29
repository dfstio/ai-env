//! `ai-env-relay`: run (the config from the environment), `check [--env-file PATH]`, `--version`
//! (plans/s13-contracts.md §R-relay.2.3).
//!
//! Exit codes: run 0 after a clean stop, 1 on a runtime failure (a bind, a server error), 2 when the config is
//! refused; `check` 0 when the four live files are loaded and the three JSON lists fresh, 1 otherwise, 2 when the
//! config is refused. `check` binds nothing and writes nothing, and never prints a key, a glob or a source name.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use ai_env_relay::config::{Config, DEFAULT_ENV_FILE};
use ai_env_relay::files::{Live, Loaded, Poll, TLS_FILE};
use ai_env_relay::lists::{GRANTS_FILE, SIGNERS_FILE, WORKERS_FILE};
use ai_env_relay::{Deps, RelayApp, RELAY_VERSION};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ai-env-relay", about = "The ai-env relay: workers on 443, MicroVM agents on the private face.", disable_version_flag = true)]
struct Cli {
    /// Print `ai-env-relay <version> (protocol <n>)`.
    #[arg(long, short = 'V')]
    version: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Load the config and the live files once, print one line per file, exit.
    Check {
        /// The env file (systemd's EnvironmentFile syntax).
        #[arg(long, value_name = "PATH", default_value = DEFAULT_ENV_FILE)]
        env_file: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.version {
        println!("ai-env-relay {RELAY_VERSION} (protocol {})", ai_env_relay_proto::PROTOCOL);
        return ExitCode::SUCCESS;
    }
    match cli.command {
        Some(Command::Check { env_file }) => check(&env_file),
        None => run(),
    }
}

/// Logging to stderr without ANSI: `RUST_LOG` (default `info`), the transport crates held at `warn` (§R-relay.2.3).
fn logging() {
    use tracing_subscriber::EnvFilter;
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    for quiet in ["h2=warn", "hyper=warn", "rustls=warn", "tonic=warn", "tower=warn"] {
        if let Ok(d) = quiet.parse() {
            filter = filter.add_directive(d);
        }
    }
    tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(std::io::stderr).init();
}

/// The `AI_ENV_RELAY_*` names of the process environment (the only ones `run` reads, with `RUST_LOG`,
/// `NOTIFY_SOCKET`, `WATCHDOG_USEC` and `WATCHDOG_PID`).
fn relay_vars() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(k, v)| {
            let k = k.into_string().ok()?;
            k.starts_with("AI_ENV_RELAY_").then_some(())?;
            Some((k, v.into_string().unwrap_or_default()))
        })
        .collect()
}

fn run() -> ExitCode {
    logging();
    let (cfg, warnings) = match Config::from_vars(relay_vars()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("config refused: {e}");
            return ExitCode::from(2);
        }
    };
    for w in warnings {
        tracing::warn!("{w}");
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("runtime: {e}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(async move {
        let deps = match Deps::production(&cfg) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("{e}");
                return ExitCode::from(1);
            }
        };
        let app = match RelayApp::new(cfg, deps) {
            Ok(app) => app,
            Err(e) => {
                tracing::error!("{e}");
                return ExitCode::from(2);
            }
        };
        tokio::spawn(signals(app.clone()));
        match app.run().await {
            Ok(()) => {
                tracing::info!("stopped");
                ExitCode::SUCCESS
            }
            Err(e) => {
                tracing::error!("{e}");
                ExitCode::from(1)
            }
        }
    })
}

/// SIGTERM and SIGINT stop (R-71); SIGHUP polls the live files at once (R-15, I's `ExecReload=`).
async fn signals(app: RelayApp) {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup())) else {
        tracing::error!("signal handlers could not be installed");
        return;
    };
    loop {
        tokio::select! {
            _ = term.recv() => break,
            _ = int.recv() => break,
            _ = hup.recv() => {
                app.poll_files();
            }
        }
    }
    app.shutdown();
}

fn check(env_file: &Path) -> ExitCode {
    let vars = match Config::read_env_file(env_file) {
        Ok(v) => v,
        Err(e) => {
            println!("config: refused ({e})");
            return ExitCode::from(2);
        }
    };
    let (cfg, warnings) = match Config::from_vars(vars) {
        Ok(c) => c,
        Err(e) => {
            println!("config: refused ({e})");
            return ExitCode::from(2);
        }
    };
    for w in warnings {
        println!("config: warning ({w})");
    }
    let now = SystemTime::now();
    let max_stale = Duration::from_secs(u64::from(cfg.limits.max_stale_s));
    let live = Live::new(&cfg.live_dir);
    let polls = live.poll(now, max_stale);
    let mut ok = true;
    let names = [WORKERS_FILE, SIGNERS_FILE, GRANTS_FILE];
    let loaded = [entries_of(&live.workers.loaded()), entries_of(&live.signers.loaded()), entries_of(&live.grants.loaded())];
    for ((file, (_, poll)), info) in names.iter().zip(&polls).zip(loaded) {
        match (poll, info) {
            (Poll::Refused(text), _) => {
                ok = false;
                println!("{file}: refused ({text})");
            }
            (_, Some((version, entries, fresh_at))) => {
                let age = fresh_at.and_then(|t| now.duration_since(t).ok());
                if age.is_none_or(|a| a > max_stale) {
                    ok = false;
                }
                let age = age.map_or_else(|| "none".to_string(), |a| a.as_secs().to_string());
                println!("{file}: loaded version={version:016x} entries={entries} age_s={age}");
            }
            (_, None) => {
                ok = false;
                println!("{file}: missing");
            }
        }
    }
    match (&polls[3].1, live.tls.loaded()) {
        (Poll::Refused(text), _) => {
            ok = false;
            println!("{TLS_FILE}: refused ({text})");
        }
        (_, Some(_)) => {
            let leaf = std::fs::read(cfg.live_dir.join(TLS_FILE)).ok().and_then(|pem| leaf_sha256(&pem));
            let shown = leaf.map_or_else(|| "?".to_string(), |d| d[..6].iter().map(|b| format!("{b:02x}")).collect());
            println!("{TLS_FILE}: loaded leaf_sha256={shown}");
        }
        (_, None) => {
            ok = false;
            println!("{TLS_FILE}: missing");
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

type Described = Option<(u64, usize, Option<SystemTime>)>;

fn entries_of<T: Counted>(loaded: &Option<Loaded<T>>) -> Described {
    loaded.as_ref().map(|l| (l.version, l.value.count(), l.fresh_at))
}

trait Counted {
    fn count(&self) -> usize;
}

impl Counted for ai_env_relay::lists::Workers {
    fn count(&self) -> usize {
        self.entries.len()
    }
}

impl Counted for ai_env_relay::lists::Signers {
    fn count(&self) -> usize {
        self.entries.len()
    }
}

impl Counted for ai_env_relay::lists::Grants {
    fn count(&self) -> usize {
        self.entries.len()
    }
}

/// The SHA-256 of `tls.pem`'s first certificate (the leaf).
fn leaf_sha256(pem: &[u8]) -> Option<[u8; 32]> {
    use rustls_pki_types::pem::PemObject;
    let leaf = rustls_pki_types::CertificateDer::pem_slice_iter(pem).next()?.ok()?;
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, leaf.as_ref());
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    Some(out)
}
