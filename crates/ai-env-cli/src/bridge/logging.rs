//! Bridge logging: `tracing` to a private file only (stdout is the JSON
//! channel), every line scrubbed, `RUST_LOG` honoured only for this crate's
//! targets, and the HTTP/TLS/AWS crates hard-capped at `info`.
use crate::bridge::errors::BridgeError;
use crate::wire::redact::ScrubMakeWriter;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{filter, fmt, EnvFilter, Layer, Registry};

/// Crates whose events above `info` are dropped regardless of `RUST_LOG`.
pub const CAPPED_PREFIXES: &[&str] = &[
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
    "tungstenite",
    "tokio_tungstenite",
    "rustls",
    "aws_smithy",
    "aws_sdk",
    "aws_config",
    "aws_runtime",
    "aws_credential_types",
];

/// Keep only `ai_env_cli…` directives from a `RUST_LOG` value; a bare level
/// applies to this crate only. Everything else logs at `info` at most.
#[must_use]
pub fn restrict_rust_log(raw: &str) -> String {
    let mut out = vec!["info".to_string()];
    for d in raw.split(',').map(str::trim).filter(|d| !d.is_empty()) {
        match d.split_once('=') {
            Some((target, level)) => {
                if target.starts_with("ai_env_cli") {
                    out.push(format!("{target}={level}"));
                }
            }
            None => {
                let l = d.to_ascii_lowercase();
                if ["trace", "debug", "info", "warn", "error"].contains(&l.as_str()) {
                    out.push(format!("ai_env_cli={l}"));
                }
            }
        }
    }
    out.join(",")
}

fn capped(meta: &tracing::Metadata<'_>) -> bool {
    CAPPED_PREFIXES.iter().any(|p| meta.target() == *p || meta.target().starts_with(&format!("{p}::")))
        && *meta.level() > Level::INFO
}

/// Sink shared between the subscriber and the caller (tests) or the log file.
#[derive(Clone)]
struct Shared<W: Write + Send>(Arc<Mutex<W>>);

impl<W: Write + Send> Write for Shared<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).flush()
    }
}

fn subscriber_over<W>(sink: Arc<Mutex<W>>, rust_log: &str) -> impl tracing::Subscriber + Send + Sync
where
    W: Write + Send + 'static,
{
    let env = EnvFilter::try_new(restrict_rust_log(rust_log)).unwrap_or_else(|_| EnvFilter::new("info"));
    let layer = fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_writer(ScrubMakeWriter(move || Shared(sink.clone())))
        .with_filter(filter::filter_fn(|meta| !capped(meta)))
        .with_filter(env);
    Registry::default().with(layer)
}

pub struct LogOpts {
    pub path: PathBuf,
    pub rust_log: Option<String>,
}

/// Open `<root>/logs/wrapper.log` (0700 dir, 0600 file, append, no symlink
/// following) and install the global subscriber. Never writes to stdout.
pub fn init(opts: &LogOpts) -> Result<(), BridgeError> {
    if let Some(dir) = opts.path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        o.custom_flags(0x0100); // O_NOFOLLOW
        #[cfg(target_os = "linux")]
        o.custom_flags(0x2_0000); // O_NOFOLLOW
    }
    let file = o.open(&opts.path)?;
    let rust_log = opts.rust_log.clone().unwrap_or_default();
    let sub = subscriber_over(Arc::new(Mutex::new(file)), &rust_log);
    tracing::subscriber::set_global_default(sub).map_err(|e| BridgeError::Config(format!("tracing already initialised: {e}")))
}

/// The same stack over an in-memory sink, for tests.
pub fn build_subscriber_for_test(sink: Arc<Mutex<Vec<u8>>>, rust_log: &str) -> impl tracing::Subscriber + Send + Sync {
    subscriber_over(sink, rust_log)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restrict_rust_log_kats() {
        assert_eq!(restrict_rust_log("trace"), "info,ai_env_cli=trace");
        assert_eq!(restrict_rust_log("hyper=trace,ai_env_cli::bridge=debug"), "info,ai_env_cli::bridge=debug");
        assert_eq!(restrict_rust_log(""), "info");
        assert_eq!(restrict_rust_log("aws_sdk_lambdamicrovms=trace"), "info");
    }
}
