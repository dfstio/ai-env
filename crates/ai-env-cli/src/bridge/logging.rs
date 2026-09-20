//! Bridge logging: `tracing` to a private file only (stdout is the JSON
//! channel), every line scrubbed, `RUST_LOG` honoured only for our own
//! targets, and the HTTP/TLS/AWS crates hard-capped at `info`.
use crate::bridge::errors::BridgeError;
use crate::wire::redact::ScrubMakeWriter;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{filter, fmt, EnvFilter, Layer, Registry};

/// Crates whose `debug`/`trace` events are dropped regardless of `RUST_LOG`:
/// exact match on the first `::` segment of the event target.
pub const CAPPED_CRATES: &[&str] = &[
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

/// Crate families capped the same way: prefix match on the first segment.
/// The SDK logs under `aws_smithy_runtime::…`, `aws_sdk_lambdamicrovms::…`,
/// `aws_config::…` — none of them an exact name in [`CAPPED_CRATES`].
pub const CAPPED_FAMILIES: &[&str] = &["aws_"];

/// Targets a bare `RUST_LOG` level expands to: the lib, the CLI and the wrapper bin.
const OUR_TARGETS: [&str; 3] = ["ai_env", "ai_env_cli", "ai_env_claude"];
const LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];

fn crate_of(target: &str) -> &str {
    target.split("::").next().unwrap_or(target)
}

/// Whether a `RUST_LOG` directive target is one of ours (`ai_env`,
/// `ai_env_cli`, `ai_env_claude`, with or without a `::` suffix).
fn ours(target: &str) -> bool {
    let krate = crate_of(target);
    krate == "ai_env" || krate.starts_with("ai_env_")
}

/// `true` when the cap drops an event with this target and level: DEBUG and
/// TRACE from a capped crate or family. INFO and above always pass.
#[must_use]
pub fn is_capped(target: &str, level: Level) -> bool {
    if level <= Level::INFO {
        return false;
    }
    let krate = crate_of(target);
    CAPPED_CRATES.contains(&krate) || CAPPED_FAMILIES.iter().any(|f| krate.starts_with(f))
}

/// Keep only our own directives from a `RUST_LOG` value; a bare level applies
/// to `ai_env`, `ai_env_cli` and `ai_env_claude`. Everything else logs at
/// `info` at most.
#[must_use]
pub fn restrict_rust_log(raw: &str) -> String {
    let mut out = vec!["info".to_string()];
    for d in raw.split(',').map(str::trim).filter(|d| !d.is_empty()) {
        match d.split_once('=') {
            Some((target, level)) => {
                let target = target.trim();
                if ours(target) {
                    out.push(format!("{target}={}", level.trim()));
                }
            }
            None => {
                let l = d.to_ascii_lowercase();
                if LEVELS.contains(&l.as_str()) {
                    out.extend(OUR_TARGETS.iter().map(|t| format!("{t}={l}")));
                }
            }
        }
    }
    out.join(",")
}

/// One event's bytes. The fmt layer hands each event to a fresh writer and
/// drops it; the buffer reaches the shared sink in a single `write_all` at
/// that point, so two threads can never interleave inside a line.
struct EventWriter<W: Write + Send> {
    sink: Arc<Mutex<W>>,
    buf: Vec<u8>,
}

impl<W: Write + Send> Write for EventWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // The bytes leave in one piece on drop; nothing to push early.
        Ok(())
    }
}

impl<W: Write + Send> Drop for EventWriter<W> {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        let _ = sink.write_all(&self.buf).and_then(|()| sink.flush());
    }
}

/// The layer/filter stack over `sink`: `RUST_LOG` restricted to our targets,
/// the cap on the HTTP/TLS/AWS crates, every line scrubbed, one write per
/// event. `init` and `build_subscriber_for_test` share it so both paths apply
/// the same cap.
fn subscriber_with_filter<W>(sink: Arc<Mutex<W>>, rust_log: &str) -> impl tracing::Subscriber + Send + Sync
where
    W: Write + Send + 'static,
{
    let env = EnvFilter::try_new(restrict_rust_log(rust_log)).unwrap_or_else(|_| EnvFilter::new("info"));
    let layer = fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_writer(ScrubMakeWriter(move || EventWriter { sink: sink.clone(), buf: Vec::new() }))
        .with_filter(filter::filter_fn(|meta| !is_capped(meta.target(), *meta.level())))
        .with_filter(env);
    Registry::default().with(layer)
}

pub struct LogOpts {
    pub path: PathBuf,
    pub rust_log: Option<String>,
}

/// The log directory: created 0700 when missing, tightened to 0700 when it
/// pre-exists wider, refused when it is a symlink or not a directory.
fn prepare_log_dir(dir: &Path) -> Result<(), BridgeError> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(BridgeError::Config(format!("{} is a symlink; refusing to log through it", dir.display()))),
        Ok(meta) if !meta.is_dir() => Err(BridgeError::Config(format!("{} is not a directory", dir.display()))),
        Ok(meta) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
                }
            }
            #[cfg(not(unix))]
            let _ = meta;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Prepare `<root>/logs` and open `<root>/logs/wrapper.log`: 0600, append,
/// no symlink following, and fchmod'ed back to 0600 when it pre-existed
/// wider. Split from `init` so the tests can exercise it without installing
/// a global subscriber.
pub fn open_log_file(path: &Path) -> Result<std::fs::File, BridgeError> {
    if let Some(dir) = path.parent() {
        prepare_log_dir(dir)?;
    }
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
        o.custom_flags(libc::O_NOFOLLOW);
    }
    let file = o.open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(BridgeError::Config(format!("{} is not a regular file", path.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            // fchmod on the descriptor we hold, not a chmod by path.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(file)
}

/// Open `<root>/logs/wrapper.log` (0700 dir, 0600 file, append, no symlink
/// following) and install the global subscriber. Never writes to stdout.
pub fn init(opts: &LogOpts) -> Result<(), BridgeError> {
    let file = open_log_file(&opts.path)?;
    let rust_log = opts.rust_log.clone().unwrap_or_default();
    let sub = subscriber_with_filter(Arc::new(Mutex::new(file)), &rust_log);
    tracing::subscriber::set_global_default(sub).map_err(|e| BridgeError::Config(format!("tracing already initialised: {e}")))
}

/// The same stack over an in-memory sink, for tests.
pub fn build_subscriber_for_test(sink: Arc<Mutex<Vec<u8>>>, rust_log: &str) -> impl tracing::Subscriber + Send + Sync {
    subscriber_with_filter(sink, rust_log)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured(rust_log: &str, emit: impl FnOnce()) -> String {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let sub = build_subscriber_for_test(sink.clone(), rust_log);
        tracing::subscriber::with_default(sub, emit);
        let bytes = sink.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn restrict_rust_log_kats() {
        assert_eq!(restrict_rust_log("trace"), "info,ai_env=trace,ai_env_cli=trace,ai_env_claude=trace");
        assert_eq!(restrict_rust_log("hyper=trace,ai_env_cli::bridge=debug"), "info,ai_env_cli::bridge=debug");
        assert_eq!(restrict_rust_log("ai_env_claude=debug, ai_env=warn ,ai_env_cli::wire::pump=trace"), "info,ai_env_claude=debug,ai_env=warn,ai_env_cli::wire::pump=trace");
        assert_eq!(restrict_rust_log(""), "info");
        assert_eq!(restrict_rust_log("aws_sdk_lambdamicrovms=trace"), "info");
        assert_eq!(restrict_rust_log("aws_smithy_runtime::client=trace,hyper_util=debug"), "info");
        assert_eq!(restrict_rust_log("ai_envelope=trace,bogus,off"), "info", "only our crates, only real levels");
    }

    #[test]
    fn cap_matches_crate_segment_and_aws_family() {
        assert!(is_capped("aws_sdk_lambdamicrovms::operation::run_microvm", Level::TRACE));
        assert!(is_capped("aws_smithy_runtime::client::orchestrator", Level::DEBUG));
        assert!(is_capped("aws_config::profile::credentials", Level::TRACE));
        assert!(is_capped("aws_runtime", Level::DEBUG));
        assert!(is_capped("hyper_util::client::legacy::pool", Level::DEBUG));
        assert!(is_capped("hyper", Level::TRACE));
        assert!(is_capped("rustls::client::hs", Level::TRACE));
        assert!(!is_capped("aws_smithy_runtime::client", Level::INFO));
        assert!(!is_capped("aws_sdk_lambdamicrovms", Level::WARN));
        assert!(!is_capped("hyper::proto", Level::ERROR));
        assert!(!is_capped("hyperx::y", Level::TRACE), "exact first segment, not a prefix");
        assert!(!is_capped("awsx::y", Level::TRACE), "the family needs the underscore");
        assert!(!is_capped("ai_env_claude::pump", Level::TRACE));
        assert!(!is_capped("ai_env_cli::bridge", Level::TRACE));
        assert!(!is_capped("ai_env", Level::DEBUG));
    }

    #[test]
    fn subscriber_caps_sdk_targets_under_rust_log_trace() {
        let text = captured("trace", || {
            tracing::trace!(target: "aws_sdk_lambdamicrovms::x", "sdk trace dropped");
            tracing::trace!(target: "aws_smithy_runtime::x", "smithy trace dropped");
            tracing::debug!(target: "aws_config::x", "config debug dropped");
            tracing::info!(target: "aws_sdk_lambdamicrovms::x", "sdk info kept");
            tracing::info!(target: "aws_smithy_runtime::x", "smithy info kept");
            tracing::trace!(target: "ai_env_claude::x", "wrapper trace kept");
            tracing::trace!(target: "ai_env_cli::bridge", "cli trace kept");
            tracing::trace!(target: "ai_env::x", "lib trace kept");
        });
        assert!(!text.contains("dropped"), "{text}");
        assert!(text.contains("sdk info kept"), "{text}");
        assert!(text.contains("smithy info kept"), "{text}");
        assert!(text.contains("wrapper trace kept"), "{text}");
        assert!(text.contains("cli trace kept"), "{text}");
        assert!(text.contains("lib trace kept"), "{text}");
    }

    #[test]
    fn subscriber_ignores_foreign_rust_log_directives() {
        let text = captured("aws_sdk_lambdamicrovms=trace,hyper=trace", || {
            tracing::trace!(target: "aws_sdk_lambdamicrovms::x", "sdk trace dropped");
            tracing::debug!(target: "hyper::proto", "hyper debug dropped");
            tracing::warn!(target: "hyper::proto", "hyper warn kept");
        });
        assert!(!text.contains("dropped"), "{text}");
        assert!(text.contains("hyper warn kept"), "{text}");
    }

    /// Counts `write` calls: with one `write_all` per event and a sink that
    /// takes every byte, the count is the number of events.
    struct Counting {
        buf: Vec<u8>,
        writes: usize,
    }

    impl Write for Counting {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.buf.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn one_write_per_event() {
        let sink = Arc::new(Mutex::new(Counting { buf: Vec::new(), writes: 0 }));
        let sub = subscriber_with_filter(sink.clone(), "");
        tracing::subscriber::with_default(sub, || {
            tracing::info!(target: "ai_env_cli::bridge", "first");
            tracing::warn!(target: "ai_env_cli::bridge", spawn = 7, attempt = 2, "second");
            tracing::trace!(target: "ai_env_cli::bridge", "filtered out, never written");
        });
        let c = sink.lock().unwrap();
        let text = String::from_utf8_lossy(&c.buf);
        assert_eq!(c.writes, 2, "{text}");
        assert_eq!(text.lines().count(), 2, "{text}");
        assert!(text.ends_with('\n'), "{text:?}");
    }

    #[test]
    fn concurrent_events_never_interleave() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let dispatch = tracing::Dispatch::new(subscriber_with_filter(sink.clone(), ""));
        let threads: Vec<_> = (0..4)
            .map(|t| {
                let d = dispatch.clone();
                std::thread::spawn(move || {
                    tracing::dispatcher::with_default(&d, || {
                        for i in 0..250 {
                            tracing::info!(target: "ai_env_cli::bridge", "thread {t} event {i} END");
                        }
                    });
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let text = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1000);
        for l in &lines {
            assert!(l.ends_with(" END"), "{l:?}");
            assert_eq!(l.matches("thread ").count(), 1, "{l:?}");
            assert_eq!(l.matches(" INFO ").count(), 1, "{l:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn log_dir_and_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();

        // A symlinked logs dir is refused before anything is opened.
        let root = tmp.path().join("sym");
        std::fs::create_dir_all(root.join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere"), root.join("logs")).unwrap();
        let path = root.join("logs").join("wrapper.log");
        // `open_log_file` is the file side of `init`; calling it directly keeps
        // the process-wide tracing default untouched (other tests share it).
        let err = open_log_file(&path).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(!path.exists());

        // A fresh root gets logs/ 0700 and wrapper.log 0600.
        let root = tmp.path().join("fresh");
        let path = root.join("logs").join("wrapper.log");
        drop(open_log_file(&path).unwrap());
        assert_eq!(std::fs::metadata(root.join("logs")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        // Pre-existing wider bits are tightened; the descriptor is append-only.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(root.join("logs"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut f = open_log_file(&path).unwrap();
        assert_eq!(std::fs::metadata(root.join("logs")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&path, "first\n").unwrap();
        f.write_all(b"second\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\nsecond\n");

        // A symlinked log file is refused too (O_NOFOLLOW), a directory as well.
        let target = tmp.path().join("target.log");
        std::fs::write(&target, "").unwrap();
        let link = root.join("logs").join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_log_file(&link).is_err());
        assert!(open_log_file(&root.join("logs")).is_err());
    }
}
