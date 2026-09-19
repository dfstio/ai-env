//! Wrapper tests — compiled only with `bridge` (`CARGO_BIN_EXE_ai-env-claude`
//! is unset otherwise). std::process only (assert_cmd is not vendored).
use std::path::{Path, PathBuf};
use std::process::Command;

fn wrapper() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env-claude")
}

fn version_token(bin: &str) -> String {
    let out = Command::new(bin).arg("--version").output().expect("spawn");
    assert!(out.status.success(), "{bin} --version failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().split_whitespace().last().expect("version token").to_string()
}

/// A fake `claude`: logs every argument on its own line to `$ARGV_LOG`.
struct FakeClaude {
    dir: tempfile::TempDir,
}

impl FakeClaude {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("claude");
        std::fs::write(&script, "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> \"$ARGV_LOG\"; done\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        FakeClaude { dir }
    }

    fn bin(&self) -> PathBuf {
        self.dir.path().join("claude")
    }

    fn log_path(&self) -> PathBuf {
        self.dir.path().join("argv.log")
    }

    fn logged(&self) -> Vec<String> {
        std::fs::read_to_string(self.log_path()).unwrap_or_default().lines().map(str::to_string).collect()
    }

    fn run(&self, args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
        let mut cmd = Command::new(wrapper());
        cmd.arg(self.bin()).args(args).env("ARGV_LOG", self.log_path());
        // Start from a known state: the kill switch is only set when a test asks for it.
        cmd.env_remove("AI_ENV_BRIDGE_LOCAL");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.output().expect("spawn wrapper")
    }
}

const STREAM_JSON: [&str; 9] = [
    "--output-format",
    "stream-json",
    "--verbose",
    "--input-format",
    "stream-json",
    "--permission-mode",
    "default",
    "--add-dir",
    "/Users/mike/other",
];

#[test]
fn bins_exist_side_by_side() {
    let w = Path::new(wrapper());
    let cli = Path::new(env!("CARGO_BIN_EXE_ai-env"));
    assert!(w.exists(), "{}", w.display());
    assert!(cli.exists(), "{}", cli.display());
    assert_eq!(w.parent(), cli.parent());
}

#[test]
fn wrapper_version_matches_ai_env() {
    assert_eq!(version_token(wrapper()), version_token(env!("CARGO_BIN_EXE_ai-env")));
    assert_eq!(version_token(wrapper()), env!("CARGO_PKG_VERSION"));
}

#[test]
fn local_route_execs_real_binary_verbatim() {
    let fake = FakeClaude::new();
    let out = fake.run(&["auth", "status", "--json"], &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fake.logged(), vec!["auth", "status", "--json"]);
}

#[test]
fn remote_stub_execs_locally_with_notice() {
    let fake = FakeClaude::new();
    let out = fake.run(&STREAM_JSON, &[]);
    assert_eq!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("ai-env-claude: remote route not implemented"), "{err}");
    let want: Vec<String> = STREAM_JSON.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(fake.logged(), want, "argv must pass through verbatim, --add-dir included");
}

#[test]
fn kill_switch_env_execs_locally_silently() {
    let fake = FakeClaude::new();
    let out = fake.run(&STREAM_JSON, &[("AI_ENV_BRIDGE_LOCAL", "1")]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fake.logged().len(), STREAM_JSON.len());
}

#[test]
fn missing_real_binary_exits_2() {
    let out = Command::new(wrapper()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("ai-env-claude: "), "{err}");
    assert!(err.contains("realBinary"), "{err}");
}

#[test]
fn unexecutable_real_binary_exits_1() {
    let out = Command::new(wrapper()).arg("/nonexistent/claude").arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot exec"));
}

// ---- T0.5: logging scrubs and caps -------------------------------------------

mod logging {
    use ai_env_cli::bridge::logging::build_subscriber_for_test;
    use ai_env_cli::wire::redact::register_secret;
    use std::sync::{Arc, Mutex};

    fn captured(rust_log: &str, emit: impl FnOnce()) -> String {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let sub = build_subscriber_for_test(sink.clone(), rust_log);
        tracing::subscriber::with_default(sub, emit);
        let bytes = sink.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn logging_scrubs_registered_token() {
        register_secret("sk-ant-oat01-SECRETSECRETSECRET");
        let text = captured("ai_env_cli=trace", || {
            tracing::info!(target: "ai_env_cli::bridge", token = "sk-ant-oat01-SECRETSECRETSECRET", "unseal");
        });
        assert!(text.contains("unseal"), "{text}");
        assert!(text.contains("[redacted"), "{text}");
        assert!(!text.contains("SECRETSECRET"), "{text}");
    }

    #[test]
    fn logging_caps_hyper_trace_despite_rust_log() {
        let text = captured("trace", || {
            tracing::trace!(target: "hyper::proto::h1", "should be capped");
            tracing::info!(target: "hyper", "kept at info");
            tracing::trace!(target: "ai_env_cli::wire", "visible");
        });
        assert!(!text.contains("should be capped"), "{text}");
        assert!(text.contains("kept at info"), "{text}");
        assert!(text.contains("visible"), "{text}");
    }
}
