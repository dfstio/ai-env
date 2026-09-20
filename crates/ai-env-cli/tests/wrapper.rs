//! Wrapper tests — compiled only with `bridge` (`CARGO_BIN_EXE_ai-env-claude`
//! is unset otherwise). std::process only (assert_cmd is not vendored).
use std::path::{Path, PathBuf};
use std::process::Command;

fn wrapper() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env-claude")
}

/// `MAJOR.MINOR.PATCH` with an optional `-prerelease` suffix (`0.2.0-rc.1`).
fn is_semver(tok: &str) -> bool {
    let (core, pre) = match tok.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (tok, None),
    };
    let mut parts = core.split('.');
    let three = (0..3).all(|_| parts.next().is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())));
    let no_more = parts.next().is_none();
    let pre_ok = pre.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'));
    three && no_more && pre_ok
}

/// The first semver token of a `--version` banner: the last whitespace token
/// is not it once a pre-release or a build annotation follows the name.
fn semver_token(banner: &str) -> Option<&str> {
    banner.split_whitespace().find(|t| is_semver(t))
}

fn version_token(bin: &str) -> String {
    let out = Command::new(bin).arg("--version").output().expect("spawn");
    assert!(out.status.success(), "{bin} --version failed: {}", String::from_utf8_lossy(&out.stderr));
    let banner = String::from_utf8(out.stdout).unwrap();
    semver_token(&banner).unwrap_or_else(|| panic!("no version token in {banner:?}")).to_string()
}

#[test]
fn semver_token_parses_pre_release_banners() {
    assert_eq!(semver_token("ai-env-claude 0.2.0-rc.1\n"), Some("0.2.0-rc.1"));
    assert_eq!(semver_token("ai-env 0.2.0\n"), Some("0.2.0"));
    assert_eq!(semver_token("ai-env 0.2.0 (58b0d22 2026-09-19)"), Some("0.2.0"));
    assert_eq!(semver_token("ai-env-claude 10.0.3-beta-2 arm64"), Some("10.0.3-beta-2"));
    assert_eq!(semver_token("ai-env-claude v2 build 7"), None);
    assert_eq!(semver_token("1.2"), None);
    assert_eq!(semver_token("1.2.3.4"), None);
    assert_eq!(semver_token("1.2.3-"), None);
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

    /// The token prefix the scrubber keys on. Fixtures are assembled at
    /// runtime so no token-shaped literal lives in the source.
    const TOKEN_PREFIX: &str = "sk-ant-";

    #[test]
    fn logging_scrubs_registered_token() {
        let tok = format!("{TOKEN_PREFIX}oat01-{}", "X".repeat(20));
        register_secret(&tok);
        let text = captured("ai_env_cli=trace", || {
            tracing::info!(target: "ai_env_cli::bridge", token = tok.as_str(), "unseal");
        });
        assert!(text.contains("unseal"), "{text}");
        assert!(text.contains("[redacted"), "{text}");
        assert!(!text.contains("XXXXXXXX"), "{text}");
    }

    #[test]
    fn logging_scrubs_registered_value_via_subscriber() {
        // Registered: masked wherever it appears, message text included.
        let secret = format!("hunter{}-{}", 2, "quiet".repeat(4));
        register_secret(&secret);
        // Never registered, but token-shaped: the shape rule catches it.
        let shaped = format!("{TOKEN_PREFIX}api03-{}", "Y".repeat(24));
        let text = captured("ai_env_cli=trace", || {
            tracing::info!(target: "ai_env_cli::bridge", "before {secret} after");
            tracing::info!(target: "ai_env_cli::bridge", "left {shaped} right");
        });
        assert!(!text.contains(&secret), "{text}");
        assert!(!text.contains(&shaped), "{text}");
        assert!(!text.contains("YYYYYYYY"), "{text}");
        assert!(text.contains(&format!("before [redacted:len={}] after", secret.len())), "{text}");
        assert!(text.contains(&format!("left {TOKEN_PREFIX}[redacted:len={}] right", shaped.len())), "{text}");
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

// ---- M05: `ai-env gates --only` never evaluates go/no-go or writes the file ----

mod gates {
    use std::process::Command;

    /// `ai-env gates --out <tmp>/gates.md <args>` with `HOME=<tmp>`. G8 is a
    /// manual gate, so nothing external (network, AWS, tools) is touched.
    fn run(args: &[&str]) -> (std::process::Output, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ai-env"))
            .arg("gates")
            .arg("--out")
            .arg(tmp.path().join("gates.md"))
            .args(args)
            .env("HOME", tmp.path())
            .output()
            .expect("spawn ai-env");
        (out, tmp)
    }

    #[test]
    fn unknown_id_is_a_usage_error() {
        let (out, tmp) = run(&["--only", "G9", "--json"]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        assert!(err.contains("unknown gate id"), "{err}");
        assert!(!tmp.path().join("gates.md").exists());
    }

    #[test]
    fn only_run_is_partial_and_writes_nothing() {
        let (out, tmp) = run(&["--only", "G8", "--json"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
        assert!(stdout.contains("\"go\":false"), "{stdout}");
        assert!(stdout.contains("\"partial\":true"), "{stdout}");
        assert!(stdout.contains("\"id\":\"G8\""), "{stdout}");
        assert!(!tmp.path().join("gates.md").exists(), "--only must not write the file");
    }

    #[test]
    fn only_run_text_mode_says_partial() {
        let (out, tmp) = run(&["--only", "g8"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
        assert!(stdout.contains("partial run (--only)"), "{stdout}");
        assert!(!stdout.lines().any(|l| l.starts_with("GO:") || l.starts_with("NO-GO:")), "no verdict on a partial run: {stdout}");
        assert!(!tmp.path().join("gates.md").exists(), "--only must not write the file");
    }

    #[test]
    fn only_run_with_a_blocking_gate_fails_without_a_verdict() {
        // G5 is manual (nothing external runs) and blocking: the subset fails
        // with exit 1, but no GO/NO-GO verdict may be issued.
        let (out, tmp) = run(&["--only", "G5"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
        assert!(stdout.contains("partial run (--only)"), "{stdout}");
        assert!(!stdout.contains("NO-GO") && !stderr.contains("NO-GO"), "no verdict on a partial run: {stdout}{stderr}");
        assert!(stderr.contains("go/no-go is not evaluated"), "{stderr}");
        assert!(!tmp.path().join("gates.md").exists(), "--only must not write the file");
    }
}
