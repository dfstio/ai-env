//! Wrapper tests (T1.2) — compiled only with `bridge` (`CARGO_BIN_EXE_ai-env-claude`
//! is unset otherwise). std::process only (assert_cmd is not vendored). Every
//! wrapper run execs `tests/fakes/claude.sh` hard-linked into a tempdir (from
//! the fake cache of `tests/common`), with the child's `HOME` and
//! `AI_ENV_BRIDGE_DIR` pointed at that tempdir, so the census, `bridge.toml`
//! and the argv log never touch the developer's `~/.config/ai-env`. Nothing
//! here mutates the test process's environment: every variable is set on the
//! child `Command` (the `s7` signal tests set one signal's disposition around
//! a spawn, serialized, and put it back).
mod common;

use ai_env_cli::bridge::census::CENSUS_VALUE_ALLOWLIST;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn wrapper() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env-claude")
}

/// Variables a developer's shell may carry that would steer the wrapper (the
/// kill switch, the lab knobs, a config-path override, the S2 pump mode and
/// its knobs — a set mode would turn these exec tests into piped runs — and
/// what S7's `local-scratch` login reads: the token, the keystore directory
/// and its two lab knobs).
const WRAPPER_ENV: [&str; 13] = [
    "AI_ENV_BRIDGE_LOCAL",
    "AI_ENV_BRIDGE_LAB_EXIT",
    "AI_ENV_BRIDGE_CONFIG",
    "AI_ENV_BRIDGE_MODE",
    "AI_ENV_BRIDGE_MIRROR_ROOT",
    "AI_ENV_BRIDGE_LAB_IGNORE_EOF",
    "AI_ENV_BRIDGE_LAB_STDOUT_NOISE",
    "AI_ENV_BRIDGE_LAB_DELAY_INIT_MS",
    "AI_ENV_BRIDGE_LAB_REPLAY_DEADLINE_MS",
    "AI_ENV_BRIDGE_LAB_SYNTHETIC_OAUTH_MS",
    "AI_ENV_BRIDGE_LAB_UNSEAL_TIMEOUT_MS",
    "AI_ENV_DIR",
    "CLAUDE_CODE_OAUTH_TOKEN",
];

/// Lossy text of a captured stream, for assertions and their messages.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
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
    assert!(out.status.success(), "{bin} --version failed: {}", text(&out.stderr));
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

/// `tests/fakes/claude.sh` hard-linked into a tempdir as `claude` (0755; one
/// cached master per content, so macOS assesses only the master's first
/// exec): it logs every argument to `$ARGV_LOG`, prints `$FAKE_STDOUT` when
/// set, copies stdin to stdout when `FAKE_ECHO_STDIN=1` and exits
/// `${FAKE_EXIT:-0}`. The same tempdir is the child's `HOME`, and
/// `<tmp>/bridge` its `AI_ENV_BRIDGE_DIR`, so `bridge.toml`, the census and
/// the argv log all live under it.
struct FakeClaude {
    dir: tempfile::TempDir,
}

impl FakeClaude {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        common::install_fake_v1(&dir.path().join("claude"));
        FakeClaude { dir }
    }

    /// The tempdir: the child's `HOME`, and the cwd of the session tests.
    fn tmp(&self) -> &Path {
        self.dir.path()
    }

    fn bin(&self) -> PathBuf {
        self.dir.path().join("claude")
    }

    fn log_path(&self) -> PathBuf {
        self.dir.path().join("argv.log")
    }

    /// Every argument the fake received, in order; empty when it never ran.
    fn logged(&self) -> Vec<String> {
        std::fs::read_to_string(self.log_path()).unwrap_or_default().lines().map(str::to_string).collect()
    }

    /// The child's `AI_ENV_BRIDGE_DIR`.
    fn bridge_dir(&self) -> PathBuf {
        self.dir.path().join("bridge")
    }

    fn census_path(&self) -> PathBuf {
        self.bridge_dir().join("logs").join("census.jsonl")
    }

    /// `wrapper <real> <args…>` with the child's environment prepared: the
    /// argv log, `HOME` and `AI_ENV_BRIDGE_DIR` set; [`WRAPPER_ENV`] removed
    /// (a developer's shell may carry them); then `envs` applied in order, so
    /// a test may set any of them. The cwd is left to the caller.
    fn command(&self, real: &Path, args: &[&str], envs: &[(&str, &str)]) -> Command {
        let mut cmd = Command::new(wrapper());
        cmd.arg(real).args(args);
        cmd.env("ARGV_LOG", self.log_path()).env("HOME", self.tmp()).env("AI_ENV_BRIDGE_DIR", self.bridge_dir());
        for k in WRAPPER_ENV {
            cmd.env_remove(k);
        }
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd
    }

    fn run(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        self.command(&self.bin(), args, envs).output().expect("spawn wrapper")
    }

    /// `run` with the child's cwd set (the route reads it against the roots).
    fn run_in(&self, cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
        self.command(&self.bin(), args, envs).current_dir(cwd).output().expect("spawn wrapper")
    }

    /// `run` with the child's `PATH` set.
    fn run_with_path(&self, args: &[&str], envs: &[(&str, &str)], path: &str) -> Output {
        self.command(&self.bin(), args, envs).env("PATH", path).output().expect("spawn wrapper")
    }

    /// `run` with argv[1] overridden (a bare name, a missing path).
    fn run_with_real(&self, real: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
        self.command(real, args, envs).output().expect("spawn wrapper")
    }

    /// Write `<tmp>/bridge/bridge.toml`.
    fn with_bridge_toml(&self, text: &str) {
        std::fs::create_dir_all(self.bridge_dir()).unwrap();
        std::fs::write(self.bridge_dir().join("bridge.toml"), text).unwrap();
    }

    /// A `bridge.toml` whose only workspace root is `root`.
    fn roots_toml(root: &Path) -> String {
        format!("[workspaces]\nroots = [{root:?}]\n")
    }

    /// The raw census file; empty when absent.
    fn census_text(&self) -> String {
        std::fs::read_to_string(self.census_path()).unwrap_or_default()
    }

    /// Every census row, oldest first; empty when the file is absent. A line
    /// that does not parse is a failure (a torn write), never skipped.
    fn census(&self) -> Vec<serde_json::Value> {
        self.census_text().lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("census line {l:?}: {e}"))).collect()
    }

    /// The one row a single run must have left.
    fn only_row(&self) -> serde_json::Value {
        let rows = self.census();
        assert_eq!(rows.len(), 1, "expected exactly one census row: {rows:?}");
        rows.into_iter().next().unwrap()
    }
}

/// The `argv` array of a census row as strings.
fn row_argv(row: &serde_json::Value) -> Vec<&str> {
    row["argv"].as_array().expect("argv array").iter().map(|v| v.as_str().expect("argv string")).collect()
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

const AUTH_STATUS: [&str; 3] = ["auth", "status", "--json"];

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
    let out = fake.run(&AUTH_STATUS, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), AUTH_STATUS);

    let row = fake.only_row();
    assert_eq!(row["v"], 1);
    assert_eq!(row["route"], "local");
    assert_eq!(row["reason"], "subcommand:auth");
    let argv = row_argv(&row);
    assert_eq!(argv[0], wrapper(), "argv[0] is the wrapper");
    assert_eq!(Some(argv[1]), fake.bin().to_str(), "argv[1] is the real binary");
    assert_eq!(&argv[2..], &AUTH_STATUS[..]);
    assert_eq!(row["ppid"], std::process::id(), "the parent is this test process");
    assert!(row["ext"].is_null(), "the fake is not under an extension bundle");
    assert!(row["note"].is_null());
    assert!(row.get("end").is_none() && row.get("exit").is_none(), "exec leaves no end/exit: {row}");
}

#[test]
fn remote_route_execs_locally_verbatim_and_censuses() {
    // With a bridge.toml whose root is the cwd: a remote row, silent, verbatim.
    let fake = FakeClaude::new();
    fake.with_bridge_toml(&FakeClaude::roots_toml(fake.tmp()));
    let out = fake.run_in(fake.tmp(), &STREAM_JSON, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "the remote route is silent in S1: {}", text(&out.stderr));
    assert_eq!(fake.logged(), STREAM_JSON, "argv must pass through verbatim, --add-dir included");
    let row = fake.only_row();
    assert_eq!(row["route"], "remote");
    assert_eq!(row["reason"], "session");
    assert_eq!(&row_argv(&row)[2..], &STREAM_JSON[..], "nothing in a session argv needs redacting");
    let cwd = row["cwd"].as_str().expect("cwd recorded");
    assert_eq!(std::fs::canonicalize(cwd).unwrap(), std::fs::canonicalize(fake.tmp()).unwrap());
    assert!(row["note"].is_null(), "{row}");

    // Without a bridge.toml: the same argv is a local row, reason unconfigured — still silent, still verbatim.
    let plain = FakeClaude::new();
    let out = plain.run_in(plain.tmp(), &STREAM_JSON, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    assert_eq!(plain.logged(), STREAM_JSON);
    let row = plain.only_row();
    assert_eq!(row["route"], "local");
    assert_eq!(row["reason"], "unconfigured");
    assert!(row["note"].is_null(), "an absent bridge.toml is not worth a note: {row}");
}

#[test]
fn outside_roots_routes_local() {
    let fake = FakeClaude::new();
    let other = tempfile::tempdir().unwrap();
    fake.with_bridge_toml(&FakeClaude::roots_toml(other.path()));
    let out = fake.run_in(fake.tmp(), &STREAM_JSON, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), STREAM_JSON, "argv is verbatim outside the roots too");
    let row = fake.only_row();
    assert_eq!(row["route"], "local");
    assert_eq!(row["reason"], "outside_roots");
    assert!(row["note"].is_null(), "{row}");

    // The same config from inside its root: remote — the roots were read, not ignored.
    let out = fake.run_in(other.path(), &STREAM_JSON, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let rows = fake.census();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["route"], "remote");
    assert_eq!(rows[1]["reason"], "session");
}

#[test]
fn kill_switch_env_execs_locally_silently() {
    let fake = FakeClaude::new();
    let out = fake.run(&STREAM_JSON, &[("AI_ENV_BRIDGE_LOCAL", "1")]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), STREAM_JSON);
    assert!(fake.census().is_empty(), "the kill switch records nothing");
    assert!(!fake.census_path().exists());
    assert!(!fake.bridge_dir().exists(), "the kill switch reads no config and creates no state");
}

#[test]
fn census_records_env_names_only() {
    let fake = FakeClaude::new();
    // Built at runtime so no token-shaped literal lives in the source.
    let canary = format!("{}oat01-{}", "sk-ant-", "X".repeat(20));
    let out = fake.run(&AUTH_STATUS, &[("AI_ENV_TEST_CANARY", &canary)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), AUTH_STATUS);

    let file = fake.census_text();
    assert!(!file.contains(&canary), "the canary value reached the census file");
    assert!(!file.contains(&"X".repeat(20)), "a fragment of the canary value reached the census file");
    assert!(!file.contains("argv.log"), "ARGV_LOG is not allowlisted: its value must not be recorded either");

    let row = fake.only_row();
    let names: Vec<&str> = row["env_names"].as_array().expect("env_names").iter().map(|v| v.as_str().unwrap()).collect();
    assert!(names.contains(&"AI_ENV_TEST_CANARY"), "{names:?}");
    assert!(names.contains(&"ARGV_LOG") && names.contains(&"HOME") && names.contains(&"AI_ENV_BRIDGE_DIR"), "{names:?}");
    assert!(names.windows(2).all(|w| w[0] < w[1]), "sorted and deduplicated: {names:?}");
    let selected = row["env_selected"].as_object().expect("env_selected");
    assert!(!selected.contains_key("AI_ENV_TEST_CANARY"));
    for key in selected.keys() {
        assert!(CENSUS_VALUE_ALLOWLIST.contains(&key.as_str()), "{key} is not allowlisted but its value was recorded");
    }

    // An allowlisted variable whose value is token-shaped is recorded scrubbed.
    let fake = FakeClaude::new();
    let out = fake.run(&AUTH_STATUS, &[("CLAUDE_CONFIG_DIR", &format!("/x/{canary}"))]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let file = fake.census_text();
    assert!(!file.contains(&canary), "an allowlisted value reached the census unscrubbed");
    let row = fake.only_row();
    assert_eq!(row["env_selected"]["CLAUDE_CONFIG_DIR"], format!("/x/sk-ant-[redacted:len={}]", canary.len()), "{row}");
}

#[test]
fn local_fallback_ignores_relative_path_entries() {
    // The fake dir holds an executable `claude`; with PATH made of relative
    // and empty entries and the cwd there, the fallback must NOT find it.
    let fake = FakeClaude::new();
    let out = fake.command(Path::new("/nonexistent/claude"), &["--version"], &[("PATH", ".::./")]).current_dir(fake.tmp()).output().expect("spawn wrapper");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("cannot exec /nonexistent/claude"), "{}", text(&out.stderr));
    assert!(fake.logged().is_empty(), "the workspace-relative claude was exec'd");
    // A bare name resolves through the same PATH rule: never against the cwd.
    let bare = fake.command(Path::new("claude"), &["--version"], &[("PATH", ".")]).current_dir(fake.tmp()).output().expect("spawn wrapper");
    assert_eq!(bare.status.code(), Some(1), "{}", text(&bare.stderr));
    assert!(fake.logged().is_empty());
    // The absolute fake dir on PATH is what the bare name should reach.
    let ok = fake.command(Path::new("claude"), &["--version"], &[("PATH", &fake.tmp().to_string_lossy())]).current_dir(fake.tmp()).output().expect("spawn wrapper");
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok.stderr));
    assert_eq!(fake.logged(), ["--version"]);
}

#[test]
fn census_redacts_mcp_add_tail() {
    let fake = FakeClaude::new();
    let env_value = format!("v-{}", "q".repeat(24));
    let api_key = format!("k-{}", "y".repeat(24));
    let env_pair = format!("K={env_value}");
    let args = ["mcp", "add", "--scope", "user", "--transport", "stdio", "--env", &env_pair, "--", "github", "npx", "-y", "@x/server", "--api-key", &api_key];
    let out = fake.run(&args, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), args, "the fake receives the full argv, credentials included");
    assert_eq!(text(&out.stderr), "ai-env-claude: mcp add edits the Mac's ~/.claude.json; VM sessions see committed .mcp.json\n");

    let file = fake.census_text();
    assert!(!file.contains(&env_value) && !file.contains(&api_key), "a credential reached the census file");
    let row = fake.only_row();
    assert_eq!(row["route"], "local");
    assert_eq!(row["reason"], "subcommand:mcp");
    let want = ["mcp", "add", "--scope", "user", "--transport", "stdio", "--env", "K=[redacted:len=26]", "--", "github", "\u{2026}"];
    assert_eq!(&row_argv(&row)[2..], &want[..]);
    assert_eq!(row["note"], "mcp add edits the Mac's ~/.claude.json");
}

#[cfg(unix)]
#[test]
fn census_file_modes_0600_dir_0700() {
    use std::os::unix::fs::PermissionsExt;
    let fake = FakeClaude::new();
    let out = fake.run(&AUTH_STATUS, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let path = fake.census_path();
    assert_eq!(mode(path.parent().unwrap()), 0o700, "logs dir");
    assert_eq!(mode(&path), 0o600, "census file");
    assert_eq!(fake.census().len(), 1);
}

#[test]
fn census_survives_16_concurrent_wrappers() {
    let fake = FakeClaude::new();
    let children: Vec<_> = (0..16)
        .map(|_| fake.command(&fake.bin(), &AUTH_STATUS, &[]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn wrapper"))
        .collect();
    for child in children {
        let out = child.wait_with_output().expect("wait");
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    }
    let file = fake.census_text();
    assert!(file.ends_with('\n'), "no partial trailing line");
    let lines: Vec<&str> = file.lines().collect();
    assert_eq!(lines.len(), 16, "one row per wrapper");
    for line in &lines {
        let row: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("torn row {line:?}: {e}"));
        assert_eq!(row["reason"], "subcommand:auth");
    }
    assert_eq!(fake.census().len(), 16);
    assert_eq!(fake.logged().len(), 16 * AUTH_STATUS.len(), "every wrapper exec'd the fake");
}

#[test]
fn census_skipped_without_home() {
    let fake = FakeClaude::new();
    let out = Command::new(wrapper())
        .arg(fake.bin())
        .args(AUTH_STATUS)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("ARGV_LOG", fake.log_path())
        .output()
        .expect("spawn wrapper");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), AUTH_STATUS, "the fake still runs");
    let err = text(&out.stderr);
    assert!(err.contains("census: HOME is not set"), "{err}");
    assert_eq!(err.lines().count(), 1, "exactly one stderr line: {err}");
    assert!(err.starts_with("ai-env-claude: "), "{err}");
    assert!(!fake.census_path().exists() && !fake.bridge_dir().exists(), "nothing was recorded anywhere under the tempdir");
}

#[test]
fn stdout_is_untouched_and_stdin_passes() {
    let fake = FakeClaude::new();
    let line = r#"{"type":"system","subtype":"init"}"#;
    let stdin_bytes: &[u8] = b"{\"type\":\"user\",\"message\":\"hi\"}\n\x00\xff\xfe raw bytes, no trailing newline";
    let mut child = fake
        .command(&fake.bin(), &STREAM_JSON, &[("FAKE_STDOUT", line), ("FAKE_ECHO_STDIN", "1")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wrapper");
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(stdin_bytes).unwrap();
        // Dropped here: EOF, as the extension's stdin close.
    }
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    let mut want = format!("{line}\n").into_bytes();
    want.extend_from_slice(stdin_bytes);
    assert_eq!(out.stdout, want, "stdout is the fake's line followed by stdin byte for byte");
    assert_eq!(fake.logged(), STREAM_JSON);
}

/// Debug builds only: the knob is compiled out of release (`bridge::lab`).
#[cfg(debug_assertions)]
#[test]
fn lab_exit_pre_exec_propagates() {
    let fake = FakeClaude::new();
    let out = fake.run(&STREAM_JSON, &[("AI_ENV_BRIDGE_LAB_EXIT", "3:boom")]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(text(&out.stderr), "boom\n", "raw message, no prefix: Cursor renders `exited with code 3. stderr: boom`");
    assert!(out.stdout.is_empty());
    assert!(fake.logged().is_empty(), "the fake never ran");
    assert!(!fake.log_path().exists());
    let row = fake.only_row();
    let note = row["note"].as_str().expect("note");
    assert!(note.contains("lab_exit:3"), "{note}");
    assert_eq!(row["reason"], "unconfigured");
    assert_eq!(row["env_selected"]["AI_ENV_BRIDGE_LAB_EXIT"], "3:boom", "the knob is allowlisted so the row explains the exit");
}

#[test]
fn bare_name_real_binary_uses_local_fallback() {
    let fake = FakeClaude::new();
    // A cwd without a `claude` in it, so the bare name cannot resolve relatively.
    let work = fake.tmp().join("work");
    std::fs::create_dir(&work).unwrap();
    let path = fake.tmp().to_str().unwrap();
    let out = fake.command(Path::new("claude"), &AUTH_STATUS, &[("PATH", path)]).current_dir(&work).output().expect("spawn wrapper");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), AUTH_STATUS, "the fake found on PATH ran");
    let err = text(&out.stderr);
    assert!(err.contains("using claude on PATH"), "{err}");
    assert!(err.starts_with("ai-env-claude: claude is not executable;"), "{err}");
    assert_eq!(err.lines().count(), 1, "{err}");
    let row = fake.only_row();
    let note = row["note"].as_str().expect("note");
    assert!(note.starts_with("local_fallback:"), "{note}");
    assert!(note.ends_with("/claude"), "the resolved path is recorded: {note}");
    assert_eq!(row_argv(&row)[1], "claude", "argv[1] is recorded as given");
    assert_eq!(row["reason"], "subcommand:auth");
}

#[test]
fn unexecutable_real_binary_exits_1_without_fallback() {
    let fake = FakeClaude::new();
    fake.with_bridge_toml("[wrapper]\nlocal_fallback = false\n");
    let out = fake.run_with_real(Path::new("/nonexistent/claude"), &["--version"], &[("PATH", "/nonexistent")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(err.starts_with("ai-env-claude: "), "{err}");
    assert!(err.contains("cannot exec /nonexistent/claude"), "{err}");
    assert!(fake.logged().is_empty());
    // The row was recorded before the failure, without a fallback note.
    let row = fake.only_row();
    assert_eq!(row["route"], "local");
    assert_eq!(row["reason"], "version");
    assert!(row["note"].is_null(), "{row}");

    // Control: the same config and PATH with an executable argv[1] — PATH is never consulted.
    let ok = fake.run_with_path(&["--version"], &[], "/nonexistent");
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok.stderr));
    assert!(ok.stderr.is_empty(), "{}", text(&ok.stderr));
    assert_eq!(fake.logged(), ["--version"]);
    assert_eq!(fake.census().len(), 2);

    // local_fallback at its default (no bridge.toml) and no claude on PATH:
    // exit 1 as well. The lookup uses the child's PATH literally (no Homebrew
    // directory appended), so a developer's real claude is never found here.
    let plain = FakeClaude::new();
    let out = plain.run_with_real(Path::new("/nonexistent/claude"), &["--version"], &[("PATH", "/nonexistent")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("cannot exec /nonexistent/claude"), "{}", text(&out.stderr));
    assert!(plain.logged().is_empty());
    assert!(plain.only_row()["note"].is_null());
}

#[test]
fn missing_real_binary_exits_2() {
    let out = Command::new(wrapper()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = text(&out.stderr);
    assert!(err.starts_with("ai-env-claude: "), "{err}");
    assert!(err.contains("realBinary"), "{err}");
}

// ---- T1.2 overhead (make perf-wrapper; release build; AI_ENV_PERF_TESTS=1) ----

/// The median of `samples` in milliseconds (the mean of the two middle values
/// for an even count).
fn median_ms(samples: &mut [Duration]) -> f64 {
    samples.sort();
    let n = samples.len();
    let mid = if n.is_multiple_of(2) { (samples[n / 2 - 1] + samples[n / 2]) / 2 } else { samples[n / 2] };
    mid.as_secs_f64() * 1000.0
}

/// 100 interleaved pairs of `wrapper <fake> auth status --json` (config read +
/// census append + exec) and a bare `<fake> auth status --json`; the wrapper's
/// median may exceed the bare median by at most 10 ms.
#[test]
#[ignore = "perf measurement: make perf-wrapper (AI_ENV_PERF_TESTS=1, release)"]
fn t1_2_wrapper_overhead_median_100_runs() {
    if std::env::var("AI_ENV_PERF_TESTS").ok().as_deref() != Some("1") {
        eprintln!("t1_2_wrapper_overhead_median_100_runs: skipped (set AI_ENV_PERF_TESTS=1)");
        return;
    }
    let fake = FakeClaude::new();
    let mut wrapped: Vec<Duration> = Vec::with_capacity(100);
    let mut bare: Vec<Duration> = Vec::with_capacity(100);
    for _ in 0..100 {
        let t = Instant::now();
        let out = fake.run(&AUTH_STATUS, &[]);
        wrapped.push(t.elapsed());
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

        let t = Instant::now();
        let out = Command::new(fake.bin()).args(AUTH_STATUS).env("ARGV_LOG", fake.log_path()).output().expect("spawn fake");
        bare.push(t.elapsed());
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }
    assert_eq!(fake.census().len(), 100, "one row per wrapped run");
    let (w, b) = (median_ms(&mut wrapped), median_ms(&mut bare));
    let delta = w - b;
    println!("T1.2 overhead: wrapper median {w:.2} ms, bare median {b:.2} ms, delta {delta:.2} ms (budget 10 ms)");
    assert!(delta <= 10.0, "wrapper overhead {delta:.2} ms exceeds the 10 ms median budget (wrapper {w:.2} ms, bare {b:.2} ms)");
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

// ---- S2: the pump mode never touches the exec path ------------------------------------

/// `<bridge>/logs/wrapper.log`: written only by a piped session.
fn wrapper_log_path(fake: &FakeClaude) -> PathBuf {
    fake.bridge_dir().join("logs").join("wrapper.log")
}

#[test]
fn local_route_leaves_no_pump_state() {
    let fake = FakeClaude::new();
    let out = fake.run(&AUTH_STATUS, &[("AI_ENV_BRIDGE_MODE", "local-child")]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), AUTH_STATUS, "exec'd verbatim: no --session-mirror, no pump");
    assert!(!wrapper_log_path(&fake).exists(), "a Local route writes no wrapper.log");
    assert!(!fake.bridge_dir().join("state").exists(), "a Local route creates no state/ (sessions, scratch)");
    assert!(!fake.bridge_dir().join("audit.jsonl").exists());
    let row = fake.only_row();
    assert_eq!(row["reason"], "subcommand:auth");
    let note = row["note"].as_str().expect("the mode is noted");
    assert!(note.split("; ").any(|p| p == "mode:local-child"), "{note}");
    assert!(row.get("end").is_none() && row.get("exit").is_none(), "exec leaves no end/exit: {row}");
}

#[test]
fn invalid_mode_execs_verbatim_with_a_note() {
    let fake = FakeClaude::new();
    let out = fake.run_in(fake.tmp(), &STREAM_JSON, &[("AI_ENV_BRIDGE_MODE", "garbage")]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), STREAM_JSON, "exec'd verbatim: no --session-mirror");
    let err = text(&out.stderr);
    assert!(err.lines().any(|l| l == "ai-env-claude: AI_ENV_BRIDGE_MODE=garbage unknown; passthrough"), "{err}");
    assert!(!wrapper_log_path(&fake).exists(), "passthrough writes no wrapper.log");
    assert!(!fake.bridge_dir().join("state").exists());
    let row = fake.only_row();
    let note = row["note"].as_str().expect("the invalid mode is noted");
    assert!(note.split("; ").any(|p| p == "mode_invalid:garbage"), "{note}");
    assert_eq!(row["route"], "local");
    assert_eq!(row["reason"], "unconfigured");
}

#[test]
fn unset_mode_session_still_execs() {
    let fake = FakeClaude::new();
    let out = fake.command(&fake.bin(), &STREAM_JSON, &[]).env_remove("AI_ENV_BRIDGE_MODE").current_dir(fake.tmp()).output().expect("spawn wrapper");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    assert_eq!(fake.logged(), STREAM_JSON, "exec'd verbatim: no --session-mirror");
    assert!(!wrapper_log_path(&fake).exists(), "no pump, no wrapper.log");
    assert!(!fake.bridge_dir().join("state").exists());
    let row = fake.only_row();
    assert!(row["note"].is_null(), "the default mode earns no note: {row}");
    assert!(row.get("end").is_none(), "{row}");
}

// ---- S7: local-scratch with the sealed setup-token; the synthetic-oauth knob ----------------

/// S7 (W7) through the real wrapper and the pump harness of `tests/common`,
/// whose child is `tests/fakes/claude-v2.sh`: its `FAKE_TOKEN_LOG` says where
/// the child found a token (fd, env, none), its length and a hash prefix,
/// never the value. The token is sealed by the real `ai-env creds setup-token`
/// with the fake age (`tests/fakes/age.sh`: hex "encryption", one `age -d` log
/// line per Touch ID, `FAKE_AGE_FAIL=cancel`, `FAKE_AGE_HANG`) and a fake
/// keystore key, all under the run's tempdir, with the fake age first on PATH
/// so the real one is never reached. Every token is built at run time with a
/// per-test tail; every token test ends by finding it nowhere it must not be
/// (the wrapper's stdout and stderr, every file of the run), and every failure
/// message of a token test shows the run with the token masked: the module
/// drives the harness through its own masked helpers ([`await_frame`],
/// [`await_exit`], [`send_line`]) rather than the harness's, whose panics print
/// the run as it is. The signal tests set the disposition a wrapper inherits
/// around its spawn (serialized, then put back): the only process-wide state
/// this file touches.
mod s7 {
    use super::common::{env_log_field, is_init, is_response_to, is_result_for, note_has, uuid, Harness, Prepared};
    use ai_env_cli::bridge::pump::{INITIALIZE_WINDOW, SYNTHETIC_OAUTH_KNOB, UNSEAL_TIMEOUT_KNOB};
    use serde_json::Value;
    use sha2::Digest as _;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    /// Upper bound for a frame the fake answers at once (generous, as in hoststate).
    const T: Duration = Duration::from_secs(30);
    const EXIT: Duration = Duration::from_secs(30);
    /// `[creds].key`'s default: the keystore key the token is sealed to.
    const KEY: &str = "ai-env-bridge";
    /// The public SE tag recipient and X25519 recovery recipient of tests/cli.rs (as tests/infra uses them).
    const SE_REC: &str = "age1tag1qwww38sn08g0m3x3ue8wh33wa4vs2wcx0427jya9fjrhxa94fxjk7yz4e4r";
    const X_REC: &str = "age15csf02ez9ze9xnk3djhm497jwjysdg96tcqwpsn4m5clex767vrs5da5j0";
    /// How every logged-out note line starts.
    const NOTE_HEAD: &str = "ai-env-claude: local-scratch without CLAUDE_CODE_OAUTH_TOKEN: ";
    const PREFIX: &str = "sk-ant-oat01-";
    /// How the wrapper logs each drop of its copy of the token, before the reason.
    const DROPPED: &str = "the setup-token copy was dropped (";
    /// A descriptor number a developer's shell might carry: no descriptor of the wrapper's.
    const STALE_FD: &str = "7";

    /// A token of the setup-token shape, built at run time, ending in `tail`.
    fn token(tail: &str) -> String {
        format!("{}{}{tail}", PREFIX, "Wr8_".repeat(20))
    }

    /// All of a token but its kind prefix: what must never be seen.
    fn random_part(t: &str) -> &str {
        &t[PREFIX.len()..]
    }

    /// The first 8 hex digits of the token's sha256: what the fake logs.
    fn sha8(t: &str) -> String {
        hex::encode(sha2::Sha256::digest(t.as_bytes()))[..8].to_string()
    }

    /// The fake age, one cached 0755 master per content (macOS assesses a new
    /// file's first exec; every run hard-links the master, as tests/common
    /// does with the fake claude).
    fn fake_age_master() -> &'static Path {
        static MASTER: OnceLock<PathBuf> = OnceLock::new();
        MASTER.get_or_init(|| {
            let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fakes").join("age.sh");
            let bytes = std::fs::read(&src).expect("read the fake age");
            let digest = hex::encode(sha2::Sha256::digest(&bytes));
            let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fake-age");
            std::fs::create_dir_all(&dir).expect("mkdir the fake age's cache");
            let path = dir.join(format!("age-{}", &digest[..16]));
            if !path.exists() {
                let tmp = dir.join(format!(".age-{}.{}.tmp", &digest[..16], std::process::id()));
                std::fs::write(&tmp, &bytes).expect("write the fake age");
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).expect("chmod the fake age");
                std::fs::rename(&tmp, &path).expect("install the fake age");
            }
            path
        })
    }

    /// The fake age as `bin/{age,age-keygen,age-plugin-se}`, the keystore key
    /// `keys/keys/ai-env-bridge` (an SE identity stub and the two public test
    /// recipients), and, once [`World::seal`] ran, the sealed token, all under
    /// the harness's tempdir.
    struct World {
        root: PathBuf,
    }

    impl World {
        fn new(p: &Prepared) -> World {
            let root = p.root.clone();
            let bin = root.join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            for name in ["age", "age-keygen", "age-plugin-se"] {
                let dest = bin.join(name);
                if std::fs::hard_link(fake_age_master(), &dest).is_err() {
                    std::fs::copy(fake_age_master(), &dest).unwrap();
                }
            }
            let key = root.join("keys").join("keys").join(KEY);
            std::fs::create_dir_all(&key).unwrap();
            std::fs::write(key.join("identity.txt"), format!("# public key: {SE_REC}\nAGE-PLUGIN-SE-1{}\n", "FAKE".repeat(2))).unwrap();
            std::fs::write(key.join("recipients.txt"), format!("{SE_REC}\n{X_REC}\n")).unwrap();
            std::fs::write(key.join("meta.toml"), "created = \"2026-10-08\"\naccess_control = \"none\"\n").unwrap();
            World { root }
        }

        fn path_var(&self) -> String {
            format!("{}:/usr/bin:/bin", self.root.join("bin").display())
        }

        fn age_log(&self) -> PathBuf {
            self.root.join("age.log")
        }

        fn token_env(&self) -> PathBuf {
            self.root.join("bridge").join("credentials").join("setup-token.env")
        }

        fn pidfile(&self) -> PathBuf {
            self.root.join("age.pid")
        }

        /// Seal `t` with the real `ai-env creds setup-token --stdin` (no runtime
        /// key is sealed, so no `combined.env`; the seal itself decrypts nothing).
        /// A developer's own `CLAUDE_CODE_*`, lab, fake-age and AWS variables
        /// are removed first, so they never cancel the ones set here (a
        /// `FAKE_AGE_LOG` of theirs would hide this seal's log).
        fn seal(&self, t: &str) {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-env"));
            for (k, _) in std::env::vars_os() {
                let k = k.to_string_lossy().into_owned();
                if k.starts_with("CLAUDE_CODE_") || k.starts_with("AI_ENV_BRIDGE_LAB_") || k.starts_with("FAKE_AGE_") || k.starts_with("AWS_") {
                    cmd.env_remove(&k);
                }
            }
            cmd.args(["creds", "setup-token", "--stdin", "--no-combined"])
                .env("HOME", &self.root)
                .env("AI_ENV_BRIDGE_DIR", self.root.join("bridge"))
                .env("AI_ENV_DIR", self.root.join("keys"))
                .env("PATH", self.path_var())
                .env("FAKE_AGE_LOG", self.age_log())
                .env_remove("AI_ENV_BRIDGE_CONFIG");
            let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn ai-env");
            child.stdin.take().expect("piped stdin").write_all(format!("{t}\n").as_bytes()).expect("write the token");
            let out = child.wait_with_output().expect("wait for ai-env");
            let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            assert!(out.status.code() == Some(0), "creds setup-token exited {:?}: {}", out.status.code(), mask(&said, random_part(t)));
            assert!(self.token_env().is_file());
            assert_eq!(self.decrypts(), 0, "sealing asks for no Touch ID");
        }

        /// The wrapper's environment: the fake age first on PATH, the keystore,
        /// the fakes' logs, both lab knobs off (`0`), and the fake age's own
        /// knobs and the fake claude's S7 knobs empty (a developer's shell may
        /// set any of them), then `extra` in order (a later value wins).
        fn envs(&self, extra: &[(&str, &str)]) -> Vec<(String, String)> {
            let mut v: Vec<(String, String)> = vec![
                ("PATH".into(), self.path_var()),
                ("AI_ENV_DIR".into(), self.root.join("keys").display().to_string()),
                ("FAKE_AGE_LOG".into(), self.age_log().display().to_string()),
                ("FAKE_TOKEN_LOG".into(), self.root.join("token.log").display().to_string()),
                (SYNTHETIC_OAUTH_KNOB.into(), "0".into()),
                (UNSEAL_TIMEOUT_KNOB.into(), "0".into()),
            ];
            for knob in ["FAKE_AGE_FAIL", "FAKE_AGE_DELAY_MS", "FAKE_AGE_HANG", "FAKE_AGE_WAIT_FILE", "FAKE_AGE_PIDFILE", "FAKE_INIT_AT_TURN", "FAKE_MISS_DELAY_MS", "FAKE_MISS_EXIT_DELAY_MS"] {
                v.push((knob.into(), String::new()));
            }
            v.extend(extra.iter().map(|(k, val)| ((*k).to_string(), (*val).to_string())));
            v
        }

        /// How many decrypts (Touch IDs) the fake age was asked for.
        fn decrypts(&self) -> usize {
            std::fs::read_to_string(self.age_log()).unwrap_or_default().lines().filter(|l| l.starts_with("age -d ")).count()
        }

        /// The fake's token lines, one per child generation.
        fn token_log(&self) -> Vec<String> {
            std::fs::read_to_string(self.root.join("token.log")).unwrap_or_default().lines().map(str::to_string).collect()
        }
    }

    fn refs(v: &[(String, String)]) -> Vec<(&str, &str)> {
        v.iter().map(|(k, val)| (k.as_str(), val.as_str())).collect()
    }

    /// `source`, `len`, `sha8`, `fdvar` and `envvar` of one token line (the
    /// fake writes no value, so the line itself may be printed).
    fn token_fields(line: &str) -> [&str; 5] {
        ["source", "len", "sha8", "fdvar", "envvar"].map(|k| env_log_field(line, k).unwrap_or_else(|| panic!("no {k} in {line}")))
    }

    // -- failure messages never print the token -------------------------------------------------

    /// `text` with `secret` masked: what a failure message may print.
    fn mask(text: &str, secret: &str) -> String {
        text.replace(secret, "[the dummy token]")
    }

    /// The run so far, with `secret` masked.
    fn masked(h: &Harness, secret: &str) -> String {
        mask(&h.transcript(), secret)
    }

    /// The first stdout frame matching `pred`, seen before or within `timeout`.
    fn await_frame(h: &mut Harness, pred: impl Fn(&Value) -> bool, timeout: Duration, secret: &str) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = h.out_json().into_iter().find(|v| pred(v)) {
                return v;
            }
            assert!(Instant::now() < deadline, "expected stdout frame not seen within {timeout:?}\n{}", masked(h, secret));
            std::thread::sleep(Duration::from_millis(3));
        }
    }

    /// Poll `cond` until it holds (at most [`T`]).
    fn await_cond(h: &mut Harness, what: &str, secret: &str, mut cond: impl FnMut(&mut Harness) -> bool) {
        let deadline = Instant::now() + T;
        loop {
            h.drain();
            if cond(h) {
                return;
            }
            assert!(Instant::now() < deadline, "{what}: not within {T:?}\n{}", masked(h, secret));
            std::thread::sleep(Duration::from_millis(3));
        }
    }

    /// The wrapper's exit within `timeout` (killed otherwise), then the end of
    /// its output ([`Harness::wait`], which by now only collects the EOFs).
    fn await_exit(h: &mut Harness, timeout: Duration, secret: &str) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        while !h.exited_now() {
            if Instant::now() >= deadline {
                let _ = h.child.kill();
                let _ = h.child.wait();
                h.drain();
                panic!("the wrapper did not exit within {timeout:?}; killed\n{}", masked(h, secret));
            }
            h.drain();
            std::thread::sleep(Duration::from_millis(2));
        }
        h.wait(EXIT).0
    }

    /// Write `line` (+ `\n`) to the wrapper's stdin.
    fn send_line(h: &mut Harness, line: &str, secret: &str) {
        if let Err(e) = h.try_send(line) {
            panic!("write to the wrapper's stdin failed ({e})\n{}", masked(h, secret));
        }
    }

    /// An `initialize` request, as the harness sends it; its request id.
    fn send_init(h: &mut Harness, secret: &str) -> String {
        let id = format!("init-s7-{}", h.sent.len());
        send_line(h, &format!(r#"{{"request_id":"{id}","type":"control_request","request":{{"subtype":"initialize","hooks":{{}},"jsonSchema":null}}}}"#), secret);
        id
    }

    /// A user line with a fresh uuid; the uuid.
    fn send_turn(h: &mut Harness, text: &str, secret: &str) -> String {
        let u = uuid(0x57_a000 + h.sent.len() as u64);
        send_line(h, &Harness::user_line(&u, text), secret);
        u
    }

    fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                match e.file_type() {
                    Ok(t) if t.is_dir() => all_files(&e.path(), out),
                    Ok(t) if t.is_file() => out.push(e.path()),
                    _ => {}
                }
            }
        }
    }

    /// `secret` is in none of the wrapper's output lines and in no file of the run.
    fn assert_nowhere(h: &mut Harness, secret: &str) {
        h.drain();
        for (i, line) in h.seen_out.iter().chain(h.seen_err.iter()).enumerate() {
            assert!(!line.contains(secret), "the token reached the wrapper's output (line {i}, {} bytes)", line.len());
        }
        let mut files = Vec::new();
        all_files(h.root(), &mut files);
        assert!(files.len() > 5, "the run's files were found: {}", files.len());
        for f in files {
            let bytes = std::fs::read(&f).unwrap_or_default();
            assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()), "the token reached {}", f.display());
        }
    }

    /// The logged-out note lines on stderr.
    fn notes(h: &mut Harness) -> Vec<String> {
        h.err_text().lines().filter(|l| l.starts_with(NOTE_HEAD)).map(str::to_string).collect()
    }

    /// The notes are exactly `want` (a failure prints them masked).
    fn assert_notes(h: &mut Harness, want: &[String], secret: &str) {
        let got = notes(h);
        assert!(got == want, "notes {}\nexpected {want:?}", mask(&format!("{got:?}"), secret));
    }

    /// The end row's note has the part `part` (a failure prints it masked).
    fn assert_end_note(h: &Harness, part: &str, secret: &str) {
        let note = h.end_note();
        assert!(note_has(&note, part), "no {part:?} in the end row's note: {}", mask(&note, secret));
    }

    /// The first `event` audit row's `detail.<field>` is `want` (a failure
    /// prints the audit rows masked).
    fn assert_audit(h: &Harness, event: &str, field: &str, want: &str, secret: &str) {
        let rows = h.audit_events(event);
        let got = rows.first().and_then(|r| r["detail"][field].as_str());
        assert!(got == Some(want), "{event}.{field} is not {want:?}: {}", mask(&format!("{:#?}", h.audit_rows()), secret));
    }

    /// Why the wrapper dropped its copy of the token, in order (`wrapper.log`).
    fn dropped_reasons(h: &Harness) -> Vec<String> {
        h.wrapper_log().lines().filter_map(|l| l.split(DROPPED).nth(1)?.split_once(')').map(|(why, _)| why.to_string())).collect()
    }

    /// One turn, then EOF; the wrapper exits 0.
    fn one_turn(h: &mut Harness, secret: &str) {
        send_init(h, secret);
        await_frame(h, is_init, T, secret);
        let u = send_turn(h, "a turn of the scratch session", secret);
        await_frame(h, |v| is_result_for(v, &u), T, secret);
        h.close_stdin();
        let status = await_exit(h, EXIT, secret);
        assert!(status.code() == Some(0), "exit {:?}\n{}", status.code(), masked(h, secret));
    }

    // -- the decrypt's process group and the signals -----------------------------------------

    /// Does any process of group `pgid` exist?
    fn group_alive(pgid: i32) -> bool {
        // SAFETY: signal 0 only checks for existence.
        unsafe { libc::killpg(pgid, 0) == 0 }
    }

    /// Wait at most 5 s for process group `pgid` to be gone.
    fn assert_group_gone(pgid: i32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while group_alive(pgid) {
            assert!(Instant::now() < deadline, "the decrypting process group {pgid} (age and its dialog) is still alive");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Kills a hanging fake age's process group when a test fails before
    /// proving it gone, so a failing run leaves no looping process behind.
    /// Disarmed once the group is proven gone: a pgid is never signalled after
    /// it may have been recycled.
    struct GroupGuard(Option<i32>);

    impl GroupGuard {
        /// Wait for the fake age to write its pid: the decrypt (the "dialog")
        /// is up, and from here the guard owns its group.
        fn started(world: &World, h: &Harness, secret: &str) -> (i32, GroupGuard) {
            let deadline = Instant::now() + T;
            // The file may exist a moment before the pid is in it.
            let pgid = loop {
                if let Some(pgid) = std::fs::read_to_string(world.pidfile()).ok().and_then(|s| s.trim().parse::<i32>().ok()) {
                    break pgid;
                }
                assert!(Instant::now() < deadline, "the decrypt never started\n{}", masked(h, secret));
                std::thread::sleep(Duration::from_millis(10));
            };
            (pgid, GroupGuard(Some(pgid)))
        }

        /// Assert the group is gone (within 5 s); only then is the guard disarmed.
        fn gone(&mut self) {
            if let Some(pgid) = self.0 {
                assert_group_gone(pgid);
                self.0 = None;
            }
        }
    }

    impl Drop for GroupGuard {
        fn drop(&mut self) {
            if let Some(pgid) = self.0.take() {
                // SAFETY: killpg(2) on the fake age's own group, which the test has not seen end.
                unsafe { libc::killpg(pgid, libc::SIGKILL) };
            }
        }
    }

    /// Serializes the spawns that set a signal's disposition ([`spawn_with`]).
    static DISPOSITIONS: Mutex<()> = Mutex::new(());

    /// `sig` at `handler` (`SIG_DFL` or `SIG_IGN`) in this process while it
    /// lives, the previous disposition put back on drop.
    struct Disposition(libc::c_int, libc::sigaction);

    impl Disposition {
        fn set(sig: libc::c_int, handler: libc::sighandler_t) -> Disposition {
            // SAFETY: sigaction(2) on zeroed (valid) structs; SIG_DFL and SIG_IGN run no code here.
            unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = handler;
                libc::sigemptyset(&raw mut act.sa_mask);
                let mut old: libc::sigaction = std::mem::zeroed();
                assert_eq!(libc::sigaction(sig, &raw const act, &raw mut old), 0, "sigaction({sig})");
                Disposition(sig, old)
            }
        }
    }

    impl Drop for Disposition {
        fn drop(&mut self) {
            // SAFETY: restores what sigaction(2) returned.
            unsafe { libc::sigaction(self.0, &raw const self.1, std::ptr::null_mut()) };
        }
    }

    /// Spawn the wrapper (local-scratch) with `sig` at `handler`, whatever
    /// this test process inherited: a `&` job of a non-interactive shell, for
    /// one, starts with SIGINT ignored, and the wrapper keeps an ignored
    /// signal ignored.
    fn spawn_with(p: Prepared, envs: &[(&str, &str)], sig: libc::c_int, handler: libc::sighandler_t) -> Harness {
        let _serial = DISPOSITIONS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _set = Disposition::set(sig, handler);
        p.spawn("local-scratch", &[], envs)
    }

    /// Send `sig` to the wrapper.
    fn signal(h: &Harness, sig: libc::c_int) {
        // SAFETY: kill(2) on our own not-yet-reaped child.
        assert_eq!(unsafe { libc::kill(i32::try_from(h.pid()).unwrap(), sig) }, 0, "kill({sig})");
    }

    // -- delivery ------------------------------------------------------------------------------

    /// A sealed token reaches the local-scratch child on fd 3
    /// (`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3`; its length and hash
    /// match) and nowhere else: not its environment — an empty
    /// `CLAUDE_CODE_OAUTH_TOKEN` and a stale descriptor number in the
    /// wrapper's environment are not passed on — not its argv, not the
    /// wrapper's output, no file. One Touch ID, the countdown in the wrapper's
    /// voice, no logged-out note; the unseal and the delivery are audited, the
    /// end row says `credential:fd`, and the wrapper's copy is dropped once
    /// the child started. With the synthetic knob off, the host sees no
    /// request of the pump's own.
    #[test]
    fn local_scratch_hands_the_sealed_token_to_the_child_on_fd_3() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Fd01");
        world.seal(&t);
        let secret = random_part(&t);
        let envs = world.envs(&[("CLAUDE_CODE_OAUTH_TOKEN", ""), ("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", STALE_FD)]);
        let mut h = p.spawn("local-scratch", &[], &refs(&envs));
        one_turn(&mut h, secret);
        let log = world.token_log();
        assert_eq!(log.len(), 1, "one child: {log:?}");
        let len = t.len().to_string();
        assert_eq!(token_fields(&log[0]), ["fd", len.as_str(), sha8(&t).as_str(), "3", "absent"], "fd 3 carried the token and nothing else did");
        assert_eq!(world.decrypts(), 1, "one Touch ID");
        let err = h.err_text();
        assert!(err.lines().any(|l| l.starts_with("ai-env-claude: waiting for Touch ID to unseal the setup token, ")), "the countdown speaks as the wrapper: {}", masked(&h, secret));
        assert_notes(&mut h, &[], secret);
        assert_end_note(&h, "credential:fd", secret);
        assert!(!h.end_note().contains("synthetic_oauth"), "{}", mask(&h.end_note(), secret));
        assert!(!h.out_lines().iter().any(|l| l.contains("oauth_token_refresh")), "no synthetic request without the knob");
        assert!(h.audit_events("credential_unseal").len() == 1, "{}", mask(&format!("{:#?}", h.audit_rows()), secret));
        assert_audit(&h, "credential_unseal", "for", "local-scratch", secret);
        assert_audit(&h, "credential_unseal", "outcome", "ok", secret);
        assert!(h.audit_events("credential_deliver").len() == 1, "{}", mask(&format!("{:#?}", h.audit_rows()), secret));
        assert_audit(&h, "credential_deliver", "deliver", "fd", secret);
        assert_audit(&h, "credential_deliver", "gen", "1", secret);
        assert_audit(&h, "credential_deliver", "name", "CLAUDE_CODE_OAUTH_TOKEN", secret);
        let wlog = h.wrapper_log();
        let spawned = wlog.find("child spawned").expect("the spawn is logged");
        let dropped = wlog.find(DROPPED).expect("the wrapper's copy is dropped");
        let init = wlog.find("session id learned").expect("the init is logged");
        assert!(spawned < dropped && dropped < init, "dropped once the child started, not kept until its init");
        assert_eq!(dropped_reasons(&h), ["the child started and no retry can respawn it"]);
        assert!(h.argv_log().iter().flatten().all(|a| !a.contains(secret)), "never in argv");
        assert_nowhere(&mut h, secret);
    }

    /// `[creds] deliver = "env"` puts the token in the child's environment
    /// (and no descriptor variable, a stale one in the wrapper's environment
    /// included); without it the default is fd (above). Still never in argv,
    /// the output or a file; the end row says `credential:env`.
    #[test]
    fn env_delivery_reaches_the_childs_environment_only_with_the_config() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Env2");
        world.seal(&t);
        let secret = random_part(&t);
        std::fs::write(p.root.join("bridge").join("bridge.toml"), "[creds]\ndeliver = \"env\"\n").unwrap();
        let envs = world.envs(&[("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", STALE_FD)]);
        let mut h = p.spawn("local-scratch", &[], &refs(&envs));
        one_turn(&mut h, secret);
        let log = world.token_log();
        assert_eq!(log.len(), 1, "{log:?}");
        let len = t.len().to_string();
        assert_eq!(token_fields(&log[0]), ["env", len.as_str(), sha8(&t).as_str(), "unset", "present"]);
        assert_eq!(world.decrypts(), 1);
        assert_end_note(&h, "credential:env", secret);
        assert_audit(&h, "credential_deliver", "deliver", "env", secret);
        assert!(h.argv_log().iter().flatten().all(|a| !a.contains(secret)), "never in argv");
        assert_nowhere(&mut h, secret);
    }

    /// No sealed token: today's behaviour — one note line, no Touch ID (age is
    /// never run), the child logged out (a stale descriptor number in the
    /// wrapper's environment is not passed on), `credential:none`.
    #[test]
    fn without_a_sealed_token_the_child_runs_logged_out_with_one_note() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let envs = world.envs(&[("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", STALE_FD)]);
        let mut h = p.spawn("local-scratch", &[], &refs(&envs));
        one_turn(&mut h, PREFIX);
        assert_notes(&mut h, &[format!("{NOTE_HEAD}no setup-token is sealed (`ai-env creds setup-token` seals one), so the child is logged out")], PREFIX);
        assert!(!world.age_log().exists(), "age never ran");
        let log = world.token_log();
        assert_eq!(token_fields(&log[0]), ["none", "0", "-", "unset", "absent"], "{log:?}");
        assert_end_note(&h, "credential:none", PREFIX);
        assert!(h.audit_events("credential_unseal").is_empty());
    }

    /// A token already in the wrapper's environment wins (the S2 behaviour):
    /// nothing is unsealed, the child inherits that token — no stale
    /// descriptor number shadows it — and the sealed one is never read.
    #[test]
    fn a_token_already_in_the_environment_wins() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let sealed = token("Sea4");
        world.seal(&sealed);
        let inherited = token("Inh4");
        let envs = world.envs(&[("CLAUDE_CODE_OAUTH_TOKEN", inherited.as_str()), ("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", STALE_FD)]);
        let mut h = p.spawn("local-scratch", &[], &refs(&envs));
        // Both tokens share every character but their last four.
        let secret = &random_part(&inherited)[..random_part(&inherited).len() - 4];
        one_turn(&mut h, secret);
        assert_eq!(world.decrypts(), 0, "no Touch ID");
        let log = world.token_log();
        let len = inherited.len().to_string();
        assert_eq!(token_fields(&log[0]), ["env", len.as_str(), sha8(&inherited).as_str(), "unset", "present"], "{log:?}");
        assert_notes(&mut h, &[], secret);
        assert_end_note(&h, "credential:inherited", secret);
        assert!(h.audit_events("credential_unseal").is_empty() && h.audit_events("credential_deliver").is_empty());
        assert_nowhere(&mut h, random_part(&sealed));
        assert_nowhere(&mut h, random_part(&inherited));
    }

    // -- the unseal fails: the child runs logged out -----------------------------------------------

    /// A dismissed Touch ID dialog never blocks or fails the session: one note
    /// line, the child logged out, the session answers and exits 0; the unseal
    /// is audited with exit 3.
    #[test]
    fn a_dismissed_dialog_runs_the_child_logged_out() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Can5");
        world.seal(&t);
        let secret = random_part(&t);
        let envs = world.envs(&[("FAKE_AGE_FAIL", "cancel")]);
        let mut h = p.spawn("local-scratch", &[], &refs(&envs));
        one_turn(&mut h, secret);
        assert_eq!(world.decrypts(), 1, "the one Touch ID asked for");
        assert_notes(&mut h, &[format!("{NOTE_HEAD}the sealed setup-token was not unsealed (the Touch ID dialog was dismissed), so the child is logged out")], secret);
        assert_eq!(token_fields(&world.token_log()[0])[0], "none");
        assert_end_note(&h, "credential:none", secret);
        assert_audit(&h, "credential_unseal", "outcome", "exit 3", secret);
        assert_nowhere(&mut h, secret);
    }

    /// A seal Anthropic refused (the S7 rejection marker in `state/creds.toml`)
    /// is never unsealed again: no Touch ID, one note naming the refusal, the
    /// child logged out.
    #[test]
    fn a_refused_seal_is_never_unsealed() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Rej6");
        world.seal(&t);
        let secret = random_part(&t);
        let tag = ai_env_cli::bridge::agent::credential::seal_tag(&world.token_env()).expect("the seal id");
        let state = p.root.join("bridge").join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("creds.toml"), format!("[[rejected]]\ntag = \"{tag}\"\nat = \"2026-10-08T09:00:00Z\"\nvm = \"microvm-test\"\n")).unwrap();
        let envs = world.envs(&[]);
        let mut h = p.spawn("local-scratch", &[], &refs(&envs));
        one_turn(&mut h, secret);
        assert_eq!(world.decrypts(), 0, "no Touch ID for a refused seal");
        assert_notes(
            &mut h,
            &[format!("{NOTE_HEAD}the sealed setup-token was refused by Anthropic on 2026-10-08T09:00:00Z (microvm-test) and is not unsealed again (`claude setup-token`, then `ai-env creds setup-token`), so the child is logged out")],
            secret,
        );
        assert_eq!(token_fields(&world.token_log()[0])[0], "none");
        assert!(h.audit_events("credential_unseal").is_empty(), "nothing was unsealed");
        assert_nowhere(&mut h, secret);
    }

    /// M53: a `state/creds.toml` that cannot be read may hold this seal's
    /// refusal, so the sealed token is not unsealed (no Touch ID), as `vm
    /// exec` refuses it: one note naming the file, the child logged out,
    /// nothing unsealed. (It used to be read as no refusal, with a warning.)
    #[test]
    fn an_unreadable_refusal_store_is_never_read_as_no_refusal() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Unr8");
        world.seal(&t);
        let secret = random_part(&t);
        let state = p.root.join("bridge").join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("creds.toml"), "[[rejected]\n").unwrap();
        let envs = world.envs(&[]);
        let mut h = p.spawn("local-scratch", &[], &refs(&envs));
        one_turn(&mut h, secret);
        assert_eq!(world.decrypts(), 0, "no Touch ID while the refusals are unknown");
        let got = notes(&mut h);
        let head = format!("{NOTE_HEAD}{} cannot be parsed (invalid table header", state.join("creds.toml").display());
        let tail = "): which tokens Anthropic refused is unknown and the sealed setup-token is not unsealed (repair that file, or remove it to forget every recorded refusal), so the child is logged out";
        assert!(got.len() == 1 && got[0].starts_with(&head) && got[0].ends_with(tail), "notes {}", mask(&format!("{got:?}"), secret));
        assert_eq!(token_fields(&world.token_log()[0])[0], "none");
        assert!(h.audit_events("credential_unseal").is_empty(), "nothing was unsealed");
        assert_nowhere(&mut h, secret);
    }

    /// An unanswered dialog ends at the deadline (here the lab knob's 1500 ms):
    /// the decrypt's whole process group is killed — the dialog with it — and
    /// the child runs logged out; the session itself is unharmed.
    #[test]
    fn an_unanswered_dialog_ends_at_the_deadline_and_the_child_runs_logged_out() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Ddl7");
        world.seal(&t);
        let secret = random_part(&t);
        let pidfile = world.pidfile().display().to_string();
        let envs = world.envs(&[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", pidfile.as_str()), (UNSEAL_TIMEOUT_KNOB, "1500")]);
        let mut h = p.spawn("local-scratch", &[], &refs(&envs));
        let (pgid, mut guard) = GroupGuard::started(&world, &h, secret);
        one_turn(&mut h, secret);
        assert_notes(&mut h, &[format!("{NOTE_HEAD}the sealed setup-token was not unsealed (no Touch ID within 1500 ms), so the child is logged out")], secret);
        guard.gone();
        assert!(std::fs::read_to_string(world.age_log()).unwrap_or_default().contains(&format!("age TERM {pgid}")), "the group was signalled");
        assert_eq!(token_fields(&world.token_log()[0])[0], "none");
        assert_audit(&h, "credential_unseal", "outcome", "exit 5", secret);
        assert_nowhere(&mut h, secret);
    }

    // -- Cursor's initialize window ------------------------------------------------------------

    /// The unseal runs before the child exists, inside Cursor's 60 s window to
    /// answer `initialize`: with the default `[creds].unseal_timeout_s` (60 s)
    /// the countdown starts from 50 s (T−10 s; 45 at the least, should the
    /// wrapper's own start have taken whole seconds), and a shorter configured
    /// budget (30 s) is kept as it is.
    #[test]
    fn the_touch_id_budget_ends_ten_seconds_before_the_initialize_window() {
        for (config, low, high) in [(None, 45, 50), (Some("[creds]\nunseal_timeout_s = 30\n"), 30, 30)] {
            let p = Harness::prepare();
            let world = World::new(&p);
            let t = token(&format!("Bd{high}"));
            world.seal(&t);
            let secret = random_part(&t);
            if let Some(text) = config {
                std::fs::write(p.root.join("bridge").join("bridge.toml"), text).unwrap();
            }
            let envs = world.envs(&[("FAKE_AGE_DELAY_MS", "200")]);
            let mut h = p.spawn("local-scratch", &[], &refs(&envs));
            one_turn(&mut h, secret);
            let err = h.err_text();
            let left: Vec<u64> = err.lines().filter_map(|l| l.strip_prefix("ai-env-claude: waiting for Touch ID to unseal the setup token, ")?.strip_suffix(" s left")?.parse().ok()).collect();
            assert!(left.first().is_some_and(|n| (low..=high).contains(n)), "{config:?}: the countdown started from {left:?} s, expected {low}..={high}");
            assert_eq!(token_fields(&world.token_log()[0])[0], "fd", "answered in time: delivered");
            assert_nowhere(&mut h, secret);
        }
    }

    /// Plan v6 §3.1 end to end, in real time (about 50 s, hence ignored; run it
    /// with `cargo test --test wrapper -- --ignored s7::an_unanswered`): with
    /// the default `[creds].unseal_timeout_s` an unanswered dialog ends at
    /// T−10 s, and the logged-out child answers `initialize` inside Cursor's
    /// 60 s window.
    #[test]
    #[ignore = "real time: about 50 s (the default Touch ID budget runs out)"]
    fn an_unanswered_dialog_at_the_default_budget_still_answers_initialize_in_time() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Win8");
        world.seal(&t);
        let secret = random_part(&t);
        let pidfile = world.pidfile().display().to_string();
        let envs = world.envs(&[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", pidfile.as_str())]);
        let mut h = p.spawn("local-scratch", &[], &refs(&envs));
        let init = send_init(&mut h, secret);
        let (_pgid, mut guard) = GroupGuard::started(&world, &h, secret);
        await_frame(&mut h, |v| is_response_to(v, &init), Duration::from_secs(75), secret);
        let took = h.started.elapsed();
        assert!(took < INITIALIZE_WINDOW, "initialize answered {} ms after the spawn: Cursor would have closed the channel", took.as_millis());
        guard.gone();
        h.close_stdin();
        let status = await_exit(&mut h, EXIT, secret);
        assert!(status.code() == Some(0), "exit {:?}\n{}", status.code(), masked(&h, secret));
        assert_notes(&mut h, &[format!("{NOTE_HEAD}the sealed setup-token was not unsealed (no Touch ID within 50 s: Cursor's 60 s initialize window allows no more), so the child is logged out")], secret);
        eprintln!("initialize answered {} ms after the spawn", took.as_millis());
        assert_nowhere(&mut h, secret);
    }

    // -- signals during the unseal --------------------------------------------------------------

    /// Ctrl-C, the extension's SIGTERM or a SIGHUP while Touch ID is awaited:
    /// the dialog is closed (the decrypt's process group is gone), nothing is
    /// spawned, the fresh scratch dir is removed, the census gets its end row,
    /// and the wrapper exits at once — 130 for SIGINT, 143 for SIGTERM and
    /// SIGHUP, as `vm exec` — instead of leaving the dialog behind. Each
    /// signal is at its default disposition for the wrapper, whatever this
    /// test process inherited. F23: with the synthetic knob (here for the
    /// SIGTERM, as B11 runs it), that end row says `synthetic_oauth:unsent`
    /// after `credential:none` (the session was never initialized); without
    /// it, no class.
    #[test]
    fn a_signal_during_the_unseal_closes_the_dialog_and_ends_the_wrapper() {
        for (sig, code, synthetic) in [(libc::SIGTERM, 143, true), (libc::SIGINT, 130, false), (libc::SIGHUP, 143, false)] {
            let p = Harness::prepare();
            let world = World::new(&p);
            let t = token(&format!("Sg{sig:02}"));
            world.seal(&t);
            let secret = random_part(&t);
            let pidfile = world.pidfile().display().to_string();
            let knob = if synthetic { "10000" } else { "0" };
            let envs = world.envs(&[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", pidfile.as_str()), (SYNTHETIC_OAUTH_KNOB, knob)]);
            let mut h = spawn_with(p, &refs(&envs), sig, libc::SIG_DFL);
            send_init(&mut h, secret);
            let (pgid, mut guard) = GroupGuard::started(&world, &h, secret);
            assert!(group_alive(pgid));
            let sent = Instant::now();
            signal(&h, sig);
            let status = await_exit(&mut h, Duration::from_secs(10), secret);
            assert!(status.code() == Some(code), "signal {sig}: exit {:?}, expected {code}\n{}", status.code(), masked(&h, secret));
            assert!(sent.elapsed() < Duration::from_secs(5), "signal {sig}: the wrapper ended at once ({:?})", sent.elapsed());
            guard.gone();
            assert!(h.err_text().contains("ai-env-claude: stopped while waiting for Touch ID: the dialog was closed and nothing was started"), "{}", masked(&h, secret));
            assert_eq!(h.spawn_count(), 0, "no child was started");
            assert!(world.token_log().is_empty());
            let end = h.end_row();
            assert_eq!(end["exit"], code);
            assert_end_note(&h, "end:sigterm", secret);
            assert_end_note(&h, "credential:none", secret);
            let note = h.end_note();
            if synthetic {
                assert!(note.ends_with("; credential:none; synthetic_oauth:unsent"), "signal {sig}: {}", mask(&note, secret));
            } else {
                assert!(!note.contains("synthetic_oauth"), "signal {sig}: {}", mask(&note, secret));
            }
            assert!(h.scratch_names().is_empty(), "the fresh scratch dir is gone: {:?}", h.scratch_names());
            assert_audit(&h, "credential_unseal", "outcome", &format!("signal {sig}"), secret);
            assert_nowhere(&mut h, secret);
        }
    }

    /// A SIGINT the wrapper inherited as ignored stays ignored while Touch ID
    /// is awaited (a background job's Ctrl-C is not meant for it): the dialog
    /// stays up and the wait goes on; a SIGTERM still closes it (143).
    #[test]
    fn an_ignored_sigint_stays_ignored_during_the_unseal() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("IgnI");
        world.seal(&t);
        let secret = random_part(&t);
        let pidfile = world.pidfile().display().to_string();
        let envs = world.envs(&[("FAKE_AGE_HANG", "1"), ("FAKE_AGE_PIDFILE", pidfile.as_str())]);
        let mut h = spawn_with(p, &refs(&envs), libc::SIGINT, libc::SIG_IGN);
        let (pgid, mut guard) = GroupGuard::started(&world, &h, secret);
        signal(&h, libc::SIGINT);
        // A caught SIGINT would have ended the wrapper within the poll and the 0.5 s kill ladder.
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!h.exited_now(), "an ignored SIGINT ended the wrapper\n{}", masked(&h, secret));
        assert!(group_alive(pgid), "an ignored SIGINT closed the dialog");
        h.sigterm();
        let status = await_exit(&mut h, Duration::from_secs(10), secret);
        assert!(status.code() == Some(143), "exit {:?}\n{}", status.code(), masked(&h, secret));
        guard.gone();
        assert_audit(&h, "credential_unseal", "outcome", &format!("signal {}", libc::SIGTERM), secret);
        assert_nowhere(&mut h, secret);
    }

    // -- --resume: the seed retry and how long the copy is kept -----------------------------------

    /// The seed retry of a `--resume` respawns the child, and the second
    /// generation gets the token too, from the same single unseal: the
    /// wrapper keeps its copy only while that retry is possible and drops it
    /// once the second generation started; the end row says `credential:fd`.
    #[test]
    fn the_seed_retry_hands_the_token_to_the_respawned_child() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Rsp9");
        world.seal(&t);
        let secret = random_part(&t);
        let sid = uuid(0x5e57_0009);
        p.plant_transcript(&sid, &[&format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, uuid(0x5e57_1009))]);
        let marker = p.root.join("resume.marker").display().to_string();
        let envs = world.envs(&[("FAKE_RESUME_FAIL_ONCE", marker.as_str())]);
        let resume = format!("--resume={sid}");
        let mut h = p.spawn("local-scratch", &[&resume], &refs(&envs));
        one_turn(&mut h, secret);
        assert!(h.spawn_count() == 2, "{} spawns\n{}", h.spawn_count(), masked(&h, secret));
        let log = world.token_log();
        assert_eq!(log.len(), 2, "{log:?}");
        let len = t.len().to_string();
        for line in &log {
            assert_eq!(token_fields(line), ["fd", len.as_str(), sha8(&t).as_str(), "3", "absent"], "{line}");
        }
        assert_eq!(world.decrypts(), 1, "one Touch ID for both generations");
        assert_eq!(h.audit_events("credential_deliver").len(), 2);
        assert_eq!(dropped_reasons(&h), ["the child started and no retry can respawn it"], "dropped at the second spawn");
        assert_end_note(&h, "respawns:1", secret);
        assert_end_note(&h, "credential:fd", secret);
        assert_nowhere(&mut h, secret);
    }

    /// A `--resume` that loads keeps the copy no longer than the retry could
    /// need it: the first init that reaches the host ends it, there and then.
    #[test]
    fn a_resumed_session_drops_the_copy_at_its_first_init() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Ini1");
        world.seal(&t);
        let secret = random_part(&t);
        let resume = format!("--resume={}", uuid(0x5e57_0011));
        let envs = world.envs(&[]);
        let mut h = p.spawn("local-scratch", &[&resume], &refs(&envs));
        one_turn(&mut h, secret);
        assert_eq!(token_fields(&world.token_log()[0])[0], "fd");
        let wlog = h.wrapper_log();
        let dropped = wlog.find(DROPPED).expect("the wrapper's copy is dropped");
        let init = wlog.find("session id learned").expect("the init is logged");
        assert!(init < dropped, "kept until the init: a seed retry was still possible");
        assert_eq!(dropped_reasons(&h), ["the first init"]);
        assert_nowhere(&mut h, secret);
    }

    /// A resumed chat that sits idle after `initialize` — the CLI sends its
    /// first init only with the first turn — does not keep the copy until
    /// then: it goes two seconds after the answer to `initialize`, before any
    /// turn, and the session goes on as usual.
    #[test]
    fn an_idle_resumed_chat_drops_the_copy_after_the_initialize_grace() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Idl2");
        world.seal(&t);
        let secret = random_part(&t);
        let resume = format!("--resume={}", uuid(0x5e57_0012));
        let envs = world.envs(&[("FAKE_INIT_AT_TURN", "1")]);
        let mut h = p.spawn("local-scratch", &[&resume], &refs(&envs));
        let init = send_init(&mut h, secret);
        await_frame(&mut h, |v| is_response_to(v, &init), T, secret);
        let answered = Instant::now();
        await_cond(&mut h, "the copy is dropped", secret, |h| !dropped_reasons(h).is_empty());
        // The grace is 2 s from the wrapper's own sight of the answer; this test may see it later.
        assert!(answered.elapsed() >= Duration::from_secs(1), "dropped {:?} after the answer, before the grace", answered.elapsed());
        assert_eq!(dropped_reasons(&h), ["no resume miss within the grace after initialize"]);
        assert!(h.out_matching(is_init).is_empty(), "no turn yet, so no init");
        let u = send_turn(&mut h, "the first turn of the resumed chat", secret);
        await_frame(&mut h, is_init, T, secret);
        await_frame(&mut h, |v| is_result_for(v, &u), T, secret);
        h.close_stdin();
        let status = await_exit(&mut h, EXIT, secret);
        assert!(status.code() == Some(0), "exit {:?}\n{}", status.code(), masked(&h, secret));
        assert_eq!(token_fields(&world.token_log()[0])[0], "fd");
        assert_eq!(dropped_reasons(&h).len(), 1, "dropped once");
        assert_nowhere(&mut h, secret);
    }

    /// A resume miss later than that grace (the CLI reports one at startup,
    /// so this is the fallback, not the plan) still gets its seed retry, but
    /// the copy is gone: the respawned child runs logged out, one note line
    /// says why, and the session answers. F24: the end row says
    /// `credential:none`, how the generation that served the session was
    /// logged in, not the first generation's `fd`.
    #[test]
    fn a_resume_miss_after_the_grace_respawns_the_child_logged_out() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Lat3");
        world.seal(&t);
        let secret = random_part(&t);
        let sid = uuid(0x5e57_0013);
        p.plant_transcript(&sid, &[&format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, uuid(0x5e57_1013))]);
        let marker = p.root.join("resume.marker").display().to_string();
        let envs = world.envs(&[("FAKE_RESUME_FAIL_ONCE", marker.as_str()), ("FAKE_RESUME_FAIL_AFTER_ACK", "1"), ("FAKE_MISS_DELAY_MS", "4000")]);
        let resume = format!("--resume={sid}");
        let mut h = p.spawn("local-scratch", &[&resume], &refs(&envs));
        one_turn(&mut h, secret);
        assert!(h.spawn_count() == 2, "{} spawns\n{}", h.spawn_count(), masked(&h, secret));
        let log = world.token_log();
        assert_eq!(log.len(), 2, "{log:?}");
        assert_eq!((token_fields(&log[0])[0], token_fields(&log[1])[0]), ("fd", "none"), "{log:?}");
        assert_eq!(world.decrypts(), 1, "no second Touch ID");
        assert_eq!(dropped_reasons(&h), ["no resume miss within the grace after initialize"]);
        assert_notes(&mut h, &[format!("{NOTE_HEAD}the seed retry respawned the child after the setup-token copy was dropped, so the child is logged out")], secret);
        assert_eq!(h.audit_events("credential_deliver").len(), 1, "delivered to the first generation only");
        assert_end_note(&h, "respawns:1", secret);
        assert_end_note(&h, "credential:none", secret);
        assert_nowhere(&mut h, secret);
    }

    /// F9: generation 1 answers `initialize`, reports the resume miss at
    /// once, and is still exiting (3.5 s) when the 2 s grace after that
    /// answer runs out: the held miss keeps the copy, and the seed retry
    /// hands it to generation 2, from the session's one Touch ID. The copy
    /// goes at that second spawn; no note line, and `credential:fd`.
    #[test]
    fn a_miss_held_over_the_initialize_grace_keeps_the_token_for_the_retry() {
        let p = Harness::prepare();
        let world = World::new(&p);
        let t = token("Hld4");
        world.seal(&t);
        let secret = random_part(&t);
        let sid = uuid(0x5e57_0014);
        p.plant_transcript(&sid, &[&format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, uuid(0x5e57_1014))]);
        let marker = p.root.join("resume.marker").display().to_string();
        let envs = world.envs(&[("FAKE_RESUME_FAIL_ONCE", marker.as_str()), ("FAKE_RESUME_FAIL_AFTER_ACK", "1"), ("FAKE_MISS_EXIT_DELAY_MS", "3500")]);
        let resume = format!("--resume={sid}");
        let mut h = p.spawn("local-scratch", &[&resume], &refs(&envs));
        let started = Instant::now();
        one_turn(&mut h, secret);
        assert!(started.elapsed() >= Duration::from_millis(3500), "generation 1 was still exiting past the grace: {:?}", started.elapsed());
        assert!(h.spawn_count() == 2, "{} spawns\n{}", h.spawn_count(), masked(&h, secret));
        let log = world.token_log();
        assert_eq!(log.len(), 2, "{log:?}");
        let len = t.len().to_string();
        for line in &log {
            assert_eq!(token_fields(line), ["fd", len.as_str(), sha8(&t).as_str(), "3", "absent"], "{line}");
        }
        assert_eq!(world.decrypts(), 1, "one Touch ID for both generations");
        assert_eq!(h.audit_events("credential_deliver").len(), 2);
        assert_eq!(dropped_reasons(&h), ["the child started and no retry can respawn it"], "kept over the grace, dropped at the second spawn");
        assert_notes(&mut h, &[], secret);
        assert_end_note(&h, "credential:fd", secret);
        assert_nowhere(&mut h, secret);
    }

    // -- the synthetic oauth_token_refresh (lab knob) --------------------------------------------

    /// The extension's answer to the synthetic request.
    fn answer(id: &str, inner: &str) -> String {
        format!(r#"{{"type":"control_response","response":{{"request_id":"{id}",{inner}}}}}"#)
    }

    /// The synthetic request on the host's stdout.
    fn is_synthetic_request(v: &Value) -> bool {
        v["type"] == "control_request" && v["request"]["subtype"] == "oauth_token_refresh"
    }

    /// With the lab knob the pump sends the extension one `oauth_token_refresh`
    /// right after the `initialize` response, and the end row records the
    /// class of the answer — the stock extension's error text, a null or
    /// missing token, or a token by its length only — while the answer itself
    /// never reaches the child.
    #[test]
    fn synthetic_oauth_records_the_answer_class_and_never_forwards_it() {
        let t = token("Syn3");
        let secret = random_part(&t);
        let cases: [(String, String); 4] = [
            (r#""subtype":"error","error":"getOAuthToken callback is not provided.""#.into(), "error(getOAuthToken callback is not provided.)".into()),
            (r#""subtype":"success","response":{"accessToken":null}"#.into(), "null".into()),
            (r#""subtype":"success","response":{}"#.into(), "absent".into()),
            (format!(r#""subtype":"success","response":{{"accessToken":"{t}"}}"#), format!("token(len={})", t.len())),
        ];
        for (inner, want) in cases {
            let mut h = Harness::spawn("local-child", &[], &[(SYNTHETIC_OAUTH_KNOB, "30000")]);
            let init = send_init(&mut h, secret);
            let req = await_frame(&mut h, is_synthetic_request, T, secret);
            let id = req["request_id"].as_str().expect("a request id").to_string();
            let out = h.out_json();
            let at_response = out.iter().position(|v| is_response_to(v, &init)).expect("the initialize response");
            let at_request = out.iter().position(is_synthetic_request).unwrap();
            assert!(at_response < at_request, "sent once the session is initialized");
            send_line(&mut h, &answer(&id, &inner), secret);
            let u = send_turn(&mut h, "after the synthetic answer", secret);
            await_frame(&mut h, |v| is_result_for(v, &u), T, secret);
            h.close_stdin();
            let status = await_exit(&mut h, EXIT, secret);
            assert!(status.code() == Some(0), "exit {:?}\n{}", status.code(), masked(&h, secret));
            assert_eq!(h.out_matching(is_synthetic_request).len(), 1, "one synthetic request");
            assert!(h.stdin_of(1).iter().all(|l| !l.contains(&id)), "the answer reached the child: {want}");
            assert_end_note(&h, &format!("synthetic_oauth:{want}"), secret);
            let rows = h.audit_events("synthetic_oauth");
            assert!(rows.len() == 1, "{}", mask(&format!("{:#?}", h.audit_rows()), secret));
            assert_audit(&h, "synthetic_oauth", "class", &want, secret);
            assert_nowhere(&mut h, secret);
        }
    }

    /// No answer within the wait is `none`, and an answer that comes later is
    /// still the pump's own: dropped, never forwarded to the child, the class
    /// unchanged.
    #[test]
    fn synthetic_oauth_without_an_answer_in_time_is_none_and_a_late_one_is_dropped() {
        let mut h = Harness::spawn("local-child", &[], &[(SYNTHETIC_OAUTH_KNOB, "300")]);
        h.send_initialize();
        let req = h.expect_out(is_synthetic_request, T);
        let id = req["request_id"].as_str().expect("a request id").to_string();
        h.wait_until("the synthetic wait ran out", T, |h| !h.audit_events("synthetic_oauth").is_empty());
        assert_eq!(h.audit_events("synthetic_oauth")[0]["detail"]["class"], "none");
        h.send(&answer(&id, r#""subtype":"error","error":"late""#));
        let u = h.send_user("after the late answer");
        h.expect_out(|v| is_result_for(v, &u), T);
        h.close_stdin();
        let (status, _) = h.wait(EXIT);
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
        assert!(h.stdin_of(1).iter().all(|l| !l.contains(&id)), "the late answer reached the child");
        assert!(note_has(&h.end_note(), "synthetic_oauth:none"), "{}", h.end_note());
        assert_eq!(h.audit_events("synthetic_oauth").len(), 1, "the late answer changes nothing");
    }

    /// Plan step B11 offline: a piped session with the knob, answered as the
    /// stock extension answers, then `ai-env wrapper census --record-probes`
    /// on that census: `stock-ext-oauth` keeps its verdict from the env names
    /// and carries the answer in its note, printed and recorded.
    #[test]
    fn record_probes_puts_the_stock_extensions_answer_in_the_stock_ext_oauth_note() {
        let mut h = Harness::spawn("local-child", &[], &[(SYNTHETIC_OAUTH_KNOB, "30000"), ("CLAUDE_CODE_ENTRYPOINT", "claude-vscode")]);
        h.send_initialize();
        let req = h.expect_out(is_synthetic_request, T);
        let id = req["request_id"].as_str().expect("a request id").to_string();
        h.send(&answer(&id, r#""subtype":"error","error":"getOAuthToken callback is not provided.""#));
        let u = h.send_user("one turn");
        h.expect_out(|v| is_result_for(v, &u), T);
        h.close_stdin();
        let (status, _) = h.wait(EXIT);
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
        let out = Command::new(env!("CARGO_BIN_EXE_ai-env"))
            .args(["wrapper", "census", "--record-probes"])
            .env("HOME", h.root())
            .env("AI_ENV_BRIDGE_DIR", h.bridge())
            .env_remove("AI_ENV_BRIDGE_CONFIG")
            .output()
            .expect("spawn ai-env");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
        let note = "the extension answered the synthetic oauth_token_refresh with error(getOAuthToken callback is not provided.)";
        assert!(stdout.contains(&format!("recorded stock-ext-oauth=absent (expected absent)\n  {note}\n")), "{stdout}");
        let probes = std::fs::read_to_string(h.bridge().join("lab").join("probes.jsonl")).expect("the probes were recorded");
        let row: Value = probes.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).rfind(|r| r["probe"] == "stock-ext-oauth").expect("a stock-ext-oauth row");
        assert_eq!((row["verdict"].as_str(), row["note"].as_str()), (Some("absent"), Some(note)));
    }

    /// A session that never initializes sends nothing: `unsent`.
    #[test]
    fn synthetic_oauth_is_unsent_before_the_session_is_initialized() {
        let mut h = Harness::spawn("local-child", &[], &[(SYNTHETIC_OAUTH_KNOB, "300")]);
        h.close_stdin();
        let (status, _) = h.wait(EXIT);
        assert_eq!(status.code(), Some(0), "{}", h.transcript());
        assert!(h.out_matching(is_synthetic_request).is_empty());
        assert!(note_has(&h.end_note(), "synthetic_oauth:unsent"), "{}", h.end_note());
    }

    /// F25: a resumed chat that its seed retry initialized — generation 1
    /// reports the resume miss before it answers `initialize`, as the CLI
    /// does, and generation 2's answer to the replayed request reaches the
    /// host under the host's id — is initialized all the same: the pump sends
    /// its one synthetic request, and the end row records the answer's class,
    /// not `unsent`. A miss after generation 1 answered sends it from
    /// generation 1, and generation 2's swallowed answer sends no second one.
    /// The answer never reaches a child.
    #[test]
    fn synthetic_oauth_goes_out_once_when_the_seed_retry_initialized_the_session() {
        for (after_ack, n) in [(false, 0x5e57_0f25_u64), (true, 0x5e57_0f26)] {
            let p = Harness::prepare();
            let sid = uuid(n);
            p.plant_transcript(&sid, &[&format!(r#"{{"type":"user","uuid":"{}","sessionId":"{sid}","message":{{"role":"user","content":"earlier"}}}}"#, uuid(n + 0x1000))]);
            let marker = p.root.join("resume.marker").display().to_string();
            let resume = format!("--resume={sid}");
            // Emptied, as `World::envs` does: a developer's own value would hold generation 1's exit.
            let mut envs = vec![("FAKE_RESUME_FAIL_ONCE", marker.as_str()), (SYNTHETIC_OAUTH_KNOB, "30000"), ("FAKE_MISS_EXIT_DELAY_MS", "")];
            if after_ack {
                envs.push(("FAKE_RESUME_FAIL_AFTER_ACK", "1"));
            }
            let mut h = p.spawn("local-scratch", &[&resume], &envs);
            let init = h.send_initialize();
            h.expect_out(|v| is_response_to(v, &init), T);
            // Queued right behind the initialize response, so it is there at once or never.
            let req = h.expect_out(is_synthetic_request, Duration::from_secs(5));
            let id = req["request_id"].as_str().expect("a request id").to_string();
            h.send(&answer(&id, r#""subtype":"error","error":"getOAuthToken callback is not provided.""#));
            let u = h.send_user("a turn of the resumed chat");
            h.expect_out(|v| is_result_for(v, &u), T);
            h.close_stdin();
            let (status, _) = h.wait(EXIT);
            assert_eq!(status.code(), Some(0), "after_ack {after_ack}: {}", h.transcript());
            assert_eq!(h.spawn_count(), 2, "after_ack {after_ack}: the seed retry ran");
            assert_eq!(h.out_matching(|v| is_response_to(v, &init)).len(), 1, "after_ack {after_ack}: one initialize answer reached the host");
            assert_eq!(h.out_matching(is_synthetic_request).len(), 1, "after_ack {after_ack}: one synthetic request");
            for gen in 1..=2 {
                assert!(h.stdin_of(gen).iter().all(|l| !l.contains(&id)), "after_ack {after_ack}: the answer reached generation {gen}");
            }
            assert!(note_has(&h.end_note(), "synthetic_oauth:error(getOAuthToken callback is not provided.)"), "after_ack {after_ack}: {}", h.end_note());
        }
    }
}
