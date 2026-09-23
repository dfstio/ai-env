//! Wrapper tests (T1.2) — compiled only with `bridge` (`CARGO_BIN_EXE_ai-env-claude`
//! is unset otherwise). std::process only (assert_cmd is not vendored). Every
//! wrapper run execs `tests/fakes/claude.sh` copied into a tempdir, with the
//! child's `HOME` and `AI_ENV_BRIDGE_DIR` pointed at that tempdir, so the
//! census, `bridge.toml` and the argv log never touch the developer's
//! `~/.config/ai-env`. Nothing here mutates the test process's environment:
//! every variable is set on the child `Command`.
use ai_env_cli::bridge::census::CENSUS_VALUE_ALLOWLIST;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn wrapper() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env-claude")
}

/// The fake `claude`, copied into every `FakeClaude` tempdir.
const FAKE_SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/claude.sh");

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

/// `tests/fakes/claude.sh` copied into a tempdir as `claude` (0755): it logs
/// every argument to `$ARGV_LOG`, prints `$FAKE_STDOUT` when set, copies stdin
/// to stdout when `FAKE_ECHO_STDIN=1` and exits `${FAKE_EXIT:-0}`. The same
/// tempdir is the child's `HOME`, and `<tmp>/bridge` its `AI_ENV_BRIDGE_DIR`,
/// so `bridge.toml`, the census and the argv log all live under it.
struct FakeClaude {
    dir: tempfile::TempDir,
}

impl FakeClaude {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("claude");
        std::fs::copy(FAKE_SCRIPT, &script).unwrap_or_else(|e| panic!("copy {FAKE_SCRIPT}: {e}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
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
    /// argv log, `HOME` and `AI_ENV_BRIDGE_DIR` set; the kill switch, the lab
    /// knob and a config-path override removed (a developer's shell may carry
    /// them); then `envs` applied in order, so a test may set any of them.
    /// The cwd is left to the caller.
    fn command(&self, real: &Path, args: &[&str], envs: &[(&str, &str)]) -> Command {
        let mut cmd = Command::new(wrapper());
        cmd.arg(real).args(args);
        cmd.env("ARGV_LOG", self.log_path()).env("HOME", self.tmp()).env("AI_ENV_BRIDGE_DIR", self.bridge_dir());
        cmd.env_remove("AI_ENV_BRIDGE_LOCAL").env_remove("AI_ENV_BRIDGE_LAB_EXIT").env_remove("AI_ENV_BRIDGE_CONFIG");
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
