//! `ai-env wrapper install` and `ai-env wrapper census` — compiled only with
//! `bridge`. Every command runs with the child's `HOME` and
//! `AI_ENV_BRIDGE_DIR` under a tempdir, so Cursor's real `settings.json`
//! (`~/Library/Application Support/Cursor/User`) and the developer's
//! `~/.config/ai-env` are never touched. The sibling the command installs is
//! the freshly built `ai-env-claude` next to `CARGO_BIN_EXE_ai-env`, which
//! lives under `target/` and so exercises the build-directory warning.
//! std::process only; nothing here mutates the test process's environment.
use ai_env_cli::bridge::census::CensusRow;
use ai_env_cli::bridge::doctor::{parse_settings, PERMISSION_SETTING, WRAPPER_SETTING};
use ai_env_cli::bridge::wrapper::ProbeRow;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn ai_env() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env")
}

/// The sibling `wrapper install` resolves: `<dir of ai-env>/ai-env-claude`,
/// absolute and not canonicalised.
fn sibling() -> PathBuf {
    Path::new(ai_env()).with_file_name("ai-env-claude")
}

/// Whether the test binaries live under a `target/` component (cargo's
/// default): then `wrapper install` must print its build-directory warning.
fn under_target() -> bool {
    Path::new(ai_env()).components().any(|c| c.as_os_str() == "target")
}

/// Lossy text of a captured stream, for assertions and their messages.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A JSON string literal, as `wrapper install` writes it.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

#[cfg(unix)]
fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// The `target/` warning is on stderr exactly when the sibling is under `target/`.
fn assert_target_warning(stderr: &str) {
    if under_target() {
        assert!(stderr.lines().any(|l| l.starts_with("ai-env: warning: ") && l.contains("build directory")), "{stderr}");
    } else {
        assert!(!stderr.contains("warning"), "{stderr}");
    }
}

/// The exact snippet `wrapper install` prints for the manual path.
fn snippet(wrapper: &str, mode: &str) -> String {
    format!("{{\n  {}: {},\n  {}: {}\n}}\n", json_str(WRAPPER_SETTING), json_str(wrapper), json_str(PERMISSION_SETTING), json_str(mode))
}

const BUNDLED: &str = "/Users/mike/.cursor/extensions/anthropic.claude-code-2.1.278-darwin-arm64/resources/native-binary/claude";
const CWD: &str = "/Users/mike/Documents/DeFi/ai-env";
const OAUTH_REFRESH_VAR: &str = "CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH";
const SESSION_TAIL: [&str; 5] = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json"];
const PLAIN_ENV: [&str; 4] = ["CLAUDE_AGENT_SDK_VERSION", "CLAUDE_CODE_ENTRYPOINT", "HOME", "PATH"];

/// A census row shaped like `CensusRow` (proved by deserialising it), with
/// the S1 `env_selected` fingerprint of a Cursor session.
fn census_row(ts: &str, route: &str, reason: &str, tail: &[&str], env_names: &[&str]) -> serde_json::Value {
    let mut argv = vec!["/Users/mike/.cargo/bin/ai-env-claude", BUNDLED];
    argv.extend_from_slice(tail);
    let row = serde_json::json!({
        "v": 1,
        "ts": ts,
        "start": 1_790_150_400_000u64,
        "pid": 4242,
        "ppid": 4200,
        "ext": "2.1.278",
        "route": route,
        "reason": reason,
        "argv": argv,
        "cwd": CWD,
        "env_names": env_names,
        "env_selected": {"CLAUDE_CODE_ENTRYPOINT": "claude-vscode", "CLAUDE_AGENT_SDK_VERSION": "0.3.278"},
        "note": null
    });
    serde_json::from_value::<CensusRow>(row.clone()).unwrap_or_else(|e| panic!("not a CensusRow: {e}"));
    row
}

/// A tempdir standing in for the user's home: Cursor's settings file under
/// `Library/Application Support/Cursor/User`, the bridge state under `bridge/`.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        Home { dir: tempfile::tempdir().unwrap() }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The child's `AI_ENV_BRIDGE_DIR`.
    fn bridge_dir(&self) -> PathBuf {
        self.path().join("bridge")
    }

    fn settings_dir(&self) -> PathBuf {
        self.path().join("Library").join("Application Support").join("Cursor").join("User")
    }

    fn settings_path(&self) -> PathBuf {
        self.settings_dir().join("settings.json")
    }

    fn write_settings(&self, text: &str) {
        std::fs::create_dir_all(self.settings_dir()).unwrap();
        std::fs::write(self.settings_path(), text).unwrap();
    }

    fn settings_text(&self) -> String {
        std::fs::read_to_string(self.settings_path()).unwrap()
    }

    /// Every `settings.json.<ts>.ai-env.bak` next to the settings file, sorted.
    fn backups(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(self.settings_dir())
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        let name = p.file_name().unwrap().to_string_lossy().into_owned();
                        name.starts_with("settings.json.") && name.ends_with(".ai-env.bak")
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    fn census_path(&self) -> PathBuf {
        self.bridge_dir().join("logs").join("census.jsonl")
    }

    fn probes_path(&self) -> PathBuf {
        self.bridge_dir().join("lab").join("probes.jsonl")
    }

    /// Append `rows` to the census file, one JSON line each.
    fn seed_census(&self, rows: &[serde_json::Value]) {
        std::fs::create_dir_all(self.census_path().parent().unwrap()).unwrap();
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.census_path()).unwrap();
        for r in rows {
            writeln!(f, "{r}").unwrap();
        }
    }

    /// Every probe row, oldest first; empty when the file is absent. A line
    /// that does not parse as a `ProbeRow` is a failure, never skipped.
    fn probes(&self) -> Vec<ProbeRow> {
        std::fs::read_to_string(self.probes_path())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("probe line {l:?}: {e}")))
            .collect()
    }

    /// `<bin> wrapper <args…>` with `HOME` and `AI_ENV_BRIDGE_DIR` under the
    /// tempdir and every ai-env override a developer's shell may carry removed.
    fn command(&self, bin: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new(bin);
        cmd.arg("wrapper").args(args).env("HOME", self.path()).env("AI_ENV_BRIDGE_DIR", self.bridge_dir());
        cmd.env_remove("AI_ENV_DIR").env_remove("AI_ENV_BRIDGE_CONFIG").env_remove("AI_ENV_BRIDGE_LOCAL").env_remove("AI_ENV_BRIDGE_LAB_EXIT");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(ai_env(), args).output().expect("spawn ai-env")
    }
}

#[test]
fn wrapper_help_lists_install_and_census() {
    let out = Home::new().run(&["--help"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("install") && stdout.contains("census"), "{stdout}");
    let out = Home::new().run(&["install", "--help"]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("--write") && stdout.contains("--permission-mode <M>"), "{stdout}");
    let out = Home::new().run(&["census", "--help"]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("--last <N>") && stdout.contains("--json") && stdout.contains("--record-probes"), "{stdout}");
}

// ---- wrapper install ------------------------------------------------------------

#[test]
fn install_dry_run_writes_nothing_and_prints_the_snippet() {
    let home = Home::new();
    let out = home.run(&["install"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    let wrapper = sibling();
    let w = wrapper.to_str().unwrap();
    assert!(wrapper.is_absolute());
    assert!(stdout.contains(&format!("wrapper:  {w}\n")), "{stdout}");
    let v = env!("CARGO_PKG_VERSION");
    assert!(stdout.contains(&format!("versions: ai-env {v}, ai-env-claude {v}\n")), "{stdout}");
    assert!(stdout.contains(&format!("settings: {} (will be created)\n", home.settings_path().display())), "{stdout}");
    assert!(stdout.contains(&format!("  {WRAPPER_SETTING}: unset -> {w:?}\n")), "{stdout}");
    assert!(stdout.contains(&format!("  {PERMISSION_SETTING}: unset -> \"default\"\n")), "{stdout}");
    let snip = snippet(w, "default");
    assert!(stdout.contains(&snip), "{stdout}");
    assert_eq!(parse_settings(&snip).unwrap()[WRAPPER_SETTING], w, "the snippet is valid JSON");
    assert!(stdout.contains("re-run with --write"), "{stdout}");
    assert!(!stdout.contains("backup:") && !stdout.contains("wrote:"), "{stdout}");
    for line in ["disableLoginPrompt", "Manual mode", "--permission-mode default", "Reload the Cursor window", "stops self-updating", "CLAUDE_CONFIG_DIR", "AI_ENV_BRIDGE_LOCAL=1"] {
        assert!(stdout.contains(line), "{line}: {stdout}");
    }
    assert_target_warning(&stderr);
    assert!(!home.settings_path().exists() && !home.settings_dir().exists(), "a dry run creates nothing");
    assert!(!home.bridge_dir().exists(), "a dry run touches no bridge state");

    // With an existing file: byte-identical afterwards, no backup, current values shown.
    let src = "{\"editor.tabSize\": 2}";
    home.write_settings(src);
    let out = home.run(&["install"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert_eq!(home.settings_text(), src);
    assert!(home.backups().is_empty());
    assert!(stdout.contains(&format!("settings: {}\n", home.settings_path().display())), "{stdout}");
}

#[test]
fn install_default_mode_comes_from_bridge_toml_and_the_flag_overrides_it() {
    let home = Home::new();
    std::fs::create_dir_all(home.bridge_dir()).unwrap();
    std::fs::write(home.bridge_dir().join("bridge.toml"), "[wrapper]\ninitial_permission_mode = \"plan\"\n").unwrap();
    let w = sibling();
    let out = home.run(&["install"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains(&snippet(w.to_str().unwrap(), "plan")), "{stdout}");
    assert!(stdout.contains("--permission-mode plan on every spawn"), "{stdout}");
    let out = home.run(&["install", "--permission-mode", "acceptEdits"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains(&snippet(w.to_str().unwrap(), "acceptEdits")), "{stdout}");
    assert!(!home.settings_dir().exists());
}

#[test]
fn install_write_backs_up_and_splices_jsonc() {
    let home = Home::new();
    let src = "{\n  // Cursor settings\n  \"claudeCode.preferredLocation\": \"panel\", /* keep */\n  \"editor.tabSize\": 2, // two\n  \"list\": [1, 2, ],\n}\n";
    home.write_settings(src);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.settings_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let out = home.run(&["install", "--write", "--permission-mode", "manual"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert_target_warning(&stderr);
    let w = sibling();
    let w = w.to_str().unwrap();

    let backups = home.backups();
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), src, "the backup is the original, byte for byte");
    assert!(stdout.contains(&format!("backup: {}\n", backups[0].display())), "{stdout}");
    assert!(stdout.contains(&format!("wrote: {}\n", home.settings_path().display())), "{stdout}");
    assert!(stdout.contains("initialPermissionMode = manual reaches the CLI as --permission-mode default"), "{stdout}");
    assert!(stdout.contains(&format!("  {WRAPPER_SETTING}: unset -> {w:?}\n")), "{stdout}");

    let new = home.settings_text();
    let want = format!("{}  {}: {},\n  {}: \"manual\",\n}}\n", &src[..src.len() - 2], json_str(WRAPPER_SETTING), json_str(w), json_str(PERMISSION_SETTING));
    assert_eq!(new, want, "comments, order and the trailing-comma style survive; only the two keys are added");
    assert!(new.contains("// Cursor settings") && new.contains("/* keep */") && new.contains("// two"));
    let v = parse_settings(&new).unwrap();
    assert_eq!(v[WRAPPER_SETTING], w);
    assert_eq!(v[PERMISSION_SETTING], "manual");
    assert_eq!(v["editor.tabSize"], 2);
    assert_eq!(v["claudeCode.preferredLocation"], "panel");
    assert_eq!(v["list"], serde_json::json!([1, 2]));
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&home.settings_path()), 0o644, "the original mode is restored after the atomic write");
        assert_eq!(mode_of(&backups[0]), 0o644, "the backup carries the original mode, not the umask default");
        assert!(!home.settings_dir().join(".settings.json.tmp").exists(), "no temp file left behind");
    }
    assert!(!home.bridge_dir().exists(), "install touches no bridge state");
}

#[test]
fn install_write_plain_json_keeps_key_order() {
    let home = Home::new();
    let src = "{\n    \"editor.tabSize\": 2,\n    \"zebra\": \"last\",\n    \"alpha\": {\"k\": [1, 2]}\n}\n";
    home.write_settings(src);
    let out = home.run(&["install", "--write"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    let w = sibling();
    let w = w.to_str().unwrap();
    let new = home.settings_text();
    let want = format!(
        "{},\n    {}: {},\n    {}: \"default\"\n}}\n",
        src.strip_suffix("\n}\n").unwrap(),
        json_str(WRAPPER_SETTING),
        json_str(w),
        json_str(PERMISSION_SETTING)
    );
    assert_eq!(new, want, "four-space indent detected, keys appended in order, no trailing comma introduced");
    let pos = |key: &str| new.find(&format!("{}:", json_str(key))).unwrap_or_else(|| panic!("{key} missing in {new}"));
    assert!(pos("editor.tabSize") < pos("zebra") && pos("zebra") < pos("alpha") && pos("alpha") < pos(WRAPPER_SETTING) && pos(WRAPPER_SETTING) < pos(PERMISSION_SETTING));
    let v = parse_settings(&new).unwrap();
    assert_eq!(v[WRAPPER_SETTING], w);
    assert_eq!(v[PERMISSION_SETTING], "default");
    assert_eq!(v["alpha"]["k"], serde_json::json!([1, 2]));
    assert_eq!(home.backups().len(), 1);
    assert_eq!(std::fs::read_to_string(&home.backups()[0]).unwrap(), src);
}

#[test]
fn install_rejects_an_unknown_permission_mode_with_exit_2() {
    let home = Home::new();
    let out = home.run(&["install", "--permission-mode", "bogus"]);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.starts_with("ai-env: "), "{err}");
    assert!(err.contains("\"bogus\"") && err.contains("bypassPermissions"), "{err}");
    assert!(!home.settings_dir().exists());
    // With --write too: the mode is checked before the settings file is touched.
    home.write_settings("{}\n");
    let out = home.run(&["install", "--write", "--permission-mode", "bogus"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert_eq!(home.settings_text(), "{}\n");
    assert!(home.backups().is_empty());
}

/// `age_cmd::effective_path()` appends `/opt/homebrew/bin` (or `/usr/local/bin`)
/// to any PATH that lacks it, so an `ai-env-claude` installed there would be
/// found whatever PATH a test sets; the exit-5 test is only provable without one.
fn homebrew_sibling_present() -> bool {
    ["/opt/homebrew/bin", "/usr/local/bin"].iter().any(|d| Path::new(d).join("ai-env-claude").is_file())
}

#[cfg(unix)]
#[test]
fn install_without_the_sibling_exits_5() {
    if homebrew_sibling_present() {
        eprintln!("install_without_the_sibling_exits_5: skipped (an ai-env-claude is installed under a Homebrew bin dir)");
        return;
    }
    // ai-env alone in a directory: no sibling next to it, none on PATH.
    let alone = tempfile::tempdir().unwrap();
    let bin_dir = alone.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let copy = bin_dir.join("ai-env");
    std::fs::copy(ai_env(), &copy).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    let home = Home::new();
    let out = home.command(copy.to_str().unwrap(), &["install"]).env("PATH", "/nonexistent").output().expect("spawn the copied ai-env");
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{err}{}", text(&out.stdout));
    assert!(err.starts_with("ai-env: ai-env-claude not found"), "{err}");
    assert!(err.contains("cargo install --path crates/ai-env-cli --locked"), "{err}");
    assert!(!home.settings_dir().exists());
    // Control: the same copy with the real bin dir on PATH finds the sibling there (PATH only) and proceeds.
    let path = Path::new(ai_env()).parent().unwrap().to_str().unwrap();
    let out = home.command(copy.to_str().unwrap(), &["install"]).env("PATH", path).output().expect("spawn the copied ai-env");
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("note: ai-env-claude found on PATH only"), "{stdout}");
    assert!(stdout.contains(&format!("wrapper:  {}\n", sibling().display())), "{stdout}");
}

#[cfg(unix)]
#[test]
fn install_refuses_a_symlinked_settings_file() {
    let home = Home::new();
    let real = home.path().join("elsewhere").join("settings.json");
    std::fs::create_dir_all(real.parent().unwrap()).unwrap();
    std::fs::write(&real, "{}\n").unwrap();
    std::fs::create_dir_all(home.settings_dir()).unwrap();
    std::os::unix::fs::symlink(&real, home.settings_path()).unwrap();
    let out = home.run(&["install", "--write"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stderr.starts_with("ai-env: ") && stderr.contains("is a symlink"), "{stderr}");
    assert!(stdout.contains(&format!("add these keys to {} by hand:", home.settings_path().display())), "{stdout}");
    assert!(stdout.contains(&snippet(sibling().to_str().unwrap(), "default")), "{stdout}");
    assert_eq!(std::fs::read_to_string(&real).unwrap(), "{}\n", "the target is untouched");
    assert!(std::fs::symlink_metadata(home.settings_path()).unwrap().file_type().is_symlink(), "the link is untouched");
    assert!(home.backups().is_empty(), "no backup of a refused edit");
    assert!(!home.settings_dir().join(".settings.json.tmp").exists());
}

// ---- wrapper census ---------------------------------------------------------------

#[test]
fn census_without_a_file_says_no_census_yet() {
    let home = Home::new();
    let want = format!("no census yet at {}\n", home.census_path().display());
    let out = home.run(&["census"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), want);
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    // The flags change nothing about an empty census: no probes are derived from nothing.
    let out = home.run(&["census", "--json", "--last", "3", "--record-probes"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), want);
    assert!(!home.bridge_dir().exists(), "reading the census creates no state");
    assert!(!home.probes_path().exists());
}

#[test]
fn census_prints_last_n_json_and_records_probes() {
    let home = Home::new();
    let remote = census_row("2026-09-23T08:00:00Z", "remote", "session", &SESSION_TAIL, &PLAIN_ENV);
    // The newer row is a subcommand: never a probe source, so its fingerprint is
    // blanked to prove `--record-probes` reads the newest SESSION row.
    let mut local = census_row("2026-09-23T08:00:05Z", "local", "subcommand:auth", &["auth", "status", "--json"], &PLAIN_ENV);
    local["env_selected"] = serde_json::json!({});
    home.seed_census(&[remote.clone(), local.clone()]);

    let out = home.run(&["census", "--last", "1"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert_eq!(stdout, format!("2026-09-23T08:00:05Z  {:<6} {:<24} 2.1.278  {CWD}  auth status --json\n", "local", "subcommand:auth"));
    let out = home.run(&["census"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    assert_eq!(lines[0], format!("2026-09-23T08:00:00Z  {:<6} {:<24} 2.1.278  {CWD}  {}", "remote", "session", SESSION_TAIL.join(" ")));

    let out = home.run(&["census", "--json"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    let rows: Vec<serde_json::Value> = stdout.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l:?}: {e}"))).collect();
    assert_eq!(rows, vec![remote, local]);
    let out = home.run(&["census", "--json", "--last", "1"]);
    assert_eq!(text(&out.stdout).lines().count(), 1);

    let out = home.run(&["census", "--record-probes"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    assert!(stdout.contains("recorded entrypoint=claude-vscode (expected claude-vscode)\n"), "{stdout}");
    assert!(stdout.contains("recorded stock-ext-oauth=absent (expected absent)\n"), "{stdout}");
    assert!(!stdout.lines().any(|l| l.starts_with("probe ")), "nothing to diff against on the first run: {stdout}");
    let probes = home.probes();
    assert_eq!(probes.len(), 2, "{probes:?}");
    assert_eq!((probes[0].probe.as_str(), probes[0].verdict.as_str(), probes[0].expected.as_str()), ("entrypoint", "claude-vscode", "claude-vscode"));
    assert_eq!((probes[1].probe.as_str(), probes[1].verdict.as_str(), probes[1].expected.as_str()), ("stock-ext-oauth", "absent", "absent"));
    for p in &probes {
        assert_eq!(p.stage, "S1");
        assert_eq!(p.ext.as_deref(), Some("2.1.278"));
        assert_eq!(p.sdk.as_deref(), Some("0.3.278"));
        assert_eq!(p.ts.len(), 20, "{}", p.ts);
        assert!(p.ts.ends_with('Z'));
    }
    #[cfg(unix)]
    {
        assert_eq!(mode_of(home.probes_path().parent().unwrap()), 0o700, "lab dir");
        assert_eq!(mode_of(&home.probes_path()), 0o600, "probes file");
    }
    // A re-run appends and re-asserts: same verdicts, no diff line.
    let out = home.run(&["census", "--last", "0", "--record-probes"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(!stdout.lines().any(|l| l.starts_with("probe ")), "{stdout}");
    assert_eq!(stdout.lines().count(), 2, "--last 0 shows no census line, only the two recorded lines: {stdout}");
    assert_eq!(home.probes().len(), 4);
}

#[test]
fn census_record_probes_fails_after_writing_when_oauth_refresh_is_present() {
    let home = Home::new();
    let mut env: Vec<&str> = PLAIN_ENV.to_vec();
    env.push(OAUTH_REFRESH_VAR);
    env.sort_unstable();
    home.seed_census(&[census_row("2026-09-23T08:00:00Z", "remote", "session", &SESSION_TAIL, &env)]);

    let out = home.run(&["census", "--record-probes"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stderr.starts_with("ai-env: "), "{stderr}");
    assert!(stderr.contains("stock-ext-oauth=present (expected absent)"), "{stderr}");
    assert!(!stderr.contains("entrypoint"), "only the failed probe is listed: {stderr}");
    assert!(stdout.contains("recorded entrypoint=claude-vscode (expected claude-vscode)\n"), "{stdout}");
    assert!(stdout.contains("recorded stock-ext-oauth=present (expected absent)\n"), "{stdout}");
    let probes = home.probes();
    assert_eq!(probes.len(), 2, "both rows are written before the failure: {probes:?}");
    assert_eq!(probes[1].verdict, "present");
    assert_eq!(probes[1].expected, "absent");

    // A later session row without the variable — demoted to local/unconfigured,
    // still a session shape — flips the verdict back; the re-run prints the diff.
    home.seed_census(&[census_row("2026-09-23T09:00:00Z", "local", "unconfigured", &SESSION_TAIL, &PLAIN_ENV)]);
    let out = home.run(&["census", "--record-probes"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("probe stock-ext-oauth: present -> absent\n"), "{stdout}");
    assert!(!stdout.contains("probe entrypoint:"), "unchanged verdicts print no diff: {stdout}");
    let probes = home.probes();
    assert_eq!(probes.len(), 4);
    assert_eq!(probes[3].verdict, "absent");
}
