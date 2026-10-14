//! `ai-env wrapper install` and `ai-env wrapper census` — compiled only with
//! `bridge`. Every command runs with the child's `HOME` and
//! `AI_ENV_BRIDGE_DIR` under a tempdir, so Cursor's real `settings.json`
//! (`~/Library/Application Support/Cursor/User`) and the developer's
//! `~/.config/ai-env` are never touched. The sibling the command installs is
//! the freshly built `ai-env-claude` next to `CARGO_BIN_EXE_ai-env`, which
//! lives under `target/` and so exercises the build-directory warning.
//! std::process only; nothing here mutates the test process's environment.
//!
//! S8 (wave 2, W8): `install --mode` and bridge.toml's `[wrapper] mode`
//! (L1), and T8.7's offline half on planted captures: `session show
//! --settings-diff` and `wrapper settings-sync` against a copy of the
//! repository's `image/` (the capture itself runs on the remote rig, in
//! tests/remote_pump.rs; the image scan through make, in tests/infra/image.rs).
// Every wait bounded (S8 phase 4); this binary has no `common`.
#[path = "common/bounded.rs"]
mod bounded;

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
/// The S3 baseline of `image/claude/settings.json`, which the planted image
/// carries whatever the repository's holds after a T8.7 promotion.
const BASE_SETTINGS: &str = "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[]}}\n";
/// How long one `ai-env` run may take here (every wait bounded).
const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

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

    /// `ai-env wrapper <args…>` run to its end within [`LIMIT`] (killed and failed past it).
    fn run(&self, args: &[&str]) -> Output {
        bounded::run_within(self.command(ai_env(), args), None, LIMIT, "ai-env wrapper")
    }

    /// `ai-env <args…>` (no `wrapper` prefix) in the same isolation, within [`LIMIT`].
    fn ai(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(ai_env());
        cmd.args(args).env("HOME", self.path()).env("AI_ENV_BRIDGE_DIR", self.bridge_dir());
        cmd.env_remove("AI_ENV_DIR").env_remove("AI_ENV_BRIDGE_CONFIG").env_remove("AI_ENV_BRIDGE_LOCAL").env_remove("AI_ENV_BRIDGE_LAB_EXIT");
        bounded::run_within(cmd, None, LIMIT, "ai-env")
    }

    fn bridge_toml(&self) -> PathBuf {
        self.bridge_dir().join("bridge.toml")
    }

    /// Every `bridge.toml.<ts>.ai-env.bak` in the bridge dir, sorted.
    fn bridge_backups(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(self.bridge_dir()).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("bridge.toml.")).collect()).unwrap_or_default();
        v.sort();
        v
    }

    /// `quarantine/<session>/settings` of the bridge.
    fn captures_dir(&self, session: &str) -> PathBuf {
        self.bridge_dir().join("quarantine").join(session).join("settings")
    }

    /// Plant `start` and `latest` (when given) as the session's captures.
    fn plant_captures(&self, session: &str, start: &serde_json::Value, latest: Option<&serde_json::Value>) {
        let dir = self.captures_dir(session);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("start.json"), serde_json::to_string_pretty(start).unwrap()).unwrap();
        if let Some(l) = latest {
            std::fs::write(dir.join("latest.json"), serde_json::to_string_pretty(l).unwrap()).unwrap();
        }
    }

    /// A copy of the repository's `image/` (its MANIFEST's text files, and a
    /// stand-in for the cross-built shim) under `img/`.
    fn plant_image(&self) -> PathBuf {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("image");
        let dst = self.path().join("img");
        for rel in ["Dockerfile", "MANIFEST", "claude.lock", "managed-settings.json", "claude/settings.json", "claude/CLAUDE.md", "claude/claude.json"] {
            let to = dst.join(rel);
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(src.join(rel), &to).unwrap_or_else(|e| panic!("{rel}: {e}"));
        }
        // The S3 baseline settings, whatever the repository's hold after a T8.7 promotion.
        std::fs::write(dst.join("claude").join("settings.json"), BASE_SETTINGS).unwrap();
        std::fs::write(dst.join("ai-env"), "stand-in for the cross-built shim\n").unwrap();
        dst
    }
}

#[test]
fn wrapper_help_lists_install_and_census() {
    let out = Home::new().run(&["--help"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("install") && stdout.contains("census") && stdout.contains("settings-sync"), "{stdout}");
    let out = Home::new().run(&["install", "--help"]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("--write") && stdout.contains("--permission-mode <M>"), "{stdout}");
    // S8 (L1): the mode the install writes into bridge.toml.
    assert!(stdout.contains("--mode <MODE>") && stdout.contains("- passthrough: ") && stdout.contains("- remote: "), "{stdout}");
    let out = Home::new().run(&["settings-sync", "--help"]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("<SESSION>") && stdout.contains("--rule <R>") && stdout.contains("--all-safe") && stdout.contains("--write") && stdout.contains("--image-dir <DIR>"), "{stdout}");
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
    for line in ["disableLoginPrompt is left alone (set it only once S8 runs Cursor's sessions in MicroVMs", "Manual mode", "--permission-mode default", "Reload the Cursor window", "Cursor still updates the extension", "CLAUDE_CONFIG_DIR", "AI_ENV_BRIDGE_LOCAL=1"] {
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

// ---- S8 (T8.7): the settings captures, their diff, settings-sync ----------------------

const SESSION: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
/// The workspace's VM path the planted captures are of.
const VM_WS: &str = "/Users/mike/w";

/// A settings file of a capture (as the VM's helper reads it): `scope`'s
/// path in the VM, `text` (`None`: absent), its size and digest.
fn settings_file(scope: &str, text: Option<&str>) -> serde_json::Value {
    use sha2::Digest;
    let path = match scope {
        "user" => "/Users/mike/.claude/settings.json".to_string(),
        "project" => format!("{VM_WS}/.claude/settings.json"),
        _ => format!("{VM_WS}/.claude/settings.local.json"),
    };
    match text {
        Some(t) => serde_json::json!({"scope": scope, "path": path, "present": true, "size": t.len(), "sha256": hex::encode(sha2::Sha256::digest(t.as_bytes())), "text": t}),
        None => serde_json::json!({"scope": scope, "path": path, "present": false, "size": 0}),
    }
}

/// A capture of the three scopes (`GET /settings`' answer) at `at`.
fn capture(user: Option<&str>, local: Option<&str>, at: &str) -> serde_json::Value {
    serde_json::json!({"path": VM_WS, "files": [settings_file("user", user), settings_file("project", None), settings_file("local", local)], "project": {}, "at": at})
}

/// A start with no local settings, and a latest where the VM's claude
/// approved two rules (one narrow, one broad), switched its mode and set an
/// environment variable; with `token`, a third rule carrying it.
fn approved(token: Option<&str>) -> (serde_json::Value, serde_json::Value) {
    let mut allow = vec!["Bash(git status)".to_string(), "Bash(*)".to_string()];
    allow.extend(token.map(|t| format!("Bash(curl -H {t})")));
    let local = serde_json::json!({"permissions": {"allow": allow, "ask": ["WebFetch(domain:docs.rs)"], "defaultMode": "acceptEdits"}, "env": {"API_HOST": "value-not-shown"}}).to_string();
    (capture(Some("{}"), None, "2026-10-12T10:00:00Z"), capture(Some("{}"), Some(&local), "2026-10-12T10:30:00Z"))
}

/// T8.7: `session show UUID --settings-diff` prints the rules the session's
/// VM added (their union: a rule a tripwire matches never shown), then, per
/// scope, its other changes (the mode's, the environment's names with their
/// values masked), and writes the diff to `diff.json` (0600, v2) beside the
/// captures; `--json` is that document. No start capture is exit 1; a
/// non-uuid exit 2.
#[test]
fn session_show_settings_diff_prints_the_rules() {
    let home = Home::new();
    let token = format!("{}{}", "sk-ant-api03-", "Q".repeat(24));
    let (start, latest) = approved(Some(&token));
    home.plant_captures(SESSION, &start, Some(&latest));
    let out = home.ai(&["session", "show", SESSION, "--settings-diff"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    let diff = home.captures_dir(SESSION).join("diff.json");
    for want in [
        &format!("settings of session {SESSION} in its VMs ({VM_WS}): start 2026-10-12T10:00:00Z"),
        "rules added, in any VM's last capture:",
        "  + allow Bash(git status)  (local)",
        "  + allow Bash(*)  (local)",
        "  + allow (a rule the tripwire anthropic-key matches: not shown)  (local)",
        "  + ask WebFetch(domain:docs.rs)  (local)",
        "VM (not recorded), the session's last (captured 2026-10-12T10:30:00Z):",
        "  user (/Users/mike/.claude/settings.json): no other change",
        "  project (/Users/mike/w/.claude/settings.json): no other change",
        "  local (/Users/mike/w/.claude/settings.local.json):",
        "    defaultMode: unset -> acceptEdits",
        "    env added: API_HOST=***",
        &format!("written: {}", diff.display()),
    ] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    for never in [token.as_str(), "value-not-shown"] {
        assert!(!stdout.contains(never) && !stderr.contains(never), "{stdout}{stderr}");
    }
    #[cfg(unix)]
    assert_eq!((mode_of(&diff), mode_of(&home.captures_dir(SESSION))), (0o600, 0o700));
    let written: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&diff).unwrap()).unwrap();
    assert!(!written.to_string().contains(&token) && !written.to_string().contains("value-not-shown"), "{written}");
    assert_eq!((written["v"].as_u64(), written["added"].as_array().map(Vec::len), written["vms"].as_array().map(Vec::len), written["vms"][0]["scopes"].as_array().map(Vec::len)), (Some(2), Some(4), Some(1), Some(3)), "{written}");
    assert_eq!((written["added"][2]["rule"].as_str(), written["vms"][0]["current"].as_bool()), (Some("Bash(git status)"), Some(true)), "by list, then rule: {written}");
    assert_eq!(written["vms"][0]["scopes"][2]["allow"]["added"][0], "Bash(git status)", "each VM's whole diff, added rules included: {written}");
    let out = home.ai(&["session", "show", SESSION, "--settings-diff", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap(), written, "--json prints the document diff.json holds");
    // Only a start capture: nothing to compare yet.
    let other = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";
    home.plant_captures(other, &start, None);
    let out = home.ai(&["session", "show", other, "--settings-diff"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("no capture after a result yet: nothing to compare"), "{}", text(&out.stdout));
    let none = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d";
    let out = home.ai(&["session", "show", none, "--settings-diff"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with(&format!("ai-env: no settings captured for session {none}")), "{}", text(&out.stderr));
    assert_eq!(home.ai(&["session", "show", "../x", "--settings-diff"]).status.code(), Some(2));
}

/// T8.7: settings-sync's dry run lists every rule the session added with
/// what happens to it (the broad allow and the mode never promoted) and
/// prints both changes (the image's settings, the policy's allow line);
/// nothing is written.
#[test]
fn settings_sync_dry_run_prints_both_changes() {
    let home = Home::new();
    let (start, latest) = approved(None);
    home.plant_captures(SESSION, &start, Some(&latest));
    let img = home.plant_image();
    let settings = img.join("claude").join("settings.json");
    let before = std::fs::read_to_string(&settings).unwrap();
    let out = home.run(&["settings-sync", SESSION, "--all-safe", "--image-dir", img.to_str().unwrap()]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    let policy = home.bridge_dir().join("settings-policy.txt");
    for want in [
        &format!("session {SESSION}: 3 rule(s) its VM added (2026-10-12T10:00:00Z against 2026-10-12T10:30:00Z)"),
        "  allow Bash(*)  (local)  never promoted: broad-allow (the repo mode refuses it, D8)",
        "  allow Bash(git status)  (local)  promote",
        "  ask WebFetch(domain:docs.rs)  (local)  promote",
        "  defaultMode unset -> acceptEdits (local): never promoted",
        &format!("{}:", settings.display()),
        "  + permissions.allow \"Bash(git status)\"",
        "  + permissions.ask \"WebFetch(domain:docs.rs)\"",
        &format!("{}:", policy.display()),
        "  + allow Bash(git status)",
        "dry run: nothing written; re-run with --write",
    ] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), before, "a dry run writes nothing");
    assert!(!policy.exists() && !std::fs::read_dir(home.captures_dir(SESSION)).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("sync-")));
    // Without a choice: the list, and how to choose.
    let out = home.run(&["settings-sync", SESSION, "--image-dir", img.to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("  allow Bash(git status)  (local)  not chosen (--rule R or --all-safe)") && stdout.ends_with("nothing to promote\n"), "{stdout}");
}

/// T8.7: `--write` splices the chosen rules into the image's settings (its
/// one-line style kept), appends the allow line to the policy (0600, new),
/// keeps both files as they were in the session's quarantine, scans the
/// image clean and says what bakes them; a second run finds them there.
#[test]
fn settings_sync_write_updates_settings_json_and_the_policy() {
    let home = Home::new();
    let (start, latest) = approved(None);
    home.plant_captures(SESSION, &start, Some(&latest));
    let img = home.plant_image();
    let settings = img.join("claude").join("settings.json");
    let before = std::fs::read_to_string(&settings).unwrap();
    assert_eq!(before, BASE_SETTINGS, "the planted image's settings");
    let out = home.run(&["settings-sync", SESSION, "--rule", "Bash(git status)", "--write", "--image-dir", img.to_str().unwrap()]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[\"Bash(git status)\"]}}\n");
    let policy = home.bridge_dir().join("settings-policy.txt");
    assert_eq!(std::fs::read_to_string(&policy).unwrap(), "allow Bash(git status)\n");
    #[cfg(unix)]
    assert_eq!((mode_of(&policy), mode_of(&settings)), (0o600, 0o644));
    let backups: Vec<PathBuf> = std::fs::read_dir(home.captures_dir(SESSION)).unwrap().flatten().map(|e| e.path()).filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("sync-")).collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(std::fs::read_to_string(backups[0].join("settings.json")).unwrap(), before, "the image's settings as they were");
    assert!(!backups[0].join("settings-policy.txt").exists(), "no policy before: nothing to keep");
    for want in [
        &format!("backup: {}", backups[0].display()),
        &format!("wrote: {}", settings.display()),
        &format!("wrote: {}", policy.display()),
        "next: make test-docker deploy (test-docker builds the zip and stamps it), then ai-env egress check --if-needed (a new image version needs its check before a credential goes in): a VM of the new image starts with these rules",
    ] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    assert!(stdout.lines().any(|l| l.starts_with("scan: clean (") && l.ends_with(" files)")), "{stdout}");
    let audit = std::fs::read_to_string(home.bridge_dir().join("audit.jsonl")).unwrap();
    let rows: Vec<serde_json::Value> = audit.lines().map(|l| serde_json::from_str(l).unwrap()).filter(|r: &serde_json::Value| r["event"] == "settings_sync").collect();
    assert_eq!(rows.len(), 1, "{audit}");
    assert_eq!((rows[0]["session_id"].as_str(), rows[0]["detail"]["outcome"].as_str(), rows[0]["detail"]["rules"].as_str()), (Some(SESSION), Some("written"), Some("1")));
    // Again: already there, nothing written.
    let out = home.run(&["settings-sync", SESSION, "--all-safe", "--write", "--image-dir", img.to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("  allow Bash(git status)  (local)  already in the image"), "{stdout}");
    // The ask rule is promoted now; the policy gains nothing (ask rules need no policy line).
    assert!(stdout.contains("  (no change: every allow is in it already)") && stdout.contains("  + permissions.ask \"WebFetch(domain:docs.rs)\""), "{stdout}");
    assert_eq!(std::fs::read_to_string(&policy).unwrap(), "allow Bash(git status)\n");
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[\"Bash(git status)\"],\"ask\":[\"WebFetch(domain:docs.rs)\"]}}\n");
}

/// T8.7: a widening rule named with `--rule` refuses the whole sync (exit
/// 9, nothing written), and a rule carrying a token is never promoted and
/// never printed; a rule the session did not add is exit 1; an image that
/// does not scan clean before the sync refuses it (exit 9).
#[test]
fn settings_sync_refuses_a_widening_rule() {
    let home = Home::new();
    let token = format!("{}{}", "AKIA", "Q".repeat(16));
    let (start, latest) = approved(Some(&token));
    home.plant_captures(SESSION, &start, Some(&latest));
    let img = home.plant_image();
    let settings = img.join("claude").join("settings.json");
    let before = std::fs::read_to_string(&settings).unwrap();
    let policy = home.bridge_dir().join("settings-policy.txt");
    let i = img.to_str().unwrap();
    for (args, code, says) in [
        (vec!["settings-sync", SESSION, "--rule", "Bash(*)", "--write", "--image-dir", i], 9, "never promoted, so nothing was written: allow Bash(*)"),
        (vec!["settings-sync", SESSION, "--rule", "Bash(git status)", "--rule", "Bash(*)", "--write", "--all-safe", "--image-dir", i], 9, "never promoted, so nothing was written: allow Bash(*)"),
        (vec!["settings-sync", SESSION, "--rule", "Read", "--write", "--image-dir", i], 1, "Read is not a rule session"),
        (vec!["settings-sync", "../x", "--all-safe"], 2, "not a session id"),
    ] {
        let out = home.run(&args);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(code), "{args:?}: {stdout}{stderr}");
        assert!(stderr.contains(says), "{args:?}: {stderr}");
        assert!(!stdout.contains(&token) && !stderr.contains(&token), "{stdout}{stderr}");
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), before, "{args:?}: nothing written");
        assert!(!policy.exists(), "{args:?}");
    }
    let out = home.run(&["settings-sync", SESSION, "--all-safe", "--image-dir", i]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("never promoted: the tripwire aws-access-key-id matches it") && !stdout.contains(&token), "{stdout}");
    // An image that already fails the scan is never written into.
    std::fs::write(img.join("claude").join("CLAUDE.md"), format!("keep {token} out\n")).unwrap();
    let out = home.run(&["settings-sync", SESSION, "--all-safe", "--write", "--image-dir", i]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(9), "{stderr}");
    assert!(stderr.contains("does not scan clean before the sync") && stderr.contains("claude/CLAUDE.md:1: aws-access-key-id") && !stderr.contains(&token), "{stderr}");
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), before);
    assert!(!policy.exists());
}

/// T8.7: what the VM writes reaches the operator's terminal neutralised. A
/// `defaultMode` carrying a key and terminal controls, and the helper's
/// time and a file path carrying them, are printed scrubbed with every
/// control character as `?`, one line each, by `session show
/// --settings-diff` and `settings-sync` alike: no key, no escape byte, no
/// forged line.
#[test]
fn the_vms_words_reach_the_terminal_scrubbed_one_line_each() {
    let home = Home::new();
    let key = format!("{}{}", "AKIA", "Q".repeat(16));
    let mode = format!("{key}\u{1b}[2K\n  allow Bash(*)  (local)  already in the image");
    let local = serde_json::json!({"permissions": {"allow": ["Bash(git status)"], "defaultMode": mode}}).to_string();
    let start = capture(Some("{}"), None, "2026-10-12T10:00:00Z");
    let mut latest = capture(Some("{}"), Some(&local), "2026-10-12T10:30:00Z\n\u{1b}[1Aai-env: forged line from the VM");
    latest["files"][2]["path"] = serde_json::json!(format!("{VM_WS}/.claude/\u{1b}[2K\nsettings.local.json"));
    home.plant_captures(SESSION, &start, Some(&latest));
    let img = home.plant_image();
    let show = home.ai(&["session", "show", SESSION, "--settings-diff"]);
    let sync = home.run(&["settings-sync", SESSION, "--image-dir", img.to_str().unwrap()]);
    // The diff: a head, the rules' two, the VM's, a line per unchanged scope and the project's, the local scope's two, `written:`.
    for (what, out, lines, at) in [("session show", &show, 10, 3), ("settings-sync", &sync, 4, 0)] {
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{what}: {stdout}{stderr}");
        assert!(!stdout.contains('\u{1b}') && !stdout.contains(&key) && !stderr.contains(&key), "{what}: {stdout:?}");
        assert_eq!(stdout.lines().count(), lines, "{what}, one line per change: {stdout}");
        assert!(stdout.lines().nth(at).is_some_and(|l| l.contains("2026-10-12T10:30:00Z??[1Aai-env: forged line from the VM")), "{what}: {stdout}");
    }
    let shown = text(&show.stdout);
    for want in ["  local (/Users/mike/w/.claude/?[2K?settings.local.json):", "    defaultMode: unset -> AKIA[redacted:len=20]?[2K?  allow Bash(*)  (local)  already in the image"] {
        assert!(shown.lines().any(|l| l == want), "{want}: {shown}");
    }
    let synced = text(&sync.stdout);
    assert!(synced.lines().any(|l| l == "  defaultMode unset -> AKIA[redacted:len=20]?[2K?  allow Bash(*)  (local)  already in the image (local): never promoted"), "{synced}");
}

/// T8.7 with T8.5 (review W8-R3): a chat reopened on a second VM, the first
/// gone. The session's captures as the wrapper leaves them: the start and
/// the first VM's last capture (`latest-<VM id>.json`, the rule it approved
/// in it), and the second VM's (`latest.json`, seeded from the Mac: no
/// rule). The rule stays in the diff (the VM that added it named) and among
/// settings-sync's candidates, which promotes it. Promoted, it stays there
/// (listed as already in the image) until `session forget` removes every
/// capture.
#[test]
fn a_rule_approved_on_a_vm_the_session_left_is_shown_and_synced() {
    let home = Home::new();
    let (first, second) = ("microvm-0a1", "microvm-0b2");
    let local = serde_json::json!({"permissions": {"allow": ["Bash(git status)"]}}).to_string();
    let kept = |vm: &str, mut capture: serde_json::Value| {
        capture["vm"] = serde_json::json!(vm);
        capture
    };
    let dir = home.captures_dir(SESSION);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, doc) in [
        ("start.json".to_string(), kept(first, capture(Some("{}"), None, "2026-10-12T10:00:00Z"))),
        (format!("latest-{first}.json"), kept(first, capture(Some("{}"), Some(&local), "2026-10-12T10:30:00Z"))),
        ("latest.json".to_string(), kept(second, capture(Some("{}"), None, "2026-10-12T11:30:00Z"))),
    ] {
        std::fs::write(dir.join(name), serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    }
    let out = home.ai(&["session", "show", SESSION, "--settings-diff"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    for want in [
        &format!("settings of session {SESSION} in its VMs ({VM_WS}): start 2026-10-12T10:00:00Z in {first}"),
        "rules added, in any VM's last capture:",
        &format!("  + allow Bash(git status)  (local; {first})"),
        &format!("VM {second}, the session's last (captured 2026-10-12T11:30:00Z):"),
        &format!("VM {first}, left (captured 2026-10-12T10:30:00Z):"),
    ] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    let written: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("diff.json")).unwrap()).unwrap();
    assert_eq!((written["start_vm"].as_str(), written["added"][0]["vms"].clone(), written["vms"][0]["vm"].as_str(), written["vms"][1]["vm"].as_str()), (Some(first), serde_json::json!([first]), Some(second), Some(first)), "{written}");
    let img = home.plant_image();
    let settings = img.join("claude").join("settings.json");
    let out = home.run(&["settings-sync", SESSION, "--rule", "Bash(git status)", "--write", "--image-dir", img.to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    for want in [&format!("session {SESSION}: 1 rule(s) its VMs added (2026-10-12T10:00:00Z against {second} 2026-10-12T11:30:00Z, {first} 2026-10-12T10:30:00Z)"), &format!("  allow Bash(git status)  (local; {first})  promote")] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{\"permissions\":{\"defaultMode\":\"default\",\"allow\":[\"Bash(git status)\"]}}\n");
    // The promotion changes no capture: the rule is still in the diff, and in the image now.
    let out = home.ai(&["session", "show", SESSION, "--settings-diff"]);
    let stdout = text(&out.stdout);
    assert!(stdout.lines().any(|l| l == format!("  + allow Bash(git status)  (local; {first})")), "{stdout}");
    let out = home.run(&["settings-sync", SESSION, "--image-dir", img.to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    for want in [format!("  allow Bash(git status)  (local; {first})  already in the image"), "nothing to promote".to_string()] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    let out = home.ai(&["session", "forget", SESSION]);
    assert_eq!((out.status.code(), text(&out.stdout)), (Some(0), format!("forgot {SESSION} (quarantine)\n")), "{}", text(&out.stderr));
    assert!(!home.bridge_dir().join("quarantine").join(SESSION).exists(), "every capture went, the left VM's too");
}

// ---- S8 (L1): install --mode -----------------------------------------------------------

const BRIDGE_TOML: &str = "# the operator's bridge\n[aws]\nregion = \"eu-central-1\" # pinned\n\n[wrapper]\ninitial_permission_mode = \"plan\"\n\n[workspaces]\nroots = [\"/Users/mike/w\"]\n";

/// L1: `install --mode remote` without `--write` reports the bridge.toml
/// change beside the install's, writes neither file and says so.
#[test]
fn install_mode_dry_run_writes_neither_file_and_says_so() {
    let home = Home::new();
    std::fs::create_dir_all(home.bridge_dir()).unwrap();
    std::fs::write(home.bridge_toml(), BRIDGE_TOML).unwrap();
    let out = home.run(&["install", "--mode", "remote"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    for want in [&format!("bridge.toml: {}", home.bridge_toml().display()), "  [wrapper] mode: unset (passthrough) -> \"remote\"", "dry run: bridge.toml not written; re-run with --write", "dry run: nothing written; re-run with --write"] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    assert!(stdout.contains("Remote mode: a Cursor chat (stream-json) under [workspaces].roots runs in the workspace's MicroVM") && !stdout.contains("roots is empty"), "{stdout}");
    assert_eq!(std::fs::read_to_string(home.bridge_toml()).unwrap(), BRIDGE_TOML);
    assert!(home.bridge_backups().is_empty() && !home.settings_path().exists());
}

/// L1: `--write --mode remote` backs bridge.toml up, then sets `[wrapper]
/// mode` in place (comments, order and every other key kept, the file's
/// mode too) beside Cursor's two keys; `--mode passthrough` switches back;
/// the same mode again writes nothing more.
#[test]
fn install_mode_write_backs_up_bridge_toml_and_switches_back() {
    let home = Home::new();
    std::fs::create_dir_all(home.bridge_dir()).unwrap();
    std::fs::write(home.bridge_toml(), BRIDGE_TOML).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.bridge_toml(), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out = home.run(&["install", "--write", "--mode", "remote"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    let remote = BRIDGE_TOML.replace("initial_permission_mode = \"plan\"\n", "initial_permission_mode = \"plan\"\nmode = \"remote\"\n");
    assert_eq!(std::fs::read_to_string(home.bridge_toml()).unwrap(), remote);
    let backups = home.bridge_backups();
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), BRIDGE_TOML, "the backup is the original");
    assert!(stdout.contains(&format!("backup: {}\n", backups[0].display())) && stdout.contains(&format!("wrote: {}\n", home.bridge_toml().display())), "{stdout}");
    #[cfg(unix)]
    assert_eq!(mode_of(&home.bridge_toml()), 0o600);
    assert_eq!(parse_settings(&home.settings_text()).unwrap()[WRAPPER_SETTING], sibling().to_str().unwrap(), "Cursor's keys are written too");
    let out = home.run(&["install", "--write", "--mode", "passthrough"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("  [wrapper] mode: \"remote\" -> \"passthrough\"") && stdout.contains("Passthrough mode: every Cursor chat runs on this Mac"), "{stdout}");
    assert_eq!(std::fs::read_to_string(home.bridge_toml()).unwrap(), remote.replace("mode = \"remote\"", "mode = \"passthrough\""));
    let out = home.run(&["install", "--write", "--mode", "passthrough"]);
    let stdout = text(&out.stdout);
    assert!(stdout.contains("  [wrapper] mode: \"passthrough\" (unchanged)") && stdout.contains("bridge.toml: nothing to write"), "{stdout}");
    assert_eq!(home.bridge_backups().len(), 2, "no backup of an unchanged file");
}

/// L1: remote mode needs a bridge.toml (exit 1 naming the fix, nothing
/// written, Cursor's settings included); passthrough without one is the
/// default already. A bridge.toml the splice cannot edit, or a symlink,
/// refuses before anything is written.
#[test]
fn install_mode_refuses_what_it_cannot_write_before_writing_anything() {
    let home = Home::new();
    let out = home.run(&["install", "--write", "--mode", "remote"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("no bridge.toml at") && stderr.contains("make infra-status WRITE=1"), "{stderr}");
    assert!(!home.settings_path().exists() && !home.bridge_toml().exists());
    let out = home.run(&["install", "--mode", "passthrough"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("absent: [wrapper] mode is passthrough already (the default)"), "{stdout}");
    assert!(!home.bridge_toml().exists());
    std::fs::create_dir_all(home.bridge_dir()).unwrap();
    for bad in ["[[wrapper]]\nmode = \"remote\"\n", "wrapper = { mode = \"remote\" }\n", "[wrapper\n"] {
        std::fs::write(home.bridge_toml(), bad).unwrap();
        let out = home.run(&["install", "--write", "--mode", "remote"]);
        assert_eq!(out.status.code(), Some(1), "{bad:?}: {}", text(&out.stderr));
        assert!(text(&out.stderr).contains("set [wrapper] mode = \"remote\" by hand"), "{bad:?}: {}", text(&out.stderr));
        assert_eq!(std::fs::read_to_string(home.bridge_toml()).unwrap(), bad);
        assert!(!home.settings_path().exists(), "{bad:?}: Cursor's settings untouched");
    }
    #[cfg(unix)]
    {
        let real = home.path().join("elsewhere.toml");
        std::fs::write(&real, BRIDGE_TOML).unwrap();
        std::fs::remove_file(home.bridge_toml()).unwrap();
        std::os::unix::fs::symlink(&real, home.bridge_toml()).unwrap();
        let out = home.run(&["install", "--write", "--mode", "remote"]);
        assert_eq!(out.status.code(), Some(1));
        assert!(text(&out.stderr).contains("is a symlink"), "{}", text(&out.stderr));
        assert_eq!(std::fs::read_to_string(&real).unwrap(), BRIDGE_TOML);
    }
    assert!(home.bridge_backups().is_empty());
}
