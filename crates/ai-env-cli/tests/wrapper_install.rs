//! `ai-env wrapper install`, `uninstall` and `census` — compiled only with
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
        cmd.env_remove("AI_ENV_DIR").env_remove("AI_ENV_BRIDGE_CONFIG").env_remove("AI_ENV_BRIDGE_LOCAL").env_remove("AI_ENV_BRIDGE_LAB_EXIT").env_remove("CLAUDE_CONFIG_DIR");
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
        cmd.env_remove("AI_ENV_DIR").env_remove("AI_ENV_BRIDGE_CONFIG").env_remove("AI_ENV_BRIDGE_LOCAL").env_remove("AI_ENV_BRIDGE_LAB_EXIT").env_remove("CLAUDE_CONFIG_DIR");
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
    assert!(stdout.lines().any(|l| l.trim_start().starts_with("uninstall ")), "{stdout}");
    // A subcommand line: the about text's "show its status" would satisfy a bare contains.
    assert!(stdout.lines().any(|l| l.trim_start().starts_with("status ")), "{stdout}");
    let out = Home::new().run(&["status", "--help"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("--json") && !stdout.contains("--write"), "{stdout}");
    // uninstall leaves bridge.toml and initialPermissionMode alone: --write is its one flag.
    let out = Home::new().run(&["uninstall", "--help"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("--write") && !stdout.contains("--mode") && !stdout.contains("--permission-mode"), "{stdout}");
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
    for line in [
        "disableLoginPrompt is left alone (set it only once S8 runs Cursor's sessions in MicroVMs",
        "Manual mode",
        "--permission-mode default",
        "Cursor reads this setting each time it starts a process: chats it starts from now on use it; a chat already running keeps its process until it ends",
        "Cursor still updates the extension",
        "CLAUDE_CONFIG_DIR",
        "AI_ENV_BRIDGE_LOCAL=1",
    ] {
        assert!(stdout.contains(line), "{line}: {stdout}");
    }
    // G1: no advice to reload (a reload restarts the open chats through the wrapper).
    assert!(!stdout.contains("Reload the Cursor window"), "{stdout}");
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

// ---- wrapper uninstall ------------------------------------------------------------

/// The line `uninstall` prints when it refuses to edit the file.
fn remove_by_hand(home: &Home) -> String {
    format!("remove {} from {} by hand\n", json_str(WRAPPER_SETTING), home.settings_path().display())
}

/// `uninstall` without `--write`: no settings file is nothing to remove and
/// creates nothing (`--write` neither); a set key prints `-> unset` with the
/// mode left alone, what Cursor would do after `--write` (never as done: the
/// key is still set, so a reload still restarts the open chats through the
/// wrapper) and the undo, and the file stays byte for byte, no backup.
#[test]
fn uninstall_dry_run_writes_nothing() {
    let home = Home::new();
    for args in [&["uninstall"][..], &["uninstall", "--write"]] {
        let out = home.run(args);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{args:?}: {stdout}{stderr}");
        assert_eq!(stdout, format!("settings: {} (absent)\n  {WRAPPER_SETTING}: unset (nothing to remove)\n", home.settings_path().display()), "{args:?}");
        assert!(stderr.is_empty(), "{args:?}: {stderr}");
    }
    assert!(!home.settings_dir().exists() && !home.bridge_dir().exists(), "nothing created");

    let w = sibling();
    let w = w.to_str().unwrap();
    let src = format!("{{\n  \"editor.tabSize\": 2,\n  {}: {},\n  {}: \"default\"\n}}\n", json_str(WRAPPER_SETTING), json_str(w), json_str(PERMISSION_SETTING));
    home.write_settings(&src);
    let out = home.run(&["uninstall"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert!(stderr.is_empty(), "no sibling looked for, no warning: {stderr}");
    let settings = format!("settings: {}", home.settings_path().display());
    let unset = format!("  {WRAPPER_SETTING}: {w:?} -> unset");
    let mode = format!("  {PERMISSION_SETTING}: \"default\" (left alone)");
    let spawn = format!("With --write, Cursor reads {WRAPPER_SETTING} at every spawn: what it starts from then on (a new chat, a reopened or restored one, its config probe) runs its bundled claude on this Mac: no ai-env-claude, no census, no MicroVM, no Touch ID.");
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        [
            settings.as_str(),
            unset.as_str(),
            mode.as_str(),
            "dry run: nothing written; re-run with --write",
            "",
            spawn.as_str(),
            "A chat already running keeps the process it started with; after the write, a window reload restarts the restored chats without the wrapper.",
            "bridge.toml is left alone ([wrapper] mode unset: passthrough): ai-env wrapper install --write brings the wrapper back, in that mode, for what Cursor starts after it.",
            "undo: ai-env wrapper install --write",
        ]
    );
    assert!(!stdout.contains("from now on"), "nothing changed yet: {stdout}");
    assert_eq!(home.settings_text(), src, "a dry run writes nothing");
    assert!(home.backups().is_empty());
    assert!(!home.bridge_dir().exists());
}

/// `uninstall --write` after `install --write --permission-mode manual`:
/// the backup is the installed text byte for byte, with the file's mode;
/// the file is that text without the wrapper's line (the mode, comments and
/// trailing comma kept); no temp file is left, no bridge state touched, and
/// the undo carries the mode. Again: nothing to remove, no backup.
#[test]
fn uninstall_write_backs_up_and_removes_only_the_wrapper_key() {
    let home = Home::new();
    let src = "{\n  // Cursor settings\n  \"claudeCode.preferredLocation\": \"panel\", /* keep */\n  \"editor.tabSize\": 2, // two\n  \"list\": [1, 2, ],\n}\n";
    home.write_settings(src);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.settings_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let out = home.run(&["install", "--write", "--permission-mode", "manual"]);
    assert_eq!(out.status.code(), Some(0), "{}{}", text(&out.stdout), text(&out.stderr));
    let installed = home.settings_text();
    let earlier = home.backups();

    let out = home.run(&["uninstall", "--write"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let backups: Vec<PathBuf> = home.backups().into_iter().filter(|b| !earlier.contains(b)).collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), installed, "the backup is the installed text, byte for byte");
    let want = format!("{}  {}: \"manual\",\n}}\n", &src[..src.len() - 2], json_str(PERMISSION_SETTING));
    assert_eq!(home.settings_text(), want, "only the wrapper's line goes");
    for want in [
        format!("  {PERMISSION_SETTING}: \"manual\" (left alone)"),
        format!("backup: {}", backups[0].display()),
        format!("wrote: {}", home.settings_path().display()),
        // Written: what Cursor starts from now on, in the present tense.
        format!("Cursor reads {WRAPPER_SETTING} at every spawn: what it starts from now on (a new chat, a reopened or restored one, its config probe) runs its bundled claude on this Mac: no ai-env-claude, no census, no MicroVM, no Touch ID."),
        "A chat already running keeps the process it started with; a window reload restarts the restored chats without the wrapper.".to_string(),
        "undo: ai-env wrapper install --write --permission-mode manual".to_string(),
    ] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    assert!(!stdout.contains("note:") && !stdout.contains("dry run") && !stdout.contains("With --write") && !stdout.contains("after the write"), "{stdout}");
    #[cfg(unix)]
    {
        assert_eq!(mode_of(&home.settings_path()), 0o644, "the file keeps its mode");
        assert_eq!(mode_of(&backups[0]), 0o644, "the backup carries it");
        assert!(!home.settings_dir().join(".settings.json.tmp").exists(), "no temp file left behind");
    }
    assert!(!home.bridge_dir().exists(), "uninstall touches no bridge state");

    let out = home.run(&["uninstall", "--write"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert_eq!(stdout, format!("settings: {}\n  {WRAPPER_SETTING}: unset (nothing to remove)\n", home.settings_path().display()));
    assert_eq!(home.settings_text(), want);
    assert_eq!(home.backups().len(), earlier.len() + 1, "no backup when there is nothing to remove");
}

/// U4: install, uninstall, install gives back the installed bytes (the
/// wrapper's key back just before the mode, not at the end), three
/// backups in all.
#[test]
fn install_uninstall_install_gives_back_the_same_bytes() {
    for src in ["{\n    \"editor.tabSize\": 2,\n    \"zebra\": \"last\"\n}\n", "{\n  // Cursor settings\n  \"list\": [1, 2, ],\n}\n"] {
        let home = Home::new();
        home.write_settings(src);
        let mut texts = Vec::new();
        for args in [&["install", "--write"][..], &["uninstall", "--write"], &["install", "--write"]] {
            let out = home.run(args);
            assert_eq!(out.status.code(), Some(0), "{args:?}: {}{}", text(&out.stdout), text(&out.stderr));
            texts.push(home.settings_text());
        }
        assert_eq!(texts[2], texts[0], "{src:?}");
        let removed = parse_settings(&texts[1]).unwrap();
        assert!(removed.get(WRAPPER_SETTING).is_none() && removed[PERMISSION_SETTING] == "default", "{}", texts[1]);
        assert_eq!(home.backups().len(), 3, "{:?}", home.backups());
    }
}

/// `install --write` over the two values it writes changes nothing: no
/// backup and no write, so settings.json keeps its bytes and its mtime
/// (`ai-env wrapper status` weighs the census against the file's last
/// change: a rewrite would leave it claiming nothing until Cursor's next
/// spawn), and it says so, as the dry run does. `--mode` then writes
/// bridge.toml alone when only its mode changes.
#[test]
fn install_over_the_same_values_writes_nothing() {
    let home = Home::new();
    home.write_settings("{\n  \"editor.tabSize\": 2\n}\n");
    let out = home.run(&["install", "--write"]);
    assert_eq!(out.status.code(), Some(0), "{}{}", text(&out.stdout), text(&out.stderr));
    let installed = home.settings_text();
    assert_eq!(home.backups().len(), 1);
    // Dated back, as for a wrapper set long ago.
    let long_ago = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_788_000_000);
    std::fs::File::options().write(true).open(home.settings_path()).unwrap().set_modified(long_ago).unwrap();
    let mtime = || std::fs::metadata(home.settings_path()).unwrap().modified().unwrap();
    let w = sibling();
    let w = w.to_str().unwrap();
    for args in [&["install", "--write"][..], &["install"]] {
        let out = home.run(args);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {stdout}{}", text(&out.stderr));
        for want in [format!("  {WRAPPER_SETTING}: {w:?} (unchanged)"), format!("  {PERMISSION_SETTING}: \"default\" (unchanged)"), "settings: nothing to write".to_string()] {
            assert!(stdout.lines().any(|l| l == want), "{args:?} {want}: {stdout}");
        }
        assert!(!stdout.contains("backup:") && !stdout.contains("wrote:") && !stdout.contains("dry run"), "{args:?}: {stdout}");
        assert_eq!((home.settings_text(), mtime(), home.backups().len()), (installed.clone(), long_ago, 1), "{args:?}: neither written nor backed up");
    }
    // --mode over the same two keys: bridge.toml is written, settings.json is not.
    std::fs::create_dir_all(home.bridge_dir()).unwrap();
    std::fs::write(home.bridge_toml(), "[workspaces]\nroots = [\"/w\"]\n").unwrap();
    let out = home.run(&["install", "--write", "--mode", "remote"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.lines().any(|l| l == "settings: nothing to write") && stdout.lines().any(|l| l == format!("wrote: {}", home.bridge_toml().display())), "{stdout}");
    assert_eq!(std::fs::read_to_string(home.bridge_toml()).unwrap(), "[workspaces]\nroots = [\"/w\"]\n\n[wrapper]\nmode = \"remote\"\n");
    assert_eq!((home.settings_text(), mtime(), home.backups().len()), (installed, long_ago, 1), "settings.json untouched");
}

/// A symlinked or unparseable settings file is exit 1, naming the key to
/// remove by hand: nothing written, no backup.
#[cfg(unix)]
#[test]
fn uninstall_refuses_a_symlink_or_an_unparseable_file() {
    let home = Home::new();
    let set = format!("{{{}: \"/x/ai-env-claude\"}}\n", json_str(WRAPPER_SETTING));
    let real = home.path().join("elsewhere").join("settings.json");
    std::fs::create_dir_all(real.parent().unwrap()).unwrap();
    std::fs::write(&real, &set).unwrap();
    std::fs::create_dir_all(home.settings_dir()).unwrap();
    std::os::unix::fs::symlink(&real, home.settings_path()).unwrap();
    let out = home.run(&["uninstall", "--write"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stderr.starts_with("ai-env: ") && stderr.contains("is a symlink"), "{stderr}");
    assert_eq!(stdout, remove_by_hand(&home));
    assert_eq!(std::fs::read_to_string(&real).unwrap(), set, "the target is untouched");
    assert!(std::fs::symlink_metadata(home.settings_path()).unwrap().file_type().is_symlink(), "the link is untouched");

    std::fs::remove_file(home.settings_path()).unwrap();
    let broken = format!("{{\n  {}: \"/x/ai-env-claude\"\n  \"a\": 1\n}}\n", json_str(WRAPPER_SETTING));
    home.write_settings(&broken);
    for args in [&["uninstall"][..], &["uninstall", "--write"]] {
        let out = home.run(args);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stdout}{stderr}");
        assert!(stderr.starts_with(&format!("ai-env: cannot parse {}", home.settings_path().display())), "{stderr}");
        assert_eq!(stdout, remove_by_hand(&home));
        assert_eq!(home.settings_text(), broken);
    }
    assert!(home.backups().is_empty(), "no backup of a refused edit");
    assert!(!home.settings_dir().join(".settings.json.tmp").exists());
}

/// `uninstall` needs no `ai-env-claude` (it still works once `cargo clean`
/// broke Cursor's wrapper): ai-env alone in a directory, nothing on PATH.
#[cfg(unix)]
#[test]
fn uninstall_needs_no_ai_env_claude() {
    let alone = tempfile::tempdir().unwrap();
    let copy = alone.path().join("ai-env");
    std::fs::copy(ai_env(), &copy).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    let home = Home::new();
    let src = format!("{{\n  \"a\": 1,\n  {}: {},\n  {}: \"default\"\n}}\n", json_str(WRAPPER_SETTING), json_str(sibling().to_str().unwrap()), json_str(PERMISSION_SETTING));
    home.write_settings(&src);
    let mut cmd = home.command(copy.to_str().unwrap(), &["uninstall", "--write"]);
    cmd.env("PATH", "/nonexistent");
    let out = bounded::run_within(cmd, None, LIMIT, "the copied ai-env");
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert_eq!(home.settings_text(), format!("{{\n  \"a\": 1,\n  {}: \"default\"\n}}\n", json_str(PERMISSION_SETTING)));
    assert_eq!(home.backups().len(), 1);
}

/// A wrapper that is no `ai-env-claude` is removed all the same, with a
/// note (the backup keeps it), and so is every top-level copy of the key,
/// with a note; a mode the undo cannot carry is named.
#[test]
fn uninstall_notes_a_foreign_wrapper_and_duplicates() {
    let home = Home::new();
    let foreign = format!("{{\n  {}: \"/opt/other/claude-wrapper\"\n}}\n", json_str(WRAPPER_SETTING));
    home.write_settings(&foreign);
    let out = home.run(&["uninstall", "--write"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    for want in [
        format!("  {WRAPPER_SETTING}: \"/opt/other/claude-wrapper\" -> unset"),
        format!("  {PERMISSION_SETTING}: unset (left alone)"),
        "note: \"/opt/other/claude-wrapper\" is not an ai-env-claude; removed all the same (the backup keeps it)".to_string(),
        "undo: ai-env wrapper install --write".to_string(),
        format!("note: install sets {PERMISSION_SETTING} to \"default\" (now unset)"),
    ] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    assert!(!stdout.contains("times"), "{stdout}");
    assert_eq!(home.settings_text(), "{\n}\n");
    assert_eq!(std::fs::read_to_string(&home.backups()[0]).unwrap(), foreign, "the backup keeps it");

    let home = Home::new();
    let twice = format!("{{\n  {w}: \"/old/ai-env-claude\",\n  \"a\": 1,\n  {w}: \"/new/ai-env-claude\"\n}}\n", w = json_str(WRAPPER_SETTING));
    home.write_settings(&twice);
    let out = home.run(&["uninstall", "--write"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    for want in [format!("  {WRAPPER_SETTING}: \"/new/ai-env-claude\" -> unset"), format!("note: {WRAPPER_SETTING} was set 2 times; every one is removed")] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    assert!(!stdout.contains("is not an ai-env-claude"), "{stdout}");
    assert_eq!(home.settings_text(), "{\n  \"a\": 1\n}\n");
}

/// The bridge.toml line names the mode the wrapper comes back in, as
/// ai-env-claude reads the file: a value it cannot read, or one that names
/// no mode, is remote, and then, as in a remote file that does not load, a
/// chat under the roots fails closed (a note says so: with a root, or roots
/// it cannot read; with none no chat goes remote, and no note); so it does
/// when a remote file with a root fails another check of the session's
/// start (no `[aws]`, a name the session's environment may not hold), the
/// note naming that exit code. The undo carries `--permission-mode` when
/// install would pick another mode than today's
/// (`[wrapper].initial_permission_mode`), or would refuse bridge.toml's: run
/// dry, install takes it and writes today's mode whenever it accepts that.
/// bridge.toml is never written.
#[test]
fn uninstall_reads_bridge_toml_as_the_wrapper_and_install_do() {
    let left_alone = |mode: &str| format!("bridge.toml is left alone ({mode}): ai-env wrapper install --write brings the wrapper back, in that mode, for what Cursor starts after it.");
    let closed_with = |code: i32| format!("note: with the wrapper back, every Cursor chat under bridge.toml's roots (every chat, when they cannot be read) exits {code} naming the error until bridge.toml is fixed (ai-env wrapper status shows it)");
    let closed = closed_with(1);
    let undo = "undo: ai-env wrapper install --write".to_string();
    let with_flag = |m: &str| format!("{undo} --permission-mode {m}");
    let refused = |was: &str| format!("note: install refuses bridge.toml's [wrapper].initial_permission_mode = \"bogus\": the undo sets {PERMISSION_SETTING} to \"default\" (now {was})");
    let (remote, unreadable) = (left_alone("[wrapper] mode = \"remote\""), left_alone("[wrapper] mode unreadable: remote"));
    let plan = "[wrapper]\nmode = \"remote\"\ninitial_permission_mode = \"plan\"\n";
    let bogus = "[wrapper]\nmode = \"remote\"\ninitial_permission_mode = \"bogus\"\n";
    // A root, and the [aws] a remote session's run plan needs (the documentation account's made-up ARNs).
    let rooted = "[wrapper]\nmode = \"remote\"\n[workspaces]\nroots = [\"/w\"]\n";
    let aws = "[aws]\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env\"\negress_connector_arn = \"arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress\"\n";
    let (planned, refusing) = (format!("{rooted}{aws}"), format!("[wrapper]\nmode = \"remote\"\nenv_extra = [\"NODE_OPTIONS\"]\n[workspaces]\nroots = [\"/w\"]\n{aws}"));
    // (bridge.toml, today's mode, the report from the bridge.toml line on, the mode the undo writes)
    let cases = [
        // The plan's form; the undo weighs today's mode against bridge.toml's, not "default".
        (plan, Some("plan"), vec![remote.clone(), undo.clone()], "plan"),
        (plan, Some("default"), vec![remote.clone(), with_flag("default")], "default"),
        (plan, None, vec![remote.clone(), undo.clone(), format!("note: install sets {PERMISSION_SETTING} to \"plan\" (now unset)")], "plan"),
        ("[wrapper]\nmode = \"passthrough\"\n", Some("default"), vec![left_alone("[wrapper] mode = \"passthrough\""), undo.clone()], "default"),
        // Not TOML (its roots unreadable: every chat counts as under them), no string, no mode: remote, as the
        // wrapper takes them; with a root, a chat under it fails closed.
        ("[wrapper]\nmode = \"remote\"\n[workspaces\nroots = [\"/w\"]\n", Some("default"), vec![unreadable.clone(), closed.clone(), undo.clone()], "default"),
        ("[wrapper]\nmode = 1\n[workspaces]\nroots = [\"/w\"]\n", Some("default"), vec![unreadable.clone(), closed.clone(), undo.clone()], "default"),
        ("[wrapper]\nmode = \"bogus\"\n[workspaces]\nroots = [\"/w\"]\n", Some("default"), vec![left_alone("[wrapper] mode = \"bogus\": remote"), closed.clone(), undo.clone()], "default"),
        // With no root, no chat goes remote: none fails closed, no note.
        ("[wrapper]\nmode = 1\n", Some("default"), vec![unreadable.clone(), undo.clone()], "default"),
        ("[wrapper]\nmode = \"bogus\"\n", Some("default"), vec![left_alone("[wrapper] mode = \"bogus\": remote"), undo.clone()], "default"),
        // A file that does not load: remote fails closed under its roots, passthrough runs on this Mac.
        ("[wrapper]\nmode = \"remote\"\n[vm]\nnope = 1\n[workspaces]\nroots = [\"/w\"]\n", Some("default"), vec![remote.clone(), closed.clone(), undo.clone()], "default"),
        ("[wrapper]\nmode = \"remote\"\n[vm]\nnope = 1\n", Some("default"), vec![remote.clone(), undo.clone()], "default"),
        ("[wrapper]\nmode = \"passthrough\"\n[vm]\nnope = 1\n", Some("default"), vec![left_alone("[wrapper] mode = \"passthrough\""), undo.clone()], "default"),
        // An initial_permission_mode install refuses: the undo names one it takes.
        (bogus, None, vec![remote.clone(), with_flag("default"), refused("unset")], "default"),
        (bogus, Some("bogus"), vec![remote.clone(), with_flag("default"), refused("\"bogus\"")], "default"),
        (bogus, Some("plan"), vec![remote.clone(), with_flag("plan")], "plan"),
        // With a root, the other checks of a remote session's start: no [aws] (exit 1), a name P0 refuses (exit 9), none.
        (rooted, Some("default"), vec![remote.clone(), closed.clone(), undo.clone()], "default"),
        (refusing.as_str(), Some("default"), vec![remote.clone(), closed_with(9), undo.clone()], "default"),
        (planned.as_str(), Some("default"), vec![remote.clone(), undo.clone()], "default"),
    ];
    let home = Home::new();
    std::fs::create_dir_all(home.bridge_dir()).unwrap();
    let settings = |now: Option<&str>| {
        let mode = now.map_or_else(String::new, |m| format!(",\n  {}: {}", json_str(PERMISSION_SETTING), json_str(m)));
        format!("{{\n  {}: \"/x/ai-env-claude\"{mode}\n}}\n", json_str(WRAPPER_SETTING))
    };
    // From the bridge.toml line to the end.
    let tail = |stdout: &str| -> Vec<String> { stdout.lines().skip_while(|l| !l.starts_with("bridge.toml is left alone")).map(str::to_string).collect() };
    for (toml, now, want, after) in cases {
        std::fs::write(home.bridge_toml(), toml).unwrap();
        home.write_settings(&settings(now));
        let out = home.run(&["uninstall"]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{toml:?} {now:?}: {stdout}{stderr}");
        assert!(stderr.is_empty(), "{toml:?} {now:?}: {stderr}");
        assert_eq!(tail(&stdout), want, "{toml:?} {now:?}");
        let undo_args: Vec<&str> = want.iter().find_map(|l| l.strip_prefix("undo: ai-env wrapper ")).unwrap().split(' ').filter(|a| *a != "--write").collect();
        let out = home.run(&undo_args);
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{toml:?} {undo_args:?}: {stdout}{}", text(&out.stderr));
        assert!(stdout.contains(&snippet(sibling().to_str().unwrap(), after)), "{toml:?} {undo_args:?}: {stdout}");
        assert_eq!(std::fs::read_to_string(home.bridge_toml()).unwrap(), toml);
    }
    // Why the flag: install without it refuses bridge.toml's value.
    std::fs::write(home.bridge_toml(), bogus).unwrap();
    let out = home.run(&["install"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));

    // --write edits settings.json only: bridge.toml byte for byte, no backup of it.
    std::fs::write(home.bridge_toml(), plan).unwrap();
    home.write_settings(&settings(Some("plan")));
    let out = home.run(&["uninstall", "--write"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert_eq!(tail(&stdout), [remote.clone(), undo.clone()]);
    assert_eq!(home.settings_text(), format!("{{\n  {}: \"plan\"\n}}\n", json_str(PERMISSION_SETTING)));
    assert_eq!(std::fs::read_to_string(home.bridge_toml()).unwrap(), plan);
    assert!(home.bridge_backups().is_empty(), "{:?}", home.bridge_backups());

    // A bridge.toml that cannot be read is remote to the wrapper too (root reads through the mode: skipped).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.bridge_toml(), std::fs::Permissions::from_mode(0o000)).unwrap();
        home.write_settings(&settings(Some("default")));
        let readable = std::fs::read(home.bridge_toml()).is_ok();
        let out = home.run(&["uninstall"]);
        std::fs::set_permissions(home.bridge_toml(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let stdout = text(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
        if readable {
            eprintln!("root reads a mode-000 file: skipped");
        } else {
            assert_eq!(tail(&stdout), [unreadable, closed, undo]);
        }
    }
}

/// Cursor's `claudeCode.environmentVariables`, which the extension hands to
/// every process it starts (the wrapper too, once install brings it back),
/// weigh in the bridge.toml line as `ai-env wrapper status` weighs them: the
/// kill switch (exactly `1`) runs every chat on this Mac whatever the mode;
/// an `AI_ENV_BRIDGE_MODE` that names a mode wins over bridge.toml's, the
/// fail-closed note following it (remote over a `[wrapper] mode` the
/// wrapper does not know still fails closed: the session's start refuses
/// the key; with no root no chat goes remote, and no note), and one that
/// names none is ignored; a
/// bridge root or bridge.toml other than this command's is named (scrubbed)
/// and its mode never claimed. Read from a list or an object, the last
/// entry winning. No other variable shows, by name or by value, and nothing
/// reaches stderr (a value that names no mode is never handed to the
/// wrapper's own reading, which would say so there).
#[test]
fn uninstall_weighs_cursors_variables_as_status_does() {
    use ai_env_cli::bridge::wrapper_status::ENV_SETTING;
    let home = Home::new();
    std::fs::create_dir_all(home.bridge_dir()).unwrap();
    // Built at run time: no secret-shaped literal in the source.
    let secret_name = format!("{}_{}", "PLANTED", "API_KEY");
    let secret_value = format!("pv-{}", "q".repeat(40));
    let token = format!("{}oat01-{}", "sk-ant-", "Z".repeat(30));
    let in_cursor = format!("Cursor's {ENV_SETTING}");
    let back = "ai-env wrapper install --write brings the wrapper back";
    let left_alone = |mode: &str, how: &str| format!("bridge.toml is left alone ({mode}): {back}, {how}, for what Cursor starts after it.");
    let over = |m: &str| format!("in {m} mode, which AI_ENV_BRIDGE_MODE in {in_cursor} sets over bridge.toml's");
    let kill = format!("bridge.toml is left alone: {back}, but the kill switch (AI_ENV_BRIDGE_LOCAL=1 in {in_cursor}) still runs every chat on this Mac.");
    let closed = "note: with the wrapper back, every Cursor chat under bridge.toml's roots (every chat, when they cannot be read) exits 1 naming the error until bridge.toml is fixed (ai-env wrapper status shows it)".to_string();
    let undo = "undo: ai-env wrapper install --write".to_string();
    let elsewhere = home.path().join("elsewhere");
    let dir = |v: &str| format!("AI_ENV_BRIDGE_DIR={v:?}");
    let another = |vars: &str, how: &str| format!("bridge.toml is left alone, but the wrapper reads another bridge root ({vars} in {in_cursor}): {back}, {how}, for what Cursor starts after it (ai-env wrapper status shows the variables).");
    let (remote, broken_remote) = ("[wrapper]\nmode = \"remote\"\n", "[wrapper]\nmode = \"remote\"\n[vm]\nnope = 1\n");
    let (passthrough, broken_passthrough) = ("[wrapper]\nmode = \"passthrough\"\n", "[wrapper]\nmode = \"passthrough\"\n[vm]\nnope = 1\n");
    // The same two files that do not load, with a root to route on.
    let (rooted_remote, rooted_passthrough) = (format!("{broken_remote}[workspaces]\nroots = [\"/w\"]\n"), format!("{broken_passthrough}[workspaces]\nroots = [\"/w\"]\n"));
    let var = |name: &str, value: serde_json::Value| serde_json::json!({ "name": name, "value": value });
    // (bridge.toml, Cursor's variables, the lines from the bridge.toml line on)
    let cases: Vec<(&str, serde_json::Value, Vec<String>)> = vec![
        // (a) The kill switch, as a list entry or an object's number: over remote, over a file that fails closed.
        (remote, serde_json::json!([var("AI_ENV_BRIDGE_LOCAL", "1".into())]), vec![kill.clone(), undo.clone()]),
        ("[wrapper]\nmode = \"remotely\"\n", serde_json::json!({ "AI_ENV_BRIDGE_LOCAL": 1, "AI_ENV_BRIDGE_MODE": "remote" }), vec![kill.clone(), undo.clone()]),
        // Anything but exactly 1 is no kill switch; the last entry of a name wins.
        (remote, serde_json::json!([var("AI_ENV_BRIDGE_LOCAL", "true".into())]), vec![left_alone("[wrapper] mode = \"remote\"", "in that mode"), undo.clone()]),
        (remote, serde_json::json!([var("AI_ENV_BRIDGE_LOCAL", "1".into()), var("AI_ENV_BRIDGE_LOCAL", "0".into())]), vec![left_alone("[wrapper] mode = \"remote\"", "in that mode"), undo.clone()]),
        // (b) A mode named wins over bridge.toml's, and the note follows the mode the chats get.
        (passthrough, serde_json::json!([var("AI_ENV_BRIDGE_MODE", "remote".into())]), vec![left_alone("[wrapper] mode = \"passthrough\"", &over("remote")), undo.clone()]),
        (remote, serde_json::json!({ "AI_ENV_BRIDGE_MODE": "passthrough" }), vec![left_alone("[wrapper] mode = \"remote\"", &over("passthrough")), undo.clone()]),
        (rooted_passthrough.as_str(), serde_json::json!([var("AI_ENV_BRIDGE_MODE", "remote".into())]), vec![left_alone("[wrapper] mode = \"passthrough\"", &over("remote")), closed.clone(), undo.clone()]),
        // With no root no chat goes remote: no note.
        (broken_passthrough, serde_json::json!([var("AI_ENV_BRIDGE_MODE", "remote".into())]), vec![left_alone("[wrapper] mode = \"passthrough\"", &over("remote")), undo.clone()]),
        (broken_remote, serde_json::json!([var("AI_ENV_BRIDGE_MODE", "passthrough".into())]), vec![left_alone("[wrapper] mode = \"remote\"", &over("passthrough")), undo.clone()]),
        ("[wrapper]\nmode = \"bogus\"\n", serde_json::json!([var("AI_ENV_BRIDGE_MODE", "local-child".into())]), vec![left_alone("[wrapper] mode = \"bogus\": remote", &over("local-child")), undo.clone()]),
        // Remote named over a mode bridge.toml does not name: the session's start still refuses the key.
        ("[wrapper]\nmode = \"remotely\"\n[workspaces]\nroots = [\"/w\"]\n", serde_json::json!([var("AI_ENV_BRIDGE_MODE", "remote".into())]), vec![left_alone("[wrapper] mode = \"remotely\": remote", &over("remote")), closed.clone(), undo.clone()]),
        // One that names no mode is ignored, its value never shown.
        (rooted_remote.as_str(), serde_json::json!([var("AI_ENV_BRIDGE_MODE", token.clone().into())]), vec![left_alone("[wrapper] mode = \"remote\"", "in that mode"), closed.clone(), undo.clone()]),
        (broken_remote, serde_json::json!([var("AI_ENV_BRIDGE_MODE", token.clone().into())]), vec![left_alone("[wrapper] mode = \"remote\"", "in that mode"), undo.clone()]),
        // (c) Another bridge root or bridge.toml: named, scrubbed and capped, its mode never claimed, no note.
        (
            broken_remote,
            serde_json::json!([var("AI_ENV_BRIDGE_DIR", format!("{}/{token}", elsewhere.display()).into())]),
            vec![another(&dir(&format!("{}/sk-ant-[redacted:len={}]", elsewhere.display(), token.len())), "in the mode the bridge.toml there names"), undo.clone()],
        ),
        (
            remote,
            serde_json::json!({ "AI_ENV_BRIDGE_CONFIG": elsewhere.join("bridge.toml"), "AI_ENV_BRIDGE_DIR": elsewhere, "AI_ENV_BRIDGE_MODE": "passthrough" }),
            vec![
                another(&format!("{} and AI_ENV_BRIDGE_CONFIG={:?}", dir(&elsewhere.display().to_string()), elsewhere.join("bridge.toml").display().to_string()), &format!("in passthrough mode (AI_ENV_BRIDGE_MODE in {in_cursor})")),
                undo.clone(),
            ],
        ),
        // This command's own root and bridge.toml are no other.
        (remote, serde_json::json!({ "AI_ENV_BRIDGE_DIR": home.bridge_dir(), "AI_ENV_BRIDGE_CONFIG": home.bridge_toml() }), vec![left_alone("[wrapper] mode = \"remote\"", "in that mode"), undo.clone()]),
    ];
    let tail = |stdout: &str| -> Vec<String> { stdout.lines().skip_while(|l| !l.starts_with("bridge.toml is left alone")).map(str::to_string).collect() };
    for (toml, mut vars, want) in cases {
        std::fs::write(home.bridge_toml(), toml).unwrap();
        // The planted variable comes first: never shown, and never the one that wins.
        match &mut vars {
            serde_json::Value::Array(list) => list.insert(0, var(&secret_name, secret_value.clone().into())),
            serde_json::Value::Object(names) => {
                names.insert(secret_name.clone(), secret_value.clone().into());
            }
            _ => unreachable!(),
        }
        let settings = serde_json::json!({ WRAPPER_SETTING: "/x/ai-env-claude", PERMISSION_SETTING: "default", ENV_SETTING: vars });
        home.write_settings(&settings.to_string());
        let out = home.run(&["uninstall"]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{settings}: {stdout}{stderr}");
        assert!(stderr.is_empty(), "{settings}: {stderr}");
        assert_eq!(tail(&stdout), want, "{settings}");
        for never in [&secret_name, &secret_value, &token] {
            assert!(!stdout.contains(never.as_str()), "{never} shown: {stdout}");
        }
        assert_eq!(std::fs::read_to_string(home.bridge_toml()).unwrap(), toml);
    }
    // --write says the same, and edits settings.json only: the variables stay.
    let settings = serde_json::json!({ WRAPPER_SETTING: "/x/ai-env-claude", PERMISSION_SETTING: "default", ENV_SETTING: [var("AI_ENV_BRIDGE_LOCAL", "1".into())] });
    home.write_settings(&settings.to_string());
    let out = home.run(&["uninstall", "--write"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert_eq!(tail(&stdout), [kill, undo]);
    assert_eq!(parse_settings(&home.settings_text()).unwrap(), serde_json::json!({ PERMISSION_SETTING: "default", ENV_SETTING: [var("AI_ENV_BRIDGE_LOCAL", "1".into())] }));
}

/// A `[wrapper] mode` that looks like a token (built at run time) never
/// shows raw in uninstall's bridge.toml line, the file loading or not, nor
/// in `install --mode`'s line on the value it replaces: scrubbed and capped
/// at 64 characters, as `ai-env wrapper status` shows it.
#[test]
fn uninstall_never_prints_a_secret_looking_mode() {
    let home = Home::new();
    std::fs::create_dir_all(home.bridge_dir()).unwrap();
    let token = format!("{}oat01-{}", "sk-ant-", "Q".repeat(40));
    let masked = format!("\"sk-ant-[redacted:len={}]\"", token.len());
    let long = "m".repeat(100);
    home.write_settings(&format!("{{\n  {}: \"/x/ai-env-claude\",\n  {}: \"default\"\n}}\n", json_str(WRAPPER_SETTING), json_str(PERMISSION_SETTING)));
    let line = |shown: &str| format!("bridge.toml is left alone ([wrapper] mode = {shown}: remote): ai-env wrapper install --write brings the wrapper back, in that mode, for what Cursor starts after it.");
    for (toml, shown) in [
        (format!("[wrapper]\nmode = \"{token}\"\n[workspaces]\nroots = [\"/w\"]\n"), masked.clone()),
        (format!("[wrapper]\nmode = \"{token}\"\n[vm]\nnope = 1\n[workspaces]\nroots = [\"/w\"]\n"), masked.clone()),
        (format!("[wrapper]\nmode = \"{long}\"\n"), format!("{:?}", "m".repeat(64))),
    ] {
        std::fs::write(home.bridge_toml(), &toml).unwrap();
        let out = home.run(&["uninstall"]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{toml:?}: {stdout}{stderr}");
        assert!(stderr.is_empty(), "{toml:?}: {stderr}");
        assert!(stdout.lines().any(|l| l == line(&shown)), "{toml:?}: {stdout}");
        assert!(!stdout.contains(&token) && !stdout.contains("QQQQ") && !stdout.contains(&long), "{toml:?}: {stdout}");
    }
    // install --mode names the value it replaces the same way (a dry run: neither file written).
    let toml = format!("[wrapper]\nmode = \"{token}\"\n[workspaces]\nroots = [\"/w\"]\n");
    std::fs::write(home.bridge_toml(), &toml).unwrap();
    let before = home.settings_text();
    let out = home.run(&["install", "--mode", "remote"]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert!(stdout.lines().any(|l| l == format!("  [wrapper] mode: {masked} -> \"remote\"")), "{stdout}");
    assert!(!format!("{stdout}{stderr}").contains("QQQQ"), "{stdout}{stderr}");
    assert_eq!((home.settings_text(), std::fs::read_to_string(home.bridge_toml()).unwrap()), (before, toml));
}

/// bridge.toml's other values these commands name never show raw either
/// (a token built at run time): an `[wrapper].initial_permission_mode`
/// install refuses, in uninstall's note on the undo and in install's own
/// refusal (exit 2), scrubbed and capped; and the error of a bridge.toml the
/// `--mode` splice refuses (exit 1), its first line only (the rest quotes
/// the file), scrubbed. Neither file is written.
#[test]
fn install_and_uninstall_never_print_a_secret_looking_bridge_toml_value() {
    let home = Home::new();
    std::fs::create_dir_all(home.bridge_dir()).unwrap();
    let token = format!("{}oat01-{}", "sk-ant-", "Q".repeat(40));
    let masked = format!("\"sk-ant-[redacted:len={}]\"", token.len());
    let settings = format!("{{\n  {}: \"/x/ai-env-claude\"\n}}\n", json_str(WRAPPER_SETTING));
    home.write_settings(&settings);
    let never = |what: &str, out: &Output| {
        let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(!all.contains(&token) && !all.contains("QQQQ"), "{what}: {all}");
    };
    std::fs::write(home.bridge_toml(), format!("[wrapper]\nmode = \"passthrough\"\ninitial_permission_mode = \"{token}\"\n")).unwrap();
    let out = home.run(&["uninstall"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    for want in ["undo: ai-env wrapper install --write --permission-mode default".to_string(), format!("note: install refuses bridge.toml's [wrapper].initial_permission_mode = {masked}: the undo sets {PERMISSION_SETTING} to \"default\" (now unset)")] {
        assert!(stdout.lines().any(|l| l == want), "{want}: {stdout}");
    }
    never("uninstall", &out);
    let out = home.run(&["install"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    let refusal = format!("ai-env: permission mode {masked} is not one of default, manual, acceptEdits, plan, bypassPermissions");
    assert!(text(&out.stderr).lines().any(|l| l == refusal), "{}", text(&out.stderr));
    never("install", &out);
    // The splice's own check of the result: a value on its error's first line, a key in the snippet after it.
    let path = home.bridge_toml().display().to_string();
    for (toml, first) in [
        (format!("[aws]\nregion = \"{token}\"\n"), format!("the result is not a valid bridge.toml: config: [aws].region = {masked} but the MicroVM bridge is pinned to eu-central-1 (eu-west-3 is not supported)")),
        (format!("[wrapper]\n{token} = 1\n"), "the result is not a valid bridge.toml: config: bridge.toml: TOML parse error at line 2, column 1".to_string()),
    ] {
        std::fs::write(home.bridge_toml(), &toml).unwrap();
        let out = home.run(&["install", "--write", "--mode", "remote"]);
        assert_eq!(out.status.code(), Some(1), "{toml:?}: {}", text(&out.stderr));
        assert_eq!(text(&out.stderr), format!("ai-env: {path}: {first}; set [wrapper] mode = \"remote\" by hand\n"), "{toml:?}");
        never(&toml, &out);
        assert_eq!((home.settings_text(), std::fs::read_to_string(home.bridge_toml()).unwrap()), (settings.clone(), toml), "nothing written");
    }
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
    assert_eq!((written["v"].as_u64(), written["added"].as_array().map(Vec::len), written["vms"].as_array().map(Vec::len), written["vms"][0]["scopes"].as_array().map(Vec::len)), (Some(3), Some(4), Some(1), Some(3)), "{written}");
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
    assert!(stdout.contains("Chats started from now on use the new mode; a window reload moves the chats already open, and restarts them.") && !stdout.contains("Reload the Cursor window"), "{stdout}");
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
    assert!(stdout.contains("Chats started from now on use the new mode; a window reload moves the chats already open, and restarts them.") && !stdout.contains("Reload the Cursor window"), "{stdout}");
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

// ---- S11 (B.4, T11.2): doctor names each broken precondition with its fix ----

/// A stand-in for a tool doctor probes: each call exits 1 (never the real aws or claude).
const REFUSED_TOOL: &str = "#!/bin/sh\nexit 1\n";

/// T11.2's process test (S11 B.4): the real `ai-env doctor` (a copy, alone in its own bin directory) names each
/// broken precondition `[NO ]` with its fix and exits 1: the sibling removed; a stale `ai-env-claude` printing
/// 0.0.9; the wrapper setting at a missing path, then at a non-executable one; a finding planted in a checkout's
/// `image/` (a temporary `git init` checkout whose `image/` holds `MANIFEST` and a regular `claude/settings.json`,
/// `image_dir_of`'s two checks, doctor run from it). Every tool doctor's rows probe is a stand-in that exits 1 (aws
/// and claude among them: no AWS call, never the real claude); the home and the bridge directory are temporary and
/// the environment is cleared.
#[cfg(unix)]
#[test]
fn doctor_names_each_broken_precondition_with_its_fix() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new();
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let executable = |p: &Path, body: &str| {
        std::fs::write(p, body).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        // macOS assesses a new executable at its first exec, which on a busy Mac can outlast doctor's 5 s probes.
        let _ = bounded::run_within(Command::new(p), None, LIMIT, "a stand-in's first run");
    };
    for tool in ["aws", "claude", "rustup", "cargo-lambda", "zig"] {
        executable(&bin.join(tool), REFUSED_TOOL);
    }
    let copy = bin.join("ai-env");
    std::fs::copy(ai_env(), &copy).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    let doctor = |cwd: &Path| -> (Option<i32>, Vec<String>) {
        let mut cmd = Command::new(&copy);
        cmd.arg("doctor").current_dir(cwd).env_clear().env("HOME", home.path()).env("AI_ENV_BRIDGE_DIR", home.bridge_dir()).env("PATH", format!("{}:/usr/bin:/bin", bin.display())).env("TMPDIR", std::env::temp_dir());
        let out = bounded::run_within(cmd, None, LIMIT, "ai-env doctor");
        let stdout = text(&out.stdout);
        (out.status.code(), stdout.lines().map(|l| l.trim_start().to_string()).collect())
    };
    let has = |rows: &[String], row: &str| assert!(rows.iter().any(|l| l == row), "no row {row:?} in:\n{}", rows.join("\n"));
    let mine = env!("CARGO_PKG_VERSION");
    let setting = WRAPPER_SETTING;
    let gone = home.path().join("gone").join("ai-env-claude");
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: gone.to_str().unwrap(), PERMISSION_SETTING: "default" }).to_string());

    // The sibling removed: both rows name the install first (provable only without an ai-env-claude in a Homebrew bin dir).
    if homebrew_sibling_present() {
        eprintln!("doctor_names_each_broken_precondition_with_its_fix: the missing sibling skipped (an ai-env-claude is installed under a Homebrew bin dir)");
    } else {
        let (code, rows) = doctor(home.path());
        assert_eq!(code, Some(1), "{}", rows.join("\n"));
        has(&rows, "[NO ] ai-env-claude missing  <- install with: cargo install --path crates/ai-env-cli --locked");
        has(&rows, &format!("[NO ] {setting} = {} does not exist  <- cargo install --path crates/ai-env-cli --locked, then ai-env wrapper install --write", gone.display()));
        has(&rows, "[-  ] image/ not scanned: not in an ai-env checkout");
    }

    // A stale ai-env-claude next to ai-env: the skew; the wrapper path missing names the setting's fix alone.
    executable(&bin.join("ai-env-claude"), "#!/bin/sh\necho 'ai-env-claude 0.0.9'\n");
    let (code, rows) = doctor(home.path());
    assert_eq!(code, Some(1), "{}", rows.join("\n"));
    has(&rows, &format!("[NO ] version skew: ai-env {mine}, ai-env-claude 0.0.9  <- install with: cargo install --path crates/ai-env-cli --locked"));
    has(&rows, &format!("[NO ] {setting} = {} does not exist  <- ai-env wrapper install --write", gone.display()));

    // The setting at a file that is not executable.
    let plain = home.path().join("plain").join("ai-env-claude");
    std::fs::create_dir_all(plain.parent().unwrap()).unwrap();
    std::fs::write(&plain, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: plain.to_str().unwrap(), PERMISSION_SETTING: "default" }).to_string());
    let (code, rows) = doctor(home.path());
    assert_eq!(code, Some(1), "{}", rows.join("\n"));
    has(&rows, &format!("[NO ] {setting} = {} is not executable  <- ai-env wrapper install --write", plain.display()));

    // A checkout: image/ with its MANIFEST and a regular claude/settings.json scans clean, then a planted symlink is a finding.
    let checkout = home.path().join("checkout");
    std::fs::create_dir_all(checkout.join("image").join("claude")).unwrap();
    let init = bounded::run_within(
        {
            let mut git = Command::new("git");
            git.args(["init", "-q"]).current_dir(&checkout);
            git
        },
        None,
        LIMIT,
        "git init",
    );
    assert!(init.status.success(), "{}", text(&init.stderr));
    std::fs::write(checkout.join("image").join("MANIFEST"), "file claude/settings.json 0644\n").unwrap();
    std::fs::write(checkout.join("image").join("claude").join("settings.json"), BASE_SETTINGS).unwrap();
    let (_, rows) = doctor(&checkout);
    has(&rows, "[ok ] image/ scan: clean (2 files)");
    std::os::unix::fs::symlink("MANIFEST", checkout.join("image").join("planted")).unwrap();
    let (code, rows) = doctor(&checkout.join("image"));
    assert_eq!(code, Some(1), "{}", rows.join("\n"));
    has(&rows, "[NO ] image/ has 1 finding(s): symlink  <- fix them, then make image-zip and make deploy");
    // image_dir_of's second check: a claude/settings.json that is no regular file is a failed scan, not a clean one.
    std::fs::remove_file(checkout.join("image").join("claude").join("settings.json")).unwrap();
    std::os::unix::fs::symlink("../MANIFEST", checkout.join("image").join("claude").join("settings.json")).unwrap();
    let (_, rows) = doctor(&checkout);
    assert!(rows.iter().any(|l| l.starts_with("[!! ] image/ scan failed: ") && l.ends_with("/claude/settings.json is not a regular file")), "{}", rows.join("\n"));
    // Without the MANIFEST it is no ai-env checkout.
    std::fs::remove_file(checkout.join("image").join("MANIFEST")).unwrap();
    let (_, rows) = doctor(&checkout);
    has(&rows, "[-  ] image/ not scanned: not in an ai-env checkout");
}
