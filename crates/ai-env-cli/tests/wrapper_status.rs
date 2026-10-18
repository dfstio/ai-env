//! `ai-env wrapper status` (plans/wrapper-status-uninstall-plan.md §2) —
//! compiled only with `bridge`. Every run clears the environment: `HOME` is a
//! tempdir holding Cursor's settings (`Library/Application
//! Support/Cursor/User`), the bridge root at its default
//! (`.config/ai-env/bridge`, the one the wrapper reads without
//! `AI_ENV_BRIDGE_DIR`) and the extensions (`.cursor/extensions`); `PATH` is a
//! temp bin dir in front of /usr/bin:/bin holding the fake aws, age and
//! osascript (tests/fakes, each logging every call; osascript also through
//! `AI_ENV_BRIDGE_LAB_OSASCRIPT`) and a `claude` that must not run
//! (tests/fakes/logged.sh). After every run no fake has logged a call (no AWS,
//! no Touch ID, no notice, no claude) and the tempdir is byte for byte what it
//! was (status writes nothing). The one process status starts is the sibling
//! ai-env-claude's `--version`, next to `CARGO_BIN_EXE_ai-env`.
//! std::process only; nothing here mutates the test process's environment.
// Every wait bounded (S8 phase 4); this binary has no `common`.
#[path = "common/bounded.rs"]
mod bounded;

use ai_env_cli::bridge::census::{CensusRow, MAX_ROW_BYTES};
use ai_env_cli::bridge::doctor::{PERMISSION_SETTING, WRAPPER_SETTING};
use ai_env_cli::bridge::wrapper_status::{CENSUS_TAIL_CHUNKS, ENV_SETTING};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// How long one `ai-env` run may take here (every wait bounded).
const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Each fake's log variable and its file under the home: absent after every run.
const LOGS: [(&str, &str); 4] = [("FAKE_AWS_LOG", "aws.log"), ("FAKE_AGE_LOG", "age.log"), ("FAKE_OSA_LOG", "osascript.log"), ("FAKE_LOG", "claude.log")];

/// The `[aws]` a remote session's run plan needs (the documentation
/// account's made-up image and egress connector): without it every remote
/// session ends at its start.
const AWS: &str = "\n[aws]\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env\"\negress_connector_arn = \"arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress\"\n";

/// When [`Home::write_settings`] dates Cursor's settings.json (its mtime):
/// before every census row these tests write, as for a wrapper set long
/// ago. Status weighs each census row against the file's last change.
const SETTINGS_CHANGED: &str = "2026-09-01T00:00:00Z";

fn ai_env() -> &'static str {
    env!("CARGO_BIN_EXE_ai-env")
}

/// The sibling status finds and asks for its version: `<dir of ai-env>/ai-env-claude`.
fn sibling() -> PathBuf {
    Path::new(ai_env()).with_file_name("ai-env-claude")
}

/// Whether the test binaries live under a `target/` component (cargo's
/// default): then doctor's build-directory warning is among the wrapper rows.
fn under_target() -> bool {
    Path::new(ai_env()).components().any(|c| c.as_os_str() == "target")
}

/// Lossy text of a captured stream, for assertions and their messages.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A JSON string literal, as Cursor writes one.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

/// A census line shaped like `CensusRow` (proved by deserialising it): its
/// `start` from the same clock read as `ts`, its argv[1] in the bundle of
/// `ext` (none: Homebrew's claude), its note the wrapper's.
fn census_row(ts: &str, route: &str, reason: &str, ext: Option<&str>, note: Option<&str>) -> String {
    let real = ext.map_or_else(|| "/opt/homebrew/bin/claude".to_string(), |v| format!("/Users/u/.cursor/extensions/anthropic.claude-code-{v}-darwin-arm64/resources/native-binary/claude"));
    let row = serde_json::json!({
        "v": 1,
        "ts": ts,
        "start": ai_env_cli::wire::time::parse_rfc3339_utc(ts).expect("an RFC 3339 UTC ts") * 1000,
        "pid": 4242,
        "ppid": 4200,
        "ext": ext,
        "route": route,
        "reason": reason,
        "argv": ["/Users/u/.cargo/bin/ai-env-claude", real, "--output-format", "stream-json"],
        "cwd": "/Users/u/work",
        "env_names": ["HOME", "PATH"],
        "env_selected": {},
        "note": note
    });
    serde_json::from_value::<CensusRow>(row.clone()).unwrap_or_else(|e| panic!("not a CensusRow: {e}"));
    row.to_string()
}

/// The pump's end row for the census line `start_row`: a clone with `end` (a
/// minute later), `exit` and the note extended (`pump::end_row`).
fn end_row(start_row: &str) -> String {
    let mut row: CensusRow = serde_json::from_str(start_row).unwrap();
    row.end = Some(row.start + 60_000);
    row.exit = Some(0);
    row.note = Some(row.note.map_or_else(|| "end:eof_term".to_string(), |n| format!("{n}; end:eof_term")));
    serde_json::to_string(&row).unwrap()
}

/// A tempdir standing in for the user's home, with the fakes' bin dir.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let home = Home { dir: tempfile::tempdir().unwrap() };
        std::fs::create_dir(home.bin()).unwrap();
        for (fake, name) in [("age.sh", "age"), ("age.sh", "age-keygen"), ("age.sh", "age-plugin-se"), ("aws.sh", "aws"), ("osascript.sh", "osascript"), ("logged.sh", "claude")] {
            let dst = home.bin().join(name);
            std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fakes").join(fake), &dst).unwrap();
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        home
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn bin(&self) -> PathBuf {
        self.path().join("bin")
    }

    fn settings_path(&self) -> PathBuf {
        self.path().join("Library").join("Application Support").join("Cursor").join("User").join("settings.json")
    }

    /// Write Cursor's settings.json, dated [`SETTINGS_CHANGED`].
    fn write_settings(&self, text: &str) {
        std::fs::create_dir_all(self.settings_path().parent().unwrap()).unwrap();
        std::fs::write(self.settings_path(), text).unwrap();
        self.date_settings(SETTINGS_CHANGED);
    }

    /// Set settings.json's mtime to `ts` (RFC 3339 UTC): its last change, as status reads it.
    fn date_settings(&self, ts: &str) {
        let secs = ai_env_cli::wire::time::parse_rfc3339_utc(ts).expect("an RFC 3339 UTC ts");
        self.date_settings_ns(secs * 1_000_000_000);
    }

    /// Set settings.json's mtime to `ns` nanoseconds since the epoch.
    fn date_settings_ns(&self, ns: u64) {
        let file = std::fs::File::options().write(true).open(self.settings_path()).unwrap();
        file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_nanos(ns)).unwrap();
    }

    /// The bridge root status and the wrapper resolve from `HOME` alone.
    fn bridge_dir(&self) -> PathBuf {
        self.path().join(".config").join("ai-env").join("bridge")
    }

    fn bridge_toml(&self) -> PathBuf {
        self.bridge_dir().join("bridge.toml")
    }

    fn write_bridge_toml(&self, text: &str) {
        std::fs::create_dir_all(self.bridge_dir()).unwrap();
        std::fs::write(self.bridge_toml(), text).unwrap();
    }

    fn census_path(&self) -> PathBuf {
        self.bridge_dir().join("logs").join("census.jsonl")
    }

    /// Append `lines` to the census, one each.
    fn seed_census(&self, lines: &[String]) {
        std::fs::create_dir_all(self.census_path().parent().unwrap()).unwrap();
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.census_path()).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
    }

    /// One extension directory per version, those of `obsolete` listed in `.obsolete`.
    fn install_extensions(&self, versions: &[&str], obsolete: &[&str]) {
        let dir = self.path().join(".cursor").join("extensions");
        let name = |v: &str| format!("anthropic.claude-code-{v}-darwin-arm64");
        for v in versions {
            std::fs::create_dir_all(dir.join(name(v))).unwrap();
        }
        let listed: serde_json::Map<String, serde_json::Value> = obsolete.iter().map(|v| (name(v), serde_json::Value::Bool(true))).collect();
        std::fs::write(dir.join(".obsolete"), serde_json::Value::Object(listed).to_string()).unwrap();
    }

    /// Every path under the home with its bytes (`None` for a directory; a
    /// symlink its target, never followed; a FIFO a marker, never opened).
    fn snapshot(&self) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let p = entry.path();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() {
                    walk(&p, out);
                    out.insert(p, None);
                } else if kind.is_symlink() {
                    let target = std::fs::read_link(&p).unwrap();
                    out.insert(p, Some(format!("symlink to {}", target.display()).into_bytes()));
                } else if kind.is_file() {
                    let bytes = std::fs::read(&p).unwrap();
                    out.insert(p, Some(bytes));
                } else {
                    out.insert(p, Some(b"not a regular file".to_vec()));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(self.path(), &mut out);
        out
    }

    /// `ai-env wrapper status <args…>` within [`LIMIT`], the environment
    /// cleared but for `HOME`, `PATH` (the fakes first) and the fakes' knobs;
    /// then no fake ran and nothing under the home changed.
    fn status(&self, args: &[&str]) -> Output {
        self.status_within(args, LIMIT)
    }

    /// [`Home::status`] within `limit`: killed and failed past it.
    fn status_within(&self, args: &[&str], limit: std::time::Duration) -> Output {
        let before = self.snapshot();
        let mut cmd = Command::new(ai_env());
        cmd.args(["wrapper", "status"])
            .args(args)
            .env_clear()
            .current_dir(self.path())
            .env("HOME", self.path())
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("AI_ENV_BRIDGE_LAB_OSASCRIPT", self.bin().join("osascript"));
        for (var, log) in LOGS {
            cmd.env(var, self.path().join(log));
        }
        let out = bounded::run_within(cmd, None, limit, "ai-env wrapper status");
        for (_, log) in LOGS {
            let p = self.path().join(log);
            assert!(!p.exists(), "{log}: a fake ran: {}", std::fs::read_to_string(&p).unwrap_or_default());
        }
        let after = self.snapshot();
        let changed: Vec<&PathBuf> = before.keys().chain(after.keys()).filter(|p| before.get(*p) != after.get(*p)).collect();
        assert!(changed.is_empty(), "status changed {changed:?}");
        out
    }
}

/// `stdout` holds each of `lines`, whole.
fn assert_lines(stdout: &str, lines: &[String]) {
    let missing: Vec<&String> = lines.iter().filter(|l| !stdout.lines().any(|s| s == l.as_str())).collect();
    assert!(missing.is_empty(), "missing {missing:#?} in:\n{stdout}");
}

/// Not installed (no settings file, no bridge.toml, no census, no
/// extension): the wrapper key's row is `[-  ]` naming the install, no row
/// is `[NO ]`, exit 0, nothing on stderr. A settings file of nothing, or of
/// comments only, is no settings (to Cursor, and to uninstall): the same rows.
#[test]
fn not_installed_is_a_skip_row_and_exit_0() {
    let home = Home::new();
    let path = home.settings_path();
    for (what, settings) in [("absent", None), ("empty", Some("")), ("empty", Some("// Cursor's settings\n  /* none yet */\n"))] {
        if let Some(t) = settings {
            home.write_settings(t);
        }
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{settings:?}: {stdout}{stderr}");
        assert!(stderr.is_empty(), "{settings:?}: {stderr}");
        assert!(stdout.starts_with("ai-env wrapper status\n"), "{stdout}");
        assert_lines(
            &stdout,
            &[
                format!("  [-  ] Cursor settings {} {what}", path.display()),
                format!("  [-  ] {WRAPPER_SETTING} not set  <- ai-env wrapper install --write"),
                format!("  [ok ] {ENV_SETTING} sets none of AI_ENV_BRIDGE_LOCAL, AI_ENV_BRIDGE_MODE, AI_ENV_BRIDGE_DIR, AI_ENV_BRIDGE_CONFIG"),
                // No wrapper: the file's mode is not what Cursor's chats get (doctor's row would say it is).
                "  [-  ] no bridge.toml ([wrapper] mode passthrough, the default): not what Cursor's chats get now (the effective mode below)".to_string(),
                "  [-  ] no wrapper: Cursor runs its bundled claude; [wrapper] mode \"passthrough\" applies after ai-env wrapper install --write".to_string(),
                "  [-  ] Cursor Claude extension not found under ~/.cursor/extensions".to_string(),
                format!("  [-  ] no census row names an extension yet ({})", home.census_path().display()),
                "  [-  ] no session in the census yet".to_string(),
            ],
        );
        assert!(!stdout.contains("[NO ]") && !stdout.contains("[!! ]"), "{settings:?}: {stdout}");
    }
}

/// The wrapper installed (the sibling, the permission key) and bridge.toml
/// in remote mode with two roots, one a `[[workspace]]`: the settings,
/// wrapper, sibling, version and bridge.toml rows are `[ok ]`, the effective
/// mode is remote, one row per root; exit 0.
#[test]
fn an_installed_sibling_in_remote_mode_shows_ok_rows() {
    let home = Home::new();
    let wrapper = sibling();
    let w = wrapper.to_str().unwrap();
    home.write_settings(&format!("{{\n  // Cursor keeps comments\n  {}: {},\n  {}: \"default\",\n}}\n", json_str(WRAPPER_SETTING), json_str(w), json_str(PERMISSION_SETTING)));
    let (a, b) = (home.path().join("work").join("a"), home.path().join("work").join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    home.write_bridge_toml(&format!("[wrapper]\nmode = \"remote\"\n\n[workspaces]\nroots = [{}]\n\n[[workspace]]\npath = {}\n{AWS}", json_str(&a.display().to_string()), json_str(&b.display().to_string())));
    let out = home.status(&[]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    let v = env!("CARGO_PKG_VERSION");
    assert_lines(
        &stdout,
        &[
            format!("  [ok ] Cursor settings {}", home.settings_path().display()),
            format!("  [ok ] {WRAPPER_SETTING} = {w}"),
            format!("  [ok ] {PERMISSION_SETTING} = default"),
            format!("  [ok ] ai-env-claude next to ai-env ({w})"),
            format!("  [ok ] same version {v}"),
            format!("  [ok ] bridge.toml {}", home.bridge_toml().display()),
            "  [ok ] wrapper mode remote: Cursor's chats under the 2 root(s) run in their workspace's MicroVM (AI_ENV_BRIDGE_LOCAL=1 runs them here)".to_string(),
            "  [ok ] effective mode remote ([wrapper] mode): Cursor's chats under the 2 root(s) run in their workspace's MicroVM, everything else on this Mac".to_string(),
            format!("  [ok ] workspace root {}", a.display()),
            format!("  [ok ] workspace root {}", b.display()),
            "  [ok ] bridge.toml passes the checks a remote session runs at its start".to_string(),
        ],
    );
    // The debug build's sibling lives under target/: doctor's warning, never a failure.
    assert_eq!(stdout.contains("[!! ] wrapper under a build directory"), under_target(), "{stdout}");
    assert!(!stdout.contains("[NO ]") && stderr.is_empty(), "{stdout}{stderr}");
}

/// S2: Cursor's kill switch, a mode it does not name and another bridge root
/// each print their row; a planted secret-looking variable never shows, by
/// name or by value, in the text or the JSON, and the mode's own
/// secret-looking value shows scrubbed only. Nothing goes to stderr: the
/// wrapper's line for a mode it does not name (`route::variable_over`) is not
/// status's.
#[test]
fn cursor_variables_print_their_rows_and_never_another_variable() {
    let home = Home::new();
    let secret_name = format!("{}_{}", "PLANTED", "API_KEY");
    let secret_value = format!("pv-{}", "q".repeat(40));
    let other_name = format!("{}_TOKEN", "GITHUB");
    let token = format!("{}oat01-{}", "sk-ant-", "Z".repeat(30));
    let elsewhere = home.path().join("elsewhere");
    let vars = serde_json::json!([
        {"name": secret_name, "value": secret_value},
        {"name": "AI_ENV_BRIDGE_LOCAL", "value": "1"},
        {"name": "AI_ENV_BRIDGE_MODE", "value": token},
        {"name": "AI_ENV_BRIDGE_DIR", "value": elsewhere},
        {"name": other_name, "value": token},
    ]);
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling(), ENV_SETTING: vars }).to_string());
    let plain = home.status(&[]);
    let json = home.status(&["--json"]);
    let stdout = text(&plain.stdout);
    assert_lines(
        &stdout,
        &[
            format!("  [!! ] AI_ENV_BRIDGE_LOCAL=1 in {ENV_SETTING}: every chat execs the bundled claude (no census, no bridge)"),
            format!("  [!! ] AI_ENV_BRIDGE_MODE=\"sk-ant-[redacted:len={}]\" in {ENV_SETTING} names no mode: ignored ([wrapper] mode decides)", token.len()),
            format!("  [!! ] AI_ENV_BRIDGE_DIR={:?} in {ENV_SETTING}: the wrapper reads that bridge root, this command {}: the rows below are this command's", elsewhere.display().to_string(), home.bridge_dir().display()),
            "  [-  ] effective mode: none, the kill switch (AI_ENV_BRIDGE_LOCAL=1) execs Cursor's bundled claude on this Mac for every chat".to_string(),
        ],
    );
    for (what, out) in [("text", &plain), ("--json", &json)] {
        assert_eq!(out.status.code(), Some(0), "{what}: {}", text(&out.stderr));
        assert!(out.stderr.is_empty(), "{what}: stderr {}", text(&out.stderr));
        let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
        for never in [&secret_name, &secret_value, &other_name, &token] {
            assert!(!all.contains(never.as_str()), "{what} shows {never}: {all}");
        }
    }
}

/// Settings that cannot be read leave the wrapper's rows unchecked (`[!! ]`,
/// exit 0): one that does not parse, one that is a directory. A wrapper key
/// naming a file that does not exist is doctor's `[NO ]`, exit 1, and the
/// mode Cursor's chats get is not judged.
#[test]
fn unreadable_settings_and_a_missing_wrapper() {
    let home = Home::new();
    let path = home.settings_path();
    home.write_settings(&format!("{{\n  {}: \n", json_str(WRAPPER_SETTING)));
    let out = home.status(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    let row = stdout.lines().find(|l| l.starts_with("  [!! ] Cursor settings.json unparseable (")).unwrap_or_else(|| panic!("no unparseable row: {stdout}"));
    assert!(row.ends_with(&format!("); wrapper rows not checked  <- {}", path.display())), "{row}");
    assert_lines(&stdout, &["  [-  ] effective mode not checked (Cursor's settings were not read)".to_string()]);
    assert!(!stdout.contains(&format!("{WRAPPER_SETTING} ")) && !stdout.contains(ENV_SETTING), "no wrapper or variable row: {stdout}");

    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let out = home.status(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    let row = stdout.lines().find(|l| l.starts_with("  [!! ] Cursor settings.json unreadable (")).unwrap_or_else(|| panic!("no unreadable row: {stdout}"));
    assert!(row.ends_with(&format!("); wrapper rows not checked  <- {}", path.display())), "{row}");

    std::fs::remove_dir(&path).unwrap();
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: "/nonexistent/ai-env-claude" }).to_string());
    let out = home.status(&[]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert_lines(
        &stdout,
        &[
            format!("  [NO ] {WRAPPER_SETTING} = /nonexistent/ai-env-claude does not exist"),
            "  [-  ] effective mode not checked: Cursor cannot start the wrapper its settings name (the wrapper row above)".to_string(),
        ],
    );
    assert_eq!(stderr, "ai-env: 1 problem(s) found\n");
}

/// A bridge.toml that does not load: `[NO ]` rows and exit 1 with doctor's
/// error line; the error's first line only (the rest quotes the file).
#[test]
fn a_broken_bridge_toml_is_a_no_row_and_exit_1() {
    let home = Home::new();
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling() }).to_string());
    home.write_bridge_toml("[wrapper]\nmode = \"remote\"\n\n[workspaces]\nroots = [\"/nonexistent-root\"]\n\n[vm]\nmax_idle_typo = 300\n");
    let out = home.status(&[]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    let error = stdout.lines().find(|l| l.starts_with("  [NO ] bridge.toml: ")).unwrap_or_else(|| panic!("no bridge.toml row: {stdout}"));
    assert!(error.contains("TOML parse error at line 8"), "{error}");
    assert!(!stdout.contains("max_idle_typo"), "the error's snippet is never printed: {stdout}");
    assert_lines(
        &stdout,
        &[
            "  [!! ] effective mode remote ([wrapper] mode), failing closed: every Cursor chat under the roots exits 1 (the rows above)".to_string(),
            "  [!! ] workspace root /nonexistent-root is no directory: no chat runs under it".to_string(),
        ],
    );
    let problems = stdout.lines().filter(|l| l.starts_with("  [NO ] ")).count();
    assert_eq!(problems, 2, "the file and the mode it fails closed in: {stdout}");
    assert_eq!(stderr, format!("ai-env: {problems} problem(s) found\n"));

    // Roots it cannot read (the [workspaces] table itself is broken): every chat would exit 1, which is a
    // problem while the wrapper routes Cursor's chats, and what comes once it does while it does not.
    home.write_bridge_toml("[wrapper]\nmode = \"remote\"\n\n[workspaces]\nroots = [\"/nonexistent-root\"]\nroots_typo = 1\n");
    let unreadable = "workspace roots unreadable (bridge.toml does not load)";
    let fix = "<- fix bridge.toml (the bridge.toml row above)";
    let out = home.status(&[]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert_lines(&stdout, &[format!("  [NO ] {unreadable}: in remote mode every Cursor chat counts as under them and exits 1  {fix}")]);
    assert_eq!(stderr, "ai-env: 3 problem(s) found\n", "the file, its mode and its roots: {stdout}");
    for settings in [serde_json::json!({ PERMISSION_SETTING: "default" }), serde_json::json!({ WRAPPER_SETTING: sibling(), ENV_SETTING: {"AI_ENV_BRIDGE_LOCAL": "1"} })] {
        home.write_settings(&settings.to_string());
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(1), "{settings}: {stdout}{stderr}");
        assert_lines(&stdout, &[format!("  [!! ] {unreadable}: once the wrapper routes Cursor's chats, in remote mode every one counts as under them and exits 1  {fix}")]);
        assert_eq!(stderr, "ai-env: 2 problem(s) found\n", "{settings}: the file and its mode: {stdout}");
    }
}

/// The census tail, with the wrapper installed: the newest spawn that names
/// an extension against the newest installed (2.1.299 is obsolete), and the
/// newest session; a row before the tail's window is never read, so a
/// census whose only such rows lie there names none. An old session's end
/// row that lands after a newer spawn hides nothing. With the wrapper
/// uninstalled, or the kill switch on, the census stops at the last spawn
/// the wrapper routed: its rows are `[-  ]`, with no reload hint.
#[test]
fn the_census_tail_finds_the_newest_extension_and_reads_no_further() {
    let home = Home::new();
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling() }).to_string());
    home.install_extensions(&["2.1.296", "2.1.299", "2.1.300"], &["2.1.299"]);
    let pad = census_row("2026-10-02T08:00:00Z", "local", "version", None, Some("x".repeat(30 * 1024).as_str()));
    let window = CENSUS_TAIL_CHUNKS * MAX_ROW_BYTES;
    let mut rows = vec![census_row("2026-10-01T08:00:00Z", "remote", "session", Some("2.1.1"), Some("mode:remote(config)"))];
    rows.extend(std::iter::repeat_n(pad, window / (30 * 1024) + 1));
    home.seed_census(&rows);
    assert!(std::fs::metadata(home.census_path()).unwrap().len() > window as u64 + 1, "the first row lies before the window");
    let stdout = text(&home.status(&[]).stdout);
    assert_lines(&stdout, &[format!("  [-  ] no census row names an extension yet ({})", home.census_path().display()), "  [-  ] no session in the census yet".to_string()]);

    let old_session = census_row("2026-10-11T08:00:00Z", "remote", "session", Some("2.1.296"), Some("mode:remote(config)"));
    home.seed_census(&[
        old_session.clone(),
        census_row("2026-10-12T08:00:00Z", "remote", "session", Some("2.1.296"), None),
        census_row("2026-10-13T08:00:00Z", "local", "subcommand:auth", Some("2.1.299"), Some("mode:remote(config)")),
        census_row("2026-10-14T08:00:00Z", "local", "version", None, None),
    ]);
    let stdout = text(&home.status(&[]).stdout);
    assert_lines(
        &stdout,
        &[
            "  [ok ] cursor extension 2.1.300 (2 versions installed)".to_string(),
            // No bridge.toml: passthrough, so the restarted chats stay here.
            "  [!! ] Cursor last ran extension 2.1.299 (2026-10-13T08:00:00Z); 2.1.300 is installed  <- a window reload picks it up (it restarts open chats on this Mac)".to_string(),
            "  [ok ] Cursor's newest session (2026-10-12T08:00:00Z) ran on this Mac".to_string(),
        ],
    );
    assert!(!stdout.contains("bundled claude"), "status never asks the bundled claude: {stdout}");
    // A reloaded window's chat starts on 2.1.300; then the 11 Oct session ends, its end row last in the file.
    home.seed_census(&[census_row("2026-10-15T08:00:00Z", "remote", "session", Some("2.1.300"), Some("prewarm:skipped(none); mode:remote(config)")), end_row(&old_session)]);
    let newest = [
        "Cursor last ran extension 2.1.300 (2026-10-15T08:00:00Z)",
        "Cursor's newest session (2026-10-15T08:00:00Z) went to its workspace's MicroVM (mode:remote(config))",
    ];
    let stdout = text(&home.status(&[]).stdout);
    assert_lines(&stdout, &newest.map(|r| format!("  [ok ] {r}")));

    // Uninstalled, then the kill switch: what Cursor runs leaves no census row.
    let stale = "what Cursor runs now leaves no census row (the rows above)";
    for settings in [serde_json::json!({ PERMISSION_SETTING: "default" }), serde_json::json!({ WRAPPER_SETTING: sibling(), ENV_SETTING: [{"name": "AI_ENV_BRIDGE_LOCAL", "value": "1"}] })] {
        home.write_settings(&settings.to_string());
        let stdout = text(&home.status(&[]).stdout);
        assert_lines(
            &stdout,
            &[
                format!("  [-  ] the newest census row names extension 2.1.300 (2026-10-15T08:00:00Z); {stale}"),
                format!("  [-  ] the newest session in the census (2026-10-15T08:00:00Z) went to its workspace's MicroVM (mode:remote(config)); {stale}"),
            ],
        );
        assert!(!stdout.contains("Cursor last ran") && !stdout.contains("Cursor's newest session"), "{settings}: {stdout}");
    }
    // Not even a stale reload hint: the window may have reloaded on 2.1.300 since.
    home.write_settings(&serde_json::json!({ PERMISSION_SETTING: "default" }).to_string());
    home.seed_census(&[census_row("2026-10-15T09:00:00Z", "local", "subcommand:auth", Some("2.1.296"), None)]);
    let stdout = text(&home.status(&[]).stdout);
    assert_lines(&stdout, &[format!("  [-  ] the newest census row names extension 2.1.296 (2026-10-15T09:00:00Z); {stale}")]);
    assert!(!stdout.contains("window reload"), "{stdout}");
}

/// The extension row's reload hint says where the chats a reload restarts
/// go: in remote mode through the wrapper, those under the roots to their
/// MicroVM, with the README's way to keep one here; while remote mode fails
/// closed (a mode bridge.toml does not name, even under Cursor's
/// `AI_ENV_BRIDGE_MODE=remote`; no `[aws]`), to an exit at their start; with
/// Cursor's `AI_ENV_BRIDGE_MODE=passthrough` over the same bridge.toml, on
/// this Mac.
#[test]
fn the_reload_hint_says_where_the_restarted_chats_go() {
    let home = Home::new();
    let root = home.path().join("work");
    std::fs::create_dir_all(&root).unwrap();
    let roots = format!("\n[workspaces]\nroots = [{}]\n", json_str(&root.display().to_string()));
    home.install_extensions(&["2.1.296", "2.1.300"], &["2.1.296"]);
    home.seed_census(&[census_row("2026-10-15T10:00:00Z", "remote", "session", Some("2.1.296"), Some("mode:remote(config)"))]);
    let stale = "  [!! ] Cursor last ran extension 2.1.296 (2026-10-15T10:00:00Z); 2.1.300 is installed  <- a window reload picks it up";
    let (remote, typo) = (format!("[wrapper]\nmode = \"remote\"\n{roots}"), format!("[wrapper]\nmode = \"remotely\"\n{roots}"));
    let exits = ", and restarts every open chat through the wrapper: those under the roots exit at their start until bridge.toml is fixed (the rows above)";
    for (toml, vars, hint, code) in [
        (format!("{remote}{AWS}"), serde_json::json!([]), ", and restarts every open chat through the wrapper: those under the roots go to their MicroVM (to keep one on this Mac: the README's \"No wrapper at all\")", 0),
        (format!("{remote}{AWS}"), serde_json::json!([{"name": "AI_ENV_BRIDGE_MODE", "value": "passthrough"}]), " (it restarts open chats on this Mac)", 0),
        // Failing closed: the session's start refuses them, so a reload sends no chat under the roots to a MicroVM.
        (remote.clone(), serde_json::json!([]), exits, 1),
        (format!("{typo}{AWS}"), serde_json::json!([]), exits, 1),
        (format!("{typo}{AWS}"), serde_json::json!([{"name": "AI_ENV_BRIDGE_MODE", "value": "remote"}]), exits, 1),
    ] {
        home.write_bridge_toml(&toml);
        home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling(), ENV_SETTING: vars }).to_string());
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(code), "{toml:?} {vars}: {stdout}{stderr}");
        assert_lines(&stdout, &[format!("{stale}{hint}")]);
    }
}

/// One cause, one problem: a `[wrapper] mode` the wrapper does not know
/// ends every remote session at its start whatever Cursor's
/// `AI_ENV_BRIDGE_MODE` says (the session's start refuses the key), so with
/// `AI_ENV_BRIDGE_MODE=remote` over it the effective mode fails closed too.
/// Doctor's mode row carries the one `[NO ]`; the checks row points at it,
/// `[!! ]`. With no wrapper, the mode row is still `[NO ]`, what install
/// brings back is said to fail closed, and the checks row still points at
/// the mode row, saying it applies once the wrapper routes the chats.
#[test]
fn a_mode_bridge_toml_does_not_name_fails_closed_under_any_variable() {
    let home = Home::new();
    let root = home.path().join("work");
    std::fs::create_dir_all(&root).unwrap();
    home.write_bridge_toml(&format!("[wrapper]\nmode = \"remotely\"\n\n[workspaces]\nroots = [{}]\n{AWS}", json_str(&root.display().to_string())));
    let doctors = "  [NO ] config: [wrapper].mode = \"remotely\": must be \"passthrough\" or \"remote\": every Cursor chat under the roots fails closed  <- ai-env wrapper install --write --mode remote (or passthrough)";
    let pointer = "  [!! ] a remote session would exit 1 at its start: [wrapper] mode (the [NO ] row above)";
    for (vars, source) in [(serde_json::json!([]), "[wrapper] mode".to_string()), (serde_json::json!([{"name": "AI_ENV_BRIDGE_MODE", "value": "remote"}]), format!("AI_ENV_BRIDGE_MODE in {ENV_SETTING}"))] {
        home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling(), ENV_SETTING: vars }).to_string());
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(1), "{vars}: {stdout}{stderr}");
        assert_lines(&stdout, &[doctors.to_string(), format!("  [!! ] effective mode remote ({source}), failing closed: every Cursor chat under the roots exits 1 (the rows above)"), pointer.to_string()]);
        assert_eq!(stderr, "ai-env: 1 problem(s) found\n", "{vars}: one cause, one [NO ]: {stdout}");
    }
    // No wrapper (as after uninstall --write): the file is still wrong, and install brings back failing closed.
    home.write_settings(&serde_json::json!({ PERMISSION_SETTING: "default", ENV_SETTING: [{"name": "AI_ENV_BRIDGE_MODE", "value": "remote"}] }).to_string());
    let out = home.status(&[]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert_lines(
        &stdout,
        &[
            "  [NO ] bridge.toml [wrapper] mode \"remotely\" (1 root), which names no mode: not what Cursor's chats get now (the effective mode below)  <- set [wrapper] mode to \"passthrough\" or \"remote\" in bridge.toml".to_string(),
            "  [-  ] no wrapper: Cursor runs its bundled claude; remote mode failing closed (the rows above) applies after ai-env wrapper install --write".to_string(),
            "  [!! ] a remote session would exit 1 at its start once the wrapper routes Cursor's chats again: [wrapper] mode (the [NO ] row above)".to_string(),
        ],
    );
    assert_eq!(stderr, "ai-env: 1 problem(s) found\n", "one cause, one [NO ]: {stdout}");
}

/// bridge.toml's mode row says what Cursor's chats do in that mode only while
/// the wrapper routes them and Cursor's `AI_ENV_BRIDGE_MODE` names no other
/// mode: with no wrapper, the kill switch or `AI_ENV_BRIDGE_MODE=passthrough`
/// it describes the file alone, `[-  ]`, right above the effective mode's
/// row, which says what the chats get; the checks of a remote session's start
/// show whenever the mode the wrapper takes is remote. Remote without a root
/// stays doctor's `[!! ]` with its fix, the file alone or not.
#[test]
fn the_mode_row_describes_bridge_toml_alone_unless_the_wrapper_routes_in_its_mode() {
    let home = Home::new();
    let root = home.path().join("work");
    std::fs::create_dir_all(&root).unwrap();
    home.write_bridge_toml(&format!("[wrapper]\nmode = \"remote\"\n\n[workspaces]\nroots = [{}]\n{AWS}", json_str(&root.display().to_string())));
    let doctors = "  [ok ] wrapper mode remote: Cursor's chats under the 1 root(s) run in their workspace's MicroVM (AI_ENV_BRIDGE_LOCAL=1 runs them here)";
    let file_only = "  [-  ] bridge.toml [wrapper] mode \"remote\" (1 root): not what Cursor's chats get now (the effective mode below)";
    let remote = "Cursor's chats under the 1 root(s) run in their workspace's MicroVM, everything else on this Mac";
    let checks = "  [ok ] bridge.toml passes the checks a remote session runs at its start";
    let (wrapper, kill) = (sibling(), serde_json::json!([{"name": "AI_ENV_BRIDGE_LOCAL", "value": "1"}]));
    for (settings, mode_row, effective, checked) in [
        // The wrapper routes in the file's mode: doctor's row holds.
        (serde_json::json!({ WRAPPER_SETTING: wrapper }), doctors, format!("  [ok ] effective mode remote ([wrapper] mode): {remote}"), true),
        (serde_json::json!({ WRAPPER_SETTING: wrapper, ENV_SETTING: {"AI_ENV_BRIDGE_MODE": "remote"} }), doctors, format!("  [ok ] effective mode remote (AI_ENV_BRIDGE_MODE in {ENV_SETTING}): {remote}"), true),
        // No wrapper, the kill switch, another mode named: the file alone; the checks still while the wrapper's mode is remote.
        (serde_json::json!({ PERMISSION_SETTING: "default" }), file_only, "  [-  ] no wrapper: Cursor runs its bundled claude; [wrapper] mode \"remote\" applies after ai-env wrapper install --write".to_string(), true),
        (serde_json::json!({ WRAPPER_SETTING: wrapper, ENV_SETTING: kill }), file_only, "  [-  ] effective mode: none, the kill switch (AI_ENV_BRIDGE_LOCAL=1) execs Cursor's bundled claude on this Mac for every chat".to_string(), true),
        (
            serde_json::json!({ WRAPPER_SETTING: wrapper, ENV_SETTING: {"AI_ENV_BRIDGE_MODE": "passthrough"} }),
            file_only,
            format!("  [ok ] effective mode passthrough (AI_ENV_BRIDGE_MODE in {ENV_SETTING}): Cursor's chats run on this Mac, each through ai-env-claude with a census row"),
            false,
        ),
    ] {
        home.write_settings(&settings.to_string());
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{settings}: {stdout}{stderr}");
        assert!(stderr.is_empty(), "{settings}: {stderr}");
        let lines: Vec<&str> = stdout.lines().collect();
        let at = lines.iter().position(|l| *l == mode_row).unwrap_or_else(|| panic!("{settings}: no {mode_row:?} in:\n{stdout}"));
        assert_eq!(lines.get(at + 1).copied(), Some(effective.as_str()), "{settings}: the effective mode's row next:\n{stdout}");
        assert_eq!(lines.iter().filter(|l| l.contains("wrapper mode remote") || l.contains("[wrapper] mode \"remote\" (")).count(), 1, "{settings}: one mode row:\n{stdout}");
        assert_eq!(stdout.contains(checks), checked, "{settings}: the checks whenever the wrapper's mode is remote:\n{stdout}");
    }
    // Remote without a root: doctor's [!! ] while the wrapper routes chats in it, else the file alone, still [!! ].
    home.write_bridge_toml(&format!("[wrapper]\nmode = \"remote\"\n{AWS}"));
    let doctors = "  [!! ] wrapper mode remote, but no [workspaces].roots: every Cursor chat runs on this Mac  <- add the roots to bridge.toml".to_string();
    let file_only = "  [!! ] bridge.toml [wrapper] mode \"remote\" (no root): not what Cursor's chats get now (the effective mode below); remote without a root runs every chat on this Mac  <- add the roots to bridge.toml".to_string();
    for (settings, mode_row) in [
        (serde_json::json!({ WRAPPER_SETTING: wrapper }), &doctors),
        (serde_json::json!({ PERMISSION_SETTING: "default" }), &file_only),
        (serde_json::json!({ WRAPPER_SETTING: wrapper, ENV_SETTING: kill }), &file_only),
        (serde_json::json!({ WRAPPER_SETTING: wrapper, ENV_SETTING: {"AI_ENV_BRIDGE_MODE": "passthrough"} }), &file_only),
    ] {
        home.write_settings(&settings.to_string());
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{settings}: {stdout}{stderr}");
        assert_lines(&stdout, std::slice::from_ref(mode_row));
    }
}

/// Remote mode with the wrapper routing Cursor's chats: bridge.toml passes
/// the checks a remote session runs at its start, `[ok ]`; or it loads, its
/// mode row is `[ok ]`, and still every remote session would end at P0
/// (`[seed]`, `[vm]`, no `[aws].image_arn`, no egress connector, a name the
/// session's environment may not hold): `[NO ]` with the exit code and the
/// first failing check's line, the effective mode failing closed, exit 1.
#[test]
fn the_checks_of_a_remote_sessions_start_are_a_row() {
    let home = Home::new();
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling() }).to_string());
    let root = home.path().join("work");
    std::fs::create_dir_all(&root).unwrap();
    let base = format!("[wrapper]\nmode = \"remote\"\n\n[workspaces]\nroots = [{}]\n", json_str(&root.display().to_string()));
    home.write_bridge_toml(&format!("{base}{AWS}"));
    let out = home.status(&[]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert_lines(&stdout, &["  [ok ] bridge.toml passes the checks a remote session runs at its start".to_string()]);
    let image = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env";
    for (extra, code, first) in [
        (format!("{AWS}\n[seed]\nmax_mib = 32\n"), 1, "config: [seed].wrapper_inline_mib: 64 is more than [seed].max_mib (32)".to_string()),
        (format!("{AWS}\n[vm]\nmax_idle_s = 10\n"), 1, "config: [vm].max_idle_s: must be 300..=28800 (plan §2.8: suspending sooner costs more than it saves)".to_string()),
        (String::new(), 1, "config: [aws].image_arn is not set in bridge.toml and no --image was given (run `make infra-status WRITE=1`)".to_string()),
        (
            format!("\n[aws]\nimage_arn = \"{image}\"\n"),
            9,
            "egress connector required (vpc egress asked for, or [egress].require=true) and none configured: make infra-status WRITE=1 writes [aws].egress_connector_arn".to_string(),
        ),
        (
            format!("{AWS}\n[creds]\nmode = \"reverse-refresh\"\n"),
            1,
            "refused: [creds].mode \"reverse-refresh\" (Tier B) is not built: use \"setup-token\"".to_string(),
        ),
    ] {
        home.write_bridge_toml(&format!("{base}{extra}"));
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(1), "{extra:?}: {stdout}{stderr}");
        assert_lines(
            &stdout,
            &[
                format!("  [ok ] bridge.toml {}", home.bridge_toml().display()),
                "  [ok ] wrapper mode remote: Cursor's chats under the 1 root(s) run in their workspace's MicroVM (AI_ENV_BRIDGE_LOCAL=1 runs them here)".to_string(),
                format!("  [!! ] effective mode remote ([wrapper] mode), failing closed: every Cursor chat under the roots exits {code} (the checks row below)"),
                format!("  [NO ] a remote session would exit {code} at its start: {first}  <- fix bridge.toml"),
            ],
        );
        assert_eq!(stderr, "ai-env: 1 problem(s) found\n", "{extra:?}: {stdout}");
    }
    // A name the session's environment may not hold: P0's refusal, exit 9.
    home.write_bridge_toml(&format!("[wrapper]\nmode = \"remote\"\nenv_extra = [\"NODE_OPTIONS\"]\n\n[workspaces]\nroots = [{}]\n{AWS}", json_str(&root.display().to_string())));
    let out = home.status(&[]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert_lines(&stdout, &["  [NO ] a remote session would exit 9 at its start: [wrapper].env_extra names NODE_OPTIONS: it changes how claude and node start in the VM; remove it from bridge.toml  <- fix bridge.toml".to_string()]);
    assert_eq!(stderr, "ai-env: 1 problem(s) found\n");
}

/// The checks of a remote session's start show whenever one can start once
/// the wrapper routes Cursor's chats again (bridge.toml loads, the mode the
/// wrapper takes is remote, a root): with no wrapper, the kill switch, both,
/// or a wrapper Cursor cannot start, the row says so. A failure is `[NO ]`
/// in every case (exit 1, as with the wrapper), the no-wrapper effective
/// mode's row pointing at it; a bridge.toml that passes them is `[ok ]`.
#[test]
fn the_checks_row_shows_while_the_wrapper_does_not_route_chats() {
    let home = Home::new();
    let root = home.path().join("work");
    std::fs::create_dir_all(&root).unwrap();
    let base = format!("[wrapper]\nmode = \"remote\"\n\n[workspaces]\nroots = [{}]\n{AWS}", json_str(&root.display().to_string()));
    let kill = serde_json::json!([{"name": "AI_ENV_BRIDGE_LOCAL", "value": "1"}]);
    let failing = "  [NO ] a remote session would exit 1 at its start once the wrapper routes Cursor's chats again: config: [seed].wrapper_inline_mib: 64 is more than [seed].max_mib (32)  <- fix bridge.toml";
    let passes = "  [ok ] bridge.toml passes the checks a remote session runs at its start";
    // (Cursor's settings, the effective mode's row over the failing [seed], the other problems)
    for (settings, effective, others) in [
        (serde_json::json!({ PERMISSION_SETTING: "default" }), "  [-  ] no wrapper: Cursor runs its bundled claude; remote mode failing closed (the checks row below) applies after ai-env wrapper install --write", 0),
        (serde_json::json!({ WRAPPER_SETTING: sibling(), ENV_SETTING: kill }), "  [-  ] effective mode: none, the kill switch (AI_ENV_BRIDGE_LOCAL=1) execs Cursor's bundled claude on this Mac for every chat", 0),
        (
            serde_json::json!({ PERMISSION_SETTING: "default", ENV_SETTING: kill }),
            "  [-  ] no wrapper: Cursor runs its bundled claude, and after ai-env wrapper install --write the kill switch (AI_ENV_BRIDGE_LOCAL=1) still execs it on this Mac for every chat",
            0,
        ),
        // The wrapper row's own [NO ] besides.
        (serde_json::json!({ WRAPPER_SETTING: "/nonexistent/ai-env-claude" }), "  [-  ] effective mode not checked: Cursor cannot start the wrapper its settings name (the wrapper row above)", 1),
    ] {
        home.write_settings(&settings.to_string());
        home.write_bridge_toml(&format!("{base}\n[seed]\nmax_mib = 32\n"));
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(1), "{settings}: {stdout}{stderr}");
        assert_lines(&stdout, &[effective.to_string(), failing.to_string()]);
        assert_eq!(stderr, format!("ai-env: {} problem(s) found\n", others + 1), "{settings}: {stdout}");
        home.write_bridge_toml(&base);
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(i32::from(others > 0)), "{settings}: {stdout}{stderr}");
        assert_lines(&stdout, &[passes.to_string()]);
        assert!(!stdout.contains("a remote session would exit"), "{settings}: {stdout}");
    }
}

/// Remote mode with no root: the wrapper routes no session remote, so
/// nothing fails at a session's start, whatever bridge.toml lacks (here
/// `[aws]`): no checks row, the effective mode's row says every chat runs
/// here and the reload hint keeps the chats it restarts on this Mac, exit 0
/// (doctor's `[!! ]` names the fix); with no wrapper, the mode that applies
/// after install says the same. A `[wrapper] mode` the wrapper does not
/// know (under Cursor's `AI_ENV_BRIDGE_MODE=remote` too) or a bridge.toml
/// that does not load stays a problem of the file, `[NO ]`, its mode row
/// saying every chat runs here until bridge.toml names a root: no row has
/// a chat fail closed.
#[test]
fn remote_without_a_root_fails_nothing_closed() {
    let home = Home::new();
    home.install_extensions(&["2.1.296", "2.1.300"], &["2.1.296"]);
    home.seed_census(&[census_row("2026-10-14T08:05:00Z", "remote", "session", Some("2.1.296"), Some("mode:remote(config)"))]);
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling() }).to_string());
    home.write_bridge_toml("[wrapper]\nmode = \"remote\"\n");
    let here = "  [!! ] Cursor last ran extension 2.1.296 (2026-10-14T08:05:00Z); 2.1.300 is installed  <- a window reload picks it up (it restarts open chats on this Mac)";
    // What any row would say of a chat ending at its start.
    let closed = |stdout: &str| ["a remote session would exit", "failing closed", "fails closed", "exits 1 naming", "go to their MicroVM"].into_iter().filter(|c| stdout.contains(c)).collect::<Vec<_>>();
    let plain = home.status(&[]);
    let stdout = text(&plain.stdout);
    assert_lines(
        &stdout,
        &[
            "  [!! ] wrapper mode remote, but no [workspaces].roots: every Cursor chat runs on this Mac  <- add the roots to bridge.toml".to_string(),
            "  [ok ] effective mode remote ([wrapper] mode), but no root: every Cursor chat runs on this Mac".to_string(),
            "  [-  ] no workspace root ([workspaces].roots, [[workspace]].path)".to_string(),
            here.to_string(),
        ],
    );
    assert!(closed(&stdout).is_empty() && !stdout.contains("passes the checks"), "{stdout}");
    for (what, out) in [("text", plain), ("--json", home.status(&["--json"]))] {
        assert_eq!(out.status.code(), Some(0), "{what}: {}{}", text(&out.stdout), text(&out.stderr));
        assert!(out.stderr.is_empty(), "{what}: {}", text(&out.stderr));
    }
    // No wrapper: nothing to check once it is back either.
    home.write_settings(&serde_json::json!({ PERMISSION_SETTING: "default" }).to_string());
    let out = home.status(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert_lines(&stdout, &["  [-  ] no wrapper: Cursor runs its bundled claude; remote mode with no root (every chat on this Mac) applies after ai-env wrapper install --write".to_string()]);
    assert!(closed(&stdout).is_empty() && !stdout.contains("passes the checks"), "{stdout}");
    // A mode it does not know, alone or under Cursor's AI_ENV_BRIDGE_MODE=remote: the mode row's one [NO ], every chat here.
    home.write_bridge_toml("[wrapper]\nmode = \"remotely\"\n");
    let until = "every Cursor chat runs on this Mac until bridge.toml names a root, then every chat under it exits 1 at its start";
    for (vars, source) in [(serde_json::json!([]), "[wrapper] mode".to_string()), (serde_json::json!([{"name": "AI_ENV_BRIDGE_MODE", "value": "remote"}]), format!("AI_ENV_BRIDGE_MODE in {ENV_SETTING}"))] {
        home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling(), ENV_SETTING: vars }).to_string());
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(1), "{vars}: {stdout}{stderr}");
        assert_lines(
            &stdout,
            &[
                format!("  [NO ] bridge.toml [wrapper] mode \"remotely\" (no root), which names no mode: {until}  <- ai-env wrapper install --write --mode remote (or passthrough)"),
                format!("  [ok ] effective mode remote ({source}), but no root: every Cursor chat runs on this Mac"),
                here.to_string(),
            ],
        );
        assert!(closed(&stdout).is_empty(), "{vars}: {:?} in {stdout}", closed(&stdout));
        assert_eq!(stderr, "ai-env: 1 problem(s) found\n", "{vars}: {stdout}");
    }
    // A remote bridge.toml that does not load (or whose mode it cannot read), its roots read and none: the
    // file's [NO ] rows, its mode row saying the chats run on this Mac.
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling() }).to_string());
    for (toml, mode) in [("[wrapper]\nmode = \"remote\"\n[vm]\nnope = 1\n", "\"remote\""), ("[wrapper]\nmode = 1\n", "unreadable")] {
        home.write_bridge_toml(toml);
        let out = home.status(&[]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(1), "{toml:?}: {stdout}{stderr}");
        assert_lines(
            &stdout,
            &[
                format!("  [NO ] bridge.toml, which does not load, [wrapper] mode {mode} (no root): {until}  <- fix bridge.toml (the bridge.toml row above)"),
                "  [ok ] effective mode remote ([wrapper] mode), but no root: every Cursor chat runs on this Mac".to_string(),
                "  [-  ] no workspace root ([workspaces].roots, [[workspace]].path)".to_string(),
                here.to_string(),
            ],
        );
        assert!(closed(&stdout).is_empty(), "{toml:?}: {:?} in {stdout}", closed(&stdout));
        assert_eq!(stderr, "ai-env: 2 problem(s) found\n", "{toml:?}: the file and its mode: {stdout}");
    }
}

/// Right after the wrapper comes back (the runbook's `install --write`),
/// the census's newest rows predate the last change of Cursor's
/// settings.json: a window reloaded while there was no wrapper ran an
/// extension the census never saw. So neither the extension Cursor last ran
/// nor its newest session is claimed, and no reload is advised; any change
/// of the file counts, read to the millisecond (rounded up) and shown so. A
/// row from after the change is Cursor's again, the extension's and the
/// session's each by its own row.
#[test]
fn census_rows_from_before_the_last_settings_change_claim_nothing() {
    let home = Home::new();
    let root = home.path().join("work");
    std::fs::create_dir_all(&root).unwrap();
    home.write_bridge_toml(&format!("[wrapper]\nmode = \"remote\"\n\n[workspaces]\nroots = [{}]\n{AWS}", json_str(&root.display().to_string())));
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling() }).to_string());
    home.install_extensions(&["2.1.296", "2.1.300"], &["2.1.296"]);
    home.seed_census(&[census_row("2026-10-14T08:05:00Z", "remote", "session", Some("2.1.296"), Some("mode:remote(config)"))]);
    // Older than the census row: today's rows, the reload hint included.
    let stdout = text(&home.status(&[]).stdout);
    assert_lines(
        &stdout,
        &[
            "  [!! ] Cursor last ran extension 2.1.296 (2026-10-14T08:05:00Z); 2.1.300 is installed  <- a window reload picks it up, and restarts every open chat through the wrapper: those under the roots go to their MicroVM (to keep one on this Mac: the README's \"No wrapper at all\")".to_string(),
            "  [ok ] Cursor's newest session (2026-10-14T08:05:00Z) went to its workspace's MicroVM (mode:remote(config))".to_string(),
        ],
    );
    // Newer than it: no claim, no hint.
    home.date_settings("2026-10-15T09:00:00Z");
    let since = "and predates the last change of Cursor's settings.json (2026-10-15T09:00:00Z): what Cursor has run since is unknown until it starts a";
    let ext_unknown = format!("  [-  ] the newest census row names extension 2.1.296 (2026-10-14T08:05:00Z) {since} process through the wrapper");
    let session_unknown = format!("  [-  ] the newest session in the census (2026-10-14T08:05:00Z) went to its workspace's MicroVM (mode:remote(config)) {since} session through the wrapper");
    let out = home.status(&[]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert_lines(&stdout, &[ext_unknown, session_unknown.clone()]);
    assert!(!stdout.contains("window reload") && !stdout.contains("Cursor last ran") && !stdout.contains("Cursor's newest session"), "{stdout}");
    // The row's own millisecond is no later change; half a millisecond after it is one, shown to the
    // millisecond (read rounded up), never as the row's own second.
    let start_ns = ai_env_cli::wire::time::parse_rfc3339_utc("2026-10-14T08:05:00Z").unwrap() * 1_000_000_000;
    home.date_settings_ns(start_ns);
    assert_lines(&text(&home.status(&[]).stdout), &["  [ok ] Cursor's newest session (2026-10-14T08:05:00Z) went to its workspace's MicroVM (mode:remote(config))".to_string()]);
    home.date_settings_ns(start_ns + 500_000);
    let stdout = text(&home.status(&[]).stdout);
    assert_lines(&stdout, &["  [-  ] the newest census row names extension 2.1.296 (2026-10-14T08:05:00Z) and predates the last change of Cursor's settings.json (2026-10-14T08:05:00.001Z): what Cursor has run since is unknown until it starts a process through the wrapper".to_string()]);
    home.date_settings("2026-10-15T09:00:00Z");
    // What Cursor starts about 1.5 s after the setting returns: its auth status first (the extension is known
    // again, the session not yet), then its config probe, a session.
    home.seed_census(&[census_row("2026-10-15T09:00:01Z", "local", "subcommand:auth", Some("2.1.300"), Some("mode:remote(config)"))]);
    let stdout = text(&home.status(&[]).stdout);
    assert_lines(&stdout, &["  [ok ] Cursor last ran extension 2.1.300 (2026-10-15T09:00:01Z)".to_string(), session_unknown]);
    home.seed_census(&[census_row("2026-10-15T09:00:02Z", "remote", "session", Some("2.1.300"), Some("prewarm:skipped(none); mode:remote(config)"))]);
    let stdout = text(&home.status(&[]).stdout);
    assert_lines(
        &stdout,
        &[
            "  [ok ] Cursor last ran extension 2.1.300 (2026-10-15T09:00:02Z)".to_string(),
            "  [ok ] Cursor's newest session (2026-10-15T09:00:02Z) went to its workspace's MicroVM (mode:remote(config))".to_string(),
        ],
    );
}

/// A `[wrapper] mode` that looks like a token (built at run time) never
/// shows raw, in the text or the JSON, the wrapper set or not, the file
/// loading or not, a root or none: doctor's mode row, kept while the
/// wrapper routes chats in the file's mode, prints it scrubbed, as the
/// file-alone row and the no-root row do.
#[test]
fn a_secret_looking_mode_is_never_printed_raw() {
    let home = Home::new();
    let root = home.path().join("work");
    std::fs::create_dir_all(&root).unwrap();
    let roots = format!("\n[workspaces]\nroots = [{}]\n", json_str(&root.display().to_string()));
    let token = format!("{}oat01-{}", "sk-ant-", "Q".repeat(40));
    let masked = format!("\"sk-ant-[redacted:len={}]\"", token.len());
    let not_now = "not what Cursor's chats get now (the effective mode below)";
    // (bridge.toml, its mode row with the wrapper set, with no wrapper)
    for (toml, routed, alone) in [
        (
            format!("[wrapper]\nmode = \"{token}\"\n{roots}{AWS}"),
            format!("  [NO ] config: [wrapper].mode = {masked}: must be \"passthrough\" or \"remote\": every Cursor chat under the roots fails closed  <- ai-env wrapper install --write --mode remote (or passthrough)"),
            format!("  [NO ] bridge.toml [wrapper] mode {masked} (1 root), which names no mode: {not_now}  <- set [wrapper] mode to \"passthrough\" or \"remote\" in bridge.toml"),
        ),
        (
            format!("[wrapper]\nmode = \"{token}\"\n[vm]\nnope = 1\n{roots}"),
            "  [NO ] wrapper mode remote, but bridge.toml does not load: every Cursor chat under its roots (every chat, when the roots cannot be read) exits 1 naming the error  <- fix bridge.toml (the bridge.toml row above)".to_string(),
            format!("  [NO ] bridge.toml, which does not load, [wrapper] mode {masked} (1 root): {not_now}  <- fix bridge.toml (the bridge.toml row above)"),
        ),
        // No root: the row that says every chat runs here, status's own.
        (
            format!("[wrapper]\nmode = \"{token}\"\n"),
            format!("  [NO ] bridge.toml [wrapper] mode {masked} (no root), which names no mode: every Cursor chat runs on this Mac until bridge.toml names a root, then every chat under it exits 1 at its start  <- ai-env wrapper install --write --mode remote (or passthrough)"),
            format!("  [NO ] bridge.toml [wrapper] mode {masked} (no root), which names no mode: {not_now}  <- set [wrapper] mode to \"passthrough\" or \"remote\" in bridge.toml"),
        ),
    ] {
        home.write_bridge_toml(&toml);
        for (settings, row) in [(serde_json::json!({ WRAPPER_SETTING: sibling() }), &routed), (serde_json::json!({ PERMISSION_SETTING: "default" }), &alone)] {
            home.write_settings(&settings.to_string());
            let plain = home.status(&[]);
            assert_lines(&text(&plain.stdout), std::slice::from_ref(row));
            for (what, out) in [("text", plain), ("--json", home.status(&["--json"]))] {
                assert_eq!(out.status.code(), Some(1), "{what}: {}", text(&out.stderr));
                let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
                assert!(!all.contains(&token) && !all.contains("QQQQ"), "{toml:?} {settings} {what}: {all}");
            }
        }
    }
}

/// The census is read as its writer guards it: a symlink in its place is
/// never followed and a FIFO never waited on (`[!! ] census unreadable`, exit
/// 0, at once); a row's `ext` and `ts` print only in the shapes the wrapper
/// writes, so a forged line in either never shows, in the text or the JSON.
#[cfg(unix)]
#[test]
fn a_census_that_is_no_regular_file_or_holds_forged_values() {
    let home = Home::new();
    home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling() }).to_string());
    home.install_extensions(&["2.1.300"], &[]);
    let mut forged: serde_json::Value = serde_json::from_str(&census_row("2026-10-12T08:00:00Z", "remote", "session", Some("2.1.296"), None)).unwrap();
    forged["ext"] = serde_json::json!("2.1.296\n  [ok ] forged extension row");
    forged["ts"] = serde_json::json!("2026-10-12T08:00:00Z\n  [ok ] forged session row");
    let forged = forged.to_string();
    let census = home.census_path().display().to_string();
    // A symlink to a census another hand wrote: refused, never read.
    let elsewhere = home.path().join("elsewhere.jsonl");
    std::fs::write(&elsewhere, format!("{forged}\n")).unwrap();
    std::fs::create_dir_all(home.census_path().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, home.census_path()).unwrap();
    let out = home.status(&[]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert_lines(&stdout, &[format!("  [!! ] census unreadable: config: {census} is a symlink; refusing to read it")]);
    assert!(!stdout.contains("forged"), "{stdout}");
    // A FIFO: refused at once, never waited on for a writer (a blocked open would run past the limit).
    std::fs::remove_file(home.census_path()).unwrap();
    let fifo = std::ffi::CString::new(home.census_path().into_os_string().into_encoded_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let out = home.status_within(&[], std::time::Duration::from_secs(20));
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert_lines(&stdout, &[format!("  [!! ] census unreadable: config: {census} is not a regular file")]);
    // A regular census holding the forged row: the values are `unrecognised`, the forged lines nowhere.
    std::fs::remove_file(home.census_path()).unwrap();
    home.seed_census(&[forged]);
    let stdout = text(&home.status(&[]).stdout);
    assert_lines(
        &stdout,
        &[
            "  [!! ] Cursor last ran extension unrecognised (unrecognised); 2.1.300 is installed  <- a window reload picks it up (it restarts open chats on this Mac)".to_string(),
            "  [ok ] Cursor's newest session (unrecognised) ran on this Mac".to_string(),
        ],
    );
    for out in [home.status(&[]), home.status(&["--json"])] {
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(!text(&out.stdout).contains("forged"), "{}", text(&out.stdout));
    }
}

/// `--json` is `doctor --json`'s shape: one JSON document of `ok`, `exit`
/// (the process's) and `rows` of exactly a tag and a text, exit 1 exactly
/// when a row is `no`; its rows are the text form's.
#[test]
fn json_has_doctors_shape() {
    for broken in [false, true] {
        let home = Home::new();
        home.write_settings(&serde_json::json!({ WRAPPER_SETTING: sibling() }).to_string());
        if broken {
            home.write_bridge_toml("[vm]\nmax_idle_typo = 1\n");
        }
        let out = home.status(&["--json"]);
        let stdout = text(&out.stdout);
        assert_eq!(stdout.lines().count(), 1, "one JSON document: {stdout}");
        let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {stdout}"));
        let mut keys: Vec<&String> = v.as_object().expect("an object").keys().collect();
        keys.sort();
        assert_eq!(keys, ["exit", "ok", "rows"], "{stdout}");
        let exit = v["exit"].as_i64().expect("exit is a number");
        assert_eq!(out.status.code().map(i64::from), Some(exit), "{stdout}");
        assert_eq!(v["ok"].as_bool(), Some(exit == 0), "{stdout}");
        let rows = v["rows"].as_array().expect("rows");
        let mut lines = vec!["ai-env wrapper status".to_string()];
        for row in rows {
            assert_eq!(row.as_object().map(serde_json::Map::len), Some(2), "{row}");
            let bracket = match row["tag"].as_str() {
                Some("ok") => "[ok ]",
                Some("no") => "[NO ]",
                Some("skip") => "[-  ]",
                Some("warn") => "[!! ]",
                other => panic!("tag {other:?}: {row}"),
            };
            lines.push(format!("  {bracket} {}", row["text"].as_str().expect("text")));
        }
        assert_eq!(exit == 1, rows.iter().any(|r| r["tag"] == "no"), "{stdout}");
        assert_eq!(exit, i64::from(broken), "{stdout}");
        let plain = home.status(&[]);
        assert_eq!(text(&plain.stdout), format!("{}\n", lines.join("\n")), "the text form prints the same rows");
    }
}
