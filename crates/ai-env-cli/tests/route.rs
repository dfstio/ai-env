//! T1.1 route policy over the argv fixtures plus the automatable half of T1.5
//! (`--features bridge`). Every `tests/fixtures/argv/*.json` is read from disk
//! and reconciled with `wire::argv::FIXTURE_NAMES` (one source of truth), then
//! run through `bridge::route::decide` inside a real workspace root, outside
//! it, and without a config. Nothing here touches the process environment.
use ai_env_cli::bridge::config::BridgeConfig;
use ai_env_cli::bridge::route::{cwd_under_roots, decide};
use ai_env_cli::wire::argv::{LocalReason, Route, FIXTURE_EXT_VERSION, FIXTURE_NAMES, KEPT_FIXTURES};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/argv");

#[derive(Deserialize)]
struct FixtureSession {
    #[serde(default)]
    add_dirs: Vec<String>,
}

/// The fields this target reads; the sanitiser fields are the argv KAT's business.
#[derive(Deserialize)]
struct Fixture {
    name: String,
    ext_version: String,
    argv: Vec<String>,
    route: String,
    reason: Option<String>,
    session: Option<FixtureSession>,
}

/// Every `*.json` under the fixture directory, parsed, sorted by name; the
/// file stem must equal the `name` field.
fn load_fixtures() -> Vec<Fixture> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(FIXTURE_DIR).unwrap_or_else(|e| panic!("read {FIXTURE_DIR}: {e}")) {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let f: Fixture = serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        assert_eq!(f.name, stem, "{}: the name field must equal the file stem", path.display());
        out.push(f);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn fixture<'a>(all: &'a [Fixture], name: &str) -> &'a Fixture {
    all.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no fixture named {name}"))
}

/// A real root on disk (`<root>/inside` is the session cwd), a second tempdir
/// outside it, and a config whose only root is `<root>`.
struct Roots {
    _root: tempfile::TempDir,
    _outside: tempfile::TempDir,
    root: PathBuf,
    inside: PathBuf,
    outside: PathBuf,
    cfg: BridgeConfig,
}

fn roots() -> Roots {
    let root_dir = tempfile::tempdir().expect("root tempdir");
    let root = root_dir.path().to_path_buf();
    let inside = root.join("inside");
    std::fs::create_dir(&inside).expect("inside dir");
    let outside_dir = tempfile::tempdir().expect("outside tempdir");
    let outside = outside_dir.path().to_path_buf();
    let cfg = BridgeConfig::parse(&format!("[workspaces]\nroots = [{:?}]\n", root)).expect("bridge.toml with one root");
    Roots { _root: root_dir, _outside: outside_dir, root, inside, outside, cfg }
}

#[test]
fn fixture_directory_equals_fixture_names() {
    let on_disk: BTreeSet<String> = load_fixtures().into_iter().map(|f| f.name).collect();
    let declared: BTreeSet<String> = FIXTURE_NAMES.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(declared.len(), FIXTURE_NAMES.len(), "FIXTURE_NAMES has a duplicate");
    assert_eq!(on_disk, declared, "tests/fixtures/argv/*.json and wire::argv::FIXTURE_NAMES disagree (left: disk, right: declared)");
}

/// Whether fixture `name`'s `ext_version` holds: `FIXTURE_EXT_VERSION`; for
/// a kept fixture (S10 F10, `KEPT_FIXTURES`, which a re-capture rewrites
/// only from a row of its shape) it or an older N.N.N, the one of its own
/// capture or tag.
fn tag_holds(name: &str, ext_version: &str) -> bool {
    fn version(v: &str) -> Option<[u32; 3]> {
        let mut parts = v.split('.').map(|p| Some(p).filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).and_then(|p| p.parse::<u32>().ok()));
        let out = [parts.next()??, parts.next()??, parts.next()??];
        parts.next().is_none().then_some(out)
    }
    ext_version == FIXTURE_EXT_VERSION || (KEPT_FIXTURES.contains(&name) && version(ext_version).zip(version(FIXTURE_EXT_VERSION)).is_some_and(|(v, at)| v <= at))
}

/// Every fixture is tagged with the extension it was captured from,
/// `FIXTURE_EXT_VERSION`; a kept one (S10 F10) with it or an older N.N.N, so
/// moving `FIXTURE_EXT_VERSION` after a re-capture that found no row of a
/// kept shape fails nothing; never a newer or a malformed one.
#[test]
fn every_fixture_is_tagged_with_the_captured_extension_version() {
    let all = load_fixtures();
    assert!(!all.is_empty());
    for f in &all {
        assert!(tag_holds(&f.name, &f.ext_version), "fixture {} was captured from another extension version ({}, not {FIXTURE_EXT_VERSION})", f.name, f.ext_version);
    }
    assert!(tag_holds("version", "2.1.278") && tag_holds("version", FIXTURE_EXT_VERSION) && tag_holds("session", FIXTURE_EXT_VERSION));
    for (name, tag) in [("session", "2.1.278"), ("version", "99.0.0"), ("version", "2.1"), ("version", "2.1.x"), ("version", "2.1.278.1"), ("version", "")] {
        assert!(!tag_holds(name, tag), "{name} tagged {tag:?}");
    }
}

#[test]
fn t1_1_fixtures_inside_outside_and_unconfigured() {
    let r = roots();
    let all = load_fixtures();
    let (mut remote, mut local) = (0usize, 0usize);
    for f in &all {
        let inside = decide(&f.argv, Some(&r.inside), Some(&r.cfg));
        let outside = decide(&f.argv, Some(&r.outside), Some(&r.cfg));
        let unconfigured = decide(&f.argv, Some(&r.inside), None);
        match f.route.as_str() {
            "remote" => {
                remote += 1;
                assert!(f.reason.is_none(), "fixture {}: a remote fixture carries no reason", f.name);
                assert!(matches!(inside, Route::Remote(_)), "fixture {}: inside the root => Remote, got {inside:?}", f.name);
                assert_eq!(outside, Route::Local(LocalReason::OutsideRoots), "fixture {}: outside the root", f.name);
                assert_eq!(unconfigured, Route::Local(LocalReason::Unconfigured), "fixture {}: no config", f.name);
            }
            "local" => {
                local += 1;
                let want = f.reason.as_deref().unwrap_or_else(|| panic!("fixture {}: a local fixture needs a reason", f.name));
                for (label, got) in [("inside", &inside), ("outside", &outside), ("unconfigured", &unconfigured)] {
                    match got {
                        Route::Local(reason) => assert_eq!(reason.name(), want, "fixture {} ({label})", f.name),
                        Route::Remote(s) => panic!("fixture {} ({label}): local shape routed Remote({s:?})", f.name),
                    }
                }
            }
            other => panic!("fixture {}: unknown route {other:?}", f.name),
        }
    }
    assert_eq!(remote, 5, "the four session fixtures and the config probe are the remote shapes (the login probe is the local `design-login --json` subcommand): {remote}");
    assert!(local >= 3, "subcommands, --version, --bare, chrome mcp and non-stream-json are local shapes: {local}");
    assert_eq!(remote + local, FIXTURE_NAMES.len());
}

#[test]
fn t1_5_add_dir_and_outside_roots() {
    let r = roots();
    let all = load_fixtures();
    let multi = fixture(&all, "session_multiroot");
    let multi_dirs = &multi.session.as_ref().expect("session_multiroot carries a session").add_dirs;
    assert_eq!(multi_dirs, &["/Users/mike/other".to_string()], "the multi-root row is the only one with --add-dir");
    match decide(&multi.argv, Some(&r.inside), Some(&r.cfg)) {
        Route::Remote(s) => assert_eq!(s.add_dirs, *multi_dirs),
        other => panic!("session_multiroot inside the root: {other:?}"),
    }
    let single = fixture(&all, "session");
    assert!(single.session.as_ref().expect("session carries a session").add_dirs.is_empty(), "a single-folder window passes no --add-dir");
    match decide(&single.argv, Some(&r.inside), Some(&r.cfg)) {
        Route::Remote(s) => assert!(s.add_dirs.is_empty()),
        other => panic!("session inside the root: {other:?}"),
    }
    let outside = decide(&single.argv, Some(&r.outside), Some(&r.cfg));
    assert_eq!(outside, Route::Local(LocalReason::OutsideRoots));
    match outside {
        Route::Local(reason) => assert_eq!(reason.name(), "outside_roots", "the census spelling of the T1.5 row"),
        Route::Remote(_) => unreachable!(),
    }
    assert!(!cwd_under_roots(&r.outside, &r.cfg.roots()));
    assert!(cwd_under_roots(&r.inside, &r.cfg.roots()));
}

#[cfg(unix)]
#[test]
fn symlinked_cwd_inside_the_root_is_remote() {
    let r = roots();
    let all = load_fixtures();
    let session = fixture(&all, "session");
    let link = r.outside.join("link-to-inside");
    std::os::unix::fs::symlink(&r.inside, &link).expect("symlink");
    assert!(cwd_under_roots(&link, &[r.root.as_path()]), "the symlink resolves under the root");
    assert!(matches!(decide(&session.argv, Some(&link), Some(&r.cfg)), Route::Remote(_)), "a symlinked cwd inside the root is still Remote");
    let to_root: &Path = &r.outside.join("link-to-root");
    std::os::unix::fs::symlink(&r.root, to_root).expect("symlink");
    assert!(matches!(decide(&session.argv, Some(to_root), Some(&r.cfg)), Route::Remote(_)), "a symlink to the root itself counts as cwd == root");
    let back_out = r.inside.join("link-to-outside");
    std::os::unix::fs::symlink(&r.outside, &back_out).expect("symlink");
    assert_eq!(decide(&session.argv, Some(&back_out), Some(&r.cfg)), Route::Local(LocalReason::OutsideRoots), "a symlink under the root that leaves it is outside");
}

// ---- S9 (G5): the local resume of a view -------------------------------------------------
//
// A remote chat's Mac file is its view (the last messages only, every line
// starting with `wire::view::VIEW_MARK_PREFIX`); a local claude resuming it
// would take it for the whole chat. The real wrapper refuses it, exit 9 with
// `LOCAL_RESUME_REFUSAL`: in the kill switch (no census, no config), and on
// every route but the remote one (its census row noting `view_refused:<word>`).
// Each run's environment is the test's alone (HOME, PATH, the bridge root);
// its real binary is a script that only notes that it ran.

const VIEW_ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
const PLAIN_ID: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";

/// A HOME whose projects directory holds the cwd's chats, a bridge root,
/// and a stand-in for the real binary.
struct ViewWorld {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    cwd: PathBuf,
    chats: PathBuf,
}

impl ViewWorld {
    fn new() -> ViewWorld {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonical tempdir");
        let cwd = root.join("work");
        std::fs::create_dir_all(&cwd).unwrap();
        let slug = ai_env_cli::wire::slug::project_dir_name(&cwd).expect("the cwd's slug");
        let chats = root.join("home/.claude/projects").join(slug);
        std::fs::create_dir_all(&chats).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        let claude = root.join("bin/claude");
        std::fs::write(&claude, "#!/bin/sh\necho ran >> \"$0.ran\"\n").unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        ViewWorld { _tmp: tmp, root, cwd, chats }
    }

    /// Chat `id` as a view, modified `age_s` seconds ago.
    fn view(&self, id: &str, age_s: u64) {
        let line = format!("{}\"type\":\"ai-title\",\"aiTitle\":\"a remote chat\",\"sessionId\":\"{id}\"}}\n", ai_env_cli::wire::view::VIEW_MARK_PREFIX);
        self.chat(id, &line, age_s);
    }

    /// Chat `id` as a transcript of its own, modified `age_s` seconds ago.
    fn plain(&self, id: &str, age_s: u64) {
        self.chat(id, &format!("{{\"type\":\"user\",\"sessionId\":\"{id}\",\"message\":{{\"role\":\"user\",\"content\":\"hi\"}}}}\n"), age_s);
    }

    fn chat(&self, id: &str, text: &str, age_s: u64) {
        let path = self.chats.join(format!("{id}.jsonl"));
        std::fs::write(&path, text).unwrap();
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(age_s);
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(when).unwrap();
    }

    /// The wrapper with `args` after the stand-in real binary, in the cwd, its environment `envs` on the test's own.
    fn run(&self, args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-env-claude"));
        cmd.arg(self.root.join("bin/claude")).args(args).current_dir(&self.cwd).env_clear();
        cmd.env("HOME", self.root.join("home")).env("PATH", "/usr/bin:/bin").env("AI_ENV_BRIDGE_DIR", self.root.join("bridge"));
        cmd.envs(envs.iter().copied()).stdin(std::process::Stdio::null());
        cmd.output().expect("run the wrapper")
    }

    /// How many times the stand-in real binary ran.
    fn ran(&self) -> usize {
        std::fs::read_to_string(self.root.join("bin/claude.ran")).map_or(0, |t| t.lines().count())
    }

    /// The census rows, oldest first.
    fn rows(&self) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(self.root.join("bridge/logs/census.jsonl")).unwrap_or_default();
        text.lines().map(|l| serde_json::from_str(l).expect("a census row")).collect()
    }

    /// The census rows' notes, oldest first.
    fn notes(&self) -> Vec<String> {
        self.rows().iter().map(|r| r["note"].as_str().unwrap_or_default().to_string()).collect()
    }
}

/// The wrapper's last stderr line.
fn last_err(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or_default().to_string()
}

fn refusal_line() -> String {
    format!("ai-env-claude: {}", ai_env_cli::wire::view::LOCAL_RESUME_REFUSAL)
}

/// Passthrough (no bridge.toml: the default mode), a local pump mode and a
/// session outside the roots in remote mode: a `--resume` of a view, in each
/// of its spellings, is exit 9 with the refusal; the census row is written
/// first, noting `view_refused:resume`; the real binary never runs. A
/// resume of a transcript of its own runs it, as before.
#[test]
fn passthrough_resume_of_a_view_exits_9() {
    let w = ViewWorld::new();
    w.view(VIEW_ID, 0);
    w.plain(PLAIN_ID, 60);
    let resume_eq = format!("--resume={VIEW_ID}");
    for args in [&["--resume", VIEW_ID][..], &[resume_eq.as_str()], &["--print", "-r", VIEW_ID, "--output-format", "json"]] {
        let out = w.run(args, &[]);
        assert_eq!((out.status.code(), last_err(&out)), (Some(9), refusal_line()), "{args:?}");
    }
    let notes = w.notes();
    assert_eq!(notes.len(), 3, "one census row per run: {notes:?}");
    assert!(notes.iter().all(|n| n.split("; ").any(|p| p == "view_refused:resume")), "{notes:?}");
    let stream = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json", "--resume", VIEW_ID];
    let out = w.run(&stream, &[("AI_ENV_BRIDGE_MODE", "local-child")]);
    assert_eq!((out.status.code(), last_err(&out)), (Some(9), refusal_line()), "a local pump mode");
    std::fs::create_dir_all(w.root.join("bridge")).unwrap();
    std::fs::write(w.root.join("bridge/bridge.toml"), format!("[workspaces]\nroots = [{:?}]\n", w.root.join("elsewhere"))).unwrap();
    let out = w.run(&stream, &[("AI_ENV_BRIDGE_MODE", "remote")]);
    assert_eq!((out.status.code(), last_err(&out)), (Some(9), refusal_line()), "remote mode, a session outside the roots");
    assert_eq!(w.ran(), 0, "the real binary never ran");
    let out = w.run(&["--resume", PLAIN_ID], &[]);
    assert_eq!((out.status.code(), w.ran()), (Some(0), 1), "a transcript of its own resumes locally: {}", String::from_utf8_lossy(&out.stderr));
}

/// The kill switch (`AI_ENV_BRIDGE_LOCAL=1`): a resume of a view is refused
/// before its raw exec, exit 9 with the refusal, no census row and no
/// config read; anything else still execs the real binary raw.
#[test]
fn kill_switch_refuses_a_view() {
    let w = ViewWorld::new();
    w.view(VIEW_ID, 0);
    w.plain(PLAIN_ID, 60);
    let kill = [("AI_ENV_BRIDGE_LOCAL", "1")];
    for args in [&["--resume", VIEW_ID, "--output-format", "stream-json"][..], &["-r", VIEW_ID], &["-c"]] {
        let out = w.run(args, &kill);
        assert_eq!((out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned()), (Some(9), format!("{}\n", refusal_line())), "{args:?}");
    }
    assert_eq!(w.ran(), 0);
    assert!(w.notes().is_empty() && !w.root.join("bridge").exists(), "the kill switch writes nothing");
    for args in [&["--resume", PLAIN_ID][..], &["--resume", "not-a-session-id"], &["--version"]] {
        let before = w.ran();
        assert_eq!(w.run(args, &kill).status.code(), Some(0), "{args:?}");
        assert_eq!(w.ran(), before + 1, "{args:?}: raw exec");
    }
}

/// `--continue` (or `-c`) resumes the newest chat of the cwd: when that is a
/// view, exit 9 with the refusal, the census noting `view_refused:continue`;
/// once a transcript of its own is the newest, it runs.
#[test]
fn continue_to_a_view_refused() {
    let w = ViewWorld::new();
    w.plain(PLAIN_ID, 120);
    w.view(VIEW_ID, 0);
    for args in [&["--continue"][..], &["-c", "--output-format", "stream-json", "--verbose", "--input-format", "stream-json"]] {
        let out = w.run(args, &[]);
        assert_eq!((out.status.code(), last_err(&out)), (Some(9), refusal_line()), "{args:?}");
    }
    let notes = w.notes();
    assert!(notes.len() == 2 && notes.iter().all(|n| n.split("; ").any(|p| p == "view_refused:continue")), "{notes:?}");
    assert_eq!(w.ran(), 0);
    w.plain(PLAIN_ID, 0);
    w.view(VIEW_ID, 120);
    let out = w.run(&["--continue"], &[]);
    assert_eq!((out.status.code(), w.ran()), (Some(0), 1), "the newest is a transcript: {}", String::from_utf8_lossy(&out.stderr));
}

/// Remote mode, a session under the roots: its chat resumes from S3 in the
/// VM, so its view here is no refusal (`view_refusal` is `None` on the
/// remote route). The lab knob (debug builds) ends the run once the row is
/// written, before the pump: no AWS. The row is the remote route's, with no
/// `view_refused:` part, and the real binary never runs.
#[cfg(debug_assertions)]
#[test]
fn remote_resume_of_a_view_is_not_refused() {
    let w = ViewWorld::new();
    w.view(VIEW_ID, 0);
    std::fs::create_dir_all(w.root.join("bridge")).unwrap();
    std::fs::write(w.root.join("bridge/bridge.toml"), format!("[workspaces]\nroots = [{:?}]\n", w.root)).unwrap();
    let stream = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json", "--resume", VIEW_ID];
    let out = w.run(&stream, &[("AI_ENV_BRIDGE_MODE", "remote"), ("AI_ENV_BRIDGE_LAB_EXIT", "3:boom")]);
    assert_eq!((out.status.code(), last_err(&out)), (Some(3), "boom".to_string()), "past the view refusal to the knob: {}", String::from_utf8_lossy(&out.stderr));
    let rows = w.rows();
    assert_eq!(rows.iter().map(|r| r["route"].as_str()).collect::<Vec<_>>(), [Some("remote")], "one row, the remote route's: {rows:?}");
    let note = rows[0]["note"].as_str().unwrap_or_default();
    assert!(note.split("; ").any(|p| p == "lab_exit:3") && !note.split("; ").any(|p| p.starts_with("view_refused:")), "{note}");
    assert_eq!(w.ran(), 0, "the real binary never ran");
}

// ---- S9 (M7; wave 2: G8): the argv fixtures re-captured from the census ------------------------

/// What a census row must share with a fixture to stand for it: the route;
/// a local one's reason, its leading words (the subcommand) and the flags
/// it names; a session's resume, continue, added directory, MCP
/// configuration, thinking off and no persistence. Never a value.
fn argv_shape(args: &[String]) -> String {
    match ai_env_cli::wire::argv::classify(args) {
        Route::Local(reason) => {
            let words: Vec<&str> = args.iter().take_while(|a| !a.starts_with('-')).map(String::as_str).collect();
            let mut flags: Vec<&str> = args.iter().filter(|a| a.starts_with("--")).map(|a| a.split('=').next().unwrap_or(a)).collect();
            flags.sort_unstable();
            flags.dedup();
            format!("local {} [{}] [{}]", reason.name(), words.join(" "), flags.join(" "))
        }
        Route::Remote(s) => format!(
            "session resume={} continue={} add_dir={} mcp={} thinking_off={} no_persistence={}",
            s.resume.is_some(),
            s.continue_,
            !s.add_dirs.is_empty(),
            s.has_mcp_config,
            s.thinking_disabled,
            s.no_session_persistence
        ),
    }
}

/// A fixture file's text with only its `ext_version` and `argv` lines
/// replaced (each on one line of its own, as every fixture writes them);
/// every other byte as it was.
fn rewritten(text: &str, ext: &str, argv: &[String]) -> String {
    let list = argv.iter().map(|a| serde_json::to_string(a).expect("a JSON string")).collect::<Vec<_>>().join(", ");
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let body = line.trim_start();
        let indent = &line[..line.len() - body.len()];
        if body.starts_with("\"ext_version\":") {
            out.push_str(&format!("{indent}\"ext_version\": {},\n", serde_json::to_string(ext).expect("a JSON string")));
        } else if body.starts_with("\"argv\":") {
            out.push_str(&format!("{indent}\"argv\": [{list}],\n"));
        } else {
            out.push_str(line);
        }
    }
    out
}

/// A census row's CLI arguments: its argv past the wrapper and the bundled claude.
fn row_args(row: &serde_json::Value) -> Option<Vec<String>> {
    let argv = row["argv"].as_array()?;
    (argv.len() >= 2).then(|| argv.iter().skip(2).filter_map(|a| a.as_str().map(str::to_string)).collect())
}

/// Whether census arguments carry a thinking budget the census masked: S9's
/// census masked every `--max-thinking-tokens=` (`[redacted:len=5]` for
/// 31999), S10's (F7) only a value that is not 1 to 7 digits, in either
/// spelling. Such a row stands for no fixture: the session fixtures'
/// hand-owned `sanitised` holds the number, which its argv would lack.
fn budget_masked(args: &[String]) -> bool {
    args.iter().enumerate().any(|(i, a)| a.starts_with("--max-thinking-tokens=[redacted:") || (a == "--max-thinking-tokens" && args.get(i + 1).is_some_and(|v| v.starts_with("[redacted:"))))
}

/// Offline, the capture's tools: every fixture has a shape of its own (so a
/// census row stands for one fixture at most), a fixture rewritten with its
/// own argv and version is byte for byte itself, and a rewrite changes the
/// argv and the version only (the hand-owned route, reason, session and
/// sanitised stay).
#[test]
fn argv_shapes_tell_the_fixtures_apart_and_a_rewrite_keeps_the_rest() {
    let all = load_fixtures();
    let shapes: BTreeSet<String> = all.iter().map(|f| argv_shape(&f.argv)).collect();
    assert_eq!(shapes.len(), all.len(), "two fixtures share a shape: {shapes:#?}");
    for f in &all {
        let path = Path::new(FIXTURE_DIR).join(format!("{}.json", f.name));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(rewritten(&text, &f.ext_version, &f.argv), text, "{}: a rewrite with its own argv and version", f.name);
        let argv: Vec<String> = f.argv.iter().cloned().chain(["--a \"quoted\" one".to_string()]).collect();
        let changed = rewritten(&text, "9.9.9", &argv);
        let (old, new): (serde_json::Value, serde_json::Value) = (serde_json::from_str(&text).unwrap(), serde_json::from_str(&changed).unwrap_or_else(|e| panic!("{}: {e}", f.name)));
        assert_eq!((new["ext_version"].as_str(), new["argv"].as_array().map(Vec::len)), (Some("9.9.9"), Some(argv.len())), "{}", f.name);
        let rest = |v: &serde_json::Value| v.as_object().unwrap().iter().filter(|(k, _)| *k != "ext_version" && *k != "argv").map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>();
        assert_eq!(rest(&new), rest(&old), "{}: the hand-owned fields stay", f.name);
    }
    let row = serde_json::json!({"argv": ["/w/ai-env-claude", "/b/claude", "--version"]});
    assert_eq!(row_args(&row), Some(vec!["--version".to_string()]));
    assert_eq!(row_args(&serde_json::json!({"argv": ["/w/ai-env-claude"]})), None);
}

/// What the capture makes of each fixture (S10 F10): `found`, each one
/// rewritten from a census row (its name, its new text, the row's pid and
/// time); `kept`, the ones of [`KEPT_FIXTURES`] no row of that extension
/// has the shape of (shapes it makes no more), left as they are; `missing`,
/// the others no row has the shape of.
#[derive(Debug, Default)]
struct Capture {
    found: Vec<(&'static str, String, String)>,
    kept: Vec<&'static str>,
    missing: Vec<&'static str>,
}

/// The capture's plan, offline: `fixtures` holds each fixture's name and
/// file text, in `FIXTURE_NAMES`' order, and `rows` the census rows (oldest
/// first); only rows of extension `ext` count, and none whose thinking
/// budget the census masked ([`budget_masked`]: an S9 census's row, written
/// before S10 F7). Each fixture takes the newest row of its shape
/// ([`argv_shape`]), its `argv` and `ext_version` rewritten
/// ([`rewritten`]); with none, a kept fixture (a shape `ext` makes no more)
/// stays as it is and any other is missing, left as it is too.
fn capture(fixtures: &[(&'static str, String)], rows: &[serde_json::Value], ext: &str) -> Capture {
    let mut out = Capture::default();
    for (name, text) in fixtures {
        let fixture: Fixture = serde_json::from_str(text).unwrap_or_else(|e| panic!("parse {name}: {e}"));
        let want = argv_shape(&fixture.argv);
        let Some((row, args)) = rows.iter().rev().filter(|r| r["ext"] == ext).find_map(|r| row_args(r).filter(|a| argv_shape(a) == want && !budget_masked(a)).map(|a| (r, a))) else {
            if KEPT_FIXTURES.contains(name) {
                out.kept.push(name);
            } else {
                out.missing.push(name);
            }
            continue;
        };
        let new = rewritten(text, ext, &args);
        let parsed: Fixture = serde_json::from_str(&new).unwrap_or_else(|e| panic!("{name}: the rewrite does not parse ({e})"));
        assert_eq!((parsed.ext_version.as_str(), &parsed.argv, parsed.route.as_str()), (ext, &args, fixture.route.as_str()), "{name}: the rewrite");
        out.found.push((name, new, format!("pid {} at {}", row["pid"], row["ts"].as_str().unwrap_or("?"))));
    }
    out
}

/// S10 F10: the capture looks for every fixture's shape, the kept ones'
/// too (`version`, `bare`, `not_stream_json`, `session_chrome_mcp`: shapes
/// extension 2.1.303 makes no more). A kept fixture no row of that
/// extension has the shape of is reported as kept, never missing, and left
/// as it is; one a row has the shape of is rewritten as any other, so a
/// shape the extension makes again is captured, never kept stale. Every
/// other fixture is rewritten from the newest row of its shape at that
/// extension, or missing. A row whose thinking budget the census masked
/// (S9's census, before S10 F7) stands for no fixture, so it never undoes
/// F7's fixtures.
#[test]
fn the_capture_reports_the_kept_fixtures_as_kept_never_missing() {
    let fixtures: Vec<(&'static str, String)> = FIXTURE_NAMES.iter().map(|name| (*name, std::fs::read_to_string(Path::new(FIXTURE_DIR).join(format!("{name}.json"))).unwrap())).collect();
    let others: Vec<&str> = FIXTURE_NAMES.iter().copied().filter(|n| !KEPT_FIXTURES.contains(n)).collect();
    assert_eq!(others.len(), FIXTURE_NAMES.len() - 4);
    let names = |found: &[(&'static str, String, String)]| found.iter().map(|(n, _, _)| *n).collect::<Vec<_>>();
    let none = capture(&fixtures, &[], "9.9.9");
    assert!(none.found.is_empty());
    assert_eq!((none.kept.as_slice(), none.missing.as_slice()), (&KEPT_FIXTURES[..], others.as_slice()), "no census row: the kept ones are kept, the others missing");
    // A row of each fixture's shape at that extension, the i-th fixture's with pid 100 + i.
    let row_of = |i: usize, text: &str| {
        let f: Fixture = serde_json::from_str(text).unwrap();
        let argv: Vec<String> = ["/w/ai-env-claude".to_string(), "/b/claude".to_string()].into_iter().chain(f.argv).collect();
        serde_json::json!({"ext": "9.9.9", "pid": 100 + i, "ts": "2026-10-20T10:00:00Z", "argv": argv})
    };
    // The census of 2.1.303's kind: no row of a kept shape.
    let made: Vec<serde_json::Value> = fixtures.iter().enumerate().filter(|(_, (n, _))| !KEPT_FIXTURES.contains(n)).map(|(i, (_, text))| row_of(i, text)).collect();
    let some = capture(&fixtures, &made, "9.9.9");
    assert_eq!(names(&some.found), others, "every other fixture is found");
    assert_eq!((some.kept.as_slice(), some.missing.len()), (&KEPT_FIXTURES[..], 0), "the kept ones are kept, none missing");
    // S10 F7: a row of S9's census, its thinking budget masked (either spelling), stands for no fixture: a session
    // fixture with no other row of its shape is missing and left with its number; a newer such row hides no older one.
    let budget = "\"--max-thinking-tokens=31999\"";
    let sessions: Vec<(usize, &(&'static str, String))> = fixtures.iter().enumerate().filter(|(_, (_, text))| text.contains(budget)).collect();
    assert_eq!(sessions.iter().map(|(_, (n, _))| *n).collect::<Vec<_>>(), ["session", "session_resume", "session_multiroot"]);
    let masked: Vec<serde_json::Value> = sessions
        .iter()
        .map(|(i, (name, text))| row_of(*i, &text.replace(budget, if *name == "session" { "\"--max-thinking-tokens\", \"[redacted:len=8]\"" } else { "\"--max-thinking-tokens=[redacted:len=5]\"" })))
        .collect();
    for (row, (_, (name, text))) in masked.iter().zip(&sessions) {
        let args = row_args(row).unwrap();
        assert!(args.iter().any(|a| a.contains("[redacted:")) && argv_shape(&args) == argv_shape(&serde_json::from_str::<Fixture>(text).unwrap().argv), "{name}: its shape, its budget masked");
    }
    let s9 = capture(&fixtures, &masked, "9.9.9");
    assert!(s9.found.is_empty(), "{s9:?}");
    assert_eq!((s9.kept.as_slice(), s9.missing.as_slice()), (&KEPT_FIXTURES[..], others.as_slice()), "S9's rows count for none: the session fixtures are missing");
    let both: Vec<serde_json::Value> = made.iter().cloned().chain(masked).collect();
    let s10 = capture(&fixtures, &both, "9.9.9");
    assert_eq!(names(&s10.found), others, "the older rows of S10's census are taken");
    assert!(s10.found.iter().filter(|(n, _, _)| n.starts_with("session")).all(|(_, new, _)| new.contains(budget)), "{s10:?}");
    // A row of every fixture's shape, the kept ones' too (and one at another, newer, extension, which counts for nothing).
    let mut rows: Vec<serde_json::Value> = fixtures.iter().enumerate().map(|(i, (_, text))| row_of(i, text)).collect();
    rows.push(serde_json::json!({"ext": "9.9.8", "pid": 1, "ts": "2026-10-20T11:00:00Z", "argv": ["/w/ai-env-claude", "/b/claude", "--version"]}));
    let every = capture(&fixtures, &rows, "9.9.9");
    assert_eq!(names(&every.found), FIXTURE_NAMES.to_vec(), "every fixture is found, a kept one too: a shape the extension makes again is captured");
    assert!(every.kept.is_empty() && every.missing.is_empty(), "{every:?}");
    for (name, new, row) in &every.found {
        let text = &fixtures.iter().find(|(n, _)| n == name).unwrap().1;
        let own = serde_json::from_str::<Fixture>(text).unwrap().ext_version;
        assert_eq!(new, &text.replace(&format!("\"ext_version\": \"{own}\""), "\"ext_version\": \"9.9.9\""), "{name}: its own argv, the new version");
        assert!(row.ends_with(" at 2026-10-20T10:00:00Z"), "{name}: {row}");
    }
    let other = capture(&fixtures, &rows, "9.9.7");
    assert_eq!((other.found.len(), other.kept.as_slice(), other.missing.as_slice()), (0, &KEPT_FIXTURES[..], others.as_slice()), "another extension's rows count for nothing");
}

/// S9 M7 (`make argv-fixtures EXT=2.1.302`; gated: AI_ENV_ARGV_CAPTURE=1
/// and AI_ENV_ARGV_EXT, never part of `make test`): for each fixture of
/// `wire::argv::FIXTURE_NAMES` ([`capture`]), the newest of the operator's
/// census rows (`ai-env wrapper census --json`) of extension EXT whose argv
/// has the fixture's shape ([`argv_shape`]) rewrites that fixture's `argv`
/// and `ext_version`, in place and nothing else ([`rewritten`]): `route`,
/// `reason`, `session` and `sanitised` stay hand-owned, so the known-answer
/// tests still check the new argv. It prints the fixtures found, the ones
/// kept (S10 F10: `KEPT_FIXTURES` with no row of their shape, shapes the
/// extension makes no more, which keep their tag) and the ones missing
/// (part B's Cursor checklist makes them); then `FIXTURE_EXT_VERSION` moves
/// to EXT by hand.
#[test]
#[ignore = "S9 M7: make argv-fixtures EXT=N.N.N (rewrites tests/fixtures/argv/*.json from the census)"]
fn capture_argv_fixtures_from_the_census() {
    if std::env::var("AI_ENV_ARGV_CAPTURE").as_deref() != Ok("1") {
        eprintln!("skipped: make argv-fixtures EXT=N.N.N runs it (AI_ENV_ARGV_CAPTURE=1, AI_ENV_ARGV_EXT)");
        return;
    }
    let ext = std::env::var("AI_ENV_ARGV_EXT").unwrap_or_default();
    let parts: Vec<&str> = ext.split('.').collect();
    assert!(parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())), "AI_ENV_ARGV_EXT={ext:?} is not N.N.N");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-env"));
    cmd.args(["wrapper", "census", "--json"]).stdin(std::process::Stdio::null());
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().to_string();
        if k.starts_with("AI_ENV_BRIDGE_LAB_") {
            cmd.env_remove(&k);
        }
    }
    let out = cmd.output().expect("ai-env wrapper census --json");
    assert!(out.status.success(), "ai-env wrapper census --json: {}", String::from_utf8_lossy(&out.stderr));
    let rows: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let path = |name: &str| Path::new(FIXTURE_DIR).join(format!("{name}.json"));
    let fixtures: Vec<(&'static str, String)> = FIXTURE_NAMES.iter().map(|name| (*name, std::fs::read_to_string(path(name)).unwrap_or_else(|e| panic!("read {}: {e}", path(name).display())))).collect();
    let plan = capture(&fixtures, &rows, &ext);
    let mut found = Vec::new();
    for (name, new, row) in &plan.found {
        std::fs::write(path(name), new).unwrap_or_else(|e| panic!("write {}: {e}", path(name).display()));
        found.push(format!("{name} ({row})"));
    }
    let listed = |names: &[&str]| if names.is_empty() { "none".to_string() } else { names.join(", ") };
    println!("argv-fixtures: {} of {} rewritten from extension {ext}'s census rows: {}", found.len(), FIXTURE_NAMES.len(), found.join(", "));
    println!("argv-fixtures: kept as they are (no {ext} row of their shape, one the extension makes no more: wire::argv::KEPT_FIXTURES): {}", listed(&plan.kept));
    println!("argv-fixtures: missing, left as they are (no {ext} row of their shape, a row of S9's census, its thinking budget masked, counting for none: make them in Cursor, part B's checklist, then run this again): {}", listed(&plan.missing));
    println!("argv-fixtures: then FIXTURE_EXT_VERSION (wire/argv.rs) moves to {ext} with its pins (a kept fixture keeps its own tag), and make test checks the hand-owned fields against the new argv");
}
