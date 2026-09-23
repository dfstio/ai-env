//! T1.1 route policy over the argv fixtures plus the automatable half of T1.5
//! (`--features bridge`). Every `tests/fixtures/argv/*.json` is read from disk
//! and reconciled with `wire::argv::FIXTURE_NAMES` (one source of truth), then
//! run through `bridge::route::decide` inside a real workspace root, outside
//! it, and without a config. Nothing here touches the process environment.
use ai_env_cli::bridge::config::BridgeConfig;
use ai_env_cli::bridge::route::{cwd_under_roots, decide};
use ai_env_cli::wire::argv::{LocalReason, Route, FIXTURE_EXT_VERSION, FIXTURE_NAMES};
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

#[test]
fn every_fixture_is_tagged_with_the_captured_extension_version() {
    let all = load_fixtures();
    assert!(!all.is_empty());
    for f in &all {
        assert_eq!(f.ext_version, FIXTURE_EXT_VERSION, "fixture {} was captured from another extension version", f.name);
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
