//! The wrapper's route decision: argv shape × cwd × `bridge.toml` roots.
//!
//! `wire::argv::classify` reads only the argv; this module adds the two facts
//! the wrapper knows and the classifier does not — whether a `bridge.toml`
//! loaded, and where Cursor spawned the process. The S1 plan (§6) fixes the
//! table:
//!
//! * A subcommand (`auth status --json`, `plugin …`, `design-login`,
//!   `edit-permission-rules`, `mcp add`/`remove`, …), `--version`,
//!   `--claude-in-chrome-mcp`, `--bare` and anything that is not a
//!   stream-json session stays `Local` with the classifier's reason,
//!   regardless of cwd or config.
//! * A stream-json session (the chat session, the config probe, the login
//!   probe) is `Remote` when `bridge.toml` loads and the canonicalised cwd is
//!   under one of its roots; `Local(OutsideRoots)` when the cwd is unknown or
//!   outside every root; `Local(Unconfigured)` when there is no usable
//!   `bridge.toml` (absent or unparseable — the parse error goes into
//!   `Loaded::note`, never on stderr).
//!
//! Roots are `[workspaces].roots` ∪ `[[workspace]].path`
//! (`BridgeConfig::roots`), each canonicalised when it exists so a symlinked
//! cwd still matches; the comparison is component-wise (`Path::starts_with`):
//! cwd == root matches, `/a/b2` is not under `/a/b`.
//!
//! `AI_ENV_BRIDGE_MODE` ([`Mode`]) decides what happens to a stream-json
//! session: unset keeps S1's exec for every route; `local-child` and
//! `local-scratch` pipe it through the S2 pump ([`piped`]); `remote` is
//! parsed and execs until S8.
use crate::bridge::config::{BridgeConfig, Paths};
use crate::wire::argv::{classify, LocalReason, Route, SessionArgs};
use std::path::{Path, PathBuf};

/// What the wrapper learned before deciding, never fatal: `paths` is `None`
/// only when `Paths::resolve` fails (`HOME` unset — no census either), `cfg`
/// is `None` when `bridge.toml` is absent or unparseable, and `note` carries
/// the error text of either failure for the census row.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Loaded {
    /// The bridge state root and config location, when `HOME` (or
    /// `AI_ENV_BRIDGE_DIR`) resolved.
    pub paths: Option<Paths>,
    /// The parsed `bridge.toml`, when the file exists and parses.
    pub cfg: Option<BridgeConfig>,
    /// The error text when `paths` or `cfg` is missing for a reason worth
    /// recording (an absent `bridge.toml` is not one).
    pub note: Option<String>,
}

/// `Paths::resolve()` then `BridgeConfig::load(&paths)`, folding every failure
/// into `Loaded` so the wrapper always goes on to exec the real binary.
#[must_use]
pub fn load_for_wrapper() -> Loaded {
    let paths = match Paths::resolve() {
        Ok(p) => p,
        Err(e) => return Loaded { paths: None, cfg: None, note: Some(first_line(&e.to_string())) },
    };
    match BridgeConfig::load(&paths) {
        Ok(Some(cfg)) => Loaded { paths: Some(paths), cfg: Some(cfg), note: None },
        Ok(None) => Loaded { paths: Some(paths), cfg: None, note: None },
        Err(e) => Loaded { paths: Some(paths), cfg: None, note: Some(first_line(&e.to_string())) },
    }
}

/// The first line of an error text: a TOML error's Display carries a snippet
/// of the offending line, which must not be copied into the census.
fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or_default().to_string()
}

/// The canonical path when the path exists, else the path as given.
fn canonical_or_raw(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Is `cwd` one of `roots` or inside one? Both sides are canonicalised when
/// they exist (a symlinked cwd resolves to where it points; a root that does
/// not exist is compared as written) and matched component-wise, so
/// `/a/b2` is not under `/a/b`. An empty root never matches.
#[must_use]
pub fn cwd_under_roots(cwd: &Path, roots: &[&Path]) -> bool {
    let cwd = canonical_or_raw(cwd);
    roots.iter().any(|r| !r.as_os_str().is_empty() && cwd.starts_with(canonical_or_raw(r)))
}

/// The route for one invocation: the classifier's verdict, with a stream-json
/// session demoted to `Local(Unconfigured)` without a config and to
/// `Local(OutsideRoots)` when `cwd` is unknown or not under `cfg.roots()`.
#[must_use]
pub fn decide(args: &[String], cwd: Option<&Path>, cfg: Option<&BridgeConfig>) -> Route {
    match classify(args) {
        Route::Remote(session) => {
            let Some(cfg) = cfg else {
                return Route::Local(LocalReason::Unconfigured);
            };
            match cwd {
                Some(dir) if cwd_under_roots(dir, &cfg.roots()) => Route::Remote(session),
                _ => Route::Local(LocalReason::OutsideRoots),
            }
        }
        local => local,
    }
}

/// `AI_ENV_BRIDGE_MODE`: whether a stream-json session is exec'd (S1) or
/// piped through the wrapper (S2's local modes; `remote` is S8's).
pub const MODE_ENV: &str = "AI_ENV_BRIDGE_MODE";

/// How a stream-json session runs. Unset means `Passthrough` — S1's exec for
/// every route — so a daily Cursor setup is untouched until the variable is
/// set on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Exec the real binary for every route (S1 behaviour; the default).
    Passthrough,
    /// Pipe the session through the wrapper to a local child that uses the
    /// Mac's own config dir (writer validated via `AI_ENV_BRIDGE_MIRROR_ROOT`).
    LocalChild,
    /// Pipe the session to a local child whose `CLAUDE_CONFIG_DIR` is a
    /// per-session scratch dir (resume seeding). The child has no login of its
    /// own: S7 hands it the sealed setup-token on fd 3 (`pump::scratch_login`),
    /// and without one it runs logged out.
    LocalScratch,
    /// Parsed, not implemented until S8: behaves as `Passthrough` + a census note.
    Remote,
}

impl Mode {
    /// The spelling of `AI_ENV_BRIDGE_MODE` and of the census note.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Mode::Passthrough => "passthrough",
            Mode::LocalChild => "local-child",
            Mode::LocalScratch => "local-scratch",
            Mode::Remote => "remote",
        }
    }
}

/// `None` (unset) or `passthrough` → `Passthrough`; the three other names
/// map to their mode; anything else → `Err(value)`.
pub fn parse_mode(value: Option<&str>) -> Result<Mode, String> {
    match value {
        None | Some("passthrough") => Ok(Mode::Passthrough),
        Some("local-child") => Ok(Mode::LocalChild),
        Some("local-scratch") => Ok(Mode::LocalScratch),
        Some("remote") => Ok(Mode::Remote),
        Some(other) => Err(other.to_string()),
    }
}

/// The mode from the environment plus the census note it earns:
/// `mode:<name>` for a non-default mode, `mode:remote(unimplemented)` for
/// `remote`, `mode_invalid:<value>` (scrubbed, ≤ 64 chars) for an unknown
/// value — which also prints one stderr line and falls back to passthrough.
/// Reads one environment variable and nothing else, so it may run on the
/// exec path.
#[must_use]
pub fn mode_from_env() -> (Mode, Option<String>) {
    let raw = std::env::var_os(MODE_ENV).map(|v| v.to_string_lossy().into_owned());
    mode_and_note(raw.as_deref())
}

/// The pure half of [`mode_from_env`].
#[must_use]
pub fn mode_and_note(raw: Option<&str>) -> (Mode, Option<String>) {
    match parse_mode(raw) {
        Ok(Mode::Passthrough) => (Mode::Passthrough, None),
        Ok(Mode::Remote) => (Mode::Remote, Some("mode:remote(unimplemented)".to_string())),
        Ok(mode) => (mode, Some(format!("mode:{}", mode.name()))),
        Err(value) => {
            let shown: String = crate::wire::redact::scrub(&value).chars().take(64).collect();
            eprintln!("ai-env-claude: {MODE_ENV}={shown} unknown; passthrough");
            (Mode::Passthrough, Some(format!("mode_invalid:{shown}")))
        }
    }
}

/// The session payload when this invocation is piped, else `None` (exec).
/// `Passthrough` and `Remote` (until S8) never pipe. The two local modes
/// pipe every stream-json session shape — `Remote(_)` and the two demoted
/// reasons `Local(OutsideRoots | Unconfigured)`, whose payload comes from
/// `classify` again — because a local child needs neither roots nor a
/// `bridge.toml`. Every other `Local` reason (subcommands, `--version`,
/// `--bare`, …) execs.
#[must_use]
pub fn piped(mode: Mode, route: &Route, args: &[String]) -> Option<SessionArgs> {
    match mode {
        Mode::Passthrough | Mode::Remote => None,
        Mode::LocalChild | Mode::LocalScratch => match route {
            Route::Remote(s) => Some(s.clone()),
            Route::Local(LocalReason::OutsideRoots | LocalReason::Unconfigured) => match classify(args) {
                Route::Remote(s) => Some(s),
                Route::Local(_) => None,
            },
            Route::Local(_) => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_names() {
        assert_eq!(parse_mode(None), Ok(Mode::Passthrough));
        for m in [Mode::Passthrough, Mode::LocalChild, Mode::LocalScratch, Mode::Remote] {
            assert_eq!(parse_mode(Some(m.name())), Ok(m), "{}", m.name());
        }
        assert_eq!(parse_mode(Some("Local-Child")), Err("Local-Child".to_string()), "names are case-sensitive");
        assert_eq!(parse_mode(Some("")), Err(String::new()));
    }

    #[test]
    fn mode_notes() {
        assert_eq!(mode_and_note(None), (Mode::Passthrough, None));
        assert_eq!(mode_and_note(Some("passthrough")), (Mode::Passthrough, None));
        assert_eq!(mode_and_note(Some("local-child")), (Mode::LocalChild, Some("mode:local-child".into())));
        assert_eq!(mode_and_note(Some("local-scratch")), (Mode::LocalScratch, Some("mode:local-scratch".into())));
        assert_eq!(mode_and_note(Some("remote")), (Mode::Remote, Some("mode:remote(unimplemented)".into())));
        assert_eq!(mode_and_note(Some("garbage")), (Mode::Passthrough, Some("mode_invalid:garbage".into())));
        let long = "x".repeat(200);
        let (_, note) = mode_and_note(Some(&long));
        assert_eq!(note.unwrap().len(), "mode_invalid:".len() + 64, "the echoed value is capped");
    }

    #[test]
    fn piped_matrix() {
        let session = session_argv();
        let session_payload = match classify(&session) {
            Route::Remote(s) => s,
            other => panic!("{other:?}"),
        };
        let auth = v(&["auth", "status", "--json"]);
        let routes: [(Route, &[String]); 8] = [
            (Route::Remote(session_payload.clone()), &session),
            (Route::Local(LocalReason::OutsideRoots), &session),
            (Route::Local(LocalReason::Unconfigured), &session),
            (Route::Local(LocalReason::Subcommand("auth".into())), &auth),
            (Route::Local(LocalReason::Version), &[]),
            (Route::Local(LocalReason::NoArgs), &[]),
            (Route::Local(LocalReason::Bare), &[]),
            (Route::Local(LocalReason::NotStreamJson), &[]),
        ];
        for mode in [Mode::Passthrough, Mode::Remote] {
            for (route, args) in &routes {
                assert_eq!(piped(mode, route, args), None, "{mode:?} {route:?}");
            }
        }
        for mode in [Mode::LocalChild, Mode::LocalScratch] {
            for (i, (route, args)) in routes.iter().enumerate() {
                let got = piped(mode, route, args);
                if i < 3 {
                    assert_eq!(got.as_ref(), Some(&session_payload), "{mode:?} {route:?}");
                } else {
                    assert_eq!(got, None, "{mode:?} {route:?}");
                }
            }
        }
        // A demoted reason whose argv is not a session shape never pipes.
        assert_eq!(piped(Mode::LocalChild, &Route::Local(LocalReason::OutsideRoots), &auth), None);
    }

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// The verified 2.1.278 chat-session shape.
    fn session_argv() -> Vec<String> {
        v(&[
            "--output-format",
            "stream-json",
            "--verbose",
            "--input-format",
            "stream-json",
            "--permission-prompt-tool",
            "stdio",
            "--setting-sources=user,project,local",
            "--permission-mode",
            "default",
            "--include-partial-messages",
            "--debug",
            "--debug-to-stderr",
            "--enable-auth-status",
            "--no-chrome",
            "--replay-user-messages",
        ])
    }

    /// The config probe: a stream-json spawn with thinking disabled.
    fn config_probe_argv() -> Vec<String> {
        v(&["--output-format", "stream-json", "--verbose", "--input-format", "stream-json", "--thinking", "disabled", "--permission-mode", "default", "--debug", "--debug-to-stderr", "--enable-auth-status", "--no-chrome", "--replay-user-messages"])
    }

    /// `<parent>/{root, root2, root/inside}` plus a config whose only root is `<parent>/root`.
    struct Roots {
        _parent: tempfile::TempDir,
        root: PathBuf,
        inside: PathBuf,
        sibling: PathBuf,
        cfg: BridgeConfig,
    }

    fn roots() -> Roots {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let inside = root.join("inside");
        let sibling = parent.path().join("root2");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir(&sibling).unwrap();
        let cfg = BridgeConfig::parse(&format!("[workspaces]\nroots = [{:?}]\n", root)).unwrap();
        Roots { _parent: parent, root, inside, sibling, cfg }
    }

    #[test]
    fn session_inside_root_is_remote() {
        let r = roots();
        for argv in [session_argv(), config_probe_argv()] {
            match decide(&argv, Some(&r.inside), Some(&r.cfg)) {
                Route::Remote(s) => assert_eq!(s.permission_mode.as_deref(), Some("default")),
                other => panic!("inside the root: {other:?}"),
            }
            assert!(matches!(decide(&argv, Some(&r.root), Some(&r.cfg)), Route::Remote(_)), "cwd == root is inside");
        }
    }

    #[test]
    fn session_outside_root_or_without_cwd_is_outside_roots() {
        let r = roots();
        let argv = session_argv();
        assert_eq!(decide(&argv, Some(&r.sibling), Some(&r.cfg)), Route::Local(LocalReason::OutsideRoots), "sibling-prefix dir");
        let elsewhere = tempfile::tempdir().unwrap();
        assert_eq!(decide(&argv, Some(elsewhere.path()), Some(&r.cfg)), Route::Local(LocalReason::OutsideRoots));
        assert_eq!(decide(&argv, None, Some(&r.cfg)), Route::Local(LocalReason::OutsideRoots), "cwd unknown");
        assert_eq!(decide(&argv, Some(&r.inside), Some(&BridgeConfig::default())), Route::Local(LocalReason::OutsideRoots), "no roots at all");
    }

    #[test]
    fn session_without_config_is_unconfigured() {
        let r = roots();
        assert_eq!(decide(&session_argv(), Some(&r.inside), None), Route::Local(LocalReason::Unconfigured));
        assert_eq!(decide(&config_probe_argv(), None, None), Route::Local(LocalReason::Unconfigured), "config wins over cwd");
        assert_eq!(LocalReason::Unconfigured.name(), "unconfigured");
        assert_eq!(LocalReason::OutsideRoots.name(), "outside_roots");
    }

    #[test]
    fn local_shapes_ignore_cwd_and_config() {
        let r = roots();
        let table: [(&[&str], LocalReason); 6] = [
            (&["auth", "status", "--json"], LocalReason::Subcommand("auth".into())),
            (&["mcp", "add", "--scope", "user", "--", "github", "…"], LocalReason::Subcommand("mcp".into())),
            (&["--version"], LocalReason::Version),
            (&["--output-format", "stream-json", "--bare"], LocalReason::Bare),
            (&["--claude-in-chrome-mcp", "--output-format", "stream-json"], LocalReason::ChromeMcp),
            (&["--output-format", "json", "-p", "hi"], LocalReason::NotStreamJson),
        ];
        for (argv, want) in table {
            let argv = v(argv);
            let want = Route::Local(want);
            assert_eq!(decide(&argv, Some(&r.inside), Some(&r.cfg)), want, "{argv:?} inside");
            assert_eq!(decide(&argv, Some(&r.sibling), Some(&r.cfg)), want, "{argv:?} outside");
            assert_eq!(decide(&argv, None, None), want, "{argv:?} no cwd, no config");
        }
        assert_eq!(decide(&[], Some(&r.inside), Some(&r.cfg)), Route::Local(LocalReason::NoArgs));
    }

    #[test]
    fn cwd_under_roots_component_wise() {
        let r = roots();
        let root: &Path = &r.root;
        assert!(cwd_under_roots(&r.inside, &[root]), "subdirectory");
        assert!(cwd_under_roots(root, &[root]), "cwd == root");
        assert!(!cwd_under_roots(&r.sibling, &[root]), "`<root>2` shares a string prefix, not a component");
        assert!(!cwd_under_roots(root, &[&r.inside]), "the root is not under its own subdirectory");
        assert!(!cwd_under_roots(&r.inside, &[]), "no roots");
        assert!(!cwd_under_roots(&r.inside, &[Path::new("")]), "an empty root matches nothing");
        let other = tempfile::tempdir().unwrap();
        assert!(cwd_under_roots(&r.inside, &[other.path(), root]), "any root suffices");
    }

    #[cfg(unix)]
    #[test]
    fn cwd_under_roots_follows_a_symlinked_cwd() {
        let r = roots();
        let elsewhere = tempfile::tempdir().unwrap();
        let link = elsewhere.path().join("link");
        std::os::unix::fs::symlink(&r.inside, &link).unwrap();
        assert!(cwd_under_roots(&link, &[&r.root]), "the symlink resolves inside the root");
        assert!(matches!(decide(&session_argv(), Some(&link), Some(&r.cfg)), Route::Remote(_)));
        let out = r.root.join("out");
        std::os::unix::fs::symlink(elsewhere.path(), &out).unwrap();
        assert!(!cwd_under_roots(&out, &[&r.root]), "a symlink inside the root that points outside is outside");
    }

    #[test]
    fn cwd_under_roots_with_a_missing_root_compares_raw_paths() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("missing");
        let inside = missing.join("sub");
        assert!(cwd_under_roots(&inside, &[&missing]), "neither side exists: raw comparison");
        assert!(cwd_under_roots(&missing, &[&missing]));
        let prefix = d.path().join("missing2");
        assert!(!cwd_under_roots(&prefix, &[&missing]));
        let existing = d.path().join("real");
        std::fs::create_dir(&existing).unwrap();
        assert!(!cwd_under_roots(&existing, &[&missing]), "an existing cwd is never under a root that does not exist");
    }

    #[test]
    fn workspace_path_counts_as_a_root() {
        let r = roots();
        let ws = r.root.join("ws");
        std::fs::create_dir(&ws).unwrap();
        let toml = format!("[[workspace]]\npath = {:?}\nbranch = \"main\"\n", ws);
        let cfg = BridgeConfig::parse(&toml).unwrap();
        assert_eq!(cfg.roots(), vec![ws.as_path()]);
        assert!(matches!(decide(&session_argv(), Some(&ws), Some(&cfg)), Route::Remote(_)), "cwd == the workspace path");
        let deeper = ws.join("crates");
        std::fs::create_dir(&deeper).unwrap();
        assert!(matches!(decide(&session_argv(), Some(&deeper), Some(&cfg)), Route::Remote(_)));
        assert_eq!(decide(&session_argv(), Some(&r.inside), Some(&cfg)), Route::Local(LocalReason::OutsideRoots), "the workspace's parent is not a root");
    }

    #[test]
    fn load_for_wrapper_never_panics() {
        // Reads the real environment: only the invariants are checked.
        let loaded = load_for_wrapper();
        if loaded.paths.is_none() {
            assert!(loaded.cfg.is_none());
            assert!(loaded.note.is_some(), "no paths means HOME is unset, and that is worth a note");
        }
        if loaded.cfg.is_some() {
            assert!(loaded.note.is_none(), "a loaded config has nothing to note");
        }
        assert_eq!(Loaded::default(), Loaded { paths: None, cfg: None, note: None });
    }
}
