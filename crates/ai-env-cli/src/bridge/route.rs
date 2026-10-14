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
//!   `Loaded::note`, never on stderr). In remote mode a `bridge.toml` that
//!   exists but does not load is the exception ([`decide_loaded`]): the
//!   roots it still names, read as plain TOML ([`Broken`]), route a session
//!   `Remote`, and P0 fails it closed naming the error (S8 L1: never a
//!   silent local run).
//!
//! Roots are `[workspaces].roots` ∪ `[[workspace]].path`
//! (`BridgeConfig::roots`), each canonicalised when it exists so a symlinked
//! cwd still matches; the comparison is component-wise (`Path::starts_with`):
//! cwd == root matches, `/a/b2` is not under `/a/b`.
//!
//! The mode ([`Mode`], [`effective_mode`]) decides what happens to a
//! stream-json session: `AI_ENV_BRIDGE_MODE` wins when it names a mode,
//! else `[wrapper].mode` (S8 L1; of a `bridge.toml` that does not load, as
//! far as it reads: [`effective_mode_loaded`]), else passthrough, S1's exec
//! for every route; `local-child` and
//! `local-scratch` (the variable only) pipe it through the S2 pump
//! ([`piped`]); `remote` pipes a session under the roots to the workspace's
//! MicroVM (S8) and execs everything else.
use crate::bridge::config::{BridgeConfig, Paths, WorkspaceCfg, WorkspacesCfg, WrapperMode};
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
    /// What a `bridge.toml` that exists but does not load still says (its
    /// mode and roots), so remote mode fails a session under its roots
    /// closed rather than running it on the Mac ([`decide_loaded`],
    /// [`effective_mode_loaded`]); `None` when the file loaded or is absent.
    pub broken: Option<Broken>,
}

/// What a `bridge.toml` that exists but does not load (a TOML error, an
/// unknown key, a wrong type, another `[aws].region`, a file that cannot be
/// read) still says, read as plain TOML: the keys the wrapper routes on, so
/// one bad line never turns a remote session into a run on the Mac (S8 L1).
#[derive(Debug, Clone, PartialEq)]
pub struct Broken {
    /// `[wrapper].mode`: `Some(None)` when the file is TOML without it,
    /// `Some(Some(value))` when it is a string; `None` when it cannot be read
    /// (the file is not TOML or cannot be read, or the value is no string).
    pub mode: Option<Option<String>>,
    /// `[workspaces].roots` then each `[[workspace]].path`, as written;
    /// `None` when `[workspaces]` or `[[workspace]]` does not match its
    /// schema (a misspelt or mistyped key), or the file is not TOML or
    /// cannot be read.
    pub roots: Option<Vec<PathBuf>>,
}

impl Broken {
    /// `text` (`None`: the file could not be read) read as plain TOML:
    /// `[wrapper].mode`, and `[workspaces]` and `[[workspace]]` each with its
    /// own schema (`lenient_roots`); every other table and key ignored.
    #[must_use]
    pub fn read(text: Option<&str>) -> Broken {
        let Some(table) = text.and_then(|t| toml::from_str::<toml::Table>(t).ok()) else {
            return Broken { mode: None, roots: None };
        };
        let mode = match table.get("wrapper") {
            None => Some(None),
            Some(wrapper) => match wrapper.as_table().map(|w| w.get("mode")) {
                Some(None) => Some(None),
                Some(Some(toml::Value::String(mode))) => Some(Some(mode.clone())),
                _ => None,
            },
        };
        Broken { mode, roots: lenient_roots(&table) }
    }
}

/// `[workspaces].roots` then each `[[workspace]].path` of `table` (a
/// workspace without a path names no root, as [`BridgeConfig::roots`]
/// takes it), the two tables read with their own schema: `None` when one
/// does not match it, so a misspelt `roots` or `path` never drops a root
/// unseen (every other table of the file stays ignored).
fn lenient_roots(table: &toml::Table) -> Option<Vec<PathBuf>> {
    let listed: WorkspacesCfg = match table.get("workspaces") {
        Some(v) => v.clone().try_into().ok()?,
        None => WorkspacesCfg::default(),
    };
    let workspaces: Vec<WorkspaceCfg> = match table.get("workspace") {
        Some(v) => v.clone().try_into().ok()?,
        None => Vec::new(),
    };
    Some(listed.roots.into_iter().chain(workspaces.into_iter().map(|w| w.path)).filter(|p| !p.as_os_str().is_empty()).collect())
}

/// `Paths::resolve()` then `BridgeConfig::load(&paths)`, folding every failure
/// into `Loaded` so the wrapper always goes on: to exec the real binary, or,
/// for a remote session under the roots of a `bridge.toml` that does not
/// load ([`Broken`]), to the remote session's P0, which fails it closed.
#[must_use]
pub fn load_for_wrapper() -> Loaded {
    match Paths::resolve() {
        Ok(paths) => load_at(paths),
        Err(e) => Loaded { paths: None, cfg: None, note: Some(first_line(&e.to_string())), broken: None },
    }
}

/// [`load_for_wrapper`] once the paths resolved: a `bridge.toml` that does
/// not load is noted (its error's first line) and read again as plain TOML.
fn load_at(paths: Paths) -> Loaded {
    match BridgeConfig::load(&paths) {
        Ok(Some(cfg)) => Loaded { paths: Some(paths), cfg: Some(cfg), note: None, broken: None },
        Ok(None) => Loaded { paths: Some(paths), cfg: None, note: None, broken: None },
        Err(e) => {
            let broken = Broken::read(std::fs::read_to_string(&paths.config).ok().as_deref());
            Loaded { paths: Some(paths), cfg: None, note: Some(first_line(&e.to_string())), broken: Some(broken) }
        }
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

/// [`decide`] on what [`load_for_wrapper`] found, in `mode`. In remote mode
/// a `bridge.toml` that exists but does not load still routes: a stream-json
/// session is `Remote` when its cwd is under the roots [`Broken`] read, or
/// when those cannot be read, and P0 then fails it closed, exit 1 naming
/// the error (S8 L1: never a silent local run); else `Local(OutsideRoots)`.
/// Every other mode keeps [`decide`]'s `Local(Unconfigured)` for it, and an
/// absent `bridge.toml` is `Local(Unconfigured)` in every mode.
#[must_use]
pub fn decide_loaded(args: &[String], cwd: Option<&Path>, loaded: &Loaded, mode: Mode) -> Route {
    let (Some(broken), Mode::Remote) = (&loaded.broken, mode) else {
        return decide(args, cwd, loaded.cfg.as_ref());
    };
    match classify(args) {
        Route::Remote(session) => {
            let under = match (&broken.roots, cwd) {
                (None, _) => true,
                (Some(roots), Some(dir)) => cwd_under_roots(dir, &roots.iter().map(PathBuf::as_path).collect::<Vec<_>>()),
                (Some(_), None) => false,
            };
            if under {
                Route::Remote(session)
            } else {
                Route::Local(LocalReason::OutsideRoots)
            }
        }
        local => local,
    }
}

/// `AI_ENV_BRIDGE_MODE`: whether a stream-json session is exec'd (S1) or
/// piped through the wrapper (S2's local modes, S8's remote one); when it
/// names a mode, it wins over `[wrapper].mode` ([`effective_mode`]).
pub const MODE_ENV: &str = "AI_ENV_BRIDGE_MODE";

/// How a stream-json session runs. Unset (and no `[wrapper].mode`) means
/// `Passthrough` — S1's exec for every route — so a daily Cursor setup is
/// untouched until a mode is chosen on purpose.
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
    /// S8: a stream-json session under the roots runs in the workspace's
    /// MicroVM through the pump's remote link, failing closed (an exit and
    /// one line, never a local run); every other route execs as `Passthrough`.
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

/// The mode from the environment alone plus the census note it earns
/// ([`mode_and_note`]). Reads one environment variable and nothing else, so
/// it may run on the exec path. The wrapper decides with [`effective_mode`].
#[must_use]
pub fn mode_from_env() -> (Mode, Option<String>) {
    let raw = std::env::var_os(MODE_ENV).map(|v| v.to_string_lossy().into_owned());
    mode_and_note(raw.as_deref())
}

/// `AI_ENV_BRIDGE_MODE`'s value as a mode, plus the census note it earns:
/// `mode:<name>` for a non-default mode (`mode:remote` for `remote`, one of
/// `remote::MODE_NOTES`), `mode_invalid:<value>` (scrubbed, ≤ 64 chars) for
/// an unknown value — which also prints one stderr line and falls back to
/// passthrough.
#[must_use]
pub fn mode_and_note(raw: Option<&str>) -> (Mode, Option<String>) {
    match parse_mode(raw) {
        Ok(Mode::Passthrough) => (Mode::Passthrough, None),
        Ok(mode) => (mode, Some(format!("mode:{}", mode.name()))),
        Err(value) => {
            let shown = shown_value(&value);
            eprintln!("ai-env-claude: {MODE_ENV}={shown} unknown; passthrough");
            (Mode::Passthrough, Some(format!("mode_invalid:{shown}")))
        }
    }
}

/// A value fit for the census: scrubbed, at most 64 characters.
fn shown_value(value: &str) -> String {
    crate::wire::redact::scrub(value).chars().take(64).collect()
}

/// The mode a stream-json session runs in (S8 L1), and the census note it
/// earns: `AI_ENV_BRIDGE_MODE` wins when it names a mode (`env`, as
/// [`mode_and_note`] reads it: tests, a window's own override); else
/// `[wrapper].mode` of `cfg` (`remote` notes `mode:remote(config)`); else
/// passthrough. A `[wrapper].mode` that is neither `passthrough` nor
/// `remote` is taken as remote, noted `mode_invalid:<value>(config)`: a
/// session under the roots then fails closed at the remote session's
/// prechecks, exit 1 naming the key, never a silent local run; every other
/// invocation execs as ever. A variable that names no mode (empty, a typo)
/// never overrides the config either: it is noted `mode_invalid:<value>`
/// beside the config's note, with one stderr line, and the config decides
/// (no config: passthrough, as S2).
#[must_use]
pub fn effective_mode(env: Option<&str>, cfg: Option<&BridgeConfig>) -> (Mode, Option<String>) {
    variable_over(env, config_mode(cfg.map(|c| c.wrapper.mode.as_str())))
}

/// [`effective_mode`] on what [`load_for_wrapper`] found. A `bridge.toml`
/// that exists but does not load keeps its say: its `[wrapper].mode` as
/// [`Broken`] read it counts as a loaded file's does (unset or `passthrough`:
/// passthrough, S1's exec with the load error noted), and a mode that cannot
/// be read (the file is not TOML or cannot be read, a value that is no
/// string) is taken as remote, noted `mode_unreadable(config)`, as an
/// unknown value is: a session under the roots then fails closed at P0,
/// naming the error ([`decide_loaded`]). The variable wins as ever when it
/// names a mode.
#[must_use]
pub fn effective_mode_loaded(env: Option<&str>, loaded: &Loaded) -> (Mode, Option<String>) {
    match &loaded.broken {
        None => effective_mode(env, loaded.cfg.as_ref()),
        Some(Broken { mode: Some(value), .. }) => variable_over(env, config_mode(value.as_deref())),
        Some(Broken { mode: None, .. }) => variable_over(env, (Mode::Remote, Some("mode_unreadable(config)".to_string()))),
    }
}

/// The mode `[wrapper].mode`'s value earns and its census note: no value
/// (no config, no key) or `passthrough` is passthrough; `remote` is noted
/// `mode:remote(config)`; any other value is taken as remote, noted
/// `mode_invalid:<value>(config)` ([`effective_mode`]).
fn config_mode(value: Option<&str>) -> (Mode, Option<String>) {
    let Some(value) = value else { return (Mode::Passthrough, None) };
    match WrapperMode::parse(value) {
        Some(WrapperMode::Passthrough) => (Mode::Passthrough, None),
        Some(WrapperMode::Remote) => (Mode::Remote, Some("mode:remote(config)".to_string())),
        None => (Mode::Remote, Some(format!("mode_invalid:{}(config)", shown_value(value)))),
    }
}

/// [`effective_mode`]'s rule for the variable over `config` (the mode the
/// file earns, and its note): the variable's mode when it names one; else
/// `config`, a variable that names no mode noted beside its note, with one
/// stderr line.
fn variable_over(env: Option<&str>, config: (Mode, Option<String>)) -> (Mode, Option<String>) {
    let shown = match env.map(|v| parse_mode(Some(v))) {
        Some(Ok(_)) => return mode_and_note(env),
        Some(Err(value)) => shown_value(&value),
        None => return config,
    };
    let (mode, note) = config;
    eprintln!("ai-env-claude: {MODE_ENV}={shown} unknown; {}", mode.name());
    let invalid = format!("mode_invalid:{shown}");
    (mode, Some(note.map_or_else(|| invalid.clone(), |n| format!("{invalid}; {n}"))))
}

/// The session payload when this invocation is piped, else `None` (exec).
/// `Passthrough` never pipes. `Remote` (S8) pipes exactly a stream-json
/// session under the roots (`Route::Remote`, which a `bridge.toml` that does
/// not load still gives: [`decide_loaded`]); every other route — outside
/// the roots, without a `bridge.toml`, a subcommand — execs locally as
/// passthrough does. The two local modes pipe every stream-json session
/// shape — `Remote(_)` and the two demoted reasons
/// `Local(OutsideRoots | Unconfigured)`, whose payload comes from `classify`
/// again — because a local child needs neither roots nor a `bridge.toml`.
/// Every other `Local` reason (subcommands, `--version`, `--bare`, …) execs.
#[must_use]
pub fn piped(mode: Mode, route: &Route, args: &[String]) -> Option<SessionArgs> {
    match mode {
        Mode::Passthrough => None,
        Mode::Remote => match route {
            Route::Remote(s) => Some(s.clone()),
            Route::Local(_) => None,
        },
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
        assert_eq!(mode_and_note(Some("remote")), (Mode::Remote, Some("mode:remote".into())));
        assert_eq!(crate::bridge::remote::MODE_NOTES[0], "mode:remote", "C6's note from the variable");
        assert_eq!(mode_and_note(Some("garbage")), (Mode::Passthrough, Some("mode_invalid:garbage".into())));
        let long = "x".repeat(200);
        let (_, note) = mode_and_note(Some(&long));
        assert_eq!(note.unwrap().len(), "mode_invalid:".len() + 64, "the echoed value is capped");
    }

    /// S8 L1: the variable wins (even over a `[wrapper].mode`) when it names
    /// a mode, else the config's mode, else passthrough; an invalid config
    /// value is taken as remote (the session fails closed at its prechecks)
    /// with its own note; a variable that names no mode (empty, a typo)
    /// leaves the decision to the config, noted beside it.
    #[test]
    fn effective_mode_prefers_the_variable_then_the_config() {
        let with = |mode: &str| BridgeConfig::parse(&format!("[wrapper]\nmode = {mode:?}\n")).unwrap();
        let (remote, passthrough, garbage) = (with("remote"), with("passthrough"), with("remotely"));
        assert_eq!(effective_mode(None, None), (Mode::Passthrough, None), "nothing configured");
        assert_eq!(effective_mode(None, Some(&BridgeConfig::default())), (Mode::Passthrough, None), "the default config");
        assert_eq!(effective_mode(None, Some(&passthrough)), (Mode::Passthrough, None));
        assert_eq!(effective_mode(None, Some(&remote)), (Mode::Remote, Some("mode:remote(config)".into())));
        assert_eq!(crate::bridge::remote::MODE_NOTES[1], "mode:remote(config)", "C6's note from the config");
        assert_eq!(effective_mode(Some("remote"), None), (Mode::Remote, Some("mode:remote".into())), "the variable alone");
        assert_eq!(effective_mode(Some("passthrough"), Some(&remote)), (Mode::Passthrough, None), "the variable wins over the config");
        assert_eq!(effective_mode(Some("remote"), Some(&passthrough)), (Mode::Remote, Some("mode:remote".into())));
        assert_eq!(effective_mode(Some("local-child"), Some(&remote)), (Mode::LocalChild, Some("mode:local-child".into())));
        assert_eq!(effective_mode(Some("garbage"), Some(&remote)), (Mode::Remote, Some("mode_invalid:garbage; mode:remote(config)".into())), "an unknown variable never overrides remote");
        assert_eq!(effective_mode(Some(""), Some(&remote)), (Mode::Remote, Some("mode_invalid:; mode:remote(config)".into())), "nor does an empty one");
        assert_eq!(effective_mode(Some("garbage"), Some(&garbage)), (Mode::Remote, Some("mode_invalid:garbage; mode_invalid:remotely(config)".into())), "an invalid config still fails closed");
        assert_eq!(effective_mode(Some("garbage"), Some(&passthrough)), (Mode::Passthrough, Some("mode_invalid:garbage".into())));
        assert_eq!(effective_mode(Some("garbage"), None), (Mode::Passthrough, Some("mode_invalid:garbage".into())), "no config: passthrough, as S2");
        assert_eq!(effective_mode(None, Some(&garbage)), (Mode::Remote, Some("mode_invalid:remotely(config)".into())), "fails closed");
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
        for (route, args) in &routes {
            assert_eq!(piped(Mode::Passthrough, route, args), None, "passthrough {route:?}");
        }
        // S8: remote pipes exactly a session under the roots; outside them, unconfigured or a subcommand execs.
        for (i, (route, args)) in routes.iter().enumerate() {
            assert_eq!(piped(Mode::Remote, route, args), (i == 0).then(|| session_payload.clone()), "remote {route:?}");
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
            assert!(loaded.cfg.is_none() && loaded.broken.is_none());
            assert!(loaded.note.is_some(), "no paths means HOME is unset, and that is worth a note");
        }
        if loaded.cfg.is_some() {
            assert!(loaded.note.is_none() && loaded.broken.is_none(), "a loaded config has nothing to note");
        }
        if loaded.broken.is_some() {
            assert!(loaded.cfg.is_none() && loaded.note.is_some(), "a file that does not load is noted");
        }
        assert_eq!(Loaded::default(), Loaded { paths: None, cfg: None, note: None, broken: None });
    }

    /// The load: an absent bridge.toml is no note and nothing broken; one
    /// that loads is the config; one that does not is its error's first line
    /// (no TOML snippet) and what [`Broken`] reads of it; one that cannot be
    /// read (a directory here) is its error, and nothing reads.
    #[test]
    fn a_bridge_toml_that_does_not_load_is_noted_and_read_as_plain_toml() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().to_path_buf(), None);
        assert_eq!(load_at(paths.clone()), Loaded { paths: Some(paths.clone()), cfg: None, note: None, broken: None }, "absent");
        std::fs::write(&paths.config, "[wrapper]\nmode = \"remote\"\n").unwrap();
        let loaded = load_at(paths.clone());
        assert!(loaded.cfg.is_some() && loaded.note.is_none() && loaded.broken.is_none(), "{loaded:?}");
        std::fs::write(&paths.config, "[wrapper]\nmode = \"remote\"\n[vm]\nmax_idle = 300\n").unwrap();
        let loaded = load_at(paths.clone());
        assert_eq!(loaded.cfg, None);
        let note = loaded.note.clone().unwrap_or_default();
        assert!(note.starts_with("config: bridge.toml: TOML parse error at line 4") && !note.contains("max_idle"), "the first line only: {note}");
        assert_eq!(loaded.broken, Some(Broken { mode: Some(Some("remote".into())), roots: Some(Vec::new()) }));
        std::fs::remove_file(&paths.config).unwrap();
        std::fs::create_dir(&paths.config).unwrap();
        let loaded = load_at(paths);
        assert!(loaded.note.as_deref().is_some_and(|n| n.starts_with("config: cannot read ")), "{loaded:?}");
        assert_eq!(loaded.broken, Some(Broken { mode: None, roots: None }));
    }

    /// What a bridge.toml that does not load still says: the keys the
    /// wrapper routes on, past an unknown key or a wrong type elsewhere; each
    /// `None` when it cannot be read (another type, a misspelt or mistyped
    /// key in the roots' two tables, or no TOML at all).
    #[test]
    fn a_broken_bridge_toml_is_read_as_plain_toml() {
        let read = |text: &str| Broken::read(Some(text));
        let roots = |list: &[&str]| Some(list.iter().map(PathBuf::from).collect::<Vec<_>>());
        let text = "[workspaces]\nroots = [\"/a\", \"/b\"]\n[wrapper]\nmode = \"remote\"\nstrip_debug = \"yes\"\n[vm]\nmax_idle = 300\n[[workspace]]\npath = \"/c\"\n[[workspace]]\nbranch = \"main\"\n";
        assert!(BridgeConfig::parse(text).is_err(), "the file does not load");
        assert_eq!(read(text), Broken { mode: Some(Some("remote".into())), roots: roots(&["/a", "/b", "/c"]) }, "a workspace without a path names no root");
        assert_eq!(read("[aws]\nregion = \"eu-west-3\"\n"), Broken { mode: Some(None), roots: roots(&[]) }, "no mode, no roots");
        assert_eq!(read("[wrapper]\nstrip_debug = true\n").mode, Some(None));
        for (text, what) in [("[wrapper]\nmode = 1\n", "a mode that is no string"), ("wrapper = \"remote\"\n", "a [wrapper] that is no table")] {
            assert_eq!(read(text).mode, None, "{what}");
        }
        for (text, what) in [
            ("[workspaces]\nroots = \"/a\"\n", "roots that are no list"),
            ("[workspaces]\nroots = [\"/a\", 1]\n", "a root that is no string"),
            ("workspaces = [\"/a\"]\n", "a [workspaces] that is no table"),
            ("[[workspace]]\npath = 1\n", "a workspace path that is no string"),
            ("[workspace]\npath = \"/a\"\n", "a [workspace] that is no list"),
            ("[workspaces]\nroot = [\"/a\"]\n", "a misspelt roots key"),
            ("[[workspace]]\npth = \"/a\"\n", "a misspelt path key"),
            ("[[workspace]]\npath = \"/a\"\nmemory_mib = \"big\"\n", "a mistyped key beside the path"),
        ] {
            assert_eq!(read(text).roots, None, "{what}");
        }
        // Not TOML at all (a hand edit that defines [wrapper] twice), or a file that cannot be read.
        let nothing = Broken { mode: None, roots: None };
        assert_eq!(read("[wrapper]\nmode = \"remote\"\n[wrapper]\nmode = \"remote\"\n"), nothing);
        assert_eq!(Broken::read(None), nothing);
    }

    /// In remote mode a bridge.toml that does not load still routes a
    /// session on the roots [`Broken`] read (none readable: every cwd is
    /// under them, and P0 fails the session closed); every other mode keeps
    /// S1's `Local(Unconfigured)`, and nothing broken is [`decide`]'s.
    #[test]
    fn a_broken_bridge_toml_routes_a_remote_session_on_its_roots() {
        let r = roots();
        let broken = |roots: Option<Vec<PathBuf>>| Loaded { broken: Some(Broken { mode: Some(Some("remote".into())), roots }), ..Loaded::default() };
        let (listed, unreadable) = (broken(Some(vec![r.root.clone()])), broken(None));
        let (session, auth) = (session_argv(), v(&["auth", "status", "--json"]));
        assert!(matches!(decide_loaded(&session, Some(&r.inside), &listed, Mode::Remote), Route::Remote(_)));
        assert!(matches!(decide_loaded(&config_probe_argv(), Some(&r.root), &listed, Mode::Remote), Route::Remote(_)), "cwd == root");
        assert_eq!(decide_loaded(&session, Some(&r.sibling), &listed, Mode::Remote), Route::Local(LocalReason::OutsideRoots));
        assert_eq!(decide_loaded(&session, None, &listed, Mode::Remote), Route::Local(LocalReason::OutsideRoots), "cwd unknown");
        for cwd in [Some(r.inside.as_path()), Some(r.sibling.as_path()), None] {
            assert!(matches!(decide_loaded(&session, cwd, &unreadable, Mode::Remote), Route::Remote(_)), "{cwd:?}: roots that cannot be read hold every cwd");
        }
        assert_eq!(decide_loaded(&auth, Some(&r.inside), &unreadable, Mode::Remote), Route::Local(LocalReason::Subcommand("auth".into())), "a subcommand stays local");
        for mode in [Mode::Passthrough, Mode::LocalChild, Mode::LocalScratch] {
            for loaded in [&listed, &unreadable] {
                assert_eq!(decide_loaded(&session, Some(&r.inside), loaded, mode), Route::Local(LocalReason::Unconfigured), "{mode:?}");
            }
        }
        let parsed = Loaded { cfg: Some(r.cfg.clone()), ..Loaded::default() };
        assert!(matches!(decide_loaded(&session, Some(&r.inside), &parsed, Mode::Remote), Route::Remote(_)));
        assert_eq!(decide_loaded(&session, Some(&r.sibling), &parsed, Mode::Remote), Route::Local(LocalReason::OutsideRoots));
        assert_eq!(decide_loaded(&session, Some(&r.inside), &Loaded::default(), Mode::Remote), Route::Local(LocalReason::Unconfigured), "an absent bridge.toml");
    }

    /// The mode of a bridge.toml that does not load is its `[wrapper].mode`
    /// as far as [`Broken`] reads it, one that cannot be read taken as
    /// remote (as an unknown value is); the variable still wins when it
    /// names a mode; nothing broken is [`effective_mode`]'s.
    #[test]
    fn a_broken_bridge_toml_keeps_its_mode() {
        let broken = |mode: Option<Option<&str>>| Loaded { broken: Some(Broken { mode: mode.map(|m| m.map(str::to_string)), roots: None }), ..Loaded::default() };
        let (remote, unreadable) = (broken(Some(Some("remote"))), broken(None));
        assert_eq!(effective_mode_loaded(None, &remote), (Mode::Remote, Some("mode:remote(config)".into())));
        assert_eq!(effective_mode_loaded(None, &broken(Some(Some("remotely")))), (Mode::Remote, Some("mode_invalid:remotely(config)".into())));
        assert_eq!(effective_mode_loaded(None, &unreadable), (Mode::Remote, Some("mode_unreadable(config)".into())), "a mode that cannot be read fails closed");
        assert_eq!(effective_mode_loaded(None, &broken(Some(Some("passthrough")))), (Mode::Passthrough, None));
        assert_eq!(effective_mode_loaded(None, &broken(Some(None))), (Mode::Passthrough, None), "no mode: S1's passthrough");
        assert_eq!(effective_mode_loaded(Some("passthrough"), &remote), (Mode::Passthrough, None), "the variable wins");
        assert_eq!(effective_mode_loaded(Some("passthrough"), &unreadable), (Mode::Passthrough, None));
        assert_eq!(effective_mode_loaded(Some("local-child"), &unreadable), (Mode::LocalChild, Some("mode:local-child".into())));
        assert_eq!(effective_mode_loaded(Some("remote"), &broken(Some(None))), (Mode::Remote, Some("mode:remote".into())));
        assert_eq!(effective_mode_loaded(Some("garbage"), &remote), (Mode::Remote, Some("mode_invalid:garbage; mode:remote(config)".into())), "an unknown variable never overrides it");
        assert_eq!(effective_mode_loaded(Some("garbage"), &unreadable), (Mode::Remote, Some("mode_invalid:garbage; mode_unreadable(config)".into())));
        assert_eq!(effective_mode_loaded(Some("remote"), &Loaded::default()), (Mode::Remote, Some("mode:remote".into())), "nothing broken");
        assert_eq!(effective_mode_loaded(None, &Loaded::default()), (Mode::Passthrough, None));
    }
}
