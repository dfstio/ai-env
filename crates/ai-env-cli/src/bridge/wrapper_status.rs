//! `ai-env wrapper status [--json]` (plans/wrapper-status-uninstall-plan.md
//! §2): whether Cursor's `claudeCode.claudeProcessWrapper` is set, which
//! `ai-env-claude` it runs, the mode and roots Cursor's chats get, whether
//! bridge.toml passes the checks a remote session runs at its start, and which
//! extension Cursor last ran. Read-only: no AWS call, no Touch ID, no write;
//! the one process it starts is the sibling's `--version`, as doctor and
//! install do (never claude, never the path the settings name). The rows are
//! doctor's (its row builders where one fits, its tags) and so is the report
//! (`commands::doctor_report_under`: exit 1 only on a `[NO ]` row, so "not
//! installed" is `[-  ]` and exit 0; `--json` is `doctor --json`'s shape).
//!
//! Of Cursor's `claudeCode.environmentVariables` it reads the four names that
//! steer the wrapper ([`CursorEnv`]) and nothing else: no other entry's name
//! or value is ever printed; of those four it shows whether
//! `AI_ENV_BRIDGE_LOCAL` is `1`, and the others' values scrubbed and capped.
use crate::bridge::census::read_tail;
use crate::bridge::config::{BridgeConfig, Paths, WrapperMode};
use crate::bridge::doctor::{
    cursor_settings_path, installed_extension_names, parse_settings, pick_bundle, row_bridge_config, row_cursor_bundle, row_same_version, row_settings_unparseable, row_sibling, row_wrapper_setting, rows_s8_loaded,
    run_capture, strip_jsonc, WRAPPER_SETTING,
};
use crate::bridge::errors::BridgeError;
use crate::bridge::remote::env::session_env;
use crate::bridge::remote::link::StartStep;
use crate::bridge::remote::{Failure, MODE_NOTES};
use crate::bridge::route::{effective_mode_loaded, load_for_wrapper, parse_mode, Broken, Loaded, Mode, MODE_ENV};
use crate::bridge::sibling::{exists_exec, find_sibling, Sibling};
use crate::bridge::vm::cmd::config_checks;
use crate::bridge::vm::run::{Egress, RunFlags, RunPlan};
use crate::commands::{doctor_report_under, DoctorLine, Tag};
use crate::errors::Result;
use crate::wire::redact::scrub;
use crate::wire::time::{parse_rfc3339, rfc3339_utc, rfc3339_utc_ms};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

/// The Cursor setting that holds the variables the extension sets for every
/// process it starts.
pub const ENV_SETTING: &str = "claudeCode.environmentVariables";
/// The wrapper's kill switch (bin/ai-env-claude.rs): exactly `1` execs the
/// real binary, with no census and no config read.
pub(crate) const LOCAL_ENV: &str = "AI_ENV_BRIDGE_LOCAL";
/// The bridge root and the bridge.toml the wrapper reads (`Paths::resolve`).
const DIR_ENV: &str = "AI_ENV_BRIDGE_DIR";
const CONFIG_ENV: &str = "AI_ENV_BRIDGE_CONFIG";
/// How much of the census the extension rows read: its last 16 × 64 KiB
/// (`census::read_tail`), never the whole file.
pub const CENSUS_TAIL_CHUNKS: usize = 16;
/// The longest mode value shown, as the census caps it.
const MODE_SHOWN: usize = 64;
/// The longest path value shown (`AI_ENV_BRIDGE_DIR`, `AI_ENV_BRIDGE_CONFIG`).
const PATH_SHOWN: usize = 256;

// ---- Cursor's variables ---------------------------------------------------------

/// JS's `String()` of a settings value, which the extension applies to each
/// variable's value: a string as it is, a whole number without `.0`, a list
/// as its items joined by commas, an object as `[object Object]`, null empty.
fn js_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() && f.fract() == 0.0 && f.abs() < 1e21 => format!("{f:.0}"),
            _ => n.to_string(),
        },
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// The value Cursor gives the variable `name` from its
/// `claudeCode.environmentVariables`, read as the extension (2.1.296 to
/// 2.1.300) reads it at every spawn: a list of `{"name", "value"}` objects
/// (an entry without a string name is skipped) or an object of names; a null
/// or missing value is empty, any other is [`js_string`]'s, and a later entry
/// of the name wins. `None` when it is not set. No other entry's value is read.
#[must_use]
pub fn cursor_variable(settings: &Value, name: &str) -> Option<String> {
    let value = match settings.get(ENV_SETTING)? {
        Value::Array(entries) => entries.iter().rev().find(|e| e.get("name").and_then(Value::as_str) == Some(name)).map(|e| e.get("value").unwrap_or(&Value::Null)),
        Value::Object(names) => names.get(name),
        _ => None,
    }?;
    Some(js_string(value))
}

/// The four variables of Cursor's `claudeCode.environmentVariables` that
/// steer the wrapper ([`cursor_variable`]); nothing else of that setting is kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CursorEnv {
    /// `AI_ENV_BRIDGE_LOCAL`: whether it is exactly `1` (the kill switch);
    /// `None` when unset. Its value is not kept.
    pub local: Option<bool>,
    /// `AI_ENV_BRIDGE_MODE`, as set.
    pub mode: Option<String>,
    /// `AI_ENV_BRIDGE_DIR` and `AI_ENV_BRIDGE_CONFIG`, unless empty
    /// (`Paths::resolve` takes an empty one as unset).
    pub dir: Option<String>,
    pub config: Option<String>,
}

impl CursorEnv {
    /// The variables Cursor's parsed user settings set.
    #[must_use]
    pub fn of(settings: &Value) -> CursorEnv {
        let var = |name: &str| cursor_variable(settings, name);
        CursorEnv { local: var(LOCAL_ENV).map(|v| v == "1"), mode: var(MODE_ENV), dir: var(DIR_ENV).filter(|v| !v.is_empty()), config: var(CONFIG_ENV).filter(|v| !v.is_empty()) }
    }

    /// `AI_ENV_BRIDGE_MODE` when it names a mode (`route::parse_mode`): the
    /// only value `route::effective_mode_loaded` is given (one that names none
    /// would print the wrapper's stderr line).
    pub(crate) fn named_mode(&self) -> Option<&str> {
        self.mode.as_deref().filter(|m| parse_mode(Some(m)).is_ok())
    }

    /// `AI_ENV_BRIDGE_DIR` and `AI_ENV_BRIDGE_CONFIG` as set: each one's
    /// name, what it names, its value, this command's own (`paths`; `None`
    /// when they did not resolve) and whether the two are the same.
    fn locations<'a>(&'a self, paths: Option<&'a Paths>) -> impl Iterator<Item = (&'static str, &'static str, &'a str, Option<&'a Path>, bool)> {
        [(DIR_ENV, "bridge root", &self.dir, paths.map(|p| p.root.as_path())), (CONFIG_ENV, "bridge.toml", &self.config, paths.map(|p| p.config.as_path()))]
            .into_iter()
            .filter_map(|(name, what, value, ours)| value.as_deref().map(|v| (name, what, v, ours, ours.is_some_and(|o| Path::new(v) == o))))
    }

    /// The variables of [`CursorEnv::locations`] that name a bridge root or a
    /// bridge.toml other than this command's (`paths`), each as its row in
    /// [`rows_cursor_env`] shows it: `NAME="value"`, scrubbed and capped.
    #[must_use]
    pub(crate) fn elsewhere(&self, paths: Option<&Paths>) -> Vec<String> {
        self.locations(paths).filter(|l| !l.4).map(|(name, _, value, _, _)| format!("{name}={}", shown(value, PATH_SHOWN))).collect()
    }
}

/// A variable's value fit for a row: scrubbed, at most `max` characters,
/// quoted (a quote or a newline in it stays inside the row).
fn shown(value: &str, max: usize) -> String {
    format!("{:?}", scrub(value).chars().take(max).collect::<String>())
}

/// A mode's value fit for a line ([`shown`], at most [`MODE_SHOWN`]
/// characters): `AI_ENV_BRIDGE_MODE`'s and `[wrapper] mode`'s, as the rows
/// here show them and `uninstall` and `install --mode` print them, and a
/// permission mode `install` refuses.
pub(crate) fn shown_mode(value: &str) -> String {
    shown(value, MODE_SHOWN)
}

/// Cursor's variables that steer the wrapper (S2): the kill switch, a mode
/// that overrides `[wrapper] mode` (or names none and is ignored), and a
/// bridge root or bridge.toml other than this command's (`paths`; `None` when
/// they did not resolve), which the rows below then do not describe. One
/// `[ok ]` row when none is set.
#[must_use]
pub fn rows_cursor_env(env: &CursorEnv, paths: Option<&Paths>) -> Vec<DoctorLine> {
    let mut rows = Vec::new();
    match env.local {
        Some(true) => rows.push(DoctorLine::row(Tag::Warn, format!("{LOCAL_ENV}=1 in {ENV_SETTING}: every chat execs the bundled claude (no census, no bridge)"))),
        Some(false) => rows.push(DoctorLine::row(Tag::Warn, format!("{LOCAL_ENV} in {ENV_SETTING} is not 1: no kill switch (the wrapper acts on exactly 1)"))),
        None => {}
    }
    match (&env.mode, env.named_mode()) {
        (_, Some(mode)) => rows.push(DoctorLine::row(Tag::Ok, format!("{MODE_ENV}={mode} in {ENV_SETTING}: it overrides [wrapper] mode"))),
        (Some(value), None) => rows.push(DoctorLine::row(Tag::Warn, format!("{MODE_ENV}={} in {ENV_SETTING} names no mode: ignored ([wrapper] mode decides)", shown_mode(value)))),
        (None, None) => {}
    }
    for (name, what, value, ours, same) in env.locations(paths) {
        rows.push(if same {
            DoctorLine::row(Tag::Ok, format!("{name}={} in {ENV_SETTING}: the {what} this command reads too", shown(value, PATH_SHOWN)))
        } else {
            let ours = ours.map_or_else(|| "none".to_string(), |o| o.display().to_string());
            DoctorLine::row(Tag::Warn, format!("{name}={} in {ENV_SETTING}: the wrapper reads that {what}, this command {ours}: the rows below are this command's", shown(value, PATH_SHOWN)))
        });
    }
    if rows.is_empty() {
        rows.push(DoctorLine::row(Tag::Ok, format!("{ENV_SETTING} sets none of {LOCAL_ENV}, {MODE_ENV}, {DIR_ENV}, {CONFIG_ENV}")));
    }
    rows
}

// ---- mode and roots ---------------------------------------------------------------

/// What Cursor starts for a chat, as its settings say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spawn {
    /// The settings were not read (unparseable or unreadable).
    Unknown,
    /// No wrapper: the extension's bundled claude.
    Bundled,
    /// A wrapper that is no executable file: every spawn fails (the wrapper row says why).
    Unrunnable,
    /// The wrapper.
    Wrapper,
}

impl Spawn {
    /// From the settings (`None`: not read; `Some(None)`: no file, or one of
    /// nothing but comments), the wrapper key read as
    /// `doctor::row_wrapper_setting` reads it.
    fn of(settings: Option<Option<&Value>>, exists_exec: &dyn Fn(&Path) -> (bool, bool)) -> Spawn {
        let Some(settings) = settings else { return Spawn::Unknown };
        match settings.and_then(|s| s.get(WRAPPER_SETTING)).and_then(Value::as_str).filter(|w| !w.is_empty()) {
            None => Spawn::Bundled,
            Some(w) if exists_exec(Path::new(w)) == (true, true) => Spawn::Wrapper,
            Some(_) => Spawn::Unrunnable,
        }
    }

    /// Whether the wrapper routes Cursor's chats now, and so writes the
    /// census: it is what Cursor starts and the kill switch in Cursor's
    /// variables (`env`) is off. Settings that were not read count, so no
    /// row plays down what it cannot rule out.
    fn wraps(self, env: &CursorEnv) -> bool {
        matches!(self, Spawn::Wrapper | Spawn::Unknown) && env.local != Some(true)
    }
}

/// The roots the wrapper routes on: `BridgeConfig::roots`, or what
/// `route::Broken` reads of a bridge.toml that does not load (`None` when it
/// cannot read them); none without a bridge.toml.
fn wrapper_roots(loaded: &Loaded) -> Option<Vec<PathBuf>> {
    match (&loaded.cfg, &loaded.broken) {
        (Some(cfg), _) => Some(cfg.roots().into_iter().map(Path::to_path_buf).collect()),
        (None, Some(broken)) => broken.roots.clone(),
        (None, None) => Some(Vec::new()),
    }
}

/// Whether the wrapper has roots to route a session remote on
/// ([`wrapper_roots`]): one at least, or roots a bridge.toml that does not
/// load hides (every chat then counts as under them). With none, every
/// session stays on this Mac in every mode (`route::decide_loaded`:
/// `Local(OutsideRoots)`), so none fails at its start.
fn has_roots(loaded: &Loaded) -> bool {
    wrapper_roots(loaded).is_none_or(|r| !r.is_empty())
}

/// Why every Cursor chat under the roots fails closed ([`fails_closed`]):
/// an exit at its start, never a run on this Mac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Closed {
    /// The wrapper cannot take bridge.toml (it does not load) or its
    /// `[wrapper] mode` (one it does not know, whatever Cursor's
    /// `AI_ENV_BRIDGE_MODE` names): exit 1, with the `[NO ]` rows above the
    /// effective mode's (bridge.toml's, its mode's).
    File,
    /// bridge.toml fails another check of a remote session's start
    /// ([`remote_checks`]): the session's exit code and the error's first
    /// line, [`row_session_checks`]'s `[NO ]`.
    Check(i32, String),
}

impl Closed {
    /// The exit code a chat under the roots ends with.
    #[must_use]
    pub(crate) fn code(&self) -> i32 {
        match self {
            Closed::File => 1,
            Closed::Check(code, _) => *code,
        }
    }

    /// The rows that say why, as the effective mode's row points at them.
    fn rows(&self) -> &'static str {
        match self {
            Closed::File => "the rows above",
            Closed::Check(..) => "the checks row below",
        }
    }
}

/// Whether every Cursor chat under the roots fails closed in `mode` (the
/// effective one), by what the wrapper loads (`loaded`, as
/// `route::load_for_wrapper` gives it), and why ([`Closed`]): remote, with
/// roots to route on ([`has_roots`]), and bridge.toml does not load or names
/// no mode (with Cursor's `AI_ENV_BRIDGE_MODE=remote` too: the session's
/// start refuses the key), or fails another check of the session's start
/// ([`remote_checks`]). Without a root no session goes remote, so none
/// fails. `uninstall` weighs it the same.
#[must_use]
pub(crate) fn fails_closed(mode: Mode, loaded: &Loaded) -> Option<Closed> {
    if mode != Mode::Remote || !has_roots(loaded) {
        return None;
    }
    match (&loaded.cfg, &loaded.broken) {
        (_, Some(_)) => Some(Closed::File),
        (Some(cfg), None) if cfg.wrapper.validate().is_err() => Some(Closed::File),
        (Some(cfg), None) => remote_checks(cfg).err().map(|(code, first)| Closed::Check(code, first)),
        (None, None) => None,
    }
}

/// bridge.toml's own `[wrapper] mode` and roots (`loaded`, as
/// `route::load_for_wrapper` gives it), the file alone: what Cursor's chats
/// get is the effective mode's row.
fn configured_mode(loaded: &Loaded) -> String {
    let roots = match wrapper_roots(loaded).map(|r| r.len()) {
        None => "its roots unreadable".to_string(),
        Some(0) => "no root".to_string(),
        Some(1) => "1 root".to_string(),
        Some(n) => format!("{n} roots"),
    };
    let unloaded = "bridge.toml, which does not load,";
    match (&loaded.cfg, &loaded.broken) {
        (Some(cfg), _) if WrapperMode::parse(&cfg.wrapper.mode).is_some() => format!("bridge.toml [wrapper] mode {} ({roots})", shown_mode(&cfg.wrapper.mode)),
        (Some(cfg), _) => format!("bridge.toml [wrapper] mode {} ({roots}), which names no mode", shown_mode(&cfg.wrapper.mode)),
        (None, Some(Broken { mode: Some(Some(m)), .. })) => format!("{unloaded} [wrapper] mode {} ({roots})", shown_mode(m)),
        (None, Some(Broken { mode: Some(None), .. })) => format!("{unloaded} [wrapper] mode unset ({roots})"),
        (None, Some(Broken { mode: None, .. })) => format!("{unloaded} [wrapper] mode unreadable ({roots})"),
        (None, None) => "no bridge.toml ([wrapper] mode passthrough, the default)".to_string(),
    }
}

/// bridge.toml's mode row: doctor's (`doctor`, the first of
/// `doctor::rows_s8_loaded`, which says what Cursor's chats do in that mode)
/// while that holds: the wrapper routes Cursor's chats (`wraps`,
/// [`Spawn::wraps`]) and Cursor's `AI_ENV_BRIDGE_MODE` (`env`) names no mode
/// other than the file's (`loaded`, as `route::load_for_wrapper` gives it).
/// Doctor's row quotes the mode as written: it is kept scrubbed
/// ([`scrubbed`]). Its `[NO ]` (a mode the wrapper does not know, a remote
/// file that does not load) has every chat under the roots fail closed;
/// with no root to route on ([`has_roots`]) every chat runs on this Mac
/// instead, which the row then says, still `[NO ]` with doctor's fix (the
/// file is wrong all the same: a root ends every chat under it at its
/// start). Else the file alone ([`configured_mode`]): no wrapper, the kill
/// switch, a wrapper that cannot run or the variable leaves Cursor's chats
/// to the effective mode's row. It is `[-  ]`, but doctor's `[NO ]` stays
/// `[NO ]` with a fix, the file being wrong whatever runs now, and doctor's
/// `[!! ]` (remote without a root) stays `[!! ]` with its fix: once the
/// file's mode applies, every chat still runs on this Mac.
#[must_use]
pub fn row_configured_mode(doctor: DoctorLine, loaded: &Loaded, env: &CursorEnv, wraps: bool) -> DoctorLine {
    let file = effective_mode_loaded(None, loaded).0;
    let broken = loaded.broken.is_some();
    if wraps && env.named_mode().is_none_or(|m| m == file.name()) {
        if !doctor.is_no() || has_roots(loaded) {
            return scrubbed(doctor);
        }
        let fix = if broken { "fix bridge.toml (the bridge.toml row above)" } else { "ai-env wrapper install --write --mode remote (or passthrough)" };
        return DoctorLine::row(Tag::No, format!("{}: every Cursor chat runs on this Mac until bridge.toml names a root, then every chat under it exits 1 at its start  <- {fix}", configured_mode(loaded)));
    }
    let text = format!("{}: not what Cursor's chats get now (the effective mode below)", configured_mode(loaded));
    match (&doctor, broken) {
        (d, true) if d.is_no() => DoctorLine::row(Tag::No, format!("{text}  <- fix bridge.toml (the bridge.toml row above)")),
        (d, false) if d.is_no() => DoctorLine::row(Tag::No, format!("{text}  <- set [wrapper] mode to \"passthrough\" or \"remote\" in bridge.toml")),
        // Doctor's one `[!! ]` here: remote without a root.
        (DoctorLine::Row { tag: Tag::Warn, .. }, _) => DoctorLine::row(Tag::Warn, format!("{text}; remote without a root runs every chat on this Mac  <- add the roots to bridge.toml")),
        _ => DoctorLine::row(Tag::Skip, text),
    }
}

/// The mode Cursor's chats get, from what Cursor starts (`spawn`), its
/// variables (`env`) and what the wrapper loads (`loaded`, as
/// `route::load_for_wrapper` gives it): no wrapper or the kill switch is
/// `[-  ]` (its bundled claude on this Mac; with no wrapper, what applies
/// after install, which the kill switch keeps local); else the wrapper's
/// mode (`route::effective_mode_loaded`) with where it comes from. Remote
/// failing closed ([`fails_closed`]) is `[!! ]`: a bridge.toml that does not
/// load or a mode the wrapper cannot take has its `[NO ]` rows above, a
/// failed check of the session's start its checks row below
/// ([`row_session_checks`], there with no wrapper too). Remote without a
/// root runs every chat on this Mac, whatever `[wrapper] mode` it is taken
/// from.
#[must_use]
pub fn row_effective_mode(spawn: Spawn, env: &CursorEnv, loaded: &Loaded) -> DoctorLine {
    let mode = effective_mode_loaded(env.named_mode(), loaded).0;
    let closed = fails_closed(mode, loaded);
    match spawn {
        Spawn::Unknown => return DoctorLine::row(Tag::Skip, "effective mode not checked (Cursor's settings were not read)"),
        Spawn::Unrunnable => return DoctorLine::row(Tag::Skip, "effective mode not checked: Cursor cannot start the wrapper its settings name (the wrapper row above)"),
        Spawn::Bundled if env.local == Some(true) => {
            return DoctorLine::row(Tag::Skip, format!("no wrapper: Cursor runs its bundled claude, and after ai-env wrapper install --write the kill switch ({LOCAL_ENV}=1) still execs it on this Mac for every chat"));
        }
        Spawn::Bundled => {
            let applies = match (&closed, env.named_mode()) {
                (Some(c), _) => format!("remote mode failing closed ({})", c.rows()),
                (None, Some(m)) => format!("{MODE_ENV}={m} in {ENV_SETTING}"),
                // The mode it is taken as, never quoted as `[wrapper] mode`'s value (that may name no mode).
                (None, None) if mode == Mode::Remote && !has_roots(loaded) => "remote mode with no root (every chat on this Mac)".to_string(),
                (None, None) => format!("[wrapper] mode {:?}", mode.name()),
            };
            return DoctorLine::row(Tag::Skip, format!("no wrapper: Cursor runs its bundled claude; {applies} applies after ai-env wrapper install --write"));
        }
        Spawn::Wrapper if env.local == Some(true) => return DoctorLine::row(Tag::Skip, format!("effective mode: none, the kill switch ({LOCAL_ENV}=1) execs Cursor's bundled claude on this Mac for every chat")),
        Spawn::Wrapper => {}
    }
    let source = match env.named_mode() {
        Some(_) => format!("{MODE_ENV} in {ENV_SETTING}"),
        None if loaded.cfg.is_some() || loaded.broken.is_some() => "[wrapper] mode".to_string(),
        None => "no bridge.toml".to_string(),
    };
    match (mode, closed) {
        (Mode::Remote, Some(c)) => DoctorLine::row(Tag::Warn, format!("effective mode remote ({source}), failing closed: every Cursor chat under the roots exits {} ({})", c.code(), c.rows())),
        // Not failing closed: the roots read (a file that does not load and hides them fails closed).
        (Mode::Remote, None) => match wrapper_roots(loaded).map_or(0, |r| r.len()) {
            0 => DoctorLine::row(Tag::Ok, format!("effective mode remote ({source}), but no root: every Cursor chat runs on this Mac")),
            roots => DoctorLine::row(Tag::Ok, format!("effective mode remote ({source}): Cursor's chats under the {roots} root(s) run in their workspace's MicroVM, everything else on this Mac")),
        },
        (Mode::Passthrough, _) => DoctorLine::row(Tag::Ok, format!("effective mode passthrough ({source}): Cursor's chats run on this Mac, each through ai-env-claude with a census row")),
        (Mode::LocalChild | Mode::LocalScratch, _) => DoctorLine::row(Tag::Ok, format!("effective mode {} ({source}): Cursor's chats are piped through ai-env-claude to a claude on this Mac (a lab mode)", mode.name())),
    }
}

/// The workspace roots the wrapper routes on (`loaded`), one row each: a
/// root that is no directory is `[!! ]` (no chat runs under it). Roots a
/// bridge.toml that does not load hides from `route::Broken` are, in remote
/// mode (`mode`, the effective one), `[NO ]` while the wrapper routes
/// Cursor's chats (`wraps`, [`Spawn::wraps`]): every chat then counts as
/// under them and exits 1; `[!! ]` while it does not, as that is what comes
/// once it does. In another mode they are `[-  ]`.
#[must_use]
pub fn rows_roots(loaded: &Loaded, mode: Mode, wraps: bool) -> Vec<DoctorLine> {
    let Some(roots) = wrapper_roots(loaded) else {
        let unreadable = "workspace roots unreadable (bridge.toml does not load)";
        let fix = "<- fix bridge.toml (the bridge.toml row above)";
        return vec![match mode {
            Mode::Remote if wraps => DoctorLine::row(Tag::No, format!("{unreadable}: in remote mode every Cursor chat counts as under them and exits 1  {fix}")),
            Mode::Remote => DoctorLine::row(Tag::Warn, format!("{unreadable}: once the wrapper routes Cursor's chats, in remote mode every one counts as under them and exits 1  {fix}")),
            _ => DoctorLine::row(Tag::Skip, unreadable),
        }];
    };
    if roots.is_empty() {
        return vec![DoctorLine::row(Tag::Skip, "no workspace root ([workspaces].roots, [[workspace]].path)")];
    }
    roots
        .iter()
        .map(|r| if r.is_dir() { DoctorLine::row(Tag::Ok, format!("workspace root {}", r.display())) } else { DoctorLine::row(Tag::Warn, format!("workspace root {} is no directory: no chat runs under it", r.display())) })
        .collect()
}

/// The checks of bridge.toml (`cfg`) a remote session runs at its start (S8
/// P0, `remote::pipeline::precheck_with`), in P0's order: `[wrapper]`,
/// `[seed]`, the `vm` checks (`vm::cmd::config_checks`), the run plan
/// without a workspace (`vm::run::RunPlan::from_cfg`: `[aws].image_arn`,
/// `[vm]`'s run limits and idle policy, the connector vpc egress needs),
/// `[creds]` (`vm::cmd::sealed_token_plan`'s first check) and the names
/// `[wrapper] env_forward` and `env_extra` may hold (`remote::env::session_env`,
/// given no variable). Not what else P0 reads: the chat's directory and
/// arguments, Cursor's environment, the sealed files, the recorded checks.
/// `Err`: the exit code of the failure P0 makes of the error
/// (`remote::Failure`) and the error's first line, scrubbed. Pure: nothing
/// is read or printed.
fn remote_checks(cfg: &BridgeConfig) -> std::result::Result<(), (i32, String)> {
    let ended = |failure: Failure, text: String| (failure.exit_code(), text.lines().next().map(|l| scrub(l).into_owned()).unwrap_or_default());
    // A check of the file is `Failure::Config` in P0, `[creds]`'s too; the run plan's refusal maps by its error.
    let config = |e: BridgeError| ended(Failure::Config { first_line: e.to_string() }, e.to_string());
    cfg.wrapper.validate().map_err(config)?;
    cfg.seed.validate().map_err(config)?;
    config_checks(cfg, || {}).map_err(config)?;
    let flags = RunFlags { egress: Some(Egress::Vpc), purpose: "session", ..RunFlags::default() };
    RunPlan::from_cfg(cfg, &flags).map_err(|e| {
        let text = e.to_string();
        ended(Failure::from_error(StartStep::Precheck, e, None), text)
    })?;
    cfg.creds.validate().map_err(config)?;
    session_env(cfg, &|_| None).map(drop).map_err(|what| ended(Failure::Refused { what: what.clone() }, what))
}

/// Whether bridge.toml passes the checks a remote session runs at its start
/// ([`remote_checks`]). Loading the file runs none of them, so a bridge.toml
/// that loads can still end every remote session at its start, naming the
/// key. A row whenever a remote session can start once the wrapper routes
/// Cursor's chats: bridge.toml loads (`loaded`, as `route::load_for_wrapper`
/// gives it), the mode the wrapper takes (`mode`: the file's, or Cursor's
/// `AI_ENV_BRIDGE_MODE` when it names one) is remote and there is a root to
/// route on; while the wrapper does not route them (`wraps` false, no
/// wrapper, the kill switch or one that cannot run: [`Spawn::wraps`]) it
/// says so. As [`fails_closed`] weighs it: a failure is `[NO ]` with the
/// session's exit code and the error's first line, but a `[wrapper] mode`
/// the wrapper does not know is `[!! ]`: the mode row above carries its
/// `[NO ]`, one problem counted once. Nothing is printed here.
#[must_use]
pub fn row_session_checks(loaded: &Loaded, mode: Mode, wraps: bool) -> Option<DoctorLine> {
    loaded.cfg.as_ref().filter(|cfg| mode == Mode::Remote && !cfg.roots().is_empty())?;
    let when = if wraps { "" } else { " once the wrapper routes Cursor's chats again" };
    Some(match fails_closed(mode, loaded) {
        None => DoctorLine::row(Tag::Ok, "bridge.toml passes the checks a remote session runs at its start"),
        Some(c @ Closed::File) => DoctorLine::row(Tag::Warn, format!("a remote session would exit {} at its start{when}: [wrapper] mode (the [NO ] row above)", c.code())),
        Some(Closed::Check(code, first)) => DoctorLine::row(Tag::No, format!("a remote session would exit {code} at its start{when}: {first}  <- fix bridge.toml")),
    })
}

// ---- the extension and the census -------------------------------------------------

/// The extension installed, as doctor picks it (`doctor::pick_bundle` of
/// `dirs`, as `doctor::installed_extension_names` lists them), and how many
/// versions are there. Status never asks its bundled claude, so unlike
/// `doctor::row_cursor_bundle` the row names no version of that.
#[must_use]
pub fn row_extension(dirs: &[String]) -> DoctorLine {
    let Some((ver, _)) = pick_bundle(dirs) else {
        // doctor's row for no extension.
        return row_cursor_bundle(dirs, None);
    };
    match dirs.iter().filter(|d| d.starts_with("anthropic.claude-code-")).count() {
        n if n > 1 => DoctorLine::row(Tag::Ok, format!("cursor extension {ver} ({n} versions installed)")),
        _ => DoctorLine::row(Tag::Ok, format!("cursor extension {ver}")),
    }
}

/// The census rows' ending while the wrapper does not route Cursor's chats
/// ([`Spawn::wraps`]): the census stops at the last spawn it routed.
const NOT_IN_CENSUS: &str = "what Cursor runs now leaves no census row (the rows above)";

/// The census rows' ending for a row from before Cursor's settings.json
/// last changed (`at`, [`predates`]): what Cursor started in between may have
/// left no row, so what it runs now is unknown until the wrapper writes a
/// newer one, for a `what` (a process, a session).
fn unseen_since(at: &str, what: &str) -> String {
    format!("and predates the last change of Cursor's settings.json ({at}): what Cursor has run since is unknown until it starts a {what} through the wrapper")
}

/// A time in ms since the epoch as a row prints it: to the second when it is
/// a whole one, else to the millisecond. A census row's `ts` is its `start`
/// cut to the second, so it never reads as later than a change it predates.
fn shown_ms(ms: u64) -> String {
    if ms.is_multiple_of(1000) { rfc3339_utc(ms / 1000) } else { rfc3339_utc_ms(ms) }
}

/// The last change of Cursor's settings.json (`changed`, ms since the epoch,
/// rounded up; `None`: unknown) as a row prints it ([`shown_ms`]), when the
/// census `row` started before it: its `start`, or, for a row without one
/// (the census writer never leaves it out), its `ts`, read to the second it
/// names, so before the change unless that second began after it; a row
/// with neither is older than any, as [`newest`] takes it. Any change
/// counts: taking the wrapper's key out and putting it back are two, and a
/// window reloaded in between ran with no census row.
fn predates(row: &Value, changed: Option<u64>) -> Option<String> {
    let changed = changed?;
    let ts = || field(row, "ts").and_then(parse_rfc3339).and_then(|s| u64::try_from(s).ok()).map(|s| s.saturating_mul(1000));
    (row.get("start").and_then(Value::as_u64).or_else(ts).unwrap_or(0) < changed).then(|| shown_ms(changed))
}

/// Where a window reload sends the open chats it restarts through the
/// wrapper: the extension row's hint ([`row_last_extension`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    /// On this Mac: a mode other than remote, or remote with no root to route on.
    Here,
    /// Those under the roots to their workspace's MicroVM.
    MicroVm,
    /// Those under the roots to an exit at their start ([`fails_closed`]).
    Exit,
}

impl Restart {
    /// In `mode` (the effective one), by what the wrapper loads (`loaded`,
    /// as `route::load_for_wrapper` gives it).
    #[must_use]
    pub fn of(mode: Mode, loaded: &Loaded) -> Restart {
        match fails_closed(mode, loaded) {
            Some(_) => Restart::Exit,
            None if mode == Mode::Remote && has_roots(loaded) => Restart::MicroVm,
            None => Restart::Here,
        }
    }
}

/// A census row's string field.
fn field<'a>(row: &'a Value, key: &str) -> Option<&'a str> {
    row.get(key).and_then(Value::as_str)
}

/// `value` when it looks like what the wrapper writes there: 1 to `max`
/// characters, each ASCII alphanumeric or one of `extra`; else
/// `unrecognised`. Only the wrapper writes the census, but nothing stops
/// another hand: a value of another shape (a newline and a forged row after
/// it, say) is never printed.
fn census_word<'a>(value: &'a str, max: usize, extra: &[u8]) -> &'a str {
    if !value.is_empty() && value.len() <= max && value.bytes().all(|c| c.is_ascii_alphanumeric() || extra.contains(&c)) {
        value
    } else {
        "unrecognised"
    }
}

/// A row's `ext` as a row prints it: a version (`doctor::bundle_version`'s
/// shape, at most 32 characters of `[0-9A-Za-z.+-]`), else `unrecognised`.
fn shown_ext(ext: &str) -> &str {
    census_word(ext, 32, b".+-")
}

/// A row's `ts` as a row prints it: a timestamp (`rfc3339_utc`'s shape, at
/// most 40 characters of `[0-9A-Za-z:.+-]`), else `unrecognised`; `?` without one.
fn shown_ts(row: &Value) -> &str {
    field(row, "ts").map_or("?", |ts| census_word(ts, 40, b":.+-"))
}

/// The newest of the census `rows` that `keep` takes, by `start` (the
/// spawn's clock read, not where the row sits in the file): an end row
/// carries its start row's, so a session that ends after a newer spawn never
/// hides it. Of equal ones the later in the file; a row without `start` is
/// older than any with one.
fn newest(rows: &[Value], keep: impl Fn(&Value) -> bool) -> Option<&Value> {
    rows.iter().filter(|r| keep(r)).max_by_key(|r| r.get("start").and_then(Value::as_u64))
}

/// Which extension Cursor last ran, from the newest census row ([`newest`])
/// that names one (`ext`: the bundle of the claude the wrapper was handed),
/// against the newest installed (`installed`): another version is `[!! ]`,
/// as a window keeps the extension it loaded until it is reloaded. Its hint
/// says where the reload sends the chats it restarts ([`Restart`]): through
/// the wrapper, those under the roots to their MicroVM, or, while remote
/// mode fails closed, to an exit at their start; else they stay on this
/// Mac. While the wrapper does not route Cursor's chats (`wraps` false) the
/// row is `[-  ]` with no hint: the census has none of what Cursor runs now;
/// so it is while that row predates the last change of Cursor's
/// settings.json (`changed`, ms since the epoch: [`predates`]), as right
/// after `install --write` puts the wrapper back. `ext` and `ts` print only
/// as their shapes ([`shown_ext`], [`shown_ts`]).
#[must_use]
pub fn row_last_extension(rows: &[Value], installed: Option<&str>, census: &Path, wraps: bool, changed: Option<u64>, restart: Restart) -> DoctorLine {
    let Some(row) = newest(rows, |r| field(r, "ext").is_some()) else {
        return DoctorLine::row(Tag::Skip, format!("no census row names an extension yet ({})", census.display()));
    };
    let ext = field(row, "ext").unwrap_or_default();
    let (shown, ts) = (shown_ext(ext), shown_ts(row));
    let reload = match restart {
        Restart::Exit => "a window reload picks it up, and restarts every open chat through the wrapper: those under the roots exit at their start until bridge.toml is fixed (the rows above)",
        Restart::MicroVm => "a window reload picks it up, and restarts every open chat through the wrapper: those under the roots go to their MicroVM (to keep one on this Mac: the README's \"No wrapper at all\")",
        Restart::Here => "a window reload picks it up (it restarts open chats on this Mac)",
    };
    match (installed, predates(row, changed)) {
        _ if !wraps => DoctorLine::row(Tag::Skip, format!("the newest census row names extension {shown} ({ts}); {NOT_IN_CENSUS}")),
        (_, Some(at)) => DoctorLine::row(Tag::Skip, format!("the newest census row names extension {shown} ({ts}) {}", unseen_since(&at, "process"))),
        (Some(v), None) if v != ext => DoctorLine::row(Tag::Warn, format!("Cursor last ran extension {shown} ({ts}); {v} is installed  <- {reload}")),
        _ => DoctorLine::row(Tag::Ok, format!("Cursor last ran extension {shown} ({ts})")),
    }
}

/// A census row of a stream-json session: `route` remote, or one of the two
/// reasons a session stays local for (outside the roots, no bridge.toml).
fn is_session_row(row: &Value) -> bool {
    field(row, "route") == Some("remote") || matches!(field(row, "reason"), Some("outside_roots" | "unconfigured"))
}

/// Where Cursor's newest session went, from the newest census row of a
/// session ([`newest`]; an end row stands for its session, whose note it
/// keeps): routed remote (`route=remote`) in remote mode (its note holds one
/// of `remote::MODE_NOTES`), it went to its workspace's MicroVM; else it ran
/// on this Mac. Neither says it alone: passthrough records a session under
/// the roots `route=remote`, and remote mode notes every row, a session
/// outside the roots too. While the wrapper does not route Cursor's chats
/// (`wraps` false), or that row predates the last change of Cursor's
/// settings.json (`changed`, ms since the epoch: [`predates`]), the row is
/// `[-  ]`: that session may not be Cursor's newest. Its `ts` prints only as
/// its shape ([`shown_ts`]).
#[must_use]
pub fn row_last_session(rows: &[Value], wraps: bool, changed: Option<u64>) -> DoctorLine {
    let Some(row) = newest(rows, is_session_row) else {
        return DoctorLine::row(Tag::Skip, "no session in the census yet");
    };
    let ts = shown_ts(row);
    let routed = field(row, "route") == Some("remote");
    let went = match field(row, "note").unwrap_or_default().split("; ").find(|p| MODE_NOTES.contains(p)).filter(|_| routed) {
        Some(note) => format!("went to its workspace's MicroVM ({note})"),
        None => "ran on this Mac".to_string(),
    };
    match (wraps, predates(row, changed)) {
        (false, _) => DoctorLine::row(Tag::Skip, format!("the newest session in the census ({ts}) {went}; {NOT_IN_CENSUS}")),
        (true, Some(at)) => DoctorLine::row(Tag::Skip, format!("the newest session in the census ({ts}) {went} {}", unseen_since(&at, "session"))),
        (true, None) => DoctorLine::row(Tag::Ok, format!("Cursor's newest session ({ts}) {went}")),
    }
}

// ---- collection -------------------------------------------------------------------

/// `line` with its text scrubbed (`wire::redact::scrub`): a row of doctor's
/// that can quote a bridge.toml value, as status prints it.
fn scrubbed(line: DoctorLine) -> DoctorLine {
    match line {
        DoctorLine::Row { tag, text } => DoctorLine::row(tag, scrub(&text)),
        plain => plain,
    }
}

/// `line` cut to its first line, scrubbed ([`scrubbed`]): a bridge.toml
/// error carries a snippet of the file, which status never prints, and its
/// first line can quote a value.
fn first_line(line: DoctorLine) -> DoctorLine {
    match line {
        DoctorLine::Row { tag, text } => scrubbed(DoctorLine::row(tag, text.lines().next().unwrap_or_default())),
        plain => plain,
    }
}

/// Collect the inputs and build every row, in the plan's order: Cursor's
/// settings, the wrapper key, the sibling, Cursor's variables, bridge.toml,
/// its mode, the mode Cursor's chats get, the roots, the checks a remote
/// session runs at its start, the extension installed and the one Cursor
/// last ran, the newest session's place.
#[must_use]
pub fn rows() -> Vec<DoctorLine> {
    let mut lines = Vec::new();
    // Cursor's user settings: the one scope the machine-scoped wrapper key takes effect in.
    // `None`: not read; `Some(None)`: no file, or one of nothing but comments (no settings to
    // Cursor, nothing to remove to uninstall).
    let path = cursor_settings_path();
    let settings = match std::fs::read_to_string(&path) {
        Ok(t) if strip_jsonc(&t).trim().is_empty() => {
            lines.push(DoctorLine::row(Tag::Skip, format!("Cursor settings {} empty", path.display())));
            Some(None)
        }
        Ok(t) => match parse_settings(&t) {
            Ok(v) => {
                lines.push(DoctorLine::row(Tag::Ok, format!("Cursor settings {}", path.display())));
                Some(Some(v))
            }
            Err(e) => {
                lines.push(row_settings_unparseable(&path, &e));
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            lines.push(DoctorLine::row(Tag::Skip, format!("Cursor settings {} absent", path.display())));
            Some(None)
        }
        Err(e) => {
            lines.push(DoctorLine::row(Tag::Warn, format!("Cursor settings.json unreadable ({e}); wrapper rows not checked  <- {}", path.display())));
            None
        }
    };
    let settings = settings.as_ref().map(Option::as_ref);
    let sibling = find_sibling("ai-env-claude");
    if let Some(s) = settings {
        lines.extend(row_wrapper_setting(s, &exists_exec, &sibling));
    }
    // The sibling's `--version`: the one process status starts.
    lines.push(row_sibling(&sibling));
    let sib_out = match &sibling {
        Sibling::Next(p) | Sibling::PathOnly(p) => run_capture(&p.to_string_lossy(), &["--version"], Duration::from_secs(5)).ok(),
        Sibling::Missing => None,
    };
    lines.push(row_same_version(sib_out.as_deref(), env!("CARGO_PKG_VERSION")));
    let env = settings.flatten().map(CursorEnv::of).unwrap_or_default();
    let spawn = Spawn::of(settings, &exists_exec);
    let wraps = spawn.wraps(&env);
    let paths = Paths::resolve();
    if settings.is_some() {
        lines.extend(rows_cursor_env(&env, paths.as_ref().ok()));
    }
    // What the wrapper itself loads, for the mode and the roots it routes on, and the mode
    // Cursor's chats get (`named_mode`: never a value that would print the wrapper's stderr line).
    let wrapper = load_for_wrapper();
    let mode = effective_mode_loaded(env.named_mode(), &wrapper).0;
    // When Cursor's settings last changed: what Cursor ran before then may not be what it runs now.
    // In ms rounded up, so a census `start` (whole ms) is less exactly when it came before the change.
    let changed = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| u64::try_from(d.as_nanos().div_ceil(1_000_000)).unwrap_or(u64::MAX));
    match &paths {
        Ok(p) => {
            let loaded = BridgeConfig::load(p);
            lines.push(first_line(row_bridge_config(p, &loaded)));
            if let Some(doctor) = rows_s8_loaded(p, &loaded).into_iter().next() {
                lines.push(row_configured_mode(doctor, &wrapper, &env, wraps));
            }
            lines.push(row_effective_mode(spawn, &env, &wrapper));
            lines.extend(rows_roots(&wrapper, mode, wraps));
            lines.extend(row_session_checks(&wrapper, mode, wraps));
        }
        Err(e) => lines.push(DoctorLine::row(Tag::No, format!("bridge paths: {e}"))),
    }
    // The extension installed; its bundled claude is not asked.
    let ext_dir = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default().join(".cursor").join("extensions");
    let dirs = installed_extension_names(&ext_dir);
    lines.push(row_extension(&dirs));
    if let Ok(p) = &paths {
        let census = p.census();
        match read_tail(&census, CENSUS_TAIL_CHUNKS) {
            Ok(rows) => {
                lines.push(row_last_extension(&rows, pick_bundle(&dirs).map(|(v, _)| v).as_deref(), &census, wraps, changed, Restart::of(mode, &wrapper)));
                lines.push(row_last_session(&rows, wraps, changed));
            }
            Err(e) => lines.push(DoctorLine::row(Tag::Warn, format!("census unreadable: {e}"))),
        }
    }
    lines
}

/// `ai-env wrapper status [--json]`: [`rows`] reported as doctor reports its
/// own (`commands::doctor_report_under`), under the heading `ai-env wrapper
/// status` or as `doctor --json`'s document; every row is printed before
/// exit 1, which only a `[NO ]` row gives.
pub fn status(json: bool) -> Result<()> {
    doctor_report_under("ai-env wrapper status", &rows(), json, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::route::Broken;

    fn text(l: &DoctorLine) -> (Tag, String) {
        match l {
            DoctorLine::Row { tag, text } => (*tag, text.clone()),
            DoctorLine::Plain(t) => (Tag::Skip, t.clone()),
        }
    }

    fn texts(rows: &[DoctorLine]) -> Vec<(Tag, String)> {
        rows.iter().map(text).collect()
    }

    fn settings(vars: Value) -> Value {
        serde_json::json!({ WRAPPER_SETTING: "/w/ai-env-claude", ENV_SETTING: vars })
    }

    /// The extension's reading (2.1.300's `Tb` and `c5`): a list of
    /// `{name, value}` or an object of names; entries without a string name
    /// skipped, a null or missing value empty, `String()` of anything else,
    /// the last entry of a name winning; names compared exactly.
    #[test]
    fn cursor_variables_are_read_as_the_extension_reads_them() {
        let list = settings(serde_json::json!([
            {"name": LOCAL_ENV, "value": "0"},
            "AI_ENV_BRIDGE_MODE=remote",
            {"value": "remote"},
            {"name": 7, "value": "remote"},
            {"name": LOCAL_ENV, "value": 1},
            {"name": MODE_ENV},
            {"name": DIR_ENV, "value": null},
            {"name": "ai_env_bridge_config", "value": "/lower"},
        ]));
        assert_eq!(cursor_variable(&list, LOCAL_ENV).as_deref(), Some("1"), "the last entry wins; a number is String()ed");
        assert_eq!(cursor_variable(&list, MODE_ENV).as_deref(), Some(""), "no value is empty");
        assert_eq!(cursor_variable(&list, DIR_ENV).as_deref(), Some(""), "null is empty");
        assert_eq!(cursor_variable(&list, CONFIG_ENV), None, "names are compared exactly");
        let object = settings(serde_json::json!({ LOCAL_ENV: 1.0, MODE_ENV: ["remote"], DIR_ENV: {"a": 1}, CONFIG_ENV: true }));
        assert_eq!(cursor_variable(&object, LOCAL_ENV).as_deref(), Some("1"), "1.0 is String()ed as 1");
        assert_eq!(cursor_variable(&object, MODE_ENV).as_deref(), Some("remote"));
        assert_eq!(cursor_variable(&object, DIR_ENV).as_deref(), Some("[object Object]"));
        assert_eq!(cursor_variable(&object, CONFIG_ENV).as_deref(), Some("true"));
        assert_eq!(js_string(&serde_json::json!(2.5)), "2.5");
        assert_eq!(js_string(&serde_json::json!([1, null, "a"])), "1,,a");
        for none in [serde_json::json!({}), settings(serde_json::json!("AI_ENV_BRIDGE_LOCAL=1")), settings(Value::Null)] {
            assert_eq!(CursorEnv::of(&none), CursorEnv::default(), "{none}");
        }
        let env = CursorEnv::of(&object);
        assert_eq!(env, CursorEnv { local: Some(true), mode: Some("remote".into()), dir: Some("[object Object]".into()), config: Some("true".into()) });
        let empty = CursorEnv::of(&settings(serde_json::json!([{"name": DIR_ENV, "value": ""}, {"name": CONFIG_ENV, "value": ""}, {"name": LOCAL_ENV, "value": "true"}])));
        assert_eq!(empty, CursorEnv { local: Some(false), ..CursorEnv::default() }, "an empty root counts as unset, as Paths::resolve takes it");
    }

    /// S2: the rows name the four variables only. The kill switch shows
    /// whether it is 1, never its value; a mode is scrubbed and capped; a
    /// root or bridge.toml other than this command's is `[!! ]`. A planted
    /// secret-looking variable shows nowhere, by name or by value.
    #[test]
    fn the_variable_rows_show_the_four_names_and_nothing_else() {
        let paths = Paths::from_root_and_env(PathBuf::from("/h/.config/ai-env/bridge"), None);
        let secret_name = format!("{}_{}", "PLANTED", "API_KEY");
        let secret_value = format!("pv-{}", "q".repeat(32));
        let token = format!("{}oat01-{}", "sk-ant-", "Z".repeat(24));
        let vars = serde_json::json!([
            {"name": secret_name, "value": secret_value},
            {"name": LOCAL_ENV, "value": "1"},
            {"name": MODE_ENV, "value": format!("{token}\n{}", "m".repeat(100))},
            {"name": DIR_ENV, "value": "/h/.config/ai-env/bridge"},
            {"name": CONFIG_ENV, "value": "/elsewhere/bridge.toml"},
            {"name": "TOKEN_ONLY", "value": token},
        ]);
        let env = CursorEnv::of(&settings(vars));
        let rows = texts(&rows_cursor_env(&env, Some(&paths)));
        assert_eq!(rows.len(), 4, "{rows:?}");
        assert_eq!(rows[0], (Tag::Warn, format!("{LOCAL_ENV}=1 in {ENV_SETTING}: every chat execs the bundled claude (no census, no bridge)")));
        // Scrubbed, then capped at 64 characters, then quoted (the newline stays on the row).
        let masked = format!("sk-ant-[redacted:len={}]\n", token.len());
        let capped = format!("{masked}{}", "m".repeat(64 - masked.chars().count()));
        assert_eq!(rows[1], (Tag::Warn, format!("{MODE_ENV}={capped:?} in {ENV_SETTING} names no mode: ignored ([wrapper] mode decides)")));
        assert_eq!(rows[2], (Tag::Ok, format!("{DIR_ENV}=\"/h/.config/ai-env/bridge\" in {ENV_SETTING}: the bridge root this command reads too")));
        assert_eq!(rows[3], (Tag::Warn, format!("{CONFIG_ENV}=\"/elsewhere/bridge.toml\" in {ENV_SETTING}: the wrapper reads that bridge.toml, this command /h/.config/ai-env/bridge/bridge.toml: the rows below are this command's")));
        for (_, t) in &rows {
            for never in [&secret_name, &secret_value, &token, &"TOKEN_ONLY".to_string()] {
                assert!(!t.contains(never.as_str()), "{never} in {t}");
            }
        }
        let off = texts(&rows_cursor_env(&CursorEnv { local: Some(false), mode: Some("remote".into()), ..CursorEnv::default() }, None));
        assert_eq!(off, vec![(Tag::Warn, format!("{LOCAL_ENV} in {ENV_SETTING} is not 1: no kill switch (the wrapper acts on exactly 1)")), (Tag::Ok, format!("{MODE_ENV}=remote in {ENV_SETTING}: it overrides [wrapper] mode"))]);
        let elsewhere = texts(&rows_cursor_env(&CursorEnv { dir: Some("/x".into()), ..CursorEnv::default() }, None));
        assert_eq!(elsewhere[0].0, Tag::Warn, "no root resolved here: never the same");
        // What uninstall names: the [!! ] ones only, as their rows show them.
        assert_eq!(env.elsewhere(Some(&paths)), vec!["AI_ENV_BRIDGE_CONFIG=\"/elsewhere/bridge.toml\"".to_string()]);
        assert_eq!(CursorEnv { dir: Some(format!("/x/{token}")), ..CursorEnv::default() }.elsewhere(None), vec![format!("AI_ENV_BRIDGE_DIR=\"/x/sk-ant-[redacted:len={}]\"", token.len())]);
        assert!(CursorEnv::default().elsewhere(Some(&paths)).is_empty());
        let none = texts(&rows_cursor_env(&CursorEnv::default(), Some(&paths)));
        assert_eq!(none, vec![(Tag::Ok, format!("{ENV_SETTING} sets none of {LOCAL_ENV}, {MODE_ENV}, {DIR_ENV}, {CONFIG_ENV}"))]);
    }

    fn loaded(toml: &str) -> Loaded {
        Loaded { cfg: Some(BridgeConfig::parse(toml).unwrap()), ..Loaded::default() }
    }

    /// The `[aws]` a remote session's run plan needs (the documentation
    /// account's made-up image and egress connector).
    const AWS: &str = "[aws]\nimage_arn = \"arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env\"\negress_connector_arn = \"arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress\"\n";

    fn broken(mode: Option<Option<&str>>, roots: Option<Vec<PathBuf>>) -> Loaded {
        Loaded { broken: Some(Broken { mode: mode.map(|m| m.map(str::to_string)), roots }), note: Some("config: bridge.toml: TOML parse error".into()), ..Loaded::default() }
    }

    /// The mode Cursor's chats get: unknown settings, a wrapper that cannot
    /// run, no wrapper (the mode that applies after install, or the kill
    /// switch that keeps them local then) and the kill switch are `[-  ]`;
    /// else the wrapper's mode and where it comes from, remote failing closed
    /// `[!! ]` when bridge.toml does not load or names no mode (Cursor's
    /// `AI_ENV_BRIDGE_MODE=remote` over it too), or fails another check of a
    /// remote session's start, each only with roots to route on (or roots it
    /// cannot read): without one no chat goes remote.
    #[test]
    fn the_effective_mode_follows_the_wrapper_the_kill_switch_and_the_mode() {
        let remote = loaded(&format!("[wrapper]\nmode = \"remote\"\n[workspaces]\nroots = [\"/a\", \"/b\"]\n{AWS}"));
        let none = CursorEnv::default();
        assert_eq!(text(&row_effective_mode(Spawn::Unknown, &none, &remote)).0, Tag::Skip);
        assert_eq!(text(&row_effective_mode(Spawn::Unrunnable, &none, &remote)).0, Tag::Skip);
        assert_eq!(
            text(&row_effective_mode(Spawn::Bundled, &none, &remote)),
            (Tag::Skip, "no wrapper: Cursor runs its bundled claude; [wrapper] mode \"remote\" applies after ai-env wrapper install --write".to_string())
        );
        let kill = CursorEnv { local: Some(true), ..CursorEnv::default() };
        assert_eq!(text(&row_effective_mode(Spawn::Wrapper, &kill, &remote)), (Tag::Skip, format!("effective mode: none, the kill switch ({LOCAL_ENV}=1) execs Cursor's bundled claude on this Mac for every chat")));
        // No wrapper: once it is installed, the kill switch still keeps every chat on the bundled claude.
        let after_install = (Tag::Skip, format!("no wrapper: Cursor runs its bundled claude, and after ai-env wrapper install --write the kill switch ({LOCAL_ENV}=1) still execs it on this Mac for every chat"));
        assert_eq!(text(&row_effective_mode(Spawn::Bundled, &kill, &remote)), after_install);
        let kill_over = CursorEnv { local: Some(true), mode: Some("remote".into()), ..CursorEnv::default() };
        assert_eq!(text(&row_effective_mode(Spawn::Bundled, &kill_over, &broken(Some(Some("remote")), None))), after_install, "over any mode, failing closed or not");
        let off = CursorEnv { local: Some(false), ..CursorEnv::default() };
        assert_eq!(text(&row_effective_mode(Spawn::Bundled, &off, &remote)), text(&row_effective_mode(Spawn::Bundled, &none, &remote)), "a variable that is not 1 is no kill switch");
        assert_eq!(
            text(&row_effective_mode(Spawn::Wrapper, &none, &remote)),
            (Tag::Ok, "effective mode remote ([wrapper] mode): Cursor's chats under the 2 root(s) run in their workspace's MicroVM, everything else on this Mac".to_string())
        );
        let (tag, t) = text(&row_effective_mode(Spawn::Wrapper, &none, &loaded("")));
        assert!(tag == Tag::Ok && t.starts_with("effective mode passthrough ([wrapper] mode): Cursor's chats run on this Mac"), "{t}");
        let (tag, t) = text(&row_effective_mode(Spawn::Wrapper, &none, &Loaded::default()));
        assert!(tag == Tag::Ok && t.starts_with("effective mode passthrough (no bridge.toml)"), "{t}");
        // Cursor's own mode variable wins when it names a mode, and only then.
        let over = CursorEnv { mode: Some("passthrough".into()), ..CursorEnv::default() };
        let (tag, t) = text(&row_effective_mode(Spawn::Wrapper, &over, &remote));
        assert!(tag == Tag::Ok && t.starts_with(&format!("effective mode passthrough ({MODE_ENV} in {ENV_SETTING})")), "{t}");
        assert_eq!(text(&row_effective_mode(Spawn::Bundled, &over, &remote)).1, format!("no wrapper: Cursor runs its bundled claude; {MODE_ENV}=passthrough in {ENV_SETTING} applies after ai-env wrapper install --write"));
        let typo = CursorEnv { mode: Some("remotely".into()), ..CursorEnv::default() };
        assert_eq!(text(&row_effective_mode(Spawn::Wrapper, &typo, &remote)), text(&row_effective_mode(Spawn::Wrapper, &none, &remote)), "a mode it does not name is ignored");
        let lab = CursorEnv { mode: Some("local-child".into()), ..CursorEnv::default() };
        assert!(text(&row_effective_mode(Spawn::Wrapper, &lab, &remote)).1.starts_with("effective mode local-child ("));
        // Failing closed: a mode the wrapper cannot take, a bridge.toml that does not load.
        let named_remote = CursorEnv { mode: Some("remote".into()), ..CursorEnv::default() };
        for (what, env, l) in [
            ("an unknown mode", &none, loaded("[wrapper]\nmode = \"remotely\"\n[workspaces]\nroots = [\"/a\"]\n")),
            // P0 refuses the key whatever the variable names: remote is no way past it.
            ("the variable's remote over an unknown mode", &named_remote, loaded(&format!("[wrapper]\nmode = \"remotely\"\n[workspaces]\nroots = [\"/a\"]\n{AWS}"))),
            ("remote, not loading", &none, broken(Some(Some("remote")), None)),
            ("a mode it cannot read", &none, broken(None, None)),
        ] {
            assert_eq!(fails_closed(Mode::Remote, &l), Some(Closed::File), "{what}");
            let (tag, t) = text(&row_effective_mode(Spawn::Wrapper, env, &l));
            assert!(tag == Tag::Warn && t.ends_with("failing closed: every Cursor chat under the roots exits 1 (the rows above)"), "{what}: {t}");
            let (tag, t) = text(&row_effective_mode(Spawn::Bundled, env, &l));
            assert_eq!((tag, t), (Tag::Skip, "no wrapper: Cursor runs its bundled claude; remote mode failing closed (the rows above) applies after ai-env wrapper install --write".to_string()), "{what}");
        }
        let (tag, t) = text(&row_effective_mode(Spawn::Wrapper, &none, &broken(Some(Some("passthrough")), None)));
        assert!(tag == Tag::Ok && t.starts_with("effective mode passthrough ([wrapper] mode)"), "a broken passthrough file stays passthrough: {t}");
        assert_eq!(fails_closed(Mode::Passthrough, &broken(Some(Some("passthrough")), None)), None);
        // Failing closed on another check of a remote session's start ([aws] missing, a name P0 refuses): its exit code, its row below.
        let unplanned = loaded("[wrapper]\nmode = \"remote\"\n[workspaces]\nroots = [\"/a\"]\n");
        let image = "config: [aws].image_arn is not set in bridge.toml and no --image was given (run `make infra-status WRITE=1`)";
        assert_eq!(fails_closed(Mode::Remote, &unplanned), Some(Closed::Check(1, image.to_string())));
        assert_eq!(
            text(&row_effective_mode(Spawn::Wrapper, &none, &unplanned)),
            (Tag::Warn, "effective mode remote ([wrapper] mode), failing closed: every Cursor chat under the roots exits 1 (the checks row below)".to_string())
        );
        // No wrapper: the checks row shows it too (row_session_checks), so this row points at it.
        assert_eq!(
            text(&row_effective_mode(Spawn::Bundled, &none, &unplanned)),
            (Tag::Skip, "no wrapper: Cursor runs its bundled claude; remote mode failing closed (the checks row below) applies after ai-env wrapper install --write".to_string())
        );
        let refused = loaded(&format!("[wrapper]\nmode = \"remote\"\nenv_extra = [\"NODE_OPTIONS\"]\n[workspaces]\nroots = [\"/a\"]\n{AWS}"));
        assert_eq!(fails_closed(Mode::Remote, &refused).map(|c| c.code()), Some(9), "P0's refusal of a configured name");
        assert!(text(&row_effective_mode(Spawn::Wrapper, &none, &refused)).1.ends_with("failing closed: every Cursor chat under the roots exits 9 (the checks row below)"));
        // No root (and roots that read): no chat goes remote (route::decide_loaded), so none fails at its start,
        // whatever the file fails; the chats run on this Mac.
        let no_root = "effective mode remote ([wrapper] mode), but no root: every Cursor chat runs on this Mac";
        for (what, env, l) in [
            ("no [aws]", &none, loaded("[wrapper]\nmode = \"remote\"\n")),
            ("an unknown mode", &none, loaded("[wrapper]\nmode = \"remotely\"\n")),
            ("the variable's remote over an unknown mode", &named_remote, loaded("[wrapper]\nmode = \"remotely\"\n")),
            ("remote, not loading", &none, broken(Some(Some("remote")), Some(Vec::new()))),
            ("a mode it cannot read", &none, broken(None, Some(Vec::new()))),
            ("the variable's remote over passthrough, not loading", &named_remote, broken(Some(Some("passthrough")), Some(Vec::new()))),
        ] {
            assert_eq!(fails_closed(Mode::Remote, &l), None, "{what}");
            let (tag, t) = text(&row_effective_mode(Spawn::Wrapper, env, &l));
            assert!(tag == Tag::Ok && t.starts_with("effective mode remote (") && t.ends_with("), but no root: every Cursor chat runs on this Mac"), "{what}: {t}");
            // No wrapper: the variable, or the mode the file is taken as, never `[wrapper] mode`'s value (it may name none).
            let after = if env.named_mode().is_some() { format!("{MODE_ENV}=remote in {ENV_SETTING}") } else { "remote mode with no root (every chat on this Mac)".to_string() };
            assert_eq!(text(&row_effective_mode(Spawn::Bundled, env, &l)), (Tag::Skip, format!("no wrapper: Cursor runs its bundled claude; {after} applies after ai-env wrapper install --write")), "{what}");
        }
        assert_eq!(text(&row_effective_mode(Spawn::Wrapper, &none, &loaded("[wrapper]\nmode = \"remote\"\n"))), (Tag::Ok, no_root.to_string()));
        // With a root, the same variable over the same broken passthrough file fails closed.
        assert_eq!(fails_closed(Mode::Remote, &broken(Some(Some("passthrough")), Some(vec![PathBuf::from("/a")]))), Some(Closed::File));
        // Another mode named: nothing of remote's applies.
        let passthrough = CursorEnv { mode: Some("passthrough".into()), ..CursorEnv::default() };
        assert_eq!(text(&row_effective_mode(Spawn::Wrapper, &passthrough, &unplanned)).0, Tag::Ok);
        assert_eq!(fails_closed(Mode::Passthrough, &unplanned), None);
    }

    /// What Cursor starts, from its wrapper key: a wrapper that is no
    /// executable file cannot run, an empty key is no wrapper. The wrapper
    /// routes Cursor's chats when it is what Cursor starts (or the settings
    /// were not read) and the kill switch is off.
    #[test]
    fn spawn_follows_the_wrapper_key() {
        let set = settings(serde_json::json!([]));
        assert_eq!(Spawn::of(None, &|_| (true, true)), Spawn::Unknown);
        assert_eq!(Spawn::of(Some(None), &|_| (true, true)), Spawn::Bundled);
        assert_eq!(Spawn::of(Some(Some(&set)), &|_| (true, true)), Spawn::Wrapper);
        assert_eq!(Spawn::of(Some(Some(&set)), &|_| (true, false)), Spawn::Unrunnable);
        assert_eq!(Spawn::of(Some(Some(&set)), &|_| (false, false)), Spawn::Unrunnable);
        assert_eq!(Spawn::of(Some(Some(&serde_json::json!({ WRAPPER_SETTING: "" }))), &|_| (true, true)), Spawn::Bundled);
        let (none, off, kill) = (CursorEnv::default(), CursorEnv { local: Some(false), ..CursorEnv::default() }, CursorEnv { local: Some(true), ..CursorEnv::default() });
        for (spawn, routes) in [(Spawn::Wrapper, true), (Spawn::Unknown, true), (Spawn::Bundled, false), (Spawn::Unrunnable, false)] {
            assert_eq!(spawn.wraps(&none), routes, "{spawn:?}");
            assert_eq!(spawn.wraps(&off), routes, "{spawn:?}, not 1");
            assert!(!spawn.wraps(&kill), "{spawn:?}, the kill switch");
        }
    }

    /// One row per root; one that is no directory warns; roots a broken
    /// bridge.toml hides are `[NO ]` in remote mode while the wrapper routes
    /// Cursor's chats, `[!! ]` (what comes once it does) while it does not.
    #[test]
    fn the_root_rows_name_each_root() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().display().to_string();
        let both = loaded(&format!("[workspaces]\nroots = [{root:?}, \"/nonexistent-root\"]\n[[workspace]]\npath = {root:?}\n"));
        assert_eq!(texts(&rows_roots(&both, Mode::Remote, true)), vec![(Tag::Ok, format!("workspace root {root}")), (Tag::Warn, "workspace root /nonexistent-root is no directory: no chat runs under it".to_string())]);
        assert_eq!(texts(&rows_roots(&both, Mode::Remote, false)), texts(&rows_roots(&both, Mode::Remote, true)), "roots it reads are what they are");
        assert_eq!(texts(&rows_roots(&loaded(""), Mode::Remote, true)), vec![(Tag::Skip, "no workspace root ([workspaces].roots, [[workspace]].path)".to_string())]);
        let listed = broken(Some(Some("remote")), Some(vec![d.path().to_path_buf()]));
        assert_eq!(texts(&rows_roots(&listed, Mode::Remote, true)), vec![(Tag::Ok, format!("workspace root {root}"))], "the roots a broken file still names");
        let hidden = broken(Some(Some("remote")), None);
        assert_eq!(
            texts(&rows_roots(&hidden, Mode::Remote, true)),
            vec![(Tag::No, "workspace roots unreadable (bridge.toml does not load): in remote mode every Cursor chat counts as under them and exits 1  <- fix bridge.toml (the bridge.toml row above)".to_string())]
        );
        assert_eq!(
            texts(&rows_roots(&hidden, Mode::Remote, false)),
            vec![(Tag::Warn, "workspace roots unreadable (bridge.toml does not load): once the wrapper routes Cursor's chats, in remote mode every one counts as under them and exits 1  <- fix bridge.toml (the bridge.toml row above)".to_string())],
            "no wrapper or the kill switch: no chat exits 1 yet"
        );
        for wraps in [true, false] {
            assert_eq!(texts(&rows_roots(&hidden, Mode::Passthrough, wraps)), vec![(Tag::Skip, "workspace roots unreadable (bridge.toml does not load)".to_string())]);
        }
        assert_eq!(texts(&rows_roots(&Loaded::default(), Mode::Passthrough, true))[0].0, Tag::Skip, "no bridge.toml: no root");
    }

    /// bridge.toml's mode row is doctor's while that holds: the wrapper
    /// routes Cursor's chats and Cursor's mode variable names no mode other
    /// than the file's; but doctor's `[NO ]`, which fails every chat under
    /// the roots closed, says with no root that every chat runs here. Else
    /// it is the file alone, `[-  ]`: no wrapper, the kill switch, another
    /// mode named; doctor's `[NO ]` (a mode the wrapper does not know, a
    /// remote file that does not load) stays `[NO ]`, and its `[!! ]`
    /// (remote without a root) stays `[!! ]`, each with its fix.
    #[test]
    fn the_mode_row_is_doctors_only_while_it_holds() {
        use crate::bridge::doctor::rows_s8;
        let doctor = |l: &Loaded| rows_s8(l.cfg.as_ref().unwrap()).remove(0);
        let over = |m: &str| CursorEnv { mode: Some(m.into()), ..CursorEnv::default() };
        let (none, kill) = (CursorEnv::default(), CursorEnv { local: Some(true), ..CursorEnv::default() });
        let now = ": not what Cursor's chats get now (the effective mode below)";
        let remote = loaded("[wrapper]\nmode = \"remote\"\n[workspaces]\nroots = [\"/a\"]\n");
        // Doctor's: no variable, one naming the file's mode, one naming none (the wrapper ignores it).
        for env in [&none, &over("remote"), &over("remotely")] {
            assert_eq!(row_configured_mode(doctor(&remote), &remote, env, true), doctor(&remote), "{env:?}");
        }
        let file_only = (Tag::Skip, format!("bridge.toml [wrapper] mode \"remote\" (1 root){now}"));
        // No wrapper or the kill switch (the wrapper routes nothing), or another mode named.
        for (env, wraps) in [(&none, false), (&kill, false), (&over("passthrough"), true), (&over("local-child"), true)] {
            assert_eq!(text(&row_configured_mode(doctor(&remote), &remote, env, wraps)), file_only, "{env:?} {wraps}");
        }
        let passthrough = loaded("[workspaces]\nroots = [\"/a\", \"/b\"]\n");
        assert_eq!(text(&row_configured_mode(doctor(&passthrough), &passthrough, &over("remote"), true)), (Tag::Skip, format!("bridge.toml [wrapper] mode \"passthrough\" (2 roots){now}")));
        assert_eq!(row_configured_mode(doctor(&passthrough), &passthrough, &over("passthrough"), true), doctor(&passthrough));
        // Remote without a root: doctor's [!! ] while it holds, else the file alone, still [!! ] with doctor's fix.
        let rootless = loaded("[wrapper]\nmode = \"remote\"\n");
        assert_eq!(text(&doctor(&rootless)).0, Tag::Warn);
        assert_eq!(row_configured_mode(doctor(&rootless), &rootless, &none, true), doctor(&rootless));
        let warned = (Tag::Warn, format!("bridge.toml [wrapper] mode \"remote\" (no root){now}; remote without a root runs every chat on this Mac  <- add the roots to bridge.toml"));
        for (env, wraps) in [(&none, false), (&kill, false), (&over("passthrough"), true)] {
            assert_eq!(text(&row_configured_mode(doctor(&rootless), &rootless, env, wraps)), warned, "{env:?} {wraps}");
        }
        // A mode the wrapper does not know is taken as remote: wrong whatever runs now.
        let typo = loaded("[wrapper]\nmode = \"remotely\"\n[workspaces]\nroots = [\"/a\"]\n");
        assert!(doctor(&typo).is_no());
        for env in [&none, &over("remote")] {
            assert_eq!(row_configured_mode(doctor(&typo), &typo, env, true), doctor(&typo), "{env:?}: P0 still refuses the key");
        }
        let wrong = (Tag::No, format!("bridge.toml [wrapper] mode \"remotely\" (1 root), which names no mode{now}  <- set [wrapper] mode to \"passthrough\" or \"remote\" in bridge.toml"));
        assert_eq!(text(&row_configured_mode(doctor(&typo), &typo, &over("passthrough"), true)), wrong);
        assert_eq!(text(&row_configured_mode(doctor(&typo), &typo, &none, false)), wrong);
        // With no root no chat goes remote: doctor's "fails closed" does not hold while the wrapper routes in
        // that mode, every chat runs here; the file is still wrong, [NO ] with doctor's fix.
        let rootless_typo = loaded("[wrapper]\nmode = \"remotely\"\n");
        let until = ": every Cursor chat runs on this Mac until bridge.toml names a root, then every chat under it exits 1 at its start";
        for env in [&none, &over("remote"), &over("remotely")] {
            let want = (Tag::No, format!("bridge.toml [wrapper] mode \"remotely\" (no root), which names no mode{until}  <- ai-env wrapper install --write --mode remote (or passthrough)"));
            assert_eq!(text(&row_configured_mode(doctor(&rootless_typo), &rootless_typo, env, true)), want, "{env:?}");
        }
        let wrong = (Tag::No, format!("bridge.toml [wrapper] mode \"remotely\" (no root), which names no mode{now}  <- set [wrapper] mode to \"passthrough\" or \"remote\" in bridge.toml"));
        assert_eq!(text(&row_configured_mode(doctor(&rootless_typo), &rootless_typo, &none, false)), wrong, "the file alone says nothing of what fails");
        // A file that does not load: doctor's row and what the wrapper reads of it, both from the file.
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().to_path_buf(), None);
        let fix = "  <- fix bridge.toml (the bridge.toml row above)";
        for (toml, want) in [
            ("[wrapper]\nmode = \"remote\"\nnope = 1\n[workspaces]\nroots = [\"/a\"]\n", (Tag::No, format!("bridge.toml, which does not load, [wrapper] mode \"remote\" (1 root){now}{fix}"))),
            ("[wrapper\n", (Tag::No, format!("bridge.toml, which does not load, [wrapper] mode unreadable (its roots unreadable){now}{fix}"))),
            ("nope = 1\n", (Tag::Skip, format!("bridge.toml, which does not load, [wrapper] mode unset (no root){now}"))),
        ] {
            std::fs::write(&paths.config, toml).unwrap();
            let doctor = rows_s8_loaded(&paths, &BridgeConfig::load(&paths)).remove(0);
            let l = Loaded { broken: Some(Broken::read(Some(toml))), note: Some("config: bridge.toml: x".into()), ..Loaded::default() };
            assert_eq!(row_configured_mode(doctor.clone(), &l, &none, true), doctor, "{toml:?}: the wrapper routes");
            assert_eq!(text(&row_configured_mode(doctor, &l, &kill, false)), want, "{toml:?}");
        }
        // Remote (or a mode it cannot read), not loading, its roots read and none: every chat runs here until one comes.
        for (toml, mode) in [("[wrapper]\nmode = \"remote\"\nnope = 1\n", "\"remote\""), ("[wrapper]\nmode = 1\n", "unreadable")] {
            std::fs::write(&paths.config, toml).unwrap();
            let doctor = rows_s8_loaded(&paths, &BridgeConfig::load(&paths)).remove(0);
            assert!(doctor.is_no(), "{toml:?}: doctor's fails closed");
            let l = Loaded { broken: Some(Broken::read(Some(toml))), note: Some("config: bridge.toml: x".into()), ..Loaded::default() };
            assert_eq!(text(&row_configured_mode(doctor.clone(), &l, &none, true)), (Tag::No, format!("bridge.toml, which does not load, [wrapper] mode {mode} (no root){until}{fix}")), "{toml:?}");
            assert_eq!(text(&row_configured_mode(doctor, &l, &kill, false)), (Tag::No, format!("bridge.toml, which does not load, [wrapper] mode {mode} (no root){now}{fix}")), "{toml:?}");
        }
        let absent = rows_s8_loaded(&paths, &Ok(None)).remove(0);
        assert_eq!(text(&row_configured_mode(absent, &Loaded::default(), &none, false)), (Tag::Skip, format!("no bridge.toml ([wrapper] mode passthrough, the default){now}")));
    }

    /// The checks a remote session runs at its start, in P0's order, on a
    /// bridge.toml that loads: `[ok ]`, or `[NO ]` with the exit code P0's
    /// failure has and the first failing check's first line, scrubbed; a
    /// `[wrapper] mode` it does not know is `[!! ]` (the mode row carries the
    /// `[NO ]`). No row unless such a session can start once the wrapper
    /// routes Cursor's chats: remote, the file loading, a root to route on;
    /// while the wrapper does not route them (no wrapper, the kill switch),
    /// the same row says so, a failure still `[NO ]`.
    #[test]
    fn the_session_checks_row_runs_the_checks_of_a_remote_sessions_start() {
        let ok = loaded(&format!("[wrapper]\nmode = \"remote\"\n[workspaces]\nroots = [\"/a\"]\n{AWS}"));
        let passes = Some((Tag::Ok, "bridge.toml passes the checks a remote session runs at its start".to_string()));
        assert_eq!(row_session_checks(&ok, Mode::Remote, true).map(|l| text(&l)), passes);
        assert_eq!(remote_checks(ok.cfg.as_ref().unwrap()), Ok(()));
        assert_eq!(row_session_checks(&ok, Mode::Remote, false).map(|l| text(&l)), passes, "no wrapper, the kill switch: the same checks");
        for mode in [Mode::Passthrough, Mode::LocalChild, Mode::LocalScratch] {
            assert_eq!(row_session_checks(&ok, mode, true), None, "{mode:?}");
        }
        assert_eq!(row_session_checks(&broken(Some(Some("remote")), None), Mode::Remote, true), None, "a file that does not load has its own rows");
        assert_eq!(row_session_checks(&Loaded::default(), Mode::Remote, true), None, "no bridge.toml: no session goes remote");
        // No root: no session goes remote, so no row, whatever the checks would say (no [aws] here, an unknown mode).
        for rootless in [loaded("[wrapper]\nmode = \"remote\"\n"), loaded(&format!("[wrapper]\nmode = \"remote\"\n{AWS}")), loaded("[wrapper]\nmode = \"remotely\"\n")] {
            for wraps in [true, false] {
                assert_eq!(row_session_checks(&rootless, Mode::Remote, wraps), None, "{rootless:?} {wraps}");
            }
        }
        let rooted = |toml: &str| loaded(&format!("[workspaces]\nroots = [\"/a\"]\n{toml}"));
        let again = " once the wrapper routes Cursor's chats again";
        // A mode the wrapper does not know: the session exits 1 on it, and the mode row above says so as [NO ].
        let typo = rooted(&format!("[wrapper]\nmode = \"remotely\"\n[seed]\nmax_mib = 0\n{AWS}"));
        assert_eq!(remote_checks(typo.cfg.as_ref().unwrap()), Err((1, "config: [wrapper].mode = \"remotely\": must be \"passthrough\" or \"remote\"".to_string())));
        assert_eq!(row_session_checks(&typo, Mode::Remote, true).map(|l| text(&l)), Some((Tag::Warn, "a remote session would exit 1 at its start: [wrapper] mode (the [NO ] row above)".to_string())));
        assert_eq!(row_session_checks(&typo, Mode::Remote, false).map(|l| text(&l)), Some((Tag::Warn, format!("a remote session would exit 1 at its start{again}: [wrapper] mode (the [NO ] row above)"))));
        let token = format!("{}oat01-{}", "sk-ant-", "Q".repeat(24));
        let credentials = format!("[aws]\ncredentials = \"{token}\"\n[transport]\nsuspend_wait_s = 5\n");
        let rfc1918 = "expected an RFC 1918 IPv4 address (10/8, 172.16/12, 192.168/16)";
        let image = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env";
        let no_connector = format!("[aws]\nimage_arn = \"{image}\"\n[creds]\nmode = \"x\"\n");
        let creds = format!("{AWS}[creds]\nmode = \"reverse-refresh\"\n[wrapper]\nenv_extra = [\"NODE_OPTIONS\"]\n");
        let names = format!("{AWS}[wrapper]\nenv_forward = [\"LANG\", \"no-name\"]\nenv_extra = [\"NODE_OPTIONS\"]\n");
        // Each a later check's failure too: the first in P0's order is the one named, with its exit code.
        for (toml, code, first) in [
            ("[seed]\nmax_mib = 0\n[vm]\nmax_idle_s = 10\n", 1, "config: [seed].max_mib: 0 is outside 1..=1024".to_string()),
            ("[vm]\nmax_idle_s = 10\n[aws]\nproxy_private_ip = \"8.8.8.8\"\n", 1, "config: [vm].max_idle_s: must be 300..=28800 (plan §2.8: suspending sooner costs more than it saves)".to_string()),
            ("[aws]\nproxy_private_ip = \"8.8.8.8\"\ncredentials = \"x\"\n", 1, format!("config: [aws].proxy_private_ip = \"8.8.8.8\": {rfc1918}")),
            ("[egress]\naccept_platform_dns = \"x\"\n[aws]\ncredentials = \"x\"\n", 1, "config: [egress].accept_platform_dns = \"x\": not an IP address (name the platform resolver you tested by its address, as `ai-env lab run dns-path` prints it: \"fd00:ec2::253\")".to_string()),
            (credentials.as_str(), 1, format!("config: [aws].credentials = \"sk-ant-[redacted:len={}]\": expected \"container\" or \"profile:<name>\"", token.len())),
            ("[transport]\nsuspend_wait_s = 5\n", 1, "config: [transport].suspend_wait_s = 5 is outside 10..=3600".to_string()),
            // The run plan (no workspace): the image, then vpc egress's connector (P0 refuses that: exit 9).
            ("[creds]\nmode = \"x\"\n", 1, "config: [aws].image_arn is not set in bridge.toml and no --image was given (run `make infra-status WRITE=1`)".to_string()),
            ("[aws]\nimage_arn = \"ai-env\"\n", 1, "config: [aws].image_arn = \"ai-env\": expected arn:aws:lambda:eu-central-1:<account>:microvm-image:<name>".to_string()),
            (no_connector.as_str(), 9, BridgeError::EgressRequired.to_string()),
            // [creds]: P0 takes even its policy refusal as a config error (exit 1).
            (creds.as_str(), 1, "refused: [creds].mode \"reverse-refresh\" (Tier B) is not built: use \"setup-token\"".to_string()),
            // The names a session's environment may hold: P0's refusal, exit 9.
            (names.as_str(), 9, "[wrapper].env_forward holds \"no-name\": not a variable name ([A-Za-z_][A-Za-z0-9_]*)".to_string()),
            (&format!("{AWS}[wrapper]\nenv_extra = [\"NODE_OPTIONS\"]\n"), 9, "[wrapper].env_extra names NODE_OPTIONS: it changes how claude and node start in the VM; remove it from bridge.toml".to_string()),
        ] {
            let l = rooted(toml);
            assert_eq!(fails_closed(Mode::Remote, &l), Some(Closed::Check(code, first.clone())), "{toml}");
            let row = row_session_checks(&l, Mode::Remote, true).map(|l| text(&l));
            assert_eq!(row, Some((Tag::No, format!("a remote session would exit {code} at its start: {first}  <- fix bridge.toml"))), "{toml}");
            let row = row_session_checks(&l, Mode::Remote, false).map(|l| text(&l));
            assert_eq!(row, Some((Tag::No, format!("a remote session would exit {code} at its start{again}: {first}  <- fix bridge.toml"))), "{toml}: no wrapper");
        }
        // The legacy accept_platform_dns = true: `vm` commands warn of it, never refuse; status says nothing of it.
        assert_eq!(row_session_checks(&rooted(&format!("[egress]\naccept_platform_dns = true\n{AWS}")), Mode::Remote, true).map(|l| text(&l).0), Some(Tag::Ok));
    }

    /// A census row as `census::build_row` writes one (`start` from the same
    /// clock read as `ts`); `end`: the pump's end row of that spawn, a minute
    /// later, its note extended.
    fn row(ts: &str, route: &str, reason: &str, ext: Option<&str>, note: Option<&str>, end: bool) -> Value {
        let start = crate::wire::time::parse_rfc3339_utc(ts).unwrap() * 1000;
        let mut r = serde_json::json!({"v": 1, "ts": ts, "start": start, "route": route, "reason": reason, "ext": ext, "note": note});
        if end {
            r["end"] = serde_json::json!(start + 60_000);
            r["note"] = serde_json::json!(note.map_or_else(|| "end:eof_term".to_string(), |n| format!("{n}; end:eof_term")));
        }
        r
    }

    /// The installed extension as doctor picks it from the directories
    /// listed, with how many of them are its; never a bundled claude's version.
    #[test]
    fn the_extension_row_names_the_newest_installed() {
        let dir = |v: &str| format!("anthropic.claude-code-{v}-darwin-arm64");
        assert_eq!(text(&row_extension(&[dir("2.1.300"), dir("2.1.296"), dir("2.1.299")])), (Tag::Ok, "cursor extension 2.1.300 (3 versions installed)".to_string()));
        assert_eq!(text(&row_extension(&[dir("2.1.296"), "some.other-extension-1.0.0".to_string()])), (Tag::Ok, "cursor extension 2.1.296".to_string()));
        assert_eq!(text(&row_extension(&["some.other-extension-1.0.0".to_string()])), (Tag::Skip, "Cursor Claude extension not found under ~/.cursor/extensions".to_string()));
        assert_eq!(text(&row_extension(&[])), text(&row_cursor_bundle(&[], None)), "doctor's row for none");
    }

    /// Where a reload sends the chats it restarts: in remote mode with a root
    /// to route on, those under the roots to their MicroVM, or to an exit at
    /// their start while remote mode fails closed; without a root, or in any
    /// other mode, on this Mac.
    #[test]
    fn the_reload_restarts_chats_where_the_mode_and_the_roots_send_them() {
        let ok = loaded(&format!("[wrapper]\nmode = \"remote\"\n[workspaces]\nroots = [\"/a\"]\n{AWS}"));
        assert_eq!(Restart::of(Mode::Remote, &ok), Restart::MicroVm);
        for mode in [Mode::Passthrough, Mode::LocalChild, Mode::LocalScratch] {
            assert_eq!(Restart::of(mode, &ok), Restart::Here, "{mode:?}");
        }
        assert_eq!(Restart::of(Mode::Remote, &loaded("[wrapper]\nmode = \"remote\"\n[workspaces]\nroots = [\"/a\"]\n")), Restart::Exit, "no [aws]");
        assert_eq!(Restart::of(Mode::Remote, &broken(Some(Some("remote")), None)), Restart::Exit, "roots it cannot read");
        assert_eq!(Restart::of(Mode::Remote, &broken(Some(Some("remote")), Some(vec![PathBuf::from("/a")]))), Restart::Exit);
        // No root: nothing goes remote, so nothing fails closed either.
        for rootless in [loaded("[wrapper]\nmode = \"remote\"\n"), loaded("[wrapper]\nmode = \"remotely\"\n"), broken(Some(Some("remote")), Some(Vec::new())), Loaded::default()] {
            assert_eq!(Restart::of(Mode::Remote, &rootless), Restart::Here, "{rootless:?}");
        }
    }

    /// The newest spawn that names an extension, by `start`, against the one
    /// installed; while the wrapper does not route Cursor's chats the census
    /// is not what Cursor runs now: `[-  ]`, no hint; nor is it while that row
    /// predates the last change of Cursor's settings.json. The hint says where
    /// the reload sends the chats it restarts ([`Restart`]).
    #[test]
    fn the_last_extension_is_the_newest_row_that_names_one() {
        let census = Path::new("/h/bridge/logs/census.jsonl");
        let here = "<- a window reload picks it up (it restarts open chats on this Mac)";
        let away = "<- a window reload picks it up, and restarts every open chat through the wrapper: those under the roots go to their MicroVM (to keep one on this Mac: the README's \"No wrapper at all\")";
        let closed = "<- a window reload picks it up, and restarts every open chat through the wrapper: those under the roots exit at their start until bridge.toml is fixed (the rows above)";
        let last = |rows: &[Value], installed: Option<&str>, wraps: bool| text(&row_last_extension(rows, installed, census, wraps, None, Restart::Here));
        assert_eq!(last(&[], Some("2.1.300"), true), (Tag::Skip, "no census row names an extension yet (/h/bridge/logs/census.jsonl)".to_string()));
        let mut rows = vec![row("2026-10-11T08:00:00Z", "local", "subcommand:auth", Some("2.1.290"), None, false), row("2026-10-12T08:00:00Z", "remote", "session", Some("2.1.296"), None, false), row("2026-10-13T08:00:00Z", "local", "version", None, None, false)];
        assert_eq!(last(&rows, Some("2.1.300"), true), (Tag::Warn, format!("Cursor last ran extension 2.1.296 (2026-10-12T08:00:00Z); 2.1.300 is installed  {here}")));
        assert_eq!(
            text(&row_last_extension(&rows, Some("2.1.300"), census, true, None, Restart::MicroVm)),
            (Tag::Warn, format!("Cursor last ran extension 2.1.296 (2026-10-12T08:00:00Z); 2.1.300 is installed  {away}"))
        );
        assert_eq!(
            text(&row_last_extension(&rows, Some("2.1.300"), census, true, None, Restart::Exit)),
            (Tag::Warn, format!("Cursor last ran extension 2.1.296 (2026-10-12T08:00:00Z); 2.1.300 is installed  {closed}"))
        );
        assert_eq!(last(&rows, Some("2.1.296"), true), (Tag::Ok, "Cursor last ran extension 2.1.296 (2026-10-12T08:00:00Z)".to_string()));
        assert_eq!(text(&row_last_extension(&rows, Some("2.1.296"), census, true, None, Restart::MicroVm)), last(&rows, Some("2.1.296"), true), "no reload to advise");
        // Cursor's settings.json changed after that row (the wrapper's key out and back, a reload in
        // between, say): what Cursor runs now is unknown, so no claim and no hint, until a newer row.
        let ms = |ts: &str| crate::wire::time::parse_rfc3339_utc(ts).unwrap() * 1000;
        let unknown = (Tag::Skip, "the newest census row names extension 2.1.296 (2026-10-12T08:00:00Z) and predates the last change of Cursor's settings.json (2026-10-12T09:30:00Z): what Cursor has run since is unknown until it starts a process through the wrapper".to_string());
        for (installed, restart) in [(Some("2.1.300"), Restart::MicroVm), (Some("2.1.300"), Restart::Here), (Some("2.1.296"), Restart::Exit), (None, Restart::Here)] {
            assert_eq!(text(&row_last_extension(&rows, installed, census, true, Some(ms("2026-10-12T09:30:00Z")), restart)), unknown, "{installed:?} {restart:?}");
        }
        // A millisecond is enough, and the change shows to the millisecond, never as the row's own second.
        let within = "the newest census row names extension 2.1.296 (2026-10-12T08:00:00Z) and predates the last change of Cursor's settings.json (2026-10-12T08:00:00.001Z): what Cursor has run since is unknown until it starts a process through the wrapper";
        assert_eq!(text(&row_last_extension(&rows, Some("2.1.300"), census, true, Some(ms("2026-10-12T08:00:00Z") + 1), Restart::Here)), (Tag::Skip, within.to_string()));
        assert_eq!((shown_ms(ms("2026-10-12T08:00:00Z")), shown_ms(ms("2026-10-12T08:00:00Z") + 250)), ("2026-10-12T08:00:00Z".to_string(), "2026-10-12T08:00:00.250Z".to_string()));
        // A row that names one after the change: today's rows.
        assert_eq!(text(&row_last_extension(&rows, Some("2.1.300"), census, true, Some(ms("2026-10-12T08:00:00Z")), Restart::MicroVm)).1, format!("Cursor last ran extension 2.1.296 (2026-10-12T08:00:00Z); 2.1.300 is installed  {away}"));
        assert_eq!(text(&row_last_extension(&rows, Some("2.1.300"), census, true, Some(ms("2026-10-01T00:00:00Z")), Restart::Here)), last(&rows, Some("2.1.300"), true));
        // A row without `start` (no census writer leaves it out) by its `ts`, read to the second it names:
        // before a change later than that second's start, never before one at or before it; one without
        // a `ts` that reads is before any change.
        let mut no_start = rows[1].clone();
        no_start.as_object_mut().unwrap().remove("start");
        let alone = |row: &Value, changed: Option<u64>| text(&row_last_extension(std::slice::from_ref(row), Some("2.1.300"), census, true, changed, Restart::Here));
        assert_eq!(alone(&no_start, Some(ms("2026-10-12T08:00:00Z") + 1)), (Tag::Skip, within.to_string()));
        for changed in [Some(ms("2026-10-12T08:00:00Z")), Some(ms("2026-10-11T08:00:00Z")), None] {
            assert_eq!(alone(&no_start, changed), last(&rows, Some("2.1.300"), true), "{changed:?}: today's row");
        }
        no_start["ts"] = serde_json::json!("2026-10-12T10:00:00+02:00");
        assert_eq!(alone(&no_start, Some(ms("2026-10-12T08:00:00Z") + 1)).0, Tag::Skip, "an offset reads as its instant");
        assert_eq!(alone(&no_start, Some(ms("2026-10-12T08:00:00Z"))).0, Tag::Warn);
        no_start["ts"] = serde_json::json!("not a time");
        assert_eq!(alone(&no_start, Some(1)).0, Tag::Skip, "no time it reads: before any change");
        assert_eq!(last(&rows, None, true).0, Tag::Ok, "nothing installed to compare with");
        // A reloaded window's chat starts on 2.1.300, then the old 2.1.296 session's end row lands: the spawn is newer.
        rows.push(row("2026-10-15T08:00:00Z", "remote", "session", Some("2.1.300"), Some("mode:remote(config)"), false));
        rows.push(row("2026-10-12T08:00:00Z", "remote", "session", Some("2.1.296"), None, true));
        assert_eq!(last(&rows, Some("2.1.300"), true), (Tag::Ok, "Cursor last ran extension 2.1.300 (2026-10-15T08:00:00Z)".to_string()));
        // An end row whose start row the tail no longer holds still stands for its spawn.
        assert_eq!(last(&rows[4..], Some("2.1.300"), true).1, format!("Cursor last ran extension 2.1.296 (2026-10-12T08:00:00Z); 2.1.300 is installed  {here}"));
        // No wrapper or the kill switch: what Cursor runs now leaves no row, and no hint whatever the mode.
        let stale = (Tag::Skip, "the newest census row names extension 2.1.296 (2026-10-12T08:00:00Z); what Cursor runs now leaves no census row (the rows above)".to_string());
        assert_eq!(last(&rows[..3], Some("2.1.300"), false), stale);
        assert_eq!(text(&row_last_extension(&rows[..3], Some("2.1.300"), census, false, None, Restart::MicroVm)), stale);
        assert_eq!(text(&row_last_extension(&rows[..3], Some("2.1.300"), census, false, None, Restart::Exit)), stale);
        assert_eq!(text(&row_last_extension(&rows[..3], Some("2.1.300"), census, false, Some(ms("2026-10-12T09:30:00Z")), Restart::MicroVm)), stale, "no wrapper says why first");
        assert_eq!(last(&[], Some("2.1.300"), false).0, Tag::Skip);
    }

    /// A census row's `ext` and `ts` print only in the shapes the wrapper
    /// writes (a version, a timestamp), else as `unrecognised`: a newline and
    /// a forged row after it, a control character, a long or empty value
    /// never reach the output. A row without `ts` shows `?`.
    #[test]
    fn census_values_print_only_in_their_shapes() {
        for ext in ["2.1.300", "2.1.300-rc.1+build.7", &"9".repeat(32)] {
            assert_eq!(shown_ext(ext), ext);
        }
        for ext in ["", "2.1.300\n  [ok ] forged", "2.1.300 ", "2.1.300\u{1b}[2J", "2.1/300", "\"2.1.300\"", &"9".repeat(33), "2.1.30\u{e9}"] {
            assert_eq!(shown_ext(ext), "unrecognised", "{ext:?}");
        }
        let ts = |v: Value| shown_ts(&serde_json::json!({ "ts": v })).to_string();
        for ok in ["2026-10-15T08:00:00Z", "2026-10-15T08:00:00.123+02:00", &"1".repeat(40)] {
            assert_eq!(ts(ok.into()), ok);
        }
        for bad in ["", "2026-10-15T08:00:00Z\n  [ok ] forged", "2026-10-15 08:00:00Z", &"1".repeat(41)] {
            assert_eq!(ts(bad.into()), "unrecognised", "{bad:?}");
        }
        assert_eq!(ts(Value::Null), "?", "no string: none");
        assert_eq!(shown_ts(&serde_json::json!({})), "?");
        // In the rows: the forged line never shows, the version compares as written (not installed's).
        let census = Path::new("/h/census.jsonl");
        let mut forged = row("2026-10-12T08:00:00Z", "remote", "session", Some("2.1.296\n  [ok ] forged ext"), Some("mode:remote(config)"), false);
        forged["ts"] = serde_json::json!("2026-10-12T08:00:00Z\n  [ok ] forged ts");
        let rows = [forged];
        assert_eq!(
            text(&row_last_extension(&rows, Some("2.1.300"), census, true, None, Restart::Here)),
            (Tag::Warn, "Cursor last ran extension unrecognised (unrecognised); 2.1.300 is installed  <- a window reload picks it up (it restarts open chats on this Mac)".to_string())
        );
        assert_eq!(text(&row_last_extension(&rows, Some("2.1.300"), census, false, None, Restart::Here)).1, "the newest census row names extension unrecognised (unrecognised); what Cursor runs now leaves no census row (the rows above)");
        assert_eq!(text(&row_last_session(&rows, true, None)), (Tag::Ok, "Cursor's newest session (unrecognised) went to its workspace's MicroVM (mode:remote(config))".to_string()));
        assert_eq!(text(&row_last_session(&rows, false, None)).1, "the newest session in the census (unrecognised) went to its workspace's MicroVM (mode:remote(config)); what Cursor runs now leaves no census row (the rows above)");
        // So in the rows of a census row from before the last change of Cursor's settings.json.
        let later = Some(crate::wire::time::parse_rfc3339_utc("2026-10-13T00:00:00Z").unwrap() * 1000);
        let since = "and predates the last change of Cursor's settings.json (2026-10-13T00:00:00Z): what Cursor has run since is unknown until it starts a";
        assert_eq!(text(&row_last_extension(&rows, Some("2.1.300"), census, true, later, Restart::Here)).1, format!("the newest census row names extension unrecognised (unrecognised) {since} process through the wrapper"));
        assert_eq!(text(&row_last_session(&rows, true, later)).1, format!("the newest session in the census (unrecognised) went to its workspace's MicroVM (mode:remote(config)) {since} session through the wrapper"));
    }

    /// The newest session row decides, by `start` (an end row stands for its
    /// own session), by its route and its mode note together: a passthrough
    /// session under the roots (`route=remote`, no mode note) ran on this
    /// Mac, and so did one outside the roots in remote mode (its mode note,
    /// `route=local`); a subcommand never counts. While the wrapper does not
    /// route Cursor's chats, or that session predates the last change of
    /// Cursor's settings.json, the row is the census's, `[-  ]`.
    #[test]
    fn the_last_session_is_read_from_its_route_and_its_mode_note() {
        assert_eq!(text(&row_last_session(&[], true, None)), (Tag::Skip, "no session in the census yet".to_string()));
        let passthrough = row("2026-10-12T07:00:00Z", "remote", "session", Some("2.1.296"), None, false);
        assert_eq!(text(&row_last_session(std::slice::from_ref(&passthrough), true, None)), (Tag::Ok, "Cursor's newest session (2026-10-12T07:00:00Z) ran on this Mac".to_string()));
        let mut rows = vec![
            passthrough,
            row("2026-10-12T08:00:00Z", "remote", "session", Some("2.1.296"), Some("prewarm:skipped(x); mode:remote(config)"), false),
            row("2026-10-12T08:00:01Z", "local", "subcommand:auth", Some("2.1.296"), Some("mode:remote(config)"), false),
            row("2026-10-12T08:00:00Z", "remote", "session", Some("2.1.296"), Some("prewarm:skipped(x); mode:remote(config)"), true),
        ];
        assert_eq!(text(&row_last_session(&rows, true, None)), (Tag::Ok, "Cursor's newest session (2026-10-12T08:00:00Z) went to its workspace's MicroVM (mode:remote(config))".to_string()));
        assert_eq!(text(&row_last_session(&rows[3..], true, None)), text(&row_last_session(&rows, true, None)), "its end row alone tells the same");
        rows.push(row("2026-10-12T09:00:00Z", "local", "outside_roots", Some("2.1.296"), Some("mode:remote(config)"), false));
        assert_eq!(text(&row_last_session(&rows, true, None)), (Tag::Ok, "Cursor's newest session (2026-10-12T09:00:00Z) ran on this Mac".to_string()));
        rows.push(row("2026-10-12T10:00:00Z", "remote", "session", None, Some("mode:remote"), false));
        assert!(text(&row_last_session(&rows, true, None)).1.ends_with("went to its workspace's MicroVM (mode:remote)"), "Cursor's own mode variable notes it too");
        rows.push(row("2026-10-12T11:00:00Z", "remote", "session", None, Some("mode:local-child"), false));
        assert!(text(&row_last_session(&rows, true, None)).1.ends_with("ran on this Mac"), "a lab mode pipes it to a claude here");
        // A remote session that ends after a newer one started: its end row is the newest row, not the newest session.
        rows.push(row("2026-10-12T10:00:00Z", "remote", "session", None, Some("mode:remote"), true));
        assert_eq!(text(&row_last_session(&rows, true, None)), (Tag::Ok, "Cursor's newest session (2026-10-12T11:00:00Z) ran on this Mac".to_string()));
        // No wrapper or the kill switch: the census's newest session, not Cursor's.
        assert_eq!(
            text(&row_last_session(&rows[..6], false, None)),
            (Tag::Skip, "the newest session in the census (2026-10-12T10:00:00Z) went to its workspace's MicroVM (mode:remote); what Cursor runs now leaves no census row (the rows above)".to_string())
        );
        assert_eq!(text(&row_last_session(&[], false, None)), (Tag::Skip, "no session in the census yet".to_string()));
        // Cursor's settings.json changed after that session started: the newest session may be one the
        // census never saw; one that started after the change is Cursor's newest again.
        let ms = |ts: &str| crate::wire::time::parse_rfc3339_utc(ts).unwrap() * 1000;
        assert_eq!(
            text(&row_last_session(&rows[..6], true, Some(ms("2026-10-12T10:30:00Z")))),
            (Tag::Skip, "the newest session in the census (2026-10-12T10:00:00Z) went to its workspace's MicroVM (mode:remote) and predates the last change of Cursor's settings.json (2026-10-12T10:30:00Z): what Cursor has run since is unknown until it starts a session through the wrapper".to_string())
        );
        assert_eq!(text(&row_last_session(&rows[..6], true, Some(ms("2026-10-12T09:59:59Z")))), text(&row_last_session(&rows[..6], true, None)));
        assert!(text(&row_last_session(&rows[..6], true, Some(ms("2026-10-12T10:00:00Z") + 250))).1.contains("(2026-10-12T10:00:00Z) went to its workspace's MicroVM (mode:remote) and predates the last change of Cursor's settings.json (2026-10-12T10:00:00.250Z)"));
        assert_eq!(text(&row_last_session(&rows[..6], false, Some(ms("2026-10-12T10:30:00Z")))), text(&row_last_session(&rows[..6], false, None)), "no wrapper says why first");
        // A newer row of another kind (a subcommand after the change) does not make the session Cursor's newest.
        let mut after = rows[..6].to_vec();
        after.push(row("2026-10-12T10:31:00Z", "local", "subcommand:auth", Some("2.1.296"), None, false));
        assert_eq!(text(&row_last_session(&after, true, Some(ms("2026-10-12T10:30:00Z")))).0, Tag::Skip);
        assert_eq!(text(&row_last_session(&[], true, Some(ms("2026-10-12T10:30:00Z")))), (Tag::Skip, "no session in the census yet".to_string()));
    }

    /// A bridge.toml error's row keeps its first line only: the rest is a
    /// snippet of the file. That line can quote a value of it: scrubbed.
    #[test]
    fn the_bridge_toml_row_keeps_the_first_line_of_its_error() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().to_path_buf(), None);
        std::fs::write(&paths.config, "[wrapper]\nmode = \"remote\"\n[vm]\nmax_idle = 300\n").unwrap();
        let full = text(&row_bridge_config(&paths, &BridgeConfig::load(&paths))).1;
        assert!(full.lines().count() > 1 && full.contains("max_idle"), "doctor's row carries the snippet: {full}");
        let (tag, t) = text(&first_line(row_bridge_config(&paths, &BridgeConfig::load(&paths))));
        assert!(tag == Tag::No && t.starts_with("bridge.toml: config: bridge.toml: TOML parse error at line 4") && !t.contains('\n') && !t.contains("max_idle"), "{t}");
        assert_eq!(first_line(DoctorLine::plain("a\nb")), DoctorLine::plain("a\nb"));
        // A value on the first line (built at run time: no secret-shaped literal in the source).
        let token = format!("{}oat01-{}", "sk-ant-", "R".repeat(30));
        std::fs::write(&paths.config, format!("[aws]\nregion = \"{token}\"\n")).unwrap();
        assert!(text(&row_bridge_config(&paths, &BridgeConfig::load(&paths))).1.contains(&token), "doctor's row quotes it");
        let (tag, t) = text(&first_line(row_bridge_config(&paths, &BridgeConfig::load(&paths))));
        assert_eq!((tag, t), (Tag::No, format!("bridge.toml: config: [aws].region = \"sk-ant-[redacted:len={}]\" but the MicroVM bridge is pinned to eu-central-1 (eu-west-3 is not supported)", token.len())));
    }

    /// Doctor's mode row, kept while the wrapper routes in the file's mode,
    /// quotes `[wrapper] mode` as written: status prints it scrubbed; the
    /// file alone shows it scrubbed and capped.
    #[test]
    fn the_mode_rows_never_show_a_secret_looking_mode() {
        use crate::bridge::doctor::rows_s8;
        let token = format!("{}oat01-{}", "sk-ant-", "Q".repeat(40));
        let l = loaded(&format!("[wrapper]\nmode = \"{token}\"\n[workspaces]\nroots = [\"/a\"]\n"));
        let doctor = rows_s8(l.cfg.as_ref().unwrap()).remove(0);
        assert!(text(&doctor).1.contains(&token), "doctor's row quotes it");
        let masked = format!("\"sk-ant-[redacted:len={}]\"", token.len());
        let kept = text(&row_configured_mode(doctor.clone(), &l, &CursorEnv::default(), true));
        assert_eq!(kept, (Tag::No, format!("config: [wrapper].mode = {masked}: must be \"passthrough\" or \"remote\": every Cursor chat under the roots fails closed  <- ai-env wrapper install --write --mode remote (or passthrough)")));
        let alone = text(&row_configured_mode(doctor, &l, &CursorEnv::default(), false));
        assert!(alone.0 == Tag::No && alone.1.starts_with(&format!("bridge.toml [wrapper] mode {masked} (1 root), which names no mode")), "{alone:?}");
        // With no root, the row that says every chat runs here quotes it the same way.
        let rootless = loaded(&format!("[wrapper]\nmode = \"{token}\"\n"));
        let row = text(&row_configured_mode(rows_s8(rootless.cfg.as_ref().unwrap()).remove(0), &rootless, &CursorEnv::default(), true));
        assert!(row.0 == Tag::No && row.1.starts_with(&format!("bridge.toml [wrapper] mode {masked} (no root), which names no mode: every Cursor chat runs on this Mac")), "{row:?}");
        assert_eq!(shown_mode(&token), masked);
        assert_eq!(shown_mode(&"m".repeat(100)), format!("{:?}", "m".repeat(64)), "capped");
    }
}
