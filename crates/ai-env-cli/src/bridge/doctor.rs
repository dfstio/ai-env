//! Bridge rows appended to `ai-env doctor`. Every row builder is a pure
//! function of already-collected inputs so it is unit-testable without the
//! subprocesses that `rows` runs (5 s timeout each).
use crate::age_cmd::{effective_path, find_in_path};
use crate::bridge::config::{env_region_warning, BridgeConfig, Paths, REGION};
use crate::bridge::errors::BridgeError;
use crate::bridge::sibling::{find_sibling, Sibling, INSTALL_HINT};
use crate::commands::{DoctorLine, Tag};
use crate::store::Keystore;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const EXPECTED_TOOLCHAIN: &str = "1.98.1";
/// cargo-lambda below this embeds a cargo-zigbuild that cannot link aarch64
/// on rustc ≥ 1.9x (`--fix-cortex-a53-843419`), measured 19 Sep 2026.
pub const MIN_CARGO_LAMBDA: (u32, u32, u32) = (1, 9, 2);
pub const CARGO_LAMBDA_HINT: &str = "cargo install cargo-lambda --locked (≥ 1.9.2; a Homebrew cargo-lambda earlier on PATH shadows it: brew uninstall cargo-lambda)";
pub const WRAPPER_SETTING: &str = "claudeCode.claudeProcessWrapper";
pub const PERMISSION_SETTING: &str = "claudeCode.initialPermissionMode";
const NODE_SUFFIXES: [&str; 5] = [".js", ".mjs", ".ts", ".tsx", ".jsx"];

// ---- subprocess capture -------------------------------------------------------

/// What a finished child left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub code: Option<i32>,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

fn drain<R: Read>(pipe: Option<R>) -> String {
    let mut buf = Vec::new();
    if let Some(mut p) = pipe {
        let _ = p.read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Run `cmd` to completion under a wall-clock timeout. `stdin` (if any) is
/// written from its own thread and both output pipes are drained by reader
/// threads, so a child that fills either pipe can never block the caller.
/// The deadline covers the whole call: the child's lifetime and, after it
/// exits, the wait for its pipes to close (a grandchild that inherited them
/// keeps them open; that wait is bounded too and reported as an error).
/// On timeout the child is killed and the readers are abandoned, never
/// joined. The environment is left as the caller built it; see `run_capture`
/// for the credential-free probe.
pub fn capture(mut cmd: Command, stdin: Option<&[u8]>, timeout: Duration) -> Result<Captured, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("{program}: {e}"))?;
    if let (Some(bytes), Some(mut w)) = (stdin, child.stdin.take()) {
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = w.write_all(&bytes);
            // `w` drops here: the child sees EOF.
        });
    }
    let out = child.stdout.take();
    let err = child.stderr.take();
    let (tx_out, rx) = std::sync::mpsc::channel::<(bool, String)>();
    let tx_err = tx_out.clone();
    std::thread::spawn(move || {
        let _ = tx_out.send((true, drain(out)));
    });
    std::thread::spawn(move || {
        let _ = tx_err.send((false, drain(err)));
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program}: timed out after {}s", fmt_secs(timeout)));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(format!("{program}: {e}")),
        }
    };
    // The pipes close when their last holder exits; wait for the readers
    // within what is left of the deadline (at least a short grace period).
    let (mut stdout, mut stderr) = (None, None);
    while stdout.is_none() || stderr.is_none() {
        let remaining = timeout.saturating_sub(start.elapsed()).max(Duration::from_millis(500));
        match rx.recv_timeout(remaining) {
            Ok((true, s)) => stdout = Some(s),
            Ok((false, s)) => stderr = Some(s),
            Err(_) => return Err(format!("{program}: exited, but its output pipes stayed open past {}s (a process it started still holds them)", fmt_secs(timeout))),
        }
    }
    Ok(Captured { code: status.code(), success: status.success(), stdout: stdout.unwrap_or_default(), stderr: stderr.unwrap_or_default() })
}

fn fmt_secs(d: Duration) -> String {
    if d.as_secs_f64().fract() == 0.0 {
        d.as_secs().to_string()
    } else {
        format!("{:.1}", d.as_secs_f64())
    }
}

/// `Ok(stdout)` (trimmed) on exit 0, else the first stderr line (or the exit
/// code when stderr is empty, or the spawn/timeout error).
pub fn run_capture_cmd(cmd: Command, stdin: Option<&[u8]>, timeout: Duration) -> Result<String, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let c = capture(cmd, stdin, timeout)?;
    if c.success {
        return Ok(c.stdout.trim().to_string());
    }
    let first = c.stderr.trim().lines().next().unwrap_or("").to_string();
    if first.is_empty() {
        Err(format!("{program}: exit {}", c.code.map_or_else(|| "signal".to_string(), |code| code.to_string())))
    } else {
        Err(first)
    }
}

/// The command a probe runs: `program args…` with `CLAUDE_CODE_OAUTH_TOKEN`
/// removed from the child's environment (probed tools have no business
/// seeing it).
fn probe_cmd(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args).env_remove("CLAUDE_CODE_OAUTH_TOKEN");
    cmd
}

/// Probe `program args…` with no stdin and without the OAuth token.
pub fn run_capture(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    run_capture_cmd(probe_cmd(program, args), None, timeout)
}

// ---- version parsing -----------------------------------------------------------

fn is_semver(t: &str) -> bool {
    let (core, pre) = t.split_once('-').map_or((t, None), |(c, p)| (c, Some(p)));
    let parts: Vec<&str> = core.split('.').collect();
    let core_ok = parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    core_ok && pre.is_none_or(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
}

/// First `x.y.z[-pre]` token in a version banner.
#[must_use]
pub fn version_token(text: &str) -> Option<String> {
    text.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ',')
        .map(|t| t.trim_start_matches('v'))
        .find(|t| is_semver(t))
        .map(str::to_string)
}

fn semver(v: &str) -> Option<(u32, u32, u32)> {
    let core = v.split('-').next().unwrap_or(v);
    let mut it = core.split('.').map(|p| p.parse::<u32>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

/// Every executable `name` on `path_env`, in PATH order, without duplicates.
#[must_use]
pub fn all_in_path(name: &str, path_env: &str) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    std::env::split_paths(path_env)
        .map(|d| d.join(name))
        .filter(|p| exists_exec(p) == (true, true))
        .filter(|p| seen.insert(std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())))
        .collect()
}

// ---- pure row builders ---------------------------------------------------------

#[must_use]
pub fn row_toolchain(rustc_out: Option<&str>) -> DoctorLine {
    match rustc_out.and_then(version_token) {
        Some(v) if v == EXPECTED_TOOLCHAIN => DoctorLine::row(Tag::Ok, format!("toolchain rustc {v}")),
        Some(v) => DoctorLine::row(Tag::Warn, format!("toolchain rustc {v} (expected {EXPECTED_TOOLCHAIN})")),
        None => DoctorLine::row(Tag::Skip, format!("rustup toolchain {EXPECTED_TOOLCHAIN} not found (dev only)")),
    }
}

/// `cargo_lambda`: every `cargo-lambda` on PATH, in PATH order, with its
/// `lambda --version` output. The first one is what `cargo lambda` runs; a
/// good one behind a bad one is reported as shadowed.
#[must_use]
pub fn row_cross_tools(cargo_lambda: &[(PathBuf, Option<String>)], zig_out: Option<&str>) -> DoctorLine {
    let zig = zig_out.and_then(version_token).unwrap_or_else(|| "zig missing".to_string());
    let versions: Vec<(&Path, Option<String>)> = cargo_lambda.iter().map(|(p, out)| (p.as_path(), out.as_deref().and_then(version_token))).collect();
    let Some((first_path, first_ver)) = versions.first() else {
        return DoctorLine::row(Tag::Skip, format!("cargo-lambda not found (needed for make vm-build): {CARGO_LAMBDA_HINT}"));
    };
    let good = |v: &Option<String>| v.as_deref().and_then(semver).is_some_and(|t| t >= MIN_CARGO_LAMBDA);
    let min = format!("{}.{}.{}", MIN_CARGO_LAMBDA.0, MIN_CARGO_LAMBDA.1, MIN_CARGO_LAMBDA.2);
    if good(first_ver) {
        let v = first_ver.as_deref().unwrap_or("?");
        return DoctorLine::row(Tag::Ok, format!("cargo-lambda {v} ({}), zig {zig} (make vm-build)", first_path.display()));
    }
    let v = first_ver.clone().unwrap_or_else(|| "unknown".to_string());
    match versions.iter().skip(1).find(|(_, ver)| good(ver)) {
        Some((p2, Some(v2))) => DoctorLine::row(
            Tag::Warn,
            format!(
                "cargo-lambda {v} < {min} ({}) shadows {v2} ({}) on PATH — put {} first or brew uninstall cargo-lambda",
                first_path.display(),
                p2.display(),
                p2.parent().unwrap_or(Path::new("~/.cargo/bin")).display()
            ),
        ),
        _ => DoctorLine::row(Tag::Warn, format!("cargo-lambda {v} < {min} ({}) — arm64 link fails on rustc 1.9x; upgrade: {CARGO_LAMBDA_HINT}", first_path.display())),
    }
}

/// `(row, credentials_unavailable)`.
#[must_use]
pub fn row_aws_identity(sts: Option<Result<&str, &str>>) -> (DoctorLine, bool) {
    match sts {
        None => (DoctorLine::row(Tag::Skip, "aws cli not found (bridge commands need it)"), false),
        Some(Err(msg)) => {
            let lower = msg.to_ascii_lowercase();
            let creds = lower.contains("credential") || lower.contains("expiredtoken") || lower.contains("invalidclienttokenid") || lower.contains("token");
            if creds {
                (DoctorLine::row(Tag::No, format!("aws credentials unavailable: {msg}")), true)
            } else {
                (DoctorLine::row(Tag::No, format!("aws identity: {msg}")), false)
            }
        }
        Some(Ok(json)) => {
            let arn = serde_json::from_str::<serde_json::Value>(json)
                .ok()
                .and_then(|v| v.get("Arn").and_then(|a| a.as_str()).map(str::to_string))
                .unwrap_or_else(|| "unknown principal".to_string());
            (DoctorLine::row(Tag::Ok, format!("aws identity {arn}")), false)
        }
    }
}

/// The region is pinned in code; an `AWS_REGION`/profile value that differs
/// is reported, never honoured.
#[must_use]
pub fn row_region(env_warning: Option<&str>) -> DoctorLine {
    match env_warning {
        None => DoctorLine::row(Tag::Ok, format!("region {REGION} (pinned in code)")),
        Some(w) => DoctorLine::row(Tag::Warn, format!("region {REGION} (pinned in code)  <- {w}")),
    }
}

/// `None`: not attempted (no identity); `Some(Err)`: the call itself failed.
#[must_use]
pub fn row_iam_simulate(sim: Option<Result<&str, &str>>) -> DoctorLine {
    let json = match sim {
        None => return DoctorLine::row(Tag::Skip, "iam simulate not run (no aws identity)"),
        Some(Err(e)) => return DoctorLine::row(Tag::Warn, format!("iam simulate failed: {e}")),
        Some(Ok(json)) => json,
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return DoctorLine::row(Tag::Warn, "iam simulate: unparseable output");
    };
    let mut denied = Vec::new();
    let mut allowed = Vec::new();
    for r in v.get("EvaluationResults").and_then(|r| r.as_array()).into_iter().flatten() {
        let action = r.get("EvalActionName").and_then(|a| a.as_str()).unwrap_or("?").to_string();
        if r.get("EvalDecision").and_then(|d| d.as_str()) == Some("allowed") {
            allowed.push(action);
        } else {
            denied.push(action);
        }
    }
    if denied.is_empty() && !allowed.is_empty() {
        DoctorLine::row(Tag::Ok, format!("{} allowed (dedicated runtime principal possible)", allowed.join(", ")))
    } else if !denied.is_empty() {
        DoctorLine::row(Tag::Skip, format!("iam simulate: {} denied — named-profile fallback", denied.join(", ")))
    } else {
        DoctorLine::row(Tag::Skip, "iam simulate: no results")
    }
}

#[must_use]
pub fn row_bridge_config(paths: &Paths, loaded: &Result<Option<BridgeConfig>, BridgeError>) -> DoctorLine {
    match loaded {
        Ok(Some(_)) => DoctorLine::row(Tag::Ok, format!("bridge.toml {}", paths.config.display())),
        Ok(None) => DoctorLine::row(
            Tag::Skip,
            format!("bridge.toml not found at {} (bridge not configured; classic commands unaffected)", paths.config.display()),
        ),
        Err(e) => DoctorLine::row(Tag::No, format!("bridge.toml: {e}")),
    }
}

#[must_use]
pub fn row_keystore_key(exists: bool, key: &str) -> DoctorLine {
    if exists {
        DoctorLine::row(Tag::Ok, format!("keystore key {key}"))
    } else {
        DoctorLine::row(Tag::Skip, format!("keystore key {key} absent  <- ai-env keygen {key}"))
    }
}

/// Highest `anthropic.claude-code-<semver>-darwin-arm64` directory name.
#[must_use]
pub fn pick_bundle(dirs: &[String]) -> Option<(String, String)> {
    dirs.iter()
        .filter_map(|d| {
            let rest = d.strip_prefix("anthropic.claude-code-")?;
            let ver = rest.strip_suffix("-darwin-arm64")?;
            semver(ver).map(|t| (t, ver.to_string(), d.clone()))
        })
        .max_by_key(|(t, _, _)| *t)
        .map(|(_, ver, dir)| (ver, dir))
}

#[must_use]
pub fn row_cursor_bundle(dirs: &[String], bundled_version: Option<&str>) -> DoctorLine {
    match pick_bundle(dirs) {
        Some((ver, _)) => {
            let n = dirs.iter().filter(|d| d.starts_with("anthropic.claude-code-")).count();
            let bundled = bundled_version.and_then(version_token).unwrap_or_else(|| "unknown".to_string());
            let mut text = format!("cursor extension {ver}, bundled claude {bundled}");
            if n > 1 {
                text.push_str(&format!(" ({n} versions installed)"));
            }
            DoctorLine::row(Tag::Ok, text)
        }
        None => DoctorLine::row(Tag::Skip, "Cursor Claude extension not found under ~/.cursor/extensions"),
    }
}

#[must_use]
pub fn row_path_claude(path_claude: Option<(&Path, &str)>, bundled_version: Option<&str>) -> DoctorLine {
    let bundled = bundled_version.and_then(version_token);
    match path_claude {
        None => DoctorLine::row(Tag::Skip, "no claude on PATH (the wrapper uses the bundled binary)"),
        Some((p, out)) => {
            let v = version_token(out).unwrap_or_else(|| "unknown".to_string());
            match &bundled {
                Some(b) if *b != v => DoctorLine::row(Tag::Warn, format!("claude on PATH {v} ({}) ≠ bundled {b}", p.display())),
                _ => DoctorLine::row(Tag::Ok, format!("claude on PATH {v} ({})", p.display())),
            }
        }
    }
}

#[must_use]
pub fn row_sibling(s: &Sibling) -> DoctorLine {
    match s {
        Sibling::Next(p) => DoctorLine::row(Tag::Ok, format!("ai-env-claude next to ai-env ({})", p.display())),
        Sibling::PathOnly(p) => DoctorLine::row(Tag::Ok, format!("ai-env-claude on PATH only ({})  <- note: the sibling next to ai-env is preferred", p.display())),
        Sibling::Missing => DoctorLine::row(Tag::No, format!("ai-env-claude missing  <- {INSTALL_HINT}")),
    }
}

#[must_use]
pub fn row_same_version(sibling_version_out: Option<&str>, mine: &str) -> DoctorLine {
    match sibling_version_out.and_then(version_token) {
        Some(v) if v == mine => DoctorLine::row(Tag::Ok, format!("same version {mine}")),
        Some(v) => DoctorLine::row(Tag::No, format!("version skew: ai-env {mine}, ai-env-claude {v}  <- {INSTALL_HINT}")),
        None => DoctorLine::row(Tag::Skip, "ai-env-claude --version not available"),
    }
}

/// Rows for Cursor's wrapper setting; `exists_exec(path) -> (exists, executable)`.
#[must_use]
pub fn row_wrapper_setting(settings: Option<&serde_json::Value>, exists_exec: &dyn Fn(&Path) -> (bool, bool), sibling: &Sibling) -> Vec<DoctorLine> {
    let mut rows = Vec::new();
    let wrapper = settings.and_then(|s| s.get(WRAPPER_SETTING)).and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    match wrapper {
        None => rows.push(DoctorLine::row(Tag::Skip, format!("{WRAPPER_SETTING} not set (ai-env wrapper install, S1)"))),
        Some(p) => {
            let path = Path::new(p);
            let (exists, exec) = exists_exec(path);
            if !exists {
                rows.push(DoctorLine::row(Tag::No, format!("{WRAPPER_SETTING} = {p} does not exist")));
            } else if !exec {
                rows.push(DoctorLine::row(Tag::No, format!("{WRAPPER_SETTING} = {p} is not executable")));
            } else {
                rows.push(DoctorLine::row(Tag::Ok, format!("{WRAPPER_SETTING} = {p}")));
            }
            if NODE_SUFFIXES.iter().any(|s| p.ends_with(s)) {
                rows.push(DoctorLine::row(Tag::Warn, "wrapper path ends in a JS/TS suffix: Cursor would run it under node (extensionless bin required)"));
            }
            if let Sibling::Next(sib) | Sibling::PathOnly(sib) = sibling {
                if sib != path {
                    rows.push(DoctorLine::row(Tag::Warn, format!("wrapper points elsewhere than the sibling ({})", sib.display())));
                }
            }
        }
    }
    if settings.and_then(|s| s.get(PERMISSION_SETTING)).and_then(|v| v.as_str()).is_none() {
        rows.push(DoctorLine::row(Tag::Skip, format!("{PERMISSION_SETTING} unset (sessions start in Manual mode)")));
    }
    rows
}

/// Row for a `settings.json` that could not be parsed at all.
#[must_use]
pub fn row_settings_unparseable(path: &Path, err: &str) -> DoctorLine {
    DoctorLine::row(Tag::Warn, format!("Cursor settings.json unparseable ({err}); wrapper rows not checked  <- {}", path.display()))
}

// ---- JSONC ------------------------------------------------------------------------

/// Strip `//` and `/* */` comments outside strings.
fn strip_comments(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut in_str) = (0, false);
    while i < c.len() {
        let ch = c[i];
        if in_str {
            out.push(ch);
            if ch == '\\' && i + 1 < c.len() {
                out.push(c[i + 1]);
                i += 2;
                continue;
            }
            if ch == '"' {
                in_str = false;
            }
            i += 1;
        } else if ch == '"' {
            in_str = true;
            out.push(ch);
            i += 1;
        } else if ch == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if ch == '/' && c.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else {
            out.push(ch);
            i += 1;
        }
    }
    out
}

/// Drop a `,` whose next significant character is `}` or `]` (outside strings).
fn strip_trailing_commas(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut in_str) = (0, false);
    while i < c.len() {
        let ch = c[i];
        if in_str {
            out.push(ch);
            if ch == '\\' && i + 1 < c.len() {
                out.push(c[i + 1]);
                i += 2;
                continue;
            }
            if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
            out.push(ch);
        } else if ch == ',' {
            let mut j = i + 1;
            while j < c.len() && c[j].is_whitespace() {
                j += 1;
            }
            if !matches!(c.get(j), Some('}') | Some(']')) {
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
        i += 1;
    }
    out
}

/// Cursor writes JSON with comments (line and block) and trailing commas.
#[must_use]
pub fn strip_jsonc(text: &str) -> String {
    strip_trailing_commas(&strip_comments(text))
}

/// Parse a JSONC settings file.
pub fn parse_settings(text: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(&strip_jsonc(text)).map_err(|e| e.to_string())
}

// ---- collection ------------------------------------------------------------------

pub struct BridgeDoctor {
    pub lines: Vec<DoctorLine>,
    pub auth_unavailable: bool,
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(unix)]
fn access_x(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path; access(2) only reads it.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

#[cfg(not(unix))]
fn access_x(_: &Path) -> bool {
    true
}

/// `(exists, executable)` — a regular file this user may execute (access(2),
/// not mode bits: ACLs and ownership count).
fn exists_exec(p: &Path) -> (bool, bool) {
    let Ok(meta) = std::fs::metadata(p) else {
        return (false, false);
    };
    (true, meta.is_file() && access_x(p))
}

/// Collect the inputs and build every bridge row.
#[must_use]
pub fn rows(store: &Keystore) -> BridgeDoctor {
    let t = Duration::from_secs(5);
    let mut lines = Vec::new();

    lines.push(row_toolchain(run_capture("rustup", &["run", EXPECTED_TOOLCHAIN, "rustc", "--version"], t).ok().as_deref()));
    let cargo_lambda: Vec<(PathBuf, Option<String>)> = all_in_path("cargo-lambda", &effective_path())
        .into_iter()
        .map(|p| {
            let out = run_capture(&p.to_string_lossy(), &["lambda", "--version"], t).ok();
            (p, out)
        })
        .collect();
    lines.push(row_cross_tools(&cargo_lambda, run_capture("zig", &["version"], t).ok().as_deref()));

    let aws_present = find_in_path("aws", &effective_path()).is_some();
    let sts = if aws_present {
        Some(run_capture("aws", &["sts", "get-caller-identity", "--region", REGION, "--output", "json"], Duration::from_secs(15)))
    } else {
        None
    };
    let (row, auth_unavailable) = row_aws_identity(sts.as_ref().map(|r| r.as_deref().map_err(String::as_str)));
    lines.push(row);
    lines.push(row_region(env_region_warning().as_deref()));
    let arn = sts.as_ref().and_then(|r| r.as_ref().ok()).and_then(|json| {
        serde_json::from_str::<serde_json::Value>(json).ok().and_then(|v| v.get("Arn").and_then(|a| a.as_str()).map(str::to_string))
    });
    let sim = arn.map(|arn| {
        run_capture(
            "aws",
            &["iam", "simulate-principal-policy", "--policy-source-arn", &arn, "--action-names", "iam:CreateUser", "iam:CreateAccessKey", "--output", "json"],
            Duration::from_secs(15),
        )
    });
    lines.push(row_iam_simulate(sim.as_ref().map(|r| r.as_deref().map_err(String::as_str))));

    match Paths::resolve() {
        Ok(paths) => {
            let loaded = BridgeConfig::load(&paths);
            lines.push(row_bridge_config(&paths, &loaded));
        }
        Err(e) => lines.push(DoctorLine::row(Tag::No, format!("bridge paths: {e}"))),
    }
    lines.push(row_keystore_key(store.key_exists("ai-env-bridge"), "ai-env-bridge"));

    let ext_dir = home().join(".cursor").join("extensions");
    let dirs: Vec<String> = std::fs::read_dir(&ext_dir)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    let bundled_out = pick_bundle(&dirs).and_then(|(_, dir)| {
        let bin = ext_dir.join(dir).join("resources").join("native-binary").join("claude");
        run_capture(&bin.to_string_lossy(), &["--version"], t).ok()
    });
    lines.push(row_cursor_bundle(&dirs, bundled_out.as_deref()));
    let path_claude = find_in_path("claude", &effective_path());
    let path_out = path_claude.as_ref().and_then(|p| run_capture(&p.to_string_lossy(), &["--version"], t).ok());
    lines.push(row_path_claude(path_claude.as_deref().zip(path_out.as_deref()), bundled_out.as_deref()));

    let sibling = find_sibling("ai-env-claude");
    lines.push(row_sibling(&sibling));
    let sib_out = match &sibling {
        Sibling::Next(p) | Sibling::PathOnly(p) => run_capture(&p.to_string_lossy(), &["--version"], t).ok(),
        Sibling::Missing => None,
    };
    lines.push(row_same_version(sib_out.as_deref(), env!("CARGO_PKG_VERSION")));

    let settings_path = home().join("Library").join("Application Support").join("Cursor").join("User").join("settings.json");
    match std::fs::read_to_string(&settings_path).ok().map(|t| parse_settings(&t)) {
        Some(Err(e)) => lines.push(row_settings_unparseable(&settings_path, &e)),
        other => lines.extend(row_wrapper_setting(other.and_then(Result::ok).as_ref(), &exists_exec, &sibling)),
    }

    BridgeDoctor { lines, auth_unavailable }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(l: &DoctorLine) -> (Tag, String) {
        match l {
            DoctorLine::Row { tag, text } => (*tag, text.clone()),
            DoctorLine::Plain(t) => (Tag::Skip, t.clone()),
        }
    }

    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(script);
        c
    }

    #[test]
    fn version_tokens() {
        assert_eq!(version_token("cargo-lambda 1.9.2 (2026-09-19Z)"), Some("1.9.2".into()));
        assert_eq!(version_token("rustc 1.98.1 (48a229cea 2026-09-01)"), Some("1.98.1".into()));
        assert_eq!(version_token("2.1.278 (Claude Code)"), Some("2.1.278".into()));
        assert_eq!(version_token("0.16.0"), Some("0.16.0".into()));
        assert_eq!(version_token("ai-env-claude 0.2.0-rc.1"), Some("0.2.0-rc.1".into()), "pre-release kept whole");
        assert_eq!(version_token("nope"), None);
        assert_eq!(semver("0.2.0-rc.1"), Some((0, 2, 0)));
    }

    #[cfg(unix)]
    #[test]
    fn capture_drains_a_full_stderr_pipe_and_a_full_stdout_pipe() {
        // 300 000 bytes on each pipe: far beyond the 64 KiB kernel buffer.
        let c = capture(sh("head -c 300000 /dev/zero | tr '\\0' e >&2; head -c 300000 /dev/zero | tr '\\0' o; exit 0"), None, Duration::from_secs(10)).unwrap();
        assert!(c.success);
        assert_eq!(c.stdout.len(), 300_000);
        assert_eq!(c.stderr.len(), 300_000);
        // The simplified helper reports success on stdout only.
        let out = run_capture_cmd(sh("head -c 300000 /dev/zero | tr '\\0' e >&2; echo done"), None, Duration::from_secs(10)).unwrap();
        assert_eq!(out, "done");
    }

    #[cfg(unix)]
    #[test]
    fn capture_times_out_and_kills() {
        let start = Instant::now();
        let err = capture(sh("sleep 5"), None, Duration::from_millis(200)).unwrap_err();
        assert!(err.contains("timed out after 0.2s"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(2), "killed promptly: {:?}", start.elapsed());
    }

    #[cfg(unix)]
    #[test]
    fn capture_feeds_stdin_and_reports_failures() {
        let mut cat = Command::new("cat");
        cat.arg("-");
        assert_eq!(run_capture_cmd(cat, Some(b"hi there"), Duration::from_secs(5)).unwrap(), "hi there");
        let err = run_capture_cmd(sh("echo first >&2; echo second >&2; exit 3"), None, Duration::from_secs(5)).unwrap_err();
        assert_eq!(err, "first");
        let err = run_capture_cmd(sh("exit 4"), None, Duration::from_secs(5)).unwrap_err();
        assert_eq!(err, "/bin/sh: exit 4");
        assert!(run_capture("/nonexistent/program-xyz", &[], Duration::from_secs(1)).unwrap_err().starts_with("/nonexistent/program-xyz: "));
    }

    #[cfg(unix)]
    #[test]
    fn capture_keeps_the_callers_env_and_env_remove_after_env_wins() {
        // Set on the command, not the process, so the test never touches the process env.
        let mut c = sh("printf %s \"${CLAUDE_CODE_OAUTH_TOKEN-unset}\"");
        c.env("CLAUDE_CODE_OAUTH_TOKEN", "fake-token-for-tests");
        assert_eq!(run_capture_cmd(c, None, Duration::from_secs(5)).unwrap(), "fake-token-for-tests", "capture leaves env alone");
        let mut c = Command::new("/bin/sh");
        c.env("CLAUDE_CODE_OAUTH_TOKEN", "fake-token-for-tests").env_remove("CLAUDE_CODE_OAUTH_TOKEN");
        c.arg("-c").arg("printf %s \"${CLAUDE_CODE_OAUTH_TOKEN-unset}\"");
        assert_eq!(run_capture_cmd(c, None, Duration::from_secs(5)).unwrap(), "unset", "env_remove after env wins (what probe_cmd relies on)");
    }

    #[test]
    fn run_capture_probes_never_inherit_the_oauth_token() {
        let cmd = probe_cmd("/bin/sh", &["-c", "true"]);
        assert!(cmd.get_envs().any(|(k, v)| k == "CLAUDE_CODE_OAUTH_TOKEN" && v.is_none()), "the removal is recorded on the command");
        assert_eq!(cmd.get_program(), "/bin/sh");
        assert_eq!(cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>(), vec!["-c", "true"]);
    }

    #[cfg(unix)]
    #[test]
    fn capture_bounds_the_wait_for_pipes_held_by_a_grandchild() {
        // The shell exits at once; the backgrounded sleep keeps both pipes open.
        let start = Instant::now();
        let err = capture(sh("sleep 3 & echo hi"), None, Duration::from_millis(200)).unwrap_err();
        assert!(err.contains("output pipes stayed open"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(2), "bounded: {:?}", start.elapsed());
    }

    #[test]
    fn toolchain_and_cross_tools() {
        assert_eq!(text(&row_toolchain(Some("rustc 1.98.1 (x)"))).0, Tag::Ok);
        assert_eq!(text(&row_toolchain(Some("rustc 1.90.0 (x)"))).0, Tag::Warn);
        assert_eq!(text(&row_toolchain(None)).0, Tag::Skip);
        let good = (PathBuf::from("/Users/mike/.cargo/bin/cargo-lambda"), Some("cargo-lambda 1.9.2 (d)".to_string()));
        let brew = (PathBuf::from("/opt/homebrew/bin/cargo-lambda"), Some("cargo-lambda 1.9.1 (d)".to_string()));
        let (tag, t) = text(&row_cross_tools(std::slice::from_ref(&good), Some("0.16.0")));
        assert_eq!(tag, Tag::Ok);
        assert!(t.contains("cargo-lambda 1.9.2 (/Users/mike/.cargo/bin/cargo-lambda), zig 0.16.0"), "{t}");
        let (tag, t) = text(&row_cross_tools(std::slice::from_ref(&brew), Some("0.16.0")));
        assert_eq!(tag, Tag::Warn);
        assert!(t.contains("1.9.1 < 1.9.2") && t.contains("upgrade:"), "{t}");
        let (tag, t) = text(&row_cross_tools(&[brew.clone(), good.clone()], None));
        assert_eq!(tag, Tag::Warn);
        assert!(t.contains("shadows 1.9.2 (/Users/mike/.cargo/bin/cargo-lambda)") && t.contains("put /Users/mike/.cargo/bin first"), "{t}");
        let (tag, _) = text(&row_cross_tools(&[good, brew], None));
        assert_eq!(tag, Tag::Ok, "the good one first on PATH is what runs");
        let (tag, t) = text(&row_cross_tools(&[], None));
        assert_eq!(tag, Tag::Skip);
        assert!(t.contains(CARGO_LAMBDA_HINT), "{t}");
    }

    #[test]
    fn aws_identity_and_region_rows() {
        let (r, u) = row_aws_identity(None);
        assert_eq!((text(&r).0, u), (Tag::Skip, false));
        let (r, u) = row_aws_identity(Some(Err("Unable to locate credentials. You can configure credentials by running \"aws configure\".")));
        assert_eq!((text(&r).0, u), (Tag::No, true));
        let (r, u) = row_aws_identity(Some(Ok("{\"Arn\":\"arn:aws:iam::123456789012:user/example\"}")));
        let (tag, t) = text(&r);
        assert_eq!((tag, u), (Tag::Ok, false));
        assert!(t.contains("user/example"), "{t}");
        let (tag, t) = text(&row_region(None));
        assert_eq!(tag, Tag::Ok);
        assert!(t.contains("eu-central-1 (pinned in code)"), "{t}");
        let (tag, t) = text(&row_region(Some("env AWS_REGION=eu-west-3 ignored (region pinned to eu-central-1)")));
        assert_eq!(tag, Tag::Warn);
        assert!(t.contains("eu-west-3 ignored"), "{t}");
    }

    #[test]
    fn iam_rows() {
        let allowed = "{\"EvaluationResults\":[{\"EvalActionName\":\"iam:CreateUser\",\"EvalDecision\":\"allowed\"},{\"EvalActionName\":\"iam:CreateAccessKey\",\"EvalDecision\":\"allowed\"}]}";
        assert_eq!(text(&row_iam_simulate(Some(Ok(allowed)))).0, Tag::Ok);
        let denied = "{\"EvaluationResults\":[{\"EvalActionName\":\"iam:CreateUser\",\"EvalDecision\":\"implicitDeny\"}]}";
        let (tag, t) = text(&row_iam_simulate(Some(Ok(denied))));
        assert_eq!(tag, Tag::Skip);
        assert!(t.contains("named-profile fallback"), "{t}");
        assert_eq!(text(&row_iam_simulate(None)).0, Tag::Skip);
        let (tag, t) = text(&row_iam_simulate(Some(Err("An error occurred (AccessDenied) when calling the SimulatePrincipalPolicy operation"))));
        assert_eq!(tag, Tag::Warn);
        assert!(t.starts_with("iam simulate failed: An error occurred (AccessDenied)"), "{t}");
        assert_eq!(text(&row_iam_simulate(Some(Ok("not json")))).0, Tag::Warn);
    }

    #[test]
    fn config_and_key_rows() {
        let p = Paths::from_root_and_env(PathBuf::from("/r"), None);
        assert_eq!(text(&row_bridge_config(&p, &Ok(None))).0, Tag::Skip);
        assert_eq!(text(&row_bridge_config(&p, &Ok(Some(BridgeConfig::default())))).0, Tag::Ok);
        assert_eq!(text(&row_bridge_config(&p, &Err(BridgeError::Config("bad".into())))).0, Tag::No);
        assert_eq!(text(&row_keystore_key(false, "ai-env-bridge")).0, Tag::Skip);
        assert_eq!(text(&row_keystore_key(true, "ai-env-bridge")).0, Tag::Ok);
    }

    #[test]
    fn cursor_rows() {
        let dirs: Vec<String> = ["anthropic.claude-code-2.1.274-darwin-arm64", "anthropic.claude-code-2.1.278-darwin-arm64", "anthropic.claude-code-2.1.276-darwin-arm64", "other.ext-1.0.0"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(pick_bundle(&dirs).unwrap().0, "2.1.278");
        let (tag, t) = text(&row_cursor_bundle(&dirs, Some("2.1.278 (Claude Code)")));
        assert_eq!(tag, Tag::Ok);
        assert!(t.contains("cursor extension 2.1.278, bundled claude 2.1.278 (3 versions installed)"), "{t}");
        assert_eq!(text(&row_cursor_bundle(&[], None)).0, Tag::Skip);
        let (tag, t) = text(&row_path_claude(Some((Path::new("/opt/homebrew/bin/claude"), "2.1.267 (Claude Code)")), Some("2.1.278 (Claude Code)")));
        assert_eq!(tag, Tag::Warn);
        assert!(t.contains("2.1.267") && t.contains("≠ bundled 2.1.278"), "{t}");
        assert_eq!(text(&row_path_claude(Some((Path::new("/x"), "2.1.278 (Claude Code)")), Some("2.1.278 (Claude Code)"))).0, Tag::Ok);
        assert_eq!(text(&row_path_claude(None, None)).0, Tag::Skip);
    }

    #[test]
    fn sibling_and_version_rows() {
        assert_eq!(text(&row_sibling(&Sibling::Next(PathBuf::from("/b/ai-env-claude")))).0, Tag::Ok);
        assert_eq!(text(&row_sibling(&Sibling::PathOnly(PathBuf::from("/p/ai-env-claude")))).0, Tag::Ok);
        let (tag, t) = text(&row_sibling(&Sibling::Missing));
        assert_eq!(tag, Tag::No);
        assert!(t.contains(INSTALL_HINT));
        assert_eq!(text(&row_same_version(Some("ai-env-claude 0.1.0"), "0.1.0")).0, Tag::Ok);
        assert_eq!(text(&row_same_version(Some("ai-env-claude 0.0.9"), "0.1.0")).0, Tag::No);
        assert_eq!(text(&row_same_version(Some("ai-env-claude 0.2.0-rc.1"), "0.2.0-rc.1")).0, Tag::Ok, "pre-release parity");
        assert_eq!(text(&row_same_version(Some("ai-env-claude 0.2.0-rc.1"), "0.2.0")).0, Tag::No);
        assert_eq!(text(&row_same_version(None, "0.1.0")).0, Tag::Skip);
    }

    #[test]
    fn jsonc_is_stripped_outside_strings() {
        let src = "{\n  // line comment\n  \"url\": \"http://x/y\", /* block */\n  \"a\": [1, 2, ], // trailing\n  \"b\": \"a//b /* c */\",\n  \"c\": \"esc\\\"aped\", \n}\n";
        let v = parse_settings(src).unwrap();
        assert_eq!(v["url"], "http://x/y");
        assert_eq!(v["a"], serde_json::json!([1, 2]));
        assert_eq!(v["b"], "a//b /* c */");
        assert_eq!(v["c"], "esc\"aped");
        assert_eq!(strip_jsonc("[1,/* x */]"), "[1]");
        assert!(parse_settings("{\"a\": }").is_err());
        assert!(parse_settings("").is_err());
    }

    #[test]
    fn wrapper_setting_rows() {
        let sib = Sibling::Next(PathBuf::from("/Users/mike/.cargo/bin/ai-env-claude"));
        let none = row_wrapper_setting(None, &|_| (false, false), &sib);
        assert_eq!(text(&none[0]).0, Tag::Skip);
        assert!(text(&none[1]).1.contains(PERMISSION_SETTING));

        let ok = parse_settings("{\n  // comment\n  \"claudeCode.claudeProcessWrapper\": \"/Users/mike/.cargo/bin/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"default\",\n}").unwrap();
        let rows = row_wrapper_setting(Some(&ok), &|_| (true, true), &sib);
        assert_eq!(rows.len(), 1);
        assert_eq!(text(&rows[0]).0, Tag::Ok);

        let js = parse_settings("{\"claudeCode.claudeProcessWrapper\": \"/x/wrapper.js\"}").unwrap();
        let rows = row_wrapper_setting(Some(&js), &|_| (true, true), &sib);
        assert!(rows.iter().any(|r| text(r).0 == Tag::Warn && text(r).1.contains("under node")));
        assert!(rows.iter().any(|r| text(r).0 == Tag::Warn && text(r).1.contains("points elsewhere")));

        let missing = parse_settings("{\"claudeCode.claudeProcessWrapper\": \"/gone\"}").unwrap();
        let rows = row_wrapper_setting(Some(&missing), &|_| (false, false), &sib);
        assert_eq!(text(&rows[0]).0, Tag::No);
        let noexec = row_wrapper_setting(Some(&missing), &|_| (true, false), &sib);
        assert!(text(&noexec[0]).1.contains("not executable"));

        let (tag, t) = text(&row_settings_unparseable(Path::new("/s.json"), "expected value at line 1 column 2"));
        assert_eq!(tag, Tag::Warn);
        assert!(t.contains("wrapper rows not checked") && t.ends_with("/s.json"), "{t}");
    }

    #[cfg(unix)]
    #[test]
    fn exists_exec_uses_access_and_all_in_path_walks_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        use std::os::unix::fs::PermissionsExt;
        for d in [&a, &b] {
            let f = d.join("tool");
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "x").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(exists_exec(&plain), (true, false));
        assert_eq!(exists_exec(&a.join("tool")), (true, true));
        assert_eq!(exists_exec(&a), (true, false), "a directory is not executable as a program");
        assert_eq!(exists_exec(&dir.path().join("nope")), (false, false));
        let path = std::env::join_paths([&b, &a, &b]).unwrap();
        assert_eq!(all_in_path("tool", &path.to_string_lossy()), vec![b.join("tool"), a.join("tool")]);
    }
}
