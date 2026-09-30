//! Bridge rows appended to `ai-env doctor`. Every row builder is a pure
//! function of already-collected inputs so it is unit-testable without the
//! subprocesses that `rows` runs (5 s timeout each).
use crate::age_cmd::{effective_path, find_in_path};
use crate::bridge::census::read_rows;
use crate::bridge::config::{env_region_warning, AwsCfg, BridgeConfig, Paths, VmCfg, REGION};
use crate::bridge::creds::{aws_env_state, AwsEnvState};
use crate::bridge::errors::BridgeError;
use crate::bridge::infra::{base_image_verdict, read_infra_state, InfraState};
use crate::bridge::sibling::{exists_exec, find_sibling, Sibling, INSTALL_HINT};
use crate::bridge::vm::registry::{list_rows, RowStatus, VmRow, PENDING_STALE_S};
use crate::commands::{DoctorLine, Tag};
use crate::store::Keystore;
use crate::wire::argv::FIXTURE_EXT_VERSION;
use crate::wire::time::{parse_rfc3339_utc, unix_now};
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

/// `cargo_lambda`: every `cargo-lambda` on PATH, in PATH order, then
/// `~/.cargo/bin`'s when it is not on PATH, each with its `lambda --version`
/// output. `make vm-build` uses the first that meets the floor (as the
/// Makefile's `CARGO_LAMBDA` selection does), so a good one behind an old
/// Homebrew one is `[ok ]` with a note that plain `cargo lambda` still runs
/// the old one.
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
            Tag::Ok,
            format!(
                "cargo-lambda {v2} ({}), zig {zig} (make vm-build uses it; plain `cargo lambda` still runs {v} from {} — brew uninstall cargo-lambda, or put {} first)",
                p2.display(),
                first_path.display(),
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
        .filter_map(|d| bundle_version(d).and_then(|ver| semver(&ver).map(|t| (t, ver, d.clone()))))
        .max_by_key(|(t, _, _)| *t)
        .map(|(_, ver, dir)| (ver, dir))
}

/// The version inside a bundle directory name
/// (`anthropic.claude-code-2.1.278-darwin-arm64` → `2.1.278`); also used by
/// the census to tag rows from the real binary's path.
#[must_use]
pub fn bundle_version(dir_name: &str) -> Option<String> {
    let rest = dir_name.strip_prefix("anthropic.claude-code-")?;
    let ver = rest.strip_suffix("-darwin-arm64")?;
    semver(ver).map(|_| ver.to_string())
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

/// `Some(Warn)` when the installed bundle (the directory version that
/// `row_cursor_bundle` reports) differs from the version the argv fixtures
/// were captured from; `None` when they agree or no bundle is installed.
#[must_use]
pub fn row_fixture_drift(bundle_version: Option<&str>) -> Option<DoctorLine> {
    match bundle_version {
        Some(v) if v != FIXTURE_EXT_VERSION => Some(DoctorLine::row(
            Tag::Warn,
            format!("cursor extension {v} ≠ fixtures tagged {FIXTURE_EXT_VERSION}  <- re-capture tests/fixtures/argv from `ai-env wrapper census`"),
        )),
        _ => None,
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
/// A wrapper under a `target/` component is a debug build that `cargo clean`
/// removes (T1.4 installs one on purpose), so it is warned about, not refused.
#[must_use]
pub fn row_wrapper_setting(settings: Option<&serde_json::Value>, exists_exec: &dyn Fn(&Path) -> (bool, bool), sibling: &Sibling) -> Vec<DoctorLine> {
    let mut rows = Vec::new();
    let wrapper = settings.and_then(|s| s.get(WRAPPER_SETTING)).and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    match wrapper {
        None => rows.push(DoctorLine::row(Tag::Skip, format!("{WRAPPER_SETTING} not set  <- ai-env wrapper install --write"))),
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
            if path.components().any(|c| c.as_os_str() == "target") {
                rows.push(DoctorLine::row(Tag::Warn, format!("wrapper under a build directory ({p}): cargo clean breaks Cursor  <- ai-env wrapper install --write from the installed ai-env")));
            }
            if let Sibling::Next(sib) | Sibling::PathOnly(sib) = sibling {
                if sib != path {
                    rows.push(DoctorLine::row(Tag::Warn, format!("wrapper points elsewhere than the sibling ({})", sib.display())));
                }
            }
        }
    }
    match settings.and_then(|s| s.get(PERMISSION_SETTING)).and_then(|v| v.as_str()) {
        Some(mode) => rows.push(DoctorLine::row(Tag::Ok, format!("{PERMISSION_SETTING} = {mode}"))),
        None => rows.push(DoctorLine::row(Tag::Skip, format!("{PERMISSION_SETTING} unset (sessions start in Manual mode)  <- ai-env wrapper install --write"))),
    }
    rows
}

/// The census row: `rows` as `census::read_rows` returns them (oldest first),
/// `path` for the hint when there are none. The last row's `ts`, `route` and
/// `reason` are shown as recorded (`?` when a field is missing).
#[must_use]
pub fn row_census(rows: &[serde_json::Value], path: &Path) -> DoctorLine {
    let Some(last) = rows.last() else {
        return DoctorLine::row(Tag::Skip, format!("no census yet ({})  <- run one Cursor session with the wrapper installed", path.display()));
    };
    let field = |k: &str| last.get(k).and_then(|v| v.as_str()).unwrap_or("?").to_string();
    DoctorLine::row(Tag::Ok, format!("census: {} rows, last {} route={} reason={}", rows.len(), field("ts"), field("route"), field("reason")))
}

// ---- S3 rows ------------------------------------------------------------------------

/// The managed base image the Pulumi program pins (infra/image-config.json;
/// a unit test keeps the two equal).
pub const BASE_IMAGE_NAME: &str = "al2023-1";
pub const BASE_IMAGE_VERSION: &str = "1";

/// `credentials/aws.env`: the sealed runtime access key (`make runtime-key`),
/// classified by [`aws_env_state`], the check `creds aws-set` makes before
/// it seals: anything there that is not a regular ai-env container (a
/// plaintext key after `ai-env decrypt --force`, a symlink) is `[NO ]`.
#[must_use]
pub fn row_runtime_credentials(state: &AwsEnvState, path: &Path) -> DoctorLine {
    match state {
        AwsEnvState::Sealed => DoctorLine::row(Tag::Ok, format!("runtime credentials sealed ({})", path.display())),
        AwsEnvState::Absent => DoctorLine::row(Tag::Skip, format!("runtime credentials absent ({})  <- make runtime-key (after make deploy)", path.display())),
        AwsEnvState::NotSealed(why) => DoctorLine::row(
            Tag::No,
            format!("runtime credentials NOT sealed: {} {why}  <- move it away, then make runtime-key ROTATE=1 (seals a new key and deletes the exposed one; plain make runtime-key when ai-env-runtime has no key left)", path.display()),
        ),
    }
}

/// The runtime credentials row for the file at `path`, as `rows` builds it.
#[must_use]
pub fn runtime_credentials(path: &Path) -> DoctorLine {
    row_runtime_credentials(&aws_env_state(path), path)
}

/// `state/infra.toml`: what the last `ai-env infra status --write` learned,
/// with where the image state came from (a live `get-microvm-image`, or the
/// stack outputs of the last successful `pulumi up` when that read failed).
#[must_use]
pub fn row_infra_state(state: &Result<Option<InfraState>, BridgeError>, path: &Path) -> DoctorLine {
    match state {
        Ok(Some(s)) => {
            let image = s.image_name.as_deref().unwrap_or("image");
            let st = s.image_state.as_deref().unwrap_or("?");
            let active = s.latest_active_image_version.as_deref().unwrap_or("none");
            let mut text = format!("infra: {image} {st}, active version {active}, claude {}, stack {} (written {})", s.claude_version.as_deref().unwrap_or("?"), s.stack, s.written);
            let failed = s.latest_failed_image_version.as_deref();
            if let Some(f) = failed {
                text.push_str(&format!("; latest FAILED version {f}"));
            }
            text.push_str(&format!("; image state from {}", s.image_state_source.as_deref().unwrap_or("an unrecorded source  <- make infra-status WRITE=1")));
            // Only a live read vouches for the image: the stack outputs are as
            // old as the last `pulumi up` (rollbacks, a deleted image).
            let live = s.image_state_source.as_deref().is_some_and(|src| src.starts_with("live "));
            // Versions are `N.0` (the service) or `N` (older state): both sides must parse.
            let newer = |a: &str, f: &str| matches!((image_version_key(a), image_version_key(f)), (Some(a), Some(f)) if a > f);
            let ok = live && matches!(st, "CREATED" | "UPDATED") && failed.is_none_or(|f| s.latest_active_image_version.as_deref().is_some_and(|a| newer(a, f)));
            DoctorLine::row(if ok { Tag::Ok } else { Tag::Warn }, text)
        }
        Ok(None) => DoctorLine::row(Tag::Skip, format!("no infra state yet ({})  <- make deploy, then make infra-status WRITE=1", path.display())),
        Err(e) => DoctorLine::row(Tag::Warn, format!("infra state unreadable: {e}")),
    }
}

/// The deployed image's claude against the Cursor bundle: the pin follows the
/// bundle (plan D2). `None` when either side is unknown.
#[must_use]
pub fn row_image_claude(image_claude: Option<&str>, bundle: Option<&str>) -> Option<DoctorLine> {
    let (img, bun) = (image_claude?, bundle?);
    Some(if img == bun {
        DoctorLine::row(Tag::Ok, format!("image claude {img} = Cursor bundle"))
    } else {
        DoctorLine::row(Tag::Warn, format!("image claude {img} != Cursor bundle {bun}  <- make claude-pin CLAUDE_VERSION={bun} && make deploy (or install the wrapper to freeze the bundle)"))
    })
}

/// The two operator scan lists; absent files mean built-in defaults only.
#[must_use]
pub fn row_review_files(tripwires: &Path, tripwires_exist: bool, policy: &Path, policy_exists: bool) -> DoctorLine {
    let one = |p: &Path, e: bool| if e { format!("{} present", p.display()) } else { format!("{} absent", p.display()) };
    let text = format!("scan lists: {}; {}", one(tripwires, tripwires_exist), one(policy, policy_exists));
    if tripwires_exist || policy_exists {
        DoctorLine::row(Tag::Ok, text)
    } else {
        DoctorLine::row(Tag::Skip, format!("{text} (built-in tripwires only, empty settings allow list)"))
    }
}

/// The pinned managed base image version, from the
/// `list-managed-microvm-image-versions` call: `None` when it was not made
/// (no AWS identity, `[-  ]`); `Some(Err)` when the call itself failed (a
/// timeout, throttling, AccessDenied, an aws CLI without `lambda-microvms`),
/// which says nothing about the version (`[!! ] not checked`); otherwise
/// [`base_image_verdict`] on the listing: AVAILABLE, or `[NO ]` naming the
/// status, with one hint.
#[must_use]
pub fn row_base_image(listing: Option<Result<&str, &str>>) -> DoctorLine {
    let pinned = format!("base image {BASE_IMAGE_NAME} version {BASE_IMAGE_VERSION}");
    match listing {
        None => DoctorLine::row(Tag::Skip, format!("{pinned} not checked (no AWS identity)")),
        Some(Err(e)) => DoctorLine::row(Tag::Warn, format!("{pinned} not checked: {e}")),
        Some(Ok(json)) => match base_image_verdict(json, BASE_IMAGE_VERSION) {
            Ok(v) => DoctorLine::row(Tag::Ok, format!("{pinned}: {v}")),
            // The verdict names its own fix for a listed version that is not AVAILABLE.
            Err(e) if e.contains("<- ") => DoctorLine::row(Tag::No, format!("{pinned}: {e}")),
            Err(e) => DoctorLine::row(Tag::No, format!("{pinned}: {e}  <- pick an AVAILABLE version in infra/image-config.json")),
        },
    }
}

/// `arn:aws:iam::<account>:root`: the account root user, which
/// `simulate-principal-policy` refuses (`InvalidInput`).
#[must_use]
pub fn is_root_arn(arn: &str) -> bool {
    arn.strip_prefix("arn:aws:iam::").and_then(|r| r.split_once(':')).is_some_and(|(acct, rest)| acct.len() == 12 && acct.bytes().all(|c| c.is_ascii_digit()) && rest == "root")
}

/// `aws iam simulate-principal-policy` for `arn` (the doctor's IAM row):
/// the region is pinned like every aws call, although IAM is global.
fn iam_simulate_args(arn: &str) -> [&str; 11] {
    ["iam", "simulate-principal-policy", "--region", REGION, "--policy-source-arn", arn, "--action-names", "iam:CreateUser", "iam:CreateAccessKey", "--output", "json"]
}

// ---- S4 rows ------------------------------------------------------------------------

/// Service Quotas code of "Max allocated ARM_64 MicroVM memory" (Gigabytes,
/// per account and region; default 400).
pub const MICROVM_MEMORY_QUOTA_CODE: &str = "L-CD1C0CC4";

/// An image version as a comparable key: the service writes `N.0`, older
/// state and the stack outputs `N`, so `"1.0"` → `(1, 0)` and `"3"` →
/// `(3, 0)`. Digits only (no sign, no space, at most one dot); anything
/// else is `None`.
#[must_use]
pub fn image_version_key(v: &str) -> Option<(u64, u64)> {
    let num = |s: &str| if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) { s.parse::<u64>().ok() } else { None };
    match v.split_once('.') {
        None => Some((num(v)?, 0)),
        Some((major, minor)) => Some((num(major)?, num(minor)?)),
    }
}

/// `aws service-quotas get-service-quota` for the MicroVM memory quota
/// (the operator's identity; region pinned).
fn quota_args() -> [&'static str; 10] {
    ["service-quotas", "get-service-quota", "--service-code", "lambda", "--quota-code", MICROVM_MEMORY_QUOTA_CODE, "--region", REGION, "--output", "json"]
}

/// `mib` as gigabytes for a row (`6`, `1.5`).
fn gib(mib: u64) -> String {
    if mib.is_multiple_of(1024) {
        (mib / 1024).to_string()
    } else {
        format!("{:.1}", mib as f64 / 1024.0)
    }
}

/// The MicroVM memory quota against what `[vm]` may run at once
/// (`max_concurrent × memory_mib`). `q` is the output of [`quota_args`]:
/// `None` when not run (no aws identity, `[-  ]`); `Some(Err)` when the call
/// failed (`[!! ]` with the reason: no verdict); otherwise the quota's
/// `Quota.Value` in Gigabytes: `[ok ]` when `value × 1024 ≥ max_concurrent ×
/// memory_mib`, else `[!! ]` (the platform refuses the run that crosses it
/// with ServiceQuotaExceeded).
#[must_use]
pub fn row_microvm_quota(q: Option<Result<&str, &str>>, max_concurrent: u32, memory_mib: u32) -> DoctorLine {
    let name = format!("microvm memory quota {MICROVM_MEMORY_QUOTA_CODE}");
    let json = match q {
        None => return DoctorLine::row(Tag::Skip, format!("{name} not checked (no aws identity)")),
        Some(Err(e)) => return DoctorLine::row(Tag::Warn, format!("{name} not checked: {e}")),
        Some(Ok(json)) => json,
    };
    let value = serde_json::from_str::<serde_json::Value>(json).ok().and_then(|v| v.get("Quota")?.get("Value")?.as_f64()).filter(|g| g.is_finite() && *g >= 0.0);
    let Some(gb) = value else {
        return DoctorLine::row(Tag::Warn, format!("{name} not checked: no Quota.Value in the get-service-quota output"));
    };
    let need_mib = u64::from(max_concurrent) * u64::from(memory_mib);
    let need = format!("[vm] max_concurrent {max_concurrent} × {memory_mib} MiB = {} GB", gib(need_mib));
    if gb * 1024.0 >= need_mib as f64 {
        DoctorLine::row(Tag::Ok, format!("{name} {gb} GB in {REGION} covers {need}"))
    } else {
        DoctorLine::row(Tag::Warn, format!("{name} {gb} GB in {REGION} < {need}  <- lower [vm].max_concurrent or request an increase (Service Quotas, lambda {MICROVM_MEMORY_QUOTA_CODE}, {REGION})"))
    }
}

/// `[vm]` as a flag-less `ai-env vm run` uses it: the settings when
/// [`VmCfg::validate`] accepts them, else `[NO ]` with its message (those
/// commands refuse to start; the wrapper is unaffected). The suspended
/// duration shown is the one sent, `min([vm].suspended_s, max duration)`
/// (plan D8); a larger configured value is named as capped (it applies to a
/// run with a longer `--max-duration`).
#[must_use]
pub fn row_vm_config(vm: &VmCfg) -> DoctorLine {
    match vm.validate() {
        Ok(()) => {
            let suspended = vm.suspended_s.unwrap_or(vm.max_duration_s).min(vm.max_duration_s);
            let note = match vm.suspended_s {
                None => " (the max duration)".to_string(),
                Some(s) if s > vm.max_duration_s => format!(" ([vm].suspended_s {s} capped at the max duration)"),
                Some(_) => String::new(),
            };
            DoctorLine::row(
                Tag::Ok,
                format!("[vm] max_concurrent {}, memory {} MiB, max duration {} s, idle {} s, suspended {suspended} s{note}", vm.max_concurrent, vm.memory_mib, vm.max_duration_s, vm.max_idle_s),
            )
        }
        Err(e) => DoctorLine::row(Tag::No, format!("{e}  <- fix [vm] in bridge.toml (ai-env vm and lab refuse it)")),
    }
}

/// The rows that read `bridge.toml` itself — [`row_execution_role`],
/// [`row_vm_config`], [`row_microvm_quota`] (`quota` as there) — only for a
/// file that parsed: for an absent or unparseable one they would describe
/// the built-in defaults as if configured, so one `[-  ]` line says they
/// were not checked (the bridge.toml row already names the reason).
#[must_use]
pub fn rows_bridge_settings(loaded: &Result<Option<BridgeConfig>, BridgeError>, quota: Option<Result<&str, &str>>) -> Vec<DoctorLine> {
    let why = match loaded {
        Ok(Some(cfg)) => return vec![row_execution_role(&cfg.aws), row_vm_config(&cfg.vm), row_microvm_quota(quota, cfg.vm.max_concurrent, cfg.vm.memory_mib)],
        Ok(None) => "no bridge.toml",
        Err(_) => "bridge.toml unparseable",
    };
    vec![DoctorLine::row(Tag::Skip, format!("execution role, [vm] and microvm memory quota not checked ({why})"))]
}

/// `state/vms`: the rows by status, and whether a pending row (a
/// `pending-<client_token>.toml` written before `RunMicrovm` and never
/// promoted to an id row) is older than [`PENDING_STALE_S`]: the trace of a
/// run that died before the answer, possibly with a VM running that no row
/// names, which `ai-env vm gc` adopts or clears. A pending row whose
/// `created` does not parse counts as stale; an id row still `pending` (a
/// `--no-wait` run) is a VM the service knows and is only counted. `[-  ]`
/// when there are no rows.
#[must_use]
pub fn row_vm_registry(rows: &[VmRow], now: u64) -> DoctorLine {
    if rows.is_empty() {
        return DoctorLine::row(Tag::Skip, "no VMs recorded (state/vms)");
    }
    let counts: Vec<String> = [RowStatus::Pending, RowStatus::Running, RowStatus::Suspended, RowStatus::Terminated, RowStatus::Unknown]
        .iter()
        .map(|s| (s.as_str(), rows.iter().filter(|r| r.status == *s).count()))
        .filter(|(_, n)| *n > 0)
        .map(|(s, n)| format!("{n} {s}"))
        .collect();
    let stale = rows.iter().filter(|r| r.is_pending_row() && parse_rfc3339_utc(&r.created).is_none_or(|c| now.saturating_sub(c) > PENDING_STALE_S)).count();
    let text = format!("vm registry: {} ({} rows)", counts.join(", "), rows.len());
    if stale == 0 {
        DoctorLine::row(Tag::Ok, text)
    } else {
        DoctorLine::row(Tag::Warn, format!("{text}; {stale} pending row(s) older than {} min  <- run: ai-env vm gc (--yes clears them)", PENDING_STALE_S / 60))
    }
}

/// `[aws].execution_role_arn`: passed to `RunMicrovm` when set; without it
/// the VM has no runtime logs and no run reports (plan D12).
#[must_use]
pub fn row_execution_role(aws: &AwsCfg) -> DoctorLine {
    match aws.execution_role_arn.as_deref().map(str::trim).filter(|a| !a.is_empty()) {
        Some(arn) => DoctorLine::row(Tag::Ok, format!("execution role {arn}")),
        None => DoctorLine::row(Tag::Warn, "[aws].execution_role_arn unset: runtime logs and run reports need it  <- make infra-status WRITE=1"),
    }
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

/// Cursor's user settings on macOS (the only scope where the machine-scoped
/// `claudeCode.claudeProcessWrapper` takes effect).
#[must_use]
pub fn cursor_settings_path() -> PathBuf {
    home().join("Library").join("Application Support").join("Cursor").join("User").join("settings.json")
}

/// Collect the inputs and build every bridge row.
#[must_use]
pub fn rows(store: &Keystore) -> BridgeDoctor {
    let t = Duration::from_secs(5);
    let mut lines = Vec::new();

    lines.push(row_toolchain(run_capture("rustup", &["run", EXPECTED_TOOLCHAIN, "rustc", "--version"], t).ok().as_deref()));
    let mut candidates = all_in_path("cargo-lambda", &effective_path());
    // The Makefile also looks in ~/.cargo/bin when it is not on PATH.
    if let Some(home) = std::env::var_os("HOME") {
        let cargo_bin = PathBuf::from(home).join(".cargo").join("bin").join("cargo-lambda");
        if cargo_bin.is_file() && !candidates.contains(&cargo_bin) {
            candidates.push(cargo_bin);
        }
    }
    let cargo_lambda: Vec<(PathBuf, Option<String>)> = candidates
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
    if arn.as_deref().is_some_and(is_root_arn) {
        lines.push(DoctorLine::row(Tag::Skip, "iam simulate: not possible for the account root user (use an IAM user or SSO role for day-to-day work)"));
    } else {
        let sim = arn.as_ref().map(|arn| run_capture("aws", &iam_simulate_args(arn), Duration::from_secs(15)));
        lines.push(row_iam_simulate(sim.as_ref().map(|r| r.as_deref().map_err(String::as_str))));
    }
    let base = arn.as_ref().map(|_| {
        let id = format!("arn:aws:lambda:{REGION}:aws:microvm-image:{BASE_IMAGE_NAME}");
        run_capture("aws", &["lambda-microvms", "list-managed-microvm-image-versions", "--image-identifier", &id, "--region", REGION, "--output", "json"], Duration::from_secs(15))
    });
    lines.push(row_base_image(base.as_ref().map(|r| r.as_deref().map_err(String::as_str))));

    let paths = Paths::resolve();
    let loaded = paths.as_ref().ok().map(BridgeConfig::load);
    // The operator's identity, like every aws call here (doctor never unseals
    // the runtime key); only for a parsed `[vm]` the quota could cover.
    let parsed = matches!(loaded, Some(Ok(Some(_))));
    let quota = arn.as_ref().filter(|_| parsed).map(|_| run_capture("aws", &quota_args(), Duration::from_secs(15)));
    let census_path = match &paths {
        Ok(paths) => {
            let loaded = loaded.as_ref().expect("loaded with the paths");
            lines.push(row_bridge_config(paths, loaded));
            Some(paths.census())
        }
        Err(e) => {
            lines.push(DoctorLine::row(Tag::No, format!("bridge paths: {e}")));
            None
        }
    };
    let cfg = loaded.as_ref().and_then(|l| l.as_ref().ok()).and_then(Option::clone).unwrap_or_default();
    let key = cfg.creds.key.as_str();
    lines.push(row_keystore_key(store.key_exists(key), key));
    let infra_state = match &paths {
        Ok(paths) => {
            lines.push(runtime_credentials(&paths.aws_env()));
            let state = read_infra_state(paths);
            lines.push(row_infra_state(&state, &paths.infra_state()));
            let loaded = loaded.as_ref().expect("loaded with the paths");
            lines.extend(rows_bridge_settings(loaded, quota.as_ref().map(|r| r.as_deref().map_err(String::as_str))));
            lines.push(match list_rows(paths) {
                Ok(vms) => row_vm_registry(&vms, unix_now()),
                Err(e) => DoctorLine::row(Tag::Warn, format!("vm registry unreadable: {e}")),
            });
            let (tw, sp) = (cfg.review.tripwires_path(paths), cfg.review.settings_policy_path(paths));
            lines.push(row_review_files(&tw, tw.is_file(), &sp, sp.is_file()));
            state.ok().flatten()
        }
        Err(_) => None,
    };

    let ext_dir = home().join(".cursor").join("extensions");
    let dirs: Vec<String> = std::fs::read_dir(&ext_dir)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    let bundle = pick_bundle(&dirs);
    let bundled_out = bundle.as_ref().and_then(|(_, dir)| {
        let bin = ext_dir.join(dir).join("resources").join("native-binary").join("claude");
        run_capture(&bin.to_string_lossy(), &["--version"], t).ok()
    });
    lines.push(row_cursor_bundle(&dirs, bundled_out.as_deref()));
    if let Some(row) = row_fixture_drift(bundle.as_ref().map(|(ver, _)| ver.as_str())) {
        lines.push(row);
    }
    if let Some(row) = row_image_claude(infra_state.as_ref().and_then(|s| s.claude_version.as_deref()), bundle.as_ref().map(|(ver, _)| ver.as_str())) {
        lines.push(row);
    }
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

    let settings_path = cursor_settings_path();
    match std::fs::read_to_string(&settings_path).ok().map(|t| parse_settings(&t)) {
        Some(Err(e)) => lines.push(row_settings_unparseable(&settings_path, &e)),
        other => lines.extend(row_wrapper_setting(other.and_then(Result::ok).as_ref(), &exists_exec, &sibling)),
    }

    if let Some(path) = census_path {
        match read_rows(&path, None) {
            Ok(rows) => lines.push(row_census(&rows, &path)),
            Err(e) => lines.push(DoctorLine::row(Tag::Warn, format!("census unreadable: {e}"))),
        }
    }

    BridgeDoctor { lines, auth_unavailable }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The row follows what is at the path, the way `creds aws-set` judges
    /// it: only a regular ai-env container is sealed; a plaintext key (what
    /// `ai-env decrypt --force` leaves in place), a symlink, even to a
    /// container, or a directory is `[NO ]`, and the row never shows the
    /// file's contents.
    #[test]
    fn runtime_credentials_row_follows_the_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("aws.env");
        let (tag, t) = text(&runtime_credentials(&p));
        assert!(tag == Tag::Skip && t.contains("runtime credentials absent") && t.contains("make runtime-key"), "{t}");

        let sealed = d.path().join("sealed.env");
        std::fs::write(&sealed, crate::container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
        assert_eq!(text(&runtime_credentials(&sealed)), (Tag::Ok, format!("runtime credentials sealed ({})", sealed.display())));

        let plain_value = format!("{}{}", "placeholder-", "not-a-key");
        std::fs::write(&p, format!("AWS_ACCESS_KEY_ID=example-id\nAWS_SECRET_ACCESS_KEY={plain_value}\n")).unwrap();
        let (tag, t) = text(&runtime_credentials(&p));
        assert_eq!(tag, Tag::No, "{t}");
        assert!(t.contains("NOT sealed") && t.contains("is not an ai-env container") && t.contains("move it away, then make runtime-key ROTATE=1"), "{t}");
        assert!(!t.contains(&plain_value) && !t.contains("example-id"), "{t}");
        std::fs::remove_file(&p).unwrap();

        std::os::unix::fs::symlink(&sealed, &p).unwrap();
        let (tag, t) = text(&runtime_credentials(&p));
        assert!(tag == Tag::No && t.contains("is a symlink"), "{t}");
        std::fs::remove_file(&p).unwrap();

        std::fs::create_dir(&p).unwrap();
        let (tag, t) = text(&runtime_credentials(&p));
        assert!(tag == Tag::No && t.contains("is not a regular file"), "{t}");
    }

    /// A failed listing call (timeout, throttling, AccessDenied, an old CLI)
    /// is no verdict on the version: `[!! ] not checked`, doctor exit 0. Only
    /// a listing that names the version as not AVAILABLE is `[NO ]`, with one hint.
    #[test]
    fn base_image_row_separates_a_failed_call_from_the_verdict() {
        let listing = |status: &str| serde_json::json!({"items": [{"imageArn": "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1", "imageVersion": BASE_IMAGE_VERSION, "status": status}]}).to_string();
        let (tag, t) = text(&row_base_image(Some(Ok(&listing("AVAILABLE")))));
        assert!(tag == Tag::Ok && t.ends_with("AVAILABLE"), "{t}");
        let (tag, t) = text(&row_base_image(Some(Ok(&listing("DEPRECATED")))));
        assert!(tag == Tag::No && t.contains("is DEPRECATED"), "{t}");
        assert_eq!(t.matches("<- ").count(), 1, "one hint: {t}");
        let (tag, t) = text(&row_base_image(Some(Ok("{\"items\": []}"))));
        assert!(tag == Tag::No && t.contains("not listed") && t.contains("<- pick an AVAILABLE version in infra/image-config.json"), "{t}");
        assert_eq!(text(&row_base_image(None)).0, Tag::Skip);

        for call in ["An error occurred (ThrottlingException) when calling the ListManagedMicrovmImageVersions operation: Rate exceeded", "aws: timed out after 15s", "usage: aws [options] <command> <subcommand> [<subcommand> ...] [parameters]"] {
            let row = row_base_image(Some(Err(call)));
            let (tag, t) = text(&row);
            assert_eq!(tag, Tag::Warn, "{call}: {t}");
            assert_eq!(t, format!("base image {BASE_IMAGE_NAME} version {BASE_IMAGE_VERSION} not checked: {call}"));
            assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0, "{call}");
        }
    }

    #[test]
    fn the_doctor_iam_call_pins_the_region() {
        assert!(is_root_arn("arn:aws:iam::123456789012:root"));
        assert!(!is_root_arn("arn:aws:iam::123456789012:user/root"));
        assert!(!is_root_arn("arn:aws:sts::123456789012:assumed-role/x/y"));
        let args = iam_simulate_args("arn:aws:iam::123456789012:user/example");
        assert!(args.windows(2).any(|w| w == ["--region", "eu-central-1"]), "{args:?}");
        assert_eq!(&args[..2], ["iam", "simulate-principal-policy"]);
        assert!(args.windows(2).any(|w| w == ["--policy-source-arn", "arn:aws:iam::123456789012:user/example"]), "{args:?}");
    }

    #[test]
    fn s3_rows() {
        let sp = Path::new("/r/state/infra.toml");
        let good = InfraState {
            stack: "dev".into(),
            written: "2026-09-29T08:00:00Z".into(),
            image_name: Some("ai-env-agent".into()),
            image_state: Some("UPDATED".into()),
            latest_active_image_version: Some("3".into()),
            image_state_source: Some("live 2026-09-29T08:00:00Z".into()),
            claude_version: Some("2.1.283".into()),
            ..InfraState::default()
        };
        let (tag, t) = text(&row_infra_state(&Ok(Some(good.clone())), sp));
        assert!(tag == Tag::Ok && t.contains("ai-env-agent UPDATED, active version 3, claude 2.1.283"), "{t}");
        assert!(t.ends_with("; image state from live 2026-09-29T08:00:00Z"), "the source is shown: {t}");
        let fallback = InfraState { image_state_source: Some("pulumi outputs (live read failed: aws: timed out after 60s)".into()), ..good.clone() };
        let (tag, t) = text(&row_infra_state(&Ok(Some(fallback)), sp));
        assert!(tag == Tag::Warn && t.ends_with("; image state from pulumi outputs (live read failed: aws: timed out after 60s)"), "only a live read vouches for the image: {t}");
        let unrecorded = InfraState { image_state_source: None, ..good.clone() };
        let (tag, t) = text(&row_infra_state(&Ok(Some(unrecorded)), sp));
        assert!(tag == Tag::Warn && t.contains("image state from an unrecorded source  <- make infra-status WRITE=1"), "{t}");
        let older_failure = InfraState { latest_failed_image_version: Some("2".into()), ..good.clone() };
        assert_eq!(text(&row_infra_state(&Ok(Some(older_failure)), sp)).0, Tag::Ok, "a failure older than the active version is history");
        let newer_failure = InfraState { latest_failed_image_version: Some("4".into()), ..good.clone() };
        let (tag, t) = text(&row_infra_state(&Ok(Some(newer_failure)), sp));
        assert!(tag == Tag::Warn && t.contains("latest FAILED version 4"), "{t}");
        let failed = InfraState { image_state: Some("CREATE_FAILED".into()), ..good };
        assert_eq!(text(&row_infra_state(&Ok(Some(failed)), sp)).0, Tag::Warn);
        let (tag, t) = text(&row_infra_state(&Ok(None), sp));
        assert!(tag == Tag::Skip && t.contains("make infra-status WRITE=1"), "{t}");
        assert_eq!(text(&row_infra_state(&Err(BridgeError::Config("bad".into())), sp)).0, Tag::Warn);

        assert!(row_image_claude(None, Some("2.1.283")).is_none());
        assert_eq!(text(&row_image_claude(Some("2.1.283"), Some("2.1.283")).unwrap()).0, Tag::Ok);
        let (tag, t) = text(&row_image_claude(Some("2.1.283"), Some("2.1.284")).unwrap());
        assert!(tag == Tag::Warn && t.contains("make claude-pin CLAUDE_VERSION=2.1.284"), "{t}");

        let (tw, pol) = (Path::new("/r/tripwires.txt"), Path::new("/r/settings-policy.txt"));
        assert_eq!(text(&row_review_files(tw, false, pol, false)).0, Tag::Skip);
        assert_eq!(text(&row_review_files(tw, true, pol, false)).0, Tag::Ok);
    }

    #[test]
    fn image_version_keys() {
        for (v, k) in [("1.0", (1, 0)), ("3", (3, 0)), ("12.5", (12, 5)), ("10", (10, 0)), ("007.0", (7, 0))] {
            assert_eq!(image_version_key(v), Some(k), "{v}");
        }
        for junk in ["", "1.", ".0", "1.0.0", "v1", "+1", "-1", " 1", "1.0 ", "a.b", "1,0"] {
            assert_eq!(image_version_key(junk), None, "{junk:?}");
        }
        assert_eq!(image_version_key(&"9".repeat(20)), None, "beyond u64");
        assert!(image_version_key("10.0") > image_version_key("9.0"), "numeric, not lexical");
        assert_eq!(image_version_key("3"), image_version_key("3.0"), "N and N.0 are one version");
    }

    /// The service's `N.0` versions (`"1.0"` did not parse as u64, so every
    /// state with a failure read as a newer failure).
    #[test]
    fn row_infra_state_orders_n0_versions() {
        let sp = Path::new("/r/state/infra.toml");
        let state = |active: &str, failed: &str| InfraState {
            stack: "dev".into(),
            written: "2026-09-29T08:00:00Z".into(),
            image_state: Some("UPDATED".into()),
            latest_active_image_version: Some(active.into()),
            latest_failed_image_version: Some(failed.into()),
            image_state_source: Some("live 2026-09-29T08:00:00Z".into()),
            ..InfraState::default()
        };
        for (active, failed, want) in [
            ("2.0", "1.0", Tag::Ok),
            ("10.0", "9.0", Tag::Ok),
            ("3", "2.0", Tag::Ok),
            ("1.0", "2.0", Tag::Warn),
            ("2.0", "2.0", Tag::Warn),
            ("junk", "1.0", Tag::Warn),
            ("2.0", "junk", Tag::Warn),
        ] {
            let (tag, t) = text(&row_infra_state(&Ok(Some(state(active, failed))), sp));
            assert_eq!(tag, want, "active {active}, failed {failed}: {t}");
            assert!(t.contains(&format!("active version {active}")) && t.contains(&format!("latest FAILED version {failed}")), "{t}");
        }
    }

    fn quota_json(gb: &str) -> String {
        format!("{{\"Quota\": {{\"ServiceCode\": \"lambda\", \"QuotaCode\": \"{MICROVM_MEMORY_QUOTA_CODE}\", \"QuotaName\": \"Max allocated ARM_64 MicroVM memory\", \"Value\": {gb}, \"Unit\": \"None\"}}}}")
    }

    #[test]
    fn row_microvm_quota_compares_gigabytes_with_max_concurrent_times_memory() {
        let (tag, t) = text(&row_microvm_quota(Some(Ok(&quota_json("400.0"))), 3, 2048));
        assert_eq!(tag, Tag::Ok, "{t}");
        assert_eq!(t, "microvm memory quota L-CD1C0CC4 400 GB in eu-central-1 covers [vm] max_concurrent 3 × 2048 MiB = 6 GB");
        assert_eq!(text(&row_microvm_quota(Some(Ok(&quota_json("6.0"))), 3, 2048)).0, Tag::Ok, "exactly enough is enough");
        let (tag, t) = text(&row_microvm_quota(Some(Ok(&quota_json("4"))), 3, 2048));
        assert_eq!(tag, Tag::Warn, "{t}");
        assert!(t.starts_with("microvm memory quota L-CD1C0CC4 4 GB in eu-central-1 < [vm] max_concurrent 3 × 2048 MiB = 6 GB  <- lower [vm].max_concurrent"), "{t}");
        assert_eq!(t.matches("<- ").count(), 1, "one hint: {t}");
        let (tag, t) = text(&row_microvm_quota(Some(Ok(&quota_json("5.5"))), 11, 512));
        assert!(tag == Tag::Ok && t.contains("5.5 GB") && t.ends_with("= 5.5 GB"), "fractions on both sides: {t}");
        assert_eq!(text(&row_microvm_quota(Some(Ok(&quota_json("5.5"))), 3, 2048)).0, Tag::Warn);
    }

    #[test]
    fn row_microvm_quota_without_a_verdict() {
        let (tag, t) = text(&row_microvm_quota(None, 3, 2048));
        assert_eq!(tag, Tag::Skip);
        assert_eq!(t, "microvm memory quota L-CD1C0CC4 not checked (no aws identity)");
        let call = "An error occurred (AccessDeniedException) when calling the GetServiceQuota operation: User is not authorized";
        let row = row_microvm_quota(Some(Err(call)), 3, 2048);
        assert_eq!(text(&row), (Tag::Warn, format!("microvm memory quota L-CD1C0CC4 not checked: {call}")));
        assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0, "a failed call is no verdict");
        for junk in ["not json", "{}", "{\"Quota\": {}}", "{\"Quota\": {\"Value\": \"400\"}}", "{\"Quota\": {\"Value\": -1}}"] {
            let (tag, t) = text(&row_microvm_quota(Some(Ok(junk)), 3, 2048));
            assert!(tag == Tag::Warn && t.ends_with("no Quota.Value in the get-service-quota output"), "{junk}: {t}");
        }
    }

    #[test]
    fn the_doctor_quota_call_pins_the_region_and_the_code() {
        let args = quota_args();
        assert_eq!(&args[..2], ["service-quotas", "get-service-quota"]);
        for pair in [["--region", "eu-central-1"], ["--service-code", "lambda"], ["--quota-code", "L-CD1C0CC4"], ["--output", "json"]] {
            assert!(args.windows(2).any(|w| w == pair), "{pair:?} in {args:?}");
        }
    }

    /// The row reads what tests/fakes/aws.sh answers for the doctor's own
    /// argv (the fake refuses a call without `--region eu-central-1`).
    #[cfg(unix)]
    #[test]
    fn row_microvm_quota_reads_the_fake_aws_answer() {
        let fake = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/aws.sh");
        let call = |gb: Option<&str>, args: &[&str]| {
            let mut cmd = Command::new("/bin/sh");
            cmd.arg(fake).args(args).env_remove("FAKE_AWS_FAIL").env_remove("FAKE_AWS_LOG").env_remove("FAKE_AWS_QUOTA_GB");
            if let Some(gb) = gb {
                cmd.env("FAKE_AWS_QUOTA_GB", gb);
            }
            run_capture_cmd(cmd, None, Duration::from_secs(10))
        };
        let out = call(None, &quota_args());
        let (tag, t) = text(&row_microvm_quota(Some(out.as_deref().map_err(String::as_str)), 3, 2048));
        assert!(tag == Tag::Ok && t.contains(" 400 GB "), "the default quota: {t}");
        let out = call(Some("4"), &quota_args());
        assert_eq!(text(&row_microvm_quota(Some(out.as_deref().map_err(String::as_str)), 3, 2048)).0, Tag::Warn);
        let other = quota_args().map(|a| if a == MICROVM_MEMORY_QUOTA_CODE { "L-00000000" } else { a });
        let err = call(None, &other).unwrap_err();
        assert!(err.starts_with("An error occurred (NoSuchResourceException)"), "{err}");
        let (tag, t) = text(&row_microvm_quota(Some(Err(&err)), 3, 2048));
        assert!(tag == Tag::Warn && t.contains("not checked: An error occurred (NoSuchResourceException)"), "{t}");
    }

    #[test]
    fn row_vm_config_summarises_or_names_the_bad_key() {
        let (tag, t) = text(&row_vm_config(&VmCfg::default()));
        assert_eq!(tag, Tag::Ok);
        assert_eq!(t, "[vm] max_concurrent 3, memory 2048 MiB, max duration 28800 s, idle 300 s, suspended 28800 s (the max duration)");
        let set = VmCfg { max_concurrent: 1, memory_mib: 4096, max_duration_s: 900, max_idle_s: 600, suspended_s: Some(900), ..VmCfg::default() };
        assert_eq!(text(&row_vm_config(&set)), (Tag::Ok, "[vm] max_concurrent 1, memory 4096 MiB, max duration 900 s, idle 600 s, suspended 900 s".to_string()));
        let below = VmCfg { suspended_s: Some(600), ..set.clone() };
        assert!(text(&row_vm_config(&below)).1.ends_with("idle 600 s, suspended 600 s"), "{:?}", text(&row_vm_config(&below)));
        // `vm run` sends min([vm].suspended_s, max duration) (plan D8): never the larger value.
        let (tag, t) = text(&row_vm_config(&VmCfg { suspended_s: Some(28_800), ..set }));
        assert_eq!(tag, Tag::Ok, "valid: a longer --max-duration uses it");
        assert_eq!(t, "[vm] max_concurrent 1, memory 4096 MiB, max duration 900 s, idle 600 s, suspended 900 s ([vm].suspended_s 28800 capped at the max duration)");
        for (bad, key) in [
            (VmCfg { max_concurrent: 0, ..VmCfg::default() }, "[vm].max_concurrent: must be at least 1"),
            (VmCfg { max_idle_s: 60, ..VmCfg::default() }, "[vm].max_idle_s: must be 300..=28800"),
            (VmCfg { max_duration_s: 28_801, ..VmCfg::default() }, "[vm].max_duration_s: must be 1..=28800"),
            (VmCfg { suspended_s: Some(0), ..VmCfg::default() }, "[vm].suspended_s: must be 1..=28800"),
            (VmCfg { memory_mib: 0, ..VmCfg::default() }, "[vm].memory_mib: must be positive"),
        ] {
            let row = row_vm_config(&bad);
            let (tag, t) = text(&row);
            assert_eq!(tag, Tag::No, "{t}");
            assert!(t.starts_with(&format!("config: {key}")) && t.ends_with("  <- fix [vm] in bridge.toml (ai-env vm and lab refuse it)"), "{t}");
            assert_eq!(crate::commands::doctor_exit_code(&[row], false), 1);
        }
    }

    /// An absent or unparseable bridge.toml never has its defaults reported
    /// as the configuration (and the quota answer is not used).
    #[test]
    fn rows_bridge_settings_only_for_a_parsed_bridge_toml() {
        let quota = quota_json("4");
        for (loaded, why) in [(Ok(None), "no bridge.toml"), (Err(BridgeError::Config("[vm].max_concurrent: invalid type".into())), "bridge.toml unparseable")] {
            let rows = rows_bridge_settings(&loaded, Some(Ok(&quota)));
            let got: Vec<(Tag, String)> = rows.iter().map(text).collect();
            assert_eq!(got, [(Tag::Skip, format!("execution role, [vm] and microvm memory quota not checked ({why})"))]);
            assert_eq!(crate::commands::doctor_exit_code(&rows, false), 0);
        }
        let cfg = BridgeConfig { vm: VmCfg { max_concurrent: 3, memory_mib: 2048, ..VmCfg::default() }, ..BridgeConfig::default() };
        let got: Vec<(Tag, String)> = rows_bridge_settings(&Ok(Some(cfg.clone())), Some(Ok(&quota))).iter().map(text).collect();
        assert_eq!(got.len(), 3, "{got:?}");
        assert_eq!(got[0], text(&row_execution_role(&cfg.aws)));
        assert_eq!(got[1], text(&row_vm_config(&cfg.vm)));
        assert!(got[2].0 == Tag::Warn && got[2].1.contains(" 4 GB in eu-central-1 < [vm] max_concurrent 3 × 2048 MiB = 6 GB"), "{got:?}");
        let got: Vec<(Tag, String)> = rows_bridge_settings(&Ok(Some(cfg)), None).iter().map(text).collect();
        assert_eq!(got[2], (Tag::Skip, "microvm memory quota L-CD1C0CC4 not checked (no aws identity)".to_string()));
    }

    fn vm(id: &str, status: RowStatus, created: &str) -> VmRow {
        VmRow { id: id.into(), client_token: "01926f2e-0000-7000-8000-000000000001".into(), status, created: created.into(), ..VmRow::default() }
    }

    #[test]
    fn row_vm_registry_counts_and_flags_stale_pending_rows() {
        let now = 1_790_000_000;
        let at = |age: u64| crate::wire::time::rfc3339_utc_ms((now - age) * 1000 + 999);
        assert_eq!(text(&row_vm_registry(&[], now)), (Tag::Skip, "no VMs recorded (state/vms)".to_string()));
        let mut rows = vec![
            vm("microvm-a", RowStatus::Running, &at(3600)),
            vm("microvm-b", RowStatus::Running, &at(60)),
            vm("microvm-c", RowStatus::Terminated, &at(86_400)),
            vm("microvm-d", RowStatus::Suspended, &at(600)),
            vm("", RowStatus::Pending, &at(60)),
        ];
        let (tag, t) = text(&row_vm_registry(&rows, now));
        assert_eq!(tag, Tag::Ok, "a young pending row is a run in progress: {t}");
        assert_eq!(t, "vm registry: 1 pending, 2 running, 1 suspended, 1 terminated (5 rows)");
        rows.push(vm("", RowStatus::Pending, &at(PENDING_STALE_S)));
        assert_eq!(text(&row_vm_registry(&rows, now)).0, Tag::Ok, "exactly 5 min is not older than 5 min");
        rows.push(vm("", RowStatus::Pending, &at(PENDING_STALE_S + 1)));
        let (tag, t) = text(&row_vm_registry(&rows, now));
        assert_eq!(tag, Tag::Warn, "{t}");
        assert_eq!(t, "vm registry: 3 pending, 2 running, 1 suspended, 1 terminated (7 rows); 1 pending row(s) older than 5 min  <- run: ai-env vm gc (--yes clears them)");
        rows.push(vm("", RowStatus::Pending, "not a date"));
        assert!(text(&row_vm_registry(&rows, now)).1.contains("; 2 pending row(s) older than 5 min"), "an undated pending row counts as stale");
        // An id row still `pending` (a `--no-wait` run) is a VM the service knows: counted, not flagged.
        let id_row = [vm("microvm-e", RowStatus::Pending, &at(7200)), vm("microvm-f", RowStatus::Unknown, &at(10))];
        assert_eq!(text(&row_vm_registry(&id_row, now)), (Tag::Ok, "vm registry: 1 pending, 1 unknown (2 rows)".to_string()));
    }

    #[test]
    fn row_execution_role_warns_when_unset() {
        let unset = "[aws].execution_role_arn unset: runtime logs and run reports need it  <- make infra-status WRITE=1".to_string();
        assert_eq!(text(&row_execution_role(&AwsCfg::default())), (Tag::Warn, unset.clone()));
        assert_eq!(text(&row_execution_role(&AwsCfg { execution_role_arn: Some("  ".into()), ..AwsCfg::default() })), (Tag::Warn, unset));
        let arn = "arn:aws:iam::123456789012:role/ai-env-microvm-exec";
        assert_eq!(text(&row_execution_role(&AwsCfg { execution_role_arn: Some(arn.into()), ..AwsCfg::default() })), (Tag::Ok, format!("execution role {arn}")));
        assert_eq!(crate::commands::doctor_exit_code(&[row_execution_role(&AwsCfg::default())], false), 0, "a warning, not a failure");
    }

    #[test]
    fn base_image_constants_match_the_pulumi_config() {
        let c: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../infra/image-config.json")).unwrap()).unwrap();
        assert_eq!(c["baseImage"]["name"], BASE_IMAGE_NAME);
        assert_eq!(c["baseImage"]["version"], BASE_IMAGE_VERSION);
    }

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
        assert_eq!(tag, Tag::Ok, "make vm-build skips the old Homebrew one: {t}");
        assert!(t.starts_with("cargo-lambda 1.9.2 (/Users/mike/.cargo/bin/cargo-lambda)") && t.contains("still runs 1.9.1 from /opt/homebrew/bin/cargo-lambda") && t.contains("put /Users/mike/.cargo/bin first"), "{t}");
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
    fn fixture_drift_row() {
        assert_eq!(FIXTURE_EXT_VERSION, "2.1.278");
        assert_eq!(row_fixture_drift(Some(FIXTURE_EXT_VERSION)), None, "the fixtures match the installed bundle");
        assert_eq!(row_fixture_drift(None), None, "no bundle: nothing to drift from");
        let (tag, t) = text(&row_fixture_drift(Some("2.1.290")).unwrap());
        assert_eq!(tag, Tag::Warn);
        assert!(t.starts_with("cursor extension 2.1.290 ≠ fixtures tagged 2.1.278  <- re-capture tests/fixtures/argv from `ai-env wrapper census`"), "{t}");
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
        assert_eq!(none.len(), 2);
        let (tag, t) = text(&none[0]);
        assert_eq!(tag, Tag::Skip);
        assert_eq!(t, format!("{WRAPPER_SETTING} not set  <- ai-env wrapper install --write"));
        let (tag, t) = text(&none[1]);
        assert_eq!(tag, Tag::Skip);
        assert_eq!(t, format!("{PERMISSION_SETTING} unset (sessions start in Manual mode)  <- ai-env wrapper install --write"));

        let ok = parse_settings("{\n  // comment\n  \"claudeCode.claudeProcessWrapper\": \"/Users/mike/.cargo/bin/ai-env-claude\",\n  \"claudeCode.initialPermissionMode\": \"default\",\n}").unwrap();
        let rows = row_wrapper_setting(Some(&ok), &|_| (true, true), &sib);
        assert_eq!(rows.len(), 2, "wrapper Ok + permission Ok, no warnings: {rows:?}");
        assert_eq!(text(&rows[0]), (Tag::Ok, format!("{WRAPPER_SETTING} = /Users/mike/.cargo/bin/ai-env-claude")));
        assert_eq!(text(&rows[1]), (Tag::Ok, format!("{PERMISSION_SETTING} = default")));

        let manual = parse_settings("{\"claudeCode.initialPermissionMode\": \"manual\"}").unwrap();
        let rows = row_wrapper_setting(Some(&manual), &|_| (true, true), &sib);
        assert_eq!(text(&rows[1]), (Tag::Ok, format!("{PERMISSION_SETTING} = manual")));
        let not_a_string = parse_settings("{\"claudeCode.initialPermissionMode\": 3}").unwrap();
        let rows = row_wrapper_setting(Some(&not_a_string), &|_| (true, true), &sib);
        assert_eq!(text(&rows[1]).0, Tag::Skip, "a non-string mode counts as unset");

        let js = parse_settings("{\"claudeCode.claudeProcessWrapper\": \"/x/wrapper.js\"}").unwrap();
        let rows = row_wrapper_setting(Some(&js), &|_| (true, true), &sib);
        assert!(rows.iter().any(|r| text(r).0 == Tag::Warn && text(r).1.contains("under node")));
        assert!(rows.iter().any(|r| text(r).0 == Tag::Warn && text(r).1.contains("points elsewhere")));
        assert!(!rows.iter().any(|r| text(r).1.contains("build directory")));

        let missing = parse_settings("{\"claudeCode.claudeProcessWrapper\": \"/gone\"}").unwrap();
        let rows = row_wrapper_setting(Some(&missing), &|_| (false, false), &sib);
        assert_eq!(text(&rows[0]).0, Tag::No);
        let noexec = row_wrapper_setting(Some(&missing), &|_| (true, false), &sib);
        assert!(text(&noexec[0]).1.contains("not executable"));

        let (tag, t) = text(&row_settings_unparseable(Path::new("/s.json"), "expected value at line 1 column 2"));
        assert_eq!(tag, Tag::Warn);
        assert!(t.contains("wrapper rows not checked") && t.ends_with("/s.json"), "{t}");
    }

    #[test]
    fn wrapper_under_target_warns() {
        let p = "/Users/mike/Documents/DeFi/ai-env/target/debug/ai-env-claude";
        let sib = Sibling::Next(PathBuf::from(p));
        let dbg = parse_settings(&format!("{{\"claudeCode.claudeProcessWrapper\": \"{p}\", \"claudeCode.initialPermissionMode\": \"default\"}}")).unwrap();
        let rows = row_wrapper_setting(Some(&dbg), &|_| (true, true), &sib);
        assert_eq!(text(&rows[0]).0, Tag::Ok, "a debug wrapper still works today");
        let warns: Vec<String> = rows.iter().filter(|r| text(r).0 == Tag::Warn).map(|r| text(r).1).collect();
        assert_eq!(warns, vec![format!("wrapper under a build directory ({p}): cargo clean breaks Cursor  <- ai-env wrapper install --write from the installed ai-env")]);
        assert_eq!(rows.len(), 3, "Ok, the target warning, the permission row: {rows:?}");

        // Only a component named exactly `target` counts: a `targets/` or `my-target/` directory is not a build directory.
        for other in ["/Users/mike/targets/ai-env-claude", "/opt/my-target/bin/ai-env-claude", "/Users/mike/.cargo/bin/ai-env-claude"] {
            let s = parse_settings(&format!("{{\"claudeCode.claudeProcessWrapper\": \"{other}\"}}")).unwrap();
            let rows = row_wrapper_setting(Some(&s), &|_| (true, true), &Sibling::Next(PathBuf::from(other)));
            assert!(!rows.iter().any(|r| text(r).1.contains("build directory")), "{other}: {rows:?}");
        }
    }

    #[test]
    fn census_rows() {
        let path = Path::new("/r/logs/census.jsonl");
        let (tag, t) = text(&row_census(&[], path));
        assert_eq!(tag, Tag::Skip);
        assert_eq!(t, "no census yet (/r/logs/census.jsonl)  <- run one Cursor session with the wrapper installed");

        let rows = vec![
            serde_json::json!({"v": 1, "ts": "2026-09-22T10:00:00Z", "route": "local", "reason": "subcommand:auth"}),
            serde_json::json!({"v": 1, "ts": "2026-09-22T10:00:05Z", "route": "remote", "reason": "session"}),
        ];
        let (tag, t) = text(&row_census(&rows, path));
        assert_eq!(tag, Tag::Ok);
        assert_eq!(t, "census: 2 rows, last 2026-09-22T10:00:05Z route=remote reason=session", "the last row wins");

        let partial = vec![serde_json::json!({"v": 1, "ts": 12, "route": "local"})];
        let (tag, t) = text(&row_census(&partial, path));
        assert_eq!(tag, Tag::Ok);
        assert_eq!(t, "census: 1 rows, last ? route=local reason=?", "missing or non-string fields read as ?");
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
