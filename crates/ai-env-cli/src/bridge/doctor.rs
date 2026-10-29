//! Bridge rows appended to `ai-env doctor`. Every row builder is a pure
//! function of already-collected inputs so it is unit-testable without the
//! subprocesses that `rows` runs (5 s timeout each; 15 s for aws). Doctor
//! never calls Pulumi: the stack's view comes from `state/infra.toml`.
//!
//! S8 operators: doctor never unseals anything (neither the runtime key nor
//! `credentials/ops.env`) and never resolves an operator: its AWS rows run
//! only under an identity `ai-env as` declared (`ai-env as ops -- ai-env
//! doctor`, one Touch ID), as that identity; without one it makes a single
//! plain `sts get-caller-identity`, only to warn when the shell's own
//! credentials are the account root's.
use crate::age_cmd::{effective_path, find_in_path};
use crate::bridge::census::read_rows;
use crate::bridge::awscli::{aws_cmd_as, program_as};
use crate::bridge::identity::{declared, parse_caller, verify_operator, KeyNotes, Operator, Verified, DEPLOYER_USER};
use crate::bridge::config::{env_region_warning, is_connector_arn, is_rfc1918, AwsCfg, BridgeConfig, CredsCfg, EgressCfg, Paths, VmCfg, WrapperMode, REGION, TRUE_ACCEPTS_NOTHING};
use crate::bridge::creds::{aws_env_state, AwsEnvState};
use crate::bridge::egress::{credential_precheck, EgressVerified};
use crate::bridge::errors::BridgeError;
use crate::bridge::infra::{base_image_verdict, read_infra_state, InfraState, CONNECTOR_NOT_IN_OUTPUTS};
use crate::bridge::sibling::{exists_exec, find_sibling, Sibling, INSTALL_HINT};
use crate::bridge::vm::registry::{list_rows, RowStatus, VmRow, PENDING_STALE_S};
use crate::commands::{DoctorLine, Tag};
use crate::store::Keystore;
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

/// `Ok(stdout)` (trimmed) on exit 0, else the stderr line that says what
/// went wrong ([`error_line`]; or the exit code when stderr is empty, or the
/// spawn/timeout error).
pub fn run_capture_cmd(cmd: Command, stdin: Option<&[u8]>, timeout: Duration) -> Result<String, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let c = capture(cmd, stdin, timeout)?;
    if c.success {
        return Ok(c.stdout.trim().to_string());
    }
    let first = error_line(&c.stderr).to_string();
    if first.is_empty() {
        Err(format!("{program}: exit {}", c.code.map_or_else(|| "signal".to_string(), |code| code.to_string())))
    } else {
        Err(first)
    }
}

/// The line of a failed command's stderr that says what went wrong: the
/// first, unless stderr is a Python traceback (a crashed aws CLI), whose
/// error is its last unindented line (`ImportError: …`), not the header.
fn error_line(stderr: &str) -> &str {
    let first = stderr.trim().lines().next().unwrap_or("").trim();
    if !first.starts_with("Traceback (most recent call last)") {
        return first;
    }
    stderr.trim().lines().rev().find(|l| !l.is_empty() && !l.starts_with(char::is_whitespace) && !l.starts_with("Traceback ")).map_or(first, str::trim)
}

/// Remove from `cmd`'s environment what a probed tool has no business
/// seeing: the variables the age children lose (`CHILD_ENV_REMOVED`: the
/// OAuth token, the API key, an AWS key, a session token, the stack's
/// passphrase) and the `ai-env as` marker. Under `ai-env as ops -- ai-env
/// doctor` the operator key is for the AWS rows alone, never for rustup, zig
/// or claude.
fn without_credentials(cmd: &mut Command) -> &mut Command {
    for name in crate::age_cmd::CHILD_ENV_REMOVED.iter().chain(&[crate::commands::RUNNER_MARKER]) {
        cmd.env_remove(name);
    }
    cmd
}

/// The command a probe runs: `program args…` without any credential of this
/// process ([`without_credentials`]).
fn probe_cmd(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    without_credentials(cmd.args(args));
    cmd
}

/// Probe `program args…` with no stdin and without any credential of this
/// process (the OAuth token, an AWS key, the marker).
pub fn run_capture(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    run_capture_cmd(probe_cmd(program, args), None, timeout)
}

/// Doctor's one plain `aws sts get-caller-identity` when no identity is
/// declared (§8.2): the shell's own credential chain as it is (an exported
/// key included: the row warns when it is the account root's), only the
/// OAuth token removed.
fn ambient_sts_cmd() -> Command {
    let mut cmd = Command::new("aws");
    cmd.args(["sts", "get-caller-identity", "--region", REGION, "--output", "json"]).env_remove("CLAUDE_CODE_OAUTH_TOKEN");
    cmd
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

/// What a row says when its AWS call needs the operator identity doctor was not given.
pub const NO_OPERATOR_ROW: &str = "no operator identity: ai-env as ops -- ai-env doctor";

/// The operator identity `ai-env as` declared (`declared`: `None` without a
/// marker, `Err` its §2.5 refusal) and what the row's one sts call answered
/// as it (`checked`): `(row, auth_unavailable)`. A refused key is the only
/// failure that sets `auth_unavailable` (exit 5).
#[must_use]
pub fn row_operator_identity(declared: Option<&std::result::Result<Operator, String>>, checked: Option<&crate::errors::Result<Verified>>) -> (DoctorLine, bool) {
    let op = match declared {
        None => return (DoctorLine::row(Tag::Skip, "operator identity: none declared (doctor never unseals credentials/ops.env)  <- ai-env as ops -- ai-env doctor (one Touch ID)"), false),
        Some(Err(e)) => return (DoctorLine::row(Tag::No, format!("operator identity: {e}")), false),
        Some(Ok(op)) => op,
    };
    let v = match checked {
        Some(Ok(v)) => v,
        Some(Err(e)) => return (DoctorLine::row(Tag::No, format!("operator identity: {e}")), e.exit_code() == 5),
        None => return (DoctorLine::row(Tag::No, "operator identity: not checked"), false),
    };
    let line = match op {
        Operator::Runner { role, tail } => DoctorLine::row(Tag::Ok, format!("operator identity {} (ai-env as {}, key ...{tail})", v.arn, role.word())),
        Operator::Sealed { key } => DoctorLine::row(Tag::Ok, format!("operator identity {} (credentials/ops.env, key ...{})", v.arn, key.tail())),
        Operator::Ambient { root: true } => DoctorLine::row(Tag::Warn, "operator identity is the account ROOT (ai-env as root: the bootstrap and break-glass only)  <- ai-env as ops -- ai-env doctor"),
        Operator::Ambient { root: false } => DoctorLine::row(Tag::Ok, format!("operator identity {} (ai-env as ambient: the aws CLI's own credentials, never the root)", v.arn)),
    };
    (line, false)
}

/// No identity declared: one plain `aws sts get-caller-identity` (`sts`:
/// `None` without an aws CLI), only to warn when the shell's own credentials
/// are the account root's; operator commands never use them.
#[must_use]
pub fn row_ambient_identity(sts: Option<Result<&str, &str>>) -> DoctorLine {
    let not_used = |e: &str| DoctorLine::row(Tag::Skip, format!("ambient aws CLI identity: {e} (not used by operator commands)"));
    match sts {
        None => DoctorLine::row(Tag::Skip, "aws cli not found (bridge commands need it)"),
        Some(Err(e)) if e.to_ascii_lowercase().contains("unable to locate credentials") => {
            DoctorLine::row(Tag::Ok, "no ambient aws CLI credentials (operator commands use ai-env as … or credentials/ops.env)")
        }
        Some(Err(e)) => not_used(e),
        Some(Ok(json)) => match parse_caller(json) {
            Ok(v) if v.is_root() => DoctorLine::row(
                Tag::Warn,
                "the ambient aws CLI credentials are the account ROOT: operator commands never use them, but a plain aws call here runs as the root; outside the bootstrap and break-glass, keep root's key out of a terminal used for ai-env (README \"Identities\")  <- ai-env as ops -- … for operator commands, ai-env as deployer -- … to deploy",
            ),
            Ok(v) => DoctorLine::row(Tag::Skip, format!("ambient aws CLI identity {} (not used by operator commands)", v.arn)),
            Err(e) => not_used(&e),
        },
    }
}

/// `credentials/ops.env`, the ai-env-ops key, from the file and the notes
/// sealed with it (`notes`: unauthenticated, display only; no Touch ID).
#[must_use]
pub fn row_ops_key(state: &AwsEnvState, path: &Path, notes: &KeyNotes) -> DoctorLine {
    match state {
        AwsEnvState::Sealed => {
            let user = notes.user.as_deref().unwrap_or("an unrecorded user");
            let tail = notes.key_id_last4.as_deref().map_or_else(|| "(key id not recorded)".to_string(), |t| format!("...{t}"));
            let day = notes.sealed_day().unwrap_or_else(|| "on an unrecorded day".to_string());
            DoctorLine::row(Tag::Ok, format!("ops key sealed ({}): {user} {tail}, sealed {day} (recorded at sealing, not authenticated)", path.display()))
        }
        AwsEnvState::Absent => DoctorLine::row(Tag::Skip, format!("ops key absent ({})  <- ai-env as deployer -- make ops-key (after the bootstrap: make operator-keys)", path.display())),
        AwsEnvState::NotSealed(why) => DoctorLine::row(Tag::No, format!("ops key NOT sealed: {} {why}  <- move it away, then ai-env as deployer -- make ops-key ROTATE=1", path.display())),
    }
}

/// The ops key row for the file at `path`, as `rows` builds it (its notes read without a Touch ID).
#[must_use]
pub fn ops_key(path: &Path) -> DoctorLine {
    let state = aws_env_state(path);
    let notes = match state {
        AwsEnvState::Sealed => crate::bridge::registry::read_regular_file(path).ok().flatten().map(|text| KeyNotes::of(&text)).unwrap_or_default(),
        _ => KeyNotes::default(),
    };
    row_ops_key(&state, path, &notes)
}

/// The deployer `state/infra.toml` records and, under an identity, its keys
/// (`keys`: the `iam list-access-keys --user-name ai-env-deployer` output;
/// `None` when not made). Its key lives in Strongbox only: one key is the
/// norm, none or two need a hand.
#[must_use]
pub fn row_deployer(state: &Result<Option<InfraState>, BridgeError>, keys: Option<Result<&str, &str>>) -> DoctorLine {
    let recorded = match state {
        Ok(s) => s.as_ref().is_some_and(|s| s.deployer_user_arn.is_some() || s.deployer_user_name.is_some()),
        Err(e) => return DoctorLine::row(Tag::Skip, format!("deployer: not checked (state/infra.toml unreadable: {e})  <- {INFRA_STATUS_HINT}")),
    };
    if !recorded {
        return DoctorLine::row(Tag::Skip, format!("deployer: none recorded in state/infra.toml  <- the bootstrap deploy, then {INFRA_STATUS_HINT}"));
    }
    let who = format!("deployer user/{DEPLOYER_USER}");
    let json = match keys {
        None => return DoctorLine::row(Tag::Ok, format!("{who} (stack output; its key is in Strongbox only)")),
        Some(Err(e)) if e.contains("NoSuchEntity") => return DoctorLine::row(Tag::No, format!("{who} does not exist, though state/infra.toml names it  <- {INFRA_STATUS_HINT}")),
        Some(Err(e)) => return DoctorLine::row(Tag::Warn, format!("deployer: iam list-access-keys failed: {e}")),
        Some(Ok(json)) => json,
    };
    let count = serde_json::from_str::<serde_json::Value>(json).ok().and_then(|v| v.get("AccessKeyMetadata").and_then(|k| k.as_array()).map(Vec::len));
    match count {
        Some(0) => DoctorLine::row(Tag::No, format!("{who} has no access key  <- ai-env as root -- make operator-keys")),
        Some(1) => DoctorLine::row(Tag::Ok, format!("{who}: 1 access key (in Strongbox only)")),
        Some(n) => DoctorLine::row(
            Tag::Warn,
            format!("{who} has {n} access keys (one left from a rotation?)  <- delete the one not in Strongbox: ai-env as deployer -- aws iam list-access-keys --user-name {DEPLOYER_USER} --region {REGION}"),
        ),
        None => DoctorLine::row(Tag::Warn, "deployer: iam list-access-keys failed: no AccessKeyMetadata in its output"),
    }
}

/// `aws iam list-access-keys` of the deployer (the deployer row's call).
fn deployer_keys_args() -> [&'static str; 8] {
    ["iam", "list-access-keys", "--user-name", DEPLOYER_USER, "--region", REGION, "--output", "json"]
}

/// The account root's access keys (`summary`: the `iam get-account-summary`
/// output; `None` without an identity): any, active or deactivated, is a
/// warning until it is deleted. ai-env needs one only for the bootstrap and
/// break-glass, and something else may: deleting it is the user's call, and
/// the hint says when, in words true under any identity (`ai-env as root`
/// before the bootstrap's `make operator-keys` included).
#[must_use]
pub fn row_root_access_keys(summary: Option<Result<&str, &str>>) -> DoctorLine {
    let not_checked = |why: &str| DoctorLine::row(Tag::Skip, format!("the account root's access keys: not checked ({why})"));
    let json = match summary {
        None => return not_checked(NO_OPERATOR_ROW),
        Some(Err(e)) => return not_checked(e),
        Some(Ok(json)) => json,
    };
    match serde_json::from_str::<serde_json::Value>(json).ok().and_then(|v| v.get("SummaryMap")?.get("AccountAccessKeysPresent")?.as_u64()) {
        Some(0) => DoctorLine::row(Tag::Ok, "the account root has no access key"),
        Some(n) => DoctorLine::row(
            Tag::Warn,
            format!("the account root has an access key (AccountAccessKeysPresent={n}, active or deactivated)  <- ai-env needs it only for the bootstrap and break-glass: delete it when nothing else uses it (IAM console, Security credentials), and never load it into a terminal used for ai-env day to day"),
        ),
        None => not_checked("no SummaryMap.AccountAccessKeysPresent in the get-account-summary output"),
    }
}

/// `aws iam get-account-summary` (the root access keys row's call).
fn account_summary_args() -> [&'static str; 6] {
    ["iam", "get-account-summary", "--region", REGION, "--output", "json"]
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

/// How long `claude auth status --json` may take: S7 plan §7 gives the row
/// 10 s, twice the doctor's version probes, so a slow first start of the
/// CLI is not reported as a failed login check.
const CLAUDE_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// `claude auth status --json` of `claude` without the token, the API key,
/// an AWS key, the marker ([`without_credentials`]) and the config-dir
/// variable (the default login is the one asked about).
fn claude_auth_cmd(claude: &Path) -> Command {
    let mut cmd = Command::new(claude);
    without_credentials(cmd.args(["auth", "status", "--json"])).env_remove("CLAUDE_CONFIG_DIR");
    cmd
}

/// [`claude_auth_cmd`] within [`CLAUDE_AUTH_TIMEOUT`].
fn claude_auth_status(claude: &Path) -> Result<String, String> {
    run_capture_cmd(claude_auth_cmd(claude), None, CLAUDE_AUTH_TIMEOUT)
}

/// `loggedIn` of a `claude auth status --json` answer; nothing else of it is read.
#[must_use]
pub fn logged_in(json: &str) -> Option<bool> {
    serde_json::from_str::<serde_json::Value>(json).ok()?.get("loggedIn")?.as_bool()
}

/// The Mac's own claude login (S7), informational: `claude setup-token` does
/// not need one, and the VM never uses it. Only `loggedIn` is shown, never
/// an account, email or organisation.
#[must_use]
pub fn row_claude_auth(claude: Option<&Path>, answer: Option<Result<String, String>>) -> DoctorLine {
    match (claude, answer) {
        (Some(p), Some(Ok(json))) => match logged_in(&json) {
            Some(true) => DoctorLine::row(Tag::Ok, format!("claude auth: logged in ({})", p.display())),
            Some(false) => DoctorLine::row(Tag::Skip, format!("claude auth: not logged in ({}); `claude setup-token` does not need it", p.display())),
            None => DoctorLine::row(Tag::Warn, format!("claude auth: {} auth status --json gave no loggedIn", p.display())),
        },
        (Some(p), Some(Err(e))) => DoctorLine::row(Tag::Warn, format!("claude auth: {} auth status failed: {}", p.display(), crate::wire::redact::scrub(&e))),
        _ => DoctorLine::row(Tag::Skip, "claude auth: no claude on this Mac (the bundled CLI or PATH)"),
    }
}

/// Highest `anthropic.claude-code-<semver>-darwin-arm64` directory name; on
/// equal versions a release beats a suffixed name, then the name decides (never
/// the directory's listing order).
#[must_use]
pub fn pick_bundle(dirs: &[String]) -> Option<(String, String)> {
    dirs.iter()
        .filter_map(|d| bundle_version(d).and_then(|ver| semver(&ver).map(|t| (t, ver, d.clone()))))
        .max_by_key(|(t, ver, d)| (*t, !ver.contains('-'), d.clone()))
        .map(|(_, ver, dir)| (ver, dir))
}

/// The extension directory names Cursor counts as installed in `dir`: real
/// directories only (a file or a symlink is no installed extension), without
/// those `dir/.obsolete` lists — after installing an older version, the newer
/// one stays on disk, listed there, until Cursor's next start deletes it.
#[must_use]
pub fn installed_extension_names(dir: &Path) -> Vec<String> {
    let obsolete: std::collections::BTreeSet<String> = std::fs::read_to_string(dir.join(".obsolete"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&t).ok())
        .map(|m| m.into_iter().filter(|(_, v)| v.as_bool() != Some(false)).map(|(k, _)| k).collect())
        .unwrap_or_default();
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| !obsolete.contains(n)).collect())
        .unwrap_or_default()
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

/// doctor's Cursor rows from the extensions directory `ext_dir` ([`bundle_rows`]), with the live Cursor windows read
/// from the census tail ([`running_windows`]); and what the bundled claude's `--version` printed (`version_of` runs
/// it), which the PATH row compares with. `auto`: automatic admission can happen (`[claude].auto_admit` on, remote
/// mode configured), so the seen row may promise it.
#[must_use]
pub fn cursor_bundle_rows(ext_dir: &Path, image_claude: Option<&str>, version_of: &dyn Fn(&Path) -> Option<String>, auto: bool) -> (Vec<DoctorLine>, Option<String>) {
    // S11 (LD-35): this Mac's claude records, read here only (the tests hand `bundle_rows` their own). S12 (V2,
    // LD-V8): the clock their Docker failures' retry is judged by, read where they are (its locks, file reads only);
    // with no bridge root, no record and the time alone.
    let (claude, clock) = match Paths::resolve() {
        Ok(p) => {
            let records = crate::bridge::claude::load_all(&p);
            let clock = crate::bridge::claude::RetryClock::read(&p, &records);
            (records, clock)
        }
        Err(_) => (Vec::new(), crate::bridge::claude::RetryClock::at(crate::wire::time::unix_now())),
    };
    bundle_rows(ext_dir, image_claude, version_of, &running_windows(), &claude, auto, &clock)
}

/// [`cursor_bundle_rows`] on the live windows `running` and the claude records `claude` (no census or state read:
/// `ext_dir` and what `version_of` runs are its other inputs): the installed bundle (the selection P10, gate G4 and
/// `ai-env claude` share), a `[!! ]` per live Cursor window on another extension than that bundle
/// ([`rows_running_windows`]: a window keeps the extension it loaded until it is reloaded), then (S11) a row per
/// Claude Code version the bundle or a live window runs and the image's fallback (`claude::rows::rows_claude_auto`,
/// the seen row's automatic admission named only with `auto`; S12, V2: a Docker failure's retry judged by `clock`,
/// handed on as given).
#[must_use]
pub fn bundle_rows(ext_dir: &Path, image_claude: Option<&str>, version_of: &dyn Fn(&Path) -> Option<String>, running: &[crate::bridge::census::RunningExtension], claude: &[crate::bridge::claude::Record], auto: bool, clock: &crate::bridge::claude::RetryClock) -> (Vec<DoctorLine>, Option<String>) {
    let dirs = installed_extension_names(ext_dir);
    let bundle = pick_bundle(&dirs);
    let bundled_out = bundle.as_ref().and_then(|(_, dir)| version_of(&ext_dir.join(dir).join("resources").join("native-binary").join("claude")));
    let ver = bundle.as_ref().map(|(v, _)| v.as_str());
    let mut lines = vec![row_cursor_bundle(&dirs, bundled_out.as_deref())];
    lines.extend(rows_running_windows(ver, running));
    lines.extend(crate::bridge::claude::rows::rows_claude_auto(claude, image_claude, ver, running, auto, clock));
    (lines, bundled_out)
}

/// The extension each live Cursor window runs (S9): `census::running_extensions` of the census tail (the last
/// `wrapper_status::CENSUS_TAIL_CHUNKS` × 64 KiB) with `registry::process_identity`. None when the bridge root does not
/// resolve or the census cannot be read (doctor's census row and `wrapper status` say why).
#[must_use]
pub fn running_windows() -> Vec<crate::bridge::census::RunningExtension> {
    let Ok(paths) = Paths::resolve() else {
        return Vec::new();
    };
    crate::bridge::census::read_tail(&paths.census(), crate::bridge::wrapper_status::CENSUS_TAIL_CHUNKS)
        .map(|rows| crate::bridge::census::running_extensions(&rows, &crate::bridge::registry::process_identity))
        .unwrap_or_default()
}

/// One live window as the rows name it (doctor's, `wrapper status`'s, `infra pin --check-bundle`'s note): its
/// extension, its host's pid and since when that host runs.
pub(crate) fn running_window_text(w: &crate::bridge::census::RunningExtension) -> String {
    format!("a Cursor window runs extension {} (host pid {}, since {})", w.ext, w.host, crate::wire::time::rfc3339_utc(w.started))
}

/// A `[!! ]` per live Cursor window (`running`) on another extension than the installed bundle (`installed`):
/// `a Cursor window runs extension 2.1.301 (host pid N, since T); 2.1.302 is installed  <- reload that window`. None
/// without an installed bundle (`row_cursor_bundle` says so), nor for a window on it.
#[must_use]
pub fn rows_running_windows(installed: Option<&str>, running: &[crate::bridge::census::RunningExtension]) -> Vec<DoctorLine> {
    let Some(installed) = installed else {
        return Vec::new();
    };
    running.iter().filter(|w| w.ext != installed).map(|w| DoctorLine::row(Tag::Warn, format!("{}; {installed} is installed  <- reload that window", running_window_text(w)))).collect()
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

/// The fix of a wrapper setting doctor refuses (S11 B.4).
const WRAPPER_FIX: &str = "ai-env wrapper install --write";
/// The one `initialPermissionMode` that is a warning: every chat starts with no permission prompt.
const BYPASS_MODE: &str = "bypassPermissions";

/// Rows for Cursor's wrapper setting; `exists_exec(path) -> (exists, executable)`.
/// A wrapper under a `target/` component is a debug build that `cargo clean`
/// removes (T1.4 installs one on purpose), so it is warned about, not refused.
/// S11 (B.4): a path that is missing or not executable names its fix (the
/// install first when `sibling` is missing too), and `bypassPermissions` is a
/// warning naming the mode to write instead.
#[must_use]
pub fn row_wrapper_setting(settings: Option<&serde_json::Value>, exists_exec: &dyn Fn(&Path) -> (bool, bool), sibling: &Sibling) -> Vec<DoctorLine> {
    let mut rows = Vec::new();
    let wrapper = settings.and_then(|s| s.get(WRAPPER_SETTING)).and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let fix = match sibling {
        Sibling::Missing => format!("cargo install --path crates/ai-env-cli --locked, then {WRAPPER_FIX}"),
        Sibling::Next(_) | Sibling::PathOnly(_) => WRAPPER_FIX.to_string(),
    };
    match wrapper {
        None => rows.push(DoctorLine::row(Tag::Skip, format!("{WRAPPER_SETTING} not set  <- ai-env wrapper install --write"))),
        Some(p) => {
            let path = Path::new(p);
            let (exists, exec) = exists_exec(path);
            if !exists {
                rows.push(DoctorLine::row(Tag::No, format!("{WRAPPER_SETTING} = {p} does not exist  <- {fix}")));
            } else if !exec {
                rows.push(DoctorLine::row(Tag::No, format!("{WRAPPER_SETTING} = {p} is not executable  <- {fix}")));
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
        Some(BYPASS_MODE) => rows.push(DoctorLine::row(Tag::Warn, format!("{PERMISSION_SETTING} = {BYPASS_MODE}: every chat starts with no permission prompt  <- {WRAPPER_FIX} --permission-mode default"))),
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

/// S9 (§4.2): the pre-push review hook of each repository root in
/// `state/workspaces/*.toml` (`review::hook_state`), in root order: `[ok ]`
/// installed, `[!! ]` missing or foreign with its fix (`box hook-install`;
/// for another hook the one line it needs, worded to stay true once it has
/// it), `[-  ]` unknown (the root is gone, or no repository). An installed
/// hook git skips (not executable for this user, as git asks access(2)) or
/// that a merged commit can replace (in the work tree,
/// `review::hook_in_work_tree`) is `[!! ]` too. No workspace yet: no row;
/// a row file that does not parse: one `[!! ]` naming it.
#[must_use]
pub fn row_pre_push_hooks(paths: &Paths) -> Vec<DoctorLine> {
    use crate::bridge::review::{calls_review, chain_line, hook_in_work_tree, hook_state, running_ai_env, HookState};
    let Ok(dir) = std::fs::read_dir(paths.workspaces()) else { return Vec::new() };
    let mut slugs: Vec<String> = dir.filter_map(Result::ok).filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".toml")).map(str::to_string)).collect();
    slugs.sort();
    let mut lines = Vec::new();
    let mut roots = std::collections::BTreeSet::new();
    for slug in slugs {
        match crate::bridge::workspace::rows::read(paths, &slug) {
            Ok(rows) => roots.extend(rows.ws.into_values().map(|w| w.root).filter(|r| !r.is_empty())),
            Err(e) => lines.push(DoctorLine::row(Tag::Warn, format!("workspace rows unreadable: {e}"))),
        }
    }
    let ai_env = running_ai_env().unwrap_or_else(|_| "ai-env".to_string());
    for root in roots {
        lines.push(match hook_state(Path::new(&root)) {
            HookState::Installed(hook) if !crate::bridge::sibling::exists_exec(&hook).1 => {
                DoctorLine::row(Tag::Warn, format!("pre-push review hook in {root} is not executable: git skips it  <- ai-env box hook-install {root}"))
            }
            HookState::Installed(hook) if hook_in_work_tree(Path::new(&root), &hook) => {
                DoctorLine::row(Tag::Warn, format!("pre-push review hook in {root} lives in the work tree ({}, core.hooksPath), or git reads a configuration file there that can move it: a merged or checked-out commit can replace it", hook.display()))
            }
            HookState::Installed(_) => DoctorLine::row(Tag::Ok, format!("pre-push review hook in {root}")),
            HookState::Missing(_) => DoctorLine::row(Tag::Warn, format!("no pre-push review hook in {root}: its pushes are not reviewed  <- ai-env box hook-install {root}")),
            HookState::Foreign(hook) => {
                let calls = if calls_review(&hook) { ", which calls box review --pre-push" } else { "" };
                DoctorLine::row(Tag::Warn, format!("{root} has another pre-push hook ({}){calls}: its pushes are reviewed only if it runs this first, before any exit or read of its stdin  <- {}", hook.display(), chain_line(&ai_env).replace('\n', "; ")))
            }
            HookState::Unknown(why) => DoctorLine::row(Tag::Skip, format!("pre-push review hook in {root} not checked: {why}")),
        });
    }
    lines
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod pre_push_hook_tests {
    use super::*;
    use crate::bridge::review::{chain_line, hook_body, PRE_PUSH_MARK};

    fn git(dir: &Path, args: &[&str]) {
        let o = Command::new("git").args(args).current_dir(dir).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    }

    /// A repository at `dir` whose hooks git runs from `.git/hooks` (set in
    /// the repository: the plain git reads this user's global config too).
    fn repo(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        git(dir, &["init", "-q"]);
        git(dir, &["config", "core.hooksPath", ".git/hooks"]);
        dir.join(".git/hooks/pre-push")
    }

    fn text(line: &DoctorLine) -> (Tag, String) {
        match line {
            DoctorLine::Row { tag, text } => (*tag, text.clone()),
            DoctorLine::Plain(t) => panic!("a plain line: {t}"),
        }
    }

    /// `body` at `hook` with `mode`, its directory made.
    fn hook_file(hook: &Path, body: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(hook, body).unwrap();
        std::fs::set_permissions(hook, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The workspace rows naming `roots`, each its own cwd.
    fn rows_naming(paths: &Paths, roots: &[&Path]) {
        std::fs::create_dir_all(paths.workspaces()).unwrap();
        let text: String = roots.iter().map(|r| format!("[ws.{:?}]\nroot = {:?}\n", r.display().to_string(), r.display().to_string())).collect();
        std::fs::write(paths.workspace_row("app"), format!("v = 1\n{text}")).unwrap();
    }

    /// One row per root of the workspace rows, in root order (a root two
    /// rows name, once): ours installed `[ok ]`; missing and foreign
    /// `[!! ]` with their fixes; a root that is gone `[-  ]`. No rows
    /// directory: no row; a row file that does not parse: named.
    #[test]
    fn each_workspace_root_gets_its_hook_row() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let paths = Paths::from_root_and_env(base.join("bridge"), None);
        assert!(row_pre_push_hooks(&paths).is_empty(), "no workspace yet");
        let (a, b, c, gone) = (base.join("work/a"), base.join("work/b"), base.join("work/c"), base.join("work/gone"));
        let hook_a = repo(&a);
        hook_file(&hook_a, &hook_body("/opt/ai-env/bin/ai-env"), 0o755);
        repo(&b);
        let hook_c = repo(&c);
        hook_file(&hook_c, "#!/bin/sh\n# the team's own checks\nexit 0\n", 0o755);
        std::fs::create_dir_all(paths.workspaces()).unwrap();
        let row = |cwd: &Path, root: &Path| format!("[ws.{:?}]\nroot = {:?}\n", cwd.display().to_string(), root.display().to_string());
        std::fs::write(paths.workspace_row("app"), format!("v = 1\n{}{}", row(&a.join("sub"), &a), row(&c, &c))).unwrap();
        std::fs::write(paths.workspace_row("other"), format!("v = 1\n{}{}{}", row(&b, &b), row(&a, &a), row(&gone, &gone))).unwrap();
        let rows: Vec<(Tag, String)> = row_pre_push_hooks(&paths).iter().map(text).collect();
        assert_eq!(rows.len(), 4, "{rows:?}");
        assert_eq!(rows[0], (Tag::Ok, format!("pre-push review hook in {}", a.display())));
        assert_eq!(rows[1], (Tag::Warn, format!("no pre-push review hook in {}: its pushes are not reviewed  <- ai-env box hook-install {}", b.display(), b.display())));
        assert_eq!(rows[2].0, Tag::Warn);
        assert!(rows[2].1.starts_with(&format!("{} has another pre-push hook ({}): its pushes are reviewed only if it runs this first, before any exit or read of its stdin  <- ai_env_refs=$(cat; echo .); ai_env_refs=${{ai_env_refs%.}}; printf '%s' \"$ai_env_refs\" | '", c.display(), hook_c.display())), "{}", rows[2].1);
        assert!(rows[2].1.ends_with("' box review --pre-push \"$1\" \"$2\" || exit 1"), "{}", rows[2].1);
        assert_eq!(rows[3].0, Tag::Skip);
        assert!(rows[3].1.starts_with(&format!("pre-push review hook in {} not checked: ", gone.display())), "{}", rows[3].1);
        assert_eq!(std::fs::read_to_string(&hook_a).unwrap().lines().nth(1), Some(PRE_PUSH_MARK));
        std::fs::write(paths.workspace_row("broken"), "v = [\n").unwrap();
        let rows: Vec<(Tag, String)> = row_pre_push_hooks(&paths).iter().map(text).collect();
        assert_eq!(rows.len(), 5);
        assert!(rows[0].0 == Tag::Warn && rows[0].1.starts_with("workspace rows unreadable: ") && rows[0].1.contains("broken.toml"), "{:?}", rows[0]);
    }

    /// An installed hook the push never runs is no `[ok ]`: one that lost
    /// its exec bit (git skips it), one where `core.hooksPath` puts it in
    /// the work tree (a merged commit can replace it). Another hook that
    /// already calls the review is said to, and still `[!! ]`: whether it
    /// exits first is not read.
    #[test]
    fn an_installed_hook_git_skips_or_a_merge_can_replace_is_named() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let paths = Paths::from_root_and_env(base.join("bridge"), None);
        let (d, e, f) = (base.join("work/d"), base.join("work/e"), base.join("work/f"));
        hook_file(&repo(&d), &hook_body("/opt/ai-env/bin/ai-env"), 0o644);
        repo(&e);
        git(&e, &["config", "core.hooksPath", ".githooks"]);
        let hook_e = e.join(".githooks/pre-push");
        hook_file(&hook_e, &hook_body("/opt/ai-env/bin/ai-env"), 0o755);
        let hook_f = repo(&f);
        hook_file(&hook_f, &format!("#!/bin/sh\nnpm test || exit 1\n{}\n", chain_line("/opt/ai-env/bin/ai-env")), 0o755);
        rows_naming(&paths, &[&d, &e, &f]);
        let rows: Vec<(Tag, String)> = row_pre_push_hooks(&paths).iter().map(text).collect();
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(rows[0], (Tag::Warn, format!("pre-push review hook in {} is not executable: git skips it  <- ai-env box hook-install {}", d.display(), d.display())));
        assert_eq!(rows[1], (Tag::Warn, format!("pre-push review hook in {} lives in the work tree ({}, core.hooksPath), or git reads a configuration file there that can move it: a merged or checked-out commit can replace it", e.display(), hook_e.display())));
        assert_eq!(rows[2].0, Tag::Warn);
        assert!(rows[2].1.starts_with(&format!("{} has another pre-push hook ({}), which calls box review --pre-push: its pushes are reviewed only if it runs this first, before any exit or read of its stdin  <- ai_env_refs=$(cat; echo .); ai_env_refs=${{ai_env_refs%.}}; printf '%s' \"$ai_env_refs\" | '", f.display(), hook_f.display())), "{}", rows[2].1);
    }
}

/// The pinned managed base image version, from the
/// `list-managed-microvm-image-versions` call: `None` when it was not made
/// (no operator identity, `[-  ]`); `Some(Err)` when the call itself failed (a
/// timeout, throttling, AccessDenied, an aws CLI without `lambda-microvms`),
/// which says nothing about the version (`[!! ] not checked`); otherwise
/// [`base_image_verdict`] on the listing: AVAILABLE, or `[NO ]` naming the
/// status, with one hint.
#[must_use]
pub fn row_base_image(listing: Option<Result<&str, &str>>) -> DoctorLine {
    let pinned = format!("base image {BASE_IMAGE_NAME} version {BASE_IMAGE_VERSION}");
    match listing {
        None => DoctorLine::row(Tag::Skip, format!("{pinned} not checked ({NO_OPERATOR_ROW})")),
        Some(Err(e)) => DoctorLine::row(Tag::Warn, format!("{pinned} not checked: {e}")),
        Some(Ok(json)) => match base_image_verdict(json, BASE_IMAGE_VERSION) {
            Ok(v) => DoctorLine::row(Tag::Ok, format!("{pinned}: {v}")),
            // The verdict names its own fix for a listed version that is not AVAILABLE.
            Err(e) if e.contains("<- ") => DoctorLine::row(Tag::No, format!("{pinned}: {e}")),
            Err(e) => DoctorLine::row(Tag::No, format!("{pinned}: {e}  <- pick an AVAILABLE version in infra/image-config.json")),
        },
    }
}

/// `aws lambda-microvms list-managed-microvm-image-versions` of the pinned base image (the operator's identity).
fn base_image_args(identifier: &str) -> [&str; 8] {
    ["lambda-microvms", "list-managed-microvm-image-versions", "--image-identifier", identifier, "--region", REGION, "--output", "json"]
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

/// What `[vm].memory_mib`, the baseline, is to the platform (S10 F8, AWS's
/// Lambda pricing page): the image's `minimumMemoryInMiB`, billed per second
/// while a VM runs; a VM bursts to 4× it (the guest's `MemTotal` shows that
/// ceiling), the extra billed only while used. Whether the memory quota
/// counts bursts is part B's to read.
const MEMORY_BASELINE: &str = "the image's minimum; bursts to 4×, billed while used";

/// The guest's memory as the VM rows show it (S10 F8): the newest row (by
/// `created`, any status: the figure is the platform's and the image's, as
/// caps are) whose `/health` named the guest's `MemTotal`, as
/// `the guest's MemTotal <n> MiB on <id>, image <version>`; `None` before
/// any VM named one.
fn guest_memory(vms: &[VmRow]) -> Option<String> {
    let row = vms.iter().filter(|r| !r.id.is_empty() && r.mem_total_mib.is_some()).max_by(|a, b| a.created.cmp(&b.created))?;
    let image = if row.image_version.is_empty() { String::new() } else { format!(", image {}", row.image_version) };
    Some(format!("the guest's MemTotal {} MiB on {}{image}", row.mem_total_mib?, row.id))
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
/// (`max_concurrent × memory_mib`, a sum of baselines: S10 F8,
/// `MEMORY_BASELINE`). `q` is the output of [`quota_args`]:
/// `None` when not run (no operator identity, `[-  ]`); `Some(Err)` when the call
/// failed (`[!! ]` with the reason: no verdict); otherwise the quota's
/// `Quota.Value` in Gigabytes: `[ok ]` when `value × 1024 ≥ max_concurrent ×
/// memory_mib`, else `[!! ]` (the platform refuses the run that crosses it
/// with ServiceQuotaExceeded).
#[must_use]
pub fn row_microvm_quota(q: Option<Result<&str, &str>>, max_concurrent: u32, memory_mib: u32) -> DoctorLine {
    let name = format!("microvm memory quota {MICROVM_MEMORY_QUOTA_CODE}");
    let json = match q {
        None => return DoctorLine::row(Tag::Skip, format!("{name} not checked ({NO_OPERATOR_ROW})")),
        Some(Err(e)) => return DoctorLine::row(Tag::Warn, format!("{name} not checked: {e}")),
        Some(Ok(json)) => json,
    };
    let value = serde_json::from_str::<serde_json::Value>(json).ok().and_then(|v| v.get("Quota")?.get("Value")?.as_f64()).filter(|g| g.is_finite() && *g >= 0.0);
    let Some(gb) = value else {
        return DoctorLine::row(Tag::Warn, format!("{name} not checked: no Quota.Value in the get-service-quota output"));
    };
    let need_mib = u64::from(max_concurrent) * u64::from(memory_mib);
    let need = format!("[vm] max_concurrent {max_concurrent} × {memory_mib} MiB baseline = {} GB", gib(need_mib));
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
/// run with a longer `--max-duration`). The memory is the image's minimum,
/// the baseline (S10 F8, `MEMORY_BASELINE`), with the guest's `MemTotal`
/// beside it once a VM's `/health` recorded one (`guest_memory` of `vms`).
#[must_use]
pub fn row_vm_config(vm: &VmCfg, vms: &[VmRow]) -> DoctorLine {
    match vm.validate() {
        Ok(()) => {
            let suspended = vm.suspended_s.unwrap_or(vm.max_duration_s).min(vm.max_duration_s);
            let note = match vm.suspended_s {
                None => " (the max duration)".to_string(),
                Some(s) if s > vm.max_duration_s => format!(" ([vm].suspended_s {s} capped at the max duration)"),
                Some(_) => String::new(),
            };
            let guest = guest_memory(vms).map(|g| format!("; {g}")).unwrap_or_default();
            DoctorLine::row(
                Tag::Ok,
                format!("[vm] max_concurrent {}, memory {} MiB baseline ({MEMORY_BASELINE}{guest}), max duration {} s, idle {} s, suspended {suspended} s{note}", vm.max_concurrent, vm.memory_mib, vm.max_duration_s, vm.max_idle_s),
            )
        }
        Err(e) => DoctorLine::row(Tag::No, format!("{e}  <- fix [vm] in bridge.toml (ai-env vm and lab refuse it)")),
    }
}

/// The rows that read `bridge.toml` itself — [`row_execution_role`],
/// [`row_vm_config`] (`vms` as there), [`row_microvm_quota`] (`quota` as there),
/// [`row_egress`] (`state` as there), [`row_dns_acceptance`] (`dns_path` as
/// there) — only for a file that parsed: for an absent or unparseable one
/// they would describe the built-in defaults as if configured, so one `[-  ]`
/// line says they were not checked (the bridge.toml row already names the
/// reason).
#[must_use]
pub fn rows_bridge_settings(
    loaded: &Result<Option<BridgeConfig>, BridgeError>,
    vms: &[VmRow],
    quota: Option<Result<&str, &str>>,
    state: &Result<Option<InfraState>, BridgeError>,
    dns_path: &Result<Option<(String, String)>, String>,
    verified: &Result<EgressVerified, BridgeError>,
    now: u64,
) -> Vec<DoctorLine> {
    let why = match loaded {
        Ok(Some(cfg)) => {
            let newest = dns_path.as_ref().map(|r| r.as_ref().map(|(v, _)| v.clone())).map_err(Clone::clone);
            return vec![
                row_execution_role(&cfg.aws),
                row_vm_config(&cfg.vm, vms),
                row_microvm_quota(quota, cfg.vm.max_concurrent, cfg.vm.memory_mib),
                row_egress(&cfg.egress, &cfg.aws, state),
                row_dns_acceptance(&cfg.egress, dns_path),
                row_creds_settings(&cfg.creds),
                row_credential_gate(cfg, state, verified, &newest, now),
                row_credential_vm_role(&cfg.aws),
            ];
        }
        Ok(None) => "no bridge.toml",
        Err(_) => "bridge.toml unparseable",
    };
    vec![DoctorLine::row(Tag::Skip, format!("execution role, [vm], microvm memory quota, egress connector, DNS acceptance, [creds] and the credential gate not checked ({why})"))]
}

/// What a mode the wrapper takes as remote does with no root to route on
/// (S9, [`rows_s8`] and [`rows_s8_loaded`]): no session goes remote, so none
/// fails closed yet; the file is wrong all the same.
const NO_ROOT_YET: &str = "every Cursor chat runs on this Mac until bridge.toml names a root, then every chat under it exits 1 at its start";

/// The S8 rows bridge.toml alone decides (plan §12): the wrapper's mode
/// (`[wrapper] mode`: `remote` without a root is `[!! ]`, every chat running
/// here; a value the wrapper does not know is `[NO ]`, every chat under the
/// roots failing closed, or, with no root, every chat running here until
/// bridge.toml names one; S9: the value quoted through
/// `wrapper_status::shown_mode`, scrubbed and capped), one `[!! ]` per
/// `[[workspace]]` still setting the deprecated `seed_allow_dirty` (D2), and
/// the `[seed]` caps (`[NO ]` when the wrapper, `box` and `vm warm` refuse
/// them). The image's `workspace_v1` is [`row_workspace_cap`]'s.
#[must_use]
pub fn rows_s8(cfg: &BridgeConfig) -> Vec<DoctorLine> {
    let shown = || crate::bridge::wrapper_status::shown_mode(&cfg.wrapper.mode);
    let mode_fix = "ai-env wrapper install --write --mode remote (or passthrough)";
    let mut rows = vec![match cfg.wrapper.wrapper_mode() {
        Ok(WrapperMode::Remote) if cfg.roots().is_empty() => DoctorLine::row(Tag::Warn, "wrapper mode remote, but no [workspaces].roots: every Cursor chat runs on this Mac  <- add the roots to bridge.toml"),
        Ok(WrapperMode::Remote) => DoctorLine::row(Tag::Ok, format!("wrapper mode remote: Cursor's chats under the {} root(s) run in their workspace's MicroVM (AI_ENV_BRIDGE_LOCAL=1 runs them here)", cfg.roots().len())),
        Ok(WrapperMode::Passthrough) => DoctorLine::row(Tag::Ok, "wrapper mode passthrough: Cursor's chats run on this Mac (ai-env wrapper install --write --mode remote runs them in MicroVMs)"),
        Err(_) if cfg.roots().is_empty() => DoctorLine::row(Tag::No, format!("bridge.toml [wrapper] mode {} (no root), which names no mode: {NO_ROOT_YET}  <- {mode_fix}", shown())),
        Err(_) => DoctorLine::row(Tag::No, format!("config: [wrapper].mode = {}: must be \"passthrough\" or \"remote\": every Cursor chat under the roots fails closed  <- {mode_fix}", shown())),
    }];
    rows.extend(cfg.workspace_overrides.iter().filter_map(crate::bridge::config::WorkspaceCfg::deprecation).map(|note| DoctorLine::row(Tag::Warn, format!("{note}  <- remove it from bridge.toml"))));
    let seed = &cfg.seed;
    rows.push(match seed.validate() {
        Ok(()) => DoctorLine::row(
            Tag::Ok,
            format!(
                "[seed] a wrapper's seed {} MiB, box seed and vm warm {} MiB, a blob {} MiB, uncommitted changes {} MiB and {} untracked files, a code-out {} MiB, {} box/wip refs kept",
                seed.wrapper_inline_mib, seed.max_mib, seed.max_blob_mib, seed.max_wip_mib, seed.max_untracked_files, seed.max_fetch_mib, seed.keep_wip_refs
            ),
        ),
        Err(e) => DoctorLine::row(Tag::No, format!("{e}  <- fix [seed] in bridge.toml (the wrapper, box and vm warm refuse it)")),
    });
    rows
}

/// [`rows_s8`] for what bridge.toml loaded as (the defaults when there is
/// none); for a file that does not load, the one row the wrapper still acts
/// on: its mode as `route::Broken` reads the file (`[NO ]` when that is
/// remote, a mode it cannot read included, as the wrapper takes it; with
/// roots it reads and none, every chat runs here until bridge.toml names
/// one, the mode quoted through `wrapper_status::shown_mode`). There are no
/// `[seed]` caps to show.
#[must_use]
pub fn rows_s8_loaded(paths: &Paths, loaded: &Result<Option<BridgeConfig>, BridgeError>) -> Vec<DoctorLine> {
    use crate::bridge::route::{effective_mode_loaded, Broken, Loaded, Mode};
    match loaded {
        Ok(Some(cfg)) => return rows_s8(cfg),
        Ok(None) => return rows_s8(&BridgeConfig::default()),
        Err(_) => {}
    }
    let broken = Broken::read(std::fs::read_to_string(&paths.config).ok().as_deref());
    let fix = "  <- fix bridge.toml (the bridge.toml row above)";
    let rootless = broken.roots.as_ref().is_some_and(Vec::is_empty);
    let shown = match &broken.mode {
        Some(Some(mode)) => crate::bridge::wrapper_status::shown_mode(mode),
        Some(None) => "unset".to_string(),
        None => "unreadable".to_string(),
    };
    vec![match effective_mode_loaded(None, &Loaded { broken: Some(broken), ..Loaded::default() }).0 {
        Mode::Remote if rootless => DoctorLine::row(Tag::No, format!("bridge.toml, which does not load, [wrapper] mode {shown} (no root): {NO_ROOT_YET}{fix}")),
        Mode::Remote => DoctorLine::row(Tag::No, format!("wrapper mode remote, but bridge.toml does not load: every Cursor chat under its roots (every chat, when the roots cannot be read) exits 1 naming the error{fix}")),
        _ => DoctorLine::row(Tag::Skip, "wrapper mode passthrough as far as bridge.toml still reads: Cursor's chats run on this Mac"),
    }]
}

/// The image version a new VM runs (`[aws].image_version` as `vm run`
/// resolves it: `active` the recorded latest active version, `N` is `N.0`),
/// or `None` when `active` and nothing is recorded.
fn new_vm_version(cfg: &BridgeConfig, state: Option<&InfraState>) -> Option<String> {
    let want = cfg.aws.image_version.trim();
    if want == "active" {
        state?.latest_active_image_version.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_string)
    } else if want.contains('.') {
        Some(want.to_string())
    } else {
        Some(format!("{want}.0"))
    }
}

/// Does the image serve the workspace routes (S8 L5, `workspace_v1`)? A
/// remote session never selects a VM without it and a pinned one exits 7
/// naming `make deploy`, so an S7 image (7.0) needs `make deploy`. The
/// evidence is the VM rows' caps (`/health`, recorded): `[!! ]` naming each
/// live VM (not terminated) whose caps lack it, with `make deploy` first
/// unless the version a new VM runs has it already (then only `ai-env vm
/// terminate`); else, for the version a new VM runs ([`new_vm_version`]),
/// the newest row of it whose caps were read (any status: caps belong to
/// the image) decides: `[ok ]` with the cap, `[!! ]` without; `[-  ]` when
/// no VM of it answered `/health` yet.
#[must_use]
pub fn row_workspace_cap(vms: &[VmRow], state: &Result<Option<InfraState>, BridgeError>, cfg: &BridgeConfig) -> DoctorLine {
    use crate::bridge::workspace::{vm_capability, Capability};
    const CAP: &str = crate::wire::frame::CAP_WORKSPACE_V1;
    let version = new_vm_version(cfg, state.as_ref().ok().and_then(Option::as_ref));
    let newest = version.as_deref().and_then(|v| vms.iter().filter(|r| r.image_version == v && vm_capability(r) != Capability::Unknown).max_by(|a, b| a.created.cmp(&b.created)));
    let lacking: Vec<&VmRow> = vms.iter().filter(|r| r.status != RowStatus::Terminated && !r.id.is_empty() && vm_capability(r) == Capability::No).collect();
    if !lacking.is_empty() {
        let named = lacking.iter().map(|r| format!("{} ({})", r.id, r.image_version)).collect::<Vec<_>>().join(", ");
        if newest.is_some_and(|r| vm_capability(r) == Capability::Yes) {
            // The image is deployed already: only the leftovers go.
            let ids = lacking.iter().map(|r| r.id.as_str()).collect::<Vec<_>>().join(", ai-env vm terminate ");
            return DoctorLine::row(Tag::Warn, format!("{CAP}: {named} lack it: remote sessions never use them  <- ai-env vm terminate {ids}"));
        }
        return DoctorLine::row(Tag::Warn, format!("{CAP}: {named} lack it (an S7 image): remote sessions never use them  <- make deploy, then ai-env vm terminate them"));
    }
    let Some(version) = version else {
        return DoctorLine::row(Tag::Skip, format!("{CAP}: no active image version recorded  <- make infra-status WRITE=1"));
    };
    match newest {
        Some(r) if vm_capability(r) == Capability::Yes => DoctorLine::row(Tag::Ok, format!("{CAP}: image version {version} serves the workspace routes (from {}'s /health)", r.id)),
        Some(r) => DoctorLine::row(Tag::Warn, format!("{CAP}: image version {version} lacks it (from {}'s /health): every remote session exits 7  <- make deploy", r.id)),
        None => DoctorLine::row(Tag::Skip, format!("{CAP}: image version {version} not known yet (no VM of it answered /health): a remote session reads it, and exits 7 naming make deploy without it")),
    }
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

// ---- S5 rows ------------------------------------------------------------------------

/// What writes the egress keys of `[aws]` and records the connector's state.
const INFRA_STATUS_HINT: &str = "make infra-status WRITE=1";

/// `[aws].egress_connector_arn` against `[egress].require`, and the state of
/// that connector as the last `ai-env infra status` recorded it
/// (`state/infra.toml` as [`read_infra_state`] returned it; no call).
/// `[NO ]`, naming the key and `make infra-status WRITE=1`: a set ARN or
/// `proxy_private_ip` that `ai-env vm` and `lab` refuse (the rules of
/// [`AwsCfg::validate_egress`], whatever `require` says), or no ARN while
/// `require` is on. No ARN with `require` off is `[-  ]`: flag-less runs use
/// the platform's internet egress. A valid ARN is `[ok ]` when its recorded
/// state is ACTIVE, `[!! ]` for any other state, when the state file records
/// another connector, or when the stack exports none
/// ([`CONNECTOR_NOT_IN_OUTPUTS`]: the key is stale), and `[-  ]` when no
/// state is recorded for it (no file, an unreadable one — its error named —,
/// no live read yet, or the read failed: the recorded source says why).
#[must_use]
pub fn row_egress(egress: &EgressCfg, aws: &AwsCfg, state: &Result<Option<InfraState>, BridgeError>) -> DoctorLine {
    let arn = aws.egress_connector_arn.as_deref().filter(|a| !a.trim().is_empty());
    if let Some(arn) = arn.filter(|a| !is_connector_arn(a)) {
        return DoctorLine::row(Tag::No, format!("[aws].egress_connector_arn = {arn:?} is not a network connector of an account in {REGION} (ai-env vm and lab refuse it)  <- {INFRA_STATUS_HINT}"));
    }
    if let Some(ip) = aws.proxy_private_ip.as_deref().filter(|ip| !ip.trim().is_empty() && !is_rfc1918(ip)) {
        return DoctorLine::row(Tag::No, format!("[aws].proxy_private_ip = {ip:?} is not an RFC 1918 address (ai-env vm and lab refuse it)  <- {INFRA_STATUS_HINT}"));
    }
    let Some(arn) = arn else {
        return if egress.require {
            DoctorLine::row(Tag::No, format!("[aws].egress_connector_arn unset, but [egress].require = true (ai-env vm run refuses without --egress internet)  <- {INFRA_STATUS_HINT} after the S5 deploy"))
        } else {
            DoctorLine::row(Tag::Skip, "[aws].egress_connector_arn unset ([egress].require = false: flag-less runs use the platform's internet egress)")
        };
    };
    let name = format!("egress connector {arn}");
    let s = match state {
        Ok(Some(s)) => s,
        Ok(None) => return DoctorLine::row(Tag::Skip, format!("{name}: no state recorded (no state/infra.toml)  <- {INFRA_STATUS_HINT}")),
        Err(e) => return DoctorLine::row(Tag::Skip, format!("{name}: state unknown (state/infra.toml unreadable: {e})  <- {INFRA_STATUS_HINT}")),
    };
    if s.connector_state_source.as_deref() == Some(CONNECTOR_NOT_IN_OUTPUTS) {
        return DoctorLine::row(Tag::Warn, format!("{name}: the stack exports no connector: remove [aws].egress_connector_arn (and proxy_private_ip) from bridge.toml"));
    }
    let norm = crate::bridge::egress::normalize_connector;
    if let Some(recorded) = s.connector_arn.as_deref().filter(|r| norm(r) != norm(arn)) {
        return DoctorLine::row(Tag::Warn, format!("{name}: state/infra.toml records the connector {recorded} instead  <- {INFRA_STATUS_HINT}"));
    }
    let source = s.connector_state_source.as_deref().unwrap_or("an unrecorded source");
    match s.connector_state.as_deref().map(str::trim).filter(|st| !st.is_empty()) {
        None => DoctorLine::row(Tag::Skip, format!("{name}: no state recorded ({})  <- {INFRA_STATUS_HINT}", s.connector_state_source.as_deref().map_or_else(|| "no live read yet".to_string(), |src| format!("state/infra.toml: {src}")))),
        Some(st) if st.eq_ignore_ascii_case("ACTIVE") => {
            let id = s.connector_id.as_deref().map(|id| format!("id {id}; ")).unwrap_or_default();
            DoctorLine::row(Tag::Ok, format!("{name} ACTIVE ({id}state from {source})"))
        }
        Some(st) => DoctorLine::row(Tag::Warn, format!("{name} is {st} (state from {source}): ai-env vm run --egress vpc needs it ACTIVE  <- make connector-status, then {INFRA_STATUS_HINT}")),
    }
}

/// `[egress].accept_platform_dns` against the newest `dns-path` row of
/// `lab/probes.jsonl` (`newest`: its verdict and `ts`; `Err` names why the
/// file could not be read), as the credential gate will judge it
/// (`egress::dns_verdict_ok`). `[NO ]` (doctor exit 1) for a pin `ai-env
/// vm`, `lab` and `egress check` refuse (`EgressCfg::validate`). The legacy
/// `true` is `[!! ]` with the exact line to write (`egress::pin_suggestion`
/// of the newest verdict: Mike's `platform-dns:fd00:ec2::253` gives
/// `accept_platform_dns = "fd00:ec2::253"`). Otherwise `[-  ]` without a
/// dns-path row, `[ok ]` when the newest verdict is accepted, and `[!! ]`
/// when it is not or the file is unreadable (the gate refuses every
/// credential then; nothing that runs today needs it, so never `[NO ]`).
#[must_use]
pub fn row_dns_acceptance(egress: &EgressCfg, newest: &Result<Option<(String, String)>, String>) -> DoctorLine {
    if let Err(e) = egress.validate() {
        return DoctorLine::row(Tag::No, format!("{e}  <- fix [egress].accept_platform_dns in bridge.toml (ai-env vm, lab and egress check refuse it)"));
    }
    let verdict = newest.as_ref().ok().and_then(Option::as_ref).map(|(v, _)| v.as_str());
    if egress.names_no_resolver() {
        return DoctorLine::row(Tag::Warn, format!("egress DNS: {TRUE_ACCEPTS_NOTHING}: only no-dns passes the credential gate  <- in bridge.toml: {}", crate::bridge::egress::pin_suggestion(verdict)));
    }
    let acceptance = egress.dns_acceptance();
    match newest {
        Err(e) => DoctorLine::row(Tag::Warn, format!("egress DNS: the dns-path rows are unreadable ({e}): the credential gate refuses every VM ({acceptance})")),
        Ok(None) => DoctorLine::row(Tag::Skip, format!("egress DNS: no dns-path verdict recorded ({acceptance})  <- ai-env lab run dns-path")),
        Ok(Some((v, ts))) if crate::bridge::egress::dns_accepted(v, egress) => DoctorLine::row(Tag::Ok, format!("egress DNS: the newest dns-path verdict {v} ({ts}) is accepted ({acceptance})")),
        Ok(Some((v, ts))) => DoctorLine::row(Tag::Warn, format!("egress DNS: the newest dns-path verdict {v} ({ts}) is NOT accepted ({acceptance}): the credential gate refuses every VM  <- ai-env lab show dns-path (its note says what replied)")),
    }
}

/// `[creds]`, the section the credential path acts on (S7): the mode, how a
/// secret is delivered and the Touch ID budget, or the key that would make
/// `ai-env vm` refuse before anything is unsealed.
#[must_use]
pub fn row_creds_settings(creds: &CredsCfg) -> DoctorLine {
    match creds.validate() {
        Ok(()) => DoctorLine::row(Tag::Ok, format!("[creds] mode {}, deliver {}, key {}, Touch ID budget {} s", creds.mode, creds.deliver, creds.key, creds.unseal_timeout_s)),
        Err(e) => DoctorLine::row(Tag::No, format!("{e}  <- fix [creds] in bridge.toml (ai-env vm and lab refuse it)")),
    }
}

/// Would the credential gate let a credential into a fresh `vpc` VM of the
/// image version new VMs run (S7)? Everything [`credential_precheck`] judges
/// without an AWS call, asked of a VM built for the question: the connector, a
/// passing `ai-env egress check` for that version with its age, and the DNS
/// evidence. The live half ([`credential_gate`]) can only run against a real
/// VM, so this row says what is in place, never that a delivery will happen.
///
/// `[!! ]` rather than `[NO ]`: nothing here breaks an uncredentialed command.
#[must_use]
pub fn row_credential_gate(cfg: &BridgeConfig, state: &Result<Option<InfraState>, BridgeError>, verified: &Result<EgressVerified, BridgeError>, dns_path: &Result<Option<String>, String>, now: u64) -> DoctorLine {
    let name = "credential gate";
    // The image and version a new VM would run, resolved as `vm run` does (`[aws].image_arn`; `[aws].image_version`:
    // `active` is the recorded latest active version, `N` is `N.0`, `N.M` itself) — not simply the latest active
    // version, which a pinned `[aws].image_version` overrides (the audit's finding).
    let s = match state {
        Ok(Some(s)) => s,
        Ok(None) => return DoctorLine::row(Tag::Skip, format!("{name}: no state recorded (no state/infra.toml)  <- {INFRA_STATUS_HINT}")),
        Err(e) => return DoctorLine::row(Tag::Skip, format!("{name}: state unknown (state/infra.toml unreadable: {e})  <- {INFRA_STATUS_HINT}")),
    };
    let image_arn = cfg.aws.image_arn.clone().filter(|a| !a.trim().is_empty()).unwrap_or_else(|| s.image_arn.clone());
    let want = cfg.aws.image_version.trim();
    let version = if want == "active" {
        match s.latest_active_image_version.as_deref().filter(|v| !v.trim().is_empty()) {
            Some(v) => v.to_string(),
            None => return DoctorLine::row(Tag::Skip, format!("{name}: no active image version recorded  <- {INFRA_STATUS_HINT}")),
        }
    } else if want.contains('.') {
        want.to_string()
    } else {
        format!("{want}.0")
    };
    let verified = match verified {
        Ok(v) => v,
        Err(e) => return DoctorLine::row(Tag::Warn, format!("{name}: the recorded checks cannot be read ({e}): every credential is refused  <- ai-env egress check")),
    };
    // A VM of the recorded version as `vm run` would make one: the row conditions hold by construction, so what
    // this judges is the evidence on disk.
    let row = VmRow {
        id: String::new(),
        image_arn,
        image_version: version.clone(),
        egress: crate::bridge::vm::run::Egress::Vpc.as_str().to_string(),
        egress_gate: Some(crate::bridge::vm::registry::GATE_PASSED.to_string()),
        shell: false,
        ..VmRow::default()
    };
    match credential_precheck(cfg, &row, verified, dns_path, now) {
        Ok(()) => DoctorLine::row(Tag::Ok, format!("{name}: in place for image version {version} (a fresh vpc VM is checked again live before any credential)")),
        Err(r) => DoctorLine::row(Tag::Warn, format!("{name}: {} [{}]", r.why, r.condition)),
    }
}

/// What a credentialed VM's execution role means for the credential (S7 D2):
/// IMDSv2 inside a VM hands uid 1000 that role's keys (measured in S6 part B),
/// so the role is kept — its policy writes the image's log group and nothing
/// else, and the runtime logs are the evidence S7 and S8 rest on — while the
/// proxy is what keeps those keys inside the VM (`ai-env egress allow` refuses
/// every AWS service host). The row records the choice; it never fails.
#[must_use]
pub fn row_credential_vm_role(aws: &AwsCfg) -> DoctorLine {
    match aws.execution_role_arn.as_deref().map(str::trim).filter(|a| !a.is_empty()) {
        Some(role) => DoctorLine::row(
            Tag::Ok,
            format!("credentialed VMs keep the execution role {role}: its keys are readable inside the VM (IMDSv2) and work only at AWS hosts, which the allowlist never carries (plan S7 D2, v6 §9)"),
        ),
        None => DoctorLine::row(Tag::Ok, "credentialed VMs run without an execution role: no AWS keys inside the VM, and no runtime logs either".to_string()),
    }
}

/// An EC2 instance id: `i-` and 8 or 17 lowercase hex digits (the one value
/// from `state/infra.toml` that [`rows`] puts on an aws command line).
#[must_use]
pub fn is_instance_id(id: &str) -> bool {
    id.strip_prefix("i-").is_some_and(|h| matches!(h.len(), 8 | 17) && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}

/// Whether [`rows`] makes the proxy row's one call, and for which instance:
/// only with an operator identity (`identity`, as for every other doctor call)
/// and a recorded `proxy_instance_id` that is an instance id
/// ([`is_instance_id`]); `None`: no call.
#[must_use]
pub fn proxy_call(identity: bool, state: Option<&InfraState>) -> Option<&str> {
    identity.then_some(())?;
    state?.proxy_instance_id.as_deref().filter(|id| is_instance_id(id))
}

/// The proxy address the VMs are told (shared with `ai-env egress env`).
pub use crate::bridge::egress::effective_proxy_ip;

/// `aws ec2 <these>` through [`aws_cmd_as`] (region, pinned endpoint, no
/// pager, no OAuth token, the declared identity): the one operator call of the proxy row.
fn proxy_describe_args(id: &str) -> [&str; 3] {
    ["describe-instances", "--instance-ids", id]
}

/// The egress proxy (S5), from `state/infra.toml`'s `proxy_instance_id` (as
/// [`read_infra_state`] returned it) and one `ec2 describe-instances` of it
/// (`described`: `None` when not made — no operator identity, [`proxy_call`]).
/// No id recorded is `[-  ]` (an unreadable file: its error named), an id
/// that is not one `[!! ]` without a call. Running is `[ok ]` with its
/// private IP (`[!! ]` when that is not the address the VMs are told,
/// [`effective_proxy_ip`] of `configured_ip` = `[aws].proxy_private_ip`).
/// Stopped, stopping or pending is `[-  ]`, never `[NO ]`: `make
/// proxy-stop` when idle is the routine, and a vpc VM simply has no way out
/// until `make proxy-start`. Terminated, shutting-down or an unknown state
/// is `[!! ]`; a failed call is `[!! ] not checked`, no verdict.
#[must_use]
pub fn row_proxy(configured_ip: Option<&str>, state: &Result<Option<InfraState>, BridgeError>, described: Option<Result<&str, &str>>) -> DoctorLine {
    let s = match state {
        Ok(s) => s.as_ref(),
        Err(e) => return DoctorLine::row(Tag::Skip, format!("egress proxy not checked (state/infra.toml unreadable: {e})  <- {INFRA_STATUS_HINT}")),
    };
    let Some(id) = s.and_then(|s| s.proxy_instance_id.as_deref()).filter(|id| !id.trim().is_empty()) else {
        let why = if s.is_some() { "state/infra.toml has no proxy_instance_id" } else { "no state/infra.toml" };
        return DoctorLine::row(Tag::Skip, format!("egress proxy: none recorded ({why})  <- {INFRA_STATUS_HINT} after the S5 deploy"));
    };
    if !is_instance_id(id) {
        return DoctorLine::row(Tag::Warn, format!("egress proxy: proxy_instance_id {id:?} in state/infra.toml is not an instance id; not checked  <- {INFRA_STATUS_HINT}"));
    }
    let name = format!("egress proxy {id}");
    let json = match described {
        None => return DoctorLine::row(Tag::Skip, format!("{name} not checked ({NO_OPERATOR_ROW})")),
        Some(Err(e)) => return DoctorLine::row(Tag::Warn, format!("{name} not checked: {e}")),
        Some(Ok(json)) => json,
    };
    let doc = serde_json::from_str::<serde_json::Value>(json).ok();
    let instance = doc.as_ref().and_then(|v| v.get("Reservations")?.as_array()).into_iter().flatten().filter_map(|r| r.get("Instances")?.as_array()).flatten().find(|i| i.get("InstanceId").and_then(|x| x.as_str()) == Some(id));
    let Some(instance) = instance else {
        return DoctorLine::row(Tag::Warn, format!("{name} not checked: the describe-instances output does not list it"));
    };
    let st = instance.get("State").and_then(|s| s.get("Name")).and_then(|n| n.as_str()).unwrap_or("in no state");
    let ip = instance.get("PrivateIpAddress").and_then(|x| x.as_str());
    match st {
        "running" => match (ip, effective_proxy_ip(configured_ip, s)) {
            (Some(ip), (want, from)) if ip != want => DoctorLine::row(Tag::Warn, format!("{name} running at {ip}, but the VMs' proxy address is {want} ({from})  <- {INFRA_STATUS_HINT}")),
            (ip, _) => DoctorLine::row(Tag::Ok, format!("{name} running ({})", ip.unwrap_or("no private IP reported"))),
        },
        "stopped" | "stopping" => DoctorLine::row(Tag::Skip, format!("{name} {st}: make proxy-start (vpc VMs have no way out until it runs)")),
        "pending" => DoctorLine::row(Tag::Skip, format!("{name} pending (starting)")),
        other => DoctorLine::row(Tag::Warn, format!("{name} is {other}: vpc VMs have no way out  <- redeploy the stack's proxy, then {INFRA_STATUS_HINT}")),
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

// ---- S11 (B.4): the doctor matrix ---------------------------------------------------

/// The newest live VM row (not terminated, by `created`) whose `/health` named its shim, and the session on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveShim {
    pub vm: String,
    pub shim: String,
    pub session: Option<String>,
}

/// [`LiveShim`] of the VM rows `vms` and the session rows `sessions`: the session on the VM is the one, not closed,
/// whose current VM it is (the latest seen); a row id that is not a VM id or a session id is never named.
#[must_use]
pub fn live_shim(vms: &[VmRow], sessions: &[crate::bridge::registry::SessionRow]) -> Option<LiveShim> {
    let row = vms
        .iter()
        .filter(|r| r.status != RowStatus::Terminated && crate::bridge::vm::registry::is_vm_id(&r.id) && r.shim_version.as_deref().is_some_and(|s| !s.trim().is_empty()))
        .max_by(|a, b| a.created.cmp(&b.created))?;
    let session = sessions
        .iter()
        .filter(|s| s.status != "closed" && s.microvm_id.as_deref() == Some(row.id.as_str()) && crate::bridge::registry::is_uuid(&s.session_id))
        .max_by(|a, b| a.last_seen.cmp(&b.last_seen))
        .map(|s| s.session_id.clone());
    Some(LiveShim { vm: row.id.clone(), shim: row.shim_version.as_deref()?.trim().to_string(), session })
}

/// [`live_shim`] of the VM rows `vms` and the session registry, else, when that registry cannot be read, or one of
/// its rows cannot (B3's review: `registry::list` would skip it), nothing and a warning saying so: a VM would look
/// session-less, and [`row_shim_version`]'s fix would turn from the session's migrate into the VM's terminate.
fn live_shim_of(paths: &Paths, vms: &[VmRow]) -> (Option<LiveShim>, Option<DoctorLine>) {
    let unread = |why: String| (None, Some(DoctorLine::row(Tag::Warn, format!("live VM shim not checked: session registry unreadable: {why}"))));
    match crate::bridge::registry::list_reporting(paths) {
        Ok((sessions, skipped)) if skipped.is_empty() => (live_shim(vms, &sessions), None),
        Ok((_, skipped)) => unread(format!("{} row(s) cannot be read ({})", skipped.len(), skipped[0])),
        Err(e) => unread(e.to_string()),
    }
}

/// The version check's third leg (L7): `ai-env` (`mine`) against the image's shim (`state/infra.toml`'s
/// `shim_version`), compared for equality, the sibling's version named when it is the same (a newer image shim's
/// fix is the install, any other's the deploy); then a warning when the
/// newest live VM's shim is older than `mine` (an unparseable version is never judged).
#[must_use]
pub fn row_shim_version(mine: &str, sibling: Option<&str>, image_shim: Option<&str>, live: Option<&LiveShim>) -> Vec<DoctorLine> {
    let mut rows = Vec::new();
    match image_shim.map(str::trim).filter(|s| !s.is_empty()) {
        None => rows.push(DoctorLine::row(Tag::Skip, format!("image shim version not recorded (state/infra.toml)  <- {INFRA_STATUS_HINT}"))),
        Some(img) if img != mine => {
            // B3-R4 (I1): an image shim newer than this ai-env (a pull and a deploy with no install) is cleared by
            // installing; `make deploy` would stamp the checkout's version again. Otherwise (an unparseable one too)
            // the image is behind.
            let newer = matches!((semver(img), semver(mine)), (Some(theirs), Some(ours)) if theirs > ours);
            let fix = if newer { INSTALL_HINT.to_string() } else { format!("make deploy, then {INFRA_STATUS_HINT}") };
            rows.push(DoctorLine::row(Tag::No, format!("image shim {img} ≠ ai-env {mine}  <- {fix}")));
        }
        Some(img) => match sibling.map(str::trim) {
            Some(sib) if sib == mine => rows.push(DoctorLine::row(Tag::Ok, format!("ai-env {mine} = ai-env-claude {sib} = image shim {img}"))),
            // An unknown or other sibling version: `row_same_version` reports it.
            _ => rows.push(DoctorLine::row(Tag::Ok, format!("ai-env {mine} = image shim {img}"))),
        },
    }
    if let Some(l) = live {
        let older = is_semver(&l.shim) && matches!((semver(&l.shim), semver(mine)), (Some(theirs), Some(ours)) if theirs < ours);
        if older {
            let fix = match &l.session {
                Some(sid) => format!("ai-env session migrate {sid}"),
                None => format!("ai-env vm terminate {}", l.vm),
            };
            rows.push(DoctorLine::row(Tag::Warn, format!("{} runs shim {}, older than ai-env {mine}  <- {fix}", l.vm, l.shim)));
        }
    }
    rows
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageScan {
    /// Not run from an ai-env checkout: no `.git` in the working directory or above it, or no `image/MANIFEST` at
    /// the root of the checkout it is in.
    NotACheckout,
    /// `wrapper::image_findings` over `<checkout>/image`: each finding's rule, and the files scanned.
    Scanned { rules: Vec<String>, files: usize },
    Failed(String),
}

/// The root of the git checkout `dir` is in: the nearest of `dir` and its ancestors holding a `.git` entry, a
/// directory or a file (a worktree's, a submodule's). Found without running git: under `ai-env as ops -- ai-env
/// doctor` a git child would inherit the operator key (`without_credentials`).
fn checkout_root(dir: &Path) -> Option<&Path> {
    dir.ancestors().find(|d| std::fs::symlink_metadata(d.join(".git")).is_ok_and(|m| m.is_dir() || m.is_file()))
}

/// The image scan `make image-stage-scan` and `settings-sync` run (`wrapper::image_findings`), over the `image/` of
/// the checkout the working directory is in ([`checkout_root`]), and that checkout's root. No checkout, or one
/// without `image/MANIFEST`, is no ai-env checkout; any other refusal of `wrapper::image_dir_of` (a
/// `claude/settings.json` that is no regular file), an unknown working directory or a scan that cannot run fails
/// closed, as [`ImageScan::Failed`].
fn image_scan(paths: &Paths, cfg: &BridgeConfig) -> (ImageScan, Option<PathBuf>) {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => return (ImageScan::Failed(format!("no working directory: {e}")), None),
    };
    let Some(image) = checkout_root(&cwd).map(|top| top.join("image")).filter(|image| image.join("MANIFEST").is_file()) else {
        return (ImageScan::NotACheckout, None);
    };
    let dir = match crate::bridge::wrapper::image_dir_of(Some(&image)) {
        Ok(dir) => dir,
        Err(e) => return (ImageScan::Failed(e.to_string()), None),
    };
    let root = dir.parent().map(Path::to_path_buf);
    let scan = match crate::bridge::wrapper::image_findings(paths, cfg, &dir) {
        Ok((findings, files)) => ImageScan::Scanned { rules: findings.into_iter().map(|f| f.rule).collect(), files },
        Err(e) => ImageScan::Failed(e.to_string()),
    };
    (scan, root)
}

/// `<root>/target/image/image.json`'s `sha256` (`make image-zip`'s record of the zip that passed the scan): `None`
/// when the file is absent, not a regular file, oversized, or holds no 64-hex `sha256`. Opened once (never through a
/// symlink, never blocking on a FIFO), the open file checked, and read with a bound: a file swapped after a check
/// is never read.
fn staged_zip_sha256(root: &Path) -> Option<String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    const MAX: u64 = 64 * 1024;
    let path = root.join("target").join("image").join("image.json");
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(&path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX {
        return None;
    }
    let mut text = String::new();
    file.take(MAX + 1).read_to_string(&mut text).ok()?;
    if text.len() as u64 > MAX {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let sha = v.get("sha256")?.as_str()?;
    (sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit())).then(|| sha.to_ascii_lowercase())
}

/// The first 12 hex digits of a sha256 as a row shows it (`?` for anything that is not hex).
fn short_sha(s: &str) -> String {
    match s.get(..12) {
        Some(head) if s.bytes().all(|b| b.is_ascii_hexdigit()) => head.to_ascii_lowercase(),
        _ => "?".to_string(),
    }
}

/// The checkout's `image/` scan (rules only, never a value or a file's content), then a warning when the deployed
/// zip (`state/infra.toml`'s `zip_sha256`) is not the one `target/image/image.json` records.
#[must_use]
pub fn row_image_scan(scan: &ImageScan, deployed_zip: Option<&str>, staged_zip: Option<&str>) -> Vec<DoctorLine> {
    let mut rows = vec![match scan {
        ImageScan::NotACheckout => DoctorLine::row(Tag::Skip, "image/ not scanned: not in an ai-env checkout"),
        ImageScan::Failed(e) => DoctorLine::row(Tag::Warn, format!("image/ scan failed: {e}")),
        ImageScan::Scanned { rules, files } if rules.is_empty() => DoctorLine::row(Tag::Ok, format!("image/ scan: clean ({files} files)")),
        ImageScan::Scanned { rules, .. } => {
            let mut named: Vec<&str> = rules.iter().map(String::as_str).collect();
            named.sort_unstable();
            named.dedup();
            DoctorLine::row(Tag::No, format!("image/ has {} finding(s): {}  <- fix them, then make image-zip and make deploy", rules.len(), named.join(", ")))
        }
    }];
    let known = |z: Option<&str>| z.map(str::trim).filter(|z| !z.is_empty()).map(str::to_string);
    if let (Some(deployed), Some(staged)) = (known(deployed_zip), known(staged_zip)) {
        if !deployed.eq_ignore_ascii_case(&staged) {
            rows.push(DoctorLine::row(
                Tag::Warn,
                format!("the deployed image zip {} is not target/image/image.json's {} (the zip that passed the scan)  <- make image-zip, then make deploy", short_sha(&deployed), short_sha(&staged)),
            ));
        }
    }
    rows
}

/// `aws budgets describe-budget` of the stack's budget, as the declared operator.
#[must_use]
pub fn budget_args(account: &str, name: &str) -> Vec<String> {
    ["budgets", "describe-budget", "--account-id", account, "--budget-name", name, "--region", REGION, "--output", "json"].iter().map(|s| (*s).to_string()).collect()
}

/// The limit, units and spend of a describe-budget answer (§B4.4), and whether the spend reached the limit; `None`
/// when a field is missing or is not the shape a budget's amounts and units have, an amount is no number, or the
/// spend is in another unit than the limit (the row names one).
fn budget_summary(json: &str) -> Option<BudgetSummary> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let b = v.get("Budget")?;
    let amount = |o: &serde_json::Value| -> Option<(String, String)> {
        let a = o.get("Amount")?.as_str()?;
        let u = o.get("Unit")?.as_str()?;
        let ok = !a.is_empty() && a.len() <= 32 && a.bytes().all(|c| c.is_ascii_digit() || c == b'.') && !u.is_empty() && u.len() <= 16 && u.bytes().all(|c| c.is_ascii_alphanumeric());
        ok.then(|| (a.to_string(), u.to_string()))
    };
    let (limit, unit) = amount(b.get("BudgetLimit")?)?;
    let time = b.get("TimeUnit")?.as_str().filter(|t| !t.is_empty() && t.len() <= 16 && t.bytes().all(|c| c.is_ascii_alphabetic()))?.to_ascii_lowercase();
    let (spent, spent_unit) = amount(b.get("CalculatedSpend")?.get("ActualSpend")?)?;
    // Both are digits and dots already; one that is still no number (`1.2.3`, `.`) is no verdict: `exists`.
    let reached = spent.parse::<f64>().ok()? >= limit.parse::<f64>().ok()?;
    (spent_unit == unit).then_some(BudgetSummary { limit, unit, time, spent, reached })
}

/// What `budget_summary` read of `describe-budget`'s answer: the limit, its unit and time unit (lower case), the
/// actual spend, and whether that spend reached the limit (B-DOC-1).
struct BudgetSummary {
    limit: String,
    unit: String,
    time: String,
    spent: String,
    reached: bool,
}

/// The budget row (L8). `name`: `[aws].budget_name`, else `state/infra.toml`'s. `answer`: `None` with no verified
/// operator. An error is shown by its first line with every 12-digit run as `<acct>` (an error names ARNs).
#[must_use]
pub fn row_budget(name: Option<&str>, answer: Option<Result<&str, &str>>) -> DoctorLine {
    let Some(name) = name.map(str::trim).filter(|n| !n.is_empty()) else {
        return DoctorLine::row(Tag::Skip, format!("budget not checked: no budget name in bridge.toml [aws] or state/infra.toml  <- {INFRA_STATUS_HINT}"));
    };
    match answer {
        None => DoctorLine::row(Tag::Skip, format!("budget {name} not checked ({NO_OPERATOR_ROW})")),
        Some(Ok(json)) => match budget_summary(json) {
            // A spend at or over its limit is no `[ok ]` (B-DOC-1).
            Some(BudgetSummary { limit, unit, time, spent, reached: true }) => DoctorLine::row(Tag::Warn, format!("budget {name}: {spent} spent of {limit} {unit} {time}  <- ai-env cost --by day")),
            Some(BudgetSummary { limit, unit, time, spent, reached: false }) => DoctorLine::row(Tag::Ok, format!("budget {name}: {limit} {unit} {time}, {spent} spent")),
            None => DoctorLine::row(Tag::Ok, format!("budget {name} exists")),
        },
        Some(Err(e)) if e.contains("NotFoundException") => DoctorLine::row(Tag::No, format!("budget {name} missing  <- make deploy")),
        Some(Err(e)) if e.contains("AccessDenied") => DoctorLine::row(Tag::Warn, format!("budget {name} not checked: AccessDenied  <- make deploy (ai-env-ops gains budgets:ViewBudget, S11 L8)")),
        Some(Err(e)) => DoctorLine::row(Tag::Warn, format!("budget {name} not checked: {}", crate::bridge::gates::mask_account_ids(e.lines().next().unwrap_or("").trim()))),
    }
}

/// The listing `row_base_image` reads (doctor.rs:943): `None` when it shows no AVAILABLE version above the pin.
#[must_use]
pub fn row_base_image_newer(listing: Option<Result<&str, &str>>) -> Option<DoctorLine> {
    use crate::bridge::infra::{text_of, version_items};
    let json = listing?.ok()?;
    let pin = image_version_key(BASE_IMAGE_VERSION)?;
    let mut newer: Vec<((u64, u64), String)> = version_items(json)
        .ok()?
        .iter()
        .filter(|i| text_of(i, "status").as_deref() == Some("AVAILABLE"))
        .filter_map(|i| {
            let v = text_of(i, "imageVersion")?;
            let key = image_version_key(&v)?;
            (key > pin).then_some((key, v))
        })
        .collect();
    newer.sort();
    newer.dedup_by_key(|(k, _)| *k);
    if newer.is_empty() {
        return None;
    }
    let list = newer.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>().join(", ");
    Some(DoctorLine::row(Tag::Warn, format!("newer {BASE_IMAGE_NAME} version(s) {list} AVAILABLE (pinned {BASE_IMAGE_VERSION})  <- infra/image-config.json")))
}

/// One row per root (`BridgeConfig::roots`) that is not a directory.
#[must_use]
pub fn rows_roots_exist(cfg: &BridgeConfig, is_dir: &dyn Fn(&Path) -> bool) -> Vec<DoctorLine> {
    cfg.roots()
        .into_iter()
        .filter(|r| !is_dir(r))
        .map(|r| DoctorLine::row(Tag::Warn, format!("workspace root {} does not exist  <- create it, or remove it from bridge.toml", r.display())))
        .collect()
}

/// `[aws].image_version` pinned (not `active`) to a version that is not the recorded active one, compared as
/// [`new_vm_version`] normalises it (`N` is `N.0`); with no recorded active version, no row.
#[must_use]
pub fn row_image_version_pin(cfg: &BridgeConfig, state: Option<&InfraState>) -> Option<DoctorLine> {
    let want = cfg.aws.image_version.trim();
    if want.is_empty() || want == "active" {
        return None;
    }
    let active = state?.latest_active_image_version.as_deref().map(str::trim).filter(|v| !v.is_empty())?;
    let pinned = new_vm_version(cfg, state)?;
    let same = match (image_version_key(&pinned), image_version_key(active)) {
        (Some(p), Some(a)) => p == a,
        _ => pinned == active,
    };
    (!same).then(|| DoctorLine::row(Tag::Warn, format!("[aws].image_version = {want} is pinned, but the active version is {active}: new VMs run {want}  <- image_version = \"active\" in bridge.toml")))
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
    // S8 operators: the identity `ai-env as` declared, from the marker alone (doctor never unseals and never
    // resolves an operator); verified by one sts call as that identity. Without one, a plain sts call only warns
    // when the shell's own credentials are the root's.
    let declared = declared();
    let checked = match &declared {
        Some(Ok(op)) => Some(verify_operator(op)),
        _ => None,
    };
    let (row, auth_unavailable) = row_operator_identity(declared.as_ref(), checked.as_ref());
    lines.push(row);
    if declared.is_none() {
        let sts = aws_present.then(|| run_capture_cmd(ambient_sts_cmd(), None, Duration::from_secs(15)));
        lines.push(row_ambient_identity(sts.as_ref().map(|r| r.as_deref().map_err(String::as_str))));
    }
    lines.push(row_region(env_region_warning().as_deref()));
    // The identity the AWS rows below run as: a declared one that answered as it must.
    let op = match (&declared, &checked) {
        (Some(Ok(op)), Some(Ok(_))) => Some(op),
        _ => None,
    };
    let call = |args: &[&str]| op.map(|op| run_capture_cmd(program_as(args, op), None, Duration::from_secs(15)));
    let paths = Paths::resolve();
    if let Ok(paths) = &paths {
        lines.push(ops_key(&paths.ops_env()));
        let state = read_infra_state(paths);
        let recorded = state.as_ref().is_ok_and(|s| s.as_ref().is_some_and(|s| s.deployer_user_arn.is_some() || s.deployer_user_name.is_some()));
        let keys = if recorded { call(&deployer_keys_args()) } else { None };
        lines.push(row_deployer(&state, keys.as_ref().map(|r| r.as_deref().map_err(String::as_str))));
    }
    let summary = call(&account_summary_args());
    lines.push(row_root_access_keys(summary.as_ref().map(|r| r.as_deref().map_err(String::as_str))));
    let base_id = format!("arn:aws:lambda:{REGION}:aws:microvm-image:{BASE_IMAGE_NAME}");
    let base = call(&base_image_args(&base_id));
    lines.push(row_base_image(base.as_ref().map(|r| r.as_deref().map_err(String::as_str))));
    // S11 (B.4): the same listing, for AVAILABLE versions above the pin.
    lines.extend(row_base_image_newer(base.as_ref().map(|r| r.as_deref().map_err(String::as_str))));

    let loaded = paths.as_ref().ok().map(BridgeConfig::load);
    // The operator's identity, like every aws call here (doctor never unseals
    // the runtime key); only for a parsed `[vm]` the quota could cover.
    let parsed = matches!(loaded, Some(Ok(Some(_))));
    let quota = if parsed { call(&quota_args()) } else { None };
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
    // S11 (L8): the stack's budget, read as the verified operator (its account is in the call, never in a row).
    let budget_name = cfg.aws.budget_name.clone().filter(|n| !n.trim().is_empty()).or_else(|| paths.as_ref().ok().and_then(|p| read_infra_state(p).ok().flatten()).and_then(|s| s.budget_name));
    let account = checked.as_ref().and_then(|c| c.as_ref().ok()).map(|v| v.account.clone());
    let budget = match (budget_name.as_deref().map(str::trim), account.as_deref()) {
        (Some(name), Some(acct)) if !name.is_empty() => {
            let args = budget_args(acct, name);
            call(&args.iter().map(String::as_str).collect::<Vec<_>>())
        }
        _ => None,
    };
    lines.push(row_budget(budget_name.as_deref(), budget.as_ref().map(|r| r.as_deref().map_err(String::as_str))));
    let key = cfg.creds.key.as_str();
    lines.push(row_keystore_key(store.key_exists(key), key));
    let (infra_state, live) = match &paths {
        Ok(paths) => {
            lines.push(runtime_credentials(&paths.aws_env()));
            // S7: the setup-token and combined.env, read without a Touch ID.
            lines.extend(crate::bridge::setup_token::doctor_rows(paths, unix_now()));
            let state = read_infra_state(paths);
            lines.push(row_infra_state(&state, &paths.infra_state()));
            // S11 (B.4): the checkout's image/ scan, then the deployed zip against the one that passed it.
            let (scan, checkout) = image_scan(paths, &cfg);
            let staged = checkout.as_deref().and_then(staged_zip_sha256);
            let deployed = state.as_ref().ok().and_then(Option::as_ref).and_then(|s| s.zip_sha256.as_deref());
            lines.extend(row_image_scan(&scan, deployed, staged.as_deref()));
            let recorded = state.as_ref().ok().and_then(Option::as_ref);
            let loaded = loaded.as_ref().expect("loaded with the paths");
            // The newest dns-path row the credential gate will read (a row of the transcript knob never counts): its
            // verdict and when it was recorded.
            let dns_path = crate::bridge::egress::newest_dns_path_row(paths);
            // The recorded passing checks the credential gate rests on (S7): read once, for the gate row.
            let verified = EgressVerified::load(paths);
            // The VM rows: their registry row below, and the guest's memory beside [vm]'s (S10 F8).
            let vms = list_rows(paths);
            lines.extend(rows_bridge_settings(loaded, vms.as_deref().unwrap_or_default(), quota.as_ref().map(|r| r.as_deref().map_err(String::as_str)), &state, &dns_path, &verified, unix_now()));
            // S5: the egress row reads only the state file; the proxy row
            // adds one operator call, for a recorded proxy and an identity.
            let described = op.and_then(|op| proxy_call(true, recorded).map(|id| aws_cmd_as("ec2", &proxy_describe_args(id), op).and_then(|cmd| run_capture_cmd(cmd, None, Duration::from_secs(15)))));
            lines.push(row_proxy(cfg.aws.proxy_private_ip.as_deref(), &state, described.as_ref().map(|r| r.as_deref().map_err(String::as_str))));
            lines.push(match &vms {
                Ok(vms) => row_vm_registry(vms, unix_now()),
                Err(e) => DoctorLine::row(Tag::Warn, format!("vm registry unreadable: {e}")),
            });
            let (tw, sp) = (cfg.review.tripwires_path(paths), cfg.review.settings_policy_path(paths));
            lines.push(row_review_files(&tw, tw.is_file(), &sp, sp.is_file()));
            lines.extend(rows_s8_loaded(paths, loaded));
            lines.extend(rows_roots_exist(&cfg, &|p: &Path| p.is_dir()));
            lines.extend(row_pre_push_hooks(paths));
            lines.push(row_workspace_cap(vms.as_deref().unwrap_or_default(), &state, &cfg));
            lines.extend(row_image_version_pin(&cfg, recorded));
            // The newest live VM's shim and the session on it, for the version row below.
            let live = live_shim_of(paths, vms.as_deref().unwrap_or_default());
            (state.ok().flatten(), live)
        }
        Err(_) => (None, (None, None)),
    };

    let image_claude = infra_state.as_ref().and_then(|s| s.claude_version.as_deref());
    // S11 (T6): automatic admission only with `[claude].auto_admit` on and the wrapper's mode remote.
    let auto = cfg.claude.auto_admit && matches!(cfg.wrapper.wrapper_mode(), Ok(WrapperMode::Remote));
    let (cursor, bundled_out) = cursor_bundle_rows(&home().join(".cursor").join("extensions"), image_claude, &|bin: &Path| run_capture(&bin.to_string_lossy(), &["--version"], t).ok(), auto);
    lines.extend(cursor);
    // S11 (C.4): the drift rows, after the Cursor rows: per running window's version its env and flag rows, then
    // the view rows.
    lines.extend(crate::bridge::drift::doctor_rows(paths.as_ref().ok(), &home().join(".cursor").join("extensions"), &cfg.wrapper));
    let path_claude = find_in_path("claude", &effective_path());
    let path_out = path_claude.as_ref().and_then(|p| run_capture(&p.to_string_lossy(), &["--version"], t).ok());
    lines.push(row_path_claude(path_claude.as_deref().zip(path_out.as_deref()), bundled_out.as_deref()));
    // S7: this Mac's own claude login, the bundled CLI before PATH's.
    let ext_dir = home().join(".cursor").join("extensions");
    let auth_claude = pick_bundle(&installed_extension_names(&ext_dir)).map(|(_, dir)| ext_dir.join(dir).join("resources").join("native-binary").join("claude")).filter(|p| p.is_file()).or(path_claude);
    let auth = auth_claude.as_ref().map(|p| claude_auth_status(p));
    lines.push(row_claude_auth(auth_claude.as_deref(), auth));

    let sibling = find_sibling("ai-env-claude");
    lines.push(row_sibling(&sibling));
    let sib_out = match &sibling {
        Sibling::Next(p) | Sibling::PathOnly(p) => run_capture(&p.to_string_lossy(), &["--version"], t).ok(),
        Sibling::Missing => None,
    };
    lines.push(row_same_version(sib_out.as_deref(), env!("CARGO_PKG_VERSION")));
    // S11 (L7): the third leg, the image's shim and the newest live VM's.
    let sib_version = sib_out.as_deref().and_then(version_token);
    let (live, live_unread) = live;
    lines.extend(row_shim_version(env!("CARGO_PKG_VERSION"), sib_version.as_deref(), infra_state.as_ref().and_then(|s| s.shim_version.as_deref()), live.as_ref()));
    lines.extend(live_unread);

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

    /// S8 operators: the IAM calls of the deployer and root-keys rows, and the
    /// base image's, pin the region like every aws call (IAM is global).
    #[test]
    fn the_doctor_iam_calls_pin_the_region() {
        assert_eq!(deployer_keys_args(), ["iam", "list-access-keys", "--user-name", "ai-env-deployer", "--region", "eu-central-1", "--output", "json"]);
        assert_eq!(account_summary_args(), ["iam", "get-account-summary", "--region", "eu-central-1", "--output", "json"]);
        let base = base_image_args("arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1");
        assert!(base.windows(2).any(|w| w == ["--region", "eu-central-1"]) && base[..2] == ["lambda-microvms", "list-managed-microvm-image-versions"], "{base:?}");
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
        assert_eq!(t, "microvm memory quota L-CD1C0CC4 400 GB in eu-central-1 covers [vm] max_concurrent 3 × 2048 MiB baseline = 6 GB");
        assert_eq!(text(&row_microvm_quota(Some(Ok(&quota_json("6.0"))), 3, 2048)).0, Tag::Ok, "exactly enough is enough");
        let (tag, t) = text(&row_microvm_quota(Some(Ok(&quota_json("4"))), 3, 2048));
        assert_eq!(tag, Tag::Warn, "{t}");
        assert!(t.starts_with("microvm memory quota L-CD1C0CC4 4 GB in eu-central-1 < [vm] max_concurrent 3 × 2048 MiB baseline = 6 GB  <- lower [vm].max_concurrent"), "{t}");
        assert_eq!(t.matches("<- ").count(), 1, "one hint: {t}");
        let (tag, t) = text(&row_microvm_quota(Some(Ok(&quota_json("5.5"))), 11, 512));
        assert!(tag == Tag::Ok && t.contains("5.5 GB") && t.ends_with("= 5.5 GB"), "fractions on both sides: {t}");
        assert_eq!(text(&row_microvm_quota(Some(Ok(&quota_json("5.5"))), 3, 2048)).0, Tag::Warn);
    }

    #[test]
    fn row_microvm_quota_without_a_verdict() {
        let (tag, t) = text(&row_microvm_quota(None, 3, 2048));
        assert_eq!(tag, Tag::Skip);
        assert_eq!(t, "microvm memory quota L-CD1C0CC4 not checked (no operator identity: ai-env as ops -- ai-env doctor)");
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
        let (tag, t) = text(&row_vm_config(&VmCfg::default(), &[]));
        assert_eq!(tag, Tag::Ok);
        assert_eq!(t, format!("[vm] max_concurrent 3, memory 2048 MiB baseline ({MEMORY_BASELINE}), max duration 28800 s, idle 300 s, suspended 28800 s (the max duration)"));
        let set = VmCfg { max_concurrent: 1, memory_mib: 4096, max_duration_s: 900, max_idle_s: 600, suspended_s: Some(900), ..VmCfg::default() };
        assert_eq!(text(&row_vm_config(&set, &[])), (Tag::Ok, format!("[vm] max_concurrent 1, memory 4096 MiB baseline ({MEMORY_BASELINE}), max duration 900 s, idle 600 s, suspended 900 s")));
        let below = VmCfg { suspended_s: Some(600), ..set.clone() };
        assert!(text(&row_vm_config(&below, &[])).1.ends_with("idle 600 s, suspended 600 s"), "{:?}", text(&row_vm_config(&below, &[])));
        // `vm run` sends min([vm].suspended_s, max duration) (plan D8): never the larger value.
        let (tag, t) = text(&row_vm_config(&VmCfg { suspended_s: Some(28_800), ..set }, &[]));
        assert_eq!(tag, Tag::Ok, "valid: a longer --max-duration uses it");
        assert_eq!(t, format!("[vm] max_concurrent 1, memory 4096 MiB baseline ({MEMORY_BASELINE}), max duration 900 s, idle 600 s, suspended 900 s ([vm].suspended_s 28800 capped at the max duration)"));
        for (bad, key) in [
            (VmCfg { max_concurrent: 0, ..VmCfg::default() }, "[vm].max_concurrent: must be at least 1"),
            (VmCfg { max_idle_s: 60, ..VmCfg::default() }, "[vm].max_idle_s: must be 300..=28800"),
            (VmCfg { max_duration_s: 28_801, ..VmCfg::default() }, "[vm].max_duration_s: must be 1..=28800"),
            (VmCfg { suspended_s: Some(0), ..VmCfg::default() }, "[vm].suspended_s: must be 1..=28800"),
            (VmCfg { memory_mib: 0, ..VmCfg::default() }, "[vm].memory_mib: must be positive"),
        ] {
            let row = row_vm_config(&bad, &[]);
            let (tag, t) = text(&row);
            assert_eq!(tag, Tag::No, "{t}");
            assert!(t.starts_with(&format!("config: {key}")) && t.ends_with("  <- fix [vm] in bridge.toml (ai-env vm and lab refuse it)"), "{t}");
            assert_eq!(crate::commands::doctor_exit_code(&[row], false), 1);
        }
    }

    /// S10 F8: the memory rows say what the platform bills (AWS's Lambda
    /// pricing): `[vm].memory_mib` is the image's minimum, the baseline billed
    /// while a VM runs, which bursts to 4× and bills the extra only while
    /// used; the quota row sums baselines. Once a VM's `/health` recorded the
    /// guest's `MemTotal` (`mem_total_mib`), the `[vm]` row names the newest
    /// such row's beside it, whatever its status; a row without one, a pending
    /// row and a bad `[vm]` show none.
    #[test]
    fn the_memory_rows_name_the_baseline_and_the_guests_memory() {
        assert_eq!(MEMORY_BASELINE, "the image's minimum; bursts to 4×, billed while used");
        let (tag, t) = text(&row_vm_config(&VmCfg::default(), &[]));
        assert_eq!((tag, t.as_str()), (Tag::Ok, "[vm] max_concurrent 3, memory 2048 MiB baseline (the image's minimum; bursts to 4×, billed while used), max duration 28800 s, idle 300 s, suspended 28800 s (the max duration)"));
        let (_, t) = text(&row_microvm_quota(Some(Ok(&quota_json("400.0"))), 3, 2048));
        assert!(t.ends_with(" covers [vm] max_concurrent 3 × 2048 MiB baseline = 6 GB"), "{t}");
        let row = |id: &str, status: RowStatus, created: &str, version: &str, mem: Option<u32>| VmRow { image_version: version.into(), mem_total_mib: mem, ..vm(id, status, created) };
        let vms = [
            row("microvm-11", RowStatus::Running, "2026-10-19T08:00:00.000Z", "11.0", Some(7_900)),
            row("microvm-12", RowStatus::Terminated, "2026-10-20T08:00:00.000Z", "12.0", Some(7_987)),
            row("microvm-12b", RowStatus::Running, "2026-10-20T09:00:00.000Z", "12.0", None),
            row("", RowStatus::Pending, "2026-10-20T10:00:00.000Z", "12.0", None),
        ];
        let (tag, t) = text(&row_vm_config(&VmCfg::default(), &vms));
        assert_eq!(tag, Tag::Ok);
        assert_eq!(t, "[vm] max_concurrent 3, memory 2048 MiB baseline (the image's minimum; bursts to 4×, billed while used; the guest's MemTotal 7987 MiB on microvm-12, image 12.0), max duration 28800 s, idle 300 s, suspended 28800 s (the max duration)");
        assert!(!text(&row_vm_config(&VmCfg::default(), &vms[2..])).1.contains("MemTotal"), "no row named one");
        let bad = text(&row_vm_config(&VmCfg { memory_mib: 0, ..VmCfg::default() }, &vms));
        assert!(bad.0 == Tag::No && !bad.1.contains("MemTotal"), "{bad:?}");
    }

    /// S7: only `loggedIn` is read; an answer without it, or a failed run,
    /// is a warning; no claude found is skipped.
    #[test]
    fn the_claude_auth_row_reads_logged_in_only() {
        let p = Path::new("/Applications/claude");
        assert_eq!(logged_in(r#"{"loggedIn":true,"email":"someone@example.com","orgId":"o"}"#), Some(true));
        assert_eq!(logged_in("{}"), None);
        assert_eq!(logged_in("not json"), None);
        let (tag, t) = text(&row_claude_auth(Some(p), Some(Ok(r#"{"loggedIn":true,"email":"someone@example.com"}"#.into()))));
        assert!(tag == Tag::Ok && !t.contains("example.com"), "{t}");
        assert_eq!(text(&row_claude_auth(Some(p), Some(Ok(r#"{"loggedIn":false}"#.into())))).0, Tag::Skip);
        assert_eq!(text(&row_claude_auth(Some(p), Some(Ok("{}".into())))).0, Tag::Warn);
        assert_eq!(text(&row_claude_auth(Some(p), Some(Err("timed out".into())))).0, Tag::Warn);
        assert_eq!(text(&row_claude_auth(None, None)).0, Tag::Skip);
    }

    /// S7 §7: the auth row waits the planned 10 s, not the doctor's 5 s
    /// version-probe budget: a CLI that answers after 6 s is still read as
    /// logged in, not as a failed run.
    #[cfg(unix)]
    #[test]
    fn the_claude_auth_status_waits_ten_seconds() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join("claude");
        std::fs::write(&claude, "#!/bin/sh\n[ \"$*\" = 'auth status --json' ] || exit 64\nsleep 6\necho '{\"loggedIn\":true}'\n").unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (tag, t) = text(&row_claude_auth(Some(&claude), Some(claude_auth_status(&claude))));
        assert!(tag == Tag::Ok && t.starts_with("claude auth: logged in"), "{t}");
    }

    /// An absent or unparseable bridge.toml never has its defaults reported
    /// as the configuration (and the quota answer is not used).
    #[test]
    fn rows_bridge_settings_only_for_a_parsed_bridge_toml() {
        let quota = quota_json("4");
        let active = ok(active_state());
        let newest: Result<Option<(String, String)>, String> = Ok(Some(("no-dns".to_string(), "2026-10-02T10:00:00Z".to_string())));
        let none = Ok(EgressVerified::default());
        let now = unix_now();
        let settings = |loaded: &Result<Option<BridgeConfig>, BridgeError>, q: Option<Result<&str, &str>>, st: &Result<Option<InfraState>, BridgeError>, dp: &Result<Option<(String, String)>, String>| {
            rows_bridge_settings(loaded, &[], q, st, dp, &none, now).iter().map(text).collect::<Vec<(Tag, String)>>()
        };
        for (loaded, why) in [(Ok(None), "no bridge.toml"), (Err(BridgeError::Config("[vm].max_concurrent: invalid type".into())), "bridge.toml unparseable")] {
            let rows = rows_bridge_settings(&loaded, &[], Some(Ok(&quota)), &active, &newest, &none, now);
            let got: Vec<(Tag, String)> = rows.iter().map(text).collect();
            assert_eq!(got, [(Tag::Skip, format!("execution role, [vm], microvm memory quota, egress connector, DNS acceptance, [creds] and the credential gate not checked ({why})"))]);
            assert_eq!(crate::commands::doctor_exit_code(&rows, false), 0, "the default [egress].require never fails a doctor without bridge.toml");
        }
        let cfg = BridgeConfig { vm: VmCfg { max_concurrent: 3, memory_mib: 2048, ..VmCfg::default() }, ..BridgeConfig::default() };
        let got = settings(&Ok(Some(cfg.clone())), Some(Ok(&quota)), &active, &newest);
        assert_eq!(got.len(), 8, "{got:?}");
        assert_eq!(got[0], text(&row_execution_role(&cfg.aws)));
        assert_eq!(got[1], text(&row_vm_config(&cfg.vm, &[])));
        // S10 F8: the VM rows reach the [vm] row (the guest's memory beside the baseline).
        let guest = [VmRow { mem_total_mib: Some(7_987), image_version: "12.0".into(), ..vm("microvm-12", RowStatus::Running, "2026-10-20T08:00:00.000Z") }];
        let with = rows_bridge_settings(&Ok(Some(cfg.clone())), &guest, None, &active, &newest, &none, now);
        assert_eq!(text(&with[1]), text(&row_vm_config(&cfg.vm, &guest)));
        assert!(text(&with[1]).1.contains("; the guest's MemTotal 7987 MiB on microvm-12, image 12.0), max duration"), "{:?}", text(&with[1]));
        assert!(got[2].0 == Tag::Warn && got[2].1.contains(" 4 GB in eu-central-1 < [vm] max_concurrent 3 × 2048 MiB baseline = 6 GB"), "{got:?}");
        assert_eq!(got[3], text(&row_egress(&cfg.egress, &cfg.aws, &active)));
        assert_eq!(got[3].0, Tag::No, "the defaults: require on, no connector: {got:?}");
        assert_eq!(got[4], text(&row_dns_acceptance(&cfg.egress, &newest)));
        assert_eq!(got[4].0, Tag::Ok, "{got:?}");
        // S7's three rows, in order: [creds], the gate's offline preconditions, the execution-role decision.
        assert_eq!(got[5], text(&row_creds_settings(&cfg.creds)));
        assert_eq!(got[5].0, Tag::Ok, "the defaults are a valid [creds]: {got:?}");
        assert!(got[6].0 == Tag::Skip && got[6].1.contains("no active image version recorded"), "without a recorded version there is nothing to judge: {got:?}");
        assert_eq!(got[7], text(&row_credential_vm_role(&cfg.aws)));
        let got = settings(&Ok(Some(cfg.clone())), None, &Ok(None), &Ok(None));
        assert_eq!(got[2], (Tag::Skip, "microvm memory quota L-CD1C0CC4 not checked (no operator identity: ai-env as ops -- ai-env doctor)".to_string()));
        assert_eq!(got[4].0, Tag::Skip, "no dns-path row: {got:?}");
        assert!(got[6].0 == Tag::Skip && got[6].1.contains("no state recorded"), "without state/infra.toml the gate row is skipped: {got:?}");
        // A configured connector with an ACTIVE recorded state: the row is [ok ].
        let cfg = BridgeConfig { aws: AwsCfg { egress_connector_arn: Some(CONNECTOR.into()), proxy_private_ip: Some("10.42.0.10".into()), ..AwsCfg::default() }, ..cfg };
        let versioned = ok(InfraState { latest_active_image_version: Some("5.0".into()), ..active_state() });
        let got = settings(&Ok(Some(cfg.clone())), None, &versioned, &newest);
        assert_eq!(got[3].0, Tag::Ok, "{got:?}");
        // The version new VMs run, with no passing check recorded for it: the row names the condition.
        assert!(got[6].0 == Tag::Warn && got[6].1.contains("[no_record]") && got[6].1.contains("image version 5.0"), "{got:?}");
        // The same evidence without a connector: the first condition, before any record is looked for.
        let no_conn = BridgeConfig { aws: AwsCfg { egress_connector_arn: None, ..cfg.aws.clone() }, ..cfg.clone() };
        let got = settings(&Ok(Some(no_conn)), None, &versioned, &newest);
        assert!(got[6].0 == Tag::Warn && got[6].1.contains("[connector_unset]"), "{got:?}");
        // Unreadable records refuse every credential, and the row says so without naming a condition.
        let unreadable: Result<EgressVerified, BridgeError> = Err(BridgeError::Config("state/egress-verified.toml: bad".into()));
        let row = text(&row_credential_gate(&cfg, &versioned, &unreadable, &Ok(Some("no-dns".into())), now));
        assert!(row.0 == Tag::Warn && row.1.contains("cannot be read") && row.1.contains("ai-env egress check"), "{row:?}");
    }

    /// The credential-gate row when everything offline is in place, and the
    /// execution-role row's two shapes (S7).
    #[test]
    fn the_credential_rows_report_what_is_in_place() {
        use crate::bridge::egress::{ConnectorFacts, VerifiedRecord};
        let now = unix_now();
        let cfg = BridgeConfig { aws: AwsCfg { egress_connector_arn: Some(CONNECTOR.into()), ..AwsCfg::default() }, ..BridgeConfig::default() };
        let state = ok(InfraState { latest_active_image_version: Some("5.0".into()), image_arn: "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent".into(), ..active_state() });
        let mut verified = EgressVerified::default();
        verified.record(
            VerifiedRecord {
                image_arn: "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent".into(),
                image_version: "5.0".into(),
                connector: CONNECTOR.into(),
                at: crate::wire::time::rfc3339_utc(now),
                dns: "no-dns".into(),
                dns_rule: crate::bridge::egress::DNS_RULE,
                egress_rule: crate::bridge::egress::EGRESS_RULE,
                connector_facts: ConnectorFacts { id: "nc-1".into(), network_protocol: "IPv4".into(), subnet_ids: vec!["subnet-1".into()], security_group_ids: vec!["sg-1".into()], ..ConnectorFacts::default() },
                image_created_at: Some(1_790_000_000),
                ..VerifiedRecord::default()
            },
            0,
        );
        let row = text(&row_credential_gate(&cfg, &state, &Ok(verified.clone()), &Ok(Some("no-dns".into())), now));
        assert!(row.0 == Tag::Ok && row.1.contains("in place for image version 5.0") && row.1.contains("checked again live"), "{row:?}");
        // A pinned [aws].image_version is the version a new VM runs, whatever the latest active one is: `4` is 4.0,
        // which has no record here, so the gate would refuse it — and the row says so.
        let pinned = BridgeConfig { aws: AwsCfg { image_version: "4".into(), ..cfg.aws.clone() }, ..cfg.clone() };
        let row = text(&row_credential_gate(&pinned, &state, &Ok(verified.clone()), &Ok(Some("no-dns".into())), now));
        assert!(row.0 == Tag::Warn && row.1.contains("image version 4.0") && row.1.contains("[no_record]"), "{row:?}");
        let exact = BridgeConfig { aws: AwsCfg { image_version: "5.0".into(), ..cfg.aws.clone() }, ..cfg.clone() };
        assert_eq!(text(&row_credential_gate(&exact, &state, &Ok(verified.clone()), &Ok(Some("no-dns".into())), now)).0, Tag::Ok);
        // The same evidence a week and a second later: too old to stand on its own.
        let stale = text(&row_credential_gate(&cfg, &state, &Ok(verified), &Ok(Some("no-dns".into())), now + crate::bridge::egress::MAX_RECORD_AGE_S + 1));
        assert!(stale.0 == Tag::Warn && stale.1.contains("[record_age]"), "{stale:?}");
        // The execution-role decision (D2), recorded either way, never a failure.
        let with_role = text(&row_credential_vm_role(&AwsCfg { execution_role_arn: Some("arn:aws:iam::123456789012:role/ai-env-vm-exec".into()), ..AwsCfg::default() }));
        assert!(with_role.0 == Tag::Ok && with_role.1.contains("IMDSv2") && with_role.1.contains("S7 D2"), "{with_role:?}");
        let without = text(&row_credential_vm_role(&AwsCfg::default()));
        assert!(without.0 == Tag::Ok && without.1.contains("no AWS keys inside the VM"), "{without:?}");
    }

    fn egress_toml(v: &str) -> EgressCfg {
        BridgeConfig::parse(&format!("[egress]\naccept_platform_dns = {v}\n")).unwrap().egress
    }

    /// The DNS row, every case: an invalid pin is the only failure (exit 1, as `ai-env vm`, `lab` and `egress
    /// check` refuse it); the legacy `true` says the exact line to write for the newest verdict; otherwise the newest
    /// dns-path verdict as the credential gate will judge it.
    #[test]
    fn row_dns_acceptance_says_what_the_gate_accepts_and_what_to_write() {
        let at = |v: &str| -> Result<Option<(String, String)>, String> { Ok(Some((v.to_string(), "2026-10-02T10:00:00Z".to_string()))) };
        let mike = at("platform-dns:fd00:ec2::253");
        // The legacy `true` with Mike's newest row: the exact line.
        let row = row_dns_acceptance(&egress_toml("true"), &mike);
        assert_eq!(
            text(&row),
            (Tag::Warn, "egress DNS: [egress].accept_platform_dns = true accepts no resolver (it names none): only no-dns passes the credential gate  <- in bridge.toml: accept_platform_dns = \"fd00:ec2::253\"".to_string())
        );
        assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0, "reported, never refused");
        for (newest, fix) in [(at("no-dns"), "remove the line"), (Ok(None), "accept_platform_dns = \"<the resolver you tested>\""), (at("platform-dns-answered:fd00:ec2::253"), "accept_platform_dns = \"<the resolver you tested>\""), (Err("x".to_string()), "accept_platform_dns = \"<the resolver you tested>\"")] {
            let (tag, t) = text(&row_dns_acceptance(&egress_toml("true"), &newest));
            assert!(tag == Tag::Warn && t.ends_with(&format!("  <- in bridge.toml: {fix}")) && !t.contains("is false"), "{newest:?}: {t}");
        }
        // The pin: Mike's newest row is accepted.
        let pinned = egress_toml("\"fd00:ec2::253\"");
        assert_eq!(
            text(&row_dns_acceptance(&pinned, &mike)),
            (Tag::Ok, "egress DNS: the newest dns-path verdict platform-dns:fd00:ec2::253 (2026-10-02T10:00:00Z) is accepted ([egress].accept_platform_dns accepts only fd00:ec2::253)".to_string())
        );
        assert_eq!(text(&row_dns_acceptance(&EgressCfg::default(), &at("no-dns"))).0, Tag::Ok, "no-dns needs no pin");
        // Not accepted: another resolver, the never-accepted classes, or no pin at all.
        for (egress, newest) in [(&pinned, at("platform-dns:169.254.169.253")), (&pinned, at("platform-dns-answered:fd00:ec2::253")), (&pinned, at("platform-dns-resolves:fd00:ec2::253")), (&pinned, at("open-dns:1.1.1.1")), (&EgressCfg::default(), mike.clone())] {
            let row = row_dns_acceptance(egress, &newest);
            let (tag, t) = text(&row);
            let v = newest.as_ref().unwrap().as_ref().unwrap().0.clone();
            assert_eq!(tag, Tag::Warn, "{t}");
            assert!(t.starts_with(&format!("egress DNS: the newest dns-path verdict {v} (2026-10-02T10:00:00Z) is NOT accepted (")) && t.contains(&egress.dns_acceptance()) && t.ends_with("  <- ai-env lab show dns-path (its note says what replied)"), "{t}");
            assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0, "{t}");
        }
        // No dns-path row; an unreadable file.
        assert_eq!(text(&row_dns_acceptance(&pinned, &Ok(None))), (Tag::Skip, "egress DNS: no dns-path verdict recorded ([egress].accept_platform_dns accepts only fd00:ec2::253)  <- ai-env lab run dns-path".to_string()));
        let (tag, t) = text(&row_dns_acceptance(&pinned, &Err("lab/probes.jsonl: Permission denied".to_string())));
        assert!(tag == Tag::Warn && t.starts_with("egress DNS: the dns-path rows are unreadable (lab/probes.jsonl: Permission denied)"), "{t}");
        // An invalid pin: [NO ], doctor exit 1, the key and the fix named, whatever the newest row says.
        for (v, why) in [("\"8.8.8.8\"", "not a platform resolver"), ("\"resolver\"", "not an IP address"), ("[\"fd00:ec2::253\", \"1.1.1.1\"]", "lists \"1.1.1.1\"")] {
            let row = row_dns_acceptance(&egress_toml(v), &mike);
            let (tag, t) = text(&row);
            assert_eq!(tag, Tag::No, "{v}: {t}");
            assert!(t.starts_with("config: [egress].accept_platform_dns") && t.contains(why) && t.ends_with("  <- fix [egress].accept_platform_dns in bridge.toml (ai-env vm, lab and egress check refuse it)"), "{v}: {t}");
            assert_eq!(crate::commands::doctor_exit_code(&[row], false), 1, "{v}");
        }
    }

    const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
    const PROXY_ID: &str = "i-0123456789abcdef0";

    /// What `ai-env infra status --write` records after a live ACTIVE read.
    fn active_state() -> InfraState {
        InfraState {
            stack: "dev".into(),
            connector_arn: Some(CONNECTOR.into()),
            connector_id: Some("nc-0a1b2c3d4e5f60718".into()),
            connector_state: Some("ACTIVE".into()),
            connector_state_source: Some("live 2026-10-01T10:00:00Z".into()),
            proxy_instance_id: Some(PROXY_ID.into()),
            proxy_private_ip: Some("10.42.0.10".into()),
            ..InfraState::default()
        }
    }

    /// `state` as `read_infra_state` returns a readable file.
    fn ok(state: InfraState) -> Result<Option<InfraState>, BridgeError> {
        Ok(Some(state))
    }

    fn unreadable() -> Result<Option<InfraState>, BridgeError> {
        Err(BridgeError::Config("/r/state/infra.toml is a symlink; refusing to read it".into()))
    }

    fn egress_cfg(require: bool) -> EgressCfg {
        EgressCfg { require, ..EgressCfg::default() }
    }

    fn aws_with(arn: Option<&str>, ip: Option<&str>) -> AwsCfg {
        AwsCfg { egress_connector_arn: arn.map(str::to_string), proxy_private_ip: ip.map(str::to_string), ..AwsCfg::default() }
    }

    /// Whether `ai-env vm` and `lab` refuse these values (`AwsCfg::validate_egress`).
    fn config_rejects(arn: &str, ip: Option<&str>) -> bool {
        aws_with(Some(arn), ip).validate_egress().is_err()
    }

    /// `[egress].require` with no connector, or any connector `ai-env vm`
    /// refuses, is `[NO ]` (doctor exit 1) naming the key and the fix.
    #[test]
    fn row_egress_fails_when_required_and_unset_or_invalid() {
        for unset in [None, Some(""), Some("  ")] {
            for state in [ok(active_state()), Ok(None), unreadable()] {
                let row = row_egress(&egress_cfg(true), &aws_with(unset, None), &state);
                let (tag, t) = text(&row);
                assert_eq!(tag, Tag::No, "{unset:?}: {t}");
                assert_eq!(t, "[aws].egress_connector_arn unset, but [egress].require = true (ai-env vm run refuses without --egress internet)  <- make infra-status WRITE=1 after the S5 deploy");
                assert_eq!(crate::commands::doctor_exit_code(&[row], false), 1);
            }
            let (tag, t) = text(&row_egress(&egress_cfg(false), &aws_with(unset, None), &Ok(None)));
            assert_eq!((tag, t.as_str()), (Tag::Skip, "[aws].egress_connector_arn unset ([egress].require = false: flag-less runs use the platform's internet egress)"), "{unset:?}");
        }
        let managed = crate::bridge::egress::internet_egress_arn();
        for bad in [managed.as_str(), "arn:aws:lambda:eu-west-3:123456789012:network-connector:ai-env-egress", "ai-env-egress", " arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress", "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress:x"] {
            for require in [true, false] {
                let row = row_egress(&egress_cfg(require), &aws_with(Some(bad), Some("10.42.0.10")), &ok(active_state()));
                let (tag, t) = text(&row);
                assert_eq!(tag, Tag::No, "{bad} (require {require}): {t}");
                assert!(t.starts_with(&format!("[aws].egress_connector_arn = {bad:?} is not a network connector")) && t.ends_with("  <- make infra-status WRITE=1"), "{t}");
                assert!(config_rejects(bad, None), "vm and lab refuse it too: {bad}");
            }
        }
        for bad in ["8.8.8.8", "100.64.0.10", "10.42.0.10/32"] {
            let (tag, t) = text(&row_egress(&egress_cfg(true), &aws_with(Some(CONNECTOR), Some(bad)), &ok(active_state())));
            assert_eq!(tag, Tag::No, "{bad}: {t}");
            assert!(t.starts_with(&format!("[aws].proxy_private_ip = {bad:?} is not an RFC 1918 address")) && t.ends_with("  <- make infra-status WRITE=1"), "{t}");
            assert!(config_rejects(CONNECTOR, Some(bad)), "{bad}");
        }
    }

    #[test]
    fn row_egress_follows_the_recorded_connector_state() {
        let aws = aws_with(Some(CONNECTOR), Some("10.42.0.10"));
        let (tag, t) = text(&row_egress(&egress_cfg(true), &aws, &ok(active_state())));
        assert_eq!((tag, t.as_str()), (Tag::Ok, "egress connector arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress ACTIVE (id nc-0a1b2c3d4e5f60718; state from live 2026-10-01T10:00:00Z)"));
        // A versioned ARN on either side is the same connector; require off changes nothing for a configured one.
        let versioned = InfraState { connector_arn: Some(format!("{CONNECTOR}:1")), ..active_state() };
        assert_eq!(text(&row_egress(&egress_cfg(false), &aws_with(Some(&format!("{CONNECTOR}:1")), None), &ok(versioned.clone()))).0, Tag::Ok);
        assert_eq!(text(&row_egress(&egress_cfg(true), &aws, &ok(versioned))).0, Tag::Ok);

        for st in ["PENDING", "INACTIVE", "FAILED", "DELETING", "DELETE_FAILED", "SOMETHING_NEW"] {
            let row = row_egress(&egress_cfg(true), &aws, &ok(InfraState { connector_state: Some(st.into()), ..active_state() }));
            let (tag, t) = text(&row);
            assert_eq!(tag, Tag::Warn, "{st}: {t}");
            assert!(t.contains(&format!("ai-env-egress is {st} (state from live 2026-10-01T10:00:00Z): ai-env vm run --egress vpc needs it ACTIVE  <- make connector-status")), "{t}");
            assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0, "{st}: a warning, not a failure");
        }

        // No state recorded for it: skip-style, with the hint (and the recorded reason when the live read failed).
        let (tag, t) = text(&row_egress(&egress_cfg(true), &aws, &Ok(None)));
        assert_eq!((tag, t.as_str()), (Tag::Skip, "egress connector arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress: no state recorded (no state/infra.toml)  <- make infra-status WRITE=1"));
        // An unreadable state file is named as such, with its error (never "no state/infra.toml").
        let (tag, t) = text(&row_egress(&egress_cfg(true), &aws, &unreadable()));
        assert_eq!(tag, Tag::Skip, "{t}");
        assert!(t.ends_with(": state unknown (state/infra.toml unreadable: config: /r/state/infra.toml is a symlink; refusing to read it)  <- make infra-status WRITE=1") && !t.contains("no state/infra.toml"), "{t}");
        let s3_era = InfraState { stack: "dev".into(), ..InfraState::default() };
        let (tag, t) = text(&row_egress(&egress_cfg(true), &aws, &ok(s3_era.clone())));
        assert!(tag == Tag::Skip && t.ends_with(": no state recorded (no live read yet)  <- make infra-status WRITE=1"), "{t}");
        let failed = InfraState {
            connector_id: None,
            connector_state: None,
            connector_state_source: Some("pulumi outputs (live read failed: aws lambda-core get-network-connector: An error occurred (AccessDeniedException))".into()),
            ..active_state()
        };
        let (tag, t) = text(&row_egress(&egress_cfg(true), &aws, &ok(failed)));
        assert_eq!(tag, Tag::Skip, "{t}");
        assert!(t.ends_with(": no state recorded (state/infra.toml: pulumi outputs (live read failed: aws lambda-core get-network-connector: An error occurred (AccessDeniedException)))  <- make infra-status WRITE=1"), "{t}");

        // The stack exports no connector any more (infra-status recorded it): a warning naming the stale key, for any require.
        let stale = InfraState { connector_state_source: Some(CONNECTOR_NOT_IN_OUTPUTS.into()), ..s3_era };
        for require in [true, false] {
            let row = row_egress(&egress_cfg(require), &aws, &ok(stale.clone()));
            let (tag, t) = text(&row);
            assert_eq!((tag, t.as_str()), (Tag::Warn, "egress connector arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress: the stack exports no connector: remove [aws].egress_connector_arn (and proxy_private_ip) from bridge.toml"));
            assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0);
        }

        // The state file describes another connector: a warning, whatever its state.
        let other = InfraState { connector_arn: Some("arn:aws:lambda:eu-central-1:123456789012:network-connector:old-egress".into()), ..active_state() };
        let (tag, t) = text(&row_egress(&egress_cfg(true), &aws, &ok(other)));
        assert_eq!(tag, Tag::Warn, "{t}");
        assert!(t.ends_with(": state/infra.toml records the connector arn:aws:lambda:eu-central-1:123456789012:network-connector:old-egress instead  <- make infra-status WRITE=1"), "{t}");
        // A lower-case state (hand-written) and no Id still read.
        let (tag, t) = text(&row_egress(&egress_cfg(true), &aws, &ok(InfraState { connector_state: Some("active".into()), connector_id: None, connector_state_source: None, ..active_state() })));
        assert!(tag == Tag::Ok && t.ends_with("ai-env-egress ACTIVE (state from an unrecorded source)"), "{t}");
    }

    fn described(state: &str, ip: Option<&str>) -> String {
        let mut i = serde_json::json!({"InstanceId": PROXY_ID, "InstanceType": "t4g.nano", "State": {"Code": 16, "Name": state}, "SubnetId": "subnet-0123456789abcdef0", "VpcId": "vpc-0123456789abcdef0"});
        if let Some(ip) = ip {
            i["PrivateIpAddress"] = serde_json::json!(ip);
        }
        serde_json::json!({"Reservations": [{"ReservationId": "r-0123456789abcdef0", "OwnerId": "123456789012", "Instances": [i]}]}).to_string()
    }

    #[test]
    fn row_proxy_running_is_ok_and_a_stopped_proxy_is_never_a_failure() {
        let s = ok(active_state());
        let (tag, t) = text(&row_proxy(None, &s, Some(Ok(&described("running", Some("10.42.0.10"))))));
        assert_eq!((tag, t.as_str()), (Tag::Ok, "egress proxy i-0123456789abcdef0 running (10.42.0.10)"));
        let (tag, t) = text(&row_proxy(None, &s, Some(Ok(&described("running", Some("10.42.0.99"))))));
        assert_eq!((tag, t.as_str()), (Tag::Warn, "egress proxy i-0123456789abcdef0 running at 10.42.0.99, but the VMs' proxy address is 10.42.0.10 (state/infra.toml)  <- make infra-status WRITE=1"));
        assert_eq!(text(&row_proxy(None, &s, Some(Ok(&described("running", None))))).1, "egress proxy i-0123456789abcdef0 running (no private IP reported)");

        // The address the VMs are told wins, as `ai-env egress env` picks it: [aws] first, then the state, then the default.
        let at_99 = described("running", Some("10.42.0.99"));
        let (tag, t) = text(&row_proxy(Some("10.42.0.99"), &s, Some(Ok(&at_99))));
        assert_eq!((tag, t.as_str()), (Tag::Ok, "egress proxy i-0123456789abcdef0 running (10.42.0.99)"), "[aws].proxy_private_ip matches");
        let (tag, t) = text(&row_proxy(Some("10.42.0.98"), &s, Some(Ok(&at_99))));
        assert_eq!((tag, t.as_str()), (Tag::Warn, "egress proxy i-0123456789abcdef0 running at 10.42.0.99, but the VMs' proxy address is 10.42.0.98 ([aws].proxy_private_ip)  <- make infra-status WRITE=1"));
        let (tag, t) = text(&row_proxy(Some("8.8.8.8"), &s, Some(Ok(&at_99))));
        assert!(tag == Tag::Warn && t.ends_with("is 10.42.0.10 (state/infra.toml)  <- make infra-status WRITE=1"), "a public [aws] value is never the proxy: {t}");
        let no_ip = ok(InfraState { proxy_private_ip: None, ..active_state() });
        let (tag, t) = text(&row_proxy(None, &no_ip, Some(Ok(&at_99))));
        assert!(tag == Tag::Warn && t.ends_with("is 10.42.0.10 (the default)  <- make infra-status WRITE=1"), "{t}");
        assert_eq!(text(&row_proxy(None, &no_ip, Some(Ok(&described("running", Some(crate::bridge::egress::PROXY_IP)))))).0, Tag::Ok);
        assert_eq!(effective_proxy_ip(Some(" 192.168.1.5 "), None), ("192.168.1.5", "[aws].proxy_private_ip"));

        for st in ["stopped", "stopping"] {
            let row = row_proxy(None, &s, Some(Ok(&described(st, Some("10.42.0.10")))));
            let (tag, t) = text(&row);
            assert_eq!((tag, t.as_str()), (Tag::Skip, format!("egress proxy i-0123456789abcdef0 {st}: make proxy-start (vpc VMs have no way out until it runs)").as_str()));
            assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0, "{st} is never [NO ]");
        }
        assert_eq!(text(&row_proxy(None, &s, Some(Ok(&described("pending", None))))), (Tag::Skip, "egress proxy i-0123456789abcdef0 pending (starting)".to_string()));
        for st in ["terminated", "shutting-down", "rebooting-forever"] {
            let row = row_proxy(None, &s, Some(Ok(&described(st, None))));
            let (tag, t) = text(&row);
            assert_eq!(tag, Tag::Warn, "{st}: {t}");
            assert!(t.starts_with(&format!("egress proxy i-0123456789abcdef0 is {st}: vpc VMs have no way out  <- ")), "{t}");
            assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0);
        }
    }

    /// Whether `rows` makes the one call: an identity and a valid recorded id, nothing else.
    #[test]
    fn the_proxy_call_needs_an_identity_and_a_valid_recorded_id() {
        let s = active_state();
        assert_eq!(proxy_call(true, Some(&s)), Some(PROXY_ID));
        assert_eq!(proxy_call(false, Some(&s)), None, "no operator identity: no call");
        assert_eq!(proxy_call(true, None), None, "no state: no call");
        for none in [None, Some(String::new())] {
            assert_eq!(proxy_call(true, Some(&InfraState { proxy_instance_id: none.clone(), ..s.clone() })), None, "{none:?}");
        }
        for bad in ["--dry-run", "i-0123456789ABCDEF0", "i-012345", "i-0123456789abcdef0 --x", " i-0123456789abcdef0", "vpc-0123456789abcdef0", "i-0123456789abcdefg"] {
            let st = InfraState { proxy_instance_id: Some(bad.into()), ..s.clone() };
            assert_eq!(proxy_call(true, Some(&st)), None, "{bad}: never on the aws command line");
            assert_eq!(proxy_call(false, Some(&st)), None, "{bad}");
        }
        assert!(is_instance_id("i-01234567") && is_instance_id(PROXY_ID));
    }

    #[test]
    fn row_proxy_without_a_verdict() {
        let s = active_state();
        // Nothing recorded: a skip row (no call is made, see the_proxy_call_needs_an_identity_and_a_valid_recorded_id).
        let (tag, t) = text(&row_proxy(None, &Ok(None), None));
        assert_eq!((tag, t.as_str()), (Tag::Skip, "egress proxy: none recorded (no state/infra.toml)  <- make infra-status WRITE=1 after the S5 deploy"));
        for none in [InfraState { proxy_instance_id: None, ..s.clone() }, InfraState { proxy_instance_id: Some(String::new()), ..s.clone() }] {
            let (tag, t) = text(&row_proxy(None, &ok(none), None));
            assert_eq!((tag, t.as_str()), (Tag::Skip, "egress proxy: none recorded (state/infra.toml has no proxy_instance_id)  <- make infra-status WRITE=1 after the S5 deploy"));
        }
        let (tag, t) = text(&row_proxy(None, &unreadable(), None));
        assert_eq!((tag, t.as_str()), (Tag::Skip, "egress proxy not checked (state/infra.toml unreadable: config: /r/state/infra.toml is a symlink; refusing to read it)  <- make infra-status WRITE=1"));
        for bad in ["--dry-run", "i-0123456789ABCDEF0", "vpc-0123456789abcdef0"] {
            let (tag, t) = text(&row_proxy(None, &ok(InfraState { proxy_instance_id: Some(bad.into()), ..s.clone() }), None));
            assert!(tag == Tag::Warn && t.contains(&format!("proxy_instance_id {bad:?} in state/infra.toml is not an instance id; not checked")), "{bad}: {t}");
        }
        let s = ok(s);
        assert_eq!(text(&row_proxy(None, &s, None)), (Tag::Skip, "egress proxy i-0123456789abcdef0 not checked (no operator identity: ai-env as ops -- ai-env doctor)".to_string()));
        // A failed call names the error: no verdict, doctor exit 0.
        let call = "aws ec2 describe-instances: An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: You are not authorized to perform this operation.";
        let row = row_proxy(None, &s, Some(Err(call)));
        assert_eq!(text(&row), (Tag::Warn, format!("egress proxy i-0123456789abcdef0 not checked: {call}")));
        assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0);
        for junk in ["not json", "{}", "{\"Reservations\": []}", "{\"Reservations\": [{\"Instances\": [{\"InstanceId\": \"i-0fedcba9876543210\"}]}]}", "{\"Reservations\": 3}"] {
            let (tag, t) = text(&row_proxy(None, &s, Some(Ok(junk))));
            assert!(tag == Tag::Warn && t.ends_with("not checked: the describe-instances output does not list it"), "{junk}: {t}");
        }
        let (tag, t) = text(&row_proxy(None, &s, Some(Ok("{\"Reservations\": [{\"Instances\": [{\"InstanceId\": \"i-0123456789abcdef0\"}]}]}"))));
        assert!(tag == Tag::Warn && t.contains("is in no state"), "{t}");
    }

    /// The proxy row's call as `rows` makes it (awscli: region and the ec2
    /// endpoint pinned), answered by tests/fakes/aws.sh from a
    /// `FAKE_AWS_ANSWERS` directory; the fake refuses a call without the pins.
    #[cfg(unix)]
    #[test]
    fn row_proxy_reads_the_fake_aws_answer_through_the_pinned_call() {
        let fake = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fakes/aws.sh");
        let answers = tempfile::tempdir().unwrap();
        let log = answers.path().join("calls.log");
        let state = ok(active_state());
        let id = proxy_call(true, state.as_ref().unwrap().as_ref()).unwrap();
        let cmd = crate::bridge::awscli::aws_cmd("ec2", &proxy_describe_args(id)).unwrap();
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["ec2", "describe-instances", "--instance-ids", PROXY_ID, "--region", "eu-central-1", "--endpoint-url", "https://ec2.eu-central-1.amazonaws.com", "--output", "json"]);
        let call = |args: &[String]| {
            let mut c = Command::new("/bin/sh");
            c.arg(fake).args(args).env("FAKE_AWS_ANSWERS", answers.path()).env("FAKE_AWS_LOG", &log).env_remove("FAKE_AWS_FAIL").env_remove("FAKE_AWS_FAIL_OP").env_remove("FAKE_AWS_PIN_ALL");
            run_capture_cmd(c, None, Duration::from_secs(10))
        };
        std::fs::write(answers.path().join("ec2.describe-instances.1.json"), described("stopped", Some("10.42.0.10"))).unwrap();
        std::fs::write(answers.path().join("ec2.describe-instances.json"), described("running", Some("10.42.0.10"))).unwrap();
        let out = call(&args);
        assert_eq!(text(&row_proxy(None, &state, Some(out.as_deref().map_err(String::as_str)))).0, Tag::Skip, "first answer: stopped");
        let out = call(&args);
        assert_eq!(text(&row_proxy(None, &state, Some(out.as_deref().map_err(String::as_str)))), (Tag::Ok, "egress proxy i-0123456789abcdef0 running (10.42.0.10)".to_string()));
        // Without the endpoint pin the fake refuses (exit 252): the row reports the error, no verdict.
        let unpinned: Vec<String> = args.iter().filter(|a| !a.contains("amazonaws.com") && *a != "--endpoint-url").cloned().collect();
        let err = call(&unpinned).unwrap_err();
        assert!(err.contains("must carry --endpoint-url https://ec2.eu-central-1.amazonaws.com"), "{err}");
        assert_eq!(text(&row_proxy(None, &state, Some(Err(&err)))).0, Tag::Warn);
        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(calls.lines().count(), 3, "{calls}");
        assert!(calls.lines().take(2).all(|l| l.ends_with("--region eu-central-1 --endpoint-url https://ec2.eu-central-1.amazonaws.com --output json")), "{calls}");
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

    /// The S8 rows bridge.toml decides: the wrapper's mode (remote without a
    /// root warns, a mode nobody knows is `[NO ]`, failing every chat under
    /// the roots closed, or with no root running every chat here until one
    /// is named; S9: such a mode quoted scrubbed and capped, never raw), one
    /// warning per workspace still setting `seed_allow_dirty`, the `[seed]`
    /// caps (`[NO ]` naming the key the commands refuse).
    #[test]
    fn the_s8_rows_name_the_mode_the_deprecation_and_the_seed_caps() {
        let rows = |toml: &str| -> Vec<(Tag, String)> { rows_s8(&BridgeConfig::parse(toml).unwrap()).iter().map(text).collect() };
        let plain = rows("");
        assert_eq!(plain.len(), 2, "{plain:?}");
        assert_eq!(plain[0], (Tag::Ok, "wrapper mode passthrough: Cursor's chats run on this Mac (ai-env wrapper install --write --mode remote runs them in MicroVMs)".to_string()));
        assert_eq!(plain[1].0, Tag::Ok);
        assert!(plain[1].1.starts_with("[seed] a wrapper's seed 64 MiB, box seed and vm warm 512 MiB,") && plain[1].1.ends_with("64 box/wip refs kept"), "{}", plain[1].1);
        let remote = rows("[wrapper]\nmode = \"remote\"\n[workspaces]\nroots = [\"/Users/mike/w\"]\n");
        assert_eq!(remote[0].0, Tag::Ok);
        assert!(remote[0].1.starts_with("wrapper mode remote: Cursor's chats under the 1 root(s) run in their workspace's MicroVM"), "{}", remote[0].1);
        let rootless = rows("[wrapper]\nmode = \"remote\"\n");
        assert_eq!(rootless[0].0, Tag::Warn, "{rootless:?}");
        let unknown = rows("[wrapper]\nmode = \"local\"\n[workspaces]\nroots = [\"/Users/mike/w\"]\n");
        assert_eq!(unknown[0], (Tag::No, "config: [wrapper].mode = \"local\": must be \"passthrough\" or \"remote\": every Cursor chat under the roots fails closed  <- ai-env wrapper install --write --mode remote (or passthrough)".to_string()));
        // With no root no chat goes remote, so none fails closed yet: every chat runs here until a root comes.
        let unknown = rows("[wrapper]\nmode = \"local\"\n");
        assert_eq!(unknown[0], (Tag::No, "bridge.toml [wrapper] mode \"local\" (no root), which names no mode: every Cursor chat runs on this Mac until bridge.toml names a root, then every chat under it exits 1 at its start  <- ai-env wrapper install --write --mode remote (or passthrough)".to_string()));
        // A key-shaped value (built at run time) is shown scrubbed and capped, with a root or without.
        let token = format!("{}oat01-{}", "sk-ant-", "Q".repeat(40));
        let masked = format!("\"sk-ant-[redacted:len={}]\"", token.len());
        for (toml, want) in [
            (format!("[wrapper]\nmode = \"{token}\"\n[workspaces]\nroots = [\"/a\"]\n"), format!("config: [wrapper].mode = {masked}: must be")),
            (format!("[wrapper]\nmode = \"{token}\"\n"), format!("bridge.toml [wrapper] mode {masked} (no root), which names no mode: ")),
            (format!("[wrapper]\nmode = \"{}\"\n", "m".repeat(100)), format!("bridge.toml [wrapper] mode {:?} (no root)", "m".repeat(64))),
        ] {
            let row = rows(&toml).remove(0);
            assert!(row.0 == Tag::No && row.1.starts_with(&want) && !row.1.contains(&token) && !row.1.contains(&"m".repeat(65)), "{toml:?}: {row:?}");
        }
        let dirty = rows("[[workspace]]\npath = \"/a\"\nseed_allow_dirty = true\n[[workspace]]\npath = \"/b\"\n[seed]\nmax_mib = 32\n");
        assert_eq!(dirty.len(), 3, "{dirty:?}");
        assert_eq!(dirty[1].0, Tag::Warn);
        assert!(dirty[1].1.starts_with("[[workspace]] /a: seed_allow_dirty is deprecated and ignored") && dirty[1].1.ends_with("<- remove it from bridge.toml"), "{}", dirty[1].1);
        assert_eq!(dirty[2].0, Tag::No, "the wrapper's 64 MiB past max_mib 32: {}", dirty[2].1);
        assert!(dirty[2].1.contains("[seed].wrapper_inline_mib: 64 is more than [seed].max_mib (32)  <- fix [seed]"), "{}", dirty[2].1);
    }

    /// For a bridge.toml that does not load, the S8 rows are the one mode
    /// row the wrapper acts on, the file read as `route::Broken` reads it:
    /// remote (a mode that cannot be read included) is `[NO ]`, passthrough
    /// or no mode `[-  ]`, never the default's `[ok ] passthrough`; with
    /// roots it reads and none (S9), every chat runs here until bridge.toml
    /// names one, the mode quoted scrubbed; a file that loads, or none,
    /// keeps [`rows_s8`]'s rows.
    #[test]
    fn the_s8_rows_of_a_bridge_toml_that_does_not_load_follow_the_wrapper() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().to_path_buf(), None);
        let rows = |toml: Option<&str>| -> Vec<(Tag, String)> {
            match toml {
                Some(toml) => std::fs::write(&paths.config, toml).unwrap(),
                None => std::fs::create_dir(&paths.config).unwrap(),
            }
            let got = rows_s8_loaded(&paths, &BridgeConfig::load(&paths)).iter().map(text).collect();
            match toml {
                Some(_) => std::fs::remove_file(&paths.config).unwrap(),
                None => std::fs::remove_dir(&paths.config).unwrap(),
            }
            got
        };
        let remote = "[wrapper]\nmode = \"remote\"\n[workspaces]\nroots = [\"/x\"]\n";
        // (what, the file or None for one that cannot be read, the tag)
        let broken: [(&str, Option<String>, Tag); 5] = [
            ("remote with an unknown key", Some(format!("{remote}[vm]\nmax_idle = 300\n")), Tag::No),
            ("no TOML at all", Some(format!("{remote}[wrapper]\nmode = \"remote\"\n")), Tag::No),
            ("a file that cannot be read", None, Tag::No),
            ("passthrough with an unknown key", Some("[wrapper]\nmode = \"passthrough\"\n[vm]\nmax_idle = 300\n".to_string()), Tag::Skip),
            ("no mode with an unknown key", Some("[vm]\nmax_idle = 300\n".to_string()), Tag::Skip),
        ];
        for (what, toml, tag) in broken {
            let got = rows(toml.as_deref());
            assert_eq!(got.len(), 1, "{what}: the mode row alone: {got:?}");
            assert_eq!(got[0].0, tag, "{what}: {}", got[0].1);
            let want = if tag == Tag::No { "wrapper mode remote, but bridge.toml does not load: every Cursor chat under its roots" } else { "wrapper mode passthrough as far as bridge.toml still reads" };
            assert!(got[0].1.starts_with(want), "{what}: {}", got[0].1);
        }
        let rows_of = |toml: &str| -> Vec<(Tag, String)> { rows_s8(&BridgeConfig::parse(toml).unwrap()).iter().map(text).collect() };
        assert_eq!(rows(Some(remote)), rows_of(remote), "a file that loads");
        let absent = rows_s8_loaded(&paths, &BridgeConfig::load(&paths)).iter().map(text).collect::<Vec<_>>();
        assert_eq!(absent, rows_of(""), "no bridge.toml: the defaults");
        // Remote, or a mode it cannot read (F1: an unknown [wrapper] key, a header-less mode), roots read and none.
        let token = format!("{}oat01-{}", "sk-ant-", "Q".repeat(40));
        let until = "every Cursor chat runs on this Mac until bridge.toml names a root, then every chat under it exits 1 at its start  <- fix bridge.toml (the bridge.toml row above)";
        for (toml, mode) in [
            ("[wrapper]\nmode = \"remote\"\n[vm]\nmax_idle = 300\n".to_string(), "\"remote\"".to_string()),
            ("[wrapper]\nmode = 1\n".to_string(), "unreadable".to_string()),
            ("[wrapper]\nmode = \"passthrough\"\nnope = 1\n".to_string(), "unreadable".to_string()),
            ("mode = \"remote\"\n".to_string(), "unreadable".to_string()),
            (format!("[wrapper]\nmode = \"{token}\"\n[vm]\nmax_idle = 300\n"), format!("\"sk-ant-[redacted:len={}]\"", token.len())),
        ] {
            let got = rows(Some(toml.as_str()));
            assert_eq!(got, vec![(Tag::No, format!("bridge.toml, which does not load, [wrapper] mode {mode} (no root): {until}"))], "{toml:?}");
        }
    }

    /// The image's `workspace_v1` (L5): a live VM without it is named (make
    /// deploy, or only `vm terminate` once the version a new VM runs has
    /// it); else the newest row of the version a new VM runs whose caps
    /// were read decides, terminated rows included; unknown is `[-  ]`.
    #[test]
    fn the_workspace_cap_row_reads_the_vms_caps_for_the_version_new_vms_run() {
        use crate::wire::frame::CAP_WORKSPACE_V1;
        let row = |id: &str, version: &str, status: RowStatus, created: &str, caps: Option<&[&str]>| VmRow { image_version: version.into(), caps: caps.map(|c| c.iter().map(|s| (*s).to_string()).collect()), ..vm(id, status, created) };
        let state = |active: &str| -> Result<Option<InfraState>, BridgeError> { Ok(Some(InfraState { latest_active_image_version: Some(active.into()), ..InfraState::default() })) };
        let cfg = BridgeConfig::default();
        let s7 = row("microvm-old", "7.0", RowStatus::Running, "2026-10-11T08:00:00.000Z", Some(&["credential_cache"]));
        let (tag, t) = text(&row_workspace_cap(std::slice::from_ref(&s7), &state("8.0"), &cfg));
        assert!(tag == Tag::Warn && t.contains("microvm-old (7.0) lack it") && t.contains("make deploy"), "{t}");
        let gone = VmRow { status: RowStatus::Terminated, ..s7.clone() };
        let (tag, t) = text(&row_workspace_cap(std::slice::from_ref(&gone), &state("7.0"), &cfg));
        assert!(tag == Tag::Warn && t.contains("image version 7.0 lacks it (from microvm-old's /health)") && t.ends_with("<- make deploy"), "a terminated row still tells the image's caps: {t}");
        let s8 = [gone.clone(), row("microvm-new", "8.0", RowStatus::Suspended, "2026-10-12T08:00:00.000Z", Some(&["credential_cache", CAP_WORKSPACE_V1])), row("microvm-unread", "8.0", RowStatus::Running, "2026-10-12T09:00:00.000Z", None)];
        assert_eq!(text(&row_workspace_cap(&s8, &state("8.0"), &cfg)), (Tag::Ok, format!("{CAP_WORKSPACE_V1}: image version 8.0 serves the workspace routes (from microvm-new's /health)")));
        let (tag, t) = text(&row_workspace_cap(&s8[2..], &state("8.0"), &cfg));
        assert!(tag == Tag::Skip && t.contains("not known yet") && t.contains("make deploy"), "{t}");
        let pinned = BridgeConfig::parse("[aws]\nimage_version = \"7\"\n").unwrap();
        assert_eq!(text(&row_workspace_cap(&s8, &state("8.0"), &pinned)).0, Tag::Warn, "[aws].image_version 7 is 7.0, which lacks it");
        assert_eq!(text(&row_workspace_cap(&[], &Ok(None), &cfg)).0, Tag::Skip, "no active version recorded");
        // Deployed already, an S7 VM still running: only it goes, no second deploy.
        let leftover = [s7.clone(), s8[1].clone()];
        assert_eq!(text(&row_workspace_cap(&leftover, &state("8.0"), &cfg)), (Tag::Warn, format!("{CAP_WORKSPACE_V1}: microvm-old (7.0) lack it: remote sessions never use them  <- ai-env vm terminate microvm-old")));
        let (tag, t) = text(&row_workspace_cap(&leftover, &state("8.0"), &pinned));
        assert!(tag == Tag::Warn && t.contains("make deploy"), "new VMs run 7.0, which lacks it: {t}");
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

    /// A crashed aws CLI prints a Python traceback: the error is its last
    /// unindented line, not the "Traceback" header (S6 part B: a Homebrew
    /// awscli whose `_awscrt` lost its libaws-c-s3 dylib).
    #[test]
    fn a_python_tracebacks_error_line_is_its_exception() {
        let tb = "Traceback (most recent call last):\n  File \"/x/awscrt/crypto.py\", line 4, in <module>\n    import _awscrt\nImportError: dlopen(/x/_awscrt.abi3.so, 0x0002): Library not loaded: /opt/homebrew/opt/aws-c-s3/lib/libaws-c-s3.1.2.dylib\n  Referenced from: <uuid> /x/_awscrt.abi3.so\n  Reason: tried: '/opt/homebrew/opt/aws-c-s3/lib/libaws-c-s3.1.2.dylib' (no such file)\n";
        assert_eq!(error_line(tb), "ImportError: dlopen(/x/_awscrt.abi3.so, 0x0002): Library not loaded: /opt/homebrew/opt/aws-c-s3/lib/libaws-c-s3.1.2.dylib");
        let chained = "Traceback (most recent call last):\n  File \"a\"\nKeyError: 'x'\n\nDuring handling of the above exception, another exception occurred:\n\nTraceback (most recent call last):\n  File \"b\"\nValueError: bad\n";
        assert_eq!(error_line(chained), "ValueError: bad", "the last exception of a chain");
        assert_eq!(error_line("Traceback (most recent call last):\n  File \"a\"\n"), "Traceback (most recent call last):", "no exception line: the header");
        assert_eq!(error_line("first\nsecond\n"), "first");
        assert_eq!(error_line("\n  An error occurred (ExpiredToken)\n"), "An error occurred (ExpiredToken)");
        assert_eq!(error_line(""), "");
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
        let err = run_capture_cmd(sh("printf 'Traceback (most recent call last):\\n  File \"x\", line 4\\n    import _awscrt\\nImportError: boom\\n' >&2; exit 1"), None, Duration::from_secs(5)).unwrap_err();
        assert_eq!(err, "ImportError: boom", "a crashed Python CLI: its exception, not the traceback's header");
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

    /// S8 operators: under `ai-env as ops -- ai-env doctor` the operator key
    /// and its marker are for the AWS rows alone: every probed tool (rustup,
    /// cargo-lambda, zig, `claude --version`, `claude auth status`,
    /// ai-env-claude) loses them with the OAuth token, the API key and a
    /// session token; the one plain sts call of a run without an identity
    /// keeps the shell's own chain (an exported root key is what it warns of).
    #[test]
    fn probes_never_inherit_an_aws_key_or_the_runner_marker() {
        let removed = |cmd: &Command| cmd.get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_string_lossy().into_owned()).collect::<Vec<_>>();
        let want = ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AI_ENV_BRIDGE_AS"];
        for (what, cmd) in [("a probe", probe_cmd("rustup", &["run", EXPECTED_TOOLCHAIN, "rustc", "--version"])), ("claude auth status", claude_auth_cmd(Path::new("/x/claude")))] {
            let gone = removed(&cmd);
            for name in want {
                assert!(gone.iter().any(|g| g == name), "{what} inherits {name}: {gone:?}");
            }
        }
        assert!(removed(&claude_auth_cmd(Path::new("/x/claude"))).iter().any(|g| g == "CLAUDE_CONFIG_DIR"), "the default login is the one asked about");
        let sts = ambient_sts_cmd();
        assert_eq!(removed(&sts), ["CLAUDE_CODE_OAUTH_TOKEN"], "the ambient chain as it is");
        assert_eq!(sts.get_args().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>(), ["sts", "get-caller-identity", "--region", "eu-central-1", "--output", "json"]);
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
    fn region_rows() {
        let (tag, t) = text(&row_region(None));
        assert_eq!(tag, Tag::Ok);
        assert!(t.contains("eu-central-1 (pinned in code)"), "{t}");
        let (tag, t) = text(&row_region(Some("env AWS_REGION=eu-west-3 ignored (region pinned to eu-central-1)")));
        assert_eq!(tag, Tag::Warn);
        assert!(t.contains("eu-west-3 ignored"), "{t}");
    }

    fn verified(arn: &str) -> crate::errors::Result<Verified> {
        Ok(parse_caller(&format!("{{\"Account\": \"123456789012\", \"Arn\": \"{arn}\"}}")).unwrap())
    }

    /// S8 operators §8.2: the operator identity row, from the marker alone and
    /// the row's one sts call; a refused key is the only exit-5 case, and with
    /// no marker doctor names `ai-env as ops -- ai-env doctor` (it never unseals).
    #[test]
    fn operator_identity_rows() {
        use crate::bridge::identity::Role;
        use crate::errors::CliError;
        let ops = Ok(Operator::Runner { role: Role::Ops, tail: "9002".into() });
        let ops_arn = "arn:aws:iam::123456789012:user/ai-env-ops";
        let (row, auth) = row_operator_identity(Some(&ops), Some(&verified(ops_arn)));
        assert_eq!((text(&row), auth), ((Tag::Ok, format!("operator identity {ops_arn} (ai-env as ops, key ...9002)")), false));
        let root = Ok(Operator::Ambient { root: true });
        let (row, _) = row_operator_identity(Some(&root), Some(&verified("arn:aws:iam::123456789012:root")));
        assert_eq!(text(&row), (Tag::Warn, "operator identity is the account ROOT (ai-env as root: the bootstrap and break-glass only)  <- ai-env as ops -- ai-env doctor".into()));
        let ambient = Ok(Operator::Ambient { root: false });
        let (row, _) = row_operator_identity(Some(&ambient), Some(&verified("arn:aws:iam::123456789012:user/agent")));
        assert_eq!(text(&row), (Tag::Ok, "operator identity arn:aws:iam::123456789012:user/agent (ai-env as ambient: the aws CLI's own credentials, never the root)".into()));
        // A declared identity that fails: [NO ] with its text; only a refused key is exit 5.
        let refused_text = "AWS refused the operator key ...9002 (InvalidClientTokenId): re-seal credentials/ops.env, which ai-env as ops unseals, with ai-env as deployer -- make ops-key ROTATE=1";
        let refused = Err(CliError::AuthUnavailable(refused_text.into()));
        let (row, auth) = row_operator_identity(Some(&ops), Some(&refused));
        assert_eq!((text(&row), auth), ((Tag::No, format!("operator identity: {refused_text}")), true));
        let other = Err(CliError::Policy("AI_ENV_BRIDGE_AS=root, but the aws CLI's credentials are arn:aws:iam::123456789012:user/rust, not the account root: unset it, or run the command under ai-env as root -- again".into()));
        let (row, auth) = row_operator_identity(Some(&root), Some(&other));
        assert!(text(&row).0 == Tag::No && text(&row).1.starts_with("operator identity: AI_ENV_BRIDGE_AS=root, but") && !auth, "{:?}", text(&row));
        let bad: std::result::Result<Operator, String> = Err("AI_ENV_BRIDGE_AS=x is not one ai-env sets (deployer:XXXX, ops:XXXX, root or ambient): unset it".into());
        let (row, auth) = row_operator_identity(Some(&bad), None);
        assert_eq!((text(&row), auth), ((Tag::No, "operator identity: AI_ENV_BRIDGE_AS=x is not one ai-env sets (deployer:XXXX, ops:XXXX, root or ambient): unset it".into()), false));
        let (row, auth) = row_operator_identity(None, None);
        assert_eq!((text(&row), auth), ((Tag::Skip, "operator identity: none declared (doctor never unseals credentials/ops.env)  <- ai-env as ops -- ai-env doctor (one Touch ID)".into()), false));
        assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0);
    }

    /// With no identity declared, the shell's own credentials are only looked
    /// at to warn when they are the root's, naming the runners instead.
    #[test]
    fn ambient_root_row_names_ai_env_as_ops() {
        let (tag, t) = text(&row_ambient_identity(Some(Ok("{\"Account\": \"123456789012\", \"Arn\": \"arn:aws:iam::123456789012:root\"}"))));
        assert_eq!(tag, Tag::Warn);
        assert_eq!(t, "the ambient aws CLI credentials are the account ROOT: operator commands never use them, but a plain aws call here runs as the root; outside the bootstrap and break-glass, keep root's key out of a terminal used for ai-env (README \"Identities\")  <- ai-env as ops -- … for operator commands, ai-env as deployer -- … to deploy");
        let row = row_ambient_identity(Some(Ok("{\"Account\": \"123456789012\", \"Arn\": \"arn:aws:iam::123456789012:user/agent\"}")));
        assert_eq!(text(&row), (Tag::Skip, "ambient aws CLI identity arn:aws:iam::123456789012:user/agent (not used by operator commands)".into()));
        let row = row_ambient_identity(Some(Err("Unable to locate credentials. You can configure credentials by running \"aws configure\".")));
        assert_eq!(text(&row), (Tag::Ok, "no ambient aws CLI credentials (operator commands use ai-env as … or credentials/ops.env)".into()));
        let row = row_ambient_identity(Some(Err("An error occurred (ExpiredToken) when calling the GetCallerIdentity operation: expired")));
        assert_eq!(text(&row), (Tag::Skip, "ambient aws CLI identity: An error occurred (ExpiredToken) when calling the GetCallerIdentity operation: expired (not used by operator commands)".into()));
        assert_eq!(text(&row_ambient_identity(None)), (Tag::Skip, "aws cli not found (bridge commands need it)".into()));
        assert!(text(&row_ambient_identity(Some(Ok("not json")))).1.starts_with("ambient aws CLI identity: unreadable answer"));
    }

    /// The ops key row reads the file and its sealing notes only (no Touch
    /// ID), as `creds status` does, showing the UTC day of the sealing.
    #[test]
    fn row_ops_key_follows_the_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ops.env");
        assert_eq!(
            text(&ops_key(&p)),
            (Tag::Skip, format!("ops key absent ({})  <- ai-env as deployer -- make ops-key (after the bootstrap: make operator-keys)", p.display()))
        );
        let notes = KeyNotes::pairs(crate::bridge::identity::OPS_USER, "9002", 1_789_804_800);
        let notes: Vec<(&str, &str)> = notes.iter().map(|(k, v)| (*k, v.as_str())).collect();
        std::fs::write(&p, crate::container::write_annotated(b"age-encryption.org/v1\n-> x\n--- y\n", &notes).unwrap()).unwrap();
        assert_eq!(text(&ops_key(&p)), (Tag::Ok, format!("ops key sealed ({}): ai-env-ops ...9002, sealed 2026-09-19 (recorded at sealing, not authenticated)", p.display())));
        std::fs::write(&p, crate::container::write(b"age-encryption.org/v1\n-> x\n--- y\n")).unwrap();
        let (tag, t) = text(&ops_key(&p));
        assert!(tag == Tag::Ok && t.ends_with("an unrecorded user (key id not recorded), sealed on an unrecorded day (recorded at sealing, not authenticated)"), "{t}");
        let plain = format!("{}{}", "placeholder-", "value");
        std::fs::write(&p, format!("AWS_ACCESS_KEY_ID=x\nAWS_SECRET_ACCESS_KEY={plain}\n")).unwrap();
        let (tag, t) = text(&ops_key(&p));
        assert_eq!(tag, Tag::No);
        assert!(t.starts_with("ops key NOT sealed: ") && t.ends_with("is not an ai-env container (plaintext?)  <- move it away, then ai-env as deployer -- make ops-key ROTATE=1") && !t.contains(&plain), "{t}");
    }

    /// The deployer the state records, with its key count under an identity:
    /// one key is the norm, none or two need a hand, a missing user is stale state.
    #[test]
    fn row_deployer_counts_its_keys() {
        let with = ok(InfraState { deployer_user_arn: Some("arn:aws:iam::123456789012:user/ai-env-deployer".into()), ..active_state() });
        let keys = |n: usize| serde_json::json!({"AccessKeyMetadata": (0..n).map(|i| serde_json::json!({"UserName": "ai-env-deployer", "Status": "Active", "N": i})).collect::<Vec<_>>()}).to_string();
        assert_eq!(text(&row_deployer(&with, None)), (Tag::Ok, "deployer user/ai-env-deployer (stack output; its key is in Strongbox only)".into()));
        assert_eq!(text(&row_deployer(&with, Some(Ok(&keys(1))))), (Tag::Ok, "deployer user/ai-env-deployer: 1 access key (in Strongbox only)".into()));
        assert_eq!(text(&row_deployer(&with, Some(Ok(&keys(0))))), (Tag::No, "deployer user/ai-env-deployer has no access key  <- ai-env as root -- make operator-keys".into()));
        assert_eq!(
            text(&row_deployer(&with, Some(Ok(&keys(2))))),
            (Tag::Warn, "deployer user/ai-env-deployer has 2 access keys (one left from a rotation?)  <- delete the one not in Strongbox: ai-env as deployer -- aws iam list-access-keys --user-name ai-env-deployer --region eu-central-1".into())
        );
        let gone = "An error occurred (NoSuchEntity) when calling the ListAccessKeys operation: The user with name ai-env-deployer cannot be found.";
        assert_eq!(text(&row_deployer(&with, Some(Err(gone)))), (Tag::No, "deployer user/ai-env-deployer does not exist, though state/infra.toml names it  <- make infra-status WRITE=1".into()));
        assert_eq!(text(&row_deployer(&with, Some(Err("aws: timed out after 15s")))), (Tag::Warn, "deployer: iam list-access-keys failed: aws: timed out after 15s".into()));
        assert_eq!(text(&row_deployer(&ok(active_state()), None)), (Tag::Skip, "deployer: none recorded in state/infra.toml  <- the bootstrap deploy, then make infra-status WRITE=1".into()));
        assert_eq!(text(&row_deployer(&Ok(None), None)).0, Tag::Skip);
        assert!(text(&row_deployer(&unreadable(), None)).1.starts_with("deployer: not checked (state/infra.toml unreadable: "));
        assert_eq!(crate::commands::doctor_exit_code(&[row_deployer(&with, Some(Ok(&keys(2))))], false), 0, "a warning, not a failure");
    }

    /// The account root's access keys, from `get-account-summary` under an
    /// identity: any key, deactivated too, warns until it is deleted.
    #[test]
    fn row_root_access_keys_counts_and_failures() {
        let summary = |n: u64| format!("{{\"SummaryMap\": {{\"AccountAccessKeysPresent\": {n}, \"AccountMFAEnabled\": 1, \"Users\": 3}}}}");
        assert_eq!(text(&row_root_access_keys(Some(Ok(&summary(0))))), (Tag::Ok, "the account root has no access key".into()));
        assert_eq!(
            text(&row_root_access_keys(Some(Ok(&summary(1))))),
            (Tag::Warn, "the account root has an access key (AccountAccessKeysPresent=1, active or deactivated)  <- ai-env needs it only for the bootstrap and break-glass: delete it when nothing else uses it (IAM console, Security credentials), and never load it into a terminal used for ai-env day to day".into())
        );
        assert!(text(&row_root_access_keys(Some(Ok(&summary(2))))).1.contains("AccountAccessKeysPresent=2"));
        assert_eq!(text(&row_root_access_keys(Some(Err("AccessDenied")))), (Tag::Skip, "the account root's access keys: not checked (AccessDenied)".into()));
        assert_eq!(text(&row_root_access_keys(None)), (Tag::Skip, "the account root's access keys: not checked (no operator identity: ai-env as ops -- ai-env doctor)".into()));
        assert_eq!(text(&row_root_access_keys(Some(Ok("{}")))).0, Tag::Skip);
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

    /// The selection P10, doctor, gate G4 and `ai-env claude` share: a version `.obsolete` lists (left on disk
    /// after installing an older one), a plain file or a symlink named like a bundle is none; a malformed `.obsolete`
    /// hides nothing; a release beats a suffixed name of the same version.
    #[test]
    fn installed_extension_names_skip_obsolete_files_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let bundle = |v: &str| format!("anthropic.claude-code-{v}-darwin-arm64");
        for v in ["2.1.287", "2.1.288"] {
            std::fs::create_dir(dir.join(bundle(v))).unwrap();
        }
        std::fs::write(dir.join(bundle("2.1.300")), "").unwrap();
        std::os::unix::fs::symlink(dir.join("nowhere"), dir.join(bundle("2.1.299"))).unwrap();
        std::os::unix::fs::symlink(dir.join(bundle("2.1.287")), dir.join(bundle("2.1.298"))).unwrap();
        let picked = || pick_bundle(&installed_extension_names(dir)).map(|(v, _)| v);
        assert_eq!(picked().as_deref(), Some("2.1.288"), "files and symlinks are no installed extension");
        std::fs::write(dir.join(".obsolete"), r#"{"anthropic.claude-code-2.1.288-darwin-arm64": true, "other.ext-1.0.0": true}"#).unwrap();
        assert_eq!(picked().as_deref(), Some("2.1.287"), "the obsolete newer one is skipped");
        let (_, t) = text(&row_cursor_bundle(&installed_extension_names(dir), Some("2.1.287 (Claude Code)")));
        assert!(t.contains("cursor extension 2.1.287") && !t.contains("versions installed"), "doctor counts only what is installed: {t}");
        std::fs::write(dir.join(".obsolete"), "not json").unwrap();
        assert_eq!(picked().as_deref(), Some("2.1.288"), "a malformed .obsolete hides nothing");
        std::fs::create_dir(dir.join(bundle("2.1.289-rc1"))).unwrap();
        std::fs::create_dir(dir.join(bundle("2.1.289"))).unwrap();
        assert_eq!(picked().as_deref(), Some("2.1.289"), "the release beats the suffixed name, whatever the listing order");
        assert!(installed_extension_names(&dir.join("absent")).is_empty());
    }

    /// doctor's own call (B3 of S10's claude-update review): its rows rest on the installed selection (an obsolete newer
    /// bundle is not the Cursor bundle), the claude it asks is the selected bundle's; S11: the claude rows follow it
    /// (phase 0's stub: the image's fallback note alone; none without a bundle or a window).
    #[test]
    fn cursor_bundle_rows_use_the_installed_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let bundle = |v: &str| format!("anthropic.claude-code-{v}-darwin-arm64");
        for v in ["2.1.287", "2.1.288"] {
            std::fs::create_dir(dir.join(bundle(v))).unwrap();
        }
        std::fs::write(dir.join(bundle("2.1.300")), "").unwrap();
        std::fs::write(dir.join(".obsolete"), r#"{"anthropic.claude-code-2.1.288-darwin-arm64": true}"#).unwrap();
        let asked = std::cell::RefCell::new(Vec::new());
        // The rows on no live window (`cursor_bundle_rows` reads them from the bridge's census: not here).
        let (lines, out) = bundle_rows(
            dir,
            Some("2.1.287"),
            &|bin: &Path| {
                asked.borrow_mut().push(bin.to_path_buf());
                Some("2.1.287 (Claude Code)".to_string())
            },
            &[],
            &[],
            true,
            &crate::bridge::claude::RetryClock::at(0),
        );
        assert_eq!(*asked.borrow(), vec![dir.join(bundle("2.1.287")).join("resources").join("native-binary").join("claude")]);
        assert_eq!(out.as_deref(), Some("2.1.287 (Claude Code)"));
        let texts: Vec<String> = lines.iter().map(|l| text(l).1).collect();
        assert!(texts[0].contains("cursor extension 2.1.287, bundled claude 2.1.287") && !texts[0].contains("versions installed"), "{texts:?}");
        assert_eq!(lines.last().map(text), Some((Tag::Skip, "the image's claude 2.1.287 runs where no staged version can".to_string())), "{texts:?}");
        // S11 (A3's rows, A §11.2): the selected bundle's version against the image's own claude.
        assert!(lines.iter().map(text).any(|r| r == (Tag::Ok, "claude 2.1.287 (the Cursor bundle): the image's own claude; chats run it with nothing to fetch".to_string())), "{texts:?}");
        let (lines, _) = bundle_rows(dir, Some("2.1.286"), &|_: &Path| None, &[], &[], true, &crate::bridge::claude::RetryClock::at(0));
        let texts: Vec<String> = lines.iter().map(|l| text(l).1).collect();
        assert!(texts.iter().any(|t| t == "the image's claude 2.1.286 runs where no staged version can"), "{texts:?}");
        let admit = "claude 2.1.287 (the Cursor bundle): not admitted yet; chats run the image's 2.1.286  <- ai-env claude admit 2.1.287 (automatic while Docker answers: [claude].auto_admit)";
        assert!(lines.iter().map(text).any(|r| r == (Tag::Warn, admit.to_string())), "{texts:?}");
        // T6: no automatic admission to promise (`[claude].auto_admit` off, or not remote): the admit alone.
        let (lines, _) = bundle_rows(dir, Some("2.1.286"), &|_: &Path| None, &[], &[], false, &crate::bridge::claude::RetryClock::at(0));
        let manual = "claude 2.1.287 (the Cursor bundle): not admitted yet; chats run the image's 2.1.286  <- ai-env claude admit 2.1.287";
        assert!(lines.iter().map(text).any(|r| r == (Tag::Warn, manual.to_string())), "{:?}", lines.iter().map(text).collect::<Vec<_>>());
        assert!(!texts.iter().any(|t| t.contains("Auto Update") || t.contains("make claude-update")), "{texts:?}");
        let (lines, out) = bundle_rows(&dir.join("absent"), Some("2.1.287"), &|_: &Path| -> Option<String> { panic!("no bundle: nothing to ask") }, &[], &[], true, &crate::bridge::claude::RetryClock::at(0));
        assert_eq!((lines.len(), text(&lines[0]).0, out), (1, Tag::Skip, None));
    }

    /// S12 (V2, §V2.3, LD-V8): `bundle_rows` hands its clock to the claude rows as given: the installed bundle's
    /// Docker failure counts its automatic retry from the version lock's later end (`clock.finished`), as `claude
    /// status` and `wrapper status` do, not from the failure alone, and is due now once `clock.now` reached it.
    #[test]
    fn bundle_rows_hand_their_clock_to_the_claude_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("extensions");
        std::fs::create_dir_all(dir.join("anthropic.claude-code-2.1.320-darwin-arm64")).unwrap();
        let p = Paths::from_root_and_env(tmp.path().join("bridge"), None);
        crate::bridge::claude::tests::put_docker(&p, "2.1.320", 'a', 1, "2026-10-24T13:50:00Z");
        let records = crate::bridge::claude::load_all(&p);
        let a = crate::wire::time::parse_rfc3339_utc("2026-10-24T13:50:00Z").unwrap();
        let clock = crate::bridge::claude::RetryClock { now: a + 60, finished: [("2.1.320".to_string(), a + 600)].into() };
        let (lines, _) = bundle_rows(&dir, Some("2.1.305"), &|_: &Path| None, &[], &records, true, &clock);
        let want = (Tag::Warn, "claude 2.1.320 (the Cursor bundle): admission failed at docker (test l2_x failed; attempt 1 of 3); chats run the image's 2.1.305  <- an automatic retry from 2026-10-24T14:15:00Z (the next remote wrapper starts it), or ai-env claude admit 2.1.320 --redo now".to_string());
        assert!(lines.iter().map(text).any(|r| r == want), "{:?}", lines.iter().map(text).collect::<Vec<_>>());
        // Its `now` too: at that time, the retry is due.
        let due = crate::bridge::claude::RetryClock { now: a + 1500, finished: [("2.1.320".to_string(), a + 600)].into() };
        let (lines, _) = bundle_rows(&dir, Some("2.1.305"), &|_: &Path| None, &[], &records, true, &due);
        let want = (Tag::Warn, "claude 2.1.320 (the Cursor bundle): admission failed at docker (test l2_x failed; attempt 1 of 3); chats run the image's 2.1.305  <- an automatic retry is due now (the next remote wrapper starts it), or ai-env claude admit 2.1.320 --redo now".to_string());
        assert!(lines.iter().map(text).any(|r| r == want), "{:?}", lines.iter().map(text).collect::<Vec<_>>());
    }

    /// S9: a live Cursor window on another extension than the installed one
    /// is named (`[!! ]`, its host's pid and since when it runs, the reload
    /// that brings it to the installed one), read from the census through
    /// `census::running_extensions` (a dead host, or a pid given to a later
    /// process, names nothing); a window on the installed extension, or
    /// none at all, adds no row.
    #[test]
    fn a_window_on_an_older_extension_is_named() {
        use crate::bridge::census::{running_extensions, RunningExtension};
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let bundle = |v: &str| format!("anthropic.claude-code-{v}-darwin-arm64");
        for v in ["2.1.301", "2.1.302"] {
            std::fs::create_dir(dir.join(bundle(v))).unwrap();
        }
        let since = crate::wire::time::parse_rfc3339_utc("2026-10-17T09:00:00Z").unwrap();
        let row = |ppid: u64, start_s: u64, ext: &str| serde_json::json!({"v": 1, "start": start_s * 1000, "pid": 4242, "ppid": ppid, "ext": ext, "route": "remote", "reason": "session"});
        let rows = vec![row(5101, since + 60, "2.1.301"), row(5102, since + 120, "2.1.302"), row(5103, since + 60, "2.1.300"), row(5104, since + 60, "2.1.299")];
        // 5101 and 5102 live since `since`; 5103 gone; 5104's pid a process that started after its row.
        let identity = |pid: u32| -> Option<(String, u64)> {
            match pid {
                5101 | 5102 => Some(("Cursor Helper (Plugin)".into(), since)),
                5104 => Some(("other".into(), since + 3600)),
                _ => None,
            }
        };
        let running = running_extensions(&rows, &identity);
        assert_eq!(running.iter().map(|w| (w.host, w.ext.as_str())).collect::<Vec<_>>(), [(5101, "2.1.301"), (5102, "2.1.302")]);
        let (lines, _) = bundle_rows(dir, None, &|_: &Path| None, &running, &[], true, &crate::bridge::claude::RetryClock::at(0));
        let texts: Vec<(Tag, String)> = lines.iter().map(text).collect();
        let older = (Tag::Warn, "a Cursor window runs extension 2.1.301 (host pid 5101, since 2026-10-17T09:00:00Z); 2.1.302 is installed  <- reload that window".to_string());
        assert_eq!(texts.iter().filter(|(_, t)| t.starts_with("a Cursor window runs extension ")).cloned().collect::<Vec<_>>(), vec![older.clone()], "the window on the installed 2.1.302 adds no row: {texts:?}");
        assert_eq!(texts[0].0, Tag::Ok, "the installed bundle first: {texts:?}");
        assert_eq!(texts[1], older, "right after it: {texts:?}");
        // No live window, or every one on the installed extension: no window row.
        for windows in [Vec::new(), vec![RunningExtension { host: 5102, ext: "2.1.302".into(), started: since, seen: (since + 120) * 1000 }]] {
            let (lines, _) = bundle_rows(dir, None, &|_: &Path| None, &windows, &[], true, &crate::bridge::claude::RetryClock::at(0));
            assert!(lines.iter().all(|l| !text(l).1.starts_with("a Cursor window runs")), "{windows:?}");
        }
        // No installed bundle: nothing to reload a window onto (the bundle row says it is missing).
        assert!(rows_running_windows(None, &running).is_empty());
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
        // S11 (B.4): each names its fix; with the sibling missing too, the install comes first.
        assert_eq!(text(&rows[0]), (Tag::No, format!("{WRAPPER_SETTING} = /gone does not exist  <- ai-env wrapper install --write")));
        assert_eq!(text(&noexec[0]), (Tag::No, format!("{WRAPPER_SETTING} = /gone is not executable  <- ai-env wrapper install --write")));
        let path_only = row_wrapper_setting(Some(&missing), &|_| (false, false), &Sibling::PathOnly(PathBuf::from("/p/ai-env-claude")));
        assert_eq!(text(&path_only[0]), (Tag::No, format!("{WRAPPER_SETTING} = /gone does not exist  <- ai-env wrapper install --write")));
        let install = "cargo install --path crates/ai-env-cli --locked, then ai-env wrapper install --write";
        let alone = row_wrapper_setting(Some(&missing), &|_| (false, false), &Sibling::Missing);
        assert_eq!(text(&alone[0]), (Tag::No, format!("{WRAPPER_SETTING} = /gone does not exist  <- {install}")));
        let alone = row_wrapper_setting(Some(&missing), &|_| (true, false), &Sibling::Missing);
        assert_eq!(text(&alone[0]), (Tag::No, format!("{WRAPPER_SETTING} = /gone is not executable  <- {install}")));
        assert_eq!(text(&row_wrapper_setting(Some(&missing), &|_| (true, true), &Sibling::Missing)[0]), (Tag::Ok, format!("{WRAPPER_SETTING} = /gone")), "a working wrapper needs no fix");
        // The bypass mode is a warning (a_bypass_permission_mode_is_a_warning holds its text).
        let bypass = parse_settings("{\"claudeCode.initialPermissionMode\": \"bypassPermissions\"}").unwrap();
        assert_eq!(text(&row_wrapper_setting(Some(&bypass), &|_| (true, true), &sib)[1]).0, Tag::Warn);

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

    // ---- S11 (B.4): the doctor matrix ------------------------------------------------

    /// Every broken precondition doctor knows is `[NO ]`, names its fix
    /// after `  <- `, and makes doctor exit 1.
    #[test]
    fn matrix_each_broken_precondition_is_no_with_a_fix() {
        let missing = parse_settings("{\"claudeCode.claudeProcessWrapper\": \"/gone/ai-env-claude\"}").unwrap();
        let next = Sibling::Next(PathBuf::from("/b/ai-env-claude"));
        let deprecated = serde_json::json!({"items": [{"imageArn": "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1", "imageVersion": BASE_IMAGE_VERSION, "status": "DEPRECATED"}]}).to_string();
        let not_found = "An error occurred (NotFoundException) when calling the DescribeBudget operation: Unable to get budget: ai-env-monthly - the budget doesn't exist.";
        let table: Vec<(&str, DoctorLine)> = vec![
            ("the wrapper path missing", row_wrapper_setting(Some(&missing), &|_| (false, false), &next).remove(0)),
            ("the wrapper path missing, the sibling too", row_wrapper_setting(Some(&missing), &|_| (false, false), &Sibling::Missing).remove(0)),
            ("the wrapper path not executable", row_wrapper_setting(Some(&missing), &|_| (true, false), &next).remove(0)),
            ("the wrapper path not executable, the sibling missing", row_wrapper_setting(Some(&missing), &|_| (true, false), &Sibling::Missing).remove(0)),
            ("the sibling missing", row_sibling(&Sibling::Missing)),
            ("ai-env-claude's skew", row_same_version(Some("ai-env-claude 0.0.9"), "0.1.0")),
            ("the image shim", row_shim_version("0.11.0", Some("0.11.0"), Some("0.1.0"), None).remove(0)),
            ("image findings", row_image_scan(&ImageScan::Scanned { rules: vec!["symlink".into()], files: 7 }, None, None).remove(0)),
            ("the budget missing", row_budget(Some("ai-env-monthly"), Some(Err(not_found)))),
            ("a DEPRECATED base image", row_base_image(Some(Ok(&deprecated)))),
            ("the runtime credentials not sealed", row_runtime_credentials(&AwsEnvState::NotSealed("is not an ai-env container".into()), Path::new("/r/credentials/aws.env"))),
        ];
        for (case, line) in table {
            let (tag, t) = text(&line);
            assert_eq!(tag, Tag::No, "{case}: {t}");
            let fix = t.split_once("  <- ").map(|(_, f)| f.trim()).unwrap_or_else(|| panic!("{case}: no fix: {t}"));
            assert!(!fix.is_empty(), "{case}: an empty fix: {t}");
            assert_eq!(crate::commands::doctor_exit_code(&[DoctorLine::row(Tag::Ok, "fine"), line], false), 1, "{case}");
        }
    }

    /// L7: ai-env against the image's recorded shim (equality), the sibling
    /// named when it is the same; then the newest live VM's shim when it is
    /// older, its fix the session's migrate or the VM's terminate.
    #[test]
    fn row_shim_version_three_legs() {
        let rows = |sib: Option<&str>, img: Option<&str>, live: Option<&LiveShim>| -> Vec<(Tag, String)> { row_shim_version("0.11.0", sib, img, live).iter().map(text).collect() };
        assert_eq!(rows(Some("0.11.0"), None, None), vec![(Tag::Skip, "image shim version not recorded (state/infra.toml)  <- make infra-status WRITE=1".to_string())]);
        assert_eq!(rows(Some("0.11.0"), Some(" "), None)[0].0, Tag::Skip, "a blank record is none");
        assert_eq!(rows(Some("0.11.0"), Some("0.1.0"), None), vec![(Tag::No, "image shim 0.1.0 ≠ ai-env 0.11.0  <- make deploy, then make infra-status WRITE=1".to_string())]);
        // B3-R4 (I1): an image shim newer than this ai-env is cleared by installing it; one that does not parse keeps the deploy.
        assert_eq!(rows(Some("0.11.0"), Some("0.12.0"), None), vec![(Tag::No, "image shim 0.12.0 ≠ ai-env 0.11.0  <- install with: cargo install --path crates/ai-env-cli --locked".to_string())]);
        assert_eq!(rows(Some("0.11.0"), Some("dev"), None), vec![(Tag::No, "image shim dev ≠ ai-env 0.11.0  <- make deploy, then make infra-status WRITE=1".to_string())]);
        assert_eq!(rows(Some("0.11.0"), Some("0.11.0"), None), vec![(Tag::Ok, "ai-env 0.11.0 = ai-env-claude 0.11.0 = image shim 0.11.0".to_string())]);
        for sib in [None, Some("0.10.0")] {
            assert_eq!(rows(sib, Some("0.11.0"), None), vec![(Tag::Ok, "ai-env 0.11.0 = image shim 0.11.0".to_string())], "{sib:?}: row_same_version names the sibling");
        }
        let live = |shim: &str, session: Option<&str>| LiveShim { vm: "microvm-a".into(), shim: shim.into(), session: session.map(str::to_string) };
        let sid = "01926f2e-0000-7000-8000-00000000000a";
        let with = rows(Some("0.11.0"), Some("0.11.0"), Some(&live("0.1.0", Some(sid))));
        assert_eq!(with.len(), 2, "{with:?}");
        assert_eq!(with[1], (Tag::Warn, format!("microvm-a runs shim 0.1.0, older than ai-env 0.11.0  <- ai-env session migrate {sid}")));
        let without = rows(Some("0.11.0"), None, Some(&live("0.1.0", None)));
        assert_eq!(without[1], (Tag::Warn, "microvm-a runs shim 0.1.0, older than ai-env 0.11.0  <- ai-env vm terminate microvm-a".to_string()), "whatever the image's record");
        for not_older in ["0.11.0", "0.12.0", "0.11.0-rc.1", "not a version", "0.1"] {
            assert_eq!(rows(Some("0.11.0"), Some("0.11.0"), Some(&live(not_older, None))).len(), 1, "{not_older}");
        }
        assert_eq!(crate::commands::doctor_exit_code(&row_shim_version("0.11.0", None, Some("0.11.0"), Some(&live("0.1.0", None))), false), 0, "the live leg warns");

        // The newest live row (by created) whose /health named its shim, and the session (not closed) on it.
        let row = |id: &str, status: RowStatus, created: &str, shim: Option<&str>| VmRow { shim_version: shim.map(str::to_string), ..vm(id, status, created) };
        let session = |sid: &str, status: &str, seen: &str| crate::bridge::registry::SessionRow { session_id: sid.into(), microvm_id: Some("microvm-new".into()), status: status.into(), last_seen: seen.into(), ..Default::default() };
        let vms = [
            row("microvm-old", RowStatus::Running, "2026-10-20T08:00:00.000Z", Some("0.1.0")),
            row("microvm-new", RowStatus::Suspended, "2026-10-22T08:00:00.000Z", Some("0.1.0")),
            row("microvm-unread", RowStatus::Running, "2026-10-23T08:00:00.000Z", None),
            row("microvm-gone", RowStatus::Terminated, "2026-10-23T09:00:00.000Z", Some("0.0.1")),
        ];
        let (closed, open) = ("01926f2e-0000-7000-8000-00000000000a", "01926f2e-0000-7000-8000-00000000000b");
        let sessions = [session(closed, "closed", "2026-10-23T10:00:00Z"), session(open, "active", "2026-10-22T10:00:00Z"), session("not-a-session-id", "active", "2026-10-23T11:00:00Z")];
        assert_eq!(live_shim(&vms, &sessions), Some(LiveShim { vm: "microvm-new".into(), shim: "0.1.0".into(), session: Some(open.into()) }));
        assert_eq!(live_shim(&vms, &[]).map(|l| l.session), Some(None));
        assert_eq!(live_shim(&vms[2..], &sessions), None, "no live row named its shim");
        // As rows() reads the session registry: none yet is no session; one that cannot be read judges nothing (its
        // VM would look session-less, the fix a terminate) and says so.
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::from_root_and_env(d.path().to_path_buf(), None);
        assert_eq!(live_shim_of(&paths, &vms), (Some(LiveShim { vm: "microvm-new".into(), shim: "0.1.0".into(), session: None }), None));
        // B3's review: one row that cannot be read (its VM would look session-less) judges nothing either.
        std::fs::create_dir_all(paths.sessions()).unwrap();
        std::fs::write(paths.sessions().join(format!("{open}.toml")), "session_id = [ not toml").unwrap();
        let (none, unread) = live_shim_of(&paths, &vms);
        let (tag, t) = text(&unread.expect("a warning"));
        assert!(none.is_none() && tag == Tag::Warn && t.starts_with(&format!("live VM shim not checked: session registry unreadable: 1 row(s) cannot be read ({open}: ")), "{t}");
        std::fs::remove_dir_all(paths.sessions()).unwrap();
        std::fs::write(paths.sessions(), "not a directory").unwrap();
        let (none, unread) = live_shim_of(&paths, &vms);
        assert_eq!(none, None);
        let (tag, t) = text(&unread.expect("a warning"));
        assert_eq!(tag, Tag::Warn);
        assert!(t.starts_with("live VM shim not checked: session registry unreadable: ") && !t.contains("terminate"), "{t}");
    }

    /// The checkout's image/ scan names rules only, sorted and unique, with
    /// their count; a deployed zip other than image.json's is one warning.
    #[test]
    fn row_image_scan_rows() {
        let one = |scan: &ImageScan| -> Vec<(Tag, String)> { row_image_scan(scan, None, None).iter().map(text).collect() };
        assert_eq!(one(&ImageScan::NotACheckout), vec![(Tag::Skip, "image/ not scanned: not in an ai-env checkout".to_string())]);
        assert_eq!(one(&ImageScan::Failed("/c/image/claude/settings.json is not a regular file".into())), vec![(Tag::Warn, "image/ scan failed: /c/image/claude/settings.json is not a regular file".to_string())]);
        assert_eq!(one(&ImageScan::Scanned { rules: vec![], files: 7 }), vec![(Tag::Ok, "image/ scan: clean (7 files)".to_string())]);
        let found = ImageScan::Scanned { rules: vec!["unexpected-key".into(), "symlink".into(), "unexpected-key".into()], files: 7 };
        assert_eq!(one(&found), vec![(Tag::No, "image/ has 3 finding(s): symlink, unexpected-key  <- fix them, then make image-zip and make deploy".to_string())]);
        let (a, b) = ("ab".repeat(32), "cd".repeat(32));
        assert_eq!(row_image_scan(&found, Some(&a), Some(&a.to_uppercase())).len(), 1, "the same zip");
        assert_eq!(row_image_scan(&found, Some(&a), None).len(), 1, "nothing staged: nothing to compare");
        assert_eq!(row_image_scan(&found, None, Some(&b)).len(), 1, "nothing deployed: nothing to compare");
        let rows = row_image_scan(&ImageScan::Scanned { rules: vec![], files: 7 }, Some(&a), Some(&b));
        assert_eq!(text(&rows[1]), (Tag::Warn, format!("the deployed image zip {} is not target/image/image.json's {} (the zip that passed the scan)  <- make image-zip, then make deploy", &a[..12], &b[..12])));
        assert_eq!(text(&row_image_scan(&found, Some("not hex"), Some(&b))[1]).1, format!("the deployed image zip ? is not target/image/image.json's {} (the zip that passed the scan)  <- make image-zip, then make deploy", &b[..12]));
        // image.json's sha256 as make image-zip writes it; anything else is no record.
        let d = tempfile::tempdir().unwrap();
        assert_eq!(staged_zip_sha256(d.path()), None);
        let file = d.path().join("target").join("image").join("image.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, format!("{{\"zip\":\"target/image/ai-env-image.zip\",\"sha256\":\"{b}\",\"key\":\"ai-env/image-{}.zip\",\"claudeVersion\":\"2.1.305\",\"shimVersion\":\"0.1.0\"}}\n", &b[..16])).unwrap();
        assert_eq!(staged_zip_sha256(d.path()), Some(b.clone()));
        std::fs::write(&file, "{\"sha256\": \"not hex\"}").unwrap();
        assert_eq!(staged_zip_sha256(d.path()), None);
        // Never through a symlink, never a FIFO (opened without blocking), never past 64 KiB.
        std::fs::write(d.path().join("real.json"), format!("{{\"sha256\":\"{b}\"}}")).unwrap();
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink(d.path().join("real.json"), &file).unwrap();
        assert_eq!(staged_zip_sha256(d.path()), None, "a symlink");
        std::fs::remove_file(&file).unwrap();
        assert!(std::process::Command::new("mkfifo").arg(&file).status().unwrap().success());
        assert_eq!(staged_zip_sha256(d.path()), None, "a FIFO");
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, format!("{{\"sha256\":\"{b}\",\"pad\":\"{}\"}}", " ".repeat(64 * 1024))).unwrap();
        assert_eq!(staged_zip_sha256(d.path()), None, "oversized");
    }

    /// The image scan's checkout, found without running git: the nearest `.git`, a directory or a worktree's file.
    #[test]
    fn checkout_root_is_the_nearest_dot_git() {
        let d = tempfile::tempdir().unwrap();
        let (top, nested) = (d.path().join("top"), d.path().join("top").join("a").join("b"));
        std::fs::create_dir_all(top.join(".git")).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(checkout_root(&nested), Some(top.as_path()));
        assert_eq!(checkout_root(&top), Some(top.as_path()));
        let worktree = top.join("a");
        std::fs::write(worktree.join(".git"), "gitdir: ../.git/worktrees/a\n").unwrap();
        assert_eq!(checkout_root(&nested), Some(worktree.as_path()), "a worktree's .git file");
    }

    /// L8: the budget as the verified operator; its account never in a row.
    #[test]
    fn row_budget_rows() {
        let acct = "7".repeat(12);
        assert_eq!(budget_args(&acct, "ai-env-monthly"), ["budgets", "describe-budget", "--account-id", acct.as_str(), "--budget-name", "ai-env-monthly", "--region", "eu-central-1", "--output", "json"]);
        let name = Some("ai-env-monthly");
        assert_eq!(text(&row_budget(None, None)), (Tag::Skip, "budget not checked: no budget name in bridge.toml [aws] or state/infra.toml  <- make infra-status WRITE=1".to_string()));
        assert_eq!(text(&row_budget(Some("  "), Some(Ok("{}")))).0, Tag::Skip, "a blank name is none");
        assert_eq!(text(&row_budget(name, None)), (Tag::Skip, "budget ai-env-monthly not checked (no operator identity: ai-env as ops -- ai-env doctor)".to_string()));
        let answer = serde_json::json!({"Budget": {"BudgetName": "ai-env-monthly", "BudgetLimit": {"Amount": "50.0", "Unit": "USD"}, "TimeUnit": "MONTHLY", "BudgetType": "COST", "CalculatedSpend": {"ActualSpend": {"Amount": "3.21", "Unit": "USD"}, "ForecastedSpend": {"Amount": "9.0", "Unit": "USD"}}}}).to_string();
        assert_eq!(text(&row_budget(name, Some(Ok(&answer)))), (Tag::Ok, "budget ai-env-monthly: 50.0 USD monthly, 3.21 spent".to_string()));
        // B-DOC-1: a spend at or over its limit is a warning naming the cost view; one below it stays [ok ].
        for (spent, tag) in [("50", Tag::Warn), ("50.00", Tag::Warn), ("72.4", Tag::Warn), ("49.99", Tag::Ok)] {
            let row = row_budget(name, Some(Ok(&answer.replace("\"3.21\"", &format!("\"{spent}\"")))));
            let want = if tag == Tag::Warn { format!("budget ai-env-monthly: {spent} spent of 50.0 USD monthly  <- ai-env cost --by day") } else { format!("budget ai-env-monthly: 50.0 USD monthly, {spent} spent") };
            assert_eq!(text(&row), (tag, want), "{spent}");
        }
        // Digits and dots that make no number: no verdict, the budget exists.
        assert_eq!(text(&row_budget(name, Some(Ok(&answer.replace("\"3.21\"", "\"3.2.1\""))))), (Tag::Ok, "budget ai-env-monthly exists".to_string()));
        let other_unit = answer.replace("\"3.21\",\"Unit\":\"USD\"", "\"3.21\",\"Unit\":\"EUR\"");
        assert_ne!(other_unit, answer);
        assert_eq!(text(&row_budget(name, Some(Ok(&other_unit)))), (Tag::Ok, "budget ai-env-monthly exists".to_string()), "a spend in another unit than the limit");
        let no_spend = serde_json::json!({"Budget": {"BudgetName": "ai-env-monthly", "BudgetLimit": {"Amount": "50.0", "Unit": "USD"}, "TimeUnit": "MONTHLY"}}).to_string();
        for exists in [no_spend.as_str(), "not json", "{\"Budget\": {\"BudgetLimit\": {\"Amount\": \"5\\n0\", \"Unit\": \"USD\"}}}"] {
            assert_eq!(text(&row_budget(name, Some(Ok(exists)))), (Tag::Ok, "budget ai-env-monthly exists".to_string()), "{exists}");
        }
        let missing = "An error occurred (NotFoundException) when calling the DescribeBudget operation: Unable to get budget: ai-env-monthly - the budget doesn't exist.";
        assert_eq!(text(&row_budget(name, Some(Err(missing)))), (Tag::No, "budget ai-env-monthly missing  <- make deploy".to_string()));
        let denied = format!("An error occurred (AccessDeniedException) when calling the DescribeBudget operation: User: arn:aws:iam::{acct}:user/ai-env-ops is not authorized to perform: budgets:ViewBudget on resource: arn:aws:budgets::{acct}:budget/ai-env-monthly");
        let row = row_budget(name, Some(Err(&denied)));
        assert_eq!(text(&row), (Tag::Warn, "budget ai-env-monthly not checked: AccessDenied  <- make deploy (ai-env-ops gains budgets:ViewBudget, S11 L8)".to_string()));
        assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0);
        let other = format!("An error occurred (ThrottlingException) when calling the DescribeBudget operation for {acct}: Rate exceeded");
        let (tag, t) = text(&row_budget(name, Some(Err(&other))));
        assert_eq!((tag, t.as_str()), (Tag::Warn, "budget ai-env-monthly not checked: An error occurred (ThrottlingException) when calling the DescribeBudget operation for <acct>: Rate exceeded"));
        assert!(!t.contains(&acct), "{t}");
    }

    /// The listing row_base_image reads: AVAILABLE versions above the pin,
    /// in version order; a DEPRECATED pin stays row_base_image's [NO ].
    #[test]
    fn row_base_image_newer_names_available_versions() {
        let item = |v: &str, s: &str| serde_json::json!({"imageArn": "arn:aws:lambda:eu-central-1:aws:microvm-image:al2023-1", "imageVersion": v, "status": s});
        let listing = |items: Vec<serde_json::Value>| serde_json::json!({ "items": items }).to_string();
        assert_eq!(row_base_image_newer(None), None);
        assert_eq!(row_base_image_newer(Some(Err("aws: timed out after 15s"))), None, "row_base_image says it");
        assert_eq!(row_base_image_newer(Some(Ok("not json"))), None);
        assert_eq!(row_base_image_newer(Some(Ok(&listing(vec![item(BASE_IMAGE_VERSION, "AVAILABLE")])))), None);
        assert_eq!(row_base_image_newer(Some(Ok(&listing(vec![item("2", "DEPRECATED"), item("3", "EXPIRING"), item("0", "AVAILABLE")])))), None, "only AVAILABLE versions above the pin");
        let json = listing(vec![item("3", "AVAILABLE"), item("1", "AVAILABLE"), item("2", "AVAILABLE"), item("2.0", "AVAILABLE"), item("4", "EXPIRING"), item("x", "AVAILABLE")]);
        let row = row_base_image_newer(Some(Ok(&json))).expect("two newer versions");
        assert_eq!(text(&row), (Tag::Warn, "newer al2023-1 version(s) 2, 3 AVAILABLE (pinned 1)  <- infra/image-config.json".to_string()));
        assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0);
        let json = listing(vec![item(BASE_IMAGE_VERSION, "DEPRECATED"), item("2", "AVAILABLE")]);
        assert_eq!(text(&row_base_image(Some(Ok(&json)))).0, Tag::No);
        assert_eq!(row_base_image_newer(Some(Ok(&json))).map(|r| text(&r).0), Some(Tag::Warn));
    }

    #[test]
    fn rows_roots_exist_warn_per_missing_root() {
        let cfg = BridgeConfig::parse("[workspaces]\nroots = [\"/w/here\", \"/w/gone\"]\n").unwrap();
        let rows: Vec<(Tag, String)> = rows_roots_exist(&cfg, &|p: &Path| p == Path::new("/w/here")).iter().map(text).collect();
        assert_eq!(rows, vec![(Tag::Warn, "workspace root /w/gone does not exist  <- create it, or remove it from bridge.toml".to_string())]);
        assert!(rows_roots_exist(&cfg, &|_| true).is_empty());
        assert_eq!(rows_roots_exist(&cfg, &|_| false).len(), 2, "one row per root");
        assert!(rows_roots_exist(&BridgeConfig::default(), &|_| false).is_empty(), "no root, no row");
        // As rows() calls it: a directory is a root, a file or nothing is not.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("file"), "x").unwrap();
        let (dir, file, gone) = (d.path().display(), d.path().join("file"), d.path().join("gone"));
        let cfg = BridgeConfig::parse(&format!("[workspaces]\nroots = [\"{dir}\", \"{}\", \"{}\"]\n", file.display(), gone.display())).unwrap();
        let rows: Vec<String> = rows_roots_exist(&cfg, &|p: &Path| p.is_dir()).iter().map(|r| text(r).1).collect();
        assert_eq!(rows, vec![format!("workspace root {} does not exist  <- create it, or remove it from bridge.toml", file.display()), format!("workspace root {} does not exist  <- create it, or remove it from bridge.toml", gone.display())]);
    }

    #[test]
    fn row_image_version_pin_warns_off_active() {
        let state = |active: Option<&str>| InfraState { latest_active_image_version: active.map(str::to_string), ..InfraState::default() };
        let pinned = |v: &str| BridgeConfig::parse(&format!("[aws]\nimage_version = \"{v}\"\n")).unwrap();
        assert_eq!(row_image_version_pin(&BridgeConfig::default(), Some(&state(Some("12.0")))), None, "active follows the recorded version");
        assert_eq!(row_image_version_pin(&pinned("12"), Some(&state(Some("12.0")))), None, "N is N.0");
        assert_eq!(row_image_version_pin(&pinned("12.0"), Some(&state(Some("12")))), None, "an older state's N");
        assert_eq!(row_image_version_pin(&pinned("11"), Some(&state(None))), None, "no recorded active version");
        assert_eq!(row_image_version_pin(&pinned("11"), None), None);
        let row = row_image_version_pin(&pinned("11"), Some(&state(Some("12.0")))).expect("pinned off active");
        assert_eq!(text(&row), (Tag::Warn, "[aws].image_version = 11 is pinned, but the active version is 12.0: new VMs run 11  <- image_version = \"active\" in bridge.toml".to_string()));
        assert_eq!(crate::commands::doctor_exit_code(&[row], false), 0);
    }

    #[test]
    fn a_bypass_permission_mode_is_a_warning() {
        let sib = Sibling::Next(PathBuf::from("/b/ai-env-claude"));
        let s = parse_settings("{\"claudeCode.claudeProcessWrapper\": \"/b/ai-env-claude\", \"claudeCode.initialPermissionMode\": \"bypassPermissions\"}").unwrap();
        let rows = row_wrapper_setting(Some(&s), &|_| (true, true), &sib);
        assert_eq!(
            rows.iter().map(text).collect::<Vec<_>>(),
            vec![
                (Tag::Ok, format!("{WRAPPER_SETTING} = /b/ai-env-claude")),
                (Tag::Warn, format!("{PERMISSION_SETTING} = bypassPermissions: every chat starts with no permission prompt  <- ai-env wrapper install --write --permission-mode default")),
            ]
        );
        assert_eq!(crate::commands::doctor_exit_code(&rows, false), 0, "a warning, not a failure");
        for mode in ["default", "manual", "acceptEdits", "plan"] {
            let s = parse_settings(&format!("{{\"claudeCode.initialPermissionMode\": \"{mode}\"}}")).unwrap();
            assert_eq!(text(&row_wrapper_setting(Some(&s), &|_| (true, true), &sib)[1]), (Tag::Ok, format!("{PERMISSION_SETTING} = {mode}")), "{mode}");
        }
    }
}
