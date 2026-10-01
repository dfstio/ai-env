//! SELECT_VM and RUN_VM (plan S4 D6–D16, D26, D28, §7, step 6): the run plan
//! resolved from `bridge.toml` and the flags (image, version, idle policy,
//! egress, ingress, execution role, workspace), the session token and the
//! run-hook payload that commits to it, the per-workspace lock and the
//! placement lock, the pending row written before `RunMicrovm`, the RUNNING
//! poll, reuse of a workspace VM, termination with the row updated, and the
//! adoption sweep after an ambiguous `RunMicrovm`.
//!
//! The S5 egress echo gate runs at all three places a VM becomes this
//! bridge's: after `RunMicrovm` ([`select_vm_detailed`]), before a reuse
//! (`try_reuse`) and before an adoption (the sweep and gc's `adopt`). A VM
//! that does not echo exactly the connectors its egress requires is
//! terminated (`terminated_by = policy`), audited `vm_egress_mismatch`, and
//! the caller gets [`BridgeError::EgressMismatch`] (exit 9).
//!
//! The session token lives in the VM row only (0600, plan §2.4); the payload
//! carries `sha256(token)`, and no audit row, log line or error text ever
//! carries the token (it is registered with the scrubber as well).
use crate::bridge::api::{self, EndpointClient, ImageVersion, IdleSpec, MicrovmApi, RunSpec, VmInfo, VmState, VmSummary};
use crate::bridge::audit::{self, AuditRow};
use crate::bridge::config::{BridgeConfig, Paths};
use crate::bridge::egress::{ConnectorAlias, ExpectedEcho};
use crate::bridge::errors::BridgeError;
use crate::bridge::route::cwd_under_roots;
use crate::bridge::vm::gc::EXPIRY_MARGIN_S;
use crate::bridge::vm::lock::lock_exclusive;
use crate::bridge::vm::owner;
use crate::bridge::vm::registry::{self, IdleRow, RowStatus, VmRow, GATE_MISMATCH, GATE_PASSED, GATE_PENDING, PENDING_STALE_S};
use crate::wire::frame::{commitment_hex, Health, RunHookPayload, WireError};
use crate::wire::redact::{register_secret, Secret};
use crate::wire::slug::project_dir_name;
use crate::wire::time::{parse_rfc3339_utc, rfc3339_utc_ms, unix_now, unix_now_ms};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long `select_vm` waits for `state/workspaces/<slug>.lock` (plan S4 D14:
/// the worst hold is ≈ 270 s — placement wait, ListMicrovms, two RunMicrovm
/// attempts and the RUNNING poll).
pub const WORKSPACE_LOCK_BUDGET: Duration = Duration::from_secs(300);

/// How long `select_vm` waits for `state/vms.lock` (held ≈ 45 s at worst).
pub const PLACEMENT_LOCK_BUDGET: Duration = Duration::from_secs(90);

/// The smallest `--idle` / `[vm].max_idle_s` (plan §2.8: suspending sooner costs more than it saves).
pub const MIN_IDLE_S: u32 = 300;

/// The service's maximum run duration (8 h).
pub const MAX_DURATION_S: u32 = 28_800;

/// Minutes of the internal Port(8080) tokens (gc and the adoption sweep).
pub const PROBE_TOKEN_MINUTES: u16 = 5;

/// How far before `created` / `since` a VM's start may lie and still be the
/// run a pending row describes (clock skew between the Mac and the service).
pub const START_SKEW_S: u64 = 60;

// ---- egress ----------------------------------------------------------------------------

/// Where a VM's outbound traffic goes (`--egress internet|vpc`, plan S4 D10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Egress {
    /// The platform default (`INTERNET_EGRESS`): no connector is sent; audited.
    Internet,
    /// `[aws].egress_connector_arn` (the S5 proxy VPC).
    Vpc,
}

impl Egress {
    /// `internet` | `vpc` (the flag value and the row's `egress`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Egress::Internet => "internet",
            Egress::Vpc => "vpc",
        }
    }
}

impl fmt::Display for Egress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Egress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "internet" => Ok(Egress::Internet),
            "vpc" => Ok(Egress::Vpc),
            other => Err(format!("egress {other:?}: expected internet or vpc")),
        }
    }
}

/// The egress a run gets and the connectors `RunMicrovm` is given (plan S4
/// D10): `vpc` needs `[aws].egress_connector_arn` (else `EgressRequired`,
/// exit 9); without a flag a configured connector means `vpc`; without a flag
/// and without a connector the platform's internet egress is used only when
/// the caller implies it (`vm smoke`, `lab run`) or `[egress].require` is
/// false, else `EgressRequired`. `internet` sends no connector.
pub fn effective_egress(cfg: &BridgeConfig, flag: Option<Egress>, imply_internet: bool) -> Result<(Egress, Vec<String>), BridgeError> {
    let connector = cfg.aws.egress_connector_arn.clone().filter(|a| !a.trim().is_empty());
    match (flag, connector) {
        (Some(Egress::Internet), _) => Ok((Egress::Internet, Vec::new())),
        (Some(Egress::Vpc) | None, Some(arn)) => Ok((Egress::Vpc, vec![arn])),
        (Some(Egress::Vpc), None) => Err(BridgeError::EgressRequired),
        (None, None) if imply_internet || !cfg.egress.require => Ok((Egress::Internet, Vec::new())),
        (None, None) => Err(BridgeError::EgressRequired),
    }
}

// ---- flags and plan --------------------------------------------------------------------

/// What `ai-env vm run` (and `vm smoke`, `lab run`) asked for, before
/// `bridge.toml` fills the gaps ([`RunPlan::from_cfg`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunFlags {
    /// `--image ARN` (default `[aws].image_arn`).
    pub image: Option<String>,
    /// `--version V`: `active`, `N` or `N.M` (default `[aws].image_version`).
    pub version: Option<String>,
    /// `--max-duration S` (default `[vm].max_duration_s`).
    pub max_duration_s: Option<u32>,
    /// `--idle S` (default `[vm].max_idle_s`, at least [`MIN_IDLE_S`]).
    pub idle_s: Option<u32>,
    /// `--suspended S` (default `min([vm].suspended_s, max duration)`).
    pub suspended_s: Option<u32>,
    /// `--no-auto-resume`.
    pub no_auto_resume: bool,
    /// `--egress internet|vpc`.
    pub egress: Option<Egress>,
    /// `--workspace PATH`: lock, reuse and the row's workspace.
    pub workspace: Option<PathBuf>,
    /// `--new`: never reuse a workspace VM.
    pub new: bool,
    /// `--label TEXT`, kept in the row.
    pub label: Option<String>,
    /// `--shell`: also pass the `SHELL_INGRESS` connector.
    pub shell: bool,
    /// `--no-execution-role`: run without `[aws].execution_role_arn`.
    pub no_execution_role: bool,
    /// Wait until RUNNING (`--no-wait` clears it).
    pub wait: bool,
    /// Who asks: `operator` | `smoke` | `probe` | `test` (audited).
    pub purpose: &'static str,
    /// `vm smoke` and `lab run`: internet egress without a flag (audited).
    pub imply_internet: bool,
    /// `lab run idle-policy-limits` only: send idle values outside the plan's ranges.
    pub allow_out_of_range_idle: bool,
}

impl Default for RunFlags {
    fn default() -> Self {
        RunFlags {
            image: None,
            version: None,
            max_duration_s: None,
            idle_s: None,
            suspended_s: None,
            no_auto_resume: false,
            egress: None,
            workspace: None,
            new: false,
            label: None,
            shell: false,
            no_execution_role: false,
            wait: true,
            purpose: "operator",
            imply_internet: false,
            allow_out_of_range_idle: false,
        }
    }
}

/// Everything a run needs, resolved from `bridge.toml` and [`RunFlags`];
/// only the image version (`want_version`) is resolved later, live, by
/// [`resolve_image_version`] inside [`select_vm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPlan {
    pub image_arn: String,
    /// `active`, `N` or `N.M` as asked.
    pub want_version: String,
    pub max_duration_s: u32,
    /// The idle policy as sent (always passed, plan S4 D8).
    pub idle: IdleSpec,
    pub egress: Egress,
    /// Empty for `internet`; `[aws].egress_connector_arn` for `vpc`.
    pub egress_connectors: Vec<String>,
    /// Empty (the platform's HTTP_INGRESS) unless `shell`.
    pub ingress_connectors: Vec<String>,
    pub shell: bool,
    pub execution_role_arn: Option<String>,
    /// The canonical workspace and its project dir name (the lock's name).
    pub workspace: Option<(PathBuf, String)>,
    pub new: bool,
    pub label: Option<String>,
    pub wait: bool,
    /// `[vm].max_concurrent` (at least 1).
    pub max_concurrent: u32,
    /// `[vm].reuse_per_workspace && !--new`.
    pub reuse: bool,
    /// `[vm].migrate_before_wall_s`: a VM with less wall time left is never reused.
    pub migrate_before_wall_s: u32,
    pub purpose: &'static str,
    /// One line each for the operator (execution role unset, a VM that will
    /// never be reused), without the `ai-env:` prefix.
    pub warnings: Vec<String>,
    /// `[vm].memory_mib`: the quota input (plan S4 D7); `select_vm` warns
    /// when the resolved version's memory differs.
    pub memory_mib: u32,
    /// The pending row's client token (a uuid) instead of a fresh uuid v7:
    /// `vm smoke` sets it so it can sweep exactly its own run. `None` from
    /// [`RunPlan::from_cfg`].
    pub client_token: Option<String>,
    /// Pad the run-hook payload with spaces after its opening `{` to exactly
    /// this many bytes ([`padded_payload`]); shorter than the payload is a
    /// config error, longer than 4096 is sent as is (the API decides).
    /// `None` from [`RunPlan::from_cfg`].
    pub pad_payload_to: Option<usize>,
}

/// `arn:aws:lambda:eu-central-1:<12 digits>:microvm-image:<name>` — the form
/// `ListMicrovms`/`GetMicrovm` echo, so rows and listings compare exactly.
#[must_use]
pub fn is_image_arn(s: &str) -> bool {
    let Some(rest) = s.strip_prefix(&format!("arn:aws:lambda:{}:", crate::bridge::config::REGION)) else { return false };
    let Some((account, name)) = rest.split_once(":microvm-image:") else { return false };
    account.len() == 12 && account.bytes().all(|c| c.is_ascii_digit()) && !name.is_empty() && name.len() <= 128 && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

/// A refusal naming where the value came from: a flag is a policy refusal
/// (exit 9), a `bridge.toml` key a config error (exit 1).
fn refuse(source: &str, why: String) -> BridgeError {
    if source.starts_with("--") {
        BridgeError::Policy(format!("{source} {why}"))
    } else {
        BridgeError::Config(format!("{source} = {why}"))
    }
}

/// The service's `Integer`: out-of-range values are refused, never clamped.
fn to_i32(value: u32, source: &str) -> Result<i32, BridgeError> {
    i32::try_from(value).map_err(|_| refuse(source, format!("{value}: exceeds {} (values are never clamped)", i32::MAX)))
}

impl RunPlan {
    /// Resolve `flags` against `cfg` (plan S4 §7 POLICY): the image ARN
    /// (`--image` or `[aws].image_arn`, else a config error naming
    /// `make infra-status WRITE=1`), the max duration (1..=28800), the idle
    /// policy (D8: idle ≥ 300, suspended defaults to `min([vm].suspended_s,
    /// max duration)` and may not exceed it; `allow_out_of_range_idle`
    /// lifts both for the lab; nothing is clamped), egress
    /// ([`effective_egress`]), ingress (D11), the execution role (D12) and the
    /// workspace (canonicalised, under `cfg.roots()` or `OutsideRoots`, exit
    /// 9). A refused flag is exit 9 naming the flag; a refused config value is
    /// exit 1 naming the key.
    pub fn from_cfg(cfg: &BridgeConfig, flags: &RunFlags) -> Result<RunPlan, BridgeError> {
        let image_arn = flags
            .image
            .clone()
            .or_else(|| cfg.aws.image_arn.clone())
            .filter(|a| !a.trim().is_empty())
            .ok_or_else(|| BridgeError::Config("[aws].image_arn is not set in bridge.toml and no --image was given (run `make infra-status WRITE=1`)".into()))?;
        // The canonical ARN only: gc matches rows against the ARN the service echoes.
        if !is_image_arn(&image_arn) {
            let src = if flags.image.is_some() { "--image" } else { "[aws].image_arn" };
            return Err(refuse(src, format!("{image_arn:?}: expected arn:aws:lambda:{}:<account>:microvm-image:<name>", crate::bridge::config::REGION)));
        }
        let want_version = flags.version.clone().unwrap_or_else(|| cfg.aws.image_version.clone());
        if cfg.vm.max_concurrent == 0 {
            return Err(BridgeError::Config("[vm].max_concurrent = 0: must be at least 1".into()));
        }
        let (max_duration_s, max_src) = match flags.max_duration_s {
            Some(v) => (v, "--max-duration"),
            None => (cfg.vm.max_duration_s, "[vm].max_duration_s"),
        };
        if !(1..=MAX_DURATION_S).contains(&max_duration_s) {
            return Err(refuse(max_src, format!("{max_duration_s}: must be 1..={MAX_DURATION_S} s (the service maximum)")));
        }
        debug_assert!(matches!(flags.purpose, "operator" | "smoke" | "probe" | "test"), "unknown run purpose {:?}", flags.purpose);
        let idle = idle_spec(cfg, flags, max_duration_s)?;
        let (egress, egress_connectors) = effective_egress(cfg, flags.egress, flags.imply_internet)?;
        let ingress_connectors = if flags.shell { vec![api::managed_connector_arn("HTTP_INGRESS"), api::managed_connector_arn("SHELL_INGRESS")] } else { Vec::new() };
        let configured_role = cfg.aws.execution_role_arn.clone().filter(|a| !a.trim().is_empty());
        let execution_role_arn = if flags.no_execution_role { None } else { configured_role.clone() };
        let workspace = flags.workspace.as_deref().map(|p| resolve_workspace(cfg, p)).transpose()?;
        let reuse = cfg.vm.reuse_per_workspace && !flags.new;
        let mut warnings = Vec::new();
        if configured_role.is_none() && !flags.no_execution_role {
            warnings.push("[aws].execution_role_arn is not set: the VM gets no runtime logs and no run report (run `make infra-status WRITE=1`)".to_string());
        }
        if workspace.is_some() && reuse && max_duration_s <= cfg.vm.migrate_before_wall_s {
            warnings.push(format!("max duration {max_duration_s} s ≤ [vm].migrate_before_wall_s {} s: this VM will never be reused", cfg.vm.migrate_before_wall_s));
        }
        Ok(RunPlan {
            image_arn,
            want_version,
            max_duration_s,
            idle,
            egress,
            egress_connectors,
            ingress_connectors,
            shell: flags.shell,
            execution_role_arn,
            workspace,
            new: flags.new,
            label: flags.label.clone(),
            wait: flags.wait,
            max_concurrent: cfg.vm.max_concurrent,
            reuse,
            migrate_before_wall_s: cfg.vm.migrate_before_wall_s,
            purpose: flags.purpose,
            warnings,
            memory_mib: cfg.vm.memory_mib,
            client_token: None,
            pad_payload_to: None,
        })
    }
}

/// The idle policy of plan S4 D8 (see [`RunPlan::from_cfg`]).
fn idle_spec(cfg: &BridgeConfig, flags: &RunFlags, max_duration_s: u32) -> Result<IdleSpec, BridgeError> {
    let lab = flags.allow_out_of_range_idle;
    let (max_idle, idle_src) = match flags.idle_s {
        Some(v) => (v, "--idle"),
        None => (cfg.vm.max_idle_s, "[vm].max_idle_s"),
    };
    if max_idle < MIN_IDLE_S && !lab {
        return Err(refuse(idle_src, format!("{max_idle}: must be at least {MIN_IDLE_S} s (plan §2.8: suspending sooner costs more than it saves)")));
    }
    let (suspended, susp_src) = match flags.suspended_s {
        Some(v) => (v, "--suspended"),
        None => (cfg.suspended_s().min(max_duration_s), if cfg.vm.suspended_s.is_some() { "[vm].suspended_s" } else { "[vm].max_duration_s" }),
    };
    if suspended == 0 && !lab {
        return Err(refuse(susp_src, "0: must be at least 1 s".to_string()));
    }
    if suspended > max_duration_s && !lab {
        return Err(refuse(susp_src, format!("{suspended}: must not exceed the max duration ({max_duration_s} s)")));
    }
    Ok(IdleSpec { max_idle_s: to_i32(max_idle, idle_src)?, suspended_s: to_i32(suspended, susp_src)?, auto_resume: cfg.vm.auto_resume && !flags.no_auto_resume })
}

/// `--workspace PATH` → (canonical path, project dir name), refused with
/// `OutsideRoots` (exit 9) unless it lies under `cfg.roots()`.
fn resolve_workspace(cfg: &BridgeConfig, path: &Path) -> Result<(PathBuf, String), BridgeError> {
    let canonical = std::fs::canonicalize(path).map_err(|e| BridgeError::Config(format!("--workspace {}: {e}", path.display())))?;
    if !canonical.is_dir() {
        return Err(BridgeError::Config(format!("--workspace {}: not a directory", canonical.display())));
    }
    if canonical.to_str().is_none() {
        // Two such paths could share one lossy row key (and one VM).
        return Err(BridgeError::Config(format!("--workspace {}: the path is not valid UTF-8", canonical.display())));
    }
    if !cwd_under_roots(&canonical, &cfg.roots()) {
        return Err(BridgeError::OutsideRoots(canonical));
    }
    let slug = project_dir_name(&canonical).map_err(|e| BridgeError::Config(format!("--workspace {}: {e}", canonical.display())))?;
    Ok((canonical, slug))
}

/// The row's `workspace` for a canonical path: what reuse (D28) matches on.
/// The slug is lossy (`a.b` and `a_b` share one) and only names the lock.
fn workspace_key(canonical: &Path) -> String {
    canonical.to_string_lossy().into_owned()
}

// ---- session token and payload ---------------------------------------------------------

/// A fresh session token: 32 bytes from the OS random source as 64
/// lowercase hex digits, registered with the scrubber before it is returned.
/// Panics only when the OS random source itself fails (a token of zeros
/// would be worse than no run).
#[must_use]
pub fn new_session_token() -> Secret<String> {
    use zeroize::Zeroize;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("getrandom: the OS random source failed; refusing to mint a session token");
    let token = Secret::new(hex::encode(bytes));
    bytes.zeroize();
    register_secret(token.expose());
    token
}

/// The run-hook payload for `token` (plan S4 D9): `{v, commit, owner,
/// created}` with `commit = sha256(token)`, validated as the shim will
/// validate it. A schema failure is a policy refusal naming the field (exit
/// 9); more than 4096 bytes is `PayloadTooLarge` (exit 9).
pub fn build_payload(token: &Secret<String>, owner: &str, created: &str) -> Result<String, BridgeError> {
    let payload = RunHookPayload::new(token, owner, created);
    let wire = |e: WireError| match e {
        WireError::PayloadTooLarge(n) => BridgeError::PayloadTooLarge(n),
        other => BridgeError::Policy(format!("run-hook payload: {other}")),
    };
    payload.validate().map_err(wire)?;
    payload.to_json().map_err(wire)
}

/// `base` (a JSON object) padded to exactly `len` bytes with spaces right
/// after its opening `{` (`RunHookPayload::from_json` accepts whitespace, so
/// up to 4096 bytes it stays shim-valid). `None` when `len` is shorter than
/// `base` or `base` does not start with `{`.
#[must_use]
pub fn padded_payload(base: &str, len: usize) -> Option<String> {
    let body = base.strip_prefix('{')?;
    let pad = len.checked_sub(base.len())?;
    Some(format!("{{{}{body}", " ".repeat(pad)))
}

// ---- image version ---------------------------------------------------------------------

/// `1.0 (SUCCESSFUL/ACTIVE), 2.0 (FAILED/INACTIVE)` for error texts.
fn listed(versions: &[ImageVersion]) -> String {
    if versions.is_empty() {
        return "none listed".to_string();
    }
    versions.iter().map(|v| format!("{} ({}/{})", v.version, v.state, v.status)).collect::<Vec<_>>().join(", ")
}

/// The version to pass to `RunMicrovm` (plan S4 D6), live on every run:
/// `active` → `GetMicrovmImage.latestActiveImageVersion`, which must also be
/// listed and runnable (SUCCESSFUL + ACTIVE); `N.M` must be listed and
/// runnable; `N` matches `N.0` (returned with a note). Anything unknown or not
/// runnable is a `Validation` error (exit 7) naming every listed version.
pub async fn resolve_image_version<A: MicrovmApi>(api: &A, arn: &str, want: &str) -> Result<(ImageVersion, Option<String>), BridgeError> {
    let versions = api.list_image_versions(arn).await?;
    let find = |v: &str| versions.iter().find(|x| x.version == v);
    let runnable = |v: &ImageVersion, asked: &str| -> Result<ImageVersion, BridgeError> {
        if v.runnable() {
            Ok(v.clone())
        } else {
            Err(BridgeError::Validation(format!("image version {} ({asked}) is {}/{}, not SUCCESSFUL/ACTIVE; listed: {}", v.version, v.state, v.status, listed(&versions))))
        }
    };
    let unknown = |asked: &str| BridgeError::Validation(format!("image version {asked:?} is not a version of {arn}; listed: {}", listed(&versions)));
    if want == "active" {
        let image = api.get_image(arn).await?;
        let Some(latest) = image.latest_active.filter(|v| !v.is_empty()) else {
            return Err(BridgeError::Validation(format!("image {arn} has no active version (latestActiveImageVersion is unset); listed: {}", listed(&versions))));
        };
        return match find(&latest) {
            Some(v) => runnable(v, "active").map(|v| (v, None)),
            None => Err(BridgeError::Validation(format!("the active version {latest} of {arn} is not listed; listed: {}", listed(&versions)))),
        };
    }
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    match want.split_once('.') {
        None if digits(want) => {
            if let Some(v) = find(want) {
                return runnable(v, want).map(|v| (v, None));
            }
            let n0 = format!("{want}.0");
            match find(&n0) {
                Some(v) => runnable(v, want).map(|v| (v, Some(format!("image version {want} = {n0}")))),
                None => Err(unknown(want)),
            }
        }
        Some((major, minor)) if digits(major) && digits(minor) => match find(want) {
            Some(v) => runnable(v, want).map(|v| (v, None)),
            None => Err(unknown(want)),
        },
        _ => Err(BridgeError::Validation(format!("image version {want:?}: expected active, N or N.M; listed: {}", listed(&versions)))),
    }
}

// ---- polling ---------------------------------------------------------------------------

/// A state poll: one `GetMicrovm` every `step` for at most `budget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Poll {
    pub step: Duration,
    pub budget: Duration,
}

impl Poll {
    /// PENDING → RUNNING after `RunMicrovm` / resume: 1 s steps for 60 s (plan S4 D16).
    pub const RUNNING: Poll = Poll { step: Duration::from_secs(1), budget: Duration::from_secs(60) };

    /// Suspend, resume and terminate settling: 1 s steps for 30 s.
    pub const SETTLE: Poll = Poll { step: Duration::from_secs(1), budget: Duration::from_secs(30) };

    /// Every second of step and budget becomes `ms_per_second` milliseconds
    /// (`AI_ENV_BRIDGE_LAB_BACKOFF_MS`; the tests use `Some(1)`); `None`
    /// leaves the poll as it is.
    #[must_use]
    pub fn scaled(self, ms_per_second: Option<u64>) -> Poll {
        let Some(ms) = ms_per_second else {
            return self;
        };
        let scale = |d: Duration| Duration::from_micros(u64::try_from(d.as_micros()).unwrap_or(u64::MAX).saturating_mul(ms) / 1000);
        Poll { step: scale(self.step), budget: scale(self.budget) }
    }
}

/// `12.3 s` / `60 ms` for messages.
fn human(d: Duration) -> String {
    if d >= Duration::from_secs(1) {
        format!("{:.1} s", d.as_secs_f64())
    } else {
        format!("{} ms", d.as_millis())
    }
}

/// A `VmInfo` for a VM the service no longer knows (only its id and state).
fn gone_info(id: &str) -> VmInfo {
    VmInfo {
        id: id.to_string(),
        state: VmState::Terminated,
        endpoint: String::new(),
        image_arn: String::new(),
        image_version: String::new(),
        started_at_unix: None,
        max_duration_s: 0,
        state_reason: None,
        execution_role_arn: None,
        idle: None,
        ingress: Vec::new(),
        egress: Vec::new(),
        terminated_at_unix: None,
    }
}

/// A `GetMicrovm` failure the waits retry within their budget: throttling,
/// an ambiguous failure, and any `Sdk` error of `get_microvm` itself (the
/// real client maps a timeout, a dispatch failure and a 5xx there). An
/// `Endpoint` error of GetMicrovm is a pinned-host violation: final.
/// `ResourceNotFound` is transient only in [`wait_after_run`].
fn transient_get(e: &BridgeError) -> bool {
    matches!(e, BridgeError::Throttled(_) | BridgeError::Ambiguous { .. } | BridgeError::Sdk { op: "get_microvm", .. })
}

/// Poll `GetMicrovm(id)` until the VM is in `want`. TERMINATING/TERMINATED
/// while waiting for a live state is `Terminated` (exit 8) with the
/// `stateReason` (the service's own answer, so a confirmed end);
/// `ResourceNotFound` while waiting for TERMINATED counts as reached (the
/// last answer, or an id-only `VmInfo`, marked TERMINATED), and is final
/// otherwise (exit 8); a transient failure ([`transient_get`]: throttled,
/// ambiguous, an SDK error of `get_microvm`) is retried within the budget; past the budget the result is `Sdk { op:
/// "wait" }` (exit 7) naming the id, the last state and the last error.
pub async fn wait_for_state<A: MicrovmApi>(api: &A, id: &str, want: &VmState, poll: Poll) -> Result<VmInfo, BridgeError> {
    wait_inner(api, id, want, poll, false).await
}

/// The RUNNING poll right after `RunMicrovm` answered: as [`wait_for_state`],
/// but `ResourceNotFound` is retried within the budget too (read-after-create:
/// the new VM may not be visible to `GetMicrovm` yet). Everywhere else a
/// vanished VM is final (exit 8 at once).
pub async fn wait_after_run<A: MicrovmApi>(api: &A, id: &str, poll: Poll) -> Result<VmInfo, BridgeError> {
    wait_inner(api, id, &VmState::Running, poll, true).await
}

async fn wait_inner<A: MicrovmApi>(api: &A, id: &str, want: &VmState, poll: Poll, not_found_transient: bool) -> Result<VmInfo, BridgeError> {
    let start = Instant::now();
    let mut last: Option<VmInfo> = None;
    // Set by every answer: the error of this round, or none after a state.
    let mut last_error: Option<String>;
    loop {
        match api.get(id).await {
            Ok(vm) if &vm.state == want => return Ok(vm),
            Ok(vm) if vm.state.is_terminal() && !want.is_terminal() => {
                let reason = vm.state_reason.clone().unwrap_or_else(|| "no stateReason".to_string());
                return Err(BridgeError::Terminated(format!("{id} is {} while waiting for {}: {reason}", vm.state.as_str(), want.as_str())));
            }
            Ok(vm) => {
                last = Some(vm);
                last_error = None;
            }
            Err(BridgeError::VmNotFound(_)) if *want == VmState::Terminated => {
                let mut vm = last.unwrap_or_else(|| gone_info(id));
                vm.state = VmState::Terminated;
                return Ok(vm);
            }
            Err(e) if transient_get(&e) || (not_found_transient && matches!(e, BridgeError::VmNotFound(_))) => {
                tracing::debug!("wait {id} for {}: retrying GetMicrovm after: {e}", want.as_str());
                last_error = Some(e.to_string());
            }
            Err(e) => return Err(e),
        }
        if start.elapsed() >= poll.budget {
            let seen = last.as_ref().map_or("unknown", |v| v.state.as_str());
            let tail = last_error.map(|e| format!("; last error: {e}")).unwrap_or_default();
            return Err(BridgeError::Sdk { op: "wait", message: format!("{id} not {} after {} (last state {seen}){tail}", want.as_str(), human(poll.budget)) });
        }
        tokio::time::sleep(poll.step).await;
    }
}

// ---- rows ------------------------------------------------------------------------------

/// The row status a service state maps to.
#[must_use]
pub fn status_of(state: &VmState) -> RowStatus {
    match state {
        VmState::Pending => RowStatus::Pending,
        VmState::Running => RowStatus::Running,
        VmState::Suspending | VmState::Suspended => RowStatus::Suspended,
        VmState::Terminating | VmState::Terminated => RowStatus::Terminated,
        VmState::Unknown(_) => RowStatus::Unknown,
    }
}

/// `created` of a row as Unix seconds.
#[must_use]
pub fn created_unix(row: &VmRow) -> Option<u64> {
    parse_rfc3339_utc(&row.created)
}

/// The idle policy of `spec` as a row keeps it.
fn idle_row(spec: &IdleSpec) -> IdleRow {
    IdleRow { max_idle_s: u32::try_from(spec.max_idle_s).unwrap_or(0), suspended_s: u32::try_from(spec.suspended_s).unwrap_or(0), auto_resume: spec.auto_resume }
}

/// The last state seen (`GetMicrovm`), when, its reason, and the endpoint
/// once known. A RUNNING answer also fills a missing (or zero) `started_at`,
/// and `wall_deadline` from it (the start and echoed max duration), when the
/// row had none (a `RunMicrovm` answer without a start, or a legacy row).
fn refresh(row: &mut VmRow, vm: &VmInfo, now: u64) {
    row.status = status_of(&vm.state);
    row.state_seen = Some(vm.state.as_str().to_string());
    row.state_seen_at = Some(now);
    row.state_reason.clone_from(&vm.state_reason);
    if let Ok(host) = api::normalize_endpoint(&vm.endpoint) {
        row.endpoint = Some(host);
    }
    if vm.state == VmState::Running && row.started_at.is_none_or(|s| s == 0) {
        if let Some(start) = vm.started_at_unix.and_then(|s| u64::try_from(s).ok()).filter(|s| *s > 0) {
            let max = u32::try_from(vm.max_duration_s).ok().filter(|m| *m > 0).unwrap_or(row.max_duration_s);
            row.started_at = Some(start);
            row.max_duration_s = max;
            row.wall_deadline = Some(start.saturating_add(u64::from(max)));
        }
    }
}

/// The row of a VM that ended: status terminated, `terminated_at` and
/// `terminated_by` kept from the first time, `state_seen` TERMINATING when it
/// was not terminated yet.
fn mark_terminated(row: &mut VmRow, by: &str, now: u64) {
    if row.status != RowStatus::Terminated {
        row.status = RowStatus::Terminated;
        row.terminated_at = Some(now);
        row.state_seen = Some(VmState::Terminating.as_str().to_string());
        row.state_seen_at = Some(now);
    }
    row.terminated_at.get_or_insert(now);
    row.terminated_by.get_or_insert_with(|| by.to_string());
}

/// Apply `f` to the on-disk row of `row.id` under the rows lock
/// (`registry::update_row`) and return what was written; when the file is
/// gone, write `row` with `f` applied.
fn update_or_write(paths: &Paths, row: &VmRow, f: impl Fn(&mut VmRow)) -> Result<VmRow, BridgeError> {
    if let Some(disk) = registry::update_row(paths, &row.id, &f)? {
        return Ok(disk);
    }
    let mut fresh = row.clone();
    f(&mut fresh);
    registry::write_row(paths, &fresh)?;
    Ok(fresh)
}

/// Fill a row from what `RunMicrovm` / `GetMicrovm` echoed: the id, the
/// endpoint, `started_at`, `wall_deadline` = start + the echoed max duration
/// (`fallback_start`, a time before the VM can have started, when the
/// service reports no start), the echoed idle policy, ingress and execution
/// role, and the state seen.
fn apply_echo(row: &mut VmRow, vm: &VmInfo, fallback_start: u64, now: u64) {
    row.id.clone_from(&vm.id);
    row.started_at = vm.started_at_unix.and_then(|s| u64::try_from(s).ok());
    let max = u32::try_from(vm.max_duration_s).ok().filter(|m| *m > 0).unwrap_or(row.max_duration_s);
    row.max_duration_s = max;
    row.wall_deadline = Some(row.started_at.unwrap_or(fallback_start).saturating_add(u64::from(max)));
    if let Some(idle) = &vm.idle {
        row.idle = Some(idle_row(idle));
    }
    if !vm.ingress.is_empty() {
        row.ingress.clone_from(&vm.ingress);
    }
    if vm.execution_role_arn.is_some() {
        row.execution_role.clone_from(&vm.execution_role_arn);
    }
    refresh(row, vm, now);
}

/// Append one audit row with `actor=cli`; a failed write is a warning (the
/// action it records already happened).
pub(crate) fn audit_event(paths: &Paths, event: &str, pairs: &[(&str, String)]) {
    let mut all: Vec<(&str, String)> = vec![("actor", "cli".to_string())];
    all.extend(pairs.iter().cloned());
    let row = AuditRow::new(event, None, audit::detail(&all));
    if let Err(e) = audit::append(&paths.audit(), &row) {
        tracing::warn!("audit {event}: {e}");
        eprintln!("ai-env: warning: audit row {event} not written: {e}");
    }
}

/// [`update_or_write`] after the fact; a failure is a warning (what it
/// records already happened). Returns the row as written, else `row` with
/// `f` applied.
fn update_or_warn(paths: &Paths, row: &VmRow, f: impl Fn(&mut VmRow)) -> VmRow {
    match update_or_write(paths, row, &f) {
        Ok(disk) => disk,
        Err(e) => {
            tracing::warn!("vm row {}: {e}", row.stem());
            eprintln!("ai-env: warning: vm row {} not updated: {e}", row.stem());
            let mut mem = row.clone();
            f(&mut mem);
            mem
        }
    }
}

// ---- the S5 egress echo gate -----------------------------------------------------------

/// The configured connector's Id alias for a `vpc` run of `connectors`
/// ([`ConnectorAlias::load`]: only when `state/infra.toml` records the Id of
/// exactly that connector), so an echo naming it by Id passes; `None` for
/// `internet`.
pub(crate) fn echo_alias(paths: &Paths, egress: Egress, connectors: &[String]) -> Option<ConnectorAlias> {
    if egress != Egress::Vpc {
        return None;
    }
    connectors.iter().find_map(|c| ConnectorAlias::load(paths, c))
}

/// What the gate holds a VM row to: [`ExpectedEcho::for_row`] (`None` — a
/// mismatch — for a `vpc` row without connectors, written before S5, or an
/// unknown egress) and the alias of its connectors.
pub(crate) fn row_gate(paths: &Paths, row: &VmRow) -> (Option<ExpectedEcho>, Option<ConnectorAlias>) {
    let alias = row.egress.parse::<Egress>().ok().and_then(|e| echo_alias(paths, e, &row.egress_connectors));
    (ExpectedEcho::for_row(row), alias)
}

/// Does `echoed` pass the gate for `expected` (`None`: never)?
pub(crate) fn echo_passes(expected: Option<&ExpectedEcho>, echoed: &[String], alias: Option<&ConnectorAlias>) -> bool {
    expected.is_some_and(|e| e.matches(echoed, alias))
}

/// The egress the gate judges right after `RunMicrovm`: its answer's, or —
/// only when that is empty — `GetMicrovm`'s, asked every `step` until
/// `deadline` (the budget the RUNNING wait shares). An answer with egress is
/// judged; a PENDING one without egress is asked again; one in any other
/// live state without egress, a failure other than a transient one
/// ([`transient_get`], or `ResourceNotFound`: read-after-create), or the
/// deadline leaves nothing echoed: a mismatch (fail closed). `Err(reason)`
/// when `GetMicrovm` says the VM ended (TERMINATING/TERMINATED) or still
/// does not know it at the deadline: the S4 `Terminated` path, not a
/// mismatch.
async fn run_echo<A: MicrovmApi>(api: &A, answer: &VmInfo, step: Duration, deadline: Instant) -> Result<Vec<String>, String> {
    if !answer.egress.is_empty() {
        return Ok(answer.egress.clone());
    }
    let id = answer.id.as_str();
    loop {
        let mut not_found = false;
        match api.get(id).await {
            Ok(vm) if vm.state.is_terminal() => {
                let reason = vm.state_reason.unwrap_or_else(|| "no stateReason".to_string());
                return Err(format!("{id} is {} before its egress was echoed: {reason}", vm.state.as_str()));
            }
            Ok(vm) if !vm.egress.is_empty() => return Ok(vm.egress),
            Ok(vm) if vm.state == VmState::Pending => tracing::debug!("egress gate: {id} PENDING without egress; asking again"),
            Ok(vm) => {
                tracing::warn!("egress gate: {id} is {} and echoes no egress (fail closed)", vm.state.as_str());
                return Ok(Vec::new());
            }
            Err(BridgeError::VmNotFound(_)) => not_found = true,
            Err(e) if transient_get(&e) => tracing::debug!("egress gate: GetMicrovm {id} again after: {e}"),
            Err(e) => {
                tracing::warn!("egress gate: GetMicrovm {id}: {e}; nothing echoed (fail closed)");
                return Ok(Vec::new());
            }
        }
        if Instant::now() >= deadline {
            if not_found {
                return Err(format!("{id}: GetMicrovm still did not find it when the RUNNING budget ran out (RunMicrovm had answered)"));
            }
            tracing::warn!("egress gate: {id} echoed no egress within the budget (fail closed)");
            return Ok(Vec::new());
        }
        tokio::time::sleep(step).await;
    }
}

/// Record a pass on `row` (rows lock): `egress_gate = passed`, and the echo
/// as the gate compared it — normalised, an Id form as its name: exactly
/// `expected`'s set (so a row written before S5 gets its connectors). A
/// failed write is a warning: the row keeps its old verdict, which the next
/// `ai-env vm gc` gates again.
fn record_pass(paths: &Paths, row: &VmRow, expected: &ExpectedEcho) -> VmRow {
    let echo = expected.connectors().to_vec();
    update_or_warn(paths, row, |r| {
        r.egress_connectors.clone_from(&echo);
        r.egress_gate = Some(GATE_PASSED.to_string());
    })
}

/// A VM whose echo failed the gate. First the verdict, `egress_gate =
/// mismatch`, on its row (when there is one; rows lock), so a failed
/// terminate — or this process dying — leaves gc a row to finish; then
/// `TerminateMicrovm` ([`request_terminate`]: the row terminated by
/// `policy`; no wait); then audit `vm_egress_mismatch {id, expected, echoed,
/// via, purpose, terminated}` (lists joined with `,`; an empty expected list
/// as `(none planned)`). `terminated` is whether `TerminateMicrovm` was
/// accepted (a row write that failed after it does not count against it).
/// Returns the error (exit 9); when not terminated, the caller keeps the id.
pub(crate) async fn reject_echo<A: MicrovmApi>(api: &A, paths: &Paths, id: &str, expected: Option<&ExpectedEcho>, echoed: &[String], via: &str, purpose: &str) -> BridgeError {
    if let Err(e) = registry::update_row(paths, id, |r| r.egress_gate = Some(GATE_MISMATCH.to_string())) {
        tracing::warn!("vm row {id}: egress_gate mismatch not recorded: {e}");
        eprintln!("ai-env: warning: vm row {id}: the egress mismatch not recorded: {e}");
    }
    let terminated = match request_terminate(api, paths, id, "policy").await {
        Ok(recorded) => {
            if let Err(e) = recorded {
                tracing::warn!("vm row {id}: the policy termination not recorded: {e}");
                eprintln!("ai-env: warning: vm row {id}: terminated, but the row was not updated: {e}");
            }
            true
        }
        Err(e) => {
            tracing::warn!("egress gate: terminating {id}: {e}");
            eprintln!("ai-env: warning: egress mismatch: terminating {id} failed: {e}");
            false
        }
    };
    let expected: Vec<String> = expected.map(|e| e.connectors().to_vec()).unwrap_or_default();
    audit_event(
        paths,
        "vm_egress_mismatch",
        &[
            ("id", id.to_string()),
            ("expected", if expected.is_empty() { "(none planned)".to_string() } else { expected.join(",") }),
            ("echoed", echoed.join(",")),
            ("via", via.to_string()),
            ("purpose", purpose.to_string()),
            ("terminated", terminated.to_string()),
        ],
    );
    tracing::warn!("vm egress mismatch {id} (via {via}): echoed [{}], expected [{}]; terminated {terminated}", echoed.join(", "), expected.join(", "));
    BridgeError::egress_mismatch(id, expected, echoed.to_vec(), terminated)
}

/// The id of a VM the gate could not confirm terminated (`None` otherwise).
fn still_alive(e: &BridgeError) -> Option<String> {
    match e {
        BridgeError::EgressMismatch(m) if !m.terminated => Some(m.id.clone()),
        _ => None,
    }
}

/// The warning line (without the `ai-env: warning:` prefix) when the
/// resolved version's memory differs from `[vm].memory_mib`, the quota input
/// (plan S4 D7); `None` when they agree or the version reports no memory.
#[must_use]
pub fn memory_warning(memory_mib: u32, version: &ImageVersion) -> Option<String> {
    let have = version.memory_mib?;
    (i64::from(have) != i64::from(memory_mib)).then(|| format!("[vm].memory_mib = {memory_mib} but version {} has {have} MiB (the quota check uses [vm].memory_mib)", version.version))
}

// ---- count (D15) -----------------------------------------------------------------------

/// The VMs that count against `[vm].max_concurrent` (plan S4 D15): the union
/// by id of the non-terminal VMs `ListMicrovms(image)` returned (any owner)
/// and the registry's id rows that are not terminated (a row whose VM the
/// listing shows TERMINATING/TERMINATED does not count, nor one whose wall
/// deadline passed more than [`EXPIRY_MARGIN_S`] ago — no VM outlives its
/// wall, and the listing may drop TERMINATED VMs), plus the pending rows
/// younger than [`PENDING_STALE_S`] that have no id row. Deliberately
/// conservative: a crashed pending row blocks a slot for up to 5 minutes.
#[must_use]
pub fn count_placed(listing: &[VmSummary], rows: &[VmRow], now: u64) -> usize {
    let terminal: BTreeSet<&str> = listing.iter().filter(|s| s.state.is_terminal()).map(|s| s.id.as_str()).collect();
    let mut ids: BTreeSet<&str> = listing.iter().filter(|s| !s.state.is_terminal()).map(|s| s.id.as_str()).collect();
    let mut promoted: BTreeSet<&str> = BTreeSet::new();
    for r in rows.iter().filter(|r| !r.is_pending_row()) {
        promoted.insert(r.client_token.as_str());
        let past_wall = r.wall_deadline.is_some_and(|d| d.saturating_add(EXPIRY_MARGIN_S) < now);
        if r.status != RowStatus::Terminated && !terminal.contains(r.id.as_str()) && !past_wall {
            ids.insert(r.id.as_str());
        }
    }
    let pending = rows
        .iter()
        .filter(|r| r.is_pending_row() && !promoted.contains(r.client_token.as_str()))
        .filter(|r| created_unix(r).is_some_and(|c| now.saturating_sub(c) < PENDING_STALE_S))
        .count();
    ids.len() + pending
}

// ---- select ----------------------------------------------------------------------------

/// What [`select_vm`] produced. Its `Debug` names the row by id and status
/// only: the row holds the session token (plan S4 D13), and `{:?}` output
/// (panics, `tracing` fields) bypasses the scrubber for a token read back
/// from disk.
#[derive(Clone)]
pub enum Selected {
    /// A new VM: `run_ms` is the `RunMicrovm` call (with its retry), `running_ms`
    /// the RUNNING poll after it (0 without `wait`).
    Started { row: VmRow, vm: VmInfo, run_ms: u64, running_ms: u64 },
    /// The workspace's VM (plan S4 D28); `resumed` when it was SUSPENDED.
    Reused { row: VmRow, vm: VmInfo, resumed: bool },
}

impl fmt::Debug for Selected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, row, vm) = match self {
            Selected::Started { row, vm, .. } => ("Started", row, vm),
            Selected::Reused { row, vm, .. } => ("Reused", row, vm),
        };
        let mut d = f.debug_struct(kind);
        d.field("id", &row.id).field("status", &row.status).field("state", &vm.state.as_str());
        match self {
            Selected::Started { run_ms, running_ms, .. } => d.field("run_ms", run_ms).field("running_ms", running_ms),
            Selected::Reused { resumed, .. } => d.field("resumed", resumed),
        };
        d.finish_non_exhaustive()
    }
}

impl Selected {
    /// The row either way.
    #[must_use]
    pub fn row(&self) -> &VmRow {
        match self {
            Selected::Started { row, .. } | Selected::Reused { row, .. } => row,
        }
    }

    /// The VM either way.
    #[must_use]
    pub fn vm(&self) -> &VmInfo {
        match self {
            Selected::Started { vm, .. } | Selected::Reused { vm, .. } => vm,
        }
    }
}

/// A failed [`select_vm_detailed`]: the error, plus what the caller needs to
/// clean up after it (plan S4 D26: `vm smoke` terminates on every failure
/// path after `RunMicrovm` returned, and sweeps for the VM of an ambiguous
/// run). Its `Debug` names the kept row by its stem only (the row holds the
/// session token).
pub struct SelectFailure {
    pub error: BridgeError,
    /// The pending row this call wrote and kept because `RunMicrovm` failed
    /// ambiguously twice (D16): hand it to [`adopt_after_ambiguous`].
    pub kept_pending: Option<Box<VmRow>>,
    /// The VM `RunMicrovm` started, when the failure came after it answered
    /// and the VM may still be alive (the row could not be promoted, the
    /// RUNNING poll failed without terminating it, or the egress gate could
    /// not terminate it); also a reuse candidate the egress gate could not
    /// terminate.
    pub started: Option<String>,
    /// The client token of the pending row this call wrote, set as soon as
    /// the row exists; `None` when the failure came before a pending row was
    /// written (version resolution, the workspace lock, reuse, `MaxConcurrent`,
    /// `Busy`, a failed pending write).
    pub client_token: Option<String>,
}

impl SelectFailure {
    fn plain(error: BridgeError) -> SelectFailure {
        SelectFailure { error, kept_pending: None, started: None, client_token: None }
    }
}

impl From<BridgeError> for SelectFailure {
    fn from(error: BridgeError) -> SelectFailure {
        SelectFailure::plain(error)
    }
}

impl From<SelectFailure> for BridgeError {
    fn from(f: SelectFailure) -> BridgeError {
        f.error
    }
}

impl fmt::Debug for SelectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectFailure").field("error", &self.error).field("kept_pending", &self.kept_pending.as_deref().map(VmRow::stem)).field("started", &self.started).field("client_token", &self.client_token).finish()
    }
}

impl fmt::Display for SelectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

/// SELECT_VM (plan S4 §7); see [`select_vm_detailed`], whose failure details
/// this drops.
pub async fn select_vm<A: MicrovmApi>(api: &A, paths: &Paths, plan: &RunPlan, poll: Poll) -> Result<Selected, BridgeError> {
    select_vm_detailed(api, paths, plan, poll).await.map_err(BridgeError::from)
}

/// SELECT_VM (plan S4 §7). The plan already passed POLICY
/// ([`RunPlan::from_cfg`]); a `vpc` plan without a connector is refused
/// first (`EgressRequired`, exit 9: no VM boots without what the gate holds
/// it to). Steps: resolve the image version live (D6; a
/// version whose memory differs from `[vm].memory_mib` costs one warning
/// line, D7); take `state/workspaces/<slug>.lock` (300 s) when a workspace
/// is given and hold it to the end; reuse the workspace's VM when allowed
/// (D28); else take `state/vms.lock` (90 s), count (D15, `MaxConcurrent` exit
/// 9), stamp `created` and write the pending row (audit `vm_egress_internet`
/// for internet egress, D10/D24), release the placement lock; call
/// `RunMicrovm` (D16: an ambiguous failure is retried once with the same
/// spec and client token; still failing, the pending row is kept for
/// `ai-env vm gc` and returned in [`SelectFailure::kept_pending`]; a
/// definite failure removes it); promote the row with the echoed fields
/// (`egress_gate` still `pending`); the S5 egress echo gate: the
/// `RunMicrovm` answer's egress (or, when it is empty, `GetMicrovm`'s:
/// `run_echo`) must be exactly the connectors the plan's egress requires
/// ([`ExpectedEcho::for_plan`]; an Id-form echo only with the alias of
/// `state/infra.toml`), else the row's verdict becomes `mismatch`,
/// TerminateMicrovm (row terminated by `policy`), audit `vm_egress_mismatch`
/// and [`BridgeError::EgressMismatch`] (exit 9; [`SelectFailure::started`]
/// only when the terminate failed); a pass records `passed` and the echo
/// (normalised) in the row's `egress_connectors`; with `plan.wait`, poll
/// RUNNING with `poll` (one budget with the gate's `GetMicrovm`s; not
/// RUNNING in budget, transient `GetMicrovm` failures included →
/// TerminateMicrovm, row terminated by `timeout`, exit 7 naming the id;
/// TERMINATING/TERMINATED while starting → exit 8), and the RUNNING answer,
/// when it carries egress, passes the gate too. Audits `vm_run` once
/// `RunMicrovm` answered, `vm_reuse` on reuse. Every failure after the
/// pending row was written carries its client token
/// ([`SelectFailure::client_token`]).
pub async fn select_vm_detailed<A: MicrovmApi>(api: &A, paths: &Paths, plan: &RunPlan, poll: Poll) -> Result<Selected, SelectFailure> {
    let Some(expected) = ExpectedEcho::for_plan(plan.egress, &plan.egress_connectors) else {
        return Err(BridgeError::EgressRequired.into());
    };
    let (version, note) = resolve_image_version(api, &plan.image_arn, &plan.want_version).await?;
    if let Some(note) = note {
        eprintln!("ai-env: {note}");
    }
    if let Some(w) = memory_warning(plan.memory_mib, &version) {
        tracing::warn!("{w}");
        eprintln!("ai-env: warning: {w}");
    }
    let _workspace_guard = match &plan.workspace {
        Some((_, slug)) => Some(lock_exclusive(&paths.workspace_lock(slug), WORKSPACE_LOCK_BUDGET, "workspace lock").await?),
        None => None,
    };
    if plan.reuse {
        if let Some((canonical, _)) = &plan.workspace {
            if let Some(selected) = try_reuse(api, paths, plan, &expected, &workspace_key(canonical), &version.version, poll).await? {
                return Ok(selected);
            }
        }
    }
    let max_duration_s = to_i32(plan.max_duration_s, "--max-duration")?;
    let (mut row, payload) = place(api, paths, plan, &version.version).await?;
    let token = Some(row.client_token.clone());
    let fail = |error: BridgeError, kept_pending: Option<Box<VmRow>>, started: Option<String>| SelectFailure { error, kept_pending, started, client_token: token.clone() };
    let spec = RunSpec {
        image_arn: plan.image_arn.clone(),
        image_version: version.version.clone(),
        execution_role_arn: plan.execution_role_arn.clone(),
        ingress_connectors: plan.ingress_connectors.clone(),
        egress_connectors: plan.egress_connectors.clone(),
        idle: plan.idle,
        max_duration_s,
        run_hook_payload: payload,
        client_token: row.client_token.clone(),
    };
    let run_unix = unix_now();
    let t0 = Instant::now();
    let vm = match run_with_retry(api, paths, &row, &spec).await {
        Ok(vm) => vm,
        Err((error, kept)) => return Err(fail(error, kept.then(|| Box::new(row.clone())), None)),
    };
    let run_ms = millis(t0.elapsed());
    apply_echo(&mut row, &vm, run_unix, unix_now());
    if let Err(error) = registry::promote_pending(paths, &row) {
        return Err(fail(error, None, Some(row.id.clone())));
    }
    audit_event(
        paths,
        "vm_run",
        &[
            ("id", row.id.clone()),
            ("purpose", plan.purpose.to_string()),
            ("image_version", row.image_version.clone()),
            ("egress", plan.egress.to_string()),
            ("shell", plan.shell.to_string()),
            ("client_token", row.client_token.clone()),
        ],
    );
    tracing::info!("vm run {} (image version {}, egress {}, purpose {})", row.id, row.image_version, plan.egress, plan.purpose);
    // The S5 egress echo gate: exactly the connectors this egress requires, or the VM goes.
    // Its GetMicrovm retries and the RUNNING wait share one budget (our own row writes are not charged to it).
    let t1 = Instant::now();
    let id = row.id.clone();
    let alias = echo_alias(paths, plan.egress, &plan.egress_connectors);
    let t_echo = Instant::now();
    let echoed = match run_echo(api, &vm, poll.step, t_echo + poll.budget).await {
        Ok(echoed) => echoed,
        Err(m) => {
            record_ended(paths, &row, &m);
            return Err(fail(BridgeError::Terminated(m), None, None));
        }
    };
    let left = poll.budget.saturating_sub(t_echo.elapsed());
    if !expected.matches(&echoed, alias.as_ref()) {
        let error = reject_echo(api, paths, &id, Some(&expected), &echoed, "run", plan.purpose).await;
        let alive = still_alive(&error);
        return Err(fail(error, None, alive));
    }
    row = record_pass(paths, &row, &expected);
    // A RunMicrovm answer without egress reports what GetMicrovm echoed (`--no-wait` returns it).
    let vm = if vm.egress.is_empty() { VmInfo { egress: echoed, ..vm } } else { vm };
    if !plan.wait {
        return Ok(Selected::Started { row, vm, run_ms, running_ms: 0 });
    }
    match wait_after_run(api, &id, Poll { step: poll.step, budget: left }).await {
        // The RUNNING answer is a GetMicrovm too: its egress, when it reports one, must still pass.
        Ok(vm) if !vm.egress.is_empty() && !expected.matches(&vm.egress, alias.as_ref()) => {
            let error = reject_echo(api, paths, &id, Some(&expected), &vm.egress, "run", plan.purpose).await;
            let alive = still_alive(&error);
            Err(fail(error, None, alive))
        }
        Ok(vm) => {
            let now = unix_now();
            match update_or_write(paths, &row, |r| refresh(r, &vm, now)) {
                Ok(disk) => Ok(Selected::Started { row: disk, vm, run_ms, running_ms: millis(t1.elapsed()) }),
                Err(e) => Err(fail(e, None, Some(id))),
            }
        }
        // The service itself answered TERMINATING/TERMINATED: a confirmed end.
        Err(BridgeError::Terminated(m)) => {
            record_ended(paths, &row, &m);
            Err(fail(BridgeError::Terminated(m), None, None))
        }
        Err(BridgeError::Sdk { op: "wait", message }) => match terminate_and_record(api, paths, &id, "timeout", None).await {
            Ok(_) => Err(fail(BridgeError::Sdk { op: "wait", message: format!("{message}; terminated it") }, None, None)),
            Err(t) => Err(fail(BridgeError::Sdk { op: "wait", message: format!("{message}; terminating it failed too ({t}); run `ai-env vm terminate {id}`") }, None, Some(id.clone()))),
        },
        Err(e) => Err(fail(e, None, Some(id))),
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The S4 `Terminated` path after `RunMicrovm` (the service answered
/// TERMINATING/TERMINATED, or never found the VM): the row terminated by
/// `platform`, with `m` as its reason.
fn record_ended(paths: &Paths, row: &VmRow, m: &str) {
    let now = unix_now();
    update_or_warn(paths, row, |r| {
        mark_terminated(r, "platform", now);
        r.state_reason = Some(m.to_string());
    });
}

/// Placement under `state/vms.lock`: count (D15), then stamp `created` and
/// write the pending row with a fresh session token (its client token is
/// `plan.client_token` when set, else a fresh uuid v7; the payload is padded
/// to `plan.pad_payload_to` when set; `egress_connectors` the planned list,
/// `egress_gate` pending)
/// and, for internet egress, append `vm_egress_internet`; the lock is
/// released on return. Returns the pending row and the payload for
/// `RunMicrovm`.
async fn place<A: MicrovmApi>(api: &A, paths: &Paths, plan: &RunPlan, version: &str) -> Result<(VmRow, String), BridgeError> {
    let _placement = lock_exclusive(&paths.placement_lock(), PLACEMENT_LOCK_BUDGET, "placement lock").await?;
    let listing = api.list(Some(&plan.image_arn)).await?;
    let rows = registry::list_rows(paths)?;
    let placed = count_placed(&listing, &rows, unix_now());
    if placed >= usize::try_from(plan.max_concurrent).unwrap_or(usize::MAX) {
        return Err(BridgeError::MaxConcurrent(plan.max_concurrent));
    }
    let client_token = match &plan.client_token {
        // Exactly the lowercase hyphenated form: the token names the pending row's file.
        Some(t) if uuid::Uuid::parse_str(t).is_ok_and(|u| u.hyphenated().to_string() == *t) => t.clone(),
        Some(t) => return Err(BridgeError::Config(format!("run plan client_token {t:?}: not a lowercase hyphenated uuid"))),
        None => uuid::Uuid::now_v7().to_string(),
    };
    let token = new_session_token();
    let who = owner();
    let created = rfc3339_utc_ms(unix_now_ms());
    let base = build_payload(&token, &who, &created)?;
    let payload = match plan.pad_payload_to {
        None => base,
        Some(n) => padded_payload(&base, n).ok_or_else(|| BridgeError::Config(format!("run plan pad_payload_to {n}: shorter than the {}-byte payload", base.len())))?,
    };
    let row = VmRow {
        v: registry::VM_SCHEMA_V,
        status: RowStatus::Pending,
        client_token,
        label: plan.label.clone(),
        workspace: plan.workspace.as_ref().map(|(p, _)| workspace_key(p)),
        slug: plan.workspace.as_ref().map(|(_, s)| s.clone()),
        image_arn: plan.image_arn.clone(),
        image_version: version.to_string(),
        owner: who,
        created,
        commit: commitment_hex(token.expose().as_bytes()),
        session_token: Some(token.expose().clone()),
        max_duration_s: plan.max_duration_s,
        idle: Some(idle_row(&plan.idle)),
        egress: plan.egress.to_string(),
        // The planned connectors: what adoption holds the VM's echo to (the gate stores the echo once it passes).
        egress_connectors: plan.egress_connectors.clone(),
        egress_gate: Some(GATE_PENDING.to_string()),
        ingress: plan.ingress_connectors.clone(),
        shell: plan.shell,
        execution_role: plan.execution_role_arn.clone(),
        ..VmRow::default()
    };
    registry::write_pending(paths, &row)?;
    // D10/D24: audited as soon as a run with internet egress may exist (an
    // ambiguous RunMicrovm can create the VM without ever answering).
    if plan.egress == Egress::Internet {
        audit_event(paths, "vm_egress_internet", &[("client_token", row.client_token.clone()), ("purpose", plan.purpose.to_string())]);
    }
    Ok((row, payload))
}

/// `RunMicrovm` per plan S4 D16. `row` is the pending row already on disk.
/// The error comes with `true` when the pending row was kept (an ambiguous
/// first attempt: the VM may exist), `false` when it was removed.
async fn run_with_retry<A: MicrovmApi>(api: &A, paths: &Paths, row: &VmRow, spec: &RunSpec) -> Result<VmInfo, (BridgeError, bool)> {
    match api.run(spec).await {
        Ok(vm) => Ok(vm),
        Err(BridgeError::Ambiguous { message: first, .. }) => {
            tracing::warn!("run_microvm ambiguous ({first}); retrying once with the same client token {}", spec.client_token);
            match api.run(spec).await {
                Ok(vm) => Ok(vm),
                Err(second) => Err((
                    BridgeError::Ambiguous {
                        op: "run_microvm",
                        message: format!(
                            "{first}; the retry with the same client token failed too ({second}); pending row {} kept: `ai-env vm gc` adopts the VM if it started, or clears the row after {} min",
                            row.stem(),
                            PENDING_STALE_S / 60
                        ),
                    },
                    true,
                )),
            }
        }
        Err(e) => {
            if let Err(r) = registry::remove_row(paths, row) {
                tracing::warn!("pending row {}: {r}", row.stem());
            }
            Err((e, false))
        }
    }
}

/// Plan S4 D28: the newest row of the workspace (the canonical path
/// `workspace`, never the lossy slug; any status but terminated — a
/// pending or unknown id row is a candidate too, e.g. after `--no-wait` or a
/// crash before the RUNNING write) with more than `migrate_before_wall_s` of
/// wall left and the same image ARN and version, egress and shell as asked;
/// `GetMicrovm` decides: RUNNING is reused, PENDING is waited for (RUNNING
/// with `poll`), SUSPENDING/SUSPENDED is resumed, then RUNNING. A VM the
/// service reports TERMINATING/TERMINATED (at once or while waiting) is
/// marked terminated and the next candidate is tried; `ResourceNotFound`
/// marks a running/suspended row terminated, while a pending/unknown row
/// (possibly seconds old: read-after-create) is only skipped. A row of
/// other connectors than the plan's `wanted` (the configuration changed) is
/// not a candidate. The S5 egress echo gate, on that first `GetMicrovm`,
/// before any resume: a VM whose egress is not exactly what its row requires
/// ([`ExpectedEcho::for_row`]; a `vpc` row without connectors, written before
/// S5, never passes), or whose row already says `mismatch` (a terminate that
/// failed), is terminated (`policy`), audited `vm_egress_mismatch` (via
/// `reuse`) and skipped; when the terminate fails the error is returned with
/// the id in [`SelectFailure::started`]. A pass records `passed` and the echo
/// (a row written before S5 gets its connectors), and the settled answer
/// (after a wait or a resume), when it carries egress, must pass again.
/// Every row write goes through the rows lock.
async fn try_reuse<A: MicrovmApi>(api: &A, paths: &Paths, plan: &RunPlan, wanted: &ExpectedEcho, workspace: &str, version: &str, poll: Poll) -> Result<Option<Selected>, SelectFailure> {
    let now = unix_now();
    let min_left = i64::from(plan.migrate_before_wall_s);
    let candidates: Vec<VmRow> = registry::list_rows(paths)?
        .into_iter()
        .filter(|r| !r.is_pending_row() && r.workspace.as_deref() == Some(workspace) && r.status != RowStatus::Terminated)
        .filter(|r| r.wall_left(now).is_some_and(|left| left > min_left))
        .filter(|r| r.image_arn == plan.image_arn && r.image_version == version && r.egress == plan.egress.as_str() && r.shell == plan.shell)
        // Another connector's VM is not this run's; a row without connectors (before S5) goes to the gate.
        .filter(|r| ExpectedEcho::for_row(r).is_none_or(|e| &e == wanted))
        .collect();
    // A VM that failed the gate: never reused; the run fails only when it could not be terminated.
    let reject = |error: BridgeError, id: &str| match still_alive(&error) {
        Some(alive) => Err(SelectFailure { error, kept_pending: None, started: Some(alive), client_token: None }),
        None => {
            eprintln!("ai-env: warning: not reusing {id}: {error}");
            Ok(())
        }
    };
    for row in candidates {
        let (expected, alias) = row_gate(paths, &row);
        let vm = match api.get(&row.id).await {
            Ok(vm) if !vm.state.is_terminal() => {
                let judged = row.egress_gate.as_deref() != Some(GATE_MISMATCH) && echo_passes(expected.as_ref(), &vm.egress, alias.as_ref());
                if !judged {
                    reject(reject_echo(api, paths, &row.id, expected.as_ref(), &vm.egress, "reuse", plan.purpose).await, &row.id)?;
                    continue;
                }
                if let Some(e) = &expected {
                    record_pass(paths, &row, e);
                }
                vm
            }
            Ok(vm) => {
                let at = vm.terminated_at_unix.and_then(|t| u64::try_from(t).ok()).unwrap_or(now);
                update_or_warn(paths, &row, |r| {
                    refresh(r, &vm, now);
                    r.terminated_at.get_or_insert(at);
                    r.terminated_by.get_or_insert_with(|| "platform".to_string());
                });
                continue;
            }
            Err(BridgeError::VmNotFound(_)) if matches!(row.status, RowStatus::Running | RowStatus::Suspended) => {
                update_or_warn(paths, &row, |r| mark_terminated(r, "platform", now));
                continue;
            }
            Err(BridgeError::VmNotFound(_)) => {
                tracing::info!("vm reuse: {} ({}) not found yet: skipped", row.id, row.status.as_str());
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let id = row.id.clone();
        let settled = async {
            match vm.state {
                VmState::Running => Ok(Some((vm, false))),
                VmState::Pending => wait_for_state(api, &id, &VmState::Running, poll).await.map(|vm| Some((vm, false))),
                VmState::Suspended | VmState::Suspending => {
                    if vm.state == VmState::Suspending {
                        wait_for_state(api, &id, &VmState::Suspended, poll).await?;
                    }
                    // Conflict: it resumed (or ended) since GetMicrovm; the RUNNING poll tells which.
                    match api.resume(&id).await {
                        Ok(()) | Err(BridgeError::Conflict(_)) => {}
                        Err(e) => return Err(e),
                    }
                    wait_for_state(api, &id, &VmState::Running, poll).await.map(|vm| Some((vm, true)))
                }
                // A state this build does not know: never reused.
                _ => Ok(None),
            }
        };
        let (vm, resumed) = match settled.await {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            // The service answered TERMINATING/TERMINATED: confirmed, try the next row.
            Err(BridgeError::Terminated(m)) => {
                let at = unix_now();
                update_or_warn(paths, &row, |r| {
                    mark_terminated(r, "platform", at);
                    r.state_reason = Some(m.clone());
                });
                continue;
            }
            // A candidate that did not settle in the budget (stuck PENDING, gone while
            // waiting) is not reused: a new VM is placed, and the operator is told.
            Err(e @ (BridgeError::Sdk { op: "wait", .. } | BridgeError::VmNotFound(_))) => {
                eprintln!("ai-env: warning: not reusing {id}: {e} (ai-env vm terminate {id} if it is stuck)");
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        // The settled answer is a GetMicrovm too: its egress, when it reports one, must still pass.
        if !vm.egress.is_empty() && !echo_passes(expected.as_ref(), &vm.egress, alias.as_ref()) {
            reject(reject_echo(api, paths, &id, expected.as_ref(), &vm.egress, "reuse", plan.purpose).await, &id)?;
            continue;
        }
        let seen = unix_now();
        let row = update_or_write(paths, &row, |r| refresh(r, &vm, seen))?;
        audit_event(paths, "vm_reuse", &[("id", row.id.clone()), ("purpose", plan.purpose.to_string()), ("resumed", resumed.to_string())]);
        tracing::info!("vm reuse {} (resumed {resumed})", row.id);
        return Ok(Some(Selected::Reused { row, vm, resumed }));
    }
    Ok(None)
}

// ---- terminate -------------------------------------------------------------------------

/// `TerminateMicrovm(id)` (a `ResourceNotFound` counts as done); then, at
/// once, the row — when there is one — becomes `terminated` with
/// `terminated_at`, `terminated_by = by` (`operator`, `gc-expired`,
/// `gc-orphan`, `smoke`, `test`, `probe`, `timeout`) and `state_seen`
/// TERMINATING (under the rows lock; a row already terminated keeps its
/// first `terminated_at` and `terminated_by`), and `vm_terminate {id, by}`
/// is audited (on every call); only then, with `wait`, TERMINATED is waited
/// for (`state_seen` updated) — a wait failure is returned as an error, the
/// record stays. Without `wait` the result is `Ok(None)`.
pub async fn terminate_and_record<A: MicrovmApi>(api: &A, paths: &Paths, id: &str, by: &str, wait: Option<Poll>) -> Result<Option<VmInfo>, BridgeError> {
    request_terminate(api, paths, id, by).await??;
    let Some(poll) = wait else {
        return Ok(None);
    };
    let vm = wait_for_state(api, id, &VmState::Terminated, poll).await?;
    let seen = unix_now();
    if let Err(e) = registry::update_row(paths, id, |row| {
        row.state_seen = Some(vm.state.as_str().to_string());
        row.state_seen_at = Some(seen);
    }) {
        tracing::warn!("vm row {id}: TERMINATED not recorded: {e}");
    }
    Ok(Some(vm))
}

/// The first half of [`terminate_and_record`]: `TerminateMicrovm(id)` (a
/// `ResourceNotFound` counts as done), the row terminated by `by` and
/// `vm_terminate {id, by}` audited. The outer `Err` means TerminateMicrovm
/// was not accepted (or `id` is not a VM id): the VM may be alive; the inner
/// one that it was, but the row write failed: the VM is terminating all the
/// same (the egress gate must not count that as a failed terminate).
pub(crate) async fn request_terminate<A: MicrovmApi>(api: &A, paths: &Paths, id: &str, by: &str) -> Result<Result<(), BridgeError>, BridgeError> {
    if !registry::is_vm_id(id) {
        return Err(BridgeError::Config(format!("not a microvm id: {id:?}")));
    }
    match api.terminate(id).await {
        Ok(()) | Err(BridgeError::VmNotFound(_)) => {}
        Err(e) => return Err(e),
    }
    let now = unix_now();
    let recorded = registry::update_row(paths, id, |row| mark_terminated(row, by, now));
    audit_event(paths, "vm_terminate", &[("id", id.to_string()), ("by", by.to_string())]);
    tracing::info!("vm terminate {id} (by {by})");
    Ok(recorded.map(|_| ()))
}

// ---- adoption --------------------------------------------------------------------------

/// One `/health` of a VM, no retry: `GetMicrovm` (endpoint; the VM must be
/// RUNNING — a request to a SUSPENDED VM would resume it and bill), a
/// [`PROBE_TOKEN_MINUTES`]-minute Port(8080) token (registered with the
/// scrubber), one `GET /health`. Only an HTTP 200 whose body names this VM
/// (`microvm_id == id`, plan S4 D30) is an answer: another status is `Http`,
/// a body for another or no `microvm_id` is `Endpoint` (a misrouted answer
/// must never adopt a pending row or make a VM look like ours). A VM found
/// TERMINATING/TERMINATED is `Terminated`, one in any other state `Conflict`.
pub(crate) async fn probe_health_once<A: MicrovmApi, E: EndpointClient>(api: &A, ep: &E, id: &str) -> Result<(VmInfo, Health), BridgeError> {
    let vm = api.get(id).await?;
    if vm.state.is_terminal() {
        return Err(BridgeError::Terminated(format!("{id} is {}: not probed", vm.state.as_str())));
    }
    if vm.state != VmState::Running {
        return Err(BridgeError::Conflict(format!("{id} is {}, not RUNNING: not probed", vm.state.as_str())));
    }
    let host = api::normalize_endpoint(&vm.endpoint)?;
    let token = api.create_auth_token(id, PROBE_TOKEN_MINUTES, api::APP_PORT).await?;
    register_secret(token.value()?.expose());
    let reply = ep.get_health(&host, &token, api::APP_PORT).await?;
    if reply.status != 200 {
        let proxy = reply.proxy_error.map(|p| format!("x-aws-proxy-error {p}; ")).unwrap_or_default();
        return Err(BridgeError::Http { status: reply.status, body: format!("{proxy}{}", reply.body) });
    }
    let Some(health) = reply.health else {
        return Err(BridgeError::Http { status: 200, body: "no /health body".to_string() });
    };
    if health.microvm_id.as_deref() != Some(id) {
        let other = health.microvm_id.as_deref().unwrap_or("no microvm_id");
        return Err(BridgeError::Endpoint(format!("{host} answered /health for {other}, not {id}: not trusted")));
    }
    Ok((vm, health))
}

/// What [`adopt_after_ambiguous`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adoption {
    /// The pending row's VM, now `state/vms/<id>.toml` (audit `vm_adopt`).
    Adopted(String),
    /// No candidate, or every candidate's `/health` answered for another run:
    /// no VM of this run is visible. The pending row stays for `ai-env vm gc`.
    NoMatch,
    /// Row-less VMs that may be this run's but could not be asked: still
    /// PENDING when the poll budget ran out, or `/health` failed (or answered
    /// for another `microvm_id`). The pending row stays; `ai-env vm gc`
    /// decides later. Never terminate these blindly: they may be foreign.
    Unresolved(Vec<String>),
}

/// The adoption sweep after an ambiguous `RunMicrovm` (plan S4 D26), for the
/// row [`SelectFailure::kept_pending`] returned. Candidates are the row-less
/// PENDING or RUNNING VMs of the pending row's image that started at or
/// after `since_unix − 60 s` (or report no start). RUNNING ones are probed
/// first; PENDING ones (a fast failure returns while the VM still boots) are
/// polled to RUNNING within one shared `poll` budget, then probed. The VM
/// whose `/health` (for its own `microvm_id`) answers the pending row's
/// `owner` + `created` is the run's: the row is promoted (`<id>.toml`
/// written, the pending row removed, audit `vm_adopt`) once its egress
/// passes the S5 echo gate; when it does not, the VM is terminated and the
/// result is [`BridgeError::EgressMismatch`] (see `promote_adopted`: when
/// `terminated` is false the caller keeps the id in its terminate guard). A
/// candidate that ends while waiting is skipped; one that cannot be asked
/// makes the result [`Adoption::Unresolved`] unless the match is found. The
/// gate's audit names no purpose (`-`): callers that know theirs use
/// [`adopt_after_ambiguous_for`].
pub async fn adopt_after_ambiguous<A: MicrovmApi, E: EndpointClient>(api: &A, ep: &E, paths: &Paths, pending: &VmRow, since_unix: u64, poll: Poll) -> Result<Adoption, BridgeError> {
    adopt_after_ambiguous_for(api, ep, paths, pending, since_unix, poll, "-").await
}

/// [`adopt_after_ambiguous`] for a caller of `purpose` (`smoke`, `probe`,
/// `test`, …), which a `vm_egress_mismatch` audit row names.
pub async fn adopt_after_ambiguous_for<A: MicrovmApi, E: EndpointClient>(api: &A, ep: &E, paths: &Paths, pending: &VmRow, since_unix: u64, poll: Poll, purpose: &str) -> Result<Adoption, BridgeError> {
    if !pending.is_pending_row() {
        return Err(BridgeError::Config(format!("adopt_after_ambiguous: {} is not a pending row", pending.stem())));
    }
    let deadline = Instant::now() + poll.budget;
    let listing = api.list(Some(&pending.image_arn)).await?;
    let rows = registry::list_rows(paths)?;
    let known: BTreeSet<&str> = rows.iter().filter(|r| !r.is_pending_row()).map(|r| r.id.as_str()).collect();
    let floor = i64::try_from(since_unix.saturating_sub(START_SKEW_S)).unwrap_or(i64::MAX);
    let mut candidates: Vec<&VmSummary> = listing
        .iter()
        .filter(|s| matches!(s.state, VmState::Running | VmState::Pending) && !known.contains(s.id.as_str()) && s.started_at_unix.is_none_or(|t| t >= floor))
        .collect();
    candidates.sort_by_key(|s| s.state != VmState::Running);
    let mut unresolved = Vec::new();
    for s in candidates {
        if s.state == VmState::Pending {
            let left = Poll { step: poll.step, budget: deadline.saturating_duration_since(Instant::now()) };
            match wait_for_state(api, &s.id, &VmState::Running, left).await {
                Ok(_) => {}
                Err(BridgeError::Terminated(_) | BridgeError::VmNotFound(_)) => continue,
                Err(e) => {
                    tracing::warn!("adoption sweep: {} did not become RUNNING: {e}", s.id);
                    unresolved.push(s.id.clone());
                    continue;
                }
            }
        }
        let (vm, health) = match probe_health_once(api, ep, &s.id).await {
            Ok(r) => r,
            Err(BridgeError::Terminated(_) | BridgeError::VmNotFound(_)) => continue,
            Err(e) => {
                tracing::warn!("adoption sweep: {} not probed: {e}", s.id);
                unresolved.push(s.id.clone());
                continue;
            }
        };
        // The run hook has not reached the shim yet (or it lost it): the VM cannot say whose it is.
        let (Some(owner), Some(created)) = (health.owner.as_deref(), health.created.as_deref()) else {
            tracing::warn!("adoption sweep: {} answered /health without owner/created (run hook not delivered yet)", s.id);
            unresolved.push(s.id.clone());
            continue;
        };
        if owner == pending.owner && created == pending.created {
            let row = promote_adopted(api, paths, pending, &vm, "sweep", purpose).await?;
            tracing::info!("adopted {} for pending row {}", row.id, pending.stem());
            return Ok(Adoption::Adopted(row.id));
        }
    }
    Ok(if unresolved.is_empty() { Adoption::NoMatch } else { Adoption::Unresolved(unresolved) })
}

/// Adopt `pending` as the row of `vm` (gc's `adopt` class): the promoted row,
/// written, the pending row removed, audit `vm_adopt` — or, when its egress
/// fails the S5 echo gate, the VM terminated and `EgressMismatch` (see
/// `promote_adopted`).
pub(crate) async fn adopt_pending<A: MicrovmApi>(api: &A, paths: &Paths, pending: &VmRow, vm: &VmInfo) -> Result<VmRow, BridgeError> {
    promote_adopted(api, paths, pending, vm, "gc", "gc").await
}

/// The S5 egress echo gate, then promotion. `vm` (its `GetMicrovm` answer)
/// must echo exactly the connectors the pending row planned
/// ([`ExpectedEcho::for_row`]; a `vpc` pending row without connectors,
/// written before S5, never passes). A pass promotes the pending row of
/// `pending.client_token` to the row of `vm` under the rows lock
/// (`registry::adopt_pending_locked`: the on-disk pending row is the one
/// promoted), with `egress_gate = passed` and the echo (normalised) in
/// `egress_connectors`, and audits `vm_adopt {id, client_token, egress,
/// via}`; when another process adopted it first (its id row carries the same
/// client token) that row is returned without a second audit row; when the
/// pending row was removed instead, the result is a `Config` error. A
/// mismatch is never adopted: the pending row is promoted with `egress_gate
/// = mismatch` (the record, and what gc finishes should the terminate fail),
/// then TerminateMicrovm (the row terminated by `policy`, no wait, no
/// `vm_adopt`) and audit `vm_egress_mismatch` (via `sweep` or `gc`, of
/// `purpose`); the result is [`BridgeError::EgressMismatch`].
async fn promote_adopted<A: MicrovmApi>(api: &A, paths: &Paths, pending: &VmRow, vm: &VmInfo, via: &str, purpose: &str) -> Result<VmRow, BridgeError> {
    let (expected, alias) = row_gate(paths, pending);
    let now = unix_now();
    let fallback = created_unix(pending).unwrap_or(now);
    if !echo_passes(expected.as_ref(), &vm.egress, alias.as_ref()) {
        // The verdict first, on the VM's own row: whatever happens next, gc finds a `mismatch` row to finish.
        if let Err(e) = registry::adopt_pending_locked(paths, &pending.client_token, |r| {
            apply_echo(r, vm, fallback, now);
            r.egress_gate = Some(GATE_MISMATCH.to_string());
        }) {
            tracing::warn!("vm row {}: the egress mismatch not recorded: {e}", vm.id);
            eprintln!("ai-env: warning: vm row {} not written (egress mismatch): {e}", vm.id);
        }
        return Err(reject_echo(api, paths, &vm.id, expected.as_ref(), &vm.egress, via, purpose).await);
    }
    let echo: Vec<String> = expected.as_ref().map(|e| e.connectors().to_vec()).unwrap_or_default();
    let promoted = registry::adopt_pending_locked(paths, &pending.client_token, |r| {
        apply_echo(r, vm, fallback, now);
        r.egress_connectors.clone_from(&echo);
        r.egress_gate = Some(GATE_PASSED.to_string());
    })?;
    let Some(row) = promoted else {
        return match registry::read_row(paths, &vm.id)? {
            Some(row) if row.client_token == pending.client_token => Ok(row),
            _ => Err(BridgeError::Config(format!("pending row {} is gone (removed by another process): {} not adopted", pending.stem(), vm.id))),
        };
    };
    audit_event(paths, "vm_adopt", &[("id", row.id.clone()), ("client_token", row.client_token.clone()), ("egress", row.egress.clone()), ("via", via.to_string())]);
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_scaling() {
        assert_eq!(Poll::RUNNING.scaled(None), Poll::RUNNING);
        assert_eq!(Poll::RUNNING.scaled(Some(1)), Poll { step: Duration::from_millis(1), budget: Duration::from_millis(60) });
        assert_eq!(Poll::SETTLE.scaled(Some(20)), Poll { step: Duration::from_millis(20), budget: Duration::from_millis(600) });
        assert_eq!(Poll::SETTLE.scaled(Some(1000)), Poll::SETTLE);
    }

    #[test]
    fn egress_parses_and_displays() {
        for e in [Egress::Internet, Egress::Vpc] {
            assert_eq!(e.to_string().parse::<Egress>(), Ok(e));
        }
        assert!("proxy".parse::<Egress>().is_err());
    }

    #[test]
    fn session_tokens_are_64_lowercase_hex_and_distinct() {
        let a = new_session_token();
        let b = new_session_token();
        for t in [&a, &b] {
            assert_eq!(t.expose().len(), 64);
            assert!(t.expose().bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        }
        assert_ne!(a.expose(), b.expose());
        assert!(!crate::wire::redact::scrub(&format!("x {} y", a.expose())).contains(a.expose().as_str()), "registered with the scrubber");
    }

    #[test]
    fn count_skips_id_rows_past_their_wall_unless_listed() {
        let now = 1_790_000_000u64;
        let row = |wall: Option<u64>| VmRow { id: "microvm-a".into(), status: RowStatus::Running, client_token: "t-a".into(), wall_deadline: wall, ..VmRow::default() };
        assert_eq!(count_placed(&[], &[row(Some(now - 50_000))], now), 0, "no VM outlives its wall");
        assert_eq!(count_placed(&[], &[row(Some(now - EXPIRY_MARGIN_S))], now), 1, "within the margin: still counted");
        assert_eq!(count_placed(&[], &[row(None)], now), 1, "no wall known: counted");
        let listed = VmSummary { id: "microvm-a".into(), state: VmState::Running, image_arn: String::new(), image_version: String::new(), started_at_unix: None };
        assert_eq!(count_placed(&[listed], &[row(Some(now - 50_000))], now), 1, "the listing says RUNNING: counted");
    }

    #[test]
    fn status_mapping() {
        assert_eq!(status_of(&VmState::Suspending), RowStatus::Suspended);
        assert_eq!(status_of(&VmState::Terminating), RowStatus::Terminated);
        assert_eq!(status_of(&VmState::Unknown("X".into())), RowStatus::Unknown);
    }
}
