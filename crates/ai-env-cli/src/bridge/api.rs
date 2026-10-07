//! The MicroVM control-plane surface the bridge needs, behind a trait so every
//! flow is testable against a fake. S0 shipped the types, the trait, the
//! fake, the SDK builder helpers (with their traps documented) and the
//! pinned-region `SdkConfig`; S4 extends the types with what `GetMicrovm`
//! echoes, adds the image and shell-token calls, the MicroVM endpoint
//! client trait ([`EndpointClient`]), the endpoint-host normaliser, and a
//! fake with the platform's observable behaviour ([`FakeMicrovmApi`], whose
//! state machine [`FakeState`] is shared with the file-backed
//! `vm::fake_file::FileFakeMicrovmApi` of the process-level tests). The real
//! client is `vm::client::SdkMicrovmApi`.
use crate::bridge::config::REGION;
use crate::bridge::errors::BridgeError;
use crate::wire::frame::{Health, HealthDetail, HealthStatus, RunHookPayload};
use crate::wire::redact::Secret;
use crate::wire::time::unix_now;
use aws_sdk_lambdamicrovms::error::BuildError;
use aws_sdk_lambdamicrovms::types::{HookState, Hooks, IdlePolicy, MicrovmHooks, MicrovmImageHooks, MicrovmState};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::Mutex;

/// The pinned region for every SDK call. `BridgeConfig::parse` already
/// rejected any `[aws].region` that differs, so the config carries no other
/// answer; keeping the SDK type here leaves `bridge::config` SDK-free for the
/// wrapper binary.
#[must_use]
pub fn region(_cfg: &crate::bridge::config::BridgeConfig) -> aws_sdk_lambdamicrovms::config::Region {
    aws_sdk_lambdamicrovms::config::Region::new(REGION)
}

/// Every MicroVM endpoint host ends with this (`<uuid>` + suffix; the label is
/// NOT the VM id — measured live in S3).
pub const ENDPOINT_SUFFIX: &str = ".lambda-microvm.eu-central-1.on.aws";

/// The port the shim serves `/health` (and later `/agent`) on.
pub const APP_PORT: u16 = 8080;

/// The in-VM port the platform's shell listens on (`wss://<endpoint>/shell`).
pub const SHELL_PORT: u16 = 8022;

/// The header key of the endpoint token in both token maps.
pub const TOKEN_HEADER: &str = "X-aws-proxy-auth";

/// `arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:<NAME>`
/// — the managed connectors (`HTTP_INGRESS`, `SHELL_INGRESS`, `INTERNET_EGRESS`).
#[must_use]
pub fn managed_connector_arn(name: &str) -> String {
    format!("arn:aws:lambda:{REGION}:aws:network-connector:aws-network-connector:{name}")
}

/// The endpoint as the API returns it → a bare host (plan S4 D4): an optional
/// `https://` and a trailing `/` are stripped; the rest must be exactly one
/// label of `[a-z0-9-]` followed by [`ENDPOINT_SUFFIX`]. Anything else (an
/// `http://` scheme, a path, a port, another domain) is refused naming the
/// raw string, so no request is ever sent to a host outside the pin.
pub fn normalize_endpoint(raw: &str) -> Result<String, BridgeError> {
    let trimmed = raw.trim();
    let host = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    let host = host.strip_suffix('/').unwrap_or(host).to_ascii_lowercase();
    let label_ok = host
        .strip_suffix(ENDPOINT_SUFFIX)
        .is_some_and(|label| !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && label.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'));
    if label_ok {
        Ok(host)
    } else {
        Err(BridgeError::Endpoint(format!("refusing endpoint {raw:?}: expected <label>{ENDPOINT_SUFFIX}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmState {
    Pending,
    Running,
    Suspending,
    Suspended,
    Terminating,
    Terminated,
    Unknown(String),
}

impl VmState {
    /// TERMINATING or TERMINATED: the VM will never serve again.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, VmState::Terminating | VmState::Terminated)
    }

    /// The service's spelling (`RUNNING`, …).
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            VmState::Pending => "PENDING",
            VmState::Running => "RUNNING",
            VmState::Suspending => "SUSPENDING",
            VmState::Suspended => "SUSPENDED",
            VmState::Terminating => "TERMINATING",
            VmState::Terminated => "TERMINATED",
            VmState::Unknown(s) => s,
        }
    }
}

impl From<&MicrovmState> for VmState {
    fn from(s: &MicrovmState) -> Self {
        match s {
            MicrovmState::Pending => VmState::Pending,
            MicrovmState::Running => VmState::Running,
            MicrovmState::Suspending => VmState::Suspending,
            MicrovmState::Suspended => VmState::Suspended,
            MicrovmState::Terminating => VmState::Terminating,
            MicrovmState::Terminated => VmState::Terminated,
            other => VmState::Unknown(other.as_str().to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdleSpec {
    pub max_idle_s: i32,
    pub suspended_s: i32,
    pub auto_resume: bool,
}

/// Everything `RunMicrovm` is given. Memory is not a run parameter (it is the
/// image version's), and hooks are image-level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSpec {
    pub image_arn: String,
    /// The resolved version (`N.0`), always passed.
    pub image_version: String,
    pub execution_role_arn: Option<String>,
    /// Empty = the platform default (HTTP_INGRESS).
    pub ingress_connectors: Vec<String>,
    /// Empty = the platform default (INTERNET_EGRESS).
    pub egress_connectors: Vec<String>,
    pub idle: IdleSpec,
    pub max_duration_s: i32,
    pub run_hook_payload: String,
    pub client_token: String,
}

/// What `RunMicrovm` / `GetMicrovm` return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmInfo {
    pub id: String,
    pub state: VmState,
    /// Bare host (see [`normalize_endpoint`]).
    pub endpoint: String,
    pub image_arn: String,
    pub image_version: String,
    pub started_at_unix: Option<i64>,
    pub max_duration_s: i32,
    pub state_reason: Option<String>,
    pub execution_role_arn: Option<String>,
    /// The idle policy as echoed.
    pub idle: Option<IdleSpec>,
    /// The connectors as echoed (the platform defaults when none were sent).
    pub ingress: Vec<String>,
    pub egress: Vec<String>,
    pub terminated_at_unix: Option<i64>,
}

/// One `ListMicrovms` item: no endpoint (gc calls `GetMicrovm` for it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmSummary {
    pub id: String,
    pub state: VmState,
    pub image_arn: String,
    pub image_version: String,
    pub started_at_unix: Option<i64>,
}

/// `GetMicrovmImage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageInfo {
    pub arn: String,
    pub name: String,
    /// `CREATED`, `UPDATED`, `CREATING`, …
    pub state: String,
    pub latest_active: Option<String>,
    pub latest_failed: Option<String>,
}

/// One `ListMicrovmImageVersions` item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageVersion {
    /// `N.0`.
    pub version: String,
    /// `SUCCESSFUL`, `FAILED`, `IN_PROGRESS`, …
    pub state: String,
    /// `ACTIVE` | `INACTIVE`.
    pub status: String,
    /// `resources[0].minimumMemoryInMiB`.
    pub memory_mib: Option<i32>,
    pub created_at_unix: Option<i64>,
}

impl ImageVersion {
    /// SUCCESSFUL and ACTIVE: a version `RunMicrovm` may use.
    #[must_use]
    pub fn runnable(&self) -> bool {
        self.state == "SUCCESSFUL" && self.status == "ACTIVE"
    }
}

/// The header map returned by `CreateMicrovmAuthToken` / `CreateMicrovmShellAuthToken`
/// (key [`TOKEN_HEADER`]), with the scope and expiry the caller asked for (the
/// output carries neither).
#[derive(Debug, Clone)]
pub struct AuthToken {
    pub headers: BTreeMap<String, Secret<String>>,
    pub port: u16,
    pub expires_at_unix: u64,
}

impl AuthToken {
    /// The `X-aws-proxy-auth` value; `Endpoint` error naming the keys (never
    /// the values) when the map lacks it.
    pub fn value(&self) -> Result<&Secret<String>, BridgeError> {
        self.headers.get(TOKEN_HEADER).ok_or_else(|| {
            let keys: Vec<&str> = self.headers.keys().map(String::as_str).collect();
            BridgeError::Endpoint(format!("token map has no {TOKEN_HEADER} (keys: {})", keys.join(", ")))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedImage {
    pub arn: String,
}

/// One `GET https://<endpoint>/health` through the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReply {
    pub status: u16,
    /// The proxy's `x-aws-proxy-error` header, when present.
    pub proxy_error: Option<String>,
    /// `Retry-After` in seconds (429).
    pub retry_after_s: Option<u64>,
    /// The parsed body of a 200.
    pub health: Option<Health>,
    /// At most 512 bytes of a non-200 body, scrubbed.
    pub body: String,
}

/// Everything the bridge asks the control plane. Native `async fn` in the
/// impls; the trait spells out `Send` futures so callers can spawn them.
pub trait MicrovmApi: Send + Sync {
    fn run(&self, spec: &RunSpec) -> impl Future<Output = Result<VmInfo, BridgeError>> + Send;
    fn get(&self, id: &str) -> impl Future<Output = Result<VmInfo, BridgeError>> + Send;
    fn suspend(&self, id: &str) -> impl Future<Output = Result<(), BridgeError>> + Send;
    fn resume(&self, id: &str) -> impl Future<Output = Result<(), BridgeError>> + Send;
    fn terminate(&self, id: &str) -> impl Future<Output = Result<(), BridgeError>> + Send;
    /// Every VM of `image_arn` (all pages), in any state the service lists.
    fn list(&self, image_arn: Option<&str>) -> impl Future<Output = Result<Vec<VmSummary>, BridgeError>> + Send;
    /// A token scoped to exactly one port (`Port(port)`), `minutes` 1..=60.
    fn create_auth_token(&self, id: &str, minutes: u16, port: u16) -> impl Future<Output = Result<AuthToken, BridgeError>> + Send;
    /// A shell token (the VM must run with `SHELL_INGRESS`); `port` is [`SHELL_PORT`].
    fn create_shell_token(&self, id: &str, minutes: u16) -> impl Future<Output = Result<AuthToken, BridgeError>> + Send;
    fn get_image(&self, arn: &str) -> impl Future<Output = Result<ImageInfo, BridgeError>> + Send;
    /// Every version of the image (all pages).
    fn list_image_versions(&self, arn: &str) -> impl Future<Output = Result<Vec<ImageVersion>, BridgeError>> + Send;
    fn list_managed_images(&self) -> impl Future<Output = Result<Vec<ManagedImage>, BridgeError>> + Send;

    /// `GetNetworkConnector` on `identifier` (an ARN or an `nc-…` id): the
    /// connector document as the service answers it, which
    /// `egress::ConnectorFacts::from_get` reads. The one call the SDK does not
    /// model, so the runtime client signs it by hand (S7 D5), and the one the
    /// credential gate needs live: the Mac compares the egress connector's
    /// configuration now with the one the recorded `ai-env egress check`
    /// verified.
    ///
    /// The default fails closed, so a client that cannot make the call can
    /// never be mistaken for one whose facts matched.
    fn get_network_connector(&self, identifier: &str) -> impl Future<Output = Result<serde_json::Value, BridgeError>> + Send {
        let _ = identifier;
        async { Err(BridgeError::Sdk { op: "get_network_connector", message: "this client cannot read a network connector".into() }) }
    }
}

/// One `GET https://<endpoint>/health/detail` through the proxy (S6, bearer only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthDetailReply {
    pub status: u16,
    pub proxy_error: Option<String>,
    pub retry_after_s: Option<u64>,
    /// The parsed body of a 200.
    pub detail: Option<HealthDetail>,
    /// At most 512 bytes of a non-200 body, scrubbed.
    pub body: String,
}

/// The MicroVM endpoint (data plane), behind a trait for the fakes.
pub trait EndpointClient: Send + Sync {
    /// `GET https://<endpoint>/health` with `x-aws-proxy-auth: <token>` and
    /// `x-aws-proxy-port: <port_header>` (normally `token.port`). Any HTTP
    /// status is `Ok(HealthReply)`; `Err(Endpoint)` is a transient transport
    /// failure (connect, reset, timeout) the caller may retry; any other
    /// `Err` is final (TLS verification, a refused host).
    fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> impl Future<Output = Result<HealthReply, BridgeError>> + Send;

    /// `GET https://<endpoint>/health/detail` with the token headers (port
    /// 8080) and `Authorization: Bearer <session token>` (S6). Errors as
    /// [`Self::get_health`]. The default (a test double that cannot) is a
    /// final `Sdk { op: "health_detail" }`.
    fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &Secret<String>) -> impl Future<Output = Result<HealthDetailReply, BridgeError>> + Send {
        let _ = (endpoint, token, bearer);
        async { Err(BridgeError::Sdk { op: "health_detail", message: "this endpoint client cannot read /health/detail".into() }) }
    }
}

/// `IdlePolicy` with every required field set — `IdlePolicy::builder().build()`
/// alone is a `BuildError` (documented trap, asserted by tests).
pub fn idle_policy(spec: &IdleSpec) -> Result<IdlePolicy, BuildError> {
    IdlePolicy::builder()
        .max_idle_duration_seconds(spec.max_idle_s)
        .suspended_duration_seconds(spec.suspended_s)
        .auto_resume_enabled(spec.auto_resume)
        .build()
}

/// Hooks on port 9000, every lifecycle hook ENABLED with the plan's budgets
/// (run/resume/suspend 30 s, terminate 60 s; image ready 600 s, validate
/// 300 s). Spelled out because the builder default is DISABLED with 1 s.
#[must_use]
pub fn hooks_config() -> Hooks {
    Hooks::builder()
        .port(9000)
        .microvm_hooks(
            MicrovmHooks::builder()
                .run(HookState::Enabled)
                .run_timeout_in_seconds(30)
                .resume(HookState::Enabled)
                .resume_timeout_in_seconds(30)
                .suspend(HookState::Enabled)
                .suspend_timeout_in_seconds(30)
                .terminate(HookState::Enabled)
                .terminate_timeout_in_seconds(60)
                .build(),
        )
        .microvm_image_hooks(
            MicrovmImageHooks::builder()
                .ready(HookState::Enabled)
                .ready_timeout_in_seconds(600)
                .validate(HookState::Enabled)
                .validate_timeout_in_seconds(300)
                .build(),
        )
        .build()
}

/// SDK configuration with every pin of `vm::client::sdk_config_for` (plan S4
/// D3) over the default credential chain: the region and the control-plane
/// URL in code (`AWS_REGION`, `AWS_ENDPOINT_URL*` and profile endpoints never
/// consulted), FIPS and dual-stack off, standard retries and timeouts, and
/// the HTTP client from `bridge::tls` (Amazon roots only, aws-lc-rs, proxy env
/// ignored) in place of the SDK default, which would load native roots and
/// honour `HTTPS_PROXY`.
pub async fn sdk_config() -> aws_config::SdkConfig {
    crate::bridge::vm::client::sdk_config_for(&crate::bridge::vm::client::RuntimeCreds::DefaultChainForReadOnlyTests).await
}

// ---- fake ---------------------------------------------------------------------

/// What a fake recorded, in call order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Call {
    Run { client_token: String },
    Get(String),
    Suspend(String),
    Resume(String),
    Terminate(String),
    List(Option<String>),
    Token { id: String, minutes: u16, port: u16 },
    ShellToken { id: String, minutes: u16 },
    GetImage(String),
    ListImageVersions(String),
    ListImages,
    /// `GetNetworkConnector` (S7).
    GetConnector(String),
    Health { endpoint: String, port: u16 },
    /// `GET /health/detail` (S6).
    HealthDetail { endpoint: String, port: u16 },
}

/// A scripted failure, serialisable so the file-backed fake can queue it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeFailure {
    /// `sdk`, `quota`, `validation`, `conflict`, `throttled`, `access_denied`,
    /// `credentials`, `not_found`, `ambiguous`, `endpoint`.
    pub kind: String,
    pub message: String,
    /// Only for this call kind (`run`, `get`, `health`, …); `None` = the next call of any kind.
    pub on: Option<String>,
    /// `run` only: create the VM first, then fail (the request reached the service).
    pub after_effect: bool,
}

impl FakeFailure {
    /// The failure a [`BridgeError`] stands for (variants outside the list become `sdk`).
    #[must_use]
    pub fn from_error(e: &BridgeError) -> FakeFailure {
        let (kind, message) = match e {
            BridgeError::Quota(m) => ("quota", m.clone()),
            BridgeError::Validation(m) => ("validation", m.clone()),
            BridgeError::Conflict(m) => ("conflict", m.clone()),
            BridgeError::Throttled(m) => ("throttled", m.clone()),
            BridgeError::AccessDenied(m) => ("access_denied", m.clone()),
            BridgeError::CredentialsUnavailable(m) => ("credentials", m.clone()),
            BridgeError::VmNotFound(m) => ("not_found", m.clone()),
            BridgeError::Ambiguous { message, .. } => ("ambiguous", message.clone()),
            BridgeError::Endpoint(m) => ("endpoint", m.clone()),
            other => ("sdk", other.to_string()),
        };
        FakeFailure { kind: kind.to_string(), message, on: None, after_effect: false }
    }

    fn to_error(&self, op: &'static str) -> BridgeError {
        let m = self.message.clone();
        match self.kind.as_str() {
            "quota" => BridgeError::Quota(m),
            "validation" => BridgeError::Validation(m),
            "conflict" => BridgeError::Conflict(m),
            "throttled" => BridgeError::Throttled(m),
            "access_denied" => BridgeError::AccessDenied(m),
            "credentials" => BridgeError::CredentialsUnavailable(m),
            "not_found" => BridgeError::VmNotFound(m),
            "ambiguous" => BridgeError::Ambiguous { op, message: m },
            "endpoint" => BridgeError::Endpoint(m),
            _ => BridgeError::Sdk { op, message: m },
        }
    }
}

/// The platform as the fakes model it: RunMicrovm idempotent by client token,
/// PENDING → RUNNING on [`FakeState::advance_all`] (or on the first `get`
/// with `auto_advance`), terminate → TERMINATING, then TERMINATED on the
/// next `get`/`list`, suspend only from RUNNING (Conflict otherwise), resume
/// only from SUSPENDED, TERMINATED VMs stay listed, tokens scoped to one port
/// and checked by the fake endpoint (403 `UNAUTHORIZED` for a wrong VM, port
/// or an expired token), a SUSPENDED VM with auto-resume resumed by the first
/// endpoint request, and per-VM scripted endpoint statuses.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FakeState {
    pub vms: BTreeMap<String, VmInfo>,
    /// client_token → id.
    pub tokens: BTreeMap<String, String>,
    pub specs: Vec<RunSpec>,
    pub calls: Vec<Call>,
    pub failures: VecDeque<FakeFailure>,
    pub next: u64,
    /// PENDING → RUNNING on the first `get`.
    pub auto_advance: bool,
    /// Added to the clock when tokens are checked ([`FakeState::expire_tokens`]).
    pub clock_offset_s: u64,
    /// Per VM id: `/health` statuses to return before the normal answer.
    pub health_script: BTreeMap<String, VecDeque<u16>>,
    /// Per VM id: the `/health` body to serve instead of the default.
    pub health_override: BTreeMap<String, Health>,
    /// Every VM's first N `/health` 200s answer like a shim that has not seen
    /// `/run` yet: the live endpoint forwards to the app before `/run`
    /// returned (S4 part B, 30 Sep 2026).
    #[serde(default)]
    pub pre_run_health: u32,
    /// Per VM id: the pre-`/run` answers served so far.
    #[serde(default)]
    pub pre_run_served: BTreeMap<String, u32>,
    /// The egress every `RunMicrovm` and `GetMicrovm` answer echoes instead
    /// of what was sent (S5 echo gate tests: a VPC run that comes back with
    /// `INTERNET_EGRESS`, an extra connector, the Id form).
    #[serde(default)]
    pub egress_echo: Option<Vec<String>>,
    /// `RunMicrovm` answers with an empty egress list (the gate must then ask
    /// `GetMicrovm`); `GetMicrovm` is unaffected.
    #[serde(default)]
    pub run_echo_empty: bool,
    /// The egress `GetMicrovm` answers echo, over [`FakeState::egress_echo`]
    /// (RunMicrovm unaffected): the Run and the Get answer disagree.
    #[serde(default)]
    pub get_egress_echo: Option<Vec<String>>,
    pub image: Option<ImageInfo>,
    pub versions: Vec<ImageVersion>,
    /// The `Retry-After` a scripted 429 carries; `None` = no header (the
    /// documented form: the client then backs off exponentially) (S6).
    #[serde(default = "default_retry_after_429")]
    pub retry_after_429: Option<u64>,
    /// `GetNetworkConnector` answers, keyed by the identifier asked for — the
    /// ARN and the `nc-…` id are separate keys, as the service accepts either.
    /// An identifier that is not here answers `ResourceNotFoundException`, so a
    /// test that forgot to seed one never passes the gate by accident (S7).
    #[serde(default)]
    pub connectors: BTreeMap<String, serde_json::Value>,
}

fn default_retry_after_429() -> Option<u64> {
    Some(1)
}

/// The image the fakes serve unless told otherwise.
pub const FAKE_IMAGE_ARN: &str = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:ai-env-agent";

impl FakeState {
    /// The default image: `ai-env-agent`, version `1.0` SUCCESSFUL/ACTIVE, 2048 MiB.
    #[must_use]
    pub fn new() -> FakeState {
        FakeState {
            image: Some(ImageInfo {
                arn: FAKE_IMAGE_ARN.to_string(),
                name: "ai-env-agent".to_string(),
                state: "CREATED".to_string(),
                latest_active: Some("1.0".to_string()),
                latest_failed: None,
            }),
            versions: vec![ImageVersion { version: "1.0".into(), state: "SUCCESSFUL".into(), status: "ACTIVE".into(), memory_mib: Some(2048), created_at_unix: Some(1_789_804_800) }],
            retry_after_429: default_retry_after_429(),
            ..FakeState::default()
        }
    }

    fn take_failure(&mut self, kind: &str, op: &'static str) -> Option<(BridgeError, bool)> {
        let pos = self.failures.iter().position(|f| f.on.as_deref().is_none_or(|on| on == kind))?;
        let f = self.failures.remove(pos)?;
        Some((f.to_error(op), f.after_effect))
    }

    fn fail(&mut self, kind: &str, op: &'static str) -> Result<(), BridgeError> {
        match self.take_failure(kind, op) {
            Some((e, _)) => Err(e),
            None => Ok(()),
        }
    }

    fn vm_mut(&mut self, id: &str, op: &'static str) -> Result<&mut VmInfo, BridgeError> {
        let _ = op;
        self.vms.get_mut(id).ok_or_else(|| BridgeError::VmNotFound(format!("MicroVM not found: {id}")))
    }

    /// TERMINATING becomes TERMINATED the next time anyone looks.
    fn settle(&mut self) {
        for vm in self.vms.values_mut() {
            if vm.state == VmState::Terminating {
                vm.state = VmState::Terminated;
                vm.terminated_at_unix = Some(unix_now() as i64);
            }
        }
    }

    /// Pending → Running for every VM (the platform's boot).
    pub fn advance_all(&mut self) {
        for vm in self.vms.values_mut() {
            if vm.state == VmState::Pending {
                vm.state = VmState::Running;
            }
        }
    }

    /// Every token minted so far reads as expired (the clock jumps 2 h).
    pub fn expire_tokens(&mut self) {
        self.clock_offset_s += 7200;
    }

    /// A VM that exists outside this client (another owner, an orphan).
    pub fn insert_vm(&mut self, vm: VmInfo) {
        self.vms.insert(vm.id.clone(), vm);
    }

    pub fn run(&mut self, spec: &RunSpec) -> Result<VmInfo, BridgeError> {
        self.calls.push(Call::Run { client_token: spec.client_token.clone() });
        let failure = self.take_failure("run", "run_microvm");
        if let Some((e, false)) = failure {
            return Err(e);
        }
        if let Some(id) = self.tokens.get(&spec.client_token).cloned() {
            if let Some((e, true)) = failure {
                return Err(e);
            }
            return Ok(self.run_answer(self.vms[&id].clone()));
        }
        // The API model's constraint (the prose says 16 KB; the schema says 4096).
        if spec.run_hook_payload.len() > RunHookPayload::MAX_BYTES {
            return Err(BridgeError::Validation(format!("runHookPayload: length {} exceeds 4096", spec.run_hook_payload.len())));
        }
        self.next += 1;
        let n = self.next;
        let id = format!("microvm-00000000-0000-4000-8000-{n:012x}");
        let vm = VmInfo {
            id: id.clone(),
            state: VmState::Pending,
            endpoint: format!("ffffffff-0000-4000-8000-{n:012x}{ENDPOINT_SUFFIX}"),
            image_arn: spec.image_arn.clone(),
            image_version: spec.image_version.clone(),
            started_at_unix: Some(unix_now() as i64),
            max_duration_s: spec.max_duration_s,
            state_reason: None,
            execution_role_arn: spec.execution_role_arn.clone(),
            idle: Some(spec.idle),
            ingress: if spec.ingress_connectors.is_empty() { vec![managed_connector_arn("HTTP_INGRESS")] } else { spec.ingress_connectors.clone() },
            egress: if spec.egress_connectors.is_empty() { vec![managed_connector_arn("INTERNET_EGRESS")] } else { spec.egress_connectors.clone() },
            terminated_at_unix: None,
        };
        self.tokens.insert(spec.client_token.clone(), id.clone());
        self.vms.insert(id, vm.clone());
        self.specs.push(spec.clone());
        match failure {
            Some((e, true)) => Err(e),
            _ => Ok(self.run_answer(vm)),
        }
    }

    /// What `RunMicrovm` returns for `vm`: [`FakeState::egress_echo`] in place
    /// of its egress, which [`FakeState::run_echo_empty`] clears.
    fn run_answer(&self, vm: VmInfo) -> VmInfo {
        let mut vm = self.echoed(vm);
        if self.run_echo_empty {
            vm.egress.clear();
        }
        vm
    }

    /// `vm` with [`FakeState::egress_echo`] in place of its egress (the stored VM keeps what was sent).
    fn echoed(&self, mut vm: VmInfo) -> VmInfo {
        if let Some(e) = &self.egress_echo {
            vm.egress.clone_from(e);
        }
        vm
    }

    pub fn get(&mut self, id: &str) -> Result<VmInfo, BridgeError> {
        self.calls.push(Call::Get(id.to_string()));
        self.fail("get", "get_microvm")?;
        self.settle();
        let auto = self.auto_advance;
        let vm = self.vm_mut(id, "get_microvm")?;
        if auto && vm.state == VmState::Pending {
            vm.state = VmState::Running;
        }
        let vm = vm.clone();
        let mut vm = self.echoed(vm);
        if let Some(e) = &self.get_egress_echo {
            vm.egress.clone_from(e);
        }
        Ok(vm)
    }

    pub fn suspend(&mut self, id: &str) -> Result<(), BridgeError> {
        self.calls.push(Call::Suspend(id.to_string()));
        self.fail("suspend", "suspend_microvm")?;
        let vm = self.vm_mut(id, "suspend_microvm")?;
        if vm.state != VmState::Running {
            return Err(BridgeError::Conflict(format!("{id} is {}, not RUNNING", vm.state.as_str())));
        }
        vm.state = VmState::Suspended;
        Ok(())
    }

    pub fn resume(&mut self, id: &str) -> Result<(), BridgeError> {
        self.calls.push(Call::Resume(id.to_string()));
        self.fail("resume", "resume_microvm")?;
        let vm = self.vm_mut(id, "resume_microvm")?;
        if vm.state != VmState::Suspended {
            return Err(BridgeError::Conflict(format!("{id} is {}, not SUSPENDED", vm.state.as_str())));
        }
        vm.state = VmState::Running;
        Ok(())
    }

    /// Idempotent (terminating a TERMINATED VM succeeds, as documented).
    pub fn terminate(&mut self, id: &str) -> Result<(), BridgeError> {
        self.calls.push(Call::Terminate(id.to_string()));
        self.fail("terminate", "terminate_microvm")?;
        let vm = self.vm_mut(id, "terminate_microvm")?;
        if vm.state != VmState::Terminated {
            vm.state = VmState::Terminating;
        }
        Ok(())
    }

    pub fn list(&mut self, image_arn: Option<&str>) -> Result<Vec<VmSummary>, BridgeError> {
        self.calls.push(Call::List(image_arn.map(str::to_string)));
        self.fail("list", "list_microvms")?;
        self.settle();
        Ok(self
            .vms
            .values()
            .filter(|v| image_arn.is_none_or(|a| v.image_arn == a))
            .map(|v| VmSummary { id: v.id.clone(), state: v.state.clone(), image_arn: v.image_arn.clone(), image_version: v.image_version.clone(), started_at_unix: v.started_at_unix })
            .collect())
    }

    /// The fake token: `eyJ` + hex of `<id>|<port>|<expiry>`, padded with `x`
    /// to 223 characters so the scrubber's JWT shape masks it like a real one.
    fn mint(id: &str, port: u16, expires: u64) -> Secret<String> {
        let mut t = format!("eyJ{}", hex::encode(format!("{id}|{port}|{expires}")));
        while t.len() < 223 {
            t.push('x');
        }
        Secret::new(t)
    }

    /// `(id, port, expiry)` of a fake token.
    fn parse_token(token: &str) -> Option<(String, u16, u64)> {
        let body = token.strip_prefix("eyJ")?.trim_end_matches('x');
        let text = String::from_utf8(hex::decode(body).ok()?).ok()?;
        let mut it = text.split('|');
        let (id, port, exp) = (it.next()?, it.next()?, it.next()?);
        Some((id.to_string(), port.parse().ok()?, exp.parse().ok()?))
    }

    pub fn create_auth_token(&mut self, id: &str, minutes: u16, port: u16) -> Result<AuthToken, BridgeError> {
        self.calls.push(Call::Token { id: id.to_string(), minutes, port });
        self.fail("token", "create_microvm_auth_token")?;
        let vm = self.vm_mut(id, "create_microvm_auth_token")?;
        if vm.state.is_terminal() {
            return Err(BridgeError::Conflict(format!("{id} is {}", vm.state.as_str())));
        }
        if !(1..=60).contains(&minutes) {
            return Err(BridgeError::Validation(format!("expirationInMinutes {minutes} out of 1..=60")));
        }
        let expires = unix_now() + u64::from(minutes) * 60;
        let mut headers = BTreeMap::new();
        headers.insert(TOKEN_HEADER.to_string(), Self::mint(id, port, expires));
        Ok(AuthToken { headers, port, expires_at_unix: expires })
    }

    pub fn create_shell_token(&mut self, id: &str, minutes: u16) -> Result<AuthToken, BridgeError> {
        self.calls.push(Call::ShellToken { id: id.to_string(), minutes });
        self.fail("shell_token", "create_microvm_shell_auth_token")?;
        let vm = self.vm_mut(id, "create_microvm_shell_auth_token")?;
        if !vm.ingress.iter().any(|a| a.ends_with(":SHELL_INGRESS")) {
            return Err(BridgeError::Validation(format!("{id} was not started with the SHELL_INGRESS connector")));
        }
        let expires = unix_now() + u64::from(minutes) * 60;
        let mut headers = BTreeMap::new();
        headers.insert(TOKEN_HEADER.to_string(), Self::mint(id, SHELL_PORT, expires));
        Ok(AuthToken { headers, port: SHELL_PORT, expires_at_unix: expires })
    }

    pub fn get_image(&mut self, arn: &str) -> Result<ImageInfo, BridgeError> {
        self.calls.push(Call::GetImage(arn.to_string()));
        self.fail("get_image", "get_microvm_image")?;
        self.image.clone().filter(|i| i.arn == arn).ok_or_else(|| BridgeError::Sdk { op: "get_microvm_image", message: format!("ResourceNotFoundException: image {arn} not found") })
    }

    pub fn list_image_versions(&mut self, arn: &str) -> Result<Vec<ImageVersion>, BridgeError> {
        self.calls.push(Call::ListImageVersions(arn.to_string()));
        self.fail("list_image_versions", "list_microvm_image_versions")?;
        if self.image.as_ref().is_none_or(|i| i.arn != arn) {
            return Err(BridgeError::Sdk { op: "list_microvm_image_versions", message: format!("ResourceNotFoundException: image {arn} not found") });
        }
        Ok(self.versions.clone())
    }

    pub fn list_managed_images(&mut self) -> Result<Vec<ManagedImage>, BridgeError> {
        self.calls.push(Call::ListImages);
        self.fail("list_images", "list_managed_microvm_images")?;
        Ok(vec![ManagedImage { arn: format!("arn:aws:lambda:{REGION}:aws:microvm-image:al2023-1") }])
    }

    pub fn get_network_connector(&mut self, identifier: &str) -> Result<serde_json::Value, BridgeError> {
        self.calls.push(Call::GetConnector(identifier.to_string()));
        self.fail("get_connector", "get_network_connector")?;
        self.connectors
            .get(identifier)
            .cloned()
            .ok_or_else(|| BridgeError::Sdk { op: "get_network_connector", message: format!("ResourceNotFoundException: network connector {identifier} not found") })
    }

    /// The proxy's part of every fake endpoint request (shared by
    /// [`Self::get_health`], [`Self::get_health_detail`] and the tests' fake
    /// `/agent` endpoint): the VM of `endpoint` and a token valid for it, for
    /// `port_header` and now; a SUSPENDED VM with auto-resume is resumed (the
    /// platform holds the request through `/resume`). `Err` is the proxy's
    /// own answer: 403 `UNAUTHORIZED`, 502 `BAD_GATEWAY` / `MICROVM_SUSPENDED`.
    pub fn endpoint_check(&mut self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<String, Box<HealthReply>> {
        let refuse = |status: u16, err: &str| Box::new(HealthReply { status, proxy_error: Some(err.into()), retry_after_s: None, health: None, body: String::new() });
        self.settle();
        let Some(id) = self.vms.values().find(|v| v.endpoint == endpoint).map(|v| v.id.clone()) else {
            return Err(refuse(403, "UNAUTHORIZED"));
        };
        let now = unix_now() + self.clock_offset_s;
        let valid = token.headers.get(TOKEN_HEADER).and_then(|t| Self::parse_token(t.expose())).is_some_and(|(tid, tport, exp)| tid == id && tport == port_header && port_header == token.port && now < exp);
        if !valid {
            return Err(refuse(403, "UNAUTHORIZED"));
        }
        let vm = self.vms.get_mut(&id).expect("found above");
        match vm.state {
            VmState::Terminating | VmState::Terminated | VmState::Pending => return Err(refuse(502, "BAD_GATEWAY")),
            VmState::Suspended | VmState::Suspending if vm.idle.is_some_and(|i| i.auto_resume) => vm.state = VmState::Running,
            VmState::Suspended | VmState::Suspending => return Err(refuse(502, "MICROVM_SUSPENDED")),
            _ => {}
        }
        Ok(id)
    }

    /// A scripted status for `id`'s next endpoint request (`None` = the normal answer).
    fn scripted(&mut self, id: &str) -> Option<HealthReply> {
        let status = self.health_script.get_mut(id).and_then(VecDeque::pop_front)?;
        (status != 200).then(|| HealthReply { status, proxy_error: None, retry_after_s: if status == 429 { self.retry_after_429 } else { None }, health: None, body: String::new() })
    }

    /// The fake endpoint: the proxy's checks, then the shim's `/health`.
    pub fn get_health(&mut self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
        self.calls.push(Call::Health { endpoint: endpoint.to_string(), port: port_header });
        self.fail("health", "health")?;
        let id = match self.endpoint_check(endpoint, token, port_header) {
            Ok(id) => id,
            Err(refusal) => return Ok(*refusal),
        };
        if let Some(r) = self.scripted(&id) {
            return Ok(r);
        }
        let mut health = self.health_override.get(&id).cloned().unwrap_or_else(|| self.default_health(&id));
        let served = self.pre_run_served.entry(id.clone()).or_default();
        if *served < self.pre_run_health {
            *served += 1;
            // What the shim knows before `/run`: no payload (owner, created), no nonce, no uptime.
            health = Health { run_hook_seen: false, owner: None, created: None, boot_nonce: None, microvm_id: None, uptime_s: 0, ..health };
        }
        Ok(HealthReply { status: 200, proxy_error: None, retry_after_s: None, health: Some(health), body: String::new() })
    }

    /// The fake endpoint's `/health/detail`: the proxy's checks, then the
    /// bearer (the VM's session token, whose commitment is in its payload).
    pub fn get_health_detail(&mut self, endpoint: &str, token: &AuthToken, bearer: &Secret<String>) -> Result<HealthDetailReply, BridgeError> {
        self.calls.push(Call::HealthDetail { endpoint: endpoint.to_string(), port: token.port });
        self.fail("health_detail", "health_detail")?;
        let as_detail = |r: HealthReply| HealthDetailReply { status: r.status, proxy_error: r.proxy_error, retry_after_s: r.retry_after_s, detail: None, body: r.body };
        let id = match self.endpoint_check(endpoint, token, token.port) {
            Ok(id) => id,
            Err(refusal) => return Ok(as_detail(*refusal)),
        };
        if let Some(r) = self.scripted(&id) {
            return Ok(as_detail(r));
        }
        let spec = self.tokens.iter().find(|(_, v)| v.as_str() == id).and_then(|(ct, _)| self.specs.iter().find(|s| &s.client_token == ct));
        let payload = spec.and_then(|s| RunHookPayload::from_json(&s.run_hook_payload).ok());
        if !payload.is_some_and(|p| p.matches(bearer.expose().as_bytes())) {
            return Ok(HealthDetailReply { status: 401, proxy_error: None, retry_after_s: None, detail: None, body: "ai-env: bearer required\n".into() });
        }
        let health = self.health_override.get(&id).cloned().unwrap_or_else(|| self.default_health(&id));
        let detail = HealthDetail {
            health,
            image_version: self.vms.get(&id).map(|v| v.image_version.clone()),
            hook_source: "peer".into(),
            agent_guard: "on".into(),
            refused_peers: BTreeMap::new(),
            hook_peers: BTreeMap::new(),
            hook_refusals: BTreeMap::new(),
            sockets_open: 0,
            sockets_authenticated: 0,
            spawns: Vec::new(),
            has_credentials: false,
            clock: None,
            listeners: Vec::new(),
            listeners_omitted: 0,
        };
        Ok(HealthDetailReply { status: 200, proxy_error: None, retry_after_s: None, detail: Some(detail), body: String::new() })
    }

    /// What the shim would answer: owner and created from the VM's own payload.
    fn default_health(&self, id: &str) -> Health {
        let spec = self.tokens.iter().find(|(_, v)| v.as_str() == id).and_then(|(ct, _)| self.specs.iter().find(|s| &s.client_token == ct));
        let payload = spec.and_then(|s| RunHookPayload::from_json(&s.run_hook_payload).ok());
        Health {
            status: HealthStatus::Ok,
            shim_version: "0.1.0".to_string(),
            claude_version: Some("2.1.284".to_string()),
            microvm_id: Some(id.to_string()),
            owner: payload.as_ref().map(|p| p.owner.clone()),
            created: payload.as_ref().map(|p| p.created.clone()),
            boot_nonce: Some(hex::encode(&crate::wire::frame::commitment_hex(id.as_bytes()).as_bytes()[..16])),
            run_hook_seen: true,
            uptime_s: 1,
            wire: Some(crate::wire::frame::WIRE_VERSION),
        }
    }
}

/// In-memory control plane + endpoint over [`FakeState`].
#[derive(Default)]
pub struct FakeMicrovmApi {
    inner: Mutex<FakeState>,
}

impl FakeMicrovmApi {
    /// The default image ([`FakeState::new`]), PENDING until advanced.
    #[must_use]
    pub fn new() -> Self {
        FakeMicrovmApi { inner: Mutex::new(FakeState::new()) }
    }

    /// Direct access to the state for scripting and assertions.
    pub fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn calls(&self) -> Vec<Call> {
        self.state().calls.clone()
    }

    /// The `RunSpec` of every VM created (not of idempotent replays).
    pub fn run_specs(&self) -> Vec<RunSpec> {
        self.state().specs.clone()
    }

    pub fn set_state(&self, id: &str, state: VmState) {
        if let Some(vm) = self.state().vms.get_mut(id) {
            vm.state = state;
        }
    }

    /// The next call fails with this error (once). Queued: several calls fail in order.
    pub fn fail_next(&self, e: BridgeError) {
        self.state().failures.push_back(FakeFailure::from_error(&e));
    }

    /// The next call of kind `on` (`run`, `get`, `health`, …) fails; with
    /// `after_effect` a `run` creates the VM before failing.
    pub fn fail_on(&self, on: &str, e: BridgeError, after_effect: bool) {
        let mut f = FakeFailure::from_error(&e);
        f.on = Some(on.to_string());
        f.after_effect = after_effect;
        self.state().failures.push_back(f);
    }

    /// Pending → Running for every VM (the platform's boot).
    pub fn advance_all(&self) {
        self.state().advance_all();
    }

    /// PENDING → RUNNING on the first `get` of each VM.
    pub fn set_auto_advance(&self, on: bool) {
        self.state().auto_advance = on;
    }

    pub fn insert_vm(&self, vm: VmInfo) {
        self.state().insert_vm(vm);
    }

    pub fn expire_tokens(&self) {
        self.state().expire_tokens();
    }

    /// `/health` of `id` answers these statuses (in order) before the normal answer.
    pub fn script_health(&self, id: &str, statuses: &[u16]) {
        self.state().health_script.insert(id.to_string(), statuses.iter().copied().collect());
    }

    /// `/health` of `id` answers this body.
    pub fn set_health(&self, id: &str, health: Health) {
        self.state().health_override.insert(id.to_string(), health);
    }

    /// Every `RunMicrovm`/`GetMicrovm` answer echoes this egress (`None`: what was sent).
    pub fn set_egress_echo(&self, echo: Option<Vec<String>>) {
        self.state().egress_echo = echo;
    }

    /// `RunMicrovm` answers with an empty egress list.
    pub fn set_run_echo_empty(&self, on: bool) {
        self.state().run_echo_empty = on;
    }

    /// Every `GetMicrovm` answer echoes this egress (`None`: as [`FakeMicrovmApi::set_egress_echo`]).
    pub fn set_get_egress_echo(&self, echo: Option<Vec<String>>) {
        self.state().get_egress_echo = echo;
    }

    /// What `GetNetworkConnector` answers for `identifier` (S7); any other
    /// identifier stays `ResourceNotFoundException`.
    pub fn set_connector(&self, identifier: &str, doc: serde_json::Value) {
        self.state().connectors.insert(identifier.to_string(), doc);
    }
}

impl MicrovmApi for FakeMicrovmApi {
    async fn run(&self, spec: &RunSpec) -> Result<VmInfo, BridgeError> {
        self.state().run(spec)
    }

    async fn get(&self, id: &str) -> Result<VmInfo, BridgeError> {
        self.state().get(id)
    }

    async fn suspend(&self, id: &str) -> Result<(), BridgeError> {
        self.state().suspend(id)
    }

    async fn resume(&self, id: &str) -> Result<(), BridgeError> {
        self.state().resume(id)
    }

    async fn terminate(&self, id: &str) -> Result<(), BridgeError> {
        self.state().terminate(id)
    }

    async fn list(&self, image_arn: Option<&str>) -> Result<Vec<VmSummary>, BridgeError> {
        self.state().list(image_arn)
    }

    async fn create_auth_token(&self, id: &str, minutes: u16, port: u16) -> Result<AuthToken, BridgeError> {
        self.state().create_auth_token(id, minutes, port)
    }

    async fn create_shell_token(&self, id: &str, minutes: u16) -> Result<AuthToken, BridgeError> {
        self.state().create_shell_token(id, minutes)
    }

    async fn get_image(&self, arn: &str) -> Result<ImageInfo, BridgeError> {
        self.state().get_image(arn)
    }

    async fn list_image_versions(&self, arn: &str) -> Result<Vec<ImageVersion>, BridgeError> {
        self.state().list_image_versions(arn)
    }

    async fn list_managed_images(&self) -> Result<Vec<ManagedImage>, BridgeError> {
        self.state().list_managed_images()
    }

    async fn get_network_connector(&self, identifier: &str) -> Result<serde_json::Value, BridgeError> {
        self.state().get_network_connector(identifier)
    }
}

impl EndpointClient for FakeMicrovmApi {
    async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
        self.state().get_health(endpoint, token, port_header)
    }

    async fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &Secret<String>) -> Result<HealthDetailReply, BridgeError> {
        self.state().get_health_detail(endpoint, token, bearer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_normalisation_pins_the_suffix() {
        let host = format!("bed07657-5d0f-abe5-1e5e-6bc7bcb0b637{ENDPOINT_SUFFIX}");
        assert_eq!(normalize_endpoint(&host).unwrap(), host);
        assert_eq!(normalize_endpoint(&format!("https://{host}/")).unwrap(), host);
        assert_eq!(normalize_endpoint(&host.to_ascii_uppercase()).unwrap(), host);
        for bad in [
            format!("http://{host}"),
            format!("{host}/health"),
            format!("{host}:443"),
            format!("a.b{ENDPOINT_SUFFIX}"),
            ENDPOINT_SUFFIX.trim_start_matches('.').to_string(),
            "evil.example.com".to_string(),
            format!("x{ENDPOINT_SUFFIX}.evil.com"),
            String::new(),
        ] {
            let e = normalize_endpoint(&bad).unwrap_err();
            assert!(matches!(e, BridgeError::Endpoint(_)), "{bad}: {e}");
        }
    }

    #[test]
    fn managed_connector_arn_shape() {
        assert_eq!(managed_connector_arn("HTTP_INGRESS"), "arn:aws:lambda:eu-central-1:aws:network-connector:aws-network-connector:HTTP_INGRESS");
    }

    #[test]
    fn fake_tokens_round_trip_and_are_scrubbed_shapes() {
        for (id, port) in [("microvm-00000000-0000-4000-8000-000000000001", 8080u16), ("microvm-00000000-0000-4000-8000-000000000010", 8022)] {
            let t = FakeState::mint(id, port, 1_789_804_800);
            assert_eq!(t.expose().len(), 223);
            assert_eq!(FakeState::parse_token(t.expose()), Some((id.to_string(), port, 1_789_804_800)), "{id}");
        }
    }

    #[test]
    fn the_egress_echo_knobs() {
        let mut s = FakeState::new();
        let spec = |token: &str, egress: Vec<String>| RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: egress,
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: token.into(),
        };
        let conn = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress".to_string();
        let a = s.run(&spec("t1", vec![conn.clone()])).unwrap();
        assert_eq!(a.egress, vec![conn.clone()], "what was sent");
        assert_eq!(s.run(&spec("t2", vec![])).unwrap().egress, vec![managed_connector_arn("INTERNET_EGRESS")], "the platform default");
        s.run_echo_empty = true;
        let b = s.run(&spec("t3", vec![conn.clone()])).unwrap();
        assert!(b.egress.is_empty(), "RunMicrovm answers nothing");
        assert_eq!(s.get(&b.id).unwrap().egress, vec![conn.clone()], "GetMicrovm still knows");
        assert!(s.run(&spec("t3", vec![conn.clone()])).unwrap().egress.is_empty(), "an idempotent replay answers the same way");
        s.run_echo_empty = false;
        s.egress_echo = Some(vec![managed_connector_arn("INTERNET_EGRESS")]);
        assert_eq!(s.get(&a.id).unwrap().egress, vec![managed_connector_arn("INTERNET_EGRESS")], "the override reaches existing VMs");
        assert_eq!(s.run(&spec("t4", vec![conn.clone()])).unwrap().egress, vec![managed_connector_arn("INTERNET_EGRESS")]);
        s.egress_echo = None;
        assert_eq!(s.get(&a.id).unwrap().egress, vec![conn.clone()], "the stored VM kept what was sent");
        s.get_egress_echo = Some(vec![managed_connector_arn("INTERNET_EGRESS")]);
        assert_eq!(s.get(&a.id).unwrap().egress, vec![managed_connector_arn("INTERNET_EGRESS")], "Get only");
        assert_eq!(s.run(&spec("t5", vec![conn.clone()])).unwrap().egress, vec![conn], "Run unaffected");
    }

    /// `GetNetworkConnector` through the fake (S7): the identifier asked for
    /// decides, an unseeded one is not found (never an empty pass), and the
    /// call is recorded.
    #[tokio::test]
    async fn the_fake_answers_only_the_connectors_it_was_given() {
        let api = FakeMicrovmApi::new();
        let arn = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";
        let doc = serde_json::json!({"Id": "nc-1", "State": "ACTIVE"});
        api.set_connector(arn, doc.clone());
        assert_eq!(api.get_network_connector(arn).await.unwrap(), doc);
        let e = api.get_network_connector("nc-1").await.unwrap_err();
        assert!(matches!(&e, BridgeError::Sdk { op: "get_network_connector", message } if message.contains("ResourceNotFoundException")), "another identifier is another key: {e}");
        assert_eq!(api.calls(), vec![Call::GetConnector(arn.to_string()), Call::GetConnector("nc-1".to_string())]);
    }

    /// A client that does not implement the call fails closed, so it can never
    /// be mistaken for one whose facts matched (S7).
    #[tokio::test]
    async fn the_default_connector_read_fails_closed() {
        struct NoConnectors;
        impl MicrovmApi for NoConnectors {
            async fn run(&self, _: &RunSpec) -> Result<VmInfo, BridgeError> {
                unimplemented!()
            }
            async fn get(&self, _: &str) -> Result<VmInfo, BridgeError> {
                unimplemented!()
            }
            async fn suspend(&self, _: &str) -> Result<(), BridgeError> {
                unimplemented!()
            }
            async fn resume(&self, _: &str) -> Result<(), BridgeError> {
                unimplemented!()
            }
            async fn terminate(&self, _: &str) -> Result<(), BridgeError> {
                unimplemented!()
            }
            async fn list(&self, _: Option<&str>) -> Result<Vec<VmSummary>, BridgeError> {
                unimplemented!()
            }
            async fn create_auth_token(&self, _: &str, _: u16, _: u16) -> Result<AuthToken, BridgeError> {
                unimplemented!()
            }
            async fn create_shell_token(&self, _: &str, _: u16) -> Result<AuthToken, BridgeError> {
                unimplemented!()
            }
            async fn get_image(&self, _: &str) -> Result<ImageInfo, BridgeError> {
                unimplemented!()
            }
            async fn list_image_versions(&self, _: &str) -> Result<Vec<ImageVersion>, BridgeError> {
                unimplemented!()
            }
            async fn list_managed_images(&self) -> Result<Vec<ManagedImage>, BridgeError> {
                unimplemented!()
            }
        }
        let e = NoConnectors.get_network_connector("nc-1").await.unwrap_err();
        assert!(matches!(&e, BridgeError::Sdk { op: "get_network_connector", .. }), "{e}");
    }

    #[test]
    fn image_version_runnable() {
        let v = |state: &str, status: &str| ImageVersion { version: "1.0".into(), state: state.into(), status: status.into(), memory_mib: None, created_at_unix: None };
        assert!(v("SUCCESSFUL", "ACTIVE").runnable());
        assert!(!v("SUCCESSFUL", "INACTIVE").runnable());
        assert!(!v("FAILED", "ACTIVE").runnable());
    }
}
