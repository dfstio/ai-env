//! The MicroVM control-plane surface the bridge needs, behind a trait so every
//! flow is testable against `FakeMicrovmApi`. S0 ships the types, the trait,
//! the fake, the SDK builder helpers (with their traps documented) and the
//! pinned-region `SdkConfig`; the real client lands with the lifecycle stage.
use crate::bridge::config::REGION;
use crate::bridge::errors::BridgeError;
use crate::wire::redact::Secret;
use crate::wire::time::unix_now;
use aws_sdk_lambdamicrovms::error::BuildError;
use aws_sdk_lambdamicrovms::types::{HookState, Hooks, IdlePolicy, MicrovmHooks, MicrovmImageHooks, MicrovmState};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmState {
    Pending,
    Running,
    Suspending,
    Suspended,
    Terminating,
    Terminated,
    Unknown(String),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleSpec {
    pub max_idle_s: i32,
    pub suspended_s: i32,
    pub auto_resume: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSpec {
    pub image_arn: String,
    pub image_version: String,
    pub execution_role_arn: Option<String>,
    pub egress_connectors: Vec<String>,
    pub idle: IdleSpec,
    pub max_duration_s: i32,
    pub run_hook_payload: String,
    pub client_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmInfo {
    pub id: String,
    pub state: VmState,
    pub endpoint: String,
    pub image_arn: String,
    pub image_version: String,
    pub started_at_unix: Option<i64>,
    pub max_duration_s: i32,
    pub state_reason: Option<String>,
}

/// The header map returned by `CreateMicrovmAuthToken` (key `X-aws-proxy-auth`).
#[derive(Debug, Clone)]
pub struct AuthToken {
    pub headers: BTreeMap<String, Secret<String>>,
    pub port: u16,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedImage {
    pub arn: String,
}

/// Everything the bridge asks the control plane. Native `async fn` in the
/// impls; the trait spells out `Send` futures so callers can spawn them.
pub trait MicrovmApi: Send + Sync {
    fn run(&self, spec: &RunSpec) -> impl Future<Output = Result<VmInfo, BridgeError>> + Send;
    fn get(&self, id: &str) -> impl Future<Output = Result<VmInfo, BridgeError>> + Send;
    fn suspend(&self, id: &str) -> impl Future<Output = Result<(), BridgeError>> + Send;
    fn resume(&self, id: &str) -> impl Future<Output = Result<(), BridgeError>> + Send;
    fn terminate(&self, id: &str) -> impl Future<Output = Result<(), BridgeError>> + Send;
    fn list(&self, image_arn: Option<&str>) -> impl Future<Output = Result<Vec<VmInfo>, BridgeError>> + Send;
    fn create_auth_token(&self, id: &str, minutes: u16, port: u16) -> impl Future<Output = Result<AuthToken, BridgeError>> + Send;
    fn list_managed_images(&self) -> impl Future<Output = Result<Vec<ManagedImage>, BridgeError>> + Send;
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

/// SDK configuration with the region pinned in code (`AWS_REGION` and
/// `AWS_DEFAULT_REGION` are never consulted) and the HTTP client from
/// `bridge::tls` (Amazon roots only, aws-lc-rs, proxy env ignored) in place
/// of the SDK default, which would load native roots and honour `HTTPS_PROXY`.
pub async fn sdk_config() -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_lambdamicrovms::config::Region::new(REGION))
        .http_client(crate::bridge::tls::sdk_http_client())
        .load()
        .await
}

// ---- fake ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Run { client_token: String },
    Get(String),
    Suspend(String),
    Resume(String),
    Terminate(String),
    List,
    Token { id: String, minutes: u16, port: u16 },
    ListImages,
}

#[derive(Default)]
struct FakeState {
    vms: BTreeMap<String, VmInfo>,
    tokens: BTreeMap<String, String>,
    calls: Vec<Call>,
    fail_next: Option<BridgeError>,
    next: u64,
}

/// In-memory control plane with the real state machine and call recording.
#[derive(Default)]
pub struct FakeMicrovmApi {
    inner: Mutex<FakeState>,
}

impl FakeMicrovmApi {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    pub fn set_state(&self, id: &str, state: VmState) {
        if let Some(vm) = self.lock().vms.get_mut(id) {
            vm.state = state;
        }
    }

    /// The next call fails with this error (once).
    pub fn fail_next(&self, e: BridgeError) {
        self.lock().fail_next = Some(e);
    }

    /// Pending → Running for every VM (the platform's boot).
    pub fn advance_all(&self) {
        for vm in self.lock().vms.values_mut() {
            if vm.state == VmState::Pending {
                vm.state = VmState::Running;
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn take_failure(st: &mut FakeState) -> Result<(), BridgeError> {
        match st.fail_next.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl MicrovmApi for FakeMicrovmApi {
    async fn run(&self, spec: &RunSpec) -> Result<VmInfo, BridgeError> {
        let mut st = self.lock();
        st.calls.push(Call::Run { client_token: spec.client_token.clone() });
        Self::take_failure(&mut st)?;
        if let Some(id) = st.tokens.get(&spec.client_token) {
            return Ok(st.vms[id].clone());
        }
        st.next += 1;
        let id = format!("mvm-{}", st.next);
        let vm = VmInfo {
            id: id.clone(),
            state: VmState::Pending,
            endpoint: format!("{id}.microvms.{REGION}.on.aws"),
            image_arn: spec.image_arn.clone(),
            image_version: spec.image_version.clone(),
            started_at_unix: Some(unix_now() as i64),
            max_duration_s: spec.max_duration_s,
            state_reason: None,
        };
        st.tokens.insert(spec.client_token.clone(), id.clone());
        st.vms.insert(id, vm.clone());
        Ok(vm)
    }

    async fn get(&self, id: &str) -> Result<VmInfo, BridgeError> {
        let mut st = self.lock();
        st.calls.push(Call::Get(id.to_string()));
        Self::take_failure(&mut st)?;
        st.vms.get(id).cloned().ok_or_else(|| BridgeError::Sdk { op: "get_microvm", message: format!("{id} not found") })
    }

    async fn suspend(&self, id: &str) -> Result<(), BridgeError> {
        let mut st = self.lock();
        st.calls.push(Call::Suspend(id.to_string()));
        Self::take_failure(&mut st)?;
        let vm = st.vms.get_mut(id).ok_or_else(|| BridgeError::Sdk { op: "suspend_microvm", message: format!("{id} not found") })?;
        if vm.state != VmState::Running {
            return Err(BridgeError::Validation(format!("{id} is {:?}, not RUNNING", vm.state)));
        }
        vm.state = VmState::Suspended;
        Ok(())
    }

    async fn resume(&self, id: &str) -> Result<(), BridgeError> {
        let mut st = self.lock();
        st.calls.push(Call::Resume(id.to_string()));
        Self::take_failure(&mut st)?;
        let vm = st.vms.get_mut(id).ok_or_else(|| BridgeError::Sdk { op: "resume_microvm", message: format!("{id} not found") })?;
        if vm.state != VmState::Suspended {
            return Err(BridgeError::Validation(format!("{id} is {:?}, not SUSPENDED", vm.state)));
        }
        vm.state = VmState::Running;
        Ok(())
    }

    async fn terminate(&self, id: &str) -> Result<(), BridgeError> {
        let mut st = self.lock();
        st.calls.push(Call::Terminate(id.to_string()));
        Self::take_failure(&mut st)?;
        let vm = st.vms.get_mut(id).ok_or_else(|| BridgeError::Sdk { op: "terminate_microvm", message: format!("{id} not found") })?;
        vm.state = VmState::Terminated;
        Ok(())
    }

    async fn list(&self, image_arn: Option<&str>) -> Result<Vec<VmInfo>, BridgeError> {
        let mut st = self.lock();
        st.calls.push(Call::List);
        Self::take_failure(&mut st)?;
        Ok(st.vms.values().filter(|v| image_arn.is_none_or(|a| v.image_arn == a)).cloned().collect())
    }

    async fn create_auth_token(&self, id: &str, minutes: u16, port: u16) -> Result<AuthToken, BridgeError> {
        let mut st = self.lock();
        st.calls.push(Call::Token { id: id.to_string(), minutes, port });
        Self::take_failure(&mut st)?;
        if !st.vms.contains_key(id) {
            return Err(BridgeError::Sdk { op: "create_microvm_auth_token", message: format!("{id} not found") });
        }
        let mut headers = BTreeMap::new();
        headers.insert("X-aws-proxy-auth".to_string(), Secret::new(format!("eyJ{}", "a".repeat(220))));
        Ok(AuthToken { headers, port, expires_at_unix: unix_now() + u64::from(minutes) * 60 })
    }

    async fn list_managed_images(&self) -> Result<Vec<ManagedImage>, BridgeError> {
        let mut st = self.lock();
        st.calls.push(Call::ListImages);
        Self::take_failure(&mut st)?;
        Ok(vec![ManagedImage { arn: format!("arn:aws:lambda:{REGION}:aws:microvm-image:al2023-1") }])
    }
}
