//! Shared harness of `tests/vm.rs`: a temp bridge root with a parsed
//! `bridge.toml` (`[aws] image_arn` = the fake image, one workspace root),
//! run flags for a 3600 s VM, the 1 ms poll, a VM started straight through
//! the API (a crash between RunMicrovm and the row, or another owner's VM),
//! a byte-for-byte snapshot of the root, and [`Spy`], a fake that looks at
//! the registry when RunMicrovm is called and can kill a VM while it boots.
#![allow(dead_code)]

use ai_env_cli::bridge::api::{
    AuthToken, EndpointClient, FakeMicrovmApi, HealthReply, IdleSpec, ImageInfo, ImageVersion, ManagedImage, MicrovmApi, RunSpec, VmInfo, VmState, VmSummary, FAKE_IMAGE_ARN,
};
use ai_env_cli::bridge::audit;
use ai_env_cli::bridge::config::{BridgeConfig, Paths};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::vm::registry::{self, RowStatus, VmRow};
use ai_env_cli::bridge::vm::run::{build_payload, new_session_token, Egress, Poll, RunFlags, RunPlan};
use ai_env_cli::errors::CliError;
use ai_env_cli::wire::frame::{commitment_hex, Health, HealthStatus};
use ai_env_cli::wire::time::{rfc3339_utc_ms, unix_now, unix_now_ms};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A made-up egress connector of the documentation account.
pub const CONNECTOR: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-egress";

/// Another owner, as a colleague's `/health` would answer.
pub const FOREIGN: &str = "someone@elsewhere";

/// One temp bridge root, its config and an approved workspace.
pub struct Env {
    pub dir: tempfile::TempDir,
    pub paths: Paths,
    /// `[workspaces].roots = [work]`.
    pub work: PathBuf,
    /// `work/ws`, the default `--workspace`.
    pub ws: PathBuf,
    pub cfg: BridgeConfig,
}

impl Env {
    /// `max_concurrent = 10` so multi-VM scenarios fit; `[egress].require` stays true.
    pub fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        let ws = work.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let paths = Paths::from_root_and_env(dir.path().join("bridge"), None);
        let text = format!("[aws]\nimage_arn = \"{FAKE_IMAGE_ARN}\"\n[vm]\nmax_concurrent = 10\n[workspaces]\nroots = [{:?}]\n", work);
        let cfg = BridgeConfig::parse(&text).unwrap();
        Env { dir, paths, work, ws, cfg }
    }

    /// Another workspace under the root (created).
    pub fn workspace(&self, name: &str) -> PathBuf {
        let p = self.work.join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// `--workspace ws --egress internet --max-duration 3600`, purpose `test`.
    pub fn flags(&self) -> RunFlags {
        RunFlags { max_duration_s: Some(3600), egress: Some(Egress::Internet), workspace: Some(self.ws.clone()), purpose: "test", ..RunFlags::default() }
    }

    pub fn plan(&self, flags: &RunFlags) -> RunPlan {
        RunPlan::from_cfg(&self.cfg, flags).unwrap_or_else(|e| panic!("plan: {e}"))
    }

    pub fn rows(&self) -> Vec<VmRow> {
        registry::list_rows(&self.paths).unwrap()
    }

    pub fn row(&self, id: &str) -> VmRow {
        registry::read_row(&self.paths, id).unwrap().unwrap_or_else(|| panic!("no row {id}"))
    }

    pub fn audit(&self) -> Vec<serde_json::Value> {
        audit::read_rows(&self.paths.audit(), None).unwrap()
    }

    /// The audit rows of one event.
    pub fn events(&self, event: &str) -> Vec<serde_json::Value> {
        self.audit().into_iter().filter(|r| r["event"] == event).collect()
    }

    /// Write a pending row as a crashed `select_vm` would have left it.
    pub fn pending_row(&self, owner: &str, created: &str, max_duration_s: u32) -> VmRow {
        self.pending_row_with_token(owner, created, max_duration_s, new_session_token().expose().clone())
    }

    /// [`Env::pending_row`] holding `token` as its session token.
    pub fn pending_row_with_token(&self, owner: &str, created: &str, max_duration_s: u32, token: String) -> VmRow {
        let row = VmRow {
            status: RowStatus::Pending,
            client_token: uuid::Uuid::now_v7().to_string(),
            image_arn: FAKE_IMAGE_ARN.to_string(),
            image_version: "1.0".to_string(),
            owner: owner.to_string(),
            created: created.to_string(),
            commit: commitment_hex(token.as_bytes()),
            session_token: Some(token),
            max_duration_s,
            egress: "internet".to_string(),
            ..VmRow::default()
        };
        registry::write_pending(&self.paths, &row).unwrap();
        row
    }
}

/// Every poll 1 s → 1 ms (RUNNING: 60 ms budget).
pub fn fast() -> Poll {
    Poll::RUNNING.scaled(Some(1))
}

/// The fake with PENDING → RUNNING on the first GetMicrovm.
pub fn api() -> FakeMicrovmApi {
    let a = FakeMicrovmApi::new();
    a.set_auto_advance(true);
    a
}

pub fn exit(e: BridgeError) -> i32 {
    CliError::from(e).exit_code()
}

/// `created` `offset_ms` from now (RFC 3339, milliseconds).
pub fn created_at(offset_ms: i64) -> String {
    rfc3339_utc_ms(unix_now_ms().saturating_add_signed(offset_ms))
}

/// A VM started straight through the API with a payload of `owner` +
/// `created` and no row (PENDING until advanced).
pub async fn run_direct<A: MicrovmApi>(api: &A, owner: &str, created: &str) -> VmInfo {
    let payload = build_payload(&new_session_token(), owner, created).unwrap();
    let spec = RunSpec {
        image_arn: FAKE_IMAGE_ARN.to_string(),
        image_version: "1.0".to_string(),
        execution_role_arn: None,
        ingress_connectors: Vec::new(),
        egress_connectors: Vec::new(),
        idle: IdleSpec { max_idle_s: 300, suspended_s: 3600, auto_resume: true },
        max_duration_s: 3600,
        run_hook_payload: payload,
        client_token: uuid::Uuid::now_v7().to_string(),
    };
    api.run(&spec).await.unwrap()
}

/// [`run_direct`] for another image (the fake does not check the image on RunMicrovm).
pub async fn run_direct_image<A: MicrovmApi>(api: &A, image_arn: &str, owner: &str, created: &str) -> VmInfo {
    let payload = build_payload(&new_session_token(), owner, created).unwrap();
    let spec = RunSpec {
        image_arn: image_arn.to_string(),
        image_version: "1.0".to_string(),
        execution_role_arn: None,
        ingress_connectors: Vec::new(),
        egress_connectors: Vec::new(),
        idle: IdleSpec { max_idle_s: 300, suspended_s: 3600, auto_resume: true },
        max_duration_s: 3600,
        run_hook_payload: payload,
        client_token: uuid::Uuid::now_v7().to_string(),
    };
    api.run(&spec).await.unwrap()
}

/// A GetMicrovm failure as the real client maps a timeout, a dispatch failure or a 5xx.
pub fn get_timeout() -> BridgeError {
    BridgeError::Sdk { op: "get_microvm", message: "dispatch failure: operation timeout".into() }
}

/// Queue `n` failures of every later GetMicrovm (clear with `api.state().failures.clear()`).
pub fn fail_gets(api: &FakeMicrovmApi, e: impl Fn() -> BridgeError, n: usize) {
    for _ in 0..n {
        api.fail_on("get", e(), false);
    }
}

/// A shim `/health` body (HTTP 200, `ok`) claiming `microvm_id`, `owner` and `created`.
pub fn health_claiming(microvm_id: Option<&str>, owner: &str, created: &str) -> Health {
    Health {
        status: HealthStatus::Ok,
        shim_version: "0.1.0".to_string(),
        claude_version: Some("2.1.284".to_string()),
        microvm_id: microvm_id.map(str::to_string),
        owner: Some(owner.to_string()),
        created: Some(created.to_string()),
        boot_nonce: Some("0f".repeat(8)),
        run_hook_seen: true,
        uptime_s: 1,
        wire: None,
        caps: vec![],
    }
}

/// Move a fake VM's start `secs` into the past.
pub fn started_ago(api: &FakeMicrovmApi, id: &str, secs: u64) {
    api.state().vms.get_mut(id).unwrap().started_at_unix = Some((unix_now() - secs) as i64);
}

/// Every file and directory under `root`: relative path → (mode, bytes).
pub fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, (u32, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let mode = meta.permissions().mode();
            if meta.is_dir() {
                out.insert(rel, (mode, Vec::new()));
                walk(root, &path, out);
            } else {
                out.insert(rel, (mode, std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// A fake that records, at the moment RunMicrovm is called, whether the
/// pending row of that client token is already on disk, that can turn a
/// VM TERMINATED (with a `stateReason`) on its first GetMicrovm, and that
/// can refuse `ListMicrovms` of one image (as the image-scoped runtime
/// policy would, AccessDenied).
pub struct Spy {
    pub inner: FakeMicrovmApi,
    pub paths: Paths,
    pub pending_at_run: Mutex<Vec<bool>>,
    pub kill_on_get: Mutex<Option<String>>,
    pub deny_list_image: Mutex<Option<String>>,
}

impl Spy {
    pub fn new(paths: &Paths) -> Spy {
        Spy { inner: api(), paths: paths.clone(), pending_at_run: Mutex::new(Vec::new()), kill_on_get: Mutex::new(None), deny_list_image: Mutex::new(None) }
    }
}

impl MicrovmApi for Spy {
    async fn run(&self, spec: &RunSpec) -> Result<VmInfo, BridgeError> {
        let there = registry::list_rows(&self.paths).unwrap().iter().any(|r| r.is_pending_row() && r.client_token == spec.client_token);
        self.pending_at_run.lock().unwrap().push(there);
        self.inner.run(spec).await
    }

    async fn get(&self, id: &str) -> Result<VmInfo, BridgeError> {
        let reason = self.kill_on_get.lock().unwrap().take();
        if let Some(reason) = reason {
            let mut st = self.inner.state();
            if let Some(vm) = st.vms.get_mut(id) {
                vm.state = VmState::Terminated;
                vm.state_reason = Some(reason);
            }
        }
        self.inner.get(id).await
    }

    async fn suspend(&self, id: &str) -> Result<(), BridgeError> {
        self.inner.suspend(id).await
    }

    async fn resume(&self, id: &str) -> Result<(), BridgeError> {
        self.inner.resume(id).await
    }

    async fn terminate(&self, id: &str) -> Result<(), BridgeError> {
        self.inner.terminate(id).await
    }

    async fn list(&self, image_arn: Option<&str>) -> Result<Vec<VmSummary>, BridgeError> {
        let denied = self.deny_list_image.lock().unwrap().clone();
        if denied.is_some() && denied.as_deref() == image_arn {
            return Err(BridgeError::AccessDenied(format!("list_microvms: not authorized on {}", image_arn.unwrap_or_default())));
        }
        self.inner.list(image_arn).await
    }

    async fn create_auth_token(&self, id: &str, minutes: u16, port: u16) -> Result<AuthToken, BridgeError> {
        self.inner.create_auth_token(id, minutes, port).await
    }

    async fn create_shell_token(&self, id: &str, minutes: u16) -> Result<AuthToken, BridgeError> {
        self.inner.create_shell_token(id, minutes).await
    }

    async fn get_image(&self, arn: &str) -> Result<ImageInfo, BridgeError> {
        self.inner.get_image(arn).await
    }

    async fn list_image_versions(&self, arn: &str) -> Result<Vec<ImageVersion>, BridgeError> {
        self.inner.list_image_versions(arn).await
    }

    async fn list_managed_images(&self) -> Result<Vec<ManagedImage>, BridgeError> {
        self.inner.list_managed_images().await
    }
}

impl EndpointClient for Spy {
    async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
        self.inner.get_health(endpoint, token, port_header).await
    }
}
