//! The file-backed fake for process-level tests (plan S4 D23, D25): the same
//! [`FakeState`] state machine as `api::FakeMicrovmApi`, kept in a JSON file
//! so several `ai-env vm …` processes share one control plane (T4.4: three
//! concurrent `vm run --workspace` → exactly one `RunMicrovm`). Every call
//! is load–apply–save under `flock(<file>.lock)`; the file is written
//! atomically, 0600. Reached only through the debug-build knob
//! `AI_ENV_BRIDGE_LAB_FAKE_API=<file>` (`bridge::lab::vm_knobs`).
use crate::bridge::api::{AuthToken, EndpointClient, FakeState, HealthReply, ImageInfo, ImageVersion, ManagedImage, MicrovmApi, RunSpec, VmInfo, VmSummary};
use crate::bridge::errors::BridgeError;
use crate::bridge::infra::write_atomic_mode;
use crate::bridge::vm::lock::lock_blocking;
use std::path::{Path, PathBuf};

/// A fake control plane + endpoint whose state lives in a file.
#[derive(Debug, Clone)]
pub struct FileFakeMicrovmApi {
    path: PathBuf,
}

impl FileFakeMicrovmApi {
    /// Use `path` (created with [`FakeState::new`] when missing or empty).
    pub fn open(path: &Path) -> Result<FileFakeMicrovmApi, BridgeError> {
        let api = FileFakeMicrovmApi { path: path.to_path_buf() };
        api.with(|_| Ok(()))?;
        Ok(api)
    }

    fn lock_path(&self) -> PathBuf {
        let mut name = self.path.file_name().map(std::ffi::OsStr::to_os_string).unwrap_or_default();
        name.push(".lock");
        self.path.with_file_name(name)
    }

    fn load(&self) -> Result<FakeState, BridgeError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) if text.trim().is_empty() => Ok(FakeState::new()),
            Ok(text) => serde_json::from_str(&text).map_err(|e| BridgeError::Config(format!("fake API state {}: {e}", self.path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FakeState::new()),
            Err(e) => Err(BridgeError::Io(std::io::Error::new(e.kind(), format!("cannot read {}: {e}", self.path.display())))),
        }
    }

    fn save(&self, state: &FakeState) -> Result<(), BridgeError> {
        let text = serde_json::to_string_pretty(state).map_err(|e| BridgeError::Config(format!("fake API state: {e}")))?;
        write_atomic_mode(&self.path, text.as_bytes(), 0o600)
    }

    /// Load, apply `f`, save — all under the file lock. The state is saved
    /// even when `f` fails (the call and the consumed failure are recorded).
    pub fn with<T>(&self, f: impl FnOnce(&mut FakeState) -> Result<T, BridgeError>) -> Result<T, BridgeError> {
        let _guard = lock_blocking(&self.lock_path())?;
        let mut state = self.load()?;
        let result = f(&mut state);
        self.save(&state)?;
        result
    }

    /// A copy of the current state (for assertions).
    pub fn snapshot(&self) -> Result<FakeState, BridgeError> {
        self.with(|s| Ok(s.clone()))
    }
}

impl MicrovmApi for FileFakeMicrovmApi {
    async fn run(&self, spec: &RunSpec) -> Result<VmInfo, BridgeError> {
        self.with(|s| s.run(spec))
    }

    async fn get(&self, id: &str) -> Result<VmInfo, BridgeError> {
        self.with(|s| s.get(id))
    }

    async fn suspend(&self, id: &str) -> Result<(), BridgeError> {
        self.with(|s| s.suspend(id))
    }

    async fn resume(&self, id: &str) -> Result<(), BridgeError> {
        self.with(|s| s.resume(id))
    }

    async fn terminate(&self, id: &str) -> Result<(), BridgeError> {
        self.with(|s| s.terminate(id))
    }

    async fn list(&self, image_arn: Option<&str>) -> Result<Vec<VmSummary>, BridgeError> {
        self.with(|s| s.list(image_arn))
    }

    async fn create_auth_token(&self, id: &str, minutes: u16, port: u16) -> Result<AuthToken, BridgeError> {
        self.with(|s| s.create_auth_token(id, minutes, port))
    }

    async fn create_shell_token(&self, id: &str, minutes: u16) -> Result<AuthToken, BridgeError> {
        self.with(|s| s.create_shell_token(id, minutes))
    }

    async fn get_image(&self, arn: &str) -> Result<ImageInfo, BridgeError> {
        self.with(|s| s.get_image(arn))
    }

    async fn list_image_versions(&self, arn: &str) -> Result<Vec<ImageVersion>, BridgeError> {
        self.with(|s| s.list_image_versions(arn))
    }

    async fn list_managed_images(&self) -> Result<Vec<ManagedImage>, BridgeError> {
        self.with(|s| s.list_managed_images())
    }
}

impl EndpointClient for FileFakeMicrovmApi {
    async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
        self.with(|s| s.get_health(endpoint, token, port_header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::api::{Call, IdleSpec, VmState, FAKE_IMAGE_ARN};

    fn spec(token: &str) -> RunSpec {
        RunSpec {
            image_arn: FAKE_IMAGE_ARN.into(),
            image_version: "1.0".into(),
            execution_role_arn: None,
            ingress_connectors: vec![],
            egress_connectors: vec![],
            idle: IdleSpec { max_idle_s: 300, suspended_s: 900, auto_resume: true },
            max_duration_s: 900,
            run_hook_payload: "{}".into(),
            client_token: token.into(),
        }
    }

    #[tokio::test]
    async fn two_handles_share_one_state_and_calls_are_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.json");
        let a = FileFakeMicrovmApi::open(&path).unwrap();
        let b = FileFakeMicrovmApi::open(&path).unwrap();
        let vm = a.run(&spec("t1")).await.unwrap();
        assert_eq!(b.run(&spec("t1")).await.unwrap().id, vm.id, "idempotent across handles");
        b.with(|s| {
            s.advance_all();
            Ok(())
        })
        .unwrap();
        assert_eq!(a.get(&vm.id).await.unwrap().state, VmState::Running);
        let calls = a.snapshot().unwrap().calls;
        assert_eq!(calls.iter().filter(|c| matches!(c, Call::Run { .. })).count(), 2);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn a_failing_call_still_records_itself() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.json");
        let api = FileFakeMicrovmApi::open(&path).unwrap();
        assert!(matches!(api.get("microvm-nope").await.unwrap_err(), BridgeError::VmNotFound(_)));
        assert_eq!(api.snapshot().unwrap().calls, vec![Call::Get("microvm-nope".into())]);
    }
}
