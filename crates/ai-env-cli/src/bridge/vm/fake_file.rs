//! The file-backed fake for process-level tests (plan S4 D23, D25): the same
//! [`FakeState`] state machine as `api::FakeMicrovmApi`, kept in a JSON file
//! so several `ai-env vm …` processes share one control plane (T4.4: three
//! concurrent `vm run --workspace` → exactly one `RunMicrovm`). Every call
//! is load–apply–save under `flock(<file>.lock)`; the file is written
//! atomically, 0600. Reached only through the debug-build knob
//! `AI_ENV_BRIDGE_LAB_FAKE_API=<file>` (`bridge::lab::vm_knobs`).
//!
//! S12 (R1-15 to R1-18): every trait call runs that load–apply–save on
//! tokio's blocking pool ([`FileFakeMicrovmApi::call`]), never on the
//! caller's runtime (the wrapper's is current-thread): its timers, the
//! pump's cut and the closing suspend's, fire on time while a call waits for
//! the lock or the save's fsyncs. A call its caller stopped waiting for runs
//! to its end, recorded and saved, as a request already sent does. One
//! exception: `GET /health` is answered on the caller, within its first
//! poll, while no one holds the lock, as S11's synchronous fake always
//! answered it (the lab-scaled readiness wait cuts it at 1 ms). `with`,
//! `snapshot` and `settled` stay synchronous: the rig and the tests call
//! them from threads. `open` stays synchronous too, but its callers outside
//! the tests run it on their runtime, once per backend built
//! (`vm::cmd::backend`, `agent::credential::connected`): one lock wait with
//! no time limit, one load and one save with its two full fsyncs, as at
//! S11. A wrapper builds its backend once, at the first generation's P1
//! (`credential::backend_for_session`); later generations and a move's
//! phase A reuse it, so no close opens the fake.
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

    /// One look at the state, saved, and the state after it (S10): what
    /// every call's [`FakeState::settle`] does first, alone. A TERMINATING
    /// VM becomes TERMINATED (with `FakeState::terminate_after_hook`, once
    /// its shim answered `/terminate`) and, with `FakeState::enforce_wall`,
    /// a live VM past its wall TERMINATING. The fake endpoint's hook bridge takes it
    /// when its unlocked copy shows a VM past its wall
    /// (`FakeState::wall_due`), then posts that VM's `/terminate`: nothing
    /// else may look at a quiet VM.
    pub fn settled(&self) -> Result<FakeState, BridgeError> {
        self.with(|s| {
            s.settle();
            Ok(s.clone())
        })
    }

    /// S12 (R1): `f` under the file lock (`with`) on tokio's blocking pool, so a call never holds the caller's runtime
    /// (the wrapper's is current-thread) through the lock, the load and the save's two full fsyncs. A caller that stops
    /// waiting (a timeout) leaves the call to run to its end: it is recorded and saved, as the platform takes a request
    /// already sent. A panic in `f` resumes on the caller; a call the runtime's shutdown cancelled is
    /// `BridgeError::Config` naming the state file.
    async fn call<T: Send + 'static>(&self, f: impl FnOnce(&mut FakeState) -> Result<T, BridgeError> + Send + 'static) -> Result<T, BridgeError> {
        let api = self.clone();
        match tokio::task::spawn_blocking(move || api.with(f)).await {
            Ok(answer) => answer,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(_) => Err(BridgeError::Config(format!("fake API state {}: the call did not run (the runtime is shutting down)", self.path.display()))),
        }
    }
}

/// S12 (R1-15): each method's `with` goes through [`FileFakeMicrovmApi::call`], its arguments cloned in.
impl MicrovmApi for FileFakeMicrovmApi {
    async fn run(&self, spec: &RunSpec) -> Result<VmInfo, BridgeError> {
        let spec = spec.clone();
        self.call(move |s| s.run(&spec)).await
    }

    async fn get(&self, id: &str) -> Result<VmInfo, BridgeError> {
        let id = id.to_string();
        let (park, answer) = self.call(move |s| Ok((std::mem::take(&mut s.park_get_ms), s.get(&id)))).await?;
        if park > 0 {
            // A process test's slow GetMicrovm (`FakeState::park_get_ms`): the answer comes late, awaited unlocked.
            tokio::time::sleep(std::time::Duration::from_millis(park)).await;
        }
        answer
    }

    async fn suspend(&self, id: &str) -> Result<(), BridgeError> {
        let id = id.to_string();
        self.call(move |s| s.suspend(&id)).await
    }

    async fn resume(&self, id: &str) -> Result<(), BridgeError> {
        let id = id.to_string();
        self.call(move |s| s.resume(&id)).await
    }

    async fn terminate(&self, id: &str) -> Result<(), BridgeError> {
        let id = id.to_string();
        self.call(move |s| s.terminate(&id)).await
    }

    async fn list(&self, image_arn: Option<&str>) -> Result<Vec<VmSummary>, BridgeError> {
        let image_arn = image_arn.map(str::to_string);
        self.call(move |s| s.list(image_arn.as_deref())).await
    }

    async fn create_auth_token(&self, id: &str, minutes: u16, port: u16) -> Result<AuthToken, BridgeError> {
        let id = id.to_string();
        self.call(move |s| s.create_auth_token(&id, minutes, port)).await
    }

    async fn create_shell_token(&self, id: &str, minutes: u16) -> Result<AuthToken, BridgeError> {
        let id = id.to_string();
        self.call(move |s| s.create_shell_token(&id, minutes)).await
    }

    async fn get_image(&self, arn: &str) -> Result<ImageInfo, BridgeError> {
        let arn = arn.to_string();
        self.call(move |s| s.get_image(&arn)).await
    }

    async fn list_image_versions(&self, arn: &str) -> Result<Vec<ImageVersion>, BridgeError> {
        let arn = arn.to_string();
        self.call(move |s| s.list_image_versions(&arn)).await
    }

    async fn get_network_connector(&self, identifier: &str) -> Result<serde_json::Value, BridgeError> {
        let identifier = identifier.to_string();
        self.call(move |s| s.get_network_connector(&identifier)).await
    }

    async fn list_managed_images(&self) -> Result<Vec<ManagedImage>, BridgeError> {
        self.call(|s| s.list_managed_images()).await
    }
}

/// S9: presigning with the lab's key (`s3::LAB_KEY_ID`, `s3::LAB_SECRET`) for the tests' fake S3 (G4 builds it).
impl crate::bridge::s3::S3Sign for FileFakeMicrovmApi {
    /// Signed with the lab key (`LAB_KEY_ID`, `LAB_SECRET`), as the tests' S3 checks it.
    async fn presign(&self, req: &crate::bridge::s3::PresignReq) -> Result<crate::wire::s3::PresignedUrl, BridgeError> {
        crate::bridge::s3::presign::sign(crate::bridge::s3::presign::lab_credentials(), req, std::time::SystemTime::now())
    }
}

/// S12 (R1-15): each method's `with` goes through [`FileFakeMicrovmApi::call`], its arguments cloned in; `get_health`
/// first tries to answer at once.
impl EndpointClient for FileFakeMicrovmApi {
    /// S12 (R1-15's one exception): answered on the caller, within its first poll, while no one holds `<file>.lock`
    /// (one attempt, `lock::try_lock_exclusive`; then `with`'s load, the state's answer and the save, as at S11): the
    /// lab-scaled readiness wait cuts each `GET /health` at what is left of its 15 ms budget, at least 1 ms
    /// (`vm::health::read_health` under `AI_ENV_BRIDGE_LAB_BACKOFF_MS=1`), which an answer from the blocking pool, a
    /// thread away, never meets. Held: through [`FileFakeMicrovmApi::call`], as every other call.
    async fn get_health(&self, endpoint: &str, token: &AuthToken, port_header: u16) -> Result<HealthReply, BridgeError> {
        if let Some(_guard) = crate::bridge::vm::lock::try_lock_exclusive(&self.lock_path())? {
            // `with`'s steps under the lock this attempt took (`with` itself would wait for it on a second descriptor).
            let mut state = self.load()?;
            let answer = state.get_health(endpoint, token, port_header);
            self.save(&state)?;
            return answer;
        }
        let (endpoint, token) = (endpoint.to_string(), token.clone());
        self.call(move |s| s.get_health(&endpoint, &token, port_header)).await
    }

    /// The state's answer, or, when it names the shim
    /// (`FakeState::health_detail_at`), the call recorded under the lock and
    /// the request sent to the shim outside it: the routed endpoint checks
    /// the token against this same file. S12 (R1): that request stays on the
    /// caller's runtime, after `call` returned.
    async fn get_health_detail(&self, endpoint: &str, token: &AuthToken, bearer: &crate::wire::redact::Secret<String>) -> Result<crate::bridge::api::HealthDetailReply, BridgeError> {
        let (at_endpoint, at_token, at_bearer) = (endpoint.to_string(), token.clone(), bearer.clone());
        let answered = self
            .call(move |s| match s.health_detail_at {
                Some(at) => s.health_detail_call(&at_endpoint, &at_token).map(|()| Err(at)),
                None => s.get_health_detail(&at_endpoint, &at_token, &at_bearer).map(Ok),
            })
            .await?;
        match answered {
            Ok(reply) => Ok(reply),
            Err(at) => detail_from_shim(at, endpoint, token, bearer).await,
        }
    }
}

/// `GET /health/detail` through the routed fake endpoint at `at` (debug
/// builds: `tls::lab_http_client`, plain http to a loopback address only),
/// as `vm::health::HttpsEndpoint` sends it to the real one: the token's
/// headers, the session bearer, `health::REQUEST_TIMEOUT`, the body capped
/// at `health::MAX_DETAIL_BODY` and read by the same rules.
#[cfg(debug_assertions)]
async fn detail_from_shim(at: std::net::SocketAddr, endpoint: &str, token: &AuthToken, bearer: &crate::wire::redact::Secret<String>) -> Result<crate::bridge::api::HealthDetailReply, BridgeError> {
    use crate::bridge::vm::health;
    let host = crate::bridge::api::normalize_endpoint(endpoint)?;
    let url = format!("http://{host}/health/detail");
    let mut auth = reqwest::header::HeaderValue::from_str(token.value()?.expose()).map_err(|_| BridgeError::Sdk { op: "health_detail", message: "the endpoint token is not a valid header value".into() })?;
    auth.set_sensitive(true);
    let req = crate::bridge::tls::lab_http_client(at, &host)?
        .get(&url)
        .header("x-aws-proxy-auth", auth)
        .header("x-aws-proxy-port", token.port.to_string())
        .header(reqwest::header::AUTHORIZATION, health::bearer_header(bearer)?)
        .timeout(health::REQUEST_TIMEOUT);
    let mut resp = req.send().await.map_err(|e| health::transport_error_for("GET", "health_detail", &url, &e))?;
    let (status, headers) = (resp.status().as_u16(), resp.headers().clone());
    let (mut body, mut truncated) = (Vec::new(), false);
    while let Some(chunk) = resp.chunk().await.map_err(|e| health::transport_error_for("GET", "health_detail", &url, &e))? {
        if health::keep_capped(&mut body, &chunk, health::MAX_DETAIL_BODY) {
            truncated = true;
            break;
        }
    }
    health::detail_from_parts(status, &headers, &body, truncated)
}

/// Release builds have no lab client (and no fake API: its knob is debug only).
#[cfg(not(debug_assertions))]
async fn detail_from_shim(_at: std::net::SocketAddr, _endpoint: &str, _token: &AuthToken, _bearer: &crate::wire::redact::Secret<String>) -> Result<crate::bridge::api::HealthDetailReply, BridgeError> {
    Err(BridgeError::Config("the fake API's health_detail_at needs a debug build".into()))
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

    /// S10: the wall through the file (`FakeState::enforce_wall`): a VM
    /// one handle aged past its wall is still RUNNING in a copy no one
    /// looked at; one look (`settled`) ends it for every handle, its
    /// reason saved, and records no call (the platform's end, not a
    /// TerminateMicrovm); the look after finds it TERMINATED.
    #[tokio::test]
    async fn the_wall_is_one_locked_look_every_handle_sees() {
        use crate::bridge::api::FAKE_WALL_REASON;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.json");
        let (a, b) = (FileFakeMicrovmApi::open(&path).unwrap(), FileFakeMicrovmApi::open(&path).unwrap());
        let vm = a.run(&spec("t1")).await.unwrap();
        a.with(|s| {
            s.enforce_wall = true;
            s.advance_all();
            s.age(&vm.id, 900);
            Ok(())
        })
        .unwrap();
        let copy = b.snapshot().unwrap();
        assert!(copy.wall_due() && copy.vms[&vm.id].state == VmState::Running, "no look yet");
        let calls = copy.calls.len();
        let looked = b.settled().unwrap();
        assert_eq!((&looked.vms[&vm.id].state, looked.vms[&vm.id].state_reason.as_deref()), (&VmState::Terminating, Some(FAKE_WALL_REASON)));
        let saved = a.snapshot().unwrap();
        assert_eq!((&saved.vms[&vm.id].state, saved.calls.len()), (&VmState::Terminating, calls), "saved, no call recorded");
        assert_eq!(a.settled().unwrap().vms[&vm.id].state, VmState::Terminated);
    }

    /// S10: the wait for a shim's `/terminate` answer through the file
    /// (`FakeState::terminate_after_hook`): what one handle recorded (the
    /// VM's shim ran, then answered) is what every other handle's look
    /// goes by, and a state saved before the fields existed reads with the
    /// switch off.
    #[tokio::test]
    async fn the_terminate_wait_is_kept_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.json");
        let (a, b) = (FileFakeMicrovmApi::open(&path).unwrap(), FileFakeMicrovmApi::open(&path).unwrap());
        let vm = a.run(&spec("t1")).await.unwrap();
        a.with(|s| {
            s.terminate_after_hook = true;
            s.advance_all();
            s.hook_ran.insert(vm.id.clone());
            Ok(())
        })
        .unwrap();
        b.terminate(&vm.id).await.unwrap();
        for _ in 0..2 {
            assert_eq!(b.get(&vm.id).await.unwrap().state, VmState::Terminating, "its shim has not answered");
        }
        a.with(|s| {
            s.terminate_answered.insert(vm.id.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(b.get(&vm.id).await.unwrap().state, VmState::Terminated);
        let mut old: serde_json::Value = serde_json::to_value(FakeState::new()).unwrap();
        for key in ["terminate_after_hook", "hook_ran", "terminate_answered", "terminating_since"] {
            assert!(old.as_object_mut().unwrap().remove(key).is_some(), "{key} is saved");
        }
        std::fs::write(&path, old.to_string()).unwrap();
        let read = b.snapshot().unwrap();
        assert!(!read.terminate_after_hook && read.hook_ran.is_empty() && read.terminate_answered.is_empty() && read.terminating_since.is_empty());
    }

    /// S12 (R1-15, R1-16): no call holds its caller's runtime (current-thread, as the wrapper's) while another
    /// holds `<file>.lock`: a thread holds it (until the calls below are cut; at most 10 s), and each of the 14
    /// trait methods in turn, under a 150 ms timeout, gives up within 400 ms. Once the lock is let go the cut
    /// calls run to their end, recorded and saved: the cut SuspendMicrovm is in the state's calls, as a request
    /// already sent may still suspend the VM.
    #[tokio::test]
    async fn a_call_never_blocks_the_runtime() {
        use crate::wire::redact::Secret;
        use std::time::{Duration, Instant};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.json");
        let api = FileFakeMicrovmApi::open(&path).unwrap();
        let vm = api.run(&spec("t1")).await.unwrap();
        api.with(|s| {
            s.advance_all();
            Ok(())
        })
        .unwrap();
        let token = api.create_auth_token(&vm.id, 5, 8080).await.unwrap();
        let bearer = Secret::new("b".repeat(64));
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let lock = api.lock_path();
        let holder = std::thread::spawn(move || {
            let guard = lock_blocking(&lock).unwrap();
            held_tx.send(()).unwrap();
            let _ = done_rx.recv_timeout(Duration::from_secs(10));
            drop(guard);
        });
        held_rx.recv().unwrap();
        async fn cut<T: std::fmt::Debug>(what: &str, call: impl std::future::Future<Output = Result<T, BridgeError>>) {
            let t = Instant::now();
            let got = tokio::time::timeout(Duration::from_millis(150), call).await;
            let took = t.elapsed();
            assert!(got.is_err() && took < Duration::from_millis(400), "{what}: the lock held elsewhere, cut at 150 ms: {got:?} after {took:?}");
        }
        let id = vm.id.as_str();
        cut("run", api.run(&spec("t2"))).await;
        cut("get", api.get(id)).await;
        cut("suspend", api.suspend(id)).await;
        cut("resume", api.resume(id)).await;
        cut("terminate", api.terminate("microvm-other0001")).await;
        cut("list", api.list(None)).await;
        cut("create_auth_token", api.create_auth_token(id, 5, 8080)).await;
        cut("create_shell_token", api.create_shell_token(id, 5)).await;
        cut("get_image", api.get_image(FAKE_IMAGE_ARN)).await;
        cut("list_image_versions", api.list_image_versions(FAKE_IMAGE_ARN)).await;
        cut("get_network_connector", api.get_network_connector("nc-0123456789abcdef")).await;
        cut("list_managed_images", api.list_managed_images()).await;
        cut("get_health", api.get_health(&vm.endpoint, &token, 8080)).await;
        cut("get_health_detail", api.get_health_detail(&vm.endpoint, &token, &bearer)).await;
        done_tx.send(()).unwrap();
        holder.join().unwrap();
        let t = Instant::now();
        while !api.snapshot().unwrap().calls.contains(&Call::Suspend(vm.id.clone())) {
            assert!(t.elapsed() < Duration::from_secs(10), "the cut suspend ran to its end once the lock was free: {:?}", api.snapshot().unwrap().calls);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// S12 (R1-15's exception): `GET /health` with `<file>.lock` free answers within its first poll, as S11's did:
    /// under a zero timeout (tokio polls the call before its timer) it still has the state's 200, recorded and saved.
    /// The lab-scaled readiness wait rests on it: each `GET /health` is cut at what is left of a 15 ms budget, at
    /// least 1 ms (`vm::health::read_health` under `AI_ENV_BRIDGE_LAB_BACKOFF_MS=1`), which an answer from the blocking
    /// pool, a thread away, never meets. With the lock held it is cut as every call is (`a_call_never_blocks_the_runtime`).
    #[tokio::test]
    async fn get_health_answers_within_its_first_poll_while_the_lock_is_free() {
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.json");
        let api = FileFakeMicrovmApi::open(&path).unwrap();
        let vm = api.run(&spec("t1")).await.unwrap();
        api.with(|s| {
            s.advance_all();
            Ok(())
        })
        .unwrap();
        let token = api.create_auth_token(&vm.id, 5, 8080).await.unwrap();
        let first = tokio::time::timeout(Duration::ZERO, api.get_health(&vm.endpoint, &token, 8080)).await;
        let reply = first.expect("the lock free: answered within the call's first poll").unwrap();
        assert_eq!((reply.status, reply.health.and_then(|h| h.microvm_id)), (200, Some(vm.id.clone())));
        let health = Call::Health { endpoint: vm.endpoint.clone(), port: 8080 };
        assert_eq!(api.snapshot().unwrap().calls.last(), Some(&health), "the request is recorded and saved");
    }
}
