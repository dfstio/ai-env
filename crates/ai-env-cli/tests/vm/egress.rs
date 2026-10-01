//! The S5 egress echo gate in-process (plan S5, W3): a VM must echo exactly
//! the connectors its egress requires — at RunMicrovm (else GetMicrovm), in
//! the RUNNING answer, on reuse, on adoption, and again in `vm gc` for every
//! live row whose gate did not pass — or it is terminated (`policy`),
//! audited `vm_egress_mismatch`, and the run fails with exit 9.
use crate::common::{api as new_api, created_at, exit, fail_gets, fast, get_timeout, run_direct, Env, Spy, CONNECTOR};
use ai_env_cli::bridge::api::{AuthToken, Call, FakeMicrovmApi, ImageInfo, ImageVersion, ManagedImage, MicrovmApi, RunSpec, VmInfo, VmState, VmSummary, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::egress::internet_egress_arn;
use ai_env_cli::bridge::errors::{BridgeError, EgressMismatch};
use ai_env_cli::bridge::infra::InfraState;
use ai_env_cli::bridge::vm::gc::{gc, GcOpts, GcReport};
use ai_env_cli::bridge::vm::owner;
use ai_env_cli::bridge::vm::registry::{self, RowStatus, VmRow, GATE_MISMATCH, GATE_PASSED, GATE_PENDING};
use ai_env_cli::bridge::vm::run::{adopt_after_ambiguous, adopt_after_ambiguous_for, new_session_token, select_vm, select_vm_detailed, Adoption, Egress, RunFlags, SelectFailure, Selected};
use ai_env_cli::wire::frame::commitment_hex;
use ai_env_cli::wire::time::unix_now;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

/// Another connector of the documentation account.
const OTHER: &str = "arn:aws:lambda:eu-central-1:123456789012:network-connector:ai-env-other";

/// The connector's Id, as `state/infra.toml` records it after a live read.
const ID: &str = "nc-0a1b2c3d";

const YES: GcOpts = GcOpts { yes: true, include_orphans: None, probe_health: true };
const DRY: GcOpts = GcOpts { yes: false, include_orphans: None, probe_health: true };

/// The connector's ARN with its Id as the resource name (an Id-form echo).
fn id_arn() -> String {
    format!("arn:aws:lambda:eu-central-1:123456789012:network-connector:{ID}")
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_string()).collect()
}

/// A bridge root whose `[aws].egress_connector_arn` is [`CONNECTOR`].
fn vpc_env() -> Env {
    let mut env = Env::new();
    env.cfg.aws.egress_connector_arn = Some(CONNECTOR.to_string());
    env
}

/// `--egress vpc` without a workspace (never reuses).
fn vpc(env: &Env) -> RunFlags {
    RunFlags { egress: Some(Egress::Vpc), workspace: None, ..env.flags() }
}

/// `--egress vpc --workspace ws` (reuses).
fn vpc_ws(env: &Env) -> RunFlags {
    RunFlags { egress: Some(Egress::Vpc), ..env.flags() }
}

async fn run<A: MicrovmApi>(env: &Env, api: &A, flags: &RunFlags) -> Result<Selected, SelectFailure> {
    select_vm_detailed(api, &env.paths, &env.plan(flags), fast()).await
}

fn started_id(s: &Selected) -> String {
    match s {
        Selected::Started { row, .. } => row.id.clone(),
        Selected::Reused { row, .. } => panic!("expected a new VM, reused {}", row.id),
    }
}

fn mismatch(e: &BridgeError) -> EgressMismatch {
    match e {
        BridgeError::EgressMismatch(m) => (**m).clone(),
        other => panic!("expected an egress mismatch, got: {other}"),
    }
}

/// Every VM TerminateMicrovm was called for, in order.
fn terminated(api: &FakeMicrovmApi) -> Vec<String> {
    api.calls().iter().filter_map(|c| if let Call::Terminate(id) = c { Some(id.clone()) } else { None }).collect()
}

/// The calls after the (one) RunMicrovm.
fn after_run(api: &FakeMicrovmApi) -> Vec<Call> {
    let calls = api.calls();
    let at = calls.iter().position(|c| matches!(c, Call::Run { .. })).expect("a RunMicrovm");
    calls[at + 1..].to_vec()
}

/// The detail of the one `vm_egress_mismatch` row, as (id, expected, echoed, via, purpose, terminated).
fn mismatch_audit(env: &Env) -> (String, String, String, String, String, String) {
    let rows = env.events("vm_egress_mismatch");
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0]["detail"];
    let f = |k: &str| d[k].as_str().unwrap_or_else(|| panic!("{k} missing: {d}")).to_string();
    assert_eq!(d.as_object().unwrap().len(), 7, "actor plus the six keys: {d}");
    (f("id"), f("expected"), f("echoed"), f("via"), f("purpose"), f("terminated"))
}

/// `by` of every `vm_terminate` row, in order.
fn terminate_by(env: &Env) -> Vec<String> {
    env.events("vm_terminate").iter().map(|r| r["detail"]["by"].as_str().unwrap().to_string()).collect()
}

/// `state/infra.toml` with this connector record (state ACTIVE).
fn write_state(env: &Env, connector_arn: Option<&str>, connector_id: Option<&str>) {
    let state = InfraState { stack: "dev".into(), connector_arn: connector_arn.map(str::to_string), connector_id: connector_id.map(str::to_string), connector_state: Some("ACTIVE".into()), ..InfraState::default() };
    let path = env.paths.infra_state();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, state.render().unwrap()).unwrap();
}

/// A select whose RunMicrovm fails ambiguously twice (the VM is created): the pending row it keeps.
async fn kept_pending(env: &Env, api: &FakeMicrovmApi, flags: &RunFlags) -> VmRow {
    let ambiguous = || BridgeError::Ambiguous { op: "run_microvm", message: "dispatch failure: connection reset".into() };
    api.fail_on("run", ambiguous(), true);
    api.fail_on("run", ambiguous(), true);
    *run(env, api, flags).await.unwrap_err().kept_pending.expect("the pending row is kept")
}

fn pending_on_disk(env: &Env) -> Option<VmRow> {
    env.rows().into_iter().find(VmRow::is_pending_row)
}

/// Rewrite the row of `id` (as another build, or a crash, left it).
fn edit_row(env: &Env, id: &str, f: impl FnOnce(&mut VmRow)) {
    let mut row = env.row(id);
    f(&mut row);
    registry::write_row(&env.paths, &row).unwrap();
}

fn throttled() -> BridgeError {
    BridgeError::Throttled("Rate exceeded".into())
}

/// The fake with two hooks: a TerminateMicrovm that first makes `state/vms`
/// read-only (the row write after it fails), and, once a VM was resumed,
/// GetMicrovm answers for it that echo `echo_after_resume`.
struct Hooked {
    inner: FakeMicrovmApi,
    read_only_on_terminate: Option<PathBuf>,
    echo_after_resume: Option<Vec<String>>,
    resumed: Mutex<Vec<String>>,
}

impl Hooked {
    fn new() -> Hooked {
        Hooked { inner: new_api(), read_only_on_terminate: None, echo_after_resume: None, resumed: Mutex::new(Vec::new()) }
    }
}

impl MicrovmApi for Hooked {
    async fn run(&self, spec: &RunSpec) -> Result<VmInfo, BridgeError> {
        self.inner.run(spec).await
    }

    async fn get(&self, id: &str) -> Result<VmInfo, BridgeError> {
        let mut vm = self.inner.get(id).await?;
        if let Some(echo) = self.echo_after_resume.as_ref().filter(|_| self.resumed.lock().unwrap().iter().any(|r| r == id)) {
            vm.egress.clone_from(echo);
        }
        Ok(vm)
    }

    async fn suspend(&self, id: &str) -> Result<(), BridgeError> {
        self.inner.suspend(id).await
    }

    async fn resume(&self, id: &str) -> Result<(), BridgeError> {
        self.resumed.lock().unwrap().push(id.to_string());
        self.inner.resume(id).await
    }

    async fn terminate(&self, id: &str) -> Result<(), BridgeError> {
        if let Some(dir) = &self.read_only_on_terminate {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        self.inner.terminate(id).await
    }

    async fn list(&self, image_arn: Option<&str>) -> Result<Vec<VmSummary>, BridgeError> {
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

async fn gc_yes(env: &Env, api: &FakeMicrovmApi) -> GcReport {
    gc(api, api, &env.paths, FAKE_IMAGE_ARN, &YES).await.unwrap()
}

// ---- after RunMicrovm -----------------------------------------------------------------------

#[tokio::test]
async fn a_vpc_run_echoing_internet_egress_is_terminated_audited_and_exits_9() {
    let env = vpc_env();
    let api = new_api();
    api.set_egress_echo(Some(vec![internet_egress_arn()]));
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    let m = mismatch(&f.error);
    assert_eq!((m.expected.clone(), m.echoed.clone(), m.terminated), (s(&[CONNECTOR]), vec![internet_egress_arn()], true));
    assert_eq!(f.started, None, "terminated: nothing is left for the caller to terminate");
    assert!(f.client_token.is_some() && f.kept_pending.is_none());
    assert_eq!(after_run(&api), [Call::Terminate(m.id.clone())], "the gate comes before the RUNNING poll, and TerminateMicrovm does not wait");
    let row = env.row(&m.id);
    assert_eq!((row.status, row.terminated_by.as_deref(), row.egress_gate.as_deref()), (RowStatus::Terminated, Some("policy"), Some(GATE_MISMATCH)));
    assert_eq!(row.egress_connectors, [CONNECTOR], "a failed echo is never stored: the planned list stays");
    assert_eq!(mismatch_audit(&env), (m.id.clone(), CONNECTOR.into(), internet_egress_arn(), "run".into(), "test".into(), "true".into()));
    assert_eq!(terminate_by(&env), ["policy"]);
    assert_eq!(env.events("vm_run").len(), 1, "the run itself is audited before the gate");
    assert!(api.state().vms[&m.id].state.is_terminal());
    assert!(f.error.to_string().contains("; terminated"), "{}", f.error);
    assert_eq!(exit(f.error), 9);
}

#[tokio::test]
async fn a_no_wait_run_is_gated_too() {
    let env = vpc_env();
    let api = new_api();
    api.set_egress_echo(Some(vec![internet_egress_arn()]));
    let f = run(&env, &api, &RunFlags { wait: false, ..vpc(&env) }).await.unwrap_err();
    let m = mismatch(&f.error);
    assert!(m.terminated);
    assert_eq!(terminated(&api), [m.id]);
}

#[tokio::test]
async fn an_extra_a_missing_or_another_connector_fails_the_gate() {
    for echo in [s(&[CONNECTOR, OTHER]), s(&[OTHER]), vec![CONNECTOR.to_string(), internet_egress_arn()], vec![CONNECTOR.to_string(), CONNECTOR.to_string(), OTHER.to_string()]] {
        let env = vpc_env();
        let api = new_api();
        api.set_egress_echo(Some(echo.clone()));
        let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
        let m = mismatch(&f.error);
        assert_eq!((m.echoed.clone(), m.terminated), (echo.clone(), true), "{echo:?}");
        assert_eq!(terminated(&api), [m.id.as_str()], "{echo:?}");
        assert_eq!(mismatch_audit(&env).2, echo.join(","), "the echo as it came, joined with ','");
        assert_eq!(exit(f.error), 9, "{echo:?}");
    }
}

#[tokio::test]
async fn the_running_answer_is_gated_too() {
    // RunMicrovm echoes the connector; the RUNNING answer (a GetMicrovm) says INTERNET_EGRESS.
    let env = vpc_env();
    let api = new_api();
    api.set_get_egress_echo(Some(vec![internet_egress_arn()]));
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    let m = mismatch(&f.error);
    assert_eq!((m.echoed.clone(), m.terminated, f.started.clone()), (vec![internet_egress_arn()], true, None));
    assert_eq!(after_run(&api), [Call::Get(m.id.clone()), Call::Terminate(m.id.clone())]);
    let row = env.row(&m.id);
    assert_eq!((row.status, row.terminated_by.as_deref(), row.egress_gate.as_deref()), (RowStatus::Terminated, Some("policy"), Some(GATE_MISMATCH)));
    assert_eq!(mismatch_audit(&env).3, "run");
    assert_eq!(exit(f.error), 9);
    // A RUNNING answer that reports no egress is not judged again (the RunMicrovm echo passed).
    let env = vpc_env();
    let api = new_api();
    api.set_get_egress_echo(Some(vec![]));
    let id = started_id(&run(&env, &api, &vpc(&env)).await.unwrap());
    assert_eq!(env.row(&id).egress_gate.as_deref(), Some(GATE_PASSED));
}

#[tokio::test]
async fn an_empty_run_echo_is_judged_by_get_microvm() {
    // GetMicrovm echoes the connector: a pass.
    let env = vpc_env();
    let api = new_api();
    api.set_run_echo_empty(true);
    let id = started_id(&run(&env, &api, &vpc(&env)).await.unwrap());
    assert_eq!(after_run(&api).first(), Some(&Call::Get(id.clone())), "the gate asked GetMicrovm");
    assert!(terminated(&api).is_empty());
    assert!(env.events("vm_egress_mismatch").is_empty());
    assert_eq!(env.row(&id).egress_connectors, [CONNECTOR]);
    // --no-wait returns the RunMicrovm answer, with the egress GetMicrovm echoed.
    let env = vpc_env();
    let api = new_api();
    api.set_run_echo_empty(true);
    let sel = run(&env, &api, &RunFlags { wait: false, ..vpc(&env) }).await.unwrap();
    assert_eq!(sel.vm().egress, [CONNECTOR]);
    // GetMicrovm echoes internet: a mismatch, judged on that answer.
    let env = vpc_env();
    let api = new_api();
    api.set_run_echo_empty(true);
    api.set_egress_echo(Some(vec![internet_egress_arn()]));
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    let m = mismatch(&f.error);
    assert_eq!((m.echoed.clone(), m.terminated), (vec![internet_egress_arn()], true));
    assert_eq!(after_run(&api), [Call::Get(m.id.clone()), Call::Terminate(m.id.clone())]);
    // A transient GetMicrovm failure (read-after-create, a timeout) is asked again.
    let env = vpc_env();
    let api = new_api();
    api.set_run_echo_empty(true);
    fail_gets(&api, get_timeout, 2);
    api.fail_on("get", BridgeError::VmNotFound("MicroVM not found".into()), false);
    let id = started_id(&run(&env, &api, &vpc(&env)).await.unwrap());
    assert_eq!(env.row(&id).egress_connectors, [CONNECTOR]);
    assert!(terminated(&api).is_empty());
    // A GetMicrovm that fails for good: nothing echoed, fail closed.
    let env = vpc_env();
    let api = new_api();
    api.set_run_echo_empty(true);
    api.fail_on("get", BridgeError::AccessDenied("get_microvm: not authorized".into()), false);
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    let m = mismatch(&f.error);
    assert_eq!((m.echoed.clone(), m.terminated), (vec![], true));
    assert!(f.error.to_string().contains("echoed egress nothing"), "{}", f.error);
    assert_eq!(mismatch_audit(&env).2, "");
    assert_eq!(exit(f.error), 9);
    // Transient failures past the budget: fail closed too.
    let env = vpc_env();
    let api = new_api();
    api.set_run_echo_empty(true);
    fail_gets(&api, get_timeout, 10_000);
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    api.state().failures.clear();
    let m = mismatch(&f.error);
    assert_eq!((m.echoed.clone(), m.terminated), (vec![], true));
    assert_eq!(terminated(&api), [m.id]);
}

#[tokio::test]
async fn a_pending_answer_without_egress_is_asked_again_a_running_one_is_a_mismatch() {
    // Still PENDING and echoing nothing: asked again until the budget, then fail closed.
    let env = vpc_env();
    let api = FakeMicrovmApi::new(); // never advances: PENDING
    api.set_run_echo_empty(true);
    api.set_get_egress_echo(Some(vec![]));
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    let m = mismatch(&f.error);
    assert_eq!((m.echoed.clone(), m.terminated), (vec![], true));
    let gets = after_run(&api).iter().filter(|c| matches!(c, Call::Get(_))).count();
    assert!(gets > 1, "a PENDING VM without egress is asked again: {gets} GetMicrovm");
    // RUNNING and echoing nothing: a mismatch on the first answer.
    let env = vpc_env();
    let api = new_api();
    api.set_run_echo_empty(true);
    api.set_get_egress_echo(Some(vec![]));
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    let m = mismatch(&f.error);
    assert_eq!(after_run(&api), [Call::Get(m.id.clone()), Call::Terminate(m.id.clone())]);
}

#[tokio::test]
async fn an_ended_vm_is_the_terminated_path_not_a_mismatch() {
    // GetMicrovm answers TERMINATED before any egress was echoed: exit 8, the row by `platform`.
    let env = vpc_env();
    let spy = Spy::new(&env.paths);
    spy.inner.set_run_echo_empty(true);
    *spy.kill_on_get.lock().unwrap() = Some("InsufficientCapacity: host reclaimed".into());
    let f = run(&env, &spy, &vpc(&env)).await.unwrap_err();
    assert!(matches!(f.error, BridgeError::Terminated(_)), "{}", f.error);
    assert!(f.error.to_string().contains("host reclaimed"), "{}", f.error);
    let id = spy.inner.state().vms.keys().next().unwrap().clone();
    let row = env.row(&id);
    assert_eq!((row.status, row.terminated_by.as_deref()), (RowStatus::Terminated, Some("platform")));
    assert!(env.events("vm_egress_mismatch").is_empty() && terminated(&spy.inner).is_empty());
    assert_eq!(exit(f.error), 8);
    // GetMicrovm never finds the VM within the budget: the same.
    let env = vpc_env();
    let api = new_api();
    api.set_run_echo_empty(true);
    fail_gets(&api, || BridgeError::VmNotFound("MicroVM not found".into()), 10_000);
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    api.state().failures.clear();
    assert!(matches!(f.error, BridgeError::Terminated(_)), "{}", f.error);
    let id = api.state().vms.keys().next().unwrap().clone();
    assert_eq!(env.row(&id).terminated_by.as_deref(), Some("platform"));
    assert!(env.events("vm_egress_mismatch").is_empty());
    assert_eq!(exit(f.error), 8);
}

#[tokio::test]
async fn a_failing_terminate_leaves_the_id_with_the_caller_and_the_row_to_gc() {
    let env = vpc_env();
    let api = new_api();
    api.set_egress_echo(Some(vec![internet_egress_arn()]));
    api.fail_on("terminate", throttled(), false);
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    let m = mismatch(&f.error);
    assert!(!m.terminated);
    assert_eq!(f.started.as_deref(), Some(m.id.as_str()), "the caller's terminate guard gets the id");
    assert!(!api.state().vms[&m.id].state.is_terminal(), "still alive");
    let row = env.row(&m.id);
    assert_ne!(row.status, RowStatus::Terminated, "the row says what is true");
    assert_eq!(row.egress_gate.as_deref(), Some(GATE_MISMATCH), "the verdict is written before the terminate is tried");
    assert_eq!(mismatch_audit(&env).5, "false");
    assert!(env.events("vm_terminate").is_empty());
    let text = f.error.to_string();
    assert!(text.contains("NOT confirmed terminated") && text.contains(&format!("ai-env vm terminate {}", m.id)), "{text}");
    assert_eq!(exit(f.error), 9);
    // A dry gc names it; `vm gc --yes` terminates it (policy), whatever it echoes now.
    let dry = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &DRY).await.unwrap();
    let item = dry.items.iter().find(|i| i.id.as_deref() == Some(m.id.as_str())).unwrap();
    assert!(item.detail.contains("egress gate mismatch"), "{}", item.detail);
    api.set_egress_echo(None);
    let report = gc_yes(&env, &api).await;
    assert_eq!((report.terminated, report.mismatches, report.errors.len()), (1, 0, 0), "{report:?}");
    assert_eq!(terminated(&api), [m.id.clone(), m.id.clone()]);
    let row = env.row(&m.id);
    assert_eq!((row.status, row.terminated_by.as_deref()), (RowStatus::Terminated, Some("policy")));
    assert_eq!(terminate_by(&env), ["policy"]);
}

#[tokio::test]
async fn a_terminate_whose_row_write_fails_still_counts_as_terminated() {
    let env = vpc_env();
    let mut api = Hooked::new();
    api.read_only_on_terminate = Some(env.paths.vms());
    api.inner.set_egress_echo(Some(vec![internet_egress_arn()]));
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    std::fs::set_permissions(env.paths.vms(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let m = mismatch(&f.error);
    assert!(m.terminated, "TerminateMicrovm was accepted; only the row write failed");
    assert_eq!(f.started, None, "nothing for the caller to terminate again");
    assert_eq!(terminated(&api.inner), [m.id.as_str()], "exactly one TerminateMicrovm");
    assert_eq!(mismatch_audit(&env).5, "true");
    assert_eq!(terminate_by(&env), ["policy"]);
    assert_eq!(env.row(&m.id).egress_gate.as_deref(), Some(GATE_MISMATCH), "the verdict was written first");
    assert_eq!(exit(f.error), 9);
}

#[tokio::test]
async fn a_vpc_plan_without_a_connector_is_refused_before_any_call() {
    let env = vpc_env();
    let api = new_api();
    for connectors in [vec![], s(&["  "])] {
        let mut plan = env.plan(&vpc(&env));
        plan.egress_connectors = connectors;
        let f = select_vm_detailed(&api, &env.paths, &plan, fast()).await.unwrap_err();
        assert!(matches!(f.error, BridgeError::EgressRequired), "{}", f.error);
        assert_eq!(exit(f.error), 9);
    }
    assert!(api.calls().is_empty(), "{:?}", api.calls());
    assert!(env.rows().is_empty());
}

#[tokio::test]
async fn an_internet_run_echoing_a_vpc_connector_is_a_mismatch() {
    let env = Env::new();
    let internet = RunFlags { workspace: None, ..env.flags() };
    for echo in [s(&[CONNECTOR]), vec![internet_egress_arn(), CONNECTOR.to_string()], vec![]] {
        let api = new_api();
        api.set_egress_echo(Some(echo.clone()));
        let f = run(&env, &api, &internet).await.unwrap_err();
        let m = mismatch(&f.error);
        assert_eq!((m.expected.clone(), m.echoed.clone(), m.terminated), (vec![internet_egress_arn()], echo.clone(), true), "{echo:?}");
        assert_eq!(env.row(&m.id).terminated_by.as_deref(), Some("policy"));
        assert_eq!(exit(f.error), 9);
    }
    let rows = env.events("vm_egress_mismatch");
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r["detail"]["via"] == "run" && r["detail"]["expected"] == internet_egress_arn().as_str()));
}

#[tokio::test]
async fn the_row_keeps_the_echo_and_the_verdict_after_a_pass() {
    // internet: nothing is sent (the pending row plans no connector); the row keeps INTERNET_EGRESS.
    let env = Env::new();
    let api = new_api();
    let plan = env.plan(&RunFlags { workspace: None, ..env.flags() });
    assert!(plan.egress_connectors.is_empty());
    let id = started_id(&select_vm(&api, &env.paths, &plan, fast()).await.unwrap());
    let row = env.row(&id);
    assert_eq!((row.egress_connectors.clone(), row.egress_gate.as_deref()), (vec![internet_egress_arn()], Some(GATE_PASSED)));
    // vpc: the echo as the gate compared it, without a version suffix.
    let env = vpc_env();
    let api = new_api();
    api.set_egress_echo(Some(vec![format!("{CONNECTOR}:3")]));
    let id = started_id(&run(&env, &api, &vpc(&env)).await.unwrap());
    let row = env.row(&id);
    assert_eq!((row.status, row.egress_connectors.clone(), row.egress_gate.as_deref()), (RowStatus::Running, s(&[CONNECTOR]), Some(GATE_PASSED)));
    assert!(env.events("vm_egress_mismatch").is_empty());
    // The pending row says `pending` until the gate ran.
    let env = vpc_env();
    let api = new_api();
    let pending = kept_pending(&env, &api, &vpc(&env)).await;
    assert_eq!((pending.egress_connectors.clone(), pending.egress_gate.as_deref()), (s(&[CONNECTOR]), Some(GATE_PENDING)));
}

#[tokio::test]
async fn the_version_suffix_and_the_name_form_pass() {
    for (configured, echo) in [(CONNECTOR.to_string(), CONNECTOR.to_string()), (CONNECTOR.to_string(), format!("{CONNECTOR}:1")), (format!("{CONNECTOR}:7"), CONNECTOR.to_string()), (format!("{CONNECTOR}:7"), format!("{CONNECTOR}:12"))] {
        let mut env = Env::new();
        env.cfg.aws.egress_connector_arn = Some(configured.clone());
        let api = new_api();
        api.set_egress_echo(Some(vec![echo.clone()]));
        let id = started_id(&run(&env, &api, &vpc(&env)).await.unwrap_or_else(|f| panic!("{configured} / {echo}: {f}")));
        assert_eq!(api.run_specs()[0].egress_connectors, [configured.as_str()], "the configured ARN is sent as is");
        assert_eq!(env.row(&id).egress_connectors, [CONNECTOR], "{configured} / {echo}");
        assert!(terminated(&api).is_empty());
    }
}

#[tokio::test]
async fn the_id_form_passes_only_with_a_matching_infra_state() {
    for echo in [id_arn(), format!("{}:2", id_arn()), ID.to_string()] {
        // No state/infra.toml: the Id is unknown, so the echo is another connector.
        let env = vpc_env();
        let api = new_api();
        api.set_egress_echo(Some(vec![echo.clone()]));
        let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
        assert!(mismatch(&f.error).terminated, "{echo}");
        if echo != ID {
            assert!(f.error.to_string().contains("make infra-status WRITE=1"), "the Id-form hint: {}", f.error);
        }
        // The state of another connector, or one without its ARN: not trusted.
        for (arn, id) in [(Some(OTHER), Some(ID)), (None, Some(ID)), (Some(CONNECTOR), None)] {
            let env = vpc_env();
            write_state(&env, arn, id);
            let api = new_api();
            api.set_egress_echo(Some(vec![echo.clone()]));
            let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
            assert!(mismatch(&f.error).terminated, "{echo} with state {arn:?} {id:?}");
        }
        // connector_id and connector_arn of exactly the configured connector: the Id form passes.
        let env = vpc_env();
        write_state(&env, Some(&format!("{CONNECTOR}:4")), Some(ID));
        let api = new_api();
        api.set_egress_echo(Some(vec![echo.clone()]));
        let id = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap_or_else(|f| panic!("{echo}: {f}")));
        assert_eq!(env.row(&id).egress_connectors, [CONNECTOR], "stored in its name form");
        // ... and the workspace VM is reused while it still echoes its Id.
        match run(&env, &api, &vpc_ws(&env)).await.unwrap() {
            Selected::Reused { row, .. } => assert_eq!(row.id, id),
            other => panic!("{echo}: expected reuse, got {other:?}"),
        }
        assert!(terminated(&api).is_empty() && env.events("vm_egress_mismatch").is_empty(), "{echo}");
    }
}

// ---- gc gates again ---------------------------------------------------------------------------

#[tokio::test]
async fn gc_gates_a_row_its_run_never_judged() {
    // `ai-env` died between RunMicrovm and the gate: the row is still `pending`. The VM passes.
    let env = vpc_env();
    let api = new_api();
    let id = started_id(&run(&env, &api, &vpc(&env)).await.unwrap());
    edit_row(&env, &id, |r| r.egress_gate = Some(GATE_PENDING.into()));
    let dry = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &DRY).await.unwrap();
    assert!(dry.items.iter().any(|i| i.id.as_deref() == Some(id.as_str()) && i.detail.contains("egress gate pending")), "{:#?}", dry.items);
    assert_eq!(env.row(&id).egress_gate.as_deref(), Some(GATE_PENDING), "a dry run writes nothing");
    let report = gc_yes(&env, &api).await;
    assert!(report.errors.is_empty() && report.terminated == 0, "{report:?}");
    assert_eq!(env.row(&id).egress_gate.as_deref(), Some(GATE_PASSED));
    assert!(terminated(&api).is_empty());
    // The same, but the VM echoes internet egress: terminated (policy), audited via gc, exit 9 material.
    let env = vpc_env();
    let api = new_api();
    let id = started_id(&run(&env, &api, &vpc(&env)).await.unwrap());
    edit_row(&env, &id, |r| r.egress_gate = Some(GATE_PENDING.into()));
    api.set_egress_echo(Some(vec![internet_egress_arn()]));
    let report = gc_yes(&env, &api).await;
    assert_eq!((report.terminated, report.mismatches, report.errors.len()), (1, 1, 1), "{report:?}");
    assert!(report.errors[0].contains(&id) && report.errors[0].contains("egress mismatch"), "{:?}", report.errors);
    assert_eq!(terminated(&api), [id.as_str()]);
    let row = env.row(&id);
    assert_eq!((row.status, row.terminated_by.as_deref(), row.egress_gate.as_deref()), (RowStatus::Terminated, Some("policy"), Some(GATE_MISMATCH)));
    assert_eq!(mismatch_audit(&env), (id.clone(), CONNECTOR.into(), internet_egress_arn(), "gc".into(), "gc".into(), "true".into()));
    // A VM still PENDING without an echo is left for the next gc.
    let env = vpc_env();
    let api = new_api();
    let id = started_id(&run(&env, &api, &vpc(&env)).await.unwrap());
    edit_row(&env, &id, |r| r.egress_gate = Some(GATE_PENDING.into()));
    api.set_state(&id, VmState::Pending);
    api.set_auto_advance(false);
    api.set_get_egress_echo(Some(vec![]));
    let report = gc_yes(&env, &api).await;
    assert!(report.errors.is_empty() && report.terminated == 0, "{report:?}");
    assert_eq!(env.row(&id).egress_gate.as_deref(), Some(GATE_PENDING));
}

#[tokio::test]
async fn gc_gates_rows_from_before_s5() {
    // An internet row of an S4 build (no verdict, no connectors): passes and gets INTERNET_EGRESS.
    let env = Env::new();
    let api = new_api();
    let id = started_id(&select_vm(&api, &env.paths, &env.plan(&RunFlags { workspace: None, ..env.flags() }), fast()).await.unwrap());
    edit_row(&env, &id, |r| {
        r.egress_gate = None;
        r.egress_connectors.clear();
    });
    let report = gc_yes(&env, &api).await;
    assert!(report.errors.is_empty(), "{report:?}");
    let row = env.row(&id);
    assert_eq!((row.egress_gate.as_deref(), row.egress_connectors.clone()), (Some(GATE_PASSED), vec![internet_egress_arn()]));
    // A vpc row of an S4 build: no connector to hold it to, so it fails closed.
    let env = vpc_env();
    let api = new_api();
    let id = started_id(&run(&env, &api, &vpc(&env)).await.unwrap());
    edit_row(&env, &id, |r| {
        r.egress_gate = None;
        r.egress_connectors.clear();
    });
    let report = gc_yes(&env, &api).await;
    assert_eq!((report.terminated, report.mismatches), (1, 1), "{report:?}");
    assert_eq!(mismatch_audit(&env).1, "(none planned)");
    assert!(report.errors[0].contains("records no egress connector"), "{:?}", report.errors);
}

#[tokio::test]
async fn gc_terminates_again_a_policy_row_whose_vm_still_runs() {
    // TerminateMicrovm answered NotFound before the VM was visible: the row says terminated (policy), the VM runs.
    let env = vpc_env();
    let api = new_api();
    api.set_egress_echo(Some(vec![internet_egress_arn()]));
    let f = run(&env, &api, &vpc(&env)).await.unwrap_err();
    let id = mismatch(&f.error).id;
    api.set_state(&id, VmState::Running);
    let dry = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &DRY).await.unwrap();
    let item = dry.items.iter().find(|i| i.id.as_deref() == Some(id.as_str())).unwrap();
    assert!(item.detail.contains("the row says terminated") && item.detail.contains("terminates it again"), "{}", item.detail);
    let report = gc_yes(&env, &api).await;
    assert_eq!((report.terminated, report.errors.len()), (1, 0), "{report:?}");
    assert_eq!(terminated(&api), [id.clone(), id.clone()]);
    assert!(api.state().vms[&id].state.is_terminal());
    assert_eq!(terminate_by(&env), ["policy", "policy"]);
    // Nothing left to do.
    let again = gc_yes(&env, &api).await;
    assert_eq!(again.terminated, 0, "{again:?}");
}

// ---- reuse ------------------------------------------------------------------------------------

#[tokio::test]
async fn reuse_terminates_a_mismatched_candidate_and_starts_a_new_vm() {
    let env = vpc_env();
    let api = new_api();
    let a = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    // The workspace VM now echoes internet egress, and it is SUSPENDED: never resumed.
    {
        let mut st = api.state();
        let vm = st.vms.get_mut(&a).unwrap();
        vm.egress = vec![internet_egress_arn()];
        vm.state = VmState::Suspended;
    }
    let b = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    assert_ne!(a, b);
    assert!(!api.calls().contains(&Call::Resume(a.clone())), "a mismatched VM is never resumed");
    assert_eq!(terminated(&api), [a.as_str()]);
    let row = env.row(&a);
    assert_eq!((row.terminated_by.as_deref(), row.egress_gate.as_deref()), (Some("policy"), Some(GATE_MISMATCH)));
    assert_eq!(mismatch_audit(&env), (a.clone(), CONNECTOR.into(), internet_egress_arn(), "reuse".into(), "test".into(), "true".into()));
    assert!(env.events("vm_reuse").is_empty());
    assert_eq!(api.run_specs().len(), 2);
    // The new VM serves the workspace from now on.
    match run(&env, &api, &vpc_ws(&env)).await.unwrap() {
        Selected::Reused { row, .. } => assert_eq!(row.id, b),
        other => panic!("expected reuse of {b}, got {other:?}"),
    }
}

#[tokio::test]
async fn the_settled_answer_after_a_resume_is_gated_too() {
    let env = vpc_env();
    // The first GetMicrovm echoes the connector; once resumed, it says INTERNET_EGRESS.
    let mut api = Hooked::new();
    api.echo_after_resume = Some(vec![internet_egress_arn()]);
    let a = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    api.inner.set_state(&a, VmState::Suspended);
    edit_row(&env, &a, |r| r.status = RowStatus::Suspended);
    let b = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    assert_ne!(a, b);
    assert!(api.inner.calls().contains(&Call::Resume(a.clone())));
    assert_eq!(terminated(&api.inner), [a.as_str()]);
    assert!(env.events("vm_reuse").is_empty());
    let (id, _, echoed, via, _, done) = mismatch_audit(&env);
    assert_eq!((id, echoed, via, done), (a.clone(), internet_egress_arn(), "reuse".into(), "true".into()));
}

#[tokio::test]
async fn a_legacy_vpc_row_is_never_reused() {
    let env = vpc_env();
    let api = new_api();
    let a = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    // As an S4 build wrote it: vpc, no connectors, no verdict. Its VM echoes the right connector all the same.
    edit_row(&env, &a, |r| {
        r.egress_connectors.clear();
        r.egress_gate = None;
    });
    let b = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    assert_ne!(a, b);
    assert_eq!(terminated(&api), [a.as_str()]);
    assert_eq!(env.row(&a).terminated_by.as_deref(), Some("policy"));
    assert_eq!(mismatch_audit(&env), (a.clone(), "(none planned)".into(), CONNECTOR.into(), "reuse".into(), "test".into(), "true".into()));
}

#[tokio::test]
async fn a_legacy_internet_row_is_reused_and_gets_its_echo() {
    let env = Env::new();
    let api = new_api();
    let a = started_id(&select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap());
    edit_row(&env, &a, |r| {
        r.egress_connectors.clear();
        r.egress_gate = None;
    });
    match select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap() {
        Selected::Reused { row, .. } => assert_eq!(row.id, a),
        other => panic!("expected reuse of {a}, got {other:?}"),
    }
    let row = env.row(&a);
    assert_eq!((row.egress_gate.as_deref(), row.egress_connectors.clone()), (Some(GATE_PASSED), vec![internet_egress_arn()]));
    assert!(terminated(&api).is_empty());
}

#[tokio::test]
async fn a_mismatch_row_is_never_reused_even_when_it_echoes_right_now() {
    let env = vpc_env();
    let api = new_api();
    let a = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    // Its gate said mismatch and the terminate did not go through; now it echoes the connector.
    edit_row(&env, &a, |r| r.egress_gate = Some(GATE_MISMATCH.into()));
    let b = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    assert_ne!(a, b);
    assert_eq!(terminated(&api), [a.as_str()]);
    assert_eq!(env.row(&a).terminated_by.as_deref(), Some("policy"));
}

#[tokio::test]
async fn a_reuse_candidate_the_gate_cannot_terminate_fails_the_run() {
    let env = vpc_env();
    let api = new_api();
    let a = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    api.state().vms.get_mut(&a).unwrap().egress = vec![internet_egress_arn()];
    api.fail_on("terminate", throttled(), false);
    let f = run(&env, &api, &vpc_ws(&env)).await.unwrap_err();
    let m = mismatch(&f.error);
    assert_eq!((m.id.as_str(), m.terminated), (a.as_str(), false));
    assert_eq!(f.started.as_deref(), Some(a.as_str()), "the id goes back to the caller");
    assert_eq!(f.client_token, None, "no pending row was written");
    assert_eq!(api.run_specs().len(), 1, "no new VM is placed beside a live mismatched one");
    assert_eq!(mismatch_audit(&env).5, "false");
    assert_eq!(env.row(&a).egress_gate.as_deref(), Some(GATE_MISMATCH));
    assert_eq!(exit(f.error), 9);
}

#[tokio::test]
async fn a_row_of_another_connector_is_neither_reused_nor_terminated() {
    let env = vpc_env();
    let api = new_api();
    let a = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    // [aws].egress_connector_arn changed since this VM started.
    edit_row(&env, &a, |r| r.egress_connectors = s(&[OTHER]));
    let b = started_id(&run(&env, &api, &vpc_ws(&env)).await.unwrap());
    assert_ne!(a, b);
    assert!(terminated(&api).is_empty());
    assert!(env.events("vm_egress_mismatch").is_empty());
    assert_eq!(env.row(&a).status, RowStatus::Running);
}

// ---- adoption ---------------------------------------------------------------------------------

#[tokio::test]
async fn the_sweep_never_adopts_a_vm_that_fails_the_gate() {
    let env = vpc_env();
    let api = new_api();
    let t0 = unix_now();
    let pending = kept_pending(&env, &api, &vpc(&env)).await;
    assert_eq!(pending.egress_connectors, [CONNECTOR], "place() writes the planned list");
    assert_eq!(pending_on_disk(&env).unwrap().egress_connectors, [CONNECTOR]);
    let ours = api.state().tokens[&pending.client_token].clone();
    api.set_egress_echo(Some(vec![internet_egress_arn()]));
    let e = adopt_after_ambiguous_for(&api, &api, &env.paths, &pending, t0, fast(), "smoke").await.unwrap_err();
    let m = mismatch(&e);
    assert_eq!((m.id.as_str(), m.expected.clone(), m.terminated), (ours.as_str(), s(&[CONNECTOR]), true));
    assert_eq!(exit(e), 9);
    assert_eq!(terminated(&api), [ours.as_str()]);
    assert_eq!(mismatch_audit(&env), (ours.clone(), CONNECTOR.into(), internet_egress_arn(), "sweep".into(), "smoke".into(), "true".into()));
    assert!(env.events("vm_adopt").is_empty(), "never adopted");
    // The record: the pending row became the VM's row, terminated by policy.
    let row = env.row(&ours);
    assert_eq!((row.status, row.terminated_by.as_deref(), row.egress_gate.as_deref()), (RowStatus::Terminated, Some("policy"), Some(GATE_MISMATCH)));
    assert_eq!(row.client_token, pending.client_token);
    assert!(pending_on_disk(&env).is_none());
    // Nothing is left to adopt.
    assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), Adoption::NoMatch);
}

#[tokio::test]
async fn a_swept_vm_the_gate_cannot_terminate_is_left_to_gc() {
    let env = vpc_env();
    let api = new_api();
    let t0 = unix_now();
    let pending = kept_pending(&env, &api, &vpc(&env)).await;
    let ours = api.state().tokens[&pending.client_token].clone();
    api.set_egress_echo(Some(vec![internet_egress_arn()]));
    api.fail_on("terminate", throttled(), false);
    let e = adopt_after_ambiguous_for(&api, &api, &env.paths, &pending, t0, fast(), "probe").await.unwrap_err();
    let m = mismatch(&e);
    assert_eq!((m.id.as_str(), m.terminated), (ours.as_str(), false));
    assert!(!api.state().vms[&ours].state.is_terminal());
    // Its row records the verdict: never adopted, never reused, and gc finishes it.
    let row = env.row(&ours);
    assert_eq!((row.status, row.egress_gate.as_deref()), (RowStatus::Running, Some(GATE_MISMATCH)));
    assert!(pending_on_disk(&env).is_none());
    assert!(env.events("vm_adopt").is_empty());
    assert_eq!(mismatch_audit(&env).4, "probe");
    let report = gc_yes(&env, &api).await;
    assert_eq!((report.adopted, report.terminated, report.errors.len()), (0, 1, 0), "{report:?}");
    assert_eq!(terminated(&api), [ours.clone(), ours.clone()]);
    assert_eq!(env.row(&ours).terminated_by.as_deref(), Some("policy"));
}

#[tokio::test]
async fn gc_never_adopts_a_vm_that_fails_the_gate() {
    let env = vpc_env();
    let api = new_api();
    let pending = kept_pending(&env, &api, &vpc(&env)).await;
    let ours = api.state().tokens[&pending.client_token].clone();
    api.advance_all();
    api.set_egress_echo(Some(s(&[CONNECTOR, OTHER])));
    let report = gc_yes(&env, &api).await;
    assert_eq!((report.adopted, report.terminated, report.mismatches), (0, 1, 1), "{report:?}");
    assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
    assert!(report.errors[0].contains("egress mismatch") && report.errors[0].contains(&ours), "{:?}", report.errors);
    assert_eq!(terminated(&api), [ours.as_str()]);
    assert_eq!(mismatch_audit(&env), (ours.clone(), CONNECTOR.into(), format!("{CONNECTOR},{OTHER}"), "gc".into(), "gc".into(), "true".into()));
    assert!(env.events("vm_adopt").is_empty());
    let row = env.row(&ours);
    assert_eq!((row.status, row.terminated_by.as_deref()), (RowStatus::Terminated, Some("policy")));
    assert!(pending_on_disk(&env).is_none());
    let g = env.events("vm_gc");
    assert_eq!((g[0]["detail"]["adopted"].as_str(), g[0]["detail"]["terminated"].as_str(), g[0]["detail"]["errors"].as_str()), (Some("0"), Some("1"), Some("1")));
}

#[tokio::test]
async fn gc_never_adopts_the_vm_of_a_legacy_vpc_pending_row() {
    let env = vpc_env();
    let api = new_api();
    // As an S4 build wrote it: vpc egress, no planned connectors.
    let token = new_session_token().expose().clone();
    let created = created_at(-10);
    let pending = VmRow {
        status: RowStatus::Pending,
        client_token: uuid::Uuid::now_v7().to_string(),
        image_arn: FAKE_IMAGE_ARN.to_string(),
        image_version: "1.0".to_string(),
        owner: owner(),
        created: created.clone(),
        commit: commitment_hex(token.as_bytes()),
        session_token: Some(token),
        max_duration_s: 3600,
        egress: "vpc".to_string(),
        ..VmRow::default()
    };
    registry::write_pending(&env.paths, &pending).unwrap();
    let vm = run_direct(&api, &owner(), &created).await.id;
    api.advance_all();
    // Its VM even echoes the configured connector: a row that plans none fails closed.
    api.set_egress_echo(Some(s(&[CONNECTOR])));
    let report = gc_yes(&env, &api).await;
    assert_eq!((report.adopted, report.terminated, report.mismatches, report.errors.len()), (0, 1, 1, 1), "{report:?}");
    assert_eq!(terminated(&api), [vm.as_str()]);
    assert_eq!(mismatch_audit(&env), (vm.clone(), "(none planned)".into(), CONNECTOR.into(), "gc".into(), "gc".into(), "true".into()));
}

#[tokio::test]
async fn adoption_that_passes_the_gate_stores_the_echo() {
    // The configured connector carries a version: the pending row plans it as configured, the row keeps it normalised.
    let mut env = Env::new();
    env.cfg.aws.egress_connector_arn = Some(format!("{CONNECTOR}:7"));
    let api = new_api();
    let t0 = unix_now();
    let pending = kept_pending(&env, &api, &vpc(&env)).await;
    assert_eq!(pending.egress_connectors, [format!("{CONNECTOR}:7")]);
    let ours = api.state().tokens[&pending.client_token].clone();
    api.set_egress_echo(Some(vec![format!("{CONNECTOR}:2")]));
    assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), Adoption::Adopted(ours.clone()));
    let row = env.row(&ours);
    assert_eq!((row.status, row.egress_connectors.clone(), row.egress_gate.as_deref()), (RowStatus::Running, s(&[CONNECTOR]), Some(GATE_PASSED)));
    assert!(terminated(&api).is_empty() && env.events("vm_egress_mismatch").is_empty());
    // An internet pending row plans nothing; the adopted row holds INTERNET_EGRESS.
    let env = Env::new();
    let api = new_api();
    let pending = kept_pending(&env, &api, &RunFlags { workspace: None, ..env.flags() }).await;
    assert!(pending.egress_connectors.is_empty());
    let ours = api.state().tokens[&pending.client_token].clone();
    api.advance_all();
    let report = gc_yes(&env, &api).await;
    assert_eq!(report.adopted, 1, "{report:?}");
    assert_eq!(env.row(&ours).egress_connectors, [internet_egress_arn()]);
}

#[tokio::test]
async fn the_id_form_during_the_sweep_and_gc_adoption() {
    for via_gc in [false, true] {
        // With the alias: adopted, stored in its name form.
        let env = vpc_env();
        write_state(&env, Some(CONNECTOR), Some(ID));
        let api = new_api();
        let t0 = unix_now();
        let pending = kept_pending(&env, &api, &vpc(&env)).await;
        let ours = api.state().tokens[&pending.client_token].clone();
        api.set_egress_echo(Some(vec![id_arn()]));
        if via_gc {
            api.advance_all();
            assert_eq!(gc_yes(&env, &api).await.adopted, 1);
        } else {
            assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), Adoption::Adopted(ours.clone()));
        }
        assert_eq!(env.row(&ours).egress_connectors, [CONNECTOR], "via_gc={via_gc}");
        assert!(terminated(&api).is_empty(), "via_gc={via_gc}");
        // Without it: the Id is another connector, a mismatch.
        let env = vpc_env();
        let api = new_api();
        let pending = kept_pending(&env, &api, &vpc(&env)).await;
        let ours = api.state().tokens[&pending.client_token].clone();
        api.set_egress_echo(Some(vec![id_arn()]));
        if via_gc {
            api.advance_all();
            let report = gc_yes(&env, &api).await;
            assert_eq!((report.adopted, report.mismatches), (0, 1), "{report:?}");
        } else {
            let e = adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap_err();
            assert!(mismatch(&e).terminated);
        }
        assert_eq!(terminated(&api), [ours.as_str()], "via_gc={via_gc}");
        assert_eq!(mismatch_audit(&env).3, if via_gc { "gc" } else { "sweep" });
    }
}
