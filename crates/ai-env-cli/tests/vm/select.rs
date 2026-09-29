//! `vm::run`: the run plan (idle, egress, roots), the payload, image-version
//! resolution, SELECT_VM (locks, reuse, count, pending rows, RunMicrovm
//! failures, the RUNNING poll), rows and audit, termination and the
//! adoption sweep.
use crate::common::{api, created_at, exit, fail_gets, fast, get_timeout, health_claiming, run_direct, Env, Spy, CONNECTOR, FOREIGN};
use ai_env_cli::bridge::api::{managed_connector_arn, Call, FakeMicrovmApi, ImageVersion, VmState, ENDPOINT_SUFFIX, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::vm::gc::{gc, GcOpts};
use ai_env_cli::bridge::vm::owner;
use ai_env_cli::bridge::vm::registry::{self, RowStatus, VmRow};
use ai_env_cli::bridge::vm::run::{
    adopt_after_ambiguous, build_payload, effective_egress, memory_warning, new_session_token, padded_payload, resolve_image_version, select_vm, select_vm_detailed, terminate_and_record, Adoption, Egress,
    Poll, RunFlags, RunPlan, SelectFailure, Selected,
};
use ai_env_cli::wire::frame::{commitment_hex, RunHookPayload};
use ai_env_cli::wire::redact::scrub;
use ai_env_cli::wire::time::{parse_rfc3339_utc, unix_now};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

fn runs(calls: &[Call]) -> Vec<String> {
    calls.iter().filter_map(|c| if let Call::Run { client_token } = c { Some(client_token.clone()) } else { None }).collect()
}

fn started_id(s: &Selected) -> String {
    match s {
        Selected::Started { row, .. } => row.id.clone(),
        Selected::Reused { row, .. } => panic!("expected a new VM, reused {}", row.id),
    }
}

fn reused_id(s: &Selected) -> String {
    match s {
        Selected::Reused { row, .. } => row.id.clone(),
        Selected::Started { row, .. } => panic!("expected reuse, started {}", row.id),
    }
}

fn ambiguous() -> BridgeError {
    BridgeError::Ambiguous { op: "run_microvm", message: "dispatch failure: connection reset".into() }
}

/// A 64-hex session token this process never registered with the scrubber,
/// as a row read back from disk by a fresh `ai-env` process holds it.
fn unregistered_token() -> String {
    let t = format!("{}{}", uuid::Uuid::now_v7().simple(), uuid::Uuid::now_v7().simple());
    assert_eq!(scrub(&t), t, "not registered, so only the code keeps it out of audit");
    t
}

/// The id of the VM RunMicrovm created for `client_token`.
fn vm_of(api: &FakeMicrovmApi, client_token: &str) -> String {
    api.state().tokens[client_token].clone()
}

/// A select_vm whose RunMicrovm fails ambiguously twice (the VM is created): the failure it returns.
async fn double_ambiguous(env: &Env, api: &FakeMicrovmApi) -> SelectFailure {
    api.fail_on("run", ambiguous(), true);
    api.fail_on("run", ambiguous(), true);
    select_vm_detailed(api, &env.paths, &env.plan(&RunFlags { workspace: None, ..env.flags() }), fast()).await.unwrap_err()
}

// ---- SELECT_VM ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn select_three_threads_same_workspace_one_run() {
    let env = Env::new();
    let api = Arc::new(api());
    let paths = Arc::new(env.paths.clone());
    let plan = Arc::new(env.plan(&env.flags()));
    let handles: Vec<_> = (0..3)
        .map(|_| {
            let (api, paths, plan) = (api.clone(), paths.clone(), plan.clone());
            tokio::spawn(async move { select_vm(&*api, &paths, &plan, fast()).await })
        })
        .collect();
    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap().unwrap());
    }
    assert_eq!(runs(&api.calls()).len(), 1, "exactly one RunMicrovm: {:?}", api.calls());
    let ids: BTreeSet<String> = results.iter().map(|s| s.row().id.clone()).collect();
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(results.iter().filter(|s| matches!(s, Selected::Reused { resumed: false, .. })).count(), 2);
    assert_eq!(results.iter().filter(|s| matches!(s, Selected::Started { .. })).count(), 1);
    let rows = env.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, RowStatus::Running);
    assert_eq!(env.events("vm_reuse").len(), 2);
    assert_eq!(env.events("vm_run").len(), 1);
}

#[tokio::test]
async fn select_resumes_a_suspended_workspace_vm() {
    let env = Env::new();
    let api = api();
    let plan = env.plan(&env.flags());
    let id = started_id(&select_vm(&api, &env.paths, &plan, fast()).await.unwrap());
    api.set_state(&id, VmState::Suspended);
    let mut row = env.row(&id);
    row.status = RowStatus::Suspended;
    registry::write_row(&env.paths, &row).unwrap();
    match select_vm(&api, &env.paths, &plan, fast()).await.unwrap() {
        Selected::Reused { row, vm, resumed } => {
            assert!(resumed);
            assert_eq!(row.id, id);
            assert_eq!(vm.state, VmState::Running);
            assert_eq!(row.status, RowStatus::Running);
            assert_eq!(row.state_seen.as_deref(), Some("RUNNING"));
        }
        other => panic!("expected reuse, started {}", other.row().id),
    }
    assert!(api.calls().contains(&Call::Resume(id.clone())));
    assert_eq!(api.run_specs().len(), 1);
    let reuse = env.events("vm_reuse");
    assert_eq!(reuse.len(), 1);
    assert_eq!(reuse[0]["detail"]["id"], id.as_str());
    assert_eq!(reuse[0]["detail"]["resumed"], "true");
    assert_eq!(reuse[0]["detail"]["actor"], "cli");
}

#[tokio::test]
async fn select_skips_a_vm_near_its_wall() {
    let env = Env::new();
    let api = api();
    let plan = env.plan(&env.flags());
    let first = started_id(&select_vm(&api, &env.paths, &plan, fast()).await.unwrap());
    let mut row = env.row(&first);
    assert_eq!(row.wall_left(unix_now()).map(|l| l > 1200), Some(true), "3600 s wall: reusable at first");
    row.wall_deadline = Some(unix_now() + 600);
    registry::write_row(&env.paths, &row).unwrap();
    let second = started_id(&select_vm(&api, &env.paths, &plan, fast()).await.unwrap());
    assert_ne!(first, second, "600 s left ≤ migrate_before_wall_s 1200: never reused");
    assert_eq!(api.run_specs().len(), 2);
    let short = env.plan(&RunFlags { max_duration_s: Some(900), ..env.flags() });
    assert!(short.warnings.iter().any(|w| w.contains("never be reused")), "{:?}", short.warnings);
}

#[tokio::test]
async fn select_never_reuses_across_egress_ingress_or_version() {
    let mut env = Env::new();
    env.cfg.aws.egress_connector_arn = Some(CONNECTOR.to_string());
    let api = api();
    api.state().versions.push(ImageVersion { version: "2.0".into(), state: "SUCCESSFUL".into(), status: "ACTIVE".into(), memory_mib: Some(2048), created_at_unix: None });
    let base = env.flags();
    let a = started_id(&select_vm(&api, &env.paths, &env.plan(&base), fast()).await.unwrap());
    let b = started_id(&select_vm(&api, &env.paths, &env.plan(&RunFlags { shell: true, ..base.clone() }), fast()).await.unwrap());
    let c = started_id(&select_vm(&api, &env.paths, &env.plan(&RunFlags { egress: Some(Egress::Vpc), ..base.clone() }), fast()).await.unwrap());
    let d = started_id(&select_vm(&api, &env.paths, &env.plan(&RunFlags { version: Some("2.0".into()), ..base.clone() }), fast()).await.unwrap());
    assert_eq!([&a, &b, &c, &d].into_iter().collect::<BTreeSet<_>>().len(), 4, "four distinct VMs");
    let specs = api.run_specs();
    assert_eq!(specs[1].ingress_connectors, [managed_connector_arn("HTTP_INGRESS"), managed_connector_arn("SHELL_INGRESS")]);
    assert_eq!(specs[2].egress_connectors, [CONNECTOR]);
    assert_eq!(specs[3].image_version, "2.0");
    assert!(specs[0].ingress_connectors.is_empty() && specs[0].egress_connectors.is_empty());
    assert_eq!(reused_id(&select_vm(&api, &env.paths, &env.plan(&base), fast()).await.unwrap()), a, "the newest row that matches everything");
    assert_eq!(api.run_specs().len(), 4);
}

#[tokio::test]
async fn select_reuse_matches_the_workspace_not_its_slug() {
    let env = Env::new();
    let api = api();
    let (dotted, underscored) = (env.workspace("a.b"), env.workspace("a_b"));
    let slug = |p: &std::path::Path| ai_env_cli::wire::slug::project_dir_name(p).unwrap();
    assert_eq!(slug(&dotted), slug(&underscored), "the project dir name is lossy: both are …-work-a-b");
    let flags = |ws: &std::path::Path| RunFlags { workspace: Some(ws.to_path_buf()), ..env.flags() };
    let first = started_id(&select_vm(&api, &env.paths, &env.plan(&flags(&dotted)), fast()).await.unwrap());
    let second = started_id(&select_vm(&api, &env.paths, &env.plan(&flags(&underscored)), fast()).await.unwrap());
    assert_ne!(first, second, "another workspace never gets this workspace's VM");
    assert_eq!(runs(&api.calls()).len(), 2, "two RunMicrovm calls");
    for (ws, id) in [(&dotted, &first), (&underscored, &second)] {
        let canonical = std::fs::canonicalize(ws).unwrap();
        assert_eq!(env.row(id).workspace.as_deref(), canonical.to_str());
        assert_eq!(&reused_id(&select_vm(&api, &env.paths, &env.plan(&flags(ws)), fast()).await.unwrap()), id, "{} reuses its own VM", ws.display());
    }
    assert_eq!(runs(&api.calls()).len(), 2);
}

#[tokio::test]
async fn max_concurrent_counts_listed_rows_and_pending_across_workspaces() {
    let mut env = Env::new();
    env.cfg.vm.max_concurrent = 4;
    let api = api();
    // 1: a foreign VM of the image (listed, RUNNING).
    run_direct(&api, FOREIGN, &created_at(0)).await;
    api.advance_all();
    // 2: a fresh pending row of another workspace.
    env.pending_row(&owner(), &created_at(0), 3600);
    // 3: a running row of a VM the image listing does not show (another image).
    let unlisted = VmRow { id: "microvm-00000000-0000-4000-8000-0000000000aa".into(), status: RowStatus::Running, client_token: uuid::Uuid::now_v7().to_string(), created: created_at(0), ..VmRow::default() };
    registry::write_row(&env.paths, &unlisted).unwrap();
    // Not counted: a stale pending row, a terminated row, a row whose VM the listing shows TERMINATED.
    env.pending_row(&owner(), &created_at(-600_000), 3600);
    let done = VmRow { id: "microvm-00000000-0000-4000-8000-0000000000bb".into(), status: RowStatus::Terminated, client_token: uuid::Uuid::now_v7().to_string(), created: created_at(0), ..VmRow::default() };
    registry::write_row(&env.paths, &done).unwrap();
    let dead = run_direct(&api, &owner(), &created_at(1)).await;
    api.state().vms.get_mut(&dead.id).unwrap().state = VmState::Terminated;
    let stale_status = VmRow { id: dead.id.clone(), status: RowStatus::Running, client_token: uuid::Uuid::now_v7().to_string(), created: created_at(1), ..VmRow::default() };
    registry::write_row(&env.paths, &stale_status).unwrap();
    // Nor an unlisted "running" row whose wall passed long ago (a VM cannot outlive its wall; ListMicrovms may drop TERMINATED VMs).
    let past_wall = VmRow {
        id: "microvm-00000000-0000-4000-8000-0000000000dd".into(),
        status: RowStatus::Running,
        client_token: uuid::Uuid::now_v7().to_string(),
        created: created_at(-60_000_000),
        wall_deadline: Some(unix_now() - 50_000),
        ..VmRow::default()
    };
    registry::write_row(&env.paths, &past_wall).unwrap();

    let a = env.plan(&RunFlags { workspace: Some(env.workspace("a")), ..env.flags() });
    started_id(&select_vm(&api, &env.paths, &a, fast()).await.unwrap());
    let before = runs(&api.calls()).len();
    let b = env.plan(&RunFlags { workspace: Some(env.workspace("b")), ..env.flags() });
    let e = select_vm(&api, &env.paths, &b, fast()).await.unwrap_err();
    assert!(matches!(e, BridgeError::MaxConcurrent(4)), "{e}");
    assert!(e.to_string().contains("max_concurrent=4"), "{e}");
    assert_eq!(exit(e), 9);
    assert_eq!(runs(&api.calls()).len(), before, "refused before any RunMicrovm");
    assert_eq!(env.rows().iter().filter(|r| r.slug.as_deref().is_some_and(|s| s.ends_with("-b"))).count(), 0, "no row for the refused run");
}

#[tokio::test]
async fn pending_row_exists_when_run_is_called() {
    let env = Env::new();
    let spy = Spy::new(&env.paths);
    let sel = select_vm(&spy, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap();
    assert_eq!(*spy.pending_at_run.lock().unwrap(), [true], "the pending row of that client token was on disk when RunMicrovm ran");
    let rows = env.rows();
    assert_eq!(rows.len(), 1, "promoted: the id row replaced the pending row");
    assert_eq!(rows[0].id, sel.row().id);
    assert!(!env.paths.vms().join(format!("pending-{}.toml", rows[0].client_token)).exists());
}

#[tokio::test]
async fn definite_run_failure_removes_pending_row_exit_7() {
    let env = Env::new();
    let api = api();
    let quota = "You have exceeded the Max allocated ARM_64 MicroVM memory quota";
    api.fail_on("run", BridgeError::Quota(quota.into()), false);
    let e = select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap_err();
    assert!(e.to_string().contains(quota), "quota text verbatim: {e}");
    assert_eq!(exit(e), 7);
    assert_eq!(runs(&api.calls()).len(), 1, "a definite failure is not retried");
    assert!(env.rows().is_empty(), "{:?}", env.rows().iter().map(VmRow::stem).collect::<Vec<_>>());
    assert!(env.events("vm_run").is_empty());
}

#[tokio::test]
async fn ambiguous_run_failure_retries_same_client_token_then_keeps_row() {
    // Twice ambiguous: the row stays for gc, and select_vm_detailed hands it back.
    let env = Env::new();
    let api = api();
    api.fail_on("run", ambiguous(), false);
    api.fail_on("run", ambiguous(), false);
    let SelectFailure { error: e, kept_pending, started, .. } = select_vm_detailed(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap_err();
    let text = e.to_string();
    assert!(text.contains("ai-env vm gc"), "{text}");
    assert_eq!(exit(e), 7);
    assert_eq!(started, None);
    let tokens = runs(&api.calls());
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0], tokens[1], "the retry reuses the client token");
    let rows = env.rows();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].is_pending_row());
    assert_eq!(rows[0].client_token, tokens[0]);
    assert_eq!(kept_pending.as_deref(), Some(&rows[0]), "exactly the row on disk");
    assert!(api.run_specs().is_empty());
    // A definite failure keeps nothing.
    api.fail_on("run", BridgeError::Validation("imageVersion 9.0 not found".into()), false);
    let failure = select_vm_detailed(&api, &env.paths, &env.plan(&RunFlags { workspace: None, ..env.flags() }), fast()).await.unwrap_err();
    assert_eq!((failure.kept_pending.is_none(), failure.started.is_none()), (true, true));
    assert_eq!(env.rows().len(), 1);
    // Once ambiguous after the VM was created: the idempotent retry returns it.
    let env = Env::new();
    let api = crate::common::api();
    api.fail_on("run", ambiguous(), true);
    let sel = select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap();
    let tokens = runs(&api.calls());
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0], tokens[1]);
    assert_eq!(api.run_specs().len(), 1, "one VM");
    assert_eq!(api.run_specs()[0].client_token, tokens[0]);
    let rows = env.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, sel.row().id);
    assert_eq!(rows[0].status, RowStatus::Running);
}

#[tokio::test]
async fn not_running_in_budget_terminates_exit_7() {
    let env = Env::new();
    let api = ai_env_cli::bridge::api::FakeMicrovmApi::new(); // never advances: stays PENDING
    let e = select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap_err();
    let text = e.to_string();
    assert!(text.contains("not RUNNING") && text.contains("PENDING") && text.contains("terminated it"), "{text}");
    assert_eq!(exit(e), 7);
    let id = api.state().vms.keys().next().expect("RunMicrovm created the VM").clone();
    assert!(api.calls().contains(&Call::Terminate(id.clone())));
    let row = env.row(&id);
    assert_eq!(row.status, RowStatus::Terminated);
    assert_eq!(row.terminated_by.as_deref(), Some("timeout"));
    assert!(row.terminated_at.is_some());
    let t = env.events("vm_terminate");
    assert_eq!(t.len(), 1);
    assert_eq!(t[0]["detail"]["by"], "timeout");
}

#[tokio::test]
async fn terminated_while_starting_exit_8() {
    let env = Env::new();
    let spy = Spy::new(&env.paths);
    *spy.kill_on_get.lock().unwrap() = Some("InsufficientCapacity: host reclaimed".into());
    let e = select_vm(&spy, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap_err();
    let text = e.to_string();
    assert!(matches!(e, BridgeError::Terminated(_)), "{text}");
    assert!(text.contains("host reclaimed"), "the stateReason is named: {text}");
    assert_eq!(exit(e), 8);
    let rows = env.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, RowStatus::Terminated);
    assert_eq!(rows[0].terminated_by.as_deref(), Some("platform"));
}

// ---- policy ------------------------------------------------------------------------------

#[test]
fn outside_roots_exit_9() {
    let env = Env::new();
    let elsewhere = tempfile::tempdir().unwrap();
    let sibling = env.dir.path().join("work2");
    std::fs::create_dir_all(&sibling).unwrap();
    for outside in [elsewhere.path().to_path_buf(), sibling] {
        let e = RunPlan::from_cfg(&env.cfg, &RunFlags { workspace: Some(outside.clone()), ..env.flags() }).unwrap_err();
        assert!(matches!(e, BridgeError::OutsideRoots(_)), "{}: {e}", outside.display());
        assert_eq!(exit(e), 9);
    }
    let e = RunPlan::from_cfg(&env.cfg, &RunFlags { workspace: Some(env.work.join("missing")), ..env.flags() }).unwrap_err();
    assert_eq!(exit(e), 1, "a workspace that does not exist is a usage error, not a policy one");
    let inside = env.plan(&env.flags());
    let (canonical, slug) = inside.workspace.unwrap();
    assert_eq!(canonical, std::fs::canonicalize(&env.ws).unwrap());
    assert_eq!(slug, ai_env_cli::wire::slug::project_dir_name(&env.ws).unwrap());
}

#[tokio::test]
async fn egress_rules() {
    let mut env = Env::new();
    // No connector, [egress].require = true.
    let e = effective_egress(&env.cfg, None, false).unwrap_err();
    assert!(matches!(e, BridgeError::EgressRequired));
    assert_eq!(exit(e), 9);
    assert_eq!(effective_egress(&env.cfg, None, true).unwrap(), (Egress::Internet, vec![]), "smoke and lab imply internet");
    assert_eq!(effective_egress(&env.cfg, Some(Egress::Internet), false).unwrap(), (Egress::Internet, vec![]));
    let e = effective_egress(&env.cfg, Some(Egress::Vpc), true).unwrap_err();
    assert_eq!(exit(e), 9, "vpc without a connector");
    let e = RunPlan::from_cfg(&env.cfg, &RunFlags { egress: None, ..env.flags() }).unwrap_err();
    assert_eq!(exit(e), 9, "vm run without a connector needs --egress internet");
    env.cfg.egress.require = false;
    assert_eq!(effective_egress(&env.cfg, None, false).unwrap(), (Egress::Internet, vec![]));
    env.cfg.egress.require = true;
    env.cfg.aws.egress_connector_arn = Some(CONNECTOR.to_string());
    assert_eq!(effective_egress(&env.cfg, None, false).unwrap(), (Egress::Vpc, vec![CONNECTOR.to_string()]), "a connector means vpc by default");
    assert_eq!(effective_egress(&env.cfg, None, true).unwrap().0, Egress::Vpc);
    assert_eq!(effective_egress(&env.cfg, Some(Egress::Internet), false).unwrap(), (Egress::Internet, vec![]));
    // Internet is audited; vpc is not.
    let api = api();
    let open = started_id(&select_vm(&api, &env.paths, &env.plan(&RunFlags { workspace: Some(env.workspace("open")), ..env.flags() }), fast()).await.unwrap());
    let closed = started_id(&select_vm(&api, &env.paths, &env.plan(&RunFlags { egress: None, workspace: Some(env.workspace("closed")), ..env.flags() }), fast()).await.unwrap());
    let internet: Vec<String> = env.events("vm_egress_internet").iter().map(|r| r["detail"]["client_token"].as_str().unwrap().to_string()).collect();
    assert_eq!(internet, [env.row(&open).client_token], "audited once, by the pending row's client token");
    let specs = api.run_specs();
    assert!(specs[0].egress_connectors.is_empty());
    assert_eq!(specs[1].egress_connectors, [CONNECTOR]);
    assert_eq!(env.row(&open).egress, "internet");
    assert_eq!(env.row(&closed).egress, "vpc");
}

#[test]
fn idle_rules() {
    let mut env = Env::new();
    let flags = RunFlags { max_duration_s: Some(900), ..env.flags() };
    // Defaults: idle = [vm].max_idle_s, suspended = min(suspended_s(), max duration), auto-resume on.
    let plan = env.plan(&flags);
    assert_eq!((plan.idle.max_idle_s, plan.idle.suspended_s, plan.idle.auto_resume), (300, 900, true));
    assert_eq!(plan.max_duration_s, 900);
    env.cfg.vm.suspended_s = Some(600);
    assert_eq!(env.plan(&flags).idle.suspended_s, 600);
    assert!(!env.plan(&RunFlags { no_auto_resume: true, ..flags.clone() }).idle.auto_resume);
    // Refused, naming the flag (exit 9) or the key (exit 1); never clamped.
    let e = RunPlan::from_cfg(&env.cfg, &RunFlags { idle_s: Some(120), ..flags.clone() }).unwrap_err();
    assert!(e.to_string().contains("--idle") && e.to_string().contains("300"), "{e}");
    assert_eq!(exit(e), 9);
    let e = RunPlan::from_cfg(&env.cfg, &RunFlags { suspended_s: Some(901), ..flags.clone() }).unwrap_err();
    assert!(e.to_string().contains("--suspended"), "{e}");
    assert_eq!(exit(e), 9);
    let e = RunPlan::from_cfg(&env.cfg, &RunFlags { max_duration_s: Some(28_801), ..flags.clone() }).unwrap_err();
    assert!(e.to_string().contains("--max-duration"), "{e}");
    let mut low = env.cfg.clone();
    low.vm.max_idle_s = 60;
    let e = RunPlan::from_cfg(&low, &flags).unwrap_err();
    assert!(e.to_string().contains("[vm].max_idle_s"), "{e}");
    assert_eq!(exit(e), 1);
    // The lab may send out-of-range values, as they are.
    let lab = RunFlags { idle_s: Some(60), suspended_s: Some(86_400), allow_out_of_range_idle: true, ..flags.clone() };
    let plan = env.plan(&lab);
    assert_eq!((plan.idle.max_idle_s, plan.idle.suspended_s), (60, 86_400));
    let e = RunPlan::from_cfg(&env.cfg, &RunFlags { suspended_s: Some(u32::MAX), ..lab }).unwrap_err();
    assert!(e.to_string().contains("never clamped"), "{e}");
    // The image comes from the flag or [aws].image_arn.
    let mut none = env.cfg.clone();
    none.aws.image_arn = None;
    let e = RunPlan::from_cfg(&none, &flags).unwrap_err();
    assert!(e.to_string().contains("make infra-status WRITE=1"), "{e}");
    assert_eq!(exit(e), 1);
    assert_eq!(RunPlan::from_cfg(&none, &RunFlags { image: Some(FAKE_IMAGE_ARN.into()), ..flags }).unwrap().image_arn, FAKE_IMAGE_ARN);
}

// ---- payload -----------------------------------------------------------------------------

#[tokio::test]
async fn payload_is_shim_valid_and_carries_only_the_commitment() {
    let token = new_session_token();
    let me = owner();
    let created = created_at(0);
    let json = build_payload(&token, &me, &created).unwrap();
    let p = RunHookPayload::from_json(&json).unwrap();
    assert_eq!(p.owner, me);
    assert!(parse_rfc3339_utc(&p.created).is_some());
    assert_eq!(p.commit, commitment_hex(token.expose().as_bytes()));
    assert!(p.matches(token.expose().as_bytes()));
    assert!(!json.contains(token.expose().as_str()), "never the token itself");
    let e = build_payload(&token, &"u".repeat(300), &created).unwrap_err();
    assert_eq!(exit(e), 9, "a payload the shim would refuse is refused here");
    // What select_vm actually sends.
    let env = Env::new();
    let api = api();
    let sel = select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap();
    let row = sel.row();
    let sent = &api.run_specs()[0].run_hook_payload;
    let p = RunHookPayload::from_json(sent).unwrap();
    assert_eq!((p.owner.as_str(), p.created.as_str(), p.commit.as_str()), (me.as_str(), row.created.as_str(), row.commit.as_str()));
    let session = row.session_token.clone().unwrap();
    assert_eq!(p.commit, commitment_hex(session.as_bytes()));
    assert!(!sent.contains(&session));
    assert!(created.ends_with('Z') && row.created.len() == "2026-09-29T10:00:00.000Z".len(), "milliseconds: {}", row.created);
}

#[test]
fn padded_payload_4096_passes_shim_validation_4097_does_not() {
    let json = build_payload(&new_session_token(), &owner(), &created_at(0)).unwrap();
    let pad = |total: usize| format!("{{{}{}", " ".repeat(total - json.len()), &json[1..]);
    let at_cap = pad(RunHookPayload::MAX_BYTES);
    assert_eq!(at_cap.len(), 4096);
    RunHookPayload::from_json(&at_cap).unwrap();
    let over = pad(RunHookPayload::MAX_BYTES + 1);
    assert_eq!(over.len(), 4097);
    assert!(RunHookPayload::from_json(&over).is_err());
    assert_eq!(exit(BridgeError::PayloadTooLarge(over.len())), 9);
}

// ---- image version -----------------------------------------------------------------------

#[tokio::test]
async fn image_version_active_and_n_to_n0_resolution() {
    let api = api();
    {
        let mut st = api.state();
        let v = |version: &str, state: &str, status: &str| ImageVersion { version: version.into(), state: state.into(), status: status.into(), memory_mib: Some(2048), created_at_unix: None };
        st.versions = vec![v("1.0", "SUCCESSFUL", "ACTIVE"), v("2.0", "SUCCESSFUL", "ACTIVE"), v("3.0", "FAILED", "ACTIVE"), v("4.0", "SUCCESSFUL", "INACTIVE")];
        st.image.as_mut().unwrap().latest_active = Some("2.0".into());
    }
    let (v, note) = resolve_image_version(&api, FAKE_IMAGE_ARN, "active").await.unwrap();
    assert_eq!((v.version.as_str(), note), ("2.0", None));
    let (v, note) = resolve_image_version(&api, FAKE_IMAGE_ARN, "1").await.unwrap();
    assert_eq!(v.version, "1.0");
    assert!(note.unwrap().contains("1.0"), "N matches N.0 with a note");
    assert_eq!(resolve_image_version(&api, FAKE_IMAGE_ARN, "1.0").await.unwrap().1, None);
    for bad in ["3", "4.0", "7", "7.0", "latest", "1.x", ""] {
        let e = resolve_image_version(&api, FAKE_IMAGE_ARN, bad).await.unwrap_err();
        assert!(matches!(e, BridgeError::Validation(_)), "{bad}: {e}");
        let text = e.to_string();
        assert!(text.contains("1.0 (SUCCESSFUL/ACTIVE)") && text.contains("3.0 (FAILED/ACTIVE)"), "names the listed versions: {text}");
        assert_eq!(exit(e), 7);
    }
    api.state().image.as_mut().unwrap().latest_active = Some("9.0".into());
    assert!(resolve_image_version(&api, FAKE_IMAGE_ARN, "active").await.unwrap_err().to_string().contains("9.0"));
    api.state().image.as_mut().unwrap().latest_active = Some("3.0".into());
    assert!(resolve_image_version(&api, FAKE_IMAGE_ARN, "active").await.is_err(), "the active version must be runnable");
    api.state().image.as_mut().unwrap().latest_active = None;
    assert!(resolve_image_version(&api, FAKE_IMAGE_ARN, "active").await.unwrap_err().to_string().contains("no active version"));
    // select_vm passes the resolved string.
    let env = Env::new();
    let api = api_with_active("1.0");
    select_vm(&api, &env.paths, &env.plan(&RunFlags { version: Some("1".into()), ..env.flags() }), fast()).await.unwrap();
    assert_eq!(api.run_specs()[0].image_version, "1.0");
}

fn api_with_active(v: &str) -> ai_env_cli::bridge::api::FakeMicrovmApi {
    let a = api();
    a.state().image.as_mut().unwrap().latest_active = Some(v.into());
    a
}

// ---- rows and audit ----------------------------------------------------------------------

#[tokio::test]
async fn vm_row_modes_and_json_view_without_session_token() {
    let env = Env::new();
    let api = api();
    let plan = env.plan(&RunFlags { label: Some("review".into()), ..env.flags() });
    let sel = select_vm(&api, &env.paths, &plan, fast()).await.unwrap();
    let Selected::Started { row, vm, .. } = &sel else { panic!("expected a new VM, reused {}", sel.row().id) };
    let path = env.paths.vms().join(format!("{}.toml", row.id));
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(env.paths.vms()).unwrap().permissions().mode() & 0o777, 0o700);
    let disk = env.row(&row.id);
    assert_eq!(&disk, row);
    assert_eq!(disk.status, RowStatus::Running);
    assert_eq!(disk.state_seen.as_deref(), Some("RUNNING"));
    assert_eq!(disk.client_token.len(), 36);
    assert_eq!(disk.client_token.as_bytes()[14], b'7', "uuid v7: {}", disk.client_token);
    assert_eq!(disk.label.as_deref(), Some("review"));
    assert_eq!(disk.workspace.as_deref(), Some(std::fs::canonicalize(&env.ws).unwrap().to_str().unwrap()));
    assert_eq!(disk.slug, Some(ai_env_cli::wire::slug::project_dir_name(&env.ws).unwrap()));
    assert_eq!((disk.image_arn.as_str(), disk.image_version.as_str()), (FAKE_IMAGE_ARN, "1.0"));
    assert!(disk.endpoint.as_deref().unwrap().ends_with(ENDPOINT_SUFFIX));
    assert_eq!(disk.owner, owner());
    assert_eq!(disk.started_at, vm.started_at_unix.map(|s| s as u64));
    assert_eq!(disk.wall_deadline, disk.started_at.map(|s| s + 3600));
    assert_eq!(disk.max_duration_s, 3600);
    let idle = disk.idle.unwrap();
    assert_eq!((idle.max_idle_s, idle.suspended_s, idle.auto_resume), (300, 3600, true));
    assert_eq!(disk.egress, "internet");
    assert_eq!(disk.ingress, [managed_connector_arn("HTTP_INGRESS")], "the echoed default ingress");
    assert!(!disk.shell);
    let session = disk.session_token.clone().unwrap();
    assert_eq!(session.len(), 64);
    assert_eq!(disk.commit, commitment_hex(session.as_bytes()));
    let view = registry::view(&disk);
    assert!(view.get("session_token").is_none());
    assert!(!view.to_string().contains(&session));
    assert_eq!(view["commit"], disk.commit.as_str());
}

#[tokio::test]
async fn audit_rows_never_contain_the_session_token() {
    let env = Env::new();
    let api = api();
    let plan = env.plan(&env.flags());
    let id = started_id(&select_vm(&api, &env.paths, &plan, fast()).await.unwrap());
    let other = started_id(&select_vm(&api, &env.paths, &env.plan(&RunFlags { workspace: None, ..env.flags() }), fast()).await.unwrap());
    let mut sessions: Vec<String> = env.rows().iter().filter_map(|r| r.session_token.clone()).collect();
    assert_eq!(sessions.len(), 2);
    // As a fresh process sees them: tokens read back from disk that the scrubber never saw.
    for vm in [&id, &other] {
        let mut row = env.row(vm);
        let token = unregistered_token();
        row.session_token = Some(token.clone());
        row.commit = commitment_hex(token.as_bytes());
        registry::write_row(&env.paths, &row).unwrap();
        sessions.push(token);
    }
    // Reuse (vm_reuse), a crashed run gc adopts (vm_adopt), termination (vm_terminate), gc (vm_gc).
    assert_eq!(reused_id(&select_vm(&api, &env.paths, &plan, fast()).await.unwrap()), id);
    let crashed = env.pending_row_with_token(&owner(), &created_at(-10), 3600, unregistered_token());
    sessions.push(crashed.session_token.clone().unwrap());
    run_direct(&api, &owner(), &crashed.created).await;
    api.advance_all();
    terminate_and_record(&api, &env.paths, &id, "test", None).await.unwrap();
    let mut row = env.row(&other);
    row.wall_deadline = Some(unix_now());
    registry::write_row(&env.paths, &row).unwrap();
    let report = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &GcOpts { yes: true, include_orphans: None, probe_health: true }).await.unwrap();
    assert_eq!((report.adopted, report.terminated), (1, 1), "{:#?}", report.items);
    let text = std::fs::read_to_string(env.paths.audit()).unwrap();
    for s in &sessions {
        assert!(!text.contains(s.as_str()), "a session token reached audit.jsonl");
    }
    assert!(!text.contains("[redacted"), "nothing had to be scrubbed: the code never hands audit a token\n{text}");
    let keys = |names: &[&str]| names.iter().map(|k| (*k).to_string()).collect::<BTreeSet<String>>();
    let expected: BTreeMap<&str, BTreeSet<String>> = [
        ("vm_run", keys(&["actor", "id", "purpose", "image_version", "egress", "shell", "client_token"])),
        ("vm_egress_internet", keys(&["actor", "client_token", "purpose"])),
        ("vm_reuse", keys(&["actor", "id", "purpose", "resumed"])),
        ("vm_terminate", keys(&["actor", "id", "by"])),
        ("vm_adopt", keys(&["actor", "id", "client_token", "egress", "via"])),
        ("vm_gc", keys(&["actor", "terminated", "adopted", "removed", "marked", "errors", "include_orphans_s"])),
    ]
    .into_iter()
    .collect();
    let rows = env.audit();
    let seen: BTreeSet<&str> = rows.iter().map(|r| r["event"].as_str().unwrap()).collect();
    assert_eq!(seen, expected.keys().copied().collect(), "{text}");
    for r in &rows {
        let event = r["event"].as_str().unwrap();
        let detail: BTreeSet<String> = r["detail"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(&detail, &expected[event], "{event}: exactly these detail keys");
        assert_eq!(r["detail"]["actor"], "cli");
    }
}

#[tokio::test]
async fn select_debug_output_never_carries_the_session_token() {
    let env = Env::new();
    let api = api();
    let plan = env.plan(&env.flags());
    let started = select_vm(&api, &env.paths, &plan, fast()).await.unwrap();
    let reused = select_vm(&api, &env.paths, &plan, fast()).await.unwrap();
    let session = started.row().session_token.clone().unwrap();
    for text in [format!("{started:?}"), format!("{reused:#?}")] {
        assert!(!text.contains(&session), "{text}");
        assert!(text.contains(&started.row().id), "names the VM: {text}");
    }
    let failure = double_ambiguous(&env, &api).await;
    let kept = failure.kept_pending.as_deref().unwrap();
    let text = format!("{failure:?}");
    assert!(!text.contains(kept.session_token.as_deref().unwrap()), "{text}");
    assert!(text.contains(&kept.stem()), "{text}");
}

// ---- terminate and adoption ---------------------------------------------------------------

#[tokio::test]
async fn terminate_and_record_is_idempotent() {
    let env = Env::new();
    let api = api();
    let id = started_id(&select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap());
    let settle = Some(Poll::SETTLE.scaled(Some(1)));
    let info = terminate_and_record(&api, &env.paths, &id, "operator", settle).await.unwrap().unwrap();
    assert_eq!(info.state, VmState::Terminated);
    let first = env.row(&id);
    assert_eq!(first.status, RowStatus::Terminated);
    assert_eq!(first.terminated_by.as_deref(), Some("operator"));
    assert_eq!(first.state_seen.as_deref(), Some("TERMINATED"));
    let again = terminate_and_record(&api, &env.paths, &id, "gc-expired", settle).await.unwrap().unwrap();
    assert_eq!(again.state, VmState::Terminated);
    let second = env.row(&id);
    assert_eq!((second.status, second.terminated_at, second.terminated_by.clone()), (first.status, first.terminated_at, first.terminated_by.clone()), "the first termination is kept");
    // A VM the service no longer knows counts as terminated; no row is invented.
    let unknown = "microvm-00000000-0000-4000-8000-0000000000cc";
    let gone = terminate_and_record(&api, &env.paths, unknown, "operator", settle).await.unwrap().unwrap();
    assert_eq!(gone.state, VmState::Terminated);
    assert!(registry::read_row(&env.paths, unknown).unwrap().is_none());
    assert_eq!(terminate_and_record(&api, &env.paths, unknown, "operator", None).await.unwrap(), None);
    assert_eq!(exit(terminate_and_record(&api, &env.paths, "../x", "operator", None).await.unwrap_err()), 1);
    let by: Vec<String> = env.events("vm_terminate").iter().map(|r| r["detail"]["by"].as_str().unwrap().to_string()).collect();
    assert_eq!(by, ["operator", "gc-expired", "operator", "operator"]);
}

#[tokio::test]
async fn adopt_after_ambiguous_finds_the_vm() {
    let env = Env::new();
    let api = api(); // a booting VM becomes RUNNING on its first GetMicrovm
    let t0 = unix_now();
    // Decoys: a foreign VM and an own VM of another run, both RUNNING and row-less.
    run_direct(&api, FOREIGN, &created_at(0)).await;
    run_direct(&api, &owner(), &created_at(-5)).await;
    api.advance_all();
    let older = env.pending_row(&owner(), &created_at(-120_000), 3600);
    let SelectFailure { error, kept_pending, started, .. } = double_ambiguous(&env, &api).await;
    assert_eq!(exit(error), 7);
    assert_eq!(started, None);
    let pending = *kept_pending.expect("the pending row is handed back");
    assert_ne!(pending.client_token, older.client_token);
    let ours = vm_of(&api, &pending.client_token);
    assert_eq!(api.state().vms[&ours].state, VmState::Pending, "the failure came back while the VM still boots");
    // Another own run started meanwhile: a newer pending row, its VM already RUNNING.
    let concurrent = env.pending_row(&owner(), &created_at(1_000), 3600);
    let concurrent_vm = run_direct(&api, &owner(), &concurrent.created).await.id;
    api.set_state(&concurrent_vm, VmState::Running);
    let adopted = adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap();
    assert_eq!(adopted, Adoption::Adopted(ours.clone()), "the VM of this run, waited for while PENDING");
    let row = env.row(&ours);
    assert_eq!(row.status, RowStatus::Running);
    assert_eq!(row.session_token, pending.session_token, "the pending row's token and commit carry over");
    assert_eq!(row.commit, pending.commit);
    assert!(row.endpoint.is_some() && row.wall_deadline.is_some());
    assert!(registry::read_row(&env.paths, &concurrent_vm).unwrap().is_none(), "the other run's VM is not taken");
    let left: BTreeSet<String> = env.rows().iter().filter(|r| r.is_pending_row()).map(VmRow::stem).collect();
    assert_eq!(left, [older.stem(), concurrent.stem()].into_iter().collect(), "only the unrelated pending rows are left");
    assert_eq!(env.events("vm_adopt")[0]["detail"]["id"], ours.as_str());
    assert_eq!(env.events("vm_adopt")[0]["detail"]["egress"], "internet");
    // Nothing left to adopt: a second sweep finds no match (every candidate answered for another run).
    assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), Adoption::NoMatch);
    let id_row = VmRow { id: ours, ..pending };
    assert_eq!(exit(adopt_after_ambiguous(&api, &api, &env.paths, &id_row, t0, fast()).await.unwrap_err()), 1, "only a pending row is swept for");
}

#[tokio::test]
async fn adopt_after_ambiguous_reports_a_vm_it_could_not_ask() {
    let env = Env::new();
    let api = FakeMicrovmApi::new(); // never advances by itself: the VM stays PENDING
    let t0 = unix_now();
    let pending = *double_ambiguous(&env, &api).await.kept_pending.unwrap();
    let ours = vm_of(&api, &pending.client_token);
    let unresolved = Adoption::Unresolved(vec![ours.clone()]);
    assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), unresolved, "still PENDING after the budget: not 'no VM'");
    // Booted, but its endpoint answers for another microvm_id (misrouted): never adopted.
    api.advance_all();
    api.set_health(&ours, health_claiming(Some("microvm-someone-else"), &pending.owner, &pending.created));
    assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), unresolved);
    api.set_health(&ours, health_claiming(None, &pending.owner, &pending.created));
    assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), unresolved);
    // Its own answer, but the run hook has not reached the shim yet (no owner, or no created): not "no VM".
    let no_owner = ai_env_cli::wire::frame::Health { owner: None, ..health_claiming(Some(&ours), &pending.owner, &pending.created) };
    api.set_health(&ours, no_owner);
    assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), unresolved, "no owner yet: unresolved, never NoMatch");
    let no_created = ai_env_cli::wire::frame::Health { created: None, ..health_claiming(Some(&ours), &pending.owner, &pending.created) };
    api.set_health(&ours, no_created);
    assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), unresolved, "no created yet: unresolved");
    assert!(registry::read_row(&env.paths, &ours).unwrap().is_none());
    assert!(env.paths.vms().join(format!("{}.toml", pending.stem())).exists(), "the pending row stays for gc");
    assert!(env.events("vm_adopt").is_empty());
    // Its own answer adopts it.
    api.state().health_override.remove(&ours);
    assert_eq!(adopt_after_ambiguous(&api, &api, &env.paths, &pending, t0, fast()).await.unwrap(), Adoption::Adopted(ours.clone()));
    // A candidate that ends while booting is skipped, not unresolved.
    let env = Env::new();
    let spy = Spy::new(&env.paths);
    spy.inner.fail_on("run", ambiguous(), true);
    spy.inner.fail_on("run", ambiguous(), true);
    let pending = *select_vm_detailed(&spy, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap_err().kept_pending.unwrap();
    let booting = vm_of(&spy.inner, &pending.client_token);
    assert_eq!(spy.inner.state().vms[&booting].state, VmState::Pending);
    *spy.kill_on_get.lock().unwrap() = Some("InsufficientCapacity: host reclaimed".into());
    assert_eq!(adopt_after_ambiguous(&spy, &spy, &env.paths, &pending, t0, fast()).await.unwrap(), Adoption::NoMatch);
}

// ---- review fixes: the RUNNING poll, termination, reuse, plan knobs ------------------------

#[tokio::test]
async fn wait_retries_transient_get_failures_while_starting() {
    // The real client maps a GetMicrovm timeout/dispatch/5xx to `Sdk { op: "get_microvm" }`,
    // and right after RunMicrovm the VM may not be visible yet (NotFound).
    let env = Env::new();
    let api = api();
    api.fail_on("get", get_timeout(), false);
    api.fail_on("get", BridgeError::VmNotFound("MicroVM not found: (read-after-create)".into()), false);
    api.fail_on("get", BridgeError::Throttled("Rate exceeded".into()), false);
    api.fail_on("get", get_timeout(), false);
    let sel = select_vm_detailed(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap();
    let id = started_id(&sel);
    assert_eq!(sel.vm().state, VmState::Running);
    let row = env.row(&id);
    assert_eq!((row.status, row.terminated_by.as_deref()), (RowStatus::Running, None));
    assert!(!api.calls().contains(&Call::Terminate(id)));
}

#[tokio::test]
async fn get_failing_through_the_budget_terminates_by_timeout_never_platform() {
    for (what, e) in [("GetMicrovm timeouts", get_timeout as fn() -> BridgeError), ("NotFound", || BridgeError::VmNotFound("MicroVM not found".into()))] {
        let env = Env::new();
        let api = api();
        fail_gets(&api, e, 2000);
        let failure = select_vm_detailed(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap_err();
        api.state().failures.clear();
        let id = api.state().vms.keys().next().expect("RunMicrovm created the VM").clone();
        let text = failure.error.to_string();
        assert!(text.contains(&id) && text.contains("not RUNNING") && text.contains("terminated it"), "{what}: {text}");
        assert_eq!(failure.started, None, "{what}: terminated, nothing left to clean up");
        let row = env.row(&id);
        assert_eq!(failure.client_token.as_deref(), Some(row.client_token.as_str()), "{what}");
        assert_eq!(exit(failure.error), 7, "{what}");
        assert!(api.calls().contains(&Call::Terminate(id.clone())), "{what}: TerminateMicrovm was called");
        assert_eq!((row.status, row.terminated_by.as_deref()), (RowStatus::Terminated, Some("timeout")), "{what}: never `platform` without the service saying so");
        assert_eq!(env.events("vm_terminate")[0]["detail"]["by"], "timeout", "{what}");
    }
}

#[tokio::test]
async fn terminate_records_the_row_and_audit_before_waiting() {
    let env = Env::new();
    let api = api();
    let id = started_id(&select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap());
    fail_gets(&api, get_timeout, 2000);
    let e = terminate_and_record(&api, &env.paths, &id, "operator", Some(fast())).await.unwrap_err();
    api.state().failures.clear();
    assert!(e.to_string().contains("not TERMINATED"), "the wait failure is returned: {e}");
    let row = env.row(&id);
    assert_eq!((row.status, row.terminated_by.as_deref(), row.state_seen.as_deref()), (RowStatus::Terminated, Some("operator"), Some("TERMINATING")), "recorded before the wait");
    assert!(row.terminated_at.is_some());
    let t = env.events("vm_terminate");
    assert_eq!(t.len(), 1);
    assert_eq!((t[0]["detail"]["id"].as_str(), t[0]["detail"]["by"].as_str()), (Some(id.as_str()), Some("operator")));
    // Without a wait: Ok(None), the record written all the same.
    let other = started_id(&select_vm(&api, &env.paths, &env.plan(&RunFlags { workspace: None, ..env.flags() }), fast()).await.unwrap());
    assert_eq!(terminate_and_record(&api, &env.paths, &other, "test", None).await.unwrap(), None);
    assert_eq!(env.row(&other).status, RowStatus::Terminated);
}

#[tokio::test]
async fn reuse_takes_a_pending_or_unknown_id_row_after_asking_the_service() {
    let env = Env::new();
    let api = FakeMicrovmApi::new(); // PENDING until advanced
    // `--no-wait`: the id row stays pending, the VM PENDING.
    let first = select_vm(&api, &env.paths, &env.plan(&RunFlags { wait: false, ..env.flags() }), fast()).await.unwrap();
    let id = started_id(&first);
    assert_eq!(env.row(&id).status, RowStatus::Pending);
    api.set_auto_advance(true);
    // As if RunMicrovm had answered without a start: a RUNNING GetMicrovm fills it in.
    let mut row = env.row(&id);
    row.started_at = None;
    registry::write_row(&env.paths, &row).unwrap();
    let plan = env.plan(&env.flags());
    match select_vm(&api, &env.paths, &plan, fast()).await.unwrap() {
        Selected::Reused { row, vm, resumed } => {
            assert_eq!((row.id.as_str(), resumed, vm.state), (id.as_str(), false, VmState::Running), "waited for RUNNING");
            assert_eq!(row.status, RowStatus::Running);
            let start = vm.started_at_unix.map(|s| s as u64);
            assert_eq!(row.started_at, start, "started_at filled from the RUNNING answer");
            assert_eq!(row.wall_deadline, start.map(|s| s + 3600));
        }
        other => panic!("the pending row's VM is reused, not a new run: {other:?}"),
    }
    assert_eq!(api.run_specs().len(), 1);
    // An unknown status is asked about too.
    let mut row = env.row(&id);
    row.status = RowStatus::Unknown;
    registry::write_row(&env.paths, &row).unwrap();
    assert_eq!(reused_id(&select_vm(&api, &env.paths, &plan, fast()).await.unwrap()), id);
    assert_eq!(env.row(&id).status, RowStatus::Running);
    // A pending row whose VM the service says ended is marked and skipped.
    let mut row = env.row(&id);
    row.status = RowStatus::Pending;
    registry::write_row(&env.paths, &row).unwrap();
    api.set_state(&id, VmState::Terminated);
    let fresh = started_id(&select_vm(&api, &env.paths, &plan, fast()).await.unwrap());
    assert_ne!(fresh, id);
    let dead = env.row(&id);
    assert_eq!((dead.status, dead.terminated_by.as_deref()), (RowStatus::Terminated, Some("platform")));
    // Not found (possibly seconds old): skipped, never marked.
    let ghost = VmRow { id: "microvm-00000000-0000-4000-8000-0000000000ee".into(), status: RowStatus::Pending, created: created_at(1_000), ..env.row(&fresh) };
    let ghost = VmRow { client_token: uuid::Uuid::now_v7().to_string(), ..ghost };
    registry::write_row(&env.paths, &ghost).unwrap();
    assert_eq!(reused_id(&select_vm(&api, &env.paths, &plan, fast()).await.unwrap()), fresh, "the next candidate");
    assert_eq!(env.row(&ghost.id).status, RowStatus::Pending, "a not-found pending row is left for gc");
}

#[tokio::test]
async fn a_chosen_client_token_names_the_pending_row_and_every_failure_after_it() {
    let env = Env::new();
    let api = api();
    let chosen = uuid::Uuid::now_v7().to_string();
    let mut plan = env.plan(&RunFlags { workspace: None, ..env.flags() });
    assert_eq!((plan.client_token.clone(), plan.pad_payload_to), (None, None), "from_cfg sets neither");
    plan.client_token = Some(chosen.clone());
    let sel = select_vm(&api, &env.paths, &plan, fast()).await.unwrap();
    assert_eq!(sel.row().client_token, chosen);
    assert_eq!(runs(&api.calls()), std::slice::from_ref(&chosen));
    // A failure after the pending row was written carries its token.
    api.fail_on("run", ambiguous(), false);
    api.fail_on("run", ambiguous(), false);
    let mut again = plan.clone();
    let second = uuid::Uuid::now_v7().to_string();
    again.client_token = Some(second.clone());
    let failure = select_vm_detailed(&api, &env.paths, &again, fast()).await.unwrap_err();
    assert_eq!(failure.client_token.as_deref(), Some(second.as_str()));
    assert_eq!(failure.kept_pending.as_deref().map(|r| r.client_token.clone()), Some(second));
    api.fail_on("run", BridgeError::Validation("no".into()), false);
    let definite = select_vm_detailed(&api, &env.paths, &env.plan(&RunFlags { workspace: None, ..env.flags() }), fast()).await.unwrap_err();
    assert!(definite.client_token.is_some() && definite.kept_pending.is_none(), "the row existed (then was removed): {definite:?}");
    // Before any pending row: no token.
    let mut full = env.cfg.clone();
    full.vm.max_concurrent = 1;
    let refused = select_vm_detailed(&api, &env.paths, &RunPlan::from_cfg(&full, &RunFlags { workspace: None, ..env.flags() }).unwrap(), fast()).await.unwrap_err();
    assert!(matches!(refused.error, BridgeError::MaxConcurrent(1)), "{refused:?}");
    assert_eq!(refused.client_token, None);
    // Anything but a lowercase hyphenated uuid is refused before placement (it names the row's file).
    let before = api.calls().len();
    for bad in ["../x", "not-a-uuid", &uuid::Uuid::now_v7().to_string().to_uppercase(), &uuid::Uuid::now_v7().simple().to_string()] {
        let mut p = plan.clone();
        p.client_token = Some(bad.to_string());
        let f = select_vm_detailed(&api, &env.paths, &p, fast()).await.unwrap_err();
        assert_eq!((exit(f.error), f.client_token), (1, None), "{bad}");
    }
    assert!(runs(&api.calls()[before..]).is_empty());
}

#[tokio::test]
async fn pad_payload_to_pads_after_the_brace_and_lets_the_api_decide() {
    let env = Env::new();
    let api = api();
    let base = env.plan(&RunFlags { workspace: None, ..env.flags() });
    let mut plan = base.clone();
    plan.pad_payload_to = Some(RunHookPayload::MAX_BYTES);
    let sel = select_vm(&api, &env.paths, &plan, fast()).await.unwrap();
    let sent = api.run_specs()[0].run_hook_payload.clone();
    assert_eq!(sent.len(), 4096);
    assert!(sent.starts_with("{ "), "spaces right after the brace");
    let p = RunHookPayload::from_json(&sent).unwrap();
    assert_eq!((p.owner.as_str(), p.created.as_str(), p.commit.as_str()), (sel.row().owner.as_str(), sel.row().created.as_str(), sel.row().commit.as_str()));
    // Over 4096: sent as is, the API refuses it (a definite failure: the pending row goes).
    plan.pad_payload_to = Some(RunHookPayload::MAX_BYTES + 1);
    let e = select_vm(&api, &env.paths, &plan, fast()).await.unwrap_err();
    assert!(matches!(e, BridgeError::Validation(_)) && e.to_string().contains("4097"), "{e}");
    assert_eq!(runs(&api.calls()).len(), 2, "it reached RunMicrovm");
    // Shorter than the payload: a config error before any row or run.
    plan.pad_payload_to = Some(10);
    let rows = env.rows().len();
    let e = select_vm(&api, &env.paths, &plan, fast()).await.unwrap_err();
    assert_eq!(exit(e), 1);
    assert_eq!((env.rows().len(), runs(&api.calls()).len()), (rows, 2));
    // The helper itself.
    let base = build_payload(&new_session_token(), &owner(), &created_at(0)).unwrap();
    assert_eq!(padded_payload(&base, base.len()).as_deref(), Some(base.as_str()));
    assert_eq!(padded_payload(&base, base.len() + 3).unwrap(), format!("{{   {}", &base[1..]));
    assert_eq!(padded_payload(&base, base.len() - 1), None);
    assert_eq!(padded_payload("[1]", 10), None, "not an object");
}

#[tokio::test]
async fn internet_egress_is_audited_when_the_pending_row_is_written() {
    // An ambiguous RunMicrovm may create the VM without ever answering: the audit row must exist anyway.
    let env = Env::new();
    let api = api();
    let failure = double_ambiguous(&env, &api).await;
    let pending = failure.kept_pending.expect("kept");
    let egress = env.events("vm_egress_internet");
    assert_eq!(egress.len(), 1);
    assert_eq!((egress[0]["detail"]["client_token"].as_str(), egress[0]["detail"]["purpose"].as_str()), (Some(pending.client_token.as_str()), Some("test")));
    assert!(env.events("vm_run").is_empty(), "vm_run stays at the answer");
    // A run that answers is audited once, not twice.
    let env = Env::new();
    select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap();
    assert_eq!((env.events("vm_egress_internet").len(), env.events("vm_run").len()), (1, 1));
}

#[test]
fn memory_warning_names_both_values() {
    let env = Env::new();
    assert_eq!(env.plan(&env.flags()).memory_mib, 2048, "[vm].memory_mib");
    let v = |mib: Option<i32>| ImageVersion { version: "1.0".into(), state: "SUCCESSFUL".into(), status: "ACTIVE".into(), memory_mib: mib, created_at_unix: None };
    assert_eq!(memory_warning(2048, &v(Some(2048))), None);
    assert_eq!(memory_warning(2048, &v(None)), None, "nothing to compare");
    assert_eq!(memory_warning(4096, &v(Some(2048))).unwrap(), "[vm].memory_mib = 4096 but version 1.0 has 2048 MiB (the quota check uses [vm].memory_mib)");
}
