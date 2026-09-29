//! `vm::gc`: the nine classes of the plan S4 §7 table in one scenario, the
//! dry run that writes nothing, what `--yes` and `--include-orphans` do,
//! adoption of a crashed run, stale pending rows, the local reconcile and
//! the `vm terminate --all` survey.
use crate::common::{api, created_at, fast, health_claiming, run_direct, run_direct_image, snapshot, started_ago, Env, Spy, FOREIGN};
use ai_env_cli::bridge::api::{Call, FakeMicrovmApi, VmState, FAKE_IMAGE_ARN};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::vm::gc::{gc, hint_line, reconcile_local, terminate_all_plan, GcAction, GcClass, GcItem, GcOpts};
use ai_env_cli::bridge::vm::owner;
use ai_env_cli::bridge::vm::registry::{self, RowStatus, VmRow};
use ai_env_cli::bridge::vm::run::{select_vm, RunFlags, Selected};
use ai_env_cli::wire::time::unix_now;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const GONE_ID: &str = "microvm-00000000-0000-4000-8000-0000000000f1";
const OLD_ID: &str = "microvm-00000000-0000-4000-8000-0000000000f2";

/// One VM or row per class (two for `registry:gone`: listed TERMINATED and unlisted).
struct Nine {
    live: String,
    expired: String,
    gone_listed: String,
    adopt_vm: String,
    adopt_stem: String,
    orphan: String,
    foreign: String,
    suspended: String,
    stale_stem: String,
}

async fn start(env: &Env, api: &FakeMicrovmApi, flags: RunFlags) -> String {
    match select_vm(api, &env.paths, &env.plan(&flags), fast()).await.unwrap() {
        Selected::Started { row, .. } => row.id,
        other => panic!("{other:?}"),
    }
}

/// Build the nine-class scenario (every VM of the fake image).
async fn nine(env: &Env, api: &FakeMicrovmApi) -> Nine {
    let now = unix_now();
    let live = start(env, api, env.flags()).await;
    let expired = start(env, api, RunFlags { workspace: None, ..env.flags() }).await;
    let mut row = env.row(&expired);
    row.wall_deadline = Some(now + 30);
    registry::write_row(&env.paths, &row).unwrap();
    let gone_listed = start(env, api, RunFlags { workspace: None, ..env.flags() }).await;
    api.set_state(&gone_listed, VmState::Terminated);
    let unlisted = VmRow { id: GONE_ID.into(), status: RowStatus::Running, client_token: uuid::Uuid::now_v7().to_string(), image_arn: FAKE_IMAGE_ARN.into(), created: created_at(0), wall_deadline: Some(now + 3600), ..VmRow::default() };
    registry::write_row(&env.paths, &unlisted).unwrap();
    // A run that crashed after RunMicrovm: its pending row and its VM.
    let crashed_created = created_at(-10);
    let pending = env.pending_row(&owner(), &crashed_created, 3600);
    let adopt_vm = run_direct(api, &owner(), &crashed_created).await.id;
    let orphan = run_direct(api, &owner(), &created_at(-20)).await.id;
    let foreign = run_direct(api, FOREIGN, &created_at(-30)).await.id;
    let suspended = run_direct(api, &owner(), &created_at(-40)).await.id;
    api.advance_all();
    api.set_state(&suspended, VmState::Suspended);
    started_ago(api, &orphan, 7200);
    started_ago(api, &foreign, 7200);
    let stale = env.pending_row(&owner(), &created_at(-600_000), 3600);
    let old = VmRow {
        id: OLD_ID.into(),
        status: RowStatus::Terminated,
        client_token: uuid::Uuid::now_v7().to_string(),
        image_arn: FAKE_IMAGE_ARN.into(),
        created: created_at(-9 * 86_400_000),
        terminated_at: Some(now - 8 * 86_400),
        terminated_by: Some("operator".into()),
        ..VmRow::default()
    };
    registry::write_row(&env.paths, &old).unwrap();
    Nine { live, expired, gone_listed, adopt_vm, adopt_stem: pending.stem(), orphan, foreign, suspended, stale_stem: stale.stem() }
}

fn by_class(items: &[GcItem]) -> BTreeMap<&'static str, Vec<String>> {
    let mut out: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for i in items {
        out.entry(i.class.name()).or_default().push(i.id.clone().or_else(|| i.stem.clone()).unwrap());
    }
    out
}

/// The one id (or stem) of `class`.
fn only(got: &BTreeMap<&'static str, Vec<String>>, class: &str) -> String {
    let v = got.get(class).unwrap_or_else(|| panic!("no {class}: {got:?}"));
    assert_eq!(v.len(), 1, "{class}: {v:?}");
    v[0].clone()
}

fn endpoint(api: &FakeMicrovmApi, id: &str) -> String {
    api.state().vms[id].endpoint.clone()
}

/// No token and no `/health` for `id` in `calls`.
fn never_probed(api: &FakeMicrovmApi, calls: &[Call], id: &str) {
    let ep = endpoint(api, id);
    for c in calls {
        match c {
            Call::Token { id: t, .. } => assert_ne!(t, id, "a token was minted for {id}"),
            Call::Health { endpoint, .. } => assert_ne!(endpoint, &ep, "/health of {id} was asked"),
            _ => {}
        }
    }
}

fn terminated(calls: &[Call]) -> BTreeSet<String> {
    calls.iter().filter_map(|c| if let Call::Terminate(id) = c { Some(id.clone()) } else { None }).collect()
}

const PROBE: GcOpts = GcOpts { yes: false, include_orphans: None, probe_health: true };
const YES: GcOpts = GcOpts { yes: true, include_orphans: None, probe_health: true };

#[tokio::test]
async fn gc_dry_run_classifies_and_writes_nothing() {
    let env = Env::new();
    let api = api();
    let n = nine(&env, &api).await;
    let before = snapshot(&env.paths.root);
    let audit_before = std::fs::read(env.paths.audit()).unwrap();
    let mark = api.calls().len();
    let report = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &PROBE).await.unwrap();
    assert_eq!(snapshot(&env.paths.root), before, "a dry run writes nothing");
    assert_eq!(std::fs::read(env.paths.audit()).unwrap(), audit_before, "not even an audit line");
    let classes: BTreeSet<GcClass> = report.items.iter().map(|i| i.class).collect();
    assert_eq!(classes, GcClass::ALL.into_iter().collect(), "all nine classes: {:#?}", report.items);
    assert!(report.items.iter().all(|i| i.action == GcAction::Report), "{:#?}", report.items);
    assert_eq!((report.terminated, report.adopted, report.removed, report.marked), (0, 0, 0, 0));
    let got = by_class(&report.items);
    assert_eq!(only(&got, "registry:live"), n.live);
    assert_eq!(only(&got, "registry:expired"), n.expired);
    assert_eq!(got["registry:gone"].iter().collect::<BTreeSet<_>>(), [&n.gone_listed, &GONE_ID.to_string()].into_iter().collect());
    assert_eq!(only(&got, "adopt"), n.adopt_vm);
    assert_eq!(report.items.iter().find(|i| i.class == GcClass::Adopt).unwrap().stem.as_deref(), Some(n.adopt_stem.as_str()));
    assert_eq!(only(&got, "orphan:mine"), n.orphan);
    assert_eq!(only(&got, "foreign"), n.foreign);
    assert_eq!(only(&got, "unprobed"), n.suspended);
    assert_eq!(only(&got, "pending:stale"), n.stale_stem);
    assert_eq!(only(&got, "terminated-old"), OLD_ID);
    let foreign = report.items.iter().find(|i| i.class == GcClass::Foreign).unwrap();
    assert!(foreign.detail.contains(FOREIGN), "the owner is reported: {}", foreign.detail);
    let calls = api.calls()[mark..].to_vec();
    assert!(terminated(&calls).is_empty());
    never_probed(&api, &calls, &n.suspended);
    assert!(calls.contains(&Call::Get(GONE_ID.into())), "an unlisted row is looked up");
}

#[tokio::test]
async fn gc_yes_terminates_only_the_expired_registry_vm() {
    let env = Env::new();
    let api = api();
    let n = nine(&env, &api).await;
    let mark = api.calls().len();
    let report = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &YES).await.unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let calls = api.calls()[mark..].to_vec();
    assert_eq!(terminated(&calls), [n.expired.clone()].into_iter().collect());
    assert_eq!((report.terminated, report.adopted, report.removed, report.marked), (1, 1, 2, 2));
    let expired = env.row(&n.expired);
    assert_eq!((expired.status, expired.terminated_by.as_deref()), (RowStatus::Terminated, Some("gc-expired")));
    for id in [n.gone_listed.as_str(), GONE_ID] {
        assert_eq!(env.row(id).status, RowStatus::Terminated, "{id} marked");
    }
    assert_eq!(env.row(&n.live).status, RowStatus::Running);
    assert_eq!(env.row(&n.adopt_vm).status, RowStatus::Running, "adopted");
    assert!(!env.paths.vms().join(format!("{}.toml", n.adopt_stem)).exists());
    assert!(!env.paths.vms().join(format!("{}.toml", n.stale_stem)).exists());
    assert!(registry::read_row(&env.paths, OLD_ID).unwrap().is_none());
    let states = {
        let st = api.state();
        (st.vms[&n.orphan].state.clone(), st.vms[&n.foreign].state.clone(), st.vms[&n.suspended].state.clone())
    };
    assert_eq!(states, (VmState::Running, VmState::Running, VmState::Suspended));
    let g = env.events("vm_gc");
    assert_eq!(g.len(), 1);
    assert_eq!((g[0]["detail"]["terminated"].as_str(), g[0]["detail"]["adopted"].as_str(), g[0]["detail"]["removed"].as_str(), g[0]["detail"]["marked"].as_str()), (Some("1"), Some("1"), Some("2"), Some("2")));
    // A second pass has nothing left to do but keep.
    let again = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &YES).await.unwrap();
    assert_eq!((again.terminated, again.adopted, again.removed, again.marked), (0, 0, 0, 0));
    assert!(again.items.iter().all(|i| i.action == GcAction::Keep), "{:#?}", again.items);
}

#[tokio::test]
async fn gc_include_orphans_terminates_own_orphan_never_foreign_never_probes_suspended() {
    let env = Env::new();
    let api = api();
    let n = nine(&env, &api).await;
    // A young orphan stays: younger than AGE.
    let young = run_direct(&api, &owner(), &created_at(-50)).await.id;
    api.advance_all();
    let mark = api.calls().len();
    let opts = GcOpts { yes: true, include_orphans: Some(Duration::from_secs(3600)), probe_health: true };
    let report = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &opts).await.unwrap();
    let calls = api.calls()[mark..].to_vec();
    assert_eq!(terminated(&calls), [n.expired.clone(), n.orphan.clone()].into_iter().collect());
    let orphan = report.items.iter().find(|i| i.id.as_deref() == Some(n.orphan.as_str())).unwrap();
    assert_eq!((orphan.class, orphan.action), (GcClass::OrphanMine, GcAction::Terminate));
    let young = report.items.iter().find(|i| i.id.as_deref() == Some(young.as_str())).unwrap();
    assert_eq!((young.class, young.action), (GcClass::OrphanMine, GcAction::Keep));
    let foreign = report.items.iter().find(|i| i.id.as_deref() == Some(n.foreign.as_str())).unwrap();
    assert_eq!((foreign.class, foreign.action), (GcClass::Foreign, GcAction::Keep));
    assert_eq!(api.state().vms[&n.foreign].state, VmState::Running);
    never_probed(&api, &calls, &n.suspended);
    assert_eq!(api.state().vms[&n.suspended].state, VmState::Suspended, "never resumed");
    let by: Vec<(String, String)> = env.events("vm_terminate").iter().map(|r| (r["detail"]["id"].as_str().unwrap().to_string(), r["detail"]["by"].as_str().unwrap().to_string())).collect();
    assert!(by.contains(&(n.orphan.clone(), "gc-orphan".to_string())), "{by:?}");
    assert!(by.contains(&(n.expired.clone(), "gc-expired".to_string())), "{by:?}");
}

#[tokio::test]
async fn gc_adopts_a_crashed_pending_row() {
    let env = Env::new();
    let api = api();
    let ambiguous = || BridgeError::Ambiguous { op: "run_microvm", message: "response timed out".into() };
    api.fail_on("run", ambiguous(), true);
    api.fail_on("run", ambiguous(), true);
    select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap_err();
    let pending = env.rows().into_iter().find(VmRow::is_pending_row).expect("kept for gc");
    api.advance_all();
    let dry = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &PROBE).await.unwrap();
    let item = dry.items.iter().find(|i| i.class == GcClass::Adopt).expect("adopt class");
    assert_eq!(item.stem.as_deref(), Some(pending.stem().as_str()));
    let id = item.id.clone().unwrap();
    assert!(env.paths.vms().join(format!("{}.toml", pending.stem())).exists(), "the dry run did not adopt");
    let report = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &YES).await.unwrap();
    assert_eq!(report.adopted, 1);
    assert!(!env.paths.vms().join(format!("{}.toml", pending.stem())).exists());
    let row = env.row(&id);
    assert_eq!(row.status, RowStatus::Running);
    assert_eq!((row.client_token.as_str(), row.created.as_str(), row.commit.as_str()), (pending.client_token.as_str(), pending.created.as_str(), pending.commit.as_str()));
    assert_eq!(row.session_token, pending.session_token);
    assert_eq!(row.slug, pending.slug, "the workspace carries over, so the VM is reusable");
    assert!(row.endpoint.is_some() && row.wall_deadline.is_some() && row.started_at.is_some());
    let adopt = env.events("vm_adopt");
    assert_eq!(adopt.len(), 1);
    assert_eq!((adopt[0]["detail"]["id"].as_str(), adopt[0]["detail"]["via"].as_str()), (Some(id.as_str()), Some("gc")));
    match select_vm(&api, &env.paths, &env.plan(&env.flags()), fast()).await.unwrap() {
        Selected::Reused { row, .. } => assert_eq!(row.id, id),
        other => panic!("the adopted VM serves its workspace: {other:?}"),
    }
}

#[tokio::test]
async fn gc_clears_stale_pending_rows_only_with_yes() {
    let env = Env::new();
    let api = api();
    let stale = env.pending_row(&owner(), &created_at(-1_200_000), 3600);
    let fresh = env.pending_row(&owner(), &created_at(0), 3600);
    let over_max = env.pending_row(&owner(), &created_at(-120_000), 60);
    // Ten minutes old, but a SUSPENDED row-less VM started right after it could be its VM.
    let waiting = env.pending_row(&owner(), &created_at(-600_000), 3600);
    let maybe = run_direct(&api, FOREIGN, &created_at(-590_000)).await.id;
    api.advance_all();
    api.set_state(&maybe, VmState::Suspended);
    started_ago(&api, &maybe, 590);
    let file = |r: &VmRow| env.paths.vms().join(format!("{}.toml", r.stem()));
    let dry = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &PROBE).await.unwrap();
    let stale_items: BTreeSet<String> = dry.items.iter().filter(|i| i.class == GcClass::PendingStale).map(|i| i.stem.clone().unwrap()).collect();
    assert_eq!(stale_items, [stale.stem(), over_max.stem()].into_iter().collect());
    let over = dry.items.iter().find(|i| i.stem.as_deref() == Some(over_max.stem().as_str())).unwrap();
    assert!(over.detail.contains("max duration"), "{}", over.detail);
    for r in [&stale, &fresh, &over_max, &waiting] {
        assert!(file(r).exists(), "the dry run kept {}", r.stem());
    }
    let report = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &YES).await.unwrap();
    assert_eq!(report.removed, 2);
    assert!(!file(&stale).exists() && !file(&over_max).exists());
    assert!(file(&fresh).exists() && file(&waiting).exists());
}

#[tokio::test]
async fn gc_never_trusts_a_health_answer_for_another_vm() {
    let env = Env::new();
    let api = api();
    // A crashed run: its pending row, and a row-less VM whose endpoint answers
    // with the pending row's owner + created but for another microvm_id.
    let created = created_at(-10);
    let pending = env.pending_row(&owner(), &created, 3600);
    let misrouted = run_direct(&api, &owner(), &created).await.id;
    // Own-looking row-less VMs, old enough for --include-orphans: one answering for another id, one without an id.
    let other_id = run_direct(&api, &owner(), &created_at(-20)).await.id;
    let anonymous = run_direct(&api, &owner(), &created_at(-30)).await.id;
    api.advance_all();
    for id in [&misrouted, &other_id, &anonymous] {
        started_ago(&api, id, 7200);
    }
    api.set_health(&misrouted, health_claiming(Some("microvm-someone-else"), &owner(), &created));
    api.set_health(&other_id, health_claiming(Some(&misrouted), &owner(), &created_at(-20)));
    api.set_health(&anonymous, health_claiming(None, &owner(), &created_at(-30)));
    let suspects: BTreeSet<String> = [misrouted.clone(), other_id.clone(), anonymous.clone()].into_iter().collect();
    let dry = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &PROBE).await.unwrap();
    let got = by_class(&dry.items);
    assert!(!got.contains_key("adopt") && !got.contains_key("orphan:mine"), "{got:?}");
    assert_eq!(got["unprobed"].iter().cloned().collect::<BTreeSet<_>>(), suspects, "a /health answer for another id counts as failed");
    let opts = GcOpts { yes: true, include_orphans: Some(Duration::from_secs(60)), probe_health: true };
    let mark = api.calls().len();
    let report = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &opts).await.unwrap();
    assert_eq!((report.terminated, report.adopted), (0, 0), "{:#?}", report.items);
    assert!(terminated(&api.calls()[mark..]).is_empty());
    assert!(env.paths.vms().join(format!("{}.toml", pending.stem())).exists(), "the pending row was not given to the misrouted VM");
    assert!(registry::read_row(&env.paths, &misrouted).unwrap().is_none());
    let plan = terminate_all_plan(&api, &api, &env.paths, FAKE_IMAGE_ARN).await.unwrap();
    for item in plan.iter().filter(|i| i.id.as_ref().is_some_and(|id| suspects.contains(id))) {
        assert_eq!((item.class, item.action), (GcClass::Unprobed, GcAction::Keep), "{item:?}");
    }
}

#[tokio::test]
async fn reconcile_local_never_probes_and_writes_nothing() {
    let env = Env::new();
    let api = api();
    let n = nine(&env, &api).await;
    let before = snapshot(&env.paths.root);
    let mark = api.calls().len();
    let items = reconcile_local(&api, &env.paths, FAKE_IMAGE_ARN).await.unwrap();
    assert_eq!(snapshot(&env.paths.root), before);
    let calls = api.calls()[mark..].to_vec();
    assert!(!calls.iter().any(|c| matches!(c, Call::Token { .. } | Call::Health { .. })), "{calls:?}");
    assert!(items.iter().all(|i| i.action == GcAction::Report));
    let got = by_class(&items);
    assert_eq!(only(&got, "registry:expired"), n.expired);
    assert_eq!(got["unprobed"].len(), 4, "without probes every row-less VM is unprobed: {got:?}");
    assert!(!got.contains_key("adopt") && !got.contains_key("orphan:mine"));
    let hint = hint_line(&items).unwrap();
    assert!(hint.contains("1 registry:expired") && hint.contains("ai-env vm gc"), "{hint}");
}

/// Every public future of `vm::gc` and `vm::run` can be spawned (checked at compile time; never polled).
#[test]
fn gc_and_run_futures_are_send() {
    fn send<T: Send>(_: T) {}
    let env = Env::new();
    let api = api();
    send(gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &YES));
    send(reconcile_local(&api, &env.paths, FAKE_IMAGE_ARN));
    send(terminate_all_plan(&api, &api, &env.paths, FAKE_IMAGE_ARN));
    let pending = VmRow::default();
    send(ai_env_cli::bridge::vm::run::adopt_after_ambiguous(&api, &api, &env.paths, &pending, 0, fast()));
    let plan = env.plan(&env.flags());
    send(ai_env_cli::bridge::vm::run::select_vm(&api, &env.paths, &plan, fast()));
    send(ai_env_cli::bridge::vm::run::select_vm_detailed(&api, &env.paths, &plan, fast()));
    send(ai_env_cli::bridge::vm::run::terminate_and_record(&api, &env.paths, "microvm-x", "test", None));
    send(ai_env_cli::bridge::vm::run::wait_for_state(&api, "microvm-x", &VmState::Running, fast()));
    send(ai_env_cli::bridge::vm::run::resolve_image_version(&api, FAKE_IMAGE_ARN, "active"));
}

#[tokio::test]
async fn terminate_all_skips_foreign_owners() {
    let env = Env::new();
    let api = api();
    let n = nine(&env, &api).await;
    let before = snapshot(&env.paths.root);
    let items = terminate_all_plan(&api, &api, &env.paths, FAKE_IMAGE_ARN).await.unwrap();
    assert_eq!(snapshot(&env.paths.root), before, "a plan writes nothing");
    let act = |a: GcAction| items.iter().filter(|i| i.action == a).map(|i| i.id.clone().unwrap()).collect::<BTreeSet<_>>();
    assert_eq!(act(GcAction::Terminate), [n.live.clone(), n.expired.clone(), n.orphan.clone(), n.adopt_vm.clone()].into_iter().collect());
    assert_eq!(act(GcAction::Keep), [n.foreign.clone(), n.suspended.clone()].into_iter().collect());
    assert!(terminated(&api.calls()).is_empty());
}

#[tokio::test]
async fn gc_treats_a_health_without_owner_or_created_as_unprobed() {
    // The run hook has not reached the shim yet: /health answers for the VM's own id, without owner or created.
    let env = Env::new();
    let api = api();
    // A ten-minute-old pending row, and the VM of that run (started 10 s after it), whose shim knows no owner yet.
    let created = created_at(-600_000);
    let pending = env.pending_row(&owner(), &created, 3600);
    let booting = run_direct(&api, &owner(), &created).await.id;
    // An own-looking VM that knows its owner but no created, old enough for --include-orphans.
    let half = run_direct(&api, &owner(), &created_at(-20)).await.id;
    api.advance_all();
    started_ago(&api, &booting, 590);
    started_ago(&api, &half, 7200);
    api.set_health(&booting, ai_env_cli::wire::frame::Health { owner: None, created: None, ..health_claiming(Some(&booting), "x", "y") });
    api.set_health(&half, ai_env_cli::wire::frame::Health { created: None, ..health_claiming(Some(&half), &owner(), "y") });
    let dry = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &PROBE).await.unwrap();
    let got = by_class(&dry.items);
    assert_eq!(got.get("unprobed").cloned().unwrap_or_default().into_iter().collect::<BTreeSet<_>>(), [booting.clone(), half.clone()].into_iter().collect(), "{got:?}");
    assert!(!got.contains_key("foreign") && !got.contains_key("orphan:mine"), "{got:?}");
    assert!(!got.contains_key("pending:stale"), "its VM may be the unprobed one: {got:?}");
    let item = dry.items.iter().find(|i| i.id.as_deref() == Some(booting.as_str())).unwrap();
    assert!(item.detail.contains("run hook not delivered"), "{}", item.detail);
    let mark = api.calls().len();
    let opts = GcOpts { yes: true, include_orphans: Some(Duration::from_secs(60)), probe_health: true };
    let report = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &opts).await.unwrap();
    assert_eq!((report.terminated, report.removed, report.adopted), (0, 0, 0), "{:#?}", report.items);
    assert!(terminated(&api.calls()[mark..]).is_empty(), "never terminated");
    assert!(env.paths.vms().join(format!("{}.toml", pending.stem())).exists(), "the pending row stays");
    // Once the hook arrives, the same VM is adopted.
    api.state().health_override.remove(&booting);
    let report = gc(&api, &api, &env.paths, FAKE_IMAGE_ARN, &YES).await.unwrap();
    assert_eq!(report.adopted, 1, "{:#?}", report.items);
    assert_eq!(env.row(&booting).client_token, pending.client_token);
}

#[tokio::test]
async fn gc_surveys_the_images_of_pending_rows() {
    const OTHER: &str = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:other";
    const DENIED: &str = "arn:aws:lambda:eu-central-1:123456789012:microvm-image:denied";
    let env = Env::new();
    let spy = Spy::new(&env.paths);
    *spy.deny_list_image.lock().unwrap() = Some(DENIED.to_string());
    // A crashed `vm run --image OTHER`, seven minutes ago: its pending row and its VM.
    let created = created_at(-420_000);
    let mut crashed = env.pending_row(&owner(), &created, 3600);
    crashed.image_arn = OTHER.to_string();
    registry::write_pending(&env.paths, &crashed).unwrap();
    let vm = run_direct_image(&spy.inner, OTHER, &owner(), &created).await.id;
    spy.inner.advance_all();
    started_ago(&spy.inner, &vm, 410);
    // A ten-minute-old pending row of an image the runtime policy will not list.
    let mut blind = env.pending_row(&owner(), &created_at(-600_000), 3600);
    blind.image_arn = DENIED.to_string();
    registry::write_pending(&env.paths, &blind).unwrap();
    let dry = gc(&spy, &spy, &env.paths, FAKE_IMAGE_ARN, &PROBE).await.unwrap();
    let calls = spy.inner.calls();
    for image in [FAKE_IMAGE_ARN, OTHER] {
        assert!(calls.contains(&Call::List(Some(image.to_string()))), "{image} listed: {calls:?}");
    }
    let adopt = dry.items.iter().find(|i| i.class == GcClass::Adopt).unwrap_or_else(|| panic!("the other image's VM is adoptable: {:#?}", dry.items));
    assert_eq!((adopt.id.as_deref(), adopt.stem.as_deref()), (Some(vm.as_str()), Some(crashed.stem().as_str())));
    let unlisted = dry.items.iter().find(|i| i.stem.as_deref() == Some(blind.stem().as_str())).expect("reported");
    assert_eq!(unlisted.class, GcClass::Unprobed, "never pending:stale when its image was not surveyed: {unlisted:?}");
    assert!(unlisted.detail.contains(DENIED) && unlisted.detail.contains("could not be listed"), "{}", unlisted.detail);
    let report = gc(&spy, &spy, &env.paths, FAKE_IMAGE_ARN, &YES).await.unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert_eq!((report.adopted, report.removed), (1, 0));
    assert_eq!(env.row(&vm).image_arn, OTHER);
    assert!(env.paths.vms().join(format!("{}.toml", blind.stem())).exists(), "kept");
    let plan = terminate_all_plan(&spy, &spy, &env.paths, FAKE_IMAGE_ARN).await.unwrap();
    assert!(plan.iter().all(|i| i.id.is_some()), "rows without a VM are not in the terminate --all plan: {plan:?}");
}
