//! tests/workspace.rs area: D3's decision as a pure function (plan §5): what
//! a seed does with each state `GET /seed` can answer.
use ai_env_cli::bridge::workspace::{decide, kept_note, Ancestry, Decision, KeptReason, MacSeed, SeedWant};
use ai_env_cli::wire::workspace::{refusal, ObjectFormat, SeedMode, SeedRecord, SeedState};

const S: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const T: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const M: &str = "cccccccccccccccccccccccccccccccccccccccc";
const WT: &str = "dddddddddddddddddddddddddddddddddddddddd";
const IT: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn record(path: &str, head: &str, wip_tree: Option<&str>) -> SeedRecord {
    SeedRecord { path: path.into(), mode: SeedMode::Clone, branch: Some("main".into()), head: head.into(), wip: None, wip_tree: wip_tree.map(str::to_string), index_tree: None, object_format: ObjectFormat::Sha1, at: "2026-10-12T08:00:00Z".into() }
}

fn state(rec: Option<SeedRecord>, tip: &str, clean: bool, pristine: bool) -> SeedState {
    SeedState { record: rec, tip: Some(tip.into()), branch: Some("main".into()), clean, pristine, shallow: None }
}

fn mac<'a>(head: &'a str, wip_tree: Option<&'static str>) -> MacSeed<'a> {
    MacSeed { vm_root: "/w", head, branch: Some("main"), wip_tree, index_tree: None }
}

const ANCESTOR: Ancestry = Ancestry { tip_known: true, tip_in_head: true, head_in_tip: false, seeded_known: true };

#[test]
fn d3_decides_each_state() {
    let auto = SeedWant::Auto;
    // Never seeded: a first seed.
    assert_eq!(decide(&SeedState::default(), &mac(M, None), &Ancestry::default(), auto), Decision::Clone);
    // Seeded at another path: refused (one workspace per VM).
    let other = decide(&state(Some(record("/other", S, None)), S, true, true), &mac(M, None), &ANCESTOR, auto);
    assert!(matches!(&other, Decision::Refuse { code, message } if *code == refusal::OTHER_WORKSPACE && message.contains("/other")), "{other:?}");
    // The same head and WIP trees: up to date, whatever the VM did since.
    assert_eq!(decide(&state(Some(record("/w", S, Some(WT))), S, false, false), &mac(S, Some(WT)), &ANCESTOR, auto), Decision::UpToDate);
    // A clean VM whose tip is an ancestor of the Mac's head: an update.
    assert_eq!(decide(&state(Some(record("/w", S, None)), T, true, false), &mac(M, None), &ANCESTOR, auto), Decision::Update { tip: T.into(), seeded: S.into() });
    // The same commit, only a new WIP on the Mac: an update of a clean VM too.
    assert_eq!(decide(&state(Some(record("/w", S, None)), S, true, true), &mac(S, Some(WT)), &ANCESTOR, auto), Decision::Update { tip: S.into(), seeded: S.into() });
    // A clean VM at the Mac's head with nothing uncommitted on the Mac: nothing to send.
    assert_eq!(decide(&state(Some(record("/w", S, None)), M, true, false), &mac(M, None), &ANCESTOR, auto), Decision::UpToDate);
    // A VM seeded dirty is dirty: kept (D2 with D3).
    assert_eq!(decide(&state(Some(record("/w", S, Some(WT))), S, false, true), &mac(M, None), &ANCESTOR, auto), Decision::Kept(KeptReason::Dirty));
    // Ahead: the Mac's head is an ancestor of the VM's tip, or the Mac lacks the tip (an agent's commit).
    let ahead = Ancestry { tip_in_head: false, head_in_tip: true, ..ANCESTOR };
    assert_eq!(decide(&state(Some(record("/w", S, None)), T, true, false), &mac(M, None), &ahead, auto), Decision::Kept(KeptReason::Ahead));
    let unknown = Ancestry { tip_known: false, ..Ancestry::default() };
    assert_eq!(decide(&state(Some(record("/w", S, None)), T, true, false), &mac(M, None), &unknown, auto), Decision::Kept(KeptReason::Ahead));
    // Diverged: neither is an ancestor; another branch checked out; the seeded commit unknown to the Mac.
    let apart = Ancestry { tip_in_head: false, head_in_tip: false, ..ANCESTOR };
    assert_eq!(decide(&state(Some(record("/w", S, None)), T, true, false), &mac(M, None), &apart, auto), Decision::Kept(KeptReason::Diverged));
    let mut on_other = state(Some(record("/w", S, None)), T, true, false);
    on_other.branch = Some("feature".into());
    assert_eq!(decide(&on_other, &mac(M, None), &ANCESTOR, auto), Decision::Kept(KeptReason::Diverged));
    assert_eq!(decide(&state(Some(record("/w", S, None)), T, true, false), &mac(M, None), &Ancestry { seeded_known: false, ..ANCESTOR }, auto), Decision::Kept(KeptReason::Diverged));
    assert_eq!(kept_note(KeptReason::Diverged), "the VM keeps its state (diverged): ai-env box fetch shows what changed");
}

/// `box seed --replace`: only a pristine VM (409 `not_pristine` otherwise,
/// decided before anything is sent); a never-seeded VM gets a first seed.
#[test]
fn replace_takes_only_a_pristine_vm() {
    let replace = SeedWant::Replace;
    assert_eq!(decide(&SeedState::default(), &mac(M, None), &Ancestry::default(), replace), Decision::Clone);
    assert_eq!(decide(&state(Some(record("/w", S, Some(WT))), S, false, true), &mac(M, None), &Ancestry::default(), replace), Decision::Replace { tip: S.into() });
    let changed = decide(&state(Some(record("/w", S, Some(WT))), T, false, false), &mac(M, None), &ANCESTOR, replace);
    assert!(matches!(&changed, Decision::Refuse { code, .. } if *code == refusal::NOT_PRISTINE), "{changed:?}");
    assert_eq!(decide(&state(Some(record("/w", S, Some(WT))), S, false, true), &mac(S, Some(WT)), &ANCESTOR, replace), Decision::UpToDate);
    let mut idx = mac(S, Some(WT));
    idx.index_tree = Some(IT);
    assert_eq!(decide(&state(Some(record("/w", S, Some(WT))), S, false, true), &idx, &ANCESTOR, replace), Decision::Replace { tip: S.into() }, "another staged tree is another seed");
}
