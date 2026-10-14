//! tests/workspace.rs area: `ensure_workspace`'s races and bounds (plan §5,
//! §10): a 409 `changed` reads the VM's state once more and decides again
//! (a second is the refusal, exit 9); a VM that turned dirty between the
//! read and the write keeps its state; a VM seeded at another path is
//! refused before anything is sent; the wrapper's deadline and its inline
//! cap give `too_slow_for_init` (exit 1) naming `vm warm` and `box seed`,
//! the CLI's cap `too_large` (exit 9).
use super::fixture::{api, caps, ensure_ctx, git, split_body, target, FakeVm, Tokens, World};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::workspace::{code, ensure_workspace, prepare, resolve, EnsureCtx, EnsureOutcome, KeptReason, SeedLimits, SeedProgress, SeedWant};
use ai_env_cli::errors::CliError;
use ai_env_cli::wire::workspace::{refusal, SeedState, WsRefusal};

fn exit(e: BridgeError) -> (i32, String) {
    let text = e.to_string();
    (CliError::from(e).exit_code(), text)
}

#[tokio::test]
async fn a_changed_tip_is_read_again_once_and_a_dirty_write_is_kept() {
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    repo.write("a.txt", "a\n");
    let head = repo.commit("a");
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    // One `changed`: read again, decide again, write again.
    vm.refuse_next.lock().unwrap().push_back(WsRefusal::new(refusal::CHANGED, "the tip moved"));
    let outcome = ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap();
    assert!(matches!(&outcome, EnsureOutcome::Updated { head: h, .. } if *h == head), "{outcome:?}");
    let calls: Vec<String> = vm.calls().into_iter().skip(2).collect();
    assert_eq!(calls, ["GET /seed", "PUT /seed update", "GET /seed", "PUT /seed update"].map(|c| if c.starts_with("GET") { format!("{c} {}", ws.vm_root) } else { c.to_string() }));
    // Two in a row: the refusal, exit 9, audited.
    repo.write("b.txt", "b\n");
    repo.commit("b");
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    for _ in 0..2 {
        vm.refuse_next.lock().unwrap().push_back(WsRefusal::new(refusal::CHANGED, "the tip moved"));
    }
    let (code, text) = exit(ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap_err());
    assert!(code == 9 && text.starts_with("workspace refused (changed)"), "{text}");
    let audit = std::fs::read_to_string(paths.audit()).unwrap();
    assert!(audit.lines().any(|l| l.contains("\"event\":\"seed_refused\"") && l.contains("\"code\":\"changed\"")), "{audit}");
    // The VM turned dirty between the read and the write: kept, its state the refusal's.
    let vm_state = SeedState { tip: Some(git(&vm.dir, &["rev-parse", "HEAD"])), clean: false, ..SeedState::default() };
    vm.refuse_next.lock().unwrap().push_back(WsRefusal::new(refusal::DIRTY, "changes of its own").with_state(vm_state.clone()));
    match ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap() {
        EnsureOutcome::Kept { reason: KeptReason::Dirty, vm_head, .. } => assert_eq!(Some(vm_head), vm_state.tip),
        other => panic!("{other:?}"),
    }
}

/// A 409 `changed` on an update with a shallow boundary (a merge of a branch
/// older than the seeded commit): the plan made again in the same scratch
/// repository sends the same boundary (the first plan's `shallow` file is no
/// graft of the second's walk), and the VM takes it.
#[tokio::test]
async fn a_changed_tip_keeps_the_updates_shallow_boundary() {
    let w = World::new();
    let repo = w.repo("app");
    let fork = repo.head();
    repo.write("main.txt", "main\n");
    repo.commit("main work");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    repo.git(&["checkout", "-q", "-b", "side", &fork]);
    repo.write("side.txt", "side one\n");
    let side1 = repo.commit("side one");
    repo.write("side.txt", "side two\n");
    repo.commit("side two");
    repo.git(&["checkout", "-q", "main"]);
    repo.git(&["merge", "-q", "--no-ff", "--no-edit", "side"]);
    let merge = repo.head();
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    vm.refuse_next.lock().unwrap().push_back(WsRefusal::new(refusal::CHANGED, "the tip moved"));
    let outcome = ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    assert!(matches!(&outcome, EnsureOutcome::Updated { head, .. } if *head == merge), "{outcome:?}");
    let shallow: Vec<Vec<String>> = vm.bodies.lock().unwrap()[1..].iter().map(|b| split_body(b).0.shallow).collect();
    assert_eq!(shallow, [vec![side1.clone()], vec![side1]], "the refused update's boundary, then the same again");
    assert_eq!(git(&vm.dir, &["rev-parse", "HEAD"]), merge);
    git(&vm.dir, &["fsck", "--connectivity-only", "--no-progress"]);
}

/// One workspace per VM: a VM seeded at one path refuses another's seed
/// before any byte of it is sent.
#[tokio::test]
async fn a_vm_seeded_elsewhere_is_refused_before_anything_is_sent() {
    let w = World::new();
    let (one, two) = (w.repo("one"), w.repo("two"));
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws_one = resolve(&cfg, &one.dir, None).unwrap();
    ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws_one, &progress), None, SeedWant::Auto).await.unwrap();
    let ws_two = resolve(&cfg, &two.dir, None).unwrap();
    let (code, text) = exit(ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws_two, &progress), None, SeedWant::Auto).await.unwrap_err());
    assert!(code == 9 && text.starts_with("workspace refused (other_workspace)") && text.contains(&ws_one.vm_root), "{text}");
    assert_eq!(vm.bodies.lock().unwrap().len(), 1, "only the first seed's body was sent");
}

/// The wrapper's bounds: its deadline (T0 + 50 s) passed, or a seed over its
/// inline cap, is `too_slow_for_init` (exit 1) naming `vm warm` and `box
/// seed`; the CLI's cap is `too_large` (exit 9).
#[tokio::test]
async fn the_wrappers_deadline_and_cap_name_vm_warm_and_box_seed() {
    let w = World::new();
    let repo = w.repo("app");
    repo.write("data.txt", &"d".repeat(4096));
    repo.commit("data");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = |lim: SeedLimits, deadline: Option<tokio::time::Instant>| EnsureCtx { api: &api, dp: &vm, tokens: &Tokens, paths: &paths, cfg: &cfg, target: &t, caps: &c, ws: &ws, lim, deadline, progress: &progress };
    let wrapper = SeedLimits::wrapper(&cfg);
    let (code_, text) = exit(ensure_workspace(&ctx(wrapper, Some(tokio::time::Instant::now())), None, SeedWant::Auto).await.unwrap_err());
    assert!(code_ == 1 && text.starts_with(&format!("workspace failed ({})", code::TOO_SLOW_FOR_INIT)) && text.contains("ai-env vm warm") && text.contains("ai-env box seed"), "{text}");
    let tiny = SeedLimits { max_bytes: 64, ..wrapper };
    let later = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
    let (code_, text) = exit(ensure_workspace(&ctx(tiny, later), None, SeedWant::Auto).await.unwrap_err());
    assert!(code_ == 1 && text.contains("[seed].wrapper_inline_mib") && text.contains(&format!("ai-env box seed {}", ws.cwd.display())), "{text}");
    let (code_, text) = exit(ensure_workspace(&ctx(tiny, None), None, SeedWant::Auto).await.unwrap_err());
    assert!(code_ == 9 && text.starts_with("workspace refused (too_large)") && text.contains("box seed --max-mib"), "{text}");
    assert!(vm.bodies.lock().unwrap().is_empty(), "nothing was sent");
    assert!(matches!(ensure_workspace(&ctx(wrapper, later), None, SeedWant::Auto).await.unwrap(), EnsureOutcome::Seeded { .. }), "within the bounds it goes");
}

// ---- phase 4 F9: the seed's scratch on every path ----

/// No scratch outlives `ensure_workspace`'s failures past the WIP snapshot
/// (T8.1 as D7 built it; the rig's
/// `e2e::a_failed_seed_leaves_no_scratch_on_either_side` fails the git on
/// either side and the endpoint): a body the VM refused after it went
/// (`git_failed`, its 500: exit 1); a body over the wrapper's inline cap
/// (exit 1) or the CLI's cap (exit 9); and, in a world of its own, a body
/// built past what the wrapper's deadline leaves (exit 1: it "does not fit
/// Cursor's 60 s window"). That seed is prepared first, then given 1 s:
/// `GET /seed` of a VM never seeded answers at once, and its 8 MiB, which
/// do not compress, need about 2.1 s at `SEED_RATE` however long the
/// packing took. Only the first body is sent. After each, `state/tmp`
/// holds nothing and is 0700.
#[tokio::test]
async fn a_seed_that_fails_after_its_body_was_built_leaves_no_scratch() {
    use std::os::unix::fs::PermissionsExt as _;
    let w = World::new();
    let repo = w.repo("app");
    repo.write("data.txt", &"d".repeat(4096));
    repo.commit("data");
    repo.write("notes.txt", "uncommitted\n");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = |lim: SeedLimits, deadline: Option<tokio::time::Instant>| EnsureCtx { api: &api, dp: &vm, tokens: &Tokens, paths: &paths, cfg: &cfg, target: &t, caps: &c, ws: &ws, lim, deadline, progress: &progress };
    let left = |tmp: &std::path::Path, what: &str| {
        let names: Vec<String> = std::fs::read_dir(tmp).map(|d| d.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
        assert!(names.is_empty(), "{what}: scratch left in state/tmp: {names:?}");
        assert_eq!(std::fs::metadata(tmp).map(|m| m.permissions().mode() & 0o777).ok(), Some(0o700), "{what}: state/tmp");
    };
    vm.refuse_next.lock().unwrap().push_back(WsRefusal::new(refusal::GIT_FAILED, "git index-pack failed"));
    let (code_, text) = exit(ensure_workspace(&ctx(SeedLimits::cli(&cfg, None), None), None, SeedWant::Auto).await.unwrap_err());
    assert!(code_ == 1 && text.contains(refusal::GIT_FAILED), "{text}");
    assert_eq!(vm.bodies.lock().unwrap().len(), 1, "the body went");
    left(&paths.tmp(), "refused after it went");
    let wrapper = SeedLimits::wrapper(&cfg);
    let later = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
    for (what, lim, deadline, want) in [
        ("over the wrapper's inline cap", SeedLimits { max_bytes: 64, ..wrapper }, later, 1),
        ("over the CLI's cap", SeedLimits { max_bytes: 64, ..wrapper }, None, 9),
    ] {
        let (code_, text) = exit(ensure_workspace(&ctx(lim, deadline), None, SeedWant::Auto).await.unwrap_err());
        assert_eq!(code_, want, "{what}: {text}");
        left(&paths.tmp(), what);
    }
    assert_eq!(vm.bodies.lock().unwrap().len(), 1, "nothing more was sent");
    // The wrapper's deadline once the body was built: the refusal after the body, never `GET /seed`'s.
    {
        let w = World::new();
        let repo = w.repo("big");
        // Bytes zlib cannot shrink (a xorshift stream), so the pack is as large as the file: 8 MiB.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let noise: Vec<u8> = (0..(8 << 20) / 8)
            .flat_map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()
            })
            .collect();
        repo.write_bytes("noise.bin", &noise);
        repo.commit("noise");
        repo.write("notes.txt", "uncommitted\n");
        let (paths, cfg) = (w.paths(), w.cfg(""));
        let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
        let ws = resolve(&cfg, &repo.dir, None).unwrap();
        let wrapper = SeedLimits::wrapper(&cfg);
        let prepared = prepare(&paths, &cfg, &ws, &wrapper).unwrap();
        let deadline = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
        let ctx = EnsureCtx { api: &api, dp: &vm, tokens: &Tokens, paths: &paths, cfg: &cfg, target: &t, caps: &c, ws: &ws, lim: wrapper, deadline, progress: &progress };
        let (code_, text) = exit(ensure_workspace(&ctx, Some(prepared), SeedWant::Auto).await.unwrap_err());
        assert!(code_ == 1 && text.starts_with(&format!("workspace failed ({})", code::TOO_SLOW_FOR_INIT)) && text.contains("does not fit Cursor's 60 s window") && text.contains(&format!("ai-env box seed {}", ws.cwd.display())), "{text}");
        assert_eq!(vm.calls(), [format!("GET /seed {}", ws.vm_root)], "the state was read, the body never sent");
        assert!(vm.bodies.lock().unwrap().is_empty(), "nothing was sent");
        left(&paths.tmp(), "past the wrapper's deadline once the body was built");
    }
}

// ---- phase 4 L1: a VM tip the Mac never had ----

/// D3 once the agent committed in the VM and no code-out brought that
/// commit to the Mac: a tip the Mac lacks is not known, never a git
/// failure (`git cat-file -e ID^{commit}` exits 128 for an object git
/// lacks). With the Mac's head the one seeded, the VM is up to date; once
/// the Mac moved on, the VM is kept `ahead`; `--replace` is refused
/// `not_pristine` (exit 9); the agent on a branch of its own is kept
/// `diverged`. Only the first seed is ever sent, and the agent's commits stay.
#[tokio::test]
async fn a_vm_tip_the_mac_never_had_is_kept_never_a_git_failure() {
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    // The agent's commit, in the VM only.
    std::fs::write(vm.dir.join("agent.txt"), "the agent's work\n").unwrap();
    git(&vm.dir, &["add", "agent.txt"]);
    git(&vm.dir, &["commit", "-q", "-m", "the agent's commit"]);
    let agent = git(&vm.dir, &["rev-parse", "HEAD"]);
    assert!(!super::fixture::git_ok(&repo.dir, &["cat-file", "-e", &agent]), "the Mac lacks the VM's tip");
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    let same = ensure_workspace(&ctx, None, SeedWant::Auto).await;
    assert!(matches!(&same, Ok(EnsureOutcome::UpToDate { head }) if *head == repo.head()), "the Mac's head the one seeded: {same:?}");
    repo.write("mac.txt", "the Mac's work\n");
    repo.commit("the Mac's commit");
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    match ensure_workspace(&ctx, None, SeedWant::Auto).await {
        Ok(EnsureOutcome::Kept { reason: KeptReason::Ahead, vm_head, note }) => {
            assert_eq!(vm_head, agent);
            assert_eq!(note, "the VM keeps its state (ahead): ai-env box fetch shows what changed");
        }
        other => panic!("the Mac moved on: {other:?}"),
    }
    let (code_, text) = exit(ensure_workspace(&ctx, None, SeedWant::Replace).await.unwrap_err());
    assert!(code_ == 9 && text.starts_with("workspace refused (not_pristine)"), "--replace: {text}");
    git(&vm.dir, &["checkout", "-q", "-b", "agent"]);
    std::fs::write(vm.dir.join("agent.txt"), "more of the agent's work\n").unwrap();
    git(&vm.dir, &["commit", "-q", "-am", "the agent's branch"]);
    let branch_tip = git(&vm.dir, &["rev-parse", "HEAD"]);
    match ensure_workspace(&ctx, None, SeedWant::Auto).await {
        Ok(EnsureOutcome::Kept { reason: KeptReason::Diverged, vm_head, .. }) => assert_eq!(vm_head, branch_tip),
        other => panic!("the agent's own branch: {other:?}"),
    }
    assert_eq!(vm.calls().iter().filter(|c| c.starts_with("PUT")).count(), 1, "only the first seed was sent: {:?}", vm.calls());
    assert_eq!(git(&vm.dir, &["rev-parse", "HEAD"]), branch_tip, "the agent's commits stay");
    let row = ai_env_cli::bridge::workspace::rows::row_of(&paths, &ws).unwrap().expect("a workspace row");
    assert_eq!(row.vm.get(super::fixture::VM).and_then(|v| v.kept.clone()).as_deref(), Some("diverged"));
}
