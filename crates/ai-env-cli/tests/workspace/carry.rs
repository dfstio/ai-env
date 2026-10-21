//! S10 (L7): a move's or a reopen's carry seed from the dead VM's fetch
//! record (`workspace::carry_source`, `SeedWant::Carry`), and the record
//! `codeout::record_fetch` keeps per VM (plans/s10-contracts.md §6.3).
//! Declared in S10 phase 0; S10 wave 1b (C) writes the tests. The record is
//! written here as the code-out leaves it (C2 writes it there): the dead VM's
//! commits and its `refs/wip/*` snapshot promoted into the user's store, ids
//! only, no ref.
use super::fixture::{api, caps, ensure_ctx, git, git_cmd, git_out, target, FakeVm, Repo, World};
use ai_env_cli::bridge::config::Paths;
use ai_env_cli::bridge::workspace::rows::{self, VmFetchRow};
use ai_env_cli::bridge::workspace::{carry_source, ensure_workspace, prepare, prepare_from_box, resolve, CarrySource, EnsureOutcome, SeedLimits, SeedProgress, SeedWant, WorkspaceRef};
use ai_env_cli::errors::CliError;
use std::time::Duration;

/// The dead VM, whose last fetch the record keeps.
const DEAD: &str = "microvm-00000000-0000-4000-8000-0000000000d1";
/// Its snapshot's ref in the VM (for the logs only).
const WIP_REF: &str = "refs/wip/20261020T080000Z-1";

/// The dead VM's work on `repo`'s HEAD, made in a clone as its agent makes
/// it: a commit (`src/lib.rs`), then uncommitted `staged.txt` staged,
/// `README.md` changed in the worktree only and `untracked.txt` new; its
/// snapshot as the VM's helper makes one (its tree the worktree, its parents
/// the head and the index commit). Every object fetched into `repo`'s store
/// as the code-out promotes them, no ref left there. The head, the snapshot,
/// the index's tree and the worktree's.
fn vm_work(w: &World, repo: &Repo) -> (String, String, String, String) {
    let dir = w.root.join("dead-vm");
    git(&w.root, &["clone", "-q", &repo.dir.display().to_string(), &dir.display().to_string()]);
    let vm = Repo { dir: dir.clone() };
    vm.write("src/lib.rs", "pub fn f() {}\n");
    let head = vm.commit("the agent's commit");
    vm.write("staged.txt", "staged\n");
    vm.git(&["add", "staged.txt"]);
    vm.write("README.md", "changed in the worktree\n");
    vm.write("untracked.txt", "new\n");
    let index_tree = vm.git(&["write-tree"]);
    let index = vm.git(&["commit-tree", &index_tree, "-p", &head, "-m", "index"]);
    // The worktree's tree, through a throwaway copy of the index.
    let idx = dir.join(".git").join("snapshot.index");
    std::fs::copy(dir.join(".git").join("index"), &idx).unwrap();
    let mut add = git_cmd(&dir);
    assert!(add.env("GIT_INDEX_FILE", &idx).args(["add", "-A"]).status().unwrap().success());
    let mut write = git_cmd(&dir);
    let o = write.env("GIT_INDEX_FILE", &idx).args(["write-tree"]).output().unwrap();
    assert!(o.status.success());
    let tree = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let wip = vm.git(&["commit-tree", &tree, "-p", &head, "-p", &index, "-m", "wip"]);
    vm.git(&["update-ref", WIP_REF, &wip]);
    repo.git(&["fetch", "-q", "--no-write-fetch-head", &dir.display().to_string(), WIP_REF]);
    (head, wip, index_tree, tree)
}

/// A fetch record of `head` (on `main`) and `wip`.
fn fetched(head: &str, wip: Option<&str>) -> VmFetchRow {
    VmFetchRow { at: 1_792_000_000, head: head.into(), branch: Some("main".into()), wip: wip.map(str::to_string), wip_ref: wip.map(|_| WIP_REF.to_string()) }
}

/// `vm`'s record in `ws`'s row (`None`: no record).
fn record(paths: &Paths, ws: &WorkspaceRef, vm: &str, f: Option<VmFetchRow>) {
    rows::update(paths, ws, |row| row.vm.entry(vm.to_string()).or_default().fetched = f).unwrap();
}

/// The Mac's source and its note; panics on the box's.
fn mac_note(source: CarrySource) -> Option<String> {
    match source {
        CarrySource::Mac { note } => note,
        other => panic!("not this Mac's seed: {other:?}"),
    }
}

/// The box's record and note; panics on the Mac's.
fn box_of(source: CarrySource) -> (VmFetchRow, Option<String>) {
    match source {
        CarrySource::Box { record, note } => (record, note),
        other => panic!("not the dead VM's seed: {other:?}"),
    }
}

/// A move's carry seed off a VM whose last fetch promoted a commit and a
/// two-parent snapshot: the box's source, prepared from the user's store
/// alone, and a never-seeded VM cloned at the dead VM's head on its branch,
/// its work left uncommitted as it was there (the index the snapshot's
/// second parent's, the worktree its tree: a staged file staged, a changed
/// file changed, an untracked one untracked); the user's repository
/// untouched; the `seed` row naming the source.
#[tokio::test]
async fn carry_applies_a_two_parent_vm_snapshot_uncommitted() {
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let (head, wip, index_tree, tree) = vm_work(&w, &repo);
    let before = repo.state();
    record(&paths, &ws, DEAD, Some(fetched(&head, Some(&wip))));
    let (rec, note) = box_of(carry_source(&paths, &ws, DEAD));
    assert_eq!((rec.head.as_str(), rec.wip.as_deref(), note), (head.as_str(), Some(wip.as_str()), None), "the Mac's HEAD is the record's ancestor: no note");
    let prepared = prepare_from_box(&paths, &cfg, &ws, &SeedLimits::wrapper(&cfg), &rec).unwrap();
    assert_eq!(prepared.source(), "box");
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let outcome = ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress), Some(prepared), SeedWant::Carry).await.unwrap();
    assert!(matches!(&outcome, EnsureOutcome::Seeded { head: h, wip: Some(s), .. } if *h == head && *s == wip), "{outcome:?}");
    assert_eq!(vm.calls().iter().filter(|c| c.starts_with("PUT /seed")).cloned().collect::<Vec<_>>(), ["PUT /seed clone"]);
    assert_eq!((git(&vm.dir, &["rev-parse", "HEAD"]), git(&vm.dir, &["symbolic-ref", "--short", "HEAD"])), (head.clone(), "main".to_string()));
    assert_eq!(git(&vm.dir, &["write-tree"]), index_tree, "the index: the snapshot's second parent's tree");
    assert_eq!(vm.worktree_tree(), tree, "the worktree: the snapshot's tree");
    // Read untrimmed: a line's first column may be a space.
    let status = String::from_utf8_lossy(&git_out(&vm.dir, &["status", "--porcelain", "--untracked-files=all"], None).stdout).into_owned();
    let mut lines: Vec<&str> = status.lines().collect();
    lines.sort_unstable();
    assert_eq!(lines, [" M README.md", "?? untracked.txt", "A  staged.txt"], "uncommitted, as on the dead VM");
    assert_eq!(git(&vm.dir, &["show", "HEAD:src/lib.rs"]), "pub fn f() {}", "the dead VM's commit");
    let seeded = vm.record().expect("the VM's seed record");
    assert_eq!((seeded.head.as_str(), seeded.wip.as_deref(), seeded.wip_tree.as_deref(), seeded.index_tree.as_deref()), (head.as_str(), Some(wip.as_str()), Some(tree.as_str()), Some(index_tree.as_str())));
    assert_eq!(repo.state(), before, "the user's repository is untouched");
    let audit = std::fs::read_to_string(paths.audit()).unwrap();
    assert!(audit.lines().any(|l| l.contains("\"event\":\"seed\"") && l.contains("\"outcome\":\"seeded\"") && l.contains("\"source\":\"box\"")), "{audit}");
}

/// A carry seed beyond the move's limits is refused, exit 9 (a failed move's
/// seed step is 7, 8 or 9), its line naming `ai-env session migrate`, which
/// moves a chat with no deadline, and audited `seed_refused`: a body over
/// `[seed].wrapper_inline_mib`, and one that does not fit what is left of
/// the move's window at `SEED_RATE` (8 MiB that do not compress, about 2.1 s,
/// given 1 s once prepared). Nothing is sent.
#[tokio::test]
async fn a_carry_seed_past_its_cap_or_window_is_refused_naming_session_migrate() {
    let refused = |e: ai_env_cli::bridge::errors::BridgeError, what: &str| {
        let text = e.to_string();
        assert_eq!(CliError::from(e).exit_code(), 9, "{text}");
        assert!(text.starts_with("workspace refused (too_large)") && text.contains(what) && text.contains("ai-env session migrate"), "{text}");
    };
    let w = World::new();
    let repo = w.repo("app");
    repo.write("data.txt", &"d".repeat(4096));
    repo.commit("data");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let mut ctx = ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    ctx.lim = SeedLimits { max_bytes: 64, ..SeedLimits::wrapper(&cfg) };
    ctx.deadline = Some(tokio::time::Instant::now() + Duration::from_secs(60));
    refused(ensure_workspace(&ctx, None, SeedWant::Carry).await.unwrap_err(), "the carry seed is over 64 B");
    assert!(vm.bodies.lock().unwrap().is_empty(), "nothing was sent");
    let audit = std::fs::read_to_string(paths.audit()).unwrap();
    assert!(audit.lines().any(|l| l.contains("\"event\":\"seed_refused\"") && l.contains("\"code\":\"too_large\"")), "{audit}");
    // Bytes zlib cannot shrink (a xorshift stream), so the pack is as large as the file: 8 MiB.
    let w = World::new();
    let repo = w.repo("big");
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
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let wrapper = SeedLimits::wrapper(&cfg);
    let prepared = prepare(&paths, &cfg, &ws, &wrapper).unwrap();
    let mut ctx = ensure_ctx(&api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    ctx.lim = wrapper;
    ctx.deadline = Some(tokio::time::Instant::now() + Duration::from_secs(1));
    refused(ensure_workspace(&ctx, Some(prepared), SeedWant::Carry).await.unwrap_err(), "does not fit the move's window");
    assert_eq!(vm.calls(), [format!("GET /seed {}", ws.vm_root)], "the state was read, the body never sent");
}

/// §6.3's rules, by the dead VM's record in the workspace's row: none (or
/// another VM's, or one a 204 refreshed with no head) is this Mac's seed,
/// noted (the VM's work was never fetched); one whose commits this Mac's
/// store lacks (or that names no commit id) too, noted; one without a WIP at
/// this Mac's HEAD or an ancestor of it is this Mac's, with no note (it holds
/// everything); any other is the box's: a commit ahead of this Mac's HEAD, a
/// WIP, with no note, and noted once this Mac's HEAD has commits the record
/// lacks.
#[test]
fn carry_source_rules() {
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let base = repo.head();
    let (head, wip, _, _) = vm_work(&w, &repo);
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let never = |note: Option<String>| note.is_some_and(|n| n.contains(DEAD) && n.contains("never fetched"));
    let elsewhere = |note: Option<String>| note.is_some_and(|n| n.contains(DEAD) && n.contains("not in this Mac's repository"));
    assert!(never(mac_note(carry_source(&paths, &ws, DEAD))), "no record");
    record(&paths, &ws, "microvm-00000000-0000-4000-8000-0000000000e1", Some(fetched(&head, Some(&wip))));
    assert!(never(mac_note(carry_source(&paths, &ws, DEAD))), "another VM's record");
    record(&paths, &ws, DEAD, Some(VmFetchRow { at: 1_792_000_000, ..VmFetchRow::default() }));
    assert!(never(mac_note(carry_source(&paths, &ws, DEAD))), "a record with no head");
    record(&paths, &ws, DEAD, Some(fetched(&base, None)));
    assert_eq!(mac_note(carry_source(&paths, &ws, DEAD)), None, "this Mac's HEAD, no WIP: this Mac holds it all");
    record(&paths, &ws, DEAD, Some(fetched(&head, None)));
    let (rec, note) = box_of(carry_source(&paths, &ws, DEAD));
    assert_eq!((rec, note), (fetched(&head, None), None), "a commit ahead of this Mac's HEAD");
    record(&paths, &ws, DEAD, Some(fetched(&head, Some(&wip))));
    assert_eq!(box_of(carry_source(&paths, &ws, DEAD)), (fetched(&head, Some(&wip)), None), "its WIP");
    let absent = "1".repeat(40);
    record(&paths, &ws, DEAD, Some(fetched(&absent, None)));
    assert!(elsewhere(mac_note(carry_source(&paths, &ws, DEAD))), "a head this Mac lacks");
    record(&paths, &ws, DEAD, Some(fetched(&head, Some(&absent))));
    assert!(elsewhere(mac_note(carry_source(&paths, &ws, DEAD))), "a WIP this Mac lacks");
    record(&paths, &ws, DEAD, Some(fetched("main", None)));
    assert!(elsewhere(mac_note(carry_source(&paths, &ws, DEAD))), "no commit id");
    // This Mac moves on: the record's head an ancestor of its HEAD is this Mac's; a diverged one the box's, noted.
    repo.write("mac.txt", "the Mac's own\n");
    repo.commit("the Mac's commit");
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    record(&paths, &ws, DEAD, Some(fetched(&base, None)));
    assert_eq!(mac_note(carry_source(&paths, &ws, DEAD)), None, "an ancestor of this Mac's HEAD, no WIP");
    record(&paths, &ws, DEAD, Some(fetched(&head, Some(&wip))));
    let (rec, note) = box_of(carry_source(&paths, &ws, DEAD));
    assert_eq!(rec, fetched(&head, Some(&wip)));
    assert!(note.as_deref().is_some_and(|n| n.contains("this Mac's HEAD has commits") && n.contains(DEAD)), "{note:?}");
}
