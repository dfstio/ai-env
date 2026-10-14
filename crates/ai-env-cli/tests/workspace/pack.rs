//! tests/workspace.rs area: the shallow transport (D7, D3): a first seed's
//! pack holds HEAD's commit and tree and the WIP, never a parent, an older
//! blob or a tag; an update sends a thin pack of exactly what the VM lacks,
//! which only applies against the VM's objects; a merge of a branch older
//! than the seeded commit marks that branch's oldest commit shallow, and the
//! VM's repository stays whole.
use super::fixture::{api, caps, ensure_ctx, git, git_out, pack_objects, split_body, target, FakeVm, World};
use ai_env_cli::bridge::workspace::pack::{first_seed_objects, update_objects};
use ai_env_cli::bridge::workspace::snapshot::Scratch;
use ai_env_cli::bridge::workspace::{ensure_workspace, resolve, EnsureOutcome, SeedProgress, SeedWant};
use ai_env_cli::wire::workspace::{ObjectFormat, SeedMode};
use std::collections::BTreeSet;

/// A first seed carries no history: of three commits only HEAD's (and its
/// tree's objects); an older version of a file and a tag never travel.
#[tokio::test]
async fn a_first_seed_carries_no_history() {
    let w = World::new();
    let repo = w.repo("app");
    repo.write("a.txt", "first version\n");
    let first = repo.commit("one");
    repo.git(&["tag", "v1"]);
    repo.write("a.txt", "second version\n");
    let second = repo.commit("two");
    repo.write("b.txt", "b\n");
    let head = repo.commit("three");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, target, caps) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress);
    assert!(matches!(ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap(), EnsureOutcome::Seeded { wip: None, .. }));
    let body = vm.bodies.lock().unwrap()[0].clone();
    let (manifest, pack) = split_body(&body);
    assert_eq!((manifest.head.as_str(), manifest.shallow.clone(), manifest.branch.as_deref(), manifest.wip.clone()), (head.as_str(), vec![head.clone()], Some("main"), None));
    let sent: BTreeSet<String> = pack_objects(&pack).into_iter().collect();
    let tree: BTreeSet<String> = repo.git(&["ls-tree", "-r", "-t", "--format=%(objectname)", "HEAD"]).lines().map(str::to_string).collect();
    let mut want = tree.clone();
    want.insert(head.clone());
    want.insert(repo.git(&["rev-parse", "HEAD^{tree}"]));
    assert_eq!(sent, want, "exactly HEAD's commit and every object of its tree");
    for absent in [first.clone(), second, repo.git(&["rev-parse", &format!("{first}:a.txt")]), repo.git(&["rev-parse", "v1"])] {
        assert!(!sent.contains(&absent), "{absent} crossed");
    }
    // The same list through the API: what the scan reads is what is packed.
    let scratch = Scratch::new(&paths, "test", &repo.dir.join(".git/objects"), ObjectFormat::Sha1).unwrap();
    let listed: BTreeSet<String> = first_seed_objects(&scratch, &head, None).unwrap().ids().into_iter().collect();
    assert_eq!(listed, sent);
}

/// D3's update: a clean VM behind the Mac gets a thin pack of exactly the
/// new commit, its tree and the changed blob, whose delta needs the VM's
/// copy of the old blob (it does not index on its own); the VM fast-forwards.
#[tokio::test]
async fn an_update_is_thin_and_minimal() {
    let w = World::new();
    let repo = w.repo("app");
    let big: String = (0..2000).map(|i| format!("line {i} of a file large enough to delta\n")).collect();
    repo.write("big.txt", &big);
    repo.write("other.txt", "untouched\n");
    repo.commit("base");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, target, caps) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress);
    ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap();
    let seeded = repo.head();
    repo.write("big.txt", &big.replace("line 1000 of", "line ONE THOUSAND of"));
    let head = repo.commit("edit");
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress);
    let outcome = ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap();
    assert_eq!(outcome, EnsureOutcome::Updated { from: seeded.clone(), head: head.clone(), wip: None, bytes: vm.bodies.lock().unwrap()[1].len() as u64 });
    assert_eq!(git(&vm.dir, &["rev-parse", "HEAD"]), head);
    git(&vm.dir, &["fsck", "--connectivity-only", "--no-progress"]);
    assert_eq!(vm.calls().iter().filter(|c| c.as_str() == "PUT /seed update").count(), 1);
    let (manifest, pack) = split_body(&vm.bodies.lock().unwrap()[1]);
    assert!(manifest.shallow.is_empty(), "a fast-forward needs no new boundary: {manifest:?}");
    // Thin: on its own the pack does not index (its delta's base is the VM's old blob).
    let tmp = tempfile::tempdir().unwrap();
    git(tmp.path(), &["init", "-q", "--bare", "x.git"]);
    assert!(!git_out(&tmp.path().join("x.git"), &["index-pack", "--stdin"], Some(&pack)).status.success(), "a thin pack");
    assert!(pack.len() < big.len() / 4, "a delta, not the file: {} bytes", pack.len());
    // Minimal: the new commit, its tree, the changed blob; the edge is the VM's tip.
    let scratch = Scratch::new(&paths, "test", &repo.dir.join(".git/objects"), ObjectFormat::Sha1).unwrap();
    let plan = update_objects(&scratch, &head, None, &seeded, &seeded, std::slice::from_ref(&seeded)).unwrap().unwrap();
    let ids: BTreeSet<String> = plan.list.ids().into_iter().collect();
    let want: BTreeSet<String> = [head.clone(), repo.git(&["rev-parse", "HEAD^{tree}"]), repo.git(&["rev-parse", "HEAD:big.txt"])].into_iter().collect();
    assert_eq!(ids, want);
    assert_eq!(plan.list.edges, vec![seeded]);
    assert_eq!(SeedMode::Update.name(), "update");
}

/// An update from a repository whose object store holds a reachability
/// bitmap (`repack.writeBitmaps`): the thin pack is the listing's, never the
/// bitmap's walk, which takes a blob the seeded commit's history holds (here
/// C1's `a.txt`, back in C3) for the shallow VM's. The update goes and the
/// VM checks it out.
#[tokio::test]
async fn an_update_from_a_store_with_a_bitmap_carries_what_the_vm_lacks() {
    let w = World::new();
    let repo = w.repo("app");
    repo.write("a.txt", "old\n");
    repo.commit("C1");
    repo.write("a.txt", "new\n");
    let seeded = repo.commit("C2");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, target, caps) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    repo.write("a.txt", "old\n");
    repo.write("c.txt", "c\n");
    let head = repo.commit("C3");
    repo.git(&["-c", "repack.writeBitmaps=true", "repack", "-adq"]);
    let packs = std::fs::read_dir(repo.dir.join(".git/objects/pack")).unwrap().filter_map(Result::ok).map(|e| e.path());
    assert!(packs.into_iter().any(|p| p.extension().is_some_and(|x| x == "bitmap")), "the store has a bitmap");
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let outcome = ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    assert!(matches!(&outcome, EnsureOutcome::Updated { from, head: h, .. } if *from == seeded && *h == head), "{outcome:?}");
    let (_, pack) = split_body(&vm.bodies.lock().unwrap()[1]);
    assert_eq!(u32::from_be_bytes(pack[8..12].try_into().unwrap()), 4, "C3, its tree, c.txt and C1's a.txt, which the shallow VM never got");
    assert_eq!(git(&vm.dir, &["rev-parse", "HEAD"]), head);
    assert_eq!(std::fs::read_to_string(vm.dir.join("a.txt")).unwrap(), "old\n");
    git(&vm.dir, &["fsck", "--connectivity-only", "--no-progress"]);
}

/// A merge of a branch that forked before the seeded commit: the branch's
/// commits travel with the update, its oldest is marked shallow (its parent
/// is history the VM never got), the merge itself is not, and the VM's
/// repository stays whole.
#[tokio::test]
async fn a_merge_of_an_older_branch_marks_its_oldest_commit_shallow() {
    let w = World::new();
    let repo = w.repo("app");
    let fork = repo.head();
    repo.write("main.txt", "main\n");
    repo.commit("main work");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, target, caps) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress);
    ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap();
    let seeded = repo.head();
    repo.git(&["checkout", "-q", "-b", "side", &fork]);
    repo.write("side.txt", "side one\n");
    let side1 = repo.commit("side one");
    repo.write("side.txt", "side two\n");
    repo.commit("side two");
    repo.git(&["checkout", "-q", "main"]);
    repo.git(&["merge", "-q", "--no-ff", "--no-edit", "side"]);
    let merge = repo.head();
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress);
    assert!(matches!(ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap(), EnsureOutcome::Updated { .. }));
    let (manifest, _) = split_body(&vm.bodies.lock().unwrap()[1]);
    assert_eq!(manifest.shallow, vec![side1.clone()], "the side branch's oldest commit, not the merge");
    assert_eq!(git(&vm.dir, &["rev-parse", "HEAD"]), merge);
    git(&vm.dir, &["fsck", "--connectivity-only", "--no-progress"]);
    assert!(super::fixture::git_ok(&vm.dir, &["merge-base", "--is-ancestor", &seeded, "HEAD"]), "the VM still sees its seed below the merge");
    assert!(!super::fixture::git_ok(&vm.dir, &["cat-file", "-e", &fork]), "the fork point's history never crossed");
}
