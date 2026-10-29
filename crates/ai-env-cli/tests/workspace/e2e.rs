//! tests/workspace.rs area: the seed and the code-out end to end, through
//! the endpoint and the native shim with its real helper (`ai-env shim-io`,
//! the rig of `tests/common/remote.rs`): `ai-env box seed` and `box fetch`
//! on the Mac, the routes and the helper's git in the VM's copy. What the
//! git-backed fake VM stands for in the other areas, here the VM itself
//! (the lead's integration: T8.1's round trip, D7's boundary, also when the
//! workspace row missed a seed; S12 (D): S11's F1, a branch the agent made
//! with no new object answered with the manifest alone, then nothing new).
use super::common::remote::{RemoteRig, FIXTURE_AUTHOR, FIXTURE_DATE};
use super::common::{git_real, Harness};
use ai_env_cli::bridge::api::Call;
use ai_env_cli::wire::workspace::CODE_PORT;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `git <args>` in `dir` (the real git, no user or system config, the
/// fixture's author and date): its stdout, trimmed; a failure panics.
fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new(git_real())
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", FIXTURE_AUTHOR.0)
        .env("GIT_AUTHOR_EMAIL", FIXTURE_AUTHOR.1)
        .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
        .env("GIT_COMMITTER_NAME", FIXTURE_AUTHOR.0)
        .env("GIT_COMMITTER_EMAIL", FIXTURE_AUTHOR.1)
        .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
        .output()
        .expect("run the real git");
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// Write each `(path, text)` under `dir`, then commit everything as `msg`: the commit.
fn commit(dir: &Path, files: &[(&str, &str)], msg: &str) -> String {
    for (path, text) in files {
        std::fs::write(dir.join(path), text).expect("write a fixture file");
    }
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

/// `ai-env box seed <work> --json` on the rig (one Touch ID): its JSON.
fn box_seed(rig: &RemoteRig) -> Value {
    let o = rig.run(&["box", "seed", &rig.work().display().to_string(), "--json"], None);
    assert!(o.status.success(), "box seed: {}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("box seed --json ({e}): {}", String::from_utf8_lossy(&o.stdout)))
}

/// The VM's `.git/shallow`, sorted.
fn vm_shallow(vm: &Path) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_to_string(vm.join(".git").join("shallow")).expect("the VM's shallow file").lines().map(str::to_string).collect();
    ids.sort();
    ids
}

/// `ai-env box fetch <work> --wip --json` on the rig (one Touch ID): its JSON.
fn box_fetch_wip(rig: &RemoteRig) -> Value {
    let o = rig.run(&["box", "fetch", &rig.work().display().to_string(), "--wip", "--json"], None);
    assert!(o.status.success(), "box fetch: {}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("box fetch --json ({e}): {}", String::from_utf8_lossy(&o.stdout)))
}

/// `git <args>` in the VM's copy `dir` as the fake claude's `FAKE_COMMIT`
/// runs it (claude-agent, no hooks, no signing), and no automatic
/// maintenance: after a commit git 2.56 repacks in the background (`repack
/// -d`), and the next git's loose objects (the test's, the helper's) race
/// its `prune-packed`. Its stdout, trimmed.
fn as_agent(dir: &Path, args: &[&str]) -> String {
    let mut all = vec!["-c", "user.name=claude-agent", "-c", "user.email=claude-agent@ai-env.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=false", "-c", "gc.auto=0"];
    all.extend_from_slice(args);
    let o = Command::new(git_real()).args(all).current_dir(dir).env_clear().env("PATH", "/usr/bin:/bin").env("HOME", dir).env("LC_ALL", "C").env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null").output().expect("run the real git");
    assert!(o.status.success(), "git {args:?} in the VM: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// What the Mac's side of a code-out leaves alone: HEAD, the branches and
/// tags, the index against HEAD and the worktree against the index
/// (untracked and ignored files included), the stash. Read without
/// optional locks, so the look writes nothing either.
fn mac_view(work: &Path) -> Vec<String> {
    [
        &["rev-parse", "HEAD"][..],
        &["for-each-ref", "refs/heads", "refs/tags"],
        &["--no-optional-locks", "status", "--porcelain=v2", "--untracked-files=all", "--ignored"],
        &["--no-optional-locks", "diff", "--cached"],
        &["--no-optional-locks", "diff"],
        &["stash", "list"],
    ]
    .iter()
    .map(|args| git(work, args))
    .collect()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The workspace row's file: `state/workspaces/<slug>.toml` in the rig's bridge dir.
fn row_file(rig: &RemoteRig) -> PathBuf {
    let slug = ai_env_cli::wire::slug::project_dir_name(&rig.work()).expect("the workspace's slug");
    rig.bridge().join("state").join("workspaces").join(format!("{slug}.toml"))
}

/// A file large enough for a thin pack to delta against.
fn big_text() -> String {
    (0..2000).map(|i| format!("line {i} of a file large enough to delta\n")).collect()
}

/// The boundary tests' start, as `updates_walk_the_vms_shallow_boundary_through_the_real_helper`'s:
/// C1 (a file large enough to delta, and `fork.txt`), then S0 on it
/// (`fork.txt` changed), the rig's VM seeded at S0. Gives the VM's copy, C1 and S0.
fn seeded_at_s0(rig: &RemoteRig) -> (PathBuf, String, String) {
    let work = rig.work();
    let c1 = commit(&work, &[("big.txt", &big_text()), ("fork.txt", "c1\n")], "C1");
    let s0 = commit(&work, &[("fork.txt", "s0\n"), ("s0.txt", "s0\n")], "S0");
    rig.start_vm();
    let seeded = box_seed(rig);
    assert_eq!(seeded["outcome"].as_str(), Some("seeded"), "{seeded}");
    let vm_dir = rig.vm_path(&work);
    assert_eq!(vm_shallow(&vm_dir), std::slice::from_ref(&s0));
    (vm_dir, c1, s0)
}

/// An old fork merged into main with `-s ours` (F1 from C1, `big.txt` and
/// `fork.txt` changed, then F2): the update that sends it marks F1 shallow.
/// Gives F1 and F2.
fn merge_old_fork(work: &Path, c1: &str) -> (String, String) {
    git(work, &["checkout", "-q", "-b", "old", c1]);
    let f1 = commit(work, &[("big.txt", &big_text().replace("line 1000 of", "line ONE THOUSAND of")), ("fork.txt", "f1\n")], "F1");
    let f2 = commit(work, &[("side.txt", "side\n")], "F2");
    git(work, &["checkout", "-q", "main"]);
    git(work, &["merge", "-q", "-s", "ours", "--no-edit", "old"]);
    (f1, f2)
}

/// One commit on `branch`, forked at `at` (`files` written; none: an empty
/// commit, its tree `at`'s), merged into main: the commit.
fn merge_fork(work: &Path, branch: &str, at: &str, files: &[(&str, &str)], msg: &str) -> String {
    git(work, &["checkout", "-q", "-b", branch, at]);
    for (path, text) in files {
        std::fs::write(work.join(path), text).expect("write a fixture file");
    }
    git(work, &["add", "-A"]);
    git(work, &["commit", "-q", "--allow-empty", "-m", msg]);
    let forked = git(work, &["rev-parse", "HEAD"]);
    git(work, &["checkout", "-q", "main"]);
    git(work, &["merge", "-q", "--no-edit", branch]);
    forked
}

/// `box seed` once the Mac moved on: the VM updated to the Mac's HEAD.
fn box_update(rig: &RemoteRig) {
    let head = git(&rig.work(), &["rev-parse", "HEAD"]);
    let updated = box_seed(rig);
    assert_eq!((updated["outcome"].as_str(), updated["detail"]["head"].as_str()), (Some("updated"), Some(head.as_str())), "{updated}");
}

/// The VM's repository whole after G (forked at C1) went in: C1's
/// `fork.txt` crossed with G, and none of `below` (C1, the fork point) did.
fn assert_whole_without(vm_dir: &Path, g: &str, below: &[&str]) {
    assert_eq!(git(vm_dir, &["show", &format!("{g}:fork.txt")]), "c1", "C1's blob crossed with G");
    git(vm_dir, &["fsck", "--connectivity-only", "--no-progress"]);
    for id in below {
        let there = Command::new(git_real()).args(["cat-file", "-e", id]).current_dir(vm_dir).status().expect("run git");
        assert!(!there.success(), "{id} never crossed");
    }
}

fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

/// T8.1 through the endpoint (plan Part A, the lead's integration): `ai-env
/// box seed` reaches the rig's VM on the code port (a Port(9418) token of a
/// seed's 15 minutes, the shim's bearer on every request) and leaves a
/// clone at the identical path (the Mac's path, under the rig's fs_root):
/// HEAD the Mac's, shallow at it, no origin, the Mac's uncommitted work (an
/// edit, a staged file, an untracked one) uncommitted there too. The agent
/// commits in the VM and edits on (as the fake claude's `FAKE_COMMIT` and
/// `FAKE_EDIT` do); `box fetch --wip` brings the commit into
/// `refs/remotes/box/main` and the edit into a `box/wip/*` snapshot on it,
/// the Mac's branches, index and worktree untouched. D3: once the Mac
/// commits, a second `box seed` keeps that dirty VM as it is, with the
/// note; a VM seeded clean is fast-forwarded by it.
#[test]
fn t8_1_seed_round_trip_through_the_endpoint() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    std::fs::write(work.join("README.md"), "fixture, edited on the Mac\n").expect("edit README.md");
    std::fs::write(work.join("staged.txt"), "staged on the Mac\n").expect("write staged.txt");
    git(&work, &["add", "staged.txt"]);
    std::fs::write(work.join("notes.txt"), "untracked on the Mac\n").expect("write notes.txt");
    let vm = rig.start_vm();
    let touch = rig.decrypts();
    let seeded = box_seed(rig);
    assert_eq!((seeded["outcome"].as_str(), seeded["vm"].as_str(), seeded["detail"]["head"].as_str()), (Some("seeded"), Some(vm.as_str()), Some(rig.head())), "{seeded}");
    assert!(seeded["detail"]["wip"].is_string(), "the uncommitted work went with the seed: {seeded}");
    // The identical path: the VM path is the Mac's own; its disk copy here lives under the fs_root.
    let vm_dir = rig.vm_path(&work);
    assert_eq!((rig.vm_cwd(), vm_dir.starts_with(rig.vm_root())), (work.display().to_string(), true), "{}", vm_dir.display());
    assert_eq!(git(&vm_dir, &["rev-parse", "HEAD"]), rig.head(), "the VM's HEAD is the Mac's");
    assert_eq!(git(&vm_dir, &["remote"]), "", "no origin in the VM");
    assert_eq!(vm_shallow(&vm_dir), [rig.head()], "shallow at the seeded commit: no history crossed");
    let status = ["--no-optional-locks", "status", "--porcelain", "--untracked-files=all"];
    assert_eq!(git(&vm_dir, &status), git(&work, &status), "the Mac's uncommitted work is uncommitted in the VM");
    let kinds = |dir: &Path| (git(dir, &["diff", "--name-only"]), git(dir, &["diff", "--cached", "--name-only"]), git(dir, &["ls-files", "--others", "--exclude-standard"]));
    assert_eq!(kinds(&vm_dir), ("README.md".to_string(), "staged.txt".to_string(), "notes.txt".to_string()), "an edit, a staged file, an untracked one");
    for file in ["README.md", "staged.txt", "notes.txt"] {
        assert_eq!(read(&vm_dir.join(file)), read(&work.join(file)), "{file}");
    }
    // The code port behind its checks: a Port(9418) token of a seed's 15 minutes, the bearer on every request.
    let calls = rig.fake_calls();
    assert!(calls.iter().any(|c| matches!(c, Call::Token { id, minutes: 15, port: CODE_PORT } if *id == vm)), "a Port(9418) token of a seed's 15 minutes: {calls:?}");
    let code: Vec<(String, u16)> = rig.endpoint.attempts().iter().filter(|a| a.port == CODE_PORT).map(|a| (a.path.clone(), a.status)).collect();
    assert!(code.iter().any(|(path, status)| path.starts_with("/seed") && *status == 201), "the seed's PUT went in: {code:?}");
    assert!(code.iter().all(|(_, status)| (200..300).contains(status)), "the bearer on every request (no 401): {code:?}");
    // The agent's commit, then an edit it has not committed, made in the VM's copy as the fake claude makes them.
    std::fs::write(vm_dir.join("agent.txt"), "from the VM\n").expect("write agent.txt in the VM");
    as_agent(&vm_dir, &["add", "-A"]);
    as_agent(&vm_dir, &["commit", "-q", "--allow-empty", "-m", "the agent's commit"]);
    let vm_commit = git(&vm_dir, &["rev-parse", "HEAD"]);
    std::fs::write(vm_dir.join("agent.txt"), "from the VM, not committed yet\n").expect("edit agent.txt in the VM");
    let mac = mac_view(&work);
    let fetched = box_fetch_wip(rig);
    let report = &fetched["report"];
    assert_eq!((fetched["vm"].as_str(), report["ok"].as_bool()), (Some(vm.as_str()), Some(true)), "{fetched}");
    let promoted = report["promoted"].as_object().unwrap_or_else(|| panic!("promoted refs: {fetched}"));
    assert_eq!(promoted.get("refs/remotes/box/main").and_then(Value::as_str), Some(vm_commit.as_str()), "{fetched}");
    let wips: Vec<&String> = promoted.keys().filter(|r| r.starts_with("refs/remotes/box/wip/")).collect();
    assert_eq!(wips.len(), 1, "one snapshot of the uncommitted edit: {fetched}");
    let wip = wips[0];
    assert_eq!((git(&work, &["rev-parse", "refs/remotes/box/main"]), git(&work, &["rev-parse", "refs/remotes/box/main^"])), (vm_commit.clone(), rig.head().to_string()), "the agent's commit on the seeded head");
    assert_eq!(git(&work, &["show", "refs/remotes/box/main:agent.txt"]), "from the VM");
    assert_eq!((git(&work, &["rev-parse", &format!("{wip}^")]), git(&work, &["show", &format!("{wip}:agent.txt")])), (vm_commit.clone(), "from the VM, not committed yet".to_string()), "the snapshot holds the edit, on the commit");
    assert_eq!(mac_view(&work), mac, "the Mac's branches, index and worktree untouched");
    // D3: the Mac moves on; the VM, which has work of its own, keeps it, and the seed says so.
    commit(&work, &[("mac.txt", "from the Mac\n")], "M2");
    let kept = box_seed(rig);
    assert_eq!((kept["outcome"].as_str(), kept["detail"]["reason"].as_str()), (Some("kept"), Some("dirty")), "{kept}");
    assert_eq!(kept["detail"]["note"].as_str(), Some("the VM keeps its state (dirty): ai-env box fetch shows what changed"), "{kept}");
    assert_eq!((git(&vm_dir, &["rev-parse", "HEAD"]), read(&vm_dir.join("agent.txt"))), (vm_commit, "from the VM, not committed yet\n".to_string()), "nothing in the VM moved");
    assert_eq!(rig.decrypts() - touch, 3, "one Touch ID per box command (D1)");
    // D3 on a VM seeded clean: a second seed after a Mac commit fast-forwards it, still shallow at the first.
    let mut q = Harness::prepare();
    let rig = q.rig();
    let work = rig.work();
    rig.start_vm();
    let seeded = box_seed(rig);
    assert_eq!((seeded["outcome"].as_str(), seeded["detail"]["wip"].as_str()), (Some("seeded"), None), "{seeded}");
    let m2 = commit(&work, &[("mac.txt", "from the Mac\n")], "M2");
    let updated = box_seed(rig);
    assert_eq!((updated["outcome"].as_str(), updated["detail"]["from"].as_str(), updated["detail"]["head"].as_str()), (Some("updated"), Some(rig.head()), Some(m2.as_str())), "{updated}");
    let vm_dir = rig.vm_path(&work);
    assert_eq!((git(&vm_dir, &["rev-parse", "HEAD"]), git(&vm_dir, &status), read(&vm_dir.join("mac.txt"))), (m2, String::new(), "from the Mac\n".to_string()), "fast-forwarded, clean");
    assert_eq!(vm_shallow(&vm_dir), [rig.head()], "the update carried no history either");
}

/// D7 through the real helper: an update's thin pack is built against the
/// VM's shallow boundary, never the Mac's whole history. The VM is seeded
/// at S0, whose parent C1 never crosses. A first update merges an old fork
/// (F1 from C1, then F2): F1 becomes a boundary commit. A second merges
/// another commit forked from C1 (G, which keeps C1's `fork.txt`, a blob
/// the VM never got) and a topic forked from S0 (Y). The Mac's whole graph
/// takes C1 for the VM's (an edge whose tree a thin pack leaves out and
/// deltas against, which the VM's `index-pack --fix-thin` and its object
/// check refuse); walked as the VM's graph, cut at S0 and at F1 (the
/// boundary the first update sent, from the workspace row), G is the new
/// boundary and Y keeps its parent, which the VM holds. Each update goes
/// in: the VM's `.git/shallow` is exactly that boundary, its repository
/// whole, the fork point absent.
#[test]
fn updates_walk_the_vms_shallow_boundary_through_the_real_helper() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    let big: String = (0..2000).map(|i| format!("line {i} of a file large enough to delta\n")).collect();
    let c1 = commit(&work, &[("big.txt", &big), ("fork.txt", "c1\n")], "C1");
    let s0 = commit(&work, &[("fork.txt", "s0\n"), ("s0.txt", "s0\n")], "S0");
    let vm = rig.start_vm();
    let seeded = box_seed(rig);
    assert_eq!((seeded["outcome"].as_str(), seeded["vm"].as_str()), (Some("seeded"), Some(vm.as_str())), "{seeded}");
    let vm_dir = rig.vm_path(&work);
    assert_eq!((git(&vm_dir, &["rev-parse", "HEAD"]), vm_shallow(&vm_dir)), (s0.clone(), vec![s0.clone()]));
    // The first update: a merge of a branch that forked at C1, below the seed.
    git(&work, &["checkout", "-q", "-b", "old", &c1]);
    let f1 = commit(&work, &[("big.txt", &big.replace("line 1000 of", "line ONE THOUSAND of")), ("fork.txt", "f1\n")], "F1");
    commit(&work, &[("side.txt", "side\n")], "F2");
    git(&work, &["checkout", "-q", "main"]);
    git(&work, &["merge", "-q", "-s", "ours", "--no-edit", "old"]);
    let m1 = git(&work, &["rev-parse", "HEAD"]);
    let updated = box_seed(rig);
    assert_eq!((updated["outcome"].as_str(), updated["detail"]["head"].as_str()), (Some("updated"), Some(m1.as_str())), "{updated}");
    let mut want = vec![s0.clone(), f1.clone()];
    want.sort();
    assert_eq!((git(&vm_dir, &["rev-parse", "HEAD"]), vm_shallow(&vm_dir)), (m1.clone(), want), "F1 is the VM's new boundary");
    // The second: another commit forked at C1 (C1's own fork.txt, which never crossed), and a topic from S0.
    git(&work, &["checkout", "-q", "-b", "older", &c1]);
    let g = commit(&work, &[("g.txt", "g\n")], "G");
    git(&work, &["checkout", "-q", "-b", "topic", &s0]);
    let y = commit(&work, &[("y.txt", "y\n")], "Y");
    git(&work, &["checkout", "-q", "main"]);
    git(&work, &["merge", "-q", "--no-edit", "older"]);
    git(&work, &["merge", "-q", "--no-edit", "topic"]);
    let m2 = git(&work, &["rev-parse", "HEAD"]);
    let updated = box_seed(rig);
    assert_eq!((updated["outcome"].as_str(), updated["detail"]["head"].as_str()), (Some("updated"), Some(m2.as_str())), "{updated}");
    let mut want = vec![s0.clone(), f1, g.clone()];
    want.sort();
    assert_eq!((git(&vm_dir, &["rev-parse", "HEAD"]), vm_shallow(&vm_dir)), (m2, want), "G alone is new: Y's parent is the VM's S0");
    assert_eq!(git(&vm_dir, &["rev-parse", &format!("{y}^")]), s0, "Y keeps its parent in the VM");
    assert_eq!(git(&vm_dir, &["show", &format!("{g}:fork.txt")]), "c1", "C1's blob crossed with G");
    git(&vm_dir, &["fsck", "--connectivity-only", "--no-progress"]);
    let c1_there = Command::new(git_real()).args(["cat-file", "-e", &c1]).current_dir(&vm_dir).status().expect("run git");
    assert!(!c1_there.success(), "the fork point never crossed");
    // The helper's own git took both packs as thin ones it completed against the VM's objects.
    let fixed = rig.vm_git_calls().iter().filter(|c| c.sub() == Some("index-pack") && c.has("--fix-thin")).count();
    assert_eq!(fixed, 2, "{:?}", rig.vm_git_calls());
}

/// D7 with the workspace row lost after the clone (its file removed): the
/// first update's walk falls back to the seeded head and goes in, F1 its new
/// boundary. The row, which never saw S0, then keeps no boundary for the VM
/// rather than F1 alone (a list without S0, which takes S0's history, C1
/// and below, for the VM's), and it never trusts one again before a clone,
/// however often it sees the VM's seed since. A merge of G (forked at C1,
/// keeping C1's `fork.txt`) and one of H (an empty commit on the fixture's
/// first, its tree that commit's) each go in with what the VM lacks.
#[test]
fn a_row_lost_after_the_clone_never_trusts_a_partial_boundary() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    let (vm_dir, c1, s0) = seeded_at_s0(rig);
    std::fs::remove_file(row_file(rig)).expect("remove the workspace row");
    let (f1, _) = merge_old_fork(&work, &c1);
    box_update(rig);
    assert_eq!(vm_shallow(&vm_dir), sorted(vec![s0.clone(), f1.clone()]), "F1 is the VM's new boundary");
    let g = merge_fork(&work, "older", &c1, &[("g.txt", "g\n")], "G");
    box_update(rig);
    let h = merge_fork(&work, "oldest", rig.head(), &[], "H");
    box_update(rig);
    assert_eq!(vm_shallow(&vm_dir), sorted(vec![s0, f1, g.clone(), h.clone()]), "each fork below the seed is a boundary of its own");
    git(&vm_dir, &["cat-file", "-e", &format!("{h}^{{tree}}")]);
    assert_whole_without(&vm_dir, &g, &[&c1, rig.head()]);
}

/// D7 with a row write lost: the row put back as it was before an update
/// that went in (as a write cut by the process's exit leaves it). The next
/// update, a plain commit, was planned on a seed the row never saw: it walks
/// from that seed alone and goes in, and the row keeps no boundary for the
/// VM rather than its old list (S0 without F1) under the new head. The merge
/// after it, of G (forked at C1, keeping C1's `fork.txt`), goes in with what
/// the VM lacks.
#[test]
fn a_lost_row_write_never_leaves_a_stale_boundary_behind() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    let (vm_dir, c1, s0) = seeded_at_s0(rig);
    let before = std::fs::read(row_file(rig)).expect("the workspace row after the clone");
    let (f1, _) = merge_old_fork(&work, &c1);
    box_update(rig);
    std::fs::write(row_file(rig), before).expect("put the workspace row back");
    commit(&work, &[("l.txt", "l\n")], "L");
    box_update(rig);
    let g = merge_fork(&work, "older", &c1, &[("g.txt", "g\n")], "G");
    box_update(rig);
    assert_eq!(vm_shallow(&vm_dir), sorted(vec![s0, f1, g.clone()]), "G alone is new");
    assert_whole_without(&vm_dir, &g, &[&c1]);
}

/// D7's fallback (a row that did not see the VM's seed) cuts the walk at the
/// VM's tip as well as at its seeded head. The agent's X on F2 (the merged
/// fork, shallow at F1 in the VM), merged into the VM's main and fetched,
/// reaches F1 other than through the seeded head: cut at the seeded head
/// alone, the Mac's graph takes F1's parent C1, and its `fork.txt`, for the
/// VM's. The Mac takes the fetched main, then merges G (forked at C1,
/// keeping C1's `fork.txt`): the update goes in with what the VM lacks.
#[test]
fn the_fallback_walk_stops_at_the_vms_tip_too() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    let (vm_dir, c1, s0) = seeded_at_s0(rig);
    let (f1, f2) = merge_old_fork(&work, &c1);
    box_update(rig);
    std::fs::remove_file(row_file(rig)).expect("remove the workspace row");
    as_agent(&vm_dir, &["checkout", "-q", "-b", "fix", &f2]);
    std::fs::write(vm_dir.join("x.txt"), "from the VM\n").expect("write x.txt in the VM");
    as_agent(&vm_dir, &["add", "-A"]);
    as_agent(&vm_dir, &["commit", "-q", "-m", "X"]);
    as_agent(&vm_dir, &["checkout", "-q", "main"]);
    as_agent(&vm_dir, &["merge", "-q", "--no-edit", "fix"]);
    let tip = git(&vm_dir, &["rev-parse", "HEAD"]);
    let fetched = box_fetch_wip(rig);
    assert_eq!(fetched["report"]["promoted"]["refs/remotes/box/main"].as_str(), Some(tip.as_str()), "{fetched}");
    git(&work, &["merge", "-q", "--ff-only", "refs/remotes/box/main"]);
    let g = merge_fork(&work, "older", &c1, &[("g.txt", "g\n")], "G");
    box_update(rig);
    assert_eq!(vm_shallow(&vm_dir), sorted(vec![s0, f1, g.clone()]), "G alone is new");
    assert_whole_without(&vm_dir, &g, &[&c1]);
}

// ---- phase 4 F9: the seed's scratch on every path ----

/// Every entry under `dir` (directories too, recursively, links not
/// followed), relative to it, sorted; none when it does not exist.
fn entries_under(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.filter_map(Result::ok) {
            let path = e.path();
            out.push(path.strip_prefix(base).unwrap_or(&path).display().to_string());
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// The design's `the_seed_bundle_is_0600_and_removed_on_every_path` (T8.1),
/// as D7 built it: the body (the manifest line and the pack) is written
/// 0600 in a 0700 scratch under the Mac's `state/tmp`, staged 0600 in the
/// VM's inbox, and neither side keeps any of it, whatever ends the seed
/// after the WIP snapshot: the VM's git failing `index-pack` (422
/// `bad_pack`, FAKE_GIT_FAIL), the Mac's failing `pack-objects` (nothing
/// sent), `PUT /seed` answered 500 by the endpoint, or the seed going in
/// (its body seen while the endpoint held the PUT). A failed first seed
/// leaves no workspace in the VM either.
#[test]
fn a_failed_seed_leaves_no_scratch_on_either_side() {
    use super::common::fake_endpoint::Action;
    use std::os::unix::fs::PermissionsExt as _;
    let mode = |p: &Path| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    for case in ["vm index-pack fails", "mac pack-objects fails", "put answered 500", "held, then in"] {
        let mut p = Harness::prepare();
        let rig = p.rig();
        let work = rig.work();
        std::fs::write(work.join("README.md"), "fixture, edited on the Mac\n").expect("edit README.md");
        std::fs::write(work.join("notes.txt"), "untracked on the Mac\n").expect("write notes.txt");
        rig.start_vm();
        let (code, says, ports) = match case {
            "vm index-pack fails" => {
                rig.set_vm_git_knobs(&[("FAKE_GIT_FAIL", "index-pack")]);
                (Some(1), "bad_pack", vec![200, 422])
            }
            "mac pack-objects fails" => {
                super::common::install_fake_git(&rig.root().join("bin").join("git"), &rig.root().join("git-mac.log"), &[("FAKE_GIT_FAIL", "pack-objects")]);
                (Some(1), "git_failed", vec![200])
            }
            "put answered 500" => {
                rig.endpoint.script_port(CODE_PORT, [Action::Forward, Action::status(500, &[])]);
                (Some(1), "500", vec![200, 500])
            }
            _ => {
                rig.endpoint.script_port(CODE_PORT, [Action::Forward, Action::Held]);
                (Some(0), "", vec![200, 201])
            }
        };
        let tmp = rig.bridge().join("state").join("tmp");
        let mut cmd = rig.ai_env(&["box", "seed", &work.display().to_string(), "--json"]);
        cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let child = cmd.spawn().expect("spawn box seed");
        if code == Some(0) {
            // While the endpoint holds the PUT, the body is on the Mac's disk: 0600 in a 0700 scratch, under a 0700 state/tmp.
            let t = std::time::Instant::now();
            let body = loop {
                if let Some(rel) = entries_under(&tmp).into_iter().find(|e| e.ends_with("/seed.body")) {
                    break tmp.join(rel);
                }
                assert!(t.elapsed() < super::common::remote::LIMIT, "{case}: no body on the Mac's disk: {:?}", entries_under(&tmp));
                std::thread::sleep(std::time::Duration::from_millis(25));
            };
            assert_eq!((mode(&body), mode(body.parent().unwrap()), mode(&tmp)), (0o600, 0o700, 0o700), "{case}: {}", body.display());
            rig.endpoint.release();
        }
        let o = super::common::bounded::finish_within(child, super::common::remote::LIMIT, "box seed");
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.status.code(), code, "{case}: {err}");
        assert!(err.contains(says), "{case}: {says} in {err}");
        assert!(rig.mac_git_calls().iter().any(|c| c.args.iter().any(|a| a == "commit-tree")), "{case}: the WIP snapshot came first");
        let statuses: Vec<u16> = rig.endpoint.attempts().iter().filter(|a| a.port == CODE_PORT).map(|a| a.status).collect();
        assert_eq!(statuses, ports, "{case}: the code port's answers");
        assert_eq!(entries_under(&tmp), Vec::<String>::new(), "{case}: the Mac's scratch is gone");
        assert_eq!(entries_under(&rig.vm_home().join(".cache").join("ai-env").join("inbox")), Vec::<String>::new(), "{case}: the VM's inbox is empty");
        assert_eq!(rig.vm_path(&work).exists(), code == Some(0), "{case}: a workspace in the VM only when the seed went in");
    }
}

// ---- S12 (D): S11's F1 end to end (plans/s11-contracts-C.md §C.1.5, the I2 row) ----

/// The `detail` of each `codeout_fetch` row in the rig's audit, oldest first.
fn codeout_details(rig: &RemoteRig) -> Vec<Value> {
    let text = std::fs::read_to_string(rig.bridge().join("audit.jsonl")).unwrap_or_default();
    text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|r| r["event"] == "codeout_fetch").map(|r| r["detail"].clone()).collect()
}

/// `vm`'s fetch record (`WsRow.vm[<vm>].fetched`) in the rig's workspace rows.
fn fetch_record(rig: &RemoteRig, vm: &str) -> Option<ai_env_cli::bridge::workspace::rows::VmFetchRow> {
    let slug = ai_env_cli::wire::slug::project_dir_name(&rig.work()).expect("the workspace's slug");
    let rows = ai_env_cli::bridge::workspace::rows::read(&rig.paths(), &slug).expect("the workspace rows");
    rows.ws.into_values().find_map(|row| row.vm.get(vm).and_then(|v| v.fetched.clone()))
}

/// The statuses the code port answered `POST /codeout` with, from the endpoint's `from`th attempt on.
fn codeout_statuses(rig: &RemoteRig, from: usize) -> Vec<u16> {
    rig.endpoint.attempts().into_iter().skip(from).filter(|a| a.port == CODE_PORT && a.path.starts_with(ai_env_cli::wire::workspace::CODEOUT_ROUTE)).map(|a| a.status).collect()
}

/// The subcommands the Mac's fake git logged, from its `from`th call on.
fn mac_subcommands(rig: &RemoteRig, from: usize) -> Vec<String> {
    rig.mac_git_calls().iter().skip(from).filter_map(|c| c.sub().map(str::to_string)).collect()
}

/// S11 F1 (plans/s11-contracts-C.md §C.1) end to end, the lead's I2 test that S11 left unbuilt (§C.1.5):
/// `ai-env box fetch --wip` through the endpoint to the native shim and its real helper, whose VM names
/// `codeout_manifest_v1` as a 13.0 image's does. After a clean seed, the first fetch gets the manifest alone
/// (200, no pack): an import without a pack promotes `box/main` and records the VM on `main`. The agent makes a
/// branch with no new object (`git checkout -b topic`): the next fetch is 200 again, not S10's 204, with 0 bytes
/// and no `index-pack`, `box/topic` and `box/main` at the seeded HEAD, the record on `topic`. A third fetch takes
/// the cheap path: nothing new, no `update-ref`, `fetch` or `merge-base`, the record kept. The Mac's branches,
/// index, worktree and stash never move; one Touch ID per box command (D1).
#[test]
fn a_checkout_b_codeout_answers_its_manifest_end_to_end() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    let head = rig.head().to_string();
    let vm = rig.start_vm();
    let touch = rig.decrypts();
    let seeded = box_seed(rig);
    assert_eq!((seeded["outcome"].as_str(), seeded["detail"]["wip"].is_null()), (Some("seeded"), true), "a clean seed, nothing uncommitted: {seeded}");
    let vm_dir = rig.vm_path(&work);
    let mac = mac_view(&work);
    // A fetch's evidence: the marks taken just before it (the endpoint's attempts, the Mac's git calls); what it
    // left, the VM's record as (HEAD, branch, snapshot) and the newest `codeout_fetch` row.
    let marks = || (rig.endpoint.attempts().len(), rig.mac_git_calls().len());
    let record = || fetch_record(rig, &vm).map(|f| (f.head, f.branch, f.wip));
    let on = |branch: &str| Some((head.clone(), Some(branch.to_string()), None));
    let newest = || codeout_details(rig).pop().unwrap_or_default();
    // The first fetch: the manifest alone (200, no pack), imported without one: box/main promoted, the record on main.
    let (at, _) = marks();
    let fetched = box_fetch_wip(rig);
    let report = &fetched["report"];
    assert_eq!(codeout_statuses(rig, at), [200], "the manifest-only answer: {fetched}");
    assert_eq!((fetched["vm"].as_str(), fetched["via"].as_str(), report["ok"].as_bool(), report["bytes"].as_u64()), (Some(vm.as_str()), Some("codeout"), Some(true), Some(0)), "{fetched}");
    assert_eq!(report["promoted"], serde_json::json!({ "refs/remotes/box/main": head }), "box/main alone, at the seeded HEAD: {fetched}");
    assert!(report.get("wip_ref").is_none() && report.get("note").is_none(), "no snapshot of a clean worktree, nothing noted: {fetched}");
    assert_eq!(record(), on("main"), "the VM's record stands on main");
    assert_eq!(git(&work, &["rev-parse", "refs/remotes/box/main"]), head);
    let row = newest();
    assert_eq!((row["outcome"].as_str(), row["promoted"].as_str(), row["bytes"].as_str()), (Some("promoted"), Some("1"), Some("0")), "{row}");
    // The agent's branch, with no new object: the worktree stays clean, so the helper makes no snapshot and no pack.
    as_agent(&vm_dir, &["checkout", "-q", "-b", "topic"]);
    assert_eq!(as_agent(&vm_dir, &["symbolic-ref", "--short", "HEAD"]), "topic");
    // The second fetch: 200 again (S10 answered 204), the import without a pack (update-ref and fetch, never
    // index-pack), both box tips at the seeded HEAD, the record on topic.
    let (at, from) = marks();
    let fetched = box_fetch_wip(rig);
    let report = &fetched["report"];
    assert_eq!(codeout_statuses(rig, at), [200], "the manifest-only answer, not S10's 204: {fetched}");
    assert_eq!(report["bytes"].as_u64(), Some(0), "no pack: {fetched}");
    assert_eq!(report["promoted"], serde_json::json!({ "refs/remotes/box/main": head, "refs/remotes/box/topic": head }), "the import wants every ref it takes, the unchanged one too: {fetched}");
    assert!(report.get("wip_ref").is_none(), "no snapshot: {fetched}");
    assert_eq!(record(), on("topic"), "the VM's record followed its branch");
    assert_eq!(git(&work, &["rev-parse", "refs/remotes/box/topic"]), head);
    let row = newest();
    assert_eq!((row["outcome"].as_str(), row["promoted"].as_str(), row["bytes"].as_str()), (Some("promoted"), Some("2"), Some("0")), "{row}");
    let subs = mac_subcommands(rig, from);
    let ran = |sub: &str| subs.iter().any(|s| s == sub);
    assert!(ran("update-ref") && ran("fetch") && !ran("index-pack"), "an import without a pack: {subs:?}");
    // The third fetch: the cheap path, nothing new: no import (no update-ref, fetch or merge-base), the record kept.
    let (at, from) = marks();
    let fetched = box_fetch_wip(rig);
    let report = &fetched["report"];
    assert_eq!(codeout_statuses(rig, at), [200], "{fetched}");
    assert_eq!((report["ok"].as_bool(), &report["promoted"], report["bytes"].as_u64()), (Some(true), &serde_json::json!({}), Some(0)), "nothing new: {fetched}");
    let row = newest();
    assert_eq!(row["outcome"].as_str(), Some("nothing_new"), "{row}");
    assert!(row.get("bytes").is_none() && row.get("promoted").is_none(), "nothing new names no bytes and no promotion: {row}");
    let subs = mac_subcommands(rig, from);
    assert!(!subs.iter().any(|s| ["index-pack", "update-ref", "fetch", "merge-base"].contains(&s.as_str())), "the cheap path runs no import: {subs:?}");
    assert_eq!(record(), on("topic"), "the record kept");
    // The end: the Mac's side never moved, three code-outs from the VM, one Touch ID per box command.
    assert_eq!(mac_view(&work), mac, "the Mac's branches, index, worktree and stash untouched");
    let rows: Vec<(Option<String>, Option<String>)> = codeout_details(rig).iter().map(|r| (r["vm"].as_str().map(str::to_string), r["via"].as_str().map(str::to_string))).collect();
    assert_eq!(rows, vec![(Some(vm.clone()), Some("codeout".to_string())); 3], "three codeout_fetch rows, each the VM's through POST /codeout");
    // DC-4 (as amended): the rig's processes never see AI_ENV_AUDIT_STRICT (`environ` removes every AI_ENV_*), and
    // there a row the registry refuses is logged and written as v1 (`audit::write_row_with`): the three rows are v2.
    let text = std::fs::read_to_string(rig.bridge().join("audit.jsonl")).unwrap_or_default();
    let versions: Vec<Option<u64>> = text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|r| r["event"] == "codeout_fetch").map(|r| r["v"].as_u64()).collect();
    assert_eq!(versions, vec![Some(u64::from(ai_env_cli::bridge::audit::AUDIT_SCHEMA_V)); 3], "registered v2 rows: the rig's processes run without AI_ENV_AUDIT_STRICT, and a refused row is written v1");
    assert_eq!(rig.decrypts() - touch, 4, "one Touch ID per box command (D1): the seed and three fetches");
}
