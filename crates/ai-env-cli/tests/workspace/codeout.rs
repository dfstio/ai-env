//! tests/workspace.rs area: code-out on the Mac (plan §7). A VM-like
//! repository built here makes a manifest and a thin pack with the git CLI;
//! the import promotes its clean refs into `refs/remotes/box/*`, quarantines
//! one that changes `.claude/settings.local.json` to a broad allow, skips a
//! reserved name and a name that meets an existing ref in another case, and
//! never touches the user's branches, index or worktree; D8 reads names as
//! the Mac's disk folds them, and a `.claude` link; git's fsck refuses a
//! tree that would write into `.git`; what a process that is gone left is
//! swept. Then the whole fetch against the git-backed fake VM: the
//! per-result snapshot comes back as `box/wip/*`, a second fetch has nothing
//! new, and the trigger coalesces a burst of results into one fetch. Last,
//! through the endpoint and the native shim's real helper (the rig of
//! `tests/common/remote.rs`): a ref the agent names after the setup-token
//! reaches no output, git argument, ref or record of the Mac's. S9: a
//! manifest naming a tree or a blob promotes neither, only counts them; a
//! ref `box_refs` skipped first is named, and a `wip_ref` naming a blob is
//! not reported.
use super::fixture::{api, caps, ensure_ctx, git, git_cmd, git_ok, git_out, target, FakeVm, Tokens, World};
use ai_env_cli::bridge::codeout::{fetch, import, CodeoutCtx, FetchOpts, Import, BOX_QUARANTINE_REFS, BOX_REFS, INCOMING_REFS};
use ai_env_cli::bridge::workspace::{ensure_workspace, resolve, SeedProgress, SeedWant};
use ai_env_cli::wire::workspace::{CodeoutManifest, ObjectFormat};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

/// A commit on `parent` in `repo` whose tree is `parent`'s with `files`
/// (`(mode, path, bytes)`) added, made through a scratch index: nothing is
/// checked out, so a name the Mac's disk folds is written as it is.
fn commit_with(repo: &Path, parent: &str, files: &[(&str, &str, &[u8])], msg: &str) -> String {
    let index = repo.join(".git").join("commit-with.index");
    let _ = std::fs::remove_file(&index);
    let indexed = |args: &[&str]| {
        let o = git_cmd(repo).env("GIT_INDEX_FILE", &index).args(args).output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    indexed(&["read-tree", parent]);
    for (mode, path, bytes) in files {
        let id = String::from_utf8_lossy(&git_out(repo, &["hash-object", "-w", "--stdin"], Some(bytes)).stdout).trim().to_string();
        indexed(&["update-index", "--add", "--cacheinfo", &format!("{mode},{id},{path}")]);
    }
    let tree = indexed(&["write-tree"]);
    git(repo, &["commit-tree", &tree, "-p", parent, "-m", msg])
}

/// The code-out of `refs` (VM ref to commit) from the VM repository `vm`,
/// its pack thin against `base` and written to `file`: its manifest.
fn codeout_of(vm: &Path, refs: &BTreeMap<String, String>, base: &str, file: &Path) -> CodeoutManifest {
    let manifest = CodeoutManifest { v: 1, object_format: ObjectFormat::Sha1, refs: refs.clone(), head: base.to_string(), branch: Some("main".into()), wip_ref: None, wip_skipped: None };
    assert_eq!(manifest.check(), Ok(()));
    let mut input: String = refs.values().map(|id| format!("{id}\n")).collect();
    input.push_str(&format!("^{base}\n"));
    let pack = git_out(vm, &["pack-objects", "--revs", "--thin", "--stdout", "-q"], Some(input.as_bytes()));
    assert!(pack.status.success(), "{}", String::from_utf8_lossy(&pack.stderr));
    std::fs::write(file, &pack.stdout).unwrap();
    manifest
}

#[test]
fn the_import_promotes_clean_refs_quarantines_a_widening_and_skips_clashes() {
    let w = World::new();
    let mac = w.repo("app");
    mac.write("src.txt", "one\n");
    let base = mac.commit("base");
    // An earlier fetch left box/Dev on the Mac.
    mac.git(&["update-ref", &format!("{BOX_REFS}Dev"), &base]);
    // The VM: a copy of the Mac's repository where the agent works.
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let at = |args: &[&str]| git(&vm, args);
    std::fs::write(vm.join("src.txt"), "two\n").unwrap();
    at(&["commit", "-q", "-am", "agent work"]);
    let main = at(&["rev-parse", "HEAD"]);
    at(&["checkout", "-q", "-b", "feature"]);
    std::fs::write(vm.join("feature.txt"), "f\n").unwrap();
    at(&["add", "feature.txt"]);
    at(&["commit", "-q", "-m", "feature"]);
    let feature = at(&["rev-parse", "HEAD"]);
    at(&["checkout", "-q", "-b", "risky"]);
    std::fs::create_dir_all(vm.join(".claude")).unwrap();
    std::fs::write(vm.join(".claude/settings.local.json"), "{\"permissions\": {\"allow\": [\"Bash(*)\"]}}\n").unwrap();
    at(&["add", ".claude/settings.local.json"]);
    at(&["commit", "-q", "-m", "allow everything"]);
    let risky = at(&["rev-parse", "HEAD"]);
    at(&["branch", "WIP", &main]);
    at(&["branch", "dev", &main]);
    at(&["checkout", "-q", "main"]);
    std::fs::write(vm.join("src.txt"), "three, uncommitted\n").unwrap();
    let snap = git_out(&vm, &["stash", "create"], None);
    let snapshot = String::from_utf8_lossy(&snap.stdout).trim().to_string();
    at(&["update-ref", "refs/wip/20261012T080000Z-1", &snapshot]);
    let mut refs: BTreeMap<String, String> = BTreeMap::new();
    for line in at(&["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads/", "refs/wip/"]).lines() {
        let (r, id) = line.split_once(' ').unwrap();
        refs.insert(r.to_string(), id.to_string());
    }
    let manifest = CodeoutManifest { v: 1, object_format: ObjectFormat::Sha1, refs: refs.clone(), head: main.clone(), branch: Some("main".into()), wip_ref: Some("refs/wip/20261012T080000Z-1".into()), wip_skipped: None };
    assert_eq!(manifest.check(), Ok(()));
    let mut input: String = refs.values().map(|id| format!("{id}\n")).collect();
    input.push_str(&format!("^{base}\n"));
    let pack = git_out(&vm, &["pack-objects", "--revs", "--thin", "--stdout", "-q"], Some(input.as_bytes()));
    assert!(pack.status.success());
    let pack_file = w.root.join("codeout.pack");
    std::fs::write(&pack_file, &pack.stdout).unwrap();
    let before = mac.state();
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let got = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &pack_file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap();
    let promoted: BTreeMap<String, String> = [("main", &main), ("feature", &feature), ("wip/20261012T080000Z-1", &snapshot)].iter().map(|(n, id)| (format!("{BOX_REFS}{n}"), (*id).clone())).collect();
    assert_eq!(got.promoted, promoted);
    assert_eq!(got.quarantined, BTreeMap::from([(format!("{BOX_QUARANTINE_REFS}risky"), risky.clone())]));
    assert!(got.findings.iter().any(|f| f.rule == "broad-allow" && f.key.as_deref() == Some("permissions.allow[0]") && f.location == format!("{BOX_REFS}risky:.claude/settings.local.json")), "{:?}", got.findings);
    assert!(got.skipped.iter().any(|s| s.starts_with("refs/heads/WIP")) && got.skipped.iter().any(|s| s.starts_with("refs/heads/dev")), "{:?}", got.skipped);
    for (name, id) in promoted.iter().chain(&got.quarantined) {
        assert_eq!(&mac.git(&["rev-parse", name]), id, "{name}");
    }
    assert_eq!(mac.git(&["rev-parse", &format!("{BOX_REFS}Dev")]), base, "the existing ref is left as it was");
    assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "no incoming ref is left");
    let after = mac.state();
    assert_eq!((after.index, after.status, after.stash), (before.index, before.status, before.stash), "the index, the worktree and the stash untouched");
    assert_eq!(mac.git(&["rev-parse", "refs/heads/main"]), base, "the user's branch untouched");
    git(&mac.dir, &["fsck", "--connectivity-only", "--no-progress"]);
}

/// D8 on a code-out as the Mac's disk reads names: a VM branch whose
/// `.claude` is a symlink (to `conf/`, which holds a broad allow), or whose
/// settings file's name only folds to one (`.CLAUDE/Settings.Local.json`;
/// `.claude/ſettings.json`, U+017F, which APFS opens as `settings.json`), is
/// quarantined, never promoted; a `settings.json` outside `.claude` is not D8's.
#[test]
fn a_linked_or_case_folded_settings_file_is_quarantined() {
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let allow: &[u8] = b"{\"permissions\": {\"allow\": [\"Bash(*)\"]}}\n";
    let hooks: &[u8] = b"{\"hooks\": {\"Stop\": [{\"command\": \"x\"}]}}\n";
    let branches = [
        ("linked", commit_with(&vm, &base, &[("120000", ".claude", b"conf"), ("100644", "conf/settings.local.json", allow)], "a linked .claude")),
        ("upper", commit_with(&vm, &base, &[("100644", ".CLAUDE/Settings.Local.json", allow)], "upper case")),
        ("longs", commit_with(&vm, &base, &[("100644", ".claude/\u{17f}ettings.json", hooks)], "a long s")),
        ("plain", commit_with(&vm, &base, &[("100644", "docs/settings.json", allow)], "no settings file of D8's")),
    ];
    let id = |b: &str| branches.iter().find(|(n, _)| *n == b).map(|(_, id)| id.clone()).unwrap();
    let refs: BTreeMap<String, String> = branches.iter().map(|(b, id)| (format!("refs/heads/{b}"), id.clone())).collect();
    let file = w.root.join("codeout.pack");
    let manifest = codeout_of(&vm, &refs, &base, &file);
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let got = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap();
    assert_eq!(got.promoted, BTreeMap::from([(format!("{BOX_REFS}plain"), id("plain"))]), "{got:?}");
    let quarantined: BTreeMap<String, String> = ["linked", "longs", "upper"].iter().map(|b| (format!("{BOX_QUARANTINE_REFS}{b}"), id(b))).collect();
    assert_eq!(got.quarantined, quarantined);
    let found: Vec<(String, String)> = got.findings.iter().map(|f| (f.location.clone(), f.rule.clone())).collect();
    for (at, rule) in [("linked:.claude", "settings-symlink"), ("upper:.CLAUDE/Settings.Local.json", "broad-allow"), ("longs:.claude/\u{17f}ettings.json", "repo-hooks")] {
        assert!(found.contains(&(format!("{BOX_REFS}{at}"), rule.to_string())), "{at}: {rule} in {found:?}");
    }
    for (name, commit) in &quarantined {
        assert_eq!(&mac.git(&["rev-parse", name]), commit, "{name}");
    }
    assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "no incoming ref is left");
}

/// The code-out's fetch runs git's fsck (`fetch.fsckObjects`): a VM branch
/// whose tree holds `.GIT/hooks/post-checkout` (made with `git mktree`; the
/// Mac's disk would check it out into `.git`) is refused before any ref
/// moves, box or quarantine, and no incoming ref is left.
#[test]
fn a_code_out_that_fails_fsck_moves_no_ref() {
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let with_input = |args: &[&str], input: &str| String::from_utf8_lossy(&git_out(&vm, args, Some(input.as_bytes())).stdout).trim().to_string();
    let hook = with_input(&["hash-object", "-w", "--stdin"], "#!/bin/sh\necho hooked\n");
    let hooks = with_input(&["mktree"], &format!("100755 blob {hook}\tpost-checkout\n"));
    let dotgit = with_input(&["mktree"], &format!("040000 tree {hooks}\thooks\n"));
    let root = with_input(&["mktree"], &format!("{}\n040000 tree {dotgit}\t.GIT\n", git(&vm, &["ls-tree", &base])));
    let evil = git(&vm, &["commit-tree", &root, "-p", &base, "-m", "a hook for the Mac"]);
    let refs = BTreeMap::from([("refs/heads/evil".to_string(), evil)]);
    let file = w.root.join("codeout.pack");
    let manifest = codeout_of(&vm, &refs, &base, &file);
    let before = mac.state();
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let e = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap_err();
    assert!(e.to_string().contains("fsck"), "{e}");
    for name in [format!("{BOX_REFS}evil"), format!("{BOX_QUARANTINE_REFS}evil")] {
        assert!(!git_ok(&mac.dir, &["rev-parse", "--verify", "--quiet", &name]), "{name}");
    }
    assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "no incoming ref is left");
    assert_eq!(mac.state().refs, before.refs, "no ref moved");
}

/// What an import cut short by its process's exit left (the wrapper's
/// close abandons a running fetch, and `process::exit` runs no destructor):
/// its incoming refs and its scratch directory go at the next import; a
/// running process's (launchd's, pid 1) stay.
#[test]
fn what_a_process_that_is_gone_left_goes_at_the_next_import() {
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    // No process has this pid (macOS's end at 99 998, Linux's at 4 194 304).
    let gone = 99_999_999;
    let (paths, cfg) = (w.paths(), w.cfg(""));
    for owner in [gone, 1] {
        mac.git(&["update-ref", &format!("{INCOMING_REFS}{owner}-0/main"), &base]);
        std::fs::create_dir_all(paths.tmp().join(format!("codeout-{owner}-AbC123")).join("repo.git")).unwrap();
    }
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let dev = commit_with(&vm, &base, &[("100644", "dev.txt", b"dev\n")], "dev");
    let file = w.root.join("codeout.pack");
    let manifest = codeout_of(&vm, &BTreeMap::from([("refs/heads/dev".to_string(), dev.clone())]), &base, &file);
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let got = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap();
    assert_eq!(got.promoted, BTreeMap::from([(format!("{BOX_REFS}dev"), dev)]));
    assert_eq!(mac.git(&["for-each-ref", "--format=%(refname)", INCOMING_REFS]), format!("{INCOMING_REFS}1-0/main"), "only a running process's");
    let left: Vec<String> = std::fs::read_dir(paths.tmp()).unwrap().filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(left, ["codeout-1-AbC123"], "the import's own went with it, a gone process's at its start");
}

/// The Mac keeps the newest `keep_wip_refs` snapshots by name, the fetch's
/// own (`wip_ref`) always among them: an older one goes in the same
/// transaction, and one the VM sent again is then not moved (git refuses
/// two commands for one ref in one transaction).
#[test]
fn the_newest_snapshots_stay_and_an_older_one_sent_again_goes() {
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let snap = |n: u32| -> (String, String) {
        std::fs::write(vm.join("README.md"), format!("snapshot {n}\n")).unwrap();
        let id = String::from_utf8_lossy(&git_out(&vm, &["stash", "create"], None).stdout).trim().to_string();
        let name = format!("refs/wip/20261012T08000{n}Z-{n}");
        git(&vm, &["update-ref", &name, &id]);
        git(&vm, &["checkout", "-q", "--", "README.md"]);
        (name, id)
    };
    let (s1, s2) = (snap(1), snap(2));
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let import_of = |sent: &[&(String, String)], keep: usize| {
        let refs: BTreeMap<String, String> = sent.iter().map(|(n, id)| (n.clone(), id.clone())).collect();
        // The last one sent is the fetch's own.
        let wip_ref = sent.last().map(|(n, _)| n.clone());
        let manifest = CodeoutManifest { v: 1, object_format: ObjectFormat::Sha1, refs: refs.clone(), head: base.clone(), branch: Some("main".into()), wip_ref, wip_skipped: None };
        assert_eq!(manifest.check(), Ok(()));
        let mut input: String = refs.values().map(|id| format!("{id}\n")).collect();
        input.push_str(&format!("^{base}\n"));
        let pack = git_out(&vm, &["pack-objects", "--revs", "--thin", "--stdout", "-q"], Some(input.as_bytes())).stdout;
        let file = w.root.join("in.pack");
        std::fs::write(&file, pack).unwrap();
        import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: keep }).unwrap()
    };
    let boxed = |(name, _): &(String, String)| format!("{BOX_REFS}{}", name.trim_start_matches("refs/"));
    let snapshots = || mac.git(&["for-each-ref", "--format=%(refname) %(objectname)", &format!("{BOX_REFS}wip/")]);
    import_of(&[&s1], 64);
    assert_eq!(snapshots(), format!("{} {}", boxed(&s1), s1.1));
    // s1 sent again, past a cap of one: deleted, not also moved; s2 the one kept.
    let got = import_of(&[&s1, &s2], 1);
    assert_eq!(got.promoted, BTreeMap::from([(boxed(&s2), s2.1.clone())]), "{got:?}");
    assert_eq!(got.tips, got.promoted, "the box refs as the import left them");
    assert_eq!(snapshots(), format!("{} {}", boxed(&s2), s2.1));
    // A VM clock behind the Mac's names: the fetch's own snapshot stays although it sorts oldest.
    let s0 = snap(0);
    let got = import_of(&[&s0], 1);
    assert_eq!(got.promoted, BTreeMap::from([(boxed(&s0), s0.1.clone())]), "{got:?}");
    assert_eq!(got.tips, got.promoted);
    assert_eq!(snapshots(), format!("{} {}", boxed(&s0), s0.1));
    assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "no incoming ref is left");
}

/// The whole fetch against the fake VM: after a seed, the agent's commit
/// and its uncommitted edit come back (`box/main`, `box/wip/*`, the seeded
/// WIP as `box/seed-wip`); asked again, nothing is new. The Mac's branch and
/// worktree never move.
#[tokio::test]
async fn a_fetch_brings_the_vms_commits_and_snapshot_into_box_refs() {
    let w = World::new();
    let repo = w.repo("app");
    repo.write("a.txt", "a\n");
    repo.commit("a");
    repo.write("a.txt", "a, uncommitted on the Mac\n");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (fake_api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ctx = ensure_ctx(&fake_api, &vm, &paths, &cfg, &t, &c, &ws, &progress);
    ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap();
    let seeded_wip = vm.record().unwrap().wip.unwrap();
    // The agent commits, then edits without committing.
    std::fs::write(vm.dir.join("b.txt"), "b\n").unwrap();
    git(&vm.dir, &["add", "b.txt"]);
    git(&vm.dir, &["commit", "-q", "-m", "agent"]);
    let agent = git(&vm.dir, &["rev-parse", "HEAD"]);
    std::fs::write(vm.dir.join("b.txt"), "b, edited\n").unwrap();
    let before = repo.state();
    let ctx = CodeoutCtx { api: Arc::new(api().await), dp: Arc::new(vm), tokens: Arc::new(Tokens), paths: paths.clone(), cfg: Arc::new(cfg.clone()), target: target(), ws: ws.clone(), capture_settings: false, transcript: None };
    let report = fetch(&ctx, FetchOpts::per_result(&cfg)).await.unwrap();
    assert!(report.ok && report.quarantined.is_empty(), "{report:?}");
    assert_eq!(report.promoted.get(&format!("{BOX_REFS}main")), Some(&agent));
    assert_eq!(report.promoted.get(&format!("{BOX_REFS}seed-wip")), Some(&seeded_wip), "the seeded WIP was never in the Mac's store");
    let wip = report.wip_ref.clone().expect("a snapshot was asked for");
    let snapshot = report.promoted.get(&format!("{BOX_REFS}{}", wip.trim_start_matches("refs/"))).expect("the snapshot promoted").clone();
    assert_eq!(repo.git(&["show", &format!("{snapshot}:b.txt")]), "b, edited");
    let after = repo.state();
    assert_eq!((after.index, after.status, after.stash), (before.index, before.status, before.stash));
    assert_eq!(repo.git(&["rev-parse", "main"]), repo.head(), "HEAD and the branch did not move");
    let row = ai_env_cli::bridge::workspace::rows::row_of(&paths, &ws).unwrap().unwrap();
    assert_eq!(row.last_fetch_vm.as_deref(), Some(super::fixture::VM));
    assert_eq!(row.fetched.get(&format!("{BOX_REFS}main")), Some(&agent));
    let listed: BTreeMap<String, String> = repo
        .git(&["for-each-ref", "--format=%(refname) %(objectname)", BOX_REFS, BOX_QUARANTINE_REFS])
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(n, id)| (n.to_string(), id.to_string()))
        .collect();
    assert_eq!(row.fetched, listed, "the row holds the box refs as the fetch left them");
    // Nothing changed in the VM since: nothing new, and no new snapshot.
    let again = fetch(&ctx, FetchOpts { wip: false, max_bytes: 1 << 20 }).await.unwrap();
    assert!(again.ok && again.promoted.is_empty() && again.bytes == 0, "{again:?}");
}

/// The per-result trigger end to end: requests coalesce into fetches on
/// the session's runtime (a burst of five before the task first runs is one
/// `POST /codeout`, and nothing is fetched after it while no result asks);
/// the fetch brings the VM's new snapshot into `box/wip/*`; closing returns
/// the last report within its budget.
#[tokio::test]
async fn the_trigger_fetches_after_results_without_blocking() {
    use ai_env_cli::bridge::codeout::{CodeoutTrigger, CLOSE_WAIT};
    let w = World::new();
    let repo = w.repo("app");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = Arc::new(FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects")));
    let (fake_api, t, c) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    ensure_workspace(&ensure_ctx(&fake_api, &vm, &paths, &cfg, &t, &c, &ws, &progress), None, SeedWant::Auto).await.unwrap();
    std::fs::write(vm.dir.join("edit.txt"), "the agent's edit\n").unwrap();
    let ctx = CodeoutCtx { api: Arc::new(api().await), dp: vm.clone(), tokens: Arc::new(Tokens), paths: paths.clone(), cfg: Arc::new(cfg.clone()), target: target(), ws: ws.clone(), capture_settings: false, transcript: None };
    let fetches = || vm.calls().iter().filter(|c| c.starts_with("POST /codeout")).count();
    let trigger = CodeoutTrigger::spawn(ctx);
    let asked = std::time::Instant::now();
    // No await in between: the task (on this current-thread runtime) has not run yet.
    for _ in 0..5 {
        trigger.request();
    }
    assert!(asked.elapsed() < std::time::Duration::from_millis(50), "a request never waits for its fetch");
    let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while trigger.last().is_none() && std::time::Instant::now() < until {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let first = trigger.last().expect("a fetch ran");
    assert!(first.ok, "{first:?}");
    let snapshot = first.wip_ref.clone().expect("a snapshot");
    assert!(first.promoted.contains_key(&format!("{BOX_REFS}{}", snapshot.trim_start_matches("refs/"))), "{first:?}");
    assert_eq!(repo.git(&["show", &format!("{BOX_REFS}{}:edit.txt", snapshot.trim_start_matches("refs/"))]), "the agent's edit");
    // A quiet second: the burst was one fetch, and none follows it.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(fetches(), 1, "five requests before the first fetch started: {:?}", vm.calls());
    let closed = std::time::Instant::now();
    let last = trigger.close(CLOSE_WAIT).await.expect("the last report");
    assert!(last.ok && closed.elapsed() < CLOSE_WAIT + std::time::Duration::from_millis(500), "{:?}", closed.elapsed());
    assert_eq!(fetches(), 1, "closing starts none");
}

/// A real remote named `box` would share `refs/remotes/box/*`: refused before anything is asked.
#[tokio::test]
async fn a_real_remote_named_box_is_refused() {
    let w = World::new();
    let repo = w.repo("app");
    repo.git(&["remote", "add", "box", "https://example.invalid/x.git"]);
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let ctx = CodeoutCtx { api: Arc::new(api().await), dp: Arc::new(vm), tokens: Arc::new(Tokens), paths, cfg: Arc::new(cfg.clone()), target: target(), ws, capture_settings: false, transcript: None };
    let e = fetch(&ctx, FetchOpts::per_result(&cfg)).await.unwrap_err();
    assert!(e.to_string().contains("remote named box"), "{e}");
    assert!(ctx.dp.calls().is_empty(), "nothing was asked of the VM");
}

// ---- phase 4 F4 -------------------------------------------------------------------------------

/// `git <args>` in the VM's copy `dir` as its agent runs it (no hooks, no
/// automatic maintenance: a background repack after a commit races the next
/// git's loose objects): its stdout, trimmed.
fn as_agent(dir: &Path, args: &[&str]) -> String {
    let mut all = vec!["-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=false", "-c", "gc.auto=0"];
    all.extend_from_slice(args);
    git(dir, &all)
}

/// `ai-env box fetch <dir> <args>` on the rig, which must exit 0: its stdout
/// and its stderr (`token` masked in a failure's message).
fn box_fetch(rig: &super::common::remote::RemoteRig, dir: &str, args: &[&str], token: &str) -> (String, String) {
    let mut all = vec!["box", "fetch", dir];
    all.extend_from_slice(args);
    let o = rig.run(&all, None);
    let (out, err) = (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned());
    assert!(o.status.success(), "box fetch {args:?}: {}{}", out.replace(token, "<TOKEN>"), err.replace(token, "<TOKEN>"));
    (out, err)
}

/// The files under `dir` (links not followed) whose path below it or whose bytes hold `needle`.
fn holding(dir: &Path, needle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().filter_map(Result::ok) {
            let path = e.path();
            let rel = path.strip_prefix(dir).unwrap_or(&path).display().to_string();
            let held = match e.file_type() {
                Ok(t) if t.is_dir() => {
                    dirs.push(path.clone());
                    false
                }
                Ok(t) if t.is_file() => std::fs::read(&path).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle.as_bytes())),
                _ => false,
            };
            if held || rel.contains(needle) {
                out.push(rel.replace(needle, "<TOKEN>"));
            }
        }
    }
    out
}

/// S8 phase 4 (review CUSTODY-3), through the endpoint and the native
/// shim's real helper: the agent, which can read the setup-token in the VM,
/// commits, then names refs after it: a branch, one under a name the box
/// namespace keeps (`wip/`), a snapshot ref, and the branch it checks out
/// (an edit left uncommitted on it). `box fetch --dry-run`, as text and as
/// JSON, and `box fetch --wip` exit 0 and count those refs, never naming
/// one, while the agent's commit comes back as `refs/remotes/box/main` and
/// its edit as a `box/wip/*` snapshot. Then a snapshot ref named after the
/// token that the VM's helper takes for its newest, the checkout unchanged
/// since (the code-out's `wip_ref`), is not the `--json` report's either.
/// The token is in no output, no git argument the Mac ran, no ref of the
/// Mac's, and no file under the bridge dir or the Mac's `.git` (its bytes
/// or its name).
#[test]
fn a_credential_shaped_vm_ref_name_is_never_promoted_recorded_or_printed() {
    let mut p = super::common::Harness::prepare();
    let rig = p.rig();
    let (token, work) = (rig.token().to_string(), rig.work());
    let dir = work.display().to_string();
    let masked = |text: &str| text.replace(&token, "<TOKEN>");
    rig.start_vm();
    let o = rig.run(&["box", "seed", &dir, "--json"], None);
    assert!(o.status.success(), "box seed: {}", String::from_utf8_lossy(&o.stderr));
    let vm = rig.vm_path(&work);
    std::fs::write(vm.join("agent.txt"), "from the VM\n").unwrap();
    as_agent(&vm, &["add", "-A"]);
    as_agent(&vm, &["commit", "-q", "-m", "the agent's commit"]);
    let commit = as_agent(&vm, &["rev-parse", "HEAD"]);
    as_agent(&vm, &["branch", &format!("x-{token}")]);
    as_agent(&vm, &["branch", &format!("wip/{token}")]);
    as_agent(&vm, &["update-ref", &format!("refs/wip/zz-{token}"), "HEAD"]);
    as_agent(&vm, &["checkout", "-q", "-b", &format!("y-{token}")]);
    std::fs::write(vm.join("agent.txt"), "from the VM, not committed yet\n").unwrap();
    let mut said: Vec<String> = Vec::new();
    // What would move: the four refs counted, the branch checked out not named either.
    let (out, err) = box_fetch(rig, &dir, &["--dry-run"], &token);
    said.extend([out.clone(), err]);
    assert!(!out.contains(&token), "{}", masked(&out));
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].ends_with(" on a branch whose name looks like a credential)"), "{out}");
    assert_eq!(lines[1..], ["  refs/heads/main -> refs/remotes/box/main: new", "  4 VM ref(s) skipped: a name that looks like a credential (not shown)", "nothing was fetched"], "{out}");
    let (out, err) = box_fetch(rig, &dir, &["--dry-run", "--json"], &token);
    said.extend([out.clone(), err]);
    assert!(!out.contains(&token), "{}", masked(&out));
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!((v["hidden"].as_u64(), &v["branch"], v["refs"].as_array().map(Vec::len)), (Some(4), &serde_json::Value::Null, Some(1)), "{v}");
    // The fetch: the commit and the snapshot of the edit promoted, the four refs left in the VM.
    let (out, err) = box_fetch(rig, &dir, &["--wip"], &token);
    said.extend([out.clone(), err.clone()]);
    assert!(!out.contains(&token) && !err.contains(&token), "{}{}", masked(&out), masked(&err));
    assert!(err.contains("4 VM ref(s) skipped: a name that looks like a credential (not shown)"), "{err}");
    assert_eq!(git(&work, &["rev-parse", "refs/remotes/box/main"]), commit);
    let snapshot = git(&work, &["for-each-ref", "--format=%(objectname)", "refs/remotes/box/wip/"]);
    assert_eq!(git(&work, &["show", &format!("{snapshot}:agent.txt")]), "from the VM, not committed yet");
    // A snapshot ref of the agent's, the newest by its name, of the unchanged checkout: the helper's own `wip_ref`.
    let tree = as_agent(&vm, &["rev-parse", &format!("{snapshot}^{{tree}}")]);
    let theirs = as_agent(&vm, &["commit-tree", &tree, "-p", "HEAD", "-m", "the agent's snapshot"]);
    as_agent(&vm, &["update-ref", &format!("refs/wip/zz-{token}-9"), &theirs]);
    let (out, err) = box_fetch(rig, &dir, &["--wip", "--json"], &token);
    said.extend([out.clone(), err]);
    assert!(!out.contains(&token), "{}", masked(&out));
    let report = &serde_json::from_str::<serde_json::Value>(&out).unwrap()["report"];
    assert_eq!(as_agent(&vm, &["for-each-ref", "--format=%(refname)", "refs/wip/"]).lines().count(), 3, "the helper took the agent's ref for its snapshot: it made none");
    assert!(report["wip_ref"].is_null() && report["note"].as_str().is_some_and(|n| n.contains("5 VM ref(s) skipped")), "{report}");
    // Nowhere on the Mac.
    assert!(said.iter().all(|s| !s.contains(&token)), "an output names it");
    let refs = git(&work, &["for-each-ref", "--format=%(refname)"]);
    assert!(!refs.contains(&token), "{}", masked(&refs));
    let argv: Vec<String> = rig.mac_git_calls().iter().flat_map(|c| c.args.clone()).filter(|a| a.contains(&token)).collect();
    assert!(argv.is_empty(), "a git argument of the Mac's: {}", masked(&argv.join(" ")));
    for root in [work.join(".git"), rig.bridge()] {
        assert_eq!(holding(&root, &token), Vec::<String>::new(), "under {}", root.display());
    }
}

// ---- phase 4 F8 -------------------------------------------------------------------------------

/// The VM branches `names`, each at a commit of its own on `base` made in
/// the VM repository `vm` (no ref is written there: the Mac's disk could
/// not hold the names side by side).
fn branches_at(vm: &Path, base: &str, names: &[&str]) -> BTreeMap<String, String> {
    names.iter().enumerate().map(|(i, name)| (format!("refs/heads/{name}"), commit_with(vm, base, &[("100644", &format!("f{i}.txt"), b"x\n")], name))).collect()
}

/// VM branches the Mac's disk takes for one name beyond ASCII case (É and
/// é, NFC and NFD, `ſ` and s, ß and ss, ς and σ), which one `update-ref`
/// transaction on APFS cannot write both of: two imports in a row both go
/// through, `main`, the snapshot and the first of each pair promoted (named
/// in NFC, as git on macOS lists refs), the second of each skipped and
/// named; the second import moves the same refs.
#[test]
fn branches_the_macs_disk_folds_beyond_ascii_never_fail_the_import() {
    use ai_env_cli::wire::workspace::nfc;
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let pairs = [("\u{c9}t\u{e9}", "\u{e9}t\u{e9}"), ("cafe\u{301}", "caf\u{e9}"), ("fix-sort", "fix-\u{17f}ort"), ("strasse", "stra\u{df}e"), ("\u{3c2}x", "\u{3c3}x")];
    let names: Vec<&str> = pairs.iter().flat_map(|(a, b)| [*a, *b]).chain(["main"]).collect();
    let mut refs = branches_at(&vm, &base, &names);
    let snapshot = commit_with(&vm, &base, &[("100644", "wip.txt", b"uncommitted\n")], "a snapshot");
    refs.insert("refs/wip/20261013T080000Z-1".to_string(), snapshot.clone());
    let file = w.root.join("codeout.pack");
    let manifest = codeout_of(&vm, &refs, &base, &file);
    let mut promoted: BTreeMap<String, String> = pairs.iter().map(|(first, _)| *first).chain(["main"]).map(|b| (format!("{BOX_REFS}{}", nfc(b)), refs[&format!("refs/heads/{b}")].clone())).collect();
    promoted.insert(format!("{BOX_REFS}wip/20261013T080000Z-1"), snapshot);
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    for round in 1..=2 {
        let got = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap_or_else(|e| panic!("import {round}: {e}"));
        assert_eq!(got.promoted, promoted, "import {round}");
        for (_, second) in pairs {
            assert!(got.skipped.iter().any(|s| s.starts_with(&format!("refs/heads/{second} "))), "import {round}: {second} is named: {:?}", got.skipped);
        }
        let listed: BTreeMap<String, String> = mac.git(&["for-each-ref", "--format=%(refname) %(objectname)", BOX_REFS]).lines().filter_map(|l| l.split_once(' ')).map(|(n, id)| (n.to_string(), id.to_string())).collect();
        assert_eq!(listed, promoted, "import {round}: the box refs as git lists them");
        assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "import {round}: no incoming ref is left");
    }
}

/// Box refs already on the Mac meet the VM's names as the Mac's disk folds
/// them: a VM `Été` beside `box/été`, and `fix-ſort` beside `box/fix-sort`,
/// are skipped and named, the existing ref left as it was (before, it was
/// written over); a VM `ünter` above `box/Ünter/x` is skipped (before, the
/// transaction failed on the directory, and every import after it); a VM
/// `café` spelled NFD and `box/café` are one ref: an update.
#[test]
fn existing_box_refs_meet_the_vms_names_as_the_macs_disk_folds_them() {
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    for existing in ["\u{e9}t\u{e9}", "fix-sort", "\u{dc}nter/x", "caf\u{e9}"] {
        mac.git(&["update-ref", &format!("{BOX_REFS}{existing}"), &base]);
    }
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let refs = branches_at(&vm, &base, &["\u{c9}t\u{e9}", "fix-\u{17f}ort", "\u{fc}nter", "cafe\u{301}", "main"]);
    let file = w.root.join("codeout.pack");
    let manifest = codeout_of(&vm, &refs, &base, &file);
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let got = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap();
    let promoted = BTreeMap::from([(format!("{BOX_REFS}caf\u{e9}"), refs["refs/heads/cafe\u{301}"].clone()), (format!("{BOX_REFS}main"), refs["refs/heads/main"].clone())]);
    assert_eq!(got.promoted, promoted, "{got:?}");
    for vm_ref in ["\u{c9}t\u{e9}", "fix-\u{17f}ort", "\u{fc}nter"] {
        assert!(got.skipped.iter().any(|s| s.starts_with(&format!("refs/heads/{vm_ref} "))), "{vm_ref} is named: {:?}", got.skipped);
    }
    for existing in ["\u{e9}t\u{e9}", "fix-sort", "\u{dc}nter/x"] {
        assert_eq!(mac.git(&["rev-parse", &format!("{BOX_REFS}{existing}")]), base, "box/{existing} as it was");
    }
    assert_eq!(mac.git(&["for-each-ref", "--format=%(refname)", BOX_REFS]).lines().count(), 5, "box/été, box/fix-sort, box/Ünter/x, box/café, box/main");
    assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "no incoming ref is left");
}

// ---- S9: the lead's integration (G2's R2) ------------------------------------------------------

/// The helper lists only refs that name a commit, and the import holds that
/// rule whoever made the manifest (S9, G2's R2 moved into `import`): a
/// hostile `/codeout` manifest naming a tree as a branch and a blob and a
/// tree as snapshots, its `wip_ref` the blob's, has those three refs left
/// out once the pack is indexed: counted (`not_commits`), never named,
/// skipped or promoted, no `wip_ref` reported, the blob never in the Mac's
/// store; its clean branch is promoted. A manifest whose HEAD names a tree
/// is `not_seeded` (exit 9), and no ref moves.
#[test]
fn a_codeout_manifest_naming_a_tree_or_a_blob_promotes_neither() {
    use ai_env_cli::bridge::errors::BridgeError;
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let dev = commit_with(&vm, &base, &[("100644", "dev.txt", b"dev\n")], "dev");
    let o = git_out(&vm, &["hash-object", "-w", "--stdin"], Some(b"a blob, not a commit\n"));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let blob = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let tree = git(&vm, &["rev-parse", &format!("{dev}^{{tree}}")]);
    let snapshot = "refs/wip/20261018T090000Z-1".to_string();
    let refs = BTreeMap::from([
        ("refs/heads/dev".to_string(), dev.clone()),
        ("refs/heads/treed".to_string(), tree.clone()),
        (snapshot.clone(), blob.clone()),
        ("refs/wip/20261018T090000Z-2".to_string(), tree.clone()),
    ]);
    let file = w.root.join("codeout.pack");
    let manifest = CodeoutManifest { wip_ref: Some(snapshot), ..codeout_of(&vm, &refs, &base, &file) };
    assert_eq!(manifest.check(), Ok(()));
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let got = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap();
    assert_eq!((&got.promoted, got.quarantined.len(), got.not_commits, &got.skipped, got.hidden, &got.wip_ref), (&BTreeMap::from([(format!("{BOX_REFS}dev"), dev.clone())]), 0, 3, &Vec::<String>::new(), 0, &None), "{got:?}");
    assert_eq!(mac.git(&["for-each-ref", "--format=%(refname)", "refs/remotes/"]), format!("{BOX_REFS}dev"), "no box ref names the tree or the blob");
    assert!(!git_ok(&mac.dir, &["cat-file", "-e", &blob]), "the blob stayed in the scratch");
    assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "no incoming ref is left");
    // A HEAD naming a tree: the VM's repository has no commit checked out, as the helper answers.
    let before = mac.state();
    let headless = CodeoutManifest { head: tree, wip_ref: None, ..manifest };
    assert_eq!(headless.check(), Ok(()));
    let e = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &headless, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap_err();
    assert!(matches!(&e, BridgeError::WorkspaceRefused { code, message } if *code == ai_env_cli::wire::workspace::refusal::NOT_SEEDED && message.contains("its HEAD names a tree")), "{e:?}");
    assert_eq!(ai_env_cli::errors::CliError::from(e).exit_code(), 9);
    assert_eq!(mac.state().refs, before.refs, "no ref moved");
    assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "no incoming ref is left");
}

/// The commit-only rule meets the refs `box_refs` and the clash check let
/// through (S9, the lead's integration, I1-R3): a snapshot ref naming a
/// blob, skipped because its name folds to that of a commit's snapshot
/// `box_refs` took first, is named as skipped, never counted; as the
/// manifest's `wip_ref` its object is still read, and no `wip_ref` is
/// reported. A branch naming a tree that `box_refs` takes first is counted,
/// and the commit's branch whose name folds to its own is skipped and named.
#[test]
fn the_commit_only_rule_meets_what_box_refs_let_through() {
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let dev = commit_with(&vm, &base, &[("100644", "dev.txt", b"dev\n")], "dev");
    let o = git_out(&vm, &["hash-object", "-w", "--stdin"], Some(b"a blob, not a commit\n"));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let blob = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let tree = git(&vm, &["rev-parse", &format!("{dev}^{{tree}}")]);
    let snapshot = "refs/wip/20261018t090000z-1".to_string();
    let refs = BTreeMap::from([
        ("refs/heads/Twin".to_string(), tree),
        ("refs/heads/dev".to_string(), dev.clone()),
        ("refs/heads/twin".to_string(), dev.clone()),
        ("refs/wip/20261018T090000Z-1".to_string(), dev.clone()),
        (snapshot.clone(), blob.clone()),
    ]);
    let file = w.root.join("codeout.pack");
    let manifest = CodeoutManifest { wip_ref: Some(snapshot.clone()), ..codeout_of(&vm, &refs, &base, &file) };
    assert_eq!(manifest.check(), Ok(()));
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let got = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap();
    let promoted = BTreeMap::from([(format!("{BOX_REFS}dev"), dev.clone()), (format!("{BOX_REFS}wip/20261018T090000Z-1"), dev.clone())]);
    let skipped: Vec<&str> = got.skipped.iter().map(|s| s.split_once(' ').map_or(s.as_str(), |(r, _)| r)).collect();
    assert_eq!((&got.promoted, got.not_commits, skipped, got.hidden, &got.wip_ref), (&promoted, 1, vec!["refs/heads/twin", snapshot.as_str()], 0, &None), "{got:?}");
    assert_eq!(mac.git(&["for-each-ref", "--format=%(refname)", "refs/remotes/"]), format!("{BOX_REFS}dev\n{BOX_REFS}wip/20261018T090000Z-1"), "no box ref names the tree or the blob");
    assert!(!git_ok(&mac.dir, &["cat-file", "-e", &blob]), "the blob stayed in the scratch");
    assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "no incoming ref is left");
}

// ---- S10 F4: the import batch ---------------------------------------------------------------------

/// Every box and quarantine ref of the Mac's repository `dir` deleted, and
/// the clean-object caches of `paths` with them: the Mac as before its first
/// import.
fn forget_imports(dir: &Path, paths: &ai_env_cli::bridge::config::Paths) {
    forget_imports_refs_only(dir);
    let _ = std::fs::remove_dir_all(paths.scan_cache());
}

/// S10 F4's equivalence fixture: the batch import (one listing and one
/// scan of every ref's new objects, D8 from one walk of the trees, S9's
/// per-ref pass only on a finding) gives exactly S9's per-ref import, by
/// every field: promoted, quarantined, the findings in their order and
/// their places, skipped, tips. The VM's branches: two clean ones and a
/// twin, a secret per branch (in the tip, in a commit's history only, in a
/// commit message), a settings widening, a `.claude` link, a path named
/// after a key, a blob over the cap, one dirty blob shared by two branches
/// (both quarantined, each at its own path), and the fixture-blob attack: a
/// permissive file of the Mac's own history copied to
/// `.claude/settings.json` (the union never lists that blob, the Mac has
/// it; the walk of the tree reads it). And two trees written raw with a
/// mode past 32 bits that git reads wrapped and fsck lets through: a
/// `.claude/settings.json` of mode `40000100644` (git's `100644`) and a
/// `.claude` of mode `40000040000` (a tree), each a broad allow (the walk
/// reads each entry as git does: none is left out). The Mac's own settings
/// file holds a hook, which no ref that leaves it as it is has read (S9's
/// `unchanged`). Again with a warm clean cache, and a set of clean refs
/// alone (the batch's fast path): the same.
#[test]
fn the_import_batch_equals_the_per_ref_scan() {
    use ai_env_cli::bridge::codeout::import_per_ref;
    let w = World::new();
    let mac = w.repo("app");
    let permissive = "{\"permissions\": {\"allow\": [\"Bash(*)\"]}}\n";
    mac.write("fixtures/permissive.json", permissive);
    // The Mac's own settings hold a hook: D8 would flag it, but a VM's ref that leaves the file as it is is not read.
    mac.write(".claude/settings.json", "{\"hooks\": {\"Stop\": [{\"command\": \"x\"}]}}\n");
    let base = mac.commit("a fixture and the Mac's settings");
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let key = format!("{}{}", "AKIA", "Z3".repeat(8));
    let other = format!("{}{}", "AKIA", "Q7".repeat(8));
    let secret = format!("aws_access_key_id = {key}\n");
    let shared = format!("[default]\naws_access_key_id = {other}\n");
    // A widening of the VM's own (not the fixture's bytes).
    let allow: &[u8] = b"{\"permissions\":{\"allow\":[\"Bash(*)\"]}}\n";
    let big = vec![b'z'; 8192];
    let clean_a = commit_with(&vm, &base, &[("100644", "a.txt", b"a\n")], "clean a");
    let held = commit_with(&vm, &base, &[("100644", "old.conf", secret.as_bytes())], "a secret");
    let base_tree = git(&vm, &["rev-parse", &format!("{base}^{{tree}}")]);
    let history = git(&vm, &["commit-tree", &base_tree, "-p", &held, "-m", "the secret removed"]);
    let branches: Vec<(&str, String)> = vec![
        ("clean-a", clean_a.clone()),
        ("clean-b", commit_with(&vm, &base, &[("100644", "b.txt", b"b\n"), ("100644", "docs/settings.json", allow)], "clean b: no settings file of D8's")),
        ("twin", clean_a),
        ("secret", commit_with(&vm, &base, &[("100644", "deploy.conf", secret.as_bytes())], "a secret in the tip")),
        ("history", history),
        ("msg", commit_with(&vm, &base, &[("100644", "m.txt", b"m\n")], &format!("deploy with {key}"))),
        ("widen", commit_with(&vm, &base, &[("100644", ".claude/settings.local.json", allow)], "a broad allow")),
        ("link", commit_with(&vm, &base, &[("120000", "pkg/.claude", b"conf")], "a linked .claude")),
        ("pathname", commit_with(&vm, &base, &[("100644", &format!("notes/{key}.txt"), b"x\n")], "a path named after a key")),
        ("big", commit_with(&vm, &base, &[("100644", "assets/big.bin", &big)], "a blob over the cap")),
        ("shared-1", commit_with(&vm, &base, &[("100644", "x/creds.txt", shared.as_bytes())], "shared, here")),
        ("shared-2", commit_with(&vm, &base, &[("100644", "y/other.txt", shared.as_bytes())], "shared, there")),
        ("attack", commit_with(&vm, &base, &[("100644", ".claude/settings.json", permissive.as_bytes())], "the Mac's own fixture as the settings")),
        ("mode-file", raw_settings(&vm, &base, "40000", "40000100644", allow, "a settings file whose mode is past 32 bits")),
        ("mode-dir", raw_settings(&vm, &base, "40000040000", "100644", allow, "a .claude whose mode is past 32 bits")),
    ];
    let fixture = git(&mac.dir, &["rev-parse", &format!("{base}:fixtures/permissive.json")]);
    assert_eq!(git(&vm, &["rev-parse", &format!("{}:.claude/settings.json", branches[12].1)]), fixture, "the attack's settings blob is the Mac's fixture");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let run = |refs: &BTreeMap<String, String>, per_ref: bool| {
        let file = w.root.join("codeout.pack");
        let manifest = codeout_of(&vm, refs, &base, &file);
        let i = Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 4096, keep_wip: 64 };
        if per_ref {
            import_per_ref(&i).unwrap()
        } else {
            import(&i).unwrap()
        }
    };
    let refs: BTreeMap<String, String> = branches.iter().map(|(b, id)| (format!("refs/heads/{b}"), id.clone())).collect();
    let per = run(&refs, true);
    let names = |m: &BTreeMap<String, String>, prefix: &str| m.keys().map(|k| k.strip_prefix(prefix).unwrap_or(k).to_string()).collect::<Vec<_>>();
    assert_eq!(names(&per.promoted, BOX_REFS), ["clean-a", "clean-b", "twin"], "{per:?}");
    assert_eq!(names(&per.quarantined, BOX_QUARANTINE_REFS), ["attack", "big", "history", "link", "mode-dir", "mode-file", "msg", "pathname", "secret", "shared-1", "shared-2", "widen"], "{per:?}");
    let rules: Vec<(&str, &str)> = per.findings.iter().map(|f| (f.location.as_str(), f.rule.as_str())).collect();
    for (at, rule) in [
        (format!("{BOX_REFS}attack:.claude/settings.json"), "broad-allow"),
        (format!("{BOX_REFS}big:assets/big.bin"), "blob-too-large"),
        (format!("{BOX_REFS}link:pkg/.claude"), "settings-symlink"),
        (format!("{BOX_REFS}mode-dir:.claude/settings.json"), "broad-allow"),
        (format!("{BOX_REFS}mode-file:.claude/settings.json"), "broad-allow"),
        (format!("{BOX_REFS}shared-1:x/creds.txt"), "aws-access-key-id"),
        (format!("{BOX_REFS}shared-2:y/other.txt"), "aws-access-key-id"),
        (format!("{BOX_REFS}widen:.claude/settings.local.json"), "broad-allow"),
    ] {
        assert!(rules.contains(&(at.as_str(), rule)), "{at}: {rule} in {rules:?}");
    }
    assert!(per.findings.iter().any(|f| f.location == format!("commit {}:old.conf", &held[..12])), "the history's secret, by its commit: {rules:?}");
    assert!(per.findings.iter().any(|f| f.location.starts_with("commit ") && !f.location.contains(':')), "the message's: {rules:?}");
    assert!(per.findings.iter().any(|f| f.location == "a path name"), "the key-named path: {rules:?}");
    assert!(per.findings.iter().all(|f| !f.text().contains(&key) && !f.text().contains(&other)), "no value in a finding");
    // The batch, from the same start: every field equal.
    forget_imports(&mac.dir, &paths);
    let batch = run(&refs, false);
    assert_eq!(batch, per, "the batch is the per-ref scan");
    // Again with the clean cache the batch left: the same.
    forget_imports_refs_only(&mac.dir);
    assert_eq!(run(&refs, false), per, "a warm cache changes no finding");
    // Clean refs alone: the batch's fast path (no ref's own listing) gives the same as well.
    let clean: BTreeMap<String, String> = refs.iter().filter(|(r, _)| ["clean-a", "clean-b", "twin"].iter().any(|b| r.ends_with(&format!("/{b}")))).map(|(r, id)| (r.clone(), id.clone())).collect();
    forget_imports(&mac.dir, &paths);
    let per = run(&clean, true);
    forget_imports(&mac.dir, &paths);
    assert_eq!(run(&clean, false), per);
    assert_eq!(per.promoted.len(), 3);
}

/// A commit on `base` in `repo` whose tree is `base`'s with its `.claude`
/// replaced by one holding `settings.json` (`bytes`), both trees written
/// raw (`hash-object -t tree --literally`) with the mode given:
/// `claude_mode` for the `.claude` entry, `file_mode` for the file's (S10
/// F4: a mode git reads wrapped, as `40000100644` for `100644`).
fn raw_settings(repo: &Path, base: &str, claude_mode: &str, file_mode: &str, bytes: &[u8], msg: &str) -> String {
    let id_of = |o: std::process::Output| {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    let tree = |raw: &[u8]| id_of(git_out(repo, &["hash-object", "-t", "tree", "--literally", "-w", "--stdin"], Some(raw)));
    let entry = |mode: &str, name: &str, id: &str| [format!("{mode} {name}\0").into_bytes(), hex::decode(id).unwrap()].concat();
    let blob = id_of(git_out(repo, &["hash-object", "-w", "--stdin"], Some(bytes)));
    let claude = tree(&entry(file_mode, "settings.json", &blob));
    let mut root = Vec::new();
    for l in git(repo, &["ls-tree", base]).lines() {
        let (head, name) = l.split_once('\t').unwrap();
        let fields: Vec<&str> = head.split(' ').collect();
        root.extend(match name {
            ".claude" => entry(claude_mode, name, &claude),
            _ => entry(fields[0].trim_start_matches('0'), name, fields[2]),
        });
    }
    assert!(git(repo, &["ls-tree", base]).lines().any(|l| l.ends_with("\t.claude")), "the base holds a .claude");
    git(repo, &["commit-tree", &tree(&root), "-p", base, "-m", msg])
}

/// The box and quarantine refs of `dir` deleted, the clean-object cache kept.
fn forget_imports_refs_only(dir: &Path) {
    let refs = git(dir, &["for-each-ref", "--format=delete %(refname)", BOX_REFS, BOX_QUARANTINE_REFS]);
    let o = git_out(dir, &["update-ref", "--stdin"], Some(format!("{refs}\n").as_bytes()));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

/// `n` branches `b000`… in the VM's checkout `vm`, each at a commit of its
/// own on its HEAD (a file of its own), written by one `git fast-import` as
/// the agent: each branch's full name to its commit.
fn vm_branches(vm: &Path, n: usize) -> BTreeMap<String, String> {
    let head = as_agent(vm, &["rev-parse", "HEAD"]);
    let mut stream = String::new();
    for i in 0..n {
        let (name, body) = (format!("b{i:03}"), format!("branch {i}\n"));
        stream.push_str(&format!("commit refs/heads/{name}\ncommitter claude-agent <claude-agent@ai-env.invalid> 1791792000 +0000\ndata {}\n{name}\nfrom {head}\nM 100644 inline {name}.txt\ndata {}\n{body}\n", name.len() + 1, body.len()));
    }
    stream.push_str("done\n");
    let o = git_out(vm, &["-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0", "fast-import", "--quiet", "--done"], Some(stream.as_bytes()));
    assert!(o.status.success(), "fast-import: {}", String::from_utf8_lossy(&o.stderr));
    let made: BTreeMap<String, String> = git(vm, &["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads/b*"]).lines().filter_map(|l| l.split_once(' ')).map(|(r, id)| (r.to_string(), id.to_string())).collect();
    assert_eq!(made.len(), n, "the VM's branches");
    made
}

/// The most git runs the Mac makes for one `box fetch` that imports
/// [`BOUND_REFS`] new branches (S10 F4): what the fetch costs whatever the
/// refs' count, with room; S9's import alone ran four or more per ref.
const GIT_RUNS_MAX: usize = 40;
/// The VM branches of the git-call bound.
const BOUND_REFS: usize = 300;

/// S10 F4's bound on git calls, through the endpoint and the native shim's
/// real helper: 300 VM branches come out of one `box fetch` (`POST
/// /codeout`), each promoted at its commit, while the Mac's git (the fake
/// git's log, deterministic) runs at most [`GIT_RUNS_MAX`] times in all:
/// one `rev-list` (the union), no `ls-tree` (the settings walk reads the
/// trees with `cat-file`), no run per ref. S9's import ran a `rev-list`,
/// two `cat-file`s and an `ls-tree` per ref (over 1200 here).
#[test]
fn three_hundred_vm_branches_import_in_a_bounded_number_of_git_runs() {
    let mut p = super::common::Harness::prepare();
    let rig = p.rig();
    let (work, dir) = (rig.work(), rig.work().display().to_string());
    rig.start_vm();
    let o = rig.run(&["box", "seed", &dir, "--json"], None);
    assert!(o.status.success(), "box seed: {}", String::from_utf8_lossy(&o.stderr));
    let branches = vm_branches(&rig.vm_path(&work), BOUND_REFS);
    let from = rig.mac_git_calls().len();
    let t = std::time::Instant::now();
    let o = rig.run(&["box", "fetch", &dir, "--json"], None);
    let took = t.elapsed();
    assert!(o.status.success(), "box fetch: {}", String::from_utf8_lossy(&o.stderr));
    let boxed: BTreeMap<String, String> = git(&work, &["for-each-ref", "--format=%(refname) %(objectname)", &format!("{BOX_REFS}b*")]).lines().filter_map(|l| l.split_once(' ')).map(|(r, id)| (r.replace(BOX_REFS, "refs/heads/"), id.to_string())).collect();
    assert!(boxed == branches, "{} of {} branches promoted", boxed.len(), branches.len());
    let ran = rig.mac_git_calls()[from..].to_vec();
    let mut subs: BTreeMap<String, usize> = BTreeMap::new();
    for call in &ran {
        *subs.entry(call.sub().unwrap_or("-").to_string()).or_default() += 1;
    }
    eprintln!("box fetch of {BOUND_REFS} VM branches: {} git runs on the Mac in {took:?}: {subs:?}", ran.len());
    assert!(ran.len() <= GIT_RUNS_MAX, "{} git runs for {BOUND_REFS} refs: {subs:?}", ran.len());
    assert_eq!((subs.get("rev-list").copied(), subs.get("ls-tree").copied()), (Some(1), None), "{subs:?}");
}

// ---- S10 phase 4: the import's bounds (F4-WALK-1, F4-WALK-2) ----------------------------------------

/// `bytes` written as a blob in `repo`: its id.
fn blob_in(repo: &Path, bytes: &[u8]) -> String {
    let o = git_out(repo, &["hash-object", "-w", "--stdin"], Some(bytes));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A tree written in `repo` by `git mktree` from `ls-tree` lines (`<mode>
/// <type> <id>\t<name>`, any order; names git takes apart, a case apart
/// too, as they are): its id.
fn mktree(repo: &Path, lines: &[String]) -> String {
    let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
    let o = git_out(repo, &["mktree"], Some(input.as_bytes()));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A commit on `base` in `repo` whose tree is `base`'s with `name` the tree `tree` too.
fn commit_with_tree(repo: &Path, base: &str, name: &str, tree: &str, msg: &str) -> String {
    let mut lines: Vec<String> = git(repo, &["ls-tree", base]).lines().map(str::to_string).collect();
    lines.push(format!("040000 tree {tree}\t{name}"));
    git(repo, &["commit-tree", &mktree(repo, &lines), "-p", base, "-m", msg])
}

/// S10 phase 4 (F4-WALK-1): a ref whose `.claude` holds 64 names that fold
/// to `settings.json`, all one blob of 40 `bypassPermissions` strings,
/// would copy the blob's 40 findings to each of its 64 paths (2560, or
/// tens of gigabytes from 13 824 names over a larger blob). The import keeps
/// the tip's first `SETTINGS_FINDINGS_MAX` settings findings (every rule
/// among them: the blob has one), all at the first path, the same in both
/// modes; the ref is quarantined, a clean one beside it promoted.
#[test]
fn a_tips_settings_findings_are_capped_alike_in_both_modes() {
    use ai_env_cli::bridge::codeout::import_per_ref;
    use ai_env_cli::bridge::workspace::blobscan::SETTINGS_FINDINGS_MAX;
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let keys: Vec<String> = (0..40).map(|i| format!("  \"k{i}\": \"bypassPermissions\"")).collect();
    let blob = blob_in(&vm, format!("{{\n{}\n}}\n", keys.join(",\n")).as_bytes());
    // Each case of the first six letters: 64 names git keeps apart, one file on the Mac's disk.
    let names: Vec<String> = (0..64u32).map(|mask| "settings.json".chars().enumerate().map(|(i, c)| if (mask >> i) & 1 == 1 { c.to_ascii_uppercase() } else { c }).collect()).collect();
    let claude = mktree(&vm, &names.iter().map(|n| format!("100644 blob {blob}\t{n}")).collect::<Vec<_>>());
    let wide = commit_with_tree(&vm, &base, ".claude", &claude, "one settings blob at 64 names");
    let clean = commit_with(&vm, &base, &[("100644", "clean.txt", b"c\n")], "clean");
    let refs = BTreeMap::from([("refs/heads/wide".to_string(), wide.clone()), ("refs/heads/clean".to_string(), clean.clone())]);
    let file = w.root.join("codeout.pack");
    let manifest = codeout_of(&vm, &refs, &base, &file);
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let i = Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 };
    let per = import_per_ref(&i).unwrap();
    assert_eq!((&per.promoted, &per.quarantined), (&BTreeMap::from([(format!("{BOX_REFS}clean"), clean)]), &BTreeMap::from([(format!("{BOX_QUARANTINE_REFS}wide"), wide)])), "{per:?}");
    assert_eq!(per.findings.len(), SETTINGS_FINDINGS_MAX, "the first: {:?}", per.findings.first());
    let first = format!("{BOX_REFS}wide:.claude/{}", names.iter().min().unwrap());
    assert!(per.findings.iter().all(|f| f.rule == "bypass-permissions" && f.location == first && f.object.as_deref() == Some(&blob[..12])), "{:?}", per.findings.iter().find(|f| f.location != first || f.rule != "bypass-permissions"));
    forget_imports(&mac.dir, &paths);
    assert_eq!(import(&i).unwrap(), per, "the batch keeps the same");
}

/// S10 phase 4 (F4-WALK-2): a settings blob over the cap is never read,
/// and never passes for a clean file. The Mac's own history holds a JSON
/// object of over 2 MiB that D8 finds nothing in (`fixtures/big.json`); a
/// VM ref copies it to `.claude/settings.json` (the union never lists that
/// blob: the Mac has it). Under a 1 MiB cap the ref is quarantined with
/// `blob-too-large` at that path, once, the same in both modes (read
/// whole, D8 found nothing and promoted it).
#[test]
fn a_settings_blob_over_the_cap_is_quarantined_unread_in_both_modes() {
    use ai_env_cli::bridge::codeout::import_per_ref;
    let w = World::new();
    let mac = w.repo("app");
    let big = format!("{{{}}}\n", " ".repeat(2 << 20));
    mac.write("fixtures/big.json", &big);
    let base = mac.commit("a large fixture");
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let copied = commit_with(&vm, &base, &[("100644", ".claude/settings.json", big.as_bytes())], "the fixture as the settings");
    let blob = git(&mac.dir, &["rev-parse", &format!("{base}:fixtures/big.json")]);
    assert_eq!(git(&vm, &["rev-parse", &format!("{copied}:.claude/settings.json")]), blob, "the Mac's own blob");
    let refs = BTreeMap::from([("refs/heads/copied".to_string(), copied.clone())]);
    let file = w.root.join("codeout.pack");
    let manifest = codeout_of(&vm, &refs, &base, &file);
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let i = Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 1 << 20, keep_wip: 64 };
    let per = import_per_ref(&i).unwrap();
    assert_eq!(per.quarantined, BTreeMap::from([(format!("{BOX_QUARANTINE_REFS}copied"), copied)]), "{per:?}");
    let at = format!("{BOX_REFS}copied:.claude/settings.json");
    let found: Vec<(&str, Option<&str>, &str)> = per.findings.iter().map(|f| (f.location.as_str(), f.object.as_deref(), f.rule.as_str())).collect();
    assert_eq!(found, [(at.as_str(), Some(&blob[..12]), "blob-too-large")]);
    forget_imports(&mac.dir, &paths);
    assert_eq!(import(&i).unwrap(), per, "the batch: the same");
}

/// S10 phase 4 (F4-WALK-1): a ref whose tree routes more paths to its
/// settings than the import walks (41 trees, every level naming the one
/// below twice: 2^40 paths to one `.claude/settings.json`, in a pack of a
/// few KB that git's fsck lets through) refuses the import at once, where
/// S9's `ls-tree -r` would list every path: no ref moves, box or
/// quarantine, and no incoming ref is left.
#[test]
fn a_tree_routing_too_many_settings_paths_refuses_the_import() {
    use ai_env_cli::bridge::errors::BridgeError;
    let w = World::new();
    let mac = w.repo("app");
    let base = mac.head();
    let vm = w.root.join("vm");
    git(&w.root, &["clone", "-q", &mac.dir.display().to_string(), "vm"]);
    let blob = blob_in(&vm, b"{}\n");
    let claude = mktree(&vm, &[format!("100644 blob {blob}\tsettings.json")]);
    let mut tree = mktree(&vm, &[format!("040000 tree {claude}\t.claude")]);
    for _ in 0..40 {
        tree = mktree(&vm, &[format!("040000 tree {tree}\ta"), format!("040000 tree {tree}\tb")]);
    }
    let dag = commit_with_tree(&vm, &base, "dag", &tree, "2^40 paths to one settings file");
    let refs = BTreeMap::from([("refs/heads/dag".to_string(), dag)]);
    let file = w.root.join("codeout.pack");
    let manifest = codeout_of(&vm, &refs, &base, &file);
    let before = mac.state();
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &mac.dir, None).unwrap();
    let t = std::time::Instant::now();
    let e = import(&Import { paths: &paths, cfg: &cfg, ws: &ws, manifest: &manifest, pack: &file, haves: std::slice::from_ref(&base), max_blob: 64 << 20, keep_wip: 64 }).unwrap_err();
    assert!(t.elapsed() < std::time::Duration::from_secs(30), "{:?}", t.elapsed());
    assert!(matches!(&e, BridgeError::WorkspaceFailed { code, message } if *code == ai_env_cli::wire::workspace::refusal::GIT_FAILED && message.contains("routes more settings paths than the import walks")), "{e:?}");
    for name in [format!("{BOX_REFS}dag"), format!("{BOX_QUARANTINE_REFS}dag")] {
        assert!(!git_ok(&mac.dir, &["rev-parse", "--verify", "--quiet", &name]), "{name}");
    }
    assert_eq!(mac.git(&["for-each-ref", INCOMING_REFS]), "", "no incoming ref is left");
    assert_eq!(mac.state().refs, before.refs, "no ref moved");
}
