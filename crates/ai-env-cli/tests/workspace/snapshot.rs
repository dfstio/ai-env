//! tests/workspace.rs area: the WIP (D2): every kind of uncommitted change
//! rides one scanned snapshot and stays uncommitted in the VM (staged,
//! unstaged, deleted, renamed, untracked; a symlink as a link, the exec bit,
//! binary bytes), ignored files never leave, special files and nested
//! repositories are noted, the `[seed]` caps refuse naming the largest (a
//! path a rule matches never, nor a failure's text), the same dirty state
//! gives the same commits, and the user's repository is never touched.
use super::fixture::{api, caps, ensure_ctx, git, target, FakeVm, Repo, World};
use ai_env_cli::bridge::errors::BridgeError;
use ai_env_cli::bridge::workspace::{code, ensure_workspace, prepare, prepare_cancellable, resolve, EnsureOutcome, SeedLimits, SeedProgress, SeedWant};
use ai_env_cli::errors::CliError;
use std::os::unix::fs::PermissionsExt;

/// A repository with every kind of change against its last commit.
fn every_change(w: &World) -> Repo {
    let repo = w.repo("app");
    for (f, text) in [("staged.txt", "one\n"), ("unstaged.txt", "one\n"), ("gone.txt", "bye\n"), ("old-name.txt", "moving\n"), ("tool.sh", "#!/bin/sh\necho hi\n")] {
        repo.write(f, text);
    }
    repo.write(".gitignore", "*.log\nprivate/\n");
    repo.commit("base");
    repo.write("staged.txt", "two\n");
    repo.git(&["add", "staged.txt"]);
    repo.write("unstaged.txt", "two\n");
    std::fs::remove_file(repo.dir.join("gone.txt")).unwrap();
    repo.git(&["mv", "old-name.txt", "new-name.txt"]);
    repo.write("untracked/new.txt", "new\n");
    repo.write("debug.log", "ignored\n");
    repo.write("private/key.txt", "ignored too\n");
    std::os::unix::fs::symlink("staged.txt", repo.dir.join("link")).unwrap();
    std::fs::set_permissions(repo.dir.join("tool.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    repo.write_bytes("blob.bin", &[0, 0x9f, 0x92, 0x96, 0xff, 0, 1, b'\n', 0]);
    repo
}

#[tokio::test]
async fn every_kind_of_change_rides_and_stays_uncommitted_in_the_vm() {
    let w = World::new();
    let repo = every_change(&w);
    let before = repo.state();
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, target, caps) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let ctx = ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress);
    assert!(matches!(ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap(), EnsureOutcome::Seeded { wip: Some(_), .. }));
    assert_eq!(repo.state(), before, "the user's repository untouched");
    let v = &vm.dir;
    let status = |dir: &std::path::Path| String::from_utf8_lossy(&super::fixture::git_out(dir, &["status", "--porcelain", "--untracked-files=all"], None).stdout).into_owned();
    assert_eq!(status(v), status(&repo.dir), "staged, unstaged, deleted, renamed, untracked: as on the Mac");
    assert!(status(v).contains("R  old-name.txt -> new-name.txt") && status(v).contains(" D gone.txt") && status(v).contains("?? untracked/new.txt"), "{}", status(v));
    assert_eq!(std::fs::read_link(v.join("link")).unwrap(), std::path::Path::new("staged.txt"), "a symlink is carried as a link");
    assert_eq!(std::fs::metadata(v.join("tool.sh")).unwrap().permissions().mode() & 0o111, 0o111, "the exec bit");
    assert_eq!(std::fs::read(v.join("blob.bin")).unwrap(), std::fs::read(repo.dir.join("blob.bin")).unwrap(), "binary bytes");
    assert_eq!(std::fs::read_to_string(v.join("unstaged.txt")).unwrap(), "two\n");
    assert_eq!(git(v, &["show", ":staged.txt"]), "two", "the staged version is the VM's index");
    for ignored in ["debug.log", "private/key.txt"] {
        assert!(!v.join(ignored).exists(), "{ignored} never leaves the Mac");
    }
    assert!(!vm.bodies.lock().unwrap().iter().any(|b| b.windows(11).any(|x| x == b"ignored too")), "nor its bytes");
}

/// One dirty state, one pair of commits, whatever the time; a change gives
/// new ones. A clean worktree carries no WIP.
#[test]
fn the_same_dirty_state_gives_the_same_commits() {
    let w = World::new();
    let repo = every_change(&w);
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let lim = SeedLimits::cli(&cfg, None);
    let first = prepare(&paths, &cfg, &ws, &lim).unwrap().summary().wip.expect("a WIP");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second = prepare(&paths, &cfg, &ws, &lim).unwrap().summary().wip.expect("a WIP");
    assert_eq!(first, second);
    assert!(first.index_commit.is_some(), "something is staged");
    repo.write("unstaged.txt", "three\n");
    let third = prepare(&paths, &cfg, &ws, &lim).unwrap().summary().wip.unwrap();
    assert_ne!(third.commit, first.commit);
    assert_eq!(third.index_commit, first.index_commit, "the index did not change");
    let clean = w.repo("clean");
    let ws = resolve(&cfg, &clean.dir, None).unwrap();
    assert_eq!(prepare(&paths, &cfg, &ws, &lim).unwrap().summary().wip, None);
    // The scratch repositories are gone with what prepared them.
    let tmp = paths.tmp();
    assert!(std::fs::read_dir(&tmp).map(|d| d.count()).unwrap_or(0) == 0, "nothing left in {}", tmp.display());
    assert_eq!(std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777, 0o700);
}

/// An edit at the same size, in the second the index was last written: git
/// would take its cached stat for clean if the index copy looked newer than
/// the file, so the copies keep the index's own mtime and git re-reads it.
#[test]
fn a_same_size_edit_in_the_indexs_own_second_is_carried() {
    let w = World::new();
    let repo = w.repo("app");
    for round in 0..5 {
        repo.write("f.txt", &format!("version {round}a\n"));
        repo.commit(&format!("round {round}"));
        repo.write("f.txt", &format!("version {round}b\n"));
        let (paths, cfg) = (w.paths(), w.cfg(""));
        let ws = resolve(&cfg, &repo.dir, None).unwrap();
        let s = prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap().summary();
        assert_eq!(s.wip.map(|w| w.changed), Some(1), "round {round}: the edit rides");
    }
}

/// Special files and nested repositories are never carried (git lists no
/// FIFO; a nested repository is noted).
#[test]
fn fifos_and_nested_repositories_are_not_carried() {
    let w = World::new();
    let repo = w.repo("app");
    let _inner = Repo::create(&repo.dir.join("inner"));
    let fifo = std::ffi::CString::new(repo.dir.join("pipe").into_os_string().into_encoded_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    repo.write("real.txt", "x\n");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let s = prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap().summary();
    assert_eq!(s.wip.as_ref().map(|w| w.untracked), Some(1), "{s:?}");
    assert!(s.notes.iter().any(|n| n.contains("inner/ is a nested repository")), "{:?}", s.notes);
    assert_eq!(s.wip.as_ref().map(|w| w.changed), Some(1), "only real.txt: {s:?}");
}

fn refused_wip(e: BridgeError) -> String {
    assert!(matches!(&e, BridgeError::WorkspaceRefused { code: c, .. } if *c == code::WIP_TOO_LARGE), "{e:?}");
    let text = e.to_string();
    assert_eq!(CliError::from(e).exit_code(), 9);
    text
}

/// `[seed]`'s caps on the uncommitted changes: the untracked files' count,
/// one file's size (untracked or tracked), all of them; over one, exit 9
/// naming the largest (at most five), before anything is sent.
#[test]
fn the_wip_caps_refuse_naming_the_largest() {
    let w = World::new();
    let repo = w.repo("app");
    let paths = w.paths();
    for (i, n) in [(1, 3000), (2, 1000), (3, 2000)] {
        repo.write(&format!("u{i}.txt"), &"x".repeat(n));
    }
    let cfg = w.cfg("[seed]\nmax_untracked_files = 2\n");
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let text = refused_wip(prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap_err());
    assert!(text.contains("3 untracked files, over [seed].max_untracked_files (2)") && text.contains("u1.txt (2.9 KiB), u3.txt (2.0 KiB), u2.txt (1000 B)"), "{text}");
    // One file over max_blob_mib: an untracked one, then a tracked one.
    let big = "y".repeat(1024 * 1024 + 1);
    repo.write("big.dat", &big);
    let cfg = w.cfg("[seed]\nmax_blob_mib = 1\n");
    let text = refused_wip(prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap_err());
    assert!(text.contains("untracked files over [seed].max_blob_mib (1.0 MiB): big.dat (1.0 MiB)"), "{text}");
    std::fs::remove_file(repo.dir.join("big.dat")).unwrap();
    repo.write("tracked.dat", "small\n");
    repo.commit("tracked");
    repo.write("tracked.dat", &big);
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let text = refused_wip(prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap_err());
    assert!(text.contains("uncommitted files over [seed].max_blob_mib") && text.contains("tracked.dat"), "{text}");
    // All of them over max_wip_mib.
    repo.write("tracked.dat", "small\n");
    for i in 0..3 {
        repo.write(&format!("half{i}.dat"), &"z".repeat(700 * 1024));
    }
    let cfg = w.cfg("[seed]\nmax_wip_mib = 1\n");
    let text = refused_wip(prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap_err());
    assert!(text.contains("over [seed].max_wip_mib (1.0 MiB)") && text.contains("half0.dat"), "{text}");
}

/// A cap's refusal never shows a path a rule matches, as a finding never
/// does: a custom tripwire's match, or a built-in's the scrubber lacks
/// (github-pat, its name built here), is `a path name` with its size, at
/// each of the five caps, untracked and staged; the other files keep their
/// names.
#[test]
fn an_over_cap_refusal_never_shows_a_tripping_path() {
    let w = World::new();
    std::fs::write(w.paths().root.join("tripwires.txt"), "zq[0-9]{6}\n").unwrap();
    let repo = w.repo("app");
    repo.write("notes/zq123456.txt", &"x".repeat(24));
    repo.write(&format!("cache/{}{}.json", "ghp_", "q".repeat(20)), &"y".repeat(20));
    repo.write("b.txt", "bb");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let base = SeedLimits::cli(&cfg, None);
    // Every cap's text that shows a path or misses its tail, all of them named at the end.
    let mut wrong = Vec::new();
    let mut refused = |lim: SeedLimits, tail: &str| {
        let text = refused_wip(prepare(&paths, &cfg, &ws, &lim).unwrap_err());
        if !text.ends_with(tail) || text.contains("zq1") || text.contains("ghp_") {
            wrong.push(text);
        }
    };
    let named = "a path name (24 B), a path name (20 B)";
    refused(SeedLimits { max_untracked_files: 1, ..base }, &format!("over [seed].max_untracked_files (1): ignore them (.gitignore) or commit them; the largest: {named}, b.txt (2 B)"));
    refused(SeedLimits { max_blob_bytes: 10, ..base }, &format!("untracked files over [seed].max_blob_mib (10 B): {named}"));
    refused(SeedLimits { max_wip_bytes: 30, ..base }, &format!("the untracked files hold 46 B, over [seed].max_wip_mib (30 B); the largest: {named}, b.txt (2 B)"));
    repo.git(&["add", "-A"]);
    refused(SeedLimits { max_blob_bytes: 10, ..base }, &format!("uncommitted files over [seed].max_blob_mib (10 B): {named}"));
    refused(SeedLimits { max_wip_bytes: 30, ..base }, &format!("the uncommitted changes add 46 B, over [seed].max_wip_mib (30 B); the largest: {named}, b.txt (2 B)"));
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// Nor does a failure's text: the stat of an untracked file a directory
/// without search permission hides, and git's `add` of a file it cannot
/// read, untracked or tracked, show a path a rule matches as `a path name`.
/// Each mode is put back before the assert (root reads through them: skipped).
#[test]
fn a_failure_never_shows_a_tripping_path() {
    // SAFETY: a plain getter.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("root reads a mode-000 file: skipped");
        return;
    }
    let w = World::new();
    std::fs::write(w.paths().root.join("tripwires.txt"), "zq[0-9]{6}\n").unwrap();
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let lim = SeedLimits::cli(&cfg, None);
    // The preparation of `repo` with `rel` at `mode`, the mode put back: its error's text.
    let failed = |repo: &Repo, rel: &str, mode: u32| {
        let ws = resolve(&cfg, &repo.dir, None).unwrap();
        let p = repo.dir.join(rel);
        let was = std::fs::metadata(&p).unwrap().permissions();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        let result = prepare(&paths, &cfg, &ws, &lim);
        std::fs::set_permissions(&p, was).unwrap();
        result.unwrap_err().to_string()
    };
    let hidden = w.repo("hidden");
    hidden.write("secret/zq123456.txt", "x\n");
    let untracked = w.repo("untracked");
    untracked.write("notes/zq123456.txt", "x\n");
    let tracked = w.repo("tracked");
    tracked.write("notes/zq123456.txt", "x\n");
    tracked.commit("tracked");
    tracked.write("notes/zq123456.txt", "changed\n");
    let texts = [failed(&hidden, "secret", 0o644), failed(&untracked, "notes/zq123456.txt", 0o000), failed(&tracked, "notes/zq123456.txt", 0o000)];
    assert_eq!(
        texts,
        [
            "cannot stat a path name: Permission denied (os error 13)",
            "workspace failed (git_failed): git add of the untracked files: git failed on a path name",
            "workspace failed (git_failed): git add -u of the tracked changes: git failed on a path name",
        ]
    );
}

/// The user's index, worktree, stash, refs and objects: never touched by a
/// snapshot, whatever it carries (a stash entry and a conflicted index too).
#[test]
fn the_users_repository_is_never_touched() {
    let w = World::new();
    let repo = every_change(&w);
    repo.write("stashed.txt", "keep me\n");
    repo.git(&["stash", "push", "-q", "--include-untracked", "--", "stashed.txt"]);
    let before = repo.state();
    assert!(!before.stash.is_empty());
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let prepared = prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap();
    assert_eq!(repo.state(), before);
    drop(prepared);
    assert_eq!(repo.state(), before);
    // A merge conflict in progress: the files are carried, the index is HEAD's in the VM.
    let conflicted = w.repo("conflicted");
    conflicted.git(&["checkout", "-q", "-b", "other"]);
    conflicted.write("c.txt", "theirs\n");
    conflicted.commit("theirs");
    conflicted.git(&["checkout", "-q", "main"]);
    conflicted.write("c.txt", "ours\n");
    conflicted.commit("ours");
    assert!(!super::fixture::git_ok(&conflicted.dir, &["merge", "-q", "other"]));
    let before = conflicted.state();
    let ws = resolve(&cfg, &conflicted.dir, None).unwrap();
    let s = prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap().summary();
    assert!(s.notes.iter().any(|n| n.contains("unresolved conflicts")), "{:?}", s.notes);
    assert!(s.wip.is_some_and(|w| w.index_commit.is_none()));
    assert_eq!(conflicted.state(), before, "the conflicted index is not resolved behind the user's back");
}

/// W2R-08: the wrapper's P1 cancels the snapshot when its start is dropped
/// or fails: a cancelled preparation gives up (`Interrupted`) and leaves no
/// scratch directory. The flag covers the preparation alone: set once it
/// returned (as P1 sets it when it is over, success included), the seed it
/// made still goes in.
#[tokio::test]
async fn a_cancelled_preparation_gives_up_and_the_flag_never_reaches_the_send() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let w = World::new();
    let repo = every_change(&w);
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let lim = SeedLimits::cli(&cfg, None);
    let e = prepare_cancellable(&paths, &cfg, &ws, &lim, Arc::new(AtomicBool::new(true))).unwrap_err();
    assert!(matches!(&e, BridgeError::Io(io) if io.kind() == std::io::ErrorKind::Interrupted), "{e}");
    let left: Vec<_> = std::fs::read_dir(paths.tmp()).map(|d| d.filter_map(Result::ok).map(|e| e.file_name()).collect()).unwrap_or_default();
    assert!(left.is_empty(), "no scratch left: {left:?}");
    let flag = Arc::new(AtomicBool::new(false));
    let prepared = prepare_cancellable(&paths, &cfg, &ws, &lim, Arc::clone(&flag)).unwrap();
    flag.store(true, Ordering::SeqCst);
    let vm = FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let (api, target, caps) = (api().await, target(), caps());
    let progress = |_: SeedProgress| {};
    let outcome = ensure_workspace(&ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress), Some(prepared), SeedWant::Auto).await.unwrap();
    assert!(matches!(outcome, EnsureOutcome::Seeded { wip: Some(_), .. }), "{outcome:?}");
}
