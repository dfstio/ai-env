//! T8.1 (S8): the Mac's workspace data plane, offline. `bridge::workspace`
//! (resolve, the WIP snapshot, the shallow pack, the scans, D3's update or
//! keep), the data plane's client, the code-out import and `box seed
//! --dry-run`, against fixture repositories the real git builds in tempdirs
//! and a git-backed fake VM (`workspace/fixture.rs`: it applies a seed's
//! manifest and pack as the shim's helper does); the user's repository is
//! never touched. The areas live in `tests/workspace/*.rs` (declared with
//! `#[path]`, so the undeclared-test lint only sees this root); the seed
//! through the endpoint and the native shim, its real helper in the VM, is
//! the lead's integration (`workspace::e2e`).
//!
//! Phase 0's own checks come first: the fake git on its own and as
//! `GitRun` runs it on either side (the Mac strips every inherited `GIT_*`,
//! the VM clears the environment: its knobs reach it through its knobs file).
mod common;

#[path = "workspace/fixture.rs"]
mod fixture;
#[path = "workspace/resolve.rs"]
mod resolve;
#[path = "workspace/snapshot.rs"]
mod snapshot;
#[path = "workspace/pack.rs"]
mod pack;
#[path = "workspace/scan.rs"]
mod scan;
#[path = "workspace/decide.rs"]
mod decide;
#[path = "workspace/ensure.rs"]
mod ensure;
#[path = "workspace/http.rs"]
mod http;
#[path = "workspace/codeout.rs"]
mod codeout;
#[path = "workspace/transcript.rs"]
mod transcript;
#[path = "workspace/cli.rs"]
mod cli;
#[path = "workspace/e2e.rs"]
mod e2e;
#[path = "workspace/smart_http.rs"]
mod smart_http;
#[path = "workspace/carry.rs"]
mod carry;

use ai_env_cli::gitrun::{GitRun, OVERRIDES};
use common::{git_calls, git_real, install_fake_git, GitCall};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// T8.1 offline, the Mac's half: a dirty workspace seeded into a VM (the
/// git-backed fake: what the shim's helper does with the manifest and the
/// pack) checks out HEAD with the uncommitted changes left uncommitted,
/// shallow at HEAD, no history, no origin; the Mac's repository untouched; a
/// second seed of the same state is up to date, and D3 keeps a VM seeded
/// dirty when the Mac moves on.
#[tokio::test]
async fn workspace_seed_local() {
    use ai_env_cli::bridge::workspace::{ensure_workspace, resolve, EnsureOutcome, KeptReason, SeedProgress, SeedWant};
    let w = fixture::World::new();
    let repo = w.repo("app");
    repo.write("src/lib.rs", "pub fn one() {}\n");
    repo.commit("lib");
    repo.write("src/lib.rs", "pub fn two() {}\n");
    repo.write("notes.txt", "untracked\n");
    let before = repo.state();
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let vm = fixture::FakeVm::new(&w.root.join("vm"), &w.root.join("vm-projects"));
    let api = fixture::api().await;
    let (target, caps) = (fixture::target(), fixture::caps());
    let steps = std::sync::Mutex::new(Vec::new());
    let progress = |p: SeedProgress| steps.lock().unwrap().push(p);
    let ctx = fixture::ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress);
    let outcome = ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap();
    let EnsureOutcome::Seeded { head, wip: Some(wip), bytes, .. } = &outcome else { panic!("{outcome:?}") };
    assert_eq!(head, &repo.head());
    assert!(*bytes > 0 && wip.len() == 40);
    assert_eq!(repo.state(), before, "the Mac's index, worktree, stash, refs and objects untouched");
    let v = &vm.dir;
    assert_eq!(fixture::git(v, &["rev-parse", "HEAD"]), repo.head());
    assert_eq!(fixture::git(v, &["remote"]), "", "no origin");
    assert_eq!(std::fs::read_to_string(v.join(".git/shallow")).unwrap().trim(), repo.head(), "shallow at the seeded commit");
    assert_eq!(fixture::git(v, &["rev-list", "--count", "HEAD"]), "1", "no history crossed");
    fixture::git(v, &["fsck", "--connectivity-only", "--no-progress"]);
    assert_eq!(fixture::git(v, &["status", "--porcelain", "--untracked-files=all"]), repo.git(&["status", "--porcelain", "--untracked-files=all"]), "the changes stay uncommitted, as on the Mac");
    assert_eq!(std::fs::read_to_string(v.join("src/lib.rs")).unwrap(), "pub fn two() {}\n");
    let steps = steps.lock().unwrap().clone();
    assert!(matches!(steps.first(), Some(SeedProgress::Snapshot { changed: 2, untracked: 1, .. })), "{steps:?}");
    assert!(steps.contains(&SeedProgress::Applied), "{steps:?}");
    // The same state again: nothing is sent.
    let again = ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap();
    assert_eq!(again, EnsureOutcome::UpToDate { head: repo.head() });
    assert_eq!(vm.calls().iter().filter(|c| c.starts_with("PUT")).count(), 1);
    // D3: a VM seeded dirty is dirty, so a new Mac commit leaves it as it is.
    repo.commit("more");
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let ctx = fixture::ensure_ctx(&api, &vm, &paths, &cfg, &target, &caps, &ws, &progress);
    match ensure_workspace(&ctx, None, SeedWant::Auto).await.unwrap() {
        EnsureOutcome::Kept { reason: KeptReason::Dirty, note, .. } => assert_eq!(note, "the VM keeps its state (dirty): ai-env box fetch shows what changed"),
        other => panic!("{other:?}"),
    }
    let row = ai_env_cli::bridge::workspace::rows::row_of(&paths, &ws).unwrap().expect("a workspace row");
    assert_eq!(row.vm.get(fixture::VM).and_then(|v| v.kept.clone()).as_deref(), Some("dirty"));
}

// ---- phase 0: the fake git ---------------------------------------------------------------

/// A tempdir with the fake git at `bin/git` (its log `git.log`), an empty
/// `repo/` and an agent `home/`.
struct FakeGit {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl FakeGit {
    fn new(knobs: &[(&str, &str)]) -> FakeGit {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for dir in ["bin", "repo", "home"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        install_fake_git(&root.join("bin").join("git"), &root.join("git.log"), knobs);
        FakeGit { _tmp: tmp, root }
    }

    fn git(&self) -> PathBuf {
        self.root.join("bin").join("git")
    }

    fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }

    fn calls(&self) -> Vec<GitCall> {
        git_calls(&self.root.join("git.log"))
    }

    /// The fake in `repo/` with an empty environment but `PATH` and `vars`
    /// (and descriptor 3 open on /dev/null when `fd3`), `stdin` then EOF.
    fn run(&self, args: &[&str], vars: &[(&str, &str)], fd3: bool, stdin: &[u8]) -> Output {
        use std::io::Write;
        let mut cmd = if fd3 {
            let mut sh = Command::new("/bin/sh");
            sh.arg("-c").arg("exec \"$0\" \"$@\" 3</dev/null").arg(self.git());
            sh
        } else {
            Command::new(self.git())
        };
        cmd.args(args).current_dir(self.repo()).env_clear().env("PATH", "/usr/bin:/bin").env("HOME", self.root.join("home")).env("GIT_CONFIG_GLOBAL", "/dev/null");
        for (k, v) in vars {
            cmd.env(k, v);
        }
        let mut child = cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let mut sink = child.stdin.take().unwrap();
        let _ = sink.write_all(stdin);
        drop(sink);
        child.wait_with_output().unwrap()
    }

    /// A commit in `repo/` by the real git: its id.
    fn commit(&self) -> String {
        let git = |args: &[&str]| {
            let o = Command::new(git_real()).args(args).current_dir(self.repo()).env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1").output().unwrap();
            assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        git(&["init", "-q", "-b", "main"]);
        std::fs::write(self.repo().join("a.txt"), "a\n").unwrap();
        git(&["add", "a.txt"]);
        git(&["-c", "user.name=t", "-c", "user.email=t@ai-env.invalid", "commit", "-q", "-m", "one"]);
        git(&["rev-parse", "HEAD"])
    }
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir).map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).collect()).unwrap_or_default();
    out.sort();
    out
}

/// `FAKE_GIT_FAIL` fails that subcommand alone (128, git's `fatal:`
/// shape), after logging it. `FAKE_GIT_KEEP_PACK` keeps a copy of what
/// `pack-objects --stdout` wrote (the caller gets the same bytes) and of
/// what `index-pack --stdin` read (which still indexes it).
#[test]
fn the_fake_git_fails_a_subcommand_and_keeps_its_packs() {
    let kept = tempfile::tempdir().unwrap();
    let keep = kept.path().display().to_string();
    let f = FakeGit::new(&[("FAKE_GIT_FAIL", "status"), ("FAKE_GIT_KEEP_PACK", &keep)]);
    let head = f.commit();
    let o = f.run(&["status"], &[], false, b"");
    assert_eq!(o.status.code(), Some(128));
    assert_eq!(String::from_utf8_lossy(&o.stderr), "fatal: fake git: status failed (FAKE_GIT_FAIL)\n");
    let o = f.run(&["log", "--format=%H"], &[], false, b"");
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), head, "another subcommand runs");
    let pack = f.run(&["pack-objects", "--revs", "--stdout"], &[], false, b"HEAD\n");
    assert!(pack.status.success() && pack.stdout.starts_with(b"PACK"), "{}", String::from_utf8_lossy(&pack.stderr));
    let packs = files(kept.path());
    assert_eq!(packs.len(), 1, "{packs:?}");
    assert_eq!(std::fs::read(&packs[0]).unwrap(), pack.stdout, "the copy is what the caller got");
    let o = f.run(&["index-pack", "--stdin"], &[], false, &pack.stdout);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let packs = files(kept.path());
    assert_eq!(packs.len(), 2, "{packs:?}");
    assert!(packs.iter().any(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("index-pack-")) && std::fs::read(p).unwrap() == pack.stdout));
    let calls = f.calls();
    let subs: Vec<Option<&str>> = calls.iter().map(GitCall::sub).collect();
    assert_eq!(subs, [Some("status"), Some("log"), Some("pack-objects"), Some("index-pack")], "the failed call is logged too");
}

/// As `GitRun` runs it: in the VM (an empty environment) and on the Mac
/// (every inherited `GIT_*` stripped) the fake still finds the real git and
/// its log through its knobs file, and logs what the run carries: the seven
/// overrides first, `GIT_CONFIG_GLOBAL` and `GIT_TERMINAL_PROMPT` alone in
/// the VM, no `GIT_*` on the Mac but what the run sets.
#[test]
fn gitrun_reaches_the_fake_git_on_either_side() {
    let f = FakeGit::new(&[]);
    let vm = GitRun::vm(&f.repo(), &f.root.join("home")).with_program(&f.git());
    vm.output(["init", "-q", "-b", "main"]).unwrap();
    let mac = GitRun::mac(&f.repo()).with_program(&f.git());
    assert!(mac.succeeds(["rev-parse", "--git-dir"]).unwrap());
    let index = f.root.join("index.tmp");
    mac.clone().env("GIT_INDEX_FILE", &index).output(["read-tree", "--empty"]).unwrap();
    let calls = f.calls();
    let overrides: Vec<String> = OVERRIDES.iter().flat_map(|o| ["-c".to_string(), (*o).to_string()]).collect();
    assert!(calls.iter().all(|c| c.args.starts_with(&overrides)), "{calls:?}");
    let envs: Vec<(Option<&str>, &[String])> = calls.iter().map(|c| (c.sub(), c.env.as_slice())).collect();
    assert_eq!(
        envs,
        [
            (Some("init"), ["GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT"].map(String::from).as_slice()),
            (Some("rev-parse"), [].as_slice()),
            (Some("read-tree"), ["GIT_INDEX_FILE".to_string()].as_slice()),
        ]
    );
    assert!(index.exists(), "the real git wrote the run's own index");
}

/// S9: with `FAKE_GIT_ENV_ALL=1` the line starts with the caller's uid and
/// `env=` names every variable the call started with, not only `GIT_*`
/// (never a value; the knobs file's are read after, and the four names the
/// fake's own /bin/sh adds are left out): under `env -i` with two names of
/// its own, exactly those two.
#[test]
fn the_fake_git_logs_every_name_and_its_uid() {
    let f = FakeGit::new(&[("FAKE_GIT_ENV_ALL", "1")]);
    let o = Command::new("/usr/bin/env").args(["-i", "LC_ALL=C", "S9_PROBE=a value"]).arg(f.git()).arg("--version").current_dir(f.repo()).output().unwrap();
    assert!(o.status.success() && o.stdout.starts_with(b"git version"), "{}", String::from_utf8_lossy(&o.stderr));
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let calls = f.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!((calls[0].uid, calls[0].env.as_slice(), calls[0].args.as_slice()), (Some(uid), ["LC_ALL", "S9_PROBE"].map(String::from).as_slice(), ["--version".to_string()].as_slice()));
    let log = std::fs::read_to_string(f.root.join("git.log")).unwrap();
    assert!(log.starts_with(&format!("uid={uid}\tenv=LC_ALL,S9_PROBE\tfds=")) && !log.contains("a value"), "{log}");
    // Without the knob: no uid, the GIT_* names alone.
    let plain = FakeGit::new(&[]);
    let o = Command::new("/usr/bin/env").args(["-i", "LC_ALL=C", "S9_PROBE=a value"]).arg(plain.git()).arg("--version").current_dir(plain.repo()).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let calls = plain.calls();
    assert_eq!((calls.len(), calls[0].uid, calls[0].env.as_slice()), (1, None, [].as_slice()), "{calls:?}");
}

// ---- S9 (G7): a seed's notes ------------------------------------------------------------------

/// S9: a seed's notes of what it does not carry name their paths as a
/// finding names one (`blobscan::shown_path`, then the scrubber): a nested
/// repository whose name a custom tripwire matches is `a path name`, one
/// whose name holds the setup-token's shape (built at run time) shows none
/// of it; one with an ordinary name keeps it. Notes reach stderr (`box
/// seed`, Cursor's line), where a tripwire-shaped name never goes.
#[test]
fn a_seed_note_never_shows_a_tripping_path() {
    use ai_env_cli::bridge::workspace::{prepare, resolve, SeedLimits};
    let w = fixture::World::new();
    std::fs::write(w.paths().root.join("tripwires.txt"), "zq[0-9]{6}\n").unwrap();
    let repo = w.repo("app");
    let token = format!("{}-{}-oat01-{}", "sk", "ant", "Kq4_".repeat(20));
    for inner in ["zq123456".to_string(), format!("x-{token}"), "inner".to_string()] {
        let _ = fixture::Repo::create(&repo.dir.join(inner));
    }
    repo.write("real.txt", "x\n");
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let notes = prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap().summary().notes;
    let shown: Vec<String> = notes.iter().map(|n| n.replace(&token, "<TOKEN>")).collect();
    assert!(notes.iter().all(|n| !n.contains("zq123") && !n.contains(&token[7..])), "{shown:#?}");
    assert!(notes.iter().any(|n| n == "a path name is a nested repository: not carried"), "{shown:#?}");
    assert!(notes.iter().any(|n| n == "inner/ is a nested repository: not carried"), "{shown:#?}");
    assert_eq!(notes.iter().filter(|n| n.ends_with(" is a nested repository: not carried")).count(), 3, "{shown:#?}");
}

/// `head` committed in `repo` as gitlinks at `paths`, each left unpopulated
/// (an empty directory, as a clone without its submodules leaves it), so the
/// worktree holds nothing uncommitted to carry.
fn commit_gitlinks(repo: &fixture::Repo, head: &str, paths: &[&str]) {
    for path in paths {
        repo.git(&["update-index", "--add", "--cacheinfo", &format!("160000,{head},{path}")]);
        std::fs::create_dir_all(repo.dir.join(path)).unwrap();
    }
    repo.git(&["commit", "-q", "-m", "submodules"]);
}

/// S9: a committed gitlink at a path a rule matches (a custom tripwire, the
/// setup-token's shape built at run time) never reaches a note: the tree
/// that holds it names it, so the seed is refused on that tree's finding,
/// which shows `a path name` (exit 9), before any note is made.
#[test]
fn a_gitlink_at_a_tripping_path_refuses_the_seed_before_any_note() {
    use ai_env_cli::bridge::errors::BridgeError;
    use ai_env_cli::bridge::workspace::{code, prepare, resolve, SeedLimits};
    let token = format!("{}-{}-oat01-{}", "sk", "ant", "Kq4_".repeat(20));
    for path in ["zq654321".to_string(), format!("y-{token}")] {
        let w = fixture::World::new();
        std::fs::write(w.paths().root.join("tripwires.txt"), "zq[0-9]{6}\n").unwrap();
        let repo = w.repo("app");
        commit_gitlinks(&repo, &repo.head(), &[&path]);
        let (paths, cfg) = (w.paths(), w.cfg(""));
        let ws = resolve(&cfg, &repo.dir, None).unwrap();
        let e = prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).expect_err("the seed refused");
        let text = e.to_string().replace(&token, "<TOKEN>");
        assert!(matches!(&e, BridgeError::WorkspaceRefused { code: c, .. } if *c == code::FINDING), "{text}");
        assert!(text.contains("a path name (tree ") && !text.contains("zq654") && !text.contains("<TOKEN>"), "{text}");
    }
}

/// S9: a seed's note of a submodule it does not carry names the gitlink's
/// path as the other notes name theirs (`blobscan::shown_path`, then the
/// scrubber). No rule matches a key-shaped segment (`token=<value>`, built
/// at run time), so the seed goes on, and the note shows no value; an
/// ordinary path keeps its name. The note is
/// `blobscan::scan_settings_within`' (nothing else reads a gitlink's path,
/// as `rev-list --objects` lists none).
#[test]
fn a_seed_note_never_shows_a_key_shaped_submodule_path() {
    use ai_env_cli::bridge::workspace::{prepare, resolve, SeedLimits};
    let w = fixture::World::new();
    let repo = w.repo("app");
    let keyed = format!("vendor/{}={}", "token", "Kq4_".repeat(5));
    commit_gitlinks(&repo, &repo.head(), &[&keyed, "vendor/lib"]);
    let (paths, cfg) = (w.paths(), w.cfg(""));
    let ws = resolve(&cfg, &repo.dir, None).unwrap();
    let notes = prepare(&paths, &cfg, &ws, &SeedLimits::cli(&cfg, None)).unwrap().summary().notes;
    assert!(notes.iter().all(|n| !n.contains("Kq4_")), "{notes:#?}");
    assert!(notes.iter().any(|n| n == "vendor/token=[redacted:len=20] is a submodule: not carried"), "{notes:#?}");
    assert!(notes.iter().any(|n| n == "vendor/lib is a submodule: not carried"), "{notes:#?}");
}
