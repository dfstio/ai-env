//! S9 wave 1 (G7): the fake git's descriptor test, out of `tests/workspace.rs`
//! into a binary of its own (S8's X1 open point 5). It asserts the exact
//! descriptors the fake's first call inherited (`[3]`), and on macOS a pipe
//! another test thread is creating can be inherited before it is marked
//! close-on-exec: beside `workspace`'s other tests it failed once under
//! load. Here it is the only test, so no other thread makes a pipe while it
//! spawns; every wait is bounded (`common::bounded`, S8 phase 4's F9).
mod common;

use common::bounded::run_within;
use common::{git_calls, git_real, install_fake_git};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

/// Every run's bound: a fake git's call, the real git's.
const LIMIT: Duration = Duration::from_secs(60);

/// A tempdir with the fake git at `bin/git` (its log `git.log`), an empty
/// `repo/` and an agent `home/`.
struct FakeGit {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl FakeGit {
    fn new() -> FakeGit {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for dir in ["bin", "repo", "home"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        install_fake_git(&root.join("bin").join("git"), &root.join("git.log"), &[]);
        FakeGit { _tmp: tmp, root }
    }

    fn git(&self) -> PathBuf {
        self.root.join("bin").join("git")
    }

    fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }

    /// The fake in `repo/` with an empty environment but `PATH`, `HOME`,
    /// `GIT_CONFIG_GLOBAL` and `vars` (and descriptor 3 open on /dev/null
    /// when `fd3`), stdin `/dev/null`, to its end within [`LIMIT`].
    fn run(&self, args: &[&str], vars: &[(&str, &str)], fd3: bool) -> Output {
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
        run_within(cmd, None, LIMIT, "the fake git")
    }
}

/// Each call is one log line: the `GIT_*` names it started with (never a
/// value; the knobs file's are read after), the descriptors from 3 up it
/// started with, every argument as given (a tab, a newline and a `%` in one
/// survive); then the real git runs it.
#[test]
fn the_fake_git_logs_each_call_then_runs_the_real_git() {
    let f = FakeGit::new();
    let o = f.run(&["init", "-q", "-b", "main"], &[("GIT_FAKE_PROBE", "a value")], true);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(f.repo().join(".git").is_dir(), "the real git ran");
    let message = "one\ttwo\nthree 100% done";
    let o = f.run(&["-c", "user.name=t", "-c", "user.email=t@ai-env.invalid", "commit", "-q", "--allow-empty", "-m", message], &[], false);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let calls = git_calls(&f.root.join("git.log"));
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!((calls[0].sub(), calls[0].env.as_slice(), calls[0].fds.as_slice()), (Some("init"), ["GIT_CONFIG_GLOBAL", "GIT_FAKE_PROBE"].map(String::from).as_slice(), [3].as_slice()));
    assert_eq!((calls[1].sub(), calls[1].fds.as_slice()), (Some("commit"), [].as_slice()));
    assert_eq!(calls[1].args.last().map(String::as_str), Some(message), "{calls:?}");
    assert!(calls[1].has("--allow-empty"));
    let log = std::fs::read_to_string(f.root.join("git.log")).unwrap();
    assert!(!log.contains("a value"), "never a value: {log}");
    let mut log_cmd = Command::new(git_real());
    log_cmd.args(["log", "-1", "--format=%B"]).current_dir(f.repo());
    let subject = run_within(log_cmd, None, LIMIT, "git log");
    assert_eq!(String::from_utf8_lossy(&subject.stdout).trim_end(), message, "the real git committed it");
}
