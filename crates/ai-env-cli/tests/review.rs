//! S9 wave 1 (G3): `ai-env box review` (the rules over the commits a push
//! would carry) and `ai-env box hook-install` (the pre-push hook that runs
//! it), through the real binary and the real git, offline: no AWS call, no
//! Touch ID, no bridge.toml needed. Each test is one tempdir world: its
//! `HOME` (no git config of the developer's reaches a child), its bridge
//! root (`AI_ENV_BRIDGE_DIR`: the audit, the scan cache, the scan lists),
//! repositories and local bare remotes; every push goes to a bare
//! repository on disk, never a network. Keys are built at run time.

mod common;

use common::bounded::run_within;
use common::{git_calls, git_real, install_fake_git};
use serde_json::{json, Value};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

/// How long one child (git, ai-env, a push running the hook) may take.
const LIMIT: Duration = Duration::from_secs(120);
/// The binary under test: what `box hook-install` names in the hook (canonical).
const AI_ENV: &str = env!("CARGO_BIN_EXE_ai-env");

/// A runtime-built AWS key id shape (never a literal in the source).
fn key_id() -> String {
    format!("{}{}", "AKIA", "Z3".repeat(8))
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn json_of(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o.stdout)))
}

/// A push's stdout and stderr: git hands a hook's stdout to its stderr.
fn both(o: &Output) -> String {
    format!("{}{}", text(&o.stdout), text(&o.stderr))
}

/// One test's world: `home/`, `bridge/`, and its repositories.
struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    /// Seconds past the fixture date of the next commit (each commit a second later: `git log` orders them).
    tick: Cell<u32>,
    /// The first entry of every child's `PATH` when set (a fake git).
    first_path: Option<PathBuf>,
}

impl World {
    fn new() -> World {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in ["home", "bridge", "keys"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        World { _tmp: tmp, root, tick: Cell::new(0), first_path: None }
    }

    fn bridge(&self) -> PathBuf {
        self.root.join("bridge")
    }

    /// Every child's environment: this world's `HOME` and bridge root, the
    /// real git on `PATH`, no system git config, the fixture's author.
    fn command(&self, program: &Path) -> Command {
        let git_dir = git_real().parent().unwrap().display().to_string();
        let path = match &self.first_path {
            Some(first) => format!("{}:{git_dir}:/usr/bin:/bin", first.display()),
            None => format!("{git_dir}:/usr/bin:/bin"),
        };
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("HOME", self.root.join("home"))
            .env("PATH", path)
            .env("AI_ENV_BRIDGE_DIR", self.bridge())
            .env("AI_ENV_DIR", self.root.join("keys"))
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "ai-env fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@ai-env.invalid")
            .env("GIT_COMMITTER_NAME", "ai-env fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@ai-env.invalid");
        cmd
    }

    /// `git args` in `dir` (the real git), its output whatever its exit.
    fn git_out(&self, dir: &Path, args: &[&str]) -> Output {
        let mut cmd = self.command(git_real());
        let date = format!("2026-10-18T08:00:{:02}+00:00", self.tick.get() % 60);
        cmd.args(args).current_dir(dir).env("GIT_AUTHOR_DATE", &date).env("GIT_COMMITTER_DATE", &date);
        run_within(cmd, None, LIMIT, "git")
    }

    /// `git args` in `dir`: its stdout, trimmed; a failure panics with its stderr.
    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let o = self.git_out(dir, args);
        assert!(o.status.success(), "git {args:?} in {}: {}", dir.display(), text(&o.stderr));
        text(&o.stdout).trim().to_string()
    }

    /// A repository `name` on `main`, its hooks where git runs them by default.
    fn repo(&self, name: &str) -> PathBuf {
        let dir = self.root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        self.git(&dir, &["init", "-q", "-b", "main"]);
        dir
    }

    /// A bare repository `name`, to push to.
    fn bare(&self, name: &str) -> PathBuf {
        let dir = self.root.join(name);
        self.git(&self.root, &["init", "-q", "--bare", dir.to_str().unwrap()]);
        dir
    }

    fn write(&self, repo: &Path, rel: &str, body: &str) {
        let p = repo.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    /// Everything in the work tree committed as `msg`: the new commit.
    fn commit(&self, repo: &Path, msg: &str) -> String {
        self.tick.set(self.tick.get() + 1);
        self.git(repo, &["add", "-A"]);
        self.git(repo, &["commit", "-q", "--allow-empty", "-m", msg]);
        self.git(repo, &["rev-parse", "HEAD"])
    }

    /// A repository with one commit pushed to its remote `origin` (a bare
    /// repository): `(repo, origin, the commit)`.
    fn pushed(&self, name: &str) -> (PathBuf, PathBuf, String) {
        let repo = self.repo(name);
        self.write(&repo, "README", "hello\n");
        let c0 = self.commit(&repo, "the base");
        let origin = self.bare(&format!("{name}-origin.git"));
        self.git(&repo, &["remote", "add", "origin", origin.to_str().unwrap()]);
        self.git(&repo, &["push", "-q", "origin", "main"]);
        (repo, origin, c0)
    }

    /// `ai-env args` in `dir` (stdin when given), within [`LIMIT`].
    fn ai_env(&self, dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
        self.ai_env_at(Path::new(AI_ENV), dir, args, stdin)
    }

    fn ai_env_at(&self, program: &Path, dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
        let mut cmd = self.command(program);
        cmd.args(args).current_dir(dir);
        run_within(cmd, stdin, LIMIT, "ai-env")
    }

    /// The audit rows of `event`, oldest first.
    fn audit(&self, event: &str) -> Vec<Value> {
        std::fs::read_to_string(self.bridge().join("audit.jsonl")).unwrap_or_default().lines().map(|l| serde_json::from_str::<Value>(l).unwrap()).filter(|r| r["event"] == event).collect()
    }

    fn audit_text(&self) -> String {
        std::fs::read_to_string(self.bridge().join("audit.jsonl")).unwrap_or_default()
    }
}

/// The commit ids of a review's `--json`.
fn ids(v: &Value) -> Vec<String> {
    v["commits"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().to_string()).collect()
}

fn short(id: &str) -> &str {
    &id[..12]
}

/// The canonical path of the binary under test, as the hook names it.
fn ai_env_canonical() -> String {
    std::fs::canonicalize(AI_ENV).unwrap().display().to_string()
}

/// The default base is every remote-tracking ref but ai-env's own: a
/// commit the box refs hold (fetched from a VM, never reviewed) is still
/// in the range, and a key in it is a finding named at its commit and
/// line; `refs/remotes/Box-Quarantine/*` counts as ai-env's too (one
/// directory on the Mac's disk). An explicit `--base` is honoured. With no
/// remote-tracking ref but ai-env's, the whole history is read and a note
/// says so.
#[test]
fn the_default_base_is_every_remote_but_box() {
    let w = World::new();
    let (repo, _origin, c0) = w.pushed("app");
    w.write(&repo, "work.txt", "the agent's work\n");
    let c1 = w.commit(&repo, "the agent's commit");
    w.git(&repo, &["update-ref", "refs/remotes/box/main", &c1]);
    w.git(&repo, &["update-ref", "refs/remotes/Box-Quarantine/main", &c1]);
    let o = w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let v = json_of(&o);
    assert_eq!(v["bases"], json!(["refs/remotes/origin/main"]), "{v}");
    assert_eq!((v["rev"].as_str(), v["head"].as_str(), v["whole_history"].as_bool(), v["verdict"].as_str()), (Some("HEAD"), Some(c1.as_str()), Some(false), Some("pass")));
    assert_eq!(ids(&v), [c1.as_str()], "the box ref's commit is reviewed");
    assert_eq!(v["repo"], repo.display().to_string());
    // A key in a commit the box ref holds: a finding at its commit and line, never the key.
    let key = key_id();
    w.write(&repo, "deploy.conf", &format!("region: x\nkey: {key}\n"));
    let c2 = w.commit(&repo, "configure the deploy");
    w.git(&repo, &["update-ref", "refs/remotes/box/main", &c2]);
    let blob = w.git(&repo, &["rev-parse", "HEAD:deploy.conf"]);
    let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains(&format!("  commit {}:deploy.conf (blob {}) line 2: rule aws-access-key-id\n", short(&c2), short(&blob))), "{out}");
    assert!(out.contains("against refs/remotes/origin/main: 2 commit(s) they lack") && out.ends_with("box review: findings\n"), "{out}");
    assert!(!out.contains(&key) && !text(&o.stderr).contains(&key));
    assert!(text(&o.stderr).starts_with("ai-env: box review: 1 finding(s) in the commits a push of HEAD would carry"), "{}", text(&o.stderr));
    // The user's own --base is honoured, box ref or not.
    let o = w.ai_env(&repo, &["box", "review", "HEAD", "--base", "refs/remotes/box/main", "--json"], None);
    assert_eq!((o.status.code(), ids(&json_of(&o)).len()), (Some(0), 0), "{}", text(&o.stderr));
    // Only ai-env's refs left: the whole history, said in a note.
    w.git(&repo, &["update-ref", "-d", "refs/remotes/origin/main"]);
    w.git(&repo, &["reset", "-q", "--hard", &c1]);
    let o = w.ai_env(&repo, &["box", "review", "main"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains("note: no base and no remote-tracking ref (but ai-env's): the whole history is reviewed") && out.contains("the whole history: 2 commit(s)"), "{out}");
    assert!(out.contains(&format!("  {} the agent's commit\n  {} the base\n", short(&c1), short(&c0))), "{out}");
    let v = json_of(&w.ai_env(&repo, &["box", "review", "main", "--json"], None));
    assert_eq!((v["whole_history"].as_bool(), v["bases"].as_array().map(Vec::len)), (Some(true), Some(0)));
    // Every run audited: the command line's mode, never a remote.
    let rows = w.audit("box_review");
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[1]["detail"]["verdict"], "findings");
    assert_eq!((rows[4]["detail"]["mode"].as_str(), rows[4]["detail"]["whole_history"].as_str(), rows[4]["detail"]["commits"].as_str()), (Some("cli"), Some("true"), Some("2")));
    assert!(rows.iter().all(|r| r["detail"].get("remote").is_none() && r["detail"]["repo"] == repo.display().to_string()));
}

/// An allow entry new against the merge base and absent from
/// `settings-policy.txt` is a finding at its line and key; the entries the
/// merge base held are not; once the policy lists it, the review passes.
/// A workspace that trusts its repo settings turns D8's mode off, never
/// the policy rule: a settings file delivered through a link (the file's
/// own, or `.claude` itself) is then a finding at the link; untrusted, D8's
/// `settings-symlink` names it. Either way the file the link reaches is
/// read under the link's name (plans/s9-contracts.md §13, I2): its entry
/// beyond the policy is named there.
#[test]
fn an_added_allow_beyond_the_policy_is_a_finding() {
    let w = World::new();
    let repo = w.repo("app");
    w.write(&repo, ".claude/settings.json", "{\n  \"permissions\": {\n    \"allow\": [\n      \"Read(./src/**)\"\n    ]\n  }\n}\n");
    w.commit(&repo, "the project's settings");
    let origin = w.bare("origin.git");
    w.git(&repo, &["remote", "add", "origin", origin.to_str().unwrap()]);
    w.git(&repo, &["push", "-q", "origin", "main"]);
    w.write(&repo, ".claude/settings.json", "{\n  \"permissions\": {\n    \"allow\": [\n      \"Read(./src/**)\",\n      \"Bash(curl:*)\"\n    ]\n  }\n}\n");
    let c1 = w.commit(&repo, "let it fetch");
    let blob = w.git(&repo, &["rev-parse", "HEAD:.claude/settings.json"]);
    let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    let line = format!("  commit {}:.claude/settings.json (blob {}) line 5: rule allow-not-in-policy, key permissions.allow[1]\n", short(&c1), short(&blob));
    assert!(out.contains(&format!("1 finding(s):\n{line}")), "{out}");
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    assert_eq!(v["findings"], json!([{ "rule": "allow-not-in-policy", "path": ".claude/settings.json", "line": 5, "commit": c1 }]));
    assert_eq!((v["more_findings"].as_u64(), v["verdict"].as_str()), (Some(0), Some("findings")));
    // Listed in the policy: clean.
    std::fs::write(w.bridge().join("settings-policy.txt"), "# reviewed 18 Oct\nallow Bash(curl:*)\n").unwrap();
    let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
    assert_eq!(o.status.code(), Some(0), "{}{}", text(&o.stdout), text(&o.stderr));
    // trust_repo_settings: D8's broad entry passes, the policy rule still names the entry it lacks.
    std::fs::remove_file(w.bridge().join("settings-policy.txt")).unwrap();
    let trusting = format!("[[workspace]]\npath = {:?}\ntrust_repo_settings = true\n", repo.display().to_string());
    std::fs::write(w.bridge().join("bridge.toml"), &trusting).unwrap();
    w.write(&repo, ".claude/settings.json", "{\n  \"permissions\": {\n    \"allow\": [\n      \"Read(./src/**)\",\n      \"Bash(*)\"\n    ]\n  }\n}\n");
    w.git(&repo, &["commit", "-q", "--amend", "-a", "-m", "let it run anything"]);
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    let rules: Vec<&str> = v["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert_eq!(rules, ["allow-not-in-policy"], "{v}");
    std::fs::remove_file(w.bridge().join("bridge.toml")).unwrap();
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    let rules: Vec<&str> = v["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert_eq!(rules, ["broad-allow", "allow-not-in-policy"], "{v}");
    // The same entry delivered through a link: the settings file a link to a team file, or `.claude` a link to a
    // directory holding it.
    let team = "{\"permissions\": {\"allow\": [\"Bash(curl:*)\"]}}\n";
    for (link, target, reached) in [(".claude/settings.json", "../docs/team-settings.json", "docs/team-settings.json"), (".claude", "cfg", "cfg/settings.json")] {
        w.git(&repo, &["reset", "-q", "--hard", "origin/main"]);
        w.write(&repo, "docs/team-settings.json", team);
        w.write(&repo, "cfg/settings.json", team);
        let at = repo.join(link);
        if at.is_dir() {
            std::fs::remove_dir_all(&at).unwrap();
        } else {
            std::fs::remove_file(&at).unwrap();
        }
        std::os::unix::fs::symlink(target, &at).unwrap();
        let c = w.commit(&repo, "share the team's settings");
        let blob = w.git(&repo, &["rev-parse", &format!("HEAD:{link}")]);
        let file = w.git(&repo, &["rev-parse", &format!("HEAD:{reached}")]);
        std::fs::write(w.bridge().join("bridge.toml"), &trusting).unwrap();
        let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
        assert_eq!(o.status.code(), Some(9), "{link}: {}{}", text(&o.stdout), text(&o.stderr));
        let lines = format!(
            "2 finding(s):\n  commit {}:{link} (blob {}): rule allow-not-in-policy, key permissions.allow\n  commit {}:{reached} (blob {}) line 1: rule allow-not-in-policy, key permissions.allow[0]\n",
            short(&c),
            short(&blob),
            short(&c),
            short(&file)
        );
        assert!(text(&o.stdout).contains(&lines), "{}", text(&o.stdout));
        let behind = json!({ "rule": "allow-not-in-policy", "path": reached, "line": 1, "commit": c });
        let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
        assert_eq!(v["findings"], json!([{ "rule": "allow-not-in-policy", "path": link, "line": null, "commit": c }, behind]), "{v}");
        std::fs::remove_file(w.bridge().join("bridge.toml")).unwrap();
        let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
        assert_eq!(v["findings"], json!([{ "rule": "settings-symlink", "path": link, "line": null, "commit": c }, behind]), "untrusted, D8 names it: {v}");
    }
}

/// A settings file counts by what lands at its path: a blob the remote
/// already holds elsewhere (an example file), copied to
/// `.claude/settings.json`, is reviewed there like a new one (D8's broad
/// entry and the policy rule); a commit putting back the merge base's own
/// version is not, nor named again.
#[test]
fn a_settings_file_copied_from_a_blob_the_remote_holds_is_reviewed() {
    let w = World::new();
    let repo = w.repo("app");
    let example = "{\n  \"permissions\": {\n    \"allow\": [\n      \"Bash(*)\"\n    ]\n  }\n}\n";
    w.write(&repo, "docs/example-settings.json", example);
    w.write(&repo, "pkg/.claude/settings.json", "{}\n");
    w.commit(&repo, "docs");
    let origin = w.bare("origin.git");
    w.git(&repo, &["remote", "add", "origin", origin.to_str().unwrap()]);
    w.git(&repo, &["push", "-q", "origin", "main"]);
    w.write(&repo, ".claude/settings.json", example);
    let copy = w.commit(&repo, "use the example");
    w.write(&repo, "pkg/.claude/settings.json", "{\"permissions\": {\"allow\": [\"Bash(git status)\"]}}\n");
    let widen = w.commit(&repo, "widen pkg");
    w.write(&repo, "pkg/.claude/settings.json", "{}\n");
    w.commit(&repo, "put pkg back");
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    let got: Vec<(String, String, String)> = v["findings"].as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["path"].as_str().unwrap().to_string(), f["commit"].as_str().unwrap().to_string())).collect();
    let want = [("broad-allow", ".claude/settings.json", &copy), ("allow-not-in-policy", ".claude/settings.json", &copy), ("allow-not-in-policy", "pkg/.claude/settings.json", &widen)];
    assert_eq!(got, want.map(|(r, p, c)| (r.to_string(), p.to_string(), c.clone())), "{v}");
}

/// S10 phase 4b (F4-WALK-2, V-4): a settings file over `[seed].max_blob_mib`
/// is sized and never read. It is `blob-too-large` at the commit and path
/// that brought it, once (the objects' scan and D8 name the same place),
/// and nothing comes from its bytes: neither D8's `broad-allow` for the
/// `Bash(*)` it holds, which reading it would find, nor the policy rule.
#[test]
fn a_settings_file_over_the_blob_cap_is_too_large_and_never_read() {
    let w = World::new();
    let (repo, _origin, _) = w.pushed("app");
    std::fs::write(w.bridge().join("bridge.toml"), "[seed]\nmax_blob_mib = 1\n").unwrap();
    let pad = "x".repeat(1024 * 1024);
    w.write(&repo, ".claude/settings.json", &format!("{{\"permissions\": {{\"allow\": [\"Bash(*)\"]}}, \"pad\": \"{pad}\"}}\n"));
    let c1 = w.commit(&repo, "settings past the cap");
    let blob = w.git(&repo, &["rev-parse", "HEAD:.claude/settings.json"]);
    let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let line = format!("  commit {}:.claude/settings.json (blob {}): rule blob-too-large (over [seed].max_blob_mib)\n", short(&c1), short(&blob));
    assert!(text(&o.stdout).contains(&format!("1 finding(s):\n{line}")), "{}", text(&o.stdout));
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    assert_eq!(v["findings"], json!([{ "rule": "blob-too-large", "path": ".claude/settings.json", "line": null, "commit": c1 }]), "{v}");
}

/// A merge whose result drops `Cargo.lock` (neither parent deleted it) is a
/// finding named at the merge (its first-parent diff), once, though the
/// head also lacks it against the merge base; put back by a later commit,
/// the merge is still named, by its own diff alone (the head no longer
/// lacks it); a commit deleting one is named at that commit.
#[test]
fn a_merge_removing_cargo_lock_is_a_finding() {
    let w = World::new();
    let repo = w.repo("app");
    w.write(&repo, "Cargo.lock", "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n");
    w.write(&repo, "src/main.rs", "fn main() {}\n");
    w.commit(&repo, "the crate");
    let origin = w.bare("origin.git");
    w.git(&repo, &["remote", "add", "origin", origin.to_str().unwrap()]);
    w.git(&repo, &["push", "-q", "origin", "main"]);
    w.git(&repo, &["checkout", "-q", "-b", "side"]);
    w.write(&repo, "side.txt", "side\n");
    let s1 = w.commit(&repo, "side work");
    w.git(&repo, &["checkout", "-q", "main"]);
    w.write(&repo, "main.txt", "main\n");
    let m1 = w.commit(&repo, "main work");
    w.git(&repo, &["merge", "-q", "--no-ff", "--no-commit", "side"]);
    w.git(&repo, &["rm", "-q", "Cargo.lock"]);
    let merge = w.commit(&repo, "merge side");
    let o = w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let v = json_of(&o);
    assert_eq!(v["findings"], json!([{ "rule": "cargo-lock-removed", "path": "Cargo.lock", "line": null, "commit": merge }]), "{v}");
    let mut got = ids(&v);
    got.sort();
    let mut want = vec![merge.clone(), m1, s1];
    want.sort();
    assert_eq!(got, want);
    let out = text(&w.ai_env(&repo, &["box", "review", "HEAD"], None).stdout);
    assert!(out.contains(&format!("  commit {}:Cargo.lock: rule cargo-lock-removed\n", short(&merge))), "{out}");
    // The lock put back after the merge: no net removal any more, the merge's first-parent diff still names it.
    w.git(&repo, &["checkout", "-q", "origin/main", "--", "Cargo.lock"]);
    let back = w.commit(&repo, "the lock back");
    let o = w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let v = json_of(&o);
    assert_eq!(v["findings"], json!([{ "rule": "cargo-lock-removed", "path": "Cargo.lock", "line": null, "commit": merge }]), "{v}");
    assert!(ids(&v).contains(&back), "{v}");
    // A plain commit deleting it: named there.
    w.git(&repo, &["reset", "-q", "--hard", "origin/main"]);
    w.git(&repo, &["rm", "-q", "Cargo.lock"]);
    let gone = w.commit(&repo, "no lock");
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    assert_eq!(v["findings"], json!([{ "rule": "cargo-lock-removed", "path": "Cargo.lock", "line": null, "commit": gone }]), "{v}");
}

/// A push replacing the remote's tip (`--force`) is reviewed against that
/// tip too: a `Cargo.lock` the remote's tip holds and the pushed head
/// lacks is a finding at the head, though no commit of the range deletes
/// it and the merge base never had one; the remote keeps its tip. The same
/// work rebased onto that tip keeps the lock, and its push goes through.
#[test]
fn a_forced_push_dropping_the_remotes_lock_is_a_finding() {
    let w = World::new();
    let (repo, origin, _) = w.pushed("app");
    let other = w.root.join("other");
    w.git(&w.root, &["clone", "-q", "-b", "main", origin.to_str().unwrap(), other.to_str().unwrap()]);
    w.write(&other, "Cargo.lock", "version = 4\n");
    let b = w.commit(&other, "the lock");
    w.git(&other, &["push", "-q", "origin", "main"]);
    w.git(&repo, &["fetch", "-q", "origin"]);
    w.write(&repo, "c.txt", "c\n");
    let c = w.commit(&repo, "other work");
    let pushed = format!("refs/heads/main {c} refs/heads/main {b}\n");
    let o = w.ai_env(&repo, &["box", "review", "--pre-push", "origin", origin.to_str().unwrap(), "--json"], Some(pushed.as_bytes()));
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let v = json_of(&o);
    assert_eq!(v["findings"], json!([{ "rule": "cargo-lock-removed", "path": "Cargo.lock", "line": null, "commit": c }]), "{v}");
    assert_eq!(ids(&v), [c.as_str()], "only the pushed commit is read");
    // Through git: the forced push is refused, and the remote keeps its lock.
    let o = w.ai_env(&repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let o = w.git_out(&repo, &["push", "--force", "origin", "main"]);
    assert!(!o.status.success() && both(&o).contains(&format!("commit {}:Cargo.lock: rule cargo-lock-removed", short(&c))), "{}", both(&o));
    assert_eq!(w.git(&origin, &["rev-parse", "refs/heads/main"]), b);
    w.git(&repo, &["rebase", "-q", "origin/main"]);
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(o.status.success(), "{}", both(&o));
}

/// cargo reads through a link, and opens a name the Mac's disk folds to
/// its own; each is a finding: a `.cargo/config.toml` that is a link, and a
/// `.cargo` that is one (cargo-config-source, key `source`), a `Cargo.lock`
/// replaced by a link (cargo-lock-removed); the files the head's links
/// reach are read under the links' names too (plans/s9-contracts.md §13,
/// I2: the configuration below the linked `.cargo`, the lock `Cargo.lock`
/// names); a lock whose `k` is U+212A KELVIN SIGN, which cargo opens as
/// `Cargo.lock` on this Mac, is read as one (its new git source named).
/// Never the sources' text.
#[test]
fn a_cargo_file_behind_a_link_or_a_folded_name_is_a_finding() {
    let w = World::new();
    let repo = w.repo("app");
    w.write(&repo, "Cargo.lock", "version = 4\n");
    w.write(&repo, ".cargo/config.toml", "[build]\njobs = 2\n");
    w.commit(&repo, "the crate");
    let origin = w.bare("origin.git");
    w.git(&repo, &["remote", "add", "origin", origin.to_str().unwrap()]);
    w.git(&repo, &["push", "-q", "origin", "main"]);
    let mirror = "[source.crates-io]\nreplace-with = \"mirror\"\n\n[source.mirror]\nregistry = \"sparse+https://mirror.example.invalid/index/\"\n";
    w.write(&repo, "tools/cargo-config.toml", mirror);
    std::fs::remove_file(repo.join(".cargo/config.toml")).unwrap();
    std::os::unix::fs::symlink("../tools/cargo-config.toml", repo.join(".cargo/config.toml")).unwrap();
    let c1 = w.commit(&repo, "share the cargo config");
    w.write(&repo, "build-cfg/config.toml", mirror);
    std::fs::remove_dir_all(repo.join(".cargo")).unwrap();
    std::os::unix::fs::symlink("build-cfg", repo.join(".cargo")).unwrap();
    let c2 = w.commit(&repo, "the cargo config from build-cfg");
    let fork = "git+https://example.invalid/fork/serde-evil?rev=1#0123456789abcdef0123456789abcdef01234567";
    let evil = format!("version = 4\n\n[[package]]\nname = \"evil\"\nversion = \"0.1.0\"\nsource = \"{fork}\"\n");
    w.write(&repo, "locks.toml", &evil);
    std::fs::remove_file(repo.join("Cargo.lock")).unwrap();
    std::os::unix::fs::symlink("locks.toml", repo.join("Cargo.lock")).unwrap();
    let c3 = w.commit(&repo, "the lock from locks.toml");
    assert!(w.git(&repo, &["diff", "--raw", "HEAD~1", "HEAD", "--", "Cargo.lock"]).ends_with("T\tCargo.lock"), "a type change");
    let kelvin = "sub/Cargo.loc\u{212a}";
    w.write(&repo, kelvin, &evil);
    let c4 = w.commit(&repo, "a sub-crate");
    let o = w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let v = json_of(&o);
    let want = json!([
        { "rule": "cargo-config-source", "path": ".cargo/config.toml", "line": null, "commit": c1 },
        { "rule": "cargo-config-source", "path": ".cargo", "line": null, "commit": c2 },
        { "rule": "cargo-config-source", "path": "build-cfg/config.toml", "line": 2, "commit": c2 },
        { "rule": "cargo-config-source", "path": "build-cfg/config.toml", "line": 5, "commit": c2 },
        { "rule": "cargo-lock-removed", "path": "Cargo.lock", "line": null, "commit": c3 },
        { "rule": "cargo-lock-source", "path": "locks.toml", "line": 6, "commit": c3 },
        { "rule": "cargo-lock-source", "path": kelvin, "line": 6, "commit": c4 },
    ]);
    assert_eq!(v["findings"], want, "{v}");
    let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
    let out = text(&o.stdout);
    let blob = |c: &str, p: &str| short(&w.git(&repo, &["rev-parse", &format!("{c}:{p}")])).to_string();
    for line in [
        format!("commit {}:.cargo/config.toml (blob {}): rule cargo-config-source, key source", short(&c1), blob(&c1, ".cargo/config.toml")),
        format!("commit {}:.cargo (blob {}): rule cargo-config-source, key source", short(&c2), blob(&c2, ".cargo")),
        format!("commit {}:Cargo.lock (blob {}): rule cargo-lock-removed", short(&c3), blob(&c3, "Cargo.lock")),
        format!("commit {}:{kelvin} (blob {}) line 6: rule cargo-lock-source, key evil 0.1.0", short(&c4), blob(&c4, kelvin)),
    ] {
        assert!(out.contains(&format!("  {line}\n")), "{line}\n{out}");
    }
    for secret in [fork, "mirror.example.invalid"] {
        assert!(!out.contains(secret) && !text(&o.stderr).contains(secret), "{secret} printed:\n{out}");
    }
}

/// The other Cargo rules and L9 through the binary: a checksum changed for
/// an unchanged version, a new source that is not crates.io, a source
/// replacement in `.cargo/config.toml`, a plaintext dotenv; each named by
/// its key, never the source, the checksum or the file's bytes. A dotenv
/// with the ai-env marker, and a template, pass.
#[test]
fn cargo_rules_and_the_dotenv_rule_name_their_keys() {
    let w = World::new();
    let repo = w.repo("app");
    let crates = "registry+https://github.com/rust-lang/crates.io-index";
    let (sum_a, sum_b) = ("a".repeat(64), "b".repeat(64));
    let lock = |sum: &str, extra: &str| format!("version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"{crates}\"\nchecksum = \"{sum}\"\n{extra}");
    w.write(&repo, "Cargo.lock", &lock(&sum_a, ""));
    w.commit(&repo, "the lock");
    let origin = w.bare("origin.git");
    w.git(&repo, &["remote", "add", "origin", origin.to_str().unwrap()]);
    w.git(&repo, &["push", "-q", "origin", "main"]);
    let fork = "git+https://example.invalid/fork/serde-evil?rev=1#0123456789abcdef0123456789abcdef01234567";
    w.write(&repo, "Cargo.lock", &lock(&sum_b, &format!("\n[[package]]\nname = \"evil\"\nversion = \"0.1.0\"\nsource = \"{fork}\"\n")));
    w.write(&repo, ".cargo/config.toml", "[source.crates-io]\nreplace-with = \"mirror\"\n\n[source.mirror]\nregistry = \"sparse+https://mirror.example.invalid/index/\"\n");
    let pw = format!("pw{}", "Z".repeat(10));
    w.write(&repo, "deploy/.env", &format!("DB_PASSWORD={pw}\n"));
    w.write(&repo, "deploy/prod.env", "AI_ENV=1\nciphertext\n");
    w.write(&repo, ".env.example", "DB_PASSWORD=\n");
    let c1 = w.commit(&repo, "dependencies and deploy");
    let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    let at = |path: &str| format!("commit {}:{path} (blob {})", short(&c1), short(&w.git(&repo, &["rev-parse", &format!("HEAD:{path}")])));
    for line in [
        format!("{} line 7: rule cargo-lock-checksum, key serde 1.0.200", at("Cargo.lock")),
        format!("{} line 12: rule cargo-lock-source, key evil 0.1.0", at("Cargo.lock")),
        format!("{} line 2: rule cargo-config-source, key source.crates-io.replace-with", at(".cargo/config.toml")),
        format!("{} line 5: rule cargo-config-source, key source.mirror.registry", at(".cargo/config.toml")),
        format!("{}: rule env-file-plaintext", at("deploy/.env")),
    ] {
        assert!(out.contains(&format!("  {line}\n")), "{line}\n{out}");
    }
    assert!(out.contains("5 finding(s):"), "{out}");
    for secret in [fork, sum_b.as_str(), "mirror.example.invalid", pw.as_str()] {
        assert!(!out.contains(secret) && !text(&o.stderr).contains(secret), "{secret} printed:\n{out}");
    }
}

/// A key in a commit message withholds that commit's subject (naming the
/// rule) and is a finding at the commit; a subject's control characters
/// never reach the terminal. No repository, a REV or a base naming no
/// commit: exit 1, nothing audited. An annotated tag is reviewed as a push
/// of it carries it: its own message too, its commit the head.
#[test]
fn subjects_are_shown_safely_and_bad_input_is_exit_1() {
    let w = World::new();
    let (repo, _origin, _) = w.pushed("app");
    let key = key_id();
    let c1 = w.commit(&repo, &format!("rotate {key}"));
    let c2 = w.commit(&repo, "colour \u{1b}[31mred\u{7} done");
    let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains(&format!("  {} colour [31mred done\n  {} (subject withheld: rule aws-access-key-id)\n", short(&c2), short(&c1))), "{out}");
    assert!(out.contains(&format!("  commit {} line 6: rule aws-access-key-id\n", short(&c1))), "{out}");
    assert!(!out.contains(&key) && !out.contains('\u{1b}'));
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    assert_eq!(v["commits"][1], json!({ "id": c1, "subject": null, "withheld": "aws-access-key-id" }));
    assert_eq!(v["findings"][0], json!({ "rule": "aws-access-key-id", "path": "", "line": 6, "commit": c1 }));
    let audited = w.audit("box_review").len();
    let plain = w.root.join("letters");
    std::fs::create_dir_all(&plain).unwrap();
    for (dir, args, says) in [
        (&plain, vec!["box", "review", "HEAD"], "is not a git repository"),
        (&repo, vec!["box", "review", "no-such-branch"], "box review: no-such-branch names no commit"),
        (&repo, vec!["box", "review", "HEAD", "--base", "origin/nope"], "box review: --base origin/nope names no commit"),
        (&repo, vec!["box", "review", "--repo", plain.to_str().unwrap(), "HEAD"], "is not a git repository"),
    ] {
        let o = w.ai_env(dir, &args, None);
        assert_eq!(o.status.code(), Some(1), "{args:?}: {}", text(&o.stderr));
        assert!(text(&o.stderr).contains(says), "{args:?}: {}", text(&o.stderr));
    }
    let o = w.ai_env(&repo, &["box", "review"], None);
    assert_eq!(o.status.code(), Some(2), "clap: REV or --pre-push");
    assert_eq!(w.audit("box_review").len(), audited, "nothing reviewed, nothing audited");
    // An annotated tag of the head, the head itself the base: only the tag object is new, and its message is read.
    w.git(&repo, &["tag", "-a", "v1", "-m", &format!("release {key}")]);
    let tag = w.git(&repo, &["rev-parse", "v1"]);
    let o = w.ai_env(&repo, &["box", "review", "v1", "--base", "HEAD"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains(&format!("1 finding(s):\n  v1 (blob {}) line 6: rule aws-access-key-id\n", short(&tag))) && !out.contains(&key), "{out}");
    let v = json_of(&w.ai_env(&repo, &["box", "review", "v1", "--base", "HEAD", "--json"], None));
    assert_eq!((v["head"].as_str(), v["rev"].as_str(), ids(&v).len()), (Some(c2.as_str()), Some("v1"), 0), "{v}");
    assert_eq!(v["findings"], json!([{ "rule": "aws-access-key-id", "path": "v1", "line": 6, "commit": c2 }]), "{v}");
}

/// The hook refuses, before reading any commit (exit 9, audited
/// `refused`): a local or remote ref under `refs/remotes/` or
/// `refs/ai-env/` (a box ref pushed, a `--mirror` push) and a remote named
/// `box` or `box-quarantine` (any case). Through git: `git push --mirror`
/// and `git push box` are refused and the remotes stay as they were; a
/// clean push goes through.
#[test]
fn pre_push_refuses_box_refs_mirror_and_a_remote_named_box() {
    let w = World::new();
    let (repo, origin, c0) = w.pushed("app");
    w.write(&repo, "work.txt", "work\n");
    let c1 = w.commit(&repo, "work");
    w.git(&repo, &["update-ref", "refs/remotes/box/main", &c1]);
    let zero = "0".repeat(40);
    let url = origin.display().to_string();
    for (remote, line, says) in [
        ("origin", format!("refs/remotes/box/main {c1} refs/heads/main {c0}\n"), "it names refs/remotes/box/main"),
        ("origin", format!("refs/heads/main {c1} refs/heads/main {c0}\nrefs/heads/main {c1} refs/AI-ENV/seed-wip {zero}\n"), "it names refs/AI-ENV/seed-wip"),
        ("box", format!("refs/heads/main {c1} refs/heads/main {zero}\n"), "the remote is named box"),
        ("Box-Quarantine", format!("refs/heads/main {c1} refs/heads/main {zero}\n"), "the remote is named box-quarantine"),
    ] {
        let o = w.ai_env(&repo, &["box", "review", "--pre-push", remote, &url], Some(line.as_bytes()));
        assert_eq!(o.status.code(), Some(9), "{remote} {line}: {}", text(&o.stderr));
        let err = text(&o.stderr);
        assert!(err.starts_with("ai-env: box review: the push is refused: ") && err.contains(says) && err.trim_end().ends_with("nothing was reviewed"), "{err}");
        assert!(text(&o.stdout).ends_with("box review: refused\n"), "{}", text(&o.stdout));
    }
    let rows = w.audit("box_review");
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|r| r["detail"]["verdict"] == "refused" && r["detail"]["mode"] == "pre_push" && r["detail"]["commits"] == "0"));
    assert_eq!(rows[0]["detail"]["remote"], "origin");
    assert_eq!(rows[2]["detail"]["remote"], "url", "box is no remote of this repository: a URL");
    let v = json_of(&w.ai_env(&repo, &["box", "review", "--pre-push", "origin", &url, "--json"], Some(format!("refs/remotes/box/main {c1} refs/heads/x {zero}\n").as_bytes())));
    assert_eq!((v["verdict"].as_str(), v["commits"].as_array().map(Vec::len), v["head"].is_null()), (Some("refused"), Some(0), true));
    // Through git, with the hook installed.
    let o = w.ai_env(&repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let o = w.git_out(&repo, &["push", "--mirror", "origin"]);
    assert!(!o.status.success() && both(&o).contains("box review: the push is refused: it names refs/"), "{}", both(&o));
    assert_eq!(w.git(&origin, &["for-each-ref", "--format=%(refname) %(objectname)"]), format!("refs/heads/main {c0}"), "the mirror push sent nothing");
    let other = w.bare("box.git");
    w.git(&repo, &["remote", "add", "box", other.to_str().unwrap()]);
    let o = w.git_out(&repo, &["push", "box", "main"]);
    assert!(!o.status.success() && both(&o).contains("the remote is named box"), "{}", both(&o));
    assert_eq!(w.git(&other, &["for-each-ref"]), "");
    assert_eq!(w.git(&repo, &["rev-parse", "refs/remotes/box/main"]), c1, "ai-env's box ref is untouched");
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(o.status.success(), "{}", both(&o));
    assert_eq!(w.git(&origin, &["rev-parse", "refs/heads/main"]), c1);
}

/// The hook reviews each push against the remote: what the remote already
/// holds is not read again; a key in a pushed commit refuses the push
/// naming the commit and the line, and the remote keeps its tip; deleting
/// a remote branch is not reviewed.
#[test]
fn the_hook_reviews_each_push_against_the_remote() {
    let w = World::new();
    let (repo, origin, _) = w.pushed("app");
    let o = w.ai_env(&repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert!(!text(&o.stderr).contains("work tree"), "`.git/hooks` is no work-tree path: {}", text(&o.stderr));
    w.write(&repo, "a.txt", "a\n");
    let c1 = w.commit(&repo, "clean work");
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(o.status.success(), "{}", both(&o));
    assert!(both(&o).contains("box review --pre-push: ") && both(&o).contains("1 ref(s) to the remote origin: 1 commit(s) it lacks"), "{}", both(&o));
    w.write(&repo, "deploy.conf", &format!("key: {}\n", key_id()));
    let c2 = w.commit(&repo, "deploy key");
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(!o.status.success());
    let out = both(&o);
    assert!(out.contains(&format!("commit {}:deploy.conf (blob ", short(&c2))) && out.contains("line 1: rule aws-access-key-id") && out.contains("1 commit(s) it lacks"), "{out}");
    assert!(out.contains("box review: 1 finding(s) in the commits this push carries"), "{out}");
    assert_eq!(w.git(&origin, &["rev-parse", "refs/heads/main"]), c1);
    let row = w.audit("box_review").pop().unwrap();
    assert_eq!((row["detail"]["mode"].as_str(), row["detail"]["remote"].as_str(), row["detail"]["verdict"].as_str(), row["detail"]["findings"].as_str()), (Some("pre_push"), Some("origin"), Some("findings"), Some("1")));
    w.git(&repo, &["push", "-q", "--no-verify", "origin", "HEAD~1:refs/heads/old"]);
    let o = w.git_out(&repo, &["push", "origin", ":refs/heads/old"]);
    assert!(o.status.success(), "a deletion carries nothing: {}", both(&o));
}

/// `box hook-install` writes where git runs hooks (`core.hooksPath`
/// honoured), 0755, the body naming this binary; again, it is up to date;
/// a dry run writes nothing and no audit row; another hook there is never
/// written over (exit 1, the line it needs printed, and said when it already
/// calls the review), while a hook of ours naming another binary, or no
/// longer executable (git would skip it), is rewritten. A hook directory in
/// the work tree, as this `core.hooksPath` is, is warned about: a merged
/// commit can replace the hook.
#[test]
fn the_hook_follows_core_hooks_path_and_never_overwrites_a_foreign_hook() {
    use std::os::unix::fs::PermissionsExt as _;
    let w = World::new();
    let repo = w.repo("app");
    w.git(&repo, &["config", "core.hooksPath", "githooks"]);
    let hook = repo.join("githooks/pre-push");
    let warning = format!("ai-env: warning: {} lies in the work tree (core.hooksPath), or git reads a configuration file there that can move it (an include): a merged or checked-out commit can replace either", hook.display());
    let o = w.ai_env(&repo, &["box", "hook-install", "--dry-run", "--json"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(json_of(&o), json!({ "repo": repo.display().to_string(), "hook": hook.display().to_string(), "outcome": "would_install" }));
    assert!(text(&o.stderr).contains(&warning), "{}", text(&o.stderr));
    let o = w.ai_env(&repo, &["box", "hook-install", "--dry-run"], None);
    let out = text(&o.stdout);
    assert!(out.starts_with(&format!("box hook-install --dry-run: {}: would install (0755)\n#!/bin/sh\n# ai-env pre-push review\n", hook.display())) && out.ends_with("nothing was written\n"), "{out}");
    assert!(!hook.exists() && w.audit("hook_install").is_empty(), "a dry run writes nothing");
    let o = w.ai_env(&w.root, &["box", "hook-install", repo.to_str().unwrap()], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert!(text(&o.stdout).starts_with(&format!("installed the pre-push review hook: {}", hook.display())), "{}", text(&o.stdout));
    assert!(text(&o.stderr).contains(&warning), "{}", text(&o.stderr));
    let body = std::fs::read_to_string(&hook).unwrap();
    assert!(body.contains(&format!("\nai_env='{}'\n", ai_env_canonical())) && body.ends_with("exec \"$ai_env\" box review --pre-push \"$1\" \"$2\"\n"), "{body}");
    assert_eq!(std::fs::metadata(&hook).unwrap().permissions().mode() & 0o777, 0o755);
    assert!(!repo.join(".git/hooks/pre-push").exists(), "core.hooksPath decides where");
    let v = json_of(&w.ai_env(&repo, &["box", "hook-install", "--json"], None));
    assert_eq!(v["outcome"], "up_to_date");
    // Its exec bit lost, its bytes the same: git would skip it, so it is rewritten 0755.
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(json_of(&w.ai_env(&repo, &["box", "hook-install", "--json"], None))["outcome"], "installed");
    assert_eq!((std::fs::read_to_string(&hook).unwrap(), std::fs::metadata(&hook).unwrap().permissions().mode() & 0o777), (body.clone(), 0o755));
    // A hook of ours naming another binary: rewritten.
    std::fs::write(&hook, body.replace(&ai_env_canonical(), "/opt/old/ai-env")).unwrap();
    assert_eq!(json_of(&w.ai_env(&repo, &["box", "hook-install", "--json"], None))["outcome"], "installed");
    assert_eq!(std::fs::read_to_string(&hook).unwrap(), body);
    // Another hook: never written over.
    let theirs = "#!/bin/sh\n# the team's own checks\nexit 0\n";
    std::fs::write(&hook, theirs).unwrap();
    let o = w.ai_env(&repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o.stderr));
    let err = text(&o.stderr);
    let line = format!("ai_env_refs=$(cat; echo .); ai_env_refs=${{ai_env_refs%.}}\nprintf '%s' \"$ai_env_refs\" | '{}' box review --pre-push \"$1\" \"$2\" || exit 1", ai_env_canonical());
    let needs = "its pushes are reviewed only if it runs these two lines first, before any exit or read of its stdin, and feeds its own stdin readers from them (printf '%s' \"$ai_env_refs\" | git lfs pre-push \"$@\"):";
    assert!(err.contains(&format!("{} is another pre-push hook: it is never written over; {needs}\n{line}", hook.display())), "{err}");
    assert!(!err.contains("warning"), "no hook of ours, no warning: {err}");
    assert_eq!(std::fs::read_to_string(&hook).unwrap(), theirs);
    let o = w.ai_env(&repo, &["box", "hook-install", "--dry-run", "--json"], None);
    assert_eq!((o.status.code(), json_of(&o)["outcome"].as_str()), (Some(0), Some("foreign")));
    // One that already calls the review: said so, and still never written over (it may exit before the call).
    let chained = format!("#!/bin/sh\nnpm test || exit 1\n{line}\n");
    std::fs::write(&hook, &chained).unwrap();
    let o = w.ai_env(&repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains(&format!("{} is another pre-push hook, which calls box review --pre-push: it is never written over; {needs}\n{line}", hook.display())), "{}", text(&o.stderr));
    assert_eq!(std::fs::read_to_string(&hook).unwrap(), chained);
    let outcomes: Vec<String> = w.audit("hook_install").iter().map(|r| r["detail"]["outcome"].as_str().unwrap().to_string()).collect();
    assert_eq!(outcomes, ["installed", "up_to_date", "installed", "installed", "foreign", "foreign"]);
    let o = w.ai_env(&w.root, &["box", "hook-install", w.root.join("home").to_str().unwrap()], None);
    assert_eq!(o.status.code(), Some(1), "no repository");
    assert!(text(&o.stderr).contains("is not a git repository"), "{}", text(&o.stderr));
}

/// The hook fails closed: when the binary it names is gone, every push is
/// refused saying how to reinstall it; reinstalled, pushes are reviewed again.
#[test]
fn the_hook_fails_closed_without_its_binary() {
    let w = World::new();
    let (repo, origin, c0) = w.pushed("app");
    let bin = w.root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let copy = bin.join("ai-env");
    if std::fs::hard_link(AI_ENV, &copy).is_err() {
        std::fs::copy(AI_ENV, &copy).unwrap();
    }
    let o = w.ai_env_at(&copy, &repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let hook = repo.join(".git/hooks/pre-push");
    assert!(std::fs::read_to_string(&hook).unwrap().contains(&format!("ai_env='{}'", copy.display())));
    std::fs::remove_file(&copy).unwrap();
    w.write(&repo, "a.txt", "a\n");
    let c1 = w.commit(&repo, "work");
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(!o.status.success());
    assert!(both(&o).contains(&format!("ai-env pre-push: {} is missing: the push is refused (ai-env box hook-install reinstalls the hook)", copy.display())), "{}", both(&o));
    assert_eq!(w.git(&origin, &["rev-parse", "refs/heads/main"]), c0);
    let o = w.ai_env(&repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(o.status.success(), "{}", both(&o));
    assert_eq!(w.git(&origin, &["rev-parse", "refs/heads/main"]), c1);
}

/// A push to a bare URL (git passes it as REMOTE too, credentials and
/// all): neither the URL nor any part of it is printed, in text or
/// `--json`, on success or with a finding, nor audited (`remote` is `url`),
/// nor passed to any git; a plain name that is no remote here, and a
/// REMOTE that differs from URL but is no plain name, count as URLs too.
#[test]
fn pre_push_to_a_bare_url_never_prints_or_audits_it() {
    let mut w = World::new();
    let fake = w.root.join("fakebin");
    std::fs::create_dir_all(&fake).unwrap();
    let log = w.root.join("git-argv.log");
    install_fake_git(&fake.join("git"), &log, &[]);
    w.first_path = Some(fake);
    let repo = w.repo("app");
    w.write(&repo, "a.txt", "a\n");
    let c0 = w.commit(&repo, "clean");
    let token = format!("{}{}", "ghp_", "Q".repeat(36));
    // The scheme's separator apart: this file's own text never reads as credentials (`url-credentials`).
    let sep = "://";
    let url = format!("https{sep}ai-env-user:{token}@example.invalid/o/r.git");
    let other = "https://example.invalid/other.git";
    let never = [token.as_str(), "example.invalid", "ai-env-user", url.as_str()];
    let pushed = format!("refs/heads/main {c0} refs/heads/main {}\n", "0".repeat(40));
    let check = |o: &Output, what: &str| {
        for s in never {
            assert!(!text(&o.stdout).contains(s) && !text(&o.stderr).contains(s), "{what}: {s:?} printed:\n{}{}", text(&o.stdout), text(&o.stderr));
        }
    };
    let o = w.ai_env(&repo, &["box", "review", "--pre-push", &url, &url], Some(pushed.as_bytes()));
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    check(&o, "text");
    assert!(text(&o.stdout).contains("1 ref(s) to a URL (not shown)"), "{}", text(&o.stdout));
    let o = w.ai_env(&repo, &["box", "review", "--pre-push", &url, &url, "--json"], Some(pushed.as_bytes()));
    check(&o, "json");
    assert_eq!(json_of(&o)["whole_history"], true, "no base: a URL has no tracking refs");
    for (remote, url) in [(url.as_str(), other), ("origin", url.as_str()), ("origin", other)] {
        let o = w.ai_env(&repo, &["box", "review", "--pre-push", remote, url], Some(pushed.as_bytes()));
        assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
        check(&o, remote);
    }
    // With a finding, the refusal's lines too.
    w.write(&repo, "deploy.conf", &format!("key: {}\n", key_id()));
    let c1 = w.commit(&repo, "key");
    let pushed = format!("refs/heads/main {c1} refs/heads/main {c0}\n");
    let o = w.ai_env(&repo, &["box", "review", "--pre-push", &url, &url], Some(pushed.as_bytes()));
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    check(&o, "finding");
    assert!(text(&o.stdout).contains("1 ref(s) to a URL (not shown): 1 commit(s) it lacks") && text(&o.stdout).contains("rule aws-access-key-id"), "{}", text(&o.stdout));
    let o = w.ai_env(&repo, &["box", "review", "--pre-push", &url, &url, "--json"], Some(pushed.as_bytes()));
    check(&o, "finding json");
    assert_eq!(ids(&json_of(&o)), [c1.as_str()], "reviewed against the remote's tip");
    let rows = w.audit("box_review");
    assert_eq!(rows.len(), 7);
    assert!(rows.iter().all(|r| r["detail"]["remote"] == "url" && r["detail"]["mode"] == "pre_push"), "{rows:?}");
    let audit = w.audit_text();
    for s in never {
        assert!(!audit.contains(s), "{s:?} audited");
    }
    let calls = git_calls(&log);
    assert!(!calls.is_empty(), "the fake git logged ai-env's runs");
    for c in &calls {
        for s in never {
            assert!(!c.args.iter().any(|a| a.contains(s)), "{s:?} in a git argument: {:?}", c.args);
        }
    }
}

/// When git runs the pre-push hook from the work tree (`core.hooksPath`
/// there), a change any reviewed commit makes at its path is a finding
/// (`pre-push-hook-changed`, plans/s9-contracts.md §13, I2), named at that
/// commit: the hook rewritten, made non-executable (git would skip it),
/// replaced by a link holding its own text (the same blob, another mode) or
/// deleted; its directory replaced by a link (that link, the hook gone from
/// under it, and the file the link reaches). Committing the hook there is
/// such a change too: that push goes with `--no-verify`. A change
/// elsewhere, and a merge bringing the remote's own change to the hook, are
/// none; nor is any of them when git runs the hook from `.git/hooks`.
/// Through git, the push of such a commit is refused, the remote keeping
/// its refs.
#[test]
fn a_change_to_the_pre_push_hook_in_the_work_tree_is_a_finding() {
    use std::os::unix::fs::PermissionsExt as _;
    let w = World::new();
    let (repo, origin, _) = w.pushed("app");
    w.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    let o = w.ai_env(&repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let body = std::fs::read_to_string(repo.join(".githooks/pre-push")).unwrap();
    let shared = w.commit(&repo, "share the hook");
    let blob = w.git(&repo, &["rev-parse", "HEAD:.githooks/pre-push"]);
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(!o.status.success() && both(&o).contains(&format!("commit {}:.githooks/pre-push (blob {}): rule pre-push-hook-changed", short(&shared), short(&blob))), "{}", both(&o));
    assert!(both(&o).contains("note: git runs the pre-push hook from the work tree (.githooks/pre-push): a change there is a finding (pre-push-hook-changed)"), "{}", both(&o));
    w.git(&repo, &["push", "-q", "--no-verify", "origin", "main"]);
    // Each case a branch of another clone (no hook runs there), fetched here as a local branch.
    let other = w.root.join("other");
    w.git(&w.root, &["clone", "-q", "-b", "main", origin.to_str().unwrap(), other.to_str().unwrap()]);
    let hook = other.join(".githooks/pre-push");
    let case = |name: &str, change: &dyn Fn()| -> String {
        w.git(&other, &["checkout", "-q", "-B", name, "origin/main"]);
        change();
        let c = w.commit(&other, name);
        w.git(&repo, &["fetch", "-q", other.to_str().unwrap(), &format!("{name}:refs/heads/{name}")]);
        c
    };
    let rewrite = case("rewrite", &|| std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap());
    let chmod = case("chmod", &|| std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap());
    let link = case("link", &|| {
        std::fs::remove_file(&hook).unwrap();
        std::os::unix::fs::symlink(&body, &hook).unwrap();
    });
    let delete = case("delete", &|| std::fs::remove_file(&hook).unwrap());
    let moved = case("moved", &|| {
        std::fs::remove_dir_all(other.join(".githooks")).unwrap();
        w.write(&other, "tools/hooks/pre-push", "#!/bin/sh\nexit 0\n");
        std::os::unix::fs::symlink("tools/hooks", other.join(".githooks")).unwrap();
    });
    case("elsewhere", &|| w.write(&other, "README", "changed\n"));
    assert!(w.git(&repo, &["diff", "--raw", "chmod~1", "chmod"]).starts_with(":100755 100644 "), "a mode change alone");
    assert!(w.git(&repo, &["diff", "--raw", "--no-abbrev", "link~1", "link"]).contains(&format!(":100755 120000 {blob} {blob} T")), "the same blob, as a link");
    let review = |rev: &str| -> (Option<i32>, Value) {
        let o = w.ai_env(&repo, &["box", "review", rev, "--json"], None);
        (o.status.code(), json_of(&o)["findings"].clone())
    };
    let at = |path: &str, commit: &str| json!({ "rule": "pre-push-hook-changed", "path": path, "line": null, "commit": commit });
    for (rev, commit) in [("rewrite", &rewrite), ("chmod", &chmod), ("link", &link), ("delete", &delete)] {
        assert_eq!(review(rev), (Some(9), json!([at(".githooks/pre-push", commit)])), "{rev}");
    }
    assert_eq!(review("moved"), (Some(9), json!([at(".githooks", &moved), at(".githooks/pre-push", &moved), at("tools/hooks/pre-push", &moved)])));
    assert_eq!(review("elsewhere"), (Some(0), json!([])));
    // Through git: the push of the rewrite is refused, the remote keeping its refs.
    let o = w.git_out(&repo, &["push", "origin", "rewrite"]);
    assert!(!o.status.success() && both(&o).contains(&format!("commit {}:.githooks/pre-push (blob ", short(&rewrite))) && both(&o).contains("rule pre-push-hook-changed"), "{}", both(&o));
    assert_eq!(w.git(&origin, &["for-each-ref", "--format=%(refname)"]), "refs/heads/main");
    // A merge bringing the remote's own change to the hook: the merge base holds it.
    w.git(&other, &["checkout", "-q", "main"]);
    w.write(&other, ".githooks/pre-push", &body.replace("every push is reviewed first", "every push is reviewed first (the team's copy)"));
    w.commit(&other, "the team's hook");
    w.git(&other, &["push", "-q", "origin", "main"]);
    w.git(&repo, &["fetch", "-q", "origin"]);
    w.write(&repo, "local.txt", "local\n");
    w.commit(&repo, "local work");
    w.git(&repo, &["merge", "-q", "--no-edit", "origin/main"]);
    assert_eq!(review("HEAD"), (Some(0), json!([])));
    // The hook git runs from `.git/hooks`: a tracked `.githooks/pre-push` is a file like any other.
    w.git(&repo, &["config", "core.hooksPath", ".git/hooks"]);
    assert_eq!(review("rewrite"), (Some(0), json!([])));
    let o = w.ai_env(&repo, &["box", "review", "rewrite"], None);
    assert!(!text(&o.stdout).contains("pre-push hook from the work tree"), "{}", text(&o.stdout));
}

/// The pre-push hook git reaches through a link in the work tree is watched
/// as git names it (plans/s9-contracts.md §13, I2), wherever the link
/// leads: with `core.hooksPath` at `.githooks`, a tracked
/// `.githooks/pre-push` linking to a hook outside the repository, or an
/// ignored `.githooks` linking to a directory outside it. A merge replaces
/// either link (git takes an ignored one as expendable), so a commit
/// putting a file there is a finding at `.githooks/pre-push`, and the note
/// names that path.
#[test]
fn a_hook_reached_through_a_link_in_the_work_tree_is_watched_as_git_names_it() {
    use std::os::unix::fs::PermissionsExt as _;
    let w = World::new();
    w.write(&w.root, "shared-hooks/pre-push", "#!/bin/sh\necho the team's hook\nexit 0\n");
    let agents = "#!/bin/sh\necho the agent's hook\nexit 0\n";
    let note = "note: git runs the pre-push hook from the work tree (.githooks/pre-push): a change there is a finding (pre-push-hook-changed)\n";
    let review = |repo: &Path| -> (Option<i32>, Value, String) {
        let o = w.ai_env(repo, &["box", "review", "agent", "--base", "main", "--json"], None);
        let out = text(&w.ai_env(repo, &["box", "review", "agent", "--base", "main"], None).stdout);
        (o.status.code(), json_of(&o)["findings"].clone(), out)
    };
    let finding = |commit: &str| json!([{ "rule": "pre-push-hook-changed", "path": ".githooks/pre-push", "line": null, "commit": commit }]);
    // A tracked link at the hook's path, replaced by a file.
    let repo = w.repo("tracked");
    std::fs::create_dir_all(repo.join(".githooks")).unwrap();
    std::os::unix::fs::symlink("../../shared-hooks/pre-push", repo.join(".githooks/pre-push")).unwrap();
    w.commit(&repo, "the team's shared hook");
    w.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    w.git(&repo, &["checkout", "-q", "-b", "agent"]);
    std::fs::remove_file(repo.join(".githooks/pre-push")).unwrap();
    w.write(&repo, ".githooks/pre-push", agents);
    std::fs::set_permissions(repo.join(".githooks/pre-push"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let c1 = w.commit(&repo, "the agent's hook");
    assert!(w.git(&repo, &["diff", "--raw", "main", "agent"]).starts_with(":120000 100755 "), "a link replaced by a file");
    let (code, found, out) = review(&repo);
    assert_eq!((code, found), (Some(9), finding(&c1)), "{out}");
    assert!(out.contains(note), "{out}");
    // An ignored link on its way: the commit is made where it is no link (another clone).
    let repo = w.repo("ignored");
    w.write(&repo, ".gitignore", "/.githooks\n");
    w.commit(&repo, "the shared hooks are no part of the repository");
    std::os::unix::fs::symlink("../shared-hooks", repo.join(".githooks")).unwrap();
    w.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    let other = w.root.join("ignored-other");
    w.git(&w.root, &["clone", "-q", repo.to_str().unwrap(), other.to_str().unwrap()]);
    w.write(&other, ".githooks/pre-push", agents);
    w.git(&other, &["add", "-f", ".githooks/pre-push"]);
    let c1 = w.commit(&other, "the agent's hook");
    w.git(&repo, &["fetch", "-q", other.to_str().unwrap(), "main:agent"]);
    let (code, found, out) = review(&repo);
    assert_eq!((code, found), (Some(9), finding(&c1)), "{out}");
    assert!(out.contains(note), "{out}");
}

/// A watched file behind a link the remote already holds is reviewed under
/// the link's name, at its own path (plans/s9-contracts.md §13, I2): the
/// lock a `Cargo.lock` link reaches (through two links too), cargo's
/// configuration below a linked `.cargo`, the settings below a linked
/// `.claude` (D8's repo mode and the policy rule) and the file a settings
/// link reaches, the file a `.env` link reaches; a link on the way
/// retargeted is a finding at that link. A file beside those targets is
/// none, and links that leave the tree are followed nowhere.
#[test]
fn a_file_behind_a_link_the_remote_holds_is_reviewed_under_its_name() {
    let w = World::new();
    let repo = w.repo("app");
    let crates = "registry+https://github.com/rust-lang/crates.io-index";
    let fork = "git+https://example.invalid/fork/serde-evil?rev=1#0123456789abcdef0123456789abcdef01234567";
    let lock = |extra: &str| format!("version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"{crates}\"\nchecksum = \"{}\"\n{extra}", "a".repeat(64));
    let evil = |name: &str| format!("\n[[package]]\nname = \"{name}\"\nversion = \"0.1.0\"\nsource = \"{fork}\"\n");
    let settings = |extra: &str| format!("{{\n  \"permissions\": {{\n    \"allow\": [\n      \"Read(./src/**)\"{extra}\n    ]\n  }}\n}}\n");
    for (path, body) in [("locks.toml", lock("")), ("locks/real.toml", lock("")), ("locks/other.toml", lock("")), ("build-cfg/config.toml", "[build]\njobs = 2\n".to_string()), ("cfg/settings.json", settings("")), ("cfg/notes.md", "notes\n".to_string()), ("docs/team-settings.json", settings("")), ("secrets.txt", "AI_ENV=1\nciphertext\n".to_string())] {
        w.write(&repo, path, &body);
    }
    let link = |target: &str, at: &str| {
        std::fs::create_dir_all(repo.join(at).parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, repo.join(at)).unwrap();
    };
    link("locks.toml", "Cargo.lock");
    link("../lock-link", "sub/Cargo.lock");
    link("locks/real.toml", "lock-link");
    link("build-cfg", ".cargo");
    link("cfg", ".claude");
    link("../../docs/team-settings.json", "pkg/.claude/settings.json");
    link("secrets.txt", ".env");
    link("/etc", "tool/.cargo");
    link("../../outside.toml", "x/Cargo.lock");
    w.commit(&repo, "the links");
    let origin = w.bare("origin.git");
    w.git(&repo, &["remote", "add", "origin", origin.to_str().unwrap()]);
    w.git(&repo, &["push", "-q", "origin", "main"]);
    // Each target changed, never a link the remote holds but one: the review read none of them before I2.
    w.write(&repo, "locks.toml", &lock(&evil("evil")));
    let c1 = w.commit(&repo, "bump the lock");
    w.write(&repo, "build-cfg/config.toml", "[source.crates-io]\nreplace-with = \"mirror\"\n");
    let c2 = w.commit(&repo, "a mirror");
    w.write(&repo, "cfg/settings.json", &settings(",\n      \"Bash(*)\""));
    let c3 = w.commit(&repo, "let it run");
    w.write(&repo, "docs/team-settings.json", &settings(",\n      \"Bash(curl:*)\""));
    let c4 = w.commit(&repo, "let the team fetch");
    w.write(&repo, "locks/real.toml", &lock(&evil("evil-two")));
    let c5 = w.commit(&repo, "bump the sub-crate's lock");
    std::fs::remove_file(repo.join("lock-link")).unwrap();
    std::os::unix::fs::symlink("locks/other.toml", repo.join("lock-link")).unwrap();
    let c6 = w.commit(&repo, "the other lock");
    let pw = format!("pw{}", "Z".repeat(10));
    w.write(&repo, "secrets.txt", &format!("DB_PASSWORD={pw}\n"));
    let c7 = w.commit(&repo, "the password");
    w.write(&repo, "cfg/notes.md", "more notes\n");
    w.commit(&repo, "notes");
    let o = w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let v = json_of(&o);
    let want = json!([
        { "rule": "cargo-lock-source", "path": "locks.toml", "line": 12, "commit": c1 },
        { "rule": "cargo-config-source", "path": "build-cfg/config.toml", "line": 2, "commit": c2 },
        { "rule": "broad-allow", "path": "cfg/settings.json", "line": 5, "commit": c3 },
        { "rule": "allow-not-in-policy", "path": "cfg/settings.json", "line": 5, "commit": c3 },
        { "rule": "allow-not-in-policy", "path": "docs/team-settings.json", "line": 5, "commit": c4 },
        { "rule": "cargo-lock-source", "path": "locks/real.toml", "line": 12, "commit": c5 },
        { "rule": "cargo-lock-removed", "path": "lock-link", "line": null, "commit": c6 },
        { "rule": "env-file-plaintext", "path": "secrets.txt", "line": null, "commit": c7 },
    ]);
    assert_eq!(v["findings"], want, "{v}");
    let out = text(&w.ai_env(&repo, &["box", "review", "HEAD"], None).stdout);
    let at = |c: &str, p: &str| format!("commit {}:{p} (blob {})", short(c), short(&w.git(&repo, &["rev-parse", &format!("{c}:{p}")])));
    for line in [
        format!("{} line 12: rule cargo-lock-source, key evil 0.1.0", at(&c1, "locks.toml")),
        format!("{} line 2: rule cargo-config-source, key source.crates-io.replace-with", at(&c2, "build-cfg/config.toml")),
        format!("{}: rule cargo-lock-removed", at(&c6, "lock-link")),
    ] {
        assert!(out.contains(&format!("  {line}\n")), "{line}\n{out}");
    }
    for secret in [fork, "mirror\"", pw.as_str()] {
        assert!(!out.contains(secret), "{secret} printed:\n{out}");
    }
}

// ---- phase 4 (RVH-1 to RVH-10) ----

impl World {
    /// `ai-env args` in `dir` with its stdout a pipe whose reader is gone (a `| head` that quit): a write there is
    /// EPIPE. Its exit code and its stderr.
    fn ai_env_closed_stdout(&self, dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> (Option<i32>, String) {
        use std::io::Write as _;
        use std::process::Stdio;
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut cmd = self.command(Path::new(AI_ENV));
        cmd.args(args).current_dir(dir).stdout(writer).stderr(Stdio::piped()).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        let mut child = cmd.spawn().unwrap();
        if let (Some(bytes), Some(mut sink)) = (stdin, child.stdin.take()) {
            let bytes = bytes.to_vec();
            std::thread::spawn(move || {
                let _ = sink.write_all(&bytes);
            });
        }
        let o = common::bounded::finish_within(child, LIMIT, "ai-env");
        (o.status.code(), text(&o.stderr))
    }
}

/// The verdict decides the exit, never the report's write (S9 phase 4,
/// RVH-1): with stdout a pipe whose reader is gone, `box review` with a
/// finding exits 9, the hook's review of a push carrying it exits 9, a push
/// the hook refuses outright (a box ref) exits 9, each audited; a clean
/// range still exits 0 (nothing found: the write's failure is no refusal).
#[test]
fn a_closed_stdout_never_passes_a_finding() {
    let w = World::new();
    let (repo, origin, c0) = w.pushed("app");
    let zeros = "0".repeat(40);
    w.write(&repo, "clean.txt", "clean\n");
    let clean = w.commit(&repo, "clean work");
    let (code, err) = w.ai_env_closed_stdout(&repo, &["box", "review", "HEAD"], None);
    assert_eq!(code, Some(0), "a clean range: {err}");
    let refs = format!("refs/heads/main {clean} refs/heads/main {c0}\n");
    let url = origin.to_str().unwrap();
    let (code, err) = w.ai_env_closed_stdout(&repo, &["box", "review", "--pre-push", "origin", url], Some(refs.as_bytes()));
    assert_eq!(code, Some(0), "a clean push: {err}");
    w.write(&repo, "deploy.conf", &format!("key: {}\n", key_id()));
    let keyed = w.commit(&repo, "deploy key");
    let (code, err) = w.ai_env_closed_stdout(&repo, &["box", "review", "HEAD"], None);
    assert_eq!(code, Some(9), "a finding, its report unwritten: {err}");
    assert!(err.contains("1 finding(s) in the commits a push of HEAD would carry"), "{err}");
    let refs = format!("refs/heads/main {keyed} refs/heads/main {c0}\n");
    let (code, err) = w.ai_env_closed_stdout(&repo, &["box", "review", "--pre-push", "origin", url], Some(refs.as_bytes()));
    assert_eq!(code, Some(9), "the push carrying it is refused: {err}");
    let refs = format!("refs/remotes/box/main {clean} refs/heads/main {zeros}\n");
    let (code, err) = w.ai_env_closed_stdout(&repo, &["box", "review", "--pre-push", "origin", url], Some(refs.as_bytes()));
    assert_eq!(code, Some(9), "a box ref is refused before anything is read: {err}");
    let verdicts: Vec<String> = w.audit("box_review").iter().map(|r| r["detail"]["verdict"].as_str().unwrap().to_string()).collect();
    assert_eq!(verdicts, ["pass", "pass", "findings", "findings", "refused"], "each run audited");
}

/// cargo's `include` (S9 phase 4, RVH-2): a new include is a finding of
/// its own (`include`), and the file it names is reviewed as cargo reads
/// it, under the including configuration's name: its source replacement is
/// named at its own path, whether the include came in the same commit or a
/// merge base held it already (a later change to an included file), the
/// string form and the table form alike. Never the value.
#[test]
fn a_cargo_include_and_the_file_it_names_are_reviewed() {
    let w = World::new();
    let (repo, _origin, _) = w.pushed("app");
    let mirror = |host: &str| format!("[source.crates-io]\nreplace-with = \"mirror\"\n\n[source.mirror]\nregistry = \"sparse+https://{host}/index/\"\n");
    w.write(&repo, ".cargo/config.toml", "# the team's\ninclude = [\"mirror.toml\"]\n\n[build]\njobs = 2\n");
    w.write(&repo, ".cargo/mirror.toml", &mirror("mirror.example.invalid"));
    let c1 = w.commit(&repo, "a mirror through an include");
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    let want = json!([
        { "rule": "cargo-config-source", "path": ".cargo/config.toml", "line": 2, "commit": c1 },
        { "rule": "cargo-config-source", "path": ".cargo/mirror.toml", "line": 2, "commit": c1 },
        { "rule": "cargo-config-source", "path": ".cargo/mirror.toml", "line": 5, "commit": c1 },
    ]);
    assert_eq!(v["findings"], want, "{v}");
    let out = text(&w.ai_env(&repo, &["box", "review", "HEAD"], None).stdout);
    assert!(out.contains(":.cargo/config.toml (blob ") && out.contains("line 2: rule cargo-config-source, key include\n"), "{out}");
    assert!(!out.contains("mirror.example.invalid"), "{out}");
    // The remote holds both now: a later change to the included file is reviewed as cargo's configuration.
    w.git(&repo, &["push", "-q", "--no-verify", "origin", "main"]);
    w.write(&repo, ".cargo/mirror.toml", &mirror("other.example.invalid"));
    let c2 = w.commit(&repo, "another mirror");
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    assert_eq!(v["findings"], json!([{ "rule": "cargo-config-source", "path": ".cargo/mirror.toml", "line": 5, "commit": c2 }]), "{v}");
    // The table form, nested includes, a file outside `.cargo/`.
    w.git(&repo, &["reset", "-q", "--hard", "origin/main"]);
    w.write(&repo, ".cargo/config.toml", "include = [{ path = \"../shared/cargo.toml\" }]\n");
    w.git(&repo, &["commit", "-q", "-a", "-m", "a shared include"]);
    w.git(&repo, &["push", "-q", "--no-verify", "origin", "main"]);
    w.write(&repo, "shared/cargo.toml", "include = [\"deeper.toml\"]\n");
    w.write(&repo, "shared/deeper.toml", "[patch.crates-io]\nserde = { path = \"../serde\" }\n");
    let c3 = w.commit(&repo, "deeper");
    let v = json_of(&w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None));
    let want = json!([
        { "rule": "cargo-config-source", "path": "shared/cargo.toml", "line": 1, "commit": c3 },
        { "rule": "cargo-config-source", "path": "shared/deeper.toml", "line": 2, "commit": c3 },
    ]);
    assert_eq!(v["findings"], want, "{v}");
}

/// What the `toml` crate (TOML 1.0) does not read fails closed (S9 phase
/// 4, RVH-3): cargo 1.98 reads TOML 1.1, a newline or a trailing comma
/// inside an inline table, so such a `.cargo/config.toml` and such a
/// `Cargo.lock` are findings at the file (keyed `source`, and no key),
/// where the same tables in TOML 1.0 are named one by one.
#[test]
fn toml_one_one_forms_cargo_reads_fail_closed() {
    let w = World::new();
    let (repo, _origin, _) = w.pushed("app");
    let fork = "git+https://example.invalid/evil#0123456789abcdef0123456789abcdef01234567";
    w.write(&repo, ".cargo/config.toml", "source = {\n  crates-io = { replace-with = \"mirror\", },\n  mirror = { registry = \"sparse+https://mirror.example.invalid/index/\", },\n}\n");
    w.write(&repo, "Cargo.lock", &format!("version = 4\npackage = [\n  {{ name = \"evil\", version = \"0.1.0\", source = \"{fork}\", }},\n]\n"));
    let c1 = w.commit(&repo, "TOML 1.1");
    let o = w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let v = json_of(&o);
    let want = json!([
        { "rule": "cargo-config-source", "path": ".cargo/config.toml", "line": null, "commit": c1 },
        { "rule": "cargo-lock-source", "path": "Cargo.lock", "line": null, "commit": c1 },
    ]);
    assert_eq!(v["findings"], want, "{v}");
    let out = text(&w.ai_env(&repo, &["box", "review", "HEAD"], None).stdout);
    assert!(out.contains("rule cargo-config-source, key source\n") && !out.contains(fork) && !out.contains("mirror.example.invalid"), "{out}");
}

/// A settings file serde_json does not read is no pass under trust (S9
/// phase 4, RVH-4): with `trust_repo_settings`, D8 is off, and a
/// `settings.json` granting `Bash(*)` beside a lone surrogate, nesting past
/// 128 or a byte that is no UTF-8 (Node reads its `permissions.allow` all
/// the same) is `allow-not-in-policy` at `permissions.allow`.
#[test]
fn an_unreadable_settings_file_is_a_finding_under_trust() {
    let w = World::new();
    let (repo, _origin, _) = w.pushed("app");
    std::fs::write(w.bridge().join("bridge.toml"), format!("[[workspace]]\npath = {:?}\ntrust_repo_settings = true\n", repo.display().to_string())).unwrap();
    let grant = "{\"permissions\": {\"allow\": [\"Bash(*)\"]}, \"x\": ";
    let mut raw = format!("{grant}\"").into_bytes();
    raw.extend_from_slice(&[0xff, b'"', b'}', b'\n']);
    for (what, doc) in [
        ("a lone surrogate", format!("{grant}\"\\ud800\"}}\n").into_bytes()),
        ("nesting past 128", format!("{grant}{}1{}}}\n", "[".repeat(129), "]".repeat(129)).into_bytes()),
        ("a byte that is no UTF-8", raw),
    ] {
        w.git(&repo, &["reset", "-q", "--hard", "origin/main"]);
        std::fs::create_dir_all(repo.join(".claude")).unwrap();
        std::fs::write(repo.join(".claude/settings.json"), &doc).unwrap();
        let c = w.commit(&repo, what);
        let o = w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None);
        assert_eq!(o.status.code(), Some(9), "{what}: {}", text(&o.stderr));
        assert_eq!(json_of(&o)["findings"], json!([{ "rule": "allow-not-in-policy", "path": ".claude/settings.json", "line": null, "commit": c }]), "{what}");
    }
}

/// A key path that trips a tripwire is never shown (S9 phase 4, RVH-5): a
/// token as a JSON key holding `bypassPermissions` is named by both rules,
/// and the token is in neither stdout nor stderr.
#[test]
fn a_token_as_a_settings_key_is_never_printed() {
    let w = World::new();
    let (repo, _origin, _) = w.pushed("app");
    let token = format!("{}{}", "ghp_", "Ab1".repeat(12));
    w.write(&repo, ".claude/settings.json", &format!("{{\"x\": {{\"{token}\": \"bypassPermissions\"}}}}\n"));
    w.commit(&repo, "a key");
    let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains("rule github-pat") && out.contains("rule bypass-permissions"), "{out}");
    assert!(!out.contains(&token) && !text(&o.stderr).contains(&token) && !out.contains(&token[..20]), "{out}");
}

/// Two push URLs (S9 phase 4, RVH-6): git moves `refs/remotes/<remote>/*`
/// after the first, so the review of the second never takes them as a
/// base: a commit with a key the first URL (and the fetch URL) held
/// already is still refused on its way to a second, empty one.
#[test]
fn a_second_push_url_is_reviewed_against_what_it_holds() {
    let w = World::new();
    let (repo, origin, _) = w.pushed("app");
    w.write(&repo, "deploy.conf", &format!("key: {}\n", key_id()));
    w.commit(&repo, "an old key");
    w.git(&repo, &["push", "-q", "--no-verify", "origin", "main"]);
    let second = w.bare("second.git");
    w.git(&repo, &["remote", "set-url", "--add", "--push", "origin", origin.to_str().unwrap()]);
    w.git(&repo, &["remote", "set-url", "--add", "--push", "origin", second.to_str().unwrap()]);
    let o = w.ai_env(&repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    w.write(&repo, "a.txt", "clean\n");
    let clean = w.commit(&repo, "clean work");
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(!o.status.success(), "{}", both(&o));
    assert!(both(&o).contains("several push URLs") && both(&o).contains("rule aws-access-key-id"), "{}", both(&o));
    assert_eq!(w.git(&origin, &["rev-parse", "refs/heads/main"]), clean, "the first URL took the clean commit");
    assert!(!w.git_out(&second, &["rev-parse", "--verify", "-q", "refs/heads/main"]).status.success(), "the second URL received nothing");
}

/// A git configuration file in the work tree can move the hook (S9 phase
/// 4, RVH-7): with `.git/config` including a tracked `.gitconfig`, a
/// commit that sets `core.hooksPath` there (and adds a hook that lets
/// everything through) is `pre-push-hook-changed`, and the review says why
/// in a note.
#[test]
fn a_tracked_git_config_the_repository_includes_is_watched() {
    let w = World::new();
    let (repo, _origin, _) = w.pushed("app");
    w.write(&repo, ".gitconfig", "[user]\n\tname = the team\n");
    w.commit(&repo, "the team's git config");
    w.git(&repo, &["push", "-q", "--no-verify", "origin", "main"]);
    w.git(&repo, &["config", "include.path", "../.gitconfig"]);
    let o = w.ai_env(&repo, &["box", "hook-install"], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("or git reads a configuration file there that can move it"), "{}", text(&o.stderr));
    w.git(&repo, &["checkout", "-q", "-b", "agent"]);
    w.write(&repo, ".gitconfig", "[user]\n\tname = the team\n[core]\n\thooksPath = .evil\n");
    w.write(&repo, ".evil/pre-push", "#!/bin/sh\nexit 0\n");
    let c = w.commit(&repo, "faster pushes");
    w.git(&repo, &["checkout", "-q", "main"]);
    let o = w.ai_env(&repo, &["box", "review", "agent", "--json"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let v = json_of(&o);
    assert_eq!(v["findings"], json!([{ "rule": "pre-push-hook-changed", "path": ".gitconfig", "line": null, "commit": c }]), "{v}");
    let out = text(&w.ai_env(&repo, &["box", "review", "agent"], None).stdout);
    assert!(out.contains("note: git reads its configuration from the work tree (.gitconfig): a change there can move the pre-push hook"), "{out}");
}

/// `refs/replace/*` never hides what a push sends (S9 phase 4, RVH-8): a
/// replace ref standing a clean blob over one with a key leaves the key a
/// finding, and the review after the replace ref went still finds it (no
/// clean entry was cached for the blob with the key).
#[test]
fn a_replace_ref_never_hides_a_blob() {
    let w = World::new();
    let (repo, _origin, _) = w.pushed("app");
    w.write(&repo, "deploy.conf", &format!("key: {}\n", key_id()));
    let c = w.commit(&repo, "deploy key");
    let keyed = w.git(&repo, &["rev-parse", "HEAD:deploy.conf"]);
    w.write(&w.root, "clean.conf", "key: none\n");
    let clean = w.git(&repo, &["hash-object", "-w", w.root.join("clean.conf").to_str().unwrap()]);
    w.git(&repo, &["replace", &keyed, &clean]);
    assert_eq!(w.git(&repo, &["cat-file", "-p", &keyed]), "key: none", "git reads the replacement");
    for when in ["under the replace ref", "after it went"] {
        let o = w.ai_env(&repo, &["box", "review", "HEAD"], None);
        assert_eq!(o.status.code(), Some(9), "{when}: {}{}", text(&o.stdout), text(&o.stderr));
        assert!(text(&o.stdout).contains(&format!("  commit {}:deploy.conf (blob {}) line 1: rule aws-access-key-id\n", short(&c), short(&keyed))), "{when}: {}", text(&o.stdout));
        if when == "under the replace ref" {
            w.git(&repo, &["replace", "-d", &keyed]);
        }
    }
}

/// Another pre-push hook that reads its stdin itself (git-lfs's shape)
/// runs the review as `box hook-install` prints it (S9 phase 4, RVH-9):
/// the two lines first, its own reader fed from `$ai_env_refs`. A push
/// carrying a key is still refused, and the other reader still gets git's
/// lines, byte for byte.
#[test]
fn a_hook_sharing_its_stdin_still_reviews_the_push() {
    let w = World::new();
    let (repo, origin, c0) = w.pushed("app");
    let seen = w.root.join("seen.txt");
    let chain = format!("ai_env_refs=$(cat; echo .); ai_env_refs=${{ai_env_refs%.}}\nprintf '%s' \"$ai_env_refs\" | '{}' box review --pre-push \"$1\" \"$2\" || exit 1", ai_env_canonical());
    let hook = repo.join(".git/hooks/pre-push");
    std::fs::write(&hook, format!("#!/bin/sh\n{chain}\nprintf '%s' \"$ai_env_refs\" | cat > '{}'\nexit 0\n", seen.display())).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let o = w.ai_env(&repo, &["box", "hook-install", "--json"], None);
    assert_eq!((o.status.code(), json_of(&o)["outcome"].as_str()), (Some(1), Some("foreign")));
    assert!(text(&o.stderr).contains("which calls box review --pre-push"), "{}", text(&o.stderr));
    w.write(&repo, "a.txt", "clean\n");
    let clean = w.commit(&repo, "clean work");
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(o.status.success(), "{}", both(&o));
    assert_eq!(std::fs::read_to_string(&seen).unwrap(), format!("refs/heads/main {clean} refs/heads/main {c0}\n"), "the hook's own reader got git's lines");
    w.write(&repo, "deploy.conf", &format!("key: {}\n", key_id()));
    w.commit(&repo, "deploy key");
    let o = w.git_out(&repo, &["push", "origin", "main"]);
    assert!(!o.status.success() && both(&o).contains("rule aws-access-key-id"), "{}", both(&o));
    assert_eq!(w.git(&origin, &["rev-parse", "refs/heads/main"]), clean);
}

/// A `Cargo.lock` emptied of its packages drops their pins as a deletion
/// does (S9 phase 4, RVH-10): a lock cut down to its `version` header is
/// `cargo-lock-removed`.
#[test]
fn an_emptied_cargo_lock_is_removed() {
    let w = World::new();
    let repo = w.repo("app");
    let crates = "registry+https://github.com/rust-lang/crates.io-index";
    w.write(&repo, "Cargo.lock", &format!("version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"{crates}\"\nchecksum = \"{}\"\n", "a".repeat(64)));
    w.commit(&repo, "the lock");
    let origin = w.bare("origin.git");
    w.git(&repo, &["remote", "add", "origin", origin.to_str().unwrap()]);
    w.git(&repo, &["push", "-q", "origin", "main"]);
    w.write(&repo, "Cargo.lock", "version = 4\n");
    let c = w.commit(&repo, "relock");
    let o = w.ai_env(&repo, &["box", "review", "HEAD", "--json"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    assert_eq!(json_of(&o)["findings"], json!([{ "rule": "cargo-lock-removed", "path": "Cargo.lock", "line": null, "commit": c }]));
}
