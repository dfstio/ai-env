//! S9 T9.1 (the lead's, offline; plans/s9-contracts.md §11, plans/s9-design-core.md
//! "T9.1, offline"): the VM's git smart-HTTP routes (`shim::gitcgi`: the real
//! helper `shim-io git-cgi` and this Mac's real `git http-backend` behind
//! them) through the routed fake endpoint, from the real Mac. `ai-env box
//! fetch --smart-http` (the Mac's own protocol v2 client, `bridge::gitsmart`)
//! into S8's import, beside plain `box fetch` (`POST /codeout`); a real git
//! client of a test's own (2100 refs, gzip, protocol v2 and v0); the
//! refusals (receive-pack 403 before any helper, every other path 404, a
//! token refused twice exit 7, a VM without `git_http_v1` exit 7 before any
//! request); what each git child saw (the fake git's `FAKE_GIT_ENV_ALL` logs
//! on both sides); then `box review` of a quarantined ref and the pre-push
//! hook in front of a local bare remote.
//!
//! The rig is `tests/common/remote.rs`' (`common::Harness::prepare().rig()`):
//! one in-process shim per test (this user's uid stands for the agent's),
//! the VM's git the fake git (a logging passthrough to this Mac's git), the
//! Mac's git the fake git first on `PATH`. A test that fetches through
//! smart-HTTP gives its fake API's `/health` `git_http_v1` itself: the rig
//! names it only after the cut-over (§8.5). Under M5 (design core) v6's
//! "only in `GIT_CONFIG_VALUE_*`" is "in no git child's argv or environment
//! at all", and "both refspecs" are the `ls-refs` prefixes plus `--no-tags`
//! and explicit refspecs on the second hop. Every wait is bounded.
use super::common::bounded::run_within;
use super::common::fake_endpoint::Action;
use super::common::remote::{RemoteRig, Reply, Req, FIXTURE_DATE};
use super::common::{git_real, install_fake_git, GitCall, Harness};
use ai_env_cli::bridge::api::Call;
use ai_env_cli::bridge::review::PRE_PUSH_MARK;
use ai_env_cli::wire::frame::CAP_GIT_HTTP_V1;
use ai_env_cli::wire::workspace::{CODE_PORT, GIT_CGI_ENV, GIT_RECEIVE_PACK_REFUSAL, GIT_UPLOAD_PACK_REQUEST_TYPE, NO_SUCH_ROUTE};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

/// Every child a test runs itself (a git, an `ai-env` but the many refs' fetch).
const LIMIT: Duration = Duration::from_secs(60);
/// `box fetch` of [`MANY`] branches: S8's import scanned and promoted each
/// ref with git runs of its own (some 90 s alone on this Mac, twice that
/// beside the binary's other tests); S10's batch (F4) scans them as one, and
/// the test prints how long it took.
const MANY_LIMIT: Duration = Duration::from_secs(600);
/// The VM branches of the many-refs tests (the design's 2100): an `ls-refs`
/// answer of about 127 KiB and a request of 2100 wants (some 103 KiB), each past 64 KiB.
const MANY: usize = 2100;
/// `GitRun::vm`'s own environment: every git the VM's helper runs starts with these five.
const VM_ENV: [&str; 5] = ["GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "HOME", "LC_ALL", "PATH"];
/// http-backend's arguments after `gitrun::OVERRIDES` (§3.3).
const CGI_TAIL: [&str; 7] = ["-c", "http.receivepack=false", "-c", "http.getanyfile=false", "-c", "http.uploadpack=true", "http-backend"];
/// The advertisement's request and upload-pack's, as the endpoint records them.
const ADVERTISE: &str = "/workspace.git/info/refs?service=git-upload-pack";
const UPLOAD_PACK: &str = "/workspace.git/git-upload-pack";
/// One protocol v2 `ls-refs` request.
const LS_REFS: &[u8] = b"0014command=ls-refs\n00010000";
/// The agent's name on its commits.
const AGENT: (&str, &str) = ("claude-agent", "claude-agent@ai-env.invalid");

/// One request of a table: its method, its path, its headers past the token and the bearer, its body.
type Case<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)], &'a [u8]);

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A push's stdout and stderr: git hands a hook's stdout to its stderr.
fn both(o: &Output) -> String {
    format!("{}{}", text(&o.stdout), text(&o.stderr))
}

/// What every git a test runs itself starts with: nothing of the
/// developer's (no user or system config, no terminal prompt), `home` its
/// `HOME`, the agent's name and the fixture's date on what it writes.
fn clean_env(cmd: &mut Command, home: &Path) {
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", AGENT.0)
        .env("GIT_AUTHOR_EMAIL", AGENT.1)
        .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
        .env("GIT_COMMITTER_NAME", AGENT.0)
        .env("GIT_COMMITTER_EMAIL", AGENT.1)
        .env("GIT_COMMITTER_DATE", FIXTURE_DATE);
}

/// The real git in `dir` as a test's own tool (no hooks, no automatic
/// maintenance: a background repack would race the next git's loose
/// objects; no signing), `stdin` fed: its output, whatever its exit.
fn git_out(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut all = vec!["-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=false", "-c", "gc.auto=0", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"];
    all.extend_from_slice(args);
    let mut cmd = Command::new(git_real());
    cmd.args(all).current_dir(dir);
    clean_env(&mut cmd, dir);
    run_within(cmd, stdin, LIMIT, "git")
}

/// `git args` in `dir` ([`git_out`]): its stdout, trimmed; a failure panics with its stderr.
fn git(dir: &Path, args: &[&str]) -> String {
    let o = git_out(dir, args, None);
    assert!(o.status.success(), "git {args:?} in {}: {}", dir.display(), text(&o.stderr));
    text(&o.stdout).trim().to_string()
}

fn git_ok(dir: &Path, args: &[&str]) -> bool {
    git_out(dir, args, None).status.success()
}

/// Every ref of `dir`'s repository matching `pattern` (`for-each-ref`'s), to its id.
fn refs_in(dir: &Path, pattern: &str) -> BTreeMap<String, String> {
    git(dir, &["for-each-ref", "--format=%(refname) %(objectname)", pattern]).lines().filter_map(|l| l.split_once(' ')).map(|(name, id)| (name.to_string(), id.to_string())).collect()
}

/// The refs under `refs/remotes/` of the Mac's workspace: the box refs and their quarantine.
fn remote_refs(work: &Path) -> BTreeMap<String, String> {
    refs_in(work, "refs/remotes/")
}

/// The agent's commit in the VM's checkout `vm`: `file` written with
/// `body`, staged alone and committed as `msg` on what is checked out.
fn agent_commit(vm: &Path, file: &str, body: &str, msg: &str) -> String {
    std::fs::write(vm.join(file), body).unwrap_or_else(|e| panic!("write {file} in the VM: {e}"));
    git(vm, &["add", "--", file]);
    git(vm, &["commit", "-q", "-m", msg]);
    git(vm, &["rev-parse", "HEAD"])
}

/// `n` branches `b0000`… in the VM's checkout `vm`, each at a commit of
/// its own on HEAD (a file of its own), written by one `git fast-import`:
/// each branch's full name to its commit.
fn many_branches(vm: &Path, n: usize) -> BTreeMap<String, String> {
    let head = git(vm, &["rev-parse", "HEAD"]);
    let mut stream = String::new();
    for i in 0..n {
        let (name, body) = (format!("b{i:04}"), format!("branch {i}\n"));
        stream.push_str(&format!(
            "commit refs/heads/{name}\ncommitter {} <{}> 1791792000 +0000\ndata {}\n{name}\nfrom {head}\nM 100644 inline {name}.txt\ndata {}\n{body}\n",
            AGENT.0,
            AGENT.1,
            name.len() + 1,
            body.len()
        ));
    }
    stream.push_str("done\n");
    let o = git_out(vm, &["fast-import", "--quiet", "--done"], Some(stream.as_bytes()));
    assert!(o.status.success(), "fast-import: {}", text(&o.stderr));
    let made = refs_in(vm, "refs/heads/b*");
    assert_eq!(made.len(), n, "the VM's branches");
    made
}

/// The Mac's side a fetch leaves alone: HEAD, the branches and tags, the
/// index and the worktree, the stash (read without optional locks).
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

/// `ai-env box seed <work> --json` on the rig, which must exit 0: its JSON.
fn box_seed(rig: &RemoteRig) -> Value {
    let o = rig.run(&["box", "seed", &rig.work().display().to_string(), "--json"], None);
    assert!(o.status.success(), "box seed: {}", text(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("box seed --json ({e}): {}", text(&o.stdout)))
}

/// The workspace's VM of an S9 image (its `/health` names `git_http_v1`,
/// which the rig's fake API names only after the cut-over), started and
/// seeded: its id.
fn s9_vm(rig: &RemoteRig) -> String {
    rig.update_fake(|s| {
        if !s.health_caps.iter().any(|c| c == CAP_GIT_HTTP_V1) {
            s.health_caps.push(CAP_GIT_HTTP_V1.to_string());
        }
    });
    let vm = rig.start_vm();
    box_seed(rig);
    vm
}

/// `ai-env box fetch <work> args…` on the rig: its output, whatever its exit.
fn box_fetch(rig: &RemoteRig, args: &[&str]) -> Output {
    let work = rig.work().display().to_string();
    let mut all = vec!["box", "fetch", work.as_str()];
    all.extend_from_slice(args);
    rig.run(&all, None)
}

/// A `box fetch --json` that exited 0: its document.
fn report_of(o: &Output) -> Value {
    assert_eq!(o.status.code(), Some(0), "box fetch: {}", text(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("box fetch --json ({e}): {}", text(&o.stdout)))
}

/// A `box fetch --json` report's promoted refs, to their commits.
fn promoted(v: &Value) -> BTreeMap<String, String> {
    let refs = v["report"]["promoted"].as_object().unwrap_or_else(|| panic!("no promoted refs in {v}"));
    refs.iter().map(|(name, id)| (name.clone(), id.as_str().unwrap_or_default().to_string())).collect()
}

/// The code port's requests to the git routes the endpoint saw, with the status each got.
fn git_requests(rig: &RemoteRig) -> Vec<(String, u16)> {
    rig.endpoint.attempts().iter().filter(|a| a.port == CODE_PORT && a.path.starts_with("/workspace.git")).map(|a| (a.path.clone(), a.status)).collect()
}

/// `(path, status)` pairs as [`git_requests`] lists them.
fn seen(pairs: &[(&str, u16)]) -> Vec<(String, u16)> {
    pairs.iter().map(|(path, status)| ((*path).to_string(), *status)).collect()
}

/// How many 9418 tokens the fake API minted so far.
fn code_mints(rig: &RemoteRig) -> usize {
    rig.fake_calls().iter().filter(|c| matches!(c, Call::Token { port: CODE_PORT, .. })).count()
}

/// The VM's http-backend runs among `calls` (each `git-cgi` helper's one).
fn backend(calls: &[GitCall]) -> Vec<&GitCall> {
    calls.iter().filter(|c| c.args.last().map(String::as_str) == Some("http-backend")).collect()
}

/// Whether `call` started with the variable `name` set (a `FAKE_GIT_ENV_ALL` log).
fn has_env(call: &GitCall, name: &str) -> bool {
    call.env.iter().any(|n| n == name)
}

/// An http-backend run started with exactly what §3.3 gives it: `GitRun::vm`'s
/// five names and the `GIT_CGI_ENV` names its request sets (a `POST` its
/// `CONTENT_TYPE` and `CONTENT_LENGTH`, a `GET` neither;
/// `HTTP_CONTENT_ENCODING` and `HTTP_GIT_PROTOCOL` when the request named
/// them), behind the CGI's overrides; as the agent (the shim's uid here).
fn assert_cgi_run(call: &GitCall) {
    let mut want: Vec<&str> = VM_ENV.to_vec();
    want.extend(["GIT_PROJECT_ROOT", "GIT_HTTP_EXPORT_ALL", "PATH_INFO", "REQUEST_METHOD", "QUERY_STRING", "REMOTE_ADDR"]);
    if has_env(call, "CONTENT_LENGTH") {
        want.extend(["CONTENT_TYPE", "CONTENT_LENGTH"]);
    }
    want.extend(["HTTP_CONTENT_ENCODING", "HTTP_GIT_PROTOCOL"].into_iter().filter(|n| has_env(call, n)));
    assert!(want.iter().all(|n| VM_ENV.contains(n) || GIT_CGI_ENV.contains(n)), "{want:?}");
    want.sort_unstable();
    assert_eq!(call.env, want, "http-backend's environment: {:?}", call.args);
    assert_eq!(call.args[call.args.len() - CGI_TAIL.len()..], CGI_TAIL, "{:?}", call.args);
    // SAFETY: getuid cannot fail.
    assert_eq!(call.uid, Some(unsafe { libc::getuid() }), "as the agent");
}

/// The `codeout_fetch` audit rows of the rig's bridge dir: (via, outcome).
fn fetch_rows(rig: &RemoteRig) -> Vec<(String, String)> {
    let audit = std::fs::read_to_string(rig.bridge().join("audit.jsonl")).unwrap_or_default();
    let rows = audit.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|r| r["event"] == "codeout_fetch");
    rows.map(|r| (r["detail"]["via"].as_str().unwrap_or("-").to_string(), r["detail"]["outcome"].as_str().unwrap_or("-").to_string())).collect()
}

fn row(via: &str, outcome: &str) -> (String, String) {
    (via.to_string(), outcome.to_string())
}

/// The VM's session token, from its row (`vm run` wrote it there).
fn session_token(rig: &RemoteRig, vm: &str) -> String {
    let file = rig.bridge().join("state").join("vms").join(format!("{vm}.toml"));
    let row: toml::Value = toml::from_str(&std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()))).expect("the VM's row");
    row.get("session_token").and_then(toml::Value::as_str).expect("the row's session token").to_string()
}

/// One request to `vm`'s code port through the endpoint, with a 9418
/// token minted for it and the session bearer.
fn code_request(rig: &RemoteRig, vm: &str, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
    let (token, bearer) = (rig.mint(vm, CODE_PORT), format!("Bearer {}", session_token(rig, vm)));
    let mut all = vec![("Authorization", bearer.as_str())];
    all.extend_from_slice(headers);
    rig.send(vm, &Req { method, path, port: CODE_PORT, token: &token, headers: &all, body })
}

/// The git routes' URL at the endpoint, as a git client names it.
fn url(rig: &RemoteRig) -> String {
    format!("http://{}/workspace.git", rig.endpoint.addr)
}

/// The real git as a client of `vm`'s git routes through the endpoint, in
/// `dir`: the VM's endpoint host, a 9418 token and the session bearer as
/// `http.extraHeader`s (a test's own client, the one place a git is handed
/// them: the code under test never does), `env` beside: its output.
fn client_git(rig: &RemoteRig, vm: &str, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let host = rig.fake().vms.get(vm).unwrap_or_else(|| panic!("no VM {vm} in the fake")).endpoint.clone();
    let headers = [format!("Host: {host}"), format!("x-aws-proxy-auth: {}", rig.mint(vm, CODE_PORT)), format!("x-aws-proxy-port: {CODE_PORT}"), format!("Authorization: Bearer {}", session_token(rig, vm))];
    let mut cmd = Command::new(git_real());
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=false", "-c", "gc.auto=0"]);
    for h in &headers {
        cmd.arg("-c").arg(format!("http.extraHeader={h}"));
    }
    cmd.args(args).current_dir(dir);
    clean_env(&mut cmd, dir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    run_within(cmd, None, LIMIT, "a git client through the endpoint")
}

/// `ai-env args` of the rig with this Mac's git first on its `PATH` (a
/// link to it in `<tmp>/bin-real`; the fake age still behind it): the fake
/// git takes 20 ms a run to log it, and S8's import ran git a few times for
/// each ref it promoted (S10's batch runs it a few times in all).
fn ai_env_real_git(rig: &RemoteRig, args: &[&str]) -> Command {
    let dir = rig.root().join("bin-real");
    if !dir.join("git").exists() {
        std::fs::create_dir_all(&dir).expect("mkdir bin-real");
        std::os::unix::fs::symlink(git_real(), dir.join("git")).expect("link this Mac's git");
    }
    let mut cmd = rig.ai_env(args);
    cmd.env("PATH", format!("{}:{}:/usr/bin:/bin", dir.display(), rig.root().join("bin").display()));
    cmd
}

/// An AWS key id's shape, built at run time (never a literal).
fn key_id() -> String {
    format!("{}{}", "AKIA", "Z3".repeat(8))
}

/// The agent commits a key (`deploy.conf`, its line 2) on `main` in the
/// VM, and `box fetch --smart-http` quarantines it: exit 9, the ref under
/// `refs/remotes/box-quarantine/`, nothing under `box/`, the key in no
/// output. Gives the VM, the commit, its `deploy.conf` blob and the key.
fn quarantined(rig: &RemoteRig) -> (String, String, String, String) {
    let work = rig.work();
    let vm = s9_vm(rig);
    let key = key_id();
    let commit = agent_commit(&rig.vm_path(&work), "deploy.conf", &format!("region: eu-central-1\nkey: {key}\n"), "configure the deploy");
    let o = box_fetch(rig, &["--smart-http"]);
    let said = both(&o);
    assert_eq!(o.status.code(), Some(9), "{}", said.replace(&key, "<KEY>"));
    assert_eq!(text(&o.stdout), format!("refs/remotes/box-quarantine/main -> {} (quarantined)\n", &commit[..12]));
    assert!(said.contains(&format!("1 ref(s) from {vm} hold a finding and went to refs/remotes/box-quarantine/*")) && !said.contains(&key), "{}", said.replace(&key, "<KEY>"));
    assert_eq!(remote_refs(&work), BTreeMap::from([("refs/remotes/box-quarantine/main".to_string(), commit.clone())]));
    let blob = git(&work, &["rev-parse", &format!("{commit}:deploy.conf")]);
    (vm, commit, blob, key)
}

/// The finding line `box review` prints for [`quarantined`]'s key.
fn finding_line(commit: &str, blob: &str) -> String {
    format!("commit {}:deploy.conf (blob {}) line 2: rule aws-access-key-id", &commit[..12], &blob[..12])
}

/// `ai-env box fetch --smart-http` end to end: the Mac's own protocol v2
/// client through the routed endpoint to the VM's git routes, the real
/// helper and this Mac's real `git http-backend` behind them. After a
/// seed, the agent's commit on `main` and on its branch `feature` come
/// back as `refs/remotes/box/main` and `box/feature` through exactly the
/// advertisement, `ls-refs` and one `fetch` (three http-backend runs behind
/// the CGI's overrides), never `POST /codeout`; the Mac's branch, index and
/// worktree untouched; the audit's `via` `smart-http`. Asked again with
/// nothing moved: nothing new, after the advertisement and `ls-refs` alone.
#[test]
fn t9_1_box_fetch_smart_http_promotes_the_vms_refs() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    let vm = s9_vm(rig);
    let vm_dir = rig.vm_path(&work);
    let main = agent_commit(&vm_dir, "agent.txt", "from the VM\n", "the agent's commit");
    git(&vm_dir, &["checkout", "-q", "-b", "feature"]);
    let feature = agent_commit(&vm_dir, "feature.txt", "a feature\n", "the agent's feature");
    git(&vm_dir, &["checkout", "-q", "main"]);
    let mac = mac_view(&work);
    let (requests, calls) = (git_requests(rig).len(), rig.vm_git_calls().len());
    let o = box_fetch(rig, &["--smart-http"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout), format!("refs/remotes/box/feature -> {}\nrefs/remotes/box/main -> {}\n", &feature[..12], &main[..12]));
    let want = BTreeMap::from([("refs/remotes/box/feature".to_string(), feature.clone()), ("refs/remotes/box/main".to_string(), main.clone())]);
    assert_eq!(remote_refs(&work), want);
    assert_eq!(git(&work, &["show", "refs/remotes/box/main:agent.txt"]), "from the VM");
    assert_eq!(mac_view(&work), mac, "the Mac's branch, index and worktree untouched");
    assert_eq!(git_requests(rig)[requests..], seen(&[(ADVERTISE, 200), (UPLOAD_PACK, 200), (UPLOAD_PACK, 200)]), "the advertisement, ls-refs, fetch");
    assert!(!rig.endpoint.attempts().iter().any(|a| a.path.starts_with("/codeout")), "never POST /codeout");
    let vm_calls = rig.vm_git_calls();
    let ran = backend(&vm_calls[calls..]);
    assert_eq!(ran.len(), 3, "an http-backend run per request: {:?}", &vm_calls[calls..]);
    assert!(ran.iter().all(|c| c.args[c.args.len() - CGI_TAIL.len()..] == CGI_TAIL), "{ran:?}");
    assert_eq!(fetch_rows(rig), [row("smart-http", "promoted")]);
    // Nothing moved since: every tip is had, so no fetch goes out.
    let requests = git_requests(rig).len();
    let o = box_fetch(rig, &["--smart-http"]);
    assert_eq!((o.status.code(), text(&o.stdout)), (Some(0), format!("nothing new from {vm}\n")), "{}", text(&o.stderr));
    assert_eq!(git_requests(rig)[requests..], seen(&[(ADVERTISE, 200), (UPLOAD_PACK, 200)]), "the advertisement and ls-refs alone");
    assert_eq!(remote_refs(&work), want);
    assert_eq!(fetch_rows(rig), [row("smart-http", "promoted"), row("smart-http", "nothing_new")]);
}

/// Both ways out of the VM promote the same tips: `box fetch --smart-http`
/// and plain `box fetch` (`POST /codeout`, no snapshot) of one VM state,
/// the box refs deleted between them, bring the same refs at the same
/// commits: the branches (one nested), the agent's snapshot ref, the
/// seeded WIP (`refs/ai-env/seed-wip`, the Mac's uncommitted edit) and a
/// detached HEAD (`box/HEAD`). Neither brings a tag, a snapshot ref naming
/// a tree, nor one naming an annotated tag (whose object never crosses).
#[test]
fn t9_1_both_modes_promote_the_same_tips() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    std::fs::write(work.join("README.md"), "fixture, edited on the Mac\n").expect("edit README.md");
    s9_vm(rig);
    let vm_dir = rig.vm_path(&work);
    let seed_wip = git(&vm_dir, &["rev-parse", "refs/ai-env/seed-wip"]);
    let main = agent_commit(&vm_dir, "a.txt", "on main\n", "the agent's main");
    git(&vm_dir, &["checkout", "-q", "-b", "feature"]);
    let feature = agent_commit(&vm_dir, "b.txt", "a feature\n", "the agent's feature");
    git(&vm_dir, &["checkout", "-q", "-b", "topic/x", &main]);
    let topic = agent_commit(&vm_dir, "c.txt", "a topic\n", "the agent's topic");
    let snapshot = git(&vm_dir, &["commit-tree", &format!("{topic}^{{tree}}"), "-p", &topic, "-m", "the agent's snapshot"]);
    git(&vm_dir, &["update-ref", "refs/wip/20261018T090000Z-1", &snapshot]);
    git(&vm_dir, &["update-ref", "refs/wip/20261018T090000Z-2", &format!("{main}^{{tree}}")]);
    git(&vm_dir, &["tag", "-a", "v1", "-m", "a release", &main]);
    let tag = git(&vm_dir, &["rev-parse", "refs/tags/v1"]);
    git(&vm_dir, &["update-ref", "refs/wip/20261018T090000Z-3", &tag]);
    git(&vm_dir, &["checkout", "-q", "--detach", &main]);
    let detached = agent_commit(&vm_dir, "d.txt", "detached\n", "the agent's detached commit");
    let want: BTreeMap<String, String> = [("main", &main), ("feature", &feature), ("topic/x", &topic), ("wip/20261018T090000Z-1", &snapshot), ("seed-wip", &seed_wip), ("HEAD", &detached)]
        .into_iter()
        .map(|(name, id)| (format!("refs/remotes/box/{name}"), id.clone()))
        .collect();
    let smart = report_of(&box_fetch(rig, &["--smart-http", "--json"]));
    assert_eq!((smart["via"].as_str(), promoted(&smart)), (Some("smart-http"), want.clone()));
    assert_eq!(remote_refs(&work), want);
    let delete: String = want.keys().map(|name| format!("delete {name}\n")).collect();
    let o = git_out(&work, &["update-ref", "--stdin"], Some(delete.as_bytes()));
    assert!(o.status.success() && remote_refs(&work).is_empty(), "{}", text(&o.stderr));
    let codeout = report_of(&box_fetch(rig, &["--json"]));
    assert_eq!((codeout["via"].as_str(), promoted(&codeout)), (Some("codeout"), want.clone()));
    assert_eq!(remote_refs(&work), want);
    assert_eq!(fetch_rows(rig), [row("smart-http", "promoted"), row("codeout", "promoted")]);
    assert_eq!(git(&work, &["for-each-ref", "refs/tags/"]), "", "no tag on the Mac");
    assert!(!git_ok(&work, &["cat-file", "-e", &tag]), "the annotated tag's object never crossed");
}

/// A VM tag never reaches the Mac: the agent tags its commit on `main`
/// (annotated) and two commits no branch holds (one tag lightweight, one
/// annotated). `box fetch --smart-http` promotes `box/main` alone: the pack
/// that crossed (kept by the Mac's fake git, `FAKE_GIT_KEEP_PACK`) holds
/// `main`'s commit and no tag object (never `include-tag`) nor a commit only
/// a tag reaches; the Mac holds no tag ref, no tag object, and neither of
/// those commits. Its first hop's `ls-refs` asked exactly the four prefixes
/// (`HEAD`, `refs/heads/`, `refs/wip/`, `refs/ai-env/seed-wip`) and its
/// `fetch` no `include-tag`, depth or filter (upload-pack's packet trace,
/// `GIT_TRACE_PACKET` from the VM's fake git's knobs). Its second hop is
/// S8's: one `git fetch --no-tags` from the scratch, one explicit refspec
/// per box ref, no pattern, nothing of `refs/tags`.
#[test]
fn t9_1_a_vm_tag_never_reaches_the_mac() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    s9_vm(rig);
    let vm_dir = rig.vm_path(&work);
    let main = agent_commit(&vm_dir, "agent.txt", "from the VM\n", "the agent's commit");
    git(&vm_dir, &["tag", "-a", "release", "-m", "a release", &main]);
    git(&vm_dir, &["checkout", "-q", "-b", "scratch"]);
    let tagged = agent_commit(&vm_dir, "leak.txt", "only a tag holds this\n", "tagged only");
    git(&vm_dir, &["tag", "leak-tag"]);
    let annotated = agent_commit(&vm_dir, "leak2.txt", "only an annotated tag holds this\n", "tagged only, annotated");
    git(&vm_dir, &["tag", "-a", "leak-annotated", "-m", "a leak"]);
    git(&vm_dir, &["checkout", "-q", "main"]);
    git(&vm_dir, &["branch", "-q", "-D", "scratch"]);
    let tags = refs_in(&vm_dir, "refs/tags/");
    assert_eq!(tags.len(), 3, "{tags:?}");
    let never: Vec<&String> = tags.values().chain([&tagged, &annotated]).collect();
    let kept = rig.root().join("kept");
    let kept_knob = kept.display().to_string();
    install_fake_git(&rig.root().join("bin").join("git"), &rig.root().join("git-mac.log"), &[("FAKE_GIT_KEEP_PACK", &kept_knob)]);
    // What the VM's upload-pack read (sourced after the fake logs its names, so it never shows in them).
    let packets = rig.root().join("vm-packets.log");
    let packets_knob = packets.display().to_string();
    rig.set_vm_git_knobs(&[("GIT_TRACE_PACKET", &packets_knob)]);
    let calls = rig.mac_git_calls().len();
    let v = report_of(&box_fetch(rig, &["--smart-http", "--json"]));
    assert_eq!(promoted(&v), BTreeMap::from([("refs/remotes/box/main".to_string(), main.clone())]));
    assert_eq!(remote_refs(&work).len(), 1);
    let trace = std::fs::read_to_string(&packets).expect("the VM's packet trace");
    let read: Vec<&str> = trace.lines().filter_map(|l| l.split_once("upload-pack< ").map(|(_, p)| p)).collect();
    let prefixes: Vec<&str> = read.iter().filter_map(|p| p.strip_prefix("ref-prefix ")).collect();
    assert_eq!(prefixes, ["HEAD", "refs/heads/", "refs/wip/", "refs/ai-env/seed-wip"], "ls-refs asked: {read:?}");
    assert!(read.contains(&"command=fetch") && read.contains(&"done"), "{read:?}");
    assert!(!read.iter().any(|p| ["include-tag", "deepen", "filter", "want-ref", "shallow"].iter().any(|n| p.starts_with(n))), "the fetch asked: {read:?}");
    // What crossed: each pack the Mac's index-pack was given, indexed again in a repository of its own
    // (its thin bases from the Mac's store), then listed whole.
    let packs: Vec<PathBuf> = std::fs::read_dir(&kept).expect("the kept packs").filter_map(Result::ok).map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("index-pack-"))).collect();
    assert!(!packs.is_empty(), "the fetched pack was kept");
    for (i, pack) in packs.iter().enumerate() {
        let crossed = rig.root().join(format!("crossed-{i}.git"));
        git(rig.root(), &["init", "-q", "--bare", &crossed.display().to_string()]);
        std::fs::write(crossed.join("objects").join("info").join("alternates"), format!("{}\n", work.join(".git").join("objects").display())).expect("write the alternates");
        let o = git_out(&crossed, &["index-pack", "--stdin", "--fix-thin"], Some(&std::fs::read(pack).expect("the kept pack")));
        assert!(o.status.success(), "index-pack of {}: {}", pack.display(), text(&o.stderr));
        let idx = std::fs::read_dir(crossed.join("objects").join("pack")).expect("the pack dir").filter_map(Result::ok).map(|e| e.path()).find(|p| p.extension().is_some_and(|x| x == "idx")).expect("the index");
        let listed = git(&crossed, &["verify-pack", "-v", &idx.display().to_string()]);
        let objects: Vec<(&str, &str)> = listed.lines().filter_map(|l| l.split_once(' ')).map(|(id, rest)| (id, rest.split(' ').next().unwrap_or_default())).filter(|(id, _)| id.len() == main.len() && id.bytes().all(|b| b.is_ascii_hexdigit())).collect();
        assert!(objects.iter().any(|(id, kind)| *id == main && *kind == "commit"), "{}: main's commit crossed: {objects:?}", pack.display());
        assert!(!objects.iter().any(|(id, kind)| *kind == "tag" || never.iter().any(|n| n.as_str() == *id)), "{}: a tag crossed: {objects:?}", pack.display());
    }
    assert_eq!(git(&work, &["for-each-ref", "refs/tags/"]), "", "no tag ref on the Mac");
    for id in &never {
        assert!(!git_ok(&work, &["cat-file", "-e", id]), "{id} (a tag, or a commit only a tag holds) never reached the Mac");
    }
    let mac_calls = rig.mac_git_calls();
    let fetches: Vec<&GitCall> = mac_calls[calls..].iter().filter(|c| c.sub() == Some("fetch")).collect();
    assert_eq!(fetches.len(), 1, "the second hop: {:?}", &mac_calls[calls..]);
    let args = &fetches[0].args;
    assert!(fetches[0].has("--no-tags"), "{args:?}");
    let specs: Vec<&String> = args.iter().filter(|a| a.starts_with('+')).collect();
    assert!(specs.len() == 1 && specs[0].starts_with("+refs/box/main:refs/ai-env/incoming/") && specs[0].ends_with("/main"), "{args:?}");
    assert!(!args.iter().any(|a| a.contains('*') || a.contains("refs/tags")), "{args:?}");
}

/// A VM branch names no ref outside the box namespace: `box/foo` lands as
/// `refs/remotes/box/box/foo`, never as `box/foo`, which the VM's own `foo`
/// takes; `box-quarantine/foo` as `refs/remotes/box/box-quarantine/foo`,
/// never in the quarantine. What the Mac gained is exactly those refs and
/// `box/main`.
#[test]
fn t9_1_box_foo_lands_as_box_box_foo() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    s9_vm(rig);
    let vm_dir = rig.vm_path(&work);
    let main = agent_commit(&vm_dir, "agent.txt", "from the VM\n", "the agent's commit");
    let mut want = BTreeMap::from([("refs/remotes/box/main".to_string(), main.clone())]);
    for (branch, file) in [("box/foo", "box-foo.txt"), ("foo", "foo.txt"), ("box-quarantine/foo", "box-quarantine-foo.txt")] {
        git(&vm_dir, &["checkout", "-q", "-b", branch, &main]);
        want.insert(format!("refs/remotes/box/{branch}"), agent_commit(&vm_dir, file, &format!("on {branch}\n"), branch));
    }
    git(&vm_dir, &["checkout", "-q", "main"]);
    let before = refs_in(&work, "refs/");
    let v = report_of(&box_fetch(rig, &["--smart-http", "--json"]));
    assert_eq!(promoted(&v), want);
    let gained: BTreeMap<String, String> = refs_in(&work, "refs/").into_iter().filter(|(name, _)| !before.contains_key(name)).collect();
    assert_eq!(gained, want, "every ref the Mac gained");
    assert_ne!(git(&work, &["rev-parse", "refs/remotes/box/box/foo"]), git(&work, &["rev-parse", "refs/remotes/box/foo"]));
}

/// Receive-pack never runs: every form of a push is 403 with the refusal's
/// text before any helper starts (the VM's fake git logs no run, the shim
/// holds no helper): the `POST` of a ref update and its pack, the `GET` of
/// its advertisement, its route by `GET` and `PUT`, and a real `git push`
/// through the endpoint, which fails on its first 403. The VM's refs stay
/// as they were. The same token and bearer then read upload-pack's
/// advertisement (200, an http-backend run): the 403s are receive-pack's own.
#[test]
fn t9_1_push_is_403_and_starts_no_helper() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    let vm = s9_vm(rig);
    let vm_dir = rig.vm_path(&work);
    let vm_refs = refs_in(&vm_dir, "refs/");
    let (calls, before) = (rig.vm_git_calls().len(), rig.endpoint.attempts().len());
    let update = format!("{} {} refs/heads/pushed\0 report-status\n", "0".repeat(40), rig.head());
    let mut body = format!("{:04x}{update}0000", update.len() + 4).into_bytes();
    body.extend_from_slice(b"PACK\0\0\0\x02\0\0\0\0");
    let kind = [("Content-Type", "application/x-git-receive-pack-request")];
    let cases: [Case<'_>; 4] = [
        ("POST", "/workspace.git/git-receive-pack", &kind, &body),
        ("GET", "/workspace.git/info/refs?service=git-receive-pack", &[], &[]),
        ("GET", "/workspace.git/git-receive-pack", &[], &[]),
        ("PUT", "/workspace.git/git-receive-pack", &kind, &body),
    ];
    for (method, path, headers, body) in cases {
        let r = code_request(rig, &vm, method, path, headers, body);
        assert_eq!((r.status, r.text()), (403, GIT_RECEIVE_PACK_REFUSAL.to_string()), "{method} {path}");
    }
    let o = client_git(rig, &vm, &work, &["push", &url(rig), "HEAD:refs/heads/pushed"], &[]);
    assert!(!o.status.success() && text(&o.stderr).contains("403"), "the push: {}", text(&o.stderr));
    let refused: Vec<(String, u16)> = rig.endpoint.attempts()[before..].iter().map(|a| (a.path.clone(), a.status)).collect();
    let (route, advert) = ("/workspace.git/git-receive-pack", "/workspace.git/info/refs?service=git-receive-pack");
    assert_eq!(refused[..cases.len()], seen(&[(route, 403), (advert, 403), (route, 403), (route, 403)]));
    assert!(refused.len() > cases.len() && refused[cases.len()..].iter().all(|(path, status)| path == advert && *status == 403), "the push's own requests: {refused:?}");
    assert_eq!(rig.vm_git_calls().len(), calls, "no helper started: no git ran in the VM");
    assert_eq!(rig.shim.spawns.helpers(), 0, "no helper running");
    assert_eq!(refs_in(&vm_dir, "refs/"), vm_refs, "the VM's refs as they were");
    let r = code_request(rig, &vm, "GET", ADVERTISE, &[("Git-Protocol", "version=2")], &[]);
    assert!(r.status == 200 && r.body.starts_with(b"000eversion 2\n"), "{} {}", r.status, r.text());
    assert_eq!(backend(&rig.vm_git_calls()[calls..]).len(), 1, "upload-pack's advertisement ran http-backend");
}

/// Only the two literal routes reach a helper: through the endpoint, with
/// a valid token and the bearer, a trailing `/`, `//`, a `..` or
/// percent-encoded segment, a dumb path (`HEAD`, `objects/…`, `config`),
/// another repository, the advertisement without its exact query, and
/// upload-pack with any query are each 404 `NO_SUCH_ROUTE` (`text/plain`),
/// and no git runs in the VM. A real dumb client (`GIT_SMART_HTTP=0`) fails
/// on its `info/refs` 404. With the same headers the literal routes answer.
#[test]
fn t9_1_traversal_and_dumb_paths_are_404() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let vm = s9_vm(rig);
    let loose = format!("/workspace.git/objects/{}/{}", &rig.head()[..2], &rig.head()[2..]);
    let gets = [
        "/workspace.git/info/refs/?service=git-upload-pack",
        "/workspace.git//info/refs?service=git-upload-pack",
        "//workspace.git/info/refs?service=git-upload-pack",
        "/workspace.git/../workspace.git/info/refs?service=git-upload-pack",
        "/workspace.git/%2e%2e/workspace.git/info/refs?service=git-upload-pack",
        "/workspace.git/info/%72efs?service=git-upload-pack",
        "/workspace.git/info/refs/../../HEAD",
        "/workspace.git/HEAD",
        "/workspace.git/config",
        "/workspace.git/objects/info/packs",
        "/workspace.git/objects/info/alternates",
        loose.as_str(),
        "/workspace.git/info/refs",
        "/workspace.git/info/refs?service=git-upload-pack&x=1",
        "/workspace.git/info/refs?service=git-upload-pac%6b",
        "/workspace.git/info/refs?service=git-upload-archive",
        "/other.git/info/refs?service=git-upload-pack",
        "/Workspace.git/info/refs?service=git-upload-pack",
        "/.git/info/refs?service=git-upload-pack",
    ];
    let posts = [
        "/workspace.git/git-upload-pack?",
        "/workspace.git/git-upload-pack?service=git-upload-pack",
        "/workspace.git/git-upload-pack/",
        "/workspace.git//git-upload-pack",
        "/workspace.git/%67it-upload-pack",
        "/workspace.git/../workspace.git/git-upload-pack",
        "/other.git/git-upload-pack",
        "/workspace.git/git-upload-archive",
    ];
    let (calls, before) = (rig.vm_git_calls().len(), rig.endpoint.attempts().len());
    let v2 = ("Git-Protocol", "version=2");
    let post_headers = [("Content-Type", GIT_UPLOAD_PACK_REQUEST_TYPE), v2];
    let not_found = |r: &Reply, method: &str, path: &str| {
        assert_eq!((r.status, r.text()), (404, NO_SUCH_ROUTE.to_string()), "{method} {path}");
        assert!(r.header("content-type").is_some_and(|t| t.starts_with("text/plain")), "{method} {path}: {:?}", r.headers);
    };
    for path in gets {
        not_found(&code_request(rig, &vm, "GET", path, &[v2], &[]), "GET", path);
    }
    for path in posts {
        not_found(&code_request(rig, &vm, "POST", path, &post_headers, LS_REFS), "POST", path);
    }
    let attempts = rig.endpoint.attempts();
    assert_eq!(attempts.len() - before, gets.len() + posts.len());
    assert!(attempts[before..].iter().all(|a| a.status == 404 && a.port == CODE_PORT), "each reached the shim and got its 404");
    let o = client_git(rig, &vm, rig.root(), &["ls-remote", &url(rig)], &[("GIT_SMART_HTTP", "0")]);
    assert!(!o.status.success(), "a dumb client: {}", text(&o.stdout));
    let last = rig.endpoint.attempts().last().map(|a| (a.path.clone(), a.status));
    assert_eq!(last, Some(("/workspace.git/info/refs".to_string(), 404)), "{}", text(&o.stderr));
    assert_eq!(rig.vm_git_calls().len(), calls, "no helper started: no git ran in the VM");
    let r = code_request(rig, &vm, "GET", ADVERTISE, &[v2], &[]);
    assert!(r.status == 200 && r.body.starts_with(b"000eversion 2\n"), "{} {}", r.status, r.text());
    let r = code_request(rig, &vm, "POST", UPLOAD_PACK, &post_headers, LS_REFS);
    assert!(r.status == 200 && r.text().contains(&format!("{} refs/heads/main", rig.head())), "{} {}", r.status, r.text());
    assert_eq!(backend(&rig.vm_git_calls()[calls..]).len(), 2, "the literal routes ran http-backend");
}

/// A real git client (this Mac's, the endpoint's headers and the bearer as
/// `http.extraHeader`s, as a test's own tool) fetches every branch of a VM
/// with 2100 through the endpoint, over protocol v2 and over v0: each gets
/// the VM's 2101 branches at their commits (`--update-shallow`: the VM's
/// copy is shallow at the seeded commit). Its requests of 2100 wants pass
/// 1 KiB, so git deflates them: each protocol's fetch has an http-backend
/// run started with `HTTP_CONTENT_ENCODING` (with `HTTP_GIT_PROTOCOL` in
/// v2, which every v2 run has and no v0 run), and every run started with
/// exactly `GitRun::vm`'s names and its request's CGI names, as the agent.
#[test]
fn t9_1_a_real_git_client_with_2100_refs_fetches_with_gzip_over_v2_and_v0() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    rig.set_vm_git_knobs(&[("FAKE_GIT_ENV_ALL", "1")]);
    let vm = s9_vm(rig);
    let vm_dir = rig.vm_path(&rig.work());
    let mut branches = many_branches(&vm_dir, MANY);
    branches.insert("refs/heads/main".to_string(), rig.head().to_string());
    for (version, v2) in [("2", true), ("0", false)] {
        let dest = rig.root().join(format!("client-v{version}.git"));
        git(rig.root(), &["init", "-q", "--bare", &dest.display().to_string()]);
        let calls = rig.vm_git_calls().len();
        let protocol = format!("protocol.version={version}");
        let o = client_git(rig, &vm, &dest, &["-c", &protocol, "fetch", "-q", "--update-shallow", &url(rig), "+refs/heads/*:refs/heads/*"], &[]);
        assert!(o.status.success(), "v{version}: {}", text(&o.stderr));
        let fetched = refs_in(&dest, "refs/heads/");
        assert!(fetched == branches, "v{version}: {} branches fetched of {}", fetched.len(), branches.len());
        let vm_calls = rig.vm_git_calls();
        let ran = backend(&vm_calls[calls..]);
        assert!(ran.len() >= 2, "v{version}: {ran:?}");
        for call in &ran {
            assert_cgi_run(call);
            assert_eq!(has_env(call, "HTTP_GIT_PROTOCOL"), v2, "v{version}: {:?}", call.env);
        }
        assert!(ran.iter().any(|c| !has_env(c, "CONTENT_LENGTH")), "v{version}: the advertisement");
        assert!(ran.iter().any(|c| has_env(c, "CONTENT_LENGTH") && has_env(c, "HTTP_CONTENT_ENCODING")), "v{version}: a gzipped request: {:?}", ran.iter().map(|c| &c.env).collect::<Vec<_>>());
    }
}

/// 2100 VM branches come out through `box fetch --smart-http`: one
/// `ls-refs` answer lists them, one `fetch` request wants their 2100
/// commits (under `GIT_REQUEST_MAX`), and S8's import promotes each as
/// `refs/remotes/box/<branch>` at its commit, `box/main` beside them:
/// three requests, three http-backend runs. S10 (F4): the fetch's time is
/// printed (T9.1's 96 s was the import's per-ref scans).
#[test]
fn t9_1_2100_vm_branches_come_out() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let (work, dir) = (rig.work(), rig.work().display().to_string());
    s9_vm(rig);
    let branches = many_branches(&rig.vm_path(&work), MANY);
    let mut want: BTreeMap<String, String> = branches.iter().map(|(name, id)| (format!("refs/remotes/box/{}", name.strip_prefix("refs/heads/").unwrap_or(name)), id.clone())).collect();
    want.insert("refs/remotes/box/main".to_string(), rig.head().to_string());
    let (requests, calls) = (git_requests(rig).len(), rig.vm_git_calls().len());
    let t = std::time::Instant::now();
    let o = run_within(ai_env_real_git(rig, &["box", "fetch", &dir, "--smart-http", "--json"]), None, MANY_LIMIT, "box fetch --smart-http of 2100 branches");
    eprintln!("box fetch --smart-http of {MANY} VM branches: {:?}", t.elapsed());
    let got = promoted(&report_of(&o));
    assert!(got == want, "{} promoted of {}", got.len(), want.len());
    let refs = remote_refs(&work);
    assert!(refs == want, "{} box refs of {}", refs.len(), want.len());
    assert_eq!(git_requests(rig)[requests..], seen(&[(ADVERTISE, 200), (UPLOAD_PACK, 200), (UPLOAD_PACK, 200)]), "one ls-refs, one fetch");
    assert_eq!(backend(&rig.vm_git_calls()[calls..]).len(), 3);
}

/// No token reaches any git child (M5: not in one's argv or environment at
/// all). With every name each git started with logged on both sides
/// (`FAKE_GIT_ENV_ALL`), a seed, a smart-HTTP dry run and a smart-HTTP
/// fetch leave logs that hold no config carrier (`GIT_CONFIG_COUNT`,
/// `GIT_CONFIG_KEY_*`, `GIT_CONFIG_VALUE_*`, `GIT_CONFIG_PARAMETERS`), no
/// `HTTP_AUTHORIZATION`, `REMOTE_USER`, cookie or `x-aws-*` header, and no
/// argument holding a URL, an endpoint token, the session token, a bearer
/// or the setup-token. Every VM git ran as the agent with
/// `GIT_CONFIG_GLOBAL`; each http-backend run (two for the dry run, three
/// for the fetch) with exactly `GitRun::vm`'s five names and its request's
/// CGI names.
#[test]
fn t9_1_no_token_reaches_any_git_child() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    rig.set_vm_git_knobs(&[("FAKE_GIT_ENV_ALL", "1")]);
    install_fake_git(&rig.root().join("bin").join("git"), &rig.root().join("git-mac.log"), &[("FAKE_GIT_ENV_ALL", "1")]);
    let (mac0, vm0) = (rig.mac_git_calls().len(), rig.vm_git_calls().len());
    let vm = s9_vm(rig);
    let vm_dir = rig.vm_path(&rig.work());
    let main = agent_commit(&vm_dir, "agent.txt", "from the VM\n", "the agent's commit");
    let calls = rig.vm_git_calls().len();
    let o = box_fetch(rig, &["--smart-http", "--dry-run"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let dry = rig.vm_git_calls().len();
    let v = report_of(&box_fetch(rig, &["--smart-http", "--json"]));
    assert_eq!(promoted(&v), BTreeMap::from([("refs/remotes/box/main".to_string(), main)]));
    let (mac_calls, vm_calls) = (rig.mac_git_calls(), rig.vm_git_calls());
    let (mac, vmc) = (&mac_calls[mac0..], &vm_calls[vm0..]);
    assert!(mac.iter().any(|c| c.sub() == Some("index-pack")) && mac.iter().any(|c| c.sub() == Some("fetch")), "the import's runs are logged");
    // The fake API's tokens are `eyJ` and the hex of `<vm>|<port>|…`; the session token is the VM row's.
    let (session, token) = (session_token(rig, &vm), format!("eyJ{}", hex::encode(format!("{vm}|"))));
    let secrets = [session.as_str(), token.as_str(), rig.token(), "Bearer", "x-aws-", "://"];
    let carrier = |n: &str| ["GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "HTTP_AUTHORIZATION", "REMOTE_USER", "HTTP_COOKIE"].contains(&n) || ["GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "HTTP_X_AWS"].iter().any(|p| n.starts_with(p));
    for (side, log) in [("the Mac", mac), ("the VM", vmc)] {
        assert!(!log.is_empty(), "{side}: its gits are logged");
        for call in log {
            assert!(call.uid.is_some() && !call.env.is_empty(), "{side}: every name logged: {call:?}");
            assert!(!call.env.iter().any(|n| carrier(n)), "{side}: a carrier in {:?} ({:?})", call.env, call.sub());
            for arg in &call.args {
                assert!(!secrets.iter().any(|s| arg.contains(s)), "{side}: an argument of git {:?} holds a URL or a credential", call.sub());
            }
        }
    }
    for call in vmc {
        // SAFETY: getuid cannot fail.
        assert_eq!(call.uid, Some(unsafe { libc::getuid() }), "as the agent: {:?}", call.args);
        assert!(has_env(call, "GIT_CONFIG_GLOBAL"), "{:?}: {:?}", call.args, call.env);
    }
    let (ran_dry, ran) = (backend(&vm_calls[calls..dry]), backend(&vm_calls[dry..]));
    assert_eq!((ran_dry.len(), ran.len()), (2, 3), "the dry run's advertisement and ls-refs; the fetch's three");
    for call in ran_dry.iter().chain(&ran) {
        assert_cgi_run(call);
        assert!(has_env(call, "HTTP_GIT_PROTOCOL") && !has_env(call, "HTTP_CONTENT_ENCODING"), "{:?}", call.env);
    }
    assert_eq!(ran.iter().filter(|c| has_env(c, "CONTENT_LENGTH")).count(), 2, "ls-refs and fetch are POSTs");
}

/// A 403 on the code port re-mints once: the first answer of the fetch
/// refused (the proxy's `UNAUTHORIZED`), `box fetch --smart-http` mints a
/// second token, asks again and promotes. Refused twice, it exits 7 naming
/// the refusal after exactly two requests and two tokens: no third, no
/// helper started, the box ref where it was.
#[test]
fn t9_1_a_403_remints_once_then_exit_7() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    s9_vm(rig);
    let vm_dir = rig.vm_path(&work);
    let first = agent_commit(&vm_dir, "agent.txt", "from the VM\n", "the agent's commit");
    let refused = || Action::status(403, &[("x-aws-proxy-error", "UNAUTHORIZED")]);
    let (mints, requests) = (code_mints(rig), git_requests(rig).len());
    rig.endpoint.script_port(CODE_PORT, [refused()]);
    let o = box_fetch(rig, &["--smart-http"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(code_mints(rig) - mints, 2, "the first token and one more after its 403");
    assert_eq!(git_requests(rig)[requests..], seen(&[(ADVERTISE, 403), (ADVERTISE, 200), (UPLOAD_PACK, 200), (UPLOAD_PACK, 200)]));
    assert_eq!(remote_refs(&work), BTreeMap::from([("refs/remotes/box/main".to_string(), first.clone())]));
    agent_commit(&vm_dir, "agent.txt", "from the VM, again\n", "the agent's second commit");
    let (mints, requests, calls) = (code_mints(rig), git_requests(rig).len(), rig.vm_git_calls().len());
    rig.endpoint.script_port(CODE_PORT, [refused(), refused()]);
    let o = box_fetch(rig, &["--smart-http"]);
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(7), "{err}");
    assert!(err.contains("token rejected: HTTP 403 for port 9418 (x-aws-proxy-error: UNAUTHORIZED)"), "{err}");
    assert_eq!(code_mints(rig) - mints, 2, "a token, then one re-mint");
    assert_eq!(git_requests(rig)[requests..], seen(&[(ADVERTISE, 403), (ADVERTISE, 403)]), "asked twice, never a third time");
    assert_eq!(rig.vm_git_calls().len(), calls, "no helper started");
    assert_eq!(remote_refs(&work), BTreeMap::from([("refs/remotes/box/main".to_string(), first)]), "the box ref where it was");
}

/// A VM whose image does not name `git_http_v1` (an S8 image's: the rig's
/// fake API without it) is refused before any request though its shim
/// serves the routes: `box fetch --smart-http` exits 7 naming `make
/// deploy`, with no token minted, nothing asked through the endpoint, no
/// git run in the VM, no box ref. Once its `/health` names it (`vm health`
/// records the caps), the same fetch goes through.
#[test]
fn t9_1_a_vm_without_git_http_v1_is_exit_7_before_any_request() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let work = rig.work();
    rig.update_fake(|s| s.health_caps.retain(|c| c != CAP_GIT_HTTP_V1));
    let vm = rig.start_vm();
    box_seed(rig);
    let main = agent_commit(&rig.vm_path(&work), "agent.txt", "from the VM\n", "the agent's commit");
    let (mints, attempts, calls) = (code_mints(rig), rig.endpoint.attempts().len(), rig.vm_git_calls().len());
    let o = box_fetch(rig, &["--smart-http"]);
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(7), "{err}");
    assert!(err.contains("lacks git_http_v1") && err.contains("make deploy"), "{err}");
    assert_eq!((code_mints(rig), rig.endpoint.attempts().len(), rig.vm_git_calls().len()), (mints, attempts, calls), "nothing minted, asked or run");
    assert!(remote_refs(&work).is_empty());
    rig.update_fake(|s| s.health_caps.push(CAP_GIT_HTTP_V1.to_string()));
    let o = rig.run(&["vm", "health", &vm, "--json"], None);
    assert!(o.status.success(), "vm health: {}", text(&o.stderr));
    let v = report_of(&box_fetch(rig, &["--smart-http", "--json"]));
    assert_eq!(promoted(&v), BTreeMap::from([("refs/remotes/box/main".to_string(), main)]));
}

/// `box review` of a ref a smart-HTTP fetch quarantined (the agent's
/// commit holds a key) exits 9 naming the finding's commit, file, blob and
/// line, never the key; `--json` names the same finding. The fixture's
/// own `main` passes.
#[test]
fn t9_1_review_of_a_quarantined_ref_exits_9_naming_the_line() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let dir = rig.work().display().to_string();
    let (_, commit, blob, key) = quarantined(rig);
    let o = rig.run(&["box", "review", "refs/remotes/box-quarantine/main", "--repo", &dir], None);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(o.status.code(), Some(9), "{}{}", out.replace(&key, "<KEY>"), err.replace(&key, "<KEY>"));
    assert!(out.contains(&format!("  {}\n", finding_line(&commit, &blob))) && out.ends_with("box review: findings\n"), "{}", out.replace(&key, "<KEY>"));
    assert!(!out.contains(&key) && !err.contains(&key));
    let o = rig.run(&["box", "review", "refs/remotes/box-quarantine/main", "--repo", &dir, "--json"], None);
    assert_eq!(o.status.code(), Some(9), "{}", text(&o.stderr));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o.stdout)));
    assert_eq!(v["findings"], json!([{ "rule": "aws-access-key-id", "path": "deploy.conf", "line": 2, "commit": commit }]), "{v}");
    assert_eq!(v["verdict"], "findings");
    let o = rig.run(&["box", "review", "main", "--repo", &dir], None);
    assert_eq!(o.status.code(), Some(0), "{}{}", text(&o.stdout), text(&o.stderr));
}

/// The pre-push hook stands between quarantined work and a local bare
/// remote: once `box hook-install` put it in the workspace, the clean
/// `main` goes to the remote, but a branch holding the quarantined commit
/// is refused (the hook's review names the finding's line), by the
/// remote's name and by its bare path alike; the remote never gets the
/// branch or the commit, and the key is in no output.
#[test]
fn t9_1_the_hook_refuses_quarantined_work_to_a_local_bare_remote() {
    let mut p = Harness::prepare();
    let rig = p.rig();
    let (work, dir) = (rig.work(), rig.work().display().to_string());
    let (_, commit, blob, key) = quarantined(rig);
    let o = rig.run(&["box", "hook-install", &dir], None);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let hook = std::fs::read_to_string(work.join(".git").join("hooks").join("pre-push")).expect("the hook");
    assert_eq!(hook.lines().nth(1), Some(PRE_PUSH_MARK), "{hook}");
    let origin = rig.root().join("origin.git");
    let origin_path = origin.display().to_string();
    git(rig.root(), &["init", "-q", "--bare", &origin_path]);
    git(&work, &["remote", "add", "origin", &origin_path]);
    // The hook's git: the workspace's own hooks, the rig's bridge dir for its review.
    let push = |args: &[&str]| -> Output {
        let mut cmd = Command::new(git_real());
        cmd.args(args).current_dir(&work);
        clean_env(&mut cmd, rig.root());
        cmd.env("PATH", format!("{}:/usr/bin:/bin", rig.root().join("bin").display()))
            .env("AI_ENV_BRIDGE_DIR", rig.bridge())
            .env("AI_ENV_DIR", rig.root().join("keys"))
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null");
        run_within(cmd, None, LIMIT, "git push")
    };
    let o = push(&["push", "-q", "origin", "main"]);
    assert!(o.status.success(), "the clean main: {}", both(&o));
    assert_eq!(git(&origin, &["rev-parse", "refs/heads/main"]), rig.head());
    git(&work, &["branch", "agent-work", "refs/remotes/box-quarantine/main"]);
    for remote in ["origin", origin_path.as_str()] {
        let o = push(&["push", remote, "agent-work"]);
        let said = both(&o);
        assert!(!o.status.success() && said.contains(&finding_line(&commit, &blob)), "to {remote}: {}", said.replace(&key, "<KEY>"));
        assert!(!said.contains(&key), "to {remote}");
    }
    assert!(!git_ok(&origin, &["rev-parse", "--verify", "-q", "refs/heads/agent-work"]), "no branch on the remote");
    assert!(!git_ok(&origin, &["cat-file", "-e", &commit]), "the quarantined commit never reached the remote");
}
